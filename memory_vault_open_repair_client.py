"""Recover an ACK owner's complete source proof over bounded native HTTP.

The caller supplies its own original authorities and independently known source
keys. No private authority upload, ambient credential, Vault or alternate local
store is created. The result retains exact originals for the caller's own state.
"""
from dataclasses import dataclass
import math
import time
from types import MappingProxyType

from memory_vault_open_transport import OpenHTTPTransport, endpoint
import memory_vault_open_repair_ack as ack
import memory_vault_open_repair_bootstrap as bootstrap
import memory_vault_open_repair_original as original
import memory_vault_open_repair_probe as probe
import memory_vault_open_repair_proof as proof
import memory_vault_open_repair_status as status
import memory_vault_open_repair_wire as wire
from memory_vault_open_repair_state import DEFAULT_LIMITS, DEFAULT_POLICY


def _entry(item):
    return dict(raw=item.raw, ref=item.ref.as_dict())


def _fail(code):
    raise wire.RepairWireError(code)


@dataclass(frozen=True, slots=True)
class RecoveredAckOwnerProof:
    source: ack.AuthenticatedAckUnboundSourceEvent
    proof: proof.AuthenticatedBootstrapProof
    current_statuses: tuple
    originals: object
    metrics: object


class AckOwnerRecoveryClient:
    def __init__(self, identity, encryption_identity, *, policy=DEFAULT_POLICY,
                 limit_policy=None, allow_loopback=False, transport=None, clock=None):
        self.identity, self.encryption_identity = identity, encryption_identity
        self.policy = policy
        self.limits = wire.build_new_wire(DEFAULT_LIMITS if limit_policy is None else limit_policy,
                                         policy,wire.RepairBudget(policy)).value
        bootstrap._limits(self.limits)
        self.subject = dict(signing_key=identity.public_descriptor(), encryption_key=encryption_identity.public_descriptor())
        self.transport = transport or OpenHTTPTransport(allow_loopback=allow_loopback)
        self.allow_loopback, self.clock = allow_loopback, clock or time.time
        self._own_transport = transport is None

    def close(self):
        if self._own_transport:
            self.transport.close()

    def _now(self):
        return wire.u53(int(self.clock()))

    def recover(self, base_url, *, target_node_entry, expected_target, expected_ack_slot,
                root_entry, read_entry, bootstrap_entry, known_statuses=(), archive_statuses=(), timeout=30):
        if type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0<timeout<=60:
            _fail("repair_invalid_deadline")
        budget = wire.RepairBudget(self.policy)
        retained = self._retained_inputs(known_statuses, archive_statuses, budget)
        started = self._now()
        deadline = time.monotonic()+timeout
        expected = wire.build_new_wire(dict(target=expected_target,slot=expected_ack_slot),self.policy,budget).value
        setup = bootstrap.verify_ack_owner_bootstrap_original(bootstrap_entry,dict(root=root_entry,read=read_entry),
            expected_ack_slot=expected["slot"],expected_owner=self.subject,at=started,limit_policy=self.limits,
            policy=self.policy,budget=budget)
        raw,ref = ack._entry(target_node_entry)
        node = original.verify_original_control(raw,expected_signing_key=expected["target"]["signing_key"],
            expected_schema="memory-vault-open-control/v1",expected_kind="node",at=started,policy=self.policy,budget=budget)
        original._node_shape(node,started,budget)
        if len(node.document.raw)!=ref.size or node.raw_sha256!=ref.raw_sha256:
            _fail("repair_ref_mismatch")
        if endpoint(base_url,allow_loopback=self.allow_loopback)!=endpoint(node.payload["base_url"],allow_loopback=self.allow_loopback):
            _fail("repair_proof_mismatch")
        grant = setup.originals["bootstrap"].payload
        obligations = self._obligations(setup.originals, expected["slot"], budget)
        known = self._known(retained, obligations, expected["slot"]["root_key"],
                            expected["target"], budget)
        expiry = min(started+min(60,max(1,int(timeout))),grant["probe_until"],grant["proof_until"],grant["expires_at"],
                     node.payload["expires_at"],*(setup.originals[name].payload["expires_at"] for name in ("root","read")))
        if expiry<=started:
            _fail("repair_access_expired")
        binding = dict(expected_subject=self.subject,expected_target=expected["target"],target_storage_epoch=node.payload["storage_epoch"],
            bootstrap_grant_sha256=setup.originals["bootstrap"].ref.raw_sha256,selector=grant["selector"],policy=self.policy,budget=budget)
        requests,wire_bytes,proof_bytes = 0,0,0

        def request(body, *, child=False):
            nonlocal requests,wire_bytes
            if requests>=grant["limits"]["max_requests"] or time.monotonic()>=deadline:
                _fail("repair_over_budget")
            requests+=1
            reply = self.transport.request_repair(base_url,body,child=child,deadline=deadline)
            if type(reply) is not bytes or not 0 < len(reply) <= proof.MAX_RESPONSE_BYTES:
                _fail("repair_invalid_response")
            wire_bytes+=len(body)+len(reply)
            return reply

        outgoing = probe.make_bootstrap_probe(self.identity,**binding,at=started,expires_at=expiry)
        if len(outgoing.original.raw)>grant["limits"]["max_probe_bytes"]:
            _fail("repair_over_budget")
        challenge_raw = request(outgoing.original.raw)
        challenge_digest = budget._hash(challenge_raw)
        challenge = dict(raw=challenge_raw,ref=wire.RawRef("meta",challenge_digest,challenge_digest,len(challenge_raw)).as_dict())
        answer = probe.solve_bootstrap_challenge(_entry(outgoing.original),challenge,signer=self.identity,
            encryption_identity=self.encryption_identity,target_nonce=outgoing.nonce,**binding,at=self._now(),expires_at=expiry)
        response = request(answer.raw)
        held = proof.verify_bootstrap_proof_response(response,expected_subject=self.subject,expected_target=expected["target"],
            target_storage_epoch=node.payload["storage_epoch"],selector=grant["selector"],bootstrap_grant_ref=setup.originals["bootstrap"].ref.as_dict(),
            probe_ref=outgoing.original.ref.as_dict(),challenge_ref=challenge["ref"],answer_ref=answer.ref.as_dict(),at=self._now(),
            max_proof_items=grant["limits"]["max_proof_items"],max_proof_bytes=grant["limits"]["max_proof_bytes"],policy=self.policy,budget=budget)
        proof_bytes = len(response)+len(held.handle.raw)+len(held.manifest.raw)
        originals,roles = {},{}
        for item in held.manifest.value["children"]:
            reference = probe._ref(item["ref"])
            roles.setdefault(item["role"],[]).append(reference)
            if reference in originals:
                continue
            if reference.size>self.policy.max_document_bytes or proof_bytes+reference.size>grant["limits"]["max_proof_bytes"]:
                _fail("repair_over_budget")
            chunks,offset = [],0
            while offset<reference.size:
                count = min(proof.MAX_CHILD_BYTES,reference.size-offset)
                child = proof.make_bootstrap_child_request(self.identity,held,subject=self.subject,target=expected["target"],
                    at=self._now(),expires_at=held.handle.payload["expires_at"],child_index=item["index"],offset=offset,
                    requested_bytes=count,policy=self.policy,budget=budget)
                received = request(child.raw,child=True)
                if len(received)!=count:
                    _fail("repair_ref_mismatch")
                budget._bytes("input_bytes",len(received))
                chunks.append(received);offset+=count
            budget._bytes("output_bytes",reference.size)
            assembled = b"".join(chunks)
            if budget._hash(assembled)!=reference.raw_sha256:
                _fail("repair_ref_mismatch")
            proof_bytes+=len(assembled)
            originals[reference]=assembled
        if self._now()>=held.handle.payload["expires_at"] or time.monotonic()>=deadline:
            _fail("repair_access_expired")
        def entry(role):
            reference=roles[role][0]
            return dict(raw=originals[reference],ref=reference.as_dict())
        resolver=wire.LocalRawResolver(self.policy,budget)
        for reference in roles["history.raw_pack"]:
            if resolver.put(reference.namespace,reference.key,originals[reference]).ref!=reference:
                _fail("repair_ref_mismatch")
        source=ack.verify_ack_unbound_source_event(entry("history.ack_unbound"),resolver,entry("ack.unbound_custody"),
            expected_ack_slot=expected["slot"],expected_owner=self.subject,expected_target=expected["target"],
            target_storage_epoch=node.payload["storage_epoch"],limit_policy=self.limits,policy=self.policy,budget=budget)
        # Every displayed historical child must be the exact original in H,
        # not another signed body of the same kind at an unrelated locator.
        for item in source.manifest.roles:
            if roles[item.role]!=[item.original.ref] or originals[item.original.ref]!=item.original.raw:
                _fail("repair_proof_mismatch")
        if (source.resources.originals["root"].ref!=setup.originals["root"].ref or
                source.resources.originals["read"].ref!=setup.originals["read"].ref or
                source.bootstrap.originals["bootstrap"].ref!=setup.originals["bootstrap"].ref):
            _fail("repair_proof_mismatch")
        current=self._current(source,roles,originals,expected["target"],budget,known)
        # A successful cryptographic check cannot extend the source's signed
        # read promise or a phase deadline while the last originals are checked.
        now = self._now()
        if (now >= min(expiry, held.handle.payload["expires_at"], source.read_until,
                       *(item.payload["valid_until"] for item in current))
                or time.monotonic() >= deadline):
            _fail("repair_access_expired")
        metrics=MappingProxyType(dict(requests=requests,wire_bytes=wire_bytes,proof_bytes=proof_bytes,
                                      **budget.snapshot()))
        return RecoveredAckOwnerProof(source,held,current,MappingProxyType(originals),metrics)

    def _obligations(self, originals, slot, budget):
        root = slot["root_key"]
        obligations=[]
        for name,role,kind in (("root","current.status.ack_root","ack.root_authority"),
                              ("read","current.status.ack_read","ack.read_grant"),
                              ("bootstrap","current.status.ack_owner_bootstrap","bootstrap.grant")):
            item=originals[name]
            obligations.append(dict(role=role,kind="authority",subject=dict(authority_kind=kind,authority_sha256=item.ref.raw_sha256),
                                    revision=item.payload["revision"],signer=self.subject["signing_key"]))
        obligations.append(dict(role="current.status.ack_slot",kind="ack_slot",subject=slot,
            revision=originals["root"].payload["revision"],signer=self.subject["signing_key"]))
        for item in obligations:
            item["scope_id"]=status.status_scope(root,item["kind"],item["subject"],self.policy,budget)
        return obligations

    @staticmethod
    def _status_entries(payload):
        entries = payload["entries"]
        if type(entries) is not wire._DraftList or not 1 <= len(entries) <= 16:
            _fail("repair_invalid_status")
        for item in entries:
            status._scope_key(status._fields(item,status._ENTRY))
        return entries

    def _retained_inputs(self, known, archive, budget):
        """Snapshot and bound the exact union before any identity lookup/I/O."""
        if type(known) not in (list,tuple) or len(known)>16:
            _fail("repair_invalid_status")
        if type(archive) not in (list,tuple):
            _fail("repair_invalid_status")
        if len(archive)>32:
            _fail("repair_status_history_capacity")
        unique={}
        for item in (*known,*archive):
            raw,ref=ack._entry(item)
            if wire._raw_size(raw,self.policy)>status.MAX_STATUS_BYTES:
                _fail("repair_invalid_status")
            raw=wire._snapshot(raw,self.policy,budget)
            unique.setdefault((raw,ref),dict(raw=raw,ref=ref.as_dict()))
            if len(unique)>32:
                _fail("repair_status_history_capacity")
        return tuple(unique.values())

    def _known(self, entries, obligations, root, target, budget):
        """Authenticate retained originals before contacting their source.

        Expired originals still retain revocation and monotone-floor evidence.
        Target resource identities become independently known only after active
        resource recovery; these preliminary signatures grant no operation.
        """
        if type(entries) not in (list,tuple) or len(entries)>32:
            _fail("repair_invalid_status")
        checked=[]
        for entry in entries:
            raw, ref = ack._entry(entry)
            parsed = original.parse_original_control(raw,self.policy,budget)
            payload = status._fields(status._fields(parsed.value,{"payload","proof"})["payload"],status._PAYLOAD)
            issuer = status._fields(payload["scope_key"],{"root_key","issuer_key_id"})["issuer_key_id"]
            issued = wire.u53(payload["issued_at"])
            if issued > self._now()+30:
                _fail("repair_status_mismatch")
            values = self._status_entries(payload)
            if issuer == self.subject["signing_key"]["key_id"]:
                signer = self.subject["signing_key"]
                allowed = [dict(scope_kind=item["kind"],scope_id=item["scope_id"]) for item in obligations]
                if issuer == target["signing_key"]["key_id"]:
                    allowed += [dict(scope_kind=item["scope_kind"],scope_id=item["scope_id"])
                                for item in values if item["scope_kind"] == "resource"]
            elif issuer == target["signing_key"]["key_id"]:
                signer = target["signing_key"]
                if any(item["scope_kind"] != "resource" for item in values):
                    _fail("repair_status_disclosure")
                allowed = [dict(scope_kind=item["scope_kind"],scope_id=item["scope_id"]) for item in values]
            else:
                _fail("repair_status_mismatch")
            observed = status.authenticate_status_original(dict(raw=parsed.raw,ref=ref.as_dict()),
                expected_root=root,expected_signing_key=signer,at=issued,allowed_scopes=allowed,
                policy=self.policy,budget=budget)
            checked.append(observed)
        self._floors(checked,(),obligations,probe_phase=True)
        return tuple(checked)

    def _floors(self, known, current, obligations, *, probe_phase=False):
        seen={};floors={}
        required={(item["signer"]["key_id"],item["kind"],item["scope_id"]):item for item in obligations}
        for observed in (*known,*current):
            issuer=observed.payload["scope_key"]["issuer_key_id"]
            revision=observed.payload["revision"]
            identity=issuer,revision
            if identity in seen and seen[identity]!=observed.canonical_sha256:
                _fail("repair_status_conflict")
            seen[identity]=observed.canonical_sha256
            for entry in observed.payload["entries"]:
                key=issuer,entry["scope_kind"],entry["scope_id"]
                wanted=required.get(key)
                mask=10 if probe_phase and wanted and wanted["role"] in (
                    "current.status.ack_root","current.status.ack_owner_bootstrap") else 2
                if entry["status"]=="revoked" and entry["operation_mask"] & mask:
                    _fail("repair_authority_revoked")
                if wanted:
                    if entry["minimum_document_revision"]>wanted["revision"]:
                        _fail("repair_status_revision")
                floors.setdefault(key,[]).append((revision,entry["minimum_document_revision"]))
        for values in floors.values():
            minimum=0
            for _,floor in sorted(values):
                if floor<minimum:
                    _fail("repair_status_rollback")
                minimum=floor
        for observed in current:
            issuer=observed.payload["scope_key"]["issuer_key_id"]
            for entry in observed.payload["entries"]:
                key=issuer,entry["scope_kind"],entry["scope_id"]
                if observed.payload["revision"]<max(revision for revision,_ in floors[key]):
                    _fail("repair_status_rollback")

    def _current(self,source,roles,originals,target,budget,known=()):
        root=source.custody.payload["ack_slot"]["root_key"]
        parents=dict(source.resources.originals)
        parents["bootstrap"]=source.bootstrap.originals["bootstrap"]
        obligations=self._obligations(parents,source.custody.payload["ack_slot"],budget)
        active=source.resources.originals["active"].payload
        obligations.append(dict(role="current.status.ack_resource",kind="resource",subject=active["resource"],
            revision=active["reservation_generation"],signer=target["signing_key"],
            scope_id=status.status_scope(root,"resource",active["resource"],self.policy,budget)))
        permitted={(item["signer"]["key_id"],item["kind"],item["scope_id"]) for item in obligations}
        for observed in known:
            issuer=observed.payload["scope_key"]["issuer_key_id"]
            if any((issuer,item["scope_kind"],item["scope_id"]) not in permitted for item in observed.payload["entries"]):
                _fail("repair_status_disclosure")
        groups={}
        for item in obligations:
            ref=roles[item["role"]][0]
            group=groups.setdefault(ref,dict(signer=item["signer"],required=[]))
            if group["signer"]!=item["signer"]:
                _fail("repair_proof_mismatch")
            group["required"].append(dict(scope_kind=item["kind"],scope_id=item["scope_id"],document_revision=item["revision"],operation_mask=2))
        checked=[]
        for ref,group in groups.items():
            allowed=[item for item in obligations if item["signer"]==group["signer"]]
            parsed=original.parse_original_control(originals[ref],self.policy,budget)
            payload=status._fields(status._fields(parsed.value,{"payload","proof"})["payload"],status._PAYLOAD)
            present={status._scope_key(item) for item in self._status_entries(payload)}
            required={(item["scope_kind"],item["scope_id"]):item for item in group["required"]}
            for item in allowed:
                key=item["kind"],item["scope_id"]
                if key in present:
                    required[key]=dict(scope_kind=item["kind"],scope_id=item["scope_id"],document_revision=item["revision"],operation_mask=2)
            observed=status.verify_status_original(dict(raw=originals[ref],ref=ref.as_dict()),expected_root=root,
                expected_signing_key=group["signer"],at=self._now(),allowed_scopes=[dict(scope_kind=item["kind"],scope_id=item["scope_id"]) for item in allowed],
                required=list(required.values()),policy=self.policy,budget=budget)
            checked.append(observed)
        self._floors((*source.statuses,*known),checked,obligations)
        return tuple(checked)
