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
import memory_vault_open_repair_empty as empty
import memory_vault_open_repair_occupied as occupied
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
    source: object
    proof: proof.AuthenticatedBootstrapProof
    current_statuses: tuple
    originals: object
    metrics: object


class AckOwnerRecoveryClient:
    def __init__(self, identity, encryption_identity, *, policy=DEFAULT_POLICY,
                 limit_policy=None, allow_loopback=False, transport=None, clock=None,
                 status_observer=None):
        if status_observer is not None and not callable(status_observer):
            _fail("repair_invalid_context")
        self.identity, self.encryption_identity = identity, encryption_identity
        self.policy = policy
        self.limits = wire.build_new_wire(DEFAULT_LIMITS if limit_policy is None else limit_policy,
                                         policy,wire.RepairBudget(policy)).value
        bootstrap._limits(self.limits)
        self.subject = dict(signing_key=identity.public_descriptor(), encryption_key=encryption_identity.public_descriptor())
        self.transport = transport or OpenHTTPTransport(allow_loopback=allow_loopback)
        self.allow_loopback, self.clock = allow_loopback, clock or time.time
        self._own_transport = transport is None
        self.status_observer = status_observer

    def close(self):
        if self._own_transport:
            self.transport.close()

    def _now(self):
        return wire.u53(int(self.clock()))

    def recover(self, base_url, *, target_node_entry, expected_target, expected_ack_slot,
                root_entry, read_entry, bootstrap_entry, known_statuses=(), archive_statuses=(), timeout=30):
        return self._recover(base_url,target_node_entry=target_node_entry,expected_target=expected_target,
            expected_ack_slot=expected_ack_slot,root_entry=root_entry,read_entry=read_entry,
            bootstrap_entry=bootstrap_entry,known_statuses=known_statuses,archive_statuses=archive_statuses,
            timeout=timeout,empty_expected=None)

    def recover_empty(self, base_url, *, target_node_entry, expected_target, expected_ack_slot,
                      root_entry, read_entry, bootstrap_entry, expected_receipt_writer,
                      expected_message_id, expected_envelope_ref,
                      known_statuses=(), archive_statuses=(), timeout=30):
        """Read a bound empty source using the caller's independent S_ACK1 tuple."""
        return self._recover(base_url,target_node_entry=target_node_entry,expected_target=expected_target,
            expected_ack_slot=expected_ack_slot,root_entry=root_entry,read_entry=read_entry,
            bootstrap_entry=bootstrap_entry,known_statuses=known_statuses,archive_statuses=archive_statuses,
            timeout=timeout,empty_expected=dict(receipt_writer=expected_receipt_writer,
                message_id=expected_message_id,envelope_ref=expected_envelope_ref))

    def _recover(self, base_url, *, target_node_entry, expected_target, expected_ack_slot,
                 root_entry, read_entry, bootstrap_entry, known_statuses, archive_statuses, timeout, empty_expected,
                 _budget=None, _source_state=None):
        if type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0<timeout<=60:
            _fail("repair_invalid_deadline")
        budget = wire.RepairBudget(self.policy) if _budget is None else _budget
        wire._context(self.policy,budget)
        retained = self._retained_inputs(known_statuses, archive_statuses, budget)
        started = self._now()
        deadline = time.monotonic()+timeout
        expected = wire.build_new_wire(dict(target=expected_target,slot=expected_ack_slot),self.policy,budget).value
        if empty_expected is not None:
            empty_expected=wire.build_new_wire(empty_expected,self.policy,budget).value
            empty.bound._expected(expected["slot"],self.subject,empty_expected["receipt_writer"],
                empty_expected["message_id"],empty_expected["envelope_ref"],started,self.policy,budget)
        source_state=("unbound" if empty_expected is None else "empty") if _source_state is None else _source_state
        if source_state not in ("unbound","empty","occupied") or (source_state=="unbound")!=(empty_expected is None):
            _fail("repair_invalid_proof")
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
                            expected["target"], budget,deferred_authorities=empty_expected is not None,
                            receipt_writer=empty_expected["receipt_writer"] if source_state=="occupied" else None)
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
            max_proof_items=grant["limits"]["max_proof_items"],max_proof_bytes=grant["limits"]["max_proof_bytes"],policy=self.policy,budget=budget,
            expected_source_state=source_state)
        proof_bytes = len(response)+len(held.handle.raw)+len(held.manifest.raw)
        originals,roles = {},{}
        for item in held.manifest.value["children"]:
            reference = wire.raw_ref(item["ref"])
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
        source_options=dict(expected_ack_slot=expected["slot"],expected_owner=self.subject,expected_target=expected["target"],
            target_storage_epoch=node.payload["storage_epoch"],limit_policy=self.limits,policy=self.policy,budget=budget)
        if empty_expected is None:
            source=ack.verify_ack_unbound_source_event(entry("history.ack_unbound"),resolver,entry("ack.unbound_custody"),**source_options)
            prior=source
        elif source_state=="empty":
            source=empty.verify_ack_empty_source_event(entry("history.ack_empty"),resolver,entry("ack.empty_custody"),
                expected_receipt_writer=empty_expected["receipt_writer"],expected_message_id=empty_expected["message_id"],
                expected_envelope_ref=empty_expected["envelope_ref"],**source_options)
            self._empty_head(entry("ack.head"),source,expected["target"],budget)
            prior=source.predecessor
        else:
            source=occupied.verify_ack_occupied_source_event(entry("history.ack_occupied_inputs"),resolver,entry("ack.commit"),
                expected_receipt_writer=empty_expected["receipt_writer"],expected_message_id=empty_expected["message_id"],
                expected_envelope_ref=empty_expected["envelope_ref"],**source_options)
            occupied.verify_ack_occupied_head(entry("ack.head"),source,expected_target=expected["target"],
                policy=self.policy,budget=budget)
            prior=source.predecessor.predecessor
        # Every displayed historical child must be the exact original in H,
        # not another signed body of the same kind at an unrelated locator.
        for item in source.manifest.roles:
            if roles[item.role]!=[item.original.ref] or originals[item.original.ref]!=item.original.raw:
                _fail("repair_proof_mismatch")
        if (prior.resources.originals["root"].ref!=setup.originals["root"].ref or
                prior.resources.originals["read"].ref!=setup.originals["read"].ref or
                prior.bootstrap.originals["bootstrap"].ref!=setup.originals["bootstrap"].ref):
            _fail("repair_proof_mismatch")
        manifests=((source.manifest,) if empty_expected is None else
            (source.manifest,prior.manifest) if source_state=="empty" else
            (source.manifest,source.predecessor.manifest,prior.manifest))
        used_packs={wire.raw_ref(item["pack_ref"]) for manifest in manifests for item in manifest.manifest.value["roles"]}
        if set(roles["history.raw_pack"]) != used_packs:
            _fail("repair_unused_pack")
        current=(self._current(source,roles,originals,expected["target"],budget,known) if empty_expected is None else
            self._current(prior,roles,originals,expected["target"],budget,known,extra_source=source) if source_state=="empty" else
            self._current(prior,roles,originals,expected["target"],budget,known,extra_source=source.predecessor,
                occupied_source=source,receipt_writer=empty_expected["receipt_writer"]))
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

    def recover_occupied(self, base_url, *, target_node_entry, expected_target, expected_ack_slot,
                         root_entry, read_entry, bootstrap_entry, expected_receipt_writer,
                         expected_message_id, expected_envelope_ref,
                         known_statuses=(), archive_statuses=(), timeout=30):
        """Recover an exact B receipt with B's explicit full bootstrap consent."""
        return self._recover(base_url,target_node_entry=target_node_entry,expected_target=expected_target,
            expected_ack_slot=expected_ack_slot,root_entry=root_entry,read_entry=read_entry,
            bootstrap_entry=bootstrap_entry,known_statuses=known_statuses,archive_statuses=archive_statuses,
            timeout=timeout,empty_expected=dict(receipt_writer=expected_receipt_writer,
                message_id=expected_message_id,envelope_ref=expected_envelope_ref),_source_state="occupied")

    def _empty_head(self,entry,source,target,budget):
        raw,ref=ack._entry(entry)
        parsed=wire.parse_new_wire(raw,self.policy,budget)
        if len(parsed.raw)!=ref.size or budget._hash(parsed.raw)!=ref.raw_sha256:
            _fail("repair_ref_mismatch")
        signed=wire.object_fields(parsed.value,{"payload","proof"})
        payload=wire.object_fields(signed["payload"],empty.resource.COMMON|{
            "ack_slot","generation","observed_at","retain_until","state","root_authority_ref","grant_ref","binding_ref"})
        if (payload["schema_version"]!=empty.resource.SCHEMA or payload["kind"]!="ack.head" or payload["state"]!="empty"
                or wire.u53(payload["generation"],1)!=1 or payload["ack_slot"]!=source.custody.payload["ack_slot"]
                or payload["observed_at"]!=source.stored_at or payload["retain_until"]!=source.retain_until
                or any(payload[name]!=source.custody.payload[name] for name in ("root_authority_ref","grant_ref","binding_ref"))):
            _fail("repair_ack_empty_mismatch")
        original._verify_control_signature(payload,signed["proof"],target["signing_key"],budget)

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

    def _known(self, entries, obligations, root, target, budget, *, deferred_authorities=False,receipt_writer=None):
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
                if deferred_authorities:
                    scopes={(item["scope_kind"],item["scope_id"]) for item in allowed}
                    scopes.update((item["scope_kind"],item["scope_id"]) for item in values if item["scope_kind"]=="authority")
                    allowed=[dict(scope_kind=kind,scope_id=scope_id) for kind,scope_id in sorted(scopes)]
                if issuer == target["signing_key"]["key_id"]:
                    allowed += [dict(scope_kind=item["scope_kind"],scope_id=item["scope_id"])
                                for item in values if item["scope_kind"] == "resource"]
            elif issuer == target["signing_key"]["key_id"]:
                signer = target["signing_key"]
                kinds={"resource"}
                if receipt_writer is not None and issuer==receipt_writer["signing_key"]["key_id"]:
                    kinds.add("authority")
                if any(item["scope_kind"] not in kinds for item in values):
                    _fail("repair_status_disclosure")
                allowed = [dict(scope_kind=item["scope_kind"],scope_id=item["scope_id"]) for item in values]
            elif receipt_writer is not None and issuer == receipt_writer["signing_key"]["key_id"]:
                signer = receipt_writer["signing_key"]
                if any(item["scope_kind"] != "authority" for item in values):
                    _fail("repair_status_disclosure")
                # Its exact completed consent hash becomes independently known
                # from the authenticated occupied closure, never from a label.
                allowed = [dict(scope_kind=item["scope_kind"],scope_id=item["scope_id"]) for item in values]
            else:
                _fail("repair_status_mismatch")
            observed = status.authenticate_status_original(dict(raw=parsed.raw,ref=ref.as_dict()),
                expected_root=root,expected_signing_key=signer,at=issued,allowed_scopes=allowed,
                policy=self.policy,budget=budget)
            checked.append(observed)
        # Co-located A/B keys make a not-yet-recovered authority scope
        # ambiguous. Conservatively retain its READ revocation before probing.
        defer=deferred_authorities and not (receipt_writer is not None and
            receipt_writer["signing_key"]["key_id"]==self.subject["signing_key"]["key_id"])
        self._floors(checked,(),obligations,probe_phase=True,deferred_authorities=defer)
        return tuple(checked)

    def _floors(self, known, current, obligations, *, probe_phase=False,deferred_authorities=False):
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
                mask=wanted.get("mask",2) if wanted else 2
                if probe_phase and wanted and wanted["role"] in ("current.status.ack_root","current.status.ack_owner_bootstrap"):
                    mask=10
                if deferred_authorities and wanted is None and issuer==self.subject["signing_key"]["key_id"] and entry["scope_kind"]=="authority":
                    mask=0
                if entry["status"]=="revoked" and entry["operation_mask"] & mask:
                    _fail("repair_authority_revoked")
                if wanted and mask:
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

    def _current(self,source,roles,originals,target,budget,known=(),*,extra_source=None,
                 occupied_source=None,receipt_writer=None):
        root=source.custody.payload["ack_slot"]["root_key"]
        parents=dict(source.resources.originals)
        parents["bootstrap"]=source.bootstrap.originals["bootstrap"]
        obligations=self._obligations(parents,source.custody.payload["ack_slot"],budget)
        active=source.resources.originals["active"].payload
        obligations.append(dict(role="current.status.ack_resource",kind="resource",subject=active["resource"],
            revision=active["reservation_generation"],signer=target["signing_key"],
            scope_id=status.status_scope(root,"resource",active["resource"],self.policy,budget)))
        if extra_source is not None:
            for name,kind in (("write","ack.write_grant"),("bootstrap","bootstrap.grant")):
                item=extra_source.authorities.originals[name]
                subject=dict(authority_kind=kind,authority_sha256=item.ref.raw_sha256)
                obligations.append(dict(role=None,kind="authority",subject=subject,revision=item.payload["revision"],
                    signer=self.subject["signing_key"],mask=0,
                    scope_id=status.status_scope(root,"authority",subject,self.policy,budget)))
        if occupied_source is not None:
            consent=occupied_source.inputs["disclosure"]
            returned=consent.payload["bootstrap_return"]
            if (returned["roles"] != ["ack.disclosure","ack.put","authority.status.disclosure","recipient.receipt"]
                    or returned["subject"]!=probe._dual(self.subject) or returned["consumer"]!="ack_owner"
                    or consent.payload["operation_mask"] & 2 != 2
                    or not occupied.B_ROLES <= set(consent.payload["allowed_roles"])):
                _fail("repair_disclosure_permission")
            if self._now() >= min(returned["until"],consent.payload["expires_at"],consent.payload["consent_until"]):
                _fail("repair_access_expired")
            subject=dict(authority_kind="ack.disclosure",authority_sha256=consent.ref.raw_sha256)
            obligations.append(dict(role="current.status.ack_disclosure",kind="authority",subject=subject,
                revision=consent.payload["revision"],signer=receipt_writer["signing_key"],mask=2,
                scope_id=status.status_scope(root,"authority",subject,self.policy,budget)))
        permitted={(item["signer"]["key_id"],item["kind"],item["scope_id"]) for item in obligations}
        for observed in known:
            issuer=observed.payload["scope_key"]["issuer_key_id"]
            if any((issuer,item["scope_kind"],item["scope_id"]) not in permitted for item in observed.payload["entries"]):
                _fail("repair_status_disclosure")
        groups={}
        for item in obligations:
            if item["role"] is None:
                continue
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
                if key in present and item.get("mask",2):
                    required[key]=dict(scope_kind=item["kind"],scope_id=item["scope_id"],document_revision=item["revision"],operation_mask=2)
            observed=status.verify_status_original(dict(raw=originals[ref],ref=ref.as_dict()),expected_root=root,
                expected_signing_key=group["signer"],at=self._now(),allowed_scopes=[dict(scope_kind=item["kind"],scope_id=item["scope_id"]) for item in allowed],
                required=list(required.values()),policy=self.policy,budget=budget,
                on_authenticated=getattr(self,"status_observer",None))
            checked.append(observed)
        historical=source.statuses if extra_source is None else (*source.statuses,*extra_source.statuses)
        if occupied_source is not None:
            historical=(*historical,*occupied_source.statuses)
        self._floors((*historical,*known),checked,obligations)
        return tuple(checked)


@dataclass(frozen=True, slots=True)
class RecoveredMailboxRootProof:
    source: object
    proof: proof.AuthenticatedBootstrapProof
    current_statuses: tuple
    originals: object
    metrics: object


class MailboxRootRecoveryClient(AckOwnerRecoveryClient):
    """Recover B's original mailbox directory from independently retained S1."""
    def recover(self, base_url, *, target_node_entry, expected_target, expected_root,
                root_entry, read_entry, bootstrap_entry, known_statuses=(), archive_statuses=(), timeout=30):
        from memory_vault_open_repair_mailbox_root import verify_mailbox_root_bootstrap, verify_mailbox_root_source_event
        if type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0<timeout<=60:
            _fail("repair_invalid_deadline")
        budget=wire.RepairBudget(self.policy);started=self._now();deadline=time.monotonic()+timeout
        expected=wire.build_new_wire(dict(root=expected_root,target=expected_target),self.policy,budget).value
        root,target=expected["root"],expected["target"]
        setup=verify_mailbox_root_bootstrap(dict(root=root_entry,read=read_entry,bootstrap=bootstrap_entry),
            expected_root=root,expected_owner=self.subject,limit_policy=self.limits,at=started,policy=self.policy,budget=budget)
        raw,ref=ack._entry(target_node_entry)
        node=original.verify_original_control(raw,expected_signing_key=target["signing_key"],expected_schema="memory-vault-open-control/v1",
            expected_kind="node",at=started,policy=self.policy,budget=budget)
        original._node_shape(node,started,budget)
        if len(node.document.raw)!=ref.size or node.raw_sha256!=ref.raw_sha256:
            _fail("repair_ref_mismatch")
        if endpoint(base_url,allow_loopback=self.allow_loopback)!=endpoint(node.payload["base_url"],allow_loopback=self.allow_loopback):
            _fail("repair_proof_mismatch")
        grant=setup["bootstrap"].payload
        retained=self._retained_inputs(known_statuses,archive_statuses,budget)
        known=[]
        for entry in retained:
            parsed=original.parse_original_control(entry["raw"],self.policy,budget)
            p=status._fields(status._fields(parsed.value,{"payload","proof"})["payload"],status._PAYLOAD)
            signer=p["signing_key"]
            if signer not in (self.subject["signing_key"],target["signing_key"]) or p["issued_at"]>started:
                _fail("repair_status_mismatch")
            values=self._status_entries(p)
            permitted={"authority","catalog","mailbox_slot"} if signer==self.subject["signing_key"] else {"resource"}
            if any(v["scope_kind"] not in permitted for v in values):
                _fail("repair_status_disclosure")
            observed=status.authenticate_status_original(entry,expected_root=root,expected_signing_key=signer,at=p["issued_at"],
                allowed_scopes=[dict(scope_kind=v["scope_kind"],scope_id=v["scope_id"]) for v in values],
                policy=self.policy,budget=budget,on_authenticated=self.status_observer)
            known.append(observed)
            if any(v["status"]=="revoked" and v["operation_mask"]&10 for v in observed.payload["entries"]):
                _fail("repair_authority_revoked")
        expiry=min(started+min(60,max(1,int(timeout))),node.payload["expires_at"],grant["probe_until"],grant["proof_until"],
            *(v.payload["expires_at"] for v in setup.values()))
        if expiry<=started:
            _fail("repair_access_expired")
        binding=dict(expected_subject=self.subject,expected_target=target,target_storage_epoch=node.payload["storage_epoch"],
            bootstrap_grant_sha256=setup["bootstrap"].ref.raw_sha256,selector=grant["selector"],consumer="mailbox_root",policy=self.policy,budget=budget)
        requests,wire_bytes,proof_bytes=0,0,0
        def request(raw,child=False):
            nonlocal requests,wire_bytes
            if requests>=grant["limits"]["max_requests"] or time.monotonic()>=deadline:
                _fail("repair_over_budget")
            requests+=1
            value=self.transport.request_repair(base_url,raw,child=child,deadline=deadline)
            if type(value) is not bytes or not 0<len(value)<=proof.MAX_RESPONSE_BYTES:
                _fail("repair_invalid_response")
            wire_bytes+=len(raw)+len(value)
            return value
        outgoing=probe.make_bootstrap_probe(self.identity,**binding,at=started,expires_at=expiry)
        if len(outgoing.original.raw)>grant["limits"]["max_probe_bytes"]:
            _fail("repair_over_budget")
        challenge_raw=request(outgoing.original.raw);digest=budget._hash(challenge_raw)
        challenge=dict(raw=challenge_raw,ref=wire.RawRef("meta",digest,digest,len(challenge_raw)).as_dict())
        answer=probe.solve_bootstrap_challenge(_entry(outgoing.original),challenge,signer=self.identity,encryption_identity=self.encryption_identity,
            target_nonce=outgoing.nonce,**binding,at=self._now(),expires_at=expiry)
        response=request(answer.raw)
        held=proof.verify_bootstrap_proof_response(response,expected_subject=self.subject,expected_target=target,
            target_storage_epoch=node.payload["storage_epoch"],selector=grant["selector"],bootstrap_grant_ref=setup["bootstrap"].ref.as_dict(),
            probe_ref=outgoing.original.ref.as_dict(),challenge_ref=challenge["ref"],answer_ref=answer.ref.as_dict(),at=self._now(),
            max_proof_items=grant["limits"]["max_proof_items"],max_proof_bytes=grant["limits"]["max_proof_bytes"],
            expected_source_state="root",consumer="mailbox_root",policy=self.policy,budget=budget)
        proof_bytes=len(response)+len(held.handle.raw)+len(held.manifest.raw)
        originals,roles={},{}
        for item in held.manifest.value["children"]:
            reference=wire.raw_ref(item["ref"]);roles.setdefault(item["role"],[]).append(reference)
            if reference in originals:
                continue
            if reference.size>self.policy.max_document_bytes or proof_bytes+reference.size>grant["limits"]["max_proof_bytes"]:
                _fail("repair_over_budget")
            chunks=[];offset=0
            while offset<reference.size:
                count=min(proof.MAX_CHILD_BYTES,reference.size-offset)
                child=proof.make_bootstrap_child_request(self.identity,held,subject=self.subject,target=target,at=self._now(),
                    expires_at=held.handle.payload["expires_at"],child_index=item["index"],offset=offset,requested_bytes=count,policy=self.policy,budget=budget)
                value=request(child.raw,True)
                if len(value)!=count:
                    _fail("repair_ref_mismatch")
                budget._bytes("input_bytes",len(value));chunks.append(value);offset+=count
            budget._bytes("output_bytes",reference.size);assembled=b"".join(chunks)
            if budget._hash(assembled)!=reference.raw_sha256:
                _fail("repair_ref_mismatch")
            originals[reference]=assembled;proof_bytes+=len(assembled)
        def entry(reference):
            return dict(raw=originals[reference],ref=reference.as_dict())
        resolver=wire.LocalRawResolver(self.policy,budget)
        for reference in roles["history.raw_pack"]:
            if resolver.put(reference.namespace,reference.key,originals[reference]).ref!=reference:
                _fail("repair_ref_mismatch")
        source=verify_mailbox_root_source_event(entry(roles["history.mailbox_root"][0]),resolver,entry(roles["root.custody"][0]),
            expected_root=root,expected_owner=self.subject,expected_target=target,target_storage_epoch=node.payload["storage_epoch"],
            limit_policy=self.limits,policy=self.policy,budget=budget)
        for name in setup:
            if source["setup"]["originals"][name].ref!=setup[name].ref or source["setup"]["originals"][name].raw!=setup[name].raw:
                _fail("repair_proof_mismatch")
        # The service plan must contain exactly the already verified history
        # objects, plus its current observations and the finite wrapper objects.
        actual={(role,ref) for role,refs in roles.items() for ref in refs if not role.startswith("current.status.")}
        wanted={(v.role,v.original.ref) for v in source["manifest"].roles}
        wanted.update(("history.raw_pack",wire.raw_ref(v["pack_ref"])) for v in source["manifest"].manifest.value["roles"])
        wanted.update((role,ref) for role in ("history.mailbox_root","root.custody") for ref in roles[role])
        if actual!=wanted:
            _fail("repair_proof_mismatch")
        obligations=[dict(v,role=v["role"].replace("historical.","current.",1),mask=v["bits"]) for v in source["obligations"]]
        current,covered=[],set()
        permitted_scopes={(v["signer"]["key_id"],v["kind"],v["scope_id"]) for v in obligations}
        for observed in known:
            if any((observed.payload["signing_key"]["key_id"],v["scope_kind"],v["scope_id"]) not in permitted_scopes for v in observed.payload["entries"]):
                _fail("repair_status_disclosure")
        for role,refs in roles.items():
            if not role.startswith("current.status."):
                continue
            for reference in refs:
                p=original.parse_original_control(originals[reference],self.policy,budget).value["payload"]
                permitted=[v for v in obligations if v["signer"]==p["signing_key"]]
                values=self._status_entries(p);present={(v["scope_kind"],v["scope_id"]) for v in values}
                matched=[v for v in permitted if v["role"]==role and (v["kind"],v["scope_id"]) in present]
                if not matched:
                    _fail("repair_status_disclosure")
                observed=status.verify_status_original(entry(reference),expected_root=root,expected_signing_key=matched[0]["signer"],at=self._now(),
                    allowed_scopes=[dict(scope_kind=v["kind"],scope_id=v["scope_id"]) for v in permitted],
                    required=[dict(scope_kind=v["kind"],scope_id=v["scope_id"],document_revision=v["revision"],operation_mask=v["mask"])
                        for v in permitted if (v["kind"],v["scope_id"]) in present],policy=self.policy,budget=budget,on_authenticated=self.status_observer)
                current.append(observed);covered.update((v["role"],v["kind"],v["scope_id"]) for v in matched)
        if covered!={(v["role"],v["kind"],v["scope_id"]) for v in obligations}:
            _fail("repair_status_missing")
        self._floors((*known,*source["statuses"]),current,obligations)
        if self._now()>=min(held.handle.payload["expires_at"],source["read_until"],source["retain_until"]) or time.monotonic()>=deadline:
            _fail("repair_access_expired")
        verify_mailbox_root_bootstrap(dict(root=root_entry,read=read_entry,bootstrap=bootstrap_entry),expected_root=root,
            expected_owner=self.subject,limit_policy=self.limits,at=self._now(),policy=self.policy,budget=budget)
        return RecoveredMailboxRootProof(MappingProxyType(source),held,tuple(current),MappingProxyType(originals),
            MappingProxyType(dict(requests=requests,wire_bytes=wire_bytes,proof_bytes=proof_bytes,**budget.snapshot())))


class MailboxSetupBuilder:
    """Recipient-side original setup documents; never sends private keys.

    The caller persists the public plan and exact returned originals before
    sending them. Only a verified custody/recovery result establishes readiness.
    All capacities, lifetimes and the permitted sender are explicit inputs.
    """
    def __init__(self, identity, encryption_identity, plan, *, policy=DEFAULT_POLICY):
        import memory_vault_open_repair_resource as resource
        import memory_vault_open_repair_history as history
        self.identity,self.policy=identity,policy
        self.owner=dict(signing_key=identity.public_descriptor(),encryption_key=encryption_identity.public_descriptor())
        budget=wire.RepairBudget(policy)
        self.plan=wire.build_new_wire(plan,policy,budget).value
        p=resource._fields(self.plan,{"root_key","slot_key","sender","target","budget","windows","limits","max_appends","max_live_items"})
        history._slot(p["slot_key"],p["root_key"]);history._dual(p["sender"])
        target=resource._dual_key(p["target"],budget)
        if (p["root_key"]["root_kind"]!="mailbox" or p["root_key"]["owner"]!=resource._dual_key(self.owner,budget)
                or p["slot_key"]["writer"]!=target):
            _fail("repair_mailbox_root_mismatch")
        resource._budget(p["budget"]);resource._windows(p["windows"]);bootstrap._limits(p["limits"])
        if not 1<=wire.u53(p["max_live_items"])<=wire.u53(p["max_appends"])<=65536 or p["max_live_items"]>p["budget"]["max_items"]:
            _fail("repair_invalid_resource")
        for name,parents in bootstrap._PARENT_CAPS.items():
            if any(p["limits"][name]>p["budget"][key] for key in parents):
                _fail("repair_invalid_resource")

    def _sign(self, kind, fields, at, until, budget):
        wire.u53(at);wire.u53(until)
        if at>=until:
            _fail("repair_resource_expired")
        payload=dict(schema_version=proof.SCHEMA,kind=kind,signing_key=self.owner["signing_key"],
            issued_at=at,expires_at=until,**fields)
        return _entry(probe._sign(wire.build_new_wire(payload,self.policy,budget).value,self.identity,self.policy,budget))

    def _id(self, name):
        import hashlib
        # Stable across a caller-persisted plan retry, without exposing root ids
        # as global resource locators or changing an already returned original.
        root=wire.build_new_wire(self.plan["root_key"],self.policy,wire.RepairBudget(self.policy)).raw
        return name+"_"+hashlib.sha256(b"memory-vault-mailbox-setup/v1\0"+root+b"\0"+name.encode()).hexdigest()

    def allocation_requests(self, *, at, expires_at):
        import memory_vault_open_repair_resource as resource
        p=self.plan;budget=wire.RepairBudget(self.policy)
        if not at<expires_at<=min(p["windows"].values()):
            _fail("repair_resource_expired")
        result={}
        for purpose in ("anchor_catalog","feed_metadata","mailbox_data"):
            intent=dict(kind="resource.owner_intent",allocation_id=self._id(purpose),root_key=p["root_key"],owner=self.owner,
                target=p["target"],target_storage_epoch=p["slot_key"]["writer_storage_epoch"],purpose=purpose,budget=p["budget"],windows=p["windows"])
            digest=budget._hash(wire.build_new_wire(intent,self.policy,budget).raw)
            result[purpose]=self._sign("resource.allocate",dict(request_id=self._id("allocate_"+purpose),
                target_node_key_id=p["target"]["signing_key"]["key_id"],target_storage_epoch=p["slot_key"]["writer_storage_epoch"],
                intent=intent,intent_sha256=digest),at,expires_at,budget)
        return result

    def allocation_packet(self, allocations):
        from memory_vault_open_repair_bind import encode_entry
        import memory_vault_open_repair_resource as resource
        purposes=("anchor_catalog","feed_metadata","mailbox_data")
        resource._fields(allocations,set(purposes))
        budget=wire.RepairBudget(self.policy)
        return wire.build_new_wire(dict(schema_version=proof.SCHEMA,kind="mailbox.source_allocate",
            owner=self.owner,allocations=[encode_entry(allocations[name],self.policy,budget) for name in purposes]),
            self.policy,budget).raw

    def _offers(self, allocations, offers, at, budget):
        import memory_vault_open_repair_resource as resource
        import memory_vault_open_repair_history as history
        purposes={"anchor_catalog","feed_metadata","mailbox_data"}
        resource._fields(allocations,purposes);resource._fields(offers,purposes)
        result={}
        for purpose in sorted(purposes):
            value=resource._fields(offers[purpose],{"raw","ref"});ref=resource._ref(value["ref"])
            parsed=wire.parse_new_wire(value["raw"],self.policy,budget)
            if len(parsed.raw)!=ref.size or budget._hash(parsed.raw)!=ref.raw_sha256:
                _fail("repair_ref_mismatch")
            signed=resource._fields(parsed.value,{"payload","proof"})
            payload=resource._fields(signed["payload"],resource.COMMON|set(resource._FIELDS[1].split()))
            original._verify_control_signature(payload,signed["proof"],self.plan["target"]["signing_key"],budget)
            intent=payload["intent"]
            expected_intent=dict(kind="resource.owner_intent",allocation_id=self._id(purpose),root_key=self.plan["root_key"],
                owner=self.owner,target=self.plan["target"],target_storage_epoch=self.plan["slot_key"]["writer_storage_epoch"],
                purpose=purpose,budget=self.plan["budget"],windows=self.plan["windows"])
            allocation=resource._fields(allocations[purpose],{"raw","ref"})
            allocation_ref=resource._ref(wire.build_new_wire(allocation["ref"],self.policy,budget).value)
            allocation_doc=wire.parse_new_wire(allocation["raw"],self.policy,budget)
            if len(allocation_doc.raw)!=allocation_ref.size or budget._hash(allocation_doc.raw)!=allocation_ref.raw_sha256:
                _fail("repair_ref_mismatch")
            allocation_signed=resource._fields(allocation_doc.value,{"payload","proof"})
            ap=resource._fields(allocation_signed["payload"],resource.COMMON|set(resource._FIELDS[0].split()))
            original._verify_control_signature(ap,allocation_signed["proof"],self.owner["signing_key"],budget)
            resource._lifetime(ap)
            if (ap["schema_version"]!=resource.SCHEMA or ap["kind"]!="resource.allocate" or ap["intent"]!=expected_intent
                    or ap["intent_sha256"]!=payload["intent_sha256"] or ap["target_node_key_id"]!=self.plan["target"]["signing_key"]["key_id"]
                    or ap["target_storage_epoch"]!=self.plan["slot_key"]["writer_storage_epoch"]
                    or not ap["issued_at"]<=payload["issued_at"]<ap["expires_at"]
                    or payload["reservation_until"]>ap["expires_at"]):
                _fail("repair_resource_mismatch")
            if (payload["schema_version"]!=resource.SCHEMA or payload["kind"]!="resource.offer" or intent!=expected_intent
                    or payload["intent_sha256"]!=budget._hash(wire.build_new_wire(expected_intent,self.policy,budget).raw)
                    or payload["allocation_request_ref"]!=allocations[purpose]["ref"]
                    or payload["target_encryption_key"]!=self.plan["target"]["encryption_key"]
                    or payload["budget"]!=self.plan["budget"] or payload["windows"]!=self.plan["windows"]
                    or not wire.u53(payload["issued_at"])<=at<wire.u53(payload["reservation_until"])):
                _fail("repair_resource_mismatch")
            history._resource(payload["resource"]);wire.u53(payload["reservation_generation"],1)
            if (payload["resource"]["node_key_id"]!=self.plan["target"]["signing_key"]["key_id"]
                    or payload["resource"]["storage_epoch"]!=self.plan["slot_key"]["writer_storage_epoch"]):
                _fail("repair_resource_mismatch")
            result[purpose]=dict(raw=parsed.raw,ref=ref.as_dict(),payload=payload)
        return result

    def slot_documents(self, allocations, offers, *, at, expires_at):
        import memory_vault_open_repair_history as history
        from memory_vault_open_repair_mailbox_activation import verify_mailbox_slot_owner_inputs
        p=self.plan;budget=wire.RepairBudget(self.policy);held=self._offers(allocations,offers,at,budget)
        result={};owner=probe._dual(self.owner);target=probe._dual(p["target"])
        def add(name,kind,**fields):
            result[name]=self._sign(kind,fields,at,expires_at,budget)
        add("maintenance","mailbox.maintenance_root",root_key=p["root_key"],authority_id=self._id("maintenance"),slot_key=p["slot_key"],
            sender=p["sender"],recipient=owner,maintainers=[target],operation_mask=127,
            allowed_roles=sorted(["bootstrap.grant","mailbox.slot","mailbox.read_grant","mailbox.maintenance_root","selected_slot_service_v1"]),
            budget=p["budget"],windows=p["windows"],max_delegate_depth=2,max_destinations_per_job=2,max_concurrent_jobs=1,revision=1)
        add("read","mailbox.read_grant",grant_id=self._id("slot_read"),root_key=p["root_key"],slot_key=p["slot_key"],reader=owner,
            serving_authority_id=self._id("maintenance"),operation_mask=2,budget=p["budget"],windows=p["windows"],revision=1)
        feed=dict(namespace="feed",key=budget._hash(wire._canonical(p["slot_key"],budget)))
        data,metadata=held["mailbox_data"],held["feed_metadata"]
        add("slot","mailbox.slot",revision=1,slot_key=p["slot_key"],feed_ref=feed,sender=p["sender"],recipient=owner,
            data_resource_ref=data["payload"]["resource"],data_resource_offer_ref=data["ref"],metadata_resource_ref=metadata["payload"]["resource"],
            metadata_resource_offer_ref=metadata["ref"],read_grant_ref=result["read"]["ref"],maintenance_root_ref=result["maintenance"]["ref"],
            max_appends=p["max_appends"],max_live_items=p["max_live_items"],budget=p["budget"],windows=p["windows"])
        add("bootstrap","bootstrap.grant",grant_id=self._id("slot_bootstrap"),revision=1,owner=owner,subject=owner,root_key=p["root_key"],
            consumer="mailbox_feed",selector=dict(root_key_sha256=budget._hash(wire._canonical(p["root_key"],budget)),
                slot_key_sha256=budget._hash(wire._canonical(p["slot_key"],budget)),feed_ref=feed,slot_sha256=result["slot"]["ref"]["raw_sha256"],
                read_grant_sha256=result["read"]["ref"]["raw_sha256"],maintenance_root_sha256=result["maintenance"]["ref"]["raw_sha256"]),
            parent_authority_ref=result["maintenance"]["ref"],caller_authority_ref=result["read"]["ref"],probe_until=expires_at,proof_until=expires_at,
            upload_until=expires_at,probe_profile="opaque_v1",response_profile="selected_slot_service_v1",upload_roles=["bootstrap.grant"],limits=p["limits"])
        add("activation","resource.activation",activation_id=self._id("slot_activation"),subject=self.owner,
            target_node_key_id=p["target"]["signing_key"]["key_id"],target_storage_epoch=p["slot_key"]["writer_storage_epoch"],root_key=p["root_key"],
            scope=dict(kind="mailbox_slot",slot_key=p["slot_key"],slot_ref=result["slot"]["ref"]),
            resource_offer_refs=sorted([data["ref"],metadata["ref"]],key=history._ref_tuple),
            authority_refs=[dict(role=kind,ref=result[name]["ref"]) for name,kind in
                (("maintenance","mailbox.maintenance_root"),("read","mailbox.read_grant"),("slot","mailbox.slot"))])
        verify_mailbox_slot_owner_inputs(result,expected_slot=p["slot_key"],expected_owner=self.owner,expected_target=p["target"],
            target_storage_epoch=p["slot_key"]["writer_storage_epoch"],offers={name:dict(raw=v["raw"],ref=v["ref"]) for name,v in (("data",data),("metadata",metadata))},
            limit_policy=p["limits"],at=at,policy=self.policy,budget=budget)
        return result

    def root_documents(self, allocations, offers, slot_entries, slot_result, *, at, expires_at):
        import memory_vault_open_repair_resource as resource
        import memory_vault_open_repair_history as history
        from memory_vault_open_repair_mailbox_activation import verify_mailbox_slot_owner_inputs, verify_mailbox_genesis
        from memory_vault_open_repair_mailbox_root import verify_mailbox_root_bootstrap
        p=self.plan;budget=wire.RepairBudget(self.policy);held=self._offers(allocations,offers,at,budget)
        resource._fields(slot_result,{"data","metadata","checkpoint","head"})
        checked=verify_mailbox_slot_owner_inputs(slot_entries,expected_slot=p["slot_key"],expected_owner=self.owner,expected_target=p["target"],
            target_storage_epoch=p["slot_key"]["writer_storage_epoch"],offers={name:dict(raw=held[purpose]["raw"],ref=held[purpose]["ref"])
                for name,purpose in (("data","mailbox_data"),("metadata","feed_metadata"))},limit_policy=p["limits"],at=at,policy=self.policy,budget=budget)
        activation=checked["activation"].payload;times=[]
        for name,purpose in (("data","mailbox_data"),("metadata","feed_metadata")):
            verified=resource.verify_mailbox_resource_inputs(dict(allocate=allocations[purpose],offer=offers[purpose],activation=slot_entries["activation"],active=slot_result[name]),
                expected_root=p["root_key"],expected_owner=self.owner,expected_target=p["target"],target_storage_epoch=p["slot_key"]["writer_storage_epoch"],
                expected_purpose=purpose,expected_scope=activation["scope"],expected_authority_refs=activation["authority_refs"],
                expected_offer_refs=activation["resource_offer_refs"],at=at,policy=self.policy,budget=budget)
            times.append(verified["active"].payload["activated_at"])
        if times[0]!=times[1]:
            _fail("repair_mailbox_slot_incomplete")
        verify_mailbox_genesis({name:slot_result[name] for name in ("head","checkpoint")},expected_slot=p["slot_key"],
            expected_signing_key=p["target"]["signing_key"],committed_at=times[0],at=at,policy=self.policy,budget=budget)
        result={};owner=probe._dual(self.owner);anchor=held["anchor_catalog"]
        def add(name,kind,**fields):
            result[name]=self._sign(kind,fields,at,expires_at,budget)
        add("root","mailbox.root_authority",root_key=p["root_key"],authority_id=self._id("root"),original_resource_ref=anchor["payload"]["resource"],
            original_resource_offer_ref=anchor["ref"],slot_ids=[p["slot_key"]["slot_id"]],maintainers=[probe._dual(p["target"])],operation_mask=127,
            allowed_roles=["bootstrap.grant","mailbox.root_authority","mailbox.root_read_grant","mailbox_root_service_v1"],budget=p["budget"],windows=p["windows"],
            max_delegate_depth=2,max_destinations_per_job=2,max_concurrent_jobs=1,revision=1)
        add("read","mailbox.root_read_grant",grant_id=self._id("root_read"),root_key=p["root_key"],reader=owner,root_authority_ref=result["root"]["ref"],
            operation_mask=2,budget=p["budget"],windows=p["windows"],revision=1)
        add("catalog","mailbox.catalog",root_key=p["root_key"],revision=1,slot_refs=[checked["slot"].ref.as_dict()],root_authority_ref=result["root"]["ref"])
        add("bootstrap","bootstrap.grant",grant_id=self._id("root_bootstrap"),revision=1,owner=owner,subject=owner,root_key=p["root_key"],consumer="mailbox_root",
            selector=dict(root_key_sha256=budget._hash(wire._canonical(p["root_key"],budget)),anchor_ref=p["root_key"]["anchor_ref"],
                root_authority_sha256=result["root"]["ref"]["raw_sha256"],read_grant_sha256=result["read"]["ref"]["raw_sha256"]),
            parent_authority_ref=result["root"]["ref"],caller_authority_ref=result["read"]["ref"],probe_until=expires_at,proof_until=expires_at,upload_until=expires_at,
            probe_profile="opaque_v1",response_profile="mailbox_root_service_v1",upload_roles=["bootstrap.grant"],limits=p["limits"])
        refs=[dict(role=kind,ref=result[name]["ref"]) for name,kind in (("root","mailbox.root_authority"),("read","mailbox.root_read_grant"),("catalog","mailbox.catalog"))]
        refs += [dict(role=kind,ref=checked[name].ref.as_dict()) for name,kind in (("slot","mailbox.slot"),("read","mailbox.read_grant"),("maintenance","mailbox.maintenance_root"))]
        refs.sort(key=lambda v:(v["role"],*history._ref_tuple(v["ref"])))
        add("activation","resource.activation",activation_id=self._id("root_activation"),subject=self.owner,target_node_key_id=p["target"]["signing_key"]["key_id"],
            target_storage_epoch=p["slot_key"]["writer_storage_epoch"],root_key=p["root_key"],
            scope=dict(kind="mailbox_root",root_key=p["root_key"],root_authority_ref=result["root"]["ref"],catalog_ref=result["catalog"]["ref"]),
            resource_offer_refs=[anchor["ref"]],authority_refs=refs)
        verify_mailbox_root_bootstrap({name:result[name] for name in ("root","read","bootstrap")},expected_root=p["root_key"],expected_owner=self.owner,
            limit_policy=p["limits"],at=at,policy=self.policy,budget=budget)
        return result
