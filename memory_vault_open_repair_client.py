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

    def activation_packet(self, stage, entries, *, at, expires_at):
        from memory_vault_open_repair_bind import encode_entry
        if stage not in ("slot","root"):
            _fail("repair_remote_setup_mismatch")
        budget=wire.RepairBudget(self.policy)
        return self._sign("mailbox.source_"+stage,dict(owner=self.owner,root_key=self.plan["root_key"],
            slot_key=self.plan["slot_key"],entries={name:encode_entry(value,self.policy,budget) for name,value in entries.items()}),
            at,expires_at,budget)["raw"]

    def destination_document(self, slot_entries, contact_originals, *, at, expires_at):
        from memory_vault_open_repair_mailbox_activation import FIELDS,KINDS
        import memory_vault_open_repair_resource as resource
        budget=wire.RepairBudget(self.policy);p=self.plan
        held=original.verify_contact_originals(contact_originals,sender_key_id=p["sender"]["signing_key_id"],
            sender_encryption_key_id=p["sender"]["encryption_key_id"],recipient_key_id=self.identity.key_id,
            recipient_encryption_key_id=self.owner["encryption_key"]["key_id"],node_key_id=p["target"]["signing_key"]["key_id"],
            storage_epoch=p["slot_key"]["writer_storage_epoch"],at=at,policy=self.policy,budget=budget)
        slot=None
        for name in ("slot","read","maintenance"):
            raw,ref=ack._entry(slot_entries[name]);parsed=wire.parse_new_wire(raw,self.policy,budget)
            if len(raw)!=ref.size or budget._hash(raw)!=ref.raw_sha256:_fail("repair_ref_mismatch")
            signed=resource._fields(parsed.value,{"payload","proof"})
            value=resource._fields(signed["payload"],resource.COMMON|set(FIELDS[name].split()))
            original._verify_control_signature(value,signed["proof"],self.owner["signing_key"],budget)
            if (value["schema_version"]!=proof.SCHEMA or value["kind"]!=KINDS[name] or value["slot_key"]!=p["slot_key"]
                    or not value["issued_at"]<=at<expires_at<=value["expires_at"]):_fail("repair_message_mismatch")
            if name=="slot":slot=value
        if (slot["sender"]!=p["sender"] or slot["recipient"]!=probe._dual(self.owner)
                or expires_at>held.originals["grant"].payload["expires_at"]):_fail("repair_message_mismatch")
        refs={}
        for field,role in (("contact_request_ref","request"),("contact_policy_ref","policy"),("contact_knock_lease_ref","knock_lease"),
                ("contact_decision_ref","decision"),("store_grant_ref","grant")):
            raw=held.originals[role].document.raw;digest=budget._hash(raw)
            refs[field]=dict(namespace="meta",key=digest,raw_sha256=digest,size=len(raw))
        fields={name:slot[name] for name in ("data_resource_ref","data_resource_offer_ref","metadata_resource_ref",
            "metadata_resource_offer_ref","read_grant_ref","maintenance_root_ref","budget","windows")}
        return self._sign("delivery.destination",dict(destination_id=self._id("destination"),sender=p["sender"],recipient=probe._dual(self.owner),
            slot_key=p["slot_key"],slot_ref=slot_entries["slot"]["ref"],**refs,**fields),at,expires_at,budget)

    def readiness_packet(self, owner_status, *, at, expires_at, read_until, retain_until):
        from memory_vault_open_repair_bind import encode_entry
        budget=wire.RepairBudget(self.policy)
        if not at<wire.u53(read_until)<=wire.u53(retain_until):
            _fail("repair_resource_expired")
        return self._sign("mailbox.source_ready",dict(owner=self.owner,root_key=self.plan["root_key"],
            slot_key=self.plan["slot_key"],entries=dict(owner_status=encode_entry(owner_status,self.policy,budget)),
            read_until=read_until,retain_until=retain_until),at,expires_at,budget)["raw"]

    def initial_owner_status(self, slot_entries, root_entries, *, at, valid_until, revision=1):
        """Sign current scopes of the caller's exact original setup documents."""
        from memory_vault_open_provider import issue_status
        import memory_vault_open_repair_resource as resource
        budget=wire.RepairBudget(self.policy);root=self.plan["root_key"];scopes=[]
        def add(entry, scope_kind):
            raw,ref=ack._entry(entry)
            parsed=wire.parse_new_wire(raw,self.policy,budget)
            if len(raw)!=ref.size or budget._hash(raw)!=ref.raw_sha256:
                _fail("repair_ref_mismatch")
            signed=resource._fields(parsed.value,{"payload","proof"});p=signed["payload"]
            original._verify_control_signature(p,signed["proof"],self.owner["signing_key"],budget)
            document_root=p["slot_key"]["root_key"] if scope_kind=="mailbox_slot" else p["root_key"]
            if document_root!=root or not p["issued_at"]<=at<valid_until<=p["expires_at"]:
                _fail("repair_mailbox_root_mismatch")
            subject=(dict(authority_kind=p["kind"],authority_sha256=ref.raw_sha256) if scope_kind=="authority"
                else dict(root_key=root) if scope_kind=="catalog" else p["slot_key"])
            scopes.append(dict(scope_kind=scope_kind,scope_id=status.status_scope(root,scope_kind,subject,self.policy,budget),
                minimum_document_revision=p["revision"],status="active",operation_mask=127))
        for name in ("root","read","bootstrap"):
            add(root_entries[name],"authority")
        add(root_entries["catalog"],"catalog");add(slot_entries["slot"],"mailbox_slot")
        for name in ("read","maintenance","bootstrap"):
            add(slot_entries[name],"authority")
        scopes.sort(key=lambda item:(item["scope_kind"],item["scope_id"]))
        signed=issue_status(self.identity,root=root,revision=revision,entries=scopes,issued_at=at,valid_until=valid_until)
        raw=wire.build_new_wire(signed,self.policy,budget).raw;digest=budget._hash(raw)
        return dict(raw=raw,ref=dict(namespace="meta",key=digest,raw_sha256=digest,size=len(raw)))

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


class MailboxSetupJournal:
    """Finite exact setup exchanges in the caller's existing protected database."""
    def __init__(self, db):
        self.db=db

    def _transaction(self, callback):
        if self.db.in_transaction:
            _fail("repair_setup_journal_transaction")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            result=callback();self.db.commit();return result
        except BaseException:
            self.db.rollback();raise

    def initialize(self):
        def create():
            self.db.execute('''CREATE TABLE IF NOT EXISTS open_mailbox_setup_jobs(
                job_key TEXT PRIMARY KEY,plan BLOB NOT NULL,blocked INTEGER NOT NULL DEFAULT 0)''')
            self.db.execute('''CREATE TABLE IF NOT EXISTS open_mailbox_setup_steps(
                job_key TEXT NOT NULL,stage TEXT NOT NULL,request BLOB NOT NULL,response BLOB,
                PRIMARY KEY(job_key,stage))''')
            self.db.execute('''CREATE TABLE IF NOT EXISTS open_mailbox_setup_statuses(
                job_key TEXT NOT NULL,digest TEXT NOT NULL,raw BLOB NOT NULL,
                PRIMARY KEY(job_key,digest))''')
        self._transaction(create);return self

    def start(self, job_key, plan):
        import re
        if type(job_key) is not str or re.fullmatch('[0-9a-f]{64}',job_key) is None or type(plan) is not bytes or not 0<len(plan)<=65536:
            _fail("repair_invalid_context")
        def save():
            old=self.db.execute('SELECT plan,blocked FROM open_mailbox_setup_jobs WHERE job_key=?',(job_key,)).fetchone()
            if old is not None:
                if bytes(old[0])!=plan:
                    _fail("repair_setup_journal_conflict")
                if old[1]:
                    _fail("repair_setup_journal_capacity")
                return
            if self.db.execute('SELECT count(*) FROM open_mailbox_setup_jobs').fetchone()[0]>=16:
                _fail("repair_setup_journal_capacity")
            self.db.execute('INSERT INTO open_mailbox_setup_jobs(job_key,plan) VALUES(?,?)',(job_key,plan))
        self._transaction(save)

    def _check(self, key):
        row=self.db.execute('SELECT blocked FROM open_mailbox_setup_jobs WHERE job_key=?',(key,)).fetchone()
        if row is None or row[0]:
            _fail("repair_setup_journal_unavailable")

    def step(self, key, stage, request=None, response=None):
        if stage not in ('allocate','slot','root','ready'):
            _fail("repair_invalid_context")
        for raw in (request,response):
            if raw is not None and (type(raw) is not bytes or not 0<len(raw)<=65536):
                _fail("repair_setup_journal_capacity")
        def save():
            self._check(key)
            row=self.db.execute('SELECT request,response FROM open_mailbox_setup_steps WHERE job_key=? AND stage=?',(key,stage)).fetchone()
            if row is None:
                if request is None:
                    if response is not None:_fail("repair_setup_journal_missing")
                    return None
                self.db.execute('INSERT INTO open_mailbox_setup_steps VALUES(?,?,?,?)',(key,stage,request,response))
                return request,response
            old_request,old_response=bytes(row[0]),None if row[1] is None else bytes(row[1])
            if (request is not None and request!=old_request) or (response is not None and old_response is not None and response!=old_response):
                _fail("repair_setup_journal_conflict")
            if response is not None and old_response is None:
                self.db.execute('UPDATE open_mailbox_setup_steps SET response=? WHERE job_key=? AND stage=?',(response,key,stage))
                old_response=response
            return old_request,old_response
        return self._transaction(save)

    def observe(self, key, authenticated):
        if not isinstance(authenticated,status.AuthenticatedStatusOriginal):
            _fail("repair_invalid_context")
        raw=authenticated.raw;digest=authenticated.raw_sha256
        def save():
            self._check(key)
            if self.db.execute('SELECT 1 FROM open_mailbox_setup_statuses WHERE job_key=? AND digest=?',(key,digest)).fetchone():
                return True
            count,size=self.db.execute('SELECT count(*),coalesce(sum(length(raw)),0) FROM open_mailbox_setup_statuses WHERE job_key=?',(key,)).fetchone()
            if count>=32 or size+len(raw)>262144:
                self.db.execute('UPDATE open_mailbox_setup_jobs SET blocked=1 WHERE job_key=?',(key,));return False
            self.db.execute('INSERT INTO open_mailbox_setup_statuses VALUES(?,?,?)',(key,digest,raw));return True
        if not self._transaction(save):
            _fail("repair_setup_journal_capacity")

    def statuses(self, key):
        self._check(key)
        rows=self.db.execute('SELECT digest,raw FROM open_mailbox_setup_statuses WHERE job_key=? ORDER BY digest',(key,)).fetchall()
        if len(rows)>32 or sum(len(row[1]) for row in rows)>262144:
            _fail("repair_setup_journal_capacity")
        return tuple(dict(raw=bytes(raw),ref=dict(namespace='meta',key=digest,raw_sha256=digest,size=len(raw))) for digest,raw in rows)


class MailboxSetupClient(MailboxRootRecoveryClient):
    """Provision and independently recover a mailbox using durable exact steps."""
    def provision(self, base_url, *, target_node_entry, plan, journal, setup_until, read_until, retain_until,
                  known_statuses=(), timeout=60):
        import hashlib
        from memory_vault_open_repair_bind import decode_entry
        import memory_vault_open_repair_resource as resource
        if not isinstance(journal,MailboxSetupJournal) or type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0<timeout<=60:
            _fail("repair_invalid_context")
        builder=MailboxSetupBuilder(self.identity,self.encryption_identity,plan,policy=self.policy)
        p=builder.plan;budget=wire.RepairBudget(self.policy);started=self._now();deadline=time.monotonic()+timeout
        if not 0<wire.u53(setup_until)<=wire.u53(read_until)<=wire.u53(retain_until)<=min(p['windows'].values()) or started>=read_until:
            _fail("repair_resource_expired")
        raw,ref=ack._entry(target_node_entry)
        node=original.verify_original_control(raw,expected_signing_key=p['target']['signing_key'],expected_schema='memory-vault-open-control/v1',
            expected_kind='node',at=started,policy=self.policy,budget=budget)
        original._node_shape(node,started,budget)
        base=base_url;address=endpoint(base_url,allow_loopback=self.allow_loopback)
        if (len(raw)!=ref.size or node.raw_sha256!=ref.raw_sha256 or node.payload['storage_epoch']!=p['slot_key']['writer_storage_epoch']
                or address!=endpoint(node.payload['base_url'],allow_loopback=self.allow_loopback)):
            _fail('repair_proof_mismatch')
        binding=wire.build_new_wire(dict(base_url=base,owner=self.subject,plan=p,setup_until=setup_until,
            read_until=read_until,retain_until=retain_until),self.policy,budget).raw
        key=hashlib.sha256(wire.build_new_wire(dict(owner=self.subject,root_key=p['root_key']),self.policy,budget).raw).hexdigest()
        journal.initialize();journal.start(key,binding)
        for entry in (*known_statuses,*journal.statuses(key)):
            preview=original.parse_original_control(entry['raw'],self.policy,budget)
            payload=status._fields(status._fields(preview.value,{'payload','proof'})['payload'],status._PAYLOAD)
            signer=payload['signing_key']
            if signer not in (self.subject['signing_key'],p['target']['signing_key']) or payload['issued_at']>started:
                _fail('repair_status_mismatch')
            values=self._status_entries(payload)
            authenticated=status.authenticate_status_original(entry,expected_root=p['root_key'],expected_signing_key=signer,
                at=payload['issued_at'],allowed_scopes=[dict(scope_kind=v['scope_kind'],scope_id=v['scope_id']) for v in values],
                policy=self.policy,budget=budget,on_authenticated=lambda item:journal.observe(key,item))
            if any(v['status']=='revoked' for v in authenticated.payload['entries']):
                _fail('repair_authority_revoked')
        def parse(raw):
            return wire.parse_new_wire(raw,self.policy,wire.RepairBudget(self.policy)).value
        def decode(values):
            meter=wire.RepairBudget(self.policy)
            return {name:decode_entry(value,self.policy,meter) for name,value in values.items()}
        def exchange(stage,make):
            saved=journal.step(key,stage)
            if saved is None:
                packet=make();saved=journal.step(key,stage,request=packet)
            packet,response=saved
            if response is None:
                if time.monotonic()>=deadline:_fail('repair_probe_expired')
                response=self.transport.request_repair(base,packet,deadline=deadline)
                value=parse(response)
                if stage=='allocate':
                    resource._fields(value,{'schema_version','kind','root_key','offers'})
                    if value['kind']!='mailbox.source_offers' or value['root_key']!=p['root_key']:_fail('repair_proof_mismatch')
                else:
                    resource._fields(value,{'schema_version','kind','request_sha256','originals'})
                    if value['kind']!='mailbox.source_'+stage+'_active' or value['request_sha256']!=hashlib.sha256(packet).hexdigest():
                        _fail('repair_proof_mismatch')
                if value['schema_version']!=proof.SCHEMA:_fail('repair_proof_mismatch')
                journal.step(key,stage,response=response)
            return parse(packet),parse(response)
        request,response=exchange('allocate',lambda:builder.allocation_packet(builder.allocation_requests(at=self._now(),expires_at=setup_until)))
        allocations={}
        for entry in request['allocations']:
            item=decode_entry(entry,self.policy,wire.RepairBudget(self.policy))
            allocations[parse(item['raw'])['payload']['intent']['purpose']]=item
        offers=decode(response['offers'])
        request,response=exchange('slot',lambda:builder.activation_packet('slot',builder.slot_documents(allocations,offers,
            at=self._now(),expires_at=min(p['windows'].values())),at=self._now(),expires_at=setup_until))
        slot_entries=decode(request['payload']['entries']);slot_result=decode(response['originals'])
        request,response=exchange('root',lambda:builder.activation_packet('root',builder.root_documents(allocations,offers,slot_entries,slot_result,
            at=self._now(),expires_at=min(p['windows'].values())),at=self._now(),expires_at=setup_until))
        root_entries=decode(request['payload']['entries'])
        def ready():
            state=builder.initial_owner_status(slot_entries,root_entries,at=self._now(),valid_until=read_until)
            return builder.readiness_packet(state,at=self._now(),expires_at=setup_until,read_until=read_until,retain_until=retain_until)
        request,response=exchange('ready',ready)
        owner_status=decode(request['payload']['entries'])['owner_status'];custody=decode(response['originals'])['custody']
        def observed(item):
            journal.observe(key,item)
            if self.status_observer is not None:self.status_observer(item)
        client=MailboxRootRecoveryClient(self.identity,self.encryption_identity,policy=self.policy,limit_policy=self.limits,
            allow_loopback=self.allow_loopback,transport=self.transport,clock=self.clock,status_observer=observed)
        remaining=deadline-time.monotonic()
        if remaining<=0:_fail('repair_probe_expired')
        result=client.recover(base,target_node_entry=target_node_entry,expected_target=p['target'],expected_root=p['root_key'],
            **{name+'_entry':root_entries[name] for name in ('root','read','bootstrap')},
            known_statuses=(*known_statuses,owner_status),archive_statuses=journal.statuses(key),timeout=min(60,remaining))
        if result.source['custody'].raw!=custody['raw'] or result.source['custody'].ref.as_dict()!=custody['ref']:
            _fail('repair_proof_mismatch')
        return result


class MailboxMessageDraftStore:
    """Persist one immutable outgoing E and its sender's repair consent.

    This is a sender draft, not admission, sender dual possession, current
    resource permission or custody. The node must check those before storage.
    """
    def __init__(self, db, identity, encryption_identity, *, policy=DEFAULT_POLICY):
        self.db,self.identity,self.encryption_identity,self.policy=db,identity,encryption_identity,policy

    def prepare(self, envelope_raw, *, recipient, slot_entries, destination_entry, contact_originals,
                at, attempt_until, consent_until):
        import hashlib
        from memory_vault import canonical_bytes
        from memory_vault_open_delivery import verify_envelope,MAX_ENVELOPE_BYTES
        import memory_vault_open_repair_history as history
        import memory_vault_open_repair_resource as resource
        from memory_vault_open_repair_bind import encode_entry,decode_entry
        budget=wire.RepairBudget(self.policy)
        if type(envelope_raw) is not bytes or not 0<len(envelope_raw)<=MAX_ENVELOPE_BYTES:
            _fail('repair_invalid_message')
        sender=dict(signing_key=self.identity.public_descriptor(),encryption_key=self.encryption_identity.public_descriptor())
        sender_ids=resource._dual_key(sender,budget);recipient_ids=resource._dual_key(recipient,budget)
        envelope=verify_envelope(envelope_raw,sender_signing_key=sender['signing_key'],sender_encryption_key=sender['encryption_key'],
            recipient_signing_key=recipient['signing_key'],recipient_encryption_key=recipient['encryption_key'],now=at)
        context=envelope['context'];reference=dict(namespace='object',key=context['object_ref']['key'],
            raw_sha256=hashlib.sha256(envelope_raw).hexdigest(),size=len(envelope_raw))
        def check(entry,kind,fields):
            raw,ref=ack._entry(entry);parsed=wire.parse_new_wire(raw,self.policy,budget)
            if len(raw)!=ref.size or budget._hash(raw)!=ref.raw_sha256:_fail('repair_ref_mismatch')
            signed=resource._fields(parsed.value,{'payload','proof'})
            payload=resource._fields(signed['payload'],resource.COMMON|set(fields.split()))
            if payload['schema_version']!=proof.SCHEMA or payload['kind']!=kind:_fail('repair_invalid_message')
            original._verify_control_signature(payload,signed['proof'],recipient['signing_key'],budget)
            resource._lifetime(payload)
            return payload
        from memory_vault_open_repair_mailbox_activation import FIELDS,KINDS
        resource._fields(slot_entries,{'slot','read','maintenance'})
        slot=check(slot_entries['slot'],KINDS['slot'],FIELDS['slot'])
        read=check(slot_entries['read'],KINDS['read'],FIELDS['read'])
        maintenance=check(slot_entries['maintenance'],KINDS['maintenance'],FIELDS['maintenance'])
        key=slot['slot_key'];root=key['root_key'];history._slot(key,root)
        names='issued_at expires_at destination_id sender recipient contact_request_ref contact_policy_ref contact_knock_lease_ref contact_decision_ref store_grant_ref slot_key slot_ref data_resource_ref data_resource_offer_ref metadata_resource_ref metadata_resource_offer_ref read_grant_ref maintenance_root_ref budget windows'
        destination=check(destination_entry,'delivery.destination',names)
        if (root['owner']!=recipient_ids or any(p['sender']!=sender_ids or p['recipient']!=recipient_ids for p in (slot,maintenance,destination))
                or read['reader']!=recipient_ids or any(p['slot_key']!=key for p in (read,maintenance,destination))
                or read['root_key']!=root or maintenance['root_key']!=root
                or read['serving_authority_id']!=maintenance['authority_id']
                or destination['slot_ref']!=slot_entries['slot']['ref']
                or slot['read_grant_ref']!=slot_entries['read']['ref'] or slot['maintenance_root_ref']!=slot_entries['maintenance']['ref']):
            _fail('repair_message_mismatch')
        for name in ('data_resource_ref','data_resource_offer_ref','metadata_resource_ref','metadata_resource_offer_ref','read_grant_ref','maintenance_root_ref'):
            if destination[name]!=slot[name]:_fail('repair_message_mismatch')
        resource._budget(destination['budget']);resource._windows(destination['windows'])
        if any(destination['budget'][name]>slot['budget'][name] for name in destination['budget']) or any(
                destination['windows'][name]>slot['windows'][name] for name in destination['windows']):
            _fail('repair_message_mismatch')
        held=original.verify_contact_originals(contact_originals,sender_key_id=self.identity.key_id,
            sender_encryption_key_id=self.encryption_identity.key_id,recipient_key_id=recipient_ids['signing_key_id'],
            recipient_encryption_key_id=recipient_ids['encryption_key_id'],node_key_id=key['writer']['signing_key_id'],
            storage_epoch=key['writer_storage_epoch'],at=destination['issued_at'],policy=self.policy,budget=budget)
        for name,role in (('contact_request_ref','request'),('contact_policy_ref','policy'),('contact_knock_lease_ref','knock_lease'),
                ('contact_decision_ref','decision'),('store_grant_ref','grant')):
            ref=resource._ref(destination[name]);doc=held.originals[role].document
            if ref.raw_sha256!=budget._hash(doc.raw) or ref.size!=len(doc.raw):_fail('repair_ref_mismatch')
        wire.u53(at);wire.u53(attempt_until);wire.u53(consent_until)
        originals=dict(slot=slot_entries,destination=destination_entry,
            contact={name:dict(raw=raw,ref=dict(namespace='meta',key=hashlib.sha256(raw).hexdigest(),raw_sha256=hashlib.sha256(raw).hexdigest(),size=len(raw)))
                     for name,raw in contact_originals.items()})
        # Binding is independent of retry time; it preserves one exact E and
        # original authority selection instead of quietly renewing an attempt.
        binding=hashlib.sha256(canonical_bytes(dict(envelope=reference,recipient=recipient,
            slot_refs={name:value['ref'] for name,value in slot_entries.items()},destination_ref=destination_entry['ref'],
            contact_hashes={name:hashlib.sha256(raw).hexdigest() for name,raw in contact_originals.items()},
            attempt_until=attempt_until,consent_until=consent_until))).hexdigest()
        journal=MailboxSetupJournal(self.db)
        def save():
            self.db.execute('''CREATE TABLE IF NOT EXISTS open_mailbox_message_drafts(
                sender TEXT NOT NULL,message_id TEXT NOT NULL,binding TEXT NOT NULL,root_digest TEXT NOT NULL,status_revision INTEGER NOT NULL,
                envelope BLOB NOT NULL,originals BLOB NOT NULL,PRIMARY KEY(sender,message_id))''')
            old=self.db.execute('SELECT binding,envelope,originals FROM open_mailbox_message_drafts WHERE sender=? AND message_id=?',
                (self.identity.key_id,context['message_id'])).fetchone()
            if old is not None:
                if old[0]!=binding or bytes(old[1])!=envelope_raw:_fail('repair_message_conflict')
                return bytes(old[2])
            if self.db.execute('SELECT count(*) FROM open_mailbox_message_drafts').fetchone()[0]>=16:
                _fail('repair_message_capacity')
            if (not context['created_at']<=at<attempt_until<=min(destination['expires_at'],held.originals['grant'].payload['expires_at'])
                    or not at<consent_until<=min(slot['expires_at'],maintenance['expires_at'],slot['windows']['retain_until'],maintenance['windows']['retain_until'])
                    or any(not p['issued_at']<=at<p['expires_at'] for p in (slot,read,maintenance,destination))):
                _fail('repair_resource_expired')
            self.db.execute('''CREATE TABLE IF NOT EXISTS open_mailbox_message_status_revisions(
                sender TEXT NOT NULL,root_digest TEXT NOT NULL,revision INTEGER NOT NULL,PRIMARY KEY(sender,root_digest))''')
            root_digest=budget._hash(wire._canonical(root,budget))
            prior=self.db.execute('SELECT revision FROM open_mailbox_message_status_revisions WHERE sender=? AND root_digest=?',
                (self.identity.key_id,root_digest)).fetchone()
            maximum=self.db.execute('SELECT max(status_revision) FROM open_mailbox_message_drafts WHERE sender=? AND root_digest=?',
                (self.identity.key_id,root_digest)).fetchone()[0]
            if (None if prior is None else prior[0])!=maximum:_fail('repair_message_ledger_missing')
            status_revision=wire.u53((maximum or 0)+1,1)
            self.db.execute('INSERT OR REPLACE INTO open_mailbox_message_status_revisions VALUES(?,?,?)',(self.identity.key_id,root_digest,status_revision))
            def sign(kind,fields,until):
                payload=wire.build_new_wire(dict(schema_version=proof.SCHEMA,kind=kind,signing_key=sender['signing_key'],
                    issued_at=at,expires_at=until,**fields),self.policy,budget).value
                return _entry(probe._sign(payload,self.identity,self.policy,budget))
            consent=sign('message.disclosure',dict(consent_id='consent_'+binding,root_key=root,slot_key=key,sender=sender_ids,
                recipient=recipient_ids,envelope_ref=reference,maintenance_root_ref=slot_entries['maintenance']['ref'],
                allowed_roles=sorted(['contact.request','delivery.attempt','message.disclosure','authority.status.disclosure']),
                operation_mask=127,consent_until=consent_until,bootstrap_return=dict(subject=recipient_ids,consumer='mailbox_feed',
                    roles=['authority.status.disclosure','message.disclosure'],until=consent_until),revision=1),consent_until)
            attempt=sign('delivery.attempt',dict(attempt_id='attempt_'+binding,message_id=context['message_id'],envelope_ref=reference,
                sender=sender_ids,recipient=recipient_ids,destination_ref=destination_entry['ref'],slot_key=key,
                operation='message.store',disclosure_ref=consent['ref'],ack_grant_ref=None),attempt_until)
            from memory_vault_open_provider import issue_status
            scope=status.status_scope(root,'authority',dict(authority_kind='message.disclosure',authority_sha256=consent['ref']['raw_sha256']),self.policy,budget)
            observation=issue_status(self.identity,root=root,revision=status_revision,entries=[dict(scope_kind='authority',scope_id=scope,
                minimum_document_revision=1,status='active',operation_mask=127)],issued_at=at,valid_until=consent_until)
            observed_raw=wire.build_new_wire(observation,self.policy,budget).raw;observed_hash=budget._hash(observed_raw)
            observed=dict(raw=observed_raw,ref=dict(namespace='meta',key=observed_hash,raw_sha256=observed_hash,size=len(observed_raw)))
            bundle=dict(disclosure=encode_entry(consent,self.policy,budget),disclosure_status=encode_entry(observed,self.policy,budget),attempt=encode_entry(attempt,self.policy,budget),
                destination=encode_entry(destination_entry,self.policy,budget),slot={name:encode_entry(value,self.policy,budget) for name,value in slot_entries.items()},
                contact={name:encode_entry(value,self.policy,budget) for name,value in originals['contact'].items()})
            raw=wire.build_new_wire(bundle,self.policy,budget).raw
            if len(raw)>131072:_fail('repair_message_capacity')
            self.db.execute('INSERT INTO open_mailbox_message_drafts VALUES(?,?,?,?,?,?,?)',(self.identity.key_id,context['message_id'],binding,root_digest,status_revision,envelope_raw,raw))
            return raw
        raw=journal._transaction(save)
        value=wire.parse_new_wire(raw,self.policy,wire.RepairBudget(self.policy)).value
        return dict(envelope=envelope_raw,originals=value,
            attempt=decode_entry(value['attempt'],self.policy,wire.RepairBudget(self.policy)),
            disclosure=decode_entry(value['disclosure'],self.policy,wire.RepairBudget(self.policy)))


def read_mailbox_index(head_entry, checkpoint_entry, *, expected_slot, expected_signing_key,
                       encryption_identity, read_original, at, max_messages,
                       policy=DEFAULT_POLICY, budget=None):
    """Read a complete encrypted prefix through a caller-authorized exact-ref reader.

    This verifies enumeration integrity, not current read authority or member
    provenance. The remote possession service must authorize read_original;
    each returned member still needs its original admission/history validation.
    No message IDs, sender state, ambient credentials or local database are used.
    """
    import memory_vault_open_repair_resource as resource
    import memory_vault_open_repair_mailbox_range as ranges
    from memory_vault_network_crypto import decrypt_bytes, NetworkCryptoError
    budget=budget or wire.RepairBudget(policy);wire._context(policy,budget)
    slot=wire.build_new_wire(expected_slot,policy,budget).value
    key=wire.build_new_wire(expected_signing_key,policy,budget).value
    wire.u53(at);wire.u53(max_messages,1)
    if max_messages>ranges.CAPACITY or not callable(read_original):_fail('repair_invalid_context')
    def checked_raw(raw,reference):
        ref=wire.raw_ref(reference)
        if ref.namespace!='meta' or not isinstance(raw,bytes) or len(raw)!=ref.size or budget._hash(raw)!=ref.raw_sha256:
            _fail('repair_ref_mismatch')
        return wire.parse_new_wire(raw,policy,budget).value
    def event(entry,kind,fields):
        resource._fields(entry,{'raw','ref'})
        signed=resource._fields(checked_raw(entry['raw'],entry['ref']),{'payload','proof'})
        p=resource._fields(signed['payload'],resource.COMMON|fields|{'slot_key','committed_at','retain_until'})
        if p['schema_version']!=resource.SCHEMA or p['kind']!=kind or p['slot_key']!=slot:
            _fail('repair_mailbox_range_mismatch')
        original._verify_control_signature(p,signed['proof'],key,budget)
        if not wire.u53(p['committed_at'])<=at<wire.u53(p['retain_until']):_fail('repair_resource_expired')
        return p
    head=event(head_entry,'mailbox.feed_head',{'checkpoint_ref','count','range_root_ref','catalog_generation'})
    cp=event(checkpoint_entry,'mailbox.checkpoint',{'slot_binding','count','leaf_root','frontier'})
    count=wire.u53(head['count']);wire.u53(head['catalog_generation'])
    if (count>max_messages or count!=cp['count'] or head['checkpoint_ref']!=checkpoint_entry['ref']
            or head['committed_at']!=cp['committed_at'] or head['retain_until']!=cp['retain_until']):
        _fail('repair_mailbox_range_mismatch')
    state={name:cp[name] for name in ('slot_binding','count','leaf_root','frontier')}
    ranges._state(state,slot,policy,budget)
    accumulated=ranges.empty_state(slot,policy=policy,budget=budget)
    entries=[];seen=set()
    def load(reference):
        ref=wire.raw_ref(reference)
        if ref.key in seen:_fail('repair_mailbox_range_mismatch')
        seen.add(ref.key)
        return checked_raw(read_original(ref.as_dict()),ref.as_dict())
    def walk(reference,level,start,end):
        nonlocal accumulated
        value=load(reference)
        fields={'schema_version','kind','slot_key','start','end'}
        fields|={'level','children'} if level>=0 else {'sealed_page_ref','entries'}
        resource._fields(value,fields)
        if (value['schema_version']!=resource.SCHEMA or value['slot_key']!=slot
                or wire.u53(value['start'])!=start or wire.u53(value['end'])!=end):_fail('repair_mailbox_range_mismatch')
        if level>=0:
            if (value['kind']!='range.index' or wire.u53(value['level'])!=level
                    or type(value['children']) is not wire._DraftList or not 1<=len(value['children'])<=16):
                _fail('repair_mailbox_range_mismatch')
            cursor=start;span=16**(level+1)
            for child in value['children']:
                resource._fields(child,{'start','end','ref'})
                stop=min(cursor+span,end)
                if wire.u53(child['start'])!=cursor or wire.u53(child['end'])!=stop or stop<=cursor:_fail('repair_mailbox_range_mismatch')
                walk(child['ref'],level-1,cursor,stop);cursor=stop
            if cursor!=end:_fail('repair_mailbox_range_mismatch')
            return
        if (value['kind']!='range.repair_page' or type(value['entries']) is not wire._DraftList
                or len(value['entries'])!=end-start or not 1<=end-start<=16):
            _fail('repair_mailbox_range_mismatch')
        for sequence,item in enumerate(value['entries'],start):
            resource._fields(item,{'sequence','admission_link_ref','sealed_core_ref'})
            if wire.u53(item['sequence'])!=sequence:_fail('repair_mailbox_range_mismatch')
            for name in ('admission_link_ref','sealed_core_ref'):
                if wire.raw_ref(item[name]).namespace!='meta':_fail('repair_ref_mismatch')
        private=wire.build_new_wire(dict(schema_version=resource.SCHEMA,kind='range.private_page',slot_key=slot,
            start=start,end=end,entries=value['entries']),policy,budget).raw
        context=dict(schema_version=resource.SCHEMA,kind='range.sealed_page',slot_key=slot,start=start,end=end,
            plaintext_sha256=budget._hash(private),plaintext_size=len(private))
        sealed=load(value['sealed_page_ref'])
        if len(sealed.get('recipients',()))!=1:_fail('repair_mailbox_range_mismatch')
        try:plaintext=decrypt_bytes(sealed,encryption_identity,context=context)
        except NetworkCryptoError:_fail('repair_mailbox_range_mismatch')
        if plaintext!=private:_fail('repair_mailbox_range_mismatch')
        for item in value['entries']:
            accumulated=ranges.append(accumulated,item['sealed_core_ref']['raw_sha256'],expected_slot=slot,policy=policy,budget=budget)
            entries.append(item)
    if count:
        level=0
        while count>16**(level+2):level+=1
        walk(head['range_root_ref'],level,0,count)
    elif head['range_root_ref'] is not None:_fail('repair_mailbox_range_mismatch')
    if any(accumulated[name]!=state[name] for name in state):_fail('repair_mailbox_range_mismatch')
    return tuple(entries)


def read_mailbox_admission(member, *, expected_slot, expected_signing_key,
                           encryption_identity, read_original, at,
                           policy=DEFAULT_POLICY, budget=None):
    """Fetch original admission bytes for an entry from read_mailbox_index.

    Authenticates the source event graph and encrypted core before fetching E.
    The returned historical inputs still require typed authority/status checks;
    this function neither imports memories nor grants trust to their contents.
    """
    import memory_vault_open_repair_resource as resource
    import memory_vault_open_repair_history as history
    import memory_vault_open_repair_mailbox_range as ranges
    from memory_vault_network_crypto import decrypt_bytes, NetworkCryptoError
    from memory_vault_open_delivery import MAX_ENVELOPE_BYTES
    budget=budget or wire.RepairBudget(policy);wire._context(policy,budget)
    slot=wire.build_new_wire(expected_slot,policy,budget).value
    key=wire.build_new_wire(expected_signing_key,policy,budget).value
    item=wire.build_new_wire(member,policy,budget).value
    resource._fields(item,{'sequence','admission_link_ref','sealed_core_ref'})
    sequence=wire.u53(item['sequence']);wire.u53(at)
    if sequence>=ranges.CAPACITY or not callable(read_original):_fail('repair_invalid_context')
    originals={}
    def load(reference,namespace='meta'):
        ref=wire.raw_ref(reference)
        if ref.namespace!=namespace or (namespace=='object' and ref.size>MAX_ENVELOPE_BYTES):_fail('repair_ref_mismatch')
        raw=read_original(ref.as_dict())
        if not isinstance(raw,bytes) or len(raw)!=ref.size or budget._hash(raw)!=ref.raw_sha256:_fail('repair_ref_mismatch')
        originals[(ref.namespace,ref.key)]=dict(raw=raw,ref=ref.as_dict())
        return raw
    def event(reference,kind,fields):
        raw=load(reference);signed=resource._fields(wire.parse_new_wire(raw,policy,budget).value,{'payload','proof'})
        p=resource._fields(signed['payload'],resource.COMMON|fields|{'slot_key'})
        if p['schema_version']!=resource.SCHEMA or p['kind']!=kind or p['slot_key']!=slot:_fail('repair_mailbox_member_mismatch')
        original._verify_control_signature(p,signed['proof'],key,budget)
        return raw,p
    _,link=event(item['admission_link_ref'],'admission.link',{'sequence','message_id','envelope_ref','core_ref',
        'sealed_core_ref','historical_manifest_ref','checkpoint_ref','inclusion_path'})
    if wire.u53(link['sequence'])!=sequence or link['sealed_core_ref']!=item['sealed_core_ref']:_fail('repair_mailbox_member_mismatch')
    core_raw,core=event(link['core_ref'],'admission.core',{'core_id','sequence','message_id','envelope_ref','attempt_ref',
        'historical_manifest_ref','data_resource_ref','metadata_resource_ref','accepted_at','object_until','enum_until'})
    original._opaque(core['core_id']);original._opaque(core['message_id'])
    if (wire.u53(core['sequence'])!=sequence or any(core[name]!=link[name] for name in ('message_id','envelope_ref','historical_manifest_ref'))
            or not wire.u53(core['accepted_at'])<=at<wire.u53(core['object_until'])<=wire.u53(core['enum_until'])):
        _fail('repair_mailbox_member_mismatch')
    for name in ('data_resource_ref','metadata_resource_ref'):
        history._resource(core[name])
        if core[name]['node_key_id']!=slot['writer']['signing_key_id'] or core[name]['storage_epoch']!=slot['writer_storage_epoch']:
            _fail('repair_mailbox_member_mismatch')
    context=dict(schema_version=resource.SCHEMA,kind='admission.sealed_core',slot_key=slot,sequence=sequence,
        plaintext_sha256=link['core_ref']['raw_sha256'],plaintext_size=len(core_raw))
    sealed_raw=load(item['sealed_core_ref']);sealed=wire.parse_new_wire(sealed_raw,policy,budget).value
    if len(sealed.get('recipients',()))!=1:_fail('repair_mailbox_member_mismatch')
    try:plain=decrypt_bytes(sealed,encryption_identity,context=context)
    except NetworkCryptoError:_fail('repair_mailbox_member_mismatch')
    if plain!=core_raw:_fail('repair_mailbox_member_mismatch')
    _,checkpoint=event(link['checkpoint_ref'],'mailbox.checkpoint',{'slot_binding','count','leaf_root','frontier','committed_at','retain_until'})
    if (wire.u53(checkpoint['count'])!=sequence+1 or not core['accepted_at']<=wire.u53(checkpoint['committed_at'])<=at
            or wire.u53(checkpoint['retain_until'])<core['enum_until']):_fail('repair_mailbox_member_mismatch')
    state={name:checkpoint[name] for name in ('slot_binding','count','leaf_root','frontier')}
    ranges.verify_inclusion(state,sequence,item['sealed_core_ref']['raw_sha256'],link['inclusion_path'],expected_slot=slot,policy=policy,budget=budget)
    manifest_raw=load(core['historical_manifest_ref']);manifest=history.parse_historical_manifest(manifest_raw,policy,budget)
    m=manifest.value
    if (m['variant']!='mailbox_member' or m['root_key']!=slot['root_key'] or m['slot_key']!=slot
            or any(m[name]!=core[name] for name in ('message_id','envelope_ref','attempt_ref'))):_fail('repair_mailbox_member_mismatch')
    resolver=wire.LocalRawResolver(policy,budget);packs={}
    for role in m['roles']:
        ref=wire.raw_ref(role['pack_ref']);previous=packs.get(ref.key)
        if previous is not None and previous!=ref.as_dict():_fail('repair_ref_mismatch')
        if previous is None:
            resolver.put('meta',ref.key,load(ref.as_dict()));packs[ref.key]=ref.as_dict()
    resolved=history.resolve_historical_inputs(manifest_raw,resolver,policy,budget)
    envelope=load(core['envelope_ref'],'object')
    return dict(core=core,link=link,checkpoint=checkpoint,history=resolved,envelope=envelope,
        originals=MappingProxyType(originals))
