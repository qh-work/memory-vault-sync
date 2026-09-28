"""Owner bind uploads only after independently verifying a complete preflight."""
from dataclasses import dataclass
import math
import secrets
import time
from types import MappingProxyType, SimpleNamespace

import memory_vault_open_repair_ack as ack
import memory_vault_open_repair_bind as bind
import memory_vault_open_repair_bootstrap as bootstrap
import memory_vault_open_repair_bound as bound
import memory_vault_open_repair_empty as empty
import memory_vault_open_repair_original as original
import memory_vault_open_repair_probe as probe
import memory_vault_open_repair_proof as proof
import memory_vault_open_repair_status as status
import memory_vault_open_repair_wire as wire
from memory_vault_open_repair_client import AckOwnerRecoveryClient, RecoveredAckOwnerProof, _entry
from memory_vault_open_repair_bind_journal import OwnerBindJournal
from memory_vault_open_transport import endpoint

JOURNAL_SCHEMA = "memory-vault-owner-bind-journal/v1"


class _DurableKnown(AckOwnerRecoveryClient):
    """Use the existing T authenticator, persisting each verified original.

    `_known` calls `_floors` after authenticating a whole original. The hook
    records that validated evidence before semantic refusal can unwind.
    """
    def __init__(self, client, journal, job_key, obligations, observed):
        self.subject,self.policy,self.clock = client.subject,client.policy,client.clock
        self.journal,self.job_key,self.obligations = journal,job_key,obligations
        self.observation_ids = tuple(sorted(journal._observation_id(item) for item in observed))

    def _known(self, entries, obligations, root, target, budget):
        # Each input collection has its own fixed bound. Authenticate new
        # originals before the retained-union capacity decision; a valid 33rd
        # observation must durably block, not disappear on the next call.
        if type(entries) not in (list,tuple) or len(entries)>126:
            wire._fail("repair_invalid_status")
        checked = []
        for entry in entries:
            checked.extend(super()._known((entry,),obligations,root,target,budget))
        super()._floors(checked,(),obligations,probe_phase=True)
        return tuple(checked)

    def _floors(self, known, current, obligations, **options):
        allowed = {(item["signer"]["key_id"],item["kind"],item["scope_id"]) for item in self.obligations}
        for item in known:
            issuer = item.payload["scope_key"]["issuer_key_id"]
            if any((issuer,row["scope_kind"],row["scope_id"]) not in allowed for row in item.payload["entries"]):
                wire._fail("repair_status_disclosure")
        self.observation_ids = self.journal._observe(self.job_key,tuple(_entry(item) for item in known),
            expected_ids=self.observation_ids)
        return super()._floors(known,current,obligations,**options)


@dataclass(frozen=True,slots=True)
class BoundOwnerAck:
    source: object
    request: object
    response: bytes
    originals: object
    current_statuses: tuple
    metrics: object


def _current(prior,authorities,entries,owner,target,slot,at,policy,budget):
    obligations = empty._obligations(prior,authorities,owner,target,slot,policy,budget)
    checked,covered = [],set()
    for entry in entries:
        raw,ref = ack._entry(entry)
        preview = original.parse_original_control(raw,policy,budget)
        payload = status._fields(status._fields(preview.value,{"payload","proof"})["payload"],status._PAYLOAD)
        issuer = status._fields(payload["scope_key"],{"root_key","issuer_key_id"})["issuer_key_id"]
        permitted = [item for item in obligations if item["signer"]["key_id"]==issuer]
        if not permitted:
            wire._fail("repair_status_mismatch")
        present = {(item["scope_kind"],item["scope_id"]) for item in AckOwnerRecoveryClient._status_entries(payload)}
        required = [dict(scope_kind=item["scope_kind"],scope_id=item["scope_id"],
            document_revision=item["revision"],operation_mask=item["mask"]) for item in permitted
            if (item["scope_kind"],item["scope_id"]) in present]
        checked.append(status.verify_status_original(dict(raw=raw,ref=ref.as_dict()),expected_root=slot["root_key"],
            expected_signing_key=permitted[0]["signer"],at=at,
            allowed_scopes=[dict(scope_kind=item["scope_kind"],scope_id=item["scope_id"]) for item in permitted],
            required=required,policy=policy,budget=budget))
        covered.update((issuer,*item) for item in present)
    if any((item["signer"]["key_id"],item["scope_kind"],item["scope_id"]) not in covered for item in obligations):
        wire._fail("repair_status_missing")
    empty._history_floors((*prior.statuses,*checked),previous=prior.statuses,current=checked)
    return tuple(checked),obligations


def _journal_entry(entry,policy,budget):
    # A local historical pack can exceed one 64 KiB network control packet.
    # The immutable local journal remains separately bounded; this does not
    # change any transmitted carrier or response limit.
    value = wire.object_fields(entry,{"ref","raw_base64url"})
    ref = ack._ref(value["ref"])
    if ref.size>policy.max_document_bytes:
        wire._fail("repair_bind_journal_capacity")
    raw = original._decode64(value["raw_base64url"],ref.size,budget,url=True)
    if budget._hash(raw)!=ref.raw_sha256:
        wire._fail("repair_ref_mismatch")
    return dict(raw=raw,ref=ref.as_dict())


class OwnerAckBindClient(AckOwnerRecoveryClient):
    def journal_key(self, *, expected_target, expected_ack_slot):
        budget = wire.RepairBudget(self.policy)
        return budget._hash(wire.build_new_wire(dict(subject=self.subject,target=expected_target,
            slot=expected_ack_slot),self.policy,budget).raw)

    def bind(self,base_url,*,target_node_entry,expected_target,expected_ack_slot,
             root_entry,read_entry,bootstrap_entry,write_entry,offer_bootstrap_entry,
             expected_receipt_writer,expected_message_id,expected_envelope_ref,
             current_statuses,read_until,retain_until,known_statuses=(),archive_statuses=(),timeout=30,journal=None):
        if type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0<timeout<=60:
            wire._fail("repair_invalid_deadline")
        if type(current_statuses) not in (list,tuple) or not 1<=len(current_statuses)<=7:
            wire._fail("repair_invalid_status")
        job_key = self.journal_key(expected_target=expected_target,expected_ack_slot=expected_ack_slot)
        if journal is not None:
            if not isinstance(journal,OwnerBindJournal):
                wire._fail("repair_invalid_context")
            journal.initialize()
            saved = journal.load(job_key)
            if saved is not None:
                return self.resume(base_url,saved,target_node_entry=target_node_entry,expected_target=expected_target,
                    expected_ack_slot=expected_ack_slot,root_entry=root_entry,read_entry=read_entry,bootstrap_entry=bootstrap_entry,
                    write_entry=write_entry,offer_bootstrap_entry=offer_bootstrap_entry,expected_receipt_writer=expected_receipt_writer,
                    expected_message_id=expected_message_id,expected_envelope_ref=expected_envelope_ref,current_statuses=current_statuses,
                    read_until=read_until,retain_until=retain_until,known_statuses=known_statuses,archive_statuses=archive_statuses,
                    timeout=timeout,journal=journal)
        deadline = time.monotonic()+timeout
        policy,budget = self.policy,wire.RepairBudget(self.policy)
        now = self._now()
        expected = wire.build_new_wire(dict(target=expected_target,slot=expected_ack_slot,writer=expected_receipt_writer,
            message_id=expected_message_id,envelope_ref=expected_envelope_ref,read_until=read_until,
            retain_until=retain_until),policy,budget).value
        if not now < wire.u53(read_until) <= wire.u53(retain_until):
            wire._fail("repair_invalid_ack_empty")
        setup = bootstrap.verify_ack_owner_bootstrap_original(bootstrap_entry,dict(root=root_entry,read=read_entry),
            expected_ack_slot=expected["slot"],expected_owner=self.subject,at=now,limit_policy=self.limits,policy=policy,budget=budget)
        authorities = bound.verify_ack_offer_bootstrap_original(offer_bootstrap_entry,dict(root=root_entry,write=write_entry),
            expected_ack_slot=expected["slot"],expected_owner=self.subject,expected_receipt_writer=expected["writer"],
            expected_message_id=expected["message_id"],expected_envelope_ref=expected["envelope_ref"],at=now,
            limit_policy=self.limits,policy=policy,budget=budget)
        grant = setup.originals["bootstrap"].payload
        if now>=grant["upload_until"] or not {"ack.write_grant","bootstrap.grant"}.issubset(grant["upload_roles"]):
            wire._fail("repair_bind_mismatch")
        # Freeze all upload originals before the first network operation. Their
        # hashes/bytes remain exactly those which the local signature checks saw.
        write_wire = bind.encode_entry(dict(raw=authorities.originals["write"].raw,ref=authorities.originals["write"].ref.as_dict()),policy,budget)
        offer_wire = bind.encode_entry(dict(raw=authorities.originals["bootstrap"].raw,ref=authorities.originals["bootstrap"].ref.as_dict()),policy,budget)
        status_wire = [bind.encode_entry(entry,policy,budget) for entry in current_statuses]
        status_entries = tuple(bind.decode_entry(entry,policy,budget) for entry in status_wire)
        retained = self._retained_inputs(known_statuses,archive_statuses,budget)
        union = {(entry["raw"],wire.raw_ref(entry["ref"])):entry for entry in (*retained,*status_entries)}
        retained = self._retained_inputs((),tuple(union.values()),budget)
        obligations = self._obligations(setup.originals,expected["slot"],budget)
        for name,kind,mask in (("write","ack.write_grant",1),("bootstrap","bootstrap.grant",11)):
            item = authorities.originals[name]
            scope = status.status_scope(expected["slot"]["root_key"],"authority",
                dict(authority_kind=kind,authority_sha256=item.ref.raw_sha256),policy,budget)
            obligations.append(dict(role=None,kind="authority",scope_id=scope,revision=item.payload["revision"],
                signer=self.subject["signing_key"],mask=mask))
        known = self._known(retained,obligations,expected["slot"]["root_key"],expected["target"],budget)
        # The new write/offer observations need not already be at unbound R.
        # All old-scope floors are still checked before private upload below;
        # preprobe known revocations/minimums have already been checked above.
        recovered = self._recover(base_url,target_node_entry=target_node_entry,expected_target=expected["target"],
            expected_ack_slot=expected["slot"],root_entry=root_entry,read_entry=read_entry,bootstrap_entry=bootstrap_entry,
            known_statuses=(),archive_statuses=(),timeout=max(0.001,deadline-time.monotonic()),empty_expected=None,_budget=budget)
        roles = {}
        for item in recovered.proof.manifest.value["children"]:
            roles.setdefault(item["role"],[]).append(wire.raw_ref(item["ref"]))
        pending = SimpleNamespace(authorities=authorities,statuses=())
        self._current(recovered.source,roles,recovered.originals,expected["target"],budget,known,extra_source=pending)
        authenticated,requirements = _current(recovered.source,authorities,status_entries,self.subject,expected["target"],
            expected["slot"],self._now(),policy,budget)
        actual_obligations = [dict(role=item["role"],kind=item["scope_kind"],scope_id=item["scope_id"],
            revision=item["revision"],signer=item["signer"],mask=item["mask"]) for item in requirements]
        self._floors((*known,*recovered.source.statuses),authenticated,actual_obligations)
        now = self._now()
        expiry = min(recovered.proof.handle.payload["expires_at"],grant["upload_until"],now+max(1,int(deadline-time.monotonic())),
            *(item.payload["valid_until"] for item in authenticated))
        if now>=expiry or time.monotonic()>=deadline:
            wire._fail("repair_access_expired")
        payload = dict(schema_version=probe.SCHEMA,kind="ack.bind_request",signing_key=self.subject["signing_key"],
            issued_at=now,expires_at=expiry,request_id="bind_"+secrets.token_hex(16),subject=probe._dual(self.subject),
            target=probe._dual(expected["target"]),target_storage_epoch=recovered.proof.handle.payload["target_storage_epoch"],
            purpose="ack.owner_bind",consumer="ack_owner",probe_ref=recovered.proof.handle.payload["probe_ref"],
            handle_ref=recovered.proof.handle.ref.as_dict(),manifest_ref=recovered.proof.manifest_ref.as_dict(),
            service_generation=recovered.proof.handle.payload["service_generation"],write=write_wire,offer=offer_wire,
            receipt_writer=expected["writer"],message_id=expected["message_id"],envelope_ref=expected["envelope_ref"],
            current_statuses=status_wire,read_until=expected["read_until"],retain_until=expected["retain_until"])
        payload = wire.build_new_wire(payload,policy,budget).value
        request = probe._sign(payload,self.identity,policy,budget)
        if len(request.raw)>bind.MAX_BYTES or recovered.metrics["requests"]>=grant["limits"]["max_requests"]:
            wire._fail("repair_over_budget")
        if journal is not None:
            saved = self._journal_record(request,recovered,retained,budget)
            journal.store_request(job_key,request.payload["request_id"],saved)
            journal.guard(job_key,())
        if self._now()>=expiry or time.monotonic()>=deadline:
            wire._fail("repair_reconciliation_required")
        raw = self.transport.request_repair(base_url,request.raw,deadline=deadline)
        result = self._finish(raw,request=request,recovered=recovered,authorities=authorities,
            authenticated=authenticated,expected=expected,grant=grant,budget=budget,deadline=deadline,
            expiry=expiry,write_wire=write_wire,offer_wire=offer_wire,status_wire=status_wire)
        if journal is not None:
            journal.store_response(job_key,raw)
        return result

    def _finish(self,raw,*,request,recovered,authorities,authenticated,expected,grant,budget,deadline,
                expiry,write_wire,offer_wire,status_wire,replay=False):
        policy,payload = self.policy,request.payload
        roles = {}
        for item in recovered.proof.manifest.value["children"]:
            roles.setdefault(item["role"],[]).append(wire.raw_ref(item["ref"]))
        if type(raw) is not bytes or not 0<len(raw)<=bind.MAX_BYTES:
            wire._fail("repair_invalid_response")
        response = wire.parse_new_wire(raw,policy,budget)
        value = wire.object_fields(response.value,bind.RESULT_FIELDS)
        if (value["schema_version"]!=probe.SCHEMA or value["kind"]!="ack.bind_response"
                or wire.raw_ref(value["request_ref"])!=request.ref):
            wire._fail("repair_bind_mismatch")
        result = {name:bind.decode_entry(value[name],policy,budget) for name in ("binding","manifest","custody","head")}
        if type(value["packs"]) is not wire._DraftList or not 1<=len(value["packs"])<=self.policy.max_entries:
            wire._fail("repair_invalid_pack")
        packs = [bind.decode_entry(item,policy,budget) for item in value["packs"]]
        resolver = wire.LocalRawResolver(policy,budget)
        for ref in roles["history.raw_pack"]:
            resolver.put(ref.namespace,ref.key,recovered.originals[ref])
        for entry in packs:
            ref = wire.raw_ref(entry["ref"])
            if resolver.put(ref.namespace,ref.key,entry["raw"]).ref!=ref:
                wire._fail("repair_ref_mismatch")
        source = empty.verify_ack_empty_source_event(result["manifest"],resolver,result["custody"],
            expected_ack_slot=expected["slot"],expected_owner=self.subject,expected_target=expected["target"],
            expected_receipt_writer=expected["writer"],expected_message_id=expected["message_id"],
            expected_envelope_ref=expected["envelope_ref"],target_storage_epoch=payload["target_storage_epoch"],
            limit_policy=self.limits,policy=policy,budget=budget)
        self._empty_head(result["head"],source,expected["target"],budget)
        used = {wire.raw_ref(item["pack_ref"]) for item in source.manifest.manifest.value["roles"]}
        if len(packs)!=len(used) or {wire.raw_ref(item["ref"]) for item in packs}!=used:
            wire._fail("repair_unused_pack")
        if (source.binding.raw!=result["binding"]["raw"] or source.binding.ref!=wire.raw_ref(result["binding"]["ref"])
                or source.predecessor.custody.raw!=recovered.source.custody.raw
                or source.predecessor.custody.ref!=recovered.source.custody.ref
                or source.authorities.originals["write"].ref!=authorities.originals["write"].ref
                or source.authorities.originals["bootstrap"].ref!=authorities.originals["bootstrap"].ref
                or source.read_until!=expected["read_until"] or source.retain_until!=expected["retain_until"]
                or any((item.raw,item.ref) not in {(v.raw,v.ref) for v in authenticated} for item in source.statuses)):
            wire._fail("repair_bind_mismatch")
        transfer = len(request.raw)+sum(wire.raw_ref(item["ref"]).size for item in [write_wire,offer_wire,*status_wire])
        transfer += len(raw)+sum(len(item["raw"]) for item in result.values())+sum(len(item["raw"]) for item in packs)
        if recovered.metrics["proof_bytes"]+transfer>grant["limits"]["max_proof_bytes"]:
            wire._fail("repair_over_budget")
        if self._now()>=expiry or time.monotonic()>=deadline:
            wire._fail("repair_access_expired")
        return BoundOwnerAck(source,request,raw,MappingProxyType(result),authenticated,
            MappingProxyType(dict(requests=1 if replay else recovered.metrics["requests"]+1,proof_bytes=recovered.metrics["proof_bytes"]+transfer,
                wire_bytes=recovered.metrics["wire_bytes"]+len(request.raw)+len(raw),**budget.snapshot())))

    def _journal_record(self,request,recovered,retained,budget):
        def encoded(item):
            return bind.encode_entry(item,self.policy,budget)
        return wire.build_new_wire(dict(schema_version=JOURNAL_SCHEMA,request=encoded(_entry(request)),
            handle=encoded(_entry(recovered.proof.handle)),
            manifest=encoded(dict(raw=recovered.proof.manifest.raw,ref=recovered.proof.manifest_ref.as_dict())),
            originals=[encoded(dict(raw=raw,ref=ref.as_dict())) for ref,raw in recovered.originals.items()],
            retained=[encoded(item) for item in retained]),self.policy,budget).raw

    def resume(self,base_url,journal_raw,*,target_node_entry,expected_target,expected_ack_slot,
               root_entry,read_entry,bootstrap_entry,write_entry,offer_bootstrap_entry,
               expected_receipt_writer,expected_message_id,expected_envelope_ref,current_statuses,
               read_until,retain_until,known_statuses=(),archive_statuses=(),timeout=30,journal=None):
        """Revalidate all saved originals, then replay one exact live carrier.

        A completed historical cache never substitutes for a network response.
        Expired authority requires independent reconciliation, never a new bind.
        """
        if type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0<timeout<=60:
            wire._fail("repair_invalid_deadline")
        if type(current_statuses) not in (tuple,list) or not 1<=len(current_statuses)<=7:
            wire._fail("repair_invalid_status")
        if journal is not None and not isinstance(journal,OwnerBindJournal):
            wire._fail("repair_invalid_context")
        job_key = self.journal_key(expected_target=expected_target,expected_ack_slot=expected_ack_slot)
        observed = ()
        if journal is not None:
            journal.initialize()
            existing = journal.load(job_key)
            if existing is None:
                wire._fail("repair_bind_journal_missing")
            if existing != journal_raw:
                wire._fail("repair_bind_journal_conflict")
            observed = journal.observations(job_key)
        deadline = time.monotonic()+timeout
        policy,budget = self.policy,wire.RepairBudget(self.policy)
        saved = wire.object_fields(wire.parse_new_wire(journal_raw,policy,budget).value,
            {"schema_version","request","handle","manifest","originals","retained"})
        if saved["schema_version"]!=JOURNAL_SCHEMA:
            wire._fail("repair_invalid_context")
        for name,maximum in (("originals",policy.max_entries),("retained",32)):
            if type(saved[name]) is not wire._DraftList or len(saved[name])>maximum:
                wire._fail("repair_over_budget")
        carrier = bind.decode_entry(saved["request"],policy,budget)
        signed = wire.object_fields(wire.parse_new_wire(carrier["raw"],policy,budget).value,{"payload","proof"})
        payload = wire.object_fields(signed["payload"],bind.FIELDS)
        if self._now()>=wire.u53(payload["expires_at"]):
            wire._fail("repair_reconciliation_required")
        original._verify_control_signature(payload,signed["proof"],self.subject["signing_key"],budget)
        probe._window(payload,self._now());original._opaque(payload["request_id"])
        expected = wire.build_new_wire(dict(target=expected_target,slot=expected_ack_slot,writer=expected_receipt_writer,
            message_id=expected_message_id,envelope_ref=expected_envelope_ref,read_until=read_until,
            retain_until=retain_until),policy,budget).value
        if (payload["schema_version"]!=probe.SCHEMA or payload["kind"]!="ack.bind_request"
                or payload["purpose"]!="ack.owner_bind" or payload["consumer"]!="ack_owner"
                or payload["signing_key"]!=self.subject["signing_key"] or payload["subject"]!=probe._dual(self.subject)
                or payload["target"]!=probe._dual(expected["target"])
                or payload["receipt_writer"]!=expected["writer"] or payload["message_id"]!=expected["message_id"]
                or payload["envelope_ref"]!=expected["envelope_ref"] or payload["read_until"]!=expected["read_until"]
                or payload["retain_until"]!=expected["retain_until"]):
            wire._fail("repair_bind_mismatch")
        setup = bootstrap.verify_ack_owner_bootstrap_original(bootstrap_entry,dict(root=root_entry,read=read_entry),
            expected_ack_slot=expected["slot"],expected_owner=self.subject,at=self._now(),limit_policy=self.limits,policy=policy,budget=budget)
        authorities = bound.verify_ack_offer_bootstrap_original(offer_bootstrap_entry,dict(root=root_entry,write=write_entry),
            expected_ack_slot=expected["slot"],expected_owner=self.subject,expected_receipt_writer=expected["writer"],
            expected_message_id=expected["message_id"],expected_envelope_ref=expected["envelope_ref"],at=self._now(),
            limit_policy=self.limits,policy=policy,budget=budget)
        grant = setup.originals["bootstrap"].payload
        if (payload["expires_at"]>grant["upload_until"] or self._now()>=grant["upload_until"]
                or not {"ack.write_grant","bootstrap.grant"}.issubset(grant["upload_roles"])):
            wire._fail("repair_bind_mismatch")
        for name,role in (("write","write"),("offer","bootstrap")):
            item = bind.decode_entry(payload[name],policy,budget)
            if item["raw"]!=authorities.originals[role].raw or wire.raw_ref(item["ref"])!=authorities.originals[role].ref:
                wire._fail("repair_bind_mismatch")
        if type(payload["current_statuses"]) is not wire._DraftList or not 1<=len(payload["current_statuses"])<=7:
            wire._fail("repair_invalid_status")
        packet_statuses = tuple(bind.decode_entry(item,policy,budget) for item in payload["current_statuses"])
        retained = (self._retained_inputs(known_statuses,(),budget)+self._retained_inputs((),archive_statuses,budget)
                    if journal is not None else self._retained_inputs(known_statuses,archive_statuses,budget))
        restored = tuple(bind.decode_entry(item,policy,budget) for item in saved["retained"])
        # The caller's new observations cannot silently rewrite the old signed
        # packet. Every current/retained whole T participates in the same meter.
        snapshots = tuple(bind.decode_entry(bind.encode_entry(item,policy,budget),policy,budget) for item in current_statuses)
        union = {(item["raw"],wire.raw_ref(item["ref"])):item for item in (*retained,*restored,*observed,*snapshots,*packet_statuses)}
        retained = tuple(union.values()) if journal is not None else self._retained_inputs((),tuple(union.values()),budget)
        obligations = self._obligations(setup.originals,expected["slot"],budget)
        for name,kind,mask in (("write","ack.write_grant",1),("bootstrap","bootstrap.grant",11)):
            item=authorities.originals[name]
            obligations.append(dict(role=None,kind="authority",scope_id=status.status_scope(expected["slot"]["root_key"],
                "authority",dict(authority_kind=kind,authority_sha256=item.ref.raw_sha256),policy,budget),
                revision=item.payload["revision"],signer=self.subject["signing_key"],mask=mask))
        recovered = self._restore_preflight(base_url,saved,payload,target_node_entry,expected,setup,budget)
        active = recovered.source.resources.originals["active"].payload
        obligations.append(dict(role="current.status.ack_resource",kind="resource",revision=active["reservation_generation"],
            signer=expected["target"]["signing_key"],mask=2,
            scope_id=status.status_scope(expected["slot"]["root_key"],"resource",active["resource"],policy,budget)))
        checker = self if journal is None else _DurableKnown(self,journal,job_key,obligations,observed)
        known = checker._known(retained,obligations,expected["slot"]["root_key"],expected["target"],budget)
        roles = {}
        for item in recovered.proof.manifest.value["children"]:
            roles.setdefault(item["role"],[]).append(wire.raw_ref(item["ref"]))
        self._current(recovered.source,roles,recovered.originals,expected["target"],budget,known,
                      extra_source=SimpleNamespace(authorities=authorities,statuses=()))
        latest,requirements = _current(recovered.source,authorities,snapshots,self.subject,expected["target"],
            expected["slot"],self._now(),policy,budget)
        authenticated,_ = _current(recovered.source,authorities,packet_statuses,self.subject,expected["target"],
            expected["slot"],self._now(),policy,budget)
        duties = [dict(role=item["role"],kind=item["scope_kind"],scope_id=item["scope_id"],revision=item["revision"],
            signer=item["signer"],mask=item["mask"]) for item in requirements]
        self._floors((*known,*latest,*recovered.source.statuses),authenticated,duties)
        expiry = min(payload["expires_at"],recovered.proof.handle.payload["expires_at"],recovered.source.read_until,
                     *(item.payload["valid_until"] for item in (*latest,*authenticated)))
        if self._now()>=expiry or time.monotonic()>=deadline:
            wire._fail("repair_reconciliation_required")
        request = empty.resource.AuthenticatedRepairOriginal(carrier["raw"],wire.raw_ref(carrier["ref"]),payload)
        if journal is not None:
            journal.store_request(job_key,payload["request_id"],journal_raw)
            journal.guard(job_key,checker.observation_ids)
        raw = self.transport.request_repair(base_url,request.raw,deadline=deadline)
        result = self._finish(raw,request=request,recovered=recovered,authorities=authorities,authenticated=authenticated,
            expected=expected,grant=grant,budget=budget,deadline=deadline,expiry=expiry,write_wire=payload["write"],
            offer_wire=payload["offer"],status_wire=payload["current_statuses"],replay=True)
        if journal is not None:
            journal.store_response(job_key,raw)
        return result

    def _restore_preflight(self,base_url,saved,request,target_node_entry,expected,setup,budget):
        policy,target = self.policy,expected["target"]
        raw,ref = ack._entry(target_node_entry)
        node = original.verify_original_control(raw,expected_signing_key=target["signing_key"],
            expected_schema="memory-vault-open-control/v1",expected_kind="node",at=self._now(),policy=policy,budget=budget)
        original._node_shape(node,self._now(),budget)
        if (len(raw)!=ref.size or node.raw_sha256!=ref.raw_sha256 or request["target_storage_epoch"]!=node.payload["storage_epoch"]
                or endpoint(base_url,allow_loopback=self.allow_loopback)!=endpoint(node.payload["base_url"],allow_loopback=self.allow_loopback)):
            wire._fail("repair_proof_mismatch")
        handle,manifest = (bind.decode_entry(saved[name],policy,budget) for name in ("handle","manifest"))
        hp = wire.object_fields(wire.object_fields(wire.parse_new_wire(handle["raw"],policy,budget).value,{"payload","proof"})["payload"],proof.HANDLE_FIELDS)
        response = wire.build_new_wire(dict(schema_version=proof.SCHEMA,kind="bootstrap.proof_response",
            handle_raw_base64url=probe._encode(handle["raw"],budget),manifest_raw_base64url=probe._encode(manifest["raw"],budget)),policy,budget)
        grant = setup.originals["bootstrap"].payload
        held = proof.verify_bootstrap_proof_response(response.raw,expected_subject=self.subject,expected_target=target,
            target_storage_epoch=node.payload["storage_epoch"],selector=grant["selector"],bootstrap_grant_ref=setup.originals["bootstrap"].ref.as_dict(),
            probe_ref=request["probe_ref"],challenge_ref=hp["challenge_ref"],answer_ref=hp["answer_ref"],at=self._now(),
            max_proof_items=grant["limits"]["max_proof_items"],max_proof_bytes=grant["limits"]["max_proof_bytes"],
            expected_source_state="unbound",policy=policy,budget=budget)
        if (held.handle.ref!=wire.raw_ref(handle["ref"]) or held.manifest_ref!=wire.raw_ref(manifest["ref"])
                or held.handle.ref!=probe._ref(request["handle_ref"]) or held.manifest_ref!=probe._ref(request["manifest_ref"])
                or request["service_generation"]!=held.handle.payload["service_generation"]
                or request["expires_at"]>held.handle.payload["expires_at"]):
            wire._fail("repair_bind_mismatch")
        originals,roles = {},{}
        for value in saved["originals"]:
            entry = _journal_entry(value,policy,budget); ref = wire.raw_ref(entry["ref"])
            if ref in originals:
                wire._fail("repair_invalid_context")
            originals[ref] = entry["raw"]
        for item in held.manifest.value["children"]:
            roles.setdefault(item["role"],[]).append(wire.raw_ref(item["ref"]))
        if set(originals)!={ref for refs in roles.values() for ref in refs}:
            wire._fail("repair_proof_mismatch")
        resolver = wire.LocalRawResolver(policy,budget)
        for ref in roles["history.raw_pack"]:
            if resolver.put(ref.namespace,ref.key,originals[ref]).ref!=ref:
                wire._fail("repair_ref_mismatch")
        def entry(role):
            ref=roles[role][0];return dict(raw=originals[ref],ref=ref.as_dict())
        source = ack.verify_ack_unbound_source_event(entry("history.ack_unbound"),resolver,entry("ack.unbound_custody"),
            expected_ack_slot=expected["slot"],expected_owner=self.subject,expected_target=target,
            target_storage_epoch=node.payload["storage_epoch"],limit_policy=self.limits,policy=policy,budget=budget)
        for item in source.manifest.roles:
            if roles[item.role]!=[item.original.ref] or originals[item.original.ref]!=item.original.raw:
                wire._fail("repair_proof_mismatch")
        for name,actual in (("root",source.resources.originals["root"]),("read",source.resources.originals["read"]),
                            ("bootstrap",source.bootstrap.originals["bootstrap"])):
            if actual.ref!=setup.originals[name].ref or actual.raw!=setup.originals[name].raw:
                wire._fail("repair_proof_mismatch")
        if {wire.raw_ref(item["pack_ref"]) for item in source.manifest.manifest.value["roles"]}!=set(roles["history.raw_pack"]):
            wire._fail("repair_unused_pack")
        transferred = len(response.raw)+len(handle["raw"])+len(manifest["raw"])+sum(len(raw) for raw in originals.values())
        if transferred>grant["limits"]["max_proof_bytes"]:
            wire._fail("repair_over_budget")
        return RecoveredAckOwnerProof(source,held,(),MappingProxyType(originals),
            MappingProxyType(dict(requests=0,wire_bytes=0,proof_bytes=transferred)))
