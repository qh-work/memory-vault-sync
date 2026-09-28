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
import memory_vault_open_repair_status as status
import memory_vault_open_repair_wire as wire
from memory_vault_open_repair_client import AckOwnerRecoveryClient


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


class OwnerAckBindClient(AckOwnerRecoveryClient):
    def bind(self,base_url,*,target_node_entry,expected_target,expected_ack_slot,
             root_entry,read_entry,bootstrap_entry,write_entry,offer_bootstrap_entry,
             expected_receipt_writer,expected_message_id,expected_envelope_ref,
             current_statuses,read_until,retain_until,known_statuses=(),archive_statuses=(),timeout=30):
        if type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0<timeout<=60:
            wire._fail("repair_invalid_deadline")
        if type(current_statuses) not in (list,tuple) or not 1<=len(current_statuses)<=7:
            wire._fail("repair_invalid_status")
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
        raw = self.transport.request_repair(base_url,request.raw,deadline=deadline)
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
            MappingProxyType(dict(requests=recovered.metrics["requests"]+1,proof_bytes=recovered.metrics["proof_bytes"]+transfer,
                wire_bytes=recovered.metrics["wire_bytes"]+len(request.raw)+len(raw),**budget.snapshot())))
