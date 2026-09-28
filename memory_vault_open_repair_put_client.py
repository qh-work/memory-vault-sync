"""Upload an existing saved-message receipt after independent ACK preflight."""
from dataclasses import dataclass, replace
import math
import time
from types import MappingProxyType

from memory_vault_open_repair_offer_client import AckOfferClient, PreparedAckOffer, _OfferStatusChecks
from memory_vault_open_repair_client import _entry, _fail
from memory_vault_open_repair_put import decode_entry, encode_entry, MAX_BYTES, PACKET_FIELDS, USE_FIELDS
from memory_vault_open_transport import endpoint
import memory_vault_open_repair_ack as ack
import memory_vault_open_repair_bound as bound
import memory_vault_open_repair_empty as empty
import memory_vault_open_repair_occupied as occupied
import memory_vault_open_repair_original as original
import memory_vault_open_repair_probe as probe
import memory_vault_open_repair_proof as proof
import memory_vault_open_repair_status as status
import memory_vault_open_repair_wire as wire
from memory_vault_open_repair_state import DEFAULT_POLICY

FULL_RETURN_ROLES = ["ack.disclosure", "ack.put", "authority.status.disclosure", "recipient.receipt"]
# A complete client workflow verifies the empty preflight, its own consent,
# and the independently returned occupied history on the same finite meter.
DEFAULT_RECEIPT_POLICY = replace(DEFAULT_POLICY, max_signature_checks=96)
JOURNAL_SCHEMA = "memory-vault-ack-put-journal/v1"


@dataclass(frozen=True, slots=True)
class CommittedAckReceipt:
    source: object
    originals: object
    metrics: object


class AckReceiptClient(AckOfferClient):
    def __init__(self, identity, encryption_identity, *, policy=DEFAULT_RECEIPT_POLICY, **options):
        super().__init__(identity, encryption_identity, policy=policy, **options)

    def put(self, base_url, receipt_entry, disclosure_entry, put_entry, *, current_statuses,
            read_until, retain_until, known_disclosure_statuses=(), timeout=30, _journal=None, **preflight_options):
        started = time.monotonic()
        budget = wire.RepairBudget(self.policy)
        if _journal is not None and not callable(_journal):
            _fail("repair_invalid_context")
        retained = self._retained_inputs(preflight_options.get("known_statuses",()),preflight_options.get("archive_statuses",()),budget)
        known_disclosure_statuses=self._retained_inputs(known_disclosure_statuses,(),budget)
        preflight_options = dict(preflight_options,known_statuses=(),archive_statuses=retained)
        prepared = self.preflight(base_url,timeout=timeout,_budget=budget,**preflight_options)
        source = prepared.source
        owner = wire.build_new_wire(preflight_options["expected_owner"],self.policy,budget).value
        target = wire.build_new_wire(preflight_options["expected_target"],self.policy,budget).value
        slot = source.custody.payload["ack_slot"]
        inputs = occupied._inputs(source,receipt_entry,disclosure_entry,put_entry,
            owner=owner,writer=self.subject,at=self._now(),policy=self.policy,budget=budget)
        if inputs["disclosure"].payload["bootstrap_return"]["roles"] != FULL_RETURN_ROLES:
            _fail("repair_disclosure_permission")
        maximum_read,maximum_retain,admit_until = occupied._windows(source,inputs,self._now())
        if not self._now() < wire.u53(read_until) <= wire.u53(retain_until) <= maximum_retain or read_until > maximum_read:
            _fail("repair_ack_occupied_mismatch")
        duties = occupied._obligations(source,inputs,owner,self.subject,target,slot,self.policy,budget)
        checked = self._put_statuses(current_statuses,known_disclosure_statuses,duties,source,owner,budget,
            retained_authorities=retained,current_authorities=prepared.current_statuses)
        handle = prepared.proof.handle.payload
        expiry = min(handle["expires_at"],admit_until,self._now()+max(1,int(timeout-(time.monotonic()-started))))
        if self._now() >= expiry or time.monotonic()-started >= timeout:
            _fail("repair_access_expired")
        # Reserve enough of this same local meter for the full occupied
        # closure before any private originals leave the caller.
        if budget.snapshot()["signature_checks"]+32 > self.policy.max_signature_checks:
            _fail("repair_over_budget")
        use = probe._sign(dict(schema_version=probe.SCHEMA,kind="bootstrap.use",signing_key=self.subject["signing_key"],
            issued_at=self._now(),expires_at=expiry,use_id=probe._fresh_id("use",budget),subject=handle["subject"],
            target=handle["target"],target_storage_epoch=handle["target_storage_epoch"],consumer="ack_offer",operation="ack.put",
            bootstrap_probe_ref=handle["probe_ref"],bootstrap_manifest_ref=prepared.proof.manifest_ref.as_dict(),
            request_ref=inputs["put"].ref.as_dict()),self.identity,self.policy,budget)
        packet = wire.build_new_wire(dict(schema_version=probe.SCHEMA,kind="ack.put_request",use=encode_entry(_entry(use),self.policy,budget),
            **{name:encode_entry(_entry(inputs[name]),self.policy,budget) for name in ("receipt","disclosure","put")},
            current_statuses=[encode_entry(_entry(item),self.policy,budget) for item in checked],
            read_until=read_until,retain_until=retain_until),self.policy,budget)
        grant = source.authorities.originals["bootstrap"].payload
        upload_bytes = len(packet.raw)+len(use.raw)+sum(len(item.raw) for item in (*inputs.values(),*checked))
        if (len(packet.raw)>MAX_BYTES or prepared.metrics["requests"]+1 > grant["limits"]["max_requests"]
                or prepared.metrics["proof_bytes"]+upload_bytes > grant["limits"]["max_proof_bytes"]):
            _fail("repair_over_budget")
        if _journal is not None:
            journal = self._journal_record(packet.raw,prepared,retained,known_disclosure_statuses,budget)
            _journal("request",journal)
        response = self.transport.request_repair(base_url,packet.raw,deadline=started+timeout)
        result=self._finish(response,prepared,inputs,checked,owner,target,use,read_until,retain_until,
            preflight_options,started,timeout,expiry,upload_bytes,budget)
        if _journal is not None:
            _journal("response",response)
        return result

    def _finish(self,response,prepared,inputs,checked,owner,target,use,read_until,retain_until,
                preflight_options,started,timeout,expiry,upload_bytes,budget,*,replay=False):
        source,handle=prepared.source,prepared.proof.handle.payload
        slot=source.custody.payload["ack_slot"]
        grant=source.authorities.originals["bootstrap"].payload
        if type(response) is not bytes or not 0 < len(response) <= MAX_BYTES:
            _fail("repair_invalid_response")
        body = wire.object_fields(wire.parse_new_wire(response,self.policy,budget).value,
            {"schema_version","kind","use_ref","manifest","commit","head","packs"})
        if body["schema_version"] != probe.SCHEMA or body["kind"] != "ack.put_response" or probe._ref(body["use_ref"]) != use.ref:
            _fail("repair_put_mismatch")
        result = {name:decode_entry(body[name],self.policy,budget) for name in ("manifest","commit","head")}
        if type(body["packs"]) is not wire._DraftList or not 1 <= len(body["packs"]) <= self.policy.max_entries:
            _fail("repair_invalid_pack")
        packs = [decode_entry(item,self.policy,budget) for item in body["packs"]]
        transferred = prepared.metrics["proof_bytes"]+upload_bytes+len(response)+sum(len(item["raw"]) for item in (*result.values(),*packs))
        if transferred > grant["limits"]["max_proof_bytes"]:
            _fail("repair_over_budget")
        resolver = wire.LocalRawResolver(self.policy,budget)
        originals = dict(prepared.originals)
        for item in prepared.proof.manifest.value["children"]:
            if item["role"] == "history.raw_pack":
                ref = wire.raw_ref(item["ref"])
                resolver.put(ref.namespace,ref.key,originals[ref])
        wanted = {wire.raw_ref(item["pack_ref"]) for item in wire.parse_new_wire(result["manifest"]["raw"],self.policy,budget).value["roles"]}
        if len(packs) != len(wanted) or {wire.raw_ref(item["ref"]) for item in packs} != wanted:
            _fail("repair_unused_pack")
        for item in packs:
            ref = wire.raw_ref(item["ref"])
            if resolver.put(ref.namespace,ref.key,item["raw"]).ref != ref:
                _fail("repair_ref_mismatch")
        complete = occupied.verify_ack_occupied_source_event(result["manifest"],resolver,result["commit"],
            expected_ack_slot=slot,expected_owner=owner,expected_receipt_writer=self.subject,
            expected_message_id=preflight_options["expected_message_id"],expected_envelope_ref=preflight_options["expected_envelope_ref"],
            expected_target=target,target_storage_epoch=handle["target_storage_epoch"],limit_policy=self.limits,policy=self.policy,budget=budget)
        occupied.verify_ack_occupied_head(result["head"],complete,expected_target=target,policy=self.policy,budget=budget)
        if (complete.predecessor.custody.ref != source.custody.ref or complete.read_until != read_until or complete.retain_until != retain_until
                or any(complete.inputs[name].ref != item.ref or complete.inputs[name].raw != item.raw for name,item in inputs.items())):
            _fail("repair_put_mismatch")
        empty._history_floors((*checked,*complete.statuses),previous=checked,current=complete.statuses)
        if self._now() >= expiry or time.monotonic()-started >= timeout:
            _fail("repair_access_expired")
        for item in (*result.values(),*packs):
            originals[wire.raw_ref(item["ref"])] = item["raw"]
        for item in complete.manifest.roles:
            originals[item.original.ref] = item.original.raw
        return CommittedAckReceipt(complete,MappingProxyType(originals),MappingProxyType(dict(
            requests=1 if replay else prepared.metrics["requests"]+1,transfer_bytes=transferred,**budget.snapshot())))

    def _journal_record(self,packet,prepared,retained,disclosure_statuses,budget):
        def raw_entry(raw):
            digest=budget._hash(raw)
            return dict(raw=raw,ref=wire.RawRef("meta",digest,digest,len(raw)).as_dict())
        def encoded(entry):
            return encode_entry(entry,self.policy,budget)
        return wire.build_new_wire(dict(schema_version=JOURNAL_SCHEMA,
            packet=encoded(raw_entry(packet)),handle=encoded(_entry(prepared.proof.handle)),
            manifest=encoded(dict(raw=prepared.proof.manifest.raw,ref=prepared.proof.manifest_ref.as_dict())),
            originals=[encoded(dict(raw=raw,ref=ref.as_dict())) for ref,raw in prepared.originals.items()],
            retained=[encoded(item) for item in retained],
            disclosure_statuses=[encoded(item) for item in disclosure_statuses]),self.policy,budget).raw

    def resume(self,base_url,journal_raw,receipt_entry,disclosure_entry,put_entry,*,current_statuses,
               read_until,retain_until,known_disclosure_statuses=(),timeout=30,_journal=None,
               **preflight_options):
        """Reauthenticate a retained exchange and replay its exact signed use.

        This never issues a new probe or consent. A lost acknowledgement is
        recoverable only while the original handle/use is live. Expiry needs
        independent reconciliation instead of silently creating a new request.
        """
        if type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0<timeout<=60:
            _fail("repair_invalid_deadline")
        if _journal is not None and not callable(_journal):
            _fail("repair_invalid_context")
        started=time.monotonic();budget=wire.RepairBudget(self.policy)
        journal=wire.object_fields(wire.parse_new_wire(journal_raw,self.policy,budget).value,
            {"schema_version","packet","handle","manifest","originals","retained","disclosure_statuses"})
        if journal["schema_version"]!=JOURNAL_SCHEMA:
            _fail("repair_invalid_context")
        for name,maximum in (("originals",self.policy.max_entries),("retained",32),("disclosure_statuses",16)):
            if type(journal[name]) is not wire._DraftList or len(journal[name])>maximum:
                _fail("repair_over_budget")
        packet=decode_entry(journal["packet"],self.policy,budget)
        if len(packet["raw"])>MAX_BYTES:
            _fail("repair_put_too_large")
        body=wire.object_fields(wire.parse_new_wire(packet["raw"],self.policy,budget).value,PACKET_FIELDS)
        if body["schema_version"]!=probe.SCHEMA or body["kind"]!="ack.put_request":
            _fail("repair_put_mismatch")
        use_entry=decode_entry(body["use"],self.policy,budget)
        signed=wire.object_fields(wire.parse_new_wire(use_entry["raw"],self.policy,budget).value,{"payload","proof"})
        use=wire.object_fields(signed["payload"],USE_FIELDS)
        # No expired carrier goes onto the wire, even if the server might have
        # committed it. A retained local response remains historical evidence.
        if self._now()>=wire.u53(use["expires_at"]):
            _fail("repair_reconciliation_required")
        original._verify_control_signature(use,signed["proof"],self.subject["signing_key"],budget)
        restored=[decode_entry(item,self.policy,budget) for item in journal["retained"]]
        latest=self._retained_inputs(preflight_options.get("known_statuses",()),preflight_options.get("archive_statuses",()),budget)
        union={(item["raw"],wire.raw_ref(item["ref"])):item for item in (*restored,*latest)}
        if len(union)>32:
            _fail("repair_status_history_capacity")
        retained=tuple(union.values())
        prepared=self._restore_preflight(base_url,journal,use,preflight_options,budget,retained)
        source,handle=prepared.source,prepared.proof.handle.payload
        owner=wire.build_new_wire(preflight_options["expected_owner"],self.policy,budget).value
        target=wire.build_new_wire(preflight_options["expected_target"],self.policy,budget).value
        if (use["schema_version"]!=probe.SCHEMA or use["kind"]!="bootstrap.use" or
                use["consumer"]!="ack_offer" or use["operation"]!="ack.put" or
                use["subject"]!=probe._dual(self.subject) or use["target"]!=probe._dual(target) or
                use["target_storage_epoch"]!=handle["target_storage_epoch"] or
                use["bootstrap_probe_ref"]!=handle["probe_ref"] or
                probe._ref(use["bootstrap_manifest_ref"])!=prepared.proof.manifest_ref):
            _fail("repair_put_mismatch")
        probe._window(use,self._now());original._opaque(use["use_id"])
        decoded={name:decode_entry(body[name],self.policy,budget,receipt=name=="receipt") for name in ("receipt","disclosure","put")}
        for name,entry in (("receipt",receipt_entry),("disclosure",disclosure_entry),("put",put_entry)):
            raw,ref=occupied._entry(entry,receipt=name=="receipt")
            if decoded[name]["raw"]!=raw or wire.raw_ref(decoded[name]["ref"])!=ref:
                _fail("repair_put_mismatch")
        if (use["request_ref"]!=decoded["put"]["ref"] or body["read_until"]!=read_until or body["retain_until"]!=retain_until):
            _fail("repair_put_mismatch")
        inputs=occupied._inputs(source,decoded["receipt"],decoded["disclosure"],decoded["put"],
            owner=owner,writer=self.subject,at=self._now(),policy=self.policy,budget=budget)
        if inputs["disclosure"].payload["bootstrap_return"]["roles"]!=FULL_RETURN_ROLES:
            _fail("repair_disclosure_permission")
        maximum_read,maximum_retain,admit_until=occupied._windows(source,inputs,self._now())
        grant=source.authorities.originals["bootstrap"].payload
        if (not self._now()<wire.u53(read_until)<=wire.u53(retain_until)<=maximum_retain or read_until>maximum_read
                or use["expires_at"]>min(handle["expires_at"],admit_until,grant["upload_until"])):
            _fail("repair_put_mismatch")
        if type(body["current_statuses"]) is not wire._DraftList or not 1<=len(body["current_statuses"])<=8:
            _fail("repair_invalid_status")
        packet_statuses=[decode_entry(item,self.policy,budget) for item in body["current_statuses"]]
        if type(known_disclosure_statuses) not in (tuple,list) or len(known_disclosure_statuses)>16:
            _fail("repair_status_history_capacity")
        disclosure_old=[decode_entry(item,self.policy,budget) for item in journal["disclosure_statuses"]]
        disclosure_old.extend(known_disclosure_statuses)
        unique={(ack._entry(item)[0],ack._entry(item)[1]):item for item in disclosure_old}
        if len(unique)>16:
            _fail("repair_status_history_capacity")
        duties=occupied._obligations(source,inputs,owner,self.subject,target,source.custody.payload["ack_slot"],self.policy,budget)
        # New caller observations and all old floors must permit this exact
        # packet; a newer status never silently rewrites the signed request.
        checked=self._put_statuses(current_statuses,tuple(unique.values()),duties,source,owner,budget,
            retained_authorities=retained,current_authorities=prepared.current_statuses)
        packet_checked=self._put_statuses(packet_statuses,(),duties,source,owner,budget,
            current_authorities=(*prepared.current_statuses,*checked))
        upload_bytes=len(packet["raw"])+len(use_entry["raw"])+sum(len(item.raw) for item in (*inputs.values(),*packet_checked))
        if prepared.metrics["proof_bytes"]+upload_bytes>grant["limits"]["max_proof_bytes"]:
            _fail("repair_over_budget")
        if budget.snapshot()["signature_checks"]+32>self.policy.max_signature_checks:
            _fail("repair_over_budget")
        if self._now()>=use["expires_at"] or time.monotonic()-started>=timeout:
            _fail("repair_reconciliation_required")
        response=self.transport.request_repair(base_url,packet["raw"],deadline=started+timeout)
        result=self._finish(response,prepared,inputs,packet_checked,owner,target,
            empty.resource.AuthenticatedRepairOriginal(use_entry["raw"],wire.raw_ref(use_entry["ref"]),use),
            read_until,retain_until,preflight_options,started,timeout,use["expires_at"],upload_bytes,budget,replay=True)
        if _journal is not None:
            _journal("response",response)
        return result

    def _restore_preflight(self,base_url,journal,use,options,budget,retained):
        expected=wire.build_new_wire({name:options[name] for name in ("expected_owner","expected_target","expected_ack_slot",
            "expected_message_id","expected_envelope_ref")},self.policy,budget).value
        owner,target,slot=expected["expected_owner"],expected["expected_target"],expected["expected_ack_slot"]
        setup=bound.verify_ack_offer_bootstrap_original(options["bootstrap_entry"],
            dict(root=options["root_entry"],write=options["write_entry"]),expected_ack_slot=slot,expected_owner=owner,
            expected_receipt_writer=self.subject,expected_message_id=expected["expected_message_id"],
            expected_envelope_ref=expected["expected_envelope_ref"],at=self._now(),limit_policy=self.limits,policy=self.policy,budget=budget)
        raw,ref=ack._entry(options["target_node_entry"])
        node=original.verify_original_control(raw,expected_signing_key=target["signing_key"],expected_schema="memory-vault-open-control/v1",
            expected_kind="node",at=self._now(),policy=self.policy,budget=budget)
        original._node_shape(node,self._now(),budget)
        if len(raw)!=ref.size or node.raw_sha256!=ref.raw_sha256 or endpoint(base_url,allow_loopback=self.allow_loopback)!=endpoint(node.payload["base_url"],allow_loopback=self.allow_loopback):
            _fail("repair_proof_mismatch")
        handle=decode_entry(journal["handle"],self.policy,budget);manifest=decode_entry(journal["manifest"],self.policy,budget)
        hp=wire.object_fields(wire.object_fields(wire.parse_new_wire(handle["raw"],self.policy,budget).value,{"payload","proof"})["payload"],proof.HANDLE_FIELDS)
        grant=setup.originals["bootstrap"].payload
        response=wire.build_new_wire(dict(schema_version=proof.SCHEMA,kind="bootstrap.proof_response",
            handle_raw_base64url=probe._encode(handle["raw"],budget),manifest_raw_base64url=probe._encode(manifest["raw"],budget)),self.policy,budget)
        held=proof.verify_bootstrap_proof_response(response.raw,expected_subject=self.subject,expected_target=target,
            target_storage_epoch=node.payload["storage_epoch"],selector=grant["selector"],bootstrap_grant_ref=setup.originals["bootstrap"].ref.as_dict(),
            probe_ref=use["bootstrap_probe_ref"],challenge_ref=hp["challenge_ref"],answer_ref=hp["answer_ref"],at=self._now(),
            max_proof_items=grant["limits"]["max_proof_items"],max_proof_bytes=grant["limits"]["max_proof_bytes"],
            expected_source_state="empty",consumer="ack_offer",policy=self.policy,budget=budget)
        if held.handle.ref!=wire.raw_ref(handle["ref"]) or held.manifest_ref!=wire.raw_ref(manifest["ref"]):
            _fail("repair_ref_mismatch")
        originals={};roles={}
        for item in journal["originals"]:
            entry=decode_entry(item,self.policy,budget);ref=wire.raw_ref(entry["ref"])
            if ref in originals:_fail("repair_invalid_context")
            originals[ref]=entry["raw"]
        for item in held.manifest.value["children"]:
            roles.setdefault(item["role"],[]).append(wire.raw_ref(item["ref"]))
        if set(originals)!={ref for refs in roles.values() for ref in refs}:
            _fail("repair_proof_mismatch")
        resolver=wire.LocalRawResolver(self.policy,budget)
        for ref in roles["history.raw_pack"]:
            if resolver.put(ref.namespace,ref.key,originals[ref]).ref!=ref:_fail("repair_ref_mismatch")
        def entry(role):
            ref=roles[role][0];return dict(raw=originals[ref],ref=ref.as_dict())
        source=empty.verify_ack_empty_source_event(entry("history.ack_empty"),resolver,entry("ack.empty_custody"),
            expected_ack_slot=slot,expected_owner=owner,expected_receipt_writer=self.subject,
            expected_message_id=expected["expected_message_id"],expected_envelope_ref=expected["expected_envelope_ref"],
            expected_target=target,target_storage_epoch=node.payload["storage_epoch"],limit_policy=self.limits,policy=self.policy,budget=budget)
        self._empty_head(entry("ack.head"),source,target,budget)
        for item in source.manifest.roles:
            if roles[item.role]!=[item.original.ref] or originals[item.original.ref]!=item.original.raw:_fail("repair_proof_mismatch")
        for name,actual in (("root",source.predecessor.resources.originals["root"]),("write",source.authorities.originals["write"]),("bootstrap",source.authorities.originals["bootstrap"])):
            if actual.ref!=setup.originals[name].ref or actual.raw!=setup.originals[name].raw:_fail("repair_proof_mismatch")
        packs={wire.raw_ref(item["pack_ref"]) for manifest in (source.manifest,source.predecessor.manifest) for item in manifest.manifest.value["roles"]}
        if packs!=set(roles["history.raw_pack"]):_fail("repair_unused_pack")
        checks=_OfferStatusChecks(owner,self.policy,self.clock)
        known=checks._known(retained,checks.obligations(setup.originals,slot,budget),slot["root_key"],target,budget,deferred_authorities=True)
        current=checks.current(source,roles,originals,target,budget,known)
        transferred=len(response.raw)+len(handle["raw"])+len(manifest["raw"])+sum(len(raw) for raw in originals.values())
        if transferred>grant["limits"]["max_proof_bytes"]:_fail("repair_over_budget")
        return PreparedAckOffer(source,held,current,MappingProxyType(originals),MappingProxyType(dict(proof_bytes=transferred)))

    def _put_statuses(self, entries, retained, duties, source, owner, budget, *, retained_authorities=(),current_authorities=()):
        if type(entries) not in (list,tuple) or not 1 <= len(entries) <= 8:
            _fail("repair_invalid_status")
        if type(retained) not in (list,tuple) or len(retained)>16:
            _fail("repair_status_history_capacity")
        root = source.custody.payload["ack_slot"]["root_key"]
        authenticated, old = [], []
        for index,entry in enumerate((*entries,*retained,*retained_authorities)):
            raw,ref = occupied._entry(entry)
            parsed = original.parse_original_control(raw,self.policy,budget)
            payload = status._fields(status._fields(parsed.value,{"payload","proof"})["payload"],status._PAYLOAD)
            issuer = status._fields(payload["scope_key"],{"root_key","issuer_key_id"})["issuer_key_id"]
            allowed = [item for item in duties if item["signer"]["key_id"]==issuer]
            if not allowed or (len(entries)<=index<len(entries)+len(retained) and issuer != self.subject["signing_key"]["key_id"]):
                _fail("repair_status_disclosure")
            at = self._now() if index<len(entries) else wire.u53(payload["issued_at"])
            if at > self._now()+30:
                _fail("repair_status_mismatch")
            item = status.authenticate_status_original(dict(raw=parsed.raw,ref=ref.as_dict()),expected_root=root,
                expected_signing_key=allowed[0]["signer"],at=at,
                allowed_scopes=[dict(scope_kind=value["scope_kind"],scope_id=value["scope_id"]) for value in allowed],policy=self.policy,budget=budget)
            (authenticated if index<len(entries) else old).append(item)
        for duty in duties:
            observations = [(item,entry) for item in authenticated if item.payload["scope_key"]["issuer_key_id"]==duty["signer"]["key_id"]
                for entry in item.payload["entries"] if (entry["scope_kind"],entry["scope_id"])==(duty["scope_kind"],duty["scope_id"])]
            if not observations:
                _fail("repair_status_missing")
            _,entry = max(observations,key=lambda pair:pair[0].payload["revision"])
            if entry["status"] != "active" or entry["operation_mask"] & duty["mask"] != duty["mask"]:
                _fail("repair_authority_revoked")
            if entry["minimum_document_revision"] > duty["revision"]:
                _fail("repair_status_revision")
        obligations = [dict(kind=item["scope_kind"],scope_id=item["scope_id"],signer=item["signer"],mask=item["mask"],revision=item["revision"],role=item["role"]) for item in duties]
        checks = _OfferStatusChecks(owner,self.policy,self.clock)
        checks._floors((*source.predecessor.statuses,*source.statuses,*current_authorities,*old),authenticated,obligations)
        return tuple(authenticated)
