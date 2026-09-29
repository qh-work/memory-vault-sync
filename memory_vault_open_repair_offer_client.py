"""Receipt-writer preflight before transmitting any private ACK originals.

Both keys and the target endpoint are checked on real HTTP. The independently
held A root/write/offer and message tuple bind the complete empty source. This
result authorizes no upload on its own: upload must recheck current permission.
"""
from dataclasses import dataclass
import math
import time
from types import MappingProxyType

from memory_vault_open_transport import endpoint
from memory_vault_open_repair_client import AckOwnerRecoveryClient, _entry, _fail
import memory_vault_open_repair_ack as ack
import memory_vault_open_repair_bound as bound
import memory_vault_open_repair_empty as empty
import memory_vault_open_repair_original as original
import memory_vault_open_repair_probe as probe
import memory_vault_open_repair_proof as proof
import memory_vault_open_repair_status as status
import memory_vault_open_repair_wire as wire


@dataclass(frozen=True, slots=True)
class PreparedAckOffer:
    source: object
    proof: proof.AuthenticatedBootstrapProof
    current_statuses: tuple
    originals: object
    metrics: object


class AckOfferClient(AckOwnerRecoveryClient):
    def preflight(self, base_url, *, target_node_entry, expected_target, expected_ack_slot,
                  expected_owner, expected_message_id, expected_envelope_ref,
                  root_entry, write_entry, bootstrap_entry, known_statuses=(), archive_statuses=(),
                  timeout=30, _budget=None):
        if type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0<timeout<=60:
            _fail("repair_invalid_deadline")
        budget = wire.RepairBudget(self.policy) if _budget is None else _budget
        wire._context(self.policy,budget)
        retained = self._retained_inputs(known_statuses, archive_statuses, budget)
        started = self._now()
        deadline = time.monotonic()+timeout
        expected = wire.build_new_wire(dict(target=expected_target,slot=expected_ack_slot,
            owner=expected_owner,message_id=expected_message_id,envelope_ref=expected_envelope_ref),self.policy,budget).value
        checks = _OfferStatusChecks(expected["owner"], self.policy, self.clock)
        setup = bound.verify_ack_offer_bootstrap_original(bootstrap_entry,dict(root=root_entry,write=write_entry),
            expected_ack_slot=expected["slot"],expected_owner=expected["owner"], expected_receipt_writer=self.subject,
            expected_message_id=expected["message_id"],expected_envelope_ref=expected["envelope_ref"],
            at=started,limit_policy=self.limits,policy=self.policy,budget=budget)
        raw,ref = ack._entry(target_node_entry)
        node = original.verify_original_control(raw,expected_signing_key=expected["target"]["signing_key"],
            expected_schema="memory-vault-open-control/v1",expected_kind="node",at=started,policy=self.policy,budget=budget)
        original._node_shape(node,started,budget)
        if len(node.document.raw)!=ref.size or node.raw_sha256!=ref.raw_sha256:
            _fail("repair_ref_mismatch")
        if endpoint(base_url,allow_loopback=self.allow_loopback)!=endpoint(node.payload["base_url"],allow_loopback=self.allow_loopback):
            _fail("repair_proof_mismatch")
        grant = setup.originals["bootstrap"].payload
        obligations = checks.obligations(setup.originals, expected["slot"], budget)
        known = checks._known(retained, obligations, expected["slot"]["root_key"],
                            expected["target"], budget,deferred_authorities=True)
        expiry = min(started+min(60,max(1,int(timeout))),grant["probe_until"],grant["proof_until"],grant["expires_at"],
                     node.payload["expires_at"],*(setup.originals[name].payload["expires_at"] for name in ("root","write")))
        if expiry<=started:
            _fail("repair_access_expired")
        binding = dict(expected_subject=self.subject,expected_target=expected["target"],target_storage_epoch=node.payload["storage_epoch"],
            bootstrap_grant_sha256=setup.originals["bootstrap"].ref.raw_sha256,selector=grant["selector"],policy=self.policy,budget=budget,consumer="ack_offer")
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
            expected_source_state="empty",consumer="ack_offer")
        proof_bytes = len(response)+len(held.handle.raw)+len(held.manifest.raw)
        # Exact originals already supplied by the caller still undergo the
        # full source/history verification below; fetching identical bytes
        # again would needlessly consume the source's finite request grant.
        available={item.ref:item.raw for item in setup.originals.values()}
        for item in retained:
            raw,ref=ack._entry(item)
            if len(raw)==ref.size and budget._hash(raw)==ref.raw_sha256:
                available[ref]=raw
        available[ack._entry(target_node_entry)[1]]=node.document.raw
        originals,roles = {},{}
        for item in held.manifest.value["children"]:
            reference = probe._ref(item["ref"])
            roles.setdefault(item["role"],[]).append(reference)
            if reference in originals:
                continue
            if reference.size>self.policy.max_document_bytes or proof_bytes+reference.size>grant["limits"]["max_proof_bytes"]:
                _fail("repair_over_budget")
            if reference in available:
                assembled=available[reference]
                budget._bytes('input_bytes',len(assembled))
            else:
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
        source_options=dict(expected_ack_slot=expected["slot"],expected_owner=expected["owner"],expected_target=expected["target"],
            target_storage_epoch=node.payload["storage_epoch"],limit_policy=self.limits,policy=self.policy,budget=budget)
        source=empty.verify_ack_empty_source_event(entry("history.ack_empty"),resolver,entry("ack.empty_custody"),
            expected_receipt_writer=self.subject,expected_message_id=expected["message_id"],
            expected_envelope_ref=expected["envelope_ref"],**source_options)
        self._empty_head(entry("ack.head"),source,expected["target"],budget)
        prior=source.predecessor
        # Every displayed historical child must be the exact original in H,
        # not another signed body of the same kind at an unrelated locator.
        for item in source.manifest.roles:
            if roles[item.role]!=[item.original.ref] or originals[item.original.ref]!=item.original.raw:
                _fail("repair_proof_mismatch")
        if (prior.resources.originals["root"].ref!=setup.originals["root"].ref or
                source.authorities.originals["write"].ref!=setup.originals["write"].ref or
                source.authorities.originals["bootstrap"].ref!=setup.originals["bootstrap"].ref):
            _fail("repair_proof_mismatch")
        manifests=(source.manifest,prior.manifest)
        used_packs={wire.raw_ref(item["pack_ref"]) for manifest in manifests for item in manifest.manifest.value["roles"]}
        if set(roles["history.raw_pack"]) != used_packs:
            _fail("repair_unused_pack")
        current=checks.current(source,roles,originals,expected["target"],budget,known)
        # A successful cryptographic check cannot extend the source's signed
        # read promise or a phase deadline while the last originals are checked.
        now = self._now()
        if (now >= min(expiry, held.handle.payload["expires_at"], source.read_until,
                       *(item.payload["valid_until"] for item in current))
                or time.monotonic() >= deadline):
            _fail("repair_access_expired")
        metrics=MappingProxyType(dict(requests=requests,wire_bytes=wire_bytes,proof_bytes=proof_bytes,
                                      **budget.snapshot()))
        return PreparedAckOffer(source,held,current,MappingProxyType(originals),metrics)


class _OfferStatusChecks:
    """Reuse only raw status/history checks with independently supplied A keys."""
    _status_entries = staticmethod(AckOwnerRecoveryClient._status_entries)
    _known = AckOwnerRecoveryClient._known
    _now = AckOwnerRecoveryClient._now

    def __init__(self, owner, policy, clock):
        self.subject, self.policy, self.clock = owner, policy, clock

    def obligations(self, originals, slot, budget):
        result = []
        for name, role, kind, mask in (("root", "ack_root", "ack.root_authority", 3),
                ("write", "ack_write", "ack.write_grant", 1),
                ("bootstrap", "ack_offer_bootstrap", "bootstrap.grant", 3)):
            item = originals[name]
            subject = dict(authority_kind=kind, authority_sha256=item.ref.raw_sha256)
            result.append(dict(role="current.status."+role,kind="authority",subject=subject,
                revision=item.payload["revision"],signer=self.subject["signing_key"],mask=mask,
                scope_id=status.status_scope(slot["root_key"],"authority",subject,self.policy,budget)))
        result.append(dict(role="current.status.ack_slot",kind="ack_slot",subject=slot,
            revision=originals["root"].payload["revision"],signer=self.subject["signing_key"],mask=3,
            scope_id=status.status_scope(slot["root_key"],"ack_slot",slot,self.policy,budget)))
        return result

    def _floors(self, known, current, obligations, *, probe_phase=False, deferred_authorities=False):
        # The owner consumer's DISCOVER/READ default must never suppress the
        # offer's independent ADMIT bit. Preserve exact per-operation masks.
        checks = [item | dict(mask=item["mask"] | (8 if probe_phase and item["role"] in
            ("current.status.ack_root", "current.status.ack_offer_bootstrap") else 0)) for item in obligations]
        return AckOwnerRecoveryClient._floors(self, known, current, checks,
            probe_phase=False, deferred_authorities=deferred_authorities)

    def current(self, source, roles, originals, target, budget, known):
        prior = source.predecessor
        slot = source.custody.payload["ack_slot"]
        obligations = self.obligations(source.authorities.originals, slot, budget)
        active = prior.resources.originals["active"].payload
        obligations.append(dict(role="current.status.ack_resource",kind="resource",subject=active["resource"],
            revision=active["reservation_generation"],signer=target["signing_key"],mask=3,
            scope_id=status.status_scope(slot["root_key"],"resource",active["resource"],self.policy,budget)))
        # These A originals are exact activation dependencies, never B's
        # current read/write authority. Whole signed statuses may mention them.
        for item, kind in ((prior.resources.originals["read"], "ack.read_grant"),
                           (prior.bootstrap.originals["bootstrap"], "bootstrap.grant")):
            subject = dict(authority_kind=kind,authority_sha256=item.ref.raw_sha256)
            obligations.append(dict(role=None,kind="authority",subject=subject,
                revision=item.payload["revision"],signer=self.subject["signing_key"],mask=0,
                scope_id=status.status_scope(slot["root_key"],"authority",subject,self.policy,budget)))
        permitted = {(item["signer"]["key_id"],item["kind"],item["scope_id"]) for item in obligations}
        for observed in known:
            issuer = observed.payload["scope_key"]["issuer_key_id"]
            if any((issuer,item["scope_kind"],item["scope_id"]) not in permitted for item in observed.payload["entries"]):
                _fail("repair_status_disclosure")
        groups = {}
        for item in obligations:
            if item["role"] is not None:
                ref = roles[item["role"]][0]
                group = groups.setdefault(ref,dict(signer=item["signer"],required=[]))
                if group["signer"] != item["signer"]:
                    _fail("repair_proof_mismatch")
                group["required"].append(dict(scope_kind=item["kind"],scope_id=item["scope_id"],
                    document_revision=item["revision"],operation_mask=item["mask"]))
        checked = []
        for ref, group in groups.items():
            allowed = [item for item in obligations if item["signer"] == group["signer"]]
            checked.append(status.verify_status_original(dict(raw=originals[ref],ref=ref.as_dict()),
                expected_root=slot["root_key"],expected_signing_key=group["signer"],at=self._now(),
                allowed_scopes=[dict(scope_kind=item["kind"],scope_id=item["scope_id"]) for item in allowed],
                required=group["required"],policy=self.policy,budget=budget))
        self._floors((*prior.statuses,*source.statuses,*known),checked,obligations)
        if self._now() >= min(active["windows"][name] for name in ("admit_until","read_until","retain_until")):
            _fail("repair_access_expired")
        return tuple(checked)
