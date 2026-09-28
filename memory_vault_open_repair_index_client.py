"""Publish one original ACK source to one explicitly consented directory.

Every outgoing request is journaled before real HTTP. Local preparation and
network verification spend the existing source's finite durable work ledger.
A returned directory lease establishes ADVERTISE only; this module never marks
USABLE or substitutes local source bytes for an independently authorized read.
"""
from dataclasses import dataclass
import hmac
import math
import threading
import time
from types import MappingProxyType

import memory_vault_open_blob as blob
import memory_vault_open_provider as provider
import memory_vault_open_repair_index as index
import memory_vault_open_repair_original as original
import memory_vault_open_repair_probe as probe
import memory_vault_open_repair_resource as resource
import memory_vault_open_repair_stage as stage
import memory_vault_open_repair_status as status
import memory_vault_open_repair_wire as wire
from memory_vault_open_repair_index_access import AckIndexSourceAccess
from memory_vault_open_repair_index_journal import AckIndexJournal
from memory_vault_open_transport import OpenHTTPTransport, endpoint


def _fail(code):
    wire._fail(code)


def _entry(item):
    return dict(raw=item.raw, ref=item.ref.as_dict())


def _sign(payload, signer, policy, budget):
    # Freeze arrays/objects before the low-level canonical signature helper.
    return probe._sign(wire.build_new_wire(payload, policy, budget).value, signer, policy, budget)


def _raw_entry(raw, budget):
    raw = wire._snapshot(raw, budget.policy, budget)
    digest = budget._hash(raw)
    return dict(raw=raw, ref=wire.RawRef("meta", digest, digest, len(raw)).as_dict())


def _encode(entry, budget):
    wire.object_fields(entry, {"raw", "ref"})
    ref = wire.raw_ref(entry["ref"])
    raw = wire._snapshot(entry["raw"], budget.policy, budget)
    if ref.size != len(raw) or budget._hash(raw) != ref.raw_sha256:
        _fail("repair_ref_mismatch")
    return dict(ref=ref.as_dict(), raw_base64url=probe._encode(raw, budget))


def _decode(value, budget):
    wire.object_fields(value, {"ref", "raw_base64url"})
    ref = wire.raw_ref(value["ref"])
    if ref.size > budget.policy.max_document_bytes:
        _fail("repair_over_budget")
    raw = original._decode64(value["raw_base64url"], ref.size, budget, url=True)
    if len(raw) != ref.size or budget._hash(raw) != ref.raw_sha256:
        _fail("repair_ref_mismatch")
    return dict(raw=raw, ref=ref.as_dict())


def _provider(entry, kind, expected_signer, at, budget):
    """Metered verification of the existing finite provider wire domains."""
    wire.object_fields(entry, {"raw", "ref"})
    ref = wire.raw_ref(entry["ref"])
    if ref.namespace != "meta" or wire._raw_size(entry["raw"], budget.policy) > provider.CAPS.get(kind, 65536):
        _fail("repair_invalid_provider_proof")
    parsed = wire.parse_new_wire(entry["raw"], budget.policy, budget)
    if len(parsed.raw) != ref.size or budget._hash(parsed.raw) != ref.raw_sha256:
        _fail("repair_ref_mismatch")
    signed = wire.object_fields(parsed.value, {"payload", "proof"})
    p = wire.object_fields(signed["payload"], provider.COMMON | provider.KINDS[kind])
    maximum = 600 if kind in ("provider.target", "provider.index_lease", "provider.fact") else 60
    if (p["schema_version"] != provider.PROFILE or p["kind"] != kind
            or not 1 <= wire.u53(p["expires_at"]) - wire.u53(p["issued_at"]) <= maximum
            or not p["issued_at"] <= at < p["expires_at"]):
        _fail("repair_provider_proof_expired")
    original._verify_control_signature(p, signed["proof"], expected_signer, budget)
    return resource.AuthenticatedRepairOriginal(parsed.raw, ref, p)


def _node(entry, keys, epoch, at, policy, budget):
    wire.object_fields(entry, {"raw", "ref"})
    ref = wire.raw_ref(entry["ref"])
    checked = original.verify_original_control(entry["raw"], expected_signing_key=keys["signing_key"],
        expected_schema="memory-vault-open-control/v1", expected_kind="node", at=at, policy=policy, budget=budget)
    original._node_shape(checked, at, budget)
    if (ref.namespace != "meta" or checked.raw_sha256 != ref.raw_sha256
            or len(checked.document.raw) != ref.size or checked.payload["storage_epoch"] != epoch):
        _fail("repair_ref_mismatch")
    return checked, dict(raw=checked.document.raw, ref=ref.as_dict())


@dataclass(frozen=True, slots=True)
class AckIndexPublication:
    state: str
    index_lease: object
    fact: object
    directory: object
    metrics: object


class AckIndexPublicationClient:
    def __init__(self, access, *, encryption_identity, transport=None, allow_loopback=False):
        if type(access) is not AckIndexSourceAccess:
            _fail("repair_invalid_context")
        self.access, self.state = access, access.state
        self.identity, self.encryption = self.state.identity, encryption_identity
        self.policy = self.state.policy
        self.journal = AckIndexJournal(self.state)
        self.transport = transport or OpenHTTPTransport(allow_loopback=allow_loopback)
        self.allow_loopback, self._own_transport = allow_loopback, transport is None
        self._lock = threading.Lock()
        if (self.policy.max_signature_checks > 64
                or encryption_identity.public_descriptor() != self.state.target["encryption_key"]):
            _fail("repair_invalid_context")

    def close(self):
        if self._own_transport:
            self.transport.close()

    def _budget(self):
        return wire.RepairBudget(self.policy)

    def _now(self):
        return self.state._now()

    def _guard(self):
        decision = self.access.check_locked(self.prepared)
        return decision.code if not decision.allowed else None

    def _expected(self, budget):
        return dict(expected_subject=self.state.target, expected_target=self.plan.intent["target"],
            target_storage_epoch=self.plan.intent["target_storage_epoch"], at=self._now(), policy=self.policy, budget=budget)

    def _time(self):
        if self._now() >= self.until or time.monotonic() >= self.deadline:
            _fail("repair_access_expired")

    def _local(self, function):
        budget = self._budget()
        with self.journal.preparation_work(self.resource_id, budget):
            self._time()
            return function(budget)

    def _step(self, number, build, check_request, verify, *, mode="repair", response_allowance=8192):
        """An exact immutable request, including retries, precedes every send."""
        saved = self.journal.saved_step(self.resource_id, number)
        def prepare(budget):
            request = bytes(saved["request"]) if saved is not None else build(budget)
            check_request(request, budget)
            if saved is not None and saved["response"] is not None:
                response = bytes(saved["response"])
                return request, response, verify(response, request, budget)
            return request, None, None
        request, response, result = self._local(prepare)
        if response is not None:
            return request, response, result
        attempt = self.journal.begin(self.resource_id, number, request,
            signature_allowance=self.policy.max_signature_checks, response_allowance=response_allowance, guard=self._guard)
        budget = self._budget()
        self._time()
        if mode == "provider":
            outgoing = wire.parse_new_wire(request, self.policy, budget).value
            reply = self.transport.request(self.base, outgoing, deadline=self.deadline)
            response = wire.build_new_wire(reply.response, self.policy, budget).raw
            # Provider canonical-object responses have no original RawRef.
            # Charge the actual wire length and refuse ambiguous normalization.
            if reply.wire_bytes != len(response):
                _fail("repair_invalid_response")
        elif mode == "blob":
            header, chunk = stage._decode_frame(request, self.policy, budget)
            outgoing = wire.parse_new_wire(header["raw"], self.policy, budget).value
            reply = self.transport.request_blob(self.base, outgoing, chunk, deadline=self.deadline)
            response = blob.encode_blob_frame(reply.header, reply.chunk)
            budget._bytes("output_bytes", len(response))
            if reply.wire_bytes != len(response):
                _fail("repair_invalid_response")
        else:
            response = self.transport.request_repair(self.base, request, deadline=self.deadline)
        if type(response) is not bytes or not 0 < len(response) <= response_allowance:
            _fail("repair_invalid_response")
        result = verify(response, request, budget)
        self._time()
        self.journal.finish(self.resource_id, attempt, response,
            signature_checks=budget.snapshot()["signature_checks"], guard=self._guard)
        self.requests += 1
        self.wire_bytes += len(request) + len(response)
        return request, response, result

    def _provider_rpc(self, action, body, budget):
        payload = dict(schema_version=provider.PROFILE, kind="provider.rpc", signing_key=self.state.target["signing_key"],
            issued_at=self._now(), expires_at=self.until, request_id=probe._fresh_id("indexrpc", budget),
            node_key_id=self.plan.intent["target"]["signing_key"]["key_id"], storage_epoch=self.plan.intent["target_storage_epoch"],
            action=action, body=body)
        return _sign(payload, self.identity, self.policy, budget).raw

    def _request_provider(self, raw, action, budget):
        checked = _provider(_raw_entry(raw, budget), "provider.rpc", self.state.target["signing_key"], self._now(), budget)
        p = checked.payload
        if (p["action"] != action or p["node_key_id"] != self.plan.intent["target"]["signing_key"]["key_id"]
                or p["storage_epoch"] != self.plan.intent["target_storage_epoch"] or p["expires_at"] > self.until):
            _fail("repair_provider_proof_mismatch")
        wire.object_fields(p["body"], set() if action == "target.get" else {"target", "challenge"})
        return checked

    def _response_provider(self, raw, request, action, budget):
        outgoing = self._request_provider(request, action, budget)
        checked = _provider(_raw_entry(raw, budget), "provider.response", self.plan.intent["target"]["signing_key"], self._now(), budget)
        p, q = checked.payload, outgoing.payload
        if (p["request_id"] != q["request_id"] or p["request_sha256"] != outgoing.ref.raw_sha256
                or p["node_key_id"] != q["node_key_id"] or p["storage_epoch"] != q["storage_epoch"]
                or p["expires_at"] > q["expires_at"] or p["issued_at"] < q["issued_at"]):
            _fail("repair_provider_proof_mismatch")
        wire.object_fields(p["body"], {"target"} if action == "target.get" else {"answer"})
        return p["body"]

    def _target(self, value, budget):
        raw = wire.build_new_wire(value, self.policy, budget).raw
        checked = _provider(_raw_entry(raw, budget), "provider.target", self.plan.intent["target"]["signing_key"], self._now(), budget)
        p = checked.payload
        if (p["node_key_id"] != self.plan.intent["target"]["signing_key"]["key_id"]
                or p["storage_epoch"] != self.plan.intent["target_storage_epoch"]
                or p["targetEncryptionKey"] != self.plan.intent["target"]["encryption_key"]):
            _fail("repair_provider_proof_mismatch")
        return checked

    def _prove_directory(self, nonce):
        def first_response(raw, request, budget):
            value = self._response_provider(raw, request, "target.get", budget)["target"]
            return self._target(value, budget)
        _, _, target = self._step(0, lambda b: self._provider_rpc("target.get", {}, b),
            lambda raw, b: self._request_provider(raw, "target.get", b), first_response, mode="provider")
        def answer_request(budget):
            p = dict(schema_version=provider.PROFILE, kind="provider.target.challenge", signing_key=self.state.target["signing_key"],
                issued_at=self._now(), expires_at=min(self.until, target.payload["expires_at"]),
                challenge_id=probe._fresh_id("indexproof", budget), target_sha256=target.ref.raw_sha256,
                node_key_id=target.payload["node_key_id"], storage_epoch=target.payload["storage_epoch"])
            p["jwe"] = probe._encrypt(nonce, self.plan.intent["target"]["encryption_key"], p, "jwe", self.policy, budget)
            challenge = _sign(p, self.identity, self.policy, budget)
            return self._provider_rpc("target.answer", dict(target=wire.parse_new_wire(target.raw, self.policy, budget).value,
                challenge=wire.parse_new_wire(challenge.raw, self.policy, budget).value), budget)
        def request_check(raw, budget):
            q = self._request_provider(raw, "target.answer", budget)
            held_target = self._target(q.payload["body"]["target"], budget)
            if held_target.raw != target.raw:
                _fail("repair_provider_proof_mismatch")
            c_raw = wire.build_new_wire(q.payload["body"]["challenge"], self.policy, budget).raw
            c = _provider(_raw_entry(c_raw, budget), "provider.target.challenge", self.state.target["signing_key"], self._now(), budget)
            if (c.payload["target_sha256"] != target.ref.raw_sha256 or c.payload["node_key_id"] != target.payload["node_key_id"]
                    or c.payload["storage_epoch"] != target.payload["storage_epoch"] or c.payload["expires_at"] > min(self.until, target.payload["expires_at"])):
                _fail("repair_provider_proof_mismatch")
            probe._jwe(c.payload["jwe"], probe._aad(c.payload, "jwe", budget), self.plan.intent["target"]["encryption_key"], self.policy, budget)
            return c
        def response_check(raw, request, budget):
            c = request_check(request, budget)
            a = self._response_provider(raw, request, "target.answer", budget)["answer"]
            a_raw = wire.build_new_wire(a, self.policy, budget).raw
            a = _provider(_raw_entry(a_raw, budget), "provider.target.answer", self.plan.intent["target"]["signing_key"], self._now(), budget)
            p = a.payload
            if (p["challenge_sha256"] != c.ref.raw_sha256 or p["target_sha256"] != target.ref.raw_sha256
                    or p["requester_key_id"] != self.identity.key_id or p["node_key_id"] != target.payload["node_key_id"]
                    or p["storage_epoch"] != target.payload["storage_epoch"] or p["expires_at"] > c.payload["expires_at"]
                    or not hmac.compare_digest(nonce, original._decode64(p["answer"], 32, budget, url=True))):
                _fail("repair_provider_proof_mismatch")
            return a
        self._step(1, answer_request, request_check, response_check, mode="provider")

    def _artifact(self, name, build, *, status_revision=False):
        reservation = self.journal.reserve_artifact(self.resource_id, name, guard=self._guard, status_revision=status_revision)
        if reservation["raw"] is None:
            raw = self._local(lambda budget: build(reservation, budget))
            reservation = self.journal.save_artifact(self.resource_id, name, raw, guard=self._guard)
        return bytes(reservation["raw"])

    def _advance(self, state, evidence):
        order = ("prepare", "allocated", "staged", "advertised", "usable")
        current = self.journal.snapshot(self.resource_id)
        if order.index(current["state"]) <= order.index(state):
            self.journal.transition(self.resource_id, state, evidence=evidence, next_due=self.until, guard=self._guard)

    def _allocation(self, entry, budget):
        checked = index._signed(entry, self.state.target["signing_key"], "resource.allocate", index.ALLOCATE_FIELDS, self.policy, budget)
        p = checked.payload
        index._timed(p, self._now())
        original._opaque(p["request_id"])
        if (p["intent"] != self.plan.intent or p["intent_sha256"] != self.plan.intent_sha256
                or p["target_node_key_id"] != self.plan.intent["target"]["signing_key"]["key_id"]
                or p["target_storage_epoch"] != self.plan.intent["target_storage_epoch"]
                or p["issued_at"] < max(self.plan.owner_consent.payload["issued_at"], self.plan.recipient_consent.payload["issued_at"])):
            _fail("repair_ack_index_mismatch")
        return checked

    def _allocate(self, supplied):
        def create(reserved, budget):
            if supplied is not None:
                return self._allocation(supplied, budget).raw
            p = dict(schema_version=resource.SCHEMA, kind="resource.allocate", signing_key=self.state.target["signing_key"],
                issued_at=reserved["created_at"], expires_at=self.plan.publish_until, request_id="index_" + self.plan.intent_sha256,
                target_node_key_id=self.plan.intent["target"]["signing_key"]["key_id"],
                target_storage_epoch=self.plan.intent["target_storage_epoch"], intent=self.plan.intent, intent_sha256=self.plan.intent_sha256)
            return _sign(p, self.identity, self.policy, budget).raw
        raw = self._artifact("allocation", create)
        allocation = self._local(lambda b: self._allocation(dict(raw=raw, ref=supplied["ref"]) if supplied is not None else _raw_entry(raw, b), b))
        parties = self.access.parties(self.prepared)
        owner, writer = parties["owner"], parties["receipt_writer"]
        def carrier(budget):
            return wire.build_new_wire(dict(schema_version=stage.SCHEMA, kind="ack.index_allocate", allocation=_encode(_entry(allocation), budget),
                owner=owner, receipt_writer=writer), self.policy, budget).raw
        def check_request(raw, budget):
            p = wire.parse_new_wire(raw, self.policy, budget).value
            wire.object_fields(p, {"schema_version", "kind", "allocation", "owner", "receipt_writer"})
            item = self._allocation(_decode(p["allocation"], budget), budget)
            if (p["schema_version"] != stage.SCHEMA or p["kind"] != "ack.index_allocate"
                    or p["owner"] != owner or p["receipt_writer"] != writer or item.ref != allocation.ref or item.raw != allocation.raw):
                _fail("repair_ack_index_mismatch")
        def check_response(raw, request, budget):
            check_request(request, budget)
            p = wire.parse_new_wire(raw, self.policy, budget).value
            wire.object_fields(p, {"schema_version", "kind", "offer", "status"})
            if p["schema_version"] != stage.SCHEMA or p["kind"] != "ack.index_allocation":
                _fail("repair_invalid_response")
            offer = index._signed(_decode(p["offer"], budget), self.plan.intent["target"]["signing_key"],
                "resource.offer", index.OFFER_FIELDS, self.policy, budget)
            o = offer.payload
            resource._budget(o["budget"]); resource._windows(o["windows"]); index.history._resource(o["resource"])
            original._opaque(o["offer_id"]); wire.u53(o["reservation_generation"], 1)
            if (o["intent"] != self.plan.intent or o["intent_sha256"] != self.plan.intent_sha256
                    or o["allocation_request_ref"] != allocation.ref.as_dict()
                    or o["target_encryption_key"] != self.plan.intent["target"]["encryption_key"]
                    or o["resource"]["node_key_id"] != self.plan.intent["target"]["signing_key"]["key_id"]
                    or o["resource"]["storage_epoch"] != self.plan.intent["target_storage_epoch"]
                    or o["budget"] != self.plan.intent["budget"] or o["windows"] != self.plan.intent["windows"]
                    or not allocation.payload["issued_at"] <= wire.u53(o["issued_at"]) <= self._now() < wire.u53(o["reservation_until"])):
                _fail("repair_ack_index_mismatch")
            observation = _decode(p["status"], budget)
            scope = status.status_scope(self.plan.intent["root_key"], "resource", o["resource"], self.policy, budget)
            status.authenticate_status_original(observation, expected_root=self.plan.intent["root_key"],
                expected_signing_key=self.plan.intent["target"]["signing_key"], at=self._now(),
                allowed_scopes=[dict(scope_kind="resource", scope_id=scope)], policy=self.policy, budget=budget)
            return offer, observation
        _, response, pair = self._step(2, carrier, check_request, check_response, response_allowance=16384)
        self._advance("allocated", response)
        return allocation, *pair

    def _assign(self, allocation, offer, directory_status):
        def assignment(reserved, budget):
            p = dict(schema_version=resource.SCHEMA, kind="maintenance.assignment", signing_key=self.state.target["signing_key"],
                issued_at=reserved["created_at"], expires_at=self.plan.publish_until, assignment_id="index_" + self.plan.intent_sha256,
                job_id=self.plan.intent["job_id"], root_key=self.plan.intent["root_key"],
                parent_root_ref=self.plan.source.predecessor.predecessor.resources.originals["root"].ref.as_dict(),
                parent_assignment_ref=None, depth=2, subject=probe._dual(self.plan.intent["target"]),
                target_node_key_id=self.plan.intent["target"]["signing_key"]["key_id"], target_storage_epoch=self.plan.intent["target_storage_epoch"],
                operation_mask=16, scope=self.plan.intent["scope"], resource_intent_sha256=self.plan.intent_sha256,
                resource_offer_ref=offer.ref.as_dict(), resource=offer.payload["resource"], bootstrap_grant_refs=[],
                budget=offer.payload["budget"], windows=offer.payload["windows"])
            return _sign(p, self.identity, self.policy, budget).raw
        raw = self._artifact("assignment", assignment)
        item = self._local(lambda b: _raw_entry(raw, b))
        def observation(reserved, budget):
            scope = status.status_scope(self.plan.intent["root_key"], "assignment",
                dict(assignment_kind="maintenance.assignment", assignment_sha256=item["ref"]["raw_sha256"]), self.policy, budget)
            p = dict(schema_version=status.SCHEMA, kind="authority.status", signing_key=self.state.target["signing_key"],
                scope_key=dict(root_key=self.plan.intent["root_key"], issuer_key_id=self.identity.key_id), revision=reserved["status_revision"],
                issued_at=reserved["created_at"], valid_until=self.plan.publish_until,
                entries=[dict(scope_kind="assignment", scope_id=scope, minimum_document_revision=0, status="active", operation_mask=16)])
            return _sign(p, self.identity, self.policy, budget).raw
        status_raw = self._artifact("assignment_status", observation, status_revision=True)
        assignment_status = self._local(lambda b: _raw_entry(status_raw, b))
        self.prepared = self.access.prepare_assignment(self.prepared, allocation_entry=_entry(allocation), offer_entry=_entry(offer),
            assignment_entry=item, directory_statuses=[assignment_status, directory_status])
        self.plan = self.access.plan(self.prepared)
        with self.state._transaction():
            code = self._guard()
        if code is not None:
            _fail(code)
        return self.access.assignment(self.prepared).assignment, assignment_status

    def _children(self, assignment, assignment_status, provider_node_entry, budget):
        source = self.plan.source
        originals = self.access.originals(self.prepared)
        manifest_ref = wire.raw_ref(source.commit.payload["historical_manifest_ref"])
        pairs = [("index.assignment", _entry(assignment)), ("index.owner_consent", _entry(self.plan.owner_consent)),
            ("index.recipient_consent", _entry(self.plan.recipient_consent)), ("index.provider_fact", _entry(self.plan.fact)),
            ("index.source_head", _entry(self.plan.head)), ("index.source_manifest", dict(raw=originals[manifest_ref], ref=manifest_ref.as_dict())),
            ("index.source_commit", _entry(source.commit)), ("provider.node", provider_node_entry), ("directory.status", assignment_status)]
        pairs.extend(("current.status", _entry(item)) for item in self.plan.statuses)
        packs = set()
        for generation in (source, source.predecessor, source.predecessor.predecessor):
            packs.update(wire.raw_ref(item["pack_ref"]) for item in generation.manifest.manifest.value["roles"])
        if len(packs) != 3:
            _fail("repair_unused_pack")
        pairs.extend(("history.raw_pack", dict(raw=originals[ref], ref=ref.as_dict())) for ref in packs)
        pairs.sort(key=lambda item: (item[0], *index.history._ref_tuple(item[1]["ref"])))
        draft = stage.make_stage_manifest(root_key=self.plan.intent["root_key"], scope=self.plan.intent["scope"],
            children=[dict(index=i, role=role, ref=entry["ref"]) for i, (role, entry) in enumerate(pairs)], policy=self.policy, budget=budget)
        return pairs, draft

    def _stage(self, assignment, assignment_status, provider_node_entry):
        children, manifest = self._local(lambda b: self._children(assignment, assignment_status, provider_node_entry, b))
        def intent_request(budget):
            return stage.make_stage_intent(self.identity, allocation_id=self.plan.intent["allocation_id"], manifest=manifest.value,
                expires_at=self.until, **self._expected(budget)).raw
        def intent_check(raw, budget):
            item = stage.verify_stage_intent(_raw_entry(raw, budget), **self._expected(budget))
            if item.payload["manifest"] != manifest.value or item.payload["allocation_id"] != self.plan.intent["allocation_id"]:
                _fail("repair_stage_mismatch")
            return item
        def challenge_check(raw, request, budget):
            intent = intent_check(request, budget)
            return stage.verify_stage_challenge(_raw_entry(raw, budget), _entry(intent), **self._expected(budget))
        intent_raw, _, challenge = self._step(3, intent_request, intent_check, challenge_check, response_allowance=16384)
        intent = self._local(lambda b: intent_check(intent_raw, b))
        def answer_request(budget):
            return stage.solve_stage_challenge(_entry(intent), _entry(challenge), signer=self.identity, encryption_identity=self.encryption,
                expires_at=self.until, **self._expected(budget)).raw
        def answer_check(raw, budget):
            # The subject can recover its nonce from the exact retained challenge.
            nonce = probe._decrypt(challenge.payload["jwe"], self.encryption, self.state.target["encryption_key"],
                probe._aad(challenge.payload, "jwe", budget), budget)
            return stage.verify_stage_answer(_entry(intent), _entry(challenge), _raw_entry(raw, budget), caller_nonce=nonce, **self._expected(budget))
        def handle_check(raw, request, budget):
            answer_check(request, budget)
            return stage.verify_stage_handle(_raw_entry(raw, budget), _entry(intent), **self._expected(budget))
        _, _, handle = self._step(4, answer_request, answer_check, handle_check, response_allowance=8192)
        step = 5
        for child_index, (_, child) in enumerate(children):
            for offset in range(0, len(child["raw"]), stage.STAGE_CHUNK_BYTES):
                def build(budget, child_index=child_index, offset=offset, child=child):
                    return stage.make_stage_child_frame(_entry(intent), _entry(handle), signer=self.identity, child_index=child_index,
                        offset=offset, chunk=child["raw"][offset:offset + stage.STAGE_CHUNK_BYTES], expires_at=self.until, **self._expected(budget))
                def check(raw, budget, child_index=child_index, offset=offset, child=child):
                    checked = stage.verify_stage_child_frame(raw, _entry(intent), _entry(handle), **self._expected(budget))
                    if (checked.child_index != child_index or checked.offset != offset or checked.child_ref != wire.raw_ref(child["ref"])
                            or checked.chunk != child["raw"][offset:offset + stage.STAGE_CHUNK_BYTES]):
                        _fail("repair_stage_mismatch")
                def receipt(raw, request, budget):
                    return stage.verify_stage_child_response_frame(raw, request, _entry(intent), _entry(handle), **self._expected(budget))
                self._step(step, build, check, receipt, mode="blob", response_allowance=8192)
                step += 1
        def close_request(budget):
            return stage.make_stage_close(_entry(intent), _entry(handle), signer=self.identity, expires_at=self.until, **self._expected(budget)).raw
        def close_check(raw, budget):
            return stage.verify_stage_close(_raw_entry(raw, budget), _entry(intent), _entry(handle), **self._expected(budget))
        def result_check(raw, request, budget):
            return stage.verify_stage_result(_raw_entry(raw, budget), _raw_entry(request, budget), _entry(intent), _entry(handle), **self._expected(budget))
        _, result_raw, result = self._step(step, close_request, close_check, result_check, response_allowance=8192)
        self._advance("staged", result_raw)
        return result, step + 1

    def _publish_request(self, allocation, offer, assignment, result, budget):
        originals, scopes = index._permissions(self.plan.originals, self.identity.key_id, self.policy, budget)
        p = dict(schema_version=resource.SCHEMA, kind="ack.index_publish", signing_key=self.state.target["signing_key"],
            issued_at=self._now(), expires_at=self.until, request_id=probe._fresh_id("indexpublish", budget),
            subject=probe._dual(self.state.target), target=probe._dual(self.plan.intent["target"]),
            target_storage_epoch=self.plan.intent["target_storage_epoch"], allocation_request_ref=allocation.ref.as_dict(),
            resource_offer_ref=offer.ref.as_dict(), assignment_ref=assignment.ref.as_dict(), owner_consent_ref=self.plan.owner_consent.ref.as_dict(),
            recipient_consent_ref=self.plan.recipient_consent.ref.as_dict(), provider_fact_ref=self.plan.fact.ref.as_dict(),
            source_head_ref=self.plan.head.ref.as_dict(), historical_manifest_ref=self.plan.source.commit.payload["historical_manifest_ref"],
            original_ack_commit_ref=self.plan.source.commit.ref.as_dict(), stage_result_ref=result.ref.as_dict(),
            source_disclosure=dict(originals=originals, status_scopes=scopes, until=self.until))
        return _sign(p, self.identity, self.policy, budget).raw

    def _publish_check(self, raw, allocation, offer, assignment, result, budget):
        item = index._signed(_raw_entry(raw, budget), self.state.target["signing_key"], "ack.index_publish", index.REQUEST_FIELDS, self.policy, budget)
        p = item.payload
        index._timed(p, self._now()); original._opaque(p["request_id"])
        wanted = dict(allocation_request_ref=allocation.ref, resource_offer_ref=offer.ref, assignment_ref=assignment.ref,
            owner_consent_ref=self.plan.owner_consent.ref, recipient_consent_ref=self.plan.recipient_consent.ref,
            provider_fact_ref=self.plan.fact.ref, source_head_ref=self.plan.head.ref, original_ack_commit_ref=self.plan.source.commit.ref,
            stage_result_ref=result.ref)
        if (any(p[name] != ref.as_dict() for name, ref in wanted.items()) or p["subject"] != probe._dual(self.state.target)
                or p["target"] != probe._dual(self.plan.intent["target"]) or p["target_storage_epoch"] != self.plan.intent["target_storage_epoch"]
                or p["historical_manifest_ref"] != self.plan.source.commit.payload["historical_manifest_ref"]
                or p["expires_at"] > self.until or p["issued_at"] < max(assignment.payload["issued_at"], result.payload["closed_at"])):
            _fail("repair_ack_index_mismatch")
        index._disclosure(p["source_disclosure"], self.plan.originals, self.identity.key_id,
            min(self.until, p["expires_at"]), self._now(), self.policy, budget)
        return item

    def _lease(self, raw, request, allocation, offer, assignment, result, budget):
        outgoing = self._publish_check(request, allocation, offer, assignment, result, budget)
        p = wire.parse_new_wire(raw, self.policy, budget).value
        wire.object_fields(p, {"schema_version", "kind", "index_lease"})
        if p["schema_version"] != stage.SCHEMA or p["kind"] != "ack.index_published":
            _fail("repair_invalid_response")
        lease_raw = wire.build_new_wire(p["index_lease"], self.policy, budget).raw
        lease = _provider(_raw_entry(lease_raw, budget), "provider.index_lease", self.plan.intent["target"]["signing_key"], self._now(), budget)
        l, f = lease.payload, self.plan.fact.payload
        original._opaque(l["index_lease_id"])
        if (l["node_key_id"] != self.plan.intent["target"]["signing_key"]["key_id"] or l["storage_epoch"] != self.plan.intent["target_storage_epoch"]
                or l["fact_sha256"] != self.plan.fact.ref.raw_sha256 or l["ref"] != f["ref"] or l["provider_key_id"] != self.identity.key_id
                or l["provider_storage_epoch"] != f["storage_epoch"] or l["custody_id"] != f["custody_id"]
                or l["index_lease_id"] != "index_" + outgoing.ref.raw_sha256 or l["issued_at"] < outgoing.payload["issued_at"]
                or l["expires_at"] > min(self.plan.publish_until, f["expires_at"], offer.payload["windows"]["publish_until"])):
            _fail("repair_ack_index_mismatch")
        return p["index_lease"]

    def publish(self, resource_id, base_url, *, target_node_entry, provider_node_entry, expected_directory,
                provider_fact_entry, intent, owner_consent_entry, recipient_consent_entry, current_statuses,
                allocation_entry=None, timeout=60):
        if not self._lock.acquire(blocking=False):
            _fail("repair_index_busy")
        try:
            return self._publish(resource_id, base_url, target_node_entry=target_node_entry, provider_node_entry=provider_node_entry,
                expected_directory=expected_directory, provider_fact_entry=provider_fact_entry, intent=intent,
                owner_consent_entry=owner_consent_entry, recipient_consent_entry=recipient_consent_entry,
                current_statuses=current_statuses, allocation_entry=allocation_entry, timeout=timeout)
        finally:
            self._lock.release()

    def _publish(self, resource_id, base_url, *, target_node_entry, provider_node_entry, expected_directory,
                provider_fact_entry, intent, owner_consent_entry, recipient_consent_entry, current_statuses,
                allocation_entry, timeout):
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 60:
            _fail("repair_invalid_deadline")
        self.resource_id, self.base = resource_id, base_url
        self.deadline = time.monotonic() + timeout
        self.requests = self.wire_bytes = 0
        self.prepared = self.access.prepare(resource_id, provider_fact_entry=provider_fact_entry, intent=intent,
            owner_consent_entry=owner_consent_entry, recipient_consent_entry=recipient_consent_entry,
            current_statuses=current_statuses, expected_directory=expected_directory, directory_storage_epoch=intent["target_storage_epoch"])
        self.plan = self.access.plan(self.prepared)
        self.until = min(self._now() + 60, self.plan.publish_until)
        budget = self._budget()
        with self.journal.preparation_work(resource_id, budget):
            try:
                saved = self.journal.snapshot(resource_id)
            except wire.RepairWireError as error:
                if error.code != "repair_index_job_missing":
                    raise
                saved = None
            if saved is not None:
                plan = wire.parse_new_wire(bytes(saved["plan"]), self.policy, budget)
                wire.object_fields(plan.value, {"semantic", "until", "nonce"})
                wire.object_fields(plan.value["semantic"], {"schema_version", "kind", "resource_id", "base_url",
                    "target_node", "provider_node", "expected_directory", "provider_fact", "intent", "owner_consent",
                    "recipient_consent", "current_statuses", "allocation"})
                self.until = wire.u53(plan.value["until"])
                nonce = original._decode64(plan.value["nonce"], 32, budget, url=True)
            nodes, frozen_nodes = [], []
            for entry, keys, epoch in ((target_node_entry, expected_directory, self.plan.intent["target_storage_epoch"]),
                    (provider_node_entry, self.state.target, self.state.node["payload"]["storage_epoch"])):
                checked, frozen = _node(entry, keys, epoch, self._now(), self.policy, budget)
                nodes.append(checked)
                frozen_nodes.append(frozen)
            target_node_entry, provider_node_entry = frozen_nodes
            if saved is not None:
                # The running node may renew its introduction while this exact
                # publication awaits a response. Authenticate both revisions,
                # then retain the original staged bytes and original deadline.
                retained, retained_entry = _node(_decode(plan.value["semantic"]["provider_node"], budget),
                    self.state.target, self.state.node["payload"]["storage_epoch"], self._now(), self.policy, budget)
                current, old = nodes[1].payload, retained.payload
                if (any(current[name] != old[name] for name in ("signing_key", "storage_epoch", "base_url", "roles"))
                        or current["revision"] < old["revision"] or current["issued_at"] < old["issued_at"]
                        or current["expires_at"] < old["expires_at"]
                        or (current["revision"] == old["revision"] and nodes[1].document.value != retained.document.value)):
                    _fail("repair_index_job_conflict")
                nodes[1], provider_node_entry = retained, retained_entry
            if allocation_entry is not None:
                allocation_entry = _entry(self._allocation(allocation_entry, budget))
            node = nodes[0]
            if ("directory" not in node.payload["roles"] or endpoint(base_url, allow_loopback=self.allow_loopback)
                    != endpoint(node.payload["base_url"], allow_loopback=self.allow_loopback)):
                _fail("repair_provider_proof_mismatch")
            self.until = min(self.until, *(node.payload["expires_at"] for node in nodes))
            semantic = dict(schema_version=stage.SCHEMA, kind="local.index_publication", resource_id=resource_id, base_url=base_url,
                target_node=_encode(target_node_entry, budget), provider_node=_encode(provider_node_entry, budget), expected_directory=self.plan.intent["target"],
                provider_fact=_encode(_entry(self.plan.fact), budget), intent=self.plan.intent,
                owner_consent=_encode(_entry(self.plan.owner_consent), budget), recipient_consent=_encode(_entry(self.plan.recipient_consent), budget),
                current_statuses=[_encode(_entry(item), budget) for item in self.plan.statuses],
                allocation=None if allocation_entry is None else _encode(allocation_entry, budget))
            if saved is None:
                nonce = probe._fresh_nonce(budget)
                plan = wire.build_new_wire(dict(semantic=semantic, until=self.until, nonce=probe._encode(nonce, budget)), self.policy, budget)
            self.journal.start(resource_id, plan.raw, deadline=self.until, guard=self._guard)
            if saved is not None and plan.value["semantic"] != semantic:
                _fail("repair_index_job_conflict")
        try:
            self._prove_directory(nonce)
            allocation, offer, directory_status = self._allocate(allocation_entry)
            assignment, assignment_status = self._assign(allocation, offer, directory_status)
            result, number = self._stage(assignment, assignment_status, provider_node_entry)
            _, raw, lease = self._step(number,
                lambda b: self._publish_request(allocation, offer, assignment, result, b),
                lambda raw, b: self._publish_check(raw, allocation, offer, assignment, result, b),
                lambda raw, request, b: self._lease(raw, request, allocation, offer, assignment, result, b), response_allowance=8192)
            self._advance("advertised", raw)
            return AckIndexPublication("advertised", lease,
                wire.parse_new_wire(self.plan.fact.raw, self.policy, self._budget()).value,
                wire.parse_new_wire(target_node_entry["raw"], self.policy, self._budget()).value,
                MappingProxyType(dict(requests=self.requests, wire_bytes=self.wire_bytes,
                    durable_attempts=self.journal.snapshot(resource_id)["attempts"], from_local_history=self.requests == 0, usable=False)))
        except Exception as error:
            code = getattr(error, "code", "repair_index_network_failure")
            if not isinstance(code, str) or not code.startswith("repair_"):
                code = "repair_index_network_failure"
            self.journal.defer(resource_id, code, next_due=min(self.until, self._now() + 5))
            raise
