"""Finite index-admission and ACK-copy staging wire, without storage or authority.

These signatures establish possession and exact provisional-byte bindings.
The caller must separately authenticate publication/allocation permission and
target dual possession, enforce durable one-use state and charge the original
parent budget. A stage result never authorizes publication or an application
commit. No network, database or filesystem operations occur here.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hmac
import struct
from types import MappingProxyType

import memory_vault_open_blob as blob
import memory_vault_open_repair_ack as ack
import memory_vault_open_repair_history as history
import memory_vault_open_repair_original as original
import memory_vault_open_repair_probe as probe
import memory_vault_open_repair_resource as resource
import memory_vault_open_repair_wire as wire

SCHEMA = probe.SCHEMA
MAX_CONTROL_BYTES = probe.MAX_CONTROL_BYTES
STAGE_CHUNK_BYTES = 16384
MAX_STAGE_ITEMS = 64
MAX_STAGE_BYTES = 1024 * 1024
_IDENTITY = frozenset("schema_version kind signing_key subject target_node_key_id target_storage_epoch".split())
_COMMON = _IDENTITY | {"issued_at", "expires_at"}
_FIELDS = {
    "intent": _COMMON | set("allocation_id manifest manifest_sha256 requested_bytes requested_items".split()),
    "challenge": _COMMON | set("challenge_id intent_ref purpose jwe".split()),
    "answer": _COMMON | set("challenge_ref intent_ref purpose answer".split()),
    "handle": _COMMON | set("handle_id intent_ref manifest_ref bootstrap_use_ref reservation_generation reserved_bytes reserved_items".split()),
    "close": _COMMON | {"close_id", "intent_ref", "handle_ref"},
    "result": _IDENTITY | set("intent_ref manifest_ref bootstrap_use_ref reservation_generation closed_at expires_at".split()),
    "child": _COMMON | set("request_id intent_ref handle_ref manifest_ref reservation_generation binding length chunk_sha256".split()),
    "child_response": _COMMON | set("request_ref handle_ref child_index child_ref offset length chunk_sha256 durable_prefix".split()),
}
_NODE_KINDS = frozenset(("challenge", "handle", "result", "child_response"))
SINGLE_STAGE_ROLES = frozenset("index.assignment index.owner_consent index.recipient_consent index.provider_fact index.source_head index.source_manifest index.source_commit provider.node".split())
STAGE_ROLES = SINGLE_STAGE_ROLES | {"current.status", "directory.status", "history.raw_pack"}
COPY_SINGLE_ROLES = ack.ROLES | frozenset(("history.ack_unbound", "ack.slot_custody",
    "copy.reservation_consent", "copy.allocation", "copy.offer", "copy.assignment",
    "copy.owner_disclosure", "copy.source_disclosure"))
COPY_STAGE_ROLES = COPY_SINGLE_ROLES | {"copy.current_status", "history.raw_pack"}
CONSUMERS = frozenset(("index_admit", "ack_copy_unbound"))


def _fail(code="repair_invalid_stage"):
    wire._fail(code)


def _fields(value, names):
    return wire.object_fields(value, names)


def _meta_ref(value):
    value = wire.raw_ref(value)
    if value.namespace != "meta":
        _fail()
    return value


def _entry(checked):
    return dict(raw=checked.raw, ref=checked.ref.as_dict())


def _scope(value, root):
    _fields(value, {"kind", "ack_slot", "grant_ref", "binding_ref", "receipt_ref", "original_ack_commit_ref"})
    if value["kind"] != "ack_occupied":
        _fail()
    history._slot(value["ack_slot"], root, ack=True)
    for name in ("grant_ref", "binding_ref", "original_ack_commit_ref"):
        _meta_ref(value[name])
    wire.raw_ref(value["receipt_ref"])


def _role(value):
    if type(value) is not str or value not in STAGE_ROLES:
        _fail()


def _expected(*, expected_subject, expected_target, target_storage_epoch, at, policy, budget,
              expected_consumer="index_admit"):
    if type(expected_consumer) is not str or expected_consumer not in CONSUMERS:_fail()
    value = wire.build_new_wire(dict(subject=expected_subject, target=expected_target,
                                    epoch=target_storage_epoch, at=at,consumer=expected_consumer), policy, budget).value
    wire.u53(value["at"])
    original._opaque(value["epoch"])
    for name in ("subject", "target"):
        keys = resource._dual_key_shape(value[name])
        original._descriptor(keys["signing_key"], budget)
        original._descriptor(keys["encryption_key"], budget, encryption=True)
    return value


@contextmanager
def _using(options):
    policy, budget = options["policy"], options["budget"]
    wire._context(policy, budget)
    with budget._lock:
        yield _expected(**options), policy, budget


def _window(payload, at):
    issued = wire.u53(payload.get("issued_at", payload.get("closed_at")))
    expires = wire.u53(payload["expires_at"])
    if not (1 <= expires - issued <= 60 and issued <= at < expires):
        _fail("repair_stage_expired")


def _base(kind, expected, expires_at):
    payload = dict(schema_version=SCHEMA, kind="proof.stage_" + kind,
        signing_key=expected["target" if kind in _NODE_KINDS else "subject"]["signing_key"],
        expires_at=wire.u53(expires_at),
        subject=expected["subject"] if kind == "intent" else probe._dual(expected["subject"]),
        target_node_key_id=expected["target"]["signing_key"]["key_id"],
        target_storage_epoch=expected["epoch"])
    payload["closed_at" if kind == "result" else "issued_at"] = expected["at"]
    _window(payload, expected["at"])
    return payload


def _manifest(value, policy, budget, expected_consumer=None):
    _fields(value, {"schema_version", "kind", "consumer", "root_key", "scope", "children"})
    if (value["schema_version"] != SCHEMA or value["kind"] != "proof.stage_manifest"
            or type(value["consumer"]) is not str or value["consumer"] not in CONSUMERS
            or expected_consumer is not None and value["consumer"] != expected_consumer):
        _fail()
    history._root(value["root_key"])
    # Consumer binding is checked again on every signed intent verification;
    # directory admission must never accept the replica upload profile.
    copying=value["consumer"]=="ack_copy_unbound"
    if copying:
        from memory_vault_open_repair_copy_resources import ack_copy_scope
        ack_copy_scope(value["scope"],value["root_key"])
        if value["scope"]["kind"]!="ack_unbound":_fail()
    else:
        _scope(value["scope"], value["root_key"])
    children = value["children"]
    if type(children) is not wire._DraftList or not 1 <= len(children) <= min(MAX_STAGE_ITEMS, policy.max_entries):
        _fail("repair_stage_capacity")
    previous, locators, counts, total = None, {}, {}, 0
    for index, child in enumerate(children):
        _fields(child, {"index", "role", "ref"})
        if wire.u53(child["index"]) != index:
            _fail()
        role = child["role"]
        if type(role) is not str or role not in (COPY_STAGE_ROLES if copying else STAGE_ROLES):_fail()
        counts[role] = counts.get(role, 0) + 1
        ref = wire.raw_ref(child["ref"])
        pair = (role, ref.namespace, ref.key, ref.raw_sha256, ref.size)
        if previous is not None and pair <= previous:
            _fail()
        previous = pair
        # The original object receipt remains inside its exact historical pack;
        # this metadata stage accepts no direct object/E upload.
        if ref.namespace != "meta":
            _fail()
        if ref.size > policy.max_document_bytes:
            _fail("repair_stage_capacity")
        location = (ref.namespace, ref.key)
        if location in locators and locators[location] != ref:
            # Repeating a complete original under another role is allowed, but
            # its declared transfer bytes/items are still charged each time.
            _fail()
        locators[location] = ref
        total += ref.size
        if total > min(MAX_STAGE_BYTES, policy.max_retained_bytes, wire.U53_MAX):
            _fail("repair_stage_capacity")
    if copying:
        if (any(counts.get(role)!=1 for role in COPY_SINGLE_ROLES)
                or not 1<=counts.get("history.raw_pack",0)<=len(ack.ROLES)
                or not 1<=counts.get("copy.current_status",0)<=16):_fail()
    elif (any(counts.get(role) != 1 for role in SINGLE_STAGE_ROLES)
            or counts.get("history.raw_pack") != 3 or counts.get("directory.status") != 1
            or not 1 <= counts.get("current.status", 0) <= 16):
        _fail()
    raw = wire._canonical(value, budget)
    if len(raw) > MAX_CONTROL_BYTES:
        _fail("repair_stage_capacity")
    digest = budget._hash(raw)
    return wire.RawRef("meta", digest, digest, len(raw)), total, len(children)


def make_stage_manifest(*, root_key, scope, children, policy, budget, consumer="index_admit"):
    wire._context(policy, budget)
    with budget._lock:
        draft = wire.build_new_wire(dict(schema_version=SCHEMA, kind="proof.stage_manifest", consumer=consumer,
                                        root_key=root_key, scope=scope, children=children), policy, budget)
        _manifest(draft.value, policy, budget)
        return draft


def _verify(entry, kind, expected, policy, budget, *, cap=MAX_CONTROL_BYTES):
    _fields(entry, {"raw", "ref"})
    reference = _meta_ref(entry["ref"])
    if wire._raw_size(entry["raw"], policy) > cap:
        _fail("repair_stage_capacity")
    draft = wire.parse_new_wire(entry["raw"], policy, budget)
    if len(draft.raw) != reference.size or budget._hash(draft.raw) != reference.raw_sha256:
        _fail("repair_ref_mismatch")
    signed = _fields(draft.value, {"payload", "proof"})
    payload = _fields(signed["payload"], _FIELDS[kind])
    _window(payload, expected["at"])
    if payload["schema_version"] != SCHEMA or payload["kind"] != "proof.stage_" + kind:
        _fail()
    if (payload["subject"] != (expected["subject"] if kind == "intent" else probe._dual(expected["subject"]))
            or payload["target_node_key_id"] != expected["target"]["signing_key"]["key_id"]
            or payload["target_storage_epoch"] != expected["epoch"]):
        _fail("repair_stage_mismatch")
    if kind == "intent":
        original._opaque(payload["allocation_id"])
        ref, total, count = _manifest(payload["manifest"], policy, budget,expected["consumer"])
        if (payload["manifest_sha256"] != ref.raw_sha256 or wire.u53(payload["requested_bytes"], 1) != total
                or wire.u53(payload["requested_items"], 1) != count):
            _fail("repair_stage_mismatch")
    for name in ("intent_ref", "challenge_ref", "handle_ref", "manifest_ref", "request_ref"):
        if name in payload:
            _meta_ref(payload[name])
    for name in ("challenge_id", "handle_id", "close_id", "request_id"):
        if name in payload:
            original._opaque(payload[name])
    if kind in ("challenge", "answer"):
        if payload["purpose"] != "proof.stage":
            _fail()
        if kind == "challenge":
            probe._jwe(payload["jwe"], probe._aad(payload, "jwe", budget), expected["subject"]["encryption_key"], policy, budget)
        else:
            original._decode64(payload["answer"], 32, budget, url=True)
    if kind in ("handle", "result"):
        if payload["bootstrap_use_ref"] is not None:
            _fail()
        wire.u53(payload["reservation_generation"], 1)
    if kind == "handle":
        wire.u53(payload["reserved_bytes"], 1)
        wire.u53(payload["reserved_items"], 1)
    if kind == "child":
        binding = _fields(payload["binding"], {"kind", "handle_id", "child_index", "offset"})
        if binding["kind"] != "repair_proof_child":
            _fail()
        original._opaque(binding["handle_id"])
        wire.u53(binding["child_index"]); wire.u53(binding["offset"])
        wire.u53(payload["reservation_generation"], 1)
        wire.u53(payload["length"], 1); original._digest(payload["chunk_sha256"])
    if kind == "child_response":
        wire.raw_ref(payload["child_ref"])
        for name in ("child_index", "offset", "durable_prefix"):
            wire.u53(payload[name])
        wire.u53(payload["length"], 1); original._digest(payload["chunk_sha256"])
    original._verify_control_signature(payload, signed["proof"],
        expected["target" if kind in _NODE_KINDS else "subject"]["signing_key"], budget)
    return resource.AuthenticatedRepairOriginal(draft.raw, reference, payload)


def _bound(child, parent, field):
    issued = child.payload.get("issued_at", child.payload.get("closed_at"))
    if (_meta_ref(child.payload[field]) != parent.ref or issued < parent.payload["issued_at"]
            or child.payload["expires_at"] > parent.payload["expires_at"]):
        _fail("repair_stage_mismatch")


def _sign(payload, signer, policy, budget):
    return probe._sign(payload, signer, policy, budget)


def make_stage_intent(signer, *, allocation_id, manifest, expires_at, **options):
    with _using(options) as (expected, policy, budget):
        # Snapshot external mutable JSON before deriving commitments.
        value = wire.build_new_wire(manifest, policy, budget).value
        ref, total, count = _manifest(value, policy, budget,expected["consumer"])
        original._opaque(allocation_id)
        payload = _base("intent", expected, expires_at)
        payload.update(allocation_id=allocation_id, manifest=value, manifest_sha256=ref.raw_sha256,
                       requested_bytes=total, requested_items=count)
        return _sign(payload, signer, policy, budget)


def verify_stage_intent(entry, **options):
    with _using(options) as (expected, policy, budget):
        return _verify(entry, "intent", expected, policy, budget)


@dataclass(frozen=True, slots=True)
class PreparedStageChallenge:
    original: resource.AuthenticatedRepairOriginal
    nonce: bytes


@dataclass(frozen=True, slots=True)
class AuthenticatedStageExchange:
    originals: object
    at: int


def issue_stage_challenge(intent_entry, *, signer, expires_at, **options):
    with _using(options) as (expected, policy, budget):
        intent = _verify(intent_entry, "intent", expected, policy, budget)
        payload = _base("challenge", expected, expires_at)
        payload.update(challenge_id=probe._fresh_id("stage", budget), intent_ref=intent.ref.as_dict(), purpose="proof.stage")
        if expires_at > intent.payload["expires_at"]:
            _fail("repair_stage_mismatch")
        nonce = probe._fresh_nonce(budget)
        payload["jwe"] = probe._encrypt(nonce, expected["subject"]["encryption_key"], payload, "jwe", policy, budget)
        return PreparedStageChallenge(_sign(payload, signer, policy, budget), nonce)


def _challenge(intent_entry, challenge_entry, expected, policy, budget):
    intent = _verify(intent_entry, "intent", expected, policy, budget)
    challenge = _verify(challenge_entry, "challenge", expected, policy, budget)
    _bound(challenge, intent, "intent_ref")
    return intent, challenge


def verify_stage_challenge(challenge_entry, intent_entry, **options):
    with _using(options) as (expected, policy, budget):
        return _challenge(intent_entry, challenge_entry, expected, policy, budget)[1]


def solve_stage_challenge(intent_entry, challenge_entry, *, signer, encryption_identity, expires_at, **options):
    with _using(options) as (expected, policy, budget):
        intent, challenge = _challenge(intent_entry, challenge_entry, expected, policy, budget)
        payload = _base("answer", expected, expires_at)
        if expires_at > challenge.payload["expires_at"]:
            _fail("repair_stage_mismatch")
        nonce = probe._decrypt(challenge.payload["jwe"], encryption_identity, expected["subject"]["encryption_key"],
                               probe._aad(challenge.payload, "jwe", budget), budget)
        payload.update(challenge_ref=challenge.ref.as_dict(), intent_ref=intent.ref.as_dict(), purpose="proof.stage",
                       answer=probe._encode(nonce, budget))
        return _sign(payload, signer, policy, budget)


def _answer(intent_entry, challenge_entry, answer_entry, caller_nonce, expected, policy, budget):
    intent, challenge = _challenge(intent_entry, challenge_entry, expected, policy, budget)
    answer = _verify(answer_entry, "answer", expected, policy, budget)
    _bound(answer, challenge, "challenge_ref"); _bound(answer, intent, "intent_ref")
    if not hmac.compare_digest(probe._nonce(caller_nonce, budget), original._decode64(answer.payload["answer"], 32, budget, url=True)):
        _fail("repair_invalid_nonce")
    return intent, challenge, answer


def verify_stage_answer(intent_entry, challenge_entry, answer_entry, *, caller_nonce, **options):
    with _using(options) as (expected, policy, budget):
        checked = _answer(intent_entry, challenge_entry, answer_entry, caller_nonce, expected, policy, budget)
        return AuthenticatedStageExchange(MappingProxyType(dict(zip(("intent", "challenge", "answer"), checked))), expected["at"])


def make_stage_handle(intent_entry, challenge_entry, answer_entry, *, caller_nonce, signer,
                      reservation_generation, expires_at, **options):
    with _using(options) as (expected, policy, budget):
        intent, challenge, answer = _answer(intent_entry, challenge_entry, answer_entry, caller_nonce, expected, policy, budget)
        if expires_at > answer.payload["expires_at"]:
            _fail("repair_stage_mismatch")
        ref, total, count = _manifest(intent.payload["manifest"], policy, budget)
        payload = _base("handle", expected, expires_at)
        payload.update(handle_id=probe._fresh_id("stagehandle", budget), intent_ref=intent.ref.as_dict(),
            manifest_ref=ref.as_dict(), bootstrap_use_ref=None, reservation_generation=wire.u53(reservation_generation, 1),
            reserved_bytes=total, reserved_items=count)
        return _sign(payload, signer, policy, budget)


def _handle(intent_entry, handle_entry, expected, policy, budget):
    intent = _verify(intent_entry, "intent", expected, policy, budget)
    handle = _verify(handle_entry, "handle", expected, policy, budget)
    _bound(handle, intent, "intent_ref")
    ref, total, count = _manifest(intent.payload["manifest"], policy, budget)
    if (_meta_ref(handle.payload["manifest_ref"]) != ref or handle.payload["reserved_bytes"] != total
            or handle.payload["reserved_items"] != count):
        _fail("repair_stage_mismatch")
    return intent, handle


def verify_stage_handle(handle_entry, intent_entry, **options):
    with _using(options) as (expected, policy, budget):
        return _handle(intent_entry, handle_entry, expected, policy, budget)[1]


def _range(intent, index, offset):
    wire.u53(index); wire.u53(offset)
    children = intent.payload["manifest"]["children"]
    if index >= len(children):
        _fail("repair_stage_mismatch")
    ref = wire.raw_ref(children[index]["ref"])
    if offset >= ref.size or offset % STAGE_CHUNK_BYTES:
        _fail("repair_stage_range")
    return ref, min(STAGE_CHUNK_BYTES, ref.size - offset)


def _encode_frame(header, chunk, budget):
    if not (0 < len(header.raw) <= blob.MAX_BLOB_HEADER_BYTES and len(chunk) <= blob.MAX_BLOB_CHUNK_BYTES):
        _fail("repair_stage_capacity")
    budget._bytes("output_bytes", 8 + blob.BLOB_PREFIX_BYTES + len(header.raw) + len(chunk))
    return b"".join((blob.MAGIC, struct.pack(">II", len(header.raw), len(chunk)), header.raw, chunk))


def _decode_frame(frame, policy, budget):
    if type(frame) not in (bytes, bytearray, memoryview):
        _fail()
    try:
        with memoryview(frame) as view:
            size = view.nbytes
            if not blob.BLOB_PREFIX_BYTES < size <= blob.MAX_BLOB_FRAME_BYTES:
                _fail("repair_stage_capacity")
            budget._bytes("input_bytes", size)
            budget._bytes("output_bytes", len(blob.MAGIC))
            if bytes(view[:len(blob.MAGIC)]) != blob.MAGIC:
                _fail()
            header_size, chunk_size = struct.unpack_from(">II", view, len(blob.MAGIC))
            if not (0 < header_size <= blob.MAX_BLOB_HEADER_BYTES and chunk_size <= blob.MAX_BLOB_CHUNK_BYTES
                    and size == blob.BLOB_PREFIX_BYTES + header_size + chunk_size):
                _fail("repair_stage_capacity")
            budget._bytes("output_bytes", header_size + chunk_size)
            header = view[blob.BLOB_PREFIX_BYTES:blob.BLOB_PREFIX_BYTES + header_size].tobytes()
            chunk = view[blob.BLOB_PREFIX_BYTES + header_size:].tobytes()
    except wire.RepairWireError:
        raise
    except (ValueError, BufferError, TypeError, struct.error):
        _fail()
    digest = budget._hash(header)
    return dict(raw=header, ref=wire.RawRef("meta", digest, digest, len(header)).as_dict()), chunk


@dataclass(frozen=True, slots=True)
class VerifiedStageChild:
    header: resource.AuthenticatedRepairOriginal
    chunk: bytes
    child_ref: wire.RawRef
    child_index: int
    offset: int


def _child_frame(frame, intent, handle, expected, policy, budget):
    entry, chunk = _decode_frame(frame, policy, budget)
    header = _verify(entry, "child", expected, policy, budget, cap=blob.MAX_BLOB_HEADER_BYTES)
    _bound(header, intent, "intent_ref"); _bound(header, handle, "handle_ref")
    payload, parent = header.payload, handle.payload
    binding = payload["binding"]
    if (payload["manifest_ref"] != parent["manifest_ref"] or payload["reservation_generation"] != parent["reservation_generation"]
            or binding["handle_id"] != parent["handle_id"]):
        _fail("repair_stage_mismatch")
    ref, length = _range(intent, binding["child_index"], binding["offset"])
    if payload["length"] != length or len(chunk) != length or budget._hash(chunk) != payload["chunk_sha256"]:
        _fail("repair_stage_chunk_mismatch")
    # One-chunk children can already be checked against their complete RawRef;
    # larger children are checked again by the durable assembler before close.
    if binding["offset"] == 0 and length == ref.size and payload["chunk_sha256"] != ref.raw_sha256:
        _fail("repair_ref_mismatch")
    return VerifiedStageChild(header, chunk, ref, binding["child_index"], binding["offset"])


def make_stage_child_frame(intent_entry, handle_entry, *, signer, child_index, offset, chunk, expires_at, **options):
    with _using(options) as (expected, policy, budget):
        intent, handle = _handle(intent_entry, handle_entry, expected, policy, budget)
        ref, length = _range(intent, child_index, offset)
        if wire._raw_size(chunk, policy) != length:
            _fail("repair_stage_range")
        chunk = wire._snapshot(chunk, policy, budget)
        payload = _base("child", expected, expires_at)
        if expires_at > handle.payload["expires_at"]:
            _fail("repair_stage_mismatch")
        digest = budget._hash(chunk)
        if offset == 0 and length == ref.size and digest != ref.raw_sha256:
            _fail("repair_ref_mismatch")
        payload.update(request_id=probe._fresh_id("stagechild", budget), intent_ref=intent.ref.as_dict(), handle_ref=handle.ref.as_dict(),
            manifest_ref=handle.payload["manifest_ref"], reservation_generation=handle.payload["reservation_generation"],
            binding=dict(kind="repair_proof_child", handle_id=handle.payload["handle_id"], child_index=child_index, offset=offset),
            length=length, chunk_sha256=digest)
        return _encode_frame(_sign(payload, signer, policy, budget), chunk, budget)


def verify_stage_child_frame(frame, intent_entry, handle_entry, **options):
    with _using(options) as (expected, policy, budget):
        intent, handle = _handle(intent_entry, handle_entry, expected, policy, budget)
        return _child_frame(frame, intent, handle, expected, policy, budget)


def make_stage_child_response_frame(request_frame, intent_entry, handle_entry, *, signer, durable_prefix, expires_at, **options):
    with _using(options) as (expected, policy, budget):
        intent, handle = _handle(intent_entry, handle_entry, expected, policy, budget)
        child = _child_frame(request_frame, intent, handle, expected, policy, budget)
        if not child.offset + len(child.chunk) <= wire.u53(durable_prefix) <= child.child_ref.size:
            _fail("repair_stage_range")
        if expires_at > child.header.payload["expires_at"]:
            _fail("repair_stage_mismatch")
        payload = _base("child_response", expected, expires_at)
        payload.update(request_ref=child.header.ref.as_dict(), handle_ref=handle.ref.as_dict(), child_index=child.child_index,
            child_ref=child.child_ref.as_dict(), offset=child.offset, length=len(child.chunk),
            chunk_sha256=child.header.payload["chunk_sha256"], durable_prefix=durable_prefix)
        return _encode_frame(_sign(payload, signer, policy, budget), b"", budget)


def verify_stage_child_response_frame(response_frame, request_frame, intent_entry, handle_entry, **options):
    with _using(options) as (expected, policy, budget):
        intent, handle = _handle(intent_entry, handle_entry, expected, policy, budget)
        child = _child_frame(request_frame, intent, handle, expected, policy, budget)
        entry, chunk = _decode_frame(response_frame, policy, budget)
        if chunk:
            _fail()
        response = _verify(entry, "child_response", expected, policy, budget, cap=blob.MAX_BLOB_HEADER_BYTES)
        _bound(response, child.header, "request_ref"); _bound(response, handle, "handle_ref")
        p = response.payload
        if (p["child_index"] != child.child_index or wire.raw_ref(p["child_ref"]) != child.child_ref
                or p["offset"] != child.offset or p["length"] != len(child.chunk)
                or p["chunk_sha256"] != child.header.payload["chunk_sha256"]
                or not child.offset + len(child.chunk) <= p["durable_prefix"] <= child.child_ref.size):
            _fail("repair_stage_mismatch")
        return response


def make_stage_close(intent_entry, handle_entry, *, signer, expires_at, **options):
    with _using(options) as (expected, policy, budget):
        intent, handle = _handle(intent_entry, handle_entry, expected, policy, budget)
        if expires_at > handle.payload["expires_at"]:
            _fail("repair_stage_mismatch")
        payload = _base("close", expected, expires_at)
        payload.update(close_id=probe._fresh_id("stageclose", budget), intent_ref=intent.ref.as_dict(), handle_ref=handle.ref.as_dict())
        return _sign(payload, signer, policy, budget)


def _close(close_entry, intent_entry, handle_entry, expected, policy, budget):
    intent, handle = _handle(intent_entry, handle_entry, expected, policy, budget)
    close = _verify(close_entry, "close", expected, policy, budget)
    _bound(close, intent, "intent_ref"); _bound(close, handle, "handle_ref")
    return intent, handle, close


def verify_stage_close(close_entry, intent_entry, handle_entry, **options):
    with _using(options) as (expected, policy, budget):
        return _close(close_entry, intent_entry, handle_entry, expected, policy, budget)[2]


def make_stage_result(close_entry, intent_entry, handle_entry, *, signer, expires_at, **options):
    """Sign a provisional completion; caller must first durably verify all bytes."""
    with _using(options) as (expected, policy, budget):
        intent, handle, close = _close(close_entry, intent_entry, handle_entry, expected, policy, budget)
        if expires_at > close.payload["expires_at"]:
            _fail("repair_stage_mismatch")
        payload = _base("result", expected, expires_at)
        payload.update(intent_ref=intent.ref.as_dict(), manifest_ref=handle.payload["manifest_ref"], bootstrap_use_ref=None,
                       reservation_generation=handle.payload["reservation_generation"])
        return _sign(payload, signer, policy, budget)


def verify_stage_result(result_entry, close_entry, intent_entry, handle_entry, **options):
    with _using(options) as (expected, policy, budget):
        intent, handle, close = _close(close_entry, intent_entry, handle_entry, expected, policy, budget)
        result = _verify(result_entry, "result", expected, policy, budget)
        _bound(result, intent, "intent_ref")
        p = result.payload
        if (p["manifest_ref"] != handle.payload["manifest_ref"] or p["reservation_generation"] != handle.payload["reservation_generation"]
                or p["closed_at"] < close.payload["issued_at"] or p["expires_at"] > close.payload["expires_at"]):
            _fail("repair_stage_mismatch")
        return result
