"""Bounded, exact-byte original controls and legacy contact-chain inputs.

Authentication here never activates a resource, grants repair authority, reads
the network or changes a Vault. ``at`` is an explicit caller-supplied historical
time, not proof that an event happened then. Opaque Memory bytes do not enter
this portable-control parser.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hmac
import re
from types import MappingProxyType
from typing import Any

from memory_vault_nodes import _base_url
from memory_vault import MemoryError
from memory_vault_open_contact import COMMON, KINDS, PROFILE, SLOT_BYTES
from memory_vault_open_control import CONTROL_SCHEMA
from memory_vault_open_repair_wire import (
    RepairPolicy, RepairBudget, RepairWireError, U53_MAX, _Parser, _DraftDict, _DraftList,
    _context, _snapshot, _canonical, _fail, _utf8_size, object_fields, u53,
)

_PATHS = frozenset({("payload", "grant"), ("payload", "resource_lease"),
                    ("payload", "grant", "payload", "resource_lease")})
_SIGNED_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]*)\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_DOMAIN = b"UniversalAgentMemory\x00message-signature\x00v1\x00"
_PROOF_SCHEMA = "universal-memory-message-signature/v1"
_KEY_SCHEMA = "universal-memory-public-key/v1"
_ENCRYPTION_SCHEMA = "memory-vault-network-encryption-key/v1"
_ROLES = ("node", "knock_lease", "policy", "request", "decision", "grant", "delivery_lease")
_NODE_FIELDS = {"schema_version", "kind", "signing_key", "revision", "status",
                "issued_at", "expires_at", "coordinate", "base_url", "storage_epoch", "roles"}


def _invalid():
    _fail("repair_invalid_original")


class _OriginalParser(_Parser):
    """Old signed-control numbers/ASCII keys; only three raw spans are held."""

    def __init__(self, text: str, budget: RepairBudget):
        super().__init__(text, budget)
        self.spans = {}

    def _value(self, depth: int):
        # The old portable profile starts at zero; wire work starts at one.
        if depth > 25:
            _invalid()
        self._space()
        if self.pos < len(self.text) and self.text[self.pos] == "-":
            self.budget._node(depth)
            start = self.pos
            while self.pos < len(self.text) and self.text[self.pos] not in " \t\r\n,]}":
                self.pos += 1
            token = self.text[start:self.pos]
            if _SIGNED_INTEGER.fullmatch(token) is None:
                _fail("repair_invalid_json")
            if len(token) > 17 or int(token) < -U53_MAX:
                _fail("repair_invalid_integer")
            return int(token), None
        return super()._value(depth)

    def parse(self):
        value, first = self._value(1)
        stack = [] if first is None else [[*first, (), 0]]
        while stack:
            frame = stack[-1]
            container, depth, state, path, start = frame
            self._space()
            end = "}" if type(container) is _DraftDict else "]"
            if ((state == "after" or state == "first")
                    and self.pos < len(self.text) and self.text[self.pos] == end):
                self.pos += 1
                if path in _PATHS:
                    self.spans[path] = (start, self.pos)
                stack.pop()
                continue
            if state == "after":
                self._take(",")
                frame[2] = "next"
                self._space()
            child_path = None
            if type(container) is _DraftDict:
                self.budget._node(depth + 1)
                key = self._string()
                if not key.isascii():
                    _invalid()
                if key in container:
                    _fail("repair_invalid_json")
                self._space()
                self._take(":")
                if path is not None:
                    candidate = (*path, key)
                    if any(item[:len(candidate)] == candidate for item in _PATHS):
                        child_path = candidate
            self._space()
            child_start = self.pos
            child, child_frame = self._value(depth + 1)
            if type(container) is _DraftDict:
                dict.__setitem__(container, key, child)
            else:
                list.append(container, child)
            frame[2] = "after"
            if child_frame is not None:
                stack.append([*child_frame, child_path, child_start])
            elif child_path in _PATHS:
                self.spans[child_path] = (child_start, self.pos)
        self._space()
        if self.pos != len(self.text):
            _fail("repair_invalid_json")
        return value


@dataclass(frozen=True, slots=True)
class DraftOriginalControl:
    raw: bytes
    value: Any
    _spans: Any
    _budget: RepairBudget

    def nested_raw(self, path: tuple[str, ...]) -> bytes:
        # A fixed tuple allowlist bounds caller paths and avoids generic queries.
        if (type(path) is not tuple or len(path) not in (2, 4)
                or any(type(item) is not str or len(item) > 14 for item in path)
                or path not in _PATHS or path not in self._spans):
            _invalid()
        with self._budget._lock:
            start, end = self._spans[path]
            self._budget._bytes("output_bytes", end - start)
            return self.raw[start:end]


def parse_original_control(raw: bytes, policy: RepairPolicy,
                           budget: RepairBudget) -> DraftOriginalControl:
    """Preserve original bytes and lexical nested grants, without authority."""
    _context(policy, budget)
    with budget._lock:
        original = _snapshot(raw, policy, budget)
        try:
            text = original.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            _fail("repair_invalid_utf8")
        parser = _OriginalParser(text, budget)
        value = parser.parse()
        if type(value) is not _DraftDict:
            _invalid()
        # Translate only fixed span endpoints in one bounded, allocation-free
        # scan. No UTF-8 prefix slices or per-character offset table is built.
        wanted = {point for span in parser.spans.values() for point in span}
        offsets, offset = {}, 0
        for index, char in enumerate(text):
            if index in wanted:
                offsets[index] = offset
            offset += _utf8_size(char)
        if len(text) in wanted:
            offsets[len(text)] = offset
        spans = MappingProxyType({path: (offsets[start], offsets[end])
                                  for path, (start, end) in parser.spans.items()})
        return DraftOriginalControl(original, value, spans, budget)


def _fields(value, names):
    if type(value) not in (dict, _DraftDict) or value.keys() != set(names):
        _invalid()
    return value


def _key_id(value, prefix="ed25519"):
    if type(value) is not str or re.fullmatch(prefix + r"_[0-9a-f]{64}", value) is None:
        _invalid()
    return value


def _opaque(value):
    if type(value) is not str or _ID.fullmatch(value) is None:
        _invalid()
    return value


def _digest(value):
    if type(value) is not str or _HASH.fullmatch(value) is None:
        _invalid()
    return value


def _decode64(value, size, budget, *, url=False):
    maximum = (size * 4 + 2) // 3 if url else ((size + 2) // 3) * 4
    padding = -size % 3
    alphabet = (r"[A-Za-z0-9_-]*" if url else
                r"[A-Za-z0-9+/]{" + str(maximum - padding) + "}" + "=" * padding)
    if (type(value) is not str or len(value) != maximum
            or re.fullmatch(alphabet, value) is None):
        _invalid()
    budget._bytes("output_bytes", len(value))
    ascii_value = value.encode("ascii")
    encoded = ascii_value
    if url and len(value) % 4:
        budget._bytes("output_bytes", len(value) + (-len(value) % 4))
        encoded = ascii_value + b"=" * (-len(value) % 4)
    # Capacity before decode, then count only a buffer actually returned by the
    # provider. Malformed base64 does not invent a decoded-buffer charge.
    budget._fits("output_bytes", size, budget.policy.max_total_bytes - budget._usage["input_bytes"])
    try:
        raw = base64.b64decode(encoded, altchars=b"-_" if url else None, validate=True)
    except ValueError:
        _invalid()
    budget._bytes("output_bytes", len(raw))
    budget._bytes("output_bytes", ((len(raw) + 2) // 3) * 4)
    canonical = base64.urlsafe_b64encode(raw) if url else base64.b64encode(raw)
    if url and canonical.endswith(b"="):
        budget._bytes("output_bytes", (len(raw) * 4 + 2) // 3)
        canonical = canonical.rstrip(b"=")
    if len(raw) != size or canonical != ascii_value:
        _invalid()
    return raw


def _descriptor(value, budget, *, encryption=False):
    value = _fields(value, {"schema_version", "algorithm", "key_id", "public_key"})
    prefix = "x25519" if encryption else "ed25519"
    if (value["schema_version"] != (_ENCRYPTION_SCHEMA if encryption else _KEY_SCHEMA)
            or value["algorithm"] != ("X25519" if encryption else "Ed25519")):
        _invalid()
    _key_id(value["key_id"], prefix)
    raw = _decode64(value["public_key"], 32, budget, url=encryption)
    if value["key_id"] != prefix + "_" + budget._hash(raw):
        _invalid()
    return raw


def _window(payload, at, maximum=U53_MAX):
    issued, expires = u53(payload["issued_at"]), u53(payload["expires_at"])
    if not 1 <= expires - issued <= maximum or issued > at + 30 or expires <= at:
        _fail("repair_invalid_original")


@dataclass(frozen=True, slots=True)
class VerifiedOriginalControl:
    """A fixed-key signature result; not a complete authorization verdict."""
    document: DraftOriginalControl
    payload: Any
    raw_sha256: str
    canonical_sha256: str


def _verify_control_signature(payload, proof, expected_signing_key, budget, *, before_proof=None):
    """Shared real Ed25519 proof math; callers close their own profile/time.

    This private helper accepts only data already parsed/frozen by its caller.
    No trust state is written; charges cover each actual key hash and proof.
    """
    if type(expected_signing_key) is str:
        expected_id = _key_id(expected_signing_key)
    else:
        _fields(expected_signing_key, {"schema_version", "algorithm", "key_id", "public_key"})
        expected_id = _key_id(expected_signing_key["key_id"])
    descriptor = payload["signing_key"]
    public = _descriptor(descriptor, budget)
    if (descriptor["key_id"] != expected_id or
            (type(expected_signing_key) is not str and descriptor != expected_signing_key)):
        _fail("repair_wrong_issuer")
    if before_proof is not None:
        before_proof()
    proof = _fields(proof, {"schema_version", "key_id", "payload_sha256", "signature"})
    if proof["schema_version"] != _PROOF_SCHEMA:
        _invalid()
    if _key_id(proof["key_id"]) != expected_id:
        _fail("repair_wrong_issuer")
    payload_digest = budget._hash(_canonical(payload, budget))
    if not hmac.compare_digest(_digest(proof["payload_sha256"]), payload_digest):
        _fail("repair_invalid_signature")
    signature = _decode64(proof["signature"], 64, budget)
    proof_body = {name: proof[name] for name in ("schema_version", "key_id", "payload_sha256")}
    canonical_proof = _canonical(proof_body, budget)
    budget._bytes("output_bytes", len(_DOMAIN) + len(canonical_proof))
    message = _DOMAIN + canonical_proof
    try:
        from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        _fail("repair_crypto_unavailable")
    try:
        public_key = Ed25519PublicKey.from_public_bytes(public)
        budget._signature_check()  # Immediately before real verify; no refund.
        public_key.verify(signature, message)
    except RepairWireError:
        raise
    except InvalidSignature:
        _fail("repair_invalid_signature")
    except (ValueError, UnsupportedAlgorithm):
        _fail("repair_crypto_unavailable")


def _verify_original_control(raw: bytes, *, expected_signing_key, expected_schema: str,
                             expected_kind: str, at: int, policy: RepairPolicy,
                             budget: RepairBudget, _expected_fields=None,
                             _maximum=None) -> VerifiedOriginalControl:
    _context(policy, budget)
    with budget._lock:
        u53(at)
        if (type(expected_schema) is not str or not 1 <= len(expected_schema) <= 128
                or type(expected_kind) is not str or not 1 <= len(expected_kind) <= 128):
            _invalid()
        if type(expected_signing_key) is str:
            expected_id = _key_id(expected_signing_key)
        else:
            _fields(expected_signing_key, {"schema_version", "algorithm", "key_id", "public_key"})
            expected_id = _key_id(expected_signing_key["key_id"])
        draft = parse_original_control(raw, policy, budget)
        if _maximum is not None and len(draft.raw) > _maximum:
            _invalid()
        signed = _fields(draft.value, {"payload", "proof"})
        payload = signed["payload"]
        if _expected_fields is not None:
            _fields(payload, _expected_fields)
        if (type(payload) is not _DraftDict or not COMMON <= payload.keys()
                or payload["schema_version"] != expected_schema or payload["kind"] != expected_kind):
            _invalid()
        _verify_control_signature(payload, signed["proof"], expected_signing_key, budget,
                                  before_proof=lambda: _window(payload, at))
        raw_digest = budget._hash(draft.raw)
        canonical_digest = budget._hash(_canonical(signed, budget))
        return VerifiedOriginalControl(draft, payload, raw_digest, canonical_digest)


def verify_original_control(raw: bytes, *, expected_signing_key, expected_schema: str,
                            expected_kind: str, at: int, policy: RepairPolicy,
                            budget: RepairBudget) -> VerifiedOriginalControl:
    """Authenticate an expected issuer/profile and finite time; not kind authority.

    Only the outer Signed/proof and common fields are closed here. A consumer
    still needs its kind-specific fields and complete typed authorization chain.
    """
    return _verify_original_control(raw, expected_signing_key=expected_signing_key,
        expected_schema=expected_schema, expected_kind=expected_kind, at=at,
        policy=policy, budget=budget)


def _member(value, choices):
    if type(value) is not str or value not in choices:
        _invalid()


def _limit(value, maximum, minimum=1):
    if u53(value, minimum) > maximum:
        _invalid()


def _contact_shape(original, kind, at, budget):
    raw = _fields(original.payload, COMMON | KINDS[kind])
    maximum = 8192 if kind == "contact.decision" else 4096
    # Legacy document() caps both original bytes and canonical Signed bytes.
    if len(original.document.raw) > maximum:
        _invalid()
    canonical = _canonical(original.document.value, budget)
    if len(canonical) > maximum:
        _invalid()
    _window(raw, at, 86400)
    for name in ("node_key_id", "owner_key_id", "subject_key_id", "recipient_key_id"):
        if name in raw:
            _key_id(raw[name])
    for name in ("subject_encryption_key_id", "recipient_encryption_key_id"):
        if name in raw:
            _key_id(raw[name], "x25519")
    for name in ("lease_id", "resource_id", "request_id", "storage_epoch"):
        if name in raw:
            _opaque(raw[name])
    for name in ("lease_sha256", "request_sha256", "policy_sha256"):
        if name in raw:
            _digest(raw[name])
    for name in ("encryption_key", "owner_encryption_key"):
        if name in raw:
            _descriptor(raw[name], budget, encryption=True)
    if kind == "resource.lease":
        _member(raw["purpose"], {"knock", "delivery"})
        _limit(raw["max_items"], 32)
        _limit(raw["max_bytes"], 16 * 1024 * 1024)
        if (raw["signing_key"]["key_id"] != raw["node_key_id"] or
                (raw["purpose"] == "knock" and raw["max_bytes"] != raw["max_items"] * SLOT_BYTES)):
            _invalid()
    elif kind == "contact.policy":
        u53(raw["revision"], 1)
        _member(raw["status"], {"active", "revoked"})
        _limit(raw["max_pending"], 32)
    elif kind == "contact.request":
        if raw["request_class"] != "message" or raw["signing_key"]["key_id"] == raw["recipient_key_id"]:
            _invalid()
    elif kind == "contact.grant":
        if raw["operations"] != ["message.store"]:
            _invalid()
    elif raw["decision"] != "approved" or raw["reason"] != "accepted":
        _invalid()


def _node_shape(original, at, budget):
    raw = _fields(original.payload, _NODE_FIELDS)
    if len(original.document.raw) > 4096 or len(_canonical(original.document.value, budget)) > 4096:
        _invalid()
    _window(raw, at, 3600)
    u53(raw["revision"], 1)
    if raw["status"] != "active":
        _invalid()
    _opaque(raw["storage_epoch"])
    _digest(raw["coordinate"])
    key_id = raw["signing_key"]["key_id"]
    budget._bytes("output_bytes", len(key_id))
    encoded_key_id = key_id.encode("ascii")
    budget._bytes("output_bytes", len(b"memory-vault-open-routing/v1\x00") + len(encoded_key_id))
    coordinate = b"memory-vault-open-routing/v1\x00" + encoded_key_id
    if budget._hash(coordinate) != raw["coordinate"]:
        _invalid()
    if type(raw["base_url"]) is not str or len(raw["base_url"]) > 512:
        _invalid()
    try:
        _base_url(raw["base_url"])
    except MemoryError:
        _invalid()
    roles = raw["roles"]
    if (type(roles) is not _DraftList or not roles or
            any(type(role) is not str or role not in {"router", "directory"} for role in roles)
            or roles != sorted(set(roles))):
        _invalid()


@dataclass(frozen=True, slots=True)
class VerifiedContactOriginals:
    """Authenticated legacy inputs only; no live grant or R3 authority."""
    originals: Any
    at: int


def verify_contact_originals(originals, *, sender_key_id: str, sender_encryption_key_id: str,
                             recipient_key_id: str, recipient_encryption_key_id: str,
                             node_key_id: str, storage_epoch: str, at: int,
                             policy: RepairPolicy, budget: RepairBudget) -> VerifiedContactOriginals:
    _context(policy, budget)
    with budget._lock:
        _fields(originals, _ROLES)
        u53(at)
        for key in (sender_key_id, recipient_key_id, node_key_id):
            _key_id(key)
        for key in (sender_encryption_key_id, recipient_encryption_key_id):
            _key_id(key, "x25519")
        _opaque(storage_epoch)
        if sender_key_id == recipient_key_id:
            _fail("repair_contact_mismatch")
        kinds = ("node", "resource.lease", "contact.policy", "contact.request",
                 "contact.decision", "contact.grant", "resource.lease")
        issuers = (node_key_id, node_key_id, recipient_key_id, sender_key_id,
                   recipient_key_id, recipient_key_id, node_key_id)
        verified = {}
        # No recursive legacy verifier or hidden repeated signature/hash work.
        for role, kind, issuer in zip(_ROLES, kinds, issuers):
            result = _verify_original_control(originals[role], expected_signing_key=issuer,
                expected_schema=CONTROL_SCHEMA if role == "node" else PROFILE,
                expected_kind=kind, at=at, policy=policy, budget=budget,
                _expected_fields=_NODE_FIELDS if role == "node" else COMMON | KINDS[kind],
                _maximum=8192 if kind == "contact.decision" else 4096)
            if role == "node":
                _node_shape(result, at, budget)
            else:
                _contact_shape(result, kind, at, budget)
            verified[role] = result
        node, knock, owner, request, decision, grant, delivery = [verified[r].payload for r in _ROLES]
        if (verified["decision"].document.nested_raw(("payload", "grant")) != verified["grant"].document.raw
                or verified["grant"].document.nested_raw(("payload", "resource_lease")) != verified["delivery_lease"].document.raw):
            _fail("repair_original_mismatch")
        if node["storage_epoch"] != storage_epoch:
            _fail("repair_contact_mismatch")
        for item in (knock, owner, request, decision, grant, delivery):
            if item["node_key_id"] != node_key_id or item["storage_epoch"] != storage_epoch:
                _fail("repair_contact_mismatch")
        # Node binding requires the original full descriptor, not only row IDs.
        if any(item["signing_key"] != node["signing_key"] for item in (knock, delivery)):
            _fail("repair_contact_mismatch")
        for lease in (knock, delivery):
            if (lease["owner_key_id"] != recipient_key_id
                    or lease["owner_encryption_key"]["key_id"] != recipient_encryption_key_id):
                _fail("repair_contact_mismatch")
        if (knock["purpose"] != "knock" or delivery["purpose"] != "delivery"
                or owner["status"] != "active" or owner["encryption_key"] != knock["owner_encryption_key"]
                or owner["lease_sha256"] != verified["knock_lease"].canonical_sha256
                or owner["max_pending"] > knock["max_items"] or owner["expires_at"] > knock["expires_at"]
                or any(owner[k] != knock[k] for k in ("lease_id", "resource_id"))):
            _fail("repair_contact_mismatch")
        if (request["encryption_key"]["key_id"] != sender_encryption_key_id
                or request["recipient_key_id"] != recipient_key_id
                or request["recipient_encryption_key_id"] != recipient_encryption_key_id
                or request["policy_sha256"] != verified["policy"].canonical_sha256
                or request["expires_at"] > owner["expires_at"]
                or any(request[k] != owner[k] for k in ("lease_id", "resource_id"))):
            _fail("repair_contact_mismatch")
        if (decision["signing_key"] != owner["signing_key"]
                or decision["request_sha256"] != verified["request"].canonical_sha256
                or decision["subject_key_id"] != sender_key_id
                or decision["subject_encryption_key_id"] != sender_encryption_key_id
                or decision["recipient_encryption_key_id"] != recipient_encryption_key_id
                or decision["expires_at"] > request["expires_at"]
                or any(decision[k] != request[k] for k in ("request_id", "policy_sha256"))):
            _fail("repair_contact_mismatch")
        if (any(decision[k] != grant[k] for k in ("request_id", "request_sha256", "signing_key",
                  "subject_key_id", "subject_encryption_key_id", "recipient_encryption_key_id"))
                or grant["expires_at"] > decision["expires_at"]
                or grant["expires_at"] > delivery["expires_at"]
                or grant["resource_id"] != delivery["resource_id"]):
            _fail("repair_contact_mismatch")
        return VerifiedContactOriginals(MappingProxyType(verified), at)
