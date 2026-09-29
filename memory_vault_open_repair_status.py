"""Metered original status observations for explicitly scoped repair inputs.

The caller derives expected scopes from authenticated typed parents. This
module checks a retained observation at its original event time. It neither
loads nor mutates current durable revision floors or grants a live operation.
"""
from dataclasses import dataclass

import memory_vault_open_repair_history as history
import memory_vault_open_repair_original as original
import memory_vault_open_repair_wire as wire

SCHEMA = "memory-vault-open-authority/v1"
MAX_STATUS_BYTES = 16384
MAX_STATUS_SECONDS = 604800
AUTHORITY_KINDS = frozenset(("ack.root_authority", "ack.read_grant",
                            "ack.write_grant", "bootstrap.grant", "ack.disclosure",
                            "ack.index_consent", "ack.copy_reservation_consent", "ack.copy_disclosure", "mailbox.root_authority", "mailbox.root_read_grant",
                            "mailbox.maintenance_root", "mailbox.read_grant", "delivery.destination",
                            "message.disclosure"))
SCOPE_KINDS = frozenset(("catalog", "mailbox_slot", "ack_slot", "authority",
                       "resource", "assignment", "contact_policy"))
_PAYLOAD = frozenset(("schema_version", "kind", "signing_key", "scope_key",
                      "revision", "issued_at", "valid_until", "entries"))
_ENTRY = frozenset(("scope_kind", "scope_id", "minimum_document_revision",
                    "status", "operation_mask"))


def _fail(code="repair_invalid_status"):
    raise wire.RepairWireError(code)


def _fields(value, names):
    try:
        return wire.object_fields(value, names)
    except wire.RepairWireError:
        _fail()


def _number(value, minimum=0):
    try:
        return wire.u53(value, minimum)
    except wire.RepairWireError:
        _fail()


def _root(value):
    try:
        history._root(value)
    except wire.RepairWireError:
        _fail()


def _scope_key(value):
    if type(value["scope_kind"]) is not str or value["scope_kind"] not in SCOPE_KINDS:
        _fail()
    try:
        original._digest(value["scope_id"])
    except wire.RepairWireError:
        _fail()
    return value["scope_kind"], value["scope_id"]


def _mask(value):
    if _number(value, 1) > 127:
        _fail()


def status_scope(root, scope_kind, subject, policy, budget):
    """Hash a closed typed scope, separately from a role alias or RawRef."""
    wire._context(policy, budget)
    with budget._lock:
        value = wire.build_new_wire(dict(root=root, scope_kind=scope_kind,
                                         subject=subject), policy, budget).value
        root, subject, kind = value["root"], value["subject"], value["scope_kind"]
        _root(root)
        if kind == "authority":
            _fields(subject, {"authority_kind", "authority_sha256"})
            if type(subject["authority_kind"]) is not str or subject["authority_kind"] not in AUTHORITY_KINDS:
                _fail()
            try:
                original._digest(subject["authority_sha256"])
            except wire.RepairWireError:
                _fail()
            payload = dict(kind=kind, root_key=root, **subject)
        elif kind == "resource":
            try:
                history._resource(subject)
            except wire.RepairWireError:
                _fail()
            payload = dict(kind=kind, root_key=root, resource=subject)
        elif kind == "ack_slot":
            try:
                history._slot(subject, root, ack=True)
            except wire.RepairWireError:
                _fail()
            payload = dict(kind=kind, root_key=root, ack_slot=subject)
        elif kind == "mailbox_slot":
            try:
                history._slot(subject, root)
            except wire.RepairWireError:
                _fail()
            payload = dict(kind=kind, root_key=root, slot_key=subject)
        elif kind == "catalog":
            _fields(subject, {"root_key"})
            if subject["root_key"] != root or root["root_kind"] != "mailbox":
                _fail()
            payload = dict(kind=kind, root_key=root)
        elif kind == "assignment":
            _fields(subject, {"assignment_kind", "assignment_sha256"})
            if subject["assignment_kind"] != "maintenance.assignment":
                _fail()
            try:
                original._digest(subject["assignment_sha256"])
            except wire.RepairWireError:
                _fail()
            payload = dict(kind=kind, root_key=root, **subject)
        else:
            _fail()
        return budget._hash(wire._canonical(payload, budget))


@dataclass(frozen=True, slots=True)
class AuthenticatedStatusOriginal:
    raw: bytes
    ref: wire.RawRef
    payload: object
    raw_sha256: str
    canonical_sha256: str
    at: int


def _status_original(entry, *, expected_root, expected_signing_key, at,
                     allowed_scopes, required, policy, budget, enforce_required,
                     on_authenticated=None):
    """Verify one whole original and its required retained observations.

    allowed_scopes is the complete set whose originals the enclosing typed
    owner/node proof may disclose. This function refuses an unrelated extra
    entry; it never projects a subset of a Signed document. It does not infer
    that the caller's expected scope list itself is an authorization chain.
    """
    wire._context(policy, budget)
    if on_authenticated is not None and not callable(on_authenticated):
        wire._fail("repair_invalid_context")
    with budget._lock:
        _fields(entry, {"raw", "ref"})
        if wire._raw_size(entry["raw"], policy) > MAX_STATUS_BYTES:
            _fail()
        # All caller expectation graphs and reference descriptors are copied
        # through the bounded constructor before their nested values are used.
        expected = wire.build_new_wire(dict(root=expected_root, signing_key=expected_signing_key,
            at=at, allowed_scopes=allowed_scopes, required=required, ref=entry["ref"]), policy, budget).value
        _root(expected["root"])
        at = _number(expected["at"])
        ref = wire.raw_ref(_fields(expected["ref"], {"namespace", "key", "raw_sha256", "size"}))
        if ref.namespace != "meta":
            _fail()
        allowed, obligations = {}, {}
        for name, fields, target in (
            ("allowed_scopes", {"scope_kind", "scope_id"}, allowed),
            ("required", {"scope_kind", "scope_id", "document_revision", "operation_mask"}, obligations)):
            values = expected[name]
            minimum = 0 if name == "required" and not enforce_required else 1
            if type(values) is not wire._DraftList or not minimum <= len(values) <= 16:
                _fail()
            for value in values:
                _fields(value, fields)
                key = _scope_key(value)
                if key in target:
                    _fail()
                if name == "required":
                    _number(value["document_revision"])
                    _mask(value["operation_mask"])
                target[key] = value
        if not obligations.keys() <= allowed.keys():
            _fail()
        document = original.parse_original_control(entry["raw"], policy, budget)
        raw_hash = budget._hash(document.raw)
        if len(document.raw) != ref.size or raw_hash != ref.raw_sha256:
            _fail("repair_ref_mismatch")
        signed = _fields(document.value, {"payload", "proof"})
        payload = _fields(signed["payload"], _PAYLOAD)
        if payload["schema_version"] != SCHEMA or payload["kind"] != "authority.status":
            _fail()
        scope = _fields(payload["scope_key"], {"root_key", "issuer_key_id"})
        _root(scope["root_key"])
        signing = payload["signing_key"]
        if (scope["root_key"] != expected["root"] or type(signing) is not wire._DraftDict
                or scope["issuer_key_id"] != signing.get("key_id")):
            _fail("repair_status_mismatch")
        _number(payload["revision"], 1)
        issued, until = _number(payload["issued_at"]), _number(payload["valid_until"])
        # An optional durable observer may retain an expired, fully authentic
        # original before live use is refused. Future or malformed intervals
        # remain invalid before observation; the original skew rule is intact.
        expired = at >= until
        if not (1 <= until - issued <= MAX_STATUS_SECONDS and issued <= at + 30
                and (not expired or on_authenticated is not None)):
            _fail("repair_status_mismatch")
        entries = payload["entries"]
        if type(entries) is not wire._DraftList or not 1 <= len(entries) <= 16:
            _fail()
        seen, previous = {}, None
        for value in entries:
            _fields(value, _ENTRY)
            key = _scope_key(value)
            if previous is not None and key <= previous:
                _fail()
            previous = key
            _number(value["minimum_document_revision"])
            _mask(value["operation_mask"])
            if value["status"] not in ("active", "revoked"):
                _fail()
            seen[key] = value
        canonical = wire._canonical(signed, budget)
        if len(canonical) > MAX_STATUS_BYTES:
            _fail()
        original._verify_control_signature(payload, signed["proof"], expected["signing_key"], budget)
        canonical_hash = budget._hash(canonical)
        if not seen.keys() <= allowed.keys():
            _fail("repair_status_disclosure")
        authenticated = AuthenticatedStatusOriginal(document.raw, ref, payload, raw_hash, canonical_hash, at)
        if on_authenticated is not None:
            # Every byte/ref, closed shape, expected issuer/root, whole typed
            # disclosure scope and signature has passed. This is evidence,
            # not an assertion that the original authorizes anything at at.
            on_authenticated(authenticated)
        if expired:
            _fail("repair_status_mismatch")
        if not obligations.keys() <= seen.keys():
            _fail("repair_status_missing")
        for key, obligation in obligations.items():
            observation = seen[key]
            if observation["status"] == "revoked":
                _fail("repair_authority_revoked")
            if observation["minimum_document_revision"] > obligation["document_revision"]:
                _fail("repair_status_revision")
            if observation["operation_mask"] & obligation["operation_mask"] != obligation["operation_mask"]:
                _fail("repair_status_operation")
        return authenticated


def authenticate_status_original(entry, *, expected_root, expected_signing_key, at,
                                 allowed_scopes, policy, budget, on_authenticated=None):
    """Authenticate a whole, currently timed observation, including denials.

    The caller must derive the finite disclosure scopes from verified parents.
    This returns authenticated revoked/minimum/mask observations for a durable
    gate to record before denying access; it grants no operation by itself.
    """
    return _status_original(entry, expected_root=expected_root,
        expected_signing_key=expected_signing_key, at=at, allowed_scopes=allowed_scopes,
        required=[], policy=policy, budget=budget, enforce_required=False,
        on_authenticated=on_authenticated)


def verify_status_original(entry, *, expected_root, expected_signing_key, at,
                           allowed_scopes, required, policy, budget, on_authenticated=None):
    """Authenticate one whole original and enforce its historical requirements."""
    return _status_original(entry, expected_root=expected_root,
        expected_signing_key=expected_signing_key, at=at, allowed_scopes=allowed_scopes,
        required=required, policy=policy, budget=budget, enforce_required=True,
        on_authenticated=on_authenticated)
