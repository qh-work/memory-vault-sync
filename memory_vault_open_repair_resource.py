"""Authenticated pre-message ACK resource inputs, without live activation.

This fixed six-original closure checks the signers' asserted setup event. It
does not prove physical capacity, current status, possession of both keys,
custody, disclosure permission, a complete repair graph or network authority.
No wall clock, network, database or Vault is accessed.
"""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType

import memory_vault_open_repair_wire as wire
import memory_vault_open_repair_original as original
import memory_vault_open_repair_history as history

SCHEMA = "memory-vault-open-repair/v1"
ROLES = ("allocate", "offer", "root", "read", "activation", "active")
COMMON = frozenset(("schema_version", "kind", "signing_key"))
_KINDS = ("resource.allocate", "resource.offer", "ack.root_authority",
          "ack.read_grant", "resource.activation", "resource.active")
_FIELDS = (
    "issued_at expires_at request_id target_node_key_id target_storage_epoch intent intent_sha256",
    "issued_at reservation_until offer_id allocation_request_ref intent intent_sha256 resource target_encryption_key reservation_generation budget windows",
    "issued_at expires_at ack_slot authority_id owner receipt_writer original_resource_ref original_resource_offer_ref maintainers operation_mask allowed_roles max_bindings max_receipts budget windows max_delegate_depth max_destinations_per_job max_concurrent_jobs revision",
    "issued_at expires_at grant_id ack_slot reader root_authority_ref operation_mask budget windows revision",
    "issued_at expires_at activation_id subject target_node_key_id target_storage_epoch root_key scope resource_offer_refs authority_refs",
    "activated_at offer_ref activation_ref resource reservation_generation root_key purpose budget windows",
)
_BUDGET = frozenset("max_live_bytes max_meta_bytes max_items max_requests max_pending max_replay_records max_jobs max_job_bytes".split())
_WINDOWS = frozenset("admit_until read_until copy_until publish_until retain_until".split())
_INTENT = frozenset("kind allocation_id root_key owner target target_storage_epoch purpose budget windows".split())
KNOWN_ALLOWED_ROLES = history.KNOWN_HISTORICAL_ROLES | frozenset((
    "bootstrap.grant", "mailbox_root_service_v1", "selected_slot_service_v1",
    "ack_owner_service_v1", "ack_offer_service_v1"))


def _invalid():
    wire._fail("repair_invalid_resource")


def _mismatch():
    wire._fail("repair_resource_mismatch")


def _fields(value, names):
    if type(value) not in (dict, wire._DraftDict) or value.keys() != set(names):
        _invalid()
    return value


def _opaque(value):
    try:
        original._opaque(value)
    except wire.RepairWireError:
        _invalid()


def _shape(function, *args, **kwargs):
    try:
        function(*args, **kwargs)
    except wire.RepairWireError:
        _invalid()


def _array(value):
    if type(value) is not wire._DraftList:
        _invalid()
    return value


def _budget(value):
    for number in _fields(value, _BUDGET).values():
        wire.u53(number)


def _windows(value, *, issued=None, expires=None):
    value = _fields(value, _WINDOWS)
    for number in value.values():
        wire.u53(number)
    for number in value.values():
        if (number > value["retain_until"] or (issued is not None and number <= issued)
                or (expires is not None and number > expires)):
            _invalid()


def _lifetime(value):
    wire.u53(value["issued_at"])
    wire.u53(value["expires_at"])
    if value["expires_at"] <= value["issued_at"]:
        _invalid()


def _opmask(value):
    if wire.u53(value) > 127:
        _invalid()


def _dual_key_shape(value):
    value = _fields(value, {"signing_key", "encryption_key"})
    for descriptor in value.values():
        _fields(descriptor, {"schema_version", "algorithm", "key_id", "public_key"})
    return value


def _dual_key(value, budget):
    value = _dual_key_shape(value)
    original._descriptor(value["signing_key"], budget)
    original._descriptor(value["encryption_key"], budget, encryption=True)
    return {"signing_key_id": value["signing_key"]["key_id"],
            "encryption_key_id": value["encryption_key"]["key_id"]}


def _ref(value):
    descriptor = _fields(value, {"namespace", "key", "raw_sha256", "size"})
    result = wire.RawRef(**descriptor)
    if result.namespace != "meta":
        _invalid()
    return result


def _intent(value):
    value = _fields(value, _INTENT)
    if value["kind"] != "resource.owner_intent" or value["purpose"] != "ack_slot":
        _invalid()
    _opaque(value["allocation_id"])
    _shape(history._root, value["root_key"])
    _opaque(value["target_storage_epoch"])
    _dual_key_shape(value["owner"])
    _dual_key_shape(value["target"])
    _budget(value["budget"])
    _windows(value["windows"])


def _role_shape(role, payload):
    for field in ("issued_at", "expires_at", "reservation_until", "activated_at"):
        if field in payload:
            wire.u53(payload[field])
    for field in ("request_id", "offer_id", "authority_id", "grant_id", "activation_id", "target_storage_epoch"):
        if field in payload:
            _opaque(payload[field])
    for field in ("target_node_key_id",):
        if field in payload:
            _shape(original._key_id, payload[field])
    for field in ("reservation_generation", "revision", "max_destinations_per_job", "max_concurrent_jobs"):
        if field in payload:
            wire.u53(payload[field])
    if "expires_at" in payload:
        _lifetime(payload)
    if "budget" in payload:
        _budget(payload["budget"])
        _windows(payload["windows"],
                 issued=payload["issued_at"] if role in ("root", "read") else None,
                 expires=payload["expires_at"] if role in ("root", "read") else None)
    if role in ("allocate", "offer"):
        _intent(payload["intent"])
        _shape(original._digest, payload["intent_sha256"])
    if role == "offer":
        wire.u53(payload["issued_at"])
        wire.u53(payload["reservation_until"])
        if payload["reservation_until"] <= payload["issued_at"]:
            _invalid()
        _ref(payload["allocation_request_ref"])
        _fields(payload["target_encryption_key"], {"schema_version", "algorithm", "key_id", "public_key"})
    if role in ("offer", "active"):
        _shape(history._resource, payload["resource"])
    if role in ("root", "read"):
        slot = payload["ack_slot"]
        _fields(slot, {"root_key", "slot_id", "receipt_writer", "grant_id"})
        _shape(history._slot, slot, slot["root_key"], ack=True)
        _opmask(payload["operation_mask"])
    if role == "root":
        _shape(history._dual, payload["owner"])
        _shape(history._dual, payload["receipt_writer"])
        _shape(history._resource, payload["original_resource_ref"])
        _ref(payload["original_resource_offer_ref"])
        for name, number in (("max_bindings", 1), ("max_receipts", 1), ("max_delegate_depth", 2)):
            if wire.u53(payload[name]) != number:
                _invalid()
        maintainers = _array(payload["maintainers"])
        previous = None
        for item in maintainers:
            _shape(history._dual, item)
            key = (item["signing_key_id"], item["encryption_key_id"])
            if previous is not None and key <= previous:
                _invalid()
            previous = key
        allowed = _array(payload["allowed_roles"])
        previous = None
        for name in allowed:
            if (type(name) is not str or name not in KNOWN_ALLOWED_ROLES
                    or (previous is not None and name <= previous)):
                _invalid()
            previous = name
    if role == "read":
        _shape(history._dual, payload["reader"])
        _ref(payload["root_authority_ref"])
    if role == "activation":
        _dual_key_shape(payload["subject"])
        _shape(history._root, payload["root_key"])
        scope = _fields(payload["scope"], {"kind", "ack_slot", "root_authority_ref"})
        if scope["kind"] != "ack_unbound":
            _invalid()
        _ref(scope["root_authority_ref"])
        offers, authorities = _array(payload["resource_offer_refs"]), _array(payload["authority_refs"])
        if len(offers) != 1 or len(authorities) != 2:
            _invalid()
        _ref(offers[0])
        for entry, name in zip(authorities, ("ack.read_grant", "ack.root_authority")):
            _fields(entry, {"role", "ref"})
            if entry["role"] != name:
                _invalid()
            _ref(entry["ref"])
    if role == "active":
        wire.u53(payload["activated_at"])
        _shape(history._root, payload["root_key"])
        _ref(payload["offer_ref"])
        _ref(payload["activation_ref"])
        if payload["purpose"] != "ack_slot":
            _invalid()


@dataclass(frozen=True, slots=True)
class AuthenticatedRepairOriginal:
    raw: bytes
    ref: wire.RawRef
    payload: object


@dataclass(frozen=True, slots=True)
class AuthenticatedAckResourceInputs:
    originals: object
    activated_at: int


def verify_ack_resource_inputs(entries, *, expected_ack_slot, expected_owner, expected_target,
                               target_storage_epoch, policy: wire.RepairPolicy,
                               budget: wire.RepairBudget) -> AuthenticatedAckResourceInputs:
    """Check one fixed pre-E resource input closure; activate nothing locally."""
    wire._context(policy, budget)
    with budget._lock:
        _fields(entries, ROLES)
        expected = wire.build_new_wire(dict(ack_slot=expected_ack_slot, owner=expected_owner,
            target=expected_target, epoch=target_storage_epoch), policy, budget).value
        slot = _fields(expected["ack_slot"], {"root_key", "slot_id", "receipt_writer", "grant_id"})
        _shape(history._slot, slot, slot["root_key"], ack=True)
        root_key = slot["root_key"]
        _opaque(expected["epoch"])
        owner_id = _dual_key(expected["owner"], budget)
        target_id = _dual_key(expected["target"], budget)
        if root_key["owner"] != owner_id:
            _mismatch()
        checked = {}
        for role, kind, names in zip(ROLES, _KINDS, _FIELDS):
            entry = _fields(entries[role], {"raw", "ref"})
            reference = _ref(entry["ref"])
            draft = wire.parse_new_wire(entry["raw"], policy, budget)
            if len(draft.raw) != reference.size or budget._hash(draft.raw) != reference.raw_sha256:
                wire._fail("repair_ref_mismatch")
            signed = _fields(draft.value, {"payload", "proof"})
            payload = _fields(signed["payload"], COMMON | frozenset(names.split()))
            if payload["schema_version"] != SCHEMA or payload["kind"] != kind:
                _invalid()
            _role_shape(role, payload)
            signer = expected["target" if role in ("offer", "active") else "owner"]["signing_key"]
            original._verify_control_signature(payload, signed["proof"], signer, budget)
            checked[role] = AuthenticatedRepairOriginal(draft.raw, reference, payload)
        allocate, offer, root, read, activation, active = (checked[r].payload for r in ROLES)

        def parent(value, role):
            if _ref(value) != checked[role].ref:
                _mismatch()

        parent(offer["allocation_request_ref"], "allocate")
        parent(root["original_resource_offer_ref"], "offer")
        parent(read["root_authority_ref"], "root")
        parent(activation["scope"]["root_authority_ref"], "root")
        parent(activation["resource_offer_refs"][0], "offer")
        parent(activation["authority_refs"][0]["ref"], "read")
        parent(activation["authority_refs"][1]["ref"], "root")
        parent(active["offer_ref"], "offer")
        parent(active["activation_ref"], "activation")
        intent_bytes = [wire._canonical(item["intent"], budget) for item in (allocate, offer)]
        intent_hashes = [budget._hash(raw) for raw in intent_bytes]
        if (intent_bytes[0] != intent_bytes[1] or any(item["intent_sha256"] != digest
                for item, digest in zip((allocate, offer), intent_hashes))):
            _mismatch()
        intent = allocate["intent"]
        if (intent["root_key"] != root_key or intent["owner"] != expected["owner"]
                or intent["target"] != expected["target"] or intent["target_storage_epoch"] != expected["epoch"]):
            _mismatch()
        _windows(intent["windows"], issued=allocate["issued_at"])
        resource = offer["resource"]
        if (resource["node_key_id"] != target_id["signing_key_id"] or resource["storage_epoch"] != expected["epoch"]
                or offer["target_encryption_key"] != expected["target"]["encryption_key"]):
            _mismatch()
        for item in (allocate, activation):
            if item["target_node_key_id"] != target_id["signing_key_id"] or item["target_storage_epoch"] != expected["epoch"]:
                _mismatch()
        if any(offer[name] != intent[name] for name in ("budget", "windows")):
            _mismatch()
        if (root["ack_slot"] != slot or read["ack_slot"] != slot or root["owner"] != owner_id
                or root["receipt_writer"] != slot["receipt_writer"] or read["reader"] != owner_id
                or root["original_resource_ref"] != resource):
            _mismatch()
        if (read["expires_at"] > root["expires_at"] or read["operation_mask"] & ~root["operation_mask"]
                or any(read["budget"][name] > root["budget"][name] for name in _BUDGET)
                or any(read["windows"][name] > root["windows"][name] for name in _WINDOWS)):
            _mismatch()
        if (activation["subject"] != expected["owner"] or activation["root_key"] != root_key
                or activation["scope"]["ack_slot"] != slot or active["root_key"] != root_key
                or any(active[name] != offer[name] for name in ("resource", "reservation_generation", "budget", "windows"))):
            _mismatch()
        at = active["activated_at"]
        if not (allocate["issued_at"] <= offer["issued_at"] < allocate["expires_at"]
                and offer["issued_at"] <= root["issued_at"] <= read["issued_at"] <= activation["issued_at"] <= at
                and at < offer["reservation_until"]
                and all(at < item["expires_at"] for item in (root, read, activation))):
            _mismatch()
        return AuthenticatedAckResourceInputs(MappingProxyType(checked), at)


def verify_mailbox_resource_inputs(entries, *, expected_root, expected_owner, expected_target,
        target_storage_epoch, expected_purpose, expected_scope, expected_authority_refs,
        expected_offer_refs, at, policy, budget):
    """Authenticate a mailbox allocation/offer/activation/active chain offline.

    Scope and authority references must come from the caller's independently
    checked owner chain. This proves original resource events, not custody,
    current permission, physical storage, or the owner authority chain itself.
    """
    wire._context(policy,budget)
    expected = wire.build_new_wire(dict(root=expected_root,owner=expected_owner,target=expected_target,
        epoch=target_storage_epoch,purpose=expected_purpose,scope=expected_scope,
        authorities=expected_authority_refs,offers=expected_offer_refs,at=at),policy,budget).value
    history._root(expected["root"])
    _opaque(expected["epoch"]);wire.u53(expected["at"])
    owner_id = _dual_key(expected["owner"],budget)
    target_id = _dual_key(expected["target"],budget)
    if (expected["root"]["root_kind"] != "mailbox" or expected["root"]["owner"] != owner_id
            or expected["purpose"] not in ("anchor_catalog","feed_metadata","mailbox_data")):
        _mismatch()
    roles = ("allocate","offer","activation","active")
    _fields(entries,roles)
    checked = {}
    for role,index in zip(roles,(0,1,4,5)):
        value = _fields(entries[role],{"raw","ref"})
        ref = _ref(wire.build_new_wire(value["ref"],policy,budget).value)
        draft = wire.parse_new_wire(value["raw"],policy,budget)
        if len(draft.raw) != ref.size or budget._hash(draft.raw) != ref.raw_sha256:
            wire._fail("repair_ref_mismatch")
        signed = _fields(draft.value,{"payload","proof"})
        p = _fields(signed["payload"],COMMON | frozenset(_FIELDS[index].split()))
        if p["schema_version"] != SCHEMA or p["kind"] != _KINDS[index]:
            _invalid()
        original._verify_control_signature(p,signed["proof"],
            expected["target" if role in ("offer","active") else "owner"]["signing_key"],budget)
        checked[role] = AuthenticatedRepairOriginal(draft.raw,ref,p)
    allocate,offer,activation,active = (checked[r].payload for r in roles)
    for p in (allocate,activation):
        _lifetime(p)
        if p["target_node_key_id"] != target_id["signing_key_id"] or p["target_storage_epoch"] != expected["epoch"]:
            _mismatch()
    for name in ("request_id",):
        _opaque(allocate[name])
    _opaque(activation["activation_id"]);_opaque(offer["offer_id"])
    for p in (allocate,offer):
        intent = _fields(p["intent"],_INTENT)
        if intent["kind"] != "resource.owner_intent" or intent["purpose"] != expected["purpose"]:
            _invalid()
        _opaque(intent["allocation_id"]);_opaque(intent["target_storage_epoch"])
        history._root(intent["root_key"])
        _dual_key_shape(intent["owner"]);_dual_key_shape(intent["target"])
        _budget(intent["budget"]);_windows(intent["windows"])
        if p["intent_sha256"] != budget._hash(wire._canonical(p["intent"],budget)):
            _mismatch()
    intent = allocate["intent"]
    if (offer["intent"] != intent or intent["root_key"] != expected["root"]
            or intent["owner"] != expected["owner"] or intent["target"] != expected["target"]
            or intent["target_storage_epoch"] != expected["epoch"] or intent["purpose"] != expected["purpose"]):
        _mismatch()
    _windows(intent["windows"],issued=allocate["issued_at"])
    history._resource(offer["resource"])
    if (offer["resource"]["node_key_id"] != target_id["signing_key_id"]
            or offer["resource"]["storage_epoch"] != expected["epoch"]
            or offer["target_encryption_key"] != expected["target"]["encryption_key"]
            or _ref(offer["allocation_request_ref"]) != checked["allocate"].ref
            or _ref(active["offer_ref"]) != checked["offer"].ref
            or _ref(active["activation_ref"]) != checked["activation"].ref):
        _mismatch()
    if (activation["subject"] != expected["owner"] or activation["root_key"] != expected["root"]
            or activation["scope"] != expected["scope"] or activation["authority_refs"] != expected["authorities"]
            or activation["resource_offer_refs"] != expected["offers"]
            or checked["offer"].ref.as_dict() not in expected["offers"]
            or active["root_key"] != expected["root"] or active["purpose"] != expected["purpose"]):
        _mismatch()
    _budget(offer["budget"]);_windows(offer["windows"])
    wire.u53(offer["reservation_generation"],1)
    if (any(offer[name] != intent[name] for name in ("budget","windows"))
            or any(active[name] != offer[name] for name in ("resource","reservation_generation","budget","windows"))):
        _mismatch()
    issued,reserved,activated = (wire.u53(v) for v in (offer["issued_at"],offer["reservation_until"],active["activated_at"]))
    if not (allocate["issued_at"] <= issued < allocate["expires_at"]
            and issued <= activation["issued_at"] <= activated <= expected["at"]
            and activated < min(reserved,activation["expires_at"],*offer["windows"].values())):
        _mismatch()
    return MappingProxyType(checked)
