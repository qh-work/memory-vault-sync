"""Authenticate existing ACK-owner bootstrap inputs, without a live permission.

The caller independently supplies the ACK slot, full owner keys, finite local
limit policy and historical event time. This fixed three-original closure
does not authenticate that time, current statuses, resources, custody, remote
physical capacity or possession of both keys. No probe or upload is performed.
"""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType

import memory_vault_open_repair_history as history
import memory_vault_open_repair_original as original
import memory_vault_open_repair_resource as resource
import memory_vault_open_repair_wire as wire


LIMIT_FIELDS = frozenset("max_probe_bytes max_proof_bytes max_proof_items max_signature_checks max_requests max_pending max_replay_records max_concurrent_handles max_candidate_attempts".split())
_GRANT_FIELDS = frozenset("issued_at expires_at grant_id revision owner subject root_key consumer selector parent_authority_ref caller_authority_ref probe_until proof_until upload_until probe_profile response_profile upload_roles limits".split())
_SELECTOR_FIELDS = frozenset(("root_key_sha256", "ack_slot_sha256", "root_authority_sha256", "read_grant_sha256"))
_UPLOAD_ROLES = frozenset(("ack.root_authority", "ack.read_grant", "ack.write_grant", "bootstrap.grant"))
_PARENT_CAPS = {
    "max_probe_bytes": ("max_meta_bytes", "max_job_bytes"),
    "max_proof_bytes": ("max_meta_bytes", "max_job_bytes"),
    "max_proof_items": ("max_items",),
    "max_signature_checks": ("max_requests",),
    "max_requests": ("max_requests",),
    "max_pending": ("max_pending",),
    "max_replay_records": ("max_replay_records",),
    "max_concurrent_handles": ("max_pending", "max_jobs"),
    "max_candidate_attempts": ("max_requests", "max_jobs"),
}


def _invalid():
    wire._fail("repair_invalid_bootstrap")


def _mismatch():
    wire._fail("repair_bootstrap_mismatch")


def _fields(value, names):
    if (type(value) not in (dict, wire._DraftDict) or len(value) != len(names)
            or any(type(key) is not str for key in value) or value.keys() != set(names)):
        _invalid()
    return value


def _shape(function, *args, **kwargs):
    """Reuse pure schema checks, never wrap metering or cryptographic work."""
    try:
        return function(*args, **kwargs)
    except wire.RepairWireError:
        _invalid()


def _ref(value):
    # A caller-created RawRef instance is not evidence that its fields passed
    # validation. Accept only a closed descriptor and construct a fresh tuple.
    descriptor = _fields(value, {"namespace", "key", "raw_sha256", "size"})
    result = wire.RawRef(**descriptor)
    if result.namespace != "meta":
        _invalid()
    return result


def _limits(value):
    value = _fields(value, LIMIT_FIELDS)
    for number in value.values():
        _shape(wire.u53, number, 1)
    return value


def _grant_shape(payload):
    for name in ("issued_at", "expires_at", "revision", "probe_until", "proof_until", "upload_until"):
        _shape(wire.u53, payload[name])
    _shape(original._opaque, payload["grant_id"])
    _shape(history._dual, payload["owner"])
    _shape(history._dual, payload["subject"])
    _shape(history._root, payload["root_key"])
    if (payload["root_key"]["root_kind"] != "ack_return"
            or payload["consumer"] != "ack_owner" or payload["probe_profile"] != "opaque_v1"
            or payload["response_profile"] != "ack_owner_service_v1"):
        _invalid()
    selector = _fields(payload["selector"], _SELECTOR_FIELDS)
    for digest in selector.values():
        _shape(original._digest, digest)
    _ref(payload["parent_authority_ref"])
    _ref(payload["caller_authority_ref"])
    roles = payload["upload_roles"]
    if type(roles) is not wire._DraftList:
        _invalid()
    previous = None
    for role in roles:
        if type(role) is not str or role not in _UPLOAD_ROLES or (previous is not None and role <= previous):
            _invalid()
        previous = role
    _limits(payload["limits"])


def _verify(entry, role, owner, policy, budget):
    entry = _fields(entry, {"raw", "ref"})
    reference = _ref(entry["ref"])
    draft = wire.parse_new_wire(entry["raw"], policy, budget)
    if len(draft.raw) != reference.size or budget._hash(draft.raw) != reference.raw_sha256:
        wire._fail("repair_ref_mismatch")
    signed = _fields(draft.value, {"payload", "proof"})
    index = 2 if role == "root" else 3
    names = _GRANT_FIELDS if role == "bootstrap" else frozenset(resource._FIELDS[index].split())
    payload = _fields(signed["payload"], resource.COMMON | names)
    kind = "bootstrap.grant" if role == "bootstrap" else resource._KINDS[index]
    if payload["schema_version"] != resource.SCHEMA or payload["kind"] != kind:
        _invalid()
    if role == "bootstrap":
        _grant_shape(payload)
    else:
        _shape(resource._role_shape, role, payload)
    original._verify_control_signature(payload, signed["proof"], owner["signing_key"], budget)
    return resource.AuthenticatedRepairOriginal(draft.raw, reference, payload)


@dataclass(frozen=True, slots=True)
class AuthenticatedAckOwnerBootstrapInputs:
    originals: object
    at: int


def verify_ack_owner_bootstrap_original(entry, parents, *, expected_ack_slot, expected_owner,
                                        at, limit_policy, policy: wire.RepairPolicy,
                                        budget: wire.RepairBudget) -> AuthenticatedAckOwnerBootstrapInputs:
    """Authenticate three original assertions; authorize no actual operation.

    ``limit_policy`` is an explicit finite caller expectation, not a certificate
    of a node's physical capacity. Actual parsing, hashes, signatures and output
    copies accumulate in the supplied shared ``budget`` even on rejection.
    """
    wire._context(policy, budget)
    with budget._lock:
        held = _fields(parents, {"root", "read"})
        expected = wire.build_new_wire(dict(ack_slot=expected_ack_slot, owner=expected_owner,
            at=at, limit_policy=limit_policy), policy, budget).value
        slot = _fields(expected["ack_slot"], {"root_key", "slot_id", "receipt_writer", "grant_id"})
        _shape(history._slot, slot, slot["root_key"], ack=True)
        owner = _shape(resource._dual_key_shape, expected["owner"])
        at = _shape(wire.u53, expected["at"])
        local_limits = _limits(expected["limit_policy"])
        original._descriptor(owner["signing_key"], budget)
        original._descriptor(owner["encryption_key"], budget, encryption=True)
        owner_id = {"signing_key_id": owner["signing_key"]["key_id"],
                    "encryption_key_id": owner["encryption_key"]["key_id"]}
        if slot["root_key"]["owner"] != owner_id:
            _mismatch()
        checked = {role: _verify(held[role], role, owner, policy, budget) for role in ("root", "read")}
        checked["bootstrap"] = _verify(entry, "bootstrap", owner, policy, budget)
        root, read, grant = (checked[role].payload for role in ("root", "read", "bootstrap"))
        if (root["ack_slot"] != slot or read["ack_slot"] != slot or root["owner"] != owner_id
                or root["receipt_writer"] != slot["receipt_writer"] or read["reader"] != owner_id
                or _ref(read["root_authority_ref"]) != checked["root"].ref
                or grant["owner"] != owner_id or grant["subject"] != owner_id
                or grant["root_key"] != slot["root_key"]
                or _ref(grant["parent_authority_ref"]) != checked["root"].ref
                or _ref(grant["caller_authority_ref"]) != checked["read"].ref):
            _mismatch()
        if (root["operation_mask"] & 10 != 10 or read["operation_mask"] & 2 != 2
                or read["operation_mask"] & ~root["operation_mask"]
                or not {"bootstrap.grant", "ack_owner_service_v1"}.issubset(root["allowed_roles"])
                or not set(grant["upload_roles"]).issubset(root["allowed_roles"])
                or any(read["budget"][name] > root["budget"][name] for name in resource._BUDGET)
                or any(read["windows"][name] > root["windows"][name] for name in resource._WINDOWS)):
            _mismatch()
        root_hash = budget._hash(wire._canonical(slot["root_key"], budget))
        slot_hash = budget._hash(wire._canonical(slot, budget))
        if grant["selector"] != dict(root_key_sha256=root_hash, ack_slot_sha256=slot_hash,
            root_authority_sha256=checked["root"].ref.raw_sha256,
            read_grant_sha256=checked["read"].ref.raw_sha256):
            _mismatch()
        if not (root["issued_at"] <= read["issued_at"] <= grant["issued_at"] <= at
                and all(at < item["expires_at"] for item in (root, read, grant))
                and read["expires_at"] <= root["expires_at"]
                and grant["expires_at"] <= min(root["expires_at"], read["expires_at"])):
            _invalid()
        for name in ("probe_until", "proof_until", "upload_until"):
            if not grant["issued_at"] < grant[name] <= grant["expires_at"]:
                _invalid()
        read_until = min(item["windows"][name] for item in (root, read)
                         for name in ("read_until", "retain_until"))
        if grant["proof_until"] > read_until or grant["upload_until"] > read_until:
            _mismatch()
        # Phase deadlines need not all outlive this external event. The later
        # consumer must select an actual action and check its own event time.
        for name, parent_fields in _PARENT_CAPS.items():
            value = grant["limits"][name]
            if (value > local_limits[name] or any(value > item["budget"][field]
                    for item in (root, read) for field in parent_fields)):
                _mismatch()
        return AuthenticatedAckOwnerBootstrapInputs(MappingProxyType(checked), at)
