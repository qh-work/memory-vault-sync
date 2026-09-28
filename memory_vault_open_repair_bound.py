"""Authenticate the original, post-envelope ACK write and offer permissions.

The caller supplies independent full owner/writer keys, the preselected slot,
message ID and exact envelope reference. These original-input checks neither
prove an envelope exists nor bind a slot, consult current status, admit a
receipt, establish possession of either private key or authorize remote IO.
The later state consumer must retain stable grant-ID conflicts and apply the
current status, resource, phase and operation checks before acting.
"""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType

import memory_vault_open_repair_bootstrap as bootstrap
import memory_vault_open_repair_history as history
import memory_vault_open_repair_original as original
import memory_vault_open_repair_resource as resource
import memory_vault_open_repair_wire as wire


_WRITE_FIELDS = frozenset("issued_at expires_at grant_id ack_slot root_authority_ref owner receipt_writer message_id envelope_ref operation max_receipts budget windows revision".split())
_SELECTOR_FIELDS = frozenset(("root_key_sha256", "ack_slot_sha256", "root_authority_sha256", "write_grant_sha256"))
_UPLOAD_ROLES = frozenset(("ack.root_authority", "ack.write_grant", "bootstrap.grant"))


def _invalid():
    wire._fail("repair_invalid_ack_bound")


def _mismatch():
    wire._fail("repair_ack_bound_mismatch")


def _fields(value, names):
    if (type(value) not in (dict, wire._DraftDict)
            or any(type(key) is not str for key in value) or value.keys() != set(names)):
        _invalid()
    return value


def _shape(function, *args, **kwargs):
    # Only schema helpers pass through here; crypto/work-meter failures retain
    # their own codes and their already incurred budget charges.
    try:
        return function(*args, **kwargs)
    except wire.RepairWireError:
        _invalid()


def _ref(value, *, metadata=True):
    descriptor = _fields(value, {"namespace", "key", "raw_sha256", "size"})
    result = _shape(wire.RawRef, **descriptor)
    if metadata and result.namespace != "meta":
        _invalid()
    return result


def _write_shape(payload):
    _shape(resource._lifetime, payload)
    _shape(wire.u53, payload["revision"])
    _shape(original._opaque, payload["grant_id"])
    slot = _fields(payload["ack_slot"], {"root_key", "slot_id", "receipt_writer", "grant_id"})
    _shape(history._slot, slot, slot["root_key"], ack=True)
    _shape(history._dual, payload["owner"])
    _shape(history._dual, payload["receipt_writer"])
    _shape(history._pattern, payload["message_id"], "msg_")
    _ref(payload["root_authority_ref"])
    _ref(payload["envelope_ref"], metadata=False)
    if payload["operation"] != "receipt.put" or _shape(wire.u53, payload["max_receipts"]) != 1:
        _invalid()
    _shape(resource._budget, payload["budget"])
    _shape(resource._windows, payload["windows"], issued=payload["issued_at"],
           expires=payload["expires_at"])


def _offer_shape(payload):
    for name in ("issued_at", "expires_at", "revision", "probe_until", "proof_until", "upload_until"):
        _shape(wire.u53, payload[name])
    _shape(original._opaque, payload["grant_id"])
    _shape(history._dual, payload["owner"])
    _shape(history._dual, payload["subject"])
    _shape(history._root, payload["root_key"])
    if (payload["root_key"]["root_kind"] != "ack_return"
            or payload["consumer"] != "ack_offer" or payload["probe_profile"] != "opaque_v1"
            or payload["response_profile"] != "ack_offer_service_v1"):
        _invalid()
    for value in _fields(payload["selector"], _SELECTOR_FIELDS).values():
        _shape(original._digest, value)
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
    _shape(bootstrap._limits, payload["limits"])


def _verify(entry, role, owner, policy, budget):
    entry = _fields(entry, {"raw", "ref"})
    reference = _ref(entry["ref"])
    draft = wire.parse_new_wire(entry["raw"], policy, budget)
    if len(draft.raw) != reference.size or budget._hash(draft.raw) != reference.raw_sha256:
        wire._fail("repair_ref_mismatch")
    signed = _fields(draft.value, {"payload", "proof"})
    names, kind = {
        "root": (frozenset(resource._FIELDS[2].split()), "ack.root_authority"),
        "write": (_WRITE_FIELDS, "ack.write_grant"),
        "bootstrap": (bootstrap._GRANT_FIELDS, "bootstrap.grant"),
    }[role]
    payload = _fields(signed["payload"], resource.COMMON | names)
    if payload["schema_version"] != resource.SCHEMA or payload["kind"] != kind:
        _invalid()
    if role == "root":
        _shape(resource._role_shape, role, payload)
    elif role == "write":
        _write_shape(payload)
    else:
        _offer_shape(payload)
    original._verify_control_signature(payload, signed["proof"], owner["signing_key"], budget)
    return resource.AuthenticatedRepairOriginal(draft.raw, reference, payload)


def _expected(ack_slot, owner, receipt_writer, message_id, envelope_ref, at, policy, budget,
              *, limit_policy=None):
    values = dict(ack_slot=ack_slot, owner=owner, receipt_writer=receipt_writer,
                  message_id=message_id, envelope_ref=envelope_ref, at=at)
    if limit_policy is not None:
        values["limit_policy"] = limit_policy
    expected = wire.build_new_wire(values, policy, budget).value
    slot = _fields(expected["ack_slot"], {"root_key", "slot_id", "receipt_writer", "grant_id"})
    _shape(history._slot, slot, slot["root_key"], ack=True)
    for name in ("owner", "receipt_writer"):
        _shape(resource._dual_key_shape, expected[name])
    # Descriptor recomputation is real work, outside the shape-error wrapper.
    owner_id = resource._dual_key(expected["owner"], budget)
    writer_id = resource._dual_key(expected["receipt_writer"], budget)
    _shape(history._pattern, expected["message_id"], "msg_")
    _ref(expected["envelope_ref"], metadata=False)
    _shape(wire.u53, expected["at"])
    if slot["root_key"]["owner"] != owner_id or slot["receipt_writer"] != writer_id:
        _mismatch()
    return expected, owner_id, writer_id


def _write_inputs(entry, root_entry, expected, owner_id, writer_id, policy, budget):
    checked = {"root": _verify(root_entry, "root", expected["owner"], policy, budget),
               "write": _verify(entry, "write", expected["owner"], policy, budget)}
    root, write = (checked[name].payload for name in ("root", "write"))
    slot, at = expected["ack_slot"], expected["at"]
    if (root["ack_slot"] != slot or write["ack_slot"] != slot
            or any(item["owner"] != owner_id or item["receipt_writer"] != writer_id
                   for item in (root, write))
            or write["grant_id"] != slot["grant_id"]
            or _ref(write["root_authority_ref"]) != checked["root"].ref
            or write["message_id"] != expected["message_id"]
            or _ref(write["envelope_ref"], metadata=False) != _ref(expected["envelope_ref"], metadata=False)
            or root["operation_mask"] & 1 != 1
            or any(write["budget"][name] > root["budget"][name] for name in resource._BUDGET)
            or any(write["windows"][name] > root["windows"][name] for name in resource._WINDOWS)):
        _mismatch()
    if not (root["issued_at"] <= write["issued_at"] <= at
            and at < write["expires_at"] <= root["expires_at"]):
        _invalid()
    return checked


@dataclass(frozen=True, slots=True)
class AuthenticatedAckWriteInputs:
    originals: object
    at: int


@dataclass(frozen=True, slots=True)
class AuthenticatedAckOfferBootstrapInputs:
    originals: object
    at: int


def verify_ack_write_grant_original(entry, root_entry, *, expected_ack_slot, expected_owner,
                                    expected_receipt_writer, expected_message_id,
                                    expected_envelope_ref, at, policy: wire.RepairPolicy,
                                    budget: wire.RepairBudget) -> AuthenticatedAckWriteInputs:
    """Verify original root/write assertions for one independently fixed E.

    ``at`` remains the caller's event expectation. Same-second parent issuance
    is permitted; no legacy future clock skew is imported. Current deadlines,
    statuses, resource state and any retained conflicting grant are separate.
    """
    wire._context(policy, budget)
    with budget._lock:
        expected, owner_id, writer_id = _expected(expected_ack_slot, expected_owner,
            expected_receipt_writer, expected_message_id, expected_envelope_ref, at, policy, budget)
        checked = _write_inputs(entry, root_entry, expected, owner_id, writer_id, policy, budget)
        return AuthenticatedAckWriteInputs(MappingProxyType(checked), expected["at"])


def verify_ack_offer_bootstrap_original(entry, parents, *, expected_ack_slot, expected_owner,
                                        expected_receipt_writer, expected_message_id,
                                        expected_envelope_ref, at, limit_policy,
                                        policy: wire.RepairPolicy, budget: wire.RepairBudget
                                        ) -> AuthenticatedAckOfferBootstrapInputs:
    """Verify the A-signed limited offer permission for exact B, root and write.

    This branch does not consume or broaden A's receipt-read grant. It requires
    explicit parent DISCOVER/READ/ACK-ADMIT and narrows proof time to the
    parent's read/retain and write's admit/retain windows; upload time narrows
    actual ACK admission. A later action checks its own phase deadline.
    """
    wire._context(policy, budget)
    with budget._lock:
        held = _fields(parents, {"root", "write"})
        expected, owner_id, writer_id = _expected(expected_ack_slot, expected_owner,
            expected_receipt_writer, expected_message_id, expected_envelope_ref, at, policy, budget,
            limit_policy=limit_policy)
        # A missing/null policy never means unlimited.
        if "limit_policy" not in expected:
            _invalid()
        local_limits = _shape(bootstrap._limits, expected["limit_policy"])
        checked = _write_inputs(held["write"], held["root"], expected, owner_id, writer_id, policy, budget)
        checked["bootstrap"] = _verify(entry, "bootstrap", expected["owner"], policy, budget)
        root, write, grant = (checked[name].payload for name in ("root", "write", "bootstrap"))
        slot = expected["ack_slot"]
        if (grant["owner"] != owner_id or grant["subject"] != writer_id
                or grant["root_key"] != slot["root_key"]
                or _ref(grant["parent_authority_ref"]) != checked["root"].ref
                or _ref(grant["caller_authority_ref"]) != checked["write"].ref
                or root["operation_mask"] & 11 != 11
                or not {"bootstrap.grant", "ack_offer_service_v1"}.issubset(root["allowed_roles"])
                or not set(grant["upload_roles"]).issubset(root["allowed_roles"])):
            _mismatch()
        selector = dict(root_key_sha256=budget._hash(wire._canonical(slot["root_key"], budget)),
                        ack_slot_sha256=budget._hash(wire._canonical(slot, budget)),
                        root_authority_sha256=checked["root"].ref.raw_sha256,
                        write_grant_sha256=checked["write"].ref.raw_sha256)
        if grant["selector"] != selector:
            _mismatch()
        if not (write["issued_at"] <= grant["issued_at"] <= expected["at"] < grant["expires_at"]
                <= min(root["expires_at"], write["expires_at"])):
            _invalid()
        for name in ("probe_until", "proof_until", "upload_until"):
            if not grant["issued_at"] < grant[name] <= grant["expires_at"]:
                _invalid()
        if (grant["proof_until"] > min(root["windows"]["read_until"], root["windows"]["retain_until"],
                                       write["windows"]["admit_until"], write["windows"]["retain_until"])
                or grant["upload_until"] > min(item["windows"][name] for item in (root, write)
                                               for name in ("admit_until", "retain_until"))):
            _mismatch()
        for name, parent_fields in bootstrap._PARENT_CAPS.items():
            value = grant["limits"][name]
            if value > local_limits[name] or any(value > item["budget"][field]
                    for item in (root, write) for field in parent_fields):
                _mismatch()
        return AuthenticatedAckOfferBootstrapInputs(MappingProxyType(checked), expected["at"])
