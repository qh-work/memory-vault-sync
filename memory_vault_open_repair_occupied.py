"""Original recipient receipt admission on the ACK slot's existing resource.

This validates the existing delivery receipt, B's exact consent and put, and
three complete original history generations. It neither proves B's local save
nor substitutes for the remote caller's independent dual-key possession gate.
"""
from dataclasses import dataclass
from types import MappingProxyType

import memory_vault_open_delivery as delivery
import memory_vault_open_repair_ack as ack
import memory_vault_open_repair_empty as empty
import memory_vault_open_repair_history as history
import memory_vault_open_repair_original as original
import memory_vault_open_repair_resource as resource
import memory_vault_open_repair_status as status
import memory_vault_open_repair_wire as wire

STATUS_ROLES = (empty.STATUS_ROLES - {"historical.status.ack_resource"}) | frozenset((
    "historical.status.ack_disclosure", "historical.status.admission_resource"))
ROLES = STATUS_ROLES | frozenset(("history.ack_empty", "ack.empty_custody", "recipient.receipt", "ack.disclosure", "ack.put"))
B_ROLES = frozenset(("recipient.receipt", "ack.disclosure", "ack.put", "historical.status.ack_disclosure"))
RETURN_ROLES_LEGACY = ("ack.disclosure", "authority.status.disclosure")
RETURN_ROLES_FULL = ("ack.disclosure", "ack.put", "authority.status.disclosure", "recipient.receipt")
_DISCLOSURE = resource.COMMON | frozenset("issued_at expires_at consent_id ack_slot root_authority_ref grant_ref receipt_ref recipient owner allowed_roles operation_mask consent_until bootstrap_return revision".split())
_PUT = resource.COMMON | frozenset("issued_at expires_at put_id ack_slot grant_ref binding_ref receipt_ref disclosure_ref operation".split())
_COMMIT = resource.COMMON | frozenset("ack_slot grant_ref binding_ref receipt_ref put_ref disclosure_ref historical_manifest_ref resource_ref stored_at read_until retain_until".split())
_HEAD = resource.COMMON | frozenset("ack_slot generation observed_at retain_until state root_authority_ref grant_ref binding_ref original_ack_commit_ref receipt_ref".split())


def _fail(code="repair_invalid_ack_occupied"):
    wire._fail(code)


def _mismatch():
    _fail("repair_ack_occupied_mismatch")


def _entry(value, *, receipt=False):
    value = wire.object_fields(value, {"raw", "ref"})
    return value["raw"], wire.raw_ref(value["ref"]) if receipt else ack._ref(value["ref"])


def _signed(entry, signer, kind, fields, policy, budget, *, receipt=False):
    raw, ref = _entry(entry, receipt=receipt)
    parsed = wire.parse_new_wire(raw, policy, budget)
    if len(parsed.raw) != ref.size or budget._hash(parsed.raw) != ref.raw_sha256:
        _fail("repair_ref_mismatch")
    signed = wire.object_fields(parsed.value, {"payload", "proof"})
    payload = wire.object_fields(signed["payload"], fields)
    if payload["schema_version"] != (delivery.PROFILE if receipt else resource.SCHEMA) or payload["kind"] != kind:
        _fail()
    original._verify_control_signature(payload, signed["proof"], signer, budget)
    return resource.AuthenticatedRepairOriginal(parsed.raw, ref, payload)


def _receipt(entry, writer, owner, message_id, envelope_ref, policy, budget):
    raw, _ = _entry(entry, receipt=True)
    if type(raw) is not bytes or len(raw) > 4096:
        _fail("repair_invalid_receipt")
    item = _signed(entry, writer["signing_key"], "recipient.receipt",
                   resource.COMMON | delivery.RECEIPT_FIELDS, policy, budget, receipt=True)
    value = item.payload
    wire.u53(value["saved_at"])
    history._pattern(value["message_id"], "msg_")
    original._key_id(value["sender_key_id"])
    original._key_id(value["recipient_key_id"])
    actual_ref = wire.raw_ref(value["envelope_ref"])
    if (value["status"] != "validated_saved" or value["message_id"] != message_id
            or actual_ref != wire.raw_ref(envelope_ref)
            or value["sender_key_id"] != owner["signing_key"]["key_id"]
            or value["recipient_key_id"] != writer["signing_key"]["key_id"]):
        _mismatch()
    # Reuse the live delivery receipt contract, including its canonical original
    # requirement. Both real signature checks are metered, never a claimed cache
    # hit. The first check closes key/proof shapes before entering the old API.
    budget._signature_check()
    try:
        delivery.verify_recipient_receipt(raw, recipient_signing_key=dict(writer["signing_key"]),
            sender_key_id=owner["signing_key"]["key_id"], message_id=message_id, envelope_ref=dict(envelope_ref))
    except delivery.MemoryError:
        _fail("repair_invalid_receipt")
    return item


def _inputs(prior, receipt_entry, disclosure_entry, put_entry, *, owner, writer, at, policy, budget):
    """Private reuse of the immediately authenticated predecessor, not an API token."""
    root = prior.predecessor.resources.originals["root"]
    write = prior.authorities.originals["write"]
    slot = root.payload["ack_slot"]
    receipt = _receipt(receipt_entry, writer, owner, write.payload["message_id"], write.payload["envelope_ref"], policy, budget)
    disclosure = _signed(disclosure_entry, writer["signing_key"], "ack.disclosure", _DISCLOSURE, policy, budget)
    put = _signed(put_entry, writer["signing_key"], "ack.put", _PUT, policy, budget)
    d, p = disclosure.payload, put.payload
    for value, id_name in ((d, "consent_id"), (p, "put_id")):
        resource._lifetime(value)
        original._opaque(value[id_name])
        history._slot(value["ack_slot"], slot["root_key"], ack=True)
        if (value["ack_slot"] != slot or ack._ref(value["grant_ref"]) != write.ref
                or wire.raw_ref(value["receipt_ref"]) != receipt.ref or not value["issued_at"] <= at < value["expires_at"]):
            _mismatch()
    wire.u53(d["revision"])
    resource._opmask(d["operation_mask"])
    roles = d["allowed_roles"]
    if (type(roles) is not wire._DraftList or not roles or any(type(role) is not str for role in roles)
            or roles != sorted(set(roles)) or not set(roles) <= history.KNOWN_HISTORICAL_ROLES
            or not B_ROLES <= set(roles) or d["operation_mask"] & 67 != 67):
        _fail("repair_disclosure_permission")
    history._dual(d["owner"])
    history._dual(d["recipient"])
    returned = wire.object_fields(d["bootstrap_return"], {"subject", "consumer", "roles", "until"})
    history._dual(returned["subject"])
    until, consent_until = wire.u53(returned["until"]), wire.u53(d["consent_until"])
    if (d["owner"] != slot["root_key"]["owner"] or d["recipient"] != slot["receipt_writer"]
            or ack._ref(d["root_authority_ref"]) != root.ref
            or returned["subject"] != d["owner"] or returned["consumer"] != "ack_owner"
            or returned["roles"] not in (list(RETURN_ROLES_LEGACY), list(RETURN_ROLES_FULL))
            or not d["issued_at"] < until <= min(consent_until, d["expires_at"], root.payload["windows"]["read_until"], root.payload["windows"]["retain_until"])
            or not d["issued_at"] < consent_until <= d["expires_at"]
            or ack._ref(p["binding_ref"]) != prior.binding.ref or ack._ref(p["disclosure_ref"]) != disclosure.ref
            or p["operation"] != "receipt.put"
            or not prior.stored_at <= receipt.payload["saved_at"] <= d["issued_at"] <= p["issued_at"] <= at):
        _mismatch()
    return MappingProxyType(dict(receipt=receipt, disclosure=disclosure, put=put))


def _obligations(prior, inputs, owner, writer, target, slot, policy, budget):
    obligations = [item | dict(role="historical.status.admission_resource") if item["role"] == "historical.status.ack_resource" else item
        for item in empty._obligations(prior.predecessor, prior.authorities, owner, target, slot, policy, budget)]
    consent = inputs["disclosure"]
    obligations.append(dict(role="historical.status.ack_disclosure", signer=writer["signing_key"], scope_kind="authority",
        scope_id=status.status_scope(slot["root_key"], "authority", dict(authority_kind="ack.disclosure", authority_sha256=consent.ref.raw_sha256), policy, budget),
        revision=consent.payload["revision"], mask=67))
    return tuple(obligations)


def _windows(prior, inputs, at):
    root, read, active = (prior.predecessor.resources.originals[name].payload for name in ("root", "read", "active"))
    write, offer = (prior.authorities.originals[name].payload for name in ("write", "bootstrap"))
    owner_boot = prior.predecessor.bootstrap.originals["bootstrap"].payload
    consent, put = inputs["disclosure"].payload, inputs["put"].payload
    admit_until = min(root["windows"]["admit_until"], active["windows"]["admit_until"], write["windows"]["admit_until"],
        root["expires_at"], write["expires_at"], offer["expires_at"], offer["upload_until"], consent["expires_at"], consent["consent_until"], put["expires_at"])
    read_until = min(prior.read_until, consent["consent_until"], consent["expires_at"], consent["bootstrap_return"]["until"],
        root["windows"]["read_until"], read["windows"]["read_until"], active["windows"]["read_until"], owner_boot["proof_until"])
    retain_until = min(prior.retain_until, root["windows"]["retain_until"], active["windows"]["retain_until"],
        write["windows"]["retain_until"], consent["consent_until"])
    if not prior.stored_at <= at < min(admit_until, read_until, retain_until):
        _fail("repair_access_expired")
    return min(read_until, retain_until), retain_until, admit_until


@dataclass(frozen=True, slots=True)
class AuthenticatedAckOccupiedSourceEvent:
    manifest: history.DraftHistoryInputs
    commit: resource.AuthenticatedRepairOriginal
    predecessor: empty.AuthenticatedAckEmptySourceEvent
    inputs: object
    statuses: tuple
    stored_at: int
    read_until: int
    retain_until: int


def verify_ack_occupied_source_event(manifest_entry, resolver, commit_entry, *, expected_ack_slot,
        expected_owner, expected_receipt_writer, expected_message_id, expected_envelope_ref,
        expected_target, target_storage_epoch, limit_policy, policy, budget):
    wire._context(policy, budget)
    with budget._lock:
        expected = wire.build_new_wire(dict(slot=expected_ack_slot, owner=expected_owner, writer=expected_receipt_writer,
            message_id=expected_message_id, envelope_ref=expected_envelope_ref, target=expected_target), policy, budget).value
        slot, owner, writer, target = (expected[name] for name in ("slot", "owner", "writer", "target"))
        commit = _signed(commit_entry, target["signing_key"], "ack.commit", _COMMIT, policy, budget)
        event, at = commit.payload, wire.u53(commit.payload["stored_at"])
        raw, ref = _entry(manifest_entry)
        parsed = wire.parse_new_wire(raw, policy, budget)
        if len(raw) != ref.size or budget._hash(raw) != ref.raw_sha256:
            _fail("repair_ref_mismatch")
        if event["ack_slot"] != slot or ack._ref(event["historical_manifest_ref"]) != ref:
            _mismatch()
        manifest = history.resolve_historical_inputs(parsed.raw, resolver, policy, budget)
        value = manifest.manifest.value
        if value["variant"] != "ack_occupied_inputs" or len(manifest.predecessors) != 1 or value["ack_slot"] != slot:
            _mismatch()
        roles = {item.role:item.original for item in manifest.roles}
        if roles.keys() != ROLES or len(roles) != len(manifest.roles):
            _fail()
        def entry(role):
            item = roles[role]
            return dict(raw=item.raw, ref=item.ref.as_dict())
        prior = empty.verify_ack_empty_source_event(entry("history.ack_empty"), resolver, entry("ack.empty_custody"),
            expected_ack_slot=slot, expected_owner=owner, expected_receipt_writer=writer,
            expected_message_id=expected["message_id"], expected_envelope_ref=expected["envelope_ref"], expected_target=target,
            target_storage_epoch=target_storage_epoch, limit_policy=limit_policy, policy=policy, budget=budget)
        inputs = _inputs(prior, entry("recipient.receipt"), entry("ack.disclosure"), entry("ack.put"),
            owner=owner, writer=writer, at=at, policy=policy, budget=budget)
        root = prior.predecessor.resources.originals["root"]
        expected_refs = dict(root_authority_ref=root.ref, grant_ref=prior.authorities.originals["write"].ref,
            binding_ref=prior.binding.ref, receipt_ref=inputs["receipt"].ref, put_ref=inputs["put"].ref, disclosure_ref=inputs["disclosure"].ref)
        for name, wanted in expected_refs.items():
            if wire.raw_ref(value[name]) != wanted or (name != "root_authority_ref" and wire.raw_ref(event[name]) != wanted):
                _mismatch()
        actual_resource = prior.predecessor.resources.originals["active"].payload["resource"]
        if value["admission_resource"] != actual_resource or event["resource_ref"] != actual_resource:
            _mismatch()
        read_until, retain_until, _ = _windows(prior, inputs, at)
        if not at < wire.u53(event["read_until"]) <= wire.u53(event["retain_until"]) <= retain_until or event["read_until"] > read_until:
            _mismatch()
        obligations = _obligations(prior, inputs, owner, writer, target, slot, policy, budget)
        statuses = empty._statuses(roles, obligations, slot["root_key"], at, policy, budget)
        old = (*prior.predecessor.statuses, *prior.statuses)
        empty._history_floors((*old, *statuses), previous=old, current=statuses)
        return AuthenticatedAckOccupiedSourceEvent(manifest, commit, prior, inputs, statuses, at, event["read_until"], event["retain_until"])


def verify_ack_occupied_head(entry, checked, *, expected_target, policy, budget):
    head = _signed(entry, expected_target["signing_key"], "ack.head", _HEAD, policy, budget)
    value, commit = head.payload, checked.commit.payload
    if (value["state"] != "occupied" or wire.u53(value["generation"], 1) != 2
            or value["observed_at"] != checked.stored_at or value["retain_until"] != checked.retain_until
            or value["ack_slot"] != commit["ack_slot"] or wire.raw_ref(value["original_ack_commit_ref"]) != checked.commit.ref
            or wire.raw_ref(value["root_authority_ref"]) != checked.predecessor.predecessor.resources.originals["root"].ref
            or any(value[name] != commit[name] for name in ("grant_ref", "binding_ref", "receipt_ref"))):
        _mismatch()
    return head
