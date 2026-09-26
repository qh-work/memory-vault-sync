"""Authenticate an original ACK-unbound source event and its whole closure.

This is a historical input result, not current read permission or proof that a
receiving node has durably stored anything. Local publication must reserve and
pin the exact originals in its own transaction.
"""
from dataclasses import dataclass

import memory_vault_open_repair_bootstrap as bootstrap
import memory_vault_open_repair_history as history
import memory_vault_open_repair_original as original
import memory_vault_open_repair_resource as resource
import memory_vault_open_repair_status as status
import memory_vault_open_repair_wire as wire

ROLES = frozenset(("ack.root_authority", "ack.read_grant", "bootstrap.ack_owner",
    "resource.ack_allocate", "resource.ack_offer", "resource.ack_activation", "resource.ack_active",
    "source.descriptor", "historical.status.ack_root", "historical.status.ack_read",
    "historical.status.ack_owner_bootstrap", "historical.status.ack_slot", "historical.status.ack_resource"))
_CUSTODY = frozenset(("schema_version", "kind", "signing_key", "ack_slot", "root_authority_ref",
    "historical_manifest_ref", "resource_ref", "stored_at", "read_until", "retain_until", "state"))


def _fail(code="repair_invalid_ack"):
    raise wire.RepairWireError(code)


def _mismatch():
    _fail("repair_ack_mismatch")


def _fields(value, names):
    try:
        return wire.object_fields(value, names)
    except wire.RepairWireError:
        _fail()


def _ref(value):
    value = _fields(value, {"namespace", "key", "raw_sha256", "size"})
    result = wire.raw_ref(value)
    if result.namespace != "meta":
        _fail()
    return result


def _entry(value):
    value = _fields(value, {"raw", "ref"})
    return value["raw"], _ref(value["ref"])


def _custody(entry, target, policy, budget):
    body, reference = _entry(entry)
    parsed = wire.parse_new_wire(body, policy, budget)
    if len(parsed.raw) != reference.size or budget._hash(parsed.raw) != reference.raw_sha256:
        _fail("repair_ref_mismatch")
    signed = _fields(parsed.value, {"payload", "proof"})
    payload = _fields(signed["payload"], _CUSTODY)
    if (payload["schema_version"] != resource.SCHEMA or payload["kind"] != "ack.slot_custody"
            or payload["state"] != "unbound"):
        _fail()
    try:
        slot = _fields(payload["ack_slot"], {"root_key", "slot_id", "receipt_writer", "grant_id"})
        history._slot(slot, slot["root_key"], ack=True)
        history._resource(payload["resource_ref"])
        for name in ("stored_at", "read_until", "retain_until"):
            wire.u53(payload[name])
    except wire.RepairWireError:
        _fail()
    _ref(payload["root_authority_ref"])
    _ref(payload["historical_manifest_ref"])
    if not payload["stored_at"] < payload["read_until"] <= payload["retain_until"]:
        _fail()
    original._verify_control_signature(payload, signed["proof"], target["signing_key"], budget)
    return resource.AuthenticatedRepairOriginal(parsed.raw, reference, payload)


@dataclass(frozen=True, slots=True)
class AuthenticatedAckUnboundSourceEvent:
    manifest: history.DraftHistoryInputs
    custody: resource.AuthenticatedRepairOriginal
    resources: resource.AuthenticatedAckResourceInputs
    bootstrap: bootstrap.AuthenticatedAckOwnerBootstrapInputs
    descriptor: original.VerifiedOriginalControl
    statuses: tuple
    stored_at: int
    read_until: int
    retain_until: int


def verify_ack_unbound_source_event(manifest_entry, resolver, custody_entry, *,
        expected_ack_slot, expected_owner, expected_target, target_storage_epoch,
        limit_policy, policy, budget):
    """Verify real originals under independent identities at signed stored_at."""
    wire._context(policy, budget)
    with budget._lock:
        expected = wire.build_new_wire(dict(ack_slot=expected_ack_slot, owner=expected_owner,
            target=expected_target, epoch=target_storage_epoch, limit_policy=limit_policy), policy, budget).value
        slot = _fields(expected["ack_slot"], {"root_key", "slot_id", "receipt_writer", "grant_id"})
        try:
            history._slot(slot, slot["root_key"], ack=True)
            original._opaque(expected["epoch"])
        except wire.RepairWireError:
            _fail()
        owner = _fields(expected["owner"], {"signing_key", "encryption_key"})
        target = _fields(expected["target"], {"signing_key", "encryption_key"})
        custody = _custody(custody_entry, target, policy, budget)
        event = custody.payload
        at = event["stored_at"]
        if event["ack_slot"] != slot:
            _mismatch()
        raw, h_ref = _entry(manifest_entry)
        if _ref(event["historical_manifest_ref"]) != h_ref:
            _mismatch()
        parsed = wire.parse_new_wire(raw, policy, budget)
        if len(parsed.raw) != h_ref.size or budget._hash(parsed.raw) != h_ref.raw_sha256:
            _fail("repair_ref_mismatch")
        manifest = history.resolve_historical_inputs(parsed.raw, resolver, policy, budget)
        value = manifest.manifest.value
        if (value["variant"] != "ack_unbound" or manifest.predecessors or
                value["root_key"] != slot["root_key"] or value["ack_slot"] != slot or
                value["root_authority_ref"] != event["root_authority_ref"]):
            _mismatch()
        if len(manifest.roles) != len(ROLES):
            _fail()
        roles = {}
        for row in manifest.roles:
            if row.role not in ROLES or row.role in roles:
                _fail()
            roles[row.role] = row.original
        if roles.keys() != ROLES:
            _fail()

        def entry(role):
            item = roles[role]
            return dict(raw=item.raw, ref=item.ref.as_dict())

        aliases = dict(allocate="resource.ack_allocate", offer="resource.ack_offer", root="ack.root_authority",
                       read="ack.read_grant", activation="resource.ack_activation", active="resource.ack_active")
        resources = resource.verify_ack_resource_inputs({key: entry(role) for key, role in aliases.items()},
            expected_ack_slot=slot, expected_owner=owner, expected_target=target,
            target_storage_epoch=expected["epoch"], policy=policy, budget=budget)
        boot = bootstrap.verify_ack_owner_bootstrap_original(entry("bootstrap.ack_owner"),
            {key: entry(aliases[key]) for key in ("root", "read")}, expected_ack_slot=slot,
            expected_owner=owner, at=at, limit_policy=expected["limit_policy"], policy=policy, budget=budget)
        node = roles["source.descriptor"]
        if len(node.raw) != node.ref.size or budget._hash(node.raw) != node.ref.raw_sha256:
            _fail("repair_ref_mismatch")
        descriptor = original.verify_original_control(node.raw, expected_signing_key=target["signing_key"],
            expected_schema="memory-vault-open-control/v1", expected_kind="node", at=at, policy=policy, budget=budget)
        original._node_shape(descriptor, at, budget)
        if descriptor.payload["storage_epoch"] != expected["epoch"]:
            _fail("repair_original_mismatch")
        r, c = (resources.originals[key].payload for key in ("root", "read"))
        g = boot.originals["bootstrap"].payload
        activation, active = (resources.originals[key].payload for key in ("activation", "active"))
        if (_ref(event["root_authority_ref"]) != resources.originals["root"].ref or
                _ref(value["root_authority_ref"]) != resources.originals["root"].ref or
                event["resource_ref"] != active["resource"] or
                event["resource_ref"]["node_key_id"] != target["signing_key"]["key_id"] or
                event["resource_ref"]["storage_epoch"] != expected["epoch"] or
                g["issued_at"] > activation["issued_at"] or active["activated_at"] > at or
                r["operation_mask"] & 74 != 74 or c["operation_mask"] & 2 != 2):
            _mismatch()
        read_until = min(r["windows"]["read_until"], r["windows"]["retain_until"], c["windows"]["read_until"],
            c["windows"]["retain_until"], active["windows"]["read_until"], r["expires_at"], c["expires_at"],
            g["expires_at"], g["probe_until"], g["proof_until"], g["upload_until"])
        if (event["read_until"] > read_until or event["retain_until"] > r["windows"]["retain_until"] or
                event["retain_until"] > active["windows"]["retain_until"]):
            _mismatch()
        obligations = []
        for name, role, kind, revision, mask in (
            ("root", "historical.status.ack_root", "ack.root_authority", r["revision"], 74),
            ("read", "historical.status.ack_read", "ack.read_grant", c["revision"], 2),
            ("bootstrap", "historical.status.ack_owner_bootstrap", "bootstrap.grant", g["revision"], 10)):
            item = boot.originals[name] if name == "bootstrap" else resources.originals[name]
            obligations.append(dict(role=role, kind="authority", subject=dict(authority_kind=kind,
                authority_sha256=item.ref.raw_sha256), revision=revision, mask=mask, signer=owner["signing_key"]))
        obligations.extend((dict(role="historical.status.ack_slot", kind="ack_slot", subject=slot,
            revision=r["revision"], mask=66, signer=owner["signing_key"]),
            dict(role="historical.status.ack_resource", kind="resource", subject=active["resource"],
                 revision=active["reservation_generation"], mask=66, signer=target["signing_key"])))
        for item in obligations:
            item["scope_id"] = status.status_scope(slot["root_key"], item["kind"], item["subject"], policy, budget)
        groups = {}
        for item in obligations:
            held = roles[item["role"]]
            group = groups.setdefault(held.ref, dict(entry=entry(item["role"]), signer=item["signer"], required=[]))
            if group["signer"] != item["signer"]:
                _mismatch()
            group["required"].append(dict(scope_kind=item["kind"], scope_id=item["scope_id"],
                document_revision=item["revision"], operation_mask=item["mask"]))
        statuses = []
        revisions, observations = {}, {}
        for group in groups.values():
            permitted = [item for item in obligations if item["signer"] == group["signer"]]
            # Parse a bounded snapshot to derive PRESENT whole-body obligations;
            # the status verifier independently authenticates those same bytes.
            parsed_status = original.parse_original_control(group["entry"]["raw"], policy, budget)
            signed_status = _fields(parsed_status.value, {"payload", "proof"})
            payload = _fields(signed_status["payload"], status._PAYLOAD)
            held = payload["entries"]
            if type(held) is not wire._DraftList or not 1 <= len(held) <= 16:
                _fail("repair_invalid_status")
            present = set()
            for observation in held:
                status._fields(observation, status._ENTRY)
                present.add(status._scope_key(observation))
            required = {(item["scope_kind"], item["scope_id"]): item for item in group["required"]}
            for item in permitted:
                key = item["kind"], item["scope_id"]
                if key in present:
                    required[key] = dict(scope_kind=item["kind"], scope_id=item["scope_id"],
                        document_revision=item["revision"], operation_mask=item["mask"])
            checked = status.verify_status_original(group["entry"], expected_root=slot["root_key"],
                expected_signing_key=group["signer"], at=at, policy=policy, budget=budget,
                allowed_scopes=[dict(scope_kind=item["kind"], scope_id=item["scope_id"]) for item in permitted],
                required=list(required.values()))
            statuses.append(checked)
            payload = checked.payload
            issuer = group["signer"]["key_id"]
            key = issuer, payload["revision"]
            if key in revisions and revisions[key] != checked.canonical_sha256:
                _fail("repair_status_conflict")
            revisions[key] = checked.canonical_sha256
            for observation in payload["entries"]:
                key = issuer, observation["scope_kind"], observation["scope_id"]
                observations.setdefault(key, []).append((payload["revision"], observation["minimum_document_revision"]))
        for values in observations.values():
            floor = 0
            for _, minimum in sorted(values):
                if minimum < floor:
                    _fail("repair_status_rollback")
                floor = minimum
        return AuthenticatedAckUnboundSourceEvent(manifest, custody, resources, boot, descriptor,
            tuple(statuses), at, event["read_until"], event["retain_until"])
