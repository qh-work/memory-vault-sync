"""Original ACK empty-source closure, including its real unbound predecessor.

No summarized predecessor, arbitrary receipt, current network authority or
caller-created authenticated wrapper is accepted in place of original bytes.
The local durable transition is implemented separately in repair_empty_state.
"""
from dataclasses import dataclass

import memory_vault_open_repair_ack as ack
import memory_vault_open_repair_bound as bound
import memory_vault_open_repair_history as history
import memory_vault_open_repair_original as original
import memory_vault_open_repair_resource as resource
import memory_vault_open_repair_status as status
import memory_vault_open_repair_wire as wire


STATUS_ROLES = frozenset(("historical.status.ack_root", "historical.status.ack_read",
    "historical.status.ack_owner_bootstrap", "historical.status.ack_write",
    "historical.status.ack_offer_bootstrap", "historical.status.ack_slot", "historical.status.ack_resource"))
ROLES = STATUS_ROLES | frozenset(("history.ack_unbound", "ack.unbound_custody",
    "ack.write_grant", "bootstrap.ack_offer", "ack.binding"))
_BINDING = resource.COMMON | frozenset(("ack_slot", "root_authority_ref", "grant_ref", "bound_at",
    "resource_ref", "retain_until"))
_CUSTODY = ack._CUSTODY | frozenset(("grant_ref", "binding_ref"))


def _fail(code="repair_invalid_ack_empty"):
    wire._fail(code)


def _mismatch():
    _fail("repair_ack_empty_mismatch")


def _fields(value, names):
    try:
        return wire.object_fields(value, names)
    except wire.RepairWireError:
        _fail()


def _signed(entry, target, kind, policy, budget):
    raw, ref = ack._entry(entry)
    parsed = wire.parse_new_wire(raw, policy, budget)
    if len(parsed.raw) != ref.size or budget._hash(parsed.raw) != ref.raw_sha256:
        _fail("repair_ref_mismatch")
    signed = _fields(parsed.value, {"payload", "proof"})
    payload = _fields(signed["payload"], _BINDING if kind == "ack.binding" else _CUSTODY)
    if payload["schema_version"] != resource.SCHEMA or payload["kind"] != kind:
        _fail()
    slot = _fields(payload["ack_slot"], {"root_key", "slot_id", "receipt_writer", "grant_id"})
    history._slot(slot, slot["root_key"], ack=True)
    history._resource(payload["resource_ref"])
    for name in ("root_authority_ref", "grant_ref"):
        ack._ref(payload[name])
    wire.u53(payload["retain_until"])
    if kind == "ack.binding":
        if not wire.u53(payload["bound_at"]) < payload["retain_until"]:
            _fail()
    else:
        for name in ("historical_manifest_ref", "binding_ref"):
            ack._ref(payload[name])
        if payload["state"] != "empty" or not wire.u53(payload["stored_at"]) < wire.u53(payload["read_until"]) <= payload["retain_until"]:
            _fail()
    original._verify_control_signature(payload, signed["proof"], target["signing_key"], budget)
    return resource.AuthenticatedRepairOriginal(parsed.raw, ref, payload)


def _obligations(prior, authorities, owner, target, slot, policy, budget):
    originals = prior.resources.originals
    requirements = []
    for role, item, kind, mask in (
        ("ack_root", originals["root"], "ack.root_authority", 75),
        ("ack_read", originals["read"], "ack.read_grant", 2),
        ("ack_owner_bootstrap", prior.bootstrap.originals["bootstrap"], "bootstrap.grant", 10),
        ("ack_write", authorities.originals["write"], "ack.write_grant", 1),
        ("ack_offer_bootstrap", authorities.originals["bootstrap"], "bootstrap.grant", 11)):
        requirements.append(dict(role="historical.status." + role, signer=owner["signing_key"],
            scope_kind="authority", scope_id=status.status_scope(slot["root_key"], "authority",
                dict(authority_kind=kind, authority_sha256=item.ref.raw_sha256), policy, budget),
            revision=item.payload["revision"], mask=mask))
    for role, kind, subject, revision, signer in (
        ("ack_slot", "ack_slot", slot, originals["root"].payload["revision"], owner["signing_key"]),
        ("ack_resource", "resource", originals["active"].payload["resource"],
         originals["active"].payload["reservation_generation"], target["signing_key"])):
        requirements.append(dict(role="historical.status." + role, signer=signer, scope_kind=kind,
            scope_id=status.status_scope(slot["root_key"], kind, subject, policy, budget), revision=revision, mask=67))
    return tuple(requirements)


def _history_floors(values, *, previous=(), current=()):
    revisions, observations = {}, {}
    for item in values:
        issuer = item.payload["scope_key"]["issuer_key_id"]
        revision = item.payload["revision"]
        key = issuer, revision
        if key in revisions and revisions[key] != item.canonical_sha256:
            _fail("repair_status_conflict")
        revisions[key] = item.canonical_sha256
        for entry in item.payload["entries"]:
            key = issuer, entry["scope_kind"], entry["scope_id"]
            observations.setdefault(key, set()).add((revision, entry["minimum_document_revision"]))
    for values in observations.values():
        floor = 0
        for _, minimum in sorted(values):
            if minimum < floor:
                _fail("repair_status_rollback")
            floor = minimum
    prior = {}
    for observed in previous:
        issuer = observed.payload["scope_key"]["issuer_key_id"]
        for item in observed.payload["entries"]:
            key = issuer, item["scope_kind"], item["scope_id"]
            revision, floor = prior.get(key, (0, 0))
            prior[key] = max(revision, observed.payload["revision"]), max(floor, item["minimum_document_revision"])
    for observed in current:
        issuer = observed.payload["scope_key"]["issuer_key_id"]
        for item in observed.payload["entries"]:
            before = prior.get((issuer, item["scope_kind"], item["scope_id"]))
            if before is not None and (observed.payload["revision"] < before[0]
                                       or item["minimum_document_revision"] < before[1]):
                _fail("repair_status_rollback")


def _statuses(roles, obligations, root_key, at, policy, budget):
    groups = {}
    for item in obligations:
        entry = roles[item["role"]]
        group = groups.setdefault(entry.ref, dict(entry=dict(raw=entry.raw, ref=entry.ref.as_dict()),
            signer=item["signer"], required=[]))
        if group["signer"] != item["signer"]:
            _mismatch()
        group["required"].append(dict(scope_kind=item["scope_kind"], scope_id=item["scope_id"],
            document_revision=item["revision"], operation_mask=item["mask"]))
    checked = []
    for group in groups.values():
        permitted = [item for item in obligations if item["signer"] == group["signer"]]
        parsed = original.parse_original_control(group["entry"]["raw"], policy, budget)
        payload = status._fields(status._fields(parsed.value, {"payload", "proof"})["payload"], status._PAYLOAD)
        entries = payload["entries"]
        if type(entries) is not wire._DraftList or not 1 <= len(entries) <= 16:
            _fail("repair_invalid_status")
        present = set()
        for entry in entries:
            status._fields(entry, status._ENTRY)
            present.add(status._scope_key(entry))
        required = {(item["scope_kind"], item["scope_id"]): item for item in group["required"]}
        for item in permitted:
            key = item["scope_kind"], item["scope_id"]
            if key in present:
                required[key] = dict(scope_kind=key[0], scope_id=key[1],
                    document_revision=item["revision"], operation_mask=item["mask"])
        checked.append(status.verify_status_original(group["entry"], expected_root=root_key,
            expected_signing_key=group["signer"], at=at, allowed_scopes=[dict(scope_kind=item["scope_kind"],
            scope_id=item["scope_id"]) for item in permitted], required=list(required.values()), policy=policy, budget=budget))
    return tuple(checked)


@dataclass(frozen=True, slots=True)
class AuthenticatedAckEmptySourceEvent:
    manifest: history.DraftHistoryInputs
    custody: resource.AuthenticatedRepairOriginal
    predecessor: ack.AuthenticatedAckUnboundSourceEvent
    binding: resource.AuthenticatedRepairOriginal
    authorities: bound.AuthenticatedAckOfferBootstrapInputs
    statuses: tuple
    stored_at: int
    read_until: int
    retain_until: int


def verify_ack_empty_source_event(manifest_entry, resolver, custody_entry, *, expected_ack_slot,
        expected_owner, expected_receipt_writer, expected_message_id, expected_envelope_ref,
        expected_target, target_storage_epoch, limit_policy, policy, budget):
    """Authenticate the entire original empty event at R's signed stored_at."""
    wire._context(policy, budget)
    with budget._lock:
        expected = wire.build_new_wire(dict(ack_slot=expected_ack_slot, owner=expected_owner,
            receipt_writer=expected_receipt_writer, message_id=expected_message_id,
            envelope_ref=expected_envelope_ref, target=expected_target, epoch=target_storage_epoch,
            limit_policy=limit_policy), policy, budget).value
        slot, owner, target = expected["ack_slot"], expected["owner"], expected["target"]
        _fields(slot, {"root_key", "slot_id", "receipt_writer", "grant_id"})
        history._slot(slot, slot["root_key"], ack=True)
        resource._dual_key_shape(owner)
        resource._dual_key_shape(target)
        original._opaque(expected["epoch"])
        custody = _signed(custody_entry, target, "ack.slot_custody", policy, budget)
        event, at = custody.payload, custody.payload["stored_at"]
        raw, ref = ack._entry(manifest_entry)
        parsed = wire.parse_new_wire(raw, policy, budget)
        if len(parsed.raw) != ref.size or budget._hash(parsed.raw) != ref.raw_sha256:
            _fail("repair_ref_mismatch")
        if event["ack_slot"] != slot or ack._ref(event["historical_manifest_ref"]) != ref:
            _mismatch()
        manifest = history.resolve_historical_inputs(parsed.raw, resolver, policy, budget)
        value = manifest.manifest.value
        if value["variant"] != "ack_empty" or len(manifest.predecessors) != 1 or value["ack_slot"] != slot:
            _mismatch()
        roles = {}
        for item in manifest.roles:
            if item.role not in ROLES or item.role in roles:
                _fail()
            roles[item.role] = item.original
        if roles.keys() != ROLES:
            _fail()
        def entry(role):
            item = roles[role]
            return dict(raw=item.raw, ref=item.ref.as_dict())
        prior = ack.verify_ack_unbound_source_event(entry("history.ack_unbound"), resolver,
            entry("ack.unbound_custody"), expected_ack_slot=slot, expected_owner=owner, expected_target=target,
            target_storage_epoch=expected["epoch"], limit_policy=expected["limit_policy"], policy=policy, budget=budget)
        root = prior.resources.originals["root"]
        authorities = bound.verify_ack_offer_bootstrap_original(entry("bootstrap.ack_offer"),
            dict(root=dict(raw=root.raw, ref=root.ref.as_dict()), write=entry("ack.write_grant")),
            expected_ack_slot=slot, expected_owner=owner, expected_receipt_writer=expected["receipt_writer"],
            expected_message_id=expected["message_id"], expected_envelope_ref=expected["envelope_ref"],
            at=at, limit_policy=expected["limit_policy"], policy=policy, budget=budget)
        binding = _signed(entry("ack.binding"), target, "ack.binding", policy, budget)
        b = binding.payload
        write, offer = (authorities.originals[name].payload for name in ("write", "bootstrap"))
        resource_ref = prior.resources.originals["active"].payload["resource"]
        for field, wanted in (("root_authority_ref", root.ref), ("grant_ref", authorities.originals["write"].ref),
                              ("binding_ref", binding.ref)):
            if ack._ref(event[field]) != wanted or ack._ref(value[field]) != wanted:
                _mismatch()
        if (b["ack_slot"] != slot or b["resource_ref"] != resource_ref or event["resource_ref"] != resource_ref
                or ack._ref(b["root_authority_ref"]) != root.ref
                or ack._ref(b["grant_ref"]) != authorities.originals["write"].ref
                or not prior.stored_at <= write["issued_at"] <= offer["issued_at"] <= b["bound_at"] <= at
                or event["retain_until"] > b["retain_until"]):
            _mismatch()
        r, read, active = (prior.resources.originals[name].payload for name in ("root", "read", "active"))
        owner_boot = prior.bootstrap.originals["bootstrap"].payload
        if r["operation_mask"] & 75 != 75:
            _mismatch()
        # A new event may make a new promise inside the actual resource/owner
        # windows; it never edits or substitutes the earlier unbound promise.
        read_until = min(r["windows"]["read_until"], read["windows"]["read_until"],
            active["windows"]["read_until"], write["windows"]["admit_until"],
            *(item["expires_at"] for item in (r, read, write, owner_boot, offer)),
            *(item[name] for item in (owner_boot, offer) for name in ("probe_until", "proof_until", "upload_until")))
        retain_until = min(r["windows"]["retain_until"], active["windows"]["retain_until"])
        if (event["read_until"] > read_until or b["retain_until"] > retain_until
                or at >= min(r["windows"]["admit_until"], active["windows"]["admit_until"],
                             write["windows"]["admit_until"])):
            _mismatch()
        obligations = _obligations(prior, authorities, owner, target, slot, policy, budget)
        statuses = _statuses(roles, obligations, slot["root_key"], at, policy, budget)
        _history_floors((*prior.statuses, *statuses), previous=prior.statuses, current=statuses)
        return AuthenticatedAckEmptySourceEvent(manifest, custody, prior, binding, authorities,
            statuses, at, event["read_until"], event["retain_until"])
