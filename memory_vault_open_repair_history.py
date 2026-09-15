"""Closed historical-manifest drafts for the repair candidate.

This layer checks representation and local original-byte references. It does
not verify signatures, derive all obligations from typed Signed parents, or
grant disclosure, resource, network, custody or Vault authority.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from types import MappingProxyType

import memory_vault_open_repair_wire as wire


SCHEMA = "memory-vault-open-repair/v1"
COMMON = frozenset(("schema_version", "kind", "variant", "root_key", "roles"))
VARIANT_FIELDS = MappingProxyType({
    "mailbox_root": frozenset(("root_authority_ref", "catalog_ref", "genesis_head_refs")),
    "mailbox_feed": frozenset(("slot_key", "slot_ref", "feed_head_ref", "covered_interval", "subtree", "members")),
    "mailbox_member": frozenset(("slot_key", "message_id", "envelope_ref", "attempt_ref")),
    "ack_unbound": frozenset(("ack_slot", "root_authority_ref")),
    "ack_empty": frozenset(("ack_slot", "root_authority_ref", "grant_ref", "binding_ref")),
    "ack_occupied_inputs": frozenset(("ack_slot", "root_authority_ref", "grant_ref", "binding_ref",
                                      "receipt_ref", "put_ref", "disclosure_ref", "admission_resource")),
})


def _names(text):
    return frozenset(text.split())


_SLOT_INPUT = _names("""
mailbox.slot mailbox.read_grant mailbox.maintenance_root bootstrap.mailbox_feed
resource.data_allocate resource.metadata_allocate resource.data_offer
resource.metadata_offer resource.slot_activation resource.data_active
resource.metadata_active source.descriptor
""")
_SLOT_OBS = _names("""historical.status.slot historical.status.read
historical.status.maintenance historical.status.bootstrap""")
_ACK_OWNER_OBS = _names("""historical.status.ack_root historical.status.ack_read
historical.status.ack_owner_bootstrap historical.status.ack_slot""")
_ACK_BOUND_OBS = _ACK_OWNER_OBS | _names("""historical.status.ack_write
historical.status.ack_offer_bootstrap""")
_ROLES = MappingProxyType({
    "mailbox_root": _SLOT_INPUT | _SLOT_OBS | _names("""
mailbox.root_authority mailbox.root_read_grant mailbox.catalog bootstrap.mailbox_root
resource.anchor_allocate resource.anchor_offer resource.anchor_activation resource.anchor_active
historical.status.root historical.status.root_read historical.status.root_bootstrap
historical.status.catalog historical.status.anchor_resource historical.status.data_resource
historical.status.metadata_resource genesis.head genesis.checkpoint
"""),
    "mailbox_member": _SLOT_INPUT | _SLOT_OBS | _names("""
contact.request contact.policy contact.decision contact.store_grant contact.knock_lease
contact.delivery_lease delivery.destination delivery.attempt message.disclosure
historical.status.disclosure historical.status.destination historical.status.data_resource
historical.status.metadata_resource ack.root_authority ack.write_grant bootstrap.ack_offer
historical.status.ack_root historical.status.ack_write historical.status.ack_offer_bootstrap
"""),
    "mailbox_feed": _SLOT_INPUT | _SLOT_OBS | _names("""
historical.status.metadata_resource feed.head feed.checkpoint history.member member.core
member.link member.custody member.checkpoint member.head member.sealed_core
historical.status.disclosure range.index range.repair_page range.sealed_page
"""),
    "ack_unbound": _ACK_OWNER_OBS | _names("""
ack.root_authority ack.read_grant bootstrap.ack_owner resource.ack_allocate resource.ack_offer
resource.ack_activation resource.ack_active source.descriptor historical.status.ack_resource
"""),
    "ack_empty": _ACK_BOUND_OBS | _names("""
history.ack_unbound ack.unbound_custody ack.write_grant bootstrap.ack_offer ack.binding
historical.status.ack_resource
"""),
    "ack_occupied_inputs": _ACK_BOUND_OBS | _names("""
history.ack_empty ack.empty_custody recipient.receipt ack.disclosure ack.put
historical.status.ack_disclosure historical.status.admission_resource admission.assignment
admission.allocate admission.offer admission.empty_replica_manifest
admission.empty_replica_custody admission.descriptor historical.status.admission_assignment
"""),
})
_OPAQUE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


def _fail():
    raise wire.RepairWireError("repair_invalid_history")


def _fields(value, names):
    try:
        return wire.object_fields(value, names)
    except wire.RepairWireError:
        _fail()


def _array(value, *, nonempty=False):
    if type(value) is not wire._DraftList or (nonempty and not value):
        _fail()
    return value


def _pattern(value, prefix):
    if type(value) is not str or re.fullmatch(re.escape(prefix) + r"[0-9a-f]{64}", value) is None:
        _fail()


def _opaque(value):
    if type(value) is not str or _OPAQUE.fullmatch(value) is None:
        _fail()


def _dual(value):
    value = _fields(value, {"signing_key_id", "encryption_key_id"})
    _pattern(value["signing_key_id"], "ed25519_")
    _pattern(value["encryption_key_id"], "x25519_")


def _root(value):
    value = _fields(value, {"owner", "root_kind", "anchor_ref", "owner_epoch", "root_id"})
    _dual(value["owner"])
    if type(value["root_kind"]) is not str or value["root_kind"] not in ("mailbox", "ack_return"):
        _fail()
    anchor = _fields(value["anchor_ref"], {"namespace", "key"})
    if anchor["namespace"] != "anchor":
        _fail()
    _pattern(anchor["key"], "")
    _opaque(value["owner_epoch"])
    _opaque(value["root_id"])


def _slot(value, root, *, ack=False):
    names = {"root_key", "slot_id", "receipt_writer", "grant_id"} if ack else {
        "root_key", "slot_id", "writer", "writer_storage_epoch"}
    value = _fields(value, names)
    _root(value["root_key"])
    if value["root_key"] != root or root["root_kind"] != ("ack_return" if ack else "mailbox"):
        _fail()
    _opaque(value["slot_id"])
    _dual(value["receipt_writer" if ack else "writer"])
    _opaque(value["grant_id" if ack else "writer_storage_epoch"])


def _resource(value):
    value = _fields(value, {"node_key_id", "storage_epoch", "lease_id", "resource_id"})
    _pattern(value["node_key_id"], "ed25519_")
    for name in ("storage_epoch", "lease_id", "resource_id"):
        _opaque(value[name])


def _ref_tuple(value):
    ref = wire.raw_ref(value)
    return ref.namespace, ref.key, ref.raw_sha256, ref.size


def _refs(values, *, ordered):
    seen, previous = set(), None
    for value in _array(values):
        key = _ref_tuple(value)
        if key in seen or (ordered and previous is not None and key <= previous):
            _fail()
        seen.add(key)
        previous = key


def _validate(draft: wire.DraftJson):
    value = draft.value
    if type(value) is not wire._DraftDict:
        _fail()
    variant = value.get("variant")
    if type(variant) is not str or variant not in VARIANT_FIELDS:
        _fail()
    _fields(value, COMMON | VARIANT_FIELDS[variant])
    if value["schema_version"] != SCHEMA or value["kind"] != "historical.manifest":
        _fail()
    root = value["root_key"]
    _root(root)
    if root["root_kind"] != ("mailbox" if variant.startswith("mailbox_") else "ack_return"):
        _fail()
    previous = None
    for role in _array(value["roles"], nonempty=True):
        _fields(role, {"role", "document_ref", "pack_ref", "entry_index"})
        name = role["role"]
        if type(name) is not str or name not in _ROLES[variant]:
            _fail()
        key = (name, *_ref_tuple(role["document_ref"]))
        if previous is not None and key <= previous:
            _fail()
        previous = key
        pack = wire.raw_ref(role["pack_ref"])
        if pack.namespace != "meta" or pack.key != pack.raw_sha256:
            _fail()
        wire.u53(role["entry_index"])
    for field in VARIANT_FIELDS[variant]:
        if field.endswith("_ref"):
            wire.raw_ref(value[field])
    if variant == "mailbox_root":
        _refs(value["genesis_head_refs"], ordered=True)
    elif variant in ("mailbox_member", "mailbox_feed"):
        _slot(value["slot_key"], root)
        if variant == "mailbox_member":
            _pattern(value["message_id"], "msg_")
        else:
            interval = _fields(value["covered_interval"], {"start", "end"})
            start, end = wire.u53(interval["start"]), wire.u53(interval["end"])
            members = _array(value["members"], nonempty=True)
            if start >= end or len(members) != end - start:
                _fail()
            subtree = _fields(value["subtree"], {"root_ref", "parent_path_refs"})
            wire.raw_ref(subtree["root_ref"])
            _refs(subtree["parent_path_refs"], ordered=False)
            if subtree["root_ref"] in subtree["parent_path_refs"]:
                _fail()
            message_ids = set()
            for sequence, member in enumerate(members, start):
                _fields(member, {"sequence", "message_id", "envelope_ref", "historical_manifest_ref",
                                 "admission_core_ref", "admission_link_ref", "source_custody_ref"})
                if wire.u53(member["sequence"]) != sequence:
                    _fail()
                _pattern(member["message_id"], "msg_")
                if member["message_id"] in message_ids:
                    _fail()
                message_ids.add(member["message_id"])
                for field in ("envelope_ref", "historical_manifest_ref", "admission_core_ref",
                              "admission_link_ref", "source_custody_ref"):
                    wire.raw_ref(member[field])
    else:
        _slot(value["ack_slot"], root, ack=True)
        if variant == "ack_occupied_inputs":
            _resource(value["admission_resource"])
    return draft


def parse_historical_manifest(raw, policy: wire.RepairPolicy, budget: wire.RepairBudget) -> wire.DraftJson:
    """Parse a closed draft; allowed role names do not prove required obligations.

    Schema traversal uses the already bounded frozen tree. The wire counters
    remain actual parse/clone/canonical work, not a full CPU/authority meter.
    """
    wire._context(policy, budget)
    with budget._lock:
        return _validate(wire.parse_new_wire(raw, policy, budget))


def build_historical_manifest(value, policy: wire.RepairPolicy, budget: wire.RepairBudget) -> wire.DraftJson:
    """Construct canonical draft bytes; no permissive serializer before limits."""
    wire._context(policy, budget)
    with budget._lock:
        return _validate(wire.build_new_wire(value, policy, budget))


@dataclass(frozen=True)
class DraftHistoryRole:
    role: str
    original: wire.RawOriginal


@dataclass(frozen=True)
class DraftHistoryInputs:
    """Resolved local bytes and explicit phase bindings, still unverified.

    The presence of a role does not certify that its bytes have the expected
    Signed kind, signer, historical validity or required complete obligations.
    Those checks belong to the typed authority consumer, not this local plan.
    """
    manifest: wire.DraftJson
    roles: tuple[DraftHistoryRole, ...]
    predecessors: tuple["DraftHistoryInputs", ...]


def resolve_historical_inputs(raw, resolver: wire.LocalRawResolver,
                              policy: wire.RepairPolicy,
                              budget: wire.RepairBudget) -> DraftHistoryInputs:
    """Resolve all direct/transitive registered input bytes from local packs.

    Every read uses the same meter and actual raw reference checks. Fixed phase
    transitions have at most three levels; arbitrary graph traversal, complete
    parent obligations and permission verification are deliberately not implied.
    No callback, URL or implicit network fallback is accepted as a resolver.
    """
    wire._context(policy, budget)
    if (type(resolver) is not wire.LocalRawResolver or resolver.budget is not budget
            or resolver.policy != policy):
        raise wire.RepairWireError("repair_invalid_policy")
    with budget._lock:
        packs, used, active = {}, {}, set()

        def walk(manifest_raw, expected_variant=None, depth=1):
            if depth > policy.max_depth:
                raise wire.RepairWireError("repair_over_budget")
            draft = parse_historical_manifest(manifest_raw, policy, budget)
            value, roles, predecessors = draft.value, [], []
            variant = value["variant"]
            if expected_variant is not None and variant != expected_variant:
                _fail()
            identity = (budget._hash(draft.raw), len(draft.raw))
            if identity in active:
                _fail()
            active.add(identity)
            by_role = {}
            for entry in value["roles"]:
                pack_ref = wire.raw_ref(entry["pack_ref"])
                key = _ref_tuple(entry["pack_ref"])
                if key not in packs:
                    # Invoke the actual local implementation, not an overridden
                    # instance method supplied as an arbitrary fetch callback.
                    original = wire.LocalRawResolver.resolve(resolver, pack_ref)
                    packs[key] = wire.parse_raw_pack(original.raw, pack_ref, policy, budget)
                    used[key] = set()
                original = packs[key].entry(entry["entry_index"], entry["document_ref"])
                used[key].add(entry["entry_index"])
                item = DraftHistoryRole(entry["role"], original)
                roles.append(item)
                by_role[(item.role, _ref_tuple(item.original.ref))] = item

            def require(role, reference):
                item = by_role.get((role, _ref_tuple(reference)))
                if item is None:
                    _fail()
                return item

            def predecessor(item, expected):
                child = walk(item.original.raw, expected, depth + 1)
                if child.manifest.value["root_key"] != value["root_key"]:
                    _fail()
                predecessors.append(child)
                return child.manifest.value

            if variant == "mailbox_root":
                require("mailbox.root_authority", value["root_authority_ref"])
                require("mailbox.catalog", value["catalog_ref"])
                for ref in value["genesis_head_refs"]:
                    require("genesis.head", ref)
                if {item.original.ref for item in roles if item.role == "genesis.head"} != {
                        wire.raw_ref(ref) for ref in value["genesis_head_refs"]}:
                    _fail()
            elif variant == "mailbox_member":
                require("delivery.attempt", value["attempt_ref"])
            elif variant == "mailbox_feed":
                require("mailbox.slot", value["slot_ref"])
                require("feed.head", value["feed_head_ref"])
                require("range.index", value["subtree"]["root_ref"])
                for ref in value["subtree"]["parent_path_refs"]:
                    require("range.index", ref)
                # Descendant indices are also legitimate range inputs. Their
                # complete set is derived later from the typed original nodes,
                # not guessed from only the subtree root and its parent path.
                for member in value["members"]:
                    child = predecessor(require("history.member", member["historical_manifest_ref"]),
                                        "mailbox_member")
                    if any(child[name] != wanted for name, wanted in (
                            ("slot_key", value["slot_key"]), ("message_id", member["message_id"]),
                            ("envelope_ref", member["envelope_ref"]))):
                        _fail()
                    for role, field in (("member.core", "admission_core_ref"),
                                        ("member.link", "admission_link_ref"),
                                        ("member.custody", "source_custody_ref")):
                        require(role, member[field])
                if {item.original.ref for item in roles if item.role == "history.member"} != {
                        wire.raw_ref(member["historical_manifest_ref"]) for member in value["members"]}:
                    _fail()
            elif variant == "ack_unbound":
                require("ack.root_authority", value["root_authority_ref"])
            else:
                prior_role, prior_variant = ("history.ack_unbound", "ack_unbound") if variant == "ack_empty" else (
                    "history.ack_empty", "ack_empty")
                prior = [item for item in roles if item.role == prior_role]
                if len(prior) != 1:
                    _fail()
                child = predecessor(prior[0], prior_variant)
                if any(child[field] != value[field] for field in ("ack_slot", "root_authority_ref")):
                    _fail()
                if variant == "ack_empty":
                    require("ack.write_grant", value["grant_ref"])
                    require("ack.binding", value["binding_ref"])
                else:
                    if any(child[field] != value[field] for field in ("grant_ref", "binding_ref")):
                        _fail()
                    for role, field in (("recipient.receipt", "receipt_ref"), ("ack.put", "put_ref"),
                                        ("ack.disclosure", "disclosure_ref")):
                        require(role, value[field])
            active.remove(identity)
            return DraftHistoryInputs(draft, tuple(roles), tuple(predecessors))

        result = walk(raw)
        if any(used[key] != set(range(len(pack.entries))) for key, pack in packs.items()):
            _fail()
        return result
