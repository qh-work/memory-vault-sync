"""Fresh synthetic complete ACK-unbound setup; no stored identity material."""
import copy
import hashlib

from memory_vault import canonical_bytes
from memory_vault_open_control import issue_node
import memory_vault_open_repair_history as history
import memory_vault_open_repair_wire as wire
from tests.open_repair_resource_fixtures import ack_resource_fixture


LIMITS = dict(max_probe_bytes=4096, max_proof_bytes=131072, max_proof_items=64,
              max_signature_checks=64, max_requests=64, max_pending=8,
              max_replay_records=128, max_concurrent_handles=8, max_candidate_attempts=8)
ROLE_MAP = {
    "ack.root_authority": "root", "ack.read_grant": "read",
    "bootstrap.ack_owner": "bootstrap", "resource.ack_allocate": "allocate",
    "resource.ack_offer": "offer", "resource.ack_activation": "activation",
    "resource.ack_active": "active", "source.descriptor": "descriptor",
    "historical.status.ack_root": "owner_status", "historical.status.ack_read": "owner_status",
    "historical.status.ack_owner_bootstrap": "owner_status",
    "historical.status.ack_slot": "owner_status", "historical.status.ack_resource": "target_status",
}


def policy(**changes):
    values = dict(max_document_bytes=524288, max_total_bytes=16000000,
                  max_nodes=400000, max_depth=64, max_string_bytes=262144,
                  max_hash_bytes=16000000, max_hashes=2000, max_entries=2000,
                  max_retained_bytes=16000000, max_signature_checks=64)
    values.update(changes)
    return wire.RepairPolicy(**values)


def reference(raw, name):
    return dict(namespace="meta", key=hashlib.sha256(("synthetic_ack:" + name).encode()).hexdigest(),
                raw_sha256=hashlib.sha256(raw).hexdigest(), size=len(raw))


def signed_entry(payload, signer, name):
    raw = canonical_bytes(dict(payload=payload, proof=signer.sign_message(payload)))
    return dict(raw=raw, ref=reference(raw, name))


def repack_fixture(fixture, *, roles=None, manifest_changes=None, custody_changes=None):
    """Rebind actual H and custody after a caller changes exact signed entries."""
    assigned = fixture["role_map"] if roles is None else roles
    entries = fixture["entries"]
    local = policy()
    unique = {entries[name]["raw"] for name in assigned.values()}
    pack = wire.build_raw_pack(list(unique), local, wire.RepairBudget(local))
    positions = {entry.raw_sha256: index for index, entry in enumerate(pack.entries)}
    rows = [dict(role=role, document_ref=entries[name]["ref"], pack_ref=pack.ref.as_dict(),
                 entry_index=positions[entries[name]["ref"]["raw_sha256"]]) for role, name in assigned.items()]
    rows.sort(key=lambda value: (value["role"], *history._ref_tuple(value["document_ref"])))
    expected = fixture["expected"]
    slot = expected["expected_ack_slot"]
    manifest = dict(schema_version=history.SCHEMA, kind="historical.manifest", variant="ack_unbound",
                    root_key=slot["root_key"], ack_slot=slot,
                    root_authority_ref=entries["root"]["ref"], roles=rows)
    manifest.update(manifest_changes or {})
    raw = wire.build_new_wire(manifest, local, wire.RepairBudget(local)).raw
    fixture["manifest"] = dict(raw=raw, ref=reference(raw, "manifest"))
    fixture["packs"] = [dict(raw=pack.raw, ref=pack.ref.as_dict())]
    payload = copy.deepcopy(fixture["docs"]["custody"]["payload"])
    payload["root_authority_ref"] = entries["root"]["ref"]
    payload["historical_manifest_ref"] = fixture["manifest"]["ref"]
    payload.update(custody_changes or {})
    fixture["custody"] = signed_entry(payload, fixture["signers"]["target"], "custody")
    return fixture


def ack_unbound_fixture(*, changes=None, capacity_overrides=None):
    """changes[role] replaces payload fields before topological re-signing."""
    docs, _, expected, signers, encryption = ack_resource_fixture(include_encryption=True)
    changes = changes or {}
    docs = copy.deepcopy(docs)
    now = 2_000_000_000
    capacity = dict(max_live_bytes=131072, max_meta_bytes=262144, max_items=64,
                    max_requests=256, max_pending=16, max_replay_records=256,
                    max_jobs=16, max_job_bytes=262144)
    capacity.update(capacity_overrides or {})
    for role in docs:
        payload = docs[role]["payload"]
        if "budget" in payload:
            payload["budget"] = copy.deepcopy(capacity)
        if "intent" in payload:
            payload["intent"]["budget"] = copy.deepcopy(capacity)
    docs["root"]["payload"]["allowed_roles"] = sorted(set(ROLE_MAP) |
        {"bootstrap.grant", "ack_owner_service_v1", "ack.write_grant"})
    entries = {}
    def add(role, payload, signer):
        payload.update(copy.deepcopy(changes.get(role, {})))
        docs[role] = dict(payload=payload, proof=signer.sign_message(payload))
        raw = canonical_bytes(docs[role])
        entries[role] = dict(raw=raw, ref=reference(raw, role))

    for role in ("allocate", "offer", "root", "read", "activation", "active"):
        payload = docs[role]["payload"]
        if role == "allocate":
            payload["intent_sha256"] = hashlib.sha256(canonical_bytes(payload["intent"])).hexdigest()
        elif role == "offer":
            payload["allocation_request_ref"] = entries["allocate"]["ref"]
            payload["intent"] = docs["allocate"]["payload"]["intent"]
            payload["intent_sha256"] = docs["allocate"]["payload"]["intent_sha256"]
        elif role == "root":
            payload["original_resource_offer_ref"] = entries["offer"]["ref"]
        elif role == "read":
            payload["root_authority_ref"] = entries["root"]["ref"]
        elif role == "activation":
            payload["scope"]["root_authority_ref"] = entries["root"]["ref"]
            payload["resource_offer_refs"] = [entries["offer"]["ref"]]
            payload["authority_refs"] = [{"role": "ack.read_grant", "ref": entries["read"]["ref"]},
                                          {"role": "ack.root_authority", "ref": entries["root"]["ref"]}]
        elif role == "active":
            payload["offer_ref"] = entries["offer"]["ref"]
            payload["activation_ref"] = entries["activation"]["ref"]
        add(role, payload, signers["target" if role in ("offer", "active") else "owner"])

    slot = expected["expected_ack_slot"]
    root = slot["root_key"]
    add("bootstrap", dict(schema_version="memory-vault-open-repair/v1", kind="bootstrap.grant",
        signing_key=signers["owner"].public_descriptor(), issued_at=now+3, expires_at=now+1200,
        grant_id="synthetic_owner_bootstrap", revision=1, owner=root["owner"], subject=root["owner"],
        root_key=root, consumer="ack_owner", selector=dict(
            root_key_sha256=hashlib.sha256(canonical_bytes(root)).hexdigest(),
            ack_slot_sha256=hashlib.sha256(canonical_bytes(slot)).hexdigest(),
            root_authority_sha256=entries["root"]["ref"]["raw_sha256"],
            read_grant_sha256=entries["read"]["ref"]["raw_sha256"]),
        parent_authority_ref=entries["root"]["ref"], caller_authority_ref=entries["read"]["ref"],
        probe_until=now+900, proof_until=now+900, upload_until=now+900,
        probe_profile="opaque_v1", response_profile="ack_owner_service_v1",
        upload_roles=["ack.read_grant", "ack.root_authority", "ack.write_grant", "bootstrap.grant"],
        limits=copy.deepcopy(LIMITS)), signers["owner"])
    node = issue_node(signers["target"], base_url="http://127.0.0.1:19091",
        storage_epoch=expected["target_storage_epoch"], roles=["directory", "router"],
        revision=1, issued_at=now+5, expires_at=now+3600)
    add("descriptor", node["payload"], signers["target"])

    scopes = []
    for name, kind in (("root", "ack.root_authority"), ("read", "ack.read_grant"), ("bootstrap", "bootstrap.grant")):
        scopes.append(dict(kind="authority", root_key=root, authority_kind=kind,
                           authority_sha256=entries[name]["ref"]["raw_sha256"]))
    scopes.append(dict(kind="ack_slot", root_key=root, ack_slot=slot))
    resource_scope = dict(kind="resource", root_key=root, resource=docs["active"]["payload"]["resource"])
    for name, signer, held in (("owner_status", signers["owner"], scopes),
                               ("target_status", signers["target"], [resource_scope])):
        observations = [dict(scope_kind=scope["kind"], scope_id=hashlib.sha256(canonical_bytes(scope)).hexdigest(),
                             minimum_document_revision=0, status="active", operation_mask=127) for scope in held]
        observations.sort(key=lambda value: (value["scope_kind"], value["scope_id"]))
        add(name, dict(schema_version="memory-vault-open-authority/v1", kind="authority.status",
            signing_key=signer.public_descriptor(), scope_key=dict(root_key=root, issuer_key_id=signer.key_id),
            revision=1, issued_at=now+5, valid_until=now+1000, entries=observations), signer)
    docs["custody"] = dict(payload=dict(schema_version="memory-vault-open-repair/v1", kind="ack.slot_custody",
        signing_key=signers["target"].public_descriptor(), ack_slot=slot, root_authority_ref=entries["root"]["ref"],
        historical_manifest_ref={}, resource_ref=docs["active"]["payload"]["resource"],
        stored_at=now+6, read_until=now+800, retain_until=now+950, state="unbound"))
    expected["limit_policy"] = copy.deepcopy(LIMITS)
    result = dict(docs=docs, entries=entries, expected=expected, signers=signers, encryption=encryption, role_map=dict(ROLE_MAP))
    return repack_fixture(result, custody_changes=changes.get("custody"))


def load_fixture(fixture, local=None):
    local = local or policy()
    budget = wire.RepairBudget(local)
    resolver = wire.LocalRawResolver(local, budget)
    for packed in fixture["packs"]:
        resolver.put("meta", packed["ref"]["key"], packed["raw"])
    return resolver, local, budget
