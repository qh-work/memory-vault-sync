"""Fresh synthetic pre-message ACK resources; no stored private fixture keys."""
import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from memory_vault import canonical_bytes
from memory_vault_network_crypto import EncryptionIdentity
from memory_vault_trust import Identity


SCHEMA = "memory-vault-open-repair/v1"
ROLES = ("allocate", "offer", "root", "read", "activation", "active")


def ack_resource_fixture(*, include_encryption=False):
    signers = {role: Identity(Ed25519PrivateKey.generate())
               for role in ("owner", "target", "writer", "maintainer")}
    encryption = {role: EncryptionIdentity.generate() for role in signers}
    keys = {role: {"signing_key": signer.public_descriptor(),
                   "encryption_key": encryption[role].public_descriptor()}
            for role, signer in signers.items()}
    ids = {role: {"signing_key_id": signer.key_id,
                  "encryption_key_id": encryption[role].key_id}
           for role, signer in signers.items()}
    now = 2_000_000_000
    root_key = {"owner": ids["owner"], "root_kind": "ack_return",
                "anchor_ref": {"namespace": "anchor", "key": "ab" * 32},
                "owner_epoch": "synthetic_owner_epoch", "root_id": "synthetic_ack_root"}
    slot = {"root_key": root_key, "slot_id": "synthetic_ack_slot",
            "receipt_writer": ids["writer"], "grant_id": "synthetic_future_write_grant"}
    budget = dict(max_live_bytes=16384, max_meta_bytes=65536, max_items=1,
                  max_requests=64, max_pending=4, max_replay_records=64,
                  max_jobs=4, max_job_bytes=65536)
    windows = {name: now + 1000 for name in
               ("admit_until", "read_until", "copy_until", "publish_until", "retain_until")}
    root_windows = {name: now + 3000 for name in windows}
    read_windows = {name: now + 2000 for name in windows}
    resource = dict(node_key_id=signers["target"].key_id,
                    storage_epoch="synthetic_target_epoch", lease_id="synthetic_lease",
                    resource_id="synthetic_resource")
    intent = dict(kind="resource.owner_intent", allocation_id="synthetic_allocation",
                  root_key=root_key, owner=keys["owner"], target=keys["target"],
                  target_storage_epoch=resource["storage_epoch"], purpose="ack_slot",
                  budget=budget, windows=windows)
    intent_hash = hashlib.sha256(canonical_bytes(intent)).hexdigest()
    docs, entries = {}, {}

    def add(role, signer, kind, **fields):
        payload = dict(schema_version=SCHEMA, kind=kind,
                       signing_key=signers[signer].public_descriptor(), **fields)
        signed = {"payload": payload, "proof": signers[signer].sign_message(payload)}
        raw = canonical_bytes(signed)
        # Opaque locators deliberately differ from the content digest.
        ref = dict(namespace="meta", key=hashlib.sha256(("synthetic:" + role).encode()).hexdigest(),
                   raw_sha256=hashlib.sha256(raw).hexdigest(), size=len(raw))
        docs[role], entries[role] = signed, {"raw": raw, "ref": ref}
        return ref

    allocation = add("allocate", "owner", "resource.allocate", issued_at=now,
                     expires_at=now + 20, request_id="synthetic_request",
                     target_node_key_id=resource["node_key_id"],
                     target_storage_epoch=resource["storage_epoch"],
                     intent=intent, intent_sha256=intent_hash)
    offer = add("offer", "target", "resource.offer", issued_at=now + 1,
                reservation_until=now + 40, offer_id="synthetic_offer",
                allocation_request_ref=allocation, intent=intent, intent_sha256=intent_hash,
                resource=resource, target_encryption_key=keys["target"]["encryption_key"],
                reservation_generation=1, budget=budget, windows=windows)
    root = add("root", "owner", "ack.root_authority", issued_at=now + 2,
               expires_at=now + 5000, ack_slot=slot, authority_id="synthetic_authority",
               owner=ids["owner"], receipt_writer=ids["writer"],
               original_resource_ref=resource, original_resource_offer_ref=offer,
               maintainers=[ids["maintainer"]], operation_mask=127,
               allowed_roles=sorted(["ack.read_grant", "ack.root_authority",
                                     "resource.ack_allocate", "resource.ack_offer",
                                     "resource.ack_activation", "resource.ack_active"]),
               max_bindings=1, max_receipts=1, budget=budget, windows=root_windows,
               max_delegate_depth=2, max_destinations_per_job=2,
               max_concurrent_jobs=2, revision=1)
    read = add("read", "owner", "ack.read_grant", issued_at=now + 3,
               expires_at=now + 4000, grant_id="synthetic_read_grant",
               ack_slot=slot, reader=ids["owner"], root_authority_ref=root,
               operation_mask=2, budget=budget, windows=read_windows, revision=1)
    activation = add("activation", "owner", "resource.activation", issued_at=now + 4,
                     expires_at=now + 15, activation_id="synthetic_activation",
                     subject=keys["owner"], target_node_key_id=resource["node_key_id"],
                     target_storage_epoch=resource["storage_epoch"], root_key=root_key,
                     scope={"kind": "ack_unbound", "ack_slot": slot, "root_authority_ref": root},
                     resource_offer_refs=[offer], authority_refs=[
                         {"role": "ack.read_grant", "ref": read},
                         {"role": "ack.root_authority", "ref": root}])
    add("active", "target", "resource.active", activated_at=now + 5,
        offer_ref=offer, activation_ref=activation, resource=resource,
        reservation_generation=1, root_key=root_key, purpose="ack_slot", budget=budget,
        windows=windows)
    expected = dict(expected_ack_slot=slot, expected_owner=keys["owner"],
                    expected_target=keys["target"],
                    target_storage_epoch=resource["storage_epoch"])
    result = docs, entries, expected, signers
    return (*result, encryption) if include_encryption else result
