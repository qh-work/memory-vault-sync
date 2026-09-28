"""Fresh synthetic post-envelope ACK inputs; no private keys are stored."""
import copy
import hashlib

from memory_vault import canonical_bytes
from tests.open_repair_resource_fixtures import ack_resource_fixture


LIMITS = dict(max_probe_bytes=512, max_proof_bytes=4096, max_proof_items=16,
              max_signature_checks=16, max_requests=16, max_pending=2,
              max_replay_records=16, max_concurrent_handles=2, max_candidate_attempts=2)


def rebuild_bound_fixture(fixture, changes=None, signers=None):
    """Sign every changed original and recompute all downstream references."""
    payloads, entries = copy.deepcopy(fixture["payloads"]), {}
    changes, signers = changes or {}, signers or {}
    for role in ("root", "write", "bootstrap"):
        payload = payloads[role]
        if role == "write":
            payload["root_authority_ref"] = entries["root"]["ref"]
        elif role == "bootstrap":
            payload["parent_authority_ref"] = entries["root"]["ref"]
            payload["caller_authority_ref"] = entries["write"]["ref"]
            payload["selector"] = dict(
                root_key_sha256=hashlib.sha256(canonical_bytes(payload["root_key"])).hexdigest(),
                ack_slot_sha256=hashlib.sha256(canonical_bytes(fixture["expected"]["expected_ack_slot"])).hexdigest(),
                root_authority_sha256=entries["root"]["ref"]["raw_sha256"],
                write_grant_sha256=entries["write"]["ref"]["raw_sha256"])
        payload.update(changes.get(role, {}))
        signer = signers.get(role, fixture["signers"]["owner"])
        payload["signing_key"] = signer.public_descriptor()
        raw = canonical_bytes(dict(payload=payload, proof=signer.sign_message(payload)))
        entries[role] = dict(raw=raw, ref=dict(namespace="meta",
            key=hashlib.sha256(("synthetic_bound_locator:" + role).encode()).hexdigest(),
            raw_sha256=hashlib.sha256(raw).hexdigest(), size=len(raw)))
    return entries


def ack_bound_fixture():
    docs, _, initial, signers, encryption = ack_resource_fixture(include_encryption=True)
    root = copy.deepcopy(docs["root"]["payload"])
    root["allowed_roles"] = sorted(set(root["allowed_roles"]) |
        {"ack.write_grant", "bootstrap.grant", "ack_offer_service_v1"})
    root["budget"]["max_items"] = 64
    envelope_raw = b"synthetic opaque envelope bytes for exact-reference binding only"
    envelope = dict(namespace="object", key="cb" * 32,
                    raw_sha256=hashlib.sha256(envelope_raw).hexdigest(), size=len(envelope_raw))
    expected = dict(expected_ack_slot=initial["expected_ack_slot"],
        expected_owner=initial["expected_owner"],
        expected_receipt_writer=dict(signing_key=signers["writer"].public_descriptor(),
                                    encryption_key=encryption["writer"].public_descriptor()),
        expected_message_id="msg_" + "fa" * 32, expected_envelope_ref=envelope,
        at=2_000_000_007)
    write = dict(schema_version="memory-vault-open-repair/v1", kind="ack.write_grant",
        signing_key=signers["owner"].public_descriptor(), issued_at=2_000_000_006,
        expires_at=2_000_002_000, grant_id=expected["expected_ack_slot"]["grant_id"],
        ack_slot=expected["expected_ack_slot"], root_authority_ref={}, owner=root["owner"],
        receipt_writer=root["receipt_writer"], message_id=expected["expected_message_id"],
        envelope_ref=envelope, operation="receipt.put", max_receipts=1,
        budget=copy.deepcopy(root["budget"]), windows={name: 2_000_001_000 for name in root["windows"]},
        revision=1)
    grant = dict(schema_version="memory-vault-open-repair/v1", kind="bootstrap.grant",
        signing_key=signers["owner"].public_descriptor(), issued_at=2_000_000_007,
        expires_at=2_000_000_900, grant_id="synthetic_offer_bootstrap", revision=1,
        owner=root["owner"], subject=root["receipt_writer"],
        root_key=expected["expected_ack_slot"]["root_key"], consumer="ack_offer", selector={},
        parent_authority_ref={}, caller_authority_ref={}, probe_until=2_000_000_800,
        proof_until=2_000_000_800, upload_until=2_000_000_800, probe_profile="opaque_v1",
        response_profile="ack_offer_service_v1",
        upload_roles=["ack.root_authority", "ack.write_grant", "bootstrap.grant"],
        limits=copy.deepcopy(LIMITS))
    result = dict(payloads=dict(root=root, write=write, bootstrap=grant), expected=expected,
                  signers=signers, encryption=encryption, envelope_raw=envelope_raw,
                  limit_policy=copy.deepcopy(LIMITS))
    result["entries"] = rebuild_bound_fixture(result)
    return result
