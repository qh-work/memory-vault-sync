"""Synthetic external-authority boundary cases; supplied but NOT executed.

The fixed, public HMAC fixture checks domain binding only. It is not a device
key ceremony, a secure recovery implementation or production trust evidence.
No private key, filesystem, installed client or external service is used.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import memory_vault_device_trust as device
from memory_vault_metadata import jcs_json_bytes


class SyntheticAuthority:
    info = device.AuthorityInfo("synthetic-hmac-authority-v1", "1", "fixture-authority")
    PUBLIC_FIXTURE_KEY = b"public-synthetic-authority-fixture-not-a-secret"

    def __init__(self) -> None:
        self.observed: list[dict] = []

    @classmethod
    def proof(cls, transition: dict) -> bytes:
        return hmac.new(cls.PUBLIC_FIXTURE_KEY, jcs_json_bytes(transition), hashlib.sha256).digest()

    def verify_transition(self, transition, proof: bytes) -> None:
        self.observed.append(dict(transition))
        if not hmac.compare_digest(self.proof(dict(transition)), proof):
            raise device.DeviceTrustError("synthetic transition proof mismatch")


class DeviceTrustTests(unittest.TestCase):
    def setUp(self) -> None:
        self.state = device.new_trust_state("fixture-installation", "device-a", "key-a")
        self.authority = SyntheticAuthority()

    def transition(self, operation: str, *, state=None, **fields) -> dict:
        state = state or self.state
        return {"schema_version": device.TRANSITION_SCHEMA, "operation": operation,
                "previous_state_sha256": state.sha256, "next_generation": state.generation + 1, **fields}

    def enroll_second(self):
        transition = self.transition("enroll", device_fingerprint="device-b",
                                     public_key_fingerprint="key-b", key_epoch=self.state.key_epoch)
        return device.enroll_device(self.state, "device-b", "key-b",
                                    proof=self.authority.proof(transition), authority=self.authority)

    def test_bootstrap_is_opaque_local_state_not_memory_ownership(self) -> None:
        value = self.state.as_dict()
        self.assertEqual(device.TrustState.from_value(value), self.state)
        self.assertEqual(value["generation"], 0)
        self.assertEqual(value["devices"][0]["public_key_fingerprint"], "key-a")
        self.assertNotIn("task_id", value)
        self.assertNotIn("memory_ids", value)
        for identity in ("task-example", "conversation-example", "workspace-example", "device-owner"):
            with self.subTest(identity=identity), self.assertRaises(device.DeviceTrustError):
                device.new_trust_state(identity, "device-a", "key-a")

    def test_unconfigured_authority_cannot_enroll_or_rotate(self) -> None:
        authority = device.UnconfiguredTrustAuthority()
        with self.assertRaises(device.TrustUnavailable):
            device.enroll_device(self.state, "device-b", "key-b", proof=b"ordinary-memory-text", authority=authority)
        with self.assertRaises(device.TrustUnavailable):
            device.rotate_key_epoch(self.state, proof=b"ordinary-memory-text", authority=authority)
        self.assertEqual(self.state.generation, 0)
        self.assertEqual(len(self.state.devices), 1)

    def test_enrollment_requires_exact_external_proof_and_preserves_original_state(self) -> None:
        next_state = self.enroll_second()
        self.assertEqual(next_state.generation, 1)
        self.assertEqual(next_state.device("device-b").public_key_fingerprint, "key-b")
        self.assertEqual(self.authority.observed[0]["previous_state_sha256"], self.state.sha256)
        self.assertEqual(len(self.state.devices), 1)
        transition = self.transition("enroll", device_fingerprint="device-b", public_key_fingerprint="key-b", key_epoch=1)
        with self.assertRaises(device.DeviceTrustError):
            device.enroll_device(self.state, "device-c", "key-c", proof=self.authority.proof(transition), authority=self.authority)

    def test_old_proof_cannot_be_replayed_against_a_new_state(self) -> None:
        transition = self.transition("enroll", device_fingerprint="device-b", public_key_fingerprint="key-b", key_epoch=1)
        old_proof = self.authority.proof(transition)
        next_state = self.enroll_second()
        with self.assertRaises(device.DeviceTrustError):
            device.enroll_device(next_state, "device-c", "key-c", proof=old_proof, authority=self.authority)
        self.assertEqual(next_state.generation, 1)

    def test_revocation_blocks_future_publication_without_removing_device_history(self) -> None:
        state = self.enroll_second()
        transition = self.transition("revoke", state=state, device_fingerprint="device-a")
        revoked = device.revoke_device(state, "device-a", proof=self.authority.proof(transition), authority=self.authority)
        self.assertEqual(revoked.device("device-a").status, "revoked")
        self.assertEqual(revoked.device("device-a").revoked_generation, revoked.generation)
        self.assertEqual(len(revoked.devices), 2)
        with self.assertRaises(device.DeviceTrustError):
            device.assert_can_publish(revoked, "device-a", key_epoch=revoked.key_epoch)
        device.assert_can_publish(revoked, "device-b", key_epoch=revoked.key_epoch)

    def test_rotation_advances_one_epoch_and_rejects_old_epoch_publication(self) -> None:
        state = self.enroll_second()
        transition = self.transition("rotate", state=state, key_epoch=2)
        rotated = device.rotate_key_epoch(state, proof=self.authority.proof(transition), authority=self.authority)
        self.assertEqual(rotated.key_epoch, 2)
        self.assertEqual({entry.key_epoch for entry in rotated.devices if entry.status == "active"}, {2})
        with self.assertRaises(device.DeviceTrustError):
            device.assert_can_publish(rotated, "device-a", key_epoch=1)
        device.assert_can_publish(rotated, "device-a", key_epoch=2)

    def test_recovery_threshold_change_is_externally_proven_and_bounded(self) -> None:
        state = self.enroll_second()
        transition = self.transition("set_threshold", state=state, recovery_threshold=2)
        updated = device.set_recovery_threshold(state, 2, proof=self.authority.proof(transition), authority=self.authority)
        self.assertEqual(updated.recovery_threshold, 2)
        self.assertEqual(state.recovery_threshold, 1)
        for invalid in (0, True, 3):
            with self.subTest(invalid=invalid), self.assertRaises(device.DeviceTrustError):
                device.set_recovery_threshold(state, invalid, proof=b"memory-is-not-approval", authority=self.authority)

    def test_state_rejects_unknown_fields_duplicate_devices_and_future_revocation(self) -> None:
        variants = []
        value = self.state.as_dict()
        value["memory_owner"] = "synthetic"
        variants.append(value)
        value = self.state.as_dict()
        value["devices"].append(copy.deepcopy(value["devices"][0]))
        variants.append(value)
        value = self.state.as_dict()
        value["devices"][0].update(status="revoked", revoked_generation=1)
        variants.append(value)
        value = self.state.as_dict()
        value["key_epoch"] = 2  # active device is still at epoch one: inconsistent snapshot
        variants.append(value)
        for value in variants:
            with self.subTest(value=value), self.assertRaises(device.DeviceTrustError):
                device.TrustState.from_value(value)

    def test_state_counter_types_and_bounds_are_closed(self) -> None:
        for field in ("generation", "key_epoch", "recovery_threshold", "recovery_epoch"):
            for invalid in (True, -1, 9_007_199_254_740_992):
                value = self.state.as_dict()
                value[field] = invalid
                with self.subTest(field=field, invalid=invalid), self.assertRaises(device.DeviceTrustError):
                    device.TrustState.from_value(value)

    def test_transition_generation_boolean_is_not_integer_one(self) -> None:
        transition = self.transition("enroll", device_fingerprint="device-b", public_key_fingerprint="key-b", key_epoch=1)
        transition["next_generation"] = True
        with self.assertRaises(device.DeviceTrustError):
            device._apply_transition(self.state, transition, self.authority.proof(transition), self.authority)

    def test_proof_size_is_bounded_before_authority_callback(self) -> None:
        for proof in (b"", b"x" * (device.MAX_PROOF_BYTES + 1), "not-bytes"):
            with self.subTest(size=len(proof)), self.assertRaises(device.DeviceTrustError):
                device.enroll_device(self.state, "device-b", "key-b", proof=proof, authority=self.authority)
        self.assertEqual(self.authority.observed, [])

    def test_recovery_descriptor_binds_state_hash_but_is_not_a_recovery_action(self) -> None:
        expected = {"schema_version": device.RECOVERY_DESCRIPTOR_SCHEMA, "encrypted_package_sha256": "1" * 64,
                    "encrypted_package_bytes": 20, "recovery_epoch": 1, "required_devices": 1,
                    "trust_state_sha256": self.state.sha256}
        descriptor = device.recovery_descriptor(self.state, encrypted_package_sha256="1" * 64,
                                                encrypted_package_bytes=20, authority=self.authority,
                                                proof=self.authority.proof(expected))
        self.assertEqual(descriptor, expected)
        self.assertEqual(device.validate_recovery_descriptor(descriptor, self.state), expected)
        self.assertEqual(len(self.authority.observed), 1)  # shape validation does not approve anything
        self.assertEqual(self.state.recovery_epoch, 0)
        self.assertEqual(len(self.state.devices), 1)
        altered = {**descriptor, "trust_state_sha256": "2" * 64}
        with self.assertRaises(device.DeviceTrustError):
            device.validate_recovery_descriptor(altered, self.state)

    def test_recovery_descriptor_rejects_boolean_epoch_or_threshold(self) -> None:
        descriptor = {"schema_version": device.RECOVERY_DESCRIPTOR_SCHEMA, "encrypted_package_sha256": "1" * 64,
                      "encrypted_package_bytes": 20, "recovery_epoch": 1, "required_devices": 1,
                      "trust_state_sha256": self.state.sha256}
        for field in ("recovery_epoch", "required_devices"):
            invalid = {**descriptor, field: True}
            with self.subTest(field=field), self.assertRaises(device.DeviceTrustError):
                device.validate_recovery_descriptor(invalid, self.state)


if __name__ == "__main__":
    unittest.main()
