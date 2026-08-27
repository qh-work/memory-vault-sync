from __future__ import annotations

import dataclasses
import unittest

from memory_vault_runtime import device_trust
from memory_vault_runtime.protocol import jcs_json_bytes, sha256_bytes


class _Authority:
    info = device_trust.AuthorityInfo(
        profile="test-authority-v1",
        version="1",
        identity="test:authority",
    )

    def verify_transition(self, transition, proof: bytes) -> None:
        if proof != b"approved":
            raise device_trust.DeviceTrustError("test proof rejected")
        if sha256_bytes(jcs_json_bytes(dict(transition))) == "0" * 64:
            raise device_trust.DeviceTrustError("impossible test transition")


class DeviceTrustTests(unittest.TestCase):
    def test_enroll_rotate_revoke_is_monotonic_and_taskless(self) -> None:
        authority = _Authority()
        state = device_trust.new_trust_state(
            "install:mac",
            "device:mac",
            "key:mac",
        )
        enrolled = device_trust.enroll_device(
            state,
            "device:windows",
            "key:windows",
            proof=b"approved",
            authority=authority,
        )
        self.assertEqual(enrolled.generation, 1)
        self.assertEqual(enrolled.device("device:windows").status, "active")
        thresholded = device_trust.set_recovery_threshold(
            enrolled,
            2,
            proof=b"approved",
            authority=authority,
        )
        self.assertEqual(thresholded.recovery_threshold, 2)
        rotated = device_trust.rotate_key_epoch(
            thresholded,
            proof=b"approved",
            authority=authority,
        )
        self.assertEqual(rotated.key_epoch, 2)
        device_trust.assert_can_publish(
            rotated,
            "device:windows",
            key_epoch=2,
        )
        with self.assertRaises(device_trust.DeviceTrustError):
            device_trust.assert_can_publish(rotated, "device:windows", key_epoch=1)
        revoked = device_trust.revoke_device(
            rotated,
            "device:windows",
            proof=b"approved",
            authority=authority,
        )
        self.assertEqual(revoked.device("device:windows").status, "revoked")
        with self.assertRaises(device_trust.DeviceTrustError):
            device_trust.assert_can_publish(revoked, "device:windows", key_epoch=2)
        self.assertEqual(
            device_trust.TrustState.from_value(revoked.as_dict()),
            revoked,
        )

    def test_unconfigured_authority_and_owner_fields_fail_closed(self) -> None:
        state = device_trust.new_trust_state(
            "install:mac",
            "device:mac",
            "key:mac",
        )
        with self.assertRaises(device_trust.TrustUnavailable):
            device_trust.enroll_device(
                state,
                "device:windows",
                "key:windows",
                proof=b"approved",
                authority=device_trust.UnconfiguredTrustAuthority(),
            )
        with self.assertRaises(device_trust.DeviceTrustError):
            device_trust.new_trust_state(
                "task-owner",
                "device:mac",
                "key:mac",
            )

    def test_recovery_descriptor_is_bound_to_exact_state_and_epoch(self) -> None:
        authority = _Authority()
        state = device_trust.new_trust_state(
            "install:mac",
            "device:mac",
            "key:mac",
        )
        descriptor = device_trust.recovery_descriptor(
            state,
            encrypted_package_sha256="a" * 64,
            encrypted_package_bytes=128,
            authority=authority,
            proof=b"approved",
        )
        self.assertEqual(
            device_trust.validate_recovery_descriptor(descriptor, state),
            descriptor,
        )
        changed = dataclasses.replace(state, generation=1)
        with self.assertRaises(device_trust.DeviceTrustError):
            device_trust.validate_recovery_descriptor(descriptor, changed)


if __name__ == "__main__":
    unittest.main()
