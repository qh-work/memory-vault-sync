"""Synthetic operator metadata cases; execution is recorded per case.

Only three selected methods ran in docs/V0_25_SCOPED_SMOKE.md, not this full file.

Fixtures contain opaque labels and manually framed bytes, not real ciphertext,
keys, accounts or memory. Hashes use hashlib directly, independently of the
application's writers. Passing a byte inspection is not authentication. These
POSIX file fixtures do not certify Windows or an external provider.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import struct
import tempfile
import unittest
from unittest import mock

import memory_vault as core
import memory_vault_client as client
import memory_vault_crypto as crypto
import memory_vault_device_trust as device


def canonical_json(value: object) -> bytes:
    # All fixture keys/strings are ASCII; integers are encoded without floats.
    # Legacy inspection must also accept its original 64-bit epoch domain.
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def envelope_bytes(*, legacy: bool = False, epoch: int = 1, payload: bytes = b"\x00SYNTHETIC-OPAQUE\xff") -> bytes:
    schema = "memory-share-envelope/v1" if legacy else "universal-memory-share-envelope/v1"
    header = {
        "schema_version": schema,
        "crypto_profile": "synthetic-opaque-frame-v1",
        "provider_version": "1",
        "recipient_fingerprint": "fixture-recipient",
        "key_epoch": epoch,
        "capability_scope_sha256": hashlib.sha256(b"synthetic selector commitment").hexdigest(),
        "ciphertext_sha256": hashlib.sha256(payload).hexdigest(),
        "ciphertext_bytes": len(payload),
    }
    if not legacy:
        uninspected = b"synthetic plaintext commitment; no plaintext file"
        header.update(plaintext_sha256=hashlib.sha256(uninspected).hexdigest(), plaintext_bytes=len(uninspected))
    raw = canonical_json(header)
    return schema.encode("ascii") + b"\n" + struct.pack(">I", len(raw)) + raw + payload


@unittest.skipUnless(os.name == "posix", "POSIX disposable private-file fixtures; native coverage is separate")
class OperatorMetadataTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="memory-v025-metadata-synthetic-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    def write(self, name: str, raw: bytes) -> Path:
        path = self.root / name
        with path.open("xb") as stream:
            stream.write(raw)
        path.chmod(0o600)
        return path

    @contextlib.contextmanager
    def no_memory_or_provider(self):
        forbidden = AssertionError("metadata inspection must not select a Vault/config/provider")
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.dict(os.environ, {
                "MEMORY_VAULT_PATH": "relative-invalid-vault",
                "MEMORY_VAULT_CLIENT_CONFIG": "relative-invalid-client-config",
            }))
            for owner, name in (
                (core, "Vault"), (core, "default_vault_path"),
                (client, "default_config_path"), (client.ClientConfig, "load"),
                (crypto, "_provider"), (crypto, "open_with_provider"),
                (crypto, "seal_with_provider"), (crypto, "verify_share_bundle"),
                (device.UnconfiguredTrustAuthority, "verify_transition"),
            ):
                stack.enter_context(mock.patch.object(owner, name, side_effect=forbidden))
            yield

    def initialize(self, path: Path) -> dict:
        return dict(device.initialize_state(
            path, installation_fingerprint="fixture-installation",
            device_fingerprint="device-a", public_key_fingerprint="key-a",
        ))

    def cli(self, entry, arguments: list[str]) -> tuple[int, dict]:
        with io.BytesIO() as output:
            with io.TextIOWrapper(output, encoding="utf-8", write_through=True) as text:
                with contextlib.redirect_stdout(text):
                    code = entry(arguments)
                raw = output.getvalue()
        return code, json.loads(raw)

    def assert_inspection(self, result: dict, *, legacy: bool, epoch: int, payload: bytes) -> None:
        self.assertEqual(result["schema_version"], "universal-memory-envelope-inspection/v1")
        self.assertEqual(result["envelope_schema"], "memory-share-envelope/v1" if legacy else "universal-memory-share-envelope/v1")
        self.assertTrue(result["valid"])
        self.assertEqual(result["key_epoch"], epoch)
        self.assertEqual(result["ciphertext_bytes"], len(payload))
        self.assertEqual(result["ciphertext_sha256"], hashlib.sha256(payload).hexdigest())
        self.assertIs(result["plaintext_binding_present"], not legacy)
        for name in ("authenticated", "plaintext_opened", "provider_invoked", "network_accessed", "memory_changed", "keys_enrolled"):
            self.assertIs(result[name], False, name)

    def test_initialize_and_status_are_metadata_only_and_read_only(self) -> None:
        path = self.root / "device-state.json"
        with self.no_memory_or_provider():
            initialized = self.initialize(path)
            before = path.stat()
            raw = path.read_bytes()
            names = set(self.root.iterdir())
            observed = dict(device.status(path))
        expected_hash = hashlib.sha256(canonical_json(json.loads(raw))).hexdigest()
        for result in (initialized, observed):
            self.assertEqual(result["schema_version"], "memory-device-trust-status/v1")
            self.assertEqual(result["state_path"], str(path))
            self.assertEqual(result["state_sha256"], expected_hash)
            self.assertEqual(result["installation_fingerprint"], "fixture-installation")
            self.assertEqual(result["generation"], 0)
            self.assertEqual(result["key_epoch"], 1)
            self.assertEqual(result["recovery_epoch"], 0)
            self.assertEqual(result["recovery_threshold"], 1)
            self.assertEqual(result["device_count"], 1)
            self.assertEqual(result["active_device_count"], 1)
            self.assertEqual(result["revoked_device_count"], 0)
            self.assertEqual(result["device_fingerprints"], ["device-a"])
            self.assertIs(result["external_authority_configured"], False)
            self.assertIs(result["private_keys_present"], False)
            for name in ("key_possession_verified", "record_signing_registry_changed", "memory_changed",
                         "network_accessed", "execution_authority_granted"):
                self.assertIs(result[name], False, name)
        self.assertIs(initialized["created"], True)
        self.assertIs(observed["created"], False)
        self.assertEqual(path.read_bytes(), raw)
        after = path.stat()
        self.assertEqual((after.st_ino, after.st_mtime_ns, after.st_ctime_ns),
                         (before.st_ino, before.st_mtime_ns, before.st_ctime_ns))
        self.assertEqual(stat.S_IMODE(after.st_mode), 0o600)
        self.assertEqual(set(self.root.iterdir()), names)

    def test_initialize_never_overwrites_an_existing_state(self) -> None:
        path = self.root / "existing-state.json"
        with self.no_memory_or_provider():
            self.initialize(path)
            raw, before = path.read_bytes(), path.stat()
            for installation in ("fixture-installation", "different-installation"):
                with self.subTest(installation=installation), self.assertRaises((device.DeviceTrustError, core.MemoryError, OSError)):
                    device.initialize_state(path, installation_fingerprint=installation,
                                            device_fingerprint="device-b", public_key_fingerprint="key-b")
                self.assertEqual(path.read_bytes(), raw)
                self.assertEqual(path.stat().st_ino, before.st_ino)

    def test_status_rejects_missing_and_invalid_states_without_creating_or_repairing(self) -> None:
        missing = self.root / "absent-parent" / "state.json"
        with self.no_memory_or_provider():
            with self.assertRaises((device.DeviceTrustError, core.MemoryError, OSError)):
                device.status(missing)
            self.assertFalse(missing.parent.exists())
            valid = {
                "schema_version": "memory-device-trust/v1", "installation_fingerprint": "fixture-installation",
                "generation": 0, "key_epoch": 1, "recovery_threshold": 1, "recovery_epoch": 0,
                "devices": [{"device_fingerprint": "device-a", "public_key_fingerprint": "key-a",
                             "status": "active", "key_epoch": 1, "enrolled_generation": 0, "revoked_generation": None}],
            }
            variants = [dict(valid, generation=True), dict(valid, unexpected="not-permitted"),
                        dict(valid, devices=valid["devices"] * 2)]
            for number, value in enumerate(variants):
                path = self.write(f"invalid-state-{number}.json", canonical_json(value))
                before = path.read_bytes()
                with self.subTest(number=number), self.assertRaises((device.DeviceTrustError, core.MemoryError, OSError)):
                    device.status(path)
                self.assertEqual(path.read_bytes(), before)

    def test_device_cli_uses_only_the_explicit_state_path(self) -> None:
        path = self.root / "cli-state.json"
        with self.no_memory_or_provider():
            code, created = self.cli(device.main, [
                "init", "--state", str(path), "--installation-fingerprint", "fixture-installation",
                "--device-fingerprint", "device-a", "--public-key-fingerprint", "key-a",
            ])
            self.assertEqual(code, 0)
            self.assertTrue(created["ok"])
            code, observed = self.cli(device.main, ["status", "--state", str(path)])
            self.assertEqual(code, 0)
            self.assertTrue(observed["ok"])
        self.assertEqual(created["result"]["state_sha256"], observed["result"]["state_sha256"])
        self.assertEqual(observed["result"]["state_path"], str(path))

    def test_new_envelope_inspection_hashes_opaque_bytes_without_opening_plaintext(self) -> None:
        payload = b"\x00new synthetic opaque bytes\xff"
        path = self.write("new-envelope.bin", envelope_bytes(payload=payload))
        before, names = path.read_bytes(), set(self.root.iterdir())
        with self.no_memory_or_provider():
            result = dict(crypto.verify_envelope(path))
        self.assert_inspection(result, legacy=False, epoch=1, payload=payload)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(set(self.root.iterdir()), names)

    def test_legacy_epoch_domain_requires_explicit_legacy_inspection(self) -> None:
        # v0.21 admitted epoch zero, 64-bit counters and empty ciphertext.
        for epoch, payload in ((0, b"old synthetic opaque bytes"), (2**63 - 1, b"")):
            path = self.write(f"old-envelope-{epoch}.bin", envelope_bytes(legacy=True, epoch=epoch, payload=payload))
            with self.subTest(epoch=epoch), self.no_memory_or_provider():
                with self.assertRaises(crypto.CryptoError):
                    crypto.read_envelope(path)
                with self.assertRaises(crypto.CryptoError):
                    crypto.verify_envelope(path)
                result = dict(crypto.verify_envelope(path, legacy_v021=True))
            self.assert_inspection(result, legacy=True, epoch=epoch, payload=payload)

    def test_both_envelopes_reject_ciphertext_tampering_truncation_and_trailing_bytes(self) -> None:
        for legacy in (False, True):
            raw = envelope_bytes(legacy=legacy)
            variants = {"tampered": raw[:-1] + bytes([raw[-1] ^ 1]),
                        "truncated": raw[:-1], "trailing": raw + b"EXTRA"}
            for name, damaged in variants.items():
                path = self.write(f"damaged-{int(legacy)}-{name}.bin", damaged)
                with self.subTest(legacy=legacy, variant=name), self.no_memory_or_provider():
                    with self.assertRaises(crypto.CryptoError):
                        crypto.verify_envelope(path, legacy_v021=legacy)
                self.assertEqual(path.read_bytes(), damaged)

    def test_crypto_cli_capabilities_and_explicit_verify_do_not_require_a_provider(self) -> None:
        with self.no_memory_or_provider():
            code, capabilities = self.cli(crypto.main, ["capabilities"])
            self.assertEqual(code, 0)
            self.assertTrue(capabilities["ok"])
            self.assertIs(capabilities["result"]["provider_configured_by_default"], False)
            for legacy in (False, True):
                payload = b"cli opaque bytes"
                path = self.write(f"cli-envelope-{int(legacy)}.bin", envelope_bytes(legacy=legacy, payload=payload))
                arguments = ["verify", "--source", str(path), "--maximum-seconds", "10"]
                if legacy:
                    arguments.append("--legacy-v021")
                code, response = self.cli(crypto.main, arguments)
                self.assertEqual(code, 0)
                self.assertTrue(response["ok"])
                self.assert_inspection(response["result"], legacy=legacy, epoch=1, payload=payload)


if __name__ == "__main__":
    unittest.main()
