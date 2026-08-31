"""Public synthetic encryption/catalog boundary cases; NOT run for this release.

The token provider is deliberately NOT encryption: it retains plaintext only
in this disposable process fixture and writes an opaque test token. Likewise,
the public HMAC catalog signer is not a real device-key ceremony. These cases
check adapter binding, failure atomicity and authority separation, never the
security of an audited external cipher/provider or real cross-device service.
"""

from __future__ import annotations

import base64
import contextlib
import copy
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import memory_vault as core
import memory_vault_crypto as crypto
import memory_vault_device_trust as device
import memory_vault_encrypted_replication as replication
import memory_vault_sharing as sharing
import memory_vault_storage as storage
from memory_vault_metadata import jcs_json_bytes, sha256_bytes


def write_share(path: Path, text: str = "Synthetic private memory content.") -> None:
    record = core.build_record(kind="fact", text=text, created_at="2026-01-01T00:00:00Z")
    choice = sharing.parse_selector({"schema_version": sharing.SELECTOR_SCHEMA, "all_records": True})
    header = {"type": "header", "schema_version": sharing.SHARE_SCHEMA, "hash_profile": core.HASH_PROFILE,
              "created_at": "2026-01-01T00:00:00Z", "selector": choice,
              "selector_sha256": core.sha256(core.canonical_bytes(choice))}
    line = core.canonical_bytes({"type": "record", "record": record, "attestation": None, "selected": True}) + b"\n"
    footer = {"type": "footer", "records": 1, "selected_records": 1,
              "records_sha256": core.sha256(record["record_sha256"].encode("ascii") + b"\n"),
              "lines_sha256": core.sha256(line)}
    storage.atomic_write(path, core.canonical_bytes(header) + b"\n" + line + core.canonical_bytes(footer) + b"\n",
                         replace=path.exists())


class SyntheticTokenProvider:
    """A stateful protocol fixture, NOT a cipher or a usable plugin/provider."""

    info = crypto.ProviderInfo("synthetic-token-provider-v1", "1", "recipient-a")

    def __init__(self) -> None:
        self.saved: dict[bytes, tuple[bytes, bytes, int]] = {}
        self.encrypt_calls = self.decrypt_calls = 0

    def encrypt_to_file(self, plaintext: Path, ciphertext: Path, *, key_epoch: int, associated_data: bytes) -> None:
        self.encrypt_calls += 1
        data = plaintext.read_bytes()
        token = b"SYNTHETIC-OPAQUE-TOKEN\x00" + hashlib.sha256(associated_data + b"\x00" + data).digest()
        self.saved[token] = data, associated_data, key_epoch
        storage.atomic_write(ciphertext, token, replace=False)

    def decrypt_to_file(self, ciphertext: Path, plaintext: Path, *, key_epoch: int, associated_data: bytes) -> None:
        self.decrypt_calls += 1
        token = ciphertext.read_bytes()
        item = self.saved.get(token)
        if item is None or item[1:] != (associated_data, key_epoch):
            raise crypto.CryptoError("synthetic_provider_binding_rejected")
        storage.atomic_write(plaintext, item[0], replace=False)


class SyntheticCatalogSigner:
    PUBLIC_FIXTURE_KEY = b"public-synthetic-catalog-fixture-not-a-secret"

    def __init__(self, key_fingerprint: str = "key-a") -> None:
        self.info = replication.SignerInfo("synthetic-hmac-catalog-v1", "1", "fixture-catalog", key_fingerprint)
        self.sign_calls = self.verify_calls = 0

    def signature(self, payload: bytes) -> bytes:
        domain = str(self.info.public_key_fingerprint).encode("ascii") + b"\x00" + payload
        return hmac.new(self.PUBLIC_FIXTURE_KEY, domain, hashlib.sha256).digest()

    def sign(self, payload: bytes) -> bytes:
        self.sign_calls += 1
        return self.signature(payload)

    def verify(self, payload: bytes, signature: bytes) -> None:
        self.verify_calls += 1
        if not hmac.compare_digest(self.signature(payload), signature):
            raise replication.ReplicationError("synthetic catalog signature rejected")


def resign_catalog(value: dict, signer: SyntheticCatalogSigner) -> dict:
    domain = {key: item for key, item in value.items() if key not in {"signature_b64", "catalog_sha256"}}
    domain.update(signer_profile=signer.info.profile, signer_version=signer.info.version,
                  signer_identity=signer.info.identity, signer_public_key_fingerprint=signer.info.public_key_fingerprint)
    domain["signature_b64"] = base64.b64encode(signer.sign(jcs_json_bytes(domain))).decode("ascii")
    domain["catalog_sha256"] = sha256_bytes(jcs_json_bytes(domain))
    return domain


@unittest.skipUnless(os.name == "posix", "disposable file-mode fixtures use POSIX")
class EncryptionBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="memory-v025-crypto-synthetic-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.plaintext = self.root / "source.ndjson"
        write_share(self.plaintext)
        self.provider = SyntheticTokenProvider()
        self.scope = sharing.verify_share_bundle(self.plaintext).selector_sha256
        self.envelope = self.root / "source-envelope.bin"
        self.opened = self.root / "opened.ndjson"

    def seal(self, *, key_epoch: int = 1) -> crypto.EnvelopeSummary:
        return crypto.seal_with_provider(self.plaintext, self.envelope, self.provider,
                                         capability_scope_sha256=self.scope, key_epoch=key_epoch)

    def rewrite_header(self, **changes) -> None:
        with self.envelope.open("rb") as stream:
            header = crypto._header(stream)
            ciphertext = stream.read()
        raw = core.canonical_bytes({**header, **changes})
        self.envelope.write_bytes(crypto.ENVELOPE_MAGIC + struct.pack(">I", len(raw)) + raw + ciphertext)

    def test_default_provider_fails_closed_before_any_output(self) -> None:
        with self.assertRaises(crypto.CryptoUnavailable):
            crypto.seal_with_provider(self.plaintext, self.envelope, crypto.UnconfiguredCryptoProvider(),
                                      capability_scope_sha256=self.scope, key_epoch=1)
        self.assertFalse(self.envelope.exists())
        capabilities = crypto.capabilities()
        self.assertFalse(capabilities["provider_configured_by_default"])
        self.assertFalse(capabilities["memory_can_select_provider"])
        self.assertFalse(capabilities["encryption_is_authorization"])

    def test_fixture_roundtrip_preserves_all_share_bytes_without_automatic_import(self) -> None:
        with mock.patch.object(core.Vault, "_connect", side_effect=AssertionError("codec cannot import a Vault")), \
                mock.patch("memory_vault_trust.Identity.load", side_effect=AssertionError("codec cannot load a signing identity")):
            sealed = self.seal()
            result = crypto.open_with_provider(self.envelope, self.opened, self.provider)
        self.assertEqual(self.opened.read_bytes(), self.plaintext.read_bytes())
        self.assertEqual(result.selector_sha256, self.scope)
        self.assertEqual(sealed.key_epoch, 1)
        self.assertEqual((self.provider.encrypt_calls, self.provider.decrypt_calls), (1, 1))
        self.assertFalse(self.opened.stat().st_mode & 0o077)

    def test_inspecting_ciphertext_does_not_call_decryption_provider(self) -> None:
        self.seal()
        with mock.patch.object(self.provider, "decrypt_to_file", side_effect=AssertionError("inspection cannot decrypt")):
            header, epoch = crypto.read_envelope(self.envelope)
        self.assertEqual(epoch, 1)
        self.assertEqual(header["capability_scope_sha256"], self.scope)
        self.assertNotIn(b"Synthetic private memory content", self.envelope.read_bytes())
        self.assertFalse(self.opened.exists())

    def test_wrong_scope_is_refused_before_provider_or_file_creation(self) -> None:
        with self.assertRaises(crypto.CryptoError):
            crypto.seal_with_provider(self.plaintext, self.envelope, self.provider,
                                      capability_scope_sha256="0" * 64, key_epoch=1)
        self.assertEqual(self.provider.encrypt_calls, 0)
        self.assertFalse(self.envelope.exists())

    def test_tampered_associated_data_cannot_publish_plaintext(self) -> None:
        self.seal()
        self.rewrite_header(plaintext_sha256="f" * 64)
        with self.assertRaises(crypto.CryptoError):
            crypto.open_with_provider(self.envelope, self.opened, self.provider)
        self.assertEqual(self.provider.decrypt_calls, 1)
        self.assertFalse(self.opened.exists())

    def test_recipient_mismatch_fails_before_decryption(self) -> None:
        self.seal()
        self.rewrite_header(recipient_fingerprint="recipient-b")
        with self.assertRaises(crypto.CryptoError):
            crypto.open_with_provider(self.envelope, self.opened, self.provider)
        self.assertEqual(self.provider.decrypt_calls, 0)
        self.assertFalse(self.opened.exists())

    def test_ciphertext_corruption_is_rejected_even_if_header_is_unchanged(self) -> None:
        self.seal()
        original = self.envelope.read_bytes()
        self.envelope.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
        with self.assertRaises(crypto.CryptoError):
            crypto.open_with_provider(self.envelope, self.opened, self.provider)
        self.assertEqual(self.provider.decrypt_calls, 0)
        self.assertFalse(self.opened.exists())

    def test_provider_partial_write_failure_never_publishes_complete_envelope(self) -> None:
        def fail_after_write(plaintext, ciphertext, **_kwargs):
            storage.atomic_write(ciphertext, b"synthetic-partial-provider-output", replace=False)
            raise crypto.CryptoError("synthetic_provider_interrupted")

        with mock.patch.object(self.provider, "encrypt_to_file", side_effect=fail_after_write):
            with self.assertRaises(crypto.CryptoError):
                self.seal()
        self.assertFalse(self.envelope.exists())
        self.assertEqual(list(self.root.glob(".memory-seal-*")), [])

    def test_provider_wrong_but_valid_plaintext_is_not_published(self) -> None:
        self.seal()

        def wrong_plaintext(_ciphertext, plaintext, **_kwargs):
            write_share(plaintext, "Synthetic different valid memory.")

        with mock.patch.object(self.provider, "decrypt_to_file", side_effect=wrong_plaintext):
            with self.assertRaises(crypto.CryptoError):
                crypto.open_with_provider(self.envelope, self.opened, self.provider)
        self.assertFalse(self.opened.exists())

    def test_existing_outputs_are_never_overwritten(self) -> None:
        self.seal()
        existing = self.envelope.read_bytes()
        with self.assertRaises(crypto.CryptoError):
            self.seal()
        self.assertEqual(existing, self.envelope.read_bytes())
        storage.atomic_write(self.opened, b"synthetic-existing-file", replace=False)
        with self.assertRaises(crypto.CryptoError):
            crypto.open_with_provider(self.envelope, self.opened, self.provider)
        self.assertEqual(self.opened.read_bytes(), b"synthetic-existing-file")

    def test_bounded_reader_rejects_oversized_stream_and_header(self) -> None:
        with self.assertRaises(crypto.CryptoError):
            crypto._stream_digest(io.BytesIO(b"x" * 17), 16)
        encoded = crypto.ENVELOPE_MAGIC + struct.pack(">I", crypto.MAX_HEADER_BYTES + 1)
        with self.assertRaises(crypto.CryptoError):
            crypto._header(io.BytesIO(encoded))


@unittest.skipUnless(os.name == "posix", "disposable file-mode fixtures use POSIX")
class EncryptedCatalogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="memory-v025-catalog-synthetic-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.source_root = self.root / "source"
        storage.private_directory(self.source_root)
        self.plaintext = self.root / "source.ndjson"
        write_share(self.plaintext)
        self.provider = SyntheticTokenProvider()
        scope = sharing.verify_share_bundle(self.plaintext).selector_sha256
        self.envelope = self.source_root / "packet.bin"
        crypto.seal_with_provider(self.plaintext, self.envelope, self.provider,
                                  capability_scope_sha256=scope, key_epoch=1)
        self.state = device.new_trust_state("fixture-installation", "device-a", "key-a")
        self.signer = SyntheticCatalogSigner()
        self.destination = self.root / "received"

    def catalog(self, *, envelopes=None, generation=1, previous=None, state=None, publisher="device-a", signer=None):
        return replication.build_catalog(envelopes or {"packet.bin": self.envelope}, state or self.state,
                                         publisher_fingerprint=publisher, generation=generation,
                                         previous_catalog_sha256=previous or "0" * 64, signer=signer or self.signer)

    def test_ciphertext_receiver_does_not_decrypt_or_execute_and_publishes_marker_last(self) -> None:
        catalog = self.catalog()
        receiver = replication.ReplicationReceiver(self.state)
        with mock.patch.object(crypto, "open_with_provider", side_effect=AssertionError("receiver cannot decrypt")), \
                mock.patch.object(core.Vault, "_connect", side_effect=AssertionError("receiver cannot admit memory")):
            summary = receiver.accept_catalog(catalog, self.source_root, self.destination, signer=self.signer)
        directory = self.destination / summary.catalog_sha256
        self.assertEqual((directory / "packet.bin").read_bytes(), self.envelope.read_bytes())
        receipt = json.loads((directory / "RECEIVED.json").read_text())
        self.assertFalse(receipt["plaintext_opened"])
        self.assertFalse(receipt["execution_authority_granted"])
        self.assertEqual(receiver.last_catalog_sha256, summary.catalog_sha256)

    def test_unconfigured_or_unbound_signer_cannot_publish(self) -> None:
        with self.assertRaises(replication.SignerUnavailable):
            self.catalog(signer=replication.UnconfiguredCatalogSigner())
        signer = SyntheticCatalogSigner()
        signer.info = replication.SignerInfo("synthetic-hmac-catalog-v1", "1", "fixture-catalog")
        with self.assertRaises(replication.ReplicationError):
            self.catalog(signer=signer)
        self.assertEqual(signer.sign_calls, 0)

    def test_builder_does_not_sign_a_future_epoch_catalog_that_receiver_must_reject(self) -> None:
        future = self.source_root / "future.bin"
        scope = sharing.verify_share_bundle(self.plaintext).selector_sha256
        crypto.seal_with_provider(self.plaintext, future, self.provider,
                                  capability_scope_sha256=scope, key_epoch=2)
        with self.assertRaises(replication.ReplicationError):
            self.catalog(envelopes={"future.bin": future})
        self.assertEqual(self.signer.sign_calls, 0)

    def test_revoked_key_cannot_impersonate_another_active_publisher(self) -> None:
        initial = self.catalog()
        value = self.state.as_dict()
        value["generation"] = 2
        value["devices"][0].update(status="revoked", revoked_generation=2)
        value["devices"].append({"device_fingerprint": "device-b", "public_key_fingerprint": "key-b",
                                 "status": "active", "key_epoch": 1, "enrolled_generation": 1,
                                 "revoked_generation": None})
        state = device.TrustState.from_value(value)
        with self.assertRaises(replication.ReplicationError):
            self.catalog(state=state, publisher="device-b", signer=self.signer)
        forged = {**initial, "publisher_fingerprint": "device-b", "trust_state_sha256": state.sha256,
                  "trust_generation": state.generation}
        forged = resign_catalog(forged, self.signer)  # valid signature by revoked key-a, not active key-b
        with self.assertRaises(replication.ReplicationError):
            replication.verify_catalog(forged, state, signer=self.signer)

    def test_replay_broken_chain_and_changed_trust_state_are_rejected(self) -> None:
        first = self.catalog()
        summary = replication.verify_catalog(first, self.state, signer=self.signer)
        with self.assertRaises(replication.ReplicationError):
            replication.verify_catalog(first, self.state, signer=self.signer,
                                       last_catalog_sha256=summary.catalog_sha256, last_generation=summary.generation)
        second = self.catalog(generation=2, previous=summary.catalog_sha256)
        verified = replication.verify_catalog(second, self.state, signer=self.signer,
                                               last_catalog_sha256=summary.catalog_sha256, last_generation=1)
        self.assertEqual(verified.generation, 2)
        with self.assertRaises(replication.ReplicationError):
            replication.verify_catalog(second, self.state, signer=self.signer)
        other = device.new_trust_state("another-installation", "device-a", "key-a")
        with self.assertRaises(replication.ReplicationError):
            replication.verify_catalog(first, other, signer=self.signer)

    def test_catalog_signature_is_not_replaced_by_recomputed_checksum(self) -> None:
        catalog = self.catalog()
        altered = copy.deepcopy(catalog)
        altered["entries"][0]["capability_scope_sha256"] = "1" * 64
        altered.pop("catalog_sha256")
        altered["catalog_sha256"] = sha256_bytes(jcs_json_bytes(altered))
        with self.assertRaises(replication.ReplicationError):
            replication.verify_catalog(altered, self.state, signer=self.signer)

    def test_alternate_base64_pad_bits_cannot_change_catalog_identity(self) -> None:
        catalog = self.catalog()
        original = catalog["signature_b64"]
        self.assertTrue(original.endswith("="))  # synthetic HMAC has 32 bytes
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        changed = original[:-2] + alphabet[alphabet.index(original[-2]) ^ 1] + "="
        self.assertEqual(base64.b64decode(changed), base64.b64decode(original))
        catalog["signature_b64"] = changed
        catalog.pop("catalog_sha256")
        catalog["catalog_sha256"] = sha256_bytes(jcs_json_bytes(catalog))
        with self.assertRaises(replication.ReplicationError):
            replication.verify_catalog(catalog, self.state, signer=self.signer)

    def test_signed_catalog_binds_entire_envelope_header(self) -> None:
        catalog = self.catalog()
        with self.envelope.open("rb") as stream:
            header = crypto._header(stream)
            ciphertext = stream.read()
        self.assertEqual(catalog["entries"][0]["envelope_header_sha256"], core.sha256(core.canonical_bytes(header)))
        header["plaintext_sha256"] = "f" * 64
        raw = core.canonical_bytes(header)
        self.envelope.write_bytes(crypto.ENVELOPE_MAGIC + struct.pack(">I", len(raw)) + raw + ciphertext)
        receiver = replication.ReplicationReceiver(self.state)
        with self.assertRaises(replication.ReplicationError):
            receiver.accept_catalog(catalog, self.source_root, self.destination, signer=self.signer)
        self.assertIsNone(receiver.last_catalog_sha256)
        self.assertFalse((self.destination / catalog["catalog_sha256"] / "RECEIVED.json").exists())

    def test_marker_write_interruption_keeps_retryable_files_and_does_not_advance_head(self) -> None:
        catalog = self.catalog()
        receiver = replication.ReplicationReceiver(self.state)
        real_output = replication._new_output

        @contextlib.contextmanager
        def interrupted_marker(path):
            with real_output(path) as stream:
                yield stream
                if Path(path).name == "RECEIVED.json":
                    raise OSError("synthetic interruption before marker publication")

        with mock.patch.object(replication, "_new_output", interrupted_marker):
            with self.assertRaises(OSError):
                receiver.accept_catalog(catalog, self.source_root, self.destination, signer=self.signer)
        directory = self.destination / catalog["catalog_sha256"]
        self.assertTrue((directory / "packet.bin").exists())
        self.assertFalse((directory / "RECEIVED.json").exists())
        self.assertIsNone(receiver.last_catalog_sha256)
        receiver.accept_catalog(catalog, self.source_root, self.destination, signer=self.signer)
        self.assertTrue((directory / "RECEIVED.json").exists())

    def test_portable_path_collisions_and_receipt_name_are_refused(self) -> None:
        for paths in (("RECEIVED.json",), ("received.json/packet",), ("Packet.bin", "packet.bin"),
                      ("packet", "packet/nested.bin"), ("../escape.bin",), ("NUL",), ("folder./packet",)):
            with self.subTest(paths=paths), self.assertRaises(replication.ReplicationError):
                self.catalog(envelopes={path: self.envelope for path in paths})

    def test_metadata_budget_is_separate_from_ciphertext_size(self) -> None:
        catalog = self.catalog()
        template = catalog["entries"][0]
        catalog["entries"] = [{**template, "path": f"{index:06d}-" + "x" * 400, "ciphertext_bytes": 1}
                              for index in range(2000)]
        catalog = resign_catalog(catalog, self.signer)
        previous_calls = self.signer.verify_calls
        with self.assertRaises(replication.ReplicationError):
            replication.verify_catalog(catalog, self.state, signer=self.signer, maximum_metadata_bytes=1024 * 1024)
        self.assertEqual(self.signer.verify_calls, previous_calls)

    def test_operation_deadline_fails_before_copy_or_head_update(self) -> None:
        catalog = self.catalog()
        receiver = replication.ReplicationReceiver(self.state)
        with mock.patch.object(replication.time, "monotonic", side_effect=[0.0, 0.0, 2.0]):
            with self.assertRaises(replication.ReplicationError):
                receiver.accept_catalog(catalog, self.source_root, self.destination,
                                        signer=self.signer, maximum_seconds=1)
        self.assertIsNone(receiver.last_catalog_sha256)
        self.assertFalse(self.destination.exists())


if __name__ == "__main__":
    unittest.main()
