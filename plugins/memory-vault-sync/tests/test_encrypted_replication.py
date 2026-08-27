from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from memory_vault_runtime import crypto_adapter, device_trust, encrypted_replication


class _TestCryptoProvider:
    info = crypto_adapter.ProviderInfo(
        profile="test-envelope-provider-v1",
        version="1",
        recipient_fingerprint="recipient:windows",
    )

    def encrypt_to_file(self, plaintext: Path, ciphertext: Path, *, key_epoch: int) -> None:
        ciphertext.write_bytes(b"TEST\0" + plaintext.read_bytes())

    def decrypt_to_file(self, ciphertext: Path, plaintext: Path, *, key_epoch: int) -> None:
        raw = ciphertext.read_bytes()
        if not raw.startswith(b"TEST\0"):
            raise crypto_adapter.CryptoError("test ciphertext is invalid")
        plaintext.write_bytes(raw[5:])


class _TestSigner:
    info = encrypted_replication.SignerInfo(
        profile="test-catalog-signer-v1",
        version="1",
        identity="signer:test",
    )

    def sign(self, payload: bytes) -> bytes:
        return b"TEST-SIGNATURE\0" + hashlib.sha256(payload).digest()

    def verify(self, payload: bytes, signature: bytes) -> None:
        expected = self.sign(payload)
        if signature != expected:
            raise encrypted_replication.ReplicationError("test signature mismatch")


class EncryptedReplicationTests(unittest.TestCase):
    def test_catalog_is_ciphertext_only_and_receiver_rejects_replay(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            provider = _TestCryptoProvider()
            for name, text in (("one.enc", b"one"), ("two.enc", b"two")):
                plaintext = root / f"{name}.plain"
                plaintext.write_bytes(text)
                crypto_adapter.seal_with_provider(
                    plaintext,
                    source / name,
                    provider,
                    capability_scope_sha256="a" * 64,
                    key_epoch=1,
                )
            state = device_trust.new_trust_state(
                "install:mac",
                "device:mac",
                "key:mac",
            )
            signer = _TestSigner()
            catalog = encrypted_replication.build_catalog(
                {"one.enc": source / "one.enc", "two.enc": source / "two.enc"},
                state,
                publisher_fingerprint="device:mac",
                generation=1,
                previous_catalog_sha256="0" * 64,
                signer=signer,
            )
            summary = encrypted_replication.verify_catalog(catalog, state, signer=signer)
            self.assertEqual(summary.entry_count, 2)
            self.assertNotIn("plaintext", str(catalog).casefold())
            receiver = encrypted_replication.ReplicationReceiver(state)
            destination = root / "received"
            accepted = receiver.accept_catalog(catalog, source, destination, signer=signer)
            self.assertEqual(accepted.catalog_sha256, summary.catalog_sha256)
            self.assertEqual((destination / "one.enc").read_bytes(), (source / "one.enc").read_bytes())
            with self.assertRaises(encrypted_replication.ReplicationError):
                receiver.accept_catalog(catalog, source, root / "replay", signer=signer)

    def test_unconfigured_signer_does_not_publish_catalog(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plaintext = root / "plain"
            plaintext.write_bytes(b"ciphertext input")
            envelope = root / "one.enc"
            crypto_adapter.seal_with_provider(
                plaintext,
                envelope,
                _TestCryptoProvider(),
                capability_scope_sha256="b" * 64,
                key_epoch=1,
            )
            state = device_trust.new_trust_state("install:mac", "device:mac", "key:mac")
            with self.assertRaises(encrypted_replication.SignerUnavailable):
                encrypted_replication.build_catalog(
                    {"one.enc": envelope},
                    state,
                    publisher_fingerprint="device:mac",
                    generation=1,
                    previous_catalog_sha256="0" * 64,
                    signer=encrypted_replication.UnconfiguredCatalogSigner(),
                )


if __name__ == "__main__":
    unittest.main()
