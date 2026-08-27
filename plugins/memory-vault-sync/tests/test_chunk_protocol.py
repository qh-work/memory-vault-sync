from __future__ import annotations

import copy
import hashlib
import sys
import unittest
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = PLUGIN_ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from memory_vault_runtime import chunks  # noqa: E402


class ChunkProtocolTests(unittest.TestCase):
    def _policy(self) -> dict:
        return chunks.policy_document(
            vault_id="codex-memory-vault",
            store_id="rclone-crypt-primary",
            container_id="rclone-" + "2" * 32,
            remote_fingerprint="2" * 64,
            key_epoch="3" * 64,
        )

    def _manifest(self) -> dict:
        return chunks.manifest_document(
            policy=self._policy(),
            artifact_sha256="c" * 64,
            artifact_size=chunks.CHUNK_SIZE_BYTES + 3,
            mime_type="application/octet-stream",
            chunks=[
                {
                    "index": 0,
                    "offset": 0,
                    "size": chunks.CHUNK_SIZE_BYTES,
                    "content_id": "a" * 64,
                },
                {
                    "index": 1,
                    "offset": chunks.CHUNK_SIZE_BYTES,
                    "size": 3,
                    "content_id": "b" * 64,
                },
            ],
        )

    def test_chunk_and_manifest_hashes_are_domain_separated(self) -> None:
        payload = b"same plaintext bytes"
        hasher = chunks.new_chunk_hasher()
        hasher.update(payload[:4])
        hasher.update(payload[4:])
        content_id = chunks.chunk_content_id(payload)
        self.assertEqual(hasher.hexdigest(), content_id)
        self.assertNotEqual(content_id, hashlib.sha256(payload).hexdigest())

        manifest = self._manifest()
        manifest_id = chunks.manifest_id(manifest)
        self.assertNotEqual(
            manifest_id,
            hashlib.sha256(chunks.manifest_bytes(manifest)).hexdigest(),
        )
        changed = copy.deepcopy(manifest)
        changed["chunks"][1]["content_id"] = "d" * 64
        self.assertNotEqual(chunks.manifest_id(changed), manifest_id)

    def test_manifest_proves_exact_offsets_count_and_total_size(self) -> None:
        manifest = self._manifest()
        normalized = chunks.validate_manifest(
            manifest,
            policy=self._policy(),
            artifact_sha256="c" * 64,
            artifact_size=chunks.CHUNK_SIZE_BYTES + 3,
            mime_type="application/octet-stream",
        )
        self.assertEqual(normalized, manifest)
        for field, value in (
            ("chunk_count", 1),
            ("total_size", chunks.CHUNK_SIZE_BYTES),
        ):
            with self.subTest(field=field):
                changed = copy.deepcopy(manifest)
                changed[field] = value
                with self.assertRaises(chunks.ChunkProtocolError):
                    chunks.validate_manifest(changed, policy=self._policy())
        changed = copy.deepcopy(manifest)
        changed["chunks"][1]["offset"] -= 1
        with self.assertRaises(chunks.ChunkProtocolError):
            chunks.validate_manifest(changed, policy=self._policy())

    def test_policy_and_manifest_reject_algorithm_or_bound_downgrade(self) -> None:
        policy = self._policy()
        changed_policy = dict(policy)
        changed_policy["algorithm"] = "whole-object-v1"
        with self.assertRaises(chunks.ChunkProtocolError):
            chunks.validate_policy(
                changed_policy,
                vault_id="codex-memory-vault",
                store_id="rclone-crypt-primary",
                container_id="rclone-" + "2" * 32,
                remote_fingerprint="2" * 64,
            )

        oversized = self._manifest()
        oversized["artifact_size"] = (
            chunks.CHUNK_SIZE_BYTES * chunks.MAX_CHUNK_COUNT + 1
        )
        with self.assertRaises(chunks.ChunkProtocolError):
            chunks.validate_manifest(oversized, policy=policy)

    def test_manifest_is_bound_to_store_fingerprint_and_key_epoch(self) -> None:
        manifest = self._manifest()
        for field, replacement in (
            ("store_id", "another-store"),
            ("container_id", "rclone-" + "4" * 32),
            ("remote_fingerprint", "5" * 64),
            ("key_epoch", "6" * 64),
            ("encryption_policy", "plaintext-v1"),
        ):
            with self.subTest(field=field):
                changed = copy.deepcopy(manifest)
                changed[field] = replacement
                with self.assertRaises(chunks.ChunkProtocolError):
                    chunks.validate_manifest(changed, policy=self._policy())

    def test_protocol_rejects_unknown_fields_and_empty_chunks(self) -> None:
        policy = self._policy()
        changed_policy = dict(policy)
        changed_policy["future"] = True
        with self.assertRaises(chunks.ChunkProtocolError):
            chunks.validate_policy(
                changed_policy,
                vault_id="codex-memory-vault",
                store_id="rclone-crypt-primary",
                container_id="rclone-" + "2" * 32,
                remote_fingerprint="2" * 64,
            )
        with self.assertRaises(chunks.ChunkProtocolError):
            chunks.chunk_content_id(b"")


if __name__ == "__main__":
    unittest.main()
