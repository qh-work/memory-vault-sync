"""One explicitly opted-in capacity check; not part of ordinary discovery.

This fixture creates a sparse 516 MiB synthetic source, streams it through the
real pack/copy/unpack functions and temporarily materializes one equally sized
output. Allow approximately 600 MiB free space. It never reads private data,
uses a Vault/key, launches a child, or contacts a host/provider. Full 2 GiB
boundary validation below checks real manifest acceptance, not a 2 GiB transfer.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import tempfile
import unittest

import memory_vault_pack as packs
import memory_vault_storage as storage
from memory_vault import MemoryError, canonical_bytes


@unittest.skipUnless(os.environ.get("MEMORY_VAULT_LARGE_PACK_SMOKE") == "1",
                     "explicit capacity-check opt-in required; uses about 600 MiB")
class PackCapacityTests(unittest.TestCase):
    @staticmethod
    def streamed_hash(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            while data := stream.read(packs.CHUNK_BYTES):
                digest.update(data)
        return digest.hexdigest()

    def test_old_export_capacity_and_resumed_copy_preserve_complete_bytes(self) -> None:
        self.assertEqual(packs.MAX_SOURCE_BYTES, 2 * 1024 * 1024 * 1024)
        self.assertEqual(packs.CHUNK_BYTES, 4 * 1024 * 1024)
        self.assertEqual(packs.MAX_CHUNKS, 512)
        with tempfile.TemporaryDirectory(prefix="memory-v025-pack-capacity-") as temporary:
            root = Path(temporary).resolve()
            # Actual full-capacity framing, with worst-size valid numeric
            # fields; this does not claim those synthetic hashes authenticate
            # any chunk bytes. Manifest inspection deliberately checks framing.
            maximum = root / "maximum-manifest"
            maximum.mkdir(mode=0o700)
            manifest = {
                "schema_version": packs.SCHEMA, "source_bytes": packs.MAX_SOURCE_BYTES,
                "source_sha256": "a" * 64, "chunk_bytes": packs.CHUNK_BYTES,
                "compression": "zlib", "chunks": [
                    {"index": index, "bytes": packs.CHUNK_BYTES,
                     "sha256": "b" * 64, "compressed_bytes": packs.MAX_COMPRESSED_BYTES,
                     "compressed_sha256": hashlib.sha256(str(index).encode()).hexdigest()}
                    for index in range(packs.MAX_CHUNKS)
                ],
            }
            encoded = canonical_bytes(manifest) + b"\n"
            self.assertLessEqual(len(encoded), packs.MAX_MANIFEST_BYTES)
            storage.atomic_write(maximum / "MANIFEST.json", encoded, replace=False)
            self.assertEqual(packs._manifest(maximum)[0], manifest)
            too_large = root / "too-large.bin"
            with too_large.open("xb") as stream:
                stream.truncate(packs.MAX_SOURCE_BYTES + 1)
            with self.assertRaisesRegex(MemoryError, "pack_unsafe_or_oversized_file"):
                packs.create(too_large, root / "must-not-exist")
            self.assertFalse((root / "must-not-exist").exists())

            size = 129 * packs.CHUNK_BYTES  # 516 MiB: actually exceeds v0.25.0.
            source = root / "synthetic-source.bin"
            with source.open("xb") as stream:
                stream.truncate(size)
                for index in range(129):
                    stream.seek(index * packs.CHUNK_BYTES)
                    stream.write(f"synthetic-capacity-chunk-{index:03d}".encode("ascii"))
            expected = self.streamed_hash(source)
            original, copied, output = root / "original", root / "copied", root / "output.bin"
            created = packs.create(source, original)
            self.assertEqual((created["source_bytes"], created["chunks"]), (size, 129))
            self.assertFalse(created["network_accessed"])
            first = packs.copy(original, copied, maximum_chunks=1)
            self.assertEqual(first["state"], "copy_pending_repeat_same_command")
            self.assertEqual(first["copied_chunks"], 1)
            self.assertFalse((copied / "MANIFEST.json").exists())
            results = [packs.copy(original, copied) for _ in range(4)]
            self.assertTrue(all(result["chunks_checked_this_run"] <= 32 for result in results))
            self.assertTrue(all(result["state"] == "copy_pending_repeat_same_command" for result in results[:-1]))
            self.assertEqual(results[-1]["state"], "copy_complete")
            self.assertEqual((copied / "MANIFEST.json").read_bytes(), (original / "MANIFEST.json").read_bytes())
            repeated = packs.copy(original, copied)
            self.assertEqual(repeated["copied_chunks"], 0)
            self.assertEqual(repeated["chunks_checked_this_run"], 0)
            unpacked = packs.unpack(copied, output)
            self.assertEqual(unpacked["bytes"], size)
            self.assertEqual(unpacked["source_sha256"], expected)
            self.assertEqual(output.stat().st_size, size)
            self.assertEqual(self.streamed_hash(output), expected)
            with self.assertRaisesRegex(MemoryError, "pack_unpack_requires_new_external_file"):
                packs.unpack(copied, output)


if __name__ == "__main__":
    unittest.main()
