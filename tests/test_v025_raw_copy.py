"""Opt-in original-byte continuation check; ordinary discovery skips it.

Creates a sparse 2 GiB + 4 MiB source and copies every byte without repacking.
Allow 2.2 GiB of temporary disk space. No network, Vault, keys or subprocesses.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

from memory_vault import MemoryError, canonical_bytes
import memory_vault_client as client
import memory_vault_file_copy as raw_copy
import memory_vault_storage as storage


@unittest.skipUnless(os.environ.get("MEMORY_VAULT_RAW_COPY_SMOKE") == "1",
                     "explicit raw-copy opt-in required; uses about 2.2 GiB")
class RawCopyTests(unittest.TestCase):
    @staticmethod
    def streamed_hash(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            while chunk := stream.read(raw_copy.CHUNK_BYTES):
                digest.update(chunk)
        return digest.hexdigest()

    def test_original_large_bytes_and_legacy_resume_preserve_data(self) -> None:
        with tempfile.TemporaryDirectory(prefix="memory-v025-raw-copy-") as temporary:
            root = Path(temporary).resolve()
            source, output, journal = (root / name for name in ("source.bin", "copy.bin", "copy.json"))
            size = 2 * 1024 * 1024 * 1024 + raw_copy.CHUNK_BYTES
            with source.open("xb") as stream:
                stream.truncate(size)
                for index in range(513):
                    stream.seek(index * raw_copy.CHUNK_BYTES)
                    stream.write(f"synthetic-original-chunk-{index:03d}".encode("ascii"))
            expected = self.streamed_hash(source)
            # Exercise the real config-free old command, not just a helper.
            captured = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
            with contextlib.redirect_stdout(captured):
                status = client.main(["copy-pack", "--pack", str(source), "--output", str(output),
                                      "--journal", str(journal), "--maximum-bytes", str(raw_copy.CHUNK_BYTES)])
            captured.flush()
            response = captured.buffer.getvalue()
            self.assertEqual(status, 0, response)
            first = json.loads(response)
            captured.close()
            self.assertTrue(first["ok"])
            self.assertEqual(output.stat().st_size, raw_copy.CHUNK_BYTES)
            state = json.loads(journal.read_bytes())
            self.assertEqual(state["offset"], raw_copy.CHUNK_BYTES)
            self.assertFalse(state["complete"])
            results = []
            for _ in range(8):
                results.append(raw_copy.resumable_copy(source, output, journal, maximum_bytes=raw_copy.MAXIMUM_BYTES))
            self.assertTrue(all(result["resumed"] for result in results))
            self.assertTrue(all(result["copied_this_call"] == raw_copy.MAXIMUM_BYTES for result in results))
            self.assertTrue(all(not result["complete"] for result in results[:-1]))
            self.assertTrue(results[-1]["complete"])
            self.assertEqual(results[-1]["source_sha256"], expected)
            self.assertEqual(results[-1]["source_bytes"], size)
            self.assertEqual(output.stat().st_size, size)
            self.assertEqual(self.streamed_hash(output), expected)
            repeated = raw_copy.resumable_copy(source, output, journal)
            self.assertTrue(repeated["complete"])
            self.assertEqual(repeated["copied_this_call"], 0)
            self.assertFalse(repeated["publisher_signature_verified"])
            self.assertFalse(repeated["memory_imported"])

            # Independently encode v0.21's actual five-field journal. A
            # matching unacknowledged tail must survive migration and resume.
            old_source, old_output, old_journal = (root / name for name in ("old.bin", "old-copy.bin", "old.json"))
            content = b"synthetic legacy original bytes\n" * 1000
            old_source.write_bytes(content)
            storage.atomic_write(old_output, content[:4096], replace=False)
            storage.atomic_write(old_journal, canonical_bytes({
                "schema_version": "memory-network-publication-journal/v1",
                "source_sha256": hashlib.sha256(content).hexdigest(),
                "source_bytes": len(content), "offset": 1024, "complete": False,
            }), replace=False)
            resumed = raw_copy.resumable_copy(old_source, old_output, old_journal, maximum_bytes=1024)
            self.assertEqual(resumed["copied_bytes"], 5120)
            self.assertEqual(old_output.read_bytes(), content[:5120])
            self.assertEqual(json.loads(old_journal.read_bytes())["schema_version"], raw_copy.JOURNAL_SCHEMA)
            complete = raw_copy.resumable_copy(old_source, old_output, old_journal)
            self.assertTrue(complete["complete"])
            self.assertEqual(old_output.read_bytes(), content)
            # Completed flags and stale metadata never authorize corrupted bytes.
            with old_output.open("r+b") as stream:
                stream.write(b"X")
            damaged = old_output.read_bytes()
            receipt = old_journal.read_bytes()
            with self.assertRaisesRegex(MemoryError, "file_copy_destination_conflict"):
                raw_copy.resumable_copy(old_source, old_output, old_journal)
            self.assertEqual(old_output.read_bytes(), damaged)
            self.assertEqual(old_journal.read_bytes(), receipt)
            unknown = root / "unknown.bin"
            storage.atomic_write(unknown, b"keep these unrelated bytes", replace=False)
            with self.assertRaisesRegex(MemoryError, "file_copy_output_exists_without_journal"):
                raw_copy.resumable_copy(old_source, unknown, root / "unknown.json")
            self.assertEqual(unknown.read_bytes(), b"keep these unrelated bytes")


if __name__ == "__main__":
    unittest.main()
