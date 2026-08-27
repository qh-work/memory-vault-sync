from __future__ import annotations

import json
import tempfile
import unittest
import zipfile
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = PLUGIN_ROOT / "scripts"
import sys

if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from memory_vault_runtime import checkpoint, packs, transport  # noqa: E402
from memory_vault_runtime.protocol import jcs_json_bytes  # noqa: E402


class PackTests(unittest.TestCase):
    def test_pack_round_trip_has_independent_hashes_and_index(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pack_path = root / "network.memory-pack"
            writer = packs.PackWriter(pack_path)
            writer.add("memory/episodes/aa/ep-a.json", b'{"episode":1}')
            writer.add("memory/events/aa/evt-a.json", b'{"event":1}')
            writer.finish()
            with packs.PackReader(pack_path) as reader:
                summary = reader.verify()
                objects = [(entry.path, raw) for entry, raw in reader.iter_objects()]
            self.assertEqual(summary.object_count, 2)
            self.assertEqual(summary.raw_bytes, 24)
            self.assertRegex(summary.sha256, r"^[0-9a-f]{64}$")
            self.assertRegex(summary.object_root_sha256, r"^[0-9a-f]{64}$")
            self.assertEqual(objects[0][0], "memory/episodes/aa/ep-a.json")

    def test_pack_zip_streaming_round_trip_and_tamper_rejection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.zip"
            with zipfile.ZipFile(source, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("memory/episodes/aa/ep-a.json", b"episode")
                archive.writestr("memory/events/aa/evt-a.json", b"event")
            pack_path = root / "source.memory-pack"
            summary = packs.pack_zip_archive(source, pack_path)
            restored = root / "restored.zip"
            restored_summary = packs.unpack_to_zip(pack_path, restored)
            self.assertEqual(summary.sha256, restored_summary.sha256)
            with zipfile.ZipFile(restored) as archive:
                self.assertEqual(archive.read("memory/events/aa/evt-a.json"), b"event")
            raw = bytearray(pack_path.read_bytes())
            raw[len(packs.MAGIC) + 4] ^= 1
            pack_path.write_bytes(raw)
            with self.assertRaises(packs.PackError):
                with packs.PackReader(pack_path) as reader:
                    reader.verify()

    def test_pack_rejects_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            writer = packs.PackWriter(Path(temporary) / "bad.pack")
            with self.assertRaises(packs.PackError):
                writer.add("../escape", b"bad")
            writer.abort()


class TransportTests(unittest.TestCase):
    def test_resumable_copy_journals_progress_and_resumes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.pack"
            destination = root / "received.pack"
            journal = root / "publish.journal"
            source.write_bytes(bytes(range(256)) * 9000)
            with self.assertRaises(transport.TransportInterrupted):
                transport.resumable_copy(
                    source,
                    destination,
                    journal,
                    interrupt_after_bytes=1_100_000,
                )
            resumed = transport.resumable_copy(source, destination, journal)
            self.assertTrue(resumed.resumed)
            self.assertTrue(resumed.complete)
            self.assertEqual(source.read_bytes(), destination.read_bytes())
            state = json.loads(journal.read_text())
            self.assertTrue(state["complete"])
            with self.assertRaises(transport.TransportError):
                transport.resumable_copy(root / "missing", destination, journal)


class CheckpointTests(unittest.TestCase):
    def test_checkpoint_chain_is_canonical_and_monotonic(self) -> None:
        first = checkpoint.build_checkpoint(
            object_root_sha256="a" * 64,
            remote_commit_sha="b" * 40,
            generation=1,
            object_count=2,
        )
        second = checkpoint.build_checkpoint(
            object_root_sha256="c" * 64,
            remote_commit_sha="d" * 40,
            generation=2,
            object_count=3,
            previous_checkpoint_sha256=first["checkpoint_sha256"],
        )
        self.assertEqual(checkpoint.verify_checkpoint(first), first)
        chain = checkpoint.verify_chain(
            [first, second],
            trusted_checkpoint_sha256=first["checkpoint_sha256"],
        )
        self.assertEqual(len(chain), 2)
        tampered = dict(second)
        tampered["object_count"] = 4
        with self.assertRaises(checkpoint.CheckpointError):
            checkpoint.verify_checkpoint(tampered)
        with self.assertRaises(checkpoint.CheckpointError):
            checkpoint.verify_chain([second], trusted_checkpoint_sha256=first["checkpoint_sha256"])

    def test_checkpoint_domain_binds_pack_root_and_commit(self) -> None:
        value = checkpoint.build_checkpoint(
            object_root_sha256="e" * 64,
            remote_commit_sha="f" * 40,
            generation=7,
            object_count=99,
        )
        self.assertEqual(
            value["checkpoint_sha256"],
            __import__("hashlib").sha256(
                jcs_json_bytes({k: v for k, v in value.items() if k != "checkpoint_sha256"})
            ).hexdigest(),
        )


if __name__ == "__main__":
    unittest.main()
