"""Minimal synthetic transport publication cases; execution recorded separately.

Every writable path belongs to this case's TemporaryDirectory. Three bounded
children of the current interpreter, across two methods, exit immediately
after a real publication syscall. They do not use a Vault, key, plugin, remote
provider, account or host configuration. These are process-interruption cases,
not power-loss durability, signed-sync acceptance or Windows certification.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import memory_vault_pack as packs
import memory_vault_storage as storage
import memory_vault_transfer as transfer
from memory_vault import MemoryError


@unittest.skipUnless(sys.platform == "darwin" or sys.platform.startswith("linux"),
                     "requires an authorized macOS/Linux synthetic directory fixture")
class TransportPublicationTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="memory-v025-transport-publication-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    def _interrupt_after_publication(self, mode: str, target: Path) -> None:
        # Both hooks perform the real syscall first. The link hook exposes the
        # old implementation's exact crash window; the rename hook interrupts
        # the replacement path at the corresponding point, before receipts.
        program = r'''
import os, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import memory_vault_pack as packs
import memory_vault_storage as storage
import memory_vault_transfer as transfer
root, mode, target = Path(sys.argv[2]), sys.argv[3], Path(sys.argv[4])
assert target.is_relative_to(root)
original_link = os.link
original_rename = storage._rename_no_replace
def interrupted_link(source, destination, *args, **kwargs):
    original_link(source, destination, *args, **kwargs)
    if Path(destination) == target:
        os._exit(73)
def interrupted_rename(source, destination):
    original_rename(source, destination)
    if Path(destination) == target:
        os._exit(73)
os.link = interrupted_link
storage._rename_no_replace = interrupted_rename
if mode == "transfer":
    transfer._write(target, {"synthetic": "pending publication"}, replace=False)
elif mode == "copy":
    packs.copy(root / "source-pack", root / "copy-pack", maximum_chunks=1)
elif mode == "unpack":
    packs.unpack(root / "copy-pack", target)
else:
    raise SystemExit("unknown fixed synthetic mode")
raise SystemExit("publication interruption point was not reached")
'''
        child = subprocess.run(
            [sys.executable, "-I", "-B", "-c", program, str(ROOT), str(self.root), mode, str(target)],
            cwd=self.root, env={"PYTHONDONTWRITEBYTECODE": "1"},
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(child.returncode, 73, child.stderr)

    def test_transfer_pending_publication_survives_process_exit_and_exact_retry(self) -> None:
        target = self.root / "publish.pending.json"
        payload = {"synthetic": "pending publication"}
        self._interrupt_after_publication("transfer", target)
        self.assertEqual(target.stat().st_nlink, 1, "publication stranded a private hard-link alias")
        self.assertEqual(transfer._read(target, private=True), payload)
        before, inode = target.read_bytes(), target.stat().st_ino
        transfer._write(target, payload, replace=False)
        self.assertEqual(target.read_bytes(), before)
        self.assertEqual(target.stat().st_ino, inode)
        with self.assertRaises(MemoryError) as conflict:
            transfer._write(target, {"synthetic": "different pending publication"}, replace=False)
        self.assertEqual(conflict.exception.code, "transfer_output_conflict")
        self.assertEqual(target.read_bytes(), before)
        self.assertEqual(list(self.root.iterdir()), [target])

    def test_pack_copy_and_unpack_survive_process_exit_without_hard_link_aliases(self) -> None:
        data = b"Synthetic portable pack publication.\x00\n"
        source = self.root / "source.bin"
        storage.atomic_write(source, data, replace=False)
        original, copied = self.root / "source-pack", self.root / "copy-pack"
        self.assertEqual(packs.create(source, original)["chunks"], 1)
        manifest, _ = packs._manifest(original)
        target = packs._chunk_path(copied, manifest["chunks"][0])
        self._interrupt_after_publication("copy", target)
        self.assertEqual(target.stat().st_nlink, 1)
        self.assertEqual(list(target.parent.iterdir()), [target])
        self.assertEqual(transfer._read(copied / "COPY_STATE.json", private=True)["verified"], {})
        self.assertFalse((copied / "MANIFEST.json").exists())
        resumed = packs.copy(original, copied, maximum_chunks=1)
        self.assertEqual(resumed["state"], "copy_complete")
        self.assertEqual(resumed["copied_chunks"], 0, "the already published chunk must be verified, not replaced")
        self.assertEqual(resumed["chunks_checked_this_run"], 1)
        replay = packs.copy(original, copied, maximum_chunks=1)
        self.assertEqual(replay["unchanged_chunks_skipped"], 1)
        self.assertEqual(replay["chunks_checked_this_run"], 0)

        unpacked = self.root / "unpacked.bin"
        self._interrupt_after_publication("unpack", unpacked)
        self.assertEqual(unpacked.stat().st_nlink, 1)
        self.assertEqual(packs._read(unpacked, len(data)), data)
        self.assertFalse(any(path.name.startswith(".memory-unpack-") for path in self.root.iterdir()))
        with self.assertRaises(MemoryError) as existing:
            packs.unpack(copied, unpacked)
        self.assertEqual(existing.exception.code, "pack_unpack_requires_new_external_file")
        self.assertEqual(unpacked.read_bytes(), data)
        self.assertEqual(source.read_bytes(), data)

    def test_exact_overlap_no_clobber_and_storage_errors_remain_explicit(self) -> None:
        target = self.root / "concurrent.json"
        payload = {"synthetic": "same immutable bytes"}
        barrier = threading.Barrier(2)
        original = storage._rename_no_replace

        def synchronized(source: Path, destination: Path) -> None:
            if destination == target:
                barrier.wait(timeout=5)
            original(source, destination)

        with mock.patch.object(storage, "_rename_no_replace", side_effect=synchronized), \
                ThreadPoolExecutor(max_workers=2) as workers:
            futures = [workers.submit(transfer._write, target, payload, replace=False) for _ in range(2)]
            self.assertEqual([future.result(timeout=10) for future in futures], [None, None])
        self.assertEqual(target.stat().st_nlink, 1)
        before = target.read_bytes()
        with self.assertRaises(FileExistsError):
            packs._new_bytes(target, b"must not overwrite JSON")
        self.assertEqual(target.read_bytes(), before)
        transfer._write(target, {"synthetic": "explicit private replacement"}, replace=True)
        self.assertEqual(transfer._read(target, private=True), {"synthetic": "explicit private replacement"})

        fragment = self.root / "private-fragment.ndjson"
        transfer._write_fragment(fragment, b"synthetic fragment\n")
        transfer._write_fragment(fragment, b"synthetic fragment\n")
        with self.assertRaises(MemoryError) as conflict:
            transfer._write_fragment(fragment, b"different fragment\n")
        self.assertEqual(conflict.exception.code, "group_fragment_conflict")
        self.assertEqual(fragment.read_bytes(), b"synthetic fragment\n")

        alias = self.root / "synthetic-alias.ndjson"
        os.link(fragment, alias)
        with self.assertRaises(MemoryError) as unsafe:
            transfer._write_fragment(fragment, b"synthetic fragment\n")
        self.assertEqual(unsafe.exception.code, "unsafe_storage_file")
        self.assertEqual(fragment.stat().st_nlink, 2, "an existing alias must not be silently repaired")

        source = self.root / "failure-source.bin"
        storage.atomic_write(source, b"synthetic failure case", replace=False)
        pack = self.root / "failure-source-pack"
        packs.create(source, pack)
        destinations = [self.root / name for name in (
            "unavailable.json", "unavailable.ndjson", "unavailable.bin", "unavailable-unpack.bin",
        )]
        writers = (
            lambda: transfer._write(destinations[0], {"synthetic": True}, replace=False),
            lambda: transfer._write_fragment(destinations[1], b"synthetic fragment\n"),
            lambda: packs._new_bytes(destinations[2], b"synthetic pack chunk"),
            lambda: packs.unpack(pack, destinations[3]),
        )
        with mock.patch.object(storage, "_rename_no_replace", side_effect=storage.StorageError("atomic_no_replace_unavailable")), \
                mock.patch.object(os, "link", side_effect=AssertionError("hard-link fallback forbidden")), \
                mock.patch.object(os, "replace", side_effect=AssertionError("overwrite fallback forbidden")):
            for writer, destination in zip(writers, destinations):
                with self.subTest(destination=destination.name):
                    with self.assertRaises(MemoryError) as unavailable:
                        writer()
                    self.assertEqual(unavailable.exception.code, "atomic_no_replace_unavailable")
                    self.assertFalse(unavailable.exception.retryable)
                    self.assertFalse(destination.exists())
        prefixes = (".vault-", ".fragment-", ".pack-write-", ".memory-unpack-")
        self.assertFalse(any(path.name.startswith(prefixes) for path in self.root.iterdir()))

    def test_explicit_shared_outputs_keep_permissions_and_exact_retry(self) -> None:
        data = b"synthetic selected export\n"
        source = self.root / "shared-source.bin"
        storage.atomic_write(source, data, replace=False)
        pack = self.root / "shared-source-pack"
        packs.create(source, pack)
        for mode in (0o755, 0o775):
            with self.subTest(mode=oct(mode)):
                shared = self.root / f"shared-{mode:o}"
                shared.mkdir(mode=0o700)
                shared.chmod(mode)  # Only this case's disposable synthetic path.
                capsule = shared / "existing.json"
                raw = b'{ "synthetic": "shared fixture" }\n'
                capsule.write_bytes(raw)
                capsule.chmod(0o644)
                inode = capsule.stat().st_ino
                transfer._write(capsule, {"synthetic": "shared fixture"}, replace=False, private=False)
                self.assertEqual(capsule.read_bytes(), raw)
                self.assertEqual(capsule.stat().st_ino, inode)
                self.assertEqual(stat.S_IMODE(capsule.stat().st_mode), 0o644)
                with self.assertRaises(MemoryError) as conflict:
                    transfer._write(capsule, {"synthetic": "different fixture"}, replace=False, private=False)
                self.assertEqual(conflict.exception.code, "transfer_output_conflict")
                with self.assertRaises(MemoryError) as private:
                    transfer._write(capsule, {"synthetic": "shared fixture"}, replace=False)
                self.assertEqual(private.exception.code, "unprotected_private_directory")
                with self.assertRaises(MemoryError) as replacement:
                    transfer._write(capsule, {"synthetic": "must not replace"}, replace=True, private=False)
                self.assertEqual(replacement.exception.code, "invalid_transfer_publication_profile")

                fresh = shared / "new.json"
                transfer._write(fresh, {"synthetic": "new shared output"}, replace=False, private=False)
                self.assertEqual(fresh.stat().st_nlink, 1)
                self.assertEqual(stat.S_IMODE(fresh.stat().st_mode), 0o600)
                fragment = shared / "existing.ndjson"
                fragment.write_bytes(b"synthetic shared fragment\n")
                fragment.chmod(0o644)
                transfer._write_fragment(fragment, b"synthetic shared fragment\n", private=False)
                self.assertEqual(stat.S_IMODE(fragment.stat().st_mode), 0o644)
                with self.assertRaises(MemoryError) as fragment_conflict:
                    transfer._write_fragment(fragment, b"different fragment\n", private=False)
                self.assertEqual(fragment_conflict.exception.code, "group_fragment_conflict")
                self.assertEqual(fragment.read_bytes(), b"synthetic shared fragment\n")
                fresh_fragment = shared / "new.ndjson"
                transfer._write_fragment(fresh_fragment, b"new synthetic shared fragment\n", private=False)
                self.assertEqual(fresh_fragment.stat().st_nlink, 1)
                self.assertEqual(stat.S_IMODE(fresh_fragment.stat().st_mode), 0o600)

                unpacked = shared / "unpacked.bin"
                self.assertEqual(packs.unpack(pack, unpacked)["state"], "unpacked_not_imported")
                self.assertEqual(unpacked.read_bytes(), data)
                self.assertEqual(unpacked.stat().st_nlink, 1)
                self.assertEqual(stat.S_IMODE(unpacked.stat().st_mode), 0o600)
                self.assertEqual(capsule.read_bytes(), raw)
                self.assertEqual(stat.S_IMODE(capsule.stat().st_mode), 0o644)
                self.assertEqual(stat.S_IMODE(shared.stat().st_mode), mode)


if __name__ == "__main__":
    unittest.main()
