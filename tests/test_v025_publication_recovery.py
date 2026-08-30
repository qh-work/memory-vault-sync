"""Small synthetic publication regressions; execution is recorded separately.

Only disposable private directories are used. One bounded child of the current
Python interpreter exits at the directory-fsync boundary; no existing process,
plugin, account, key or Vault is accessed. This is not a power-loss experiment
or a native Windows/Linux certification.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import memory_vault_client as client
import memory_vault_storage as storage
from memory_vault import MemoryError


@unittest.skipUnless(sys.platform == "darwin" or sys.platform.startswith("linux"),
                     "requires an authorized macOS/Linux private-directory fixture")
class PublicationRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="memory-v025-publication-synthetic-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.config = client.ClientConfig(self.root / "client.json", self.root / "unused-vault.sqlite3", True)

    def test_client_publication_survives_process_exit_without_hard_link_alias(self) -> None:
        key = "a" * 64
        state = client.HookState(self.config)
        destination = state.path("prompts", key)
        # The old link/fsync/unlink sequence exits with two names for one inode.
        # An exclusive rename has consumed the temporary name at this point.
        program = r'''
import os, stat, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import memory_vault_client as client
root = Path(sys.argv[2])
config = client.ClientConfig(root / "client.json", root / "unused-vault.sqlite3", True)
state = client.HookState(config)
target = state.path("prompts", "a" * 64)
original_fsync = os.fsync
def exit_after_publication(descriptor):
    original_fsync(descriptor)
    if stat.S_ISDIR(os.fstat(descriptor).st_mode) and target.exists():
        os._exit(73)
os.fsync = exit_after_publication
state.once("prompts", "a" * 64, {"user": "Synthetic interrupted publication."})
raise SystemExit("publication interruption point was not reached")
'''
        child = subprocess.run(
            [sys.executable, "-I", "-B", "-c", program, str(ROOT), str(self.root)],
            cwd=self.root, env={"PYTHONDONTWRITEBYTECODE": "1"},
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(child.returncode, 73, child.stderr)
        self.assertEqual(destination.stat().st_nlink, 1, "interrupted publication left a hard-link alias")
        self.assertEqual(client._read_json(destination), {
            "schema_version": client.STATE_SCHEMA, "user": "Synthetic interrupted publication.",
        })
        before = destination.read_bytes()
        state.once("prompts", key, {"user": "Synthetic interrupted publication."})
        self.assertEqual(destination.read_bytes(), before)
        self.assertEqual(list(destination.parent.iterdir()), [destination])
        self.assertFalse(self.config.vault_path.exists())

    def test_no_clobber_concurrency_exact_retry_and_alias_checks_remain(self) -> None:
        state = client.HookState(self.config)
        key = "b" * 64
        state.once("prompts", key, {"user": "Synthetic original."})
        destination = state.path("prompts", key)
        before = destination.read_bytes()
        state.once("prompts", key, {"user": "Synthetic original."})
        with self.assertRaises(MemoryError) as conflict:
            state.once("prompts", key, {"user": "Different synthetic prompt."})
        self.assertEqual(conflict.exception.code, "hook_event_conflict")
        self.assertEqual(destination.read_bytes(), before)

        race = self.root / "race.json"
        barrier = threading.Barrier(2)
        original = storage._rename_no_replace
        def synchronized(source, target):
            barrier.wait(timeout=5)
            return original(source, target)
        def publish(payload):
            try:
                storage.atomic_write(race, payload, replace=False)
                return "published"
            except FileExistsError:
                return "exists"
        with mock.patch.object(storage, "_rename_no_replace", side_effect=synchronized), \
                ThreadPoolExecutor(max_workers=2) as workers:
            futures = [workers.submit(publish, payload) for payload in (b"first", b"second")]
            self.assertEqual(sorted(item.result(timeout=10) for item in futures), ["exists", "published"])
        self.assertIn(race.read_bytes(), {b"first", b"second"})
        self.assertEqual(race.stat().st_nlink, 1)
        storage.atomic_write(race, b"explicit replacement", replace=True)
        self.assertEqual(race.read_bytes(), b"explicit replacement")

        alias = self.root / "synthetic-hard-link.json"
        os.link(destination, alias)
        with self.assertRaises(MemoryError) as unsafe:
            client._read_json(destination)
        self.assertEqual(unsafe.exception.code, "unsafe_client_file")
        with self.assertRaises(storage.StorageError):
            storage.atomic_write(alias, b"must not overwrite", replace=False)
        symbolic = self.root / "synthetic-symbolic-link.json"
        symbolic.symlink_to(race)
        with self.assertRaises(storage.StorageError):
            storage.atomic_write(symbolic, b"must not overwrite", replace=False)
        self.assertEqual(destination.read_bytes(), before)
        self.assertEqual(race.read_bytes(), b"explicit replacement")

    def test_unsupported_native_rename_has_no_unsafe_publication_fallback(self) -> None:
        temporary = self.root / "source.tmp"
        destination = self.root / "not-published.json"
        storage.atomic_write(temporary, b"complete synthetic bytes", replace=False)
        with mock.patch.object(storage, "_rename_no_replace", side_effect=storage.StorageError("atomic_no_replace_unavailable")), \
                mock.patch.object(storage.os, "link", side_effect=AssertionError("hard-link fallback forbidden")), \
                mock.patch.object(storage.os, "replace", side_effect=AssertionError("overwrite fallback forbidden")):
            with self.assertRaises(storage.StorageError) as unavailable:
                storage.publish_file(temporary, destination, replace=False)
        self.assertEqual(unavailable.exception.code, "atomic_no_replace_unavailable")
        self.assertEqual(temporary.read_bytes(), b"complete synthetic bytes")
        self.assertEqual(temporary.stat().st_nlink, 1)
        self.assertFalse(destination.exists())
        with mock.patch.object(storage, "_rename_no_replace", side_effect=storage.StorageError("atomic_no_replace_unavailable")):
            with self.assertRaises(MemoryError) as client_error:
                client._write_once(destination, {"synthetic": True})
        self.assertEqual(client_error.exception.code, "atomic_no_replace_unavailable")
        self.assertFalse(client_error.exception.retryable)
        self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
