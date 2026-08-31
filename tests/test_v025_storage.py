"""Synthetic native-storage contracts for independent reviewers.

These tests were authored, not executed during development. Pure ACL/path
cases need no OS changes. Windows integration cases create only their own
temporary synthetic files, never real keys, provider accounts or user Vaults.
"""
from __future__ import annotations

import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from memory_vault_storage import (
    StorageError, _acl_allowed, _windows_path, atomic_write, check_fd,
    check_private_directory, file_lock, open_file, private_directory, publish_file,
)


USER = "S-1-5-21-111-222-333-1001"
OTHER = "S-1-5-21-111-222-333-1002"
SYSTEM = "S-1-5-18"
FULL = 0x001F01FF
READ = 0x00120089


class NativePolicyTests(unittest.TestCase):
    def test_only_local_unambiguous_windows_names(self) -> None:
        self.assertEqual(_windows_path(r"C:\Users\Synthetic\vault\state.json"), r"C:\Users\Synthetic\vault\state.json")
        for value in (r"\\server\share\state.json", r"\\?\C:\private\state.json", r"C:relative.json",
                      r"C:\private\state.json:secret", r"C:\private\..\other.json", r"C:\private\.\state.json",
                      r"C:\private\NUL.txt", r"C:\private\COM¹", r"C:\private\CONOUT$", "C:\\private\\trailing. "):
            with self.subTest(value=value), self.assertRaises(StorageError):
                _windows_path(value)

    def test_private_acl_does_not_accept_other_user_read_or_write(self) -> None:
        safe = [(0, 3, FULL, USER), (0, 3, FULL, SYSTEM)]
        self.assertTrue(_acl_allowed(USER, USER, safe, private=True, directory=True))
        self.assertFalse(_acl_allowed(OTHER, USER, safe, private=True, directory=True))
        for rights in (READ, FULL, 0x10000, 0x40000, 0x80000):
            self.assertFalse(_acl_allowed(USER, USER, safe + [(0, 0, rights, OTHER)], private=True, directory=False))

    def test_inherited_child_access_is_checked_for_private_sqlite_parent(self) -> None:
        safe = [(0, 3, FULL, USER), (0, 3, FULL, SYSTEM)]
        # Inherit-only broad access is harmless to this file, but must not be
        # allowed to make future database sidecars readable to another user.
        self.assertFalse(_acl_allowed(USER, USER, safe + [(0, 0x0B, READ, OTHER)], private=True, directory=True))
        self.assertTrue(_acl_allowed(USER, USER, safe + [(0, 0x0B, FULL, "S-1-3-0")], private=True, directory=True))

    def test_trusted_executable_can_be_read_but_not_changed_by_others(self) -> None:
        base = [(0, 0, FULL, USER)]
        self.assertTrue(_acl_allowed(USER, USER, base + [(0, 0, READ, OTHER)], private=False, directory=False))
        for rights in (2, 4, 16, 64, 256, 0x10000, 0x40000, 0x80000, 0x40000000, 0x10000000):
            self.assertFalse(_acl_allowed(USER, USER, base + [(0, 0, rights, OTHER)], private=False, directory=False))
        self.assertTrue(_acl_allowed(SYSTEM, USER, [(0, 0, 4, OTHER)], private=False, directory=True, ancestor=True))
        self.assertFalse(_acl_allowed(SYSTEM, USER, [(0, 0, 64, OTHER)], private=False, directory=True, ancestor=True))

    def test_unknown_ace_or_flags_fail_closed_even_with_zero_access_mask(self) -> None:
        for entry in ((5, 0, 0, USER), (9, 0, 0, USER), (0, 0x80, 0, USER)):
            self.assertFalse(_acl_allowed(USER, USER, [entry], private=True, directory=False))

    def test_windows_trust_cache_uses_checked_native_file_not_posix_mode_bits(self) -> None:
        import memory_vault_trust as trust
        registry = trust.TrustStore(ROOT / "synthetic-trust-file-never-created.json")
        info = SimpleNamespace(st_dev=1, st_ino=2, st_mtime_ns=3, st_ctime_ns=4, st_size=5)
        with (mock.patch.object(trust.os, "name", "nt"),
              mock.patch.object(trust, "_safe_parent", return_value=True),
              mock.patch.object(trust, "_open_existing", return_value=123) as opened,
              mock.patch.object(trust.os, "fstat", return_value=info),
              mock.patch.object(trust.os, "close") as closed,
              mock.patch.object(trust, "_check_file", side_effect=AssertionError("POSIX check reached Windows"))):
            self.assertEqual(registry._snapshot_token(), (1, 2, 3, 4, 5))
        opened.assert_called_once_with(registry.path, os.O_RDONLY)
        closed.assert_called_once_with(123)


@unittest.skipUnless(os.name == "posix", "POSIX private creation contract")
class PosixStorageCreationTests(unittest.TestCase):
    def test_all_new_private_ancestors_receive_private_modes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="memory-vault-posix-synthetic-") as name:
            root = Path(name).resolve()
            prior_mode = stat.S_IMODE(root.stat().st_mode)
            leaf = root / "new-control" / "nested" / "private"
            private_directory(leaf)
            for path in (leaf, leaf.parent, leaf.parent.parent):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(root.stat().st_mode), prior_mode)


@unittest.skipUnless(os.name == "nt", "requires an independently authorized native Windows run")
class WindowsStorageIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="memory-vault-native-synthetic-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "private"
        private_directory(self.root)

    def test_native_created_private_file_has_checked_acl_and_is_not_inheritable(self) -> None:
        check_private_directory(self.root)
        path = self.root / "synthetic.json"
        fd = open_file(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, private=True)
        try:
            check_fd(fd, private=True)
            self.assertFalse(os.get_inheritable(fd))
            os.write(fd, b'{"synthetic":true}\n')
            os.fsync(fd)
        finally:
            os.close(fd)
        read = open_file(path, os.O_RDONLY, private=True)
        try:
            self.assertEqual(os.read(read, 128), b'{"synthetic":true}\n')
        finally:
            os.close(read)

    def test_atomic_no_clobber_and_streaming_publish(self) -> None:
        path = self.root / "state.json"
        atomic_write(path, b"first\n", replace=False)
        with self.assertRaises(FileExistsError):
            atomic_write(path, b"second\n", replace=False)
        self.assertEqual(path.read_bytes(), b"first\n")
        temporary = self.root / "prepared.tmp"
        atomic_write(temporary, b"synthetic streaming archive\n", replace=False)
        publish_file(temporary, path, replace=True)
        self.assertFalse(temporary.exists())
        self.assertEqual(path.read_bytes(), b"synthetic streaming archive\n")

    def test_native_lock_is_nonblocking_and_does_not_create_read_only_target(self) -> None:
        path = self.root / "sync.lock"
        with file_lock(path):
            with self.assertRaises(StorageError) as conflict:
                with file_lock(path, create=False, busy_code="synthetic_lock_busy"):
                    self.fail("exclusive lock unexpectedly entered")
            self.assertEqual(conflict.exception.code, "synthetic_lock_busy")
        missing = self.root / "absent.lock"
        with self.assertRaises(FileNotFoundError):
            with file_lock(missing, create=False):
                self.fail("missing read-only lock unexpectedly entered")
        self.assertFalse(missing.exists())

    def test_hardlinked_private_file_is_rejected(self) -> None:
        path = self.root / "original.json"
        atomic_write(path, b"synthetic fixture\n", replace=False)
        os.link(path, self.root / "alias.json")
        with self.assertRaises(StorageError):
            open_file(path, os.O_RDONLY, private=True)


if __name__ == "__main__":
    unittest.main()
