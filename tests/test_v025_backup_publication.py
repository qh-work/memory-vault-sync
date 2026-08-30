"""Disposable backup/migration publication regressions; execution tracked separately.

These cases use fixture bytes, not a Vault, database, legacy archive, provider,
key, account or host. In-process exceptions observe publication boundaries; no
child is started, and this is not a power-loss or native Windows certification.
"""

from __future__ import annotations

import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import memory_vault_backup as backup
import memory_vault_migrate as migrate
import memory_vault_storage as storage
from memory_vault import MemoryError


class InterruptedAfterPublication(BaseException):
    """Stop immediately after a synthetic file's publication syscall."""


@unittest.skipUnless(sys.platform == "darwin" or sys.platform.startswith("linux"),
                     "requires an authorized macOS/Linux temporary-directory fixture")
class BackupPublicationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="memory-v025-backup-publication-synthetic-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()

    def fixture(self, path: Path, value: bytes) -> Path:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        return path

    def test_backup_publication_interruption_leaves_one_private_file_in_0755_parent(self) -> None:
        os.chmod(self.root, 0o755)
        source = self.fixture(self.root / "staged.tmp", b"synthetic backup bytes\n")
        destination = self.root / "snapshot.bin"
        observations = []
        original_rename = storage._rename_no_replace
        original_link = os.link

        def interrupt_after_rename(temporary, target):
            original_rename(temporary, target)
            observations.append((destination.stat().st_nlink, source.exists()))
            raise InterruptedAfterPublication()

        def interrupt_after_legacy_link(temporary, target, **options):
            # On the old code this captures the two names before unlink could
            # run. The fixed publisher never invokes this legacy operation.
            original_link(temporary, target, **options)
            observations.append((destination.stat().st_nlink, source.exists()))
            raise InterruptedAfterPublication()

        with mock.patch.object(storage, "_rename_no_replace", side_effect=interrupt_after_rename), \
                mock.patch.object(os, "link", side_effect=interrupt_after_legacy_link):
            with self.assertRaises(InterruptedAfterPublication):
                backup._publish_file(source, destination)

        self.assertEqual(observations, [(1, False)])
        self.assertEqual(backup.regular(destination).st_nlink, 1)
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o755)
        self.assertEqual(destination.read_bytes(), b"synthetic backup bytes\n")
        self.assertFalse(source.exists())

    def test_pair_0755_contract_and_rollback_after_each_directory_fsync_failure(self) -> None:
        os.chmod(self.root, 0o755)
        nominal_output, nominal_report = self.root / "nominal.ndjson", self.root / "nominal-report.json"
        migrate._publish_pair(nominal_output, nominal_report, [b"synthetic bundle\n"], b"synthetic report\n")
        for path, expected in ((nominal_output, b"synthetic bundle\n"), (nominal_report, b"synthetic report\n")):
            self.assertEqual(path.read_bytes(), expected)
            self.assertEqual(path.stat().st_nlink, 1)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

        for fail_at in (1, 2):
            with self.subTest(directory_fsync=fail_at):
                output = self.root / ("failed-" + str(fail_at) + ".ndjson")
                report = self.root / ("failed-" + str(fail_at) + "-report.json")
                observed = []
                original_fsync = os.fsync

                def fail_after_move(descriptor):
                    original_fsync(descriptor)
                    if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                        observed.append((report.exists(), output.exists()))
                        self.assertEqual(report.stat().st_nlink, 1)
                        if output.exists():
                            self.assertEqual(output.stat().st_nlink, 1)
                        if len(observed) == fail_at:
                            raise OSError("synthetic directory fsync failure")

                with mock.patch.object(os, "fsync", side_effect=fail_after_move):
                    with self.assertRaisesRegex(OSError, "synthetic directory fsync failure"):
                        migrate._publish_pair(output, report, [b"synthetic pending bundle\n"], b"synthetic pending report\n")

                self.assertEqual(observed, [(True, False)] if fail_at == 1 else [(True, False), (True, True)])
                self.assertFalse(output.exists())
                self.assertFalse(report.exists())
                self.assertEqual(list(self.root.glob(".memory-migration-*")), [])
        self.assertEqual(nominal_output.read_bytes(), b"synthetic bundle\n")
        self.assertEqual(nominal_report.read_bytes(), b"synthetic report\n")
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o755)

    def test_existing_outputs_keep_error_domains_and_old_aliases(self) -> None:
        source = self.fixture(self.root / "source.tmp", b"synthetic new bytes")
        destination = self.fixture(self.root / "existing.bin", b"synthetic prior bytes")
        alias = self.root / "prior-alias.bin"
        os.link(destination, alias)
        os.chmod(destination, 0o644)
        with self.assertRaises(MemoryError) as existing:
            backup._publish_file(source, destination)
        self.assertEqual(existing.exception.code, "backup_output_exists")
        self.assertEqual(source.read_bytes(), b"synthetic new bytes")
        self.assertEqual(destination.read_bytes(), b"synthetic prior bytes")
        self.assertEqual(destination.stat().st_nlink, 2)

        output, report = self.root / "output.ndjson", self.fixture(self.root / "existing-report.json", b"prior report")
        report_alias = self.root / "prior-report-alias.json"
        os.link(report, report_alias)
        with self.assertRaises(migrate.MigrationError) as collision:
            migrate._publish_pair(output, report, [b"new bundle"], b"new report")
        self.assertEqual(collision.exception.code, "output_exists")
        self.assertFalse(output.exists())
        self.assertEqual(report.read_bytes(), b"prior report")
        self.assertEqual(report.stat().st_nlink, 2)
        self.assertEqual(list(self.root.glob(".memory-migration-*")), [])

    def test_pair_failure_preserves_competing_targets_and_aliased_owned_report(self) -> None:
        original_publish = storage.publish_file
        for scenario in ("competing-output", "replaced-report", "aliased-report"):
            with self.subTest(scenario=scenario):
                directory = self.root / scenario
                directory.mkdir(mode=0o700)
                output, report = directory / "output.ndjson", directory / "report.json"
                alias = directory / "report-alias.json"

                def fail_second(temporary, destination, **options):
                    if destination != output:
                        return original_publish(temporary, destination, **options)
                    if scenario == "competing-output":
                        self.fixture(output, b"competing output")
                        raise FileExistsError("synthetic output collision")
                    if scenario == "replaced-report":
                        replacement = self.fixture(directory / "replacement.tmp", b"competing report")
                        os.replace(replacement, report)
                    else:
                        os.link(report, alias)
                    raise OSError("synthetic second publication failure")

                with mock.patch.object(storage, "publish_file", side_effect=fail_second):
                    with self.assertRaises((migrate.MigrationError, OSError)):
                        migrate._publish_pair(output, report, [b"owned bundle"], b"owned report")
                if scenario == "competing-output":
                    self.assertEqual(output.read_bytes(), b"competing output")
                    self.assertFalse(report.exists())
                elif scenario == "replaced-report":
                    self.assertEqual(report.read_bytes(), b"competing report")
                    self.assertFalse(output.exists())
                else:
                    self.assertEqual(report.read_bytes(), b"owned report")
                    self.assertEqual(alias.read_bytes(), b"owned report")
                    self.assertEqual(report.stat().st_nlink, 2)
                    self.assertFalse(output.exists())
                self.assertEqual(list(directory.glob(".memory-migration-*")), [])


if __name__ == "__main__":
    unittest.main()
