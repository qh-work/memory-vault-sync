"""Synthetic portable pack/migration cases; authored, NOT executed.

Native cases run only when a reviewer explicitly runs them on Windows. All
files are synthetic and confined to each case's own temporary directory; no
real Vault, signing key, provider configuration or native host state is read.
"""
from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
for directory in (ROOT, Path(__file__).resolve().parent):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

import memory_vault_migrate as migrate
import memory_vault_pack as packs
import memory_vault_storage as storage
from memory_vault import MemoryError
from test_v025_legacy_pack import document_files, episode


class _PackFixtures:
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="memory-vault-portable-packs-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve() / "private"
        storage.private_directory(self.root)

    def source_zip(self, name: str = "synthetic-old.zip") -> Path:
        path = self.root / name
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for member, raw in document_files([episode(1)]).items():
                archive.writestr(member, raw)
        return path


@unittest.skipUnless(os.name in {"nt", "posix"}, "protected platform profile required")
class PortablePackTests(_PackFixtures, unittest.TestCase):
    def test_resumable_file_profile_preserves_bytes_and_existing_outputs(self) -> None:
        data = b"A" * packs.CHUNK_BYTES + b"synthetic second chunk\x00\n"
        source = self.root / "source.bin"
        storage.atomic_write(source, data, replace=False)
        original, copied, output = self.root / "original", self.root / "copied", self.root / "unpacked.bin"
        self.assertEqual(packs.create(source, original)["chunks"], 2)
        self.assertEqual(packs.copy(original, copied, maximum_chunks=1)["state"], "copy_pending_repeat_same_command")
        self.assertFalse((copied / "MANIFEST.json").exists())
        self.assertEqual(packs.copy(original, copied, maximum_chunks=1)["state"], "copy_complete")
        self.assertEqual(packs.unpack(copied, output)["state"], "unpacked_not_imported")
        self.assertEqual(output.read_bytes(), data)
        with self.assertRaises((MemoryError, FileExistsError)):
            packs.unpack(copied, output)
        self.assertEqual(output.read_bytes(), data)
        self.assertEqual(packs.MAX_SOURCE_BYTES, 2 * 1024 * 1024 * 1024)

    def test_hardlinked_input_is_not_a_safe_selected_source(self) -> None:
        source = self.source_zip()
        alias = self.root / "source-hardlink.zip"
        os.link(source, alias)
        with self.assertRaises((MemoryError, storage.StorageError)):
            packs.create(source, self.root / "must-not-pack")
        with self.assertRaises((migrate.MigrationError, storage.StorageError)):
            migrate.convert(alias, self.root / "must-not-convert.ndjson", self.root / "must-not-report.json")
        self.assertFalse((self.root / "must-not-pack").exists())
        self.assertFalse((self.root / "must-not-convert.ndjson").exists())

    def test_small_migrator_keeps_interface_and_dry_run_has_no_output(self) -> None:
        source = self.source_zip()
        output, report = self.root / "converted.ndjson", self.root / "report.json"
        preview = migrate.convert(source, output, report, dry_run=True)
        self.assertFalse(preview["written"])
        self.assertFalse(output.exists())
        self.assertFalse(report.exists())
        result = migrate.convert(source, output, report)
        self.assertTrue(result["written"])
        self.assertEqual(result["import_admission_default"], "quarantined")
        self.assertEqual(migrate.MAX_SOURCE_BYTES, 64 * 1024 * 1024)
        saved = output.read_bytes()
        with self.assertRaises(migrate.MigrationError):
            migrate.convert(source, output, report)
        self.assertEqual(output.read_bytes(), saved)

    @unittest.skipUnless(os.name == "posix", "POSIX pathname-replacement case")
    def test_selected_source_replacement_is_detected_after_descriptor_read(self) -> None:
        source = self.root / "selected.bin"
        replacement = self.root / "replacement.bin"
        storage.atomic_write(source, b"original", replace=False)
        storage.atomic_write(replacement, b"replacement", replace=False)
        with self.assertRaisesRegex(MemoryError, "pack_source_changed_retry_new_output"):
            with packs._source_stream(source, 1024) as stream:
                self.assertEqual(stream.read(), b"original")
                os.replace(replacement, source)


@unittest.skipUnless(os.name == "nt", "requires a separately authorized native Windows run")
class NativePackTests(_PackFixtures, unittest.TestCase):
    def test_create_copy_unpack_do_not_fall_back_to_posix_publication(self) -> None:
        source = self.root / "synthetic.bin"
        storage.atomic_write(source, b"native source\n", replace=False)
        with (mock.patch.object(os, "link", side_effect=AssertionError("POSIX publication used")),
              mock.patch.object(os, "fchmod", create=True, side_effect=AssertionError("POSIX mode repair used"))):
            packs.create(source, self.root / "native-pack")
            packs.copy(self.root / "native-pack", self.root / "native-copy")
            packs.unpack(self.root / "native-copy", self.root / "native-output.bin")
        storage.check_private_directory(self.root / "native-pack")
        storage.check_private_directory(self.root / "native-copy" / "chunks")
        descriptor = storage.open_file(self.root / "native-output.bin", os.O_RDONLY, private=True)
        try:
            self.assertFalse(os.get_inheritable(descriptor))
            self.assertEqual(os.read(descriptor, 1024), b"native source\n")
        finally:
            os.close(descriptor)

    def test_small_zip_pair_uses_native_private_publication_without_fchmod(self) -> None:
        source = self.source_zip("windows-source.zip")
        output, report = self.root / "windows-output.ndjson", self.root / "windows-report.json"
        with (mock.patch.object(os, "link", side_effect=AssertionError("POSIX publication used")),
              mock.patch.object(os, "fchmod", create=True, side_effect=AssertionError("POSIX mode repair used"))):
            result = migrate.convert(source, output, report)
        self.assertFalse(result["original_author_authenticated"])
        for path in (output, report):
            descriptor = storage.open_file(path, os.O_RDONLY, private=True)
            os.close(descriptor)

    def test_native_second_publication_failure_only_rolls_back_owned_report(self) -> None:
        source = self.source_zip("rollback-source.zip")
        output, report = self.root / "rollback-output.ndjson", self.root / "rollback-report.json"
        publish = storage.publish_file

        def fail_second(temporary: Path, destination: Path, *, replace: bool = False) -> None:
            if destination == output:
                raise FileExistsError("synthetic publication collision")
            publish(temporary, destination, replace=replace)

        with mock.patch.object(storage, "publish_file", side_effect=fail_second):
            with self.assertRaises(migrate.MigrationError):
                migrate.convert(source, output, report)
        self.assertFalse(output.exists())
        self.assertFalse(report.exists())
        self.assertTrue(source.exists())


if __name__ == "__main__":
    unittest.main()
