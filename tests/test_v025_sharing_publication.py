"""Small synthetic sharing-publication regressions; supplied without execution.

Only a disposable private directory and one unsigned, synthetic wire record are
used. The durability-barrier case observes link state before finally-cleanup and
injects an in-process interruption; it is not a process-exit or power-loss test.
No Vault/config, provider, key, host, subprocess, network or account is accessed.
"""

from __future__ import annotations

import hashlib
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

import memory_vault as core
import memory_vault_sharing as sharing
import memory_vault_storage as storage


class InterruptedAfterPublication(BaseException):
    """Synthetic interruption after the destination becomes durable."""


def synthetic_share_bytes() -> bytes:
    record = core.build_record(kind="fact", text="Synthetic publication boundary.",
                               created_at="2026-01-01T00:00:00Z")
    selector = sharing.parse_selector({
        "schema_version": sharing.SELECTOR_SCHEMA,
        "memory_ids": [record["memory_id"]],
    })
    header = {
        "type": "header", "schema_version": sharing.SHARE_SCHEMA,
        "hash_profile": core.HASH_PROFILE, "created_at": "2026-01-01T00:00:00Z",
        "selector": selector, "selector_sha256": core.sha256(core.canonical_bytes(selector)),
    }
    frame = core.canonical_bytes({
        "type": "record", "record": record, "attestation": None, "selected": True,
    }) + b"\n"
    footer = {
        "type": "footer", "records": 1, "selected_records": 1,
        "records_sha256": hashlib.sha256(record["record_sha256"].encode("ascii") + b"\n").hexdigest(),
        "lines_sha256": hashlib.sha256(frame).hexdigest(),
    }
    return core.canonical_bytes(header) + b"\n" + frame + core.canonical_bytes(footer) + b"\n"


@unittest.skipUnless(sys.platform == "darwin" or sys.platform.startswith("linux"),
                     "requires an authorized macOS/Linux private-directory fixture")
class SharingPublicationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="memory-v025-share-publication-synthetic-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.destination = self.root / "selected.ndjson"
        self.payload = synthetic_share_bytes()

    def test_interrupted_directory_fsync_has_no_temporary_hard_link_alias(self) -> None:
        observations = []
        original_fsync = os.fsync

        def interrupt_after_publication(descriptor):
            original_fsync(descriptor)
            if stat.S_ISDIR(os.fstat(descriptor).st_mode) and self.destination.exists():
                # Observe BEFORE finally can remove any temporary name. The old
                # link/fsync/unlink sequence has nlink=2 and a temporary here.
                observations.append((self.destination.stat().st_nlink,
                                     sorted(path.name for path in self.root.glob(".memory-share-*"))))
                raise InterruptedAfterPublication()

        with mock.patch.object(sharing.os, "fsync", side_effect=interrupt_after_publication):
            with self.assertRaises(InterruptedAfterPublication):
                with sharing._new_output(self.destination) as stream:
                    stream.write(self.payload)

        self.assertEqual(observations, [(1, [])])
        self.assertEqual(self.destination.stat().st_nlink, 1)
        self.assertEqual(self.destination.read_bytes(), self.payload)
        summary = sharing.verify_share_bundle(self.destination)
        self.assertEqual((summary.records, summary.selected_records, summary.attestations), (1, 1, 0))
        self.assertEqual(summary.sha256, hashlib.sha256(self.payload).hexdigest())
        self.assertEqual(list(self.root.iterdir()), [self.destination])

    def test_existing_and_raced_outputs_are_not_overwritten_and_aliases_still_fail(self) -> None:
        with sharing._new_output(self.destination) as stream:
            stream.write(self.payload)
        with self.assertRaises(core.MemoryError) as existing:
            with sharing._new_output(self.destination):
                self.fail("existing destination must fail before opening the output")
        self.assertEqual(existing.exception.code, "share_output_exists")
        self.assertEqual(self.destination.read_bytes(), self.payload)

        raced = self.root / "raced.ndjson"
        with self.assertRaises(FileExistsError):
            with sharing._new_output(raced) as stream:
                stream.write(self.payload)
                # A separate publisher wins after the initial existence check.
                descriptor = os.open(raced, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "wb") as competitor:
                    competitor.write(b"synthetic competing publication")
        self.assertEqual(raced.read_bytes(), b"synthetic competing publication")
        self.assertEqual(raced.stat().st_nlink, 1)
        self.assertEqual(list(self.root.glob(".memory-share-*")), [])

        alias = self.root / "synthetic-existing-alias.ndjson"
        os.link(self.destination, alias)
        with self.assertRaises(core.MemoryError) as unsafe:
            sharing.verify_share_bundle(self.destination)
        self.assertEqual(unsafe.exception.code, "unsafe_share_source")
        self.assertEqual(self.destination.read_bytes(), self.payload)
        self.assertEqual(alias.read_bytes(), self.payload)

    def test_unsupported_exclusive_rename_has_no_link_or_overwrite_fallback(self) -> None:
        with mock.patch.object(storage, "_rename_no_replace", side_effect=storage.StorageError("atomic_no_replace_unavailable")), \
                mock.patch.object(storage.os, "link", side_effect=AssertionError("hard-link fallback forbidden")), \
                mock.patch.object(storage.os, "replace", side_effect=AssertionError("overwrite fallback forbidden")):
            with self.assertRaises(storage.StorageError) as unavailable:
                with sharing._new_output(self.destination) as stream:
                    stream.write(self.payload)
        self.assertEqual(unavailable.exception.code, "atomic_no_replace_unavailable")
        self.assertFalse(unavailable.exception.retryable)
        self.assertFalse(self.destination.exists())
        self.assertEqual(list(self.root.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
