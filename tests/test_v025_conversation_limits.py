"""Explicit temporary v0.21 conversation-format regressions; no live Vault."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
for directory in (ROOT, Path(__file__).resolve().parent):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

import memory_vault_legacy_pack as packs
import memory_vault_migrate as legacy
from memory_vault import sha256
from test_v025_legacy_pack import old_wire_pack


class InterruptedAfterPublication(BaseException):
    """A synthetic interruption, not a process exit or power-loss test."""


@unittest.skipUnless(os.name == "posix", "fixture permissions use POSIX")
class ConversationLimitTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="memory-vault-conversation-limit-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    @staticmethod
    def conversation() -> dict:
        return {
            "schema_version": "conversation-export/v1", "source_id": "synthetic-history",
            "title": "Synthetic short-message history", "captured_at": "2026-01-01T00:00:00Z",
            "coverage": "full", "included_content": ["visible messages"],
            "excluded_content": ["hidden reasoning"],
            "messages": [{"ordinal": index, "role": "user" if index % 2 == 0 else "assistant",
                          "text": "synthetic-" + str(index)} for index in range(20_001)],
        }

    def source(self, value: dict, name: str) -> tuple[Path, str, bytes, dict[str, bytes]]:
        member = "sources/synthetic-history/revisions/synthetic-revision.json"
        raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.assertLess(len(raw), packs.MAX_MEMBER_BYTES)
        manifest = {
            "schema_version": "memory-network-bundle/v1", "network_contract": "memory-network-graph/v1",
            "remote_commit_sha": "b" * 40, "exported_at": "2026-01-01T01:00:00Z",
            "native_conversation_ids_included": False, "credentials_included": False,
            "entries": [{"path": member, "sha256": sha256(raw), "size": len(raw)}],
        }
        manifest["network_sha256"] = legacy._legacy_hash(manifest)
        files = {member: raw, "MANIFEST.json": legacy._legacy_jcs(manifest) + b"\n"}
        source = self.root / name
        source.write_bytes(old_wire_pack(files))
        source.chmod(0o600)
        return source, member, raw, files

    def test_many_short_messages_verify_repack_and_convert_losslessly(self) -> None:
        value = self.conversation()
        expected_messages = value["messages"]
        source, member, raw, files = self.source(value, "many-messages.pack")
        original_hash = sha256(source.read_bytes())
        self.assertEqual(packs.verify(source)["state"], "verified_hashes_and_graph")

        repacked = self.root / "repacked.zip"
        packs.repack(source, repacked, format="zip")
        with zipfile.ZipFile(repacked) as archive:
            self.assertEqual({name: archive.read(name) for name in archive.namelist()}, files)

        capsule = self.root / "converted.zip"
        packs.convert(source, capsule)
        with zipfile.ZipFile(capsule) as archive:
            manifest = json.loads(archive.read("MANIFEST.json"))
            records = {
                value["record"]["memory_id"]: value["record"]
                for part in manifest["record_parts"]
                for line in archive.read(part["path"]).splitlines()
                if (value := json.loads(line)).get("type") == "record"
            }
            mappings = [json.loads(line) for part in manifest["mapping_parts"]
                        for line in archive.read(part["path"]).splitlines()]
        self.assertEqual(len(mappings), 1)
        mapping = mappings[0]
        evidence = b"".join(
            base64.b64decode(json.loads(records[reference["memory_id"]]["text"].split("\n", 1)[1])["data"], validate=True)
            for reference in mapping["original_evidence_records"]
        )
        self.assertEqual(evidence, raw)
        self.assertGreater(len(mapping["visible_fragment_records"]), 1)
        body = "".join(json.loads(records[reference["memory_id"]]["text"].split("\n", 1)[1])
                       for reference in mapping["visible_fragment_records"])
        messages = json.loads(body.split("\n", 2)[2])
        self.assertEqual(messages, expected_messages)
        self.assertEqual(messages[-1]["text"], "synthetic-20000")
        self.assertEqual(sha256(source.read_bytes()), original_hash)

        # The small, single-bundle converter retains its documented subset.
        with self.assertRaisesRegex(legacy.MigrationError, "invalid_legacy_messages"):
            legacy._conversation(json.loads(raw), member, sha256(raw))

    def test_full_converter_still_checks_every_message_after_twenty_thousand(self) -> None:
        for field, invalid, code in (
            ("ordinal", 0, "invalid_legacy_message_order"),
            ("role", "system", "unsupported_legacy_message_role"),
        ):
            with self.subTest(field=field):
                value = self.conversation()
                value["messages"][-1][field] = invalid
                source, _member, _raw, _files = self.source(value, field + ".pack")
                with self.assertRaisesRegex(legacy.MigrationError, code):
                    packs.verify(source)

    def test_full_pack_publication_has_single_name_at_directory_fsync(self) -> None:
        value = self.conversation()
        value["messages"] = value["messages"][:1]
        source, _member, _raw, _files = self.source(value, "one-message.pack")
        destination = self.root / "one-message.zip"
        observations = []
        original_fsync = os.fsync

        def interrupt(descriptor: int) -> None:
            original_fsync(descriptor)
            if stat.S_ISDIR(os.fstat(descriptor).st_mode) and destination.exists():
                observations.append((destination.stat().st_nlink,
                                     sorted(path.name for path in self.root.glob(".memory-v021-*"))))
                raise InterruptedAfterPublication()

        with mock.patch.object(packs.os, "fsync", side_effect=interrupt):
            with self.assertRaises(InterruptedAfterPublication):
                packs.repack(source, destination, format="zip")
        self.assertEqual(observations, [(1, [])])
        self.assertEqual(packs.verify(destination)["state"], "verified_hashes_and_graph")


if __name__ == "__main__":
    unittest.main()
