"""Synthetic v0.21 wire/projection cases; supplied, NOT executed by this turn.

Only explicit temporary fixtures are used. No private Vault, account, signing
key, host transcript, network client or external crypto provider is required.
Large scale is a separately documented external validation task, not a claim
made by these small deterministic fixtures.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock
import zipfile
import zlib

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import memory_vault_legacy_pack as packs
import memory_vault_migrate as legacy
from memory_vault import AUTHORITY, MemoryError, Vault, canonical_bytes, sha256, validate_record
from memory_vault_client import CONFIG_SCHEMA


def episode(number: int, *, text: str = "Synthetic visible question", parents: tuple[str, ...] = ()) -> dict:
    value = {"schema_version": "memory-episode/v1", "episode_id": "ep-" + format(number, "040x"),
             "source_id": "src-" + "a" * 40, "source_sequence": number, "parent_episode_ids": list(parents),
             "captured_at": "2026-01-01T00:00:00Z", "created_at": "2026-01-01T00:00:00Z",
             "coverage": "partial_active_turn", "included_content": ["visible user prompt", "visible final assistant message"],
             "excluded_content": ["hidden reasoning", "credentials", "native conversation identifiers"],
             "messages": [{"ordinal": 0, "role": "user", "phase": "unknown", "text": text},
                          {"ordinal": 1, "role": "assistant", "phase": "final_answer", "text": "Synthetic visible final answer"}],
             "hash_profile": "jcs-rfc8785+sha256/episode-v1"}
    value["episode_sha256"] = legacy._legacy_hash(value)
    return value


def event(anchor: dict, *, statement: str = "Keep memory task-independent", kind: str = "decision",
          claim_key: str | None = "storage-direction", **relations: list[str]) -> dict:
    payload = {"profile": "memory-network-semantic/v1", "claim": {"statement": statement, "reason": None, "concepts": ["memory", "continuity"]}}
    refs = {name: list(relations.get(name, [])) for name in ("parents", "supersedes", "conflicts_with", "resolves")}
    identity_domain = {"source_id": anchor["source_id"], "episode_id": anchor["episode_id"], "kind": kind,
                       "claim_key": claim_key, **refs, "payload": payload}
    value = {"schema_version": "memory-event/v2", "memory_event_id": "evt-" + legacy._legacy_hash(identity_domain)[:40],
             "kind": kind, "confidence": "assistant_inferred", "source": {"source_id": anchor["source_id"],
             "revision_id": anchor["episode_id"], "source_sequence": anchor["source_sequence"], "evidence_anchor_sha256": anchor["episode_sha256"]},
             "claim_key": claim_key, **refs, "payload": payload, "payload_sha256": legacy._legacy_hash(payload),
             "hash_profile": "jcs-rfc8785+sha256/event-v2", "created_at": "2026-01-01T00:00:01Z"}
    value["event_sha256"] = legacy._legacy_hash(value)
    return value


def document_files(episodes: list[dict], events: list[dict] = ()) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    for value in episodes:
        identity = value["episode_id"]
        files[f"memory/episodes/{identity[3:5]}/{identity}.json"] = (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    for value in events:
        identity = value["memory_event_id"]
        files[f"memory/events/{identity[4:6]}/{identity}.json"] = (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    domain = {"schema_version": "memory-network-bundle/v1", "network_contract": "memory-network-graph/v1",
              "remote_commit_sha": "b" * 40, "exported_at": "2026-01-01T01:00:00Z",
              "native_conversation_ids_included": False, "credentials_included": False,
              "entries": [{"path": name, "sha256": sha256(raw), "size": len(raw)} for name, raw in sorted(files.items())]}
    domain["network_sha256"] = legacy._legacy_hash(domain)
    files["MANIFEST.json"] = (json.dumps(domain, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    return files


def old_wire_pack(files: dict[str, bytes]) -> bytes:
    """Independent writer of the inspected old frame/index/footer grammar."""
    output = bytearray(b"memory-pack/v1\n")
    entries = []
    for name, raw in sorted(files.items()):
        compressed = zlib.compress(raw, level=6)
        header = {"path": name, "sha256": hashlib.sha256(raw).hexdigest(), "raw_size": len(raw), "compressed_size": len(compressed)}
        entries.append({**header, "offset": len(output)})
        encoded = legacy._legacy_jcs(header)
        output.extend(struct.pack(">I", len(encoded)) + encoded + compressed)
    index = legacy._legacy_jcs({"schema_version": "memory-pack-index/v1", "entries": entries})
    output.extend(index + struct.pack(">Q", len(index)) + b"memory-pack-index/v1\n")
    return bytes(output)


@unittest.skipUnless(os.name == "posix", "fixture permissions use POSIX; native Windows validation is separate")
class LegacyPackTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    def source(self, files: dict[str, bytes], name: str = "old.pack", *, zipped: bool = False) -> Path:
        path = self.root / name
        if zipped:
            with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for member, raw in files.items():
                    archive.writestr(member, raw)
        else:
            path.write_bytes(old_wire_pack(files))
        path.chmod(0o600)
        return path

    def contents(self, capsule: Path) -> tuple[dict, list[dict], list[dict]]:
        with zipfile.ZipFile(capsule) as archive:
            manifest = json.loads(archive.read("MANIFEST.json"))
            records = [value["record"] for item in manifest["record_parts"]
                       for line in archive.read(item["path"]).splitlines()
                       if (value := json.loads(line)).get("type") == "record"]
            mappings = [json.loads(line) for item in manifest["mapping_parts"] for line in archive.read(item["path"]).splitlines()]
        return manifest, records, mappings

    def test_production_range_is_not_old_small_migrator_subset(self) -> None:
        self.assertEqual(packs.MAX_SOURCE_BYTES, 2 * 1024**3)
        self.assertEqual(packs.MAX_RAW_BYTES, 2 * 1024**3)
        self.assertEqual(packs.MAX_DOCUMENTS, 250_000)
        self.assertEqual(packs.MAX_MANIFEST_BYTES, 64 * 1024**2)
        self.assertEqual(packs.MAX_INDEX_BYTES, 128 * 1024**2)

    def test_actual_old_pack_and_zip_repack_preserve_every_member_byte(self) -> None:
        anchor = episode(1)
        files = document_files([anchor], [event(anchor)])
        source = self.source(files)
        result = packs.verify(source)
        expected_root = legacy._legacy_hash([{"path": name, "raw_size": len(raw), "sha256": sha256(raw)} for name, raw in sorted(files.items())])
        self.assertEqual(result["object_root_sha256"], expected_root)
        self.assertFalse(result["original_author_authenticated"])
        self.assertEqual(result["authority"], AUTHORITY)
        output = self.root / "repacked.zip"
        packs.repack(source, output, format="zip")
        with zipfile.ZipFile(output) as archive:
            self.assertEqual({name: archive.read(name) for name in archive.namelist()}, files)
        second = self.root / "repacked.pack"
        packs.repack(output, second, format="pack")
        self.assertEqual(packs.verify(second)["object_root_sha256"], expected_root)

    def test_checkpoint_is_hash_only_and_explicit_anchor_is_compared(self) -> None:
        source = self.source(document_files([episode(1)]))
        first, second = self.root / "checkpoint-0.json", self.root / "checkpoint-1.json"
        created = packs.create_checkpoint(source, first, generation=0)
        self.assertFalse(created["checkpoint_is_signature"])
        checked = packs.verify(source, checkpoint=first, trusted_checkpoint_sha256=created["checkpoint_sha256"])
        self.assertTrue(checked["trusted_anchor_checked"])
        self.assertFalse(checked["original_author_authenticated"])
        packs.create_checkpoint(source, second, generation=1, previous_checkpoint_sha256=created["checkpoint_sha256"])
        chain = packs.verify_checkpoint_chain([first, second], trusted_checkpoint_sha256=created["checkpoint_sha256"])
        self.assertFalse(chain["pack_object_root_checked"])
        with self.assertRaises(MemoryError):
            packs.verify(source, checkpoint=first, trusted_checkpoint_sha256="0" * 64)
        wrong = self.source(document_files([episode(2)]), "other.pack")
        with self.assertRaises(MemoryError):
            packs.verify(wrong, checkpoint=first)
        with self.assertRaises(MemoryError):
            packs.verify_checkpoint_chain([second, first])

    def test_conversion_retains_exact_evidence_claims_and_typed_relations(self) -> None:
        first = episode(1, text="  UTF8 visible e\u0301 / 中 文\n\n  ")
        second = episode(2, parents=(first["episode_id"],))
        decision = event(first)
        correction = event(second, statement="Refine the same direction", kind="correction",
                           parents=[decision["memory_event_id"]], supersedes=[decision["memory_event_id"]])
        files = document_files([first, second], [decision, correction])
        source = self.source(files)
        capsule = self.root / "converted.zip"
        result = packs.convert(source, capsule)
        manifest, records, mappings = self.contents(capsule)
        self.assertTrue(result["visible_text_preserved"])
        self.assertEqual(manifest["import_admission_default"], "quarantined")
        self.assertEqual(manifest["signed_records"], 0)
        by_id = {record["memory_id"]: validate_record(record) for record in records}
        by_old = {row["legacy_id"]: row for row in mappings}
        for row in mappings:
            pieces = []
            for reference in row["original_evidence_records"]:
                record = by_id[reference["memory_id"]]
                envelope = json.loads(record["text"].split("\n", 1)[1])
                self.assertEqual(envelope["offset"], sum(len(piece) for piece in pieces))
                pieces.append(base64.b64decode(envelope["data"], validate=True))
            self.assertEqual(b"".join(pieces), files[row["source_path"]])
            self.assertEqual(sha256(b"".join(pieces)), row["source_document_sha256"])
        mapped = by_id[by_old[correction["memory_event_id"]]["memory_id"]]
        self.assertIn("claim:v021:storage-direction", mapped["entities"])
        self.assertIn("semantic:v021:correction", mapped["entities"])
        old_target = by_old[decision["memory_event_id"]]["memory_id"]
        self.assertIn({"type": "supersedes", "target": old_target}, mapped["relations"])
        self.assertIn({"type": "derived_from", "target": old_target}, mapped["relations"])
        self.assertEqual(mapped["provenance"]["confidence"], "imported")
        exact = self.root / "original-again.pack"
        packs.extract(capsule, exact, original=True)
        self.assertEqual(exact.read_bytes(), source.read_bytes())

    def test_large_visible_body_is_fragmented_and_parts_are_dependency_ordered(self) -> None:
        text = "Visible multilingual evidence 中文.\n" * 12_000
        anchor = episode(1, text=text)
        source = self.source(document_files([anchor]))
        capsule = self.root / "parts.zip"
        with mock.patch.object(packs, "MAX_PART_BYTES", 128 * 1024):
            packs.convert(source, capsule)
        manifest, records, mappings = self.contents(capsule)
        self.assertGreater(len(manifest["record_parts"]), 1)
        seen: set[str] = set()
        for record in records:
            self.assertTrue({edge["target"] for edge in record["relations"]}.issubset(seen))
            seen.add(record["memory_id"])
        mapping = mappings[0]
        by_id = {record["memory_id"]: record for record in records}
        rendered = "".join(json.loads(by_id[reference["memory_id"]]["text"].split("\n", 1)[1])
                           for reference in mapping["visible_fragment_records"])
        messages = json.loads(rendered.split("\n", 1)[1])
        self.assertEqual(messages, anchor["messages"])
        vault = Vault(self.root / "new.sqlite3")
        for number, part in enumerate(manifest["record_parts"], 1):
            extracted = self.root / f"part-{number}.ndjson"
            packs.extract(capsule, extracted, part=number)
            self.assertEqual(extracted.stat().st_size, part["size"])
            result = vault.import_bundle(extracted)
            self.assertEqual(result["admission"], "quarantined")

    def test_all_four_old_256_edge_lists_survive_projection(self) -> None:
        anchor = episode(1)
        priors = [event(anchor, statement=f"Prior synthetic decision {number}", claim_key=None) for number in range(256)]
        targets = [value["memory_event_id"] for value in priors]
        final = event(anchor, statement="All typed edges remain", **{name: targets for name in packs._RELATIONS})
        source = self.source(document_files([anchor], [*priors, final]))
        capsule = self.root / "edges.zip"
        packs.convert(source, capsule)
        _manifest, records, mappings = self.contents(capsule)
        by_old = {row["legacy_id"]: row for row in mappings}
        mapping = by_old[final["memory_event_id"]]
        self.assertGreater(len(mapping["relation_projection_records"]), 1)
        by_id = {record["memory_id"]: record for record in records}
        observed = {(edge["type"], edge["target"]) for row in mapping["relation_projection_records"] for edge in by_id[row["memory_id"]]["relations"]}
        for name, relation in packs._RELATIONS.items():
            for old_id in final[name]:
                self.assertIn((relation, by_old[old_id]["memory_id"]), observed)

    def test_explicit_alias_registration_does_not_grant_trust(self) -> None:
        anchor = episode(1)
        source = self.source(document_files([anchor], [event(anchor)]))
        capsule = self.root / "aliases.zip"
        packs.convert(source, capsule)
        manifest, _records, mappings = self.contents(capsule)
        vault_path = self.root / "imported.sqlite3"
        vault = Vault(vault_path)
        for number in range(1, len(manifest["record_parts"]) + 1):
            output = self.root / f"import-{number}.ndjson"
            packs.extract(capsule, output, part=number)
            vault.import_bundle(output)
        config = self.root / "client.json"
        config.write_bytes(canonical_bytes({"schema_version": CONFIG_SCHEMA, "vault_path": str(vault_path), "capture_visible_turns": False}))
        config.chmod(0o600)
        first = packs.register_aliases(capsule, config)
        second = packs.register_aliases(capsule, config)
        self.assertEqual(first["added"], len(mappings))
        self.assertEqual(second["added"], 0)
        self.assertFalse(first["trust_granted"])
        for row in mappings:
            result = vault.handle({"op": "get", "memory_id": row["memory_id"]})
            self.assertEqual(result["result"]["verification"]["admission"], "quarantined")

    def test_rehashed_capsule_cannot_relabel_the_original_source_alias(self) -> None:
        anchor = episode(1)
        source = self.source(document_files([anchor]))
        capsule = self.root / "mapping-original.zip"
        packs.convert(source, capsule)
        manifest, _records, _mappings = self.contents(capsule)
        vault_path = self.root / "mapped.sqlite3"
        for number in range(1, len(manifest["record_parts"]) + 1):
            part = self.root / f"mapped-{number}.ndjson"
            packs.extract(capsule, part, part=number)
            Vault(vault_path).import_bundle(part)
        config = self.root / "client.json"
        config.write_bytes(canonical_bytes({"schema_version": CONFIG_SCHEMA, "vault_path": str(vault_path), "capture_visible_turns": False}))
        config.chmod(0o600)
        with zipfile.ZipFile(capsule) as archive:
            members = {name: archive.read(name) for name in archive.namelist()}
        modified = copy.deepcopy(manifest)
        item = modified["mapping_parts"][0]
        row = json.loads(members[item["path"]].splitlines()[0])
        row["source_id"] = "src-" + "f" * 40
        members[item["path"]] = canonical_bytes(row) + b"\n"
        item["sha256"] = sha256(members[item["path"]])
        item["size"] = len(members[item["path"]])
        modified.pop("capsule_manifest_sha256")
        modified["capsule_manifest_sha256"] = sha256(canonical_bytes(modified))
        members["MANIFEST.json"] = canonical_bytes(modified) + b"\n"
        tampered = self.root / "mapping-rehashed.zip"
        with zipfile.ZipFile(tampered, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, raw in members.items():
                archive.writestr(name, raw)
        with self.assertRaisesRegex(MemoryError, "conversion_alias_source_mismatch"):
            packs.register_aliases(tampered, config)
        self.assertFalse((self.root / "client.state").exists())

    def test_tampered_pack_and_undeclared_path_never_publish_partial_conversion(self) -> None:
        files = document_files([episode(1)])
        source = self.source(files)
        source.write_bytes(source.read_bytes() + b"trailing")
        output = self.root / "must-not-exist.zip"
        with self.assertRaises((MemoryError, legacy.MigrationError)):
            packs.convert(source, output)
        self.assertFalse(output.exists())
        unsafe = {**files, "../../outside.json": b"{}"}
        source = self.source(unsafe, "unsafe.pack")
        with self.assertRaises((MemoryError, legacy.MigrationError)):
            packs.convert(source, output)
        self.assertFalse(output.exists())

    def test_existing_destinations_and_symlink_sources_are_rejected(self) -> None:
        source = self.source(document_files([episode(1)]))
        output = self.root / "existing.zip"
        output.write_bytes(b"preserve this exact existing data")
        with self.assertRaises((MemoryError, legacy.MigrationError)):
            packs.convert(source, output)
        self.assertEqual(output.read_bytes(), b"preserve this exact existing data")
        link = self.root / "alias.pack"
        link.symlink_to(source)
        with self.assertRaises((MemoryError, legacy.MigrationError)):
            packs.verify(link)

    def test_dry_run_has_no_published_file_or_vault(self) -> None:
        source = self.source(document_files([episode(1)]))
        output = self.root / "dry-run.zip"
        result = packs.convert(source, output, dry_run=True)
        self.assertEqual(result["state"], "validated_only")
        self.assertTrue(result["temporary_index_used"])
        self.assertFalse(result["written"])
        self.assertFalse(result["vault_database_opened"])
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
