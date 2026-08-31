"""Independent synthetic legacy-conversion edge cases; authored, NOT executed.

The helper fixtures encode the inspected v0.21 grammar. Every file/database is
created only under this module's own temporary directory when a reviewer later
chooses to run it. No real Vault, key, credential, provider or host is used.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT, Path(__file__).resolve().parent):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import memory_vault_legacy_pack as packs
import memory_vault_migrate as legacy
from memory_vault import MemoryError, Vault, canonical_bytes, sha256
from memory_vault_client import CONFIG_SCHEMA
from test_v025_legacy_pack import document_files, episode, event, old_wire_pack


def _refresh_source_manifest(files: dict[str, bytes]) -> None:
    manifest = json.loads(files["MANIFEST.json"])
    manifest.pop("network_sha256", None)
    manifest["entries"] = [{"path": name, "sha256": sha256(raw), "size": len(raw)}
                           for name, raw in sorted(files.items()) if name != "MANIFEST.json"]
    manifest["network_sha256"] = legacy._legacy_hash(manifest)
    files["MANIFEST.json"] = canonical_bytes(manifest) + b"\n"


@unittest.skipUnless(os.name == "posix", "synthetic POSIX fixtures; native validation remains separate")
class LegacyPackEdgeTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="memory-vault-legacy-edges-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    def source(self, files: dict[str, bytes], name: str) -> Path:
        path = self.root / name
        path.write_bytes(old_wire_pack(files))
        path.chmod(0o600)
        return path

    def members(self, path: Path) -> tuple[dict, dict[str, bytes]]:
        # These fixtures are deliberately small; the production implementation
        # must continue streaming and must not adopt this test-only read-all.
        with zipfile.ZipFile(path) as archive:
            values = {name: archive.read(name) for name in archive.namelist()}
        return json.loads(values["MANIFEST.json"]), values

    def extract_parts(self, capsule: Path, manifest: dict, prefix: str) -> list[Path]:
        paths = []
        for number in range(1, len(manifest["record_parts"]) + 1):
            path = self.root / f"{prefix}-{number}.ndjson"
            packs.extract(capsule, path, part=number)
            paths.append(path)
        return paths

    def test_unicode_escaped_secret_metadata_is_checked_before_base64_projection(self) -> None:
        for field in ("included_content", "excluded_content"):
            with self.subTest(field=field):
                anchor = episode(1)
                anchor[field] = ["Synthetic fixture only: ghp_" + "x" * 30]
                anchor.pop("episode_sha256")
                anchor["episode_sha256"] = legacy._legacy_hash(anchor)
                files = document_files([anchor])
                name = next(name for name in files if name.startswith("memory/episodes/"))
                files[name] = files[name].replace(b"ghp_", b"\\u0067hp_")
                _refresh_source_manifest(files)
                source = self.source(files, field + ".pack")
                # Checksums genuinely match: the failure must be the decoded
                # privacy guard, not a conveniently invalid synthetic archive.
                self.assertTrue(packs.verify(source)["legacy_checksums_verified"])
                output = self.root / (field + ".zip")
                with self.assertRaises(MemoryError) as captured:
                    packs.convert(source, output)
                self.assertEqual(captured.exception.code, "publication_secret_detected")
                self.assertFalse(output.exists())

    def test_old_event_alias_cannot_be_redirected_to_one_same_kind_projection(self) -> None:
        anchor = episode(1)
        priors = [event(anchor, statement=f"Synthetic prior {number}", claim_key=None) for number in range(129)]
        targets = [value["memory_event_id"] for value in priors]
        final = event(anchor, statement="Preserve the whole conflict", kind="conflict_declared",
                      parents=targets, conflicts_with=targets)
        source = self.source(document_files([anchor], [*priors, final]), "wide.pack")
        capsule = self.root / "wide.zip"
        packs.convert(source, capsule)
        manifest, values = self.members(capsule)
        vault_path = self.root / "imported.sqlite3"
        for part in self.extract_parts(capsule, manifest, "import"):
            Vault(vault_path).import_bundle(part)
        config = self.root / "client.json"
        config.write_bytes(canonical_bytes({"schema_version": CONFIG_SCHEMA, "vault_path": str(vault_path),
                                           "capture_visible_turns": False}))
        config.chmod(0o600)

        modified = copy.deepcopy(manifest)
        selected_part = None
        for number, item in enumerate(modified["mapping_parts"], 1):
            mappings = [json.loads(line) for line in values[item["path"]].splitlines()]
            for mapping in mappings:
                if mapping["legacy_id"] != final["memory_event_id"]:
                    continue
                self.assertGreater(len(mapping["relation_projection_records"]), 1)
                fragment = mapping["relation_projection_records"][0]
                original = Vault(vault_path).handle({"op": "get", "memory_id": mapping["memory_id"]})["result"]["record"]
                partial = Vault(vault_path).handle({"op": "get", "memory_id": fragment["memory_id"]})["result"]["record"]
                self.assertEqual((original["kind"], partial["kind"]), ("relation", "relation"))
                self.assertNotEqual(original["memory_id"], partial["memory_id"])
                mapping["memory_id"], mapping["record_sha256"] = fragment["memory_id"], fragment["record_sha256"]
                selected_part = number
            if selected_part == number:
                values[item["path"]] = b"".join(canonical_bytes(mapping) + b"\n" for mapping in mappings)
                item["size"], item["sha256"] = len(values[item["path"]]), sha256(values[item["path"]])
        self.assertIsNotNone(selected_part)
        modified.pop("capsule_manifest_sha256")
        modified["capsule_manifest_sha256"] = sha256(canonical_bytes(modified))
        values["MANIFEST.json"] = canonical_bytes(modified) + b"\n"
        tampered = self.root / "mapping-redirected.zip"
        with zipfile.ZipFile(tampered, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, raw in values.items():
                archive.writestr(name, raw)
        with self.assertRaises((MemoryError, legacy.MigrationError)):
            packs.register_aliases(tampered, config, part=selected_part)
        self.assertFalse((self.root / "client.state").exists())

    def test_cycle_and_missing_target_fail_without_publishing_partial_conversion(self) -> None:
        first = episode(1, parents=("ep-" + format(2, "040x"),))
        second = episode(2, parents=(first["episode_id"],))
        source = self.source(document_files([first, second]), "cycle.pack")
        output = self.root / "cycle.zip"
        with self.assertRaises(MemoryError) as captured:
            packs.convert(source, output)
        self.assertEqual(captured.exception.code, "cyclic_legacy_graph_requires_explicit_resolution")
        self.assertFalse(output.exists())

        source = self.source(document_files([first]), "missing.pack")
        with self.assertRaises(MemoryError) as captured:
            packs.verify(source)
        self.assertEqual(captured.exception.code, "missing_legacy_relation_target")
        output = self.root / "missing.zip"
        with self.assertRaises(MemoryError):
            packs.convert(source, output)
        self.assertFalse(output.exists())

    def test_cross_part_dependency_requires_predecessors_and_replay_adds_nothing(self) -> None:
        source = self.source(document_files([episode(1, text="Synthetic multilingual evidence 中文.\n" * 12000)]), "parts.pack")
        capsule = self.root / "parts.zip"
        with mock.patch.object(packs, "MAX_PART_BYTES", 128 * 1024):
            packs.convert(source, capsule)
        manifest, values = self.members(capsule)
        self.assertGreater(len(manifest["record_parts"]), 1)
        paths = self.extract_parts(capsule, manifest, "piece")
        prior: set[str] = set()
        dependent_index = None
        for index, item in enumerate(manifest["record_parts"]):
            records = [value["record"] for line in values[item["path"]].splitlines()
                       if (value := json.loads(line)).get("type") == "record"]
            if any(relation["target"] in prior for record in records for relation in record["relations"]):
                dependent_index = index
                break
            prior.update(record["memory_id"] for record in records)
        self.assertIsNotNone(dependent_index)
        vault = Vault(self.root / "new.sqlite3")
        with self.assertRaises(MemoryError) as captured:
            vault.import_bundle(paths[dependent_index])
        self.assertEqual(captured.exception.code, "dangling_relation")
        for part in paths:
            vault.import_bundle(part)
        count = vault.handle({"op": "status"})["result"]["records"]
        for part in paths:
            replay = vault.import_bundle(part)
            self.assertEqual(replay["records_added"], 0)
        self.assertEqual(vault.handle({"op": "status"})["result"]["records"], count)


if __name__ == "__main__":
    unittest.main()
