"""One synthetic offline artifact-catalog conversion check; no cloud or Vault.

All identifiers, names, classifications and entries below are invented fixture
data. There is no private catalog, account, credential, device or host path.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import tempfile
import unittest

import memory_vault_artifact_catalog as catalogs
import memory_vault_storage as storage
from memory_vault import BUNDLE_SCHEMA, MemoryError, canonical_bytes, strict_json_loads, validate_record


class ArtifactCatalogTests(unittest.TestCase):
    def test_both_catalogs_preserve_content_locations_evidence_and_outputs(self) -> None:
        with tempfile.TemporaryDirectory(prefix="memory-artifact-catalog-synthetic-") as temporary:
            root = Path(temporary).resolve()
            first_hash, second_hash = "1" * 64, "2" * 64
            backup = {
                "schema_version": "artifact-backup-index/v1", "created_at": "2032-02-03T04:05:06Z",
                "authority": {"strategy": "synthetic-historical-git-claim"},
                "records": [
                    {"record_id": "fixture-row-1", "task_id": "fixture-private-task-do-not-copy",
                     "display_name": "shared-name.zip", "source_relative_path": "private-directory/shared-name.zip",
                     "classification": "synthetic archive", "content_sha256": first_hash, "size_bytes": 12,
                     "extension": ".zip", "storage": {"mode": "google_drive",
                         "canonical_drive_file_id": "fixture_file_alpha", "uploaded_drive_file_id": "fixture_file_beta",
                         "drive_parent_id": "fixture_parent", "drive_name": "stored-archive.zip",
                         "remote_size_verified": True, "remote_content_checksum": "historical-sha256-claim"}},
                    {"record_id": "fixture-row-2", "display_name": "shared-name.zip",
                     "content_sha256": second_hash, "size_bytes": 19,
                     "storage": {"canonical_drive_file_id": "fixture_file_gamma", "drive_parent_id": "fixture_parent"}},
                ],
            }
            imported = {
                "schema_version": "drive-import/v1", "recorded_at": "2033-01-01T00:00:00Z",
                "drive_root_id": "fixture_parent", "objects": [
                    {"drive_file_id": "fixture_file_delta", "drive_parent_id": "fixture_parent",
                     "display_name": "other-label.zip", "logical_path": "old-directory/other-label.zip",
                     "size": 12, "mime_type": "application/zip", "sha256": first_hash,
                     "mapping_status": "path_ambiguous", "aliases": ["directory/alias-label.zip"]},
                    {"drive_file_id": "fixture_file_unresolved", "drive_parent_id": "fixture_parent",
                     "display_name": "unresolved-label.bin", "size": 8, "sha256": None,
                     "mapping_status": "needs_hash_verification", "aliases": ["old/unresolved-alias.bin"]},
                ],
            }
            source_a, source_b = root / "backup.json", root / "import.json"
            for path, value in ((source_a, backup), (source_b, imported)):
                storage.atomic_write(path, canonical_bytes(value) + b"\n", replace=False)
            output, report = root / "converted.ndjson", root / "mapping.json"
            dry = catalogs.convert_catalogs([source_a, source_b], output, report, dry_run=True)
            self.assertFalse(output.exists())
            self.assertFalse(report.exists())
            self.assertFalse(dry["network_accessed"])
            self.assertFalse(dry["vault_accessed"])
            self.assertNotIn("entries", dry)
            result = catalogs.convert_catalogs([source_a, source_b], output, report)
            self.assertEqual(result["bundle_sha256"], dry["bundle_sha256"])
            self.assertEqual(result["report_sha256"], dry["report_sha256"])
            self.assertEqual(result["counts"], {"input_catalogs": 2, "unique_catalogs": 2,
                "catalog_rows": 4, "unique_contents": 2, "unique_locations": 4, "unique_drive_file_ids": 4,
                "artifact_records": 2, "locator_records": 4, "source_evidence_records": 4,
                "bundle_records": 10, "located_rows": 3, "unresolved_rows": 1, "logical_path_ambiguous_rows": 1})
            lines = [strict_json_loads(line) for line in output.read_bytes().splitlines()]
            self.assertEqual(lines[0]["schema_version"], BUNDLE_SCHEMA)
            records = [validate_record(line["record"]) for line in lines[1:-1]]
            self.assertEqual(lines[-1]["record_count"], len(records))
            self.assertEqual(lines[-1]["records_sha256"], hashlib.sha256(b"".join(
                record["record_sha256"].encode("ascii") + b"\n" for record in records)).hexdigest())
            bodies = [(record, strict_json_loads(record["text"])) for record in records]
            descriptors = {body["sha256"]: record for record, body in bodies if body["schema_version"] == catalogs.DESCRIPTOR_SCHEMA}
            locations = [(record, body) for record, body in bodies if body["schema_version"] == catalogs.LOCATION_SCHEMA]
            self.assertEqual({body["file_id"] for _, body in locations}, {
                "fixture_file_alpha", "fixture_file_beta", "fixture_file_gamma", "fixture_file_delta"})
            for record, body in locations:
                self.assertEqual(record["relations"], [{"type": "related_to", "target": descriptors[body["sha256"]]["memory_id"]}])
                self.assertFalse(body["current_content_verified"])
                self.assertFalse(body["author_authenticated"])
            ambiguous = next(body for _, body in locations if body["file_id"] == "fixture_file_delta")
            self.assertTrue(ambiguous["logical_path_ambiguous"])
            self.assertIn("alias-label.zip", ambiguous["labels"])
            unresolved = [body for _, body in bodies if body.get("status") == "unresolved"]
            self.assertEqual(len(unresolved), 1)
            self.assertIn("missing_content_sha256", unresolved[0]["reasons"])
            self.assertIn("unresolved-alias.bin", unresolved[0]["labels"])
            encoded = output.read_bytes()
            self.assertNotIn(b"fixture-private-task-do-not-copy", encoded)
            self.assertNotIn(b"private-directory/", encoded)
            private = strict_json_loads(report.read_bytes())
            self.assertEqual(len(private["entries"]), 4)
            self.assertIn(backup["records"][0], [item["original_entry"] for item in private["entries"]])
            for record in records:
                self.assertEqual(record["provenance"]["source_type"], "imported")
                self.assertEqual(record["provenance"]["confidence"], "imported")
            # Input order and adding a later source retain this batch's earliest
            # genuine evidence time. No invented epoch is used to force an ID.
            reordered = catalogs.convert_catalogs([source_b, source_a], dry_run=True)
            self.assertEqual(reordered["bundle_sha256"], result["bundle_sha256"])
            only_a, only_a_report = root / "single.ndjson", root / "single-report.json"
            catalogs.convert_catalogs([source_a], only_a, only_a_report)
            single = [strict_json_loads(line)["record"] for line in only_a.read_bytes().splitlines()[1:-1]]
            self.assertEqual({record["memory_id"] for record in single if record["kind"] == "artifact"},
                             {record["memory_id"] for record in descriptors.values()})
            self.assertTrue(all(record["created_at"] == "2032-02-03T04:05:06.000000Z"
                                for record in descriptors.values()))
            saved = (output.read_bytes(), report.read_bytes())
            with self.assertRaisesRegex(MemoryError, "artifact_catalog_output_exists"):
                catalogs.convert_catalogs([source_a, source_b], output, report)
            self.assertEqual((output.read_bytes(), report.read_bytes()), saved)
            conflict = {"schema_version": "drive-import/v1", "recorded_at": "2033-01-01T00:00:00Z",
                        "objects": [{"sha256": first_hash, "size": 13, "drive_file_id": "fixture_conflict"}]}
            conflict_path = root / "conflict.json"
            storage.atomic_write(conflict_path, canonical_bytes(conflict), replace=False)
            with self.assertRaisesRegex(MemoryError, "artifact_catalog_sha256_size_conflict"):
                catalogs.convert_catalogs([source_a, conflict_path], root / "never-bundle", root / "never-report")
            self.assertFalse((root / "never-bundle").exists())
            self.assertFalse((root / "never-report").exists())
            if os.name == "posix":
                linked = root / "linked-output"
                linked.symlink_to(output)
                with self.assertRaisesRegex(storage.StorageError, "storage_reparse_point_forbidden"):
                    catalogs.convert_catalogs([source_a], linked, root / "never-linked-report")
                self.assertEqual(output.read_bytes(), saved[0])
                self.assertFalse((root / "never-linked-report").exists())


if __name__ == "__main__":
    unittest.main()
