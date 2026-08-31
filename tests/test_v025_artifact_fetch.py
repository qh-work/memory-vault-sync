"""One synthetic migrate/select/fetch flow, with HTTP and OS secrets simulated.

The real converter, canonical selection, DriveClient OAuth/root/range logic,
private files, progress journal, partial recovery and final SHA-256 are used.
Only DriveClient._wire and its explicit OS credential getter are replaced.
This is NOT a real Google Drive, OAuth, Keychain, network or crash experiment.
All catalog entries, names, IDs and credential strings are invented fixtures.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import tempfile
import time
import unittest
from unittest.mock import patch
import urllib.parse

import memory_vault_artifact_catalog as catalogs
import memory_vault_artifacts as artifacts
import memory_vault_drive as drive
import memory_vault_storage as storage
from memory_vault import MemoryError, canonical_bytes, strict_json_loads


class ArtifactFetchTests(unittest.TestCase):
    def test_migrated_locator_resumes_verifies_and_rejects_unsafe_transitions(self) -> None:
        payload = b"First synthetic segment. Second synthetic segment."
        expected_hash = hashlib.sha256(payload).hexdigest()
        first_count = 13
        fixture_root, fixture_folder, fixture_file = "fixture_root", "fixture_folder", "fixture_file"
        reference = {"kind": "macos-generic", "service": "synthetic-memory-fixture", "account": "fixture-oauth"}
        provider = {"version": "1", "outside": False, "change_after_range": False, "corrupt_range": False}
        wire_calls: list[tuple[str, str]] = []
        ranges: list[tuple[str, int, int]] = []
        created: dict[str, dict] = {}

        def folder(identifier: str, parents: list[str]) -> dict:
            return {"id": identifier, "name": "synthetic-folder", "mimeType": drive.FOLDER_MIME,
                    "parents": parents, "trashed": False, "version": "1"}

        def file_metadata(identifier: str, data: bytes, *, name: str, parent: str, version: str) -> dict:
            return {"id": identifier, "name": name, "mimeType": "application/octet-stream",
                    "parents": [parent], "size": str(len(data)), "version": version,
                    "sha256Checksum": hashlib.sha256(data).hexdigest(), "trashed": False,
                    "capabilities": {"canDownload": True}}

        def wire(instance, url: str, *, method: str, body: bytes | None,
                 headers: dict, maximum: int) -> tuple[int, dict[str, str], bytes]:
            del instance
            wire_calls.append((method, url))
            parsed = urllib.parse.urlsplit(url)
            query = urllib.parse.parse_qs(parsed.query)
            response_headers: dict[str, str] = {}
            status = 200
            if url == drive.TOKEN_URL:
                self.assertEqual(method, "POST")
                self.assertIsNotNone(body)
                form = urllib.parse.parse_qs(body.decode("ascii"))
                self.assertEqual(form, {"client_id": ["fixture-desktop-client"],
                    "refresh_token": ["fixture-refresh-token"], "client_secret": ["fixture-client-secret"],
                    "grant_type": ["refresh_token"]})
                data = canonical_bytes({"access_token": "fixture-access-token", "expires_in": 3600, "token_type": "Bearer"})
            else:
                self.assertEqual(headers.get("Authorization"), "Bearer fixture-access-token")
                self.assertEqual(parsed.scheme, "https")
                self.assertEqual(parsed.netloc, "www.googleapis.com")
                if parsed.path == "/upload/drive/v3/files":
                    self.assertEqual(method, "POST")
                    self.assertEqual(query.get("uploadType"), ["multipart"])
                    boundary = headers["Content-Type"].split("boundary=", 1)[1].encode("ascii")
                    parts = body.split(b"--" + boundary)
                    self.assertEqual(len(parts), 4)
                    document = strict_json_loads(parts[1].split(b"\r\n\r\n", 1)[1][:-2])
                    uploaded_bytes = parts[2].split(b"\r\n\r\n", 1)[1][:-2]
                    self.assertEqual(document["parents"], [fixture_folder])
                    metadata = file_metadata("fixture_uploaded", uploaded_bytes, name=document["name"],
                                             parent=fixture_folder, version="1")
                    self.assertEqual(document["mimeType"], metadata["mimeType"])
                    created["fixture_uploaded"] = {"metadata": metadata, "data": uploaded_bytes}
                    data = canonical_bytes(metadata)
                    status = 201
                elif parsed.path == "/drive/v3/files":
                    self.assertEqual(method, "GET")
                    self.assertIn(fixture_folder, query.get("q", [""])[0])
                    data = canonical_bytes({"files": []})
                else:
                    self.assertEqual(method, "GET")
                    self.assertTrue(parsed.path.startswith("/drive/v3/files/"))
                    identifier = parsed.path.rsplit("/", 1)[1]
                    if query.get("alt") == ["media"]:
                        original = created[identifier]["data"] if identifier in created else payload
                        self.assertIn(identifier, (fixture_file, "fixture_uploaded"))
                        match = re.fullmatch(r"bytes=([0-9]+)-([0-9]+)", headers.get("Range", ""))
                        self.assertIsNotNone(match)
                        start, end = (int(value) for value in match.groups())
                        self.assertTrue(0 <= start <= end < len(original))
                        data = original[start:end + 1]
                        self.assertEqual(maximum, len(data))
                        ranges.append((identifier, start, len(data)))
                        if provider["corrupt_range"]:
                            data = bytes([data[0] ^ 1]) + data[1:]
                        if provider["change_after_range"]:
                            provider["version"] = "2"
                        status = 206
                        response_headers["content-range"] = f"bytes {start}-{end}/{len(original)}"
                    elif identifier == fixture_root:
                        data = canonical_bytes(folder(fixture_root, []))
                    elif identifier == fixture_folder:
                        data = canonical_bytes(folder(fixture_folder, [fixture_root]))
                    elif identifier == "fixture_outside":
                        data = canonical_bytes(folder(identifier, []))
                    elif identifier in created:
                        data = canonical_bytes(created[identifier]["metadata"])
                    else:
                        self.assertEqual(identifier, fixture_file)
                        data = canonical_bytes(file_metadata(fixture_file, payload, name="synthetic-object.bin",
                            parent="fixture_outside" if provider["outside"] else fixture_folder,
                            version=provider["version"]))
            self.assertLessEqual(len(data), maximum)
            return status, response_headers, data

        with tempfile.TemporaryDirectory(prefix="memory-artifact-fetch-synthetic-") as temporary:
            root = Path(temporary).resolve()
            source, bundle, report, selection = (root / name for name in (
                "source.json", "bundle.ndjson", "report.json", "selected.json"))
            inventory = {"schema_version": "drive-import/v1", "recorded_at": "2034-03-04T05:06:07Z",
                "drive_root_id": fixture_root, "objects": [{"drive_file_id": fixture_file,
                    # Historical parent differs deliberately: the real provider
                    # must prove the current ancestor chain under the config root.
                    "drive_parent_id": "fixture_historical_parent", "display_name": "synthetic-object.bin",
                    "size": len(payload), "sha256": expected_hash, "mime_type": "application/octet-stream",
                    "mapping_status": "path_ambiguous", "aliases": ["old/synthetic-alias.bin"]}]}
            storage.atomic_write(source, canonical_bytes(inventory), replace=False)
            converted = catalogs.convert_catalogs([source], bundle, report)
            self.assertEqual(converted["counts"]["located_rows"], 1)
            mapping = strict_json_loads(report.read_bytes())
            memory_id = mapping["entries"][0]["locator_memory_ids"][0]
            selected = artifacts.select_location(bundle, memory_id, selection)
            self.assertFalse(selected["network_accessed"])
            self.assertEqual(strict_json_loads(selection.read_bytes())["memory_id"], memory_id)
            config = root / "drive.json"
            storage.atomic_write(config, canonical_bytes({"schema_version": drive.CONFIG_SCHEMA,
                "root_folder_id": fixture_root, "oauth_client_id": "fixture-desktop-client",
                "credential_ref": reference}), replace=False)

            def paths(name: str) -> tuple[Path, Path, Path]:
                output = root / (name + ".bin")
                return output, root / (name + ".journal"), root / ("." + output.name + ".memory-vault-part")

            def fetch(output: Path, journal: Path, amount: int) -> dict:
                return dict(artifacts.fetch_artifact(config, selection, output, journal,
                                                     maximum_bytes=amount, maximum_seconds=30))

            with patch.object(drive.DriveClient, "_wire", new=wire), patch.object(drive, "config_password", return_value=
                    canonical_bytes({"refresh_token": "fixture-refresh-token", "client_secret": "fixture-client-secret"}).decode("utf-8")) as getter:
                output, journal, partial = paths("good")
                first = fetch(output, journal, first_count)
                self.assertFalse(first["complete"])
                self.assertEqual(first["downloaded_this_call"], first_count)
                self.assertFalse(output.exists())
                self.assertEqual(partial.read_bytes(), payload[:first_count])
                saved = strict_json_loads(journal.read_bytes())
                self.assertEqual(saved["offset"], first_count)
                self.assertEqual(saved["chunks"][0]["sha256"], hashlib.sha256(payload[:first_count]).hexdigest())
                second = fetch(output, journal, len(payload) - first_count)
                self.assertTrue(second["complete"])
                self.assertTrue(second["content_sha256_verified"])
                self.assertEqual(output.read_bytes(), payload)
                self.assertEqual(hashlib.sha256(output.read_bytes()).hexdigest(), expected_hash)
                self.assertFalse(partial.exists())
                self.assertEqual(ranges, [(fixture_file, 0, first_count), (fixture_file, first_count, len(payload) - first_count)])
                before = (len(wire_calls), getter.call_count)
                repeated = fetch(output, journal, first_count)
                self.assertTrue(repeated["complete"])
                self.assertEqual(repeated["downloaded_this_call"], 0)
                self.assertFalse(repeated["remote_metadata_checked_this_call"])
                self.assertFalse(repeated["remote_latest_proven"])
                self.assertEqual((len(wire_calls), getter.call_count), before)
                self.assertEqual(getter.call_args.args[0], reference)

                # Model an unacknowledged local tail without pretending to
                # reproduce a real process/power failure. Its validation must
                # respect this call's byte budget before it is journaled.
                tail_output, tail_journal, tail_partial = paths("unacknowledged")
                fetch(tail_output, tail_journal, first_count)
                fd = storage.open_file(tail_partial, os.O_WRONLY | os.O_APPEND, private=True)
                with os.fdopen(fd, "ab") as stream:
                    stream.write(payload[first_count:first_count + 5])
                    stream.flush()
                progress_before = tail_journal.read_bytes()
                range_count = len(ranges)
                with self.assertRaisesRegex(MemoryError, "artifact_resume_budget_too_small"):
                    fetch(tail_output, tail_journal, 2)
                self.assertEqual(len(ranges), range_count)
                self.assertEqual(tail_journal.read_bytes(), progress_before)
                self.assertEqual(tail_partial.read_bytes(), payload[:first_count + 5])
                adopted = fetch(tail_output, tail_journal, len(payload))
                self.assertTrue(adopted["complete"])
                self.assertEqual(tail_output.read_bytes(), payload)
                self.assertFalse(tail_partial.exists())

                damaged_output, damaged_journal, damaged_partial = paths("damaged")
                fetch(damaged_output, damaged_journal, first_count)
                progress_before = damaged_journal.read_bytes()
                fd = storage.open_file(damaged_partial, os.O_RDWR, private=True)
                with os.fdopen(fd, "r+b") as stream:
                    stream.write(b"!")
                    stream.flush()
                    os.fsync(stream.fileno())
                range_count = len(ranges)
                with self.assertRaisesRegex(MemoryError, "artifact_partial_conflict"):
                    fetch(damaged_output, damaged_journal, len(payload))
                self.assertFalse(damaged_output.exists())
                self.assertEqual(damaged_journal.read_bytes(), progress_before)
                self.assertEqual(len(ranges), range_count)
                self.assertEqual(damaged_partial.read_bytes(), b"!" + payload[1:first_count])

                changed_output, changed_journal, changed_partial = paths("changed")
                fetch(changed_output, changed_journal, first_count)
                provider["change_after_range"] = True
                with self.assertRaisesRegex(MemoryError, "artifact_remote_version_changed"):
                    fetch(changed_output, changed_journal, len(payload))
                self.assertFalse(changed_output.exists())
                self.assertEqual(changed_partial.read_bytes(), payload)
                self.assertEqual(strict_json_loads(changed_journal.read_bytes())["remote_version"], "1")
                provider["change_after_range"] = False
                range_count = len(ranges)
                with self.assertRaisesRegex(MemoryError, "artifact_remote_version_changed"):
                    fetch(changed_output, changed_journal, len(payload))
                self.assertEqual(len(ranges), range_count)
                provider["version"] = "1"

                bad_output, bad_journal, bad_partial = paths("bad-hash")
                provider["corrupt_range"] = True
                with self.assertRaisesRegex(MemoryError, "artifact_content_mismatch"):
                    fetch(bad_output, bad_journal, len(payload))
                self.assertFalse(bad_output.exists())
                self.assertTrue(bad_partial.exists())
                self.assertNotEqual(hashlib.sha256(bad_partial.read_bytes()).hexdigest(), expected_hash)
                self.assertNotEqual(strict_json_loads(bad_journal.read_bytes())["phase"], "complete")
                provider["corrupt_range"] = False

                unknown_output, unknown_journal, _ = paths("unknown")
                storage.atomic_write(unknown_output, b"existing unrelated fixture", replace=False)
                call_count = len(wire_calls)
                with self.assertRaisesRegex(MemoryError, "artifact_output_exists_without_journal"):
                    fetch(unknown_output, unknown_journal, len(payload))
                self.assertEqual(unknown_output.read_bytes(), b"existing unrelated fixture")
                self.assertFalse(unknown_journal.exists())
                self.assertEqual(len(wire_calls), call_count)

                outside_output, outside_journal, outside_partial = paths("outside")
                provider["outside"] = True
                range_count = len(ranges)
                with self.assertRaisesRegex(MemoryError, "drive_object_outside_root"):
                    fetch(outside_output, outside_journal, len(payload))
                self.assertFalse(outside_output.exists())
                self.assertFalse(outside_journal.exists())
                self.assertFalse(outside_partial.exists())
                self.assertEqual(len(ranges), range_count)
                provider["outside"] = False

                # One small new object also uses the real upload MIME framing,
                # exact metadata checks and range reader over the simulated wire.
                client = drive.DriveClient(drive.DriveConfig.from_file(config), deadline=time.monotonic() + 30)
                upload_data = b"synthetic-new-cloud-object"
                uploaded = client.upload_bytes(fixture_folder, "synthetic-new.bin", upload_data)
                self.assertEqual(uploaded["id"], "fixture_uploaded")
                self.assertEqual(created["fixture_uploaded"]["data"], upload_data)
                observed = client.read_range(uploaded["id"], 0, len(upload_data))
                self.assertEqual(observed, upload_data)
                self.assertEqual(hashlib.sha256(observed).hexdigest(), uploaded["sha256Checksum"])


if __name__ == "__main__":
    unittest.main()
