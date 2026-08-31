#!/usr/bin/env python3
"""Explicit, offline conversion of private Drive artifact inventories.

The portable artifact descriptor is historical evidence about content, not an
attachment or an authorization. Its time is the earliest source-catalog time
for that content in this conversion, never a guessed file-creation timestamp.
Another conversion may create different evidence IDs for the same content;
the shared artifact:sha256 entity associates them without rewriting records.
Locations and source observations retain their own catalog's timestamp.

No Git, Vault, credential provider, network or legacy executable is accessed.
The bundle and report contain PRIVATE metadata and must never enter a public
release. Task identifiers and complete source paths remain in the report only.
An explicit later import/fetch operation still needs normal host authorization.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import os
from pathlib import Path
import re
import sys
from typing import Any, Mapping, Sequence

from memory_vault import (
    BUNDLE_SCHEMA, HASH_PROFILE, MAX_BUNDLE_BYTES, MAX_BUNDLE_LINE_BYTES,
    MAX_BUNDLE_RECORDS, MemoryError, build_record, canonical_bytes, failure,
    sha256, strict_json_loads, success, validate_record, write_response,
)
import memory_vault_storage as storage

DESCRIPTOR_SCHEMA = "universal-memory-artifact-descriptor/v1"
LOCATION_SCHEMA = "universal-memory-artifact-location/v1"
ENTRY_SCHEMA = "universal-memory-artifact-catalog-entry/v1"
REPORT_SCHEMA = "universal-memory-artifact-catalog-report/v1"
RESULT_SCHEMA = "universal-memory-artifact-catalog-result/v1"
MAX_SOURCES = 32
MAX_SOURCE_BYTES = 32 * 1024 * 1024
MAX_TOTAL_SOURCE_BYTES = 64 * 1024 * 1024
MAX_REPORT_BYTES = 64 * 1024 * 1024
MAX_ROWS = 20_000
MAX_ENTRY_BYTES = 512 * 1024
_HASH = re.compile(r"[0-9a-f]{64}")
_DRIVE_ID = re.compile(r"[A-Za-z0-9_-]{2,256}")
_MIME = re.compile(r"[a-z0-9.+-]+/[a-z0-9.+-]{1,100}")
_TYPES = {"zip": "application/zip", "pdf": "application/pdf",
          "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
          "txt": "text/plain", "md": "text/markdown", "json": "application/json",
          "png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg"}


def _path(value: Path) -> Path:
    return storage.validate_path(Path(value).expanduser())


def _fingerprint(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _tree(value: Any) -> None:
    """Bound source JSON without treating arbitrary source keys as commands."""
    count = 0

    def visit(item: Any, depth: int) -> None:
        nonlocal count
        count += 1
        if depth > 24 or count > 1_000_000:
            raise MemoryError("artifact_catalog_structure_limit")
        if item is None or type(item) is bool:
            return
        if type(item) is int:
            if not -(2**63) <= item < 2**63:
                raise MemoryError("artifact_catalog_integer_limit")
        elif isinstance(item, str):
            if "\x00" in item:
                raise MemoryError("artifact_catalog_invalid_text")
            try:
                item.encode("utf-8")
            except UnicodeError:
                raise MemoryError("artifact_catalog_invalid_text") from None
        elif isinstance(item, list):
            for child in item:
                visit(child, depth + 1)
        elif isinstance(item, dict):
            for key, child in item.items():
                visit(key, depth + 1)
                visit(child, depth + 1)
        else:
            raise MemoryError("artifact_catalog_noncanonical_value")

    visit(value, 0)


def _timestamp(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 40:
        raise MemoryError("artifact_catalog_timestamp_required")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError()
        return parsed.astimezone(dt.timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
    except (ValueError, OverflowError):
        raise MemoryError("artifact_catalog_invalid_timestamp") from None


def _read_source(path: Path) -> tuple[dict[str, Any], str, int]:
    storage.check_private_directory(path.parent)
    fd = storage.open_file(path, os.O_RDONLY, private=True)
    with os.fdopen(fd, "rb") as stream:
        before = storage.check_fd(stream.fileno(), private=True)
        if not 1 <= before.st_size <= MAX_SOURCE_BYTES:
            raise MemoryError("artifact_catalog_source_size_limit")
        raw = stream.read(MAX_SOURCE_BYTES + 1)
        after = storage.check_fd(stream.fileno(), private=True)
        if len(raw) != before.st_size or _fingerprint(before) != _fingerprint(after):
            raise MemoryError("artifact_catalog_source_changed")
        if _fingerprint(path.lstat()) != _fingerprint(after):
            raise MemoryError("artifact_catalog_source_changed")
    value = strict_json_loads(raw)
    _tree(value)
    if not isinstance(value, dict):
        raise MemoryError("artifact_catalog_object_required")
    return value, sha256(raw), len(raw)


def _safe_label(value: Any, *, relative_path: bool = False) -> str | None:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 2048:
        return None
    if any(ord(char) < 32 or 127 <= ord(char) < 160 for char in value):
        return None
    if relative_path:
        # Only the visible basename survives. No host path or task hierarchy is
        # added to the portable record, even when present in the private input.
        if value.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", value):
            return None
        parts = value.replace("\\", "/").split("/")
        if any(part in ("", ".", "..") for part in parts) or "://" in value:
            return None
        value = parts[-1]
    if not value.strip() or any(char in value for char in "/\\") or value in (".", ".."):
        return None
    return value


def _labels(entry: Mapping[str, Any]) -> list[str]:
    found: set[str] = set()
    for key in ("display_name", "drive_name"):
        value = _safe_label(entry.get(key))
        if value is not None:
            found.add(value)
    aliases = entry.get("aliases", [])
    if aliases is not None and not isinstance(aliases, list):
        raise MemoryError("artifact_catalog_invalid_aliases")
    for item in [*(aliases or []), entry.get("logical_path"), entry.get("source_relative_path")]:
        value = _safe_label(item, relative_path=True)
        if value is not None:
            found.add(value)
    return sorted(found)


def _normalize(entry: dict[str, Any], schema: str) -> dict[str, Any]:
    if len(canonical_bytes(entry)) > MAX_ENTRY_BYTES:
        raise MemoryError("artifact_catalog_entry_size_limit")
    backup = schema == "artifact-backup-index/v1"
    selected_storage = entry.get("storage", {}) if backup else {}
    if not isinstance(selected_storage, dict):
        raise MemoryError("artifact_catalog_invalid_storage_reference")
    digest = entry.get("content_sha256" if backup else "sha256")
    size = entry.get("size_bytes" if backup else "size")
    reasons: list[str] = []
    if digest is None or digest == "":
        digest = None
        reasons.append("missing_content_sha256")
    elif not isinstance(digest, str) or _HASH.fullmatch(digest) is None:
        digest = None
        reasons.append("invalid_content_sha256")
    if type(size) is not int or not 0 <= size < 2**63:
        size = None
        reasons.append("missing_or_invalid_size")
    references: dict[str, list[str]] = {}
    selected = [("canonical", selected_storage.get("canonical_drive_file_id")),
                ("uploaded", selected_storage.get("uploaded_drive_file_id"))] if backup else [
                    ("imported", entry.get("drive_file_id"))]
    for role, identifier in selected:
        if identifier is None or identifier == "":
            continue
        if not isinstance(identifier, str) or _DRIVE_ID.fullmatch(identifier) is None:
            reasons.append("invalid_drive_file_id_" + role)
        else:
            references.setdefault(identifier, []).append(role)
    if not references:
        reasons.append("missing_drive_file_id")
    parent = selected_storage.get("drive_parent_id") if backup else entry.get("drive_parent_id")
    if not isinstance(parent, str) or _DRIVE_ID.fullmatch(parent) is None:
        parent = None
        reasons.append("missing_or_invalid_drive_parent_id")
    labels = _labels({**entry, **({"drive_name": selected_storage.get("drive_name")} if backup else {})})
    label = _safe_label(entry.get("display_name")) or (labels[0] if labels else "Imported artifact")
    classification = _safe_label(entry.get("classification"))
    mapping = _safe_label(entry.get("mapping_status"))
    # A per-object status can be "exact" while the source catalog's aggregate
    # still reports path ambiguity. Absence of an explicit ambiguity label is
    # unknown, not evidence that a logical path has been disambiguated.
    ambiguous = True if mapping is not None and "ambiguous" in mapping.casefold() else None
    mime = entry.get("mime_type")
    inferred_mime = mime is None
    if mime is None:
        extension = entry.get("extension")
        extension = extension.lower().lstrip(".") if isinstance(extension, str) else ""
        mime = _TYPES.get(extension, "application/octet-stream")
    elif not isinstance(mime, str) or _MIME.fullmatch(mime) is None:
        mime = None
        reasons.append("invalid_mime_type")
    # Provider coordinates do not prove authorization, current byte integrity,
    # path disambiguation, a real author or that the object still exists.
    addressable = digest is not None and size is not None and bool(references)
    historical = {key: selected_storage[key] for key in ("remote_size_verified", "remote_content_checksum")
                  if key in selected_storage and (
                      type(selected_storage[key]) in (bool, int, type(None))
                      or _safe_label(selected_storage[key]) is not None)}
    return {"sha256": digest, "size": size, "references": references, "parent_id": parent,
            "label": label, "labels": labels, "classification": classification,
            "historical_mapping_status": mapping, "logical_path_ambiguous": ambiguous,
            "mime_type": mime, "mime_type_inferred": inferred_mime,
            "addressable": addressable, "reasons": sorted(set(reasons)),
            "historical_verification_claims": historical}


def _record(kind: str, body: Mapping[str, Any], *, source_ref: str, created_at: str,
            entities: Sequence[str], relations: Sequence[Mapping[str, str]] = ()) -> dict[str, Any]:
    record = build_record(kind=kind, text=canonical_bytes(dict(body)).decode("utf-8"),
                          entities=entities, relations=relations, created_at=created_at,
                          provenance={"source_type": "imported", "confidence": "imported", "source_ref": source_ref})
    return validate_record(record)


def _bundle(records: Sequence[Mapping[str, Any]], timestamp: str) -> bytes:
    if len(records) > MAX_BUNDLE_RECORDS:
        raise MemoryError("artifact_catalog_record_limit")
    result = bytearray(canonical_bytes({"type": "header", "schema_version": BUNDLE_SCHEMA,
                                       "created_at": timestamp, "hash_profile": HASH_PROFILE}) + b"\n")
    digest = hashlib.sha256()
    for record in records:
        line = canonical_bytes({"type": "record", "record": record}) + b"\n"
        if len(line) > MAX_BUNDLE_LINE_BYTES:
            raise MemoryError("artifact_catalog_record_size_limit")
        result.extend(line)
        digest.update(str(record["record_sha256"]).encode("ascii") + b"\n")
        if len(result) > MAX_BUNDLE_BYTES:
            raise MemoryError("artifact_catalog_bundle_size_limit")
    result.extend(canonical_bytes({"type": "footer", "record_count": len(records),
                                   "records_sha256": digest.hexdigest()}) + b"\n")
    if len(result) > MAX_BUNDLE_BYTES:
        raise MemoryError("artifact_catalog_bundle_size_limit")
    return bytes(result)


def _new_output(path: Path) -> None:
    _path(path)
    try:
        path.lstat()
    except FileNotFoundError:
        return
    raise MemoryError("artifact_catalog_output_exists")


def convert_catalogs(sources: Sequence[Path], output: Path | None = None,
                     report: Path | None = None, *, dry_run: bool = False) -> Mapping[str, Any]:
    """Convert all selected rows; emit two NEW private files, never auto-import.

    ``dry_run`` reads/hashes the explicit inputs and returns only counts/hashes.
    Missing hashes/coordinates are retained as unresolved provenance records.
    A location is merely structurally addressable, never verified or authorized.
    The report is published first; a later bundle-publication failure may leave
    that report, but no existing destination is overwritten or removed.
    """
    if type(dry_run) is not bool or isinstance(sources, (str, bytes, Path)) or not 1 <= len(sources) <= MAX_SOURCES:
        raise MemoryError("artifact_catalog_sources_required")
    paths = [_path(value) for value in sources]
    if len(set(paths)) != len(paths):
        raise MemoryError("artifact_catalog_duplicate_source_path")
    if not dry_run and (output is None or report is None):
        raise MemoryError("artifact_catalog_output_and_report_required")
    output_path = _path(output) if output is not None else None
    report_path = _path(report) if report is not None else None
    selected_outputs = [path for path in (output_path, report_path) if path is not None]
    if len(set(selected_outputs)) != len(selected_outputs) or any(path in paths for path in selected_outputs):
        raise MemoryError("artifact_catalog_output_path_conflict")
    all_paths = [*paths, *selected_outputs]
    if any(first in second.parents for first in all_paths for second in all_paths):
        raise MemoryError("artifact_catalog_output_path_conflict")
    if not dry_run:
        for path in selected_outputs:
            _new_output(path)

    catalogs: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []
    input_bytes = 0
    sizes: dict[str, int] = {}
    content_times: dict[str, str] = {}
    file_identities: dict[str, tuple[str, int]] = {}
    for path in paths:
        value, source_hash, size = _read_source(path)
        input_bytes += size
        if input_bytes > MAX_TOTAL_SOURCE_BYTES:
            raise MemoryError("artifact_catalog_total_source_limit")
        schema = value.get("schema_version")
        if schema not in ("artifact-backup-index/v1", "drive-import/v1"):
            raise MemoryError("artifact_catalog_unsupported_schema")
        key = "records" if schema == "artifact-backup-index/v1" else "objects"
        timestamp = _timestamp(value.get("created_at" if key == "records" else "recorded_at"))
        entries = value.get(key)
        if not isinstance(entries, list) or len(rows) + len(entries) > MAX_ROWS:
            raise MemoryError("artifact_catalog_row_limit")
        catalogs.append({"source_catalog_sha256": source_hash, "source_bytes": size,
                         "schema_version": schema, "source_path": str(path), "created_at": timestamp,
                         "row_count": len(entries), "original_metadata": {name: child for name, child in value.items() if name != key}})
        for ordinal, entry in enumerate(entries):
            if not isinstance(entry, dict):
                raise MemoryError("artifact_catalog_entry_object_required")
            normalized = _normalize(entry, schema)
            digest, byte_count = normalized["sha256"], normalized["size"]
            if digest is not None and byte_count is not None:
                if digest in sizes and sizes[digest] != byte_count:
                    raise MemoryError("artifact_catalog_sha256_size_conflict")
                sizes[digest] = byte_count
                content_times[digest] = min(content_times.get(digest, timestamp), timestamp)
                for identifier in normalized["references"]:
                    identity = (digest, byte_count)
                    if identifier in file_identities and file_identities[identifier] != identity:
                        raise MemoryError("artifact_catalog_drive_identity_conflict")
                    file_identities[identifier] = identity
            rows.append({"source_catalog_sha256": source_hash, "source_entry_sha256": sha256(canonical_bytes(entry)),
                         "source_entry_index": ordinal, "created_at": timestamp,
                         "original_entry": entry, "normalized": normalized})

    descriptors: dict[str, dict[str, Any]] = {}
    records: dict[str, dict[str, Any]] = {}
    for digest, byte_count in sorted(sizes.items()):
        entity = "artifact:sha256:" + digest
        record = _record("artifact", {"schema_version": DESCRIPTOR_SCHEMA, "sha256": digest, "size": byte_count},
                         source_ref=entity, created_at=content_times[digest], entities=[entity])
        descriptors[digest] = record
        records[record["memory_id"]] = record
    addresses: set[tuple[str, str, str | None, str, int]] = set()
    locator_ids: set[str] = set()
    evidence_ids: set[str] = set()
    report_rows: list[dict[str, Any]] = []
    unresolved = 0
    for row in sorted(rows, key=lambda item: (item["source_catalog_sha256"], item["source_entry_index"])):
        item = row["normalized"]
        descriptor = descriptors.get(item["sha256"]) if item["size"] is not None else None
        entity = "artifact:sha256:" + item["sha256"] if item["sha256"] is not None else "artifact:unresolved"
        source_ref = "artifact-catalog:sha256:" + row["source_catalog_sha256"]
        origin = {key: row[key] for key in ("source_catalog_sha256", "source_entry_sha256", "source_entry_index")}
        hints = {key: item[key] for key in ("label", "labels", "classification", "historical_mapping_status", "logical_path_ambiguous")}
        locations: list[str] = []
        if item["addressable"]:
            assert descriptor is not None
            for identifier, roles in sorted(item["references"].items()):
                body = {"schema_version": LOCATION_SCHEMA, "provider": "google-drive", "file_id": identifier,
                        "parent_id": item["parent_id"], "sha256": item["sha256"], "size": item["size"],
                        "mime_type": item["mime_type"], "mime_type_inferred": item["mime_type_inferred"],
                        "reference_roles": roles, "current_content_verified": False,
                        "author_authenticated": False, "requires_configured_authorization": True, **hints, **origin}
                record = _record("provenance", body, source_ref=source_ref, created_at=row["created_at"],
                                 entities=[entity], relations=[{"type": "related_to", "target": descriptor["memory_id"]}])
                records[record["memory_id"]] = record
                locations.append(record["memory_id"])
                locator_ids.add(record["memory_id"])
                addresses.add(("google-drive", identifier, item["parent_id"], item["sha256"], item["size"]))
        else:
            unresolved += 1
        body = {"schema_version": ENTRY_SCHEMA, "status": "located_unverified" if locations else "unresolved",
                "sha256": item["sha256"], "size": item["size"], "reasons": item["reasons"],
                "artifact_memory_id": descriptor["memory_id"] if descriptor else None,
                "locator_memory_ids": locations, "current_content_verified": False,
                "author_authenticated": False, "historical_claims_are_verification": False,
                "historical_verification_claims": item["historical_verification_claims"], **hints, **origin}
        relations = ([{"type": "related_to", "target": descriptor["memory_id"]}] if descriptor else []) + [
            {"type": "related_to", "target": identity} for identity in locations]
        evidence = _record("provenance", body, source_ref=source_ref, created_at=row["created_at"],
                           entities=[entity], relations=relations)
        records[evidence["memory_id"]] = evidence
        evidence_ids.add(evidence["memory_id"])
        report_rows.append({**origin, "original_entry": row["original_entry"], "status": body["status"],
                            "reasons": item["reasons"], "artifact_memory_id": body["artifact_memory_id"],
                            "locator_memory_ids": locations, "evidence_memory_id": evidence["memory_id"]})

    counts = {"input_catalogs": len(catalogs), "unique_catalogs": len({item["source_catalog_sha256"] for item in catalogs}),
              "catalog_rows": len(rows), "unique_contents": len(descriptors), "unique_locations": len(addresses),
              "unique_drive_file_ids": len({address[1] for address in addresses}),
              "artifact_records": len(descriptors), "locator_records": len(locator_ids),
              "source_evidence_records": len(evidence_ids), "bundle_records": len(records),
              "located_rows": len(rows) - unresolved, "unresolved_rows": unresolved,
              "logical_path_ambiguous_rows": sum(bool(row["normalized"]["logical_path_ambiguous"]) for row in rows)}
    timestamp = min(item["created_at"] for item in catalogs)
    bundle_raw = _bundle(list(records.values()), timestamp)
    report_value = {"schema_version": REPORT_SCHEMA, "private_metadata_included": True,
                    "task_ownership_created": False, "git_required": False,
                    "source_catalogs": sorted(catalogs, key=lambda item: (item["source_catalog_sha256"], item["source_path"])),
                    "entries": report_rows, "counts": counts, "bundle_sha256": sha256(bundle_raw),
                    "bundle_bytes": len(bundle_raw), "records_imported": False,
                    "current_content_verified": False, "author_authenticated": False}
    report_raw = canonical_bytes(report_value) + b"\n"
    if len(report_raw) > MAX_REPORT_BYTES:
        raise MemoryError("artifact_catalog_report_size_limit")
    result = {"schema_version": RESULT_SCHEMA, "state": "dry_run" if dry_run else "converted_private_files",
              "counts": counts, "source_catalog_sha256": sorted({item["source_catalog_sha256"] for item in catalogs}),
              "bundle_sha256": sha256(bundle_raw), "bundle_bytes": len(bundle_raw),
              "report_sha256": sha256(report_raw), "report_bytes": len(report_raw),
              "network_accessed": False, "vault_accessed": False, "records_imported": False,
              "files_downloaded": 0, "current_content_verified": False, "signatures_included": False,
              "private_metadata_included": True, "task_ownership_created": False}
    if not dry_run:
        assert output_path is not None and report_path is not None
        # Both names are checked before either file is published; each atomic
        # no-replace publication also independently defeats an intervening race.
        for path in (report_path, output_path):
            _new_output(path)
            storage.private_directory(path.parent)
        storage.atomic_write(report_path, report_raw, replace=False)
        try:
            storage.atomic_write(output_path, bundle_raw, replace=False)
        except OSError:
            raise MemoryError("artifact_catalog_bundle_publication_failed_report_retained") from None
        result["output"] = str(output_path)
        result["report"] = str(report_path)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Convert explicitly selected private artifact catalogs; no cloud access or import.")
    parser.add_argument("--source", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = convert_catalogs(args.source, args.output, args.report, dry_run=args.dry_run)
        write_response(success(result))
        return 0
    except MemoryError as exc:
        write_response(failure(exc.code, retryable=exc.retryable))
    except storage.StorageError as exc:
        write_response(failure(exc.code, retryable=exc.retryable))
    except FileExistsError:
        write_response(failure("artifact_catalog_output_exists"))
    except (OSError, ValueError, TypeError):
        write_response(failure("artifact_catalog_operation_failed"))
    return 1


if __name__ == "__main__":
    sys.exit(main())
