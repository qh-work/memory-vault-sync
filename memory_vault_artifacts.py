#!/usr/bin/env python3
"""Explicit artifact migration and bounded original-byte retrieval.

An artifact location is evidence, never permission to access a provider. Only
the operator's separate local Drive configuration selects credentials and root.
These operations are not exposed by recall, hooks, or the memory protocol.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import time
from typing import Any, Mapping, Sequence

from memory_vault import MemoryError, Vault, canonical_bytes, failure, strict_json_loads, success, validate_record, write_response
from memory_vault_file_copy import _fingerprint, _open_checked, _path_digest, _stable
import memory_vault_storage as storage

LOCATION_SCHEMA = "universal-memory-artifact-location/v1"
JOURNAL_SCHEMA = "memory-vault-artifact-download/v1"
CHUNK_BYTES = 4 * 1024 * 1024
MAX_JOURNAL_BYTES = 16 * 1024 * 1024
MAX_LOCATION_BYTES = 1024 * 1024
MAX_CHUNKS = 150000
_HEX = re.compile(r"[0-9a-f]{64}")
_ID = re.compile(r"[A-Za-z0-9_-]{1,256}")


def _read_json(path: Path, maximum: int) -> Any:
    with _open_checked(storage.validate_path(path), private=True) as (stream, fingerprint):
        if fingerprint[4] > maximum:
            raise MemoryError("artifact_metadata_too_large")
        raw = stream.read(maximum + 1)
        if len(raw) > maximum:
            raise MemoryError("artifact_metadata_too_large")
        return strict_json_loads(raw)


def location(value: Any) -> dict[str, Any]:
    """Extract only passive object identity; ignore no execution/config fields."""
    if isinstance(value, dict) and "memory_id" in value:
        record = validate_record(value)
        if record["kind"] != "provenance":
            raise MemoryError("artifact_location_record_required")
        value = strict_json_loads(record["text"])
    required = {"schema_version", "provider", "file_id", "parent_id", "sha256", "size"}
    optional = {"mime_type", "mime_type_inferred", "label", "labels", "source_catalog_sha256", "source_entry_sha256", "source_entry_index",
                "aliases", "classification", "historical_mapping_status", "mapping_status",
                "historical_verification", "locator_role", "path_ambiguous", "logical_path_ambiguous",
                "reference_roles", "current_content_verified", "author_authenticated", "requires_configured_authorization"}
    if (not isinstance(value, dict) or not required.issubset(value)
            or not set(value).issubset(required | optional)
            or value["schema_version"] != LOCATION_SCHEMA or value["provider"] != "google-drive"
            or not isinstance(value["file_id"], str) or _ID.fullmatch(value["file_id"]) is None
            or value["parent_id"] is not None and (not isinstance(value["parent_id"], str) or _ID.fullmatch(value["parent_id"]) is None)
            or not isinstance(value["sha256"], str) or _HEX.fullmatch(value["sha256"]) is None
            or type(value["size"]) is not int or not 0 <= value["size"] < 2**63):
        raise MemoryError("invalid_artifact_location")
    # Retain only exact byte/object identity for a download binding. Display
    # aliases, historical mapping claims and URLs never choose a local path.
    return {key: value[key] for key in sorted(required)}


def select_location(bundle: Path, memory_id: str, output: Path) -> Mapping[str, Any]:
    bundle, output = storage.validate_path(bundle), storage.validate_path(output)
    if bundle == output or not re.fullmatch(r"mem_[0-9a-f]{40}", memory_id):
        raise MemoryError("invalid_artifact_selection")
    chosen: dict[str, Any] | None = None

    def visit(record: Mapping[str, Any]) -> None:
        nonlocal chosen
        if record["memory_id"] == memory_id:
            location(record)
            chosen = dict(record)

    with _open_checked(bundle, private=True):
        # Checks the full bundle footer and each canonical record, without
        # constructing a Vault, importing data, or trusting an author.
        Vault._scan_bundle(bundle, visitor=visit)
    if chosen is None:
        raise MemoryError("artifact_location_not_found")
    encoded = canonical_bytes(chosen) + b"\n"
    storage.atomic_write(output, encoded, replace=False)
    return {"state": "selected", "memory_id": memory_id,
            "selection_sha256": hashlib.sha256(encoded).hexdigest(),
            "publisher_signature_verified": False, "network_accessed": False}


def _check_time(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise MemoryError("artifact_time_budget_exceeded", retryable=True)


def _digest(stream: Any, size: int, deadline: float) -> str:
    stream.seek(0)
    remaining, digest = size, hashlib.sha256()
    while remaining:
        _check_time(deadline)
        data = stream.read(min(CHUNK_BYTES, remaining))
        if not data:
            raise MemoryError("artifact_local_file_changed")
        digest.update(data)
        remaining -= len(data)
    if stream.read(1):
        raise MemoryError("artifact_local_file_changed")
    return digest.hexdigest()


def _journal(path: Path) -> dict[str, Any] | None:
    try:
        value = _read_json(path, MAX_JOURNAL_BYTES)
    except FileNotFoundError:
        return None
    fields = {"schema_version", "binding", "sha256", "size", "offset", "phase",
              "fingerprint", "chunks", "remote_version"}
    if (not isinstance(value, dict) or set(value) != fields or value["schema_version"] != JOURNAL_SCHEMA
            or not isinstance(value["binding"], str) or _HEX.fullmatch(value["binding"]) is None
            or not isinstance(value["sha256"], str) or _HEX.fullmatch(value["sha256"]) is None
            or type(value["size"]) is not int or not 0 <= value["size"] < 2**63
            or type(value["offset"]) is not int or not 0 <= value["offset"] <= value["size"]
            or value["phase"] not in {"downloading", "verified", "complete"}
            or not isinstance(value["remote_version"], str) or not re.fullmatch(r"[0-9]{1,30}", value["remote_version"])
            or not isinstance(value["chunks"], list) or len(value["chunks"]) > MAX_CHUNKS):
        raise MemoryError("invalid_artifact_journal")
    total = 0
    for chunk in value["chunks"]:
        if (not isinstance(chunk, dict) or set(chunk) != {"size", "sha256"}
                or type(chunk["size"]) is not int or not 1 <= chunk["size"] <= CHUNK_BYTES
                or not isinstance(chunk["sha256"], str) or _HEX.fullmatch(chunk["sha256"]) is None):
            raise MemoryError("invalid_artifact_journal")
        total += chunk["size"]
    fingerprint = value["fingerprint"]
    if (total != value["offset"] or (value["phase"] != "downloading" and total != value["size"])
            or (fingerprint is None and total != 0)
            or fingerprint is not None and (not isinstance(fingerprint, list) or len(fingerprint) != 7
                or any(type(item) is not int for item in fingerprint) or fingerprint[4] != total)):
        raise MemoryError("invalid_artifact_journal")
    return value


def _save(path: Path, state: Mapping[str, Any], *, replace: bool = True) -> None:
    raw = canonical_bytes(state) + b"\n"
    if len(raw) > MAX_JOURNAL_BYTES:
        raise MemoryError("artifact_journal_capacity_exceeded")
    storage.atomic_write(path, raw, replace=replace)


def _metadata(client: Any, source: Mapping[str, Any]) -> Mapping[str, Any]:
    value = client.metadata(source["file_id"])
    if (value.get("id") != source["file_id"] or value.get("trashed", False)
            or value.get("size") != str(source["size"])
            or str(value.get("mimeType", "")).startswith("application/vnd.google-apps.")
            or not isinstance(value.get("version"), str) or not re.fullmatch(r"[0-9]{1,30}", value["version"])
            or value.get("sha256Checksum", source["sha256"]) != source["sha256"]):
        raise MemoryError("artifact_remote_identity_mismatch")
    # The catalog parent is historical location evidence, not authority. The
    # Drive client independently proves the CURRENT ancestry is inside its
    # configured root, including when a file moved within that permitted root.
    return value


def _result(state: Mapping[str, Any], downloaded: int, *, remote_checked: bool) -> Mapping[str, Any]:
    return {"state": "complete" if state["phase"] == "complete" else "partial",
            "sha256": state["sha256"], "size": state["size"], "received_bytes": state["offset"],
            "downloaded_this_call": downloaded, "complete": state["phase"] == "complete",
            "content_sha256_verified": state["phase"] == "complete",
            "remote_metadata_checked_this_call": remote_checked,
            "remote_latest_proven": False,
            "publisher_signature_verified": False, "memory_imported": False,
            "artifact_executed": False}


def _finish(output: Path, partial: Path, journal: Path, state: dict[str, Any], deadline: float) -> None:
    if output.exists() and partial.exists():
        raise MemoryError("artifact_output_conflict")
    selected = output if output.exists() else partial
    with _open_checked(selected, private=True) as (stream, fingerprint):
        if fingerprint[4] != state["size"]:
            raise MemoryError("artifact_output_conflict")
        if state["phase"] == "downloading" or state["fingerprint"] != fingerprint:
            if _digest(stream, state["size"], deadline) != state["sha256"]:
                raise MemoryError("artifact_content_mismatch")
        _stable(selected, stream, fingerprint, private=True)
        state.update(phase="verified", fingerprint=fingerprint)
    _save(journal, state)
    if selected == partial:
        storage.publish_file(partial, output, replace=False)
    with _open_checked(output, private=True) as (_, fingerprint):
        state.update(phase="complete", fingerprint=fingerprint)
    _save(journal, state)


def fetch_artifact(drive_config: Path, locator: Path, output: Path, journal: Path, *,
                   maximum_bytes: int = 128 * 1024 * 1024, maximum_seconds: int = 60) -> Mapping[str, Any]:
    """One finite window; repeat the same explicit request to resume safely."""
    from memory_vault_drive import DriveClient, DriveConfig

    if (type(maximum_bytes) is not int or not 1 <= maximum_bytes <= 256 * 1024 * 1024
            or type(maximum_seconds) is not int or not 1 <= maximum_seconds <= 300):
        raise MemoryError("invalid_artifact_budget")
    drive_config, locator, output, journal = (storage.validate_path(path) for path in (drive_config, locator, output, journal))
    partial = output.with_name("." + output.name + ".memory-vault-part")
    lock = journal.with_name(journal.name + ".lock")
    paths = [drive_config, locator, output, journal, partial, lock]
    if len(set(paths)) != len(paths) or any(a in b.parents for a in paths for b in paths if a != b):
        raise MemoryError("artifact_path_conflict")
    source = location(_read_json(locator, MAX_LOCATION_BYTES))
    config = DriveConfig.from_file(drive_config)
    deadline = time.monotonic() + maximum_seconds
    binding = hashlib.sha256(canonical_bytes({"source": source,
        "root": config.root_folder_id, "output": _path_digest(output),
        "journal": _path_digest(journal), "partial": _path_digest(partial)})).hexdigest()
    storage.private_directory(output.parent)
    storage.private_directory(journal.parent)
    with storage.file_lock(lock, busy_code="artifact_download_busy"):
        state = _journal(journal)
        if state is not None and (state["binding"] != binding or state["sha256"] != source["sha256"] or state["size"] != source["size"]):
            raise MemoryError("artifact_journal_binding_mismatch")
        if state is None and (output.exists() or partial.exists()):
            raise MemoryError("artifact_output_exists_without_journal")
        if state is not None and state["phase"] in {"verified", "complete"}:
            _finish(output, partial, journal, state, deadline)
            return _result(state, 0, remote_checked=False)
        if output.exists():
            raise MemoryError("artifact_output_conflict")
        client = DriveClient(config, deadline=deadline, active_check=lambda: _check_time(deadline))
        metadata = _metadata(client, source)
        if state is not None and state["remote_version"] != metadata["version"]:
            raise MemoryError("artifact_remote_version_changed")
        if state is None:
            state = {"schema_version": JOURNAL_SCHEMA, "binding": binding,
                "sha256": source["sha256"], "size": source["size"], "offset": 0,
                "phase": "downloading", "fingerprint": None, "chunks": [], "remote_version": metadata["version"]}
            _save(journal, state, replace=False)
        if not partial.exists() and state["offset"]:
            raise MemoryError("artifact_partial_missing")
        downloaded = 0
        with _open_checked(partial, writable=True, create=not partial.exists(), private=True) as (stream, fingerprint):
            if not state["offset"] <= fingerprint[4] <= min(state["size"], state["offset"] + CHUNK_BYTES):
                raise MemoryError("artifact_partial_conflict")
            if fingerprint != state["fingerprint"]:
                # Normal exact retries skip the committed prefix entirely.
                # Changed local files require their saved chunk hashes; only
                # an unacknowledged crash tail is fetched again from Drive.
                stream.seek(0)
                for chunk in state["chunks"]:
                    _check_time(deadline)
                    observed = stream.read(chunk["size"])
                    if len(observed) != chunk["size"] or hashlib.sha256(observed).hexdigest() != chunk["sha256"]:
                        raise MemoryError("artifact_partial_conflict")
                tail = fingerprint[4] - state["offset"]
                if tail:
                    if len(state["chunks"]) >= MAX_CHUNKS:
                        raise MemoryError("artifact_journal_capacity_exceeded")
                    if tail > maximum_bytes:
                        raise MemoryError("artifact_resume_budget_too_small", retryable=True)
                    expected = client.read_range(source["file_id"], state["offset"], tail)
                    if len(expected) != tail or stream.read(tail) != expected:
                        raise MemoryError("artifact_partial_conflict")
                    # The interrupted writer may have flushed without fsync.
                    # Make the adopted bytes durable before their receipt.
                    stream.flush()
                    os.fsync(stream.fileno())
                    state["chunks"].append({"size": tail, "sha256": hashlib.sha256(expected).hexdigest()})
                    state["offset"] += tail
                    downloaded += tail
                _stable(partial, stream, fingerprint, private=True)
            state["fingerprint"] = fingerprint
            _save(journal, state)
            while state["offset"] < state["size"] and downloaded < maximum_bytes:
                _check_time(deadline)
                if len(state["chunks"]) >= MAX_CHUNKS:
                    raise MemoryError("artifact_journal_capacity_exceeded")
                count = min(CHUNK_BYTES, state["size"] - state["offset"], maximum_bytes - downloaded)
                data = client.read_range(source["file_id"], state["offset"], count)
                if len(data) != count:
                    raise MemoryError("artifact_remote_short_read", retryable=True)
                _stable(partial, stream, state["fingerprint"], private=True)
                stream.seek(state["offset"])
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
                state["chunks"].append({"size": count, "sha256": hashlib.sha256(data).hexdigest()})
                state["offset"] += count
                downloaded += count
                state["fingerprint"] = _fingerprint(storage.check_fd(stream.fileno(), private=True))
                _stable(partial, stream, state["fingerprint"], private=True)
                _save(journal, state)
            if _metadata(client, source)["version"] != state["remote_version"]:
                raise MemoryError("artifact_remote_version_changed")
        if state["offset"] == state["size"]:
            _finish(output, partial, journal, state, deadline)
        return _result(state, downloaded, remote_checked=True)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("migrate", help="convert explicitly selected old catalogs offline", add_help=False)
    select = sub.add_parser("select", help="extract one canonical location record from a verified bundle")
    select.add_argument("--bundle", type=Path, required=True)
    select.add_argument("--memory-id", required=True)
    select.add_argument("--output", type=Path, required=True)
    fetch = sub.add_parser("fetch", help="explicitly fetch original bytes; never import or execute them")
    fetch.add_argument("--drive-config", type=Path, required=True)
    fetch.add_argument("--locator", type=Path, required=True)
    fetch.add_argument("--output", type=Path, required=True)
    fetch.add_argument("--journal", type=Path, required=True)
    fetch.add_argument("--maximum-bytes", type=int, default=128 * 1024 * 1024)
    fetch.add_argument("--maximum-seconds", type=int, default=60)
    args, remaining = parser.parse_known_args(argv)
    if args.command == "migrate":
        from memory_vault_artifact_catalog import main as migrate_main
        return migrate_main(remaining)
    if remaining:
        parser.error("unrecognized arguments")
    try:
        result = (select_location(args.bundle, args.memory_id, args.output) if args.command == "select" else
                  fetch_artifact(args.drive_config, args.locator, args.output, args.journal,
                                 maximum_bytes=args.maximum_bytes, maximum_seconds=args.maximum_seconds))
        write_response(success(result))
        return 0
    except MemoryError as exc:
        write_response(failure(exc.code, retryable=exc.retryable))
    except storage.StorageError as exc:
        write_response(failure(exc.code, retryable=exc.retryable))
    except (OSError, ValueError):
        write_response(failure("artifact_io_failed"))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
