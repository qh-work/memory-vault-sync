"""Crash-safe, resumable local byte transport for verified memory packs."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from memory_vault_runtime.protocol import jcs_json_bytes, strict_json_loads


JOURNAL_SCHEMA = "memory-network-publication-journal/v1"
MAX_COPY_CHUNK = 1024 * 1024
MAX_JOURNAL_BYTES = 16 * 1024


class TransportError(ValueError):
    """A resumable copy cannot safely continue."""


class TransportInterrupted(TransportError):
    """Test or caller injected an interruption after a durable journal step."""


@dataclasses.dataclass(frozen=True)
class CopySummary:
    source_sha256: str
    source_bytes: int
    copied_bytes: int
    resumed: bool
    complete: bool


def _file_identity(path: Path) -> tuple[str, int]:
    if not path.is_file() or path.is_symlink():
        raise TransportError("transport source is not a regular file")
    stat_result = path.stat()
    if getattr(stat_result, "st_nlink", 1) != 1:
        raise TransportError("transport source has unexpected link count")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(MAX_COPY_CHUNK):
            digest.update(chunk)
    final_stat = path.stat()
    if (
        final_stat.st_size != stat_result.st_size
        or getattr(final_stat, "st_ino", None) != getattr(stat_result, "st_ino", None)
        or getattr(final_stat, "st_dev", None) != getattr(stat_result, "st_dev", None)
    ):
        raise TransportError("transport source changed while hashing")
    return digest.hexdigest(), stat_result.st_size


def _write_journal(path: Path, value: dict[str, Any]) -> None:
    raw = jcs_json_bytes(value)
    if len(raw) > MAX_JOURNAL_BYTES:
        raise TransportError("transport journal is too large")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        temporary.write_bytes(raw)
        temporary.chmod(0o600)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _read_journal(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    if path.is_symlink() or path.stat().st_size > MAX_JOURNAL_BYTES:
        raise TransportError("transport journal is unsafe")
    try:
        value = strict_json_loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise TransportError("transport journal is invalid") from exc
    if not isinstance(value, dict) or set(value) != {
        "schema_version", "source_sha256", "source_bytes", "offset", "complete"
    } or value.get("schema_version") != JOURNAL_SCHEMA:
        raise TransportError("transport journal schema is invalid")
    source_sha = value["source_sha256"]
    source_bytes = value["source_bytes"]
    offset = value["offset"]
    if (
        not isinstance(source_sha, str) or len(source_sha) != 64
        or any(c not in "0123456789abcdef" for c in source_sha)
        or isinstance(source_bytes, bool) or not isinstance(source_bytes, int) or source_bytes < 0
        or isinstance(offset, bool) or not isinstance(offset, int) or offset < 0
        or not isinstance(value["complete"], bool)
    ):
        raise TransportError("transport journal values are invalid")
    if offset > source_bytes or (value["complete"] and offset != source_bytes):
        raise TransportError("transport journal offset is invalid")
    return value


def resumable_copy(
    source: Path,
    destination: Path,
    journal: Path,
    *,
    interrupt_after_bytes: int | None = None,
) -> CopySummary:
    """Copy a pack with an atomic progress journal and safe restart semantics."""

    source_sha256, source_bytes = _file_identity(source)
    state = _read_journal(journal)
    resumed = state is not None
    if state is not None and (
        state["source_sha256"] != source_sha256
        or state["source_bytes"] != source_bytes
    ):
        raise TransportError("transport source changed during resume")
    offset = int(state["offset"]) if state is not None else 0
    if destination.exists() and (destination.is_symlink() or not destination.is_file()):
        raise TransportError("transport destination is unsafe")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.parent.is_symlink():
        raise TransportError("transport destination parent is unsafe")
    if state is not None and state["complete"]:
        if destination.exists():
            destination_sha, destination_bytes = _file_identity(destination)
            if destination_sha == source_sha256 and destination_bytes == source_bytes:
                return CopySummary(source_sha256, source_bytes, source_bytes, True, True)
        offset = 0
        resumed = True
    mode = "r+b" if destination.exists() else "w+b"
    with source.open("rb") as source_handle, destination.open(mode) as destination_handle:
        destination_handle.truncate(offset)
        source_handle.seek(offset)
        destination_handle.seek(offset)
        while offset < source_bytes:
            chunk = source_handle.read(min(MAX_COPY_CHUNK, source_bytes - offset))
            if not chunk:
                raise TransportError("transport source ended unexpectedly")
            destination_handle.write(chunk)
            destination_handle.flush()
            os.fsync(destination_handle.fileno())
            offset += len(chunk)
            _write_journal(
                journal,
                {
                    "schema_version": JOURNAL_SCHEMA,
                    "source_sha256": source_sha256,
                    "source_bytes": source_bytes,
                    "offset": offset,
                    "complete": offset == source_bytes,
                },
            )
            if interrupt_after_bytes is not None and offset >= interrupt_after_bytes and offset < source_bytes:
                raise TransportInterrupted("transport interrupted after journaled chunk")
    return CopySummary(source_sha256, source_bytes, offset, resumed, offset == source_bytes)
