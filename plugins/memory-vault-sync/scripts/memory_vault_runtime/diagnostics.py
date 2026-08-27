"""Bounded, content-free private diagnostic records.

Diagnostic records are local observability metadata, never task authority.
They deliberately exclude exception messages, tracebacks, arguments, paths,
environment variables, host/user identity, conversation content, and hidden
reasoning.  The caller supplies only a reviewed operation and error category.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


DIAGNOSTIC_RECORD_SCHEMA = "memory-vault-private-diagnostic/v1"
DIAGNOSTIC_SUMMARY_SCHEMA = "memory-vault-private-diagnostics/v1"
MAX_DIAGNOSTIC_RECORD_BYTES = 4 * 1024
MAX_DIAGNOSTIC_RECORDS = 64
MAX_DIAGNOSTIC_TOTAL_BYTES = 256 * 1024

_CORRELATION_RE = re.compile(r"^diag-[0-9a-f]{32}$")
_OPERATION_RE = re.compile(r"^[a-z][a-z0-9.-]{2,63}$")
_CATEGORY_RE = re.compile(r"^[a-z][a-z0-9-]{2,31}$")
_VERSION_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+-]{0,127}$")
_UTC_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?Z$"
)
_RECORD_NAME_RE = re.compile(r"^diag-[0-9a-f]{32}\.json$")


class DiagnosticError(ValueError):
    """The private diagnostic store or record is outside its fixed bounds."""


@dataclass(frozen=True)
class _RecordInventory:
    path: Path
    size: int
    modified_ns: int
    device: int
    inode: int


def _is_reparse_point(observed: os.stat_result) -> bool:
    attributes = int(getattr(observed, "st_file_attributes", 0))
    reparse_flag = int(
        getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x0400)
    )
    return bool(attributes & reparse_flag)


def _identity_matches(
    expected: os.stat_result | _RecordInventory,
    observed: os.stat_result,
) -> bool:
    expected_device = int(getattr(expected, "st_dev", getattr(expected, "device", 0)))
    expected_inode = int(getattr(expected, "st_ino", getattr(expected, "inode", 0)))
    observed_device = int(getattr(observed, "st_dev", 0))
    observed_inode = int(getattr(observed, "st_ino", 0))
    if expected_inode and observed_inode:
        return (
            expected_device == observed_device
            and expected_inode == observed_inode
        )
    return True


def _record_metadata_matches(
    expected: os.stat_result | _RecordInventory,
    observed: os.stat_result,
) -> bool:
    expected_size = int(getattr(expected, "st_size", getattr(expected, "size", -1)))
    expected_modified = int(
        getattr(expected, "st_mtime_ns", getattr(expected, "modified_ns", -1))
    )
    if (
        not _identity_matches(expected, observed)
        or expected_size != int(observed.st_size)
    ):
        return False
    # Windows DirEntry/path stat and CRT handle fstat do not expose identical
    # timestamp representations.  The device/inode identity and exact size
    # remain stable across those interfaces.
    return os.name == "nt" or expected_modified == int(observed.st_mtime_ns)


def _validate_directory_stat(observed: os.stat_result) -> None:
    if (
        not stat.S_ISDIR(observed.st_mode)
        or stat.S_ISLNK(observed.st_mode)
        or _is_reparse_point(observed)
    ):
        raise DiagnosticError("private diagnostic directory is unsafe")


def _validate_record_stat(observed: os.stat_result) -> None:
    if (
        not stat.S_ISREG(observed.st_mode)
        or stat.S_ISLNK(observed.st_mode)
        or _is_reparse_point(observed)
        or int(getattr(observed, "st_nlink", 1)) != 1
        or observed.st_size > MAX_DIAGNOSTIC_RECORD_BYTES
        or (
            os.name != "nt"
            and stat.S_IMODE(observed.st_mode) & 0o077 != 0
        )
    ):
        raise DiagnosticError("private diagnostic entry is unsafe")


def new_correlation_id() -> str:
    """Return an opaque identifier that contains no device or task identity."""

    return f"diag-{secrets.token_hex(16)}"


def _validated_text(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise DiagnosticError(f"{label} is invalid")
    return value


def diagnostic_record(
    *,
    correlation_id: str,
    occurred_at: str,
    operation: str,
    runtime_version: str,
    error_category: str,
) -> dict[str, Any]:
    """Build the exact content-free record persisted for one failure."""

    return {
        "schema_version": DIAGNOSTIC_RECORD_SCHEMA,
        "correlation_id": _validated_text(
            correlation_id,
            _CORRELATION_RE,
            "diagnostic correlation ID",
        ),
        "occurred_at": _validated_text(
            occurred_at,
            _UTC_RE,
            "diagnostic timestamp",
        ),
        "operation": _validated_text(
            operation,
            _OPERATION_RE,
            "diagnostic operation",
        ),
        "runtime_version": _validated_text(
            runtime_version,
            _VERSION_RE,
            "diagnostic runtime version",
        ),
        "error_category": _validated_text(
            error_category,
            _CATEGORY_RE,
            "diagnostic error category",
        ),
        "remote_pointer_moved": False,
        "captured_sensitive_content": False,
    }


def _record_bytes(value: Mapping[str, Any]) -> bytes:
    raw = (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("ascii")
    if len(raw) > MAX_DIAGNOSTIC_RECORD_BYTES:
        raise DiagnosticError("diagnostic record exceeds the byte bound")
    return raw


def _controlled_directory(path: Path) -> None:
    try:
        path.mkdir(mode=0o700, parents=False, exist_ok=True)
        observed = path.lstat()
    except OSError as exc:
        raise DiagnosticError(
            "private diagnostic directory is unavailable"
        ) from exc
    _validate_directory_stat(observed)
    try:
        if os.name != "nt":
            flags = (
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            descriptor = os.open(path, flags)
            try:
                opened = os.fstat(descriptor)
                named = path.lstat()
                _validate_directory_stat(opened)
                _validate_directory_stat(named)
                if not _identity_matches(opened, named):
                    raise DiagnosticError(
                        "private diagnostic directory changed"
                    )
                os.fchmod(descriptor, 0o700)
                opened_again = os.fstat(descriptor)
                named_again = path.lstat()
                _validate_directory_stat(opened_again)
                _validate_directory_stat(named_again)
                if (
                    not _identity_matches(opened, opened_again)
                    or not _identity_matches(opened_again, named_again)
                    or stat.S_IMODE(opened_again.st_mode) != 0o700
                ):
                    raise DiagnosticError(
                        "private diagnostic directory changed"
                    )
            finally:
                os.close(descriptor)
        else:
            os.chmod(path, 0o700)
            observed_again = path.lstat()
            _validate_directory_stat(observed_again)
            if not _identity_matches(observed, observed_again):
                raise DiagnosticError(
                    "private diagnostic directory changed"
                )
    except OSError as exc:
        raise DiagnosticError(
            "private diagnostic directory permissions are unsafe"
        ) from exc


def _records_directory(data_dir: Path) -> Path:
    try:
        observed = data_dir.lstat()
    except OSError as exc:
        raise DiagnosticError("plugin data directory is unavailable") from exc
    try:
        _validate_directory_stat(observed)
    except DiagnosticError as exc:
        raise DiagnosticError("plugin data directory is unsafe") from exc
    diagnostics = data_dir / "diagnostics"
    records = diagnostics / "records"
    _controlled_directory(diagnostics)
    _controlled_directory(records)
    return records


def _inventory(records: Path) -> list[_RecordInventory]:
    result: list[_RecordInventory] = []
    try:
        entries = list(os.scandir(records))
    except OSError as exc:
        raise DiagnosticError("private diagnostics cannot be listed") from exc
    for entry in entries:
        if _RECORD_NAME_RE.fullmatch(entry.name) is None:
            raise DiagnosticError(
                "private diagnostic directory contains an unexpected entry"
            )
        try:
            # DirEntry.stat reports zero device/inode/link values on Windows;
            # a fresh path stat supplies the real identity and link count.
            observed = os.stat(entry.path, follow_symlinks=False)
        except OSError as exc:
            raise DiagnosticError(
                "private diagnostic entry changed during listing"
            ) from exc
        _validate_record_stat(observed)
        result.append(
            _RecordInventory(
                path=Path(entry.path),
                size=int(observed.st_size),
                modified_ns=int(observed.st_mtime_ns),
                device=int(getattr(observed, "st_dev", 0)),
                inode=int(getattr(observed, "st_ino", 0)),
            )
        )
    return result


def _rotate(records: Path, incoming_bytes: int) -> None:
    inventory = _inventory(records)
    total = sum(item.size for item in inventory)
    ordered = sorted(
        inventory,
        key=lambda item: (item.modified_ns, item.path.name),
    )
    while (
        len(ordered) >= MAX_DIAGNOSTIC_RECORDS
        or total + incoming_bytes > MAX_DIAGNOSTIC_TOTAL_BYTES
    ):
        if not ordered:
            raise DiagnosticError("diagnostic retention bounds are impossible")
        item = ordered.pop(0)
        try:
            item.path.unlink()
        except OSError as exc:
            raise DiagnosticError("private diagnostic rotation failed") from exc
        total -= item.size


def _read_record(item: _RecordInventory) -> bytes:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NOINHERIT", 0)
    )
    descriptor = -1
    try:
        descriptor = os.open(item.path, flags)
        opened = os.fstat(descriptor)
        named = item.path.lstat()
        _validate_record_stat(opened)
        _validate_record_stat(named)
        if (
            not _record_metadata_matches(item, opened)
            or not _record_metadata_matches(opened, named)
        ):
            raise DiagnosticError(
                "private diagnostic entry changed before reading"
            )
        chunks: list[bytes] = []
        remaining = MAX_DIAGNOSTIC_RECORD_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        opened_again = os.fstat(descriptor)
        named_again = item.path.lstat()
        _validate_record_stat(opened_again)
        _validate_record_stat(named_again)
        if (
            len(raw) != item.size
            or not _record_metadata_matches(opened, opened_again)
            or not _record_metadata_matches(opened_again, named_again)
        ):
            raise DiagnosticError(
                "private diagnostic entry changed while reading"
            )
        return raw
    except OSError as exc:
        raise DiagnosticError(
            "private diagnostic entry could not be read safely"
        ) from exc
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass


def record_private_diagnostic(
    data_dir: Path,
    *,
    correlation_id: str,
    occurred_at: str,
    operation: str,
    runtime_version: str,
    error_category: str,
) -> dict[str, Any]:
    """Persist one exclusive 0600 record after bounded local rotation."""

    value = diagnostic_record(
        correlation_id=correlation_id,
        occurred_at=occurred_at,
        operation=operation,
        runtime_version=runtime_version,
        error_category=error_category,
    )
    raw = _record_bytes(value)
    records = _records_directory(data_dir)
    path = records / f"{value['correlation_id']}.json"
    try:
        path.lstat()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise DiagnosticError(
            "private diagnostic record identity is unavailable"
        ) from exc
    else:
        raise DiagnosticError("private diagnostic correlation already exists")
    _rotate(records, len(raw))
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NOINHERIT", 0)
    )
    descriptor = -1
    created = False
    try:
        descriptor = os.open(path, flags, 0o600)
        created = True
        opened = os.fstat(descriptor)
        named = path.lstat()
        _validate_record_stat(opened)
        _validate_record_stat(named)
        if not _identity_matches(opened, named):
            raise DiagnosticError("private diagnostic file is unsafe")
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        else:
            os.chmod(path, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
            opened_again = os.fstat(stream.fileno())
            named_again = path.lstat()
            _validate_record_stat(opened_again)
            _validate_record_stat(named_again)
            if (
                opened_again.st_size != len(raw)
                or not _identity_matches(opened, opened_again)
                or not _identity_matches(opened_again, named_again)
            ):
                raise DiagnosticError(
                    "private diagnostic file changed while writing"
                )
    except (OSError, DiagnosticError) as exc:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if created:
            try:
                path.unlink()
            except OSError:
                pass
        if isinstance(exc, DiagnosticError):
            raise
        raise DiagnosticError("private diagnostic record could not be written") from exc
    return dict(value)


def _validated_loaded_record(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "schema_version",
        "correlation_id",
        "occurred_at",
        "operation",
        "runtime_version",
        "error_category",
        "remote_pointer_moved",
        "captured_sensitive_content",
    }:
        raise DiagnosticError("private diagnostic record fields are invalid")
    normalized = diagnostic_record(
        correlation_id=value.get("correlation_id"),
        occurred_at=value.get("occurred_at"),
        operation=value.get("operation"),
        runtime_version=value.get("runtime_version"),
        error_category=value.get("error_category"),
    )
    if value.get("remote_pointer_moved") is not False or value.get(
        "captured_sensitive_content"
    ) is not False:
        raise DiagnosticError("private diagnostic safety claims changed")
    return normalized


def diagnostics_summary(data_dir: Path, *, limit: int = 10) -> dict[str, Any]:
    """Return a bounded path-free view of recent local diagnostics."""

    if not isinstance(limit, int) or isinstance(limit, bool) or not 0 <= limit <= 64:
        raise DiagnosticError("diagnostic summary limit is invalid")
    records = _records_directory(data_dir)
    loaded: list[dict[str, Any]] = []
    corrupt = 0
    for item in _inventory(records):
        try:
            raw = _read_record(item)
            if len(raw) != item.size or len(raw) > MAX_DIAGNOSTIC_RECORD_BYTES:
                raise DiagnosticError("diagnostic size changed")
            value = json.loads(raw.decode("ascii"))
            normalized = _validated_loaded_record(value)
            if item.path.name != f"{normalized['correlation_id']}.json":
                raise DiagnosticError("diagnostic filename changed")
            if raw != _record_bytes(normalized):
                raise DiagnosticError("diagnostic bytes are not canonical")
            loaded.append(normalized)
        except (DiagnosticError, OSError, UnicodeDecodeError, ValueError):
            corrupt += 1
    loaded.sort(
        key=lambda item: (item["occurred_at"], item["correlation_id"]),
        reverse=True,
    )
    return {
        "schema_version": DIAGNOSTIC_SUMMARY_SCHEMA,
        "available": True,
        "private_local_only": True,
        "record_count": len(loaded),
        "corrupt_record_count": corrupt,
        "recent_records": loaded[:limit],
        "retention": {
            "maximum_record_bytes": MAX_DIAGNOSTIC_RECORD_BYTES,
            "maximum_records": MAX_DIAGNOSTIC_RECORDS,
            "maximum_total_bytes": MAX_DIAGNOSTIC_TOTAL_BYTES,
        },
        "captured_sensitive_content": False,
    }
