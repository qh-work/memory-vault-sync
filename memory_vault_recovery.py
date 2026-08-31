#!/usr/bin/env python3
"""Explicit, offline client-state recovery; archived state is never authority.

The memory-only snapshot module deliberately excludes client control state.
This opt-in layer preserves selected, documented control formats as private
evidence. Restoring evidence does not resume capture, transfer or execution.
Only a separate operator call can publish a new local-resume configuration.
No path, command, credential or permission is taken from a restored payload.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import sqlite3
import stat
import time
from typing import Any, Iterator, Mapping, Sequence

from memory_vault import AUTHORITY, MAX_BUNDLE_LINE_BYTES, MemoryError, Vault, canonical_bytes, sha256, strict_json_loads, utc_now, validate_record
from memory_vault_capture import (
    CAPTURE_COLUMNS, CAPTURE_SQL, HOOK_CAPTURE_FILENAME, HOOK_CAPTURE_SCHEMA,
    HOOK_FRAGMENT_PROFILE, MAX_CAPTURE_JOBS, MAX_CAPTURE_RECORDS, load_capture,
    parse_hook_fragment, validate_capture_header, validate_capture_projection,
    validate_capture_state, validate_hook_fragment_projection,
)
import memory_vault_backup as database_backup
import memory_vault_storage as protected_storage


BACKUP_SCHEMA = "universal-memory-client-backup/v1"
RECOVERY_SCHEMA = "universal-memory-client-recovery/v1"
ACTIVATION_SCHEMA = "universal-memory-client-activation/v1"
COMPONENTS = frozenset({"hooks", "lifecycle", "hosts", "compat", "sync"})
LOCAL_COMPONENTS = COMPONENTS - {"sync"}
MAX_FILES = 20_000
MAX_DIRECTORIES = 20_000
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_CONTROL_BYTES = 16 * 1024 * 1024
MAX_CONTROL_DATABASE_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 8 * 1024 * 1024 * 1024
MAX_CONTROL_ROWS = 2_000_000
_HASH = re.compile(r"[0-9a-f]{64}")
_MEMORY = re.compile(r"mem_[0-9a-f]{40}")
_STORE = re.compile(r"store_[0-9a-f]{32}")
_ITEM = re.compile(r"item_[0-9a-f]{64}")
_QUEUE = re.compile(r"[0-9a-f]{64}\.json")
_FRAGMENT = re.compile(r"[0-9]{6}-[0-9a-f]{64}\.ndjson")
_NUMBER_RECEIPT = re.compile(r"[0-9]{1,6}\.json")
_CAPSULE = re.compile(r"[0-9]{20}-[0-9]{20}-[0-9a-f]{64}\.json")
_KEY = re.compile(r"ed25519_[0-9a-f]{64}")
_HOSTS = frozenset({"generic", "claude-code", "gemini-cli"})
_HOOK_GROUPS = frozenset({"prompts", "outbox", "done", "conflicts"})
_HOST_GROUPS = frozenset({"turns", "pending", "receipts", "finals"})
_SYNC_TOP_FILES = frozenset({"sync-state.json", "sync-trigger.json", "launch.json",
                             "remote-receipt.json", "worker-events.ndjson"})
_SYNC_LOCKS = ("launch.lock", "worker.lock", "trigger.lock", "transfer/transfer.lock")
_REVIEW_FILES = frozenset({"intent.json", "original.json", "replacement.json", "decision.json", "completed.json"})
_LEGACY_EXCLUDED = ("private_keys", "credentials", "trust_registry", "original_client_and_sync_configuration",
             "host_permissions", "executable_code", "external_exchange_directories", "rclone_cache_and_tmp",
             "lock_files", "unselected_components")
_EXCLUDED = (*_LEGACY_EXCLUDED, "native_drive_ciphertext_cache")

# Closed schemas are recreated from these literals, never from SQLite programs
# supplied by an archive. Optional indexes in the canonical memory DB are owned
# by memory_vault_backup; these are private client correlation/capture databases.
_CONTROL_SQL = {
    "lifecycle": {
        "meta": "CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)",
        "sessions": "CREATE TABLE sessions(handle TEXT PRIMARY KEY,state TEXT NOT NULL CHECK(state IN ('open','closed')))",
        "turns": "CREATE TABLE turns(handle TEXT PRIMARY KEY,session_handle TEXT NOT NULL REFERENCES sessions(handle),phase TEXT NOT NULL CHECK(phase IN ('staged','committing','committed','aborted')),user_text TEXT,assistant_text TEXT,continuity_text TEXT,commit_request TEXT)",
        "turns_session": "CREATE INDEX turns_session ON turns(session_handle,phase)",
        "requests": "CREATE TABLE requests(request_key TEXT PRIMARY KEY,payload_sha256 TEXT NOT NULL,response_json TEXT,session_handle TEXT REFERENCES sessions(handle),turn_handle TEXT REFERENCES turns(handle))",
    },
    "compat": {
        "meta": "CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)",
        "sessions": "CREATE TABLE sessions(handle TEXT PRIMARY KEY,state TEXT NOT NULL CHECK(state IN ('open','closed')))",
        "turns": "CREATE TABLE turns(handle TEXT PRIMARY KEY,session_handle TEXT NOT NULL REFERENCES sessions(handle),phase TEXT NOT NULL CHECK(phase IN ('staged','pending','done','aborted')),user_text TEXT,assistant_text TEXT,user_sha256 TEXT NOT NULL,assistant_sha256 TEXT,created_at TEXT NOT NULL,receipt_id TEXT,abort_reason TEXT,last_error TEXT,memory_id TEXT)",
        "host_turns_pending": "CREATE INDEX host_turns_pending ON turns(phase,created_at)",
        "host_turns_session": "CREATE INDEX host_turns_session ON turns(session_handle,phase)",
        "requests": "CREATE TABLE requests(request_key TEXT PRIMARY KEY,request_sha256 TEXT NOT NULL,response_json TEXT NOT NULL,turn_handle TEXT REFERENCES turns(handle))",
        "semantic_jobs": "CREATE TABLE semantic_jobs(proposal_sha256 TEXT PRIMARY KEY,created_at TEXT NOT NULL,memory_id TEXT)",
        "aliases": "CREATE TABLE aliases(legacy_id TEXT PRIMARY KEY,memory_id TEXT NOT NULL,record_sha256 TEXT NOT NULL,source_id TEXT,evidence_anchor_sha256 TEXT)",
    },
}
_DATABASE_NAMES = {"lifecycle": "lifecycle-v1.sqlite3", "compat": "host-protocol-v1.sqlite3", "hooks": HOOK_CAPTURE_FILENAME}
_CONTROL_COLUMNS = {
    "lifecycle": {
        "meta": ("key", "value"), "sessions": ("handle", "state"),
        "turns": ("handle", "session_handle", "phase", "user_text", "assistant_text", "continuity_text", "commit_request"),
        "requests": ("request_key", "payload_sha256", "response_json", "session_handle", "turn_handle"),
    },
    "compat": {
        "meta": ("key", "value"), "sessions": ("handle", "state"),
        "turns": ("handle", "session_handle", "phase", "user_text", "assistant_text", "user_sha256", "assistant_sha256", "created_at",
                  "receipt_id", "abort_reason", "last_error", "memory_id"),
        "requests": ("request_key", "request_sha256", "response_json", "turn_handle"),
        "semantic_jobs": ("proposal_sha256", "created_at", "memory_id"),
        "aliases": ("legacy_id", "memory_id", "record_sha256", "source_id", "evidence_anchor_sha256"),
    },
}
_CONTROL_SQL["hooks"] = {"meta": "CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)", **CAPTURE_SQL}
_CONTROL_COLUMNS["hooks"] = {"meta": ("key", "value"), **CAPTURE_COLUMNS}
_CONTROL_V2_SQL = {component: {**_CONTROL_SQL[component], **CAPTURE_SQL} for component in ("lifecycle", "compat")}
_CONTROL_V2_COLUMNS = {component: {**_CONTROL_COLUMNS[component], **CAPTURE_COLUMNS} for component in ("lifecycle", "compat")}
_CONTROL_V2_SQL["lifecycle"]["capture_sessions"] = "CREATE TABLE capture_sessions(session_handle TEXT PRIMARY KEY REFERENCES sessions(handle),scope_key TEXT NOT NULL)"
_CONTROL_V2_COLUMNS["lifecycle"]["capture_sessions"] = ("session_handle", "scope_key")
_CONTROL_SCHEMAS = {
    "lifecycle": {1: "universal-memory-lifecycle-state/v1", 2: "universal-memory-lifecycle-state/v2"},
    "compat": {1: "memory-vault-host-compat-state/v1", 2: "memory-vault-host-compat-state/v2"},
    "hooks": {1: HOOK_CAPTURE_SCHEMA},
}
_CAPTURE_KEY = re.compile(r"[A-Za-z0-9._:@+\-]{1,256}")


def _control_layout(component: str, version: int) -> tuple[str, Mapping[str, str], Mapping[str, tuple[str, ...]]]:
    _require(component in _CONTROL_SCHEMAS and version in _CONTROL_SCHEMAS[component], "unsupported_client_control_schema")
    statements = _CONTROL_V2_SQL[component] if version == 2 else _CONTROL_SQL[component]
    columns = _CONTROL_V2_COLUMNS[component] if version == 2 else _CONTROL_COLUMNS[component]
    return _CONTROL_SCHEMAS[component][version], statements, columns


def _control_version(component: str, schema: Any) -> int:
    for version, candidate in _CONTROL_SCHEMAS.get(component, {}).items():
        if schema == candidate:
            return version
    raise MemoryError("unsupported_client_control_schema")


def _control_count_limit(table: str) -> int:
    if table == "capture_records":
        return MAX_CAPTURE_JOBS * MAX_CAPTURE_RECORDS
    if table in {"capture_heads", "capture_jobs"}:
        return MAX_CAPTURE_JOBS
    return MAX_CONTROL_ROWS


def _require(value: bool, code: str = "invalid_client_recovery_state") -> None:
    if not value:
        raise MemoryError(code)


def _selection(values: Sequence[str], *, local_only: bool = False) -> list[str]:
    allowed = LOCAL_COMPONENTS if local_only else COMPONENTS
    _require(isinstance(values, (list, tuple)) and bool(values)
             and all(isinstance(item, str) and item in allowed for item in values)
             and len(set(values)) == len(values), "explicit_recovery_components_required")
    _require("hosts" not in values or "lifecycle" in values, "host_recovery_requires_lifecycle")
    return sorted(values)


def _private_directory(path: Path) -> os.stat_result:
    selected = database_backup.absolute(path)
    protected_storage.check_private_directory(selected)
    info = selected.lstat()
    return info


def _prepare_directory(path: Path, *, private: bool = True) -> None:
    """Create each missing level privately, never chmod an existing ancestor.

    Path.mkdir(parents=True, mode=0700) protects only the leaf on POSIX; implicit
    intermediate 0755 directories would make our own archive fail its closed
    private-tree inventory. Preserve trusted existing outer parents instead.
    """
    selected = database_backup.absolute(path)
    if os.name == "nt":
        protected_storage.private_directory(selected)
        return
    missing: list[Path] = []
    current = selected
    while not current.exists():
        missing.append(current)
        current = current.parent
    database_backup._private_parent(current)
    for directory in reversed(missing):
        try:
            directory.mkdir(mode=0o700)
        except FileExistsError:
            pass
        protected_storage.check_private_directory(directory)
    if private:
        protected_storage.check_private_directory(selected)


def _new_directory(path: Path) -> None:
    _prepare_directory(path.parent, private=False)
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        raise MemoryError("recovery_output_exists") from None
    # POSIX private modes / Windows inherited native ACLs are independently
    # checked before writing anything into the exclusively created directory.
    protected_storage.check_private_directory(path)


def _overlaps(left: Path, right: Path) -> bool:
    return left == right or left in right.parents or right in left.parents


def _fingerprint(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _hash_file(path: Path, deadline: float, *, maximum: int = MAX_TOTAL_BYTES) -> tuple[str, int]:
    before = database_backup.regular(path)
    _require(before.st_size <= maximum, "client_recovery_file_limit")
    digest, size = hashlib.sha256(), 0
    descriptor = protected_storage.open_file(path, os.O_RDONLY, private=True)
    with os.fdopen(descriptor, "rb") as stream:
        _require(_fingerprint(os.fstat(stream.fileno())) == _fingerprint(before), "recovery_source_changed")
        while True:
            database_backup._check_time(deadline)
            block = stream.read(1024 * 1024)
            if not block:
                break
            size += len(block)
            _require(size <= maximum, "client_recovery_file_limit")
            digest.update(block)
        _require(_fingerprint(os.fstat(stream.fileno())) == _fingerprint(before), "recovery_source_changed")
    _require(_fingerprint(database_backup.regular(path)) == _fingerprint(before) and size == before.st_size,
             "recovery_source_changed")
    return digest.hexdigest(), size


def _read_json(path: Path, deadline: float, *, maximum: int = MAX_CONTROL_BYTES) -> dict[str, Any]:
    digest, size = _hash_file(path, deadline, maximum=maximum)
    descriptor = protected_storage.open_file(path, os.O_RDONLY, private=True)
    with os.fdopen(descriptor, "rb") as stream:
        data = stream.read(maximum + 1)
    _require(len(data) == size and sha256(data) == digest, "recovery_source_changed")
    value = strict_json_loads(data)
    _require(isinstance(value, dict), "invalid_recovery_document")
    return dict(value)


def _write_json(path: Path, value: Mapping[str, Any], *, maximum: int = MAX_MANIFEST_BYTES) -> None:
    encoded = canonical_bytes(value) + b"\n"
    _require(len(encoded) <= maximum, "client_recovery_manifest_limit")
    _prepare_directory(path.parent)
    try:
        protected_storage.atomic_write(path, encoded, replace=False)
    except FileExistsError:
        raise MemoryError("recovery_output_exists") from None


def _copy_file(source: Path, destination: Path, deadline: float, *, maximum: int) -> tuple[str, int]:
    before = database_backup.regular(source)
    _require(before.st_size <= maximum, "client_recovery_file_limit")
    _prepare_directory(destination.parent)
    temporary = database_backup._new_temporary(destination.parent)
    digest, size = hashlib.sha256(), 0
    try:
        with contextlib.ExitStack() as stack:
            incoming = stack.enter_context(os.fdopen(protected_storage.open_file(source, os.O_RDONLY, private=True), "rb"))
            outgoing = stack.enter_context(os.fdopen(protected_storage.open_file(temporary, os.O_WRONLY, private=True), "wb"))
            _require(_fingerprint(os.fstat(incoming.fileno())) == _fingerprint(before), "recovery_source_changed")
            while True:
                database_backup._check_time(deadline)
                block = incoming.read(1024 * 1024)
                if not block:
                    break
                size += len(block)
                _require(size <= maximum, "client_recovery_file_limit")
                digest.update(block)
                outgoing.write(block)
            outgoing.flush()
            os.fsync(outgoing.fileno())
            _require(_fingerprint(os.fstat(incoming.fileno())) == _fingerprint(before), "recovery_source_changed")
        _require(_fingerprint(database_backup.regular(source)) == _fingerprint(before) and size == before.st_size,
                 "recovery_source_changed")
        database_backup._publish_file(temporary, destination)
        return digest.hexdigest(), size
    finally:
        temporary.unlink(missing_ok=True)


def _host_kind(parts: tuple[str, ...], directory: bool) -> str | None:
    if len(parts) == 1:
        return "directory" if directory and parts[0] in _HOSTS else None
    if parts[0] not in _HOSTS or not _HASH.fullmatch(parts[1]):
        return None
    if len(parts) == 2:
        return "directory" if directory else None
    if len(parts) == 3:
        if directory and parts[2] in _HOST_GROUPS:
            return "directory"
        if not directory and parts[2] in {"session.json", ".lock"}:
            return "lock" if parts[2] == ".lock" else "json"
    if len(parts) == 4 and parts[2] in _HOST_GROUPS and not directory and _QUEUE.fullmatch(parts[3]):
        return "json"
    return None


def _sync_kind(parts: tuple[str, ...], directory: bool) -> str | None:
    if len(parts) == 1:
        if not directory and parts[0] in _SYNC_TOP_FILES:
            return "opaque" if parts[0].endswith("ndjson") else "json"
        if not directory and parts[0] in _SYNC_LOCKS:
            return "lock"
        if directory and parts[0] in {"transfer", "remote-group-receipts", "exchange", "rclone", "native-drive"}:
            return "excluded" if parts[0] in {"rclone", "native-drive"} else "directory"
        return None
    if parts[0] == "remote-group-receipts":
        if not _HASH.fullmatch(parts[1]):
            return None
        return ("directory" if directory else None) if len(parts) == 2 else (
            "json" if len(parts) == 3 and not directory and _NUMBER_RECEIPT.fullmatch(parts[2]) else None)
    if parts[0] == "transfer":
        if len(parts) == 2:
            if not directory and parts[1] in {"dependency-index.sqlite3", "dependency-index.sqlite3-journal",
                                              "dependency-index.sqlite3-wal", "dependency-index.sqlite3-shm"}:
                return "monitor"
            if not directory and parts[1] in {"state.json", "publish.pending.json", "publish.started.json", "transfer.lock"}:
                return "lock" if parts[1] == "transfer.lock" else "json"
            if directory and parts[1] in {"publication-reviews", "outgoing-groups", "incoming-groups", "group-copy-receipts", "received-capsules"}:
                return "directory"
        if len(parts) == 3 and parts[1] == "received-capsules" and not directory and _QUEUE.fullmatch(parts[2]):
            return "json"
        if len(parts) >= 3 and _HASH.fullmatch(parts[2]):
            if len(parts) == 3:
                return "directory" if directory and parts[1] in {"publication-reviews", "outgoing-groups", "incoming-groups", "group-copy-receipts"} else None
            if len(parts) == 4 and not directory:
                if parts[1] == "publication-reviews" and parts[3] in _REVIEW_FILES:
                    return "json"
                if parts[1] in {"outgoing-groups", "incoming-groups"} and _FRAGMENT.fullmatch(parts[3]):
                    return "opaque"
                if parts[1] in {"incoming-groups", "group-copy-receipts"} and _NUMBER_RECEIPT.fullmatch(parts[3]):
                    return "json"
        return None
    if parts[0] == "exchange":
        if not _KEY.fullmatch(parts[1]):
            return None
        if len(parts) == 2:
            return "directory" if directory else None
        if not _STORE.fullmatch(parts[2]):
            return None
        if len(parts) == 3:
            return "directory" if directory else None
        if len(parts) == 4:
            if directory and parts[3] == "groups":
                return "directory"
            return "json" if not directory and _CAPSULE.fullmatch(parts[3]) else None
        if parts[3] == "groups" and _HASH.fullmatch(parts[4]):
            if len(parts) == 5:
                return "directory" if directory else None
            if len(parts) == 6 and not directory and _FRAGMENT.fullmatch(parts[5]):
                return "opaque"
    return None


@dataclass(frozen=True)
class Source:
    path: Path
    component: str
    logical: str | None
    kind: str


def _inventory(config: Any, selected: Sequence[str], sync: Any, deadline: float) -> tuple[list[Source], dict[str, Any], list[Path]]:
    sources: list[Source] = []
    observed: dict[str, Any] = {}
    locks: list[Path] = []
    directories = 0

    def observe(path: Path, *, directory: bool = False) -> bool:
        database_backup._check_time(deadline)
        database_backup.absolute(path)
        try:
            info = _private_directory(path) if directory else database_backup.regular(path)
        except FileNotFoundError:
            observed[str(path)] = None
            return False
        observed[str(path)] = _fingerprint(info)
        return True

    def add(path: Path, component: str, logical: str | None, kind: str) -> None:
        if observe(path):
            sources.append(Source(path, component, logical, kind))
            _require(len(sources) <= MAX_FILES, "client_recovery_file_limit")

    def scan(root: Path, component: str, prefix: str, classifier: Any, parts: tuple[str, ...] = ()) -> None:
        nonlocal directories
        if not observe(root, directory=True):
            return
        directories += 1
        _require(directories <= MAX_DIRECTORIES, "client_recovery_directory_limit")
        names: list[str] = []
        with os.scandir(root) as entries:
            for entry in entries:
                database_backup._check_time(deadline)
                _require(len(names) < MAX_FILES, "client_recovery_file_limit")
                names.append(entry.name)
        observed[str(root) + "/<entries>"] = sorted(names)
        for name in sorted(names):
            path = root / name
            info = path.lstat()
            is_directory = stat.S_ISDIR(info.st_mode)
            kind = classifier(parts + (name,), is_directory)
            _require(kind is not None, "unexpected_client_recovery_entry")
            if kind == "directory":
                scan(path, component, prefix + "/" + name, classifier, parts + (name,))
            elif kind == "excluded":
                observe(path, directory=True)
            elif kind == "lock":
                observe(path)
                locks.append(path)
            elif kind == "monitor":
                # Derived receiver-known indexes are not delivery authority.
                # Observe their metadata for quiescence, but never archive or
                # activate one as a trusted continuation of an old stream.
                observe(path)
            else:
                add(path, component, prefix + "/" + name, kind)

    add(config.path, "configuration", None, "monitor")
    add(config.vault_path, "memory", None, "memory")
    for suffix in ("-journal", "-wal", "-shm"):
        add(Path(str(config.vault_path) + suffix), "memory", None, "monitor")
    # Watch the root too: creating a selected database or queue after discovery
    # must invalidate the snapshot, not disappear from its supposedly full set.
    observe(config.state_path, directory=True)
    for component in selected:
        if component == "hooks":
            for group in sorted(_HOOK_GROUPS):
                scan(config.state_path / group, component, "control/hooks/" + group,
                     lambda parts, directory: "json" if len(parts) == 1 and not directory and _QUEUE.fullmatch(parts[0]) else None)
            path = config.state_path / HOOK_CAPTURE_FILENAME
            add(path, component, "control/hooks/" + path.name, "sqlite")
            for suffix in ("-journal", "-wal", "-shm"):
                add(Path(str(path) + suffix), component, None, "monitor")
        elif component in _DATABASE_NAMES:
            path = config.state_path / _DATABASE_NAMES[component]
            add(path, component, "control/" + component + "/" + path.name, "sqlite")
            for suffix in ("-journal", "-wal", "-shm"):
                add(Path(str(path) + suffix), component, None, "monitor")
        elif component == "hosts":
            scan(config.state_path / "hosts-v1", component, "control/hosts", _host_kind)
        elif component == "sync":
            _require(sync is not None, "sync_not_configured")
            add(sync.path, "configuration", None, "monitor")
            scan(sync.state_directory, component, "control/sync", _sync_kind)
    return sources, observed, locks


@contextlib.contextmanager
def _quiescent_locks(paths: Sequence[Path], sync: Any) -> Iterator[None]:
    order = {str(sync.state_directory / name): index for index, name in enumerate(_SYNC_LOCKS)} if sync else {}
    with contextlib.ExitStack() as stack:
        for path in sorted(set(paths), key=lambda item: (order.get(str(item), 10), str(item))):
            before = database_backup.regular(path)
            stack.enter_context(protected_storage.file_lock(path, create=False, busy_code="client_recovery_not_quiescent"))
            _require(_fingerprint(database_backup.regular(path)) == _fingerprint(before), "recovery_source_changed")
        yield


def _control_summary(connection: sqlite3.Connection, component: str, source: Mapping[str, Any]) -> dict[str, Any]:
    if hasattr(connection, "setlimit"):
        connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 8 * 1024 * 1024)
    version = connection.execute("PRAGMA user_version").fetchone()[0]
    schema, expected, expected_columns = _control_layout(component, version)
    seen: set[str] = set()
    for row in connection.execute("SELECT type,name,tbl_name,sql FROM sqlite_master"):
        if row["type"] == "index" and row["sql"] is None and row["name"].startswith("sqlite_autoindex_") and row["tbl_name"] in expected:
            continue
        name = row["name"]
        _require(name in expected and isinstance(row["sql"], str)
                 and database_backup._sql(row["sql"]) == database_backup._sql(expected[name]), "unsupported_client_control_schema")
        seen.add(name)
    _require(seen == set(expected), "unsupported_client_control_schema")
    metadata = dict(connection.execute("SELECT key,value FROM meta"))
    binding = source["compat_vault_path_sha256"] if component == "compat" else source["vault_path_sha256"]
    _require(set(metadata) == ({"schema_version", "vault_path_sha256"} | ({"store_id"} if component == "compat" else set()))
             and metadata["schema_version"] == schema and metadata["vault_path_sha256"] == binding,
             "client_control_source_binding_changed")
    if component == "compat":
        _require(metadata["store_id"] in {"", source["store_id"]}, "client_control_source_binding_changed")
    logical_bytes = connection.execute("PRAGMA page_count").fetchone()[0] * connection.execute("PRAGMA page_size").fetchone()[0]
    _require(0 < logical_bytes <= (256 * 1024 * 1024 if component == "compat" else MAX_CONTROL_DATABASE_BYTES),
             "client_control_database_limit")
    for table, columns in expected_columns.items():
        _require(tuple(row["name"] for row in connection.execute("PRAGMA table_info(" + table + ")")) == columns,
                 "unsupported_client_control_schema")
    counts = {name: int(connection.execute("SELECT COUNT(*) FROM " + name).fetchone()[0])
              for name, sql in expected.items() if sql.startswith("CREATE TABLE")}
    _require(all(count <= _control_count_limit(name) for name, count in counts.items()), "client_control_row_limit")
    database_backup._integrity(connection)
    phases = {}
    if component != "hooks":
        phases = {str(row[0]): int(row[1]) for row in connection.execute("SELECT phase,COUNT(*) FROM turns GROUP BY phase")}
        pending = ("staged", "committing") if component == "lifecycle" else ("staged", "pending")
        _require(sum(phases.get(phase, 0) for phase in pending) <= 256
                 and connection.execute("SELECT COUNT(*) FROM sessions WHERE state='open'").fetchone()[0] <= 128,
                 "client_control_pending_limit")
    if "capture_jobs" in expected:
        validate_capture_state(connection)
    if component == "compat":
        from memory_vault_compat import MAX_ALIAS_ROWS, MAX_CONTROL_ROWS as COMPAT_CONTROL_ROWS
        _require(counts["aliases"] <= MAX_ALIAS_ROWS and counts["requests"] <= COMPAT_CONTROL_ROWS,
                 "client_control_row_limit")
    return {"schema_version": schema, "counts": counts, "turn_phases": phases}


def _entry(component: str, path: str, kind: str, digest: str, size: int) -> dict[str, Any]:
    return {"entry_id": "item_" + sha256(canonical_bytes([path, digest])), "component": component,
            "path": path, "kind": kind, "sha256": digest, "bytes": size}


def _snapshot(connection: sqlite3.Connection, destination: Path, deadline: float) -> tuple[str, int]:
    _prepare_directory(destination.parent)
    temporary = database_backup._new_temporary(destination.parent)
    try:
        with contextlib.closing(sqlite3.connect(temporary)) as copied:
            database_backup._copy_database(connection, copied, deadline)
            database_backup._integrity(copied)
        digest, size = _hash_file(temporary, deadline)
        database_backup._publish_file(temporary, destination)
        return digest, size
    finally:
        temporary.unlink(missing_ok=True)


def backup_client(config_path: Path, output: Path, *, include: Sequence[str], quiesced: bool = False,
                  timeout: int = database_backup.DEFAULT_TIMEOUT) -> Mapping[str, Any]:
    """Capture explicitly selected offline state; manifest-last, not global atomicity.

    The operator must stop every writer first. Existing known advisory locks
    plus whole selected-source inventory/content comparisons detect activity;
    they cannot lock arbitrary agents or replace that offline maintenance step.
    """
    protected_storage.require_supported_storage()
    _require(quiesced is True, "offline_quiesced_acknowledgement_required")
    selected = _selection(include)
    deadline = database_backup._deadline(timeout)
    from memory_vault_client import ClientConfig, _digest, bound_sync_config
    config = ClientConfig.load(database_backup.absolute(config_path))
    sync = bound_sync_config(config) if "sync" in selected else None
    destination = database_backup.absolute(output)
    for source_path in (config.path, config.vault_path, config.state_path,
                        *([sync.path, sync.state_directory] if sync else [])):
        _require(not _overlaps(destination, source_path), "client_recovery_path_overlap")
    initial_sources, initial_inventory, locks = _inventory(config, selected, sync, deadline)
    source_info = {"store_id": "", "vault_path_sha256": _digest(str(config.vault_path)),
                   "compat_vault_path_sha256": sha256(str(config.vault_path).encode("utf-8")),
                   "signed_writes_configured": config.identity_path is not None,
                   "capture_visible_turns_configured": config.capture_visible_turns,
                   "sync_configured": config.sync_config_path is not None,
                   "memory_database_present": initial_inventory[str(config.vault_path)] is not None}
    with _quiescent_locks(locks, sync), contextlib.ExitStack() as stack:
        if source_info["memory_database_present"]:
            memory = stack.enter_context(database_backup.readonly_database(config.vault_path, deadline))
        else:
            # Capture can be pending before the first successful memory write.
            # Build an empty snapshot in RAM, not an initialized source Vault.
            # Its store ID is a snapshot placeholder, explicitly labelled below.
            memory = stack.enter_context(contextlib.closing(sqlite3.connect(":memory:")))
            database_backup._harden(memory, deadline, readonly=False)
            Vault._initialize(memory)
            memory.commit()
        summary = database_backup.database_summary(memory)
        database_backup._integrity(memory)
        source_info["store_id"] = summary["store_id"]
        databases: dict[str, sqlite3.Connection] = {}
        control_summaries: dict[str, Any] = {}
        for source in initial_sources:
            if source.kind == "sqlite":
                connection = stack.enter_context(database_backup.readonly_database(source.path, deadline))
                control_summaries[source.component] = _control_summary(connection, source.component, source_info)
                databases[source.component] = connection
        sources, before, _ = _inventory(config, selected, sync, deadline)
        _require((before[str(config.vault_path)] is not None) == source_info["memory_database_present"], "recovery_source_changed")
        # A DB appearing between discovery and the pinned read transactions is
        # a concurrent writer, not an invitation to snapshot it at another time.
        _require({item.component for item in sources if item.kind == "sqlite"} == set(databases), "recovery_source_changed")
        for item in initial_sources:
            if item.kind in {"sqlite", "memory"}:
                _require(initial_inventory[str(item.path)] == before.get(str(item.path)), "recovery_source_changed")
        hashes = {str(item.path): _hash_file(item.path, deadline) for item in sources}
        _require(sum(value[1] for value in hashes.values()) <= MAX_TOTAL_BYTES, "client_recovery_total_limit")
        _new_directory(destination)
        memory_dir = destination / "memory"
        _new_directory(memory_dir)
        memory_digest, memory_size = _snapshot(memory, memory_dir / database_backup.SNAPSHOT_NAME, deadline)
        memory_manifest = {
            "schema_version": database_backup.BACKUP_SCHEMA, "created_at": utc_now(),
            "source_database_schema": summary["database_schema"], "source_store_id": summary["store_id"],
            "database": {"name": database_backup.SNAPSHOT_NAME, "bytes": memory_size, "sha256": memory_digest},
            "counts": summary["counts"], "attestations": summary["attestations"],
            "components": list(database_backup.COMPONENTS), "excluded": list(database_backup.EXCLUDED),
            "checksum_authenticates_sender": False, "client_state_consistently_snapshotted": False,
        }
        _write_json(memory_dir / database_backup.MANIFEST_NAME, memory_manifest)
        manifest_hash, manifest_size = _hash_file(memory_dir / database_backup.MANIFEST_NAME, deadline)
        entries = [_entry("memory", "memory/" + database_backup.SNAPSHOT_NAME, "sqlite", memory_digest, memory_size),
                   _entry("memory", "memory/" + database_backup.MANIFEST_NAME, "json", manifest_hash, manifest_size)]
        for item in sources:
            if item.logical is None:
                continue
            target = destination.joinpath(*PurePosixPath(item.logical).parts)
            if item.kind == "sqlite":
                digest, size = _snapshot(databases[item.component], target, deadline)
            else:
                digest, size = _copy_file(item.path, target, deadline, maximum=MAX_CONTROL_BYTES)
                _require((digest, size) == hashes[str(item.path)], "recovery_source_changed")
            entries.append(_entry(item.component, item.logical, item.kind, digest, size))
        final_sources, after, _ = _inventory(config, selected, sync, deadline)
        _require(before == after and {str(item.path) for item in sources} == {str(item.path) for item in final_sources},
                 "recovery_source_changed")
        for item in final_sources:
            _require(_hash_file(item.path, deadline) == hashes[str(item.path)], "recovery_source_changed")
        _require(_inventory(config, selected, sync, deadline)[1] == before, "recovery_source_changed")
        _require(ClientConfig.load(config.path) == config, "recovery_source_changed")
        if sync is not None:
            _require(bound_sync_config(config) == sync, "recovery_source_changed")
        _require(sum(item["bytes"] for item in entries) <= MAX_TOTAL_BYTES, "client_recovery_total_limit")
        manifest = {"schema_version": BACKUP_SCHEMA, "created_at": utc_now(), "components": selected,
                    "source": source_info, "entries": sorted(entries, key=lambda item: item["path"]),
                    "control_summaries": control_summaries, "excluded": list(_EXCLUDED),
                    "consistency": {"mode": "operator_offline_quiesced", "global_atomic_snapshot": False,
                                    "selected_source_inventory_rechecked": True, "selected_source_content_rechecked": True,
                                    "existing_advisory_locks_checked": len(locks), "uncooperative_writers_excluded_by_operator": True},
                    "checksum_authenticates_sender": False, "contains_plaintext_memory": True,
                    "restored_state_may_execute": False}
        database_backup._check_time(deadline)
        _write_json(destination / "manifest.json", manifest)
    return {"state": "client_snapshot_created", "backup": str(destination), "components": selected,
            "files": len(entries), "bytes": sum(item["bytes"] for item in entries),
            "consistency": manifest["consistency"], "keys_copied": False, "network_accessed": False,
            "manifest_is_commit_marker": True, "control_state_is_authorization": False}


def _entry_path(value: Mapping[str, Any]) -> tuple[str, ...]:
    _require(set(value) == {"entry_id", "component", "path", "kind", "sha256", "bytes"}, "invalid_client_backup_manifest")
    path, component = value["path"], value["component"]
    _require(isinstance(component, str) and isinstance(path, str) and "\\" not in path and "\x00" not in path
             and not path.startswith("/") and ".." not in PurePosixPath(path).parts
             and str(PurePosixPath(path)) == path, "invalid_client_backup_path")
    parts = PurePosixPath(path).parts
    expected_kind = None
    if parts == ("memory", database_backup.SNAPSHOT_NAME) and component == "memory":
        expected_kind = "sqlite"
    elif parts == ("memory", database_backup.MANIFEST_NAME) and component == "memory":
        expected_kind = "json"
    elif len(parts) >= 3 and parts[0] == "control" and parts[1] == component:
        if component == "hooks" and len(parts) == 4 and parts[2] in _HOOK_GROUPS and _QUEUE.fullmatch(parts[3]):
            expected_kind = "json"
        elif component in _DATABASE_NAMES and parts[2:] == (_DATABASE_NAMES[component],):
            expected_kind = "sqlite"
        elif component == "hosts":
            expected_kind = _host_kind(parts[2:], False)
        elif component == "sync":
            expected_kind = _sync_kind(parts[2:], False)
    _require(expected_kind in {"sqlite", "json", "opaque"} and value["kind"] == expected_kind,
             "unsupported_client_backup_entry")
    maximum = (database_backup.MAX_DATABASE_BYTES if component == "memory" and expected_kind == "sqlite"
               else MAX_CONTROL_DATABASE_BYTES if expected_kind == "sqlite" else MAX_CONTROL_BYTES)
    _require(isinstance(value["sha256"], str) and _HASH.fullmatch(value["sha256"]) is not None
             and type(value["bytes"]) is int and 0 <= value["bytes"] <= maximum
             and value["entry_id"] == "item_" + sha256(canonical_bytes([path, value["sha256"]])),
             "invalid_client_backup_entry")
    return parts


def _check_archive_tree(root: Path, entries: Sequence[Mapping[str, Any]], deadline: float) -> None:
    files = {item["path"] for item in entries} | {"manifest.json"}
    prefixes = {str(parent) for path in files for parent in PurePosixPath(path).parents if str(parent) != "."}
    found: set[str] = set()
    seen = 0

    def scan(directory: Path, prefix: str = "") -> None:
        nonlocal seen
        _private_directory(directory)
        with os.scandir(directory) as children:
            for child in children:
                database_backup._check_time(deadline)
                seen += 1
                _require(seen <= MAX_FILES + MAX_DIRECTORIES + 1, "client_recovery_file_limit")
                relative = prefix + child.name
                path = Path(child.path)
                if child.is_dir(follow_symlinks=False):
                    _require(relative in prefixes, "unexpected_client_backup_entry")
                    scan(path, relative + "/")
                else:
                    _require(relative in files, "unexpected_client_backup_entry")
                    database_backup.regular(path)
                    found.add(relative)
    scan(root)
    _require(found == files, "client_backup_incomplete")


def _manifest(root: Path, deadline: float) -> tuple[dict[str, Any], str]:
    _private_directory(root)
    path = root / "manifest.json"
    digest, _ = _hash_file(path, deadline, maximum=MAX_MANIFEST_BYTES)
    value = _read_json(path, deadline, maximum=MAX_MANIFEST_BYTES)
    _require(set(value) == {"schema_version", "created_at", "components", "source", "entries", "control_summaries",
                           "excluded", "consistency", "checksum_authenticates_sender", "contains_plaintext_memory",
                           "restored_state_may_execute"}
             and value["schema_version"] == BACKUP_SCHEMA and value["checksum_authenticates_sender"] is False
             and value["contains_plaintext_memory"] is True and value["restored_state_may_execute"] is False,
             "invalid_client_backup_manifest")
    selected = _selection(value["components"])
    source = value["source"]
    _require(isinstance(source, dict) and set(source) == {"store_id", "vault_path_sha256", "compat_vault_path_sha256",
                                                       "signed_writes_configured", "capture_visible_turns_configured", "sync_configured",
                                                       "memory_database_present"},
             "invalid_client_backup_manifest")
    _require(isinstance(source["store_id"], str) and _STORE.fullmatch(source["store_id"]) is not None
             and all(isinstance(source[key], str) and _HASH.fullmatch(source[key]) is not None
                     for key in ("vault_path_sha256", "compat_vault_path_sha256"))
             and all(type(source[key]) is bool for key in ("signed_writes_configured", "capture_visible_turns_configured", "sync_configured", "memory_database_present")),
             "invalid_client_backup_manifest")
    consistency = value["consistency"]
    _require(isinstance(consistency, dict) and set(consistency) == {
        "mode", "global_atomic_snapshot", "selected_source_inventory_rechecked", "selected_source_content_rechecked",
        "existing_advisory_locks_checked", "uncooperative_writers_excluded_by_operator"}
        and consistency["mode"] == "operator_offline_quiesced" and consistency["global_atomic_snapshot"] is False
        and consistency["selected_source_inventory_rechecked"] is True and consistency["selected_source_content_rechecked"] is True
        and consistency["uncooperative_writers_excluded_by_operator"] is True
        and type(consistency["existing_advisory_locks_checked"]) is int
        and 0 <= consistency["existing_advisory_locks_checked"] <= MAX_FILES, "invalid_client_backup_manifest")
    entries = value["entries"]
    _require(isinstance(entries, list) and 2 <= len(entries) <= MAX_FILES + 2, "invalid_client_backup_manifest")
    paths: set[str] = set()
    for entry in entries:
        _require(isinstance(entry, dict), "invalid_client_backup_entry")
        _entry_path(entry)
        _require(entry["component"] == "memory" or entry["component"] in selected, "unselected_client_backup_entry")
        _require(entry["path"] not in paths, "duplicate_client_backup_entry")
        paths.add(entry["path"])
    _require({"memory/" + database_backup.SNAPSHOT_NAME, "memory/" + database_backup.MANIFEST_NAME} <= paths
             and sum(entry["bytes"] for entry in entries) <= MAX_TOTAL_BYTES, "client_backup_incomplete")
    _require(isinstance(value["control_summaries"], dict) and not set(value["control_summaries"]) - (set(selected) & set(_DATABASE_NAMES))
             and value["excluded"] in (list(_LEGACY_EXCLUDED), list(_EXCLUDED)), "invalid_client_backup_manifest")
    for component, summary in value["control_summaries"].items():
        _require(isinstance(summary, dict), "invalid_client_backup_manifest")
        version = _control_version(component, summary.get("schema_version"))
        schema, _, columns = _control_layout(component, version)
        expected_tables = set(columns)
        allowed_phases = (set() if component == "hooks" else {"staged", "committing", "committed", "aborted"}
                          if component == "lifecycle" else {"staged", "pending", "done", "aborted"})
        _require(isinstance(summary, dict) and set(summary) == {"schema_version", "counts", "turn_phases"}
                 and summary["schema_version"] == schema
                 and isinstance(summary["counts"], dict) and set(summary["counts"]) == expected_tables
                 and all(type(count) is int and 0 <= count <= _control_count_limit(name) for name, count in summary["counts"].items())
                 and isinstance(summary["turn_phases"], dict)
                 and not set(summary["turn_phases"]) - allowed_phases
                 and all(type(count) is int and 0 <= count <= MAX_CONTROL_ROWS for count in summary["turn_phases"].values()),
                 "invalid_client_backup_manifest")
    _check_archive_tree(root, entries, deadline)
    _require(_hash_file(path, deadline, maximum=MAX_MANIFEST_BYTES)[0] == digest, "recovery_source_changed")
    return value, digest


def _checked_entry(root: Path, entry: Mapping[str, Any], deadline: float) -> Path:
    path = root.joinpath(*_entry_path(entry))
    _require(_hash_file(path, deadline, maximum=entry["bytes"]) == (entry["sha256"], entry["bytes"]),
             "client_backup_checksum_mismatch")
    return path


def _remaining_timeout(deadline: float) -> int:
    database_backup._check_time(deadline)
    return max(1, min(database_backup.MAX_TIMEOUT, int(deadline - time.monotonic()) + 1))


def _external_trust(path: Path | None, forbidden: Sequence[Path]) -> Path | None:
    if path is None:
        return None
    selected = database_backup.absolute(path)
    _require(not any(_overlaps(selected, root) for root in forbidden), "independent_recovery_trust_required")
    database_backup.regular(selected)
    return selected


def restore_client(backup: Path, output: Path, *, trust_store: Path | None = None,
                   accept_unsigned: bool = False, timeout: int = database_backup.DEFAULT_TIMEOUT) -> Mapping[str, Any]:
    """New memory DB plus inert evidence; never re-enable old host or sync state."""
    protected_storage.require_supported_storage()
    deadline = database_backup._deadline(timeout)
    source, destination = database_backup.absolute(backup), database_backup.absolute(output)
    _require(not _overlaps(source, destination), "restore_requires_new_external_path")
    trust = _external_trust(trust_store, (source, destination))
    manifest, digest = _manifest(source, deadline)
    _new_directory(destination)
    evidence = destination / "evidence"
    _new_directory(evidence)
    for entry in manifest["entries"]:
        path = _checked_entry(source, entry, deadline)
        copied = _copy_file(path, evidence.joinpath(*_entry_path(entry)), deadline, maximum=entry["bytes"])
        _require(copied == (entry["sha256"], entry["bytes"]), "client_backup_checksum_mismatch")
    copied_manifest, _ = _copy_file(source / "manifest.json", evidence / "manifest.json", deadline, maximum=MAX_MANIFEST_BYTES)
    _require(copied_manifest == digest, "recovery_source_changed")
    original_memory, _ = database_backup._manifest(evidence / "memory")
    _require(original_memory["source_store_id"] == manifest["source"]["store_id"]
             and (manifest["source"]["memory_database_present"] or original_memory["counts"]["memories"] == 0),
             "client_backup_memory_binding_changed")
    restored = database_backup.restore_database(evidence / "memory", destination / "memory.sqlite3", trust_store=trust,
                                                accept_unsigned=accept_unsigned, timeout=_remaining_timeout(deadline))
    from memory_vault_client import CONFIG_SCHEMA
    config: dict[str, Any] = {"schema_version": CONFIG_SCHEMA, "vault_path": str(destination / "memory.sqlite3"),
                              "capture_visible_turns": False}
    # An independently selected trust registry is a current read-time check,
    # not a policy imported from the archive. No signing identity is selected.
    if trust is not None:
        config["trust_path"] = str(trust)
    _write_json(destination / "client.json", config)
    recovery = {"schema_version": RECOVERY_SCHEMA, "created_at": utc_now(), "evidence_manifest_sha256": digest,
                "source_store_id": manifest["source"]["store_id"], "new_store_id": restored["new_store_id"],
                "baseline_database_sha256": restored["database_sha256"], "components": manifest["components"],
                "control_state_active": False, "capture_enabled": False, "sync_enabled": False,
                "old_transfer_authorizations_restored": False, "host_permissions_restored": False,
                "keys_restored": False, "evidence_is_authorization": False}
    _write_json(destination / "recovery.json", recovery)
    return {"state": "client_restored_inert", "recovery": str(destination), "config": str(destination / "client.json"),
            "vault": str(destination / "memory.sqlite3"), "evidence": str(evidence), "components": manifest["components"],
            "memory": restored, "control_state_active": False, "pending_replayed": False, "sync_enabled": False,
            "local_resume_requires_explicit_authorization": True, "network_accessed": False,
            "historical_receipts_are_current_trust": False}


def _recovery(root: Path, deadline: float) -> tuple[dict[str, Any], dict[str, Any], Path]:
    _private_directory(root)
    receipt = _read_json(root / "recovery.json", deadline, maximum=32 * 1024)
    _require(set(receipt) == {"schema_version", "created_at", "evidence_manifest_sha256", "source_store_id", "new_store_id",
                             "baseline_database_sha256", "components", "control_state_active", "capture_enabled", "sync_enabled",
                             "old_transfer_authorizations_restored", "host_permissions_restored", "keys_restored", "evidence_is_authorization"}
             and receipt["schema_version"] == RECOVERY_SCHEMA
             and all(receipt[name] is False for name in ("control_state_active", "capture_enabled", "sync_enabled",
                                                         "old_transfer_authorizations_restored", "host_permissions_restored",
                                                         "keys_restored", "evidence_is_authorization")), "invalid_client_recovery_manifest")
    evidence = root / "evidence"
    manifest, digest = _manifest(evidence, deadline)
    _require(receipt["evidence_manifest_sha256"] == digest and receipt["components"] == manifest["components"]
             and receipt["source_store_id"] == manifest["source"]["store_id"]
             and isinstance(receipt["new_store_id"], str) and _STORE.fullmatch(receipt["new_store_id"]) is not None
             and receipt["new_store_id"] != receipt["source_store_id"]
             and isinstance(receipt["baseline_database_sha256"], str) and _HASH.fullmatch(receipt["baseline_database_sha256"]) is not None,
             "client_recovery_binding_changed")
    with database_backup.readonly_database(root / "memory.sqlite3", deadline) as connection:
        _require(database_backup.database_summary(connection)["store_id"] == receipt["new_store_id"], "client_recovery_binding_changed")
    return receipt, manifest, evidence


def _capsule_candidate(entry: Mapping[str, Any]) -> bool:
    parts = PurePosixPath(entry["path"]).parts
    return entry["component"] == "sync" and (parts == ("control", "sync", "transfer", "publish.pending.json")
        or (len(parts) == 5 and parts[2:4] == ("transfer", "received-capsules") and _QUEUE.fullmatch(parts[4]) is not None)
        or (len(parts) == 6 and parts[2] == "transfer" and parts[3] == "publication-reviews" and parts[5] in {"original.json", "replacement.json"})
        or (len(parts) == 6 and parts[2] == "exchange" and _CAPSULE.fullmatch(parts[5]) is not None))


def review_recovery(recovery: Path, *, component: str | None = None, offset: int = 0, limit: int = 50,
                    timeout: int = database_backup.DEFAULT_TIMEOUT) -> Mapping[str, Any]:
    """Bounded content-free inventory; an entry is not a signature approval."""
    _require(component is None or component in COMPONENTS | {"memory"}, "invalid_recovery_component")
    _require(type(offset) is int and 0 <= offset <= MAX_FILES and type(limit) is int and 1 <= limit <= 100,
             "invalid_recovery_page")
    deadline = database_backup._deadline(timeout)
    receipt, manifest, _ = _recovery(database_backup.absolute(recovery), deadline)
    items = [item for item in manifest["entries"] if component is None or item["component"] == component]
    page = [{**item, "local_activation_candidate": item["component"] in LOCAL_COMPONENTS,
             "signed_memory_import_candidate": _capsule_candidate(item), "contents_read": False,
             "current_signature_trust_verified": False} for item in items[offset:offset + limit]]
    return {"state": "recovery_evidence_review", "evidence_manifest_sha256": receipt["evidence_manifest_sha256"],
            "entries": page, "total": len(items), "next_offset": offset + len(page) if offset + len(page) < len(items) else None,
            "source_control_summaries": manifest["control_summaries"], "source_summaries_are_historical": True,
            "capture_enabled": False, "pending_replayed": False, "network_accessed": False,
            "review_is_authorization": False, "sync_requires_new_configuration_and_stream": True}


def _match(value: Any, pattern: re.Pattern[str], *, nullable: bool = False) -> None:
    _require((value is None and nullable) or (isinstance(value, str) and pattern.fullmatch(value) is not None))


def _text(value: Any, maximum: int, *, nullable: bool = False) -> None:
    if value is None and nullable:
        return
    _require(isinstance(value, str) and bool(value.strip()) and "\x00" not in value)
    _require(len(value.encode("utf-8")) <= maximum)


def _object(value: Any, required: set[str], optional: set[str] = frozenset()) -> dict[str, Any]:
    _require(isinstance(value, dict) and required <= set(value) and not set(value) - required - optional)
    return dict(value)


def _record_reference(connection: sqlite3.Connection, memory_id: Any, *, kind: str | None = None,
                      digest: str | None = None) -> None:
    _match(memory_id, _MEMORY)
    row = connection.execute("SELECT kind,record_sha256 FROM memories WHERE memory_id=?", (memory_id,)).fetchone()
    _require(row is not None and (kind is None or row["kind"] == kind)
             and (digest is None or row["record_sha256"] == digest), "restored_control_memory_reference_missing")


def _lifecycle_response(value: Any, memory: sqlite3.Connection | None = None) -> dict[str, Any]:
    from memory_vault_client import _REQUEST
    from memory_vault_lifecycle import RESULT_SCHEMA, OPERATIONS, _SESSION, _TURN
    response = _object(value, {"schema_version", "ok", "authority", "result", "request_id", "op", "replayed"})
    _require(response["schema_version"] == RESULT_SCHEMA and response["ok"] is True
             and response["authority"] == AUTHORITY and type(response["replayed"]) is bool
             and response["op"] in OPERATIONS and response["op"] != "capabilities")
    _match(response["request_id"], _REQUEST)
    allowed = {
        "session.open": {"state", "current_state", "session_handle", "memory_saved", "network_accessed"},
        "session.close": {"state", "current_state", "session_handle", "aborted_turns", "memory_saved", "long_term_memory_deleted", "network_accessed"},
        "turn.input": {"state", "current_state", "session_handle", "turn_handle", "memory_saved", "capture_basis", "network_accessed"},
        "turn.abort": {"state", "current_state", "session_handle", "turn_handle", "memory_saved", "long_term_memory_deleted", "network_accessed"},
        "turn.commit": {"state", "current_state", "session_handle", "turn_handle", "memory_saved", "episode_id", "continuity_id",
                        "capture_basis", "host_attestation", "network_accessed", "receipt_scope"},
    }
    result = _object(response["result"], allowed[response["op"]])
    _match(result["session_handle"], _SESSION)
    _require(result["network_accessed"] is False and type(result["memory_saved"]) is bool
             and result["current_state"] in {"open", "closed", "staged", "committing", "committed", "aborted"})
    if "turn_handle" in result:
        _match(result["turn_handle"], _TURN)
    for field, kind in (("episode_id", "episode"), ("continuity_id", "continuity")):
        if field in result:
            _match(result[field], _MEMORY)
            if memory is not None:
                _record_reference(memory, result[field], kind=kind)
    if response["op"] == "turn.commit":
        _require(result["host_attestation"] is False and result["capture_basis"] == "caller_reported"
                 and result["receipt_scope"] == "local_save_not_current_trust_or_remote_delivery")
    return response


def _compat_response(value: Any) -> dict[str, Any]:
    from memory_vault_compat import RESPONSE_SCHEMA, PROTOCOL_VERSION, RECEIPT_OPERATIONS, _authority, _REQUEST, _CONTINUITY, _TURN
    response = _object(value, {"schema_version", "protocol_version", "request_id", "operation", "status", "authority", "result"})
    _require(response["schema_version"] == RESPONSE_SCHEMA and response["protocol_version"] == PROTOCOL_VERSION
             and response["authority"] == _authority() and response["operation"] in RECEIPT_OPERATIONS
             and response["status"] in {"accepted_local", "published", "duplicate", "degraded"})
    _match(response["request_id"], _REQUEST)
    allowed = {
        "session.open": ({"continuity_handle", "sync_state", "network_accessed"}, set()),
        "session.close": ({"continuity_handle", "closed", "network_accessed"}, set()),
        "turn.input": ({"continuity_handle", "turn_handle", "evidence_context", "network_accessed"}, set()),
        "turn.abort": ({"continuity_handle", "turn_handle", "aborted", "terminal_state", "network_accessed"}, {"queue_state"}),
        "turn.commit": ({"continuity_handle", "turn_handle", "outcome", "receipt_id", "queue_state", "network_accessed"}, set()),
    }
    result = _object(response["result"], *allowed[response["operation"]])
    _match(result["continuity_handle"], _CONTINUITY)
    _require(type(result["network_accessed"]) is bool)
    if "turn_handle" in result:
        _match(result["turn_handle"], _TURN)
    if "evidence_context" in result:
        _require(result["evidence_context"] is None)
    if "receipt_id" in result:
        _match(result["receipt_id"], re.compile(r"mvrturn_[0-9a-f]{64}"))
    if "queue_state" in result:
        _require(result["queue_state"] in {"pending", "done"})
    if "sync_state" in result:
        _match(result["sync_state"], re.compile(r"[a-z][a-z0-9_]{1,95}"))
        # The exact old response remains in evidence. The active derived copy
        # must not report an old network window as a new recovery-time action.
        result["sync_state"] = "historical_restored_receipt"
    result["network_accessed"] = False
    response["result"] = result
    response["status"] = "accepted_local"
    return response


def _validate_control_row(component: str, table: str, row: dict[str, Any], memory: sqlite3.Connection) -> dict[str, Any]:
    if table == "capture_sessions":
        _require(set(row) == {"session_handle", "scope_key"})
        _match(row["session_handle"], re.compile(r"ses_[0-9a-f]{32}"))
        _match(row["scope_key"], _CAPTURE_KEY)
        return row
    if table in CAPTURE_COLUMNS:
        _require(set(row) == set(CAPTURE_COLUMNS[table]))
        if table == "capture_jobs":
            return validate_capture_header(row)
        if table == "capture_heads":
            _match(row["scope_key"], _CAPTURE_KEY)
            _match(row["last_job_key"], _CAPTURE_KEY, nullable=True)
            _require(type(row["accepted_sequence"]) is int and 0 <= row["accepted_sequence"] <= 2**63 - 1)
        else:
            _match(row["job_key"], _CAPTURE_KEY)
            _match(row["memory_id"], _MEMORY)
            _match(row["record_sha256"], _HASH)
            _require(type(row["ordinal"]) is int and 0 <= row["ordinal"] < MAX_CAPTURE_RECORDS
                     and row["memory_id"] == "mem_" + row["record_sha256"][:40])
            if row["record_json"] is not None:
                _require(isinstance(row["record_json"], str)
                         and len(row["record_json"].encode("utf-8")) <= MAX_BUNDLE_LINE_BYTES)
                record = validate_record(strict_json_loads(row["record_json"]))
                _require(record["memory_id"] == row["memory_id"] and record["record_sha256"] == row["record_sha256"])
        return row
    from memory_vault_client import _digest
    from memory_vault_lifecycle import _SESSION, _TURN
    from memory_vault_compat import _CONTINUITY, _TURN as COMPAT_TURN
    session_pattern, turn_pattern = (_SESSION, _TURN) if component == "lifecycle" else (_CONTINUITY, COMPAT_TURN)
    if table == "sessions":
        _match(row["handle"], session_pattern)
        _require(row["state"] in {"open", "closed"})
    elif table == "turns":
        _match(row["handle"], turn_pattern)
        _match(row["session_handle"], session_pattern)
        phase = row["phase"]
        pending = {"staged", "committing"} if component == "lifecycle" else {"staged", "pending"}
        _require(phase in pending | ({"committed", "aborted"} if component == "lifecycle" else {"done", "aborted"}))
        maximum = 480 * 1024 if component == "lifecycle" else 2 * 1024 * 1024
        for field in ("user_text", "assistant_text"):
            _text(row[field], maximum, nullable=True)
        if phase in pending:
            _require(row["user_text"] is not None and (phase == "staged" or row["assistant_text"] is not None))
        else:
            _require(row["user_text"] is None and row["assistant_text"] is None)
        if component == "lifecycle":
            _text(row["continuity_text"], 32 * 1024, nullable=True)
            _match(row["commit_request"], _HASH, nullable=True)
            _require((phase != "committing" or (row["continuity_text"] is not None and row["commit_request"] is not None))
                     and (phase not in {"committed", "aborted"} or row["continuity_text"] is None))
        else:
            _match(row["user_sha256"], _HASH)
            _match(row["assistant_sha256"], _HASH, nullable=True)
            for field, digest in (("user_text", "user_sha256"), ("assistant_text", "assistant_sha256")):
                if row[field] is not None:
                    _require(sha256(row[field].encode("utf-8")) == row[digest])
            _text(row["created_at"], 64)
            _match(row["receipt_id"], re.compile(r"mvrturn_[0-9a-f]{64}"), nullable=True)
            _match(row["last_error"], re.compile(r"[a-z][a-z0-9_]{1,95}"), nullable=True)
            _text(row["abort_reason"], 96, nullable=True)
            _require(phase not in {"pending", "done"} or row["receipt_id"] is not None)
            if row["memory_id"] is not None:
                _record_reference(memory, row["memory_id"], kind="episode")
            _require(phase != "done" or row["memory_id"] is not None)
    elif table == "requests":
        _match(row["request_key"], _HASH)
        _match(row["payload_sha256"] if component == "lifecycle" else row["request_sha256"], _HASH)
        _match(row["turn_handle"], turn_pattern, nullable=True)
        if component == "lifecycle":
            _match(row["session_handle"], session_pattern)
        if row["response_json"] is not None:
            response = strict_json_loads(row["response_json"])
            response = _lifecycle_response(response, memory) if component == "lifecycle" else _compat_response(response)
            key = _digest(response["request_id"]) if component == "lifecycle" else sha256(response["request_id"].encode("ascii"))
            _require(key == row["request_key"])
            row["response_json"] = canonical_bytes(response).decode("utf-8")
        else:
            _require(component == "lifecycle" and row["turn_handle"] is not None)
    elif table == "semantic_jobs":
        _match(row["proposal_sha256"], _HASH)
        _text(row["created_at"], 64)
        if row["memory_id"] is not None:
            _record_reference(memory, row["memory_id"])
    elif table == "aliases":
        _match(row["legacy_id"], re.compile(r"(?:ep|evt)-[0-9a-f]{40}"))
        _match(row["record_sha256"], _HASH)
        _match(row["source_id"], re.compile(r"src-[0-9a-f]{40}"), nullable=True)
        _match(row["evidence_anchor_sha256"], _HASH, nullable=True)
        _record_reference(memory, row["memory_id"], digest=row["record_sha256"],
                          kind="episode" if row["legacy_id"].startswith("ep-") else None)
        if row["legacy_id"].startswith("evt-"):
            _require(memory.execute("SELECT kind FROM memories WHERE memory_id=?", (row["memory_id"],)).fetchone()[0] != "episode")
    return row


def _validate_capture_control(connection: sqlite3.Connection, component: str,
                              memory: sqlite3.Connection, deadline: float) -> None:
    """Verify local correlations and hydrate saved plans from actual canonical facts.

    Pending predecessors can refer to another accepted plan, not yet a Vault
    row. Saved metadata must instead resolve every full hash. Neither case is a
    signature/admission decision or authorization to run a restored request.
    """
    validate_capture_state(connection)
    for original in connection.execute("SELECT job_key FROM capture_jobs ORDER BY scope_key,accepted_sequence"):
        database_backup._check_time(deadline)
        plan = load_capture(connection, original[0])
        _require(plan is not None)
        records = []
        for reference in plan["record_refs"]:
            database_backup._check_time(deadline)
            canonical = memory.execute("SELECT record_json,record_sha256 FROM memories WHERE memory_id=?", (reference["memory_id"],)).fetchone()
            if canonical is None:
                _require(plan["state"] == "pending", "restored_control_memory_reference_missing")
                continue
            record = validate_record(strict_json_loads(canonical["record_json"]))
            _require(record["memory_id"] == reference["memory_id"]
                     and record["record_sha256"] == canonical["record_sha256"] == reference["record_sha256"],
                     "restored_control_memory_reference_missing")
            records.append(record)
        if plan["state"] == "saved":
            validate_capture_projection(plan, records)
        if component == "hooks" and plan["builder_profile"] == HOOK_FRAGMENT_PROFILE:
            validate_hook_fragment_projection(plan, records if plan["state"] == "saved" else plan["records"])
        if component in {"lifecycle", "hooks"}:
            from memory_vault import RESULT_SCHEMA as CORE_RESULT_SCHEMA
            from memory_vault_client import _digest
            core_receipt = memory.execute("SELECT request_sha256,response_json FROM receipts WHERE request_id=?", (plan["canonical_request_id"],)).fetchone()
            if core_receipt is None:
                _require(plan["state"] == "pending", "capture_receipt_missing")
            else:
                _require(len(records) == plan["record_count"], "restored_control_memory_reference_missing")
                validate_capture_projection(plan, records)
                episode = next(record for record in records if record["memory_id"] == plan["episode_id"])
                expected_result = {
                    "state": "saved_local", "episode_id": plan["episode_id"], "continuity_id": plan["continuity_id"],
                    "capture_basis": "host_event_fields" if episode["provenance"].get("source_type") == "visible_turn" else "caller_reported",
                    "host_attestation": False, "network_accessed": False,
                }
                expected_response = {"schema_version": CORE_RESULT_SCHEMA, "ok": True, "authority": dict(AUTHORITY),
                                     "result": expected_result, "request_id": plan["canonical_request_id"]}
                _require(core_receipt["request_sha256"] == _digest({"profile": "memory-vault-client-capture-receipt/v1",
                                                                    "projection_sha256": plan["projection_sha256"]})
                         and strict_json_loads(core_receipt["response_json"]) == expected_response, "invalid_capture_receipt")
        if component == "lifecycle":
            from memory_vault_lifecycle import CAPTURE_PROFILE, LifecycleState
            turn = connection.execute("SELECT * FROM turns WHERE handle=?", (plan["job_key"],)).fetchone()
            _require(turn is not None and turn["phase"] in {"committing", "committed"}
                     and plan["builder_profile"] == CAPTURE_PROFILE)
            scope = connection.execute("SELECT scope_key FROM capture_sessions WHERE session_handle=?", (turn["session_handle"],)).fetchone()
            _require(scope is not None and scope[0] == plan["scope_key"])
            if turn["phase"] == "committing":
                LifecycleState.check_plan(turn, plan, scope[0])
            else:
                _require(plan["state"] == "saved")
                receipt = connection.execute("SELECT response_json FROM requests WHERE request_key=?", (turn["commit_request"],)).fetchone()
                _require(receipt is not None and receipt[0] is not None)
                response = _lifecycle_response(strict_json_loads(receipt[0]), memory)
                _require(response["op"] == "turn.commit" and response["result"]["turn_handle"] == plan["job_key"]
                         and response["result"]["episode_id"] == plan["episode_id"]
                         and response["result"]["continuity_id"] == plan["continuity_id"])
                from memory_vault_client import _request_id
                _require(plan["canonical_request_id"] == _request_id(response["request_id"], "lifecycle-capture-v2"))
        elif component == "compat":
            from memory_vault_compat import ALIAS_PROFILE, _projection_receipt, validate_capture_turn
            turn = connection.execute("SELECT * FROM turns WHERE handle=?", (plan["job_key"],)).fetchone()
            _require(turn is not None)
            validate_capture_turn(dict(turn), plan)
            core_receipt = memory.execute("SELECT request_sha256,response_json FROM receipts WHERE request_id=?", (plan["canonical_request_id"],)).fetchone()
            if core_receipt is None:
                _require(plan["state"] == "pending", "capture_receipt_missing")
            else:
                _require(len(records) == plan["record_count"], "restored_control_memory_reference_missing")
                validate_capture_projection(plan, records)
                response = _projection_receipt(core_receipt["response_json"], plan["canonical_request_id"])
                _require(core_receipt["request_sha256"] == sha256(canonical_bytes({"profile": ALIAS_PROFILE, "records": records,
                                                                                 "anchor": plan["episode_id"]}))
                         and response["result"]["memory_id"] == plan["episode_id"]
                         and response["result"]["kind"] == "episode", "invalid_capture_receipt")
        else:
            _match(plan["job_key"], _HASH)
            _match(plan["scope_key"], _HASH)
            _require(plan["builder_profile"] in {"codex-visible-turn+continues/v1", HOOK_FRAGMENT_PROFILE}
                     and plan["canonical_request_id"] == "req_hook_capture_" + plan["job_key"])


def _rebuild_control(source: Path, destination: Path, component: str, old_source: Mapping[str, Any],
                     new_vault: Path, new_store: str, memory: sqlite3.Connection, deadline: float) -> Mapping[str, Any]:
    from memory_vault_client import _digest
    with database_backup.readonly_database(source, deadline, immutable=True) as original:
        summary = _control_summary(original, component, old_source)
        version = _control_version(component, summary["schema_version"])
        _, statements, _ = _control_layout(component, version)
        temporary = database_backup._new_temporary(destination.parent)
        try:
            with contextlib.closing(sqlite3.connect(temporary)) as rebuilt, rebuilt:
                database_backup._harden(rebuilt, deadline, readonly=False)
                if hasattr(rebuilt, "setlimit"):
                    rebuilt.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 8 * 1024 * 1024)
                rebuilt.execute("PRAGMA journal_mode=DELETE")
                rebuilt.execute("PRAGMA synchronous=FULL")
                rebuilt.execute("PRAGMA secure_delete=ON")
                rebuilt.execute("BEGIN IMMEDIATE")
                for statement in statements.values():
                    rebuilt.execute(statement)
                for table, statement in statements.items():
                    if not statement.startswith("CREATE TABLE"):
                        continue
                    for raw in original.execute("SELECT * FROM " + table):
                        database_backup._check_time(deadline)
                        row = dict(raw)
                        if table == "meta":
                            if row["key"] == "vault_path_sha256":
                                row["value"] = sha256(str(new_vault).encode("utf-8")) if component == "compat" else _digest(str(new_vault))
                            elif row["key"] == "store_id":
                                row["value"] = new_store
                        else:
                            row = _validate_control_row(component, table, row, memory)
                        columns = list(row)
                        rebuilt.execute("INSERT INTO " + table + "(" + ",".join(columns) + ") VALUES(" + ",".join("?" for _ in columns) + ")", tuple(row[name] for name in columns))
                rebuilt.execute("PRAGMA user_version=" + str(version))
                if component == "lifecycle":
                    # A NULL receipt is only an exact frozen turn.commit job.
                    invalid = rebuilt.execute(
                        "SELECT 1 FROM requests r LEFT JOIN turns t ON t.handle=r.turn_handle WHERE r.response_json IS NULL "
                        "AND (t.handle IS NULL OR t.phase!='committing' OR t.commit_request!=r.request_key) LIMIT 1").fetchone()
                    _require(invalid is None)
                    orphan = rebuilt.execute(
                        "SELECT 1 FROM turns t LEFT JOIN requests r ON r.request_key=t.commit_request WHERE t.phase='committing' "
                        "AND (r.request_key IS NULL OR r.turn_handle!=t.handle OR r.response_json IS NOT NULL) LIMIT 1").fetchone()
                    _require(orphan is None)
                if "capture_jobs" in statements:
                    rebuilt.row_factory = sqlite3.Row
                    _validate_capture_control(rebuilt, component, memory, deadline)
                database_backup._integrity(rebuilt)
            database_backup._publish_file(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)
    return summary


def _hook_document(value: Any, group: str, memory: sqlite3.Connection, *, key: str | None = None,
                   capture: sqlite3.Connection | None = None) -> dict[str, Any]:
    from memory_vault_client import FRAGMENT_STATE_SCHEMA, HookState, hook_supplement_key
    # Reuse closed source schemas, never an archive-supplied validator. Old
    # v1/v2 remain exact pairs; v3 explicitly records just one observed role.
    result = HookState.validate(group, value)
    fragment = result["schema_version"] == FRAGMENT_STATE_SCHEMA
    for field in ("user", "assistant"):
        if field in result and result[field] is not None:
            _text(result[field], 480 * 1024)
    if group == "done":
        _record_reference(memory, result["episode_id"], kind="episode")
        _record_reference(memory, result["continuity_id"], kind="continuity")
        _match(result["user_sha256"], _HASH, nullable=fragment)
        _match(result["assistant_sha256"], _HASH, nullable=fragment)
    if group == "conflicts":
        _require(result["reason"] == "different_prompts_for_same_turn")
    if key is not None and group in {"outbox", "done"}:
        if fragment:
            expected_key = result["turn_key"] if result["supplement"] is None else hook_supplement_key(result["turn_key"])
            _require(key == expected_key, "hook_recovery_fragment_turn_changed")
        plan = load_capture(capture, key) if capture is not None else None
        if fragment and group == "done":
            _require(plan is not None, "hook_recovery_capture_plan_missing")
        if plan is not None:
            _validate_hook_plan_document(plan, result, group)
    return result


def _validate_hook_plan_document(plan: Mapping[str, Any], value: Mapping[str, Any], group: str) -> None:
    from memory_vault_client import validate_hook_capture
    validate_hook_capture(plan, job=value if group == "outbox" else None, done=value if group == "done" else None)


def _hook_plan_evidence(plan: Mapping[str, Any], connection: sqlite3.Connection, state: Path,
                        memory: sqlite3.Connection, deadline: float) -> tuple[dict[str, Any], dict[str, Any]]:
    """Hydrate only canonical evidence; loading it grants no current admission."""
    from memory_vault_client import hook_capture_source
    prepared = dict(plan)
    if prepared["builder_profile"] == HOOK_FRAGMENT_PROFILE:
        if not prepared["records"]:
            records = []
            for reference in prepared["record_refs"]:
                database_backup._check_time(deadline)
                row = memory.execute("SELECT record_json,record_sha256 FROM memories WHERE memory_id=?", (reference["memory_id"],)).fetchone()
                _require(row is not None, "restored_control_memory_reference_missing")
                record = validate_record(strict_json_loads(row["record_json"]))
                _require(record["memory_id"] == reference["memory_id"]
                         and record["record_sha256"] == row["record_sha256"] == reference["record_sha256"],
                         "restored_control_memory_reference_missing")
                records.append(record)
            prepared["records"] = records
        validate_hook_fragment_projection(prepared, prepared["records"])
    documents = {}
    for group in ("outbox", "done"):
        path = state / group / (prepared["job_key"] + ".json")
        if path.exists():
            documents[group] = _hook_document(_read_json(path, deadline), group, memory,
                                               key=prepared["job_key"], capture=connection)
    # Canonical save -> durable done -> clear outbox -> mark saved may stop at
    # any boundary. Done alone is sufficient, including for a pending plan.
    _require(bool(documents), "hook_recovery_capture_evidence_missing")
    facts = hook_capture_source(prepared, job=documents.get("outbox"), done=documents.get("done"))
    return prepared, facts


def _validate_hook_fragment_anchor(connection: sqlite3.Connection, state: Path, memory: sqlite3.Connection,
                                   facts: Mapping[str, Any], deadline: float, *, plan: Mapping[str, Any] | None = None) -> None:
    """Prove the exact local turn's initial fragment, never a guessed head.

    An unaccepted outbox can precede its own plan, but its supplement must
    already have a durable initial plan. A pending initial plan may hold the
    anchor bytes before they exist in the Vault. Saved plans must hydrate from
    canonical records. Neither evidence source restores execution or trust.
    """
    from memory_vault_client import FRAGMENT_STATE_SCHEMA
    supplement = facts["supplement"]
    if supplement is None:
        return
    primary = load_capture(connection, facts["turn_key"])
    _require(primary is not None and primary["builder_profile"] == HOOK_FRAGMENT_PROFILE
             and primary["scope_key"] == facts["scope_key"]
             and (plan is None or primary["accepted_sequence"] < plan["accepted_sequence"]),
             "hook_recovery_fragment_turn_changed")
    primary, original = _hook_plan_evidence(primary, connection, state, memory, deadline)
    _require(original["schema_version"] == FRAGMENT_STATE_SCHEMA
             and original["turn_key"] == facts["turn_key"] and original["supplement"] is None
             and original["scope_key"] == facts["scope_key"], "hook_recovery_fragment_turn_changed")
    anchor = next(record for record in primary["records"] if record["memory_id"] == primary["episode_id"])
    _require(all(anchor[name] == supplement[name] for name in ("memory_id", "record_sha256")),
             "hook_recovery_fragment_anchor_changed")
    parsed = parse_hook_fragment(anchor)
    observed_role = "user" if facts["user_sha256"] is not None else "assistant"
    _require(parsed["supplement"] is None and parsed["observed_role"] != observed_role,
             "hook_recovery_fragment_anchor_changed")
    present = memory.execute("SELECT record_json,record_sha256 FROM memories WHERE memory_id=?", (anchor["memory_id"],)).fetchone()
    if present is not None:
        canonical = validate_record(strict_json_loads(present["record_json"]))
        _require(canonical == anchor and canonical["record_sha256"] == present["record_sha256"],
                 "hook_recovery_fragment_anchor_changed")
    else:
        _require(primary["state"] == "pending", "restored_control_memory_reference_missing")


def _validate_hook_capture_files(connection: sqlite3.Connection | None, state: Path,
                                  memory: sqlite3.Connection, deadline: float, *, outbox_keys: Sequence[str] = ()) -> None:
    from memory_vault_client import FRAGMENT_STATE_SCHEMA, _digest
    for original in connection.execute("SELECT job_key FROM capture_jobs") if connection is not None else ():
        database_backup._check_time(deadline)
        plan = load_capture(connection, original[0])
        _require(plan is not None)
        prepared, facts = _hook_plan_evidence(plan, connection, state, memory, deadline)
        if facts["schema_version"] == FRAGMENT_STATE_SCHEMA:
            _validate_hook_fragment_anchor(connection, state, memory, facts, deadline, plan=prepared)
    for key in outbox_keys:
        database_backup._check_time(deadline)
        if connection is not None and load_capture(connection, key) is not None:
            continue
        # Publication of source bytes may precede freeze. Do not manufacture a
        # timestamp/sequence/record ID just to validate that unaccepted outbox.
        value = _hook_document(_read_json(state / "outbox" / (key + ".json"), deadline), "outbox", memory,
                               key=key, capture=connection)
        if value["schema_version"] != FRAGMENT_STATE_SCHEMA or value["supplement"] is None:
            continue
        _require(connection is not None, "hook_recovery_capture_plan_missing")
        facts = {"schema_version": value["schema_version"], "scope_key": value["scope_key"],
                 "turn_key": value["turn_key"], "supplement": value["supplement"],
                 "user_sha256": _digest(value["user"]) if value["user"] is not None else None,
                 "assistant_sha256": _digest(value["assistant"]) if value["assistant"] is not None else None}
        _validate_hook_fragment_anchor(connection, state, memory, facts, deadline)


def _host_document(value: Any, parts: tuple[str, ...], old_source: Mapping[str, Any], new_vault: Path,
                   lifecycle: sqlite3.Connection, memory: sqlite3.Connection) -> dict[str, Any]:
    from memory_vault_client import _digest
    from memory_vault_hosts import STATE_SCHEMA
    from memory_vault_lifecycle import _SESSION, _TURN, _validate
    base = {"schema_version", "vault_path_sha256"}
    _require(isinstance(value, dict) and value.get("schema_version") == STATE_SCHEMA
             and value.get("vault_path_sha256") == old_source["vault_path_sha256"], "host_recovery_binding_changed")
    group = parts[2] if len(parts) == 4 else "session"
    if group == "session":
        result = _object(value, base | {"generation", "session_handle", "state", "active_turn"}, {"close_requested", "latest_input_stamp"})
        _require(type(result["generation"]) is int and 0 <= result["generation"] <= 2**63 - 1
                 and result["state"] in {"opening", "open", "closed"})
        _match(result["session_handle"], _SESSION, nullable=True)
        _match(result["active_turn"], _HASH, nullable=True)
        if "close_requested" in result:
            _require(type(result["close_requested"]) is bool)
        if "latest_input_stamp" in result:
            _text(result["latest_input_stamp"], 64)
    elif group == "turns":
        result = _object(value, base | {"turn_key", "session_handle", "turn_handle", "phase", "prompt_sha256", "stamp", "expected_active"})
        _require(result["phase"] in {"opening", "staged", "committing", "committed", "aborted"}
                 and result["turn_key"] + ".json" == parts[3])
        _match(result["turn_key"], _HASH)
        _match(result["session_handle"], _SESSION)
        _match(result["turn_handle"], _TURN, nullable=True)
        _match(result["prompt_sha256"], _HASH)
        _match(result["expected_active"], _HASH, nullable=True)
        _text(result["stamp"], 64, nullable=True)
    elif group == "pending":
        result = _object(value, base | {"request", "request_sha256", "turn_key"})
        request = _validate(result["request"])
        _require(request["op"] in {"turn.input", "turn.commit"}
                 and result["request_sha256"] == _digest(request) and parts[3] == _digest(request["request_id"]) + ".json")
        _match(result["turn_key"], _HASH)
        if request["op"] == "turn.input":
            _require(lifecycle.execute("SELECT 1 FROM sessions WHERE handle=?", (request["session_handle"],)).fetchone() is not None)
        else:
            _require(lifecycle.execute("SELECT 1 FROM turns WHERE handle=?", (request["turn_handle"],)).fetchone() is not None)
    elif group == "receipts":
        result = _object(value, base | {"request_sha256", "response"})
        response = _lifecycle_response(result["response"], memory)
        _match(result["request_sha256"], _HASH)
        key = _digest(response["request_id"])
        _require(parts[3] == key + ".json")
        row = lifecycle.execute("SELECT payload_sha256,response_json FROM requests WHERE request_key=?", (key,)).fetchone()
        _require(row is not None and row["payload_sha256"] == result["request_sha256"] and row["response_json"] is not None,
                 "host_recovery_receipt_missing")
    else:
        result = _object(value, base | {"turn_key", "payload_sha256"})
        _match(result["turn_key"], _HASH)
        _match(result["payload_sha256"], _HASH)
    for field, table in (("session_handle", "sessions"), ("turn_handle", "turns")):
        if result.get(field) is not None:
            _require(lifecycle.execute("SELECT 1 FROM " + table + " WHERE handle=?", (result[field],)).fetchone() is not None,
                     "host_recovery_handle_missing")
    if lifecycle.execute("PRAGMA user_version").fetchone()[0] == 2:
        # A restored native session must retain its original source scope even
        # across lifecycle generations. The path hash never becomes authority.
        session_handle = result.get("session_handle")
        if group == "pending":
            request = result["request"]
            session_handle = request.get("session_handle")
            if session_handle is None:
                turn = lifecycle.execute("SELECT session_handle FROM turns WHERE handle=?", (request["turn_handle"],)).fetchone()
                session_handle = turn[0] if turn is not None else None
            if request["op"] == "turn.commit":
                plan = load_capture(lifecycle, request["turn_handle"])
                if plan is not None:
                    from memory_vault_client import _request_id
                    _require(plan["canonical_request_id"] == _request_id(request["request_id"], "lifecycle-capture-v2"))
        elif group == "receipts":
            session_handle = result["response"]["result"]["session_handle"]
        if session_handle is not None:
            scope = lifecycle.execute("SELECT scope_key FROM capture_sessions WHERE session_handle=?", (session_handle,)).fetchone()
            if scope is not None:
                _require(scope[0] == "hst_" + _digest(["native-visible-capture/v1", parts[0], parts[1]]),
                         "host_recovery_capture_scope_changed")
    result["vault_path_sha256"] = _digest(str(new_vault))
    return result


def activate_recovery(recovery: Path, output_config: Path, *, include: Sequence[str], authorize_local_resume: bool = False,
                      identity: Path | None = None, trust_store: Path | None = None, allow_unsigned_local: bool = False,
                      timeout: int = database_backup.DEFAULT_TIMEOUT) -> Mapping[str, Any]:
    """Rebuild selected formats in NEW local state and publish a NEW config last.

    This separate operator authorization enables local capture/retry. It never
    invokes a pending job, registers hooks, writes host approval, loads a private
    key, copies a sync configuration, or starts a worker. A later explicit local
    retry or separately approved host event can resume the preserved requests.
    """
    _require(authorize_local_resume is True, "local_resume_authorization_required")
    _require(type(allow_unsigned_local) is bool, "invalid_unsigned_acceptance")
    selected = _selection(include, local_only=True)
    deadline = database_backup._deadline(timeout)
    root, output = database_backup.absolute(recovery), database_backup.absolute(output_config)
    receipt, manifest, evidence = _recovery(root, deadline)
    _require(set(selected) <= set(manifest["components"]), "recovery_component_not_backed_up")
    trust = _external_trust(trust_store, (root,))
    signer = _external_trust(identity, (root,))
    _require(signer is None or trust is not None, "identity_requires_trust_store")
    _require(signer is None or signer != trust, "client_paths_must_be_separate")
    _require(not manifest["source"]["signed_writes_configured"] or signer is not None or allow_unsigned_local,
             "recovery_signing_identity_or_explicit_unsigned_required")
    from memory_vault_client import CONFIG_SCHEMA, ClientConfig
    proposed = ClientConfig(output, root / "memory.sqlite3", True, signer, trust, None)
    state = proposed.state_path
    for target in (output, state):
        _require(not target.exists() and not _overlaps(target, evidence) and not _overlaps(target, proposed.vault_path)
                 and all(not _overlaps(target, item) for item in (trust, signer) if item is not None),
                 "recovery_requires_new_config_and_state")
    _require(not _overlaps(output, state), "client_recovery_path_overlap")
    activation_path = output.parent / (output.stem + ".recovery-receipt.json")
    _require(not activation_path.exists() and activation_path != output, "recovery_output_exists")
    _new_directory(state)
    entries = [entry for entry in manifest["entries"] if entry["component"] in selected]
    by_component = {entry["component"]: entry for entry in entries if entry["kind"] == "sqlite"}
    summaries: dict[str, Any] = {}
    with database_backup.readonly_database(proposed.vault_path, deadline) as memory:
        _require(database_backup.database_summary(memory)["store_id"] == receipt["new_store_id"], "client_recovery_binding_changed")
        for component in ("lifecycle", "compat", "hooks"):
            if component in by_component:
                entry = by_component[component]
                path = _checked_entry(evidence, entry, deadline)
                summaries[component] = _rebuild_control(path, state / _DATABASE_NAMES[component], component,
                                                        manifest["source"], proposed.vault_path, receipt["new_store_id"], memory, deadline)
                _require(summaries[component] == manifest["control_summaries"].get(component), "client_control_summary_changed")
        with contextlib.ExitStack() as stack:
            lifecycle = None
            hook_capture = None
            hook_outbox_keys = []
            if "hosts" in selected and any(entry["component"] == "hosts" for entry in entries):
                _require("lifecycle" in by_component, "host_recovery_requires_lifecycle_database")
                lifecycle = stack.enter_context(database_backup.readonly_database(state / _DATABASE_NAMES["lifecycle"], deadline, immutable=True))
            if "hooks" in by_component:
                hook_capture = stack.enter_context(database_backup.readonly_database(state / HOOK_CAPTURE_FILENAME, deadline, immutable=True))
            for entry in entries:
                if entry["component"] not in {"hooks", "hosts"} or entry["kind"] == "sqlite":
                    continue
                path = _checked_entry(evidence, entry, deadline)
                value = _read_json(path, deadline)
                parts = PurePosixPath(entry["path"]).parts
                if entry["component"] == "hooks":
                    value = _hook_document(value, parts[2], memory, key=Path(parts[3]).stem, capture=hook_capture)
                    target = state / parts[2] / parts[3]
                    if parts[2] == "outbox":
                        hook_outbox_keys.append(Path(parts[3]).stem)
                else:
                    assert lifecycle is not None
                    value = _host_document(value, parts[2:], manifest["source"], proposed.vault_path, lifecycle, memory)
                    target = state.joinpath("hosts-v1", *parts[2:])
                _write_json(target, value, maximum=MAX_CONTROL_BYTES)
            if "hooks" in selected:
                _validate_hook_capture_files(hook_capture, state, memory, deadline, outbox_keys=hook_outbox_keys)
    config: dict[str, Any] = {"schema_version": CONFIG_SCHEMA, "vault_path": str(proposed.vault_path), "capture_visible_turns": True}
    if signer is not None:
        config["identity_path"] = str(signer)
    if trust is not None:
        config["trust_path"] = str(trust)
    activation = {"schema_version": ACTIVATION_SCHEMA, "created_at": utc_now(), "evidence_manifest_sha256": receipt["evidence_manifest_sha256"],
                  "new_store_id": receipt["new_store_id"], "components": selected, "local_capture_authorized": True,
                  "source_signed_writes_configured": manifest["source"]["signed_writes_configured"],
                  "new_signing_identity_selected": signer is not None, "unsigned_local_explicitly_allowed": allow_unsigned_local,
                  "historical_receipts_are_current_trust": False, "sync_authorized": False,
                  "host_permissions_granted": False, "pending_replayed": False, "network_accessed": False,
                  "configuration_sha256": sha256(canonical_bytes(config)), "rebuilt_control_summaries": summaries}
    _write_json(activation_path, activation)
    database_backup._check_time(deadline)
    _write_json(output, config)  # Publication is last; no half-restored active config.
    return {"state": "local_recovery_configuration_created", "config": str(output), "client_state": str(state),
            "activation_receipt": str(activation_path), "components": selected, "pending_replayed": False,
            "capture_enabled_by_explicit_operator": True, "sync_configured": False, "private_key_loaded": False,
            "host_permissions_granted": False, "network_accessed": False,
            "next_step": "explicit_local_retry_or_original_host_request", "historical_receipts_are_current_trust": False}


def import_recovery(recovery: Path, *, entry_id: str, trust_store: Path, authorize_memory_import: bool = False,
                    timeout: int = database_backup.DEFAULT_TIMEOUT) -> Mapping[str, Any]:
    """Reverify one complete archived signed capsule/group; local admission only.

    This is NOT transport replay: old cursors, sender publication decisions and
    chain-head receipts are never installed as new delivery state. Every record
    attestation and the envelope are checked against independently selected
    current trust. Missing fragments or dependencies abort before any admission.
    """
    _require(authorize_memory_import is True, "recovery_memory_import_authorization_required")
    _match(entry_id, _ITEM)
    deadline = database_backup._deadline(timeout)
    root = database_backup.absolute(recovery)
    receipt, manifest, evidence = _recovery(root, deadline)
    trust = _external_trust(trust_store, (root,))
    _require(trust is not None, "independent_recovery_trust_required")
    entries = {entry["path"]: entry for entry in manifest["entries"]}
    chosen = next((entry for entry in manifest["entries"] if entry["entry_id"] == entry_id), None)
    _require(chosen is not None and _capsule_candidate(chosen), "recovery_signed_capsule_required")
    path = _checked_entry(evidence, chosen, deadline)
    from memory_vault_transfer import DirectoryTransfer, MAX_CAPSULE_BYTES, _fragment_name
    endpoint = DirectoryTransfer(vault=root / "memory.sqlite3", exchange=evidence / "control" / "sync" / "exchange",
                                 state_directory=evidence / "control" / "sync" / "transfer", trust_store=trust)
    capsule = _read_json(path, deadline, maximum=MAX_CAPSULE_BYTES)
    payload, digest = endpoint._verify_capsule(capsule)
    chosen_parts = PurePosixPath(chosen["path"]).parts
    if chosen_parts[2:4] == ("transfer", "received-capsules"):
        _require(chosen_parts[-1] == digest + ".json", "recovery_capsule_name_mismatch")
    elif chosen_parts[2] == "exchange":
        _require(chosen_parts[3:5] == (payload["sender_key_id"], payload["source_store_id"])
                 and chosen_parts[-1] == f"{payload['after']:020d}-{payload['cursor']:020d}-{digest}.json",
                 "recovery_capsule_name_mismatch")
    records, proofs = list(payload["records"]), dict(payload["attestations"])
    if payload.get("group") is not None:
        group = payload["group"]
        whole, record_bytes = hashlib.sha256(), 0
        for fragment in group["fragments"]:
            database_backup._check_time(deadline)
            name = _fragment_name(fragment)
            candidates = [
                "control/sync/transfer/incoming-groups/" + group["group_id"] + "/" + name,
                "control/sync/transfer/outgoing-groups/" + group["group_id"] + "/" + name,
                "control/sync/exchange/" + payload["sender_key_id"] + "/" + payload["source_store_id"] + "/groups/" + group["group_id"] + "/" + name,
            ]
            selected = next((entries[candidate] for candidate in candidates if candidate in entries), None)
            _require(selected is not None, "recovery_group_incomplete")
            fragment_path = _checked_entry(evidence, selected, deadline)
            descriptor = protected_storage.open_file(fragment_path, os.O_RDONLY, private=True)
            with os.fdopen(descriptor, "rb") as stream:
                data = stream.read(fragment["bytes"] + 1)
            whole.update(data)
            for record, proof in endpoint._fragment_records(fragment, data, verify_signatures=True):
                _require(record["memory_id"] not in proofs, "duplicate_bundle_record")
                records.append(record)
                proofs[record["memory_id"]] = proof
                record_bytes += len(canonical_bytes(record))
                _require(len(records) <= group["record_count"] and record_bytes <= group["record_bytes"], "group_content_mismatch")
        _require(len(records) == group["record_count"] and record_bytes == group["record_bytes"]
                 and whole.hexdigest() == group["records_sha256"], "group_content_mismatch")
    # Re-check current trust after a potentially long fragment verification.
    endpoint.trust.require_trusted(payload["sender_key_id"])
    for proof in proofs.values():
        database_backup._check_time(deadline)
        endpoint.trust.require_trusted(proof["key_id"])
    database_backup._check_time(deadline)
    identifier = sha256(canonical_bytes(["recovery-memory-import/v1", receipt["evidence_manifest_sha256"], entry_id]))
    from memory_vault_dependency import ingest_verified
    result = ingest_verified(endpoint.vault, endpoint.trust, records, proofs,
                             transfer_id="xfer_" + identifier, payload_sha256=digest,
                             previous_payload_sha256=None, index=None)
    return {"state": "archived_signed_memory_imported", "entry_id": entry_id, "batch_sha256": digest,
            "memory": result, "current_signatures_verified": True, "old_cursors_restored": False,
            "old_publication_permissions_restored": False, "delivery_stream_identity_changed": False,
            "network_accessed": False, "worker_started": False, "private_key_loaded": False,
            "signature_does_not_authorize_execution": True}
