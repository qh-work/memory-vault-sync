#!/usr/bin/env python3
"""Explicit, bounded SQLite memory snapshots and restore-to-new-copy recovery.

This module never snapshots credentials, client queues, host configuration or
sync state. A checksum is not a publisher signature. Restored signed evidence
must be checked against independently selected current trust, not backup policy.
"""

from __future__ import annotations

from collections import Counter
import contextlib
import hashlib
import os
from pathlib import Path
import re
import sqlite3
import stat
import tempfile
import time
from typing import Any, Iterator, Mapping

from memory_vault import (
    ADMISSION_STATES, AUTHORITY, DATABASE_READER, DATABASE_SCHEMA,
    DATABASE_WRITER, MAX_BUNDLE_LINE_BYTES, MemoryError, RESULT_SCHEMA, Vault,
    canonical_bytes, normalize_text, strict_json_loads, utc_now,
    validate_record,
)


BACKUP_SCHEMA = "universal-memory-sqlite-backup/v1"
SNAPSHOT_NAME = "memory.sqlite3"
MANIFEST_NAME = "manifest.json"
MAX_DATABASE_BYTES = 2 * 1024 * 1024 * 1024
MAX_MANIFEST_BYTES = 32 * 1024
MAX_RECORDS = 1_000_000
MAX_RECEIPTS = 2_000_000
DEFAULT_TIMEOUT = 60
MAX_TIMEOUT = 300
_STORE = re.compile(r"store_[0-9a-f]{32}")
_HASH = re.compile(r"[0-9a-f]{64}")
_REQUEST = re.compile(r"req_[A-Za-z0-9_-]{8,96}")
COMPONENTS = (
    "canonical_records", "relations", "retrieval_index", "record_attestations",
    "admission_history", "write_idempotency_receipts", "delivery_metadata",
)
EXCLUDED = (
    "private_keys", "trust_registry", "client_configuration", "host_permissions",
    "hook_prompts_and_outbox", "hook_conflicts_and_receipts", "lifecycle_state",
    "sync_configuration_and_cursors", "pending_transfer_capsules", "artifacts",
)

# Exact supported SQLite schema, not a loader for arbitrary SQLite programs.
# Unknown tables, views or triggers fail before a restored copy is writable.
_TABLE_SQL = {
    "metadata": "CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL)",
    "memories": "CREATE TABLE memories(ingest_seq INTEGER PRIMARY KEY AUTOINCREMENT,memory_id TEXT NOT NULL UNIQUE,record_sha256 TEXT NOT NULL UNIQUE,kind TEXT NOT NULL,text TEXT NOT NULL,normalized_text TEXT NOT NULL,created_at TEXT NOT NULL,record_json TEXT NOT NULL)",
    "terms": "CREATE TABLE terms(token TEXT NOT NULL,memory_id TEXT NOT NULL REFERENCES memories(memory_id),frequency INTEGER NOT NULL,PRIMARY KEY(token,memory_id))",
    "relations": "CREATE TABLE relations(source_id TEXT NOT NULL REFERENCES memories(memory_id),relation TEXT NOT NULL,target_id TEXT NOT NULL REFERENCES memories(memory_id) DEFERRABLE INITIALLY DEFERRED,PRIMARY KEY(source_id,relation,target_id))",
    "receipts": "CREATE TABLE receipts(request_id TEXT PRIMARY KEY,request_sha256 TEXT NOT NULL,response_json TEXT NOT NULL,created_at TEXT NOT NULL)",
    "record_admissions": "CREATE TABLE record_admissions(memory_id TEXT PRIMARY KEY REFERENCES memories(memory_id),state TEXT NOT NULL CHECK(state IN ('local_unsigned','accepted_unsigned','verified','quarantined')),signer_key_id TEXT,attestation_json TEXT)",
    "delivery_log": "CREATE TABLE delivery_log(sequence INTEGER PRIMARY KEY AUTOINCREMENT,memory_id TEXT NOT NULL REFERENCES memories(memory_id))",
    "transfer_receipts": "CREATE TABLE transfer_receipts(transfer_id TEXT PRIMARY KEY,payload_sha256 TEXT NOT NULL,result_json TEXT NOT NULL,created_at TEXT NOT NULL)",
    "sqlite_sequence": "CREATE TABLE sqlite_sequence(name,seq)",
}
_INDEX_SQL = {
    "terms_memory": "CREATE INDEX terms_memory ON terms(memory_id)",
    "relations_target": "CREATE INDEX relations_target ON relations(target_id,relation)",
    "delivery_memory": "CREATE INDEX delivery_memory ON delivery_log(memory_id)",
}
# Additive, disposable v0.25 indexes. A complete older v2 database remains a
# supported input; a partially created or differently defined extension does
# not become permission to execute unknown SQLite programs during restore.
_DERIVED_TABLE_SQL = {
    "memory_entities": "CREATE TABLE memory_entities(entity TEXT NOT NULL,memory_id TEXT NOT NULL REFERENCES memories(memory_id),PRIMARY KEY(entity,memory_id))",
    "retrieval_index": "CREATE TABLE retrieval_index(memory_id TEXT PRIMARY KEY REFERENCES memories(memory_id),profile TEXT NOT NULL,token_count INTEGER NOT NULL CHECK(token_count>=0),timeline_key TEXT NOT NULL)",
}
_DERIVED_INDEX_SQL = {
    "memory_entities_memory": "CREATE INDEX memory_entities_memory ON memory_entities(memory_id)",
    "retrieval_index_timeline": "CREATE INDEX retrieval_index_timeline ON retrieval_index(timeline_key,memory_id)",
}
_TRIGGER_SQL = {
    "memories_no_update": "CREATE TRIGGER memories_no_update BEFORE UPDATE ON memories BEGIN SELECT RAISE(ABORT,'append-only memories'); END",
    "memories_no_delete": "CREATE TRIGGER memories_no_delete BEFORE DELETE ON memories BEGIN SELECT RAISE(ABORT,'append-only memories'); END",
}


def absolute(path: Path) -> Path:
    selected = Path(path).expanduser()
    if not selected.is_absolute() or ".." in selected.parts:
        raise MemoryError("backup_path_must_be_absolute")
    if any(part.is_symlink() for part in (selected, *selected.parents)):
        raise MemoryError("unsafe_backup_path")
    if os.name == "nt":
        from memory_vault_storage import validate_path
        return validate_path(selected)
    return selected


def regular(path: Path, *, private: bool = True) -> os.stat_result:
    absolute(path)
    if os.name == "nt":
        from memory_vault_storage import open_file
        descriptor = open_file(path, os.O_RDONLY, private=private)
        try:
            return os.fstat(descriptor)
        finally:
            os.close(descriptor)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise MemoryError("unsafe_backup_file")
    if private and os.name == "posix" and (info.st_uid != os.getuid() or info.st_mode & 0o077):
        raise MemoryError("backup_file_not_private")
    return info


def _fingerprint(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _private_parent(path: Path) -> None:
    if os.name == "nt":
        from memory_vault_storage import private_directory
        private_directory(path)
        return
    if os.name != "posix":
        raise MemoryError("protected_backup_storage_unavailable")
    absolute(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    for ancestor in (path, *path.parents):
        info = ancestor.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, os.getuid()}:
            raise MemoryError("unsafe_backup_parent")
        if info.st_mode & 0o022 and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX):
            raise MemoryError("unsafe_backup_parent")


def _deadline(timeout: int) -> float:
    if type(timeout) is not int or not 1 <= timeout <= MAX_TIMEOUT:
        raise MemoryError("invalid_backup_timeout")
    return time.monotonic() + timeout


def _check_time(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise MemoryError("backup_work_limit", retryable=True)


def _harden(connection: sqlite3.Connection, deadline: float, *, readonly: bool) -> None:
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA trusted_schema=OFF")
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA busy_timeout=500")
    if readonly:
        connection.execute("PRAGMA query_only=ON")
    if hasattr(connection, "setlimit"):
        connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 4 * 1024 * 1024)
        connection.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, 64 * 1024)
    connection.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)


@contextlib.contextmanager
def readonly_database(path: Path, deadline: float, *, immutable: bool = False) -> Iterator[sqlite3.Connection]:
    selected = absolute(path)
    regular(selected)
    if not immutable:
        for ending in ("-wal", "-shm", "-journal"):
            sidecar = Path(str(selected) + ending)
            absolute(sidecar)
            if sidecar.exists():
                regular(sidecar)
    suffix = "?mode=ro&immutable=1" if immutable else "?mode=ro"
    with contextlib.closing(sqlite3.connect(selected.as_uri() + suffix, uri=True, timeout=0.5)) as connection:
        _harden(connection, deadline, readonly=True)
        connection.execute("BEGIN")
        yield connection


def _sql(value: str) -> str:
    return re.sub(r"\s+", "", value).casefold().replace("ifnotexists", "").rstrip(";")


def database_summary(connection: sqlite3.Connection) -> dict[str, Any]:
    """Read schema and aggregate counts only; never select a memory's text."""
    expected = {**{name: ("table", sql) for name, sql in _TABLE_SQL.items()},
                **{name: ("index", sql) for name, sql in _INDEX_SQL.items()},
                **{name: ("trigger", sql) for name, sql in _TRIGGER_SQL.items()}}
    derived = {**{name: ("table", sql) for name, sql in _DERIVED_TABLE_SQL.items()},
               **{name: ("index", sql) for name, sql in _DERIVED_INDEX_SQL.items()}}
    allowed = {**expected, **derived}
    seen: set[str] = set()
    for row in connection.execute("SELECT type,name,tbl_name,sql FROM sqlite_master"):
        name = str(row["name"])
        if row["type"] == "index" and row["sql"] is None and name.startswith("sqlite_autoindex_") and row["tbl_name"] in (_TABLE_SQL | _DERIVED_TABLE_SQL):
            continue
        if name not in allowed or row["type"] != allowed[name][0] or not isinstance(row["sql"], str) or _sql(row["sql"]) != _sql(allowed[name][1]):
            raise MemoryError("unsupported_backup_database_schema")
        seen.add(name)
    if seen not in (set(expected), set(allowed)):
        raise MemoryError("unsupported_backup_database_schema")
    metadata = dict(connection.execute("SELECT key,value FROM metadata WHERE key IN ('schema','min_reader','min_writer','store_id')"))
    if (metadata.get("schema") != DATABASE_SCHEMA or metadata.get("min_reader") != str(DATABASE_READER)
            or metadata.get("min_writer") != str(DATABASE_WRITER)
            or not isinstance(metadata.get("store_id"), str) or not _STORE.fullmatch(metadata["store_id"])):
        raise MemoryError("unsupported_backup_database_schema")
    pages = int(connection.execute("PRAGMA page_count").fetchone()[0])
    page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
    if pages <= 0 or page_size not in {512, 1024, 2048, 4096, 8192, 16384, 32768, 65536} or pages * page_size > MAX_DATABASE_BYTES:
        raise MemoryError("backup_database_too_large")
    counts = {name: int(connection.execute("SELECT COUNT(*) FROM " + name).fetchone()[0])
              for name in ("memories", "terms", "relations", "receipts", "record_admissions", "delivery_log", "transfer_receipts")}
    if counts["memories"] > MAX_RECORDS or counts["receipts"] > MAX_RECEIPTS:
        raise MemoryError("backup_row_limit")
    if counts["memories"] != counts["record_admissions"]:
        raise MemoryError("backup_admission_incomplete")
    admissions = {str(row[0]): int(row[1]) for row in connection.execute("SELECT state,COUNT(*) FROM record_admissions GROUP BY state")}
    if set(admissions) - ADMISSION_STATES:
        raise MemoryError("invalid_backup_admission")
    return {"database_schema": DATABASE_SCHEMA, "store_id": metadata["store_id"],
            "logical_bytes": pages * page_size, "page_size": page_size,
            "counts": counts, "admissions": admissions,
            "extended_retrieval_index_present": set(derived).issubset(seen),
            "attestations": int(connection.execute("SELECT COUNT(*) FROM record_admissions WHERE attestation_json IS NOT NULL").fetchone()[0])}


def _integrity(connection: sqlite3.Connection) -> None:
    result = connection.execute("PRAGMA quick_check(1)").fetchone()
    if result is None or result[0] != "ok" or connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
        raise MemoryError("backup_database_inconsistent")


def _copy_database(source: sqlite3.Connection, destination: sqlite3.Connection, deadline: float) -> None:
    def progress(status: int, remaining: int, total: int) -> None:
        _check_time(deadline)
        if status not in {sqlite3.SQLITE_OK, sqlite3.SQLITE_DONE, sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}:
            raise MemoryError("backup_copy_failed")
    _check_time(deadline)
    source.backup(destination, pages=128, progress=progress, sleep=0.01)
    _harden(destination, deadline, readonly=False)
    destination.execute("PRAGMA journal_mode=DELETE")
    destination.execute("PRAGMA synchronous=FULL")


def _file_hash(path: Path, deadline: float) -> tuple[str, int]:
    before = regular(path)
    if before.st_size > MAX_DATABASE_BYTES:
        raise MemoryError("backup_database_too_large")
    digest = hashlib.sha256()
    total = 0
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(descriptor, "rb") as stream:
        if _fingerprint(os.fstat(stream.fileno())) != _fingerprint(before):
            raise MemoryError("backup_source_changed")
        while True:
            _check_time(deadline)
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_DATABASE_BYTES:
                raise MemoryError("backup_database_too_large")
            digest.update(chunk)
        if _fingerprint(os.fstat(stream.fileno())) != _fingerprint(before):
            raise MemoryError("backup_source_changed")
    if _fingerprint(regular(path)) != _fingerprint(before) or total != before.st_size:
        raise MemoryError("backup_source_changed")
    return digest.hexdigest(), total


def _sync_directory(path: Path) -> None:
    if os.name == "nt":
        # Native publication uses MoveFileEx WRITE_THROUGH below; opening a
        # directory with the POSIX fsync recipe is not supported on Windows.
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _publish_file(temporary: Path, destination: Path) -> None:
    absolute(destination)
    if os.name == "nt":
        from memory_vault_storage import publish_file
        publish_file(temporary, destination, replace=False)
        return
    try:
        os.link(temporary, destination)
    except FileExistsError:
        raise MemoryError("backup_output_exists") from None
    temporary.unlink()
    _sync_directory(destination.parent)


def _new_temporary(parent: Path) -> Path:
    descriptor, name = tempfile.mkstemp(prefix=".memory-recovery-", suffix=".sqlite3", dir=parent)
    if os.name == "nt":
        from memory_vault_storage import check_fd
        check_fd(descriptor, private=True)
    else:
        os.fchmod(descriptor, 0o600)
    os.close(descriptor)
    return Path(name)


def backup_database(vault_path: Path, output: Path, *, timeout: int = DEFAULT_TIMEOUT) -> Mapping[str, Any]:
    """Create a new snapshot directory; the manifest is its commit marker."""
    deadline = _deadline(timeout)
    source, destination = absolute(vault_path), absolute(output)
    regular(source)
    if destination.exists() or destination == source or destination in source.parents:
        raise MemoryError("backup_output_exists")
    _private_parent(destination.parent)
    temporary: Path | None = None
    with readonly_database(source, deadline) as connection:
        source_summary = database_summary(connection)
        _integrity(connection)
        try:
            destination.mkdir(mode=0o700)
        except FileExistsError:
            raise MemoryError("backup_output_exists") from None
        temporary = _new_temporary(destination)
        try:
            with contextlib.closing(sqlite3.connect(temporary)) as copied:
                _copy_database(connection, copied, deadline)
                summary = database_summary(copied)
                _integrity(copied)
            if summary != source_summary:
                raise MemoryError("backup_snapshot_mismatch")
            digest, size = _file_hash(temporary, deadline)
            _publish_file(temporary, destination / SNAPSHOT_NAME)
            temporary = None
            manifest = {
                "schema_version": BACKUP_SCHEMA, "created_at": utc_now(),
                "source_database_schema": DATABASE_SCHEMA, "source_store_id": summary["store_id"],
                "database": {"name": SNAPSHOT_NAME, "bytes": size, "sha256": digest},
                "counts": summary["counts"], "attestations": summary["attestations"],
                "components": list(COMPONENTS), "excluded": list(EXCLUDED),
                "checksum_authenticates_sender": False, "client_state_consistently_snapshotted": False,
            }
            encoded = canonical_bytes(manifest) + b"\n"
            descriptor, name = tempfile.mkstemp(prefix=".manifest-", dir=destination)
            staged_manifest = Path(name)
            try:
                with os.fdopen(descriptor, "wb") as stream:
                    if os.name == "nt":
                        from memory_vault_storage import check_fd
                        check_fd(stream.fileno(), private=True)
                    else:
                        os.fchmod(stream.fileno(), 0o600)
                    stream.write(encoded)
                    stream.flush()
                    os.fsync(stream.fileno())
                _publish_file(staged_manifest, destination / MANIFEST_NAME)
            finally:
                staged_manifest.unlink(missing_ok=True)
            return {"state": "memory_snapshot_created", "backup": str(destination),
                    "database_bytes": size, "database_sha256": digest,
                    "records": summary["counts"]["memories"], "record_attestations": summary["attestations"],
                    "write_receipts": summary["counts"]["receipts"], "excluded": list(EXCLUDED),
                    "network_accessed": False, "keys_copied": False, "client_state_backup": False}
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)


def _manifest(directory: Path) -> tuple[dict[str, Any], Path]:
    root = absolute(directory)
    if not root.is_dir():
        raise MemoryError("backup_directory_missing")
    path = root / MANIFEST_NAME
    info = regular(path)
    if info.st_size > MAX_MANIFEST_BYTES:
        raise MemoryError("invalid_backup_manifest")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as stream:
        encoded = stream.read(MAX_MANIFEST_BYTES + 1)
    if len(encoded) > MAX_MANIFEST_BYTES:
        raise MemoryError("invalid_backup_manifest")
    value = strict_json_loads(encoded)
    fields = {"schema_version", "created_at", "source_database_schema", "source_store_id", "database",
              "counts", "attestations", "components", "excluded", "checksum_authenticates_sender", "client_state_consistently_snapshotted"}
    if not isinstance(value, dict) or set(value) != fields:
        raise MemoryError("invalid_backup_manifest")
    database = value.get("database")
    if (value["schema_version"] != BACKUP_SCHEMA or value["source_database_schema"] != DATABASE_SCHEMA
            or not isinstance(value["source_store_id"], str) or not _STORE.fullmatch(value["source_store_id"])
            or value["components"] != list(COMPONENTS) or value["excluded"] != list(EXCLUDED)
            or value["checksum_authenticates_sender"] is not False or value["client_state_consistently_snapshotted"] is not False
            or not isinstance(database, dict) or set(database) != {"name", "bytes", "sha256"}
            or database["name"] != SNAPSHOT_NAME or type(database["bytes"]) is not int
            or not 1 <= database["bytes"] <= MAX_DATABASE_BYTES
            or not isinstance(database["sha256"], str) or not _HASH.fullmatch(database["sha256"])):
        raise MemoryError("invalid_backup_manifest")
    snapshot = root / SNAPSHOT_NAME
    if any(os.path.lexists(Path(str(snapshot) + suffix)) for suffix in ("-wal", "-shm", "-journal")):
        raise MemoryError("snapshot_has_external_journal")
    regular(snapshot)
    return value, snapshot


def _validate_write_receipts(connection: sqlite3.Connection, deadline: float) -> None:
    if connection.execute("SELECT 1 FROM receipts WHERE length(CAST(response_json AS BLOB))>65536 LIMIT 1").fetchone():
        raise MemoryError("invalid_backup_write_receipt")
    for row in connection.execute("SELECT request_id,request_sha256,response_json FROM receipts"):
        _check_time(deadline)
        value = strict_json_loads(row["response_json"])
        if (not isinstance(row["request_id"], str) or not _REQUEST.fullmatch(row["request_id"])
                or not isinstance(row["request_sha256"], str) or not _HASH.fullmatch(row["request_sha256"])
                or not isinstance(value, dict) or set(value) != {"schema_version", "ok", "authority", "result", "request_id"}
                or value["schema_version"] != RESULT_SCHEMA or value["ok"] is not True
                or value["authority"] != dict(AUTHORITY) or value["request_id"] != row["request_id"]):
            raise MemoryError("invalid_backup_write_receipt")
        result = value["result"]
        if isinstance(result, dict) and result.get("state") == "requeued":
            if (set(result) != {"state", "records", "network_accessed"}
                    or type(result["records"]) is not int or not 1 <= result["records"] <= 256
                    or result["network_accessed"] is not False):
                raise MemoryError("invalid_backup_write_receipt")
            continue
        if isinstance(result, dict) and result.get("state") == "index_page_rebuilt":
            fields = {"state", "records", "through", "next_after", "complete", "range_complete", "index", "canonical_records_changed", "network_accessed"}
            index = result.get("index")
            if (set(result) != fields or type(result["records"]) is not int or not 0 <= result["records"] <= 256
                    or type(result["through"]) is not int or not 0 <= result["through"] <= 2**63 - 1
                    or (result["next_after"] is not None and (type(result["next_after"]) is not int or not 0 <= result["next_after"] <= result["through"]))
                    or any(type(result[key]) is not bool for key in ("complete", "range_complete"))
                    or result["canonical_records_changed"] is not False or result["network_accessed"] is not False
                    or not isinstance(index, dict) or set(index) != {"profile", "complete", "first_unindexed_sequence", "repair_operation", "canonical_records_changed"}
                    or not isinstance(index["profile"], str) or len(index["profile"]) > 128
                    or type(index["complete"]) is not bool or index["repair_operation"] != "memory.reindex"
                    or index["canonical_records_changed"] is not False
                    or (index["first_unindexed_sequence"] is not None and (type(index["first_unindexed_sequence"]) is not int or not 1 <= index["first_unindexed_sequence"] <= result["through"]))):
                raise MemoryError("invalid_backup_write_receipt")
            # Historical derived-index receipts are retained for exact retry,
            # not used as evidence that this restored index is still complete.
            continue
        if (not isinstance(result, dict) or set(result) - {"state", "memory_id", "kind", "network_accessed", "verification"}
                or result.get("state") not in {"stored", "duplicate"} or result.get("network_accessed") is not False
                or not isinstance(result.get("memory_id"), str)):
            raise MemoryError("invalid_backup_write_receipt")
        memory = connection.execute("SELECT kind FROM memories WHERE memory_id=?", (result["memory_id"],)).fetchone()
        if memory is None or result.get("kind") != memory["kind"]:
            raise MemoryError("invalid_backup_write_receipt")


def _rebuild_restored_copy(connection: sqlite3.Connection, deadline: float, *, trust: Any, accept_unsigned: bool) -> dict[str, Any]:
    """Rebuild derived data; preserved signatures never import backup authority."""
    if connection.execute("SELECT 1 FROM memories WHERE length(CAST(record_json AS BLOB))>? LIMIT 1", (MAX_BUNDLE_LINE_BYTES,)).fetchone():
        raise MemoryError("backup_record_too_large")
    if connection.execute("SELECT 1 FROM record_admissions WHERE length(CAST(attestation_json AS BLOB))>2048 LIMIT 1").fetchone():
        raise MemoryError("backup_attestation_too_large")
    _validate_write_receipts(connection, deadline)
    connection.execute("BEGIN IMMEDIATE")
    Vault.ensure_retrieval_tables(connection)
    connection.execute("DELETE FROM terms")
    connection.execute("DELETE FROM memory_entities")
    connection.execute("DELETE FROM retrieval_index")
    connection.execute("DELETE FROM relations")
    connection.execute("DELETE FROM transfer_receipts")
    connection.execute("DELETE FROM delivery_log")
    connection.execute("DELETE FROM sqlite_sequence WHERE name='delivery_log'")
    counts = {"verified": 0, "accepted_unsigned": 0, "quarantined": 0}
    rejected: Counter[str] = Counter()
    for row in connection.execute("SELECT m.*,a.state AS admission_state,a.signer_key_id,a.attestation_json FROM memories m JOIN record_admissions a USING(memory_id) ORDER BY ingest_seq"):
        _check_time(deadline)
        record = validate_record(strict_json_loads(row["record_json"]))
        if (canonical_bytes(record).decode("utf-8") != row["record_json"]
                or any(record[name] != row[name] for name in ("memory_id", "record_sha256", "kind", "text", "created_at"))
                or normalize_text(record["text"]) != row["normalized_text"]):
            raise MemoryError("invalid_backup_record")
        Vault.rebuild_record_index(connection, record)
        connection.executemany("INSERT INTO relations(source_id,relation,target_id) VALUES(?,?,?)", ((record["memory_id"], relation["type"], relation["target"]) for relation in record["relations"]))
        admission = "quarantined"
        if row["attestation_json"] is None:
            if accept_unsigned and row["admission_state"] in {"local_unsigned", "accepted_unsigned"}:
                admission = "accepted_unsigned"
        elif trust is not None:
            from memory_vault_trust import TrustError
            try:
                if not isinstance(row["attestation_json"], str) or len(row["attestation_json"].encode("utf-8")) > 2048:
                    raise MemoryError("invalid_attestation")
                proof = strict_json_loads(row["attestation_json"])
                signer = trust.verify_record(record, proof)
                if signer != row["signer_key_id"]:
                    raise MemoryError("attestation_signer_mismatch")
                admission = "verified"
            except (MemoryError, TrustError) as exc:
                if exc.code in {"cryptography_unavailable", "ed25519_unavailable", "protected_storage_unavailable", "storage_unavailable"}:
                    raise MemoryError("restore_trust_unavailable") from None
                rejected[exc.code] += 1
        connection.execute("UPDATE record_admissions SET state=? WHERE memory_id=?", (admission, record["memory_id"]))
        connection.execute("INSERT INTO delivery_log(memory_id) VALUES(?)", (record["memory_id"],))
        counts[admission] += 1
    new_store = "store_" + os.urandom(16).hex()
    connection.execute("UPDATE metadata SET value=? WHERE key='store_id'", (new_store,))
    connection.commit()
    _integrity(connection)
    return {"new_store_id": new_store, "admissions": counts, "signature_rejections": dict(rejected),
            "current_trust_checked": trust is not None, "derived_index_rebuilt": True,
            "old_transfer_receipts_discarded": True, "delivery_stream_reset": True}


def restore_database(backup: Path, output: Path, *, trust_store: Path | None = None,
                     accept_unsigned: bool = False, timeout: int = DEFAULT_TIMEOUT) -> Mapping[str, Any]:
    """Restore only to a NEW local file; never alter the backup or live Vault."""
    deadline = _deadline(timeout)
    if type(accept_unsigned) is not bool:
        raise MemoryError("invalid_unsigned_acceptance")
    root, destination = absolute(backup), absolute(output)
    if destination.exists() or destination == root or root in destination.parents:
        raise MemoryError("restore_requires_new_external_path")
    if any(os.path.lexists(Path(str(destination) + suffix)) for suffix in ("-journal", "-wal", "-shm")):
        raise MemoryError("restore_target_has_journal")
    manifest, snapshot = _manifest(root)
    original_snapshot = _fingerprint(regular(snapshot))
    digest, size = _file_hash(snapshot, deadline)
    if digest != manifest["database"]["sha256"] or size != manifest["database"]["bytes"]:
        raise MemoryError("backup_checksum_mismatch")
    trust = None
    if trust_store is not None:
        from memory_vault_trust import TrustError, TrustStore
        try:
            trust = TrustStore(absolute(trust_store))
            if not trust.path.exists():
                raise MemoryError("restore_trust_store_missing")
            trust.status()
        except TrustError as exc:
            raise MemoryError(exc.code) from None
    _private_parent(destination.parent)
    temporary = _new_temporary(destination.parent)
    try:
        with readonly_database(snapshot, deadline, immutable=True) as source:
            summary = database_summary(source)
            _integrity(source)
            if (summary["store_id"] != manifest["source_store_id"] or summary["counts"] != manifest["counts"]
                    or summary["attestations"] != manifest["attestations"]):
                raise MemoryError("backup_manifest_mismatch")
            with contextlib.closing(sqlite3.connect(temporary)) as copied:
                _copy_database(source, copied, deadline)
                restored = _rebuild_restored_copy(copied, deadline, trust=trust, accept_unsigned=accept_unsigned)
        if _fingerprint(regular(snapshot)) != original_snapshot:
            raise MemoryError("backup_source_changed")
        _check_time(deadline)
        restored_hash, restored_size = _file_hash(temporary, deadline)
        _publish_file(temporary, destination)
        return {"state": "memory_restored_to_new_copy", "vault": str(destination),
                "records": summary["counts"]["memories"], "write_receipts": summary["counts"]["receipts"],
                "record_attestations_preserved": summary["attestations"],
                "database_sha256": restored_hash, "database_bytes": restored_size, **restored,
                "historical_receipts_are_current_trust": False, "client_configuration_changed": False,
                "reuse_old_sync_state": False, "keys_restored": False, "network_accessed": False,
                "excluded": list(EXCLUDED)}
    finally:
        temporary.unlink(missing_ok=True)
