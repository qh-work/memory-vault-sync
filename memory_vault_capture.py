#!/usr/bin/env python3
"""Frozen local capture plans, not memory owners or an execution authority.

The shared helpers operate inside the caller's existing SQLite transaction.
They do not open a Vault, load a key, select a host, or commit that transaction.
Lifecycle, compatibility and visible-hook journals keep their own acceptance
boundary; only the resulting canonical records travel between agents.
"""

from __future__ import annotations

import contextlib
import os
from pathlib import Path
import re
import sqlite3
from typing import Any, Callable, Iterator, Mapping, Sequence

from memory_vault import (
    MAX_BUNDLE_LINE_BYTES, MemoryError, canonical_bytes, sha256, strict_json_loads,
    utc_now, validate_record, _timestamp,
)


MAX_CAPTURE_JOBS = 100_000
MAX_CAPTURE_PENDING_JOBS = 256
MAX_CAPTURE_PENDING_BYTES = 32 * 1024 * 1024
MAX_CAPTURE_RECORDS = 64
HOOK_CAPTURE_SCHEMA = "memory-vault-hook-capture-state/v1"
HOOK_CAPTURE_FILENAME = "hook-capture-v1.sqlite3"

CAPTURE_SQL = {
    "capture_heads": "CREATE TABLE capture_heads(scope_key TEXT PRIMARY KEY,accepted_sequence INTEGER NOT NULL CHECK(accepted_sequence>=0),last_job_key TEXT REFERENCES capture_jobs(job_key) DEFERRABLE INITIALLY DEFERRED)",
    "capture_jobs": "CREATE TABLE capture_jobs(job_key TEXT PRIMARY KEY,scope_key TEXT NOT NULL,accepted_sequence INTEGER NOT NULL CHECK(accepted_sequence>0),builder_profile TEXT NOT NULL,input_sha256 TEXT NOT NULL,created_at TEXT NOT NULL,predecessor_job_key TEXT REFERENCES capture_jobs(job_key) DEFERRABLE INITIALLY DEFERRED,previous_continuity_id TEXT,previous_record_sha256 TEXT,episode_id TEXT NOT NULL,continuity_id TEXT NOT NULL,projection_sha256 TEXT NOT NULL,canonical_request_id TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('pending','saved')),record_count INTEGER NOT NULL CHECK(record_count BETWEEN 1 AND 64),UNIQUE(scope_key,accepted_sequence))",
    "capture_records": "CREATE TABLE capture_records(job_key TEXT NOT NULL REFERENCES capture_jobs(job_key),ordinal INTEGER NOT NULL CHECK(ordinal>=0),memory_id TEXT NOT NULL,record_sha256 TEXT NOT NULL,record_json TEXT,PRIMARY KEY(job_key,ordinal),UNIQUE(job_key,memory_id))",
    "capture_jobs_pending": "CREATE INDEX capture_jobs_pending ON capture_jobs(state,scope_key,accepted_sequence)",
}
CAPTURE_COLUMNS = {
    "capture_heads": ("scope_key", "accepted_sequence", "last_job_key"),
    "capture_jobs": ("job_key", "scope_key", "accepted_sequence", "builder_profile", "input_sha256", "created_at",
                     "predecessor_job_key", "previous_continuity_id", "previous_record_sha256", "episode_id", "continuity_id",
                     "projection_sha256", "canonical_request_id", "state", "record_count"),
    "capture_records": ("job_key", "ordinal", "memory_id", "record_sha256", "record_json"),
}
_KEY = re.compile(r"[A-Za-z0-9._:@+\-]{1,256}")
_PROFILE = re.compile(r"[A-Za-z0-9._:/@+\-]{1,128}")
_ID = re.compile(r"mem_[0-9a-f]{40}")
_HASH = re.compile(r"[0-9a-f]{64}")


def _match(value: Any, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise MemoryError("invalid_capture_state")
    return value


def _integer(value: Any, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise MemoryError("invalid_capture_state")
    return value


def initialize_capture(connection: sqlite3.Connection) -> None:
    """Create the fixed tables only within an authorized caller transaction."""
    if not connection.in_transaction:
        raise MemoryError("capture_transaction_required")
    for statement in CAPTURE_SQL.values():
        connection.execute(statement)


def capture_digest(plan: Mapping[str, Any], records: Sequence[Mapping[str, Any]]) -> str:
    """A frozen projection digest independent of local scope/path ownership."""
    return sha256(canonical_bytes({
        "builder_profile": plan["builder_profile"], "created_at": plan["created_at"],
        "previous_continuity_id": plan["previous_continuity_id"],
        "previous_record_sha256": plan["previous_record_sha256"],
        "episode_id": plan["episode_id"], "continuity_id": plan["continuity_id"],
        "records": list(records),
    }))


def validate_capture_header(value: Mapping[str, Any]) -> dict[str, Any]:
    row = dict(value)
    if set(row) != set(CAPTURE_COLUMNS["capture_jobs"]):
        raise MemoryError("invalid_capture_state")
    for key in ("job_key", "scope_key", "canonical_request_id"):
        _match(row[key], _KEY)
    _match(row["builder_profile"], _PROFILE)
    for key in ("input_sha256", "projection_sha256"):
        _match(row[key], _HASH)
    for key in ("episode_id", "continuity_id"):
        _match(row[key], _ID)
    if row["episode_id"] == row["continuity_id"]:
        raise MemoryError("invalid_capture_state")
    _timestamp(row["created_at"])
    _integer(row["accepted_sequence"], 1, 2**63 - 1)
    _integer(row["record_count"], 2, MAX_CAPTURE_RECORDS)
    if row["state"] not in {"pending", "saved"}:
        raise MemoryError("invalid_capture_state")
    previous = (row["predecessor_job_key"], row["previous_continuity_id"], row["previous_record_sha256"])
    if any(item is None for item in previous):
        if previous != (None, None, None):
            raise MemoryError("invalid_capture_state")
    else:
        _match(previous[0], _KEY)
        _match(previous[1], _ID)
        _match(previous[2], _HASH)
        if previous[0] == row["job_key"] or previous[1] == row["continuity_id"]:
            raise MemoryError("invalid_capture_state")
    return row


def validate_capture_projection(plan: Mapping[str, Any], records: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    header = validate_capture_header({key: plan[key] for key in CAPTURE_COLUMNS["capture_jobs"]})
    prepared = [validate_record(record) for record in records]
    if len(prepared) != header["record_count"] or len({record["memory_id"] for record in prepared}) != len(prepared):
        raise MemoryError("invalid_capture_projection")
    by_id = {record["memory_id"]: record for record in prepared}
    if (header["episode_id"] not in by_id or by_id[header["episode_id"]]["kind"] != "episode"
            or header["continuity_id"] not in by_id or by_id[header["continuity_id"]]["kind"] != "continuity"
            or any(record["created_at"] != header["created_at"] for record in prepared)):
        raise MemoryError("invalid_capture_projection")
    continuity = by_id[header["continuity_id"]]
    expected = [{"type": "derived_from", "target": header["episode_id"]}]
    if header["previous_continuity_id"] is not None:
        expected.append({"type": "continues", "target": header["previous_continuity_id"]})
    if {(edge["type"], edge["target"]) for edge in continuity["relations"]} != {(edge["type"], edge["target"]) for edge in expected}:
        raise MemoryError("invalid_capture_projection")
    # A visible-turn plan may carry episode fragments, never arbitrary external
    # semantic edges or a second predecessor selected during materialization.
    for record in prepared:
        if record["memory_id"] != header["continuity_id"] and record["kind"] != "episode":
            raise MemoryError("invalid_capture_projection")
        for relation in record["relations"]:
            if relation["target"] not in by_id and (record["memory_id"], relation["type"], relation["target"]) != (
                    header["continuity_id"], "continues", header["previous_continuity_id"]):
                raise MemoryError("invalid_capture_projection")
    if capture_digest(header, prepared) != header["projection_sha256"]:
        raise MemoryError("capture_projection_changed")
    return prepared


def load_capture(connection: sqlite3.Connection, job_key: str) -> dict[str, Any] | None:
    _match(job_key, _KEY)
    original = connection.execute("SELECT * FROM capture_jobs WHERE job_key=?", (job_key,)).fetchone()
    if original is None:
        return None
    plan = validate_capture_header(dict(original))
    rows = list(connection.execute("SELECT * FROM capture_records WHERE job_key=? ORDER BY ordinal LIMIT ?", (job_key, MAX_CAPTURE_RECORDS + 1)))
    if len(rows) != plan["record_count"]:
        raise MemoryError("invalid_capture_projection")
    refs, records = [], []
    for ordinal, original_record in enumerate(rows):
        row = dict(original_record)
        if (set(row) != set(CAPTURE_COLUMNS["capture_records"]) or row["job_key"] != job_key
                or row["ordinal"] != ordinal):
            raise MemoryError("invalid_capture_projection")
        _match(row["memory_id"], _ID)
        _match(row["record_sha256"], _HASH)
        if row["memory_id"] != "mem_" + row["record_sha256"][:40]:
            raise MemoryError("invalid_capture_projection")
        refs.append({"memory_id": row["memory_id"], "record_sha256": row["record_sha256"]})
        if row["record_json"] is None:
            if plan["state"] != "saved":
                raise MemoryError("invalid_capture_projection")
        else:
            if not isinstance(row["record_json"], str) or len(row["record_json"].encode("utf-8")) > MAX_BUNDLE_LINE_BYTES:
                raise MemoryError("capture_projection_limit")
            record = validate_record(strict_json_loads(row["record_json"]))
            if any(record[key] != row[key] for key in ("memory_id", "record_sha256")):
                raise MemoryError("capture_projection_changed")
            records.append(record)
    if len({reference["memory_id"] for reference in refs}) != len(refs):
        raise MemoryError("invalid_capture_projection")
    if {plan["episode_id"], plan["continuity_id"]} - {reference["memory_id"] for reference in refs}:
        raise MemoryError("invalid_capture_projection")
    if records:
        if len(records) != len(refs):
            raise MemoryError("invalid_capture_projection")
        records = validate_capture_projection(plan, records)
    plan["records"] = records
    plan["record_refs"] = refs
    return plan


def freeze_capture(
    connection: sqlite3.Connection, *, scope_key: str, job_key: str, input_sha256: str,
    builder_profile: str, canonical_request_id: str,
    build_projection: Callable[[str, Mapping[str, str] | None], tuple[Sequence[Mapping[str, Any]], str, str]],
    created_at: str | None = None,
) -> dict[str, Any]:
    """Freeze predecessor, time and bytes atomically with the caller's accept.

    The last accepted plan can still be pending. A later plan must retain that
    predecessor until it exists canonically; it cannot silently omit the edge.
    The builder is never called again on an exact retry.
    """
    if not connection.in_transaction:
        raise MemoryError("capture_transaction_required")
    for value in (scope_key, job_key, canonical_request_id):
        _match(value, _KEY)
    _match(input_sha256, _HASH)
    _match(builder_profile, _PROFILE)
    existing = load_capture(connection, job_key)
    if existing is not None:
        if any(existing[key] != value for key, value in (
                ("scope_key", scope_key), ("input_sha256", input_sha256),
                ("builder_profile", builder_profile), ("canonical_request_id", canonical_request_id))):
            raise MemoryError("capture_request_conflict")
        if created_at is not None and existing["created_at"] != created_at:
            raise MemoryError("capture_request_conflict")
        return existing
    if connection.execute("SELECT COUNT(*) FROM capture_jobs").fetchone()[0] >= MAX_CAPTURE_JOBS:
        raise MemoryError("capture_history_limit")
    if connection.execute("SELECT COUNT(*) FROM capture_jobs WHERE state='pending'").fetchone()[0] >= MAX_CAPTURE_PENDING_JOBS:
        raise MemoryError("capture_pending_limit")
    head = connection.execute("SELECT * FROM capture_heads WHERE scope_key=?", (scope_key,)).fetchone()
    previous = None
    predecessor_job_key = None
    sequence = 1
    if head is not None:
        head = dict(head)
        if set(head) != set(CAPTURE_COLUMNS["capture_heads"]) or head["scope_key"] != scope_key:
            raise MemoryError("invalid_capture_head")
        _integer(head["accepted_sequence"], 1, 2**63 - 2)
        parent = load_capture(connection, _match(head["last_job_key"], _KEY))
        if parent is None or parent["scope_key"] != scope_key or parent["accepted_sequence"] != head["accepted_sequence"]:
            raise MemoryError("invalid_capture_head")
        predecessor_job_key = parent["job_key"]
        previous = next(reference for reference in parent["record_refs"] if reference["memory_id"] == parent["continuity_id"])
        sequence = head["accepted_sequence"] + 1
    fixed_time = _timestamp(created_at if created_at is not None else utc_now())
    records, episode_id, continuity_id = build_projection(fixed_time, previous)
    records = [validate_record(record) for record in records]
    if not 2 <= len(records) <= MAX_CAPTURE_RECORDS:
        raise MemoryError("capture_projection_limit")
    encoded = [canonical_bytes(record).decode("utf-8") for record in records]
    occupied = int(connection.execute("SELECT COALESCE(SUM(length(CAST(r.record_json AS BLOB))),0) FROM capture_records r JOIN capture_jobs j ON j.job_key=r.job_key WHERE j.state='pending'").fetchone()[0])
    if occupied + sum(len(record.encode("utf-8")) for record in encoded) > MAX_CAPTURE_PENDING_BYTES:
        raise MemoryError("capture_pending_bytes_limit")
    plan = {
        "job_key": job_key, "scope_key": scope_key, "accepted_sequence": sequence,
        "builder_profile": builder_profile, "input_sha256": input_sha256, "created_at": fixed_time,
        "predecessor_job_key": predecessor_job_key,
        "previous_continuity_id": previous["memory_id"] if previous is not None else None,
        "previous_record_sha256": previous["record_sha256"] if previous is not None else None,
        "episode_id": episode_id, "continuity_id": continuity_id,
        "projection_sha256": "0" * 64, "canonical_request_id": canonical_request_id,
        "state": "pending", "record_count": len(records),
    }
    plan["projection_sha256"] = capture_digest(plan, records)
    validate_capture_projection(plan, records)
    columns = CAPTURE_COLUMNS["capture_jobs"]
    connection.execute("INSERT INTO capture_jobs(" + ",".join(columns) + ") VALUES(" + ",".join("?" for _ in columns) + ")", tuple(plan[column] for column in columns))
    connection.executemany("INSERT INTO capture_records(job_key,ordinal,memory_id,record_sha256,record_json) VALUES(?,?,?,?,?)", (
        (job_key, ordinal, record["memory_id"], record["record_sha256"], encoded[ordinal]) for ordinal, record in enumerate(records)
    ))
    connection.execute("INSERT INTO capture_heads(scope_key,accepted_sequence,last_job_key) VALUES(?,?,?) ON CONFLICT(scope_key) DO UPDATE SET accepted_sequence=excluded.accepted_sequence,last_job_key=excluded.last_job_key", (scope_key, sequence, job_key))
    result = load_capture(connection, job_key)
    assert result is not None
    return result


def mark_capture_saved(connection: sqlite3.Connection, job_key: str) -> None:
    """Clear duplicate staging text only after canonical durability is known."""
    if not connection.in_transaction:
        raise MemoryError("capture_transaction_required")
    if load_capture(connection, job_key) is None:
        raise MemoryError("unknown_capture_job")
    connection.execute("UPDATE capture_jobs SET state='saved' WHERE job_key=?", (job_key,))
    connection.execute("UPDATE capture_records SET record_json=NULL WHERE job_key=?", (job_key,))


def validate_capture_state(connection: sqlite3.Connection) -> Mapping[str, int]:
    """Explicit full recovery validation; never a per-turn history scan."""
    jobs = list(connection.execute("SELECT job_key FROM capture_jobs LIMIT ?", (MAX_CAPTURE_JOBS + 1,)))
    if len(jobs) > MAX_CAPTURE_JOBS:
        raise MemoryError("capture_history_limit")
    plans: dict[str, dict[str, Any]] = {}
    latest: dict[str, dict[str, Any]] = {}
    pending_count = pending_bytes = record_count = 0
    for row in jobs:
        plan = load_capture(connection, row[0])
        assert plan is not None
        plans[plan["job_key"]] = {key: value for key, value in plan.items() if key != "records"}
        previous_latest = latest.get(plan["scope_key"])
        if previous_latest is None or plan["accepted_sequence"] > previous_latest["accepted_sequence"]:
            latest[plan["scope_key"]] = plans[plan["job_key"]]
        record_count += plan["record_count"]
        if plan["state"] == "pending":
            pending_count += 1
            pending_bytes += sum(len(canonical_bytes(record)) for record in plan["records"])
    if pending_count > MAX_CAPTURE_PENDING_JOBS or pending_bytes > MAX_CAPTURE_PENDING_BYTES:
        raise MemoryError("capture_pending_limit")
    for plan in plans.values():
        parent_key = plan["predecessor_job_key"]
        if parent_key is None:
            if plan["accepted_sequence"] != 1:
                raise MemoryError("invalid_capture_predecessor")
            continue
        parent = plans.get(parent_key)
        if (parent is None or parent["scope_key"] != plan["scope_key"]
                or parent["accepted_sequence"] + 1 != plan["accepted_sequence"]
                or parent["continuity_id"] != plan["previous_continuity_id"]):
            raise MemoryError("invalid_capture_predecessor")
        reference = next(item for item in parent["record_refs"] if item["memory_id"] == parent["continuity_id"])
        if reference["record_sha256"] != plan["previous_record_sha256"]:
            raise MemoryError("invalid_capture_predecessor")
    heads = list(connection.execute("SELECT * FROM capture_heads LIMIT ?", (MAX_CAPTURE_JOBS + 1,)))
    if len(heads) != len(latest):
        raise MemoryError("invalid_capture_head")
    for original in heads:
        head = dict(original)
        if set(head) != set(CAPTURE_COLUMNS["capture_heads"]):
            raise MemoryError("invalid_capture_head")
        tip = latest.get(head["scope_key"])
        if tip is None or head["last_job_key"] != tip["job_key"] or head["accepted_sequence"] != tip["accepted_sequence"]:
            raise MemoryError("invalid_capture_head")
    if connection.execute("SELECT COUNT(*) FROM capture_records").fetchone()[0] != record_count:
        raise MemoryError("invalid_capture_projection")
    if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
        raise MemoryError("invalid_capture_state")
    return {"capture_heads": len(heads), "capture_jobs": len(plans), "capture_records": record_count}


class HookCaptureJournal:
    """Private acceptance journal for visible hooks; no host or Vault access.

    Outbox files are preparatory input. A turn joins its local causal sequence
    only when ``freeze_capture`` commits here. Neither opening the journal nor
    following its scopes grants permission to read or write canonical memory.
    """

    def __init__(self, state_path: Path, vault_path: Path):
        self.path = Path(state_path) / HOOK_CAPTURE_FILENAME
        self.vault_path_sha256 = sha256(canonical_bytes(str(vault_path)))

    @staticmethod
    def _schema(connection: sqlite3.Connection) -> None:
        expected = {"meta": "CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)", **CAPTURE_SQL}
        normalize = lambda sql: re.sub(r"\s+", "", sql).lower()
        found: dict[str, str] = {}
        for row in connection.execute("SELECT name,sql FROM sqlite_master WHERE sql IS NOT NULL"):
            if row[0] not in expected or normalize(row[1]) != normalize(expected[row[0]]):
                raise MemoryError("unsupported_hook_capture_state")
            found[row[0]] = row[1]
        if set(found) != set(expected):
            raise MemoryError("unsupported_hook_capture_state")

    def connect(self, *, writable: bool = False) -> sqlite3.Connection | None:
        from memory_vault_storage import StorageError, open_file, private_directory, validate_path
        try:
            validate_path(self.path)
            if not writable and not self.path.parent.exists():
                return None
            private_directory(self.path.parent, create=writable)
            try:
                descriptor = open_file(self.path, os.O_RDWR | os.O_CREAT if writable else os.O_RDONLY, private=True)
            except FileNotFoundError:
                if not writable:
                    return None
                raise
            os.close(descriptor)
            for suffix in ("-journal", "-wal", "-shm"):
                try:
                    descriptor = open_file(Path(str(self.path) + suffix), os.O_RDONLY, private=True)
                except FileNotFoundError:
                    continue
                os.close(descriptor)
        except StorageError as exc:
            raise MemoryError(exc.code, retryable=exc.retryable) from None
        connection = sqlite3.connect(self.path.as_uri() + ("?mode=rw" if writable else "?mode=ro"), uri=True, timeout=5)
        connection.row_factory = sqlite3.Row
        try:
            connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 8 * 1024 * 1024)
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            if writable:
                connection.execute("PRAGMA journal_mode=DELETE")
                connection.execute("PRAGMA synchronous=FULL")
                connection.execute("PRAGMA secure_delete=ON")
                connection.execute("BEGIN IMMEDIATE")
            else:
                connection.execute("PRAGMA query_only=ON")
                connection.execute("BEGIN")
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version == 0:
                if connection.execute("SELECT 1 FROM sqlite_master LIMIT 1").fetchone():
                    raise MemoryError("unsupported_hook_capture_state")
                if not writable:
                    connection.close()
                    return None
                connection.execute("CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)")
                initialize_capture(connection)
                connection.executemany("INSERT INTO meta(key,value) VALUES(?,?)", (
                    ("schema_version", HOOK_CAPTURE_SCHEMA), ("vault_path_sha256", self.vault_path_sha256),
                ))
                connection.execute("PRAGMA user_version=1")
            elif version != 1:
                raise MemoryError("unsupported_hook_capture_state")
            self._schema(connection)
            meta = dict(connection.execute("SELECT key,value FROM meta"))
            if meta != {"schema_version": HOOK_CAPTURE_SCHEMA, "vault_path_sha256": self.vault_path_sha256}:
                raise MemoryError("hook_capture_vault_changed")
            connection.commit()
            if writable and os.name != "nt":
                descriptor = os.open(self.path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            return connection
        except BaseException:
            connection.close()
            raise

    @contextlib.contextmanager
    def transaction(self, *, writable: bool = True) -> Iterator[sqlite3.Connection | None]:
        connection = self.connect(writable=writable)
        if connection is None:
            yield None
            return
        with contextlib.closing(connection), connection:
            connection.execute("BEGIN IMMEDIATE" if writable else "BEGIN")
            yield connection
