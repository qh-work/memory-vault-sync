#!/usr/bin/env python3
"""Explicit local visible-turn lifecycle over the one canonical Memory Vault.

This is universal-memory-lifecycle/v1, not the legacy v0.21 wire protocol.
Session/turn handles correlate local staging only. They never own memory or
enter canonical records. Capture must be explicitly enabled by the operator;
requests provide caller-reported visible text, never independent host evidence.
There is no transcript discovery or permission decision. A committed local turn
can notify the independently opted-in full-mode sync worker without waiting for
network delivery. See docs/LIFECYCLE.md for cancellation and crash-retry semantics.
"""

from __future__ import annotations

import argparse
import contextlib
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import sys
from typing import Any, Iterator, Mapping, Sequence

from memory_vault import (
    MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, MemoryError, VERSION, canonical_bytes,
    failure, read_request, strict_json_loads, success,
)
from memory_vault_client import (
    MAX_TURN_PART_BYTES, ClientConfig, _absolute, _continuity, _digest, _object,
    _private_directory, _request_id, _text, default_config_path, notify_sync, observe_turn,
)


PROFILE = "universal-memory-lifecycle/v1"
REQUEST_SCHEMA = "universal-memory-lifecycle-request/v1"
RESULT_SCHEMA = "universal-memory-lifecycle-result/v1"
STATE_SCHEMA = "universal-memory-lifecycle-state/v1"
OPERATIONS = (
    "capabilities", "session.open", "turn.input", "turn.commit", "turn.abort",
    "session.close",
)
MAX_ACTIVE_SESSIONS = 128
MAX_PENDING_TURNS = 256
MAX_PENDING_BYTES = 32 * 1024 * 1024
_SESSION = re.compile(r"ses_[0-9a-f]{32}")
_TURN = re.compile(r"turn_[0-9a-f]{32}")


def _ok(op: str, result: Mapping[str, Any], request_id: str | None = None) -> dict[str, Any]:
    response = success(result, request_id=request_id)
    response.update(schema_version=RESULT_SCHEMA, op=op, replayed=False)
    return response


def _error(code: str, *, request: Mapping[str, Any] | None = None, retryable: bool = False) -> dict[str, Any]:
    value = request or {}
    request_id = value.get("request_id")
    response = failure(code, retryable=retryable, request_id=request_id if isinstance(request_id, str) else None)
    response["schema_version"] = RESULT_SCHEMA
    if value.get("op") in OPERATIONS:
        response["op"] = value["op"]
    return response


def _validate(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("op") not in OPERATIONS:
        raise MemoryError("unsupported_lifecycle_operation")
    op = value["op"]
    required = {"schema_version", "op"}
    optional: set[str] = set()
    if op == "capabilities":
        optional.add("request_id")
    else:
        required.add("request_id")
    if op in {"turn.input", "session.close"}:
        required.add("session_handle")
    if op == "turn.input":
        required.add("user")
    if op in {"turn.commit", "turn.abort"}:
        required.add("turn_handle")
    if op == "turn.commit":
        required.add("assistant")
        optional.add("continuity")
    request = _object(value, required=required, optional=optional)
    if request["schema_version"] != REQUEST_SCHEMA:
        raise MemoryError("unsupported_lifecycle_schema")
    if "request_id" in request:
        _request_id(request["request_id"], "validate-only")
    for name, pattern in (("session_handle", _SESSION), ("turn_handle", _TURN)):
        if name in request and (not isinstance(request[name], str) or pattern.fullmatch(request[name]) is None):
            raise MemoryError("invalid_lifecycle_handle")
    for name in ("user", "assistant", "continuity"):
        if name in request:
            _text(request[name], maximum=32 * 1024 if name == "continuity" else MAX_TURN_PART_BYTES)
    if len(canonical_bytes(request)) > MAX_REQUEST_BYTES:
        raise MemoryError("request_too_large")
    return request


def capabilities(request_id: str | None = None) -> Mapping[str, Any]:
    return _ok("capabilities", {
        "profile": PROFILE, "implementation_version": VERSION,
        "request_schema": REQUEST_SCHEMA, "result_schema": RESULT_SCHEMA,
        "operations": list(OPERATIONS), "transport": "local_ndjson_stdio",
        "legacy_v021_wire_compatible": False, "capture_opt_in_required": True,
        "capture_basis": "caller_reported", "host_attestation": False,
        "memory_store": "shared_canonical_vault", "handles_are_memory_owners": False,
        "context_view": "core_handoff_or_recall", "network_accessed": False,
        "limits": {
            "request_bytes": MAX_REQUEST_BYTES, "turn_part_bytes": MAX_TURN_PART_BYTES,
            "continuity_bytes": 32 * 1024, "active_sessions": MAX_ACTIVE_SESSIONS,
            "pending_turns": MAX_PENDING_TURNS, "pending_text_bytes": MAX_PENDING_BYTES,
        },
    }, request_id)


class LifecycleState:
    """Private staging and content-free receipts, never a second memory store.

    SQLite's local transaction lock serializes cancellation versus freezing a
    commit. The committing marker is durable BEFORE any canonical write. A
    crashed process therefore cannot make a later abort falsely claim rollback.
    """

    def __init__(self, config: ClientConfig):
        self.config = config
        self.path = _absolute(config.state_path / "lifecycle-v1.sqlite3")

    @staticmethod
    def _check_file(path: Path, *, create: bool = False, readonly: bool = False) -> bool:
        _absolute(path)
        flags = (os.O_RDONLY if readonly else os.O_RDWR) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        if create:
            flags |= os.O_CREAT
        try:
            descriptor = os.open(path, flags, 0o600)
        except FileNotFoundError:
            if not create:
                return False
            raise
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise MemoryError("unsafe_lifecycle_state")
            if os.name != "nt" and (info.st_uid != os.geteuid() or info.st_mode & 0o077):
                raise MemoryError("lifecycle_state_not_private")
        finally:
            os.close(descriptor)
        return True

    def completed_receipt(self, request: Mapping[str, Any]) -> Mapping[str, Any] | None:
        """A completed save can be acknowledged after capture is disabled.

        This opens only an existing control database in SQLite mode=ro. It does
        not create directories, initialize/upgrade state, resume a partial
        commit or load a signing key. The receipt is explicitly historical,
        never a cached assertion of current signature trust.
        """
        if not self.path.parent.exists():
            return None
        info = self.path.parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or (os.name != "nt" and (info.st_uid != os.geteuid() or info.st_mode & 0o077)):
            raise MemoryError("lifecycle_state_not_private")
        if not self._check_file(self.path, readonly=True):
            return None
        for suffix in ("-journal", "-wal", "-shm"):
            self._check_file(Path(str(self.path) + suffix), readonly=True)
        with contextlib.closing(sqlite3.connect(self.path.as_uri() + "?mode=ro", uri=True, timeout=5)) as connection, connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("BEGIN")
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version == 0:
                # A crash may leave the exclusively created file empty before
                # schema initialization. There is no receipt to replay; only
                # the later, explicitly authorized mutation may initialize it.
                return None
            if version != 1:
                raise MemoryError("unsupported_lifecycle_state")
            meta = dict(connection.execute("SELECT key,value FROM meta"))
            if meta.get("schema_version") != STATE_SCHEMA:
                raise MemoryError("unsupported_lifecycle_state")
            if meta.get("vault_path_sha256") != _digest(str(self.config.vault_path)):
                raise MemoryError("lifecycle_vault_changed")
            return self.receipt(connection, request)

    def _connect(self) -> sqlite3.Connection:
        _private_directory(self.path.parent)
        self._check_file(self.path, create=True)
        for suffix in ("-journal", "-wal", "-shm"):
            self._check_file(Path(str(self.path) + suffix))
        connection = sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True, timeout=5)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA secure_delete=ON")
            connection.execute("BEGIN IMMEDIATE")
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version == 0:
                if connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' LIMIT 1").fetchone():
                    raise MemoryError("unsupported_lifecycle_state")
                for statement in (
                    "CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)",
                    "CREATE TABLE sessions(handle TEXT PRIMARY KEY,state TEXT NOT NULL CHECK(state IN ('open','closed')))",
                    "CREATE TABLE turns(handle TEXT PRIMARY KEY,session_handle TEXT NOT NULL REFERENCES sessions(handle),phase TEXT NOT NULL CHECK(phase IN ('staged','committing','committed','aborted')),user_text TEXT,assistant_text TEXT,continuity_text TEXT,commit_request TEXT)",
                    "CREATE INDEX turns_session ON turns(session_handle,phase)",
                    "CREATE TABLE requests(request_key TEXT PRIMARY KEY,payload_sha256 TEXT NOT NULL,response_json TEXT,session_handle TEXT REFERENCES sessions(handle),turn_handle TEXT REFERENCES turns(handle))",
                ):
                    connection.execute(statement)
                connection.executemany("INSERT INTO meta(key,value) VALUES(?,?)", (
                    ("schema_version", STATE_SCHEMA),
                    ("vault_path_sha256", _digest(str(self.config.vault_path))),
                ))
                connection.execute("PRAGMA user_version=1")
            elif version != 1:
                raise MemoryError("unsupported_lifecycle_state")
            meta = dict(connection.execute("SELECT key,value FROM meta"))
            if meta.get("schema_version") != STATE_SCHEMA:
                raise MemoryError("unsupported_lifecycle_state")
            if meta.get("vault_path_sha256") != _digest(str(self.config.vault_path)):
                raise MemoryError("lifecycle_vault_changed")
            connection.commit()
            if os.name != "nt":
                directory = os.open(self.path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
            return connection
        except BaseException:
            connection.close()
            raise

    @contextlib.contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with contextlib.closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            yield connection

    @staticmethod
    def receipt(connection: sqlite3.Connection, request: Mapping[str, Any]) -> Mapping[str, Any] | None:
        row = connection.execute("SELECT * FROM requests WHERE request_key=?", (_digest(request["request_id"]),)).fetchone()
        if row is None:
            return None
        if row["payload_sha256"] != _digest(request):
            raise MemoryError("request_id_conflict")
        if row["response_json"] is None:
            if request["op"] != "turn.commit":
                raise MemoryError("invalid_lifecycle_receipt")
            return None
        response = strict_json_loads(row["response_json"])
        if not isinstance(response, dict) or response.get("schema_version") != RESULT_SCHEMA:
            raise MemoryError("invalid_lifecycle_receipt")
        response["replayed"] = True
        if row["turn_handle"]:
            current = connection.execute("SELECT phase FROM turns WHERE handle=?", (row["turn_handle"],)).fetchone()
        else:
            current = connection.execute("SELECT state FROM sessions WHERE handle=?", (row["session_handle"],)).fetchone()
        if current is None:
            raise MemoryError("invalid_lifecycle_receipt")
        response["result"]["current_state"] = current[0]
        return response

    @staticmethod
    def save_receipt(connection: sqlite3.Connection, request: Mapping[str, Any], result: Mapping[str, Any], *, session: str, turn: str | None = None) -> Mapping[str, Any]:
        response = _ok(request["op"], {**result, "network_accessed": False}, request["request_id"])
        connection.execute(
            "INSERT INTO requests(request_key,payload_sha256,response_json,session_handle,turn_handle) VALUES(?,?,?,?,?)",
            (_digest(request["request_id"]), _digest(request), canonical_bytes(response).decode("utf-8"), session, turn),
        )
        return response

    @staticmethod
    def budget(connection: sqlite3.Connection, additional_bytes: int) -> None:
        row = connection.execute(
            "SELECT COALESCE(SUM(COALESCE(length(CAST(user_text AS BLOB)),0)+COALESCE(length(CAST(assistant_text AS BLOB)),0)+COALESCE(length(CAST(continuity_text AS BLOB)),0)),0) FROM turns WHERE phase IN ('staged','committing')"
        ).fetchone()
        if row[0] + additional_bytes > MAX_PENDING_BYTES:
            raise MemoryError("lifecycle_pending_text_limit")

    @staticmethod
    def session(connection: sqlite3.Connection, handle: str) -> sqlite3.Row:
        row = connection.execute("SELECT * FROM sessions WHERE handle=?", (handle,)).fetchone()
        if row is None:
            raise MemoryError("unknown_session_handle")
        return row

    @staticmethod
    def turn(connection: sqlite3.Connection, handle: str) -> sqlite3.Row:
        row = connection.execute("SELECT * FROM turns WHERE handle=?", (handle,)).fetchone()
        if row is None:
            raise MemoryError("unknown_turn_handle")
        return row

    def prepare(self, request: Mapping[str, Any]) -> tuple[Mapping[str, Any] | None, dict[str, Any] | None]:
        """Return a completed response or a durably frozen canonical-write job."""
        op = request["op"]
        with self.transaction() as connection:
            prior = self.receipt(connection, request)
            if prior is not None:
                return prior, None
            if op == "session.open":
                count = connection.execute("SELECT COUNT(*) FROM sessions WHERE state='open'").fetchone()[0]
                if count >= MAX_ACTIVE_SESSIONS:
                    raise MemoryError("lifecycle_session_limit")
                session = "ses_" + secrets.token_hex(16)
                connection.execute("INSERT INTO sessions(handle,state) VALUES(?,'open')", (session,))
                return self.save_receipt(connection, request, {
                    "state": "opened", "current_state": "open", "session_handle": session,
                    "memory_saved": False,
                }, session=session), None
            if op in {"turn.input", "session.close"}:
                session = request["session_handle"]
                current_session = self.session(connection, session)
                if current_session["state"] != "open":
                    raise MemoryError("session_closed")
                if op == "session.close":
                    if connection.execute("SELECT 1 FROM turns WHERE session_handle=? AND phase='committing' LIMIT 1", (session,)).fetchone():
                        raise MemoryError("session_commit_in_progress")
                    cancelled = connection.execute(
                        "UPDATE turns SET phase='aborted',user_text=NULL,assistant_text=NULL,continuity_text=NULL WHERE session_handle=? AND phase='staged'", (session,)
                    ).rowcount
                    connection.execute("UPDATE sessions SET state='closed' WHERE handle=?", (session,))
                    return self.save_receipt(connection, request, {
                        "state": "closed", "current_state": "closed", "session_handle": session,
                        "aborted_turns": cancelled, "memory_saved": False, "long_term_memory_deleted": False,
                    }, session=session), None
                count = connection.execute("SELECT COUNT(*) FROM turns WHERE phase IN ('staged','committing')").fetchone()[0]
                if count >= MAX_PENDING_TURNS:
                    raise MemoryError("lifecycle_pending_turn_limit")
                self.budget(connection, len(request["user"].encode("utf-8")))
                turn = "turn_" + secrets.token_hex(16)
                connection.execute("INSERT INTO turns(handle,session_handle,phase,user_text) VALUES(?,?,'staged',?)", (turn, session, request["user"]))
                return self.save_receipt(connection, request, {
                    "state": "staged", "current_state": "staged", "session_handle": session,
                    "turn_handle": turn, "memory_saved": False, "capture_basis": "caller_reported",
                }, session=session, turn=turn), None
            turn = request["turn_handle"]
            current_turn = self.turn(connection, turn)
            session = current_turn["session_handle"]
            if op == "turn.abort":
                if current_turn["phase"] == "committing":
                    raise MemoryError("commit_started_cannot_abort")
                if current_turn["phase"] == "committed":
                    raise MemoryError("turn_already_committed")
                connection.execute("UPDATE turns SET phase='aborted',user_text=NULL,assistant_text=NULL,continuity_text=NULL WHERE handle=?", (turn,))
                return self.save_receipt(connection, request, {
                    "state": "aborted", "current_state": "aborted", "session_handle": session,
                    "turn_handle": turn, "memory_saved": False, "long_term_memory_deleted": False,
                }, session=session, turn=turn), None
            if current_turn["phase"] == "aborted":
                raise MemoryError("turn_aborted")
            if current_turn["phase"] == "committed":
                raise MemoryError("turn_already_committed")
            request_key = _digest(request["request_id"])
            if current_turn["phase"] == "committing":
                if current_turn["commit_request"] != request_key:
                    raise MemoryError("turn_commit_in_progress")
                return None, dict(current_turn)
            if self.session(connection, session)["state"] != "open":
                raise MemoryError("session_closed")
            continuity = request.get("continuity")
            if continuity is None:
                # Freeze derived text now so software upgrades cannot silently
                # change the second half of an interrupted two-record commit.
                continuity = _continuity(current_turn["user_text"], request["assistant"], host_visible=False)
            self.budget(connection, len(request["assistant"].encode("utf-8")) + len(continuity.encode("utf-8")))
            connection.execute(
                "INSERT INTO requests(request_key,payload_sha256,response_json,session_handle,turn_handle) VALUES(?,?,NULL,?,?)",
                (request_key, _digest(request), session, turn),
            )
            connection.execute(
                "UPDATE turns SET phase='committing',assistant_text=?,continuity_text=?,commit_request=? WHERE handle=?",
                (request["assistant"], continuity, request_key, turn),
            )
            return None, dict(self.turn(connection, turn))

    def commit(self, request: Mapping[str, Any], job: Mapping[str, Any]) -> Mapping[str, Any]:
        try:
            stored = observe_turn(
                self.config, request_id=_request_id(request["request_id"], "lifecycle-commit-v1"),
                user=job["user_text"], assistant=job["assistant_text"], continuity=job["continuity_text"],
                caller_source="lifecycle-caller-reported",
            )
            if not stored.get("ok"):
                problem = stored.get("error", {})
                response = _error(problem.get("code", "lifecycle_commit_unconfirmed"), request=request, retryable=problem.get("retryable", False))
                response["resume_same_request"] = True
                if "partial_result" in stored:
                    response["partial_result"] = stored["partial_result"]
                return response
            with self.transaction() as connection:
                prior = self.receipt(connection, request)
                if prior is not None:
                    return prior
                turn = self.turn(connection, request["turn_handle"])
                if turn["phase"] != "committing" or turn["commit_request"] != _digest(request["request_id"]):
                    raise MemoryError("lifecycle_commit_state_conflict")
                response = _ok("turn.commit", {
                    **stored["result"], "state": "committed", "current_state": "committed",
                    "session_handle": turn["session_handle"], "turn_handle": turn["handle"],
                    "memory_saved": True, "receipt_scope": "local_save_not_current_trust_or_remote_delivery",
                }, request["request_id"])
                connection.execute(
                    "UPDATE turns SET phase='committed',user_text=NULL,assistant_text=NULL,continuity_text=NULL WHERE handle=?", (turn["handle"],)
                )
                connection.execute(
                    "UPDATE requests SET response_json=? WHERE request_key=?", (canonical_bytes(response).decode("utf-8"), _digest(request["request_id"]))
                )
            notify_sync(self.config, "turn-commit")
            return response
        except MemoryError as exc:
            response = _error(exc.code, request=request, retryable=exc.retryable)
        except Exception:
            response = _error("lifecycle_commit_unconfirmed", request=request, retryable=True)
        response["resume_same_request"] = True
        return response


def handle(config_path: Path, value: Any) -> Mapping[str, Any]:
    request: dict[str, Any] | None = None
    try:
        request = _validate(value)
        if request["op"] == "capabilities":
            return capabilities(request.get("request_id"))
        config = ClientConfig.load(config_path)
        state = LifecycleState(config)
        may_mutate = config.capture_visible_turns or request["op"] in {"turn.abort", "session.close"}
        try:
            prior = state.completed_receipt(request)
        except sqlite3.OperationalError:
            # An interrupted SQLite transaction can leave a hot journal which
            # mode=ro cannot recover. Only an independently authorized mutation
            # may reopen writable; prepare() checks the receipt again before
            # taking any transition. Disabled capture never resumes a commit.
            if not may_mutate:
                raise
            prior = None
        if prior is not None:
            return prior
        # Disabling capture forbids new inputs and commits, but must not trap
        # uncommitted visible text: explicit abort/close remain available.
        if not may_mutate:
            raise MemoryError("capture_not_enabled")
        response, job = state.prepare(request)
        if response is not None:
            return response
        if job is None:
            raise MemoryError("invalid_lifecycle_state")
        return state.commit(request, job)
    except MemoryError as exc:
        return _error(exc.code, request=request, retryable=exc.retryable)
    except sqlite3.Error as exc:
        busy = "locked" in str(exc).lower() or "busy" in str(exc).lower()
        return _error("lifecycle_state_busy" if busy else "lifecycle_state_unavailable", request=request, retryable=busy)
    except Exception:
        return _error("lifecycle_unavailable", request=request, retryable=True)


def _emit(response: Mapping[str, Any]) -> None:
    encoded = canonical_bytes(response) + b"\n"
    if len(encoded) > MAX_RESPONSE_BYTES:
        encoded = canonical_bytes(_error("response_too_large")) + b"\n"
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()


def run_stream(config_path: Path, *, serve: bool = False) -> int:
    if not serve:
        try:
            response = handle(config_path, read_request())
        except MemoryError as exc:
            response = _error(exc.code, retryable=exc.retryable)
        except Exception:
            response = _error("lifecycle_unavailable", retryable=True)
        _emit(response)
        return 0 if response.get("ok") else 1
    while True:
        line = sys.stdin.buffer.readline(MAX_REQUEST_BYTES + 1)
        if not line:
            return 0
        if len(line) > MAX_REQUEST_BYTES or not line.endswith(b"\n"):
            _emit(_error("invalid_frame"))
            return 1
        try:
            response = handle(config_path, strict_json_loads(line))
        except MemoryError as exc:
            response = _error(exc.code, retryable=exc.retryable)
        except Exception:
            response = _error("lifecycle_unavailable", retryable=True)
        _emit(response)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Explicit local Memory Vault lifecycle v1; no automatic installation or networking.")
    parser.add_argument("--config", type=Path, help="same operator-controlled configuration as MCP and the client protocol entry")
    parser.add_argument("--serve", action="store_true", help="serve lifecycle NDJSON until EOF")
    args = parser.parse_args(argv)
    try:
        config_path = _absolute(args.config) if args.config is not None else default_config_path()
        return run_stream(config_path, serve=args.serve)
    except MemoryError as exc:
        _emit(_error(exc.code, retryable=exc.retryable))
        return 1
    except Exception:
        _emit(_error("lifecycle_unavailable", retryable=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
