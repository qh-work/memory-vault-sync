"""Bounded enrollment for an operator-run, synthetic-only network trial.

The coordinator is deliberately separate from the relay and memory store.  It
accepts only a one-time run code and a candidate's public Ed25519/X25519
descriptors, then delegates membership issuance to ``invite_candidate``.  It
never receives candidate private keys, plaintext memories, or execution
requests.

State initialization and serving are explicit foreground operations.  Run
codes are stored as HMAC tags under a private, operator-selected state
directory.  A claimed code is never reassigned, including after a partial
failure.  Exact retries for the same public identity recover the already
persisted invitation when the signed roster commit can be verified.
"""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import hashlib
import hmac
import os
from pathlib import Path
import re
import secrets
import sqlite3
import ssl
import sys
import threading
import time
from typing import Any, Iterator, Mapping, Sequence

from memory_vault import MemoryError, canonical_bytes, strict_json_loads
from memory_vault_network import origin
from memory_vault_network_admin import _read, invite_candidate
from memory_vault_network_control import member, verify_invite, verify_roster
from memory_vault_network_crypto import (
    NetworkCryptoError,
    document,
    document_sha256,
    object_fields,
    opaque,
)
import memory_vault_storage as storage
from memory_vault_trust import Identity, TrustStore, _absolute_path, _read_private, _write_new_private


CONFIG_SCHEMA = "memory-vault-trial-coordinator-config/v1"
SERVICE_SCHEMA = "memory-vault-trial-service/v1"
RESULT_SCHEMA = "memory-vault-trial-enrollment-result/v1"
MAX_CONFIG_BYTES = 64 * 1024
MAX_INVITATION_BYTES = 2 * 1024 * 1024
_RUN_CODE = re.compile(r"[A-Za-z0-9._~-]{32,128}")
_SCHEMA = """
CREATE TABLE IF NOT EXISTS metadata (
 key TEXT PRIMARY KEY, value BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS run_codes (
 code_tag TEXT PRIMARY KEY,
 state TEXT NOT NULL CHECK(state IN ('ready','claimed','completed')),
 candidate_sha256 TEXT,
 signing_key_id TEXT,
 encryption_key_id TEXT,
 invitation_path TEXT,
 result BLOB,
 claimed_at INTEGER,
 completed_at INTEGER,
 CHECK((state='ready' AND candidate_sha256 IS NULL AND result IS NULL)
    OR (state='claimed' AND candidate_sha256 IS NOT NULL AND result IS NULL)
    OR (state='completed' AND candidate_sha256 IS NOT NULL AND result IS NOT NULL))
);
CREATE TABLE IF NOT EXISTS attempts (
 bucket TEXT NOT NULL,
 window INTEGER NOT NULL,
 count INTEGER NOT NULL,
 PRIMARY KEY(bucket,window)
);
"""

DEFAULT_LIMITS = {
    "maximum_request_bytes": 16 * 1024,
    "maximum_concurrency": 4,
    "maximum_codes": 128,
    "maximum_enrollments": 96,
    "rate_window_seconds": 60,
    "maximum_requests_per_source_window": 8,
    "maximum_requests_per_global_window": 64,
    "invitation_lifetime_seconds": 300,
    "body_timeout_seconds": 10,
}
_LIMIT_RANGES = {
    "maximum_request_bytes": (1024, 32 * 1024),
    "maximum_concurrency": (1, 8),
    "maximum_codes": (1, 256),
    "maximum_enrollments": (1, 128),
    "rate_window_seconds": (10, 300),
    "maximum_requests_per_source_window": (1, 32),
    "maximum_requests_per_global_window": (1, 256),
    "invitation_lifetime_seconds": (60, 900),
    "body_timeout_seconds": (1, 10),
}


class TrialCoordinatorError(MemoryError):
    """Content-free trial enrollment failure."""


def _run_code(value: Any) -> str:
    if not isinstance(value, str) or _RUN_CODE.fullmatch(value) is None:
        raise TrialCoordinatorError("trial_run_code_invalid")
    return value


def _private_bytes(path: Path, maximum: int) -> bytes:
    fd = storage.open_file(path, os.O_RDONLY, private=True)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if before.st_size > maximum:
            raise TrialCoordinatorError("trial_state_invalid")
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise TrialCoordinatorError("trial_state_invalid")
    return raw


def _limits(value: Any) -> dict[str, int]:
    if not isinstance(value, Mapping) or set(value) - set(DEFAULT_LIMITS):
        raise TrialCoordinatorError("trial_configuration_invalid")
    result = dict(DEFAULT_LIMITS)
    for name, raw in value.items():
        if type(raw) is not int or not _LIMIT_RANGES[name][0] <= raw <= _LIMIT_RANGES[name][1]:
            raise TrialCoordinatorError("trial_configuration_invalid")
        result[name] = raw
    if result["maximum_enrollments"] > result["maximum_codes"]:
        raise TrialCoordinatorError("trial_configuration_invalid")
    if result["maximum_requests_per_source_window"] > result["maximum_requests_per_global_window"]:
        raise TrialCoordinatorError("trial_configuration_invalid")
    return result


def _configuration(config_path: Path) -> tuple[dict[str, Any], Path, Path, dict[str, int]]:
    selected = _absolute_path(config_path)
    raw = _read_private(selected, MAX_CONFIG_BYTES)
    if raw is None:
        raise TrialCoordinatorError("trial_configuration_missing")
    config = document(raw, maximum=MAX_CONFIG_BYTES)
    required = {
        "schema_version", "authority_config_path", "state_directory",
        "authority_url", "relays", "reference_peer_key_id", "limits",
    }
    if not isinstance(config, Mapping) or set(config) != required or config["schema_version"] != CONFIG_SCHEMA:
        raise TrialCoordinatorError("trial_configuration_invalid")
    authority = _absolute_path(Path(config["authority_config_path"])) if isinstance(config["authority_config_path"], str) else None
    state = _absolute_path(Path(config["state_directory"])) if isinstance(config["state_directory"], str) else None
    if authority is None or state is None:
        raise TrialCoordinatorError("trial_configuration_invalid")
    relays = config["relays"]
    if (not isinstance(relays, list) or not 1 <= len(relays) <= 2
            or any(not isinstance(item, str) for item in relays)):
        raise TrialCoordinatorError("trial_configuration_invalid")
    try:
        authority_url = origin(config["authority_url"])
        checked_relays = [origin(item) for item in relays]
        reference = opaque(config["reference_peer_key_id"])
    except MemoryError:
        raise TrialCoordinatorError("trial_configuration_invalid") from None
    if len(set(checked_relays)) != len(checked_relays):
        raise TrialCoordinatorError("trial_configuration_invalid")
    paths = {
        selected, authority, state / "trial.sqlite3", state / "code-pepper.bin",
        state / "operation.lock", state / "database.lock",
    }
    if len(paths) != 6 or state in {selected, authority} or selected == authority:
        raise TrialCoordinatorError("trial_configuration_path_conflict")
    checked = dict(config)
    checked["authority_url"], checked["relays"], checked["reference_peer_key_id"] = authority_url, checked_relays, reference
    checked_limits = _limits(config["limits"])
    checked["limits"] = checked_limits
    return checked, authority, state, checked_limits


class TrialCoordinator:
    """Synchronous bounded enrollment state machine behind an optional ASGI app."""

    def __init__(self, config_path: Path, *, initialize: bool = False):
        self.config_path = _absolute_path(config_path)
        self.config, self.authority_config, self.directory, self.limits = _configuration(self.config_path)
        self.database = self.directory / "trial.sqlite3"
        self.pepper_path = self.directory / "code-pepper.bin"
        self.operation_lock = self.directory / "operation.lock"
        self.database_lock = self.directory / "database.lock"
        self.invitation_directory = self.directory / "invitations"
        self._database_thread_lock = threading.Lock()
        self._operation_thread_lock = threading.Lock()
        if initialize:
            storage.private_directory(self.directory)
            storage.private_directory(self.invitation_directory)
            with storage.file_lock(self.operation_lock, busy_code="trial_busy"):
                if not self.pepper_path.exists():
                    storage.atomic_write(self.pepper_path, secrets.token_bytes(32), replace=False)
                with self._transaction(initialize=True) as db:
                    commitment = document_sha256(self.config)
                    saved = self._get(db, "config_sha256")
                    if saved is None:
                        self._set(db, "config_sha256", commitment)
                    elif saved != commitment:
                        raise TrialCoordinatorError("trial_state_configuration_mismatch")
        else:
            self._check_state()
            with self._transaction() as db:
                if self._get(db, "config_sha256") != document_sha256(self.config):
                    raise TrialCoordinatorError("trial_state_configuration_mismatch")
        self._pepper = _private_bytes(self.pepper_path, 32)
        if len(self._pepper) != 32:
            raise TrialCoordinatorError("trial_state_invalid")
        self.network_id, self.issuer_public = self._validate_authority()

    def _check_state(self) -> None:
        try:
            storage.check_private_directory(self.directory)
            storage.check_private_directory(self.invitation_directory)
        except (OSError, storage.StorageError):
            raise TrialCoordinatorError("trial_state_missing") from None
        if not self.database.exists() or not self.pepper_path.exists():
            raise TrialCoordinatorError("trial_state_missing")

    def _validate_authority(self) -> tuple[str, dict[str, str]]:
        config = _read(self.authority_config, private=True, maximum=16 * 1024)
        required = {"schema_version", "network_id", "identity_path", "trust_store_path", "roster_path"}
        if (not required <= set(config)
                or set(config) - required - {"node_directory_path", "topic_state_path"}
                or config["schema_version"] != "memory-vault-network-authority-config/v1"):
            raise TrialCoordinatorError("trial_authority_invalid")
        try:
            network_id = opaque(config["network_id"])
            identity = Identity.load(_absolute_path(Path(config["identity_path"])))
            trust = TrustStore(_absolute_path(Path(config["trust_store_path"])))
            public = trust.require_trusted(identity.key_id)
            roster_doc = _read(Path(config["roster_path"]), private=True)
            roster = verify_roster(roster_doc, trust, network_id=network_id, allow_expired=True)
            peers = {entry["signing_key"]["key_id"]: entry for entry in roster["members"]}
            reference = peers.get(self.config["reference_peer_key_id"])
            if reference is None or reference["status"] != "active" or not {"send", "receive"} <= set(reference["scope"]):
                raise TrialCoordinatorError("trial_reference_peer_not_authorized")
            return network_id, public
        except TrialCoordinatorError:
            raise
        except (MemoryError, OSError, TypeError, ValueError):
            raise TrialCoordinatorError("trial_authority_invalid") from None

    @contextlib.contextmanager
    def _transaction(self, *, initialize: bool = False) -> Iterator[sqlite3.Connection]:
        if not self._database_thread_lock.acquire(blocking=False):
            raise TrialCoordinatorError("trial_busy", retryable=True)
        try:
            with storage.file_lock(self.database_lock, busy_code="trial_busy"):
                storage.check_private_directory(self.directory)
                for suffix in ("", "-wal", "-shm", "-journal"):
                    path = Path(str(self.database) + suffix)
                    if path.exists() or path.is_symlink():
                        fd = storage.open_file(path, os.O_RDONLY, private=True)
                        os.close(fd)
                if not self.database.exists():
                    if not initialize:
                        raise TrialCoordinatorError("trial_state_missing")
                    fd = storage.open_file(self.database, os.O_RDWR | os.O_CREAT | os.O_EXCL, private=True)
                    os.close(fd)
                db = sqlite3.connect(self.database, timeout=0, isolation_level=None)
                db.row_factory = sqlite3.Row
                try:
                    db.execute("PRAGMA journal_mode=WAL")
                    db.execute("PRAGMA synchronous=FULL")
                    db.execute("PRAGMA trusted_schema=OFF")
                    db.execute("PRAGMA wal_autocheckpoint=32")
                    db.execute("PRAGMA max_page_count=2048")
                    if initialize:
                        db.executescript(_SCHEMA)
                    db.execute("BEGIN IMMEDIATE")
                    yield db
                    db.execute("COMMIT")
                except BaseException:
                    if db.in_transaction:
                        db.execute("ROLLBACK")
                    raise
                finally:
                    db.close()
        except storage.StorageError as exc:
            raise TrialCoordinatorError(exc.code, retryable=exc.retryable) from None
        except sqlite3.Error:
            raise TrialCoordinatorError("trial_storage_unavailable", retryable=True) from None
        finally:
            self._database_thread_lock.release()

    @staticmethod
    def _get(db: sqlite3.Connection, key: str) -> Any:
        row = db.execute("SELECT value FROM metadata WHERE key=?", (key,)).fetchone()
        return strict_json_loads(row[0]) if row else None

    @staticmethod
    def _set(db: sqlite3.Connection, key: str, value: Any) -> None:
        db.execute("INSERT OR REPLACE INTO metadata VALUES (?,?)", (key, canonical_bytes(value)))

    def _tag(self, code: str) -> str:
        return hmac.new(self._pepper, code.encode("ascii"), hashlib.sha256).hexdigest()

    def add_codes(self, values: Sequence[str]) -> Mapping[str, Any]:
        if (not isinstance(values, Sequence) or isinstance(values, (str, bytes))
                or not 1 <= len(values) <= self.limits["maximum_codes"]):
            raise TrialCoordinatorError("trial_run_codes_invalid")
        codes = [_run_code(value) for value in values]
        tags = [self._tag(value) for value in codes]
        if len(set(tags)) != len(tags):
            raise TrialCoordinatorError("trial_run_codes_duplicate")
        with self._transaction() as db:
            current = db.execute("SELECT COUNT(*) FROM run_codes").fetchone()[0]
            new = sum(1 for tag in tags if db.execute("SELECT 1 FROM run_codes WHERE code_tag=?", (tag,)).fetchone() is None)
            if current + new > self.limits["maximum_codes"]:
                raise TrialCoordinatorError("trial_code_capacity_full")
            for tag in tags:
                db.execute("INSERT OR IGNORE INTO run_codes(code_tag,state) VALUES (?,'ready')", (tag,))
        return {"state": "run_codes_added", "added": new, "total": current + new, "plaintext_codes_stored": False}

    def _consume_rate(self, source: str) -> None:
        if not isinstance(source, str):
            source = "unknown"
        source_tag = hashlib.sha256(source[:512].encode("utf-8", "replace")).hexdigest()
        window = int(time.time()) // self.limits["rate_window_seconds"]
        buckets = (
            ("global", self.limits["maximum_requests_per_global_window"]),
            ("source:" + source_tag, self.limits["maximum_requests_per_source_window"]),
        )
        with self._transaction() as db:
            db.execute("DELETE FROM attempts WHERE window<?", (window - 1,))
            if db.execute("SELECT COUNT(*) FROM attempts").fetchone()[0] > 1024:
                raise TrialCoordinatorError("trial_rate_state_full", retryable=True)
            for bucket, maximum in buckets:
                row = db.execute("SELECT count FROM attempts WHERE bucket=? AND window=?", (bucket, window)).fetchone()
                if row is not None and row["count"] >= maximum:
                    raise TrialCoordinatorError("trial_rate_limited", retryable=True)
            for bucket, _maximum in buckets:
                db.execute("INSERT INTO attempts VALUES (?,?,1) ON CONFLICT(bucket,window) DO UPDATE SET count=count+1",
                           (bucket, window))

    @staticmethod
    def _candidate(value: Any) -> dict[str, Any]:
        try:
            checked = member(value)
            return member({**checked, "status": "active", "scope": ["receive", "send"]})
        except MemoryError:
            raise TrialCoordinatorError("trial_candidate_public_identity_invalid") from None

    def enroll_bytes(self, data: bytes, *, source: str) -> Mapping[str, Any]:
        self._consume_rate(source)
        try:
            request = object_fields(document(data, maximum=self.limits["maximum_request_bytes"]), {"run_code", "candidate"})
        except MemoryError:
            raise TrialCoordinatorError("trial_enrollment_request_invalid") from None
        code = _run_code(request["run_code"])
        candidate = self._candidate(request["candidate"])
        return self.enroll(code=code, candidate=candidate)

    def _binding(self, candidate: Mapping[str, Any]) -> tuple[str, str, str]:
        return (document_sha256(candidate), candidate["signing_key"]["key_id"], candidate["encryption_key"]["key_id"])

    def _claim(self, tag: str, candidate: Mapping[str, Any]) -> tuple[str, Path, Mapping[str, Any] | None]:
        candidate_sha, signing_id, encryption_id = self._binding(candidate)
        with self._transaction() as db:
            row = db.execute("SELECT * FROM run_codes WHERE code_tag=?", (tag,)).fetchone()
            if row is None:
                raise TrialCoordinatorError("trial_run_code_invalid")
            if row["state"] != "ready":
                if (row["candidate_sha256"] != candidate_sha or row["signing_key_id"] != signing_id
                        or row["encryption_key_id"] != encryption_id):
                    raise TrialCoordinatorError("trial_run_code_already_used")
                if row["state"] == "completed":
                    return row["state"], Path(row["invitation_path"]), strict_json_loads(row["result"])
                return row["state"], Path(row["invitation_path"]), None
            reserved = db.execute("SELECT COUNT(*) FROM run_codes WHERE state!='ready'").fetchone()[0]
            if reserved >= self.limits["maximum_enrollments"]:
                raise TrialCoordinatorError("trial_capacity_full", retryable=True)
            output = self.invitation_directory / ("invitation-" + tag + ".json")
            db.execute("UPDATE run_codes SET state='claimed',candidate_sha256=?,signing_key_id=?,encryption_key_id=?,"
                       "invitation_path=?,claimed_at=? WHERE code_tag=? AND state='ready'",
                       (candidate_sha, signing_id, encryption_id, str(output), int(time.time()), tag))
            return "claimed", output, None

    def _result_from_invitation(self, candidate: Mapping[str, Any], output: Path) -> dict[str, Any]:
        package = _read(output, private=True, maximum=MAX_INVITATION_BYTES)
        authority = _read(self.authority_config, private=True, maximum=16 * 1024)
        identity = Identity.load(_absolute_path(Path(authority["identity_path"])))
        trust = TrustStore(_absolute_path(Path(authority["trust_store_path"])))
        trust.require_trusted(identity.key_id)
        if identity.public_descriptor() != self.issuer_public or opaque(authority["network_id"]) != self.network_id:
            raise TrialCoordinatorError("trial_authority_changed")
        invite = verify_invite(package["invite"], trust, network_id=self.network_id)
        invited_roster = verify_roster(package["roster"], trust, network_id=self.network_id, allow_expired=True)
        current_document = _read(Path(authority["roster_path"]), private=True)
        current = verify_roster(current_document, trust, network_id=self.network_id, allow_expired=True)
        expected = {**candidate, "status": "active", "scope": ["receive", "send"]}
        current_members = {item["signing_key"]["key_id"]: item for item in current["members"]}
        invited_members = {item["signing_key"]["key_id"]: item for item in invited_roster["members"]}
        reference = current_members.get(self.config["reference_peer_key_id"])
        if (invite["candidate_signing_key"] != expected["signing_key"]
                or invite["candidate_encryption_key"] != expected["encryption_key"]
                or invite["scope"] != expected["scope"]
                or invite["roster_sha256"] != document_sha256(package["roster"])
                or invited_roster["version"] > current["version"]
                or invited_members.get(expected["signing_key"]["key_id"]) != expected
                or current_members.get(expected["signing_key"]["key_id"]) != expected
                or reference is None or reference["status"] != "active"
                or not {"send", "receive"} <= set(reference["scope"])):
            raise TrialCoordinatorError("trial_invitation_recovery_invalid")
        issued_at, expires_at = invite["issued_at"], invite["expires_at"]
        service = {
            "schema_version": SERVICE_SCHEMA,
            "network_id": self.network_id,
            "authority_url": self.config["authority_url"],
            "relays": self.config["relays"],
            "issuer_public_key": self.issuer_public,
            "reference_peer_key_id": self.config["reference_peer_key_id"],
            "issued_at": issued_at,
            "expires_at": expires_at,
            "synthetic_only": True,
            "content_enforcement": "endpoint-only",
            "relay_plaintext_access": False,
            "execution_authority": False,
        }
        return {
            "schema_version": RESULT_SCHEMA,
            "state": "invited",
            "invitation": package,
            "service": service,
            "service_proof": identity.sign_message(service),
            "expires_at": expires_at,
        }

    def _complete(self, tag: str, candidate: Mapping[str, Any], output: Path,
                  result: Mapping[str, Any]) -> Mapping[str, Any]:
        candidate_sha, signing_id, encryption_id = self._binding(candidate)
        encoded = canonical_bytes(result)
        if len(encoded) > MAX_INVITATION_BYTES:
            raise TrialCoordinatorError("trial_result_too_large")
        with self._transaction() as db:
            row = db.execute("SELECT * FROM run_codes WHERE code_tag=?", (tag,)).fetchone()
            if (row is None or row["state"] not in {"claimed", "completed"}
                    or row["candidate_sha256"] != candidate_sha or row["signing_key_id"] != signing_id
                    or row["encryption_key_id"] != encryption_id or row["invitation_path"] != str(output)):
                raise TrialCoordinatorError("trial_claim_changed")
            if row["state"] == "completed":
                saved = strict_json_loads(row["result"])
                if canonical_bytes(saved) != encoded:
                    raise TrialCoordinatorError("trial_result_conflict")
                return saved
            db.execute("UPDATE run_codes SET state='completed',result=?,completed_at=? WHERE code_tag=? AND state='claimed'",
                       (encoded, int(time.time()), tag))
        return result

    def enroll(self, *, code: str, candidate: Mapping[str, Any]) -> Mapping[str, Any]:
        code, candidate = _run_code(code), self._candidate(candidate)
        tag = self._tag(code)
        if not self._operation_thread_lock.acquire(blocking=False):
            raise TrialCoordinatorError("trial_busy", retryable=True)
        try:
            try:
                operation = storage.file_lock(self.operation_lock, busy_code="trial_busy")
                with operation:
                    state, output, saved = self._claim(tag, candidate)
                    if saved is not None:
                        return saved
                    # A claimed row plus a durable output is the only crash
                    # recovery path.  Verify both the package and current
                    # operator roster before returning or completing it.
                    if not output.exists():
                        candidate_path = self.invitation_directory / ("candidate-" + tag + ".json")
                        if not candidate_path.exists():
                            storage.atomic_write(candidate_path, canonical_bytes(candidate) + b"\n", replace=False)
                        elif _read(candidate_path, private=True, maximum=16 * 1024) != candidate:
                            raise TrialCoordinatorError("trial_candidate_binding_changed")
                        invite_candidate(
                            authority_config=self.authority_config,
                            candidate=candidate_path,
                            output=output,
                            scope=("receive", "send"),
                            lifetime_seconds=self.limits["invitation_lifetime_seconds"],
                        )
                    result = self._result_from_invitation(candidate, output)
                    return self._complete(tag, candidate, output, result)
            except storage.StorageError as exc:
                raise TrialCoordinatorError(exc.code, retryable=exc.retryable) from None
        finally:
            self._operation_thread_lock.release()


def initialize_trial_coordinator(*, config: Path, authority_config: Path, state_directory: Path,
                                 authority_url: str, relays: Sequence[str], reference_peer_key_id: str,
                                 run_codes: Sequence[str], limits: Mapping[str, int] | None = None) -> Mapping[str, Any]:
    """Create private trial state and HMAC-store explicit operator run codes."""
    selected, authority, state = _absolute_path(config), _absolute_path(authority_config), _absolute_path(state_directory)
    codes = [_run_code(value) for value in run_codes]
    if not codes or len(set(codes)) != len(codes):
        raise TrialCoordinatorError("trial_run_codes_invalid")
    if os.path.lexists(selected) or os.path.lexists(state):
        raise TrialCoordinatorError("trial_configuration_exists")
    checked_limits = _limits({} if limits is None else limits)
    if len(codes) > checked_limits["maximum_codes"]:
        raise TrialCoordinatorError("trial_code_capacity_full")
    value = {
        "schema_version": CONFIG_SCHEMA,
        "authority_config_path": str(authority),
        "state_directory": str(state),
        "authority_url": origin(authority_url),
        "relays": [origin(item) for item in relays],
        "reference_peer_key_id": opaque(reference_peer_key_id),
        "limits": checked_limits,
    }
    if not 1 <= len(value["relays"]) <= 2 or len(set(value["relays"])) != len(value["relays"]):
        raise TrialCoordinatorError("trial_configuration_invalid")
    storage.private_directory(selected.parent)
    storage.private_directory(state.parent)
    state.mkdir(mode=0o700)
    storage.check_private_directory(state)
    _write_new_private(selected, canonical_bytes(value) + b"\n")
    coordinator = TrialCoordinator(selected, initialize=True)
    added = coordinator.add_codes(codes)
    return {"state": "trial_coordinator_initialized", "config": str(selected), **added,
            "run_codes_returned": False, "services_started": False}


def add_run_codes(config_path: Path, run_codes: Sequence[str]) -> Mapping[str, Any]:
    return TrialCoordinator(config_path).add_codes(run_codes)


def create_app(config_path: Path) -> Any:
    """Create, but do not start, the bounded enrollment ASGI application."""
    try:
        from starlette.applications import Starlette
        from starlette.concurrency import run_in_threadpool
        from starlette.responses import Response
        from starlette.routing import Route
    except ImportError:
        raise TrialCoordinatorError("trial_http_dependency_unavailable") from None
    coordinator = TrialCoordinator(config_path)
    gate = threading.BoundedSemaphore(coordinator.limits["maximum_concurrency"])

    def response(value: Mapping[str, Any], status: int = 200) -> Any:
        return Response(canonical_bytes(value), status_code=status, media_type="application/json",
                        headers={"Cache-Control": "no-store"})

    async def enroll(request: Any) -> Any:
        if not gate.acquire(blocking=False):
            return response({"error": {"code": "trial_busy", "retryable": True}}, 429)
        try:
            if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
                raise TrialCoordinatorError("trial_json_required")
            if request.headers.get("content-encoding", "identity").strip().lower() not in {"", "identity"}:
                raise TrialCoordinatorError("trial_content_encoding_rejected")

            async def read_body() -> bytes:
                data = bytearray()
                async for chunk in request.stream():
                    if len(data) + len(chunk) > coordinator.limits["maximum_request_bytes"]:
                        raise TrialCoordinatorError("trial_request_too_large")
                    data.extend(chunk)
                return bytes(data)

            try:
                body = await asyncio.wait_for(read_body(), timeout=coordinator.limits["body_timeout_seconds"])
            except asyncio.TimeoutError:
                raise TrialCoordinatorError("trial_request_timeout", retryable=True) from None
            source = request.client.host if request.client is not None else "unknown"
            result = await run_in_threadpool(coordinator.enroll_bytes, body, source=source)
            return response(result)
        except MemoryError as exc:
            code, retryable = exc.code, getattr(exc, "retryable", False)
            if code == "trial_request_too_large":
                status = 413
            elif code in {"trial_json_required", "trial_content_encoding_rejected"}:
                status = 415
            elif code == "trial_request_timeout":
                status = 408
            elif code == "trial_run_code_invalid":
                status = 403
            elif code == "trial_run_code_already_used":
                status = 409
            elif retryable or code in {"trial_busy", "trial_rate_limited", "trial_capacity_full", "trial_rate_state_full"}:
                status = 429
            else:
                status = 400
            return response({"error": {"code": code, "retryable": retryable}}, status)
        except Exception:
            return response({"error": {"code": "trial_coordinator_unavailable", "retryable": True}}, 503)
        finally:
            gate.release()

    app = Starlette(routes=[Route("/v1/trial/enroll", enroll, methods=["POST"])])
    app.state.coordinator = coordinator
    app.state.gate = gate
    return app


def _codes_file(path: Path) -> list[str]:
    raw = _read_private(_absolute_path(path), 64 * 1024)
    if raw is None:
        raise TrialCoordinatorError("trial_run_code_file_missing")
    values = document(raw, maximum=64 * 1024)
    if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
        raise TrialCoordinatorError("trial_run_codes_invalid")
    return values


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Bounded synthetic Memory Vault trial enrollment")
    commands = parser.add_subparsers(dest="action", required=True)
    init = commands.add_parser("init")
    init.add_argument("--config", type=Path, required=True)
    init.add_argument("--authority-config", type=Path, required=True)
    init.add_argument("--state-directory", type=Path, required=True)
    init.add_argument("--authority-url", required=True)
    init.add_argument("--relay", action="append", required=True)
    init.add_argument("--reference-peer-key-id", required=True)
    init.add_argument("--run-code-file", type=Path, required=True)
    add = commands.add_parser("add-codes")
    add.add_argument("--config", type=Path, required=True)
    add.add_argument("--run-code-file", type=Path, required=True)
    serve = commands.add_parser("serve")
    serve.add_argument("--config", type=Path, required=True)
    serve.add_argument("--port", type=int, default=8768)
    serve.add_argument("--tls-certfile", type=Path)
    serve.add_argument("--tls-keyfile", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.action == "init":
            result = initialize_trial_coordinator(
                config=args.config,
                authority_config=args.authority_config,
                state_directory=args.state_directory,
                authority_url=args.authority_url,
                relays=args.relay,
                reference_peer_key_id=args.reference_peer_key_id,
                run_codes=_codes_file(args.run_code_file),
            )
        elif args.action == "add-codes":
            result = add_run_codes(args.config, _codes_file(args.run_code_file))
        else:
            if not 1024 <= args.port <= 65535:
                raise TrialCoordinatorError("trial_nonprivileged_port_required")
            if (args.tls_certfile is None) != (args.tls_keyfile is None):
                raise TrialCoordinatorError("trial_tls_certificate_and_key_required")
            tls: dict[str, str] = {}
            if args.tls_certfile is not None:
                cert, key = _absolute_path(args.tls_certfile), _absolute_path(args.tls_keyfile)
                for path, private in ((cert, False), (key, True)):
                    fd = storage.open_file(path, os.O_RDONLY, private=private)
                    os.close(fd)
                try:
                    ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(cert, key)
                except (OSError, ssl.SSLError):
                    raise TrialCoordinatorError("trial_tls_configuration_invalid") from None
                tls = {"ssl_certfile": str(cert), "ssl_keyfile": str(key)}
            try:
                import uvicorn
            except ImportError:
                raise TrialCoordinatorError("trial_http_dependency_unavailable") from None
            uvicorn.run(create_app(args.config), host="127.0.0.1", port=args.port, access_log=False,
                        limit_concurrency=TrialCoordinator(args.config).limits["maximum_concurrency"],
                        timeout_keep_alive=5, proxy_headers=False, **tls)
            return 0
        sys.stdout.write(canonical_bytes(result).decode() + "\n")
        return 0
    except (MemoryError, storage.StorageError, OSError) as exc:
        code = getattr(exc, "code", "trial_unavailable")
        retryable = getattr(exc, "retryable", False)
        sys.stderr.write(canonical_bytes({"error": {"code": code, "retryable": retryable}}).decode() + "\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
