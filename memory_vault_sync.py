#!/usr/bin/env python3
"""Explicitly configured finite synchronization windows for the full client.

request_sync never performs network I/O or waits for a worker. No daemon,
launchd entry, cron job, credential discovery or automatic trust enrollment.
"""
from __future__ import annotations

import argparse
import contextlib
from dataclasses import dataclass
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import uuid
from typing import Any, Iterator, Mapping, Sequence

_SOURCE_DIRECTORY = str(Path(__file__).resolve().parent)
if _SOURCE_DIRECTORY not in sys.path:
    sys.path.insert(0, _SOURCE_DIRECTORY)

from memory_vault import MemoryError, canonical_bytes, failure, sha256, strict_json_loads, success, write_response
from memory_vault_remote import Budget, RcloneBackend, executable_sha256, peer_value, remote_path
from memory_vault_transfer import DirectoryTransfer, MAX_CAPSULE_BYTES, _path, _private_directory, _read, _write
from memory_vault_trust import TrustError

CONFIG_SCHEMA = "universal-memory-sync-config/v1"
STATE_SCHEMA = "universal-memory-sync-state/v1"
REQUEST_SCHEMA = "universal-memory-sync-trigger/v1"
REMOTE_STATE_SCHEMA = "universal-memory-remote-receipt/v1"
MAX_CONTROL_BYTES = 32 * 1024
MAX_EVENT_LOG_BYTES = 512 * 1024
REASONS = frozenset({"session-start", "memory-write", "turn-commit", "explicit"})
DEFAULT_LIMITS = {"maximum_batches": 4, "maximum_files": 16,
                  "maximum_bytes": 32 * 1024 * 1024, "maximum_seconds": 45,
                  "record_limit": 100, "batch_bytes": 256 * 1024}
_HEX = re.compile(r"[0-9a-f]{64}")
_GENERATION = re.compile(r"[0-9a-f]{32}")
_CODE = re.compile(r"[a-z][a-z0-9_]{1,63}")
_STATES = {"never_run", "running", "idle", "attention_required", "retry_pending", "cancelled"}
_COUNTERS = {"published_batches", "uploaded_batches", "received_batches", "records_added",
             "blocked_records", "rejected_batches", "receipt_replays", "peer_failures"}


def _object(value: Any, keys: set[str], code: str = "invalid_sync_configuration") -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise MemoryError(code)
    return dict(value)


def _absolute(value: Any) -> Path:
    if not isinstance(value, (str, Path)) or not str(value) or "\x00" in str(value):
        raise MemoryError("invalid_sync_path")
    selected = Path(value)
    if not selected.is_absolute() or ".." in selected.parts or len(selected.parts) < 3:
        raise MemoryError("absolute_sync_path_required")
    return _path(selected)


def _read_control(path: Path) -> dict[str, Any] | None:
    _path(path)
    if not path.exists():
        return None
    # No mkdir, trust loading, database access or network on this path.
    info = path.parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise MemoryError("unprotected_sync_control")
    return dict(_read(path, maximum=MAX_CONTROL_BYTES, private=True))


def _write_control(path: Path, value: Mapping[str, Any], *, replace: bool = True) -> None:
    if len(canonical_bytes(value)) + 1 > MAX_CONTROL_BYTES:
        raise MemoryError("sync_control_too_large")
    _private_directory(path.parent)
    _write(path, value, replace=replace)


@contextlib.contextmanager
def _lock(path: Path) -> Iterator[None]:
    _private_directory(path.parent)
    import fcntl

    fd = os.open(_path(path), os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
                 | getattr(os, "O_NONBLOCK", 0), 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_nlink != 1:
            raise MemoryError("unprotected_sync_lock")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise MemoryError("sync_busy", retryable=True) from None
        yield
    finally:
        os.close(fd)


def _bounded_int(value: Any, low: int, high: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        raise MemoryError("invalid_sync_limit")
    return value


@dataclass(frozen=True)
class SyncConfig:
    path: Path
    vault: Path
    identity: Path
    trust_store: Path
    state_directory: Path
    enabled: bool
    automatic: bool
    background: bool
    backend: Mapping[str, Any]
    limits: Mapping[str, int]

    @classmethod
    def load(cls, path: Path) -> SyncConfig:
        if os.name != "posix":
            raise MemoryError("unsupported_private_sync_storage")
        selected = _absolute(path)
        raw = _read_control(selected)
        if raw is None:
            raise MemoryError("sync_not_configured")
        return cls.from_document(selected, raw)

    @classmethod
    def from_document(cls, path: Path, value: Mapping[str, Any]) -> SyncConfig:
        if os.name != "posix":
            raise MemoryError("unsupported_private_sync_storage")
        raw = _object(value, {"schema_version", "vault", "identity", "trust_store", "state_directory",
                              "enabled", "automatic", "background", "backend", "limits"})
        if raw["schema_version"] != CONFIG_SCHEMA:
            raise MemoryError("unsupported_sync_schema")
        for key in ("enabled", "automatic", "background"):
            if not isinstance(raw[key], bool):
                raise MemoryError("invalid_sync_configuration")
        selected = _absolute(path)
        vault, identity, trust, state = (_absolute(raw[key]) for key in ("vault", "identity", "trust_store", "state_directory"))
        private_files = [selected, vault, identity, trust]
        if len(set(private_files)) != len(private_files):
            raise MemoryError("sync_path_conflict")
        if any(left in right.parents for left in private_files for right in private_files if left != right):
            raise MemoryError("sync_path_conflict")
        if any(state == item or state in item.parents or item in state.parents for item in private_files):
            raise MemoryError("sync_private_state_conflict")
        backend = raw["backend"]
        if not isinstance(backend, dict):
            raise MemoryError("invalid_sync_backend")
        if backend.get("kind") == "directory":
            backend = _object(backend, {"kind", "exchange"})
            exchange = _absolute(backend["exchange"])
            if any(exchange == item or exchange in item.parents or item in exchange.parents for item in [*private_files, state]):
                raise MemoryError("private_state_inside_exchange")
            backend["exchange"] = str(exchange)
        elif backend.get("kind") == "rclone":
            backend = _object(backend, {"kind", "executable", "executable_sha256", "config_file", "remote", "peers"})
            executable, config_file = _absolute(backend["executable"]), _absolute(backend["config_file"])
            if (config_file == executable
                    or any(item == other or item in other.parents or other in item.parents
                           for item in (config_file, executable) for other in [*private_files, state])):
                raise MemoryError("sync_path_conflict")
            if not isinstance(backend["executable_sha256"], str) or _HEX.fullmatch(backend["executable_sha256"]) is None:
                raise MemoryError("invalid_remote_executable_hash")
            backend["remote"] = remote_path(backend["remote"])
            if not isinstance(backend["peers"], list) or len(backend["peers"]) > 16:
                raise MemoryError("invalid_sync_peers")
            peers = [peer_value(value) for value in backend["peers"]]
            if len({(value["key_id"], value["store_id"]) for value in peers}) != len(peers):
                raise MemoryError("duplicate_sync_peer")
            backend.update(executable=str(executable), config_file=str(config_file), peers=peers)
        else:
            raise MemoryError("unsupported_sync_backend")
        limits = _object(raw["limits"], set(DEFAULT_LIMITS))
        for key, low, high in (("maximum_batches", 1, 16), ("maximum_files", 2, 64),
                               ("maximum_bytes", 8 * 1024 * 1024, 128 * 1024 * 1024),
                               ("maximum_seconds", 5, 60), ("record_limit", 1, 256),
                               ("batch_bytes", 4096, 1024 * 1024)):
            _bounded_int(limits[key], low, high)
        return cls(selected, vault, identity, trust, state, raw["enabled"], raw["automatic"], raw["background"], backend, limits)

    @property
    def binding(self) -> str:
        # Stream cursors belong to a storage destination, not to the current
        # peer roster or binary version. Those still invalidate a live window
        # below, but an explicit upgrade must not silently reset stream history.
        destination = ({"kind": "directory", "exchange": self.backend["exchange"]}
                       if self.backend["kind"] == "directory" else
                       {"kind": "rclone", "config_file": self.backend["config_file"], "remote": self.backend["remote"]})
        return sha256(canonical_bytes({"vault": str(self.vault), "identity": str(self.identity),
                                       "trust_store": str(self.trust_store), "state_directory": str(self.state_directory),
                                       "backend": destination}))

    def matches(self, vault: Path, identity: Path | None, trust: Path | None) -> None:
        if (identity is None or trust is None or self.vault != _absolute(vault)
                or self.identity != _absolute(identity) or self.trust_store != _absolute(trust)):
            raise MemoryError("sync_client_binding_mismatch")


def _new_state(config: SyncConfig) -> dict[str, Any]:
    return {"schema_version": STATE_SCHEMA, "binding": config.binding, "state": "never_run",
            "attempts": 0, "failures": 0, "started_at": 0, "finished_at": 0, "running_until": 0,
            "last_success_at": 0, "next_retry_at": 0, "last_error": None,
            "completed_generation": None, "counts": {key: 0 for key in sorted(_COUNTERS)}}


def _state(config: SyncConfig) -> dict[str, Any]:
    raw = _read_control(config.state_directory / "sync-state.json")
    if raw is None:
        return _new_state(config)
    _object(raw, set(_new_state(config)), "invalid_sync_state")
    if raw["schema_version"] != STATE_SCHEMA or raw["binding"] != config.binding:
        raise MemoryError("sync_state_binding_changed")
    if not isinstance(raw["state"], str) or raw["state"] not in _STATES:
        raise MemoryError("invalid_sync_state")
    for key in ("attempts", "failures", "started_at", "finished_at", "running_until", "last_success_at", "next_retry_at"):
        _bounded_int(raw[key], 0, 2**63 - 1)
    if raw["last_error"] is not None and (not isinstance(raw["last_error"], str) or _CODE.fullmatch(raw["last_error"]) is None):
        raise MemoryError("invalid_sync_state")
    if raw["completed_generation"] is not None and (not isinstance(raw["completed_generation"], str) or _GENERATION.fullmatch(raw["completed_generation"]) is None):
        raise MemoryError("invalid_sync_state")
    _object(raw["counts"], _COUNTERS, "invalid_sync_state")
    for value in raw["counts"].values():
        _bounded_int(value, 0, 2**63 - 1)
    return raw


def _trigger(config: SyncConfig) -> dict[str, Any] | None:
    raw = _read_control(config.state_directory / "sync-trigger.json")
    if raw is None:
        return None
    _object(raw, {"schema_version", "binding", "generation", "reason", "requested_at"}, "invalid_sync_trigger")
    if (raw["schema_version"] != REQUEST_SCHEMA or raw["binding"] != config.binding
            or not isinstance(raw["generation"], str) or _GENERATION.fullmatch(raw["generation"]) is None
            or not isinstance(raw["reason"], str) or raw["reason"] not in REASONS):
        raise MemoryError("invalid_sync_trigger")
    _bounded_int(raw["requested_at"], 0, 2**63 - 1)
    return raw


def status(config_path: Path) -> Mapping[str, Any]:
    """Read-only metadata; does not initialize a directory, Vault, key or worker."""
    config = SyncConfig.load(config_path)
    state = _state(config)
    trigger = _trigger(config)
    pending = trigger is not None and trigger["generation"] != state["completed_generation"]
    lease_active = state["state"] == "running" and state["running_until"] > int(time.time())
    return {"state": "interrupted_retry_pending" if state["state"] == "running" and not lease_active else state["state"],
            "enabled": config.enabled, "automatic": config.automatic, "background": config.background,
            "backend": config.backend["kind"], "pending": pending, "worker_lease_active": lease_active,
            "attempts": state["attempts"], "failures": state["failures"], "next_retry_at": state["next_retry_at"],
            "last_error": state["last_error"], "last_success_at": state["last_success_at"],
            "counts": dict(state["counts"]), "memory_content_included": False,
            "remote_ai_read_verified": False, "network_accessed": False}


def _enqueue(config: SyncConfig, reason: str) -> None:
    with _lock(config.state_directory / "trigger.lock"):
        _state(config)  # Refuse stale state tied to a different Vault/destination.
        _write_control(config.state_directory / "sync-trigger.json", {
            "schema_version": REQUEST_SCHEMA, "binding": config.binding,
            "generation": uuid.uuid4().hex, "reason": reason, "requested_at": int(time.time()),
        })


def _spawn(config: SyncConfig) -> str:
    # Startup reservation coalesces notifications before a child obtains its
    # work lock. The durable trigger survives failed/abandoned reservations.
    with _lock(config.state_directory / "launch.lock"):
        try:
            with _lock(config.state_directory / "worker.lock"):
                pass
        except MemoryError as exc:
            if exc.code == "sync_busy":
                return "coalesced"
            raise
        state = _state(config)
        if state["next_retry_at"] > int(time.time()):
            return "backoff_pending"
        reservation_path = config.state_directory / "launch.json"
        reservation = _read_control(reservation_path)
        if reservation is not None:
            _object(reservation, {"expires_at"}, "invalid_sync_launch_state")
            if _bounded_int(reservation["expires_at"], 0, 2**63 - 1) > int(time.time()):
                return "coalesced"
        _write_control(reservation_path, {"expires_at": int(time.time()) + 5})
        log_path = _path(config.state_directory / "worker-events.ndjson")
        fd = os.open(log_path, os.O_CREAT | os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
                     | getattr(os, "O_NONBLOCK", 0), 0o600)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_mode & 0o077 or info.st_nlink != 1):
                raise MemoryError("unprotected_sync_event_log")
            if info.st_size >= MAX_EVENT_LOG_BYTES:
                raise MemoryError("sync_event_log_review_required")
            command = [sys.executable, "-I", str(Path(__file__).resolve()), "--config", str(config.path), "run", "--background-worker"]
            subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=fd, stderr=fd,
                             close_fds=True, start_new_session=True, shell=False)
        finally:
            os.close(fd)
        return "worker_started"


def request_sync(
    config_path: Path, *, expected_vault: Path, expected_identity: Path | None,
    expected_trust: Path | None, reason: str,
) -> Mapping[str, Any]:
    """Notify after a durable local write. Always return without remote work."""
    try:
        if not isinstance(reason, str) or reason not in REASONS:
            raise MemoryError("invalid_sync_reason")
        config = SyncConfig.load(config_path)
        config.matches(expected_vault, expected_identity, expected_trust)
        if not config.enabled or (reason != "explicit" and not config.automatic):
            return {"state": "disabled", "network_accessed": False, "local_memory_unchanged": True}
        _enqueue(config, reason)
        state = _spawn(config) if config.automatic and config.background else "queued"
        return {"state": state, "network_accessed": False, "local_memory_unchanged": True,
                "remote_ai_read_verified": False}
    except (MemoryError, TrustError, OSError, ValueError, TypeError) as exc:
        return {"state": "sync_unavailable", "error_code": _error_code(exc),
                "network_accessed": False, "local_memory_unchanged": True}


def _error_code(exc: BaseException) -> str:
    code = getattr(exc, "code", "sync_storage_unavailable")
    return code if isinstance(code, str) and _CODE.fullmatch(code) else "sync_unavailable"


def _publication_guard(records: Sequence[Mapping[str, Any]]) -> None:
    try:
        from memory_vault_privacy import assert_publishable
    except ImportError:
        raise MemoryError("publication_policy_unavailable") from None
    assert_publishable(records)


def _remote_receipt(config: SyncConfig) -> dict[str, Any]:
    raw = _read_control(config.state_directory / "remote-receipt.json")
    if raw is None:
        return {"schema_version": REMOTE_STATE_SCHEMA, "binding": config.binding,
                "key_id": None, "store_id": None, "sent_cursor": 0}
    _object(raw, {"schema_version", "binding", "key_id", "store_id", "sent_cursor"}, "invalid_remote_receipt")
    if raw["schema_version"] != REMOTE_STATE_SCHEMA or raw["binding"] != config.binding:
        raise MemoryError("remote_receipt_binding_changed")
    if raw["key_id"] is not None or raw["store_id"] is not None:
        peer_value({"key_id": raw["key_id"], "store_id": raw["store_id"]})
    _bounded_int(raw["sent_cursor"], 0, 2**63 - 1)
    if raw["sent_cursor"] and raw["key_id"] is None:
        raise MemoryError("invalid_remote_receipt")
    return raw


def _push_pending(config: SyncConfig, endpoint: DirectoryTransfer, remote: RcloneBackend) -> bool:
    state = endpoint._state()
    receipt = _remote_receipt(config)
    if state["published_cursor"] == receipt["sent_cursor"]:
        return False
    if state["published_cursor"] < receipt["sent_cursor"] or endpoint.identity is None:
        raise MemoryError("remote_send_cursor_changed")
    endpoint._bind_vault(state, missing_ok=False)
    key, store = endpoint.identity.key_id, state["vault_store_id"]
    peer_value({"key_id": key, "store_id": store})
    if state["publisher_key_id"] != key or receipt["key_id"] not in {None, key} or receipt["store_id"] not in {None, store}:
        raise MemoryError("remote_publisher_changed")
    name = f"{receipt['sent_cursor']:020d}-{state['published_cursor']:020d}-{state['last_published']}.json"
    source = endpoint.exchange / key / store / name
    capsule = _read(source, private=True)
    payload, digest = endpoint._verify_capsule(capsule)
    if (payload["after"] != receipt["sent_cursor"] or payload["cursor"] != state["published_cursor"]
            or payload["sender_key_id"] != key or payload["source_store_id"] != store
            or digest != state["last_published"]):
        raise MemoryError("remote_pending_source_changed")
    _publication_guard(payload["records"])
    # Refuse to create a new authenticated fork after control-state loss or a
    # second publisher configuration. This is a bounded preflight, not a remote
    # compare-and-swap: operators must still use one publisher state per stream.
    for candidate, size in remote.candidates(key, store, payload["after"]):
        if candidate == name:
            continue  # upload() independently verifies exact existing bytes.
        raw = remote.download(key, store, payload["after"], candidate, size)
        try:
            competing = strict_json_loads(raw)
            if not isinstance(competing, Mapping):
                raise MemoryError("invalid_transfer_envelope")
            other, other_digest = endpoint._verify_capsule(competing)
            other_name = f"{other['after']:020d}-{other['cursor']:020d}-{other_digest}.json"
            conflict = (other["sender_key_id"] == key and other["source_store_id"] == store
                        and other["after"] == payload["after"] and candidate == other_name
                        and other_digest != digest)
        except (MemoryError, TrustError):
            continue  # Unauthenticated text cannot choose a sending cursor.
        if conflict:
            raise MemoryError("authenticated_stream_fork")
    remote.upload(source, key_id=key, store_id=store, after=payload["after"], name=name,
                  expected=canonical_bytes(capsule) + b"\n")
    receipt.update(key_id=key, store_id=store, sent_cursor=payload["cursor"])
    _write_control(config.state_directory / "remote-receipt.json", receipt)
    return True


def _pull_peer(endpoint: DirectoryTransfer, remote: RcloneBackend, peer: Mapping[str, str]) -> Mapping[str, Any] | None:
    key, store = peer["key_id"], peer["store_id"]
    endpoint.trust.require_trusted(key)  # Before even listing the remote prefix.
    after = int(endpoint._state()["received"].get(key + "/" + store, 0))
    candidates = remote.candidates(key, store, after)
    authenticated: dict[str, Mapping[str, Any]] = {}
    rejected = 0
    for name, size in candidates:
        try:
            raw = remote.download(key, store, after, name, size)
            capsule = strict_json_loads(raw)
            if not isinstance(capsule, dict):
                raise MemoryError("invalid_transfer_envelope")
            payload, digest = endpoint._verify_capsule(capsule)
            expected_name = f"{after:020d}-{payload['cursor']:020d}-{digest}.json"
            if payload["after"] != after or payload["sender_key_id"] != key or payload["source_store_id"] != store or name != expected_name:
                raise MemoryError("transfer_envelope_mismatch")
            authenticated[digest] = capsule
        except (MemoryError, TrustError) as exc:
            if getattr(exc, "code", "").startswith(("sync_", "remote_timeout", "remote_command")):
                raise
            rejected += 1
    if len(authenticated) > 1:
        raise MemoryError("authenticated_stream_fork")
    if not authenticated:
        if rejected:
            raise MemoryError("remote_prefix_not_verified")
        return None
    result = dict(endpoint.receive_capsule(next(iter(authenticated.values())), sender_key_id=key,
                                           source_store_id=store, after=after))
    result["rejected_candidates"] = rejected
    return result


def _window(config: SyncConfig, *, background_worker: bool, counts: dict[str, int]) -> bool:
    budget = Budget(seconds=config.limits["maximum_seconds"], maximum_bytes=config.limits["maximum_bytes"],
                    maximum_files=config.limits["maximum_files"])

    def active() -> None:
        budget.remaining()
        current = SyncConfig.load(config.path)
        if not current.enabled or (background_worker and (not current.automatic or not current.background)):
            raise MemoryError("sync_cancelled")
        if (current.binding != config.binding or current.backend != config.backend
                or current.limits != config.limits):
            raise MemoryError("sync_configuration_changed")

    active()
    exchange = Path(config.backend["exchange"]) if config.backend["kind"] == "directory" else config.state_directory / "exchange"
    _private_directory(config.state_directory / "transfer")
    endpoint = DirectoryTransfer(vault=config.vault, exchange=exchange, state_directory=config.state_directory / "transfer",
                                 trust_store=config.trust_store, identity=config.identity)
    maximum = config.limits["maximum_batches"]
    remote: RcloneBackend | None = None
    if config.backend["kind"] == "rclone":
        _private_directory(exchange)
        work = config.state_directory / "rclone"
        _private_directory(work)
        _private_directory(work / "cache")
        _private_directory(work / "tmp")
        remote = RcloneBackend(config.backend, work_directory=work, budget=budget, active_check=active)

    def publication_guard(records: Sequence[Mapping[str, Any]]) -> None:
        active()
        _publication_guard(records)
        if remote is None:
            # Reserve the full supported capsule ceiling, including signature
            # and closure overhead; never guess a smaller size from record text.
            budget.transfer(MAX_CAPSULE_BYTES)

    # Publish local durable work before spending the remaining window on peers.
    # A malformed/offline peer cannot monopolize every attempt to send local
    # memory. An empty receiving Vault is permitted to bootstrap below.
    more = False
    for index in range(maximum):
        active()
        try:
            if remote is not None and _push_pending(config, endpoint, remote):
                counts["uploaded_batches"] += 1
            result = endpoint.publish(limit=config.limits["record_limit"], maximum_bytes=config.limits["batch_bytes"],
                                      publication_guard=publication_guard)
        except MemoryError as exc:
            if exc.code == "not_initialized" and endpoint._state()["vault_store_id"] is None:
                break
            raise
        if result["state"] == "up_to_date":
            break
        counts["published_batches"] += 1
        counts["blocked_records"] += len(result.get("blocked", []))
        if remote is not None and _push_pending(config, endpoint, remote):
            counts["uploaded_batches"] += 1
        more = index == maximum - 1

    peer_error: str | None = None
    if remote is not None:
        received = 0
        for peer in config.backend["peers"]:
            for _ in range(maximum - received):
                active()
                try:
                    result = _pull_peer(endpoint, remote, peer)
                except (MemoryError, TrustError) as exc:
                    code = _error_code(exc)
                    if code.startswith("sync_"):
                        raise  # Shared time/byte/cancellation bounds still win.
                    counts["peer_failures"] += 1
                    peer_error = peer_error or code
                    break  # Other explicitly configured peers remain eligible.
                if result is None:
                    break
                received += 1
                counts["received_batches"] += 1
                counts["records_added"] += result["records_added"]
                counts["receipt_replays"] += int(result["receipt_replayed"])
                counts["blocked_records"] += result["blocked_records"]
                counts["rejected_batches"] += result["rejected_candidates"]
            if received >= maximum:
                break
    elif exchange.is_dir():
        result = endpoint.receive(maximum_batches=maximum, active_check=active,
                                  before_read=lambda: budget.transfer(MAX_CAPSULE_BYTES), skip_local_stream=True)
        counts["received_batches"] += int(result["batches"])
        counts["records_added"] += int(result["records_added"])
        counts["blocked_records"] += int(result["sender_blocked_records"])
        counts["rejected_batches"] += len(result["rejected"]) + int(result["gaps"]) + int(result["unknown_senders"])
        counts["receipt_replays"] += int(result["receipt_replays"])
        more = more or bool(result.get("more_possible", False))
    if peer_error is not None:
        raise MemoryError(peer_error, retryable=True)
    # Newly received records may need forwarding in a later window. Do not
    # mark that generation exhausted merely because the outbound pass ran first.
    # Admission upgrades of existing records can create outbound changes even
    # when records_added is zero, so every received batch keeps a later pass due.
    return more or counts["received_batches"] > 0


def run(config_path: Path, *, background_worker: bool = False) -> Mapping[str, Any]:
    config = SyncConfig.load(config_path)
    if not config.enabled or (background_worker and (not config.automatic or not config.background)):
        return {"state": "disabled", "network_accessed": False}
    _private_directory(config.state_directory)
    with _lock(config.state_directory / "worker.lock"):
        state = _state(config)
        if background_worker and state["next_retry_at"] > int(time.time()):
            return {"state": "backoff_pending", "network_accessed": False}
        if not background_worker or _trigger(config) is None:
            _enqueue(config, "explicit")
        trigger = _trigger(config)
        assert trigger is not None
        state.update(state="running", attempts=state["attempts"] + 1, started_at=int(time.time()),
                     running_until=int(time.time()) + config.limits["maximum_seconds"] + 30,
                     last_error=None, counts={key: 0 for key in sorted(_COUNTERS)})
        _write_control(config.state_directory / "sync-state.json", state)
        more = False
        try:
            more = _window(config, background_worker=background_worker, counts=state["counts"])
            state.update(state="attention_required" if state["counts"]["blocked_records"] or state["counts"]["rejected_batches"] else "idle",
                         failures=0, next_retry_at=0, last_success_at=int(time.time()))
            if not more:
                state["completed_generation"] = trigger["generation"]
        except (MemoryError, TrustError, OSError, ValueError, TypeError) as exc:
            code = _error_code(exc)
            failures = state["failures"] + 1
            state.update(state="cancelled" if code == "sync_cancelled" else "retry_pending", failures=failures,
                         last_error=code, next_retry_at=int(time.time()) + min(300, 5 * 2**min(failures - 1, 6)))
        finally:
            state.update(finished_at=int(time.time()), running_until=0)
            _write_control(config.state_directory / "sync-state.json", state)
        latest = _trigger(config)
        pending = latest is not None and latest["generation"] != state["completed_generation"]
        return {"state": state["state"], "last_error": state["last_error"], "counts": dict(state["counts"]),
                "more_work_possible": more, "pending": pending, "remote_ai_read_verified": False,
                "memory_content_included": False, "network_backend": config.backend["kind"] == "rclone"}


def _configure(args: argparse.Namespace) -> Mapping[str, Any]:
    if os.name != "posix":
        raise MemoryError("unsupported_private_sync_storage")
    selected = _absolute(args.config)
    if args.backend == "directory":
        if args.exchange is None or any((args.rclone_executable, args.rclone_config, args.remote, args.peer)):
            raise MemoryError("invalid_sync_backend_arguments")
        backend: dict[str, Any] = {"kind": "directory", "exchange": str(_absolute(args.exchange))}
    else:
        if args.exchange is not None or not all((args.rclone_executable, args.rclone_config, args.remote)):
            raise MemoryError("invalid_sync_backend_arguments")
        peers = []
        for value in args.peer:
            parts = value.split("/")
            if len(parts) != 2:
                raise MemoryError("invalid_sync_peer")
            peers.append(peer_value({"key_id": parts[0], "store_id": parts[1]}))
        executable = _absolute(args.rclone_executable)
        backend = {"kind": "rclone", "executable": str(executable), "executable_sha256": executable_sha256(executable),
                   "config_file": str(_absolute(args.rclone_config)), "remote": remote_path(args.remote), "peers": peers}
    document = {"schema_version": CONFIG_SCHEMA, "vault": str(_absolute(args.vault)),
                "identity": str(_absolute(args.identity)), "trust_store": str(_absolute(args.trust_store)),
                "state_directory": str(_absolute(args.state_directory)), "enabled": not args.disabled,
                "automatic": args.automatic, "background": args.background, "backend": backend,
                "limits": {**DEFAULT_LIMITS, "maximum_seconds": args.maximum_seconds}}
    config = SyncConfig.from_document(selected, document)
    if selected.exists():
        if not args.replace:
            raise MemoryError("sync_configuration_exists")
        old = SyncConfig.load(selected)
        if old.binding != config.binding and old.state_directory == config.state_directory:
            raise MemoryError("new_sync_state_directory_required")
    _write_control(selected, document, replace=args.replace)
    return {"state": "configured", "backend": config.backend["kind"], "automatic": config.automatic,
            "background": config.background, "enabled": config.enabled, "network_accessed": False,
            "credentials_created": False, "keys_enrolled": False, "worker_started": False}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    configure = commands.add_parser("configure", help="explicit private configuration; no network or installation")
    for name in ("vault", "identity", "trust-store", "state-directory"):
        configure.add_argument("--" + name, type=Path, required=True)
    configure.add_argument("--backend", choices=("directory", "rclone"), required=True)
    configure.add_argument("--exchange", type=Path)
    configure.add_argument("--rclone-executable", type=Path)
    configure.add_argument("--rclone-config", type=Path)
    configure.add_argument("--remote")
    configure.add_argument("--peer", action="append", default=[])
    configure.add_argument("--automatic", action="store_true")
    configure.add_argument("--background", action="store_true")
    configure.add_argument("--disabled", action="store_true")
    configure.add_argument("--replace", action="store_true")
    configure.add_argument("--maximum-seconds", type=int, default=DEFAULT_LIMITS["maximum_seconds"])
    worker = commands.add_parser("run", help="one explicitly requested bounded synchronization window")
    worker.add_argument("--background-worker", action="store_true", help=argparse.SUPPRESS)
    commands.add_parser("status", help="read-only content-free state; never start synchronization")
    args = parser.parse_args(argv)
    try:
        if args.command == "configure":
            result = _configure(args)
        elif args.command == "status":
            result = status(args.config)
        else:
            result = run(args.config, background_worker=args.background_worker)
        write_response(success(result))
        return 0 if result.get("state") not in {"retry_pending", "cancelled"} else 1
    except (MemoryError, TrustError, OSError, ValueError, TypeError) as exc:
        write_response(failure(_error_code(exc), retryable=bool(getattr(exc, "retryable", False))))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
