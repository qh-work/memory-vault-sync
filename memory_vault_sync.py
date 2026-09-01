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
from typing import Any, Callable, Iterator, Mapping, Sequence

_SOURCE_DIRECTORY = str(Path(__file__).resolve().parent)
if _SOURCE_DIRECTORY not in sys.path:
    sys.path.insert(0, _SOURCE_DIRECTORY)

from memory_vault import MemoryError, canonical_bytes, failure, sha256, strict_json_loads, success, write_response
from memory_vault_credentials import MAX_REFERENCE_BYTES, password_reference
from memory_vault_remote import Budget, NativeDriveBackend, RcloneBackend, executable_sha256, native_drive_specification, peer_value, remote_path
from memory_vault_transfer import DirectoryTransfer, MAX_CAPSULE_BYTES, MAX_REVIEW_DOCUMENT, _fragment_name, _path, _private_directory, _read, _read_fragment, _write
from memory_vault_trust import TrustError
import memory_vault_storage as protected_storage

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
    if os.name == "nt":
        protected_storage.check_private_directory(path.parent)
    else:
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
    if os.name == "nt":
        try:
            with protected_storage.file_lock(path, busy_code="sync_busy"):
                yield
            return
        except protected_storage.StorageError as exc:
            raise MemoryError(exc.code, retryable=exc.retryable) from None
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
        if os.name not in {"posix", "nt"}:
            raise MemoryError("unsupported_private_sync_storage")
        protected_storage.require_supported_storage()
        selected = _absolute(path)
        raw = _read_control(selected)
        if raw is None:
            raise MemoryError("sync_not_configured")
        return cls.from_document(selected, raw)

    @classmethod
    def from_document(cls, path: Path, value: Mapping[str, Any]) -> SyncConfig:
        if os.name not in {"posix", "nt"}:
            raise MemoryError("unsupported_private_sync_storage")
        protected_storage.require_supported_storage()
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
            keys = {"kind", "executable", "executable_sha256", "config_file", "remote", "peers"}
            if "config_password_ref" in backend:
                keys.add("config_password_ref")
            backend = _object(backend, keys)
            if "config_password_ref" in backend:
                backend["config_password_ref"] = password_reference(backend["config_password_ref"])
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
        elif backend.get("kind") == "native-drive":
            backend = native_drive_specification(backend)
            config_file, encryption_key = (_absolute(backend[key]) for key in ("config_file", "encryption_key_path"))
            if (config_file == encryption_key
                    or config_file in encryption_key.parents or encryption_key in config_file.parents
                    or any(item == other or item in other.parents or other in item.parents
                           for item in (config_file, encryption_key) for other in [*private_files, state])):
                raise MemoryError("sync_path_conflict")
            backend.update(config_file=str(config_file), encryption_key_path=str(encryption_key))
        else:
            raise MemoryError("unsupported_sync_backend")
        limits = _object(raw["limits"], set(DEFAULT_LIMITS))
        for key, low, high in (("maximum_batches", 1, 16), ("maximum_files", 2, 64),
                               ("maximum_bytes", 8 * 1024 * 1024, 128 * 1024 * 1024),
                               ("maximum_seconds", 5, 60), ("record_limit", 1, 256),
                               ("batch_bytes", 4096, 3 * 1024 * 1024)):
            _bounded_int(limits[key], low, high)
        if backend["kind"] == "native-drive" and (limits["maximum_files"] < 8 or limits["maximum_bytes"] < 24 * 1024 * 1024):
            # One maximal original may require two ciphertext chunks, a commit
            # and exact read-backs. Keep the general/rclone limits unchanged.
            raise MemoryError("native_drive_window_too_small")
        return cls(selected, vault, identity, trust, state, raw["enabled"], raw["automatic"], raw["background"], backend, limits)

    @property
    def binding(self) -> str:
        # Stream cursors belong to a storage destination, not to the current
        # peer roster or binary version. Those still invalidate a live window
        # below, but an explicit upgrade must not silently reset stream history.
        if self.backend["kind"] == "directory":
            destination = {"kind": "directory", "exchange": self.backend["exchange"]}
        elif self.backend["kind"] == "rclone":
            destination = {"kind": "rclone", "config_file": self.backend["config_file"], "remote": self.backend["remote"]}
        else:
            destination = {key: self.backend[key] for key in ("kind", "config_file", "root_folder_id", "encryption_key_path")}
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
        fd = (protected_storage.open_file(log_path, os.O_CREAT | os.O_WRONLY | os.O_APPEND, private=True) if os.name == "nt" else
              os.open(log_path, os.O_CREAT | os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
                      | getattr(os, "O_NONBLOCK", 0), 0o600))
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or (os.name != "nt" and (info.st_uid != os.getuid() or info.st_mode & 0o077))):
                raise MemoryError("unprotected_sync_event_log")
            if info.st_size >= MAX_EVENT_LOG_BYTES:
                raise MemoryError("sync_event_log_review_required")
            # Managed runtimes have an exact source inventory. A finite worker
            # must not introduce unlisted bytecode into that immutable tree.
            command = [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--config", str(config.path), "run", "--background-worker"]
            subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=fd, stderr=fd,
                             close_fds=True, start_new_session=os.name != "nt", shell=False)
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


def _publication_guard(
    records: Sequence[Mapping[str, Any]], *, endpoint: DirectoryTransfer | None = None,
    payload: Mapping[str, Any] | None = None,
) -> None:
    try:
        from memory_vault_privacy import assert_publishable
    except ImportError:
        raise MemoryError("publication_policy_unavailable") from None
    approved = endpoint.local_path_approvals(payload) if endpoint is not None and payload is not None else set()
    assert_publishable(records, approved_local_path_ids=approved)


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


def _push_pending(config: SyncConfig, endpoint: DirectoryTransfer, remote: RcloneBackend | NativeDriveBackend) -> bool:
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
    endpoint.validate_outgoing_payload(payload)
    _publication_guard(endpoint.records_for_payload(payload)[0], endpoint=endpoint, payload=payload)
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
    if payload.get("group") is not None:
        group = payload["group"]
        receipts = config.state_directory / "remote-group-receipts" / group["group_id"]
        # Create the private root explicitly: mkdir(parents=True) applies its
        # requested mode only to the final directory, not missing ancestors.
        _private_directory(config.state_directory)
        _private_directory(receipts.parent)
        _private_directory(receipts)
        transferred = 0
        for fragment in group["fragments"]:
            receipt_path = receipts / (str(fragment["index"]) + ".json")
            expected_receipt = {"binding": config.binding, "group_id": group["group_id"],
                                "index": fragment["index"], "sha256": fragment["sha256"], "bytes": fragment["bytes"]}
            if receipt_path.exists():
                if _read(receipt_path, private=True) != expected_receipt:
                    raise MemoryError("remote_group_receipt_conflict")
                continue
            if transferred >= 8:
                raise MemoryError("remote_group_pending", retryable=True)
            fragment_path = endpoint.exchange / key / store / "groups" / group["group_id"] / _fragment_name(fragment)
            expected_fragment = _read_fragment(fragment_path, maximum=fragment["bytes"])
            remote.upload_fragment(fragment_path, key_id=key, store_id=store, group=group,
                                   fragment=fragment, expected=expected_fragment)
            _write(receipt_path, expected_receipt, replace=False)
            transferred += 1
    remote.upload(source, key_id=key, store_id=store, after=payload["after"], name=name,
                  expected=canonical_bytes(capsule) + b"\n")
    receipt.update(key_id=key, store_id=store, sent_cursor=payload["cursor"])
    _write_control(config.state_directory / "remote-receipt.json", receipt)
    return True


def _pull_peer(
    endpoint: DirectoryTransfer, remote: RcloneBackend | NativeDriveBackend, peer: Mapping[str, str], *,
    active_check: Callable[[], None] | None = None,
    on_progress: Callable[[Mapping[str, Any]], None] | None = None,
) -> Mapping[str, Any] | None:
    key, store = peer["key_id"], peer["store_id"]
    endpoint.trust.require_trusted(key)  # Before even listing the remote prefix.
    state = endpoint._state()
    after = int(state["received"].get(key + "/" + store, 0))
    head = state["received_heads"].get(key + "/" + store)
    if head is not None:
        observed: set[str] = set()
        for name, size in remote.candidates(key, store, head["after"]):
            raw = remote.download(key, store, head["after"], name, size)
            try:
                historical = strict_json_loads(raw)
                if not isinstance(historical, dict):
                    continue
                old, old_digest = endpoint._verify_capsule(historical, verify_records=False)
                expected_name = f"{head['after']:020d}-{old['cursor']:020d}-{old_digest}.json"
                if old["sender_key_id"] == key and old["source_store_id"] == store and old["after"] == head["after"] and name == expected_name:
                    observed.add(old_digest)
            except (MemoryError, TrustError):
                continue
        if observed != {head["batch_sha256"]}:
            raise MemoryError("authenticated_stream_fork" if len(observed) > 1 else "remote_history_missing_or_changed")
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
    def progress(result: Mapping[str, Any]) -> None:
        if on_progress is not None:
            on_progress({**result, "rejected_candidates": rejected})

    result = dict(endpoint.receive_capsule(next(iter(authenticated.values())), sender_key_id=key,
                                           source_store_id=store, after=after,
                                           fragment_loader=lambda group, fragment: remote.download_fragment(key, store, group, fragment),
                                           active_check=active_check, on_progress=progress))
    result["rejected_candidates"] = rejected
    return result


def _window(
    config: SyncConfig, *, background_worker: bool, counts: dict[str, int],
    direction: str = "both", maximum_seconds: int | None = None,
) -> bool:
    seconds = config.limits["maximum_seconds"] if maximum_seconds is None else min(maximum_seconds, config.limits["maximum_seconds"])
    budget = Budget(seconds=seconds, maximum_bytes=config.limits["maximum_bytes"],
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
                                 trust_store=config.trust_store, identity=None if direction == "receive" else config.identity)
    maximum = config.limits["maximum_batches"]
    remote: RcloneBackend | NativeDriveBackend | None = None
    if config.backend["kind"] == "rclone":
        _private_directory(exchange)
        work = config.state_directory / "rclone"
        _private_directory(work)
        _private_directory(work / "cache")
        _private_directory(work / "tmp")
        remote = RcloneBackend(config.backend, work_directory=work, budget=budget, active_check=active)
    elif config.backend["kind"] == "native-drive":
        _private_directory(exchange)
        remote = NativeDriveBackend(config.backend, work_directory=config.state_directory / "native-drive",
                                    budget=budget, active_check=active)

    def publication_guard(payload: Mapping[str, Any]) -> None:
        active()
        _publication_guard(endpoint.records_for_payload(payload)[0], endpoint=endpoint, payload=payload)
        if config.backend["kind"] == "native-drive":
            # The generic shared-directory publisher may create intermediate
            # POSIX parents with the process umask. A private cloud staging tree
            # must instead protect every new level for offline client backup.
            peer_value({"key_id": payload["sender_key_id"], "store_id": payload["source_store_id"]})
            directory = exchange / payload["sender_key_id"] / payload["source_store_id"]
            protected_storage.private_directory(directory)
            if payload.get("group") is not None:
                protected_storage.private_directory(directory / "groups" / payload["group"]["group_id"])
        if remote is None:
            # Reserve the full supported capsule ceiling, including signature
            # and closure overhead; never guess a smaller size from record text.
            budget.transfer(MAX_CAPSULE_BYTES)

    # Publish local durable work before spending the remaining window on peers.
    # A malformed/offline peer cannot monopolize every attempt to send local
    # memory. An empty receiving Vault is permitted to bootstrap below.
    more = False
    outbound_review_error: MemoryError | None = None
    for index in range(maximum if direction != "receive" else 0):
        active()
        try:
            if remote is not None and _push_pending(config, endpoint, remote):
                counts["uploaded_batches"] += 1
            result = endpoint.publish(limit=config.limits["record_limit"], maximum_bytes=config.limits["batch_bytes"],
                                      capsule_guard=publication_guard, before_fragment_write=lambda size: budget.transfer(size))
        except MemoryError as exc:
            if exc.code == "not_initialized" and endpoint._state()["vault_store_id"] is None:
                break
            if exc.code == "remote_group_pending":
                more = True
                break
            if exc.code in {"publication_local_path_detected", "publication_secret_detected"}:
                # Only outbound publication needs this operator decision. Keep
                # the exact frozen pending batch and error, but do not starve
                # independently verified incoming memory in the same bounded
                # window. Trust, storage, cancellation and budget errors do not
                # enter this branch or acquire permission to continue.
                outbound_review_error = exc
                break
            raise
        if result["state"] == "group_publication_pending":
            more = True
            break
        if result["state"] == "up_to_date":
            break
        counts["published_batches"] += 1
        counts["blocked_records"] += len(result.get("blocked", []))
        if remote is not None:
            try:
                if _push_pending(config, endpoint, remote):
                    counts["uploaded_batches"] += 1
            except MemoryError as exc:
                if exc.code != "remote_group_pending":
                    raise
                more = True
                break
        more = index == maximum - 1

    peer_error: str | None = None
    if remote is not None:
        received = 0
        for peer in config.backend["peers"]:
            for _ in range(maximum - received):
                active()
                accounted = False

                def remote_progress(result: Mapping[str, Any]) -> None:
                    nonlocal received, accounted
                    if accounted or result["state"] != "received":
                        return
                    received += 1
                    counts["received_batches"] += 1
                    counts["records_added"] += int(result["records_added"])
                    counts["receipt_replays"] += int(result["receipt_replayed"])
                    counts["blocked_records"] += int(result["blocked_records"])
                    counts["rejected_batches"] += int(result["rejected_candidates"])
                    accounted = True

                try:
                    result = _pull_peer(endpoint, remote, peer, active_check=active,
                                        on_progress=remote_progress)
                except (MemoryError, TrustError) as exc:
                    code = _error_code(exc)
                    if accounted or code.startswith("sync_"):
                        # A local head-write failure after durable admission is
                        # not a malformed/offline peer. Preserve its completed
                        # count and let the atomic receipt make retry exact.
                        raise  # Shared time/byte/cancellation bounds also win.
                    counts["peer_failures"] += 1
                    peer_error = peer_error or code
                    break  # Other explicitly configured peers remain eligible.
                if result is None:
                    break
                if result["state"] == "group_receiving_pending":
                    more = True
                    break
                remote_progress(result)
            if received >= maximum:
                break
    elif exchange.is_dir():
        accounted = {key: 0 for key in ("received_batches", "records_added", "blocked_records", "rejected_batches", "receipt_replays")}

        def receive_progress(report: Mapping[str, Any]) -> None:
            # Admission has its own durable receipt before the stream-head
            # write/next read. Keep completed work visible if either fails, and
            # apply the same cumulative snapshot at normal return exactly once.
            totals = {
                "received_batches": int(report["batches"]),
                "records_added": int(report["records_added"]),
                "blocked_records": int(report["sender_blocked_records"]),
                "rejected_batches": len(report["rejected"]) + int(report["gaps"]) + int(report["unknown_senders"]),
                "receipt_replays": int(report["receipt_replays"]),
            }
            for key, total in totals.items():
                counts[key] += total - accounted[key]
                accounted[key] = total

        result = endpoint.receive(maximum_batches=maximum, active_check=active,
                                  before_read=lambda: budget.transfer(MAX_CAPSULE_BYTES),
                                  before_fragment_read=lambda size: budget.transfer(size), skip_local_stream=True,
                                  on_progress=receive_progress)
        receive_progress(result)
        more = more or bool(result.get("more_possible", False))
    if peer_error is not None:
        raise MemoryError(peer_error, retryable=True)
    if outbound_review_error is not None:
        # Receive errors/cancellation above take their usual precedence. Only
        # a normally completed receive phase reports the pending review error.
        raise outbound_review_error
    # Newly received records may need forwarding in a later window. Do not
    # mark that generation exhausted merely because the outbound pass ran first.
    # Admission upgrades of existing records can create outbound changes even
    # when records_added is zero, so every received batch keeps a later pass due.
    return more or counts["received_batches"] > 0


def run(
    config_path: Path, *, background_worker: bool = False, direction: str = "both",
    maximum_seconds: int | None = None,
) -> Mapping[str, Any]:
    if direction not in {"both", "receive"} or (background_worker and direction != "both"):
        raise MemoryError("invalid_sync_direction")
    if maximum_seconds is not None:
        _bounded_int(maximum_seconds, 1, 60)
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
            more = _window(config, background_worker=background_worker, counts=state["counts"],
                           direction=direction, maximum_seconds=maximum_seconds)
            state.update(state="attention_required" if state["counts"]["blocked_records"] or state["counts"]["rejected_batches"] else "idle",
                         failures=0, next_retry_at=0, last_success_at=int(time.time()))
            if not more and direction != "receive":
                state["completed_generation"] = trigger["generation"]
        except (MemoryError, TrustError, OSError, ValueError, TypeError) as exc:
            code = _error_code(exc)
            failures = state["failures"] + 1
            # A review-blocked sender or interrupted receive can still have
            # received durable records.
            # Preserve that progress without completing its pending generation
            # or claiming that the rejected outbound batch was published.
            more = more or state["counts"]["received_batches"] > 0
            state.update(state="cancelled" if code == "sync_cancelled" else "retry_pending", failures=failures,
                         last_error=code, next_retry_at=int(time.time()) + min(300, 5 * 2**min(failures - 1, 6)))
        finally:
            state.update(finished_at=int(time.time()), running_until=0)
            _write_control(config.state_directory / "sync-state.json", state)
        latest = _trigger(config)
        pending = latest is not None and latest["generation"] != state["completed_generation"]
        return {"state": state["state"], "last_error": state["last_error"], "counts": dict(state["counts"]),
                "more_work_possible": more, "pending": pending, "remote_ai_read_verified": False,
                "memory_content_included": False, "network_backend": config.backend["kind"] != "directory",
                "direction": direction, "remote_latest_proven": False,
                "outbound_attempted": direction != "receive"}


def receive(config_path: Path, *, maximum_seconds: int | None = None) -> Mapping[str, Any]:
    """One explicit receive-only freshness attempt; never piggyback an upload."""
    return run(config_path, direction="receive", maximum_seconds=maximum_seconds)


def flush(config_path: Path, *, maximum_seconds: int | None = None) -> Mapping[str, Any]:
    """One explicit bounded bidirectional window, not an eventual-delivery claim."""
    return run(config_path, maximum_seconds=maximum_seconds)


def _endpoint(config: SyncConfig, *, writing: bool) -> DirectoryTransfer:
    exchange = Path(config.backend["exchange"]) if config.backend["kind"] == "directory" else config.state_directory / "exchange"
    return DirectoryTransfer(vault=config.vault, exchange=exchange, state_directory=config.state_directory / "transfer",
                             trust_store=config.trust_store, identity=config.identity if writing else None)


def review(config_path: Path, *, offset: int = 0, limit: int = 100) -> Mapping[str, Any]:
    config = SyncConfig.load(config_path)
    result = dict(_endpoint(config, writing=False).review_pending(offset=offset, limit=limit))
    result["operator_action_required"] = result["state"] == "pending_review"
    return result


def resolve(
    config_path: Path, *, batch_sha256: str, request_id: str, exclude: Sequence[str],
    keep: Sequence[str], allow_local_paths: bool = False,
) -> Mapping[str, Any]:
    config = SyncConfig.load(config_path)
    with _lock(config.state_directory / "worker.lock"):
        _state(config)
        endpoint = _endpoint(config, writing=True)
        if config.backend["kind"] != "directory" and endpoint.pending_path.exists():
            pending, _ = endpoint._verify_capsule(_read(endpoint.pending_path, private=True), verify_records=False)
            if _remote_receipt(config)["sent_cursor"] > pending["after"]:
                raise MemoryError("review_remote_publication_already_recorded")
        result = endpoint.resolve_pending(batch_sha256=batch_sha256, request_id=request_id,
                                          exclude=exclude, keep=keep, allow_local_paths=allow_local_paths)
        _enqueue(config, "explicit")
        return {**result, "worker_started": False, "next_action": "explicit_flush_or_next_enabled_event"}


def requeue(config_path: Path, *, identifiers: Sequence[str], request_id: str) -> Mapping[str, Any]:
    """Idempotently add delivery events; neither redact nor trust any record."""
    config = SyncConfig.load(config_path)
    with _lock(config.state_directory / "worker.lock"):
        _state(config)
        endpoint = _endpoint(config, writing=False)
        endpoint._bind_vault(endpoint._state(), missing_ok=False)
        result = endpoint.vault.requeue_records(identifiers, request_id=request_id)
        _enqueue(config, "explicit")
        return {**result, "worker_started": False, "publication_review_reused": False,
                "next_action": "explicit_flush_or_next_enabled_event"}


def anchor(config_path: Path, *, capsule: Path) -> Mapping[str, Any]:
    config = SyncConfig.load(config_path)
    with _lock(config.state_directory / "worker.lock"):
        _state(config)
        return _endpoint(config, writing=False).anchor_received(_read(_absolute(capsule)))


def _configure(args: argparse.Namespace) -> Mapping[str, Any]:
    if os.name not in {"posix", "nt"}:
        raise MemoryError("unsupported_private_sync_storage")
    protected_storage.require_supported_storage()
    selected = _absolute(args.config)
    reference_path = getattr(args, "rclone_password_ref", None)
    drive_config = getattr(args, "drive_config", None)
    encryption_key = getattr(args, "encryption_key", None)
    recipient_keys = getattr(args, "recipient_key", [])
    native_arguments = (drive_config, encryption_key, recipient_keys)
    peers = []
    for value in args.peer:
        parts = value.split("/")
        if len(parts) != 2:
            raise MemoryError("invalid_sync_peer")
        peers.append(peer_value({"key_id": parts[0], "store_id": parts[1]}))
    if args.backend == "directory":
        if args.exchange is None or any((args.rclone_executable, args.rclone_config, args.remote, args.peer, reference_path, *native_arguments)):
            raise MemoryError("invalid_sync_backend_arguments")
        backend: dict[str, Any] = {"kind": "directory", "exchange": str(_absolute(args.exchange))}
    elif args.backend == "rclone":
        if args.exchange is not None or any(native_arguments) or not all((args.rclone_executable, args.rclone_config, args.remote)):
            raise MemoryError("invalid_sync_backend_arguments")
        executable = _absolute(args.rclone_executable)
        backend = {"kind": "rclone", "executable": str(executable), "executable_sha256": executable_sha256(executable),
                   "config_file": str(_absolute(args.rclone_config)), "remote": remote_path(args.remote), "peers": peers}
        if reference_path is not None:
            backend["config_password_ref"] = password_reference(dict(_read(
                _absolute(reference_path), maximum=MAX_REFERENCE_BYTES, private=True)))
    elif args.backend == "native-drive":
        from memory_vault_drive import DriveConfig
        if (any((args.exchange, args.rclone_executable, args.rclone_config, args.remote, reference_path))
                or not all(native_arguments)):
            raise MemoryError("invalid_sync_backend_arguments")
        config_file = _absolute(drive_config)
        selected_drive = DriveConfig.from_file(config_file)
        backend = {"kind": "native-drive", "config_file": str(config_file),
                   "root_folder_id": selected_drive.root_folder_id, "encryption_key_path": str(_absolute(encryption_key)),
                   "recipient_keys": [dict(_read(_absolute(path), maximum=4096)) for path in recipient_keys], "peers": peers}
    else:
        raise MemoryError("unsupported_sync_backend")
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
    configure.add_argument("--backend", choices=("directory", "rclone", "native-drive"), required=True)
    configure.add_argument("--exchange", type=Path)
    configure.add_argument("--rclone-executable", type=Path)
    configure.add_argument("--rclone-config", type=Path)
    configure.add_argument("--rclone-password-ref", type=Path,
                           help="explicit private JSON identifying an existing OS credential, not a password or command")
    configure.add_argument("--drive-config", type=Path, help="explicit protected native Drive configuration")
    configure.add_argument("--encryption-key", type=Path, help="explicit local X25519 private key; required for native Drive")
    configure.add_argument("--recipient-key", type=Path, action="append", default=[],
                           help="explicit public X25519 descriptor JSON; repeat for self and other backup recipients")
    configure.add_argument("--remote")
    configure.add_argument("--peer", action="append", default=[])
    configure.add_argument("--automatic", action="store_true")
    configure.add_argument("--background", action="store_true")
    configure.add_argument("--disabled", action="store_true")
    configure.add_argument("--replace", action="store_true")
    configure.add_argument("--maximum-seconds", type=int, default=DEFAULT_LIMITS["maximum_seconds"])
    worker = commands.add_parser("run", help="one explicitly requested bounded synchronization window")
    worker.add_argument("--background-worker", action="store_true", help=argparse.SUPPRESS)
    worker.add_argument("--maximum-seconds", type=int)
    for name in ("receive", "flush"):
        explicit = commands.add_parser(name, help="one bounded explicit " + ("receive-only freshness attempt" if name == "receive" else "bidirectional synchronization attempt"))
        explicit.add_argument("--maximum-seconds", type=int)
    commands.add_parser("status", help="read-only content-free state; never start synchronization")
    inspection = commands.add_parser("review", help="read-only per-record findings; no private-key read, content output or network")
    inspection.add_argument("--offset", type=int, default=0)
    inspection.add_argument("--limit", type=int, default=100)
    decision = commands.add_parser("resolve", help="operator-only complete keep/exclude decision for an unexposed pending batch")
    decision.add_argument("--batch-sha256")
    decision.add_argument("--request-id")
    decision.add_argument("--decision-file", type=Path, help="explicit private JSON selection for a large reviewed group")
    decision.add_argument("--exclude", nargs="*", default=[])
    decision.add_argument("--keep", nargs="*", default=[])
    decision.add_argument("--allow-local-paths", action="store_true")
    retry = commands.add_parser("requeue", help="operator-only idempotent retry of exact canonical IDs; never edits memory")
    retry.add_argument("--memory-id", dest="identifiers", nargs="+", required=True)
    retry.add_argument("--request-id", required=True)
    historical = commands.add_parser("anchor", help="bind an existing legacy receipt to its exact signed capsule")
    historical.add_argument("--capsule", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "configure":
            result = _configure(args)
        elif args.command == "status":
            result = status(args.config)
        elif args.command == "review":
            result = review(args.config, offset=args.offset, limit=args.limit)
        elif args.command == "resolve":
            if args.decision_file is not None:
                if any((args.batch_sha256, args.request_id, args.exclude, args.keep, args.allow_local_paths)):
                    raise MemoryError("conflicting_review_arguments")
                selection = _object(dict(_read(_absolute(args.decision_file), maximum=MAX_REVIEW_DOCUMENT, private=True)),
                                    {"batch_sha256", "request_id", "exclude", "keep", "allow_local_paths"}, "invalid_review_decision")
            else:
                selection = {"batch_sha256": args.batch_sha256, "request_id": args.request_id,
                             "exclude": args.exclude, "keep": args.keep, "allow_local_paths": args.allow_local_paths}
            result = resolve(args.config, **selection)
        elif args.command == "requeue":
            result = requeue(args.config, identifiers=args.identifiers, request_id=args.request_id)
        elif args.command == "anchor":
            result = anchor(args.config, capsule=args.capsule)
        elif args.command in {"receive", "flush"}:
            result = (receive if args.command == "receive" else flush)(args.config, maximum_seconds=args.maximum_seconds)
        else:
            result = run(args.config, background_worker=args.background_worker, maximum_seconds=args.maximum_seconds)
        write_response(success(result))
        return 0 if result.get("state") not in {"retry_pending", "cancelled"} else 1
    except (MemoryError, TrustError, OSError, ValueError, TypeError) as exc:
        write_response(failure(_error_code(exc), retryable=bool(getattr(exc, "retryable", False))))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
