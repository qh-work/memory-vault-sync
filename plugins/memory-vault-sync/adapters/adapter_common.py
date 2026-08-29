"""Shared, standard-library-only support for Memory Vault host adapters.

Host adapters are intentionally thin.  They translate one host lifecycle event
into one bounded request to the local Memory Vault process.  Native session
identifiers are reduced to keyed local lookup keys and never cross that stdio
boundary.  The Vault owns memory; a host, model, conversation, or task never
does.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import time
from typing import Any, BinaryIO, Iterator, Mapping, MutableMapping, Sequence


REQUEST_SCHEMA = "memory-vault-host-request/v1"
RESPONSE_SCHEMA = "memory-vault-host-response/v1"
PROTOCOL_VERSION = "1.0"
STATE_SCHEMA = "memory-vault-host-adapter-state/v1"
ADAPTER_VERSION = "0.1.0"

MAX_HOOK_INPUT_BYTES = 2 * 1024 * 1024
MAX_PROTOCOL_BYTES = 3 * 1024 * 1024
MAX_PROTOCOL_OUTPUT_BYTES = 3 * 1024 * 1024
MAX_VISIBLE_TEXT_BYTES = 1024 * 1024
MAX_CONTEXT_BYTES = 10_000
MAX_RECALL_CONTEXT_BYTES = 8192
MAX_NATIVE_ID_BYTES = 1024
MAX_STATE_BYTES = 512 * 1024
MAX_SESSIONS = 512
MAX_COMMAND_PARTS = 32
MAX_COMMAND_PART_BYTES = 4096
LOCK_WAIT_SECONDS = 2.0
LOCK_STALE_SECONDS = 600.0
VAULT_TIMEOUT_SECONDS = 30.0
VAULT_OPERATION_TIMEOUT_SECONDS = {
    "capabilities": 10.0,
    "session.open": 145.0,
    # Two exact prompt-stage attempts remain inside a 15 second host hook.
    "turn.input": 5.0,
    # Two identical commit attempts still fit inside a 30 second host hook.
    "turn.commit": 14.0,
    "turn.abort": 2.0,
    "session.close": 2.0,
    "memory.recall": 15.0,
    "memory.remember": 30.0,
    "memory.status": 10.0,
    "sync.flush": 30.0,
}
ACK_RETRY_OPERATIONS = {"turn.input", "turn.commit"}

SUCCESS_STATUSES = {
    "accepted_local",
    "published",
    "duplicate",
    "degraded",
}
ALL_STATUSES = SUCCESS_STATUSES | {"rejected"}
SESSION_HANDLE_RE = re.compile(r"mvc1_[A-Za-z0-9_-]{43}")
TURN_HANDLE_RE = re.compile(r"mvt1_[A-Za-z0-9_-]{43}")

FORBIDDEN_RESPONSE_KEYS = {
    "instruction",
    "instructions",
    "decision",
    "permission",
    "permissions",
    "authorization",
    "authorize",
    "execution",
    "execute",
    "command",
    "shell",
    "tool_call",
    "policy",
    "policy_change",
    "role_escalation",
    "system_prompt",
    "developer_message",
    "hidden_reasoning",
    "chain_of_thought",
    "task_id",
    "project_id",
    "native_session_id",
    "native_turn_id",
    "transcript_path",
}

# Semantic proposals may describe memories and relations, but cannot smuggle a
# host-only surface or an authority/execution concept into the Vault request.
FORBIDDEN_PROPOSAL_KEYS = {
    "task",
    "task_id",
    "project",
    "project_id",
    "binding",
    "binding_id",
    "routing",
    "routing_id",
    "owner",
    "owner_id",
    "vault_id",
    "conversation",
    "conversation_id",
    "native_conversation_id",
    "native_session_id",
    "native_turn_id",
    "model",
    "model_id",
    "workspace",
    "workspace_id",
    "cwd",
    "path",
    "transcript",
    "transcript_path",
    "environment",
    "env",
    "hostname",
    "account",
    "email",
    "token",
    "credential",
    "password",
    "cookie",
    "instruction",
    "instructions",
    "authorization",
    "permission",
    "permissions",
    "permission_mode",
    "policy",
    "policy_change",
    "consent",
    "role_escalation",
    "execution",
    "execute",
    "command",
    "shell",
    "tool",
    "tools",
    "tool_call",
    "tool_data",
    "tool_result",
    "agent_spawn",
    "resource",
    "resource_expand",
    "system",
    "system_message",
    "system_prompt",
    "developer_message",
    "chain_of_thought",
    "hidden",
    "hidden_reasoning",
    "confidence",
}

REQUIRED_AUTHORITY = {
    "memory": "untrusted_historical_evidence",
    "instruction_eligible": False,
    "authorization_eligible": False,
    "execution_eligible": False,
    "policy_change_eligible": False,
    "current_user_input_precedence": True,
}


class AdapterFailure(Exception):
    """Sanitized adapter failure; messages never contain private input."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def strict_json_loads(value: str | bytes) -> Any:
    """Decode one strict JSON value without duplicate keys or extensions."""

    if isinstance(value, bytes):
        if value.startswith(b"\xef\xbb\xbf"):
            raise AdapterFailure("json_bom_forbidden")
        try:
            text = value.decode("utf-8")
        except UnicodeDecodeError:
            raise AdapterFailure("invalid_json") from None
    elif isinstance(value, str):
        text = value
    else:
        raise AdapterFailure("invalid_json")
    if text.startswith("\ufeff"):
        raise AdapterFailure("json_bom_forbidden")

    def reject_constant(_token: str) -> None:
        raise AdapterFailure("non_finite_json_number")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, child in pairs:
            if key in result:
                raise AdapterFailure("duplicate_json_key")
            result[key] = child
        return result

    try:
        return json.loads(
            text,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise AdapterFailure("invalid_json") from None


def _utf8_size(value: str) -> int:
    return len(value.encode("utf-8"))


def require_mapping(value: Any, code: str = "invalid_object") -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise AdapterFailure(code)
    return value


def require_exact_fields(
    value: Any,
    fields: set[str],
    code: str = "invalid_shape",
) -> Mapping[str, Any]:
    raw = require_mapping(value, code)
    if set(raw) != fields:
        raise AdapterFailure(code)
    return raw


def require_native_id(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or "\x00" in value
        or _utf8_size(value) > MAX_NATIVE_ID_BYTES
    ):
        raise AdapterFailure("invalid_native_session")
    return value


def require_visible_text(
    value: Any,
    *,
    nullable: bool = False,
    empty: bool = False,
) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str):
        raise AdapterFailure("invalid_visible_text")
    if (not empty and not value) or "\x00" in value:
        raise AdapterFailure("invalid_visible_text")
    if _utf8_size(value) > MAX_VISIBLE_TEXT_BYTES:
        raise AdapterFailure("visible_text_too_large")
    return value


def require_limit(value: Any, default: int = 8) -> int:
    if value is None:
        value = default
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 32:
        raise AdapterFailure("invalid_limit")
    return value


def read_bounded_json(
    stream: BinaryIO | None = None,
    *,
    maximum_bytes: int = MAX_HOOK_INPUT_BYTES,
) -> Mapping[str, Any]:
    source = stream if stream is not None else sys.stdin.buffer
    data = source.read(maximum_bytes + 1)
    if len(data) > maximum_bytes:
        raise AdapterFailure("input_too_large")
    if not data:
        raise AdapterFailure("empty_input")
    value = strict_json_loads(data)
    return require_mapping(value)


def write_json(value: Mapping[str, Any]) -> None:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    sys.stdout.write(encoded + "\n")
    sys.stdout.flush()


def hook_noop() -> dict[str, Any]:
    return {}


def hook_context(event_name: str, context: str | None) -> dict[str, Any]:
    if not context:
        return hook_noop()
    if _utf8_size(context) > MAX_CONTEXT_BYTES:
        raise AdapterFailure("context_too_large")
    return {
        "hookSpecificOutput": {
            "hookEventName": event_name,
            "additionalContext": context,
        }
    }


def _default_state_base() -> Path:
    configured = os.environ.get("MEMORY_VAULT_ADAPTER_STATE_DIR")
    if configured:
        return Path(configured).expanduser()
    if os.name == "nt":
        local = os.environ.get("LOCALAPPDATA")
        if local:
            return Path(local) / "MemoryVault" / "host-adapters"
    xdg = os.environ.get("XDG_STATE_HOME")
    if xdg:
        return Path(xdg) / "memory-vault" / "host-adapters"
    return Path.home() / ".local" / "state" / "memory-vault" / "host-adapters"


def _safe_adapter_slug(adapter_id: str) -> str:
    slug = re.sub(r"[^a-z0-9._-]", "-", adapter_id.lower())
    if not slug or len(slug) > 80:
        raise AdapterFailure("invalid_adapter_identity")
    return slug


def _private_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:
        if os.name != "nt":
            raise AdapterFailure("state_permission_failed") from None


class PrivateState:
    """Bounded atomic local map from an HMAC key to Vault-issued handles."""

    def __init__(self, adapter_id: str):
        self.directory = _default_state_base() / _safe_adapter_slug(adapter_id)
        self.state_path = self.directory / "state.json"
        self.lock_path = self.directory / "state.lock"

    def _acquire_lock(self) -> int:
        _private_directory(self.directory)
        deadline = time.monotonic() + LOCK_WAIT_SECONDS
        while True:
            try:
                descriptor = os.open(
                    self.lock_path,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
                try:
                    os.chmod(self.lock_path, 0o600)
                except OSError:
                    pass
                return descriptor
            except FileExistsError:
                try:
                    age = time.time() - self.lock_path.stat().st_mtime
                    if age > LOCK_STALE_SECONDS:
                        self.lock_path.unlink()
                        continue
                except FileNotFoundError:
                    continue
                except OSError:
                    pass
                if time.monotonic() >= deadline:
                    raise AdapterFailure("state_busy") from None
                time.sleep(0.02)
            except OSError:
                raise AdapterFailure("state_lock_failed") from None

    def _release_lock(self, descriptor: int) -> None:
        try:
            os.close(descriptor)
        finally:
            try:
                self.lock_path.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                pass

    def _new_state(self) -> MutableMapping[str, Any]:
        secret = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")
        return {
            "schema_version": STATE_SCHEMA,
            "secret": secret,
            "counter": 0,
            "sessions": {},
        }

    def _validate_state(self, value: Any) -> MutableMapping[str, Any]:
        raw = require_exact_fields(
            value,
            {"schema_version", "secret", "counter", "sessions"},
            "invalid_state",
        )
        if raw.get("schema_version") != STATE_SCHEMA:
            raise AdapterFailure("invalid_state")
        secret_text = raw.get("secret")
        if not isinstance(secret_text, str):
            raise AdapterFailure("invalid_state")
        try:
            secret = base64.b64decode(
                secret_text.encode("ascii"), altchars=b"-_", validate=True
            )
        except (ValueError, UnicodeEncodeError):
            raise AdapterFailure("invalid_state") from None
        if len(secret) != 32:
            raise AdapterFailure("invalid_state")
        counter = raw.get("counter")
        sessions = raw.get("sessions")
        if (
            isinstance(counter, bool)
            or not isinstance(counter, int)
            or counter < 0
            or not isinstance(sessions, dict)
            or len(sessions) > MAX_SESSIONS
        ):
            raise AdapterFailure("invalid_state")
        for key, entry in sessions.items():
            if not isinstance(key, str) or re.fullmatch(r"[0-9a-f]{64}", key) is None:
                raise AdapterFailure("invalid_state")
            self._validate_entry(entry)
        return dict(raw)

    @staticmethod
    def _validate_entry(value: Any) -> MutableMapping[str, Any]:
        raw = require_exact_fields(
            value,
            {"continuity_handle", "turn_handle", "last_used"},
            "invalid_state",
        )
        continuity = raw.get("continuity_handle")
        turn = raw.get("turn_handle")
        last_used = raw.get("last_used")
        if continuity is not None and not _valid_session_handle(continuity):
            raise AdapterFailure("invalid_state")
        if turn is not None and not _valid_turn_handle(turn):
            raise AdapterFailure("invalid_state")
        if (
            isinstance(last_used, bool)
            or not isinstance(last_used, int)
            or last_used < 0
        ):
            raise AdapterFailure("invalid_state")
        return dict(raw)

    def _load(self) -> MutableMapping[str, Any]:
        if not self.state_path.exists():
            return self._new_state()
        try:
            with self.state_path.open("rb") as handle:
                data = handle.read(MAX_STATE_BYTES + 1)
        except OSError:
            raise AdapterFailure("state_read_failed") from None
        if len(data) > MAX_STATE_BYTES:
            raise AdapterFailure("invalid_state")
        try:
            value = strict_json_loads(data)
        except AdapterFailure:
            raise AdapterFailure("invalid_state") from None
        return self._validate_state(value)

    def _save(self, state: Mapping[str, Any]) -> None:
        try:
            encoded = json.dumps(
                state,
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        except (TypeError, ValueError):
            raise AdapterFailure("state_write_failed") from None
        if len(encoded) > MAX_STATE_BYTES:
            raise AdapterFailure("state_too_large")
        descriptor = -1
        temporary_name = ""
        try:
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=".state-",
                suffix=".tmp",
                dir=self.directory,
            )
            os.chmod(temporary_name, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = -1
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_name, self.state_path)
            temporary_name = ""
            try:
                os.chmod(self.state_path, 0o600)
            except OSError:
                if os.name != "nt":
                    raise
            if hasattr(os, "O_DIRECTORY"):
                directory_fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        except OSError:
            raise AdapterFailure("state_write_failed") from None
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if temporary_name:
                try:
                    os.unlink(temporary_name)
                except OSError:
                    pass

    @contextlib.contextmanager
    def edit(self) -> Iterator["StateEditor"]:
        descriptor = self._acquire_lock()
        try:
            state = self._load()
            editor = StateEditor(state)
            try:
                yield editor
            finally:
                if editor.dirty or not self.state_path.exists():
                    self._save(state)
        finally:
            self._release_lock(descriptor)


class StateEditor:
    def __init__(self, state: MutableMapping[str, Any]):
        self.state = state
        self.dirty = False

    def _secret(self) -> bytes:
        return base64.urlsafe_b64decode(self.state["secret"].encode("ascii"))

    def session_key(self, native_session_id: str) -> str:
        native = require_native_id(native_session_id)
        return hmac.new(self._secret(), native.encode("utf-8"), hashlib.sha256).hexdigest()

    def get(self, native_session_id: str) -> MutableMapping[str, Any] | None:
        key = self.session_key(native_session_id)
        entry = self.state["sessions"].get(key)
        if entry is None:
            return None
        self.touch(entry)
        return entry

    def get_or_create(self, native_session_id: str) -> MutableMapping[str, Any]:
        key = self.session_key(native_session_id)
        sessions = self.state["sessions"]
        entry = sessions.get(key)
        if entry is None:
            while len(sessions) >= MAX_SESSIONS:
                oldest = min(sessions, key=lambda item: sessions[item]["last_used"])
                del sessions[oldest]
            entry = {
                "continuity_handle": None,
                "turn_handle": None,
                "last_used": 0,
            }
            sessions[key] = entry
            self.dirty = True
        self.touch(entry)
        return entry

    def delete(self, native_session_id: str) -> None:
        key = self.session_key(native_session_id)
        if self.state["sessions"].pop(key, None) is not None:
            self.dirty = True

    def touch(self, entry: MutableMapping[str, Any]) -> None:
        self.state["counter"] += 1
        entry["last_used"] = self.state["counter"]
        self.dirty = True

    def set_handles(
        self,
        entry: MutableMapping[str, Any],
        *,
        continuity_handle: str | None = None,
        turn_handle: str | None | object = ...,
    ) -> None:
        if continuity_handle is not None:
            if not _valid_session_handle(continuity_handle):
                raise AdapterFailure("invalid_continuity_handle")
            entry["continuity_handle"] = continuity_handle
        if turn_handle is not ...:
            if turn_handle is not None and not _valid_turn_handle(turn_handle):
                raise AdapterFailure("invalid_turn_handle")
            entry["turn_handle"] = turn_handle
        self.touch(entry)


def _valid_session_handle(value: Any) -> bool:
    return isinstance(value, str) and SESSION_HANDLE_RE.fullmatch(value) is not None


def _valid_turn_handle(value: Any) -> bool:
    return isinstance(value, str) and TURN_HANDLE_RE.fullmatch(value) is not None


def _validate_result_tree(value: Any) -> None:
    nodes = 0

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > 16_384 or depth > 12:
            raise AdapterFailure("invalid_vault_response")
        if item is None or isinstance(item, (str, bool, int)):
            return
        if isinstance(item, float):
            raise AdapterFailure("float_in_vault_response")
        if isinstance(item, Mapping):
            for key, child in item.items():
                if not isinstance(key, str):
                    raise AdapterFailure("invalid_vault_response")
                normalized = key.casefold().replace("-", "_")
                if normalized in FORBIDDEN_RESPONSE_KEYS:
                    safe_negative_capability = normalized in {
                        "permission",
                        "permissions",
                        "authorization",
                        "authorize",
                        "execution",
                        "execute",
                        "policy_change",
                        "role_escalation",
                    } and child is False
                    if not safe_negative_capability:
                        raise AdapterFailure("authority_field_in_vault_result")
                visit(child, depth + 1)
            return
        if isinstance(item, list):
            for child in item:
                visit(child, depth + 1)
            return
        raise AdapterFailure("invalid_vault_response")

    visit(value, 0)


def _validate_proposal_tree(value: Any) -> None:
    nodes = 0

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > 16_384 or depth > 12:
            raise AdapterFailure("invalid_proposal")
        if item is None or isinstance(item, (bool, int)):
            return
        if isinstance(item, str):
            if "\x00" in item or _utf8_size(item) > MAX_VISIBLE_TEXT_BYTES:
                raise AdapterFailure("invalid_proposal")
            return
        if isinstance(item, float):
            raise AdapterFailure("invalid_proposal")
        if isinstance(item, Mapping):
            for key, child in item.items():
                if not isinstance(key, str):
                    raise AdapterFailure("invalid_proposal")
                normalized = key.casefold().replace("-", "_")
                if normalized in FORBIDDEN_PROPOSAL_KEYS:
                    raise AdapterFailure("forbidden_proposal_field")
                visit(child, depth + 1)
            return
        if isinstance(item, list):
            for child in item:
                visit(child, depth + 1)
            return
        raise AdapterFailure("invalid_proposal")

    visit(value, 0)


def _request_id() -> str:
    return "mvr1_" + secrets.token_urlsafe(18).rstrip("=")


class VaultClient:
    def __init__(self, adapter_id: str, host_family: str):
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{1,63}", adapter_id):
            raise AdapterFailure("invalid_adapter_identity")
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{1,63}", host_family):
            raise AdapterFailure("invalid_adapter_identity")
        self.adapter = {
            "id": adapter_id,
            "version": ADAPTER_VERSION,
            "host_family": host_family,
        }

    @staticmethod
    def _command() -> Sequence[str]:
        configured = os.environ.get("MEMORY_VAULT_HOST_COMMAND_JSON")
        if configured:
            try:
                command = strict_json_loads(configured)
            except AdapterFailure:
                raise AdapterFailure("invalid_vault_command") from None
            if (
                not isinstance(command, list)
                or not command
                or len(command) > MAX_COMMAND_PARTS
                or any(
                    not isinstance(part, str)
                    or not part
                    or "\x00" in part
                    or _utf8_size(part) > MAX_COMMAND_PART_BYTES
                    for part in command
                )
            ):
                raise AdapterFailure("invalid_vault_command")
            return tuple(command)
        plugin_root = Path(__file__).resolve().parent.parent
        return (
            sys.executable,
            str(plugin_root / "scripts" / "vault_sync.py"),
            "host-adapter",
            "--request-stdin",
        )

    def request(self, operation: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        request_id = _request_id()
        request = {
            "schema_version": REQUEST_SCHEMA,
            "protocol_version": PROTOCOL_VERSION,
            "request_id": request_id,
            "operation": operation,
            "adapter": dict(self.adapter),
            "payload": dict(payload),
        }
        try:
            encoded = json.dumps(
                request,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        except (TypeError, ValueError):
            raise AdapterFailure("invalid_protocol_payload") from None
        if len(encoded) > MAX_PROTOCOL_BYTES:
            raise AdapterFailure("protocol_request_too_large")
        command = self._command()
        environment = os.environ.copy()
        attempts = 2 if operation in ACK_RETRY_OPERATIONS else 1
        timeout = VAULT_OPERATION_TIMEOUT_SECONDS.get(
            operation, VAULT_TIMEOUT_SECONDS
        )
        completed: subprocess.CompletedProcess[bytes] | None = None
        failure_code = "vault_unavailable"
        for attempt in range(attempts):
            try:
                candidate = subprocess.run(
                    command,
                    input=encoded,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    check=False,
                    timeout=timeout,
                    env=environment,
                )
            except (OSError, subprocess.TimeoutExpired):
                failure_code = "vault_unavailable"
                if attempt + 1 < attempts:
                    continue
                raise AdapterFailure(failure_code) from None
            if candidate.returncode != 0:
                failure_code = "vault_refused"
                if attempt + 1 < attempts:
                    continue
                raise AdapterFailure(failure_code)
            completed = candidate
            break
        if completed is None:
            raise AdapterFailure(failure_code)
        if not completed.stdout or len(completed.stdout) > MAX_PROTOCOL_OUTPUT_BYTES:
            raise AdapterFailure("invalid_vault_response")
        try:
            response = strict_json_loads(completed.stdout)
        except AdapterFailure:
            raise AdapterFailure("invalid_vault_response") from None
        raw = require_mapping(response, "invalid_vault_response")
        if (
            raw.get("schema_version") != RESPONSE_SCHEMA
            or raw.get("protocol_version") != PROTOCOL_VERSION
            or raw.get("request_id") != request_id
            or raw.get("operation") != operation
            or raw.get("status") not in ALL_STATUSES
            or raw.get("authority") != REQUIRED_AUTHORITY
        ):
            raise AdapterFailure("invalid_vault_response")
        if raw.get("status") == "rejected":
            if set(raw) != {
                "schema_version",
                "protocol_version",
                "request_id",
                "operation",
                "status",
                "authority",
                "error",
            }:
                raise AdapterFailure("invalid_vault_response")
            error = raw.get("error")
            if (
                not isinstance(error, Mapping)
                or set(error) != {"code", "retryable"}
                or not isinstance(error.get("code"), str)
                or not isinstance(error.get("retryable"), bool)
            ):
                raise AdapterFailure("invalid_vault_response")
            raise AdapterFailure("vault_rejected")
        if set(raw) != {
            "schema_version",
            "protocol_version",
            "request_id",
            "operation",
            "status",
            "authority",
            "result",
        }:
            raise AdapterFailure("invalid_vault_response")
        result = raw.get("result")
        if not isinstance(result, Mapping):
            raise AdapterFailure("invalid_vault_response")
        _validate_result_tree(result)
        return result


class LifecycleAdapter:
    """Host-neutral lifecycle actions over one shared Vault."""

    def __init__(self, adapter_id: str, host_family: str):
        self.client = VaultClient(adapter_id, host_family)
        self.state = PrivateState(adapter_id)

    @staticmethod
    def _context(result: Mapping[str, Any]) -> str | None:
        value = result.get("evidence_context")
        if value is None:
            return None
        evidence = require_exact_fields(
            value,
            {
                "kind",
                "content_type",
                "authority",
                "instruction_eligible",
                "authorization_eligible",
                "execution_eligible",
                "current_user_input_precedence",
                "truncated",
                "omitted_count",
                "text",
            },
            "invalid_evidence_context",
        )
        if (
            evidence.get("kind") != "evidence_context"
            or evidence.get("content_type") != "text/plain"
            or evidence.get("authority") != "none"
            or evidence.get("instruction_eligible") is not False
            or evidence.get("authorization_eligible") is not False
            or evidence.get("execution_eligible") is not False
            or evidence.get("current_user_input_precedence") is not True
            or not isinstance(evidence.get("truncated"), bool)
            or isinstance(evidence.get("omitted_count"), bool)
            or not isinstance(evidence.get("omitted_count"), int)
            or evidence.get("omitted_count") < 0
        ):
            raise AdapterFailure("invalid_evidence_context")
        text = evidence.get("text")
        if not isinstance(text, str) or _utf8_size(text) > MAX_CONTEXT_BYTES:
            raise AdapterFailure("invalid_evidence_context")
        return text

    @staticmethod
    def _network_free(result: Mapping[str, Any]) -> None:
        if result.get("network_accessed") is not False:
            raise AdapterFailure("network_free_contract_failed")

    def capabilities(self) -> Mapping[str, Any]:
        return self.client.request("capabilities", {})

    def _open_locked(
        self,
        editor: StateEditor,
        native_session_id: str,
        reason: str,
    ) -> tuple[MutableMapping[str, Any], Mapping[str, Any]]:
        if reason not in {"startup", "resume", "clear", "compact"}:
            raise AdapterFailure("invalid_session_reason")
        entry = editor.get_or_create(native_session_id)
        result = self.client.request(
            "session.open",
            {
                "continuity_handle": entry["continuity_handle"],
                "reason": reason,
            },
        )
        continuity = result.get("continuity_handle")
        if not _valid_session_handle(continuity):
            raise AdapterFailure("invalid_continuity_handle")
        if reason == "compact":
            self._network_free(result)
        editor.set_handles(entry, continuity_handle=continuity)
        return entry, result

    def session_open(self, native_session_id: str, reason: str) -> Mapping[str, Any]:
        with self.state.edit() as editor:
            _entry, result = self._open_locked(editor, native_session_id, reason)
            return result

    def turn_input(
        self,
        native_session_id: str,
        visible_user_text: str,
        limit: int = 8,
    ) -> Mapping[str, Any]:
        text = require_visible_text(visible_user_text)
        recall_limit = require_limit(limit)
        with self.state.edit() as editor:
            entry = editor.get_or_create(native_session_id)
            if entry["continuity_handle"] is None:
                entry, _ = self._open_locked(
                    editor, native_session_id, "startup"
                )
            if entry["turn_handle"] is not None:
                self.client.request(
                    "turn.abort",
                    {
                        "continuity_handle": entry["continuity_handle"],
                        "turn_handle": entry["turn_handle"],
                        "reason": "user_interrupt",
                    },
                )
                editor.set_handles(entry, turn_handle=None)
            result = self.client.request(
                "turn.input",
                {
                    "continuity_handle": entry["continuity_handle"],
                    "turn_handle": None,
                    "visible_user_text": text,
                    "limit": recall_limit,
                },
            )
            self._network_free(result)
            continuity = result.get("continuity_handle")
            turn = result.get("turn_handle")
            if not _valid_session_handle(continuity):
                raise AdapterFailure("invalid_continuity_handle")
            if not _valid_turn_handle(turn):
                raise AdapterFailure("invalid_turn_handle")
            self._context(result)
            editor.set_handles(
                entry,
                continuity_handle=continuity,
                turn_handle=turn,
            )
            return result

    def turn_commit(
        self,
        native_session_id: str,
        *,
        outcome: str,
        visible_user_text: str | None,
        visible_assistant_text: str | None,
    ) -> Mapping[str, Any] | None:
        if outcome != "final":
            raise AdapterFailure("invalid_turn_outcome")
        user_text = require_visible_text(visible_user_text, nullable=True)
        assistant_text = require_visible_text(visible_assistant_text, nullable=True)
        if assistant_text is None:
            raise AdapterFailure("empty_turn_commit")
        with self.state.edit() as editor:
            entry = editor.get(native_session_id)
            if entry is None or entry["continuity_handle"] is None:
                if user_text is None:
                    return None
                entry, _ = self._open_locked(
                    editor, native_session_id, "startup"
                )
            if entry["turn_handle"] is None and user_text is None:
                return None
            result = self.client.request(
                "turn.commit",
                {
                    "continuity_handle": entry["continuity_handle"],
                    "turn_handle": entry["turn_handle"],
                    "outcome": outcome,
                    "visible_user_text": user_text,
                    "visible_assistant_text": assistant_text,
                },
            )
            editor.set_handles(entry, turn_handle=None)
            return result

    def turn_abort(
        self,
        native_session_id: str,
        reason: str = "unknown",
    ) -> Mapping[str, Any] | None:
        if reason not in {"cancelled", "host_error", "user_interrupt", "unknown"}:
            raise AdapterFailure("invalid_abort_reason")
        with self.state.edit() as editor:
            entry = editor.get(native_session_id)
            if (
                entry is None
                or entry["continuity_handle"] is None
                or entry["turn_handle"] is None
            ):
                return None
            result = self.client.request(
                "turn.abort",
                {
                    "continuity_handle": entry["continuity_handle"],
                    "turn_handle": entry["turn_handle"],
                    "reason": reason,
                },
            )
            editor.set_handles(entry, turn_handle=None)
            return result

    def session_close(self, native_session_id: str) -> Mapping[str, Any] | None:
        with self.state.edit() as editor:
            entry = editor.get(native_session_id)
            if entry is None or entry["continuity_handle"] is None:
                editor.delete(native_session_id)
                return None
            if entry["turn_handle"] is not None:
                self.client.request(
                    "turn.abort",
                    {
                        "continuity_handle": entry["continuity_handle"],
                        "turn_handle": entry["turn_handle"],
                        "reason": "unknown",
                    },
                )
            result = self.client.request(
                "session.close",
                {"continuity_handle": entry["continuity_handle"]},
            )
            editor.delete(native_session_id)
            return result

    def memory_recall(self, query: str, limit: int = 8) -> Mapping[str, Any]:
        text = require_visible_text(query)
        result = self.client.request(
            "memory.recall",
            {
                "query": text,
                "limit": require_limit(limit),
                "maximum_context_bytes": MAX_RECALL_CONTEXT_BYTES,
            },
        )
        self._network_free(result)
        self._context(result)
        return result

    def memory_remember(self, proposal: Mapping[str, Any]) -> Mapping[str, Any]:
        if not isinstance(proposal, Mapping):
            raise AdapterFailure("invalid_proposal")
        _validate_proposal_tree(proposal)
        return self.client.request("memory.remember", {"proposal": dict(proposal)})

    def memory_status(self) -> Mapping[str, Any]:
        return self.client.request("memory.status", {})

    def sync_flush(self) -> Mapping[str, Any]:
        return self.client.request("sync.flush", {})


def generic_error() -> dict[str, Any]:
    return {
        "schema_version": "memory-vault-local-host-result/v1",
        "status": "rejected",
        "error": {"code": "adapter_failure", "retryable": False},
    }


def generic_success(result: Mapping[str, Any] | None) -> dict[str, Any]:
    return {
        "schema_version": "memory-vault-local-host-result/v1",
        "status": "accepted",
        "result": dict(result or {}),
        "authority": dict(REQUIRED_AUTHORITY),
    }
