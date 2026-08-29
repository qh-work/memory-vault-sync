"""Strict model-neutral lifecycle protocol for one shared Memory Vault.

The protocol is intentionally smaller than any host hook surface. Claude,
Gemini, local agents, and future runtimes translate only visible lifecycle
events into these messages. The Vault issues local continuity handles; native
conversation identifiers, model names, tasks, permissions, and execution
requests are not part of the protocol.

This module performs no filesystem, Git, model, or network work. It validates
bounded JSON values and constructs content-safe response envelopes. The core
runtime owns receipts, durable queuing, recall, and synchronization.
"""

from __future__ import annotations

import dataclasses
import re
import secrets
from typing import Any, Mapping, Sequence

from memory_vault_runtime.errors import HostProtocolError


PROTOCOL_VERSION = "1.0"
REQUEST_SCHEMA = "memory-vault-host-request/v1"
RESPONSE_SCHEMA = "memory-vault-host-response/v1"
REQUEST_RECEIPT_SCHEMA = "memory-vault-host-request-receipt/v1"
MAX_REQUEST_BYTES = 3 * 1024 * 1024
MAX_REQUEST_ID_BYTES = 160
MAX_ADAPTER_ID_BYTES = 64
MAX_VERSION_BYTES = 64
MAX_HOST_FAMILY_BYTES = 64
MAX_STRUCTURE_DEPTH = 12
MAX_STRUCTURE_NODES = 16_384
DEFAULT_RECALL_LIMIT = 8
MAX_RECALL_LIMIT = 32
DEFAULT_RECALL_CONTEXT_BYTES = 8 * 1024
MIN_RECALL_CONTEXT_BYTES = 512
MAX_RECALL_CONTEXT_BYTES = 64 * 1024

OPERATIONS = (
    "capabilities",
    "session.open",
    "turn.input",
    "turn.commit",
    "turn.abort",
    "session.close",
    "memory.recall",
    "memory.remember",
    "memory.status",
    "sync.flush",
)

NETWORK_FREE_OPERATIONS = frozenset(
    {
        "capabilities",
        "turn.input",
        "turn.commit",
        "turn.abort",
        "session.close",
        "memory.recall",
        "memory.status",
    }
)

MUTATING_RECEIPT_OPERATIONS = frozenset(
    {"session.open", "turn.input", "turn.commit", "turn.abort", "session.close"}
)

_REQUEST_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@+-]{0,159}")
_SLUG_RE = re.compile(r"[a-z0-9][a-z0-9._-]{1,63}")
_VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?")
_CONTINUITY_HANDLE_RE = re.compile(r"mvc1_[A-Za-z0-9_-]{43}")
_TURN_HANDLE_RE = re.compile(r"mvt1_[A-Za-z0-9_-]{43}")

# These names are excluded even inside semantic proposal payloads. They are
# authority, execution, native-host, or ownership concepts rather than memory.
_FORBIDDEN_KEYS = frozenset(
    {
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
        "authorization",
        "permission",
        "policy",
        "consent",
        "role_escalation",
        "execute",
        "command",
        "shell",
        "tool_call",
        "agent_spawn",
        "resource",
        "resource_expand",
        "system_prompt",
        "developer_message",
        "chain_of_thought",
        "hidden_reasoning",
        "confidence",
    }
)


@dataclasses.dataclass(frozen=True)
class AdapterIdentity:
    adapter_id: str
    version: str
    host_family: str


@dataclasses.dataclass(frozen=True)
class HostRequest:
    request_id: str
    operation: str
    adapter: AdapterIdentity
    payload: Mapping[str, Any]


def _exact_object(
    value: Any,
    *,
    required: set[str],
    optional: set[str] = frozenset(),
    label: str,
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise HostProtocolError(f"{label} is not an object")
    observed = set(value)
    if not required.issubset(observed) or not observed.issubset(
        required | optional
    ):
        raise HostProtocolError(f"{label} has an invalid shape")
    return value


def _bounded_text(
    value: Any,
    label: str,
    *,
    maximum_bytes: int,
) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise HostProtocolError(f"{label} is invalid")
    if len(value.encode("utf-8")) > maximum_bytes:
        raise HostProtocolError(f"{label} exceeds the fixed limit")
    return value


def _optional_visible_text(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return _bounded_text(value, label, maximum_bytes=2 * 1024 * 1024)


def _adapter_identity(value: Any) -> AdapterIdentity:
    raw = _exact_object(
        value,
        required={"id", "version", "host_family"},
        label="adapter",
    )
    adapter_id = _bounded_text(
        raw.get("id"), "adapter id", maximum_bytes=MAX_ADAPTER_ID_BYTES
    )
    version = _bounded_text(
        raw.get("version"), "adapter version", maximum_bytes=MAX_VERSION_BYTES
    )
    host_family = _bounded_text(
        raw.get("host_family"),
        "adapter host family",
        maximum_bytes=MAX_HOST_FAMILY_BYTES,
    )
    if _SLUG_RE.fullmatch(adapter_id) is None:
        raise HostProtocolError("adapter id is invalid")
    if _VERSION_RE.fullmatch(version) is None:
        raise HostProtocolError("adapter version is invalid")
    if _SLUG_RE.fullmatch(host_family) is None:
        raise HostProtocolError("adapter host family is invalid")
    return AdapterIdentity(adapter_id, version, host_family)


def validate_continuity_handle(value: Any) -> str:
    if not isinstance(value, str) or _CONTINUITY_HANDLE_RE.fullmatch(value) is None:
        raise HostProtocolError("continuity handle is invalid")
    return value


def validate_turn_handle(value: Any) -> str:
    if not isinstance(value, str) or _TURN_HANDLE_RE.fullmatch(value) is None:
        raise HostProtocolError("turn handle is invalid")
    return value


def new_continuity_handle() -> str:
    return "mvc1_" + secrets.token_urlsafe(32)


def new_turn_handle() -> str:
    return "mvt1_" + secrets.token_urlsafe(32)


def _optional_handle(value: Any, *, turn: bool) -> str | None:
    if value is None:
        return None
    return validate_turn_handle(value) if turn else validate_continuity_handle(value)


def _positive_int(
    value: Any,
    label: str,
    *,
    maximum: int,
    minimum: int = 1,
) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < minimum
        or value > maximum
    ):
        raise HostProtocolError(f"{label} is invalid")
    return value


def _validate_tree(value: Any) -> None:
    """Reject ambiguous JSON values and authority-shaped proposal keys."""

    nodes = 0

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_STRUCTURE_NODES or depth > MAX_STRUCTURE_DEPTH:
            raise HostProtocolError("host request structure exceeds the fixed limit")
        if item is None or isinstance(item, (str, bool, int)):
            return
        if isinstance(item, float):
            raise HostProtocolError("floating point host values are forbidden")
        if isinstance(item, Mapping):
            for key, child in item.items():
                if not isinstance(key, str):
                    raise HostProtocolError("host request key is invalid")
                normalized = key.casefold().replace("-", "_")
                if normalized in _FORBIDDEN_KEYS:
                    raise HostProtocolError("host request contains a forbidden field")
                visit(child, depth + 1)
            return
        if isinstance(item, Sequence) and not isinstance(
            item, (str, bytes, bytearray)
        ):
            for child in item:
                visit(child, depth + 1)
            return
        raise HostProtocolError("host request contains an unsupported value")

    visit(value, 0)


def _validate_payload(operation: str, value: Any) -> Mapping[str, Any]:
    if operation in {"capabilities", "memory.status", "sync.flush"}:
        return _exact_object(value, required=set(), label=f"{operation} payload")

    if operation == "session.close":
        raw = _exact_object(
            value, required={"continuity_handle"}, label="session.close payload"
        )
        validate_continuity_handle(raw.get("continuity_handle"))
        return raw

    if operation == "session.open":
        raw = _exact_object(
            value,
            required={"continuity_handle", "reason"},
            label="session.open payload",
        )
        _optional_handle(raw.get("continuity_handle"), turn=False)
        if raw.get("reason") not in {"startup", "resume", "clear", "compact"}:
            raise HostProtocolError("session.open reason is invalid")
        return raw

    if operation == "turn.input":
        raw = _exact_object(
            value,
            required={
                "continuity_handle",
                "turn_handle",
                "visible_user_text",
                "limit",
            },
            label="turn.input payload",
        )
        validate_continuity_handle(raw.get("continuity_handle"))
        _optional_handle(raw.get("turn_handle"), turn=True)
        _bounded_text(
            raw.get("visible_user_text"),
            "visible user text",
            maximum_bytes=2 * 1024 * 1024,
        )
        _positive_int(raw.get("limit"), "recall limit", maximum=MAX_RECALL_LIMIT)
        return raw

    if operation == "turn.commit":
        raw = _exact_object(
            value,
            required={
                "continuity_handle",
                "turn_handle",
                "outcome",
                "visible_user_text",
                "visible_assistant_text",
            },
            label="turn.commit payload",
        )
        validate_continuity_handle(raw.get("continuity_handle"))
        turn_handle = _optional_handle(raw.get("turn_handle"), turn=True)
        outcome = raw.get("outcome")
        if outcome != "final":
            raise HostProtocolError("turn.commit outcome is invalid")
        user_text = _optional_visible_text(
            raw.get("visible_user_text"), "visible user text"
        )
        assistant_text = _optional_visible_text(
            raw.get("visible_assistant_text"), "visible assistant text"
        )
        if assistant_text is None:
            raise HostProtocolError("final turn has no visible assistant text")
        if turn_handle is None and user_text is None:
            raise HostProtocolError("atomic turn commit requires visible user text")
        return raw

    if operation == "turn.abort":
        raw = _exact_object(
            value,
            required={"continuity_handle", "turn_handle", "reason"},
            label="turn.abort payload",
        )
        validate_continuity_handle(raw.get("continuity_handle"))
        validate_turn_handle(raw.get("turn_handle"))
        if raw.get("reason") not in {
            "cancelled",
            "host_error",
            "user_interrupt",
            "unknown",
        }:
            raise HostProtocolError("turn.abort reason is invalid")
        return raw

    if operation == "memory.recall":
        raw = _exact_object(
            value,
            required={"query", "limit", "maximum_context_bytes"},
            label="memory.recall payload",
        )
        _bounded_text(
            raw.get("query"), "memory recall query", maximum_bytes=64 * 1024
        )
        _positive_int(raw.get("limit"), "recall limit", maximum=MAX_RECALL_LIMIT)
        _positive_int(
            raw.get("maximum_context_bytes"),
            "recall context bytes",
            maximum=MAX_RECALL_CONTEXT_BYTES,
            minimum=MIN_RECALL_CONTEXT_BYTES,
        )
        return raw

    if operation == "memory.remember":
        raw = _exact_object(
            value, required={"proposal"}, label="memory.remember payload"
        )
        proposal = _exact_object(
            raw.get("proposal"),
            required={
                "schema_version",
                "source_id",
                "episode_id",
                "kind",
                "claim_key",
                "parents",
                "supersedes",
                "conflicts_with",
                "resolves",
                "payload",
            },
            label="semantic memory proposal",
        )
        if proposal.get("schema_version") != (
            "memory-network-semantic-proposal/v1"
        ):
            raise HostProtocolError("semantic memory proposal is invalid")
        if not isinstance(proposal.get("source_id"), str) or re.fullmatch(
            r"src-[0-9a-f]{40}", proposal["source_id"]
        ) is None:
            raise HostProtocolError("semantic memory source is invalid")
        if not isinstance(proposal.get("episode_id"), str) or re.fullmatch(
            r"ep-[0-9a-f]{40}", proposal["episode_id"]
        ) is None:
            raise HostProtocolError("semantic memory episode is invalid")
        if proposal.get("kind") not in {
            "decision",
            "constraint",
            "progress",
            "next_action",
            "hypothesis",
            "artifact_created",
            "artifact_verified",
            "correction",
            "user_preference",
            "conflict_declared",
            "conflict_resolved",
            "checkpoint_note",
        }:
            raise HostProtocolError("semantic memory kind is invalid")
        claim_key = proposal.get("claim_key")
        if claim_key is not None and (
            not isinstance(claim_key, str)
            or re.fullmatch(r"[a-z0-9][a-z0-9_-]{1,63}", claim_key) is None
        ):
            raise HostProtocolError("semantic memory claim key is invalid")
        for relation in (
            "parents",
            "supersedes",
            "conflicts_with",
            "resolves",
        ):
            targets = proposal.get(relation)
            if (
                not isinstance(targets, list)
                or len(targets) > 128
                or any(
                    not isinstance(target, str)
                    or re.fullmatch(r"evt-[0-9a-f]{40}", target) is None
                    for target in targets
                )
                or len(targets) != len(set(targets))
            ):
                raise HostProtocolError(
                    "semantic memory relation is invalid"
                )
        claim = _exact_object(
            proposal.get("payload"),
            required={"statement", "reason", "concepts"},
            label="semantic memory claim",
        )
        _bounded_text(
            claim.get("statement"),
            "semantic memory statement",
            maximum_bytes=16 * 1024,
        )
        reason = claim.get("reason")
        if reason is not None:
            _bounded_text(
                reason,
                "semantic memory reason",
                maximum_bytes=8 * 1024,
            )
        concepts = claim.get("concepts")
        if (
            not isinstance(concepts, list)
            or len(concepts) > 64
            or any(not isinstance(concept, str) for concept in concepts)
            or len(concepts) != len(set(concepts))
        ):
            raise HostProtocolError("semantic memory concepts are invalid")
        for concept in concepts:
            _bounded_text(
                concept,
                "semantic memory concept",
                maximum_bytes=128,
            )
        return raw

    raise HostProtocolError("host operation is unsupported")


def validate_request(value: Any) -> HostRequest:
    raw = _exact_object(
        value,
        required={
            "schema_version",
            "protocol_version",
            "request_id",
            "operation",
            "adapter",
            "payload",
        },
        label="host request",
    )
    if raw.get("schema_version") != REQUEST_SCHEMA:
        raise HostProtocolError("host request schema is unsupported")
    if raw.get("protocol_version") != PROTOCOL_VERSION:
        raise HostProtocolError("host protocol major is unsupported")
    request_id = _bounded_text(
        raw.get("request_id"),
        "request id",
        maximum_bytes=MAX_REQUEST_ID_BYTES,
    )
    if _REQUEST_ID_RE.fullmatch(request_id) is None:
        raise HostProtocolError("request id is invalid")
    operation = raw.get("operation")
    if operation not in OPERATIONS:
        raise HostProtocolError("host operation is unsupported")
    adapter = _adapter_identity(raw.get("adapter"))
    payload = _validate_payload(str(operation), raw.get("payload"))
    # Apply the recursive authority/ownership/value-domain check only after
    # structural validation so ordinary shape errors remain deterministic.
    _validate_tree(payload)
    return HostRequest(request_id, str(operation), adapter, payload)


def request_document(request: HostRequest) -> dict[str, Any]:
    """Return the exact canonical request domain used by local receipts."""

    return {
        "schema_version": REQUEST_SCHEMA,
        "protocol_version": PROTOCOL_VERSION,
        "request_id": request.request_id,
        "operation": request.operation,
        "adapter": {
            "id": request.adapter.adapter_id,
            "version": request.adapter.version,
            "host_family": request.adapter.host_family,
        },
        "payload": dict(request.payload),
    }


def authority_labels() -> dict[str, Any]:
    return {
        "memory": "untrusted_historical_evidence",
        "instruction_eligible": False,
        "authorization_eligible": False,
        "execution_eligible": False,
        "policy_change_eligible": False,
        "current_user_input_precedence": True,
    }


def success_response(
    request: HostRequest,
    *,
    status: str,
    result: Mapping[str, Any],
) -> dict[str, Any]:
    if status not in {
        "accepted_local",
        "published",
        "duplicate",
        "degraded",
    }:
        raise HostProtocolError("host response status is invalid")
    return {
        "schema_version": RESPONSE_SCHEMA,
        "protocol_version": PROTOCOL_VERSION,
        "request_id": request.request_id,
        "operation": request.operation,
        "status": status,
        "authority": authority_labels(),
        "result": dict(result),
    }


def error_response(
    *,
    request_id: str | None,
    operation: str | None,
    code: str,
    retryable: bool,
) -> dict[str, Any]:
    safe_request_id = (
        request_id
        if isinstance(request_id, str)
        and len(request_id.encode("utf-8")) <= MAX_REQUEST_ID_BYTES
        and _REQUEST_ID_RE.fullmatch(request_id) is not None
        else None
    )
    safe_operation = operation if operation in OPERATIONS else None
    return {
        "schema_version": RESPONSE_SCHEMA,
        "protocol_version": PROTOCOL_VERSION,
        "request_id": safe_request_id,
        "operation": safe_operation,
        "status": "rejected",
        "authority": authority_labels(),
        "error": {
            "code": code if _SLUG_RE.fullmatch(code) is not None else "rejected",
            "retryable": bool(retryable),
        },
    }


def capability_result() -> dict[str, Any]:
    return {
        "protocol_versions": [PROTOCOL_VERSION],
        "operations": list(OPERATIONS),
        "network_free_operations": sorted(NETWORK_FREE_OPERATIONS),
        "transport": {
            "encoding": "utf-8",
            "framing": "one-json-object-per-line",
            "maximum_request_bytes": MAX_REQUEST_BYTES,
        },
        "memory_model": "taskless_associative_append_only",
        "delivery": "at_least_once_exact_effect",
        "handles": {
            "issuer": "vault_runtime",
            "installation_local": True,
            "ownership": False,
            "authorization": False,
        },
        "recall": {
            "local_only": True,
            "untrusted_historical_evidence": True,
            "current_user_input_precedence": True,
            "default_limit": DEFAULT_RECALL_LIMIT,
            "maximum_limit": MAX_RECALL_LIMIT,
            "default_context_bytes": DEFAULT_RECALL_CONTEXT_BYTES,
            "minimum_context_bytes": MIN_RECALL_CONTEXT_BYTES,
            "maximum_context_bytes": MAX_RECALL_CONTEXT_BYTES,
        },
        "commit": {
            "durable_local_ack_before_network": True,
            "atomic_visible_turn_supported": True,
            "same_handle_different_content": "hard_conflict",
        },
    }
