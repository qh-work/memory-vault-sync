"""Disjoint encrypted payloads: transport never manufactures recollection."""
from __future__ import annotations

from typing import Any, Mapping
import re

from memory_vault import MemoryError, canonical_bytes, strict_json_loads
from memory_vault_network_crypto import document, unb64url

CONTENT_SCHEMA = "memory-vault-network-content/v2"
MAX_CONTENT_TEXT_BYTES = 16384
MAX_CONTENT_SHARE_BYTES = 2 * 1024 * 1024
MAX_CONTENT_BYTES = 4 * 1024 * 1024
HINT_SCHEMA = "memory-vault-hint/v1"
HINT_TYPES = {"observation", "experiment", "inference", "hearsay", "speculation", "summary", "external_source", "unspecified"}


def hint_identifier(value: Any, *, memory: bool = False) -> bool:
    return isinstance(value, str) and re.fullmatch(r"mem_[0-9a-f]{40}" if memory else r"msg_[0-9a-f]{64}", value) is not None


def hint_expiry(value: Any) -> bool:
    return type(value) is int and 1 <= value <= 2**53 - 1


def validate_control(value: Any) -> dict[str, Any]:
    try:
        control = document(value, maximum=4096)
        kind = control.get("kind")
        if control.get("schema_version") != HINT_SCHEMA:
            raise ValueError()
        fields = {"schema_version", "kind"}
        if kind == "query":
            fields |= {"query"}
            valid = isinstance(control.get("query"), str) and 1 <= len(control["query"].encode("utf-8")) <= 256
        elif kind == "select":
            fields |= {"offer_message_id", "memory_id"}
            valid = hint_identifier(control.get("offer_message_id")) and hint_identifier(control.get("memory_id"), memory=True)
        elif kind == "refusal":
            fields |= {"request_message_id", "reason"}
            valid = hint_identifier(control.get("request_message_id")) and control.get("reason") == "not_available"
        elif kind == "hints":
            fields |= {"request_message_id", "expires_at", "hints"}
            items = control.get("hints")
            valid = (hint_identifier(control.get("request_message_id")) and hint_expiry(control.get("expires_at"))
                     and isinstance(items, list) and len(items) <= 4)
            if valid:
                ids = set()
                for item in items:
                    if (not isinstance(item, dict) or set(item) != {"memory_id", "excerpt", "epistemic_type"}
                            or not hint_identifier(item.get("memory_id"), memory=True) or item["memory_id"] in ids
                            or not isinstance(item.get("excerpt"), str) or len(item["excerpt"].encode("utf-8")) > 128
                            or not isinstance(item.get("epistemic_type"), str) or item["epistemic_type"] not in HINT_TYPES):
                        valid = False
                        break
                    ids.add(item["memory_id"])
        else:
            valid = False
        if not valid or set(control) != fields or len(canonical_bytes(control)) > 4096:
            raise ValueError()
        return control
    except (MemoryError, ValueError, TypeError, UnicodeError, RecursionError):
        raise MemoryError("network_invalid_content") from None


def validate_content(value: bytes | Mapping[str, Any]) -> dict[str, Any]:
    """Validate restored queues and decrypted bodies with identical semantics.

    A memory transfer still requires the existing canonical/share verifier.
    The earlier preview payload is deliberately unsupported, never inferred.
    """
    try:
        content = document(value, maximum=MAX_CONTENT_BYTES)
    except (MemoryError, UnicodeError, RecursionError):
        # Preserve the earlier message JSON errors; well-formed Hint objects
        # with disallowed control numbers use the closed Hint schema error.
        try:
            candidate = strict_json_loads(value) if isinstance(value, bytes) and len(value) <= MAX_CONTENT_BYTES else value
            kind = candidate.get("kind") if isinstance(candidate, Mapping) else None
            if isinstance(kind, str) and kind in {"hint_control", "hint_transfer"}:
                raise MemoryError("network_invalid_content")
        except MemoryError as exc:
            if exc.code == "network_invalid_content":
                raise
        raise MemoryError("network_invalid_content_json") from None
    if content.get("schema_version") != CONTENT_SCHEMA:
        raise MemoryError("network_unsupported_content_schema")
    kind = content.get("kind")
    if kind == "hint_control":
        if set(content) != {"schema_version", "kind", "control"}:
            raise MemoryError("network_invalid_content")
        validate_control(content["control"])
        return content
    if kind == "hint_transfer":
        if (set(content) != {"schema_version", "kind", "request_message_id", "offer_message_id", "memory_id", "expires_at", "share"}
                or not hint_identifier(content.get("request_message_id")) or not hint_identifier(content.get("offer_message_id"))
                or not hint_identifier(content.get("memory_id"), memory=True) or not hint_expiry(content.get("expires_at"))):
            raise MemoryError("network_invalid_content")
        try:
            unb64url(content["share"], maximum=MAX_CONTENT_SHARE_BYTES)
        except (MemoryError, TypeError):
            raise MemoryError("network_invalid_content") from None
        return content
    if kind == "message":
        fields, key = {"schema_version", "kind", "text"}, "text"
    elif kind == "memory_transfer":
        fields, key = {"schema_version", "kind", "note", "share"}, "note"
    else:
        raise MemoryError("network_invalid_content")
    if (set(content) != fields or not isinstance(content[key], str)
            or (kind == "message" and not content[key])
            or len(content[key].encode("utf-8")) > MAX_CONTENT_TEXT_BYTES):
        raise MemoryError("network_invalid_content")
    if kind == "memory_transfer":
        try:
            unb64url(content["share"], maximum=MAX_CONTENT_SHARE_BYTES)
        except MemoryError:
            raise MemoryError("network_invalid_content_share_encoding") from None
    return content


def content_text(content: Mapping[str, Any]) -> str:
    return content["text"] if content["kind"] == "message" else content["note"] if content["kind"] == "memory_transfer" else ""
