"""Disjoint encrypted payloads: transport never manufactures recollection."""
from __future__ import annotations

from typing import Any, Mapping

from memory_vault import MemoryError
from memory_vault_network_crypto import document, unb64url

CONTENT_SCHEMA = "memory-vault-network-content/v2"
MAX_CONTENT_TEXT_BYTES = 16384
MAX_CONTENT_SHARE_BYTES = 2 * 1024 * 1024
MAX_CONTENT_BYTES = 4 * 1024 * 1024


def validate_content(value: bytes | Mapping[str, Any]) -> dict[str, Any]:
    """Validate restored queues and decrypted bodies with identical semantics.

    A memory transfer still requires the existing canonical/share verifier.
    The earlier preview payload is deliberately unsupported, never inferred.
    """
    try:
        content = document(value, maximum=MAX_CONTENT_BYTES)
    except (MemoryError, UnicodeError, RecursionError):
        raise MemoryError("network_invalid_content_json") from None
    if content.get("schema_version") != CONTENT_SCHEMA:
        raise MemoryError("network_unsupported_content_schema")
    kind = content.get("kind")
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
    return content["text"] if content["kind"] == "message" else content["note"]
