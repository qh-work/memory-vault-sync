"""Versioned encrypted-chunk manifest primitives.

This module deliberately owns no provider calls.  The runtime places every
policy, manifest, and chunk path inside a verified rclone/crypt boundary; the
functions here define the deterministic plaintext protocol used before that
encryption boundary.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Mapping, Sequence

from memory_vault_runtime.protocol import persisted_json_bytes


CHUNK_POLICY_SCHEMA = "memory-vault-chunk-policy/v1"
CHUNK_MANIFEST_SCHEMA = "memory-vault-chunk-manifest/v1"
CHUNK_RECEIPT_SCHEMA = "memory-vault-chunk-verification/v1"
CHUNK_READER_PROTOCOL = "encrypted-fixed-chunks-v1"
CHUNK_ALGORITHM = "fixed-16m-domain-sha256-v1"
CHUNK_ENCRYPTION_POLICY = "rclone-crypt-standard-v1"
CHUNK_SIZE_BYTES = 16 * 1024 * 1024
MAX_CHUNK_COUNT = 4096
MAX_CHUNK_MANIFEST_BYTES = 2 * 1024 * 1024
DEFAULT_CHUNK_MINIMUM_BYTES = 32 * 1024 * 1024
CHUNK_POLICY_PATH = ".memory-vault-chunk-policy.json"
CHUNK_ROOT = "chunks/v1"
CHUNK_MANIFEST_ROOT = "chunk-manifests/v1"

_CHUNK_HASH_DOMAIN = b"memory-vault-sync\x00plaintext-chunk\x00v1\x00"
_MANIFEST_HASH_DOMAIN = b"memory-vault-sync\x00chunk-manifest\x00v1\x00"
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$")


class ChunkProtocolError(ValueError):
    """A policy or manifest is outside the fixed v1 protocol domain."""


def _hex64(value: Any, label: str) -> str:
    if not isinstance(value, str) or _HEX64_RE.fullmatch(value) is None:
        raise ChunkProtocolError(f"{label} is invalid")
    return value


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        raise ChunkProtocolError(f"{label} is invalid")
    return value


def chunk_content_id(payload: bytes) -> str:
    """Return a domain-separated identity for one non-empty plaintext chunk."""

    if not isinstance(payload, bytes) or not payload:
        raise ChunkProtocolError("chunk payload must be non-empty bytes")
    if len(payload) > CHUNK_SIZE_BYTES:
        raise ChunkProtocolError("chunk payload exceeds the fixed size")
    return hashlib.sha256(_CHUNK_HASH_DOMAIN + payload).hexdigest()


def new_chunk_hasher() -> Any:
    """Return the fixed domain-seeded hasher for bounded streaming reads."""

    return hashlib.sha256(_CHUNK_HASH_DOMAIN)


def policy_document(
    *,
    vault_id: str,
    store_id: str,
    container_id: str,
    remote_fingerprint: str,
    key_epoch: str,
) -> dict[str, Any]:
    value = {
        "schema_version": CHUNK_POLICY_SCHEMA,
        "reader_protocol": CHUNK_READER_PROTOCOL,
        "algorithm": CHUNK_ALGORITHM,
        "encryption_policy": CHUNK_ENCRYPTION_POLICY,
        "vault_id": _identifier(vault_id, "chunk policy vault_id"),
        "store_id": _identifier(store_id, "chunk policy store_id"),
        "container_id": _identifier(
            container_id,
            "chunk policy container_id",
        ),
        "remote_fingerprint": _hex64(
            remote_fingerprint,
            "chunk policy remote_fingerprint",
        ),
        "key_epoch": _hex64(key_epoch, "chunk policy key_epoch"),
        "chunk_size": CHUNK_SIZE_BYTES,
        "maximum_chunks": MAX_CHUNK_COUNT,
        "maximum_manifest_bytes": MAX_CHUNK_MANIFEST_BYTES,
    }
    return validate_policy(
        value,
        vault_id=vault_id,
        store_id=store_id,
        container_id=container_id,
        remote_fingerprint=remote_fingerprint,
    )


def validate_policy(
    value: Any,
    *,
    vault_id: str,
    store_id: str,
    container_id: str,
    remote_fingerprint: str,
) -> dict[str, Any]:
    fields = {
        "schema_version",
        "reader_protocol",
        "algorithm",
        "encryption_policy",
        "vault_id",
        "store_id",
        "container_id",
        "remote_fingerprint",
        "key_epoch",
        "chunk_size",
        "maximum_chunks",
        "maximum_manifest_bytes",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ChunkProtocolError("chunk policy fields are invalid")
    expected = {
        "schema_version": CHUNK_POLICY_SCHEMA,
        "reader_protocol": CHUNK_READER_PROTOCOL,
        "algorithm": CHUNK_ALGORITHM,
        "encryption_policy": CHUNK_ENCRYPTION_POLICY,
        "vault_id": _identifier(vault_id, "chunk policy vault_id"),
        "store_id": _identifier(store_id, "chunk policy store_id"),
        "container_id": _identifier(
            container_id,
            "chunk policy container_id",
        ),
        "remote_fingerprint": _hex64(
            remote_fingerprint,
            "chunk policy remote_fingerprint",
        ),
        "chunk_size": CHUNK_SIZE_BYTES,
        "maximum_chunks": MAX_CHUNK_COUNT,
        "maximum_manifest_bytes": MAX_CHUNK_MANIFEST_BYTES,
    }
    for key, expected_value in expected.items():
        if value.get(key) != expected_value:
            raise ChunkProtocolError(f"chunk policy {key} changed")
    key_epoch = _hex64(value.get("key_epoch"), "chunk policy key_epoch")
    return {**expected, "key_epoch": key_epoch}


def chunk_relative_path(policy: Mapping[str, Any], content_id: str) -> str:
    epoch = _hex64(policy.get("key_epoch"), "chunk policy key_epoch")
    digest = _hex64(content_id, "chunk content_id")
    return f"{CHUNK_ROOT}/{epoch}/{digest[:2]}/{digest}"


def manifest_relative_path(policy: Mapping[str, Any], manifest_id: str) -> str:
    epoch = _hex64(policy.get("key_epoch"), "chunk policy key_epoch")
    digest = _hex64(manifest_id, "chunk manifest_id")
    return f"{CHUNK_MANIFEST_ROOT}/{epoch}/{digest}.json"


def manifest_document(
    *,
    policy: Mapping[str, Any],
    artifact_sha256: str,
    artifact_size: int,
    mime_type: str,
    chunks: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    value = {
        "schema_version": CHUNK_MANIFEST_SCHEMA,
        "reader_protocol": CHUNK_READER_PROTOCOL,
        "algorithm": CHUNK_ALGORITHM,
        "encryption_policy": CHUNK_ENCRYPTION_POLICY,
        "store_id": policy.get("store_id"),
        "container_id": policy.get("container_id"),
        "remote_fingerprint": policy.get("remote_fingerprint"),
        "key_epoch": policy.get("key_epoch"),
        "artifact_sha256": artifact_sha256,
        "artifact_size": artifact_size,
        "mime_type": mime_type,
        "chunk_size": CHUNK_SIZE_BYTES,
        "chunk_count": len(chunks),
        "total_size": sum(
            int(item.get("size", -1))
            for item in chunks
            if isinstance(item, Mapping)
        ),
        "chunks": [dict(item) for item in chunks],
    }
    return validate_manifest(value, policy=policy)


def validate_manifest(
    value: Any,
    *,
    policy: Mapping[str, Any],
    artifact_sha256: str | None = None,
    artifact_size: int | None = None,
    mime_type: str | None = None,
) -> dict[str, Any]:
    fields = {
        "schema_version",
        "reader_protocol",
        "algorithm",
        "encryption_policy",
        "store_id",
        "container_id",
        "remote_fingerprint",
        "key_epoch",
        "artifact_sha256",
        "artifact_size",
        "mime_type",
        "chunk_size",
        "chunk_count",
        "total_size",
        "chunks",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ChunkProtocolError("chunk manifest fields are invalid")
    fixed = {
        "schema_version": CHUNK_MANIFEST_SCHEMA,
        "reader_protocol": CHUNK_READER_PROTOCOL,
        "algorithm": CHUNK_ALGORITHM,
        "encryption_policy": CHUNK_ENCRYPTION_POLICY,
        "store_id": policy.get("store_id"),
        "container_id": policy.get("container_id"),
        "remote_fingerprint": policy.get("remote_fingerprint"),
        "key_epoch": policy.get("key_epoch"),
        "chunk_size": CHUNK_SIZE_BYTES,
    }
    for key, expected in fixed.items():
        if value.get(key) != expected:
            raise ChunkProtocolError(f"chunk manifest {key} changed")
    digest = _hex64(value.get("artifact_sha256"), "artifact sha256")
    size = value.get("artifact_size")
    if (
        not isinstance(size, int)
        or isinstance(size, bool)
        or size < 1
        or size > CHUNK_SIZE_BYTES * MAX_CHUNK_COUNT
    ):
        raise ChunkProtocolError("artifact size is outside chunk bounds")
    media_type = value.get("mime_type")
    if (
        not isinstance(media_type, str)
        or re.fullmatch(r"[a-z0-9.+-]+/[a-z0-9.+-]+", media_type) is None
    ):
        raise ChunkProtocolError("chunk manifest MIME type is invalid")
    if artifact_sha256 is not None and digest != _hex64(
        artifact_sha256,
        "expected artifact sha256",
    ):
        raise ChunkProtocolError("chunk manifest artifact hash does not match")
    if artifact_size is not None and size != artifact_size:
        raise ChunkProtocolError("chunk manifest artifact size does not match")
    if mime_type is not None and media_type != mime_type:
        raise ChunkProtocolError("chunk manifest MIME type does not match")
    raw_chunks = value.get("chunks")
    expected_count = (size + CHUNK_SIZE_BYTES - 1) // CHUNK_SIZE_BYTES
    if (
        not isinstance(raw_chunks, list)
        or not 1 <= len(raw_chunks) <= MAX_CHUNK_COUNT
        or value.get("chunk_count") != len(raw_chunks)
        or len(raw_chunks) != expected_count
    ):
        raise ChunkProtocolError("chunk manifest count is invalid")
    chunks: list[dict[str, Any]] = []
    total = 0
    for index, raw in enumerate(raw_chunks):
        if not isinstance(raw, Mapping) or set(raw) != {
            "index",
            "offset",
            "size",
            "content_id",
        }:
            raise ChunkProtocolError("chunk descriptor fields are invalid")
        expected_size = min(CHUNK_SIZE_BYTES, size - total)
        if (
            raw.get("index") != index
            or raw.get("offset") != total
            or raw.get("size") != expected_size
        ):
            raise ChunkProtocolError("chunk descriptor sequence is invalid")
        content_id = _hex64(raw.get("content_id"), "chunk content_id")
        chunks.append(
            {
                "index": index,
                "offset": total,
                "size": expected_size,
                "content_id": content_id,
            }
        )
        total += expected_size
    if total != size or value.get("total_size") != total:
        raise ChunkProtocolError("chunk manifest total-size proof is invalid")
    normalized = {
        **fixed,
        "artifact_sha256": digest,
        "artifact_size": size,
        "mime_type": media_type,
        "chunk_count": len(chunks),
        "total_size": total,
        "chunks": chunks,
    }
    if len(manifest_bytes(normalized)) > MAX_CHUNK_MANIFEST_BYTES:
        raise ChunkProtocolError("chunk manifest exceeds the byte bound")
    return normalized


def manifest_bytes(value: Mapping[str, Any]) -> bytes:
    raw = persisted_json_bytes(value)
    if len(raw) > MAX_CHUNK_MANIFEST_BYTES:
        raise ChunkProtocolError("chunk manifest exceeds the byte bound")
    return raw


def manifest_id(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_MANIFEST_HASH_DOMAIN + manifest_bytes(value)).hexdigest()
