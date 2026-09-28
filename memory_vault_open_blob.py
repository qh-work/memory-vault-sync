"""Bounded original-byte blob frames and authenticated chunk controls.

A verified header identifies its signer, target and exact bytes. Storage must
separately recheck the local handle, grants, resources and authenticated subject.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
import secrets
import struct
import time
from typing import Any, Mapping

from memory_vault import MemoryError, canonical_bytes
from memory_vault_network_control import _sign, _verify, _window
from memory_vault_network_crypto import (
    PublicKeyTrust, digest, document, integer, object_fields, opaque,
    public_signing_key,
)
from memory_vault_open_control import verify_node

BLOB_PATH = "/open/v1/blob"
PROFILE = "memory-vault-open-blob/v1"
MAX_BLOB_HEADER_BYTES = 8192
MAX_BLOB_CHUNK_BYTES = 262144
BLOB_PREFIX_BYTES = 14
MAX_BLOB_FRAME_BYTES = BLOB_PREFIX_BYTES + MAX_BLOB_HEADER_BYTES + MAX_BLOB_CHUNK_BYTES
MAX_BLOB_OBJECT_BYTES = 6 * 1024 * 1024
MAGIC = b"MVOB1\0"
COMMON = {"schema_version", "kind", "signing_key", "issued_at", "expires_at",
          "request_id", "node_key_id", "storage_epoch", "action", "body"}


class BlobError(MemoryError):
    pass


def _fail(code):
    raise BlobError("open_blob_" + code)


@dataclass(frozen=True)
class BlobFrame:
    header: Mapping[str, Any]
    chunk: bytes


def _signed_header(value):
    header = document(value, maximum=MAX_BLOB_HEADER_BYTES)
    raw = canonical_bytes(header)
    if not 1 <= len(raw) <= MAX_BLOB_HEADER_BYTES:
        _fail("header_size")
    header = document(raw, maximum=MAX_BLOB_HEADER_BYTES)
    object_fields(header, {"payload", "proof"}, "open_blob_invalid_header")
    if not isinstance(header["payload"], Mapping) or not isinstance(header["proof"], Mapping):
        _fail("invalid_header")
    if isinstance(value, bytes) and value != raw:
        _fail("noncanonical_header")
    nodes = 0

    def visit(item, depth):
        nonlocal nodes
        nodes += 1
        if nodes > 1024 or depth > 16:
            _fail("header_complexity")
        children = item.values() if isinstance(item, Mapping) else item if isinstance(item, list) else ()
        for child in children:
            visit(child, depth + 1)

    visit(header, 0)
    return header, raw


def encode_blob_frame(header, chunk: bytes) -> bytes:
    if not isinstance(chunk, bytes) or len(chunk) > MAX_BLOB_CHUNK_BYTES:
        _fail("chunk_size")
    _, raw = _signed_header(header)
    return MAGIC + struct.pack(">II", len(raw), len(chunk)) + raw + chunk


def decode_blob_frame(frame: bytes) -> BlobFrame:
    if not isinstance(frame, bytes) or not BLOB_PREFIX_BYTES + 1 <= len(frame) <= MAX_BLOB_FRAME_BYTES:
        _fail("frame_size")
    if frame[:6] != MAGIC:
        _fail("frame_magic")
    header_size, chunk_size = struct.unpack_from(">II", frame, 6)
    if not 1 <= header_size <= MAX_BLOB_HEADER_BYTES:
        _fail("header_size")
    if chunk_size > MAX_BLOB_CHUNK_BYTES:
        _fail("chunk_size")
    if BLOB_PREFIX_BYTES + header_size + chunk_size != len(frame):
        _fail("frame_length")
    header, _ = _signed_header(frame[BLOB_PREFIX_BYTES:BLOB_PREFIX_BYTES + header_size])
    return BlobFrame(header, frame[BLOB_PREFIX_BYTES + header_size:])


def _now(now):
    return int(time.time()) if now is None else integer(now)


def _identifier(value, prefix):
    if not isinstance(value, str) or re.fullmatch(re.escape(prefix) + r"[0-9a-f]{64}", value) is None:
        _fail("invalid_identifier")
    return value


def _ref(value):
    raw = object_fields(value, {"namespace", "key", "raw_sha256", "size"}, "open_blob_invalid_ref")
    if raw["namespace"] not in ("object", "meta"):
        _fail("invalid_ref")
    digest(raw["key"])
    digest(raw["raw_sha256"])
    if integer(raw["size"], minimum=1) > MAX_BLOB_OBJECT_BYTES:
        _fail("object_size")
    return raw


def _chunk_range(body):
    _identifier(body["handle_id"], "blob_")
    ref = _ref(body["ref"])
    offset, length = integer(body["offset"]), integer(body["length"], minimum=1)
    if offset >= ref["size"] or offset % MAX_BLOB_CHUNK_BYTES != 0 or length != min(MAX_BLOB_CHUNK_BYTES, ref["size"] - offset):
        _fail("invalid_chunk_range")


def _request_body(action, value):
    if action not in ("upload.chunk", "download.chunk"):
        _fail("invalid_action")
    names = {"handle_id", "ref", "offset", "length"}
    body = object_fields(value, names | ({"chunk_sha256"} if action == "upload.chunk" else set()), "open_blob_invalid_body")
    _chunk_range(body)
    if action == "upload.chunk":
        digest(body["chunk_sha256"])
    return body


def _response_body(action, value, wanted):
    if isinstance(value, Mapping) and "error" in value:
        body = object_fields(value, {"error"}, "open_blob_invalid_body")
        error = object_fields(body["error"], {"code", "retryable"}, "open_blob_invalid_body")
        if (not isinstance(error["code"], str) or re.fullmatch(r"[a-z][a-z0-9_]{1,63}", error["code"]) is None
                or type(error["retryable"]) is not bool):
            _fail("invalid_body")
        return body
    names = {"handle_id", "ref", "offset", "length", "chunk_sha256"}
    body = object_fields(value, names | ({"durable_prefix"} if action == "upload.chunk" else set()), "open_blob_invalid_body")
    _chunk_range(body)
    digest(body["chunk_sha256"])
    if any(body[name] != wanted[name] for name in ("handle_id", "ref", "offset", "length")):
        _fail("response_mismatch")
    if action == "upload.chunk":
        prefix = integer(body["durable_prefix"])
        if (body["chunk_sha256"] != wanted["chunk_sha256"] or not body["offset"] + body["length"] <= prefix <= body["ref"]["size"]
                or (prefix != body["ref"]["size"] and prefix % MAX_BLOB_CHUNK_BYTES != 0)):
            _fail("response_mismatch")
    return body


def _verify_header(value, kind, node, now):
    signed, _ = _signed_header(value)
    names = COMMON | ({"request_sha256", "requester_key_id"} if kind == "blob.response" else set())
    raw = object_fields(signed["payload"], names, "open_blob_invalid_header")
    if raw["schema_version"] != PROFILE or raw["kind"] != kind:
        _fail("wrong_schema")
    signer = public_signing_key(raw["signing_key"])
    _window(raw, maximum=60, now=now)
    _identifier(raw["request_id"], "rpc_")
    _identifier(raw["node_key_id"], "ed25519_")
    opaque(raw["storage_epoch"])
    if raw["action"] not in ("upload.chunk", "download.chunk"):
        _fail("invalid_action")
    target = verify_node(node, now=now)
    if (target["status"] != "active" or raw["node_key_id"] != target["signing_key"]["key_id"]
            or raw["storage_epoch"] != target["storage_epoch"]):
        _fail("wrong_node")
    if kind == "blob.response":
        digest(raw["request_sha256"])
        _identifier(raw["requester_key_id"], "ed25519_")
        if signer != target["signing_key"]:
            _fail("wrong_node")
    _verify(signed, PublicKeyTrust([signer]))
    return raw


def sign_blob_request(signer, *, node, action, handle_id, ref, offset, length, chunk=None, now=None):
    now = _now(now)
    target = verify_node(node, now=now)
    body = {"handle_id": handle_id, "ref": ref, "offset": offset, "length": length}
    if action == "upload.chunk":
        if not isinstance(chunk, bytes) or len(chunk) != length or len(chunk) > MAX_BLOB_CHUNK_BYTES:
            _fail("chunk_size")
        body["chunk_sha256"] = hashlib.sha256(chunk).hexdigest()
    elif chunk is not None and chunk != b"":
        _fail("unexpected_chunk")
    _request_body(action, body)
    signed = _sign({"schema_version": PROFILE, "kind": "blob.request", "signing_key": signer.public_descriptor(),
                    "issued_at": now, "expires_at": integer(now + 60), "request_id": "rpc_" + secrets.token_hex(32),
                    "node_key_id": target["signing_key"]["key_id"], "storage_epoch": target["storage_epoch"],
                    "action": action, "body": body}, signer)
    verify_blob_request(signed, node=node, now=now)
    return signed


def verify_blob_request(value, *, node, now=None):
    raw = _verify_header(value, "blob.request", node, _now(now))
    _request_body(raw["action"], raw["body"])
    return raw


def sign_blob_response(signer, *, request, node, body, now=None):
    now = _now(now)
    original = verify_blob_request(request, node=node, now=now)
    _response_body(original["action"], body, original["body"])
    _, request_bytes = _signed_header(request)
    signed = _sign({"schema_version": PROFILE, "kind": "blob.response", "signing_key": signer.public_descriptor(),
                    "issued_at": now, "expires_at": min(integer(now + 60), original["expires_at"]),
                    "request_id": original["request_id"], "request_sha256": hashlib.sha256(request_bytes).hexdigest(),
                    "requester_key_id": original["signing_key"]["key_id"], "node_key_id": original["node_key_id"],
                    "storage_epoch": original["storage_epoch"], "action": original["action"], "body": body}, signer)
    verify_blob_response(signed, request=request, node=node, now=now)
    return signed


def verify_blob_response(value, *, request, node, now=None):
    now = _now(now)
    original = verify_blob_request(request, node=node, now=now)
    raw = _verify_header(value, "blob.response", node, now)
    _, request_bytes = _signed_header(request)
    if (raw["request_id"] != original["request_id"] or raw["request_sha256"] != hashlib.sha256(request_bytes).hexdigest()
            or raw["requester_key_id"] != original["signing_key"]["key_id"] or raw["action"] != original["action"]
            or raw["expires_at"] > original["expires_at"]):
        _fail("response_mismatch")
    _response_body(raw["action"], raw["body"], original["body"])
    return raw
