#!/usr/bin/env python3
"""Offline, bounded v0.21 production pack/bundle conversion.

The old container is not the current chunk-transfer profile. This module reads
its actual zlib frames, index, taskless catalog and hash-only checkpoints. It
does not run an old runtime, Git, a network client, a key provider or a Vault.
Bodies and graph work lists are held in a private temporary SQLite index, not
in a collection of every old document in memory. Conversion is an explicit,
unsigned projection; original bytes and typed evidence links remain available.
"""

from __future__ import annotations

import argparse
import base64
from collections.abc import Iterator, Mapping, Sequence
from contextlib import closing, contextmanager
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import struct
import sys
import tempfile
from typing import Any, BinaryIO, Callable
import uuid
import zipfile
import zlib

from memory_vault import (
    AUTHORITY, BUNDLE_SCHEMA, HASH_PROFILE, MAX_BUNDLE_LINE_BYTES,
    MAX_BUNDLE_RECORDS, MemoryError, build_record, canonical_bytes, sha256,
    validate_record,
)
import memory_vault_migrate as legacy


PACK_MAGIC = b"memory-pack/v1\n"
INDEX_MAGIC = b"memory-pack-index/v1\n"
PACK_INDEX_SCHEMA = "memory-pack-index/v1"
CHECKPOINT_SCHEMA = "memory-network-checkpoint/v1"
CHECKPOINT_CONTRACT = "memory-network-checkpoint-catalog/v1"
CAPSULE_SCHEMA = "memory-vault-v021-conversion/v1"
MAP_SCHEMA = "memory-vault-v021-identity-map/v1"
RESULT_SCHEMA = "memory-vault-v021-pack-result/v1"
MAX_SOURCE_BYTES = 2 * 1024 * 1024 * 1024
MAX_RAW_BYTES = 2 * 1024 * 1024 * 1024
MAX_DOCUMENTS = 250_000
MAX_OBJECTS = MAX_DOCUMENTS + 1
MAX_MEMBER_BYTES = 2 * 1024 * 1024
MAX_MANIFEST_BYTES = 64 * 1024 * 1024
MAX_PACK_OBJECT_BYTES = 16 * 1024 * 1024
MAX_INDEX_BYTES = 128 * 1024 * 1024
MAX_HEADER_BYTES = 16 * 1024
MAX_CENTRAL_BYTES = 256 * 1024 * 1024
MAX_CHECKPOINT_BYTES = 16 * 1024
MAX_PART_BYTES = 32 * 1024 * 1024
MAX_MAP_PART_BYTES = 4 * 1024 * 1024
MAX_CAPSULE_BYTES = 24 * 1024 * 1024 * 1024
MAX_OUTPUT_RAW_BYTES = 16 * 1024 * 1024 * 1024
MAX_PARTS = 4096
MAX_PROJECTION_RECORDS = 8_000_000
FRAGMENT_BYTES = 64 * 1024
_HASH = re.compile(r"[0-9a-f]{64}")
_COMMIT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_RELATIONS = {"parents": "derived_from", "supersedes": "supersedes",
              "conflicts_with": "conflicts_with", "resolves": "resolves"}


def _fail(code: str) -> None:
    raise MemoryError(code)


def _integer(value: Any, maximum: int, *, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        _fail("invalid_legacy_integer")
    return value


def _object(value: Any, fields: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        _fail("invalid_legacy_shape")
    return value


def _match(value: Any, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        _fail("invalid_legacy_identity")
    return value


def _path(value: Any) -> str:
    if not isinstance(value, str) or len(value.encode("utf-8")) > 512:
        _fail("unsafe_legacy_member_path")
    if value != "MANIFEST.json" and not (
        legacy._EPISODE_PATH.fullmatch(value) or legacy._EVENT_PATH.fullmatch(value)
        or legacy._CONVERSATION_PATH.fullmatch(value)
    ):
        _fail("unsafe_legacy_member_path")
    return value


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    result = stream.read(size)
    if len(result) != size:
        _fail("truncated_legacy_container")
    return result


def _absolute(path: Path) -> Path:
    if os.name == "nt":
        from memory_vault_storage import validate_path
        return validate_path(path)
    return legacy._absolute(path)


def _new_output(path: Path, *, create_parent: bool = False) -> None:
    _absolute(path)
    if os.name == "nt":
        from memory_vault_storage import private_directory
        if create_parent:
            private_directory(path.parent)
        try:
            path.lstat()
        except FileNotFoundError:
            return
        _fail("output_exists")
    legacy._new_output(path)
    if create_parent:
        legacy._check_parent_chain(path, create=True, private=True)


@contextmanager
def _source(path: Path, *, maximum: int = MAX_SOURCE_BYTES) -> Iterator[BinaryIO]:
    path = _absolute(path)
    if os.name != "nt" and not legacy._check_parent_chain(path, create=False, private=False):
        _fail("legacy_source_not_found")
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or not 1 <= before.st_size <= maximum:
        _fail("invalid_legacy_source")
    if os.name == "nt":
        from memory_vault_storage import open_file
        descriptor = open_file(path, os.O_RDONLY)
    else:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                             | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(descriptor, "rb") as stream:
        observed = os.fstat(stream.fileno())
        if not stat.S_ISREG(observed.st_mode) or (before.st_dev, before.st_ino) != (observed.st_dev, observed.st_ino):
            _fail("legacy_source_changed")
        fingerprint = (observed.st_size, observed.st_mtime_ns, observed.st_ctime_ns)
        yield stream
        after = os.fstat(stream.fileno())
        if fingerprint != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            _fail("legacy_source_changed")


def _digest_stream(stream: BinaryIO, *, maximum: int) -> tuple[str, int]:
    stream.seek(0)
    digest, total = hashlib.sha256(), 0
    while chunk := stream.read(1024 * 1024):
        total += len(chunk)
        if total > maximum:
            _fail("legacy_container_too_large")
        digest.update(chunk)
    stream.seek(0)
    return digest.hexdigest(), total


class _JSONCatalog:
    """Streaming closed object with one array of small entries.

    Both old catalogs may be tens of MiB; only one entry/token is decoded at a
    time. The complete byte range is consumed, including trailing whitespace.
    Duplicate keys, non-UTF8, trailing values and oversized tokens fail closed.
    """

    def __init__(self, stream: BinaryIO, length: int) -> None:
        self.stream, self.remaining = stream, length
        self.buffer = b""
        self.offset = 0

    def peek(self) -> int | None:
        if self.offset == len(self.buffer):
            if not self.remaining:
                return None
            self.buffer = _read_exact(self.stream, min(64 * 1024, self.remaining))
            self.remaining -= len(self.buffer)
            self.offset = 0
        return self.buffer[self.offset]

    def take(self) -> int:
        value = self.peek()
        if value is None:
            _fail("truncated_legacy_json")
        self.offset += 1
        return value

    def whitespace(self) -> None:
        while self.peek() in (9, 10, 13, 32):
            self.take()

    def expect(self, token: int) -> None:
        self.whitespace()
        if self.take() != token:
            _fail("invalid_legacy_catalog_json")

    def value(self, *, maximum: int = MAX_HEADER_BYTES) -> Any:
        self.whitespace()
        first = self.peek()
        if first is None:
            _fail("truncated_legacy_json")
        raw = bytearray()
        quoted, escaped, depth = False, False, 0
        composite = first in (ord("{"), ord("["))
        string = first == ord('"')
        while True:
            following = self.peek()
            if following is None:
                break
            if raw and not quoted and depth == 0:
                if composite or string or following in (9, 10, 13, 32, 44, 93, 125):
                    break
            token = self.take()
            raw.append(token)
            if len(raw) > maximum:
                _fail("legacy_catalog_token_too_large")
            if quoted:
                if escaped:
                    escaped = False
                elif token == 92:
                    escaped = True
                elif token == 34:
                    quoted = False
            elif token == 34:
                quoted = True
            elif token in (123, 91):
                depth += 1
                if depth > 32:
                    _fail("legacy_json_too_deep")
            elif token in (125, 93):
                depth -= 1
                if depth < 0:
                    _fail("invalid_legacy_catalog_json")
        result = legacy._json_loads(bytes(raw))
        legacy._legacy_jcs(result)
        return result

    def read(self, fields: set[str], consume: Callable[[dict[str, Any]], None], *, maximum_entries: int) -> dict[str, Any]:
        self.expect(123)
        seen: set[str] = set()
        metadata: dict[str, Any] = {}
        count = 0
        self.whitespace()
        if self.peek() != 125:
            while True:
                key = self.value(maximum=256)
                if not isinstance(key, str) or key not in fields or key in seen:
                    _fail("invalid_legacy_catalog_fields")
                seen.add(key)
                self.expect(58)
                if key == "entries":
                    self.expect(91)
                    self.whitespace()
                    if self.peek() != 93:
                        while True:
                            value = self.value()
                            if not isinstance(value, dict):
                                _fail("invalid_legacy_catalog_entry")
                            count += 1
                            if count > maximum_entries:
                                _fail("legacy_object_limit")
                            consume(value)
                            self.whitespace()
                            if self.peek() == 93:
                                break
                            self.expect(44)
                    self.expect(93)
                else:
                    metadata[key] = self.value()
                self.whitespace()
                if self.peek() == 125:
                    break
                self.expect(44)
        self.expect(125)
        self.whitespace()
        if self.peek() is not None or seen != fields:
            _fail("invalid_legacy_catalog_fields")
        metadata["entry_count"] = count
        return metadata


def _zip_directory(stream: BinaryIO, *, maximum_entries: int, maximum_central: int) -> int:
    """Bound the central-directory allocation before stdlib ZIP opens it."""
    size = os.fstat(stream.fileno()).st_size
    if size < 22:
        _fail("truncated_legacy_zip")
    stream.seek(size - 22)
    signature, disk, central_disk, on_disk, total, central_size, central_offset, comment = struct.unpack("<4s4H2LH", _read_exact(stream, 22))
    if signature != b"PK\x05\x06" or disk or central_disk or comment:
        _fail("unsupported_legacy_zip")
    end_of_directory = size - 22
    if total == 65535 or on_disk == 65535 or central_size == 0xFFFFFFFF or central_offset == 0xFFFFFFFF:
        if size < 98:
            _fail("truncated_legacy_zip64")
        stream.seek(size - 42)
        locator, locator_disk, position, disks = struct.unpack("<4sLQL", _read_exact(stream, 20))
        if locator != b"PK\x06\x07" or locator_disk or disks != 1 or position > size - 98:
            _fail("unsupported_legacy_zip64")
        stream.seek(position)
        values = struct.unpack("<4sQ2H2L4Q", _read_exact(stream, 56))
        if values[0] != b"PK\x06\x06" or not 44 <= values[1] <= 4096 or values[4] or values[5]:
            _fail("unsupported_legacy_zip64")
        on_disk, total, central_size, central_offset = values[6:]
        if position + 12 + values[1] != size - 42:
            _fail("invalid_legacy_zip64_bounds")
        end_of_directory = position
    if (on_disk != total or not 1 <= total <= maximum_entries or central_size > maximum_central
            or central_offset + central_size != end_of_directory):
        _fail("legacy_zip_directory_limit")
    stream.seek(0)
    return total


def _inflate(stream: BinaryIO, compressed_size: int, raw_size: int) -> bytes:
    decoder = zlib.decompressobj()
    output = bytearray()
    remaining = compressed_size
    while remaining:
        chunk = _read_exact(stream, min(64 * 1024, remaining))
        remaining -= len(chunk)
        try:
            output.extend(decoder.decompress(chunk, raw_size - len(output) + 1))
        except zlib.error:
            _fail("invalid_legacy_compression")
        if len(output) > raw_size or decoder.unconsumed_tail or decoder.unused_data:
            _fail("legacy_decompression_bound")
    if not decoder.eof or len(output) != raw_size:
        _fail("invalid_legacy_compressed_size")
    return bytes(output)


class _Archive:
    def __init__(self, stream: BinaryIO, connection: sqlite3.Connection) -> None:
        self.stream, self.db = stream, connection
        self.source_sha256, self.source_bytes = _digest_stream(stream, maximum=MAX_SOURCE_BYTES)
        self.format = "pack" if stream.read(len(PACK_MAGIC)) == PACK_MAGIC else "zip"
        stream.seek(0)
        self.raw_bytes = 0
        self.db.executescript("""
            CREATE TABLE members(path TEXT PRIMARY KEY, raw_size INTEGER NOT NULL,
                sha256 TEXT NOT NULL, offset INTEGER, compressed_size INTEGER,
                seen INTEGER NOT NULL DEFAULT 0, raw BLOB);
            CREATE TABLE nodes(id INTEGER PRIMARY KEY, legacy_id TEXT NOT NULL UNIQUE,
                path TEXT NOT NULL UNIQUE, schema TEXT NOT NULL, kind TEXT NOT NULL,
                created_at TEXT NOT NULL, remaining INTEGER NOT NULL DEFAULT 0,
                done INTEGER NOT NULL DEFAULT 0, memory_id TEXT, record_sha256 TEXT,
                mapping_json BLOB);
            CREATE TABLE episode_anchors(legacy_id TEXT PRIMARY KEY, source_id TEXT NOT NULL,
                source_sequence INTEGER NOT NULL, episode_sha256 TEXT NOT NULL,
                roles_json BLOB NOT NULL, parents_json BLOB NOT NULL);
            CREATE INDEX ready_nodes ON nodes(done,remaining,created_at,legacy_id);
            CREATE TABLE edges(source INTEGER NOT NULL, target INTEGER NOT NULL,
                relation TEXT NOT NULL, ordinal INTEGER NOT NULL,
                PRIMARY KEY(source,target,relation));
            CREATE INDEX edge_dependants ON edges(target,source);
            CREATE TABLE emitted(memory_id TEXT PRIMARY KEY, record_sha256 TEXT NOT NULL);
        """)
        if self.format == "pack":
            self._pack()
        else:
            self._zip()
        self.object_count = self.db.execute("SELECT COUNT(*) FROM members").fetchone()[0]
        self.object_root_sha256 = self._root()
        self.manifest = self._manifest()
        self._nodes()
        self._edges()

    def _put(self, path: str, raw: bytes, *, existing: bool = False) -> None:
        self.raw_bytes += len(raw)
        if self.raw_bytes > MAX_RAW_BYTES:
            _fail("legacy_expanded_size_limit")
        if existing:
            self.db.execute("UPDATE members SET raw=?,seen=1 WHERE path=?", (raw, path))
        else:
            self.db.execute("INSERT INTO members(path,raw_size,sha256,raw,seen) VALUES(?,?,?,?,1)",
                            (path, len(raw), sha256(raw), raw))

    def _pack(self) -> None:
        stream = self.stream
        if self.source_bytes < len(PACK_MAGIC) + len(INDEX_MAGIC) + 8:
            _fail("truncated_legacy_pack")
        stream.seek(-len(INDEX_MAGIC) - 8, os.SEEK_END)
        index_size = struct.unpack(">Q", _read_exact(stream, 8))[0]
        if _read_exact(stream, len(INDEX_MAGIC)) != INDEX_MAGIC or not 1 <= index_size <= MAX_INDEX_BYTES:
            _fail("invalid_legacy_pack_footer")
        index_start = self.source_bytes - len(INDEX_MAGIC) - 8 - index_size
        if index_start < len(PACK_MAGIC):
            _fail("invalid_legacy_pack_bounds")

        def index_entry(value: dict[str, Any]) -> None:
            _object(value, {"path", "sha256", "raw_size", "offset", "compressed_size"})
            path = _path(value["path"])
            maximum = MAX_PACK_OBJECT_BYTES if path == "MANIFEST.json" else MAX_MEMBER_BYTES
            raw_size = _integer(value["raw_size"], maximum)
            offset = _integer(value["offset"], index_start, minimum=len(PACK_MAGIC))
            compressed = _integer(value["compressed_size"], self.source_bytes, minimum=1)
            if offset + compressed + 4 > index_start:
                _fail("invalid_legacy_pack_bounds")
            self.db.execute("INSERT INTO members(path,raw_size,sha256,offset,compressed_size) VALUES(?,?,?,?,?)",
                            (path, raw_size, _match(value["sha256"], _HASH), offset, compressed))

        stream.seek(index_start)
        metadata = _JSONCatalog(stream, index_size).read({"entries", "schema_version"}, index_entry, maximum_entries=MAX_OBJECTS)
        if metadata["schema_version"] != PACK_INDEX_SCHEMA:
            _fail("unsupported_legacy_pack_index")
        stream.seek(len(PACK_MAGIC))
        while stream.tell() < index_start:
            offset = stream.tell()
            if offset + 4 > index_start:
                _fail("invalid_legacy_pack_bounds")
            header_size = struct.unpack(">I", _read_exact(stream, 4))[0]
            if not 1 <= header_size <= MAX_HEADER_BYTES or stream.tell() + header_size > index_start:
                _fail("invalid_legacy_pack_header")
            value = _object(legacy._json_loads(_read_exact(stream, header_size)), {"path", "sha256", "raw_size", "compressed_size"})
            path = _path(value["path"])
            row = self.db.execute("SELECT * FROM members WHERE path=?", (path,)).fetchone()
            if (row is None or row["seen"] or row["offset"] != offset
                    or any(value[key] != row[key] or type(value[key]) is not type(row[key])
                           for key in ("raw_size", "compressed_size", "sha256"))
                    or stream.tell() + row["compressed_size"] > index_start):
                _fail("legacy_pack_index_mismatch")
            raw = _inflate(stream, row["compressed_size"], row["raw_size"])
            if sha256(raw) != row["sha256"]:
                _fail("legacy_member_hash_mismatch")
            self._put(path, raw, existing=True)
        if stream.tell() != index_start or self.db.execute("SELECT 1 FROM members WHERE seen=0 LIMIT 1").fetchone():
            _fail("legacy_pack_index_mismatch")

    def _zip(self) -> None:
        count = _zip_directory(self.stream, maximum_entries=MAX_OBJECTS, maximum_central=MAX_CENTRAL_BYTES)
        with zipfile.ZipFile(self.stream, "r") as archive:
            infos = archive.infolist()
            if len(infos) != count or archive.comment:
                _fail("invalid_legacy_zip_directory")
            for info in infos:
                path = _path(info.filename)
                maximum = MAX_MANIFEST_BYTES if path == "MANIFEST.json" else MAX_MEMBER_BYTES
                if (info.is_dir() or info.flag_bits & 1 or info.comment
                        or stat.S_IFMT(info.external_attr >> 16) not in (0, stat.S_IFREG)
                        or info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                        or not 0 <= info.file_size <= maximum):
                    _fail("unsafe_legacy_zip_member")
                with archive.open(info, "r") as member:
                    raw = member.read(maximum + 1)
                if len(raw) != info.file_size:
                    _fail("legacy_member_size_mismatch")
                self._put(path, raw)

    def _root(self) -> str:
        digest = hashlib.sha256(b"[")
        first = True
        for row in self.db.execute("SELECT path,raw_size,sha256 FROM members ORDER BY path"):
            if not first:
                digest.update(b",")
            first = False
            digest.update(legacy._legacy_jcs(dict(row)))
        digest.update(b"]")
        return digest.hexdigest()

    def _manifest(self) -> dict[str, Any]:
        row = self.db.execute("SELECT raw FROM members WHERE path='MANIFEST.json'").fetchone()
        if row is None:
            _fail("legacy_manifest_missing")
        previous: str | None = None

        def entry(value: dict[str, Any]) -> None:
            nonlocal previous
            _object(value, {"path", "sha256", "size"})
            path = _path(value["path"])
            if path == "MANIFEST.json" or (previous is not None and path <= previous):
                _fail("legacy_manifest_path_order")
            previous = path
            observed = self.db.execute("SELECT raw_size,sha256 FROM members WHERE path=?", (path,)).fetchone()
            if observed is None or _integer(value["size"], MAX_MEMBER_BYTES) != observed["raw_size"] or _match(value["sha256"], _HASH) != observed["sha256"]:
                _fail("legacy_manifest_member_mismatch")

        fields = {"schema_version", "network_contract", "remote_commit_sha", "exported_at",
                  "native_conversation_ids_included", "credentials_included", "entries", "network_sha256"}
        raw = row["raw"]
        value = _JSONCatalog(io.BytesIO(raw), len(raw)).read(fields, entry, maximum_entries=MAX_DOCUMENTS)
        if (value["schema_version"] != legacy.SOURCE_SCHEMA
                or value["network_contract"] not in ("memory-network-graph/v1", "memory-network-index/v1")
                or value["native_conversation_ids_included"] is not False or value["credentials_included"] is not False
                or value["entry_count"] != self.object_count - 1):
            _fail("unsupported_legacy_manifest")
        _match(value["remote_commit_sha"], _COMMIT)
        legacy._timestamp(value["exported_at"])
        digest = hashlib.sha256(b"{")
        for ordinal, key in enumerate(sorted(fields - {"network_sha256"})):
            if ordinal:
                digest.update(b",")
            digest.update(legacy._legacy_jcs(key) + b":")
            if key != "entries":
                digest.update(legacy._legacy_jcs(value[key]))
                continue
            digest.update(b"[")
            for index, member in enumerate(self.db.execute("SELECT path,raw_size,sha256 FROM members WHERE path!='MANIFEST.json' ORDER BY path")):
                if index:
                    digest.update(b",")
                digest.update(legacy._legacy_jcs({"path": member["path"], "sha256": member["sha256"], "size": member["raw_size"]}))
            digest.update(b"]")
        digest.update(b"}")
        if _match(value["network_sha256"], _HASH) != digest.hexdigest():
            _fail("legacy_manifest_hash_mismatch")
        return value

    def document(self, path: str) -> tuple[dict[str, Any], bytes, str]:
        row = self.db.execute("SELECT raw,sha256 FROM members WHERE path=?", (path,)).fetchone()
        if row is None:
            _fail("missing_legacy_document")
        raw = row["raw"]
        value = legacy._json_loads(raw)
        if not isinstance(value, dict):
            _fail("invalid_legacy_document")
        legacy._legacy_jcs(value)
        return value, raw, row["sha256"]

    def _nodes(self) -> None:
        # Separate passes establish exact episode anchors before any event is
        # admitted to the work graph. Every body remains a <=2MiB temporary row.
        for events in (False, True):
            paths = self.db.execute("SELECT path FROM members WHERE path!='MANIFEST.json' ORDER BY path")
            for item in paths:
                path = item["path"]
                if path.startswith("memory/events/") != events:
                    continue
                value, _raw, digest = self.document(path)
                schema = value.get("schema_version")
                if schema == legacy.EPISODE_SCHEMA and not events:
                    node = legacy._episode(value, path, digest)
                elif schema == legacy.CONVERSATION_SCHEMA and not events:
                    # Each nonempty JSON message consumes bytes in this actual
                    # <=2 MiB member. Do not inherit the small ZIP converter's
                    # unrelated 20,000-message cap or trust a manifest count.
                    node = legacy._conversation(value, path, digest, maximum_messages=len(_raw))
                elif schema == legacy.EVENT_SCHEMA and events:
                    node = self._event(value, path, digest)
                else:
                    _fail("unsupported_legacy_document_schema")
                self.db.execute("INSERT INTO nodes(legacy_id,path,schema,kind,created_at) VALUES(?,?,?,?,?)",
                                (node.identity, path, schema, node.kind, node.created_at))
                if schema == legacy.EPISODE_SCHEMA:
                    # Repeated semantic claims need the checked anchor, not
                    # repeated decoding of its potentially 2MiB visible body.
                    self.db.execute("INSERT INTO episode_anchors VALUES(?,?,?,?,?,?)", (
                        node.identity, value["source_id"], value["source_sequence"], value["episode_sha256"],
                        canonical_bytes([message["role"] for message in value["messages"]]),
                        canonical_bytes(value["parent_episode_ids"]),
                    ))

    def _event(self, value: dict[str, Any], path: str, digest: str) -> legacy._Node:
        """Validate the production v2 profile without its old migrator's 256
        total-edge shortcut. Four independent lists may each contain 256.
        """
        _object(value, legacy._EVENT_FIELDS)
        identity = _match(value["memory_event_id"], legacy._EVENT)
        match = legacy._EVENT_PATH.fullmatch(path)
        if match is None or match[2] != identity or (match[1] is not None and match[1] != identity[4:6]):
            _fail("legacy_event_path_mismatch")
        if not isinstance(value["kind"], str) or value["kind"] not in legacy._EVENT_KINDS or value["confidence"] not in ("source_explicit", "assistant_inferred"):
            _fail("unsupported_legacy_event_kind")
        source = _object(value["source"], {"source_id", "revision_id", "source_sequence", "evidence_anchor_sha256"})
        _match(source["source_id"], legacy._SOURCE)
        revision = _match(source["revision_id"], legacy._EPISODE)
        episode_row = self.db.execute("SELECT * FROM episode_anchors WHERE legacy_id=?", (revision,)).fetchone()
        if episode_row is None:
            _fail("missing_legacy_episode_evidence")
        episode = {"source_id": episode_row["source_id"], "source_sequence": episode_row["source_sequence"],
                   "episode_sha256": episode_row["episode_sha256"],
                   "parent_episode_ids": legacy._json_loads(episode_row["parents_json"]),
                   "messages": [{"role": role} for role in legacy._json_loads(episode_row["roles_json"])]}
        if (_integer(source["source_sequence"], 9_007_199_254_740_991) != episode["source_sequence"]
                or source["source_id"] != episode["source_id"] or source["evidence_anchor_sha256"] != episode["episode_sha256"]):
            _fail("legacy_evidence_anchor_mismatch")
        if value["claim_key"] is not None:
            _match(value["claim_key"], legacy._IDENTIFIER)
        refs = {name: legacy._references(value[name], identity, legacy._EVENT, 256) for name in _RELATIONS}
        if value["kind"] == "conflict_declared" and len(refs["conflicts_with"]) < 2:
            _fail("invalid_legacy_conflict")
        if value["kind"] == "conflict_resolved" and not refs["resolves"]:
            _fail("invalid_legacy_conflict")
        if value["hash_profile"] != "jcs-rfc8785+sha256/event-v2":
            _fail("unsupported_legacy_hash_profile")
        payload = value["payload"]
        if not isinstance(payload, dict) or _match(value["payload_sha256"], _HASH) != legacy._legacy_hash(payload):
            _fail("legacy_payload_hash_mismatch")
        legacy._verify_hash(value, "event_sha256")
        parent_relation = "derived_from"
        if payload.get("profile") == "memory-network-episode-event/v1":
            _object(payload, {"memory_form", "profile", "message_count", "roles", "continuity"})
            parents = episode["parent_episode_ids"]
            expected = [legacy._episode_event_id(source["source_id"], parents[-1])] if parents else []
            if (value["kind"] != "checkpoint_note" or value["confidence"] != "source_explicit"
                    or value["claim_key"] is not None or payload["memory_form"] != "episodic"
                    or payload["roles"] != [message["role"] for message in episode["messages"]]
                    or type(payload["message_count"]) is not int or payload["message_count"] != len(episode["messages"])
                    or payload["continuity"] != ("continues" if expected else "origin")
                    or refs["parents"] != expected or any(refs[name] for name in ("supersedes", "conflicts_with", "resolves"))
                    or identity != legacy._episode_event_id(source["source_id"], revision)):
                _fail("invalid_legacy_continuity_profile")
            parent_relation = "continues"
        elif payload.get("profile") == "memory-network-semantic/v1":
            _object(payload, {"profile", "claim"})
            if value["confidence"] != "assistant_inferred" or not isinstance(payload["claim"], dict) or not payload["claim"]:
                _fail("invalid_legacy_semantic_profile")
            legacy._check_claim_fields(payload["claim"])
            domain = {"source_id": source["source_id"], "episode_id": revision, "kind": value["kind"],
                      "claim_key": value["claim_key"], **refs, "payload": payload}
            if identity != "evt-" + legacy._legacy_hash(domain)[:40]:
                _fail("legacy_event_identity_mismatch")
        else:
            _fail("unsupported_legacy_event_profile")
        relations = [("derived_from", revision)]
        for name, targets in refs.items():
            relation = parent_relation if name == "parents" else _RELATIONS[name]
            relations.extend((relation, target) for target in targets)
        return legacy._Node(identity, legacy.EVENT_SCHEMA, legacy._EVENT_KINDS[value["kind"]],
                            "", legacy._timestamp(value["created_at"]), tuple(relations), digest,
                            "legacy-v021:sha256:" + digest, ())

    def _edges(self) -> None:
        for row in self.db.execute("SELECT id,legacy_id,path,schema FROM nodes ORDER BY id"):
            value, _raw, digest = self.document(row["path"])
            if row["schema"] == legacy.EPISODE_SCHEMA:
                relations = [("continues", target) for target in value["parent_episode_ids"]]
            elif row["schema"] == legacy.EVENT_SCHEMA:
                relations = self._event(value, row["path"], digest).relations
            else:
                relations = []
            for ordinal, (relation, target) in enumerate(relations):
                found = self.db.execute("SELECT id FROM nodes WHERE legacy_id=?", (target,)).fetchone()
                if found is None:
                    _fail("missing_legacy_relation_target")
                self.db.execute("INSERT OR IGNORE INTO edges VALUES(?,?,?,?)", (row["id"], found["id"], relation, ordinal))
            self.db.execute("UPDATE nodes SET remaining=(SELECT COUNT(DISTINCT target) FROM edges WHERE source=?) WHERE id=?",
                            (row["id"], row["id"]))

    def summary(self) -> dict[str, Any]:
        schemas = {row[0]: row[1] for row in self.db.execute("SELECT schema,COUNT(*) FROM nodes GROUP BY schema")}
        return {"schema_version": RESULT_SCHEMA, "container_format": self.format,
                "source_sha256": self.source_sha256, "source_bytes": self.source_bytes,
                "object_count": self.object_count, "raw_bytes": self.raw_bytes,
                "object_root_sha256": self.object_root_sha256,
                "legacy_network_sha256": self.manifest["network_sha256"], "document_schemas": schemas,
                "legacy_checksums_verified": True, "original_author_authenticated": False,
                "vault_database_opened": False, "temporary_index_used": True,
                "source_modified": False, "network_accessed": False, "authority": dict(AUTHORITY)}


@contextmanager
def _scratch() -> Iterator[Path]:
    if os.name != "nt":
        with tempfile.TemporaryDirectory(prefix="memory-vault-v021-") as directory:
            yield Path(directory)
        return
    from memory_vault_storage import check_private_directory, private_directory
    parent = _absolute(Path(tempfile.gettempdir()))
    check_private_directory(parent)
    directory = parent / ("memory-vault-v021-" + uuid.uuid4().hex)
    private_directory(directory)
    try:
        yield directory
    finally:
        # Only this invocation's newly created, private random directory.
        shutil.rmtree(directory)


@contextmanager
def _archive(source: Path) -> Iterator[_Archive]:
    # Temporary state is disposable, private and local. No user-selected Vault
    # path, configuration, hook queue, credential or trust store is opened.
    with _scratch() as directory:
        index = directory / "objects.sqlite3"
        if os.name == "nt":
            from memory_vault_storage import open_file
            descriptor = open_file(index, os.O_WRONLY | os.O_CREAT | os.O_EXCL, private=True)
        else:
            descriptor = os.open(index, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(descriptor)
        connection = sqlite3.connect(index)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA journal_mode=OFF")
            connection.execute("PRAGMA synchronous=OFF")
            # Bodies live in the protected on-disk table. Work-list sorting
            # uses indexed keys/per-node <=1024 edges, not an unprotected
            # system temporary file containing visible memory bodies.
            connection.execute("PRAGMA temp_store=MEMORY")
            connection.execute("PRAGMA cache_size=-8192")
            connection.execute("PRAGMA trusted_schema=OFF")
            with _source(source) as stream:
                yield _Archive(stream, connection)
        finally:
            connection.close()


def _checkpoint_value(raw: bytes) -> dict[str, Any]:
    value = _object(legacy._json_loads(raw), {
        "checkpoint_sha256", "generation", "network_contract", "object_count",
        "object_root_sha256", "previous_checkpoint_sha256", "remote_commit_sha", "schema_version",
    })
    if value["schema_version"] != CHECKPOINT_SCHEMA or value["network_contract"] != CHECKPOINT_CONTRACT:
        _fail("unsupported_legacy_checkpoint")
    _integer(value["generation"], 2**63 - 1)
    _integer(value["object_count"], 1_000_000)
    _match(value["remote_commit_sha"], re.compile(r"[0-9a-f]{40}"))
    _match(value["object_root_sha256"], _HASH)
    if value["previous_checkpoint_sha256"] is not None:
        _match(value["previous_checkpoint_sha256"], _HASH)
    legacy._verify_hash(value, "checkpoint_sha256")
    return value


def _checkpoint(archive: _Archive, checkpoint: Path | None, trusted_checkpoint_sha256: str | None) -> tuple[dict[str, Any], bytes | None]:
    if checkpoint is None:
        if trusted_checkpoint_sha256 is not None:
            _fail("checkpoint_anchor_requires_checkpoint")
        return {"checkpoint_checked": False, "trusted_anchor_checked": False}, None
    with _source(checkpoint, maximum=MAX_CHECKPOINT_BYTES) as stream:
        raw = stream.read(MAX_CHECKPOINT_BYTES + 1)
    value = _checkpoint_value(raw)
    if value["object_root_sha256"] != archive.object_root_sha256 or value["object_count"] != archive.object_count:
        _fail("legacy_checkpoint_object_mismatch")
    if trusted_checkpoint_sha256 is not None and _match(trusted_checkpoint_sha256, _HASH) != value["checkpoint_sha256"]:
        _fail("legacy_checkpoint_anchor_mismatch")
    return {"checkpoint_checked": True, "trusted_anchor_checked": trusted_checkpoint_sha256 is not None,
            "checkpoint_sha256": value["checkpoint_sha256"], "checkpoint_generation": value["generation"],
            "checkpoint_is_signature": False, "checkpoint_commit_matches_bundle": value["remote_commit_sha"] == archive.manifest["remote_commit_sha"]}, raw


def verify(source: Path, *, checkpoint: Path | None = None, trusted_checkpoint_sha256: str | None = None) -> Mapping[str, Any]:
    with _archive(source) as archive:
        checked, _raw = _checkpoint(archive, checkpoint, trusted_checkpoint_sha256)
        result = {**archive.summary(), **checked, "state": "verified_hashes_and_graph", "written": False}
    return result


def verify_checkpoint_chain(paths: Sequence[Path], *, trusted_checkpoint_sha256: str | None = None) -> Mapping[str, Any]:
    """Check explicit oldest-to-newest files, without trusting the chain itself.

    Use verify(source, checkpoint=last_path) to additionally bind the last
    checkpoint to that pack. A previous hash alone cannot fetch a missing file.
    """
    if not isinstance(paths, (list, tuple)) or not 1 <= len(paths) <= 1024:
        _fail("legacy_checkpoint_chain_limit")
    previous = None
    first = None
    for path in paths:
        with _source(path, maximum=MAX_CHECKPOINT_BYTES) as stream:
            current = _checkpoint_value(stream.read(MAX_CHECKPOINT_BYTES + 1))
        if previous is None:
            first = current["checkpoint_sha256"]
            if trusted_checkpoint_sha256 is not None and _match(trusted_checkpoint_sha256, _HASH) != first:
                _fail("legacy_checkpoint_anchor_mismatch")
        elif (current["generation"] != previous["generation"] + 1
              or current["previous_checkpoint_sha256"] != previous["checkpoint_sha256"]):
            _fail("legacy_checkpoint_chain_mismatch")
        previous = current
    assert previous is not None
    return {"schema_version": RESULT_SCHEMA, "state": "checkpoint_hash_chain_verified", "checkpoints": len(paths),
            "first_checkpoint_sha256": first, "last_checkpoint_sha256": previous["checkpoint_sha256"],
            "trusted_anchor_checked": trusted_checkpoint_sha256 is not None, "original_author_authenticated": False,
            "checkpoint_is_signature": False, "pack_object_root_checked": False, "network_accessed": False,
            "trust_granted": False, "written": False, "authority": dict(AUTHORITY)}


def create_checkpoint(source: Path, output: Path, *, generation: int,
                      previous_checkpoint_sha256: str | None = None) -> Mapping[str, Any]:
    source, output = _absolute(source), _absolute(output)
    if source == output:
        _fail("paths_must_be_distinct")
    _integer(generation, 9_007_199_254_740_991)
    if previous_checkpoint_sha256 is not None:
        _match(previous_checkpoint_sha256, _HASH)
    with _staging(output) as (staged, stream):
        with _archive(source) as archive:
            commit = _match(archive.manifest["remote_commit_sha"], re.compile(r"[0-9a-f]{40}"))
            value = {"schema_version": CHECKPOINT_SCHEMA, "network_contract": CHECKPOINT_CONTRACT,
                     "generation": generation, "object_count": archive.object_count,
                     "object_root_sha256": archive.object_root_sha256, "remote_commit_sha": commit,
                     "previous_checkpoint_sha256": previous_checkpoint_sha256}
            value["checkpoint_sha256"] = legacy._legacy_hash(value)
            raw = canonical_bytes(value) + b"\n"
            stream.write(raw)
            result = {**archive.summary(), "state": "hash_checkpoint_created", "checkpoint_sha256": value["checkpoint_sha256"],
                      "generation": generation, "output_sha256": sha256(raw), "output_bytes": len(raw),
                      "checkpoint_is_signature": False, "trusted_anchor_checked": False, "written": True}
        _publish(staged, output, stream)
    return result


@contextmanager
def _staging(output: Path) -> Iterator[tuple[Path, BinaryIO]]:
    output = _absolute(output)
    _new_output(output, create_parent=True)
    if os.name == "nt":
        from memory_vault_storage import open_file
        path = output.parent / (".memory-v021-" + uuid.uuid4().hex + ".tmp")
        descriptor = open_file(path, os.O_RDWR | os.O_CREAT | os.O_EXCL, private=True)
    else:
        descriptor, name = tempfile.mkstemp(prefix=".memory-v021-", dir=output.parent)
        path = Path(name)
    try:
        with os.fdopen(descriptor, "w+b") as stream:
            if os.name != "nt":
                os.fchmod(stream.fileno(), 0o600)
            yield path, stream
            if not stream.closed:
                stream.flush()
                os.fsync(stream.fileno())
    finally:
        # The unique temporary is ours; destination publication is a separate
        # no-clobber rename performed only after source fingerprints are checked.
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def _publish(staged: Path, output: Path, stream: BinaryIO) -> None:
    from memory_vault_storage import StorageError, publish_file
    stream.flush()
    os.fsync(stream.fileno())
    if os.fstat(stream.fileno()).st_size > MAX_CAPSULE_BYTES:
        _fail("legacy_output_size_limit")
    if os.name == "nt":
        # Native protected handles intentionally deny delete-sharing. Close
        # before WRITE_THROUGH/no-copy publication, not before file flushing.
        stream.close()
        publish_file(staged, output, replace=False)
        return
    legacy._check_parent_chain(output, create=False, private=True)
    try:
        publish_file(staged, output, replace=False, private_parent=False)
    except FileExistsError:
        _fail("output_exists")
    except StorageError as exc:
        raise MemoryError(exc.code, retryable=exc.retryable) from None


def _write_pack(archive: _Archive, output: BinaryIO) -> None:
    output.write(PACK_MAGIC)
    archive.db.execute("CREATE TEMP TABLE output_index(path TEXT PRIMARY KEY,sha256 TEXT,raw_size INTEGER,offset INTEGER,compressed_size INTEGER)")
    for row in archive.db.execute("SELECT path,raw,raw_size,sha256 FROM members ORDER BY path"):
        if row["raw_size"] > MAX_PACK_OBJECT_BYTES:
            _fail("legacy_pack_object_exceeds_original_16mib_limit")
        raw = row["raw"]
        compressed = zlib.compress(raw, level=6)
        entry = {"path": row["path"], "sha256": row["sha256"], "raw_size": len(raw), "compressed_size": len(compressed)}
        offset = output.tell()
        header = legacy._legacy_jcs(entry)
        output.write(struct.pack(">I", len(header)))
        output.write(header)
        output.write(compressed)
        archive.db.execute("INSERT INTO output_index VALUES(?,?,?,?,?)", (row["path"], row["sha256"], len(raw), offset, len(compressed)))
    start = output.tell()
    output.write(b'{"entries":[')
    for ordinal, row in enumerate(archive.db.execute("SELECT * FROM output_index ORDER BY path")):
        if ordinal:
            output.write(b",")
        output.write(legacy._legacy_jcs(dict(row)))
    output.write(b'],"schema_version":"memory-pack-index/v1"}')
    length = output.tell() - start
    if length > MAX_INDEX_BYTES:
        _fail("legacy_pack_index_too_large")
    output.write(struct.pack(">Q", length))
    output.write(INDEX_MAGIC)
    if output.tell() > MAX_SOURCE_BYTES:
        _fail("legacy_repacked_container_too_large")


def repack(source: Path, output: Path, *, format: str = "pack", checkpoint: Path | None = None,
           trusted_checkpoint_sha256: str | None = None) -> Mapping[str, Any]:
    source, output = _absolute(source), _absolute(output)
    if source == output or format not in ("pack", "zip"):
        _fail("invalid_legacy_repack_arguments")
    with _staging(output) as (staged, stream):
        with _archive(source) as archive:
            checked, _raw = _checkpoint(archive, checkpoint, trusted_checkpoint_sha256)
            if format == "pack":
                _write_pack(archive, stream)
            else:
                with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as target:
                    for row in archive.db.execute("SELECT path,raw FROM members ORDER BY path"):
                        target.writestr(row["path"], row["raw"])
                if stream.tell() > MAX_SOURCE_BYTES:
                    _fail("legacy_repacked_container_too_large")
            digest, size = _digest_stream(stream, maximum=MAX_SOURCE_BYTES)
            result = {**archive.summary(), **checked, "state": "repacked", "output_format": format,
                      "output_sha256": digest, "output_bytes": size, "original_member_bytes_preserved": True, "written": True}
        _publish(staged, output, stream)
    return result


class _Parts:
    def __init__(self, archive: zipfile.ZipFile | None, created_at: str) -> None:
        self.archive, self.created_at = archive, created_at
        self.parts: list[dict[str, Any]] = []
        self.current: BinaryIO | None = None
        self.count = self.total = self.size = self.raw_total = 0
        self.part_hash = hashlib.sha256()
        self.record_hash = hashlib.sha256()

    def _write(self, raw: bytes) -> None:
        self.raw_total += len(raw)
        if self.raw_total > MAX_OUTPUT_RAW_BYTES:
            _fail("legacy_projection_size_limit")
        if self.current is not None:
            self.current.write(raw)
        self.part_hash.update(raw)
        self.size += len(raw)

    def _start(self) -> None:
        if len(self.parts) >= MAX_PARTS:
            _fail("legacy_projection_part_limit")
        self.name = f"records/{len(self.parts) + 1:06d}.ndjson"
        self.current = self.archive.open(self.name, "w", force_zip64=True) if self.archive is not None else None
        self.size = self.count = 0
        self.part_hash = hashlib.sha256()
        self.record_hash = hashlib.sha256()
        self._write(canonical_bytes({"type": "header", "schema_version": BUNDLE_SCHEMA,
                                     "created_at": self.created_at, "hash_profile": HASH_PROFILE}) + b"\n")

    def add(self, record: Mapping[str, Any]) -> tuple[int, int]:
        line = canonical_bytes({"type": "record", "record": record}) + b"\n"
        if len(line) > MAX_BUNDLE_LINE_BYTES or len(line) + 1024 > MAX_PART_BYTES:
            _fail("legacy_projection_line_limit")
        if not self.size:
            self._start()
        if self.size + len(line) + 256 > MAX_PART_BYTES or self.count >= MAX_BUNDLE_RECORDS:
            self.finish()
            self._start()
        ordinal = self.total
        self._write(line)
        self.record_hash.update(record["record_sha256"].encode("ascii") + b"\n")
        self.count += 1
        self.total += 1
        if self.total > MAX_PROJECTION_RECORDS:
            _fail("legacy_projection_record_limit")
        return len(self.parts) + 1, ordinal

    def finish(self) -> None:
        if not self.size:
            return
        self._write(canonical_bytes({"type": "footer", "record_count": self.count, "records_sha256": self.record_hash.hexdigest()}) + b"\n")
        if self.current is not None:
            self.current.close()
        self.parts.append({"path": self.name, "size": self.size, "sha256": self.part_hash.hexdigest(),
                           "record_count": self.count, "first_global_ordinal": self.total - self.count,
                           "last_global_ordinal": self.total - 1, "requires_previous_parts": len(self.parts)})
        self.current = None
        self.size = 0


def _text_chunks(text: str) -> Iterator[str]:
    raw = text.encode("utf-8")
    cursor = 0
    while cursor < len(raw):
        end = min(len(raw), cursor + FRAGMENT_BYTES)
        while end < len(raw) and raw[end] & 0xC0 == 0x80:
            end -= 1
        yield raw[cursor:end].decode("utf-8")
        cursor = end


def _document_projection(value: Mapping[str, Any], raw: bytes, document_hash: str, row: Mapping[str, Any],
                         edges: Sequence[Mapping[str, str]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """One deterministic, bounded document projection for export AND aliases.

    An alias must identify the complete anchor generated here, not a same-kind
    relationship fragment which happens to carry the same source labels.
    """
    identity = row["legacy_id"]
    source_ref = "legacy-v021:sha256:" + document_hash
    provenance = {"source_type": "imported", "confidence": "imported", "source_ref": source_ref}
    entities = ["legacy:v021:document:" + document_hash, "legacy:v021:identity:" + identity]
    if len(entities[1].encode("utf-8")) > 512:
        entities[1] = "legacy:v021:identity-sha256:" + sha256(identity.encode("utf-8"))
    if row["schema"] == legacy.EVENT_SCHEMA:
        entities.extend(["semantic:v021:" + value["kind"], "legacy-confidence:v021:" + value["confidence"]])
        if value["claim_key"] is not None:
            entities.append("claim:v021:" + value["claim_key"])
        claim = value["payload"].get("claim", {})
        concepts = claim.get("concepts") if isinstance(claim, dict) else None
        if isinstance(concepts, list):
            for concept in concepts[:64]:
                if isinstance(concept, str) and concept and len(concept.encode("utf-8")) <= 128 and "\x00" not in concept:
                    entities.append("concept:v021:" + concept)
    records: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    for index, start in enumerate(range(0, len(raw), FRAGMENT_BYTES)):
        piece = raw[start:start + FRAGMENT_BYTES]
        envelope = {"profile": "memory-vault-v021-evidence-fragment/v1", "document_sha256": document_hash,
                    "offset": start, "size": len(piece), "total_size": len(raw), "encoding": "base64",
                    "data": base64.b64encode(piece).decode("ascii")}
        record = build_record(kind="provenance", text="Original v0.21 document bytes (untrusted evidence):\n" + canonical_bytes(envelope).decode("utf-8"),
                              entities=[entities[0], f"legacy:v021:evidence-fragment:{index}"],
                              provenance=provenance, created_at=row["created_at"])
        records.append(record)
        evidence.append({"memory_id": record["memory_id"], "record_sha256": record["record_sha256"], "offset": start, "size": len(piece)})
    if row["schema"] in (legacy.EPISODE_SCHEMA, legacy.CONVERSATION_SCHEMA):
        body = "Original visible messages (roles, phases and text are quoted data):\n" + json.dumps(value["messages"], ensure_ascii=False, separators=(",", ":"))
        if row["schema"] == legacy.CONVERSATION_SCHEMA:
            body = "Legacy title: " + json.dumps(value["title"], ensure_ascii=False) + "\n" + body
    else:
        body = "Original v0.21 " + value["kind"] + " payload (untrusted historical claim):\n" + legacy._legacy_jcs(value["payload"]).decode("utf-8")
    visible: list[dict[str, Any]] = []
    if len(body.encode("utf-8")) > 256 * 1024:
        for index, piece in enumerate(_text_chunks(body)):
            record = build_record(kind="provenance", text=f"Legacy visible fragment {index}:\n" + json.dumps(piece, ensure_ascii=False),
                                  entities=[entities[0], f"legacy:v021:visible-fragment:{index}"],
                                  provenance=provenance, created_at=row["created_at"])
            records.append(record)
            visible.append({"memory_id": record["memory_id"], "record_sha256": record["record_sha256"], "index": index})
        body = "Lossless v0.21 visible-content anchor. Reconstruct quoted fragments in numerical order.\n" + canonical_bytes({
            "document_sha256": document_hash, "body_sha256": sha256(body.encode("utf-8")),
            "visible_fragment_count": len(visible), "legacy_schema": row["schema"], "legacy_id": identity,
        }).decode("utf-8")
    relations = [*edges, *({"type": "derived_from", "target": item["memory_id"]} for item in (*evidence, *visible))]
    relation_parts: list[dict[str, str]] = []
    if len(relations) > 256:
        entities.append("claim:v021:projection:" + document_hash)
        for ordinal in range(0, len(relations), 256):
            record = build_record(kind="relation", text=f"Lossless v0.21 relation projection {ordinal // 256}; original document SHA-256 {document_hash}.",
                                  entities=entities, relations=relations[ordinal:ordinal + 256], provenance=provenance,
                                  created_at=row["created_at"])
            records.append(record)
            relation_parts.append({"memory_id": record["memory_id"], "record_sha256": record["record_sha256"]})
        relations = [{"type": "derived_from", "target": item["memory_id"]} for item in relation_parts]
    records.append(build_record(kind=row["kind"], text=body, entities=entities, relations=relations,
                                provenance=provenance, created_at=row["created_at"]))
    return records, {"original_evidence_records": evidence, "visible_fragment_records": visible,
                     "relation_projection_records": relation_parts}


def _project(archive: _Archive, parts: _Parts) -> int:
    db, completed = archive.db, 0

    def emit(record: dict[str, Any]) -> tuple[int | None, int | None]:
        record = validate_record(record)
        found = db.execute("SELECT record_sha256 FROM emitted WHERE memory_id=?", (record["memory_id"],)).fetchone()
        if found is not None:
            if found["record_sha256"] != record["record_sha256"]:
                _fail("legacy_projection_identity_collision")
            return None, None
        db.execute("INSERT INTO emitted VALUES(?,?)", (record["memory_id"], record["record_sha256"]))
        return parts.add(record)

    while True:
        row = db.execute("SELECT * FROM nodes WHERE done=0 AND remaining=0 ORDER BY created_at,legacy_id LIMIT 1").fetchone()
        if row is None:
            break
        value, raw, document_hash = archive.document(row["path"])
        # A unicode-escaped secret may be hidden in the raw spelling; inspect
        # every decoded field before preserving raw JSON as base64 evidence.
        from memory_vault_privacy import assert_publishable
        assert_publishable([{"text": raw.decode("utf-8")}, value])
        identity = row["legacy_id"]
        edges = [{"type": item["relation"], "target": item["memory_id"]} for item in db.execute(
            "SELECT edges.relation,nodes.memory_id FROM edges JOIN nodes ON nodes.id=edges.target WHERE edges.source=? ORDER BY edges.ordinal,edges.target,edges.relation", (row["id"],))]
        if any(item["target"] is None for item in edges):
            _fail("legacy_projection_dependency_missing")
        records, projected = _document_projection(value, raw, document_hash, row, edges)
        for record in records:
            part, ordinal = emit(record)
        record = records[-1]
        source_id = value.get("source_id") if row["schema"] != legacy.EVENT_SCHEMA else value["source"]["source_id"]
        anchor = value.get("episode_sha256", document_hash) if row["schema"] != legacy.EVENT_SCHEMA else value["source"]["evidence_anchor_sha256"]
        mapping = {"schema_version": MAP_SCHEMA, "legacy_schema": row["schema"], "legacy_id": identity,
                   "source_document_sha256": document_hash, "memory_id": record["memory_id"], "record_sha256": record["record_sha256"],
                   "source_id": source_id, "evidence_anchor_sha256": anchor, "source_path": row["path"],
                   "legacy_claim_key": value.get("claim_key"), "legacy_confidence": value.get("confidence"),
                   "legacy_source_sequence": value.get("source_sequence") if row["schema"] != legacy.EVENT_SCHEMA else value["source"]["source_sequence"],
                   **projected, "part": part, "global_ordinal": ordinal,
                   "original_author_authenticated": False}
        db.execute("UPDATE nodes SET done=1,memory_id=?,record_sha256=?,mapping_json=? WHERE id=?",
                   (record["memory_id"], record["record_sha256"], canonical_bytes(mapping), row["id"]))
        db.execute("UPDATE nodes SET remaining=remaining-1 WHERE id IN (SELECT source FROM edges WHERE target=?)", (row["id"],))
        completed += 1
    if db.execute("SELECT 1 FROM nodes WHERE done=0 LIMIT 1").fetchone():
        _fail("cyclic_legacy_graph_requires_explicit_resolution")
    parts.finish()
    return completed


def _maps(archive: _Archive, target: zipfile.ZipFile | None) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    member: BinaryIO | None = None
    size = count = 0
    digest = hashlib.sha256()
    name = ""

    def finish() -> None:
        nonlocal member, size, count, digest
        if not size:
            return
        if member is not None:
            member.close()
        results.append({"path": name, "size": size, "sha256": digest.hexdigest(), "mapping_count": count})
        member, size, count, digest = None, 0, 0, hashlib.sha256()

    for row in archive.db.execute("SELECT mapping_json FROM nodes ORDER BY legacy_id"):
        line = bytes(row[0]) + b"\n"
        if len(line) > 256 * 1024:
            _fail("legacy_mapping_row_limit")
        if size and size + len(line) > MAX_MAP_PART_BYTES:
            finish()
        if not size:
            if len(results) >= MAX_PARTS:
                _fail("legacy_mapping_part_limit")
            name = f"mappings/{len(results) + 1:06d}.ndjson"
            member = target.open(name, "w", force_zip64=True) if target is not None else None
        if member is not None:
            member.write(line)
        digest.update(line)
        size += len(line)
        count += 1
    finish()
    return results


def _conversion(archive: _Archive, target: zipfile.ZipFile | None, checkpoint_summary: Mapping[str, Any], checkpoint_raw: bytes | None) -> dict[str, Any]:
    parts = _Parts(target, legacy._timestamp(archive.manifest["exported_at"]))
    try:
        documents = _project(archive, parts)
    finally:
        if parts.current is not None:
            parts.current.close()
    mappings = _maps(archive, target)
    source_name = "source/original." + archive.format
    if target is not None:
        archive.stream.seek(0)
        digest, size = hashlib.sha256(), 0
        with target.open(source_name, "w", force_zip64=True) as member:
            while chunk := archive.stream.read(1024 * 1024):
                digest.update(chunk)
                size += len(chunk)
                if size > MAX_SOURCE_BYTES:
                    _fail("legacy_source_changed")
                member.write(chunk)
        if digest.hexdigest() != archive.source_sha256 or size != archive.source_bytes:
            _fail("legacy_source_changed")
        if checkpoint_raw is not None:
            target.writestr("source/checkpoint.json", checkpoint_raw)
    summary = {**archive.summary(), **checkpoint_summary, "schema_version": CAPSULE_SCHEMA,
               "state": "converted" if target is not None else "validated_only",
               "source_documents": documents, "records": parts.total, "record_parts": parts.parts,
               "mapping_parts": mappings, "source_member": {"path": source_name, "size": archive.source_bytes, "sha256": archive.source_sha256},
               "checkpoint_member": None if checkpoint_raw is None else {"path": "source/checkpoint.json", "size": len(checkpoint_raw), "sha256": sha256(checkpoint_raw)},
               "projection_profile": "v021-lossless-evidence+typed-graph/v1", "written": target is not None,
               "original_member_bytes_preserved": True, "visible_text_preserved": True,
               "claim_keys_preserved": True, "source_metadata_preserved_as_evidence": True,
               "signed_records": 0, "import_admission_default": "quarantined", "trust_granted": False,
               "dependency_order": "all-record-relations-target-earlier-global-ordinals",
               "part_closure": "import-all-previous-parts-first; individually-valid-not-individually-complete",
               "new_record_ids": True, "old_handles_included": False}
    # MANIFEST is deliberately not a self-signature. Its hash catalog is for
    # corruption checking; an attacker replacing it does not acquire trust.
    summary["capsule_manifest_sha256"] = sha256(canonical_bytes(summary))
    if target is not None:
        raw = canonical_bytes(summary) + b"\n"
        if len(raw) > 8 * 1024 * 1024:
            _fail("legacy_conversion_manifest_limit")
        target.writestr("MANIFEST.json", raw)
    return summary


def convert(source: Path, output: Path, *, checkpoint: Path | None = None,
            trusted_checkpoint_sha256: str | None = None, dry_run: bool = False) -> Mapping[str, Any]:
    source, output = _absolute(source), _absolute(output)
    if source == output:
        _fail("paths_must_be_distinct")
    _new_output(output)
    if dry_run:
        with _archive(source) as archive:
            checked, raw = _checkpoint(archive, checkpoint, trusted_checkpoint_sha256)
            return _conversion(archive, None, checked, raw)
    with _staging(output) as (staged, stream):
        with _archive(source) as archive:
            checked, raw = _checkpoint(archive, checkpoint, trusted_checkpoint_sha256)
            with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as target:
                summary = _conversion(archive, target, checked, raw)
            output_hash, output_size = _digest_stream(stream, maximum=MAX_CAPSULE_BYTES)
        _publish(staged, output, stream)
    return {**summary, "output_sha256": output_hash, "output_bytes": output_size}


@contextmanager
def _capsule(source: Path) -> Iterator[tuple[zipfile.ZipFile, dict[str, Any]]]:
    with _source(source, maximum=MAX_CAPSULE_BYTES) as stream:
        count = _zip_directory(stream, maximum_entries=MAX_PARTS * 2 + 3, maximum_central=16 * 1024 * 1024)
        with zipfile.ZipFile(stream, "r") as archive:
            infos = archive.infolist()
            names = [item.filename for item in infos]
            if len(names) != count or len(set(names)) != len(names) or "MANIFEST.json" not in names:
                _fail("invalid_conversion_capsule")
            for item in infos:
                if (item.is_dir() or item.flag_bits & 1 or item.comment or item.extra and len(item.extra) > MAX_HEADER_BYTES
                        or stat.S_IFMT(item.external_attr >> 16) not in (0, stat.S_IFREG)
                        or item.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)):
                    _fail("unsafe_conversion_capsule")
            manifest_info = archive.getinfo("MANIFEST.json")
            if manifest_info.file_size > 8 * 1024 * 1024:
                _fail("conversion_manifest_limit")
            with archive.open(manifest_info) as member:
                manifest = legacy._json_loads(member.read(8 * 1024 * 1024 + 1))
            if not isinstance(manifest, dict) or manifest.get("schema_version") != CAPSULE_SCHEMA:
                _fail("unsupported_conversion_capsule")
            domain = dict(manifest)
            observed = domain.pop("capsule_manifest_sha256", None)
            if _match(observed, _HASH) != sha256(canonical_bytes(domain)) or manifest.get("authority") != AUTHORITY:
                _fail("conversion_manifest_hash_mismatch")
            declared: set[str] = {"MANIFEST.json"}
            for collection, prefix, maximum in (("record_parts", "records", MAX_PART_BYTES), ("mapping_parts", "mappings", MAX_MAP_PART_BYTES)):
                entries = manifest.get(collection)
                if not isinstance(entries, list) or len(entries) > MAX_PARTS:
                    _fail("conversion_catalog_limit")
                for index, item in enumerate(entries):
                    if not isinstance(item, dict) or item.get("path") != f"{prefix}/{index + 1:06d}.ndjson":
                        _fail("invalid_conversion_catalog")
                    _integer(item.get("size"), maximum, minimum=1)
                    _match(item.get("sha256"), _HASH)
                    declared.add(item["path"])
            for key, allowed, maximum in (("source_member", {"source/original.pack", "source/original.zip"}, MAX_SOURCE_BYTES),
                                          ("checkpoint_member", {"source/checkpoint.json"}, MAX_CHECKPOINT_BYTES)):
                item = manifest.get(key)
                if key == "checkpoint_member" and item is None:
                    continue
                if not isinstance(item, dict) or set(item) != {"path", "size", "sha256"} or item["path"] not in allowed:
                    _fail("invalid_conversion_source_catalog")
                _integer(item["size"], maximum, minimum=1)
                _match(item["sha256"], _HASH)
                declared.add(item["path"])
            if set(names) != declared:
                _fail("conversion_capsule_members_mismatch")
            for item in [*manifest["record_parts"], *manifest["mapping_parts"], manifest["source_member"], *([manifest["checkpoint_member"]] if manifest.get("checkpoint_member") else [])]:
                if archive.getinfo(item["path"]).file_size != item["size"]:
                    _fail("conversion_member_size_mismatch")
            yield archive, manifest


def _copy_member(archive: zipfile.ZipFile, item: Mapping[str, Any], output: BinaryIO) -> None:
    digest, size = hashlib.sha256(), 0
    with archive.open(item["path"]) as member:
        while chunk := member.read(1024 * 1024):
            size += len(chunk)
            if size > item["size"]:
                _fail("conversion_member_size_mismatch")
            digest.update(chunk)
            output.write(chunk)
    if size != item["size"] or digest.hexdigest() != item["sha256"]:
        _fail("conversion_member_hash_mismatch")


def extract(source: Path, output: Path, *, part: int = 1, original: bool = False) -> Mapping[str, Any]:
    source, output = _absolute(source), _absolute(output)
    if source == output:
        _fail("paths_must_be_distinct")
    _integer(part, MAX_PARTS, minimum=1)
    with _staging(output) as (staged, stream):
        with _capsule(source) as (archive, manifest):
            if not original and part > len(manifest["record_parts"]):
                _fail("conversion_part_not_found")
            item = manifest["source_member"] if original else manifest["record_parts"][part - 1]
            _copy_member(archive, item, stream)
            result = {"schema_version": RESULT_SCHEMA, "state": "original_restored" if original else "part_extracted",
                      "output_sha256": item["sha256"], "output_bytes": item["size"],
                      "part": None if original else part, "record_parts": len(manifest["record_parts"]),
                      "requires_previous_parts": None if original else part - 1,
                      "original_author_authenticated": False, "trust_granted": False, "vault_database_opened": False,
                      "network_accessed": False, "written": True, "authority": dict(AUTHORITY)}
        _publish(staged, output, stream)
    return result


def _mapped_document(vault: Any, connection: sqlite3.Connection, mapping: Mapping[str, Any]) -> tuple[dict[str, Any], bytes]:
    """Reconstruct/check preserved raw evidence before accepting source aliases."""
    entries = mapping.get("original_evidence_records")
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_MEMBER_BYTES // FRAGMENT_BYTES:
        _fail("invalid_conversion_evidence_map")
    output = bytearray()
    total: int | None = None
    prefix = "Original v0.21 document bytes (untrusted evidence):\n"
    for reference in entries:
        _object(reference, {"memory_id", "record_sha256", "offset", "size"})
        row = connection.execute("SELECT * FROM memories WHERE memory_id=?", (reference["memory_id"],)).fetchone()
        if row is None:
            _fail("conversion_target_not_imported")
        record = vault._record_from_row(row)
        if (record["record_sha256"] != reference["record_sha256"] or record["kind"] != "provenance"
                or not record["text"].startswith(prefix)):
            _fail("conversion_evidence_record_mismatch")
        value = _object(legacy._json_loads(record["text"][len(prefix):].encode("utf-8")), {
            "profile", "document_sha256", "offset", "size", "total_size", "encoding", "data",
        })
        if (value["profile"] != "memory-vault-v021-evidence-fragment/v1" or value["encoding"] != "base64"
                or value["document_sha256"] != mapping.get("source_document_sha256")
                or _integer(value["offset"], MAX_MEMBER_BYTES) != len(output)
                or value["offset"] != reference["offset"] or value["size"] != reference["size"]
                or not isinstance(value["data"], str)):
            _fail("conversion_evidence_fragment_mismatch")
        observed_total = _integer(value["total_size"], MAX_MEMBER_BYTES, minimum=1)
        if total is not None and total != observed_total:
            _fail("conversion_evidence_fragment_mismatch")
        total = observed_total
        size = _integer(value["size"], FRAGMENT_BYTES, minimum=1)
        if len(value["data"]) > 4 * ((FRAGMENT_BYTES + 2) // 3):
            _fail("conversion_evidence_fragment_limit")
        try:
            raw = base64.b64decode(value["data"].encode("ascii"), validate=True)
        except (ValueError, UnicodeError):
            _fail("conversion_evidence_encoding_invalid")
        if len(raw) != size or len(output) + size > total:
            _fail("conversion_evidence_fragment_mismatch")
        output.extend(raw)
    if len(output) != total or sha256(bytes(output)) != mapping.get("source_document_sha256"):
        _fail("conversion_evidence_hash_mismatch")
    value = legacy._json_loads(bytes(output))
    if not isinstance(value, dict) or value.get("schema_version") != mapping.get("legacy_schema"):
        _fail("conversion_evidence_schema_mismatch")
    if value["schema_version"] == legacy.EPISODE_SCHEMA:
        legacy._episode(value, mapping["source_path"], mapping["source_document_sha256"])
        expected = (value["episode_id"], value["source_id"], value["episode_sha256"])
    elif value["schema_version"] == legacy.EVENT_SCHEMA:
        _object(value, legacy._EVENT_FIELDS)
        legacy._verify_hash(value, "event_sha256")
        if _match(value["payload_sha256"], _HASH) != legacy._legacy_hash(value["payload"]):
            _fail("legacy_payload_hash_mismatch")
        source = _object(value["source"], {"source_id", "revision_id", "source_sequence", "evidence_anchor_sha256"})
        expected = (value["memory_event_id"], source["source_id"], source["evidence_anchor_sha256"])
    else:
        _fail("unsupported_conversion_alias")
    if expected != (mapping.get("legacy_id"), mapping.get("source_id"), mapping.get("evidence_anchor_sha256")):
        _fail("conversion_alias_source_mismatch")
    return value, bytes(output)


def _primary_identity(record: Mapping[str, Any]) -> str:
    """A dependency must be an old document anchor, never a projection part."""
    prefix = "legacy:v021:identity:"
    identities = [item[len(prefix):] for item in record["entities"] if item.startswith(prefix)]
    if len(identities) != 1 or not (legacy._EPISODE.fullmatch(identities[0]) or legacy._EVENT.fullmatch(identities[0])):
        _fail("conversion_dependency_identity_mismatch")
    identity = identities[0]
    episode = legacy._EPISODE.fullmatch(identity) is not None
    if episode != (record["kind"] == "episode"):
        _fail("conversion_dependency_kind_mismatch")
    text = record["text"]
    large = "Lossless v0.21 visible-content anchor. Reconstruct quoted fragments in numerical order.\n"
    if text.startswith(large):
        anchor = _object(legacy._json_loads(text[len(large):].encode("utf-8")), {
            "document_sha256", "body_sha256", "visible_fragment_count", "legacy_schema", "legacy_id",
        })
        if (anchor["legacy_id"] != identity
                or anchor["legacy_schema"] != (legacy.EPISODE_SCHEMA if episode else legacy.EVENT_SCHEMA)
                or "legacy:v021:document:" + _match(anchor["document_sha256"], _HASH) not in record["entities"]):
            _fail("conversion_dependency_identity_mismatch")
    elif episode:
        if not text.startswith("Original visible messages (roles, phases and text are quoted data):\n"):
            _fail("conversion_dependency_not_anchor")
    else:
        kinds = [item[len("semantic:v021:"):] for item in record["entities"] if item.startswith("semantic:v021:")]
        if (len(kinds) != 1 or kinds[0] not in legacy._EVENT_KINDS or record["kind"] != legacy._EVENT_KINDS[kinds[0]]
                or not text.startswith("Original v0.21 " + kinds[0] + " payload (untrusted historical claim):\n")):
            _fail("conversion_dependency_not_anchor")
    return identity


def _mapped_projection(vault: Any, connection: sqlite3.Connection, mapping: Mapping[str, Any],
                       candidate: Mapping[str, Any], value: dict[str, Any], raw: bytes) -> None:
    """Bind the alias to the complete deterministic canonical document.

    Checks every current canonical fragment, the exact typed dependency set
    and the original evidence bytes. An external map cannot exchange a full
    event for one same-kind relation part or omit a visible/evidence fragment.
    Dependency identity labels remain untrusted historical claims, never an
    author attestation; current admission is still checked on alias use.
    """
    def read(identity: Any, digest: Any = None) -> dict[str, Any]:
        _match(identity, re.compile(r"mem_[0-9a-f]{40}"))
        found = connection.execute("SELECT * FROM memories WHERE memory_id=?", (identity,)).fetchone()
        if found is None:
            _fail("conversion_target_not_imported")
        record = vault._record_from_row(found)
        if digest is not None and record["record_sha256"] != _match(digest, _HASH):
            _fail("conversion_mapping_evidence_mismatch")
        return record

    references: dict[str, list[dict[str, Any]]] = {}
    for name, fields, maximum in (
        ("original_evidence_records", {"memory_id", "record_sha256", "offset", "size"}, 32),
        ("visible_fragment_records", {"memory_id", "record_sha256", "index"}, 256),
        ("relation_projection_records", {"memory_id", "record_sha256"}, 16),
    ):
        entries = mapping.get(name)
        if not isinstance(entries, list) or len(entries) > maximum:
            _fail("invalid_conversion_fragment_map")
        references[name] = [_object(item, fields) for item in entries]
    auxiliaries = {item["memory_id"] for name in ("original_evidence_records", "visible_fragment_records") for item in references[name]}
    relation_records = [read(item["memory_id"], item["record_sha256"]) for item in references["relation_projection_records"]]
    actual = [edge for record in (relation_records or [candidate]) for edge in record["relations"] if edge["target"] not in auxiliaries]
    identities: dict[str, str] = {}
    target_identities: dict[str, str] = {}
    for edge in actual:
        memory_id = edge["target"]
        old_id = target_identities.get(memory_id)
        if old_id is None:
            old_id = _primary_identity(read(memory_id))
            target_identities[memory_id] = old_id
        if old_id in identities and identities[old_id] != memory_id:
            _fail("conversion_dependency_identity_collision")
        identities[old_id] = memory_id
    if value["schema_version"] == legacy.EPISODE_SCHEMA:
        kind = "episode"
        old_edges = [("continues", target) for target in value["parent_episode_ids"]]
    else:
        if value["kind"] not in legacy._EVENT_KINDS:
            _fail("unsupported_legacy_event_kind")
        kind = legacy._EVENT_KINDS[value["kind"]]
        old_edges = [("derived_from", value["source"]["revision_id"])]
        episodic = value["payload"].get("profile") == "memory-network-episode-event/v1"
        for name, relation in _RELATIONS.items():
            targets = legacy._references(value[name], value["memory_event_id"], legacy._EVENT, 256)
            old_edges.extend(("continues" if name == "parents" and episodic else relation, target) for target in targets)
    expected_edges: list[dict[str, str]] = []
    expected_pairs: set[tuple[str, str]] = set()
    for relation, old_id in old_edges:
        if old_id not in identities:
            _fail("conversion_dependency_missing")
        pair = (relation, identities[old_id])
        if pair not in expected_pairs:
            expected_pairs.add(pair)
            expected_edges.append({"type": pair[0], "target": pair[1]})
    if expected_pairs != {(edge["type"], edge["target"]) for edge in actual}:
        _fail("conversion_dependency_set_mismatch")
    row = {"legacy_id": mapping["legacy_id"], "schema": value["schema_version"], "kind": kind,
           "created_at": legacy._timestamp(value["created_at"])}
    expected, projected = _document_projection(value, raw, mapping["source_document_sha256"], row, expected_edges)
    if candidate != expected[-1] or any(mapping[name] != projected[name] for name in projected):
        _fail("conversion_alias_not_complete_anchor")
    for record in expected[:-1]:
        if read(record["memory_id"], record["record_sha256"]) != record:
            _fail("conversion_projection_record_mismatch")


def register_aliases(source: Path, config_path: Path, *, part: int = 1) -> Mapping[str, Any]:
    """Explicit local control-state registration AFTER ordinary bundle import.

    The canonical records themselves carry legacy identity/document markers;
    no selected archive assertion is allowed to relabel an unrelated record.
    Admission remains governed by current trust when a host consumes an alias.
    """
    from memory_vault_client import ClientConfig
    from memory_vault_compat import register_legacy_aliases
    _integer(part, MAX_PARTS, minimum=1)
    config = ClientConfig.load(config_path)
    batch: list[dict[str, Any]] = []
    added = checked = 0
    with _capsule(source) as (archive, manifest):
        if part > len(manifest["mapping_parts"]):
            _fail("conversion_mapping_part_not_found")
        item = manifest["mapping_parts"][part - 1]
        with archive.open(item["path"]) as stream:
            raw = stream.read(MAX_MAP_PART_BYTES + 1)
        if len(raw) != item["size"] or sha256(raw) != item["sha256"]:
            _fail("conversion_member_hash_mismatch")
        rows = raw.splitlines()
        if len(rows) > MAX_DOCUMENTS:
            _fail("conversion_mapping_row_limit")
        # Validate this whole bounded mapping part before making its first
        # idempotent batch. A concurrent missing record can still stop later
        # batches; earlier registrations are harmless and retries are exact.
        vault = config.vault()
        with closing(vault._connect(writable=False)) as connection:
            for line in rows:
                value = legacy._json_loads(line)
                if not isinstance(value, dict) or value.get("schema_version") != MAP_SCHEMA:
                    _fail("invalid_conversion_mapping")
                identity = value.get("legacy_id")
                if value.get("legacy_schema") == legacy.CONVERSATION_SCHEMA:
                    continue
                _match(identity, legacy._EPISODE if value.get("legacy_schema") == legacy.EPISODE_SCHEMA else legacy._EVENT)
                stored = connection.execute("SELECT * FROM memories WHERE memory_id=?", (value.get("memory_id"),)).fetchone()
                if stored is None:
                    _fail("conversion_target_not_imported")
                record = vault._record_from_row(stored)
                if (record["record_sha256"] != value.get("record_sha256")
                        or "legacy:v021:identity:" + identity not in record["entities"]
                        or "legacy:v021:document:" + str(value.get("source_document_sha256")) not in record["entities"]):
                    _fail("conversion_mapping_evidence_mismatch")
                original, original_raw = _mapped_document(vault, connection, value)
                _mapped_projection(vault, connection, value, record, original, original_raw)
                batch.append({key: value.get(key) for key in ("legacy_id", "memory_id", "record_sha256", "source_id", "evidence_anchor_sha256")})
    # The selected capsule's descriptor/fingerprint check has completed before
    # any durable control-state registration. Canonical targets are rechecked
    # independently by each bounded registration transaction.
    for offset in range(0, len(batch), 1024):
        result = register_legacy_aliases(config_path, batch[offset:offset + 1024])
        added += int(result["added"])
        checked += len(batch[offset:offset + 1024])
    return {"schema_version": RESULT_SCHEMA, "state": "aliases_registered", "checked": checked, "added": added,
            "mapping_part": part, "mapping_parts": len(manifest["mapping_parts"]), "trust_granted": False,
            "vault_database_opened": True, "canonical_records_changed": False, "control_state_changed": added > 0,
            "network_accessed": False, "authority": dict(AUTHORITY)}


class _Parser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        _fail("invalid_arguments")


def main(argv: Sequence[str] | None = None, *, config_path: Path | None = None) -> int:
    try:
        arguments = list(sys.argv[1:] if argv is None else argv)
        if arguments in (["--help"], ["-h"]):
            result: Mapping[str, Any] = {"schema_version": RESULT_SCHEMA, "commands": ["verify", "repack", "checkpoint", "verify-chain", "convert", "extract", "register-aliases"],
                "source": "absolute old memory-pack/v1 or export-network ZIP", "conversion": "unsigned lossless capsule; explicit import required",
                "limits": {"source_bytes": MAX_SOURCE_BYTES, "raw_bytes": MAX_RAW_BYTES, "documents": MAX_DOCUMENTS}, "network_accessed": False}
        else:
            parser = _Parser(add_help=False)
            parser.add_argument("command", choices=("verify", "repack", "checkpoint", "verify-chain", "convert", "extract", "register-aliases"))
            parser.add_argument("--source", type=Path)
            parser.add_argument("--output", type=Path)
            parser.add_argument("--format", choices=("pack", "zip"), default="pack")
            parser.add_argument("--checkpoint", type=Path)
            parser.add_argument("--trusted-checkpoint-sha256")
            parser.add_argument("--dry-run", action="store_true")
            parser.add_argument("--part", type=int, default=1)
            parser.add_argument("--original", action="store_true")
            parser.add_argument("--config", type=Path)
            parser.add_argument("--generation", type=int)
            parser.add_argument("--previous-checkpoint-sha256")
            parser.add_argument("--chain", type=Path, nargs="+")
            args = parser.parse_args(arguments)
            read_flags = {"--source", "--checkpoint", "--trusted-checkpoint-sha256"}
            allowed = {
                "verify": read_flags,
                "repack": read_flags | {"--output", "--format"},
                "convert": read_flags | {"--output", "--dry-run"},
                "checkpoint": {"--source", "--output", "--generation", "--previous-checkpoint-sha256"},
                "verify-chain": {"--chain", "--trusted-checkpoint-sha256"},
                "extract": {"--source", "--output", "--part", "--original"},
                "register-aliases": {"--source", "--config", "--part"},
            }[args.command]
            if any(item.startswith("--") and item.split("=", 1)[0] not in allowed for item in arguments):
                _fail("invalid_arguments_for_operation")
            if args.command != "verify-chain" and args.source is None:
                _fail("source_required")
            common = {"checkpoint": args.checkpoint, "trusted_checkpoint_sha256": args.trusted_checkpoint_sha256}
            if args.command == "verify":
                result = verify(args.source, **common)
            elif args.command == "verify-chain":
                result = verify_checkpoint_chain(args.chain, trusted_checkpoint_sha256=args.trusted_checkpoint_sha256)
            elif args.command == "register-aliases":
                selected = config_path or args.config
                if selected is None:
                    from memory_vault_client import default_config_path
                    selected = default_config_path()
                if config_path is not None and args.config is not None and _absolute(config_path) != _absolute(args.config):
                    _fail("selected_configuration_mismatch")
                result = register_aliases(args.source, selected, part=args.part)
            else:
                if args.output is None:
                    _fail("output_required")
                if args.command == "repack":
                    result = repack(args.source, args.output, format=args.format, **common)
                elif args.command == "checkpoint":
                    result = create_checkpoint(args.source, args.output, generation=args.generation,
                                               previous_checkpoint_sha256=args.previous_checkpoint_sha256)
                elif args.command == "convert":
                    result = convert(args.source, args.output, dry_run=args.dry_run, **common)
                else:
                    result = extract(args.source, args.output, part=args.part, original=args.original)
        print(json.dumps({"ok": True, "result": result}, ensure_ascii=False, separators=(",", ":")))
        return 0
    except (MemoryError, legacy.MigrationError) as exc:
        code = exc.code
    except (OSError, sqlite3.Error, zipfile.BadZipFile, RuntimeError, ValueError, TypeError, KeyError, OverflowError):
        code = "legacy_pack_unavailable"
    print(json.dumps({"ok": False, "error": {"code": code}, "authority": dict(AUTHORITY)}, separators=(",", ":")))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
