#!/usr/bin/env python3
"""Small v0.21 export-network ZIP to current portable NDJSON conversion.

This is a bounded, one-way, offline migration tool, not an old runtime. It never
opens a Git repository, indexes private application data, connects to a server,
modifies the source archive, grants trust, or imports the resulting bundle.
Only an explicitly selected export file is read. Unknown schemas, unsupported
claims, missing graph targets, and cyclic graphs fail before outputs are made.
This retained, single-bundle interface is not the complete v0.25 pack migrator;
memory_vault_legacy_pack.py supplies lossless large-pack/multipart conversion.
"""

from __future__ import annotations

import argparse
from collections import Counter
from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import dataclass
import datetime as dt
import hashlib
import heapq
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from typing import Any, BinaryIO, Iterator
import uuid
import zipfile

# Adjacent source files are also usable when this file is loaded by path rather
# than started as a script. There is no package installation or runtime download.
_SOURCE_DIRECTORY = str(Path(__file__).resolve().parent)
if _SOURCE_DIRECTORY not in sys.path:
    sys.path.insert(0, _SOURCE_DIRECTORY)

from memory_vault import (  # noqa: E402
    BUNDLE_SCHEMA,
    HASH_PROFILE,
    MAX_BUNDLE_BYTES,
    MAX_BUNDLE_LINE_BYTES,
    MAX_BUNDLE_RECORDS,
    MemoryError as VaultError,
    build_record,
    canonical_bytes,
    sha256,
    validate_record,
)
import memory_vault_storage as protected_storage  # noqa: E402


MIGRATION_SCHEMA = "universal-memory-migration-report/v1"
SOURCE_SCHEMA = "memory-network-bundle/v1"
EPISODE_SCHEMA = "memory-episode/v1"
EVENT_SCHEMA = "memory-event/v2"
CONVERSATION_SCHEMA = "conversation-export/v1"
MAX_SOURCE_BYTES = 64 * 1024 * 1024
MAX_MEMBER_BYTES = 2 * 1024 * 1024
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_ENTRIES = 10_000
MAX_REPORT_BYTES = 16 * 1024 * 1024

_DIGEST = re.compile(r"[0-9a-f]{64}")
_EPISODE = re.compile(r"ep-[0-9a-f]{40}")
_EVENT = re.compile(r"evt-[0-9a-f]{40}")
_SOURCE = re.compile(r"src-[0-9a-f]{40}")
_IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9_-]{1,63}")
_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})"
)
_EPISODE_PATH = re.compile(r"memory/episodes/([0-9a-f]{2})/(ep-[0-9a-f]{40})\.json")
_EVENT_PATH = re.compile(r"memory/events/(?:([0-9a-f]{2})/)?(evt-[0-9a-f]{40})\.json")
_CONVERSATION_PATH = re.compile(r"sources/([a-z0-9][a-z0-9_-]{1,63})/revisions/([a-z0-9][a-z0-9_-]{1,63})\.json")
_EVENT_FIELDS = {
    "schema_version", "memory_event_id", "kind", "confidence", "source",
    "claim_key", "parents", "supersedes", "conflicts_with", "resolves", "payload",
    "payload_sha256", "hash_profile", "event_sha256", "created_at",
}
_EVENT_KINDS = {
    "decision": "decision",
    "constraint": "observation",
    "progress": "observation",
    "next_action": "continuity",
    "hypothesis": "observation",
    "artifact_created": "artifact",
    "artifact_verified": "artifact",
    "correction": "observation",
    "user_preference": "observation",
    "conflict_declared": "relation",
    "conflict_resolved": "relation",
    "checkpoint_note": "continuity",
}
_PRIVATE_CLAIM_FIELDS = {
    "task_id", "task_ids", "task_ref", "semantic_task_id", "semantic_task_ids",
    "conversation_id", "conversation_ids", "conversation_ref", "thread_id", "thread_ref",
    "project_id", "project_ids", "project_ref", "native_conversation_id",
    "source_id", "revision_id", "source_instance_id", "agent_id", "device_id",
    "runtime_id", "session_id", "session_ref", "local_path", "absolute_path",
    "credential", "credentials", "api_key", "access_token", "refresh_token", "private_key",
}
_PRIVATE_CLAIM_FIELD_KEYS = {
    re.sub(r"[^a-z0-9]", "", field.casefold()) for field in _PRIVATE_CLAIM_FIELDS
}


class MigrationError(ValueError):
    def __init__(self, code: str, *, member_sha256: str | None = None):
        self.code = code
        self.member_sha256 = member_sha256
        super().__init__(code)


@dataclass(frozen=True)
class _Node:
    identity: str
    schema: str
    kind: str
    text: str
    created_at: str
    relations: tuple[tuple[str, str], ...]
    source_document_sha256: str
    source_ref: str
    uncarried_fields: tuple[str, ...]
    relation_projection: str | None = None


def _object(value: Any, required: set[str], optional: set[str] = frozenset()) -> dict[str, Any]:
    if not isinstance(value, dict) or not required.issubset(value) or set(value) - required - optional:
        raise MigrationError("invalid_legacy_shape")
    return value


def _text(value: Any, *, maximum: int = MAX_MEMBER_BYTES) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise MigrationError("invalid_legacy_text")
    try:
        if len(value.encode("utf-8")) > maximum:
            raise MigrationError("legacy_text_too_large")
    except UnicodeError:
        raise MigrationError("invalid_legacy_text") from None
    return value


def _match(value: Any, pattern: re.Pattern[str], code: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise MigrationError(code)
    return value


def _timestamp(value: Any) -> str:
    _match(value, _TIMESTAMP, "invalid_legacy_timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    except (ValueError, OverflowError):
        raise MigrationError("invalid_legacy_timestamp") from None


def _string_list(value: Any, maximum: int) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum:
        raise MigrationError("invalid_legacy_list")
    return [_text(item, maximum=4096) for item in value]


def _references(value: Any, own_id: str, pattern: re.Pattern[str], maximum: int) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum:
        raise MigrationError("invalid_legacy_relations")
    result = [_match(item, pattern, "invalid_legacy_relation_id") for item in value]
    if len(set(result)) != len(result) or own_id in result:
        raise MigrationError("invalid_legacy_relations")
    return result


def _json_loads(data: bytes) -> Any:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise MigrationError("duplicate_legacy_json_key")
            result[key] = value
        return result

    def reject(_value: str) -> None:
        raise MigrationError("invalid_legacy_json")

    if data.startswith(b"\xef\xbb\xbf"):
        raise MigrationError("invalid_legacy_json")
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=unique, parse_constant=reject)
    except MigrationError:
        raise
    except (UnicodeError, ValueError, RecursionError):
        raise MigrationError("invalid_legacy_json") from None
    return value


def _legacy_jcs(value: Any) -> bytes:
    """The integer-only JCS domain actually used by the v0.21 export writer.

    Derived from that version's protocol.py, not a replacement crypto or a
    general legacy runtime. UTF-16 key ordering matters for non-ASCII claim keys.
    """
    nodes = 0

    def encode(item: Any, depth: int) -> str:
        nonlocal nodes
        nodes += 1
        if depth > 32 or nodes > 500_000:
            raise MigrationError("legacy_json_structure_too_large")
        if item is None:
            return "null"
        if item is True:
            return "true"
        if item is False:
            return "false"
        if isinstance(item, int):
            if abs(item) > 9_007_199_254_740_991:
                raise MigrationError("legacy_integer_out_of_range")
            return str(item)
        if isinstance(item, float):
            raise MigrationError("legacy_float_forbidden")
        if isinstance(item, str):
            return json.dumps(item, ensure_ascii=False, separators=(",", ":"))
        if isinstance(item, list):
            return "[" + ",".join(encode(child, depth + 1) for child in item) + "]"
        if isinstance(item, dict):
            if any(not isinstance(key, str) for key in item):
                raise MigrationError("invalid_legacy_json")
            keys = sorted(item, key=lambda key: key.encode("utf-16be"))
            return "{" + ",".join(
                json.dumps(key, ensure_ascii=False) + ":" + encode(item[key], depth + 1)
                for key in keys
            ) + "}"
        raise MigrationError("invalid_legacy_json")

    try:
        result = encode(value, 0).encode("utf-8")
    except (UnicodeError, ValueError, RecursionError):
        raise MigrationError("invalid_legacy_json") from None
    if len(result) > MAX_MANIFEST_BYTES:
        raise MigrationError("legacy_json_too_large")
    return result


def _legacy_hash(value: Any) -> str:
    return sha256(_legacy_jcs(value))


def _verify_hash(value: dict[str, Any], field: str) -> None:
    digest = _match(value.get(field), _DIGEST, "invalid_legacy_hash")
    domain = dict(value)
    domain.pop(field)
    if digest != _legacy_hash(domain):
        raise MigrationError("legacy_hash_mismatch")


def _messages(value: Any, *, maximum: int, phase_required: bool) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not 1 <= len(value) <= maximum:
        raise MigrationError("invalid_legacy_messages")
    result = []
    for ordinal, item in enumerate(value):
        required = {"ordinal", "role", "text"} | ({"phase"} if phase_required else set())
        message = _object(item, required, set() if phase_required else {"phase"})
        if type(message["ordinal"]) is not int or message["ordinal"] != ordinal:
            raise MigrationError("invalid_legacy_message_order")
        if message["role"] not in ("user", "assistant"):
            raise MigrationError("unsupported_legacy_message_role")
        phase = message.get("phase", "unknown")
        if phase not in ("commentary", "final_answer", "unknown"):
            raise MigrationError("unsupported_legacy_message_phase")
        result.append({"ordinal": ordinal, "role": message["role"], "phase": phase, "text": _text(message["text"])})
    return result


def _render_messages(messages: list[dict[str, Any]]) -> str:
    return "\n\n".join(
        f"{message['role'].upper()} [{message['phase']}]:\n{message['text']}"
        for message in messages
    )


def _episode(value: dict[str, Any], path: str, member_hash: str) -> _Node:
    _object(value, {
        "schema_version", "episode_id", "source_id", "source_sequence", "parent_episode_ids",
        "captured_at", "coverage", "included_content", "excluded_content", "messages",
        "hash_profile", "created_at", "episode_sha256",
    })
    identity = _match(value["episode_id"], _EPISODE, "invalid_legacy_episode_id")
    matched = _EPISODE_PATH.fullmatch(path)
    if matched is None or matched[2] != identity or matched[1] != identity[3:5]:
        raise MigrationError("legacy_episode_path_mismatch")
    _match(value["source_id"], _SOURCE, "invalid_legacy_source_id")
    if type(value["source_sequence"]) is not int or value["source_sequence"] < 0:
        raise MigrationError("invalid_legacy_sequence")
    parents = _references(value["parent_episode_ids"], identity, _EPISODE, 64)
    if value["coverage"] != "partial_active_turn" or value["captured_at"] != value["created_at"]:
        raise MigrationError("unsupported_legacy_episode_coverage")
    _string_list(value["included_content"], 32)
    _string_list(value["excluded_content"], 32)
    messages = _messages(value["messages"], maximum=2, phase_required=True)
    if value["hash_profile"] != "jcs-rfc8785+sha256/episode-v1":
        raise MigrationError("unsupported_legacy_hash_profile")
    _verify_hash(value, "episode_sha256")
    return _Node(
        identity=identity, schema=EPISODE_SCHEMA, kind="episode", text=_render_messages(messages),
        created_at=_timestamp(value["created_at"]),
        relations=tuple(("continues", target) for target in parents),
        source_document_sha256=member_hash, source_ref="legacy-v021:sha256:" + _legacy_hash(value),
        uncarried_fields=("source_id", "source_sequence", "included_content", "excluded_content", "coverage"),
        relation_projection="parent_episode_ids->continues" if parents else None,
    )


def _conversation(
    value: dict[str, Any], path: str, member_hash: str, *, maximum_messages: int = 20_000,
) -> _Node:
    _object(value, {
        "schema_version", "source_id", "title", "captured_at", "coverage",
        "included_content", "excluded_content", "messages",
    })
    matched = _CONVERSATION_PATH.fullmatch(path)
    if matched is None or matched[1] != value["source_id"]:
        raise MigrationError("legacy_conversation_path_mismatch")
    title = _text(value["title"], maximum=2000)
    if len(title) > 500 or value["coverage"] not in ("full", "partial", "partial_active_turn"):
        raise MigrationError("invalid_legacy_conversation")
    _string_list(value["included_content"], 100)
    _string_list(value["excluded_content"], 100)
    # The retained single-bundle ZIP converter has its original count limit.
    # The full pack converter supplies a bound derived from the already checked
    # member bytes: v0.21 conversation exports had no independent message cap.
    messages = _messages(value["messages"], maximum=maximum_messages, phase_required=False)
    return _Node(
        identity="conversation:" + path, schema=CONVERSATION_SCHEMA, kind="episode",
        text=f"Legacy visible conversation snapshot\nTitle: {title}\nCoverage: {value['coverage']}\n\n" + _render_messages(messages),
        created_at=_timestamp(value["captured_at"]), relations=(),
        source_document_sha256=member_hash, source_ref="legacy-v021:sha256:" + _legacy_hash(value),
        uncarried_fields=("source_id", "included_content", "excluded_content"),
    )


def _check_claim_fields(value: Any) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if re.sub(r"[^a-z0-9]", "", key.casefold()) in _PRIVATE_CLAIM_FIELD_KEYS:
                raise MigrationError("private_identifier_in_legacy_claim")
            _check_claim_fields(child)
    elif isinstance(value, list):
        for child in value:
            _check_claim_fields(child)


def _episode_event_id(source_id: str, episode_id: str) -> str:
    return "evt-" + sha256(f"episode\0{source_id}\0{episode_id}".encode("utf-8"))[:40]


def _event(
    value: dict[str, Any], path: str, member_hash: str,
    episodes: Mapping[str, dict[str, Any]],
) -> _Node:
    _object(value, _EVENT_FIELDS)
    identity = _match(value["memory_event_id"], _EVENT, "invalid_legacy_event_id")
    matched = _EVENT_PATH.fullmatch(path)
    if matched is None or matched[2] != identity or (matched[1] is not None and matched[1] != identity[4:6]):
        raise MigrationError("legacy_event_path_mismatch")
    if not isinstance(value["kind"], str) or value["kind"] not in _EVENT_KINDS:
        raise MigrationError("unsupported_legacy_event_kind")
    if value["confidence"] not in ("source_explicit", "assistant_inferred"):
        raise MigrationError("unsupported_legacy_confidence")
    source = _object(value["source"], {"source_id", "revision_id", "source_sequence", "evidence_anchor_sha256"})
    _match(source["source_id"], _SOURCE, "invalid_legacy_source_id")
    revision = _match(source["revision_id"], _EPISODE, "invalid_legacy_episode_id")
    episode = episodes.get(revision)
    if episode is None:
        raise MigrationError("missing_legacy_episode_evidence")
    if (
        type(source["source_sequence"]) is not int
        or source["source_sequence"] != episode["source_sequence"]
        or source["source_id"] != episode["source_id"]
        or source["evidence_anchor_sha256"] != episode["episode_sha256"]
    ):
        raise MigrationError("legacy_evidence_anchor_mismatch")
    if value["claim_key"] is not None:
        _match(value["claim_key"], _IDENTIFIER, "invalid_legacy_claim_key")
    references = {
        relation: _references(value[relation], identity, _EVENT, 256)
        for relation in ("parents", "supersedes", "conflicts_with", "resolves")
    }
    if value["kind"] == "conflict_declared" and len(references["conflicts_with"]) < 2:
        raise MigrationError("invalid_legacy_conflict")
    if value["kind"] == "conflict_resolved" and not references["resolves"]:
        raise MigrationError("invalid_legacy_conflict")
    if value["hash_profile"] != "jcs-rfc8785+sha256/event-v2":
        raise MigrationError("unsupported_legacy_hash_profile")
    payload = value["payload"]
    if not isinstance(payload, dict):
        raise MigrationError("invalid_legacy_payload")
    if _match(value["payload_sha256"], _DIGEST, "invalid_legacy_hash") != _legacy_hash(payload):
        raise MigrationError("legacy_payload_hash_mismatch")
    _verify_hash(value, "event_sha256")
    profile = payload.get("profile")
    parent_relation = "related_to"
    if profile == "memory-network-episode-event/v1":
        _object(payload, {"memory_form", "profile", "message_count", "roles", "continuity"})
        parents = episode["parent_episode_ids"]
        expected_parents = [_episode_event_id(source["source_id"], parents[-1])] if parents else []
        if (
            value["kind"] != "checkpoint_note" or value["confidence"] != "source_explicit"
            or value["claim_key"] is not None or payload["memory_form"] != "episodic"
            or payload["roles"] != [message["role"] for message in episode["messages"]]
            or type(payload["message_count"]) is not int or payload["message_count"] != len(episode["messages"])
            or payload["continuity"] != ("continues" if expected_parents else "origin")
            or references["parents"] != expected_parents
            or any(references[relation] for relation in ("supersedes", "conflicts_with", "resolves"))
            or identity != _episode_event_id(source["source_id"], revision)
        ):
            raise MigrationError("invalid_legacy_continuity_profile")
        parent_relation = "continues"
        text = "Imported visible-episode continuity checkpoint\n" + canonical_bytes(payload).decode("utf-8")
    elif profile == "memory-network-semantic/v1":
        _object(payload, {"profile", "claim"})
        claim = payload["claim"]
        if value["confidence"] != "assistant_inferred" or not isinstance(claim, dict) or not claim:
            raise MigrationError("invalid_legacy_semantic_profile")
        _check_claim_fields(claim)
        identity_domain = {
            "source_id": source["source_id"], "episode_id": revision, "kind": value["kind"],
            "claim_key": value["claim_key"], **references, "payload": payload,
        }
        if identity != "evt-" + _legacy_hash(identity_domain)[:40]:
            raise MigrationError("legacy_event_identity_mismatch")
        # Preserve the entire structured claim as evidence. Do not invent a
        # summary, infer a new goal, or promote an old confidence label.
        text = f"Imported legacy {value['kind']} claim\n" + canonical_bytes(claim).decode("utf-8")
    else:
        raise MigrationError("unsupported_legacy_event_profile")
    relations = [("derived_from", revision)]
    for relation, targets in references.items():
        new_relation = parent_relation if relation == "parents" else relation
        relations.extend((new_relation, target) for target in targets)
    if len(relations) > 256:
        raise MigrationError("legacy_relation_count_exceeds_current_limit")
    return _Node(
        identity=identity, schema=EVENT_SCHEMA, kind=_EVENT_KINDS[value["kind"]], text=text,
        created_at=_timestamp(value["created_at"]), relations=tuple(relations),
        source_document_sha256=member_hash, source_ref="legacy-v021:sha256:" + _legacy_hash(value),
        uncarried_fields=("source.source_id", "source.source_sequence", "claim_key", "confidence"),
        relation_projection="parents->" + parent_relation if references["parents"] else None,
    )


def _absolute(value: Path) -> Path:
    path = Path(value)
    if os.name == "nt":
        try:
            return protected_storage.validate_path(path)
        except protected_storage.StorageError as exc:
            raise MigrationError(exc.code) from None
    if not path.is_absolute() or ".." in path.parts or not path.name or "\x00" in str(path):
        raise MigrationError("absolute_plain_path_required")
    return path


def _check_parent_chain(path: Path, *, create: bool, private: bool) -> bool:
    if os.name == "nt":
        try:
            protected_storage.validate_path(path)
            if private:
                protected_storage.private_directory(path.parent, create=create)
            elif not path.parent.exists():
                return False
            return True
        except FileNotFoundError:
            return False
        except protected_storage.StorageError as exc:
            raise MigrationError(exc.code) from None
    if private and (os.name != "posix" or not hasattr(os, "O_NOFOLLOW")):
        raise MigrationError("protected_output_unavailable")
    current = Path(path.anchor)
    for part in path.parts[1:-1]:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            if not create:
                return False
            try:
                current.mkdir(mode=0o700)
            except FileExistsError:
                pass
            info = current.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise MigrationError("unsafe_path_parent")
        if private:
            uid = os.getuid()
            if info.st_uid not in {0, uid}:
                raise MigrationError("unsafe_path_parent")
            sticky_root = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
            if stat.S_IMODE(info.st_mode) & 0o022 and not sticky_root:
                raise MigrationError("unsafe_path_parent")
    if private:
        parent = path.parent.lstat()
        if parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) & 0o022:
            raise MigrationError("unsafe_path_parent")
    return True


@contextmanager
def _open_source(path: Path) -> Iterator[BinaryIO]:
    path = _absolute(path)
    if not _check_parent_chain(path, create=False, private=False):
        raise MigrationError("source_not_found")
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_SOURCE_BYTES:
        raise MigrationError("invalid_source_file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = protected_storage.open_file(path, flags) if os.name == "nt" else os.open(path, flags)
    with os.fdopen(fd, "rb") as stream:
        observed = os.fstat(stream.fileno())
        if (not stat.S_ISREG(observed.st_mode) or observed.st_nlink != 1
                or _source_fingerprint(before) != _source_fingerprint(observed)):
            raise MigrationError("source_changed")
        fingerprint = _source_fingerprint(observed)
        yield stream
        after = os.fstat(stream.fileno())
        if fingerprint != _source_fingerprint(after) or fingerprint != _source_fingerprint(path.lstat()):
            raise MigrationError("source_changed")


def _source_fingerprint(info: os.stat_result) -> tuple[int, ...]:
    mode = stat.S_IFMT(info.st_mode) if os.name == "nt" else info.st_mode
    return (info.st_dev, info.st_ino, mode, info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _new_output(path: Path) -> None:
    # lstat also detects a broken link; an existing output is never overwritten.
    _check_parent_chain(path, create=False, private=False)
    try:
        path.lstat()
    except FileNotFoundError:
        return
    raise MigrationError("output_exists")


def _archive_member(archive: zipfile.ZipFile, name: str, maximum: int) -> bytes:
    with archive.open(name, "r") as stream:
        result = stream.read(maximum + 1)
    if len(result) > maximum:
        raise MigrationError("legacy_member_too_large")
    return result


def _read_archive(source: Path) -> tuple[dict[str, Any], dict[str, _Node], str]:
    with _open_source(source) as stream:
        archive_digest = hashlib.sha256()
        source_bytes = 0
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            source_bytes += len(chunk)
            if source_bytes > MAX_SOURCE_BYTES:
                raise MigrationError("legacy_archive_too_large")
            archive_digest.update(chunk)
        stream.seek(0)
        with zipfile.ZipFile(stream, "r") as archive:
            infos = archive.infolist()
            if len(infos) > MAX_ENTRIES + 1 or archive.comment:
                raise MigrationError("unsupported_legacy_archive")
            names: set[str] = set()
            expanded = 0
            for info in infos:
                name = info.filename
                maximum = MAX_MANIFEST_BYTES if name == "MANIFEST.json" else MAX_MEMBER_BYTES
                file_type = stat.S_IFMT(info.external_attr >> 16)
                if (
                    name in names or info.is_dir() or info.flag_bits & 1 or info.comment
                    or info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                    or file_type not in (0, stat.S_IFREG) or info.file_size < 0 or info.file_size > maximum
                    or (info.file_size > 0 and info.compress_size <= 0)
                    or (info.compress_size > 0 and info.file_size > info.compress_size * 250)
                ):
                    raise MigrationError("unsafe_legacy_archive_member")
                if name != "MANIFEST.json" and not (_EPISODE_PATH.fullmatch(name) or _EVENT_PATH.fullmatch(name) or _CONVERSATION_PATH.fullmatch(name)):
                    raise MigrationError("unsupported_legacy_member_path")
                names.add(name)
                expanded += info.file_size
                if expanded > MAX_SOURCE_BYTES:
                    raise MigrationError("legacy_archive_too_large")
            if "MANIFEST.json" not in names:
                raise MigrationError("legacy_manifest_missing")
            manifest = _object(_json_loads(_archive_member(archive, "MANIFEST.json", MAX_MANIFEST_BYTES)), {
                "schema_version", "network_contract", "remote_commit_sha", "exported_at",
                "native_conversation_ids_included", "credentials_included", "entries", "network_sha256",
            })
            if (
                manifest["schema_version"] != SOURCE_SCHEMA
                or manifest["network_contract"] != "memory-network-graph/v1"
                or manifest["native_conversation_ids_included"] is not False
                or manifest["credentials_included"] is not False
            ):
                raise MigrationError("unsupported_legacy_manifest")
            _match(manifest["remote_commit_sha"], re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})"), "invalid_legacy_commit")
            _timestamp(manifest["exported_at"])
            _verify_hash(manifest, "network_sha256")
            entries = manifest["entries"]
            if not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
                raise MigrationError("invalid_legacy_entries")
            documents: dict[str, tuple[dict[str, Any], str]] = {}
            previous: str | None = None
            for raw in entries:
                entry = _object(raw, {"path", "sha256", "size"})
                path = _text(entry["path"], maximum=512)
                if path not in names or path == "MANIFEST.json" or (previous is not None and path <= previous):
                    raise MigrationError("legacy_manifest_members_mismatch")
                previous = path
                expected_hash = _match(entry["sha256"], _DIGEST, "invalid_legacy_hash")
                if type(entry["size"]) is not int or not 0 <= entry["size"] <= MAX_MEMBER_BYTES:
                    raise MigrationError("invalid_legacy_member_size")
                data = _archive_member(archive, path, MAX_MEMBER_BYTES)
                if len(data) != entry["size"] or sha256(data) != expected_hash:
                    raise MigrationError("legacy_member_hash_mismatch", member_sha256=expected_hash)
                try:
                    value = _json_loads(data)
                    if not isinstance(value, dict):
                        raise MigrationError("invalid_legacy_shape")
                    _legacy_jcs(value)
                    if value.get("schema_version") not in (EPISODE_SCHEMA, EVENT_SCHEMA, CONVERSATION_SCHEMA):
                        raise MigrationError("unsupported_legacy_schema")
                except MigrationError as exc:
                    raise MigrationError(exc.code, member_sha256=expected_hash) from None
                documents[path] = (value, expected_hash)
            if names != {"MANIFEST.json", *documents}:
                raise MigrationError("legacy_manifest_members_mismatch")

    # The source descriptor is closed before conversion or output creation.
    nodes: dict[str, _Node] = {}
    episodes: dict[str, dict[str, Any]] = {}
    for events in (False, True):
        for path, (value, member_hash) in documents.items():
            schema = value["schema_version"]
            if (schema == EVENT_SCHEMA) != events:
                continue
            try:
                if schema == EPISODE_SCHEMA:
                    node = _episode(value, path, member_hash)
                    episodes[node.identity] = value
                elif schema == CONVERSATION_SCHEMA:
                    node = _conversation(value, path, member_hash)
                else:
                    node = _event(value, path, member_hash, episodes)
                if node.identity in nodes:
                    raise MigrationError("duplicate_legacy_identity")
                nodes[node.identity] = node
            except MigrationError as exc:
                raise MigrationError(exc.code, member_sha256=member_hash) from None
    return manifest, nodes, archive_digest.hexdigest()


def _convert_nodes(nodes: Mapping[str, _Node]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    dependencies: dict[str, set[str]] = {}
    dependants: dict[str, set[str]] = {identity: set() for identity in nodes}
    for identity, node in nodes.items():
        targets = {target for _, target in node.relations}
        if not targets.issubset(nodes):
            raise MigrationError("missing_legacy_relation_target", member_sha256=node.source_document_sha256)
        dependencies[identity] = targets
        for target in targets:
            dependants[target].add(identity)
    def priority(identity: str) -> tuple[dt.datetime, str]:
        # A random content-ID sort would turn historical current-state views
        # into a different order on import, since the core uses ingest_seq.
        captured = dt.datetime.fromisoformat(nodes[identity].created_at.replace("Z", "+00:00"))
        return captured, identity

    ready = [priority(identity) for identity, targets in dependencies.items() if not targets]
    heapq.heapify(ready)
    mapped: dict[str, dict[str, Any]] = {}
    report_rows: list[dict[str, Any]] = []
    while ready:
        _, identity = heapq.heappop(ready)
        node = nodes[identity]
        relations = [{"type": relation, "target": mapped[target]["memory_id"]} for relation, target in node.relations]
        try:
            record = validate_record(build_record(
                kind=node.kind, text=node.text, created_at=node.created_at,
                relations=relations,
                provenance={"source_type": "imported", "confidence": "imported", "source_ref": node.source_ref},
            ))
        except VaultError as exc:
            raise MigrationError("current_record_" + exc.code, member_sha256=node.source_document_sha256) from None
        mapped[identity] = record
        row: dict[str, Any] = {
            "legacy_schema": node.schema,
            "legacy_identity_sha256": sha256((node.schema + "\0" + identity).encode("utf-8")),
            "source_document_sha256": node.source_document_sha256,
            "memory_id": record["memory_id"],
            "output_ordinal": len(mapped) - 1,
            "current_kind": node.kind,
            "uncarried_metadata_fields": list(node.uncarried_fields),
        }
        if node.relation_projection:
            row["relation_projection"] = node.relation_projection
        report_rows.append(row)
        for child in sorted(dependants[identity]):
            dependencies[child].remove(identity)
            if not dependencies[child]:
                heapq.heappush(ready, priority(child))
    if len(mapped) != len(nodes):
        raise MigrationError("cyclic_legacy_relations")
    records = list(mapped.values())
    if len({record["memory_id"] for record in records}) != len(records):
        raise MigrationError("ambiguous_migrated_identity")
    if len(records) > MAX_BUNDLE_RECORDS:
        raise MigrationError("current_bundle_too_large")
    report_rows.sort(key=lambda row: row["legacy_identity_sha256"])
    return records, report_rows


def _bundle_lines(records: list[dict[str, Any]], created_at: str) -> Iterator[bytes]:
    header = {"type": "header", "schema_version": BUNDLE_SCHEMA, "created_at": created_at, "hash_profile": HASH_PROFILE}
    yield canonical_bytes(header) + b"\n"
    digest = hashlib.sha256()
    for record in records:
        line = canonical_bytes({"type": "record", "record": record}) + b"\n"
        if len(line) > MAX_BUNDLE_LINE_BYTES:
            raise MigrationError("current_bundle_line_too_large")
        digest.update(record["record_sha256"].encode("ascii") + b"\n")
        yield line
    yield canonical_bytes({"type": "footer", "record_count": len(records), "records_sha256": digest.hexdigest()}) + b"\n"


def _stage(path: Path, chunks: Iterator[bytes]) -> Path:
    _check_parent_chain(path, create=True, private=True)
    if os.name == "nt":
        temporary = path.parent / (".memory-migration-" + uuid.uuid4().hex)
        fd = protected_storage.open_file(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, private=True)
    else:
        fd, name = tempfile.mkstemp(prefix=".memory-migration-", dir=path.parent)
        temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            if os.name != "nt":
                os.fchmod(stream.fileno(), 0o600)
            for chunk in chunks:
                stream.write(chunk)
            stream.flush()
            os.fsync(stream.fileno())
        return temporary
    except BaseException:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise


def _publish_pair(output: Path, report: Path, bundle: list[bytes], report_bytes: bytes) -> None:
    # Complete both private temporary files first, then publish without replacement.
    # These two paths cannot form a cross-directory atomic transaction. Publish
    # the report first so a complete output always has its mapping report.
    staged: list[Path] = []
    published: list[tuple[Path, int, int]] = []
    try:
        staged.append(_stage(output, iter(bundle)))
        staged.append(_stage(report, iter((report_bytes,))))
        for temporary, destination in ((staged[1], report), (staged[0], output)):
            info = temporary.lstat()
            try:
                if os.name == "nt":
                    # Native same-volume publication checks the actual source
                    # handle, inherited ACLs and the resulting file identity.
                    protected_storage.publish_file(temporary, destination, replace=False)
                else:
                    # Retain the existing owned/non-writable parent contract;
                    # publication must not newly require every output dir 0700.
                    _check_parent_chain(destination, create=False, private=True)
                    if os.path.lexists(destination):
                        raise MigrationError("output_exists")
                    protected_storage.publish_file(temporary, destination, replace=False,
                                                   private_parent=False)
            except FileExistsError:
                raise MigrationError("output_exists") from None
            finally:
                # A rename may have succeeded before directory fsync or the
                # post-publication check failed. Track that effect even when
                # publish_file raises, but never claim a competing destination.
                if not os.path.lexists(temporary):
                    try:
                        moved = destination.lstat()
                    except OSError:
                        pass
                    else:
                        if (stat.S_ISREG(moved.st_mode) and moved.st_nlink == 1
                                and (moved.st_dev, moved.st_ino) == (info.st_dev, info.st_ino)):
                            published.append((destination, info.st_dev, info.st_ino))
    except BaseException:
        for destination, device, inode in reversed(published):
            try:
                info = destination.lstat()
                if (stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                        and (info.st_dev, info.st_ino) == (device, inode)):
                    # Recheck the current protected file on every platform;
                    # never clean up a replacement, reparse point or alias.
                    descriptor = protected_storage.open_file(destination, os.O_RDONLY, private=True)
                    try:
                        current = os.fstat(descriptor)
                        if (current.st_dev, current.st_ino) != (device, inode):
                            continue
                    finally:
                        os.close(descriptor)
                    destination.unlink()
            except OSError:
                pass
        raise
    finally:
        for temporary in staged:
            try:
                temporary.unlink()
            except OSError:
                pass


def convert(source: Path, output: Path, report: Path, *, dry_run: bool = False) -> dict[str, Any]:
    """Validate first; dry-run produces only a content-free stdout/API summary."""
    source, output, report = (_absolute(path) for path in (source, output, report))
    if len({source, output, report}) != 3:
        raise MigrationError("paths_must_be_distinct")
    _new_output(output)
    _new_output(report)
    manifest, nodes, source_hash = _read_archive(source)
    records, mappings = _convert_nodes(nodes)
    bundle = list(_bundle_lines(records, _timestamp(manifest["exported_at"])))
    bundle_size = sum(len(line) for line in bundle)
    if bundle_size > MAX_BUNDLE_BYTES:
        raise MigrationError("current_bundle_too_large")
    bundle_hash = hashlib.sha256()
    for line in bundle:
        bundle_hash.update(line)
    summary: dict[str, Any] = {
        "schema_version": MIGRATION_SCHEMA,
        "state": "validated_only" if dry_run else "converted",
        "source_archive_sha256": source_hash,
        "legacy_network_sha256": manifest["network_sha256"],
        "records": len(records), "source_documents": len(nodes),
        "source_schemas": dict(sorted(Counter(node.schema for node in nodes.values()).items())),
        "bundle_schema": BUNDLE_SCHEMA, "bundle_bytes": bundle_size,
        "bundle_sha256": bundle_hash.hexdigest(),
        "legacy_checksums_verified": True, "original_author_authenticated": False,
        "signed_records": 0, "import_admission_default": "quarantined",
        "source_modified": False, "database_opened": False, "network_accessed": False,
        "written": not dry_run, "mapping_entries": len(mappings),
        "uncarried_metadata_fields": sorted({field for node in nodes.values() for field in node.uncarried_fields}),
        "visible_text_preserved": True,
        "output_order": "dependency_first_then_recorded_time",
        "privacy_note": "Structured source identities are hashed; visible text is not a privacy scrubber.",
    }
    report_bytes = canonical_bytes({**summary, "identity_mappings": mappings}) + b"\n"
    if len(report_bytes) > MAX_REPORT_BYTES:
        raise MigrationError("migration_report_too_large")
    if not dry_run:
        _publish_pair(output, report, bundle, report_bytes)
    return summary


class _Parser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise MigrationError("invalid_arguments")


def main(argv: list[str] | None = None) -> int:
    result: dict[str, Any]
    exit_code = 0
    try:
        arguments = list(sys.argv[1:] if argv is None else argv)
        if arguments in (["-h"], ["--help"]):
            result = {"ok": True, "schema_version": MIGRATION_SCHEMA, "arguments": ["--source ABSOLUTE_ZIP", "--output ABSOLUTE_NDJSON", "--report ABSOLUTE_JSON", "--dry-run (optional; writes nothing)"]}
        else:
            parser = _Parser(add_help=False)
            parser.add_argument("--source", type=Path, required=True)
            parser.add_argument("--output", type=Path, required=True)
            parser.add_argument("--report", type=Path, required=True)
            parser.add_argument("--dry-run", action="store_true")
            args = parser.parse_args(arguments)
            result = {"ok": True, **convert(args.source, args.output, args.report, dry_run=args.dry_run)}
    except MigrationError as exc:
        error: dict[str, Any] = {"code": exc.code}
        if exc.member_sha256 is not None:
            error["member_sha256"] = exc.member_sha256
        result = {"ok": False, "schema_version": MIGRATION_SCHEMA, "error": error}
        exit_code = 2
    except (OSError, zipfile.BadZipFile, RuntimeError, ValueError, VaultError):
        result = {"ok": False, "schema_version": MIGRATION_SCHEMA, "error": {"code": "conversion_failed"}}
        exit_code = 2
    except KeyboardInterrupt:
        result = {"ok": False, "schema_version": MIGRATION_SCHEMA, "error": {"code": "interrupted"}}
        exit_code = 130
    except Exception:
        result = {"ok": False, "schema_version": MIGRATION_SCHEMA, "error": {"code": "conversion_failed"}}
        exit_code = 2
    try:
        sys.stdout.write(json.dumps(result, ensure_ascii=False, sort_keys=True, allow_nan=False) + "\n")
        sys.stdout.flush()
    except OSError:
        return 2
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
