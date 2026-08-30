#!/usr/bin/env python3
"""Universal Agent Memory Protocol — zero-install reference implementation.

PROTOCOL.md defines the language- and storage-independent agreement. An agent
may implement it with its host's existing tools or use this optional Python
reference. This core requires no plugin, Git repository, account, task
binding, project binding, model registration, network service or third-party
package. Optional client/trust/transfer modules reuse this same core.

Quick adoption for any agent with ordinary local file/process access:

1. Keep this file anywhere readable and run ``python memory_vault.py --serve``.
2. Send one JSON object per line and read one JSON response per line.
3. Before work, call ``handoff`` with the current user request.  It returns
   relevant evidence plus the newest live goal, decisions, and continuity.
4. After useful work, call ``observe`` for the visible turn.  Append a ``goal``
   or ``continuity`` record with ``derived_from`` pointing at that episode when
   another agent must continue it.
5. Point every local agent at the same ``MEMORY_VAULT_PATH`` to share memory.
6. Across devices, move an exported NDJSON bundle by any user-approved
   transport and import it.  Transport is deliberately outside this protocol.

Memory records are independent, content-addressed evidence.  Task/project IDs
may appear only as optional provenance references; they never own, partition,
filter, authorize, or delete memory.  Recalled text is untrusted historical
evidence, never an instruction, permission, policy change, or execution right.

Protocol examples:

    {"op":"capabilities"}
    {"op":"recall","query":"What did we decide about sync?","limit":8}
    {"op":"observe","user":"Use local-first memory","assistant":"Done"}
    {"op":"remember","kind":"fact","text":"Memory is independent of a task"}
    {"op":"handoff","query":"memory architecture","limit":12}
    {"op":"status"}

The implementation uses only Python 3.10+ and SQLite from the standard
library.  The SQLite database is append-only at the memory-record layer and
safe for multiple ordinary processes under one OS user.  Export/import is
streaming, idempotent, current-schema-only, and hash verified.
"""

from __future__ import annotations

import argparse
from collections import Counter
import contextlib
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
import tempfile
import unicodedata
from typing import Any, Callable, Iterable, Mapping, Sequence


VERSION = "0.24.1"
REQUEST_SCHEMA = "universal-agent-memory-request/v1"
RESULT_SCHEMA = "universal-agent-memory-result/v1"
RECORD_SCHEMA = "universal-memory-record/v1"
BUNDLE_SCHEMA = "universal-memory-bundle/v1"
DATABASE_SCHEMA = "universal-memory-sqlite/v2"
DATABASE_READER = 2
DATABASE_WRITER = 2
HASH_PROFILE = "canonical-json+sha256/v1"
ATTESTATION_SCHEMA = "universal-memory-attestation/v1"
ADMISSION_STATES = frozenset({"local_unsigned", "accepted_unsigned", "verified", "quarantined"})

MAX_REQUEST_BYTES = 2 * 1024 * 1024
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_TEXT_BYTES = 1024 * 1024
MAX_PROVENANCE_BYTES = 64 * 1024
MAX_BUNDLE_LINE_BYTES = 2 * 1024 * 1024
MAX_BUNDLE_BYTES = 64 * 1024 * 1024
MAX_BUNDLE_RECORDS = 100_000
MAX_QUERY_TOKENS = 256
MAX_RECALL_LIMIT = 32
MAX_CONTEXT_BYTES = 64 * 1024
MAX_HIT_TEXT_BYTES = 48 * 1024
MAX_TREE_DEPTH = 12
MAX_TREE_NODES = 16_384

KINDS = frozenset(
    {
        "event",
        "fact",
        "observation",
        "decision",
        "artifact",
        "entity",
        "relation",
        "provenance",
        "summary",
        "goal",
        "continuity",
        "episode",
    }
)
RELATIONS = frozenset(
    {
        "related_to",
        "derived_from",
        "supports",
        "supersedes",
        "conflicts_with",
        "resolves",
        "continues",
    }
)
AUTHORITY = {
    "memory": "untrusted_historical_evidence",
    "instruction_eligible": False,
    "authorization_eligible": False,
    "execution_eligible": False,
    "policy_change_eligible": False,
    "current_user_input_precedence": True,
}

_MEMORY_ID = re.compile(r"mem_[0-9a-f]{40}")
_REQUEST_ID = re.compile(r"req_[A-Za-z0-9_-]{8,96}")
_JSON_KEY = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{0,127}")
_UTC_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z"
)
_LATIN = re.compile(r"[a-z0-9][a-z0-9_+.-]{0,63}")
_SPACE = re.compile(r"\s+")
_STOPWORDS = {
    "about",
    "after",
    "also",
    "and",
    "are",
    "but",
    "can",
    "for",
    "from",
    "have",
    "into",
    "not",
    "that",
    "the",
    "their",
    "then",
    "this",
    "was",
    "were",
    "will",
    "with",
    "you",
    "your",
}
_PROVENANCE_REFERENCE_KEYS = {
    "source_ref",
    "task_ref",
    "project_ref",
    "conversation_ref",
    "model_ref",
    "agent_ref",
    "device_ref",
    "request_ref",
}
_PROVENANCE_SOURCE_TYPES = {"visible_turn", "agent_supplied", "imported"}
_PROVENANCE_CONFIDENCE = {"observed", "assistant_inferred", "imported"}


class MemoryError(Exception):
    """Expected, content-free protocol failure."""

    def __init__(self, code: str, *, retryable: bool = False):
        super().__init__(code)
        self.code = code
        self.retryable = bool(retryable)


def _sqlite_memory_error(exc: sqlite3.Error) -> MemoryError:
    message = str(exc).casefold()
    code = getattr(exc, "sqlite_errorcode", None)
    busy_codes = {
        getattr(sqlite3, "SQLITE_BUSY", -1),
        getattr(sqlite3, "SQLITE_LOCKED", -2),
    }
    if code in busy_codes or "busy" in message or "locked" in message:
        return MemoryError("busy", retryable=True)
    return MemoryError("storage_unavailable")


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _utf8_length(value: str) -> int:
    try:
        return len(value.encode("utf-8"))
    except UnicodeError:
        raise MemoryError("invalid_text") from None


def canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        raise MemoryError("invalid_json_value") from None


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def strict_json_loads(value: bytes | str) -> Any:
    if isinstance(value, bytes):
        if value.startswith(b"\xef\xbb\xbf"):
            raise MemoryError("json_bom_forbidden")
        try:
            text = value.decode("utf-8")
        except UnicodeDecodeError:
            raise MemoryError("invalid_json") from None
    elif isinstance(value, str):
        text = value
    else:
        raise MemoryError("invalid_json")

    def reject_constant(_token: str) -> None:
        raise MemoryError("non_finite_json_number")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, child in pairs:
            if key in result:
                raise MemoryError("duplicate_json_key")
            result[key] = child
        return result

    try:
        return json.loads(
            text,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (ValueError, RecursionError):
        raise MemoryError("invalid_json") from None


def _validate_tree(value: Any) -> None:
    nodes = 0

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_TREE_NODES or depth > MAX_TREE_DEPTH:
            raise MemoryError("structure_too_large")
        if item is None or isinstance(item, bool):
            return
        if isinstance(item, int):
            if not -(2**63) <= item <= 2**63 - 1:
                raise MemoryError("integer_out_of_range")
            return
        if isinstance(item, float):
            raise MemoryError("floating_point_forbidden")
        if isinstance(item, str):
            if "\x00" in item or _utf8_length(item) > MAX_TEXT_BYTES:
                raise MemoryError("invalid_text")
            return
        if isinstance(item, list):
            for child in item:
                visit(child, depth + 1)
            return
        if isinstance(item, Mapping):
            for key, child in item.items():
                if not isinstance(key, str) or _JSON_KEY.fullmatch(key) is None:
                    raise MemoryError("invalid_key")
                visit(child, depth + 1)
            return
        raise MemoryError("unsupported_value")

    visit(value, 0)


def _exact_object(
    value: Any,
    *,
    required: set[str],
    optional: set[str] = frozenset(),
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise MemoryError("invalid_object")
    observed = set(value)
    if not required.issubset(observed) or not observed.issubset(required | optional):
        raise MemoryError("invalid_shape")
    return value


def _visible_text(value: Any, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise MemoryError("invalid_text")
    if _utf8_length(value) > MAX_TEXT_BYTES:
        raise MemoryError("text_too_large")
    return value


def _entities(value: Any) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > 256:
        raise MemoryError("invalid_entities")
    for item in value:
        if (
            not isinstance(item, str)
            or not item.strip()
            or "\x00" in item
            or _utf8_length(item) > 512
        ):
            raise MemoryError("invalid_entities")
    return list(dict.fromkeys(value))


def _relations(value: Any) -> list[dict[str, str]]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > 256:
        raise MemoryError("invalid_relations")
    result: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for item in value:
        raw = _exact_object(item, required={"type", "target"})
        relation = raw.get("type")
        target = raw.get("target")
        if not isinstance(relation, str) or relation not in RELATIONS or not isinstance(target, str) or _MEMORY_ID.fullmatch(target) is None:
            raise MemoryError("invalid_relation")
        pair = (str(relation), target)
        if pair not in seen:
            seen.add(pair)
            result.append({"type": str(relation), "target": target})
    return result


def _provenance(value: Any, *, caller_supplied: bool = False) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise MemoryError("invalid_provenance")
    allowed = set(_PROVENANCE_REFERENCE_KEYS)
    if not caller_supplied:
        allowed.update({"source_type", "confidence"})
    if not set(value).issubset(allowed):
        raise MemoryError("forbidden_provenance_field")
    result: dict[str, str] = {}
    for key, item in value.items():
        if (
            not isinstance(key, str)
            or not isinstance(item, str)
            or not item.strip()
            or "\x00" in item
            or _utf8_length(item) > 2048
        ):
            raise MemoryError("invalid_provenance")
        result[key] = item
    source_type = result.get("source_type")
    confidence = result.get("confidence")
    if source_type is not None and source_type not in _PROVENANCE_SOURCE_TYPES:
        raise MemoryError("invalid_provenance")
    if confidence is not None and confidence not in _PROVENANCE_CONFIDENCE:
        raise MemoryError("invalid_provenance")
    if len(canonical_bytes(result)) > MAX_PROVENANCE_BYTES:
        raise MemoryError("provenance_too_large")
    return result


def _request_provenance(
    value: Any, *, source_type: str, confidence: str
) -> dict[str, str]:
    result = _provenance(value, caller_supplied=True)
    result["source_type"] = source_type
    result["confidence"] = confidence
    return result


def build_record(
    *,
    kind: str,
    text: str,
    entities: Sequence[str] = (),
    relations: Sequence[Mapping[str, str]] = (),
    provenance: Mapping[str, Any] | None = None,
    created_at: str | None = None,
) -> dict[str, Any]:
    if not isinstance(kind, str) or kind not in KINDS:
        raise MemoryError("invalid_kind")
    body: dict[str, Any] = {
        "schema_version": RECORD_SCHEMA,
        "kind": kind,
        "text": str(_visible_text(text)),
        "entities": _entities(list(entities)),
        "relations": _relations([dict(item) for item in relations]),
        "provenance": _provenance(provenance or {}),
        "created_at": created_at or utc_now(),
        "hash_profile": HASH_PROFILE,
    }
    digest = sha256(canonical_bytes(body))
    record = dict(body)
    record["memory_id"] = "mem_" + digest[:40]
    record["record_sha256"] = digest
    if len(canonical_bytes(record)) > MAX_BUNDLE_LINE_BYTES:
        raise MemoryError("record_too_large")
    return record


def _timestamp(value: Any) -> str:
    if not isinstance(value, str) or _UTC_TIMESTAMP.fullmatch(value) is None:
        raise MemoryError("invalid_timestamp")
    try:
        dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise MemoryError("invalid_timestamp") from None
    return value


def validate_record(value: Any) -> dict[str, Any]:
    raw = _exact_object(
        value,
        required={
            "schema_version",
            "kind",
            "text",
            "entities",
            "relations",
            "provenance",
            "created_at",
            "hash_profile",
            "memory_id",
            "record_sha256",
        },
    )
    if raw.get("schema_version") != RECORD_SCHEMA or raw.get("hash_profile") != HASH_PROFILE:
        raise MemoryError("unsupported_record_schema")
    if not isinstance(raw.get("kind"), str) or raw.get("kind") not in KINDS:
        raise MemoryError("invalid_kind")
    text = _visible_text(raw.get("text"))
    entities = _entities(raw.get("entities"))
    relations = _relations(raw.get("relations"))
    provenance = _provenance(raw.get("provenance"))
    created_at = _timestamp(raw.get("created_at"))
    memory_id = raw.get("memory_id")
    digest = raw.get("record_sha256")
    if not isinstance(memory_id, str) or _MEMORY_ID.fullmatch(memory_id) is None:
        raise MemoryError("invalid_memory_id")
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise MemoryError("invalid_record_hash")
    body = {
        "schema_version": RECORD_SCHEMA,
        "kind": str(raw["kind"]),
        "text": str(text),
        "entities": entities,
        "relations": relations,
        "provenance": provenance,
        "created_at": created_at,
        "hash_profile": HASH_PROFILE,
    }
    observed = sha256(canonical_bytes(body))
    if digest != observed or memory_id != "mem_" + observed[:40]:
        raise MemoryError("record_hash_mismatch")
    return {**body, "memory_id": memory_id, "record_sha256": digest}


def normalize_text(value: str) -> str:
    return _SPACE.sub(" ", unicodedata.normalize("NFKC", value).casefold()).strip()


def _bounded_text(value: str, maximum: int = MAX_HIT_TEXT_BYTES) -> tuple[str, bool]:
    encoded = value.encode("utf-8")
    if len(encoded) <= maximum:
        return value, False
    return encoded[:maximum].decode("utf-8", errors="ignore"), True


def _is_cjk(character: str) -> bool:
    codepoint = ord(character)
    return (
        0x3400 <= codepoint <= 0x4DBF
        or 0x4E00 <= codepoint <= 0x9FFF
        or 0xF900 <= codepoint <= 0xFAFF
        or 0x3040 <= codepoint <= 0x30FF
        or 0xAC00 <= codepoint <= 0xD7AF
    )


def tokenize(value: str, *, maximum: int = MAX_QUERY_TOKENS, maximum_input_bytes: int = 64 * 1024) -> list[str]:
    if not isinstance(value, str) or not value.strip():
        return []
    if len(value.encode("utf-8")) > maximum_input_bytes:
        raise MemoryError("query_too_large")
    normalized = normalize_text(value)
    result: list[str] = []
    for match in _LATIN.finditer(normalized):
        token = match.group(0)
        if token not in _STOPWORDS:
            result.append("w:" + token)
            if len(result) >= maximum:
                return result
    run: list[str] = []

    def flush() -> None:
        if not run:
            return
        joined = "".join(run)
        if len(joined) == 1:
            result.append("c:" + joined)
        else:
            result.extend("c:" + joined[index : index + 2] for index in range(len(joined) - 1))
            if len(joined) <= 8:
                result.append("p:" + joined)
        run.clear()

    for character in normalized:
        if _is_cjk(character):
            run.append(character)
        else:
            flush()
        if len(result) >= maximum:
            return result[:maximum]
    flush()
    return result[:maximum]


def default_vault_path() -> Path:
    configured = os.environ.get("MEMORY_VAULT_PATH")
    if configured:
        path = Path(configured).expanduser()
        if not path.is_absolute():
            raise MemoryError("vault_path_must_be_absolute")
        return path
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home()) / "UniversalAgentMemory"
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support" / "UniversalAgentMemory"
    else:
        xdg = os.environ.get("XDG_DATA_HOME")
        base = Path(xdg).expanduser() / "universal-agent-memory" if xdg else Path.home() / ".local" / "share" / "universal-agent-memory"
    return base / "vault-v1.sqlite3"


def _absolute_path(value: Path, *, error: str) -> Path:
    path = value.expanduser()
    if not path.is_absolute():
        raise MemoryError(error)
    if path.is_symlink():
        raise MemoryError("unsafe_path")
    return path.absolute()


def _ensure_private_directory(path: Path) -> None:
    if path.is_symlink():
        raise MemoryError("unsafe_vault_path")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink() or not path.is_dir():
        raise MemoryError("unsafe_vault_path")
    with contextlib.suppress(OSError):
        path.chmod(0o700)


def _plain_file(path: Path) -> bool:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return False
    return stat.S_ISREG(mode) and not path.is_symlink()


def _json_line(value: Mapping[str, Any]) -> bytes:
    return canonical_bytes(value) + b"\n"


def capability_result() -> dict[str, Any]:
    return {
        "protocol": REQUEST_SCHEMA,
        "version": VERSION,
        "operations": [
            "capabilities",
            "remember",
            "observe",
            "recall",
            "get",
            "handoff",
            "status",
            "changes",
        ],
        "database_schema": DATABASE_SCHEMA,
        "database_reader": DATABASE_READER,
        "database_writer": DATABASE_WRITER,
        "memory_model": "taskless_content_addressed_append_only",
        "shared_across_local_agents": True,
        "portable_bundle": BUNDLE_SCHEMA,
        "plugin_required": False,
        "git_required": False,
        "account_required": False,
        "network_required": False,
        "network_accessed": False,
        "unsigned_import_default": "quarantined",
        "optional_signing": "external_ed25519_provider",
        "signature_is_authorization": False,
    }


class Vault:
    """One append-only taskless Vault usable by unrelated AI processes."""

    def __init__(
        self,
        path: Path | None = None,
        *,
        signer: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None = None,
        observation_source: str = "caller_reported",
        trust_check: Callable[[str], Any] | None = None,
    ):
        selected = path or default_vault_path()
        self.path = _absolute_path(selected, error="vault_path_must_be_absolute")
        if observation_source not in {"caller_reported", "host_visible_turn"}:
            raise MemoryError("invalid_observation_source")
        self.signer = signer
        self.observation_source = observation_source
        self.trust_check = trust_check

    def _connect(self, *, writable: bool = True) -> sqlite3.Connection:
        if writable:
            _ensure_private_directory(self.path.parent)
        if self.path.is_symlink():
            raise MemoryError("unsafe_vault_path")
        if not writable and not _plain_file(self.path):
            raise MemoryError("not_initialized")
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(
                str(self.path) if writable else self.path.as_uri() + "?mode=ro",
                timeout=5.0, uri=not writable,
            )
            connection.row_factory = sqlite3.Row
            # Trust is injected by the local integration, never by recalled text
            # or request JSON. A read checks current trust without changing data.
            checked_keys: dict[str, bool] = {}

            def admitted(state: str, key_id: str | None) -> int:
                if state == "quarantined" or state not in ADMISSION_STATES:
                    return 0
                if state != "verified":
                    return 1
                if not key_id:
                    return 0
                if self.trust_check is None:
                    return 2  # Verified at admission, not a fresh trust assertion.
                if key_id not in checked_keys:
                    try:
                        self.trust_check(key_id)
                        checked_keys[key_id] = True
                    except Exception:
                        checked_keys[key_id] = False
                return 2 if checked_keys[key_id] else 0

            connection.create_function("vault_admitted", 2, admitted)
            connection.execute("PRAGMA busy_timeout=5000")
            connection.execute("PRAGMA foreign_keys=ON")
            with contextlib.suppress(sqlite3.Error):
                connection.execute("PRAGMA trusted_schema=OFF")
            self._initialize(connection, allow_upgrade=writable)
            journal = str(connection.execute("PRAGMA journal_mode").fetchone()[0])
            if writable and journal.casefold() != "wal":
                selected_journal = str(
                    connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]
                )
                if selected_journal.casefold() != "wal":
                    raise MemoryError("wal_unavailable")
            connection.execute("PRAGMA synchronous=FULL")
            if writable:
                with contextlib.suppress(OSError):
                    self.path.chmod(0o600)
            return connection
        except sqlite3.Error as exc:
            if connection is not None:
                connection.close()
            raise _sqlite_memory_error(exc) from exc
        except Exception:
            if connection is not None:
                connection.close()
            raise

    @staticmethod
    def _initialize(connection: sqlite3.Connection, *, allow_upgrade: bool = True) -> None:
        metadata_exists = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='metadata'"
        ).fetchone()
        if metadata_exists is not None:
            metadata = {
                str(row["key"]): str(row["value"])
                for row in connection.execute(
                    "SELECT key,value FROM metadata WHERE key IN ('schema','min_reader','min_writer')"
                )
            }
            current_metadata = {
                "schema": DATABASE_SCHEMA,
                "min_reader": str(DATABASE_READER),
                "min_writer": str(DATABASE_WRITER),
            }
            prior_metadata = {
                "schema": "universal-memory-sqlite/v1",
                "min_reader": "1",
                "min_writer": "1",
            }
            if metadata not in (current_metadata, prior_metadata):
                raise MemoryError("unsupported_database_schema")
            required_objects = {
                "memories",
                "terms",
                "relations",
                "receipts",
                "memories_no_update",
                "memories_no_delete",
            }
            observed_objects = {
                str(row["name"])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE name IN ("
                    + ",".join("?" for _ in required_objects)
                    + ")",
                    tuple(required_objects),
                )
            }
            if observed_objects != required_objects:
                raise MemoryError("unsupported_database_schema")
            if metadata == prior_metadata:
                if not allow_upgrade:
                    raise MemoryError("database_upgrade_required")
                # Additive upgrade: never rewrite canonical records or receipts.
                # V1 did not retain import admission, so its existing records
                # remain explicitly unsigned; historical authors are unknown.
                connection.execute("BEGIN IMMEDIATE")
                Vault._initialize_admissions(connection)
                connection.executemany(
                    "UPDATE metadata SET value=? WHERE key=?",
                    ((value, key) for key, value in current_metadata.items()),
                )
                connection.execute(f"PRAGMA user_version={DATABASE_WRITER}")
                connection.commit()
            auxiliary = {"record_admissions", "delivery_log", "transfer_receipts"}
            observed_auxiliary = {
                str(row[0]) for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name IN ("
                    + ",".join("?" for _ in auxiliary) + ")", tuple(auxiliary)
                )
            }
            if observed_auxiliary != auxiliary:
                raise MemoryError("unsupported_database_schema")
            store = connection.execute("SELECT value FROM metadata WHERE key='store_id'").fetchone()
            if store is None or re.fullmatch(r"store_[0-9a-f]{32}", str(store[0])) is None:
                raise MemoryError("unsupported_database_schema")
            return
        if not allow_upgrade:
            raise MemoryError("not_initialized")
        connection.executescript(
            """
            BEGIN IMMEDIATE;
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS memories (
                ingest_seq INTEGER PRIMARY KEY AUTOINCREMENT,
                memory_id TEXT NOT NULL UNIQUE,
                record_sha256 TEXT NOT NULL UNIQUE,
                kind TEXT NOT NULL,
                text TEXT NOT NULL,
                normalized_text TEXT NOT NULL,
                created_at TEXT NOT NULL,
                record_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS terms (
                token TEXT NOT NULL,
                memory_id TEXT NOT NULL REFERENCES memories(memory_id),
                frequency INTEGER NOT NULL,
                PRIMARY KEY(token, memory_id)
            );
            CREATE INDEX IF NOT EXISTS terms_memory ON terms(memory_id);
            CREATE TABLE IF NOT EXISTS relations (
                source_id TEXT NOT NULL REFERENCES memories(memory_id),
                relation TEXT NOT NULL,
                target_id TEXT NOT NULL REFERENCES memories(memory_id)
                    DEFERRABLE INITIALLY DEFERRED,
                PRIMARY KEY(source_id, relation, target_id)
            );
            CREATE INDEX IF NOT EXISTS relations_target ON relations(target_id, relation);
            CREATE TABLE IF NOT EXISTS receipts (
                request_id TEXT PRIMARY KEY,
                request_sha256 TEXT NOT NULL,
                response_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TRIGGER IF NOT EXISTS memories_no_update
            BEFORE UPDATE ON memories BEGIN SELECT RAISE(ABORT, 'append-only memories'); END;
            CREATE TRIGGER IF NOT EXISTS memories_no_delete
            BEFORE DELETE ON memories BEGIN SELECT RAISE(ABORT, 'append-only memories'); END;
            """
        )
        connection.executemany(
            "INSERT OR IGNORE INTO metadata(key,value) VALUES(?,?)",
            (
                ("schema", DATABASE_SCHEMA),
                ("min_reader", str(DATABASE_READER)),
                ("min_writer", str(DATABASE_WRITER)),
            ),
        )
        connection.execute(f"PRAGMA user_version={DATABASE_WRITER}")
        Vault._initialize_admissions(connection)
        connection.commit()
        metadata = {
            str(row["key"]): str(row["value"])
            for row in connection.execute(
                "SELECT key,value FROM metadata WHERE key IN ('schema','min_reader','min_writer')"
            )
        }
        if metadata != {
            "schema": DATABASE_SCHEMA,
            "min_reader": str(DATABASE_READER),
            "min_writer": str(DATABASE_WRITER),
        }:
            raise MemoryError("unsupported_database_schema")

    @staticmethod
    def _initialize_admissions(connection: sqlite3.Connection) -> None:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS record_admissions ("
            "memory_id TEXT PRIMARY KEY REFERENCES memories(memory_id), "
            "state TEXT NOT NULL CHECK(state IN ('local_unsigned','accepted_unsigned','verified','quarantined')), "
            "signer_key_id TEXT, attestation_json TEXT)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS delivery_log ("
            "sequence INTEGER PRIMARY KEY AUTOINCREMENT, "
            "memory_id TEXT NOT NULL REFERENCES memories(memory_id))"
        )
        connection.execute("CREATE INDEX IF NOT EXISTS delivery_memory ON delivery_log(memory_id)")
        connection.execute(
            "CREATE TABLE IF NOT EXISTS transfer_receipts ("
            "transfer_id TEXT PRIMARY KEY, payload_sha256 TEXT NOT NULL, "
            "result_json TEXT NOT NULL, created_at TEXT NOT NULL)"
        )
        connection.execute(
            "INSERT OR IGNORE INTO metadata(key,value) VALUES('store_id',?)",
            ("store_" + os.urandom(16).hex(),),
        )
        connection.execute(
            "INSERT INTO delivery_log(memory_id) "
            "SELECT memory_id FROM memories WHERE memory_id NOT IN "
            "(SELECT memory_id FROM record_admissions) ORDER BY ingest_seq"
        )
        connection.execute(
            "INSERT OR IGNORE INTO record_admissions(memory_id,state) "
            "SELECT memory_id,'accepted_unsigned' FROM memories"
        )

    @staticmethod
    def _set_admission(
        connection: sqlite3.Connection,
        record: Mapping[str, Any],
        state: str,
        attestation: Mapping[str, Any] | None = None,
    ) -> bool:
        if state not in ADMISSION_STATES:
            raise MemoryError("invalid_admission")
        key_id = None
        encoded = None
        if state == "verified":
            # This checks the wire shape only. The optional integration MUST
            # cryptographically verify before calling ingest_records(verified).
            proof = _exact_object(attestation, required={
                "schema_version", "key_id", "record_sha256", "signature"
            })
            if (
                proof["schema_version"] != ATTESTATION_SCHEMA
                or proof["record_sha256"] != record["record_sha256"]
                or not isinstance(proof["key_id"], str)
                or re.fullmatch(r"ed25519_[0-9a-f]{64}", proof["key_id"]) is None
                or not isinstance(proof["signature"], str)
                or len(proof["signature"]) > 256
            ):
                raise MemoryError("invalid_attestation")
            key_id = proof["key_id"]
            encoded = canonical_bytes(proof).decode("utf-8")
        elif attestation is not None:
            raise MemoryError("unexpected_attestation")
        memory_id = str(record["memory_id"])
        old = connection.execute(
            "SELECT *,vault_admitted(state,signer_key_id) AS active_rank "
            "FROM record_admissions WHERE memory_id=?", (memory_id,)
        ).fetchone()
        if old is not None:
            # A duplicate unsigned import must never demote an admitted record;
            # a freshly verified copy may admit a quarantined or revoked record.
            rank = 2 if state == "verified" else 0 if state == "quarantined" else 1
            if int(old["active_rank"]) >= rank:
                return False
            connection.execute(
                "UPDATE record_admissions SET state=?,signer_key_id=?,attestation_json=? WHERE memory_id=?",
                (state, key_id, encoded, memory_id),
            )
        else:
            connection.execute(
                "INSERT INTO record_admissions(memory_id,state,signer_key_id,attestation_json) VALUES(?,?,?,?)",
                (memory_id, state, key_id, encoded),
            )
        connection.execute("INSERT INTO delivery_log(memory_id) VALUES(?)", (memory_id,))
        return old is not None

    @staticmethod
    def _requeue_dependents(connection: sqlite3.Connection, identifiers: Iterable[str]) -> None:
        """Re-admission can unblock a previously deferred relation closure.

        Gather seeds once per transaction, not once per imported record, to
        avoid quadratic work when a whole unsigned bundle is admitted.
        """
        values = set(identifiers)
        if not values:
            return
        connection.execute("CREATE TEMP TABLE IF NOT EXISTS requeue_seeds(memory_id TEXT PRIMARY KEY)")
        connection.execute("DELETE FROM requeue_seeds")
        connection.executemany("INSERT INTO requeue_seeds(memory_id) VALUES(?)", ((value,) for value in values))
        connection.execute(
            "WITH RECURSIVE dependents(memory_id) AS ("
            "SELECT r.source_id FROM relations r JOIN requeue_seeds s ON s.memory_id=r.target_id "
            "UNION SELECT r.source_id FROM relations r JOIN dependents d ON d.memory_id=r.target_id) "
            "INSERT INTO delivery_log(memory_id) SELECT d.memory_id FROM dependents d "
            "JOIN record_admissions a ON a.memory_id=d.memory_id "
            "WHERE vault_admitted(a.state,a.signer_key_id)>0 ORDER BY d.memory_id"
        )
        connection.execute("DELETE FROM requeue_seeds")

    def _verification(self, connection: sqlite3.Connection, memory_id: str) -> dict[str, Any]:
        row = connection.execute(
            "SELECT *,vault_admitted(state,signer_key_id) AS active_rank "
            "FROM record_admissions WHERE memory_id=?", (memory_id,)
        ).fetchone()
        if row is None:
            raise MemoryError("stored_admission_missing")
        return {
            "admission": str(row["state"]),
            "signer_key_id": row["signer_key_id"],
            "signature_verified_at_admission": row["state"] == "verified",
            "current_trust_checked": self.trust_check is not None and row["state"] == "verified",
            "eligible_for_context": int(row["active_rank"]) > 0,
            "claimed_provenance_is_authenticated": False,
            "grants_authority": False,
        }

    @staticmethod
    def _insert_record(
        connection: sqlite3.Connection,
        value: Mapping[str, Any],
        *,
        allow_pending_relations: bool = False,
    ) -> tuple[str, bool]:
        record = validate_record(value)
        memory_id = str(record["memory_id"])
        encoded = canonical_bytes(record).decode("utf-8")
        existing = connection.execute(
            "SELECT record_json FROM memories WHERE memory_id=?", (memory_id,)
        ).fetchone()
        if existing is not None:
            if str(existing[0]) != encoded:
                raise MemoryError("memory_identity_conflict")
            return memory_id, False
        if not allow_pending_relations:
            for relation in record["relations"]:
                target = connection.execute(
                    "SELECT 1 FROM memories WHERE memory_id=?", (relation["target"],)
                ).fetchone()
                if target is None:
                    raise MemoryError("dangling_relation")
        connection.execute(
            "INSERT INTO memories(memory_id,record_sha256,kind,text,normalized_text,created_at,record_json) VALUES(?,?,?,?,?,?,?)",
            (
                memory_id,
                record["record_sha256"],
                record["kind"],
                record["text"],
                normalize_text(str(record["text"])),
                record["created_at"],
                encoded,
            ),
        )
        indexed_text = " ".join(
            [str(record["text"]), *(str(entity) for entity in record["entities"])]
        )
        counts = Counter(tokenize(indexed_text, maximum=4096, maximum_input_bytes=MAX_BUNDLE_LINE_BYTES))
        connection.executemany(
            "INSERT INTO terms(token,memory_id,frequency) VALUES(?,?,?)",
            ((token, memory_id, frequency) for token, frequency in counts.items()),
        )
        connection.executemany(
            "INSERT INTO relations(source_id,relation,target_id) VALUES(?,?,?)",
            (
                (memory_id, relation["type"], relation["target"])
                for relation in record["relations"]
            ),
        )
        return memory_id, True

    def _remember(
        self,
        connection: sqlite3.Connection,
        *,
        kind: str,
        text: str,
        entities: Sequence[str],
        relations: Sequence[Mapping[str, str]],
        provenance: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        record = build_record(
            kind=kind,
            text=text,
            entities=entities,
            relations=relations,
            provenance=provenance,
        )
        attestation = self.signer(record) if self.signer is not None else None
        if self.signer is not None and not isinstance(attestation, Mapping):
            raise MemoryError("signer_did_not_attest")
        memory_id, inserted = self._insert_record(connection, record)
        admission_changed = self._set_admission(
            connection, record, "verified" if attestation is not None else "local_unsigned", attestation
        )
        if admission_changed:
            self._requeue_dependents(connection, [memory_id])
        return {
            "state": "stored" if inserted else "duplicate",
            "memory_id": memory_id,
            "kind": kind,
            "network_accessed": False,
            "verification": self._verification(connection, memory_id),
        }

    @staticmethod
    def _record_from_row(row: sqlite3.Row) -> dict[str, Any]:
        try:
            value = strict_json_loads(str(row["record_json"]))
        except MemoryError:
            raise MemoryError("stored_record_invalid") from None
        record = validate_record(value)
        if (
            record["memory_id"] != row["memory_id"]
            or record["kind"] != row["kind"]
            or record["text"] != row["text"]
            or record["created_at"] != row["created_at"]
        ):
            raise MemoryError("stored_record_invalid")
        return record

    @staticmethod
    def _memory_status(connection: sqlite3.Connection, memory_id: str) -> str:
        own = connection.execute(
            "SELECT vault_admitted(state,signer_key_id) FROM record_admissions WHERE memory_id=?",
            (memory_id,),
        ).fetchone()
        if own is None or int(own[0]) == 0:
            return "quarantined"
        rank = int(own[0])
        superseded = connection.execute(
            "SELECT 1 FROM relations r JOIN record_admissions a ON a.memory_id=r.source_id "
            "WHERE r.target_id=? AND r.relation='supersedes' "
            "AND vault_admitted(a.state,a.signer_key_id)>=? LIMIT 1",
            (memory_id, rank),
        ).fetchone()
        if superseded is not None:
            return "superseded"
        unresolved = connection.execute(
            "SELECT 1 FROM relations r JOIN record_admissions a ON a.memory_id=r.source_id "
            "JOIN record_admissions b ON b.memory_id=r.target_id "
            "WHERE (r.source_id=? OR r.target_id=?) AND r.relation='conflicts_with' "
            "AND vault_admitted(a.state,a.signer_key_id)>=? "
            "AND vault_admitted(b.state,b.signer_key_id)>0 LIMIT 1",
            (memory_id, memory_id, rank),
        ).fetchone()
        if unresolved is not None:
            resolved = connection.execute(
                "SELECT 1 FROM relations r JOIN record_admissions a ON a.memory_id=r.source_id "
                "WHERE r.target_id=? AND r.relation='resolves' "
                "AND vault_admitted(a.state,a.signer_key_id)>=? LIMIT 1",
                (memory_id, rank),
            ).fetchone()
            return "resolved" if resolved is not None else "conflicted"
        return "current"

    def _recall_rows(
        self,
        connection: sqlite3.Connection,
        *,
        query: str,
        limit: int,
    ) -> list[dict[str, Any]]:
        tokens = list(dict.fromkeys(tokenize(query)))
        rows: list[sqlite3.Row]
        if tokens:
            placeholders = ",".join("?" for _ in tokens)
            rows = list(
                connection.execute(
                    "SELECT m.*,COUNT(DISTINCT t.token) AS matched,SUM(t.frequency) AS frequency "
                    "FROM terms t JOIN memories m ON m.memory_id=t.memory_id "
                    "JOIN record_admissions a ON a.memory_id=m.memory_id "
                    f"WHERE t.token IN ({placeholders}) AND vault_admitted(a.state,a.signer_key_id)>0 "
                    "GROUP BY m.memory_id "
                    "ORDER BY matched DESC,frequency DESC,m.ingest_seq DESC LIMIT ?",
                    (*tokens, min(512, max(limit * 12, limit))),
                )
            )
        else:
            pattern = "%" + normalize_text(query).replace("%", "\\%").replace("_", "\\_") + "%"
            rows = list(
                connection.execute(
                    "SELECT m.*,1 AS matched,1 AS frequency FROM memories m "
                    "JOIN record_admissions a ON a.memory_id=m.memory_id "
                    "WHERE normalized_text LIKE ? ESCAPE '\\' "
                    "AND vault_admitted(a.state,a.signer_key_id)>0 ORDER BY ingest_seq DESC LIMIT ?",
                    (pattern, min(512, max(limit * 12, limit))),
                )
            )
        normalized_query = normalize_text(query)
        kind_weight = {
            "decision": 900,
            "goal": 875,
            "fact": 850,
            "continuity": 800,
            "summary": 700,
            "observation": 600,
            "episode": 400,
        }
        candidates: dict[str, dict[str, Any]] = {}
        for row in rows:
            record = self._record_from_row(row)
            matched = int(row["matched"])
            frequency = int(row["frequency"])
            coverage = (matched * 10_000) // max(1, len(tokens))
            phrase_bonus = 2500 if normalized_query in str(row["normalized_text"]) else 0
            score = coverage + min(frequency, 50) * 100 + phrase_bonus + kind_weight.get(
                str(record["kind"]), 500
            )
            candidates[str(record["memory_id"])] = {
                "record": record,
                "score_milli": score,
                "matched_tokens": matched,
                "ingest_seq": int(row["ingest_seq"]),
            }
        if candidates:
            identifiers = list(candidates)
            placeholders = ",".join("?" for _ in identifiers)
            related = list(
                connection.execute(
                    "SELECT source_id,target_id,relation FROM relations r "
                    "JOIN record_admissions a ON a.memory_id=r.source_id "
                    "JOIN record_admissions b ON b.memory_id=r.target_id "
                    f"WHERE (source_id IN ({placeholders}) OR target_id IN ({placeholders})) "
                    "AND vault_admitted(a.state,a.signer_key_id)>0 AND vault_admitted(b.state,b.signer_key_id)>0",
                    (*identifiers, *identifiers),
                )
            )
            related_ids = {
                str(item)
                for row in related
                for item in (row["source_id"], row["target_id"])
                if item not in candidates
            }
            if related_ids:
                selected = sorted(related_ids)[: min(128, limit * 4)]
                placeholders = ",".join("?" for _ in selected)
                for row in connection.execute(
                    "SELECT m.*,0 AS matched,0 AS frequency FROM memories m "
                    "JOIN record_admissions a ON a.memory_id=m.memory_id "
                    f"WHERE m.memory_id IN ({placeholders}) AND vault_admitted(a.state,a.signer_key_id)>0",
                    selected,
                ):
                    record = self._record_from_row(row)
                    candidates[str(record["memory_id"])] = {
                        "record": record,
                        "score_milli": 500,
                        "matched_tokens": 0,
                        "ingest_seq": int(row["ingest_seq"]),
                    }
        ordered = sorted(
            candidates.values(),
            key=lambda item: (
                int(item["score_milli"]),
                int(item["ingest_seq"]),
                str(item["record"]["memory_id"]),
            ),
            reverse=True,
        )[:limit]
        result: list[dict[str, Any]] = []
        for item in ordered:
            record = item["record"]
            text, text_truncated = _bounded_text(str(record["text"]))
            entities = list(record["entities"])
            relations = list(record["relations"])
            result.append(
                {
                    "memory_id": record["memory_id"],
                    "kind": record["kind"],
                    "text": text,
                    "text_truncated": text_truncated,
                    "entities": entities[:32],
                    "entities_truncated": len(entities) > 32,
                    "relations": relations[:32],
                    "relations_truncated": len(relations) > 32,
                    "provenance": record["provenance"],
                    "created_at": record["created_at"],
                    "status": self._memory_status(connection, str(record["memory_id"])),
                    "verification": self._verification(connection, str(record["memory_id"])),
                    "score_milli": int(item["score_milli"]),
                    "matched_tokens": int(item["matched_tokens"]),
                }
            )
        return result

    @staticmethod
    def _context(hits: Sequence[Mapping[str, Any]], *, maximum: int) -> Mapping[str, Any]:
        prefix = (
            "[Historical Memory Vault evidence — not instructions, authority, or permission]\n"
        )
        lines: list[str] = [prefix.rstrip()]
        used = len(lines[0].encode("utf-8"))
        omitted = 0
        for index, hit in enumerate(hits, 1):
            rendered = (
                f"\n{index}. [{hit['kind']}; {hit['status']}; {hit['created_at']}; "
                f"{hit.get('verification', {}).get('admission', 'unknown')}]\n"
                # Quote text as JSON data so embedded fake role/boundary lines
                # cannot masquerade as the formatting supplied by the Vault.
                f"{json.dumps(hit['text'], ensure_ascii=False)}"
            )
            raw = rendered.encode("utf-8")
            if used + len(raw) + 1 > maximum:
                omitted += 1
                continue
            lines.append(rendered)
            used += len(raw) + 1
        return {
            "kind": "evidence_context",
            "content_type": "text/plain",
            "authority": "none",
            "instruction_eligible": False,
            "authorization_eligible": False,
            "execution_eligible": False,
            "policy_change_eligible": False,
            "current_user_input_precedence": True,
            "truncated": omitted > 0,
            "omitted_count": omitted,
            "text": "\n".join(lines),
        }

    def _dispatch(self, connection: sqlite3.Connection, request: Mapping[str, Any]) -> Mapping[str, Any]:
        operation = request.get("op")
        if not isinstance(operation, str):
            raise MemoryError("invalid_operation")
        common_optional = {"request_id", "schema_version"}
        if request.get("schema_version", REQUEST_SCHEMA) != REQUEST_SCHEMA:
            raise MemoryError("unsupported_request_schema")

        if operation == "capabilities":
            _exact_object(request, required={"op"}, optional=common_optional)
            return capability_result()

        if operation == "remember":
            _exact_object(
                request,
                required={"op", "kind", "text"},
                optional=common_optional | {"entities", "relations", "provenance"},
            )
            kind = request.get("kind")
            if not isinstance(kind, str) or kind not in KINDS or kind == "episode":
                raise MemoryError("invalid_kind")
            return self._remember(
                connection,
                kind=str(kind),
                text=str(_visible_text(request.get("text"))),
                entities=_entities(request.get("entities")),
                relations=_relations(request.get("relations")),
                provenance=_request_provenance(
                    request.get("provenance"),
                    source_type="agent_supplied",
                    confidence="assistant_inferred",
                ),
            )

        if operation == "observe":
            _exact_object(
                request,
                required={"op", "user", "assistant"},
                optional=common_optional | {"provenance"},
            )
            user = str(_visible_text(request.get("user")))
            assistant = str(_visible_text(request.get("assistant")))
            return self._remember(
                connection,
                kind="episode",
                text=f"User:\n{user}\n\nAssistant:\n{assistant}",
                entities=[],
                relations=[],
                provenance=_request_provenance(
                    request.get("provenance"),
                    source_type="visible_turn" if self.observation_source == "host_visible_turn" else "agent_supplied",
                    confidence="observed" if self.observation_source == "host_visible_turn" else "assistant_inferred",
                ),
            )

        if operation in {"recall", "handoff"}:
            _exact_object(
                request,
                required={"op", "query"},
                optional=common_optional | {"limit", "maximum_context_bytes"},
            )
            query = str(_visible_text(request.get("query")))
            limit = request.get("limit", 8 if operation == "recall" else 12)
            maximum = request.get("maximum_context_bytes", 8192)
            if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_RECALL_LIMIT:
                raise MemoryError("invalid_limit")
            if not isinstance(maximum, int) or isinstance(maximum, bool) or not 512 <= maximum <= MAX_CONTEXT_BYTES:
                raise MemoryError("invalid_context_limit")
            hits = self._recall_rows(connection, query=query, limit=limit)
            if operation == "handoff":
                # Goal continuity is guaranteed a place even when semantic
                # recall already filled the requested limit. This remains a
                # dynamic view over records, never a Task container.
                structural: list[dict[str, Any]] = []
                seen_kinds: set[str] = set()
                for row in connection.execute(
                    "SELECT m.* FROM memories m "
                    "JOIN record_admissions a ON a.memory_id=m.memory_id "
                    "WHERE m.kind IN ('goal','continuity','decision','summary') "
                    "AND vault_admitted(a.state,a.signer_key_id)>0 "
                    "AND EXISTS ("
                    "SELECT 1 FROM relations r JOIN memories e ON e.memory_id=r.target_id "
                    "JOIN record_admissions ea ON ea.memory_id=e.memory_id "
                    "WHERE r.source_id=m.memory_id AND r.relation='derived_from' "
                    "AND e.kind='episode' AND vault_admitted(ea.state,ea.signer_key_id)>0) "
                    "ORDER BY vault_admitted(a.state,a.signer_key_id) DESC,m.ingest_seq DESC LIMIT ?",
                    (max(32, limit * 8),),
                ):
                    record = self._record_from_row(row)
                    memory_id = str(record["memory_id"])
                    kind = str(record["kind"])
                    status = self._memory_status(connection, memory_id)
                    if status != "current" or kind in seen_kinds:
                        continue
                    text, text_truncated = _bounded_text(str(record["text"]))
                    entities = list(record["entities"])
                    relations = list(record["relations"])
                    structural.append(
                        {
                            "memory_id": memory_id,
                            "kind": kind,
                            "text": text,
                            "text_truncated": text_truncated,
                            "entities": entities[:32],
                            "entities_truncated": len(entities) > 32,
                            "relations": relations[:32],
                            "relations_truncated": len(relations) > 32,
                            "provenance": record["provenance"],
                            "created_at": record["created_at"],
                            "status": status,
                            "verification": self._verification(connection, memory_id),
                            "score_milli": 0,
                            "matched_tokens": 0,
                        }
                    )
                    seen_kinds.add(kind)
                    if len(seen_kinds) == 4:
                        break
                structural.sort(
                    key=lambda hit: {
                        "goal": 0,
                        "continuity": 1,
                        "decision": 2,
                        "summary": 3,
                    }[str(hit["kind"])]
                )
                combined = structural + hits
                unique: list[dict[str, Any]] = []
                seen_ids: set[str] = set()
                for hit in combined:
                    memory_id = str(hit["memory_id"])
                    if memory_id not in seen_ids:
                        seen_ids.add(memory_id)
                        unique.append(hit)
                hits = unique
            return {
                "hits": hits[:limit],
                "evidence_context": self._context(hits[:limit], maximum=maximum),
                "network_accessed": False,
            }

        if operation == "get":
            _exact_object(
                request,
                required={"op", "memory_id"},
                optional=common_optional,
            )
            memory_id = request.get("memory_id")
            if not isinstance(memory_id, str) or _MEMORY_ID.fullmatch(memory_id) is None:
                raise MemoryError("invalid_memory_id")
            row = connection.execute(
                "SELECT * FROM memories WHERE memory_id=?", (memory_id,)
            ).fetchone()
            if row is None:
                raise MemoryError("not_found")
            record = self._record_from_row(row)
            return {
                "record": record,
                "status": self._memory_status(connection, memory_id),
                "verification": self._verification(connection, memory_id),
                "network_accessed": False,
            }

        if operation == "status":
            _exact_object(request, required={"op"}, optional=common_optional)
            rows = {
                str(row["kind"]): int(row["count"])
                for row in connection.execute(
                    "SELECT kind,COUNT(*) AS count FROM memories GROUP BY kind"
                )
            }
            count = sum(rows.values())
            latest_row = connection.execute(
                "SELECT created_at FROM memories ORDER BY ingest_seq DESC LIMIT 1"
            ).fetchone()
            return {
                "state": "ready",
                "store_id": str(connection.execute("SELECT value FROM metadata WHERE key='store_id'").fetchone()[0]),
                "records": count,
                "by_kind": rows,
                "latest_at": str(latest_row[0]) if latest_row is not None else None,
                "storage": "local_append_only_sqlite",
                "database_schema": DATABASE_SCHEMA,
                "database_reader": DATABASE_READER,
                "database_writer": DATABASE_WRITER,
                "network_accessed": False,
                "admissions": {
                    str(row[0]): int(row[1]) for row in connection.execute(
                        "SELECT state,COUNT(*) FROM record_admissions GROUP BY state"
                    )
                },
                "context_eligible_records": int(connection.execute(
                    "SELECT COUNT(*) FROM record_admissions WHERE vault_admitted(state,signer_key_id)>0"
                ).fetchone()[0]),
                "current_trust_checked": self.trust_check is not None,
            }

        if operation == "changes":
            _exact_object(request, required={"op"}, optional=common_optional | {
                "after", "limit", "maximum_bytes", "store_id", "require_verified"
            })
            return self._changes(
                connection, after=request.get("after", 0), limit=request.get("limit", 100),
                maximum_bytes=request.get("maximum_bytes", 256 * 1024),
                store_id=request.get("store_id"),
                require_verified=request.get("require_verified", False),
            )

        raise MemoryError("unsupported_operation")

    def _changes(
        self, connection: sqlite3.Connection, *, after: int = 0, limit: int = 100,
        maximum_bytes: int = 256 * 1024, store_id: str | None = None, require_verified: bool = False,
    ) -> Mapping[str, Any]:
        if not isinstance(after, int) or isinstance(after, bool) or after < 0:
            raise MemoryError("invalid_cursor")
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 256:
            raise MemoryError("invalid_limit")
        if not isinstance(maximum_bytes, int) or isinstance(maximum_bytes, bool) or not 4096 <= maximum_bytes <= 3 * 1024 * 1024:
            raise MemoryError("invalid_transfer_limit")
        if not isinstance(require_verified, bool):
            raise MemoryError("invalid_admission_filter")
        actual_store = str(connection.execute("SELECT value FROM metadata WHERE key='store_id'").fetchone()[0])
        if store_id is not None and store_id != actual_store:
            raise MemoryError("store_identity_changed")
        head = int(connection.execute("SELECT COALESCE(MAX(sequence),0) FROM delivery_log").fetchone()[0])
        if after > head:
            raise MemoryError("cursor_ahead")
        rows = list(connection.execute(
            "SELECT d.sequence,d.memory_id FROM delivery_log d "
            "JOIN record_admissions a ON a.memory_id=d.memory_id "
            "WHERE d.sequence>? AND vault_admitted(a.state,a.signer_key_id)>0 "
            "ORDER BY d.sequence LIMIT ?", (after, limit + 1)
        ))
        records: dict[str, Mapping[str, Any]] = {}
        proofs: dict[str, Mapping[str, Any]] = {}
        ingest_order: dict[str, int] = {}
        blocked: list[Mapping[str, Any]] = []
        used = 1024  # Account for the cursor/envelope, not just memory text.
        cursor = after
        more = len(rows) > limit
        for row in rows[:limit]:
            additions: dict[str, Mapping[str, Any]] = {}
            added_proofs: dict[str, Mapping[str, Any]] = {}
            pending = [str(row["memory_id"])]
            added_bytes = 0
            blocked_reason = None
            while pending:
                memory_id = pending.pop()
                if memory_id in records or memory_id in additions:
                    continue
                if len(additions) >= 1024:
                    blocked_reason = "dependency_budget_exceeded"
                    break
                dependency = connection.execute(
                    "SELECT m.*,a.attestation_json,vault_admitted(a.state,a.signer_key_id) AS admission_rank FROM memories m "
                    "JOIN record_admissions a ON a.memory_id=m.memory_id "
                    "WHERE m.memory_id=? AND vault_admitted(a.state,a.signer_key_id)>0", (memory_id,)
                ).fetchone()
                if dependency is None:
                    blocked_reason = "dependency_not_admitted"
                    break
                if require_verified and int(dependency["admission_rank"]) < 2:
                    blocked_reason = "unsigned_dependency"
                    break
                record = self._record_from_row(dependency)
                ingest_order[memory_id] = int(dependency["ingest_seq"])
                additions[memory_id] = record
                added_bytes += len(canonical_bytes(record)) + 256
                if dependency["attestation_json"] is not None:
                    proof = strict_json_loads(str(dependency["attestation_json"]))
                    added_proofs[memory_id] = proof
                    added_bytes += len(canonical_bytes(proof))
                if added_bytes > maximum_bytes - 1024:
                    blocked_reason = "dependency_budget_exceeded"
                    break
                pending.extend(str(relation["target"]) for relation in record["relations"])
            if blocked_reason is not None:
                disposition = {"memory_id": str(row["memory_id"]), "sequence": int(row["sequence"]), "reason": blocked_reason}
                cost = len(canonical_bytes(disposition)) + 32
                if used + cost > maximum_bytes:
                    more = True
                    break
                blocked.append(disposition)
                used += cost
                cursor = int(row["sequence"])
                continue
            if used + added_bytes > maximum_bytes or len(records) + len(additions) > 1024:
                more = True
                break
            records.update(additions)
            proofs.update(added_proofs)
            used += added_bytes
            cursor = int(row["sequence"])
        if not more:
            cursor = head  # Advance over quarantined records without sending them.
        return {
            "store_id": actual_store, "after": after, "cursor": cursor,
            "has_more": more, "records": [records[key] for key in sorted(records, key=lambda key: (ingest_order[key], key))], "attestations": proofs,
            "blocked": blocked,
            "dependency_closure_included": True, "network_accessed": False,
        }

    def ingest_records(
        self, records: Iterable[Mapping[str, Any]], *, admission: str = "quarantined",
        attestations: Mapping[str, Mapping[str, Any]] | None = None,
        transfer_id: str | None = None, payload_sha256: str | None = None,
    ) -> Mapping[str, Any]:
        """Trusted in-process admission API, not exposed through request JSON.

        A caller selecting verified MUST verify every record against an
        independently provisioned TrustStore first. Memory content cannot select
        this mode. Atomic receipts make a crashed receiver's retries idempotent.
        """
        if admission not in ADMISSION_STATES - {"local_unsigned"}:
            raise MemoryError("invalid_admission")
        prepared: dict[str, dict[str, Any]] = {}
        size = 0
        for value in records:
            record = validate_record(value)
            memory_id = str(record["memory_id"])
            if memory_id in prepared:
                raise MemoryError("duplicate_bundle_record")
            prepared[memory_id] = record
            size += len(canonical_bytes(record))
            if len(prepared) > MAX_BUNDLE_RECORDS or size > MAX_BUNDLE_BYTES:
                raise MemoryError("bundle_too_large")
        proofs = dict(attestations or {})
        if admission == "verified" and set(proofs) != set(prepared):
            raise MemoryError("missing_attestation")
        if admission != "verified" and proofs:
            raise MemoryError("unexpected_attestation")
        if transfer_id is not None and (
            not isinstance(transfer_id, str) or re.fullmatch(r"xfer_[0-9a-f]{64}", transfer_id) is None
            or not isinstance(payload_sha256, str) or re.fullmatch(r"[0-9a-f]{64}", payload_sha256) is None
        ):
            raise MemoryError("invalid_transfer_receipt")
        with contextlib.closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            if transfer_id is not None:
                prior = connection.execute("SELECT * FROM transfer_receipts WHERE transfer_id=?", (transfer_id,)).fetchone()
                if prior is not None:
                    if prior["payload_sha256"] != payload_sha256:
                        raise MemoryError("transfer_replay_conflict")
                    replay = dict(strict_json_loads(str(prior["result_json"])))
                    replay["records_added"] = 0
                    replay["receipt_replayed"] = True
                    return replay
            added = 0
            upgraded: set[str] = set()
            for record in prepared.values():
                _, inserted = self._insert_record(connection, record, allow_pending_relations=True)
                if self._set_admission(connection, record, admission, proofs.get(str(record["memory_id"]))):
                    upgraded.add(str(record["memory_id"]))
                added += int(inserted)
            self._requeue_dependents(connection, upgraded)
            result = {"state": "imported", "records_seen": len(prepared), "records_added": added, "admission": admission}
            if transfer_id is not None:
                connection.execute(
                    "INSERT INTO transfer_receipts(transfer_id,payload_sha256,result_json,created_at) VALUES(?,?,?,?)",
                    (transfer_id, payload_sha256, canonical_bytes(result).decode("utf-8"), utc_now()),
                )
            try:
                connection.commit()
            except sqlite3.IntegrityError:
                raise MemoryError("dangling_relation") from None
            return result

    def quarantine_signer(self, key_id: str) -> Mapping[str, Any]:
        """Explicit local maintenance; preserves memory bytes and attestations."""
        if not isinstance(key_id, str) or re.fullmatch(r"ed25519_[0-9a-f]{64}", key_id) is None:
            raise MemoryError("invalid_key_id")
        with contextlib.closing(self._connect()) as connection, connection:
            count = connection.execute(
                "UPDATE record_admissions SET state='quarantined' WHERE signer_key_id=? AND state='verified'", (key_id,)
            ).rowcount
            return {"state": "quarantined", "records": count}

    def requeue_records(self, identifiers: Sequence[str]) -> Mapping[str, Any]:
        """Explicit delivery retry after trust/dependency/budget repair; no content edit."""
        if not identifiers or len(identifiers) > 256:
            raise MemoryError("invalid_limit")
        if any(not isinstance(value, str) or _MEMORY_ID.fullmatch(value) is None for value in identifiers):
            raise MemoryError("invalid_memory_id")
        with contextlib.closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            for memory_id in set(identifiers):
                if self._memory_status(connection, memory_id) == "quarantined":
                    raise MemoryError("record_not_admitted")
                connection.execute("INSERT INTO delivery_log(memory_id) VALUES(?)", (memory_id,))
            self._requeue_dependents(connection, identifiers)
            return {"state": "requeued", "records": len(set(identifiers)), "network_accessed": False}

    def handle(self, value: Any) -> Mapping[str, Any]:
        if not isinstance(value, Mapping):
            return failure("invalid_object")
        request = dict(value)
        request_id = request.get("request_id")
        if request_id is not None and (
            not isinstance(request_id, str) or _REQUEST_ID.fullmatch(request_id) is None
        ):
            return failure("invalid_request_id")
        try:
            _validate_tree(request)
            request_digest = sha256(canonical_bytes(request))
        except MemoryError as exc:
            return failure(exc.code, retryable=exc.retryable, request_id=request_id)
        if request.get("op") == "capabilities":
            try:
                _exact_object(
                    request,
                    required={"op"},
                    optional={"schema_version", "request_id"},
                )
                if request.get("schema_version", REQUEST_SCHEMA) != REQUEST_SCHEMA:
                    raise MemoryError("unsupported_request_schema")
                # Capability discovery is deliberately zero-write and does not
                # create the database or its parent directory.
                return success(capability_result(), request_id=request_id)
            except MemoryError as exc:
                return failure(
                    exc.code, retryable=exc.retryable, request_id=request_id
                )
        try:
            mutating = request.get("op") in {"remember", "observe"}
            with contextlib.closing(self._connect(writable=mutating)) as connection, connection:
                if mutating:
                    connection.execute("BEGIN IMMEDIATE")
                else:
                    connection.execute("BEGIN")
                if mutating and isinstance(request_id, str):
                    receipt = connection.execute(
                        "SELECT request_sha256,response_json FROM receipts WHERE request_id=?",
                        (request_id,),
                    ).fetchone()
                    if receipt is not None:
                        if str(receipt["request_sha256"]) != request_digest:
                            raise MemoryError("request_id_conflict")
                        response = strict_json_loads(str(receipt["response_json"]))
                        if not isinstance(response, Mapping):
                            raise MemoryError("stored_receipt_invalid")
                        # Exact-effect retry, but current trust is a live view,
                        # not a claim frozen in an old successful receipt.
                        result = response.get("result")
                        if isinstance(result, dict) and isinstance(result.get("memory_id"), str):
                            result["verification"] = self._verification(connection, result["memory_id"])
                        connection.rollback()
                        return dict(response)
                result = self._dispatch(connection, request)
                response = success(result, request_id=request_id)
                if mutating and isinstance(request_id, str):
                    connection.execute(
                        "INSERT INTO receipts(request_id,request_sha256,response_json,created_at) VALUES(?,?,?,?)",
                        (
                            request_id,
                            request_digest,
                            canonical_bytes(response).decode("utf-8"),
                            utc_now(),
                        ),
                    )
                if mutating:
                    connection.commit()
                return response
        except MemoryError as exc:
            return failure(exc.code, retryable=exc.retryable, request_id=request_id)
        except sqlite3.OperationalError as exc:
            problem = _sqlite_memory_error(exc)
            return failure(
                problem.code,
                retryable=problem.retryable,
                request_id=request_id,
            )
        except Exception:
            return failure("unavailable", retryable=True, request_id=request_id)

    def export_bundle(self, output: Path) -> Mapping[str, Any]:
        destination = _absolute_path(output, error="bundle_path_must_be_absolute")
        if destination.exists() or destination.is_symlink():
            raise MemoryError("output_exists")
        _ensure_private_directory(destination.parent)
        descriptor = -1
        temporary = ""
        count = 0
        written = 0
        accumulator = hashlib.sha256()
        try:
            descriptor, temporary = tempfile.mkstemp(
                prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
            )
            os.chmod(temporary, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = -1
                header = _json_line(
                    {
                        "type": "header",
                        "schema_version": BUNDLE_SCHEMA,
                        "created_at": utc_now(),
                        "hash_profile": HASH_PROFILE,
                    }
                )
                handle.write(header)
                written += len(header)
                with contextlib.closing(self._connect(writable=False)) as connection, connection:
                    connection.execute("BEGIN")
                    for row in connection.execute(
                        "SELECT * FROM memories ORDER BY ingest_seq"
                    ):
                        record = self._record_from_row(row)
                        line = _json_line({"type": "record", "record": record})
                        handle.write(line)
                        written += len(line)
                        accumulator.update(str(record["record_sha256"]).encode("ascii") + b"\n")
                        count += 1
                        if count > MAX_BUNDLE_RECORDS or written > MAX_BUNDLE_BYTES:
                            raise MemoryError("bundle_too_large")
                footer = _json_line(
                    {
                        "type": "footer",
                        "record_count": count,
                        "records_sha256": accumulator.hexdigest(),
                    }
                )
                written += len(footer)
                if written > MAX_BUNDLE_BYTES:
                    raise MemoryError("bundle_too_large")
                handle.write(footer)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.link(temporary, destination)
            except FileExistsError:
                raise MemoryError("output_exists") from None
            os.unlink(temporary)
            temporary = ""
            with contextlib.suppress(OSError):
                destination.chmod(0o600)
            with contextlib.suppress(OSError):
                directory_fd = os.open(destination.parent, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            return {"state": "exported", "records": count, "bundle": BUNDLE_SCHEMA,
                    "signatures_included": False, "import_admission_default": "quarantined"}
        except MemoryError:
            raise
        except sqlite3.Error as exc:
            raise _sqlite_memory_error(exc) from exc
        except OSError as exc:
            raise MemoryError("export_failed") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if temporary:
                with contextlib.suppress(OSError):
                    os.unlink(temporary)

    @staticmethod
    def _scan_bundle(
        path: Path,
        *,
        visitor: Any = None,
    ) -> tuple[int, set[str], set[str], tuple[int, int, int, int]]:
        count = 0
        accumulator = hashlib.sha256()
        footer: Mapping[str, Any] | None = None
        memory_ids: set[str] = set()
        relation_targets: set[str] = set()
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(descriptor, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise MemoryError("invalid_bundle_path")
            fingerprint = (
                int(info.st_dev),
                int(info.st_ino),
                int(info.st_size),
                int(info.st_mtime_ns),
            )
            if info.st_size > MAX_BUNDLE_BYTES:
                raise MemoryError("bundle_too_large")
            first = handle.readline(MAX_BUNDLE_LINE_BYTES + 1)
            if (
                not first
                or len(first) > MAX_BUNDLE_LINE_BYTES
                or not first.endswith(b"\n")
            ):
                raise MemoryError("invalid_bundle")
            header = strict_json_loads(first)
            _exact_object(
                header,
                required={"type", "schema_version", "created_at", "hash_profile"},
            )
            if (
                header.get("type") != "header"
                or header.get("schema_version") != BUNDLE_SCHEMA
                or header.get("hash_profile") != HASH_PROFILE
            ):
                raise MemoryError("unsupported_bundle_schema")
            _timestamp(header.get("created_at"))
            while True:
                line = handle.readline(MAX_BUNDLE_LINE_BYTES + 1)
                if not line:
                    break
                if len(line) > MAX_BUNDLE_LINE_BYTES or not line.endswith(b"\n"):
                    raise MemoryError("invalid_bundle")
                value = strict_json_loads(line)
                if not isinstance(value, Mapping):
                    raise MemoryError("invalid_bundle")
                if value.get("type") == "footer":
                    footer = _exact_object(
                        value,
                        required={"type", "record_count", "records_sha256"},
                    )
                    if handle.read(1):
                        raise MemoryError("invalid_bundle")
                    break
                raw = _exact_object(value, required={"type", "record"})
                if raw.get("type") != "record":
                    raise MemoryError("invalid_bundle")
                record = validate_record(raw.get("record"))
                memory_id = str(record["memory_id"])
                if memory_id in memory_ids:
                    raise MemoryError("duplicate_bundle_record")
                memory_ids.add(memory_id)
                relation_targets.update(
                    str(relation["target"]) for relation in record["relations"]
                )
                count += 1
                if count > MAX_BUNDLE_RECORDS:
                    raise MemoryError("bundle_too_large")
                accumulator.update(
                    str(record["record_sha256"]).encode("ascii") + b"\n"
                )
                if visitor is not None:
                    visitor(record)
            if footer is None:
                raise MemoryError("invalid_bundle")
            footer_count = footer.get("record_count")
            footer_hash = footer.get("records_sha256")
            if (
                not isinstance(footer_count, int)
                or isinstance(footer_count, bool)
                or not isinstance(footer_hash, str)
                or re.fullmatch(r"[0-9a-f]{64}", footer_hash) is None
                or footer_count != count
                or footer_hash != accumulator.hexdigest()
            ):
                raise MemoryError("bundle_hash_mismatch")
        return count, memory_ids, relation_targets, fingerprint

    def import_bundle(self, source: Path, *, accept_unsigned: bool = False) -> Mapping[str, Any]:
        path = _absolute_path(source, error="bundle_path_must_be_absolute")
        if not _plain_file(path):
            raise MemoryError("invalid_bundle_path")
        inserted = 0
        try:
            count, memory_ids, relation_targets, fingerprint = self._scan_bundle(path)
            current = path.stat()
            if fingerprint != (
                int(current.st_dev),
                int(current.st_ino),
                int(current.st_size),
                int(current.st_mtime_ns),
            ):
                raise MemoryError("bundle_changed")
            with contextlib.closing(self._connect()) as connection, connection:
                missing = sorted(relation_targets - memory_ids)
                unresolved: list[str] = []
                for offset in range(0, len(missing), 500):
                    batch = missing[offset : offset + 500]
                    placeholders = ",".join("?" for _ in batch)
                    present = {
                        str(row["memory_id"])
                        for row in connection.execute(
                            f"SELECT memory_id FROM memories WHERE memory_id IN ({placeholders})",
                            batch,
                        )
                    }
                    unresolved.extend(
                        memory_id for memory_id in batch if memory_id not in present
                    )
                if unresolved:
                    raise MemoryError("dangling_relation")
                connection.execute("BEGIN IMMEDIATE")

                upgraded: set[str] = set()

                def insert_record(record: Mapping[str, Any]) -> None:
                    nonlocal inserted
                    _memory_id, was_inserted = self._insert_record(
                        connection, record, allow_pending_relations=True
                    )
                    if self._set_admission(connection, record, "accepted_unsigned" if accept_unsigned else "quarantined"):
                        upgraded.add(str(record["memory_id"]))
                    inserted += int(was_inserted)

                second_count, _ids, _targets, second_fingerprint = self._scan_bundle(
                    path, visitor=insert_record
                )
                if second_count != count or second_fingerprint != fingerprint:
                    raise MemoryError("bundle_changed")
                self._requeue_dependents(connection, upgraded)
                try:
                    connection.commit()
                except sqlite3.IntegrityError:
                    raise MemoryError("dangling_relation") from None
        except sqlite3.Error as exc:
            raise _sqlite_memory_error(exc) from exc
        except OSError as exc:
            raise MemoryError("import_failed") from exc
        return {
            "state": "imported",
            "records_seen": count,
            "records_added": inserted,
            "bundle": BUNDLE_SCHEMA,
            "admission": "accepted_unsigned" if accept_unsigned else "quarantined",
        }


def success(
    result: Mapping[str, Any], *, request_id: str | None = None
) -> dict[str, Any]:
    response: dict[str, Any] = {
        "schema_version": RESULT_SCHEMA,
        "ok": True,
        "result": dict(result),
        "authority": dict(AUTHORITY),
    }
    if request_id is not None:
        response["request_id"] = request_id
    return response


def failure(
    code: str, *, retryable: bool = False, request_id: str | None = None
) -> dict[str, Any]:
    safe = code if re.fullmatch(r"[a-z][a-z0-9_]{1,63}", code) else "rejected"
    response: dict[str, Any] = {
        "schema_version": RESULT_SCHEMA,
        "ok": False,
        "error": {"code": safe, "retryable": bool(retryable)},
        "authority": dict(AUTHORITY),
    }
    if request_id is not None and _REQUEST_ID.fullmatch(request_id) is not None:
        response["request_id"] = request_id
    return response


def read_request(stream: Any = None) -> Any:
    source = stream if stream is not None else sys.stdin.buffer
    data = source.read(MAX_REQUEST_BYTES + 1)
    if not data:
        raise MemoryError("empty_input")
    if len(data) > MAX_REQUEST_BYTES:
        raise MemoryError("request_too_large")
    return strict_json_loads(data)


def write_response(value: Mapping[str, Any]) -> None:
    encoded = _json_line(value)
    if len(encoded) > MAX_RESPONSE_BYTES:
        encoded = _json_line(failure("response_too_large"))
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()


def serve(vault: Vault) -> int:
    while True:
        line = sys.stdin.buffer.readline(MAX_REQUEST_BYTES + 1)
        if not line:
            return 0
        if len(line) > MAX_REQUEST_BYTES or not line.endswith(b"\n"):
            write_response(failure("invalid_frame"))
            return 0
        try:
            value = strict_json_loads(line)
            response = vault.handle(value)
        except MemoryError as exc:
            response = failure(exc.code, retryable=exc.retryable)
        except Exception:
            response = failure("unavailable", retryable=True)
        write_response(response)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Universal zero-install persistent memory for AI agents."
    )
    parser.add_argument(
        "--vault",
        type=Path,
        help="shared SQLite path; defaults to MEMORY_VAULT_PATH or the user data directory",
    )
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--serve", action="store_true", help="serve NDJSON until EOF")
    action.add_argument("--export", dest="export_path", type=Path, help="write a new portable NDJSON bundle")
    action.add_argument("--import", dest="import_path", type=Path, help="import one current-schema NDJSON bundle")
    action.add_argument("--upgrade", action="store_true", help="explicitly initialize or additively upgrade this Vault")
    action.add_argument("--requeue", nargs="+", metavar="MEMORY_ID", help="explicitly retry blocked delivery records after repairing dependencies or increasing transfer limits")
    parser.add_argument("--accept-unsigned", action="store_true", help="explicitly admit the imported unsigned bundle into context (never authenticate it)")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.accept_unsigned and args.import_path is None:
        write_response(failure("accept_unsigned_requires_import"))
        return 0
    try:
        vault = Vault(args.vault)
    except MemoryError as exc:
        write_response(failure(exc.code, retryable=exc.retryable))
        return 0
    except Exception:
        write_response(failure("unavailable"))
        return 0
    if args.serve:
        return serve(vault)
    if args.requeue is not None:
        try:
            write_response(success(vault.requeue_records(args.requeue)))
        except MemoryError as exc:
            write_response(failure(exc.code, retryable=exc.retryable))
        except Exception:
            write_response(failure("unavailable"))
        return 0
    if args.upgrade:
        try:
            with contextlib.closing(vault._connect()):
                pass
            write_response(success({"state": "ready", "database_schema": DATABASE_SCHEMA}))
        except MemoryError as exc:
            write_response(failure(exc.code, retryable=exc.retryable))
        except Exception:
            write_response(failure("unavailable"))
        return 0
    if args.export_path is not None:
        try:
            write_response(success(vault.export_bundle(args.export_path)))
        except MemoryError as exc:
            write_response(failure(exc.code, retryable=exc.retryable))
        except Exception:
            write_response(failure("unavailable"))
        return 0
    if args.import_path is not None:
        try:
            write_response(success(vault.import_bundle(args.import_path, accept_unsigned=args.accept_unsigned)))
        except MemoryError as exc:
            write_response(failure(exc.code, retryable=exc.retryable))
        except Exception:
            write_response(failure("unavailable"))
        return 0
    try:
        request = read_request()
        response = vault.handle(request)
    except MemoryError as exc:
        response = failure(exc.code, retryable=exc.retryable)
    except Exception:
        response = failure("unavailable", retryable=True)
    write_response(response)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
