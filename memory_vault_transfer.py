#!/usr/bin/env python3
"""Explicit, signed, incremental delivery through a user-selected directory.

The directory may be carried by a separately authorized shared-folder service.
This adapter opens no network connections, installs nothing, starts no daemon,
and never transports private keys. It is not encrypted storage or a network ACL.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import os
from pathlib import Path
import re
import sqlite3
import stat
import tempfile
from typing import Any, Callable, Iterator, Mapping, Sequence

from memory_vault import MAX_BUNDLE_BYTES, MAX_BUNDLE_RECORDS, MemoryError, Vault, canonical_bytes, failure, sha256, strict_json_loads, success, validate_record, write_response
from memory_vault_trust import Identity, TrustError, TrustStore
import memory_vault_storage as protected_storage
from memory_vault_dependency import DependencyIndex, incremental_changes, ingest_verified, validate_outgoing


DELTA_SCHEMA = "universal-memory-delta/v1"
CHAINED_DELTA_SCHEMA = "universal-memory-delta/v2"
INCREMENTAL_DELTA_SCHEMA = "universal-memory-delta/v3"
_CHAINED_SCHEMAS = frozenset({CHAINED_DELTA_SCHEMA, INCREMENTAL_DELTA_SCHEMA})
STATE_SCHEMA = "universal-memory-transfer-state/v1"
REVIEW_SCHEMA = "universal-memory-publication-review/v1"
DECISION_SCHEMA = "universal-memory-publication-decision/v1"
GROUP_SCHEMA = "universal-memory-fragment-group/v1"
MAX_CAPSULE_BYTES = 4 * 1024 * 1024
MAX_FRAGMENT_BYTES = MAX_CAPSULE_BYTES
MAX_GROUP_BYTES = MAX_BUNDLE_BYTES + MAX_BUNDLE_RECORDS * 4096
MAX_GROUP_FRAGMENTS = (MAX_GROUP_BYTES + MAX_FRAGMENT_BYTES - 1) // MAX_FRAGMENT_BYTES + 1
MAX_REVIEW_DOCUMENT = 16 * 1024 * 1024
MAX_DISCOVERY_FILES = 20_000
MAX_PEERS = 256
MAX_REVIEW_RECORDS = MAX_BUNDLE_RECORDS
MAX_DISPOSITIONS = 1024
_KEY = re.compile(r"ed25519_[0-9a-f]{64}")
_STORE = re.compile(r"store_[0-9a-f]{32}")
_MEMORY = re.compile(r"mem_[0-9a-f]{40}")
_HASH = re.compile(r"[0-9a-f]{64}")
_REQUEST = re.compile(r"req_[A-Za-z0-9_-]{8,96}")
_CAPSULE_NAME = re.compile(r"([0-9]{20})-([0-9]{20})-([0-9a-f]{64})\.json")


def _path(value: Path) -> Path:
    path = value.expanduser()
    if os.name == "nt":
        try:
            return protected_storage.validate_path(path)
        except protected_storage.StorageError as exc:
            raise MemoryError(exc.code, retryable=exc.retryable) from None
    if not path.is_absolute() or ".." in path.parts:
        raise MemoryError("transfer_path_must_be_absolute")
    for part in (path, *path.parents):
        if part.is_symlink():
            raise MemoryError("unsafe_transfer_path")
    return path


def _private_directory(path: Path) -> None:
    if os.name == "nt":
        try:
            protected_storage.private_directory(path)
            return
        except protected_storage.StorageError as exc:
            raise MemoryError(exc.code, retryable=exc.retryable) from None
    if os.name != "posix":
        raise MemoryError("unsupported_private_storage")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise MemoryError("unprotected_transfer_state")


def _read(path: Path, *, maximum: int = MAX_CAPSULE_BYTES, private: bool = False) -> Mapping[str, Any]:
    _path(path)
    descriptor = (protected_storage.open_file(path, os.O_RDONLY, private=private) if os.name == "nt" else
                  os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)))
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise MemoryError("invalid_transfer_file")
        if os.name != "nt" and private and (info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_nlink != 1):
            raise MemoryError("unprotected_transfer_state")
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise MemoryError("transfer_too_large")
    value = strict_json_loads(data)
    if not isinstance(value, Mapping):
        raise MemoryError("invalid_transfer_file")
    return value


def _write(path: Path, value: Mapping[str, Any], *, replace: bool, maximum: int = MAX_CAPSULE_BYTES,
           private: bool = True) -> None:
    """Atomic private state or explicitly selected immutable exchange output."""
    _path(path)
    if type(private) is not bool or (not private and replace):
        raise MemoryError("invalid_transfer_publication_profile")
    encoded = canonical_bytes(value) + b"\n"
    if len(encoded) > maximum:
        raise MemoryError("transfer_too_large")
    try:
        try:
            if os.name == "nt":
                # The native profile stays private even for an exchange file.
                protected_storage.atomic_write(path, encoded, replace=replace)
            else:
                descriptor, temporary_name = tempfile.mkstemp(prefix=".vault-", suffix=".tmp", dir=path.parent)
                temporary = Path(temporary_name)
                try:
                    with os.fdopen(descriptor, "wb") as stream:
                        os.fchmod(stream.fileno(), 0o600)
                        stream.write(encoded)
                        stream.flush()
                        os.fsync(stream.fileno())
                    if replace and path.exists():
                        _read(path, maximum=maximum, private=True)
                    # One exclusive rename consumes the temporary name. A
                    # process exit cannot strand a private two-link journal.
                    protected_storage.publish_file(temporary, path, replace=replace, private_parent=private)
                finally:
                    with contextlib.suppress(FileNotFoundError):
                        temporary.unlink()
        except FileExistsError:
            if replace or canonical_bytes(_read(path, maximum=maximum, private=private)) != canonical_bytes(value):
                raise MemoryError("transfer_output_conflict") from None
    except protected_storage.StorageError as exc:
        raise MemoryError(exc.code, retryable=exc.retryable) from None


@contextlib.contextmanager
def _lock(directory: Path) -> Iterator[None]:
    _private_directory(directory)
    if os.name == "nt":
        try:
            with protected_storage.file_lock(directory / "transfer.lock", busy_code="transfer_busy"):
                yield
            return
        except protected_storage.StorageError as exc:
            raise MemoryError(exc.code, retryable=exc.retryable) from None
    import fcntl  # POSIX only; no unsafe cross-platform lock emulation.
    target = directory / "transfer.lock"
    descriptor = os.open(target, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
                         | getattr(os, "O_NONBLOCK", 0), 0o600)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_nlink != 1:
            raise MemoryError("unprotected_transfer_state")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise MemoryError("transfer_busy", retryable=True) from None
        yield
    finally:
        os.close(descriptor)


def _cursor(value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 2**63 - 1:
        raise MemoryError("invalid_cursor")
    return value


def _fragment_name(fragment: Mapping[str, Any]) -> str:
    return f"{fragment['index']:06d}-{fragment['sha256']}.ndjson"


def _read_fragment(path: Path, *, maximum: int = MAX_FRAGMENT_BYTES) -> bytes:
    fd = (protected_storage.open_file(_path(path), os.O_RDONLY) if os.name == "nt" else
          os.open(_path(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)))
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise MemoryError("invalid_group_fragment")
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise MemoryError("invalid_group_fragment")
    return raw


def _write_fragment(path: Path, data: bytes, *, private: bool = True) -> None:
    """Publish complete fragment bytes atomically and without overwriting."""
    _path(path)
    if type(private) is not bool:
        raise MemoryError("invalid_transfer_publication_profile")
    if not data or len(data) > MAX_FRAGMENT_BYTES:
        raise MemoryError("invalid_group_fragment")
    try:
        try:
            if os.name == "nt":
                protected_storage.atomic_write(path, data, replace=False)
            else:
                fd, name = tempfile.mkstemp(prefix=".fragment-", dir=path.parent)
                temporary = Path(name)
                try:
                    with os.fdopen(fd, "wb") as stream:
                        os.fchmod(stream.fileno(), 0o600)
                        stream.write(data)
                        stream.flush()
                        os.fsync(stream.fileno())
                    protected_storage.publish_file(temporary, path, replace=False, private_parent=private)
                finally:
                    with contextlib.suppress(FileNotFoundError):
                        temporary.unlink()
        except FileExistsError:
            if _read_fragment(path) != data:
                raise MemoryError("group_fragment_conflict") from None
    except protected_storage.StorageError as exc:
        raise MemoryError(exc.code, retryable=exc.retryable) from None


def _group(value: Any) -> dict[str, Any]:
    if (not isinstance(value, dict)
            or set(value) != {"schema_version", "group_id", "record_count", "record_bytes", "encoded_bytes", "records_sha256", "fragments"}
            or value["schema_version"] != GROUP_SCHEMA
            or not isinstance(value["group_id"], str) or not _HASH.fullmatch(value["group_id"])
            or not isinstance(value["records_sha256"], str) or not _HASH.fullmatch(value["records_sha256"])):
        raise MemoryError("invalid_transfer_group")
    for name, maximum in (("record_count", MAX_BUNDLE_RECORDS), ("record_bytes", MAX_BUNDLE_BYTES), ("encoded_bytes", MAX_GROUP_BYTES)):
        if type(value[name]) is not int or not 1 <= value[name] <= maximum:
            raise MemoryError("invalid_transfer_group")
    fragments = value["fragments"]
    if not isinstance(fragments, list) or not 1 <= len(fragments) <= MAX_GROUP_FRAGMENTS:
        raise MemoryError("invalid_transfer_group")
    for index, fragment in enumerate(fragments):
        if (not isinstance(fragment, dict) or set(fragment) != {"index", "sha256", "bytes", "records"}
                or fragment["index"] != index or type(fragment["index"]) is not int
                or type(fragment["bytes"]) is not int or not 1 <= fragment["bytes"] <= MAX_FRAGMENT_BYTES
                or type(fragment["records"]) is not int or not 1 <= fragment["records"] <= MAX_BUNDLE_RECORDS
                or not isinstance(fragment["sha256"], str) or not _HASH.fullmatch(fragment["sha256"])):
            raise MemoryError("invalid_transfer_group")
    descriptor = {key: part for key, part in value.items() if key != "group_id"}
    if (sum(part["bytes"] for part in fragments) != value["encoded_bytes"]
            or sum(part["records"] for part in fragments) != value["record_count"]
            or sha256(canonical_bytes(descriptor)) != value["group_id"]):
        raise MemoryError("invalid_transfer_group")
    return dict(value)


class DirectoryTransfer:
    """One explicit local exchange endpoint, not an always-running service."""

    def __init__(
        self, *, vault: Path, exchange: Path, state_directory: Path,
        trust_store: Path, identity: Path | None = None,
    ):
        self.exchange = _path(exchange)
        self.state_directory = _path(state_directory)
        self.vault_path = _path(vault)
        trust_path = _path(trust_store)
        identity_path = _path(identity) if identity is not None else None
        private_files = [self.vault_path, trust_path, *([identity_path] if identity_path is not None else [])]
        if len(set(private_files)) != len(private_files):
            raise MemoryError("transfer_path_conflict")
        for private_file in private_files:
            if (private_file == self.state_directory or self.state_directory in private_file.parents
                    or private_file in self.state_directory.parents
                    or any(private_file in other.parents for other in private_files)):
                raise MemoryError("transfer_path_conflict")
        for private_path in (self.state_directory, self.vault_path, trust_path, identity_path):
            if private_path is not None and (private_path == self.exchange or self.exchange in private_path.parents):
                raise MemoryError("private_state_inside_exchange")
        if self.state_directory == self.exchange or self.state_directory in self.exchange.parents:
            raise MemoryError("exchange_inside_private_state")
        self.trust = TrustStore(trust_path)
        self.identity = Identity.load(identity_path) if identity_path is not None else None
        self.vault = Vault(self.vault_path, trust_check=self.trust.require_trusted)
        self.state_path = self.state_directory / "state.json"
        self.pending_path = self.state_directory / "publish.pending.json"
        self.started_path = self.state_directory / "publish.started.json"

    def _state(self) -> dict[str, Any]:
        if not self.state_path.exists():
            return {"schema_version": STATE_SCHEMA, "vault_store_id": None, "publisher_key_id": None,
                    "published_cursor": 0, "last_published": None, "received": {}, "received_heads": {}}
        value = dict(_read(self.state_path, private=True))
        original_fields = {"schema_version", "vault_store_id", "publisher_key_id", "published_cursor", "last_published", "received"}
        if set(value) not in (original_fields, original_fields | {"received_heads"}):
            raise MemoryError("invalid_transfer_state")
        value.setdefault("received_heads", {})
        if value["schema_version"] != STATE_SCHEMA or not isinstance(value["received"], dict):
            raise MemoryError("invalid_transfer_state")
        if value["vault_store_id"] is not None and (not isinstance(value["vault_store_id"], str) or not _STORE.fullmatch(value["vault_store_id"])):
            raise MemoryError("invalid_transfer_state")
        if value["publisher_key_id"] is not None and (not isinstance(value["publisher_key_id"], str) or not _KEY.fullmatch(value["publisher_key_id"])):
            raise MemoryError("invalid_transfer_state")
        _cursor(value["published_cursor"])
        if value["last_published"] is not None and (not isinstance(value["last_published"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["last_published"])):
            raise MemoryError("invalid_transfer_state")
        if len(value["received"]) > MAX_PEERS:
            raise MemoryError("too_many_transfer_peers")
        for peer, cursor in value["received"].items():
            parts = peer.split("/")
            if len(parts) != 2 or not _KEY.fullmatch(parts[0]) or not _STORE.fullmatch(parts[1]):
                raise MemoryError("invalid_transfer_state")
            _cursor(cursor)
        heads = value["received_heads"]
        if not isinstance(heads, dict) or not set(heads) <= set(value["received"]):
            raise MemoryError("invalid_transfer_history")
        for peer, head in heads.items():
            if (not isinstance(head, dict) or set(head) not in ({"after", "cursor", "batch_sha256"}, {"after", "cursor", "batch_sha256", "chained"})
                    or not isinstance(head["batch_sha256"], str) or not _HASH.fullmatch(head["batch_sha256"])
                    or not _cursor(head["after"]) < _cursor(head["cursor"])
                    or head["cursor"] != value["received"][peer]):
                raise MemoryError("invalid_transfer_history")
            head.setdefault("chained", False)
            if type(head["chained"]) is not bool:
                raise MemoryError("invalid_transfer_history")
        return value

    def _bind_vault(self, state: dict[str, Any], *, missing_ok: bool) -> None:
        # A stream binding needs one indexed metadata value, not status's full
        # memory/admission counts. The core read-only connection retains its
        # path, schema/version and required-table checks without migrating data.
        _path(self.vault_path)
        if os.name == "nt":
            # SQLite and its sidecars inherit only from an independently
            # protected parent; the lightweight core makes no such ACL claim.
            protected_storage.private_directory(self.vault_path.parent, create=missing_ok)
            for path in (self.vault_path, *[Path(str(self.vault_path) + suffix) for suffix in ("-wal", "-shm", "-journal")]):
                if path.exists():
                    fd = protected_storage.open_file(path, os.O_RDONLY, private=True)
                    os.close(fd)
        try:
            with contextlib.closing(self.vault._connect(writable=False)) as connection:
                row = connection.execute("SELECT value FROM metadata WHERE key='store_id'").fetchone()
                store_id = str(row[0]) if row is not None else ""
                if _STORE.fullmatch(store_id) is None:
                    raise MemoryError("unsupported_database_schema")
        except MemoryError as exc:
            if exc.code == "not_initialized" and missing_ok and state["vault_store_id"] is None:
                return
            if exc.code == "not_initialized" and state["vault_store_id"] is not None:
                raise MemoryError("receiver_vault_missing") from None
            raise
        except sqlite3.Error:
            raise MemoryError("vault_metadata_unavailable", retryable=True) from None
        if state["vault_store_id"] is not None and state["vault_store_id"] != store_id:
            raise MemoryError("store_identity_changed")
        state["vault_store_id"] = store_id

    def _verify_capsule(self, capsule: Mapping[str, Any], *, verify_records: bool = True) -> tuple[dict[str, Any], str]:
        if set(capsule) != {"payload", "proof"} or not isinstance(capsule["payload"], Mapping):
            raise MemoryError("invalid_transfer_envelope")
        payload = dict(capsule["payload"])
        if not isinstance(payload.get("schema_version"), str):
            raise MemoryError("unsupported_transfer_schema")
        fields = {"schema_version", "source_store_id", "sender_key_id", "after", "cursor", "records", "attestations", "blocked"}
        if payload.get("schema_version") in _CHAINED_SCHEMAS:
            fields |= {"previous_batch_sha256", "publication_review", "group"}
        elif payload.get("schema_version") != DELTA_SCHEMA:
            raise MemoryError("unsupported_transfer_schema")
        if payload.get("schema_version") == INCREMENTAL_DELTA_SCHEMA:
            fields.add("dependency_mode")
        if set(payload) != fields:
            raise MemoryError("invalid_transfer_payload")
        store_id, sender = payload["source_store_id"], payload["sender_key_id"]
        if not isinstance(store_id, str) or not _STORE.fullmatch(store_id) or not isinstance(sender, str) or not _KEY.fullmatch(sender):
            raise MemoryError("invalid_transfer_source")
        if _cursor(payload["cursor"]) <= _cursor(payload["after"]):
            raise MemoryError("invalid_transfer_cursor")
        if payload["schema_version"] in _CHAINED_SCHEMAS:
            previous = payload["previous_batch_sha256"]
            if ((payload["after"] == 0 and previous is not None)
                    or (payload["after"] > 0 and (not isinstance(previous, str) or not _HASH.fullmatch(previous)))):
                raise MemoryError("invalid_transfer_history")
        if payload["schema_version"] == INCREMENTAL_DELTA_SCHEMA:
            if (not isinstance(payload["dependency_mode"], str)
                    or payload["dependency_mode"] not in {"closure", "prior_stream"}
                    or (payload["after"] == 0 and payload["dependency_mode"] != "closure")):
                raise MemoryError("invalid_dependency_mode")
        if self.trust.verify_message(payload, capsule["proof"]) != sender:
            raise MemoryError("transfer_signer_mismatch")
        blocked = payload["blocked"]
        if not isinstance(blocked, list) or len(blocked) > (MAX_DISPOSITIONS if payload["schema_version"] in _CHAINED_SCHEMAS else 256):
            raise MemoryError("invalid_transfer_disposition")
        reasons = {"dependency_not_admitted", "dependency_budget_exceeded", "unsigned_dependency"}
        if payload["schema_version"] == INCREMENTAL_DELTA_SCHEMA:
            reasons.remove("dependency_budget_exceeded")
        if payload["schema_version"] in _CHAINED_SCHEMAS:
            reasons.add("operator_excluded")
        sequences: set[int] = set()
        for item in blocked:
            if (not isinstance(item, dict) or set(item) != {"memory_id", "sequence", "reason"}
                    or not isinstance(item["memory_id"], str) or re.fullmatch(r"mem_[0-9a-f]{40}", item["memory_id"]) is None
                    or not isinstance(item["reason"], str)
                    or item["reason"] not in reasons
                    or not payload["after"] < _cursor(item["sequence"]) <= payload["cursor"]):
                raise MemoryError("invalid_transfer_disposition")
            if item["sequence"] in sequences:
                raise MemoryError("duplicate_transfer_disposition")
            sequences.add(item["sequence"])
        if not isinstance(payload["records"], list) or len(payload["records"]) > 1024 or not isinstance(payload["attestations"], Mapping):
            raise MemoryError("invalid_transfer_records")
        identifiers: set[str] = set()
        for raw in payload["records"]:
            record = validate_record(raw)
            memory_id = str(record["memory_id"])
            if memory_id in identifiers:
                raise MemoryError("duplicate_bundle_record")
            identifiers.add(memory_id)
            proof = payload["attestations"].get(memory_id)
            if proof is None:
                raise MemoryError("missing_attestation")
            if verify_records:
                self.trust.verify_record(record, proof)
        if set(payload["attestations"]) != identifiers:
            raise MemoryError("unexpected_attestation")
        if payload["schema_version"] in _CHAINED_SCHEMAS:
            group = _group(payload["group"]) if payload["group"] is not None else None
            if group is not None and (identifiers or payload["attestations"]):
                raise MemoryError("mixed_group_and_inline_records")
            review = payload["publication_review"]
            if review is not None:
                if (not isinstance(review, dict)
                        or set(review) != {"schema_version", "request_id", "replaces_unpublished_batch_sha256", "selection_sha256", "excluded_records", "retained_records"}
                        or review["schema_version"] != REVIEW_SCHEMA
                        or not isinstance(review["request_id"], str) or not _REQUEST.fullmatch(review["request_id"])
                        or not isinstance(review["replaces_unpublished_batch_sha256"], str)
                        or not _HASH.fullmatch(review["replaces_unpublished_batch_sha256"])
                        or not isinstance(review["selection_sha256"], str) or not _HASH.fullmatch(review["selection_sha256"])
                        or type(review["excluded_records"]) is not int or not 0 <= review["excluded_records"] <= MAX_REVIEW_RECORDS
                        or type(review["retained_records"]) is not int
                        or review["retained_records"] != (group["record_count"] if group else len(identifiers))):
                    raise MemoryError("invalid_publication_review")
            elif any(item["reason"] == "operator_excluded" for item in blocked):
                raise MemoryError("missing_publication_review")
            if (payload["schema_version"] == INCREMENTAL_DELTA_SCHEMA and payload["dependency_mode"] == "closure"
                    and group is None and any(relation["target"] not in identifiers
                                               for record in payload["records"] for relation in record["relations"])):
                raise MemoryError("incomplete_transfer_closure")
        return payload, sha256(canonical_bytes(payload))

    @staticmethod
    def _review_ids(value: Any) -> set[str]:
        if (not isinstance(value, (list, tuple)) or len(value) > MAX_REVIEW_RECORDS
                or any(not isinstance(item, str) or not _MEMORY.fullmatch(item) for item in value)
                or len(set(value)) != len(value)):
            raise MemoryError("invalid_review_record_ids")
        return set(value)

    @staticmethod
    def _check_chain(state: Mapping[str, Any], payload: Mapping[str, Any]) -> None:
        peer = payload["sender_key_id"] + "/" + payload["source_store_id"]
        head = state["received_heads"].get(peer)
        if payload["schema_version"] not in _CHAINED_SCHEMAS:
            if head is not None and head.get("chained"):
                raise MemoryError("transfer_history_downgrade")
            return
        if payload["after"] == 0:
            return
        if head is None:
            raise MemoryError("legacy_history_anchor_required")
        if head["cursor"] != payload["after"] or head["batch_sha256"] != payload["previous_batch_sha256"]:
            raise MemoryError("transfer_history_anchor_mismatch")

    @staticmethod
    def _remember_head(state: dict[str, Any], payload: Mapping[str, Any], digest: str) -> None:
        peer = payload["sender_key_id"] + "/" + payload["source_store_id"]
        state["received"][peer] = payload["cursor"]
        state["received_heads"][peer] = {"after": payload["after"], "cursor": payload["cursor"], "batch_sha256": digest,
                                         "chained": payload["schema_version"] in _CHAINED_SCHEMAS}

    def _dependency_index(self, *, create_vault: bool = False) -> DependencyIndex:
        # Receiver initialization is already an explicitly authorized admission
        # operation. No read-only review/status path invokes this helper.
        with contextlib.closing(self.vault._connect(writable=create_vault)) as connection:
            store = str(connection.execute("SELECT value FROM metadata WHERE key='store_id'").fetchone()[0])
        return DependencyIndex(self.state_directory / "dependency-index.sqlite3", store_id=store,
                               destination=str(self.exchange))

    def validate_outgoing_payload(self, payload: Mapping[str, Any]) -> None:
        if payload["schema_version"] == INCREMENTAL_DELTA_SCHEMA:
            records, _ = self.records_for_payload(payload)
            validate_outgoing(self.vault, self.trust, self._dependency_index(), records)

    def _dependency_history(self, payload: Mapping[str, Any]) -> None:
        if not payload["after"]:
            return
        previous = payload["previous_batch_sha256"]
        try:
            capsule = _read(self.state_directory / "received-capsules" / (previous + ".json"), private=True)
        except FileNotFoundError:
            raise MemoryError("dependency_base_evidence_missing") from None
        historical, digest = self._verify_capsule(capsule, verify_records=False)
        if (digest != previous or historical["sender_key_id"] != payload["sender_key_id"]
                or historical["source_store_id"] != payload["source_store_id"]
                or historical["cursor"] != payload["after"]):
            raise MemoryError("dependency_base_evidence_mismatch")

    def _record_published(self, capsule: Mapping[str, Any], digest: str) -> None:
        payload = capsule["payload"]
        output = self.exchange / payload["sender_key_id"] / payload["source_store_id"] / (
            f"{payload['after']:020d}-{payload['cursor']:020d}-{digest}.json")
        if canonical_bytes(_read(_path(output))) != canonical_bytes(capsule):
            raise MemoryError("transfer_output_conflict")
        records, _ = self.records_for_payload(payload, verify_signatures=False)
        with self._dependency_index().connect() as cache:
            DependencyIndex.published(cache, payload, digest, records)

    def _group_directory(self, group: Mapping[str, Any], *, incoming: bool = False) -> Path:
        return _path(self.state_directory / ("incoming-groups" if incoming else "outgoing-groups") / group["group_id"])

    def _make_group(self, records: Sequence[Mapping[str, Any]], proofs: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
        """Freeze a complete logical closure as independently verified fragments."""
        fragments: list[dict[str, Any]] = []
        contents: list[bytes] = []
        pending = bytearray()
        part_records = 0
        record_bytes = 0
        whole = hashlib.sha256()
        for record in records:
            record_bytes += len(canonical_bytes(record))
            line = canonical_bytes({"record": record, "attestation": proofs[record["memory_id"]]}) + b"\n"
            if len(line) > MAX_FRAGMENT_BYTES:
                raise MemoryError("group_record_too_large")
            if pending and len(pending) + len(line) > MAX_FRAGMENT_BYTES:
                data = bytes(pending)
                fragments.append({"index": len(fragments), "sha256": sha256(data), "bytes": len(data), "records": part_records})
                contents.append(data)
                pending.clear()
                part_records = 0
            pending.extend(line)
            part_records += 1
            whole.update(line)
        if pending:
            data = bytes(pending)
            fragments.append({"index": len(fragments), "sha256": sha256(data), "bytes": len(data), "records": part_records})
            contents.append(data)
        descriptor = {"schema_version": GROUP_SCHEMA, "record_count": len(records), "record_bytes": record_bytes,
                      "encoded_bytes": sum(fragment["bytes"] for fragment in fragments),
                      "records_sha256": whole.hexdigest(), "fragments": fragments}
        group = _group({**descriptor, "group_id": sha256(canonical_bytes(descriptor))})
        directory = self._group_directory(group)
        _private_directory(directory.parent)
        _private_directory(directory)
        for fragment, data in zip(fragments, contents):
            _write_fragment(directory / _fragment_name(fragment), data)
        return group

    def _fragment_records(
        self, fragment: Mapping[str, Any], data: bytes, *, verify_signatures: bool,
    ) -> list[tuple[dict[str, Any], Mapping[str, Any]]]:
        if len(data) != fragment["bytes"] or sha256(data) != fragment["sha256"] or not data.endswith(b"\n"):
            raise MemoryError("group_fragment_hash_mismatch")
        rows: list[tuple[dict[str, Any], Mapping[str, Any]]] = []
        for line in data.splitlines():
            rows.append(self._fragment_record(line, verify_signatures=verify_signatures))
        if len(rows) != fragment["records"]:
            raise MemoryError("group_record_count_mismatch")
        return rows

    def _fragment_record(self, line: bytes, *, verify_signatures: bool) -> tuple[dict[str, Any], Mapping[str, Any]]:
        value = strict_json_loads(line)
        if (not isinstance(value, dict) or set(value) != {"record", "attestation"}
                or not isinstance(value["attestation"], dict)
                or len(canonical_bytes(value["attestation"])) > 4096 or canonical_bytes(value) != line):
            raise MemoryError("invalid_group_record")
        record = validate_record(value["record"])
        if verify_signatures:
            self.trust.verify_record(record, value["attestation"])
        return record, value["attestation"]

    def _review_page(
        self, payload: Mapping[str, Any], offset: int, limit: int,
    ) -> tuple[list[Mapping[str, Any]], dict[str, Mapping[str, Any]], int]:
        if payload.get("group") is None:
            records = list(payload["records"])[offset:offset + limit]
            return records, {record["memory_id"]: payload["attestations"][record["memory_id"]] for record in records}, len(payload["records"])
        group = _group(payload["group"])
        records: list[Mapping[str, Any]] = []
        proofs: dict[str, Mapping[str, Any]] = {}
        ordinal = 0
        directory = self._group_directory(group)
        for fragment in group["fragments"]:
            start, end = max(0, offset - ordinal), min(fragment["records"], offset + limit - ordinal)
            ordinal += fragment["records"]
            if start >= end:
                continue
            data = _read_fragment(directory / _fragment_name(fragment))
            lines = data.splitlines()
            if (len(data) != fragment["bytes"] or sha256(data) != fragment["sha256"]
                    or not data.endswith(b"\n") or len(lines) != fragment["records"]):
                raise MemoryError("group_fragment_hash_mismatch")
            # The complete containing fragment hash is checked, but only this
            # requested page is parsed/verified. Review never repeatedly scans
            # a whole 64 MiB group merely to display another hundred IDs.
            for line in lines[start:end]:
                record, proof = self._fragment_record(line, verify_signatures=False)
                records.append(record)
                proofs[record["memory_id"]] = proof
        return records, proofs, group["record_count"]

    def records_for_payload(
        self, payload: Mapping[str, Any], *, incoming: bool = False,
        verify_signatures: bool = True,
    ) -> tuple[list[Mapping[str, Any]], dict[str, Mapping[str, Any]]]:
        """Materialize only a bounded, complete core-supported atomic group."""
        if payload.get("group") is None:
            return list(payload["records"]), dict(payload["attestations"])
        group = _group(payload["group"])
        directory = self._group_directory(group, incoming=incoming)
        records: list[Mapping[str, Any]] = []
        proofs: dict[str, Mapping[str, Any]] = {}
        whole = hashlib.sha256()
        total = 0
        for fragment in group["fragments"]:
            data = _read_fragment(directory / _fragment_name(fragment))
            whole.update(data)
            for record, proof in self._fragment_records(fragment, data, verify_signatures=verify_signatures):
                if record["memory_id"] in proofs:
                    raise MemoryError("duplicate_bundle_record")
                records.append(record)
                proofs[record["memory_id"]] = proof
                total += len(canonical_bytes(record))
                if total > group["record_bytes"] or len(records) > group["record_count"]:
                    raise MemoryError("group_content_mismatch")
        if len(records) != group["record_count"] or total != group["record_bytes"] or whole.hexdigest() != group["records_sha256"]:
            raise MemoryError("group_content_mismatch")
        return records, proofs

    def _group_file_valid(self, path: Path, fragment: Mapping[str, Any], receipt_path: Path) -> bool:
        if not path.exists() or not receipt_path.exists():
            return False
        info = _path(path).lstat()
        if not stat.S_ISREG(info.st_mode):
            raise MemoryError("invalid_group_fragment")
        fingerprint = [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns]
        receipt = _read(receipt_path, private=True)
        return receipt == {"sha256": fragment["sha256"], "bytes": fragment["bytes"], "fingerprint": fingerprint}

    def _record_group_file(self, path: Path, fragment: Mapping[str, Any], receipt_path: Path) -> None:
        info = path.lstat()
        _write(receipt_path, {"sha256": fragment["sha256"], "bytes": fragment["bytes"],
                             "fingerprint": [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns]}, replace=True)

    def publish_group_fragments(
        self, payload: Mapping[str, Any], *, maximum_fragments: int = 8,
        before_write: Callable[[int], None] | None = None,
    ) -> bool:
        if type(maximum_fragments) is not int or not 1 <= maximum_fragments <= MAX_GROUP_FRAGMENTS:
            raise MemoryError("invalid_fragment_limit")
        group = _group(payload["group"])
        source = self._group_directory(group)
        destination = _path(self.exchange / payload["sender_key_id"] / payload["source_store_id"] / "groups" / group["group_id"])
        if os.name == "nt":
            _private_directory(destination)
        else:
            destination.mkdir(parents=True, exist_ok=True, mode=0o700)
        receipts = _path(self.state_directory / "group-copy-receipts" / group["group_id"])
        _private_directory(receipts.parent)
        _private_directory(receipts)
        copied = 0
        for fragment in group["fragments"]:
            target = destination / _fragment_name(fragment)
            receipt = receipts / (str(fragment["index"]) + ".json")
            if self._group_file_valid(target, fragment, receipt):
                continue
            if copied >= maximum_fragments:
                return False
            if before_write is not None:
                before_write(fragment["bytes"])
            data = _read_fragment(source / _fragment_name(fragment))
            self._fragment_records(fragment, data, verify_signatures=False)
            _write_fragment(target, data, private=False)
            self._record_group_file(target, fragment, receipt)
            copied += 1
        return True

    def stage_group_fragments(
        self, payload: Mapping[str, Any], *, loader: Callable[[Mapping[str, Any], Mapping[str, Any]], bytes],
        maximum_fragments: int = 8,
    ) -> bool:
        """Stage resumably without admitting a partial dependency graph."""
        if type(maximum_fragments) is not int or not 1 <= maximum_fragments <= MAX_GROUP_FRAGMENTS:
            raise MemoryError("invalid_fragment_limit")
        group = _group(payload["group"])
        directory = self._group_directory(group, incoming=True)
        _private_directory(directory.parent)
        _private_directory(directory)
        copied = 0
        for fragment in group["fragments"]:
            target = directory / _fragment_name(fragment)
            receipt = directory / (str(fragment["index"]) + ".json")
            if self._group_file_valid(target, fragment, receipt):
                continue
            if copied >= maximum_fragments:
                return False
            data = loader(group, fragment)
            self._fragment_records(fragment, data, verify_signatures=True)
            _write_fragment(target, data)
            self._record_group_file(target, fragment, receipt)
            copied += 1
        return True

    def _admit_payload(self, payload: Mapping[str, Any], digest: str) -> Mapping[str, Any]:
        records, proofs = self.records_for_payload(payload, incoming=True)
        identifiers = {record["memory_id"] for record in records}
        closed = all(relation["target"] in identifiers for record in records for relation in record["relations"])
        if payload["schema_version"] == INCREMENTAL_DELTA_SCHEMA:
            if payload["dependency_mode"] == "closure" and not closed:
                raise MemoryError("incomplete_transfer_closure")
            self._dependency_history(payload)
            return ingest_verified(self.vault, self.trust, records, proofs, transfer_id="xfer_" + digest,
                                   payload_sha256=digest,
                                   previous_payload_sha256=payload["previous_batch_sha256"] if payload["after"] else None,
                                   index=self._dependency_index(create_vault=True))
        if closed:
            # Self-contained old batches seed current positive validation too,
            # so the first v3 continuation need not rescan a maximum-size base.
            return ingest_verified(self.vault, self.trust, records, proofs, transfer_id="xfer_" + digest,
                                   payload_sha256=digest, index=self._dependency_index(create_vault=True))
        # Core bounds, closure validation, current trust and idempotent receipt
        # all apply once to the complete group. No fragment is a partial import.
        return self.vault.ingest_records(records, admission="verified", attestations=proofs,
                                         transfer_id="xfer_" + digest, payload_sha256=digest)

    def _received_evidence(self, capsule: Mapping[str, Any], digest: str) -> None:
        """Retain the authenticated envelope needed to recover staged fragments.

        It is not a receive cursor, admission decision, or permission. A private
        backup must be able to authenticate a partial group's manifest without
        depending on an external exchange surviving unchanged.
        """
        if not _HASH.fullmatch(digest):
            raise MemoryError("invalid_transfer_digest")
        directory = _path(self.state_directory / "received-capsules")
        _private_directory(directory)
        _write(directory / (digest + ".json"), capsule, replace=False)

    def _review_directory(self, request_id: str) -> Path:
        if not isinstance(request_id, str) or not _REQUEST.fullmatch(request_id):
            raise MemoryError("invalid_request_id")
        return _path(self.state_directory / "publication-reviews" / sha256(request_id.encode("utf-8")))

    def _prefix_exposed(self, payload: Mapping[str, Any]) -> bool:
        """A started/exchange publication is immutable even after a crash.

        Local review never attempts to retract bytes from a shared directory or
        to infer that a remote AI did not consume them. A bounded scan also
        catches another locally published digest at the same stream prefix.
        """
        if self.started_path.exists():
            return True
        directory = _path(self.exchange / payload["sender_key_id"] / payload["source_store_id"])
        if not directory.exists():
            return False
        if not directory.is_dir():
            raise MemoryError("unsafe_transfer_path")
        with os.scandir(directory) as entries:
            for count, entry in enumerate(entries, 1):
                if count > MAX_DISCOVERY_FILES:
                    raise MemoryError("exchange_discovery_limit")
                match = _CAPSULE_NAME.fullmatch(entry.name)
                if match and int(match[1]) == payload["after"]:
                    return True  # Unknown bytes cannot authorize replacement.
        return False

    def review_pending(self, *, offset: int = 0, limit: int = 100) -> Mapping[str, Any]:
        """Pure read: no lock creation, database writes, private key or network.

        Instantiate this endpoint without ``identity`` on the read-only path.
        The exact payload hash is an optimistic concurrency token, not consent.
        """
        if (not isinstance(offset, int) or isinstance(offset, bool) or not 0 <= offset <= MAX_REVIEW_RECORDS
                or not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 256):
            raise MemoryError("invalid_review_page")
        state = self._state()
        if not self.pending_path.exists():
            return {"state": "nothing_pending", "records": [], "files_written": False,
                    "network_accessed": False, "memory_content_included": False}
        capsule = _read(self.pending_path, private=True)
        payload, digest = self._verify_capsule(capsule, verify_records=False)
        self._bind_vault(state, missing_ok=False)
        if (payload["source_store_id"] != state["vault_store_id"]
                or state["publisher_key_id"] not in {None, payload["sender_key_id"]}):
            raise MemoryError("pending_transfer_source_changed")
        from memory_vault_privacy import review_records
        records, proofs, record_count = self._review_page(payload, offset, limit)
        findings = review_records(records)
        records_by_id = {record["memory_id"]: record for record in records}
        with contextlib.closing(self.vault._connect(writable=False)) as connection:
            for finding in findings:
                dependents = [str(row[0]) for row in connection.execute(
                    "SELECT DISTINCT source_id FROM relations WHERE target_id=? ORDER BY source_id LIMIT 257", (finding["memory_id"],))]
                finding["dependent_ids"] = dependents[:256]
                finding["dependents_truncated"] = len(dependents) > 256
                finding["dependent_ids_scope"] = "canonical_vault_may_include_records_outside_this_batch"
                try:
                    self.trust.verify_record(records_by_id[finding["memory_id"]], proofs[finding["memory_id"]])
                    finding["signature_state"] = "verified_current_trust"
                except TrustError as exc:
                    finding["signature_state"] = exc.code
        rewritable = (payload["after"] == state["published_cursor"] and not self._prefix_exposed(payload))
        return {"state": "pending_review" if rewritable else "publication_started_not_rewritable",
                "batch_sha256": digest, "after": payload["after"], "cursor": payload["cursor"],
                "records": findings, "record_count": record_count,
                "offset": offset, "next_offset": offset + limit if offset + limit < record_count else None,
                "group_id": payload["group"]["group_id"] if payload.get("group") else None,
                "complete_group_verified": False if payload.get("group") else None,
                "blocked": payload["blocked"], "rewritable": rewritable,
                "files_written": False, "network_accessed": False,
                "memory_content_included": False, "review_is_authorization": False}

    def local_path_approvals(self, payload: Mapping[str, Any]) -> set[str]:
        """Accept only this endpoint's independent completed operator journal.

        A signed packet's review text alone confers no publication permission.
        Forwarding received memory makes a new packet and must be reviewed again.
        """
        review = payload.get("publication_review")
        if review is None:
            return set()
        directory = self._review_directory(review["request_id"])
        try:
            decision = _read(directory / "decision.json", maximum=MAX_REVIEW_DOCUMENT, private=True)
            completed = _read(directory / "completed.json", private=True)
        except FileNotFoundError:
            raise MemoryError("publication_review_incomplete") from None
        digest = sha256(canonical_bytes(payload))
        if (decision.get("schema_version") != DECISION_SCHEMA or decision.get("request_id") != review["request_id"]
                or decision.get("replacement_batch_sha256") != digest
                or decision.get("original_batch_sha256") != review["replaces_unpublished_batch_sha256"]
                or decision.get("source_store_id") != payload["source_store_id"]
                or decision.get("sender_key_id") != payload["sender_key_id"]
                or completed.get("decision_sha256") != sha256(canonical_bytes(decision))
                or completed.get("replacement_batch_sha256") != digest):
            raise MemoryError("publication_review_approval_mismatch")
        approved = self._review_ids(decision.get("approved_local_path_ids"))
        excluded = self._review_ids(decision.get("excluded_memory_ids"))
        retained = self._review_ids(decision.get("retained_memory_ids"))
        if (not approved <= retained or excluded & retained
                or len(excluded) != review["excluded_records"] or len(retained) != review["retained_records"]
                or sha256(canonical_bytes({"excluded": sorted(excluded), "retained": sorted(retained)})) != review["selection_sha256"]):
            raise MemoryError("publication_review_approval_mismatch")
        return approved

    def resolve_pending(
        self, *, batch_sha256: str, request_id: str,
        exclude: Sequence[str], keep: Sequence[str], allow_local_paths: bool = False,
    ) -> Mapping[str, Any]:
        """Explicitly replace only never-published pending bytes, with evidence.

        Every selected record must be explicitly kept or excluded. Dependencies
        cannot be implicitly discarded. Original/new signed bytes, decision and
        idempotent completion stay in a private audit directory. Canonical Vault
        records, published capsules and transfer cursors are never edited here.
        """
        if self.identity is None:
            raise MemoryError("publisher_identity_required")
        self.trust.require_trusted(self.identity.key_id)
        if not isinstance(batch_sha256, str) or not _HASH.fullmatch(batch_sha256) or type(allow_local_paths) is not bool:
            raise MemoryError("invalid_review_decision")
        excluded, retained = self._review_ids(exclude), self._review_ids(keep)
        if excluded & retained or len(excluded | retained) > MAX_REVIEW_RECORDS:
            raise MemoryError("invalid_review_partition")
        directory = self._review_directory(request_id)
        arguments = {"batch_sha256": batch_sha256, "excluded": sorted(excluded), "retained": sorted(retained),
                     "allow_local_paths": allow_local_paths}
        argument_digest = sha256(canonical_bytes(arguments))
        with _lock(self.state_directory):
            state = self._state()
            self._bind_vault(state, missing_ok=False)
            if state["publisher_key_id"] not in {None, self.identity.key_id}:
                raise MemoryError("publisher_identity_changed")
            intent_path = directory / "intent.json"
            if intent_path.exists():
                intent = _read(intent_path, private=True)
                if (intent.get("arguments_sha256") != argument_digest or intent.get("request_id") != request_id
                        or intent.get("source_store_id") != state["vault_store_id"]
                        or intent.get("sender_key_id") != self.identity.key_id):
                    raise MemoryError("request_id_conflict")
                if (directory / "completed.json").exists():
                    saved = _read(directory / "decision.json", maximum=MAX_REVIEW_DOCUMENT, private=True)
                    replacement_payload, _ = self._verify_capsule(_read(directory / "replacement.json", private=True), verify_records=False)
                    if saved.get("arguments_sha256") != argument_digest:
                        raise MemoryError("request_id_conflict")
                    self.local_path_approvals(replacement_payload)
                    result = dict(_read(directory / "completed.json", private=True))
                    result["receipt_replayed"] = True
                    return result
            if not self.pending_path.exists():
                raise MemoryError("review_pending_missing")
            pending = _read(self.pending_path, private=True)
            payload, current_digest = self._verify_capsule(pending, verify_records=False)
            if (payload["after"] != state["published_cursor"] or payload["source_store_id"] != state["vault_store_id"]
                    or payload["sender_key_id"] != self.identity.key_id or self._prefix_exposed(payload)):
                raise MemoryError("review_publication_already_started")
            decision_path = directory / "decision.json"
            if decision_path.exists():
                # Complete an interrupted atomic replacement without generating
                # new signatures or recomputing policy from changed data.
                decision = _read(decision_path, maximum=MAX_REVIEW_DOCUMENT, private=True)
                replacement = _read(directory / "replacement.json", private=True)
                _, replacement_digest = self._verify_capsule(replacement)
                if (decision.get("arguments_sha256") != argument_digest
                        or decision.get("replacement_batch_sha256") != replacement_digest
                        or current_digest not in {batch_sha256, replacement_digest}):
                    raise MemoryError("review_pending_changed")
            else:
                if current_digest != batch_sha256:
                    raise MemoryError("review_pending_changed")
                original_records, original_proofs = self.records_for_payload(payload, verify_signatures=False)
                records = {record["memory_id"]: record for record in original_records}
                if set(records) != excluded | retained:
                    raise MemoryError("review_requires_complete_partition")
                kept_records = [record for record in original_records if record["memory_id"] in retained]
                if any(relation["target"] in excluded for record in kept_records for relation in record["relations"]):
                    raise MemoryError("review_dependency_selection_conflict")
                from memory_vault_privacy import assert_publishable, review_records
                assert_publishable(kept_records, allow_local_paths=allow_local_paths)
                approved = sorted(finding["memory_id"] for finding in review_records(kept_records)
                                  if "publication_local_path_detected" in finding["reasons"])
                for record in kept_records:
                    self.trust.verify_record(record, original_proofs[record["memory_id"]])
                dispositions = {item["sequence"]: dict(item) for item in payload["blocked"]}
                # Only read immutable delivery roots. Dependencies outside this
                # cursor range remain explicitly listed in the signed review.
                with contextlib.closing(self.vault._connect(writable=False)) as connection:
                    for memory_id in sorted(excluded):
                        for row in connection.execute(
                            "SELECT sequence FROM delivery_log WHERE memory_id=? AND sequence>? AND sequence<=? ORDER BY sequence LIMIT ?",
                            (memory_id, payload["after"], payload["cursor"], MAX_REVIEW_RECORDS + 1),
                        ):
                            dispositions[int(row[0])] = {"memory_id": memory_id, "sequence": int(row[0]), "reason": "operator_excluded"}
                            if len(dispositions) > MAX_DISPOSITIONS:
                                raise MemoryError("publication_review_limit")
                previous_review = payload.get("publication_review")
                if previous_review is not None:
                    self.local_path_approvals(payload)  # Require the complete earlier decision, not just its text.
                previous_decision = (_read(self._review_directory(previous_review["request_id"]) / "decision.json",
                                           maximum=MAX_REVIEW_DOCUMENT, private=True) if previous_review is not None else {})
                all_excluded = excluded | set(previous_decision.get("excluded_memory_ids", []))
                if len(all_excluded | retained) > MAX_REVIEW_RECORDS or all_excluded & retained:
                    raise MemoryError("publication_review_limit")
                replacement_payload = {**payload, "schema_version": (INCREMENTAL_DELTA_SCHEMA
                    if payload["schema_version"] == INCREMENTAL_DELTA_SCHEMA else CHAINED_DELTA_SCHEMA),
                    "previous_batch_sha256": state["last_published"],
                    "records": kept_records, "attestations": {key: original_proofs[key] for key in sorted(retained)},
                    "blocked": [dispositions[key] for key in sorted(dispositions)],
                    "group": None,
                    "publication_review": {"schema_version": REVIEW_SCHEMA, "request_id": request_id,
                        "replaces_unpublished_batch_sha256": batch_sha256,
                        "selection_sha256": sha256(canonical_bytes({"excluded": sorted(all_excluded), "retained": sorted(retained)})),
                        "excluded_records": len(all_excluded), "retained_records": len(retained)}}
                if (len(kept_records) > 1024 or len(canonical_bytes(replacement_payload)) > MAX_CAPSULE_BYTES - 4096):
                    replacement_payload["group"] = self._make_group(kept_records, replacement_payload["attestations"])
                    replacement_payload["records"], replacement_payload["attestations"] = [], {}
                replacement = {"payload": replacement_payload, "proof": dict(self.identity.sign_message(replacement_payload))}
                _, replacement_digest = self._verify_capsule(replacement)
                decision = {"schema_version": DECISION_SCHEMA, "request_id": request_id,
                    "arguments_sha256": argument_digest, "source_store_id": payload["source_store_id"],
                    "sender_key_id": payload["sender_key_id"], "original_batch_sha256": batch_sha256,
                    "replacement_batch_sha256": replacement_digest, "approved_local_path_ids": approved,
                    "excluded_memory_ids": sorted(all_excluded), "retained_memory_ids": sorted(retained),
                    "canonical_memory_changed": False, "publication_authorized_by_memory": False}
                _private_directory(directory.parent)
                _private_directory(directory)
                _write(intent_path, {"request_id": request_id, "arguments_sha256": argument_digest,
                                     "source_store_id": state["vault_store_id"], "sender_key_id": self.identity.key_id}, replace=False)
                _write(directory / "original.json", pending, replace=False)
                _write(directory / "replacement.json", replacement, replace=False)
                _write(decision_path, decision, replace=False, maximum=MAX_REVIEW_DOCUMENT)
            if current_digest == batch_sha256:
                _write(self.pending_path, replacement, replace=True)
            completed = {"state": "publication_review_applied", "request_id": request_id,
                "decision_sha256": sha256(canonical_bytes(decision)), "original_batch_sha256": batch_sha256,
                "replacement_batch_sha256": replacement_digest,
                "excluded_records": len(decision["excluded_memory_ids"]), "retained_records": len(retained),
                "canonical_memory_changed": False, "published": False, "network_accessed": False,
                "remote_ai_read_verified": False, "receipt_replayed": False}
            _write(directory / "completed.json", completed, replace=False)
            return completed

    def publish(
        self, *, limit: int = 100, maximum_bytes: int = 256 * 1024,
        attest_unsigned: bool = False,
        publication_guard: Callable[[Sequence[Mapping[str, Any]]], None] | None = None,
        capsule_guard: Callable[[Mapping[str, Any]], None] | None = None,
        before_fragment_write: Callable[[int], None] | None = None,
        maximum_fragments: int = 8,
    ) -> Mapping[str, Any]:
        if self.identity is None:
            raise MemoryError("publisher_identity_required")
        self.trust.require_trusted(self.identity.key_id)
        with _lock(self.state_directory):
            state = self._state()
            self._bind_vault(state, missing_ok=False)
            if state["publisher_key_id"] not in {None, self.identity.key_id}:
                raise MemoryError("publisher_identity_changed")
            state["publisher_key_id"] = self.identity.key_id
            if not self.pending_path.exists() and self.started_path.exists():
                started = _read(self.started_path, private=True)
                if started != {"batch_sha256": state["last_published"], "cursor": state["published_cursor"]}:
                    raise MemoryError("publication_state_incomplete")
                self.started_path.unlink()  # Completed redundant marker only.
            if self.pending_path.exists():
                capsule = _read(self.pending_path, private=True)
                payload, digest = self._verify_capsule(capsule, verify_records=False)
                if payload["sender_key_id"] != self.identity.key_id or payload["source_store_id"] != state["vault_store_id"]:
                    raise MemoryError("pending_transfer_source_changed")
                if payload["cursor"] == state["published_cursor"] and digest == state["last_published"]:
                    if self.started_path.exists():
                        started = _read(self.started_path, private=True)
                        if started != {"batch_sha256": digest, "cursor": payload["cursor"]}:
                            raise MemoryError("publication_state_incomplete")
                    self._record_published(capsule, digest)
                    self.pending_path.unlink()  # Already durable; only the redundant pending copy.
                    if self.started_path.exists():
                        self.started_path.unlink()
                    return {"state": "published", "recovered_receipt": True,
                            "records": payload["group"]["record_count"] if payload.get("group") else len(payload["records"]), "network_accessed": False}
                if payload["after"] != state["published_cursor"]:
                    raise MemoryError("pending_transfer_cursor_changed")
                try:
                    self._verify_capsule(capsule)
                except TrustError:
                    raise MemoryError("pending_trust_changed") from None
            else:
                directory = _path(self.exchange / self.identity.key_id / str(state["vault_store_id"]))
                if not self.state_path.exists() and directory.is_dir():
                    with os.scandir(directory) as existing:
                        if any(_CAPSULE_NAME.fullmatch(entry.name) for entry in existing):
                            raise MemoryError("publisher_state_missing")
                if not attest_unsigned:
                    delta = incremental_changes(self.vault, self.trust, self._dependency_index(),
                                                sender_key_id=self.identity.key_id, store_id=state["vault_store_id"],
                                                after=state["published_cursor"], previous_digest=state["last_published"],
                                                limit=limit, maximum_bytes=maximum_bytes)
                else:
                    result = self.vault.handle({"op": "changes", "after": state["published_cursor"], "store_id": state["vault_store_id"],
                                                "limit": limit, "maximum_bytes": maximum_bytes, "require_verified": False})
                    if not result["ok"]:
                        raise MemoryError(str(result["error"]["code"]))
                    delta = result["result"]
                    if any(item["reason"] == "dependency_budget_exceeded" for item in delta["blocked"]):
                        delta = self.vault.transfer_changes(after=state["published_cursor"], store_id=state["vault_store_id"],
                                                            limit=limit, require_verified=False)
                if delta["cursor"] == delta["after"]:
                    _write(self.state_path, state, replace=True)
                    return {"state": "up_to_date", "records": 0, "network_accessed": False}
                proofs = dict(delta["attestations"])
                for record in delta["records"]:
                    memory_id = str(record["memory_id"])
                    if memory_id not in proofs:
                        if not attest_unsigned:
                            raise MemoryError("unsigned_record_requires_explicit_attestation")
                        proofs[memory_id] = dict(self.identity.sign_record(record))
                    self.trust.verify_record(record, proofs[memory_id])
                payload = {"schema_version": CHAINED_DELTA_SCHEMA, "source_store_id": delta["store_id"], "sender_key_id": self.identity.key_id,
                           "after": delta["after"], "cursor": delta["cursor"], "records": delta["records"], "attestations": proofs,
                           "blocked": delta["blocked"], "previous_batch_sha256": state["last_published"], "publication_review": None, "group": None}
                if not delta["dependency_closure_included"]:
                    payload.update(schema_version=INCREMENTAL_DELTA_SCHEMA, dependency_mode="prior_stream")
                if len(payload["records"]) > 1024 or len(canonical_bytes(payload)) > MAX_CAPSULE_BYTES - 4096:
                    payload["group"] = self._make_group(payload["records"], proofs)
                    payload["records"], payload["attestations"] = [], {}
                capsule = {"payload": payload, "proof": dict(self.identity.sign_message(payload))}
                _, digest = self._verify_capsule(capsule)
                # Save the exact signed bytes before delivery so a crash cannot
                # turn a retry into a different batch with the same cursor.
                _write(self.pending_path, capsule, replace=False)
            # A full client can enforce an outbound privacy policy without
            # turning local memory storage into a publication permission.
            # Keep exact pending bytes and the old cursor if review blocks it.
            self.validate_outgoing_payload(payload)
            if payload.get("publication_review") is not None:
                self.local_path_approvals(payload)  # Incomplete operator decisions cannot escape.
            if capsule_guard is not None:
                capsule_guard(payload)
            elif publication_guard is not None:
                publication_guard(self.records_for_payload(payload)[0])
            # This journal closes the crash gap between review and shared-folder
            # publication. Even if the output later disappears, it is never
            # safe to rewrite this prefix as if nobody had seen its bytes.
            _write(self.started_path, {"batch_sha256": digest, "cursor": payload["cursor"]}, replace=False)
            if payload.get("group") is not None:
                if not self.publish_group_fragments(payload, maximum_fragments=maximum_fragments, before_write=before_fragment_write):
                    return {"state": "group_publication_pending", "records": payload["group"]["record_count"],
                            "group_id": payload["group"]["group_id"], "cursor_advanced": False,
                            "batch_sha256": digest, "network_accessed": False}
            if os.name == "nt":
                if not self.exchange.exists():
                    _private_directory(self.exchange)
            else:
                self.exchange.mkdir(parents=True, exist_ok=True, mode=0o700)
            directory = _path(self.exchange / self.identity.key_id / str(payload["source_store_id"]))
            if os.name == "nt":
                _private_directory(directory)
            else:
                directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            destination = directory / f"{payload['after']:020d}-{payload['cursor']:020d}-{digest}.json"
            _write(destination, capsule, replace=False, private=False)
            self._record_published(capsule, digest)
            state["published_cursor"] = payload["cursor"]
            state["last_published"] = digest
            _write(self.state_path, state, replace=True)
            self.pending_path.unlink()
            self.started_path.unlink()
            return {"state": "published_with_blocked" if payload["blocked"] else "published",
                    "records": payload["group"]["record_count"] if payload.get("group") else len(payload["records"]),
                    "cursor": payload["cursor"], "blocked": payload["blocked"],
                    "batch_sha256": digest, "network_accessed": False}

    def receive_capsule(
        self, capsule: Mapping[str, Any], *, sender_key_id: str,
        source_store_id: str, after: int,
        fragment_loader: Callable[[Mapping[str, Any], Mapping[str, Any]], bytes] | None = None,
        maximum_fragments: int = 8,
        active_check: Callable[[], None] | None = None,
        on_progress: Callable[[Mapping[str, Any]], None] | None = None,
    ) -> Mapping[str, Any]:
        """Admit one explicitly fetched signed prefix, never a directory trust hint.

        A bounded remote adapter must establish that no other authenticated
        candidate exists at this prefix before calling this method. An explicit
        bounded fragment loader may do remote reads while the nonblocking local
        transfer lock prevents another receiver from committing the same prefix.
        Optional trusted in-process checks revalidate the current operation
        before admission. The progress observer receives one content-free
        per-capsule receipt after durable admission, before a separate head write
        can fail; consumers must not count it again on normal return. Neither
        callback is supplied by the received memory or a wire message.
        """
        if active_check is not None:
            active_check()
        with _lock(self.state_directory):
            state = self._state()
            self._bind_vault(state, missing_ok=True)
            payload, digest = self._verify_capsule(capsule)
            peer = sender_key_id + "/" + source_store_id
            if (payload["sender_key_id"] != sender_key_id
                    or payload["source_store_id"] != source_store_id
                    or payload["after"] != after):
                raise MemoryError("receive_cursor_changed")
            head = state["received_heads"].get(peer)
            if (head is not None and head["batch_sha256"] == digest
                    and head["after"] == payload["after"] and head["cursor"] == payload["cursor"]):
                # An already committed last head needs no fragments or writes.
                # Require the separate atomic core receipt, not a cursor alone.
                with contextlib.closing(self.vault._connect(writable=False)) as connection:
                    row = connection.execute("SELECT payload_sha256 FROM transfer_receipts WHERE transfer_id=?", ("xfer_" + digest,)).fetchone()
                if row is None or row[0] != digest:
                    raise MemoryError("receive_receipt_missing")
                result = {"state": "received", "records_added": 0, "receipt_replayed": True,
                          "blocked_records": len(payload["blocked"]), "cursor": payload["cursor"]}
                if active_check is not None:
                    active_check()
                if on_progress is not None:
                    on_progress(dict(result))
                return result
            if int(state["received"].get(peer, 0)) != after:
                raise MemoryError("receive_cursor_changed")
            if peer not in state["received"] and len(state["received"]) >= MAX_PEERS:
                raise MemoryError("too_many_transfer_peers")
            self._check_chain(state, payload)
            self._received_evidence(capsule, digest)
            if payload.get("group") is not None:
                if fragment_loader is None:
                    raise MemoryError("group_fragment_loader_required")
                if not self.stage_group_fragments(payload, loader=fragment_loader, maximum_fragments=maximum_fragments):
                    return {"state": "group_receiving_pending", "records_added": 0, "receipt_replayed": False,
                            "blocked_records": len(payload["blocked"]), "cursor": after,
                            "group_id": payload["group"]["group_id"], "cursor_advanced": False}
            # The final provider read/fragment validation can outlive the last
            # command-level permission check. Recheck this local operation,
            # including cancellation and its shared budget, before admission.
            if active_check is not None:
                active_check()
            admitted = self._admit_payload(payload, digest)
            result = {"state": "received", "records_added": int(admitted["records_added"]),
                      "receipt_replayed": bool(admitted.get("receipt_replayed", False)),
                      "blocked_records": len(payload["blocked"]), "cursor": payload["cursor"]}
            if on_progress is not None:
                on_progress(dict(result))
            self._bind_vault(state, missing_ok=False)
            self._remember_head(state, payload, digest)
            _write(self.state_path, state, replace=True)
            return result

    def acknowledge_published(self) -> Mapping[str, Any]:
        """Explicit crash recovery: acknowledge an identical, already present file.

        It neither republishes a now-untrusted record nor changes key trust. If
        the file is absent, uncertainty is retained for operator reconciliation.
        """
        with _lock(self.state_directory):
            state = self._state()
            self._bind_vault(state, missing_ok=False)
            capsule = _read(self.pending_path, private=True)
            payload, digest = self._verify_capsule(capsule, verify_records=False)
            if payload["source_store_id"] != state["vault_store_id"] or state["publisher_key_id"] not in {None, payload["sender_key_id"]}:
                raise MemoryError("pending_transfer_source_changed")
            if state["published_cursor"] not in {payload["after"], payload["cursor"]}:
                raise MemoryError("pending_transfer_cursor_changed")
            if state["published_cursor"] == payload["cursor"] and state["last_published"] != digest:
                raise MemoryError("pending_transfer_receipt_conflict")
            directory = _path(self.exchange / payload["sender_key_id"] / payload["source_store_id"])
            destination = directory / f"{payload['after']:020d}-{payload['cursor']:020d}-{digest}.json"
            if canonical_bytes(_read(destination)) != canonical_bytes(capsule):
                raise MemoryError("transfer_output_conflict")
            self._record_published(capsule, digest)
            if self.started_path.exists():
                started = _read(self.started_path, private=True)
                if started != {"batch_sha256": digest, "cursor": payload["cursor"]}:
                    raise MemoryError("publication_state_incomplete")
            state["publisher_key_id"] = payload["sender_key_id"]
            state["published_cursor"] = payload["cursor"]
            state["last_published"] = digest
            _write(self.state_path, state, replace=True)
            self.pending_path.unlink()
            if self.started_path.exists():
                self.started_path.unlink()
            return {"state": "publication_acknowledged", "records_republished": 0, "network_accessed": False}

    def anchor_received(self, capsule: Mapping[str, Any]) -> Mapping[str, Any]:
        """Bind a v0.24 receipt to its exact historical signed capsule.

        This explicit compatibility repair never accepts new memory or an
        unobserved remote claim. The existing atomic Vault receipt must prove
        that this exact payload was already ingested at the saved cursor.
        """
        with _lock(self.state_directory):
            state = self._state()
            self._bind_vault(state, missing_ok=False)
            payload, digest = self._verify_capsule(capsule, verify_records=False)
            peer = payload["sender_key_id"] + "/" + payload["source_store_id"]
            if state["received"].get(peer) != payload["cursor"]:
                raise MemoryError("history_anchor_cursor_mismatch")
            with contextlib.closing(self.vault._connect(writable=False)) as connection:
                row = connection.execute("SELECT payload_sha256 FROM transfer_receipts WHERE transfer_id=?", ("xfer_" + digest,)).fetchone()
            if row is None or row[0] != digest:
                raise MemoryError("history_anchor_receipt_missing")
            self._received_evidence(capsule, digest)
            old = state["received_heads"].get(peer)
            new = {"after": payload["after"], "cursor": payload["cursor"], "batch_sha256": digest,
                   "chained": payload["schema_version"] in _CHAINED_SCHEMAS}
            if old is not None and old != new:
                raise MemoryError("history_anchor_conflict")
            state["received_heads"][peer] = new
            _write(self.state_path, state, replace=True)
            return {"state": "history_anchored_from_existing_receipt", "batch_sha256": digest,
                    "memory_records_added": 0, "network_accessed": False, "receipt_replayed": old == new}

    def receive(
        self, *, maximum_batches: int = 16,
        active_check: Callable[[], None] | None = None,
        before_read: Callable[[], None] | None = None,
        before_fragment_read: Callable[[int], None] | None = None,
        skip_local_stream: bool = False,
        maximum_fragments: int = 8,
        on_progress: Callable[[Mapping[str, Any]], None] | None = None,
    ) -> Mapping[str, Any]:
        """Receive bounded batches, optionally reporting durable local progress.

        ``on_progress`` receives cumulative content-free report snapshots after
        successful Vault admission/receipt persistence, before the separate
        stream-head write or another read can fail. It is a trusted in-process
        observer, never an incoming-memory callback or authorization surface.
        The final report can include additional rejections/discovery results;
        callers consuming both must aggregate deltas, not add both totals.
        """
        if not isinstance(maximum_batches, int) or isinstance(maximum_batches, bool) or not 1 <= maximum_batches <= 256:
            raise MemoryError("invalid_limit")
        if type(maximum_fragments) is not int or not 1 <= maximum_fragments <= MAX_GROUP_FRAGMENTS:
            raise MemoryError("invalid_fragment_limit")
        report: dict[str, Any] = {"state": "received", "batches": 0, "records_added": 0, "unknown_senders": 0,
                                  "gaps": 0, "rejected": [], "sender_blocked_records": 0,
                                  "receipt_replays": 0, "groups_pending": 0, "network_accessed": False}
        candidate_checks = 0
        with _lock(self.state_directory):
            state = self._state()
            self._bind_vault(state, missing_ok=True)
            if not self.exchange.is_dir():
                raise MemoryError("exchange_directory_missing")
            peers: list[tuple[str, str, Path]] = []
            entries_seen = 0
            with os.scandir(self.exchange) as senders:
                for sender in senders:
                    if active_check is not None:
                        active_check()
                    entries_seen += 1
                    if entries_seen > MAX_DISCOVERY_FILES:
                        raise MemoryError("exchange_discovery_limit")
                    if not _KEY.fullmatch(sender.name) or not sender.is_dir(follow_symlinks=False):
                        continue
                    try:
                        self.trust.require_trusted(sender.name)
                    except TrustError:
                        report["unknown_senders"] += 1
                        continue
                    with os.scandir(sender.path) as stores:
                        for store in stores:
                            if active_check is not None:
                                active_check()
                            entries_seen += 1
                            if entries_seen > MAX_DISCOVERY_FILES:
                                raise MemoryError("exchange_discovery_limit")
                            if _STORE.fullmatch(store.name) and store.is_dir(follow_symlinks=False):
                                local_sender = self.identity.key_id if self.identity is not None else state["publisher_key_id"]
                                if (skip_local_stream and sender.name == local_sender
                                        and store.name == state["vault_store_id"]):
                                    continue
                                peers.append((sender.name, store.name, Path(store.path)))
                                if len(peers) > MAX_PEERS:
                                    raise MemoryError("too_many_transfer_peers")
            for sender, store, directory in sorted(peers):
                peer = sender + "/" + store
                if peer not in state["received"] and len(state["received"]) >= MAX_PEERS:
                    raise MemoryError("too_many_transfer_peers")
                candidates: dict[int, list[tuple[int, str, Path]]] = {}
                with os.scandir(directory) as entries:
                    for entry in entries:
                        if active_check is not None and entries_seen % 64 == 0:
                            active_check()
                        entries_seen += 1
                        if entries_seen > MAX_DISCOVERY_FILES:
                            raise MemoryError("exchange_discovery_limit")
                        match = _CAPSULE_NAME.fullmatch(entry.name)
                        if match and entry.is_file(follow_symlinks=False):
                            candidates.setdefault(int(match[1]), []).append((int(match[2]), match[3], Path(entry.path)))
                expected = int(state["received"].get(peer, 0))
                head = state["received_heads"].get(peer)
                if head is not None:
                    observed: set[str] = set()
                    for cursor, digest, path in sorted(candidates.get(head["after"], [])):
                        if active_check is not None:
                            active_check()
                        candidate_checks += 1
                        if candidate_checks > 256:
                            report["more_possible"] = True
                            report["candidate_limit_reached"] = True
                            return report
                        if before_read is not None:
                            before_read()
                        try:
                            historical, actual = self._verify_capsule(_read(path), verify_records=False)
                            if (actual == digest and historical["sender_key_id"] == sender and historical["source_store_id"] == store
                                    and historical["after"] == head["after"] and historical["cursor"] == cursor):
                                observed.add(digest)
                        except (MemoryError, TrustError, OSError):
                            continue
                    if observed != {head["batch_sha256"]}:
                        if len(report["rejected"]) < 32:
                            report["rejected"].append({"code": "authenticated_stream_fork" if len(observed) > 1 else "remote_history_missing_or_changed",
                                                       "batch_sha256": head["batch_sha256"]})
                        continue
                while True:
                    group = candidates.get(expected, [])
                    if not group:
                        if any(after > expected for after in candidates):
                            report["gaps"] += 1
                        break  # Never skip a missing authenticated prefix.
                    authenticated: dict[str, tuple[Mapping[str, Any], Mapping[str, Any]]] = {}
                    for cursor, digest, path in sorted(group):
                        if active_check is not None:
                            active_check()
                        candidate_checks += 1
                        if candidate_checks > 256:
                            report["more_possible"] = True
                            report["candidate_limit_reached"] = True
                            return report
                        if before_read is not None:
                            before_read()  # Budget failures are not malformed-peer rejections.
                        try:
                            capsule = _read(path)
                            payload, actual_digest = self._verify_capsule(capsule)
                            if (actual_digest != digest or payload["sender_key_id"] != sender or payload["source_store_id"] != store
                                    or payload["after"] != expected or payload["cursor"] != cursor):
                                raise MemoryError("transfer_envelope_mismatch")
                        except (MemoryError, TrustError, OSError) as exc:
                            if len(report["rejected"]) < 32:
                                report["rejected"].append({"batch_sha256": digest, "code": getattr(exc, "code", "transfer_file_unavailable")})
                            # An unauthenticated filename cannot decide which
                            # trusted batch is next. Keep checking this prefix.
                            continue
                        authenticated[digest] = (payload, capsule)
                    if not authenticated:
                        break
                    if len(authenticated) != 1:
                        report["rejected"].append({"code": "authenticated_stream_fork"})
                        break  # A real signed fork needs operator resolution.
                    digest, (payload, capsule) = next(iter(authenticated.items()))
                    cursor = int(payload["cursor"])
                    try:
                        self._check_chain(state, payload)
                        self._received_evidence(capsule, digest)
                        if payload.get("group") is not None:
                            def loader(group: Mapping[str, Any], fragment: Mapping[str, Any]) -> bytes:
                                if active_check is not None:
                                    active_check()
                                if before_fragment_read is not None:
                                    before_fragment_read(fragment["bytes"])
                                elif before_read is not None:
                                    before_read()
                                return _read_fragment(_path(directory / "groups" / group["group_id"] / _fragment_name(fragment)), maximum=fragment["bytes"])
                            if not self.stage_group_fragments(payload, loader=loader, maximum_fragments=maximum_fragments):
                                report["groups_pending"] += 1
                                report["more_possible"] = True
                                break
                        if active_check is not None:
                            active_check()
                        result = self._admit_payload(payload, digest)
                    except (MemoryError, TrustError) as exc:
                        if exc.code.startswith("sync_"):
                            raise  # Work-budget exhaustion leaves the group pending.
                        if len(report["rejected"]) < 32:
                            report["rejected"].append({"batch_sha256": digest, "code": exc.code})
                        break  # Leave evidence available for explicit inspection/retry.
                    report["batches"] += 1
                    report["records_added"] += int(result["records_added"])
                    report["sender_blocked_records"] += len(payload["blocked"])
                    report["receipt_replays"] += int(bool(result.get("receipt_replayed", False)))
                    if on_progress is not None:
                        on_progress({**report, "rejected": [dict(item) for item in report["rejected"]]})
                    # Local control-state failures after admission are not
                    # malformed-peer rejections. Preserve the durable count and
                    # let the caller report the error; the atomic Vault receipt
                    # makes a later retry safe even if this head was not saved.
                    self._bind_vault(state, missing_ok=False)
                    self._remember_head(state, payload, digest)
                    _write(self.state_path, state, replace=True)
                    expected = cursor
                    if report["batches"] >= maximum_batches:
                        report["more_possible"] = True
                        return report
            _write(self.state_path, state, replace=True)
        report.setdefault("more_possible", False)
        return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("publish", "receive", "acknowledge-published", "review", "resolve", "anchor"))
    parser.add_argument("--vault", type=Path, required=True)
    parser.add_argument("--exchange", type=Path, required=True)
    parser.add_argument("--state-directory", type=Path, required=True)
    parser.add_argument("--trust-store", type=Path, required=True)
    parser.add_argument("--identity", type=Path)
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--maximum-bytes", type=int, default=256 * 1024)
    parser.add_argument("--maximum-batches", type=int, default=16)
    parser.add_argument("--attest-unsigned", action="store_true", help="explicitly attest exact unsigned bytes as the publisher, not as their original author")
    parser.add_argument("--offset", type=int, default=0)
    parser.add_argument("--batch-sha256")
    parser.add_argument("--request-id")
    parser.add_argument("--exclude", nargs="*", default=[])
    parser.add_argument("--keep", nargs="*", default=[])
    parser.add_argument("--allow-local-paths", action="store_true", help="operator-only exact reviewed batch allowance; never bypass secret checks")
    parser.add_argument("--capsule", type=Path, help="exact previously received capsule for an explicit legacy history anchor")
    args = parser.parse_args(argv)
    try:
        endpoint = DirectoryTransfer(vault=args.vault, exchange=args.exchange, state_directory=args.state_directory,
                                     trust_store=args.trust_store, identity=None if args.action in {"review", "anchor", "receive"} else args.identity)
        if args.action == "publish":
            result = endpoint.publish(limit=args.limit, maximum_bytes=args.maximum_bytes, attest_unsigned=args.attest_unsigned)
        elif args.action == "receive":
            if args.attest_unsigned:
                raise MemoryError("attestation_requires_publish")
            result = endpoint.receive(maximum_batches=args.maximum_batches)
        elif args.action == "review":
            result = endpoint.review_pending(offset=args.offset, limit=args.limit)
        elif args.action == "resolve":
            result = endpoint.resolve_pending(batch_sha256=args.batch_sha256, request_id=args.request_id,
                                              exclude=args.exclude, keep=args.keep, allow_local_paths=args.allow_local_paths)
        elif args.action == "anchor":
            if args.capsule is None:
                raise MemoryError("history_anchor_capsule_required")
            result = endpoint.anchor_received(_read(_path(args.capsule)))
        else:
            if args.attest_unsigned:
                raise MemoryError("attestation_requires_publish")
            result = endpoint.acknowledge_published()
        write_response(success(result))
        return 0
    except (MemoryError, TrustError) as exc:
        write_response(failure(exc.code, retryable=getattr(exc, "retryable", False)))
    except (OSError, ValueError):
        write_response(failure("transfer_unavailable"))
    except Exception:
        write_response(failure("transfer_unavailable"))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
