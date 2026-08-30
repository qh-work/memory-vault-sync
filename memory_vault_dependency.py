"""Bounded, independently verified dependency reuse for signed transfer.

This optional module never changes canonical memory or grants authority. Its
private SQLite index is disposable: only actual published members may shorten
an outgoing closure; an incoming closure is verified against the actual Vault
inside the atomic admission transaction. A trust-policy digest plus SQL-backed
invalidation epoch makes a historical validation reusable, not permanent trust.
"""
from __future__ import annotations

import contextlib
import os
from pathlib import Path
import re
import sqlite3
from typing import Any, Iterator, Mapping, Sequence

from memory_vault import MAX_BUNDLE_BYTES, MAX_BUNDLE_RECORDS, MemoryError, Vault, canonical_bytes, sha256, strict_json_loads
import memory_vault_storage as storage
from memory_vault_trust import TrustStore


INDEX_SCHEMA = "universal-memory-dependency-index/v1"
MAX_INDEX_BYTES = 512 * 1024 * 1024
_SCHEMA = {
    "metadata": "CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL)",
    "heads": "CREATE TABLE heads(stream TEXT PRIMARY KEY,cursor INTEGER NOT NULL,digest TEXT NOT NULL)",
    "members": "CREATE TABLE members(stream TEXT NOT NULL,memory_id TEXT NOT NULL,record_sha256 TEXT NOT NULL,PRIMARY KEY(stream,memory_id))",
    "validations": "CREATE TABLE validations(memory_id TEXT PRIMARY KEY,record_sha256 TEXT NOT NULL,epoch TEXT NOT NULL,trust_sha256 TEXT NOT NULL)",
}


def _trust_digest(trust: TrustStore) -> str:
    # _read validates the independently provisioned protected registry; incoming
    # keys, caller-provided revisions and remembered text are never this policy.
    return sha256(canonical_bytes(trust._read()))


class DependencyIndex:
    """Private positive-member/validation cache, bound to one Vault and output.

    There are no memory bodies, keys or authorization decisions in this index.
    No caller should restore it as live state or use it as a received receipt.
    Connections are scoped to a single bounded operation, not a daemon.
    """

    def __init__(self, path: Path, *, store_id: str, destination: str):
        if not path.is_absolute() or ".." in path.parts or re.fullmatch(r"store_[0-9a-f]{32}", store_id) is None:
            raise MemoryError("invalid_dependency_index")
        self.path = path
        self.binding = sha256(canonical_bytes({"store_id": store_id, "destination": destination}))

    @contextlib.contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection: sqlite3.Connection | None = None
        descriptor: int | None = None
        try:
            storage.private_directory(self.path.parent, create=True)
            try:
                descriptor = storage.open_file(self.path, os.O_RDWR | os.O_CREAT | os.O_EXCL, private=True)
            except FileExistsError:
                descriptor = storage.open_file(self.path, os.O_RDWR, private=True)
            if os.fstat(descriptor).st_size > MAX_INDEX_BYTES:
                raise MemoryError("dependency_index_limit")
            for suffix in ("-journal", "-wal", "-shm"):
                sidecar = Path(str(self.path) + suffix)
                if sidecar.exists():
                    checked = storage.open_file(sidecar, os.O_RDONLY, private=True)
                    os.close(checked)
            connection = sqlite3.connect(str(self.path), timeout=5.0)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA busy_timeout=5000")
            connection.execute("PRAGMA synchronous=FULL")
            page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
            connection.execute("PRAGMA max_page_count=" + str(MAX_INDEX_BYTES // page_size))
            objects = {str(row[0]): str(row[1]) for row in connection.execute(
                "SELECT name,sql FROM sqlite_master WHERE sql IS NOT NULL LIMIT 5"
            )}
            if not objects:
                with connection:
                    connection.execute("BEGIN IMMEDIATE")
                    for statement in _SCHEMA.values():
                        connection.execute(statement)
                    connection.executemany("INSERT INTO metadata(key,value) VALUES(?,?)",
                                           (("schema", INDEX_SCHEMA), ("binding", self.binding)))
            elif objects != _SCHEMA:
                raise MemoryError("unsupported_dependency_index")
            metadata = {str(row[0]): str(row[1]) for row in connection.execute("SELECT key,value FROM metadata LIMIT 3")}
            if metadata != {"schema": INDEX_SCHEMA, "binding": self.binding}:
                raise MemoryError("dependency_index_binding_changed")
            yield connection
        except storage.StorageError as exc:
            raise MemoryError(exc.code, retryable=exc.retryable) from None
        except sqlite3.Error:
            raise MemoryError("dependency_index_unavailable", retryable=True) from None
        finally:
            if connection is not None:
                connection.close()
            if descriptor is not None:
                os.close(descriptor)

    @staticmethod
    def head_matches(connection: sqlite3.Connection, stream: str, cursor: int, digest: str | None) -> bool:
        row = connection.execute("SELECT cursor,digest FROM heads WHERE stream=?", (stream,)).fetchone()
        return row is not None and row["cursor"] == cursor and row["digest"] == digest

    @staticmethod
    def published(connection: sqlite3.Connection, payload: Mapping[str, Any], digest: str,
                  records: Sequence[Mapping[str, Any]]) -> None:
        """Called only after exact immutable output publication was confirmed.

        A missing index starts a sparse positive inventory from this actual
        batch, never guesses earlier members. A mismatching surviving head is
        not silently reset. Replaying the same publication is idempotent.
        """
        stream = payload["sender_key_id"] + "/" + payload["source_store_id"]
        with connection:
            connection.execute("BEGIN IMMEDIATE")
            old = connection.execute("SELECT cursor,digest FROM heads WHERE stream=?", (stream,)).fetchone()
            if old is not None and not (
                (old["cursor"] == payload["cursor"] and old["digest"] == digest)
                or (old["cursor"] == payload["after"] and (old["digest"] == payload.get("previous_batch_sha256")
                    or payload["schema_version"] == "universal-memory-delta/v1"))
            ):
                raise MemoryError("dependency_frontier_incomplete")
            if old is None and connection.execute("SELECT 1 FROM members WHERE stream=? LIMIT 1", (stream,)).fetchone():
                raise MemoryError("dependency_frontier_incomplete")
            for record in records:
                previous = connection.execute("SELECT record_sha256 FROM members WHERE stream=? AND memory_id=?",
                                              (stream, record["memory_id"])).fetchone()
                if previous is not None and previous[0] != record["record_sha256"]:
                    raise MemoryError("memory_identity_conflict")
                connection.execute("INSERT OR IGNORE INTO members(stream,memory_id,record_sha256) VALUES(?,?,?)",
                                   (stream, record["memory_id"], record["record_sha256"]))
            connection.execute("INSERT INTO heads(stream,cursor,digest) VALUES(?,?,?) "
                               "ON CONFLICT(stream) DO UPDATE SET cursor=excluded.cursor,digest=excluded.digest",
                               (stream, payload["cursor"], digest))


class DependencyValidation:
    """Bounded full-closure validation with explicitly invalidatable positives."""

    def __init__(self, trust: TrustStore, cache: sqlite3.Connection | None = None):
        self.trust = trust
        self.cache = cache
        self.epoch: str | None = None
        self.trust_sha256: str | None = None
        self.loaded: dict[str, Mapping[str, Any]] = {}
        self.rows: dict[str, sqlite3.Row | None] = {}
        self.checked: set[str] = set()
        self.certificates: dict[str, Mapping[str, Any]] = {}
        self.bytes_read = 0
        self.database_bytes_read = 0
        self.started = False
        self.complete = False

    def begin(self, connection: sqlite3.Connection) -> None:
        if self.started:
            return
        self.epoch = Vault.dependency_epoch(connection)
        self.trust_sha256 = _trust_digest(self.trust)
        self.started = True

    def touch(self, record: Mapping[str, Any]) -> None:
        identifier = str(record["memory_id"])
        if identifier in self.loaded:
            if self.loaded[identifier] != record:
                raise MemoryError("memory_identity_conflict")
            return
        size = len(canonical_bytes(record))
        if len(self.loaded) >= MAX_BUNDLE_RECORDS or self.bytes_read + size > MAX_BUNDLE_BYTES:
            raise MemoryError("dependency_revalidation_required", retryable=True)
        self.loaded[identifier] = record
        self.bytes_read += size

    def export_row(self, connection: sqlite3.Connection, identifier: str) -> sqlite3.Row | None:
        """Read each canonical body at most once in this bounded DB snapshot."""
        if identifier in self.rows:
            return self.rows[identifier]
        if len(self.rows) >= MAX_BUNDLE_RECORDS:
            raise MemoryError("dependency_revalidation_required", retryable=True)
        metadata = connection.execute(
            "SELECT length(CAST(m.record_json AS BLOB)) AS bytes,"
            "length(CAST(a.attestation_json AS BLOB)) AS proof_bytes,"
            "vault_admitted(a.state,a.signer_key_id) AS admission_rank FROM memories m "
            "JOIN record_admissions a USING(memory_id) WHERE m.memory_id=?", (identifier,),
        ).fetchone()
        if metadata is None or int(metadata["admission_rank"]) == 0:
            self.rows[identifier] = None
            return None
        if metadata["proof_bytes"] is not None and int(metadata["proof_bytes"]) > 1024:
            raise MemoryError("stored_attestation_invalid")
        if self.database_bytes_read + int(metadata["bytes"]) > MAX_BUNDLE_BYTES:
            raise MemoryError("dependency_revalidation_required", retryable=True)
        row = connection.execute(
            "SELECT m.*,a.state,a.signer_key_id,a.attestation_json,"
            "vault_admitted(a.state,a.signer_key_id) AS admission_rank FROM memories m "
            "JOIN record_admissions a USING(memory_id) WHERE m.memory_id=?", (identifier,),
        ).fetchone()
        self.rows[identifier] = row
        self.database_bytes_read += int(metadata["bytes"])
        return row

    def _load(self, connection: sqlite3.Connection, identifier: str) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
        row = self.export_row(connection, identifier)
        if row is None or row["state"] == "quarantined":
            raise MemoryError("dependency_not_admitted")
        if row["state"] != "verified" or row["attestation_json"] is None:
            raise MemoryError("unsigned_dependency")
        try:
            self.trust.require_trusted(str(row["signer_key_id"]))
        except Exception:
            raise MemoryError("dependency_not_admitted") from None
        if identifier not in self.loaded:
            self.touch(Vault._record_from_row(row))
        record = self.loaded[identifier]
        if record["record_sha256"] != row["record_sha256"]:
            raise MemoryError("stored_record_invalid")
        if len(str(row["attestation_json"]).encode("utf-8")) > 1024:
            raise MemoryError("stored_attestation_invalid")
        proof = strict_json_loads(str(row["attestation_json"]))
        if not isinstance(proof, Mapping):
            raise MemoryError("stored_attestation_invalid")
        return record, proof

    def _cached(self, record: Mapping[str, Any]) -> bool:
        if self.cache is None or self.epoch is None:
            return False
        row = self.cache.execute("SELECT record_sha256,epoch,trust_sha256 FROM validations WHERE memory_id=?",
                                 (record["memory_id"],)).fetchone()
        return row is not None and tuple(row) == (record["record_sha256"], self.epoch, self.trust_sha256)

    def require(self, connection: sqlite3.Connection, identifiers: Sequence[str]) -> None:
        self.begin(connection)
        pending = list(dict.fromkeys(identifier for identifier in identifiers if identifier not in self.checked))
        queued = set(pending)
        visited: set[str] = set()
        candidates: dict[str, Mapping[str, Any]] = {}
        while pending:
            identifier = pending.pop()
            queued.discard(identifier)
            if identifier in self.checked or identifier in visited:
                continue
            record, proof = self._load(connection, identifier)
            visited.add(identifier)
            if self._cached(record):
                continue
            self.trust.verify_record(record, proof)
            candidates[identifier] = record
            for relation in record["relations"]:
                target = relation["target"]
                if target not in queued and target not in visited and target not in self.checked:
                    if len(queued) + len(visited) + len(self.checked) >= MAX_BUNDLE_RECORDS:
                        raise MemoryError("dependency_revalidation_required", retryable=True)
                    queued.add(target)
                    pending.append(target)
        # A cycle is valid only after every member was actually verified; no
        # in-progress/partial DFS node becomes a reusable positive certificate.
        self.checked.update(visited)
        self.certificates.update(candidates)

    def finish(self, connection: sqlite3.Connection) -> None:
        if (_trust_digest(self.trust) != self.trust_sha256
                or Vault.dependency_epoch(connection) != self.epoch):
            raise MemoryError("dependency_validation_changed", retryable=True)
        self.complete = True

    def validate(self, connection: sqlite3.Connection, records: Mapping[str, Mapping[str, Any]],
                 attestations: Mapping[str, Mapping[str, Any]]) -> None:
        self.begin(connection)
        # The core invokes this after actual insertion/admission, so every
        # lookup below observes the exact state that this transaction will save.
        for record in records.values():
            self.touch(record)
        self.require(connection, list(records))
        self.finish(connection)

    def persist(self) -> None:
        # The caller must invoke this only AFTER its Vault transaction commits.
        # A rolled-back generation could be reused by a later unrelated write.
        if self.cache is None or self.epoch is None or not self.complete:
            return
        with self.cache:
            self.cache.executemany(
                "INSERT INTO validations(memory_id,record_sha256,epoch,trust_sha256) VALUES(?,?,?,?) "
                "ON CONFLICT(memory_id) DO UPDATE SET record_sha256=excluded.record_sha256,epoch=excluded.epoch,trust_sha256=excluded.trust_sha256",
                ((record["memory_id"], record["record_sha256"], self.epoch, self.trust_sha256)
                 for record in self.certificates.values()),
            )


class PublishedBoundary(DependencyValidation):
    """A private, exact published-member frontier; never a JSON request field."""

    def __init__(self, trust: TrustStore, cache: sqlite3.Connection, *, stream: str,
                 cursor: int, digest: str | None):
        super().__init__(trust, cache)
        self.stream = stream
        self.usable = DependencyIndex.head_matches(cache, stream, cursor, digest)

    def can_omit(self, connection: sqlite3.Connection, record: Mapping[str, Any]) -> bool:
        if not self.usable:
            return False
        member = self.cache.execute("SELECT record_sha256 FROM members WHERE stream=? AND memory_id=?",
                                    (self.stream, record["memory_id"])).fetchone()
        if member is None:
            return False
        if member[0] != record["record_sha256"]:
            raise MemoryError("dependency_frontier_identity_conflict")
        self.require(connection, [str(record["memory_id"])])
        return True


def incremental_changes(vault: Vault, trust: TrustStore, index: DependencyIndex, *,
                        sender_key_id: str, store_id: str, after: int, previous_digest: str | None,
                        limit: int = 100, maximum_bytes: int = 256 * 1024) -> Mapping[str, Any]:
    """Read complete new records, shortening only a verified published prefix."""
    with index.connect() as cache:
        boundary = PublishedBoundary(trust, cache, stream=sender_key_id + "/" + store_id,
                                     cursor=after, digest=previous_digest)
        try:
            result = vault.transfer_changes(after=after, store_id=store_id, limit=limit,
                                            maximum_bytes=maximum_bytes, maximum_records=1024,
                                            require_verified=True, dependency_boundary=boundary)
        except MemoryError as exc:
            if exc.code != "dependency_budget_exceeded":
                raise
            # Retain the small-page target, then use the existing complete-group
            # bounds only when one root cannot fit. Never sign a size omission.
            boundary = PublishedBoundary(trust, cache, stream=sender_key_id + "/" + store_id,
                                         cursor=after, digest=previous_digest)
            result = vault.transfer_changes(after=after, store_id=store_id, limit=limit,
                                            require_verified=True, dependency_boundary=boundary)
        boundary.persist()  # Read transaction has successfully finished.
        return result


def validate_outgoing(vault: Vault, trust: TrustStore, index: DependencyIndex,
                      records: Sequence[Mapping[str, Any]]) -> None:
    """Recheck a frozen v3 batch against current local transitive admission."""
    with index.connect() as cache, contextlib.closing(vault._connect(writable=False)) as connection, connection:
        connection.execute("BEGIN")
        validator = DependencyValidation(trust, cache)
        validator.begin(connection)
        for record in records:
            validator.touch(record)
        validator.require(connection, [str(record["memory_id"]) for record in records])
        validator.finish(connection)
        connection.commit()
        validator.persist()


def ingest_verified(vault: Vault, trust: TrustStore, records: Sequence[Mapping[str, Any]],
                    attestations: Mapping[str, Mapping[str, Any]], *, transfer_id: str,
                    payload_sha256: str, previous_payload_sha256: str | None = None,
                    index: DependencyIndex | None = None) -> Mapping[str, Any]:
    """Atomic current-trust import, also usable by explicit offline recovery.

    Recovery passes no previous payload or live index: it validates the actual
    restored Vault, never revives archived stream state. Missing/untrusted or
    oversized closures fail without partial admission. Exact receipts stay
    historical acknowledgments and never re-admit quarantined memories.
    """
    if len(records) > MAX_BUNDLE_RECORDS:
        raise MemoryError("bundle_too_large")
    size = 0
    for record in records:
        size += len(canonical_bytes(record))
        if size > MAX_BUNDLE_BYTES:
            raise MemoryError("bundle_too_large")
    if set(attestations) != {record["memory_id"] for record in records}:
        raise MemoryError("missing_attestation")
    for record in records:
        trust.verify_record(record, attestations[record["memory_id"]])
    with (index.connect() if index is not None else contextlib.nullcontext(None)) as cache:
        validator = DependencyValidation(trust, cache)
        result = vault.ingest_records(records, admission="verified", attestations=attestations,
                                      transfer_id=transfer_id, payload_sha256=payload_sha256,
                                      expected_previous_payload_sha256=previous_payload_sha256,
                                      dependency_validator=validator.validate)
        validator.persist()  # Never write positive certificates before COMMIT.
        return result
