#!/usr/bin/env python3
"""Explicit content-selected, dependency-complete portable memory shares.

No selector owns memory. No packet can select local admission policy, enroll a
key, invoke a provider, open a network or execute a remembered instruction.
The independent canonical record/v1 bytes and record attestations are retained.
This is an operator data-transfer path, not work on the ordinary recall path.
"""

from __future__ import annotations

import argparse
from array import array
import base64
import binascii
from collections import Counter, deque
import contextlib
from dataclasses import dataclass
import datetime as dt
import hashlib
import os
from pathlib import Path
import re
import sqlite3
import stat
import tempfile
import time
from typing import Any, Callable, Iterator, Mapping, Sequence

from memory_vault import (
    ATTESTATION_SCHEMA, HASH_PROFILE, KINDS, MAX_BUNDLE_LINE_BYTES,
    MemoryError, Vault, canonical_bytes, failure, normalize_text, sha256,
    strict_json_loads, success, utc_now, validate_record, write_response,
)
from memory_vault_client import ClientConfig, _absolute, _private_directory
from memory_vault_privacy import assert_publishable, review_records


SELECTOR_SCHEMA = "universal-memory-selection/v1"
SHARE_SCHEMA = "universal-memory-share/v1"
MAX_SELECTOR_BYTES = 16 * 1024
MAX_SHARE_BYTES = 2 * 1024 * 1024 * 1024
MAX_SHARE_RECORDS = 250_000
MAX_SHARE_EDGES = MAX_SHARE_RECORDS * 256
MAX_SOURCE_RECORDS = 1_000_000
MAX_LINE_BYTES = MAX_BUNDLE_LINE_BYTES + 4096
_MEMORY = re.compile(r"mem_[0-9a-f]{40}")
_KEY = re.compile(r"ed25519_[0-9a-f]{64}")
_CLAIM = re.compile(r"[a-z0-9][a-z0-9_-]{1,63}")


@dataclass(frozen=True)
class ShareSummary:
    path: str
    records: int
    selected_records: int
    dependency_records: int
    attestations: int
    raw_bytes: int
    sha256: str
    selector_sha256: str
    records_sha256: str

    def as_dict(self) -> dict[str, Any]:
        return {**self.__dict__, "schema_version": SHARE_SCHEMA,
                "dependency_closure_verified": True,
                "signatures_cryptographically_verified": False,
                "checksum_authenticates_sender": False, "grants_authority": False}


def _timestamp(value: Any) -> dt.datetime:
    if (not isinstance(value, str) or len(value) > 64
            or re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})", value) is None):
        raise MemoryError("invalid_share_timestamp")
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(dt.timezone.utc)
    except (ValueError, OverflowError):
        raise MemoryError("invalid_share_timestamp") from None


def parse_selector(value: Any) -> dict[str, Any]:
    if isinstance(value, (bytes, str)):
        encoded = value.encode("utf-8") if isinstance(value, str) else value
        if len(encoded) > MAX_SELECTOR_BYTES:
            raise MemoryError("share_selector_too_large")
        value = strict_json_loads(encoded)
    fields = {"schema_version", "memory_ids", "claim_keys", "concepts", "entities", "kinds", "captured_after", "captured_before", "all_records"}
    if (not isinstance(value, dict) or set(value) - fields
            or value.get("schema_version") != SELECTOR_SCHEMA
            or len(canonical_bytes(value)) > MAX_SELECTOR_BYTES):
        raise MemoryError("invalid_share_selector")
    result: dict[str, Any] = {"schema_version": SELECTOR_SCHEMA}
    for key in ("memory_ids", "claim_keys", "concepts", "entities", "kinds"):
        items = value.get(key, [])
        if (not isinstance(items, list) or len(items) > 64
                or any(not isinstance(item, str) or not item or len(item.encode("utf-8")) > 512
                       or any(char in item for char in "\x00\r\n") for item in items)
                or len(set(items)) != len(items)):
            raise MemoryError("invalid_share_selector")
        if key == "memory_ids" and any(_MEMORY.fullmatch(item) is None for item in items):
            raise MemoryError("invalid_share_memory_id")
        if key == "claim_keys" and any(_CLAIM.fullmatch(item) is None for item in items):
            raise MemoryError("invalid_share_claim_key")
        if key == "kinds" and set(items) - KINDS:
            raise MemoryError("invalid_share_kind")
        result[key] = sorted(items)
    for key in ("captured_after", "captured_before"):
        raw = value.get(key)
        result[key] = _timestamp(raw).isoformat().replace("+00:00", "Z") if raw is not None else None
    if result["captured_after"] and result["captured_before"] and _timestamp(result["captured_after"]) >= _timestamp(result["captured_before"]):
        raise MemoryError("invalid_share_time_range")
    all_records = value.get("all_records", False)
    if type(all_records) is not bool:
        raise MemoryError("invalid_share_selector")
    result["all_records"] = all_records
    if not all_records and not any(result[key] for key in fields - {"schema_version", "all_records"}):
        raise MemoryError("empty_share_selector")
    if all_records and any(result[key] for key in fields - {"schema_version", "all_records"}):
        raise MemoryError("ambiguous_share_selector")
    return result


def _matches(record: Mapping[str, Any], selector: Mapping[str, Any]) -> bool:
    if selector["all_records"]:
        return True
    if selector["kinds"] and record["kind"] not in selector["kinds"]:
        return False
    captured = _timestamp(record["created_at"])
    if selector["captured_after"] and captured < _timestamp(selector["captured_after"]):
        return False
    if selector["captured_before"] and captured >= _timestamp(selector["captured_before"]):
        return False
    axes: list[bool] = []
    if selector["memory_ids"]:
        axes.append(record["memory_id"] in selector["memory_ids"])
    if selector["claim_keys"]:
        axes.append(any("claim:" + key in record["entities"] or "claim:v021:" + key in record["entities"] for key in selector["claim_keys"]))
    if selector["entities"]:
        axes.append(bool(set(selector["entities"]) & set(record["entities"])))
    if selector["concepts"]:
        text = normalize_text(" ".join([record["text"], *record["entities"]]))
        axes.append(any(normalize_text(concept) in text for concept in selector["concepts"]))
    return any(axes) if axes else True


def _deadline(seconds: int) -> float:
    if type(seconds) is not int or not 1 <= seconds <= 3600:
        raise MemoryError("invalid_share_time_budget")
    return time.monotonic() + seconds


def _check_time(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise MemoryError("share_work_limit", retryable=True)


def _proof(record: Mapping[str, Any], value: Any) -> Mapping[str, Any] | None:
    if value is None:
        return None
    if (not isinstance(value, dict) or set(value) != {"schema_version", "key_id", "record_sha256", "signature"}
            or value["schema_version"] != ATTESTATION_SCHEMA
            or not isinstance(value["key_id"], str) or _KEY.fullmatch(value["key_id"]) is None
            or value["record_sha256"] != record["record_sha256"]
            or not isinstance(value["signature"], str) or not 1 <= len(value["signature"]) <= 256
            or len(canonical_bytes(value)) > 2048):
        raise MemoryError("invalid_share_attestation")
    try:
        signature = base64.b64decode(value["signature"].encode("ascii"), validate=True)
        if len(signature) != 64 or base64.b64encode(signature).decode("ascii") != value["signature"]:
            raise ValueError
    except (ValueError, UnicodeError, binascii.Error):
        raise MemoryError("invalid_share_attestation") from None
    return value


def _row(connection: sqlite3.Connection, memory_id: str) -> sqlite3.Row:
    row = connection.execute(
        "SELECT m.*,a.attestation_json,vault_admitted(a.state,a.signer_key_id) AS admitted "
        "FROM memories m JOIN record_admissions a USING(memory_id) WHERE m.memory_id=?", (memory_id,),
    ).fetchone()
    if row is None or int(row["admitted"]) <= 0:
        raise MemoryError("share_dependency_not_admitted")
    return row


def _selection(connection: sqlite3.Connection, selector: Mapping[str, Any], deadline: float) -> tuple[set[str], dict[str, int]]:
    roots: set[str] = set()
    order: dict[str, int] = {}
    query = ("SELECT m.* FROM memories m JOIN record_admissions a USING(memory_id) "
             "WHERE vault_admitted(a.state,a.signer_key_id)>0")
    parameters: list[str] = []
    # Exact IDs are indexed; exporting a few selected memories must not scan a
    # million unrelated records. OR-based content axes still need a full scan.
    if selector["memory_ids"] and not any(selector[key] for key in ("claim_keys", "concepts", "entities")):
        parameters = selector["memory_ids"]
        query += " AND m.memory_id IN (" + ",".join("?" for _ in parameters) + ")"
    query += " ORDER BY m.ingest_seq"
    for count, row in enumerate(connection.execute(query, parameters), 1):
        _check_time(deadline)
        if count > MAX_SOURCE_RECORDS:
            raise MemoryError("share_source_record_limit")
        record = Vault._record_from_row(row)
        if _matches(record, selector):
            roots.add(record["memory_id"])
            if len(roots) > MAX_SHARE_RECORDS:
                raise MemoryError("share_record_limit")
    if not roots:
        raise MemoryError("share_no_matching_records")
    pending = deque(sorted(roots))
    queued = set(roots)
    while pending:
        _check_time(deadline)
        memory_id = pending.popleft()
        row = _row(connection, memory_id)
        record = Vault._record_from_row(row)
        order[memory_id] = int(row["ingest_seq"])
        for relation in record["relations"]:
            target = relation["target"]
            if target not in queued:
                queued.add(target)
                if len(queued) > MAX_SHARE_RECORDS:
                    raise MemoryError("share_dependency_closure_limit")
                pending.append(target)
    return roots, order


@contextlib.contextmanager
def _new_output(output: Path) -> Iterator[Any]:
    destination = _absolute(output)
    if os.path.lexists(destination):
        raise MemoryError("share_output_exists")
    _private_directory(destination.parent)
    descriptor, name = tempfile.mkstemp(prefix=".memory-share-", dir=destination.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            if os.name == "nt":
                from memory_vault_storage import check_fd
                check_fd(stream.fileno(), private=True)
            yield stream
            stream.flush()
            os.fsync(stream.fileno())
        if os.name == "nt":
            from memory_vault_storage import publish_file
            publish_file(temporary, destination, replace=False)
        else:
            os.link(temporary, destination)
        if os.name == "posix":
            directory = os.open(destination.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def export_share(config_path: Path, output: Path | None, selector: Any, *,
                 allow_local_paths: bool = False, maximum_seconds: int = 300) -> Mapping[str, Any]:
    """Review or publish a new private plaintext file, never a remote upload."""
    if type(allow_local_paths) is not bool:
        raise MemoryError("invalid_share_review_option")
    selected = parse_selector(selector)
    deadline = _deadline(maximum_seconds)
    config = ClientConfig.load(_absolute(config_path))
    if not config.vault_path.exists():
        raise MemoryError("vault_not_initialized")
    vault = config.vault()
    with contextlib.closing(vault._connect(writable=False)) as connection:
        connection.execute("BEGIN")
        roots, order = _selection(connection, selected, deadline)
        identifiers = sorted(order, key=lambda item: (order[item], item))
        reasons: Counter[str] = Counter()
        blocked = 0
        if output is None:
            for memory_id in identifiers:
                _check_time(deadline)
                finding = review_records([Vault._record_from_row(_row(connection, memory_id))])[0]
                reasons.update(finding["reasons"])
                blocked += bool(finding["reasons"])
            return {"state": "share_selection_reviewed", "selected_records": len(roots),
                    "dependency_records": len(order) - len(roots), "records": len(order),
                    "privacy_findings": dict(reasons), "records_with_findings": blocked,
                    "sample_selected_ids": sorted(roots)[:64], "sample_truncated": len(roots) > 64,
                    "selector_sha256": sha256(canonical_bytes(selected)), "contents_included": False,
                    "files_written": False, "network_accessed": False, "grants_authority": False}
        header = {"type": "header", "schema_version": SHARE_SCHEMA, "hash_profile": HASH_PROFILE,
                  "created_at": utc_now(), "selector": selected, "selector_sha256": sha256(canonical_bytes(selected))}
        total = count = signed = 0
        signer_keys: set[str] = set()
        lines_digest = hashlib.sha256()
        records_digest = hashlib.sha256()
        with _new_output(output) as stream:
            encoded = canonical_bytes(header) + b"\n"
            stream.write(encoded)
            total += len(encoded)
            for memory_id in identifiers:
                _check_time(deadline)
                row = _row(connection, memory_id)
                record = Vault._record_from_row(row)
                assert_publishable([record], allow_local_paths=allow_local_paths)
                proof = _proof(record, strict_json_loads(row["attestation_json"]) if row["attestation_json"] else None)
                if proof is not None:
                    signer_keys.add(proof["key_id"])
                line = canonical_bytes({"type": "record", "record": record, "attestation": proof, "selected": memory_id in roots}) + b"\n"
                total += len(line)
                if len(line) > MAX_LINE_BYTES or total > MAX_SHARE_BYTES - MAX_SELECTOR_BYTES:
                    raise MemoryError("share_byte_limit")
                stream.write(line)
                lines_digest.update(line)
                records_digest.update(record["record_sha256"].encode("ascii") + b"\n")
                count += 1
                signed += proof is not None
            footer = {"type": "footer", "records": count, "selected_records": len(roots),
                      "records_sha256": records_digest.hexdigest(), "lines_sha256": lines_digest.hexdigest()}
            stream.write(canonical_bytes(footer) + b"\n")
            if signer_keys and config.trust_path is not None:
                from memory_vault_trust import TrustStore
                current_trust = TrustStore(config.trust_path)
                for key_id in sorted(signer_keys):
                    _check_time(deadline)
                    current_trust.require_trusted(key_id)
    return {"state": "private_share_exported", "path": str(_absolute(output)), "records": count,
            "selected_records": len(roots), "dependency_records": count - len(roots), "attestations": signed,
            "encrypted": False, "source_memory_changed": False, "network_accessed": False,
            "attestation_crypto_checked_on_export": False, "privacy_scan_is_complete_dlp": False}


def _fingerprint(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _named_matches(named: os.stat_result, opened: os.stat_result) -> bool:
    # Windows path stat and CRT fstat can represent timestamps differently.
    # Native open_file pins/checks the path; the fd's own full fingerprint is
    # still compared before/after the read to catch in-place modifications.
    return (_fingerprint(named)[:3] == _fingerprint(opened)[:3] if os.name == "nt"
            else _fingerprint(named) == _fingerprint(opened))


class _ClosureIndex:
    """Bounded integer adjacency, not a retained graph of plaintext objects."""

    _END = 0xFFFFFFFF

    def __init__(self) -> None:
        self.identifiers: dict[str, int] = {}
        self.heads = array("I")
        self.targets = array("I")
        self.following = array("I")
        self.roots = array("I")
        self.seen = bytearray()
        self.records = 0
        if self.heads.itemsize < 4:
            raise MemoryError("share_integer_index_unavailable")

    def _index(self, memory_id: str) -> int:
        prior = self.identifiers.get(memory_id)
        if prior is not None:
            return prior
        index = len(self.identifiers)
        if index >= MAX_SHARE_RECORDS:
            raise MemoryError("share_dependency_closure_limit")
        self.identifiers[memory_id] = index
        self.heads.append(self._END)
        self.seen.append(0)
        return index

    def add(self, record: Mapping[str, Any], *, selected: bool) -> None:
        index = self._index(record["memory_id"])
        if self.seen[index]:
            raise MemoryError("share_duplicate_or_record_limit")
        self.seen[index] = 1
        self.records += 1
        if selected:
            self.roots.append(index)
        for relation in record["relations"]:
            if len(self.targets) >= MAX_SHARE_EDGES:
                raise MemoryError("share_dependency_edge_limit")
            target = self._index(relation["target"])
            self.targets.append(target)
            self.following.append(self.heads[index])
            self.heads[index] = len(self.targets) - 1

    def verify(self, deadline: float) -> None:
        if not self.roots or self.records != len(self.identifiers):
            raise MemoryError("share_footer_or_closure_mismatch")
        reached = bytearray(len(self.identifiers))
        pending: deque[int] = deque()
        for root in self.roots:
            reached[root] = 1
            pending.append(root)
        count = len(pending)
        while pending:
            _check_time(deadline)
            index = pending.popleft()
            edge = self.heads[index]
            while edge != self._END:
                target = self.targets[edge]
                if not reached[target]:
                    reached[target] = 1
                    count += 1
                    pending.append(target)
                edge = self.following[edge]
        if count != self.records:
            # A false selected flag must not smuggle unrelated records into an
            # otherwise valid share with a narrowly bound content selector.
            raise MemoryError("share_contains_unselected_non_dependency")


def _scan(path: Path, deadline: float, *, visitor: Callable[[Mapping[str, Any], Mapping[str, Any] | None], None] | None = None) -> ShareSummary:
    source = _absolute(path)
    if os.name == "nt":
        from memory_vault_storage import open_file
        descriptor = open_file(source, os.O_RDONLY)
    else:
        descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 1 <= before.st_size <= MAX_SHARE_BYTES
                or not _named_matches(source.lstat(), before)):
            raise MemoryError("unsafe_share_source")
        digest = hashlib.sha256()

        def frame() -> tuple[dict[str, Any], bytes]:
            _check_time(deadline)
            line = stream.readline(MAX_LINE_BYTES + 1)
            if not line or not line.endswith(b"\n") or len(line) > MAX_LINE_BYTES:
                raise MemoryError("invalid_share_frame")
            value = strict_json_loads(line)
            if not isinstance(value, dict) or canonical_bytes(value) + b"\n" != line:
                raise MemoryError("noncanonical_share_frame")
            digest.update(line)
            return value, line

        header, _ = frame()
        if (set(header) != {"type", "schema_version", "hash_profile", "created_at", "selector", "selector_sha256"}
                or header["type"] != "header" or header["schema_version"] != SHARE_SCHEMA
                or header["hash_profile"] != HASH_PROFILE):
            raise MemoryError("invalid_share_header")
        _timestamp(header["created_at"])
        selector = parse_selector(header["selector"])
        if selector != header["selector"] or header["selector_sha256"] != sha256(canonical_bytes(selector)):
            raise MemoryError("share_selector_hash_mismatch")
        closure = _ClosureIndex()
        roots = signed = 0
        lines_digest = hashlib.sha256()
        records_digest = hashlib.sha256()
        while True:
            value, line = frame()
            if value.get("type") == "footer":
                expected = {"type": "footer", "records": closure.records, "selected_records": roots,
                            "records_sha256": records_digest.hexdigest(), "lines_sha256": lines_digest.hexdigest()}
                if (value != expected or type(value.get("records")) is not int
                        or type(value.get("selected_records")) is not int or roots == 0
                        or stream.read(1)):
                    raise MemoryError("share_footer_or_closure_mismatch")
                closure.verify(deadline)
                break
            if (set(value) != {"type", "record", "attestation", "selected"}
                    or value["type"] != "record" or type(value["selected"]) is not bool):
                raise MemoryError("invalid_share_record_frame")
            record = validate_record(value["record"])
            proof = _proof(record, value["attestation"])
            closure.add(record, selected=value["selected"])
            if value["selected"]:
                if not _matches(record, selector):
                    raise MemoryError("share_selected_record_mismatch")
                roots += 1
            signed += proof is not None
            lines_digest.update(line)
            records_digest.update(record["record_sha256"].encode("ascii") + b"\n")
            if visitor is not None:
                visitor(record, proof)
        if (_fingerprint(os.fstat(stream.fileno())) != _fingerprint(before)
                or not _named_matches(source.lstat(), before)):
            raise MemoryError("share_source_changed")
        return ShareSummary(str(source), closure.records, roots, closure.records - roots, signed,
                            before.st_size, digest.hexdigest(), header["selector_sha256"], records_digest.hexdigest())


def verify_share_bundle(path: Path, *, maximum_seconds: int = 300) -> ShareSummary:
    """Validate complete bytes and closure only, not caller authority or truth."""
    return _scan(path, _deadline(maximum_seconds))


def import_share(config_path: Path, source: Path, *, verify_signatures: bool = False,
                 accept_unsigned: bool = False, maximum_seconds: int = 300) -> Mapping[str, Any]:
    if type(verify_signatures) is not bool or type(accept_unsigned) is not bool or (verify_signatures and accept_unsigned):
        raise MemoryError("ambiguous_share_admission")
    deadline = _deadline(maximum_seconds)
    config = ClientConfig.load(_absolute(config_path))
    trust = None
    if verify_signatures:
        if config.trust_path is None:
            raise MemoryError("share_independent_trust_required")
        from memory_vault_trust import TrustStore
        trust = TrustStore(config.trust_path)
    summary = _scan(source, deadline)
    admission = "verified" if verify_signatures else "accepted_unsigned" if accept_unsigned else "quarantined"
    transfer_id = "xfer_" + sha256(canonical_bytes({"operation": "share-import/v1", "share_sha256": summary.sha256, "admission": admission}))
    vault = config.vault(storage_write=True)  # no private signing identity is loaded
    with contextlib.closing(vault._connect()) as connection, connection:
        connection.execute("BEGIN IMMEDIATE")
        prior = connection.execute("SELECT * FROM transfer_receipts WHERE transfer_id=?", (transfer_id,)).fetchone()
        if prior is not None and prior["payload_sha256"] != summary.sha256:
            raise MemoryError("share_import_receipt_conflict")
        added = 0
        upgraded: set[str] = set()
        signer_keys: set[str] = set()

        def receive(record: Mapping[str, Any], proof: Mapping[str, Any] | None) -> None:
            nonlocal added
            _check_time(deadline)
            if trust is not None:
                if proof is None:
                    raise MemoryError("share_record_signature_required")
                trust.verify_record(record, proof)
                signer_keys.add(proof["key_id"])
            if prior is not None:
                return
            _, inserted = vault._insert_record(connection, record, allow_pending_relations=True)
            if vault._set_admission(connection, record, admission, proof if verify_signatures else None):
                upgraded.add(record["memory_id"])
            added += int(inserted)

        observed = _scan(source, deadline, visitor=receive)
        if observed != summary:
            raise MemoryError("share_source_changed")
        def check_current_signers() -> None:
            # A bounded long import must not rely solely on an early record's
            # admission check. This is a final trust checkpoint, not an atomic
            # transaction with the independently managed trust file.
            if trust is not None:
                for key_id in sorted(signer_keys):
                    _check_time(deadline)
                    trust.require_trusted(key_id)
        if prior is not None:
            check_current_signers()
            result = strict_json_loads(prior["result_json"])
            return {**result, "records_added": 0, "receipt_replayed": True,
                    "current_trust_checked": verify_signatures, "network_accessed": False}
        vault._requeue_dependents(connection, upgraded)
        result = {"state": "share_imported", "records_seen": summary.records, "records_added": added,
                  "admission": admission, "share_sha256": summary.sha256, "current_trust_checked": verify_signatures,
                  "signatures_preserved_in_source": True, "record_proofs_stored": verify_signatures,
                  "network_accessed": False, "worker_started": False, "trust_policy_changed": False}
        connection.execute("INSERT INTO transfer_receipts(transfer_id,payload_sha256,result_json,created_at) VALUES(?,?,?,?)",
                           (transfer_id, summary.sha256, canonical_bytes(result).decode("utf-8"), utc_now()))
        check_current_signers()
        _check_time(deadline)
        try:
            connection.commit()
        except sqlite3.IntegrityError:
            raise MemoryError("share_relation_closure_failed") from None
        return result


def main(argv: Sequence[str] | None = None, *, config_path: Path | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--maximum-seconds", type=int, default=300)
    sub = parser.add_subparsers(dest="action", required=True)
    for name in ("review", "export"):
        command = sub.add_parser(name)
        command.add_argument("--selector", type=Path, required=True)
        if name == "export":
            command.add_argument("--out", type=Path, required=True)
            command.add_argument("--allow-local-paths", action="store_true")
    inspect = sub.add_parser("verify")
    inspect.add_argument("--source", type=Path, required=True)
    receive = sub.add_parser("import")
    receive.add_argument("--source", type=Path, required=True)
    mode = receive.add_mutually_exclusive_group()
    mode.add_argument("--verify-signatures", action="store_true")
    mode.add_argument("--accept-unsigned", action="store_true")
    args = parser.parse_args(argv)
    try:
        if config_path is not None and args.config is not None:
            raise MemoryError("use_client_selected_configuration")
        selected_config = config_path or args.config
        if args.action == "verify":
            result = verify_share_bundle(args.source, maximum_seconds=args.maximum_seconds).as_dict()
        elif selected_config is None:
            raise MemoryError("share_client_configuration_required")
        elif args.action in {"review", "export"}:
            from memory_vault_update import read_file
            selector = parse_selector(read_file(args.selector, MAX_SELECTOR_BYTES))
            result = export_share(selected_config, getattr(args, "out", None), selector,
                                  allow_local_paths=getattr(args, "allow_local_paths", False), maximum_seconds=args.maximum_seconds)
        else:
            result = import_share(selected_config, args.source, verify_signatures=args.verify_signatures,
                                  accept_unsigned=args.accept_unsigned, maximum_seconds=args.maximum_seconds)
        write_response(success(result))
        return 0
    except MemoryError as exc:
        write_response(failure(exc.code, retryable=exc.retryable))
    except Exception:
        write_response(failure("sharing_unavailable", retryable=True))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
