#!/usr/bin/env python3
"""Explicit, signed, incremental delivery through a user-selected directory.

The directory may be carried by a separately authorized shared-folder service.
This adapter opens no network connections, installs nothing, starts no daemon,
and never transports private keys. It is not encrypted storage or a network ACL.
"""
from __future__ import annotations

import argparse
import contextlib
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any, Iterator, Mapping, Sequence

from memory_vault import MemoryError, Vault, canonical_bytes, failure, sha256, strict_json_loads, success, validate_record, write_response
from memory_vault_trust import Identity, TrustError, TrustStore


DELTA_SCHEMA = "universal-memory-delta/v1"
STATE_SCHEMA = "universal-memory-transfer-state/v1"
MAX_CAPSULE_BYTES = 4 * 1024 * 1024
MAX_DISCOVERY_FILES = 20_000
MAX_PEERS = 256
_KEY = re.compile(r"ed25519_[0-9a-f]{64}")
_STORE = re.compile(r"store_[0-9a-f]{32}")
_CAPSULE_NAME = re.compile(r"([0-9]{20})-([0-9]{20})-([0-9a-f]{64})\.json")


def _path(value: Path) -> Path:
    path = value.expanduser()
    if not path.is_absolute() or ".." in path.parts:
        raise MemoryError("transfer_path_must_be_absolute")
    for part in (path, *path.parents):
        if part.is_symlink():
            raise MemoryError("unsafe_transfer_path")
    return path


def _private_directory(path: Path) -> None:
    if os.name != "posix":
        raise MemoryError("unsupported_private_storage")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise MemoryError("unprotected_transfer_state")


def _read(path: Path, *, maximum: int = MAX_CAPSULE_BYTES, private: bool = False) -> Mapping[str, Any]:
    _path(path)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise MemoryError("invalid_transfer_file")
        if private and (info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_nlink != 1):
            raise MemoryError("unprotected_transfer_state")
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise MemoryError("transfer_too_large")
    value = strict_json_loads(data)
    if not isinstance(value, Mapping):
        raise MemoryError("invalid_transfer_file")
    return value


def _write(path: Path, value: Mapping[str, Any], *, replace: bool) -> None:
    """Durable atomic output; immutable exchange files never overwrite peers."""
    _path(path)
    encoded = canonical_bytes(value) + b"\n"
    if len(encoded) > MAX_CAPSULE_BYTES:
        raise MemoryError("transfer_too_large")
    descriptor, temporary_name = tempfile.mkstemp(prefix=".vault-", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        if replace:
            if path.exists():
                _read(path, private=True)
            os.replace(temporary, path)
        else:
            try:
                os.link(temporary, path)
            except FileExistsError:
                if canonical_bytes(_read(path)) != canonical_bytes(value):
                    raise MemoryError("transfer_output_conflict") from None
            temporary.unlink()
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        with contextlib.suppress(FileNotFoundError):
            temporary.unlink()


@contextlib.contextmanager
def _lock(directory: Path) -> Iterator[None]:
    _private_directory(directory)
    import fcntl  # POSIX only; no unsafe cross-platform lock emulation.
    target = directory / "transfer.lock"
    descriptor = os.open(target, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
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

    def _state(self) -> dict[str, Any]:
        if not self.state_path.exists():
            return {"schema_version": STATE_SCHEMA, "vault_store_id": None, "publisher_key_id": None,
                    "published_cursor": 0, "last_published": None, "received": {}}
        value = dict(_read(self.state_path, private=True))
        if set(value) != {"schema_version", "vault_store_id", "publisher_key_id", "published_cursor", "last_published", "received"}:
            raise MemoryError("invalid_transfer_state")
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
        return value

    def _bind_vault(self, state: dict[str, Any], *, missing_ok: bool) -> None:
        result = self.vault.handle({"op": "status"})
        if not result["ok"]:
            code = str(result["error"]["code"])
            if code == "not_initialized" and missing_ok and state["vault_store_id"] is None:
                return
            if code == "not_initialized" and state["vault_store_id"] is not None:
                raise MemoryError("receiver_vault_missing")
            raise MemoryError(code)
        store_id = result["result"]["store_id"]
        if state["vault_store_id"] is not None and state["vault_store_id"] != store_id:
            raise MemoryError("store_identity_changed")
        state["vault_store_id"] = store_id

    def _verify_capsule(self, capsule: Mapping[str, Any], *, verify_records: bool = True) -> tuple[dict[str, Any], str]:
        if set(capsule) != {"payload", "proof"} or not isinstance(capsule["payload"], Mapping):
            raise MemoryError("invalid_transfer_envelope")
        payload = dict(capsule["payload"])
        if set(payload) != {"schema_version", "source_store_id", "sender_key_id", "after", "cursor", "records", "attestations", "blocked"}:
            raise MemoryError("invalid_transfer_payload")
        if payload["schema_version"] != DELTA_SCHEMA:
            raise MemoryError("unsupported_transfer_schema")
        store_id, sender = payload["source_store_id"], payload["sender_key_id"]
        if not isinstance(store_id, str) or not _STORE.fullmatch(store_id) or not isinstance(sender, str) or not _KEY.fullmatch(sender):
            raise MemoryError("invalid_transfer_source")
        if _cursor(payload["cursor"]) <= _cursor(payload["after"]):
            raise MemoryError("invalid_transfer_cursor")
        if self.trust.verify_message(payload, capsule["proof"]) != sender:
            raise MemoryError("transfer_signer_mismatch")
        blocked = payload["blocked"]
        if not isinstance(blocked, list) or len(blocked) > 256:
            raise MemoryError("invalid_transfer_disposition")
        for item in blocked:
            if (not isinstance(item, dict) or set(item) != {"memory_id", "sequence", "reason"}
                    or not isinstance(item["memory_id"], str) or re.fullmatch(r"mem_[0-9a-f]{40}", item["memory_id"]) is None
                    or not isinstance(item["reason"], str)
                    or item["reason"] not in {"dependency_not_admitted", "dependency_budget_exceeded", "unsigned_dependency"}
                    or not payload["after"] < _cursor(item["sequence"]) <= payload["cursor"]):
                raise MemoryError("invalid_transfer_disposition")
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
        return payload, sha256(canonical_bytes(payload))

    def publish(self, *, limit: int = 100, maximum_bytes: int = 256 * 1024, attest_unsigned: bool = False) -> Mapping[str, Any]:
        if self.identity is None:
            raise MemoryError("publisher_identity_required")
        self.trust.require_trusted(self.identity.key_id)
        with _lock(self.state_directory):
            state = self._state()
            self._bind_vault(state, missing_ok=False)
            if state["publisher_key_id"] not in {None, self.identity.key_id}:
                raise MemoryError("publisher_identity_changed")
            state["publisher_key_id"] = self.identity.key_id
            if self.pending_path.exists():
                capsule = _read(self.pending_path, private=True)
                payload, digest = self._verify_capsule(capsule, verify_records=False)
                if payload["sender_key_id"] != self.identity.key_id or payload["source_store_id"] != state["vault_store_id"]:
                    raise MemoryError("pending_transfer_source_changed")
                if payload["cursor"] == state["published_cursor"] and digest == state["last_published"]:
                    self.pending_path.unlink()  # Already durable; only the redundant pending copy.
                    return {"state": "published", "recovered_receipt": True, "records": len(payload["records"]), "network_accessed": False}
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
                result = self.vault.handle({"op": "changes", "after": state["published_cursor"], "store_id": state["vault_store_id"],
                                            "limit": limit, "maximum_bytes": maximum_bytes, "require_verified": not attest_unsigned})
                if not result["ok"]:
                    raise MemoryError(str(result["error"]["code"]))
                delta = result["result"]
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
                payload = {"schema_version": DELTA_SCHEMA, "source_store_id": delta["store_id"], "sender_key_id": self.identity.key_id,
                           "after": delta["after"], "cursor": delta["cursor"], "records": delta["records"], "attestations": proofs,
                           "blocked": delta["blocked"]}
                capsule = {"payload": payload, "proof": dict(self.identity.sign_message(payload))}
                digest = sha256(canonical_bytes(payload))
                # Save the exact signed bytes before delivery so a crash cannot
                # turn a retry into a different batch with the same cursor.
                _write(self.pending_path, capsule, replace=False)
            self.exchange.mkdir(parents=True, exist_ok=True, mode=0o700)
            directory = _path(self.exchange / self.identity.key_id / str(payload["source_store_id"]))
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            destination = directory / f"{payload['after']:020d}-{payload['cursor']:020d}-{digest}.json"
            _write(destination, capsule, replace=False)
            state["published_cursor"] = payload["cursor"]
            state["last_published"] = digest
            _write(self.state_path, state, replace=True)
            self.pending_path.unlink()
            return {"state": "published_with_blocked" if payload["blocked"] else "published", "records": len(payload["records"]),
                    "cursor": payload["cursor"], "blocked": payload["blocked"],
                    "batch_sha256": digest, "network_accessed": False}

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
            state["publisher_key_id"] = payload["sender_key_id"]
            state["published_cursor"] = payload["cursor"]
            state["last_published"] = digest
            _write(self.state_path, state, replace=True)
            self.pending_path.unlink()
            return {"state": "publication_acknowledged", "records_republished": 0, "network_accessed": False}

    def receive(self, *, maximum_batches: int = 16) -> Mapping[str, Any]:
        if not isinstance(maximum_batches, int) or isinstance(maximum_batches, bool) or not 1 <= maximum_batches <= 256:
            raise MemoryError("invalid_limit")
        report: dict[str, Any] = {"state": "received", "batches": 0, "records_added": 0, "unknown_senders": 0,
                                  "gaps": 0, "rejected": [], "sender_blocked_records": 0,
                                  "receipt_replays": 0, "network_accessed": False}
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
                            entries_seen += 1
                            if entries_seen > MAX_DISCOVERY_FILES:
                                raise MemoryError("exchange_discovery_limit")
                            if _STORE.fullmatch(store.name) and store.is_dir(follow_symlinks=False):
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
                        entries_seen += 1
                        if entries_seen > MAX_DISCOVERY_FILES:
                            raise MemoryError("exchange_discovery_limit")
                        match = _CAPSULE_NAME.fullmatch(entry.name)
                        if match and entry.is_file(follow_symlinks=False):
                            candidates.setdefault(int(match[1]), []).append((int(match[2]), match[3], Path(entry.path)))
                expected = int(state["received"].get(peer, 0))
                while True:
                    group = candidates.get(expected, [])
                    if not group:
                        if any(after > expected for after in candidates):
                            report["gaps"] += 1
                        break  # Never skip a missing authenticated prefix.
                    authenticated: dict[str, Mapping[str, Any]] = {}
                    for cursor, digest, path in sorted(group):
                        candidate_checks += 1
                        if candidate_checks > 256:
                            report["more_possible"] = True
                            report["candidate_limit_reached"] = True
                            return report
                        try:
                            payload, actual_digest = self._verify_capsule(_read(path))
                            if (actual_digest != digest or payload["sender_key_id"] != sender or payload["source_store_id"] != store
                                    or payload["after"] != expected or payload["cursor"] != cursor):
                                raise MemoryError("transfer_envelope_mismatch")
                        except (MemoryError, TrustError, OSError) as exc:
                            if len(report["rejected"]) < 32:
                                report["rejected"].append({"batch_sha256": digest, "code": getattr(exc, "code", "transfer_file_unavailable")})
                            # An unauthenticated filename cannot decide which
                            # trusted batch is next. Keep checking this prefix.
                            continue
                        authenticated[digest] = payload
                    if not authenticated:
                        break
                    if len(authenticated) != 1:
                        report["rejected"].append({"code": "authenticated_stream_fork"})
                        break  # A real signed fork needs operator resolution.
                    digest, payload = next(iter(authenticated.items()))
                    cursor = int(payload["cursor"])
                    try:
                        result = self.vault.ingest_records(
                            payload["records"], admission="verified", attestations=payload["attestations"],
                            transfer_id="xfer_" + digest, payload_sha256=digest,
                        )
                        self._bind_vault(state, missing_ok=False)
                    except (MemoryError, TrustError) as exc:
                        if len(report["rejected"]) < 32:
                            report["rejected"].append({"batch_sha256": digest, "code": exc.code})
                        break  # Leave evidence available for explicit inspection/retry.
                    state["received"][peer] = cursor
                    _write(self.state_path, state, replace=True)
                    expected = cursor
                    report["batches"] += 1
                    report["records_added"] += int(result["records_added"])
                    report["sender_blocked_records"] += len(payload["blocked"])
                    report["receipt_replays"] += int(bool(result.get("receipt_replayed", False)))
                    if report["batches"] >= maximum_batches:
                        report["more_possible"] = True
                        return report
            _write(self.state_path, state, replace=True)
        report["more_possible"] = False
        return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("publish", "receive", "acknowledge-published"))
    parser.add_argument("--vault", type=Path, required=True)
    parser.add_argument("--exchange", type=Path, required=True)
    parser.add_argument("--state-directory", type=Path, required=True)
    parser.add_argument("--trust-store", type=Path, required=True)
    parser.add_argument("--identity", type=Path)
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--maximum-bytes", type=int, default=256 * 1024)
    parser.add_argument("--maximum-batches", type=int, default=16)
    parser.add_argument("--attest-unsigned", action="store_true", help="explicitly attest exact unsigned bytes as the publisher, not as their original author")
    args = parser.parse_args(argv)
    try:
        endpoint = DirectoryTransfer(vault=args.vault, exchange=args.exchange, state_directory=args.state_directory,
                                     trust_store=args.trust_store, identity=args.identity)
        if args.action == "publish":
            result = endpoint.publish(limit=args.limit, maximum_bytes=args.maximum_bytes, attest_unsigned=args.attest_unsigned)
        elif args.action == "receive":
            if args.attest_unsigned:
                raise MemoryError("attestation_requires_publish")
            result = endpoint.receive(maximum_batches=args.maximum_batches)
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
