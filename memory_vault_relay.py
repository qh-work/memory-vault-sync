"""Opt-in, invitation-only ciphertext relay; never an execution authority.

The independent operator pins an issuer key and a signed roster in a private
configuration. The relay owns neither that issuer's private key nor any peer's
decryption key. SQLite tracks delivery, not memory ownership. No import starts
a server, changes host permissions, enrolls peers, or contacts the network.
"""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import hashlib
import hmac
import ipaddress
import os
from pathlib import Path
import secrets
import sqlite3
import sys
import threading
import time
from typing import Any, Iterator, Mapping
from urllib.parse import urlsplit

from memory_vault import MemoryError, canonical_bytes, strict_json_loads
from memory_vault_trust import Identity
import memory_vault_storage as storage
from memory_vault_network_crypto import (
    MAX_ENVELOPE_BYTES, PublicKeyTrust, digest, document, document_sha256,
    envelope_sha256, integer, object_fields, opaque, public_signing_key,
    verify_envelope,
)
from memory_vault_network_control import (
    create_join_challenge, verify_invite, verify_join_proof, verify_request,
    verify_roster, verify_status,
)

CONFIG_SCHEMA = "memory-vault-relay-config/v1"
DEFAULT_LIMITS = {
    "maximum_request_bytes": 8 * 1024 * 1024,
    "maximum_envelope_bytes": MAX_ENVELOPE_BYTES,
    "maximum_poll_bytes": 8 * 1024 * 1024,
    "maximum_messages": 4096,
    "maximum_object_bytes": 256 * 1024 * 1024,
    "maximum_members": 256,
    "maximum_control_rows": 256,
    "maximum_concurrency": 8,
}
_SCHEMA = """
CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS members (
 key_id TEXT PRIMARY KEY, encryption_key BLOB NOT NULL, scopes BLOB NOT NULL,
 invite_id TEXT UNIQUE);
CREATE TABLE IF NOT EXISTS invitations (
 invite_id TEXT PRIMARY KEY, invite_sha256 TEXT NOT NULL, request_sha256 TEXT NOT NULL,
 result BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS challenges (
 invite_id TEXT PRIMARY KEY, invite_sha256 TEXT NOT NULL, challenge_id TEXT NOT NULL,
 answer_sha256 TEXT NOT NULL, document BLOB NOT NULL, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS status_nonces (
 nonce TEXT PRIMARY KEY, expires_at INTEGER NOT NULL, status_sha256 TEXT, result BLOB);
CREATE TABLE IF NOT EXISTS messages (
 sequence INTEGER PRIMARY KEY AUTOINCREMENT, message_id TEXT NOT NULL UNIQUE,
 envelope_sha256 TEXT NOT NULL UNIQUE, object_bytes INTEGER NOT NULL,
 sender_key_id TEXT NOT NULL, roster BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS recipients (
 message_id TEXT NOT NULL REFERENCES messages(message_id), key_id TEXT NOT NULL,
 PRIMARY KEY(message_id,key_id));
CREATE INDEX IF NOT EXISTS recipient_mailbox ON recipients(key_id,message_id);
CREATE TABLE IF NOT EXISTS receipts (
 sequence INTEGER PRIMARY KEY AUTOINCREMENT,
 message_id TEXT NOT NULL REFERENCES messages(message_id), key_id TEXT NOT NULL,
 request_id TEXT NOT NULL, request_sha256 TEXT NOT NULL, document BLOB NOT NULL,
 result BLOB NOT NULL, UNIQUE(message_id,key_id), UNIQUE(key_id,request_id));
"""


class RelayError(MemoryError):
    pass


def _read(path: Path, maximum: int) -> bytes:
    fd = storage.open_file(path, os.O_RDONLY, private=True)
    with os.fdopen(fd, "rb") as stream:
        if os.fstat(stream.fileno()).st_size > maximum:
            raise RelayError("relay_file_too_large")
        value = stream.read(maximum + 1)
    if len(value) > maximum:
        raise RelayError("relay_file_too_large")
    return value


def _url(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 2048:
        raise RelayError("relay_invalid_url")
    parsed = urlsplit(value)
    if (parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username
            or parsed.password or parsed.query or parsed.fragment or parsed.path not in ("", "/")):
        raise RelayError("relay_invalid_url")
    try:
        loopback = ipaddress.ip_address(parsed.hostname).is_loopback
    except ValueError:
        loopback = parsed.hostname == "localhost"
    if parsed.scheme != "https" and not loopback:
        raise RelayError("relay_https_required")
    return value.rstrip("/")


def _wrapper(value: Mapping[str, Any], required: set[str], optional: set[str] = frozenset()) -> dict[str, Any]:
    if not isinstance(value, Mapping) or not required <= set(value) or set(value) - required - optional:
        raise RelayError("relay_invalid_request")
    return dict(value)


class Relay:
    """Synchronous durable relay; suitable for an explicit ASGI service or tests.

    Acknowledgments are recipient-signed claims of validated local storage.
    They never claim that an agent understood, acted on, or executed a message.
    All operations fail closed while independently signed roster status is stale.
    """

    def __init__(self, config_path: Path):
        self.config_path = storage.validate_path(Path(config_path))
        config = document(_read(self.config_path, 1024 * 1024), maximum=1024 * 1024)
        _wrapper(config, {"schema_version", "network_id", "issuer_public_key", "roster_path",
                          "state_directory", "base_url", "init_member_key_ids"},
                 {"require_join_key_ids", "authority_url", "limits", "node_identity_path", "storage_epoch"})
        if config["schema_version"] != CONFIG_SCHEMA:
            raise RelayError("relay_config_schema")
        self.network_id = opaque(config["network_id"])
        self.issuer = public_signing_key(config["issuer_public_key"])
        self.issuers = PublicKeyTrust([self.issuer])
        self.base_url = _url(config["base_url"])
        self.authority_url = _url(config["authority_url"]) if config.get("authority_url") else None
        if ("node_identity_path" in config) != ("storage_epoch" in config):
            raise RelayError("relay_node_identity_configuration_invalid")
        self.node_identity = (Identity.load(storage.validate_path(Path(config["node_identity_path"])))
                              if "node_identity_path" in config else None)
        self.storage_epoch = opaque(config["storage_epoch"]) if self.node_identity is not None else None
        self.limits = dict(DEFAULT_LIMITS)
        custom = config.get("limits", {})
        if not isinstance(custom, dict) or set(custom) - set(self.limits):
            raise RelayError("relay_invalid_limits")
        for name, value in custom.items():
            if not 1 <= integer(value) <= DEFAULT_LIMITS[name]:
                raise RelayError("relay_invalid_limits")
            self.limits[name] = value
        self.initial = self._key_ids(config["init_member_key_ids"])
        self.require_join = self._key_ids(config.get("require_join_key_ids", []))
        if self.initial & self.require_join:
            raise RelayError("relay_bootstrap_join_overlap")
        self.directory = storage.validate_path(Path(config["state_directory"]))
        self.object_directory = self.directory / "objects"
        self.database = self.directory / "relay.sqlite3"
        self.lock_path = self.directory / "relay.lock"
        self._lock = threading.Lock()
        roster = document(_read(storage.validate_path(Path(config["roster_path"])), 1024 * 1024))
        payload = verify_roster(roster, self.issuers, network_id=self.network_id, allow_expired=True)
        if len(payload["members"]) > self.limits["maximum_members"]:
            raise RelayError("relay_member_limit")
        bootstrap = self._members(payload)
        if any(key not in bootstrap or bootstrap[key]["status"] != "active" for key in self.initial):
            raise RelayError("relay_bootstrap_not_authorized")
        storage.private_directory(self.directory)
        storage.private_directory(self.object_directory)
        with self._transaction(initialize=True) as db:
            if self._get(db, "network_id") is None:
                self._set(db, "network_id", self.network_id)
                self._set(db, "issuer", self.issuer)
                self._set(db, "roster", roster)
                self._set(db, "initial_members", sorted(self.initial))
                for key in sorted(self.initial):
                    member = bootstrap[key]
                    db.execute("INSERT INTO members VALUES (?,?,?,NULL)",
                               (key, canonical_bytes(member["encryption_key"]), canonical_bytes(member["scope"])))
            elif (self._get(db, "network_id") != self.network_id or self._get(db, "issuer") != self.issuer
                  or self._get(db, "initial_members") != sorted(self.initial)):
                raise RelayError("relay_state_configuration_mismatch")
            node_binding = self.node_descriptor()
            saved_binding = self._get(db, "node_binding")
            if saved_binding is None and node_binding is not None:
                # Explicitly adding a node identity to an older local relay is
                # allowed; replacing an already bound key/epoch is not.
                self._set(db, "node_binding", node_binding)
            elif saved_binding != node_binding:
                raise RelayError("relay_node_identity_changed")

    def node_descriptor(self) -> dict[str, Any] | None:
        if self.node_identity is None:
            return None
        return {"signing_key": self.node_identity.public_descriptor(),
                "base_url": self.base_url, "storage_epoch": self.storage_epoch}

    def _node_current(self, db: sqlite3.Connection, action: str) -> Mapping[str, Any]:
        from memory_vault_nodes import authorized_node, verify_directory, verify_node_status
        if self.node_identity is None:
            raise RelayError("relay_node_identity_required")
        roster_doc, roster = self._current(db)
        directory, status = self._get(db, "node_directory"), self._get(db, "node_status")
        if directory is None or status is None:
            raise RelayError("relay_node_fresh_status_required", retryable=True)
        nodes = verify_directory(directory, self.issuers, network_id=self.network_id, allow_expired=True)
        verify_node_status(status, self.issuers, network_id=self.network_id, nonce=status["payload"]["nonce"],
                           roster_sha256=document_sha256(roster_doc), roster_version=roster["version"],
                           directory_sha256=document_sha256(directory), directory_version=nodes["version"])
        return authorized_node(nodes, self.node_identity.key_id, action,
                               base_url=self.base_url, storage_epoch=self.storage_epoch)

    def drain(self) -> Mapping[str, Any]:
        """Persist a write fence; never claim the node is safe to remove yet."""
        with self._transaction() as db:
            self._node_current(db, "export")
            existing = self._get(db, "draining")
            if existing is None:
                existing = {"state": "draining", "started_at": int(time.time()),
                            "messages": db.execute("SELECT COUNT(*) FROM messages").fetchone()[0],
                            "receipts": db.execute("SELECT COUNT(*) FROM receipts").fetchone()[0],
                            "members": db.execute("SELECT COUNT(*) FROM members").fetchone()[0]}
                self._set(db, "draining", existing)
            return {**existing, "safe_to_remove": False, "migration_required": True,
                    "source_data_deleted": False}

    def _writable(self, db: sqlite3.Connection) -> None:
        if self._get(db, "draining") is not None:
            raise RelayError("relay_draining", retryable=True)
        incoming = self._get(db, "node_transfer_import")
        if incoming is not None and incoming.get("state") == "receiving":
            raise RelayError("relay_node_import_in_progress", retryable=True)

    def transfer(self, value: Mapping[str, Any]) -> dict[str, Any]:
        from memory_vault_node_transfer import receive_transfer
        return receive_transfer(self, value)

    def _stored_result(self, result: dict[str, Any]) -> dict[str, Any]:
        if self.node_identity is None:
            return result
        payload = {"schema_version": "memory-vault-node-storage-receipt/v1", "network_id": self.network_id,
                   "node": self.node_descriptor(), "receipt": result}
        return {**result, "node_receipt": {"payload": payload, "proof": self.node_identity.sign_message(payload)}}

    @staticmethod
    def _key_ids(values: Any) -> set[str]:
        if not isinstance(values, list) or len(values) > 256 or any(not isinstance(v, str) for v in values):
            raise RelayError("relay_invalid_members")
        result = {opaque(v) for v in values}
        if len(result) != len(values):
            raise RelayError("relay_duplicate_members")
        return result

    @staticmethod
    def _members(roster: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
        return {member["signing_key"]["key_id"]: member for member in roster["members"]}

    @contextlib.contextmanager
    def _transaction(self, *, initialize: bool = False) -> Iterator[sqlite3.Connection]:
        if not self._lock.acquire(blocking=False):
            raise RelayError("relay_busy", retryable=True)
        try:
            with storage.file_lock(self.lock_path, busy_code="relay_busy"):
                storage.check_private_directory(self.directory)
                storage.check_private_directory(self.object_directory)
                for suffix in ("", "-wal", "-shm", "-journal"):
                    path = Path(str(self.database) + suffix)
                    if path.exists() or path.is_symlink():
                        fd = storage.open_file(path, os.O_RDONLY, private=True)
                        os.close(fd)
                if not self.database.exists():
                    fd = storage.open_file(self.database, os.O_RDWR | os.O_CREAT | os.O_EXCL, private=True)
                    os.close(fd)
                db = sqlite3.connect(self.database, timeout=0, isolation_level=None)
                db.row_factory = sqlite3.Row
                try:
                    db.execute("PRAGMA journal_mode=WAL")
                    db.execute("PRAGMA synchronous=FULL")
                    db.execute("PRAGMA foreign_keys=ON")
                    db.execute("PRAGMA wal_autocheckpoint=64")
                    # Delivery and signed control metadata have a separate hard
                    # ceiling; ciphertext quotas include crash-orphan objects.
                    db.execute("PRAGMA max_page_count=16384")
                    if initialize:
                        db.executescript(_SCHEMA)
                    db.execute("BEGIN IMMEDIATE")
                    yield db
                    db.execute("COMMIT")
                except BaseException:
                    if db.in_transaction:
                        db.execute("ROLLBACK")
                    raise
                finally:
                    db.close()
        except sqlite3.Error:
            raise RelayError("relay_storage_unavailable", retryable=True) from None
        finally:
            self._lock.release()

    @staticmethod
    def _get(db: sqlite3.Connection, key: str) -> Any:
        row = db.execute("SELECT value FROM metadata WHERE key=?", (key,)).fetchone()
        return strict_json_loads(row[0]) if row else None

    @staticmethod
    def _set(db: sqlite3.Connection, key: str, value: Any) -> None:
        db.execute("INSERT OR REPLACE INTO metadata VALUES (?,?)", (key, canonical_bytes(value)))

    def _current(self, db: sqlite3.Connection, *, fresh: bool = True) -> tuple[dict[str, Any], dict[str, Any]]:
        roster = self._get(db, "roster")
        payload = verify_roster(roster, self.issuers, network_id=self.network_id, allow_expired=True)
        if fresh:
            status = self._get(db, "status")
            if status is None:
                raise RelayError("relay_fresh_issuer_status_required", retryable=True)
            verify_status(status, self.issuers, network_id=self.network_id,
                          nonce=status["payload"]["nonce"], roster_sha256=document_sha256(roster),
                          roster_version=payload["version"])
        return roster, payload

    def _member(self, db: sqlite3.Connection, roster: Mapping[str, Any], key: str,
                scope: str | None = None) -> dict[str, Any]:
        if not isinstance(key, str):
            raise RelayError("relay_membership_required")
        member = self._members(roster).get(key)
        saved = db.execute("SELECT * FROM members WHERE key_id=?", (key,)).fetchone()
        if member is None or member["status"] != "active" or saved is None:
            raise RelayError("relay_membership_required")
        if strict_json_loads(saved["encryption_key"]) != member["encryption_key"]:
            raise RelayError("relay_member_key_changed")
        if scope and (scope not in member["scope"] or scope not in strict_json_loads(saved["scopes"])):
            raise RelayError("relay_scope_denied")
        return member

    def descriptor(self) -> dict[str, Any]:
        return {"schema_version": "memory-vault-agent-discovery/v1", "network_id": self.network_id,
                "service": "memory-vault-ciphertext-relay", "base_url": self.base_url,
                "authority_url": self.authority_url, "issuer_key_id": self.issuer["key_id"],
                "authentication": "issuer-invitation-and-peer-signatures", "end_to_end_encryption": True,
                "delivery": "at-least-once", "execution_authority": False,
                "endpoints": {"status": "/v1/status", "join": "/v1/join", "messages": "/v1/messages",
                              "poll": "/v1/poll", "ack": "/v1/ack"}, "limits": dict(self.limits),
                "receipt_states": ["stored", "validated_saved"], "receipt_is_understanding": False}

    def status_challenge(self) -> dict[str, Any]:
        now = int(time.time())
        with self._transaction() as db:
            db.execute("DELETE FROM status_nonces WHERE expires_at<=?", (now,))
            roster, payload = self._current(db, fresh=False)
            # GET is intentionally unauthenticated so a new endpoint can
            # refresh control state before sending. Reuse the one outstanding
            # challenge instead of allocating a row per GET; otherwise an
            # unauthenticated caller can exhaust the bounded control table.
            pending = db.execute(
                "SELECT nonce,expires_at FROM status_nonces "
                "WHERE status_sha256 IS NULL ORDER BY rowid LIMIT 1"
            ).fetchone()
            if pending is None:
                count = db.execute("SELECT COUNT(*) FROM status_nonces").fetchone()[0]
                if count >= self.limits["maximum_control_rows"]:
                    # Completed refreshes are only an idempotency cache. Keep
                    # the newest bounded history and make room for one live
                    # challenge; never evict an outstanding challenge.
                    remove = count - self.limits["maximum_control_rows"] + 1
                    db.execute(
                        "DELETE FROM status_nonces WHERE nonce IN "
                        "(SELECT nonce FROM status_nonces WHERE status_sha256 IS NOT NULL "
                        "ORDER BY rowid LIMIT ?)", (remove,)
                    )
                nonce, expires_at = secrets.token_hex(32), now + 300
                db.execute("INSERT INTO status_nonces(nonce,expires_at) VALUES (?,?)", (nonce, expires_at))
            else:
                nonce, expires_at = pending["nonce"], pending["expires_at"]
            result = {"nonce": nonce, "expires_at": expires_at, "current_roster_version": payload["version"],
                      "current_roster_sha256": document_sha256(roster)}
            if self.node_identity is not None:
                challenge = {"schema_version": "memory-vault-node-challenge/v1", "network_id": self.network_id,
                             "node": self.node_descriptor(), "nonce": nonce, "issued_at": now, "expires_at": expires_at}
                result["node_challenge"] = {"payload": challenge, "proof": self.node_identity.sign_message(challenge)}
            return result

    def update_status(self, value: Mapping[str, Any]) -> dict[str, Any]:
        raw = _wrapper(document(value, maximum=4 * 1024 * 1024), {"status"}, {"roster", "nodes", "node_status"})
        if ("nodes" in raw) != ("node_status" in raw):
            raise RelayError("relay_node_status_incomplete")
        status_doc = document(raw["status"], maximum=1024 * 1024)
        nonce = opaque(status_doc.get("payload", {}).get("nonce"))
        status_hash = document_sha256({"status": status_doc, "nodes": raw["nodes"], "node_status": raw["node_status"]}) if "nodes" in raw else document_sha256(status_doc)
        with self._transaction() as db:
            old_doc, old = self._current(db, fresh=False)
            candidate = raw.get("roster", old_doc)
            candidate_hash = document_sha256(candidate)
            roster = verify_roster(candidate, self.issuers, network_id=self.network_id,
                                   minimum_version=old["version"], allow_expired=True)
            if len(roster["members"]) > self.limits["maximum_members"]:
                raise RelayError("relay_member_limit")
            if roster["version"] == old["version"] and candidate_hash != document_sha256(old_doc):
                raise RelayError("relay_roster_version_conflict")
            # Match endpoint checks for an adjacent checkpoint. After a gap,
            # the pinned issuer's fresh nonce-bound status authorizes its
            # latest snapshot; unavailable intermediate links are not invented.
            if (roster["version"] == old["version"] + 1
                    and roster["previous_sha256"] != document_sha256(old_doc)):
                raise RelayError("network_roster_chain_mismatch")
            challenge = db.execute("SELECT * FROM status_nonces WHERE nonce=?", (nonce,)).fetchone()
            if challenge is None or challenge["expires_at"] <= int(time.time()):
                raise RelayError("relay_status_nonce_required")
            status = verify_status(status_doc, self.issuers, network_id=self.network_id, nonce=nonce,
                                   roster_sha256=candidate_hash, roster_version=roster["version"])
            if "nodes" in raw:
                from memory_vault_nodes import authorized_node, verify_directory, verify_node_status
                nodes = verify_directory(raw["nodes"], self.issuers, network_id=self.network_id,
                    previous_directory=self._get(db, "node_directory"), allow_expired=True)
                node_status = verify_node_status(raw["node_status"], self.issuers, network_id=self.network_id,
                    nonce=nonce, roster_sha256=candidate_hash, roster_version=roster["version"],
                    directory_sha256=document_sha256(raw["nodes"]), directory_version=nodes["version"])
                old_node_status = self._get(db, "node_status")
                if old_node_status and node_status["issued_at"] < old_node_status["payload"]["issued_at"]:
                    raise RelayError("relay_node_status_rollback")
                if self.node_identity is not None:
                    authorized_node(nodes, self.node_identity.key_id, "refresh",
                                    base_url=self.base_url, storage_epoch=self.storage_epoch)
            if challenge["status_sha256"] is not None:
                result = strict_json_loads(challenge["result"])
                # Several authorized endpoints can receive the one shared
                # pending challenge concurrently. Their issuer responses may
                # differ only by signed issuance time. After fully verifying
                # the new response above, treat an equivalent roster/node
                # snapshot as the same refresh; reject any control-state
                # difference under the consumed nonce.
                same_roster = (result.get("roster_version") == roster["version"]
                               and result.get("roster_sha256") == candidate_hash)
                saved_nodes = self._get(db, "node_directory")
                same_nodes = (("nodes" in raw and saved_nodes == raw["nodes"])
                              or ("nodes" not in raw and saved_nodes is None))
                if challenge["status_sha256"] != status_hash and not (same_roster and same_nodes):
                    raise RelayError("relay_status_nonce_conflict")
                return result
            previous_status = self._get(db, "status")
            if previous_status and status["issued_at"] < previous_status["payload"]["issued_at"]:
                raise RelayError("relay_status_rollback")
            result = {"state": "fresh", "roster_version": roster["version"],
                      "roster_sha256": candidate_hash, "expires_at": status["expires_at"]}
            self._set(db, "roster", candidate)
            self._set(db, "status", status_doc)
            if "nodes" in raw:
                self._set(db, "node_directory", raw["nodes"])
                self._set(db, "node_status", raw["node_status"])
            db.execute("UPDATE status_nonces SET status_sha256=?,result=? WHERE nonce=?",
                       (status_hash, canonical_bytes(result), nonce))
            return result

    def join(self, value: Mapping[str, Any]) -> dict[str, Any]:
        raw = _wrapper(document(value, maximum=3 * 1024 * 1024), {"invite", "roster"}, {"request"})
        invite_hash = document_sha256(raw["invite"])
        request_hash = document_sha256(raw["request"]) if "request" in raw else None
        with self._transaction() as db:
            _, current = self._current(db)
            # Exact successful retry is a lookup, not renewed authorization.
            # The original verified bytes must match and the member must still
            # be active. It remains safe after a request/invitation expires.
            invite_id = opaque(raw["invite"].get("payload", {}).get("invite_id"))
            consumed = db.execute("SELECT * FROM invitations WHERE invite_id=?", (invite_id,)).fetchone()
            if consumed:
                if consumed["invite_sha256"] != invite_hash or consumed["request_sha256"] != request_hash:
                    raise RelayError("relay_invite_already_consumed")
                result = strict_json_loads(consumed["result"])
                self._member(db, current, result["member_key_id"])
                return result
            self._writable(db)
            invite = verify_invite(raw["invite"], self.issuers, network_id=self.network_id)
            roster_hash = document_sha256(raw["roster"])
            roster = verify_roster(raw["roster"], self.issuers, network_id=self.network_id, allow_expired=True)
            if invite["roster_sha256"] != roster_hash or roster["version"] > current["version"]:
                raise RelayError("relay_invite_roster_mismatch")
            key = invite["candidate_signing_key"]["key_id"]
            expected = {"signing_key": invite["candidate_signing_key"], "encryption_key": invite["candidate_encryption_key"],
                        "scope": invite["scope"], "status": "active"}
            if self._members(roster).get(key) != expected or self._members(current).get(key) != expected:
                raise RelayError("relay_invite_candidate_mismatch")
            if db.execute("SELECT 1 FROM members WHERE key_id=?", (key,)).fetchone():
                raise RelayError("relay_member_already_joined")
            now = int(time.time())
            challenge = db.execute("SELECT * FROM challenges WHERE invite_id=?", (invite_id,)).fetchone()
            if challenge and challenge["invite_sha256"] != invite_hash:
                raise RelayError("relay_invite_id_conflict")
            if "request" not in raw:
                if challenge and challenge["expires_at"] > now:
                    return {"state": "challenge", "challenge": strict_json_loads(challenge["document"])}
                db.execute("DELETE FROM challenges WHERE expires_at<=?", (now,))
                if db.execute("SELECT COUNT(*) FROM challenges").fetchone()[0] >= self.limits["maximum_control_rows"]:
                    raise RelayError("relay_join_challenge_limit", retryable=True)
                challenge_doc, answer = create_join_challenge(invite, challenge_id=secrets.token_hex(32),
                    issued_at=now, expires_at=min(now + 300, invite["expires_at"]))
                db.execute("INSERT INTO challenges VALUES (?,?,?,?,?,?)",
                           (invite_id, invite_hash, challenge_doc["challenge_id"],
                            hashlib.sha256(answer.encode("ascii")).hexdigest(), canonical_bytes(challenge_doc),
                            challenge_doc["expires_at"]))
                return {"state": "challenge", "challenge": challenge_doc}
            if challenge is None or challenge["expires_at"] <= now:
                raise RelayError("relay_join_challenge_required")
            verify_join_proof(raw["request"], invite, challenge_id=challenge["challenge_id"],
                              answer_sha256=challenge["answer_sha256"], invite_sha256=invite_hash)
            if db.execute("SELECT COUNT(*) FROM members").fetchone()[0] >= self.limits["maximum_members"]:
                raise RelayError("relay_member_limit")
            if db.execute("SELECT COUNT(*) FROM invitations").fetchone()[0] >= self.limits["maximum_control_rows"]:
                raise RelayError("relay_invitation_history_limit")
            result = {"state": "joined", "network_id": self.network_id, "member_key_id": key,
                      "invite_id": invite_id, "roster_version": current["version"]}
            db.execute("INSERT INTO members VALUES (?,?,?,?)", (key, canonical_bytes(expected["encryption_key"]),
                       canonical_bytes(expected["scope"]), invite_id))
            db.execute("INSERT INTO invitations VALUES (?,?,?,?)",
                       (invite_id, invite_hash, request_hash, canonical_bytes(result)))
            db.execute("DELETE FROM challenges WHERE invite_id=?", (invite_id,))
            return result

    def _historical(self, db: sqlite3.Connection, current: Mapping[str, Any], envelope: Mapping[str, Any],
                    historical: Mapping[str, Any]) -> dict[str, Any]:
        roster = verify_roster(historical, self.issuers, network_id=self.network_id, allow_expired=True)
        if (roster["version"] > current["version"] or roster["version"] != envelope["roster_version"]
                or document_sha256(historical) != envelope["roster_sha256"]):
            raise RelayError("relay_envelope_roster_mismatch")
        peers = self._members(roster)
        for key, scope in [(envelope["sender_key_id"], "send")] + [(key, "receive") for key in envelope["recipient_key_ids"]]:
            active = self._member(db, current, key, scope)
            old = peers.get(key)
            if (old is None or old["status"] != "active" or scope not in old["scope"]
                    or old["signing_key"] != active["signing_key"] or old["encryption_key"] != active["encryption_key"]):
                raise RelayError("relay_envelope_member_changed")
        return roster

    def _object_usage(self) -> tuple[int, int]:
        count, size = 0, 0
        for path in self.object_directory.iterdir():
            fd = storage.open_file(path, os.O_RDONLY, private=True)
            try:
                size += os.fstat(fd).st_size
                count += 1
            finally:
                os.close(fd)
        return count, size

    def post_message(self, value: Mapping[str, Any]) -> dict[str, Any]:
        raw = _wrapper(document(value, maximum=self.limits["maximum_request_bytes"]), {"envelope"}, {"roster"})
        envelope = document(raw["envelope"], maximum=self.limits["maximum_envelope_bytes"])
        encoded = canonical_bytes(envelope)
        content_hash = envelope_sha256(envelope)
        with self._transaction() as db:
            current_doc, current = self._current(db)
            trust = PublicKeyTrust([m["signing_key"] for m in current["members"] if m["status"] == "active"])
            payload = verify_envelope(envelope, trust, network_id=self.network_id)
            existing = db.execute("SELECT * FROM messages WHERE message_id=?", (payload["message_id"],)).fetchone()
            if existing and existing["envelope_sha256"] != content_hash:
                raise RelayError("relay_message_id_conflict")
            historical = raw.get("roster")
            if historical is None:
                if existing:
                    historical = strict_json_loads(existing["roster"])
                elif payload["roster_sha256"] == document_sha256(current_doc):
                    historical = current_doc
                else:
                    raise RelayError("relay_historical_roster_required")
            previous = self._historical(db, current, payload, historical)
            # JWE recipient routing must correspond exactly to the separately
            # signed roster's encryption keys, never unbound relay-selected keys.
            expected_kids = {self._members(previous)[key]["encryption_key"]["key_id"] for key in payload["recipient_key_ids"]}
            actual_kids = [recipient.get("header", {}).get("kid") for recipient in payload["jwe"]["recipients"]]
            if len(actual_kids) != len(expected_kids) or set(actual_kids) != expected_kids:
                raise RelayError("relay_encryption_recipients_mismatch")
            object_path = self.object_directory / (content_hash + ".json")
            if existing:
                if not hmac.compare_digest(_read(object_path, self.limits["maximum_envelope_bytes"]), encoded):
                    raise RelayError("relay_stored_object_corrupt")
                return self._stored_result({"state": "stored", "message_id": payload["message_id"], "envelope_sha256": content_hash,
                                            "sequence": existing["sequence"]})
            self._writable(db)
            count, size = self._object_usage()
            orphan_exists = object_path.exists()
            if ((count + (0 if orphan_exists else 1)) > self.limits["maximum_messages"]
                    or size + (0 if orphan_exists else len(encoded)) > self.limits["maximum_object_bytes"]):
                raise RelayError("relay_queue_full", retryable=True)
            if object_path.exists():
                if not hmac.compare_digest(_read(object_path, self.limits["maximum_envelope_bytes"]), encoded):
                    raise RelayError("relay_stored_object_corrupt")
                # An earlier rename can have succeeded before directory fsync
                # failed. Matching orphan bytes alone are not a durability
                # barrier: republish the exact bytes before committing a row.
                storage.atomic_write(object_path, encoded, replace=True)
            else:
                # fsync + no-replace publication precede the SQLite commit.
                # A crash may leave a counted orphan, never a successful DB row
                # whose ciphertext was still only in volatile memory.
                storage.atomic_write(object_path, encoded, replace=False)
            cursor = db.execute("INSERT INTO messages(message_id,envelope_sha256,object_bytes,sender_key_id,roster) VALUES (?,?,?,?,?)",
                (payload["message_id"], content_hash, len(encoded), payload["sender_key_id"], canonical_bytes(historical)))
            db.executemany("INSERT INTO recipients VALUES (?,?)", [(payload["message_id"], key) for key in payload["recipient_key_ids"]])
            return self._stored_result({"state": "stored", "message_id": payload["message_id"], "envelope_sha256": content_hash,
                                        "sequence": cursor.lastrowid})

    def _request(self, db: sqlite3.Connection, current: Mapping[str, Any], value: Mapping[str, Any],
                 action: str, *, scope: str | None = None) -> tuple[str, dict[str, Any]]:
        key = value.get("proof", {}).get("key_id")
        member = self._member(db, current, key, scope)
        request = verify_request(value, PublicKeyTrust([member["signing_key"]]), network_id=self.network_id, action=action)
        return key, request

    def poll(self, value: Mapping[str, Any]) -> dict[str, Any]:
        raw = document(value, maximum=1024 * 1024)
        with self._transaction() as db:
            _, current = self._current(db)
            key, request = self._request(db, current, raw, "poll")
            body = object_fields(request["body"], {"cursor", "receipt_cursor", "limit", "maximum_bytes"})
            cursor, receipt_cursor = integer(body["cursor"]), integer(body["receipt_cursor"])
            limit, maximum = integer(body["limit"], minimum=1), integer(body["maximum_bytes"], minimum=1)
            if limit > 32 or maximum > self.limits["maximum_poll_bytes"]:
                raise RelayError("relay_poll_budget_exceeded")
            member = self._member(db, current, key)
            grant = strict_json_loads(db.execute("SELECT scopes FROM members WHERE key_id=?", (key,)).fetchone()[0])
            scopes = set(member["scope"]) & set(grant)
            result: dict[str, Any] = {"messages": [], "cursor": cursor, "receipts": [],
                                      "receipt_cursor": receipt_cursor, "has_more": False}
            rows = db.execute("SELECT m.* FROM messages m JOIN recipients r USING(message_id) WHERE r.key_id=? AND m.sequence>? ORDER BY m.sequence LIMIT ?",
                              (key, cursor, limit + 1)).fetchall() if "receive" in scopes else []
            for row in rows[:limit]:
                envelope = document(_read(self.object_directory / (row["envelope_sha256"] + ".json"),
                                          self.limits["maximum_envelope_bytes"]))
                if envelope_sha256(envelope) != row["envelope_sha256"]:
                    raise RelayError("relay_stored_object_corrupt")
                # Revoked/key-rotated messages are not re-delivered. Cursor is
                # still advanced over them so a stale sender cannot block a
                # recipient's newer valid deliveries indefinitely.
                try:
                    self._historical(db, current, envelope, strict_json_loads(row["roster"]))
                except RelayError as exc:
                    if exc.code not in {"relay_membership_required", "relay_member_key_changed", "relay_scope_denied", "relay_envelope_member_changed"}:
                        raise
                    result["cursor"] = row["sequence"]
                    continue
                candidate = {**result, "messages": result["messages"] + [envelope], "cursor": row["sequence"]}
                if len(canonical_bytes(candidate)) > maximum:
                    if not result["messages"]:
                        raise RelayError("relay_poll_budget_too_small", retryable=True)
                    result["has_more"] = True
                    break
                result = candidate
            else:
                result["has_more"] = len(rows) > limit
            receipts = db.execute("SELECT a.* FROM receipts a JOIN messages m USING(message_id) WHERE m.sender_key_id=? AND a.sequence>? ORDER BY a.sequence LIMIT ?",
                                  (key, receipt_cursor, limit + 1)).fetchall() if "send" in scopes else []
            for receipt in receipts[:limit]:
                candidate = {**result, "receipts": result["receipts"] + [strict_json_loads(receipt["document"])],
                             "receipt_cursor": receipt["sequence"]}
                if len(canonical_bytes(candidate)) > maximum:
                    if not result["messages"] and not result["receipts"]:
                        raise RelayError("relay_poll_budget_too_small", retryable=True)
                    result["has_more"] = True
                    break
                result = candidate
            else:
                result["has_more"] = result["has_more"] or len(receipts) > limit
            if len(canonical_bytes(result)) > maximum:
                raise RelayError("relay_poll_budget_too_small", retryable=True)
            return result

    def ack(self, value: Mapping[str, Any]) -> dict[str, Any]:
        raw = document(value, maximum=1024 * 1024)
        request_hash = document_sha256(raw)
        with self._transaction() as db:
            _, current = self._current(db)
            key = raw.get("proof", {}).get("key_id")
            self._member(db, current, key, "receive")
            exact = db.execute("SELECT * FROM receipts WHERE key_id=? AND request_sha256=?", (key, request_hash)).fetchone()
            if exact:
                return strict_json_loads(exact["result"])
            self._writable(db)
            key, request = self._request(db, current, raw, "ack", scope="receive")
            body = object_fields(request["body"], {"message_id", "envelope_sha256", "state"})
            message_id, content_hash = opaque(body["message_id"]), digest(body["envelope_sha256"])
            if body["state"] != "validated_saved":
                raise RelayError("relay_receipt_state_rejected")
            row = db.execute("SELECT m.* FROM messages m JOIN recipients r USING(message_id) WHERE m.message_id=? AND r.key_id=?",
                             (message_id, key)).fetchone()
            if row is None or row["envelope_sha256"] != content_hash:
                raise RelayError("relay_receipt_message_mismatch")
            if db.execute("SELECT 1 FROM receipts WHERE key_id=? AND request_id=?",
                          (key, request["request_id"])).fetchone():
                raise RelayError("relay_receipt_id_conflict")
            existing = db.execute("SELECT result FROM receipts WHERE key_id=? AND message_id=?",
                                  (key, message_id)).fetchone()
            if existing:
                # A restored endpoint retains its identity but intentionally
                # starts without delivery cursors or the old signed request.
                # A fresh, independently verified claim for the same stored
                # ciphertext is idempotent. Preserve the original proof and
                # sequence; never replace them with the retry's signature.
                return strict_json_loads(existing["result"])
            result = {"state": "validated_saved", "message_id": message_id, "envelope_sha256": content_hash,
                      "recipient_key_id": key}
            cursor = db.execute("INSERT INTO receipts(message_id,key_id,request_id,request_sha256,document,result) VALUES (?,?,?,?,?,?)",
                                (message_id, key, request["request_id"], request_hash, canonical_bytes(raw), b"{}"))
            result["receipt_sequence"] = cursor.lastrowid
            db.execute("UPDATE receipts SET result=? WHERE sequence=?", (canonical_bytes(result), cursor.lastrowid))
            return result


def create_app(config_path: Path) -> Any:
    """Create, but do not start, an explicitly configured optional ASGI app."""
    try:
        from starlette.applications import Starlette
        from starlette.concurrency import run_in_threadpool
        from starlette.responses import JSONResponse
        from starlette.routing import Route
    except ImportError:
        raise RelayError("relay_web_dependency_unavailable") from None
    relay = Relay(config_path)
    gate = threading.BoundedSemaphore(relay.limits["maximum_concurrency"])

    async def endpoint(request: Any) -> Any:
        if not gate.acquire(blocking=False):
            return JSONResponse({"error": {"code": "relay_busy", "retryable": True}}, status_code=429)
        try:
            if request.method == "GET":
                operation = relay.descriptor if request.url.path == "/.well-known/agent-memory.json" else relay.status_challenge
                return JSONResponse(await run_in_threadpool(operation), headers={"Cache-Control": "no-store"})
            if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
                raise RelayError("relay_json_required")
            if request.headers.get("content-encoding", "identity") != "identity":
                raise RelayError("relay_content_encoding_rejected")
            async def read_body() -> bytes:
                data = bytearray()
                async for chunk in request.stream():
                    if len(data) + len(chunk) > relay.limits["maximum_request_bytes"]:
                        raise RelayError("relay_request_too_large")
                    data.extend(chunk)
                return bytes(data)
            try:
                data = await asyncio.wait_for(read_body(), timeout=10)
            except asyncio.TimeoutError:
                raise RelayError("relay_request_timeout", retryable=True) from None
            value = document(data, maximum=relay.limits["maximum_request_bytes"])
            operation = {"/v1/status": relay.update_status, "/v1/join": relay.join,
                         "/v1/messages": relay.post_message, "/v1/poll": relay.poll, "/v1/ack": relay.ack,
                         "/v1/node-transfer": relay.transfer}[request.url.path]
            return JSONResponse(await run_in_threadpool(operation, value), headers={"Cache-Control": "no-store"})
        except (MemoryError, storage.StorageError) as exc:
            code = exc.code
            retryable = getattr(exc, "retryable", False)
            status = 429 if code in {"relay_busy", "relay_queue_full", "relay_status_challenge_limit", "relay_join_challenge_limit"} else 400
            return JSONResponse({"error": {"code": code, "retryable": retryable}}, status_code=status,
                                headers={"Cache-Control": "no-store"})
        except (ValueError, TypeError, KeyError, AttributeError, OSError):
            # Never expose configuration paths, SQL details or incoming bytes.
            return JSONResponse({"error": {"code": "relay_invalid_or_unavailable", "retryable": False}}, status_code=400)
        finally:
            gate.release()

    app = Starlette(routes=[Route("/.well-known/agent-memory.json", endpoint, methods=["GET"]),
                            Route("/v1/status", endpoint, methods=["GET", "POST"]),
                            *[Route("/v1/" + name, endpoint, methods=["POST"]) for name in ("join", "messages", "poll", "ack", "node-transfer")]])
    app.state.relay = relay
    return app


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Explicit invitation-only E2EE ciphertext relay")
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve")
    serve.add_argument("--config", type=Path, required=True)
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--tls-certfile", type=Path)
    serve.add_argument("--tls-keyfile", type=Path)
    args = parser.parse_args(argv)
    try:
        if not 1024 <= args.port <= 65535:
            raise RelayError("relay_nonprivileged_port_required")
        try:
            loopback = ipaddress.ip_address(args.host).is_loopback
        except ValueError:
            loopback = args.host == "localhost"
        if (args.tls_certfile is None) != (args.tls_keyfile is None):
            raise RelayError("relay_tls_certificate_and_key_required")
        if not loopback and args.tls_certfile is None:
            raise RelayError("relay_external_listener_requires_tls")
        tls: dict[str, str] = {}
        if args.tls_certfile is not None:
            import ssl
            cert = storage.validate_path(args.tls_certfile)
            key = storage.validate_path(args.tls_keyfile)
            for path, private in ((cert, False), (key, True)):
                descriptor = storage.open_file(path, os.O_RDONLY, private=private)
                os.close(descriptor)
            try:
                ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(cert, key)
            except (OSError, ssl.SSLError):
                raise RelayError("relay_tls_configuration_invalid") from None
            tls = {"ssl_certfile": str(cert), "ssl_keyfile": str(key)}
        app = create_app(args.config)
        if tls and not app.state.relay.base_url.startswith("https://"):
            raise RelayError("relay_tls_public_url_required")
        try:
            from uvicorn import run
        except ImportError:
            raise RelayError("relay_web_dependency_unavailable") from None
        run(app, host=args.host, port=args.port, access_log=False, limit_concurrency=app.state.relay.limits["maximum_concurrency"],
            timeout_keep_alive=5, proxy_headers=False, **tls)
        return 0
    except (MemoryError, storage.StorageError) as exc:
        sys.stderr.write(canonical_bytes({"error": {"code": exc.code, "retryable": getattr(exc, "retryable", False)}}).decode() + "\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
