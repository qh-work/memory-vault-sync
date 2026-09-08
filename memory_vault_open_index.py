"""Node-local finite public-contact leases in an existing transport SQLite DB."""
from __future__ import annotations

import hashlib
import sqlite3
import threading
import time
from typing import Any, Mapping

from memory_vault import canonical_bytes
from memory_vault_network_crypto import document, document_sha256, integer
from memory_vault_open_control import (
    MAX_CONTROL_BYTES, MAX_DESCRIPTOR_SECONDS, MAX_LEASE_SECONDS,
    MAX_REQUEST_SECONDS, OpenControlError, contact_key, issue_lease,
    verify_contact, verify_node, verify_request,
)
from memory_vault_trust import Identity

FLOOR_RETENTION_SECONDS = MAX_DESCRIPTOR_SECONDS + MAX_REQUEST_SECONDS + 30


class OpenIndex:
    """No network calls, key generation, Vault access or independently opened DB.

    Each operation owns a short transaction. The caller must not supply a
    connection with an already active transaction or use it concurrently.
    Independent handles/processes serialize through SQLite's writer lock.
    """

    def __init__(self, connection: sqlite3.Connection, signer: Identity, node: Mapping[str, Any], *,
                 enabled: bool = False, maximum_records: int = 128,
                 maximum_bytes: int = 2 * 1024 * 1024, maximum_replays: int = 512,
                 maximum_lease_seconds: int = MAX_LEASE_SECONDS):
        if type(enabled) is not bool:
            raise OpenControlError("open_invalid_index_policy")
        limits = ((maximum_records, 65_536), (maximum_bytes, 64 * 1024 * 1024),
                  (maximum_replays, 65_536), (maximum_lease_seconds, MAX_LEASE_SECONDS))
        if any(integer(value, minimum=1) > ceiling for value, ceiling in limits):
            raise OpenControlError("open_invalid_index_policy")
        checked = verify_node(node, now=node["payload"]["issued_at"])
        if checked["signing_key"] != signer.public_descriptor():
            raise OpenControlError("open_wrong_node")
        self.connection, self.signer, self.node = connection, signer, document(node)
        self.enabled, self.maximum_records, self.maximum_bytes = enabled, maximum_records, maximum_bytes
        self.maximum_replays, self.maximum_lease_seconds = maximum_replays, maximum_lease_seconds
        self._lock = threading.RLock()

    def initialize(self) -> None:
        with self._lock:
            db = self.connection
            if db.in_transaction:
                raise OpenControlError("open_storage_transaction")
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute("CREATE TABLE IF NOT EXISTS open_index_state (name TEXT PRIMARY KEY,value TEXT NOT NULL)")
                db.execute("""CREATE TABLE IF NOT EXISTS open_contact_floors (
                    owner TEXT PRIMARY KEY, lookup_key TEXT NOT NULL UNIQUE,
                    revision INTEGER NOT NULL,digest TEXT NOT NULL,record BLOB NOT NULL,
                    second_digest TEXT,second_record BLOB,status TEXT NOT NULL,retain_until INTEGER NOT NULL)""")
                db.execute("""CREATE TABLE IF NOT EXISTS open_contacts (
                    owner TEXT PRIMARY KEY,record BLOB NOT NULL,lease BLOB NOT NULL,
                    lease_id TEXT NOT NULL,expires_at INTEGER NOT NULL)""")
                db.execute("""CREATE TABLE IF NOT EXISTS open_index_replay (
                    owner TEXT NOT NULL,request_id TEXT NOT NULL,digest TEXT NOT NULL,
                    response BLOB NOT NULL,retain_until INTEGER NOT NULL,
                    PRIMARY KEY(owner,request_id))""")
                db.execute("CREATE INDEX IF NOT EXISTS open_contact_expiry ON open_contacts(expires_at)")
                db.execute("CREATE INDEX IF NOT EXISTS open_floor_expiry ON open_contact_floors(retain_until)")
                db.execute("CREATE INDEX IF NOT EXISTS open_replay_expiry ON open_index_replay(retain_until)")
                expected = self.signer.key_id + ":" + self.node["payload"]["storage_epoch"]
                previous = db.execute("SELECT value FROM open_index_state WHERE name='binding'").fetchone()
                if previous is not None and previous[0] != expected:
                    raise OpenControlError("open_storage_epoch_mismatch")
                db.execute("INSERT OR IGNORE INTO open_index_state(name,value) VALUES('binding',?)", (expected,))
                db.commit()
            except BaseException:
                db.rollback()
                raise

    def _prune(self, now: int) -> None:
        self.connection.execute("DELETE FROM open_contacts WHERE expires_at<=?", (now,))
        self.connection.execute("DELETE FROM open_contact_floors WHERE retain_until<=? AND owner NOT IN (SELECT owner FROM open_contacts)", (now,))
        self.connection.execute("DELETE FROM open_index_replay WHERE retain_until<=?", (now,))

    def _capacity(self) -> None:
        db = self.connection
        records = db.execute("SELECT count(*) FROM open_contact_floors").fetchone()[0]
        replays = db.execute("SELECT count(*) FROM open_index_replay").fetchone()[0]
        # Reserve two maximum descriptors per floor so observing a same-revision
        # fork can always invalidate a previously accepted contact, even when
        # all unreserved capacity is full. This is reserved capacity, not a
        # claim that padding or two records physically exist on disk.
        floors = records * (2 * 4096 + 512)
        contacts = db.execute("SELECT coalesce(sum(length(record)+length(lease)+256),0) FROM open_contacts").fetchone()[0]
        replay_bytes = db.execute("SELECT coalesce(sum(length(response)+256),0) FROM open_index_replay").fetchone()[0]
        if records > self.maximum_records or replays > self.maximum_replays or floors + contacts + replay_bytes > self.maximum_bytes:
            raise OpenControlError("open_index_capacity", retryable=True)

    def _get(self, key: str, now: int) -> dict[str, Any]:
        floor = self.connection.execute(
            "SELECT owner,status FROM open_contact_floors WHERE lookup_key=?", (key,)).fetchone()
        if floor is None:
            return {"state": "not_found"}
        if floor[1] in {"revoked", "conflict"}:
            return {"state": floor[1]}
        row = self.connection.execute(
            "SELECT record,lease FROM open_contacts WHERE owner=? AND expires_at>?", (floor[0], now)).fetchone()
        if row is None:
            return {"state": "not_found"}
        return {"state": "found", "contact": document(bytes(row[0])), "lease": document(bytes(row[1]))}

    def handle(self, request: Mapping[str, Any] | bytes, *, now: int | None = None) -> dict[str, Any]:
        """Return the strict response body; the HTTP owner signs its outer reply.

        Replay returns the original signed lease bytes. A same-revision fork
        persists bounded evidence and a blocked state before reporting refusal.
        """
        current = int(time.time()) if now is None else integer(now)
        signed_request = document(request, maximum=MAX_CONTROL_BYTES)
        checked = verify_request(signed_request, node=self.node, now=current)
        if checked["action"] not in {"get", "put", "renew"}:
            raise OpenControlError("open_unsupported_action")
        if not self.enabled or "directory" not in self.node["payload"]["roles"]:
            raise OpenControlError("open_index_closed")
        failure = None
        with self._lock:
            db = self.connection
            if db.in_transaction:
                raise OpenControlError("open_storage_transaction")
            db.execute("BEGIN IMMEDIATE")
            try:
                # A wait for the writer lock must not extend request authority.
                current = int(time.time()) if now is None else integer(now)
                checked = verify_request(signed_request, node=self.node, now=current)
                self._prune(current)
                if checked["action"] == "get":
                    result = self._get(checked["body"]["key"], current)
                else:
                    result, failure = self._write(signed_request, checked, current)
                self._capacity()
                db.commit()
            except BaseException:
                db.rollback()
                raise
        if failure is not None:
            raise failure
        return result

    def _write(self, signed: Mapping[str, Any], request: Mapping[str, Any], now: int) -> tuple[dict[str, Any], OpenControlError | None]:
        db, body = self.connection, request["body"]
        contact = document(body["contact"])
        payload = verify_contact(contact, now=now)
        owner = payload["signing_key"]["key_id"]
        if request["signer"] != payload["signing_key"]:
            raise OpenControlError("open_index_not_owner")
        request_digest, contact_digest = document_sha256(signed), document_sha256(contact)
        old_request = db.execute("SELECT digest,response FROM open_index_replay WHERE owner=? AND request_id=?",
                                 (owner, request["request_id"])).fetchone()
        if old_request is not None:
            if old_request[0] != request_digest:
                raise OpenControlError("open_request_conflict")
            # A remembered lease is evidence of its original acceptance only.
            # Revocation/fork floors still gate public get and new writes.
            return document(bytes(old_request[1])), None
        if body["lease_seconds"] > self.maximum_lease_seconds:
            raise OpenControlError("open_index_lease_limit")
        floor = db.execute("SELECT revision,digest,record,status,retain_until,second_digest FROM open_contact_floors WHERE owner=?", (owner,)).fetchone()
        if floor is not None and floor[3] == "conflict":
            raise OpenControlError("open_contact_conflict")
        if floor is not None and payload["revision"] < floor[0]:
            raise OpenControlError("open_contact_rollback")
        if floor is not None and payload["revision"] == floor[0]:
            if contact_digest != floor[1]:
                # Preserve both original owner signatures; never select a
                # same-revision winner by arrival time or lexicographic hash.
                db.execute("UPDATE open_contact_floors SET second_digest=?,second_record=?,status='conflict',retain_until=? WHERE owner=?",
                           (contact_digest, canonical_bytes(contact), max(floor[4], now + FLOOR_RETENTION_SECONDS), owner))
                db.execute("DELETE FROM open_contacts WHERE owner=?", (owner,))
                return {}, OpenControlError("open_contact_conflict")
        if request["action"] == "renew":
            previous = db.execute("SELECT record,lease_id FROM open_contacts WHERE owner=?", (owner,)).fetchone()
            if (previous is None or previous[1] != body["lease_id"]
                    or document_sha256(document(bytes(previous[0]))) != contact_digest):
                raise OpenControlError("open_lease_not_found")
            lease_id = previous[1]
        else:
            lease_id = "lease_" + hashlib.sha256((self.signer.key_id + ":" + request_digest).encode("ascii")).hexdigest()
        lease = issue_lease(self.signer, node=self.node, contact=contact, request=signed,
                            lease_id=lease_id, issued_at=now,
                            expires_at=min(now + body["lease_seconds"], payload["expires_at"]))
        state = "active" if payload["status"] == "active" and payload["allow_discovery"] else "revoked"
        retained = max(payload["expires_at"] + MAX_REQUEST_SECONDS + 30, now + FLOOR_RETENTION_SECONDS,
                       floor[4] if floor is not None else 0)
        db.execute("""INSERT INTO open_contact_floors(owner,lookup_key,revision,digest,record,second_digest,second_record,status,retain_until)
                      VALUES(?,?,?,?,?,NULL,NULL,?,?) ON CONFLICT(owner) DO UPDATE SET
                      revision=excluded.revision,digest=excluded.digest,record=excluded.record,
                      second_digest=NULL,second_record=NULL,status=excluded.status,retain_until=excluded.retain_until""",
                   (owner, contact_key(owner), payload["revision"], contact_digest, canonical_bytes(contact), state, retained))
        if state == "active":
            db.execute("""INSERT INTO open_contacts(owner,record,lease,lease_id,expires_at) VALUES(?,?,?,?,?)
                          ON CONFLICT(owner) DO UPDATE SET record=excluded.record,lease=excluded.lease,
                          lease_id=excluded.lease_id,expires_at=excluded.expires_at""",
                       (owner, canonical_bytes(contact), canonical_bytes(lease), lease_id, lease["payload"]["expires_at"]))
        else:
            db.execute("DELETE FROM open_contacts WHERE owner=?", (owner,))
        result = {"lease": lease}
        db.execute("INSERT INTO open_index_replay(owner,request_id,digest,response,retain_until) VALUES(?,?,?,?,?)",
                   (owner, request["request_id"], request_digest, canonical_bytes(result), request["expires_at"] + 30))
        return result, None
