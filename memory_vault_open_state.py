"""Durable local observation floors for self-signed open control descriptors."""
from __future__ import annotations

import sqlite3
import threading
import time
from typing import Any, Mapping

from memory_vault import canonical_bytes
from memory_vault_network_crypto import document, document_sha256, integer
from memory_vault_open_control import (
    MAX_DESCRIPTOR_BYTES, MAX_DESCRIPTOR_SECONDS, MAX_REQUEST_SECONDS,
    OpenControlError, verify_contact, verify_node,
)

FLOOR_RETENTION_SECONDS = MAX_DESCRIPTOR_SECONDS + MAX_REQUEST_SECONDS + 30
MAX_FLOORS = 4096
MAX_STATE_BYTES = 64 * 1024 * 1024
RESERVED_BYTES_PER_FLOOR = 2 * MAX_DESCRIPTOR_BYTES + 512


class OpenCheckpoints:
    """Uses an existing transport connection; does not own an identity or Vault.

    Only active, nonconflicting descriptors return successfully. Revocations
    and the first fork are committed before their typed refusal is raised.
    A signed higher revision cannot automatically settle an observed fork.
    """

    def __init__(self, connection: sqlite3.Connection, *, maximum_records: int = MAX_FLOORS,
                 maximum_bytes: int = MAX_STATE_BYTES):
        if (integer(maximum_records, minimum=1) > MAX_FLOORS or
                integer(maximum_bytes, minimum=1) > MAX_STATE_BYTES):
            raise OpenControlError("open_invalid_checkpoint_policy")
        self.connection, self.maximum_records, self.maximum_bytes = connection, maximum_records, maximum_bytes
        self._lock = threading.RLock()

    def initialize(self) -> None:
        with self._lock:
            db = self.connection
            if db.in_transaction:
                raise OpenControlError("open_storage_transaction")
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute("""CREATE TABLE IF NOT EXISTS open_control_floors (
                    kind TEXT NOT NULL,key_id TEXT NOT NULL,revision INTEGER NOT NULL,
                    digest TEXT NOT NULL,record BLOB NOT NULL,second_digest TEXT,second_record BLOB,
                    status TEXT NOT NULL,retain_until INTEGER NOT NULL,PRIMARY KEY(kind,key_id))""")
                db.execute("CREATE INDEX IF NOT EXISTS open_control_floor_expiry ON open_control_floors(retain_until)")
                db.commit()
            except BaseException:
                db.rollback()
                raise

    @staticmethod
    def _verify(signed: Mapping[str, Any], now: int) -> dict[str, Any]:
        payload = signed.get("payload")
        if not isinstance(payload, Mapping):
            raise OpenControlError("open_unsupported_control")
        kind = payload.get("kind")
        if kind == "node":
            return verify_node(signed, now=now)
        if kind == "contact":
            return verify_contact(signed, now=now)
        raise OpenControlError("open_unsupported_control")

    def accept(self, signed_descriptor: Mapping[str, Any] | bytes, *, now: int | None = None) -> dict[str, Any]:
        signed = document(signed_descriptor, maximum=MAX_DESCRIPTOR_BYTES)
        current = int(time.time()) if now is None else integer(now)
        payload = self._verify(signed, current)
        failure = None
        with self._lock:
            db = self.connection
            if db.in_transaction:
                raise OpenControlError("open_storage_transaction")
            db.execute("BEGIN IMMEDIATE")
            try:
                current = int(time.time()) if now is None else integer(now)
                payload = self._verify(signed, current)
                db.execute("DELETE FROM open_control_floors WHERE retain_until<=?", (current,))
                key = (payload["kind"], payload["signing_key"]["key_id"])
                previous = db.execute("SELECT revision,digest,status,retain_until FROM open_control_floors WHERE kind=? AND key_id=?", key).fetchone()
                fingerprint = document_sha256(signed)
                retained = max(current + FLOOR_RETENTION_SECONDS, payload["expires_at"] + MAX_REQUEST_SECONDS + 30,
                               previous[3] if previous is not None else 0)
                if previous is not None and previous[2] == "conflict":
                    raise OpenControlError("open_control_conflict")
                if previous is not None and payload["revision"] < previous[0]:
                    raise OpenControlError("open_control_rollback")
                if previous is not None and payload["revision"] == previous[0] and fingerprint != previous[1]:
                    db.execute("UPDATE open_control_floors SET status='conflict',second_digest=?,second_record=?,retain_until=? WHERE kind=? AND key_id=?",
                               (fingerprint, canonical_bytes(signed), retained, *key))
                    failure = OpenControlError("open_control_conflict")
                else:
                    db.execute("""INSERT INTO open_control_floors(kind,key_id,revision,digest,record,status,retain_until)
                                  VALUES(?,?,?,?,?,?,?) ON CONFLICT(kind,key_id) DO UPDATE SET
                                  revision=excluded.revision,digest=excluded.digest,record=excluded.record,
                                  status=excluded.status,retain_until=excluded.retain_until""",
                               (*key, payload["revision"], fingerprint, canonical_bytes(signed), payload["status"], retained))
                    if payload["status"] == "revoked":
                        failure = OpenControlError("open_control_revoked")
                count = db.execute("SELECT count(*) FROM open_control_floors").fetchone()[0]
                if count > self.maximum_records or count * RESERVED_BYTES_PER_FLOOR > self.maximum_bytes:
                    raise OpenControlError("open_checkpoint_capacity", retryable=True)
                db.commit()
            except BaseException:
                db.rollback()
                raise
        if failure is not None:
            raise failure
        return payload
