"""One durable reservation envelope for open services sharing a transport DB.

This accounts promised storage and bounded service metadata, not filesystem
pages, WAL growth, free disk, throughput or remote physical capacity. Existing
oversubscribed obligations survive migration; only new reservations are denied.
All mutations belong to the caller's transaction. Triggers cover other writers
of the same legacy service tables, including native service implementations.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import sqlite3

from memory_vault import MemoryError
from memory_vault_network_crypto import document

SCHEMA = "memory-vault-open-capacity/v1"
_SCHEMA_DATA = json.loads(Path(__file__).with_name("memory_vault_open_capacity_schema.json").read_text(encoding="utf-8"))
if _SCHEMA_DATA["schema_version"] != SCHEMA:
    raise MemoryError("open_capacity_schema_mismatch")
DEFAULT_POLICY = _SCHEMA_DATA["default_policy"]
U53_MAX = 9007199254740991
# Node-wide SQL maxima: contact challenges <=1 MiB; delivery possessions
# <=512*(8192+1024), read handles <=256*(4096+1024), plus row/index allowance.
SERVICE_RESERVE_BYTES = _SCHEMA_DATA["charges"]["service_reserve_bytes"]
PROVIDER_LEASE_BYTES = _SCHEMA_DATA["charges"]["provider_lease_bytes"]
PROVIDER_REPLAY_BYTES = _SCHEMA_DATA["charges"]["provider_replay_bytes"]
CONTACT_LEASE_BYTES = _SCHEMA_DATA["charges"]["contact_lease_bytes"]
# 2*49152 upload intents + 3*4096 descriptor/receipts + 20 KiB references,
# <=24 chunk rows and bookkeeping. Delivery body stays reserved only once.
DELIVERY_ITEM_BYTES = _SCHEMA_DATA["charges"]["delivery_item_bytes"]
RESERVATION_TABLES = _SCHEMA_DATA["reservation_tables"]
CAPACITY_TABLES = tuple(_SCHEMA_DATA["capacity_tables"])
TRIGGERS = tuple(_SCHEMA_DATA["triggers"])


def _fail(code):
    raise MemoryError("open_capacity_" + code)


def _number(value, minimum=0):
    if type(value) is not int or not minimum <= value <= U53_MAX:
        _fail("invalid_policy")
    return value


def _policy(value):
    if type(value) is not dict or value.keys() != DEFAULT_POLICY.keys():
        _fail("invalid_policy")
    return {name: _number(value[name], 1) for name in DEFAULT_POLICY}


def translate_error(error):
    """Translate only our SQLite trigger refusals; preserve other DB errors."""
    if isinstance(error, sqlite3.Error) and str(error).startswith("open_capacity_"):
        return MemoryError(str(error))
    return error


def provider_charge(record):
    budget = document(bytes(record), maximum=8192)["payload"]["budget"]
    names = ("max_live_bytes", "max_meta_bytes", "max_job_bytes", "max_replay_records")
    for name in names:
        _number(budget[name])
    return _number(sum(budget[name] for name in names[:3]) +
                   budget["max_replay_records"] * PROVIDER_REPLAY_BYTES + PROVIDER_LEASE_BYTES, 1)


def contact_charge(purpose, max_items, max_bytes):
    _number(max_items, 1); _number(max_bytes, 1)
    if purpose not in ("knock", "delivery"):
        _fail("invalid_reservation")
    return _number(max_bytes + (max_items * DELIVERY_ITEM_BYTES if purpose == "delivery" else 0)
                   + CONTACT_LEASE_BYTES, 1)



class CapacityAuthority:
    """Same-DB reservation accounting; the caller commits or rolls back."""

    def __init__(self, db, *, policy=None):
        self.db = db
        self.requested_policy = None if policy is None else _policy(policy)

    def _transaction(self):
        if not self.db.in_transaction:
            _fail("transaction_required")

    def _bound_policy(self):
        row = self.db.execute("SELECT schema_version,maximum_reserved_bytes,maximum_reservations FROM open_capacity_policy WHERE singleton=1").fetchone()
        if row is None or row[0] != SCHEMA:
            _fail("binding_missing")
        actual = _policy(dict(zip(DEFAULT_POLICY, row[1:])))
        if self.requested_policy is not None and self.requested_policy != actual:
            _fail("policy_mismatch")
        return actual

    def _write_lock(self):
        self._transaction()
        # A deferred caller must acquire the writer lock here before reading
        # totals. A stale read transaction fails its upgrade instead of racing.
        self.db.execute("UPDATE open_capacity_policy SET singleton=singleton WHERE singleton=1")
        return self._bound_policy()

    def check_policy(self):
        """Acquire the shared writer lock and check this caller's binding."""
        return self._write_lock()

    def initialize(self):
        self._transaction()
        for sql in (*RESERVATION_TABLES.values(), *CAPACITY_TABLES):
            self.db.execute(sql)
        if self.db.execute("SELECT 1 FROM open_capacity_policy WHERE singleton=1").fetchone() is None:
            if self.db.execute("SELECT 1 FROM open_capacity_reservations LIMIT 1").fetchone():
                _fail("binding_missing")
            actual = self.requested_policy or DEFAULT_POLICY
            self.db.execute("INSERT INTO open_capacity_policy VALUES(1,?,?,?)", (SCHEMA, *actual.values()))
        self._write_lock()
        # Install both legacy reservation tables, even if only one service is
        # configured now, so a later native initializer cannot bypass triggers.
        for row in self.db.execute("SELECT lease_id,digest,record,retain_until,owner,allocation_id,root_digest FROM open_provider_resources"):
            self._migrate("provider", row[0], row[1], provider_charge(row[2]), row[3], row[4], row[5], row[6])
        for row in self.db.execute("SELECT lease_id,allocation_sha256,purpose,max_items,max_bytes,retain_until,owner,allocation_id FROM open_contact_resource_leases"):
            self._migrate("contact", row[0], row[1], contact_charge(row[2], row[3], row[4]), row[5], row[6], row[7])
        for sql in TRIGGERS:
            self.db.execute(sql)
        # No cap check here: migrating old obligations never drops or weakens
        # their reservation merely because the configured cap is already full.

    def _migrate(self, service, reservation_id, digest, charge, retain, owner, operation, root_digest=""):
        values = (service, reservation_id, digest, charge, _number(retain), owner, operation, root_digest)
        old = self.db.execute("SELECT service,reservation_id,digest,charge_bytes,retain_until,owner,operation_id,root_digest FROM open_capacity_reservations WHERE service=? AND reservation_id=?", values[:2]).fetchone()
        if old is not None:
            if tuple(old) != values:
                _fail("reservation_conflict")
            return
        self.db.execute("INSERT INTO open_capacity_reservations VALUES(?,?,?,?,?,?,?,?)", values)

    def usage(self):
        actual = self._bound_policy()
        charges = [row[0] for row in self.db.execute("SELECT charge_bytes FROM open_capacity_reservations")]
        reserved = SERVICE_RESERVE_BYTES + sum(_number(value, 1) for value in charges)
        return dict(reserved_bytes=reserved if reserved <= U53_MAX else str(reserved), reservations=len(charges),
                    oversubscribed=reserved > actual["maximum_reserved_bytes"] or len(charges) > actual["maximum_reservations"],
                    **actual)

    def reserve(self, service, reservation_id, input_digest, charge_bytes, retain_until, *, owner, operation_id):
        """Reserve repair resources once; legacy inserts use the same totals."""
        self._write_lock()
        if service not in ("ack", "repair_index", "contact_directory"):
            _fail("invalid_service")
        for value in (reservation_id, owner, operation_id):
            if type(value) is not str or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value) is None:
                _fail("invalid_reservation")
        if type(input_digest) is not str or re.fullmatch(r"[0-9a-f]{64}", input_digest) is None:
            _fail("invalid_reservation")
        _number(charge_bytes, 1); _number(retain_until)
        previous = self.db.execute("SELECT 1 FROM open_capacity_reservations WHERE service=? AND reservation_id=?", (service, reservation_id)).fetchone()
        self.db.execute("SAVEPOINT open_capacity_reserve")
        try:
            self._migrate(service, reservation_id, input_digest, charge_bytes, retain_until, owner, operation_id)
            if previous is None and self.usage()["oversubscribed"]:
                _fail("exhausted")
            self.db.execute("RELEASE open_capacity_reserve")
            return previous is None
        except BaseException:
            self.db.execute("ROLLBACK TO open_capacity_reserve")
            self.db.execute("RELEASE open_capacity_reserve")
            raise

    def _has(self, table, column, value):
        if self.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone() is None:
            return False
        return self.db.execute("SELECT 1 FROM " + table + " WHERE " + column + "=? LIMIT 1", (value,)).fetchone() is not None

    def collect_released(self, service, *, now, limit=128):
        """Release only absent legacy obligations after their full replay tail.

        ACK release is deliberately absent until its owning persistent lifecycle
        supplies concrete tables and the complete pin/receipt dependency rules.
        """
        self._write_lock()
        _number(now)
        if service not in ("provider", "contact", "contact_directory") or type(limit) is not int or not 1 <= limit <= 128:
            _fail("invalid_collection")
        rows = self.db.execute("SELECT reservation_id,owner,operation_id,root_digest FROM open_capacity_reservations WHERE service=? AND retain_until<=? ORDER BY retain_until,reservation_id LIMIT ?", (service, now, limit)).fetchall()
        released = 0
        for reservation_id, owner, operation, root_digest in rows:
            if service == "contact_directory":
                if not self._has("open_contact_directory_jobs", "job_id", reservation_id):
                    self.db.execute("DELETE FROM open_capacity_reservations WHERE service=? AND reservation_id=?", (service, reservation_id))
                    released += 1
                continue
            table = "open_provider_resources" if service == "provider" else "open_contact_resource_leases"
            if self._has(table, "lease_id", reservation_id):
                continue
            if service == "provider":
                if self._has("open_provider_facts", "resource_id", reservation_id):
                    continue
                if self._has("open_provider_status", "root_digest", root_digest):
                    continue
                if self._has("open_provider_replay", "caller", owner):
                    # Preserve only this allocation's replay, not all traffic
                    # of the same owner.
                    if self.db.execute("SELECT 1 FROM open_provider_replay WHERE caller=? AND allocation_id=? LIMIT 1", (owner, operation)).fetchone():
                        continue
            elif any(self._has(name, "lease_id", reservation_id) for name in (
                    "open_contact_policies", "open_contact_requests", "open_delivery_handles", "open_delivery_messages")):
                continue
            self.db.execute("DELETE FROM open_capacity_reservations WHERE service=? AND reservation_id=?", (service, reservation_id))
            released += 1
        return released
