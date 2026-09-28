"""Bounded exact owner-bind retries in the caller's existing protected DB.

No identity, Vault, separate database, authority renewal, or network is opened.
Rows are immutable original exchanges; application reconciliation owns cleanup.
"""
import re
import hashlib

from memory_vault import canonical_bytes
from memory_vault_network_crypto import document

import memory_vault_open_repair_wire as wire

MAX_RECORDS = 16
MAX_RECORD_BYTES = 1048576


class OwnerBindJournal:
    def __init__(self, db):
        self.db = db

    def _transaction(self, operation):
        if self.db.in_transaction:
            wire._fail("repair_bind_journal_transaction")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            result = operation()
            self.db.commit()
            return result
        except BaseException:
            self.db.rollback()
            raise

    def initialize(self):
        def create():
            self.db.execute("""CREATE TABLE IF NOT EXISTS open_repair_owner_bind_journal (
                job_key TEXT PRIMARY KEY,request_id TEXT NOT NULL,request BLOB NOT NULL,response BLOB,blocked_code TEXT)""")
            if "blocked_code" not in {row[1] for row in self.db.execute("PRAGMA table_info(open_repair_owner_bind_journal)")}:
                self.db.execute("ALTER TABLE open_repair_owner_bind_journal ADD COLUMN blocked_code TEXT")
            self.db.execute("""CREATE TABLE IF NOT EXISTS open_repair_owner_bind_observations (
                job_key TEXT NOT NULL,observation_id TEXT NOT NULL,reference BLOB NOT NULL,original BLOB NOT NULL,
                PRIMARY KEY(job_key,observation_id))""")
        self._transaction(create)
        return self

    @staticmethod
    def _key(job_key):
        if type(job_key) is not str or re.fullmatch(r"[0-9a-f]{64}", job_key) is None:
            wire._fail("repair_invalid_context")

    def load(self, job_key):
        self._key(job_key)
        row = self.db.execute("SELECT request,blocked_code FROM open_repair_owner_bind_journal WHERE job_key=?", (job_key,)).fetchone()
        if row and row[1] is not None:
            wire._fail("repair_status_history_capacity")
        return bytes(row[0]) if row else None

    def observations(self, job_key):
        self.load(job_key)
        rows = self.db.execute("SELECT reference,original FROM open_repair_owner_bind_observations WHERE job_key=? ORDER BY observation_id", (job_key,)).fetchall()
        if len(rows)>32:
            wire._fail("repair_status_history_capacity")
        return tuple(dict(raw=bytes(row[1]),ref=document(bytes(row[0]))) for row in rows)

    @staticmethod
    def _observation_id(entry):
        return hashlib.sha256(canonical_bytes(entry["ref"])+entry["raw"]).hexdigest()

    def _observe(self, job_key, entries, *, expected_ids):
        """Private: the client supplies fully authenticated, exact-scope T only.

        Commit observations before a caller can reject their semantic floor.
        A concurrent new observation must be reauthenticated on a retry.
        """
        expected = {self._observation_id(item):item for item in entries}
        def write():
            row = self.db.execute("SELECT length(request),length(response),blocked_code FROM open_repair_owner_bind_journal WHERE job_key=?", (job_key,)).fetchone()
            if row is None:
                wire._fail("repair_bind_journal_missing")
            if row[2] is not None:
                return "repair_status_history_capacity"
            current = {item[0] for item in self.db.execute("SELECT observation_id FROM open_repair_owner_bind_observations WHERE job_key=?", (job_key,))}
            additions = {key:item for key,item in expected.items() if key not in current}
            retained = self.db.execute("SELECT coalesce(sum(length(reference)+length(original)),0) FROM open_repair_owner_bind_observations WHERE job_key=?", (job_key,)).fetchone()[0]
            needed = sum(len(canonical_bytes(item["ref"]))+len(item["raw"]) for item in additions.values())
            if len(current|expected.keys())>32 or row[0]+max(65536,row[1] or 0)+retained+needed>MAX_RECORD_BYTES:
                self.db.execute("UPDATE open_repair_owner_bind_journal SET blocked_code='repair_status_history_capacity' WHERE job_key=?", (job_key,))
                return "repair_status_history_capacity"
            for key,item in additions.items():
                self.db.execute("INSERT INTO open_repair_owner_bind_observations VALUES(?,?,?,?)", (job_key,key,canonical_bytes(item["ref"]),item["raw"]))
            return "repair_bind_journal_changed" if current != set(expected_ids) else None
        code = self._transaction(write)
        if code:
            wire._fail(code)
        return tuple(sorted(set(expected_ids)|expected.keys()))

    def guard(self, job_key, observation_ids):
        def check():
            self.load(job_key)
            current = tuple(row[0] for row in self.db.execute("SELECT observation_id FROM open_repair_owner_bind_observations WHERE job_key=? ORDER BY observation_id", (job_key,)))
            if current!=observation_ids:
                wire._fail("repair_bind_journal_changed")
        self._transaction(check)

    def request_id(self, job_key):
        self._key(job_key)
        row = self.db.execute("SELECT request_id FROM open_repair_owner_bind_journal WHERE job_key=?", (job_key,)).fetchone()
        return row[0] if row else None

    def store_request(self, job_key, request_id, raw):
        self._key(job_key)
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_RECORD_BYTES - 65536:
            wire._fail("repair_bind_journal_capacity")
        if type(request_id) is not str or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", request_id) is None:
            wire._fail("repair_invalid_context")
        def write():
            previous = self.db.execute("SELECT request_id,request FROM open_repair_owner_bind_journal WHERE job_key=?", (job_key,)).fetchone()
            if previous:
                if previous[0] != request_id or bytes(previous[1]) != raw:
                    wire._fail("repair_bind_journal_conflict")
                return
            if self.db.execute("SELECT count(*) FROM open_repair_owner_bind_journal").fetchone()[0] >= MAX_RECORDS:
                wire._fail("repair_bind_journal_capacity")
            self.db.execute("INSERT INTO open_repair_owner_bind_journal VALUES(?,?,?,NULL,NULL)", (job_key, request_id, raw))
        self._transaction(write)

    def store_response(self, job_key, raw):
        self._key(job_key)
        if type(raw) is not bytes or not 0 < len(raw) <= 65536:
            wire._fail("repair_bind_journal_capacity")
        def write():
            row = self.db.execute("SELECT request,response FROM open_repair_owner_bind_journal WHERE job_key=?", (job_key,)).fetchone()
            if row is None or len(row[0]) + len(raw) > MAX_RECORD_BYTES:
                wire._fail("repair_bind_journal_capacity")
            if row[1] is not None and bytes(row[1]) != raw:
                wire._fail("repair_bind_journal_conflict")
            self.db.execute("UPDATE open_repair_owner_bind_journal SET response=? WHERE job_key=?", (raw, job_key))
        self._transaction(write)
