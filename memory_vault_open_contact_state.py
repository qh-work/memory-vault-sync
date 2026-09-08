"""Finite contact obligations in the existing protected transport database.

Resource reservations pay for requests, their maximum result and replay tail at
admission. No table here owns Vault records, author trust or message receipts.
"""
from __future__ import annotations

import hashlib
import hmac
import sqlite3
import threading
import time

from memory_vault import canonical_bytes
from memory_vault_network_crypto import document, document_sha256, integer, unb64url
from memory_vault_open_contact import (
    ContactError, SLOT_BYTES, MAX_REQUEST_BYTES, MAX_DECISION_BYTES, fail,
    issue_challenge, node_binding, sign_document, verify_challenge,
    verify_decision, verify_document, verify_lease, verify_policy,
    verify_request, verify_rpc,
)
from memory_vault_open_control import verify_node

RETENTION_SECONDS = 30
GC_BATCH = 128
MAX_SUBJECT_CHALLENGES = 4
MAX_OWNER_SUBMIT_CHALLENGES = 16
# Handlers own separate state instances/connections. CPU admission must be shared
# by the process, not recreated for each HTTP exchange.
_CHALLENGE_SLOTS = {purpose: threading.BoundedSemaphore(1) for purpose in ("submit", "result")}


class ContactState:
    """A caller-owned connection; independent handles serialize through SQLite.

    ``clock`` is a test clock, not a captured HTTP timestamp. Cryptographic
    challenge construction is outside the transaction; admission is rechecked
    after obtaining the writer lock. No operation awaits or performs network IO.
    """

    def __init__(self, db, identity, node, *, enabled=False, maximum_leases=128,
                 maximum_knock_items=1024, maximum_knock_bytes=16 * 1024 * 1024,
                 maximum_delivery_items=1024, maximum_delivery_bytes=64 * 1024 * 1024,
                 maximum_challenges=128, maximum_challenge_bytes=1024 * 1024, clock=None):
        if type(enabled) is not bool:
            fail("contact_invalid_local_policy")
        limits = ((maximum_leases, 128), (maximum_knock_items, 1024),
                  (maximum_knock_bytes, 16 * 1024 * 1024), (maximum_delivery_items, 1024),
                  (maximum_delivery_bytes, 64 * 1024 * 1024), (maximum_challenges, 128),
                  (maximum_challenge_bytes, 1024 * 1024))
        if any(integer(value, minimum=1) > ceiling for value, ceiling in limits):
            fail("contact_invalid_local_policy")
        target = verify_node(node, now=node["payload"]["issued_at"])
        if target["signing_key"] != identity.public_descriptor():
            fail("contact_wrong_node")
        self.db, self.identity, self.node = db, identity, document(node)
        self.enabled, self.clock = enabled, clock or time.time
        self.maximum_leases = maximum_leases
        self.maximum_knock_items, self.maximum_knock_bytes = maximum_knock_items, maximum_knock_bytes
        self.maximum_delivery_items, self.maximum_delivery_bytes = maximum_delivery_items, maximum_delivery_bytes
        self.maximum_challenges, self.maximum_challenge_bytes = maximum_challenges, maximum_challenge_bytes
        self._lock = threading.RLock()

    def _now(self):
        return integer(int(self.clock()))

    def _one(self, sql, parameters=()):
        cursor = self.db.execute(sql, parameters)
        row = cursor.fetchone()
        return dict(zip((column[0] for column in cursor.description), row)) if row is not None else None

    def _binding(self):
        row = self._one("SELECT value FROM open_contact_state WHERE name='binding'")
        expected = self.identity.key_id + ":" + self.node["payload"]["storage_epoch"]
        if row is None or row["value"] != expected:
            fail("contact_storage_epoch_mismatch")

    def _transaction(self, operation, *, rpc=None):
        with self._lock:
            if self.db.in_transaction:
                fail("contact_storage_transaction")
            self.db.execute("BEGIN IMMEDIATE")
            try:
                now = self._now()
                self._binding()
                if rpc is not None:
                    verify_rpc(rpc, node=self.node, now=now)
                self._prune(now)
                result = operation(now)
                self.db.commit()
            except BaseException:
                self.db.rollback()
                raise
        # Security floors may have to commit before their typed refusal.
        if isinstance(result, ContactError):
            raise result
        return result

    def initialize(self):
        with self._lock:
            if self.db.in_transaction:
                fail("contact_storage_transaction")
            self.db.execute("BEGIN IMMEDIATE")
            try:
                statements = [
                    "CREATE TABLE IF NOT EXISTS open_contact_state(name TEXT PRIMARY KEY,value TEXT NOT NULL)",
                    """CREATE TABLE IF NOT EXISTS open_contact_resource_leases(
                        lease_id TEXT PRIMARY KEY,owner TEXT NOT NULL,allocation_id TEXT NOT NULL,
                        allocation_sha256 TEXT NOT NULL,purpose TEXT NOT NULL,record BLOB NOT NULL,
                        max_items INTEGER NOT NULL,max_bytes INTEGER NOT NULL,expires_at INTEGER NOT NULL,
                        retain_until INTEGER NOT NULL,status TEXT NOT NULL,grant_request TEXT,
                        UNIQUE(owner,allocation_id))""",
                    """CREATE TABLE IF NOT EXISTS open_contact_policies(
                        owner TEXT PRIMARY KEY,lease_id TEXT NOT NULL,revision INTEGER NOT NULL,
                        digest TEXT NOT NULL,record BLOB NOT NULL,second_record BLOB,
                        status TEXT NOT NULL,retain_until INTEGER NOT NULL)""",
                    """CREATE TABLE IF NOT EXISTS open_contact_requests(
                        sender TEXT NOT NULL,request_id TEXT NOT NULL,digest TEXT NOT NULL,owner TEXT NOT NULL,
                        lease_id TEXT NOT NULL,record BLOB NOT NULL,state TEXT NOT NULL,decision BLOB,
                        decision_sha256 TEXT,expires_at INTEGER NOT NULL,retain_until INTEGER NOT NULL,
                        PRIMARY KEY(sender,request_id))""",
                    """CREATE TABLE IF NOT EXISTS open_contact_challenges(
                        sender TEXT NOT NULL,request_id TEXT NOT NULL,purpose TEXT NOT NULL,
                        request_sha256 TEXT NOT NULL,record BLOB NOT NULL,digest TEXT NOT NULL,
                        answer_sha256 TEXT NOT NULL,expires_at INTEGER NOT NULL,retain_until INTEGER NOT NULL,
                        used INTEGER NOT NULL,PRIMARY KEY(sender,request_id,purpose))""",
                    "CREATE INDEX IF NOT EXISTS open_resource_expiry ON open_contact_resource_leases(retain_until)",
                    "CREATE INDEX IF NOT EXISTS open_policy_expiry ON open_contact_policies(retain_until)",
                    "CREATE INDEX IF NOT EXISTS open_request_expiry ON open_contact_requests(retain_until)",
                    "CREATE INDEX IF NOT EXISTS open_request_lease ON open_contact_requests(lease_id,state,expires_at)",
                    "CREATE INDEX IF NOT EXISTS open_request_pair ON open_contact_requests(sender,owner,state,expires_at)",
                    "CREATE INDEX IF NOT EXISTS open_challenge_expiry ON open_contact_challenges(retain_until)",
                    "CREATE INDEX IF NOT EXISTS open_challenge_purpose ON open_contact_challenges(purpose)",
                ]
                for statement in statements:
                    self.db.execute(statement)
                expected = self.identity.key_id + ":" + self.node["payload"]["storage_epoch"]
                prior = self._one("SELECT value FROM open_contact_state WHERE name='binding'")
                if prior is None:
                    if any(self._one("SELECT 1 FROM " + table + " LIMIT 1") for table in (
                            "open_contact_resource_leases", "open_contact_policies", "open_contact_requests", "open_contact_challenges")):
                        fail("contact_storage_binding_missing")
                    self.db.execute("INSERT INTO open_contact_state VALUES('binding',?)", (expected,))
                self._binding()
                self.db.commit()
            except BaseException:
                self.db.rollback()
                raise

    def _prune(self, now):
        # Bounded indexed batches. Never remove a live obligation or its tail.
        for table in ("open_contact_challenges", "open_contact_requests"):
            self.db.execute("DELETE FROM " + table + " WHERE rowid IN (SELECT rowid FROM " + table +
                            " WHERE retain_until<=? ORDER BY retain_until LIMIT ?)", (now, GC_BATCH))
        self.db.execute("""DELETE FROM open_contact_policies WHERE rowid IN (
            SELECT rowid FROM open_contact_policies WHERE retain_until<=? AND lease_id NOT IN
            (SELECT lease_id FROM open_contact_requests) ORDER BY retain_until LIMIT ?)""", (now, GC_BATCH))
        self.db.execute("""DELETE FROM open_contact_resource_leases WHERE rowid IN (
            SELECT rowid FROM open_contact_resource_leases WHERE retain_until<=? AND lease_id NOT IN
            (SELECT lease_id FROM open_contact_requests) AND lease_id NOT IN
            (SELECT lease_id FROM open_contact_policies) ORDER BY retain_until LIMIT ?)""", (now, GC_BATCH))

    def gc(self):
        """One bounded local collection step, available even when admission closes."""
        return self._transaction(lambda now: {"state": "collected"})

    def revoke_lease(self, lease_id):
        """Explicit node-owner action; never callable through the public RPC."""
        def operation(now):
            self.db.execute("UPDATE open_contact_resource_leases SET status='revoked' WHERE lease_id=?", (lease_id,))
            self.db.execute("UPDATE open_contact_policies SET status='revoked' WHERE lease_id=?", (lease_id,))
            return {"state": "revoked"}
        return self._transaction(operation)

    def _open(self):
        if not self.enabled:
            fail("contact_closed")

    def _lease(self, lease_id, now, *, active=True):
        row = self._one("SELECT * FROM open_contact_resource_leases WHERE lease_id=?", (lease_id,))
        if row is None:
            fail("contact_lease_not_found")
        verify_lease(document(bytes(row["record"])), node=self.node, now=now)
        if active and row["status"] != "active":
            fail("contact_lease_revoked")
        return row

    def _policy(self, owner, now):
        row = self._one("SELECT * FROM open_contact_policies WHERE owner=?", (owner,))
        if row is None or row["status"] != "active":
            fail("contact_unavailable")
        lease = self._lease(row["lease_id"], now)
        policy, resource = document(bytes(row["record"])), document(bytes(lease["record"]))
        verify_policy(policy, lease=resource, node=self.node, now=now)
        return policy, resource

    def _request(self, signed, now):
        original = verify_document(signed, "contact.request", now=now)
        policy, lease = self._policy(original["recipient_key_id"], now)
        raw = verify_request(signed, policy=policy, lease=lease, node=self.node, now=now)
        old = self._one("SELECT * FROM open_contact_requests WHERE sender=? AND request_id=?",
                        (raw["signing_key"]["key_id"], raw["request_id"]))
        if old is not None and old["digest"] != document_sha256(signed):
            fail("contact_request_conflict")
        return raw, policy, lease, old

    def _request_capacity(self, raw, policy):
        if self._one("""SELECT 1 FROM open_contact_requests WHERE sender=? AND owner=?
                AND state='pending' AND expires_at>? LIMIT 1""",
                     (raw["signing_key"]["key_id"], raw["recipient_key_id"], self._now())):
            fail("contact_pending_exists")
        count = self._one("SELECT count(*) AS n FROM open_contact_requests WHERE lease_id=?", (raw["lease_id"],))["n"]
        # All retained results/tombstones occupy their already reserved slot.
        if count >= policy["payload"]["max_pending"]:
            fail("contact_capacity")

    def _challenge_existing(self, request, purpose, now):
        raw, policy, lease, old = self._request(request, now)
        if purpose == "submit" and old is None:
            self._open()
            self._request_capacity(raw, policy)
        elif purpose == "result" and old is None:
            fail("contact_request_not_found")
        row = self._one("SELECT * FROM open_contact_challenges WHERE sender=? AND request_id=? AND purpose=?",
                        (raw["signing_key"]["key_id"], raw["request_id"], purpose))
        if row and row["request_sha256"] != document_sha256(request):
            fail("contact_request_conflict")
        if row and row["expires_at"] > now and not row["used"]:
            return document(bytes(row["record"]))
        usage = self._one("SELECT count(*) AS n,coalesce(sum(length(record)+256),0) AS bytes FROM open_contact_challenges")
        subject = self._one("SELECT count(*) AS n FROM open_contact_challenges WHERE sender=?", (raw["signing_key"]["key_id"],))["n"]
        # Check a conservative maximum before doing expensive encryption. The
        # same conditions are checked again on commit after concurrent writers.
        added = MAX_REQUEST_BYTES + 256 - (len(row["record"]) + 256 if row else 0)
        if (subject + (0 if row else 1) > MAX_SUBJECT_CHALLENGES
                or usage["n"] + (0 if row else 1) > self.maximum_challenges
                or usage["bytes"] + added > self.maximum_challenge_bytes):
            fail("contact_challenge_capacity")
        if purpose == "submit":
            submissions = self._one("SELECT count(*) AS n,coalesce(sum(length(record)+256),0) AS bytes FROM open_contact_challenges WHERE purpose='submit'")
            sender_submissions = self._one("SELECT count(*) AS n FROM open_contact_challenges WHERE sender=? AND purpose='submit'", (raw["signing_key"]["key_id"],))["n"]
            # The entire table is capped at 128 rows. This bounded scan avoids
            # rewriting existing storage and counts every retained challenge,
            # including consumed rows, against its recipient's allowance.
            owner_count = sum(document(bytes(item[0]))["payload"]["recipient_key_id"] == raw["recipient_key_id"]
                              for item in self.db.execute("SELECT record FROM open_contact_challenges WHERE purpose='submit' LIMIT 128"))
            if (sender_submissions + (0 if row else 1) > MAX_SUBJECT_CHALLENGES * 3 // 4
                    or owner_count + (0 if row else 1) > min(MAX_OWNER_SUBMIT_CHALLENGES, policy["payload"]["max_pending"])
                    or submissions["n"] + (0 if row else 1) > self.maximum_challenges * 3 // 4
                    or submissions["bytes"] + added > self.maximum_challenge_bytes * 3 // 4):
                fail("contact_challenge_capacity")
        return None

    def _challenge_capacity(self):
        row = self._one("SELECT count(*) AS n,coalesce(sum(length(record)+256),0) AS bytes FROM open_contact_challenges")
        if row["n"] > self.maximum_challenges or row["bytes"] > self.maximum_challenge_bytes:
            fail("contact_challenge_capacity")
        submit = self._one("SELECT count(*) AS n,coalesce(sum(length(record)+256),0) AS bytes FROM open_contact_challenges WHERE purpose='submit'")
        if submit["n"] > self.maximum_challenges * 3 // 4 or submit["bytes"] > self.maximum_challenge_bytes * 3 // 4:
            fail("contact_challenge_capacity")

    def _issue_challenge(self, rpc, checked):
        body = checked["body"]
        existing = self._transaction(lambda now: self._challenge_existing(body["request"], body["purpose"], now), rpc=rpc)
        if existing is not None:
            return {"challenge": existing}
        # Mature JWE encryption and entropy generation never hold the writer lock.
        slot = _CHALLENGE_SLOTS[body["purpose"]]
        if not slot.acquire(blocking=False):
            fail("contact_challenge_capacity")
        try:
            challenge, answer_digest = issue_challenge(self.identity, request=body["request"], node=self.node,
                                                       purpose=body["purpose"], now=self._now())
        finally:
            slot.release()
        def commit(now):
            existing = self._challenge_existing(body["request"], body["purpose"], now)
            if existing is not None:
                return {"challenge": existing}
            raw = verify_challenge(challenge, request=body["request"], node=self.node, purpose=body["purpose"], now=now)
            self.db.execute("""INSERT INTO open_contact_challenges VALUES(?,?,?,?,?,?,?,?,?,0)
                ON CONFLICT(sender,request_id,purpose) DO UPDATE SET request_sha256=excluded.request_sha256,
                record=excluded.record,digest=excluded.digest,answer_sha256=excluded.answer_sha256,
                expires_at=excluded.expires_at,retain_until=excluded.retain_until,used=0""",
                (raw["subject_key_id"], raw["request_id"], raw["purpose"], raw["request_sha256"], canonical_bytes(challenge),
                 document_sha256(challenge), answer_digest, raw["expires_at"], raw["expires_at"] + RETENTION_SECONDS))
            self._challenge_capacity()
            return {"challenge": challenge}
        return self._transaction(commit, rpc=rpc)

    def _proof(self, body, purpose, now, *, replay=False):
        challenge = verify_challenge(body["challenge"], request=body["request"], node=self.node, purpose=purpose, now=now)
        row = self._one("SELECT * FROM open_contact_challenges WHERE sender=? AND request_id=? AND purpose=?",
                        (challenge["subject_key_id"], challenge["request_id"], purpose))
        answer = hashlib.sha256(unb64url(body["answer"], maximum=32, size=32)).hexdigest()
        if (row is None or row["digest"] != document_sha256(body["challenge"])
                or row["request_sha256"] != document_sha256(body["request"])
                or (row["used"] and not replay) or not hmac.compare_digest(row["answer_sha256"], answer)):
            fail("contact_invalid_proof")
        self.db.execute("UPDATE open_contact_challenges SET used=1 WHERE sender=? AND request_id=? AND purpose=?",
                        (challenge["subject_key_id"], challenge["request_id"], purpose))

    def _allocate(self, rpc, now):
        self._open()
        body, owner = rpc["body"], rpc["signing_key"]["key_id"]
        digest = document_sha256(body)
        previous = self._one("SELECT * FROM open_contact_resource_leases WHERE owner=? AND allocation_id=?", (owner, body["allocation_id"]))
        if previous:
            if previous["allocation_sha256"] != digest:
                fail("contact_allocation_conflict")
            self._lease(previous["lease_id"], now)
            return {"lease": document(bytes(previous["record"]))}
        if body["purpose"] == "knock" and self._one("SELECT 1 FROM open_contact_resource_leases WHERE owner=? AND purpose='knock' AND status='active' AND expires_at>? LIMIT 1", (owner, now)):
            fail("contact_knock_exists")
        total = self._one("SELECT count(*) AS n FROM open_contact_resource_leases")["n"]
        used = self._one("SELECT coalesce(sum(max_items),0) AS items,coalesce(sum(max_bytes),0) AS bytes FROM open_contact_resource_leases WHERE purpose=?", (body["purpose"],))
        maximum_items, maximum_bytes = ((self.maximum_knock_items, self.maximum_knock_bytes) if body["purpose"] == "knock"
                                        else (self.maximum_delivery_items, self.maximum_delivery_bytes))
        if total >= self.maximum_leases or used["items"] + body["max_items"] > maximum_items or used["bytes"] + body["max_bytes"] > maximum_bytes:
            fail("contact_capacity")
        token = hashlib.sha256((self.identity.key_id + ":" + self.node["payload"]["storage_epoch"] + ":" + owner + ":" + digest).encode()).hexdigest()
        lease = sign_document(self.identity, "resource.lease", issued_at=now, expires_at=now + body["lease_seconds"],
            node_key_id=self.identity.key_id, storage_epoch=self.node["payload"]["storage_epoch"], owner_key_id=owner,
            owner_encryption_key=body["encryption_key"], lease_id="lease_" + token, resource_id="resource_" + token,
            purpose=body["purpose"], max_items=body["max_items"], max_bytes=body["max_bytes"])
        self.db.execute("INSERT INTO open_contact_resource_leases VALUES(?,?,?,?,?,?,?,?,?,?,?,NULL)",
                        (lease["payload"]["lease_id"], owner, body["allocation_id"], digest, body["purpose"], canonical_bytes(lease),
                         body["max_items"], body["max_bytes"], now + body["lease_seconds"], now + body["lease_seconds"] + RETENTION_SECONDS, "active"))
        return {"lease": lease}

    def _put_policy(self, rpc, now):
        body = rpc["body"]
        raw = verify_policy(body["policy"], lease=body["lease"], node=self.node, now=now)
        lease = self._lease(raw["lease_id"], now, active=False)
        if document_sha256(document(bytes(lease["record"]))) != document_sha256(body["lease"]):
            fail("contact_lease_mismatch")
        owner, digest = raw["signing_key"]["key_id"], document_sha256(body["policy"])
        previous = self._one("SELECT * FROM open_contact_policies WHERE owner=?", (owner,))
        if previous:
            if previous["status"] == "conflict":
                fail("contact_policy_conflict")
            if raw["revision"] < previous["revision"]:
                fail("contact_policy_rollback")
            if raw["revision"] == previous["revision"]:
                if previous["digest"] == digest:
                    if previous["status"] != raw["status"]:
                        fail("contact_lease_revoked")
                    return {"state": raw["status"]}
                self.db.execute("UPDATE open_contact_policies SET status='conflict',second_record=?,retain_until=max(retain_until,?) WHERE owner=?", (canonical_bytes(body["policy"]), lease["retain_until"], owner))
                self.db.execute("UPDATE open_contact_resource_leases SET status='revoked' WHERE lease_id=?", (previous["lease_id"],))
                return ContactError("contact_policy_conflict")
        if raw["status"] == "active":
            self._open()
            if lease["status"] != "active":
                fail("contact_lease_revoked")
        if raw["status"] == "revoked":
            self.db.execute("UPDATE open_contact_resource_leases SET status='revoked' WHERE lease_id=?", (raw["lease_id"],))
        self.db.execute("""INSERT INTO open_contact_policies VALUES(?,?,?,?,?,NULL,?,?) ON CONFLICT(owner)
            DO UPDATE SET lease_id=excluded.lease_id,revision=excluded.revision,digest=excluded.digest,
            record=excluded.record,second_record=NULL,status=excluded.status,retain_until=max(retain_until,excluded.retain_until)""",
            (owner, raw["lease_id"], raw["revision"], digest, canonical_bytes(body["policy"]), raw["status"], lease["retain_until"]))
        return {"state": raw["status"]}

    def _submit(self, rpc, now):
        body = rpc["body"]
        raw, policy, lease, old = self._request(body["request"], now)
        self._proof(body, "submit", now, replay=old is not None)
        if old is not None:
            return {"state": "contact_queued", "request_sha256": old["digest"]}
        self._open()
        self._request_capacity(raw, policy)
        digest = document_sha256(body["request"])
        self.db.execute("INSERT INTO open_contact_requests VALUES(?,?,?,?,?,?,'pending',NULL,NULL,?,?)",
            (raw["signing_key"]["key_id"], raw["request_id"], digest, raw["recipient_key_id"], raw["lease_id"],
             canonical_bytes(body["request"]), raw["expires_at"], raw["expires_at"] + RETENTION_SECONDS))
        return {"state": "contact_queued", "request_sha256": digest}

    def _poll(self, rpc, now):
        lease = self._lease(rpc["body"]["lease_id"], now)
        if lease["owner"] != rpc["signing_key"]["key_id"] or lease["purpose"] != "knock":
            fail("contact_wrong_subject")
        policy, resource = self._policy(lease["owner"], now)
        requests, size = [], 0
        # A policy revision invalidates old requests but not their retained
        # obligations. Scan the existing per-lease maximum before limiting the
        # current-policy page; otherwise four stale rows can block every poll.
        for row in self.db.execute("SELECT record FROM open_contact_requests WHERE lease_id=? AND state='pending' AND expires_at>? ORDER BY request_id,sender LIMIT 32", (lease["lease_id"], now)):
            record = document(bytes(row[0]))
            try:
                verify_request(record, policy=policy, lease=resource, node=self.node, now=now)
            except ContactError:
                continue
            amount = len(canonical_bytes(record))
            if size + amount > 16 * 1024:
                break
            requests.append(record)
            size += amount
            if len(requests) == 4:
                break
        return {"requests": requests}

    def _decide(self, rpc, now):
        body = rpc["body"]
        raw, policy, lease, old = self._request(body["request"], now)
        if old is None:
            fail("contact_request_not_found")
        decision = verify_decision(body["decision"], request=body["request"], policy=policy, lease=lease, node=self.node, now=now)
        digest = document_sha256(body["decision"])
        if old["decision"] is not None:
            if old["decision_sha256"] != digest:
                fail("contact_decision_conflict")
            return {"state": "decided", "request_sha256": old["digest"]}
        if decision["grant"] is not None:
            grant = decision["grant"]["payload"]
            delivery = self._lease(grant["resource_lease"]["payload"]["lease_id"], now)
            if (delivery["purpose"] != "delivery" or delivery["owner"] != raw["recipient_key_id"]
                    or document_sha256(document(bytes(delivery["record"]))) != document_sha256(grant["resource_lease"])
                    or delivery["grant_request"] is not None):
                fail("contact_delivery_unavailable")
            # One grant owns this complete finite reservation. The future message
            # carrier must debit its max_items/max_bytes, never allocate again.
            self.db.execute("UPDATE open_contact_resource_leases SET grant_request=? WHERE lease_id=?", (old["digest"], delivery["lease_id"]))
        self.db.execute("UPDATE open_contact_requests SET state='decided',decision=?,decision_sha256=? WHERE sender=? AND request_id=?",
                        (canonical_bytes(body["decision"]), digest, raw["signing_key"]["key_id"], raw["request_id"]))
        return {"state": "decided", "request_sha256": old["digest"]}

    def _result(self, rpc, now):
        body = rpc["body"]
        raw, policy, lease, old = self._request(body["request"], now)
        if old is None:
            fail("contact_request_not_found")
        self._proof(body, "result", now)
        if old["decision"] is None:
            return {"state": "pending", "decision": None}
        signed = document(bytes(old["decision"]))
        decision = verify_decision(signed, request=body["request"], policy=policy, lease=lease, node=self.node, now=now)
        if decision["grant"] is not None:
            delivery = self._lease(decision["grant"]["payload"]["resource_lease"]["payload"]["lease_id"], now)
            if delivery["grant_request"] != old["digest"]:
                fail("contact_delivery_unavailable")
        return {"state": decision["decision"], "decision": signed}

    def handle(self, rpc):
        signed = document(rpc, maximum=65536)
        checked = verify_rpc(signed, node=self.node, now=self._now())
        if checked["action"] == "challenge":
            return self._issue_challenge(signed, checked)
        def operation(now):
            action = checked["action"]
            if action == "policy.get":
                policy, lease = self._policy(checked["body"]["recipient_key_id"], now)
                return {"policy": policy, "lease": lease}
            return {"lease": self._allocate, "policy.put": self._put_policy, "submit": self._submit,
                    "poll": self._poll, "decide": self._decide, "result": self._result}[action](checked, now)
        return self._transaction(operation, rpc=signed)
