"""Shared reservation accounting in fresh synthetic SQLite files only."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from memory_vault import MemoryError, canonical_bytes
from memory_vault_network_crypto import EncryptionIdentity
import memory_vault_open_capacity as capacity
import memory_vault_open_contact as contact
from memory_vault_open_contact_state import ContactState
from memory_vault_open_control import issue_node
import memory_vault_open_provider as provider
from memory_vault_open_provider_state import ProviderState
from memory_vault_trust import Identity


BUDGET = dict(max_live_bytes=0, max_meta_bytes=98304, max_items=1,
              max_requests=8, max_pending=1, max_replay_records=8,
              max_jobs=0, max_job_bytes=0)
PROVIDER_CHARGE = 98304 + 8 * 32768 + 36864
CONTACT_CHARGE = 8192 + 131072 + 4096


class OpenCapacityTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix="open-capacity-synthetic-")
        self.addCleanup(folder.cleanup)
        self.path = Path(folder.name) / "network.sqlite3"
        self.db = self.connect()
        self.addCleanup(lambda: self.db.close())
        self.now = 2_000_000_000
        self.node_key = Identity(Ed25519PrivateKey.generate())
        self.owner = Identity(Ed25519PrivateKey.generate())
        self.node_encryption, self.owner_encryption = EncryptionIdentity.generate(), EncryptionIdentity.generate()
        self.node = issue_node(self.node_key, base_url="http://127.0.0.1:18501", storage_epoch="synthetic_capacity_epoch",
            roles=["directory", "router"], revision=1, issued_at=self.now, expires_at=self.now + 3600)
        self.subject = dict(signing_key=self.owner.public_descriptor(), encryption_key=self.owner_encryption.public_descriptor())
        self.root = dict(owner=provider.as_dual(self.subject), root_kind="mailbox",
            anchor_ref=dict(namespace="anchor", key="a" * 64), owner_epoch="synthetic_owner_epoch", root_id="synthetic_root")

    def connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA trusted_schema=OFF")
        return db

    def cap(self, charge=PROVIDER_CHARGE + CONTACT_CHARGE, count=4096):
        return dict(maximum_reserved_bytes=capacity.SERVICE_RESERVE_BYTES + charge, maximum_reservations=count)

    def initialize(self, policy=None, db=None):
        db = self.db if db is None else db
        authority = capacity.CapacityAuthority(db, policy=policy)
        db.execute("BEGIN IMMEDIATE")
        try:
            authority.initialize(); db.commit()
        except BaseException:
            db.rollback(); raise
        return authority

    def states(self, policy=None, db=None):
        db = self.db if db is None else db
        kwargs = dict(enabled=True, clock=lambda: self.now, capacity_policy=policy)
        p = ProviderState(db, self.node_key, self.node, encryption_identity=self.node_encryption, **kwargs)
        c = ContactState(db, self.node_key, self.node, **kwargs)
        p.initialize(); c.initialize()
        return p, c

    def allocate_provider(self, state, allocation="synthetic_provider"):
        intent = provider.sign_document(self.owner, "root.resource.intent", issued_at=self.now,
            expires_at=self.now + 600, allocation_id=allocation, root_key=self.root, subject=self.subject,
            node_key_id=self.node_key.key_id, storage_epoch="synthetic_capacity_epoch", purpose="provider_index",
            budget=BUDGET, windows={name: self.now + 600 for name in provider.WINDOWS})
        return state.handle(provider.sign_rpc(self.owner, node=self.node, action="resource.allocate",
            body={"intent": intent}, now=self.now, request_id=allocation))

    def allocate_contact(self, state, allocation="synthetic_contact"):
        return state.handle(contact.sign_rpc(self.owner, node=self.node, action="lease", now=self.now,
            body=dict(encryption_key=self.owner_encryption.public_descriptor(), purpose="delivery",
                      max_items=1, max_bytes=8192, lease_seconds=600, allocation_id=allocation)))

    def insert_contact(self, lease="legacy_contact", *, retain=200, max_bytes=8192):
        self.db.execute("INSERT INTO open_contact_resource_leases VALUES(?,?,?,?,?,?,?,?,?,?,?,NULL)",
            (lease, "synthetic_owner", lease, "a" * 64, "delivery", b"{}", 1, max_bytes, 100, retain, "active"))

    def insert_provider(self, lease="legacy_provider", *, retain=200):
        record = canonical_bytes({"payload": {"budget": BUDGET}})
        self.db.execute("INSERT INTO open_provider_resources VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,0)",
            (lease, "synthetic_owner", lease, "b" * 64, b"{}", record, "c" * 64,
             "provider_index", "active", b"{}", 1, 100, retain))

    def assertCode(self, code, operation, *args, **kwargs):
        with self.assertRaises(MemoryError) as caught:
            operation(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def test_real_service_allocations_share_one_bound_cap_and_replay(self):
        p, c = self.states(self.cap())
        p_result = self.allocate_provider(p)
        c_result = self.allocate_contact(c)
        self.assertEqual(p.capacity.usage()["reserved_bytes"], self.cap()["maximum_reserved_bytes"])
        self.assertEqual(p.capacity.usage()["reservations"], 2)
        self.assertEqual(self.allocate_provider(p), p_result)
        self.assertEqual(self.allocate_contact(c), c_result)
        self.assertCode("open_capacity_exhausted", self.allocate_contact, c, "another_allocation")
        self.assertEqual(p.capacity.usage()["reservations"], 2)

    def test_competing_provider_and_contact_connections_cannot_oversell(self):
        cap = self.cap(PROVIDER_CHARGE)
        self.states(cap)
        start = threading.Barrier(2)
        def attempt(kind):
            with self.connect() as db:
                p, c = self.states(cap, db)
                start.wait(timeout=5)
                try:
                    (self.allocate_provider(p) if kind == "provider" else self.allocate_contact(c))
                    return "stored"
                except MemoryError as error:
                    return error.code
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(attempt, ("provider", "contact")))
        self.assertCountEqual(outcomes, ["stored", "open_capacity_exhausted"])
        usage = capacity.CapacityAuthority(self.db).usage()
        self.assertEqual(usage["reservations"], 1)
        self.assertLessEqual(usage["reserved_bytes"], cap["maximum_reserved_bytes"])

    def test_reopen_adopts_policy_and_explicit_mismatch_rolls_back(self):
        p, c = self.states(self.cap())
        saved = self.allocate_contact(c)
        self.db.close(); self.db = self.connect()
        p, c = self.states()
        self.assertEqual(self.allocate_contact(c), saved)
        before = [tuple(row) for row in self.db.execute("SELECT name,sql FROM sqlite_master ORDER BY name")]
        wrong = ContactState(self.db, self.node_key, self.node, capacity_policy=self.cap(1))
        self.assertCode("open_capacity_policy_mismatch", wrong.initialize)
        self.assertFalse(self.db.in_transaction)
        self.assertEqual(before, [tuple(row) for row in self.db.execute("SELECT name,sql FROM sqlite_master ORDER BY name")])
        self.assertEqual(c.capacity.usage()["maximum_reserved_bytes"], self.cap()["maximum_reserved_bytes"])

    def test_raw_sql_writer_uses_same_charge_and_cannot_enlarge_obligation(self):
        authority = self.initialize(self.cap(CONTACT_CHARGE))
        self.insert_contact(); self.db.commit()
        self.assertEqual(authority.usage()["reserved_bytes"], self.cap(CONTACT_CHARGE)["maximum_reserved_bytes"])
        with self.assertRaisesRegex(sqlite3.IntegrityError, "open_capacity_exhausted"):
            self.insert_provider()
        self.db.rollback()
        for assignment in ("max_bytes=max_bytes+1", "max_items=max_items+1", "retain_until=retain_until+1",
                           "record=x'7b7d20'", "allocation_sha256='" + "f" * 64 + "'"):
            with self.subTest(assignment=assignment), self.assertRaisesRegex(sqlite3.IntegrityError, "open_capacity_immutable_reservation"):
                self.db.execute("UPDATE open_contact_resource_leases SET " + assignment)
            self.db.rollback()
        self.db.execute("UPDATE open_contact_resource_leases SET status='revoked',grant_request='synthetic_request'")
        self.db.commit()
        self.assertEqual(authority.usage()["reservations"], 1)

    def test_oversubscribed_legacy_migration_preserves_every_existing_obligation(self):
        for sql in capacity.RESERVATION_TABLES.values():
            self.db.execute(sql)
        self.insert_contact(); self.insert_provider(); self.db.commit()
        authority = self.initialize(self.cap(1, 1))
        self.assertTrue(authority.usage()["oversubscribed"])
        self.assertEqual(authority.usage()["reservations"], 2)
        self.assertEqual(self.db.execute("SELECT count(*) FROM open_provider_resources").fetchone()[0], 1)
        self.assertEqual(self.db.execute("SELECT count(*) FROM open_contact_resource_leases").fetchone()[0], 1)
        with self.assertRaisesRegex(sqlite3.IntegrityError, "open_capacity_exhausted"):
            self.insert_contact("new_obligation")
        self.db.rollback()
        self.assertEqual(authority.usage()["reservations"], 2)
        self.initialize()  # Reconciliation is idempotent even while over cap.

    def test_failed_service_transaction_rolls_back_reservation_and_signed_result(self):
        p, _ = self.states(self.cap())
        with patch.object(p, "_remember", side_effect=RuntimeError("synthetic_failure")):
            with self.assertRaisesRegex(RuntimeError, "synthetic_failure"):
                self.allocate_provider(p)
        self.assertEqual(p.capacity.usage()["reservations"], 0)
        self.assertEqual(self.db.execute("SELECT count(*) FROM open_provider_resources").fetchone()[0], 0)
        self.assertEqual(self.db.execute("SELECT count(*) FROM open_provider_replay").fetchone()[0], 0)
        self.allocate_provider(p)

    def test_expiry_does_not_release_existing_rows_or_delivery_dependencies(self):
        authority = self.initialize(self.cap())
        self.insert_contact()
        self.db.execute("CREATE TABLE open_delivery_handles(lease_id TEXT)")
        self.db.execute("INSERT INTO open_delivery_handles VALUES('legacy_contact')")
        self.db.commit()
        self.db.execute("BEGIN IMMEDIATE")
        self.assertEqual(authority.collect_released("contact", now=300), 0)
        self.db.execute("DELETE FROM open_contact_resource_leases")
        self.assertEqual(authority.collect_released("contact", now=300), 0)
        self.db.execute("DELETE FROM open_delivery_handles")
        self.assertEqual(authority.collect_released("contact", now=199), 0)
        self.assertEqual(authority.collect_released("contact", now=200), 1)
        self.db.commit()
        self.assertEqual(authority.usage()["reservations"], 0)

    def test_provider_replay_survives_resource_deletion_until_own_release(self):
        authority = self.initialize(self.cap())
        self.insert_provider()
        self.db.execute("CREATE TABLE open_provider_replay(caller TEXT,allocation_id TEXT)")
        self.db.execute("CREATE TABLE open_provider_status(root_digest TEXT)")
        self.db.execute("INSERT INTO open_provider_replay VALUES('synthetic_owner','legacy_provider')")
        self.db.execute("INSERT INTO open_provider_status VALUES(?)", ("c" * 64,))
        self.db.commit()
        self.db.execute("BEGIN IMMEDIATE")
        self.db.execute("DELETE FROM open_provider_resources")
        self.assertEqual(authority.collect_released("provider", now=300), 0)
        self.db.execute("DELETE FROM open_provider_replay")
        self.assertEqual(authority.collect_released("provider", now=300), 0)
        self.db.execute("DELETE FROM open_provider_status")
        self.assertEqual(authority.collect_released("provider", now=300), 1)
        self.db.commit()

    def test_ack_reservation_requires_transaction_and_retries_without_new_charge(self):
        authority = self.initialize(self.cap(123))
        args = ("ack", "synthetic_ack", "d" * 64, 123, 300)
        kwargs = dict(owner="synthetic_owner", operation_id="synthetic_allocate")
        self.assertCode("open_capacity_transaction_required", authority.reserve, *args, **kwargs)
        self.db.execute("BEGIN")  # Authority itself acquires the writer lock.
        self.assertTrue(authority.reserve(*args, **kwargs))
        self.assertFalse(authority.reserve(*args, **kwargs))
        self.assertCode("open_capacity_reservation_conflict", authority.reserve,
                        "ack", "synthetic_ack", "e" * 64, 123, 300, **kwargs)
        self.assertCode("open_capacity_exhausted", authority.reserve,
                        "ack", "second_ack", "e" * 64, 1, 300, **kwargs)
        self.db.commit()  # A caught refusal cannot accidentally retain a row.
        self.assertEqual(authority.usage()["reservations"], 1)

    def test_delivery_consumption_does_not_reserve_contact_body_again(self):
        authority = self.initialize(self.cap(CONTACT_CHARGE))
        self.insert_contact()
        self.db.execute("CREATE TABLE open_delivery_messages(lease_id TEXT,envelope BLOB)")
        self.db.execute("INSERT INTO open_delivery_messages VALUES('legacy_contact',?)", (b"synthetic ciphertext",))
        self.db.commit()
        self.assertEqual(authority.usage()["reserved_bytes"], capacity.SERVICE_RESERVE_BYTES + CONTACT_CHARGE)
        self.assertEqual(authority.usage()["reservations"], 1)


if __name__ == "__main__":
    unittest.main()
