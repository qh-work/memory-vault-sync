"""Finite local index admission using temporary DBs and actual owner signatures."""
import sqlite3
import unittest

from memory_vault import MemoryError, canonical_bytes
from memory_vault_open_control import contact_key, sign_request, verify_lease
from memory_vault_open_index import FLOOR_RETENTION_SECONDS, OpenIndex
from tests import test_open_control as control_fixture


class OpenIndexTests(unittest.TestCase):
    make_node = control_fixture.OpenControlTests.make_node
    make_contact = control_fixture.OpenControlTests.make_contact
    request = control_fixture.OpenControlTests.request

    def setUp(self):
        control_fixture.OpenControlTests.setUp(self)
        self.db_path = self.path / "existing_transport.sqlite3"
        self.db = sqlite3.connect(self.db_path)
        self.addCleanup(lambda: self.db.close())
        self.db.execute("CREATE TABLE prior_transport_state(value TEXT NOT NULL)")
        self.db.execute("INSERT INTO prior_transport_state VALUES('synthetic unchanged state')")
        self.db.commit()
        self.index = OpenIndex(self.db, self.server, self.node, enabled=True)
        self.index.initialize()

    def put(self, *, contact=None, request_id="put_fixture", now=None, seconds=120):
        current = self.now if now is None else now
        request = self.request("put", {"contact": self.contact if contact is None else contact, "lease_seconds": seconds},
                               request_id=request_id, issued_at=current, expires_at=current + 60)
        return self.index.handle(request, now=current), request

    def get(self, *, now=None):
        current = self.now if now is None else now
        request = self.request("get", {"key": contact_key(self.owner.key_id)},
                               issued_at=current, expires_at=current + 60)
        return self.index.handle(request, now=current)

    def test_real_signed_put_get_renew_and_restart_preserve_exact_bytes(self):
        result, request = self.put()
        lease = verify_lease(result["lease"], node=self.node, contact=self.contact, now=self.now)
        self.assertEqual(lease["owner_key_id"], self.owner.key_id)
        retrieved = self.get()
        self.assertEqual(canonical_bytes(retrieved["contact"]), canonical_bytes(self.contact))
        self.assertEqual(canonical_bytes(retrieved["lease"]), canonical_bytes(result["lease"]))
        renewal = self.request("renew", {"contact": self.contact, "lease_id": lease["lease_id"], "lease_seconds": 200},
                               request_id="renew_fixture", issued_at=self.now + 20, expires_at=self.now + 80)
        extended = self.index.handle(renewal, now=self.now + 20)
        self.assertEqual(extended["lease"]["payload"]["lease_id"], lease["lease_id"])
        self.assertEqual(extended["lease"]["payload"]["expires_at"], self.now + 220)
        self.db.close()
        self.db = sqlite3.connect(self.db_path)
        self.index = OpenIndex(self.db, self.server, self.node, enabled=True)
        self.index.initialize()
        self.assertEqual(canonical_bytes(self.get(now=self.now + 21)["lease"]), canonical_bytes(extended["lease"]))
        self.assertEqual(self.db.execute("SELECT value FROM prior_transport_state").fetchone()[0], "synthetic unchanged state")

    def test_default_closed_and_foreign_owner_cannot_allocate(self):
        closed = OpenIndex(self.db, self.server, self.node)
        request = self.request("put", {"contact": self.contact, "lease_seconds": 60})
        with self.assertRaisesRegex(MemoryError, "open_index_closed"):
            closed.handle(request, now=self.now)
        foreign = sign_request(self.other, action="put", request_id="foreign_fixture", node=self.node,
                               body={"contact": self.contact, "lease_seconds": 60},
                               issued_at=self.now, expires_at=self.now + 60)
        with self.assertRaisesRegex(MemoryError, "open_index_not_owner"):
            self.index.handle(foreign, now=self.now)
        self.assertEqual(self.db.execute("SELECT count(*) FROM open_contacts").fetchone()[0], 0)
        self.assertEqual(self.db.execute("SELECT count(*) FROM open_contact_floors").fetchone()[0], 0)

    def test_revocation_and_optout_do_not_publish_or_erase_security_floors(self):
        self.put()
        revoked = self.make_contact(revision=2, status="revoked", allow_discovery=False)
        self.put(contact=revoked, request_id="revoke_fixture")
        self.assertEqual(self.get(), {"state": "revoked"})
        with self.assertRaisesRegex(MemoryError, "open_contact_rollback"):
            self.put(request_id="rollback_fixture")
        row = self.db.execute("SELECT revision,record,retain_until FROM open_contact_floors WHERE owner=?", (self.owner.key_id,)).fetchone()
        self.assertEqual(row[0], 2)
        self.assertEqual(bytes(row[1]), canonical_bytes(revoked))
        self.assertGreaterEqual(row[2], self.now + FLOOR_RETENTION_SECONDS)
        opted_out = self.make_contact(revision=3, allow_discovery=False)
        self.put(contact=opted_out, request_id="optout_fixture")
        self.assertEqual(self.get(), {"state": "revoked"})

    def test_same_revision_fork_is_durable_even_when_unreserved_quota_is_full(self):
        self.put()
        # Set the configured budget to exactly the existing conservative
        # reservation/usage. The fork slot was reserved at first admission.
        floor_bytes = 2 * 4096 + 512
        contact_bytes = self.db.execute("SELECT sum(length(record)+length(lease)+256) FROM open_contacts").fetchone()[0]
        replay_bytes = self.db.execute("SELECT sum(length(response)+256) FROM open_index_replay").fetchone()[0]
        self.index.maximum_bytes = floor_bytes + contact_bytes + replay_bytes
        fork = self.make_contact(allow_discovery=False)
        with self.assertRaisesRegex(MemoryError, "open_contact_conflict"):
            self.put(contact=fork, request_id="fork_fixture")
        self.assertEqual(self.get(), {"state": "conflict"})
        row = self.db.execute("SELECT record,second_record FROM open_contact_floors").fetchone()
        self.assertEqual(bytes(row[0]), canonical_bytes(self.contact))
        self.assertEqual(bytes(row[1]), canonical_bytes(fork))
        self.db.close()
        self.db = sqlite3.connect(self.db_path)
        self.index = OpenIndex(self.db, self.server, self.node, enabled=True)
        self.index.initialize()
        self.assertEqual(self.get(), {"state": "conflict"})
        with self.assertRaisesRegex(MemoryError, "open_contact_conflict"):
            self.put(contact=self.make_contact(revision=2), request_id="unresolved_new_revision")
        self.assertEqual(self.get(), {"state": "conflict"})

    def test_replay_exact_receipt_and_changed_input_conflict(self):
        result, request = self.put()
        repeated = self.index.handle(request, now=self.now + 1)
        self.assertEqual(canonical_bytes(result), canonical_bytes(repeated))
        self.assertEqual(self.db.execute("SELECT count(*) FROM open_index_replay").fetchone()[0], 1)
        with self.assertRaisesRegex(MemoryError, "open_request_conflict"):
            self.put(seconds=121)
        self.assertEqual(canonical_bytes(self.get()["lease"]), canonical_bytes(result["lease"]))

    def test_capacity_and_sqlite_failure_roll_back_full_obligation(self):
        self.index.maximum_bytes = 1
        with self.assertRaisesRegex(MemoryError, "open_index_capacity"):
            self.put()
        self.assertEqual(self.db.execute("SELECT count(*) FROM open_contacts").fetchone()[0], 0)
        self.assertEqual(self.db.execute("SELECT count(*) FROM open_contact_floors").fetchone()[0], 0)
        self.index.maximum_bytes = 2 * 1024 * 1024
        self.db.execute("CREATE TRIGGER synthetic_failure BEFORE INSERT ON open_contacts BEGIN SELECT RAISE(ABORT,'synthetic interruption'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            self.put()
        self.assertEqual(self.db.execute("SELECT count(*) FROM open_contact_floors").fetchone()[0], 0)
        self.assertEqual(self.db.execute("SELECT count(*) FROM open_index_replay").fetchone()[0], 0)
        self.db.execute("DROP TRIGGER synthetic_failure")
        self.put()
        self.index.maximum_replays = 1
        with self.assertRaisesRegex(MemoryError, "open_index_capacity"):
            self.put(contact=self.make_contact(revision=2), request_id="full_replay_fixture")
        self.assertEqual(self.get()["contact"]["payload"]["revision"], 1)

    def test_lease_and_contact_clocks_are_separate_and_renewal_is_scoped(self):
        result, _ = self.put(seconds=30)
        self.assertEqual(self.get(now=self.now + 30), {"state": "not_found"})
        self.assertEqual(self.db.execute("SELECT count(*) FROM open_contact_floors").fetchone()[0], 1)
        request = self.request("renew", {"contact": self.contact, "lease_id": result["lease"]["payload"]["lease_id"], "lease_seconds": 120},
                               request_id="late_renew", issued_at=self.now + 30, expires_at=self.now + 90)
        with self.assertRaisesRegex(MemoryError, "open_lease_not_found"):
            self.index.handle(request, now=self.now + 30)
        short = self.make_contact(revision=2, expires_at=self.now + 50)
        result, _ = self.put(contact=short, request_id="bounded_owner_expiry", seconds=120)
        self.assertEqual(result["lease"]["payload"]["expires_at"], self.now + 50)

    def test_epoch_changes_and_nested_transactions_do_not_reactivate_index(self):
        self.put()
        other_epoch = self.make_node(self.server, storage_epoch="replacement_epoch")
        replacement = OpenIndex(self.db, self.server, other_epoch, enabled=True)
        with self.assertRaisesRegex(MemoryError, "open_storage_epoch_mismatch"):
            replacement.initialize()
        self.db.execute("BEGIN IMMEDIATE")
        with self.assertRaisesRegex(MemoryError, "open_storage_transaction"):
            self.get()
        self.db.rollback()
        self.assertEqual(self.get()["state"], "found")


if __name__ == "__main__":
    unittest.main()
