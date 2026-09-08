"""Signed observation floors survive restart without becoming a trust store."""
import sqlite3
import unittest

from memory_vault import MemoryError, canonical_bytes
from memory_vault_open_state import OpenCheckpoints, RESERVED_BYTES_PER_FLOOR
from tests import test_open_control as control_fixture


class OpenStateTests(unittest.TestCase):
    make_node = control_fixture.OpenControlTests.make_node
    make_contact = control_fixture.OpenControlTests.make_contact

    def setUp(self):
        control_fixture.OpenControlTests.setUp(self)
        self.database = self.path / "existing_transport.sqlite3"
        self.db = sqlite3.connect(self.database)
        self.addCleanup(lambda: self.db.close())
        self.db.execute("CREATE TABLE existing_transport_marker(value TEXT)")
        self.db.execute("INSERT INTO existing_transport_marker VALUES('synthetic preserved')")
        self.db.commit()
        self.state = OpenCheckpoints(self.db)
        self.state.initialize()

    def test_restart_preserves_highest_revision_and_original_signed_bytes(self):
        newer = self.make_node(self.server, revision=3)
        self.state.accept(newer, now=self.now)
        self.db.close()
        self.db = sqlite3.connect(self.database)
        self.state = OpenCheckpoints(self.db)
        self.state.initialize()
        with self.assertRaisesRegex(MemoryError, "open_control_rollback"):
            self.state.accept(self.node, now=self.now + 1)
        self.assertEqual(bytes(self.db.execute("SELECT record FROM open_control_floors").fetchone()[0]), canonical_bytes(newer))
        self.assertEqual(self.db.execute("SELECT value FROM existing_transport_marker").fetchone()[0], "synthetic preserved")

    def test_revocation_is_committed_before_refusal_and_blocks_older_contacts(self):
        self.state.accept(self.contact, now=self.now)
        revoked = self.make_contact(revision=2, status="revoked")
        with self.assertRaisesRegex(MemoryError, "open_control_revoked"):
            self.state.accept(revoked, now=self.now)
        row = self.db.execute("SELECT status,record FROM open_control_floors").fetchone()
        self.assertEqual(row[0], "revoked")
        self.assertEqual(bytes(row[1]), canonical_bytes(revoked))
        with self.assertRaisesRegex(MemoryError, "open_control_rollback"):
            self.state.accept(self.contact, now=self.now + 1)

    def test_reserved_fork_slot_survives_full_capacity_and_does_not_auto_resolve(self):
        self.state = OpenCheckpoints(self.db, maximum_records=1, maximum_bytes=RESERVED_BYTES_PER_FLOOR)
        self.state.accept(self.node, now=self.now)
        fork = self.make_node(self.server, base_url="http://127.0.0.1:18502")
        with self.assertRaisesRegex(MemoryError, "open_control_conflict"):
            self.state.accept(fork, now=self.now)
        row = self.db.execute("SELECT record,second_record FROM open_control_floors").fetchone()
        self.assertEqual(bytes(row[0]), canonical_bytes(self.node))
        self.assertEqual(bytes(row[1]), canonical_bytes(fork))
        with self.assertRaisesRegex(MemoryError, "open_control_conflict"):
            self.state.accept(self.make_node(self.server, revision=2), now=self.now + 1)
        with self.assertRaisesRegex(MemoryError, "open_checkpoint_capacity"):
            self.state.accept(self.make_node(self.other), now=self.now)
        self.assertEqual(self.db.execute("SELECT count(*) FROM open_control_floors").fetchone()[0], 1)

    def test_invalid_signature_and_storage_failure_never_partially_create_floor(self):
        altered = dict(self.node)
        altered["proof"] = self.other.sign_message(altered["payload"])
        with self.assertRaises(MemoryError):
            self.state.accept(altered, now=self.now)
        self.assertEqual(self.db.execute("SELECT count(*) FROM open_control_floors").fetchone()[0], 0)
        self.db.execute("CREATE TRIGGER synthetic_floor_failure BEFORE INSERT ON open_control_floors BEGIN SELECT RAISE(ABORT,'synthetic failure'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            self.state.accept(self.node, now=self.now)
        self.assertEqual(self.db.execute("SELECT count(*) FROM open_control_floors").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
