"""Real mailbox reservations and crash/retry boundaries in synthetic SQLite."""
import copy
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from memory_vault import MemoryError, canonical_bytes
from memory_vault_open_capacity import SERVICE_RESERVE_BYTES
from memory_vault_open_repair_mailbox_resources import RepairMailboxResources, PURPOSES
from memory_vault_open_repair_state import RepairAckState
from memory_vault_open_repair_wire import RepairWireError
from tests.open_repair_ack_fixtures import ack_unbound_fixture, signed_entry


class MailboxResourceTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(prefix="synthetic-mailbox-resource-")
        self.addCleanup(self.folder.cleanup)
        self.path = Path(self.folder.name) / "network.sqlite3"
        self.f = ack_unbound_fixture()
        self.now = 2_000_000_001
        self.connect()
        self.addCleanup(lambda: self.db.close())

    def connect(self, capacity_policy=None):
        self.db = sqlite3.connect(self.path)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA trusted_schema=OFF")
        self.source = RepairAckState(self.db, self.f["signers"]["target"], self.f["docs"]["descriptor"],
            encryption_identity=self.f["encryption"]["target"], clock=lambda: self.now,
            capacity_policy=capacity_policy)
        self.state = RepairMailboxResources(self.source)
        self.state.initialize()

    def entry(self, purpose, **changes):
        p = copy.deepcopy(self.f["docs"]["allocate"]["payload"])
        p["intent"]["root_key"]["root_kind"] = "mailbox"
        p["intent"]["purpose"] = purpose
        p["intent"]["allocation_id"] = "synthetic_" + purpose
        p["request_id"] = "request_" + purpose
        p["intent"].update(changes)
        p["intent_sha256"] = hashlib.sha256(canonical_bytes(p["intent"])).hexdigest()
        return signed_entry(p, self.f["signers"]["owner"], purpose)

    def allocate(self, entry, **options):
        return self.state.allocate(entry, expected_owner=self.f["expected"]["expected_owner"], **options)

    def initial(self, entries=None, **options):
        return self.state.allocate_initial(entries or [self.entry(p) for p in sorted(PURPOSES)],
            expected_owner=self.f["expected"]["expected_owner"], **options)

    def test_three_real_reservations_survive_restart_and_exact_expired_retry(self):
        offers = self.initial()
        self.assertEqual(set(offers), PURPOSES)
        self.assertEqual(self.source.capacity.usage()["reservations"], 3)
        self.assertEqual(self.db.execute("SELECT DISTINCT status FROM open_repair_mailbox_resources").fetchall(), [("pending",)])
        self.assertEqual(self.db.execute("SELECT DISTINCT service FROM open_capacity_reservations").fetchall(), [("mailbox",)])
        self.assertEqual(self.db.execute("SELECT count(*) FROM open_repair_ack_resources").fetchone()[0], 0)
        original_usage = self.source.capacity.usage()
        self.db.close()
        self.now += 2000
        self.connect()
        self.assertEqual(self.initial(), offers)
        self.assertEqual(self.source.capacity.usage(), original_usage)
        for offer in offers.values():
            self.assertLess(json.loads(offer["raw"])["payload"]["reservation_until"], self.now)

    def test_shared_capacity_refuses_batch_without_leaking_earlier_reservations(self):
        self.db.execute("UPDATE open_capacity_policy SET maximum_reservations=2 WHERE singleton=1")
        self.db.commit()
        with self.assertRaisesRegex(MemoryError, "open_capacity_exhausted"):
            self.initial()
        self.assertEqual(self.source.capacity.usage()["reservations"], 0)
        self.assertEqual(self.db.execute("SELECT count(*) FROM open_repair_mailbox_resources").fetchone()[0], 0)
        self.allocate(self.entry("anchor_catalog"))
        self.db.execute("BEGIN IMMEDIATE")
        self.source.capacity.reserve("ack", "synthetic_other", "a" * 64, 1, self.now + 100,
            owner="synthetic_owner", operation_id="synthetic_other")
        self.db.commit()
        with self.assertRaisesRegex(MemoryError, "open_capacity_exhausted"):
            self.allocate(self.entry("mailbox_data"))
        self.assertEqual(self.source.capacity.usage()["reservations"], 2)

    def test_conflicting_retry_and_ack_authority_cannot_allocate_mailbox(self):
        first = self.allocate(self.entry("mailbox_data"))
        changed = self.entry("feed_metadata", allocation_id="synthetic_mailbox_data")
        with self.assertRaisesRegex(RepairWireError, "repair_allocation_conflict"):
            self.allocate(changed)
        with self.assertRaisesRegex(RepairWireError, "repair_invalid_resource"):
            self.allocate(self.f["entries"]["allocate"])
        self.assertEqual(self.allocate(self.entry("mailbox_data")), first)
        resource_id = json.loads(first["raw"])["payload"]["resource"]["resource_id"]
        with self.assertRaisesRegex(RepairWireError, "repair_unknown_resource"):
            self.source._row(resource_id)

    def test_missing_live_capacity_mismatched_root_and_commit_guard_roll_back(self):
        caps = copy.deepcopy(self.f["docs"]["allocate"]["payload"]["intent"]["budget"])
        caps["max_live_bytes"] = 0
        with self.assertRaisesRegex(RepairWireError, "repair_insufficient_capacity"):
            self.allocate(self.entry("mailbox_data", budget=caps))
        entries = [self.entry(p) for p in sorted(PURPOSES)]
        root = copy.deepcopy(json.loads(entries[0]["raw"])["payload"]["intent"]["root_key"])
        root["root_id"] = "synthetic_other_root"
        entries[0] = self.entry("anchor_catalog", root_key=root)
        with self.assertRaisesRegex(RepairWireError, "repair_resource_mismatch"):
            self.initial(entries)
        calls = []
        def guard():
            calls.append(True)
            return "synthetic_authority_changed" if len(calls) == 2 else None
        with self.assertRaisesRegex(RepairWireError, "synthetic_authority_changed"):
            self.initial(_transaction_guard=guard)
        self.assertEqual(self.source.capacity.usage()["reserved_bytes"], SERVICE_RESERVE_BYTES)
        self.assertEqual(self.db.execute("SELECT count(*) FROM open_repair_mailbox_resources").fetchone()[0], 0)

    def test_rejects_wrong_owner_epoch_and_non_mailbox_purpose_before_reserving(self):
        original = json.loads(self.entry("mailbox_data")["raw"])["payload"]
        mutations = [
            ("purpose", []), ("purpose", "ack_slot"),
            ("target_storage_epoch", "synthetic_wrong_epoch"),
            ("owner", self.source.target),
        ]
        for name, value in mutations:
            with self.subTest(name=name, value=value):
                payload = copy.deepcopy(original)
                payload["intent"][name] = value
                payload["intent_sha256"] = hashlib.sha256(canonical_bytes(payload["intent"])).hexdigest()
                entry = signed_entry(payload, self.f["signers"]["owner"], "synthetic_bad")
                with self.assertRaises(RepairWireError):
                    self.allocate(entry)
                self.assertEqual(self.source.capacity.usage()["reservations"], 0)
        entry = signed_entry(original, self.f["signers"]["writer"], "synthetic_wrong_signer")
        with self.assertRaises(RepairWireError):
            self.allocate(entry)
        self.assertEqual(self.source.capacity.usage()["reservations"], 0)


if __name__ == "__main__":
    unittest.main()
