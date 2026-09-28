"""Synthetic owner originals activate real node resource rows atomically."""
import copy
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from memory_vault import canonical_bytes
from memory_vault_open_repair_mailbox_activation import MailboxSlotActivation
from memory_vault_open_repair_mailbox_resources import RepairMailboxResources
from memory_vault_open_repair_state import RepairAckState
from memory_vault_open_repair_wire import RepairWireError
import memory_vault_open_repair_history as history
from tests.open_repair_ack_fixtures import ack_unbound_fixture, signed_entry, LIMITS


class MailboxActivationTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(prefix="synthetic-mailbox-activation-")
        self.addCleanup(self.folder.cleanup)
        self.path = Path(self.folder.name) / "network.sqlite3"
        self.f = ack_unbound_fixture()
        self.now = 2_000_000_001
        self.connect()
        self.addCleanup(lambda: self.db.close())
        self.owner = self.f["expected"]["expected_owner"]
        self.offers = {}
        for purpose in ("mailbox_data", "feed_metadata"):
            p = copy.deepcopy(self.f["docs"]["allocate"]["payload"])
            p["intent"]["root_key"]["root_kind"] = "mailbox"
            p["intent"]["purpose"] = purpose
            p["intent"]["allocation_id"] = "synthetic_" + purpose
            p["request_id"] = "request_" + purpose
            p["intent_sha256"] = hashlib.sha256(canonical_bytes(p["intent"])).hexdigest()
            self.offers[purpose] = self.resources.allocate(signed_entry(p, self.f["signers"]["owner"], purpose),
                expected_owner=self.owner)
        self.root = p["intent"]["root_key"]
        self.slot_key = dict(root_key=self.root, slot_id="synthetic_slot", writer=self.dual(self.source.target),
                             writer_storage_epoch=self.source.node["payload"]["storage_epoch"])
        self.now += 1

    def connect(self):
        self.db = sqlite3.connect(self.path)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA trusted_schema=OFF")
        self.source = RepairAckState(self.db, self.f["signers"]["target"], self.f["docs"]["descriptor"],
            encryption_identity=self.f["encryption"]["target"], clock=lambda: self.now)
        self.resources = RepairMailboxResources(self.source)
        self.state = MailboxSlotActivation(self.resources)
        self.state.initialize()

    @staticmethod
    def dual(value):
        return dict(signing_key_id=value["signing_key"]["key_id"], encryption_key_id=value["encryption_key"]["key_id"])

    def setup_entries(self, changes=None):
        changes = changes or {}
        entries = {}
        def add(name, kind, **fields):
            p = dict(schema_version="memory-vault-open-repair/v1", kind=kind,
                signing_key=self.owner["signing_key"], issued_at=self.now, expires_at=self.now+600, **fields)
            p.update(changes.get(name, {}))
            entries[name] = signed_entry(p, self.f["signers"]["owner"], "synthetic_"+name)
            return p
        owner = self.dual(self.owner)
        sender = dict(signing_key_id=self.f["signers"]["writer"].key_id,
                      encryption_key_id=self.f["encryption"]["writer"].key_id)
        caps = copy.deepcopy(self.f["docs"]["allocate"]["payload"]["intent"]["budget"])
        windows = {k:self.now+600 for k in self.f["docs"]["allocate"]["payload"]["intent"]["windows"]}
        add("maintenance", "mailbox.maintenance_root", root_key=self.root,
            authority_id="synthetic_maintenance", slot_key=self.slot_key, sender=sender, recipient=owner,
            maintainers=[self.dual(self.source.target)], operation_mask=127,
            allowed_roles=sorted(["bootstrap.grant", "mailbox.slot", "mailbox.read_grant", "mailbox.maintenance_root", "selected_slot_service_v1"]),
            budget=caps, windows=windows, max_delegate_depth=2,max_destinations_per_job=2,max_concurrent_jobs=1,revision=1)
        add("read", "mailbox.read_grant", grant_id="synthetic_read", root_key=self.root,
            slot_key=self.slot_key, reader=owner, serving_authority_id="synthetic_maintenance",
            operation_mask=2,budget=caps, windows=windows,revision=1)
        data, metadata = self.offers["mailbox_data"], self.offers["feed_metadata"]
        slot = add("slot", "mailbox.slot", revision=1,slot_key=self.slot_key,
            feed_ref=dict(namespace="feed", key="a"*64), sender=sender, recipient=owner,
            data_resource_ref=json.loads(data["raw"])["payload"]["resource"],data_resource_offer_ref=data["ref"],
            metadata_resource_ref=json.loads(metadata["raw"])["payload"]["resource"],metadata_resource_offer_ref=metadata["ref"],
            read_grant_ref=entries["read"]["ref"],maintenance_root_ref=entries["maintenance"]["ref"],
            max_appends=16,max_live_items=16,budget=caps,windows=windows)
        add("bootstrap", "bootstrap.grant", grant_id="synthetic_bootstrap",revision=1,
            owner=owner,subject=owner,root_key=self.root,consumer="mailbox_feed",
            selector=dict(root_key_sha256=hashlib.sha256(canonical_bytes(self.root)).hexdigest(),
                slot_key_sha256=hashlib.sha256(canonical_bytes(self.slot_key)).hexdigest(),feed_ref=slot["feed_ref"],
                slot_sha256=entries["slot"]["ref"]["raw_sha256"],read_grant_sha256=entries["read"]["ref"]["raw_sha256"],
                maintenance_root_sha256=entries["maintenance"]["ref"]["raw_sha256"]),
            parent_authority_ref=entries["maintenance"]["ref"],caller_authority_ref=entries["read"]["ref"],
            probe_until=self.now+600,proof_until=self.now+600,upload_until=self.now+600,
            probe_profile="opaque_v1",response_profile="selected_slot_service_v1",
            upload_roles=["bootstrap.grant"],limits=LIMITS)
        add("activation", "resource.activation", activation_id="synthetic_activation",subject=self.owner,
            target_node_key_id=self.source.identity.key_id,target_storage_epoch=self.slot_key["writer_storage_epoch"],
            root_key=self.root,scope=dict(kind="mailbox_slot",slot_key=self.slot_key,slot_ref=entries["slot"]["ref"]),
            resource_offer_refs=sorted([data["ref"],metadata["ref"]],key=history._ref_tuple),
            authority_refs=[dict(role=kind,ref=entries[name]["ref"]) for name,kind in (
                ("maintenance","mailbox.maintenance_root"),("read","mailbox.read_grant"),("slot","mailbox.slot"))])
        return entries

    def activate(self, entries=None, **options):
        return self.state.activate(entries or self.setup_entries(), expected_slot=self.slot_key, **options)

    def test_pair_and_originals_survive_restart_without_reactivation(self):
        entries = self.setup_entries()
        result = self.activate(entries)
        self.assertEqual(set(result), {"data","metadata"})
        self.assertEqual(self.db.execute("SELECT status FROM open_repair_mailbox_resources").fetchall(), [("active",),("active",)])
        inputs = json.loads(self.db.execute("SELECT inputs FROM open_repair_mailbox_slot_activations").fetchone()[0])
        self.assertEqual({k:v["raw"].encode() for k,v in inputs.items()}, {k:v["raw"] for k,v in entries.items()})
        usage = self.source.capacity.usage()
        self.db.close(); self.now += 2000; self.connect()
        self.assertEqual(self.activate(entries), result)
        self.assertEqual(self.source.capacity.usage(), usage)
        self.assertEqual(self.db.execute("SELECT count(*) FROM open_repair_mailbox_slot_activations").fetchone()[0],1)

    def test_wrong_selected_scope_and_bootstrap_cannot_activate(self):
        for changes in ({"read":{"serving_authority_id":"wrong"}},
                        {"bootstrap":{"consumer":"mailbox_root"}},
                        {"bootstrap":{"upload_roles":["ack.write_grant"]}},
                        {"slot":{"max_live_items":17,"max_appends":16}}):
            with self.subTest(changes=changes):
                with self.assertRaises(RepairWireError):
                    self.activate(self.setup_entries(changes))
                self.assertEqual(self.db.execute("SELECT DISTINCT status FROM open_repair_mailbox_resources").fetchall(),[("pending",)])

    def test_commit_guard_failure_rolls_back_both_rows_and_retry_is_exact(self):
        calls = []
        def guard():
            calls.append(True)
            return "synthetic_scope_revoked" if len(calls)==2 else None
        with self.assertRaisesRegex(RepairWireError,"synthetic_scope_revoked"):
            self.activate(_transaction_guard=guard)
        self.assertEqual(self.db.execute("SELECT DISTINCT status FROM open_repair_mailbox_resources").fetchall(),[("pending",)])
        self.assertEqual(self.db.execute("SELECT count(*) FROM open_repair_mailbox_slot_activations").fetchone()[0],0)
        first = self.activate()
        with self.assertRaisesRegex(RepairWireError,"repair_activation_conflict"):
            self.activate(self.setup_entries({"read":{"grant_id":"different"}}))
        self.assertEqual(self.activate(),first)

    def test_expired_offer_is_not_activated(self):
        entries = self.setup_entries()
        self.now += 61
        with self.assertRaisesRegex(RepairWireError,"repair_resource_inactive"):
            self.activate(entries)
        self.assertEqual(self.db.execute("SELECT DISTINCT status FROM open_repair_mailbox_resources").fetchall(),[("pending",)])

    def test_metadata_exhaustion_does_not_leave_only_data_active(self):
        # Existing metadata usage is charged independently of the live payload
        # capacity. The second update must roll back the first activation.
        self.db.execute("UPDATE open_repair_mailbox_resources SET metadata_bytes=262144 WHERE purpose='feed_metadata'")
        self.db.commit()
        with self.assertRaisesRegex(RepairWireError,"repair_insufficient_capacity"):
            self.activate()
        self.assertEqual(self.db.execute("SELECT DISTINCT status FROM open_repair_mailbox_resources").fetchall(),[("pending",)])
        self.assertEqual(self.db.execute("SELECT count(*) FROM open_repair_mailbox_slot_activations").fetchone()[0],0)

    def test_expiry_during_work_is_rechecked_before_commit(self):
        calls = []
        def guard():
            calls.append(True)
            if len(calls) == 2:
                self.now += 61
        with self.assertRaisesRegex(RepairWireError,"repair_resource_expired"):
            self.activate(_transaction_guard=guard)
        self.assertEqual(self.db.execute("SELECT DISTINCT status FROM open_repair_mailbox_resources").fetchall(),[("pending",)])
        self.assertEqual(self.db.execute("SELECT count(*) FROM open_repair_mailbox_slot_activations").fetchone()[0],0)


if __name__ == "__main__":
    unittest.main()
