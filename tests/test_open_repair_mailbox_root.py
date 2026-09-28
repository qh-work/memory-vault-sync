"""Real local anchor activation over a fresh synthetic committed slot."""
import copy
import hashlib
import json
import unittest

from memory_vault import canonical_bytes
from memory_vault_open_repair_mailbox_root import MailboxRootActivation
from memory_vault_open_repair_wire import RepairWireError
import memory_vault_open_repair_history as history
from tests.open_repair_ack_fixtures import signed_entry, LIMITS
from tests import test_open_repair_mailbox_activation as slot_fixture


class MailboxRootTests(unittest.TestCase):
    def setUp(self):
        self.h = slot_fixture.MailboxActivationTests("test_pair_and_originals_survive_restart_without_reactivation")
        self.h.setUp(); self.addCleanup(self.h.doCleanups)
        h = self.h
        self.slot_entries = h.setup_entries()
        h.activate(self.slot_entries)
        p = copy.deepcopy(h.f["docs"]["allocate"]["payload"])
        p["intent"].update(root_key=h.root,purpose="anchor_catalog",allocation_id="synthetic_anchor")
        p["intent"]["windows"].update(getattr(self,"anchor_window_overrides",{}))
        p["request_id"] = "synthetic_anchor_request"
        p["intent_sha256"] = hashlib.sha256(canonical_bytes(p["intent"])).hexdigest()
        self.offer = h.resources.allocate(signed_entry(p,h.f["signers"]["owner"],"synthetic_anchor"),expected_owner=h.owner)
        self.state = MailboxRootActivation(h.resources); self.state.initialize()

    def entries(self, changes=None):
        changes = changes or {}
        h = self.h; entries = {}
        def add(name,kind,**fields):
            p = dict(schema_version="memory-vault-open-repair/v1",kind=kind,signing_key=h.owner["signing_key"],
                issued_at=h.now,expires_at=h.now+600,**fields)
            p.update(changes.get(name,{}))
            entries[name] = signed_entry(p,h.f["signers"]["owner"],"synthetic_root_"+name)
        caps = copy.deepcopy(h.f["docs"]["allocate"]["payload"]["intent"]["budget"])
        windows = {k:h.now+600 for k in h.f["docs"]["allocate"]["payload"]["intent"]["windows"]}
        add("root","mailbox.root_authority",root_key=h.root,authority_id="synthetic_root_authority",
            original_resource_ref=json.loads(self.offer["raw"])["payload"]["resource"],original_resource_offer_ref=self.offer["ref"],
            slot_ids=[h.slot_key["slot_id"]],maintainers=[h.dual(h.source.target)],operation_mask=127,
            allowed_roles=["bootstrap.grant","mailbox.root_authority","mailbox.root_read_grant","mailbox_root_service_v1"],
            budget=caps,windows=windows,max_delegate_depth=2,max_destinations_per_job=2,max_concurrent_jobs=1,revision=1)
        add("read","mailbox.root_read_grant",grant_id="synthetic_root_read",root_key=h.root,reader=h.dual(h.owner),
            root_authority_ref=entries["root"]["ref"],operation_mask=2,budget=caps,windows=windows,revision=1)
        add("catalog","mailbox.catalog",root_key=h.root,revision=1,slot_refs=[self.slot_entries["slot"]["ref"]],
            root_authority_ref=entries["root"]["ref"])
        add("bootstrap","bootstrap.grant",grant_id="synthetic_root_bootstrap",revision=1,
            owner=h.dual(h.owner),subject=h.dual(h.owner),root_key=h.root,consumer="mailbox_root",
            selector=dict(root_key_sha256=hashlib.sha256(canonical_bytes(h.root)).hexdigest(),anchor_ref=h.root["anchor_ref"],
                root_authority_sha256=entries["root"]["ref"]["raw_sha256"],read_grant_sha256=entries["read"]["ref"]["raw_sha256"]),
            parent_authority_ref=entries["root"]["ref"],caller_authority_ref=entries["read"]["ref"],
            probe_until=h.now+600,proof_until=h.now+600,upload_until=h.now+600,probe_profile="opaque_v1",
            response_profile="mailbox_root_service_v1",upload_roles=["bootstrap.grant"],limits=LIMITS)
        refs = [dict(role=kind,ref=entries[name]["ref"]) for name,kind in (
            ("root","mailbox.root_authority"),("read","mailbox.root_read_grant"),("catalog","mailbox.catalog"))]
        refs += [dict(role=kind,ref=self.slot_entries[name]["ref"]) for name,kind in (
            ("slot","mailbox.slot"),("read","mailbox.read_grant"),("maintenance","mailbox.maintenance_root"))]
        refs.sort(key=lambda v:(v["role"],*history._ref_tuple(v["ref"])))
        add("activation","resource.activation",activation_id="synthetic_root_activation",subject=h.owner,
            target_node_key_id=h.source.identity.key_id,target_storage_epoch=h.slot_key["writer_storage_epoch"],root_key=h.root,
            scope=dict(kind="mailbox_root",root_key=h.root,root_authority_ref=entries["root"]["ref"],catalog_ref=entries["catalog"]["ref"]),
            resource_offer_refs=[self.offer["ref"]],authority_refs=refs)
        return entries

    def activate(self, entries=None, **options):
        return self.state.activate(entries or self.entries(),expected_root=self.h.root,slot_keys=[self.h.slot_key],**options)

    def test_anchor_catalog_and_slot_originals_persist_and_replay_after_restart(self):
        entries = self.entries(); first = self.activate(entries)
        self.assertEqual(json.loads(first["raw"])["payload"]["purpose"],"anchor_catalog")
        row = self.h.db.execute("SELECT inputs,slots FROM open_repair_mailbox_roots").fetchone()
        self.assertEqual(json.loads(row[0])["catalog"]["raw"].encode(),entries["catalog"]["raw"])
        self.assertEqual(json.loads(row[1])[0]["entries"]["slot"]["raw"].encode(),self.slot_entries["slot"]["raw"])
        self.assertEqual(self.h.db.execute("SELECT DISTINCT status FROM open_repair_mailbox_resources").fetchall(),[("active",)])
        usage = self.h.source.capacity.usage()
        self.h.db.close(); self.h.now += 2000; self.h.connect()
        self.state = MailboxRootActivation(self.h.resources); self.state.initialize()
        self.assertEqual(self.activate(entries),first)
        self.assertEqual(self.h.source.capacity.usage(),usage)

    def test_catalog_cannot_substitute_or_omit_committed_slots(self):
        for change in ({"catalog":{"slot_refs":[]}}, {"root":{"slot_ids":["synthetic_other"]}},
                       {"bootstrap":{"consumer":"mailbox_feed"}}, {"activation":{"authority_refs":[]}}):
            with self.subTest(change=change),self.assertRaises(RepairWireError):
                self.activate(self.entries(change))
        self.assertEqual(self.h.db.execute("SELECT count(*) FROM open_repair_mailbox_roots").fetchone()[0],0)

    def test_missing_genesis_is_not_a_completed_slot(self):
        self.h.db.execute("DELETE FROM open_repair_mailbox_genesis");self.h.db.commit()
        with self.assertRaisesRegex(RepairWireError,"repair_mailbox_slot_incomplete"):
            self.activate()

    def test_final_guard_rolls_back_anchor_and_conflicting_replay_is_rejected(self):
        calls = []
        def guard():
            calls.append(True)
            return "synthetic_revoked" if len(calls)==2 else None
        with self.assertRaisesRegex(RepairWireError,"synthetic_revoked"):
            self.activate(_transaction_guard=guard)
        self.assertEqual(self.h.db.execute("SELECT status FROM open_repair_mailbox_resources WHERE purpose='anchor_catalog'").fetchone()[0],"pending")
        self.assertEqual(self.h.db.execute("SELECT count(*) FROM open_repair_mailbox_roots").fetchone()[0],0)
        first = self.activate()
        with self.assertRaisesRegex(RepairWireError,"repair_activation_conflict"):
            self.activate(self.entries({"read":{"grant_id":"synthetic_changed"}}))
        self.assertEqual(self.activate(),first)

    def test_expiry_during_anchor_commit_preserves_the_existing_slot(self):
        calls = []
        def guard():
            calls.append(True)
            if len(calls)==2:
                self.h.now += 61
        with self.assertRaisesRegex(RepairWireError,"repair_resource_expired"):
            self.activate(_transaction_guard=guard)
        self.assertEqual(self.h.db.execute("SELECT count(*) FROM open_repair_mailbox_roots").fetchone()[0],0)
        self.assertEqual(self.h.db.execute("SELECT status FROM open_repair_mailbox_resources WHERE purpose='anchor_catalog'").fetchone()[0],"pending")
        self.assertEqual(self.h.db.execute("SELECT count(*) FROM open_repair_mailbox_genesis").fetchone()[0],1)


if __name__ == "__main__":
    unittest.main()
