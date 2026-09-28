"""Node resource facts from actual synthetic mailbox reservations."""
import json
import unittest

from memory_vault_open_repair_mailbox_source import MailboxRootSource
from memory_vault_open_repair_mailbox_root import MailboxRootActivation
from memory_vault_open_repair_state import DEFAULT_POLICY
import memory_vault_open_repair_status as status
from memory_vault_open_repair_wire import RepairBudget, RepairWireError
from tests import test_open_repair_mailbox_root as root_fixture


class MailboxSourceTests(unittest.TestCase):
    def setUp(self):
        self.host = root_fixture.MailboxRootTests("test_anchor_catalog_and_slot_originals_persist_and_replay_after_restart")
        if "history" in self._testMethodName:
            self.host.anchor_budget_overrides = dict(max_meta_bytes=1048576)
        self.host.setUp();self.addCleanup(self.host.doCleanups)
        active = self.host.activate()
        self.resource_id = json.loads(active["raw"])["payload"]["resource"]["resource_id"]
        self.source = MailboxRootSource(self.host.state);self.source.initialize()
        self.until = self.host.h.now+100

    def observe(self,request="synthetic_observation",**options):
        return self.source.observe_resources(self.resource_id,request,valid_until=self.until,**options)

    def owner_observation(self):
        import memory_vault_open_provider as provider
        from tests.test_open_repair_status import status_entry
        context = self.host.state.owner_status_context(self.resource_id)
        value = status_entry(provider.issue_status(self.host.h.f["signers"]["owner"],root=self.host.h.root,revision=1,
            entries=[dict(scope_kind=v["scope_kind"],scope_id=v["scope_id"],minimum_document_revision=1,
                status="active",operation_mask=127) for v in context["required"]],
            issued_at=self.host.h.now,valid_until=self.until))
        self.host.state.observe_owner_status(self.resource_id,value)
        return value

    def test_history_pins_complete_originals_and_replays_after_restart(self):
        import memory_vault_open_repair_wire as wire
        import memory_vault_open_repair_history as history
        owner = self.owner_observation(); node = self.observe()[0]
        saved = self.source.prepare_history(self.resource_id,"synthetic_observation")
        budget = RepairBudget(DEFAULT_POLICY)
        resolver = wire.LocalRawResolver(DEFAULT_POLICY,budget)
        resolver.put("meta",saved["pack"]["ref"]["key"],saved["pack"]["raw"])
        resolved = history.resolve_historical_inputs(saved["manifest"]["raw"],resolver,DEFAULT_POLICY,budget)
        self.assertEqual({v.role for v in resolved.roles},history._ROLES["mailbox_root"])
        for v in resolved.roles:
            if v.role.startswith("historical.status."):
                self.assertEqual(v.original.raw,node["raw"] if v.role.endswith("_resource") else owner["raw"])
        before = self.host.h.db.execute("SELECT metadata_bytes FROM open_repair_mailbox_resources WHERE resource_id=?",(self.resource_id,)).fetchone()
        self.host.h.db.close();self.host.h.now += 1000;self.host.h.connect()
        self.source = MailboxRootSource(MailboxRootActivation(self.host.h.resources));self.source.initialize()
        self.assertEqual(self.source.prepare_history(self.resource_id,"synthetic_observation"),saved)
        self.assertEqual(self.host.h.db.execute("SELECT metadata_bytes FROM open_repair_mailbox_resources WHERE resource_id=?",(self.resource_id,)).fetchone(),before)

    def test_history_requires_current_owner_and_complete_resource_observation(self):
        self.observe()
        with self.assertRaisesRegex(RepairWireError,"repair_status_missing"):
            self.source.prepare_history(self.resource_id,"synthetic_observation")
        self.owner_observation()
        self.observe("synthetic_selected",slot_keys=[self.host.h.slot_key])
        with self.assertRaisesRegex(RepairWireError,"repair_status_missing"):
            self.source.prepare_history(self.resource_id,"synthetic_selected")
        self.assertEqual(self.host.h.db.execute("SELECT count(*) FROM open_repair_mailbox_root_history").fetchone()[0],0)

    def test_history_failed_commit_preserves_capacity_and_allows_retry(self):
        self.owner_observation();self.observe()
        before = self.host.h.db.execute("SELECT metadata_bytes FROM open_repair_mailbox_resources WHERE resource_id=?",(self.resource_id,)).fetchone()
        calls = []
        def guard():
            calls.append(True)
            return "synthetic_closed" if len(calls)==2 else None
        with self.assertRaisesRegex(RepairWireError,"synthetic_closed"):
            self.source.prepare_history(self.resource_id,"synthetic_observation",_transaction_guard=guard)
        self.assertEqual(self.host.h.db.execute("SELECT count(*) FROM open_repair_mailbox_root_history").fetchone()[0],0)
        self.assertEqual(self.host.h.db.execute("SELECT metadata_bytes FROM open_repair_mailbox_resources WHERE resource_id=?",(self.resource_id,)).fetchone(),before)
        self.source.prepare_history(self.resource_id,"synthetic_observation")

    def test_history_status_expiring_during_commit_leaves_no_promise(self):
        self.owner_observation();self.observe()
        calls = []
        def guard():
            calls.append(True)
            if len(calls)==2:
                self.host.h.now = self.until
        with self.assertRaises(RepairWireError):
            self.source.prepare_history(self.resource_id,"synthetic_observation",_transaction_guard=guard)
        self.assertEqual(self.host.h.db.execute("SELECT count(*) FROM open_repair_mailbox_root_history").fetchone()[0],0)

    def test_history_never_expands_the_signed_resource_capacity(self):
        self.owner_observation();self.observe()
        self.host.h.db.execute("UPDATE open_repair_mailbox_resources SET metadata_bytes=1048576 WHERE resource_id=?",(self.resource_id,))
        self.host.h.db.commit()
        with self.assertRaisesRegex(RepairWireError,"repair_insufficient_capacity"):
            self.source.prepare_history(self.resource_id,"synthetic_observation")
        self.assertEqual(self.host.h.db.execute("SELECT count(*) FROM open_repair_mailbox_root_history").fetchone()[0],0)
        self.assertEqual(self.host.h.db.execute("SELECT metadata_bytes FROM open_repair_mailbox_resources WHERE resource_id=?",(self.resource_id,)).fetchone()[0],1048576)

    def test_real_anchor_and_slot_resources_share_one_node_signed_original(self):
        result = self.observe();self.assertEqual(len(result),1)
        payload = json.loads(result[0]["raw"])["payload"]
        self.assertEqual(payload["revision"],1)
        self.assertEqual(len(payload["entries"]),3)
        scopes = []
        for (raw,) in self.host.h.db.execute("SELECT offer FROM open_repair_mailbox_resources"):
            ref = json.loads(raw)["payload"]["resource"]
            scopes.append(dict(scope_kind="resource",scope_id=status.status_scope(self.host.h.root,"resource",ref,DEFAULT_POLICY,RepairBudget(DEFAULT_POLICY))))
        status.verify_status_original(result[0],expected_root=self.host.h.root,
            expected_signing_key=self.host.h.source.identity.public_descriptor(),at=self.host.h.now,
            allowed_scopes=scopes,required=[dict(**s,document_revision=1,operation_mask=66) for s in scopes],
            policy=DEFAULT_POLICY,budget=RepairBudget(DEFAULT_POLICY))

    def test_selected_slot_excludes_anchor_and_uses_next_revision(self):
        all_resources = self.observe()
        selected = self.observe("synthetic_slot_only",slot_keys=[self.host.h.slot_key])
        self.assertEqual(len(json.loads(all_resources[0]["raw"])["payload"]["entries"]),3)
        p = json.loads(selected[0]["raw"])["payload"]
        self.assertEqual(p["revision"],2);self.assertEqual(len(p["entries"]),2)
        anchor = json.loads(self.host.offer["raw"])["payload"]["resource"]
        anchor_scope = status.status_scope(self.host.h.root,"resource",anchor,DEFAULT_POLICY,RepairBudget(DEFAULT_POLICY))
        self.assertNotIn(anchor_scope,[value["scope_id"] for value in p["entries"]])

    def test_restart_and_expired_retry_return_original_without_new_revision(self):
        first = self.observe()
        before = self.host.h.db.execute("SELECT metadata_bytes FROM open_repair_mailbox_resources WHERE resource_id=?",(self.resource_id,)).fetchone()
        self.host.h.db.close();self.host.h.now += 101;self.host.h.connect()
        self.source = MailboxRootSource(MailboxRootActivation(self.host.h.resources));self.source.initialize()
        self.assertEqual(self.observe(),first)
        self.assertEqual(self.host.h.db.execute("SELECT metadata_bytes FROM open_repair_mailbox_resources WHERE resource_id=?",(self.resource_id,)).fetchone(),before)
        self.assertEqual(self.host.h.db.execute("SELECT revision FROM open_repair_mailbox_node_revisions").fetchone()[0],1)

    def test_conflicting_request_and_failed_commit_cannot_advance_counter(self):
        first = self.observe()
        with self.assertRaisesRegex(RepairWireError,"repair_status_request_conflict"):
            self.observe(slot_keys=[self.host.h.slot_key])
        calls = []
        def guard():
            calls.append(True)
            return "synthetic_closed" if len(calls)==2 else None
        with self.assertRaisesRegex(RepairWireError,"synthetic_closed"):
            self.observe("synthetic_failed",_transaction_guard=guard)
        self.assertEqual(self.observe(),first)
        self.assertEqual(self.host.h.db.execute("SELECT revision FROM open_repair_mailbox_node_revisions").fetchone()[0],1)
        self.assertEqual(self.host.h.db.execute("SELECT count(*) FROM open_repair_mailbox_node_observations").fetchone()[0],1)

    def test_missing_counter_is_not_recreated_over_historical_observations(self):
        self.observe()
        self.host.h.db.execute("DELETE FROM open_repair_mailbox_node_revisions");self.host.h.db.commit()
        with self.assertRaisesRegex(RepairWireError,"repair_mailbox_status_ledger_missing"):
            self.observe("synthetic_next")

    def test_lost_earlier_request_cannot_be_resigned_as_a_new_result(self):
        self.observe()
        self.observe("synthetic_second",slot_keys=[self.host.h.slot_key])
        self.host.h.db.execute("DELETE FROM open_repair_mailbox_node_observations WHERE request_id='synthetic_observation'")
        self.host.h.db.commit()
        with self.assertRaisesRegex(RepairWireError,"repair_mailbox_status_ledger_missing"):
            self.observe()


if __name__ == "__main__":
    unittest.main()
