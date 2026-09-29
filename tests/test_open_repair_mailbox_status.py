"""Persistent owner revocation floors over an actual synthetic mailbox root."""
import json
import unittest

import memory_vault_open_provider as provider
from memory_vault_open_repair_mailbox_root import MailboxRootActivation
from memory_vault_open_repair_wire import RepairWireError
from tests import test_open_repair_mailbox_root as root_fixture
from tests.test_open_repair_status import status_entry


class MailboxStatusTests(unittest.TestCase):
    def setUp(self):
        self.host = root_fixture.MailboxRootTests("test_anchor_catalog_and_slot_originals_persist_and_replay_after_restart")
        if self._testMethodName == "test_ending_admission_does_not_shorten_independent_read_window":
            self.host.anchor_window_overrides = dict(admit_until=2_000_000_010)
        self.host.setUp(); self.addCleanup(self.host.doCleanups)
        active = self.host.activate()
        self.resource_id = json.loads(active["raw"])["payload"]["resource"]["resource_id"]
        self.root = self.host.state
        self.context = self.root.owner_status_context(self.resource_id)
        self.assertEqual(len(self.context["required"]),8)

    def entry(self,revision=1,*,revoked=False,minimum=1,selected=None,issued=None,until=None):
        h = self.host.h
        items = self.context["required"] if selected is None else selected
        entries = [dict(scope_kind=item["scope_kind"],scope_id=item["scope_id"],
            minimum_document_revision=minimum,status="revoked" if revoked else "active",operation_mask=127) for item in items]
        return status_entry(provider.issue_status(h.f["signers"]["owner"],root=h.root,revision=revision,
            entries=entries,issued_at=h.now if issued is None else issued,valid_until=h.now+300 if until is None else until))

    def observe(self,entry):
        return self.root.observe_owner_status(self.resource_id,entry)

    def guard(self):
        guard = self.root.owner_status_guard(self.resource_id)
        with self.root.source._transaction():
            return guard()

    def restart(self):
        h = self.host.h
        h.db.close(); h.connect()
        self.root = MailboxRootActivation(h.resources); self.root.initialize()

    def test_current_whole_status_is_required_and_replay_does_not_recharge(self):
        self.assertEqual(self.guard(),"repair_status_missing")
        entry = self.entry(); self.observe(entry)
        self.assertIsNone(self.guard())
        row = self.host.h.db.execute("SELECT metadata_bytes FROM open_repair_mailbox_resources WHERE resource_id=?",(self.resource_id,)).fetchone()
        self.observe(entry)
        self.assertEqual(self.host.h.db.execute("SELECT metadata_bytes FROM open_repair_mailbox_resources WHERE resource_id=?",(self.resource_id,)).fetchone(),row)
        self.restart(); self.assertIsNone(self.guard())

    def test_revocation_survives_restart_old_replay_and_new_active_status(self):
        old = self.entry(); self.observe(old)
        self.observe(self.entry(2,revoked=True))
        self.assertEqual(self.guard(),"repair_authority_revoked")
        self.restart()
        self.observe(old)  # Exact archived bytes remain an idempotent observation.
        self.observe(self.entry(3))
        self.assertEqual(self.guard(),"repair_authority_revoked")

    def test_expired_authentic_revocation_is_retained_before_refusal(self):
        start = self.host.h.now
        self.observe(self.entry())
        revoked = self.entry(2,revoked=True,issued=start,until=start+300)
        self.host.h.now += 301
        with self.assertRaisesRegex(RepairWireError,"repair_status_mismatch"):
            self.observe(revoked)
        self.restart()
        self.assertEqual(self.guard(),"repair_authority_revoked")

    def test_same_revision_disjoint_whole_documents_latch_conflict(self):
        scopes = self.context["required"]
        self.observe(self.entry(selected=scopes[:4]))
        self.assertEqual(self.guard(),"repair_status_missing")
        with self.assertRaisesRegex(RepairWireError,"repair_status_conflict"):
            self.observe(self.entry(selected=scopes[4:]))
        self.restart(); self.assertEqual(self.guard(),"repair_status_conflict")

    def test_minimum_revision_cannot_be_rolled_back_by_new_status(self):
        self.observe(self.entry(minimum=2))
        self.assertEqual(self.guard(),"repair_status_revision")
        with self.assertRaisesRegex(RepairWireError,"repair_status_rollback"):
            self.observe(self.entry(2,minimum=1))
        self.restart(); self.assertEqual(self.guard(),"repair_status_revision")

    def test_partial_ledger_loss_fails_closed(self):
        self.observe(self.entry())
        self.host.h.db.execute("DELETE FROM open_repair_mailbox_status_floors WHERE scope_id=?",(self.context["required"][0]["scope_id"],))
        self.host.h.db.commit()
        self.assertEqual(self.guard(),"repair_mailbox_status_ledger_missing")
        self.restart(); self.assertEqual(self.guard(),"repair_mailbox_status_ledger_missing")

    def test_capacity_failure_is_durable_without_accepting_a_status(self):
        self.host.h.db.execute("UPDATE open_repair_mailbox_resources SET metadata_bytes=262144 WHERE resource_id=?",(self.resource_id,))
        self.host.h.db.commit()
        with self.assertRaisesRegex(RepairWireError,"repair_mailbox_status_capacity"):
            self.observe(self.entry())
        self.restart(); self.assertEqual(self.guard(),"repair_mailbox_status_capacity")

    def test_revocation_observed_under_another_resource_still_blocks_anchor(self):
        from memory_vault_open_repair_mailbox_status import MailboxStatusLedger
        self.observe(self.entry())
        h = self.host.h
        data_id = h.db.execute("SELECT resource_id FROM open_repair_mailbox_resources WHERE purpose='mailbox_data'").fetchone()[0]
        ledger = MailboxStatusLedger(h.resources); ledger.initialize()
        ledger.observe(data_id,self.entry(2,revoked=True),expected_signing_key=self.context["signing_key"],
            allowed_scopes=[dict(scope_kind=v["scope_kind"],scope_id=v["scope_id"]) for v in self.context["required"]])
        self.observe(self.entry(3))
        self.restart(); self.assertEqual(self.guard(),"repair_authority_revoked")

    def test_other_signer_cannot_poison_the_owner_journal(self):
        h = self.host.h
        self.assertEqual(self.guard(),"repair_status_missing")
        entries = [dict(scope_kind=v["scope_kind"],scope_id=v["scope_id"],minimum_document_revision=1,
            status="revoked",operation_mask=127) for v in self.context["required"]]
        forged = status_entry(provider.issue_status(h.f["signers"]["writer"],root=h.root,revision=100,
            entries=entries,issued_at=h.now,valid_until=h.now+300))
        with self.assertRaises(RepairWireError):
            self.observe(forged)
        self.assertEqual(h.db.execute("SELECT count(*) FROM open_repair_mailbox_status_documents").fetchone()[0],0)
        self.observe(self.entry());self.assertIsNone(self.guard())

    def test_new_status_does_not_extend_expired_original_owner_authority(self):
        self.observe(self.entry())
        self.host.h.now += 601
        self.observe(self.entry(2))
        self.assertEqual(self.guard(),"repair_resource_expired")

    def test_ending_admission_does_not_shorten_independent_read_window(self):
        self.observe(self.entry())
        self.host.h.now += 11
        self.assertIsNone(self.guard())


if __name__ == "__main__":
    unittest.main()
