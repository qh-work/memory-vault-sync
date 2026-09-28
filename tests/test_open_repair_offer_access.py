"""Real empty-source permission for the independent B receipt writer."""
import unittest
from memory_vault_open_repair_offer_access import RepairAckOfferAccess, FIXED_PROOF_ROLES
from tests import test_open_repair_empty_access as fixture


class RepairOfferAccessTests(unittest.TestCase):
    def setUp(self):
        self.host = fixture.OpenRepairEmptyAccessTests()
        self.addCleanup(self.host.doCleanups)
        self.host.setUp()
        self.state, self.case = self.host.state, self.host.case
        self.gate = RepairAckOfferAccess(self.state)
        self.gate.initialize()

    def prepare(self, **changes):
        return self.gate.prepare(self.case.h.resource_id, **(dict(action="proof") | changes))

    def decision(self, prepared):
        with self.state._transaction():
            return self.gate.check_locked(prepared)

    def test_real_offer_uses_writer_subject_grant_and_closed_originals(self):
        prepared = self.prepare()
        with self.state._transaction():
            decision = self.gate.check_locked(prepared)
            self.assertTrue(decision.allowed, decision.code)
            decision, children = self.gate.proof_inputs(prepared)
        self.assertTrue(decision.allowed, decision.code)
        self.assertEqual(decision.subject, self.case.h.fixture["expected"]["expected_ack_slot"]["receipt_writer"])
        self.assertEqual(decision.bootstrap_grant_ref.as_dict(), self.case.offer["ref"])
        self.assertEqual({item["role"] for item in children if item["role"] != "history.raw_pack"}, FIXED_PROOF_ROLES)
        self.assertNotIn("read_grant_sha256", decision.selector)
        self.assertIn("write_grant_sha256", decision.selector)

    def test_owner_read_revocation_does_not_revoke_independent_offer(self):
        revoked = self.host.changed_status(revoked_roles=("current.status.ack_read",), revoked_mask=2)
        statuses = [revoked, self.case.expected["current_statuses"][1]]
        owner = self.host.decision(self.host.prepare(current_statuses=statuses))
        self.assertFalse(owner.allowed)
        offered = self.decision(self.prepare(current_statuses=statuses))
        self.assertTrue(offered.allowed, offered.code)

    def test_writer_admit_revocation_denies_offer_and_stale_proof_children(self):
        prepared = self.prepare()
        self.assertTrue(self.decision(prepared).allowed)
        revoked = self.host.changed_status(revoked_roles=("ack.write_grant",), revoked_mask=1)
        statuses = [revoked, self.case.expected["current_statuses"][1]]
        offered = self.decision(self.prepare(current_statuses=statuses))
        self.assertFalse(offered.allowed)
        self.assertEqual(offered.code, "repair_authority_revoked")
        with self.state._transaction():
            decision, children = self.gate.proof_inputs(prepared)
        self.assertFalse(decision.allowed)
        self.assertEqual(children, ())
        # A separate owner READ is still valid under the same durable floors.
        self.assertTrue(self.host.decision(self.host.prepare(current_statuses=statuses)).allowed)
