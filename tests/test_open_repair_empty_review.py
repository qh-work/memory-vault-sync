"""Empty retries must reauthenticate every retained predecessor pin."""
import unittest

from memory_vault_open_repair_empty_state import RepairAckEmptyState
import memory_vault_open_repair_wire as wire
from tests import test_open_repair_empty as empty_fixture


class EmptyPredecessorPinReviewTests(unittest.TestCase):
    def setUp(self):
        self.case=empty_fixture.OpenRepairEmptyTests()
        self.case.setUp()
        self.addCleanup(self.case.tearDown)
        self.original=self.case.bind()

    def restart_and_refuse(self):
        case=self.case
        case.h.db.commit()
        case.h.db.close()
        case.h.connect()
        case.empty=RepairAckEmptyState(case.h.state)
        case.empty.initialize()
        with self.assertRaises(wire.RepairWireError):
            case.bind()
        self.assertEqual(case.h.db.execute("SELECT count(*) FROM open_repair_ack_bindings").fetchone()[0],1)

    def test_corrupt_predecessor_standalone_original_is_not_hidden_by_intact_pack(self):
        case=self.case
        ref=case.h.fixture["entries"]["root"]["ref"]
        case.h.db.execute("UPDATE open_repair_ack_objects SET raw=? WHERE namespace=? AND opaque_key=?",
                         (b"corrupt predecessor root",ref["namespace"],ref["key"]))
        self.restart_and_refuse()

    def test_valid_original_under_wrong_predecessor_role_cannot_pass_exact_retry(self):
        case=self.case
        ref=case.h.fixture["entries"]["read"]["ref"]
        case.h.db.execute("DELETE FROM open_repair_ack_pins WHERE resource_id=? AND role='ack.root_authority'",
                         (case.h.resource_id,))
        case.h.db.execute("INSERT INTO open_repair_ack_pins VALUES(?,?,?,?)",
                         (case.h.resource_id,ref["namespace"],ref["key"],"ack.root_authority"))
        self.restart_and_refuse()

    def test_unreferenced_predecessor_pack_is_not_silently_retained_as_authorized(self):
        case=self.case
        policy=case.h.state.policy
        packed=wire.build_raw_pack([b'{"synthetic":"unrelated object"}'],policy,wire.RepairBudget(policy))
        ref=packed.ref
        case.h.db.execute("INSERT INTO open_repair_ack_objects VALUES(?,?,?,?,?)",
                         (ref.namespace,ref.key,ref.raw_sha256,ref.size,packed.raw))
        case.h.db.execute("INSERT INTO open_repair_ack_pins VALUES(?,?,?,?)",
                         (case.h.resource_id,ref.namespace,ref.key,"pack"))
        self.restart_and_refuse()


if __name__=="__main__":
    unittest.main()
