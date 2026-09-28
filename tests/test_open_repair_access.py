"""Real current T observations, durable denials and same-source service gates."""
import copy
import hashlib
import json
import unittest
from unittest import mock

from memory_vault import canonical_bytes
from memory_vault_open_repair_access import RepairAckAccess, CURRENT_ROLES
import memory_vault_open_repair_wire as wire
from tests.open_repair_ack_fixtures import signed_entry
from tests import test_open_repair_state as source_fixture
from tests import open_repair_ack_fixtures as ack_fixture


class RepairAccessTests(unittest.TestCase):
    def setUp(self):
        self.source = source_fixture.RepairStateTests()
        self.source.setUp()
        self.source.activate()
        self.source.finalize()
        self.access = RepairAckAccess(self.source.state)
        self.access.initialize()

    def tearDown(self):
        self.source.tearDown()

    def statuses(self, revision=1, change=None):
        f = self.source.fixture
        result = []
        for role, signer in (("owner_status", "owner"), ("target_status", "target")):
            payload = copy.deepcopy(f["docs"][role]["payload"])
            payload["revision"] = revision
            if change is not None:
                change(role, payload)
            result.append(signed_entry(payload, f["signers"][signer], "current_" + role))
        return result

    def gate(self, entries=None, **options):
        prepared = self.access.prepare(self.source.resource_id, action=options.pop("action", "proof"),
            current_statuses=entries, **options)
        with self.source.state._transaction():
            result = self.access.check_locked(prepared)
        return result

    def test_current_complete_gate_proof_children_and_exact_retry(self):
        prepared = self.access.prepare(self.source.resource_id, action="challenge")
        with self.source.state._transaction():
            decision = self.access.check_locked(prepared)
            decision, children = self.access.proof_inputs(prepared)
        self.assertTrue(decision.allowed)
        self.assertEqual(len(children), 21)
        self.assertTrue(set(CURRENT_ROLES) <= {child["role"] for child in children})
        self.assertEqual(sum(child["role"] == "history.raw_pack" for child in children), 1)
        for child in children:
            self.assertEqual(child["ref"].size, len(child["raw"]))
        metadata = self.source.state._row(self.source.resource_id)["metadata_bytes"]
        again = self.gate(action="challenge")
        self.assertTrue(again.allowed)
        self.assertEqual(again.generation, decision.generation)
        self.assertEqual(self.source.state._row(self.source.resource_id)["metadata_bytes"], metadata)

    def test_older_current_revocation_survives_rollback_denial_and_restart(self):
        self.assertTrue(self.gate(self.statuses(3)).allowed)
        def revoke(role, payload):
            if role == "owner_status":
                payload["entries"][0]["status"] = "revoked"
        refused = self.gate(self.statuses(2, revoke))
        self.assertFalse(refused.allowed)
        self.assertEqual(refused.code, "repair_authority_revoked")
        self.source.db.close()
        self.source.connect()
        self.access = RepairAckAccess(self.source.state)
        self.access.initialize()
        self.assertEqual(self.gate(self.statuses(4)).code, "repair_authority_revoked")

    def test_same_revision_signed_conflict_is_sticky_after_denial(self):
        self.assertTrue(self.gate(self.statuses(2)).allowed)
        def changed(role, payload):
            if role == "owner_status":
                payload["valid_until"] -= 1
        self.assertEqual(self.gate(self.statuses(2, changed)).code, "repair_status_conflict")
        self.assertEqual(self.gate(self.statuses(3)).code, "repair_status_conflict")

    def test_minimum_floor_and_missing_operation_are_persisted(self):
        def advanced(role, payload):
            if role == "owner_status":
                payload["entries"][0]["minimum_document_revision"] = 2
        self.assertEqual(self.gate(self.statuses(2, advanced)).code, "repair_status_revision")
        result = self.gate(self.statuses(3))
        self.assertFalse(result.allowed)
        self.assertIn(result.code, ("repair_status_rollback", "repair_status_revision"))

    def test_challenge_discover_cannot_be_substituted_by_proof_read(self):
        def read_only(role, payload):
            for item in payload["entries"]:
                item["operation_mask"] = 2
        entries = self.statuses(2, read_only)
        self.assertTrue(self.gate(entries, action="proof").allowed)
        result = self.gate(entries, action="challenge")
        self.assertEqual(result.code, "repair_status_operation")

    def test_whole_status_unrelated_entry_rejected_even_with_all_needed_entries(self):
        def unrelated(role, payload):
            if role == "owner_status":
                payload["entries"].append(dict(scope_kind="authority", scope_id="ff"*32,
                    minimum_document_revision=0, status="active", operation_mask=127))
                payload["entries"].sort(key=lambda item:(item["scope_kind"], item["scope_id"]))
        self.assertEqual(self.gate(self.statuses(2, unrelated)).code, "repair_status_disclosure")

    def test_current_clock_generation_and_changed_bytes_are_rechecked(self):
        first = self.gate(self.statuses(1))
        changed = self.gate(self.statuses(2))
        self.assertGreater(changed.generation, first.generation)
        self.assertEqual(self.gate(expected_generation=first.generation).code, "repair_access_generation")
        prepared = self.access.prepare(self.source.resource_id, action="proof")
        self.source.now[0] = changed.expires_at
        with self.source.state._transaction():
            self.assertFalse(self.access.check_locked(prepared).allowed)

    def test_equivalent_signed_wire_changes_generation_without_revision_conflict(self):
        entries = self.statuses(2)
        first = self.gate(entries)
        raw = json.dumps(json.loads(entries[0]["raw"]), indent=2).encode()
        entries[0] = dict(raw=raw, ref={**entries[0]["ref"], "raw_sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)})
        changed = self.gate(entries)
        self.assertTrue(changed.allowed)
        self.assertGreater(changed.generation, first.generation)
        self.assertEqual(self.gate().generation, changed.generation)

    def test_removed_pinned_bytes_cannot_use_an_earlier_preparation(self):
        prepared = self.access.prepare(self.source.resource_id, action="proof")
        self.source.db.execute("DELETE FROM open_repair_ack_objects WHERE rowid=(SELECT min(rowid) FROM open_repair_ack_objects)")
        self.source.db.commit()
        with self.source.state._transaction(), self.assertRaisesRegex(wire.RepairWireError, "repair_storage_corrupt"):
            self.access.check_locked(prepared)

    def test_private_preparation_shared_work_meter_and_no_crypto_under_lock(self):
        budget = wire.RepairBudget(self.source.state.policy)
        prepared = self.access.prepare(self.source.resource_id, action="proof",
            policy=self.source.state.policy, budget=budget)
        before = budget.snapshot()
        with self.source.state._transaction():
            self.assertTrue(self.access.check_locked(prepared).allowed)
            decision, children = self.access.proof_inputs(prepared)
            self.assertTrue(decision.allowed)
            self.assertTrue(children)
        self.assertEqual(before, budget.snapshot())
        self.assertGreater(before["signature_checks"], 0)
        other = RepairAckAccess(self.source.state)
        with self.source.state._transaction(), self.assertRaisesRegex(wire.RepairWireError, "repair_access_preparation"):
            other.check_locked(prepared)

    def test_lost_floor_is_not_reinitialized_and_capacity_latches_closed(self):
        self.assertTrue(self.gate().allowed)
        self.source.db.execute("DELETE FROM open_repair_access_floors WHERE rowid=(SELECT min(rowid) FROM open_repair_access_floors)")
        self.source.db.commit()
        prepared = self.access.prepare(self.source.resource_id, action="proof")
        with self.source.state._transaction(), self.assertRaisesRegex(wire.RepairWireError, "repair_access_ledger_missing"):
            self.access.check_locked(prepared)

    def test_capacity_failure_survives_later_freed_metadata(self):
        self.source.db.execute("UPDATE open_repair_ack_resources SET metadata_bytes=262144")
        self.source.db.commit()
        self.assertEqual(self.gate().code, "repair_access_capacity")
        self.source.db.execute("UPDATE open_repair_ack_resources SET metadata_bytes=0")
        self.source.db.commit()
        self.assertEqual(self.gate().code, "repair_access_capacity")

    def test_ack_slot_revocation_crosses_two_resources_and_invalidates_existing_child(self):
        first_resource = self.source.resource_id
        self.assertTrue(self.gate(self.statuses(3)).allowed)
        def revoke_slot(role, payload):
            if role == "owner_status":
                next(item for item in payload["entries"] if item["scope_kind"] == "ack_slot")["status"] = "revoked"
        first_revocation = self.statuses(5, revoke_slot)
        f = self.source.fixture
        allocation = copy.deepcopy(f["docs"]["allocate"]["payload"])
        allocation["intent"]["allocation_id"] = "synthetic_second_allocation"
        allocation["request_id"] = "synthetic_second_request"
        allocation["intent_sha256"] = hashlib.sha256(canonical_bytes(allocation["intent"])).hexdigest()
        f["entries"]["allocate"] = signed_entry(allocation, f["signers"]["owner"], "second_allocate")
        f["docs"]["allocate"] = json.loads(f["entries"]["allocate"]["raw"])
        self.source.now[0] = 2_000_000_001
        reference = ack_fixture.reference
        with mock.patch.object(ack_fixture, "reference", side_effect=lambda raw, name: reference(raw, "second_" + name)):
            self.source.activate()
        self.source.finalize()
        self.assertNotEqual(first_resource, self.source.resource_id)
        second = self.gate(self.statuses(4))
        self.assertTrue(second.allowed)
        child = self.access.prepare(self.source.resource_id, action="child", expected_generation=second.generation)
        revoked = self.access.prepare(first_resource, action="proof", current_statuses=first_revocation)
        with self.source.state._transaction():
            self.assertEqual(self.access.check_locked(revoked).code, "repair_authority_revoked")
        with self.source.state._transaction():
            self.assertEqual(self.access.check_locked(child).code, "repair_authority_revoked")
        self.assertEqual(self.gate(self.statuses(6)).code, "repair_authority_revoked")
        self.source.db.execute("DELETE FROM open_repair_access_floors WHERE resource_id=? AND scope_kind='ack_slot'", (first_resource,))
        self.source.db.commit()
        prepared = self.access.prepare(self.source.resource_id, action="child")
        with self.source.state._transaction(), self.assertRaisesRegex(wire.RepairWireError, "repair_access_ledger_missing"):
            self.access.check_locked(prepared)


if __name__ == "__main__":
    unittest.main()
