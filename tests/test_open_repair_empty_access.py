"""Owner READ after durable binding, independent of receipt-writer ADMIT."""
from dataclasses import replace
import hashlib
import json
import sqlite3
import threading
import unittest
from unittest.mock import patch

from memory_vault import canonical_bytes
import memory_vault_open_repair_access as unbound_access
import memory_vault_open_repair_empty as empty
from memory_vault_open_repair_empty_access import FIXED_PROOF_ROLES, PROFILE, RepairAckEmptyAccess
from memory_vault_open_repair_empty_state import RepairAckEmptyState
import memory_vault_open_repair_wire as wire
from memory_vault_open_repair_state import RepairAckState
from tests.open_repair_ack_fixtures import signed_entry
from tests import test_open_repair_empty as fixture


class OpenRepairEmptyAccessTests(unittest.TestCase):
    def setUp(self):
        self.case = fixture.OpenRepairEmptyTests()
        self.case.setUp()
        self.addCleanup(self.case.tearDown)
        self.result = self.case.bind()
        self.state = self.case.h.state
        self.gate = RepairAckEmptyAccess(self.state)
        self.gate.initialize()

    def prepare(self, **changes):
        return self.gate.prepare(self.case.h.resource_id, **(dict(action="proof") | changes))

    def decision(self, prepared):
        with self.state._transaction():
            return self.gate.check_locked(prepared)

    def changed_status(self, *, revoked_roles=(), revoked_mask=1, revision=3, whole_mask=None):
        payload = json.loads(self.case.expected["current_statuses"][0]["raw"])["payload"]
        payload["revision"] = revision
        held = self.gate._get(self.prepare())
        # The seven scopes come from actual checked historical originals, not
        # from a test-supplied summary or an asserted current permission.
        manifest = json.loads(self.result["manifest"]["raw"])
        role_entries = {row["role"]:row["document_ref"] for row in manifest["roles"]}
        scope_ids = {}
        for name in ("ack.write_grant", "bootstrap.ack_offer"):
            entry = role_entries[name]
            kind = "ack.write_grant" if name == "ack.write_grant" else "bootstrap.grant"
            scope_ids[name] = hashlib.sha256(canonical_bytes(dict(kind="authority",
                root_key=self.case.h.fixture["expected"]["expected_ack_slot"]["root_key"],
                authority_kind=kind, authority_sha256=entry["raw_sha256"]))).hexdigest()
        for item in held["obligations"]:
            scope_ids[item["role"]] = item["scope_id"]
        for observation in payload["entries"]:
            if whole_mask is not None:
                observation["operation_mask"] = whole_mask
            if observation["scope_id"] in {scope_ids[name] for name in revoked_roles}:
                observation.update(status="revoked", operation_mask=revoked_mask)
        return signed_entry(payload, self.case.h.fixture["signers"]["owner"], "current-empty-owner-" + str(revision))

    def test_owner_source_complete_22_children_and_current_gate_without_writer_permission(self):
        prepared = self.prepare()
        before = self.state.db.execute("SELECT metadata_bytes FROM open_repair_ack_resources").fetchone()[0]
        with self.state._transaction():
            self.assertTrue(self.gate.check_locked(prepared).allowed)
            decision, children = self.gate.proof_inputs(prepared)
        self.assertTrue(decision.allowed)
        self.assertEqual(PROFILE, "ack_owner_service_v1")
        self.assertEqual(len(children), 22)
        self.assertEqual({item["role"] for item in children if item["role"] != "history.raw_pack"}, FIXED_PROOF_ROLES)
        self.assertEqual(len([item for item in children if item["role"] == "history.raw_pack"]), 2)
        self.assertEqual(decision.subject, self.case.h.fixture["expected"]["expected_ack_slot"]["root_key"]["owner"])
        self.assertEqual(decision.bootstrap_grant_ref.as_dict(), self.case.h.fixture["entries"]["bootstrap"]["ref"])
        self.assertEqual(self.state.db.execute("SELECT metadata_bytes FROM open_repair_ack_resources").fetchone()[0], before)
        with self.assertRaises(TypeError):
            children[0]["raw"] = b"forged"

    def test_writer_write_and_offer_revocation_does_not_revoke_owner_read(self):
        revoked = self.changed_status(revoked_roles=("ack.write_grant", "bootstrap.ack_offer"), revoked_mask=11)
        decision = self.decision(self.prepare(current_statuses=[revoked, self.case.expected["current_statuses"][1]]))
        self.assertTrue(decision.allowed, decision.code)
        self.assertTrue(self.decision(self.prepare()).allowed)
        self.assertGreater(self.state.db.execute("SELECT count(*) FROM open_repair_access_floors WHERE revoked_mask!=0").fetchone()[0], 0)

    def test_latest_owner_only_status_does_not_require_refreshing_writer_scopes(self):
        payload = json.loads(self.changed_status()["raw"])["payload"]
        required = {(item["scope_kind"], item["scope_id"]) for item in self.gate._get(self.prepare())["obligations"]}
        payload["entries"] = [item for item in payload["entries"] if (item["scope_kind"], item["scope_id"]) in required]
        self.assertEqual(len(payload["entries"]), 4)
        current = signed_entry(payload, self.case.h.fixture["signers"]["owner"], "owner-only-current-status")
        self.assertTrue(self.decision(self.prepare(current_statuses=[current, self.case.expected["current_statuses"][1]])).allowed)
        # The older whole document is still the saved writer-scope floor, but
        # its outdated owner entries must not be selected as a READ refresh.
        self.assertTrue(self.decision(self.prepare()).allowed)

    def test_owner_read_revocation_persists_across_restart_and_old_active_replay(self):
        revoked = self.changed_status(revoked_roles=("current.status.ack_read",), revoked_mask=2)
        decision = self.decision(self.prepare(current_statuses=[revoked, self.case.expected["current_statuses"][1]]))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "repair_authority_revoked")

    def test_revocation_after_successful_prepare_yields_no_proof_children(self):
        prepared = self.prepare()
        self.assertTrue(self.decision(prepared).allowed)
        revoked = self.changed_status(revoked_roles=("current.status.ack_read",), revoked_mask=2)
        refusal = self.decision(self.prepare(current_statuses=[revoked, self.case.expected["current_statuses"][1]]))
        self.assertFalse(refusal.allowed)
        with self.state._transaction():
            decision, children = self.gate.proof_inputs(prepared)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "repair_authority_revoked")
        self.assertEqual(children, ())
        self.case.h.db.close()
        self.case.h.connect()
        self.state = self.case.h.state
        self.gate = RepairAckEmptyAccess(self.state)
        self.gate.initialize()
        decision = self.decision(self.prepare(current_statuses=self.case.expected["current_statuses"]))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "repair_authority_revoked")

    def test_discover_required_only_for_challenge_read_scope_never_adds_admit(self):
        narrow = self.changed_status(whole_mask=2)
        statuses = [narrow, self.case.expected["current_statuses"][1]]
        self.assertTrue(self.decision(self.prepare(current_statuses=statuses)).allowed)
        self.assertTrue(self.decision(self.prepare(action="child", current_statuses=statuses)).allowed)
        decision = self.decision(self.prepare(action="challenge", current_statuses=statuses))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "repair_status_operation")
        self.assertEqual({item["mask"] for item in self.gate._get(self.prepare())["obligations"]}, {2})

    def test_whole_status_unrelated_scope_is_never_returned(self):
        payload = json.loads(self.changed_status()["raw"])["payload"]
        payload["entries"].append(dict(scope_kind="authority", scope_id="00" * 32,
            minimum_document_revision=0, status="active", operation_mask=127))
        payload["entries"].sort(key=lambda item:(item["scope_kind"], item["scope_id"]))
        unrelated = signed_entry(payload, self.case.h.fixture["signers"]["owner"], "unrelated-status")
        decision = self.decision(self.prepare(current_statuses=[unrelated, self.case.expected["current_statuses"][1]]))
        self.assertFalse(decision.allowed)
        self.assertEqual(self.state.db.execute("SELECT count(*) FROM open_repair_access_documents WHERE revision=3").fetchone()[0], 0)

    def test_shared_budget_and_all_crypto_outside_writer_last_check_has_no_new_work(self):
        local = replace(self.state.policy, max_signature_checks=30)
        budget = wire.RepairBudget(local)
        hash_impl = wire.RepairBudget._hash
        def checked_hash(meter, raw):
            self.assertFalse(self.state.db.in_transaction)
            return hash_impl(meter, raw)
        with patch.object(wire.RepairBudget, "_hash", new=checked_hash):
            prepared = self.prepare(policy=local, budget=budget)
            before = budget.snapshot()
            decision = self.decision(prepared)
            with self.state._transaction():
                result, children = self.gate.proof_inputs(prepared)
        self.assertTrue(decision.allowed)
        self.assertTrue(result.allowed)
        self.assertEqual(before, budget.snapshot())
        self.assertEqual(before["signature_checks"], 23)
        self.assertEqual(len(children), 22)
        with self.assertRaises(wire.RepairWireError):
            self.prepare(policy=local, budget=budget)
        self.assertEqual(budget.snapshot()["signature_checks"], 30)

    def test_binding_or_pins_changed_between_prepare_and_release_refuses(self):
        prepared = self.prepare()
        self.state.db.execute("UPDATE open_repair_ack_bindings SET generation=generation+1")
        self.state.db.commit()
        with self.assertRaises(wire.RepairWireError) as caught:
            self.decision(prepared)
        self.assertEqual(caught.exception.code, "repair_access_generation")
        with self.assertRaises(wire.RepairWireError):
            self.prepare()

    def test_another_connection_changes_writer_keys_after_prepare_no_children_escape(self):
        prepared = self.prepare()
        self.assertTrue(self.decision(prepared).allowed)
        failures = []
        def change():
            try:
                db = sqlite3.connect(self.case.h.path)
                db.execute("UPDATE open_repair_ack_bindings SET writer_keys=?", (canonical_bytes(self.state.target),))
                db.commit()
                db.close()
            except Exception as error:
                failures.append(error)
        worker = threading.Thread(target=change)
        worker.start(); worker.join(timeout=10)
        self.assertFalse(worker.is_alive())
        self.assertEqual(failures, [])
        with self.assertRaises(wire.RepairWireError) as caught:
            with self.state._transaction():
                self.gate.proof_inputs(prepared)
        self.assertEqual(caught.exception.code, "repair_access_generation")

    def test_two_connections_binding_same_slot_commit_once_then_exact_retry(self):
        other = fixture.OpenRepairEmptyTests()
        other.setUp()
        self.addCleanup(other.tearDown)
        barrier = threading.Barrier(2)
        original_build = RepairAckEmptyState._build
        results, failures, raced = [], [], []
        def together(binding_state, held, budget):
            result = original_build(binding_state, held, budget)
            barrier.wait(timeout=10)
            return result
        def bind():
            db = None
            try:
                db = sqlite3.connect(other.h.path, timeout=15)
                state = RepairAckState(db, other.h.state.identity, other.h.state.node,
                    encryption_identity=other.h.state.encryption_identity,
                    limit_policy=other.h.state.limits, clock=lambda:other.h.now[0])
                state.initialize()
                engine = RepairAckEmptyState(state)
                engine.initialize()
                try:
                    value = engine.bind(other.h.resource_id, other.write, other.offer, **other.expected)
                except wire.RepairWireError as error:
                    raced.append(error.code)
                    if error.code != "repair_access_generation":
                        raise
                    value = engine.bind(other.h.resource_id, other.write, other.offer, **other.expected)
                results.append(value)
            except Exception as error:
                failures.append(error)
            finally:
                if db is not None:
                    db.close()
        with patch.object(RepairAckEmptyState, "_build", new=together):
            workers = [threading.Thread(target=bind) for _ in range(2)]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join(timeout=20)
        self.assertFalse(any(worker.is_alive() for worker in workers))
        self.assertEqual(failures, [])
        self.assertEqual(raced, ["repair_access_generation"])
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0], results[1])
        self.assertEqual(other.h.db.execute("SELECT count(*) FROM open_repair_ack_bindings").fetchone()[0], 1)
        self.assertEqual(other.h.db.execute("SELECT count(*) FROM open_capacity_reservations WHERE service='ack'").fetchone()[0], 1)

    def test_persisted_full_writer_keys_exact_retry_restart_and_bad_descriptor_refusal(self):
        row = self.state.db.execute("SELECT writer_keys FROM open_repair_ack_bindings").fetchone()
        self.assertEqual(bytes(row[0]), canonical_bytes(self.case.expected["expected_receipt_writer"]))
        self.assertEqual(self.case.bind(), self.result)
        wrong = dict(self.case.expected["expected_receipt_writer"])
        wrong["encryption_key"] = self.state.encryption_identity.public_descriptor()
        self.state.db.execute("UPDATE open_repair_ack_bindings SET writer_keys=?", (canonical_bytes(wrong),))
        self.state.db.commit()
        self.case.h.db.close()
        self.case.h.connect()
        self.state = self.case.h.state
        self.gate = RepairAckEmptyAccess(self.state)
        self.gate.initialize()
        with self.assertRaises(wire.RepairWireError):
            self.prepare()
        self.case.empty = RepairAckEmptyState(self.state)
        with self.assertRaises(wire.RepairWireError) as caught:
            self.case.bind()
        self.assertEqual(caught.exception.code, "repair_binding_writer_mismatch")

    def test_missing_writer_keys_old_schema_is_not_fabricated_on_initialize(self):
        # Simulate the earlier development schema exactly. Existing original
        # refs remain, but missing full descriptors cannot be reconstructed.
        self.state.db.execute("ALTER TABLE open_repair_ack_bindings DROP COLUMN writer_keys")
        self.state.db.commit()
        RepairAckEmptyState(self.state).initialize()
        self.assertIsNone(self.state.db.execute("SELECT writer_keys FROM open_repair_ack_bindings").fetchone()[0])
        with self.assertRaises(wire.RepairWireError) as caught:
            self.prepare()
        self.assertEqual(caught.exception.code, "repair_binding_ledger_missing")

    def test_binding_advances_previous_unbound_service_generation(self):
        other = fixture.OpenRepairEmptyTests()
        other.setUp()
        self.addCleanup(other.tearDown)
        gate = unbound_access.RepairAckAccess(other.h.state)
        gate.initialize()
        prepared = gate.prepare(other.h.resource_id, action="proof")
        with other.h.state._transaction():
            before = gate.check_locked(prepared).generation
        other.bind()
        after = other.h.db.execute("SELECT generation FROM open_repair_access_state").fetchone()[0]
        self.assertGreater(after, before)
        with self.assertRaises(wire.RepairWireError):
            gate.prepare(other.h.resource_id, action="child", expected_generation=before)


if __name__ == "__main__":
    unittest.main()
