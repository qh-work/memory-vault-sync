"""Real synthetic delivery receipts committed to an existing local ACK slot."""
import copy
import hashlib
import json
import sqlite3
import unittest
from unittest.mock import patch

from memory_vault import canonical_bytes
import memory_vault_open_delivery as delivery
import memory_vault_open_repair_empty_access as empty_access
import memory_vault_open_repair_occupied as occupied
from memory_vault_open_repair_occupied_state import RepairAckOccupiedState
import memory_vault_open_repair_wire as wire
from tests.open_repair_ack_fixtures import reference, signed_entry
from tests import test_open_repair_empty as empty_tests


def receipt_inputs(case, *, saved_at=2_000_000_008, revision=1, bootstrap_roles=None):
    f, expected = case.h.fixture, case.expected
    writer = f["signers"]["writer"]
    slot = f["expected"]["expected_ack_slot"]
    doc = delivery.issue_recipient_receipt(writer, message_id=expected["expected_message_id"],
        envelope_ref=expected["expected_envelope_ref"], sender_key_id=f["signers"]["owner"].key_id, saved_at=saved_at)
    raw = canonical_bytes(doc)
    receipt = dict(raw=raw, ref=reference(raw, "receipt-" + str(saved_at)) | {"namespace":"object"})
    disclosure_payload = dict(schema_version="memory-vault-open-repair/v1", kind="ack.disclosure", signing_key=writer.public_descriptor(),
        issued_at=saved_at, expires_at=2_000_000_700, consent_id="synthetic_consent_" + str(saved_at),
        ack_slot=slot, root_authority_ref=f["entries"]["root"]["ref"], grant_ref=case.write["ref"], receipt_ref=receipt["ref"],
        recipient=slot["receipt_writer"], owner=slot["root_key"]["owner"], allowed_roles=sorted(occupied.B_ROLES),
        operation_mask=67, consent_until=2_000_000_650, bootstrap_return=dict(subject=slot["root_key"]["owner"],
        consumer="ack_owner", roles=list(occupied.RETURN_ROLES_FULL if bootstrap_roles is None else bootstrap_roles), until=2_000_000_600), revision=1)
    disclosure = signed_entry(disclosure_payload, writer, "disclosure-" + str(saved_at))
    put = signed_entry(dict(schema_version="memory-vault-open-repair/v1", kind="ack.put", signing_key=writer.public_descriptor(),
        issued_at=saved_at, expires_at=2_000_000_650, put_id="synthetic_put_" + str(saved_at), ack_slot=slot,
        grant_ref=case.write["ref"], binding_ref=case.bound["binding"]["ref"], receipt_ref=receipt["ref"],
        disclosure_ref=disclosure["ref"], operation="receipt.put"), writer, "put-" + str(saved_at))
    scope = dict(kind="authority", root_key=slot["root_key"], authority_kind="ack.disclosure", authority_sha256=disclosure["ref"]["raw_sha256"])
    payload = copy.deepcopy(f["docs"]["owner_status"]["payload"])
    payload.update(signing_key=writer.public_descriptor(), revision=revision, issued_at=saved_at,
        scope_key=dict(root_key=slot["root_key"], issuer_key_id=writer.key_id), entries=[dict(scope_kind="authority",
            scope_id=hashlib.sha256(canonical_bytes(scope)).hexdigest(), minimum_document_revision=0, status="active", operation_mask=67)])
    writer_status = signed_entry(payload, writer, "disclosure-status-" + str(saved_at) + "-" + str(revision))
    return receipt, disclosure, put, dict(current_statuses=[*expected["current_statuses"], writer_status],
        read_until=2_000_000_550, retain_until=2_000_000_650)


class OpenRepairOccupiedTests(unittest.TestCase):
    def setUp(self):
        self.case = empty_tests.OpenRepairEmptyTests()
        self.case.setUp()
        self.h = self.case.h
        self.case.bound = self.case.bind()
        self.h.now[0] = 2_000_000_008
        self.engine = RepairAckOccupiedState(self.h.state)
        self.engine.initialize()
        self.receipt, self.disclosure, self.put_entry, self.options = receipt_inputs(self.case)

    def tearDown(self):
        self.case.tearDown()

    def put(self, **changes):
        return self.engine.put(self.h.resource_id, self.receipt, self.disclosure, self.put_entry, **(self.options | changes))

    def assertCode(self, code, callback, *args, **kwargs):
        with self.assertRaises(wire.RepairWireError) as caught:
            callback(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def verify(self, result):
        policy = self.h.state.policy
        budget = wire.RepairBudget(policy)
        resolver = wire.LocalRawResolver(policy, budget)
        for namespace,key,raw in self.h.db.execute("""SELECT o.namespace,o.opaque_key,o.raw FROM open_repair_ack_objects o
            JOIN open_repair_ack_pins p ON p.namespace=o.namespace AND p.opaque_key=o.opaque_key
            WHERE p.resource_id=? AND p.role IN ('pack','empty:pack','occupied:pack')""", (self.h.resource_id,)):
            resolver.put(namespace,key,bytes(raw))
        checked = occupied.verify_ack_occupied_source_event(result["manifest"], resolver, result["commit"],
            **self.h.fixture["expected"], **{name:self.case.expected[name] for name in
                ("expected_receipt_writer", "expected_message_id", "expected_envelope_ref")}, policy=policy, budget=budget)
        occupied.verify_ack_occupied_head(result["head"], checked, expected_target=self.h.state.target, policy=policy, budget=budget)
        return checked

    def test_original_delivery_receipt_commit_full_closure_and_restart_exact_retry(self):
        with patch.object(delivery, "verify_recipient_receipt", wraps=delivery.verify_recipient_receipt) as legacy:
            result = self.put()
            self.assertEqual(legacy.call_count, 2)
        checked = self.verify(result)
        self.assertEqual(checked.inputs["receipt"].raw, self.receipt["raw"])
        self.assertEqual(checked.inputs["receipt"].ref.as_dict(), self.receipt["ref"])
        self.assertEqual(len(checked.manifest.roles), 13)
        self.assertEqual(checked.predecessor.custody.raw, self.case.bound["custody"]["raw"])
        self.assertEqual(self.h.db.execute("SELECT status FROM open_repair_ack_resources").fetchone()[0], "occupied")
        self.assertEqual(self.h.db.execute("SELECT kind,state FROM open_repair_ack_jobs").fetchone(), ("ack.head.publish", "pending"))
        self.assertEqual(self.h.db.execute("SELECT live_bytes FROM open_repair_ack_commits").fetchone()[0], len(self.receipt["raw"]))
        before = self.h.db.execute("SELECT metadata_bytes FROM open_repair_ack_resources").fetchone()[0]
        self.assertEqual(self.put(), result)
        self.assertEqual(self.h.db.execute("SELECT metadata_bytes FROM open_repair_ack_resources").fetchone()[0], before)
        self.h.db.close()
        self.h.connect()
        self.engine = RepairAckOccupiedState(self.h.state)
        self.engine.initialize()
        self.assertEqual(self.put(), result)
        with self.assertRaises(TypeError):
            checked.inputs["receipt"].payload["saved_at"] = 0

    def test_failed_commit_exposes_no_partial_objects_job_or_usage(self):
        self.h.db.execute("CREATE TRIGGER synthetic_put_fail BEFORE INSERT ON open_repair_ack_jobs BEGIN SELECT RAISE(ABORT,'synthetic_failure'); END")
        self.h.db.commit()
        with self.assertRaises(sqlite3.IntegrityError):
            self.put()
        self.assertEqual(self.h.db.execute("SELECT status FROM open_repair_ack_resources").fetchone()[0], "empty")
        for table in ("open_repair_ack_commits", "open_repair_ack_jobs"):
            self.assertEqual(self.h.db.execute("SELECT count(*) FROM " + table).fetchone()[0], 0)
        self.assertEqual(self.h.db.execute("SELECT count(*) FROM open_repair_ack_pins WHERE role LIKE 'occupied:%'").fetchone()[0], 0)
        self.assertEqual(self.h.db.execute("SELECT max(revision) FROM open_repair_access_documents WHERE issuer=?",
            (self.h.fixture["signers"]["writer"].key_id,)).fetchone()[0], 1)

    def test_crypto_outside_writer_and_exact_signature_meter(self):
        policy, calls = self.h.state.policy, []
        budget = wire.RepairBudget(policy)
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        key_type = type(Ed25519PublicKey.from_public_bytes(b"a" * 32))
        real = key_type.verify
        def verification(key, signature, data):
            self.assertFalse(self.h.db.in_transaction)
            calls.append(1)
            return real(key, signature, data)
        hashing = wire.RepairBudget._hash
        def hash_outside(meter, raw):
            self.assertFalse(self.h.db.in_transaction)
            return hashing(meter, raw)
        with patch.object(key_type, "verify", new=verification), patch.object(wire.RepairBudget, "_hash", new=hash_outside):
            self.put(policy=policy, budget=budget)
        self.assertEqual(budget.snapshot()["signature_checks"], len(calls))
        self.assertLessEqual(len(calls), 64)

    def test_bad_receipt_binding_or_signer_cannot_poison_slot(self):
        original = self.receipt
        for change, signer in (({"message_id":"msg_" + "ee" * 32}, self.h.fixture["signers"]["writer"]),
                               ({}, self.h.fixture["signers"]["owner"]),
                               ({"status":"saved"}, self.h.fixture["signers"]["writer"]),
                               ({"saved_at":True}, self.h.fixture["signers"]["writer"])):
            payload = json.loads(original["raw"])["payload"]
            payload.update(change, signing_key=signer.public_descriptor())
            self.receipt = signed_entry(payload, signer, "bad-receipt")
            with self.subTest(change=change), self.assertRaises(wire.RepairWireError):
                self.put()
            self.assertEqual(self.h.db.execute("SELECT status FROM open_repair_ack_resources").fetchone()[0], "empty")
            self.assertEqual(self.h.db.execute("SELECT count(*) FROM open_repair_ack_receipt_conflicts").fetchone()[0], 0)
        self.receipt = original
        self.put()

    def test_b_status_revocation_persists_and_old_active_cannot_restore(self):
        payload = json.loads(self.options["current_statuses"][-1]["raw"])["payload"]
        payload["revision"] = 2
        payload["entries"][0].update(status="revoked", operation_mask=1)
        revoked = signed_entry(payload, self.h.fixture["signers"]["writer"], "B-revoked")
        self.assertCode("repair_authority_revoked", self.put, current_statuses=[*self.options["current_statuses"][:2], revoked])
        self.assertCode("repair_authority_revoked", self.put)
        self.assertEqual(self.h.db.execute("SELECT count(*) FROM open_repair_ack_commits").fetchone()[0], 0)

    def test_valid_different_receipt_retains_stable_tuple_conflict(self):
        result = self.put()
        self.h.now[0] += 1
        receipt, consent, put, options = receipt_inputs(self.case, saved_at=self.h.now[0], revision=2)
        self.assertCode("repair_receipt_conflict", self.engine.put, self.h.resource_id, receipt, consent, put, **options)
        self.assertEqual(self.h.db.execute("SELECT raw,retained FROM open_repair_ack_receipt_conflicts").fetchone(), (receipt["raw"], 1))
        self.assertEqual(self.h.db.execute("SELECT status FROM open_repair_ack_resources").fetchone()[0], "conflicted")
        self.assertEqual(self.verify(result).inputs["receipt"].raw, self.receipt["raw"])

    def test_missing_prior_original_or_pending_job_cannot_be_hidden_by_retry(self):
        self.put()
        ref = self.h.fixture["entries"]["root"]["ref"]
        self.h.db.execute("UPDATE open_repair_ack_objects SET raw=? WHERE namespace=? AND opaque_key=?", (b"corrupt-root", ref["namespace"], ref["key"]))
        self.h.db.commit()
        self.assertCode("repair_storage_corrupt", self.put)
        self.h.db.execute("UPDATE open_repair_ack_objects SET raw=? WHERE namespace=? AND opaque_key=?", (self.h.fixture["entries"]["root"]["raw"],ref["namespace"],ref["key"]))
        self.h.db.execute("DELETE FROM open_repair_ack_jobs")
        self.h.db.commit()
        self.assertCode("repair_receipt_ledger_missing", self.put)

    def test_final_live_guard_refusal_keeps_floors_but_returns_no_commit(self):
        calls = []
        def guard(decision):
            self.assertTrue(self.h.db.in_transaction)
            calls.append(decision.generation)
            return "repair_live_session_changed" if len(calls) == 2 else None
        self.assertCode("repair_live_session_changed", self.put, _transaction_guard=guard)
        self.assertEqual(len(calls), 2)
        self.assertEqual(self.h.db.execute("SELECT count(*) FROM open_repair_ack_commits").fetchone()[0], 0)
        self.assertGreater(self.h.db.execute("SELECT count(*) FROM open_repair_access_documents WHERE issuer=?",
            (self.h.fixture["signers"]["writer"].key_id,)).fetchone()[0], 0)

    def test_old_empty_owner_handle_is_invalid_after_occupied_commit(self):
        gate = empty_access.RepairAckEmptyAccess(self.h.state)
        prepared = gate.prepare(self.h.resource_id, action="proof")
        with self.h.state._transaction():
            before = gate.check_locked(prepared).generation
        self.put()
        self.assertGreater(self.h.db.execute("SELECT generation FROM open_repair_access_state").fetchone()[0], before)
        with self.h.state._transaction():
            self.assertCode("repair_resource_inactive", gate.check_locked, prepared)

    def test_disclosure_closed_return_and_independent_exact_put_refs(self):
        original_consent, original_put = self.disclosure, self.put_entry
        writer = self.h.fixture["signers"]["writer"]
        for change in ({"owner":self.h.fixture["expected"]["expected_ack_slot"]["receipt_writer"]},
                       {"bootstrap_return":{"subject":json.loads(original_consent["raw"])["payload"]["owner"],
                        "consumer":"ack_offer", "roles":["ack.disclosure", "authority.status.disclosure"], "until":2_000_000_600}},
                       {"allowed_roles":["ack.disclosure", "ack.put"]},
                       {"receipt_ref":self.receipt["ref"] | {"key":"00" * 32}},
                       {"operation_mask":66}):
            payload = json.loads(original_consent["raw"])["payload"] | change
            self.disclosure = signed_entry(payload, writer, "invalid-consent")
            with self.subTest(change=change), self.assertRaises(wire.RepairWireError):
                self.put()
        self.disclosure = original_consent
        for field in ("binding_ref", "disclosure_ref", "grant_ref", "receipt_ref"):
            payload = json.loads(original_put["raw"])["payload"]
            payload[field] = payload[field] | {"key":"00" * 32}
            self.put_entry = signed_entry(payload, writer, "invalid-put")
            with self.subTest(field=field), self.assertRaises(wire.RepairWireError):
                self.put()
        self.put_entry = original_put
        self.assertEqual(self.h.db.execute("SELECT count(*) FROM open_repair_ack_commits").fetchone()[0], 0)

    def test_whole_b_status_with_unrelated_scope_is_never_stripped(self):
        payload = json.loads(self.options["current_statuses"][-1]["raw"])["payload"]
        payload["entries"].append(payload["entries"][0] | {"scope_id":"ff" * 32})
        payload["entries"].sort(key=lambda item:(item["scope_kind"],item["scope_id"]))
        unrelated = signed_entry(payload, self.h.fixture["signers"]["writer"], "unrelated-B-scope")
        with self.assertRaises(wire.RepairWireError):
            self.put(current_statuses=[*self.options["current_statuses"][:2], unrelated])
        self.assertEqual(self.h.db.execute("SELECT count(*) FROM open_repair_access_documents WHERE issuer=?",
            (self.h.fixture["signers"]["writer"].key_id,)).fetchone()[0], 0)

    def test_current_owner_write_admit_is_independent_of_owner_read(self):
        payload = json.loads(self.options["current_statuses"][0]["raw"])["payload"]
        scope = dict(kind="authority", root_key=self.h.fixture["expected"]["expected_ack_slot"]["root_key"],
                     authority_kind="ack.write_grant", authority_sha256=self.case.write["ref"]["raw_sha256"])
        digest = hashlib.sha256(canonical_bytes(scope)).hexdigest()
        payload["revision"] = 3
        for item in payload["entries"]:
            if item["scope_id"] == digest:
                item.update(status="revoked", operation_mask=1)
        revoked = signed_entry(payload, self.h.fixture["signers"]["owner"], "revoke-write-only")
        self.assertCode("repair_authority_revoked", self.put, current_statuses=[revoked,*self.options["current_statuses"][1:]])
        gate = empty_access.RepairAckEmptyAccess(self.h.state)
        prepared = gate.prepare(self.h.resource_id, action="proof")
        with self.h.state._transaction():
            self.assertTrue(gate.check_locked(prepared).allowed)

    def test_mid_build_b_revoke_blocks_last_transaction(self):
        original_build = self.engine._build
        payload = json.loads(self.options["current_statuses"][-1]["raw"])["payload"]
        payload["revision"] = 2
        payload["entries"][0].update(status="revoked", operation_mask=1)
        revoked = signed_entry(payload, self.h.fixture["signers"]["writer"], "mid-build-B-revoke")
        def build(held, budget):
            result = original_build(held, budget)
            options = self.options | {"current_statuses":[*self.options["current_statuses"][:2],revoked]}
            other = self.engine.access.prepare_put(self.h.resource_id,self.receipt,self.disclosure,self.put_entry,
                **options,policy=self.h.state.policy,budget=wire.RepairBudget(self.h.state.policy))
            with self.h.state._transaction():
                self.assertEqual(self.engine.access.check_locked(other).code,"repair_authority_revoked")
            return result
        with patch.object(self.engine,"_build",side_effect=build):
            self.assertCode("repair_authority_revoked",self.put)
        self.assertEqual(self.h.db.execute("SELECT count(*) FROM open_repair_ack_commits").fetchone()[0],0)

    def test_capacity_denial_preserves_fresh_b_observation(self):
        self.h.db.execute("UPDATE open_repair_ack_resources SET metadata_bytes=507000")
        self.h.db.commit()
        self.assertCode("repair_insufficient_capacity",self.put)
        self.assertEqual(self.h.db.execute("SELECT max(revision) FROM open_repair_access_documents WHERE issuer=?",
            (self.h.fixture["signers"]["writer"].key_id,)).fetchone()[0],1)
        self.assertEqual(self.h.db.execute("SELECT count(*) FROM open_repair_ack_jobs").fetchone()[0],0)

    def test_transport_publish_failure_rolls_back_receipt_head_usage_job_and_replay(self):
        phases=[]
        self.h.db.execute("CREATE TABLE synthetic_replay(value TEXT)")
        self.h.db.commit()
        def hook(phase, held, result):
            phases.append(phase)
            self.assertEqual(self.h.db.in_transaction,phase!="result")
            if phase=="result":
                self.assertEqual(result.keys(),{"manifest","commit","head"})
            if phase=="publish":
                self.assertEqual(self.h.db.execute("SELECT status FROM open_repair_ack_resources").fetchone()[0],"occupied")
                self.h.db.execute("INSERT INTO synthetic_replay VALUES('response')")
                return "repair_response_capacity"
        self.assertCode("repair_response_capacity",self.put,_transaction_hook=hook)
        self.assertEqual(phases,["prepare","result","commit","publish"])
        self.assertEqual(self.h.db.execute("SELECT status FROM open_repair_ack_resources").fetchone()[0],"empty")
        for table in ("synthetic_replay","open_repair_ack_commits","open_repair_ack_jobs"):
            self.assertEqual(self.h.db.execute("SELECT count(*) FROM "+table).fetchone()[0],0)

    def test_same_receipt_different_signed_put_is_retry_mismatch_without_poison(self):
        result=self.put()
        payload=json.loads(self.put_entry["raw"])["payload"] | {"put_id":"another_valid_put"}
        self.put_entry=signed_entry(payload,self.h.fixture["signers"]["writer"],"changed-put")
        self.assertCode("repair_receipt_retry_mismatch",self.put)
        self.assertEqual(self.h.db.execute("SELECT status FROM open_repair_ack_resources").fetchone()[0],"occupied")
        self.assertEqual(self.h.db.execute("SELECT count(*) FROM open_repair_ack_receipt_conflicts").fetchone()[0],0)
        self.assertEqual(self.verify(result).inputs["receipt"].raw,self.receipt["raw"])

    def test_only_exact_old_two_and_explicit_new_four_return_variants_are_valid(self):
        for roles in (("ack.disclosure","ack.put","authority.status.disclosure"),
                      tuple(reversed(occupied.RETURN_ROLES_FULL)),
                      (*occupied.RETURN_ROLES_FULL,"recipient.receipt"),
                      (*occupied.RETURN_ROLES_LEGACY,"memory")):
            receipt,disclosure,put,options=receipt_inputs(self.case,bootstrap_roles=roles)
            with self.subTest(roles=roles),self.assertRaises(wire.RepairWireError):
                self.engine.put(self.h.resource_id,receipt,disclosure,put,**options)
        receipt,disclosure,put,options=receipt_inputs(self.case,bootstrap_roles=occupied.RETURN_ROLES_LEGACY)
        result=self.engine.put(self.h.resource_id,receipt,disclosure,put,**options)
        self.assertEqual(self.verify(result).inputs["disclosure"].payload["bootstrap_return"]["roles"],list(occupied.RETURN_ROLES_LEGACY))


if __name__ == "__main__":
    unittest.main()
