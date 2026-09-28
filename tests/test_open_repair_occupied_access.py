"""Current owner READ over an actual three-generation occupied ACK resource."""
import hashlib
import json
import sqlite3
import unittest
from unittest.mock import patch

from memory_vault import canonical_bytes
import memory_vault_open_repair_occupied as occupied
from memory_vault_open_repair_occupied_access import RepairAckOccupiedAccess, FIXED_PROOF_ROLES
from memory_vault_open_repair_occupied_state import RepairAckOccupiedState
import memory_vault_open_repair_wire as wire
from tests.open_repair_ack_fixtures import signed_entry
from tests import test_open_repair_occupied as occupied_fixture
from tests.test_open_repair_occupied import receipt_inputs


class OpenRepairOccupiedAccessTests(unittest.TestCase):
    def setUp(self):
        self.case=occupied_fixture.OpenRepairOccupiedTests()
        self.case.setUp()
        self.h=self.case.h
        self.case.receipt,self.case.disclosure,self.case.put_entry,self.case.options=receipt_inputs(self.case.case)
        self.result=self.case.put()
        self.gate=RepairAckOccupiedAccess(self.h.state)
        self.gate.initialize()

    def tearDown(self):
        self.case.tearDown()

    def prepare(self, **options):
        return self.gate.prepare(self.h.resource_id,action="proof",**options)

    def read(self, **options):
        prepared=self.prepare(**options)
        with self.h.state._transaction():
            decision=self.gate.check_locked(prepared)
            if not decision.allowed:
                return decision,()
            return self.gate.proof_inputs(prepared)

    def assertCode(self,code,callback,*args,**options):
        with self.assertRaises(wire.RepairWireError) as caught:
            callback(*args,**options)
        self.assertEqual(caught.exception.code,code)

    def test_full_three_generation_originals_and_receipt_object_child_after_restart(self):
        decision,children=self.read()
        self.assertTrue(decision.allowed,decision.code)
        self.assertEqual(len(children),25)
        self.assertEqual({item["role"] for item in children if item["role"]!="history.raw_pack"},FIXED_PROOF_ROLES)
        receipt=next(item for item in children if item["role"]=="recipient.receipt")
        self.assertEqual(receipt["raw"],self.case.receipt["raw"])
        self.assertEqual(receipt["ref"].as_dict(),self.case.receipt["ref"])
        self.assertEqual(receipt["ref"].namespace,"object")
        self.assertEqual(decision.subject,self.h.fixture["expected"]["expected_ack_slot"]["root_key"]["owner"])
        self.h.db.close();self.h.connect()
        RepairAckOccupiedState(self.h.state).initialize()
        self.gate=RepairAckOccupiedAccess(self.h.state);self.gate.initialize()
        other,again=self.read()
        self.assertTrue(other.allowed,other.code)
        self.assertEqual(again,children)

    def test_single_full_verification_crypto_outside_writer_and_actual_budget(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        key_type=type(Ed25519PublicKey.from_public_bytes(b"a"*32));verify=key_type.verify;calls=[]
        def check(key,signature,data):
            self.assertFalse(self.h.db.in_transaction);calls.append(1)
            return verify(key,signature,data)
        policy=self.h.state.policy;budget=wire.RepairBudget(policy)
        with patch.object(key_type,"verify",new=check):
            prepared=self.prepare(policy=policy,budget=budget)
            before=budget.snapshot()
            with self.h.state._transaction():
                self.assertTrue(self.gate.check_locked(prepared).allowed)
                self.assertTrue(self.gate.proof_inputs(prepared)[0].allowed)
            self.assertEqual(before,budget.snapshot())
        self.assertEqual(budget.snapshot()["signature_checks"],len(calls))
        self.assertEqual(len(calls),33)

    def test_read_revocation_of_exact_b_consent_persists_across_restart(self):
        payload=json.loads(self.case.options["current_statuses"][-1]["raw"])["payload"]
        payload["revision"]=2;payload["entries"][0].update(status="revoked",operation_mask=2)
        revoked=signed_entry(payload,self.h.fixture["signers"]["writer"],"read-revoke-B")
        decision,children=self.read(current_statuses=[*self.case.options["current_statuses"][:2],revoked])
        self.assertFalse(decision.allowed);self.assertEqual(decision.code,"repair_authority_revoked");self.assertEqual(children,())
        self.h.db.close();self.h.connect()
        self.gate=RepairAckOccupiedAccess(self.h.state);self.gate.initialize()
        decision,children=self.read(current_statuses=self.case.options["current_statuses"])
        self.assertEqual(decision.code,"repair_authority_revoked");self.assertEqual(children,())

    def test_writer_admit_revocation_does_not_revoke_owner_read(self):
        payload=json.loads(self.case.options["current_statuses"][0]["raw"])["payload"]
        scope=dict(kind="authority",root_key=self.h.fixture["expected"]["expected_ack_slot"]["root_key"],
            authority_kind="ack.write_grant",authority_sha256=self.case.case.write["ref"]["raw_sha256"])
        digest=hashlib.sha256(canonical_bytes(scope)).hexdigest()
        payload["revision"]=3
        for item in payload["entries"]:
            if item["scope_id"]==digest:item.update(status="revoked",operation_mask=1)
        revoked=signed_entry(payload,self.h.fixture["signers"]["owner"],"write-revoke-still-read")
        decision,children=self.read(current_statuses=[revoked,*self.case.options["current_statuses"][1:]])
        self.assertTrue(decision.allowed,decision.code);self.assertEqual(len(children),25)
        self.assertTrue(self.read()[0].allowed)

    def test_prepared_receipt_cannot_escape_after_last_gate_read_revocation(self):
        prepared=self.prepare()
        with self.h.state._transaction():self.assertTrue(self.gate.check_locked(prepared).allowed)
        payload=json.loads(self.case.options["current_statuses"][-1]["raw"])["payload"]
        payload["revision"]=2;payload["entries"][0].update(status="revoked",operation_mask=2)
        revoked=signed_entry(payload,self.h.fixture["signers"]["writer"],"late-B-read-revoke")
        self.assertFalse(self.read(current_statuses=[*self.case.options["current_statuses"][:2],revoked])[0].allowed)
        with self.h.state._transaction():
            decision,children=self.gate.proof_inputs(prepared)
            self.assertEqual(decision.code,"repair_authority_revoked");self.assertEqual(children,())

    def test_every_generation_standalone_original_is_rechecked_not_hidden_by_packs(self):
        for role in ("ack.root_authority","empty:ack.write_grant","occupied:recipient.receipt"):
            row=self.h.db.execute("""SELECT o.namespace,o.opaque_key,o.raw FROM open_repair_ack_objects o
                JOIN open_repair_ack_pins p ON p.namespace=o.namespace AND p.opaque_key=o.opaque_key WHERE p.role=?""",(role,)).fetchone()
            self.h.db.execute("UPDATE open_repair_ack_objects SET raw=? WHERE namespace=? AND opaque_key=?",(b"corrupt",row[0],row[1]));self.h.db.commit()
            with self.subTest(role=role):self.assertCode("repair_storage_corrupt",self.prepare)
            self.h.db.execute("UPDATE open_repair_ack_objects SET raw=? WHERE namespace=? AND opaque_key=?",(row[2],row[0],row[1]));self.h.db.commit()

    def test_exact_commit_job_reservation_and_writer_ledger_rechecked_before_reply(self):
        for sql,code in (("UPDATE open_repair_ack_commits SET live_bytes=live_bytes+1","repair_access_generation"),
                         ("UPDATE open_repair_ack_jobs SET raw=X'7B7D'","repair_access_generation"),
                         ("UPDATE open_capacity_reservations SET charge_bytes=charge_bytes-1 WHERE service='ack'","repair_access_generation"),
                         ("UPDATE open_repair_ack_bindings SET writer_keys=X'7B7D'","repair_access_generation")):
            prepared=self.prepare()
            with self.h.state._transaction():
                self.assertTrue(self.gate.check_locked(prepared).allowed)
            self.h.db.execute("SAVEPOINT corrupt")
            self.h.db.execute(sql)
            with self.subTest(sql=sql):self.assertCode(code,self.gate.check_locked,prepared)
            self.h.db.execute("ROLLBACK TO corrupt");self.h.db.execute("RELEASE corrupt")

    def test_whole_b_status_unrelated_scope_is_refused_without_receipt(self):
        payload=json.loads(self.case.options["current_statuses"][-1]["raw"])["payload"]
        payload["revision"]=2;payload["entries"].append(payload["entries"][0]|{"scope_id":"ff"*32})
        payload["entries"].sort(key=lambda item:(item["scope_kind"],item["scope_id"]))
        bad=signed_entry(payload,self.h.fixture["signers"]["writer"],"extra-B-scope")
        decision,children=self.read(current_statuses=[*self.case.options["current_statuses"][:2],bad])
        self.assertFalse(decision.allowed);self.assertEqual(children,())

    def test_saved_old_two_role_disclosure_never_becomes_full_proof_permission(self):
        other=occupied_fixture.OpenRepairOccupiedTests();other.setUp()
        try:
            # Explicitly sign the old two-role variant, which remains valid
            # for put but not full bootstrap. Never edit its signed bytes.
            other.receipt,other.disclosure,other.put_entry,other.options=receipt_inputs(other.case,bootstrap_roles=occupied.RETURN_ROLES_LEGACY)
            other.put()
            gate=RepairAckOccupiedAccess(other.h.state);gate.initialize()
            payload=json.loads(other.options["current_statuses"][-1]["raw"])["payload"]
            payload["revision"]=2
            fresh=signed_entry(payload,other.h.fixture["signers"]["writer"],"legacy-current")
            prepared=gate.prepare(other.h.resource_id,action="proof",current_statuses=[*other.options["current_statuses"][:2],fresh])
            with other.h.state._transaction():
                decision=gate.check_locked(prepared)
                self.assertEqual(decision.code,"repair_disclosure_bootstrap_unsupported")
            self.assertEqual(other.h.db.execute("SELECT max(revision) FROM open_repair_access_documents WHERE issuer=?",
                (other.h.fixture["signers"]["writer"].key_id,)).fetchone()[0],2)
        finally:other.tearDown()


if __name__=="__main__":unittest.main()
