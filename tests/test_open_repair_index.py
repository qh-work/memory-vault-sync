import copy
import json
import unittest
from unittest.mock import patch

import memory_vault_open_repair_index as index
import memory_vault_open_repair_wire as wire
from tests.open_repair_ack_fixtures import signed_entry
from tests.open_repair_index_fixtures import IndexFixture


class AckIndexTests(unittest.TestCase):
    def setUp(self):
        self.f=IndexFixture()

    def tearDown(self):
        self.f.close()

    def mutate(self,entry,signer,changes):
        payload=json.loads(entry["raw"])["payload"]
        payload.update(changes)
        return signed_entry(payload,signer,"mutated-index-input")

    def test_new_exact_directory_consent_preserves_old_receipt_and_67_disclosure(self):
        old=self.f.case.disclosure["raw"]
        result,usage=self.f.verify(admission=True)
        self.assertIsNone(result.denial_code)
        self.assertEqual(result.plan.source.inputs["receipt"].raw,self.f.case.receipt["raw"])
        self.assertEqual(result.plan.source.inputs["disclosure"].raw,old)
        self.assertEqual(json.loads(old)["payload"]["operation_mask"],67)
        self.assertLessEqual(usage["signature_checks"],64)
        with self.assertRaises(TypeError):
            result.plan.intent["job_id"]="other"

    def test_raw_hash_tuple_target_and_minimal_descriptor_are_not_optional(self):
        for role,change in (("writer",{"operation_mask":2}),("writer",{"target_storage_epoch":"wrong"}),
                ("owner",{"reservation_disclosure":{"intent_sha256":"00"*32,"until":self.f.until}}),
                ("owner",{"receipt_ref":dict(self.f.case.receipt["ref"],key="ff"*32)})):
            previous=self.f.consents[role]
            self.f.consents[role]=self.mutate(previous,self.f.f["signers"][role],change)
            with self.subTest(change=change),self.assertRaises(wire.RepairWireError):
                self.f.verify()
            self.f.consents[role]=previous
        self.f.consents["writer"]={**self.f.consents["writer"],"raw":b"corrupt"}
        with self.assertRaises(wire.RepairWireError):
            self.f.verify()

    def test_missing_cross_signer_or_duplicate_original_disclosure_is_rejected(self):
        original=self.f.consents["writer"]
        for mutation in ("missing","foreign","duplicate"):
            payload=json.loads(original["raw"])["payload"]
            rows=payload["post_assignment_disclosure"]["originals"]
            if mutation=="missing": rows.pop()
            elif mutation=="duplicate": rows.append(rows[0])
            else: rows.append(json.loads(self.f.consents["owner"]["raw"])["payload"]["post_assignment_disclosure"]["originals"][0])
            self.f.consents["writer"]=signed_entry(payload,self.f.f["signers"]["writer"],"bad-permission")
            with self.subTest(mutation=mutation),self.assertRaises(wire.RepairWireError):
                self.f.verify()

    def test_current_revocation_returns_authenticated_denial_for_durable_floor(self):
        wanted=self.f.authority(self.f.consents["writer"],"ack.index_consent")
        position=next(i for i,item in enumerate(self.f.current) if any(e['scope_id']==wanted for e in json.loads(item['raw'])['payload']['entries']))
        old=self.f.current[position]
        payload=json.loads(old["raw"])["payload"]
        for entry in payload["entries"]:
            if entry["scope_id"]==wanted: entry.update(status="revoked",operation_mask=16)
        self.f.current[position]=signed_entry(payload,self.f.f["signers"]["writer"],"revoked")
        result,_=self.f.verify()
        self.assertEqual(result.denial_code,"repair_authority_revoked")
        self.assertIn(self.f.current[position]["raw"],[item.raw for item in result.statuses])

    def test_assignment_does_not_grant_owner_bootstrap_or_another_target(self):
        original=self.f.assignment
        for change in ({"operation_mask":18},{"bootstrap_grant_refs":[self.f.f["entries"]["bootstrap"]["ref"]]},
                {"target_storage_epoch":"wrong"},{"parent_assignment_ref":self.f.result["commit"]["ref"]}):
            self.f.assignment=self.mutate(original,self.f.f["signers"]["target"],change)
            with self.subTest(change=change),self.assertRaises(wire.RepairWireError):
                self.f.verify(admission=True)

    def test_retention_and_publish_are_distinct_current_obligations(self):
        original=self.f.current[1]
        payload=json.loads(original["raw"])["payload"]
        old_scope=self.f.authority(self.f.case.disclosure,"ack.disclosure")
        for entry in payload["entries"]:
            if entry["scope_id"]==old_scope: entry["operation_mask"]=2
        self.f.current[1]=signed_entry(payload,self.f.f["signers"]["writer"],"no-retain")
        result,_=self.f.verify()
        self.assertEqual(result.denial_code,"repair_status_operation")
        self.assertEqual(len(result.statuses),5)

    def test_directory_current_refusal_survives_full_source_verification(self):
        payload=json.loads(self.f.directory_statuses[1]["raw"])["payload"]
        payload["entries"][0]["status"]="revoked"
        self.f.directory_statuses[1]=signed_entry(payload,self.f.directory,"revoked-D")
        result,_=self.f.verify(admission=True)
        self.assertEqual(result.denial_code,"repair_authority_revoked")
        self.assertIn(self.f.directory_statuses[1]["raw"],[item.raw for item in result.statuses])

    def test_missing_predecessor_pack_and_wrong_source_own_disclosure_refuse(self):
        args,kwargs=self.f.inputs()
        args=list(args)
        args[1]=wire.LocalRawResolver(kwargs["policy"],kwargs["budget"])
        with self.assertRaises(wire.RepairWireError):
            index.verify_ack_index_plan(*args,**kwargs)
        payload=json.loads(self.f.request["raw"])["payload"]
        payload["source_disclosure"]["originals"].pop(0)
        self.f.request=signed_entry(payload,self.f.f["signers"]["target"],"missing-R-original")
        with self.assertRaises(wire.RepairWireError):
            self.f.verify(admission=True)

    def test_all_real_signature_work_uses_one_meter(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        key_type=type(Ed25519PublicKey.from_public_bytes(b"a"*32))
        real=key_type.verify
        calls=[]
        def verify(key,signature,data):
            calls.append(1)
            return real(key,signature,data)
        with patch.object(key_type,"verify",new=verify):
            result,usage=self.f.verify(admission=True)
        self.assertIsNone(result.denial_code)
        self.assertEqual(usage["signature_checks"],len(calls))

    def test_new_consents_cannot_add_an_old_root_maintainer_or_publish_bit(self):
        for settings in ({"source_maintainer":False},{"root_publish":False}):
            other=IndexFixture(**settings)
            try:
                with self.subTest(settings=settings),self.assertRaises(wire.RepairWireError):
                    other.verify()
            finally:
                other.close()

    def test_pre_stage_assignment_requires_no_future_request_or_result(self):
        args,kwargs=self.f.inputs()
        checked=index.verify_ack_index_assignment(*args,**kwargs,allocation_entry=self.f.allocation,
            offer_entry=self.f.offer,assignment_entry=self.f.assignment,directory_statuses=self.f.directory_statuses)
        self.assertIsNone(checked.denial_code)
        self.assertFalse(hasattr(checked,'request'))
        self.assertEqual(kwargs['budget'].snapshot()['signature_checks'],42)


if __name__=="__main__":
    unittest.main()
