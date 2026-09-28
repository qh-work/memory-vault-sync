"""A durable consumer sees authenticated denials, never unverified input."""
import copy
import unittest

import memory_vault_open_repair_status as status
import memory_vault_open_repair_wire as wire
from tests.test_open_repair_status import historical_status_fixture, resign_status, status_entry, POLICY, NOW


class StatusObserverTests(unittest.TestCase):
    def test_callback_preserves_denials_after_authentication_without_extra_crypto(self):
        signed,entry,options,signers,*_=historical_status_fixture()
        local=wire.RepairPolicy(**POLICY)
        def verify(original=entry,expectations=options,callback=None):
            budget=wire.RepairBudget(local)
            try:
                result=status.verify_status_original(original,**expectations,policy=local,budget=budget,
                    on_authenticated=callback)
                return result,None,budget.snapshot()
            except wire.RepairWireError as exc:
                return None,exc.code,budget.snapshot()
        def changed(mutate,signer=None):
            return status_entry(resign_status(signed,signer or signers['owner'],mutate),pretty=True)
        cases=[('repair_authority_revoked',changed(lambda p:p['entries'][0].update(status='revoked')),options),
               ('repair_status_revision',changed(lambda p:p['entries'][0].update(minimum_document_revision=2)),options),
               ('repair_status_operation',changed(lambda p:p['entries'][0].update(operation_mask=1)),options),
               ('repair_status_missing',changed(lambda p:p.update(entries=p['entries'][:1])),options),
               ('repair_status_mismatch',entry,dict(options,at=NOW+600))]
        for expected,original,expectations in cases:
            with self.subTest(code=expected):
                seen=[]
                result,code,meter=verify(original,expectations,seen.append)
                self.assertIsNone(result);self.assertEqual(code,expected)
                self.assertEqual(len(seen),1)
                self.assertEqual(seen[0].raw,original['raw'])
                self.assertEqual(seen[0].ref.as_dict(),original['ref'])
                self.assertEqual(meter['signature_checks'],1)
        narrowed=copy.deepcopy(options)
        narrowed['allowed_scopes']=narrowed['allowed_scopes'][:1]
        narrowed['required']=narrowed['required'][:1]
        wrong_root=copy.deepcopy(options);wrong_root['expected_root']['root_id']='another_synthetic_root'
        for original,expectations in [(changed(lambda p:None,signers['target']),options),(entry,narrowed),
                (entry,wrong_root),(changed(lambda p:p.update(issued_at=NOW+100,valid_until=NOW+700)),options)]:
            with self.subTest(invalid=expectations):
                seen=[]
                result,code,_=verify(original,expectations,seen.append)
                self.assertIsNone(result);self.assertIsNotNone(code);self.assertEqual(seen,[])
        seen=[]
        default,code,default_meter=verify()
        observed,observed_code,observed_meter=verify(callback=seen.append)
        self.assertIsNone(code);self.assertIsNone(observed_code)
        self.assertEqual(default,observed);self.assertEqual(seen,[observed])
        self.assertEqual(default_meter,observed_meter)
        _,expired_code,expired_meter=verify(expectations=dict(options,at=NOW+600))
        self.assertEqual(expired_code,'repair_status_mismatch')
        self.assertEqual(expired_meter['signature_checks'],0)


if __name__=='__main__':unittest.main()
