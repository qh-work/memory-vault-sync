"""Publication shares the source's durable refusal and immutable-byte guards."""
import json
import unittest
from unittest.mock import patch

from memory_vault_open_repair_index_access import AckIndexSourceAccess
from memory_vault_open_repair_wire import RepairWireError
from tests.open_repair_index_fixtures import IndexFixture
from tests.open_repair_ack_fixtures import signed_entry
from tests import test_open_repair_state as source_tests
import memory_vault_open_repair_wire as wire


class AckIndexSourceAccessTests(unittest.TestCase):
    def setUp(self):
        original=source_tests.RepairStateTests.owner_setup
        def setup(h):
            # Explicit finite profile on a fresh source, before A signs it.
            limits=dict(h.state.limits,max_signature_checks=256)
            h.state.limits=wire.build_new_wire(limits,h.state.policy,wire.RepairBudget(h.state.policy)).value
            h.fixture['expected']['limit_policy']=limits
            h.fixture['docs']['bootstrap']['payload']['limits']=limits
            return original(h)
        with patch.object(source_tests.RepairStateTests,'owner_setup',setup):
            self.f=IndexFixture()
        self.f.h.now[0]=self.f.at
        self.gate=AckIndexSourceAccess(self.f.h.state);self.gate.initialize()

    def tearDown(self):
        self.f.close()

    def prepare(self,current=None):
        f=self.f
        return self.gate.prepare(f.h.resource_id,provider_fact_entry=f.fact,intent=f.intent,
            owner_consent_entry=f.consents['owner'],recipient_consent_entry=f.consents['writer'],
            current_statuses=f.current if current is None else current,
            expected_directory=f.directory_keys,directory_storage_epoch=f.epoch)

    def decide(self,prepared):
        with self.f.h.state._transaction():
            return self.gate.check_locked(prepared)

    def test_recipient_publication_revoke_survives_restart_without_changing_receipt(self):
        f=self.f
        self.assertTrue(self.decide(self.prepare()).allowed)
        scope=f.authority(f.consents['writer'],'ack.index_consent')
        current=list(f.current)
        for i,entry in enumerate(current):
            p=json.loads(entry['raw'])['payload']
            if p['signing_key']['key_id']!=f.f['signers']['writer'].key_id:continue
            if not any(item['scope_id']==scope for item in p['entries']):continue
            p['revision']+=1
            next(item for item in p['entries'] if item['scope_id']==scope).update(status='revoked',operation_mask=16)
            current[i]=signed_entry(p,f.f['signers']['writer'],'synthetic_index_revoke')
        decision=self.decide(self.prepare(current))
        self.assertFalse(decision.allowed);self.assertEqual(decision.code,'repair_authority_revoked')
        before=f.h.db.execute('SELECT * FROM open_repair_ack_commits').fetchone()
        f.h.db.close();f.h.connect();self.gate=AckIndexSourceAccess(f.h.state);self.gate.initialize()
        decision=self.decide(self.prepare())
        self.assertFalse(decision.allowed);self.assertEqual(decision.code,'repair_authority_revoked')
        self.assertEqual(f.h.db.execute('SELECT * FROM open_repair_ack_commits').fetchone(),before)

    def test_source_byte_change_between_preparation_and_send_is_rejected(self):
        prepared=self.prepare()
        self.f.h.db.execute("UPDATE open_repair_ack_jobs SET raw=?",(b'changed synthetic job',));self.f.h.db.commit()
        with self.assertRaisesRegex(RepairWireError,'repair_access_generation'):
            self.decide(prepared)

    def test_complete_source_role_mapping_and_original_job_are_checked_before_send(self):
        f=self.f
        original=f.h.db.execute("SELECT namespace,opaque_key FROM open_repair_ack_pins WHERE role='ack.root_authority'").fetchone()
        ref=f.f['entries']['read']['ref']
        f.h.db.execute("UPDATE open_repair_ack_pins SET namespace=?,opaque_key=? WHERE role='ack.root_authority'",(ref['namespace'],ref['key']))
        f.h.db.commit()
        with self.assertRaisesRegex(RepairWireError,'repair_storage_corrupt'):
            self.prepare()
        f.h.db.execute("UPDATE open_repair_ack_pins SET namespace=?,opaque_key=? WHERE role='ack.root_authority'",original)
        f.h.db.execute("UPDATE open_repair_ack_jobs SET raw=?",(b'corrupt existing job',));f.h.db.commit()
        with self.assertRaisesRegex(RepairWireError,'repair_receipt_ledger_missing'):
            self.prepare()

    def test_prepare_counts_real_crypto_before_start_and_failed_validation_keeps_work(self):
        f=self.f
        prepared=self.prepare()
        parties=self.gate.parties(prepared)
        self.assertEqual(parties['owner'],f.f['expected']['expected_owner'])
        self.assertEqual(parties['receipt_writer'],f.case.case.expected['expected_receipt_writer'])
        with self.assertRaises(TypeError):
            parties['owner']['signing_key']['key_id']='untrusted caller mutation'
        work=f.h.db.execute('SELECT signature_allowance,signature_checks FROM open_repair_bootstrap_work').fetchall()
        self.assertEqual(work,[(64,38)])
        self.assertEqual(f.h.db.execute('SELECT requests,signatures,replays FROM open_repair_bootstrap_usage').fetchone(),(1,38,1))
        self.assertIsNone(f.h.db.execute('SELECT 1 FROM open_repair_index_execution').fetchone())
        bad=dict(f.consents['writer'],raw=b'corrupt consent')
        with self.assertRaises(RepairWireError):
            self.gate.prepare(f.h.resource_id,provider_fact_entry=f.fact,intent=f.intent,
                owner_consent_entry=f.consents['owner'],recipient_consent_entry=bad,current_statuses=f.current,
                expected_directory=f.directory_keys,directory_storage_epoch=f.epoch)
        total=f.h.db.execute('SELECT signatures FROM open_repair_bootstrap_usage').fetchone()[0]
        self.assertGreater(total,38)
        self.assertEqual(total,f.h.db.execute('SELECT sum(signature_checks) FROM open_repair_bootstrap_work').fetchone()[0])
        self.assertTrue(self.decide(prepared).allowed)

    def test_capacity_reservation_corruption_is_not_a_valid_source(self):
        self.f.h.db.execute("UPDATE open_capacity_reservations SET charge_bytes=charge_bytes-1 WHERE service='ack'")
        self.f.h.db.commit()
        with self.assertRaisesRegex(RepairWireError,'repair_capacity_reservation_missing'):
            self.prepare()

    def test_assignment_resource_refusal_is_added_to_same_permanent_floor_gate(self):
        f=self.f
        prepared=self.prepare()
        def extend(statuses):
            return self.gate.prepare_assignment(prepared,allocation_entry=f.allocation,offer_entry=f.offer,
                assignment_entry=f.assignment,directory_statuses=statuses)
        bound=extend(f.directory_statuses)
        self.assertTrue(self.decide(bound).allowed)
        self.assertEqual(len(self.gate.assignment(bound).obligations),8)
        denied=list(f.directory_statuses)
        payload=json.loads(denied[1]['raw'])['payload']
        payload['revision']+=1
        payload['entries'][0].update(status='revoked',operation_mask=16)
        denied[1]=signed_entry(payload,f.directory,'revoked-directory-resource')
        self.assertEqual(self.decide(extend(denied)).code,'repair_authority_revoked')
        # The older validated offer/assignment cannot erase the newly seen D floor.
        self.assertEqual(self.decide(bound).code,'repair_authority_revoked')


if __name__=='__main__':unittest.main()
