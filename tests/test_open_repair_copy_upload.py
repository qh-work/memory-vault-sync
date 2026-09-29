"""Actual SQLite copy upload, restart and commit with synthetic originals."""
import json
import unittest
from memory_vault_open_repair_copy_upload import RepairCopyUpload
import memory_vault_open_repair_copy_authority as authority
import memory_vault_open_repair_stage as stage
import memory_vault_open_repair_wire as wire
from tests import test_open_repair_copy_state as fixtures
from tests.open_repair_ack_fixtures import load_fixture,signed_entry


def entry(item):return dict(raw=item.raw,ref=item.ref.as_dict())


class CopyUploadTests(unittest.TestCase):
    def setUp(self):
        self.h=fixtures.CopyStateTests();self.h.source_capacity=dict(max_meta_bytes=1048576,max_job_bytes=1048576,max_requests=4096)
        self.h.setUp();self.addCleanup(self.h.doCleanups)
        h=self.h;self.state=h.destination.state;self.policy=self.state.policy
        self.rid=json.loads(h.offer['raw'])['payload']['resource']['resource_id']
        self.context=dict(expected_ack_slot=h.f['expected']['expected_ack_slot'],expected_owner=h.f['expected']['expected_owner'],
            expected_source=h.f['expected']['expected_target'],source_storage_epoch=h.f['expected']['target_storage_epoch'],
            expected_maintainer=h.base.keys)
        resolver,_,budget=load_fixture(h.f,self.policy)
        statuses=[signed_entry(p,s,'current_'+str(i)) for i,(p,s) in enumerate(zip(h.status_values,h.status_signers))]
        plan=authority.verify_unbound_copy(h.f['manifest'],resolver,h.f['custody'],h.request,h.offer,h.assignment,
            h.base.consent,h.disclosures['owner'],h.disclosures['source'],**self.context,expected_target=self.state.target,
            target_storage_epoch=self.state.node['payload']['storage_epoch'],current_statuses=statuses,at=h.base.now,
            limit_policy=h.f['expected']['limit_policy'],policy=self.policy,budget=budget)
        self.assertIsNone(plan.denial_code)
        rows=[dict(role=e.role,**entry(e.original)) for e in plan.originals]
        rows.extend(dict(role=role,**e) for role,e in [('history.ack_unbound',h.f['manifest']),('copy.allocation',h.request),
            ('copy.offer',h.offer),('copy.assignment',h.assignment),('copy.owner_disclosure',h.disclosures['owner']),
            ('copy.source_disclosure',h.disclosures['source'])])
        rows.extend(dict(role='copy.current_status',**e) for e in statuses)
        rows.extend(dict(role='history.raw_pack',**e) for e in h.f['packs'])
        self.rows=sorted(rows,key=lambda e:(e['role'],e['ref']['namespace'],e['ref']['key'],e['ref']['raw_sha256'],e['ref']['size']))
        self.upload=RepairCopyUpload(self.state);self.upload.initialize()
        manifest=stage.make_stage_manifest(root_key=h.base.intent['root_key'],scope=h.base.intent['scope'],consumer='ack_copy_unbound',
            children=[dict(index=i,role=e['role'],ref=e['ref']) for i,e in enumerate(self.rows)],
            policy=self.policy,budget=wire.RepairBudget(self.policy))
        self.intent=entry(stage.make_stage_intent(h.f['signers']['maintainer'],allocation_id=h.base.intent['allocation_id'],
            manifest=manifest.value,expires_at=h.base.now+40,**self.options()))

    def options(self):
        return dict(expected_subject=self.h.base.keys,expected_target=self.state.target,
            target_storage_epoch=self.state.node['payload']['storage_epoch'],at=self.h.base.now,
            expected_consumer='ack_copy_unbound',policy=self.policy,budget=wire.RepairBudget(self.policy))

    def restart(self):
        self.h.destination.db.close();self.h.destination.connect();self.state=self.h.destination.state
        self.upload=RepairCopyUpload(self.state);self.upload.initialize()

    def handshake(self):
        self.challenge=self.upload.intent(self.rid,self.intent)
        self.answer=entry(stage.solve_stage_challenge(self.intent,self.challenge,signer=self.h.f['signers']['maintainer'],
            encryption_identity=self.h.f['encryption']['maintainer'],expires_at=self.h.base.now+35,**self.options()))
        self.handle=self.upload.answer(self.rid,self.answer)

    def frame(self,index,offset=0):
        raw=self.rows[index]['raw'][offset:offset+stage.STAGE_CHUNK_BYTES]
        return stage.make_stage_child_frame(self.intent,self.handle,signer=self.h.f['signers']['maintainer'],
            child_index=index,offset=offset,chunk=raw,expires_at=self.h.base.now+30,**self.options())

    def test_all_originals_survive_restart_before_atomic_copy_commit(self):
        self.handshake();first=self.frame(0);response=self.upload.child(self.rid,first)
        self.restart();self.assertEqual(self.upload.intent(self.rid,self.intent),self.challenge)
        self.assertEqual(self.upload.answer(self.rid,self.answer),self.handle)
        self.assertEqual(self.upload.child(self.rid,first),response)
        for i,row in enumerate(self.rows):
            for offset in range(0,len(row['raw']),stage.STAGE_CHUNK_BYTES):
                if i==0 and offset==0:continue
                frame=self.frame(i,offset);returned=self.upload.child(self.rid,frame)
                stage.verify_stage_child_response_frame(returned,frame,self.intent,self.handle,**self.options())
        self.assertEqual(self.state.db.execute('SELECT count(*) FROM open_repair_copy_commits').fetchone()[0],0)
        close=entry(stage.make_stage_close(self.intent,self.handle,signer=self.h.f['signers']['maintainer'],
            expires_at=self.h.base.now+25,**self.options()))
        result=self.upload.close(self.rid,close);self.restart()
        self.assertEqual(self.upload.close(self.rid,close),result)
        self.assertEqual(self.state.db.execute('SELECT count(*) FROM open_repair_copy_commits').fetchone()[0],0)
        custody=self.upload.commit_closed(self.rid,**self.context)
        self.assertEqual(json.loads(custody['raw'])['payload']['original_custody_ref'],self.h.f['custody']['ref'])
        self.assertEqual(self.state.db.execute('SELECT count(*) FROM open_repair_copy_commits').fetchone()[0],1)

    def test_incomplete_upload_never_closes_or_commits(self):
        self.handshake();self.upload.child(self.rid,self.frame(0))
        close=entry(stage.make_stage_close(self.intent,self.handle,signer=self.h.f['signers']['maintainer'],
            expires_at=self.h.base.now+25,**self.options()))
        with self.assertRaisesRegex(wire.RepairWireError,'repair_stage_incomplete'):self.upload.close(self.rid,close)
        self.restart()
        with self.assertRaisesRegex(wire.RepairWireError,'repair_stage_incomplete'):self.upload.commit_closed(self.rid,**self.context)
        self.assertEqual(self.state.db.execute('SELECT count(*) FROM open_repair_copy_commits').fetchone()[0],0)

    def test_different_request_for_same_chunk_refuses_after_restart(self):
        self.handshake();self.upload.child(self.rid,self.frame(0));self.restart()
        with self.assertRaisesRegex(wire.RepairWireError,'repair_stage_replay_conflict'):
            self.upload.child(self.rid,self.frame(0))
        self.assertEqual(self.state.db.execute('SELECT count(*) FROM open_repair_copy_upload_chunks').fetchone()[0],1)

    def test_missing_shared_reservation_refuses_more_upload(self):
        self.handshake()
        self.state.db.execute("DELETE FROM open_capacity_reservations WHERE service='repair_copy' AND reservation_id=?",(self.rid,))
        self.state.db.commit();self.restart()
        with self.assertRaisesRegex(wire.RepairWireError,'repair_copy_ledger_missing'):
            self.upload.child(self.rid,self.frame(0))

    def test_unauthenticated_intent_does_not_charge_owner_work(self):
        payload=json.loads(self.intent['raw'])['payload']
        wrong=signed_entry(payload,self.h.f['signers']['owner'],'synthetic_wrong_uploader')
        with self.assertRaises(wire.RepairWireError):self.upload.intent(self.rid,wrong)
        self.assertEqual(self.state.db.execute('SELECT count(*) FROM open_repair_copy_upload_work').fetchone()[0],0)
        self.assertEqual(self.state.db.execute('SELECT count(*) FROM open_repair_copy_upload_sessions').fetchone()[0],0)

    def test_exact_retries_exhaust_real_shared_budget_across_restart(self):
        first=self.upload.intent(self.rid,self.intent)
        for _ in range(63):self.assertEqual(self.upload.intent(self.rid,self.intent),first)
        self.restart()
        with self.assertRaisesRegex(wire.RepairWireError,'repair_copy_work_capacity'):
            self.upload.intent(self.rid,self.intent)
        self.assertEqual(self.state.db.execute('SELECT requests FROM open_repair_copy_work WHERE resource_id=?',(self.rid,)).fetchone()[0],64)
        self.assertEqual(self.state.db.execute('SELECT count(*) FROM open_repair_copy_upload_work WHERE actual IS NOT NULL').fetchone()[0],64)

    def test_wrong_encryption_answer_is_charged_without_issuing_handle(self):
        challenge=self.upload.intent(self.rid,self.intent)
        answer=entry(stage.solve_stage_challenge(self.intent,challenge,signer=self.h.f['signers']['maintainer'],
            encryption_identity=self.h.f['encryption']['maintainer'],expires_at=self.h.base.now+35,**self.options()))
        payload=json.loads(answer['raw'])['payload'];payload['answer']='A'*43
        wrong=signed_entry(payload,self.h.f['signers']['maintainer'],'synthetic_wrong_encryption_answer')
        with self.assertRaisesRegex(wire.RepairWireError,'repair_invalid_nonce'):self.upload.answer(self.rid,wrong)
        self.assertIsNone(self.state.db.execute('SELECT handle FROM open_repair_copy_upload_sessions').fetchone()[0])
        self.restart();self.assertTrue(self.upload.answer(self.rid,answer)['raw'])
        self.assertEqual(self.state.db.execute('SELECT requests FROM open_repair_copy_work WHERE resource_id=?',(self.rid,)).fetchone()[0],3)
        self.assertEqual(self.state.db.execute('SELECT count(*) FROM open_repair_copy_upload_work WHERE actual IS NOT NULL').fetchone()[0],3)
