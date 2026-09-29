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
        prepared=self.prepare_upload()
        self.assertEqual(self.rows,[dict(role=e['role'],**e['entry']) for e in prepared['children']])
        self.intent=prepared['intent']

    def prepare_upload(self,current=None):
        h=self.h;journal=h.base.journal;resolver,_,_=load_fixture(h.f,journal.policy)
        statuses=current if current is not None else [signed_entry(p,s,'current_'+str(i)) for i,(p,s) in enumerate(zip(h.status_values,h.status_signers))]
        return journal.prepare_upload_unbound(h.f['manifest'],resolver,h.f['custody'],h.request,h.offer,h.assignment,
            h.base.consent,h.disclosures['owner'],h.disclosures['source'],
            expected_ack_slot=self.context['expected_ack_slot'],expected_owner=self.context['expected_owner'],
            expected_source=self.context['expected_source'],source_storage_epoch=self.context['source_storage_epoch'],
            expected_target=self.state.target,target_storage_epoch=self.state.node['payload']['storage_epoch'],
            current_statuses=statuses,at=h.base.now,limit_policy=h.f['expected']['limit_policy'])

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

    def test_sender_prepared_upload_is_exact_after_journal_restart(self):
        self.h.base.local.db.close();self.h.base.local.connect();self.h.base.open_journal()
        prepared=self.prepare_upload()
        self.assertEqual(prepared['intent'],self.intent)
        self.assertEqual(self.h.base.local.db.execute('SELECT count(*) FROM ack_copy_prepare_uploads').fetchone()[0],1)

    def test_sender_retains_revocation_and_refuses_old_upload_after_restart(self):
        import copy
        values=copy.deepcopy(self.h.status_values);values[0]['revision']+=1
        for e in values[0]['entries']:e['status']='revoked'
        current=[signed_entry(p,s,'denied_current_'+str(i)) for i,(p,s) in enumerate(zip(values,self.h.status_signers))]
        with self.assertRaisesRegex(wire.RepairWireError,'repair_authority_revoked'):
            self.prepare_upload(current)
        self.h.base.local.db.close();self.h.base.local.connect();self.h.base.open_journal()
        with self.assertRaisesRegex(wire.RepairWireError,'repair_status_rollback|repair_authority_revoked'):
            self.prepare_upload()
        self.assertEqual(self.h.base.local.db.execute('SELECT count(*) FROM ack_copy_prepare_uploads').fetchone()[0],1)


class CopyUploadHTTPTests(unittest.TestCase):
    def setUp(self):
        import threading,time
        from pathlib import Path
        from unittest.mock import patch
        from memory_vault_open_control import issue_node
        from memory_vault_open_node import OpenHTTPServer
        from memory_vault_open_transport import OpenHTTPTransport
        self.case=CopyUploadTests();self.case.setUp();self.addCleanup(self.case.doCleanups)
        self.h=self.case.h;self.errors=[]
        self.clock=patch('time.time',return_value=self.h.base.now);self.clock.start();self.addCleanup(self.clock.stop)
        with patch('socket.getfqdn',return_value='localhost'):self.server=OpenHTTPServer(('127.0.0.1',0),None)
        self.addCleanup(self.server.server_close)
        state=self.case.state;self.base='http://127.0.0.1:'+str(self.server.server_port)
        self.descriptor=issue_node(state.identity,base_url=self.base,storage_epoch=state.node['payload']['storage_epoch'],
            roles=['directory','router'],revision=2,issued_at=self.h.base.now-1,expires_at=self.h.base.now+3599)
        self.directory=Path(self.h.destination.temp.name)
        for name in ('network.sqlite3','network.sqlite3-wal','network.sqlite3-shm'):
            path=self.directory/name
            if path.exists():path.chmod(0o600)
        self.start();self.addCleanup(self.stop)
        self.transport=OpenHTTPTransport(allow_loopback=True);self.addCleanup(self.transport.close)

    def start(self):
        import threading
        from memory_vault_open_node import OpenParticipant
        state=self.case.state
        self.participant=OpenParticipant(state.identity,self.directory,seeds=[],descriptor=self.descriptor,
            encryption_identity=state.encryption_identity,allow_loopback=True,provider_policy=dict(enabled=True),
            repair_policy=dict(enabled=True,limit_policy=self.h.f['expected']['limit_policy']))
        for name in ('handle_repair','handle_blob'):
            original=getattr(self.participant,name)
            def observed(*args,method=original):
                try:return method(*args)
                except Exception as error:self.errors.append(getattr(error,'code',type(error).__name__));raise
            setattr(self.participant,name,observed)
        self.server.participant=self.participant
        self.thread=threading.Thread(target=self.server.serve_forever,kwargs=dict(poll_interval=.02),daemon=True);self.thread.start()

    def stop(self):
        self.server.shutdown();self.server.server_close();self.thread.join(3);self.participant.close()

    def restart(self):
        from unittest.mock import patch
        from memory_vault_open_node import OpenHTTPServer
        address=self.server.server_address;self.stop()
        with patch('socket.getfqdn',return_value='localhost'):self.server=OpenHTTPServer(address,None)
        self.start()

    def send(self,entry):
        import time,hashlib
        from memory_vault import MemoryError
        try:raw=self.transport.request_repair(self.base,entry['raw'],deadline=time.monotonic()+15)
        except MemoryError as error:raise AssertionError(self.errors) from error
        digest=hashlib.sha256(raw).hexdigest()
        return dict(raw=raw,ref=dict(namespace='meta',key=digest,raw_sha256=digest,size=len(raw)))

    def send_frame(self,raw):
        import time
        from memory_vault import MemoryError
        from memory_vault_open_blob import decode_blob_frame,encode_blob_frame
        frame=decode_blob_frame(raw)
        try:reply=self.transport.request_blob(self.base,frame.header,frame.chunk,deadline=time.monotonic()+15)
        except MemoryError as error:raise AssertionError(self.errors) from error
        return encode_blob_frame(reply.header,reply.chunk)

    def test_http_upload_restarts_and_keeps_commit_separate(self):
        c=self.case;challenge=self.send(c.intent);self.restart()
        answer=entry(stage.solve_stage_challenge(c.intent,challenge,signer=self.h.f['signers']['maintainer'],
            encryption_identity=self.h.f['encryption']['maintainer'],expires_at=self.h.base.now+35,**c.options()))
        c.handle=self.send(answer)
        stage.verify_stage_handle(c.handle,c.intent,**c.options())
        first=c.frame(0);response=self.send_frame(first);self.restart()
        self.assertEqual(self.send(c.intent),challenge);self.assertEqual(self.send(answer),c.handle)
        self.assertEqual(self.send_frame(first),response)
        for i,row in enumerate(c.rows):
            for offset in range(0,len(row['raw']),stage.STAGE_CHUNK_BYTES):
                if i==0 and offset==0:continue
                frame=c.frame(i,offset);returned=self.send_frame(frame)
                stage.verify_stage_child_response_frame(returned,frame,c.intent,c.handle,**c.options())
        close=entry(stage.make_stage_close(c.intent,c.handle,signer=self.h.f['signers']['maintainer'],
            expires_at=self.h.base.now+25,**c.options()))
        result=self.send(close);self.restart();self.assertEqual(self.send(close),result)
        stage.verify_stage_result(result,close,c.intent,c.handle,**c.options())
        with self.participant.state.db() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM open_repair_copy_commits').fetchone()[0],0)
        from memory_vault_open_repair_copy_upload import make_copy_commit_request
        from memory_vault_open_repair_index_state import decode_entry
        request=entry(make_copy_commit_request(self.h.f['signers']['maintainer'],intent_entry=c.intent,result_entry=result,
            resource_id=c.rid,expected_owner=c.context['expected_owner'],expected_source=c.context['expected_source'],
            source_storage_epoch=c.context['source_storage_epoch'],expires_at=self.h.base.now+20,**c.options()))
        for variation in ('locator','before_close'):
            changed=json.loads(request['raw'])['payload']
            if variation=='locator':changed['stage_result_ref']['key']='f'*64
            else:changed['issued_at']-=1
            wrong=signed_entry(changed,self.h.f['signers']['maintainer'],'synthetic_wrong_commit_'+variation)
            with self.assertRaisesRegex(AssertionError,'repair_copy_upload_mismatch'):self.send(wrong)
            with self.participant.state.db() as db:
                self.assertEqual(db.execute('SELECT count(*) FROM open_repair_copy_commits').fetchone()[0],0)
            self.errors.clear()
        response=self.send(request);self.restart();self.assertEqual(self.send(request),response)
        budget=wire.RepairBudget(c.policy);value=wire.parse_new_wire(response['raw'],c.policy,budget).value
        self.assertEqual(value['kind'],'ack.copy_committed')
        custody=decode_entry(value['custody'],c.policy,budget);manifest=decode_entry(value['manifest'],c.policy,budget)
        self.assertNotEqual(custody['ref']['key'],custody['ref']['raw_sha256'])
        resolver=wire.LocalRawResolver(c.policy,budget)
        for child in c.rows:resolver.put(child['ref']['namespace'],child['ref']['key'],child['raw'])
        checked=authority.verify_unbound_replica_event(manifest,resolver,custody,**c.context,
            expected_target=c.state.target,target_storage_epoch=c.state.node['payload']['storage_epoch'],
            limit_policy=self.h.f['expected']['limit_policy'],policy=c.policy,budget=budget)
        self.assertEqual(checked['source'].custody.ref.as_dict(),self.h.f['custody']['ref'])
        with self.participant.state.db() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM open_repair_copy_commits').fetchone()[0],1)
        self.assertEqual(self.errors,[])

    def test_http_rejects_unrelated_signer_without_charging_reserved_resource(self):
        payload=json.loads(self.case.intent['raw'])['payload']
        wrong=signed_entry(payload,self.h.f['signers']['owner'],'synthetic_http_wrong_uploader')
        with self.assertRaises(AssertionError):self.send(wrong)
        with self.participant.state.db() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM open_repair_copy_upload_work').fetchone()[0],0)
            self.assertEqual(db.execute('SELECT count(*) FROM open_repair_copy_upload_sessions').fetchone()[0],0)
        self.assertTrue(self.errors)

    def test_http_upload_respects_operator_repair_switch(self):
        self.participant.repair_policy['enabled']=False
        with self.assertRaisesRegex(AssertionError,'open_repair_closed'):self.send(self.case.intent)
        with self.participant.state.db() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM open_repair_copy_upload_sessions').fetchone()[0],0)

    def client_upload(self,transport=None):
        from memory_vault_open_repair_copy_client import AckCopyUploadClient
        from memory_vault import canonical_bytes
        h=self.h;c=self.case
        client=AckCopyUploadClient(h.base.journal,encryption_identity=h.f['encryption']['maintainer'],transport=transport,allow_loopback=True)
        self.addCleanup(client.close)
        resolver,_,_=load_fixture(h.f,h.base.journal.policy)
        node=dict(raw=canonical_bytes(self.descriptor))
        import hashlib
        digest=hashlib.sha256(node['raw']).hexdigest()
        node['ref']=dict(namespace='meta',key=digest,raw_sha256=digest,size=len(node['raw']))
        return client.upload(self.base,h.f['manifest'],resolver,h.f['custody'],h.request,h.offer,h.assignment,
            h.base.consent,h.disclosures['owner'],h.disclosures['source'],target_node_entry=node,
            **{k:v for k,v in c.context.items() if k!='expected_maintainer'},expected_target=c.state.target,
            target_storage_epoch=c.state.node['payload']['storage_epoch'],limit_policy=h.f['expected']['limit_policy'],
            current_statuses=[signed_entry(p,s,'current_'+str(i)) for i,(p,s) in enumerate(zip(h.status_values,h.status_signers))])

    def test_client_uploads_and_verifies_custody_over_actual_http(self):
        result=self.client_upload()
        self.assertEqual(result['state'],'replica_committed')
        with self.participant.state.db() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM open_repair_copy_commits').fetchone()[0],1)
        before=self.h.base.local.db.execute('SELECT sum(network) FROM ack_copy_client_work').fetchone()[0]
        self.restart()
        self.h.base.local.db.close();self.h.base.local.connect();self.h.base.open_journal()
        self.assertEqual(self.client_upload(),result)
        self.assertEqual(self.h.base.local.db.execute('SELECT sum(network) FROM ack_copy_client_work').fetchone()[0],before)

    def test_client_retries_exact_commit_after_lost_reply_and_restart(self):
        from memory_vault import MemoryError
        host=self
        class LostReply:
            def __init__(self):self.dropped=False;self.calls=[]
            def request(self,*args,**kwargs):return host.transport.request(*args,**kwargs)
            def request_blob(self,*args,**kwargs):return host.transport.request_blob(*args,**kwargs)
            def request_repair(self,base,raw,**kwargs):
                self.calls.append(raw);result=host.transport.request_repair(base,raw,**kwargs)
                if json.loads(raw)['payload']['kind']=='ack.copy_commit' and not self.dropped:
                    self.dropped=True;raise MemoryError('open_network_unavailable')
                return result
        transport=LostReply()
        with self.assertRaisesRegex(MemoryError,'open_network_unavailable'):self.client_upload(transport)
        last=transport.calls[-1];count=len(transport.calls)
        self.restart();self.h.base.local.db.close();self.h.base.local.connect();self.h.base.open_journal()
        self.assertEqual(self.client_upload(transport)['state'],'replica_committed')
        self.assertEqual(transport.calls[count:],[last])

    def test_client_refuses_signed_wrong_target_nonce_before_disclosure(self):
        from memory_vault import canonical_bytes
        from memory_vault_open_transport import TransportReply
        host=self
        class WrongNonce:
            def request(self,base,value,**kwargs):
                reply=host.transport.request(base,value,**kwargs)
                if value['payload']['action']=='target.answer':
                    changed=json.loads(canonical_bytes(reply.response));p=changed['payload']
                    answer=p['body']['answer']['payload'];answer['answer']='A'*43
                    signer=host.case.state.identity
                    p['body']['answer']=dict(payload=answer,proof=signer.sign_message(answer))
                    changed=dict(payload=p,proof=signer.sign_message(p))
                    return TransportReply(changed,reply.observed_address,len(canonical_bytes(changed)))
                return reply
            def request_repair(self,*args,**kwargs):raise AssertionError('disclosed originals')
            def request_blob(self,*args,**kwargs):raise AssertionError('disclosed originals')
        with self.assertRaisesRegex(wire.RepairWireError,'repair_provider_proof_mismatch'):self.client_upload(WrongNonce())
        with self.participant.state.db() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM open_repair_copy_upload_sessions').fetchone()[0],0)

    def test_client_observed_revocation_during_preflight_stops_upload(self):
        host=self
        class RevokeDuringProof:
            def request(self,*args,**kwargs):
                reply=host.transport.request(*args,**kwargs)
                h=host.h
                statuses=[signed_entry(p,s,'current_'+str(i)) for i,(p,s) in enumerate(zip(h.status_values,h.status_signers))]
                revoked=json.loads(statuses[0]['raw'])['payload'];revoked['revision']+=1
                for item in revoked['entries']:item['status']='revoked'
                statuses[0]=signed_entry(revoked,h.f['signers']['owner'],'synthetic_midflight_revocation')
                with host.assertRaisesRegex(wire.RepairWireError,'repair_authority_revoked'):host.case.prepare_upload(statuses)
                return reply
            def request_repair(self,*args,**kwargs):raise AssertionError('disclosed revoked originals')
            def request_blob(self,*args,**kwargs):raise AssertionError('disclosed revoked originals')
        with self.assertRaisesRegex(wire.RepairWireError,'repair_status_changed'):self.client_upload(RevokeDuringProof())
        with self.participant.state.db() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM open_repair_copy_upload_sessions').fetchone()[0],0)
