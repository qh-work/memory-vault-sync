"""Actual cold saved memory to native ordinary-receive receipt return."""
import base64
import json
import subprocess
import unittest
import sqlite3
import time
from pathlib import Path
from unittest.mock import patch
from tests import test_open_delivery_http as fixture
from tests import test_open_ack_typescript_agent as runtime
from memory_vault_open_client import ACK_CONNECT_SCHEMA

DRIVER=runtime.DRIVER.replace("const agent=new Agent", "if(input.clock_offset){const clock=Date.now;Date.now=()=>clock()+input.clock_offset*1000;}\nconst agent=new Agent").replace("if(name==='requestNode'", """if(name==='requestRepair'&&input.lose_reply&&JSON.parse(Buffer.from(args[1]).toString()).kind==='ack.put_request'&&JSON.parse(Buffer.from(result).toString()).kind==='ack.put_response'){
      const error=Error('synthetic lost ACK reply');error.code='synthetic_lost_ack_reply';throw error;
    }
    if(name==='requestNode'""")

class NativeMailboxReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        runtime.NativeAckAgentTests.setUpClass.__func__(cls)
        (cls.fixture/'driver.mjs').write_text(DRIVER)

    def native(self,agent,requests,*,lose_reply=False,no_network=False,clock_offset=0):
        run=subprocess.run([self.node,'--experimental-strip-types',str(self.fixture/'driver.mjs')],cwd=self.fixture,
            input=json.dumps(dict(client_config=str(agent.client_config),network_config=str(agent.network_config),requests=requests,lose_reply=lose_reply,no_network=no_network,clock_offset=clock_offset)).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=75)
        self.assertEqual(run.returncode,0,run.stderr.decode(errors='replace')[-2500:]);out=json.loads(run.stdout);self.assertEqual(out['subprocessCalls'],0)
        state=Path(json.loads(Path(agent.network_config).read_bytes())['state_directory'])/'network.sqlite3'
        db=sqlite3.connect(state)
        try:self.assertEqual(db.execute('PRAGMA integrity_check').fetchall(),[('ok',)])
        finally:db.close()
        for row in out['results']:self.assertTrue(row['ok'],(row,run.stderr.decode(errors='replace')[-2000:]))
        self.assertNotIn('network_storage_unavailable',json.dumps(out),(out,run.stderr.decode(errors='replace')[-2000:]))
        if no_network:self.assertEqual(out['calls'],[])
        return out

    def test_native_ordinary_receive_returns_cold_memory_receipt_after_lost_reply(self):
        self.check_return('resume')

    def test_expired_retained_revocation_stops_pending_native_return(self):
        self.check_return('revoke')

    def test_expired_uncertain_return_stops_ordinary_polling(self):
        self.check_return('expired')

    def check_return(self,mode):
        h=fixture.MailboxStagingHTTPTests('test_cold_mailbox_returns_independent_receipt');h.setUp();self.addCleanup(h.doCleanups)
        from memory_vault_trust import TrustStore
        from memory_vault_client import ClientConfig
        TrustStore(ClientConfig.load(h.b.client_config).trust_path).add(h.ai.public_descriptor())
        call=h.call
        def share(agent,**request):
            invitation=request.get('invitation',{})
            if agent is h.a and ((request['op']=='send' and not request.get('memory_ids')) or (invitation.get('action')=='prepare' and invitation.get('schema_version')==ACK_CONNECT_SCHEMA and not invitation.get('memory_ids'))):
                m=call(h.a,op='remember',request_id='req_native_retained_return_memory',kind='observation',text='Synthetic cold mailbox return memory.')
                if request['op']=='send':request=dict(request,memory_ids=[m['memory_id']])
                else:request=dict(request,invitation=dict(invitation,memory_ids=[m['memory_id']]))
            return call(agent,**request)
        h.call=share;visited=[]
        def returned(host):
            visited.append(True);write=json.loads(h.ack_configuration['ack.write_grant']['raw'])['payload'];mid=write['message_id']
            selected=dict(schema_version=ACK_CONNECT_SCHEMA,action='register_mailbox_receipt_return',message_id=mid,source_url=host.nodes[0]['payload']['base_url'],source_key_id=host.identities[0].key_id,repair_profile='receipt')
            query=dict(schema_version=ACK_CONNECT_SCHEMA,action='inspect_mailbox_receipt_return',message_id=mid)
            self.native(h.b,[dict(op='connect',invitation=selected),dict(op='connect',invitation=selected)],no_network=True)
            first=self.native(h.b,[dict(op='receive',limit=1)],lose_reply=True)['results'][0]['result']
            self.assertTrue(any(e['code']=='synthetic_lost_ack_reply' for e in first['errors']),first);self.assertTrue(first['network_accessed']);self.assertFalse(first.get('receipt_returns'))
            pending=self.native(h.b,[dict(op='connect',invitation=query)],no_network=True)['results'][0]['result'];self.assertEqual(pending['state'],'pending');self.assertEqual(pending['result']['code'],'synthetic_lost_ack_reply')
            if mode=='expired':
                expired=self.native(h.b,[dict(op='receive',limit=1)],clock_offset=120)
                errors=expired['results'][0]['result']['errors'];self.assertTrue(any(e['code'] in {'repair_reconciliation_required','repair_saved_reconciliation_required'} for e in errors),errors)
                self.assertFalse(any(c['kind']=='requestRepair' for c in expired['calls']))
                held=self.native(h.b,[dict(op='connect',invitation=query)],no_network=True)['results'][0]['result'];self.assertEqual(held['state'],'reconciliation_required')
                stopped=self.native(h.b,[dict(op='receive',limit=1)],clock_offset=120);self.assertFalse(any(c['kind']=='requestRepair' for c in stopped['calls']));self.assertFalse(stopped['results'][0]['result'].get('receipt_returns'))
                return
            if mode=='revoke':
                from memory_vault_open_provider import issue_status
                from tests.test_open_repair_status import status_entry
                from memory_vault_open_repair_status import authenticate_status_original
                from memory_vault_open_repair_admin import _ReplicaStatusJournal
                from memory_vault_open_repair_state import DEFAULT_POLICY
                from memory_vault_open_repair_wire import RepairBudget
                old=json.loads(h.ack_configuration['historical.status.ack_root']['raw'])['payload'];now=int(time.time())
                denied=status_entry(issue_status(h.ai,root=write['ack_slot']['root_key'],revision=99,entries=[dict(e,status='revoked') for e in old['entries']],issued_at=now-10,valid_until=now-1))
                checked=authenticate_status_original(denied,expected_root=write['ack_slot']['root_key'],expected_signing_key=h.ai.public_descriptor(),at=now-10,allowed_scopes=[dict(scope_kind=e['scope_kind'],scope_id=e['scope_id']) for e in old['entries']],policy=DEFAULT_POLICY,budget=RepairBudget(DEFAULT_POLICY))
                with h.b._network() as network:
                    with network.participant.state.db() as db:_ReplicaStatusJournal(db,write['ack_slot']['root_key'],original_source=True).observe(checked)
                for _ in range(2):
                    refused=self.native(h.b,[dict(op='receive',limit=1)])
                    result=refused['results'][0]['result'];self.assertFalse(result.get('receipt_returns'));self.assertTrue(any(e['code']=='repair_authority_revoked' for e in result['errors']),result)
                    self.assertFalse(any(c['kind']=='requestRepair' for c in refused['calls']),refused['calls'])
                return
            resumed=self.native(h.b,[dict(op='receive',limit=1)])['results'][0]['result'];self.assertEqual(resumed['receipt_returns'],[dict(message_id=mid,state='retained_at_ack_source',from_local_history=False)])
            completed=self.native(h.b,[dict(op='connect',invitation=query)],no_network=True)['results'][0]['result'];self.assertEqual(completed['state'],'complete')
            again=self.native(h.b,[dict(op='receive',limit=1)]);self.assertFalse(again['results'][0]['result'].get('receipt_returns'));self.assertFalse(any(c['kind']=='requestRepair' for c in again['calls']))
            with h.b._network() as network:
                inbox=network._delivery()._inbox(mid);saved=json.loads(inbox['result']);self.assertEqual(saved['content_kind'],'memory_transfer');self.assertEqual(saved['share']['records_added'],1)
                inspected=network.connect(invitation=query);self.assertEqual(inspected,completed)
                with patch.object(network.participant.transport,'request_repair',side_effect=AssertionError('completed native request repeated HTTP')):
                    py=network.connect(invitation=dict(selected,action='return_mailbox_receipt'))
                self.assertTrue(py['from_local_history']);self.assertEqual(py['commit_ref'],completed['result']['commit_ref'])
            chunks=[];cursor=None
            while True:
                q=dict(schema_version=ACK_CONNECT_SCHEMA,action='export_preparation',request_id=h.ack_preparation_request_id,part='owner_invitation')
                if cursor is not None:q['cursor']=cursor
                page=h.call(h.a,op='connect',invitation=q);chunks.append(base64.b64decode(page['bundle_chunk']));cursor=page['next_cursor']
                if cursor is None:break
            recovered=h.call(h.a,op='connect',invitation=json.loads(b''.join(chunks)));self.assertEqual(recovered['message_id'],mid)
            with h.a._network() as network:
                with network.participant.state.db() as db:self.assertIsNotNone(db.execute('SELECT acknowledgement FROM open_delivery_outbox WHERE message_id=?',(mid,)).fetchone()[0])
            self.native(h.b,[dict(op='connect',invitation=dict(query,action='remove_mailbox_receipt_return')),dict(op='connect',invitation=selected)],no_network=True)
            replay=self.native(h.b,[dict(op='receive',limit=1)]);self.assertTrue(replay['results'][0]['result']['receipt_returns'][0]['from_local_history']);self.assertFalse(any(c['kind']=='requestRepair' for c in replay['calls']))
        h._return_cold_ack=returned;h.test_cold_mailbox_returns_independent_receipt();self.assertEqual(visited,[True])

if __name__=='__main__':unittest.main()
