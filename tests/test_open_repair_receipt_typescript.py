"""Real saved inbox to native durable ACK return, with the delivery node offline."""
import json
import subprocess
import unittest
from unittest.mock import patch
from tests import test_open_repair_receipt as saved_py
from tests import test_open_ack_typescript_agent as agent_ts

DRIVER=agent_ts.DRIVER.replace("const agent=new Agent", "Date.now=()=>2_000_000_008_000;\nconst agent=new Agent")
DRIVER=DRIVER.replace("if(name==='requestNode'", """if(name==='requestRepair'&&input.corruptReply&&JSON.parse(Buffer.from(args[1]).toString()).kind==='ack.put_request'){
      const body=JSON.parse(Buffer.from(result).toString());
      if(body.kind==='ack.put_response'){body.commit.ref.raw_sha256='0'.repeat(64);return Buffer.from(JSON.stringify(body));}
    }
    if(name==='requestNode'""")

class NativeSavedReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        agent_ts.NativeAckAgentTests.setUpClass.__func__(cls)
        (cls.fixture/'driver.mjs').write_text(DRIVER)

    def setUp(self):
        self.case=saved_py.SavedReceiptPublicationTests();self.addCleanup(self.case.doCleanups);self.case.setUp()
        self.case.send(memory=True);self.case.save_without_old_receipt_upload()
        def encode(e):return dict(raw=e['raw'].decode(),ref=e['ref'])
        self.request={n:encode(v) if n.endswith('_entry') else [encode(e) for e in v] if n=='current_statuses' else v for n,v in self.case.request.items()}
        self.invitation=dict(schema_version='memory-vault-open-ack-connect/v1',action='return_receipt',repair_profile='receipt',base_url=self.case.ack.http.base,request=self.request)

    def native(self,*,no_network=False,corrupt=False,agent=None,invitation=None):
        agent=agent or self.case.delivery.b
        result=subprocess.run([self.node,'--experimental-strip-types',str(self.fixture/'driver.mjs')],cwd=self.fixture,
            input=json.dumps(dict(client_config=str(agent.client_config),network_config=str(agent.network_config),
                requests=[dict(op='connect',invitation=invitation or self.invitation)],no_network=no_network,corruptReply=corrupt)).encode(),
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=45)
        self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace')[-3000:])
        output=json.loads(result.stdout);self.assertEqual(output['subprocessCalls'],0)
        if no_network:self.assertEqual(output['calls'],[])
        return output

    def test_native_saved_memory_return_and_shared_completed_history(self):
        result=self.native();returned=result['results'][0];self.assertTrue(returned['ok'],returned)
        self.assertEqual(returned['result']['state'],'retained_at_ack_source');self.assertFalse(returned['result']['from_local_history'])
        again=self.native(no_network=True)['results'][0];self.assertTrue(again['ok'],again)
        self.assertTrue(again['result']['from_local_history']);self.assertEqual(again['result']['commit_ref'],returned['result']['commit_ref'])
        publisher=self.case.publisher()
        with patch.object(publisher.client,'put',side_effect=AssertionError('completed history accessed network')):
            result=publisher.publish_saved(self.case.ack.http.base,self.case.request)
        self.assertTrue(result.from_local_history);self.assertEqual(result.source.commit.ref.as_dict(),returned['result']['commit_ref'])
        self.assertEqual(self.case.delivery.host.processes,{})
        self.case.ack.http.restart();f=self.case.ack.f
        def encode(e):return dict(raw=e['raw'].decode(),ref=e['ref'])
        request=dict(target_node_entry=encode(f['entries']['descriptor']),expected_target=f['expected']['expected_target'],
            expected_ack_slot=f['expected']['expected_ack_slot'],root_entry=encode(f['entries']['root']),read_entry=encode(f['entries']['read']),
            bootstrap_entry=encode(f['entries']['bootstrap']),expected_receipt_writer=self.case.ack.expected['expected_receipt_writer'],
            expected_message_id=self.case.message_id,expected_envelope_ref=self.case.envelope_ref)
        invitation=dict(schema_version=self.invitation['schema_version'],action='recover_receipt',repair_profile='receipt',base_url=self.case.ack.http.base,request=request)
        recovered=self.native(agent=self.case.delivery.a,invitation=invitation)['results'][0]
        self.assertTrue(recovered['ok'],recovered);self.assertTrue(recovered['result']['endpoint_validated'])
        self.assertFalse(recovered['result']['acknowledgement_pending'])
        self.assertEqual(recovered['result']['commit_ref'],returned['result']['commit_ref'])

    def test_native_resumes_pending_python_return(self):
        publisher=self.case.publisher();exchange=publisher.client.transport.request_repair
        def lose_response(base,raw,**options):
            result=exchange(base,raw,**options)
            if json.loads(raw).get('kind')=='ack.put_request':raise RuntimeError('synthetic lost committed response')
            return result
        with patch.object(publisher.client.transport,'request_repair',side_effect=lose_response),self.assertRaisesRegex(RuntimeError,'synthetic lost'):
            publisher.publish_saved(self.case.ack.http.base,self.case.request)
        self.case.ack.http.restart()
        result=self.native();returned=result['results'][0];self.assertTrue(returned['ok'],returned)
        self.assertEqual(len(result['calls']),1)
        self.assertEqual(self.case.ack.source.db.execute('SELECT count(*) FROM open_repair_put_requests').fetchone()[0],1)

    def test_unsaved_inbox_and_changed_envelope_refuse_before_network(self):
        self.request['envelope_ref']=dict(self.request['envelope_ref'],raw_sha256='0'*64)
        result=self.native(no_network=True)['results'][0];self.assertFalse(result['ok'])
        self.assertEqual(result['error']['code'],'repair_saved_tuple_mismatch')
        self.request['envelope_ref']=self.case.request['envelope_ref']
        with self.case.delivery.b._network() as network:
            with network.participant.state.db() as db:db.execute("UPDATE open_delivery_inbox SET phase='staged'")
        result=self.native(no_network=True)['results'][0];self.assertFalse(result['ok'])
        self.assertEqual(result['error']['code'],'repair_receipt_not_saved')

    def test_native_restarts_and_replays_pending_put_without_new_consent(self):
        result=self.native(corrupt=True)['results'][0];self.assertFalse(result['ok']);self.assertEqual(result['error']['code'],'repair_ref_mismatch')
        self.case.ack.http.restart()
        result=self.native();returned=result['results'][0];self.assertTrue(returned['ok'],returned)
        self.assertEqual(len(result['calls']),1)
        self.assertEqual(self.case.ack.source.db.execute('SELECT count(*) FROM open_repair_put_requests').fetchone()[0],1)
        self.assertTrue(self.native(no_network=True)['results'][0]['result']['from_local_history'])

if __name__=='__main__':unittest.main()
