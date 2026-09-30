"""Native Agent confirms an original send and shares signed refusal history."""
import copy
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from memory_vault_open_transport import OpenHTTPTransport
from tests import test_open_delivery_http as fixtures
from tests import test_network_typescript_agent_network as ts_runtime

DRIVER = ts_runtime.DRIVER.split("const {Agent}",1)[0] + r"""
const {Agent}=await import('./agent.ts');
const {OpenHTTPTransport}=await import('./open-transport.ts');
const chunks=[];for await(const chunk of process.stdin)chunks.push(chunk);
const input=JSON.parse(Buffer.concat(chunks).toString('utf8')),calls=[];
for(const name of ['requestRepair','request','requestNode','requestBlob']){
  const original=OpenHTTPTransport.prototype[name];
  OpenHTTPTransport.prototype[name]=async function(...args){
    calls.push({kind:name,base:args[0]});
    if(input.no_network)throw Error('confirmed or revoked operation attempted HTTP');
    const result=await original.apply(this,args);
    if(name==='requestNode'&&input.node_override&&args[0]===input.node_override.payload.base_url)
      return {...result,response:input.node_override};
    return result;
  };
}
const agent=new Agent(input.client_config,input.network_config),results=[];
for(const request of input.requests)results.push(await agent.handle(request));
process.stdout.write(JSON.stringify({results,calls,subprocessCalls}));
"""


class NativeAckAgentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ts_runtime.TypeScriptAgentNetworkTests.setUpClass.__func__(cls)
        (cls.fixture/'driver.mjs').write_text(DRIVER)

    def native(self,agent,requests,*,no_network=False,node_override=None):
        result=subprocess.run([self.node,'--experimental-strip-types',str(self.fixture/'driver.mjs')],
            input=json.dumps(dict(client_config=str(agent.client_config),network_config=str(agent.network_config),
                requests=requests,no_network=no_network,node_override=node_override)).encode(),cwd=self.fixture,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=45)
        self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace')[-3000:])
        value=json.loads(result.stdout);self.assertEqual(value['subprocessCalls'],0)
        if no_network:self.assertEqual(value['calls'],[])
        return value

    def test_native_original_send_uses_existing_preparation_and_refuses_replaced_source(self):
        self.automatic=True
        self.test_native_recovers_original_receipt_then_reuses_python_state_and_revocation()

    def test_native_recovers_original_receipt_then_reuses_python_state_and_revocation(self):
        h=fixtures.MailboxStagingHTTPTests('test_cold_mailbox_returns_independent_receipt')
        h.setUp();self.addCleanup(h.doCleanups)
        call=h.call;recovered=[]
        def dispatch(agent,**request):
            invitation=request.get('invitation',{})
            if agent is h.a and invitation.get('action')=='recover_receipt':
                h.host.stop(0)
                before={p:p.read_bytes() for p in (Path(h.a.client_config),Path(h.a.network_config))}
                if getattr(self,'automatic',False):
                    changed=dict(h.ack_original_send_request,text=h.ack_original_send_request['text']+' changed')
                    invalid=self.native(h.a,[changed],no_network=True)['results'][0]
                    self.assertFalse(invalid['ok']);self.assertEqual(invalid['error']['code'],'network_request_id_conflict')
                    from memory_vault_open_control import issue_node
                    import time
                    old=h.ack_host.nodes[0]['payload'];now=int(time.time())
                    replacement=issue_node(h.ack_host.identities[0],base_url=old['base_url'],
                        storage_epoch='synthetic_changed_epoch',roles=old['roles'],revision=old['revision']+1,
                        issued_at=now-1,expires_at=now+300)
                    wrong=self.native(h.a,[h.ack_original_send_request],node_override=replacement)
                    refused=wrong['results'][0];self.assertTrue(refused['ok'],refused)
                    self.assertEqual(refused['result']['state'],'storage_accepted')
                    self.assertEqual(refused['result']['ack_recovery_error']['code'],'open_ack_preparation_conflict')
                    self.assertFalse(any(c['kind']=='requestRepair' for c in wrong['calls']))
                    selected=h.ack_original_send_request
                else:selected=request
                result=self.native(h.a,[selected]);response=result['results'][0]
                if getattr(self,'automatic',False):self.assertEqual(response['result']['ack_recovery'],'validated_saved')
                self.assertTrue(response['ok'],response)
                self.assertEqual(response['result']['state'],'validated_saved')
                self.assertTrue(result['calls'])
                self.assertTrue(all(c['base']==h.ack_host.nodes[0]['payload']['base_url'] for c in result['calls']))
                for p,raw in before.items():self.assertEqual(p.read_bytes(),raw)
                recovered.append((copy.deepcopy(invitation),response['result']))
                return response['result']
            return call(agent,**request)
        h.call=dispatch
        h.test_cold_mailbox_returns_independent_receipt()
        self.assertEqual(len(recovered),1)
        invitation,saved=recovered[0]
        # A new native process uses the shared outbox and never reads either node.
        repeated=self.native(h.a,[h.ack_original_send_request],no_network=True)['results'][0]
        self.assertTrue(repeated['ok'],repeated)
        self.assertEqual(repeated['result']['message_id'],saved['message_id'])
        self.assertEqual(repeated['result']['state'],'validated_saved')
        self.assertFalse(repeated['result']['network_accessed'])
        with patch.object(OpenHTTPTransport,'request_node',side_effect=AssertionError('confirmed Python send contacted node')):
            self.assertEqual(call(h.a,**h.ack_original_send_request)['state'],'validated_saved')
        # Reuse one actual authenticated owner status from the native journal.
        with h.a._network() as network:
            with network.participant.state.db() as db:
                entries=[json.loads(bytes(r[0])) for r in db.execute('SELECT raw FROM open_mailbox_setup_statuses')]
        from memory_vault_open_provider import issue_status
        from tests.test_open_repair_status import scope_digest,status_entry
        import time
        grant=invitation['request']['read_entry']
        root=invitation['request']['expected_ack_slot']['root_key']
        revision=max(e['payload']['revision'] for e in entries if e['payload']['signing_key']==h.ai.public_descriptor())+1
        subject=dict(authority_kind='ack.read_grant',authority_sha256=grant['ref']['raw_sha256'])
        scope=scope_digest(root,'authority',subject)
        now=int(time.time())
        signed=issue_status(h.ai,root=root,revision=revision,issued_at=now,valid_until=now+300,
            entries=[dict(scope_kind='authority',scope_id=scope,minimum_document_revision=json.loads(grant['raw'])['payload']['revision'],status='revoked',operation_mask=2)])
        entry=status_entry(signed)
        observation=dict(raw=entry['raw'].decode(),ref=entry['ref'])
        denied=dict(invitation,request=dict(invitation['request'],known_statuses=[observation]))
        refused=self.native(h.a,[dict(op='connect',invitation=denied)],no_network=True)['results'][0]
        self.assertFalse(refused['ok']);self.assertEqual(refused['error']['code'],'repair_authority_revoked')
        replay=self.native(h.a,[dict(op='connect',invitation=invitation)],no_network=True)['results'][0]
        self.assertFalse(replay['ok']);self.assertEqual(replay['error']['code'],'repair_authority_revoked')
        with patch.object(OpenHTTPTransport,'request_repair',side_effect=AssertionError('Python forgot native revocation')):
            replay=h.a.handle(dict(op='connect',invitation=invitation))
        self.assertFalse(replay['ok']);self.assertEqual(replay['error']['code'],'repair_authority_revoked')


if __name__=='__main__':unittest.main()
