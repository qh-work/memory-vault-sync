"""Native recipient obtains the exact mailbox body over real owned HTTP."""
import hashlib
import json
import subprocess
import threading
import time
import unittest
from dataclasses import asdict,replace
from tests import test_network_typescript_agent_network as runtime
from tests import test_open_delivery_http as fixture
from tests.test_open_repair_probe_typescript import encoded
from tests.open_repair_ack_fixtures import signed_entry
from memory_vault_open_repair_mailbox_snapshot import MailboxSnapshotSource
import memory_vault_open_repair_wire as wire
import memory_vault_open_repair_history as history

DRIVER=runtime.DRIVER.split('const {Agent}',1)[0]+r'''
const {OpenNetworkClient}=await import('./open-client.ts'),{MailboxFeedRecoveryClient}=await import('./open-mailbox-client.ts');
const {MailboxSetupJournal}=await import('./open-mailbox-journal.ts'),{OpenHTTPTransport}=await import('./open-transport.ts');
const {createHash}=await import('node:crypto'),{decryptEnvelope}=await import('./open-delivery.ts');
const {validateSigningIdentity,validateEncryptionIdentity}=await import('./crypto.ts');
const chunks=[];for await(const chunk of process.stdin)chunks.push(chunk);const v=JSON.parse(Buffer.concat(chunks).toString()),decode=e=>({raw:Buffer.from(e.raw,'base64'),ref:e.ref});
const calls=[],original=OpenHTTPTransport.prototype.requestRepair;let denyHttp=false;
OpenHTTPTransport.prototype.requestRepair=async function(...args){const p=JSON.parse(Buffer.from(args[1]).toString());calls.push(p.kind??p.payload?.kind);if(denyHttp)throw Error('network after retained revocation');return original.apply(this,args);};
let network,client;const results=[];
try{
  network=new OpenNetworkClient(v.network_config);const journal=new MailboxSetupJournal(network.participant);
  const make=()=>new MailboxFeedRecoveryClient(network.identity,network.encryption,{policy:v.policy,limitPolicy:v.limits,allowLoopback:true});client=make();
  const opts={...v.options,targetNodeEntry:decode(v.node),slotEntries:Object.fromEntries(Object.entries(v.slots).map(([n,e])=>[n,decode(e)])),journal};
  const start=performance.now(),feed=await client.recover(v.base,opts),body=await client.readMember(v.base,feed,feed.entries[0]);
  const plain=await decryptEnvelope(body.envelope,{sender_signing_key:v.options.expectedSender.signing_key,sender_encryption_key:v.options.expectedSender.encryption_key,recipient_signing_key:validateSigningIdentity(network.identity),recipient_encryption_key:validateEncryptionIdentity(network.encryption),encryption_identity:network.encryption});
  results.push({ok:true,count:feed.entries.length,envelopeHash:createHash('sha256').update(body.envelope).digest('hex'),plaintext:Buffer.from(plain).toString(),requests:feed.metrics.requests,seconds:(performance.now()-start)/1000});
  let code;const before=calls.length;try{await client.readMember(v.base,{...feed},feed.entries[0]);}catch(e){code=e.code;}results.push({forged:code,calls:calls.length-before});
  denyHttp=true;const count=calls.length;try{await client.recover(v.base,{...opts,knownStatuses:[decode(v.revoked)]});results.push({revoked:'accepted'});}catch(e){results.push({revoked:e.code,calls:calls.length-count});}
  client.close();client=make();const prior=calls.length;try{await client.recover(v.base,opts);results.push({restart:'accepted'});}catch(e){results.push({restart:e.code,calls:calls.length-prior});}
}catch(e){results.push({ok:false,code:e.code??'untyped_error',detail:String(e.stack)});}
finally{client?.close();network?.close();}
process.stdout.write(JSON.stringify({results,calls,subprocessCalls}));
'''

class NativeMailboxClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        runtime.TypeScriptAgentNetworkTests.setUpClass.__func__(cls)
        (cls.fixture/'driver.mjs').write_text(DRIVER)
        from tests.test_open_ack_typescript_agent import DRIVER as agent_driver
        (cls.fixture/'agent-driver.mjs').write_text(agent_driver)

    def test_native_http_feed_body_and_durable_denial(self):
        self.check_http(False)

    def test_registered_agent_downloads_imports_and_retains_receipt(self):
        self.check_http(True)

    def test_registered_agent_recovers_mailbox_with_independent_ack(self):
        self.check_http(True,True)

    def check_http(self,agent_mode,with_ack=False):
        method='test_ack_configuration_survives_mailbox_custody' if with_ack else 'test_actual_delivery_stages_exact_ciphertext_under_mailbox_resources'
        h=fixture.MailboxStagingHTTPTests(method);h.setUp();self.addCleanup(h.doCleanups);visited=[]
        if agent_mode:
            from memory_vault_trust import TrustStore
            from memory_vault_client import ClientConfig
            TrustStore(ClientConfig.load(h.b.client_config).trust_path).add(h.ai.public_descriptor())
            original_call=h.call
            def share(agent,**request):
                if agent is h.a and (request['op']=='send' or (request.get('invitation',{}).get('action')=='prepare' and request.get('invitation',{}).get('schema_version')=='memory-vault-open-ack-connect/v1')):
                    remembered=original_call(h.a,op='remember',request_id='req_native_http_memory',kind='observation',text='Synthetic remotely recovered memory.')
                    if request['op']=='send':request=dict(request,memory_ids=[remembered['memory_id']])
                    else:request=dict(request,invitation=dict(request['invitation'],memory_ids=[remembered['memory_id']]))
                return original_call(agent,**request)
            h.call=share
        def inspect(staging,key,head):
            visited.append(True);s=staging.source;rid=staging.db.execute('SELECT resource_id FROM open_repair_mailbox_roots').fetchone()[0]
            snapshot=MailboxSnapshotSource(staging).load(rid,key,head,max_bytes=2_000_000,max_items=256)
            part=snapshot.parts[2];budget=wire.RepairBudget(s.policy);resolver=wire.LocalRawResolver(s.policy,budget)
            for role,ref in part.transfer:
                if role=='history.raw_pack':resolver.put(ref.namespace,ref.key,snapshot.read(ref.as_dict()))
            tree=history.resolve_historical_inputs(snapshot.read(part.manifest.as_dict()),resolver,s.policy,budget)
            roles={v.role:dict(raw=v.original.raw,ref=v.original.ref.as_dict()) for v in tree.roles}
            envelope=snapshot.read(snapshot.envelopes[0].as_dict());context=json.loads(envelope)['payload']['context']
            sender=dict(signing_key=h.ai.public_descriptor(),encryption_key=context['sender_encryption_key'])
            from memory_vault_open_node import OpenParticipant,OpenHTTPServer
            participant=OpenParticipant(s.identity,h.root/'node_0/transport',seeds=[],descriptor=s.node,encryption_identity=s.encryption_identity,allow_loopback=True,repair_policy=dict(enabled=True,limit_policy=s.limits),contact_policy=dict(enabled=True),delivery_policy=dict(enabled=True))
            server=OpenHTTPServer(('127.0.0.1',0),participant);thread=threading.Thread(target=server.serve_forever,kwargs=dict(poll_interval=.02),daemon=True);thread.start()
            def close():server.shutdown();server.server_close();thread.join(timeout=3);participant.close()
            self.addCleanup(close)
            base='http://127.0.0.1:'+str(server.server_port)
            node=signed_entry(dict(s.node['payload'],base_url=base,revision=s.node['payload']['revision']+1),s.identity,'synthetic_native_feed_node')
            # The ordinary delivery transport cannot supply this message anymore.
            staging.db.execute('DELETE FROM open_delivery_messages');staging.db.execute('DELETE FROM open_contact_resource_leases');staging.db.commit()
            from memory_vault_open_provider import issue_status
            from tests.test_open_repair_status import status_entry
            p=json.loads(roles['historical.status.slot']['raw'])['payload'];now=int(time.time())
            revoked=status_entry(issue_status(h.bi,root=key['root_key'],revision=99,entries=[dict(v,status='revoked') for v in p['entries']],issued_at=now-10,valid_until=now-1))
            call=dict(network_config=str(h.b.network_config),base=base,node=encoded(node),slots={n:encoded(roles[r]) for n,r in [('slot','mailbox.slot'),('read','mailbox.read_grant'),('maintenance','mailbox.maintenance_root'),('bootstrap','bootstrap.mailbox_feed')]},options=dict(expectedSlot=key,expectedSender=sender,expectedTarget=s.target),policy=asdict(replace(s.policy,max_signature_checks=512)),limits=s.limits,revoked=encoded(revoked))
            if agent_mode:
                invitation=dict(schema_version='memory-vault-open-mailbox-connect/v1',action='register',base_url=base,limit_policy=s.limits,expected_slot=key,expected_sender=sender,expected_target=s.target,target_node_entry=dict(raw=node['raw'].decode(),ref=node['ref']),slot_entries={n:dict(raw=roles[r]['raw'].decode(),ref=roles[r]['ref']) for n,r in [('slot','mailbox.slot'),('read','mailbox.read_grant'),('maintenance','mailbox.maintenance_root'),('bootstrap','bootstrap.mailbox_feed')]})
                message=json.loads(roles['delivery.attempt']['raw'])['payload']['message_id']
                def native(requests,no_network=False,allow_failure=False):
                    v=dict(client_config=str(h.b.client_config),network_config=str(h.b.network_config),requests=requests,no_network=no_network)
                    run=subprocess.run([self.node,'--experimental-strip-types',str(self.fixture/'agent-driver.mjs')],cwd=self.fixture,input=json.dumps(v).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=75)
                    self.assertEqual(run.returncode,0,run.stderr.decode(errors='replace')[-2000:]);out=json.loads(run.stdout);self.assertEqual(out['subprocessCalls'],0)
                    if no_network:self.assertEqual(out['calls'],[])
                    if not allow_failure:
                        for row in out['results']:self.assertTrue(row['ok'],row)
                    return out
                invalid=native([dict(op='connect',invitation=dict(invitation,base_url=base+'/wrong')),dict(op='connect',invitation=dict(invitation,expected_sender=s.target)),dict(op='connect',invitation=dict(schema_version=invitation['schema_version'],action='list'))],True,True)['results']
                self.assertFalse(invalid[0]['ok']);self.assertFalse(invalid[1]['ok']);self.assertEqual(invalid[2]['result']['mailboxes'],[])
                registered=native([dict(op='connect',invitation=invitation)],True)['results'][0]['result'];self.assertEqual(registered['state'],'registered')
                self.assertEqual(native([dict(op='connect',invitation=invitation)],True)['results'][0]['result'],registered)
                received=native([dict(op='receive',limit=1)])
                result=received['results'][0]['result'];self.assertTrue(result['network_accessed']);self.assertEqual(result['errors'],[]);self.assertEqual(len(result['messages']),1,result)
                saved=result['messages'][0];self.assertEqual(saved['state'],'validated_saved');self.assertEqual(saved['content_kind'],'memory_transfer');self.assertEqual(saved['share']['records_added'],1)
                reopened=native([dict(op='receive',message_id=message),dict(op='connect',invitation=dict(schema_version=invitation['schema_version'],action='list'))],True)
                self.assertEqual(reopened['results'][1]['result']['mailboxes'],[registered['receiver_id']])
                with h.b._network() as network:
                    inbox=network._delivery()._inbox(message);self.assertEqual(inbox['phase'],'saved');self.assertEqual(inbox['receipt_sent'],0);self.assertIsNotNone(inbox['receipt'])
                    # Python reopens the exact native evidence and authenticates its saved receipt.
                    network._delivery()._verify_mailbox_inbox(network._delivery()._inbox_session(inbox['session']),inbox)
                    self.assertEqual(network._delivery()._saved_receipt(message),json.loads(inbox['receipt']))
                    self.assertEqual(network._mailbox_saved_receiver(registered['receiver_id']),invitation)
                removed=native([dict(op='connect',invitation=dict(schema_version=invitation['schema_version'],action='remove',receiver_id=registered['receiver_id'])),dict(op='connect',invitation=dict(schema_version=invitation['schema_version'],action='list'))],True)
                self.assertEqual(removed['results'][1]['result']['mailboxes'],[])
                return
            result=subprocess.run([self.node,'--experimental-strip-types',str(self.fixture/'driver.mjs')],cwd=self.fixture,input=json.dumps(call).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=75)
            self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace')[-2000:]);out=json.loads(result.stdout);self.assertEqual(out['subprocessCalls'],0)
            self.assertEqual(len(out['results']),4,out);good,forged,denied,restarted=out['results'];self.assertTrue(good['ok'],out);self.assertEqual(good['envelopeHash'],hashlib.sha256(envelope).hexdigest());self.assertIn('Synthetic mailbox staging message',good['plaintext']);self.assertEqual(good['count'],1)
            self.assertIn('mailbox.body_read',out['calls']);self.assertEqual(forged,dict(forged='repair_proof_mismatch',calls=0));self.assertEqual(denied,dict(revoked='repair_authority_revoked',calls=0));self.assertEqual(restarted,dict(restart='repair_authority_revoked',calls=0))
        h.inspect_committed_mailbox=inspect;getattr(h,method)();self.assertEqual(visited,[True])

if __name__=='__main__':unittest.main()
