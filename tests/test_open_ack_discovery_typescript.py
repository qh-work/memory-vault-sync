"""Native discovery reads a real directory and independently retrieves its receipt."""
import base64
import json
from pathlib import Path
import subprocess
import unittest
from types import SimpleNamespace
from tests.test_open_repair_admin import _AdminFixture
from tests import test_network_typescript_agent_network as ts_runtime
from tests.test_open_repair_probe_typescript import private_signing,encoded
from tests import test_open_repair_index_recovery as fixtures

DRIVER=ts_runtime.DRIVER.split('const {Agent}',1)[0]+r'''
const chunks=[];for await(const c of process.stdin)chunks.push(c);
const input=JSON.parse(Buffer.concat(chunks).toString('utf8'));Date.now=()=>input.now*1000;
const {OpenParticipant}=await import('./open-participant.ts');
const {OpenProviderClient}=await import('./open-provider-client.ts');
const {AckOwnerRecoveryClient}=await import('./open-repair-client.ts');
const {DiscoveredAckRecoveryClient}=await import('./open-ack-discovery.ts');
const decode=v=>({raw:Buffer.from(v.raw,'base64'),ref:v.ref});
const p=new OpenParticipant(input.signing,input.state,{seeds:input.routed?[input.options.expectedDirectoryNode]:[],allow_loopback:true}),calls=[];
if(!input.routed)p.lookupProviderDirectory=async()=>{throw Error('explicit directory lookup must not select another directory');};
for(const n of ['request','requestRepair']){
 const original=p.transport[n].bind(p.transport);p.transport[n]=async(...args)=>{calls.push({method:n,base:args[0]});return original(...args);};
}
const reader=new AckOwnerRecoveryClient(input.signing,input.encryption,{limitPolicy:input.limits,transport:p.transport,allowLoopback:true});
try{
 if(input.agent){
  const {Agent}=await import('./agent.ts');
  const options=input.options,request={expected_directory_node:options.expectedDirectoryNode,expected_directory:options.expectedDirectory,expected_source_epoch:options.expectedSourceEpoch,
    expected_target:options.expectedTarget,expected_ack_slot:options.expectedAckSlot,expected_receipt_writer:options.expectedReceiptWriter,expected_message_id:options.expectedMessageId,expected_envelope_ref:options.expectedEnvelopeRef};
  for(const [snake,camel] of [['root_entry','rootEntry'],['read_entry','readEntry'],['bootstrap_entry','bootstrapEntry']])request[snake]={raw:Buffer.from(options[camel].raw,'base64').toString('utf8'),ref:options[camel].ref};
  if(input.routed){delete request.expected_directory_node;delete request.expected_directory;}
  const result=await new Agent(input.client_config,input.network_config).handle({op:'connect',invitation:{schema_version:'memory-vault-open-ack-connect/v1',action:input.routed?'recover_routed_receipt':'recover_discovered_receipt',repair_profile:'receipt-index',request}});
  process.stdout.write(JSON.stringify({...result,subprocessCalls}));
 }else{
 const options={...input.options,rootEntry:decode(input.options.rootEntry),readEntry:decode(input.options.readEntry),bootstrapEntry:decode(input.options.bootstrapEntry)};
 const client=new DiscoveredAckRecoveryClient(new OpenProviderClient(p,input.encryption),reader);
 if(input.routed){delete options.expectedDirectoryNode;delete options.expectedDirectory;}
 const r=await (input.routed?client.recoverRouted(options):client.recover(options));
 process.stdout.write(JSON.stringify({ok:true,state:r.state,receipt:Buffer.from(r.recovery.source.inputs.receipt.raw).toString('base64'),
   commit:r.recovery.source.commit.ref,custody:r.fact.payload.custody_id,calls,subprocessCalls}));
 }
}catch(e){process.stdout.write(JSON.stringify({ok:false,code:e.code??'untyped_error',detail:e.code?undefined:String(e.stack),calls,subprocessCalls}));}
finally{reader.close();p.close();}
'''
class NativeAckDiscoveryTests(_AdminFixture,unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ts_runtime.TypeScriptAgentNetworkTests.setUpClass.__func__(cls)
        (cls.fixture/'driver.mjs').write_text(DRIVER)
    def setUp(self):
        self.h=fixtures.IndexedReceiptRecoveryTests();self.h.setUp();self.addCleanup(self.h.doCleanups)
    def native(self,agent=False,routed=False):
        h=self.h;c=h.host.c;f=c.f.f;q=h.options
        names={'expectedDirectoryNode':'expected_directory_node','expectedDirectory':'expected_directory',
            'expectedTarget':'expected_target','expectedSourceEpoch':'expected_source_epoch','expectedAckSlot':'expected_ack_slot',
            'expectedReceiptWriter':'expected_receipt_writer','expectedMessageId':'expected_message_id','expectedEnvelopeRef':'expected_envelope_ref'}
        options={a:q[b] for a,b in names.items()}
        options.update({a:encoded(q[b]) for a,b in [('rootEntry','root_entry'),('readEntry','read_entry'),('bootstrapEntry','bootstrap_entry')]})
        data=dict(signing=private_signing(f['signers']['owner']),encryption=f['encryption']['owner'].private_document(),
            now=c.f.at,state=str(Path(c.temp.name).resolve()/'native-discovery'),limits=f['expected']['limit_policy'],options=options,agent=agent,routed=routed,client_config=str(getattr(self,'config','')),network_config=str(getattr(self,'network','')))
        process=subprocess.run([self.node,'--experimental-strip-types',str(self.fixture/'driver.mjs')],cwd=self.fixture,
            input=json.dumps(data).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=45)
        self.assertEqual(process.returncode,0,process.stderr.decode(errors='replace')[-3000:]);result=json.loads(process.stdout)
        self.assertEqual(result['subprocessCalls'],0);return result
    def test_exact_directory_then_independent_owner_read(self):
        self.h.host.publish();r=self.native();self.assertTrue(r['ok'],r);self.assertEqual(r['state'],'usable')
        self.assertEqual(base64.b64decode(r['receipt']),self.h.host.c.f.case.receipt['raw'])
        self.assertEqual(r['custody'],'ack_'+r['commit']['raw_sha256'])
        self.assertTrue(any(c['method']=='requestRepair' for c in r['calls']))
    def test_routed_directory_then_independent_owner_read(self):
        self.h.host.publish();r=self.native(routed=True);self.assertTrue(r['ok'],r)
        self.assertEqual(base64.b64decode(r['receipt']),self.h.host.c.f.case.receipt['raw'])
        self.assertEqual(r['custody'],'ack_'+r['commit']['raw_sha256'])
        self.assertTrue(any(c['method']=='request' for c in r['calls']))

    def test_signed_wrong_custody_is_not_a_receipt_confirmation(self):
        import hashlib
        from memory_vault import canonical_bytes
        import memory_vault_open_provider as wire
        lease=self.h.host.publish();c=self.h.host.c;f=c.f
        fact=wire.issue_fact(f.f['signers']['target'],ref=f.root['anchor_ref'],
            storage_epoch=f.f['expected']['target_storage_epoch'],custody_id='ack_'+'00'*32,revision=2,
            issued_at=f.at,expires_at=f.until)
        payload=dict(lease['payload'],fact_sha256=hashlib.sha256(canonical_bytes(fact)).hexdigest(),custody_id=fact['payload']['custody_id'])
        other=dict(payload=payload,proof=f.directory.sign_message(payload))
        key=hashlib.sha256(canonical_bytes(dict(ref=fact['payload']['ref'],provider_key_id=fact['payload']['signing_key']['key_id'],
            storage_epoch=fact['payload']['storage_epoch'],custody_id=fact['payload']['custody_id']))).hexdigest()
        c.db.execute('UPDATE open_repair_index_facts SET fact_key=?,record=?,digest=?,revision=2,index_lease=?',
            (key,canonical_bytes(fact),payload['fact_sha256'],canonical_bytes(other)));c.db.commit()
        r=self.native();self.assertFalse(r['ok'],r);self.assertEqual(r['code'],'repair_index_custody_mismatch')
        self.assertTrue(any(c['method']=='requestRepair' for c in r['calls']))
    def test_both_agent_facades_read_but_refuse_a_receipt_without_the_original_send(self):
        from memory_vault_agent import Agent
        import sqlite3
        self.h.host.publish();self.host=SimpleNamespace(source=self.h.host.c.f.h);self.configure_owner()
        routed=getattr(self,'routed_facade',False)
        if routed:
            config=json.loads(self.network.read_bytes());config['seeds']=[self.h.host.c.node];self.network.write_text(json.dumps(config)+'\n')
        native=self.native(agent=True,routed=routed);self.assertFalse(native['ok'],native)
        self.assertEqual(native['error']['code'],'open_delivery_message_not_found')
        request=dict(self.h.options)
        if routed:request.pop('expected_directory_node');request.pop('expected_directory')
        for name in ('root_entry','read_entry','bootstrap_entry'):
            request[name]=dict(raw=request[name]['raw'].decode(),ref=request[name]['ref'])
        from unittest.mock import patch
        import memory_vault_open_node as nodes
        routing=nodes.RoutingTable
        with patch.object(nodes,'RoutingTable',side_effect=lambda *a,**kw:routing(*a,**(kw|dict(now=lambda:self.h.host.c.f.at)))):
            agent=Agent(self.config,self.network)
            result=agent.handle(dict(op='connect',invitation=dict(schema_version='memory-vault-open-ack-connect/v1',
                action='recover_routed_receipt' if routed else 'recover_discovered_receipt',repair_profile='receipt-index',request=request)))
        self.assertFalse(result['ok'],result);self.assertEqual(result['error']['code'],'open_delivery_message_not_found')
        with sqlite3.connect(self.directory/'transport/network.sqlite3') as db:
            self.assertGreater(db.execute('SELECT count(*) FROM open_ack_replica_statuses').fetchone()[0],0)
            self.assertEqual(db.execute('SELECT count(*) FROM open_delivery_outbox').fetchone()[0],0)
    def test_both_routed_agent_facades_refuse_a_receipt_without_original_send(self):
        self.routed_facade=True
        self.test_both_agent_facades_read_but_refuse_a_receipt_without_the_original_send()

    def test_missing_fact_never_starts_private_read(self):
        r=self.native();self.assertFalse(r['ok']);self.assertEqual(r['code'],'repair_index_not_observed')
        self.assertFalse(any(c['method']=='requestRepair' for c in r['calls']))

if __name__=='__main__':unittest.main()
