"""Real native/Python first contact and shared SQLite restart, one fault domain.

All identities and stored bytes are synthetic. Every Node process forbids
subprocess delegation before importing production code; native JOSE is real.
"""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import time
import unittest

from memory_vault import canonical_bytes
from memory_vault_network_crypto import EncryptionIdentity, document_sha256
from memory_vault_open_contact import PROFILE, verify_response as verify_contact_response
from memory_vault_open_contact_client import CONNECT_SCHEMA, OpenContactClient
from memory_vault_open_control import coordinate, verify_response
from memory_vault_open_node import OpenParticipant
from memory_vault_open_routing import LookupBudget
from memory_vault_storage import atomic_write
from memory_vault_trust import Identity
from tests.test_open_typescript_http import GUARD, NODE_DRIVER, MixedNodes
from tests import test_network_typescript_agent_network as ts_runtime

DRIVER=GUARD+r"""
const {OpenParticipant}=await import('./open-participant.ts');
const {OpenContactClient}=await import('./open-contact-client.ts');
const {OpenHTTPTransport}=await import('./open-transport.ts');
const {Agent}=await import('./agent.ts');
const chunks=[];let size=0;
for await(const chunk of process.stdin){size+=chunk.length;if(size>1048576)throw Error('synthetic input limit');chunks.push(chunk);}
const input=JSON.parse(Buffer.concat(chunks).toString('utf8')),results=[],calls=[];
const original=OpenHTTPTransport.prototype.request;
OpenHTTPTransport.prototype.request=async function(base,value,deadline){
  const call={request:value,response:null,observed_address:null};calls.push(call);
  const reply=await original.call(this,base,value,deadline);
  call.response=reply.response;call.observed_address=reply.observed_address;return reply;
};
let participant;
try{
  if(input.mode==='agent'){
    const agent=new Agent(input.client_config,input.network_config);
    for(const request of input.requests)results.push(await agent.handle(request));
  }else{
    participant=new OpenParticipant(input.identity,input.state,{seeds:input.seeds,allow_loopback:true});
    const client=new OpenContactClient(participant,input.encryption);
    for(const operation of input.operations){try{
      const value=operation.op==='enable'?await client.enable(operation.node,operation.options):
        operation.op==='request'?await client.request(operation.recipient_key_id,{request_id:operation.request_id}):
        operation.op==='poll'?await client.poll(operation.lease_id):
        operation.op==='decide'?await client.decide(operation.request_ref,operation.options):
        operation.op==='result'?await client.result(operation.request_id):
        await client.dispatch(operation.invitation,operation.request_id);
      results.push({ok:true,value});
    }catch(error){results.push({ok:false,code:error.code??'untyped_error',retryable:error.retryable??false});}}
  }
}finally{participant?.close();}
process.stdout.write(JSON.stringify({results,calls,subprocessCalls}));
"""


class ContactTypeScriptHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ts_runtime.TypeScriptAgentNetworkTests.setUpClass.__func__(cls)
        (cls.fixture/'driver.mjs').write_text(DRIVER)
        (cls.fixture/'node-driver.mjs').write_text(NODE_DRIVER)

    def setUp(self):
        temporary=tempfile.TemporaryDirectory(prefix='memory-contact-mixed-synthetic-')
        self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name).resolve()

    def host(self,count,native):
        host=MixedNodes(self.root,count,self.node,self.fixture,native)
        self.addCleanup(host.close)
        host.stop(count-1)
        config=json.loads(host.configs[-1].read_bytes());config['contact_policy']={'enabled':True}
        atomic_write(host.configs[-1],canonical_bytes(config),replace=True);host.start(count-1)
        return host

    def identity(self,name):
        identity=Identity.generate(self.root/name/'identity.json')
        encryption=EncryptionIdentity.generate();encryption.save(self.root/name/'encryption.json')
        return identity,encryption

    def python(self,name,identity,encryption,seeds):
        participant=OpenParticipant(identity,self.root/name/'transport',seeds=seeds,allow_loopback=True)
        self.addCleanup(participant.close)
        return OpenContactClient(participant,encryption)

    def ts(self,**value):
        result=subprocess.run([self.node,'--experimental-strip-types',str(self.fixture/'driver.mjs')],
            input=json.dumps(value).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=self.fixture,timeout=40)
        self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace')[-6000:])
        payload=json.loads(result.stdout);self.assertEqual(payload['subprocessCalls'],0);return payload

    def native(self,name,seeds,operations):
        return self.ts(mode='contact',identity=json.loads((self.root/name/'identity.json').read_bytes()),
            encryption=json.loads((self.root/name/'encryption.json').read_bytes()),state=str(self.root/name/'transport'),
            seeds=seeds,operations=operations)

    def values(self,result):
        for row in result['results']:self.assertTrue(row['ok'],row)
        return [row['value'] for row in result['results']]

    def mature(self,host):
        identity,encryption=self.identity('observer')
        observer=self.python('observer',identity,encryption,host.nodes[:2])
        deadline=time.monotonic()+25;target=host.nodes[-1]['payload']['signing_key']['key_id']
        while time.monotonic()<deadline:
            route=asyncio.run(observer.participant._lookup(coordinate(target),'general',LookupBudget()))
            if any(node['payload']['signing_key']['key_id']==target for node in route['candidates']):break
            time.sleep(.25)
        self.assertTrue(any(node['payload']['signing_key']['key_id']==target for node in route['candidates']),route)
        observer.participant.close()

    def assert_trace(self,result,seeds):
        known={node['payload']['signing_key']['key_id']:node for node in seeds};introduced=set();traversed=[]
        configured=set(known)
        for call in result['calls']:
            request=call['request'];target=request['payload']['node_key_id'];node=known[target]
            if call['response'] is None:continue
            if target in introduced and target not in configured:traversed.append(target)
            self.assertEqual(call['observed_address'],'127.0.0.1')
            verify=verify_contact_response if request['payload']['schema_version']==PROFILE else verify_response
            checked=verify(call['response'],request=request,node=node)
            for candidate in checked['body'].get('nodes',[]):
                key=candidate['payload']['signing_key']['key_id'];introduced.add(key);known[key]=candidate
        self.assertTrue(traversed,'No response-derived real HTTP hop')

    def test_native_cold_sender_offline_python_owner_shared_client_and_resource_restart(self):
        host=self.host(7,{1,3,5})
        b,be=self.identity('owner');owner=self.python('owner',b,be,host.nodes[-2:])
        enabled=asyncio.run(owner.enable(host.nodes[-1],allocation_id='synthetic_knock',max_pending=2))
        self.assertEqual(enabled['state'],'active');owner.participant.close()
        self.mature(host)
        # A is born after B exits, with neither a B grant nor B's resource node.
        a,ae=self.identity('new-sender')
        protected=self.root/'synthetic-original-proof.bin';protected.write_bytes(b'synthetic original record\x00\xff')
        before=hashlib.sha256(protected.read_bytes()).hexdigest()
        queued=self.native('new-sender',host.nodes[:2],[{'op':'request','recipient_key_id':b.key_id,'request_id':'synthetic_contact'}])
        result=self.values(queued)[0];self.assertEqual(result['state'],'contact_queued');self.assertFalse(result['recipient_approved'])
        self.assertLessEqual(result['metrics']['requests'],64);self.assert_trace(queued,host.nodes[:2])
        sender=self.python('new-sender',a,ae,host.nodes[:2])
        self.assertEqual(asyncio.run(sender.result('synthetic_contact'))['state'],'pending')
        owner=self.python('owner',b,be,host.nodes[-2:]);pending=asyncio.run(owner.poll(enabled['lease_id']))
        self.assertEqual(len(pending['requests']),1);self.assertFalse(pending['recipient_approved'])
        ref=pending['requests'][0]['request_ref']
        self.assertEqual(asyncio.run(owner.decide(ref,decision='approved'))['state'],'decided')
        sender.participant.close();owner.participant.close()
        # Native R opens the same admitted requests/result/lease DB from Python.
        host.stop(6);host.native.add(6);host.start(6)
        results=self.values(self.native('new-sender',host.nodes[:2],[{'op':'result','request_id':'synthetic_contact'}]))
        approved=results[0];self.assertEqual(approved['state'],'approved');self.assertTrue(approved['authority_verified'])
        self.assertFalse(approved['open_messaging_supported']);grant=approved['grant']['payload']
        self.assertEqual(grant['subject_key_id'],a.key_id);self.assertEqual(grant['subject_encryption_key_id'],ae.key_id)
        self.assertEqual(grant['operations'],['message.store']);self.assertEqual(grant['resource_lease']['payload']['purpose'],'delivery')
        self.assertEqual(hashlib.sha256(protected.read_bytes()).hexdigest(),before)
        with sqlite3.connect(self.root/'new-sender/transport/network.sqlite3') as db:
            saved=json.loads(bytes(db.execute("SELECT body FROM open_contact_local WHERE category='result' AND reference='synthetic_contact'").fetchone()[0]))
        self.assertEqual(saved['decision']['payload']['grant'],approved['grant'])

    def test_python_sender_native_offline_owner_native_resource_and_owner_restart(self):
        host=self.host(2,{1});b,be=self.identity('owner')
        enabled=self.values(self.native('owner',host.nodes,[{'op':'enable','node':host.nodes[-1],
            'options':{'allocation_id':'synthetic_knock','max_pending':2}}]))[0]
        # Native B's process has now exited; create a fresh Python A.
        a,ae=self.identity('sender');sender=self.python('sender',a,ae,host.nodes)
        queued=asyncio.run(sender.request(b.key_id,request_id='synthetic_native_owner'))
        self.assertEqual(queued['state'],'contact_queued');self.assertFalse(queued['recipient_approved'])
        pending=self.values(self.native('owner',host.nodes,[{'op':'poll','lease_id':enabled['lease_id']}]))[0]
        self.assertEqual(len(pending['requests']),1);ref=pending['requests'][0]['request_ref']
        invalid=self.native('owner',host.nodes,[{'op':'decide','request_ref':ref,'options':{'decision':'approved','max_items':0}}])
        self.assertEqual(invalid['results'][0]['code'],'network_invalid_integer');self.assertEqual(invalid['calls'],[])
        with sqlite3.connect(self.root/'owner/transport/network.sqlite3') as db:
            self.assertEqual(db.execute("SELECT count(*) FROM open_contact_local WHERE category='allocation'").fetchone()[0],0)
        decision=self.values(self.native('owner',host.nodes,[{'op':'decide','request_ref':ref,'options':{'decision':'approved'}}]))[0]
        self.assertEqual(decision['state'],'decided')
        changed=self.native('owner',host.nodes,[{'op':'decide','request_ref':ref,'options':{'decision':'approved','max_bytes':512}}])
        self.assertEqual(changed['results'][0]['code'],'contact_local_conflict');self.assertEqual(changed['calls'],[])
        result=asyncio.run(sender.result('synthetic_native_owner'));self.assertEqual(result['state'],'approved')
        self.assertEqual(result['grant']['payload']['subject_key_id'],a.key_id)
        # The native six-op facade consumes Python's exact outgoing SQLite state;
        # an approved finite grant still leaves agent authority ineligible.
        facade=self.agent(self.agent_config('sender',host.nodes),[{'op':'connect','invitation':{
            'schema_version':CONNECT_SCHEMA,'action':'result','request_id':'synthetic_native_owner'}}])[0]
        self.assertTrue(facade['ok'],facade);self.assertEqual(facade['result']['grant'],result['grant'])
        # A Python B reopens native local control and retries the exact decision.
        owner=self.python('owner',b,be,host.nodes)
        self.assertEqual(asyncio.run(owner.decide(ref,decision='approved'))['state'],'decided')
        with sqlite3.connect(self.root/'owner/transport/network.sqlite3') as db:
            self.assertEqual(db.execute("SELECT count(*) FROM open_contact_local WHERE category='allocation'").fetchone()[0],1)
        self.assertFalse((self.root/'owner/vault.sqlite3').exists())

    def agent_config(self,name,seeds):
        client=self.root/name/'client.json';network=self.root/name/'open.json'
        atomic_write(client,canonical_bytes({'schema_version':'memory-vault-client-config/v1',
            'vault_path':str(self.root/name/'vault.sqlite3'),'identity_path':str(self.root/name/'identity.json'),
            'trust_path':str(self.root/name/'trust.json'),'capture_visible_turns':False}),replace=False)
        atomic_write(network,canonical_bytes({'schema_version':'memory-vault-open-client-config/v1','client_config_path':str(client),
            'state_directory':str(self.root/name/'transport'),'encryption_key_path':str(self.root/name/'encryption.json'),
            'seeds':seeds,'allow_loopback':True}),replace=False)
        return {'client_config':str(client),'network_config':str(network)}

    def test_native_local_capacity_reserves_result_and_decision_before_remote_admission(self):
        host=self.host(1,{0});b,be=self.identity('owner')
        owner=self.python('owner',b,be,host.nodes)
        enabled=asyncio.run(owner.enable(host.nodes[0],allocation_id='synthetic_knock',max_pending=1));owner.participant.close()
        a,ae=self.identity('sender')
        self.values(self.native('sender',host.nodes,[]))
        def database(name):return self.root/name/'transport/network.sqlite3'
        def fill(name):
            with sqlite3.connect(database(name)) as db:
                count=db.execute('SELECT count(*) FROM open_contact_local').fetchone()[0]
                db.executemany('INSERT INTO open_contact_local VALUES(?,?,?,?)',[
                    ('synthetic_filler','synthetic_fill_'+str(i),canonical_bytes({'synthetic':'finite local quota fixture'}),int(time.time())+600)
                    for i in range(127-count)])
        def free_one(name):
            with sqlite3.connect(database(name)) as db:
                db.execute("DELETE FROM open_contact_local WHERE category='synthetic_filler' AND reference='synthetic_fill_0'")
        def snapshot(name):
            with sqlite3.connect(database(name)) as db:
                return db.execute('SELECT category,reference,body,expires_at FROM open_contact_local ORDER BY category,reference').fetchall()
        def delivery_count():
            with sqlite3.connect(self.root/'node_0/transport/network.sqlite3') as db:
                return db.execute("SELECT count(*) FROM open_contact_resource_leases WHERE purpose='delivery'").fetchone()[0]
        fill('sender');before=snapshot('sender')
        operation={'op':'request','recipient_key_id':b.key_id,'request_id':'synthetic_at_capacity'}
        failed=self.native('sender',host.nodes,[operation])
        self.assertEqual(failed['results'][0]['code'],'contact_local_capacity');self.assertEqual(snapshot('sender'),before)
        self.assertFalse(any(call['request']['payload'].get('action') in {'challenge','submit'} for call in failed['calls']))
        free_one('sender');queued=self.values(self.native('sender',host.nodes,[operation]))[0]
        self.assertEqual(queued['state'],'contact_queued')
        with sqlite3.connect(database('sender')) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM open_contact_local').fetchone()[0],128)
            reserved=bytes(db.execute("SELECT body FROM open_contact_local WHERE category='result' AND reference='synthetic_at_capacity'").fetchone()[0])
            self.assertEqual(reserved,canonical_bytes({'state':'reserved_contact_control'}))
        poll=self.values(self.native('owner',host.nodes,[{'op':'poll','lease_id':enabled['lease_id']}]))[0]
        ref=poll['requests'][0]['request_ref'];fill('owner');before=snapshot('owner')
        decide={'op':'decide','request_ref':ref,'options':{'decision':'approved'}}
        failed=self.native('owner',host.nodes,[decide])
        self.assertEqual(failed['results'][0]['code'],'contact_local_capacity');self.assertEqual(failed['calls'],[])
        self.assertEqual(snapshot('owner'),before);self.assertEqual(delivery_count(),0)
        free_one('owner');self.assertEqual(self.values(self.native('owner',host.nodes,[decide]))[0]['state'],'decided')
        self.assertEqual(delivery_count(),1)
        completed=self.values(self.native('sender',host.nodes,[{'op':'result','request_id':'synthetic_at_capacity'}]))[0]
        self.assertEqual(completed['state'],'approved')
        with sqlite3.connect(database('sender')) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM open_contact_local').fetchone()[0],128)
            saved=json.loads(bytes(db.execute("SELECT body FROM open_contact_local WHERE category='result' AND reference='synthetic_at_capacity'").fetchone()[0]))
        self.assertEqual(saved['decision']['payload']['grant'],completed['grant'])

    def test_native_enable_reserves_local_handle_and_validates_before_remote_opt_in(self):
        host=self.host(1,{0});self.identity('owner');self.values(self.native('owner',host.nodes,[]))
        local=self.root/'owner/transport/network.sqlite3';remote=self.root/'node_0/transport/network.sqlite3'
        with sqlite3.connect(local) as db:
            db.executemany('INSERT INTO open_contact_local VALUES(?,?,?,?)',[
                ('synthetic_filler','synthetic_fill_'+str(i),canonical_bytes({'synthetic':'finite local quota fixture'}),int(time.time())+600)
                for i in range(128)])
        operation={'op':'enable','node':host.nodes[0],'options':{'allocation_id':'synthetic_enable_full','max_pending':1}}
        failed=self.native('owner',host.nodes,[operation])
        self.assertEqual(failed['results'][0]['code'],'contact_local_capacity');self.assertEqual(failed['calls'],[])
        with sqlite3.connect(remote) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM open_contact_resource_leases').fetchone()[0],0)
        for values in [{'revision':0},{'max_pending':None},{'max_pending':'synthetic'},{'lease_seconds':False}]:
            invalid=self.native('owner',host.nodes,[{**operation,'options':{**operation['options'],**values}}])
            self.assertEqual(invalid['results'][0]['code'],'network_invalid_integer');self.assertEqual(invalid['calls'],[])
        with sqlite3.connect(local) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM open_contact_local').fetchone()[0],128)
            db.execute("DELETE FROM open_contact_local WHERE category='synthetic_filler' AND reference='synthetic_fill_0'")
        enabled=self.values(self.native('owner',host.nodes,[operation]))[0];self.assertEqual(enabled['state'],'active')
        with sqlite3.connect(local) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM open_contact_local').fetchone()[0],128)
            self.assertEqual(db.execute("SELECT count(*) FROM open_contact_local WHERE category='policy_pending'").fetchone()[0],0)
            session=json.loads(bytes(db.execute("SELECT body FROM open_contact_local WHERE category='policy' AND reference=?",(enabled['lease_id'],)).fetchone()[0]))
        self.assertEqual(session['lease']['payload']['lease_id'],enabled['lease_id'])
        self.assertEqual(session['policy']['payload']['lease_sha256'],document_sha256(session['lease']))
        repeated=self.native('owner',host.nodes,[operation]);again=self.values(repeated)[0]
        self.assertEqual(again['lease_id'],enabled['lease_id']);self.assertEqual(again['expires_at'],enabled['expires_at'])
        self.assertFalse(any(call['request']['payload'].get('action')=='lease' for call in repeated['calls']))
        with sqlite3.connect(local) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM open_contact_local').fetchone()[0],128)
            self.assertEqual(db.execute("SELECT count(*) FROM open_contact_local WHERE category='policy_pending'").fetchone()[0],0)
        with sqlite3.connect(remote) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM open_contact_resource_leases').fetchone()[0],1)
            self.assertEqual(db.execute('SELECT count(*) FROM open_contact_policies').fetchone()[0],1)

    def agent(self,config,requests):
        result=self.ts(mode='agent',**config,requests=requests)
        for response in result['results']:
            self.assertLessEqual(len(canonical_bytes(response)),8192)
            self.assertFalse(response['authority']['authorization_eligible'])
        return result['results']

    def test_native_agent_explicit_connect_rejection_and_fixed_privacy_boundary(self):
        host=self.host(1,{0});b,be=self.identity('owner');owner=self.agent_config('owner',host.nodes)
        def connect(action,**values):return {'op':'connect','invitation':{'schema_version':CONNECT_SCHEMA,'action':action,**values}}
        enabled=self.agent(owner,[connect('enable',node=host.nodes[0],allocation_id='synthetic_knock',max_pending=1,lease_seconds=600,revision=1)])[0]
        self.assertTrue(enabled['ok'],enabled);lease=enabled['result']['lease_id']
        a,ae=self.identity('sender');sender=self.agent_config('sender',host.nodes)
        identity_before={name:(self.root/name/'identity.json').read_bytes() for name in ['owner','sender']}
        request=connect('request',recipient_key_id=b.key_id);request['request_id']='req_synthetic_contact'
        queued=self.agent(sender,[request,connect('result',request_id='req_synthetic_contact')])
        self.assertEqual(queued[0]['result']['state'],'contact_queued');self.assertFalse(queued[0]['result']['recipient_approved'])
        self.assertEqual(queued[1]['result']['state'],'pending')
        poll=self.agent(owner,[connect('poll',lease_id=lease)])[0]
        ref=poll['result']['requests'][0]['request_ref'];self.assertFalse(poll['result']['recipient_approved'])
        rejected=self.agent(owner,[connect('decide',request_ref=ref,decision='rejected',max_items=1,max_bytes=1024)])[0]
        self.assertTrue(rejected['ok'],rejected)
        completed=self.agent(sender,[connect('result',request_id='req_synthetic_contact'),
            {'op':'send','request_id':'req_synthetic_unsupported','recipients':[b.key_id],'text':'synthetic'}, {'op':'receive'}])
        self.assertEqual(completed[0]['result']['state'],'rejected');self.assertIsNone(completed[0]['result']['grant'])
        self.assertEqual([row['error']['code'] for row in completed[1:]],['open_messaging_unsupported']*2)
        for name in ['owner','sender']:
            self.assertEqual((self.root/name/'identity.json').read_bytes(),identity_before[name])
            self.assertFalse((self.root/name/'vault.sqlite3').exists());self.assertFalse((self.root/name/'trust.json').exists())


if __name__=='__main__':unittest.main()
