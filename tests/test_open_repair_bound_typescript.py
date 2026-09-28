"""Native original ACK write/offer closure with real independent Ed25519 work."""
import base64
import copy
import hashlib
import json
import subprocess
import unittest

from memory_vault import canonical_bytes
import memory_vault_open_repair_bound as bound
import memory_vault_open_repair_wire as wire
from tests import test_network_typescript_agent_network as ts_runtime
from tests.open_repair_bound_fixtures import LIMITS, ack_bound_fixture, rebuild_bound_fixture
from tests.test_open_repair_probe_typescript import encoded

POLICY=dict(max_document_bytes=65536,max_total_bytes=4000000,max_nodes=100000,max_depth=100,
    max_string_bytes=65536,max_hash_bytes=4000000,max_hashes=1000,max_entries=1000,max_retained_bytes=4000000,max_signature_checks=100)
DRIVER=r"""
import child from 'node:child_process';
import crypto from 'node:crypto';
import {syncBuiltinESMExports} from 'node:module';
let subprocessCalls=0,nativeChecks=0;
const deny=()=>{subprocessCalls++;throw Error('native bound verifier must not delegate');};
for(const name of ['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork'])child[name]=deny;
const actualVerify=crypto.verify;crypto.verify=(...args)=>{nativeChecks++;return actualVerify(...args);};syncBuiltinESMExports();
const b=await import('./open-repair-bound.ts'),w=await import('./open-repair-wire.ts');
const chunks=[];let size=0;for await(const chunk of process.stdin){size+=chunk.length;if(size>4194304)throw Error('synthetic input limit');chunks.push(chunk);}
const calls=JSON.parse(Buffer.concat(chunks).toString('utf8')),results=[];
for(const c of calls){const start=nativeChecks;let budget,callbacks=0;try{
  budget=new w.RepairBudget(c.policy);const entries=Object.fromEntries(Object.entries(c.entries).map(([role,item])=>[role,{raw:Buffer.from(item.raw,'base64'),ref:item.ref}]));
  const options={...c.options,policy:c.policy,budget};if(c.offer)options.limitPolicy=c.limits;
  const verify=()=>c.offer?b.verifyAckOfferBootstrapOriginal(entries.bootstrap,{root:entries.root,write:entries.write},options):b.verifyAckWriteGrantOriginal(entries.write,entries.root,options);
  if(c.host==='options')Object.defineProperty(options,'expectedOwner',{get(){callbacks++;throw Error('getter');}});
  if(c.host==='proxy')options.expectedAckSlot=new Proxy(options.expectedAckSlot,{ownKeys(){callbacks++;throw Error('proxy');}});
  if(c.host==='entry')Object.defineProperty(entries.write,'raw',{get(){callbacks++;throw Error('getter');}});
  const result=verify();let immutable=true,retryCode;
  if(c.mutate){const previous=Buffer.from(result.originals.write.raw);entries.write.raw.fill(0);result.originals.write.raw.fill(0);options.expectedAckSlot.grant_id='changed';immutable=Buffer.from(result.originals.write.raw).equals(previous);}
  if(c.repeat){try{verify();}catch(e){retryCode=e.code;}}
  results.push({ok:true,at:result.at,originals:Object.fromEntries(Object.entries(result.originals).map(([role,item])=>[role,{raw:Buffer.from(item.raw).toString('base64'),ref:item.ref,payload:item.payload}])),
    frozen:Object.isFrozen(result)&&Object.isFrozen(result.originals)&&Object.values(result.originals).every(item=>Object.isFrozen(item)&&Object.isFrozen(item.payload)),
    immutable,retryCode,work:budget.snapshot(),nativeChecks:nativeChecks-start,callbacks});
}catch(e){results.push({ok:false,code:e.code??'untyped_error',detail:e.code?undefined:String(e.stack),work:budget?.snapshot(),nativeChecks:nativeChecks-start,callbacks});}}
process.stdout.write(JSON.stringify({results,subprocessCalls}));
"""


class OpenRepairBoundTypeScriptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ts_runtime.TypeScriptAgentNetworkTests.setUpClass.__func__(cls)
        (cls.fixture/'driver.mjs').write_text(DRIVER)

    def setUp(self):
        self.f=ack_bound_fixture()

    def call(self,changes=None,signers=None,*,offer=True,expected=None,policy=None,limits=None,**extra):
        entries=rebuild_bound_fixture(self.f,changes,signers)
        e=self.f['expected']|(expected or {})
        names=dict(expected_ack_slot='expectedAckSlot',expected_owner='expectedOwner',expected_receipt_writer='expectedReceiptWriter',
            expected_message_id='expectedMessageId',expected_envelope_ref='expectedEnvelopeRef',at='at')
        return dict(entries={role:encoded(item) for role,item in entries.items()},offer=offer,
            options={names[name]:copy.deepcopy(value) for name,value in e.items()},policy=POLICY|(policy or {}),limits=self.f['limit_policy'] if limits is None else limits,**extra)

    def py(self,call):
        entries={role:dict(raw=base64.b64decode(item['raw']),ref=item['ref']) for role,item in call['entries'].items()}
        names=dict(expectedAckSlot='expected_ack_slot',expectedOwner='expected_owner',expectedReceiptWriter='expected_receipt_writer',
            expectedMessageId='expected_message_id',expectedEnvelopeRef='expected_envelope_ref',at='at')
        policy=wire.RepairPolicy(**call['policy']);meter=wire.RepairBudget(policy)
        options={names[name]:value for name,value in call['options'].items()}|dict(policy=policy,budget=meter)
        try:
            if call['offer']:
                result=bound.verify_ack_offer_bootstrap_original(entries['bootstrap'],{role:entries[role] for role in ('root','write')},limit_policy=call['limits'],**options)
            else:
                result=bound.verify_ack_write_grant_original(entries['write'],entries['root'],**options)
            return dict(ok=True,at=result.at,work=meter.snapshot())
        except wire.RepairWireError as error:
            return dict(ok=False,code=error.code,work=meter.snapshot())

    def ts(self,calls):
        process=subprocess.run([self.node,'--experimental-strip-types',str(self.fixture/'driver.mjs')],cwd=self.fixture,
            input=json.dumps(calls).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=35)
        self.assertEqual(process.returncode,0,process.stderr.decode(errors='replace')[-4000:])
        result=json.loads(process.stdout);self.assertEqual(result['subprocessCalls'],0)
        return result['results']

    def parity(self,calls):
        actual=self.ts(calls)
        for call,result in zip(calls,actual):
            expected=self.py(call)
            with self.subTest(offer=call['offer'],code=expected.get('code')):
                self.assertEqual(result['ok'],expected['ok'],result)
                if not expected['ok']:
                    self.assertEqual(result['code'],expected['code'],result)
                self.assertEqual(result['work']['signature_checks'],expected['work']['signature_checks'])
                self.assertEqual(result['nativeChecks'],result['work']['signature_checks'])
                self.assertEqual(result['work']['hashes'],expected['work']['hashes'])
        return actual

    def test_two_three_real_native_signatures_preserve_opaque_originals_and_shared_budget(self):
        calls=[self.call(offer=offer,policy=dict(max_signature_checks=count)) for offer,count in ((False,2),(True,3))]
        results=self.parity(calls)
        for call,result,count in zip(calls,results,(2,3)):
            self.assertTrue(result['ok'],result);self.assertTrue(result['frozen'])
            self.assertEqual(result['nativeChecks'],count)
            for role,item in result['originals'].items():
                self.assertEqual(item['raw'],call['entries'][role]['raw'])
                self.assertEqual(item['ref'],call['entries'][role]['ref'])
                self.assertNotEqual(item['ref']['key'],item['ref']['raw_sha256'])
            call['repeat']=True
        for result,count in zip(self.ts(calls),(2,3)):
            self.assertTrue(result['ok'],result);self.assertEqual(result['retryCode'],'repair_over_budget')
            self.assertEqual(result['nativeChecks'],count)

    def test_expected_dual_keys_and_selected_grant_are_independent(self):
        other=ack_bound_fixture();calls=[]
        for name in ('expected_owner','expected_receipt_writer','expected_ack_slot'):
            calls.append(self.call(expected={name:other['expected'][name]}))
        for part in ('signing_key','encryption_key'):
            wrong=copy.deepcopy(self.f['expected']['expected_receipt_writer']);wrong[part]=other['expected']['expected_receipt_writer'][part]
            calls.append(self.call(expected=dict(expected_receipt_writer=wrong)))
            wrong=copy.deepcopy(self.f['expected']['expected_receipt_writer']);wrong[part]['public_key']=other['expected']['expected_receipt_writer'][part]['public_key']
            calls.append(self.call(expected=dict(expected_receipt_writer=wrong)))
        calls.append(self.call({'write':{'grant_id':'unselected_ack_grant'}}))
        for role in ('root','write','bootstrap'):
            calls.append(self.call(signers={role:self.f['signers']['writer']}))
        self.assertTrue(all(not result['ok'] for result in self.parity(calls)))

    def test_message_envelope_all_ref_fields_and_parent_selectors_are_exact(self):
        calls=[self.call({'write':{'message_id':'msg_'+'ac'*32}})]
        envelope=self.f['expected']['expected_envelope_ref']
        for name,value in (('namespace','meta'),('key','ad'*32),('raw_sha256','ae'*32),('size',envelope['size']+1)):
            calls.append(self.call({'write':{'envelope_ref':envelope|{name:value}}}))
        for role,field,parent in (('write','root_authority_ref','root'),('bootstrap','parent_authority_ref','root'),('bootstrap','caller_authority_ref','write')):
            for name,value in (('key','0'*64),('raw_sha256','0'*64),('size',1)):
                calls.append(self.call({role:{field:self.f['entries'][parent]['ref']|{name:value}}}))
        selector=json.loads(self.f['entries']['bootstrap']['raw'])['payload']['selector']
        for name in selector:
            calls.append(self.call({'bootstrap':{'selector':selector|{name:'0'*64}}}))
        self.assertTrue(all(not result['ok'] for result in self.parity(calls)))
        # Metadata E locators are legal only when independently selected, too.
        meta=envelope|dict(namespace='meta')
        self.assertTrue(self.parity([self.call({'write':{'envelope_ref':meta}},expected=dict(expected_envelope_ref=meta))])[0]['ok'])

    def test_ack_only_authority_bits_and_offer_upload_roles(self):
        calls=[]
        for offer,masks in ((False,(0,1,2,8,10)),(True,(1,3,9,10,11))):
            calls.extend(self.call({'root':{'operation_mask':mask}},offer=offer) for mask in masks)
        for removed in ('bootstrap.grant','ack_offer_service_v1','ack.write_grant'):
            calls.append(self.call({'root':{'allowed_roles':[role for role in self.f['payloads']['root']['allowed_roles'] if role!=removed]}}))
        for roles in (['ack.read_grant'],['bootstrap.grant','ack.write_grant'],['bootstrap.grant','bootstrap.grant'],['ack.put'],[]):
            calls.append(self.call({'bootstrap':{'upload_roles':roles}}))
        for changes in ({'operation':'message.send'},{'max_receipts':2},{'max_receipts':True},{'operation_mask':127}):
            calls.append(self.call({'write':changes}))
        for changes in ({'consumer':'ack_owner'},{'response_profile':'ack_owner_service_v1'},{'probe_profile':'full_originals'}):
            calls.append(self.call({'bootstrap':changes}))
        self.parity(calls)

    def test_closed_integer_lifetime_window_and_parent_budget_narrowing(self):
        calls=[]
        for role in ('root','write','bootstrap'):
            calls.append(self.call({role:{'revision':True}}))
        for at in (2_000_000_001,2_000_000_006,2_000_000_900):
            calls.append(self.call(expected=dict(at=at)))
        calls.append(self.call({role:{'issued_at':2_000_000_007,'revision':0} for role in ('root','write','bootstrap')}))
        for changes in ({'write':{'issued_at':2_000_000_001}},{'bootstrap':{'issued_at':2_000_000_005}},
                        {'write':{'issued_at':2_000_000_008}},{'bootstrap':{'expires_at':2_000_002_001}}):
            calls.append(self.call(changes))
        write=self.f['payloads']['write'];root=self.f['payloads']['root']
        for name,amount in write['budget'].items():
            calls.append(self.call({'write':{'budget':write['budget']|{name:amount+1}}}))
        for role,field in (('root','read_until'),('write','admit_until')):
            changes={role:{'windows':self.f['payloads'][role]['windows']|{field:2_000_000_700}}}
            if role=='root':changes['write']={'windows':write['windows']|{field:2_000_000_700}}
            calls.append(self.call(changes))
        calls.append(self.call({'write':{'windows':write['windows']|{'read_until':2_000_000_008}}}))
        calls.append(self.call({'bootstrap':{name:2_000_000_008 for name in ('probe_until','proof_until','upload_until')}},expected=dict(at=2_000_000_009)))
        self.parity(calls)

    def test_all_nine_limits_have_positive_local_and_both_parent_caps(self):
        calls=[]
        for name in LIMITS:
            calls.append(self.call({'bootstrap':{'limits':LIMITS|{name:0}}}))
            calls.append(self.call(limits=LIMITS|{name:LIMITS[name]-1}))
            calls.append(self.call(limits=LIMITS|{name:True}))
        for name in ('max_meta_bytes','max_job_bytes','max_items','max_requests','max_pending','max_replay_records','max_jobs'):
            for role in ('root','write'):
                calls.append(self.call({role:{'budget':self.f['payloads'][role]['budget']|{name:0}}}))
        calls.extend([self.call(limits=LIMITS|{'infinity':1}),self.call({'bootstrap':{'limits':{name:1 for name in LIMITS}}},limits={name:1 for name in LIMITS})])
        null=self.call();null['limits']=None;calls.append(null)
        self.parity(calls)

    def test_bad_signature_hash_size_canonical_wire_and_shared_work_limits(self):
        calls=[]
        for role in ('root','write','bootstrap'):
            call=self.call();entry=call['entries'][role];signed=json.loads(base64.b64decode(entry['raw']))
            signed['proof']['signature']=base64.b64encode(b'\0'*64).decode();raw=canonical_bytes(signed)
            entry.update(raw=base64.b64encode(raw).decode());entry['ref'].update(size=len(raw),raw_sha256=hashlib.sha256(raw).hexdigest());calls.append(call)
        for field,value in (('size',1),('raw_sha256','0'*64)):
            call=self.call();call['entries']['write']['ref'][field]=value;calls.append(call)
        call=self.call();entry=call['entries']['write'];entry['raw']=base64.b64encode(b' '+base64.b64decode(entry['raw'])).decode();calls.append(call)
        calls.extend(self.call(policy={name:1}) for name in ('max_nodes','max_hashes','max_total_bytes','max_signature_checks'))
        self.parity(calls)

    def test_bounded_snapshot_immutable_outputs_and_no_host_callbacks(self):
        result=self.ts([self.call(mutate=True)])[0]
        self.assertTrue(result['ok'],result);self.assertTrue(result['immutable']);self.assertTrue(result['frozen'])
        for result in self.ts([self.call(host=kind) for kind in ('options','proxy','entry')]):
            self.assertFalse(result['ok']);self.assertEqual(result['callbacks'],0)
            self.assertIn(result['code'],('repair_invalid_ack_bound','repair_invalid_json'))


if __name__=='__main__':
    unittest.main()
