"""Native ACK owner bootstrap original authentication, never live permission."""
import base64
import copy
import hashlib
import json
import subprocess
import unittest

from memory_vault import canonical_bytes
from tests import test_network_typescript_agent_network as ts_runtime
from tests.open_repair_resource_fixtures import ack_resource_fixture
import memory_vault_open_repair_wire as wire

POLICY=dict(max_document_bytes=65536,max_total_bytes=4194304,max_nodes=200000,max_depth=100,
            max_string_bytes=65536,max_hash_bytes=4194304,max_hashes=1000,max_entries=1000,
            max_retained_bytes=4194304,max_signature_checks=100)
LIMITS=dict(max_probe_bytes=512,max_proof_bytes=4096,max_proof_items=4,max_signature_checks=16,
            max_requests=16,max_pending=2,max_replay_records=16,max_concurrent_handles=2,max_candidate_attempts=2)
DRIVER=r"""
import * as b from './open-repair-bootstrap.ts';
import * as w from './open-repair-wire.ts';
const chunks=[];for await(const chunk of process.stdin)chunks.push(chunk);
const calls=JSON.parse(Buffer.concat(chunks).toString('utf8')),results=[];
for(const c of calls){let budget;try{
  budget=new w.RepairBudget(c.policy);const options={...c.options,policy:c.policy,budget};
  const decode=x=>({raw:Buffer.from(x.raw,'base64'),ref:x.ref});
  const entry=decode(c.entry),parents=Object.fromEntries(Object.entries(c.parents).map(([name,value])=>[name,decode(value)]));
  if(c.op==='hostile'){
    let traps=0;let code;const slot=new Proxy(options.expectedAckSlot,{ownKeys(){traps++;throw Error('trap');}});
    try{b.verifyAckOwnerBootstrapOriginal(entry,parents,{...options,expectedAckSlot:slot});}catch(e){code=e.code??'untyped_error';}
    const bad={...options};Object.defineProperty(bad,'limitPolicy',{enumerable:true,get(){traps++;throw Error('trap');}});
    let getterCode;try{b.verifyAckOwnerBootstrapOriginal(entry,parents,bad);}catch(e){getterCode=e.code??'untyped_error';}
    results.push({ok:true,result:{traps,code,getterCode},work:budget.snapshot()});continue;
  }
  const value=b.verifyAckOwnerBootstrapOriginal(entry,parents,options);
  let immutable=true;
  if(c.mutate){entry.raw.fill(0);parents.root.raw.fill(0);options.expectedAckSlot.slot_id='changed';const raw=value.originals.bootstrap.raw;raw.fill(0);immutable=value.originals.bootstrap.raw[0]===123&&value.originals.root.payload.ack_slot.slot_id!=='changed';}
  results.push({ok:true,result:{at:value.at,refs:Object.fromEntries(Object.entries(value.originals).map(([name,original])=>[name,original.ref])),immutable,frozen:Object.isFrozen(value)&&Object.isFrozen(value.originals)&&Object.values(value.originals).every(Object.isFrozen)},work:budget.snapshot()});
}catch(e){results.push({ok:false,code:e.code??'untyped_error',work:budget?.snapshot()});}}
process.stdout.write(JSON.stringify(results));
"""


class OpenRepairBootstrapTypeScriptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ts_runtime.TypeScriptAgentNetworkTests.setUpClass.__func__(cls)
        (cls.fixture/'driver.mjs').write_text(DRIVER)

    def setUp(self):
        docs,entries,expected,signers=ack_resource_fixture()
        self.signer=signers['owner'];self.expected=expected
        self.payloads={name:copy.deepcopy(docs[name]['payload']) for name in ('root','read')}
        for payload in self.payloads.values():payload['budget']['max_items']=16
        root=self.payloads['root'];root['allowed_roles']=sorted(set(root['allowed_roles'])|{'ack_owner_service_v1','bootstrap.grant','ack.write_grant'})
        now=root['issued_at']-2;self.at=now+5
        self.payloads['bootstrap']=dict(schema_version='memory-vault-open-repair/v1',kind='bootstrap.grant',signing_key=self.signer.public_descriptor(),
            issued_at=now+4,expires_at=now+120,grant_id='synthetic_bootstrap',revision=1,owner=root['owner'],subject=root['owner'],
            root_key=expected['expected_ack_slot']['root_key'],consumer='ack_owner',selector={},parent_authority_ref={},caller_authority_ref={},
            probe_until=now+100,proof_until=now+100,upload_until=now+100,probe_profile='opaque_v1',response_profile='ack_owner_service_v1',
            upload_roles=['ack.read_grant','ack.root_authority','ack.write_grant','bootstrap.grant'],limits=LIMITS)
        self.entries=self.rebuilt({})

    def rebuilt(self,changes):
        payloads=copy.deepcopy(self.payloads);entries={}
        for role in ('root','read','bootstrap'):
            payload=payloads[role]
            if role=='read':payload['root_authority_ref']=entries['root']['ref']
            elif role=='bootstrap':
                payload['parent_authority_ref']=entries['root']['ref'];payload['caller_authority_ref']=entries['read']['ref']
                payload['selector']=dict(root_key_sha256=hashlib.sha256(canonical_bytes(payload['root_key'])).hexdigest(),
                    ack_slot_sha256=hashlib.sha256(canonical_bytes(self.expected['expected_ack_slot'])).hexdigest(),
                    root_authority_sha256=entries['root']['ref']['raw_sha256'],read_grant_sha256=entries['read']['ref']['raw_sha256'])
            payload.update(changes.get(role,{}))
            raw=canonical_bytes(dict(payload=payload,proof=self.signer.sign_message(payload)))
            entries[role]=dict(raw=raw,ref=dict(namespace='meta',key=hashlib.sha256(('locator:'+role).encode()).hexdigest(),
                raw_sha256=hashlib.sha256(raw).hexdigest(),size=len(raw)))
        return entries

    def call(self,entries=None,options=None,policy=None,**extra):
        entries=entries or self.entries
        def encoded(item):return dict(raw=base64.b64encode(item['raw']).decode(),ref=item['ref'])
        expected=dict(expectedAckSlot=self.expected['expected_ack_slot'],expectedOwner=self.expected['expected_owner'],at=self.at,limitPolicy=LIMITS)
        expected.update(options or {})
        return dict(entry=encoded(entries['bootstrap']),parents={name:encoded(entries[name]) for name in ('root','read')},
                    options=expected,policy=policy or POLICY,**extra)

    def ts(self,calls):
        run=subprocess.run([self.node,'--experimental-strip-types',str(self.fixture/'driver.mjs')],cwd=self.fixture,
            input=json.dumps(calls).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
        self.assertEqual(run.returncode,0,run.stderr.decode(errors='replace')[-5000:]);return json.loads(run.stdout)

    def py(self,entries=None,**options):
        import memory_vault_open_repair_bootstrap as bootstrap
        entries=entries or self.entries;policy=wire.RepairPolicy(**POLICY);budget=wire.RepairBudget(policy)
        args=dict(expected_ack_slot=self.expected['expected_ack_slot'],expected_owner=self.expected['expected_owner'],at=self.at,limit_policy=LIMITS)
        args.update(options)
        result=bootstrap.verify_ack_owner_bootstrap_original(entries['bootstrap'],{name:entries[name] for name in ('root','read')},policy=policy,budget=budget,**args)
        return result,budget.snapshot()

    def test_three_actual_signatures_selector_hashes_and_input_snapshots(self):
        result=self.ts([self.call(mutate=True)])[0];self.assertTrue(result['ok'],result)
        value,work=self.py();self.assertEqual(result['result']['at'],value.at)
        self.assertEqual(result['work']['signature_checks'],3);self.assertEqual(result['work']['hashes'],13)
        self.assertEqual(result['work']['hash_bytes'],work['hash_bytes'])
        self.assertEqual(result['result']['refs'],{name:item['ref'] for name,item in self.entries.items()})
        self.assertTrue(result['result']['immutable']);self.assertTrue(result['result']['frozen'])

    def test_canonical_q_full_refs_and_closed_shapes(self):
        spaced=copy.deepcopy(self.entries);item=spaced['bootstrap'];item['raw']=b' '+item['raw'];item['ref'].update(size=len(item['raw']),raw_sha256=hashlib.sha256(item['raw']).hexdigest())
        wrong=copy.deepcopy(self.entries);wrong['read']['ref']['raw_sha256']='0'*64
        extra=self.rebuilt({'bootstrap':{'future_write_grant_ref':self.entries['read']['ref']}})
        result=self.ts([self.call(entries) for entries in (spaced,wrong,extra)])
        self.assertEqual([x['code'] for x in result],['repair_noncanonical_json','repair_ref_mismatch','repair_invalid_bootstrap'])

    def test_selector_cannot_use_locator_key_or_another_preheld_scope(self):
        selector=json.loads(self.entries['bootstrap']['raw'])['payload']['selector']
        bad=self.rebuilt({'bootstrap':{'selector':{**selector,'root_authority_sha256':self.entries['root']['ref']['key']}}})
        slot={**self.expected['expected_ack_slot'],'slot_id':'other_slot'}
        result=self.ts([self.call(bad),self.call(options=dict(expectedAckSlot=slot))])
        self.assertEqual([x['code'] for x in result],['repair_bootstrap_mismatch']*2)

    def test_profile_consumer_subject_and_parent_permissions_are_exact(self):
        other=ack_resource_fixture()[2]['expected_ack_slot']['root_key']['owner']
        changes=[{'bootstrap':{'consumer':'ack_offer'}},{'bootstrap':{'response_profile':'ack_offer_service_v1'}},
                 {'bootstrap':{'subject':other}},{'root':{'operation_mask':2}},
                 {'read':{'operation_mask':8}},{'root':{'allowed_roles':['ack.read_grant','ack.root_authority']}}]
        results=self.ts([self.call(self.rebuilt(change)) for change in changes])
        self.assertTrue(all(not x['ok'] and x['code'] in ('repair_invalid_bootstrap','repair_bootstrap_mismatch') for x in results),results)

    def test_phase_deadlines_are_bounded_but_not_all_required_after_event(self):
        at=self.at;issued=self.payloads['bootstrap']['issued_at']
        accepted=self.rebuilt({'bootstrap':{'probe_until':at,'proof_until':at,'upload_until':at}})
        result=self.ts([self.call(accepted)])[0];self.assertTrue(result['ok'],result);self.py(accepted)
        cases=[{'bootstrap':{'probe_until':issued}},{'bootstrap':{'proof_until':self.payloads['bootstrap']['expires_at']+1}},
               {'bootstrap':{'upload_until':self.payloads['bootstrap']['expires_at']+1}},
               {'bootstrap':{'issued_at':at+1}},{'bootstrap':{'expires_at':at}}]
        results=self.ts([self.call(self.rebuilt(change)) for change in cases])
        self.assertTrue(all(not x['ok'] for x in results),results)

    def test_read_window_intersects_proof_and_upload_and_expiry_causality(self):
        now=self.at-5
        windows={name:now+30 for name in self.payloads['read']['windows']}
        cases=[{'read':{'windows':windows}}, {'read':{'issued_at':self.payloads['bootstrap']['issued_at']+1}},
               {'root':{'expires_at':self.payloads['read']['expires_at']-1}}]
        results=self.ts([self.call(self.rebuilt(change)) for change in cases])
        self.assertTrue(all(not x['ok'] for x in results),results)

    def test_all_nine_grant_limits_are_positive_and_bounded_by_independent_policy(self):
        calls=[]
        for name in LIMITS:
            calls.append(self.call(self.rebuilt({'bootstrap':{'limits':{**LIMITS,name:0}}})))
            calls.append(self.call(options=dict(limitPolicy={**LIMITS,name:LIMITS[name]-1})))
        result=self.ts(calls)
        self.assertTrue(all(not x['ok'] for x in result),result)
        missing={k:v for k,v in LIMITS.items() if k!='max_signature_checks'}
        self.assertEqual(self.ts([self.call(options=dict(limitPolicy=missing))])[0]['code'],'repair_invalid_bootstrap')

    def test_each_parent_budget_cap_can_narrow_bootstrap_limits(self):
        parent_caps={'max_meta_bytes':1,'max_job_bytes':1,'max_items':1,'max_requests':1,'max_pending':1,'max_replay_records':1,'max_jobs':1}
        cases=[self.rebuilt({'read':{'budget':{**self.payloads['read']['budget'],name:value}}}) for name,value in parent_caps.items()]
        result=self.ts([self.call(entries) for entries in cases]);self.assertTrue(all(x['code']=='repair_bootstrap_mismatch' for x in result),result)

    def test_upload_roles_are_ordered_branch_subset_and_no_future_binding(self):
        changes=[{'upload_roles':['ack.root_authority','ack.read_grant']},{'upload_roles':['bootstrap.grant','bootstrap.grant']},
                 {'upload_roles':['contact.request']},{'upload_roles':[]}]
        result=self.ts([self.call(self.rebuilt({'bootstrap':change})) for change in changes])
        self.assertTrue(all(x['code']=='repair_invalid_bootstrap' for x in result[:3]),result)
        self.assertTrue(result[3]['ok'],result[3])
        narrowed=[name for name in self.payloads['root']['allowed_roles'] if name!='ack.write_grant']
        refused=self.ts([self.call(self.rebuilt({'root':{'allowed_roles':narrowed}}))])[0]
        self.assertEqual(refused['code'],'repair_bootstrap_mismatch')

    def test_failed_signature_and_shared_signature_cap_do_not_refund_work(self):
        entries=copy.deepcopy(self.entries);doc=json.loads(entries['bootstrap']['raw']);doc['proof']['signature']=base64.b64encode(b'\0'*64).decode()
        raw=canonical_bytes(doc);entries['bootstrap']['raw']=raw;entries['bootstrap']['ref'].update(size=len(raw),raw_sha256=hashlib.sha256(raw).hexdigest())
        bad,limited=self.ts([self.call(entries),self.call(policy={**POLICY,'max_signature_checks':2})])
        self.assertEqual(bad['code'],'repair_invalid_signature');self.assertEqual(bad['work']['signature_checks'],3)
        self.assertEqual(limited['code'],'repair_over_budget');self.assertEqual(limited['work']['signature_checks'],2)

    def test_expected_host_objects_are_bounded_without_getter_or_proxy_execution(self):
        result=self.ts([self.call(op='hostile')])[0];self.assertEqual(result['result'],dict(traps=0,code='repair_invalid_json',getterCode='repair_invalid_bootstrap'))
        self.assertEqual(result['work']['signature_checks'],0)

    def test_malformed_parent_window_types_fail_before_comparison_or_signature(self):
        changes=[{'root':{'windows':{**self.payloads['root']['windows'],'retain_until':{}}}},
                 {'read':{'windows':{**self.payloads['read']['windows'],'read_until':[]}}}]
        results=self.ts([self.call(self.rebuilt(change)) for change in changes])
        self.assertEqual([item['code'] for item in results],['repair_invalid_bootstrap']*2)
        self.assertEqual([item['work']['signature_checks'] for item in results],[0,1])
