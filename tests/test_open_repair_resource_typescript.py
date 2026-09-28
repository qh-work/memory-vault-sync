"""Native six-original ACK resource authentication over fresh synthetic proofs."""
import base64
import copy
import hashlib
import json
import subprocess
import unittest

from memory_vault import canonical_bytes
from tests import test_network_typescript_agent_network as ts_runtime
from tests.open_repair_resource_fixtures import ack_resource_fixture, ROLES
import memory_vault_open_repair_wire as wire
import memory_vault_open_repair_resource as resource

POLICY=dict(max_document_bytes=65536,max_total_bytes=4194304,max_nodes=200000,max_depth=100,
            max_string_bytes=65536,max_hash_bytes=4194304,max_hashes=1000,max_entries=1000,
            max_retained_bytes=4194304,max_signature_checks=100)
DRIVER=r"""
import * as r from './open-repair-resource.ts';
import * as w from './open-repair-wire.ts';
const chunks=[];for await(const chunk of process.stdin)chunks.push(chunk);
const calls=JSON.parse(Buffer.concat(chunks).toString('utf8')),results=[];
for(const c of calls){let budget;try{
  budget=new w.RepairBudget(c.policy);const options={...c.options,policy:c.policy,budget};
  const entries=Object.fromEntries(Object.entries(c.entries).map(([role,item])=>[role,{raw:Buffer.from(item.raw,'base64'),ref:item.ref}]));
  if(c.op==='hostile'){
    let traps=0;const expected=new Proxy(c.options.expectedOwner,{ownKeys(){traps++;throw Error('unexpected trap');}});
    let code;try{r.verifyAckResourceInputs(entries,{...options,expectedOwner:expected});}catch(e){code=e.code??'untyped_error';}
    let getterCode;const hostile={...options};Object.defineProperty(hostile,'expectedAckSlot',{enumerable:true,get(){traps++;throw Error('unexpected getter');}});
    try{r.verifyAckResourceInputs(entries,hostile);}catch(e){getterCode=e.code??'untyped_error';}
    results.push({ok:true,result:{traps,code,getterCode},work:budget.snapshot()});continue;
  }
  const value=r.verifyAckResourceInputs(entries,options);
  let immutable=true;
  if(c.mutate){
    for(const entry of Object.values(entries))entry.raw.fill(0);
    c.options.expectedAckSlot.slot_id='changed';
    const exposed=value.originals.root.raw;exposed.fill(0);
    immutable=value.originals.root.payload.ack_slot.slot_id!=='changed'&&value.originals.root.raw[0]===123;
  }
  results.push({ok:true,result:{activated_at:value.activated_at,refs:Object.fromEntries(Object.entries(value.originals).map(([role,item])=>[role,item.ref])),immutable,frozen:Object.isFrozen(value)&&Object.isFrozen(value.originals)&&Object.values(value.originals).every(Object.isFrozen)},work:budget.snapshot()});
}catch(e){results.push({ok:false,code:e.code??'untyped_error',work:budget?.snapshot()});}}
process.stdout.write(JSON.stringify(results));
"""


class OpenRepairResourceTypeScriptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ts_runtime.TypeScriptAgentNetworkTests.setUpClass.__func__(cls)
        (cls.fixture/'driver.mjs').write_text(DRIVER)

    def setUp(self):
        self.docs,self.entries,self.expected,self.signers=ack_resource_fixture()

    def ts(self,calls):
        run=subprocess.run([self.node,'--experimental-strip-types',str(self.fixture/'driver.mjs')],cwd=self.fixture,
            input=json.dumps(calls).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
        self.assertEqual(run.returncode,0,run.stderr.decode(errors='replace')[-5000:]);return json.loads(run.stdout)

    def call(self,entries=None,expected=None,policy=None,**extra):
        expected=expected or self.expected
        options={''.join([parts[0]]+[part.title() for part in parts[1:]]):value
                 for name,value in expected.items() for parts in [name.split('_')]}
        return dict(entries={role:dict(raw=base64.b64encode(item['raw']).decode(),ref=item['ref'])
                            for role,item in (entries or self.entries).items()},options=options,policy=policy or POLICY,**extra)

    def py(self,entries=None,expected=None,policy=None):
        policy=wire.RepairPolicy(**(policy or POLICY));budget=wire.RepairBudget(policy)
        result=resource.verify_ack_resource_inputs(entries or self.entries,**(expected or self.expected),policy=policy,budget=budget)
        return result,budget.snapshot()

    def rebuilt(self,changes):
        """Re-sign the full real DAG so failures cannot hide behind stale hashes."""
        docs=copy.deepcopy(self.docs)
        for role,updates in changes.items():docs[role]['payload'].update(updates)
        refs={};entries={}
        for role in ROLES:
            payload=docs[role]['payload']
            if role=='offer':payload['allocation_request_ref']=refs['allocate']
            elif role=='root':payload['original_resource_offer_ref']=refs['offer']
            elif role=='read':payload['root_authority_ref']=refs['root']
            elif role=='activation':
                payload['scope']['root_authority_ref']=refs['root'];payload['resource_offer_refs']=[refs['offer']]
                payload['authority_refs']=[dict(role='ack.read_grant',ref=refs['read']),dict(role='ack.root_authority',ref=refs['root'])]
            elif role=='active':payload['offer_ref']=refs['offer'];payload['activation_ref']=refs['activation']
            if role in ('allocate','offer'):payload['intent_sha256']=hashlib.sha256(canonical_bytes(payload['intent'])).hexdigest()
            signer=self.signers['target' if role in ('offer','active') else 'owner']
            signed=dict(payload=payload,proof=signer.sign_message(payload));raw=canonical_bytes(signed)
            ref={**self.entries[role]['ref'],'raw_sha256':hashlib.sha256(raw).hexdigest(),'size':len(raw)}
            refs[role]=ref;entries[role]=dict(raw=raw,ref=ref)
        return entries

    def test_six_real_proofs_hashes_and_original_refs_match_python(self):
        result=self.ts([self.call(mutate=True)])[0];self.assertTrue(result['ok'],result)
        value,work=self.py()
        self.assertEqual(result['result']['activated_at'],value.activated_at)
        self.assertEqual(result['work']['signature_checks'],6)
        self.assertEqual(result['work']['hashes'],24)
        self.assertEqual(result['work']['hash_bytes'],work['hash_bytes'])
        self.assertEqual(result['result']['refs'],{role:item['ref'] for role,item in self.entries.items()})
        self.assertTrue(result['result']['immutable']);self.assertTrue(result['result']['frozen'])
        self.assertTrue(all(item['ref']['key']!=item['ref']['raw_sha256'] for item in self.entries.values()))

    def test_canonical_q_and_full_raw_reference_are_mandatory(self):
        spaced=copy.deepcopy(self.entries);spaced['active']['raw']=b' '+spaced['active']['raw']
        spaced['active']['ref'].update(size=len(spaced['active']['raw']),raw_sha256=hashlib.sha256(spaced['active']['raw']).hexdigest())
        wrong=copy.deepcopy(self.entries);wrong['root']['ref']['raw_sha256']='0'*64
        missing=copy.deepcopy(self.entries);del missing['offer']
        extra=copy.deepcopy(self.entries);extra['other']=extra['offer']
        results=self.ts([self.call(entries) for entries in (spaced,wrong,missing,extra)])
        self.assertEqual([x['code'] for x in results],['repair_noncanonical_json','repair_ref_mismatch','repair_invalid_resource','repair_invalid_resource'])

    def test_q_closed_shapes_do_not_inherit_legacy_time_or_alias_fields(self):
        cases=[self.rebuilt({'active':{'issued_at':2_000_000_000,'expires_at':2_000_000_999}}),
               self.rebuilt({'offer':{'expires_at':2_000_000_999}}),
               self.rebuilt({'activation':{'scope':{'kind':'ack_empty','ack_slot':self.expected['expected_ack_slot'],'root_authority_ref':self.entries['root']['ref']}}})]
        results=self.ts([self.call(entries) for entries in cases])
        self.assertTrue(all(x['code']=='repair_invalid_resource' for x in results),results)
        self.assertEqual(results[0]['work']['signature_checks'],5)
        self.assertEqual(results[1]['work']['signature_checks'],1)

    def test_independent_expected_owner_target_slot_and_epoch_reject_substitution(self):
        other_docs,_,other,_=ack_resource_fixture()
        changes=[dict(expected_owner=other['expected_owner']),dict(expected_target=other['expected_target']),
                 dict(expected_ack_slot=other['expected_ack_slot']),dict(target_storage_epoch='wrong_epoch')]
        results=self.ts([self.call(expected={**self.expected,**change}) for change in changes])
        self.assertTrue(all(not x['ok'] for x in results),results)
        self.assertTrue(all(x['code'] in ('repair_wrong_issuer','repair_resource_mismatch') for x in results),results)

    def test_temporal_causality_and_expiry_refuse_even_with_all_references_resigned(self):
        now=self.docs['allocate']['payload']['issued_at']
        cases=[{'offer':{'issued_at':now+20}}, {'root':{'issued_at':now}},
               {'read':{'issued_at':now+1}}, {'activation':{'issued_at':now+2}},
               {'active':{'activated_at':now+3}}, {'active':{'activated_at':now+40}},
               {'activation':{'expires_at':now+5}}, {'read':{'expires_at':now+5}}]
        entries=[self.rebuilt(change) for change in cases]
        results=self.ts([self.call(value) for value in entries])
        for value,result in zip(entries,results):
            with self.subTest(change=result):
                self.assertEqual(result['code'],'repair_invalid_resource')
                with self.assertRaises(wire.RepairWireError):self.py(value)

    def test_offer_active_resource_budget_and_generation_are_exact(self):
        active=self.docs['active']['payload']
        cases=[{'active':{'reservation_generation':2}}, {'active':{'budget':{**active['budget'],'max_items':2}}},
               {'active':{'windows':{**active['windows'],'read_until':active['windows']['read_until']-1}}},
               {'active':{'resource':{**active['resource'],'resource_id':'wrong'}}}]
        results=self.ts([self.call(self.rebuilt(change)) for change in cases])
        self.assertTrue(all(x['code']=='repair_resource_mismatch' for x in results),results)

    def test_owner_windows_can_outlive_source_and_not_yet_permit_all_operations(self):
        now=self.docs['allocate']['payload']['issued_at']
        long_root=self.docs['root']['payload']['windows']['retain_until']
        self.assertGreater(long_root,self.docs['offer']['payload']['windows']['retain_until'])
        windows={**self.docs['allocate']['payload']['intent']['windows'],'admit_until':now+1}
        a={**self.docs['allocate']['payload']['intent'],'windows':windows}
        o={**self.docs['offer']['payload']['intent'],'windows':windows}
        entries=self.rebuilt({'allocate':{'intent':a},'offer':{'intent':o,'windows':windows},'active':{'windows':windows}})
        result=self.ts([self.call(entries)])[0];self.assertTrue(result['ok'],result)
        self.py(entries)

    def test_read_authority_subsets_and_known_role_names_are_enforced(self):
        root=self.docs['root']['payload'];read=self.docs['read']['payload']
        cases=[{'read':{'budget':{**read['budget'],'max_items':root['budget']['max_items']+1}}},
               {'read':{'windows':{**read['windows'],'retain_until':root['windows']['retain_until']+1}}},
               {'root':{'operation_mask':1}}, {'root':{'allowed_roles':['not.a.role']}},
               {'root':{'allowed_roles':['ack.read_grant','ack.read_grant']}}]
        results=self.ts([self.call(self.rebuilt(change)) for change in cases])
        self.assertTrue(all(not x['ok'] and x['code'] in ('repair_invalid_resource','repair_resource_mismatch') for x in results),results)

    def test_signature_budget_and_failed_real_proof_work_are_cumulative(self):
        bad=copy.deepcopy(self.entries);doc=copy.deepcopy(self.docs['active'])
        doc['proof']['signature']=base64.b64encode(b'\0'*64).decode();raw=canonical_bytes(doc)
        bad['active']=dict(raw=raw,ref={**bad['active']['ref'],'raw_sha256':hashlib.sha256(raw).hexdigest(),'size':len(raw)})
        failed,limited=self.ts([self.call(bad),self.call(policy={**POLICY,'max_signature_checks':5})])
        self.assertEqual(failed['code'],'repair_invalid_signature');self.assertEqual(failed['work']['signature_checks'],6)
        self.assertEqual(limited['code'],'repair_over_budget');self.assertEqual(limited['work']['signature_checks'],5)

    def test_hostile_expected_objects_never_invoke_getters_or_proxy_traps(self):
        result=self.ts([self.call(op='hostile')])[0];self.assertTrue(result['ok'],result)
        self.assertEqual(result['result'],dict(traps=0,code='repair_invalid_json',getterCode='repair_invalid_resource'))
        self.assertEqual(result['work']['signature_checks'],0)
