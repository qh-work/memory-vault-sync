"""Actual native inline proof containers and signed subject-bound ranges."""
import base64
import copy
import hashlib
import json
import subprocess
import unittest

from memory_vault import canonical_bytes
import memory_vault_open_repair_proof as proof
import memory_vault_open_repair_wire as wire
from tests import test_network_typescript_agent_network as ts_runtime
from tests import test_open_repair_proof as py_fixture
from tests.test_open_repair_probe_typescript import private_signing

POLICY=dict(max_document_bytes=524288,max_total_bytes=16000000,max_nodes=400000,max_depth=64,
    max_string_bytes=262144,max_hash_bytes=16000000,max_hashes=2000,max_entries=2000,max_retained_bytes=16000000,max_signature_checks=64)
DRIVER=r"""
import * as p from './open-repair-proof.ts';
import * as w from './open-repair-wire.ts';
const chunks=[];for await(const chunk of process.stdin)chunks.push(chunk);
const calls=JSON.parse(Buffer.concat(chunks).toString('utf8')),results=[];
const encode=x=>({raw:Buffer.from(x.raw).toString('base64'),ref:x.ref,payload:x.payload});
const decode=x=>({raw:Buffer.from(x.raw,'base64'),ref:x.ref});
for(const c of calls){let budget;try{
 budget=new w.RepairBudget(c.policy);const options={...c.options,policy:c.policy,budget};let result;
 if(c.op==='make'){
   const value=p.makeBootstrapProofResponse(c.signer,c.manifest,{...c.makeOptions,policy:c.policy,budget});result={raw:Buffer.from(value.raw).toString('base64')};
 }else{
   const inputRaw=Buffer.from(c.raw,'base64');let callbacks=0;
   if(c.rawGetter)Object.defineProperty(inputRaw,'length',{get(){callbacks++;throw Error('raw getter');}});
   const checked=p.verifyBootstrapProofResponse(inputRaw,options);
   if(c.op==='verify')result={manifest:checked.manifest.value,manifest_ref:checked.manifest_ref,handle:encode(checked.handle),callbacks,frozen:Object.isFrozen(checked)&&Object.isFrozen(checked.manifest.value)};
   else if(c.op==='child'){
     const child=p.makeBootstrapChildRequest(c.signer,checked,{...c.childOptions,policy:c.policy,budget});
     const verified=p.verifyBootstrapChildRequest({raw:child.raw,ref:child.ref},checked,{expectedSubject:c.childOptions.subject,expectedTarget:c.childOptions.target,
        at:c.childOptions.at,policy:c.policy,budget});result=encode(verified);
   }else if(c.op==='verify_child')result=encode(p.verifyBootstrapChildRequest(decode(c.child),checked,{...c.childOptions,policy:c.policy,budget}));
   else if(c.op==='fake'){
     let callbacks=0,codes=[];for(const value of [{...checked},new Proxy(checked,{get(){callbacks++;throw Error('proxy');}})]){
       try{p.makeBootstrapChildRequest(c.signer,value,{...c.childOptions,policy:c.policy,budget});codes.push(null);}catch(e){codes.push(e.code??'untyped_error');}}
     result={callbacks,codes};
   }
 }
 results.push({ok:true,result,work:budget.snapshot()});
 }catch(error){results.push({ok:false,code:error.code??'untyped_error',work:budget?.snapshot()});}}
process.stdout.write(JSON.stringify(results));
"""


class OpenRepairProofTypeScriptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ts_runtime.TypeScriptAgentNetworkTests.setUpClass.__func__(cls)
        (cls.fixture/'driver.mjs').write_text(DRIVER)

    def setUp(self):
        self.py=py_fixture.RepairProofTests();self.py.setUp();self.addCleanup(self.py.doCleanups)
        self.raw=self.py.response().raw

    def call(self,op='verify',**extra):
        h=self.py
        options=dict(expectedSubject=h.subject,expectedTarget=h.target,targetStorageEpoch=h.binding['target_storage_epoch'],
            selector=h.binding['selector'],bootstrapGrantRef=h.fixture['entries']['bootstrap']['ref'],at=h.now,
            probeRef=h.parents['probe_ref'],challengeRef=h.parents['challenge_ref'],answerRef=h.parents['answer_ref'],maxProofItems=64,maxProofBytes=131072)
        child_options=dict(subject=h.subject,target=h.target,at=h.now,expiresAt=h.now+20,childIndex=0,offset=0,requestedBytes=32)
        return dict(op=op,raw=base64.b64encode(self.raw).decode(),options=options,policy=POLICY,
            signer=private_signing(h.fixture['signers']['owner']),childOptions=child_options,**extra)

    def ts(self,calls):
        process=subprocess.run([self.node,'--experimental-strip-types',str(self.fixture/'driver.mjs')],cwd=self.fixture,
            input=json.dumps(calls).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
        self.assertEqual(process.returncode,0,process.stderr.decode(errors='replace')[-5000:]);return json.loads(process.stdout)

    def test_native_verifies_python_inline_handle_and_full_twenty_one_role_manifest(self):
        actual=self.ts([self.call()])[0];self.assertTrue(actual['ok'],actual)
        expected=self.py.verify(self.raw)
        self.assertEqual(actual['result']['manifest'],self.py.manifest)
        self.assertEqual(actual['result']['manifest_ref'],expected.manifest_ref.as_dict())
        self.assertEqual(actual['work']['signature_checks'],1);self.assertTrue(actual['result']['frozen'])

    def make_call(self,manifest=None):
        h=self.py;call=self.call('make',manifest=manifest or h.manifest,
            makeOptions=dict(probeRef=h.parents['probe_ref'],challengeRef=h.parents['challenge_ref'],answerRef=h.parents['answer_ref'],
                subject=h.subject,target=h.target,at=h.now,expiresAt=h.now+30,handleId='synthetic_native_handle'))
        call['signer']=private_signing(h.fixture['signers']['target']);return call

    def test_native_builder_emits_python_verifiable_response(self):
        actual=self.ts([self.make_call()])[0];self.assertTrue(actual['ok'],actual)
        expected=self.py.verify(base64.b64decode(actual['result']['raw']))
        self.assertEqual(expected.manifest.raw,canonical_bytes(self.py.manifest))
        self.assertEqual(expected.handle.payload['handle_id'],'synthetic_native_handle')
        self.assertEqual(actual['work']['signature_checks'],0)

    def test_signed_opaque_manifest_locator_is_preserved(self):
        wrapper=json.loads(self.raw);handle=json.loads(base64.urlsafe_b64decode(wrapper['handle_raw_base64url']+'==='))
        handle['payload']['manifest_ref']['key']='e'*64
        handle['proof']=self.py.fixture['signers']['target'].sign_message(handle['payload'])
        wrapper['handle_raw_base64url']=base64.urlsafe_b64encode(canonical_bytes(handle)).rstrip(b'=').decode()
        raw=canonical_bytes(wrapper);call=self.call();call['raw']=base64.b64encode(raw).decode()
        actual=self.ts([call])[0];self.assertTrue(actual['ok'],actual)
        self.assertEqual(actual['result']['manifest_ref']['key'],'e'*64)
        self.assertEqual(self.py.verify(raw).manifest_ref.key,'e'*64)

    def test_builder_rejects_missing_future_duplicate_or_non_content_addressed_pack_roles(self):
        calls=[]
        for change in ('missing','future','duplicate','pack'):
            m=copy.deepcopy(self.py.manifest)
            if change=='missing':m['children'].pop()
            elif change=='future':m['children'][0]['role']='recipient.receipt'
            elif change=='duplicate':m['children'][1]['role']=m['children'][0]['role']
            else:next(item for item in m['children'] if item['role']=='history.raw_pack')['ref']['key']='e'*64
            calls.append(self.make_call(m))
        for result in self.ts(calls):self.assertEqual(result['code'],'repair_invalid_proof')

    def test_encoded_plus_decoded_bytes_and_item_limits_reject_before_signature(self):
        calls=[]
        for name,value in (('maxProofBytes',len(self.raw)),('maxProofItems',20)):
            call=self.call();call['options'][name]=value;calls.append(call)
        actual=self.ts(calls)
        self.assertEqual(actual[0]['code'],'repair_proof_too_large');self.assertEqual(actual[0]['work']['signature_checks'],0)
        self.assertEqual(actual[1]['code'],'repair_invalid_proof')

    def test_native_signed_child_matches_python_and_excludes_unlisted_grant_field(self):
        actual=self.ts([self.call('child')])[0];self.assertTrue(actual['ok'],actual)
        checked=self.py.verify(self.raw);entry=dict(raw=base64.b64decode(actual['result']['raw']),ref=actual['result']['ref'])
        verified=proof.verify_bootstrap_child_request(entry,checked,expected_subject=self.py.subject,expected_target=self.py.target,
            at=self.py.now,policy=self.py.policy,budget=wire.RepairBudget(self.py.policy))
        self.assertEqual(verified.raw,entry['raw']);self.assertNotIn('bootstrap_grant_sha256',verified.payload)
        self.assertEqual(actual['work']['signature_checks'],2)

    def test_parent_subject_and_target_bindings_and_finite_ranges_are_enforced(self):
        calls=[]
        for change in ({'subject':self.py.target},{'target':self.py.subject},{'childIndex':99},{'offset':9007199254740991},{'requestedBytes':0},
                       {'expiresAt':self.py.now+31}):
            call=self.call('child');call['childOptions']={**call['childOptions'],**change};calls.append(call)
        actual=self.ts(calls)
        self.assertEqual([item['code'] for item in actual],['repair_proof_mismatch','repair_proof_mismatch','repair_invalid_range',
            'repair_invalid_range','repair_invalid_integer','repair_proof_mismatch'])

    def test_caller_forged_or_proxy_proof_result_is_not_an_authenticated_parent(self):
        actual=self.ts([self.call('fake')])[0];self.assertTrue(actual['ok'],actual)
        self.assertEqual(actual['result'],dict(callbacks=0,codes=['repair_invalid_proof','repair_invalid_proof']))

    def test_python_child_verifies_natively_and_signed_handle_substitution_refuses(self):
        checked=self.py.verify(self.raw)
        child=proof.make_bootstrap_child_request(self.py.fixture['signers']['owner'],checked,subject=self.py.subject,target=self.py.target,
            at=self.py.now,expires_at=self.py.now+20,child_index=0,offset=0,requested_bytes=32,
            policy=self.py.policy,budget=wire.RepairBudget(self.py.policy))
        call=self.call('verify_child',child=dict(raw=base64.b64encode(child.raw).decode(),ref=child.ref.as_dict()))
        call['childOptions']=dict(expectedSubject=self.py.subject,expectedTarget=self.py.target,at=self.py.now)
        bad=copy.deepcopy(call);document=json.loads(child.raw);document['payload']['handle_ref']['key']='e'*64
        document['proof']=self.py.fixture['signers']['owner'].sign_message(document['payload']);raw=canonical_bytes(document)
        bad['child']=dict(raw=base64.b64encode(raw).decode(),ref={**child.ref.as_dict(),'raw_sha256':hashlib.sha256(raw).hexdigest(),'size':len(raw)})
        actual=self.ts([call,bad]);self.assertTrue(actual[0]['ok'],actual[0]);self.assertEqual(actual[1]['code'],'repair_proof_mismatch')

    def test_inline_manifest_swap_and_actual_handle_signature_tampering_refuse(self):
        changed=copy.deepcopy(self.py.manifest);changed['service_generation']=2
        other=json.loads(self.py.response(changed).raw);wrapper=json.loads(self.raw)
        wrapper['manifest_raw_base64url']=other['manifest_raw_base64url']
        swapped=self.call();swapped['raw']=base64.b64encode(canonical_bytes(wrapper)).decode()
        wrapper=json.loads(self.raw);handle=json.loads(base64.urlsafe_b64decode(wrapper['handle_raw_base64url']+'==='))
        handle['proof']['signature']=base64.b64encode(bytes(64)).decode()
        wrapper['handle_raw_base64url']=base64.urlsafe_b64encode(canonical_bytes(handle)).rstrip(b'=').decode()
        damaged=self.call();damaged['raw']=base64.b64encode(canonical_bytes(wrapper)).decode()
        actual=self.ts([swapped,damaged])
        self.assertEqual([item['code'] for item in actual],['repair_ref_mismatch','repair_invalid_signature'])
        self.assertEqual(actual[1]['work']['signature_checks'],1)

    def test_typed_array_length_getter_is_not_executed(self):
        actual=self.ts([self.call(rawGetter=True)])[0]
        self.assertTrue(actual['ok'],actual);self.assertEqual(actual['result']['callbacks'],0)
