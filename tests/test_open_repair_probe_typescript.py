"""Real native X25519/AES and Ed25519 bootstrap possession interoperability."""
import base64
import copy
import hashlib
import json
import subprocess
import unittest

from cryptography.hazmat.primitives import serialization
from memory_vault import canonical_bytes
from tests import test_network_typescript_agent_network as ts_runtime
from tests.open_repair_resource_fixtures import ack_resource_fixture
import memory_vault_open_repair_wire as wire

POLICY=dict(max_document_bytes=65536,max_total_bytes=4194304,max_nodes=200000,max_depth=100,
            max_string_bytes=65536,max_hash_bytes=4194304,max_hashes=1000,max_entries=1000,
            max_retained_bytes=4194304,max_signature_checks=100)
DRIVER=r"""
import * as p from './open-repair-probe.ts';
import * as w from './open-repair-wire.ts';
const chunks=[];for await(const chunk of process.stdin)chunks.push(chunk);
const calls=JSON.parse(Buffer.concat(chunks).toString('utf8')),results=[];
const decode=x=>({raw:Buffer.from(x.raw,'base64'),ref:x.ref});
const encode=x=>({raw:Buffer.from(x.raw).toString('base64'),ref:x.ref,payload:x.payload});
const entry=x=>({raw:x.raw,ref:x.ref});
for(const c of calls){let budget;try{
 budget=new w.RepairBudget(c.policy);const options={...c.options,policy:c.policy,budget};let result;
 if(c.op==='roundtrip'){
   const initial=await p.makeBootstrapProbe(c.subjectSigning,{...options,expiresAt:options.at+60});
   let probe=entry(initial.original);if(c.opaque)probe={raw:probe.raw,ref:{...probe.ref,key:'a'.repeat(64)}};
   const challenge=await p.issueBootstrapChallenge(probe,{...options,signer:c.targetSigning,encryptionIdentity:c.targetEncryption,expiresAt:options.at+50});
   const targetNonce=initial.nonce;let nonceCallbacks=0;
   if(c.nonceGetter)Object.defineProperty(targetNonce,'length',{get(){nonceCallbacks++;throw Error('nonce getter');}});
   const answer=await p.solveBootstrapChallenge(probe,entry(challenge.original),{...options,signer:c.subjectSigning,encryptionIdentity:c.subjectEncryption,
      targetNonce:c.wrongTargetNonce?Buffer.alloc(32):targetNonce,expiresAt:options.at+40});
   const checked=p.verifyBootstrapAnswer(probe,entry(challenge.original),entry(answer),{...options,callerNonce:c.wrongCallerNonce?Buffer.alloc(32):challenge.nonce});
   result={probe:encode(probe),challenge:encode(challenge.original),answer:encode(answer),targetNonce:Buffer.from(initial.nonce).toString('base64'),
     callerNonce:Buffer.from(challenge.nonce).toString('base64'),at:checked.at,nonceCallbacks,frozen:Object.isFrozen(checked)&&Object.isFrozen(checked.originals)};
 }else if(c.op==='make'){
   const pending=p.makeBootstrapProbe(c.subjectSigning,{...options,expiresAt:c.expires});
   if(c.mutate){options.expectedSubject.encryption_key.public_key='changed';c.subjectSigning.private_key='changed';}
   const value=await pending;let immutable=true;
   if(c.mutate){const n=value.nonce,n2=Buffer.from(value.nonce),raw=value.original.raw;n.fill(0);raw.fill(0);immutable=Buffer.from(value.nonce).equals(n2)&&value.original.raw[0]===123;}
   result={original:encode(value.original),nonce:Buffer.from(value.nonce).toString('base64'),immutable};
 }else if(c.op==='host'){
   let callbacks=0,codes=[];
   const invoke=fn=>{try{fn();codes.push(null);}catch(e){codes.push(e.code??'untyped_error');}};
   const hostile={...options};Object.defineProperty(hostile,'expectedSubject',{get(){callbacks++;throw Error('getter');}});
   invoke(()=>p.verifyBootstrapProbe(decode(c.probe),hostile));
   invoke(()=>p.verifyBootstrapProbe(decode(c.probe),{...options,selector:new Proxy(options.selector,{ownKeys(){callbacks++;throw Error('proxy');}})}));
   const raw=decode(c.probe);Object.defineProperty(raw,'raw',{get(){callbacks++;throw Error('getter');}});
   invoke(()=>p.verifyBootstrapProbe(raw,options));result={callbacks,codes};
 }else if(c.op==='probe')result=encode(p.verifyBootstrapProbe(decode(c.probe),options));
 else if(c.op==='issue'){
   const value=await p.issueBootstrapChallenge(decode(c.probe),{...options,signer:c.targetSigning,encryptionIdentity:c.targetEncryption,expiresAt:c.expires});
   result={original:encode(value.original),nonce:Buffer.from(value.nonce).toString('base64')};
 }else if(c.op==='solve')result=encode(await p.solveBootstrapChallenge(decode(c.probe),decode(c.challenge),{...options,signer:c.subjectSigning,
   encryptionIdentity:c.subjectEncryption,targetNonce:Buffer.from(c.targetNonce,'base64'),expiresAt:c.expires}));
 else if(c.op==='verify'){
   const value=p.verifyBootstrapAnswer(decode(c.probe),decode(c.challenge),decode(c.answer),{...options,callerNonce:Buffer.from(c.callerNonce,'base64')});
   result={at:value.at,refs:Object.fromEntries(Object.entries(value.originals).map(([name,entry])=>[name,entry.ref]))};
 }
 results.push({ok:true,result,work:budget.snapshot()});
 }catch(error){results.push({ok:false,code:error.code??'untyped_error',work:budget?.snapshot()});}}
process.stdout.write(JSON.stringify(results));
"""


def private_signing(signer):
    secret=signer._private_key.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())
    return {**signer.public_descriptor(),'schema_version':'universal-memory-identity/v1','private_key':base64.b64encode(secret).decode()}


def encoded(entry):
    raw=entry['raw'] if isinstance(entry,dict) else entry.raw
    ref=entry['ref'] if isinstance(entry,dict) else entry.ref.as_dict()
    return dict(raw=base64.b64encode(raw).decode(),ref=ref)


class OpenRepairProbeTypeScriptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ts_runtime.TypeScriptAgentNetworkTests.setUpClass.__func__(cls)
        (cls.fixture/'driver.mjs').write_text(DRIVER)

    def setUp(self):
        self.docs,self.entries,self.expected,self.signers,self.encryption=ack_resource_fixture(include_encryption=True)
        root=self.expected['expected_ack_slot']['root_key']
        self.options=dict(expectedSubject=self.expected['expected_owner'],expectedTarget=self.expected['expected_target'],
            targetStorageEpoch=self.expected['target_storage_epoch'],bootstrapGrantSha256='d'*64,at=2_000_000_006,
            selector=dict(root_key_sha256=hashlib.sha256(canonical_bytes(root)).hexdigest(),
                ack_slot_sha256=hashlib.sha256(canonical_bytes(self.expected['expected_ack_slot'])).hexdigest(),
                root_authority_sha256=self.entries['root']['ref']['raw_sha256'],read_grant_sha256=self.entries['read']['ref']['raw_sha256']))

    def call(self,op='roundtrip',**extra):
        return dict(op=op,options=copy.deepcopy(self.options),policy=POLICY,subjectSigning=private_signing(self.signers['owner']),
            targetSigning=private_signing(self.signers['target']),subjectEncryption=self.encryption['owner'].private_document(),
            targetEncryption=self.encryption['target'].private_document(),**extra)

    def ts(self,calls):
        process=subprocess.run([self.node,'--experimental-strip-types',str(self.fixture/'driver.mjs')],cwd=self.fixture,
            input=json.dumps(calls).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
        self.assertEqual(process.returncode,0,process.stderr.decode(errors='replace')[-6000:]);return json.loads(process.stdout)

    def test_actual_native_mutual_possession_uses_six_verifications_and_opaque_refs(self):
        result=self.ts([self.call(opaque=True)])[0];self.assertTrue(result['ok'],result)
        self.assertEqual(result['work']['signature_checks'],6);self.assertTrue(result['result']['frozen'])
        self.assertEqual(result['result']['probe']['ref']['key'],'a'*64)
        for name in ('probe','challenge','answer'):
            item=result['result'][name];raw=base64.b64decode(item['raw'])
            self.assertEqual(hashlib.sha256(raw).hexdigest(),item['ref']['raw_sha256'])
            self.assertEqual(raw,canonical_bytes(json.loads(raw)))

    def test_nonce_mismatch_and_cumulative_signature_limit_refuse(self):
        capped=self.call();capped['policy']={**POLICY,'max_signature_checks':5}
        results=self.ts([self.call(wrongTargetNonce=True),self.call(wrongCallerNonce=True),capped])
        self.assertEqual([item['code'] for item in results],['repair_invalid_nonce','repair_invalid_nonce','repair_over_budget'])
        self.assertEqual(results[-1]['work']['signature_checks'],5)

    def test_short_transport_windows_have_no_skew_or_child_extension(self):
        for expires in (self.options['at'],self.options['at']+61):
            result=self.ts([self.call('make',expires=expires)])[0]
            self.assertEqual(result['code'],'repair_invalid_probe')
        first=self.ts([self.call('make',expires=self.options['at']+10)])[0]
        self.assertTrue(first['ok'],first)
        probe=first['result']['original']
        early=self.call('probe',probe=probe);early['options']['at']-=1
        late=self.call('probe',probe=probe);late['options']['at']+=10
        extended=self.call('issue',probe=probe,expires=self.options['at']+11)
        self.assertEqual([item['code'] for item in self.ts([early,late,extended])],['repair_invalid_probe','repair_invalid_probe','repair_probe_mismatch'])

    def py_options(self):
        return dict(expected_subject=self.options['expectedSubject'],expected_target=self.options['expectedTarget'],
            target_storage_epoch=self.options['targetStorageEpoch'],bootstrap_grant_sha256=self.options['bootstrapGrantSha256'],
            selector=self.options['selector'],at=self.options['at'])

    @staticmethod
    def entry(value):
        if isinstance(value,dict):return dict(raw=base64.b64decode(value['raw']),ref=value['ref'])
        return dict(raw=value.raw,ref=value.ref.as_dict())

    def test_python_verifies_native_full_exchange_and_exact_metered_outer_hashes(self):
        import memory_vault_open_repair_probe as probe
        native=self.ts([self.call()])[0];self.assertTrue(native['ok'],native);value=native['result']
        local=wire.RepairPolicy(**POLICY);budget=wire.RepairBudget(local)
        checked=probe.verify_bootstrap_answer(*(self.entry(value[name]) for name in ('probe','challenge','answer')),
            caller_nonce=base64.b64decode(value['callerNonce']),**self.py_options(),policy=local,budget=budget)
        self.assertEqual(checked.at,value['at']);self.assertEqual(native['work']['hashes'],44)
        call=self.call('verify',**{name:value[name] for name in ('probe','challenge','answer')},callerNonce=value['callerNonce'])
        verified=self.ts([call])[0];self.assertTrue(verified['ok'],verified)
        for field in ('signature_checks','hashes','hash_bytes'):
            self.assertEqual(verified['work'][field],budget.snapshot()[field],field)

    def test_bidirectional_python_native_nonce_encryption_and_answer_signatures(self):
        import memory_vault_open_repair_probe as probe
        local=wire.RepairPolicy(**POLICY);budget=wire.RepairBudget(local);options=self.py_options()
        initial=probe.make_bootstrap_probe(self.signers['owner'],**options,expires_at=options['at']+60,policy=local,budget=budget)
        issued=self.ts([self.call('issue',probe=encoded(initial.original),expires=options['at']+50)])[0]
        self.assertTrue(issued['ok'],issued);challenge=issued['result']
        answer=probe.solve_bootstrap_challenge(self.entry(initial.original),self.entry(challenge['original']),
            signer=self.signers['owner'],encryption_identity=self.encryption['owner'],target_nonce=initial.nonce,
            **options,expires_at=options['at']+40,policy=local,budget=budget)
        verified=self.ts([self.call('verify',probe=encoded(initial.original),challenge=challenge['original'],answer=encoded(answer),
            callerNonce=challenge['nonce'])])[0];self.assertTrue(verified['ok'],verified)
        native=self.ts([self.call('make',expires=options['at']+60)])[0];self.assertTrue(native['ok'],native)
        initial=native['result']
        challenge=probe.issue_bootstrap_challenge(self.entry(initial['original']),signer=self.signers['target'],
            encryption_identity=self.encryption['target'],**options,expires_at=options['at']+50,policy=local,budget=budget)
        answered=self.ts([self.call('solve',probe=initial['original'],challenge=encoded(challenge.original),targetNonce=initial['nonce'],
            expires=options['at']+40)])[0];self.assertTrue(answered['ok'],answered)
        checked=probe.verify_bootstrap_answer(self.entry(initial['original']),self.entry(challenge.original),self.entry(answered['result']),
            caller_nonce=challenge.nonce,**options,policy=local,budget=budget)
        self.assertEqual(checked.at,options['at'])

    def test_expected_bindings_and_real_invalid_signature_are_checked(self):
        initial=self.ts([self.call('make',expires=self.options['at']+60)])[0]['result']['original']
        calls=[]
        for name in ('epoch','grant','selector','target','subject','signature'):
            call=self.call('probe',probe=copy.deepcopy(initial))
            if name=='epoch':call['options']['targetStorageEpoch']='different_epoch'
            elif name=='grant':call['options']['bootstrapGrantSha256']='e'*64
            elif name=='selector':call['options']['selector']['ack_slot_sha256']='e'*64
            elif name=='target':call['options']['expectedTarget']=call['options']['expectedSubject']
            elif name=='subject':call['options']['expectedSubject']=call['options']['expectedTarget']
            else:
                value=json.loads(base64.b64decode(initial['raw']));value['proof']['signature']=base64.b64encode(bytes(64)).decode()
                raw=canonical_bytes(value);call['probe']=encoded(dict(raw=raw,ref={**initial['ref'],'size':len(raw),'raw_sha256':hashlib.sha256(raw).hexdigest()}))
            calls.append(call)
        results=self.ts(calls)
        self.assertEqual([item['code'] for item in results],['repair_probe_mismatch']*5+['repair_invalid_signature'])
        self.assertEqual(results[-1]['work']['signature_checks'],1)

    def test_signed_wrong_jwe_aad_key_and_ciphertext_shape_fail_before_crypto(self):
        initial=self.ts([self.call('make',expires=self.options['at']+60)])[0]['result']['original']
        calls=[]
        for mutation in ('aad','kid','recipients','ciphertext'):
            value=json.loads(base64.b64decode(initial['raw']));jwe=value['payload']['target_nonce_jwe']
            if mutation=='aad':jwe['aad']=base64.urlsafe_b64encode(b'wrong').rstrip(b'=').decode()
            elif mutation=='kid':jwe['recipients'][0]['header']['kid']=self.options['expectedSubject']['encryption_key']['key_id']
            elif mutation=='recipients':jwe['recipients'].append(copy.deepcopy(jwe['recipients'][0]))
            else:jwe['ciphertext']=jwe['ciphertext'][:-1]
            value['proof']=self.signers['owner'].sign_message(value['payload']);raw=canonical_bytes(value)
            entry=dict(raw=raw,ref={**initial['ref'],'size':len(raw),'raw_sha256':hashlib.sha256(raw).hexdigest()})
            calls.append(self.call('probe',probe=encoded(entry)))
        for result in self.ts(calls):
            self.assertFalse(result['ok'],result);self.assertNotEqual(result['code'],'untyped_error')
            self.assertEqual(result['work']['signature_checks'],0)

    def test_async_expected_and_private_inputs_are_snapshotted_and_outputs_immutable(self):
        result=self.ts([self.call('make',expires=self.options['at']+60,mutate=True)])[0]
        self.assertTrue(result['ok'],result);self.assertTrue(result['result']['immutable'])
        self.assertEqual(result['result']['original']['payload']['subject'],self.options['expectedSubject'])
        verified=self.ts([self.call('probe',probe=result['result']['original'])])[0]
        self.assertTrue(verified['ok'],verified)

    def test_host_getters_proxies_and_raw_accessors_have_zero_callbacks(self):
        initial=self.ts([self.call('make',expires=self.options['at']+60)])[0]['result']['original']
        result=self.ts([self.call('host',probe=initial)])[0]
        self.assertTrue(result['ok'],result);self.assertEqual(result['result']['callbacks'],0)
        self.assertTrue(all(code and code!='untyped_error' for code in result['result']['codes']))
        self.assertEqual(result['work']['signature_checks'],0)
        nonce=self.ts([self.call(nonceGetter=True)])[0]
        self.assertTrue(nonce['ok'],nonce);self.assertEqual(nonce['result']['nonceCallbacks'],0)

    def test_real_aead_tampering_and_mismatched_private_key_pairs_fail(self):
        initial=self.ts([self.call('make',expires=self.options['at']+60)])[0]['result']['original']
        value=json.loads(base64.b64decode(initial['raw']))
        ciphertext=value['payload']['target_nonce_jwe']['ciphertext']
        value['payload']['target_nonce_jwe']['ciphertext']=('B' if ciphertext[0]!='B' else 'A')+ciphertext[1:]
        value['proof']=self.signers['owner'].sign_message(value['payload']);raw=canonical_bytes(value)
        damaged=encoded(dict(raw=raw,ref={**initial['ref'],'raw_sha256':hashlib.sha256(raw).hexdigest(),'size':len(raw)}))
        tamper=self.call('issue',probe=damaged,expires=self.options['at']+50)
        wrong_x=self.call('issue',probe=initial,expires=self.options['at']+50)
        wrong_x['targetEncryption']['private_key']=self.encryption['owner'].private_document()['private_key']
        wrong_ed=self.call('make',expires=self.options['at']+60)
        wrong_ed['subjectSigning']['private_key']=private_signing(self.signers['target'])['private_key']
        results=self.ts([tamper,wrong_x,wrong_ed])
        self.assertEqual([item['code'] for item in results],['repair_decryption_failed','repair_probe_mismatch','repair_probe_mismatch'])
