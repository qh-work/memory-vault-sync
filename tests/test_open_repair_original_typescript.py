"""Real native Ed25519 checks over synthetic original controls; no fallback.

Local input authentication only, not a repair transport/authority acceptance.
"""
import base64
import copy
import hashlib
import json
import subprocess
import unittest

from memory_vault import canonical_bytes
import memory_vault_open_repair_original as original
import memory_vault_open_repair_wire as wire
from tests import test_network_typescript_agent_network as ts_runtime
from tests import test_open_contact as fixture

POLICY = dict(max_document_bytes=65536, max_total_bytes=4194304,
              max_nodes=200000, max_depth=100, max_string_bytes=65536,
              max_hash_bytes=4194304, max_hashes=1000, max_entries=1000,
              max_retained_bytes=4194304, max_signature_checks=100)
ROLES = ('node','knock_lease','policy','request','decision','grant','delivery_lease')
DRIVER = r"""
import * as o from './open-repair-original.ts';
import * as w from './open-repair-wire.ts';
const chunks=[];
for await(const chunk of process.stdin)chunks.push(chunk);
const calls=JSON.parse(Buffer.concat(chunks).toString('utf8')), results=[];
const bytes=raw=>Buffer.from(raw,'base64');
for(const c of calls){
  let budget;
  try{
    budget=new w.RepairBudget(c.policy); const policy=c.policy;
    let result;
    if(c.op==='parse'){
      const raw=bytes(c.raw), draft=o.parseOriginalControl(raw,policy,budget);
      if(c.mutate)raw.fill(0);
      result={value:draft.value,raw:Buffer.from(draft.raw).toString('base64'),frozen:Object.isFrozen(draft)&&Object.isFrozen(draft.value)};
      if(c.path)result.nested=Buffer.from(draft.nestedRaw(c.path)).toString('base64');
      if(c.mutate){const exported=draft.raw;exported.fill(0);result.unchanged=Buffer.from(draft.raw).toString('base64');}
    }else if(c.op==='verify'){
      const value=o.verifyOriginalControl(bytes(c.raw),{...c.options,policy,budget});
      result={payload:value.payload,raw_sha256:value.raw_sha256,canonical_sha256:value.canonical_sha256};
    }else if(c.op==='contact'){
      const value=o.verifyContactOriginals(Object.fromEntries(Object.entries(c.raws).map(([k,v])=>[k,bytes(v)])),{...c.options,policy,budget});
      result={at:value.at,originals:Object.fromEntries(Object.entries(value.originals).map(([k,v])=>[k,{raw_sha256:v.raw_sha256,canonical_sha256:v.canonical_sha256}]))};
    }else if(c.op==='packcontact'){
      const resolver=new w.LocalRawResolver(policy,budget), raw=bytes(c.pack);
      resolver.put('meta',c.ref.key,raw);
      const packed=w.parseRawPack(resolver.resolve(c.ref).raw,c.ref,policy,budget);
      const originals=Object.fromEntries(Object.entries(c.entries).map(([role,item])=>[role,packed.entry(item.index,item.ref).raw]));
      const before=budget.snapshot(); const value=o.verifyContactOriginals(originals,{...c.options,policy,budget});
      result={before,roles:Object.keys(value.originals)};
    }else if(c.op==='repeat'){
      const errors=[];for(let i=0;i<2;i++){try{o.verifyOriginalControl(bytes(c.raw),{...c.options,policy,budget});errors.push(null);}catch(e){errors.push(e.code??'untyped_error');}}
      result={errors};
    }else if(c.op==='brands'){
      const errors=[];let traps=0;
      const invoke=f=>{try{f();errors.push(null);}catch(e){errors.push(e.code??'untyped_error');}};
      invoke(()=>o.parseOriginalControl(bytes(c.raw),policy,null));
      invoke(()=>o.parseOriginalControl(bytes(c.raw),policy,Object.create(w.RepairBudget.prototype)));
      invoke(()=>new w.RepairBudget(new Proxy(policy,{getOwnPropertyDescriptor(){traps++;throw Error('trap');}})));
      invoke(()=>Object.defineProperty(budget,'signatureCheck',{value:()=>{}}));
      result={errors,traps,frozen:Object.isFrozen(budget)};
    }
    results.push({ok:true,result,work:budget.snapshot()});
  }catch(e){results.push({ok:false,code:e.code??'untyped_error',work:budget?.snapshot()});}
}
process.stdout.write(JSON.stringify(results));
"""


def b64(raw):
    return base64.b64encode(raw).decode()


class OpenRepairOriginalTypeScriptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ts_runtime.TypeScriptAgentNetworkTests.setUpClass.__func__(cls)
        (cls.fixture / 'driver.mjs').write_text(DRIVER)

    def setUp(self):
        self.py = fixture.OpenContactProtocolTests('test_valid_opt_in_request_and_explicit_finite_delivery_decision')
        self.addCleanup(self.py.doCleanups)
        self.py.setUp()
        h = self.py
        decision = h.make_decision()
        grant = decision['payload']['grant']
        self.documents = dict(zip(ROLES, [h.node,h.lease,h.policy,h.request,decision,grant,grant['payload']['resource_lease']]))
        self.raws = {k: canonical_bytes(v) for k,v in self.documents.items()}
        self.options = dict(senderKeyId=h.sender.key_id,senderEncryptionKeyId=h.sender_encryption.key_id,
                            recipientKeyId=h.recipient.key_id,recipientEncryptionKeyId=h.recipient_encryption.key_id,
                            nodeKeyId=h.server.key_id,storageEpoch='synthetic_epoch',at=h.now)

    def ts(self, calls):
        run = subprocess.run([self.node,'--experimental-strip-types',str(self.fixture / 'driver.mjs')],
                             cwd=self.fixture,input=json.dumps(calls).encode(),stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,timeout=30)
        self.assertEqual(run.returncode,0,run.stderr.decode(errors='replace')[-5000:])
        return json.loads(run.stdout)

    def call(self, op, **values):
        return dict(op=op,policy=POLICY,**values)

    def contact(self, raws=None, options=None, policy=None):
        return dict(op='contact',raws={k:b64(v) for k,v in (raws or self.raws).items()},
                    options={**self.options,**(options or {})},policy=policy or POLICY)

    def verify(self, document=None, **changes):
        document = document or self.documents['request']
        payload = document['payload']
        options = dict(expectedSigningKey=payload['signing_key']['key_id'],expectedSchema=payload['schema_version'],
                       expectedKind=payload['kind'],at=self.py.now)
        options.update(changes)
        return self.call('verify',raw=b64(canonical_bytes(document)),options=options)

    def py_contact(self, raws=None, **changes):
        h = self.py
        options = dict(sender_key_id=h.sender.key_id,sender_encryption_key_id=h.sender_encryption.key_id,
                       recipient_key_id=h.recipient.key_id,recipient_encryption_key_id=h.recipient_encryption.key_id,
                       node_key_id=h.server.key_id,storage_epoch='synthetic_epoch',at=h.now)
        options.update(changes)
        policy = wire.RepairPolicy(**POLICY); budget = wire.RepairBudget(policy)
        value = original.verify_contact_originals(raws or self.raws,policy=policy,budget=budget,**options)
        return value,budget.snapshot()

    def test_exact_utf8_spans_escaped_keys_and_immutable_snapshots(self):
        raw = '{ "extra": "🧪\\\"}","payload":{"\\u0067rant": { "v": -0, "payload": {"resource_lease":{"n":-9007199254740991}}}},"payload/grant":{"wrong":true},"":{"payload":{"grant":{"wrong":false}}}}'.encode()
        call = self.call('parse',raw=b64(raw),path=['payload','grant'],mutate=True)
        actual = self.ts([call])[0]
        self.assertTrue(actual['ok'],actual)
        policy = wire.RepairPolicy(**POLICY); budget = wire.RepairBudget(policy)
        py = original.parse_original_control(raw,policy,budget)
        self.assertEqual(base64.b64decode(actual['result']['nested']),py.nested_raw(('payload','grant')))
        self.assertEqual(actual['result']['raw'],b64(raw))
        self.assertEqual(actual['result']['unchanged'],b64(raw))
        self.assertTrue(actual['result']['frozen'])
        self.assertEqual(actual['work']['signature_checks'],0)

    def test_portable_control_parser_refusals_match_python(self):
        raws = [b'[]',b'null',b'"scalar"',b'{"x":1.0}',b'{"x":9223372036854775807}',
                b'{"x":-9007199254740992}',b'{"x":0,"\\u0078":1}',b'{"x":"\\ud800"}',
                b'{"x":"\xff"}','{"非ascii":1}'.encode(),b'{"x":'+b'['*25+b'0'+b']'*25+b'}']
        actual = self.ts([self.call('parse',raw=b64(raw)) for raw in raws])
        for raw,result in zip(raws,actual):
            with self.subTest(raw=raw):
                policy=wire.RepairPolicy(**POLICY)
                with self.assertRaises(wire.RepairWireError) as exc:
                    original.parse_original_control(raw,policy,wire.RepairBudget(policy))
                self.assertFalse(result['ok'],result)
                self.assertEqual(result['code'],exc.exception.code)

    def test_real_expected_signatures_and_both_digests_match_python(self):
        results = self.ts([self.verify(value) for value in self.documents.values()])
        for (role,document),result in zip(self.documents.items(),results):
            with self.subTest(role=role):
                self.assertTrue(result['ok'],result)
                self.assertEqual(result['work']['signature_checks'],1)
                self.assertEqual(result['work']['hashes'],4)
                raw=self.raws[role]
                self.assertEqual(result['result']['raw_sha256'],hashlib.sha256(raw).hexdigest())
                self.assertEqual(result['result']['canonical_sha256'],hashlib.sha256(canonical_bytes(document)).hexdigest())

    def test_full_contact_chain_matches_python_and_charges_seven_signatures(self):
        result=self.ts([self.contact()])[0]; self.assertTrue(result['ok'],result)
        value,work=self.py_contact()
        self.assertEqual(result['work']['signature_checks'],7)
        for field in ('hashes','hash_bytes','input_bytes','nodes','string_bytes','max_depth'):
            self.assertEqual(result['work'][field],work[field],field)
        for role,verified in value.originals.items():
            self.assertEqual(result['result']['originals'][role],dict(raw_sha256=verified.raw_sha256,canonical_sha256=verified.canonical_sha256))

    def test_independent_expected_identities_reject_self_authenticated_substitution(self):
        h=self.py
        changes=[dict(senderKeyId=h.other.key_id),dict(recipientKeyId=h.other.key_id),dict(nodeKeyId=h.other.key_id),
                 dict(senderEncryptionKeyId=h.other_encryption.key_id),dict(recipientEncryptionKeyId=h.other_encryption.key_id),
                 dict(storageEpoch='synthetic_wrong')]
        results=self.ts([self.contact(options=change) for change in changes])
        for change,result in zip(changes,results):
            with self.subTest(change=change):
                self.assertFalse(result['ok'],result)
                self.assertIn(result['code'],('repair_wrong_issuer','repair_contact_mismatch'))

    def test_signature_allowance_failed_signature_consumption_and_legacy_default_zero(self):
        bad=copy.deepcopy(self.documents['request'])
        bad['proof']['signature']=base64.b64encode(b'\0'*64).decode()
        call=self.verify(bad); call['op']='repeat';call['policy']={**POLICY,'max_signature_checks':1}
        good=self.verify(); good['policy']={k:v for k,v in POLICY.items() if k!='max_signature_checks'}
        results=self.ts([call,good])
        self.assertEqual(results[0]['result']['errors'],['repair_invalid_signature','repair_over_budget'])
        self.assertEqual(results[0]['work']['signature_checks'],1)
        self.assertEqual(results[1]['code'],'repair_over_budget')
        self.assertEqual(results[1]['work']['signature_checks'],0)

    def test_literal_nested_original_mismatch_and_consistent_noncanonical_inputs(self):
        mismatched={**self.raws,'grant':b' '+self.raws['grant']}
        good={**self.raws,'node':b' \n'+self.raws['node']+b'\n','request':b' \n'+self.raws['request']}
        results=self.ts([self.contact(mismatched),self.contact(good)])
        self.assertEqual(results[0]['code'],'repair_original_mismatch')
        self.assertTrue(results[1]['ok'],results[1])
        value,_=self.py_contact(good)
        self.assertNotEqual(value.originals['request'].raw_sha256,value.originals['request'].canonical_sha256)
        self.assertEqual(results[1]['result']['originals']['request']['canonical_sha256'],value.originals['request'].canonical_sha256)

    def test_authentication_tamper_kind_proof_key_and_time_refusals(self):
        bad=copy.deepcopy(self.documents['request']);bad['payload']['request_id']='changed'
        proof=copy.deepcopy(self.documents['request']);proof['proof']['key_id']=self.py.other.key_id
        calls=[self.verify(bad),self.verify(proof),self.verify(expectedKind='resource.lease'),
               self.verify(at=self.py.now+600),self.verify(at=self.py.now-31),self.verify(expectedSchema=''),
               self.verify(expectedKind='x'*129)]
        results=self.ts(calls)
        self.assertEqual([x['code'] for x in results],['repair_invalid_signature','repair_wrong_issuer',
            'repair_invalid_original','repair_invalid_original','repair_invalid_original','repair_invalid_original','repair_invalid_original'])
        self.assertTrue(all(x['work']['signature_checks']==0 for x in results))

    def test_finite_limits_and_unshadowable_budget_brand(self):
        variants=[('max_document_bytes',1),('max_nodes',1),('max_hashes',1),('max_hash_bytes',1),('max_signature_checks',0)]
        calls=[]
        for field,value in variants:
            call=self.verify();call['policy']={**POLICY,field:value};calls.append(call)
        results=self.ts(calls+[self.call('brands',raw=b64(b'{}'))])
        self.assertTrue(all(x['code']=='repair_over_budget' for x in results[:-1]),results)
        brand=results[-1]['result'];self.assertEqual(brand['traps'],0)
        self.assertEqual(brand['errors'][:3],['repair_invalid_policy']*3)
        self.assertIsNotNone(brand['errors'][3]);self.assertTrue(brand['frozen'])

    def test_closed_role_shape_and_policy_fields_reject_before_crypto(self):
        raw=copy.deepcopy(self.documents['node']);raw['payload']['unexpected']='extra'
        raw['proof']=self.py.server.sign_message(raw['payload'])
        call=self.contact({**self.raws,'node':canonical_bytes(raw)})
        bad=self.verify();bad['policy']={**POLICY,'unknown_limit':3}
        results=self.ts([call,bad,self.contact(policy={**POLICY,'max_signature_checks':-1})])
        self.assertEqual([x['code'] for x in results],['repair_invalid_original','repair_invalid_policy','repair_invalid_policy'])
        self.assertEqual(results[0]['work']['signature_checks'],0)

    def test_real_pack_resolver_and_contact_share_one_cumulative_budget(self):
        policy=wire.RepairPolicy(**POLICY); producer=wire.RepairBudget(policy)
        pack=wire.build_raw_pack(list(self.raws.values()),policy,producer)
        entries={}
        for role,raw in self.raws.items():
            digest=hashlib.sha256(raw).hexdigest()
            index=next(i for i,e in enumerate(pack.entries) if e.raw_sha256==digest)
            entries[role]=dict(index=index,ref=dict(namespace='meta',key=digest,raw_sha256=digest,size=len(raw)))
        call=dict(op='packcontact',policy=POLICY,pack=b64(pack.raw),ref=pack.ref.as_dict(),entries=entries,options=self.options)
        limited={**call,'policy':{**POLICY,'max_signature_checks':6}}
        result,refused=self.ts([call,limited])
        self.assertTrue(result['ok'],result)
        self.assertEqual(result['result']['roles'],list(ROLES))
        self.assertEqual(result['result']['before']['signature_checks'],0)
        self.assertGreater(result['result']['before']['hashes'],7)
        self.assertEqual(result['work']['signature_checks'],7)
        self.assertGreater(result['work']['hashes'],result['result']['before']['hashes'])
        self.assertEqual(refused['code'],'repair_over_budget')
        self.assertEqual(refused['work']['signature_checks'],6)
        self.assertGreater(refused['work']['hashes'],result['result']['before']['hashes'])

    def test_wrong_signature_domain_and_signed_scope_change_are_rejected(self):
        wrong=copy.deepcopy(self.documents['request'])
        body={k:v for k,v in wrong['proof'].items() if k!='signature'}
        signature=self.py.sender._private_key.sign(b'wrong-domain\0'+canonical_bytes(body))
        wrong['proof']['signature']=base64.b64encode(signature).decode()
        grant=self.py.changed(self.documents['grant'],self.py.recipient,operations=['vault.read'])
        decision=self.py.changed(self.documents['decision'],self.py.recipient,grant=grant)
        invalid_scope={**self.raws,'grant':canonical_bytes(grant),'decision':canonical_bytes(decision)}
        domain,scope=self.ts([self.verify(wrong),self.contact(invalid_scope)])
        self.assertEqual(domain['code'],'repair_invalid_signature')
        self.assertEqual(domain['work']['signature_checks'],1)
        self.assertEqual(scope['code'],'repair_invalid_original')
        with self.assertRaises(wire.RepairWireError) as exc:
            self.py_contact(invalid_scope)
        self.assertEqual(scope['code'],exc.exception.code)

    def test_base64_missing_padding_refuses_before_oversized_decode(self):
        badkey=copy.deepcopy(self.documents['request'])
        badkey['payload']['signing_key']['public_key']='A'*44
        badsig=copy.deepcopy(self.documents['request'])
        badsig['proof']['signature']='A'*88
        results=self.ts([self.verify(badkey),self.verify(badsig)])
        self.assertEqual([r['code'] for r in results],['repair_invalid_original']*2)
        self.assertEqual(results[0]['work']['output_bytes'],0)
        self.assertEqual(results[0]['work']['hashes'],0)
        self.assertEqual(results[1]['work']['hashes'],2)
        self.assertTrue(all(r['work']['signature_checks']==0 for r in results))
        expected_encoded_payload=len(canonical_bytes(badsig['payload']))
        self.assertEqual(results[1]['work']['output_bytes'],32+44+expected_encoded_payload)
