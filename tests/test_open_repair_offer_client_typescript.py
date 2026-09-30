"""Native writer reads the independently authorized source over actual HTTP."""
import hashlib
import json
import subprocess
import unittest

from memory_vault import canonical_bytes
from memory_vault_open_repair_offer_access import RepairAckOfferAccess
from tests import test_network_typescript_agent_network as runtime
from tests import test_open_repair_probe_typescript as probe_ts
from tests import test_open_repair_proof_typescript as proof_ts
from tests.open_repair_ack_fixtures import signed_entry
from tests.test_open_repair_empty_http import EmptyHTTPFixture

DRIVER=r"""
import child from 'node:child_process';
import crypto from 'node:crypto';
import {syncBuiltinESMExports} from 'node:module';
let subprocessCalls=0,nativeChecks=0;
const deny=()=>{subprocessCalls++;throw Error('native offer must not delegate');};
for(const name of ['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork'])child[name]=deny;
const originalVerify=crypto.verify;crypto.verify=(...args)=>{nativeChecks++;return originalVerify(...args);};syncBuiltinESMExports();
const {AckOfferClient}=await import('./open-repair-offer-client.ts');
const {OpenHTTPTransport}=await import('./open-transport.ts');
const chunks=[];let size=0;for await(const chunk of process.stdin){size+=chunk.length;if(size>1048576)throw Error('fixture limit');chunks.push(chunk);}
const input=JSON.parse(Buffer.concat(chunks).toString('utf8')),decode=item=>({raw:Buffer.from(item.raw,'base64'),ref:item.ref});
const transport=new OpenHTTPTransport({allow_loopback:true}),calls=[],request=transport.requestRepair.bind(transport);
transport.requestRepair=async(base,raw,...rest)=>{calls.push(JSON.parse(Buffer.from(raw).toString()).payload.kind);return request(base,raw,...rest);};
const client=new AckOfferClient(input.signing,input.encryption,{policy:input.policy,limitPolicy:input.limits,transport,
  allowLoopback:true,clock:()=>input.now});
const options={...input.options};
for(const name of ['targetNodeEntry','rootEntry','writeEntry','bootstrapEntry'])options[name]=decode(options[name]);
for(const name of ['knownStatuses','archiveStatuses'])if(options[name])options[name]=options[name].map(decode);
try{
  const result=await client.preflight(input.base,options);
  const original=result.originals[0],before=Buffer.from(original.raw).toString('hex');original.raw.fill(0);
  process.stdout.write(JSON.stringify({ok:true,metrics:result.metrics,consumer:result.proof.handle.payload.consumer,
    write:result.source.authorities.originals.write.ref,bootstrap:result.source.authorities.originals.bootstrap.ref,
    custody:Buffer.from(result.source.custody.raw).toString('base64'),originals:result.originals.length,
    immutable:Buffer.from(original.raw).toString('hex')===before,calls,nativeChecks,subprocessCalls}));
}catch(error){process.stdout.write(JSON.stringify({ok:false,code:error.code??'untyped_error',detail:error.code?undefined:String(error.stack),calls,nativeChecks,subprocessCalls}));}
finally{client.close();transport.close();}
"""


class NativeOfferClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        runtime.TypeScriptAgentNetworkTests.setUpClass.__func__(cls)
        (cls.fixture/'driver.mjs').write_text(DRIVER)

    def setUp(self):
        self.host=EmptyHTTPFixture(self)
        self.f=self.host.f

    def call(self,**extra):
        f=self.f;e=f['expected'];h=self.host
        return dict(base=h.http.base,signing=probe_ts.private_signing(f['signers']['writer']),
            encryption=f['encryption']['writer'].private_document(),now=2_000_000_007,
            policy=proof_ts.POLICY,limits=e['limit_policy'],options=dict(
                targetNodeEntry=probe_ts.encoded(f['entries']['descriptor']),expectedTarget=e['expected_target'],
                expectedAckSlot=e['expected_ack_slot'],expectedOwner=e['expected_owner'],
                expectedMessageId=h.expected['expected_message_id'],expectedEnvelopeRef=h.expected['expected_envelope_ref'],
                rootEntry=probe_ts.encoded(f['entries']['root']),writeEntry=probe_ts.encoded(h.write),bootstrapEntry=probe_ts.encoded(h.offer))|extra)

    def native(self,value):
        result=subprocess.run([self.node,'--experimental-strip-types',str(self.fixture/'driver.mjs')],cwd=self.fixture,
            input=json.dumps(value).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=40)
        self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace')[-2000:])
        value=json.loads(result.stdout);self.assertEqual(value['subprocessCalls'],0);return value

    def revoke(self,kind,original,mask):
        root=self.f['expected']['expected_ack_slot']['root_key']
        scope=hashlib.sha256(canonical_bytes(dict(kind='authority',root_key=root,
            authority_kind=kind,authority_sha256=original['ref']['raw_sha256']))).hexdigest()
        payload=json.loads(self.host.expected['current_statuses'][0]['raw'])['payload'];payload['revision']=3
        for item in payload['entries']:
            if item['scope_id']==scope:item.update(status='revoked',operation_mask=mask)
        return signed_entry(payload,self.f['signers']['owner'],'synthetic-native-offer-revocation')

    def test_native_complete_source_read_after_restart(self):
        self.host.http.restart();result=self.native(self.call())
        self.assertTrue(result['ok'],result);self.assertTrue(result['immutable'])
        self.assertEqual(result['consumer'],'ack_offer')
        self.assertEqual(result['write'],self.host.write['ref']);self.assertEqual(result['bootstrap'],self.host.offer['ref'])
        self.assertEqual(result['metrics']['requests'],12);self.assertEqual(result['originals'],12)
        self.assertEqual(result['nativeChecks'],result['metrics']['signature_checks'])
        self.assertEqual(result['calls'][:2],['bootstrap.probe','bootstrap.answer'])
        self.assertTrue(all(kind=='bootstrap.proof_child_request' for kind in result['calls'][2:]))

    def test_writer_admit_revocation_refuses_before_any_private_probe(self):
        revoked=self.revoke('ack.write_grant',self.host.write,1)
        result=self.native(self.call(knownStatuses=[probe_ts.encoded(revoked)]))
        self.assertFalse(result['ok']);self.assertEqual(result['code'],'repair_authority_revoked');self.assertEqual(result['calls'],[])

    def test_historical_owner_read_revocation_does_not_revoke_writer_admit(self):
        revoked=self.revoke('ack.read_grant',self.f['entries']['read'],2)
        gate=RepairAckOfferAccess(self.host.source.state);gate.initialize()
        prepared=gate.prepare(self.host.source.resource_id,action='proof',current_statuses=[revoked,self.host.expected['current_statuses'][1]])
        with self.host.source.state._transaction():self.assertTrue(gate.check_locked(prepared).allowed)
        result=self.native(self.call(knownStatuses=[probe_ts.encoded(revoked)]))
        self.assertTrue(result['ok'],result);self.assertEqual(result['metrics']['requests'],12)

    def test_root_discover_revocation_and_archived_write_revocation_refuse_before_probe(self):
        cases=[('ack.root_authority',self.f['entries']['root'],8,'knownStatuses'),
               ('ack.write_grant',self.host.write,1,'archiveStatuses')]
        for kind,original,mask,field in cases:
            with self.subTest(kind=kind):
                revoked=self.revoke(kind,original,mask)
                result=self.native(self.call(**{field:[probe_ts.encoded(revoked)]}))
                self.assertFalse(result['ok']);self.assertEqual(result['code'],'repair_authority_revoked');self.assertEqual(result['calls'],[])

    def test_message_binding_mismatch_refuses_before_network(self):
        result=self.native(self.call(expectedMessageId='msg_'+'f'*64))
        self.assertFalse(result['ok']);self.assertEqual(result['calls'],[])
        self.assertNotEqual(result['code'],'untyped_error')


if __name__=='__main__':unittest.main()
