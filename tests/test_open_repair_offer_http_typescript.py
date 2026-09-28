"""Real native receipt-writer possession, offer proof and exact child HTTP."""
import base64
import copy
import hashlib
import json
import subprocess
import unittest

from memory_vault import canonical_bytes
import memory_vault_open_repair_probe as probe
import memory_vault_open_repair_proof as proof
import memory_vault_open_repair_wire as wire
from tests import test_network_typescript_agent_network as ts_runtime
from tests import test_open_repair_empty_http as http_fixture
from tests import test_open_repair_probe_typescript as probe_ts
from tests import test_open_repair_proof_typescript as proof_ts

DRIVER=r"""
import child from 'node:child_process';
import crypto from 'node:crypto';
import {syncBuiltinESMExports} from 'node:module';
let subprocessCalls=0,nativeChecks=0;const deny=()=>{subprocessCalls++;throw Error('native offer must not delegate');};
for(const name of ['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork'])child[name]=deny;
const originalVerify=crypto.verify;crypto.verify=(...args)=>{nativeChecks++;return originalVerify(...args);};syncBuiltinESMExports();
const p=await import('./open-repair-probe.ts'),q=await import('./open-repair-proof.ts'),b=await import('./open-repair-bound.ts'),w=await import('./open-repair-wire.ts');
const {OpenHTTPTransport,REPAIR_PATH}=await import('./open-transport.ts'),{performance}=await import('node:perf_hooks');
const chunks=[];let size=0;for await(const chunk of process.stdin){size+=chunk.length;if(size>1048576)throw Error('synthetic input limit');chunks.push(chunk);}
const input=JSON.parse(Buffer.concat(chunks).toString('utf8')),decode=item=>({raw:Buffer.from(item.raw,'base64'),ref:item.ref});
const transport=new OpenHTTPTransport({allow_loopback:true}),calls=[],budget=new w.RepairBudget(input.policy);
const entry=item=>({raw:item.raw,ref:item.ref});let callbacks=0;
try{
  const authorities=b.verifyAckOfferBootstrapOriginal(decode(input.entries.offer),{root:decode(input.entries.root),write:decode(input.entries.write)},
    {...input.bound,at:input.options.at,limitPolicy:input.limits,policy:input.policy,budget});
  const options={...input.options,policy:input.policy,budget};
  const request=async(raw,child=false)=>{calls.push({path:REPAIR_PATH,kind:JSON.parse(Buffer.from(raw).toString('utf8')).payload.kind,child});
    return transport.requestRepair(input.base,raw,performance.now()/1000+15,{child});};
  const first=await p.makeBootstrapProbe(input.signing,{...options,expiresAt:input.options.at+50});
  const firstRaw=first.original.raw,challengeRaw=await request(firstRaw),hash=budget.hash(challengeRaw);
  const challenge={raw:challengeRaw,ref:{namespace:'meta',key:hash,raw_sha256:hash,size:challengeRaw.length}};
  const answer=await p.solveBootstrapChallenge({raw:firstRaw,ref:first.original.ref},challenge,{...options,signer:input.signing,encryptionIdentity:input.encryption,
    targetNonce:first.nonce,expiresAt:input.options.at+40});
  const response=await request(answer.raw),proofOptions={expectedSubject:options.expectedSubject,expectedTarget:options.expectedTarget,
    targetStorageEpoch:options.targetStorageEpoch,selector:input.proofConsumer==='ack_owner'?input.ownerSelector:options.selector,
    bootstrapGrantRef:authorities.originals.bootstrap.ref,probeRef:first.original.ref,challengeRef:challenge.ref,answerRef:answer.ref,
    at:input.options.at,maxProofItems:input.limits.max_proof_items,maxProofBytes:input.limits.max_proof_bytes,expectedSourceState:'empty',
    consumer:input.proofConsumer??'ack_offer',policy:input.policy,budget};
  const checked=q.verifyBootstrapProofResponse(response,proofOptions),selected=checked.manifest.value.children.find(item=>item.role==='ack.binding');
  const subject=input.ownerChild?input.owner:options.expectedSubject,signer=input.ownerChild?input.ownerSigning:input.signing;
  const child=q.makeBootstrapChildRequest(signer,checked,{subject,target:options.expectedTarget,at:input.options.at,expiresAt:input.options.at+30,
    childIndex:selected.index,offset:0,requestedBytes:selected.ref.size,policy:input.policy,budget});
  q.verifyBootstrapChildRequest(entry(child),checked,{expectedSubject:options.expectedSubject,expectedTarget:options.expectedTarget,at:input.options.at,policy:input.policy,budget});
  const raw=await request(child.raw,true);budget.input(raw.length);if(raw.length!==selected.ref.size||budget.hash(raw)!==selected.ref.raw_sha256)throw new w.RepairError('repair_ref_mismatch');
  const {policy:unusedPolicy,budget:unusedBudget,...savedOptions}=proofOptions;
  process.stdout.write(JSON.stringify({ok:true,calls,nativeChecks,subprocessCalls,callbacks,work:budget.snapshot(),
    consumer:checked.handle.payload.consumer,manifest:checked.manifest.value,selected,raw:Buffer.from(raw).toString('base64'),
    child:{raw:Buffer.from(child.raw).toString('base64'),ref:child.ref,payload:child.payload},proofOptions:savedOptions,response:Buffer.from(response).toString('base64')}));
}catch(error){process.stdout.write(JSON.stringify({ok:false,code:error.code??'untyped_error',detail:error.code?undefined:String(error.stack),
  calls,nativeChecks,subprocessCalls,callbacks,work:budget.snapshot()}));}finally{transport.close();}
"""


class OpenRepairOfferHTTPTypeScriptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ts_runtime.TypeScriptAgentNetworkTests.setUpClass.__func__(cls)
        (cls.fixture/'driver.mjs').write_text(DRIVER)
        (cls.fixture/'probe-driver.mjs').write_text(probe_ts.DRIVER)
        (cls.fixture/'proof-driver.mjs').write_text(proof_ts.DRIVER)

    def setUp(self):
        self.host=http_fixture.EmptyHTTPFixture(self)
        self.f=self.host.f

    def call(self,**extra):
        grant=json.loads(self.host.offer['raw'])['payload'];e=self.f['expected'];binding=self.host.expected
        return dict(base=self.host.http.base,signing=probe_ts.private_signing(self.f['signers']['writer']),
            encryption=self.f['encryption']['writer'].private_document(),ownerSigning=probe_ts.private_signing(self.f['signers']['owner']),owner=e['expected_owner'],
            limits=e['limit_policy'],policy=proof_ts.POLICY,entries={name:probe_ts.encoded(item) for name,item in
                [('root',self.f['entries']['root']),('write',self.host.write),('offer',self.host.offer)]},
            bound=dict(expectedAckSlot=e['expected_ack_slot'],expectedOwner=e['expected_owner'],expectedReceiptWriter=binding['expected_receipt_writer'],
                expectedMessageId=binding['expected_message_id'],expectedEnvelopeRef=binding['expected_envelope_ref']),
            options=dict(expectedSubject=binding['expected_receipt_writer'],expectedTarget=e['expected_target'],targetStorageEpoch=e['target_storage_epoch'],
                bootstrapGrantSha256=self.host.offer['ref']['raw_sha256'],selector=grant['selector'],at=2_000_000_007,consumer='ack_offer'),
            ownerSelector=json.loads(self.f['entries']['bootstrap']['raw'])['payload']['selector'],**extra)

    def run_native(self,value,driver='driver.mjs'):
        process=subprocess.run([self.node,'--experimental-strip-types',str(self.fixture/driver)],cwd=self.fixture,
            input=json.dumps(value).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=35)
        self.assertEqual(process.returncode,0,process.stderr.decode(errors='replace')[-5000:]);return json.loads(process.stdout)

    def ts(self,value):
        result=self.run_native(value);self.assertEqual(result['subprocessCalls'],0)
        self.assertEqual(result['nativeChecks'],result['work']['signature_checks']);return result

    def test_real_native_offer_mutual_possession_and_exact_child_after_restart(self):
        original=self.host.http.participant.handle_repair
        def restart_after_probe(raw):
            result=original(raw)
            if json.loads(raw)['payload']['kind']=='bootstrap.probe':self.host.http.restart()
            return result
        self.host.http.participant.handle_repair=restart_after_probe
        result=self.ts(self.call())
        self.assertTrue(result['ok'],result);self.assertEqual(result['nativeChecks'],7)
        self.assertEqual([item['kind'] for item in result['calls']],['bootstrap.probe','bootstrap.answer','bootstrap.proof_child_request'])
        self.assertTrue(all(item['path']=='/open/v1/repair/bootstrap' for item in result['calls']))
        self.assertEqual(result['consumer'],'ack_offer');self.assertEqual(result['manifest']['response_profile'],'ack_offer_service_v1')
        roles={item['role'] for item in result['manifest']['children']}
        self.assertTrue({'current.status.ack_write','current.status.ack_offer_bootstrap'}<=roles)
        self.assertTrue({'current.status.ack_read','current.status.ack_owner_bootstrap'}.isdisjoint(roles))
        self.assertEqual(len(result['manifest']['children']),22)
        self.assertEqual(base64.b64decode(result['raw']),self.host.result['binding']['raw'])
        self.assertEqual(result['selected']['ref'],self.host.result['binding']['ref'])
        self.assertEqual(result['child']['payload']['consumer'],'ack_offer')

    def test_owner_read_selector_cannot_be_used_for_offer_probe(self):
        call=self.call();call['options']['selector']=call['ownerSelector']
        result=self.ts(call);self.assertFalse(result['ok']);self.assertEqual(result['code'],'repair_invalid_probe');self.assertEqual(result['calls'],[])

    def test_wrong_owner_grant_digest_cannot_select_writer_authority(self):
        call=self.call();call['options']['bootstrapGrantSha256']=self.f['entries']['bootstrap']['ref']['raw_sha256']
        result=self.ts(call);self.assertFalse(result['ok']);self.assertEqual(result['code'],'open_request_rejected');self.assertEqual(len(result['calls']),1)

    def test_owner_cannot_reuse_offer_proof_consumer_or_child_identity(self):
        result=self.ts(self.call(proofConsumer='ack_owner'))
        self.assertFalse(result['ok']);self.assertEqual(result['code'],'repair_proof_mismatch');self.assertEqual(len(result['calls']),2)

    def test_owner_cannot_sign_child_for_a_real_writer_handle(self):
        result=self.ts(self.call(ownerChild=True))
        self.assertFalse(result['ok']);self.assertEqual(result['code'],'repair_proof_mismatch');self.assertEqual(len(result['calls']),2)

    def test_native_offer_target_can_issue_python_decryptable_challenge_and_verify_answer(self):
        c=self.call();options=c['options'];local=wire.RepairPolicy(**c['policy']);budget=wire.RepairBudget(local)
        py=dict(expected_subject=options['expectedSubject'],expected_target=options['expectedTarget'],target_storage_epoch=options['targetStorageEpoch'],
            bootstrap_grant_sha256=options['bootstrapGrantSha256'],selector=options['selector'],at=options['at'],consumer='ack_offer',policy=local,budget=budget)
        first=probe.make_bootstrap_probe(self.f['signers']['writer'],expires_at=options['at']+50,**py)
        base=dict(options=options,policy=c['policy'],subjectSigning=c['signing'],subjectEncryption=c['encryption'],
            targetSigning=probe_ts.private_signing(self.f['signers']['target']),targetEncryption=self.f['encryption']['target'].private_document())
        native=self.run_native([base|dict(op='issue',probe=probe_ts.encoded(first.original),expires=options['at']+40)],'probe-driver.mjs')[0]
        self.assertTrue(native['ok'],native);challenge=native['result']
        entry=lambda item:dict(raw=base64.b64decode(item['raw']),ref=item['ref'])
        answer=probe.solve_bootstrap_challenge(dict(raw=first.original.raw,ref=first.original.ref.as_dict()),entry(challenge['original']),
            signer=self.f['signers']['writer'],encryption_identity=self.f['encryption']['writer'],target_nonce=first.nonce,expires_at=options['at']+30,**py)
        call=base|dict(op='verify',probe=probe_ts.encoded(first.original),challenge=challenge['original'],answer=probe_ts.encoded(answer),callerNonce=challenge['nonce'])
        result=self.run_native([call],'probe-driver.mjs')[0];self.assertTrue(result['ok'],result);self.assertEqual(result['work']['signature_checks'],3)

    def test_closed_offer_container_rejects_owner_current_roles_and_unbound_phase(self):
        actual=self.ts(self.call());self.assertTrue(actual['ok'],actual)
        wrapper=json.loads(base64.b64decode(actual['response']));manifest=actual['manifest'];call=dict(op='verify',raw=actual['response'],options=actual['proofOptions'],policy=proof_ts.POLICY)
        calls=[call|dict(options=call['options']|{'expectedSourceState':'unbound'})]
        for mutation in ('current_roles','consumer','profile'):
            m=copy.deepcopy(manifest)
            if mutation=='current_roles':
                for row in m['children']:
                    if row['role']=='current.status.ack_write':row['role']='current.status.ack_read'
                    elif row['role']=='current.status.ack_offer_bootstrap':row['role']='current.status.ack_owner_bootstrap'
            elif mutation=='consumer':m['consumer']='ack_owner'
            else:m['response_profile']='ack_owner_service_v1'
            raw=canonical_bytes(m);h=json.loads(base64.urlsafe_b64decode(wrapper['handle_raw_base64url']+'==='))
            h['payload']['manifest_ref']=dict(namespace='meta',key=hashlib.sha256(raw).hexdigest(),raw_sha256=hashlib.sha256(raw).hexdigest(),size=len(raw))
            h['proof']=self.f['signers']['target'].sign_message(h['payload'])
            changed=canonical_bytes(wrapper|dict(handle_raw_base64url=base64.urlsafe_b64encode(canonical_bytes(h)).rstrip(b'=').decode(),manifest_raw_base64url=base64.urlsafe_b64encode(raw).rstrip(b'=').decode()))
            calls.append(call|dict(raw=base64.b64encode(changed).decode()))
        o=actual['proofOptions']
        calls.append(dict(op='make',manifest=manifest,options={},policy=proof_ts.POLICY,signer=probe_ts.private_signing(self.f['signers']['target']),
            makeOptions=dict(probeRef=o['probeRef'],challengeRef=o['challengeRef'],answerRef=o['answerRef'],subject=o['expectedSubject'],
                target=o['expectedTarget'],at=o['at'],expiresAt=o['at']+30,handleId='native_offer_container')))
        result=self.run_native(calls,'proof-driver.mjs')
        self.assertEqual([item['code'] for item in result[:-1]],['repair_invalid_proof','repair_invalid_proof','repair_proof_mismatch','repair_proof_mismatch'])
        self.assertTrue(result[-1]['ok'],result[-1])
        checked=proof.verify_bootstrap_proof_response(base64.b64decode(result[-1]['result']['raw']),expected_subject=o['expectedSubject'],
            expected_target=o['expectedTarget'],target_storage_epoch=o['targetStorageEpoch'],selector=o['selector'],bootstrap_grant_ref=o['bootstrapGrantRef'],
            probe_ref=o['probeRef'],challenge_ref=o['challengeRef'],answer_ref=o['answerRef'],at=o['at'],max_proof_items=o['maxProofItems'],
            max_proof_bytes=o['maxProofBytes'],expected_source_state='empty',consumer='ack_offer',policy=self.host.fixture.local,budget=wire.RepairBudget(self.host.fixture.local))
        self.assertEqual(checked.manifest.raw,canonical_bytes(manifest))


if __name__=='__main__':
    unittest.main()
