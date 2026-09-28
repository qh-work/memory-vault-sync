"""Actual Node-to-Python receipt recovery with explicit recipient disclosure."""
import base64
import copy
import hashlib
import json
import subprocess
import unittest
from unittest.mock import patch

from memory_vault import canonical_bytes
from memory_vault_open_repair_occupied_access import RepairAckOccupiedAccess
import memory_vault_open_repair_proof as proof
import memory_vault_open_repair_status as status
import memory_vault_open_repair_wire as wire
from tests import test_network_typescript_agent_network as ts_runtime
from tests import test_open_repair_occupied_client as http_fixture
from tests import test_open_repair_proof_typescript as proof_ts
from tests.open_repair_ack_fixtures import signed_entry
from tests.test_open_repair_probe_typescript import encoded, private_signing

DRIVER=r"""
import child from 'node:child_process';
import crypto from 'node:crypto';
import {syncBuiltinESMExports} from 'node:module';
let subprocessCalls=0,nativeChecks=0;
const deny=()=>{subprocessCalls++;throw Error('occupied recovery must be native');};
for(const name of ['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork'])child[name]=deny;
const originalVerify=crypto.verify;crypto.verify=(...args)=>{nativeChecks++;return originalVerify(...args);};syncBuiltinESMExports();
const {AckOwnerRecoveryClient,DEFAULT_REPAIR_CLIENT_POLICY}=await import('./open-repair-client.ts');
const {OpenHTTPTransport,REPAIR_PATH}=await import('./open-transport.ts');
const chunks=[];let size=0;for await(const chunk of process.stdin){size+=chunk.length;if(size>1048576)throw Error('synthetic input limit');chunks.push(chunk);}
const input=JSON.parse(Buffer.concat(chunks).toString('utf8')),decode=item=>({raw:Buffer.from(item.raw,'base64'),ref:item.ref});
const calls=[],transport=new OpenHTTPTransport({allow_loopback:true}),request=transport.requestRepair.bind(transport);
transport.requestRepair=async(base,raw,deadline,options)=>{
  calls.push({base,path:REPAIR_PATH,kind:JSON.parse(Buffer.from(raw).toString('utf8')).payload?.kind,child:options?.child??false});
  const value=await request(base,raw,deadline,options);
  if(options?.child&&input.damage==='receipt'&&Buffer.from(value).equals(Buffer.from(input.receipt,'base64')))value[0]^=1;
  return value;
};
let client;
try{
  client=new AckOwnerRecoveryClient(input.signing,input.encryption,{policy:{...DEFAULT_REPAIR_CLIENT_POLICY,...(input.policy??{})},
    limitPolicy:input.limits,allowLoopback:true,transport,clock:()=>2000000008});
  const options={targetNodeEntry:decode(input.entries.descriptor),expectedTarget:input.expected.expected_target,expectedAckSlot:input.expected.expected_ack_slot,
    rootEntry:decode(input.entries.root),readEntry:decode(input.entries.read),bootstrapEntry:decode(input.entries.bootstrap),
    expectedReceiptWriter:input.binding.expected_receipt_writer,expectedMessageId:input.binding.expected_message_id,expectedEnvelopeRef:input.binding.expected_envelope_ref,
    knownStatuses:(input.known??[]).map(decode),archiveStatuses:(input.archive??[]).map(decode),timeout:30};
  const pending=input.empty?client.recoverEmpty(input.base,options):client.recoverOccupied(input.base,options);
  if(input.mutate){input.binding.expected_receipt_writer.signing_key.public_key='changed';input.binding.expected_envelope_ref.key='changed';options.rootEntry.raw.fill(0);input.signing.private_key='changed';}
  const result=await pending,first=result.originals[0],held=Buffer.from(first.raw);first.raw.fill(0);
  const serialize=item=>({ref:item.ref,raw:Buffer.from(item.raw).toString('base64'),payload:item.payload});
  process.stdout.write(JSON.stringify({ok:true,stored_at:result.source.stored_at,metrics:result.metrics,roles:result.proof.manifest.value.children,
    profile:result.proof.manifest.value.response_profile,source:{commit:serialize(result.source.commit),
      inputs:Object.fromEntries(Object.entries(result.source.inputs).map(([role,item])=>[role,serialize(item)])),
      empty:serialize(result.source.predecessor.custody),unbound:serialize(result.source.predecessor.predecessor.custody),
      originalOwnerProfile:result.source.predecessor.predecessor.bootstrap.originals.bootstrap.payload.response_profile},
    originals:result.originals.map(serialize),statuses:result.current_statuses.map(serialize),
    immutable:Buffer.from(first.raw).equals(held)&&Object.isFrozen(result.originals)&&Object.isFrozen(result),calls,nativeChecks,subprocessCalls}));
}catch(error){process.stdout.write(JSON.stringify({ok:false,code:error.code??'untyped_error',detail:error.code?undefined:String(error.stack),calls,nativeChecks,subprocessCalls}));}
finally{client?.close();transport.close();}
"""


class OpenRepairOccupiedClientTypeScriptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ts_runtime.TypeScriptAgentNetworkTests.setUpClass.__func__(cls)
        (cls.fixture/'driver.mjs').write_text(DRIVER)
        (cls.fixture/'proof-driver.mjs').write_text(proof_ts.DRIVER)

    def start(self,full_return=True):
        self.host=http_fixture.OccupiedHTTPFixture(self,full_return=full_return);self.f=self.host.f

    def call(self,**extra):
        return copy.deepcopy(dict(base=self.host.http.base,signing=private_signing(self.f['signers']['owner']),
            encryption=self.f['encryption']['owner'].private_document(),limits=self.f['expected']['limit_policy'],
            expected=self.f['expected'],entries={name:encoded(self.f['entries'][name]) for name in ('descriptor','root','read','bootstrap')},
            binding={name:self.host.empty.expected[name] for name in ('expected_receipt_writer','expected_message_id','expected_envelope_ref')},
            receipt=encoded(self.host.receipt)['raw'],**extra))

    def ts(self,call):
        process=subprocess.run([self.node,'--experimental-strip-types',str(self.fixture/'driver.mjs')],cwd=self.fixture,
            input=json.dumps(call).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=40)
        self.assertEqual(process.returncode,0,process.stderr.decode(errors='replace')[-5000:])
        result=json.loads(process.stdout);self.assertEqual(result['subprocessCalls'],0);return result

    def test_real_http_restart_exact_receipt_three_generations_one_native_budget(self):
        self.start();original=self.host.http.participant.handle_repair
        def restart_after_probe(raw):
            response=original(raw)
            if json.loads(raw)['payload']['kind']=='bootstrap.probe':self.host.http.restart()
            return response
        self.host.http.participant.handle_repair=restart_after_probe
        result=self.ts(self.call(mutate=True))
        self.assertTrue(result['ok'],result);self.assertTrue(result['immutable'])
        self.assertEqual(len(result['roles']),25);self.assertEqual(sum(row['role']=='history.raw_pack' for row in result['roles']),3)
        self.assertEqual((result['metrics']['signature_checks'],result['nativeChecks']),(39,39))
        self.assertEqual(result['metrics']['requests'],len(result['originals'])+2);self.assertEqual(len(result['statuses']),3)
        self.assertEqual(result['profile'],'ack_owner_service_v1');self.assertEqual(result['source']['originalOwnerProfile'],'ack_owner_service_v1')
        for name,expected in (('receipt',self.host.receipt),('disclosure',self.host.disclosure),('put',self.host.put)):
            self.assertEqual(result['source']['inputs'][name]['raw'],encoded(expected)['raw']);self.assertEqual(result['source']['inputs'][name]['ref'],expected['ref'])
        self.assertEqual(result['source']['commit']['raw'],encoded(self.host.result['commit'])['raw'])
        self.assertEqual(result['source']['empty']['raw'],encoded(self.host.empty.result['custody'])['raw'])
        self.assertEqual(result['source']['inputs']['receipt']['ref']['namespace'],'object')
        self.assertNotEqual(self.host.receipt['ref']['key'],self.host.receipt['ref']['raw_sha256'])
        self.assertTrue(all(item['path']=='/open/v1/repair/bootstrap' for item in result['calls']))
        for item in result['originals']:
            raw=base64.b64decode(item['raw']);ref=item['ref'];self.assertEqual((len(raw),hashlib.sha256(raw).hexdigest()),(ref['size'],ref['raw_sha256']))
            stored=self.host.source.db.execute('SELECT raw FROM open_repair_ack_objects WHERE namespace=? AND opaque_key=?',(ref['namespace'],ref['key'])).fetchone()
            self.assertIsNotNone(stored);self.assertEqual(raw,bytes(stored[0]))

    def test_old_two_role_disclosure_stops_at_server_before_proof(self):
        self.start(full_return=False);result=self.ts(self.call())
        self.assertFalse(result['ok']);self.assertEqual(result['code'],'open_request_rejected');self.assertEqual(len(result['calls']),1)

    def test_client_independently_refuses_old_two_role_disclosure_from_misbehaving_source(self):
        self.start(full_return=False);prepare=RepairAckOccupiedAccess.prepare
        # A deliberately noncompliant synthetic server sends its valid old
        # originals. The native reader must enforce B's narrower signed grant.
        def bypass_server_return_gate(access,*args,**kwargs):
            prepared=prepare(access,*args,**kwargs)
            held=access._prepared[prepared]
            if held['code']=='repair_disclosure_bootstrap_unsupported':held['code']=None
            return prepared
        with patch.object(RepairAckOccupiedAccess,'prepare',new=bypass_server_return_gate):result=self.ts(self.call())
        self.assertFalse(result['ok'],result);self.assertEqual(result['code'],'repair_disclosure_permission');self.assertGreater(len(result['calls']),2)

    def test_expired_archived_b_read_revocation_and_old_fork_prevent_any_probe(self):
        self.start();p=json.loads(self.host.options['current_statuses'][-1]['raw'])['payload'];p.update(revision=2,issued_at=2_000_000_007,valid_until=2_000_000_008)
        p['entries'][0].update(status='revoked',operation_mask=2);revoked=signed_entry(p,self.f['signers']['writer'],'expired-B-revocation')
        result=self.ts(self.call(archive=[encoded(revoked)]));self.assertFalse(result['ok']);self.assertEqual(result['code'],'repair_authority_revoked');self.assertEqual(result['calls'],[])
        p=json.loads(self.host.options['current_statuses'][-1]['raw'])['payload'];p['valid_until']-=1;fork=signed_entry(p,self.f['signers']['writer'],'B-old-revision-fork')
        result=self.ts(self.call(archive=[encoded(self.host.options['current_statuses'][-1]),encoded(fork)]))
        self.assertFalse(result['ok']);self.assertEqual(result['code'],'repair_status_conflict');self.assertEqual(result['calls'],[])

    def test_known_archive_overlap_keeps_b_current_status_and_uses_one_budget(self):
        self.start();entries=[encoded(item) for item in self.host.options['current_statuses']]
        result=self.ts(self.call(known=entries,archive=entries));self.assertTrue(result['ok'],result)
        self.assertEqual((result['nativeChecks'],result['metrics']['signature_checks']),(42,42));self.assertLessEqual(result['nativeChecks'],64)
        self.assertEqual({item['payload']['scope_key']['issuer_key_id'] for item in result['statuses']},
            {self.f['signers'][who].key_id for who in ('owner','target','writer')})

    def test_independent_message_cannot_reinterpret_actual_receipt(self):
        self.start();call=self.call();call['binding']['expected_message_id']='msg_'+'dd'*32
        result=self.ts(call);self.assertFalse(result['ok']);self.assertEqual(result['code'],'repair_ack_bound_mismatch');self.assertGreater(len(result['calls']),2)

    def test_independent_envelope_opaque_locator_is_not_rewritten(self):
        self.start();call=self.call();call['binding']['expected_envelope_ref']['key']='de'*32
        result=self.ts(call);self.assertFalse(result['ok']);self.assertEqual(result['code'],'repair_ack_bound_mismatch');self.assertGreater(len(result['calls']),2)

    def test_wrong_independent_dual_writer_stops_before_network(self):
        self.start();call=self.call();call['binding']['expected_receipt_writer']['encryption_key']=call['expected']['expected_owner']['encryption_key']
        result=self.ts(call);self.assertFalse(result['ok']);self.assertEqual(result['code'],'repair_ack_bound_mismatch');self.assertEqual(result['calls'],[])

    def test_occupied_roles_cannot_be_consumed_as_empty(self):
        self.start();result=self.ts(self.call(empty=True));self.assertFalse(result['ok']);self.assertEqual(result['code'],'repair_proof_mismatch');self.assertEqual(len(result['calls']),2)

    def test_corrupt_real_receipt_response_fails_exact_hash_binding(self):
        self.start();result=self.ts(self.call(damage='receipt'));self.assertFalse(result['ok']);self.assertEqual(result['code'],'repair_ref_mismatch')
        self.assertEqual(self.host.verify().inputs['receipt'].raw,self.host.receipt['raw'])

    def observe(self,entries):
        gate=RepairAckOccupiedAccess(self.host.source.state);gate.initialize();prepared=gate.prepare(self.host.source.resource_id,action='proof',current_statuses=entries)
        with self.host.source.state._transaction():return gate.check_locked(prepared)

    def test_write_admit_revocation_does_not_revoke_owner_receipt_read(self):
        self.start();p=json.loads(self.host.options['current_statuses'][0]['raw'])['payload'];p['revision']=3
        scope=status.status_scope(self.f['expected']['expected_ack_slot']['root_key'],'authority',dict(authority_kind='ack.write_grant',authority_sha256=self.host.empty.write['ref']['raw_sha256']),
            self.host.source.state.policy,wire.RepairBudget(self.host.source.state.policy))
        next(row for row in p['entries'] if row['scope_id']==scope).update(status='revoked',operation_mask=1,minimum_document_revision=2)
        revoked=signed_entry(p,self.f['signers']['owner'],'occupied-write-revoked')
        decision=self.observe([revoked,*self.host.options['current_statuses'][1:]]);self.assertTrue(decision.allowed,decision.code)
        result=self.ts(self.call(known=[encoded(revoked)]));self.assertTrue(result['ok'],result);self.assertEqual(result['nativeChecks'],40)

    def test_midstream_b_read_revocation_stops_actual_child_delivery(self):
        self.start();original=self.host.http.participant.handle_repair;changed=[]
        p=json.loads(self.host.options['current_statuses'][-1]['raw'])['payload'];p['revision']=2;p['entries'][0].update(status='revoked',operation_mask=2)
        revoked=signed_entry(p,self.f['signers']['writer'],'midstream-B-revoke')
        def revoke_after_child(raw):
            response,child=original(raw)
            if child and not changed:
                with self.host.http.participant.state.db() as db:
                    service=self.host.http.participant._repair_service(db,json.loads(raw)['payload'])
                    prepared=service.access.prepare(self.host.source.resource_id,action='proof',current_statuses=[*self.host.options['current_statuses'][:-1],revoked])
                    with service.state._transaction():changed.append(service.access.check_locked(prepared).code)
            return response,child
        self.host.http.participant.handle_repair=revoke_after_child
        result=self.ts(self.call());self.assertFalse(result['ok']);self.assertEqual(result['code'],'open_request_rejected');self.assertEqual(len(result['calls']),4)
        self.assertEqual(changed,['repair_authority_revoked'])

    def test_known_b_authority_must_match_recovered_consent_scope(self):
        self.start();p=json.loads(self.host.options['current_statuses'][-1]['raw'])['payload'];p['revision']=2;p['entries'][0]['scope_id']='fd'*32
        unrelated=signed_entry(p,self.f['signers']['writer'],'unrelated-B-authority')
        result=self.ts(self.call(archive=[encoded(unrelated)]));self.assertFalse(result['ok']);self.assertEqual(result['code'],'repair_status_disclosure');self.assertGreater(len(result['calls']),2)

    def test_target_signed_wrong_head_receipt_ref_is_rejected(self):
        self.start();p=json.loads(self.host.result['head']['raw'])['payload'];p['receipt_ref']=p['receipt_ref']|{'key':'other-receipt'}
        changed=signed_entry(p,self.f['signers']['target'],'wrong-occupied-head');original=RepairAckOccupiedAccess.proof_inputs
        def changed_head(access,prepared):
            decision,children=original(access,prepared)
            return decision,tuple(dict(item,ref=wire.raw_ref(changed['ref']),raw=changed['raw']) if item['role']=='ack.head' else item for item in children)
        with patch.object(RepairAckOccupiedAccess,'proof_inputs',new=changed_head):result=self.ts(self.call())
        self.assertFalse(result['ok']);self.assertEqual(result['code'],'repair_ack_occupied_mismatch')

    def test_target_signed_extra_unreferenced_pack_is_rejected(self):
        self.start();policy=self.host.source.state.policy;pack=wire.build_raw_pack([b'{}'],policy,wire.RepairBudget(policy))
        original=RepairAckOccupiedAccess.proof_inputs
        def extra_pack(access,prepared):
            decision,children=original(access,prepared)
            return decision,(*children,dict(role='history.raw_pack',ref=pack.ref,raw=pack.raw))
        with patch.object(RepairAckOccupiedAccess,'proof_inputs',new=extra_pack):result=self.ts(self.call())
        self.assertFalse(result['ok']);self.assertEqual(result['code'],'repair_unused_pack')

    def test_client_rejects_actual_signed_b_read_denial_supplied_as_current_child(self):
        self.start();p=json.loads(self.host.options['current_statuses'][-1]['raw'])['payload'];p['revision']=2;p['entries'][0].update(status='revoked',operation_mask=2)
        denied=signed_entry(p,self.f['signers']['writer'],'current-B-denial');original=RepairAckOccupiedAccess.proof_inputs
        def denial_child(access,prepared):
            decision,children=original(access,prepared)
            return decision,tuple(dict(item,ref=wire.raw_ref(denied['ref']),raw=denied['raw']) if item['role']=='current.status.ack_disclosure' else item for item in children)
        with patch.object(RepairAckOccupiedAccess,'proof_inputs',new=denial_child):result=self.ts(self.call())
        self.assertFalse(result['ok']);self.assertEqual(result['code'],'repair_authority_revoked')

    def test_every_signature_shares_default_budget_without_resets(self):
        self.start();result=self.ts(self.call(policy={'max_signature_checks':38}));self.assertFalse(result['ok'])
        self.assertEqual(result['code'],'repair_over_budget');self.assertEqual(result['nativeChecks'],38)

    def test_native_occupied_container_phase_roles_namespace_and_python_roundtrip(self):
        self.start();fixture=self.host.empty.fixture;first=fixture.make_probe();challenge=self.host.http.control(self.host.http.send(first.original.raw))
        answer=fixture.solve(first,challenge);response=self.host.http.send(answer.raw)
        wrapper=json.loads(response);manifest=json.loads(base64.urlsafe_b64decode(wrapper['manifest_raw_base64url']+'=='));handle=json.loads(base64.urlsafe_b64decode(wrapper['handle_raw_base64url']+'=='))
        e=self.f['expected'];p=handle['payload']
        options=dict(expectedSubject=e['expected_owner'],expectedTarget=e['expected_target'],targetStorageEpoch=e['target_storage_epoch'],
            selector=manifest['selector'],bootstrapGrantRef=self.f['entries']['bootstrap']['ref'],probeRef=p['probe_ref'],
            challengeRef=p['challenge_ref'],answerRef=p['answer_ref'],at=2_000_000_008,maxProofItems=64,maxProofBytes=262144,expectedSourceState='occupied')
        call=dict(op='verify',raw=base64.b64encode(response).decode(),options=options,policy=proof_ts.POLICY)
        calls=[call,call|dict(options=options|{'expectedSourceState':'empty'}),call|dict(options=options|{'expectedSourceState':'unbound'})]
        def packet(value):
            m=copy.deepcopy(value)
            for index,item in enumerate(m['children']):item['index']=index
            raw=canonical_bytes(m);h=copy.deepcopy(handle);h['payload'].update(child_count=len(m['children']),manifest_ref=dict(namespace='meta',
                key=hashlib.sha256(raw).hexdigest(),raw_sha256=hashlib.sha256(raw).hexdigest(),size=len(raw)))
            h['proof']=self.f['signers']['target'].sign_message(h['payload'])
            return canonical_bytes(dict(schema_version=proof.SCHEMA,kind='bootstrap.proof_response',
                handle_raw_base64url=base64.urlsafe_b64encode(canonical_bytes(h)).rstrip(b'=').decode(),manifest_raw_base64url=base64.urlsafe_b64encode(raw).rstrip(b'=').decode()))
        for change in ('old_profile','missing_disclosure_status','missing_put','two_packs','object_status'):
            m=copy.deepcopy(manifest)
            if change=='old_profile':m['response_profile']='ack_owner_occupied_service_v1'
            elif change=='missing_disclosure_status':m['children']=[row for row in m['children'] if row['role']!='current.status.ack_disclosure']
            elif change=='missing_put':m['children']=[row for row in m['children'] if row['role']!='ack.put']
            elif change=='two_packs':m['children'].remove(next(row for row in m['children'] if row['role']=='history.raw_pack'))
            else:next(row for row in m['children'] if row['role']=='current.status.ack_disclosure')['ref']['namespace']='object'
            calls.append(call|dict(raw=base64.b64encode(packet(m)).decode()))
        calls.append(call|dict(op='make',signer=private_signing(self.f['signers']['target']),manifest=manifest,
            makeOptions=dict(subject=e['expected_owner'],target=e['expected_target'],probeRef=p['probe_ref'],challengeRef=p['challenge_ref'],answerRef=p['answer_ref'],
                at=2_000_000_008,expiresAt=2_000_000_030,handleId='native-occupied-roundtrip')))
        process=subprocess.run([self.node,'--experimental-strip-types',str(self.fixture/'proof-driver.mjs')],cwd=self.fixture,
            input=json.dumps(calls).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
        self.assertEqual(process.returncode,0,process.stderr.decode(errors='replace')[-5000:]);results=json.loads(process.stdout)
        self.assertTrue(results[0]['ok'],results[0]);self.assertTrue(all(not row['ok'] for row in results[1:-1]));self.assertTrue(results[-1]['ok'],results[-1])
        self.assertEqual([row['code'] for row in results[1:4]],['repair_proof_mismatch']*3)
        native=base64.b64decode(results[-1]['result']['raw']);policy=wire.RepairPolicy(**proof_ts.POLICY)
        accepted=proof.verify_bootstrap_proof_response(native,expected_subject=e['expected_owner'],expected_target=e['expected_target'],
            target_storage_epoch=e['target_storage_epoch'],selector=manifest['selector'],bootstrap_grant_ref=self.f['entries']['bootstrap']['ref'],
            probe_ref=p['probe_ref'],challenge_ref=p['challenge_ref'],answer_ref=p['answer_ref'],at=2_000_000_008,max_proof_items=64,max_proof_bytes=262144,
            expected_source_state='occupied',policy=policy,budget=wire.RepairBudget(policy))
        self.assertEqual(accepted.manifest.value,manifest)


if __name__=='__main__':unittest.main()
