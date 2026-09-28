"""Real native owner HTTP recovery of message-bound empty ACK evidence."""
import base64
import copy
import hashlib
import json
import subprocess
import unittest
from unittest.mock import patch

from memory_vault import canonical_bytes
import memory_vault_open_repair_proof as proof
import memory_vault_open_repair_status as status
import memory_vault_open_repair_wire as wire
from memory_vault_open_repair_empty_access import RepairAckEmptyAccess
from tests import test_network_typescript_agent_network as ts_runtime
from tests import test_open_repair_empty_http as http_fixture
from tests import test_open_repair_proof_typescript as proof_ts
from tests.open_repair_ack_fixtures import signed_entry
from tests.test_open_repair_probe_typescript import encoded, private_signing

DRIVER=r"""
import child from 'node:child_process';
import crypto from 'node:crypto';
import {syncBuiltinESMExports} from 'node:module';
let subprocessCalls=0,nativeChecks=0;
const deny=()=>{subprocessCalls++;throw Error('native empty recovery must not delegate');};
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
  if(options?.child&&input.damage==='short')return value.subarray(0,value.length-1);
  if(options?.child&&input.damage==='corrupt'){value[0]^=1;return value;}
  return value;
};
let client;
try{
  client=new AckOwnerRecoveryClient(input.signing,input.encryption,{policy:{...DEFAULT_REPAIR_CLIENT_POLICY,...(input.policy??{})},
    limitPolicy:input.limits,allowLoopback:true,transport,clock:()=>2000000007});
  const options={targetNodeEntry:decode(input.entries.descriptor),expectedTarget:input.expected.expected_target,expectedAckSlot:input.expected.expected_ack_slot,
    rootEntry:decode(input.entries.root),readEntry:decode(input.entries.read),bootstrapEntry:decode(input.entries.bootstrap),
    knownStatuses:(input.known??[]).map(decode),archiveStatuses:(input.archive??[]).map(decode),timeout:30};
  if(!input.unbound)Object.assign(options,{expectedReceiptWriter:input.binding.expected_receipt_writer,
    expectedMessageId:input.binding.expected_message_id,expectedEnvelopeRef:input.binding.expected_envelope_ref});
  let callbacks=0;if(input.getter)Object.defineProperty(options,'expectedReceiptWriter',{get(){callbacks++;throw Error('getter');}});
  const pending=input.unbound?client.recover(input.base,options):client.recoverEmpty(input.base,options);
  if(input.mutate){input.binding.expected_receipt_writer.signing_key.public_key='changed';input.binding.expected_envelope_ref.key='0'.repeat(64);options.rootEntry.raw.fill(0);input.signing.private_key='changed';}
  const result=await pending,first=result.originals[0],held=Buffer.from(first.raw);first.raw.fill(0);
  const serialize=item=>({ref:item.ref,raw:Buffer.from(item.raw).toString('base64'),payload:item.payload});
  process.stdout.write(JSON.stringify({ok:true,stored_at:result.source.stored_at,metrics:result.metrics,roles:result.proof.manifest.value.children,
    profile:result.proof.manifest.value.response_profile,source:{custody:serialize(result.source.custody),binding:serialize(result.source.binding),
      write:serialize(result.source.authorities.originals.write),predecessor:serialize(result.source.predecessor.custody),
      originalOwnerProfile:result.source.predecessor.bootstrap.originals.bootstrap.payload.response_profile},
    originals:result.originals.map(serialize),statuses:result.current_statuses.map(serialize),
    immutable:Buffer.from(first.raw).equals(held)&&Object.isFrozen(result.originals)&&Object.isFrozen(result),calls,nativeChecks,subprocessCalls,callbacks}));
}catch(error){process.stdout.write(JSON.stringify({ok:false,code:error.code??'untyped_error',detail:error.code?undefined:String(error.stack),calls,nativeChecks,subprocessCalls}));}
finally{client?.close();transport.close();}
"""


class OpenRepairEmptyClientTypeScriptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ts_runtime.TypeScriptAgentNetworkTests.setUpClass.__func__(cls)
        (cls.fixture/'driver.mjs').write_text(DRIVER)
        (cls.fixture/'proof-driver.mjs').write_text(proof_ts.DRIVER)

    def setUp(self):
        self.host=http_fixture.EmptyHTTPFixture(self)
        self.f=self.host.f

    def call(self,**extra):
        return dict(base=self.host.http.base,signing=private_signing(self.f['signers']['owner']),
            encryption=self.f['encryption']['owner'].private_document(),limits=self.f['expected']['limit_policy'],
            expected=copy.deepcopy(self.f['expected']),entries={name:encoded(self.f['entries'][name]) for name in ('descriptor','root','read','bootstrap')},
            binding=copy.deepcopy({name:self.host.expected[name] for name in ('expected_receipt_writer','expected_message_id','expected_envelope_ref')}),**extra)

    def ts(self,call):
        process=subprocess.run([self.node,'--experimental-strip-types',str(self.fixture/'driver.mjs')],cwd=self.fixture,
            input=json.dumps(call).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=40)
        self.assertEqual(process.returncode,0,process.stderr.decode(errors='replace')[-5000:])
        result=json.loads(process.stdout);self.assertEqual(result['subprocessCalls'],0)
        return result

    def test_actual_native_recovery_after_restart_preserves_both_generations_and_exact_tuple(self):
        original=self.host.http.participant.handle_repair
        def restart_after_probe(raw):
            response=original(raw)
            if json.loads(raw)['payload']['kind']=='bootstrap.probe':self.host.http.restart()
            return response
        self.host.http.participant.handle_repair=restart_after_probe
        result=self.ts(self.call())
        self.assertTrue(result['ok'],result);self.assertTrue(result['immutable'])
        self.assertEqual((len(result['roles']),len(result['originals']),len(result['statuses'])),(22,12,2))
        self.assertEqual((result['metrics']['requests'],result['metrics']['signature_checks'],result['nativeChecks']),(14,30,30))
        self.assertEqual(result['profile'],'ack_owner_service_v1')
        self.assertEqual(result['source']['originalOwnerProfile'],'ack_owner_service_v1')
        prior_ref=next(row['document_ref'] for row in json.loads(self.host.result['manifest']['raw'])['roles'] if row['role']=='ack.unbound_custody')
        prior_raw=self.host.source.db.execute('SELECT raw FROM open_repair_ack_objects WHERE namespace=? AND opaque_key=?',
            (prior_ref['namespace'],prior_ref['key'])).fetchone()[0]
        for name,expected in (('custody',self.host.result['custody']),('binding',self.host.result['binding']),
                              ('write',self.host.write),('predecessor',dict(raw=bytes(prior_raw),ref=prior_ref))):
            self.assertEqual(result['source'][name]['raw'],encoded(expected)['raw'])
            self.assertEqual(result['source'][name]['ref'],expected['ref'])
        self.assertTrue(all(item['path']=='/open/v1/repair/bootstrap' for item in result['calls']))
        self.assertEqual(sum(item['role']=='history.raw_pack' for item in result['roles']),2)
        for item in result['originals']:
            raw=base64.b64decode(item['raw']);ref=item['ref']
            self.assertEqual((len(raw),hashlib.sha256(raw).hexdigest()),(ref['size'],ref['raw_sha256']))
            stored=self.host.source.db.execute('SELECT raw FROM open_repair_ack_objects WHERE namespace=? AND opaque_key=?',
                (ref['namespace'],ref['key'])).fetchone()
            self.assertIsNotNone(stored);self.assertEqual(raw,bytes(stored[0]))

    def test_expected_tuple_is_snapshotted_before_async_network(self):
        result=self.ts(self.call(mutate=True))
        self.assertTrue(result['ok'],result);self.assertTrue(result['immutable'])

    def test_independent_receipt_writer_mismatch_and_accessor_prevent_network(self):
        call=self.call();call['binding']['expected_receipt_writer']=call['expected']['expected_owner']
        result=self.ts(call);self.assertFalse(result['ok']);self.assertEqual(result['code'],'repair_ack_bound_mismatch');self.assertEqual(result['calls'],[])
        result=self.ts(self.call(getter=True));self.assertFalse(result['ok']);self.assertEqual(result['code'],'repair_unknown_fields');self.assertEqual(result['calls'],[])

    def test_independent_message_mismatch_rejected_after_real_source_recovery(self):
        call=self.call();call['binding']['expected_message_id']='msg_'+'be'*32
        result=self.ts(call);self.assertFalse(result['ok']);self.assertEqual(result['code'],'repair_ack_bound_mismatch');self.assertEqual(len(result['calls']),14)

    def test_independent_envelope_opaque_locator_mismatch_rejected(self):
        call=self.call();call['binding']['expected_envelope_ref']['key']='db'*32
        result=self.ts(call);self.assertFalse(result['ok']);self.assertEqual(result['code'],'repair_ack_bound_mismatch');self.assertEqual(len(result['calls']),14)

    def test_old_unbound_api_rejects_empty_roles_inside_the_same_owner_profile(self):
        result=self.ts(self.call(unbound=True));self.assertFalse(result['ok']);self.assertEqual(result['code'],'repair_proof_mismatch');self.assertEqual(len(result['calls']),2)

    def test_short_actual_http_child_does_not_produce_recovered_evidence(self):
        result=self.ts(self.call(damage='short'));self.assertFalse(result['ok']);self.assertEqual(result['code'],'repair_ref_mismatch');self.assertEqual(len(result['calls']),3)

    def test_known_archive_overlap_uses_one_budget_with_whole_extra_authority_scopes(self):
        known=[encoded(item) for item in self.host.expected['current_statuses']]
        result=self.ts(self.call(known=known,archive=known))
        self.assertTrue(result['ok'],result);self.assertEqual(result['nativeChecks'],32);self.assertEqual(result['metrics']['signature_checks'],32)

    def test_native_work_budget_cannot_reset_between_source_head_and_current_checks(self):
        result=self.ts(self.call(policy={'max_signature_checks':29}))
        self.assertFalse(result['ok']);self.assertEqual(result['code'],'repair_over_budget');self.assertEqual(result['nativeChecks'],29)

    def revocation(self,kind,scope_id=None):
        payload=json.loads(self.host.expected['current_statuses'][0]['raw'])['payload'];payload['revision']=3
        item=next(item for item in payload['entries'] if item['scope_kind']==kind and (scope_id is None or item['scope_id']==scope_id))
        item.update(status='revoked',operation_mask=2 if kind=='ack_slot' else 1)
        if kind=='authority':item['minimum_document_revision']=2
        return signed_entry(payload,self.f['signers']['owner'],'native-empty-revocation-'+kind)

    def revoke(self,kind,scope_id=None):
        changed=self.revocation(kind,scope_id)
        with self.assertRaises(wire.RepairWireError) as caught:
            self.host.empty.bind(self.host.source.resource_id,self.host.write,self.host.offer,
                **(self.host.expected|dict(current_statuses=[changed,self.host.expected['current_statuses'][1]])))
        self.assertEqual(caught.exception.code,'repair_authority_revoked')
        return changed

    def test_write_admit_revocation_remains_visible_while_owner_read_still_works(self):
        scope=status.status_scope(self.f['expected']['expected_ack_slot']['root_key'],'authority',
            dict(authority_kind='ack.write_grant',authority_sha256=self.host.write['ref']['raw_sha256']),
            self.host.fixture.local,wire.RepairBudget(self.host.fixture.local))
        revoked=self.revoke('authority',scope)
        result=self.ts(self.call(known=[encoded(revoked)]))
        self.assertTrue(result['ok'],result);self.assertEqual(result['nativeChecks'],31)
        owner=next(item['payload'] for item in result['statuses'] if item['payload']['scope_key']['issuer_key_id']==self.f['signers']['owner'].key_id)
        observed=next(item for item in owner['entries'] if item['scope_id']==scope)
        self.assertEqual((observed['status'],observed['minimum_document_revision']),('revoked',2))

    def test_live_owner_read_revocation_between_children_stops_real_native_http(self):
        original=self.host.http.participant.handle_repair;changed=[];revoked=self.revocation('ack_slot')
        def revoke_after_child(raw):
            response,child=original(raw)
            if child and not changed:
                with self.host.http.participant.state.db() as db:
                    service=self.host.http.participant._repair_service(db,json.loads(raw)['payload'])
                    prepared=service.access.prepare(self.host.source.resource_id,action='proof',
                        current_statuses=[revoked,self.host.expected['current_statuses'][1]])
                    with service.state._transaction():changed.append(service.access.check_locked(prepared).code)
            return response,child
        self.host.http.participant.handle_repair=revoke_after_child
        result=self.ts(self.call())
        self.assertFalse(result['ok']);self.assertEqual(result['code'],'open_request_rejected');self.assertEqual(len(result['calls']),4);self.assertEqual(changed,['repair_authority_revoked'])

    def test_deferred_unrelated_authority_history_rejected_after_actual_binding_is_known(self):
        payload=json.loads(self.host.expected['current_statuses'][0]['raw'])['payload']
        payload['entries'].append(dict(scope_kind='authority',scope_id='fe'*32,minimum_document_revision=0,status='active',operation_mask=1))
        payload['entries'].sort(key=lambda item:(item['scope_kind'],item['scope_id']))
        payload['revision']=3
        known=signed_entry(payload,self.f['signers']['owner'],'native-empty-unrelated-authority')
        result=self.ts(self.call(known=[encoded(known)]))
        self.assertFalse(result['ok']);self.assertEqual(result['code'],'repair_status_disclosure');self.assertEqual(len(result['calls']),14)

    def test_real_http_correctly_signed_but_wrong_empty_head_binding_is_rejected(self):
        payload=json.loads(self.host.result['head']['raw'])['payload']
        payload['binding_ref']=payload['binding_ref']|{'key':'0'*64}
        changed=signed_entry(payload,self.f['signers']['target'],'wrong-native-empty-head')
        original=RepairAckEmptyAccess.proof_inputs
        def changed_head(access,prepared):
            decision,children=original(access,prepared)
            children=tuple(dict(item,ref=wire.raw_ref(changed['ref']),raw=changed['raw']) if item['role']=='ack.head' else item for item in children)
            return decision,children
        with patch.object(RepairAckEmptyAccess,'proof_inputs',new=changed_head):
            result=self.ts(self.call())
        self.assertFalse(result['ok']);self.assertEqual(result['code'],'repair_ack_empty_mismatch');self.assertEqual(len(result['calls']),14)

    def test_real_http_extra_unreferenced_pack_is_refused_even_with_a_valid_handle(self):
        pack=wire.build_raw_pack([b'{}'],self.host.fixture.local,wire.RepairBudget(self.host.fixture.local))
        original=RepairAckEmptyAccess.proof_inputs
        def extra_pack(access,prepared):
            decision,children=original(access,prepared)
            return decision,(*children,dict(role='history.raw_pack',ref=pack.ref,raw=pack.raw))
        with patch.object(RepairAckEmptyAccess,'proof_inputs',new=extra_pack):
            result=self.ts(self.call())
        self.assertFalse(result['ok']);self.assertEqual(result['code'],'repair_unused_pack');self.assertEqual(len(result['calls']),15)

    def test_native_container_accepts_only_explicit_local_phase_and_closed_owner_profile(self):
        accepted=self.host.handshake();handle=json.loads(accepted.handle.raw);manifest=json.loads(accepted.manifest.raw)
        e=self.f['expected'];p=handle['payload']
        options=dict(expectedSubject=e['expected_owner'],expectedTarget=e['expected_target'],targetStorageEpoch=e['target_storage_epoch'],
            selector=manifest['selector'],bootstrapGrantRef=self.f['entries']['bootstrap']['ref'],probeRef=p['probe_ref'],
            challengeRef=p['challenge_ref'],answerRef=p['answer_ref'],at=2_000_000_007,maxProofItems=64,maxProofBytes=262144,expectedSourceState='empty')
        def packet(changed=None):
            m=copy.deepcopy(manifest if changed is None else changed)
            for index,item in enumerate(m['children']):item['index']=index
            raw=canonical_bytes(m);h=copy.deepcopy(handle)
            h['payload'].update(manifest_ref=dict(namespace='meta',key=hashlib.sha256(raw).hexdigest(),raw_sha256=hashlib.sha256(raw).hexdigest(),size=len(raw)),child_count=len(m['children']))
            h['proof']=self.f['signers']['target'].sign_message(h['payload'])
            return canonical_bytes(dict(schema_version=proof.SCHEMA,kind='bootstrap.proof_response',
                handle_raw_base64url=base64.urlsafe_b64encode(canonical_bytes(h)).rstrip(b'=').decode(),
                manifest_raw_base64url=base64.urlsafe_b64encode(raw).rstrip(b'=').decode()))
        call=dict(op='verify',raw=base64.b64encode(packet()).decode(),options=options,policy=proof_ts.POLICY)
        calls=[call,call|dict(options=options|{'expectedSourceState':'unbound'}),call|dict(options=options|{'expectedSourceState':'future'})]
        for change in ('wire_profile','missing_head','mixed_roles','one_pack','duplicate_pack'):
            m=copy.deepcopy(manifest)
            if change=='wire_profile':m['response_profile']='ack_owner_empty_service_v1'
            elif change=='missing_head':m['children']=[item for item in m['children'] if item['role']!='ack.head']
            elif change=='mixed_roles':next(item for item in m['children'] if item['role']=='ack.head')['role']='ack.read_grant'
            elif change=='one_pack':m['children'].remove(next(item for item in m['children'] if item['role']=='history.raw_pack'))
            else:
                packs=[item for item in m['children'] if item['role']=='history.raw_pack'];packs[1]['ref']=packs[0]['ref']
            calls.append(call|dict(raw=base64.b64encode(packet(m)).decode()))
        process=subprocess.run([self.node,'--experimental-strip-types',str(self.fixture/'proof-driver.mjs')],cwd=self.fixture,
            input=json.dumps(calls).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)
        self.assertEqual(process.returncode,0,process.stderr.decode(errors='replace')[-5000:]);results=json.loads(process.stdout)
        self.assertTrue(results[0]['ok'],results[0])
        self.assertEqual([item['code'] for item in results[1:]],['repair_proof_mismatch','repair_invalid_proof','repair_proof_mismatch',
            'repair_invalid_proof','repair_invalid_proof','repair_invalid_proof','repair_invalid_proof'])


if __name__=='__main__':
    unittest.main()
