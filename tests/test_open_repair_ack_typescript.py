"""Native source-custody event authentication using synthetic original bytes."""
import base64
import copy
import hashlib
import json
import subprocess
import unittest

from memory_vault import canonical_bytes
from tests import test_network_typescript_agent_network as ts_runtime
from tests import test_open_contact as contact_fixture
import memory_vault_open_repair_wire as wire
from tests.open_repair_ack_fixtures import ack_unbound_fixture, repack_fixture, signed_entry, reference, load_fixture

POLICY=dict(max_document_bytes=524288,max_total_bytes=33554432,max_nodes=1000000,max_depth=100,
            max_string_bytes=131072,max_hash_bytes=16777216,max_hashes=1000,max_entries=1000,
            max_retained_bytes=4194304,max_signature_checks=100)
DRIVER=r"""
import * as a from './open-repair-ack.ts';
import * as o from './open-repair-original.ts';
import * as w from './open-repair-wire.ts';
const chunks=[];for await(const chunk of process.stdin)chunks.push(chunk);
const calls=JSON.parse(Buffer.concat(chunks).toString('utf8')),results=[];
const decode=value=>({raw:Buffer.from(value.raw,'base64'),ref:value.ref});
for(const c of calls){let budget,callbacks=0;try{
  budget=new w.RepairBudget(c.policy);const options={...c.options,policy:c.policy,budget};
  if(c.host==='getter')Object.defineProperty(options,'expectedAckSlot',{get(){callbacks++;throw Error('getter');}});
  if(c.host==='proxy')options.expectedOwner=new Proxy(options.expectedOwner,{getOwnPropertyDescriptor(){callbacks++;throw Error('proxy');}});
  if(c.op==='node'){
    const result=o.verifySourceNodeOriginal(Buffer.from(c.raw,'base64'),options);
    results.push({ok:true,result:{payload:result.payload,raw_sha256:result.raw_sha256},work:budget.snapshot()});continue;
  }
  const resolver=new w.LocalRawResolver(c.policy,budget);
  for(const pack of c.packs??[]){const entry=decode(pack);resolver.put(entry.ref.namespace,entry.ref.key,entry.raw);}
  const value=a.verifyAckUnboundSourceEvent(decode(c.manifest),resolver,decode(c.custody),options);
  let immutable=true;
  if(c.mutate){options.expectedAckSlot.slot_id='changed';const raw=value.custody.raw;raw.fill(0);immutable=value.custody.raw[0]===123&&value.custody.payload.ack_slot.slot_id!=='changed';}
  results.push({ok:true,result:{stored_at:value.stored_at,read_until:value.read_until,retain_until:value.retain_until,
    status_count:value.statuses.length,custody_ref:value.custody.ref,immutable,frozen:Object.isFrozen(value)&&Object.isFrozen(value.statuses)},work:budget.snapshot()});
}catch(e){results.push({ok:false,code:e.code??'untyped_error',callbacks,work:budget?.snapshot()});}}
process.stdout.write(JSON.stringify(results));
"""


def encoded(entry):
    return dict(raw=base64.b64encode(entry['raw']).decode(),ref=entry['ref'])


class OpenRepairAckTypeScriptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ts_runtime.TypeScriptAgentNetworkTests.setUpClass.__func__(cls)
        (cls.fixture/'driver.mjs').write_text(DRIVER)

    def ts(self,calls):
        run=subprocess.run([self.node,'--experimental-strip-types',str(self.fixture/'driver.mjs')],cwd=self.fixture,
            input=json.dumps(calls).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
        self.assertEqual(run.returncode,0,run.stderr.decode(errors='replace')[-5000:]);return json.loads(run.stdout)

    def call(self,fixture,policy=None,**extra):
        options={''.join([parts[0]]+[part.title() for part in parts[1:]]):value
                 for name,value in fixture['expected'].items() for parts in [name.split('_')]}
        return dict(manifest=encoded(fixture['manifest']),custody=encoded(fixture['custody']),packs=[encoded(pack) for pack in fixture['packs']],
                    options=options,policy=policy or POLICY,**extra)

    def test_real_original_node_wrapper_keeps_epoch_and_historical_time_validation(self):
        py=contact_fixture.OpenContactProtocolTests('test_valid_opt_in_request_and_explicit_finite_delivery_decision')
        self.addCleanup(py.doCleanups);py.setUp()
        raw=canonical_bytes(py.node)
        call=dict(op='node',raw=base64.b64encode(raw).decode(),policy=POLICY,
                  options=dict(expectedSigningKey=py.server.public_descriptor(),expectedStorageEpoch='synthetic_epoch',at=py.now))
        epoch={**call,'options':{**call['options'],'expectedStorageEpoch':'wrong'}}
        expired={**call,'options':{**call['options'],'at':py.now+3600}}
        valid,bad,late=self.ts([call,epoch,expired])
        self.assertTrue(valid['ok'],valid);self.assertEqual(valid['work']['signature_checks'],1)
        self.assertEqual(valid['work']['hashes'],5)
        self.assertEqual(valid['result']['raw_sha256'],hashlib.sha256(raw).hexdigest())
        self.assertEqual(bad['code'],'repair_original_mismatch');self.assertEqual(late['code'],'repair_invalid_original')

    def test_complete_thirteen_role_event_authenticates_and_groups_status_originals(self):
        fixture=ack_unbound_fixture()
        result=self.ts([self.call(fixture,mutate=True)])[0]
        self.assertTrue(result['ok'],result)
        self.assertEqual(result['result']['status_count'],2)
        self.assertEqual(result['work']['signature_checks'],13)
        self.assertEqual(result['result']['stored_at'],2_000_000_006)
        self.assertEqual(result['result']['read_until'],2_000_000_800)
        self.assertEqual(result['result']['retain_until'],2_000_000_950)
        self.assertTrue(result['result']['immutable']);self.assertTrue(result['result']['frozen'])

    def test_complete_event_matches_python_real_work_and_original_custody(self):
        import memory_vault_open_repair_ack as ack
        fixture=ack_unbound_fixture();local=wire.RepairPolicy(**POLICY)
        resolver,local,budget=load_fixture(fixture,local)
        expected=ack.verify_ack_unbound_source_event(fixture['manifest'],resolver,fixture['custody'],
            **fixture['expected'],policy=local,budget=budget)
        actual=self.ts([self.call(fixture)])[0];self.assertTrue(actual['ok'],actual)
        self.assertEqual(actual['result']['custody_ref'],expected.custody.ref.as_dict())
        self.assertEqual(actual['result']['stored_at'],expected.stored_at)
        self.assertEqual(actual['result']['status_count'],len(expected.statuses))
        for field in ('signature_checks','hashes','hash_bytes'):
            self.assertEqual(actual['work'][field],budget.snapshot()[field],field)

    def test_custody_real_signature_and_canonical_shape_gate_the_event(self):
        calls=[]
        for variant in ('signature','whitespace','future_body'):
            fixture=ack_unbound_fixture();document=json.loads(fixture['custody']['raw'])
            if variant=='signature':
                document['proof']['signature']=base64.b64encode(bytes(64)).decode()
                raw=canonical_bytes(document)
            elif variant=='whitespace':raw=b' '+fixture['custody']['raw']
            else:
                document['payload']['binding_ref']={}
                document['proof']=fixture['signers']['target'].sign_message(document['payload'])
                raw=canonical_bytes(document)
            fixture['custody']=dict(raw=raw,ref=reference(raw,'bad_custody'));calls.append(self.call(fixture))
        actual=self.ts(calls)
        self.assertEqual(actual[0]['code'],'repair_invalid_signature')
        self.assertEqual(actual[0]['work']['signature_checks'],1)
        self.assertFalse(actual[1]['ok']);self.assertEqual(actual[1]['work']['signature_checks'],0)
        self.assertEqual(actual[2]['code'],'repair_invalid_ack');self.assertEqual(actual[2]['work']['signature_checks'],0)

    def test_independent_slot_owner_target_epoch_and_no_caller_event_time(self):
        fixture=ack_unbound_fixture();calls=[]
        for name in ('slot','owner','target','epoch','at'):
            call=self.call(fixture);options=copy.deepcopy(call['options']);call['options']=options
            if name=='slot':options['expectedAckSlot']['grant_id']='another_future_grant'
            elif name=='owner':options['expectedOwner']=options['expectedTarget']
            elif name=='target':options['expectedTarget']=options['expectedOwner']
            elif name=='epoch':options['targetStorageEpoch']='another_epoch'
            else:options['at']=2_000_000_006
            calls.append(call)
        for actual in self.ts(calls):
            self.assertFalse(actual['ok'],actual);self.assertNotEqual(actual['code'],'untyped_error')

    def test_exact_role_closure_and_manifest_custody_reference(self):
        calls=[]
        for change in ('missing','extra','manifest_ref','manifest_bytes'):
            fixture=ack_unbound_fixture()
            if change in ('missing','extra'):
                roles=dict(fixture['role_map'])
                if change=='missing':del roles['historical.status.ack_slot']
                else:roles['ack.write_grant']='read'
                repack_fixture(fixture,roles=roles)
            elif change=='manifest_ref':fixture['manifest']['ref']['key']='a'*64
            else:fixture['manifest']['raw']=fixture['manifest']['raw'][:-1]+b' '
            calls.append(self.call(fixture))
        for actual in self.ts(calls):
            self.assertFalse(actual['ok'],actual);self.assertNotEqual(actual['code'],'untyped_error')

    def test_custody_promises_and_original_chronology_are_closed(self):
        variants=[{'custody':{'read_until':2_000_000_901}},
                  {'custody':{'retain_until':2_000_001_001}},
                  {'custody':{'stored_at':2_000_000_004}},
                  {'bootstrap':{'issued_at':2_000_000_005}},
                  {'descriptor':{'storage_epoch':'different_epoch'}}]
        actual=self.ts([self.call(ack_unbound_fixture(changes=change)) for change in variants])
        for result in actual:
            self.assertFalse(result['ok'],result);self.assertNotEqual(result['code'],'untyped_error')
        self.assertEqual(actual[-1]['code'],'repair_original_mismatch')

    def split_owner_status(self,fixture,first_changes=None,second_changes=None):
        first=copy.deepcopy(fixture['docs']['owner_status']['payload'])
        second=copy.deepcopy(first);second['revision']=2
        if first_changes:first_changes(first)
        if second_changes:second_changes(second)
        fixture['entries']['owner_status']=signed_entry(first,fixture['signers']['owner'],'owner_status')
        fixture['entries']['owner_status_2']=signed_entry(second,fixture['signers']['owner'],'owner_status_2')
        fixture['role_map']['historical.status.ack_read']='owner_status_2'
        return repack_fixture(fixture)

    def read_observation(self,fixture,payload):
        scope=dict(kind='authority',root_key=fixture['expected']['expected_ack_slot']['root_key'],
            authority_kind='ack.read_grant',authority_sha256=fixture['entries']['read']['ref']['raw_sha256'])
        scope_id=hashlib.sha256(canonical_bytes(scope)).hexdigest()
        return next(item for item in payload['entries'] if item['scope_id']==scope_id)

    def test_every_present_permitted_scope_preserves_revocation_floor_and_operation(self):
        calls=[]
        for changes in ({'status':'revoked'},{'minimum_document_revision':2},{'operation_mask':8}):
            fixture=ack_unbound_fixture()
            self.split_owner_status(fixture,lambda payload:self.read_observation(fixture,payload).update(changes))
            calls.append(self.call(fixture))
        actual=self.ts(calls)
        self.assertEqual([item['code'] for item in actual],
            ['repair_authority_revoked','repair_status_revision','repair_status_operation'])

    def test_cross_original_status_revision_conflict_and_floor_rollback(self):
        conflict=ack_unbound_fixture()
        self.split_owner_status(conflict,second_changes=lambda payload:payload.update(revision=1,issued_at=2_000_000_006))
        rollback=ack_unbound_fixture()
        self.split_owner_status(rollback,lambda payload:self.read_observation(rollback,payload).update(minimum_document_revision=1))
        actual=self.ts([self.call(conflict),self.call(rollback)])
        self.assertEqual([item['code'] for item in actual],['repair_status_conflict','repair_status_rollback'])

    def test_legacy_status_whitespace_is_not_a_canonical_equivocation(self):
        fixture=ack_unbound_fixture()
        raw=b' \n'+json.dumps(fixture['docs']['owner_status'],indent=2,ensure_ascii=False).encode()+b'\n'
        fixture['entries']['owner_status_2']=dict(raw=raw,ref=reference(raw,'owner_status_2'))
        fixture['role_map']['historical.status.ack_read']='owner_status_2'
        repack_fixture(fixture)
        result=self.ts([self.call(fixture)])[0];self.assertTrue(result['ok'],result)
        self.assertEqual(result['result']['status_count'],3)
        self.assertEqual(result['work']['signature_checks'],14)

    def test_shared_budget_exhaustion_keeps_all_real_signature_work(self):
        fixture=ack_unbound_fixture()
        result=self.ts([self.call(fixture,policy={**POLICY,'max_signature_checks':12})])[0]
        self.assertEqual(result['code'],'repair_over_budget');self.assertEqual(result['work']['signature_checks'],12)

    def test_expected_input_accessors_and_proxies_never_invoke_callbacks(self):
        fixture=ack_unbound_fixture()
        for result in self.ts([self.call(fixture,host='getter'),self.call(fixture,host='proxy')]):
            self.assertFalse(result['ok']);self.assertNotEqual(result['code'],'untyped_error')
            self.assertEqual(result['callbacks'],0);self.assertEqual(result['work']['signature_checks'],0)
