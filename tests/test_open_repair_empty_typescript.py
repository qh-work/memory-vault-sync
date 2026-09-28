"""Native empty event authentication against real synthetic Python commits."""
import base64
import copy
import dataclasses
import hashlib
import json
import subprocess
import unittest

from memory_vault import canonical_bytes
import memory_vault_open_repair_empty as empty
import memory_vault_open_repair_wire as wire
from tests import test_network_typescript_agent_network as ts_runtime
from tests import test_open_repair_empty as empty_fixture
from tests.open_repair_ack_fixtures import reference, signed_entry
from tests.test_open_repair_probe_typescript import encoded

DRIVER=r"""
import child from 'node:child_process';
import crypto from 'node:crypto';
import {syncBuiltinESMExports} from 'node:module';
let subprocessCalls=0,nativeChecks=0;
const deny=()=>{subprocessCalls++;throw Error('native empty verifier must not delegate');};
for(const name of ['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork'])child[name]=deny;
const actualVerify=crypto.verify;crypto.verify=(...args)=>{nativeChecks++;return actualVerify(...args);};syncBuiltinESMExports();
const e=await import('./open-repair-empty.ts'),w=await import('./open-repair-wire.ts');
const chunks=[];let size=0;for await(const chunk of process.stdin){size+=chunk.length;if(size>16777216)throw Error('synthetic input limit');chunks.push(chunk);}
const calls=JSON.parse(Buffer.concat(chunks).toString('utf8')),results=[];
const decode=item=>({raw:Buffer.from(item.raw,'base64'),ref:item.ref});
const encode=item=>({raw:Buffer.from(item.raw).toString('base64'),ref:item.ref,payload:item.payload});
for(const c of calls){const start=nativeChecks;let budget,callbacks=0;try{
  budget=new w.RepairBudget(c.policy);const resolver=new w.LocalRawResolver(c.policy,budget);
  for(const pack of c.packs){const item=decode(pack);resolver.put(item.ref.namespace,item.ref.key,item.raw);}
  const options={...c.options,policy:c.policy,budget},manifest=decode(c.manifest),custody=decode(c.custody);
  if(c.host==='options')Object.defineProperty(options,'expectedOwner',{get(){callbacks++;throw Error('getter');}});
  if(c.host==='proxy')options.expectedAckSlot=new Proxy(options.expectedAckSlot,{ownKeys(){callbacks++;throw Error('proxy');}});
  if(c.host==='entry')Object.defineProperty(custody,'raw',{get(){callbacks++;throw Error('getter');}});
  const verify=()=>e.verifyAckEmptySourceEvent(manifest,resolver,custody,options),result=verify();let immutable=true,retryCode;
  if(c.mutate){const original=Buffer.from(result.custody.raw);custody.raw.fill(0);result.custody.raw.fill(0);options.expectedAckSlot.grant_id='changed';immutable=Buffer.from(result.custody.raw).equals(original)&&result.binding.payload.ack_slot.grant_id!=='changed';}
  if(c.repeat){try{verify();}catch(error){retryCode=error.code;}}
  results.push({ok:true,stored_at:result.stored_at,read_until:result.read_until,retain_until:result.retain_until,
    custody:encode(result.custody),binding:encode(result.binding),predecessor:encode(result.predecessor.custody),
    authorities:Object.fromEntries(Object.entries(result.authorities.originals).map(([role,item])=>[role,encode(item)])),
    statuses:result.statuses.map(encode),roles:result.manifest.roles.map(item=>item.role),
    frozen:Object.isFrozen(result)&&Object.isFrozen(result.statuses)&&Object.isFrozen(result.binding.payload)&&Object.isFrozen(result.predecessor),
    immutable,retryCode,work:budget.snapshot(),nativeChecks:nativeChecks-start,callbacks});
}catch(error){results.push({ok:false,code:error.code??'untyped_error',detail:error.code?undefined:String(error.stack),work:budget?.snapshot(),nativeChecks:nativeChecks-start,callbacks});}}
process.stdout.write(JSON.stringify({results,subprocessCalls}));
"""


class OpenRepairEmptyTypeScriptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ts_runtime.TypeScriptAgentNetworkTests.setUpClass.__func__(cls)
        (cls.fixture/'driver.mjs').write_text(DRIVER)

    def setUp(self):
        self.source=empty_fixture.OpenRepairEmptyTests()
        self.source.setUp()
        self.addCleanup(self.source.tearDown)
        self.result=self.source.bind()
        self.f=self.source.h.fixture
        self.packs=[]
        for namespace,key,raw in self.source.h.db.execute("""SELECT o.namespace,o.opaque_key,o.raw FROM open_repair_ack_objects o
            JOIN open_repair_ack_pins p ON o.namespace=p.namespace AND o.opaque_key=p.opaque_key
            WHERE p.resource_id=? AND p.role IN ('pack','empty:pack')""",(self.source.h.resource_id,)):
            raw=bytes(raw)
            self.packs.append(dict(raw=raw,ref=dict(namespace=namespace,key=key,raw_sha256=hashlib.sha256(raw).hexdigest(),size=len(raw))))

    def call(self,result=None,packs=(),*,expected=None,policy=None,**extra):
        result=result or self.result
        expected=self.f['expected']|{name:self.source.expected[name] for name in
            ('expected_receipt_writer','expected_message_id','expected_envelope_ref')}|(expected or {})
        options={''.join([parts[0]]+[part.title() for part in parts[1:]]):copy.deepcopy(value)
            for name,value in expected.items() for parts in [name.split('_')]}
        return dict(manifest=encoded(result['manifest']),custody=encoded(result['custody']),
            packs=[encoded(item) for item in [*self.packs,*packs]],options=options,
            policy=dataclasses.asdict(self.source.h.state.policy)|(policy or {}),**extra)

    def py(self,call):
        policy=wire.RepairPolicy(**call['policy']);budget=wire.RepairBudget(policy)
        resolver=wire.LocalRawResolver(policy,budget)
        decode=lambda item:dict(raw=base64.b64decode(item['raw']),ref=item['ref'])
        names=dict(expectedAckSlot='expected_ack_slot',expectedOwner='expected_owner',expectedReceiptWriter='expected_receipt_writer',
            expectedMessageId='expected_message_id',expectedEnvelopeRef='expected_envelope_ref',expectedTarget='expected_target',
            targetStorageEpoch='target_storage_epoch',limitPolicy='limit_policy')
        try:
            for item in call['packs']:
                item=decode(item);resolver.put(item['ref']['namespace'],item['ref']['key'],item['raw'])
            result=empty.verify_ack_empty_source_event(decode(call['manifest']),resolver,decode(call['custody']),
                **{names[name]:value for name,value in call['options'].items()},policy=policy,budget=budget)
            return dict(ok=True,stored_at=result.stored_at,work=budget.snapshot())
        except wire.RepairWireError as error:
            return dict(ok=False,code=error.code,work=budget.snapshot())

    def ts(self,calls):
        process=subprocess.run([self.node,'--experimental-strip-types',str(self.fixture/'driver.mjs')],cwd=self.fixture,
            input=json.dumps(calls).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=35)
        self.assertEqual(process.returncode,0,process.stderr.decode(errors='replace')[-5000:])
        result=json.loads(process.stdout);self.assertEqual(result['subprocessCalls'],0)
        return result['results']

    def parity(self,calls):
        actual=self.ts(calls)
        for call,result in zip(calls,actual):
            expected=self.py(call)
            with self.subTest(code=expected.get('code')):
                self.assertEqual(result['ok'],expected['ok'],result)
                if not expected['ok']:self.assertEqual(result['code'],expected['code'],result)
                for field in ('signature_checks','hashes','hash_bytes'):
                    self.assertEqual(result['work'][field],expected['work'][field],field)
                self.assertEqual(result['nativeChecks'],result['work']['signature_checks'])
        return actual

    def altered(self,**changes):
        result,packs=self.source.rebuild_outer(self.result,**changes)
        return self.call(result,packs)

    def test_complete_native_event_rechecks_real_predecessor_and_exact_originals(self):
        result=self.parity([self.call()])[0]
        self.assertTrue(result['ok'],result);self.assertTrue(result['frozen'])
        self.assertEqual(result['nativeChecks'],20)
        self.assertEqual(set(result['roles']),empty.ROLES)
        self.assertEqual(len(result['statuses']),2)
        self.assertEqual(result['stored_at'],2_000_000_007)
        for name,expected in (('custody',self.result['custody']),('binding',self.result['binding']),('predecessor',self.f['custody'])):
            self.assertEqual(result[name]['raw'],encoded(expected)['raw']);self.assertEqual(result[name]['ref'],expected['ref'])
        for name,expected in (('root',self.f['entries']['root']),('write',self.source.write),('bootstrap',self.source.offer)):
            self.assertEqual(result['authorities'][name]['raw'],encoded(expected)['raw'])
            self.assertEqual(result['authorities'][name]['ref'],expected['ref'])

    def test_signed_binding_custody_exact_refs_resource_and_causal_windows(self):
        binding=json.loads(self.result['binding']['raw'])['payload']
        changes=[dict(binding_signer=self.f['signers']['owner']),dict(binding_changes={'bound_at':2_000_000_006}),
            dict(binding_changes={'bound_at':2_000_000_008}),dict(binding_changes={'retain_until':2_000_000_800}),
            dict(custody_changes={'read_until':2_000_000_701}),dict(custody_changes={'state':'unbound'}),
            dict(binding_changes={'resource_ref':binding['resource_ref']|{'storage_epoch':'wrong_epoch'}})]
        for field in ('root_authority_ref','grant_ref'):
            changes.append(dict(binding_changes={field:binding[field]|{'key':'0'*64}}))
        self.assertTrue(all(not result['ok'] for result in self.parity([self.altered(**change) for change in changes])))

    def test_every_direct_role_and_real_recursive_predecessor_are_required(self):
        calls=[self.altered(omit=(role,)) for role in sorted(empty.ROLES) if role!='ack.binding']
        summary=canonical_bytes(dict(verified=True,state='unbound',source_digest=self.f['manifest']['ref']['raw_sha256']))
        calls.append(self.altered(replacements={'history.ack_unbound':dict(raw=summary,ref=reference(summary,'untrusted-summary'))}))
        custody=json.loads(self.f['custody']['raw'])
        custody['proof']['signature']=base64.b64encode(bytes(64)).decode();raw=canonical_bytes(custody)
        calls.append(self.altered(replacements={'ack.unbound_custody':dict(raw=raw,ref=reference(raw,'bad-previous-signature'))}))
        missing=self.call();previous_refs={item['pack_ref']['key'] for item in json.loads(self.f['manifest']['raw'])['roles']}
        missing['packs']=[item for item in missing['packs'] if item['ref']['key'] not in previous_refs];calls.append(missing)
        results=self.parity(calls);self.assertTrue(all(not result['ok'] for result in results))
        self.assertEqual(results[-2]['code'],'repair_invalid_signature');self.assertEqual(results[-2]['nativeChecks'],2)

    def test_independently_selected_dual_writer_message_and_full_envelope_ref(self):
        writer=self.source.expected['expected_receipt_writer'];calls=[]
        calls.append(self.call(expected={'expected_message_id':'msg_'+'bc'*32}))
        calls.append(self.call(expected={'expected_receipt_writer':self.f['expected']['expected_owner']}))
        for part in ('signing_key','encryption_key'):
            calls.append(self.call(expected={'expected_receipt_writer':writer|{part:self.f['expected']['expected_owner'][part]}}))
        envelope=self.source.expected['expected_envelope_ref']
        for field,value in (('namespace','meta'),('key','0'*64),('raw_sha256','0'*64),('size',envelope['size']+1)):
            calls.append(self.call(expected={'expected_envelope_ref':envelope|{field:value}}))
        calls.append(self.call(expected={'target_storage_epoch':'different_epoch'}))
        self.assertTrue(all(not result['ok'] for result in self.parity(calls)))

    def test_whole_multiscope_status_denials_and_cross_generation_conflict(self):
        calls=[]
        source=json.loads(self.source.expected['current_statuses'][0]['raw'])['payload']
        for change in ('conflict','operation','revoked','floor','scope','expiry'):
            payload=copy.deepcopy(source)
            if change=='conflict':payload['revision']=1
            elif change=='expiry':payload['valid_until']=2_000_000_007
            else:
                item=next(item for item in payload['entries'] if item['scope_kind']=='ack_slot')
                item.update({'operation':dict(operation_mask=66),'revoked':dict(status='revoked',operation_mask=1),
                    'floor':dict(minimum_document_revision=2),'scope':dict(scope_id='0'*64)}[change])
                payload['entries'].sort(key=lambda item:(item['scope_kind'],item['scope_id']))
            status=signed_entry(payload,self.f['signers']['owner'],'empty-status-'+change)
            calls.append(self.altered(replacements={role:status for role in empty.STATUS_ROLES if role!='historical.status.ack_resource'}))
        results=self.parity(calls);self.assertTrue(all(not result['ok'] for result in results))
        self.assertEqual(results[0]['code'],'repair_status_conflict')
        self.assertEqual(results[1]['code'],'repair_status_operation')

    def previous_status(self,change):
        manifest=json.loads(self.f['manifest']['raw']);roles={}
        for row in manifest['roles']:
            ref=row['document_ref']
            raw=self.source.h.db.execute('SELECT raw FROM open_repair_ack_objects WHERE namespace=? AND opaque_key=?',
                (ref['namespace'],ref['key'])).fetchone()[0]
            roles[row['role']]=dict(raw=bytes(raw),ref=ref)
        payload=json.loads(roles['historical.status.ack_root']['raw'])['payload']
        if change=='revision':payload['revision']=3
        else:
            for item in payload['entries']:item['minimum_document_revision']=1
        status=signed_entry(payload,self.f['signers']['owner'],'prior-owner-'+change)
        for role in tuple(roles):
            if role.startswith('historical.status.') and role!='historical.status.ack_resource':roles[role]=status
        policy=self.source.h.state.policy
        pack=wire.build_raw_pack(list({item['raw'] for item in roles.values()}),policy,wire.RepairBudget(policy))
        positions={item.raw_sha256:index for index,item in enumerate(pack.entries)}
        manifest['roles']=[dict(role=role,document_ref=item['ref'],pack_ref=pack.ref.as_dict(),
            entry_index=positions[item['ref']['raw_sha256']]) for role,item in sorted(roles.items())]
        raw=canonical_bytes(manifest);prior_manifest=dict(raw=raw,ref=reference(raw,'prior-manifest-'+change))
        custody=json.loads(self.f['custody']['raw'])['payload'];custody['historical_manifest_ref']=prior_manifest['ref']
        prior_custody=signed_entry(custody,self.f['signers']['target'],'prior-custody-'+change)
        result,packs=self.source.rebuild_outer(self.result,replacements={'history.ack_unbound':prior_manifest,'ack.unbound_custody':prior_custody})
        return self.call(result,[*packs,dict(raw=pack.raw,ref=pack.ref.as_dict())])

    def test_cross_generation_minimum_and_observed_revision_never_roll_back(self):
        results=self.parity([self.previous_status(change) for change in ('floor','revision')])
        self.assertEqual([result.get('code') for result in results],['repair_status_rollback']*2)
        self.assertEqual([result['nativeChecks'] for result in results],[20,20])

    def test_noncanonical_legacy_status_keeps_whole_identity_and_other_role_cannot_hide_denial(self):
        document=json.loads(self.source.expected['current_statuses'][0]['raw'])
        raw=b' \n'+json.dumps(document,indent=2).encode()+b'\n'
        original=dict(raw=raw,ref=reference(raw,'spaced-status'))
        valid=self.altered(replacements={'historical.status.ack_write':original})
        payload=copy.deepcopy(document['payload'])
        for item in payload['entries']:
            if item['scope_kind']=='ack_slot':item.update(status='revoked',operation_mask=1)
        revoked=signed_entry(payload,self.f['signers']['owner'],'other-role-revocation')
        results=self.parity([valid,self.altered(replacements={'historical.status.ack_write':revoked})])
        self.assertTrue(results[0]['ok'],results[0]);self.assertEqual(results[0]['nativeChecks'],21)
        self.assertEqual(results[1]['code'],'repair_authority_revoked')

    def test_actual_target_signature_and_raw_hash_size_are_not_trusted(self):
        calls=[]
        for field,value in (('size',1),('raw_sha256','0'*64)):
            call=self.call();call['custody']['ref'][field]=value;calls.append(call)
        for role in ('custody','manifest'):
            call=self.call();raw=b' '+base64.b64decode(call[role]['raw']);call[role]=encoded(dict(raw=raw,ref=reference(raw,'noncanonical-'+role)));calls.append(call)
        call=self.call();document=json.loads(base64.b64decode(call['custody']['raw']));document['proof']['signature']=base64.b64encode(bytes(64)).decode()
        raw=canonical_bytes(document);call['custody']=encoded(dict(raw=raw,ref=reference(raw,'bad-custody-signature')));calls.append(call)
        results=self.parity(calls);self.assertTrue(all(not result['ok'] for result in results));self.assertEqual(results[-1]['nativeChecks'],1)

    def test_all_recursive_work_uses_one_finite_budget(self):
        calls=[self.call(policy={'max_signature_checks':limit}) for limit in (1,13,19,20)]
        results=self.parity(calls)
        self.assertEqual([result['ok'] for result in results],[False,False,False,True])
        for result,limit in zip(results,(1,13,19,20)):
            self.assertEqual(result['nativeChecks'],limit)
            if limit<20:self.assertEqual(result['code'],'repair_over_budget')
        repeated=self.ts([self.call(policy={'max_signature_checks':20},repeat=True)])[0]
        self.assertTrue(repeated['ok'],repeated);self.assertEqual(repeated['retryCode'],'repair_over_budget');self.assertEqual(repeated['nativeChecks'],20)

    def test_snapshots_and_immutable_outputs_never_invoke_host_callbacks(self):
        result=self.ts([self.call(mutate=True)])[0]
        self.assertTrue(result['ok'],result);self.assertTrue(result['immutable']);self.assertTrue(result['frozen'])
        for result in self.ts([self.call(host=kind) for kind in ('options','proxy','entry')]):
            self.assertFalse(result['ok']);self.assertEqual(result['callbacks'],0);self.assertEqual(result['nativeChecks'],0)
            self.assertNotEqual(result['code'],'untyped_error',result)


if __name__=='__main__':
    unittest.main()
