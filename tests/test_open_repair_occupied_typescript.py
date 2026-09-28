"""Actual native occupied receipt verification over synthetic Python originals."""
import base64
import copy
import dataclasses
import hashlib
import json
import subprocess
import unittest

from memory_vault import canonical_bytes
import memory_vault_open_repair_occupied as occupied
import memory_vault_open_repair_wire as wire
from tests import test_network_typescript_agent_network as ts_runtime
from tests import test_open_repair_occupied as occupied_fixture
from tests.open_repair_ack_fixtures import reference, signed_entry
from tests.test_open_repair_probe_typescript import encoded

DRIVER=r"""
import child from 'node:child_process';
import crypto from 'node:crypto';
import {syncBuiltinESMExports} from 'node:module';
let subprocessCalls=0,nativeChecks=0;
const deny=()=>{subprocessCalls++;throw Error('occupied verifier must be native');};
for(const name of ['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork'])child[name]=deny;
const actualVerify=crypto.verify;crypto.verify=(...args)=>{nativeChecks++;return actualVerify(...args);};syncBuiltinESMExports();
const o=await import('./open-repair-occupied.ts'),w=await import('./open-repair-wire.ts');
const chunks=[];let size=0;for await(const chunk of process.stdin){size+=chunk.length;if(size>16777216)throw Error('synthetic input limit');chunks.push(chunk);}
const calls=JSON.parse(Buffer.concat(chunks).toString('utf8')),results=[];
const decode=item=>({raw:Buffer.from(item.raw,'base64'),ref:item.ref});
const encode=item=>({raw:Buffer.from(item.raw).toString('base64'),ref:item.ref,payload:item.payload});
for(const c of calls){const start=nativeChecks;let budget,callbacks=0;try{
  budget=new w.RepairBudget(c.policy);const resolver=new w.LocalRawResolver(c.policy,budget);
  for(const pack of c.packs){const item=decode(pack);resolver.put(item.ref.namespace,item.ref.key,item.raw);}
  const options={...c.options,policy:c.policy,budget},manifest=decode(c.manifest),commit=decode(c.commit);
  if(c.host==='options')Object.defineProperty(options,'expectedOwner',{get(){callbacks++;throw Error('getter');}});
  if(c.host==='proxy')options.expectedAckSlot=new Proxy(options.expectedAckSlot,{ownKeys(){callbacks++;throw Error('proxy');}});
  if(c.host==='entry')Object.defineProperty(commit,'raw',{get(){callbacks++;throw Error('getter');}});
  const verify=()=>o.verifyAckOccupiedSourceEvent(manifest,resolver,commit,options),result=verify();
  const headOptions={expectedTarget:options.expectedTarget,policy:c.policy,budget};let head,retryCode,brandCode,immutable=true;
  if(c.head)head=o.verifyAckOccupiedHead(decode(c.head),result,headOptions);
  if(c.forged){try{o.verifyAckOccupiedHead(decode(c.forged),{...result},headOptions);}catch(error){brandCode=error.code;}}
  if(c.mutate){const raw=Buffer.from(result.commit.raw);commit.raw.fill(0);result.commit.raw.fill(0);options.expectedAckSlot.grant_id='changed';immutable=Buffer.from(result.commit.raw).equals(raw)&&result.commit.payload.ack_slot.grant_id!=='changed';}
  if(c.repeat){try{verify();}catch(error){retryCode=error.code;}}
  results.push({ok:true,stored_at:result.stored_at,read_until:result.read_until,retain_until:result.retain_until,
    commit:encode(result.commit),head:head&&encode(head),inputs:Object.fromEntries(Object.entries(result.inputs).map(([role,item])=>[role,encode(item)])),
    empty:encode(result.predecessor.custody),unbound:encode(result.predecessor.predecessor.custody),
    statuses:result.statuses.map(encode),roles:result.manifest.roles.map(item=>item.role),
    frozen:Object.isFrozen(result)&&Object.isFrozen(result.inputs)&&Object.isFrozen(result.inputs.receipt.payload)&&Object.isFrozen(result.statuses),
    immutable,retryCode,brandCode,work:budget.snapshot(),nativeChecks:nativeChecks-start,callbacks});
}catch(error){results.push({ok:false,code:error.code??'untyped_error',detail:error.code?undefined:String(error.stack),work:budget?.snapshot(),nativeChecks:nativeChecks-start,callbacks});}}
process.stdout.write(JSON.stringify({results,subprocessCalls}));
"""


class OpenRepairOccupiedTypeScriptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ts_runtime.TypeScriptAgentNetworkTests.setUpClass.__func__(cls)
        (cls.fixture/'driver.mjs').write_text(DRIVER)

    def setUp(self):
        self.source=occupied_fixture.OpenRepairOccupiedTests()
        self.source.setUp();self.addCleanup(self.source.tearDown)
        self.result=self.source.put();self.f=self.source.h.fixture
        self.packs=[]
        for namespace,key,raw in self.source.h.db.execute("""SELECT o.namespace,o.opaque_key,o.raw FROM open_repair_ack_objects o
            JOIN open_repair_ack_pins p ON o.namespace=p.namespace AND o.opaque_key=p.opaque_key
            WHERE p.resource_id=? AND p.role IN ('pack','empty:pack','occupied:pack')""",(self.source.h.resource_id,)):
            raw=bytes(raw);self.packs.append(dict(raw=raw,ref=dict(namespace=namespace,key=key,raw_sha256=hashlib.sha256(raw).hexdigest(),size=len(raw))))

    def call(self,result=None,packs=(),*,expected=None,policy=None,head=False,**extra):
        result=result or self.result
        expected=self.f['expected']|{name:self.source.case.expected[name] for name in
            ('expected_receipt_writer','expected_message_id','expected_envelope_ref')}|(expected or {})
        options={''.join([parts[0]]+[part.title() for part in parts[1:]]):copy.deepcopy(value)
            for name,value in expected.items() for parts in [name.split('_')]}
        return copy.deepcopy(dict(manifest=encoded(result['manifest']),commit=encoded(result['commit']),
            packs=[encoded(item) for item in [*self.packs,*packs]],options=options,
            policy=dataclasses.asdict(self.source.h.state.policy)|(policy or {}),
            **(dict(head=encoded(result['head'])) if head else {}),**extra))

    def py(self,call):
        policy=wire.RepairPolicy(**call['policy']);budget=wire.RepairBudget(policy);resolver=wire.LocalRawResolver(policy,budget)
        decode=lambda item:dict(raw=base64.b64decode(item['raw']),ref=item['ref'])
        names=dict(expectedAckSlot='expected_ack_slot',expectedOwner='expected_owner',expectedReceiptWriter='expected_receipt_writer',
            expectedMessageId='expected_message_id',expectedEnvelopeRef='expected_envelope_ref',expectedTarget='expected_target',
            targetStorageEpoch='target_storage_epoch',limitPolicy='limit_policy')
        try:
            for item in call['packs']:
                item=decode(item);resolver.put(item['ref']['namespace'],item['ref']['key'],item['raw'])
            result=occupied.verify_ack_occupied_source_event(decode(call['manifest']),resolver,decode(call['commit']),
                **{names[name]:value for name,value in call['options'].items()},policy=policy,budget=budget)
            if call.get('head'):occupied.verify_ack_occupied_head(decode(call['head']),result,
                expected_target=call['options']['expectedTarget'],policy=policy,budget=budget)
            return dict(ok=True,stored_at=result.stored_at,work=budget.snapshot())
        except wire.RepairWireError as error:return dict(ok=False,code=error.code,work=budget.snapshot())

    def ts(self,calls):
        process=subprocess.run([self.node,'--experimental-strip-types',str(self.fixture/'driver.mjs')],cwd=self.fixture,
            input=json.dumps(calls).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=40)
        self.assertEqual(process.returncode,0,process.stderr.decode(errors='replace')[-5000:])
        result=json.loads(process.stdout);self.assertEqual(result['subprocessCalls'],0);return result['results']

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

    def altered(self,*,receipt_changes=None,disclosure_changes=None,put_changes=None,commit_changes=None,head_changes=None,
            receipt_signer=None,disclosure_signer=None,put_signer=None,commit_signer=None,head_signer=None,replacements=None,omit=(),head=False,receipt_namespace=None):
        manifest=json.loads(self.result['manifest']['raw']);roles={}
        for row in manifest['roles']:
            ref=row['document_ref'];raw=self.source.h.db.execute('SELECT raw FROM open_repair_ack_objects WHERE namespace=? AND opaque_key=?',
                (ref['namespace'],ref['key'])).fetchone()[0];roles[row['role']]=dict(raw=bytes(raw),ref=ref)
        writer=self.f['signers']['writer'];target=self.f['signers']['target']
        if receipt_changes is not None or receipt_signer or receipt_namespace:
            p=json.loads(roles['recipient.receipt']['raw'])['payload'];p.update(receipt_changes or {})
            if receipt_signer:p['signing_key']=receipt_signer.public_descriptor()
            roles['recipient.receipt']=signed_entry(p,receipt_signer or writer,'changed-receipt')
            roles['recipient.receipt']['ref']['namespace']=receipt_namespace or 'object'
        if receipt_changes is not None or receipt_signer or receipt_namespace or disclosure_changes is not None or disclosure_signer:
            p=json.loads(roles['ack.disclosure']['raw'])['payload'];p['receipt_ref']=roles['recipient.receipt']['ref'];p.update(disclosure_changes or {})
            if disclosure_signer:p['signing_key']=disclosure_signer.public_descriptor()
            roles['ack.disclosure']=signed_entry(p,disclosure_signer or writer,'changed-disclosure')
            status=json.loads(roles['historical.status.ack_disclosure']['raw'])['payload']
            scope=dict(kind='authority',root_key=p['ack_slot']['root_key'],authority_kind='ack.disclosure',authority_sha256=roles['ack.disclosure']['ref']['raw_sha256'])
            status['entries'][0]['scope_id']=hashlib.sha256(canonical_bytes(scope)).hexdigest()
            roles['historical.status.ack_disclosure']=signed_entry(status,writer,'changed-disclosure-status')
        p=json.loads(roles['ack.put']['raw'])['payload'];p.update(receipt_ref=roles['recipient.receipt']['ref'],disclosure_ref=roles['ack.disclosure']['ref']);p.update(put_changes or {})
        if put_signer:p['signing_key']=put_signer.public_descriptor()
        roles['ack.put']=signed_entry(p,put_signer or writer,'changed-put')
        roles.update(replacements or {})
        for field,role in (('receipt_ref','recipient.receipt'),('disclosure_ref','ack.disclosure'),('put_ref','ack.put')):manifest[field]=roles[role]['ref']
        for role in omit:roles.pop(role)
        policy=self.source.h.state.policy;pack=wire.build_raw_pack(list({item['raw'] for item in roles.values()}),policy,wire.RepairBudget(policy))
        positions={item.raw_sha256:index for index,item in enumerate(pack.entries)}
        manifest['roles']=[dict(role=role,document_ref=item['ref'],pack_ref=pack.ref.as_dict(),entry_index=positions[item['ref']['raw_sha256']]) for role,item in sorted(roles.items())]
        raw=canonical_bytes(manifest);manifest_entry=dict(raw=raw,ref=reference(raw,'changed-occupied-history'))
        p=json.loads(self.result['commit']['raw'])['payload'];p.update(historical_manifest_ref=manifest_entry['ref'])
        for field in ('receipt_ref','disclosure_ref','put_ref'):p[field]=manifest[field]
        p.update(commit_changes or {})
        if commit_signer:p['signing_key']=commit_signer.public_descriptor()
        commit=signed_entry(p,commit_signer or target,'changed-commit')
        p=json.loads(self.result['head']['raw'])['payload'];p.update(original_ack_commit_ref=commit['ref'],receipt_ref=manifest['receipt_ref']);p.update(head_changes or {})
        if head_signer:p['signing_key']=head_signer.public_descriptor()
        newhead=signed_entry(p,head_signer or target,'changed-head')
        return self.call(dict(manifest=manifest_entry,commit=commit,head=newhead),[dict(raw=pack.raw,ref=pack.ref.as_dict())],head=head)

    def test_native_receipt_exact_object_ref_and_three_real_generations(self):
        result=self.parity([self.call(head=True)])[0]
        self.assertTrue(result['ok'],result);self.assertTrue(result['frozen']);self.assertEqual(result['nativeChecks'],29)
        self.assertEqual(set(result['roles']),occupied.ROLES);self.assertEqual(len(result['statuses']),3)
        for name,expected in (('commit',self.result['commit']),('head',self.result['head']),('empty',self.source.case.bound['custody']),('unbound',self.f['custody'])):
            self.assertEqual(result[name]['raw'],encoded(expected)['raw']);self.assertEqual(result[name]['ref'],expected['ref'])
        for name,expected in (('receipt',self.source.receipt),('disclosure',self.source.disclosure),('put',self.source.put_entry)):
            self.assertEqual(result['inputs'][name]['raw'],encoded(expected)['raw']);self.assertEqual(result['inputs'][name]['ref'],expected['ref'])
        self.assertEqual(result['inputs']['receipt']['ref']['namespace'],'object')
        self.assertNotEqual(result['inputs']['receipt']['ref']['key'],result['inputs']['receipt']['ref']['raw_sha256'])
        self.assertTrue(self.parity([self.altered(receipt_namespace='meta')])[0]['ok'])

    def test_existing_receipt_contract_independent_binding_and_actual_signer(self):
        owner=self.f['signers']['owner'];p=json.loads(self.source.receipt['raw'])['payload']
        changes=[{'message_id':'msg_'+'ef'*32},{'status':'saved'},{'saved_at':True},{'saved_at':2_000_000_006},
            {'sender_key_id':self.f['signers']['target'].key_id},{'recipient_key_id':owner.key_id},
            {'schema_version':'memory-vault-open-repair/v1'}]
        for field,value in (('namespace','meta'),('key','different-locator'),('raw_sha256','0'*64),('size',1)):
            changes.append({'envelope_ref':p['envelope_ref']|{field:value}})
        calls=[self.altered(receipt_changes=change) for change in changes]+[self.altered(receipt_signer=owner)]
        results=self.parity(calls);self.assertTrue(all(not item['ok'] for item in results))
        self.assertEqual(results[-1]['code'],'repair_wrong_issuer')

    def test_only_two_closed_explicit_disclosure_variants_and_exact_put(self):
        p=json.loads(self.source.disclosure['raw'])['payload'];r=p['bootstrap_return']
        variants=[list(occupied.RETURN_ROLES_LEGACY),list(occupied.RETURN_ROLES_FULL),list(occupied.RETURN_ROLES_FULL)[:3],
            list(reversed(occupied.RETURN_ROLES_FULL)),[*occupied.RETURN_ROLES_LEGACY,'ack.disclosure']]
        calls=[self.altered(disclosure_changes={'bootstrap_return':r|{'roles':roles}}) for roles in variants]
        calls.extend([self.altered(disclosure_changes={'bootstrap_return':r|{'consumer':'ack_offer'}}),
            self.altered(disclosure_changes={'operation_mask':66}),self.altered(disclosure_changes={'allowed_roles':['ack.disclosure','ack.put']}),
            self.altered(disclosure_signer=self.f['signers']['owner']),self.altered(put_signer=self.f['signers']['owner']),
            self.altered(put_changes={'operation':'receipt.read'})])
        put=json.loads(self.source.put_entry['raw'])['payload']
        calls.extend(self.altered(put_changes={field:put[field]|{'key':'unrelated'}}) for field in ('binding_ref','grant_ref','receipt_ref','disclosure_ref'))
        results=self.parity(calls);self.assertEqual([item['ok'] for item in results],[True,True]+[False]*(len(calls)-2))

    def test_every_role_and_actual_empty_predecessor_required(self):
        calls=[self.altered(omit=(role,)) for role in sorted(occupied.ROLES)]
        custody=json.loads(self.source.case.bound['custody']['raw']);custody['proof']['signature']=base64.b64encode(bytes(64)).decode()
        raw=canonical_bytes(custody);calls.append(self.altered(replacements={'ack.empty_custody':dict(raw=raw,ref=reference(raw,'bad-prior-signature'))}))
        missing=self.call();previous_keys={row['pack_ref']['key'] for row in json.loads(self.f['manifest']['raw'])['roles']}
        missing['packs']=[item for item in missing['packs'] if item['ref']['key'] not in previous_keys];calls.append(missing)
        results=self.parity(calls);self.assertTrue(all(not item['ok'] for item in results));self.assertEqual(results[-2]['code'],'repair_invalid_signature')

    def test_whole_disclosure_status_cannot_hide_scope_revocation_floor_or_conflict(self):
        p=json.loads(self.source.options['current_statuses'][-1]['raw'])['payload'];calls=[]
        for name in ('revoked','operation','floor','scope','extra','expiry'):
            status=copy.deepcopy(p)
            if name=='expiry':status['valid_until']=2_000_000_008
            elif name=='extra':status['entries'].append(status['entries'][0]|{'scope_id':'ff'*32});status['entries'].sort(key=lambda item:(item['scope_kind'],item['scope_id']))
            else:status['entries'][0].update({'revoked':dict(status='revoked',operation_mask=1),'operation':dict(operation_mask=66),
                'floor':dict(minimum_document_revision=2),'scope':dict(scope_id='00'*32)}[name])
            item=signed_entry(status,self.f['signers']['writer'],'status-'+name)
            calls.append(self.altered(replacements={'historical.status.ack_disclosure':item}))
        owner=json.loads(self.source.options['current_statuses'][0]['raw'])['payload'];owner['revision']=1
        item=signed_entry(owner,self.f['signers']['owner'],'conflicting-old-owner-status')
        calls.append(self.altered(replacements={role:item for role in occupied.STATUS_ROLES if role not in ('historical.status.admission_resource','historical.status.ack_disclosure')}))
        results=self.parity(calls);self.assertTrue(all(not item['ok'] for item in results));self.assertEqual(results[-1]['code'],'repair_status_conflict')
        self.assertEqual(results[0]['code'],'repair_authority_revoked')

    def test_signed_target_commit_and_head_window_ref_and_state_bindings(self):
        c=json.loads(self.result['commit']['raw'])['payload'];h=json.loads(self.result['head']['raw'])['payload'];calls=[]
        for changes in ({'read_until':2_000_000_601},{'retain_until':2_000_000_651},{'stored_at':2_000_000_007},
                {'resource_ref':c['resource_ref']|{'storage_epoch':'wrong_epoch'}},{'grant_ref':c['grant_ref']|{'key':'wrong'}}):
            calls.append(self.altered(commit_changes=changes))
        for changes in ({'state':'empty'},{'generation':1},{'observed_at':2_000_000_009},{'retain_until':2_000_000_651},
                {'receipt_ref':h['receipt_ref']|{'key':'wrong'}},{'root_authority_ref':h['root_authority_ref']|{'key':'wrong'}}):
            calls.append(self.altered(head_changes=changes,head=True))
        calls.extend([self.altered(commit_signer=self.f['signers']['owner']),self.altered(head_signer=self.f['signers']['owner'],head=True)])
        self.assertTrue(all(not item['ok'] for item in self.parity(calls)))

    def test_independent_writer_message_envelope_and_shared_finite_work(self):
        calls=[self.call(expected={name:value}) for name,value in [('expected_message_id','msg_'+'ab'*32),
            ('expected_receipt_writer',self.f['expected']['expected_owner']),('target_storage_epoch','other_epoch')]]
        ref=self.source.case.expected['expected_envelope_ref'];calls.append(self.call(expected={'expected_envelope_ref':ref|{'key':'other-locator'}}))
        self.assertTrue(all(not item['ok'] for item in self.parity(calls)))
        results=self.parity([self.call(policy={'max_signature_checks':limit}) for limit in (1,20,27,28)])
        self.assertEqual([item['ok'] for item in results],[False,False,False,True])
        for item,limit in zip(results,(1,20,27,28)):
            self.assertEqual(item['nativeChecks'],limit)
            if limit<28:self.assertEqual(item['code'],'repair_over_budget')
        result=self.ts([self.call(policy={'max_signature_checks':28},repeat=True)])[0]
        self.assertTrue(result['ok'],result);self.assertEqual(result['retryCode'],'repair_over_budget');self.assertEqual(result['nativeChecks'],28)

    def test_raw_integrity_host_callbacks_and_immutable_authenticated_head_input(self):
        calls=[]
        for field,value in (('size',1),('raw_sha256','0'*64)):
            call=self.call();call['commit']['ref'][field]=value;calls.append(call)
        for role in ('manifest','commit'):
            call=self.call();raw=b' '+base64.b64decode(call[role]['raw']);call[role]=encoded(dict(raw=raw,ref=reference(raw,'noncanonical-'+role)));calls.append(call)
        self.assertTrue(all(not item['ok'] for item in self.parity(calls)))
        result=self.ts([self.call(mutate=True,forged=encoded(self.result['head']))])[0]
        self.assertTrue(result['ok'],result);self.assertTrue(result['immutable']);self.assertTrue(result['frozen']);self.assertEqual(result['brandCode'],'repair_invalid_ack_occupied')
        for result in self.ts([self.call(host=kind) for kind in ('options','proxy','entry')]):
            self.assertFalse(result['ok']);self.assertEqual(result['callbacks'],0);self.assertEqual(result['nativeChecks'],0);self.assertNotEqual(result['code'],'untyped_error',result)


if __name__=='__main__':unittest.main()
