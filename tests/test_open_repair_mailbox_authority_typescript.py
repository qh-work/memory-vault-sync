"""Original Python mailbox owner controls consumed by the native reader."""
import copy
import json
import subprocess
import unittest
from dataclasses import asdict
from tests import test_network_typescript_agent_network as runtime
from tests import test_open_repair_mailbox_activation as activation
from tests.test_open_repair_probe_typescript import encoded
from tests.open_repair_ack_fixtures import signed_entry
from memory_vault_open_repair_mailbox_activation import verify_mailbox_feed_bootstrap,verify_mailbox_slot_owner_inputs,verify_mailbox_genesis
from memory_vault_open_repair_wire import RepairBudget,RepairWireError

DRIVER=runtime.DRIVER.split('const {Agent}',1)[0]+r'''
const {RepairBudget}=await import('./open-repair-wire.ts');
const api=await import('./open-repair-mailbox-authority.ts');
const chunks=[];for await(const chunk of process.stdin)chunks.push(chunk);
const v=JSON.parse(Buffer.concat(chunks).toString()),decode=e=>({raw:Buffer.from(e.raw,'base64'),ref:e.ref}),
  entries=Object.fromEntries(Object.entries(v.entries).map(([k,e])=>[k,decode(e)])),budget=new RepairBudget(v.policy),options={...v.options,policy:v.policy,budget};
try{
  const result=v.operation==='resource'?api.verifyMailboxResourceInputs(entries,options):v.operation==='genesis'?api.verifyMailboxGenesis(entries,options):v.operation==='bootstrap'?api.verifyMailboxFeedBootstrap(entries,options):
    api.verifyMailboxSlotOwnerInputs(entries,Object.fromEntries(Object.entries(v.offers).map(([k,e])=>[k,decode(e)])),options);
  const first=Object.values(result)[0],before=Buffer.from(first.raw).toString('hex');first.raw.fill(0);
  process.stdout.write(JSON.stringify({ok:true,refs:Object.fromEntries(Object.entries(result).map(([k,e])=>[k,e.ref])),
    immutable:before===Buffer.from(first.raw).toString('hex'),metrics:budget.snapshot(),subprocessCalls}));
}catch(e){process.stdout.write(JSON.stringify({ok:false,code:e.code??'untyped_error',detail:e.code?undefined:String(e.stack),metrics:budget.snapshot(),subprocessCalls}));}
'''

class NativeMailboxAuthorityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        runtime.TypeScriptAgentNetworkTests.setUpClass.__func__(cls)
        (cls.fixture/'driver.mjs').write_text(DRIVER)

    def setUp(self):
        self.case=activation.MailboxActivationTests();self.case.setUp();self.addCleanup(self.case.doCleanups)
        self.entries=self.case.setup_entries();self.policy=self.case.source.policy
        self.options=dict(expectedSlot=self.case.slot_key,expectedOwner=self.case.owner,expectedTarget=self.case.source.target,
            targetStorageEpoch=self.case.slot_key['writer_storage_epoch'],limitPolicy=self.case.source.limits,at=self.case.now)
        self.offers={n:self.case.offers[p] for n,p in [('data','mailbox_data'),('metadata','feed_metadata')]}

    def native(self,entries=None,*,operation='owner',options=None,policy=None):
        selected=entries or self.entries
        if operation=='bootstrap':selected={k:v for k,v in selected.items() if k!='activation'}
        value=dict(operation=operation,entries={k:encoded(v) for k,v in selected.items()},offers={k:encoded(v) for k,v in self.offers.items()},
            options=options or self.options,policy=policy or asdict(self.policy))
        result=subprocess.run([self.node,'--experimental-strip-types',str(self.fixture/'driver.mjs')],cwd=self.fixture,
            input=json.dumps(value).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=25)
        self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace')[-2000:]);out=json.loads(result.stdout)
        self.assertEqual(out['subprocessCalls'],0);return out

    def python(self,entries,*,bootstrap=False,at=None):
        c=self.case;args=dict(expected_slot=c.slot_key,expected_owner=c.owner,expected_target=c.source.target,
            target_storage_epoch=c.slot_key['writer_storage_epoch'],limit_policy=c.source.limits,at=at or c.now,
            policy=self.policy,budget=RepairBudget(self.policy))
        if bootstrap:return verify_mailbox_feed_bootstrap({k:v for k,v in entries.items() if k!='activation'},**args)
        return verify_mailbox_slot_owner_inputs(entries,offers=self.offers,**args)

    def test_exact_owner_chain_and_bootstrap_keep_original_refs(self):
        for operation in ['owner','bootstrap']:
            native=self.native(operation=operation);self.assertTrue(native['ok'],native);self.assertTrue(native['immutable'])
            checked=self.python(self.entries,bootstrap=operation=='bootstrap')
            self.assertEqual(native['refs'],{k:v.ref.as_dict() for k,v in checked.items()})
            self.assertEqual(native['metrics']['signature_checks'],5 if operation=='owner' else 4)

    def test_owner_signed_wrong_reader_is_not_authorized(self):
        entries=self.case.setup_entries(dict(read=dict(reader=self.case.dual(self.case.source.target))))
        for bootstrap in [False,True]:
            with self.assertRaises(RepairWireError):self.python(entries,bootstrap=bootstrap)
            result=self.native(entries,operation='bootstrap' if bootstrap else 'owner');self.assertFalse(result['ok']);self.assertNotEqual(result['code'],'untyped_error')

    def test_changed_scope_or_budget_never_repairs_signed_parent_chain(self):
        for name,field,value in [('activation','target_storage_epoch','changed_epoch'),('slot','max_live_items',65537),('bootstrap','proof_until',self.case.now),
                                 ('maintenance','allowed_roles',['bootstrap.grant','bootstrap.grant'])]:
            with self.subTest(name=name):
                entries=copy.deepcopy(self.entries);p=json.loads(entries[name]['raw'])['payload'];p[field]=value
                entries[name]=signed_entry(p,self.case.f['signers']['owner'],'synthetic_mutated_owner')
                with self.assertRaises(RepairWireError):self.python(entries)
                result=self.native(entries);self.assertFalse(result['ok']);self.assertNotEqual(result['code'],'untyped_error')

    def test_invalid_reference_expiry_and_signature_budget_refuse(self):
        entries=copy.deepcopy(self.entries);entries['slot']['ref']['raw_sha256']='0'*64
        result=self.native(entries);self.assertFalse(result['ok']);self.assertEqual(result['code'],'repair_ref_mismatch')
        result=self.native(options=dict(self.options,at=self.case.now+600));self.assertFalse(result['ok']);self.assertEqual(result['code'],'repair_resource_expired')
        result=self.native(policy=dict(asdict(self.policy),max_signature_checks=4));self.assertFalse(result['ok']);self.assertEqual(result['code'],'repair_over_budget')

    def test_actual_durable_resource_chain_matches_owner_scope_and_original_limits(self):
        from memory_vault_open_repair_resource import verify_mailbox_resource_inputs
        c=self.case;activated=c.activate(self.entries);p=json.loads(self.entries['activation']['raw'])['payload']
        for name,purpose in [('data','mailbox_data'),('metadata','feed_metadata')]:
            row=c.db.execute('SELECT allocation,allocation_ref FROM open_repair_mailbox_resources WHERE purpose=?',(purpose,)).fetchone()
            entries=dict(allocate=dict(raw=bytes(row[0]),ref=json.loads(row[1])),offer=self.offers[name],activation=self.entries['activation'],active=activated[name])
            options=dict(expectedRoot=c.root,expectedOwner=c.owner,expectedTarget=c.source.target,targetStorageEpoch=c.slot_key['writer_storage_epoch'],
                expectedPurpose=purpose,expectedScope=p['scope'],expectedAuthorityRefs=p['authority_refs'],expectedOfferRefs=p['resource_offer_refs'],at=c.now)
            checked=verify_mailbox_resource_inputs(entries,expected_root=c.root,expected_owner=c.owner,expected_target=c.source.target,
                target_storage_epoch=c.slot_key['writer_storage_epoch'],expected_purpose=purpose,expected_scope=p['scope'],expected_authority_refs=p['authority_refs'],
                expected_offer_refs=p['resource_offer_refs'],at=c.now,policy=self.policy,budget=RepairBudget(self.policy))
            result=self.native(entries,operation='resource',options=options);self.assertTrue(result['ok'],result);self.assertTrue(result['immutable'])
            self.assertEqual(result['refs'],{k:v.ref.as_dict() for k,v in checked.items()})
            result=self.native(entries,operation='resource',options=dict(options,expectedPurpose='anchor_catalog'))
            self.assertFalse(result['ok']);self.assertNotEqual(result['code'],'untyped_error')
            changed=json.loads(entries['active']['raw'])['payload'];changed['budget']['max_items']+=1
            wrong=dict(entries,active=signed_entry(changed,c.f['signers']['target'],'synthetic_inflated_resource'))
            result=self.native(wrong,operation='resource',options=options);self.assertFalse(result['ok']);self.assertEqual(result['code'],'repair_resource_mismatch')

    def test_actual_node_genesis_requires_empty_count_and_exact_commit(self):
        c=self.case;activated=c.activate(self.entries);entries={n:activated[n] for n in ('checkpoint','head')}
        options=dict(expectedSlot=c.slot_key,expectedSigningKey=c.source.identity.public_descriptor(),committedAt=c.now,at=c.now)
        result=self.native(entries,operation='genesis',options=options);self.assertTrue(result['ok'],result);self.assertTrue(result['immutable'])
        self.assertEqual(result['refs'],{n:e['ref'] for n,e in entries.items()})
        for field,value in [('count',1),('catalog_generation',1),('range_root_ref',entries['checkpoint']['ref'])]:
            p=json.loads(entries['head']['raw'])['payload'];p[field]=value
            wrong=dict(entries,head=signed_entry(p,c.f['signers']['target'],'synthetic_nonempty_genesis'))
            result=self.native(wrong,operation='genesis',options=options);self.assertFalse(result['ok']);self.assertNotEqual(result['code'],'untyped_error')
            with self.assertRaises(RepairWireError):verify_mailbox_genesis(wrong,expected_slot=c.slot_key,expected_signing_key=c.source.identity.public_descriptor(),
                committed_at=c.now,at=c.now,policy=self.policy,budget=RepairBudget(self.policy))

if __name__=='__main__':unittest.main()
