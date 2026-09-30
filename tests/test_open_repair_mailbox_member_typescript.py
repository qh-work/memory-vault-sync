"""Native admission graph consumes originals from a real HTTP mailbox commit."""
import copy
import json
import subprocess
import unittest
from dataclasses import asdict
from tests import test_network_typescript_agent_network as runtime
from tests import test_open_delivery_http as http_fixture
from tests.test_open_repair_probe_typescript import encoded
from tests.open_repair_ack_fixtures import reference
import memory_vault_open_repair_wire as wire
import memory_vault_open_repair_history as history
from memory_vault_open_repair_mailbox_snapshot import MailboxSnapshotSource
from memory_vault_open_repair_mailbox_activation import verify_mailbox_member_inputs

DRIVER=runtime.DRIVER.split('const {Agent}',1)[0]+r'''
const {RepairBudget,LocalRawResolver}=await import('./open-repair-wire.ts');
const {verifyMailboxMemberInputs}=await import('./open-repair-mailbox-member.ts');
const {verifyMailboxFeedSourceEvent}=await import('./open-repair-mailbox-feed.ts');
const chunks=[];for await(const chunk of process.stdin)chunks.push(chunk);
const calls=JSON.parse(Buffer.concat(chunks).toString()),decode=e=>({raw:Buffer.from(e.raw,'base64'),ref:e.ref}),out=[];
for(const v of calls){let budget;try{
  budget=new RepairBudget(v.policy);const resolver=new LocalRawResolver(v.policy,budget);
  for(const p of v.packs){const e=decode(p);resolver.put(e.ref.namespace,e.ref.key,e.raw);}
  if(v.operation==='feed'){const result=verifyMailboxFeedSourceEvent(decode(v.manifest),resolver,decode(v.custody),{...v.options,policy:v.policy,budget});out.push({ok:true,count:result.graph.head.count,statuses:result.graph.statuses.map(v=>v.canonical_sha256),retain_until:result.retain_until,metrics:budget.snapshot()});continue;}
  const graph=verifyMailboxMemberInputs(decode(v.manifest),resolver,{...v.options,policy:v.policy,budget});
  out.push({ok:true,accepted_at:graph.accepted_at,refs:Object.fromEntries(Object.entries(graph.roles).map(([k,e])=>[k,e.ref])),
    statuses:graph.statuses.map(v=>v.canonical_sha256),ack:graph.ack_configuration!==null,metrics:budget.snapshot()});
}catch(e){out.push({ok:false,code:e.code??'untyped_error',detail:String(e.stack),metrics:budget?.snapshot()});}}
process.stdout.write(JSON.stringify({out,subprocessCalls}));
'''

class NativeMailboxMemberTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        runtime.TypeScriptAgentNetworkTests.setUpClass.__func__(cls)
        (cls.fixture/'driver.mjs').write_text(DRIVER)

    def native(self,calls):
        result=subprocess.run([self.node,'--experimental-strip-types',str(self.fixture/'driver.mjs')],cwd=self.fixture,
            input=json.dumps(calls).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=40)
        self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace')[-2000:]);out=json.loads(result.stdout)
        self.assertEqual(out['subprocessCalls'],0);return out['out']

    def test_committed_http_member_originals_and_denied_cross_bindings(self):
        h=http_fixture.MailboxStagingHTTPTests('test_actual_delivery_stages_exact_ciphertext_under_mailbox_resources')
        h.setUp();self.addCleanup(h.doCleanups);visited=[]
        def inspect(staging,key,head):
            visited.append(True);s=staging.source
            rid=staging.db.execute('SELECT resource_id FROM open_repair_mailbox_roots').fetchone()[0]
            held=MailboxSnapshotSource(staging).load(rid,key,head,max_bytes=2_000_000,max_items=256);part=held.parts[2]
            def entry(ref):return dict(raw=held.read(ref.as_dict()),ref=ref.as_dict())
            packs=[entry(ref) for role,ref in part.transfer if role=='history.raw_pack'];manifest=entry(part.manifest)
            core=next(ref for role,ref in part.transfer if role=='member.core');accepted=json.loads(held.read(core.as_dict()))['payload']['accepted_at']
            owner=json.loads(staging.db.execute('SELECT owner_keys FROM open_repair_mailbox_resources LIMIT 1').fetchone()[0])
            envelope=json.loads(held.read(held.envelopes[0].as_dict()))
            sender=dict(signing_key=h.ai.public_descriptor(),encryption_key=envelope['payload']['context']['sender_encryption_key'])
            options=dict(expectedSlot=key,expectedOwner=owner,expectedSender=sender,expectedTarget=s.target,
                targetStorageEpoch=s.node['payload']['storage_epoch'],acceptedAt=accepted,limitPolicy=s.limits)
            budget=wire.RepairBudget(s.policy);resolver=wire.LocalRawResolver(s.policy,budget)
            for p in packs:resolver.put(p['ref']['namespace'],p['ref']['key'],p['raw'])
            resolved=history.resolve_historical_inputs(manifest['raw'],resolver,s.policy,budget)
            expected=verify_mailbox_member_inputs(resolved,expected_slot=key,expected_owner=owner,expected_sender=sender,expected_target=s.target,
                target_storage_epoch=options['targetStorageEpoch'],accepted_at=accepted,limit_policy=s.limits,policy=s.policy,budget=budget)
            call=dict(manifest=encoded(manifest),packs=[encoded(p) for p in packs],options=options,policy=asdict(s.policy))
            call=json.loads(json.dumps(call))
            calls=[call];labels=['exact']
            for name,value in [('expectedSender',owner),('targetStorageEpoch','different_epoch'),('acceptedAt',accepted+10000)]:
                wrong=copy.deepcopy(call);wrong['options'][name]=value;calls.append(wrong);labels.append(name)
            wrong=copy.deepcopy(call);wrong['manifest']['ref']['raw_sha256']='0'*64;calls.append(wrong);labels.append('manifest_ref')
            wrong=copy.deepcopy(call);wrong['policy']['max_signature_checks']=3;calls.append(wrong);labels.append('signature_budget')
            # Repack exact original documents under a wrong role. Every pack hash
            # remains valid; typed admission checks must reject the substitution.
            roles={row.role:dict(raw=row.original.raw,ref=row.original.ref.as_dict()) for row in resolved.roles}
            for target,other in [('historical.status.disclosure','historical.status.slot'),('contact.decision','contact.policy'),('delivery.destination','delivery.attempt')]:
                altered=dict(roles);altered[target]=roles[other];meter=wire.RepairBudget(s.policy)
                pack=wire.build_raw_pack([v['raw'] for v in altered.values()],s.policy,meter)
                indices={(v.raw_sha256,v.size):i for i,v in enumerate(pack.entries)}
                value=dict(json.loads(manifest['raw']),roles=[dict(role=role,document_ref=v['ref'],pack_ref=pack.ref.as_dict(),entry_index=indices[(v['ref']['raw_sha256'],v['ref']['size'])]) for role,v in sorted(altered.items())])
                changed=history.build_historical_manifest(value,s.policy,meter)
                wrong=copy.deepcopy(call);wrong['manifest']=encoded(dict(raw=changed.raw,ref=reference(changed.raw,'native_mutated_member')))
                wrong['packs']=[encoded(dict(raw=pack.raw,ref=pack.ref.as_dict()))];calls.append(wrong);labels.append(target)
            results=self.native(calls);good=results[0];self.assertTrue(good['ok'],good)
            self.assertEqual(good['accepted_at'],accepted);self.assertEqual(good['refs'],{k:v['ref'] for k,v in expected['roles'].items()})
            self.assertEqual(good['statuses'],[v.canonical_sha256 for v in expected['statuses']]);self.assertEqual(good['ack'],expected['ack_configuration'] is not None)
            from memory_vault_open_repair_mailbox_activation import verify_mailbox_feed_source_event
            feedpart=held.parts[1];feedpacks=[entry(ref) for role,ref in feedpart.transfer if role=='history.raw_pack']
            feedoptions={k:v for k,v in options.items() if k not in ('acceptedAt','targetStorageEpoch')}
            feedcall=json.loads(json.dumps(dict(operation='feed',manifest=encoded(entry(feedpart.manifest)),custody=encoded(entry(feedpart.custody)),packs=[encoded(p) for p in feedpacks],options=feedoptions,policy=asdict(s.policy))))
            meter=wire.RepairBudget(s.policy);local=wire.LocalRawResolver(s.policy,meter)
            for pack in feedpacks:local.put(pack['ref']['namespace'],pack['ref']['key'],pack['raw'])
            feedexpected=verify_mailbox_feed_source_event(entry(feedpart.manifest),local,entry(feedpart.custody),expected_slot=key,expected_owner=owner,expected_sender=sender,expected_target=s.target,limit_policy=s.limits,policy=s.policy,budget=meter)
            feedcalls=[feedcall]
            wrong=copy.deepcopy(feedcall);wrong['options']['expectedSender']=owner;feedcalls.append(wrong)
            wrong=copy.deepcopy(feedcall);wrong['custody']['ref']['raw_sha256']='0'*64;feedcalls.append(wrong)
            feedresults=self.native(feedcalls);self.assertTrue(feedresults[0]['ok'],feedresults[0])
            self.assertEqual(feedresults[0]['count'],1);self.assertEqual(feedresults[0]['retain_until'],feedexpected['retain_until'])
            self.assertEqual(feedresults[0]['statuses'],[v.canonical_sha256 for v in feedexpected['graph']['statuses']])
            for result in feedresults[1:]:self.assertFalse(result['ok']);self.assertNotEqual(result['code'],'untyped_error',result)
            for label,result in zip(labels[1:],results[1:]):
                with self.subTest(label=label):self.assertFalse(result['ok'],result);self.assertNotEqual(result['code'],'untyped_error',result)
        h.inspect_committed_mailbox=inspect
        h.test_actual_delivery_stages_exact_ciphertext_under_mailbox_resources();self.assertEqual(visited,[True])

if __name__=='__main__':unittest.main()
