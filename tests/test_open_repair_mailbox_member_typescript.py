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
const {readMailboxIndex,readMailboxAdmission}=await import('./open-repair-mailbox-read.ts');
const {createHash}=await import('node:crypto');
const {verifyMailboxInboxEvidence}=await import('./open-repair-mailbox-inbox.ts');
const chunks=[];for await(const chunk of process.stdin)chunks.push(chunk);
const calls=JSON.parse(Buffer.concat(chunks).toString()),decode=e=>({raw:Buffer.from(e.raw,'base64'),ref:e.ref}),out=[];
for(const v of calls){let budget,objectReads=0,observed=0;try{
  budget=new RepairBudget(v.policy);const resolver=new LocalRawResolver(v.policy,budget);
  for(const p of v.packs){const e=decode(p);resolver.put(e.ref.namespace,e.ref.key,e.raw);}
  if(v.operation==='inbox'){const result=await verifyMailboxInboxEvidence(v.evidence,Buffer.from(v.envelope,'base64'),v.options);out.push({ok:true,envelopeHash:createHash('sha256').update(result.envelope).digest('hex'),message:result.core.message_id});continue;}
  if(v.operation==='admission'){const originals=new Map(v.originals.map(e=>{const d=decode(e);return [JSON.stringify(d.ref),d.raw];}));
    const result=await readMailboxAdmission(v.member,{...v.options,currentStatuses:v.current.map(decode),knownStatuses:v.known.map(decode),statusObligations:[],onStatusAuthenticated:()=>{observed++;},policy:v.policy,budget,readOriginal:async ref=>{if(ref.namespace==='object')objectReads++;const raw=originals.get(JSON.stringify(ref));if(!raw)throw Error('missing exact original');return raw;}});
    out.push({ok:true,envelopeHash:createHash('sha256').update(result.envelope).digest('hex'),objectReads,observed,metrics:budget.snapshot()});continue;}
  if(v.operation==='index'){let reads=0;const originals=new Map(v.originals.map(e=>{const d=decode(e);return [JSON.stringify(d.ref),d.raw];}));
    const entries=await readMailboxIndex(decode(v.head),decode(v.checkpoint),{...v.options,policy:v.policy,budget,readOriginal:async ref=>{reads++;if(ref.namespace!=='meta')throw Error('premature object read');const bytes=originals.get(JSON.stringify(ref));if(!bytes)throw Error('missing exact ref');return bytes;}});
    out.push({ok:true,entries,reads,metrics:budget.snapshot()});continue;}
  if(v.operation==='feed'){const result=verifyMailboxFeedSourceEvent(decode(v.manifest),resolver,decode(v.custody),{...v.options,policy:v.policy,budget});out.push({ok:true,count:result.graph.head.count,statuses:result.graph.statuses.map(v=>v.canonical_sha256),retain_until:result.retain_until,metrics:budget.snapshot()});continue;}
  const graph=verifyMailboxMemberInputs(decode(v.manifest),resolver,{...v.options,policy:v.policy,budget});
  out.push({ok:true,accepted_at:graph.accepted_at,refs:Object.fromEntries(Object.entries(graph.roles).map(([k,e])=>[k,e.ref])),
    statuses:graph.statuses.map(v=>v.canonical_sha256),ack:graph.ack_configuration!==null,metrics:budget.snapshot()});
}catch(e){out.push({ok:false,code:e.code??'untyped_error',detail:String(e.stack),objectReads,observed,metrics:budget?.snapshot()});}}
process.stdout.write(JSON.stringify({out,subprocessCalls}));
'''

class NativeMailboxMemberTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        runtime.TypeScriptAgentNetworkTests.setUpClass.__func__(cls)
        (cls.fixture/'driver.mjs').write_text(DRIVER)
        from tests.test_open_ack_typescript_agent import DRIVER as agent_driver
        agent_driver=agent_driver.replace('process.stdout.write(JSON.stringify({results,calls,subprocessCalls}));',r'''
let savedReceipt;
if(input.saved_receipt){
  const {OpenNetworkClient}=await import('./open-client.ts'),{OpenDeliveryClient}=await import('./open-delivery-client.ts'),{loadClient}=await import('./client-config.ts');
  const network=new OpenNetworkClient(input.network_config),delivery=new OpenDeliveryClient(network.participant,network.encryption,loadClient(input.client_config));
  try{const item=await delivery.savedReceiptForAck(input.saved_receipt.message_id,input.saved_receipt.owner,input.saved_receipt.envelope_ref);savedReceipt={raw:Buffer.from(item.raw).toString('base64'),ref:item.ref};}
  finally{delivery.close();network.close();}
}
process.stdout.write(JSON.stringify({results,calls,subprocessCalls,savedReceipt}));
''')
        (cls.fixture/'agent-driver.mjs').write_text(agent_driver)

    def native(self,calls):
        result=subprocess.run([self.node,'--experimental-strip-types',str(self.fixture/'driver.mjs')],cwd=self.fixture,
            input=json.dumps(calls).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=40)
        self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace')[-2000:]);out=json.loads(result.stdout)
        self.assertEqual(out['subprocessCalls'],0);return out['out']

    def test_committed_http_member_originals_and_denied_cross_bindings(self):
        self.check_committed(False)

    def test_committed_http_member_with_independent_ack_configuration(self):
        self.check_committed(True)

    def check_committed(self,with_ack):
        method='test_ack_configuration_survives_mailbox_custody' if with_ack else 'test_actual_delivery_stages_exact_ciphertext_under_mailbox_resources'
        h=http_fixture.MailboxStagingHTTPTests(method)
        h.setUp();self.addCleanup(h.doCleanups);visited=[]
        from memory_vault_trust import TrustStore
        from memory_vault_client import ClientConfig
        TrustStore(ClientConfig.load(h.b.client_config).trust_path).add(h.ai.public_descriptor())
        call=h.call
        def share(agent,**request):
            if agent is h.a and (request['op']=='send' or (request.get('invitation',{}).get('action')=='prepare' and request.get('invitation',{}).get('schema_version')=='memory-vault-open-ack-connect/v1')) and not (request.get('memory_ids') or request.get('invitation',{}).get('memory_ids')):
                remembered=call(h.a,op='remember',request_id='req_native_cold_memory',kind='observation',text='Synthetic native cold recovery memory.')
                if request['op']=='send':request=dict(request,memory_ids=[remembered['memory_id']])
                else:request=dict(request,invitation=dict(request['invitation'],memory_ids=[remembered['memory_id']]))
            return call(agent,**request)
        h.call=share
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
            from memory_vault_open_repair_client import read_mailbox_index
            with h.b._network() as network:encryption=network.encryption
            headref=wire.raw_ref(json.loads(held.read(feedpart.manifest.as_dict()))['feed_head_ref'])
            cpref=wire.raw_ref(feedexpected['graph']['head']['checkpoint_ref'])
            indexoptions=dict(expectedSlot=key,expectedSigningKey=s.target['signing_key'],encryptionIdentity=encryption.private_document(),at=feedexpected['custody'].payload['stored_at'],maxMessages=10)
            indexcall=json.loads(json.dumps(dict(operation='index',head=encoded(entry(headref)),checkpoint=encoded(entry(cpref)),originals=[encoded(entry(ref)) for ref in held.originals],packs=[],options=indexoptions,policy=asdict(s.policy))))
            expectedindex=read_mailbox_index(entry(headref),entry(cpref),expected_slot=key,expected_signing_key=s.target['signing_key'],encryption_identity=encryption,read_original=held.read,at=indexoptions['at'],max_messages=10,policy=s.policy)
            from memory_vault_network_crypto import EncryptionIdentity
            wrong=copy.deepcopy(indexcall);wrong['options']['encryptionIdentity']=EncryptionIdentity.generate().private_document()
            indexresults=self.native([indexcall,wrong]);self.assertTrue(indexresults[0]['ok'],indexresults[0]);self.assertEqual(indexresults[0]['entries'],list(expectedindex));self.assertGreater(indexresults[0]['reads'],0)
            self.assertFalse(indexresults[1]['ok']);self.assertEqual(indexresults[1]['code'],'repair_mailbox_range_mismatch')
            from memory_vault_open_repair_client import read_mailbox_admission
            statuses=list({row.original.ref.raw_sha256:dict(raw=row.original.raw,ref=row.original.ref.as_dict()) for row in resolved.roles if row.role.startswith('historical.status.') and not row.role.startswith('historical.status.ack_')}.values())
            admissionoptions=dict(indexoptions,expectedOwner=owner,expectedSender=sender,expectedTarget=s.target,limitPolicy=s.limits);admissionoptions.pop('maxMessages')
            admissioncall=json.loads(json.dumps(dict(operation='admission',member=expectedindex[0],originals=indexcall['originals'],packs=[],options=admissionoptions,current=[encoded(v) for v in statuses],known=[],policy=asdict(s.policy))))
            checked=read_mailbox_admission(expectedindex[0],expected_slot=key,expected_signing_key=s.target['signing_key'],expected_owner=owner,expected_sender=sender,expected_target=s.target,limit_policy=s.limits,current_statuses=statuses,encryption_identity=encryption,read_original=held.read,at=indexoptions['at'],policy=s.policy)
            from memory_vault_open_provider import issue_status
            from tests.test_open_repair_status import status_entry
            owner_status=next(json.loads(v['raw'])['payload'] for v in statuses if json.loads(v['raw'])['payload']['signing_key']['key_id']==h.bi.key_id)
            denied=status_entry(issue_status(h.bi,root=key['root_key'],revision=99,entries=[dict(row,status='revoked') for row in owner_status['entries']],issued_at=indexoptions['at']-10,valid_until=indexoptions['at']-1))
            wrong=copy.deepcopy(admissioncall);wrong['known']=[encoded(denied)]
            missing=copy.deepcopy(admissioncall);missing['current']=[encoded(v) for v in statuses if json.loads(v['raw'])['payload']['signing_key']['key_id']!=h.ai.key_id]
            admissionresults=self.native([admissioncall,wrong,missing]);self.assertTrue(admissionresults[0]['ok'],admissionresults[0])
            import hashlib
            self.assertEqual(admissionresults[0]['envelopeHash'],hashlib.sha256(checked['envelope']).hexdigest());self.assertEqual(admissionresults[0]['objectReads'],1)
            for result,code in zip(admissionresults[1:],['repair_authority_revoked','repair_status_missing']):
                self.assertFalse(result['ok'],result);self.assertEqual(result['code'],code,result);self.assertEqual(result['objectReads'],0);self.assertGreater(result['observed'],0)
            from memory_vault_open_repair_client import verify_mailbox_inbox_evidence
            from memory_vault_network_crypto import b64url
            evidence=dict(schema_version='memory-vault-mailbox-inbox/v1',received_at=indexoptions['at'],slot=key,sender=sender,target=s.target,limits=s.limits,member=expectedindex[0],manifest_ref=feedpart.manifest.as_dict(),custody_ref=feedpart.custody.as_dict(),originals=[dict(ref=ref.as_dict(),raw_base64url=b64url(held.read(ref.as_dict()))) for ref in held.originals if ref.namespace=='meta'],status_refs=[v['ref'] for v in statuses])
            verify_mailbox_inbox_evidence(evidence,checked['envelope'],owner=owner,encryption_identity=encryption,staged_at=indexoptions['at'])
            import base64
            inboxcall=json.loads(json.dumps(dict(operation='inbox',packs=[],policy=asdict(s.policy),evidence=evidence,envelope=base64.b64encode(checked['envelope']).decode(),options=dict(owner=owner,encryptionIdentity=encryption.private_document(),stagedAt=indexoptions['at']))))
            wrong=copy.deepcopy(inboxcall);wrong['evidence']['received_at']+=1
            inboxresults=self.native([inboxcall,wrong]);self.assertTrue(inboxresults[0]['ok'],inboxresults[0]);self.assertEqual(inboxresults[0]['message'],checked['core']['message_id']);self.assertFalse(inboxresults[1]['ok']);self.assertEqual(inboxresults[1]['code'],'repair_invalid_context')
            # The Python recipient stops after durable staging. A fresh native
            # Agent resumes that inbox and imports the original memory bytes.
            from memory_vault_open_delivery import decrypt_envelope
            from memory_vault_network_crypto import document
            plaintext=decrypt_envelope(checked['envelope'],encryption_identity=encryption,sender_signing_key=sender['signing_key'],sender_encryption_key=sender['encryption_key'],recipient_signing_key=owner['signing_key'],recipient_encryption_key=owner['encryption_key'])
            session=dict(mailbox=evidence,authority={name:document(roles[role]['raw']) for name,role in [('request','contact.request'),('policy','contact.policy')]},source_node=s.node)
            with h.b._network() as network:
                row=network._delivery()._stage_inbox(message_id=checked['core']['message_id'],sender_key_id=h.ai.key_id,envelope=checked['envelope'],body=plaintext,session=session)
                self.assertEqual(row['phase'],'staged')
            result=subprocess.run([self.node,'--experimental-strip-types',str(self.fixture/'agent-driver.mjs')],cwd=self.fixture,input=json.dumps(dict(client_config=str(h.b.client_config),network_config=str(h.b.network_config),requests=[dict(op='receive',limit=1),dict(op='receive',message_id=checked['core']['message_id'])],no_network=True,saved_receipt=dict(message_id=checked['core']['message_id'],owner=sender,envelope_ref=checked['core']['envelope_ref']))).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=40)
            self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace')[-2000:]);native=json.loads(result.stdout);self.assertEqual(native['subprocessCalls'],0);self.assertEqual(native['calls'],[])
            for result in native['results']:self.assertTrue(result['ok'],result)
            messages=native['results'][0]['result']['messages'];self.assertEqual(len(messages),1,messages);self.assertEqual(messages[0]['state'],'validated_saved');self.assertEqual(messages[0]['content_kind'],'memory_transfer');self.assertEqual(messages[0]['share']['records_added'],1)
            with h.b._network() as network:
                row=network._delivery()._inbox(checked['core']['message_id']);self.assertEqual(row['phase'],'saved');self.assertIsNotNone(row['receipt']);self.assertFalse(row['receipt_sent']);self.assertEqual(base64.b64decode(native['savedReceipt']['raw']),bytes(row['receipt']))
            for label,result in zip(labels[1:],results[1:]):
                with self.subTest(label=label):self.assertFalse(result['ok'],result);self.assertNotEqual(result['code'],'untyped_error',result)
        h.inspect_committed_mailbox=inspect
        getattr(h,method)();self.assertEqual(visited,[True])

if __name__=='__main__':unittest.main()
