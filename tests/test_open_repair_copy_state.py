"""Real destination storage with synthetic owner/source copy permissions."""
import copy
import hashlib
import json
import unittest
from dataclasses import replace

from memory_vault import canonical_bytes
from memory_vault_open_repair_copy_state import RepairCopyState
import memory_vault_open_repair_copy_authority as authority
import memory_vault_open_repair_ack as ack
import memory_vault_open_repair_index as index
import memory_vault_open_repair_status as status
import memory_vault_open_repair_wire as wire
from tests import test_open_repair_copy_prepare as preparation
from tests.open_repair_ack_fixtures import load_fixture,signed_entry,reference


class CopyStateTests(unittest.TestCase):
    def setUp(self):
        self.base=preparation.CopyPreparationTests()
        self.base.source_capacity=getattr(self,"source_capacity",None)
        self.base.setUp();self.addCleanup(self.base.doCleanups)
        self.f=self.base.f;self.destination=self.base.destination
        if getattr(self,'extra_pack',False):
            p=self.destination.state.policy
            raws=list({entry['raw'] for entry in self.f['entries'].values()})+[b'synthetic undisclosed pack entry']
            pack=wire.build_raw_pack(raws,p,wire.RepairBudget(p))
            positions={entry.raw_sha256:i for i,entry in enumerate(pack.entries)}
            manifest=json.loads(self.f['manifest']['raw'])
            for member in manifest['roles']:
                member['pack_ref']=pack.ref.as_dict();member['entry_index']=positions[member['document_ref']['raw_sha256']]
            raw=canonical_bytes(manifest);self.f['manifest']=dict(raw=raw,ref=reference(raw,'changed_manifest'))
            self.f['packs']=[dict(raw=pack.raw,ref=pack.ref.as_dict())]
            payload=json.loads(self.f['custody']['raw'])['payload'];payload['historical_manifest_ref']=self.f['manifest']['ref']
            self.f['custody']=signed_entry(payload,self.f['signers']['target'],'changed_custody')
            self.base.intent['historical_manifest_ref']=self.f['manifest']['ref'];self.base.make_consent()
        if hasattr(self,'metadata_budget'):
            self.base.intent['budget']['max_meta_bytes']=self.metadata_budget;self.base.make_consent()
        self.offer=self.base.allocate_offer();self.assignment=self.base.prepare(offer=self.offer)
        self.request=self.base.prepare();self.store=RepairCopyState(self.destination.state);self.store.initialize()
        resolver,p,budget=load_fixture(self.f,self.destination.state.policy)
        source=ack.verify_ack_unbound_source_event(self.f['manifest'],resolver,self.f['custody'],
            **self.f['expected'],policy=p,budget=budget)
        reservation=index._signed(self.base.consent,self.f['expected']['expected_owner']['signing_key'],
            'ack.copy_reservation_consent',authority.CONSENT_FIELDS,p,budget)
        rows=authority.source_inventory(source,reservation,p,budget)
        self.disclosures={}
        for variant,signer in (('owner',self.f['signers']['owner']),('source',self.f['signers']['target'])):
            originals,scopes=authority.disclosure_permissions(rows,signer.key_id,self.base.intent['root_key'],p,budget)
            payload=dict(schema_version='memory-vault-open-repair/v1',kind='ack.copy_disclosure',signing_key=signer.public_descriptor(),
                issued_at=self.base.now,expires_at=2_000_000_100,consent_id='synthetic_'+variant+'_disclosure',revision=1,
                variant=variant,root_key=self.base.intent['root_key'],assignment_ref=self.assignment['ref'],
                source_custody_ref=self.f['custody']['ref'],historical_manifest_ref=self.f['manifest']['ref'],
                target=self.destination.state.target,target_storage_epoch=self.base.intent['target_storage_epoch'],
                disclosure=dict(originals=originals,status_scopes=scopes,until=2_000_000_100))
            self.disclosures[variant]=signed_entry(payload,signer,variant+'_copy_disclosure')
        owner=copy.deepcopy(self.base.owner_status);owner['revision']=3
        source_status=copy.deepcopy(self.f['docs']['target_status']['payload']);source_status['revision']=2
        for variant,value,signer in (('owner',owner,self.f['signers']['owner']),('source',source_status,self.f['signers']['target'])):
            scope=status.status_scope(self.base.intent['root_key'],'authority',dict(authority_kind='ack.copy_disclosure',
                authority_sha256=self.disclosures[variant]['ref']['raw_sha256']),p,wire.RepairBudget(p))
            value['entries'].append(dict(scope_kind='authority',scope_id=scope,minimum_document_revision=0,status='active',operation_mask=4))
            value['entries'].sort(key=lambda e:(e['scope_kind'],e['scope_id']))
        scope=status.status_scope(self.base.intent['root_key'],'assignment',dict(assignment_kind='maintenance.assignment',
            assignment_sha256=self.assignment['ref']['raw_sha256']),p,wire.RepairBudget(p))
        maintainer=dict(schema_version=status.SCHEMA,kind='authority.status',signing_key=self.f['signers']['maintainer'].public_descriptor(),
            scope_key=dict(root_key=self.base.intent['root_key'],issuer_key_id=self.f['signers']['maintainer'].key_id),
            revision=1,issued_at=self.base.now,valid_until=2_000_000_100,entries=[dict(scope_kind='assignment',scope_id=scope,
                minimum_document_revision=0,status='active',operation_mask=70)])
        self.status_values=[owner,source_status,maintainer]
        self.status_signers=[self.f['signers'][name] for name in ('owner','target','maintainer')]

    def commit(self, current=None):
        resolver,_,_=load_fixture(self.f,self.destination.state.policy)
        return self.store.commit_unbound(self.f['manifest'],resolver,self.f['custody'],self.request,self.offer,self.assignment,
            self.base.consent,self.disclosures['owner'],self.disclosures['source'],
            expected_ack_slot=self.f['expected']['expected_ack_slot'],expected_owner=self.f['expected']['expected_owner'],
            expected_source=self.f['expected']['expected_target'],source_storage_epoch=self.f['expected']['target_storage_epoch'],
            expected_maintainer=self.base.keys,current_statuses=current if current is not None else [signed_entry(p,s,'current_'+str(i)) for i,(p,s) in enumerate(zip(self.status_values,self.status_signers))],
            limit_policy=self.f['expected']['limit_policy'])

    def test_commit_keeps_exact_source_after_restart(self):
        custody=self.commit();p=json.loads(custody['raw'])['payload']
        self.assertEqual(p['kind'],'replica.custody');self.assertEqual(p['original_custody_ref'],self.f['custody']['ref'])
        self.assertEqual(p['assignment_ref'],self.assignment['ref'])
        self.destination.db.close();self.destination.connect();self.store=RepairCopyState(self.destination.state);self.store.initialize()
        self.assertEqual(self.commit(),custody)
        resolver=wire.LocalRawResolver(self.destination.state.policy,wire.RepairBudget(self.destination.state.policy))
        actual={}
        for raw,ref in self.destination.db.execute('SELECT raw,ref FROM open_repair_copy_objects'):
            ref=json.loads(bytes(ref));actual[ref['raw_sha256']]=bytes(raw);resolver.put(ref['namespace'],ref['key'],bytes(raw))
        self.assertEqual(actual[self.f['manifest']['ref']['raw_sha256']],self.f['manifest']['raw'])
        self.assertEqual(actual[self.f['custody']['ref']['raw_sha256']],self.f['custody']['raw'])
        source=ack.verify_ack_unbound_source_event(dict(raw=actual[self.f['manifest']['ref']['raw_sha256']],ref=self.f['manifest']['ref']),
            resolver,dict(raw=actual[self.f['custody']['ref']['raw_sha256']],ref=self.f['custody']['ref']),
            **self.f['expected'],policy=self.destination.state.policy,budget=resolver.budget)
        self.assertEqual(source.custody.ref.as_dict(),self.f['custody']['ref'])

    def test_revoked_assignment_never_creates_custody_and_survives_retry(self):
        old=copy.deepcopy(self.status_values[2]);self.status_values[2]['revision']=2
        self.status_values[2]['entries'][0]['status']='revoked'
        with self.assertRaisesRegex(wire.RepairWireError,'repair_authority_revoked'):self.commit()
        self.assertEqual(self.destination.db.execute('SELECT count(*) FROM open_repair_copy_commits').fetchone()[0],0)
        self.status_values[2]=old
        with self.assertRaisesRegex(wire.RepairWireError,'repair_status_rollback|repair_authority_revoked'):self.commit()

    def test_missing_source_disclosure_cannot_be_replaced_by_owner_consent(self):
        self.disclosures['source']=self.disclosures['owner']
        with self.assertRaises(wire.RepairWireError):self.commit()
        self.assertEqual(self.destination.db.execute('SELECT count(*) FROM open_repair_copy_commits').fetchone()[0],0)

    def test_interrupted_commit_rolls_back_all_copied_objects(self):
        self.destination.db.execute("CREATE TRIGGER synthetic_copy_interrupt BEFORE INSERT ON open_repair_copy_commits BEGIN SELECT RAISE(ABORT,'synthetic copy interruption'); END")
        self.destination.db.commit()
        with self.assertRaisesRegex(Exception,'synthetic copy interruption'):self.commit()
        self.assertEqual(self.destination.db.execute('SELECT count(*) FROM open_repair_copy_objects').fetchone()[0],0)
        self.destination.db.execute('DROP TRIGGER synthetic_copy_interrupt');self.destination.db.commit()
        self.assertEqual(json.loads(self.commit()['raw'])['payload']['kind'],'replica.custody')

    def test_unused_pack_bytes_are_not_disclosed_or_copied(self):
        other=CopyStateTests();other.extra_pack=True;self.addCleanup(other.doCleanups)
        with self.assertRaisesRegex(wire.RepairWireError,'repair_invalid_history'):other.setUp()
        self.assertEqual(other.base.local.db.execute('SELECT count(*) FROM ack_copy_prepare_jobs').fetchone()[0],0)

    def test_deleted_copied_object_cannot_recreate_a_successful_commit(self):
        self.commit()
        self.destination.db.execute('DELETE FROM open_repair_copy_objects WHERE rowid=(SELECT min(rowid) FROM open_repair_copy_objects)')
        self.destination.db.commit()
        with self.assertRaisesRegex(wire.RepairWireError,'repair_copy_objects_missing'):self.commit()

    def test_insufficient_metadata_reservation_does_not_commit_or_oversell(self):
        other=CopyStateTests();other.metadata_budget=40000;self.addCleanup(other.doCleanups);other.setUp()
        usage=other.destination.state.capacity.usage()
        with self.assertRaisesRegex(wire.RepairWireError,'repair_copy_(status_)?capacity'):other.commit()
        self.assertEqual(other.destination.state.capacity.usage(),usage)
        self.assertEqual(other.destination.db.execute('SELECT count(*) FROM open_repair_copy_commits').fetchone()[0],0)
        self.assertEqual(other.destination.db.execute('SELECT count(*) FROM open_repair_copy_objects').fetchone()[0],0)

    def test_bad_later_status_does_not_erase_an_authenticated_revocation(self):
        owner=copy.deepcopy(self.status_values[0]);owner['revision']+=1
        for entry in owner['entries']:entry['status']='revoked'
        signed=signed_entry(owner,self.status_signers[0],'revoked_owner')
        with self.assertRaises(wire.RepairWireError):self.commit(current=[signed,{'raw':b'{}','ref':signed['ref']}])
        self.destination.db.close();self.destination.connect();self.store=RepairCopyState(self.destination.state);self.store.initialize()
        with self.assertRaisesRegex(wire.RepairWireError,'repair_status_rollback|repair_authority_revoked'):self.commit()

    def test_assignment_cannot_name_another_owner_service(self):
        body=json.loads(self.assignment['raw'])['payload'];body['bootstrap_grant_refs']=[]
        self.assignment=signed_entry(body,self.f['signers']['maintainer'],'changed_assignment')
        with self.assertRaises(wire.RepairWireError):self.commit()
        self.assertEqual(self.destination.db.execute('SELECT count(*) FROM open_repair_copy_commits').fetchone()[0],0)

    def restore(self,resource_id):
        return self.store.restore_unbound(resource_id,expected_ack_slot=self.f['expected']['expected_ack_slot'],
            expected_owner=self.f['expected']['expected_owner'],expected_source=self.f['expected']['expected_target'],
            source_storage_epoch=self.f['expected']['target_storage_epoch'],expected_maintainer=self.base.keys,
            limit_policy=self.f['expected']['limit_policy'])

    def portable(self):
        custody=self.commit();rid=json.loads(custody['raw'])['payload']['resource']['resource_id']
        held=self.destination.state._one('SELECT * FROM open_repair_copy_commits WHERE resource_id=?',(rid,))
        manifest=self.destination.state._saved(held,'manifest')
        # Copy actual committed bytes to an independent client. No operator DB,
        # private target key, or caller-created authenticated wrapper is used.
        entries=[]
        for table in ('objects','observations'):
            for raw,ref in self.destination.db.execute('SELECT raw,ref FROM open_repair_copy_'+table+' WHERE resource_id=?',(rid,)):
                entries.append(dict(raw=bytes(raw),ref=json.loads(bytes(ref))))
        expected=dict(expected_ack_slot=self.f['expected']['expected_ack_slot'],expected_owner=self.f['expected']['expected_owner'],
            expected_source=self.f['expected']['expected_target'],source_storage_epoch=self.f['expected']['target_storage_epoch'],
            expected_maintainer=self.base.keys,expected_target=self.destination.state.target,
            target_storage_epoch=self.destination.state.node['payload']['storage_epoch'],limit_policy=self.f['expected']['limit_policy'])
        return manifest,custody,entries,expected

    def verify_portable(self,bundle):
        manifest,custody,entries,expected=bundle
        policy=self.destination.state.policy;budget=wire.RepairBudget(policy)
        resolver=wire.LocalRawResolver(policy,budget)
        for entry in entries:
            ref=wire.raw_ref(entry['ref']);resolver.put(ref.namespace,ref.key,entry['raw'])
        return authority.verify_unbound_replica_event(manifest,resolver,custody,**expected,policy=policy,budget=budget)

    def test_independent_client_reconstructs_replica_without_destination_database(self):
        bundle=self.portable();expected_source=self.f['custody']['raw']
        self.destination.db.close();self.destination.connect()
        for table in ('objects','observations','commits','resources'):
            self.destination.db.execute('DELETE FROM open_repair_copy_'+table)
        self.destination.db.commit()
        self.f['entries']={};self.f['packs']=[];self.f['custody']=None
        result=self.verify_portable(bundle)
        self.assertEqual(result['state'],'historical_replica')
        self.assertEqual(result['source'].custody.raw,expected_source)
        self.assertEqual(result['custody'].raw,bundle[1]['raw'])
        self.assertNotIn('object_readable',result)

    def test_replica_client_requires_exact_original_reference_not_matching_hash(self):
        bundle=self.portable()
        missing=self.f['custody']['ref']
        for entry in bundle[2]:
            if entry['ref']==missing:entry['ref']=dict(missing,key='f'*64)
        with self.assertRaises(wire.RepairWireError):self.verify_portable(bundle)

    def test_replica_client_rejects_wrong_independent_source_identity(self):
        bundle=self.portable();bundle[3]['expected_source']=bundle[3]['expected_target']
        with self.assertRaises(wire.RepairWireError):self.verify_portable(bundle)

    def test_replica_client_rejects_tampered_manifest_bytes(self):
        bundle=self.portable();value=json.loads(bundle[0]['raw']);value['kind']='replica.changed'
        bundle[0]['raw']=canonical_bytes(value)
        with self.assertRaisesRegex(wire.RepairWireError,'repair_ref_mismatch'):self.verify_portable(bundle)

    def test_local_service_reads_exact_committed_originals_after_restart(self):
        custody=self.commit();rid=json.loads(custody['raw'])['payload']['resource']['resource_id']
        status_ref=self.restore(rid)['entries']['copy.current_status'][0]
        self.destination.db.close();self.destination.connect();self.store=RepairCopyState(self.destination.state);self.store.initialize()
        for entry in (custody,self.f['custody'],status_ref):
            self.assertEqual(self.store.read_local_original(rid,entry['ref']),entry['raw'])
        alias=dict(self.f['custody']['ref'],key='f'*64)
        with self.assertRaisesRegex(wire.RepairWireError,'repair_ref_missing'):self.store.read_local_original(rid,alias)

    def test_later_observations_are_not_exposed_as_committed_children(self):
        custody=self.commit();rid=json.loads(custody['raw'])['payload']['resource']['resource_id']
        self.status_values[0]['revision']+=1
        current=[signed_entry(p,s,'later_'+str(i)) for i,(p,s) in enumerate(zip(self.status_values,self.status_signers))]
        self.assertEqual(self.commit(current=current),custody)
        with self.assertRaisesRegex(wire.RepairWireError,'repair_ref_missing'):
            self.store.read_local_original(rid,current[0]['ref'])

    def test_local_read_does_not_reset_the_service_work_budget(self):
        custody=self.commit();rid=json.loads(custody['raw'])['payload']['resource']['resource_id']
        budget=wire.RepairBudget(replace(self.destination.state.policy,max_signature_checks=1))
        self.assertEqual(self.store.read_local_original(rid,custody['ref'],_budget=budget),custody['raw'])
        with self.assertRaisesRegex(wire.RepairWireError,'repair_over_budget'):
            self.store.read_local_original(rid,custody['ref'],_budget=budget)

    def test_local_read_refuses_missing_shared_capacity(self):
        custody=self.commit();rid=json.loads(custody['raw'])['payload']['resource']['resource_id']
        self.destination.db.execute("DELETE FROM open_capacity_reservations WHERE service='repair_copy'");self.destination.db.commit()
        with self.assertRaisesRegex(wire.RepairWireError,'repair_copy_ledger_missing'):
            self.store.read_local_original(rid,custody['ref'])

    def test_reconstructs_history_from_destination_only_after_expiry_and_restart(self):
        custody=self.commit();rid=json.loads(custody['raw'])['payload']['resource']['resource_id']
        original=self.f['custody']['raw']
        self.f['manifest']=None;self.f['packs']=[];self.f['entries']={};self.f['custody']=None
        self.destination.db.close();self.destination.connect();self.store=RepairCopyState(self.destination.state);self.store.initialize()
        self.destination.now[0]+=1000
        restored=self.restore(rid)
        self.assertEqual(restored['state'],'historical_replica')
        self.assertEqual(restored['source'].custody.raw,original)
        self.assertEqual(restored['custody'].raw,custody['raw'])
        self.assertEqual(len(restored['authority'].statuses),3)
        self.assertNotIn('object_readable',restored)

    def test_missing_commit_status_original_prevents_reconstruction(self):
        custody=self.commit();rid=json.loads(custody['raw'])['payload']['resource']['resource_id']
        manifest=json.loads(self.destination.db.execute('SELECT manifest FROM open_repair_copy_commits').fetchone()[0])
        ref=next(item['ref'] for item in manifest['original_roles'] if item['role']=='copy.current_status')
        digest=hashlib.sha256(canonical_bytes(ref)).hexdigest()
        self.destination.db.execute('DELETE FROM open_repair_copy_objects WHERE ref_digest=?',(digest,))
        self.destination.db.execute('DELETE FROM open_repair_copy_observations WHERE raw_digest=?',(ref['raw_sha256'],));self.destination.db.commit()
        with self.assertRaisesRegex(wire.RepairWireError,'repair_copy_objects_missing'):self.restore(rid)

    def test_new_current_status_does_not_rewrite_the_original_commit_proof(self):
        custody=self.commit();rid=json.loads(custody['raw'])['payload']['resource']['resource_id']
        self.status_values[0]['revision']+=1
        self.assertEqual(self.commit(),custody)
        restored=self.restore(rid)
        owner=next(item for item in restored['authority'].statuses if item.payload['signing_key']==self.status_signers[0].public_descriptor())
        self.assertEqual(owner.payload['revision'],3)

    def test_missing_capacity_ledger_refuses_reconstruction(self):
        custody=self.commit();rid=json.loads(custody['raw'])['payload']['resource']['resource_id']
        self.destination.db.execute("DELETE FROM open_capacity_reservations WHERE service='repair_copy'");self.destination.db.commit()
        with self.assertRaisesRegex(wire.RepairWireError,'repair_copy_ledger_missing'):self.restore(rid)

    def test_replica_signature_cannot_substitute_for_recomputed_history_edges(self):
        custody=self.commit();rid=json.loads(custody['raw'])['payload']['resource']['resource_id']
        row=self.destination.state._one('SELECT * FROM open_repair_copy_commits WHERE resource_id=?',(rid,))
        manifest=json.loads(bytes(row['manifest']));manifest['edges'][0]['relation']='ack-commit-receipt'
        raw=canonical_bytes(manifest);sha=hashlib.sha256(raw).hexdigest()
        ref=dict(namespace='meta',key=sha,raw_sha256=sha,size=len(raw))
        payload=json.loads(custody['raw'])['payload'];payload['replica_manifest_ref']=ref
        changed=signed_entry(payload,self.destination.state.identity,'synthetic_changed_replica')
        self.destination.db.execute('UPDATE open_repair_copy_commits SET manifest=?,manifest_ref=?,custody=?,custody_ref=? WHERE resource_id=?',
            (raw,canonical_bytes(ref),changed['raw'],canonical_bytes(changed['ref']),rid));self.destination.db.commit()
        with self.assertRaisesRegex(wire.RepairWireError,'repair_copy_commit_mismatch'):self.restore(rid)



class CopyReadTests(unittest.TestCase):
    # New signed resources reserve room for multiple current-status generations.
    # Existing copy commitments and their capacity limits are never enlarged.
    source_capacity=dict(max_meta_bytes=524288)
    setUp=CopyStateTests.setUp
    commit=CopyStateTests.commit
    restore=CopyStateTests.restore

    def read_configuration(self):
        policy=self.destination.state.policy
        resolver,_,_=load_fixture(self.f,policy)
        copy_statuses=[signed_entry(p,s,'copy_status_'+str(i)) for i,(p,s) in enumerate(zip(self.status_values,self.status_signers))]
        plan=authority.verify_unbound_copy(self.f['manifest'],resolver,self.f['custody'],self.request,self.offer,self.assignment,
            self.base.consent,self.disclosures['owner'],self.disclosures['source'],
            expected_ack_slot=self.f['expected']['expected_ack_slot'],expected_owner=self.f['expected']['expected_owner'],
            expected_source=self.f['expected']['expected_target'],source_storage_epoch=self.f['expected']['target_storage_epoch'],
            expected_maintainer=self.base.keys,expected_target=self.destination.state.target,
            target_storage_epoch=self.base.intent['target_storage_epoch'],current_statuses=copy_statuses,
            at=self.destination.now[0],limit_policy=self.f['expected']['limit_policy'],policy=policy,budget=resolver.budget)
        self.assertIsNone(plan.denial_code)
        consents={};current=[];root=self.base.intent['root_key'];now=self.destination.now[0]
        for i,(variant,name) in enumerate((('owner','owner'),('source','target'),('maintainer','maintainer'))):
            signer=self.f['signers'][name];budget=wire.RepairBudget(policy)
            originals,scopes=authority.copy_return_permissions(plan,signer.key_id,policy,budget)
            p=dict(schema_version=authority.resource.SCHEMA,kind='ack.replica_return_consent',signing_key=signer.public_descriptor(),
                issued_at=self.base.now,expires_at=2_000_000_100,consent_id='synthetic_return_'+variant,revision=1,variant=variant,
                root_key=root,source_custody_ref=self.f['custody']['ref'],historical_manifest_ref=self.f['manifest']['ref'],
                assignment_ref=self.assignment['ref'],subject=root['owner'],
                target=self.destination.state.target,target_storage_epoch=self.base.intent['target_storage_epoch'],
                bootstrap_grant_ref=plan.source.bootstrap.originals['bootstrap'].ref.as_dict(),
                return_permission=dict(originals=originals,status_scopes=scopes,until=2_000_000_100))
            entry=signed_entry(p,signer,'return_'+variant);consents[variant]=entry
            scope=status.status_scope(root,'authority',dict(authority_kind=p['kind'],authority_sha256=entry['ref']['raw_sha256']),policy,budget)
            value=copy.deepcopy(self.status_values[i]);value['revision']+=1
            value['entries'].append(dict(scope_kind='authority',scope_id=scope,minimum_document_revision=0,status='active',operation_mask=2))
            value['entries'].sort(key=lambda e:(e['scope_kind'],e['scope_id']))
            current.append(signed_entry(value,signer,'return_status_'+variant))
        # A/R/M have signed both return permissions and current observations
        # before P commits; no additional contact with them is required below.
        custody=self.commit(current=copy_statuses);rid=json.loads(custody['raw'])['payload']['resource']['resource_id']
        target=self.destination.state.identity
        scope=status.status_scope(root,'resource',json.loads(custody['raw'])['payload']['resource'],policy,wire.RepairBudget(policy))
        value=dict(schema_version=status.SCHEMA,kind='authority.status',signing_key=target.public_descriptor(),
            scope_key=dict(root_key=root,issuer_key_id=target.key_id),revision=1,issued_at=now,valid_until=2_000_000_100,
            entries=[dict(scope_kind='resource',scope_id=scope,minimum_document_revision=0,status='active',operation_mask=2)])
        current.append(signed_entry(value,target,'return_target_status'))
        return rid,consents,current

    def prepare_read(self,configuration):
        rid,consents,current=configuration
        return self.store.prepare_unbound_read(rid,consents,expected_ack_slot=self.f['expected']['expected_ack_slot'],
            expected_owner=self.f['expected']['expected_owner'],expected_source=self.f['expected']['expected_target'],
            source_storage_epoch=self.f['expected']['target_storage_epoch'],expected_maintainer=self.base.keys,
            current_statuses=current,limit_policy=self.f['expected']['limit_policy'])

    def test_current_return_permission_survives_restart_and_closed_upload_reservation(self):
        config=self.read_configuration();self.destination.now[0]+=61
        self.destination.db.close();self.destination.connect();self.store=RepairCopyState(self.destination.state);self.store.initialize()
        result=self.prepare_read(config)
        self.assertEqual(result['state'],'permission_checked')
        self.assertEqual(result['subject'],self.base.intent['root_key']['owner'])
        self.assertGreater(result['expires_at'],self.destination.now[0])
        self.assertNotIn('object_readable',result)
        self.assertNotIn('entries',result)

    def test_copy_disclosure_does_not_substitute_for_explicit_owner_return(self):
        config=self.read_configuration();config[1]['source']=self.disclosures['source']
        with self.assertRaises(wire.RepairWireError):self.prepare_read(config)

    def test_return_permission_cannot_authorize_another_reader(self):
        config=self.read_configuration();payload=json.loads(config[1]['source']['raw'])['payload']
        payload['subject']=self.base.keys
        config[1]['source']=signed_entry(payload,self.f['signers']['target'],'wrong_reader')
        with self.assertRaises(wire.RepairWireError):self.prepare_read(config)

    def test_read_assignment_revocation_is_retained_across_restart_and_old_replay(self):
        config=self.read_configuration();old=copy.deepcopy(config[2])
        payload=json.loads(config[2][2]['raw'])['payload'];payload['revision']+=1
        for entry in payload['entries']:
            if entry['scope_kind']=='assignment':entry['status']='revoked'
        config[2][2]=signed_entry(payload,self.f['signers']['maintainer'],'return_revoked_assignment')
        with self.assertRaisesRegex(wire.RepairWireError,'repair_authority_revoked'):self.prepare_read(config)
        self.destination.db.close();self.destination.connect();self.store=RepairCopyState(self.destination.state);self.store.initialize()
        with self.assertRaisesRegex(wire.RepairWireError,'repair_status_rollback|repair_authority_revoked'):
            self.prepare_read((config[0],config[1],old))

    def test_malformed_later_read_status_cannot_erase_valid_revocation(self):
        config=self.read_configuration();old=copy.deepcopy(config[2])
        payload=json.loads(config[2][0]['raw'])['payload'];payload['revision']+=1
        for entry in payload['entries']:entry['status']='revoked'
        config[2][0]=signed_entry(payload,self.f['signers']['owner'],'revoked_return_owner')
        config[2][1]=dict(raw=b'{}',ref=config[2][1]['ref'])
        with self.assertRaises(wire.RepairWireError):self.prepare_read(config)
        with self.assertRaisesRegex(wire.RepairWireError,'repair_status_rollback|repair_authority_revoked'):
            self.prepare_read((config[0],config[1],old))

    def test_missing_current_target_resource_status_refuses_read(self):
        config=self.read_configuration();config[2].pop()
        with self.assertRaisesRegex(wire.RepairWireError,'repair_status_missing'):self.prepare_read(config)

    def test_copy_only_current_owner_authority_cannot_serve_reads(self):
        config=self.read_configuration();payload=json.loads(config[2][0]['raw'])['payload']
        scope=status.status_scope(self.base.intent['root_key'],'authority',dict(authority_kind='ack.root_authority',
            authority_sha256=self.f['entries']['root']['ref']['raw_sha256']),self.destination.state.policy,wire.RepairBudget(self.destination.state.policy))
        for entry in payload['entries']:
            if entry['scope_id']==scope:entry['operation_mask']=4
        config[2][0]=signed_entry(payload,self.f['signers']['owner'],'copy_only_current_owner')
        with self.assertRaisesRegex(wire.RepairWireError,'repair_status_operation'):self.prepare_read(config)

    def test_read_metadata_exhaustion_blocks_instead_of_forgetting_status(self):
        other=CopyReadTests();other.source_capacity=None;other.setUp();self.addCleanup(other.doCleanups)
        config=other.read_configuration();other.prepare_read(config)
        payload=json.loads(config[2][3]['raw'])['payload'];payload['revision']+=1
        config[2][3]=signed_entry(payload,other.destination.state.identity,'new_target_status')
        with self.assertRaisesRegex(wire.RepairWireError,'repair_copy_status_capacity'):other.prepare_read(config)
        self.assertEqual(other.destination.db.execute('SELECT count(*) FROM open_repair_copy_blocks').fetchone()[0],1)
        other.destination.db.close();other.destination.connect();other.store=RepairCopyState(other.destination.state);other.store.initialize()
        with self.assertRaisesRegex(wire.RepairWireError,'repair_copy_status_capacity'):other.prepare_read(config)

    def test_return_grants_can_be_signed_before_copy_without_later_signer_contact(self):
        from contextlib import ExitStack
        from unittest.mock import patch
        original_commit=self.commit
        identity_type=type(self.f['signers']['owner']);sign=identity_type.sign_message
        unavailable={self.f['signers'][name].key_id for name in ('owner','target','maintainer')}
        def offline_signer(identity,*args,**kwargs):
            if identity.key_id in unavailable:raise AssertionError('original signer unavailable after copy starts')
            return sign(identity,*args,**kwargs)
        with ExitStack() as closed:
            def commit_with_signers_offline(*args,**kwargs):
                closed.enter_context(patch.object(identity_type,'sign_message',offline_signer))
                return original_commit(*args,**kwargs)
            self.commit=commit_with_signers_offline
            configuration=self.read_configuration()
            self.assertEqual(self.prepare_read(configuration)['state'],'permission_checked')
