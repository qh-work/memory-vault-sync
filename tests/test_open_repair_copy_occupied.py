"""Saved-receipt replicas through actual durable stores, HTTP and Agent sends."""
import copy
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from memory_vault import canonical_bytes
import memory_vault_open_repair_copy_authority as authority
import memory_vault_open_repair_copy_source as source_view
from memory_vault_open_repair_copy_prepare import AckCopyPreparation
from memory_vault_open_repair_copy_state import RepairCopyState
import memory_vault_open_repair_index as index
import memory_vault_open_repair_status as status
import memory_vault_open_repair_wire as wire
from tests import test_open_repair_empty as empty_fixture
from tests import test_open_repair_state as state_fixture
from tests.open_repair_ack_fixtures import signed_entry


class OccupiedCopyStateTests(unittest.TestCase):
    def setUp(self):
        # Fund all three generations, staged transfer and four return consents before the
        # first source allocation/activation is signed. No runtime cap changes.
        class FundedSource(state_fixture.RepairStateTests):
            capacity_overrides=dict(max_meta_bytes=2097152,max_job_bytes=1048576,max_requests=4096)
            limit_overrides=dict(max_probe_bytes=8192,max_proof_bytes=1048576,max_signature_checks=4096)
            def activate(self):
                f=self.fixture
                for name in ('root','read'):f['docs'][name]['payload']['budget']['max_meta_bytes']=2097152
                allocation=copy.deepcopy(f['docs']['allocate']['payload'])
                allocation['intent']['budget']['max_meta_bytes']=2097152
                allocation['intent_sha256']=hashlib.sha256(canonical_bytes(allocation['intent'])).hexdigest()
                f['entries']['allocate']=signed_entry(allocation,f['signers']['owner'],'synthetic_funded_source')
                f['docs']['allocate']=json.loads(f['entries']['allocate']['raw'])
                return super().activate()
        self.original=empty_fixture.OpenRepairEmptyTests()
        with patch.object(empty_fixture.source_tests,'RepairStateTests',FundedSource):self.original.setUp()
        self.addCleanup(self.original.tearDown)
        if hasattr(self,'before_bind'):self.before_bind()
        self.empty_result=self.original.bind();self.original.bound=self.empty_result
        if hasattr(self,'after_bind'):self.after_bind()
        from tests.test_open_repair_occupied import receipt_inputs
        from memory_vault_open_repair_occupied_state import RepairAckOccupiedState
        self.original.h.now[0]=2_000_000_008
        engine=RepairAckOccupiedState(self.original.h.state);engine.initialize()
        self.receipt,self.original_disclosure,put,options=receipt_inputs(self.original)
        self.result=engine.put(self.original.h.resource_id,self.receipt,self.original_disclosure,put,**options)
        self.recipient_status=copy.deepcopy(json.loads(options['current_statuses'][-1]['raw'])['payload'])
        self.recipient_status['revision']=2
        self.f=self.original.h.fixture
        self.destination=state_fixture.RepairStateTests();self.destination.setUp();self.addCleanup(self.destination.tearDown)
        self.destination.now[0]=self.now=2_000_000_010
        self.policy=self.destination.state.policy
        self.store=RepairCopyState(self.destination.state);self.store.initialize()
        self.temp=tempfile.TemporaryDirectory(prefix='synthetic-occupied-copy-');self.addCleanup(self.temp.cleanup)
        self.journal_path=Path(self.temp.name)/'maintainer.sqlite3';self.open_journal()
        self.addCleanup(lambda:self.local.close())
        self.bound={name:self.original.expected[name] for name in
            ('expected_receipt_writer','expected_message_id','expected_envelope_ref')}
        self.context=dict(expected_ack_slot=self.f['expected']['expected_ack_slot'],
            expected_owner=self.f['expected']['expected_owner'],expected_source=self.f['expected']['expected_target'],
            source_storage_epoch=self.f['expected']['target_storage_epoch'])
        self.keys=self.journal.keys;root=self.f['docs']['root']['payload']
        self.intent=dict(kind='resource.copy_intent',allocation_id='synthetic_bound_allocate',job_id='synthetic_bound_job',
            root_key=root['ack_slot']['root_key'],caller=self.keys,target=self.destination.state.target,
            target_storage_epoch=self.destination.state.node['payload']['storage_epoch'],purpose='ack_replica',
            scope=dict(kind='ack_occupied',ack_slot=root['ack_slot'],grant_ref=self.original.write['ref'],binding_ref=self.empty_result['binding']['ref'],receipt_ref=self.receipt['ref'],original_ack_commit_ref=self.result['commit']['ref']),
            historical_manifest_ref=self.result['manifest']['ref'],budget=dict(root['budget']),
            windows={name:self.now+90 for name in root['windows']})
        self.consent=signed_entry(dict(schema_version='memory-vault-open-repair/v1',kind='ack.copy_reservation_consent',
            signing_key=self.f['signers']['owner'].public_descriptor(),issued_at=self.now,expires_at=self.now+90,
            consent_id='synthetic_bound_consent',revision=1,root_authority_ref=self.f['entries']['root']['ref'],
            source_custody_ref=self.result['commit']['ref'],historical_manifest_ref=self.result['manifest']['ref'],
            maintainer=dict(signing_key_id=self.keys['signing_key']['key_id'],encryption_key_id=self.keys['encryption_key']['key_id']),
            target=self.intent['target'],target_storage_epoch=self.intent['target_storage_epoch'],
            reservation_disclosure=dict(intent_sha256=hashlib.sha256(canonical_bytes(self.intent)).hexdigest(),until=self.now+90)),
            self.f['signers']['owner'],'synthetic_bound_consent')
        self.owner_status=copy.deepcopy(json.loads(self.original.expected['current_statuses'][0]['raw'])['payload'])
        self.owner_status.update(revision=3,issued_at=self.now)
        self.add_authority(self.owner_status,self.consent,4)
        payload=copy.deepcopy(json.loads(self.consent['raw'])['payload'])
        payload.update(kind='ack.copy_recipient_reservation_consent',signing_key=self.f['signers']['writer'].public_descriptor(),
            consent_id='synthetic_recipient_reservation')
        self.recipient_reservation=signed_entry(payload,self.f['signers']['writer'],'synthetic_recipient_reservation')
        self.add_authority(self.recipient_status,self.recipient_reservation,4)
        self.request=self.prepare()
        if getattr(self,'reserve_remotely',False):return
        self.complete_reservation(self.store.allocate(self.request,expected_caller=self.keys))

    def complete_reservation(self,offer):
        self.offer=offer
        self.assignment=self.prepare(offer=self.offer)
        resolver=self.resolver()
        checked=source_view.authenticate_source(self.result['manifest'],resolver,self.result['commit'],source_state='occupied',bound=self.bound,
            expected_ack_slot=self.context['expected_ack_slot'],expected_owner=self.context['expected_owner'],
            expected_target=self.context['expected_source'],target_storage_epoch=self.context['source_storage_epoch'],
            limit_policy=self.f['expected']['limit_policy'],policy=self.policy,budget=resolver.budget)
        reservation=index._signed(self.consent,self.context['expected_owner']['signing_key'],'ack.copy_reservation_consent',
            authority.CONSENT_FIELDS,self.policy,resolver.budget)
        recipient_reservation=index._signed(self.recipient_reservation,self.bound['expected_receipt_writer']['signing_key'],
            'ack.copy_recipient_reservation_consent',authority.CONSENT_FIELDS,self.policy,resolver.budget)
        rows=authority.source_inventory(checked,reservation,self.policy,resolver.budget,recipient_reservation)
        self.disclosures={}
        for variant,name in (('owner','owner'),('source','target'),('recipient','writer')):
            signer=self.f['signers'][name]
            originals,scopes=authority.disclosure_permissions(rows,signer.key_id,self.intent['root_key'],self.policy,resolver.budget)
            self.disclosures[variant]=signed_entry(dict(schema_version='memory-vault-open-repair/v1',kind='ack.copy_disclosure',
                signing_key=signer.public_descriptor(),issued_at=self.now,expires_at=self.now+90,consent_id='synthetic_bound_'+variant,
                revision=1,variant=variant,root_key=self.intent['root_key'],assignment_ref=self.assignment['ref'],
                source_custody_ref=self.result['commit']['ref'],historical_manifest_ref=self.result['manifest']['ref'],
                target=self.intent['target'],target_storage_epoch=self.intent['target_storage_epoch'],
                disclosure=dict(originals=originals,status_scopes=scopes,until=self.now+90)),signer,'synthetic_bound_'+variant)
        self.owner_status['revision']=4;self.add_authority(self.owner_status,self.disclosures['owner'],4)
        self.recipient_status['revision']=3;self.add_authority(self.recipient_status,self.disclosures['recipient'],4)
        self.source_status=copy.deepcopy(self.f['docs']['target_status']['payload']);self.source_status['revision']=2
        self.add_authority(self.source_status,self.disclosures['source'],4)
        scope=status.status_scope(self.intent['root_key'],'assignment',dict(assignment_kind='maintenance.assignment',
            assignment_sha256=self.assignment['ref']['raw_sha256']),self.policy,wire.RepairBudget(self.policy))
        self.maintainer_status=dict(schema_version=status.SCHEMA,kind='authority.status',signing_key=self.keys['signing_key'],
            scope_key=dict(root_key=self.intent['root_key'],issuer_key_id=self.keys['signing_key']['key_id']),revision=1,
            issued_at=self.now,valid_until=self.now+90,entries=[dict(scope_kind='assignment',scope_id=scope,
                minimum_document_revision=0,status='active',operation_mask=70)])

    def open_journal(self):
        self.local=sqlite3.connect(self.journal_path)
        self.journal=AckCopyPreparation(self.local,self.f['signers']['maintainer'],self.f['encryption']['maintainer'],policy=self.policy)
        self.journal.initialize()

    def add_authority(self,payload,entry,mask):
        kind=json.loads(entry['raw'])['payload']['kind']
        scope=status.status_scope(self.intent['root_key'],'authority',dict(authority_kind=kind,authority_sha256=entry['ref']['raw_sha256']),
            self.policy,wire.RepairBudget(self.policy))
        payload['entries'].append(dict(scope_kind='authority',scope_id=scope,minimum_document_revision=0,status='active',operation_mask=mask))
        payload['entries'].sort(key=lambda e:(e['scope_kind'],e['scope_id']))

    def resolver(self):
        resolver=wire.LocalRawResolver(self.policy,wire.RepairBudget(self.policy))
        for namespace,key,raw in self.original.h.db.execute("""SELECT o.namespace,o.opaque_key,o.raw FROM open_repair_ack_objects o
            JOIN open_repair_ack_pins p ON o.namespace=p.namespace AND o.opaque_key=p.opaque_key
            WHERE p.resource_id=? AND p.role IN ('pack','empty:pack','occupied:pack')""",(self.original.h.resource_id,)):
            resolver.put(namespace,key,bytes(raw))
        return resolver

    def prepare(self,offer=None):
        resolver=self.resolver()
        args=dict(**self.context,**self.bound,current_statuses=[signed_entry(self.owner_status,self.f['signers']['owner'],'copy_owner'),
            self.f['entries']['target_status'],signed_entry(self.recipient_status,self.f['signers']['writer'],'recipient_current')],recipient_reservation_entry=self.recipient_reservation,at=self.now,limit_policy=self.f['expected']['limit_policy'],budget=resolver.budget)
        method=self.journal.prepare_occupied if offer is None else self.journal.assign_occupied
        if offer is not None:args['offer_entry']=offer
        return method(self.result['manifest'],resolver,self.result['commit'],self.consent,self.intent,**args)

    def statuses(self):
        return [signed_entry(payload,self.f['signers'][name],'copy_current_'+name) for payload,name in
            ((self.owner_status,'owner'),(self.source_status,'target'),(self.maintainer_status,'maintainer'),(self.recipient_status,'writer'))]

    def commit(self):
        return self.store.commit_occupied(self.result['manifest'],self.resolver(),self.result['commit'],self.request,self.offer,self.assignment,
            self.consent,self.disclosures['owner'],self.disclosures['source'],**self.context,**self.bound,
            expected_maintainer=self.keys,current_statuses=self.statuses(),limit_policy=self.f['expected']['limit_policy'],
            recipient_reservation_entry=self.recipient_reservation,recipient_disclosure_entry=self.disclosures['recipient'])

    def restart(self):
        self.destination.db.close();self.destination.connect();self.store=RepairCopyState(self.destination.state);self.store.initialize()

    def read_configuration(self,custody):
        resolver=self.resolver()
        plan=authority.verify_occupied_copy(self.result['manifest'],resolver,self.result['commit'],self.request,self.offer,self.assignment,
            self.consent,self.disclosures['owner'],self.disclosures['source'],**self.context,**self.bound,
            expected_maintainer=self.keys,expected_target=self.destination.state.target,target_storage_epoch=self.intent['target_storage_epoch'],
            recipient_reservation_entry=self.recipient_reservation,recipient_disclosure_entry=self.disclosures['recipient'],
            current_statuses=self.statuses(),at=self.now,limit_policy=self.f['expected']['limit_policy'],policy=self.policy,budget=resolver.budget)
        self.assertIsNone(plan.denial_code)
        consents={};current=[];root=self.intent['root_key']
        for variant,name,previous in (('owner','owner',self.owner_status),('source','target',self.source_status),
                ('maintainer','maintainer',self.maintainer_status),('recipient','writer',self.recipient_status)):
            signer=self.f['signers'][name];budget=wire.RepairBudget(self.policy)
            originals,scopes=authority.copy_return_permissions(plan,signer.key_id,self.policy,budget)
            consent=signed_entry(dict(schema_version=authority.resource.SCHEMA,kind='ack.replica_return_consent',
                signing_key=signer.public_descriptor(),issued_at=self.now,expires_at=self.now+90,consent_id='synthetic_empty_return_'+variant,
                revision=1,variant=variant,root_key=root,source_custody_ref=self.result['commit']['ref'],
                historical_manifest_ref=self.result['manifest']['ref'],assignment_ref=self.assignment['ref'],subject=root['owner'],
                target=self.destination.state.target,target_storage_epoch=self.intent['target_storage_epoch'],
                bootstrap_grant_ref=plan.source.bootstrap.originals['bootstrap'].ref.as_dict(),
                return_permission=dict(originals=originals,status_scopes=scopes,until=self.now+90)),signer,'synthetic_empty_return_'+variant)
            consents[variant]=consent
            payload=copy.deepcopy(previous);payload['revision']+=1;self.add_authority(payload,consent,2)
            current.append(signed_entry(payload,signer,'synthetic_empty_return_status_'+variant))
        event=json.loads(custody['raw'])['payload'];target=self.destination.state.identity
        scope=status.status_scope(root,'resource',event['resource'],self.policy,wire.RepairBudget(self.policy))
        current.append(signed_entry(dict(schema_version=status.SCHEMA,kind='authority.status',signing_key=target.public_descriptor(),
            scope_key=dict(root_key=root,issuer_key_id=target.key_id),revision=1,issued_at=self.now,valid_until=self.now+90,
            entries=[dict(scope_kind='resource',scope_id=scope,minimum_document_revision=0,status='active',operation_mask=2)]),
            target,'synthetic_empty_return_target'))
        return event['resource']['resource_id'],consents,current

    def test_existing_receipt_and_three_original_generations_survive_restart(self):
        custody=self.commit();self.restart();self.assertEqual(self.commit(),custody)
        rid=json.loads(custody['raw'])['payload']['resource']['resource_id']
        restored=self.store.restore_occupied(rid,**self.context,**self.bound,expected_maintainer=self.keys,limit_policy=self.f['expected']['limit_policy'])
        self.assertEqual(restored['source'].event.inputs['receipt'].raw,self.receipt['raw'])
        self.assertEqual(restored['source'].event.inputs['receipt'].ref.as_dict(),self.receipt['ref'])
        self.assertEqual(restored['source'].custody.raw,self.result['commit']['raw'])
        self.assertEqual(len(source_view.source_manifests(restored['source'])),3)
        self.assertEqual(json.loads(self.assignment['raw'])['payload']['operation_mask'],70)
        with self.assertRaises(wire.RepairWireError):
            self.store.restore_empty(rid,**self.context,**self.bound,expected_maintainer=self.keys,limit_policy=self.f['expected']['limit_policy'])

    def test_recipient_must_authorize_reservation_before_any_allocation(self):
        resolver=self.resolver()
        with self.assertRaises(wire.RepairWireError):
            self.journal.prepare_occupied(self.result['manifest'],resolver,self.result['commit'],self.consent,self.intent,
                **self.context,**self.bound,current_statuses=self.statuses(),at=self.now,
                limit_policy=self.f['expected']['limit_policy'],budget=resolver.budget)

    def test_recipient_copy_consent_cannot_be_replaced_by_owner_consent(self):
        self.disclosures['recipient']=self.disclosures['owner']
        with self.assertRaises(wire.RepairWireError):self.commit()
        self.assertEqual(self.destination.db.execute('SELECT count(*) FROM open_repair_copy_commits').fetchone()[0],0)

    def test_independent_recipient_return_is_required_and_revocation_survives_restart(self):
        custody=self.commit();rid,consents,current=self.read_configuration(custody)
        args=dict(**self.context,**self.bound,expected_maintainer=self.keys,limit_policy=self.f['expected']['limit_policy'])
        with self.assertRaises(wire.RepairWireError):
            self.store.prepare_occupied_read(rid,{k:v for k,v in consents.items() if k!='recipient'},current_statuses=current,**args)
        read=self.store.prepare_occupied_read(rid,consents,current_statuses=current,**args)
        self.assertIsNone(read['denial_code'])
        revoked=copy.deepcopy(json.loads(current[3]['raw'])['payload']);revoked['revision']+=1
        root=self.intent['root_key'];scope=index._authority(root,index._signed(consents['recipient'],self.bound['expected_receipt_writer']['signing_key'],
            'ack.replica_return_consent',authority.RETURN_FIELDS,self.policy,wire.RepairBudget(self.policy)),self.policy,wire.RepairBudget(self.policy))
        for entry in revoked['entries']:
            if entry['scope_id']==scope:entry['status']='revoked'
        updated=signed_entry(revoked,self.f['signers']['writer'],'synthetic_recipient_read_revoked')
        changed=[*current[:3],updated,current[4]]
        with self.assertRaises(wire.RepairWireError):self.store.prepare_occupied_read(rid,consents,current_statuses=changed,**args)
        self.restart()
        with self.assertRaises(wire.RepairWireError):self.store.prepare_occupied_read(rid,consents,current_statuses=current,**args)

    def test_old_writer_admission_revocation_does_not_revoke_saved_receipt_read(self):
        custody=self.commit();rid,consents,current=self.read_configuration(custody)
        changed=copy.deepcopy(json.loads(current[0]['raw'])['payload']);changed['revision']+=1
        document=json.loads(self.original.write['raw'])['payload']
        scope=status.status_scope(self.intent['root_key'],'authority',dict(authority_kind=document['kind'],
            authority_sha256=self.original.write['ref']['raw_sha256']),self.policy,wire.RepairBudget(self.policy))
        matches=[entry for entry in changed['entries'] if entry['scope_id']==scope]
        self.assertEqual(len(matches),1);matches[0]['status']='revoked'
        current[0]=signed_entry(changed,self.f['signers']['owner'],'synthetic_old_admission_revoked')
        args=dict(**self.context,**self.bound,expected_maintainer=self.keys,limit_policy=self.f['expected']['limit_policy'])
        self.store.prepare_occupied_read(rid,consents,current_statuses=current,**args)
        self.restart()
        self.assertIsNone(self.store.prepare_occupied_read(rid,consents,current_statuses=current,**args)['denial_code'])

    def test_recipient_copy_revocation_is_retained_when_commit_is_refused(self):
        payload=self.recipient_status
        scope=status.status_scope(self.intent['root_key'],'authority',dict(authority_kind='ack.copy_disclosure',
            authority_sha256=self.disclosures['recipient']['ref']['raw_sha256']),self.policy,wire.RepairBudget(self.policy))
        previous=copy.deepcopy(payload);payload['revision']+=1
        for entry in payload['entries']:
            if entry['scope_id']==scope:entry['status']='revoked'
        with self.assertRaisesRegex(wire.RepairWireError,'repair_authority_revoked'):self.commit()
        self.restart();self.recipient_status=previous
        with self.assertRaises(wire.RepairWireError):self.commit()
        self.assertEqual(self.destination.db.execute('SELECT count(*) FROM open_repair_copy_commits').fetchone()[0],0)

    def test_observation_reuse_requires_exact_raw_bytes_and_full_reference(self):
        custody=self.commit();rid,consents,current=self.read_configuration(custody)
        args=dict(**self.context,**self.bound,expected_maintainer=self.keys,limit_policy=self.f['expected']['limit_policy'])
        self.store.prepare_occupied_read(rid,consents,current_statuses=current,**args)
        entry=current[3];ref=canonical_bytes(entry['ref']);digest=entry['ref']['raw_sha256']
        for damage in ('bytes','reference'):
            with self.subTest(damage=damage):
                raw=entry['raw'];reference=ref
                if damage=='bytes':
                    value=json.loads(raw);value['payload']['revision']+=1;raw=canonical_bytes(value)
                else:reference=canonical_bytes(dict(entry['ref'],size=entry['ref']['size']+1))
                self.assertNotEqual((raw,reference),(entry['raw'],ref))
                self.destination.db.execute('UPDATE open_repair_copy_observations SET raw=?,ref=? WHERE resource_id=? AND raw_digest=?',
                    (raw,reference,rid,digest));self.destination.db.commit()
                with self.assertRaises(wire.RepairWireError):self.store.prepare_occupied_read(rid,consents,current_statuses=current,**args)
                self.destination.db.execute('UPDATE open_repair_copy_observations SET raw=?,ref=? WHERE resource_id=? AND raw_digest=?',
                    (entry['raw'],ref,rid,digest));self.destination.db.commit()

    def test_compact_upload_reuses_exact_history_and_rejects_parallel_substitution(self):
        from memory_vault_open_repair_stage import OCCUPIED_COPY_ROLES
        options=dict(**self.context,**self.bound,expected_target=self.destination.state.target,
            target_storage_epoch=self.intent['target_storage_epoch'],current_statuses=self.statuses(),at=self.now,
            limit_policy=self.f['expected']['limit_policy'],recipient_disclosure_entry=self.disclosures['recipient'])
        def prepare(**extra):
            return self.journal.prepare_upload_occupied(self.result['manifest'],self.resolver(),self.result['commit'],
                self.request,self.offer,self.assignment,self.consent,self.disclosures['owner'],self.disclosures['source'],
                **options,**extra)
        with self.assertRaisesRegex(wire.RepairWireError,'repair_copy_recipient_consent_missing'):prepare()
        prepared=prepare(recipient_reservation_entry=self.recipient_reservation)
        children=[dict(role=row['role'],**row['entry']) for row in prepared['children']]
        self.assertEqual({row['role'] for row in children},OCCUPIED_COPY_ROLES)
        self.assertNotIn('recipient.receipt',{row['role'] for row in children})
        resolver=self.resolver()
        source_view.resolve_occupied_stage_originals(children,resolver,self.policy,resolver.budget)
        self.assertEqual(resolver.resolve(self.receipt['ref']).raw,self.receipt['raw'])
        bad=copy.deepcopy(children)
        claimed=next(row for row in bad if row['role']=='history.ack_empty')
        claimed['ref']['key']='f'*64
        resolver=self.resolver()
        with self.assertRaisesRegex(wire.RepairWireError,'repair_copy_upload_mismatch'):
            source_view.resolve_occupied_stage_originals(bad,resolver,self.policy,resolver.budget)


class OccupiedCopyHTTPTests(unittest.TestCase):
    def setUp(self):
        from memory_vault_open_control import issue_node
        from memory_vault_open_node import OpenHTTPServer
        from memory_vault_open_transport import OpenHTTPTransport
        from tests.test_open_repair_copy_upload import CopyUploadHTTPTests
        self.fixture=self.make_fixture() if hasattr(self,'make_fixture') else OccupiedCopyStateTests()
        self.fixture.reserve_remotely=getattr(self,'reserve_remotely',False)
        self.addCleanup(self.fixture.doCleanups);self.fixture.setUp()
        f=self.fixture
        self.h=SimpleNamespace(destination=f.destination,f=f.f,base=SimpleNamespace(now=f.now))
        self.errors=[]
        self.clock=patch('time.time',return_value=f.now);self.clock.start();self.addCleanup(self.clock.stop)
        with patch('socket.getfqdn',return_value='localhost'):self.server=OpenHTTPServer(('127.0.0.1',0),None)
        self.addCleanup(self.server.server_close)
        state=f.destination.state;self.base='http://127.0.0.1:'+str(self.server.server_port)
        self.case=SimpleNamespace(state=state)
        self.descriptor=issue_node(state.identity,base_url=self.base,storage_epoch=state.node['payload']['storage_epoch'],
            roles=['directory','router'],revision=2,issued_at=f.now-1,expires_at=f.now+3599)
        self.directory=Path(f.destination.temp.name)
        for name in ('network.sqlite3','network.sqlite3-wal','network.sqlite3-shm'):
            path=self.directory/name
            if path.exists():path.chmod(0o600)
        self.start=CopyUploadHTTPTests.start.__get__(self)
        self.stop=CopyUploadHTTPTests.stop.__get__(self)
        self.restart=CopyUploadHTTPTests.restart.__get__(self)
        if getattr(self,'reserve_remotely',False):
            from tests.test_open_repair_copy_resources import RemoteCopyClientHTTPTests
            self.start=RemoteCopyClientHTTPTests.start.__get__(self)
        self.start();self.addCleanup(self.stop)
        self.transport=OpenHTTPTransport(allow_loopback=True);self.addCleanup(self.transport.close)
        raw=canonical_bytes(self.descriptor);digest=hashlib.sha256(raw).hexdigest()
        self.node=dict(raw=raw,ref=dict(namespace='meta',key=digest,raw_sha256=digest,size=len(raw)))

    def upload(self,transport=None):
        from memory_vault_open_repair_copy_client import AckCopyUploadClient
        f=self.fixture
        client=AckCopyUploadClient(f.journal,encryption_identity=f.f['encryption']['maintainer'],
            transport=transport or self.transport,allow_loopback=True)
        self.addCleanup(client.close)
        return client.upload_occupied(self.base,f.result['manifest'],f.resolver(),f.result['commit'],f.request,f.offer,f.assignment,
            f.consent,f.disclosures['owner'],f.disclosures['source'],target_node_entry=self.node,**f.context,**f.bound,
            expected_target=f.destination.state.target,target_storage_epoch=f.intent['target_storage_epoch'],
            current_statuses=f.statuses(),limit_policy=f.f['expected']['limit_policy'],recipient_reservation_entry=f.recipient_reservation,recipient_disclosure_entry=f.disclosures['recipient'])

    def test_lost_successful_copy_commit_resumes_same_replica_after_both_restarts(self):
        from memory_vault import MemoryError
        f=self.fixture;host=self
        class LostCommitReply:
            lost=False
            def request(self,*args,**kwargs):return host.transport.request(*args,**kwargs)
            def request_blob(self,*args,**kwargs):return host.transport.request_blob(*args,**kwargs)
            def request_repair(self,base,raw,**kwargs):
                reply=host.transport.request_repair(base,raw,**kwargs)
                if not self.lost and json.loads(raw)['payload']['kind']=='ack.copy_occupied_commit':
                    self.lost=True;raise MemoryError('synthetic_lost_copy_commit')
                return reply
        transport=LostCommitReply()
        with self.assertRaisesRegex(MemoryError,'synthetic_lost_copy_commit'):self.upload(transport)
        with self.participant.state.db() as db:
            original=bytes(db.execute('SELECT custody FROM open_repair_copy_commits').fetchone()[0])
        self.restart();f.local.close();f.open_journal()
        result=self.upload()
        self.assertEqual(result['custody']['raw'],original)
        self.assertEqual(result['state'],'replica_committed')
        self.assertEqual(self.errors,[])
        with self.participant.state.db() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM open_repair_copy_commits').fetchone()[0],1)
            self.assertEqual(db.execute('SELECT count(*) FROM open_repair_ack_resources').fetchone()[0],0)

    def test_owner_recovers_bound_replica_after_copy_without_original_node(self):
        from memory_vault_open_repair_client import AckOwnerRecoveryClient
        from memory_vault_open_repair_copy_service import ReplicaOccupiedReadService
        import memory_vault_open_repair_proof as proof
        f=self.fixture;copied=self.upload()
        rid,consents,statuses=f.read_configuration(copied['custody'])
        with self.participant.state.db() as db:
            service=ReplicaOccupiedReadService(self.participant._repair_service(db).state);service.initialize()
            service.configure(rid,context=dict(**f.context,**f.bound,expected_maintainer=f.keys),consents=consents,current_statuses=statuses)
        self.restart();f.original.h.db.close()
        host=self;requested_children=[];responses=[]
        class ObservedTransport:
            def request_repair(self,base,raw,**options):
                if options.get('child'):requested_children.append(json.loads(raw)['payload']['child_index'])
                reply=host.transport.request_repair(base,raw,**options)
                if not options.get('child'):responses.append(reply)
                return reply
        client=AckOwnerRecoveryClient(f.f['signers']['owner'],f.f['encryption']['owner'],
            limit_policy=f.f['expected']['limit_policy'],allow_loopback=True,transport=ObservedTransport())
        self.addCleanup(client.close)
        arguments=dict(target_node_entry=self.node,expected_target=f.destination.state.target,
            **{name:value for name,value in f.context.items() if name!='expected_owner'},**f.bound,expected_maintainer=f.keys,
            root_entry=f.f['entries']['root'],read_entry=f.f['entries']['read'],bootstrap_entry=f.f['entries']['bootstrap'])
        result=client.recover_replica_occupied(self.base,**arguments)
        self.assertEqual(result.replica['source'].event.inputs['receipt'].raw,f.receipt['raw'])
        self.assertEqual(result.replica['source'].event.commit.raw,f.result['commit']['raw'])
        self.assertEqual(result.replica['custody'].raw,copied['custody']['raw'])
        rows=result.proof.manifest.value['children']
        packed=[row for row in rows if row['role'] in proof.replica_read_pack_roles('replica_occupied')]
        self.assertGreater(len(packed),10)
        for row in packed:self.assertNotIn(row['index'],requested_children)
        self.assertEqual(result.metrics['proof_bytes'],len(responses[1])+len(result.proof.handle.raw)
            +len(result.proof.manifest.raw)+sum(len(raw) for raw in result.originals.values()))
        with self.participant.state.db() as db:
            self.assertLess(db.execute('SELECT requests FROM open_repair_copy_work').fetchone()[0],64)
            self.assertTrue(all(1<=row[0]<=row[1]<=64 for row in db.execute(
                'SELECT signature_checks,signature_allowance FROM open_repair_bootstrap_work')))
        self.assertEqual(self.errors,[])
        build_pack=wire.build_raw_pack
        def with_extra_original(raws,policy,budget):
            return build_pack([*raws,b'{"synthetic":"unadvertised"}'],policy,budget)
        with patch('memory_vault_open_repair_copy_service.wire.build_raw_pack',side_effect=with_extra_original):
            with self.assertRaisesRegex(wire.RepairWireError,'repair_proof_mismatch'):
                client.recover_replica_occupied(self.base,**arguments)



from tests.test_open_repair_admin import _CopyAdminFixture
from tests.test_open_repair_admin import _AdminFixture


class OccupiedReplicaAgentTests(unittest.TestCase):
    setUp=OccupiedCopyHTTPTests.setUp
    upload=OccupiedCopyHTTPTests.upload

    def make_fixture(self):
        fixture=OccupiedCopyStateTests()
        fixture.before_bind=lambda:self.prepare_delivery(fixture)
        fixture.after_bind=lambda:self.save_delivery(fixture)
        return fixture

    def prepare_delivery(self,fixture):
        import base64,threading
        from cryptography.hazmat.primitives import serialization
        from memory_vault_network_crypto import EncryptionIdentity
        from memory_vault_open_control import issue_node
        from memory_vault_open_delivery import envelope_ref
        from memory_vault_open_node import OpenHTTPServer,OpenParticipant
        from memory_vault_trust import Identity,TrustStore,_write_new_private
        from memory_vault_client import ClientConfig
        from tests.test_open_agent import configured_agent
        from tests.test_open_delivery_http import DeliveryHTTPTests
        f=fixture.original.h.fixture
        self.delivery_now=[2_000_000_007]
        clock=patch('time.time',side_effect=lambda:self.delivery_now[0]);clock.start();self.addCleanup(clock.stop)
        from memory_vault_open_routing import RoutingTable
        original_table=RoutingTable.__init__
        def dated_table(table,key_id,directory=False,now=None):
            original_table(table,key_id,directory,now=now or (lambda:self.delivery_now[0]))
        tables=patch.object(RoutingTable,'__init__',new=dated_table);tables.start();self.addCleanup(tables.stop)
        temp=tempfile.TemporaryDirectory(prefix='synthetic-replica-agent-');self.addCleanup(temp.cleanup)
        root=Path(temp.name);identity=Identity.generate(root/'node-identity.json');encryption=EncryptionIdentity.generate()
        with patch('socket.getfqdn',return_value='localhost'):server=OpenHTTPServer(('127.0.0.1',0),None)
        self.addCleanup(server.server_close)
        descriptor=issue_node(identity,base_url='http://127.0.0.1:'+str(server.server_port),
            storage_epoch='synthetic_delivery_epoch',roles=['directory','router'],revision=1,
            issued_at=self.delivery_now[0]-1,expires_at=self.delivery_now[0]+3599)
        participant=OpenParticipant(identity,root/'node',seeds=[],descriptor=descriptor,
            encryption_identity=encryption,allow_loopback=True,index_policy=dict(enabled=True),
            contact_policy=dict(enabled=True),delivery_policy=dict(enabled=True))
        server.participant=participant
        thread=threading.Thread(target=server.serve_forever,kwargs=dict(poll_interval=.02),daemon=True);thread.start()
        self.delivery_stopped=False
        def stop():
            if not self.delivery_stopped:
                server.shutdown();server.server_close();thread.join(3);participant.close();self.delivery_stopped=True
        self.stop_delivery=stop;self.addCleanup(stop)
        agents={}
        for role in ('owner','writer'):
            signer=f['signers'][role]
            def save_identity(path,signer=signer):
                private=signer._private_key.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())
                _write_new_private(path,canonical_bytes(dict(signer.public_descriptor(),
                    schema_version='universal-memory-identity/v1',private_key=base64.b64encode(private).decode())))
                return signer
            with patch.object(Identity,'generate',side_effect=save_identity),patch.object(EncryptionIdentity,'generate',return_value=f['encryption'][role]):
                agents[role]=configured_agent(SimpleNamespace(root=root/role,nodes=[descriptor]))[0]
        self.sender,self.recipient=agents['owner'],agents['writer']
        delivery=DeliveryHTTPTests();delivery.a=self.sender;delivery.b=self.recipient
        delivery.ai=f['signers']['owner'];delivery.bi=f['signers']['writer'];delivery.host=SimpleNamespace(nodes=[descriptor])
        self.delivery=delivery
        TrustStore(ClientConfig.load(self.recipient.client_config).trust_path).add(f['signers']['owner'].public_descriptor())
        remembered=delivery.call(self.sender,op='remember',request_id='req_replica_memory',kind='observation',
            text='Synthetic selected memory remains readable after both original nodes stop.')
        self.memory_id=remembered['memory_id']
        _,reference=delivery.request_contact();self.assertTrue(delivery.decide(reference,'approved')['recipient_approved'])
        self.send_request=dict(op='send',request_id='req_replica_delivery',recipients=[delivery.bi.key_id],
            text='Synthetic receipt replica delivery',memory_ids=[self.memory_id])
        sent=delivery.call(self.sender,**self.send_request)
        self.assertTrue(sent['storage_accepted']);self.assertFalse(sent['endpoint_validated'])
        with self.sender._network() as network:
            envelope=bytes(network._delivery()._outbox(self.send_request['request_id'])['envelope'])
        fixture.original.write,fixture.original.offer,fixture.original.expected=empty_fixture.bound_inputs(
            f,message_id=sent['message_id'],envelope_ref=envelope_ref(envelope))

    def save_delivery(self,fixture):
        from memory_vault_open_delivery_client import OpenDeliveryClient
        self.delivery_now[0]=2_000_000_008
        async def retain_without_original_return(client,message_id,budget,node=None):
            client._saved_receipt(message_id)
            return False
        with patch.object(OpenDeliveryClient,'_send_receipt',new=retain_without_original_return):
            saved=self.delivery.call(self.recipient,op='receive',limit=4)
        self.assertEqual(saved['errors'],[]);self.assertEqual(saved['messages'][0]['state'],'validated_saved')
        self.assertGreater(saved['messages'][0]['share']['records_added'],0)
        with self.recipient._network() as network:
            self.actual_receipt=bytes(network._delivery()._inbox(fixture.original.expected['expected_message_id'])['receipt'])

    def test_agent_updates_original_send_after_delivery_and_ack_sources_stop(self):
        from memory_vault_agent import Agent
        from memory_vault_client import ClientConfig
        from memory_vault_open_client import ACK_CONNECT_SCHEMA
        from memory_vault_open_repair_copy_service import ReplicaOccupiedReadService
        f=self.fixture
        self.assertEqual(f.receipt['raw'],self.actual_receipt)
        copied=self.upload();rid,consents,statuses=f.read_configuration(copied['custody'])
        with self.participant.state.db() as db:
            service=ReplicaOccupiedReadService(self.participant._repair_service(db).state);service.initialize()
            service.configure(rid,context=dict(**f.context,**f.bound,expected_maintainer=f.keys),consents=consents,current_statuses=statuses)
        self.restart();f.original.h.db.close();self.stop_delivery()
        encode=lambda entry:dict(raw=entry['raw'].decode(),ref=entry['ref'])
        request=dict(target_node_entry=encode(self.node),expected_target=f.destination.state.target,
            **{name:value for name,value in f.context.items() if name!='expected_owner'},**f.bound,expected_maintainer=f.keys,
            **{name+'_entry':encode(f.f['entries'][name]) for name in ('root','read','bootstrap')})
        invitation=dict(schema_version=ACK_CONNECT_SCHEMA,action='recover_replica_receipt',base_url=self.base,
            repair_profile='receipt-index',request=request)
        config=ClientConfig.load(self.sender.client_config)
        unchanged={path:path.read_bytes() for path in (config.identity_path,config.trust_path,config.vault_path,self.sender.network_config)}
        from tests.test_open_delivery_http import repair_failure_diagnostics
        with repair_failure_diagnostics():result=self.delivery.call(self.sender,op='connect',invitation=invitation)
        self.assertEqual(result['state'],'validated_saved');self.assertTrue(result['endpoint_validated'])
        self.assertFalse(result['acknowledgement_pending']);self.assertEqual(result['commit_ref'],f.result['commit']['ref'])
        self.assertEqual(result['replica_custody_ref'],copied['custody']['ref'])
        self.sender=Agent(self.sender.client_config,self.sender.network_config)
        confirmed=self.delivery.call(self.sender,**self.send_request)
        self.assertTrue(confirmed['endpoint_validated']);self.assertEqual(confirmed['message_id'],f.bound['expected_message_id'])
        with self.sender._network() as network:
            row=network._delivery()._outbox(self.send_request['request_id'])
            self.assertEqual(bytes(row['acknowledgement']),self.actual_receipt)
        remembered=self.delivery.call(self.recipient,op='recall',memory_id=self.memory_id)
        self.assertEqual(remembered['hits'][0]['text'],'Synthetic selected memory remains readable after both original nodes stop.')
        self.assertEqual({path:path.read_bytes() for path in unchanged},unchanged)
        self.assertEqual(self.errors,[])


class OccupiedCopyProvisionTests(unittest.TestCase):
    def test_agent_prepares_explicit_copy_maintainer_without_extending_old_grants(self):
        import base64
        from memory_vault_agent import Agent
        from memory_vault_network_crypto import EncryptionIdentity,unb64url
        from memory_vault_open_client import ACK_CONNECT_SCHEMA
        from memory_vault_open_repair_remote_provision import RemoteAckSourceProvisioner
        from memory_vault_trust import Identity
        from tests.test_open_repair_remote_provision import RemoteProvisionTests
        host=RemoteProvisionTests();self.addCleanup(host.doCleanups);host.setUp()
        signer=Identity.generate(host.root/'copy-maintainer.json');encryption=EncryptionIdentity.generate()
        maintainer=dict(signing_key=signer.public_descriptor(),encryption_key=encryption.public_descriptor())
        invitation=dict(schema_version=ACK_CONNECT_SCHEMA,action='prepare',source_url=host.options['source_url'],
            source_key_id=host.options['source_key_id'],repair_profile='receipt-index',lifetime=3600,
            request_id=host.options['request_id'],recipient=host.options['recipient'],text=host.options['text'],
            memory_ids=[],copy_maintainer=maintainer)
        result=host.delivery.call(host.delivery.a,op='connect',invitation=invitation)
        self.assertEqual(result['state'],'ack_source_prepared');self.assertEqual(host.delivery.stored_count(),0)
        request=dict(schema_version=ACK_CONNECT_SCHEMA,action='export_preparation',request_id=host.options['request_id'],part='owner_request')
        data=b''
        while True:
            page=host.delivery.call(host.delivery.a,op='connect',invitation=request)
            self.assertEqual(page['offset'],len(data));data+=base64.b64decode(page['bundle_chunk'],validate=True)
            if page['next_cursor'] is None:break
            request['cursor']=page['next_cursor']
        root=json.loads(unb64url(json.loads(data)['root']['raw_base64url'],maximum=65536))['payload']
        self.assertEqual(root['operation_mask'],95)
        self.assertIn(dict(signing_key_id=signer.key_id,encryption_key_id=encryption.key_id),root['maintainers'])
        self.assertEqual(len(root['maintainers']),2);self.assertGreaterEqual(root['budget']['max_meta_bytes'],2097152)
        host.delivery.a=Agent(host.delivery.a.client_config,host.delivery.a.network_config)
        with patch.object(RemoteAckSourceProvisioner,'queue_and_prepare',side_effect=AssertionError('unexpected renewed preparation')):
            restored=host.delivery.call(host.delivery.a,op='connect',invitation=invitation)
        self.assertEqual(restored['message_id'],result['message_id']);self.assertFalse(restored['network_accessed'])
        removed={key:value for key,value in invitation.items() if key!='copy_maintainer'}
        denied=host.delivery.a.handle(dict(op='connect',invitation=removed))
        self.assertFalse(denied['ok']);self.assertEqual(denied['error']['code'],'open_ack_preparation_conflict')
        with host.delivery.a._network() as network:
            owner=dict(signing_key=network.identity.public_descriptor(),encryption_key=network.encryption.public_descriptor())
        for extra,code in ((dict(repair_profile='receipt'),'repair_copy_profile_required'),
                (dict(copy_maintainer=owner),'repair_copy_maintainer_distinct_parties_required')):
            with self.subTest(code=code):
                invalid=dict(invitation,request_id='req_invalid_copy_preparation',**extra)
                refused=host.delivery.a.handle(dict(op='connect',invitation=invalid))
                self.assertFalse(refused['ok']);self.assertEqual(refused['error']['code'],code)
        with host.delivery.a._network() as network:
            with network.participant.state.db() as db:
                self.assertEqual(db.execute('SELECT count(*) FROM open_ack_agent_preparations').fetchone()[0],1)
                plan=json.loads(bytes(db.execute('SELECT plan FROM open_repair_source_provision').fetchone()[0]))
                self.assertEqual(plan['plan_version'],3)


class OccupiedCopyReservationTests(unittest.TestCase):
    def test_remote_reservation_lost_reply_replays_before_bound_upload(self):
        from memory_vault import MemoryError
        from memory_vault_open_repair_copy_client import AckCopyUploadClient
        host=OccupiedCopyHTTPTests();host.reserve_remotely=True;self.addCleanup(host.doCleanups);host.setUp()
        f=host.fixture;requests=[]
        class LostReply:
            def request(self,*args,**options):return host.transport.request(*args,**options)
            def request_repair(self,base,raw,**options):
                requests.append(raw);response=host.transport.request_repair(base,raw,**options)
                if len(requests)==1:raise MemoryError('synthetic_lost_allocation_reply')
                return response
        transport=LostReply()
        def reserve():
            client=AckCopyUploadClient(f.journal,encryption_identity=f.f['encryption']['maintainer'],
                transport=transport,allow_loopback=True)
            self.addCleanup(client.close)
            return client.reserve_occupied(host.base,f.result['manifest'],f.resolver(),f.result['commit'],f.consent,f.intent,
                target_node_entry=host.node,**f.context,**f.bound,current_statuses=[
                    signed_entry(f.owner_status,f.f['signers']['owner'],'synthetic_occupied_reserve'),f.f['entries']['target_status'],signed_entry(f.recipient_status,f.f['signers']['writer'],'synthetic_reserve_recipient')],
                limit_policy=f.f['expected']['limit_policy'],recipient_reservation_entry=f.recipient_reservation)
        self.assertEqual(f.destination.db.execute('SELECT count(*) FROM open_repair_copy_resources').fetchone()[0],0)
        with self.assertRaisesRegex(MemoryError,'synthetic_lost_allocation_reply'):reserve()
        host.restart();f.local.close();f.open_journal()
        result=reserve();self.assertEqual(result['allocation'],f.request)
        self.assertEqual(requests[0],requests[1])
        self.assertEqual(f.destination.db.execute('SELECT count(*) FROM open_repair_copy_resources').fetchone()[0],1)
        f.complete_reservation(result['offer']);copied=host.upload()
        self.assertEqual(copied['state'],'replica_committed')
        self.assertEqual(json.loads(copied['custody']['raw'])['payload']['scope'],f.intent['scope'])


class OccupiedCopyAdminTests(_CopyAdminFixture,unittest.TestCase):
    copy_operation='upload'

    def setUp(self):
        from memory_vault_open_repair_admin import OCCUPIED_COPY_REQUEST_SCHEMA
        from memory_vault_open_client import OpenNetworkClient
        self.remote=OccupiedCopyHTTPTests();self.remote.reserve_remotely=self.copy_operation=='reserve'
        self.remote.setUp();self.addCleanup(self.remote.doCleanups)
        f=self.remote.fixture
        packs=[]
        for namespace,key,raw in f.original.h.db.execute("""SELECT DISTINCT o.namespace,o.opaque_key,o.raw FROM open_repair_ack_objects o
            JOIN open_repair_ack_pins p ON o.namespace=p.namespace AND o.opaque_key=p.opaque_key
            WHERE p.resource_id=? AND p.role IN ('pack','empty:pack','occupied:pack')""",(f.original.h.resource_id,)):
            raw=bytes(raw);packs.append(dict(raw=raw,ref=dict(namespace=namespace,key=key,
                raw_sha256=hashlib.sha256(raw).hexdigest(),size=len(raw))))
        h=SimpleNamespace(destination=f.destination,f=dict(f.f,manifest=f.result['manifest'],custody=f.result['commit'],packs=packs),
            consent=f.consent,intent=f.intent)
        self.configure_copy(h,self.remote.descriptor,self.copy_operation)
        self.request.update(schema_version=OCCUPIED_COPY_REQUEST_SCHEMA,
            receipt_writer=f.bound['expected_receipt_writer'],message_id=f.bound['expected_message_id'],envelope_ref=f.bound['expected_envelope_ref'])
        self.request['recipient_reservation']=self.encode(f.recipient_reservation)
        if self.copy_operation=='reserve':
            self.request['current_statuses']=[self.encode(signed_entry(f.owner_status,f.f['signers']['owner'],'synthetic_cli_occupied_reserve')),
                self.encode(f.f['entries']['target_status']),self.encode(signed_entry(f.recipient_status,f.f['signers']['writer'],'synthetic_cli_recipient'))]
            return
        for name,entry in dict(allocation=f.request,offer=f.offer,assignment=f.assignment,
                owner_disclosure=f.disclosures['owner'],source_disclosure=f.disclosures['source'],recipient_disclosure=f.disclosures['recipient']).items():
            self.request[name]=self.encode(entry)
        self.request['current_statuses']=[self.encode(e) for e in f.statuses()]
        with OpenNetworkClient(self.network) as network,network.participant.state.db() as db:
            for table,sql in f.local.execute("SELECT name,sql FROM sqlite_master WHERE type='table' AND name LIKE 'ack_copy_prepare_%'").fetchall():
                db.execute(sql)
                for row in f.local.execute('SELECT * FROM '+table).fetchall():
                    db.execute('INSERT INTO '+table+' VALUES('+','.join('?' for _ in row)+')',row)
            db.commit()

    def test_command_keeps_bound_history_and_preserves_original_identity(self):
        import stat
        code,output,error=self.call('copy-upload-occupied');self.assertEqual((code,error),(0,''))
        evidence=json.loads(self.output.read_bytes())
        self.assertEqual(evidence['state'],'replica_committed');self.assertEqual(evidence['source_state'],'occupied')
        self.assertFalse(evidence['recipient_saved']);self.assertFalse(evidence['receipt_admission_authorized'])
        self.assertFalse(self.vault.exists())
        self.remote.restart();self.request_path=self.directory/'retry.json';self.output=self.directory/'retry-result.json'
        code,output,error=self.call('copy-upload-occupied');self.assertEqual((code,error),(0,''))
        self.assertEqual(json.loads(self.output.read_bytes()),evidence)
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode),0o600)
        self.assertEqual({path:path.read_bytes() for path in self.originals},self.originals)


class OccupiedCopyReserveAdminTests(_CopyAdminFixture,unittest.TestCase):
    copy_operation='reserve'
    setUp=OccupiedCopyAdminTests.setUp

    def test_remote_command_reserves_the_exact_bound_slot(self):
        from memory_vault_network_crypto import unb64url
        code,output,error=self.call('copy-reserve-occupied');self.assertEqual((code,error),(0,''))
        evidence=json.loads(self.output.read_bytes())
        self.assertEqual(evidence['state'],'capacity_reserved_and_assigned');self.assertEqual(evidence['source_state'],'occupied')
        assignment=json.loads(unb64url(evidence['assignment']['raw_base64url'],maximum=524288))['payload']
        self.assertEqual(assignment['scope'],self.remote.fixture.intent['scope'])
        self.assertEqual(assignment['operation_mask'],70);self.assertEqual(len(assignment['bootstrap_grant_refs']),2)
        self.assertFalse(json.loads(output)['recipient_saved']);self.assertFalse(self.vault.exists())
        self.assertEqual({path:path.read_bytes() for path in self.originals},self.originals)


class OccupiedReplicaAdminTests(_AdminFixture,unittest.TestCase):
    repair_profile='receipt-index'
    command_timeout=60

    def setUp(self):
        from memory_vault_open_repair_admin import OCCUPIED_REPLICA_REQUEST_SCHEMA
        from memory_vault_network_crypto import b64url
        self.remote=OccupiedCopyHTTPTests();self.addCleanup(self.remote.doCleanups);self.remote.setUp()
        f=self.remote.fixture;self.copied=self.remote.upload()
        self.rid,self.consents,self.statuses=f.read_configuration(self.copied['custody'])
        self.host=SimpleNamespace(source=SimpleNamespace(temp=f.destination.temp,fixture=f.f))
        self.configure_owner()
        self.request.update(schema_version=OCCUPIED_REPLICA_REQUEST_SCHEMA,target=f.destination.state.target,
            source=f.context['expected_source'],source_storage_epoch=f.context['source_storage_epoch'],maintainer=f.keys,
            receipt_writer=f.bound['expected_receipt_writer'],message_id=f.bound['expected_message_id'],
            envelope_ref=f.bound['expected_envelope_ref'],node=dict(raw_base64url=b64url(self.remote.node['raw']),ref=self.remote.node['ref']))

    def test_operator_configures_bound_replica_and_owner_recovers_after_restart(self):
        import base64,contextlib,io,stat
        from cryptography.hazmat.primitives import serialization
        from memory_vault_network_crypto import b64url,unb64url
        from memory_vault_open_node import NODE_CONFIG
        from memory_vault_open_repair_admin import OCCUPIED_REPLICA_CONFIG_SCHEMA,main
        from memory_vault_trust import _write_new_private
        f=self.remote.fixture;state=f.destination.state
        operator=self.directory/'operator';operator.mkdir(mode=0o700)
        identity=operator/'identity.json';encryption=operator/'encryption.json';config=operator/'node.json'
        secret=state.identity._private_key.private_bytes(serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,serialization.NoEncryption())
        _write_new_private(identity,canonical_bytes(dict(state.identity.public_descriptor(),
            schema_version='universal-memory-identity/v1',private_key=base64.b64encode(secret).decode())))
        state.encryption_identity.save(encryption)
        _write_new_private(config,canonical_bytes(dict(schema_version=NODE_CONFIG,identity_path=str(identity),
            encryption_key_path=str(encryption),state_directory=str(self.remote.directory),node=self.remote.descriptor,
            seeds=[],allow_loopback=True,index_policy=dict(enabled=False),
            repair_policy=dict(enabled=True,limit_policy=f.f['expected']['limit_policy']),
            listen_host='127.0.0.1',listen_port=self.remote.server.server_port)))
        unchanged={path:path.read_bytes() for path in (identity,encryption,config)}
        encode=lambda entry:dict(raw_base64url=b64url(entry['raw']),ref=entry['ref'])
        settings=dict(schema_version=OCCUPIED_REPLICA_CONFIG_SCHEMA,resource_id=self.rid,
            context=dict(**f.context,**f.bound,expected_maintainer=f.keys),
            consents={name:encode(entry) for name,entry in self.consents.items()},
            current_statuses=[encode(entry) for entry in self.statuses])
        path=operator/'request.json';output=operator/'result.json'
        _write_new_private(path,canonical_bytes(settings))
        stdout,stderr=io.StringIO(),io.StringIO()
        with contextlib.redirect_stdout(stdout),contextlib.redirect_stderr(stderr):
            code=main(['configure-replica-occupied','--node-config',str(config),'--request',str(path),'--output',str(output)])
        self.assertEqual((code,stderr.getvalue()),(0,''));self.assertEqual(json.loads(stdout.getvalue())['state'],'configured')
        self.remote.restart();f.original.h.db.close()
        code,stdout,error=self.call('recover-replica-occupied');self.assertEqual((code,error),(0,''))
        result=json.loads(stdout);evidence=json.loads(self.output.read_bytes())
        self.assertEqual(result['state'],'ack_replica_occupied_source_recovered')
        self.assertTrue(result['recipient_saved']);self.assertFalse(result['vault_modified']);self.assertFalse(self.vault.exists())
        self.assertEqual(unb64url(evidence['replica_custody']['raw_base64url'],maximum=524288),self.copied['custody']['raw'])
        self.assertEqual(evidence['envelope_ref'],f.bound['expected_envelope_ref'])
        self.assertEqual(unb64url(evidence['recipient_receipt']['raw_base64url'],maximum=4096),f.receipt['raw'])
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode),0o600)
        self.assertEqual({path:path.read_bytes() for path in self.originals},self.originals)
        self.assertEqual({path:path.read_bytes() for path in unchanged},unchanged)
        with sqlite3.connect(self.directory/'transport'/'network.sqlite3') as db:
            refs={bytes(row[0]) for row in db.execute('SELECT ref FROM open_ack_replica_statuses')}
        self.assertEqual(refs,{canonical_bytes(entry['ref']) for entry in evidence['archive_statuses']})
        self.assertNotIn(b'"private_key"',self.output.read_bytes())




from tests import test_open_repair_proof_typescript as proof_ts_tests


class OccupiedReplicaProofTypeScriptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        proof_ts_tests.OpenRepairProofTypeScriptTests.setUpClass.__func__(cls)

    setUp=proof_ts_tests.OpenRepairProofTypeScriptTests.setUp
    call=proof_ts_tests.OpenRepairProofTypeScriptTests.call
    make_call=proof_ts_tests.OpenRepairProofTypeScriptTests.make_call
    ts=proof_ts_tests.OpenRepairProofTypeScriptTests.ts

    def test_explicit_bound_replica_profile_matches_python_and_refuses_downgrade(self):
        import base64
        import memory_vault_open_repair_proof as proof
        # Container grammar only; the HTTP cases reconstruct each real original.
        manifest=copy.deepcopy(self.py.manifest);reference=self.py.fixture['entries']['root']['ref']
        packed=self.py.fixture['packs'][0]['ref']
        rows=[dict(role=role,ref=packed if role=='replica.read_pack' else reference)
            for role in sorted(proof.REPLICA_OCCUPIED_FIXED_ROLES)]
        rows.extend(dict(role='history.raw_pack',ref=ref) for ref in
            (packed,dict(namespace='meta',key='0'*64,raw_sha256='0'*64,size=1),dict(namespace='meta',key='1'*64,raw_sha256='1'*64,size=1)))
        repeated='historical.status.ack_root'
        rows.append(dict(role=repeated,ref=self.py.fixture['entries']['read']['ref']))
        rows.append(dict(role=repeated,ref=self.py.fixture['entries']['bootstrap']['ref']))
        manifest['children']=[dict(index=i,**row) for i,row in enumerate(rows)]
        raw=self.py.response(manifest).raw;self.py.verify(raw,expected_source_state='replica_occupied')
        call=self.call();call['raw']=base64.b64encode(raw).decode();call['options']['expectedSourceState']='replica_occupied'
        downgraded=copy.deepcopy(call);downgraded['options']['expectedSourceState']='replica_unbound'
        missing=copy.deepcopy(manifest);missing['children']=[row for row in missing['children'] if row['role']!='replica.read_pack']
        for i,row in enumerate(missing['children']):row['index']=i
        extra=copy.deepcopy(manifest);extra['children'].append(dict(index=len(rows),role=repeated,ref=self.py.fixture['entries']['active']['ref']))
        for malformed in (missing,extra):
            with self.assertRaises(wire.RepairWireError):self.py.response(malformed)
        results=self.ts([call,downgraded,self.make_call(missing),self.make_call(extra)])
        self.assertTrue(results[0]['ok'],results[0]);self.assertEqual(results[0]['result']['manifest'],manifest)
        self.assertEqual(results[1]['code'],'repair_proof_mismatch')
        self.assertEqual([row['code'] for row in results[2:]],['repair_invalid_proof','repair_invalid_proof'])
