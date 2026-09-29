"""Synthetic bound-slot copying through actual durable source/destination stores."""
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


class EmptyCopyStateTests(unittest.TestCase):
    def setUp(self):
        # Fund the extra source generation and provisional transfer before the
        # first source allocation/activation is signed. No runtime cap changes.
        class FundedSource(state_fixture.RepairStateTests):
            capacity_overrides=dict(max_meta_bytes=1048576,max_job_bytes=1048576,max_requests=4096)
            limit_overrides=dict(max_probe_bytes=8192,max_proof_bytes=1048576,max_signature_checks=4096)
            def activate(self):
                f=self.fixture
                for name in ('root','read'):f['docs'][name]['payload']['budget']['max_meta_bytes']=1048576
                allocation=copy.deepcopy(f['docs']['allocate']['payload'])
                allocation['intent']['budget']['max_meta_bytes']=1048576
                allocation['intent_sha256']=hashlib.sha256(canonical_bytes(allocation['intent'])).hexdigest()
                f['entries']['allocate']=signed_entry(allocation,f['signers']['owner'],'synthetic_funded_source')
                f['docs']['allocate']=json.loads(f['entries']['allocate']['raw'])
                return super().activate()
        self.original=empty_fixture.OpenRepairEmptyTests()
        with patch.object(empty_fixture.source_tests,'RepairStateTests',FundedSource):self.original.setUp()
        self.addCleanup(self.original.tearDown)
        self.result=self.original.bind();self.f=self.original.h.fixture
        self.destination=state_fixture.RepairStateTests();self.destination.setUp();self.addCleanup(self.destination.tearDown)
        self.destination.now[0]=self.now=2_000_000_010
        self.policy=self.destination.state.policy
        self.store=RepairCopyState(self.destination.state);self.store.initialize()
        self.temp=tempfile.TemporaryDirectory(prefix='synthetic-empty-copy-');self.addCleanup(self.temp.cleanup)
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
            scope=dict(kind='ack_empty',ack_slot=root['ack_slot'],grant_ref=self.original.write['ref'],binding_ref=self.result['binding']['ref']),
            historical_manifest_ref=self.result['manifest']['ref'],budget=dict(root['budget']),
            windows={name:self.now+90 for name in root['windows']})
        self.consent=signed_entry(dict(schema_version='memory-vault-open-repair/v1',kind='ack.copy_reservation_consent',
            signing_key=self.f['signers']['owner'].public_descriptor(),issued_at=self.now,expires_at=self.now+90,
            consent_id='synthetic_bound_consent',revision=1,root_authority_ref=self.f['entries']['root']['ref'],
            source_custody_ref=self.result['custody']['ref'],historical_manifest_ref=self.result['manifest']['ref'],
            maintainer=dict(signing_key_id=self.keys['signing_key']['key_id'],encryption_key_id=self.keys['encryption_key']['key_id']),
            target=self.intent['target'],target_storage_epoch=self.intent['target_storage_epoch'],
            reservation_disclosure=dict(intent_sha256=hashlib.sha256(canonical_bytes(self.intent)).hexdigest(),until=self.now+90)),
            self.f['signers']['owner'],'synthetic_bound_consent')
        self.owner_status=copy.deepcopy(json.loads(self.original.expected['current_statuses'][0]['raw'])['payload'])
        self.owner_status.update(revision=3,issued_at=self.now)
        self.add_authority(self.owner_status,self.consent,4)
        self.request=self.prepare()
        if getattr(self,'reserve_remotely',False):return
        self.complete_reservation(self.store.allocate(self.request,expected_caller=self.keys))

    def complete_reservation(self,offer):
        self.offer=offer
        self.assignment=self.prepare(offer=self.offer)
        resolver=self.resolver()
        checked=source_view.authenticate_source(self.result['manifest'],resolver,self.result['custody'],source_state='empty',bound=self.bound,
            expected_ack_slot=self.context['expected_ack_slot'],expected_owner=self.context['expected_owner'],
            expected_target=self.context['expected_source'],target_storage_epoch=self.context['source_storage_epoch'],
            limit_policy=self.f['expected']['limit_policy'],policy=self.policy,budget=resolver.budget)
        reservation=index._signed(self.consent,self.context['expected_owner']['signing_key'],'ack.copy_reservation_consent',
            authority.CONSENT_FIELDS,self.policy,resolver.budget)
        rows=authority.source_inventory(checked,reservation,self.policy,resolver.budget)
        self.disclosures={}
        for variant,name in (('owner','owner'),('source','target')):
            signer=self.f['signers'][name]
            originals,scopes=authority.disclosure_permissions(rows,signer.key_id,self.intent['root_key'],self.policy,resolver.budget)
            self.disclosures[variant]=signed_entry(dict(schema_version='memory-vault-open-repair/v1',kind='ack.copy_disclosure',
                signing_key=signer.public_descriptor(),issued_at=self.now,expires_at=self.now+90,consent_id='synthetic_bound_'+variant,
                revision=1,variant=variant,root_key=self.intent['root_key'],assignment_ref=self.assignment['ref'],
                source_custody_ref=self.result['custody']['ref'],historical_manifest_ref=self.result['manifest']['ref'],
                target=self.intent['target'],target_storage_epoch=self.intent['target_storage_epoch'],
                disclosure=dict(originals=originals,status_scopes=scopes,until=self.now+90)),signer,'synthetic_bound_'+variant)
        self.owner_status['revision']=4;self.add_authority(self.owner_status,self.disclosures['owner'],4)
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
            WHERE p.resource_id=? AND p.role IN ('pack','empty:pack')""",(self.original.h.resource_id,)):
            resolver.put(namespace,key,bytes(raw))
        return resolver

    def prepare(self,offer=None):
        resolver=self.resolver()
        args=dict(**self.context,**self.bound,current_statuses=[signed_entry(self.owner_status,self.f['signers']['owner'],'copy_owner'),
            self.f['entries']['target_status']],at=self.now,limit_policy=self.f['expected']['limit_policy'],budget=resolver.budget)
        method=self.journal.prepare_empty if offer is None else self.journal.assign_empty
        if offer is not None:args['offer_entry']=offer
        return method(self.result['manifest'],resolver,self.result['custody'],self.consent,self.intent,**args)

    def statuses(self):
        return [signed_entry(payload,self.f['signers'][name],'copy_current_'+name) for payload,name in
            ((self.owner_status,'owner'),(self.source_status,'target'),(self.maintainer_status,'maintainer'))]

    def commit(self):
        return self.store.commit_empty(self.result['manifest'],self.resolver(),self.result['custody'],self.request,self.offer,self.assignment,
            self.consent,self.disclosures['owner'],self.disclosures['source'],**self.context,**self.bound,
            expected_maintainer=self.keys,current_statuses=self.statuses(),limit_policy=self.f['expected']['limit_policy'])

    def restart(self):
        self.destination.db.close();self.destination.connect();self.store=RepairCopyState(self.destination.state);self.store.initialize()

    def read_configuration(self,custody):
        resolver=self.resolver()
        plan=authority.verify_empty_copy(self.result['manifest'],resolver,self.result['custody'],self.request,self.offer,self.assignment,
            self.consent,self.disclosures['owner'],self.disclosures['source'],**self.context,**self.bound,
            expected_maintainer=self.keys,expected_target=self.destination.state.target,target_storage_epoch=self.intent['target_storage_epoch'],
            current_statuses=self.statuses(),at=self.now,limit_policy=self.f['expected']['limit_policy'],policy=self.policy,budget=resolver.budget)
        self.assertIsNone(plan.denial_code)
        consents={};current=[];root=self.intent['root_key']
        for variant,name,previous in (('owner','owner',self.owner_status),('source','target',self.source_status),
                ('maintainer','maintainer',self.maintainer_status)):
            signer=self.f['signers'][name];budget=wire.RepairBudget(self.policy)
            originals,scopes=authority.copy_return_permissions(plan,signer.key_id,self.policy,budget)
            consent=signed_entry(dict(schema_version=authority.resource.SCHEMA,kind='ack.replica_return_consent',
                signing_key=signer.public_descriptor(),issued_at=self.now,expires_at=self.now+90,consent_id='synthetic_empty_return_'+variant,
                revision=1,variant=variant,root_key=root,source_custody_ref=self.result['custody']['ref'],
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

    def test_exact_binding_and_both_generations_survive_destination_restart(self):
        custody=self.commit();self.restart();self.assertEqual(self.commit(),custody)
        rid=json.loads(custody['raw'])['payload']['resource']['resource_id']
        restored=self.store.restore_empty(rid,**self.context,**self.bound,expected_maintainer=self.keys,limit_policy=self.f['expected']['limit_policy'])
        self.assertEqual(restored['source'].event.binding.raw,self.result['binding']['raw'])
        self.assertEqual(restored['source'].event.predecessor.custody.raw,self.f['custody']['raw'])
        self.assertEqual(restored['source'].custody.raw,self.result['custody']['raw'])
        self.assertEqual(json.loads(self.assignment['raw'])['payload']['operation_mask'],70)
        self.assertEqual(len(json.loads(self.assignment['raw'])['payload']['bootstrap_grant_refs']),2)
        with self.assertRaises(wire.RepairWireError):
            self.store.restore_unbound(rid,**self.context,expected_maintainer=self.keys,limit_policy=self.f['expected']['limit_policy'])

    def test_copy_refuses_a_different_message_or_receipt_writer(self):
        other=self.keys
        self.assertNotEqual(other,self.bound['expected_receipt_writer'])
        envelope=copy.deepcopy(self.bound['expected_envelope_ref']);envelope['raw_sha256']='0'*64
        for name,value in (('expected_message_id','0'*64),('expected_receipt_writer',other),('expected_envelope_ref',envelope)):
            with self.subTest(binding=name),self.assertRaises(wire.RepairWireError):
                self.store.commit_empty(self.result['manifest'],self.resolver(),self.result['custody'],
                    self.request,self.offer,self.assignment,self.consent,self.disclosures['owner'],self.disclosures['source'],
                    **self.context,**dict(self.bound,**{name:value}),expected_maintainer=self.keys,
                    current_statuses=self.statuses(),limit_policy=self.f['expected']['limit_policy'])
        self.assertEqual(self.destination.db.execute('SELECT count(*) FROM open_repair_copy_commits').fetchone()[0],0)

    def test_empty_read_retains_write_revocation_after_restart(self):
        custody=self.commit();rid,consents,current=self.read_configuration(custody)
        arguments=dict(**self.context,**self.bound,expected_maintainer=self.keys,limit_policy=self.f['expected']['limit_policy'])
        with self.assertRaises(wire.RepairWireError):
            self.store.prepare_empty_read(rid,{name:item for name,item in consents.items() if name!='source'},
                current_statuses=current,**arguments)
        revoked=copy.deepcopy(json.loads(current[0]['raw'])['payload']);revoked['revision']+=1
        write_scope=status.status_scope(self.intent['root_key'],'authority',dict(authority_kind='ack.write_grant',
            authority_sha256=self.original.write['ref']['raw_sha256']),self.policy,wire.RepairBudget(self.policy))
        for item in revoked['entries']:
            if item['scope_id']==write_scope:item['status']='revoked'
        self.assertTrue(any(item['status']=='revoked' for item in revoked['entries']))
        incoming=[signed_entry(revoked,self.f['signers']['owner'],'synthetic_revoked_read'),*current[1:]]
        with self.assertRaisesRegex(wire.RepairWireError,'repair_authority_revoked'):
            self.store.prepare_empty_read(rid,consents,current_statuses=incoming,**arguments)
        self.restart()
        with self.assertRaises(wire.RepairWireError):
            self.store.prepare_empty_read(rid,consents,current_statuses=current,**arguments)

    def test_copy_transaction_failure_cannot_leave_partial_custody(self):
        self.destination.db.execute("CREATE TRIGGER synthetic_copy_crash BEFORE INSERT ON open_repair_copy_commits BEGIN SELECT RAISE(ABORT,'synthetic crash'); END")
        self.destination.db.commit()
        with self.assertRaisesRegex(Exception,'synthetic crash'):self.commit()
        self.assertEqual(self.destination.db.execute('SELECT count(*) FROM open_repair_copy_objects').fetchone()[0],0)
        self.assertEqual(self.destination.db.execute('SELECT count(*) FROM open_repair_copy_commits').fetchone()[0],0)
        self.restart();self.destination.db.execute('DROP TRIGGER synthetic_copy_crash');self.destination.db.commit()
        self.assertTrue(self.commit()['raw'])

    def test_bound_write_revocation_is_retained_before_refusing_copy(self):
        previous=copy.deepcopy(self.owner_status)
        scope=status.status_scope(self.intent['root_key'],'authority',dict(authority_kind='ack.write_grant',
            authority_sha256=self.original.write['ref']['raw_sha256']),self.policy,wire.RepairBudget(self.policy))
        self.owner_status['revision']=5
        for row in self.owner_status['entries']:
            if row['scope_id']==scope:row['status']='revoked'
        with self.assertRaisesRegex(wire.RepairWireError,'repair_authority_revoked'):self.commit()
        self.restart();self.owner_status=previous
        with self.assertRaisesRegex(wire.RepairWireError,'repair_status_rollback|repair_authority_revoked'):self.commit()
        self.assertEqual(self.destination.db.execute('SELECT count(*) FROM open_repair_copy_commits').fetchone()[0],0)


class EmptyCopyHTTPTests(unittest.TestCase):
    def setUp(self):
        from memory_vault_open_control import issue_node
        from memory_vault_open_node import OpenHTTPServer
        from memory_vault_open_transport import OpenHTTPTransport
        from tests.test_open_repair_copy_upload import CopyUploadHTTPTests
        self.fixture=EmptyCopyStateTests();self.fixture.reserve_remotely=getattr(self,'reserve_remotely',False)
        self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
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
        return client.upload_empty(self.base,f.result['manifest'],f.resolver(),f.result['custody'],f.request,f.offer,f.assignment,
            f.consent,f.disclosures['owner'],f.disclosures['source'],target_node_entry=self.node,**f.context,**f.bound,
            expected_target=f.destination.state.target,target_storage_epoch=f.intent['target_storage_epoch'],
            current_statuses=f.statuses(),limit_policy=f.f['expected']['limit_policy'])

    def test_lost_successful_copy_commit_resumes_same_replica_after_both_restarts(self):
        from memory_vault import MemoryError
        f=self.fixture;host=self
        class LostCommitReply:
            lost=False
            def request(self,*args,**kwargs):return host.transport.request(*args,**kwargs)
            def request_blob(self,*args,**kwargs):return host.transport.request_blob(*args,**kwargs)
            def request_repair(self,base,raw,**kwargs):
                reply=host.transport.request_repair(base,raw,**kwargs)
                if not self.lost and json.loads(raw)['payload']['kind']=='ack.copy_empty_commit':
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
        from memory_vault_open_repair_copy_service import ReplicaEmptyReadService
        import memory_vault_open_repair_proof as proof
        f=self.fixture;copied=self.upload()
        rid,consents,statuses=f.read_configuration(copied['custody'])
        with self.participant.state.db() as db:
            service=ReplicaEmptyReadService(self.participant._repair_service(db).state);service.initialize()
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
        result=client.recover_replica_empty(self.base,**arguments)
        self.assertEqual(result.replica['source'].event.binding.raw,f.result['binding']['raw'])
        self.assertEqual(result.replica['source'].event.predecessor.custody.raw,f.f['custody']['raw'])
        self.assertEqual(result.replica['custody'].raw,copied['custody']['raw'])
        rows=result.proof.manifest.value['children']
        packed=[row for row in rows if row['role'] in proof.REPLICA_READ_PACK_ROLES]
        self.assertGreater(len(packed),10)
        for row in packed:self.assertNotIn(row['index'],requested_children)
        self.assertEqual(result.metrics['proof_bytes'],len(responses[1])+len(result.proof.handle.raw)
            +len(result.proof.manifest.raw)+sum(len(raw) for raw in result.originals.values()))
        with self.participant.state.db() as db:
            self.assertLess(db.execute('SELECT requests FROM open_repair_copy_work').fetchone()[0],64)
        self.assertEqual(self.errors,[])
        build_pack=wire.build_raw_pack
        def with_extra_original(raws,policy,budget):
            return build_pack([*raws,b'{"synthetic":"unadvertised"}'],policy,budget)
        with patch('memory_vault_open_repair_copy_service.wire.build_raw_pack',side_effect=with_extra_original):
            with self.assertRaisesRegex(wire.RepairWireError,'repair_proof_mismatch'):
                client.recover_replica_empty(self.base,**arguments)


from tests.test_open_repair_admin import _CopyAdminFixture
from tests.test_open_repair_admin import _AdminFixture


class EmptyCopyReservationTests(unittest.TestCase):
    def test_remote_reservation_lost_reply_replays_before_bound_upload(self):
        from memory_vault import MemoryError
        from memory_vault_open_repair_copy_client import AckCopyUploadClient
        host=EmptyCopyHTTPTests();host.reserve_remotely=True;self.addCleanup(host.doCleanups);host.setUp()
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
            return client.reserve_empty(host.base,f.result['manifest'],f.resolver(),f.result['custody'],f.consent,f.intent,
                target_node_entry=host.node,**f.context,**f.bound,current_statuses=[
                    signed_entry(f.owner_status,f.f['signers']['owner'],'synthetic_empty_reserve'),f.f['entries']['target_status']],
                limit_policy=f.f['expected']['limit_policy'])
        self.assertEqual(f.destination.db.execute('SELECT count(*) FROM open_repair_copy_resources').fetchone()[0],0)
        with self.assertRaisesRegex(MemoryError,'synthetic_lost_allocation_reply'):reserve()
        host.restart();f.local.close();f.open_journal()
        result=reserve();self.assertEqual(result['allocation'],f.request)
        self.assertEqual(requests[0],requests[1])
        self.assertEqual(f.destination.db.execute('SELECT count(*) FROM open_repair_copy_resources').fetchone()[0],1)
        f.complete_reservation(result['offer']);copied=host.upload()
        self.assertEqual(copied['state'],'replica_committed')
        self.assertEqual(json.loads(copied['custody']['raw'])['payload']['scope'],f.intent['scope'])


class EmptyCopyAdminTests(_CopyAdminFixture,unittest.TestCase):
    copy_operation='upload'

    def setUp(self):
        from memory_vault_open_repair_admin import EMPTY_COPY_REQUEST_SCHEMA
        from memory_vault_open_client import OpenNetworkClient
        self.remote=EmptyCopyHTTPTests();self.remote.reserve_remotely=self.copy_operation=='reserve'
        self.remote.setUp();self.addCleanup(self.remote.doCleanups)
        f=self.remote.fixture
        packs=[]
        for namespace,key,raw in f.original.h.db.execute("""SELECT DISTINCT o.namespace,o.opaque_key,o.raw FROM open_repair_ack_objects o
            JOIN open_repair_ack_pins p ON o.namespace=p.namespace AND o.opaque_key=p.opaque_key
            WHERE p.resource_id=? AND p.role IN ('pack','empty:pack')""",(f.original.h.resource_id,)):
            raw=bytes(raw);packs.append(dict(raw=raw,ref=dict(namespace=namespace,key=key,
                raw_sha256=hashlib.sha256(raw).hexdigest(),size=len(raw))))
        h=SimpleNamespace(destination=f.destination,f=dict(f.f,manifest=f.result['manifest'],custody=f.result['custody'],packs=packs),
            consent=f.consent,intent=f.intent)
        self.configure_copy(h,self.remote.descriptor,self.copy_operation)
        self.request.update(schema_version=EMPTY_COPY_REQUEST_SCHEMA,
            receipt_writer=f.bound['expected_receipt_writer'],message_id=f.bound['expected_message_id'],envelope_ref=f.bound['expected_envelope_ref'])
        if self.copy_operation=='reserve':
            self.request['current_statuses']=[self.encode(signed_entry(f.owner_status,f.f['signers']['owner'],'synthetic_cli_empty_reserve')),
                self.encode(f.f['entries']['target_status'])]
            return
        for name,entry in dict(allocation=f.request,offer=f.offer,assignment=f.assignment,
                owner_disclosure=f.disclosures['owner'],source_disclosure=f.disclosures['source']).items():
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
        code,output,error=self.call('copy-upload-empty');self.assertEqual((code,error),(0,''))
        evidence=json.loads(self.output.read_bytes())
        self.assertEqual(evidence['state'],'replica_committed');self.assertEqual(evidence['source_state'],'empty')
        self.assertFalse(evidence['recipient_saved']);self.assertFalse(evidence['receipt_admission_authorized'])
        self.assertFalse(self.vault.exists())
        self.remote.restart();self.request_path=self.directory/'retry.json';self.output=self.directory/'retry-result.json'
        code,output,error=self.call('copy-upload-empty');self.assertEqual((code,error),(0,''))
        self.assertEqual(json.loads(self.output.read_bytes()),evidence)
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode),0o600)
        self.assertEqual({path:path.read_bytes() for path in self.originals},self.originals)


class EmptyCopyReserveAdminTests(_CopyAdminFixture,unittest.TestCase):
    copy_operation='reserve'
    setUp=EmptyCopyAdminTests.setUp

    def test_remote_command_reserves_the_exact_bound_slot(self):
        from memory_vault_network_crypto import unb64url
        code,output,error=self.call('copy-reserve-empty');self.assertEqual((code,error),(0,''))
        evidence=json.loads(self.output.read_bytes())
        self.assertEqual(evidence['state'],'capacity_reserved_and_assigned');self.assertEqual(evidence['source_state'],'empty')
        assignment=json.loads(unb64url(evidence['assignment']['raw_base64url'],maximum=524288))['payload']
        self.assertEqual(assignment['scope'],self.remote.fixture.intent['scope'])
        self.assertEqual(assignment['operation_mask'],70);self.assertEqual(len(assignment['bootstrap_grant_refs']),2)
        self.assertFalse(json.loads(output)['recipient_saved']);self.assertFalse(self.vault.exists())
        self.assertEqual({path:path.read_bytes() for path in self.originals},self.originals)


class EmptyReplicaAdminTests(_AdminFixture,unittest.TestCase):
    repair_profile='receipt-index'
    command_timeout=60

    def setUp(self):
        from memory_vault_open_repair_admin import EMPTY_REPLICA_REQUEST_SCHEMA
        from memory_vault_network_crypto import b64url
        self.remote=EmptyCopyHTTPTests();self.addCleanup(self.remote.doCleanups);self.remote.setUp()
        f=self.remote.fixture;self.copied=self.remote.upload()
        self.rid,self.consents,self.statuses=f.read_configuration(self.copied['custody'])
        self.host=SimpleNamespace(source=SimpleNamespace(temp=f.destination.temp,fixture=f.f))
        self.configure_owner()
        self.request.update(schema_version=EMPTY_REPLICA_REQUEST_SCHEMA,target=f.destination.state.target,
            source=f.context['expected_source'],source_storage_epoch=f.context['source_storage_epoch'],maintainer=f.keys,
            receipt_writer=f.bound['expected_receipt_writer'],message_id=f.bound['expected_message_id'],
            envelope_ref=f.bound['expected_envelope_ref'],node=dict(raw_base64url=b64url(self.remote.node['raw']),ref=self.remote.node['ref']))

    def test_operator_configures_bound_replica_and_owner_recovers_after_restart(self):
        import base64,contextlib,io,stat
        from cryptography.hazmat.primitives import serialization
        from memory_vault_network_crypto import b64url,unb64url
        from memory_vault_open_node import NODE_CONFIG
        from memory_vault_open_repair_admin import EMPTY_REPLICA_CONFIG_SCHEMA,main
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
        settings=dict(schema_version=EMPTY_REPLICA_CONFIG_SCHEMA,resource_id=self.rid,
            context=dict(**f.context,**f.bound,expected_maintainer=f.keys),
            consents={name:encode(entry) for name,entry in self.consents.items()},
            current_statuses=[encode(entry) for entry in self.statuses])
        path=operator/'request.json';output=operator/'result.json'
        _write_new_private(path,canonical_bytes(settings))
        stdout,stderr=io.StringIO(),io.StringIO()
        with contextlib.redirect_stdout(stdout),contextlib.redirect_stderr(stderr):
            code=main(['configure-replica-empty','--node-config',str(config),'--request',str(path),'--output',str(output)])
        self.assertEqual((code,stderr.getvalue()),(0,''));self.assertEqual(json.loads(stdout.getvalue())['state'],'configured')
        self.remote.restart();f.original.h.db.close()
        code,stdout,error=self.call('recover-replica-empty');self.assertEqual((code,error),(0,''))
        result=json.loads(stdout);evidence=json.loads(self.output.read_bytes())
        self.assertEqual(result['state'],'ack_replica_empty_source_recovered')
        self.assertFalse(result['recipient_saved']);self.assertFalse(result['vault_modified']);self.assertFalse(self.vault.exists())
        self.assertEqual(unb64url(evidence['replica_custody']['raw_base64url'],maximum=524288),self.copied['custody']['raw'])
        self.assertEqual(evidence['envelope_ref'],f.bound['expected_envelope_ref'])
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode),0o600)
        self.assertEqual({path:path.read_bytes() for path in self.originals},self.originals)
        self.assertEqual({path:path.read_bytes() for path in unchanged},unchanged)
        with sqlite3.connect(self.directory/'transport'/'network.sqlite3') as db:
            refs={bytes(row[0]) for row in db.execute('SELECT ref FROM open_ack_replica_statuses')}
        self.assertEqual(refs,{canonical_bytes(entry['ref']) for entry in evidence['archive_statuses']})
        self.assertNotIn(b'"private_key"',self.output.read_bytes())


from tests import test_open_repair_proof_typescript as proof_ts_tests


class EmptyReplicaProofTypeScriptTests(unittest.TestCase):
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
            for role in sorted(proof.REPLICA_EMPTY_FIXED_ROLES)]
        rows.extend(dict(role='history.raw_pack',ref=ref) for ref in
            (packed,dict(namespace='meta',key='0'*64,raw_sha256='0'*64,size=1)))
        repeated=next(iter(sorted(proof.REPLICA_EMPTY_REPEATED)))
        rows.append(dict(role=repeated,ref=self.py.fixture['entries']['read']['ref']))
        manifest['children']=[dict(index=i,**row) for i,row in enumerate(rows)]
        raw=self.py.response(manifest).raw;self.py.verify(raw,expected_source_state='replica_empty')
        call=self.call();call['raw']=base64.b64encode(raw).decode();call['options']['expectedSourceState']='replica_empty'
        downgraded=copy.deepcopy(call);downgraded['options']['expectedSourceState']='replica_unbound'
        missing=copy.deepcopy(manifest);missing['children']=[row for row in missing['children'] if row['role']!='replica.read_pack']
        for i,row in enumerate(missing['children']):row['index']=i
        extra=copy.deepcopy(manifest);extra['children'].append(dict(index=len(rows),role=repeated,ref=self.py.fixture['entries']['bootstrap']['ref']))
        for malformed in (missing,extra):
            with self.assertRaises(wire.RepairWireError):self.py.response(malformed)
        results=self.ts([call,downgraded,self.make_call(missing),self.make_call(extra)])
        self.assertTrue(results[0]['ok'],results[0]);self.assertEqual(results[0]['result']['manifest'],manifest)
        self.assertEqual(results[1]['code'],'repair_proof_mismatch')
        self.assertEqual([row['code'] for row in results[2:]],['repair_invalid_proof','repair_invalid_proof'])


if __name__=='__main__':unittest.main()
