"""Fresh-owner consent gates real destination reservations and durable retries."""
import copy
import hashlib
import json
import unittest

from memory_vault import canonical_bytes
from memory_vault_open_repair_copy_prepare import AckCopyPreparation
from memory_vault_open_repair_copy_resources import RepairCopyResources
import memory_vault_open_repair_status as status
import memory_vault_open_repair_wire as wire
from tests import test_open_repair_state as state_fixture
from tests.open_repair_ack_fixtures import load_fixture, signed_entry, policy


class CopyPreparationTests(unittest.TestCase):
    def setUp(self):
        self.local = state_fixture.RepairStateTests(); self.local.setUp(); self.addCleanup(self.local.tearDown)
        self.destination = state_fixture.RepairStateTests(); self.destination.setUp(); self.addCleanup(self.destination.tearDown)
        self.f = self.local.fixture; self.p = policy()
        self.now = 2_000_000_010
        self.keys = dict(signing_key=self.f['signers']['maintainer'].public_descriptor(),
                         encryption_key=self.f['encryption']['maintainer'].public_descriptor())
        self.open_journal()
        root = self.f['docs']['root']['payload']
        self.intent = dict(kind='resource.copy_intent',allocation_id='synthetic_copy_allocate',job_id='synthetic_copy_job',
            root_key=root['ack_slot']['root_key'],caller=self.keys,target=self.destination.state.target,
            target_storage_epoch=self.destination.state.node['payload']['storage_epoch'],purpose='ack_replica',
            scope=dict(kind='ack_unbound',ack_slot=root['ack_slot'],root_authority_ref=self.f['entries']['root']['ref']),
            historical_manifest_ref=self.f['manifest']['ref'],budget=dict(root['budget']),
            windows={key:2_000_000_100 for key in root['windows']})
        self.make_consent()

    def open_journal(self):
        self.journal = AckCopyPreparation(self.local.db,self.f['signers']['maintainer'],
            self.f['encryption']['maintainer'],policy=self.p)
        self.journal.initialize()

    def make_consent(self):
        self.consent_payload = dict(schema_version='memory-vault-open-repair/v1',kind='ack.copy_reservation_consent',
            signing_key=self.f['signers']['owner'].public_descriptor(),issued_at=self.now,expires_at=2_000_000_100,
            consent_id='synthetic_copy_consent',revision=1,root_authority_ref=self.f['entries']['root']['ref'],
            source_custody_ref=self.f['custody']['ref'],historical_manifest_ref=self.f['manifest']['ref'],
            maintainer=dict(signing_key_id=self.f['signers']['maintainer'].key_id,
                encryption_key_id=self.f['encryption']['maintainer'].key_id),target=self.intent['target'],
            target_storage_epoch=self.intent['target_storage_epoch'],
            reservation_disclosure=dict(intent_sha256=hashlib.sha256(canonical_bytes(self.intent)).hexdigest(),until=2_000_000_100))
        self.consent = signed_entry(self.consent_payload,self.f['signers']['owner'],'copy_consent')
        self.owner_status = copy.deepcopy(self.f['docs']['owner_status']['payload'])
        self.owner_status.update(revision=2,issued_at=self.now)
        scope = status.status_scope(self.intent['root_key'],'authority',dict(authority_kind='ack.copy_reservation_consent',
            authority_sha256=self.consent['ref']['raw_sha256']),self.p,wire.RepairBudget(self.p))
        self.owner_status['entries'].append(dict(scope_kind='authority',scope_id=scope,
            minimum_document_revision=0,status='active',operation_mask=4))
        self.owner_status['entries'].sort(key=lambda e:(e['scope_kind'],e['scope_id']))

    def prepare(self, *, offer=None, **changes):
        resolver,p,budget=load_fixture(self.f,self.p)
        kwargs=dict(expected_ack_slot=self.f['expected']['expected_ack_slot'],expected_owner=self.f['expected']['expected_owner'],
            expected_source=self.f['expected']['expected_target'],source_storage_epoch=self.f['expected']['target_storage_epoch'],
            current_statuses=[signed_entry(self.owner_status,self.f['signers']['owner'],'copy_current'),self.f['entries']['target_status']],
            at=self.now,limit_policy=self.f['expected']['limit_policy'],budget=budget)
        kwargs.update(changes)
        method = self.journal.prepare_unbound if offer is None else self.journal.assign_unbound
        if offer is not None:kwargs['offer_entry']=offer
        return method(self.f['manifest'],resolver,self.f['custody'],self.consent,self.intent,**kwargs)

    def test_prepared_request_reserves_real_capacity_and_survives_restart(self):
        request=self.prepare()
        self.destination.now[0]=self.now
        resources=RepairCopyResources(self.destination.state);resources.initialize()
        before=self.destination.state.capacity.usage()
        offer=resources.allocate(request,expected_caller=self.keys)
        self.assertNotEqual(before,self.destination.state.capacity.usage())
        self.assertEqual(json.loads(offer['raw'])['payload']['allocation_request_ref'],request['ref'])
        self.local.db.close();self.local.connect();self.open_journal()
        self.assertEqual(self.prepare(),request)
        self.assertEqual(resources.allocate(self.prepare(),expected_caller=self.keys),offer)
        self.assertEqual(self.local.db.execute('SELECT count(*) FROM ack_copy_prepare_jobs').fetchone()[0],1)
        self.assertEqual(self.destination.db.execute('SELECT count(*) FROM open_repair_ack_resources').fetchone()[0],0)

    def test_changed_destination_cannot_reuse_owner_consent(self):
        self.intent['target_storage_epoch']='changed_epoch'
        with self.assertRaises(wire.RepairWireError):self.prepare()
        self.assertEqual(self.local.db.execute('SELECT count(*) FROM ack_copy_prepare_jobs').fetchone()[0],0)

    def test_current_revocation_survives_restart_and_rejects_old_active_replay(self):
        self.prepare()
        original=copy.deepcopy(self.owner_status)
        self.owner_status['revision']=3
        self.owner_status['entries'][0]['status']='revoked'
        with self.assertRaisesRegex(wire.RepairWireError,'repair_authority_revoked'):self.prepare()
        self.local.db.close();self.local.connect();self.open_journal()
        self.owner_status=original
        with self.assertRaisesRegex(wire.RepairWireError,'repair_status_rollback|repair_authority_revoked'):self.prepare()

    def test_expired_prepared_request_is_not_resigned_on_retry(self):
        request=self.prepare();self.now+=61
        with self.assertRaises(wire.RepairWireError):self.prepare()
        stored=self.local.db.execute('SELECT request FROM ack_copy_prepare_jobs').fetchone()[0]
        self.assertEqual(bytes(stored),request['raw'])

    def test_unlisted_maintainer_cannot_prepare(self):
        self.journal.identity=self.f['signers']['writer']
        self.journal.keys=dict(signing_key=self.f['signers']['writer'].public_descriptor(),
            encryption_key=self.f['encryption']['writer'].public_descriptor())
        self.intent['caller']=self.journal.keys
        with self.assertRaises(wire.RepairWireError):self.prepare()

    def test_new_consent_cannot_overwrite_existing_job(self):
        original=self.prepare()
        self.intent['allocation_id']='different_allocation';self.make_consent()
        self.owner_status['revision']=3
        with self.assertRaises(wire.RepairWireError):self.prepare()
        self.assertEqual(bytes(self.local.db.execute('SELECT request FROM ack_copy_prepare_jobs').fetchone()[0]),original['raw'])

    def test_authentic_revocation_is_kept_when_next_document_is_malformed(self):
        self.prepare(); old=copy.deepcopy(self.owner_status)
        self.owner_status['revision']=3
        for entry in self.owner_status['entries']:
            entry['status']='revoked'
        revoked=signed_entry(self.owner_status,self.f['signers']['owner'],'revoked')
        with self.assertRaises(wire.RepairWireError):
            self.prepare(current_statuses=[revoked,{'raw':b'{}','ref':revoked['ref']}])
        self.owner_status=old
        with self.assertRaisesRegex(wire.RepairWireError,'repair_status_rollback|repair_authority_revoked'):
            self.prepare()

    def test_expired_revocation_is_observed_before_refusal(self):
        self.prepare();old=copy.deepcopy(self.owner_status)
        self.owner_status.update(revision=3,issued_at=self.now-2,valid_until=self.now)
        for entry in self.owner_status['entries']:entry['status']='revoked'
        with self.assertRaises(wire.RepairWireError):self.prepare()
        self.owner_status=old
        with self.assertRaisesRegex(wire.RepairWireError,'repair_status_rollback|repair_authority_revoked'):self.prepare()

    def test_newer_active_status_cannot_clear_observed_revocation(self):
        self.prepare();old=copy.deepcopy(self.owner_status)
        self.owner_status['revision']=3
        for entry in self.owner_status['entries']:entry['status']='revoked'
        with self.assertRaises(wire.RepairWireError):self.prepare()
        self.owner_status=old;self.owner_status['revision']=4
        with self.assertRaisesRegex(wire.RepairWireError,'repair_authority_revoked'):self.prepare()

    def test_missing_identity_binding_is_not_recreated(self):
        self.prepare()
        self.local.db.execute('DELETE FROM ack_copy_prepare_binding');self.local.db.commit()
        with self.assertRaises(wire.RepairWireError):self.open_journal()

    def test_changed_cached_request_cannot_be_replayed(self):
        request=self.prepare();body=json.loads(request['raw']);body['payload']['expires_at']+=1
        raw=canonical_bytes(body);ref=dict(request['ref'],size=len(raw),raw_sha256=hashlib.sha256(raw).hexdigest())
        self.local.db.execute('UPDATE ack_copy_prepare_jobs SET request=?,ref=?',(raw,canonical_bytes(ref)));self.local.db.commit()
        with self.assertRaises(wire.RepairWireError):self.prepare()

    def allocate_offer(self):
        request=self.prepare();self.destination.now[0]=self.now
        target=RepairCopyResources(self.destination.state);target.initialize()
        return target.allocate(request,expected_caller=self.keys)

    def test_real_offer_gets_exact_durable_owner_read_copy_assignment(self):
        offer=self.allocate_offer();assignment=self.prepare(offer=offer)
        p=json.loads(assignment['raw'])['payload']
        self.assertEqual(p['operation_mask'],70)
        self.assertEqual(p['resource_offer_ref'],offer['ref'])
        self.assertEqual(p['resource'],json.loads(offer['raw'])['payload']['resource'])
        self.assertEqual(p['bootstrap_grant_refs'],[self.f['entries']['bootstrap']['ref']])
        self.assertEqual(p['scope'],self.intent['scope'])
        self.assertIsNone(p['parent_assignment_ref'])
        self.local.db.close();self.local.connect();self.open_journal()
        self.assertEqual(self.prepare(offer=offer),assignment)
        self.assertEqual(self.local.db.execute('SELECT count(*) FROM ack_copy_prepare_assignments').fetchone()[0],1)

    def test_forged_offer_cannot_create_assignment(self):
        offer=self.allocate_offer();body=json.loads(offer['raw']);body['payload']['resource']['resource_id']='changed_resource'
        raw=canonical_bytes(body);offer=dict(raw=raw,ref=dict(offer['ref'],size=len(raw),raw_sha256=hashlib.sha256(raw).hexdigest()))
        with self.assertRaises(wire.RepairWireError):self.prepare(offer=offer)
        self.assertEqual(self.local.db.execute('SELECT count(*) FROM ack_copy_prepare_assignments').fetchone()[0],0)

    def test_revocation_between_reservation_and_assignment_refuses_delegation(self):
        offer=self.allocate_offer();self.owner_status['revision']=3
        for entry in self.owner_status['entries']:entry['status']='revoked'
        with self.assertRaises(wire.RepairWireError):self.prepare(offer=offer)
        self.assertEqual(self.local.db.execute('SELECT count(*) FROM ack_copy_prepare_assignments').fetchone()[0],0)

    def test_copy_only_current_root_cannot_delegate_read_or_retain(self):
        offer=self.allocate_offer();self.owner_status['revision']=3
        for entry in self.owner_status['entries']:entry['operation_mask']=4
        with self.assertRaisesRegex(wire.RepairWireError,'repair_status_operation'):self.prepare(offer=offer)
        self.assertEqual(self.local.db.execute('SELECT count(*) FROM ack_copy_prepare_assignments').fetchone()[0],0)

    def test_revoked_owner_read_grant_prevents_service_assignment(self):
        offer=self.allocate_offer();self.owner_status['revision']=3
        scope=status.status_scope(self.intent['root_key'],'authority',dict(authority_kind='ack.read_grant',
            authority_sha256=self.f['entries']['read']['ref']['raw_sha256']),self.p,wire.RepairBudget(self.p))
        next(entry for entry in self.owner_status['entries'] if entry['scope_id']==scope)['status']='revoked'
        with self.assertRaisesRegex(wire.RepairWireError,'repair_authority_revoked'):self.prepare(offer=offer)
        self.assertEqual(self.local.db.execute('SELECT count(*) FROM ack_copy_prepare_assignments').fetchone()[0],0)
