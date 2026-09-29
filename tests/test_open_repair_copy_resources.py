"""Real destination capacity for a copy offer, never a replica commitment."""
import copy
import hashlib
import json
import unittest
from memory_vault import canonical_bytes
from memory_vault_open_repair_copy_resources import RepairCopyResources
import memory_vault_open_repair_wire as wire
from tests import test_open_repair_state as fixture
from tests.open_repair_ack_fixtures import signed_entry


class CopyReservationTests(unittest.TestCase):
    def setUp(self):
        self.local=fixture.RepairStateTests();self.local.setUp();self.addCleanup(self.local.tearDown)
        self.f=self.local.fixture;self.caller=self.f['expected']['expected_owner']
        self.resources=RepairCopyResources(self.local.state);self.resources.initialize()
        slot=self.f['docs']['root']['payload']['ack_slot']
        self.intent=dict(kind='resource.copy_intent',allocation_id='copy_allocation_001',job_id='copy_job_001',
            root_key=slot['root_key'],caller=self.caller,target=self.local.state.target,
            target_storage_epoch=self.local.state.node['payload']['storage_epoch'],purpose='ack_replica',
            scope=dict(kind='ack_unbound',ack_slot=slot,root_authority_ref=self.f['entries']['root']['ref']),
            historical_manifest_ref=self.f['manifest']['ref'],
            budget=dict(max_live_bytes=16384,max_meta_bytes=131072,max_items=16,max_requests=64,
                max_pending=8,max_replay_records=16,max_jobs=1,max_job_bytes=131072),
            windows={name:2_000_000_100 for name in ('admit_until','read_until','copy_until','publish_until','retain_until')})

    def request(self, intent=None):
        intent=copy.deepcopy(self.intent if intent is None else intent)
        p=dict(schema_version='memory-vault-open-repair/v1',kind='resource.allocate',
            signing_key=self.caller['signing_key'],issued_at=2_000_000_000,expires_at=2_000_000_060,
            request_id='copy_request_001',target_node_key_id=self.local.state.identity.key_id,
            target_storage_epoch=self.local.state.node['payload']['storage_epoch'],intent=intent,
            intent_sha256=hashlib.sha256(canonical_bytes(intent)).hexdigest())
        return signed_entry(p,self.f['signers']['owner'],'copy_allocate')

    def test_real_shared_reservation_and_restart_exact_retry(self):
        entry=self.request();before=self.local.state.capacity.usage()
        result=self.resources.allocate(entry,expected_caller=self.caller)
        usage=self.local.state.capacity.usage()
        row=self.local.state._one('SELECT * FROM open_repair_copy_resources')
        self.assertEqual(row['status'],'reserved')
        reserved=self.local.state._one("SELECT * FROM open_capacity_reservations WHERE service='repair_copy'")
        self.assertEqual(reserved['charge_bytes'],row['charge_bytes'])
        self.assertNotEqual(usage,before)
        self.local.db.close();self.local.connect()
        self.resources=RepairCopyResources(self.local.state);self.resources.initialize()
        self.local.now[0]=2_000_000_080
        self.assertEqual(self.resources.allocate(entry,expected_caller=self.caller),result)
        self.assertEqual(self.local.state.capacity.usage(),usage)
        self.assertEqual(self.local.db.execute('SELECT count(*) FROM open_repair_ack_resources').fetchone()[0],0)

    def test_conflict_does_not_allocate_second_reservation(self):
        self.resources.allocate(self.request(),expected_caller=self.caller)
        before=self.local.state.capacity.usage()
        changed=copy.deepcopy(self.intent);changed['job_id']='copy_job_other'
        with self.assertRaisesRegex(wire.RepairWireError,'repair_copy_allocation_conflict'):
            self.resources.allocate(self.request(changed),expected_caller=self.caller)
        self.assertEqual(self.local.state.capacity.usage(),before)

    def test_wrong_target_and_index_intent_cannot_be_reused(self):
        for updates in ({'kind':'resource.index_intent'},{'target_storage_epoch':'other_epoch'},{'purpose':'provider_index'}):
            with self.subTest(updates=updates):
                with self.assertRaises(wire.RepairWireError):
                    self.resources.allocate(self.request(dict(self.intent,**updates)),expected_caller=self.caller)
        self.assertEqual(self.local.db.execute('SELECT count(*) FROM open_repair_copy_resources').fetchone()[0],0)

    def test_failed_offer_storage_rolls_back_shared_capacity(self):
        before=self.local.state.capacity.usage()
        self.local.db.execute("CREATE TRIGGER synthetic_copy_failure BEFORE INSERT ON open_repair_copy_resources BEGIN SELECT RAISE(ABORT,'synthetic copy failure'); END")
        self.local.db.commit()
        with self.assertRaisesRegex(Exception,'synthetic copy failure'):
            self.resources.allocate(self.request(),expected_caller=self.caller)
        self.assertEqual(self.local.state.capacity.usage(),before)

    def test_missing_shared_ledger_is_not_recreated_by_retry(self):
        entry=self.request();self.resources.allocate(entry,expected_caller=self.caller)
        self.local.db.execute("DELETE FROM open_capacity_reservations WHERE service='repair_copy'");self.local.db.commit()
        with self.assertRaisesRegex(wire.RepairWireError,'repair_copy_ledger_missing'):
            self.resources.allocate(entry,expected_caller=self.caller)
        self.assertEqual(self.local.db.execute("SELECT count(*) FROM open_capacity_reservations WHERE service='repair_copy'").fetchone()[0],0)


    def test_other_service_reservations_reduce_copy_capacity(self):
        usage=self.local.state.capacity.usage()
        with self.local.state._transaction():
            self.local.state.capacity.reserve('ack','synthetic_existing','a'*64,
                usage['maximum_reserved_bytes']-usage['reserved_bytes']-1,2_000_000_100,
                owner='synthetic_owner',operation_id='synthetic_existing')
        before=self.local.state.capacity.usage()
        with self.assertRaisesRegex(Exception,'open_capacity_exhausted'):
            self.resources.allocate(self.request(),expected_caller=self.caller)
        self.assertEqual(self.local.state.capacity.usage(),before)
        self.assertEqual(self.local.db.execute('SELECT count(*) FROM open_repair_copy_resources').fetchone()[0],0)


    def test_changed_signed_request_cannot_reserve_capacity(self):
        entry=self.request();body=json.loads(entry['raw']);body['payload']['request_id']='forged_request'
        raw=canonical_bytes(body);digest=hashlib.sha256(raw).hexdigest()
        forged=dict(raw=raw,ref=dict(namespace='meta',key=digest,raw_sha256=digest,size=len(raw)))
        before=self.local.state.capacity.usage()
        with self.assertRaises(wire.RepairWireError):self.resources.allocate(forged,expected_caller=self.caller)
        self.assertEqual(self.local.state.capacity.usage(),before)
        self.assertEqual(self.local.db.execute('SELECT count(*) FROM open_repair_copy_resources').fetchone()[0],0)

    def test_unknown_scope_kind_is_a_protocol_failure(self):
        for kind in ([],{},None,'mailbox_member'):
            intent=copy.deepcopy(self.intent);intent['scope']['kind']=kind
            with self.subTest(kind=kind):
                with self.assertRaises(wire.RepairWireError):
                    self.resources.allocate(self.request(intent),expected_caller=self.caller)
