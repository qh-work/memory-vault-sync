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


class RemoteCopyAllocationTests(unittest.TestCase):
    def setUp(self):
        from memory_vault_open_repair_copy_resources import RepairRemoteCopyAllocation
        self.h=CopyReservationTests();self.h.setUp();self.addCleanup(self.h.doCleanups)
        self.h.local.now[0]=2_000_000_010
        self.policy=dict(enabled=True,max_requests=2,max_caller_resources=1)
        self.service=RepairRemoteCopyAllocation(self.h.local.state,policy=self.policy);self.service.initialize()

    def carrier(self,entry=None):
        from memory_vault_open_repair_index_state import encode_entry
        return canonical_bytes(dict(schema_version='memory-vault-open-repair/v1',kind='ack.copy_allocate',
            caller=self.h.caller,allocation=encode_entry(entry or self.h.request())))

    def test_remote_offer_uses_real_capacity_and_charges_exact_retry_after_restart(self):
        from memory_vault_open_repair_copy_resources import RepairRemoteCopyAllocation
        from memory_vault_open_repair_index_state import decode_entry
        before=self.h.local.state.capacity.usage();raw=self.carrier()
        first=self.service.handle(raw)
        self.assertGreater(self.h.local.state.capacity.usage()['reserved_bytes'],before['reserved_bytes'])
        result=json.loads(first);self.assertEqual(result['kind'],'ack.copy_allocation')
        budget=wire.RepairBudget(self.h.local.state.policy)
        offer=decode_entry(result['offer'],budget.policy,budget)
        self.assertEqual(json.loads(offer['raw'])['payload']['allocation_request_ref'],self.h.request()['ref'])
        self.h.local.db.close();self.h.local.connect()
        self.service=RepairRemoteCopyAllocation(self.h.local.state,policy=self.policy);self.service.initialize()
        self.assertEqual(self.service.handle(raw),first)
        with self.assertRaisesRegex(wire.RepairWireError,'repair_copy_work_capacity'):self.service.handle(raw)
        self.assertEqual(self.h.local.db.execute('SELECT requests FROM open_repair_copy_work').fetchone()[0],2)
        self.assertEqual(self.h.local.db.execute('SELECT count(*) FROM open_repair_copy_resources').fetchone()[0],1)

    def test_disabled_remote_policy_refuses_before_reservation(self):
        from memory_vault_open_repair_copy_resources import RepairRemoteCopyAllocation
        service=RepairRemoteCopyAllocation(self.h.local.state)
        with self.assertRaisesRegex(wire.RepairWireError,'repair_remote_copy_closed'):service.handle(self.carrier())
        self.assertEqual(self.h.local.db.execute('SELECT count(*) FROM open_repair_copy_resources').fetchone()[0],0)

    def test_invalid_signature_does_not_create_caller_or_reserve_capacity(self):
        from memory_vault_open_repair_index_state import encode_entry
        entry=self.h.request();body=json.loads(entry['raw']);body['payload']['request_id']='synthetic_forgery'
        raw=canonical_bytes(body);digest=hashlib.sha256(raw).hexdigest()
        entry=dict(raw=raw,ref=dict(namespace='meta',key=digest,raw_sha256=digest,size=len(raw)))
        before=self.h.local.state.capacity.usage()
        with self.assertRaises(wire.RepairWireError):self.service.handle(self.carrier(entry))
        self.assertEqual(self.h.local.state.capacity.usage(),before)
        self.assertEqual(self.h.local.db.execute('SELECT count(*) FROM open_repair_copy_remote_callers').fetchone()[0],0)

    def test_resource_ceiling_refuses_new_offer_but_keeps_attempt_charge(self):
        self.service.handle(self.carrier())
        other=dict(self.h.intent,allocation_id='synthetic_second',job_id='synthetic_second')
        before=self.h.local.state.capacity.usage()
        with self.assertRaisesRegex(wire.RepairWireError,'repair_copy_capacity'):self.service.handle(self.carrier(self.h.request(other)))
        self.assertEqual(self.h.local.state.capacity.usage(),before)
        self.assertEqual(self.h.local.db.execute('SELECT count(*) FROM open_repair_copy_remote_work').fetchone()[0],2)

    def test_missing_admission_ledger_is_not_recreated(self):
        raw=self.carrier();self.service.handle(raw)
        self.h.local.db.execute("DELETE FROM open_capacity_reservations WHERE operation_id='remote_copy'");self.h.local.db.commit()
        with self.assertRaisesRegex(wire.RepairWireError,'repair_copy_ledger_missing'):self.service.handle(raw)

    def test_expired_request_cannot_renew_remote_reservation(self):
        raw=self.carrier();self.service.handle(raw);self.h.local.now[0]+=61
        with self.assertRaisesRegex(wire.RepairWireError,'repair_copy_allocation_mismatch'):self.service.handle(raw)

    def test_allocation_over_real_http_survives_node_restart(self):
        import threading,time
        from pathlib import Path
        from unittest.mock import patch
        from memory_vault_open_control import issue_node
        from memory_vault_open_node import OpenParticipant,OpenHTTPServer
        from memory_vault_open_transport import OpenHTTPTransport
        from memory_vault import MemoryError
        h=self.h;state=h.local.state
        clock=patch('time.time',return_value=h.local.now[0]);clock.start();self.addCleanup(clock.stop)
        directory=Path(h.local.temp.name)
        for name in ('network.sqlite3','network.sqlite3-wal','network.sqlite3-shm'):
            path=directory/name
            if path.exists():path.chmod(0o600)
        with patch('socket.getfqdn',return_value='localhost'):server=OpenHTTPServer(('127.0.0.1',0),None)
        base='http://127.0.0.1:'+str(server.server_port)
        descriptor=issue_node(state.identity,base_url=base,storage_epoch=state.node['payload']['storage_epoch'],
            roles=['directory','router'],revision=2,issued_at=h.local.now[0],expires_at=h.local.now[0]+300)
        transport=OpenHTTPTransport(allow_loopback=True);self.addCleanup(transport.close)
        first=None
        for attempt in range(2):
            participant=OpenParticipant(state.identity,directory,seeds=[],descriptor=descriptor,
                encryption_identity=state.encryption_identity,allow_loopback=True,
                repair_policy=dict(enabled=True,remote_copy=self.policy,limit_policy=h.f['expected']['limit_policy']))
            if attempt:
                with patch('socket.getfqdn',return_value='localhost'):server=OpenHTTPServer(address,participant)
            else:server.participant=participant
            address=server.server_address
            thread=threading.Thread(target=server.serve_forever,kwargs=dict(poll_interval=.02),daemon=True);thread.start()
            try:
                result=transport.request_repair(base,self.carrier(),deadline=time.monotonic()+10)
                if first is None:first=result
                else:self.assertEqual(first,result)
            finally:
                server.shutdown();server.server_close();thread.join(3);participant.close()
        self.assertEqual(h.local.db.execute('SELECT count(*) FROM open_repair_copy_resources').fetchone()[0],1)


class RemoteCopyClientHTTPTests(unittest.TestCase):
    def setUp(self):
        import threading
        from pathlib import Path
        from unittest.mock import patch
        from memory_vault_open_control import issue_node
        from memory_vault_open_node import OpenHTTPServer
        from memory_vault_open_transport import OpenHTTPTransport
        from tests.test_open_repair_copy_prepare import CopyPreparationTests
        self.h=CopyPreparationTests();self.addCleanup(self.h.doCleanups);self.h.setUp()
        clock=patch('time.time',return_value=self.h.now);clock.start();self.addCleanup(clock.stop)
        with patch('socket.getfqdn',return_value='localhost'):self.server=OpenHTTPServer(('127.0.0.1',0),None)
        self.directory=Path(self.h.destination.temp.name);state=self.h.destination.state
        for name in ('network.sqlite3','network.sqlite3-wal','network.sqlite3-shm'):
            path=self.directory/name
            if path.exists():path.chmod(0o600)
        self.base='http://127.0.0.1:'+str(self.server.server_port)
        self.descriptor=issue_node(state.identity,base_url=self.base,storage_epoch=state.node['payload']['storage_epoch'],
            roles=['directory','router'],revision=2,issued_at=self.h.now-1,expires_at=self.h.now+300)
        self.start();self.addCleanup(self.stop)
        self.transport=OpenHTTPTransport(allow_loopback=True);self.addCleanup(self.transport.close)

    def start(self):
        import threading
        from memory_vault_open_node import OpenParticipant
        state=self.h.destination.state
        self.participant=OpenParticipant(state.identity,self.directory,seeds=[],descriptor=self.descriptor,
            encryption_identity=state.encryption_identity,allow_loopback=True,provider_policy=dict(enabled=True),
            repair_policy=dict(enabled=True,remote_copy=dict(enabled=True),limit_policy=self.h.f['expected']['limit_policy']))
        self.server.participant=self.participant
        self.thread=threading.Thread(target=self.server.serve_forever,kwargs=dict(poll_interval=.02),daemon=True);self.thread.start()

    def stop(self):
        self.server.shutdown();self.server.server_close();self.thread.join(3);self.participant.close()

    def restart(self):
        from unittest.mock import patch
        from memory_vault_open_node import OpenHTTPServer
        address=self.server.server_address;self.stop()
        with patch('socket.getfqdn',return_value='localhost'):self.server=OpenHTTPServer(address,None)
        self.start()

    def reserve(self,transport=None):
        from memory_vault_open_repair_copy_client import AckCopyUploadClient
        from tests.open_repair_ack_fixtures import load_fixture
        h=self.h;client=AckCopyUploadClient(h.journal,encryption_identity=h.f['encryption']['maintainer'],transport=transport,allow_loopback=True)
        self.addCleanup(client.close)
        resolver,_,_=load_fixture(h.f,h.p)
        raw=canonical_bytes(self.descriptor);digest=hashlib.sha256(raw).hexdigest()
        node=dict(raw=raw,ref=dict(namespace='meta',key=digest,raw_sha256=digest,size=len(raw)))
        return client.reserve(self.base,h.f['manifest'],resolver,h.f['custody'],h.consent,h.intent,target_node_entry=node,
            expected_ack_slot=h.f['expected']['expected_ack_slot'],expected_owner=h.f['expected']['expected_owner'],
            expected_source=h.f['expected']['expected_target'],source_storage_epoch=h.f['expected']['target_storage_epoch'],
            current_statuses=[signed_entry(h.owner_status,h.f['signers']['owner'],'copy_current'),h.f['entries']['target_status']],
            limit_policy=h.f['expected']['limit_policy'])

    def test_client_reserves_real_capacity_then_creates_original_assignment(self):
        before=self.h.destination.state.capacity.usage()
        result=self.reserve();self.assertEqual(result['state'],'capacity_reserved')
        self.assertGreater(self.h.destination.state.capacity.usage()['reserved_bytes'],before['reserved_bytes'])
        assignment=self.h.prepare(offer=result['offer'])
        payload=json.loads(assignment['raw'])['payload']
        self.assertEqual(payload['resource_offer_ref'],result['offer']['ref'])
        self.assertEqual(payload['resource'],json.loads(result['offer']['raw'])['payload']['resource'])
        self.assertEqual(self.h.destination.db.execute('SELECT count(*) FROM open_repair_copy_commits').fetchone()[0],0)

    def test_client_lost_allocation_reply_replays_exact_request_after_both_restarts(self):
        from memory_vault import MemoryError
        host=self
        class LostReply:
            def __init__(self):self.calls=[]
            def request(self,*args,**kwargs):return host.transport.request(*args,**kwargs)
            def request_repair(self,base,raw,**kwargs):
                self.calls.append(raw);result=host.transport.request_repair(base,raw,**kwargs)
                if len(self.calls)==1:raise MemoryError('open_network_unavailable')
                return result
        transport=LostReply()
        with self.assertRaisesRegex(MemoryError,'open_network_unavailable'):self.reserve(transport)
        self.restart();self.h.local.db.close();self.h.local.connect();self.h.open_journal()
        result=self.reserve(transport)
        self.assertEqual(result['state'],'capacity_reserved');self.assertEqual(transport.calls[0],transport.calls[1])
        self.assertEqual(self.h.destination.db.execute('SELECT count(*) FROM open_repair_copy_resources').fetchone()[0],1)
