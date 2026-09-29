"""Finite synthetic remote setup, genuine stages and interrupted exact retries."""
import copy
import hashlib
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
import unittest

from memory_vault import canonical_bytes
from memory_vault_open_repair_bind import encode_entry, decode_entry
from memory_vault_open_repair_remote_setup import RepairRemoteSetupService, SCHEMA, _ref
from memory_vault_open_repair_state import DEFAULT_POLICY, RECEIPT_WORKFLOW_LIMITS as DEFAULT_LIMITS
from memory_vault_open_repair_state import RepairAckState
import memory_vault_open_repair_wire as wire
from tests import test_open_repair_state as local_fixture
from tests.open_repair_ack_fixtures import signed_entry


class RemoteSetupTests(unittest.TestCase):
    def setUp(self):
        self.local=local_fixture.RepairStateTests(); self.local.setUp(); self.addCleanup(self.local.tearDown)
        self.f=self.local.fixture
        self.f['docs']['bootstrap']['payload']['limits']=dict(DEFAULT_LIMITS)
        self.local.state.limits=dict(DEFAULT_LIMITS)
        for item in self.f['docs'].values():
            payload=item['payload']
            for caps in ([payload['budget']] if 'budget' in payload else [])+([payload['intent']['budget']] if 'intent' in payload else []):
                caps['max_pending']=8; caps['max_replay_records']=128; caps['max_requests']=2048
                caps['max_meta_bytes']=1048576; caps['max_job_bytes']=1048576
        allocation=self.f['docs']['allocate']['payload']
        allocation['intent_sha256']=hashlib.sha256(canonical_bytes(allocation['intent'])).hexdigest()
        self.f['entries']['allocate']=signed_entry(allocation,self.f['signers']['owner'],'allocate')
        self.local.now[0]=2_000_000_001
        self.connect()

    def connect(self):
        self.service=RepairRemoteSetupService(self.local.state,policy=dict(enabled=True))
        self.service.initialize()

    def encode(self,entry):
        return encode_entry(entry,self.local.state.policy,wire.RepairBudget(self.local.state.policy))

    def allocation(self):
        return canonical_bytes(dict(schema_version=SCHEMA,kind='ack.source_allocate',
            allocation=self.encode(self.f['entries']['allocate']),owner=self.f['expected']['expected_owner']))

    def allocate(self):
        response=json.loads(self.service.handle(self.allocation()))
        offer=decode_entry(response['offer'],self.local.state.policy,wire.RepairBudget(self.local.state.policy))
        self.f['entries']['offer']=offer; self.f['docs']['offer']=json.loads(offer['raw'])
        self.local.resource_id=self.f['docs']['offer']['payload']['resource']['resource_id']
        return response

    def setup_request(self, *, revoked=False):
        self.local.now[0]=2_000_000_006
        self.local.owner_setup()
        slot=self.f['expected']['expected_ack_slot']; root=slot['root_key']
        scopes=[dict(kind='authority',root_key=root,authority_kind=kind,
            authority_sha256=self.f['entries'][name]['ref']['raw_sha256']) for name,kind in
            (('root','ack.root_authority'),('read','ack.read_grant'),('bootstrap','bootstrap.grant'))]
        scopes.append(dict(kind='ack_slot',root_key=root,ack_slot=slot))
        payload=copy.deepcopy(self.f['docs']['owner_status']['payload'])
        payload['entries']=sorted([dict(scope_kind=v['kind'],scope_id=hashlib.sha256(canonical_bytes(v)).hexdigest(),
            minimum_document_revision=0,status='revoked' if revoked else 'active',operation_mask=127)
            for v in scopes],key=lambda v:(v['scope_kind'],v['scope_id']))
        self.f['entries']['owner_status']=signed_entry(payload,self.f['signers']['owner'],'owner_status')
        fields=dict(schema_version=SCHEMA,kind='ack.source_setup',signing_key=self.f['expected']['expected_owner']['signing_key'],
            issued_at=self.local.now[0],expires_at=self.local.now[0]+60,request_id='remote_setup_synthetic',
            subject=self.f['expected']['expected_owner'],target=self.f['expected']['expected_target'],
            target_storage_epoch=self.f['expected']['target_storage_epoch'],allocation_ref=self.f['entries']['allocate']['ref'],
            offer_ref=self.f['entries']['offer']['ref'],ack_slot=slot,read_until=2_000_000_800,retain_until=2_000_000_950,
            **{name:self.encode(self.f['entries']['descriptor' if name=='node' else name])
                for name in ('node','root','read','bootstrap','activation','owner_status')})
        return canonical_bytes(dict(payload=fields,proof=self.f['signers']['owner'].sign_message(fields)))

    def restart(self):
        self.local.db.close(); self.local.connect(); self.local.state.limits=dict(DEFAULT_LIMITS); self.connect()

    def test_real_unbound_exact_retry_restart_and_shared_budget(self):
        allocate=self.allocate(); request=self.setup_request()
        first=self.service.handle(request)
        result=json.loads(first)
        self.assertEqual(result['kind'],'ack.source_ready')
        self.assertEqual(result['request_ref'],_ref(request))
        row=self.local.state._row(self.local.resource_id)
        self.assertEqual(row['status'],'unbound')
        self.assertGreater(self.local.db.execute('SELECT count(*) FROM open_repair_ack_pins').fetchone()[0],0)
        usage=self.local.db.execute('SELECT requests,signatures,proof_bytes FROM open_repair_bootstrap_usage').fetchone()
        self.assertEqual(usage[0],2); self.assertGreater(usage[1],15); self.assertLess(usage[1],64)
        self.restart()
        self.assertEqual(self.service.handle(request),first)
        self.assertEqual(json.loads(self.service.handle(self.allocation())),allocate)
        current=self.local.db.execute('SELECT requests,signatures,proof_bytes FROM open_repair_bootstrap_usage').fetchone()
        self.assertTrue(all(b>a for a,b in zip(usage,current)))
        self.assertEqual(self.local.db.execute('SELECT count(*) FROM open_repair_ack_resources').fetchone()[0],1)

    def split_setup_request(self, *, revoked=False):
        packet=json.loads(self.setup_request());p=packet['payload'];signer=self.f['signers']['owner']
        entry=decode_entry(p['owner_status'],self.local.state.policy,wire.RepairBudget(self.local.state.policy))
        observation=json.loads(entry['raw'])['payload']
        root=p['ack_slot']['root_key']
        scope=hashlib.sha256(canonical_bytes(dict(kind='authority',root_key=root,
            authority_kind='ack.root_authority',authority_sha256=self.f['entries']['root']['ref']['raw_sha256']))).hexdigest()
        root_observation=copy.deepcopy(observation)
        root_observation['revision']=observation['revision']+1
        root_observation['entries']=[dict(v,status='revoked' if revoked else 'active') for v in observation['entries'] if v['scope_id']==scope]
        observation['entries']=[v for v in observation['entries'] if v['scope_id']!=scope]
        self.assertEqual(len(root_observation['entries']),1)
        p['owner_status']=self.encode(signed_entry(observation,signer,'owner_status'))
        p['root_status']=self.encode(signed_entry(root_observation,signer,'root_status'))
        return canonical_bytes(dict(payload=p,proof=signer.sign_message(p)))

    def test_non_object_setup_payload_rejects_without_charging(self):
        for payload in (None, [], 'root_status'):
            with self.subTest(payload=payload):
                with self.assertRaises(wire.RepairWireError):
                    self.service.handle(canonical_bytes(dict(payload=payload,proof={})))
        self.assertEqual(self.local.db.execute('SELECT count(*) FROM open_repair_remote_owners').fetchone()[0],0)

    def test_separate_root_original_survives_real_storage_and_restart(self):
        self.allocate();request=self.split_setup_request()
        first=self.service.handle(request)
        self.assertEqual(json.loads(first)['kind'],'ack.source_ready')
        self.assertEqual(self.local.state._row(self.local.resource_id)['status'],'unbound')
        packet=json.loads(request)['payload']
        entry=decode_entry(packet['root_status'],self.local.state.policy,wire.RepairBudget(self.local.state.policy))
        self.assertIsNotNone(self.local.db.execute('SELECT 1 FROM open_repair_access_documents WHERE raw=?',(entry['raw'],)).fetchone())
        self.restart();self.assertEqual(self.service.handle(request),first)

    def test_separate_root_revocation_is_persistent_before_activation(self):
        self.allocate();request=self.split_setup_request(revoked=True)
        with self.assertRaisesRegex(wire.RepairWireError,'repair_authority_revoked'):self.service.handle(request)
        self.assertEqual(self.local.state._row(self.local.resource_id)['status'],'pending')
        self.restart()
        with self.assertRaisesRegex(wire.RepairWireError,'repair_authority_revoked'):self.service.handle(request)

    def test_active_crash_remains_honest_and_same_finish_recovers(self):
        self.allocate(); request=self.setup_request()
        with patch.object(self.local.state,'finalize_unbound',side_effect=RuntimeError('synthetic interruption')):
            with self.assertRaisesRegex(RuntimeError,'synthetic interruption'):self.service.handle(request)
        row=self.local.state._row(self.local.resource_id)
        self.assertEqual(row['status'],'active'); self.assertIsNone(row['custody'])
        self.assertIsNone(self.local.db.execute("SELECT response FROM open_repair_remote_requests WHERE kind='setup'").fetchone()[0])
        before=self.local.db.execute('SELECT requests,signatures,proof_bytes FROM open_repair_bootstrap_usage').fetchone()
        self.restart()
        result=json.loads(self.service.handle(request))
        self.assertEqual(result['kind'],'ack.source_ready')
        self.assertEqual(self.local.state._row(self.local.resource_id)['status'],'unbound')
        after=self.local.db.execute('SELECT requests,signatures,proof_bytes FROM open_repair_bootstrap_usage').fetchone()
        self.assertTrue(all(b>a for a,b in zip(before,after)))

    def test_current_revocation_is_durable_before_active_and_cannot_reset_request(self):
        self.allocate(); request=self.setup_request(revoked=True)
        with self.assertRaisesRegex(wire.RepairWireError,'repair_authority_revoked'):self.service.handle(request)
        self.assertEqual(self.local.state._row(self.local.resource_id)['status'],'pending')
        self.assertGreater(self.local.db.execute('SELECT count(*) FROM open_repair_access_floors WHERE revoked_mask<>0').fetchone()[0],0)
        self.restart()
        with self.assertRaisesRegex(wire.RepairWireError,'repair_authority_revoked'):self.service.handle(request)
        replacement=self.setup_request()
        with self.assertRaisesRegex(wire.RepairWireError,'repair_remote_setup_conflict'):self.service.handle(replacement)

    def test_opt_in_closed_and_wrong_owner_cannot_charge(self):
        raw=self.allocation()
        closed=RepairRemoteSetupService(self.local.state)
        with self.assertRaisesRegex(wire.RepairWireError,'repair_remote_setup_closed'):closed.handle(raw)
        packet=json.loads(raw); packet['owner']=self.f['expected']['expected_target']
        with self.assertRaises(wire.RepairWireError):self.service.handle(canonical_bytes(packet))
        self.assertEqual(self.local.db.execute('SELECT count(*) FROM open_repair_remote_owners').fetchone()[0],0)

    def test_expired_setup_does_not_resign_or_claim_ready(self):
        self.allocate(); request=self.setup_request(); first=self.service.handle(request)
        self.local.now[0]+=61
        with self.assertRaisesRegex(wire.RepairWireError,'repair_remote_setup_reconciliation_required'):self.service.handle(request)
        self.assertEqual(self.local.db.execute("SELECT response FROM open_repair_remote_requests WHERE kind='setup'").fetchone()[0],first)

    def test_unsettled_allocation_crash_transfers_its_full_allowance_after_restart(self):
        # The actual allocation commits, then the process loses its remaining
        # opportunity to attach or settle work. No fabricated resource row.
        with patch.object(self.service,'_attach',side_effect=RuntimeError('synthetic crash')),patch.object(self.service,'_settle',return_value=None):
            with self.assertRaisesRegex(RuntimeError,'synthetic crash'):self.service.handle(self.allocation())
        pending=self.local.db.execute('SELECT attempt_id,signature_allowance,signature_checks FROM open_repair_remote_attempts').fetchone()
        self.assertEqual(pending[1:],(64,None))
        self.assertEqual(self.local.db.execute('SELECT count(*) FROM open_repair_ack_resources').fetchone()[0],1)
        self.restart(); self.allocate()
        kept=self.local.db.execute('SELECT signature_allowance,signature_checks FROM open_repair_bootstrap_work WHERE attempt_id=?',(pending[0],)).fetchone()
        self.assertEqual(kept,(64,None))
        self.assertEqual(self.local.db.execute('SELECT requests FROM open_repair_bootstrap_usage').fetchone()[0],2)
        self.assertEqual(self.local.db.execute('SELECT count(*) FROM open_repair_ack_resources').fetchone()[0],1)

    def test_two_connections_exact_allocation_and_finish_share_one_resource_and_work(self):
        self.allocate(); request=self.setup_request()
        def run():
            db=sqlite3.connect(self.local.path,timeout=10)
            try:
                state=RepairAckState(db,self.f['signers']['target'],self.f['docs']['descriptor'],
                    encryption_identity=self.f['encryption']['target'],limit_policy=DEFAULT_LIMITS,
                    clock=lambda:self.local.now[0])
                service=RepairRemoteSetupService(state,policy=dict(enabled=True));service.initialize()
                return service.handle(request)
            finally:db.close()
        with ThreadPoolExecutor(max_workers=2) as pool:
            left,right=list(pool.map(lambda _:run(),range(2)))
        self.assertEqual(left,right)
        self.assertEqual(self.local.db.execute('SELECT count(*) FROM open_repair_ack_resources').fetchone()[0],1)
        self.assertEqual(self.local.db.execute('SELECT requests FROM open_repair_bootstrap_usage').fetchone()[0],3)
        self.assertEqual(self.local.db.execute('SELECT count(*) FROM open_repair_bootstrap_work WHERE signature_checks IS NULL').fetchone()[0],0)

    def test_expiry_inside_activation_writer_rolls_back_active_but_keeps_observations(self):
        self.allocate(); request=self.setup_request()
        sign=self.local.state._sign
        def expire(payload,name,budget):
            result=sign(payload,name,budget)
            if name=='resource-status':self.local.now[0]+=61
            return result
        with patch.object(self.local.state,'_sign',side_effect=expire):
            with self.assertRaisesRegex(wire.RepairWireError,'repair_remote_setup_reconciliation_required'):
                self.service.handle(request)
        row=self.local.state._row(self.local.resource_id)
        self.assertEqual(row['status'],'pending');self.assertIsNone(row['active'])
        self.assertGreater(self.local.db.execute('SELECT count(*) FROM open_repair_access_documents').fetchone()[0],0)
        self.assertIsNone(self.local.db.execute("SELECT response FROM open_repair_remote_requests WHERE kind='setup'").fetchone()[0])

    def test_remote_policy_and_actual_journal_reservation_do_not_silently_change(self):
        with self.assertRaisesRegex(wire.RepairWireError,'repair_remote_policy_mismatch'):
            RepairRemoteSetupService(self.local.state,policy=dict(enabled=True,max_journal_bytes=1024)).initialize()
        self.allocate()
        self.local.db.execute("DELETE FROM open_capacity_reservations WHERE reservation_id LIKE 'setup_%'");self.local.db.commit()
        with self.assertRaisesRegex(wire.RepairWireError,'repair_remote_setup_corrupt'):
            self.service.handle(self.allocation())


if __name__=='__main__':unittest.main()


class MailboxDraftTransportTests(unittest.TestCase):
    def encode(self, raw, **kwargs):
        from memory_vault_open_repair_bind import encode_mailbox_draft
        return encode_mailbox_draft(raw, DEFAULT_POLICY, wire.RepairBudget(DEFAULT_POLICY), **kwargs)

    def decode(self, value):
        from memory_vault_open_repair_bind import decode_mailbox_draft
        # Use the actual parsed immutable wire objects, as the HTTP service does.
        policy=DEFAULT_POLICY;budget=wire.RepairBudget(policy)
        return decode_mailbox_draft(wire.parse_new_wire(canonical_bytes(value),policy,budget).value,policy,budget)

    def test_exact_bytes_compact_and_legacy(self):
        raw=canonical_bytes({'synthetic': ['original signature bytes']*1000})
        for compact in (False,True):
            with self.subTest(compact=compact):
                encoded=self.encode(raw,compact=compact)
                self.assertEqual(self.decode(encoded)['raw'],raw)
                if compact:self.assertLess(len(canonical_bytes(encoded)),65536)

    def test_rejects_expansion_truncation_trailing_and_changed_hash(self):
        import base64,zlib
        raw=b'x'*131072
        encoded=self.encode(raw,compact=True)
        self.assertEqual(self.decode(encoded)['raw'],raw)
        variants=[]
        short=copy.deepcopy(encoded);short['ref']['size']=32;variants.append(short)
        large=copy.deepcopy(encoded);large['ref']['size']=131073;variants.append(large)
        altered=copy.deepcopy(encoded);altered['ref']['raw_sha256']='0'*64;variants.append(altered)
        for data in (zlib.compress(raw)[:-1],zlib.compress(raw)+b'trailing',zlib.compress(raw)+zlib.compress(b'other'),b'not zlib'):
            item=copy.deepcopy(encoded);item['compressed_size']=len(data)
            item['raw_base64url']=base64.urlsafe_b64encode(data).decode().rstrip('=');variants.append(item)
        for item in variants:
            with self.subTest(item_size=item['ref']['size'],compressed=item['compressed_size']):
                with self.assertRaises(wire.RepairWireError):self.decode(item)
