"""Actual persistent directory reservations and bounded original-frame admission."""
import copy
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from memory_vault import canonical_bytes
from memory_vault_open_control import issue_node
import memory_vault_open_repair_stage as stage
import memory_vault_open_repair_wire as wire
from memory_vault_open_repair_index_state import RepairIndexState
from tests.open_repair_ack_fixtures import reference, signed_entry
from tests.open_repair_index_fixtures import IndexFixture
from tests import test_open_repair_state as source_tests


class DirectoryFixture:
    def __init__(self, case, *, publication=None, directory_path=None):
        original_allocate = source_tests.RepairStateTests.allocate
        def allocate(instance):
            # A freshly signed source can fund the complete multi-frame
            # publication; never enlarge an existing reservation afterward.
            f = instance.fixture
            payload = copy.deepcopy(f['docs']['allocate']['payload'])
            limits=f['expected']['limit_policy']
            caps = dict(payload['intent']['budget'],max_meta_bytes=max(2097152,limits['max_proof_bytes']),
                max_job_bytes=max(payload['intent']['budget']['max_job_bytes'],limits['max_proof_bytes']),
                max_requests=max(payload['intent']['budget']['max_requests'],limits['max_signature_checks']))
            payload['intent']['budget'] = caps
            payload['intent_sha256'] = hashlib.sha256(canonical_bytes(payload['intent'])).hexdigest()
            f['entries']['allocate'] = signed_entry(payload,f['signers']['owner'],'large-source-allocate')
            f['docs']['allocate'] = json.loads(f['entries']['allocate']['raw'])
            for name in ('root','read'):
                f['docs'][name]['payload']['budget'] = copy.deepcopy(caps)
            return original_allocate(instance)
        if publication is None:
            with patch.object(source_tests.RepairStateTests,'allocate',allocate):
                self.f = IndexFixture(index_max_meta_bytes=2097152)
            case.addCleanup(self.f.close)
        else:
            self.f = publication
        if directory_path is None:
            self.temp = tempfile.TemporaryDirectory(prefix='memory-vault-synthetic-index-')
            case.addCleanup(self.temp.cleanup)
            self.path = Path(self.temp.name)/'directory.sqlite3'
        else:
            self.path = directory_path
        f = self.f
        self.now = [f.at]
        self.node = issue_node(f.directory,base_url='http://127.0.0.1:19099',storage_epoch=f.epoch,
            roles=['directory','router'],revision=1,issued_at=f.at-1,expires_at=f.at+600)
        self.connect()
        case.addCleanup(lambda:self.db.close())
        self.allocation = self.state.allocate(f.allocation,expected_owner=f.f['expected']['expected_owner'],
            expected_receipt_writer=f.case.case.expected['expected_receipt_writer'])
        self.assignment = json.loads(f.assignment['raw'])['payload']
        offer = json.loads(self.allocation['offer']['raw'])['payload']
        self.assignment.update(issued_at=f.at,resource_offer_ref=self.allocation['offer']['ref'],resource=offer['resource'])
        self.assignment = signed_entry(self.assignment,f.f['signers']['target'],'real-index-assignment')
        assignment_scope = dict(scope_kind='assignment',scope_id=hashlib.sha256(canonical_bytes(dict(kind='assignment',root_key=f.root,
            assignment_kind='maintenance.assignment',assignment_sha256=self.assignment['ref']['raw_sha256']))).hexdigest())
        self.assignment_status = f.status(f.f['signers']['target'],[assignment_scope],getattr(f,'assignment_revision',3),'real-assignment-status',minimum=0)
        pairs = [('index.assignment',self.assignment),('index.owner_consent',f.consents['owner']),('index.recipient_consent',f.consents['writer']),
            ('index.provider_fact',f.fact),('index.source_head',f.result['head']),('index.source_manifest',f.result['manifest']),
            ('index.source_commit',f.result['commit']),('directory.status',self.assignment_status)]
        node_raw = canonical_bytes(f.f['docs']['descriptor'])
        pairs.append(('provider.node',dict(raw=node_raw,ref=reference(node_raw,'provider-node'))))
        pairs.extend(('current.status',item) for item in f.current)
        for ns,key,digest,size,raw in f.h.db.execute('''SELECT o.namespace,o.opaque_key,o.raw_sha256,o.size,o.raw FROM open_repair_ack_objects o JOIN open_repair_ack_pins p
            ON p.namespace=o.namespace AND p.opaque_key=o.opaque_key WHERE p.resource_id=? AND p.role IN ('pack','empty:pack','occupied:pack')''',(f.h.resource_id,)):
            pairs.append(('history.raw_pack',dict(raw=bytes(raw),ref=dict(namespace=ns,key=key,raw_sha256=digest,size=size))))
        self.children = sorted(pairs,key=lambda p:(p[0],p[1]['ref']['namespace'],p[1]['ref']['key'],p[1]['ref']['raw_sha256'],p[1]['ref']['size']))
        budget = wire.RepairBudget(f.policy)
        manifest = stage.make_stage_manifest(root_key=f.root,scope=f.scope,children=[dict(index=i,role=role,ref=e['ref'])
            for i,(role,e) in enumerate(self.children)],policy=f.policy,budget=budget)
        self.intent = stage.make_stage_intent(f.f['signers']['target'],allocation_id=f.intent['allocation_id'],manifest=manifest.value,
            expires_at=f.at+60,**self.expected())
        self.request = None

    def connect(self):
        self.db = sqlite3.connect(self.path)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.state = RepairIndexState(self.db,self.f.directory,self.node,encryption_identity=self.f.directory_encryption,
            limit_policy=self.f.f['expected']['limit_policy'],clock=lambda:self.now[0])
        self.state.initialize()

    def restart(self):
        self.db.close();self.connect()

    def expected(self):
        f=self.f
        return dict(expected_subject=f.publisher,expected_target=f.directory_keys,target_storage_epoch=f.epoch,
            at=self.now[0],policy=f.policy,budget=wire.RepairBudget(f.policy))

    @staticmethod
    def entry(item):
        return dict(raw=item.raw,ref=item.ref.as_dict())

    def begin(self):
        f=self.f
        self.challenge = self.state.stage_intent(self.entry(self.intent))
        self.answer = stage.solve_stage_challenge(self.entry(self.intent),self.challenge,signer=f.f['signers']['target'],
            encryption_identity=f.f['encryption']['target'],expires_at=f.at+60,**self.expected())
        self.handle = self.state.stage_answer(self.entry(self.answer))

    def frames(self):
        for i,(_,entry) in enumerate(self.children):
            for offset in range(0,len(entry['raw']),stage.STAGE_CHUNK_BYTES):
                yield stage.make_stage_child_frame(self.entry(self.intent),self.handle,signer=self.f.f['signers']['target'],
                    child_index=i,offset=offset,chunk=entry['raw'][offset:offset+stage.STAGE_CHUNK_BYTES],expires_at=self.f.at+60,**self.expected())

    def finish(self):
        self.close = stage.make_stage_close(self.entry(self.intent),self.handle,signer=self.f.f['signers']['target'],
            expires_at=self.f.at+60,**self.expected())
        self.result = self.state.stage_close(self.entry(self.close))
        payload = json.loads(self.f.request['raw'])['payload']
        payload.update(issued_at=self.f.at,resource_offer_ref=self.allocation['offer']['ref'],assignment_ref=self.assignment['ref'],stage_result_ref=self.result['ref'])
        self.request = signed_entry(payload,self.f.f['signers']['target'],'real-index-publication')

    def stage(self):
        self.begin()
        for frame in self.frames():
            response = self.state.stage_child(frame)
            stage.verify_stage_child_response_frame(response,frame,self.entry(self.intent),self.handle,**self.expected())
        self.finish()


class RepairIndexStateTests(unittest.TestCase):
    def setUp(self):
        self.case = DirectoryFixture(self)

    def assertCode(self,code,call,*args,**kwargs):
        with self.assertRaises(wire.RepairWireError) as caught:
            call(*args,**kwargs)
        self.assertEqual(caught.exception.code,code)

    def test_real_frames_commit_restart_exact_retry_and_opaque_lookup(self):
        c=self.case;c.stage()
        self.assertEqual(c.state.lookup(c.f.root['anchor_ref']),[])
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        key_type=type(Ed25519PublicKey.from_public_bytes(b'x'*32))
        verify=key_type.verify;calls=[]
        def checked_verify(key,signature,data):
            self.assertFalse(c.db.in_transaction)
            calls.append(1)
            return verify(key,signature,data)
        with patch.object(key_type,'verify',checked_verify):
            lease=c.state.accept(c.request)
        actual=c.db.execute('SELECT actual FROM open_repair_index_work ORDER BY rowid DESC LIMIT 1').fetchone()[0]
        self.assertEqual(actual,len(calls))
        self.assertEqual(lease['payload']['provider_key_id'],c.f.publisher['signing_key']['key_id'])
        self.assertEqual(len(c.state.lookup(c.f.root['anchor_ref'])),1)
        c.restart()
        self.assertEqual(c.state.accept(c.request),lease)
        self.assertEqual(c.db.execute('SELECT count(*) FROM open_repair_index_facts').fetchone()[0],1)
        row=c.db.execute('SELECT actual FROM open_repair_index_work ORDER BY rowid DESC LIMIT 1').fetchone()
        self.assertLessEqual(row[0],64)
        self.assertGreater(row[0],40)

    def test_response_capacity_failure_keeps_authenticated_status_observations(self):
        c=self.case;c.stage()
        with patch.object(c.state,'_output_locked',side_effect=wire.RepairWireError('repair_index_work_capacity')):
            self.assertCode('repair_index_work_capacity',c.state.accept,c.request)
        self.assertEqual(c.db.execute('SELECT count(*) FROM open_repair_index_facts').fetchone()[0],0)
        count=c.db.execute('SELECT count(*) FROM open_repair_index_status_originals').fetchone()[0]
        self.assertGreater(count,0)
        c.restart()
        self.assertEqual(c.db.execute('SELECT count(*) FROM open_repair_index_status_originals').fetchone()[0],count)
        self.assertTrue(c.state.accept(c.request))

    def test_incomplete_close_and_corrupt_frame_do_not_publish_and_work_persists(self):
        c=self.case;c.begin()
        close=stage.make_stage_close(c.entry(c.intent),c.handle,signer=c.f.f['signers']['target'],expires_at=c.f.at+60,**c.expected())
        self.assertCode('repair_stage_incomplete',c.state.stage_close,c.entry(close))
        frame=next(c.frames())
        with self.assertRaises(wire.RepairWireError):
            c.state.stage_child(frame[:-1]+bytes([frame[-1]^1]))
        count=c.db.execute('SELECT count(*) FROM open_repair_index_work').fetchone()[0]
        c.restart()
        self.assertEqual(c.db.execute('SELECT count(*) FROM open_repair_index_work').fetchone()[0],count)
        self.assertEqual(c.state.lookup(c.f.root['anchor_ref']),[])

    def test_new_authenticated_revocation_hides_old_index_after_restart(self):
        c=self.case;c.stage();c.state.accept(c.request)
        f=copy.copy(c.f)
        f.intent=copy.deepcopy(f.intent);f.intent['allocation_id']='second_index_allocation'
        f.intent['job_id']='second_index_job'
        f.intent_digest=hashlib.sha256(canonical_bytes(f.intent)).hexdigest()
        allocation=json.loads(f.allocation['raw'])['payload']
        allocation.update(intent=f.intent,intent_sha256=f.intent_digest,request_id='second_index_allocate')
        f.allocation=signed_entry(allocation,f.f['signers']['target'],'second-allocate')
        f.consents={}
        for role in ('owner','writer'):
            payload=json.loads(c.f.consents[role]['raw'])['payload']
            payload['reservation_disclosure']['intent_sha256']=f.intent_digest
            payload['consent_id'] += '_second'
            f.consents[role]=signed_entry(payload,f.f['signers'][role],'second-consent-'+role)
        f.current=[]
        for old in c.f.current:
            payload=json.loads(old['raw'])['payload'];payload['revision']+=2
            role=next(name for name in ('owner','writer','target') if f.f['signers'][name].key_id==payload['signing_key']['key_id'])
            if role in f.consents:
                oldscope=c.f.authority(c.f.consents[role],'ack.index_consent')
                for item in payload['entries']:
                    if item['scope_id']==oldscope:
                        item['scope_id']=f.authority(f.consents[role],'ack.index_consent')
                    if role=='owner' and item['scope_id']==f.authority(f.f['entries']['root'],'ack.root_authority'):
                        item.update(status='revoked',operation_mask=16)
                payload['entries'].sort(key=lambda item:(item['scope_kind'],item['scope_id']))
            f.current.append(signed_entry(payload,f.f['signers'][role],'second-current-'+role+'-'+str(payload['revision'])))
        f.assignment=copy.deepcopy(f.assignment)
        p=json.loads(f.assignment['raw'])['payload'];p.update(job_id=f.intent['job_id'],resource_intent_sha256=f.intent_digest,assignment_id='second_assignment')
        f.assignment=signed_entry(p,f.f['signers']['target'],'second-assignment')
        f.assignment_revision=5
        p=json.loads(f.request['raw'])['payload'];p.update(request_id='second_publish',allocation_request_ref=f.allocation['ref'],
            owner_consent_ref=f.consents['owner']['ref'],recipient_consent_ref=f.consents['writer']['ref'])
        f.request=signed_entry(p,f.f['signers']['target'],'second-request')
        newer=DirectoryFixture(self,publication=f,directory_path=c.path)
        self.assertEqual(json.loads(newer.allocation['status']['raw'])['payload']['revision'],2)
        newer.stage()
        self.assertCode('repair_authority_revoked',newer.state.accept,newer.request)
        c.restart()
        self.assertEqual(c.state.lookup(c.f.root['anchor_ref']),[])
        self.assertCode('repair_authority_revoked',c.state.accept,c.request)
        rows=c.state.lookup_candidates(c.f.root['anchor_ref'])
        self.assertEqual(len(rows),1);self.assertFalse(rows[0]['eligible'])
        self.assertEqual(c.db.execute('SELECT count(*) FROM open_repair_index_facts').fetchone()[0],1)
