"""Private source preparation, separate identities, durable status sequences."""
import copy
import json
from pathlib import Path
import sqlite3
import unittest
from unittest.mock import patch

from memory_vault import canonical_bytes
import memory_vault_open_repair_index as index
from memory_vault_open_repair_index_prepare import AckIndexPlanPreparer, AckIndexConsentSigner, assemble_publication
from memory_vault_open_repair_wire import RepairWireError
from tests import open_repair_ack_fixtures as fixtures
from tests.test_open_repair_index_state import DirectoryFixture


class AckIndexPreparationTests(unittest.TestCase):
    def setUp(self):
        limits=dict(fixtures.LIMITS,max_probe_bytes=8192,max_signature_checks=4096,max_proof_bytes=4194304,max_requests=128)
        with patch.object(fixtures,'LIMITS',limits):
            self.host=DirectoryFixture(self)
        self.f=self.host.f
        self.f.h.now[0]=self.f.at
        self.preparer=AckIndexPlanPreparer(self.f.h.state)
        self.options=dict(expected_directory=self.f.directory_keys,
            directory_node_entry=dict(raw=canonical_bytes(self.host.node),ref=fixtures.reference(canonical_bytes(self.host.node),'prepare-directory')),
            allocation_id='synthetic_prepared_allocation',job_id='synthetic_prepared_job',
            budget_limits=self.f.intent['budget'],windows=self.f.intent['windows'],current_statuses=self.f.current[:3])
        self.expected=dict(expected_ack_slot=self.f.slot,expected_owner=self.f.f['expected']['expected_owner'],
            expected_source=self.f.publisher,source_storage_epoch=self.f.f['expected']['target_storage_epoch'],
            expected_directory=self.f.directory_keys,directory_storage_epoch=self.f.epoch,
            **{name:self.f.case.case.expected[name] for name in ('expected_receipt_writer','expected_message_id','expected_envelope_ref')})
        self.dbs={}

    def signer(self,role):
        if role not in self.dbs:
            db=sqlite3.connect(Path(self.host.temp.name)/(role+'-signer.sqlite3'))
            self.dbs[role]=db; self.addCleanup(db.close)
        return AckIndexConsentSigner(self.f.f['signers'][role],self.f.f['encryption'][role],self.dbs[role],clock=lambda:self.f.at)

    def test_export_separate_signatures_and_assembled_plan_verify(self):
        bundle=self.preparer.export(self.f.h.resource_id,**self.options)
        self.assertEqual(self.preparer.export(self.f.h.resource_id,**self.options),bundle)
        owner=self.signer('owner').sign(bundle,variant='owner',expected=self.expected,renew_source_status=True)
        writer=self.signer('writer').sign(bundle,variant='receipt_writer',expected=self.expected,renew_source_status=True)
        request=assemble_publication(bundle,owner,writer,expected=self.expected,at=self.f.at)
        from memory_vault_open_repair_admin import _entry
        gate=self.preparer.gate
        prepared=gate.prepare(self.f.h.resource_id,provider_fact_entry=_entry(request['fact']),intent=request['intent'],
            owner_consent_entry=_entry(request['owner_consent']),recipient_consent_entry=_entry(request['recipient_consent']),
            current_statuses=[_entry(item) for item in request['current_statuses']],expected_directory=self.f.directory_keys,directory_storage_epoch=self.f.epoch)
        with self.f.h.state._transaction():
            self.assertTrue(gate.check_locked(prepared).allowed)
        for value in (owner,writer):
            q=_entry(value['consent']); t=json.loads(_entry(value['publication_status'])['raw'])['payload']
            self.assertEqual(len(t['entries']),1)
            self.assertEqual(t['entries'][0]['operation_mask'],16)
            self.assertNotIn(q['ref'],[item['ref'] for item in self.f.current[:3]])
        self.assertIsNone(self.f.h.db.execute('SELECT 1 FROM open_repair_index_execution').fetchone())

    def test_identity_tuple_and_inventory_tamper_cannot_sign(self):
        bundle=self.preparer.export(self.f.h.resource_id,**self.options)
        signer=self.signer('writer')
        with self.assertRaisesRegex(RepairWireError,'repair_index_signer_identity'):
            signer.sign(bundle,variant='owner',expected=self.expected)
        wrong=dict(self.expected,expected_message_id='msg_'+'ff'*32)
        with self.assertRaises(RepairWireError): signer.sign(bundle,variant='receipt_writer',expected=wrong)
        bad=copy.deepcopy(bundle);bad['inventory'].pop()
        with self.assertRaisesRegex(RepairWireError,'repair_index_inventory_mismatch'):
            signer.sign(bad,variant='receipt_writer',expected=self.expected)
        self.assertEqual(self.dbs['writer'].execute('SELECT count(*) FROM open_repair_index_consent_outputs').fetchone()[0],0)

    def test_shared_revision_max_and_exact_retry_preserve_source_whole_status(self):
        bundle=self.preparer.export(self.f.h.resource_id,**self.options)
        signer=self.signer('writer');db=self.dbs['writer']
        import hashlib
        root=hashlib.sha256(canonical_bytes(self.f.root)).hexdigest()
        db.execute("INSERT INTO open_provider_client_meta VALUES(?,?)",('status:'+root,'11'))
        db.execute("INSERT INTO open_provider_state VALUES(?,?)",('status_revision:'+root,'21'))
        db.execute('INSERT INTO open_repair_saved_ack_roots VALUES(?,31)',(root,))
        db.execute('INSERT INTO open_repair_index_issuer_sequence VALUES(?,?,41)',(root,self.f.f['signers']['writer'].key_id));db.commit()
        first=signer.sign(bundle,variant='receipt_writer',expected=self.expected,renew_source_status=True)
        from memory_vault_open_repair_admin import _entry
        source=json.loads(_entry(first['source_statuses'][0])['raw'])['payload']
        qstatus=json.loads(_entry(first['publication_status'])['raw'])['payload']
        self.assertEqual((source['revision'],qstatus['revision']),(42,43))
        self.assertEqual(source['entries'],json.loads(self.f.current[1]['raw'])['payload']['entries'])
        again=self.signer('writer').sign(bundle,variant='receipt_writer',expected=self.expected,renew_source_status=True)
        self.assertEqual(first,again)
        self.assertEqual(db.execute('SELECT revision FROM open_repair_saved_ack_roots WHERE root_digest=?',(root,)).fetchone()[0],43)

    def test_known_revocation_is_retained_before_refusal_and_cannot_be_forgotten(self):
        bundle=self.preparer.export(self.f.h.resource_id,**self.options)
        signer=self.signer('writer')
        revoked=json.loads(self.f.current[1]['raw'])['payload'];revoked['revision']+=20
        for item in revoked['entries']: item.update(status='revoked',operation_mask=64)
        signed=fixtures.signed_entry(revoked,self.f.f['signers']['writer'],'known-publish-revoke')
        with self.assertRaises(RepairWireError):
            signer.sign(bundle,variant='receipt_writer',expected=self.expected,known_statuses=[signed],renew_source_status=True)
        self.assertGreater(self.dbs['writer'].execute('SELECT count(*) FROM open_repair_index_signer_statuses WHERE revision=?',(revoked['revision'],)).fetchone()[0],0)
        with self.assertRaises(RepairWireError):
            self.signer('writer').sign(bundle,variant='receipt_writer',expected=self.expected,renew_source_status=True)
        self.assertEqual(self.dbs['writer'].execute('SELECT count(*) FROM open_repair_index_consent_outputs').fetchone()[0],0)

    def test_known_q_revocation_blocks_cached_consent_after_restart(self):
        bundle=self.preparer.export(self.f.h.resource_id,**self.options)
        signer=self.signer('writer')
        result=signer.sign(bundle,variant='receipt_writer',expected=self.expected)
        from memory_vault_open_repair_admin import _entry
        revoked=json.loads(_entry(result['publication_status'])['raw'])['payload']
        revoked['revision']+=1;revoked['entries'][0]['status']='revoked'
        observation=fixtures.signed_entry(revoked,self.f.f['signers']['writer'],'known-q-revoked')
        with self.assertRaises(RepairWireError):
            signer.sign(bundle,variant='receipt_writer',expected=self.expected,known_statuses=[observation])
        with self.assertRaises(RepairWireError):
            self.signer('writer').sign(bundle,variant='receipt_writer',expected=self.expected)
        self.assertEqual(self.dbs['writer'].execute('SELECT count(*) FROM open_repair_index_consent_outputs').fetchone()[0],1)

    def test_concurrent_new_observation_between_signing_and_commit_refuses_output(self):
        bundle=self.preparer.export(self.f.h.resource_id,**self.options)
        signer=self.signer('writer')
        import memory_vault_open_repair_index_prepare as module
        old=module._signed_entry
        inserted=[]
        def sign(payload,*args):
            result=old(payload,*args)
            if not inserted:
                inserted.append(True)
                db=self.dbs['writer']
                row=db.execute('SELECT * FROM open_repair_index_signer_statuses LIMIT 1').fetchone()
                # A second process has appended an observation since the exact
                # archive snapshot; no unverified new summary may be ignored.
                db.execute('INSERT INTO open_repair_index_signer_statuses VALUES(?,?,?,?,?,?)',(*row[:2],999,*row[3:]));db.commit()
            return result
        with patch.object(module,'_signed_entry',side_effect=sign):
            with self.assertRaisesRegex(RepairWireError,'repair_index_preparation_changed'):
                signer.sign(bundle,variant='receipt_writer',expected=self.expected)
        self.assertIsNone(self.dbs['writer'].execute('SELECT raw FROM open_repair_index_consent_outputs').fetchone()[0])

    def test_same_canonical_known_original_alias_is_not_a_conflict(self):
        bundle=self.preparer.export(self.f.h.resource_id,**self.options)
        old=self.f.current[1]
        raw=json.dumps(json.loads(old['raw']),indent=2).encode()
        alternate=dict(raw=raw,ref=fixtures.reference(raw,'alternate-whole-status'))
        result=self.signer('writer').sign(bundle,variant='receipt_writer',expected=self.expected,known_statuses=[old,alternate])
        self.assertEqual(result['variant'],'receipt_writer')

    def test_legacy_fact_or_unknown_execution_cannot_start_new_publication(self):
        db=self.f.h.db
        db.execute('CREATE TABLE IF NOT EXISTS open_provider_local(category TEXT,reference TEXT,body BLOB,retain_until INTEGER)')
        db.execute('INSERT INTO open_provider_local VALUES(?,?,?,?)',('publish','earlier',canonical_bytes(dict(body=dict(fact=json.loads(self.f.fact['raw'])))),self.f.until));db.commit()
        with self.assertRaisesRegex(RepairWireError,'repair_index_existing_fact'):
            self.preparer.export(self.f.h.resource_id,**self.options)
        self.assertEqual(db.execute('SELECT count(*) FROM open_repair_index_prepare_exports').fetchone()[0],0)

    def test_durable_floor_on_read_scope_cannot_be_lowered_by_explicit_renewal(self):
        bundle=self.preparer.export(self.f.h.resource_id,**self.options)
        signer=self.signer('owner');db=self.dbs['owner']
        import hashlib
        root=hashlib.sha256(canonical_bytes(self.f.root)).hexdigest()
        scope=self.f.authority(self.f.f['entries']['read'],'ack.read_grant')
        payload=json.loads(self.f.current[0]['raw'])['payload']
        old=next(item for item in payload['entries'] if item['scope_id']==scope)
        db.execute('''CREATE TABLE open_repair_index_floors(issuer TEXT,root_digest TEXT,scope_kind TEXT,scope_id TEXT,
            revision INTEGER,minimum_revision INTEGER,revoked_mask INTEGER,conflict INTEGER)''')
        db.execute('INSERT INTO open_repair_index_floors VALUES(?,?,?,?,?,?,0,0)',
            (self.f.f['signers']['owner'].key_id,root,old['scope_kind'],scope,payload['revision'],old['minimum_document_revision']+1));db.commit()
        with self.assertRaisesRegex(RepairWireError,'repair_status_revision'):
            signer.sign(bundle,variant='owner',expected=self.expected,renew_source_status=True)
        self.assertEqual(db.execute('SELECT count(*) FROM open_repair_index_consent_outputs').fetchone()[0],0)

    def test_directory_budget_refused_before_fact_or_consent_is_signed(self):
        for changes in (dict(max_items=65),dict(max_meta_bytes=2097153)):
            options=dict(self.options,budget_limits=dict(self.options['budget_limits'],**changes))
            with self.assertRaisesRegex(RepairWireError,'repair_index_allocation_mismatch'):
                self.preparer.export(self.f.h.resource_id,**options)
        self.assertEqual(self.f.h.db.execute('SELECT count(*) FROM open_repair_index_prepare_exports').fetchone()[0],0)
