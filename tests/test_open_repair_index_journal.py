"""Interrupted publication work stays charged beside the actual ACK commit."""
import unittest
import os
import hashlib
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor

from memory_vault import canonical_bytes
from memory_vault_open_repair_state import RepairAckState

from memory_vault_open_repair_index_journal import AckIndexJournal
from memory_vault_open_repair_service import RepairBootstrapService
from memory_vault_open_repair_wire import RepairWireError
import memory_vault_open_repair_wire as wire
from tests import test_open_repair_occupied as occupied_fixture


class OpenRepairIndexJournalTests(unittest.TestCase):
    def setUp(self):
        self.case = occupied_fixture.OpenRepairOccupiedTests()
        self.case.setUp()
        self.h = self.case.h
        self.case.put()
        RepairBootstrapService(self.h.state).initialize()
        self.h.db.execute("INSERT INTO open_repair_bootstrap_usage VALUES(?,3,20,9000,5)",(self.h.resource_id,))
        self.h.db.commit()
        self.journal = AckIndexJournal(self.h.state)
        self.journal.initialize()
        self.job = self.h.db.execute("SELECT * FROM open_repair_ack_jobs").fetchone()
        self.journal.start(self.h.resource_id,b'{"synthetic_plan":1}',deadline=self.h.now[0]+100,guard=lambda:None)

    def tearDown(self):
        self.case.tearDown()

    def usage(self):
        return self.h.db.execute("SELECT requests,signatures,proof_bytes,replays FROM open_repair_bootstrap_usage").fetchone()

    def test_lost_response_restart_keeps_exact_request_and_all_prior_work(self):
        first = self.journal.begin(self.h.resource_id,0,b'synthetic_request',signature_allowance=8,
            response_allowance=128,guard=lambda:None)
        charged = self.usage()
        self.assertEqual(charged,(4,28,9000+len(b'synthetic_request')+128,6))
        self.h.db.close(); self.h.connect()
        self.journal = AckIndexJournal(self.h.state); self.journal.initialize()
        self.assertEqual(self.journal.saved_step(self.h.resource_id,0)['request'],b'synthetic_request')
        self.assertEqual(self.usage(),charged)
        with self.assertRaisesRegex(RepairWireError,'repair_index_job_conflict'):
            self.journal.begin(self.h.resource_id,0,b'changed_request',signature_allowance=8,
                response_allowance=128,guard=lambda:None)
        self.assertEqual(self.usage(),charged)
        second = self.journal.begin(self.h.resource_id,0,b'synthetic_request',signature_allowance=8,
            response_allowance=128,guard=lambda:None)
        self.assertGreater(second,first)
        self.journal.finish(self.h.resource_id,second,b'synthetic_response',signature_checks=2,guard=lambda:None)
        settled = self.usage()
        self.assertEqual(settled,(5,30,charged[2]+len(b'synthetic_request')+len(b'synthetic_response'),7))
        self.journal.finish(self.h.resource_id,second,b'synthetic_response',signature_checks=2,guard=lambda:None)
        self.assertEqual(self.usage(),settled)
        self.assertEqual(self.h.db.execute("SELECT * FROM open_repair_ack_jobs").fetchone(),self.job)

    def test_authenticated_refusal_is_committed_without_network_attempt(self):
        before = self.usage()
        def refused():
            self.h.db.execute("INSERT INTO open_repair_state VALUES('synthetic_observed_refusal','revoked')")
            return 'repair_authority_revoked'
        with self.assertRaisesRegex(RepairWireError,'repair_authority_revoked'):
            self.journal.begin(self.h.resource_id,0,b'synthetic_request',signature_allowance=8,
                response_allowance=128,guard=refused)
        self.assertEqual(self.usage(),before)
        self.assertEqual(self.h.db.execute("SELECT value FROM open_repair_state WHERE name='synthetic_observed_refusal'").fetchone(),('revoked',))
        self.assertIsNone(self.journal.saved_step(self.h.resource_id,0))

    def test_existing_shared_usage_and_reserved_job_capacity_cannot_reset(self):
        self.h.db.execute("UPDATE open_repair_bootstrap_usage SET signatures=?",(self.h.state.limits['max_signature_checks'],))
        self.h.db.commit(); before=self.usage()
        with self.assertRaisesRegex(RepairWireError,'repair_index_job_capacity'):
            self.journal.begin(self.h.resource_id,0,b'synthetic_request',signature_allowance=1,
                response_allowance=128,guard=lambda:None)
        self.assertEqual(self.usage(),before)
        with self.assertRaisesRegex(RepairWireError,'repair_index_job_conflict'):
            self.journal.start(self.h.resource_id,b'{"synthetic_plan":2}',deadline=self.h.now[0]+100,guard=lambda:None)
        self.assertEqual(self.journal.snapshot(self.h.resource_id)['plan'],b'{"synthetic_plan":1}')

    def test_new_floor_survives_later_capacity_denial(self):
        self.h.db.execute("UPDATE open_repair_bootstrap_usage SET signatures=?",(self.h.state.limits['max_signature_checks'],));self.h.db.commit()
        def observed():
            self.h.db.execute("INSERT OR IGNORE INTO open_repair_state VALUES('synthetic_new_floor','observed')")
        with self.assertRaisesRegex(RepairWireError,'repair_index_job_capacity'):
            self.journal.begin(self.h.resource_id,0,b'request',signature_allowance=1,response_allowance=1,guard=observed)
        self.assertEqual(self.h.db.execute("SELECT value FROM open_repair_state WHERE name='synthetic_new_floor'").fetchone(),('observed',))

    def test_prepare_reservation_is_shared_with_unsettled_work_and_old_signed_limit(self):
        now=self.h.now[0]
        self.h.db.execute('INSERT INTO open_repair_bootstrap_work VALUES(?,?,?,?,NULL,?,?)',('synthetic_pending',self.h.resource_id,'a'*64,44,now,now+100))
        self.h.db.commit()
        # A higher runtime ceiling does not replace the old signed grant's 64.
        old=self.h.state.limits
        self.h.state.limits=dict(old,max_signature_checks=512)
        budget=wire.RepairBudget(self.h.state.policy)
        with self.assertRaisesRegex(RepairWireError,'repair_index_job_capacity'):
            with self.journal.preparation_work(self.h.resource_id,budget):
                self.fail('should refuse before crypto')
        self.assertEqual(budget.snapshot()['signature_checks'],0)
        self.assertEqual(self.usage()[1],20)
        self.h.state.limits=old

    @unittest.skipUnless(hasattr(os,'fork'),'requires local POSIX process isolation')
    def test_process_loss_during_preparation_keeps_allowance_after_restart(self):
        self.h.db.execute('UPDATE open_repair_bootstrap_usage SET signatures=0');self.h.db.commit()
        self.h.db.close()
        pid=os.fork()
        if pid==0:
            try:
                self.h.connect();journal=AckIndexJournal(self.h.state);journal.initialize()
                with journal.preparation_work(self.h.resource_id,wire.RepairBudget(self.h.state.policy)):
                    os._exit(0)
            except BaseException:
                os._exit(2)
        _,status=os.waitpid(pid,0)
        self.assertEqual(os.waitstatus_to_exitcode(status),0)
        self.h.connect();self.journal=AckIndexJournal(self.h.state);self.journal.initialize()
        self.assertEqual(self.h.db.execute('SELECT signature_allowance,signature_checks FROM open_repair_bootstrap_work').fetchone(),(64,None))
        with self.assertRaisesRegex(RepairWireError,'repair_index_job_capacity'):
            with self.journal.preparation_work(self.h.resource_id,wire.RepairBudget(self.h.state.policy)):
                self.fail('lost work must remain reserved')
        self.assertEqual(self.h.db.execute('SELECT * FROM open_repair_ack_jobs').fetchone(),self.job)

    def test_artifact_bytes_and_sequence_reservations_are_stable_across_restart(self):
        resource=self.h.resource_id
        first=self.journal.reserve_artifact(resource,'assignment-status',status_revision=True,guard=lambda:None)
        revision=first['status_revision']
        self.assertGreater(revision,1)
        self.assertIsNone(first['raw'])
        self.h.db.close();self.h.connect();self.journal=AckIndexJournal(self.h.state);self.journal.initialize()
        self.assertEqual(self.journal.reserve_artifact(resource,'assignment-status',status_revision=True,guard=lambda:None),first)
        saved=self.journal.save_artifact(resource,'assignment-status',b'actual synthetic signed artifact',guard=lambda:None)
        self.assertEqual(saved['status_revision'],revision)
        with self.assertRaisesRegex(RepairWireError,'repair_index_job_conflict'):
            self.journal.save_artifact(resource,'assignment-status',b'other bytes',guard=lambda:None)
        self.assertEqual(self.h.db.execute('SELECT * FROM open_repair_ack_jobs').fetchone(),self.job)

    def test_concurrent_sequence_reservations_include_existing_issuer_counter(self):
        setup=json.loads(bytes(self.h.state._row(self.h.resource_id)['activation_inputs']))
        root=json.loads(setup['root']['raw'])['payload']['ack_slot']['root_key']
        digest=hashlib.sha256(canonical_bytes(root)).hexdigest()
        self.h.db.execute('CREATE TABLE IF NOT EXISTS open_provider_state(name TEXT PRIMARY KEY,value TEXT NOT NULL)')
        self.h.db.execute('INSERT INTO open_provider_state VALUES(?,?)',('status_revision:'+digest,'9'));self.h.db.commit()
        def reserve(name):
            db=sqlite3.connect(self.h.path,timeout=20)
            try:
                f=self.h.fixture
                state=RepairAckState(db,f['signers']['target'],f['docs']['descriptor'],encryption_identity=f['encryption']['target'],
                    limit_policy=f['expected']['limit_policy'],clock=lambda:self.h.now[0])
                state.initialize();journal=AckIndexJournal(state);journal.initialize()
                return journal.reserve_artifact(self.h.resource_id,name,status_revision=True,guard=lambda:None)['status_revision']
            finally: db.close()
        with ThreadPoolExecutor(max_workers=2) as pool:
            revisions=list(pool.map(reserve,('first-status','second-status')))
        self.assertEqual(sorted(revisions),[10,11])
        self.assertEqual(self.h.db.execute('SELECT value FROM open_provider_state WHERE name=?',('status_revision:'+digest,)).fetchone(),('11',))


if __name__ == '__main__':
    unittest.main()
