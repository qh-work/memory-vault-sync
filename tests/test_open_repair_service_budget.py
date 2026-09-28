"""Actual authenticated failures consume durable finite bootstrap work."""
import json
import sqlite3
import unittest
import threading
from concurrent.futures import ThreadPoolExecutor

from memory_vault_open_repair_wire import RepairWireError
from tests import test_open_repair_service as service_fixture

entry = service_fixture.entry
from tests.open_repair_ack_fixtures import signed_entry


class RepairServiceBudgetTests(unittest.TestCase):
    def setUp(self):
        self.case = service_fixture.RepairServiceTests()
        self.case.setUp()

    def tearDown(self):
        self.case.tearDown()

    def usage(self):
        row = self.case.source.db.execute(
            'SELECT requests,signatures,proof_bytes,replays FROM open_repair_bootstrap_usage').fetchone()
        return row or (0, 0, 0, 0)

    def refusal(self, code, function, *args, **kwargs):
        with self.assertRaises(RepairWireError) as caught:
            function(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def test_exact_answer_retry_charges_encoded_and_decoded_response(self):
        c = self.case
        c.start()
        first, challenge, answer, response, accepted = c.handshake()
        before = self.usage()
        self.assertEqual(c.service.answer(entry(answer)).raw, response.raw)
        after = self.usage()
        self.assertEqual(after[2] - before[2], len(response.raw) + len(accepted.handle.raw) + len(accepted.manifest.raw))
        self.assertEqual(after[0] - before[0], 1)
        self.assertGreater(after[1], before[1])

    def test_authenticated_conflicting_answers_keep_actual_work(self):
        c = self.case
        c.start()
        _, _, answer, _, _ = c.handshake()
        payload = json.loads(answer.raw)['payload']
        payload['expires_at'] -= 1
        changed = signed_entry(payload, c.source.fixture['signers']['owner'], 'conflicting_answer_budget')
        for _ in range(2):
            before = self.usage()
            self.refusal('repair_probe_replay_conflict', c.service.answer, changed)
            after = self.usage()
            self.assertEqual(after[0], before[0] + 1)
            self.assertGreater(after[1] - before[1], 30)
            self.assertEqual(after[2], before[2])
        rows = c.source.db.execute('SELECT signature_allowance,signature_checks FROM open_repair_bootstrap_work').fetchall()
        self.assertTrue(all(actual is not None and 0 < actual <= reserved for reserved, actual in rows))
        self.assertEqual(sum(actual for _, actual in rows), self.usage()[1])

    def test_wrong_signed_nonce_is_charged_without_proof_or_consumption(self):
        c = self.case
        c.start()
        first = c.make_probe()
        challenge = c.service.challenge(entry(first.original))
        answer = c.solve(first, challenge)
        payload = json.loads(answer.raw)['payload']
        payload['answer'] = 'A' * 43
        changed = signed_entry(payload, c.source.fixture['signers']['owner'], 'wrong_nonce_budget')
        before = self.usage()
        self.refusal('repair_invalid_nonce', c.service.answer, changed)
        after = self.usage()
        self.assertEqual(after[0], before[0] + 1)
        self.assertEqual(after[1] - before[1], 4)
        self.assertEqual(after[2], before[2])
        self.assertEqual(c.source.db.execute('SELECT answer_digest FROM open_repair_bootstrap_challenges').fetchone(), (None,))
        self.assertEqual(c.source.db.execute('SELECT count(*) FROM open_repair_bootstrap_handles').fetchone()[0], 0)

    def test_unauthenticated_signature_never_charges_nominated_owner(self):
        c = self.case
        c.start()
        first = c.make_probe()
        packet = json.loads(first.original.raw)
        packet['proof']['signature'] = 'A' * 86 + '=='
        from memory_vault import canonical_bytes
        from tests.open_repair_ack_fixtures import reference
        raw = canonical_bytes(packet)
        changed = dict(raw=raw, ref=reference(raw, 'unauthenticated'))
        self.refusal('repair_invalid_signature', c.service.challenge, changed)
        self.assertEqual(self.usage(), (0, 0, 0, 0))
        self.assertEqual(c.source.db.execute('SELECT count(*) FROM open_repair_bootstrap_work').fetchone()[0], 0)

    def test_pending_failure_consumes_attempt_but_no_new_challenge(self):
        c = self.case
        c.start(max_pending=1)
        c.service.challenge(entry(c.make_probe().original))
        before = self.usage()
        self.refusal('repair_service_capacity', c.service.challenge, entry(c.make_probe().original))
        after = self.usage()
        self.assertEqual(after[0], before[0] + 1)
        self.assertGreater(after[1], before[1])
        self.assertEqual(c.source.db.execute('SELECT count(*) FROM open_repair_bootstrap_challenges').fetchone()[0], 1)
        self.assertEqual(c.source.db.execute('SELECT count(*) FROM open_repair_bootstrap_work').fetchone()[0], 2)

    def test_work_preflight_stops_exhausted_grant_before_history(self):
        c = self.case
        c.start(max_requests=1)
        first = c.make_probe()
        c.service.challenge(entry(first.original))
        before = self.usage()
        # Submitted evidence is not an authenticated observation when work
        # admission is already exhausted; no heavy proof preparation may run.
        def unexpected(*args, **kwargs):
            self.fail('historical verification ran after durable work exhaustion')
        c.service.access.prepare = unexpected
        self.refusal('repair_service_capacity', c.service.challenge, entry(first.original))
        self.assertEqual(self.usage(), before)

    def test_small_grant_uses_actual_work_instead_of_local_ceiling(self):
        c = self.case
        c.start(max_signature_checks=18)
        first = c.make_probe()
        self.assertTrue(c.service.challenge(entry(first.original)).raw)
        self.assertEqual(self.usage()[1], 18)
        self.assertEqual(c.source.db.execute(
            'SELECT signature_allowance,signature_checks FROM open_repair_bootstrap_work').fetchone(), (18, 18))
        before = self.usage()
        self.refusal('repair_service_capacity', c.service.challenge, entry(first.original))
        self.assertEqual(self.usage(), before)

    def test_partial_work_stops_at_small_remaining_grant_and_stays_charged(self):
        c = self.case
        c.start(max_signature_checks=17)
        first = c.make_probe()
        self.refusal('repair_service_capacity', c.service.challenge, entry(first.original))
        self.assertEqual(self.usage()[0:2], (1, 17))
        self.assertEqual(c.source.db.execute(
            'SELECT signature_allowance,signature_checks FROM open_repair_bootstrap_work').fetchone(), (17, 17))
        self.assertEqual(c.source.db.execute('SELECT count(*) FROM open_repair_bootstrap_challenges').fetchone()[0], 0)
        c.restart()
        self.refusal('repair_service_capacity', c.service.challenge, entry(first.original))
        self.assertEqual(self.usage()[0:2], (1, 17))

    def test_settlement_commit_failure_retains_full_reservation_on_restart(self):
        c = self.case
        c.start(max_signature_checks=64)
        c.restart(failing_commit=True)
        first = c.make_probe()
        c.source.db.fail_after = 4  # reserve, observe, publish, then fail settlement.
        with self.assertRaisesRegex(sqlite3.OperationalError, 'synthetic_commit_failure'):
            c.service.challenge(entry(first.original))
        self.assertFalse(c.source.db.in_transaction)
        self.assertEqual(c.source.db.execute('SELECT signature_allowance,signature_checks FROM open_repair_bootstrap_work').fetchone(), (64, None))
        self.assertEqual(self.usage()[1], 0)
        c.restart()
        self.refusal('repair_service_capacity', c.service.challenge, entry(first.original))
        self.assertEqual(c.source.db.execute('SELECT signature_allowance,signature_checks FROM open_repair_bootstrap_work').fetchone(), (64, None))

    def test_parallel_attempt_cannot_spend_an_outstanding_reservation(self):
        from memory_vault_open_repair_service import RepairBootstrapService
        from memory_vault_open_repair_state import RepairAckState
        c = self.case
        c.start(max_signature_checks=64)
        first, second = c.make_probe(), c.make_probe()
        entered, release = threading.Event(), threading.Event()

        class PausedAfterAdmission(RepairBootstrapService):
            def _challenge(self, *args, **kwargs):
                entered.set()
                if not release.wait(5):
                    raise RuntimeError('synthetic_admission_barrier_timeout')
                return super()._challenge(*args, **kwargs)

        def worker():
            with sqlite3.connect(c.source.path) as db:
                old = c.source.state
                state = RepairAckState(db, old.identity, old.node,
                    encryption_identity=old.encryption_identity, policy=old.policy,
                    limit_policy=c.source.fixture['expected']['limit_policy'], clock=lambda:c.source.now[0])
                state.initialize()
                service = PausedAfterAdmission(state)
                service.initialize()
                return service.challenge(entry(first.original)).raw

        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(worker)
            try:
                self.assertTrue(entered.wait(5))
                self.refusal('repair_service_capacity', c.service.challenge, entry(second.original))
                self.assertEqual(c.source.db.execute('SELECT signature_allowance,signature_checks FROM open_repair_bootstrap_work').fetchone(), (64, None))
            finally:
                release.set()
            self.assertTrue(pending.result(timeout=5))
        self.assertEqual(self.usage()[0], 1)
        self.assertEqual(self.usage()[1], 18)

    def test_authenticated_floors_survive_later_decryption_failure(self):
        c = self.case
        c.start()
        first = c.make_probe()
        payload = json.loads(first.original.raw)['payload']
        value = payload['target_nonce_jwe']['ciphertext']
        payload['target_nonce_jwe']['ciphertext'] = ('A' if value[0] != 'A' else 'B') + value[1:]
        changed = signed_entry(payload, c.source.fixture['signers']['owner'], 'signed_bad_aead')
        self.refusal('repair_decryption_failed', c.service.challenge, changed, current_statuses=c.statuses(revision=2))
        self.assertEqual(c.source.db.execute('SELECT min(revision),max(revision) FROM open_repair_access_floors').fetchone(), (2, 2))
        self.assertEqual(self.usage()[0], 1)
        self.assertEqual(self.usage()[1], 18)
        self.assertEqual(c.source.db.execute('SELECT count(*) FROM open_repair_bootstrap_challenges').fetchone()[0], 0)
        c.restart()
        self.assertEqual(c.source.db.execute('SELECT min(revision),max(revision) FROM open_repair_access_floors').fetchone(), (2, 2))

    def test_child_replay_charges_work_but_not_repeated_bytes(self):
        c = self.case
        c.start()
        *_, accepted = c.handshake()
        request = c.child(accepted)
        self.assertTrue(c.service.child(entry(request)))
        before = self.usage()
        self.refusal('repair_child_replay', c.service.child, entry(request))
        after = self.usage()
        self.assertEqual(after[0], before[0] + 1)
        self.assertGreater(after[1], before[1])
        self.assertEqual(after[2], before[2])
        self.assertEqual(c.source.db.execute('SELECT count(*) FROM open_repair_bootstrap_requests').fetchone()[0], 1)


if __name__ == '__main__':
    unittest.main()
