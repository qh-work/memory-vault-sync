"""Synthetic durable source service: actual possession and protected proof bytes."""
import copy
import hashlib
import json
import sqlite3
import unittest

from memory_vault import canonical_bytes
from memory_vault_open_repair_access import RepairAckAccess
from memory_vault_open_repair_ack import verify_ack_unbound_source_event
import memory_vault_open_repair_probe as probe
import memory_vault_open_repair_proof as proof
from memory_vault_open_repair_service import RepairBootstrapService
import memory_vault_open_repair_wire as wire
from tests.open_repair_ack_fixtures import signed_entry
from tests import test_open_repair_state as source_fixture


def entry(original):
    return dict(raw=original.raw, ref=original.ref.as_dict())


class SyntheticCommitFailure(sqlite3.Connection):
    """Fail before committing, so the service must roll back before returning."""
    fail_after = None

    def commit(self):
        if self.fail_after is not None:
            self.fail_after -= 1
            if self.fail_after == 0:
                self.fail_after = None
                raise sqlite3.OperationalError("synthetic_commit_failure")
        return super().commit()


class RepairServiceTests(unittest.TestCase):
    def setUp(self):
        self.source = source_fixture.RepairStateTests()
        self.source.setUp()

    def tearDown(self):
        self.source.tearDown()

    def start(self, **limits):
        f = self.source.fixture
        # The real four-descriptor encrypted probe is larger than 4 KiB.
        # This source explicitly reserves a sufficient finite transport profile.
        changes = dict(max_probe_bytes=8192, max_signature_checks=512) | limits
        f["expected"]["limit_policy"].update(changes)
        f["docs"]["bootstrap"]["payload"]["limits"].update(changes)
        allocation = f["docs"]["allocate"]["payload"]
        allocation["intent"]["budget"]["max_requests"] = 1024
        allocation["intent_sha256"] = hashlib.sha256(canonical_bytes(allocation["intent"])).hexdigest()
        f["entries"]["allocate"] = signed_entry(allocation, f["signers"]["owner"], "allocate")
        f["docs"]["allocate"] = json.loads(f["entries"]["allocate"]["raw"])
        for role in ("root", "read"):
            f["docs"][role]["payload"]["budget"]["max_requests"] = 1024
        self.source.db.close()
        self.source.connect()
        self.source.activate()
        self.custody = self.source.finalize()
        self.service = RepairBootstrapService(self.source.state)
        self.service.initialize()
        self.local = self.source.state.policy
        return self.service

    def restart(self, *, failing_commit=False):
        self.source.db.close()
        if failing_commit:
            old = self.source.state
            self.source.db = sqlite3.connect(self.source.path, factory=SyntheticCommitFailure)
            self.source.db.execute("PRAGMA journal_mode=WAL")
            self.source.db.execute("PRAGMA synchronous=FULL")
            self.source.db.execute("PRAGMA trusted_schema=OFF")
            self.source.state = type(old)(self.source.db, old.identity, old.node,
                encryption_identity=old.encryption_identity, policy=self.local,
                limit_policy=self.source.fixture["expected"]["limit_policy"],
                clock=lambda:self.source.now[0])
            self.source.state.initialize()
        else:
            self.source.connect(policy=self.local)
        self.service = RepairBootstrapService(self.source.state)
        self.service.initialize()

    def options(self):
        f = self.source.fixture
        return dict(expected_subject=f["expected"]["expected_owner"],
            expected_target=f["expected"]["expected_target"],
            target_storage_epoch=f["expected"]["target_storage_epoch"],
            bootstrap_grant_sha256=f["entries"]["bootstrap"]["ref"]["raw_sha256"],
            selector=f["docs"]["bootstrap"]["payload"]["selector"],
            at=self.source.now[0], policy=self.local, budget=wire.RepairBudget(self.local))

    def make_probe(self):
        return probe.make_bootstrap_probe(self.source.fixture["signers"]["owner"],
            expires_at=self.source.now[0]+50, **self.options())

    def solve(self, first, challenge):
        f = self.source.fixture
        return probe.solve_bootstrap_challenge(entry(first.original), entry(challenge),
            signer=f["signers"]["owner"], encryption_identity=f["encryption"]["owner"],
            target_nonce=first.nonce, expires_at=challenge.payload["expires_at"], **self.options())

    def authenticate_response(self, response, first, challenge, answer):
        options = self.options()
        options.pop("bootstrap_grant_sha256")
        f = self.source.fixture
        return proof.verify_bootstrap_proof_response(response.raw, **options,
            bootstrap_grant_ref=f["entries"]["bootstrap"]["ref"], probe_ref=first.original.ref.as_dict(),
            challenge_ref=challenge.ref.as_dict(), answer_ref=answer.ref.as_dict(),
            max_proof_items=f["expected"]["limit_policy"]["max_proof_items"],
            max_proof_bytes=f["expected"]["limit_policy"]["max_proof_bytes"])

    def handshake(self):
        first = self.make_probe()
        challenge = self.service.challenge(entry(first.original))
        answer = self.solve(first, challenge)
        response = self.service.answer(entry(answer))
        return first, challenge, answer, response, self.authenticate_response(response, first, challenge, answer)

    def child(self, accepted, index=0, offset=0, size=None):
        f = self.source.fixture
        reference = accepted.manifest.value["children"][index]["ref"]
        size = min(proof.MAX_CHILD_BYTES, reference["size"]-offset) if size is None else size
        return proof.make_bootstrap_child_request(f["signers"]["owner"], accepted,
            subject=f["expected"]["expected_owner"], target=f["expected"]["expected_target"],
            at=self.source.now[0], expires_at=accepted.handle.payload["expires_at"],
            child_index=index, offset=offset, requested_bytes=size,
            policy=self.local, budget=wire.RepairBudget(self.local))

    def statuses(self, revision=2, revoked=False):
        f = self.source.fixture
        result = []
        for role, signer in (("owner_status", "owner"), ("target_status", "target")):
            payload = copy.deepcopy(f["docs"][role]["payload"])
            payload["revision"] = revision
            if revoked and role == "owner_status":
                payload["entries"][0]["status"] = "revoked"
            result.append(signed_entry(payload, f["signers"][signer], "current_" + role))
        return result

    def observe(self, statuses):
        access = RepairAckAccess(self.source.state)
        access.initialize()
        prepared = access.prepare(self.source.resource_id, action="proof", current_statuses=statuses)
        with self.source.state._transaction():
            return access.check_locked(prepared)

    def assertCode(self, expected, function, *args, **kwargs):
        with self.assertRaises(wire.RepairWireError) as caught:
            function(*args, **kwargs)
        self.assertEqual(caught.exception.code, expected)

    def usage(self):
        row = self.source.db.execute("SELECT requests,signatures,proof_bytes,replays FROM open_repair_bootstrap_usage").fetchone()
        return row or (0,0,0,0)

    def test_challenge_shortens_to_actual_authority_and_retains_deadline_after_restart(self):
        self.start();until=self.source.now[0]+20
        current=[]
        for role,signer in (('owner_status','owner'),('target_status','target')):
            payload=copy.deepcopy(self.source.fixture['docs'][role]['payload'])
            payload.update(revision=2,valid_until=until)
            current.append(signed_entry(payload,self.source.fixture['signers'][signer],'short_'+role))
        first=self.make_probe()
        challenge=self.service.challenge(entry(first.original),current_statuses=current)
        self.assertEqual(challenge.payload['expires_at'],until)
        self.restart()
        answer=self.solve(first,challenge)
        accepted=self.authenticate_response(self.service.answer(entry(answer)),first,challenge,answer)
        self.assertLessEqual(accepted.handle.payload['expires_at'],until)
        self.source.now[0]=until
        with self.assertRaises(wire.RepairWireError):self.service.child(entry(self.child(accepted,0,0)))

    def test_real_handshake_restart_fetches_complete_remote_historical_closure(self):
        self.start()
        first = self.make_probe()
        self.assertGreater(len(first.original.raw), 4096)
        self.assertLessEqual(len(first.original.raw), 8192)
        challenge = self.service.challenge(entry(first.original))
        self.restart()
        answer = self.solve(first, challenge)
        response = self.service.answer(entry(answer))
        accepted = self.authenticate_response(response, first, challenge, answer)
        self.assertEqual(len(accepted.manifest.value["children"]), 21)
        self.restart()
        fetched, by_role = {}, {}
        for index, child in enumerate(accepted.manifest.value["children"]):
            ref = wire.raw_ref(child["ref"])
            if ref not in fetched:
                chunks = []
                for offset in range(0, ref.size, proof.MAX_CHILD_BYTES):
                    request = self.child(accepted, index, offset)
                    chunks.append(self.service.child(entry(request)))
                raw = b"".join(chunks)
                self.assertEqual(len(raw), ref.size)
                self.assertEqual(hashlib.sha256(raw).hexdigest(), ref.raw_sha256)
                fetched[ref] = dict(raw=raw, ref=ref.as_dict())
            by_role[child["role"]] = fetched[ref]
        meter = wire.RepairBudget(self.local)
        resolver = wire.LocalRawResolver(self.local, meter)
        for child in accepted.manifest.value["children"]:
            if child["role"] == "history.raw_pack":
                ref = wire.raw_ref(child["ref"])
                resolver.put(ref.namespace, ref.key, fetched[ref]["raw"])
        verified = verify_ack_unbound_source_event(by_role["history.ack_unbound"], resolver,
            by_role["ack.unbound_custody"], **self.source.fixture["expected"], policy=self.local, budget=meter)
        self.assertEqual(verified.stored_at, 2_000_000_006)
        self.assertEqual(by_role["ack.unbound_custody"], self.custody)

    def test_exact_retries_survive_restart_without_new_reservations(self):
        self.start()
        first, challenge, answer, response, accepted = self.handshake()
        usage = self.source.state.capacity.usage()
        self.restart()
        self.assertEqual(self.service.challenge(entry(first.original)).raw, challenge.raw)
        self.assertEqual(self.service.answer(entry(answer)).raw, response.raw)
        request = self.child(accepted)
        raw = self.service.child(entry(request))
        self.restart()
        self.assertTrue(raw)
        self.assertCode("repair_child_replay", self.service.child, entry(request))
        self.assertEqual(self.source.state.capacity.usage(), usage)

    def test_current_revocation_between_probe_and_answer_survives_restart(self):
        self.start()
        first = self.make_probe()
        challenge = self.service.challenge(entry(first.original))
        answer = self.solve(first, challenge)
        decision = self.observe(self.statuses(revoked=True))
        self.assertEqual(decision.code, "repair_authority_revoked")
        self.restart()
        self.assertCode("repair_authority_revoked", self.service.answer, entry(answer))
        self.assertCode("repair_authority_revoked", self.service.challenge, entry(first.original),
                        current_statuses=self.statuses(revision=3))

    def test_current_revocation_between_children_refuses_even_exact_retry(self):
        self.start()
        *_, accepted = self.handshake()
        request = self.child(accepted)
        self.assertTrue(self.service.child(entry(request)))
        self.assertEqual(self.observe(self.statuses(revoked=True)).code, "repair_authority_revoked")
        self.restart()
        self.assertCode("repair_authority_revoked", self.service.child, entry(request))

    def test_new_current_generation_invalidates_frozen_child_handle(self):
        self.start()
        *_, accepted = self.handshake()
        request = self.child(accepted)
        changed = self.observe(self.statuses())
        self.assertTrue(changed.allowed)
        self.assertGreater(changed.generation, accepted.handle.payload["service_generation"])
        self.assertCode("repair_access_generation", self.service.child, entry(request))

    def test_same_probe_locator_and_one_use_answer_conflicts(self):
        self.start()
        first, challenge, answer, response, accepted = self.handshake()
        changed = entry(first.original)
        changed["ref"]["key"] = "ef" * 32
        self.assertCode("repair_probe_replay_conflict", self.service.challenge, changed)
        payload = json.loads(answer.raw)["payload"]
        payload["expires_at"] -= 1
        changed_answer = signed_entry(payload, self.source.fixture["signers"]["owner"], "conflicting_answer")
        self.assertCode("repair_probe_replay_conflict", self.service.answer, changed_answer)
        changed_answer_ref = entry(answer)
        changed_answer_ref["ref"]["key"] = "ab" * 32
        self.assertCode("repair_probe_replay_conflict", self.service.answer, changed_answer_ref)
        self.assertEqual(self.service.answer(entry(answer)).raw, response.raw)
        self.assertEqual(self.source.db.execute("SELECT count(*) FROM open_repair_bootstrap_handles").fetchone()[0], 1)

    def test_pending_limit_refuses_second_probe_without_phantom_reservation(self):
        self.start(max_pending=1)
        first, second = self.make_probe(), self.make_probe()
        self.service.challenge(entry(first.original))
        usage = self.usage()
        metadata = self.source.state._row(self.source.resource_id)["metadata_bytes"]
        reservation = self.source.state.capacity.usage()
        self.assertCode("repair_service_capacity", self.service.challenge, entry(second.original))
        self.assertEqual(self.source.db.execute("SELECT count(*) FROM open_repair_bootstrap_challenges").fetchone()[0], 1)
        charged = self.usage()
        self.assertEqual(charged[0], usage[0]+1)
        self.assertGreater(charged[1], usage[1])
        self.assertEqual(charged[2], usage[2])
        self.assertEqual(charged[3], usage[3]+1)
        self.assertGreater(self.source.state._row(self.source.resource_id)["metadata_bytes"], metadata)
        self.assertEqual(self.source.state.capacity.usage(), reservation)

    def test_new_status_floors_survive_service_capacity_denial(self):
        self.start(max_pending=1)
        first, second = self.make_probe(), self.make_probe()
        self.service.challenge(entry(first.original))
        self.assertCode("repair_service_capacity", self.service.challenge, entry(second.original),
                        current_statuses=self.statuses(revision=2))
        self.assertEqual(self.source.db.execute("SELECT min(revision),max(revision) FROM open_repair_access_floors").fetchone(), (2,2))
        self.restart()
        self.assertCode("repair_status_rollback", self.service.challenge, entry(second.original),
                        current_statuses=self.statuses(revision=1))
        self.assertEqual(self.source.db.execute("SELECT requests FROM open_repair_bootstrap_usage").fetchone()[0], 3)

    def test_signature_cap_is_cumulative_across_handshake_and_child_requests(self):
        self.start(max_signature_checks=96)
        *_, accepted = self.handshake()
        request = self.child(accepted)
        before = self.source.db.execute("SELECT signatures FROM open_repair_bootstrap_usage").fetchone()[0]
        self.assertGreater(before, 32)
        self.assertLessEqual(before, 96)
        # The remaining grant is smaller than the local 64-check ceiling,
        # but can still serve a child. A later partial attempt consumes only
        # its finite remainder, then exhaustion rejects before more crypto.
        self.assertTrue(self.service.child(entry(request)))
        completed = 1
        for _ in range(96):
            try:
                self.service.child(entry(self.child(accepted)))
            except wire.RepairWireError as exc:
                self.assertEqual(exc.code, "repair_service_capacity")
                break
            completed += 1
        else:
            self.fail("cumulative signature grant was not exhausted")
        self.assertEqual(self.source.db.execute("SELECT signatures FROM open_repair_bootstrap_usage").fetchone()[0], 96)
        self.assertEqual(self.source.db.execute("SELECT count(*) FROM open_repair_bootstrap_requests").fetchone()[0], completed)
        usage = self.usage()
        self.assertCode("repair_service_capacity", self.service.child, entry(self.child(accepted)))
        self.assertEqual(self.usage(), usage)

    def test_insufficient_proof_bytes_exposes_no_handle_or_answer_consumption(self):
        self.start(max_proof_bytes=1024)
        first = self.make_probe()
        challenge = self.service.challenge(entry(first.original))
        answer = self.solve(first, challenge)
        self.assertCode("repair_proof_too_large", self.service.answer, entry(answer))
        self.assertEqual(self.source.db.execute("SELECT count(*) FROM open_repair_bootstrap_handles").fetchone()[0], 0)
        self.assertEqual(self.source.db.execute("SELECT answer_digest,response FROM open_repair_bootstrap_challenges").fetchone(), (None,None))

    def test_challenge_publication_failure_returns_no_challenge_but_keeps_actual_work(self):
        self.start()
        self.restart(failing_commit=True)
        first = self.make_probe()
        metadata = self.source.state._row(self.source.resource_id)["metadata_bytes"]
        self.source.db.fail_after = 3  # Reserve and observe commit; publication fails.
        with self.assertRaisesRegex(sqlite3.OperationalError, "synthetic_commit_failure"):
            self.service.challenge(entry(first.original))
        self.assertFalse(self.source.db.in_transaction)
        self.assertEqual(self.source.db.execute("SELECT count(*) FROM open_repair_bootstrap_challenges").fetchone()[0], 0)
        self.assertEqual(self.usage()[0], 1)
        self.assertGreater(self.usage()[1], 0)
        self.assertGreater(self.source.state._row(self.source.resource_id)["metadata_bytes"], metadata)
        self.assertEqual(self.source.db.execute("SELECT count(*) FROM open_repair_bootstrap_work WHERE signature_checks IS NULL").fetchone()[0], 0)
        self.service.challenge(entry(first.original))

    def test_answer_commit_failure_returns_no_proof_and_retry_can_complete(self):
        self.start()
        first = self.make_probe()
        challenge = self.service.challenge(entry(first.original))
        answer = self.solve(first, challenge)
        self.restart(failing_commit=True)
        usage = self.usage()
        self.source.db.fail_after = 3  # Work and observation commit; publishing commit fails.
        with self.assertRaisesRegex(sqlite3.OperationalError, "synthetic_commit_failure"):
            self.service.answer(entry(answer))
        self.assertFalse(self.source.db.in_transaction)
        self.assertEqual(self.source.db.execute("SELECT count(*) FROM open_repair_bootstrap_handles").fetchone()[0], 0)
        self.assertEqual(self.source.db.execute("SELECT answer_digest,response FROM open_repair_bootstrap_challenges").fetchone(), (None,None))
        charged = self.usage()
        self.assertEqual(charged[0], usage[0]+1)
        self.assertGreater(charged[1], usage[1])
        self.assertEqual(charged[2], usage[2])
        self.assertEqual(charged[3], usage[3]+1)
        response = self.service.answer(entry(answer))
        self.authenticate_response(response, first, challenge, answer)


if __name__ == "__main__":
    unittest.main()
