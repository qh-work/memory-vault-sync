"""Actual owner HTTP recovery of a message-bound, still-empty ACK source."""
import json
import unittest
from unittest.mock import patch

from memory_vault import MemoryError
from memory_vault_open_repair_empty_state import RepairAckEmptyState
import memory_vault_open_repair_proof as proof
import memory_vault_open_repair_wire as wire
from tests import test_open_repair_http as http_fixture
from tests.test_open_repair_empty import bound_inputs


class EmptyHTTPFixture:
    """Reserve both real generations before signing any owner authority."""
    def __init__(self, case, *, signature_limit=512, proof_limit=262144, bind=True):
        start = http_fixture.service_fixture.RepairServiceTests.start
        participant = http_fixture.RepairHTTPTests.participant_for

        def provision(source_case, **limits):
            f = source_case.source.fixture
            f["docs"]["allocate"]["payload"]["intent"]["budget"]["max_meta_bytes"] = 1048576
            f["docs"]["allocate"]["payload"]["intent"]["budget"]["max_job_bytes"] = max(
                f["docs"]["allocate"]["payload"]["intent"]["budget"]["max_job_bytes"], proof_limit)
            for name in ("root", "read"):
                f["docs"][name]["payload"]["budget"]["max_meta_bytes"] = 1048576
                f["docs"][name]["payload"]["budget"]["max_job_bytes"] = max(
                    f["docs"][name]["payload"]["budget"]["max_job_bytes"], proof_limit)
            root = f["docs"]["root"]["payload"]
            root["allowed_roles"] = sorted(set(root["allowed_roles"]) | {
                "ack_offer_service_v1", "bootstrap.ack_offer",
                "historical.status.ack_write", "historical.status.ack_offer_bootstrap"})
            return start(source_case, **(dict(max_signature_checks=signature_limit,
                max_proof_bytes=proof_limit) | limits))

        def configured(host, directory, policy):
            if policy is not None:
                policy = dict(policy, limit_policy=dict(policy["limit_policy"],
                    max_signature_checks=signature_limit, max_proof_bytes=proof_limit))
            return participant(host, directory, policy)

        case.enterContext(patch.object(http_fixture.service_fixture.RepairServiceTests, "start", provision))
        case.enterContext(patch.object(http_fixture.RepairHTTPTests, "participant_for", configured))
        self.http = http_fixture.RepairHTTPTests()
        case.addCleanup(self.http.doCleanups)
        self.http.setUp()
        self.source, self.fixture = self.http.source, self.http.fixture
        self.f = self.source.fixture
        self.source.now[0] = 2_000_000_007
        case.enterContext(patch("time.time", return_value=2_000_000_007))
        self.empty = RepairAckEmptyState(self.source.state)
        self.empty.initialize()
        self.write, self.offer, self.expected = bound_inputs(self.f)
        self.result = self.empty.bind(self.source.resource_id, self.write, self.offer, **self.expected) if bind else None

    def handshake(self, *, restart=False):
        first = self.fixture.make_probe()
        challenge = self.http.control(self.http.send(first.original.raw))
        if restart:
            self.http.restart()
        answer = self.fixture.solve(first, challenge)
        raw = self.http.send(answer.raw)
        options = self.fixture.options()
        return proof.verify_bootstrap_proof_response(raw,
            expected_subject=options["expected_subject"], expected_target=options["expected_target"],
            target_storage_epoch=options["target_storage_epoch"], selector=options["selector"],
            bootstrap_grant_ref=self.f["entries"]["bootstrap"]["ref"],
            probe_ref=first.original.ref.as_dict(), challenge_ref=challenge.ref.as_dict(),
            answer_ref=answer.ref.as_dict(), at=self.source.now[0],
            max_proof_items=self.f["expected"]["limit_policy"]["max_proof_items"],
            max_proof_bytes=self.f["expected"]["limit_policy"]["max_proof_bytes"],
            expected_source_state="empty", policy=self.fixture.local,
            budget=wire.RepairBudget(self.fixture.local))


class RepairEmptyHTTPTests(unittest.TestCase):
    def test_real_http_restart_returns_bound_empty_profile_and_both_history_generations(self):
        host = EmptyHTTPFixture(self)
        accepted = host.handshake(restart=True)
        children = accepted.manifest.value["children"]
        self.assertEqual(accepted.manifest.value["response_profile"], "ack_owner_service_v1")
        self.assertEqual(host.f["docs"]["bootstrap"]["payload"]["response_profile"], "ack_owner_service_v1")
        roles = {row["role"] for row in children}
        self.assertTrue({"history.ack_empty", "history.ack_unbound", "ack.empty_custody",
                         "ack.unbound_custody", "ack.binding", "ack.head"} <= roles)
        packs = [row["ref"] for row in children if row["role"] == "history.raw_pack"]
        self.assertGreaterEqual(len(packs), 2)
        self.assertEqual(len(packs), len({json.dumps(ref, sort_keys=True) for ref in packs}))
        self.assertEqual(host.source.db.execute("SELECT status FROM open_repair_ack_resources").fetchone()[0], "empty")

    def test_disabled_service_cannot_serve_an_existing_empty_source(self):
        host = EmptyHTTPFixture(self)
        first = host.fixture.make_probe()
        host.http.restart(enabled=False)
        with self.assertRaises(MemoryError):
            host.http.send(first.original.raw)
        self.assertEqual(host.source.db.execute("SELECT count(*) FROM open_repair_bootstrap_work").fetchone()[0], 0)
