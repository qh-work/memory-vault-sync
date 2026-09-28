"""Actual receipt-writer possession and proof reads over the fixed HTTP route."""
import json
import unittest

import memory_vault_open_repair_probe as probe
import memory_vault_open_repair_proof as proof
import memory_vault_open_repair_wire as wire
from tests.test_open_repair_empty_http import EmptyHTTPFixture


def entry(original):
    return dict(raw=original.raw, ref=original.ref.as_dict())


class RepairOfferHTTPTests(unittest.TestCase):
    def handshake(self, *, restart=False):
        host = EmptyHTTPFixture(self)
        f, local = host.f, host.fixture.local
        grant = json.loads(host.offer["raw"])["payload"]
        expected = dict(expected_subject=host.expected["expected_receipt_writer"],
            expected_target=f["expected"]["expected_target"], target_storage_epoch=f["expected"]["target_storage_epoch"],
            bootstrap_grant_sha256=host.offer["ref"]["raw_sha256"], selector=grant["selector"],
            at=host.source.now[0], policy=local, budget=wire.RepairBudget(local), consumer="ack_offer")
        first = probe.make_bootstrap_probe(f["signers"]["writer"], expires_at=expected["at"]+50, **expected)
        challenge = host.http.control(host.http.send(first.original.raw))
        if restart:
            host.http.restart()
        answer = probe.solve_bootstrap_challenge(entry(first.original), entry(challenge),
            signer=f["signers"]["writer"], encryption_identity=f["encryption"]["writer"],
            target_nonce=first.nonce, expires_at=expected["at"]+40, **expected)
        raw = host.http.send(answer.raw)
        checked = proof.verify_bootstrap_proof_response(raw,
            **{name: expected[name] for name in ("expected_subject", "expected_target", "target_storage_epoch", "selector", "at", "policy", "budget", "consumer")},
            bootstrap_grant_ref=host.offer["ref"], probe_ref=first.original.ref.as_dict(),
            challenge_ref=challenge.ref.as_dict(), answer_ref=answer.ref.as_dict(), expected_source_state="empty",
            max_proof_items=grant["limits"]["max_proof_items"], max_proof_bytes=grant["limits"]["max_proof_bytes"])
        return host, expected, checked

    def test_real_writer_exchange_survives_restart_and_reads_exact_child(self):
        host, expected, checked = self.handshake(restart=True)
        self.assertEqual(checked.manifest.value["response_profile"], "ack_offer_service_v1")
        self.assertEqual(checked.handle.payload["consumer"], "ack_offer")
        self.assertEqual(len(checked.manifest.value["children"]), 22)
        child = checked.manifest.value["children"][0]
        request = proof.make_bootstrap_child_request(host.f["signers"]["writer"], checked,
            subject=expected["expected_subject"], target=expected["expected_target"], at=expected["at"],
            expires_at=expected["at"]+30, child_index=0, offset=0, requested_bytes=child["ref"]["size"],
            policy=expected["policy"], budget=expected["budget"])
        host.http.restart()
        raw = host.http.send(request.raw, child=True)
        ref = wire.raw_ref(child["ref"])
        self.assertEqual(len(raw), ref.size)
        self.assertEqual(expected["budget"]._hash(raw), ref.raw_sha256)

    def test_owner_cannot_use_writer_handle_even_with_its_real_signing_key(self):
        host, expected, checked = self.handshake()
        with self.assertRaises(wire.RepairWireError):
            proof.make_bootstrap_child_request(host.f["signers"]["owner"], checked,
                subject=host.f["expected"]["expected_owner"], target=expected["expected_target"], at=expected["at"],
                expires_at=expected["at"]+30, child_index=0, offset=0, requested_bytes=1,
                policy=expected["policy"], budget=expected["budget"])
