"""A receipt writer independently verifies its actual source before upload."""
import hashlib
import json
import unittest

from memory_vault import canonical_bytes
from memory_vault_open_repair_offer_access import RepairAckOfferAccess
from memory_vault_open_repair_offer_client import AckOfferClient
import memory_vault_open_repair_wire as wire
from tests.open_repair_ack_fixtures import signed_entry
from tests.test_open_repair_empty_http import EmptyHTTPFixture


class RepairOfferClientTests(unittest.TestCase):
    def setUp(self):
        self.host = EmptyHTTPFixture(self, **getattr(self, "fixture_limits", {}))
        f = self.host.f
        self.client = AckOfferClient(f["signers"]["writer"],f["encryption"]["writer"],
            policy=self.host.fixture.local,limit_policy=f["expected"]["limit_policy"],allow_loopback=True)
        self.addCleanup(self.client.close)
        self.args = dict(target_node_entry=f["entries"]["descriptor"],expected_target=f["expected"]["expected_target"],
            expected_ack_slot=f["expected"]["expected_ack_slot"],expected_owner=f["expected"]["expected_owner"],
            root_entry=f["entries"]["root"],write_entry=self.host.write,bootstrap_entry=self.host.offer,
            expected_message_id=self.host.expected["expected_message_id"],expected_envelope_ref=self.host.expected["expected_envelope_ref"])

    def revoke(self, kind, original):
        root = self.host.f["expected"]["expected_ack_slot"]["root_key"]
        scope = hashlib.sha256(canonical_bytes(dict(kind="authority",root_key=root,
            authority_kind=kind,authority_sha256=original["ref"]["raw_sha256"]))).hexdigest()
        payload = json.loads(self.host.expected["current_statuses"][0]["raw"])["payload"]
        payload["revision"] = 3
        for item in payload["entries"]:
            if item["scope_id"] == scope:
                item.update(status="revoked",operation_mask=1 if kind == "ack.write_grant" else 2)
        return signed_entry(payload,self.host.f["signers"]["owner"],"synthetic-offer-revocation")

    def test_real_complete_http_preflight_checks_both_generations_and_exact_tuple(self):
        self.host.http.restart()
        result = self.client.preflight(self.host.http.base,**self.args)
        self.assertEqual(result.proof.manifest.value["consumer"], "ack_offer")
        self.assertEqual(result.source.authorities.originals["write"].ref.as_dict(),self.host.write["ref"])
        self.assertEqual(result.source.authorities.originals["bootstrap"].ref.as_dict(),self.host.offer["ref"])
        self.assertEqual(len(result.originals),12)
        self.assertEqual(result.metrics["requests"],14)
        self.assertEqual(result.metrics["signature_checks"],30)

    def test_known_writer_revocation_refuses_before_any_probe(self):
        revoked = self.revoke("ack.write_grant",self.host.write)
        with self.assertRaises(wire.RepairWireError) as caught:
            self.client.preflight(self.host.http.base,known_statuses=[revoked],**self.args)
        self.assertEqual(caught.exception.code,"repair_authority_revoked")
        self.assertEqual(self.host.source.db.execute("SELECT count(*) FROM open_repair_bootstrap_challenges").fetchone()[0],0)

    def test_owner_read_revocation_does_not_remove_receipt_writer_offer(self):
        revoked = self.revoke("ack.read_grant",self.host.f["entries"]["read"])
        statuses = [revoked,self.host.expected["current_statuses"][1]]
        gate = RepairAckOfferAccess(self.host.source.state)
        gate.initialize()
        prepared = gate.prepare(self.host.source.resource_id,action="proof",current_statuses=statuses)
        with self.host.source.state._transaction():
            self.assertTrue(gate.check_locked(prepared).allowed)
        result = self.client.preflight(self.host.http.base,known_statuses=[revoked],**self.args)
        self.assertEqual(result.metrics["requests"],15)  # The newer current T is an additional exact original.
        self.assertEqual(result.source.authorities.originals["write"].ref.as_dict(),self.host.write["ref"])
