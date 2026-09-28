"""The B client preflights, authorizes, uploads and verifies a real ACK commit."""
from dataclasses import replace
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from memory_vault_open_repair_put_client import AckReceiptClient
import memory_vault_open_repair_wire as wire
from tests import test_open_repair_offer_client as offer_fixture
from tests.test_open_repair_occupied import receipt_inputs


class RepairPutClientTests(unittest.TestCase):
    def setUp(self):
        self.case = offer_fixture.RepairOfferClientTests()
        self.addCleanup(self.case.doCleanups)
        self.case.setUp()
        self.host = self.case.host
        self.host.source.now[0] = 2_000_000_008
        self.enterContext(patch("time.time",return_value=2_000_000_008))
        self.fixture = SimpleNamespace(h=self.host.source,expected=self.host.expected,write=self.host.write,bound=self.host.result)
        self.inputs = receipt_inputs(self.fixture)

    def client(self, *, signatures=None):
        f = self.host.f
        options = {} if signatures is None else dict(policy=replace(self.host.fixture.local,max_signature_checks=signatures))
        client = AckReceiptClient(f["signers"]["writer"],f["encryption"]["writer"],
            **options,
            limit_policy=f["expected"]["limit_policy"],allow_loopback=True,clock=lambda:self.host.source.now[0])
        self.addCleanup(client.close)
        return client

    def test_real_client_commits_and_independently_verifies_original_receipt(self):
        receipt,disclosure,put,options = self.inputs
        result = self.client().put(self.host.http.base,receipt,disclosure,put,**options,**self.case.args)
        self.assertEqual(result.source.inputs["receipt"].raw,receipt["raw"])
        self.assertEqual(result.source.inputs["receipt"].ref.as_dict(),receipt["ref"])
        self.assertEqual(result.metrics["requests"],15)
        self.assertEqual(result.metrics["signature_checks"],66)
        self.assertEqual(self.host.source.db.execute("SELECT status FROM open_repair_ack_resources").fetchone()[0],"occupied")

    def test_narrow_legacy_consent_never_uploads_receipt(self):
        from memory_vault_open_repair_occupied import RETURN_ROLES_LEGACY
        receipt,disclosure,put,options = receipt_inputs(self.fixture,bootstrap_roles=RETURN_ROLES_LEGACY)
        with self.assertRaises(wire.RepairWireError) as caught:
            self.client().put(self.host.http.base,receipt,disclosure,put,**options,**self.case.args)
        self.assertEqual(caught.exception.code,"repair_disclosure_permission")
        self.assertEqual(self.host.source.db.execute("SELECT status FROM open_repair_ack_resources").fetchone()[0],"empty")
        self.assertEqual(self.host.source.db.execute("SELECT requests FROM open_repair_bootstrap_usage").fetchone()[0],14)

    def test_insufficient_remaining_client_budget_refuses_before_receipt_upload(self):
        receipt,disclosure,put,options = self.inputs
        with self.assertRaises(wire.RepairWireError) as caught:
            self.client(signatures=64).put(self.host.http.base,receipt,disclosure,put,**options,**self.case.args)
        self.assertEqual(caught.exception.code,"repair_over_budget")
        self.assertEqual(self.host.source.db.execute("SELECT status FROM open_repair_ack_resources").fetchone()[0],"empty")
        self.assertEqual(self.host.source.db.execute("SELECT requests FROM open_repair_bootstrap_usage").fetchone()[0],14)
