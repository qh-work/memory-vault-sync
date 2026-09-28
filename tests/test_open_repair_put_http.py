"""Existing bootstrap.use and actual HTTP receipt admission on the same node."""
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from memory_vault import MemoryError
from memory_vault_open_repair_put import RepairAckPutService, encode_entry
import memory_vault_open_repair_probe as probe
import memory_vault_open_repair_wire as wire
from tests import test_open_repair_offer_client as offer_fixture
from tests.test_open_repair_occupied import receipt_inputs


class RepairPutHTTPTests(unittest.TestCase):
    def setUp(self):
        self.case = offer_fixture.RepairOfferClientTests()
        # Each retry returns the original occupied pack again; authorize that
        # cumulative transfer before the owner signs the initial allocation.
        self.case.fixture_limits = dict(proof_limit=524288)
        self.addCleanup(self.case.doCleanups)
        self.case.setUp()
        self.host = self.case.host
        self.host.source.now[0] = 2_000_000_008
        self.enterContext(patch("time.time",return_value=2_000_000_008))
        self.case.client.clock = lambda: self.host.source.now[0]
        self.proof = self.case.client.preflight(self.host.http.base,**self.case.args)
        fixture = SimpleNamespace(h=self.host.source,expected=self.host.expected,write=self.host.write,bound=self.host.result)
        self.receipt,self.disclosure,self.put,self.options = receipt_inputs(fixture)

    def request(self, *, use_changes=None):
        policy = self.host.fixture.local
        budget = wire.RepairBudget(policy)
        handle = self.proof.proof.handle.payload
        payload = dict(schema_version=probe.SCHEMA,kind="bootstrap.use",signing_key=self.host.f["signers"]["writer"].public_descriptor(),
            issued_at=self.host.source.now[0],expires_at=min(self.host.source.now[0]+20,handle["expires_at"]),use_id="synthetic_receipt_use",
            subject=handle["subject"],target=handle["target"],target_storage_epoch=handle["target_storage_epoch"],consumer="ack_offer",operation="ack.put",
            bootstrap_probe_ref=handle["probe_ref"],bootstrap_manifest_ref=self.proof.proof.manifest_ref.as_dict(),request_ref=self.put["ref"])
        payload.update(use_changes or {})
        use = probe._sign(payload,self.host.f["signers"]["writer"],policy,budget)
        def encoded(entry):
            return encode_entry(entry,policy,budget)
        return wire.build_new_wire(dict(schema_version=probe.SCHEMA,kind="ack.put_request",use=encoded(dict(raw=use.raw,ref=use.ref.as_dict())),
            receipt=encoded(self.receipt),disclosure=encoded(self.disclosure),put=encoded(self.put),
            current_statuses=[encoded(item) for item in self.options["current_statuses"]],
            read_until=self.options["read_until"],retain_until=self.options["retain_until"]),policy,budget).raw

    def test_actual_http_put_and_restart_exact_retry_preserve_original_receipt(self):
        raw = self.request()
        response = self.host.http.send(raw)
        self.assertEqual(self.host.source.db.execute("SELECT status FROM open_repair_ack_resources").fetchone()[0],"occupied")
        row = self.host.source.db.execute("""SELECT o.raw FROM open_repair_ack_objects o JOIN open_repair_ack_pins p
            ON p.namespace=o.namespace AND p.opaque_key=o.opaque_key WHERE p.role='occupied:recipient.receipt'""").fetchone()
        self.assertEqual(bytes(row[0]),self.receipt["raw"])
        self.assertEqual(self.host.source.db.execute("SELECT count(*) FROM open_repair_put_requests WHERE committed_generation IS NOT NULL").fetchone()[0],1)
        self.host.http.restart()
        self.assertEqual(self.host.http.send(raw),response)

    def test_signed_use_cannot_borrow_owner_consumer_or_another_put_reference(self):
        for changes in ({"consumer":"ack_owner"}, {"request_ref":self.disclosure["ref"]}):
            with self.assertRaises(MemoryError):
                self.host.http.send(self.request(use_changes=changes))
            self.assertEqual(self.host.source.db.execute("SELECT status FROM open_repair_ack_resources").fetchone()[0],"empty")
            self.assertEqual(self.host.source.db.execute("SELECT count(*) FROM open_repair_ack_commits").fetchone()[0],0)

    def test_failure_persisting_http_result_rolls_back_receipt_commit_and_job(self):
        RepairAckPutService(self.host.source.state).initialize()
        self.host.source.db.execute("""CREATE TRIGGER synthetic_result_failure
            BEFORE UPDATE OF response ON open_repair_put_requests WHEN NEW.response IS NOT NULL
            BEGIN SELECT RAISE(ABORT,'synthetic result persistence failure'); END""")
        self.host.source.db.commit()
        with self.assertRaises(MemoryError):
            self.host.http.send(self.request())
        self.assertEqual(self.host.source.db.execute("SELECT status FROM open_repair_ack_resources").fetchone()[0],"empty")
        for table in ("open_repair_ack_commits","open_repair_ack_jobs"):
            self.assertEqual(self.host.source.db.execute("SELECT count(*) FROM "+table).fetchone()[0],0)
        self.assertEqual(self.host.source.db.execute("SELECT count(*) FROM open_repair_ack_pins WHERE role LIKE 'occupied:%'").fetchone()[0],0)
        self.assertEqual(self.host.source.db.execute("SELECT count(*) FROM open_repair_put_requests WHERE committed_generation IS NOT NULL").fetchone()[0],0)
