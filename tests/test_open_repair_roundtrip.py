"""One durable resource, three real HTTP clients, and the original B receipt."""
import hashlib
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from memory_vault import canonical_bytes
from memory_vault_open_repair_bind_client import OwnerAckBindClient
from memory_vault_open_repair_client import AckOwnerRecoveryClient
from memory_vault_open_repair_put_client import AckReceiptClient
from tests.open_repair_ack_fixtures import signed_entry
from tests.test_open_repair_empty_http import EmptyHTTPFixture
from tests.test_open_repair_occupied import receipt_inputs
from tests import test_open_repair_state as state_fixture


class AckRoundTripTests(unittest.TestCase):
    def test_remote_bind_put_restart_and_owner_recovers_exact_receipt_on_one_ledger(self):
        # Both grants and the actual resource reservation are signed with this
        # finite allowance before allocation. No persisted budget is rewritten.
        activate = state_fixture.RepairStateTests.activate
        def provision(source):
            f = source.fixture
            allocation = f["docs"]["allocate"]["payload"]
            allocation["intent"]["budget"]["max_requests"] = 2048
            allocation["intent_sha256"] = hashlib.sha256(canonical_bytes(allocation["intent"])).hexdigest()
            f["entries"]["allocate"] = signed_entry(allocation, f["signers"]["owner"], "allocate")
            for name in ("root", "read"):
                f["docs"][name]["payload"]["budget"]["max_requests"] = 2048
            return activate(source)
        self.enterContext(patch.object(state_fixture.RepairStateTests, "activate", provision))
        host = EmptyHTTPFixture(self, bind=False, signature_limit=2048, proof_limit=1048576)
        f = host.f
        owner_args = dict(target_node_entry=f["entries"]["descriptor"],
            expected_target=f["expected"]["expected_target"],
            expected_ack_slot=f["expected"]["expected_ack_slot"],
            root_entry=f["entries"]["root"], read_entry=f["entries"]["read"],
            bootstrap_entry=f["entries"]["bootstrap"])
        bound_tuple = {name: host.expected[name] for name in
            ("expected_receipt_writer", "expected_message_id", "expected_envelope_ref")}
        # A new observation of an old scope cannot silently replace the floor
        # that the source has actually shown in its independently read proof.
        old = f["entries"]["owner_status"]
        old_scopes = {row["scope_id"] for row in json.loads(old["raw"])["payload"]["entries"]}
        new = json.loads(host.expected["current_statuses"][0]["raw"])["payload"]
        new["entries"] = [row for row in new["entries"] if row["scope_id"] not in old_scopes]
        statuses = [old, signed_entry(new, f["signers"]["owner"], "roundtrip_new_authorities"),
            f["entries"]["target_status"]]
        common = dict(limit_policy=f["expected"]["limit_policy"],
            transport=host.http.transport, allow_loopback=True)
        binder = OwnerAckBindClient(f["signers"]["owner"], f["encryption"]["owner"],
            policy=host.fixture.local, **common)
        self.assertEqual(host.fixture.usage(), (0, 0, 0, 0))
        bound = binder.bind(host.http.base, **owner_args, **bound_tuple,
            write_entry=host.write, offer_bootstrap_entry=host.offer,
            current_statuses=statuses, read_until=host.expected["read_until"],
            retain_until=host.expected["retain_until"])
        after_bind = host.fixture.usage()
        self.assertEqual(host.source.db.execute("SELECT status FROM open_repair_ack_resources").fetchone()[0], "empty")
        self.assertGreater(after_bind[1], 0)

        host.source.now[0] = 2_000_000_008
        self.enterContext(patch("time.time", return_value=2_000_000_008))
        original = SimpleNamespace(h=host.source, expected=host.expected | dict(current_statuses=statuses),
            write=host.write, bound={"binding":dict(raw=bound.source.binding.raw, ref=bound.source.binding.ref.as_dict())})
        receipt, disclosure, put, put_options = receipt_inputs(original)
        writer = AckReceiptClient(f["signers"]["writer"], f["encryption"]["writer"], **common)
        committed = writer.put(host.http.base, receipt, disclosure, put, **put_options,
            target_node_entry=owner_args["target_node_entry"], expected_target=owner_args["expected_target"],
            expected_ack_slot=owner_args["expected_ack_slot"], expected_owner=f["expected"]["expected_owner"],
            root_entry=owner_args["root_entry"], write_entry=host.write, bootstrap_entry=host.offer,
            expected_message_id=bound_tuple["expected_message_id"], expected_envelope_ref=bound_tuple["expected_envelope_ref"])
        after_put = host.fixture.usage()
        self.assertGreater(after_put[0], after_bind[0])
        self.assertGreater(after_put[1], after_bind[1])
        self.assertEqual(committed.source.inputs["receipt"].raw, receipt["raw"])
        self.assertEqual(committed.source.predecessor.custody.ref, bound.source.custody.ref)

        host.http.restart()
        self.assertEqual(host.fixture.usage(), after_put)
        reader = AckOwnerRecoveryClient(f["signers"]["owner"], f["encryption"]["owner"],
            policy=host.fixture.local, **common)
        recovered = reader.recover_occupied(host.http.base, **owner_args, **bound_tuple,
            known_statuses=put_options["current_statuses"], archive_statuses=statuses)
        final_usage = host.fixture.usage()
        self.assertEqual(recovered.source.inputs["receipt"].raw, receipt["raw"])
        self.assertEqual(recovered.source.inputs["receipt"].ref.as_dict(), receipt["ref"])
        self.assertEqual(recovered.source.commit.ref, committed.source.commit.ref)
        self.assertEqual(recovered.source.predecessor.binding.ref, bound.source.binding.ref)
        self.assertEqual(final_usage[0] - after_put[0], recovered.metrics["requests"])
        self.assertGreater(final_usage[1], after_put[1])
        self.assertLessEqual(final_usage[1], 2048)
        self.assertLessEqual(final_usage[2], 1048576)
        self.assertEqual(host.source.db.execute("SELECT count(*) FROM open_repair_ack_resources").fetchone()[0], 1)
        self.assertEqual(host.source.db.execute("SELECT count(*) FROM open_repair_ack_bindings").fetchone()[0], 1)
        self.assertEqual(host.source.db.execute("SELECT count(*) FROM open_repair_ack_commits").fetchone()[0], 1)
        self.assertEqual(host.source.db.execute("SELECT status FROM open_repair_ack_resources").fetchone()[0], "occupied")
        self.assertEqual(host.source.db.execute("SELECT count(*) FROM open_repair_bootstrap_work WHERE signature_checks IS NULL").fetchone()[0], 0)
        self.assertEqual(host.source.db.execute("SELECT sum(signature_checks) FROM open_repair_bootstrap_work").fetchone()[0], final_usage[1])
        self.metrics = dict(after_bind=after_bind, after_put=after_put, after_recovery=final_usage,
            owner=dict(recovered.metrics), writer=dict(committed.metrics), receipt_bytes=len(receipt["raw"]))


if __name__ == "__main__":
    unittest.main()
