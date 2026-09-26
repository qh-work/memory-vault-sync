"""Actual packed contact originals consumed with one finite work meter.

Synthetic old-protocol signatures prove the contact subchain at a supplied
time. They do not prove the new repair resource/consent graph or a live grant.
"""
import hashlib
import unittest

from memory_vault import canonical_bytes
import memory_vault_open_repair_original as original
import memory_vault_open_repair_wire as wire
from tests import test_open_contact as contact_fixtures


class OpenRepairContactInputsTests(unittest.TestCase):
    def setUp(self):
        fixture = contact_fixtures.OpenContactProtocolTests()
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        self.fixture = fixture
        decision = fixture.make_decision()
        grant = decision["payload"]["grant"]
        self.raws = {name: canonical_bytes(value) for name, value in {
            "node": fixture.node, "knock_lease": fixture.lease,
            "policy": fixture.policy, "request": fixture.request,
            "decision": decision, "grant": grant,
            "delivery_lease": grant["payload"]["resource_lease"],
        }.items()}
        self.expected = dict(
            sender_key_id=fixture.sender.key_id,
            sender_encryption_key_id=fixture.sender_encryption.key_id,
            recipient_key_id=fixture.recipient.key_id,
            recipient_encryption_key_id=fixture.recipient_encryption.key_id,
            node_key_id=fixture.server.key_id,
            storage_epoch="synthetic_epoch", at=fixture.now + 1,
        )

    def packed_inputs(self, raws=None, signatures=7):
        raws = self.raws if raws is None else raws
        policy = wire.RepairPolicy(
            max_document_bytes=262144, max_total_bytes=4000000,
            max_nodes=100000, max_depth=64, max_string_bytes=65536,
            max_hash_bytes=4000000, max_hashes=500, max_entries=500,
            max_retained_bytes=4000000, max_signature_checks=signatures,
        )
        # Writer and consumer have distinct meters. The consumer never resets
        # its budget when moving from byte integrity to real signature checks.
        packed = wire.build_raw_pack(list(raws.values()), policy, wire.RepairBudget(policy))
        budget = wire.RepairBudget(policy)
        resolver = wire.LocalRawResolver(policy, budget)
        stored = resolver.put("meta", packed.ref.key, packed.raw)
        read = resolver.resolve(stored.ref)
        parsed = wire.parse_raw_pack(read.raw, stored.ref, policy, budget)
        positions = {entry.raw_sha256: i for i, entry in enumerate(parsed.entries)}
        inputs = {}
        for role, raw in raws.items():
            digest = hashlib.sha256(raw).hexdigest()
            reference = wire.RawRef("meta", digest, digest, len(raw))
            inputs[role] = parsed.entry(positions[digest], reference).raw
            self.assertEqual(inputs[role], raw)
        self.assertEqual(budget.snapshot()["signature_checks"], 0)
        return inputs, policy, budget

    def test_original_pack_to_approved_chain_uses_one_real_budget(self):
        inputs, policy, budget = self.packed_inputs()
        before = budget.snapshot()
        checked = original.verify_contact_originals(inputs, **self.expected, policy=policy, budget=budget)
        self.assertEqual(checked.at, self.expected["at"])
        self.assertEqual(set(checked.originals), set(self.raws))
        self.assertEqual(checked.originals["request"].payload["signing_key"]["key_id"], self.fixture.sender.key_id)
        self.assertEqual(checked.originals["decision"].payload["signing_key"]["key_id"], self.fixture.recipient.key_id)
        self.assertEqual(checked.originals["delivery_lease"].payload["signing_key"]["key_id"], self.fixture.server.key_id)
        for role, verified in checked.originals.items():
            self.assertEqual(verified.document.raw, self.raws[role])
            self.assertEqual(verified.raw_sha256, hashlib.sha256(self.raws[role]).hexdigest())
        after = budget.snapshot()
        self.assertEqual(after["signature_checks"], 7)
        self.assertGreater(after["hashes"], before["hashes"])
        self.assertGreater(after["input_bytes"], before["input_bytes"])
        self.assertEqual(after["retained_bytes"], before["retained_bytes"])
        with self.assertRaises(wire.RepairWireError) as caught:
            original.verify_contact_originals(inputs, **self.expected, policy=policy, budget=budget)
        self.assertEqual(caught.exception.code, "repair_over_budget")
        self.assertEqual(budget.snapshot()["signature_checks"], 7)

    def test_valid_pack_and_signatures_do_not_replace_literal_nested_originals(self):
        for role in ("grant", "delivery_lease"):
            with self.subTest(role=role):
                altered = dict(self.raws)
                # Same parsed value and valid signature, different original
                # bytes from the independently preserved parent Signed value.
                altered[role] = altered[role].replace(b'{"payload":', b'{"payload": ', 1)
                self.assertNotEqual(altered[role], self.raws[role])
                inputs, policy, budget = self.packed_inputs(altered)
                with self.assertRaises(wire.RepairWireError):
                    original.verify_contact_originals(inputs, **self.expected, policy=policy, budget=budget)

    def test_intact_packed_chain_cannot_choose_its_own_expected_recipient(self):
        inputs, policy, budget = self.packed_inputs()
        expected = {**self.expected, "recipient_key_id": self.fixture.other.key_id}
        with self.assertRaises(wire.RepairWireError):
            original.verify_contact_originals(inputs, **expected, policy=policy, budget=budget)


if __name__ == "__main__":
    unittest.main()
