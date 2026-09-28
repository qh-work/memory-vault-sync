"""Real packed ACK setup originals, with one shared finite consumer budget."""
import base64
import copy
import hashlib
import unittest

from memory_vault import canonical_bytes
import memory_vault_open_repair_resource as resource
import memory_vault_open_repair_wire as wire
from tests.open_repair_resource_fixtures import ack_resource_fixture


class OpenRepairResourceInputsTests(unittest.TestCase):
    def setUp(self):
        self.docs, self.entries, self.expected, self.signers = ack_resource_fixture()

    def packed_inputs(self, entries=None):
        entries = self.entries if entries is None else entries
        policy = wire.RepairPolicy(262144, 8000000, 200000, 64, 65536,
                                   8000000, 500, 500, 8000000, 6)
        packed = wire.build_raw_pack([entry["raw"] for entry in entries.values()],
                                     policy, wire.RepairBudget(policy))
        budget = wire.RepairBudget(policy)
        resolver = wire.LocalRawResolver(policy, budget)
        stored = resolver.put("meta", packed.ref.key, packed.raw)
        parsed = wire.parse_raw_pack(resolver.resolve(stored.ref).raw,
                                     stored.ref, policy, budget)
        positions = {entry.raw_sha256: index for index, entry in enumerate(parsed.entries)}
        result = {}
        for role, entry in entries.items():
            ref = entry["ref"]
            self.assertNotEqual(ref["key"], ref["raw_sha256"])
            raw = parsed.entry(positions[ref["raw_sha256"]], ref).raw
            result[role] = {"raw": raw, "ref": ref}
        self.assertEqual(budget.snapshot()["signature_checks"], 0)
        return result, policy, budget

    def test_packed_setup_retains_parent_locators_and_shared_crypto_budget(self):
        inputs, policy, budget = self.packed_inputs()
        before = budget.snapshot()
        checked = resource.verify_ack_resource_inputs(inputs, **self.expected,
                                                       policy=policy, budget=budget)
        self.assertEqual(checked.activated_at, self.docs["active"]["payload"]["activated_at"])
        self.assertEqual(set(checked.originals), set(self.entries))
        # An owner's rights can outlive the original source's own promise.
        self.assertGreater(self.docs["root"]["payload"]["windows"]["retain_until"],
                           self.docs["offer"]["payload"]["windows"]["retain_until"])
        after = budget.snapshot()
        self.assertEqual(after["signature_checks"], 6)
        self.assertGreater(after["hashes"], before["hashes"])
        self.assertGreater(after["input_bytes"], before["input_bytes"])
        self.assertEqual(after["retained_bytes"], before["retained_bytes"])
        with self.assertRaises(wire.RepairWireError) as caught:
            resource.verify_ack_resource_inputs(inputs, **self.expected,
                                                 policy=policy, budget=budget)
        self.assertEqual(caught.exception.code, "repair_over_budget")
        self.assertEqual(budget.snapshot()["signature_checks"], 6)

    def test_valid_pack_cannot_change_parent_locator_without_new_parent_bytes(self):
        entries = copy.deepcopy(self.entries)
        entries["root"]["ref"]["key"] = "cd" * 32
        inputs, policy, budget = self.packed_inputs(entries)
        with self.assertRaises(wire.RepairWireError):
            resource.verify_ack_resource_inputs(inputs, **self.expected,
                                                 policy=policy, budget=budget)

    def test_packed_invalid_active_signature_is_charged_not_refunded(self):
        signed = copy.deepcopy(self.docs["active"])
        signature = bytearray(base64.b64decode(signed["proof"]["signature"]))
        signature[0] ^= 1
        signed["proof"]["signature"] = base64.b64encode(signature).decode()
        raw = canonical_bytes(signed)
        entries = copy.deepcopy(self.entries)
        entries["active"] = {"raw": raw, "ref": {**entries["active"]["ref"],
            "raw_sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}}
        inputs, policy, budget = self.packed_inputs(entries)
        with self.assertRaises(wire.RepairWireError) as caught:
            resource.verify_ack_resource_inputs(inputs, **self.expected,
                                                 policy=policy, budget=budget)
        self.assertEqual(caught.exception.code, "repair_invalid_signature")
        self.assertEqual(budget.snapshot()["signature_checks"], 6)


if __name__ == "__main__":
    unittest.main()
