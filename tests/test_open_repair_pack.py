"""Synthetic original-byte pack checks, not signature/repair acceptance."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError
import hashlib
from threading import Barrier
import unittest

import memory_vault_open_repair_wire as wire
from tests.test_open_repair_wire import policy


def frame(bodies):
    records = [(hashlib.sha256(raw).digest(), len(raw), raw) for raw in bodies]
    records.sort()
    return (b"MVRP1\0" + len(records).to_bytes(4, "big") +
            b"".join(size.to_bytes(8, "big") + digest + raw
                     for digest, size, raw in records))


def reference(raw, namespace="meta", key=None):
    digest = hashlib.sha256(raw).hexdigest()
    return wire.RawRef(namespace, key or digest, digest, len(raw))


class OpenRepairPackTests(unittest.TestCase):
    def assertCode(self, code, callback, *args):
        with self.assertRaises(wire.RepairWireError) as caught:
            callback(*args)
        self.assertEqual(caught.exception.code, code)

    def parse(self, raw, local=None):
        local = local or policy()
        return wire.parse_raw_pack(raw, reference(raw), local, wire.RepairBudget(local))

    def test_exact_binary_frame_preserves_originals_and_opaque_parent_refs(self):
        # Deliberately not new U53/canonical wire: the pack must not rewrite it.
        originals = [b' {"value":9223372036854775807,"proof":{"synthetic":true}}\r\n',
                     b"\xff\0synthetic-encrypted-bytes"]
        encoded = frame(originals)
        local = policy()
        budget = wire.RepairBudget(local)
        built = wire.build_raw_pack(originals[::-1], local, budget)
        self.assertEqual(built.raw, encoded)
        self.assertEqual(built.ref, reference(encoded))
        parsed = self.parse(encoded)
        for index, item in enumerate(parsed.entries):
            raw = next(value for value in originals if hashlib.sha256(value).hexdigest() == item.raw_sha256)
            expected = reference(raw, "object", "a" * 64)
            resolved = parsed.entry(index, expected)
            self.assertEqual(resolved.ref, expected)
            self.assertEqual(resolved.raw, raw)
            self.assertEqual(encoded[item.offset:item.offset + item.size], raw)
        self.assertEqual(budget.snapshot()["signature_checks"], 0)
        self.assertEqual(budget.snapshot()["hashes"], 3)
        self.assertEqual(budget.snapshot()["retained_bytes"], len(encoded) + 80)
        self.assertEqual(budget.snapshot()["entries"], 3)

    def test_builder_dedup_preserves_work_and_freezes_mutable_inputs(self):
        mutable = bytearray(b"synthetic original")
        local = policy()
        budget = wire.RepairBudget(local)
        built = wire.build_raw_pack([mutable, bytes(mutable)], local, budget)
        mutable[:] = b"changed"
        self.assertEqual(built.raw, frame([b"synthetic original"]))
        self.assertEqual(budget.snapshot()["input_bytes"], 2 * len(b"synthetic original"))
        self.assertEqual(budget.snapshot()["hashes"], 3)
        self.assertEqual(len(built.entries), 1)
        with self.assertRaises(FrozenInstanceError):
            built.entries[0].offset = 0
        with self.assertRaises(FrozenInstanceError):
            built.raw = b"changed"
        self.assertCode("repair_invalid_pack", wire.build_raw_pack, [], local, budget)
        self.assertCode("repair_invalid_pack", wire.build_raw_pack, [b""], local, budget)
        self.assertCode("repair_invalid_pack", wire.build_raw_pack, [built.raw], local, budget)

    def test_strict_framing_length_order_duplicates_and_nesting(self):
        one = frame([b"x"])
        two = frame([b"a", b"b"])
        cases = [b"BADRP1\0", one + b"\0", one[:-1],
                 b"MVRP1\0" + (0).to_bytes(4, "big"),
                 one[:10] + (0).to_bytes(8, "big") + one[18:],
                 one[:10] + (wire.U53_MAX + 1).to_bytes(8, "big") + one[18:],
                 one[:10] + ((1 << 64) - 1).to_bytes(8, "big") + one[18:],
                 one[:10] + (2).to_bytes(8, "big") + one[18:],
                 two[:10] + two[51:] + two[10:51],
                 b"MVRP1\0" + (2).to_bytes(4, "big") + one[10:] * 2,
                 frame([one])]
        for index, raw in enumerate(cases):
            with self.subTest(case=index):
                self.assertCode("repair_invalid_pack", self.parse, raw)

    def test_actual_pack_and_entry_hashes_and_explicit_locator_binding(self):
        encoded = frame([b"synthetic"])
        local = policy()
        wrong = wire.RawRef("meta", "0" * 64, "0" * 64, len(encoded))
        self.assertCode("repair_ref_mismatch", wire.parse_raw_pack,
                        encoded, wrong, local, wire.RepairBudget(local))
        for ref in (reference(encoded, "object"), reference(encoded, "meta", "a" * 64)):
            self.assertCode("repair_ref_mismatch", wire.parse_raw_pack,
                            encoded, ref, local, wire.RepairBudget(local))
        changed = encoded[:-1] + bytes([encoded[-1] ^ 1])
        self.assertCode("repair_ref_mismatch", self.parse, changed)
        parsed = self.parse(encoded)
        self.assertCode("repair_ref_mismatch", parsed.entry, 0, reference(b"other"))
        self.assertCode("repair_invalid_pack", parsed.entry, 1, reference(b"synthetic"))
        for invalid in (True, -1, 1.0, "0", wire.U53_MAX + 1):
            self.assertCode("repair_invalid_integer", parsed.entry, invalid, reference(b"synthetic"))

    def test_capacity_precedes_snapshot_hash_and_is_shared_with_resolver(self):
        encoded = frame([b"x"])
        for changes in ({"max_entries": 1}, {"max_retained_bytes": len(encoded) + 39},
                        {"max_document_bytes": len(encoded) - 1}):
            local = policy(**changes)
            budget = wire.RepairBudget(local)
            self.assertCode("repair_over_budget", wire.parse_raw_pack,
                            bytearray(encoded), reference(encoded), local, budget)
            self.assertEqual(budget.snapshot()["input_bytes"], 0)
            self.assertEqual(budget.snapshot()["hashes"], 0)
        local = policy(max_entries=2)
        budget = wire.RepairBudget(local)
        wire.parse_raw_pack(encoded, reference(encoded), local, budget)
        resolver = wire.LocalRawResolver(local, budget)
        self.assertCode("repair_over_budget", resolver.put, "object", "a" * 64, b"x")
        self.assertEqual(budget.snapshot()["entries"], 2)
        self.assertEqual(budget.snapshot()["hashes"], 2)

    def test_actual_copy_hash_costs_and_retry_budget_are_not_reset(self):
        encoded = frame([b"x"])
        local = policy(max_hashes=2)
        budget = wire.RepairBudget(local)
        parsed = wire.parse_raw_pack(encoded, reference(encoded), local, budget)
        used = budget.snapshot()
        self.assertEqual(used["hash_bytes"], len(encoded) + 1)
        self.assertEqual(used["nodes"], 1)
        self.assertCode("repair_over_budget", parsed.entry, 0, reference(b"x"))
        self.assertEqual(budget.snapshot()["hashes"], 2)
        self.assertEqual(budget.snapshot()["output_bytes"], 1)  # Actual attempted slice.
        self.assertCode("repair_over_budget", wire.parse_raw_pack,
                        encoded, reference(encoded), local, budget)
        self.assertEqual(budget.snapshot()["input_bytes"], 2 * len(encoded))
        self.assertEqual(budget.snapshot()["entries"], 2)

    def test_shared_budget_serializes_complete_pack_operations(self):
        encoded = frame([b"x"])
        local = policy(max_entries=2, max_hashes=2)
        budget = wire.RepairBudget(local)
        start = Barrier(2)
        def parse():
            start.wait(timeout=3)
            try:
                wire.parse_raw_pack(encoded, reference(encoded), local, budget)
                return "ok"
            except wire.RepairWireError as error:
                return error.code
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: parse(), range(2)))
        self.assertCountEqual(results, ["ok", "repair_over_budget"])
        self.assertEqual(budget.snapshot()["hashes"], 2)
        self.assertEqual(budget.snapshot()["entries"], 2)
