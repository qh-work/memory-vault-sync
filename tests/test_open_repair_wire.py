"""Synthetic local draft-wire boundaries; not repair/authority acceptance."""
import base64
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import hashlib
import json
from pathlib import Path
from threading import Barrier, BrokenBarrierError
import unittest
from unittest.mock import patch

import memory_vault_open_repair_wire as wire


def policy(**changes):
    # Explicit test-only policy, not product defaults or measured live maxima.
    result = wire.RepairPolicy(
        max_document_bytes=65536, max_total_bytes=1000000,
        max_nodes=10000, max_depth=4096, max_string_bytes=65536,
        max_hash_bytes=1000000, max_hashes=100, max_entries=100,
        max_retained_bytes=1000000,
    )
    return replace(result, **changes)


class OpenRepairWireTests(unittest.TestCase):
    def assertCode(self, code, function, *args, **kwargs):
        with self.assertRaises(wire.RepairWireError) as caught:
            function(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def test_shared_original_byte_vectors(self):
        source = Path(__file__).resolve().parents[1] / "examples/protocol/open-repair-wire-v1.json"
        fixtures = json.loads(source.read_text(encoding="utf-8"))
        self.assertEqual(fixtures["schema_version"], "memory-vault-open-repair-wire-fixtures/v1")
        self.assertIs(fixtures["synthetic_only"], True)
        self.assertGreaterEqual(len(fixtures["cases"]), 36)
        for case in fixtures["cases"]:
            with self.subTest(case=case["id"]):
                raw = base64.b64decode(case["raw_base64"], validate=True)
                local = policy()
                budget = wire.RepairBudget(local)
                parse = wire.parse_new_json if case["mode"] == "strict" else wire.parse_new_wire
                expected = case["expected"]
                if expected["ok"]:
                    draft = parse(raw, local, budget)
                    self.assertEqual(draft.raw, raw)
                    self.assertEqual(draft.value, expected["value"])
                else:
                    self.assertCode(expected["code"], parse, raw, local, budget)
                self.assertEqual(budget.snapshot()["signature_checks"], 0)
                self.assertEqual(budget.snapshot()["hashes"], 0)

    def test_required_policy_is_finite_and_bound_to_meter(self):
        with self.assertRaises(TypeError):
            wire.RepairPolicy()
        for invalid in (True, False, 0, -1, 1.0, "10", wire.U53_MAX + 1):
            with self.subTest(invalid=invalid):
                self.assertCode("repair_invalid_policy", policy, max_nodes=invalid)
        local = policy(max_total_bytes=4)
        budget = wire.RepairBudget(local)
        larger = replace(local, max_total_bytes=400)
        self.assertCode("repair_invalid_policy", wire.parse_new_json, b"{}", larger, budget)
        with self.assertRaises(AttributeError):
            budget.policy = larger
        wire.parse_new_json(b"{}", local, budget)
        resolver = wire.LocalRawResolver(local, budget)  # Cannot clear prior work.
        with self.assertRaises(AttributeError):
            resolver.budget = wire.RepairBudget(local)
        with self.assertRaises(AttributeError):
            resolver.policy = larger
        wire.parse_new_json(b"{}", local, budget)
        self.assertCode("repair_over_budget", wire.parse_new_json, b"0", local, budget)
        self.assertEqual(budget.snapshot()["input_bytes"], 4)

    def test_raw_byte_limits_precede_copy_decode_and_hash(self):
        local = policy(max_document_bytes=3, max_total_bytes=3)
        budget = wire.RepairBudget(local)
        self.assertCode("repair_over_budget", wire.parse_new_wire, b"\xff\xff\xff\xff", local, budget)
        self.assertEqual(budget.snapshot()["input_bytes"], 0)
        self.assertEqual(budget.snapshot()["nodes"], 0)
        resolver = wire.LocalRawResolver(local, budget)
        self.assertCode("repair_over_budget", resolver.put, "object", "a" * 64, b"abcd")
        self.assertEqual(budget.snapshot()["hashes"], 0)
        self.assertEqual(budget.snapshot()["entries"], 0)
        self.assertCode("repair_invalid_utf8", wire.parse_new_json, b'"\xff"', local, budget)
        self.assertEqual(budget.snapshot()["input_bytes"], 3)
        self.assertCode("repair_over_budget", wire.parse_new_json, b"0", local, budget)

    def test_exact_node_depth_and_actual_canonical_output_meter(self):
        raw = b'{"a":[1]}'
        local = policy(max_total_bytes=len(raw) * 2, max_nodes=8, max_depth=3)
        budget = wire.RepairBudget(local)
        wire.parse_new_wire(raw, local, budget)
        self.assertEqual(budget.snapshot(), dict(
            input_bytes=9, output_bytes=9, nodes=8, string_bytes=2, max_depth=3,
            hash_bytes=0, hashes=0, entries=0, retained_bytes=0, signature_checks=0,
        ))
        for changes in ({"max_nodes": 7}, {"max_depth": 2}, {"max_total_bytes": 17}):
            with self.subTest(changes=changes):
                narrow = replace(local, **changes)
                meter = wire.RepairBudget(narrow)
                self.assertCode("repair_over_budget", wire.parse_new_wire, raw, narrow, meter)
                used = meter.snapshot()
                self.assertLessEqual(used["nodes"], narrow.max_nodes)
                self.assertLessEqual(used["input_bytes"] + used["output_bytes"], narrow.max_total_bytes)
        copied = budget.snapshot()
        copied["input_bytes"] = 0
        self.assertEqual(budget.snapshot()["input_bytes"], 9)

    def test_iterative_depth_above_interpreter_recursion_limit(self):
        depth = 1200
        raw = b"[" * depth + b"0" + b"]" * depth
        local = policy(max_depth=depth + 1, max_nodes=2 * (depth + 1))
        budget = wire.RepairBudget(local)
        value = wire.parse_new_wire(raw, local, budget).value
        for _ in range(depth):
            self.assertEqual(len(value), 1)
            value = value[0]
        self.assertEqual(value, 0)
        self.assertEqual(budget.snapshot()["max_depth"], depth + 1)

    def test_decoded_string_bound_and_failed_work_stays_charged(self):
        local = policy(max_string_bytes=3)
        budget = wire.RepairBudget(local)
        self.assertCode("repair_over_budget", wire.parse_new_json,
                        '"éxy"'.encode(), local, budget)
        self.assertEqual(budget.snapshot()["string_bytes"], 3)
        self.assertEqual(budget.snapshot()["input_bytes"], 6)
        valid = wire.parse_new_json(b'"\\u00e9x"', local, budget)
        self.assertEqual(valid.value, "éx")
        self.assertEqual(budget.snapshot()["string_bytes"], 6)

    def test_closed_fields_and_u53_do_not_confuse_bool_with_integer(self):
        local = policy()
        value = wire.parse_new_json(b'{"count":true,"extra":0}', local,
                                    wire.RepairBudget(local)).value
        self.assertCode("repair_unknown_fields", wire.object_fields, value, {"count"})
        wire.object_fields(value, {"count", "extra"})
        self.assertCode("repair_invalid_integer", wire.u53, value["count"])
        for invalid in (False, -1, 0.0, "0", wire.U53_MAX + 1):
            self.assertCode("repair_invalid_integer", wire.u53, invalid)
        self.assertEqual(wire.u53(wire.U53_MAX), wire.U53_MAX)
        self.assertCode("repair_invalid_integer", wire.u53, 0, 1)
        self.assertCode("repair_unknown_fields", wire.object_fields, [], set())
        self.assertCode("repair_unknown_fields", wire.object_fields, {1: "value"}, {1})

    def test_caller_mutation_does_not_change_fixed_raw(self):
        local = policy()
        raw = bytearray(b'{"draft":[0]}')
        draft = wire.parse_new_wire(raw, local, wire.RepairBudget(local))
        raw[:] = b"not-json-now!"
        with self.assertRaises(TypeError):
            draft.value["draft"][0] = 9
        with self.assertRaises(TypeError):
            draft.value.update(draft=[9])
        with self.assertRaises(TypeError):
            draft.value["draft"].append(9)
        self.assertEqual(draft.raw, b'{"draft":[0]}')
        reparsed = wire.parse_new_wire(draft.raw, local, wire.RepairBudget(local))
        self.assertEqual(reparsed.value, {"draft": [0]})

    def test_historical_originals_are_lossless_and_not_parsed_or_verified(self):
        local = policy()
        budget = wire.RepairBudget(local)
        resolver = wire.LocalRawResolver(local, budget)
        original = b' { "int64": 9223372036854775807, "synthetic": true }\r\n'
        mutable = bytearray(original)
        held = resolver.put("meta", "a" * 64, mutable)
        mutable[0] = 0
        self.assertEqual(held.raw, original)
        self.assertEqual(held.ref.raw_sha256, hashlib.sha256(original).hexdigest())
        self.assertNotEqual(held.ref.key, held.ref.raw_sha256)
        self.assertEqual(resolver.resolve(held.ref.as_dict()).raw, original)
        binary = b"\xff\x00synthetic-not-json"
        self.assertEqual(resolver.put("object", "b" * 64, binary).raw, binary)
        self.assertEqual(budget.snapshot()["nodes"], 0)
        self.assertEqual(budget.snapshot()["signature_checks"], 0)
        self.assertEqual(budget.snapshot()["output_bytes"], 0)

    def test_resolver_namespace_key_digest_size_and_conflicting_retries(self):
        local = policy()
        budget = wire.RepairBudget(local)
        resolver = wire.LocalRawResolver(local, budget)
        first = resolver.put("meta", "a" * 64, b"one")
        resolver.put("object", "a" * 64, b"two")
        self.assertCode("repair_ref_missing", resolver.resolve,
                        dict(first.ref.as_dict(), key="b" * 64))
        self.assertCode("repair_ref_mismatch", resolver.resolve,
                        dict(first.ref.as_dict(), namespace="object"))
        self.assertCode("repair_ref_mismatch", resolver.resolve,
                        dict(first.ref.as_dict(), size=2))
        self.assertCode("repair_ref_conflict", resolver.put, "meta", "a" * 64, b"two")
        self.assertEqual(resolver.resolve(first.ref).raw, b"one")
        for changes in ({"namespace": "anchor"}, {"key": "A" * 64},
                        {"raw_sha256": "x" * 64}, {"size": True}, {"size": 0},
                        {"size": wire.U53_MAX + 1}, {"extra": "no"}):
            with self.subTest(changes=changes):
                self.assertCode("repair_invalid_ref", wire.raw_ref,
                                dict(first.ref.as_dict(), **changes))

    def test_resolver_actual_repeated_hash_work_without_duplicate_retention(self):
        local = policy()
        budget = wire.RepairBudget(local)
        resolver = wire.LocalRawResolver(local, budget)
        first = resolver.put("object", "a" * 64, b"abc")
        resolver.put("object", "a" * 64, b"abc")
        resolver.get(first.ref)
        self.assertEqual(budget.snapshot(), dict(
            input_bytes=9, output_bytes=0, nodes=0, string_bytes=0, max_depth=0,
            hash_bytes=9, hashes=3, entries=1, retained_bytes=3, signature_checks=0,
        ))
        first.ref.as_dict()["size"] = 99
        self.assertEqual(resolver.get(first.ref).ref.size, 3)

    def test_resolver_limits_fail_before_new_hold_or_hash(self):
        for changes in ({"max_entries": 1}, {"max_retained_bytes": 3},
                        {"max_hashes": 1}, {"max_hash_bytes": 3}):
            with self.subTest(changes=changes):
                local = policy(**changes)
                budget = wire.RepairBudget(local)
                resolver = wire.LocalRawResolver(local, budget)
                resolver.put("object", "a" * 64, b"abc")
                self.assertCode("repair_over_budget", resolver.put, "object", "b" * 64, b"def")
                used = budget.snapshot()
                self.assertEqual(used["hashes"], 1)
                self.assertEqual(used["hash_bytes"], 3)
                self.assertEqual(used["entries"], 1)
                self.assertEqual(used["retained_bytes"], 3)
                self.assertCode("repair_ref_missing", resolver.resolve,
                                dict(namespace="object", key="b" * 64,
                                     raw_sha256=hashlib.sha256(b"def").hexdigest(), size=3))

    def test_shared_budget_serializes_real_concurrent_hash_work(self):
        local = policy(max_hashes=1)
        budget = wire.RepairBudget(local)
        resolver = wire.LocalRawResolver(local, budget)
        start = Barrier(2)
        inside_hash = Barrier(2)
        real_sha256 = hashlib.sha256

        def overlapping_real_hash(raw):
            # Without the operation lock both prechecks pass and both workers
            # cross this barrier. With the lock only one can enter, so its
            # bounded wait ends before it executes the real hash exactly once.
            try:
                inside_hash.wait(timeout=0.5)
            except BrokenBarrierError:
                pass
            return real_sha256(raw)

        def put(key):
            start.wait(timeout=5)
            try:
                return resolver.put("object", key * 64, b"abc")
            except wire.RepairWireError as error:
                return error.code

        with patch.object(wire.hashlib, "sha256", side_effect=overlapping_real_hash) as actual:
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(put, key) for key in ("a", "b")]
                results = [future.result(timeout=5) for future in futures]
        accepted = [value for value in results if type(value) is wire.RawOriginal]
        self.assertEqual(len(accepted), 1)
        self.assertEqual(results.count("repair_over_budget"), 1)
        self.assertEqual(actual.call_count, 1)
        self.assertEqual(accepted[0].ref.raw_sha256, real_sha256(b"abc").hexdigest())
        used = budget.snapshot()
        self.assertEqual(used["hashes"], 1)
        self.assertEqual(used["hash_bytes"], 3)
        self.assertEqual(used["entries"], 1)
        self.assertEqual(used["retained_bytes"], 3)
        self.assertEqual(used["signature_checks"], 0)


if __name__ == "__main__":
    unittest.main()
