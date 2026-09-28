"""Synthetic actual bootstrap proofs; no probe, current permission or custody."""
import base64
import copy
from dataclasses import replace
import hashlib
import json
import unittest

from memory_vault import canonical_bytes
import memory_vault_open_repair_bootstrap as bootstrap
import memory_vault_open_repair_wire as wire
from tests.open_repair_resource_fixtures import ack_resource_fixture


LIMITS = dict(max_probe_bytes=512, max_proof_bytes=4096, max_proof_items=4,
              max_signature_checks=16, max_requests=16, max_pending=2,
              max_replay_records=16, max_concurrent_handles=2, max_candidate_attempts=2)


def policy(**changes):
    return replace(wire.RepairPolicy(65536, 4000000, 100000, 100, 65536,
                                   4000000, 1000, 1000, 4000000, 100), **changes)


class OpenRepairBootstrapTests(unittest.TestCase):
    def setUp(self):
        docs, _, expected, signers = ack_resource_fixture()
        self.signer, self.other_signer = signers["owner"], signers["target"]
        self.expected = dict(expected_ack_slot=expected["expected_ack_slot"],
                             expected_owner=expected["expected_owner"],
                             at=2_000_000_005, limit_policy=copy.deepcopy(LIMITS))
        self.payloads = {name: copy.deepcopy(docs[name]["payload"]) for name in ("root", "read")}
        for payload in self.payloads.values():
            payload["budget"]["max_items"] = 16
        root = self.payloads["root"]
        root["allowed_roles"] = sorted(set(root["allowed_roles"]) |
                                       {"ack_owner_service_v1", "bootstrap.grant", "ack.write_grant"})
        self.payloads["bootstrap"] = dict(
            schema_version="memory-vault-open-repair/v1", kind="bootstrap.grant",
            signing_key=self.signer.public_descriptor(), issued_at=2_000_000_004,
            expires_at=2_000_000_120, grant_id="synthetic_owner_bootstrap", revision=1,
            owner=root["owner"], subject=root["owner"], root_key=self.expected["expected_ack_slot"]["root_key"],
            consumer="ack_owner", selector={}, parent_authority_ref={}, caller_authority_ref={},
            probe_until=2_000_000_100, proof_until=2_000_000_100, upload_until=2_000_000_100,
            probe_profile="opaque_v1", response_profile="ack_owner_service_v1",
            upload_roles=["ack.read_grant", "ack.root_authority", "ack.write_grant", "bootstrap.grant"],
            limits=copy.deepcopy(LIMITS))
        self.entries = self.rebuilt()

    def rebuilt(self, changes=None, signers=None):
        """Every change receives actual signatures and exact downstream refs."""
        changes, signers, entries = changes or {}, signers or {}, {}
        payloads = copy.deepcopy(self.payloads)
        for role in ("root", "read", "bootstrap"):
            payload = payloads[role]
            if role == "read":
                payload["root_authority_ref"] = entries["root"]["ref"]
            elif role == "bootstrap":
                payload["parent_authority_ref"] = entries["root"]["ref"]
                payload["caller_authority_ref"] = entries["read"]["ref"]
                payload["selector"] = dict(
                    root_key_sha256=hashlib.sha256(canonical_bytes(payload["root_key"])).hexdigest(),
                    ack_slot_sha256=hashlib.sha256(canonical_bytes(self.expected["expected_ack_slot"])).hexdigest(),
                    root_authority_sha256=entries["root"]["ref"]["raw_sha256"],
                    read_grant_sha256=entries["read"]["ref"]["raw_sha256"])
            payload.update(changes.get(role, {}))
            signer = signers.get(role, self.signer)
            payload["signing_key"] = signer.public_descriptor()
            raw = canonical_bytes(dict(payload=payload, proof=signer.sign_message(payload)))
            entries[role] = dict(raw=raw, ref=dict(namespace="meta",
                key=hashlib.sha256(("synthetic_bootstrap_locator:" + role).encode()).hexdigest(),
                raw_sha256=hashlib.sha256(raw).hexdigest(), size=len(raw)))
        return entries

    def verify(self, entries=None, local=None, budget=None, **expected):
        entries, local = self.entries if entries is None else entries, local or policy()
        return bootstrap.verify_ack_owner_bootstrap_original(entries["bootstrap"],
            {name: entries[name] for name in ("root", "read")}, **(self.expected | expected),
            policy=local, budget=budget or wire.RepairBudget(local))

    def assertCode(self, code, operation, *args, **kwargs):
        with self.assertRaises(wire.RepairWireError) as caught:
            operation(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def test_three_actual_signatures_full_refs_and_shared_meter(self):
        local = policy(max_signature_checks=3)
        meter = wire.RepairBudget(local)
        result = self.verify(local=local, budget=meter)
        self.assertEqual(result.at, self.expected["at"])
        self.assertEqual(set(result.originals), {"root", "read", "bootstrap"})
        for name, item in result.originals.items():
            self.assertEqual(item.raw, self.entries[name]["raw"])
            self.assertEqual(item.ref.as_dict(), self.entries[name]["ref"])
            self.assertNotEqual(item.ref.key, item.ref.raw_sha256)
        work = meter.snapshot()
        self.assertEqual((work["signature_checks"], work["hashes"]), (3, 13))
        self.assertEqual(work["retained_bytes"], 0)
        self.assertCode("repair_over_budget", self.verify, local=local, budget=meter)
        self.assertEqual(meter.snapshot()["signature_checks"], 3)
        self.assertGreater(meter.snapshot()["hashes"], work["hashes"])

    def test_original_bytes_and_expected_objects_are_snapshots(self):
        entries, slot = copy.deepcopy(self.entries), copy.deepcopy(self.expected["expected_ack_slot"])
        entries["root"]["raw"] = bytearray(entries["root"]["raw"])
        entries["bootstrap"]["raw"] = bytearray(entries["bootstrap"]["raw"])
        result = self.verify(entries, expected_ack_slot=slot)
        entries["root"]["raw"][:] = b"x" * len(entries["root"]["raw"])
        entries["bootstrap"]["ref"]["key"] = "0" * 64
        slot["slot_id"] = "changed_after_verification"
        self.assertEqual(result.originals["root"].raw, self.entries["root"]["raw"])
        self.assertEqual(result.originals["bootstrap"].ref.as_dict(), self.entries["bootstrap"]["ref"])
        self.assertEqual(result.originals["read"].payload["ack_slot"], self.expected["expected_ack_slot"])
        with self.assertRaises(TypeError):
            result.originals["root"] = None
        with self.assertRaises(TypeError):
            result.originals["bootstrap"].payload["limits"]["max_requests"] = 999
        with self.assertRaises(AttributeError):
            result.originals["root"].raw = b"{}"

    def test_independent_owner_slot_and_bounded_expected_input(self):
        other = ack_resource_fixture()[2]["expected_owner"]
        self.assertCode("repair_bootstrap_mismatch", self.verify, expected_owner=other)
        slot = copy.deepcopy(self.expected["expected_ack_slot"])
        slot["grant_id"] = "other_future_write_grant"
        self.assertCode("repair_bootstrap_mismatch", self.verify, expected_ack_slot=slot)
        local = policy(max_nodes=1)
        meter = wire.RepairBudget(local)
        self.assertCode("repair_over_budget", self.verify, local=local, budget=meter)
        self.assertEqual(meter.snapshot()["signature_checks"], 0)
        for role in ("root", "read", "bootstrap"):
            with self.subTest(role=role):
                self.assertCode("repair_wrong_issuer", self.verify,
                                self.rebuilt(signers={role: self.other_signer}))

    def test_canonical_q_full_ref_and_untrusted_reference_wrappers(self):
        for field, value in (("size", 1), ("raw_sha256", "0" * 64)):
            entries = copy.deepcopy(self.entries)
            entries["root"]["ref"][field] = value
            self.assertCode("repair_ref_mismatch", self.verify, entries)
        entries = copy.deepcopy(self.entries)
        entries["root"]["raw"] = b" " + entries["root"]["raw"]
        self.assertCode("repair_noncanonical_json", self.verify, entries)
        entries = copy.deepcopy(self.entries)
        entries["root"]["ref"] = wire.RawRef(**entries["root"]["ref"])
        self.assertCode("repair_invalid_bootstrap", self.verify, entries)
        entries = copy.deepcopy(self.entries)
        entries["root"]["ref"]["namespace"] = "object"
        self.assertCode("repair_invalid_bootstrap", self.verify, entries)
        entries = copy.deepcopy(self.entries)
        entries["read"]["extra"] = True
        self.assertCode("repair_invalid_bootstrap", self.verify, entries)

    def test_parent_refs_bind_all_four_fields_and_selector_uses_original_digest(self):
        for role, field, parent in (("read", "root_authority_ref", "root"),
                                    ("bootstrap", "parent_authority_ref", "root"),
                                    ("bootstrap", "caller_authority_ref", "read")):
            for part, value in (("key", "0" * 64), ("raw_sha256", "0" * 64), ("size", 1)):
                with self.subTest(role=role, field=field, part=part):
                    changed = self.entries[parent]["ref"] | {part: value}
                    self.assertCode("repair_bootstrap_mismatch", self.verify, self.rebuilt({role: {field: changed}}))
        selector = json.loads(self.entries["bootstrap"]["raw"])["payload"]["selector"]
        for name in selector:
            self.assertCode("repair_bootstrap_mismatch", self.verify,
                self.rebuilt({"bootstrap": {"selector": selector | {name: self.entries["root"]["ref"]["key"]}}}))

    def test_parent_shapes_permissions_and_subject_are_closed(self):
        other_id = ack_resource_fixture()[2]["expected_ack_slot"]["root_key"]["owner"]
        invalid = ({"bootstrap": {"consumer": "ack_offer"}},
                   {"bootstrap": {"response_profile": "ack_offer_service_v1"}},
                   {"bootstrap": {"future_write_grant_ref": self.entries["read"]["ref"]}},
                   {"root": {"max_bindings": True}}, {"root": {"max_receipts": 2}},
                   {"root": {"windows": self.payloads["root"]["windows"] | {"retain_until": {}}}})
        for changes in invalid:
            self.assertCode("repair_invalid_bootstrap", self.verify, self.rebuilt(changes))
        mismatches = ({"bootstrap": {"subject": other_id}}, {"read": {"reader": other_id}},
                      {"root": {"operation_mask": 2}}, {"read": {"operation_mask": 8}},
                      {"root": {"allowed_roles": ["ack.read_grant", "ack.root_authority"]}})
        for changes in mismatches:
            self.assertCode("repair_bootstrap_mismatch", self.verify, self.rebuilt(changes))
        # This subset requires only discovery and read, without inventing live
        # retention permission; custody integration requires its extra bits.
        self.verify(self.rebuilt({"root": {"operation_mask": 10}}))

    def test_parent_narrowing_cannot_expand_read_budget_windows_or_mask(self):
        changes = ({"read": {"budget": self.payloads["read"]["budget"] | {"max_live_bytes": 999999}}},
                   {"read": {"windows": {name: 2_000_003_500 for name in self.payloads["read"]["windows"]}}},
                   {"root": {"operation_mask": 10}, "read": {"operation_mask": 18}})
        for change in changes:
            self.assertCode("repair_bootstrap_mismatch", self.verify, self.rebuilt(change))

    def test_explicit_time_and_parent_causality_without_future_skew(self):
        for at in (2_000_000_003, 2_000_000_120):
            self.assertCode("repair_invalid_bootstrap", self.verify, at=at)
        cases = ({"read": {"issued_at": 2_000_000_001}},
                 {"bootstrap": {"issued_at": 2_000_000_002}},
                 {"bootstrap": {"issued_at": 2_000_000_006}},
                 {"bootstrap": {"expires_at": 2_000_004_500}},
                 {"root": {"expires_at": 2_000_003_500}})
        for change in cases:
            self.assertCode("repair_invalid_bootstrap", self.verify, self.rebuilt(change))
        # Same-second setup events and revision zero are valid Q values.
        self.verify(self.rebuilt({"root": {"issued_at": 2_000_000_003, "revision": 0},
                                  "read": {"issued_at": 2_000_000_003, "revision": 0},
                                  "bootstrap": {"issued_at": 2_000_000_003, "revision": 0}}))

    def test_phase_deadlines_narrow_the_action_without_claiming_all_phases_live(self):
        for name in ("probe_until", "proof_until", "upload_until"):
            for value in (2_000_000_004, 2_000_000_121):
                self.assertCode("repair_invalid_bootstrap", self.verify,
                                self.rebuilt({"bootstrap": {name: value}}))
        deadlines = {name: self.expected["at"] for name in ("probe_until", "proof_until", "upload_until")}
        self.verify(self.rebuilt({"bootstrap": deadlines}))
        windows = {name: 2_000_000_030 for name in self.payloads["read"]["windows"]}
        self.assertCode("repair_bootstrap_mismatch", self.verify, self.rebuilt({"read": {"windows": windows}}))

    def test_nine_finite_positive_grant_and_policy_limits(self):
        for name in LIMITS:
            with self.subTest(name=name):
                self.assertCode("repair_invalid_bootstrap", self.verify,
                    self.rebuilt({"bootstrap": {"limits": LIMITS | {name: 0}}}))
                self.assertCode("repair_bootstrap_mismatch", self.verify,
                                limit_policy=LIMITS | {name: LIMITS[name] - 1})
                self.assertCode("repair_invalid_bootstrap", self.verify, limit_policy=LIMITS | {name: False})
        self.assertCode("repair_invalid_bootstrap", self.verify,
                        limit_policy={key: value for key, value in LIMITS.items() if key != "max_signature_checks"})
        self.assertCode("repair_invalid_bootstrap", self.verify, limit_policy=LIMITS | {"unbounded": True})

    def test_every_parent_cap_mapping_is_applied_without_old_provider_minimums(self):
        for name in ("max_meta_bytes", "max_job_bytes", "max_items", "max_requests",
                     "max_pending", "max_replay_records", "max_jobs"):
            for role in ("root", "read"):
                with self.subTest(name=name, role=role):
                    changes = {role: {"budget": self.payloads[role]["budget"] | {name: 0}}}
                    self.assertCode("repair_bootstrap_mismatch", self.verify, self.rebuilt(changes))
        limits = {name: 1 for name in LIMITS}
        self.verify(self.rebuilt({"bootstrap": {"limits": limits}}), limit_policy=limits)

    def test_upload_registry_parent_subset_and_future_role_name_without_body(self):
        for roles in (["ack.root_authority", "ack.read_grant"], ["bootstrap.grant", "bootstrap.grant"],
                      ["contact.request"]):
            self.assertCode("repair_invalid_bootstrap", self.verify,
                            self.rebuilt({"bootstrap": {"upload_roles": roles}}))
        narrowed = [name for name in self.payloads["root"]["allowed_roles"] if name != "ack.write_grant"]
        self.assertCode("repair_bootstrap_mismatch", self.verify, self.rebuilt({"root": {"allowed_roles": narrowed}}))
        self.verify(self.rebuilt({"bootstrap": {"upload_roles": []}}))
        self.verify()  # A permitted future role name does not require its body.

    def test_failed_signature_and_shared_hash_budget_never_refund_work(self):
        entries = copy.deepcopy(self.entries)
        signed = json.loads(entries["bootstrap"]["raw"])
        signed["proof"]["signature"] = base64.b64encode(b"\0" * 64).decode()
        raw = canonical_bytes(signed)
        entries["bootstrap"]["raw"] = raw
        entries["bootstrap"]["ref"].update(raw_sha256=hashlib.sha256(raw).hexdigest(), size=len(raw))
        local = policy()
        meter = wire.RepairBudget(local)
        self.assertCode("repair_invalid_signature", self.verify, entries, local=local, budget=meter)
        self.assertEqual(meter.snapshot()["signature_checks"], 3)
        self.assertEqual(meter.snapshot()["hashes"], 11)
        local = policy(max_hashes=12)
        meter = wire.RepairBudget(local)
        self.assertCode("repair_over_budget", self.verify, local=local, budget=meter)
        self.assertEqual((meter.snapshot()["signature_checks"], meter.snapshot()["hashes"]), (3, 12))


if __name__ == "__main__":
    unittest.main()
