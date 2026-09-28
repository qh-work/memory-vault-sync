"""Actual owner signatures for one exact synthetic post-envelope ACK grant."""
import base64
import copy
from dataclasses import replace
import hashlib
import json
import unittest

from memory_vault import canonical_bytes
import memory_vault_open_repair_bound as bound
import memory_vault_open_repair_wire as wire
from tests.open_repair_bound_fixtures import LIMITS, ack_bound_fixture, rebuild_bound_fixture


def policy(**changes):
    return replace(wire.RepairPolicy(65536, 4000000, 100000, 100, 65536,
                                   4000000, 1000, 1000, 4000000, 100), **changes)


class OpenRepairBoundTests(unittest.TestCase):
    def setUp(self):
        self.f = ack_bound_fixture()

    def rebuilt(self, changes=None, signers=None):
        return rebuild_bound_fixture(self.f, changes, signers)

    def verify(self, entries=None, *, offer=True, local=None, meter=None, **expected):
        entries, local = entries or self.f["entries"], local or policy()
        args = self.f["expected"] | expected
        args.update(policy=local, budget=meter or wire.RepairBudget(local))
        if offer:
            args.setdefault("limit_policy", self.f["limit_policy"])
            return bound.verify_ack_offer_bootstrap_original(entries["bootstrap"],
                {name: entries[name] for name in ("root", "write")}, **args)
        return bound.verify_ack_write_grant_original(entries["write"], entries["root"], **args)

    def assertCode(self, code, operation, *args, **kwargs):
        with self.assertRaises(wire.RepairWireError) as caught:
            operation(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def test_real_two_and_three_signature_closures_keep_exact_originals(self):
        for offer, signatures in ((False, 2), (True, 3)):
            local = policy(max_signature_checks=signatures)
            meter = wire.RepairBudget(local)
            result = self.verify(offer=offer, local=local, meter=meter)
            self.assertEqual(set(result.originals), {"root", "write", "bootstrap"} if offer else {"root", "write"})
            for role, item in result.originals.items():
                self.assertEqual(item.raw, self.f["entries"][role]["raw"])
                self.assertEqual(item.ref.as_dict(), self.f["entries"][role]["ref"])
                self.assertNotEqual(item.ref.key, item.ref.raw_sha256)
            self.assertEqual(meter.snapshot()["signature_checks"], signatures)
            self.assertEqual(result.at, self.f["expected"]["at"])
            previous = meter.snapshot()
            self.assertCode("repair_over_budget", self.verify, offer=offer, local=local, meter=meter)
            self.assertEqual(meter.snapshot()["signature_checks"], signatures)
            self.assertGreater(meter.snapshot()["hashes"], previous["hashes"])

    def test_immutable_snapshots_and_no_trust_in_public_result_wrappers(self):
        entries, expected = copy.deepcopy(self.f["entries"]), copy.deepcopy(self.f["expected"])
        entries["write"]["raw"] = bytearray(entries["write"]["raw"])
        result = self.verify(entries, **expected)
        entries["write"]["raw"][:] = b"x" * len(entries["write"]["raw"])
        expected["expected_ack_slot"]["grant_id"] = "changed"
        self.assertEqual(result.originals["write"].raw, self.f["entries"]["write"]["raw"])
        with self.assertRaises(TypeError):
            result.originals["write"] = None
        with self.assertRaises(TypeError):
            result.originals["bootstrap"].payload["limits"]["max_requests"] = 999
        with self.assertRaises(AttributeError):
            result.at = 0
        entries = copy.deepcopy(self.f["entries"])
        entries["root"]["ref"] = wire.RawRef(**entries["root"]["ref"])
        self.assertCode("repair_invalid_ack_bound", self.verify, entries)
        entries["root"] = result.originals["root"]
        self.assertCode("repair_invalid_ack_bound", self.verify, entries)

    def test_full_independent_owner_writer_and_preselected_slot(self):
        other = ack_bound_fixture()
        for name in ("expected_owner", "expected_receipt_writer", "expected_ack_slot"):
            self.assertCode("repair_ack_bound_mismatch", self.verify, **{name: other["expected"][name]})
        for field in ("signing_key", "encryption_key"):
            changed = copy.deepcopy(self.f["expected"]["expected_receipt_writer"])
            changed[field] = other["expected"]["expected_receipt_writer"][field]
            self.assertCode("repair_ack_bound_mismatch", self.verify, expected_receipt_writer=changed)
            # A matching claimed ID does not excuse a different actual public
            # key. Both independent descriptors are recomputed before work.
            changed = copy.deepcopy(self.f["expected"]["expected_receipt_writer"])
            changed[field]["public_key"] = other["expected"]["expected_receipt_writer"][field]["public_key"]
            local, meter = policy(), wire.RepairBudget(policy())
            self.assertCode("repair_invalid_original", self.verify, expected_receipt_writer=changed,
                            local=local, meter=meter)
            self.assertEqual(meter.snapshot()["signature_checks"], 0)
        self.assertCode("repair_ack_bound_mismatch", self.verify,
            self.rebuilt({"write": {"grant_id": "not_the_preselected_grant"}}))
        for role in ("root", "write", "bootstrap"):
            self.assertCode("repair_wrong_issuer", self.verify,
                self.rebuilt(signers={role: self.f["signers"]["writer"]}))

    def test_exact_message_and_all_envelope_reference_fields(self):
        self.assertCode("repair_ack_bound_mismatch", self.verify,
            self.rebuilt({"write": {"message_id": "msg_" + "ac" * 32}}))
        envelope = self.f["expected"]["expected_envelope_ref"]
        for field, value in (("namespace", "meta"), ("key", "ad" * 32),
                             ("raw_sha256", "ae" * 32), ("size", envelope["size"] + 1)):
            with self.subTest(field=field):
                self.assertCode("repair_ack_bound_mismatch", self.verify,
                    self.rebuilt({"write": {"envelope_ref": envelope | {field: value}}}))
        self.assertCode("repair_invalid_ack_bound", self.verify,
            self.rebuilt({"write": {"message_id": "synthetic_without_msg_digest"}}))
        self.assertCode("repair_invalid_ack_bound", self.verify,
            self.rebuilt({"write": {"envelope_ref": envelope | {"size": True}}}))

    def test_all_parent_ref_parts_and_selector_raw_hashes(self):
        entries = self.f["entries"]
        for role, field, parent in (("write", "root_authority_ref", "root"),
                                    ("bootstrap", "parent_authority_ref", "root"),
                                    ("bootstrap", "caller_authority_ref", "write")):
            for part, value in (("key", "0" * 64), ("raw_sha256", "0" * 64), ("size", 1)):
                self.assertCode("repair_ack_bound_mismatch", self.verify,
                    self.rebuilt({role: {field: entries[parent]["ref"] | {part: value}}}))
        selector = json.loads(entries["bootstrap"]["raw"])["payload"]["selector"]
        for name in selector:
            self.assertCode("repair_ack_bound_mismatch", self.verify,
                self.rebuilt({"bootstrap": {"selector": selector | {name: entries["root"]["ref"]["key"]}}}))

    def test_write_is_receipt_only_and_offer_subject_is_exact_writer(self):
        for change in ({"operation": "message.send"}, {"max_receipts": 2}, {"max_receipts": True},
                       {"operation_mask": 127}, {"future_receipt_ref": self.f["entries"]["root"]["ref"]}):
            self.assertCode("repair_invalid_ack_bound", self.verify, self.rebuilt({"write": change}))
        for change in ({"consumer": "ack_owner"}, {"response_profile": "ack_owner_service_v1"},
                       {"probe_profile": "full_originals"}):
            self.assertCode("repair_invalid_ack_bound", self.verify, self.rebuilt({"bootstrap": change}))
        self.assertCode("repair_ack_bound_mismatch", self.verify,
            self.rebuilt({"bootstrap": {"subject": self.f["payloads"]["root"]["owner"]}}))
        self.assertCode("repair_ack_bound_mismatch", self.verify,
            self.rebuilt({"write": {"receipt_writer": self.f["payloads"]["root"]["owner"]}}))

    def test_operation_and_disclosure_permissions_narrow_independently(self):
        for mask in (0, 2, 8, 10):
            self.assertCode("repair_ack_bound_mismatch", self.verify,
                self.rebuilt({"root": {"operation_mask": mask}}), offer=False)
        self.verify(self.rebuilt({"root": {"operation_mask": 1}}), offer=False)
        for mask in (1, 3, 9, 10):
            self.assertCode("repair_ack_bound_mismatch", self.verify,
                self.rebuilt({"root": {"operation_mask": mask}}))
        self.verify(self.rebuilt({"root": {"operation_mask": 11}}))
        for removed in ("bootstrap.grant", "ack_offer_service_v1", "ack.write_grant"):
            roles = [role for role in self.f["payloads"]["root"]["allowed_roles"] if role != removed]
            self.assertCode("repair_ack_bound_mismatch", self.verify,
                self.rebuilt({"root": {"allowed_roles": roles}}))
        for roles in (["ack.read_grant"], ["bootstrap.grant", "ack.write_grant"],
                      ["bootstrap.grant", "bootstrap.grant"], ["ack.put"]):
            self.assertCode("repair_invalid_ack_bound", self.verify,
                self.rebuilt({"bootstrap": {"upload_roles": roles}}))
        self.verify(self.rebuilt({"bootstrap": {"upload_roles": []}}))

    def test_write_budget_windows_and_expiry_cannot_expand_parent(self):
        write = self.f["payloads"]["write"]
        for field in write["budget"]:
            self.assertCode("repair_ack_bound_mismatch", self.verify,
                self.rebuilt({"write": {"budget": write["budget"] | {field: write["budget"][field] + 1}}}))
        expanded = {name: 2_000_003_500 for name in write["windows"]}
        self.assertCode("repair_ack_bound_mismatch", self.verify,
            self.rebuilt({"write": {"expires_at": 2_000_004_000, "windows": expanded}}))
        self.assertCode("repair_invalid_ack_bound", self.verify,
            self.rebuilt({"write": {"expires_at": 2_000_006_000}}))

    def test_q_clock_causality_and_exact_event_boundaries(self):
        for at in (2_000_000_001, 2_000_000_006, 2_000_000_900):
            self.assertCode("repair_invalid_ack_bound", self.verify, at=at)
        for changes in ({"write": {"issued_at": 2_000_000_001}},
                        {"bootstrap": {"issued_at": 2_000_000_005}},
                        {"write": {"issued_at": 2_000_000_008}},
                        {"bootstrap": {"expires_at": 2_000_002_001}}):
            self.assertCode("repair_invalid_ack_bound", self.verify, self.rebuilt(changes))
        # Equal-second dependencies and zero revisions remain legal Q values.
        self.verify(self.rebuilt({role: {"issued_at": 2_000_000_007, "revision": 0}
                                  for role in ("root", "write", "bootstrap")}))
        for at in (2_000_000_005, 2_000_002_000):
            self.assertCode("repair_invalid_ack_bound", self.verify, offer=False, at=at)

    def test_offer_proof_uses_write_admit_window_without_broad_read_grant(self):
        root, write = self.f["payloads"]["root"], self.f["payloads"]["write"]
        for role, field in (("root", "read_until"), ("write", "admit_until")):
            payload = self.f["payloads"][role]
            changes = {role: {"windows": payload["windows"] | {field: 2_000_000_700}}}
            if role == "root":
                changes["write"] = {"windows": write["windows"] | {field: 2_000_000_700}}
            self.assertCode("repair_ack_bound_mismatch", self.verify, self.rebuilt(changes))
        self.assertCode("repair_ack_bound_mismatch", self.verify, self.rebuilt({
            "root": {"windows": root["windows"] | {"admit_until": 2_000_000_700}},
            "write": {"windows": write["windows"] | {"admit_until": 2_000_000_700}},
            "bootstrap": {"proof_until": 2_000_000_600}}))
        # B receives limited service-proof READ from this explicit grant, not
        # the write document's general read window or any A receipt-read grant.
        self.verify(self.rebuilt({"write": {"windows": write["windows"] | {"read_until": 2_000_000_008}}}))
        deadlines = {name: 2_000_000_008 for name in ("probe_until", "proof_until", "upload_until")}
        self.verify(self.rebuilt({"bootstrap": deadlines}), at=2_000_000_009)
        for field in deadlines:
            for value in (2_000_000_007, 2_000_000_901):
                self.assertCode("repair_invalid_ack_bound", self.verify,
                    self.rebuilt({"bootstrap": {field: value}}))

    def test_nine_limits_positive_closed_bounded_by_both_parents_and_policy(self):
        for name in LIMITS:
            self.assertCode("repair_invalid_ack_bound", self.verify,
                self.rebuilt({"bootstrap": {"limits": LIMITS | {name: 0}}}))
            self.assertCode("repair_ack_bound_mismatch", self.verify,
                limit_policy=LIMITS | {name: LIMITS[name] - 1})
            self.assertCode("repair_invalid_ack_bound", self.verify, limit_policy=LIMITS | {name: True})
        for name in ("max_meta_bytes", "max_job_bytes", "max_items", "max_requests",
                     "max_pending", "max_replay_records", "max_jobs"):
            for role in ("root", "write"):
                self.assertCode("repair_ack_bound_mismatch", self.verify, self.rebuilt({role: {
                    "budget": self.f["payloads"][role]["budget"] | {name: 0}}}))
        self.assertCode("repair_invalid_ack_bound", self.verify, limit_policy=None)
        self.assertCode("repair_invalid_ack_bound", self.verify, limit_policy=LIMITS | {"infinity": 1})
        limits = {name: 1 for name in LIMITS}
        self.verify(self.rebuilt({"bootstrap": {"limits": limits}}), limit_policy=limits)

    def test_canonical_raw_refs_exact_signatures_and_work_on_failure(self):
        for field, value in (("size", 1), ("raw_sha256", "0" * 64)):
            entries = copy.deepcopy(self.f["entries"])
            entries["write"]["ref"][field] = value
            self.assertCode("repair_ref_mismatch", self.verify, entries)
        entries = copy.deepcopy(self.f["entries"])
        entries["write"]["raw"] = b" " + entries["write"]["raw"]
        self.assertCode("repair_noncanonical_json", self.verify, entries)
        for role in ("root", "write", "bootstrap"):
            entries = copy.deepcopy(self.f["entries"])
            signed = json.loads(entries[role]["raw"])
            signed["proof"]["signature"] = base64.b64encode(b"\0" * 64).decode()
            raw = canonical_bytes(signed)
            entries[role]["raw"] = raw
            entries[role]["ref"].update(size=len(raw), raw_sha256=hashlib.sha256(raw).hexdigest())
            local, meter = policy(), wire.RepairBudget(policy())
            self.assertCode("repair_invalid_signature", self.verify, entries, local=local, meter=meter)
            self.assertEqual(meter.snapshot()["signature_checks"], ("root", "write", "bootstrap").index(role) + 1)
            self.assertGreater(meter.snapshot()["hashes"], 0)
        local = policy(max_nodes=1)
        meter = wire.RepairBudget(local)
        self.assertCode("repair_over_budget", self.verify, local=local, meter=meter)
        self.assertEqual(meter.snapshot()["signature_checks"], 0)


if __name__ == "__main__":
    unittest.main()
