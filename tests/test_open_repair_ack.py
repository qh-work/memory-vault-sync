"""Complete synthetic source closures; actual keys, packs, signatures and times."""
import copy
import hashlib
import json
import unittest

from memory_vault import canonical_bytes
from memory_vault_open_repair_ack import verify_ack_unbound_source_event
import memory_vault_open_repair_wire as wire
from tests.open_repair_ack_fixtures import (ack_unbound_fixture, load_fixture, policy,
    reference, repack_fixture, signed_entry)


class OpenRepairAckTests(unittest.TestCase):
    def verify(self, fixture=None, local=None, **expected):
        fixture = fixture or ack_unbound_fixture()
        resolver, local, budget = load_fixture(fixture, local)
        checked = verify_ack_unbound_source_event(fixture["manifest"], resolver, fixture["custody"],
            **(fixture["expected"] | expected), policy=local, budget=budget)
        return checked, budget

    def assertCode(self, code, fixture, **options):
        with self.assertRaises(wire.RepairWireError) as caught:
            self.verify(fixture, **options)
        self.assertEqual(caught.exception.code, code)

    def test_complete_source_originals_and_shared_actual_crypto(self):
        fixture = ack_unbound_fixture()
        checked, budget = self.verify(fixture)
        self.assertEqual(checked.stored_at, 2_000_000_006)
        self.assertEqual(len(checked.manifest.roles), 13)
        self.assertEqual(len(checked.statuses), 2)
        self.assertEqual(budget.snapshot()["signature_checks"], 13)
        self.assertEqual(budget.snapshot()["hashes"], 87)
        self.assertEqual(checked.custody.raw, fixture["custody"]["raw"])
        self.assertCode("repair_over_budget", fixture, local=policy(max_signature_checks=12))

    def test_exact_role_set_no_future_message_or_receipt_dependency(self):
        fixture = ack_unbound_fixture()
        self.assertNotIn("recipient.receipt", fixture["role_map"])
        self.assertNotIn("ack.write_grant", fixture["role_map"])
        changed = dict(fixture["role_map"])
        del changed["historical.status.ack_slot"]
        self.assertCode("repair_invalid_ack", repack_fixture(fixture, roles=changed))
        fixture = ack_unbound_fixture()
        changed = fixture["role_map"] | {"recipient.receipt": "root"}
        self.assertCode("repair_invalid_history", repack_fixture(fixture, roles=changed))

    def test_custody_is_signed_by_independently_expected_target(self):
        fixture = ack_unbound_fixture()
        payload = json.loads(fixture["custody"]["raw"])["payload"]
        payload["signing_key"] = fixture["signers"]["owner"].public_descriptor()
        fixture["custody"] = signed_entry(payload, fixture["signers"]["owner"], "custody")
        self.assertCode("repair_wrong_issuer", fixture)
        self.assertCode("repair_wrong_issuer", ack_unbound_fixture(),
                        expected_target=ack_unbound_fixture()["expected"]["expected_target"])

    def test_full_manifest_reference_and_custody_fields_are_closed(self):
        for field, value in (("key", "0"*64), ("raw_sha256", "0"*64), ("size", 1)):
            fixture = ack_unbound_fixture()
            fixture["manifest"]["ref"][field] = value
            self.assertCode("repair_ack_mismatch", fixture)
        fixture = ack_unbound_fixture(changes={"custody": {"issued_at": 2_000_000_006}})
        self.assertCode("repair_invalid_ack", fixture)
        fixture = ack_unbound_fixture()
        fixture["custody"]["ref"]["raw_sha256"] = "0" * 64
        self.assertCode("repair_ref_mismatch", fixture)

    def test_source_time_and_promise_narrowing(self):
        for changes in ({"stored_at": 2_000_000_004}, {"read_until": 2_000_000_901},
                        {"retain_until": 2_000_001_001}):
            fixture = ack_unbound_fixture(changes={"custody": changes})
            self.assertCode("repair_ack_mismatch", fixture)
        self.assertCode("repair_invalid_ack", ack_unbound_fixture(changes={"custody": {
            "read_until": 2_000_000_006}}))
        self.assertCode("repair_ack_mismatch", ack_unbound_fixture(changes={"bootstrap": {
            "issued_at": 2_000_000_005}}))

    def test_root_retention_bit_and_source_epoch_cannot_be_inferred(self):
        self.assertCode("repair_ack_mismatch", ack_unbound_fixture(changes={"root": {"operation_mask": 10}}))
        self.assertCode("repair_original_mismatch", ack_unbound_fixture(changes={"descriptor": {
            "storage_epoch": "different_source_epoch"}}))

    def extra_owner_status(self, fixture, payload, *, role="historical.status.ack_root"):
        fixture["entries"]["owner_status_extra"] = signed_entry(payload, fixture["signers"]["owner"], "owner_status_extra")
        roles = fixture["role_map"] | {role: "owner_status_extra"}
        return repack_fixture(fixture, roles=roles)

    def test_other_present_scope_revocation_cannot_be_hidden_by_role_alias(self):
        fixture = ack_unbound_fixture()
        payload = copy.deepcopy(fixture["docs"]["owner_status"]["payload"])
        # This body is used for root, but its slot observation still applies.
        row = next(item for item in payload["entries"] if item["scope_kind"] == "ack_slot")
        row["status"] = "revoked"
        payload["revision"] = 2
        self.assertCode("repair_authority_revoked", self.extra_owner_status(fixture, payload))

    def test_same_revision_equivocation_and_minimum_revision_rollback(self):
        fixture = ack_unbound_fixture()
        payload = copy.deepcopy(fixture["docs"]["owner_status"]["payload"])
        payload["valid_until"] -= 1
        self.assertCode("repair_status_conflict", self.extra_owner_status(fixture, payload))
        fixture = ack_unbound_fixture()
        payload = copy.deepcopy(fixture["docs"]["owner_status"]["payload"])
        for row in payload["entries"]:
            row["minimum_document_revision"] = 1
        fixture["entries"]["owner_status"] = signed_entry(payload, fixture["signers"]["owner"], "owner_status")
        lowered = copy.deepcopy(payload)
        lowered["revision"] = 2
        lowered["entries"][0]["minimum_document_revision"] = 0
        self.assertCode("repair_status_rollback", self.extra_owner_status(fixture, lowered))

    def test_legacy_status_whitespace_is_distinct_original_not_equivocation(self):
        fixture = ack_unbound_fixture()
        raw = b" \n" + fixture["entries"]["owner_status"]["raw"] + b"\n"
        fixture["entries"]["spaced_status"] = dict(raw=raw, ref=reference(raw, "spaced_status"))
        roles = fixture["role_map"] | {"historical.status.ack_root": "spaced_status"}
        checked, budget = self.verify(repack_fixture(fixture, roles=roles))
        self.assertEqual(len(checked.statuses), 3)
        self.assertEqual(budget.snapshot()["signature_checks"], 14)
        owner = [item for item in checked.statuses if item.payload["signing_key"] == fixture["expected"]["expected_owner"]["signing_key"]]
        self.assertEqual(len({item.canonical_sha256 for item in owner}), 1)
        self.assertEqual(len({item.raw_sha256 for item in owner}), 2)

    def test_whole_status_disclosure_scope_and_mask(self):
        fixture = ack_unbound_fixture()
        payload = copy.deepcopy(fixture["docs"]["owner_status"]["payload"])
        payload["entries"].append(dict(scope_kind="resource", scope_id="0"*64,
            minimum_document_revision=0, status="active", operation_mask=127))
        payload["entries"].sort(key=lambda item: (item["scope_kind"], item["scope_id"]))
        self.assertCode("repair_status_disclosure", self.extra_owner_status(fixture, payload))
        fixture = ack_unbound_fixture()
        payload = copy.deepcopy(fixture["docs"]["owner_status"]["payload"])
        next(item for item in payload["entries"] if item["scope_kind"] == "ack_slot")["operation_mask"] = 2
        self.assertCode("repair_status_operation", self.extra_owner_status(fixture, payload))

    def test_returned_source_event_is_immutable_and_retains_exact_bytes(self):
        fixture = ack_unbound_fixture()
        fixture["custody"]["raw"] = bytearray(fixture["custody"]["raw"])
        checked, _ = self.verify(fixture)
        original = checked.custody.raw
        fixture["custody"]["raw"][:] = b"x" * len(original)
        fixture["expected"]["expected_ack_slot"]["slot_id"] = "changed"
        self.assertEqual(checked.custody.raw, original)
        with self.assertRaises(TypeError):
            checked.custody.payload["read_until"] = 0
        with self.assertRaises(AttributeError):
            checked.statuses = ()


if __name__ == "__main__":
    unittest.main()
