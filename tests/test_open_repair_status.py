"""Original historical status evidence, without current acceptance or a ledger."""
import base64
import copy
import hashlib
import json
import unittest

from memory_vault import canonical_bytes
import memory_vault_open_provider as provider
import memory_vault_open_repair_status as status
import memory_vault_open_repair_wire as wire
from tests.open_repair_resource_fixtures import ack_resource_fixture


POLICY = dict(max_document_bytes=65536, max_total_bytes=4194304, max_nodes=200000,
              max_depth=100, max_string_bytes=65536, max_hash_bytes=4194304,
              max_hashes=1000, max_entries=1000, max_retained_bytes=4194304,
              max_signature_checks=100)
NOW = 2_000_000_000


def scope_digest(root, kind, subject):
    value = {"kind": kind, "root_key": root}
    if kind == "authority":
        value.update(subject)
    else:
        value["resource" if kind == "resource" else "ack_slot"] = subject
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def status_entry(signed, *, pretty=False):
    raw = ((" \n" + json.dumps(signed, ensure_ascii=False, indent=2) + "\n").encode()
           if pretty else canonical_bytes(signed))
    return {"raw": raw, "ref": {"namespace": "meta",
        "key": hashlib.sha256(b"synthetic historical status locator").hexdigest(),
        "raw_sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}}


def historical_status_fixture():
    docs, originals, expected, signers = ack_resource_fixture()
    root = copy.deepcopy(expected["expected_ack_slot"]["root_key"])
    subjects = {name: {"authority_kind": docs[name]["payload"]["kind"],
                       "authority_sha256": originals[name]["ref"]["raw_sha256"]}
                for name in ("root", "read")}
    scopes = {name: {"scope_kind": "authority", "scope_id": scope_digest(root, "authority", subject)}
              for name, subject in subjects.items()}
    entries = sorted([{**scopes[name], "minimum_document_revision": 1,
                       "status": "active", "operation_mask": mask}
                      for name, mask in (("root", 74), ("read", 2))],
                     key=lambda item: (item["scope_kind"], item["scope_id"]))
    signed = provider.issue_status(signers["owner"], root=root, revision=7,
        entries=entries, issued_at=NOW, valid_until=NOW + 600)
    allowed = sorted(scopes.values(), key=lambda item: (item["scope_kind"], item["scope_id"]))
    required = sorted([{**scopes[name], "document_revision": 1, "operation_mask": mask}
                       for name, mask in (("root", 74), ("read", 2))],
                      key=lambda item: (item["scope_kind"], item["scope_id"]))
    options = dict(expected_root=root, expected_signing_key=signers["owner"].public_descriptor(),
                   at=NOW + 5, allowed_scopes=allowed, required=required)
    return signed, status_entry(signed), options, signers, subjects, expected, docs


def resign_status(signed, signer, mutate):
    payload = copy.deepcopy(signed["payload"])
    mutate(payload)
    return {"payload": payload, "proof": signer.sign_message(payload)}


class OpenRepairStatusTests(unittest.TestCase):
    def setUp(self):
        (self.signed, self.entry, self.options, self.signers, self.subjects,
         self.expected, self.docs) = historical_status_fixture()

    def verify(self, entry=None, options=None, local=None, budget=None):
        local = local or wire.RepairPolicy(**POLICY)
        return status.verify_status_original(self.entry if entry is None else entry,
            **(self.options if options is None else options), policy=local,
            budget=budget or wire.RepairBudget(local))

    def assertCode(self, code, entry=None, options=None, **kwargs):
        with self.assertRaises(wire.RepairWireError) as caught:
            self.verify(entry, options, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def changed(self, mutate, signer=None):
        return status_entry(resign_status(self.signed, signer or self.signers["owner"], mutate))

    def test_closed_typed_scopes_match_original_canonical_digest_and_meter_hashes(self):
        root = self.options["expected_root"]
        cases = [("authority", self.subjects["root"]), ("authority", self.subjects["read"]),
                 ("authority", {"authority_kind": "ack.write_grant", "authority_sha256": "ab" * 32}),
                 ("authority", {"authority_kind": "bootstrap.grant", "authority_sha256": "cd" * 32}),
                 ("ack_slot", self.expected["expected_ack_slot"]),
                 ("resource", self.docs["active"]["payload"]["resource"])]
        local = wire.RepairPolicy(**POLICY)
        budget = wire.RepairBudget(local)
        for kind, subject in cases:
            self.assertEqual(status.status_scope(root, kind, subject, local, budget),
                             scope_digest(root, kind, subject))
        self.assertEqual(budget.snapshot()["hashes"], len(cases))
        self.assertEqual(budget.snapshot()["signature_checks"], 0)
        for kind, subject in (("authority", {**self.subjects["root"], "unexpected": 1}),
                              ("authority", {"authority_kind": "root.authority", "authority_sha256": "ab" * 32}),
                              ("unknown", {})):
            with self.assertRaises(wire.RepairWireError):
                status.status_scope(root, kind, subject, local, budget)

    def test_real_multi_scope_status_preserves_original_and_canonical_digests(self):
        entry = status_entry(self.signed, pretty=True)
        local = wire.RepairPolicy(**POLICY)
        budget = wire.RepairBudget(local)
        checked = self.verify(entry, local=local, budget=budget)
        self.assertEqual(checked.raw, entry["raw"])
        self.assertEqual(checked.raw_sha256, hashlib.sha256(entry["raw"]).hexdigest())
        self.assertEqual(checked.canonical_sha256, hashlib.sha256(canonical_bytes(self.signed)).hexdigest())
        self.assertNotEqual(checked.raw_sha256, checked.canonical_sha256)
        self.assertEqual(checked.at, self.options["at"])
        self.assertEqual(checked.payload, self.signed["payload"])
        self.assertEqual(checked.ref.as_dict(), entry["ref"])
        self.assertNotEqual(checked.ref.key, checked.raw_sha256)
        self.assertEqual(budget.snapshot()["signature_checks"], 1)
        self.assertEqual(budget.snapshot()["retained_bytes"], 0)

    def test_matching_entry_never_authorizes_other_entry_in_same_original(self):
        chosen = self.options["required"][0]
        options = {**self.options, "allowed_scopes": [{k: chosen[k] for k in ("scope_kind", "scope_id")}],
                   "required": [chosen]}
        self.assertCode("repair_status_disclosure", options=options)
        self.verify()  # Both originals' exact scopes are permitted together.

    def test_missing_required_scope_is_distinct_from_valid_partial_document(self):
        entry = self.changed(lambda p: p.update(entries=p["entries"][:1]))
        self.assertCode("repair_status_missing", entry)

    def test_required_operation_bits_revocation_and_document_revision(self):
        self.assertCode("repair_authority_revoked", self.changed(
            lambda p: p["entries"][0].update(status="revoked")))
        self.assertCode("repair_status_operation", self.changed(
            lambda p: p["entries"][0].update(operation_mask=1)))
        self.assertCode("repair_status_revision", self.changed(
            lambda p: p["entries"][0].update(minimum_document_revision=2)))
        # The observation revision is not the original authority's revision.
        self.verify(self.changed(lambda p: p.update(revision=900)))
        options = copy.deepcopy(self.options)
        options["required"][0]["operation_mask"] |= 8
        entry = self.changed(lambda p: p["entries"][0].update(operation_mask=2))
        self.assertCode("repair_status_operation", entry, options)

    def test_expected_issuer_root_and_exact_ref_are_independent(self):
        self.assertCode("repair_wrong_issuer", options={**self.options,
            "expected_signing_key": self.signers["target"].public_descriptor()})
        root = copy.deepcopy(self.options["expected_root"])
        root["root_id"] = "different_synthetic_root"
        self.assertCode("repair_status_mismatch", options={**self.options, "expected_root": root})
        for field, value in (("raw_sha256", "00" * 32), ("size", 1)):
            entry = copy.deepcopy(self.entry)
            entry["ref"][field] = value
            self.assertCode("repair_ref_mismatch", entry)

    def test_resource_status_is_signed_by_resource_node_with_generation_floor(self):
        root = self.options["expected_root"]
        resource = self.docs["active"]["payload"]["resource"]
        scope = {"scope_kind": "resource", "scope_id": scope_digest(root, "resource", resource)}
        signed = provider.issue_status(self.signers["target"], root=root, revision=22,
            entries=[{**scope, "minimum_document_revision": 1, "status": "active", "operation_mask": 66}],
            issued_at=NOW, valid_until=NOW + 600)
        options = {**self.options, "expected_signing_key": self.signers["target"].public_descriptor(),
                   "allowed_scopes": [scope], "required": [{**scope, "document_revision": 1, "operation_mask": 66}]}
        self.verify(status_entry(signed), options)
        options["required"][0]["document_revision"] = 0
        self.assertCode("repair_status_revision", status_entry(signed), options)

    def test_legacy_historical_time_uses_explicit_event_and_retains_thirty_second_skew(self):
        self.verify(options={**self.options, "at": NOW - 30})
        self.verify(options={**self.options, "at": NOW + 599})
        for at in (NOW - 31, NOW + 600):
            with self.assertRaises(wire.RepairWireError):
                self.verify(options={**self.options, "at": at})
        for value in (NOW, NOW + 604801):
            with self.assertRaises(wire.RepairWireError):
                self.verify(self.changed(lambda p: p.update(valid_until=value)))
        self.verify(self.changed(lambda p: p.update(valid_until=NOW + 604800)))

    def test_original_closed_shape_entry_order_and_size_cap(self):
        mutations = [lambda p: p.update(expires_at=NOW + 600),
                     lambda p: p.update(entries=[]),
                     lambda p: p.update(revision=0),
                     lambda p: p["entries"].reverse(),
                     lambda p: p["entries"].append(p["entries"][0]),
                     lambda p: p["entries"][0].update(operation_mask=0),
                     lambda p: p["entries"][0].update(scope_kind="unregistered_scope"),
                     lambda p: p.update(entries=[{**p["entries"][0], "scope_id": format(i, "064x")}
                                                 for i in range(17)]),
                     lambda p: p["entries"][0].update(unexpected=True)]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                self.assertCode("repair_invalid_status", self.changed(mutate))
        entry = copy.deepcopy(self.entry)
        entry["raw"] = b" " * 16384 + entry["raw"]
        entry["ref"].update(size=len(entry["raw"]), raw_sha256=hashlib.sha256(entry["raw"]).hexdigest())
        local = wire.RepairPolicy(**POLICY)
        budget = wire.RepairBudget(local)
        with self.assertRaises(wire.RepairWireError):
            self.verify(entry, local=local, budget=budget)
        self.assertEqual(budget.snapshot()["signature_checks"], 0)

    def test_actual_bad_signature_and_repeated_calls_consume_shared_budget(self):
        local = wire.RepairPolicy(**{**POLICY, "max_signature_checks": 1})
        budget = wire.RepairBudget(local)
        self.verify(local=local, budget=budget)
        self.assertCode("repair_over_budget", local=local, budget=budget)
        self.assertEqual(budget.snapshot()["signature_checks"], 1)
        signed = copy.deepcopy(self.signed)
        signed["proof"]["signature"] = base64.b64encode(bytes(64)).decode()
        failed_budget = wire.RepairBudget(local)
        self.assertCode("repair_invalid_signature", status_entry(signed), local=local, budget=failed_budget)
        self.assertEqual(failed_budget.snapshot()["signature_checks"], 1)

    def test_input_copy_and_expected_context_boundaries(self):
        entry = copy.deepcopy(self.entry)
        entry["raw"] = bytearray(entry["raw"])
        options = copy.deepcopy(self.options)
        checked = self.verify(entry, options)
        entry["raw"][:] = bytes(len(entry["raw"]))
        entry["ref"]["key"] = "00" * 32
        options["expected_root"]["root_id"] = "mutated"
        self.assertEqual(checked.raw, self.entry["raw"])
        self.assertEqual(checked.ref.key, self.entry["ref"]["key"])
        local = wire.RepairPolicy(**{**POLICY, "max_nodes": 1})
        budget = wire.RepairBudget(local)
        self.assertCode("repair_over_budget", local=local, budget=budget)
        self.assertEqual(budget.snapshot()["signature_checks"], 0)


if __name__ == "__main__":
    unittest.main()
