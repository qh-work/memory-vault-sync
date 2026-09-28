"""Real synthetic six-proof resource inputs; no activation or network claim."""
import base64
import copy
from dataclasses import replace
import hashlib
import unittest

from memory_vault import canonical_bytes
import memory_vault_open_repair_original as original
import memory_vault_open_repair_resource as resource
import memory_vault_open_repair_wire as wire
from tests.open_repair_resource_fixtures import ack_resource_fixture, ROLES


def policy(**changes):
    return replace(wire.RepairPolicy(65536, 4000000, 100000, 100, 65536,
                                   4000000, 1000, 1000, 4000000, 100), **changes)


class OpenRepairResourceTests(unittest.TestCase):
    def setUp(self):
        self.docs, self.entries, self.expected, self.signers = ack_resource_fixture()

    def assertCode(self, code, operation, *args, **kwargs):
        with self.assertRaises(wire.RepairWireError) as caught:
            operation(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def verify(self, entries=None, local=None, budget=None, **expected):
        local = local or policy()
        return resource.verify_ack_resource_inputs(self.entries if entries is None else entries,
            **(self.expected | expected), policy=local, budget=budget or wire.RepairBudget(local))

    def revised(self, role, mutate):
        """Re-sign all six real documents and repair unchanged downstream refs."""
        docs = copy.deepcopy(self.docs)
        mutate(docs[role]["payload"])
        changes, entries = [], {}

        def refs(value):
            if type(value) is dict:
                for old, new in changes:
                    if value == old:
                        return dict(new)
                return {key: refs(child) for key, child in value.items()}
            if type(value) is list:
                return [refs(child) for child in value]
            return value

        for name in ROLES:
            payload = refs(docs[name]["payload"])
            signer = self.signers["target" if name in ("offer", "active") else "owner"]
            raw = canonical_bytes(dict(payload=payload, proof=signer.sign_message(payload)))
            reference = self.entries[name]["ref"] | dict(raw_sha256=hashlib.sha256(raw).hexdigest(), size=len(raw))
            changes.append((self.entries[name]["ref"], reference))
            entries[name] = dict(raw=raw, ref=reference)
        return entries

    def test_six_real_proofs_preserve_raw_refs_and_owner_horizons(self):
        local = policy(max_signature_checks=6)
        budget = wire.RepairBudget(local)
        result = self.verify(local=local, budget=budget)
        self.assertEqual(result.activated_at, self.docs["active"]["payload"]["activated_at"])
        self.assertEqual(set(result.originals), set(ROLES))
        for name, item in result.originals.items():
            self.assertEqual(item.raw, self.entries[name]["raw"])
            self.assertEqual(item.ref.as_dict(), self.entries[name]["ref"])
            self.assertNotEqual(item.ref.key, item.ref.raw_sha256)
        work = budget.snapshot()
        self.assertEqual((work["signature_checks"], work["hashes"]), (6, 24))
        self.assertEqual(work["retained_bytes"], 0)
        self.assertGreater(result.originals["root"].payload["windows"]["read_until"],
                           result.originals["offer"].payload["windows"]["read_until"])
        self.assertNotEqual(result.originals["read"].payload["grant_id"], self.expected["expected_ack_slot"]["grant_id"])
        with self.assertRaises(TypeError):
            result.originals["root"] = None
        with self.assertRaises(AttributeError):
            result.originals["root"].raw = b"{}"
        self.assertCode("repair_over_budget", self.verify, local=local, budget=budget)
        self.assertEqual(budget.snapshot()["signature_checks"], 6)

    def test_new_event_shapes_do_not_loosen_legacy_control_verification(self):
        for role in ("offer", "active"):
            payload = self.docs[role]["payload"]
            local = policy()
            self.assertCode("repair_invalid_original", original.verify_original_control,
                self.entries[role]["raw"], expected_signing_key=payload["signing_key"]["key_id"],
                expected_schema=resource.SCHEMA, expected_kind=payload["kind"], at=2_000_000_000,
                policy=local, budget=wire.RepairBudget(local))
        self.verify()  # The purpose-specific Q path has the actual event fields.

    def test_expected_inputs_are_bounded_and_do_not_accept_self_selected_identity(self):
        replacement = self.expected["expected_target"]
        self.assertCode("repair_resource_mismatch", self.verify, expected_owner=replacement)
        self.assertCode("repair_wrong_issuer", self.verify, expected_target=self.expected["expected_owner"])
        self.assertCode("repair_resource_mismatch", self.verify, target_storage_epoch="different_epoch")
        slot = copy.deepcopy(self.expected["expected_ack_slot"])
        slot["grant_id"] = "another_future_id"
        self.assertCode("repair_resource_mismatch", self.verify, expected_ack_slot=slot)
        local = policy(max_nodes=1)
        budget = wire.RepairBudget(local)
        self.assertCode("repair_over_budget", self.verify, local=local, budget=budget)
        self.assertEqual(budget.snapshot()["signature_checks"], 0)
        slot["unexpected"] = "field"
        self.assertCode("repair_invalid_resource", self.verify, expected_ack_slot=slot)

    def test_input_canonical_bytes_and_reference_integrity_are_mandatory(self):
        entries = copy.deepcopy(self.entries)
        entries["allocate"]["raw"] = b" " + entries["allocate"]["raw"]
        self.assertCode("repair_noncanonical_json", self.verify, entries)
        for field, value in (("raw_sha256", "0" * 64), ("size", 1)):
            entries = copy.deepcopy(self.entries)
            entries["allocate"]["ref"][field] = value
            self.assertCode("repair_ref_mismatch", self.verify, entries)
        entries = copy.deepcopy(self.entries)
        entries["allocate"]["ref"]["namespace"] = "object"
        self.assertCode("repair_invalid_resource", self.verify, entries)
        self.assertCode("repair_invalid_resource", self.verify, self.entries | {"later_receipt": {}})
        entries = copy.deepcopy(self.entries)
        entries["allocate"]["unknown"] = 0
        self.assertCode("repair_invalid_resource", self.verify, entries)

    def test_parent_reference_checks_bind_opaque_locator_as_well_as_digest(self):
        for role, field in (("offer", "allocation_request_ref"), ("root", "original_resource_offer_ref"),
                            ("read", "root_authority_ref"), ("active", "offer_ref"), ("active", "activation_ref")):
            with self.subTest(role=role, field=field):
                entries = self.revised(role, lambda payload: payload[field].update(key="0" * 64))
                self.assertCode("repair_resource_mismatch", self.verify, entries)

    def test_intent_exact_equality_hash_owner_target_epoch_and_reserved_budget(self):
        mutations = [lambda p: p.update(intent_sha256="0" * 64),
                     lambda p: p["intent"].update(allocation_id="other_allocation"),
                     lambda p: p.update(target_encryption_key=self.expected["expected_owner"]["encryption_key"]),
                     lambda p: p["resource"].update(storage_epoch="another_epoch"),
                     lambda p: p["budget"].update(max_jobs=p["budget"]["max_jobs"] + 1)]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                self.assertCode("repair_resource_mismatch", self.verify, self.revised("offer", mutate))
        self.assertCode("repair_invalid_resource", self.verify,
                        self.revised("allocate", lambda p: p["intent"].update(kind="resource.copy_intent")))

    def test_activation_exact_unbound_scope_offer_and_authority_closure(self):
        for mutate, code in (
            (lambda p: p["scope"].update(kind="ack_empty"), "repair_invalid_resource"),
            (lambda p: p["scope"]["ack_slot"].update(slot_id="another_slot"), "repair_resource_mismatch"),
            (lambda p: p["resource_offer_refs"].append(p["resource_offer_refs"][0]), "repair_invalid_resource"),
            (lambda p: p["authority_refs"].reverse(), "repair_invalid_resource"),
            (lambda p: p["authority_refs"][0].update(role="ack.write_grant"), "repair_invalid_resource"),
            (lambda p: p["authority_refs"][0]["ref"].update(key="0" * 64), "repair_resource_mismatch"),
            (lambda p: p.update(subject=self.expected["expected_target"]), "repair_resource_mismatch")):
            with self.subTest(code=code):
                self.assertCode(code, self.verify, self.revised("activation", mutate))

    def test_asserted_event_times_are_ordered_with_no_future_skew_or_current_clock(self):
        now = self.docs["allocate"]["payload"]["issued_at"]
        cases = [("offer", "issued_at", now - 1), ("offer", "issued_at", now + 20),
                 ("root", "issued_at", now), ("read", "issued_at", now + 1),
                 ("activation", "issued_at", now + 2), ("active", "activated_at", now + 3),
                 ("active", "activated_at", now + 40), ("activation", "expires_at", now + 5)]
        for role, field, value in cases:
            with self.subTest(role=role, field=field):
                self.assertCode("repair_resource_mismatch", self.verify,
                                self.revised(role, lambda p: p.update({field: value})))
        # Allocation already expired by the event is legal: the offer was
        # produced while it was valid and its separate reservation is live.
        self.verify(self.revised("allocate", lambda p: p.update(expires_at=now + 2)))
        # No old 30-second skew is introduced into this source-event sequence.
        self.verify(self.revised("active", lambda p: p.update(activated_at=now + 4)))

    def test_windows_parent_narrowing_and_operation_mask_are_bounded(self):
        now = self.docs["allocate"]["payload"]["issued_at"]
        cases = [("root", lambda p: p["windows"].update(read_until=p["expires_at"] + 1), "repair_invalid_resource"),
                 ("read", lambda p: p["windows"].update(read_until=p["issued_at"]), "repair_invalid_resource"),
                 ("read", lambda p: p["windows"].update(read_until=now + 3500, retain_until=now + 3500), "repair_resource_mismatch"),
                 ("read", lambda p: p["budget"].update(max_items=2), "repair_resource_mismatch"),
                 ("root", lambda p: p.update(operation_mask=1), "repair_resource_mismatch"),
                 ("read", lambda p: p.update(operation_mask=128), "repair_invalid_resource")]
        for role, mutate, code in cases:
            with self.subTest(role=role, code=code):
                self.assertCode(code, self.verify, self.revised(role, mutate))

    def test_resource_window_can_end_at_offer_without_becoming_a_live_promise(self):
        deadline = self.docs["offer"]["payload"]["issued_at"]
        windows = {name: deadline for name in self.docs["offer"]["payload"]["windows"]}
        for role in ("allocate", "offer"):
            intent = self.docs[role]["payload"]["intent"]
            intent["windows"] = windows
            self.docs[role]["payload"]["intent_sha256"] = hashlib.sha256(canonical_bytes(intent)).hexdigest()
        self.docs["offer"]["payload"]["windows"] = windows
        self.docs["active"]["payload"]["windows"] = windows
        result = self.verify(self.revised("active", lambda p: None))
        self.assertGreater(result.activated_at, deadline)
        entries = copy.deepcopy(self.entries)
        entries["allocate"]["ref"] = wire.RawRef(**entries["allocate"]["ref"])
        self.assertCode("repair_invalid_resource", self.verify, entries)

    def test_role_names_limits_and_typed_shapes_refuse_before_crypto(self):
        local = policy()
        budget = wire.RepairBudget(local)
        self.assertCode("repair_invalid_resource", self.verify,
                        self.revised("allocate", lambda p: p.update(unknown=True)), local=local, budget=budget)
        self.assertEqual(budget.snapshot()["signature_checks"], 0)
        for mutate in (lambda p: p.update(max_bindings=2), lambda p: p.update(max_receipts=2),
                       lambda p: p.update(max_delegate_depth=3), lambda p: p["allowed_roles"].append("unregistered.role"),
                       lambda p: p["allowed_roles"].append(p["allowed_roles"][-1]),
                       lambda p: p["maintainers"].append(p["maintainers"][0])):
            self.assertCode("repair_invalid_resource", self.verify, self.revised("root", mutate))
        self.verify(self.revised("root", lambda p: p.update(allowed_roles=[], maintainers=[], revision=0)))
        # The complete alphabet includes later bootstrap/service roles; naming
        # one is not a new disclosure or service authorization result.
        self.verify(self.revised("root", lambda p: p.update(allowed_roles=sorted(resource.KNOWN_ALLOWED_ROLES))))

    def test_real_bad_signature_and_sixth_limit_consume_shared_work(self):
        entries = copy.deepcopy(self.entries)
        doc = copy.deepcopy(self.docs["active"])
        doc["proof"]["signature"] = base64.b64encode(bytes(64)).decode()
        raw = canonical_bytes(doc)
        entries["active"] = dict(raw=raw, ref=entries["active"]["ref"] | dict(
            size=len(raw), raw_sha256=hashlib.sha256(raw).hexdigest()))
        local = policy(max_signature_checks=6)
        budget = wire.RepairBudget(local)
        self.assertCode("repair_invalid_signature", self.verify, entries, local=local, budget=budget)
        self.assertEqual(budget.snapshot()["signature_checks"], 6)
        self.assertCode("repair_over_budget", self.verify, local=local, budget=budget)
        self.assertEqual(budget.snapshot()["signature_checks"], 6)
        local = policy(max_signature_checks=5)
        budget = wire.RepairBudget(local)
        self.assertCode("repair_over_budget", self.verify, local=local, budget=budget)
        self.assertEqual(budget.snapshot()["signature_checks"], 5)

    def test_mutable_original_snapshot_and_resource_event_shape_cannot_be_substituted(self):
        entries = {name: dict(raw=bytearray(entry["raw"]), ref=copy.deepcopy(entry["ref"]))
                   for name, entry in self.entries.items()}
        result = self.verify(entries)
        for entry in entries.values():
            entry["raw"][:] = bytes(len(entry["raw"]))
            entry["ref"]["key"] = "0" * 64
        self.assertEqual(result.originals["root"].raw, self.entries["root"]["raw"])
        for role, field in (("offer", "expires_at"), ("active", "issued_at")):
            self.assertCode("repair_invalid_resource", self.verify,
                            self.revised(role, lambda p: p.update({field: 1})))


if __name__ == "__main__":
    unittest.main()
