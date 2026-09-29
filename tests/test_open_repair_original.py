"""Synthetic original controls; no network, Vault or live repair authority."""
import base64
import copy
from dataclasses import replace
import hashlib
import json
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from memory_vault import canonical_bytes
from memory_vault_network_crypto import EncryptionIdentity, document_sha256
from memory_vault_open_contact import SLOT_BYTES, sign_document, verify_decision
from memory_vault_open_control import issue_node
from memory_vault_trust import Identity
import memory_vault_open_repair_original as original
import memory_vault_open_repair_wire as wire


def local_policy(**changes):
    policy = wire.RepairPolicy(65536, 2000000, 100000, 100, 65536,
                              2000000, 200, 1000, 2000000, 100)
    return replace(policy, **changes)


def contact_fixture(*, identities=None, encryption=None, now=2_000_000_000, storage_epoch="synthetic_epoch"):
    """Whole synthetic approved chain, with in-memory keys and no private files."""
    sender, recipient, node = identities or [Identity(Ed25519PrivateKey.generate()) for _ in range(3)]
    sender_enc, recipient_enc = encryption or [EncryptionIdentity.generate() for _ in range(2)]
    docs = {}
    docs["node"] = issue_node(node, base_url="http://127.0.0.1:18501", storage_epoch=storage_epoch,
                              roles=["directory", "router"], revision=1,
                              issued_at=now, expires_at=now + 3600)

    def signed(who, kind, **values):
        return sign_document(who, kind, issued_at=now, expires_at=now + 600, **values)

    for role, purpose in (("knock_lease", "knock"), ("delivery_lease", "delivery")):
        docs[role] = signed(node, "resource.lease", node_key_id=node.key_id,
            storage_epoch=storage_epoch, owner_key_id=recipient.key_id,
            owner_encryption_key=recipient_enc.public_descriptor(), lease_id="synthetic_" + purpose,
            resource_id="synthetic_" + purpose + "_resource", purpose=purpose,
            max_items=2, max_bytes=2 * SLOT_BYTES if purpose == "knock" else 32768)
    knock = docs["knock_lease"]["payload"]
    docs["policy"] = signed(recipient, "contact.policy", node_key_id=node.key_id,
        storage_epoch=storage_epoch, lease_id=knock["lease_id"], resource_id=knock["resource_id"],
        lease_sha256=document_sha256(docs["knock_lease"]), encryption_key=recipient_enc.public_descriptor(),
        revision=1, status="active", max_pending=2)
    docs["request"] = signed(sender, "contact.request", request_id="synthetic_request",
        encryption_key=sender_enc.public_descriptor(), recipient_key_id=recipient.key_id,
        recipient_encryption_key_id=recipient_enc.key_id, node_key_id=node.key_id,
        storage_epoch=storage_epoch, lease_id=knock["lease_id"], resource_id=knock["resource_id"],
        policy_sha256=document_sha256(docs["policy"]), request_class="message")
    docs["grant"] = signed(recipient, "contact.grant", request_id="synthetic_request",
        request_sha256=document_sha256(docs["request"]), subject_key_id=sender.key_id,
        subject_encryption_key_id=sender_enc.key_id, recipient_encryption_key_id=recipient_enc.key_id,
        node_key_id=node.key_id, storage_epoch=storage_epoch, operations=["message.store"],
        resource_id=docs["delivery_lease"]["payload"]["resource_id"], resource_lease=docs["delivery_lease"])
    docs["decision"] = signed(recipient, "contact.decision", request_id="synthetic_request",
        request_sha256=document_sha256(docs["request"]), subject_key_id=sender.key_id,
        subject_encryption_key_id=sender_enc.key_id, recipient_encryption_key_id=recipient_enc.key_id,
        node_key_id=node.key_id, storage_epoch=storage_epoch, policy_sha256=document_sha256(docs["policy"]),
        decision="approved", reason="accepted", grant=docs["grant"])
    expected = dict(sender_key_id=sender.key_id, sender_encryption_key_id=sender_enc.key_id,
        recipient_key_id=recipient.key_id, recipient_encryption_key_id=recipient_enc.key_id,
        node_key_id=node.key_id, storage_epoch=storage_epoch, at=now)
    return docs, expected, dict(sender=sender, recipient=recipient, node=node)


class OpenRepairOriginalTests(unittest.TestCase):
    def setUp(self):
        self.docs, self.expected, self.signers = contact_fixture()

    def assertCode(self, code, function, *args, **kwargs):
        with self.assertRaises(wire.RepairWireError) as caught:
            function(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def raw(self, docs=None):
        return {name: canonical_bytes(doc) for name, doc in (self.docs if docs is None else docs).items()}

    def verify(self, raws=None, policy=None, budget=None, **changes):
        policy = policy or local_policy()
        return original.verify_contact_originals(raws or self.raw(), policy=policy,
            budget=budget or wire.RepairBudget(policy), **(self.expected | changes))

    def generic(self, raw=None, policy=None, budget=None, **changes):
        policy = policy or local_policy()
        values = dict(expected_signing_key=self.expected["node_key_id"],
                      expected_schema="memory-vault-open-control/v1", expected_kind="node",
                      at=self.expected["at"], policy=policy, budget=budget or wire.RepairBudget(policy))
        return original.verify_original_control(raw or self.raw()["node"], **(values | changes))

    def changed(self, role, **changes):
        docs = copy.deepcopy(self.docs)
        signer = self.signers["node" if role in ("node", "knock_lease", "delivery_lease")
                              else "sender" if role == "request" else "recipient"]
        docs[role]["payload"].update(changes)
        docs[role]["proof"] = signer.sign_message(docs[role]["payload"])
        if role == "delivery_lease":
            docs["grant"]["payload"]["resource_lease"] = docs[role]
            docs["grant"]["proof"] = self.signers["recipient"].sign_message(docs["grant"]["payload"])
        if role in ("grant", "delivery_lease"):
            docs["decision"]["payload"]["grant"] = docs["grant"]
            docs["decision"]["proof"] = self.signers["recipient"].sign_message(docs["decision"]["payload"])
        return self.raw(docs)

    def test_fixed_raw_spans_preserve_unicode_escapes_whitespace_and_mutable_snapshot(self):
        local = local_policy()
        budget = wire.RepairBudget(local)
        lease = b'{ "payload" : {"v":-0}, "proof": null }'
        grant = b'{ "payload" : { "resource_lease" : ' + lease + b'}, "proof": false }'
        raw = bytearray(b'{"before":"' + "雪😀".encode() + b'", "payload": {"\\u0067rant": ' + grant + b'}}')
        draft = original.parse_original_control(raw, local, budget)
        raw[:] = b"x" * len(raw)
        self.assertEqual(draft.nested_raw(("payload", "grant")), grant)
        self.assertEqual(draft.nested_raw(("payload", "grant", "payload", "resource_lease")), lease)
        self.assertEqual(draft.value["payload"]["grant"]["payload"]["resource_lease"]["payload"]["v"], 0)
        self.assertEqual(budget.snapshot()["output_bytes"], len(grant) + len(lease))
        self.assertEqual(budget.snapshot()["signature_checks"], 0)
        with self.assertRaises(TypeError):
            draft.value["payload"]["grant"] = None
        with self.assertRaises(AttributeError):
            draft.raw = b"{}"
        for path in (("payload", "missing"), ("payload", "grant", "proof"), ["payload", "grant"], ("x" * 100000, "grant")):
            self.assertCode("repair_invalid_original", draft.nested_raw, path)

    def test_old_signed_integer_profile_without_relaxing_new_wire(self):
        local = local_policy()
        for value in (-wire.U53_MAX, -1, 0, wire.U53_MAX):
            raw = canonical_bytes({"value": value})
            self.assertEqual(original.parse_original_control(raw, local, wire.RepairBudget(local)).value["value"], value)
        self.assertCode("repair_invalid_json", wire.parse_new_wire, b'{"value":-1}', local, wire.RepairBudget(local))
        failures = [(b'{"v":9007199254740992}', "repair_invalid_integer"),
                    (b'{"v":-9007199254740992}', "repair_invalid_integer"),
                    (b'{"v":1.0}', "repair_invalid_json"), (b'{"v":1e0}', "repair_invalid_json"),
                    (b'{"v":-01}', "repair_invalid_json"), (b'{"v":true,"\\u0076":false}', "repair_invalid_json"),
                    (b'{"v":"\\ud800"}', "repair_invalid_unicode"), (b'{"v":"\xff"}', "repair_invalid_utf8"),
                    ('{"雪":1}'.encode(), "repair_invalid_original"), (b'[]', "repair_invalid_original")]
        for raw, code in failures:
            with self.subTest(raw=raw):
                self.assertCode(code, original.parse_original_control, raw, local, wire.RepairBudget(local))
        raw = b'{"v":' + b'[' * 23 + b'0' + b']' * 23 + b'}'
        original.parse_original_control(raw, local, wire.RepairBudget(local))
        self.assertCode("repair_invalid_original", original.parse_original_control,
                        b'{"v":' + b'[' * 24 + b'0' + b']' * 24 + b'}', local, wire.RepairBudget(local))

    def test_explicit_expected_signer_and_old_raw_vs_canonical_digest(self):
        raw = b" \n" + json.dumps(self.docs["node"], ensure_ascii=False, indent=1).encode() + b"\n"
        verified = self.generic(raw)
        self.assertEqual(verified.raw_sha256, hashlib.sha256(raw).hexdigest())
        self.assertEqual(verified.canonical_sha256, document_sha256(self.docs["node"]))
        self.assertNotEqual(verified.raw_sha256, verified.canonical_sha256)
        self.generic(expected_signing_key=self.signers["node"].public_descriptor())
        self.assertCode("repair_wrong_issuer", self.generic, expected_signing_key=self.expected["sender_key_id"])
        descriptor = self.signers["node"].public_descriptor() | {"algorithm": "not-Ed25519"}
        self.assertCode("repair_wrong_issuer", self.generic, expected_signing_key=descriptor)
        for values in ({"expected_schema": "wrong/v1"}, {"expected_kind": "contact"}, {"at": True}):
            self.assertCode("repair_invalid_integer" if values.get("at") is True else "repair_invalid_original", self.generic, **values)

    def test_real_invalid_signature_and_shared_cap_are_not_refunded(self):
        doc = copy.deepcopy(self.docs["node"])
        signature = bytearray(base64.b64decode(doc["proof"]["signature"]))
        signature[0] ^= 1
        doc["proof"]["signature"] = base64.b64encode(signature).decode()
        local = local_policy(max_signature_checks=1)
        budget = wire.RepairBudget(local)
        self.assertCode("repair_invalid_signature", self.generic, canonical_bytes(doc), policy=local, budget=budget)
        first = budget.snapshot()
        self.assertEqual(first["signature_checks"], 1)
        self.assertEqual(first["hashes"], 2)
        self.assertCode("repair_over_budget", self.generic, policy=local, budget=budget)
        self.assertEqual(budget.snapshot()["signature_checks"], 1)
        self.assertGreater(budget.snapshot()["hashes"], first["hashes"])

    def test_proof_shape_domain_and_payload_digest_are_strict(self):
        for mutation, code in (({"extra": 0}, "repair_invalid_original"),
                               ({"schema_version": "wrong/v1"}, "repair_invalid_original"),
                               ({"key_id": self.expected["sender_key_id"]}, "repair_wrong_issuer"),
                               ({"payload_sha256": "0" * 64}, "repair_invalid_signature"),
                               ({"signature": "!" * 88}, "repair_invalid_original")):
            doc = copy.deepcopy(self.docs["node"])
            doc["proof"].update(mutation)
            self.assertCode(code, self.generic, canonical_bytes(doc))
        doc = copy.deepcopy(self.docs["node"])
        body = {key: value for key, value in doc["proof"].items() if key != "signature"}
        doc["proof"]["signature"] = base64.b64encode(self.signers["node"]._private_key.sign(
            b"wrong-domain\x00" + canonical_bytes(body))).decode()
        self.assertCode("repair_invalid_signature", self.generic, canonical_bytes(doc))

    def test_hash_output_signature_and_policy_limits_use_one_meter(self):
        default = wire.RepairPolicy(65536, 2000000, 100000, 100, 65536, 2000000, 200, 1000, 2000000)
        self.assertEqual(default.max_signature_checks, 0)
        self.assertCode("repair_over_budget", self.generic, policy=default)
        for value in (True, -1, 1.0, wire.U53_MAX + 1):
            self.assertCode("repair_invalid_policy", local_policy, max_signature_checks=value)
        local = local_policy(max_hashes=1)
        budget = wire.RepairBudget(local)
        self.assertCode("repair_over_budget", self.generic, policy=local, budget=budget)
        self.assertEqual((budget.snapshot()["hashes"], budget.snapshot()["signature_checks"]), (1, 0))
        local = local_policy(max_signature_checks=1, max_hashes=4)
        budget = wire.RepairBudget(local)
        self.generic(policy=local, budget=budget)
        self.assertEqual((budget.snapshot()["hashes"], budget.snapshot()["signature_checks"]), (4, 1))
        self.assertCode("repair_over_budget", self.generic, policy=local, budget=budget)
        local = local_policy(max_total_bytes=len(self.raw()["node"]) + 40)
        budget = wire.RepairBudget(local)
        self.assertCode("repair_over_budget", self.generic, policy=local, budget=budget)
        self.assertEqual(budget.snapshot()["signature_checks"], 0)

    def test_complete_chain_matches_existing_verifier_with_seven_real_signatures(self):
        legacy = verify_decision(self.docs["decision"], request=self.docs["request"], policy=self.docs["policy"],
                                 lease=self.docs["knock_lease"], node=self.docs["node"], now=self.expected["at"])
        local = local_policy(max_signature_checks=7)
        budget = wire.RepairBudget(local)
        result = self.verify(policy=local, budget=budget)
        self.assertEqual(result.originals["decision"].payload, legacy)
        self.assertEqual(result.at, self.expected["at"])
        self.assertEqual(budget.snapshot()["signature_checks"], 7)
        self.assertEqual(budget.snapshot()["hashes"], 33)  # 7*4 + node coordinate + 4 X25519 descriptors.
        with self.assertRaises(TypeError):
            result.originals["grant"] = None
        self.assertEqual(budget.snapshot()["retained_bytes"], 0)  # Like other Drafts, not total heap holdings.
        self.assertCode("repair_over_budget", self.verify, policy=local_policy(max_signature_checks=6))

    def test_chain_requires_all_independent_expected_ids_and_exact_role_set(self):
        for name in ("sender_key_id", "recipient_key_id", "node_key_id"):
            with self.subTest(name=name):
                self.assertCode("repair_wrong_issuer", self.verify, **{name: "ed25519_" + "0" * 64})
        for name in ("sender_encryption_key_id", "recipient_encryption_key_id"):
            self.assertCode("repair_contact_mismatch", self.verify, **{name: "x25519_" + "0" * 64})
        self.assertCode("repair_contact_mismatch", self.verify, storage_epoch="other_epoch")
        raw = self.raw()
        self.assertCode("repair_invalid_original", self.verify, raw | {"hidden": b"{}"})
        raw.pop("grant")
        self.assertCode("repair_invalid_original", self.verify, raw)

    def test_semantically_equal_nested_originals_must_be_literal_bytes(self):
        raw = self.raw()
        raw["grant"] = b" " + raw["grant"]
        self.assertCode("repair_original_mismatch", self.verify, raw)
        raw = self.raw()
        raw["delivery_lease"] = json.dumps(self.docs["delivery_lease"], indent=1).encode()
        self.assertCode("repair_original_mismatch", self.verify, raw)

    def test_noncanonical_nested_and_outer_bytes_work_when_originals_match(self):
        raw = self.raw()
        lease = json.dumps(self.docs["delivery_lease"], indent=1).encode()
        grant = raw["grant"].replace(b'"resource_lease":' + raw["delivery_lease"], b'"resource_lease":' + lease)
        decision = raw["decision"].replace(b'"grant":' + raw["grant"], b'"grant":' + grant)
        raw.update(grant=grant, delivery_lease=lease, decision=b" \n" + decision + b"\n")
        result = self.verify(raw)
        self.assertEqual(result.originals["grant"].document.raw, grant)
        self.assertEqual(result.originals["delivery_lease"].canonical_sha256, document_sha256(self.docs["delivery_lease"]))

    def test_explicit_historical_time_has_old_future_skew_and_strict_expiry(self):
        self.verify(at=self.expected["at"] - 30)
        self.assertCode("repair_invalid_original", self.verify, at=self.expected["at"] - 31)
        self.verify(at=self.expected["at"] + 599)
        self.assertCode("repair_invalid_original", self.verify, at=self.expected["at"] + 600)
        self.assertCode("repair_invalid_original", self.verify,
                        self.changed("knock_lease", expires_at=self.expected["at"] + 86401))

    def test_validly_signed_node_shape_and_control_unknown_fields_refuse(self):
        for values in ({"status": "revoked"}, {"coordinate": "0" * 64}, {"roles": ["router", "directory"]},
                       {"roles": []}, {"base_url": "http://example.org"}, {"base_url": "https://example.org/path"},
                       {"revision": 0}, {"expires_at": self.expected["at"] + 3601}):
            with self.subTest(values=values):
                self.assertCode("repair_invalid_integer" if values.get("revision") == 0 else "repair_invalid_original",
                                self.verify, self.changed("node", **values))
        local = local_policy()
        budget = wire.RepairBudget(local)
        self.assertCode("repair_invalid_original", self.verify, self.changed("node", unknown=True), policy=local, budget=budget)
        self.assertEqual(budget.snapshot()["signature_checks"], 0)

    def test_validly_signed_contact_chain_rejects_wrong_scope_reservation_and_bindings(self):
        cases = [("knock_lease", {"max_items": 33}, "repair_invalid_original"),
                 ("knock_lease", {"max_bytes": SLOT_BYTES}, "repair_invalid_original"),
                 ("policy", {"max_pending": 3}, "repair_contact_mismatch"),
                 ("policy", {"status": "revoked"}, "repair_contact_mismatch"),
                 ("request", {"request_class": "memory.read"}, "repair_invalid_original"),
                 ("request", {"policy_sha256": "0" * 64}, "repair_contact_mismatch"),
                 ("decision", {"request_sha256": "0" * 64}, "repair_contact_mismatch"),
                 ("decision", {"decision": "rejected", "reason": "declined", "grant": None}, "repair_invalid_original"),
                 ("grant", {"operations": ["memory.read"]}, "repair_invalid_original"),
                 ("grant", {"resource_id": "other_resource"}, "repair_contact_mismatch"),
                 ("delivery_lease", {"owner_key_id": self.expected["sender_key_id"]}, "repair_contact_mismatch"),
                 ("delivery_lease", {"purpose": "knock", "max_bytes": 2 * SLOT_BYTES}, "repair_contact_mismatch"),
                 ("grant", {"storage_epoch": "other_epoch"}, "repair_contact_mismatch")]
        for role, values, code in cases:
            with self.subTest(role=role, values=values):
                self.assertCode(code, self.verify, self.changed(role, **values))


if __name__ == "__main__":
    unittest.main()
