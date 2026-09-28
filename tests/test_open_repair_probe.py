"""Fresh synthetic two-way X25519/Ed25519 exchange, without service claims."""
import base64
import copy
from dataclasses import replace
import hashlib
import json
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from memory_vault import canonical_bytes
import memory_vault_network_crypto as crypto
import memory_vault_open_repair_probe as probe
import memory_vault_open_repair_wire as wire
from memory_vault_trust import Identity


def policy(**changes):
    return replace(wire.RepairPolicy(65536, 16000000, 1000000, 100, 65536,
                                   16000000, 1000, 1000, 16000000, 100), **changes)


def probe_fixture():
    signers = {name: Identity(Ed25519PrivateKey.generate()) for name in ("subject", "target")}
    encryption = {name: crypto.EncryptionIdentity.generate() for name in signers}
    keys = {name: dict(signing_key=signers[name].public_descriptor(), encryption_key=encryption[name].public_descriptor())
            for name in signers}
    expected = dict(expected_subject=keys["subject"], expected_target=keys["target"],
        target_storage_epoch="synthetic_probe_epoch", bootstrap_grant_sha256="a" * 64,
        selector={name: str(index + 1) * 64 for index, name in enumerate(sorted(probe._SELECTOR))}, at=2_000_000_000)
    return signers, encryption, expected


def entry(value):
    return dict(raw=value.raw, ref=value.ref.as_dict())


class OpenRepairProbeTests(unittest.TestCase):
    def setUp(self):
        self.signers, self.encryption, self.expected = probe_fixture()

    def options(self, local=None, budget=None, **changes):
        local = local or policy()
        return self.expected | dict(policy=local, budget=budget or wire.RepairBudget(local)) | changes

    def make(self, **options):
        return probe.make_bootstrap_probe(self.signers["subject"], expires_at=self.expected["at"] + 50,
                                           **self.options(**options))

    def challenge(self, first, **options):
        return probe.issue_bootstrap_challenge(first, signer=self.signers["target"],
            encryption_identity=self.encryption["target"], expires_at=self.expected["at"] + 40, **self.options(**options))

    def solve(self, first, second, nonce, **options):
        return probe.solve_bootstrap_challenge(first, second, signer=self.signers["subject"],
            encryption_identity=self.encryption["subject"], target_nonce=nonce,
            expires_at=self.expected["at"] + 30, **self.options(**options))

    def exchange(self, local=None, budget=None, locator=None):
        first = self.make(local=local, budget=budget)
        first_entry = entry(first.original)
        if locator:
            first_entry["ref"]["key"] = locator
        second = self.challenge(first_entry, local=local, budget=budget)
        third = self.solve(first_entry, entry(second.original), first.nonce, local=local, budget=budget)
        return first, second, third, first_entry

    def verify(self, first, second, third, nonce, **options):
        return probe.verify_bootstrap_answer(first, second, third, caller_nonce=nonce, **self.options(**options))

    def changed(self, item, mutate, signer="subject"):
        document = json.loads(item["raw"])
        mutate(document["payload"])
        document["proof"] = self.signers[signer].sign_message(document["payload"])
        raw = canonical_bytes(document)
        return dict(raw=raw, ref=item["ref"] | dict(raw_sha256=hashlib.sha256(raw).hexdigest(), size=len(raw)))

    def assertCode(self, code, function, *args, **kwargs):
        with self.assertRaises(wire.RepairWireError) as caught:
            function(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def test_real_mutual_exchange_counts_every_actual_outer_hash_and_verification(self):
        local = policy(max_signature_checks=6, max_hashes=44)
        meter = wire.RepairBudget(local)
        first, second, third, first_entry = self.exchange(local, meter)
        result = self.verify(first_entry, entry(second.original), entry(third), second.nonce, local=local, budget=meter)
        self.assertEqual(set(result.originals), {"probe", "challenge", "answer"})
        self.assertEqual(result.at, self.expected["at"])
        self.assertEqual((meter.snapshot()["signature_checks"], meter.snapshot()["hashes"]), (6, 44))
        self.assertEqual(result.originals["answer"].raw, third.raw)
        self.assertCode("repair_over_budget", self.verify, first_entry, entry(second.original), entry(third),
                        second.nonce, local=local, budget=meter)
        self.assertEqual(meter.snapshot()["signature_checks"], 6)
        with self.assertRaises(TypeError):
            result.originals["answer"] = None

    def test_builders_create_fresh_ids_nonces_and_compatible_existing_jwe(self):
        a, b = self.make(), self.make()
        self.assertEqual(len(a.nonce), 32)
        self.assertNotEqual(a.nonce, b.nonce)
        self.assertNotEqual(a.original.payload["probe_id"], b.original.payload["probe_id"])
        payload = json.loads(a.original.raw)["payload"]
        jwe = payload.pop("target_nonce_jwe")
        self.assertEqual(crypto.decrypt_bytes(jwe, self.encryption["target"], context=payload), a.nonce)
        local = policy(max_signature_checks=0)
        self.make(local=local)  # Signing is not mislabeled as a verification.

    def test_offer_exchange_uses_exact_writer_selector_and_both_real_keys(self):
        selector = dict(self.expected["selector"])
        selector["write_grant_sha256"] = selector.pop("read_grant_sha256")
        self.expected.update(consumer="ack_offer", selector=selector)
        local = policy(max_signature_checks=6, max_hashes=44)
        budget = wire.RepairBudget(local)
        first, second, third, first_entry = self.exchange(local, budget)
        result = self.verify(first_entry, entry(second.original), entry(third), second.nonce,
                             local=local, budget=budget)
        self.assertTrue(all(item.payload["consumer"] == "ack_offer" for item in result.originals.values()))
        self.assertEqual((budget.snapshot()["signature_checks"], budget.snapshot()["hashes"]), (6, 44))
        self.assertNotIn("read_grant_sha256", result.originals["probe"].payload["selector"])

    def test_owner_and_offer_consumers_cannot_borrow_each_others_exchange(self):
        owner = self.make()
        selector = dict(self.expected["selector"])
        selector["write_grant_sha256"] = selector.pop("read_grant_sha256")
        self.assertCode("repair_invalid_probe", probe.verify_bootstrap_probe, entry(owner.original),
                        **self.options(consumer="ack_offer", selector=selector))
        offer = self.make(consumer="ack_offer", selector=selector)
        self.assertCode("repair_invalid_probe", probe.verify_bootstrap_probe, entry(offer.original), **self.options())
        # Even the same signing keys cannot re-label a retained encrypted probe:
        # consumer and selector are part of the original AEAD context.
        forged = self.changed(entry(owner.original), lambda p: p.update(consumer="ack_offer", selector=selector))
        self.assertCode("repair_invalid_original", probe.verify_bootstrap_probe, forged,
                        **self.options(consumer="ack_offer", selector=selector))

    def test_offer_rejects_read_selector_and_unknown_consumers_before_signing(self):
        for consumer in ("ack_offer", "mailbox_root", [], None):
            self.assertCode("repair_invalid_probe", self.make, consumer=consumer)

    def test_independently_expected_subject_target_epoch_grant_and_selector(self):
        first = entry(self.make().original)
        _, _, other = probe_fixture()
        changes = (dict(expected_subject=other["expected_subject"]), dict(expected_target=other["expected_target"]),
                   dict(target_storage_epoch="other_epoch"), dict(bootstrap_grant_sha256="b" * 64),
                   dict(selector=self.expected["selector"] | {"ack_slot_sha256": "e" * 64}))
        for change in changes:
            self.assertCode("repair_probe_mismatch", probe.verify_bootstrap_probe, first, **self.options(**change))

    def test_full_raw_references_are_bound_while_opaque_keys_remain_opaque(self):
        first, second, third, first_entry = self.exchange(locator="f" * 64)
        self.assertNotEqual(first_entry["ref"]["key"], first_entry["ref"]["raw_sha256"])
        self.verify(first_entry, entry(second.original), entry(third), second.nonce)
        changed_ref = copy.deepcopy(first_entry)
        changed_ref["ref"]["key"] = "e" * 64
        self.assertCode("repair_probe_mismatch", self.verify, changed_ref, entry(second.original), entry(third), second.nonce)
        first_entry["ref"]["size"] += 1
        self.assertCode("repair_ref_mismatch", self.verify, first_entry, entry(second.original), entry(third), second.nonce)

    def test_closed_shapes_canonical_wire_and_correct_profile_domains(self):
        first = entry(self.make().original)
        for mutation in (lambda p: p.update(head_ref={}), lambda p: p.update(purpose="contact.submit"),
                         lambda p: p.update(consumer="ack_offer"), lambda p: p.update(issued_at=True)):
            self.assertCode("repair_invalid_probe", probe.verify_bootstrap_probe,
                            self.changed(first, mutation), **self.options())
        spaced = dict(raw=b" " + first["raw"], ref=first["ref"])
        self.assertCode("repair_noncanonical_json", probe.verify_bootstrap_probe, spaced, **self.options())
        first["ref"] = wire.RawRef(**first["ref"])
        self.assertCode("repair_invalid_probe", probe.verify_bootstrap_probe, first, **self.options())

    def test_nonce_answers_are_exact_and_do_not_imply_replay_consumption(self):
        first, second, third, first_entry = self.exchange()
        self.assertCode("repair_invalid_nonce", self.solve, first_entry, entry(second.original), b"\0" * 32)
        self.assertCode("repair_invalid_nonce", self.verify, first_entry, entry(second.original), entry(third), b"\0" * 32)
        # Pure verification permits identical local rechecks; the service must
        # persist challenge consumption and refuse repeated network admission.
        self.verify(first_entry, entry(second.original), entry(third), second.nonce)
        self.verify(first_entry, entry(second.original), entry(third), second.nonce)

    def test_re_signed_ciphertext_tampering_fails_actual_aead_and_keeps_work(self):
        first = entry(self.make().original)
        def corrupt(payload):
            encoded = payload["target_nonce_jwe"]["ciphertext"]
            raw = bytearray(crypto.unb64url(encoded, maximum=1024))
            raw[0] ^= 1
            payload["target_nonce_jwe"]["ciphertext"] = crypto.b64url(bytes(raw))
        tampered = self.changed(first, corrupt)
        local = policy()
        meter = wire.RepairBudget(local)
        self.assertCode("repair_decryption_failed", self.challenge, tampered, local=local, budget=meter)
        before = meter.snapshot()
        self.assertEqual(before["signature_checks"], 1)
        self.assertCode("repair_decryption_failed", self.challenge, tampered, local=local, budget=meter)
        self.assertEqual(meter.snapshot()["signature_checks"], 2)
        self.assertGreater(meter.snapshot()["hashes"], before["hashes"])

    def test_jwe_aad_single_recipient_and_recipient_key_are_checked_before_signature(self):
        first = entry(self.make().original)
        mutations = (lambda p: p["target_nonce_jwe"]["recipients"].append(copy.deepcopy(p["target_nonce_jwe"]["recipients"][0])),
                     lambda p: p["target_nonce_jwe"]["recipients"][0]["header"].update(kid=self.expected["expected_subject"]["encryption_key"]["key_id"]),
                     lambda p: p["target_nonce_jwe"].update(aad=crypto.b64url(b"{}")))
        for index, mutation in enumerate(mutations):
            local = policy(); meter = wire.RepairBudget(local)
            with self.assertRaises(wire.RepairWireError):
                probe.verify_bootstrap_probe(self.changed(first, mutation), **self.options(local, meter))
            self.assertEqual(meter.snapshot()["signature_checks"], 0, index)

    def test_explicit_time_has_no_skew_and_children_cannot_extend_parent(self):
        now = self.expected["at"]
        for expiry in (now, now + 61):
            self.assertCode("repair_invalid_probe", probe.make_bootstrap_probe, self.signers["subject"],
                            expires_at=expiry, **self.options())
        first = entry(self.make().original)
        for at in (now - 1, now + 50):
            self.assertCode("repair_invalid_probe", probe.verify_bootstrap_probe, first, **self.options(at=at))
        self.assertCode("repair_probe_mismatch", probe.issue_bootstrap_challenge, first,
            signer=self.signers["target"], encryption_identity=self.encryption["target"],
            expires_at=now + 51, **self.options())
        a, b, _, first_entry = self.exchange()
        self.assertCode("repair_probe_mismatch", probe.solve_bootstrap_challenge, first_entry, entry(b.original),
            signer=self.signers["subject"], encryption_identity=self.encryption["subject"],
            target_nonce=a.nonce, expires_at=now + 41, **self.options())

    def test_wrong_private_key_and_failed_signature_never_yield_success(self):
        first = entry(self.make().original)
        self.assertCode("repair_probe_mismatch", probe.issue_bootstrap_challenge, first,
            signer=self.signers["target"], encryption_identity=self.encryption["subject"],
            expires_at=self.expected["at"] + 40, **self.options())
        signed = json.loads(first["raw"])
        signed["proof"]["signature"] = base64.b64encode(b"\0" * 64).decode()
        raw = canonical_bytes(signed)
        tampered = dict(raw=raw, ref=first["ref"] | dict(raw_sha256=hashlib.sha256(raw).hexdigest(), size=len(raw)))
        local = policy(); meter = wire.RepairBudget(local)
        self.assertCode("repair_invalid_signature", probe.verify_bootstrap_probe, tampered, **self.options(local, meter))
        self.assertEqual(meter.snapshot()["signature_checks"], 1)

    def test_original_snapshots_and_bounded_secret_nonce_buffers(self):
        first, second, third, first_entry = self.exchange()
        first_entry["raw"] = bytearray(first_entry["raw"])
        result = self.verify(first_entry, entry(second.original), entry(third), second.nonce)
        first_entry["raw"][:] = b"x" * len(first_entry["raw"])
        self.assertEqual(result.originals["probe"].raw, first.original.raw)
        from array import array
        huge_nonce = memoryview(array("I", [0] * 32))
        self.assertCode("repair_invalid_nonce", self.verify, entry(first.original), entry(second.original), entry(third), huge_nonce)

    def test_existing_jwe_protected_header_semantics_preserve_key_order(self):
        first = self.make()
        payload = json.loads(first.original.raw)["payload"]
        payload.pop("target_nonce_jwe")
        _, _, jwe, okp = crypto._providers()
        frame = crypto.MAGIC + (32).to_bytes(8, "big") + hashlib.sha256(first.nonce).digest() + first.nonce
        obj = jwe.GeneralJSONEncryption({"typ": crypto.BYTES_SCHEMA, "enc": crypto.ENC}, frame, aad=canonical_bytes(payload))
        recipient = self.expected["expected_target"]["encryption_key"]
        key = okp.import_key(dict(kty="OKP", crv="X25519", x=recipient["public_key"], kid=recipient["key_id"]))
        obj.add_recipient(dict(alg=crypto.ALG, kid=recipient["key_id"]), key)
        value = jwe.encrypt_json(obj, None, registry=crypto._registry(jwe))
        changed = self.changed(entry(first.original), lambda p: p.update(target_nonce_jwe=value))
        self.challenge(changed)


if __name__ == "__main__":
    unittest.main()
