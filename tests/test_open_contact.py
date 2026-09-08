"""Bounded first-contact protocol checks with real Ed25519/X25519/JWE.

All identities and control documents are synthetic. These tests establish
protocol validation, not network delivery or independent fault domains.
"""
import copy
import hashlib
from pathlib import Path
import tempfile
import unittest

from memory_vault import MemoryError, canonical_bytes
from memory_vault_network_crypto import (
    EncryptionIdentity, b64url, document_sha256, encrypt_bytes, unb64url,
)
from memory_vault_open_contact import (
    CHALLENGE_SECONDS, MAX_CONTROL_BYTES, MAX_DECISION_BYTES, MAX_REQUEST_BYTES,
    SLOT_BYTES, issue_challenge, sign_document, sign_response, sign_rpc,
    solve_challenge, verify_challenge, verify_decision, verify_document,
    verify_lease, verify_policy, verify_request, verify_response, verify_rpc,
)
from memory_vault_open_control import issue_node
from memory_vault_trust import Identity


class OpenContactProtocolTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = root = Path(temporary.name).resolve()
        self.server = Identity.generate(root / "synthetic_node.json")
        self.recipient = Identity.generate(root / "synthetic_recipient.json")
        self.sender = Identity.generate(root / "synthetic_sender.json")
        self.other = Identity.generate(root / "synthetic_other.json")
        self.recipient_encryption = EncryptionIdentity.generate()
        self.sender_encryption = EncryptionIdentity.generate()
        self.other_encryption = EncryptionIdentity.generate()
        self.now = 2_000_000_000
        self.node = self.make_node()
        self.lease = self.make_lease("knock")
        self.policy = self.make_policy()
        self.request = self.make_request()

    def make_node(self, **changes):
        values = dict(base_url="http://127.0.0.1:18501", storage_epoch="synthetic_epoch",
                      roles=["directory", "router"], revision=1,
                      issued_at=self.now, expires_at=self.now + 3600)
        values.update(changes)
        return issue_node(self.server, **values)

    def signed(self, signer, kind, **values):
        fields = dict(issued_at=self.now, expires_at=self.now + 600)
        fields.update(values)
        return sign_document(signer, kind, **fields)

    def make_lease(self, purpose, **changes):
        values = dict(node_key_id=self.server.key_id, storage_epoch="synthetic_epoch",
                      owner_key_id=self.recipient.key_id,
                      owner_encryption_key=self.recipient_encryption.public_descriptor(),
                      lease_id="synthetic_" + purpose + "_lease",
                      resource_id="synthetic_" + purpose + "_resource", purpose=purpose,
                      max_items=2, max_bytes=2 * SLOT_BYTES if purpose == "knock" else 32768)
        values.update(changes)
        return self.signed(self.server, "resource.lease", **values)

    def make_policy(self, **changes):
        lease = self.lease["payload"]
        values = dict(node_key_id=lease["node_key_id"], storage_epoch=lease["storage_epoch"],
                      lease_id=lease["lease_id"], lease_sha256=document_sha256(self.lease),
                      resource_id=lease["resource_id"],
                      encryption_key=self.recipient_encryption.public_descriptor(),
                      revision=1, status="active", max_pending=2)
        values.update(changes)
        return self.signed(self.recipient, "contact.policy", **values)

    def make_request(self, **changes):
        policy = self.policy["payload"]
        values = dict(request_id="synthetic_request", encryption_key=self.sender_encryption.public_descriptor(),
                      recipient_key_id=self.recipient.key_id,
                      recipient_encryption_key_id=self.recipient_encryption.key_id,
                      policy_sha256=document_sha256(self.policy), request_class="message",
                      **{key: policy[key] for key in ("node_key_id", "storage_epoch", "lease_id", "resource_id")})
        values.update(changes)
        return self.signed(self.sender, "contact.request", **values)

    def make_grant(self, **changes):
        lease = self.make_lease("delivery")
        values = dict(request_id=self.request["payload"]["request_id"],
                      request_sha256=document_sha256(self.request), subject_key_id=self.sender.key_id,
                      subject_encryption_key_id=self.sender_encryption.key_id,
                      recipient_encryption_key_id=self.recipient_encryption.key_id,
                      resource_lease=lease, operations=["message.store"],
                      **{key: lease["payload"][key] for key in ("node_key_id", "storage_epoch", "resource_id")})
        values.update(changes)
        return self.signed(self.recipient, "contact.grant", **values)

    def make_decision(self, approved=True, **changes):
        values = dict(request_id=self.request["payload"]["request_id"],
                      request_sha256=document_sha256(self.request), subject_key_id=self.sender.key_id,
                      subject_encryption_key_id=self.sender_encryption.key_id,
                      recipient_encryption_key_id=self.recipient_encryption.key_id,
                      node_key_id=self.server.key_id, storage_epoch="synthetic_epoch",
                      policy_sha256=document_sha256(self.policy),
                      decision="approved" if approved else "rejected",
                      reason="accepted" if approved else "declined",
                      grant=self.make_grant() if approved else None)
        values.update(changes)
        return self.signed(self.recipient, "contact.decision", **values)

    @staticmethod
    def changed(value, signer, **changes):
        """Re-sign malformed documents so schema tests do not rely on bad proofs."""
        result = copy.deepcopy(value)
        result["payload"].update(changes)
        result["proof"] = signer.sign_message(result["payload"])
        return result

    def verify_request(self, value, **changes):
        values = dict(policy=self.policy, lease=self.lease, node=self.node, now=self.now)
        values.update(changes)
        return verify_request(value, **values)

    def verify_decision(self, value, **changes):
        values = dict(request=self.request, policy=self.policy, lease=self.lease,
                      node=self.node, now=self.now)
        values.update(changes)
        return verify_decision(value, **values)

    def result_rpc(self):
        challenge, _ = issue_challenge(self.server, request=self.request, node=self.node,
                                       purpose="result", now=self.now)
        answer = solve_challenge(challenge, request=self.request, node=self.node, purpose="result",
                                 encryption_identity=self.sender_encryption, now=self.now)
        return sign_rpc(self.sender, node=self.node, action="result",
            body=dict(request=self.request, challenge=challenge, answer=answer), now=self.now)

    def test_valid_opt_in_request_and_explicit_finite_delivery_decision(self):
        self.assertEqual(verify_lease(self.lease, node=self.node, now=self.now)["purpose"], "knock")
        self.assertEqual(verify_policy(self.policy, lease=self.lease, node=self.node,
                                       now=self.now)["status"], "active")
        self.assertEqual(self.verify_request(self.request)["request_class"], "message")
        decision = self.verify_decision(self.make_decision())
        grant = decision["grant"]["payload"]
        reservation = grant["resource_lease"]["payload"]
        self.assertEqual(grant["operations"], ["message.store"])
        self.assertEqual(reservation["purpose"], "delivery")
        self.assertEqual(reservation["resource_id"], grant["resource_id"])
        self.assertEqual((reservation["max_items"], reservation["max_bytes"]), (2, 32768))
        self.assertLessEqual(grant["expires_at"], reservation["expires_at"])
        self.assertEqual(self.verify_decision(self.make_decision(False))["grant"], None)

    def test_real_challenge_roundtrip_requires_both_requester_keys(self):
        for purpose in ("submit", "result"):
            with self.subTest(purpose=purpose):
                challenge, expected_hash = issue_challenge(self.server, request=self.request,
                    node=self.node, purpose=purpose, now=self.now)
                answer = solve_challenge(challenge, request=self.request, node=self.node,
                    purpose=purpose, encryption_identity=self.sender_encryption, now=self.now)
                plaintext = unb64url(answer, maximum=32, size=32)
                self.assertEqual(hashlib.sha256(plaintext).hexdigest(), expected_hash)
                self.assertNotIn(answer, canonical_bytes(challenge).decode())
                with self.assertRaisesRegex(MemoryError, "contact_wrong_subject"):
                    solve_challenge(challenge, request=self.request, node=self.node,
                        purpose=purpose, encryption_identity=self.other_encryption, now=self.now)
                body = dict(request=self.request, challenge=challenge, answer=answer)
                signed = sign_rpc(self.sender, node=self.node, action=purpose, body=body, now=self.now)
                self.assertEqual(verify_rpc(signed, node=self.node, now=self.now)["signing_key"],
                                 self.sender.public_descriptor())
                wrong = sign_rpc(self.other, node=self.node, action=purpose, body=body, now=self.now)
                with self.assertRaisesRegex(MemoryError, "contact_wrong_subject"):
                    verify_rpc(wrong, node=self.node, now=self.now)

    def test_challenge_rejects_wrong_purpose_request_node_signer_and_expiry(self):
        challenge, _ = issue_challenge(self.server, request=self.request, node=self.node,
                                       purpose="submit", now=self.now)
        cases = [dict(purpose="result"), dict(request=self.make_request(request_id="other_request")),
                 dict(node=self.make_node(storage_epoch="restarted_epoch")),
                 dict(now=self.now + CHALLENGE_SECONDS)]
        for changes in cases:
            values = dict(request=self.request, node=self.node, purpose="submit", now=self.now)
            values.update(changes)
            with self.subTest(changes=changes.keys()), self.assertRaises(MemoryError):
                verify_challenge(challenge, **values)
        context = {key: value for key, value in challenge["payload"].items() if key != "jwe"}
        context["signing_key"] = self.other.public_descriptor()
        forged = {"payload": {**context, "jwe": encrypt_bytes(b"x" * 32,
                    [self.sender_encryption.public_descriptor()], context=context)}}
        forged["proof"] = self.other.sign_message(forged["payload"])
        with self.assertRaisesRegex(MemoryError, "contact_challenge_mismatch"):
            verify_challenge(forged, request=self.request, node=self.node, purpose="submit", now=self.now)
        with self.assertRaisesRegex(MemoryError, "contact_wrong_node"):
            issue_challenge(self.other, request=self.request, node=self.node, purpose="submit", now=self.now)

    def test_challenge_jwe_cannot_be_rebound_or_have_ciphertext_tampered(self):
        challenge, _ = issue_challenge(self.server, request=self.request, node=self.node,
                                       purpose="submit", now=self.now)
        rebound = self.changed(challenge, self.server, purpose="result")
        with self.assertRaises(MemoryError):
            solve_challenge(rebound, request=self.request, node=self.node, purpose="result",
                            encryption_identity=self.sender_encryption, now=self.now)
        damaged = copy.deepcopy(challenge)
        ciphertext = unb64url(damaged["payload"]["jwe"]["ciphertext"], maximum=256)
        damaged["payload"]["jwe"]["ciphertext"] = b64url(bytes([ciphertext[0] ^ 1]) + ciphertext[1:])
        damaged = self.changed(damaged, self.server)
        with self.assertRaises(MemoryError):
            solve_challenge(damaged, request=self.request, node=self.node, purpose="submit",
                            encryption_identity=self.sender_encryption, now=self.now)

    def test_challenge_plaintext_is_exactly_32_bytes_and_has_one_recipient(self):
        challenge, _ = issue_challenge(self.server, request=self.request, node=self.node,
                                       purpose="submit", now=self.now)
        context = {key: value for key, value in challenge["payload"].items() if key != "jwe"}
        for length in (0, 31, 33, 129):
            changed = self.changed(challenge, self.server,
                jwe=encrypt_bytes(b"x" * length, [self.sender_encryption.public_descriptor()], context=context))
            with self.subTest(length=length), self.assertRaises(MemoryError):
                solve_challenge(changed, request=self.request, node=self.node, purpose="submit",
                                encryption_identity=self.sender_encryption, now=self.now)
        recipients = [self.sender_encryption.public_descriptor(), self.other_encryption.public_descriptor()]
        changed = self.changed(challenge, self.server, jwe=encrypt_bytes(b"x" * 32, recipients, context=context))
        with self.assertRaises(MemoryError):
            verify_challenge(changed, request=self.request, node=self.node, purpose="submit", now=self.now)

    def test_request_rejects_arbitrary_content_and_missing_or_extra_fields(self):
        for field in ("text", "message", "payload", "memory", "private_key", "grant", "body"):
            with self.subTest(field=field), self.assertRaises(MemoryError):
                self.verify_request(self.changed(self.request, self.sender, **{field: "synthetic forbidden content"}))
        for value in ("arbitrary text", [], {}, None):
            with self.subTest(value=value), self.assertRaises(MemoryError):
                self.verify_request(value)
        for field in self.request["payload"]:
            missing = copy.deepcopy(self.request)
            del missing["payload"][field]
            with self.subTest(missing=field), self.assertRaises(MemoryError):
                self.verify_request(self.changed(missing, self.sender))
        extra_envelope = {**self.request, "extra": "forbidden"}
        with self.assertRaises(MemoryError):
            self.verify_request(extra_envelope)

    def test_request_rejects_booleans_unsafe_numbers_invalid_times_and_identifiers(self):
        for field in ("issued_at", "expires_at"):
            for value in (True, False, -1, 9_007_199_254_740_992, 2.5, "2000000000"):
                with self.subTest(field=field, value=value), self.assertRaises(MemoryError):
                    self.verify_request(self.changed(self.request, self.sender, **{field: value}))
        for fields in (dict(expires_at=self.now), dict(expires_at=self.now + 86401),
                       dict(issued_at=self.now + 31, expires_at=self.now + 100)):
            with self.subTest(fields=fields), self.assertRaises(MemoryError):
                self.verify_request(self.changed(self.request, self.sender, **fields))
        for field in ("request_id", "lease_id", "resource_id", "storage_epoch"):
            for value in ("", "*", "id with spaces", "x" * 129, True, 1, None):
                with self.subTest(field=field, value=value), self.assertRaises(MemoryError):
                    self.verify_request(self.changed(self.request, self.sender, **{field: value}))
        for value in ("*", "write", ["message"], {}, True):
            with self.subTest(request_class=value), self.assertRaises(MemoryError):
                self.verify_request(self.changed(self.request, self.sender, request_class=value))

    def test_request_requires_current_recipient_policy_and_exact_lease_bindings(self):
        changes = dict(recipient_key_id=self.other.key_id,
                       recipient_encryption_key_id=self.other_encryption.key_id,
                       policy_sha256="f" * 64, node_key_id=self.other.key_id,
                       storage_epoch="other_epoch", lease_id="other_lease", resource_id="other_resource")
        for field, value in changes.items():
            with self.subTest(field=field), self.assertRaisesRegex(MemoryError, "contact_request_mismatch"):
                self.verify_request(self.changed(self.request, self.sender, **{field: value}))
        with self.assertRaisesRegex(MemoryError, "contact_request_mismatch"):
            self.verify_request(self.request, policy=self.make_policy(status="revoked"))
        with self.assertRaisesRegex(MemoryError, "contact_self_request"):
            self.verify_request(self.changed(self.request, self.recipient,
                signing_key=self.recipient.public_descriptor()))
        with self.assertRaises(MemoryError):
            self.verify_request(self.request, now=self.now + 600)

    def test_policy_cannot_claim_another_owner_key_resource_or_excess_quota(self):
        changes = dict(encryption_key=self.other_encryption.public_descriptor(),
                       lease_sha256="f" * 64, max_pending=3, resource_id="another_resource",
                       expires_at=self.now + 601)
        for field, value in changes.items():
            changed = self.changed(self.policy, self.recipient, **{field: value})
            with self.subTest(field=field), self.assertRaisesRegex(MemoryError, "contact_policy_mismatch"):
                verify_policy(changed, lease=self.lease, node=self.node, now=self.now)
        changed = self.changed(self.policy, self.other, signing_key=self.other.public_descriptor())
        with self.assertRaisesRegex(MemoryError, "contact_policy_mismatch"):
            verify_policy(changed, lease=self.lease, node=self.node, now=self.now)

    def test_resource_reservations_have_finite_limits_and_knock_result_budget(self):
        for field, values in {"max_items": [True, 0, 33, 9_007_199_254_740_992],
                              "max_bytes": [True, 0, 16 * 1024 * 1024 + 1]}.items():
            for value in values:
                with self.subTest(field=field, value=value), self.assertRaises(MemoryError):
                    self.make_lease("delivery", **{field: value})
        for size in (SLOT_BYTES, 2 * SLOT_BYTES - 1, 2 * SLOT_BYTES + 1):
            with self.subTest(knock_bytes=size), self.assertRaisesRegex(MemoryError, "contact_invalid_reservation"):
                self.make_lease("knock", max_bytes=size)
        for purpose in ("directory", "index", "*", True):
            with self.subTest(purpose=purpose), self.assertRaises(MemoryError):
                verify_document(self.changed(self.lease, self.server, purpose=purpose), "resource.lease", now=self.now)

    def test_grant_rejects_knock_lease_wildcard_and_extra_authority(self):
        with self.assertRaisesRegex(MemoryError, "contact_grant_mismatch"):
            self.make_grant(resource_lease=self.lease, resource_id=self.lease["payload"]["resource_id"])
        for operations in ([], ["*"], ["message.store", "memory.remember"], ["memory.read"], "message.store"):
            with self.subTest(operations=operations), self.assertRaisesRegex(MemoryError, "contact_invalid_scope"):
                self.make_grant(operations=operations)
        for resource in ("*", "", "all/resources"):
            with self.subTest(resource=resource), self.assertRaises(MemoryError):
                self.make_grant(resource_id=resource)
        grant = self.make_grant()
        for field, value in dict(node_key_id=self.other.key_id, storage_epoch="other_epoch",
                                resource_id="other_resource", recipient_encryption_key_id=self.other_encryption.key_id,
                                expires_at=self.now + 601).items():
            with self.subTest(field=field), self.assertRaisesRegex(MemoryError, "contact_grant_mismatch"):
                verify_document(self.changed(grant, self.recipient, **{field: value}), "contact.grant", now=self.now)

    def test_decision_binds_original_request_both_parties_node_policy_and_expiry(self):
        decision = self.make_decision(False)
        changes = dict(request_id="other_request", request_sha256="f" * 64,
                       subject_key_id=self.other.key_id, subject_encryption_key_id=self.other_encryption.key_id,
                       recipient_encryption_key_id=self.other_encryption.key_id, node_key_id=self.other.key_id,
                       storage_epoch="other_epoch", policy_sha256="f" * 64, expires_at=self.now + 601)
        for field, value in changes.items():
            with self.subTest(field=field), self.assertRaisesRegex(MemoryError, "contact_decision_mismatch"):
                self.verify_decision(self.changed(decision, self.recipient, **{field: value}))
        other = self.changed(decision, self.other, signing_key=self.other.public_descriptor())
        with self.assertRaisesRegex(MemoryError, "contact_decision_mismatch"):
            self.verify_decision(other)
        with self.assertRaisesRegex(MemoryError, "contact_decision_mismatch"):
            self.verify_decision(decision, request=self.make_request(request_id="substitute"))
        with self.assertRaises(MemoryError):
            self.verify_decision(decision, now=self.now + 600)

    def test_approved_decision_requires_matching_grant_and_rejection_has_none(self):
        approved = self.make_decision()
        for field, value in dict(request_id="other_request", request_sha256="f" * 64,
                                subject_key_id=self.other.key_id,
                                subject_encryption_key_id=self.other_encryption.key_id,
                                recipient_encryption_key_id=self.other_encryption.key_id).items():
            grant = self.changed(approved["payload"]["grant"], self.recipient, **{field: value})
            with self.subTest(field=field), self.assertRaises(MemoryError):
                self.verify_decision(self.changed(approved, self.recipient, grant=grant))
        for value in (dict(grant=None), dict(reason="declined"), dict(expires_at=self.now + 599)):
            with self.subTest(value=value), self.assertRaises(MemoryError):
                self.verify_decision(self.changed(approved, self.recipient, **value))
        rejected = self.make_decision(False)
        for value in (dict(grant=approved["payload"]["grant"]), dict(reason="accepted"), dict(reason="freeform text")):
            with self.subTest(value=value), self.assertRaises(MemoryError):
                self.verify_decision(self.changed(rejected, self.recipient, **value))

    def test_tampered_signatures_never_validate(self):
        documents = [(self.lease, "resource.lease"), (self.policy, "contact.policy"),
                     (self.request, "contact.request"), (self.make_grant(), "contact.grant"),
                     (self.make_decision(), "contact.decision")]
        for value, kind in documents:
            wrong = copy.deepcopy(value)
            wrong["proof"] = self.other.sign_message(wrong["payload"])
            with self.subTest(kind=kind), self.assertRaisesRegex(MemoryError, "contact_invalid_signature"):
                verify_document(wrong, kind, now=self.now)

    def test_duplicate_json_oversize_and_unknown_profiles_are_rejected(self):
        encoded = canonical_bytes(self.request)
        duplicate = b'{"payload":{},' + encoded[1:]
        with self.assertRaises(MemoryError):
            self.verify_request(duplicate)
        with self.assertRaisesRegex(MemoryError, "network_document_too_large"):
            self.verify_request(encoded + b" " * MAX_REQUEST_BYTES)
        for field, value in (("schema_version", "unrelated/v1"), ("kind", "memory"), ("kind", {})):
            with self.subTest(field=field, value=value), self.assertRaises(MemoryError):
                self.verify_request(self.changed(self.request, self.sender, **{field: value}))

    def test_rpc_response_binding_and_no_freeform_success_or_error_fields(self):
        rpc = sign_rpc(self.sender, node=self.node, action="policy.get",
                       body={"recipient_key_id": self.recipient.key_id}, now=self.now)
        response = sign_response(self.server, request=rpc, node=self.node,
                                 body={"lease": self.lease, "policy": self.policy}, now=self.now)
        self.assertEqual(verify_response(response, request=rpc, node=self.node,
                                        now=self.now)["body"]["policy"], self.policy)
        for field, value in dict(request_id="different", request_sha256="0" * 64,
                                node_key_id=self.other.key_id, storage_epoch="other_epoch").items():
            with self.subTest(field=field), self.assertRaises(MemoryError):
                verify_response(self.changed(response, self.server, **{field: value}),
                                request=rpc, node=self.node, now=self.now)
        for body in ({"lease": self.lease, "policy": self.policy, "text": "forbidden"},
                     {"error": {"code": "contact_full", "retryable": 1}},
                     {"error": {"code": "contact_full", "retryable": True, "text": "forbidden"}}):
            with self.subTest(body=body.keys()), self.assertRaises(MemoryError):
                verify_response(self.changed(response, self.server, body=body),
                                request=rpc, node=self.node, now=self.now)
        with self.assertRaises(MemoryError):
            sign_rpc(self.sender, node=self.node, action="message.store", body={}, now=self.now)

    def test_real_documents_and_nested_rpc_fit_declared_budgets(self):
        challenge, _ = issue_challenge(self.server, request=self.request, node=self.node,
                                       purpose="submit", now=self.now)
        answer = solve_challenge(challenge, request=self.request, node=self.node, purpose="submit",
                                 encryption_identity=self.sender_encryption, now=self.now)
        decision = self.make_decision()
        documents = [(self.lease, MAX_REQUEST_BYTES), (self.policy, MAX_REQUEST_BYTES),
                     (self.request, MAX_REQUEST_BYTES), (challenge, MAX_REQUEST_BYTES),
                     (decision["payload"]["grant"], MAX_REQUEST_BYTES), (decision, MAX_DECISION_BYTES)]
        for value, maximum in documents:
            with self.subTest(kind=value["payload"]["kind"]):
                self.assertLessEqual(len(canonical_bytes(value)), maximum)
        submit = sign_rpc(self.sender, node=self.node, action="submit",
            body=dict(request=self.request, challenge=challenge, answer=answer), now=self.now)
        decide = sign_rpc(self.recipient, node=self.node, action="decide",
            body=dict(request=self.request, decision=decision), now=self.now)
        for rpc in (submit, decide):
            self.assertLessEqual(len(canonical_bytes(rpc)), MAX_CONTROL_BYTES)
            verify_rpc(rpc, node=self.node, now=self.now)
        self.assertLessEqual(len(canonical_bytes(self.request)) + len(canonical_bytes(decision)) + 512,
                             SLOT_BYTES)

    def test_result_response_rejects_validly_signed_decision_substitution(self):
        rpc = self.result_rpc()
        decision = self.make_decision(False)
        response = sign_response(self.server, request=rpc, node=self.node,
            body=dict(state="rejected", decision=decision), now=self.now)
        verify_response(response, request=rpc, node=self.node, now=self.now)
        replacements = dict(request_id="other_request", request_sha256="f" * 64,
                            subject_key_id=self.other.key_id,
                            subject_encryption_key_id=self.other_encryption.key_id,
                            recipient_encryption_key_id=self.other_encryption.key_id,
                            node_key_id=self.other.key_id, storage_epoch="other_epoch",
                            policy_sha256="f" * 64, expires_at=self.now + 601)
        for field, value in replacements.items():
            changed = self.changed(decision, self.recipient, **{field: value})
            swapped = self.changed(response, self.server, body=dict(state="rejected", decision=changed))
            with self.subTest(field=field), self.assertRaisesRegex(MemoryError, "contact_decision_mismatch"):
                verify_response(swapped, request=rpc, node=self.node, now=self.now)
        changed = self.changed(decision, self.other, signing_key=self.other.public_descriptor())
        swapped = self.changed(response, self.server, body=dict(state="rejected", decision=changed))
        with self.assertRaisesRegex(MemoryError, "contact_decision_mismatch"):
            verify_response(swapped, request=rpc, node=self.node, now=self.now)

    def test_result_response_requires_current_resource_node_and_exact_state(self):
        rpc = self.result_rpc()
        lease = self.changed(self.make_lease("delivery"), self.other,
            node_key_id=self.other.key_id, signing_key=self.other.public_descriptor())
        grant = self.make_grant(resource_lease=lease, node_key_id=self.other.key_id)
        decision = self.make_decision(grant=grant)
        response = sign_response(self.server, request=rpc, node=self.node,
                                 body=dict(state="approved", decision=decision), now=self.now)
        with self.assertRaisesRegex(MemoryError, "contact_wrong_node"):
            verify_response(response, request=rpc, node=self.node, now=self.now)
        for body in (dict(state="pending", decision=self.make_decision()),
                     dict(state="approved", decision=self.make_decision(False)),
                     dict(state="rejected", decision=None)):
            with self.subTest(body=body["state"]), self.assertRaises(MemoryError):
                verify_response(self.changed(response, self.server, body=body),
                                request=rpc, node=self.node, now=self.now)

    def test_policy_put_response_cannot_claim_the_opposite_state(self):
        rpc = sign_rpc(self.recipient, node=self.node, action="policy.put",
                       body=dict(lease=self.lease, policy=self.policy), now=self.now)
        response = sign_response(self.server, request=rpc, node=self.node,
                                 body=dict(state="active"), now=self.now)
        verify_response(response, request=rpc, node=self.node, now=self.now)
        with self.assertRaisesRegex(MemoryError, "contact_policy_mismatch"):
            verify_response(self.changed(response, self.server, body=dict(state="revoked")),
                            request=rpc, node=self.node, now=self.now)

    def test_nested_rpc_enums_reject_unknown_strings_and_non_strings(self):
        rpc = sign_rpc(self.sender, node=self.node, action="challenge",
                       body=dict(request=self.request, purpose="submit"), now=self.now)
        for value in ("unknown", "__proto__", "toString", [], {}, True, None):
            with self.subTest(action=value), self.assertRaises(MemoryError):
                verify_rpc(self.changed(rpc, self.sender, action=value), node=self.node, now=self.now)
            body = dict(request=self.request, purpose=value)
            with self.subTest(purpose=value), self.assertRaises(MemoryError):
                verify_rpc(self.changed(rpc, self.sender, body=body), node=self.node, now=self.now)

    def test_resource_node_cannot_extend_explicitly_requested_lease_duration(self):
        body = dict(encryption_key=self.recipient_encryption.public_descriptor(), purpose="knock",
                    max_items=2, max_bytes=2 * SLOT_BYTES, lease_seconds=1, allocation_id="synthetic_one_second")
        rpc = sign_rpc(self.recipient, node=self.node, action="lease", body=body, now=self.now)
        response = sign_response(self.server, request=rpc, node=self.node,
                                 body=dict(lease=self.lease), now=self.now)
        with self.assertRaisesRegex(MemoryError, "contact_lease_mismatch"):
            verify_response(response, request=rpc, node=self.node, now=self.now)
        limited = self.make_lease("knock", expires_at=self.now + 1)
        response = sign_response(self.server, request=rpc, node=self.node,
                                 body=dict(lease=limited), now=self.now)
        verify_response(response, request=rpc, node=self.node, now=self.now)


if __name__ == "__main__":
    unittest.main()
