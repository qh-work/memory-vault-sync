"""Synthetic real-signature tests for the isolated open control profile."""
import copy
import hashlib
from pathlib import Path
import tempfile
import unittest

from memory_vault import MemoryError, canonical_bytes
from memory_vault_network_crypto import EncryptionIdentity
from memory_vault_open_control import (
    contact_key, coordinate, issue_contact, issue_lease, issue_node, sign_request,
    sign_response, verify_contact, verify_lease, verify_node, verify_request,
    verify_response,
)
from memory_vault_trust import Identity


class OpenControlTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name).resolve()
        self.owner = Identity.generate(self.path / "owner.json")
        self.server = Identity.generate(self.path / "node.json")
        self.other = Identity.generate(self.path / "other.json")
        self.encryption = EncryptionIdentity.generate()
        self.now = 2_000_000_000
        self.node = self.make_node(self.server)
        self.contact = self.make_contact()

    def make_node(self, signer, **changes):
        values = dict(base_url="http://127.0.0.1:18501", storage_epoch="fixture_epoch",
                      roles=["directory", "router"], revision=1,
                      issued_at=self.now, expires_at=self.now + 3600)
        values.update(changes)
        return issue_node(signer, **values)

    def make_contact(self, **changes):
        values = dict(encryption_key=self.encryption.public_descriptor(), revision=1,
                      allow_discovery=True, endpoints=[], issued_at=self.now,
                      expires_at=self.now + 3600)
        values.update(changes)
        return issue_contact(self.owner, **values)

    def request(self, action, body, **changes):
        values = dict(action=action, request_id="synthetic_request", node=self.node,
                      body=body, issued_at=self.now, expires_at=self.now + 60)
        values.update(changes)
        return sign_request(self.owner, **values)

    @staticmethod
    def resigned(signer, document):
        result = copy.deepcopy(document)
        result["proof"] = signer.sign_message(result["payload"])
        return result

    def test_self_certified_coordinates_and_separate_contact_domain(self):
        expected = hashlib.sha256(b"memory-vault-open-routing/v1\x00" + self.server.key_id.encode()).hexdigest()
        self.assertEqual(coordinate(self.server.key_id), expected)
        self.assertNotEqual(contact_key(self.server.key_id), expected)
        self.assertEqual(verify_node(self.node, now=self.now)["coordinate"], expected)
        self.assertEqual(verify_contact(self.contact, now=self.now)["signing_key"], self.owner.public_descriptor())
        wrong = copy.deepcopy(self.node)
        wrong["payload"]["coordinate"] = "0" * 64
        with self.assertRaisesRegex(MemoryError, "open_coordinate_mismatch"):
            verify_node(self.resigned(self.server, wrong), now=self.now)

    def test_all_request_actions_strict_and_signed(self):
        bodies = [("hello", {"node": None}), ("find", {"target": coordinate(self.other.key_id), "view": "directory"}),
                  ("get", {"key": contact_key(self.owner.key_id)}),
                  ("put", {"contact": self.contact, "lease_seconds": 120}),
                  ("renew", {"contact": self.contact, "lease_seconds": 120, "lease_id": "synthetic_lease"})]
        for action, body in bodies:
            with self.subTest(action=action):
                request = self.request(action, body)
                self.assertEqual(verify_request(request, node=self.node, now=self.now)["body"], body)
                wrong = copy.deepcopy(request)
                wrong["payload"]["request_id"] = "substituted_request"
                with self.assertRaises(MemoryError):
                    verify_request(wrong, node=self.node, now=self.now)
                wrong = copy.deepcopy(request)
                wrong["payload"]["body"]["arbitrary"] = "not allowed"
                with self.assertRaises(MemoryError):
                    verify_request(self.resigned(self.owner, wrong), node=self.node, now=self.now)
        with self.assertRaisesRegex(MemoryError, "open_sender_mismatch"):
            self.request("hello", {"node": self.node})

    def test_response_exact_request_node_epoch_and_local_clock_binding(self):
        request = self.request("hello", {"node": None})
        response = sign_response(self.server, request=request, node=self.node, body={"node": self.node},
                                 issued_at=self.now, expires_at=self.now + 60)
        self.assertEqual(verify_response(response, request=request, node=self.node, now=self.now)["body"]["node"], self.node)
        for field, replacement in [("request_id", "other_request"), ("request_sha256", "0" * 64),
                                   ("node_key_id", self.other.key_id), ("storage_epoch", "other_epoch")]:
            changed = copy.deepcopy(response)
            changed["payload"][field] = replacement
            with self.subTest(field=field), self.assertRaises(MemoryError):
                verify_response(self.resigned(self.server, changed), request=request, node=self.node, now=self.now)
        with self.assertRaises(MemoryError):
            verify_response(response, request=request, node=self.node, now=self.now + 60)
        with self.assertRaises(MemoryError):
            verify_node(self.node, now=self.now - 31)
        changed = copy.deepcopy(response)
        changed["payload"]["issued_at"] += 1
        changed["payload"]["expires_at"] += 1
        with self.assertRaises(MemoryError):
            verify_response(self.resigned(self.server, changed), request=request, node=self.node, now=self.now + 1)

    def test_public_pointers_reject_private_payloads_unhashable_kind_and_limits(self):
        for kind in ([], {}, None):
            bad = copy.deepcopy(self.contact)
            bad["payload"]["kind"] = kind
            with self.subTest(kind=kind), self.assertRaises(MemoryError):
                verify_contact(self.resigned(self.owner, bad), now=self.now)
        for field in ("memory_id", "text", "grant", "private_key"):
            bad = copy.deepcopy(self.contact)
            bad["payload"][field] = "synthetic prohibited field"
            with self.subTest(field=field), self.assertRaises(MemoryError):
                verify_contact(self.resigned(self.owner, bad), now=self.now)
        endpoint = dict(kind="node", node_key_id=self.server.key_id,
                        base_url="http://127.0.0.1:18501", storage_epoch="fixture_epoch")
        self.assertEqual(len(verify_contact(self.make_contact(endpoints=[endpoint]), now=self.now)["endpoints"]), 1)
        with self.assertRaises(MemoryError):
            self.make_contact(endpoints=[endpoint] * 5)
        with self.assertRaises(MemoryError):
            self.make_node(self.server, base_url="https://" + "a" * 510)
        with self.assertRaises(MemoryError):
            self.make_node(self.server, roles=["router", "directory"])
        with self.assertRaises(MemoryError):
            self.make_contact(revision=True)

    def test_real_lease_signature_binding_and_no_boolean_revision(self):
        request = self.request("put", {"contact": self.contact, "lease_seconds": 120})
        lease = issue_lease(self.server, node=self.node, contact=self.contact, request=request,
                            lease_id="synthetic_lease", issued_at=self.now, expires_at=self.now + 120)
        self.assertEqual(verify_lease(lease, node=self.node, contact=self.contact, now=self.now)["expires_at"], self.now + 120)
        response = sign_response(self.server, request=request, node=self.node, body={"lease": lease},
                                 issued_at=self.now, expires_at=self.now + 60)
        verify_response(response, request=request, node=self.node, now=self.now)
        for field, value in (("contact_revision", True), ("owner_key_id", self.other.key_id),
                             ("contact_sha256", "f" * 64), ("storage_epoch", "different_epoch")):
            changed = copy.deepcopy(lease)
            changed["payload"][field] = value
            with self.subTest(field=field), self.assertRaises(MemoryError):
                verify_lease(self.resigned(self.server, changed), node=self.node, contact=self.contact, now=self.now)

    def test_find_candidates_and_duplicate_json_are_bounded(self):
        request = self.request("find", {"target": "0" * 64, "view": "general"})
        with self.assertRaisesRegex(MemoryError, "open_duplicate_candidate"):
            sign_response(self.server, request=request, node=self.node, body={"nodes": [self.node, self.node]},
                          issued_at=self.now, expires_at=self.now + 60)
        encoded = canonical_bytes(self.node)
        duplicate = b'{"payload":{},' + encoded[1:]
        with self.assertRaises(MemoryError):
            verify_node(duplicate, now=self.now)


if __name__ == "__main__":
    unittest.main()
