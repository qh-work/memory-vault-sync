"""Synthetic node-control checks; no public network, user data, or services."""
from __future__ import annotations

import copy
from pathlib import Path
import tempfile
import time
import unittest

from memory_vault import MemoryError, canonical_bytes
from memory_vault_network_control import (
    create_authority_app, issue_roster, sign_request, verify_request, verify_status,
)
from memory_vault_network_crypto import EncryptionIdentity, PublicKeyTrust, document_sha256
from memory_vault_nodes import (
    authorized_node, issue_directory, issue_node_status, sign_node_request,
    verify_directory, verify_node_request, verify_node_status,
)
from memory_vault_storage import atomic_write
from memory_vault_trust import Identity, TrustStore


class NetworkNodeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="memory-nodes-synthetic-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.issuer, self.first, self.second, self.member = [Identity.generate(self.root / (name + ".json"))
            for name in ("issuer", "first", "second", "member")]
        self.trust = PublicKeyTrust([self.issuer.public_descriptor()])
        self.now = int(time.time())
        self.network = "synthetic-node-network"
        self.entry = self.node(self.first, "http://127.0.0.1:8765", "synthetic-epoch-first")
        self.directory = self.issue([self.entry])

    def node(self, identity, url, epoch, status="active"):
        return {"signing_key": identity.public_descriptor(), "base_url": url, "storage_epoch": epoch,
                "scope": ["export", "import", "node.status"], "status": status}

    def issue(self, nodes, previous=None, **overrides):
        args = {"network_id": self.network, "version": 1 if previous is None else previous["payload"]["version"] + 1,
                "previous_sha256": "0" * 64 if previous is None else document_sha256(previous),
                "nodes": nodes, "issued_at": self.now, "expires_at": self.now + 300}
        args.update(overrides)
        return issue_directory(self.issuer, **args)

    def verify(self, directory, **kwargs):
        return verify_directory(directory, self.trust, network_id=self.network, now=self.now, **kwargs)

    def reject(self, code, operation):
        with self.assertRaises(MemoryError) as caught:
            operation()
        self.assertEqual(caught.exception.code, code)

    def request(self, signer=None, action="refresh", body=None):
        return sign_node_request(signer or self.first, network_id=self.network, action=action,
            request_id="synthetic-node-request", body={"nonce": "synthetic-nonce"} if body is None else body,
            issued_at=self.now, expires_at=self.now + 60)

    def test_directory_requires_pinned_issuer_and_strict_public_entries(self):
        verified = self.verify(self.directory)
        self.assertEqual(verified["nodes"], [self.entry])
        self.assertNotIn(b"private_key", canonical_bytes(self.directory))
        self.reject("unknown_key", lambda: verify_directory(self.directory,
            PublicKeyTrust([self.second.public_descriptor()]), network_id=self.network, now=self.now))
        tampered = copy.deepcopy(self.directory)
        tampered["payload"]["nodes"][0]["base_url"] = "https://attacker.invalid"
        with self.assertRaises(MemoryError):
            self.verify(tampered)
        self.reject("network_node_directory_binding_mismatch", lambda: verify_directory(
            self.directory, self.trust, network_id="different-network", now=self.now))
        for field, value in (("encryption_key", {}), ("scope", ["receive"]),
                             ("base_url", "http://remote.invalid"), ("base_url", "https://node.invalid/path")):
            with self.subTest(field=field, value=value), self.assertRaises(MemoryError):
                self.issue([{**self.entry, field: value}])
        duplicate = self.node(self.second, "https://second.invalid", self.entry["storage_epoch"])
        self.reject("network_node_directory_duplicate", lambda: self.issue([self.entry, duplicate]))
        self.reject("network_invalid_validity", lambda: self.issue([self.entry], expires_at=self.now + 301))
        self.reject("network_control_expired", lambda: verify_directory(
            self.directory, self.trust, network_id=self.network, now=self.now + 300))

    def test_directory_checkpoints_reject_conflict_rollback_and_replacement(self):
        second = self.issue([{**self.entry, "status": "draining"}], self.directory)
        self.verify(second, previous_directory=self.directory)
        self.assertEqual(self.verify(second, previous_directory=second), second["payload"])
        self.reject("network_node_directory_rollback", lambda: self.verify(self.directory, previous_directory=second))
        self.reject("network_node_directory_rollback", lambda: self.verify(self.directory, minimum_version=2))
        conflicting = self.issue([{**self.entry, "scope": ["node.status"]}])
        self.reject("network_node_directory_version_conflict", lambda: self.verify(conflicting, previous_directory=self.directory))
        broken_chain = self.issue([self.entry], self.directory, previous_sha256="a" * 64)
        self.reject("network_node_directory_chain_mismatch", lambda: self.verify(broken_chain, previous_directory=self.directory))
        for field, value in (("base_url", "https://replacement.invalid"), ("storage_epoch", "different-epoch")):
            changed = self.issue([{**self.entry, field: value}], self.directory)
            self.reject("network_node_identity_changed", lambda: self.verify(changed, previous_directory=self.directory))
        replaced = self.issue([self.node(self.second, self.entry["base_url"], "replacement-epoch")], self.directory)
        self.reject("network_node_tombstone_required", lambda: self.verify(replaced, previous_directory=self.directory))

    def test_revocation_tombstones_and_replacement_do_not_reactivate_old_node(self):
        revoked = {**self.entry, "status": "revoked"}
        second = self.issue([revoked], self.directory)
        self.verify(second, previous_directory=self.directory)
        resurrected = self.issue([self.entry], second)
        self.reject("network_node_reactivation_forbidden", lambda: self.verify(resurrected, previous_directory=second))
        replacement = self.node(self.second, self.entry["base_url"], "synthetic-replacement-epoch")
        third = self.issue([revoked, replacement], second)
        checked = self.verify(third, previous_directory=second)
        self.assertEqual(authorized_node(checked, self.second.key_id, "import"), replacement)
        self.reject("network_node_inactive", lambda: authorized_node(checked, self.first.key_id, "refresh"))
        self.reject("network_node_tombstone_required", lambda: self.verify(self.issue([replacement], third), previous_directory=third))

    def test_node_actions_are_scope_and_storage_identity_bound(self):
        payload = self.verify(self.directory)
        authorized_node(payload, self.first.key_id, "refresh", base_url=self.entry["base_url"], storage_epoch=self.entry["storage_epoch"])
        self.reject("network_node_identity_changed", lambda: authorized_node(payload, self.first.key_id, "export", storage_epoch="wrong-epoch"))
        self.reject("network_node_authorization_required", lambda: authorized_node(payload, self.second.key_id, "refresh"))
        draining = self.verify(self.issue([{**self.entry, "status": "draining"}], self.directory))
        authorized_node(draining, self.first.key_id, "refresh")
        authorized_node(draining, self.first.key_id, "export")
        self.reject("network_node_inactive", lambda: authorized_node(draining, self.first.key_id, "import"))
        limited = self.verify(self.issue([{**self.entry, "scope": ["node.status"]}]))
        self.reject("network_node_scope_denied", lambda: authorized_node(limited, self.first.key_id, "export"))

    def test_node_request_domain_is_not_an_agent_request(self):
        trust = PublicKeyTrust([self.first.public_descriptor()])
        request = self.request()
        self.assertEqual(verify_node_request(request, trust, network_id=self.network, action="refresh", now=self.now)["body"], {"nonce": "synthetic-nonce"})
        self.reject("network_request_binding_mismatch", lambda: verify_request(request, trust, network_id=self.network, now=self.now))
        agent_request = sign_request(self.first, network_id=self.network, action="status", request_id="synthetic-member-request",
            body={"nonce": "synthetic-nonce"}, issued_at=self.now, expires_at=self.now + 60)
        self.reject("network_node_request_binding_mismatch", lambda: verify_node_request(agent_request, trust, network_id=self.network, now=self.now))
        self.reject("network_node_action_rejected", lambda: verify_node_request(request, trust, network_id=self.network, action="import", now=self.now))
        self.reject("network_control_expired", lambda: verify_node_request(request, trust, network_id=self.network, now=self.now + 60))
        self.reject("network_node_action_rejected", lambda: self.request(action="send"))
        raw = canonical_bytes(request)
        duplicated = raw.replace(b'"action":"refresh"', b'"action":"refresh","action":"export"')
        with self.assertRaises(MemoryError):
            verify_node_request(duplicated, trust, network_id=self.network, now=self.now)

    def test_node_status_binds_nonce_and_both_control_documents(self):
        args = {"network_id": self.network, "nonce": "synthetic-nonce", "roster_sha256": "a" * 64,
                "roster_version": 4, "directory_sha256": document_sha256(self.directory), "directory_version": 1}
        status = issue_node_status(self.issuer, **args, issued_at=self.now, expires_at=self.now + 300)
        verify_node_status(status, self.trust, **args, now=self.now)
        for key, wrong in (("nonce", "wrong-nonce"), ("roster_sha256", "b" * 64),
                           ("roster_version", 3), ("directory_sha256", "b" * 64), ("directory_version", 2)):
            with self.subTest(key=key), self.assertRaises(MemoryError):
                verify_node_status(status, self.trust, **{**args, key: wrong}, now=self.now)
        self.reject("network_control_expired", lambda: verify_node_status(status, self.trust, **args, now=self.now + 300))

    def test_authority_node_route_does_not_grant_agent_membership(self):
        from starlette.testclient import TestClient

        trust = TrustStore(self.root / "issuer-trust.json")
        trust.add(self.issuer.public_descriptor())
        roster = issue_roster(self.issuer, network_id=self.network, version=1, previous_sha256="0" * 64,
            members=[{"signing_key": self.member.public_descriptor(), "encryption_key": EncryptionIdentity.generate().public_descriptor(),
                      "status": "active", "scope": ["receive", "send"]}], issued_at=self.now, expires_at=self.now + 300)
        roster_path, directory_path, config_path = [self.root / name for name in ("roster.json", "nodes.json", "authority.json")]
        atomic_write(roster_path, canonical_bytes(roster), replace=False)
        atomic_write(directory_path, canonical_bytes(self.directory), replace=False)
        config = {"schema_version": "memory-vault-network-authority-config/v1", "network_id": self.network,
                  "identity_path": str(self.root / "issuer.json"), "trust_store_path": str(trust.path), "roster_path": str(roster_path)}
        atomic_write(config_path, canonical_bytes(config), replace=False)
        query = {"network_id": self.network, "nonce": "synthetic-nonce", "request": self.request()}
        member_request = sign_request(self.member, network_id=self.network, action="status", request_id="synthetic-member-status",
            body={"nonce": "synthetic-nonce"}, issued_at=self.now, expires_at=self.now + 60)
        with TestClient(create_authority_app(config_path)) as client:
            self.assertEqual(client.post("/v1/node-status", json=query).json()["error"], "network_node_authority_not_configured")
            legacy = client.post("/v1/status", json={**query, "request": member_request})
            self.assertEqual(legacy.status_code, 200, legacy.json())
            self.assertEqual(set(legacy.json()), {"status", "roster"})
            config["node_directory_path"] = str(directory_path)
            atomic_write(config_path, canonical_bytes(config), replace=True)
            answer = client.post("/v1/node-status", json=query)
            self.assertEqual(answer.status_code, 200, answer.json())
            result = answer.json()
            self.assertEqual(set(result), {"status", "roster", "nodes", "node_status"})
            self.assertEqual(result["roster"], roster)
            self.assertEqual(result["nodes"], self.directory)
            verify_status(result["status"], self.trust, network_id=self.network, nonce=query["nonce"],
                roster_sha256=document_sha256(roster), roster_version=1)
            verify_node_status(result["node_status"], self.trust, network_id=self.network, nonce=query["nonce"],
                roster_sha256=document_sha256(roster), roster_version=1,
                directory_sha256=document_sha256(self.directory), directory_version=1)
            member_answer = client.post("/v1/status", json={**query, "request": member_request})
            self.assertEqual(member_answer.status_code, 200, member_answer.json())
            self.assertEqual(set(member_answer.json()), {"status", "roster", "nodes", "node_status"})
            verify_node_status(member_answer.json()["node_status"], self.trust, network_id=self.network, nonce=query["nonce"],
                roster_sha256=document_sha256(roster), roster_version=1,
                directory_sha256=document_sha256(self.directory), directory_version=1)
            self.assertNotEqual(client.post("/v1/status", json=query).status_code, 200)
            self.assertNotEqual(client.post("/v1/node-status", json={**query, "request": member_request}).status_code, 200)
            self.assertNotEqual(client.post("/v1/node-status", json={**query, "request": self.request(self.second)}).status_code, 200)
            self.assertNotEqual(client.post("/v1/node-status", json={**query, "nonce": "different-nonce"}).status_code, 200)
            # An operator-selected expired directory remains inert on its own;
            # a fresh issuer response can explicitly attest it is still current.
            expired = self.issue([self.entry], issued_at=self.now - 301, expires_at=self.now - 1)
            atomic_write(directory_path, canonical_bytes(expired), replace=True)
            refreshed = client.post("/v1/node-status", json=query)
            self.assertEqual(refreshed.status_code, 200, refreshed.json())
            verify_node_status(refreshed.json()["node_status"], self.trust, network_id=self.network, nonce=query["nonce"],
                roster_sha256=document_sha256(roster), roster_version=1,
                directory_sha256=document_sha256(expired), directory_version=1)
            revoked = self.issue([{**self.entry, "status": "revoked"}], self.directory)
            atomic_write(directory_path, canonical_bytes(revoked), replace=True)
            rejected = client.post("/v1/node-status", json=query)
            self.assertEqual(rejected.json()["error"], "network_node_inactive")


if __name__ == "__main__":
    unittest.main()
