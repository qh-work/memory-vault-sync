"""One synthetic user-level setup/invitation check; no sockets or real data."""
from __future__ import annotations

from pathlib import Path
import hashlib
import os
import sqlite3
import sys
import tempfile
import time
import unittest
from unittest import mock

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from memory_vault import MemoryError, canonical_bytes
from memory_vault_network import NetworkClient, HTTPTransport
from memory_vault_network_admin import backup_keys, restore_keys, create_identity, initialize, configure_network, invite_candidate, _read
from memory_vault_network_crypto import EncryptionIdentity, PublicKeyTrust, document_sha256
from memory_vault_network_control import create_authority_app, import_recovery, issue_roster, verify_invite, verify_roster, verify_status
from memory_vault_relay import Relay


class NetworkAdminTests(unittest.TestCase):
    def test_keys_backup_restore_is_inactive_and_does_not_touch_vault(self) -> None:
        from memory_vault_trust import Identity, _write_new_private
        with tempfile.TemporaryDirectory(prefix="network-recovery-synthetic-") as temporary, mock.patch.object(
                HTTPTransport, "request", side_effect=AssertionError("key recovery must not access a network")):
            root = Path(temporary).resolve()
            owner = root / "owner"
            initialize(owner, network_id="synthetic-recovery-network")
            client = NetworkClient(owner / "network.json")
            roster = _read(owner / "roster.json")
            # A known local checkpoint is backed up, but delivery cursors and
            # unsent message bodies must never be restored as completed work.
            with client.db() as connection:
                connection.execute("INSERT INTO state VALUES('roster',?)", (canonical_bytes(roster).decode(),))
                connection.execute("INSERT INTO state VALUES(?,?)", ("cursor:http://127.0.0.1:8765", '{"cursor":123,"receipt_cursor":45}'))
                connection.execute("INSERT INTO outbox(request_id,message_id,input_sha,body) VALUES(?,?,?,?)",
                                   ("synthetic-unsent", "synthetic-unsent-message", "a" * 64, b"SYNTHETIC-OFFLINE-OUTBOX-NOT-IN-RECOVERY"))
            package, secret = root / "keys.encrypted.json", root / "offline-secret.json"
            saved = backup_keys(network_config=owner / "network.json", output=package, secret_file=secret)
            self.assertTrue(saved["offline_unsent_messages_not_backed_up"])
            self.assertFalse(saved["issuer_key_shared_with_endpoint"])
            authority = _read(owner / "authority.json", private=True)
            issuer_private = _read(authority["identity_path"], private=True)
            recovered_payload = import_recovery(_read(package, private=True),
                recovery_secret=_read(secret, private=True)["secret"], network_id=client.network_id)["payload"]
            # Inspect the decrypted synthetic package: ciphertext absence alone
            # would not prove that endpoint backup excludes issuer authority.
            self.assertNotIn(issuer_private["private_key"].encode(), canonical_bytes(recovered_payload))
            self.assertNotIn(authority["identity_path"].encode(), canonical_bytes(recovered_payload))
            self.assertEqual(recovered_payload["signing_identity"]["key_id"], client.identity.key_id)
            cipher = package.read_bytes()
            self.assertNotIn(_read(secret, private=True)["secret"].encode(), cipher)
            self.assertNotIn(_read(owner / "identity.json", private=True)["private_key"].encode(), cipher)
            self.assertNotIn(_read(owner / "encryption.json", private=True)["private_key"].encode(), cipher)
            self.assertNotIn(str(owner).encode(), cipher)
            self.assertNotIn(b"SYNTHETIC-OFFLINE-OUTBOX-NOT-IN-RECOVERY", cipher)
            if os.name == "posix":
                self.assertEqual(package.stat().st_mode & 0o777, 0o600)
                self.assertEqual(secret.stat().st_mode & 0o777, 0o600)
            vault = root / "already-restored.sqlite3"
            _write_new_private(vault, b"")
            with sqlite3.connect(vault) as connection:
                connection.execute("CREATE TABLE preserved(value TEXT)")
                connection.execute("INSERT INTO preserved VALUES('synthetic-existing-vault')")
            before = hashlib.sha256(vault.read_bytes()).hexdigest()
            wrong = Identity.generate(root / "wrong-issuer-private.json")
            _write_new_private(root / "wrong-issuer-public.json", canonical_bytes(wrong.public_descriptor()))
            with self.assertRaises(MemoryError) as rejected:
                restore_keys(package=package, secret_file=secret, directory=root / "rejected", vault=vault,
                             confirm_network_id="synthetic-recovery-network", issuer_public=root / "wrong-issuer-public.json",
                             authority_url="http://127.0.0.1:9767", relays=["http://127.0.0.1:9765"])
            self.assertEqual(rejected.exception.code, "network_recovery_issuer_mismatch")
            self.assertFalse((root / "rejected").exists())
            destination = root / "restored-keys"
            result = restore_keys(package=package, secret_file=secret, directory=destination, vault=vault,
                                  confirm_network_id="synthetic-recovery-network", issuer_public=owner / "issuer-public.json",
                                  authority_url="http://127.0.0.1:9767", relays=["http://127.0.0.1:9765"])
            self.assertTrue(result["activation_disabled"])
            self.assertTrue(result["requires_fresh_issuer_status"])
            self.assertFalse(result["vault_changed"])
            self.assertEqual(hashlib.sha256(vault.read_bytes()).hexdigest(), before)
            self.assertFalse((destination / "network-state").exists())
            recovered = NetworkClient(destination / "network.json")
            self.assertEqual(recovered.identity.key_id, client.identity.key_id)
            self.assertNotEqual(recovered.identity.key_id, issuer_private["key_id"])
            self.assertFalse((destination / "authority-identity.json").exists())
            self.assertFalse((destination / "authority-trust.json").exists())
            self.assertEqual(recovered.encryption.public_descriptor(), client.encryption.public_descriptor())
            self.assertEqual(recovered.authority_url, "http://127.0.0.1:9767")
            self.assertEqual(recovered.client_config.vault_path, vault)
            marker = _read(destination / "recovery-state.json", private=True)
            self.assertEqual(marker["minimum_roster_version"], 1)
            self.assertEqual(marker["last_roster_sha256"], document_sha256(roster))
            self.assertFalse(marker["old_delivery_cursors_restored"])
            self.assertFalse(marker["offline_outbox_restored"])

    def test_initialized_endpoint_cannot_issue_network_control(self) -> None:
        from starlette.testclient import TestClient
        with tempfile.TemporaryDirectory(prefix="network-authority-synthetic-") as temporary:
            owner = Path(temporary).resolve() / "owner"
            result = initialize(owner, network_id="synthetic-separated-authority")
            endpoint = NetworkClient(owner / "network.json")
            issuer = _read(owner / "issuer-public.json")
            issuers = PublicKeyTrust([issuer])
            previous = _read(owner / "roster.json")
            self.assertFalse(result["issuer_key_shared_with_endpoint"])
            self.assertNotEqual(endpoint.identity.key_id, issuer["key_id"])
            self.assertEqual(result["owner_key_id"], endpoint.identity.key_id)
            self.assertEqual(result["issuer_key_id"], issuer["key_id"])
            self.assertEqual(_read(owner / "relay.json")["init_member_key_ids"], [endpoint.identity.key_id])
            now = int(time.time())
            forged = issue_roster(endpoint.identity, network_id=endpoint.network_id, version=2,
                previous_sha256=document_sha256(previous), members=previous["payload"]["members"],
                issued_at=now, expires_at=now + 300)
            with self.assertRaises(MemoryError) as rejected:
                verify_roster(forged, issuers, network_id=endpoint.network_id)
            self.assertEqual(rejected.exception.code, "unknown_key")
            # The separately held issuer still serves fresh status for the
            # ordinary member. In-process ASGI makes no listening socket.
            nonce = "synthetic-separated-authority-nonce"
            with TestClient(create_authority_app(owner / "authority.json")) as authority:
                response = authority.post("/v1/status", json={"network_id": endpoint.network_id, "nonce": nonce,
                    "request": endpoint._request("status", {"nonce": nonce})})
            self.assertEqual(response.status_code, 200)
            verify_status(response.json()["status"], issuers, network_id=endpoint.network_id, nonce=nonce,
                          roster_sha256=document_sha256(previous), roster_version=1)

    def test_explicit_shared_issuer_configuration_is_readable_and_warns(self) -> None:
        with tempfile.TemporaryDirectory(prefix="network-legacy-authority-synthetic-") as temporary:
            root = Path(temporary).resolve()
            owner = root / "explicit-owner"
            create_identity(owner)
            configured = configure_network(client_config=owner / "client.json", encryption_key=owner / "encryption.json",
                issuer_public=owner / "issuer-public.json", network_id="synthetic-explicit-shared-key",
                authority_url="http://127.0.0.1:8767", relays=["http://127.0.0.1:8765"], output=owner / "network.json")
            self.assertTrue(configured["issuer_key_shared_with_endpoint"])
            client = NetworkClient(owner / "network.json")
            self.assertEqual(client.identity.key_id, _read(owner / "issuer-public.json")["key_id"])
            saved = backup_keys(network_config=owner / "network.json", output=root / "keys.json", secret_file=root / "secret.json")
            self.assertTrue(saved["issuer_key_shared_with_endpoint"])
            self.assertIn("contains issuer authority", saved["warning"])

    def test_new_only_identity_init_invite_and_configure(self) -> None:
        with tempfile.TemporaryDirectory(prefix="network-admin-synthetic-") as temporary, mock.patch.object(
                HTTPTransport, "request", side_effect=AssertionError("setup must not access a network")):
            root = Path(temporary).resolve()
            owner, candidate = root / "owner", root / "candidate"
            result = initialize(owner, network_id="synthetic-network")
            self.assertFalse(result["network_accessed"])
            self.assertFalse(result["services_started"])
            self.assertFalse((owner / "vault").exists())
            original_key = (owner / "identity.json").read_bytes()
            with self.assertRaises(MemoryError):
                initialize(owner, network_id="must-not-replace")
            self.assertEqual((owner / "identity.json").read_bytes(), original_key)
            generated = create_identity(candidate)
            self.assertFalse(generated["capture_visible_turns"])
            self.assertNotIn(b"private_key", (candidate / "member-public.json").read_bytes())
            public = _read(candidate / "member-public.json")
            encryption = EncryptionIdentity.load(candidate / "encryption.json")
            self.assertEqual(public["encryption_key"], encryption.public_descriptor())
            before = _read(owner / "roster.json")
            invitation_path = root / "invitation.json"
            invited = invite_candidate(authority_config=owner / "authority.json", candidate=candidate / "member-public.json", output=invitation_path)
            self.assertEqual(invited["roster_version"], 2)
            self.assertFalse(invited["candidate_private_key_received"])
            invitation = _read(invitation_path)
            issuers = PublicKeyTrust([_read(owner / "issuer-public.json")])
            invite = verify_invite(invitation["invite"], issuers, network_id="synthetic-network")
            roster = verify_roster(invitation["roster"], issuers, network_id="synthetic-network", minimum_version=2,
                                   expected_previous_sha256=document_sha256(before))
            self.assertEqual(invite["roster_sha256"], document_sha256(invitation["roster"]))
            self.assertEqual(len(roster["members"]), 2)
            self.assertNotIn(b"private_key", canonical_bytes(invitation))
            with self.assertRaises(MemoryError):
                invite_candidate(authority_config=owner / "authority.json", candidate=candidate / "member-public.json", output=root / "duplicate.json")
            configured = configure_network(client_config=candidate / "client.json", encryption_key=candidate / "encryption.json",
                                            issuer_public=owner / "issuer-public.json", network_id="synthetic-network",
                                            authority_url="http://127.0.0.1:8767", relays=["http://127.0.0.1:8765"], output=candidate / "network.json")
            self.assertFalse(configured["keys_enrolled"])
            client = NetworkClient(candidate / "network.json")
            self.assertEqual(client.identity.key_id, public["signing_key"]["key_id"])
            self.assertFalse((candidate / "vault").exists())
            self.assertFalse((candidate / "network-state").exists())
            # Constructing a local relay does not bind a socket. Candidate is
            # in the signed roster but is not in its data-access bootstrap list.
            relay = Relay(owner / "relay.json")
            self.assertNotIn(client.identity.key_id, relay.initial)
            self.assertNotIn("identity_path", _read(owner / "relay.json"))
            self.assertNotIn("encryption_key_path", _read(owner / "relay.json"))


if __name__ == "__main__":
    unittest.main()
