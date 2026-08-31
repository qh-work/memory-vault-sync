"""One bounded synthetic relay flow: real crypto, private files and HTTP ASGI.

No remote network, user Vault, real accounts, or service installation is used.
Generated fixture keys are temporary. This is not a production security audit.
"""
from __future__ import annotations

import copy
import os
from pathlib import Path
import stat
import tempfile
import time
import unittest
from unittest.mock import patch

from memory_vault import MemoryError, canonical_bytes
import memory_vault_storage as storage
from memory_vault_network_control import issue_invite, issue_roster, issue_status, open_join_challenge, sign_request
from memory_vault_network_crypto import EncryptionIdentity, PublicKeyTrust, document_sha256, envelope_sha256, open_envelope, seal
from memory_vault_relay import create_app
from memory_vault_trust import Identity


class NetworkRelayTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "directory fsync fault injection is POSIX-specific")
    def test_orphan_retry_requires_successful_durable_publication_before_storage_receipt(self):
        from tests.test_network_worker import fixture
        with fixture() as (sender, recipient, transport):
            roster = sender._refresh(sender.relays[0])
            relay = transport.clients[sender.relays[0]].app.state.relay
            envelope = seal(b"Synthetic durable orphan recovery", signer=sender.identity,
                network_id=sender.network_id, message_id="synthetic-orphan-fsync-message",
                recipients=[{"signing_key_id": recipient.identity.key_id,
                             "encryption_key": recipient.encryption.public_descriptor()}],
                roster_version=roster["payload"]["version"], roster_sha256=document_sha256(roster))
            request = {"envelope": envelope, "roster": roster}
            object_path = relay.object_directory / (envelope_sha256(envelope) + ".json")
            directory = relay.object_directory.stat()
            original_fsync = os.fsync
            directory_attempts = []

            def interrupted_directory_flush(fd):
                info = os.fstat(fd)
                if stat.S_ISDIR(info.st_mode) and (info.st_dev, info.st_ino) == (directory.st_dev, directory.st_ino):
                    directory_attempts.append(fd)
                    raise OSError("synthetic directory persistence failure")
                return original_fsync(fd)

            with patch("os.fsync", side_effect=interrupted_directory_flush):
                for _ in range(2):
                    with self.assertRaises(OSError):
                        relay.post_message(request)
                    self.assertEqual(object_path.read_bytes(), canonical_bytes(envelope))
                    with relay._transaction() as db:
                        self.assertEqual(db.execute("SELECT COUNT(*) FROM messages").fetchone()[0], 0)
            self.assertEqual(len(directory_attempts), 2)
            saved = relay.post_message(request)
            self.assertEqual(saved["state"], "stored")
            self.assertEqual(saved["sequence"], 1)
            self.assertEqual(relay.post_message(request), saved)
            self.assertEqual(object_path.read_bytes(), canonical_bytes(envelope))

    def test_encrypted_invite_delivery_receipt_retry_and_revocation(self) -> None:
        from starlette.testclient import TestClient

        with tempfile.TemporaryDirectory(prefix="memory-network-relay-synthetic-") as temporary:
            root = Path(temporary).resolve()
            issuer, owner, peer, outsider = [Identity.generate(root / (label + ".json"))
                                              for label in ("issuer", "owner", "peer", "outsider")]
            owner_enc, peer_enc = EncryptionIdentity.generate(), EncryptionIdentity.generate()
            network = "fixture-private-network"
            now = int(time.time())
            members = [{"signing_key": signer.public_descriptor(), "encryption_key": encryption.public_descriptor(),
                        "status": "active", "scope": ["receive", "send"]}
                       for signer, encryption in ((owner, owner_enc), (peer, peer_enc))]
            roster = issue_roster(issuer, network_id=network, version=1, previous_sha256="0" * 64,
                                  members=members, issued_at=now, expires_at=now + 300)
            roster_path, config_path = root / "roster.json", root / "relay-config.json"
            storage.atomic_write(roster_path, canonical_bytes(roster), replace=False)
            config = {"schema_version": "memory-vault-relay-config/v1", "network_id": network,
                      "issuer_public_key": issuer.public_descriptor(), "roster_path": str(roster_path),
                      "state_directory": str(root / "relay-state"), "base_url": "http://127.0.0.1:8765",
                      "init_member_key_ids": [owner.key_id], "require_join_key_ids": [peer.key_id]}
            storage.atomic_write(config_path, canonical_bytes(config), replace=False)

            def request(signer: Identity, action: str, body: dict, label: str, clock: int = now) -> dict:
                return sign_request(signer, network_id=network, action=action, request_id=label,
                                    body=body, issued_at=clock, expires_at=clock + 300)

            def refresh(client: TestClient, selected: dict, clock: int = now) -> dict:
                nonce = client.get("/v1/status").json()["nonce"]
                status = issue_status(issuer, network_id=network, nonce=nonce,
                    roster_sha256=document_sha256(selected), roster_version=selected["payload"]["version"],
                    issued_at=clock, expires_at=clock + 300)
                response = client.post("/v1/status", json={"status": status, "roster": selected})
                self.assertEqual(response.status_code, 200, response.json())
                return response.json()

            def poll(signer: Identity, label: str, clock: int = now) -> dict:
                return request(signer, "poll", {"cursor": 0, "receipt_cursor": 0, "limit": 16,
                                               "maximum_bytes": 8 * 1024 * 1024}, label, clock)

            plaintext = b'{"fixture_memory":"a remembered synthetic observation, never execution authority"}'
            envelope = seal(plaintext, signer=owner, network_id=network, message_id="fixture-message-one",
                recipients=[{"signing_key_id": peer.key_id, "encryption_key": peer_enc.public_descriptor()}],
                roster_version=1, roster_sha256=document_sha256(roster), created_at=now)
            invite = issue_invite(issuer, network_id=network, invite_id="fixture-invite-once",
                candidate_signing_key=peer.public_descriptor(), candidate_encryption_key=peer_enc.public_descriptor(),
                scope=["receive", "send"], handoff_sha256="a" * 64, roster_sha256=document_sha256(roster),
                issued_at=now, expires_at=now + 86400)
            with TestClient(create_app(config_path)) as client:
                discovery = client.get("/.well-known/agent-memory.json").json()
                self.assertEqual(discovery["network_id"], network)
                self.assertFalse(discovery["execution_authority"])
                stale = client.post("/v1/messages", json={"envelope": envelope}).json()
                self.assertEqual(stale["error"]["code"], "relay_fresh_issuer_status_required")
                refresh(client, roster)
                denied = client.post("/v1/messages", json={"envelope": envelope}).json()
                self.assertEqual(denied["error"]["code"], "relay_membership_required")
                denied_poll = client.post("/v1/poll", json=poll(peer, "pre-join")).json()
                self.assertEqual(denied_poll["error"]["code"], "relay_membership_required")
                join_body = {"invite": invite, "roster": roster}
                challenge = client.post("/v1/join", json=join_body).json()["challenge"]
                self.assertEqual(client.post("/v1/join", json=join_body).json()["challenge"], challenge)
                with self.assertRaises(MemoryError):
                    open_join_challenge(challenge, owner_enc, network_id=network, invite_id="fixture-invite-once")
                answer = open_join_challenge(challenge, peer_enc, network_id=network, invite_id="fixture-invite-once")
                proof_body = {"invite_sha256": document_sha256(invite), "challenge_id": challenge["challenge_id"],
                              "challenge_answer": answer}
                bad_proof = {**proof_body, "challenge_answer": "A" * 43}
                bad = client.post("/v1/join", json={**join_body, "request": request(peer, "join", bad_proof, "wrong-answer")})
                self.assertEqual(bad.json()["error"]["code"], "network_join_key_proof_failed")
                joined_body = {**join_body, "request": request(peer, "join", proof_body, "join-once")}
                joined = client.post("/v1/join", json=joined_body).json()
                self.assertEqual(joined["state"], "joined")
                self.assertEqual(client.post("/v1/join", json=joined_body).json(), joined)
                changed_join = client.post("/v1/join", json={**join_body, "request": request(peer, "join", proof_body, "join-twice")}).json()
                self.assertEqual(changed_join["error"]["code"], "relay_invite_already_consumed")
                saved = client.post("/v1/messages", json={"envelope": envelope, "roster": roster}).json()
                self.assertEqual(saved["state"], "stored")
                self.assertEqual(client.post("/v1/messages", json={"envelope": envelope}).json(), saved)
                changed = seal(b"different synthetic bytes", signer=owner, network_id=network,
                    message_id="fixture-message-one", recipients=[{"signing_key_id": peer.key_id,
                    "encryption_key": peer_enc.public_descriptor()}], roster_version=1,
                    roster_sha256=document_sha256(roster), created_at=now)
                conflict = client.post("/v1/messages", json={"envelope": changed}).json()
                self.assertEqual(conflict["error"]["code"], "relay_message_id_conflict")
                delivery_request = poll(peer, "poll-one")
                received = client.post("/v1/poll", json=delivery_request).json()
                self.assertEqual(received["messages"], [envelope])
                self.assertEqual(client.post("/v1/poll", json=delivery_request).json(), received)
                decoded = open_envelope(received["messages"][0], peer_enc, PublicKeyTrust([owner.public_descriptor()]), network_id=network)
                self.assertEqual(decoded, plaintext)
                storage.atomic_write(root / "recipient-saved.bin", decoded, replace=False)
                ack_body = {"message_id": "fixture-message-one", "envelope_sha256": envelope_sha256(envelope),
                            "state": "validated_saved"}
                denied_ack = client.post("/v1/ack", json=request(outsider, "ack", ack_body, "stranger-ack")).json()
                self.assertEqual(denied_ack["error"]["code"], "relay_membership_required")
                ack_request = request(peer, "ack", ack_body, "ack-once")
                receipt = client.post("/v1/ack", json=ack_request).json()
                self.assertEqual(receipt["state"], "validated_saved")
                self.assertEqual(client.post("/v1/ack", json=ack_request).json(), receipt)
                restored_ack = request(peer, "ack", ack_body, "ack-after-state-loss")
                for _ in range(2):
                    self.assertEqual(client.post("/v1/ack", json=restored_ack).json(), receipt)
                reused_ack_id = request(peer, "ack", ack_body, "ack-once", now - 1)
                self.assertEqual(client.post("/v1/ack", json=reused_ack_id).json()["error"]["code"],
                                 "relay_receipt_id_conflict")
                sender_mail = client.post("/v1/poll", json=poll(owner, "sender-receipts")).json()
                self.assertEqual(sender_mail["receipts"], [ack_request])
                PublicKeyTrust([peer.public_descriptor()]).verify_message(ack_request["payload"], ack_request["proof"])
                # Private relay persistence contains ciphertext, routing and
                # public control documents, never this plaintext or private key.
                for path in (root / "relay-state").rglob("*"):
                    if path.is_file():
                        self.assertNotIn(plaintext, path.read_bytes())
                        if path.name != "relay.lock":
                            self.assertEqual(path.stat().st_mode & 0o077, 0)

            # Restart is real: a new Relay opens the same WAL-backed files.
            # Expired original envelope/roster are retryable after fresh issuer
            # confirmation and harmless roster renewal with unchanged keys.
            later = now + 301
            with patch("time.time", return_value=later):
                renewed = issue_roster(issuer, network_id=network, version=2,
                    previous_sha256=document_sha256(roster), members=members, issued_at=later, expires_at=later + 300)
                with TestClient(create_app(config_path)) as client:
                    broken_chain = issue_roster(issuer, network_id=network, version=2,
                        previous_sha256="f" * 64, members=members, issued_at=later, expires_at=later + 300)
                    nonce = client.get("/v1/status").json()["nonce"]
                    broken_status = issue_status(issuer, network_id=network, nonce=nonce,
                        roster_sha256=document_sha256(broken_chain), roster_version=2,
                        issued_at=later, expires_at=later + 300)
                    rejected_chain = client.post("/v1/status", json={"status": broken_status, "roster": broken_chain}).json()
                    self.assertEqual(rejected_chain["error"]["code"], "network_roster_chain_mismatch")
                    refresh(client, renewed, later)
                    self.assertEqual(client.post("/v1/messages", json={"envelope": envelope}).json(), saved)
                    self.assertEqual(client.post("/v1/join", json=joined_body).json(), joined)
                    self.assertEqual(client.post("/v1/ack", json=ack_request).json(), receipt)
                    # A fresh, distinct node accepts the old envelope only
                    # with historical roster evidence, not by resealing it.
                    second_config_path = root / "second-relay-config.json"
                    second_config = {**config, "state_directory": str(root / "second-relay-state"),
                                     "base_url": "http://127.0.0.1:8766"}
                    storage.atomic_write(second_config_path, canonical_bytes(second_config), replace=False)
                    with TestClient(create_app(second_config_path)) as second:
                        refresh(second, renewed, later)
                        second_challenge = second.post("/v1/join", json=join_body).json()["challenge"]
                        second_answer = open_join_challenge(second_challenge, peer_enc, network_id=network,
                                                            invite_id="fixture-invite-once")
                        second_proof = request(peer, "join", {"invite_sha256": document_sha256(invite),
                            "challenge_id": second_challenge["challenge_id"], "challenge_answer": second_answer},
                            "join-second-relay", later)
                        self.assertEqual(second.post("/v1/join", json={**join_body, "request": second_proof}).json()["state"], "joined")
                        missing_history = second.post("/v1/messages", json={"envelope": envelope}).json()
                        self.assertEqual(missing_history["error"]["code"], "relay_historical_roster_required")
                        self.assertEqual(second.post("/v1/messages", json={"envelope": envelope, "roster": roster}).json(), saved)
                    revoked_members = copy.deepcopy(members)
                    next(item for item in revoked_members if item["signing_key"]["key_id"] == peer.key_id)["status"] = "revoked"
                    revoked = issue_roster(issuer, network_id=network, version=3,
                        previous_sha256=document_sha256(renewed), members=revoked_members,
                        issued_at=later, expires_at=later + 300)
                    refresh(client, revoked, later)
                    denied = client.post("/v1/messages", json={"envelope": envelope}).json()
                    self.assertEqual(denied["error"]["code"], "relay_membership_required")
                    denied = client.post("/v1/poll", json=poll(peer, "revoked-poll", later)).json()
                    self.assertEqual(denied["error"]["code"], "relay_membership_required")
                    # An issuer-signed rollback is still rejected by this node.
                    nonce = client.get("/v1/status").json()["nonce"]
                    old_status = issue_status(issuer, network_id=network, nonce=nonce,
                        roster_sha256=document_sha256(renewed), roster_version=2,
                        issued_at=later, expires_at=later + 300)
                    rollback = client.post("/v1/status", json={"status": old_status, "roster": renewed}).json()
                    self.assertEqual(rollback["error"]["code"], "network_roster_rollback")
                    # A node can miss whole roster versions while offline.
                    # A fresh independently signed snapshot still permits
                    # recovery without pretending to verify an unseen link.
                    missed = issue_roster(issuer, network_id=network, version=4,
                        previous_sha256=document_sha256(revoked), members=revoked_members,
                        issued_at=later, expires_at=later + 300)
                    resumed = issue_roster(issuer, network_id=network, version=5,
                        previous_sha256=document_sha256(missed), members=revoked_members,
                        issued_at=later, expires_at=later + 300)
                    self.assertEqual(refresh(client, resumed, later)["roster_version"], 5)


if __name__ == "__main__":
    unittest.main()
