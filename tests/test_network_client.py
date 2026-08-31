"""One small complete network journey; synthetic identities, two actual ASGI nodes.

This validates reference endpoints, not real AI model adoption or public cloud.
"""
from contextlib import ExitStack, closing
import copy
import hashlib
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from memory_vault import MemoryError, canonical_bytes, strict_json_loads
from memory_vault_agent import Agent
from memory_vault_client import ClientConfig, CONFIG_SCHEMA
from memory_vault_network import NetworkClient, HTTPTransport
from memory_vault_network_control import create_authority_app, issue_roster, issue_invite, sign_request
from memory_vault_network_crypto import EncryptionIdentity, document_sha256, seal
from memory_vault_relay import create_app
from memory_vault_storage import atomic_write
from memory_vault_trust import Identity, TrustStore


class Transport:
    def __init__(self, clients):
        self.clients = clients
        self.offline = set()
        self.drop_after_store = None
        self.drop_before_join = None
        self.drop_before_ack = None
        self.response_hook = None

    def request(self, base, method, path, value=None):
        if base in self.offline:
            raise MemoryError("network_unavailable", retryable=True)
        if self.drop_before_join == base and path == "/v1/join" and "request" in (value or {}):
            self.drop_before_join = None
            raise MemoryError("network_unavailable", retryable=True)
        if self.drop_before_ack == base and path == "/v1/ack":
            self.drop_before_ack = None
            raise MemoryError("network_unavailable", retryable=True)
        response = self.clients[base].request(method, path, content=None if value is None else canonical_bytes(value), headers={"content-type": "application/json"})
        result = response.json()
        if response.status_code != 200:
            error = result.get("error", {})
            raise MemoryError(error if isinstance(error, str) else error.get("code", "network_unavailable"))
        if self.drop_after_store == base and path == "/v1/messages":
            self.drop_after_store = None
            raise MemoryError("network_unavailable", retryable=True)
        if self.response_hook is not None:
            return self.response_hook(base, path, value, result)
        return result


class NetworkClientTests(unittest.TestCase):
    def test_join_handoff_offline_retry_two_nodes_and_receipts(self):
        from starlette.testclient import TestClient
        with tempfile.TemporaryDirectory(prefix="memory-network-client-synthetic-") as temporary, ExitStack() as stack:
            root = Path(temporary).resolve()
            issuer = Identity.generate(root / "issuer.json")
            trust = TrustStore(root / "issuer-trust.json")
            trust.add(issuer.public_descriptor())
            identities, encryption, configs = [], [], []
            for name in ("first", "second"):
                member_root = root / name
                identity = Identity.generate(member_root / "identity.json")
                key = EncryptionIdentity.generate()
                key.save(member_root / "encryption.json")
                identities.append(identity)
                encryption.append(key)
                config = member_root / "client.json"
                atomic_write(config, canonical_bytes({"schema_version": CONFIG_SCHEMA, "vault_path": str(member_root / "memory.sqlite3"),
                    "capture_visible_turns": False, "identity_path": str(member_root / "identity.json"), "trust_path": str(member_root / "trust.json")}), replace=False)
                configs.append(config)
            for config in configs:
                record_trust = TrustStore(config.parent / "trust.json")
                # Explicit independent fixture policy, not automatic enrollment
                # by an incoming message or invitation.
                for identity in identities:
                    record_trust.add(identity.public_descriptor())
            now = int(time.time())
            clock = [now]
            stack.enter_context(patch("time.time", side_effect=lambda: clock[0]))
            members = [{"signing_key": identity.public_descriptor(), "encryption_key": key.public_descriptor(), "status": "active", "scope": ["receive", "send"]}
                       for identity, key in zip(identities, encryption)]
            network = "synthetic-network"
            roster = issue_roster(issuer, network_id=network, version=1, previous_sha256="0" * 64, members=members, issued_at=now, expires_at=now + 300)
            roster_path = root / "roster.json"
            atomic_write(roster_path, canonical_bytes(roster), replace=False)
            authority = root / "authority.json"
            atomic_write(authority, canonical_bytes({"schema_version": "memory-vault-network-authority-config/v1", "network_id": network,
                "identity_path": str(root / "issuer.json"), "trust_store_path": str(root / "issuer-trust.json"), "roster_path": str(roster_path)}), replace=False)
            authority_url, relays = "http://127.0.0.1:8767", ["http://127.0.0.1:8765", "http://127.0.0.1:8768"]
            clients = {authority_url: stack.enter_context(TestClient(create_authority_app(authority)))}
            for index, relay_url in enumerate(relays):
                relay_config = root / ("relay-" + str(index) + ".json")
                atomic_write(relay_config, canonical_bytes({"schema_version": "memory-vault-relay-config/v1", "network_id": network,
                    "issuer_public_key": issuer.public_descriptor(), "roster_path": str(roster_path), "state_directory": str(root / ("node-" + str(index))),
                    "base_url": relay_url, "init_member_key_ids": [identities[0].key_id]}), replace=False)
                clients[relay_url] = stack.enter_context(TestClient(create_app(relay_config)))
            transport = Transport(clients)
            network_configs = []
            for config in configs:
                path = config.parent / "network.json"
                atomic_write(path, canonical_bytes({"schema_version": "memory-vault-network-client/v1", "network_id": network,
                    "client_config_path": str(config), "state_directory": str(config.parent / "network-state"), "encryption_key_path": str(config.parent / "encryption.json"),
                    "issuer_public_key": issuer.public_descriptor(), "relays": relays, "authority_url": authority_url}), replace=False)
                network_configs.append(path)
            first, second = [Agent(config, net, transport=transport) for config, net in zip(configs, network_configs)]
            invite = issue_invite(issuer, network_id=network, invite_id="synthetic-invite", candidate_signing_key=identities[1].public_descriptor(),
                candidate_encryption_key=encryption[1].public_descriptor(), scope=["receive", "send"], handoff_sha256=hashlib.sha256(b"").hexdigest(),
                roster_sha256=document_sha256(roster), issued_at=now, expires_at=now + 3600)
            transport.drop_before_join = relays[0]
            joined = second.handle({"op": "connect", "invitation": {"invite": invite, "roster": roster}, "request_id": "req_synthetic_join"})
            self.assertTrue(joined["ok"], joined)
            self.assertEqual(joined["result"]["joined_nodes"], 1, joined)
            # A persisted proof that never reached the node can expire. First
            # retry its exact bytes, then renew only after explicit rejection.
            clock[0] += 61
            self.assertEqual(second.handle({"op": "connect", "invitation": {"invite": invite, "roster": roster}, "request_id": "req_synthetic_join"})["result"]["joined_nodes"], 2)
            observed = ClientConfig.load(configs[0]).vault(writing=True).handle({"op": "observe", "request_id": "req_synthetic_source", "user": "Preserve memory beyond the session", "assistant": "Keep the selected evidence."})
            goal = first.handle({"op": "remember", "request_id": "req_synthetic_goal", "kind": "continuity", "text": "Synthetic handoff: continue reviewing private memory transport.",
                                 "relations": [{"type": "derived_from", "target": observed["result"]["memory_id"]}]})
            self.assertTrue(goal["ok"], goal)
            memory_id = goal["result"]["memory_id"]
            original = ClientConfig.load(configs[0]).vault().handle({"op": "get", "memory_id": memory_id})["result"]["record"]
            send = {"op": "send", "request_id": "req_synthetic_delivery", "recipients": [identities[1].key_id], "text": "Synthetic agent-to-agent handoff", "memory_ids": [memory_id]}
            transport.offline.add(relays[1])
            transport.drop_after_store = relays[0]
            pending = first.handle(send)
            self.assertEqual(pending["result"]["state"], "queued_local", pending)
            network_client = NetworkClient(network_configs[0], transport=transport)
            with network_client.db() as db:
                frozen = bytes(db.execute("SELECT envelope FROM outbox").fetchone()[0])
            transport.offline.clear()
            saved = first.handle(send)
            self.assertEqual(saved["result"]["stored_nodes"], 2, saved)
            self.assertFalse(saved["result"]["endpoint_validated"])
            with network_client.db() as db:
                self.assertEqual(bytes(db.execute("SELECT envelope FROM outbox").fetchone()[0]), frozen)
            # Receive from the second replica while the first node is offline.
            transport.offline.add(relays[0])
            transport.drop_before_ack = relays[1]
            received = second.handle({"op": "receive"})
            self.assertTrue(received["ok"], received)
            self.assertEqual(len(received["result"]["messages"]), 1, received)
            self.assertEqual(received["result"]["messages"][0]["share"]["admission"], "verified", received)
            self.assertFalse(received["authority"]["execution_eligible"])
            self.assertTrue(received["result"]["errors"])
            clock[0] += 61
            # The message is already locally durable; an unsent expired ack
            # renews without importing a duplicate canonical memory record.
            retried_receive = second.handle({"op": "receive"})
            self.assertFalse([error for error in retried_receive["result"]["errors"] if error["node"] == 1], retried_receive)
            restored = ClientConfig.load(configs[1]).vault().handle({"op": "get", "memory_id": memory_id})["result"]["record"]
            self.assertEqual(canonical_bytes(restored), canonical_bytes(original))
            recall = second.handle({"op": "recall", "query": "handoff memory", "handoff": True})
            self.assertTrue(recall["result"]["hits"], recall)
            first.handle({"op": "receive"})
            self.assertTrue(first.handle(send)["result"]["endpoint_validated"])
            transport.offline.clear()
            second.handle({"op": "receive"})
            self.assertFalse(first.handle({**send, "text": "changed under same request"})["ok"])
            for node in (root / "node-0", root / "node-1"):
                for stored in node.rglob("*"):
                    if stored.is_file():
                        self.assertNotIn(b"Synthetic agent-to-agent handoff", stored.read_bytes())

            # Endpoint validation does not delegate authorization to a relay.
            receiving = NetworkClient(network_configs[1], transport=transport)
            encrypted = strict_json_loads(frozen)
            for denied_key, denied_scope in ((identities[0].key_id, "send"), (identities[1].key_id, "receive")):
                scoped = copy.deepcopy(members)
                selected = next(member for member in scoped if member["signing_key"]["key_id"] == denied_key)
                selected["scope"].remove(denied_scope)
                restricted = issue_roster(issuer, network_id=network, version=2, previous_sha256=document_sha256(roster),
                    members=scoped, issued_at=clock[0], expires_at=clock[0] + 300)
                with self.assertRaises(MemoryError) as denied:
                    receiving._accept(encrypted, restricted)
                self.assertEqual(denied.exception.code, "network_receive_scope_denied")
            switched = seal(canonical_bytes({"schema_version": "memory-vault-network-content/v1", "text": "fixture", "share": None}),
                signer=identities[0], network_id=network, message_id="fixture-switched-recipient",
                recipients=[{"signing_key_id": identities[1].key_id, "encryption_key": encryption[0].public_descriptor()}],
                roster_version=1, roster_sha256=document_sha256(roster), created_at=clock[0])
            with self.assertRaises(MemoryError) as swapped:
                receiving._accept(switched, roster)
            self.assertEqual(swapped.exception.code, "network_encryption_recipient_changed")
            third_key = EncryptionIdentity.generate()
            multirecipient = seal(canonical_bytes({"schema_version": "memory-vault-network-content/v1", "text": "fixture", "share": None}),
                signer=identities[0], network_id=network, message_id="fixture-multiple-recipients",
                recipients=[{"signing_key_id": identities[1].key_id, "encryption_key": encryption[1].public_descriptor()},
                            {"signing_key_id": identities[0].key_id, "encryption_key": third_key.public_descriptor()}],
                roster_version=1, roster_sha256=document_sha256(roster), created_at=clock[0])
            with self.assertRaises(MemoryError) as swapped_other:
                receiving._accept(multirecipient, roster)
            self.assertEqual(swapped_other.exception.code, "network_encryption_recipient_changed")

            self.assertEqual(first.handle({**send, "request_id": "req_synthetic_ack_binding"})["result"]["stored_nodes"], 2)
            with receiving.db() as db:
                before_ack = {row["key"]: row["value"] for row in db.execute("SELECT key,value FROM state WHERE key LIKE 'cursor:%'")}
            transport.response_hook = lambda base, path, value, result: {**result, "message_id": "wrong-fixture-message"} if path == "/v1/ack" else result
            wrong_ack = second.handle({"op": "receive"})
            self.assertTrue(wrong_ack["result"]["errors"])
            self.assertTrue(all(error["code"] == "network_invalid_ack_receipt" for error in wrong_ack["result"]["errors"]))
            transport.response_hook = None
            with receiving.db() as db:
                after_ack = {row["key"]: row["value"] for row in db.execute("SELECT key,value FROM state WHERE key LIKE 'cursor:%'")}
            self.assertEqual(before_ack, after_ack)
            self.assertFalse(second.handle({"op": "receive"})["result"]["errors"])

            # Malicious/malformed cursor hints cannot poison durable local
            # progress with an out-of-range integer, even on an empty page.
            with receiving.db() as db:
                before = {row["key"]: row["value"] for row in db.execute("SELECT key,value FROM state WHERE key LIKE 'cursor:%'")}
            transport.response_hook = lambda base, path, value, result: {**result, "cursor": 2 ** 60} if path == "/v1/poll" else result
            rejected = second.handle({"op": "receive"})
            self.assertTrue(rejected["result"]["errors"])
            transport.response_hook = None
            with receiving.db() as db:
                after = {row["key"]: row["value"] for row in db.execute("SELECT key,value FROM state WHERE key LIKE 'cursor:%'")}
            self.assertEqual(before, after)

            # Recovery keeps the same identities and canonical Vault, but has
            # no old delivery cursors, signed acknowledgements or outbox.
            # Replaying that history must not wedge either endpoint's inbox.
            def restored_client(index, label):
                restored_config = copy.deepcopy(strict_json_loads(network_configs[index].read_bytes()))
                restored_config["state_directory"] = str(root / label)
                restored_path = root / (label + ".json")
                atomic_write(restored_path, canonical_bytes(restored_config), replace=False)
                return NetworkClient(restored_path, transport=transport)

            restored_sender = restored_client(0, "restored-sender-state")
            restored_recipient = restored_client(1, "restored-recipient-state")
            for restored_client_instance, index in ((restored_sender, 0), (restored_recipient, 1)):
                self.assertEqual(restored_client_instance.identity.key_id, identities[index].key_id)
                self.assertEqual(restored_client_instance.client_config.path, configs[index])
            replay = restored_recipient.receive()
            self.assertFalse(replay["errors"], replay)
            self.assertEqual(len(replay["messages"]), 2)
            for _ in range(2):
                repeated = restored_recipient.receive()
                self.assertFalse(repeated["errors"], repeated)
                self.assertEqual(repeated["messages"], [])

            # Unknown receipts still require full peer verification and a
            # valid saved-state claim before they can advance the cursor.
            def invalid_old_receipt(base, path, value, result):
                if path != "/v1/poll" or not result["receipts"]:
                    return result
                invalid_body = {**result["receipts"][0]["payload"]["body"], "state": "not_validated"}
                invalid = sign_request(identities[1], network_id=network, action="ack",
                    request_id="req_synthetic_invalid_old_receipt", body=invalid_body,
                    issued_at=clock[0], expires_at=clock[0] + 60)
                return {**result, "receipts": [invalid, *result["receipts"][1:]]}

            transport.response_hook = invalid_old_receipt
            invalid_replay = restored_sender.receive()
            self.assertEqual([error["code"] for error in invalid_replay["errors"]],
                             ["network_receipt_binding_mismatch"] * 2)
            with restored_sender.db() as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM state WHERE key LIKE 'cursor:%'").fetchone()[0], 0)
                self.assertEqual(db.execute("SELECT COUNT(*) FROM acknowledgements").fetchone()[0], 0)
            transport.response_hook = None
            old_receipts = restored_sender.receive()
            self.assertFalse(old_receipts["errors"], old_receipts)
            self.assertEqual(old_receipts["unmatched_receipts"], 4)
            for _ in range(2):
                repeated = restored_sender.receive()
                self.assertFalse(repeated["errors"], repeated)
                self.assertEqual(repeated["unmatched_receipts"], 0)
            with restored_sender.db() as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM acknowledgements").fetchone()[0], 0)
                self.assertEqual(db.execute("SELECT COUNT(*) FROM outbox").fetchone()[0], 0)

            continued_args = {"request_id": "req_synthetic_after_restore", "recipients": [identities[1].key_id],
                              "text": "Synthetic communication continues after endpoint recovery."}
            continued = restored_sender.send(**continued_args)
            self.assertEqual(continued["stored_nodes"], 2, continued)
            self.assertFalse(continued["endpoint_validated"])
            new_delivery = restored_recipient.receive()
            self.assertFalse(new_delivery["errors"], new_delivery)
            self.assertEqual([message["message_id"] for message in new_delivery["messages"]], [continued["message_id"]])
            new_receipts = restored_sender.receive()
            self.assertFalse(new_receipts["errors"], new_receipts)
            self.assertEqual(new_receipts["unmatched_receipts"], 0)
            self.assertTrue(restored_sender.send(**continued_args)["endpoint_validated"])
            with restored_sender.db() as db:
                self.assertEqual([row[0] for row in db.execute("SELECT message_id FROM acknowledgements")], [continued["message_id"]])
            self._assert_invalid_content_is_quarantined(restored_sender, restored_recipient)

            # Restore anchors are authenticated evidence, not activation. A
            # fresh status signed for an older roster is still rejected.
            anchored = issue_roster(issuer, network_id=network, version=2, previous_sha256=document_sha256(roster),
                members=members, issued_at=clock[0], expires_at=clock[0] + 300)
            marker_path = network_configs[1].parent / "recovery-state.json"
            marker = {"schema_version": "memory-vault-network-restored-state/v1", "network_id": network,
                "activation_disabled": True, "requires_fresh_issuer_status": True, "minimum_roster_version": 2,
                "last_verified_roster": anchored, "last_roster_sha256": document_sha256(anchored),
                "old_delivery_cursors_restored": False, "offline_outbox_restored": False, "vault_restored_by_this_command": False}
            atomic_write(marker_path, canonical_bytes(marker), replace=False)
            with self.assertRaises(MemoryError) as recovery:
                receiving._status("fixture-recovery-nonce")
            self.assertEqual(recovery.exception.code, "network_recovery_roster_rollback")

            # Public configuration changes cannot silently reuse another
            # endpoint/network's private delivery database.
            mismatched = copy.deepcopy(strict_json_loads(network_configs[0].read_bytes()))
            mismatched["network_id"] = "different-fixture-network"
            mismatch_path = network_configs[0].parent / "mismatch-network.json"
            atomic_write(mismatch_path, canonical_bytes(mismatched), replace=False)
            with self.assertRaises(MemoryError) as mismatch:
                with NetworkClient(mismatch_path, transport=transport).db():
                    pass
            self.assertEqual(mismatch.exception.code, "network_state_configuration_mismatch")

            # Exercise the real HTTP adapter's retry classification without a
            # socket. No untrusted error text is promoted into a response code.
            import httpx
            native_client = httpx.Client
            mock_wire = httpx.MockTransport(lambda req: httpx.Response(429, json={"error": {"code": "relay_busy", "retryable": True}}))
            with patch("httpx.Client", side_effect=lambda **kwargs: native_client(transport=mock_wire, **kwargs)):
                with self.assertRaises(MemoryError) as limited:
                    HTTPTransport().request(relays[0], "POST", "/v1/poll", {})
                self.assertTrue(limited.exception.retryable)

    def _assert_invalid_content_is_quarantined(self, sender, recipient):
        """An authorized malicious peer cannot turn bad JSON into a queue jam."""
        def post_invalid(message_id):
            current = sender._refresh(sender.relays[0])
            envelope = seal(b"SYNTHETIC_INVALID_CONTENT_MUST_NEVER_ENTER_VAULT", signer=sender.identity,
                network_id=sender.network_id, message_id=message_id,
                recipients=[{"signing_key_id": recipient.identity.key_id,
                             "encryption_key": recipient.encryption.public_descriptor()}],
                roster_version=current["payload"]["version"], roster_sha256=document_sha256(current))
            for relay in sender.relays:
                sender._refresh(relay)
                sender.transport.request(relay, "POST", "/v1/messages", {"envelope": envelope, "roster": current})
            return envelope, current

        with closing(recipient.client_config.vault()._connect()) as db:
            before_count = db.execute("SELECT COUNT(*) FROM memories").fetchone()[0]
        invalid, current = post_invalid("fixture-invalid-application-content")
        followup = {"request_id": "req_synthetic_after_invalid_content", "recipients": [recipient.identity.key_id],
                    "text": "Synthetic valid memory after a rejected message remains readable."}
        sent = sender.send(**followup)
        self.assertEqual(sent["stored_nodes"], 2, sent)
        delivered = recipient.receive()
        self.assertFalse(delivered["errors"], delivered)
        outcomes = {item["message_id"]: item for item in delivered["messages"]}
        self.assertEqual(outcomes[invalid["message_id"]]["state"], "rejected")
        self.assertEqual(outcomes[invalid["message_id"]]["code"], "network_invalid_content_json")
        self.assertNotIn("text", outcomes[invalid["message_id"]])
        self.assertEqual(outcomes[sent["message_id"]]["state"], "validated_saved")
        self.assertEqual(outcomes[sent["message_id"]]["text"], followup["text"])
        for _ in range(2):
            self.assertEqual(recipient.receive()["messages"], [])
        with recipient.db() as db:
            rejected = db.execute("SELECT * FROM quarantine").fetchall()
            self.assertEqual(len(rejected), 1)
            self.assertEqual(bytes(rejected[0]["envelope"]), canonical_bytes(invalid))
            self.assertNotIn(b"SYNTHETIC_INVALID_CONTENT_MUST_NEVER_ENTER_VAULT", bytes(rejected[0]["envelope"]))
            self.assertEqual(db.execute("SELECT COUNT(*) FROM inbox WHERE message_id=?", (invalid["message_id"],)).fetchone()[0], 0)
            before_cursors = {row["key"]: row["value"] for row in db.execute("SELECT key,value FROM state WHERE key LIKE 'cursor:%'")}
        with closing(recipient.client_config.vault()._connect()) as db:
            records = db.execute("SELECT text FROM memories").fetchall()
            self.assertEqual(len(records), before_count + 1)
            self.assertTrue(any(row[0] == followup["text"] for row in records))
            self.assertFalse(any("SYNTHETIC_INVALID_CONTENT_MUST_NEVER_ENTER_VAULT" in row[0] for row in records))
        for relay in sender.relays:
            with sender.transport.clients[relay].app.state.relay._transaction() as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM receipts WHERE message_id=?", (invalid["message_id"],)).fetchone()[0], 0)
        self.assertFalse(sender.receive()["errors"])
        self.assertTrue(sender.send(**followup)["endpoint_validated"])

        # Authentication/decryption failures never enter this quarantine path,
        # even when the message ID previously had rejected application content.
        forged = copy.deepcopy(invalid)
        forged["proof"]["key_id"] = "fixture-untrusted-signer"
        with self.assertRaises(MemoryError):
            recipient._accept(forged, current)
        damaged = copy.deepcopy(invalid)
        damaged["jwe"]["tag"] = "AAAAAAAAAAAAAAAAAAAAAA"
        damaged["proof"] = sender.identity.sign_message({key: value for key, value in damaged.items() if key != "proof"})
        with self.assertRaises(MemoryError):
            recipient._accept(damaged, current)

        post_invalid("fixture-quarantine-capacity-exhausted")
        blocked = sender.send("req_synthetic_after_quarantine_capacity", [recipient.identity.key_id],
                              "Synthetic later message must wait if quarantine is full.")
        for constant, maximum in (("MAX_QUARANTINE_MESSAGES", 1), ("MAX_QUARANTINE_BYTES", len(canonical_bytes(invalid)))):
            with patch("memory_vault_network." + constant, maximum):
                # Duplicated ciphertext does not consume another slot/byte
                # budget, including when the quarantine is already at its cap.
                self.assertEqual(recipient._accept(invalid, current)["state"], "rejected")
                full = recipient.receive()
                self.assertEqual(full["messages"], [])
                self.assertEqual([error["code"] for error in full["errors"]], ["network_quarantine_capacity"] * 2)
                with recipient.db() as db:
                    self.assertEqual({row["key"]: row["value"] for row in db.execute("SELECT key,value FROM state WHERE key LIKE 'cursor:%'")}, before_cursors)
                    self.assertEqual(db.execute("SELECT COUNT(*) FROM quarantine").fetchone()[0], 1)
                    self.assertEqual(db.execute("SELECT COUNT(*) FROM inbox WHERE message_id=?", (blocked["message_id"],)).fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
