"""Real loopback node maintenance and replacement with test-owned processes.

All keys, files and memory are temporary synthetic fixtures. The tampering
cases alter real HTTP responses at the test transport boundary. These checks
do not claim TLS, physical fault-domain, complete migration or model evidence.
"""
from __future__ import annotations

from contextlib import ExitStack, redirect_stderr
import copy
import hashlib
import io
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch

from memory_vault import MemoryError, canonical_bytes, strict_json_loads
from memory_vault_agent import Agent
from memory_vault_client import ClientConfig, CONFIG_SCHEMA
from memory_vault_network import HTTPTransport, NetworkClient
from memory_vault_network_control import issue_invite, issue_roster, open_join_challenge, sign_request
from memory_vault_network_crypto import EncryptionIdentity, document_sha256
from memory_vault_node import inspect, refresh
from memory_vault_nodes import issue_directory
from memory_vault_relay import Relay, main as relay_main
from memory_vault_storage import atomic_write
from memory_vault_trust import Identity, TrustError, TrustStore
from tests.test_network_http import _LoopbackService


class _ObservedHTTP(HTTPTransport):
    def __init__(self):
        super().__init__()
        self.mutator = None
        self.callers = []

    def request(self, base, method, path, value=None, *, deadline=None):
        if value is not None:
            proof = value.get("request", {}).get("proof", {})
            self.callers.append((path, proof.get("key_id")))
        result = super().request(base, method, path, value, deadline=deadline)
        return self.mutator(base, method, path, result) if self.mutator else result


class NetworkNodeListenerSafetyTests(unittest.TestCase):
    def test_external_listener_without_tls_is_rejected_before_app_or_socket(self):
        with tempfile.TemporaryDirectory(prefix="memory-node-listener-synthetic-") as temporary:
            config = Path(temporary).resolve() / "intentionally-absent-config.json"
            cases = [(["--host", host], "relay_external_listener_requires_tls")
                     for host in ("0.0.0.0", "::", "192.0.2.30", "synthetic-node.invalid")]
            cases.extend([(["--host", "0.0.0.0", option, str(config.parent / "absent-tls-file")],
                           "relay_tls_certificate_and_key_required")
                          for option in ("--tls-certfile", "--tls-keyfile")])
            for options, error in cases:
                with self.subTest(options=options), patch("memory_vault_relay.create_app") as create, \
                        patch("uvicorn.run") as run, redirect_stderr(io.StringIO()) as output:
                    result = relay_main(["serve", "--config", str(config), *options])
                    self.assertEqual(result, 2)
                    self.assertEqual(strict_json_loads(output.getvalue())["error"]["code"], error)
                    create.assert_not_called()
                    run.assert_not_called()
                    self.assertFalse(config.exists())


@unittest.skipUnless(os.name == "posix", "the loopback fixture inherits test-owned POSIX sockets")
class NetworkNodeRuntimeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="memory-node-runtime-synthetic-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.dict(os.environ, {"NO_PROXY": "127.0.0.1,localhost,::1",
                                                         "no_proxy": "127.0.0.1,localhost,::1"}))
        self.services = []
        self.authority = self.service("authority", "authority")
        self.relays = [self.service("relay-" + str(index), "relay") for index in range(2)]
        self.network_id = "synthetic-node-runtime-network"
        self.issuer = Identity.generate(self.root / "issuer.json")
        TrustStore(self.root / "issuer-trust.json").add(self.issuer.public_descriptor())
        self.identities, self.encryption, self.configs, self.net_configs = [], [], [], []
        for name in ("sender", "receiver", "candidate"):
            location = self.root / name
            identity = Identity.generate(location / "identity.json")
            encryption = EncryptionIdentity.generate()
            encryption.save(location / "encryption.json")
            self.identities.append(identity)
            self.encryption.append(encryption)
            config = location / "client.json"
            atomic_write(config, canonical_bytes({"schema_version": CONFIG_SCHEMA,
                "vault_path": str(location / "memory.sqlite3"), "capture_visible_turns": False,
                "identity_path": str(location / "identity.json"), "trust_path": str(location / "trust.json")}), replace=False)
            self.configs.append(config)
            net = location / "network.json"
            atomic_write(net, canonical_bytes({"schema_version": "memory-vault-network-client/v1",
                "network_id": self.network_id, "client_config_path": str(config),
                "state_directory": str(location / "network-state"), "encryption_key_path": str(location / "encryption.json"),
                "issuer_public_key": self.issuer.public_descriptor(), "relays": [relay.url for relay in self.relays],
                "authority_url": self.authority.url}), replace=False)
            self.net_configs.append(net)
        for config in self.configs:
            trust = TrustStore(config.parent / "trust.json")
            for identity in self.identities:
                trust.add(identity.public_descriptor())
        now = int(time.time())
        members = [{"signing_key": identity.public_descriptor(), "encryption_key": encryption.public_descriptor(),
                    "scope": ["receive", "send"], "status": "active"}
                   for identity, encryption in zip(self.identities, self.encryption)]
        self.roster = issue_roster(self.issuer, network_id=self.network_id, version=1, previous_sha256="0" * 64,
                                  members=members, issued_at=now, expires_at=now + 300)
        self.roster_path, self.directory_path = self.root / "roster.json", self.root / "nodes.json"
        atomic_write(self.roster_path, canonical_bytes(self.roster), replace=False)
        self.node_identities, self.node_entries, self.relay_configs = [], [], []
        for index, relay in enumerate(self.relays):
            key_path = self.root / ("node-signing-" + str(index) + ".json")
            identity = Identity.generate(key_path)
            epoch = "synthetic-storage-epoch-" + str(index)
            self.node_identities.append(identity)
            self.node_entries.append({"signing_key": identity.public_descriptor(), "base_url": relay.url,
                                      "storage_epoch": epoch, "scope": ["export", "import", "node.status"], "status": "active"})
            config = {"schema_version": "memory-vault-relay-config/v1", "network_id": self.network_id,
                "issuer_public_key": self.issuer.public_descriptor(), "roster_path": str(self.roster_path),
                "state_directory": str(self.root / ("node-state-" + str(index))), "base_url": relay.url,
                "init_member_key_ids": [self.identities[0].key_id], "authority_url": self.authority.url,
                "node_identity_path": str(key_path), "storage_epoch": epoch}
            atomic_write(relay.config, canonical_bytes(config), replace=False)
            self.relay_configs.append(config)
        self.directory = issue_directory(self.issuer, network_id=self.network_id, version=1, previous_sha256="0" * 64,
                                         nodes=self.node_entries, issued_at=now, expires_at=now + 300)
        atomic_write(self.directory_path, canonical_bytes(self.directory), replace=False)
        self.authority_config = {"schema_version": "memory-vault-network-authority-config/v1", "network_id": self.network_id,
            "identity_path": str(self.root / "issuer.json"), "trust_store_path": str(self.root / "issuer-trust.json"),
            "roster_path": str(self.roster_path), "node_directory_path": str(self.directory_path)}
        atomic_write(self.authority.config, canonical_bytes(self.authority_config), replace=False)
        for service in self.services:
            service.start()
        self.transports = [self.stack.enter_context(_ObservedHTTP()) for _ in range(3)]
        self.sender, self.receiver = [NetworkClient(config, transport=transport)
            for config, transport in zip(self.net_configs[:2], self.transports[:2])]
        self.invitation = {"invite": self.invite(1), "roster": self.roster}

    def tearDown(self):
        self.stack.close()
        for service in self.services:
            self.assertTrue(all(process.poll() is not None for process in service.processes))

    def service(self, name, kind):
        service = _LoopbackService(self.root, name, kind)
        self.stack.callback(service.stop)
        self.services.append(service)
        return service

    def invite(self, index):
        now = int(time.time())
        return issue_invite(self.issuer, network_id=self.network_id, invite_id="synthetic-runtime-invite-" + str(index),
            candidate_signing_key=self.identities[index].public_descriptor(),
            candidate_encryption_key=self.encryption[index].public_descriptor(), scope=["receive", "send"],
            handoff_sha256=hashlib.sha256(b"").hexdigest(), roster_sha256=document_sha256(self.roster),
            issued_at=now, expires_at=now + 3600)

    def join_receiver(self):
        result = self.receiver.connect(self.invitation, request_id="req_synthetic_runtime_join")
        self.assertEqual(result["joined_nodes"], 2, result)
        self.assertFalse(result["errors"], result)

    def outbox(self):
        with self.sender.db() as db:
            return {row["request_id"]: dict(row) for row in db.execute("SELECT * FROM outbox")}

    def bookkeeping(self, client, url):
        with client.db() as db:
            return {row["key"]: row["value"] for row in db.execute("SELECT * FROM state")
                    if row["key"] in {"cursor:" + url, "node:" + url}
                    or row["key"].startswith(("ack:" + url + ":", "join:" + url + ":"))}

    def reject_http(self, code, path, body):
        with self.assertRaises(MemoryError) as caught:
            self.transports[2].request(self.relays[0].url, "POST", path, body)
        self.assertEqual(caught.exception.code, code)

    def test_independent_refresh_and_persistent_drain_fence_over_real_http(self):
        local = Relay(self.relays[0].config)
        node_transport = self.transports[2]
        result = refresh(local, transport=node_transport)
        self.assertEqual(result["state"], "fresh", result)
        self.assertFalse(result["agent_identity_used"])
        self.assertFalse(result["plaintext_keys_used"])
        self.assertIn(("/v1/node-status", self.node_identities[0].key_id), node_transport.callers)
        self.assertNotIn(self.node_identities[0].key_id, {entry["signing_key"]["key_id"] for entry in self.roster["payload"]["members"]})
        self.assertNotIn("encryption_key", local.node_descriptor())
        self.assertFalse(inspect(local)["safe_to_remove"])
        now = int(time.time())
        # A node signing key still cannot use member mailbox operations.
        node_poll = sign_request(self.node_identities[0], network_id=self.network_id, action="poll",
            request_id="synthetic-node-cannot-poll", body={"cursor": 0, "receipt_cursor": 0, "limit": 1, "maximum_bytes": 8192},
            issued_at=now, expires_at=now + 60)
        self.reject_http("relay_membership_required", "/v1/poll", node_poll)
        self.join_receiver()
        sent = self.sender.send("req_synthetic_before_drain", [self.identities[1].key_id], "Synthetic message retained during drain")
        self.assertEqual(sent["stored_nodes"], 2, sent)
        stored = self.outbox()["req_synthetic_before_drain"]
        envelope = strict_json_loads(stored["envelope"])
        drained = local.drain()
        self.assertEqual(drained["state"], "draining")
        self.assertFalse(drained["safe_to_remove"])
        self.assertTrue(drained["migration_required"])
        self.assertEqual(drained["messages"], 1)
        self.assertEqual(drained["receipts"], 0)
        self.assertEqual(drained["members"], 2)
        self.assertEqual(local.drain(), drained)
        pending = self.sender.send("req_synthetic_during_drain", [self.identities[1].key_id], "Synthetic write rejected by draining node")
        self.assertEqual(pending["stored_nodes"], 1, pending)
        self.assertTrue(any(error["code"] == "relay_draining" for error in pending["errors"]), pending)
        admission = {"invite": self.invite(2), "roster": self.roster}
        acknowledgement = sign_request(self.identities[1], network_id=self.network_id, action="ack",
            request_id="synthetic-ack-after-drain", body={"message_id": sent["message_id"],
                "envelope_sha256": document_sha256(envelope), "state": "validated_saved"}, issued_at=now, expires_at=now + 60)
        self.reject_http("relay_draining", "/v1/join", admission)
        self.reject_http("relay_draining", "/v1/ack", acknowledgement)
        self.relays[0].stop()
        self.relays[0].start()
        restarted = Relay(self.relays[0].config)
        refresh(restarted, transport=node_transport)
        state = inspect(restarted)
        self.assertEqual(state["state"], "draining")
        self.assertFalse(state["safe_to_remove"])
        self.assertFalse(state["source_data_deleted"])
        self.assertEqual((state["stored_messages"], state["stored_receipts"]), (1, 0))
        self.assertEqual(restarted.drain(), drained)
        pending_envelope = strict_json_loads(self.outbox()["req_synthetic_during_drain"]["envelope"])
        self.reject_http("relay_draining", "/v1/messages", {"envelope": pending_envelope, "roster": self.roster})
        self.reject_http("relay_draining", "/v1/join", admission)
        self.reject_http("relay_draining", "/v1/ack", acknowledgement)

    def test_authenticated_same_url_replacement_resets_only_delivery_state(self):
        self.join_receiver()
        original_agent = Agent(self.configs[0])
        saved = original_agent.handle({"op": "remember", "request_id": "req_synthetic_runtime_record", "kind": "fact",
                                       "text": "Synthetic canonical evidence: a silver crane keeps the violet map."})
        self.assertTrue(saved["ok"], saved)
        memory_id = saved["result"]["memory_id"]
        original = ClientConfig.load(self.configs[0]).vault().handle({"op": "get", "memory_id": memory_id})["result"]["record"]
        for index in range(2):
            sent = self.sender.send("req_synthetic_old_node_" + str(index), [self.identities[1].key_id],
                                    "Synthetic prior-node message " + str(index), [memory_id])
            self.assertEqual(sent["stored_nodes"], 2, sent)
        received = self.receiver.receive()
        self.assertFalse(received["errors"], received)
        self.assertEqual(len(received["messages"]), 2)
        self.assertFalse(self.sender.receive()["errors"])
        old_outbox = self.outbox()
        source, other = [relay.url for relay in self.relays]
        old_receiver_source = self.bookkeeping(self.receiver, source)
        other_bookkeeping = self.bookkeeping(self.receiver, other)
        self.assertEqual(strict_json_loads(old_receiver_source["cursor:" + source])["cursor"], 2)
        self.assertTrue(any(key.startswith("join:" + source + ":") for key in old_receiver_source))
        with self.receiver.db() as db:
            old_inbox = {row["message_id"]: dict(row) for row in db.execute("SELECT * FROM inbox")}
        # Rejected forged responses must not reset already accepted delivery state.
        def bad_challenge(base, method, path, response):
            if base == source and method == "GET" and path == "/v1/status":
                response = copy.deepcopy(response)
                proof = response["node_challenge"]["proof"]
                signature = proof["signature"]
                proof["signature"] = ("A" if signature[0] != "A" else "B") + signature[1:]
            return response
        def bad_directory(base, method, path, response):
            if base == self.authority.url and method == "POST" and path == "/v1/status":
                response = copy.deepcopy(response)
                response["nodes"]["payload"]["nodes"][0]["storage_epoch"] = "forged-epoch"
            return response
        for mutator in (bad_challenge, bad_directory):
            self.transports[1].mutator = mutator
            try:
                with self.assertRaises((MemoryError, TrustError)):
                    self.receiver._refresh(source)
            finally:
                self.transports[1].mutator = None
            self.assertEqual(self.bookkeeping(self.receiver, source), old_receiver_source)
        legacy = {key: value for key, value in self.authority_config.items() if key != "node_directory_path"}
        atomic_write(self.authority.config, canonical_bytes(legacy), replace=True)
        try:
            with self.assertRaises(MemoryError) as downgrade:
                self.receiver._refresh(source)
            self.assertEqual(downgrade.exception.code, "network_node_directory_downgrade")
        finally:
            atomic_write(self.authority.config, canonical_bytes(self.authority_config), replace=True)
        self.assertEqual(self.bookkeeping(self.receiver, source), old_receiver_source)
        # Keep the old node directory/data. Replacement has a new signing key,
        # new epoch and empty database; this is explicitly not state migration.
        self.relays[0].stop()
        replacement_path = self.root / "replacement-node-signing.json"
        replacement = Identity.generate(replacement_path)
        replacement_entry = {**self.node_entries[0], "signing_key": replacement.public_descriptor(),
                             "storage_epoch": "synthetic-replacement-epoch"}
        nodes = [{**self.node_entries[0], "status": "revoked"}, self.node_entries[1], replacement_entry]
        now = int(time.time())
        directory = issue_directory(self.issuer, network_id=self.network_id, version=2,
            previous_sha256=document_sha256(self.directory), nodes=nodes, issued_at=now, expires_at=now + 300)
        atomic_write(self.directory_path, canonical_bytes(directory), replace=True)
        replacement_config = {**self.relay_configs[0], "node_identity_path": str(replacement_path),
            "storage_epoch": replacement_entry["storage_epoch"], "state_directory": str(self.root / "replacement-node-state")}
        atomic_write(self.relays[0].config, canonical_bytes(replacement_config), replace=True)
        self.relays[0].start()
        refresh(Relay(self.relays[0].config), transport=self.transports[2])
        # Perform fresh authorized admission without changing the existing
        # receiver's old cursor. It will discover the new incarnation on poll.
        challenge = self.transports[2].request(source, "POST", "/v1/join", self.invitation)["challenge"]
        answer = open_join_challenge(challenge, self.encryption[1], network_id=self.network_id,
                                     invite_id=self.invitation["invite"]["payload"]["invite_id"])
        proof = sign_request(self.identities[1], network_id=self.network_id, action="join",
            request_id="synthetic-replacement-admission", body={"invite_sha256": document_sha256(self.invitation["invite"]),
                "challenge_id": challenge["challenge_id"], "challenge_answer": answer}, issued_at=now, expires_at=now + 60)
        self.assertEqual(self.transports[2].request(source, "POST", "/v1/join", {**self.invitation, "request": proof})["state"], "joined")
        new_send = self.sender.send("req_synthetic_replacement", [self.identities[1].key_id],
                                    "Synthetic message at sequence one after replacement", [memory_id])
        self.assertEqual(new_send["stored_nodes"], 2, new_send)
        self.assertEqual(self.bookkeeping(self.receiver, source), old_receiver_source)
        self.assertEqual(self.bookkeeping(self.receiver, other), other_bookkeeping)
        with sqlite3.connect(self.root / "replacement-node-state" / "relay.sqlite3") as db:
            self.assertEqual(db.execute("SELECT sequence FROM messages WHERE message_id=?", (new_send["message_id"],)).fetchone()[0], 1)
        after_outbox = self.outbox()
        for request_id, before in old_outbox.items():
            after = after_outbox[request_id]
            self.assertEqual({key: value for key, value in before.items() if key != "receipts"},
                             {key: value for key, value in after.items() if key != "receipts"})
            before_receipts, after_receipts = strict_json_loads(before["receipts"]), strict_json_loads(after["receipts"])
            self.assertNotIn(source, after_receipts)
            self.assertEqual(after_receipts[other], before_receipts[other])
        received = self.receiver.receive()
        self.assertFalse(received["errors"], received)
        self.assertEqual([message["message_id"] for message in received["messages"]], [new_send["message_id"]])
        new_source = self.bookkeeping(self.receiver, source)
        self.assertEqual(strict_json_loads(new_source["cursor:" + source])["cursor"], 1)
        self.assertEqual(strict_json_loads(new_source["node:" + source])["storage_epoch"], replacement_entry["storage_epoch"])
        self.assertFalse(any(key.startswith("join:" + source + ":") for key in new_source))
        for key in old_receiver_source:
            if key.startswith("ack:" + source + ":"):
                self.assertNotIn(key, new_source)
        with self.receiver.db() as db:
            for message_id, before in old_inbox.items():
                self.assertEqual(dict(db.execute("SELECT * FROM inbox WHERE message_id=?", (message_id,)).fetchone()), before)
        for config in self.configs[:2]:
            record = ClientConfig.load(config).vault().handle({"op": "get", "memory_id": memory_id})["result"]["record"]
            self.assertEqual(canonical_bytes(record), canonical_bytes(original))
        self.assertFalse(self.receiver.receive()["messages"])


if __name__ == "__main__":
    unittest.main()
