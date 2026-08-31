"""Deterministic concurrent-client schedules over real synthetic HTTP nodes.

Every response is obtained from the real authority/relay before a second
independent client is scheduled. No signed document, signature, cipher, SQLite
result or authorization is mocked. Only test-owned temporary nodes are replaced.
"""
from __future__ import annotations

import os
import time
import unittest

from memory_vault import MemoryError, canonical_bytes, strict_json_loads
from memory_vault_network import HTTPTransport, NetworkClient
from memory_vault_network_crypto import document_sha256
from memory_vault_nodes import issue_directory
from memory_vault_storage import atomic_write
from memory_vault_trust import Identity
from tests import test_network_node_runtime as runtime


@unittest.skipUnless(os.name == "posix", "test-owned loopback socket fixture requires POSIX")
class NetworkClientRaceTests(unittest.TestCase):
    def setUp(self):
        self.host = runtime.NetworkNodeRuntimeTests("test_independent_refresh_and_persistent_drain_fence_over_real_http")
        self.addCleanup(self.host.doCleanups)
        self.host.setUp()
        self.addCleanup(self.host.tearDown)
        self.host.join_receiver()
        transport = self.host.stack.enter_context(HTTPTransport())
        self.other = NetworkClient(self.host.net_configs[1], transport=transport)
        self.url = self.host.relays[0].url

    def state(self, name):
        with self.host.receiver.db() as connection:
            row = connection.execute("SELECT value FROM state WHERE key=?", (name,)).fetchone()
            return strict_json_loads(row["value"]) if row else None

    def replace(self):
        host = self.host
        host.relays[0].stop()
        identity_path = host.root / "race-replacement-identity.json"
        identity = Identity.generate(identity_path)
        entry = {**host.node_entries[0], "signing_key": identity.public_descriptor(),
                 "storage_epoch": "synthetic-race-replacement-epoch"}
        timestamp = int(time.time())
        directory = issue_directory(host.issuer, network_id=host.network_id, version=2,
            previous_sha256=document_sha256(host.directory),
            nodes=[{**host.node_entries[0], "status": "revoked"}, host.node_entries[1], entry],
            issued_at=timestamp, expires_at=timestamp + 300)
        atomic_write(host.directory_path, canonical_bytes(directory), replace=True)
        config = {**host.relay_configs[0], "node_identity_path": str(identity_path),
            "storage_epoch": entry["storage_epoch"], "state_directory": str(host.root / "race-replacement-state"),
            # Explicit synthetic operator initialization; no old membership DB
            # is copied or accepted as authority on the replacement node.
            "init_member_key_ids": [item.key_id for item in host.identities[:2]]}
        atomic_write(host.relays[0].config, canonical_bytes(config), replace=True)
        host.relays[0].start()
        self.other._refresh(self.url)
        return {key: entry[key] for key in ("signing_key", "base_url", "storage_epoch")}

    def test_verified_old_status_cannot_rebind_after_another_client_replaces_node(self):
        host = self.host
        challenge = host.transports[1].request(self.url, "GET", "/v1/status")
        old = host.receiver._status(challenge["nonce"])
        binding = self.replace()
        with host.receiver.db() as connection:
            connection.execute("INSERT OR REPLACE INTO state VALUES(?,?)", ("cursor:" + self.url,
                canonical_bytes({"cursor": 1, "receipt_cursor": 0}).decode()))
        with self.assertRaises(MemoryError) as caught:
            host.receiver._bind_node(self.url, challenge, old)
        self.assertEqual(caught.exception.code, "network_node_directory_rollback")
        self.assertEqual(self.state("node:" + self.url), binding)
        self.assertEqual(self.state("node_directory")["payload"]["version"], 2)
        self.assertEqual(self.state("cursor:" + self.url)["cursor"], 1)

    def test_late_old_poll_cannot_overwrite_new_node_cursor_and_hide_sequence_one(self):
        host = self.host
        sent = host.sender.send("req_synthetic_race_old", [host.identities[1].key_id], "Old node history")
        self.assertEqual(sent["stored_nodes"], 2, sent)
        self.assertFalse(host.receiver.receive()["errors"])
        self.assertEqual(self.state("cursor:" + self.url)["cursor"], 1)
        replaced = []

        def schedule(base, method, route, response):
            if base == self.url and route == "/v1/poll" and not replaced:
                replaced.append(True)
                self.replace()
            return response

        host.transports[1].mutator = schedule
        try:
            stale = host.receiver.receive()
        finally:
            host.transports[1].mutator = None
        self.assertEqual([item["code"] for item in stale["errors"] if item["node"] == 0], ["network_node_changed"], stale)
        self.assertTrue(next(item for item in stale["errors"] if item["node"] == 0)["retryable"])
        self.assertIsNone(self.state("cursor:" + self.url))
        # The other replica cannot mask a skipped message on the replaced node.
        host.relays[1].stop()
        new = host.sender.send("req_synthetic_race_new", [host.identities[1].key_id], "New node sequence one")
        self.assertEqual(new["stored_nodes"], 1, new)
        received = host.receiver.receive()
        self.assertEqual([item["message_id"] for item in received["messages"]], [new["message_id"]], received)
        self.assertEqual(self.state("cursor:" + self.url)["cursor"], 1)

    def test_same_node_late_poll_does_not_move_cursor_backwards(self):
        host = self.host
        for index in range(2):
            sent = host.sender.send("req_synthetic_race_order_" + str(index), [host.identities[1].key_id], "Ordered evidence " + str(index))
            self.assertEqual(sent["stored_nodes"], 2, sent)
        advanced = []

        def schedule(base, method, route, response):
            if base == self.url and route == "/v1/poll" and not advanced:
                advanced.append(True)
                other = self.other.receive(4)
                self.assertFalse(other["errors"], other)
                self.assertEqual(self.state("cursor:" + self.url)["cursor"], 2)
            return response

        host.transports[1].mutator = schedule
        try:
            late = host.receiver.receive(1)
        finally:
            host.transports[1].mutator = None
        self.assertFalse(late["errors"], late)
        self.assertEqual(self.state("cursor:" + self.url)["cursor"], 2)
        self.assertFalse(host.receiver.receive()["messages"])

    def test_node_replacement_while_ack_waits_cannot_commit_old_page(self):
        host = self.host
        sent = host.sender.send("req_synthetic_race_ack", [host.identities[1].key_id], "Saved before the old acknowledgement returns")
        self.assertEqual(sent["stored_nodes"], 2, sent)
        replaced = []

        def schedule(base, method, route, response):
            if base == self.url and route == "/v1/ack" and not replaced:
                replaced.append(True)
                self.replace()
            return response

        host.transports[1].mutator = schedule
        try:
            late = host.receiver.receive()
        finally:
            host.transports[1].mutator = None
        self.assertEqual([item["code"] for item in late["errors"] if item["node"] == 0], ["network_node_changed"], late)
        self.assertIsNone(self.state("cursor:" + self.url))
        self.assertIsNone(self.state("ack:" + self.url + ":" + sent["message_id"]))
        with host.receiver.db() as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM inbox WHERE message_id=?", (sent["message_id"],)).fetchone()[0], 1)
        new = host.sender.send("req_synthetic_race_ack_new", [host.identities[1].key_id], "Read sequence one after the acknowledgement race")
        self.assertEqual(new["stored_nodes"], 2, new)
        result = host.receiver.receive()
        self.assertFalse(result["errors"], result)
        self.assertEqual([item["message_id"] for item in result["messages"]], [new["message_id"]])
        self.assertEqual(self.state("cursor:" + self.url)["cursor"], 1)

    def test_same_node_late_receipt_page_cannot_rewind_receipt_cursor(self):
        host = self.host
        for index in range(2):
            sent = host.sender.send("req_synthetic_race_receipt_" + str(index), [host.identities[1].key_id], "Receipt evidence " + str(index))
            self.assertEqual(sent["stored_nodes"], 2, sent)
        self.assertFalse(host.receiver.receive()["errors"])
        transport = host.stack.enter_context(HTTPTransport())
        other_sender = NetworkClient(host.net_configs[0], transport=transport)
        advanced = []

        def receipt_cursor():
            with host.sender.db() as connection:
                value = connection.execute("SELECT value FROM state WHERE key=?", ("cursor:" + self.url,)).fetchone()
                return strict_json_loads(value["value"])["receipt_cursor"]

        def schedule(base, method, route, response):
            if base == self.url and route == "/v1/poll" and not advanced:
                advanced.append(True)
                other = other_sender.receive(4)
                self.assertFalse(other["errors"], other)
                self.assertEqual(receipt_cursor(), 2)
            return response

        host.transports[0].mutator = schedule
        try:
            late = host.sender.receive(1)
        finally:
            host.transports[0].mutator = None
        self.assertFalse(late["errors"], late)
        self.assertEqual(receipt_cursor(), 2)
        with host.sender.db() as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM acknowledgements").fetchone()[0], 2)


if __name__ == "__main__":
    unittest.main()
