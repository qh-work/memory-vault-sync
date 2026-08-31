"""Explicit bounded pump checks with temporary identities and two ASGI relays."""
from contextlib import ExitStack, closing, contextmanager
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from memory_vault import MemoryError, canonical_bytes, strict_json_loads
from memory_vault_client import CONFIG_SCHEMA
from memory_vault_network import HTTPTransport, NetworkClient
from memory_vault_network_control import create_authority_app, issue_roster
from memory_vault_network_crypto import EncryptionIdentity
from memory_vault_relay import create_app
from memory_vault_storage import atomic_write
from memory_vault_trust import Identity, TrustStore
import memory_vault_network_worker as worker


class Transport:
    def __init__(self, clients):
        self.clients = clients
        self.offline = set()
        self.drop_after_store = None
        self.calls = []
        self.clock = None
        self.step = 0

    def request(self, base, method, path, value=None):
        self.calls.append((base, method, path, None if self.clock is None else self.clock[0]))
        if base in self.offline:
            raise MemoryError("network_unavailable", retryable=True)
        response = self.clients[base].request(method, path,
            content=None if value is None else canonical_bytes(value), headers={"content-type": "application/json"})
        result = response.json()
        if self.clock is not None:
            self.clock[0] += self.step
        if response.status_code != 200:
            error = result["error"]
            raise MemoryError(error["code"], retryable=error.get("retryable", False))
        if base == self.drop_after_store and path == "/v1/messages":
            self.drop_after_store = None
            raise MemoryError("network_unavailable", retryable=True)
        return result


@contextmanager
def fixture():
    from starlette.testclient import TestClient
    with tempfile.TemporaryDirectory(prefix="memory-network-pump-synthetic-") as temporary, ExitStack() as stack:
        root = Path(temporary).resolve()
        issuer = Identity.generate(root / "issuer.json")
        issuer_trust = TrustStore(root / "issuer-trust.json")
        issuer_trust.add(issuer.public_descriptor())
        identities, keys, configs = [], [], []
        for name in ("sender", "recipient"):
            directory = root / name
            identity = Identity.generate(directory / "identity.json")
            key = EncryptionIdentity.generate()
            key.save(directory / "encryption.json")
            config = directory / "client.json"
            atomic_write(config, canonical_bytes({"schema_version": CONFIG_SCHEMA,
                "vault_path": str(directory / "vault" / "memory.sqlite3"), "capture_visible_turns": False,
                "identity_path": str(directory / "identity.json"), "trust_path": str(directory / "trust.json")}), replace=False)
            identities.append(identity)
            keys.append(key)
            configs.append(config)
        for config in configs:
            trust = TrustStore(config.parent / "trust.json")
            for identity in identities:
                trust.add(identity.public_descriptor())
        now = int(time.time())
        network = "synthetic-pump-network"
        roster = issue_roster(issuer, network_id=network, version=1, previous_sha256="0" * 64,
            members=[{"signing_key": identity.public_descriptor(), "encryption_key": key.public_descriptor(),
                      "scope": ["receive", "send"], "status": "active"} for identity, key in zip(identities, keys)],
            issued_at=now, expires_at=now + 300)
        roster_path = root / "roster.json"
        atomic_write(roster_path, canonical_bytes(roster), replace=False)
        authority_url = "http://127.0.0.1:9780"
        relays = ["http://127.0.0.1:9781", "http://127.0.0.1:9782"]
        authority_config = root / "authority.json"
        atomic_write(authority_config, canonical_bytes({"schema_version": "memory-vault-network-authority-config/v1",
            "network_id": network, "identity_path": str(root / "issuer.json"),
            "trust_store_path": str(root / "issuer-trust.json"), "roster_path": str(roster_path)}), replace=False)
        clients = {authority_url: stack.enter_context(TestClient(create_authority_app(authority_config)))}
        for index, relay in enumerate(relays):
            config = root / ("relay-" + str(index) + ".json")
            atomic_write(config, canonical_bytes({"schema_version": "memory-vault-relay-config/v1",
                "network_id": network, "issuer_public_key": issuer.public_descriptor(), "roster_path": str(roster_path),
                "state_directory": str(root / ("node-" + str(index))), "base_url": relay,
                "init_member_key_ids": [identity.key_id for identity in identities]}), replace=False)
            clients[relay] = stack.enter_context(TestClient(create_app(config)))
        transport = Transport(clients)
        endpoints = []
        for config in configs:
            network_config = config.parent / "network.json"
            atomic_write(network_config, canonical_bytes({"schema_version": "memory-vault-network-client/v1",
                "network_id": network, "client_config_path": str(config), "state_directory": str(config.parent / "network-state"),
                "encryption_key_path": str(config.parent / "encryption.json"), "issuer_public_key": issuer.public_descriptor(),
                "relays": relays, "authority_url": authority_url}), replace=False)
            endpoints.append(NetworkClient(network_config, transport=transport))
        yield endpoints[0], endpoints[1], transport


class NetworkWorkerTests(unittest.TestCase):
    def test_offline_restart_pump_retries_frozen_bytes_two_nodes_and_receives(self):
        with fixture() as (sender, recipient, transport):
            transport.offline.update(sender.relays)
            for index in range(2):
                result = sender.send("req_synthetic_pump_" + str(index), [recipient.identity.key_id],
                                     "Synthetic durable offline memory " + str(index))
                self.assertEqual(result["stored_nodes"], 0)
            with sender.db() as db:
                before = {row["request_id"]: bytes(row["body"]) for row in db.execute("SELECT * FROM outbox")}
                self.assertTrue(all(row[0] is None for row in db.execute("SELECT envelope FROM outbox")))
            with closing(sender.client_config.vault()._connect()) as db:
                original_ids = [row[0] for row in db.execute("SELECT memory_id FROM memories ORDER BY memory_id")]
            sender = NetworkClient(sender.config_path, transport=transport)
            transport.offline.remove(sender.relays[0])
            partial = sender.pump(maximum_messages=1, receive_limit=0)
            self.assertEqual(partial["outbound_attempted"], 1)
            self.assertEqual(partial["outbound"][0]["stored_nodes"], 1)
            self.assertTrue(partial["retryable"])
            self.assertTrue(partial["outbound"][0]["errors"][0]["retryable"])
            with sender.db() as db:
                frozen = bytes(db.execute("SELECT envelope FROM outbox WHERE request_id='req_synthetic_pump_0'").fetchone()[0])
                # Old frozen rows have recoverable routing even if the new
                # optional metadata was absent in their original version.
                db.execute("UPDATE outbox SET recipients=NULL WHERE request_id='req_synthetic_pump_0'")
            transport.offline.clear()
            transport.drop_after_store = sender.relays[1]
            interrupted = sender.pump(maximum_messages=2, receive_limit=0)
            self.assertTrue(interrupted["retryable"])
            sender = NetworkClient(sender.config_path, transport=transport)
            finished = sender.pump(receive_limit=0)
            self.assertEqual(finished["remaining_outbox"], 0, finished)
            self.assertEqual(finished["state"], "completed")
            with sender.db() as db:
                self.assertEqual({row["request_id"]: bytes(row["body"]) for row in db.execute("SELECT * FROM outbox")}, before)
                self.assertEqual(bytes(db.execute("SELECT envelope FROM outbox WHERE request_id='req_synthetic_pump_0'").fetchone()[0]), frozen)
            for relay in sender.relays:
                with transport.clients[relay].app.state.relay._transaction() as db:
                    self.assertEqual(db.execute("SELECT COUNT(*) FROM messages").fetchone()[0], 2)
            received = recipient.pump(maximum_messages=0)
            self.assertEqual(len(received["receive"]["messages"]), 2, received)
            acknowledged = sender.pump()
            self.assertEqual(acknowledged["outbound_attempted"], 0)
            self.assertFalse(acknowledged["receive"]["errors"])
            with sender.db() as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM acknowledgements").fetchone()[0], 2)
            with closing(sender.client_config.vault()._connect()) as db:
                self.assertEqual([row[0] for row in db.execute("SELECT memory_id FROM memories ORDER BY memory_id")], original_ids)
            self.assertEqual(recipient.pump(maximum_messages=0)["receive"]["messages"], [])

    def test_legacy_unfrozen_queue_requires_original_request_and_does_not_starve(self):
        with fixture() as (sender, recipient, transport):
            transport.offline.update(sender.relays)
            original = {"request_id": "req_synthetic_legacy_pending", "recipients": [recipient.identity.key_id], "text": "Synthetic legacy offline row."}
            sender.send(**original)
            with sender.db() as db:
                db.execute("ALTER TABLE outbox DROP COLUMN recipients")
            sender = NetworkClient(sender.config_path, transport=transport)
            sender.send("req_synthetic_routable_pending", [recipient.identity.key_id], "Synthetic routable offline row.")
            transport.offline.clear()
            blocked = sender.pump(maximum_messages=1, receive_limit=0)
            self.assertEqual(blocked["outbound"][0]["errors"][0]["code"], "network_outbox_recipients_unavailable")
            self.assertTrue(blocked["outbound"][0]["errors"][0]["requires_original_request"])
            self.assertFalse(blocked["outbound"][0]["errors"][0]["retryable"])
            rotated = sender.pump(maximum_messages=1, receive_limit=0)
            self.assertEqual(rotated["outbound"][0]["request_id"], "req_synthetic_routable_pending")
            self.assertEqual(rotated["outbound"][0]["stored_nodes"], 2)
            attention = sender.pump(maximum_messages=1, receive_limit=0)
            self.assertEqual(attention["state"], "needs_attention")
            self.assertFalse(attention["retryable"])
            sender.send(**original)
            self.assertEqual(sender.pump(receive_limit=0)["remaining_outbox"], 0)

    def test_time_budget_stops_new_requests_and_stale_authority_blocks_delivery(self):
        with fixture() as (sender, recipient, transport):
            transport.offline.update(sender.relays)
            sender.send("req_synthetic_time_budget", [recipient.identity.key_id], "Synthetic deadline-bound delivery.")
            transport.offline.clear()
            transport.calls.clear()
            transport.clock, transport.step = [100.0], 0.6
            with patch("memory_vault_network.time.monotonic", side_effect=lambda: transport.clock[0]):
                result = sender.pump(maximum_seconds=1)
            self.assertTrue(result["budget_exhausted"], result)
            self.assertEqual(result["remaining_outbox"], 1)
            self.assertTrue(result["retryable"])
            self.assertEqual(len(transport.calls), 2)
            self.assertTrue(all(call[3] < 101 for call in transport.calls))
            self.assertFalse(any(call[2] == "/v1/messages" for call in transport.calls))
            transport.clock, transport.step = None, 0
            transport.calls.clear()
            transport.offline.add(sender.authority_url)
            later = int(time.time()) + 600
            with patch("time.time", return_value=later):
                unavailable = sender.pump(receive_limit=0)
                local = sender.client_config.vault(writing=True).handle({"op": "remember", "request_id": "req_synthetic_local_still_available",
                    "kind": "observation", "text": "Synthetic local memory remains available while authority is offline."})
            self.assertTrue(local["ok"], local)
            self.assertTrue(unavailable["retryable"])
            self.assertEqual(unavailable["remaining_outbox"], 1)
            self.assertFalse(any(call[2] == "/v1/messages" for call in transport.calls))

    def test_budget_validation_http_timeouts_and_selected_client_cli(self):
        with fixture() as (sender, recipient, transport):
            for budget in ({"maximum_messages": 17}, {"maximum_messages": True}, {"maximum_seconds": 0},
                           {"maximum_seconds": 61}, {"maximum_seconds": 0.5}, {"receive_limit": 5}):
                with self.assertRaises(MemoryError) as invalid:
                    sender.pump(**budget)
                self.assertEqual(invalid.exception.code, "network_invalid_pump_budget")
            self.assertEqual(transport.calls, [])
            output = []
            args = ["--network-config", str(sender.config_path), "--maximum-messages", "0", "--receive-limit", "0"]
            with patch.object(worker, "NetworkClient", return_value=sender), patch.object(worker, "write_response", side_effect=output.append):
                self.assertEqual(worker.main(args, client_config=sender.client_config.path), 0)
                self.assertTrue(output[-1]["ok"])
                self.assertFalse(output[-1]["result"]["worker_started"])
                self.assertEqual(worker.main(args, client_config=recipient.client_config.path), 1)
                self.assertEqual(output[-1]["error"]["code"], "network_client_config_mismatch")
            self.assertEqual(transport.calls, [])
        import httpx
        original_client, observed = httpx.Client, []
        mock = httpx.MockTransport(lambda request: observed.append(request.extensions["timeout"]) or httpx.Response(200, json={"ok": True}))
        with patch("httpx.Client", side_effect=lambda **kwargs: original_client(transport=mock, **kwargs)), patch("memory_vault_network.time.monotonic", return_value=100):
            with HTTPTransport() as http:
                http.request("http://127.0.0.1:9780", "GET", "/v1/status", deadline=100.5)
                self.assertTrue(all(value <= 0.5 for value in observed[0].values()))
                with self.assertRaises(MemoryError) as deadline:
                    http.request("http://127.0.0.1:9780", "GET", "/v1/status", deadline=100)
                self.assertEqual(deadline.exception.code, "network_budget_exhausted")
                self.assertEqual(len(observed), 1)


if __name__ == "__main__":
    unittest.main()
