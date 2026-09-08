"""Official Agent facade with the same local Vault and an explicit open profile."""
from pathlib import Path
import socket
import time
import unittest
from unittest.mock import patch

from memory_vault import MemoryError, canonical_bytes
from memory_vault_agent import Agent
from memory_vault_client import CONFIG_SCHEMA as CLIENT_SCHEMA, ClientConfig
from memory_vault_network import NetworkClient
from memory_vault_network_crypto import EncryptionIdentity
from memory_vault_open_client import CONFIG_SCHEMA as OPEN_SCHEMA, OpenNetworkClient
from memory_vault_open_transport import OpenHTTPTransport
from memory_vault_storage import atomic_write
from memory_vault_trust import Identity, TrustStore
from tests.test_open_node import nodes


def configured_agent(host):
    directory = host.root / "official_endpoint"
    identity_path = directory / "identity.json"
    identity = Identity.generate(identity_path)
    encryption = EncryptionIdentity.generate()
    encryption_path = directory / "encryption.json"
    encryption.save(encryption_path)
    trust_path = directory / "trust.json"
    TrustStore(trust_path).add(identity.public_descriptor())
    client_path, network_path = directory / "client.json", directory / "open.json"
    atomic_write(client_path, canonical_bytes({"schema_version": CLIENT_SCHEMA,
        "vault_path": str(directory / "vault" / "memory.sqlite3"), "capture_visible_turns": False,
        "identity_path": str(identity_path), "trust_path": str(trust_path)}), replace=False)
    atomic_write(network_path, canonical_bytes({"schema_version": OPEN_SCHEMA,
        "client_config_path": str(client_path), "state_directory": str(directory / "open_transport"),
        "encryption_key_path": str(encryption_path), "seeds": host.nodes[:2], "allow_loopback": True}), replace=False)
    return Agent(client_path, network_path), identity, encryption, encryption_path


class OpenAgentTests(unittest.TestCase):
    def test_agent_connect_discover_real_http_reuses_existing_identity_and_vault(self):
        with nodes(1) as host:
            agent, identity, encryption, encryption_path = configured_agent(host)
            remote = Identity.generate(host.root / "remote_contact" / "identity.json")
            contact = host.contact(remote, EncryptionIdentity.generate())
            self.assertIn("lease", host.put_only_last(remote, contact))
            saved = agent.handle({"op": "remember", "request_id": "req_open_existing_memory",
                                  "kind": "observation", "text": "Synthetic preexisting local observation."})
            self.assertTrue(saved["ok"], saved)
            config = ClientConfig.load(agent.client_config)
            before = {path: path.read_bytes() for path in (config.identity_path, encryption_path,
                                                           config.trust_path, config.vault_path)}
            with patch.object(Identity, "generate", side_effect=AssertionError("unexpected new signing identity")), \
                 patch.object(EncryptionIdentity, "generate", side_effect=AssertionError("unexpected new encryption identity")), \
                 patch.object(NetworkClient, "__init__", side_effect=AssertionError("unexpected private profile fallback")):
                with agent._network() as selected:
                    self.assertIsInstance(selected, OpenNetworkClient)
                    self.assertEqual(selected.identity.key_id, identity.key_id)
                    self.assertEqual(selected.encryption.public_descriptor(), encryption.public_descriptor())
                    self.assertEqual(selected.client_config.path, config.path)
                    self.assertEqual(selected.client_config.vault_path, config.vault_path)
                connected = agent.handle({"op": "connect"})
                self.assertTrue(connected["ok"], connected)
                self.assertEqual(connected["result"]["profile"], "open-routing-v1")
                self.assertFalse(connected["result"]["authority_required"])
                self.assertFalse(connected["result"]["open_messaging_supported"])
                discovered = agent.handle({"op": "discover", "online": True, "key_id": remote.key_id})
                self.assertTrue(discovered["ok"], discovered)
                self.assertEqual(discovered["result"]["state"], "found", discovered)
                self.assertEqual(canonical_bytes(discovered["result"]["contact"]), canonical_bytes(contact))
                self.assertTrue(discovered["result"]["network_accessed"])
                self.assertFalse(discovered["result"]["discovery_grants_access"])
                self.assertFalse(discovered["result"]["encryption_key_possession_proven"])
                self.assertNotIn("route", discovered["result"])
                self.assertLessEqual(len(canonical_bytes(discovered)), 8192)
            self.assertEqual({path: path.read_bytes() for path in before}, before)
            recalled = agent.handle({"op": "recall", "memory_id": saved["result"]["memory_id"]})
            self.assertTrue(recalled["ok"], recalled)
            self.assertEqual(recalled["result"]["hits"][0]["text"], "Synthetic preexisting local observation.")

    def test_offline_remember_recall_discovery_never_construct_network_or_generate_keys(self):
        with nodes(1) as host:
            agent, identity, encryption, encryption_path = configured_agent(host)
            host.stop(0)
            with patch.object(agent, "_network", side_effect=AssertionError("offline operation accessed network")), \
                 patch.object(OpenHTTPTransport, "request", side_effect=AssertionError("offline operation made HTTP request")), \
                 patch.object(Identity, "generate", side_effect=AssertionError("unexpected signing identity")), \
                 patch.object(EncryptionIdentity, "generate", side_effect=AssertionError("unexpected encryption identity")):
                saved = agent.handle({"op": "remember", "request_id": "req_open_offline_memory",
                                      "kind": "observation", "text": "Synthetic memory persists with every node offline."})
                self.assertTrue(saved["ok"], saved)
                recalled = agent.handle({"op": "recall", "memory_id": saved["result"]["memory_id"]})
                self.assertTrue(recalled["ok"], recalled)
                self.assertFalse(recalled["result"]["network_accessed"])
                self.assertEqual(recalled["result"]["hits"][0]["text"], "Synthetic memory persists with every node offline.")
                discovered = agent.handle({"op": "discover", "online": False})
                self.assertTrue(discovered["ok"], discovered)
                self.assertFalse(discovered["result"]["network_accessed"])
                conflict = agent.handle({"op": "discover", "online": False, "key_id": identity.key_id})
                self.assertFalse(conflict["ok"])
                self.assertEqual(conflict["error"]["code"], "invalid_client_arguments")
                malformed = agent.handle({"op": "discover", "online": True, "key_id": "not_an_identity"})
                self.assertFalse(malformed["ok"])
            self.assertFalse((agent.client_config.parent / "open_transport").exists())
            with patch.object(OpenHTTPTransport, "request", side_effect=AssertionError("offline direct client made HTTP")) as http:
                with OpenNetworkClient(agent.network_config) as direct:
                    self.assertFalse(direct.discover(online=False)["network_accessed"])
                    with self.assertRaisesRegex(MemoryError, "invalid_client_arguments"):
                        direct.discover(online=False, key_id=identity.key_id)
                http.assert_not_called()

    def test_unimplemented_mail_and_private_invitation_explicitly_refuse_without_http_or_fallback(self):
        with nodes(1) as host:
            agent, identity, encryption, encryption_path = configured_agent(host)
            host.stop(0)
            requests = [
                ({"op": "send", "request_id": "req_open_unsupported_send", "recipients": [identity.key_id],
                  "text": "Synthetic unopened message."}, "open_messaging_unsupported"),
                ({"op": "receive", "limit": 1}, "open_messaging_unsupported"),
                ({"op": "receive", "message_id": "msg_" + "a" * 64, "offset": 0}, "open_messaging_unsupported"),
                ({"op": "receive", "respond_to": "msg_" + "b" * 64}, "open_messaging_unsupported"),
                ({"op": "connect", "invitation": {"schema_version": "synthetic-private-invitation"}}, "open_private_invitation_unsupported"),
            ]
            with patch.object(OpenHTTPTransport, "request", side_effect=AssertionError("unsupported operation made HTTP request")) as http, \
                 patch.object(NetworkClient, "__init__", side_effect=AssertionError("unexpected private profile fallback")), \
                 patch.object(Identity, "generate", side_effect=AssertionError("unexpected signing identity")), \
                 patch.object(EncryptionIdentity, "generate", side_effect=AssertionError("unexpected encryption identity")):
                for request, code in requests:
                    with self.subTest(request=request["op"], code=code):
                        result = agent.handle(request)
                        self.assertFalse(result["ok"], result)
                        self.assertEqual(result["error"]["code"], code)
                http.assert_not_called()
            self.assertFalse(ClientConfig.load(agent.client_config).vault_path.exists())

    def test_actual_slow_incoming_header_is_closed_and_slot_reusable(self):
        with nodes(1) as host:
            agent, identity, encryption, encryption_path = configured_agent(host)
            port = int(host.nodes[0]["payload"]["base_url"].rsplit(":", 1)[1])
            started = time.monotonic()
            closed = False
            with socket.create_connection(("127.0.0.1", port), timeout=.5) as connection:
                connection.settimeout(.05)
                connection.sendall(b"POST /open/v1/rpc HTTP/1.1\r\nX-Synthetic-Slow: ")
                # New bytes arrive well inside the three-second idle timeout;
                # only the total request deadline should cut this off.
                while time.monotonic() - started < 4.5:
                    try:
                        connection.sendall(b"x")
                        if connection.recv(1) == b"":
                            closed = True
                            break
                    except socket.timeout:
                        pass
                    except (BrokenPipeError, ConnectionResetError):
                        closed = True
                        break
                    time.sleep(.1)
            self.assertTrue(closed, "A continuously drip-fed request exceeded the overall deadline")
            self.assertLess(time.monotonic() - started, 4.5)
            result = agent.handle({"op": "connect"})
            self.assertTrue(result["ok"], result)


if __name__ == "__main__":
    unittest.main()
