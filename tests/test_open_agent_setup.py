"""Selected endpoint onboarding with real signed HTTP and existing identities."""
import json
from pathlib import Path
import time
import unittest
from unittest.mock import patch

from memory_vault import MemoryError, canonical_bytes
from memory_vault_client import ClientConfig
from memory_vault_open_agent_setup import fetch_introductions, initialize_agent
from memory_vault_open_control import issue_node, verify_node
from memory_vault_open_transport import OpenHTTPTransport
from memory_vault_trust import Identity, _write_new_private
from tests.test_open_agent import configured_agent
from tests.test_open_node import nodes


class AgentSetupTests(unittest.TestCase):
    def test_selected_origin_requires_matching_key_and_real_signed_challenge(self):
        with nodes(1) as host:
            signer = Identity.generate(host.root / 'client' / 'identity.json')
            base = host.nodes[0]['payload']['base_url']
            received = fetch_introductions(signer, [(base, host.identities[0].key_id)], allow_loopback=True)
            self.assertEqual(len(received), 1)
            self.assertEqual(verify_node(received[0])['signing_key'], host.identities[0].public_descriptor())
            with patch.object(OpenHTTPTransport, 'request', side_effect=AssertionError('unselected node challenged')):
                with self.assertRaisesRegex(MemoryError, 'open_seed_endpoint_mismatch'):
                    fetch_introductions(signer, [(base, signer.key_id)], allow_loopback=True)
            with patch.object(OpenHTTPTransport, 'request', side_effect=MemoryError('synthetic_challenge_unavailable')):
                with self.assertRaisesRegex(MemoryError, 'synthetic_challenge_unavailable'):
                    fetch_introductions(signer, [(base, host.identities[0].key_id)], allow_loopback=True)

    def test_file_setup_remains_offline_and_preserves_existing_client(self):
        with nodes(1) as host:
            agent, signer, _, _ = configured_agent(host)
            config = ClientConfig.load(agent.client_config)
            protected = [config.path, config.identity_path, config.trust_path]
            before = {path: path.read_bytes() for path in protected}
            now = int(time.time())
            public = issue_node(host.identities[0], base_url='https://synthetic.example',
                storage_epoch='synthetic_setup_epoch', roles=['directory', 'router'],
                revision=1, issued_at=now, expires_at=now + 600)
            seed = host.root / 'public-node.json'
            _write_new_private(seed, canonical_bytes(public))
            destination = host.root / 'new-agent-transport'
            with patch.object(OpenHTTPTransport, 'request_node', side_effect=AssertionError('offline setup used HTTP')):
                result = initialize_agent(agent.client_config, destination, seeds=[seed])
            self.assertFalse(result['network_accessed'])
            self.assertEqual(result['signing_key_id'], signer.key_id)
            stored = json.loads(Path(result['network_config_path']).read_bytes())
            self.assertEqual(stored['seeds'], [public])
            self.assertEqual({path: path.read_bytes() for path in protected}, before)
            self.assertFalse(config.vault_path.exists())

    def test_existing_state_or_private_origin_refuses_before_initialization(self):
        with nodes(1) as host:
            agent, signer, _, _ = configured_agent(host)
            existing = host.root / 'existing'
            existing.mkdir()
            with patch.object(OpenHTTPTransport, 'request_node', side_effect=AssertionError('invalid setup used HTTP')):
                with self.assertRaisesRegex(MemoryError, 'open_setup_directory_exists'):
                    initialize_agent(agent.client_config, existing,
                        seed_endpoints=[('https://synthetic.example', signer.key_id)])
                destination = host.root / 'never-created'
                with self.assertRaisesRegex(MemoryError, 'open_destination_rejected'):
                    initialize_agent(agent.client_config, destination,
                        seed_endpoints=[('http://127.0.0.1:8787', signer.key_id)])
            self.assertFalse(destination.exists())
            self.assertEqual(list(existing.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
