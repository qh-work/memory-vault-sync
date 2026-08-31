"""One real loopback HTTP journey with temporary, test-owned processes.

Uses native HTTPTransport, Uvicorn, an authority and two independent relay
processes. All identities and memories are synthetic. This is a same-machine
process/restart check, not TLS, physical failure-domain or real-model evidence.
"""
from __future__ import annotations

from contextlib import ExitStack
import hashlib
import http.client
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from memory_vault import canonical_bytes
from memory_vault_agent import Agent
from memory_vault_client import ClientConfig, CONFIG_SCHEMA
from memory_vault_network import HTTPTransport, NetworkClient
from memory_vault_network_control import issue_invite, issue_roster
from memory_vault_network_crypto import EncryptionIdentity, document_sha256
from memory_vault_storage import atomic_write
from memory_vault_trust import Identity, TrustStore


_SERVE = """
from pathlib import Path
import socket
import sys
import uvicorn
from memory_vault_network_control import create_authority_app
from memory_vault_relay import create_app
factory = create_authority_app if sys.argv[1] == 'authority' else create_app
app = factory(Path(sys.argv[2]))
listener = socket.socket(fileno=int(sys.argv[3]))
configuration = uvicorn.Config(app, log_level='error', access_log=False,
                               proxy_headers=False, timeout_keep_alive=1)
uvicorn.Server(configuration).run(sockets=[listener])
"""


class _LoopbackService:
    """Bind our own ephemeral socket before spawning; never adopt another PID."""

    def __init__(self, root: Path, name: str, kind: str):
        self.config = root / (name + '.json')
        self.log = root / (name + '.log')
        self.kind = kind
        self.port = 0
        self.process = None
        self.processes = []
        self.listener = self._bind()
        self.port = self.listener.getsockname()[1]
        self.url = 'http://127.0.0.1:' + str(self.port)

    def _bind(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(('127.0.0.1', self.port))
            return listener
        except BaseException:
            listener.close()
            raise

    def start(self):
        if self.process is not None:
            raise AssertionError('test service is already running')
        if self.listener is None:
            # Reclaim only the previously owned address. An occupied port is
            # a test failure, never permission to stop or contact its owner.
            self.listener = self._bind()
        environment = {key: value for key, value in os.environ.items()
                       if key.upper() not in {'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY'}}
        environment['PYTHONDONTWRITEBYTECODE'] = '1'
        try:
            with self.log.open('ab') as output:
                self.process = subprocess.Popen(
                    [sys.executable, '-B', '-c', _SERVE, self.kind, str(self.config), str(self.listener.fileno())],
                    cwd=ROOT, env=environment, stdin=subprocess.DEVNULL,
                    stdout=output, stderr=subprocess.STDOUT, pass_fds=(self.listener.fileno(),))
            self.processes.append(self.process)
        finally:
            self.listener.close()
            self.listener = None
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise AssertionError('test service exited: ' + self.log.read_text()[-4096:])
            connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=0.25)
            try:
                connection.request('GET', '/__synthetic_readiness__')
                response = connection.getresponse()
                if response.status == 404:
                    response.read(4096)
                    return
            except (OSError, http.client.HTTPException):
                pass
            finally:
                connection.close()
            time.sleep(0.025)
        raise AssertionError('test service did not become ready within 15 seconds')

    def stop(self):
        if self.listener is not None:
            self.listener.close()
            self.listener = None
        if self.process is not None:
            process, self.process = self.process, None
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


@unittest.skipUnless(os.name == 'posix', 'this explicit socket-inheritance fixture requires POSIX')
class NetworkHTTPTests(unittest.TestCase):
    def test_real_http_two_nodes_degraded_retry_and_signed_receipts(self):
        with tempfile.TemporaryDirectory(prefix='memory-network-http-synthetic-') as temporary, ExitStack() as stack:
            root = Path(temporary).resolve()
            stack.enter_context(patch.dict(os.environ, {'NO_PROXY': '127.0.0.1,localhost,::1',
                                                       'no_proxy': '127.0.0.1,localhost,::1'}))
            authority = _LoopbackService(root, 'authority', 'authority')
            stack.callback(authority.stop)
            relays = []
            for index in range(2):
                relay = _LoopbackService(root, 'relay-' + str(index), 'relay')
                stack.callback(relay.stop)
                relays.append(relay)
            issuer = Identity.generate(root / 'issuer.json')
            TrustStore(root / 'issuer-trust.json').add(issuer.public_descriptor())
            identities, encryption, configs, network_configs = [], [], [], []
            for name in ('first', 'second'):
                member = root / name
                identity = Identity.generate(member / 'identity.json')
                key = EncryptionIdentity.generate()
                key.save(member / 'encryption.json')
                identities.append(identity)
                encryption.append(key)
                config = member / 'client.json'
                atomic_write(config, canonical_bytes({'schema_version': CONFIG_SCHEMA,
                    'vault_path': str(member / 'memory.sqlite3'), 'capture_visible_turns': False,
                    'identity_path': str(member / 'identity.json'), 'trust_path': str(member / 'trust.json')}), replace=False)
                configs.append(config)
            for config in configs:
                trust = TrustStore(config.parent / 'trust.json')
                for identity in identities:
                    trust.add(identity.public_descriptor())  # Independent synthetic trust policy.
            now, network_id = int(time.time()), 'synthetic-loopback-network'
            members = [{'signing_key': identity.public_descriptor(), 'encryption_key': key.public_descriptor(),
                        'status': 'active', 'scope': ['receive', 'send']}
                       for identity, key in zip(identities, encryption)]
            roster = issue_roster(issuer, network_id=network_id, version=1, previous_sha256='0' * 64,
                                  members=members, issued_at=now, expires_at=now + 300)
            roster_path = root / 'roster.json'
            atomic_write(roster_path, canonical_bytes(roster), replace=False)
            atomic_write(authority.config, canonical_bytes({'schema_version': 'memory-vault-network-authority-config/v1',
                'network_id': network_id, 'identity_path': str(root / 'issuer.json'),
                'trust_store_path': str(root / 'issuer-trust.json'), 'roster_path': str(roster_path)}), replace=False)
            for index, relay in enumerate(relays):
                atomic_write(relay.config, canonical_bytes({'schema_version': 'memory-vault-relay-config/v1',
                    'network_id': network_id, 'issuer_public_key': issuer.public_descriptor(),
                    'roster_path': str(roster_path), 'state_directory': str(root / ('node-' + str(index))),
                    'base_url': relay.url, 'init_member_key_ids': [identities[0].key_id]}), replace=False)
            for config in configs:
                path = config.parent / 'network.json'
                atomic_write(path, canonical_bytes({'schema_version': 'memory-vault-network-client/v1',
                    'network_id': network_id, 'client_config_path': str(config),
                    'state_directory': str(config.parent / 'network-state'),
                    'encryption_key_path': str(config.parent / 'encryption.json'),
                    'issuer_public_key': issuer.public_descriptor(), 'relays': [relay.url for relay in relays],
                    'authority_url': authority.url}), replace=False)
                network_configs.append(path)
            for service in (authority, *relays):
                service.start()
            transports = [stack.enter_context(HTTPTransport()) for _ in configs]
            first, second = [Agent(config, net, transport=transport)
                             for config, net, transport in zip(configs, network_configs, transports)]
            invite = issue_invite(issuer, network_id=network_id, invite_id='synthetic-http-invite',
                candidate_signing_key=identities[1].public_descriptor(), candidate_encryption_key=encryption[1].public_descriptor(),
                scope=['receive', 'send'], handoff_sha256=hashlib.sha256(b'').hexdigest(),
                roster_sha256=document_sha256(roster), issued_at=now, expires_at=now + 3600)
            joined = second.handle({'op': 'connect', 'invitation': {'invite': invite, 'roster': roster},
                                    'request_id': 'req_synthetic_http_join'})
            self.assertTrue(joined['ok'], joined)
            self.assertEqual(joined['result']['joined_nodes'], 2, joined)
            self.assertFalse(joined['result']['degraded'], joined)
            remembered = first.handle({'op': 'remember', 'request_id': 'req_synthetic_http_memory', 'kind': 'fact',
                                      'text': 'Synthetic loopback evidence: the bronze fox remembers a green lantern.'})
            self.assertTrue(remembered['ok'], remembered)
            memory_id = remembered['result']['memory_id']
            original = ClientConfig.load(configs[0]).vault().handle({'op': 'get', 'memory_id': memory_id})['result']['record']
            baseline = {'op': 'send', 'request_id': 'req_synthetic_http_baseline', 'recipients': [identities[1].key_id],
                        'text': 'Synthetic first HTTP delivery', 'memory_ids': [memory_id]}
            self.assertEqual(first.handle(baseline)['result']['stored_nodes'], 2)
            received = second.handle({'op': 'receive'})
            self.assertTrue(received['ok'], received)
            self.assertFalse(received['result']['errors'], received)
            self.assertEqual(len(received['result']['messages']), 1, received)
            self.assertEqual(received['result']['messages'][0]['share']['admission'], 'verified', received)
            self.assertFalse(first.handle({'op': 'receive'})['result']['errors'])
            self.assertTrue(first.handle(baseline)['result']['endpoint_validated'])

            # This is a new delivery while one of our own processes is down.
            # Existing durable receipts are not proof of current availability.
            relays[1].stop()
            retry = {**baseline, 'request_id': 'req_synthetic_http_restart', 'text': 'Synthetic delivery during relay restart'}
            pending = first.handle(retry)
            self.assertTrue(pending['ok'], pending)
            self.assertEqual(pending['result']['stored_nodes'], 1, pending)
            self.assertTrue(pending['result']['degraded'], pending)
            self.assertEqual(pending['result']['state'], 'queued_local', pending)
            self.assertTrue(pending['result']['errors'], pending)
            sender = NetworkClient(network_configs[0], transport=transports[0])
            with sender.db() as connection:
                frozen = bytes(connection.execute('SELECT envelope FROM outbox WHERE request_id=?', (retry['request_id'],)).fetchone()[0])
            relays[1].start()
            resumed = first.handle(retry)
            self.assertEqual(resumed['result']['stored_nodes'], 2, resumed)
            self.assertFalse(resumed['result']['degraded'], resumed)
            self.assertFalse(resumed['result']['errors'], resumed)
            self.assertEqual(resumed['result']['message_id'], pending['result']['message_id'])
            with sender.db() as connection:
                self.assertEqual(bytes(connection.execute('SELECT envelope FROM outbox WHERE request_id=?', (retry['request_id'],)).fetchone()[0]), frozen)
                self.assertEqual(connection.execute('SELECT COUNT(*) FROM outbox').fetchone()[0], 2)
            received = second.handle({'op': 'receive'})
            self.assertFalse(received['result']['errors'], received)
            self.assertEqual([message['message_id'] for message in received['result']['messages']], [resumed['result']['message_id']])
            self.assertFalse(first.handle({'op': 'receive'})['result']['errors'])
            self.assertTrue(first.handle(retry)['result']['endpoint_validated'])
            self.assertEqual(second.handle({'op': 'receive'})['result']['messages'], [])
            restored = ClientConfig.load(configs[1]).vault().handle({'op': 'get', 'memory_id': memory_id})['result']['record']
            self.assertEqual(canonical_bytes(restored), canonical_bytes(original))
            receiver = NetworkClient(network_configs[1], transport=transports[1])
            with receiver.db() as connection:
                self.assertEqual(connection.execute('SELECT COUNT(*) FROM inbox').fetchone()[0], 2)
            for index in range(2):
                with sqlite3.connect(root / ('node-' + str(index)) / 'relay.sqlite3') as connection:
                    self.assertEqual(connection.execute('SELECT COUNT(*) FROM messages').fetchone()[0], 2)
                    self.assertEqual(connection.execute('SELECT COUNT(*) FROM receipts').fetchone()[0], 2)
            for service in (authority, *relays):
                service.stop()
                self.assertTrue(all(process.poll() is not None for process in service.processes))


if __name__ == '__main__':
    unittest.main()
