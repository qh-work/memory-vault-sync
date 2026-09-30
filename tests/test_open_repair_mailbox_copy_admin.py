"""Existing identities run the complete root copy and recovery commands over HTTP."""
import base64
import contextlib
import hashlib
import io
import json
import stat
from types import SimpleNamespace
import unittest

from cryptography.hazmat.primitives import serialization
from memory_vault import canonical_bytes
from memory_vault_network_crypto import b64url, unb64url
from memory_vault_open_repair_admin import main
from memory_vault_open_repair_mailbox_copy_admin import UPLOAD_SCHEMA, RECOVER_SCHEMA, CONFIG_SCHEMA
from memory_vault_open_repair_mailbox_copy_state import MailboxCopyState
from memory_vault_trust import _write_new_private
from tests import test_open_repair_admin as admin_fixture
from tests import test_open_repair_mailbox_copy_upload as http_fixture


class MailboxRootCopyAdminTests(admin_fixture._AdminFixture, unittest.TestCase):
    repair_profile = 'receipt-index'

    def setUp(self):
        self.remote = http_fixture.MailboxRootCopyUploadTests()
        self.addCleanup(self.remote.doCleanups); self.remote.setUp()
        self.h = self.remote.h

    @staticmethod
    def encode(entry):
        return dict(raw_base64url=b64url(entry['raw']), ref=entry['ref'])

    def owner_config(self, role):
        original = self.h.h.host.h
        self.host = SimpleNamespace(source=SimpleNamespace(temp=original.folder, fixture=original.f))
        self.configure_owner(role)
        raw = canonical_bytes(self.remote.descriptor); digest = hashlib.sha256(raw).hexdigest()
        self.node = self.encode(dict(raw=raw, ref=dict(namespace='meta', key=digest, raw_sha256=digest, size=len(raw))))

    def upload_request(self):
        h = self.h
        self.owner_config('target')
        self.request = dict(schema_version=UPLOAD_SCHEMA, node=self.node, root_key=h.root_key,
            owner=h.owner, source=h.source.target, source_storage_epoch=h.source.node['payload']['storage_epoch'],
            target=h.target, target_storage_epoch=h.intent['target_storage_epoch'],
            originals=[self.encode(h.saved['pack'])], current_statuses=[self.encode(e) for e in h.statuses],
            **{name: self.encode(e) for name, e in dict(manifest=h.saved['manifest'], custody=h.custody,
                allocation=h.allocation, offer=h.offer, assignment=h.assignment, reservation=h.reservation,
                owner_disclosure=h.consents[0], source_disclosure=h.consents[1]).items()})

    def test_upload_command_keeps_same_commit_after_restart_and_never_replaces_output(self):
        self.upload_request()
        code, output, error = self.call('copy-upload-root')
        self.assertEqual((code, error), (0, ''))
        evidence = json.loads(self.output.read_bytes())
        self.assertEqual(evidence['state'], 'replica_committed')
        self.assertFalse(json.loads(output)['recipient_saved'])
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)
        self.remote.restart(); self.request_path = self.directory / 'retry.json'
        code, output, error = self.call('copy-upload-root')
        self.assertEqual((code, output), (1, ''))
        self.assertEqual(json.loads(error)['error'], 'repair_output_exists')
        self.assertEqual(json.loads(self.output.read_bytes()), evidence)
        self.request_path = self.directory / 'resumed.json'; self.output = self.directory / 'resumed-result.json'
        code, output, error = self.call('copy-upload-root')
        self.assertEqual((code, error), (0, ''))
        self.assertEqual(json.loads(self.output.read_bytes()), evidence)
        self.assertFalse(self.vault.exists())
        self.assertEqual({path: path.read_bytes() for path in self.originals}, self.originals)

    def test_reservation_command_requires_operator_opt_in_and_reuses_real_assignment(self):
        from memory_vault_open_repair_copy_resources import remote_copy_policy
        from tests.test_open_repair_mailbox_reservation import MailboxReservationTests
        self.owner_config('target')
        h = self.h
        material = MailboxReservationTests()
        material.configure_reservation(h)
        self.request = dict(schema_version='memory-vault-open-mailbox-root-copy-reservation-request/v1',
            node=self.node, root_key=h.root_key, owner=h.owner, source=h.source.target,
            source_storage_epoch=h.source.node['payload']['storage_epoch'], intent=material.intent,
            originals=[self.encode(h.saved['pack'])], current_statuses=[self.encode(e) for e in material.statuses],
            manifest=self.encode(h.saved['manifest']), custody=self.encode(h.custody),
            reservation=self.encode(material.reservation))
        code, output, error = self.call('copy-reserve-root')
        self.assertEqual((code, output), (1, ''))
        self.assertFalse(self.output.exists())
        self.remote.participant.repair_policy['remote_mailbox_copy'] = remote_copy_policy(dict(enabled=True))
        self.request_path = self.directory / 'enabled.json'
        code, output, error = self.call('copy-reserve-root')
        self.assertEqual((code, error), (0, ''))
        evidence = json.loads(self.output.read_bytes())
        self.assertEqual(evidence['state'], 'capacity_reserved_and_assigned')
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)
        payload = json.loads(unb64url(evidence['assignment']['raw_base64url'], maximum=65536))['payload']
        self.assertEqual(payload['operation_mask'], 70)
        self.assertEqual(payload['resource_offer_ref'], evidence['offer']['ref'])
        self.request_path = self.directory / 'retry-reservation.json'
        code, output, error = self.call('copy-reserve-root')
        self.assertEqual(json.loads(error)['error'], 'repair_output_exists')
        self.request_path = self.directory / 'restarted-reservation.json'
        self.output = self.directory / 'restarted-result.json'
        self.remote.restart()
        self.remote.participant.repair_policy['remote_mailbox_copy'] = remote_copy_policy(dict(enabled=True))
        code, output, error = self.call('copy-reserve-root')
        self.assertEqual((code, error), (0, ''))
        self.assertEqual(json.loads(self.output.read_bytes()), evidence)
        self.assertFalse(self.vault.exists())
        self.assertEqual({path: path.read_bytes() for path in self.originals}, self.originals)

    def configure_node(self, custody):
        from memory_vault_open_node import NODE_CONFIG
        h = self.h; state = h.p.state
        folder = self.remote.directory / 'synthetic-operator'; folder.mkdir(mode=0o700)
        identity = folder / 'identity.json'; encryption = folder / 'encryption.json'
        secret = state.identity._private_key.private_bytes(serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw, serialization.NoEncryption())
        _write_new_private(identity, canonical_bytes(dict(state.identity.public_descriptor(),
            schema_version='universal-memory-identity/v1', private_key=base64.b64encode(secret).decode())))
        state.encryption_identity.save(encryption)
        config = folder / 'node.json'
        _write_new_private(config, canonical_bytes(dict(schema_version=NODE_CONFIG,
            identity_path=str(identity), encryption_key_path=str(encryption), state_directory=str(self.remote.directory),
            node=self.remote.descriptor, seeds=[], allow_loopback=True, index_policy=dict(enabled=False),
            repair_policy=dict(enabled=True, limit_policy=h.source.limits),
            listen_host='127.0.0.1', listen_port=self.remote.server.server_port)))
        consents, current = h.read_permissions(custody)
        context = h.read_context(); context.pop('limit_policy')
        request = dict(schema_version=CONFIG_SCHEMA, resource_id=json.loads(custody['raw'])['payload']['resource']['resource_id'],
            context=context, consents={name: self.encode(e) for name, e in consents.items()},
            current_statuses=[self.encode(e) for e in current])
        path = folder / 'request.json'; output = folder / 'result.json'
        _write_new_private(path, canonical_bytes(request))
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(['configure-replica-root', '--node-config', str(config), '--request', str(path), '--output', str(output)])
        self.assertEqual((code, stderr.getvalue()), (0, ''))
        self.assertEqual(json.loads(stdout.getvalue())['state'], 'configured')
        self.assertFalse(json.loads(stdout.getvalue())['network_started'])

    def test_configure_and_recover_commands_keep_original_directory_after_source_loss(self):
        from memory_vault_open_client import OpenNetworkClient
        h = self.h
        store = MailboxCopyState(h.p.state); store.initialize(); custody = h.commit(store)
        self.configure_node(custody); self.owner_config('owner')
        setup = h.event['setup']['originals']
        self.request = dict(schema_version=RECOVER_SCHEMA, node=self.node, root_key=h.root_key,
            source=h.source.target, source_storage_epoch=h.source.node['payload']['storage_epoch'],
            target=h.target, maintainer=h.source.target, known_statuses=[], archive_statuses=[],
            **{name: self.encode(http_fixture.entry(setup[name])) for name in ('root', 'read', 'bootstrap')})
        h.source.db.close(); self.remote.restart()
        code, output, error = self.call('recover-replica-root')
        self.assertEqual((code, error), (0, ''))
        result = json.loads(self.output.read_bytes())
        self.assertEqual(result['state'], 'mailbox_root_replica_recovered')
        self.assertEqual(result['replica_custody'], self.encode(custody))
        originals = {e['ref']['raw_sha256']: unb64url(e['raw_base64url'], maximum=524288) for e in result['originals']}
        self.assertEqual(originals[setup['catalog'].ref.raw_sha256], setup['catalog'].raw)
        with OpenNetworkClient(self.network) as network, network.participant.state.db() as db:
            self.assertGreater(db.execute('SELECT count(*) FROM open_ack_replica_statuses').fetchone()[0], 0)
        self.assertFalse(self.vault.exists())
        self.assertFalse(json.loads(output)['recipient_saved'])
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)
        self.assertEqual({path: path.read_bytes() for path in self.originals}, self.originals)
