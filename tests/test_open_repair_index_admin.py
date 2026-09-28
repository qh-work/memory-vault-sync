"""Actual source publication and independent owner recovery through both CLIs."""
import base64
import contextlib
import io
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from memory_vault import canonical_bytes
from memory_vault_network_crypto import b64url
import memory_vault_open_node as node_module
from memory_vault_open_repair_index_admin import main, REQUEST_SCHEMA, RECOVERY_REQUEST_SCHEMA
from memory_vault_open_repair_index_state import encode_entry
from memory_vault_trust import _write_new_private
from tests.test_open_repair_admin import _AdminFixture
from tests import test_open_repair_index_recovery as recovery_fixture


class RepairIndexAdminTests(_AdminFixture, unittest.TestCase):
    def setUp(self):
        self.live = recovery_fixture.IndexedReceiptRecoveryTests()
        self.live.setUp()
        self.addCleanup(self.live.doCleanups)
        self.c = self.live.host.c
        self.host = SimpleNamespace(source=self.c.f.h)
        self.configure_owner()
        self.owner_request = dict(schema_version=RECOVERY_REQUEST_SCHEMA,
            directory=self.c.f.directory_keys,
            directory_node=dict(raw_base64url=b64url(canonical_bytes(self.c.node)),
                ref=self.live.host.entry(canonical_bytes(self.c.node))['ref']),
            target=self.c.f.publisher, source_epoch=self.c.f.f['expected']['target_storage_epoch'],
            ack_slot=self.request['ack_slot'], root=self.request['root'], read=self.request['read'],
            bootstrap=self.request['bootstrap'], known_statuses=[],
            **{key:self.live.options['expected_'+key] for key in ('receipt_writer','message_id','envelope_ref')})
        self.owner_request_path = self.directory/'index-recovery.json'
        _write_new_private(self.owner_request_path, canonical_bytes(self.owner_request))
        # All identities are freshly generated synthetic fixtures. The source
        # config reopens its real protected HTTP database without copying it.
        source = self.c.f.f
        self.source_identity = self.directory/'source-identity.json'
        secret = source['signers']['target']._private_key.private_bytes(serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw, serialization.NoEncryption())
        _write_new_private(self.source_identity, canonical_bytes(dict(
            source['signers']['target'].public_descriptor(), schema_version='universal-memory-identity/v1',
            private_key=base64.b64encode(secret).decode())))
        self.source_encryption = self.directory/'source-encryption.json'
        source['encryption']['target'].save(self.source_encryption)
        config = dict(schema_version=node_module.NODE_CONFIG, identity_path=str(self.source_identity),
            encryption_key_path=str(self.source_encryption), state_directory=str(self.c.f.h.path.parent),
            node=source['docs']['descriptor'], seeds=[], allow_loopback=True, index_policy={},
            provider_policy=dict(enabled=True), repair_policy=dict(enabled=True,limit_policy=source['expected']['limit_policy']),
            listen_host='127.0.0.1', listen_port=self.live.source_server.server_port)
        self.source_config = self.directory/'source-node.json'
        _write_new_private(self.source_config, canonical_bytes(config))
        self.publication_request = self.directory/'publication.json'
        request = dict(schema_version=REQUEST_SCHEMA, resource_id=self.c.f.h.resource_id,
            directory=self.c.f.directory_keys, node=self.owner_request['directory_node'],
            fact=encode_entry(self.c.f.fact), intent=self.c.f.intent,
            owner_consent=encode_entry(self.c.f.consents['owner']),
            recipient_consent=encode_entry(self.c.f.consents['writer']),
            current_statuses=[encode_entry(item) for item in self.c.f.current],
            allocation=encode_entry(self.c.f.allocation))
        _write_new_private(self.publication_request, canonical_bytes(request))
        self.originals.update({path:path.read_bytes() for path in
            (self.source_config,self.source_identity,self.source_encryption,self.publication_request,self.owner_request_path)})

    def run_command(self, command, request, output):
        config_flag, config = ('--node-config',self.source_config) if command=='publish' else ('--network-config',self.network)
        stdout,stderr=io.StringIO(),io.StringIO()
        routing=node_module.RoutingTable
        with patch.object(node_module,'RoutingTable',side_effect=lambda *args,**kwargs:routing(*args,**(kwargs|dict(now=lambda:self.c.f.at)))):
            with contextlib.redirect_stdout(stdout),contextlib.redirect_stderr(stderr):
                code=main([command,config_flag,str(config),'--request',str(request),'--output',str(output),'--timeout','60'])
        return code,stdout.getvalue(),stderr.getvalue()

    def test_real_source_cli_publication_then_independent_owner_cli_receipt_read(self):
        publication=self.directory/'published.json'
        code,stdout,stderr=self.run_command('publish',self.publication_request,publication)
        self.assertEqual((code,stderr),(0,''))
        self.assertEqual(json.loads(stdout)['state'],'advertised')
        self.assertFalse(json.loads(publication.read_bytes())['independent_readback_verified'])
        code,stdout,stderr=self.run_command('recover',self.owner_request_path,self.output)
        self.assertEqual((code,stderr),(0,''))
        self.assertEqual(json.loads(stdout)['state'],'usable')
        recovered=json.loads(self.output.read_bytes())
        self.assertTrue(recovered['independent_readback_verified'])
        self.assertEqual(recovered['recipient_receipt'],encode_entry(self.c.f.case.receipt))
        self.assertEqual(recovered['source_commit'],encode_entry(self.c.f.result['commit']))
        self.assertFalse(self.vault.exists())
        self.assertEqual({path:path.read_bytes() for path in self.originals},self.originals)

    def test_existing_result_refuses_before_any_source_publication(self):
        _write_new_private(self.output,b'{"preserved":true}\n')
        before=self.c.db.execute('SELECT count(*) FROM open_repair_index_work').fetchone()[0]
        for command,request in (('publish',self.publication_request),('recover',self.owner_request_path)):
            code,stdout,stderr=self.run_command(command,request,self.output)
            self.assertEqual((code,stdout),(1,''))
            self.assertEqual(json.loads(stderr)['error'],'repair_output_exists')
        self.assertEqual(self.output.read_bytes(),b'{"preserved":true}\n')
        self.assertEqual(self.c.db.execute('SELECT count(*) FROM open_repair_index_work').fetchone()[0],before)
