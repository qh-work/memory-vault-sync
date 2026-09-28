"""Separate local signers prepare a request consumed by actual HTTP commands."""
import base64
import contextlib
import io
import json
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from memory_vault import canonical_bytes
import memory_vault_open_node as node_module
from memory_vault_open_repair_index_prepare_admin import main, EXPORT_SCHEMA
from memory_vault_trust import TrustStore, _write_new_private
from tests import test_open_repair_index_admin as admin_fixture


class RepairIndexPrepareAdminTests(unittest.TestCase):
    def setUp(self):
        self.live = admin_fixture.RepairIndexAdminTests()
        self.live.setUp()
        self.addCleanup(self.live.doCleanups)
        self.directory = self.live.directory
        self.f = self.live.c.f
        self.writer_directory = self.directory/'writer'
        self.writer_directory.mkdir(mode=0o700)
        writer = self.f.f['signers']['writer']
        identity = self.writer_directory/'identity.json'
        secret = writer._private_key.private_bytes(serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw, serialization.NoEncryption())
        _write_new_private(identity, canonical_bytes(dict(writer.public_descriptor(),
            schema_version='universal-memory-identity/v1', private_key=base64.b64encode(secret).decode())))
        encryption = self.writer_directory/'encryption.json'
        self.f.f['encryption']['writer'].save(encryption)
        trust = self.writer_directory/'trust.json'
        TrustStore(trust).add(writer.public_descriptor())
        config = self.writer_directory/'client.json'
        self.writer_vault = self.writer_directory/'vault'/'memory.sqlite3'
        _write_new_private(config, canonical_bytes(dict(schema_version='memory-vault-client-config/v1',
            identity_path=str(identity), trust_path=str(trust), vault_path=str(self.writer_vault),
            capture_visible_turns=False)))
        self.writer_network = self.writer_directory/'open.json'
        _write_new_private(self.writer_network, canonical_bytes(dict(schema_version='memory-vault-open-client-config/v1',
            client_config_path=str(config), state_directory=str(self.writer_directory/'transport'),
            encryption_key_path=str(encryption), seeds=[self.f.f['docs']['descriptor']], allow_loopback=True)))
        self.expected_path = self.directory/'independent-expected.json'
        expected = dict(expected_ack_slot=self.f.slot, expected_owner=self.f.f['expected']['expected_owner'],
            expected_source=self.f.publisher, source_storage_epoch=self.f.f['expected']['target_storage_epoch'],
            expected_directory=self.f.directory_keys, directory_storage_epoch=self.f.epoch,
            **{key:self.f.case.case.expected[key] for key in
                ('expected_receipt_writer','expected_message_id','expected_envelope_ref')})
        _write_new_private(self.expected_path, canonical_bytes(expected))
        self.private_originals = {p:p.read_bytes() for p in (identity,encryption,trust,config,self.writer_network)}

    def command(self, arguments):
        stdout, stderr = io.StringIO(), io.StringIO()
        routing = node_module.RoutingTable
        with patch.object(node_module, 'RoutingTable', side_effect=lambda *a,**kw:routing(*a,**(kw|dict(now=lambda:self.f.at)))):
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                result = main([str(item) for item in arguments])
        self.assertEqual((result,stderr.getvalue()), (0,''))
        summary = json.loads(stdout.getvalue())
        self.assertFalse(summary['network_accessed'])
        self.assertFalse(summary['vault_modified'])
        return summary

    def test_export_separate_signatures_assemble_publish_and_owner_read(self):
        export_request = self.directory/'export-request.json'
        bundle = self.directory/'plan.json'
        _write_new_private(export_request, canonical_bytes(dict(schema_version=EXPORT_SCHEMA,
            resource_id=self.f.h.resource_id, directory=self.f.directory_keys,
            directory_node=self.live.owner_request['directory_node'],
            allocation_id='synthetic_cli_prepared_allocation', job_id='synthetic_cli_prepared_job',
            budget_limits=self.f.intent['budget'], windows=self.f.intent['windows'])))
        self.command(['export','--node-config',self.live.source_config,'--request',export_request,'--output',bundle])
        results = {}
        for variant,config in (('owner',self.live.network),('receipt_writer',self.writer_network)):
            results[variant] = self.directory/(variant+'-consent.json')
            self.command(['sign','--network-config',config,'--bundle',bundle,'--expected',self.expected_path,
                '--variant',variant,'--renew-source-status','--output',results[variant]])
        request = self.directory/'prepared-publication.json'
        self.command(['assemble','--bundle',bundle,'--owner-consent',results['owner'],
            '--recipient-consent',results['receipt_writer'],'--expected',self.expected_path,'--output',request])
        code,_,error = self.live.run_command('publish',request,self.directory/'prepared-published.json')
        self.assertEqual((code,error),(0,''))
        code,_,error = self.live.run_command('recover',self.live.owner_request_path,self.live.output)
        self.assertEqual((code,error),(0,''))
        recovered = json.loads(self.live.output.read_bytes())
        self.assertEqual(recovered['state'],'usable')
        self.assertTrue(recovered['independent_readback_verified'])
        self.assertFalse(self.live.vault.exists())
        self.assertFalse(self.writer_vault.exists())
        self.assertEqual({p:p.read_bytes() for p in self.private_originals},self.private_originals)
