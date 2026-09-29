"""Independent sender/source setup over actual HTTP with synthetic identities."""
import json
import base64
import hashlib
import time
import unittest
from unittest.mock import patch

from memory_vault import MemoryError, canonical_bytes
from memory_vault_client import ClientConfig
from memory_vault_open_delivery_client import OpenDeliveryClient
from memory_vault_open_repair_bind_client import OwnerAckBindClient
from memory_vault_open_repair_client import AckOwnerRecoveryClient
from memory_vault_open_repair_remote_provision_admin import prepare_remote_source
import memory_vault_open_repair_wire as wire
from memory_vault_open_transport import OpenHTTPTransport
from memory_vault_storage import atomic_write
from memory_vault_trust import TrustStore
from tests import test_open_repair_provision as local_fixture


class RemoteProvisionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = local_fixture.ProvisionTests()
        self.fixture.setUp(); self.addCleanup(self.fixture.doCleanups)
        self.delivery, self.source, self.root = self.fixture.delivery, self.fixture.source, self.fixture.root
        self.source.stop(0)
        config = json.loads(self.source.configs[0].read_bytes())
        config['provider_policy'] = dict(enabled=True)
        config['repair_policy']['remote_setup'] = dict(enabled=True)
        atomic_write(self.source.configs[0], canonical_bytes(config), replace=True)
        self.source.start(0)
        self.options = dict(source_url=self.source.nodes[0]['payload']['base_url'],
            source_key_id=self.source.identities[0].key_id, profile='receipt-index',
            **self.fixture.request)

    def test_independent_source_selected_memory_saved_receipt_and_offline_delivery_node(self):
        TrustStore(ClientConfig.load(self.delivery.b.client_config).trust_path).add(self.delivery.ai.public_descriptor())
        memory = self.delivery.call(self.delivery.a, op='remember', request_id='req_remote_selected_memory',
            kind='observation', text='Synthetic selected memory prepared using an independent remote source.')
        selected = [memory['memory_id']]
        from memory_vault_open_client import ACK_CONNECT_SCHEMA
        from memory_vault_open_repair_remote_provision import RemoteAckSourceProvisioner
        invitation = dict(schema_version=ACK_CONNECT_SCHEMA, action='prepare',
            source_url=self.options['source_url'], source_key_id=self.options['source_key_id'],
            repair_profile=self.options['profile'], lifetime=3600,
            request_id=self.options['request_id'], recipient=self.options['recipient'],
            text=self.options['text'], memory_ids=selected)
        prepared = self.delivery.call(self.delivery.a, op='connect', invitation=invitation)
        self.assertEqual(prepared['state'], 'ack_source_prepared')
        self.assertFalse(prepared['preparation_delivery_uploaded'])
        self.assertEqual(self.delivery.stored_count(), 0)
        with patch.object(RemoteAckSourceProvisioner, 'queue_and_prepare', side_effect=AssertionError('unexpected network')):
            restored = self.delivery.call(self.delivery.a, op='connect', invitation=invitation)
        self.assertEqual(restored['state'], 'ack_source_configured')
        self.assertFalse(restored['network_accessed'])
        conflict = self.delivery.a.handle(dict(op='connect', invitation=dict(invitation, lifetime=3601)))
        self.assertFalse(conflict['ok'])
        self.assertIn('open_ack_preparation_conflict', str(conflict))
        for part in ('owner_invitation', 'recipient_invitation'):
            request = dict(schema_version=ACK_CONNECT_SCHEMA, action='export_preparation',
                request_id=self.options['request_id'], part=part)
            raw = b''
            while True:
                page = self.delivery.call(self.delivery.a, op='connect', invitation=request)
                self.assertEqual(page['offset'], len(raw))
                self.assertFalse(page['network_accessed'])
                raw += base64.b64decode(page['bundle_chunk'], validate=True)
                if page['next_cursor'] is None: break
                request['cursor'] = page['next_cursor']
            self.assertEqual(len(raw), page['total_bytes'])
            self.assertEqual(hashlib.sha256(raw).hexdigest(), page['bundle_sha256'])
            prepared[part] = json.loads(raw)

        sent = self.delivery.call(self.delivery.a, op='send', request_id=self.options['request_id'],
            recipients=[self.options['recipient']], text=self.options['text'], memory_ids=selected)
        self.assertEqual(sent['message_id'], prepared['message_id'])
        async def no_original_upload(client, message_id, budget, node=None):
            client._saved_receipt(message_id)
            return False
        with patch.object(OpenDeliveryClient, '_send_receipt', new=no_original_upload):
            received = self.delivery.call(self.delivery.b, op='receive', limit=4)
        self.assertEqual(received['errors'], [])
        self.assertEqual(received['messages'][0]['state'], 'validated_saved')
        self.assertGreater(received['messages'][0]['share']['records_added'], 0)
        self.delivery.host.stop(0)
        with self.delivery.b._network() as network:
            original = bytes(network._delivery()._inbox(prepared['message_id'])['receipt'])
        returned = self.delivery.call(self.delivery.b, op='connect', invitation=prepared['recipient_invitation'])
        self.assertEqual(returned['state'], 'retained_at_ack_source')
        self.assertEqual(returned['receipt_ref']['raw_sha256'], hashlib.sha256(original).hexdigest())
        recovered = self.delivery.call(self.delivery.a, op='connect', invitation=prepared['owner_invitation'])
        self.assertTrue(recovered['endpoint_validated'])
        self.assertFalse(recovered['acknowledgement_pending'])
        self.assertEqual(recovered['commit_ref'], returned['commit_ref'])
        with self.delivery.a._network() as network:
            row = network._delivery()._outbox(self.options['request_id'])
            self.assertEqual(bytes(row['acknowledgement']), original)
        self.assertEqual(self.delivery.host.processes, {})

    def test_existing_combined_owner_status_resumes_without_replacing_originals(self):
        from memory_vault_open_repair_remote_provision import RemoteAckSourceProvisioner
        original_step=RemoteAckSourceProvisioner._step
        def legacy_setup(client,name,make):
            result=original_step(client,name,make)
            if name=='setup':
                base=[('ack.root_authority',result['root']),('ack.read_grant',result['read']),('bootstrap.grant',result['bootstrap'])]
                original_step(client,'owner_status',lambda:client._status(base,2))
            return result
        output=self.root/'legacy-combined-source.json'
        with patch.object(RemoteAckSourceProvisioner,'_step',new=legacy_setup):
            first=prepare_remote_source(self.delivery.a.network_config,output,**self.options)
        with self.delivery.a._network() as network:
            with network.participant.state.db() as db:
                before=bytes(db.execute('SELECT steps FROM open_repair_source_provision').fetchone()[0])
        self.assertNotIn('root_status',json.loads(before))
        self.source.stop(0);self.source.start(0)
        resumed={key:value for key,value in self.options.items() if key not in ('recipient','text')}
        second=prepare_remote_source(self.delivery.a.network_config,self.root/'legacy-combined-retry.json',**resumed)
        self.assertEqual(json.loads(output.read_bytes()),json.loads((self.root/'legacy-combined-retry.json').read_bytes()))
        with self.delivery.a._network() as network:
            with network.participant.state.db() as db:
                after=bytes(db.execute('SELECT steps FROM open_repair_source_provision').fetchone()[0])
        self.assertEqual(before,after)

    def test_completed_bind_with_expired_carrier_reconciles_without_new_envelope(self):
        original_bind = OwnerAckBindClient.bind
        def shorter_bind(client, *args, **kwargs):
            return original_bind(client, *args, **dict(kwargs, timeout=10))
        output = self.root / 'remote-short-bind.json'
        with patch.object(OwnerAckBindClient, 'bind', new=shorter_bind):
            prepare_remote_source(self.delivery.a.network_config, output, **self.options)
        prepared = json.loads(output.read_bytes())
        with self.delivery.a._network() as network:
            envelope = bytes(network._delivery()._outbox(self.options['request_id'])['envelope'])
            with network.participant.state.db() as db:
                saved = json.loads(bytes(db.execute('SELECT request FROM open_repair_owner_bind_journal').fetchone()[0]))
        encoded = saved['request']['raw_base64url']
        packet = json.loads(base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)))
        delay = max(0, packet['payload']['expires_at'] - time.time() + .05)
        self.assertLessEqual(delay, 11)
        time.sleep(delay)
        resumed = {key: value for key, value in self.options.items() if key not in ('recipient', 'text')}
        retried = self.root / 'remote-reconciled.json'
        real = OpenHTTPTransport.request_repair
        def no_second_bind(transport, base, raw, **kwargs):
            self.assertNotEqual(json.loads(raw).get('payload', {}).get('kind'), 'ack.bind_request')
            return real(transport, base, raw, **kwargs)
        with patch.object(OpenHTTPTransport, 'request_repair', new=no_second_bind):
            prepare_remote_source(self.delivery.a.network_config, retried, **resumed)
        self.assertEqual(json.loads(retried.read_bytes()), prepared)
        with self.delivery.a._network() as network:
            self.assertEqual(bytes(network._delivery()._outbox(self.options['request_id'])['envelope']), envelope)

    def test_lost_setup_reply_resumes_exact_request_before_first_encryption(self):
        original = OpenHTTPTransport.request_repair
        requests = []
        def lose_first_reply(transport, base, raw, **kwargs):
            result = original(transport, base, raw, **kwargs)
            if json.loads(raw).get('payload', {}).get('kind') == 'ack.source_setup':
                requests.append(raw)
                if len(requests) == 1:
                    raise MemoryError('synthetic_lost_setup_reply')
            return result
        output = self.root / 'remote-lost-reply.json'
        with patch.object(OpenHTTPTransport, 'request_repair', new=lose_first_reply):
            with self.assertRaisesRegex(MemoryError, 'synthetic_lost_setup_reply'):
                prepare_remote_source(self.delivery.a.network_config, output, **self.options)
            self.assertFalse(output.exists())
            with self.delivery.a._network() as network:
                before = network._delivery()._outbox(self.options['request_id'])
                self.assertIsNone(before['envelope']); self.assertIsNone(before['session'])
                self.assertIsNone(before['intent']); self.assertEqual(before['upload_offset'], 0)
            self.source.stop(0); self.source.start(0)
            resumed = {key: value for key, value in self.options.items() if key not in ('recipient', 'text')}
            result = prepare_remote_source(self.delivery.a.network_config, output, **resumed)
        self.assertEqual(result['state'], 'empty')
        self.assertEqual(len(requests), 2)
        self.assertEqual(requests[0], requests[1])
        with self.delivery.a._network() as network:
            after = network._delivery()._outbox(self.options['request_id'])
            self.assertEqual(after['message_id'], before['message_id'])
            self.assertIsNotNone(after['envelope'])
            self.assertIsNone(after['intent']); self.assertEqual(after['upload_offset'], 0)
        self.assertEqual(self.delivery.stored_count(), 0)

    def test_authenticated_current_revocation_survives_rejected_prepare_and_restart(self):
        verify_current = AckOwnerRecoveryClient._current
        learned = {}
        def newer_current(client, source, roles, originals, target, budget, *args, **kwargs):
            # Fault injection is at the whole-current-status verification
            # boundary, after an actual HTTP source/proof/history recovery.
            # The replacement is independently signed by A; no authentication,
            # operation check or observer callback is mocked or bypassed.
            held = roles['current.status.ack_slot'][0]
            payload = json.loads(originals[held])['payload']
            payload['revision'] = 4
            next(row for row in payload['entries'] if row['scope_kind']=='ack_slot').update(
                status='revoked',operation_mask=2)
            raw = canonical_bytes(dict(payload=payload,proof=self.delivery.ai.sign_message(payload)))
            from memory_vault_open_repair_provision import _entry
            entry = _entry(raw)
            reference = wire.raw_ref(entry['ref'])
            changed = dict(roles)
            for role in ('current.status.ack_root','current.status.ack_read',
                         'current.status.ack_owner_bootstrap','current.status.ack_slot'):
                if roles[role]==[held]:changed[role] = [reference]
            learned.update(entry)
            return verify_current(client,source,changed,dict(originals)|{reference:raw},target,budget,*args,**kwargs)
        output = self.root / 'remote-revoked-current.json'
        with patch.object(AckOwnerRecoveryClient,'_current',new=newer_current):
            with self.assertRaisesRegex(wire.RepairWireError,'repair_authority_revoked'):
                prepare_remote_source(self.delivery.a.network_config,output,**self.options)
        self.assertFalse(output.exists())
        with self.delivery.a._network() as network:
            outbox = network._delivery()._outbox(self.options['request_id'])
            self.assertIsNone(outbox['envelope']); self.assertIsNone(outbox['session'])
            with network.participant.state.db() as db:
                rows = db.execute('SELECT reference,original FROM open_repair_remote_status_originals').fetchall()
                self.assertTrue(any(json.loads(bytes(row['reference']))==learned['ref'] and
                                    bytes(row['original'])==learned['raw'] for row in rows))
                steps = json.loads(bytes(db.execute('SELECT steps FROM open_repair_source_provision').fetchone()[0]))
                self.assertNotIn('encryption_authorized',steps)
        self.source.stop(0); self.source.start(0)
        resumed = {key:value for key,value in self.options.items() if key not in ('recipient','text')}
        # The fresh process receives no new status argument and the live source
        # still has its older active T. Retained authenticated evidence refuses
        # before any repair probe or ciphertext, instead of forgetting denial.
        with patch.object(OpenHTTPTransport,'request_repair',side_effect=AssertionError('known revocation reached network')):
            with self.assertRaisesRegex(wire.RepairWireError,'repair_authority_revoked'):
                prepare_remote_source(self.delivery.a.network_config,self.root/'remote-revoked-resume.json',**resumed)
        with self.delivery.a._network() as network:
            self.assertIsNone(network._delivery()._outbox(self.options['request_id'])['envelope'])
        self.assertEqual(self.delivery.stored_count(),0)


if __name__ == '__main__':
    unittest.main()
