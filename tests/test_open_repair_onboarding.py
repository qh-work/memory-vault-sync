"""New operator commands connect actual selected-memory delivery to ACK discovery."""
import base64
import json
import threading
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from memory_vault import canonical_bytes
from memory_vault_client import ClientConfig
from memory_vault_network_crypto import EncryptionIdentity
from memory_vault_open_control import issue_node
from memory_vault_open_node import OpenParticipant, OpenHTTPServer, NODE_CONFIG
from memory_vault_open_repair_admin import _entry
from memory_vault_open_repair_index_admin import publish_index, recover_index, RECOVERY_REQUEST_SCHEMA
from memory_vault_open_repair_index_prepare_admin import export_plan, sign_consent, assemble_plan, EXPORT_SCHEMA
from memory_vault_open_repair_provision import encode_original, decode_saved_request
from memory_vault_open_repair_provision_admin import prepare_source
from memory_vault_open_repair_state import INDEX_WORKFLOW_LIMITS
from memory_vault_trust import Identity, TrustStore, _write_new_private
from tests import test_open_repair_receipt as receipt_fixture


class AckOnboardingTests(unittest.TestCase):
    def setUp(self):
        self.fixture = receipt_fixture.SavedReceiptPublicationTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.delivery = self.fixture.delivery
        self.directory = self.delivery.root/'onboarding'
        self.directory.mkdir(mode=0o700)

    def write(self, name, value):
        path = self.directory/name
        _write_new_private(path,canonical_bytes(value))
        return path

    def node(self, name):
        import hashlib
        root=self.directory/name;root.mkdir(mode=0o700)
        identity=Identity(Ed25519PrivateKey.generate()); encryption=EncryptionIdentity.generate()
        server=OpenHTTPServer(('127.0.0.1',0),None)
        self.addCleanup(server.server_close)
        base='http://127.0.0.1:'+str(server.server_port)
        descriptor=issue_node(identity,base_url=base,storage_epoch='synthetic_'+name,
            roles=['directory','router'],revision=1,issued_at=2_000_000_000,expires_at=2_000_003_000)
        identity_path=root/'identity.json'
        secret=identity._private_key.private_bytes(serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,serialization.NoEncryption())
        _write_new_private(identity_path,canonical_bytes(dict(identity.public_descriptor(),
            schema_version='universal-memory-identity/v1',private_key=base64.b64encode(secret).decode())))
        encryption_path=root/'encryption.json';encryption.save(encryption_path)
        config=dict(schema_version=NODE_CONFIG,identity_path=str(identity_path),encryption_key_path=str(encryption_path),
            state_directory=str(root/'state'),node=descriptor,seeds=[],allow_loopback=True,index_policy={},
            provider_policy=dict(enabled=True),repair_policy=dict(enabled=True,limit_policy=INDEX_WORKFLOW_LIMITS),
            listen_host='127.0.0.1',listen_port=server.server_port)
        path=root/'node-config.json';_write_new_private(path,canonical_bytes(config))
        participant=OpenParticipant(identity,root/'state',seeds=[],descriptor=descriptor,encryption_identity=encryption,
            allow_loopback=True,index_policy={},provider_policy=config['provider_policy'],repair_policy=config['repair_policy'])
        server.participant=participant
        thread=threading.Thread(target=server.serve_forever,kwargs=dict(poll_interval=.02),daemon=True);thread.start()
        def stop():
            server.shutdown();server.server_close();thread.join(timeout=3);participant.close()
        self.addCleanup(stop)
        raw=canonical_bytes(descriptor);digest=hashlib.sha256(raw).hexdigest()
        return dict(path=path,base=base,node=encode_original(dict(raw=raw,
            ref=dict(namespace='meta',key=digest,raw_sha256=digest,size=len(raw)))),
            keys=dict(signing_key=identity.public_descriptor(),encryption_key=encryption.public_descriptor()),
            epoch=descriptor['payload']['storage_epoch'])

    def test_new_source_selected_memory_and_independent_directory_receipt(self):
        source,directory=self.node('source'),self.node('directory')
        TrustStore(ClientConfig.load(self.delivery.b.client_config).trust_path).add(self.delivery.ai.public_descriptor())
        remembered=self.delivery.call(self.delivery.a,op='remember',request_id='req_onboarding_memory',
            kind='observation',text='Synthetic selected memory shared by independently configured agents.')
        selected=[remembered['memory_id']]
        prepared_path=self.directory/'source-prepared.json'
        prepare_source(self.delivery.a.network_config,source['path'],prepared_path,
            request_id='req_onboarding_send',recipient=self.delivery.bi.key_id,
            text='Synthetic onboarding message',memory_ids=selected,profile='receipt-index',lifetime=1800)
        prepared=json.loads(prepared_path.read_bytes())
        self.assertEqual(prepared['state'],'empty');self.assertFalse(prepared['delivery_uploaded'])
        self.assertFalse(prepared['recipient_saved'])
        sent=self.delivery.call(self.delivery.a,op='send',request_id='req_onboarding_send',
            recipients=[self.delivery.bi.key_id],text='Synthetic onboarding message',memory_ids=selected)
        self.assertTrue(sent['storage_accepted'])
        saved_clock=patch('time.time',return_value=2_000_000_008)
        saved_clock.start();self.addCleanup(saved_clock.stop)
        received=self.delivery.call(self.delivery.b,op='receive',limit=4)
        self.assertEqual(received['errors'],[])
        message=received['messages'][0]
        self.assertEqual(message['state'],'validated_saved')
        self.assertEqual(message['content_kind'],'memory_transfer')
        self.assertGreater(message['share']['records_added'],0)
        self.delivery.host.stop(0)
        with self.delivery.b._network() as network:
            original=bytes(network._delivery()._inbox(prepared['message_id'])['receipt'])
            published=network.publish_saved_ack(source['base'],decode_saved_request(prepared['recipient_request']),
                repair_profile='receipt-index')
        self.assertEqual(published.source.inputs['receipt'].raw,original)
        owner=prepared['owner_request'];root=json.loads(_entry(owner['root'])['raw'])['payload']
        caps=dict(root['budget'],max_live_bytes=0,
            max_items=min(root['budget']['max_items'],64),
            max_meta_bytes=min(root['budget']['max_meta_bytes'],2*1024*1024))
        export_request=self.write('export.json',dict(schema_version=EXPORT_SCHEMA,resource_id=prepared['resource_id'],
            directory=directory['keys'],directory_node=directory['node'],allocation_id='synthetic_onboarding_index',
            job_id='synthetic_onboarding_publication',budget_limits=caps,windows=root['windows']))
        plan=self.directory/'plan.json';export_plan(source['path'],export_request,plan)
        with self.delivery.a._network() as network:
            owner_keys=dict(signing_key=network.identity.public_descriptor(),encryption_key=network.encryption.public_descriptor())
        expected=self.write('expected.json',dict(expected_ack_slot=owner['ack_slot'],expected_owner=owner_keys,
            expected_receipt_writer=owner['receipt_writer'],expected_message_id=owner['message_id'],
            expected_envelope_ref=owner['envelope_ref'],expected_source=source['keys'],source_storage_epoch=source['epoch'],
            expected_directory=directory['keys'],directory_storage_epoch=directory['epoch']))
        consents={}
        for variant,agent in (('owner',self.delivery.a),('receipt_writer',self.delivery.b)):
            consents[variant]=self.directory/(variant+'.json')
            sign_consent(agent.network_config,plan,expected,consents[variant],variant=variant,renew_source_status=True)
        publication_request=self.directory/'publication-request.json'
        assemble_plan(plan,consents['owner'],consents['receipt_writer'],expected,publication_request)
        publish_index(source['path'],publication_request,self.directory/'published.json')
        recovery_request=self.write('recovery-request.json',dict(schema_version=RECOVERY_REQUEST_SCHEMA,
            directory=directory['keys'],directory_node=directory['node'],target=source['keys'],source_epoch=source['epoch'],
            **{key:owner[key] for key in ('ack_slot','root','read','bootstrap','receipt_writer','message_id','envelope_ref','known_statuses')}))
        recovered_path=self.directory/'recovered.json'
        recover_index(self.delivery.a.network_config,recovery_request,recovered_path)
        recovered=json.loads(recovered_path.read_bytes())
        self.assertEqual(recovered['state'],'usable')
        self.assertEqual(_entry(recovered['recipient_receipt'])['raw'],original)
        self.assertEqual(_entry(recovered['source_commit'])['raw'],published.source.commit.raw)
        self.assertEqual(self.delivery.host.processes,{})
