"""Production provisioning from actual approved delivery, without ACK fixtures."""
import asyncio
import json
import sqlite3
from unittest.mock import patch
import unittest

from memory_vault import canonical_bytes
from memory_vault_client import ClientConfig
from memory_vault_network_crypto import EncryptionIdentity
from memory_vault_open_delivery_client import OpenDeliveryClient, _DeliveryBudget
from memory_vault_open_repair_admin import recover_ack
from memory_vault_open_repair_provision import AckSourceProvisioner, decode_saved_request
from memory_vault_open_repair_provision_admin import prepare_source
from memory_vault_open_repair_state import INDEX_WORKFLOW_LIMITS
from memory_vault_open_repair_wire import RepairWireError
from memory_vault_storage import atomic_write
from memory_vault_trust import TrustStore, _write_new_private
from tests import test_open_delivery_http as delivery_fixture
from tests.test_open_node import HTTPNodes


class ProvisionTests(unittest.TestCase):
    def setUp(self):
        self.delivery=delivery_fixture.DeliveryHTTPTests();self.addCleanup(self.delivery.doCleanups);self.delivery.setUp()
        self.root=self.delivery.root
        self.source=HTTPNodes(self.root/'ack',1);self.addCleanup(self.source.close)
        self.source.stop(0)
        config=json.loads(self.source.configs[0].read_bytes())
        encryption=EncryptionIdentity.generate();key=self.root/'ack'/'encryption.json';encryption.save(key)
        config.update(encryption_key_path=str(key),repair_policy=dict(enabled=True,limit_policy=INDEX_WORKFLOW_LIMITS))
        atomic_write(self.source.configs[0],canonical_bytes(config),replace=True)
        self.source.start(0)
        _,ref=self.delivery.request_contact()
        self.assertTrue(self.delivery.decide(ref,'approved')['recipient_approved'])
        self.request=dict(request_id='req_provision_send',recipient=self.delivery.bi.key_id,text='Synthetic prepared message')

    def prepare(self, name='prepared.json', **overrides):
        path=self.root/name
        result=prepare_source(self.delivery.a.network_config,self.source.configs[0],path,**(self.request|overrides))
        self.assertEqual(result['state'],'empty')
        return json.loads(path.read_bytes())

    def test_selected_memory_freeze_resume_send_save_offline_publish_and_recover(self):
        TrustStore(ClientConfig.load(self.delivery.b.client_config).trust_path).add(self.delivery.ai.public_descriptor())
        memory=self.delivery.call(self.delivery.a,op='remember',request_id='req_provision_memory',kind='observation',
            text='Synthetic selected memory for production source preparation.')
        bundle=self.prepare(memory_ids=[memory['memory_id']],profile='receipt-index')
        self.assertEqual(self.delivery.stored_count(),0)
        self.source.stop(0);self.source.start(0)
        retry=self.prepare('resumed.json',recipient=None,text='',profile='receipt-index')
        self.assertEqual(retry,bundle)
        with self.delivery.a._network() as network:
            before=network._delivery()._outbox(self.request['request_id'])
            self.assertIsNone(before['intent']);self.assertEqual(before['upload_offset'],0)
            sent=network.send(request_id=self.request['request_id'],recipients=[self.request['recipient']],
                text=self.request['text'],memory_ids=[memory['memory_id']])
            after=network._delivery()._outbox(self.request['request_id'])
            self.assertEqual(bytes(before['envelope']),bytes(after['envelope']))
        self.assertEqual(sent['message_id'],bundle['message_id'])
        # Leave B's durable original receipt intact but disable its old route.
        async def no_old_upload(client,message_id,budget,node=None):
            client._saved_receipt(message_id)
            return False
        with patch.object(OpenDeliveryClient,'_send_receipt',new=no_old_upload):
            received=self.delivery.call(self.delivery.b,op='receive',limit=4)
        self.assertEqual(received['errors'],[])
        self.assertEqual(received['messages'][0]['state'],'validated_saved')
        self.delivery.host.stop(0)
        with self.delivery.b._network() as network:
            original=bytes(network._delivery()._inbox(bundle['message_id'])['receipt'])
            recipient=bundle['recipient_request']
            result=network.publish_saved_ack(recipient['base_url'],decode_saved_request(recipient),repair_profile=recipient['repair_profile'])
        self.assertEqual(result.source.inputs['receipt'].raw,original)
        owner_path=self.root/'owner-request.json';_write_new_private(owner_path,canonical_bytes(bundle['owner_request'])+b'\n')
        recovered=recover_ack(self.delivery.a.network_config,owner_path,self.root/'owner-result.json',phase='occupied',repair_profile='receipt-index')
        self.assertEqual(recovered['state'],'ack_occupied_source_recovered')
        self.assertEqual(self.delivery.host.processes,{})

    def test_sent_outbox_and_conflicting_request_refuse(self):
        bundle=self.prepare()
        from memory_vault import MemoryError
        with self.assertRaises(MemoryError):self.prepare('changed.json',text='Changed selection')
        sent=self.delivery.call(self.delivery.a,op='send',request_id=self.request['request_id'],
            recipients=[self.request['recipient']],text=self.request['text'])
        self.assertEqual(sent['message_id'],bundle['message_id'])
        with self.assertRaises(RepairWireError) as caught:self.prepare('unsafe.json')
        self.assertEqual(caught.exception.code,'repair_provision_already_sent')
        self.assertFalse((self.root/'unsafe.json').exists())

    def test_committed_bind_survives_local_result_interruption(self):
        original=AckSourceProvisioner._step
        def fail_result(provision,name,build):
            if name=='bound':raise RepairWireError('synthetic_result_interrupted')
            return original(provision,name,build)
        with patch.object(AckSourceProvisioner,'_step',new=fail_result),self.assertRaises(RepairWireError):
            self.prepare()
        self.assertFalse((self.root/'prepared.json').exists())
        database=self.root/'ack'/'node_0'/'transport'/'network.sqlite3'
        with sqlite3.connect(database) as db:
            before=db.execute('SELECT * FROM open_repair_ack_bindings').fetchall()
        self.assertEqual(len(before),1)
        self.source.stop(0);self.source.start(0)
        bundle=self.prepare('resumed.json',recipient=None,text='')
        with sqlite3.connect(database) as db:
            self.assertEqual(db.execute('SELECT * FROM open_repair_ack_bindings').fetchall(),before)
            self.assertEqual(db.execute('SELECT count(*) FROM open_repair_ack_resources').fetchone()[0],1)
        self.assertEqual(self.delivery.stored_count(),0)
        self.assertEqual(bundle['state'],'empty')

    def test_real_unbound_custody_precedes_encryption_and_both_interruptions_resume(self):
        encrypt=OpenDeliveryClient._encrypt_outbox
        database=self.root/'ack'/'node_0'/'transport'/'network.sqlite3'
        snapshots=[]
        def checked_source(client,row):
            with sqlite3.connect(database) as db:
                source=db.execute("SELECT status,custody,custody_ref,activation_inputs FROM open_repair_ack_resources").fetchone()
                self.assertEqual(source[0],'unbound')
                self.assertIsNotNone(source[1])
                self.assertGreater(db.execute('SELECT count(*) FROM open_repair_ack_pins').fetchone()[0],0)
                setup=json.loads(source[3])
                self.assertEqual(json.loads(setup['root']['raw'])['payload']['kind'],'ack.root_authority')
                self.assertEqual(json.loads(setup['read']['raw'])['payload']['kind'],'ack.read_grant')
            with client.participant.state.db() as db:
                plan,steps=db.execute('SELECT plan,steps FROM open_repair_source_provision WHERE request_id=?',(row['request_id'],)).fetchone()
            self.assertEqual(json.loads(plan)['plan_version'],2)
            self.assertNotIn('envelope_ref',json.loads(plan))
            self.assertEqual(json.loads(steps)['encryption_authorized']['custody_ref'],json.loads(source[2]))
            self.assertNotIn('envelope',json.loads(steps))
            snapshots.append(source)
        def before_encryption(client,row,session):
            checked_source(client,row)
            self.assertIsNone(row['envelope'])
            raise RepairWireError('synthetic_before_encryption')
        with patch.object(OpenDeliveryClient,'_encrypt_outbox',new=before_encryption),self.assertRaises(RepairWireError):
            self.prepare()
        with self.delivery.a._network() as network:
            self.assertIsNone(network._delivery()._outbox(self.request['request_id'])['envelope'])
        # A saved marker cannot bypass current source integrity on the first
        # encryption after restart. Actually remove one retained root pin.
        with sqlite3.connect(database) as db:
            pin=db.execute("SELECT * FROM open_repair_ack_pins WHERE role='ack.root_authority'").fetchone()
            self.assertIsNotNone(pin)
            db.execute("DELETE FROM open_repair_ack_pins WHERE role='ack.root_authority'")
        with patch.object(OpenDeliveryClient,'_encrypt_outbox',side_effect=AssertionError('missing source pin allowed encryption')):
            with self.assertRaises(RepairWireError):
                self.prepare('missing-pin.json',recipient=None,text='')
        self.assertFalse((self.root/'missing-pin.json').exists())
        with self.delivery.a._network() as network:
            self.assertIsNone(network._delivery()._outbox(self.request['request_id'])['envelope'])
        with sqlite3.connect(database) as db:
            db.execute('INSERT INTO open_repair_ack_pins VALUES(?,?,?,?)',pin)
        def after_encryption(client,row,session):
            checked_source(client,row)
            encrypt(client,row,session)
            raise RepairWireError('synthetic_after_encryption')
        with patch.object(OpenDeliveryClient,'_encrypt_outbox',new=after_encryption),self.assertRaises(RepairWireError):
            self.prepare('interrupted-again.json',recipient=None,text='')
        with self.delivery.a._network() as network:
            frozen=bytes(network._delivery()._outbox(self.request['request_id'])['envelope'])
        self.source.stop(0);self.source.start(0)
        bundle=self.prepare('resumed.json',recipient=None,text='')
        self.assertEqual(snapshots[0],snapshots[1])
        with self.delivery.a._network() as network:
            self.assertEqual(bytes(network._delivery()._outbox(self.request['request_id'])['envelope']),frozen)
        self.assertEqual(bundle['state'],'empty')
        self.assertEqual(self.delivery.stored_count(),0)

    def test_existing_ciphertext_without_pre_e_journal_is_not_retrofitted(self):
        with self.delivery.a._network() as network:
            delivery=network._delivery()
            digest,selected=delivery._send_input(self.request['request_id'],[self.request['recipient']],self.request['text'],[],None)
            row=delivery._prepare_outbox(self.request['request_id'],self.request['recipient'],digest,self.request['text'],selected)
            session=asyncio.run(delivery._sending_session(row['recipient'],_DeliveryBudget()))
            frozen=bytes(delivery._encrypt_outbox(row,session)['envelope'])
        with self.assertRaises(RepairWireError) as caught:self.prepare()
        self.assertEqual(caught.exception.code,'repair_provision_preexisting_envelope')
        with self.delivery.a._network() as network:
            self.assertEqual(bytes(network._delivery()._outbox(self.request['request_id'])['envelope']),frozen)
        self.assertFalse((self.root/'prepared.json').exists())
        with sqlite3.connect(self.root/'ack'/'node_0'/'transport'/'network.sqlite3') as db:
            self.assertEqual(db.execute('SELECT count(*) FROM open_repair_ack_resources').fetchone()[0],0)


if __name__=='__main__':unittest.main()
