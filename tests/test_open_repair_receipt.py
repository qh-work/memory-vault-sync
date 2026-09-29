"""Actual approved HTTP delivery/save followed by an independent ACK node."""
import json
import threading
import time
import tempfile
from unittest.mock import patch
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from memory_vault import canonical_bytes
from memory_vault_client import ClientConfig
from memory_vault_trust import Identity, TrustStore
from memory_vault_network_crypto import EncryptionIdentity
from memory_vault_open_delivery import envelope_ref
from memory_vault_open_delivery_client import OpenDeliveryClient
from memory_vault_open_node import OpenParticipant, OpenHTTPServer
import memory_vault_open_node as node_module
from memory_vault_open_repair_put_client import AckReceiptClient
from memory_vault_open_repair_client import AckOwnerRecoveryClient
from memory_vault_open_repair_receipt import SavedAckReceiptPublisher
import memory_vault_open_repair_wire as wire
from tests import test_open_delivery_http as delivery_fixture
from tests import open_repair_ack_fixtures as ack_fixture
from tests import open_repair_resource_fixtures as resource_fixture
from tests import test_open_repair_empty_http as empty_http
from tests.test_open_repair_empty import bound_inputs


class _LocalClockHTTPNodes(delivery_fixture.HTTPNodes):
    """Real sockets/SQLite with both services on the same explicit test clock."""
    def start(self,index):
        config=json.loads(self.configs[index].read_bytes())
        participant=OpenParticipant(self.identities[index],self.root/("node_"+str(index))/"transport",
            seeds=config["seeds"],descriptor=config["node"],allow_loopback=True,index_policy=config["index_policy"],
            contact_policy=config.get("contact_policy"),delivery_policy=config.get("delivery_policy"))
        with patch("socket.getfqdn",return_value="localhost"):
            server=OpenHTTPServer(("127.0.0.1",config["listen_port"]),participant)
        thread=threading.Thread(target=server.serve_forever,kwargs=dict(poll_interval=.02),daemon=True)
        thread.start();self.processes[index]=(server,thread,participant)

    def stop(self,index):
        entry=self.processes.pop(index,None)
        if entry:
            server,thread,participant=entry
            server.shutdown();server.server_close();thread.join(timeout=3);participant.close()


class SavedReceiptPublicationTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch("time.time",return_value=2_000_000_007))
        self.enterContext(patch.object(delivery_fixture,"HTTPNodes",_LocalClockHTTPNodes))
        routing=node_module.RoutingTable
        self.enterContext(patch.object(node_module,"RoutingTable",side_effect=lambda *args,**kwargs:routing(*args,**(kwargs|{"now":lambda:time.time()}))))
        self.delivery=delivery_fixture.DeliveryHTTPTests();self.addCleanup(self.delivery.doCleanups);self.delivery.setUp()
        with self.delivery.a._network() as network:self.a_encryption=network.encryption
        with self.delivery.b._network() as network:self.b_encryption=network.encryption
        _,reference=self.delivery.request_contact()
        self.assertTrue(self.delivery.decide(reference,"approved")["recipient_approved"])
        self.ack=None

    def _ack_before_upload(self,row):
        self.message_id=row["message_id"];self.envelope_ref=envelope_ref(bytes(row["envelope"]))
        real_fixture=ack_fixture.ack_resource_fixture
        def same_agents(**options):
            signers=[self.delivery.ai,Identity(Ed25519PrivateKey.generate()),self.delivery.bi,Identity(Ed25519PrivateKey.generate())]
            encryption=[self.a_encryption,EncryptionIdentity.generate(),self.b_encryption,EncryptionIdentity.generate()]
            with patch.object(resource_fixture,"Identity",side_effect=signers),patch.object(resource_fixture.EncryptionIdentity,"generate",side_effect=encryption):
                return real_fixture(**options)
        def real_binding(f,**options):
            return bound_inputs(f,message_id=self.message_id,envelope_ref=self.envelope_ref,**options)
        with patch.object(ack_fixture,"ack_resource_fixture",side_effect=same_agents),patch.object(empty_http,"bound_inputs",side_effect=real_binding):
            # Protected DB paths use the actual resolved local test directory,
            # never macOS's /var symlink alias or a disabled path check.
            with patch.object(tempfile,"tempdir",str(self.delivery.root)):
                self.ack=empty_http.EmptyHTTPFixture(self,proof_limit=1048576,signature_limit=1024)
        self.request=dict(message_id=self.message_id,envelope_ref=self.envelope_ref,ack_slot=self.ack.f["expected"]["expected_ack_slot"],
            owner=self.ack.f["expected"]["expected_owner"],target=self.ack.f["expected"]["expected_target"],target_node_entry=self.ack.f["entries"]["descriptor"],
            root_entry=self.ack.f["entries"]["root"],write_entry=self.ack.write,bootstrap_entry=self.ack.offer,binding_entry=self.ack.result["binding"],
            current_statuses=self.ack.expected["current_statuses"],read_until=2_000_000_550,retain_until=2_000_000_650)

    def send(self, *, memory=False):
        selected=[]
        if memory:
            TrustStore(ClientConfig.load(self.delivery.b.client_config).trust_path).add(self.delivery.ai.public_descriptor())
            remembered=self.delivery.call(self.delivery.a,op="remember",request_id="req_ack_saved_memory",kind="observation",text="Synthetic current-facts reminder for ACK integration.")
            selected=[remembered["memory_id"]]
        self.selected_memory_ids=selected
        upload=OpenDeliveryClient._upload
        async def before_upload(client,row,node,handle,budget):
            if self.ack is None:self._ack_before_upload(row)
            return await upload(client,row,node,handle,budget)
        with patch.object(OpenDeliveryClient,"_upload",new=before_upload):
            with self.delivery.a._network() as network:
                sent=network.send(request_id="req_saved_ack_send",recipients=[self.delivery.bi.key_id],
                    text="Synthetic saved ACK message",memory_ids=selected)
        self.assertTrue(sent["storage_accepted"])
        self.assertEqual(sent["message_id"],self.message_id)

    def save_without_old_receipt_upload(self):
        self.ack.source.now[0]=2_000_000_008
        self.enterContext(patch("time.time",return_value=2_000_000_008))
        async def receipt_only(client,message_id,budget,node=None):
            client._saved_receipt(message_id)
        with patch.object(OpenDeliveryClient,"_send_receipt",new=receipt_only):
            received=self.delivery.call(self.delivery.b,op="receive",limit=4)
        self.assertEqual(received["errors"],[])
        self.assertEqual(received["messages"][0]["state"],"validated_saved")
        self.delivery.host.stop(0)
        return received

    def publisher(self):
        network=self.enterContext(self.delivery.b._network())
        client=AckReceiptClient(self.delivery.bi,self.b_encryption,limit_policy=self.ack.f["expected"]["limit_policy"],
            allow_loopback=True,clock=lambda:self.ack.source.now[0])
        self.addCleanup(client.close)
        return SavedAckReceiptPublisher(network._delivery(),client)

    def test_saved_message_original_receipt_uploads_with_delivery_node_offline_and_restarts(self):
        self.send();self.save_without_old_receipt_upload();publisher=self.publisher()
        saved=publisher.delivery._inbox(self.message_id)
        self.assertEqual(saved["receipt_sent"],0)
        original=bytes(saved["receipt"])
        with patch.object(publisher.delivery,"_saved_receipt",wraps=publisher.delivery._saved_receipt) as actual:
            result=publisher.publish_saved(self.ack.http.base,self.request)
            self.assertEqual(actual.call_count,1)
        self.assertFalse(result.from_local_history)
        self.assertEqual(result.source.inputs["receipt"].raw,original)
        self.assertEqual(result.source.inputs["receipt"].payload["envelope_ref"],self.envelope_ref)
        self.assertEqual(result.source.inputs["disclosure"].payload["bootstrap_return"]["roles"],
            ["ack.disclosure","ack.put","authority.status.disclosure","recipient.receipt"])
        row=self.ack.source.db.execute("""SELECT o.raw FROM open_repair_ack_objects o JOIN open_repair_ack_pins p
            ON p.namespace=o.namespace AND p.opaque_key=o.opaque_key WHERE p.role='occupied:recipient.receipt'""").fetchone()
        self.assertEqual(bytes(row[0]),original)
        # New publisher instance reads actual retained B originals and verifies
        # the complete saved historical result without asking an offline node.
        other=self.publisher()
        with patch.object(other.client,"put",side_effect=AssertionError("completed local retry accessed network")):
            retry=other.publish_saved(self.ack.http.base,self.request)
        self.assertTrue(retry.from_local_history)
        self.assertEqual(retry.source.commit.raw,result.source.commit.raw)
        self.ack.http.restart()
        f=self.ack.f
        owner=AckOwnerRecoveryClient(self.delivery.ai,self.a_encryption,policy=self.ack.source.state.policy,
            limit_policy=f["expected"]["limit_policy"],allow_loopback=True,clock=lambda:self.ack.source.now[0])
        self.addCleanup(owner.close)
        recovered=owner.recover_occupied(self.ack.http.base,target_node_entry=f["entries"]["descriptor"],
            expected_target=f["expected"]["expected_target"],expected_ack_slot=f["expected"]["expected_ack_slot"],
            root_entry=f["entries"]["root"],read_entry=f["entries"]["read"],bootstrap_entry=f["entries"]["bootstrap"],
            expected_receipt_writer=self.ack.expected["expected_receipt_writer"],expected_message_id=self.message_id,
            expected_envelope_ref=self.envelope_ref)
        self.assertEqual(recovered.source.inputs["receipt"].raw,original)
        self.assertEqual(recovered.source.commit.raw,result.source.commit.raw)
        self.assertEqual(self.delivery.host.processes,{})

    def test_approved_selected_memory_is_actually_saved_before_original_receipt_publication(self):
        self.send(memory=True);received=self.save_without_old_receipt_upload()
        self.assertEqual(received["messages"][0]["content_kind"],"memory_transfer")
        self.assertGreater(received["messages"][0]["share"]["records_added"],0)
        from memory_vault_open_client import ACK_CONNECT_SCHEMA
        from memory_vault_open_transport import OpenHTTPTransport
        def encoded(entry):return dict(raw=entry['raw'].decode('utf-8'),ref=entry['ref'])
        request={name:(encoded(value) if name.endswith('_entry') else [encoded(v) for v in value] if name=='current_statuses' else value)
            for name,value in self.request.items()}
        invitation=dict(schema_version=ACK_CONNECT_SCHEMA,action='return_receipt',base_url=self.ack.http.base,repair_profile='receipt',request=request)
        returned=self.delivery.call(self.delivery.b,op='connect',invitation=invitation)
        self.assertEqual(returned['state'],'retained_at_ack_source');self.assertFalse(returned['from_local_history'])
        with patch.object(OpenHTTPTransport,'request_repair',side_effect=AssertionError('completed return contacted source')):
            retry=self.delivery.call(self.delivery.b,op='connect',invitation=invitation)
        self.assertTrue(retry['from_local_history']);self.assertFalse(retry['network_accessed'])
        self.assertEqual(retry['commit_ref'],returned['commit_ref'])
        self.ack.http.restart();f=self.ack.f
        owner_request=dict(target_node_entry=encoded(f['entries']['descriptor']),expected_target=f['expected']['expected_target'],
            expected_ack_slot=f['expected']['expected_ack_slot'],root_entry=encoded(f['entries']['root']),read_entry=encoded(f['entries']['read']),
            bootstrap_entry=encoded(f['entries']['bootstrap']),expected_receipt_writer=self.ack.expected['expected_receipt_writer'],
            expected_message_id=self.message_id,expected_envelope_ref=self.envelope_ref)
        bad_request=dict(owner_request,root_entry=dict(owner_request['root_entry'],raw=owner_request['root_entry']['raw']+' '))
        with patch.object(OpenHTTPTransport,'request_repair',side_effect=AssertionError('invalid recovery invitation contacted source')):
            rejected=self.delivery.a.handle(dict(op='connect',invitation=dict(schema_version=ACK_CONNECT_SCHEMA,action='recover_receipt',
                base_url=self.ack.http.base,repair_profile='receipt',request=bad_request)))
        self.assertFalse(rejected['ok'])
        with self.delivery.a._network() as network:
            with network.participant.state.db() as db:
                self.assertEqual(db.execute('SELECT count(*) FROM open_mailbox_setup_jobs').fetchone()[0],0)
        recovered=self.delivery.call(self.delivery.a,op='connect',invitation=dict(schema_version=ACK_CONNECT_SCHEMA,action='recover_receipt',
            base_url=self.ack.http.base,repair_profile='receipt',request=owner_request))
        self.assertTrue(recovered['endpoint_validated']);self.assertFalse(recovered['acknowledgement_pending'])
        self.assertEqual(recovered['commit_ref'],returned['commit_ref'])
        with self.delivery.a._network() as network:
            with network.participant.state.db() as db:
                self.assertGreater(db.execute('SELECT count(*) FROM open_mailbox_setup_statuses').fetchone()[0],0)
            stored=network.participant.state.db()
            with stored as db:
                self.assertIsNotNone(db.execute('SELECT acknowledgement FROM open_delivery_outbox WHERE message_id=?',(self.message_id,)).fetchone()[0])
        with patch.object(OpenDeliveryClient,'call',side_effect=AssertionError('acknowledged retry used original delivery node')):
            sent=self.delivery.call(self.delivery.a,op='send',request_id='req_saved_ack_send',recipients=[self.delivery.bi.key_id],
                text='Synthetic saved ACK message',memory_ids=self.selected_memory_ids)
        self.assertTrue(sent['endpoint_validated']);self.assertFalse(sent['network_accessed'])
        self.assertEqual(self.delivery.host.processes,{})

    def test_unsaved_wrong_tuple_and_unknown_request_fields_refuse_before_ack_network(self):
        self.send();publisher=self.publisher()
        with patch.object(publisher.client,"put",side_effect=AssertionError("invalid saved input uploaded")):
            with self.assertRaises(wire.RepairWireError) as caught:publisher.publish_saved(self.ack.http.base,self.request)
            self.assertEqual(caught.exception.code,"repair_receipt_not_saved")
        self.save_without_old_receipt_upload()
        with patch.object(publisher.client,"put",side_effect=AssertionError("wrong tuple uploaded")):
            for request in (self.request|{"envelope_ref":self.envelope_ref|{"key":"ff"*32}},self.request|{"saved":True}):
                with self.subTest(request_keys=sorted(request)),self.assertRaises(wire.RepairWireError):
                    publisher.publish_saved(self.ack.http.base,request)
        with publisher.delivery.participant.state.db() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM open_repair_saved_acks").fetchone()[0],0)


if __name__=="__main__":unittest.main()
