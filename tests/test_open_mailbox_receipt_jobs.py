"""Retained independent receipt return through real ordinary Agent calls."""
import base64
import json
import unittest
import time
from unittest.mock import patch

from memory_vault import MemoryError
from memory_vault_open_client import ACK_CONNECT_SCHEMA
from memory_vault_open_transport import OpenHTTPTransport
from tests import test_open_delivery_http as fixtures


class RetainedReceiptTests(unittest.TestCase):
    def test_ordinary_receive_retries_lost_return_after_restart_and_sender_recovers(self):
        h=fixtures.MailboxStagingHTTPTests('test_cold_mailbox_returns_independent_receipt')
        h.setUp();self.addCleanup(h.doCleanups)
        h._return_cold_ack=lambda host:self.run_return(h,host)
        h.test_cold_mailbox_returns_independent_receipt()

    def run_return(self,h,host):
        write=json.loads(h.ack_configuration['ack.write_grant']['raw'])['payload']
        mid=write['message_id']
        selection=dict(schema_version=ACK_CONNECT_SCHEMA,action='register_mailbox_receipt_return',message_id=mid,
            source_url=host.nodes[0]['payload']['base_url'],source_key_id=host.identities[0].key_id,repair_profile='receipt')
        # Registration is local even when the exact message is not here yet.
        unknown=dict(selection,message_id='msg_'+'a'*64)
        with h.b._network() as network:
            with patch.object(network.participant.transport,'request_repair',side_effect=AssertionError('registration contacted source')):
                self.assertFalse(network.connect(invitation=unknown)['network_accessed'])
                self.assertFalse(network.connect(invitation=selection)['network_accessed'])
                self.assertFalse(network.connect(invitation=selection)['network_accessed'])
            with self.assertRaisesRegex(MemoryError,'open_ack_mailbox_return_conflict'):
                network.connect(invitation=dict(selection,source_url='http://127.0.0.1:1'))
        original=OpenHTTPTransport.request_repair;dropped=[];deadlines=[]
        def lose_response(transport,*args,**options):
            deadlines.append(options['deadline'])
            reply=original(transport,*args,**options)
            try:kind=json.loads(reply).get('kind')
            except (ValueError,UnicodeDecodeError):kind=None
            if kind=='ack.put_response' and not dropped:
                dropped.append(True);raise MemoryError('synthetic_lost_ack_reply')
            return reply
        started=time.monotonic()
        with patch.object(OpenHTTPTransport,'request_repair',new=lose_response):
            first=h.call(h.b,op='receive',limit=1)
        self.assertEqual(dropped,[True]);self.assertTrue(first['network_accessed'])
        self.assertTrue(deadlines);self.assertLessEqual(max(deadlines),started+31)
        self.assertTrue(any(e['code']=='synthetic_lost_ack_reply' for e in first['errors']),first)
        self.assertFalse(first.get('receipt_returns'))
        failure=h.call(h.b,op='connect',invitation=dict(schema_version=ACK_CONNECT_SCHEMA,
            action='inspect_mailbox_receipt_return',message_id=mid))
        self.assertEqual(failure['result']['code'],'synthetic_lost_ack_reply')
        # The next Agent operation reopens protected state after remote commit.
        resumed=h.call(h.b,op='receive',limit=1)
        self.assertIn('receipt_returns',resumed,resumed)
        self.assertEqual(resumed['receipt_returns'][0]['message_id'],mid)
        self.assertEqual(resumed['receipt_returns'][0]['state'],'retained_at_ack_source')
        inspect=dict(schema_version=ACK_CONNECT_SCHEMA,action='inspect_mailbox_receipt_return',message_id=mid)
        completed=h.call(h.b,op='connect',invitation=inspect)
        self.assertEqual(completed['state'],'complete');self.assertFalse(completed['source_rechecked'])
        with patch.object(OpenHTTPTransport,'request_repair',side_effect=AssertionError('completed return repeated HTTP')):
            again=h.call(h.b,op='receive',limit=1)
        self.assertFalse(again.get('receipt_returns'))
        unknown_state=h.call(h.b,op='connect',invitation=dict(inspect,message_id=unknown['message_id']))
        self.assertEqual(unknown_state['state'],'pending')
        # The actual original sender obtains B's saved receipt at the ACK node.
        chunks=[];cursor=None
        while True:
            query=dict(schema_version=ACK_CONNECT_SCHEMA,action='export_preparation',request_id=h.ack_preparation_request_id,part='owner_invitation')
            if cursor is not None:query['cursor']=cursor
            page=h.call(h.a,op='connect',invitation=query);chunks.append(base64.b64decode(page['bundle_chunk']));cursor=page['next_cursor']
            if cursor is None:break
        recovered=h.call(h.a,op='connect',invitation=json.loads(b''.join(chunks)))
        self.assertEqual(recovered['message_id'],mid)
        with h.a._network() as network:
            with network.participant.state.db() as db:
                self.assertIsNotNone(db.execute('SELECT acknowledgement FROM open_delivery_outbox WHERE message_id=?',(mid,)).fetchone()[0])
        with h.b._network() as network:
            with network.participant.state.db() as db:
                original_request=bytes(db.execute('SELECT request FROM open_mailbox_ack_returns WHERE message_id=?',(mid,)).fetchone()[0])
            network.connect(invitation=dict(schema_version=ACK_CONNECT_SCHEMA,action='remove_mailbox_receipt_return',message_id=mid))
            with network.participant.state.db() as db:
                self.assertEqual(bytes(db.execute('SELECT request FROM open_mailbox_ack_returns WHERE message_id=?',(mid,)).fetchone()[0]),original_request)
                self.assertEqual(db.execute('SELECT phase FROM open_delivery_inbox WHERE message_id=?',(mid,)).fetchone()[0],'saved')
            network.connect(invitation=selection)
        # Removing/re-registering may use verified history, but not send again.
        with patch.object(OpenHTTPTransport,'request_repair',side_effect=AssertionError('retained history repeated HTTP')):
            replay=h.call(h.b,op='receive',limit=1)
        self.assertTrue(replay['receipt_returns'][0]['from_local_history'])
        # Expired uncertain uploads stop scheduled polling instead of minting
        # another request or repeatedly consuming the normal receive budget.
        with h.b._network() as network:
            network.connect(invitation=dict(schema_version=ACK_CONNECT_SCHEMA,action='remove_mailbox_receipt_return',message_id=mid))
            network.connect(invitation=selection)
            with patch.object(network,'_ack_return_mailbox_receipt',side_effect=MemoryError('repair_reconciliation_required')):
                refused=network.receive(limit=1)
            self.assertTrue(any(e['code']=='repair_reconciliation_required' for e in refused['errors']))
            self.assertEqual(network.connect(invitation=inspect)['state'],'reconciliation_required')
            with patch.object(network,'_ack_return_mailbox_receipt',side_effect=AssertionError('terminal selection retried')):
                network.receive(limit=1)


class ReplicaReceiptReturnTests(unittest.TestCase):
    def test_registered_replica_receive_imports_memory_and_returns_independent_ack(self):
        from tests.test_open_repair_mailbox_feed_copy import MailboxFeedCopyTests
        MailboxFeedCopyTests.http_roundtrip(self,message=True,commands=True,agent=True,registered=True)

    def run_fixture(self, inspect):
        from tests.test_open_repair_mailbox_feed_copy import FeedCopyFixture
        h=fixtures.MailboxStagingHTTPTests('test_actual_delivery_stages_exact_ciphertext_under_mailbox_resources')
        h.setUp();self.addCleanup(h.doCleanups);h.ack_cold_return=True
        def receive(staging,slot,head):
            # This combined workflow uses real clocks, including the independent
            # ACK subprocess. Keep synthetic copy authority alive on slow runners;
            # original reservation and possession deadlines remain unchanged.
            replica=FeedCopyFixture(self,h,staging,slot,head,message=True,lifetime=180)
            write=json.loads(h.ack_configuration['ack.write_grant']['raw'])['payload']
            with h.b._network() as network:
                self.assertIsNone(network._delivery()._inbox(write['message_id']))
            selection=dict(schema_version=ACK_CONNECT_SCHEMA,action='register_mailbox_receipt_return',
                message_id=write['message_id'],source_url=h.ack_host.nodes[0]['payload']['base_url'],
                source_key_id=h.ack_host.identities[0].key_id,repair_profile='receipt')
            self.assertFalse(h.call(h.b,op='connect',invitation=selection)['network_accessed'])
            inspect(replica)
        def returned(host):
            write=json.loads(h.ack_configuration['ack.write_grant']['raw'])['payload'];mid=write['message_id']
            completed=h.call(h.b,op='connect',invitation=dict(schema_version=ACK_CONNECT_SCHEMA,
                action='inspect_mailbox_receipt_return',message_id=mid))
            self.assertEqual(completed['state'],'complete',completed)
            from memory_vault_open_delivery_client import OpenDeliveryClient
            changed=dict(h.ack_original_send_request,text=h.ack_original_send_request['text']+' changed')
            with patch.object(OpenHTTPTransport,'request_node',side_effect=AssertionError('changed send read ACK source')):
                refused=h.a.handle(changed)
            self.assertFalse(refused['ok']);self.assertEqual(refused['error']['code'],'network_request_id_conflict')
            with patch.object(OpenDeliveryClient,'call',side_effect=AssertionError('original delivery endpoint used')):
                recovered=h.call(h.a,**h.ack_original_send_request)
            self.assertEqual(recovered['message_id'],mid)
            self.assertEqual(recovered['state'],'validated_saved')
            self.assertEqual(recovered['ack_recovery'],'validated_saved')
            self.assertTrue(recovered['network_accessed'])
            with patch.object(OpenHTTPTransport,'request_node',side_effect=AssertionError('saved acknowledgement read source again')):
                again=h.call(h.a,**h.ack_original_send_request)
            self.assertEqual(again['state'],'validated_saved');self.assertFalse(again['network_accessed'])
            with h.a._network() as network:
                with network.participant.state.db() as db:
                    self.assertIsNotNone(db.execute('SELECT acknowledgement FROM open_delivery_outbox WHERE message_id=?',(mid,)).fetchone()[0])
        h.inspect_committed_mailbox=receive;h._return_cold_ack=returned
        h.test_ack_configuration_survives_mailbox_custody()


if __name__=='__main__':unittest.main()
