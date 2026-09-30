"""Real admitted ciphertext retained only under independent message authority."""
import copy
import json
import unittest
from unittest.mock import patch

import memory_vault_open_repair_wire as wire
from tests import test_open_delivery_http as fixtures
from tests.test_open_repair_mailbox_feed_copy import FeedCopyFixture


class MailboxMessageCopyTests(unittest.TestCase):
    def test_http_upload_recovers_lost_commit_reply_and_retains_exact_body(self):
        from tests.test_open_repair_mailbox_feed_copy import MailboxFeedCopyTests
        MailboxFeedCopyTests.http_roundtrip(self,message=True,upload_only=True)

    def test_owner_reads_original_message_after_source_closes_and_replica_restarts(self):
        from tests.test_open_repair_mailbox_feed_copy import MailboxFeedCopyTests
        MailboxFeedCopyTests.http_roundtrip(self,message=True)

    def test_commands_upload_configure_and_receive_shared_memory_from_replica(self):
        from tests.test_open_repair_mailbox_feed_copy import MailboxFeedCopyTests
        MailboxFeedCopyTests.http_roundtrip(self,message=True,commands=True)

    def test_agent_receives_replica_memory_and_retains_statuses_after_source_loss(self):
        from tests.test_open_repair_mailbox_feed_copy import MailboxFeedCopyTests
        MailboxFeedCopyTests.http_roundtrip(self,message=True,commands=True,agent=True)

    def test_replica_memory_returns_independent_receipt_to_original_sender(self):
        from tests.test_open_repair_mailbox_feed_copy import MailboxFeedCopyTests
        self.with_independent_return=True
        MailboxFeedCopyTests.http_roundtrip(self,message=True,commands=True,agent=True)

    def run_fixture(self, inspect):
        fixture=fixtures.MailboxStagingHTTPTests('test_actual_delivery_stages_exact_ciphertext_under_mailbox_resources')
        fixture.setUp();self.addCleanup(fixture.doCleanups)
        fixture.ack_cold_return=True
        def receive(staging,slot,head):
            h=FeedCopyFixture(self,fixture,staging,slot,head,message=True)
            with patch('time.time',return_value=h.now):inspect(h)
        fixture.inspect_committed_mailbox=receive
        if getattr(self,'with_independent_return',False):
            fixture.test_ack_configuration_survives_mailbox_custody()
        else:
            fixture.test_actual_delivery_stages_exact_ciphertext_under_mailbox_resources()

    def verify_replica_delivery(self,h,reader,recovered,message,descriptor):
        from memory_vault import canonical_bytes
        from memory_vault_open_delivery import verify_recipient_receipt
        message_id=message['core']['message_id']
        with h.recipient_agent._network() as network:
            delivery=network._delivery()
            with patch.object(delivery,'_finish_inbox',side_effect=RuntimeError('synthetic durable import interruption')):
                with self.assertRaisesRegex(RuntimeError,'synthetic durable import interruption'):
                    delivery.receive_recovered_mailbox_replica(reader,recovered,message,target_node_entry=h.wrap(canonical_bytes(descriptor)))
            self.assertEqual(delivery._inbox(message_id)['phase'],'staged')
            original=bytes(delivery._inbox(message_id)['session']);changed=json.loads(original)
            changed['mailbox']['originals'][0]['ref']['size']+=1
            with network.participant.state.db() as db:db.execute('UPDATE open_delivery_inbox SET session=? WHERE message_id=?',(canonical_bytes(changed),message_id))
            with patch('memory_vault_open_delivery_client.NetworkClient._import_received_share',side_effect=AssertionError('invalid proof imported')):
                with self.assertRaisesRegex(Exception,'repair_ref_mismatch'):delivery._finish_inbox(message_id)
            with network.participant.state.db() as db:db.execute('UPDATE open_delivery_inbox SET session=? WHERE message_id=?',(original,message_id))
        with h.recipient_agent._network() as restarted:
            delivery=restarted._delivery()
            with patch.object(restarted.participant.transport,'request_repair',side_effect=AssertionError('offline import made network request')):
                result=delivery._finish_inbox(message_id)
                self.assertEqual(delivery._finish_inbox(message_id),result)
            self.assertEqual(result['state'],'validated_saved')
            self.assertEqual(result['content_kind'],'memory_transfer')
            self.assertEqual(result['share']['records_added'],1)
            receipt=delivery._saved_receipt(message_id)
            verify_recipient_receipt(receipt,recipient_signing_key=h.owner['signing_key'],sender_key_id=h.sender['signing_key']['key_id'],
                message_id=message_id,envelope_ref=h.envelope_ref)
            again=delivery.receive_recovered_mailbox_replica(reader,recovered,message,target_node_entry=h.wrap(canonical_bytes(descriptor)))
            self.assertEqual(again['messages'],[])
            self.assertEqual(delivery._saved_receipt(message_id),receipt)
        recalled=h.call_agent(h.recipient_agent,op='recall',query='Synthetic mailbox memory')
        self.assertTrue(any(hit['text']=='Synthetic mailbox memory: consult current evidence before reuse.' for hit in recalled['hits']))

    def test_message_bytes_and_original_custody_survive_source_loss_and_restart(self):
        def inspect(h):
            receipt=h.commit();self.assertEqual(h.commit(),receipt)
            self.assertEqual(json.loads(receipt['raw'])['payload']['original_custody_ref'],h.source_custody_ref)
            self.assertNotEqual(h.source_custody_ref,h.custody['ref'])
            self.assertEqual(h.db.execute('SELECT length(raw) FROM open_repair_copy_bodies').fetchone()[0],h.envelope_ref['size'])
            expected=h.snapshot.read(h.envelope_ref)
            h.source.db.close();h.db.close();h.connect()
            result=h.store.restore_message(h.rid,**h.context())
            self.assertEqual(result['source']['custody'].ref.as_dict(),h.source_custody_ref)
            self.assertEqual(h.store.read_local_original(h.rid,h.envelope_ref),expected)
            h.db.execute('DELETE FROM open_repair_copy_bodies');h.db.commit()
            with self.assertRaises(wire.RepairWireError):h.store.restore_message(h.rid,**h.context())
        self.run_fixture(inspect)

    def test_wrong_ciphertext_and_feed_permission_cannot_create_message_custody(self):
        def inspect(h):
            wrong=dict(raw=b'x'*h.envelope_ref['size'],ref=h.envelope_ref)
            with self.assertRaisesRegex(wire.RepairWireError,'repair_ref_mismatch'):
                h.store.commit_message(*h.args(),**h.context(),current_statuses=h.statuses,envelope_entry=wrong)
            self.assertEqual(h.db.execute('SELECT count(*) FROM open_repair_copy_commits').fetchone()[0],0)
            value=json.loads(h.disclosures['sender']['raw'])['payload'];value['kind']='mailbox.feed_copy_disclosure'
            from memory_vault import canonical_bytes
            h.disclosures['sender']=h.wrap(canonical_bytes(dict(payload=value,proof=h.signers['sender'].sign_message(value))))
            with self.assertRaises(wire.RepairWireError):h.commit()
            self.assertEqual(h.db.execute('SELECT count(*) FROM open_repair_copy_bodies').fetchone()[0],0)
        self.run_fixture(inspect)
