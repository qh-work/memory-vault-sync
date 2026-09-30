"""Ordinary Agent polls retain independent replica selection through restarts."""
import json
import unittest

from tests import test_open_repair_mailbox_message_copy as message_fixtures
from tests import test_open_repair_mailbox_feed_copy as feed_fixtures


class RegisteredReplicaTests(unittest.TestCase):
    def run_fixture(self, inspect):
        return message_fixtures.MailboxMessageCopyTests.run_fixture(self, inspect)

    def test_ordinary_receive_recovers_memory_once_from_registered_replica_after_source_loss(self):
        feed_fixtures.MailboxFeedCopyTests.http_roundtrip(self, message=True, commands=True, agent=True, registered=True)

    def inspect_registration(self, h, registration, configured):
        from memory_vault import canonical_bytes
        from memory_vault_open_client import MAILBOX_CONNECT_SCHEMA
        listed=h.call_agent(h.recipient_agent,op='connect',invitation=dict(schema_version=MAILBOX_CONNECT_SCHEMA,action='list_replicas'))
        self.assertEqual(listed['replicas'],[configured['receiver_id']])
        with h.recipient_agent._network() as network:
            with network.participant.state.db() as db:
                row=db.execute('SELECT body,body_sha256,last_attempt FROM open_mailbox_replica_receivers WHERE receiver_id=?',(configured['receiver_id'],)).fetchone()
                self.assertEqual(bytes(row['body']),canonical_bytes(registration));self.assertEqual(row['last_attempt'],0)
        self.assertIn('expected_envelope_ref',registration['request'])
        self.assertEqual(registration['request']['expected_sender'],h.sender)
        from dataclasses import replace
        from unittest.mock import patch
        from memory_vault_open_control import issue_node
        with h.recipient_agent._network() as network:
            from memory_vault import MemoryError
            import hashlib
            def alternate(epoch):
                value=json.loads(canonical_bytes(registration))
                signed=issue_node(h.identity,base_url=value['base_url'],storage_epoch=epoch,
                    roles=['directory','router'],revision=10,issued_at=h.now,expires_at=h.now+300)
                raw=canonical_bytes(signed);digest=hashlib.sha256(raw).hexdigest()
                value['request']['target_node_entry']=dict(raw=raw.decode('utf-8'),ref=dict(namespace='meta',key=digest,raw_sha256=digest,size=len(raw)))
                return value
            extra=network._mailbox_connect(alternate('synthetic_second_epoch'))
            with self.assertRaises(MemoryError) as refused:
                network._mailbox_connect(alternate('synthetic_third_epoch'))
            self.assertEqual(refused.exception.code,'open_mailbox_receiver_capacity')
            network._mailbox_connect(dict(schema_version=MAILBOX_CONNECT_SCHEMA,action='remove_replica',receiver_id=extra['receiver_id']))
            inspected=network._mailbox_connect(dict(schema_version=MAILBOX_CONNECT_SCHEMA,action='inspect_replica',receiver_id=configured['receiver_id']))
            self.assertFalse(inspected['network_accessed']);self.assertFalse(inspected['source_rechecked'])
            original = network.participant.transport.request_node
            def wrong_epoch(base, **options):
                reply = original(base, **options)
                current = reply.response['payload']
                forged = issue_node(h.identity, base_url=base, storage_epoch='synthetic_new_storage_epoch',
                    roles=current['roles'], revision=current['revision']+1, issued_at=h.now, expires_at=h.now+300)
                return replace(reply, response=forged)
            with patch.object(network.participant.transport,'request_node',side_effect=wrong_epoch):
                refused = network.receive(limit=1)
            self.assertEqual(refused['messages'],[])
            self.assertTrue(any(e['code']=='open_invalid_mailbox_receiver' for e in refused['errors']))

    def inspect_received_registration(self, h, registration, configured):
        from memory_vault import MemoryError, canonical_bytes
        from memory_vault_open_client import MAILBOX_CONNECT_SCHEMA
        from memory_vault_open_provider import issue_status
        from memory_vault_open_repair_status import status_scope
        from memory_vault_open_repair_wire import RepairBudget
        from tests.test_open_repair_status import status_entry
        import memory_vault_open_repair_wire as wire
        scope = status_scope(h.root,'authority',dict(authority_kind=h.parent.payload['kind'],authority_sha256=h.parent.ref.raw_sha256),h.policy,RepairBudget(h.policy))
        revoked = status_entry(issue_status(h.signers['owner'],root=h.root,revision=1000000,
            entries=[dict(scope_kind='authority',scope_id=scope,minimum_document_revision=1,status='revoked',operation_mask=8)],
            issued_at=h.now,valid_until=h.until))
        entry = dict(raw=revoked['raw'].decode('utf-8'),ref=revoked['ref'])
        changed=json.loads(canonical_bytes(registration));changed['request']['archive_statuses']=[entry,dict(raw='{}',ref=entry['ref'])]
        with h.recipient_agent._network() as network:
            with self.assertRaises(MemoryError):network._mailbox_connect(changed)
            with network.participant.state.db() as db:
                count=db.execute('SELECT count(*) FROM open_ack_replica_statuses').fetchone()[0]
                self.assertIsNotNone(db.execute('SELECT 1 FROM open_ack_replica_statuses WHERE raw=?',(revoked['raw'],)).fetchone())
            removed=network._mailbox_connect(dict(schema_version=MAILBOX_CONNECT_SCHEMA,action='remove_replica',receiver_id=configured['receiver_id']))
            self.assertEqual(removed['state'],'removed')
        with h.recipient_agent._network() as restarted:
            with restarted.participant.state.db() as db:
                self.assertEqual(db.execute('SELECT count(*) FROM open_ack_replica_statuses').fetchone()[0],count)
                self.assertEqual(db.execute('SELECT count(*) FROM open_mailbox_replica_receivers').fetchone()[0],0)
                self.assertEqual(db.execute("SELECT count(*) FROM open_delivery_inbox WHERE phase='saved'").fetchone()[0],1)



if __name__=='__main__':unittest.main()
