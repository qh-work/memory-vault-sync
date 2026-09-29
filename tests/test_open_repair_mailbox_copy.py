"""Mailbox data and discovery reserve separate real replacement capacity."""
import copy
import json
import unittest

from memory_vault_open_repair_mailbox_copy import MailboxCopyResources
from memory_vault_open_repair_wire import RepairWireError
from tests import test_open_repair_copy_resources as fixture


class MailboxCopyReservationTests(unittest.TestCase):
    def setUp(self):
        self.parent = fixture.CopyReservationTests('test_real_shared_reservation_and_restart_exact_retry')
        self.parent.setUp(); self.addCleanup(self.parent.doCleanups)
        self.state = self.parent.local.state
        self.resources = MailboxCopyResources(self.state); self.resources.initialize()
        self.root = dict(copy.deepcopy(self.parent.intent['root_key']), root_kind='mailbox')
        self.slot = dict(root_key=self.root, slot_id='synthetic_mailbox_copy', writer={
            'signing_key_id': self.state.identity.key_id, 'encryption_key_id': self.state.encryption_identity.key_id},
            writer_storage_epoch=self.state.node['payload']['storage_epoch'])
        # A reservation binds selectors; it does not assert that these opaque
        # references are authenticated mailbox originals or grant any upload.
        self.meta = self.parent.f['entries']['root']['ref']
        self.envelope = dict(self.meta, namespace='object')

    def intent(self, kind):
        scope = {
            'mailbox_root': dict(kind=kind, root_key=self.root, root_authority_ref=self.meta, catalog_ref=self.meta),
            'mailbox_feed': dict(kind=kind, slot_key=self.slot, slot_ref=self.meta, feed_head_ref=self.meta,
                source_custody_ref=self.meta, subtree=dict(start=0, end=1, root_ref=self.meta, parent_path_refs=[])),
            'mailbox_member': dict(kind=kind, slot_key=self.slot, attempt_ref=self.meta, envelope_ref=self.envelope,
                admission_link_ref=self.meta, source_custody_ref=self.meta),
        }[kind]
        intent = copy.deepcopy(self.parent.intent)
        intent.update(root_key=self.root, scope=scope, allocation_id='copy_' + kind, job_id='job_' + kind,
            purpose={'mailbox_root': 'root_replica', 'mailbox_feed': 'feed_replica', 'mailbox_member': 'message_replica'}[kind])
        intent['budget']['max_live_bytes'] = self.envelope['size'] if kind == 'mailbox_member' else 0
        return intent

    def allocate(self, intent):
        return self.resources.allocate(self.parent.request(intent), expected_caller=self.parent.caller)

    def test_distinct_catalog_feed_and_message_reservations_survive_restart(self):
        intents = [self.intent(kind) for kind in ('mailbox_root', 'mailbox_feed', 'mailbox_member')]
        offers = [self.allocate(intent) for intent in intents]
        ids = {json.loads(offer['raw'])['payload']['resource']['resource_id'] for offer in offers}
        self.assertEqual(len(ids), 3)
        usage = self.state.capacity.usage()
        self.assertEqual(self.state.db.execute("SELECT count(*) FROM open_capacity_reservations WHERE service='repair_copy'").fetchone()[0], 3)
        self.parent.local.db.close(); self.parent.local.connect()
        self.state = self.parent.local.state
        self.resources = MailboxCopyResources(self.state); self.resources.initialize()
        self.assertEqual([self.allocate(intent) for intent in intents], offers)
        self.assertEqual(self.state.capacity.usage(), usage)
        changed = copy.deepcopy(intents[0]); changed['job_id'] += '_changed'
        with self.assertRaisesRegex(RepairWireError, 'repair_copy_allocation_conflict'):
            self.allocate(changed)
        self.assertEqual(self.state.capacity.usage(), usage)

    def test_scope_and_live_bytes_cannot_cross_purpose(self):
        before = self.state.capacity.usage()
        for kind in ('mailbox_root', 'mailbox_feed', 'mailbox_member'):
            intent = self.intent(kind)
            intent['budget']['max_live_bytes'] = 1 if kind != 'mailbox_member' else 0
            with self.subTest(kind=kind), self.assertRaisesRegex(RepairWireError, 'repair_copy_capacity'):
                self.allocate(intent)
        mismatch = self.intent('mailbox_feed'); mismatch['purpose'] = 'message_replica'
        with self.assertRaisesRegex(RepairWireError, 'repair_copy_scope'):
            self.allocate(mismatch)
        with self.assertRaises(RepairWireError):
            self.parent.resources.allocate(self.parent.request(self.intent('mailbox_root')), expected_caller=self.parent.caller)
        with self.assertRaisesRegex(RepairWireError, 'repair_copy_scope'):
            self.allocate(self.parent.intent)
        self.assertEqual(self.state.capacity.usage(), before)

    def test_partial_or_foreign_feed_cannot_reserve_full_prefix(self):
        changes = [dict(start=1), dict(end=0), dict(end=65537), dict(parent_path_refs=[self.meta])]
        for change in changes:
            intent = self.intent('mailbox_feed'); intent['scope']['subtree'].update(change)
            with self.subTest(change=change), self.assertRaises(RepairWireError):
                self.allocate(intent)
        intent = self.intent('mailbox_member'); intent['scope']['envelope_ref']['namespace'] = 'meta'
        with self.assertRaisesRegex(RepairWireError, 'repair_copy_scope'):
            self.allocate(intent)
        self.assertEqual(self.state.db.execute('SELECT count(*) FROM open_repair_copy_resources').fetchone()[0], 0)
