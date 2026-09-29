"""Original ciphertext and cold discovery evidence remain one exact prefix."""
import json
import unittest

from memory_vault_open_repair_mailbox_snapshot import MailboxSnapshotSource
from memory_vault_open_repair_wire import RepairWireError
from tests import test_open_delivery_http as http_fixture


class MailboxSnapshotTests(unittest.TestCase):
    def test_actual_committed_snapshot_preserves_exact_discovery_and_ciphertext(self):
        fixture = http_fixture.MailboxStagingHTTPTests('test_actual_delivery_stages_exact_ciphertext_under_mailbox_resources')
        fixture.setUp(); self.addCleanup(fixture.doCleanups)
        visited = []

        def inspect(staging, key, head):
            visited.append(True)
            source = MailboxSnapshotSource(staging)
            rid = staging.db.execute('SELECT resource_id FROM open_repair_mailbox_roots').fetchone()[0]
            options = dict(max_bytes=2_000_000, max_items=256)
            def resources():
                return [tuple(row) for row in staging.db.execute('SELECT * FROM open_repair_mailbox_resources ORDER BY resource_id')]
            before = resources()
            held = source.load(rid, key, head, **options)
            self.assertEqual(resources(), before)
            self.assertEqual(len(held.envelopes), 1)
            raw = staging.db.execute('SELECT envelope FROM open_mailbox_message_staging').fetchone()[0]
            self.assertEqual(held.read(held.envelopes[0].as_dict()), bytes(raw))
            self.assertEqual(json.loads(held.read(held.feed_manifest.as_dict()))['feed_head_ref'], head)
            self.assertEqual(json.loads(held.read(held.root_manifest.as_dict()))['root_key'], key['root_key'])
            core = next(ref for role, ref in held.parts[2].transfer if role == 'member.core')
            self.assertLessEqual(held.retain_until, json.loads(held.read(core.as_dict()))['payload']['object_until'])
            replay = source.load(rid, key, head, **options)
            self.assertEqual(dict(replay.originals), dict(held.originals))
            # Both historical verifiers can use only the compact transfer's
            # exact packs, independently of the source database and sender.
            import memory_vault_open_repair_wire as wire
            from memory_vault_open_repair_mailbox_root import verify_mailbox_root_source_event
            from memory_vault_open_repair_mailbox_activation import verify_mailbox_feed_source_event
            s = staging.source
            owner = json.loads(staging.db.execute('SELECT owner_keys FROM open_repair_mailbox_resources LIMIT 1').fetchone()[0])
            context = json.loads(raw)['payload']['context']
            sender = dict(signing_key=fixture.ai.public_descriptor(), encryption_key=context['sender_encryption_key'])
            def entry(ref):
                return dict(raw=held.read(ref.as_dict()), ref=ref.as_dict())
            def resolver(part):
                budget = wire.RepairBudget(s.policy)
                result = wire.LocalRawResolver(s.policy, budget)
                for role, ref in part.transfer:
                    if role == 'history.raw_pack':
                        self.assertEqual(result.put(ref.namespace, ref.key, held.read(ref.as_dict())).ref, ref)
                return result, budget
            self.assertEqual([part.scope['kind'] for part in held.parts], ['mailbox_root', 'mailbox_feed', 'mailbox_member'])
            self.assertFalse(set(held.envelopes) & {ref for role, ref in held.parts[0].transfer + held.parts[1].transfer})
            self.assertNotIn(held.root_manifest, {ref for role, ref in held.parts[1].transfer})
            resolved, budget = resolver(held.parts[0])
            root = verify_mailbox_root_source_event(entry(held.root_manifest), resolved, entry(held.root_custody),
                expected_root=key['root_key'], expected_owner=owner, expected_target=s.target,
                target_storage_epoch=s.node['payload']['storage_epoch'], limit_policy=s.limits, policy=s.policy, budget=budget)
            resolved, budget = resolver(held.parts[1])
            feed = verify_mailbox_feed_source_event(entry(held.feed_manifest), resolved, entry(held.feed_custody),
                expected_slot=key, expected_owner=owner, expected_sender=sender, expected_target=s.target,
                limit_policy=s.limits, policy=s.policy, budget=budget)
            self.assertEqual(feed['graph']['head']['count'], 1)
            self.assertEqual(root['custody'].payload['root_key'], key['root_key'])
            self.assertLess(len(held.transfer), len(held.originals))
            with self.assertRaisesRegex(RepairWireError, 'repair_snapshot_capacity'):
                source.load(rid, key, head, max_bytes=100, max_items=256)
            data_id = staging.db.execute('SELECT data_id FROM open_mailbox_message_staging').fetchone()[0]
            staging.db.execute("UPDATE open_repair_mailbox_resources SET status='pending' WHERE resource_id=?", (data_id,)); staging.db.commit()
            with self.assertRaisesRegex(RepairWireError, 'repair_resource_inactive'):
                source.load(rid, key, head, **options)
            staging.db.execute("UPDATE open_repair_mailbox_resources SET status='active' WHERE resource_id=?", (data_id,)); staging.db.commit()
            # A missing envelope cannot produce a metadata-only success.
            staging.db.execute("UPDATE open_mailbox_message_staging SET envelope=?", (b'corrupt',)); staging.db.commit()
            with self.assertRaisesRegex(RepairWireError, 'repair_ref_mismatch'):
                source.load(rid, key, head, **options)
            staging.db.execute('UPDATE open_mailbox_message_staging SET envelope=?', (raw,)); staging.db.commit()
            marker = staging.db.execute("SELECT name,value FROM open_repair_state WHERE name LIKE 'mailbox_feed_custody:%'").fetchone()
            staging.db.execute('DELETE FROM open_repair_state WHERE name=?', (marker[0],)); staging.db.commit()
            with self.assertRaisesRegex(RepairWireError, 'repair_storage_corrupt'):
                source.load(rid, key, head, **options)
            staging.db.execute('INSERT INTO open_repair_state VALUES(?,?)', tuple(marker)); staging.db.commit()
            self.assertEqual(dict(source.load(rid, key, head, **options).originals), dict(held.originals))
            import sqlite3
            from memory_vault_open_delivery_state import DeliveryState
            from memory_vault_open_repair_state import RepairAckState
            from memory_vault_open_repair_mailbox_resources import RepairMailboxResources
            from memory_vault_open_repair_mailbox_source import MailboxMessageStaging
            path = staging.db.execute('PRAGMA database_list').fetchone()[2]
            staging.db.close()
            db = sqlite3.connect(path); db.row_factory = sqlite3.Row; self.addCleanup(db.close)
            state = RepairAckState(db, s.identity, s.node, encryption_identity=s.encryption_identity, policy=s.policy, limit_policy=s.limits)
            restored = MailboxMessageStaging(RepairMailboxResources(state), DeliveryState(db, s.identity, s.node, enabled=True))
            restored.initialize()
            self.assertEqual(dict(MailboxSnapshotSource(restored).load(rid, key, head, **options).originals), dict(held.originals))

        fixture.inspect_committed_mailbox = inspect
        fixture.test_actual_delivery_stages_exact_ciphertext_under_mailbox_resources()
        self.assertEqual(visited, [True])
