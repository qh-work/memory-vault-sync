"""Root copies retain B/S originals and an exact finite M-to-P assignment."""
import copy
import json
import unittest

from memory_vault import canonical_bytes
import memory_vault_open_repair_wire as wire
import memory_vault_open_repair_index as index
import memory_vault_open_repair_status as status
from memory_vault_open_provider import issue_status
from memory_vault_open_repair_mailbox_copy import MailboxCopyResources
from memory_vault_open_repair_mailbox_copy_authority import root_copy_inventory, verify_mailbox_root_copy
from memory_vault_open_repair_mailbox_root import verify_mailbox_root_source_event
from memory_vault_open_repair_copy_authority import disclosure_permissions
from tests import test_open_repair_mailbox_source as source_fixture
from tests import test_open_repair_state as target_fixture
from tests.open_repair_ack_fixtures import signed_entry
from tests.test_open_repair_status import status_entry


class MailboxRootCopyAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.h = source_fixture.MailboxSourceTests('test_custody_recovery_full_http_originals')
        self.h.setUp(); self.addCleanup(self.h.doCleanups)
        self.h.owner_observation(); self.h.observe()
        self.saved = self.h.source.prepare_history(self.h.resource_id, 'synthetic_observation')
        self.custody = self.h.custody()
        self.source = self.h.source.source
        self.owner = self.h.host.h.owner
        self.owner_signer = self.h.host.h.f['signers']['owner']
        self.root_key = self.h.host.h.root
        self.p = target_fixture.RepairStateTests(); self.p.setUp(); self.addCleanup(self.p.tearDown)
        self.now = max(self.source._now(), self.p.state.node['payload']['issued_at'])
        self.until = self.now + 50
        self.p.now[0] = self.now
        self.target = self.p.state.target
        self.resources = MailboxCopyResources(self.p.state); self.resources.initialize()
        budget = wire.RepairBudget(self.source.policy); resolver = self.resolver(budget)
        self.event = verify_mailbox_root_source_event(self.saved['manifest'], resolver, self.custody,
            expected_root=self.root_key, expected_owner=self.owner, expected_target=self.source.target,
            target_storage_epoch=self.source.node['payload']['storage_epoch'], limit_policy=self.source.limits,
            policy=self.source.policy, budget=budget)
        root = self.event['setup']['originals']['root']; bootstrap = self.event['setup']['originals']['bootstrap']
        scope = dict(kind='mailbox_root', root_key=self.root_key, root_authority_ref=root.ref.as_dict(),
            catalog_ref=self.event['setup']['originals']['catalog'].ref.as_dict())
        self.intent = dict(kind='resource.copy_intent', allocation_id='synthetic_mailbox_root_copy', job_id='synthetic_mailbox_root_job',
            root_key=self.root_key, caller=self.source.target, target=self.target,
            target_storage_epoch=self.p.state.node['payload']['storage_epoch'], purpose='root_replica', scope=scope,
            historical_manifest_ref=self.saved['manifest']['ref'], budget=dict(root.payload['budget'], max_live_bytes=0),
            windows={name:self.until for name in root.payload['windows']})
        digest = budget._hash(canonical_bytes(self.intent))
        self.reservation = self.sign('mailbox.copy_reservation_consent', self.owner_signer, dict(
            consent_id='synthetic_reservation', revision=1, root_authority_ref=root.ref.as_dict(),
            source_custody_ref=self.custody['ref'], historical_manifest_ref=self.saved['manifest']['ref'],
            maintainer=dict(signing_key_id=self.source.identity.key_id, encryption_key_id=self.source.encryption_identity.key_id),
            target=self.target, target_storage_epoch=self.intent['target_storage_epoch'],
            reservation_disclosure=dict(intent_sha256=digest, until=self.until)))
        self.allocation = self.sign('resource.allocate', self.source.identity, dict(request_id='synthetic_mailbox_allocate',
            target_node_key_id=self.p.state.identity.key_id, target_storage_epoch=self.intent['target_storage_epoch'],
            intent=self.intent, intent_sha256=digest))
        self.offer = self.resources.allocate(self.allocation, expected_caller=self.source.target)
        offer = json.loads(self.offer['raw'])['payload']
        self.assignment = self.sign('maintenance.assignment', self.source.identity, dict(assignment_id='synthetic_mailbox_assignment',
            job_id=self.intent['job_id'], root_key=self.root_key, parent_root_ref=root.ref.as_dict(), parent_assignment_ref=None,
            depth=2, subject=dict(signing_key_id=self.p.state.identity.key_id, encryption_key_id=self.p.state.encryption_identity.key_id),
            target_node_key_id=self.p.state.identity.key_id, target_storage_epoch=self.intent['target_storage_epoch'],
            operation_mask=70, scope=scope, resource_intent_sha256=digest, resource_offer_ref=self.offer['ref'], resource=offer['resource'],
            bootstrap_grant_refs=[bootstrap.ref.as_dict()], budget=self.intent['budget'], windows=self.intent['windows']))
        from memory_vault_open_repair_copy_prepare import CONSENT_FIELDS
        reservation = index._signed(self.reservation, self.owner['signing_key'], 'mailbox.copy_reservation_consent',
            CONSENT_FIELDS, self.source.policy, budget)
        rows = root_copy_inventory(self.event, reservation, self.source.policy, budget)
        self.consents = []
        for variant, signer in (('owner', self.owner_signer), ('source', self.source.identity)):
            originals, scopes = disclosure_permissions(rows, signer.key_id, self.root_key, self.source.policy, budget)
            self.consents.append(self.sign('mailbox.copy_disclosure', signer, dict(consent_id='synthetic_' + variant + '_disclosure',
                revision=1, variant=variant, root_key=self.root_key, assignment_ref=self.assignment['ref'],
                source_custody_ref=self.custody['ref'], historical_manifest_ref=self.saved['manifest']['ref'],
                target=self.target, target_storage_epoch=self.intent['target_storage_epoch'],
                disclosure=dict(originals=originals, status_scopes=scopes, until=self.until))))
        requirements = {}
        def add(signer, kind, scope_id, revision, mask):
            key = (signer['key_id'], kind, scope_id)
            old = requirements.get(key)
            requirements[key] = dict(scope_kind=kind, scope_id=scope_id, minimum_document_revision=revision,
                status='active', operation_mask=mask | (old['operation_mask'] if old else 0))
        for item in self.event['obligations']:
            add(item['signer'], item['kind'], item['scope_id'], item['revision'], item['bits'])
        def auth(entry, signer, mask):
            p = json.loads(entry['raw'])['payload']
            scope_id = status.status_scope(self.root_key, 'authority', dict(authority_kind=p['kind'], authority_sha256=entry['ref']['raw_sha256']), self.source.policy, budget)
            add(signer, 'authority', scope_id, p['revision'], mask)
        auth(dict(raw=root.raw, ref=root.ref.as_dict()), self.owner['signing_key'], 78)
        auth(self.reservation, self.owner['signing_key'], 4)
        for consent, keys in zip(self.consents, (self.owner, self.source.target)):
            auth(consent, keys['signing_key'], 4)
        active = self.event['setup']['anchor']['active'].payload
        add(self.source.target['signing_key'], 'resource', status.status_scope(self.root_key, 'resource', active['resource'], self.source.policy, budget), active['reservation_generation'], 4)
        add(self.source.target['signing_key'], 'assignment', status.status_scope(self.root_key, 'assignment',
            dict(assignment_kind='maintenance.assignment', assignment_sha256=self.assignment['ref']['raw_sha256']), self.source.policy, budget), 0, 70)
        self.statuses = []
        for signer in (self.owner_signer, self.source.identity):
            entries = [value for key, value in sorted(requirements.items()) if key[0] == signer.key_id]
            self.statuses.append(status_entry(issue_status(signer, root=self.root_key, revision=2, entries=entries, issued_at=self.now, valid_until=self.until)))

    def sign(self, kind, signer, fields):
        return signed_entry(dict(schema_version='memory-vault-open-repair/v1', kind=kind, signing_key=signer.public_descriptor(),
            issued_at=self.now, expires_at=self.until, **fields), signer, kind.replace('.', '_'))

    def resolver(self, budget):
        result = wire.LocalRawResolver(self.source.policy, budget)
        entry = self.saved['pack']; result.put('meta', entry['ref']['key'], entry['raw'])
        return result

    def verify(self, **changes):
        budget = wire.RepairBudget(self.source.policy)
        options = dict(expected_root=self.root_key, expected_owner=self.owner, expected_source=self.source.target,
            source_storage_epoch=self.source.node['payload']['storage_epoch'], expected_maintainer=self.source.target,
            expected_target=self.target, target_storage_epoch=self.intent['target_storage_epoch'], current_statuses=self.statuses,
            at=self.now, limit_policy=self.source.limits, policy=self.source.policy, budget=budget)
        options.update(changes)
        return verify_mailbox_root_copy(self.saved['manifest'], self.resolver(budget), self.custody,
            self.allocation, self.offer, self.assignment, self.reservation, *self.consents, **options)

    def test_root_copy_authenticates_complete_source_and_independent_consents(self):
        plan = self.verify()
        self.assertIsNone(plan.denial_code)
        self.assertEqual(plan.source['custody'].raw, self.custody['raw'])
        self.assertEqual(plan.assignment.payload['operation_mask'], 70)
        self.assertEqual(plan.read_until, self.until)

    def test_assignment_cannot_add_admission_or_another_operation_root(self):
        original = self.assignment
        for changes in (dict(operation_mask=71), dict(parent_assignment_ref=self.offer['ref'])):
            payload = json.loads(original['raw'])['payload']; payload.update(changes)
            self.assignment = signed_entry(payload, self.source.identity, 'synthetic_changed_assignment')
            with self.subTest(changes=changes), self.assertRaises(wire.RepairWireError):
                self.verify()

    def test_current_revocation_is_observed_and_cannot_be_covered_by_old_history(self):
        first = json.loads(self.statuses[0]['raw'])['payload']
        entries = copy.deepcopy(first['entries']); entries[0]['status'] = 'revoked'
        revoked = status_entry(issue_status(self.owner_signer, root=self.root_key, revision=3,
            entries=entries, issued_at=self.now, valid_until=self.until))
        observed = []
        plan = self.verify(current_statuses=[revoked, self.statuses[1]], on_observed=observed.append)
        self.assertEqual(plan.denial_code, 'repair_authority_revoked')
        self.assertIn(revoked['raw'], [value.raw for value in observed])

    def commit(self, store, statuses=None):
        budget = wire.RepairBudget(self.source.policy)
        return store.commit_root(self.saved['manifest'], self.resolver(budget), self.custody,
            self.allocation, self.offer, self.assignment, self.reservation, *self.consents,
            expected_root=self.root_key, expected_owner=self.owner, expected_source=self.source.target,
            source_storage_epoch=self.source.node['payload']['storage_epoch'], expected_maintainer=self.source.target,
            current_statuses=self.statuses if statuses is None else statuses, limit_policy=self.source.limits)

    def test_actual_root_copy_keeps_original_bytes_after_source_shutdown_and_target_restart(self):
        from memory_vault_open_repair_mailbox_copy_state import MailboxCopyState
        store = MailboxCopyState(self.p.state); store.initialize()
        receipt = self.commit(store)
        self.assertEqual(self.commit(store), receipt)
        payload = json.loads(receipt['raw'])['payload']; rid = payload['resource']['resource_id']
        self.assertEqual(payload['original_custody_ref'], self.custody['ref'])
        manifest = json.loads(store.read_local_original(rid, payload['replica_manifest_ref']))
        self.assertEqual(manifest['scope'], self.intent['scope'])
        self.assertTrue({'catalog-slot', 'slot-feed', 'head-checkpoint'} <= {edge['relation'] for edge in manifest['edges']})
        before = self.p.state.capacity.usage()
        self.source.db.close()
        self.p.db.close(); self.p.connect()
        store = MailboxCopyState(self.p.state); store.initialize()
        for entry in (*self.saved.values(), self.custody):
            self.assertEqual(store.read_local_original(rid, entry['ref']), entry['raw'])
        self.assertEqual(self.p.state.capacity.usage(), before)
        self.assertEqual(self.p.db.execute('SELECT count(*) FROM open_repair_copy_commits').fetchone()[0], 1)

    def test_failed_root_copy_rolls_back_custody_and_retains_authenticated_revocation(self):
        from memory_vault_open_repair_mailbox_copy_state import MailboxCopyState
        store = MailboxCopyState(self.p.state); store.initialize()
        self.p.db.execute("CREATE TRIGGER synthetic_root_copy_failure BEFORE INSERT ON open_repair_copy_commits BEGIN SELECT RAISE(ABORT,'synthetic interrupted copy'); END")
        self.p.db.commit()
        with self.assertRaisesRegex(Exception, 'synthetic interrupted copy'):
            self.commit(store)
        self.assertEqual(self.p.db.execute('SELECT count(*) FROM open_repair_copy_objects').fetchone()[0], 0)
        self.assertEqual(self.p.db.execute('SELECT count(*) FROM open_repair_copy_commits').fetchone()[0], 0)
        self.p.db.execute('DROP TRIGGER synthetic_root_copy_failure'); self.p.db.commit()
        entries = json.loads(self.statuses[0]['raw'])['payload']['entries']; entries[0]['status'] = 'revoked'
        revoked = status_entry(issue_status(self.owner_signer, root=self.root_key, revision=3,
            entries=entries, issued_at=self.now, valid_until=self.until))
        with self.assertRaisesRegex(wire.RepairWireError, 'repair_authority_revoked'):
            self.commit(store, [revoked, self.statuses[1]])
        self.p.db.close(); self.p.connect()
        store = MailboxCopyState(self.p.state); store.initialize()
        with self.assertRaises(wire.RepairWireError):
            self.commit(store)
        self.assertEqual(self.p.db.execute('SELECT count(*) FROM open_repair_copy_commits').fetchone()[0], 0)
