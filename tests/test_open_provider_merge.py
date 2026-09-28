"""Real authorized publications cannot clear a fork through the other store."""
import json
import unittest
from unittest.mock import patch

import memory_vault_open_provider as provider
from memory_vault_open_provider_state import ProviderState
from memory_vault_open_repair_wire import RepairWireError
from tests.test_open_repair_index_state import DirectoryFixture


class ProviderMergeTests(unittest.TestCase):
    def fixture(self, *, repair_revision=1):
        issue = provider.issue_fact
        def signed(*args, **kwargs):
            kwargs['revision'] = repair_revision
            return issue(*args, **kwargs)
        with patch.object(provider, 'issue_fact', signed):
            self.c = DirectoryFixture(self)
        c, f = self.c, self.c.f
        self.state = ProviderState(c.db, f.directory, c.node, encryption_identity=f.directory_encryption,
            enabled=True, clock=lambda:f.at, repair_lookup=c.state.lookup_candidates)
        self.state.initialize()
        owner = f.f['signers']['owner']
        intent = provider.sign_document(owner, 'root.resource.intent', issued_at=f.at, expires_at=f.at+100,
            allocation_id='synthetic_cross_store_resource', root_key=f.root, subject=f.f['expected']['expected_owner'],
            node_key_id=f.directory.key_id, storage_epoch=f.epoch, purpose='provider_index',
            budget=dict(max_live_bytes=0,max_meta_bytes=196608,max_items=2,max_requests=8,max_pending=1,
                max_replay_records=8,max_jobs=0,max_job_bytes=0), windows={name:f.at+100 for name in provider.WINDOWS})
        self.lease = self.rpc(owner, 'resource.allocate', dict(intent=intent))['lease']
        self.grant = provider.sign_document(owner, 'provider.publication.grant', issued_at=f.at, expires_at=f.at+100,
            root_key=f.root, resource=self.lease['payload']['resource'], resource_lease_sha256=provider.document_sha256(self.lease),
            publisher=f.publisher_id, ref=f.root['anchor_ref'], grant_id='synthetic_cross_store_grant', revision=1,
            operation_mask=16, maximum_fact_seconds=100)
        self.status = provider.issue_status(owner, root=f.root, revision=100, issued_at=f.at, valid_until=f.at+100,
            entries=[dict(scope_kind='authority',scope_id=provider.authority_scope(f.root,'provider.publication.grant',
                provider.document_sha256(self.grant)),minimum_document_revision=1,status='active',operation_mask=16)])

    def rpc(self, signer, action, body):
        return self.state.handle(provider.sign_rpc(signer,node=self.c.node,action=action,body=body,now=self.c.f.at))

    def legacy(self, revision, custody_id=None):
        f = self.c.f
        old = json.loads(f.fact['raw'])['payload']
        fact = provider.issue_fact(f.f['signers']['target'], ref=f.root['anchor_ref'], storage_epoch=old['storage_epoch'],
            custody_id=custody_id or old['custody_id'], revision=revision, issued_at=f.at, expires_at=f.at+90)
        return self.rpc(f.f['signers']['target'],'provider.put',dict(fact=fact,provider_node=f.f['docs']['descriptor'],
            publication_grant=self.grant,resource_lease=self.lease,owner_status=self.status,
            allocation_id=custody_id or 'synthetic_cross_store_put_'+str(revision),lease_seconds=90))

    def lookup(self, maximum_bytes=49152):
        f = self.c.f
        return self.rpc(f.f['signers']['owner'],'provider.get',dict(ref=f.root['anchor_ref'],after=None,limit=4,maximum_bytes=maximum_bytes))

    def restart(self):
        c = self.c
        c.restart()
        self.state = ProviderState(c.db,c.f.directory,c.node,encryption_identity=c.f.directory_encryption,
            enabled=True,clock=lambda:c.f.at,repair_lookup=c.state.lookup_candidates)
        self.state.initialize()

    def test_repair_then_legacy_fork_stays_denied_after_restart_and_higher_revision(self):
        self.fixture(); c = self.c
        c.stage(); c.state.accept(c.request)
        # A later application admission would exhaust this legacy resource.
        # The authenticated fork must be retained before that later check.
        c.db.execute('UPDATE open_provider_resources SET requests_used=8');c.db.commit()
        with self.assertRaisesRegex(provider.ProviderError,'provider_fact_conflict'):
            self.legacy(1)
        row = c.db.execute('SELECT status,second_record FROM open_repair_index_facts').fetchone()
        self.assertEqual(row[0],'conflict');self.assertIsNotNone(row[1])
        self.restart()
        with self.assertRaisesRegex(provider.ProviderError,'provider_fact_inactive'):
            self.legacy(2)
        with self.assertRaisesRegex(RepairWireError,'repair_index_fact_inactive'):
            c.state.accept(c.request)
        self.assertEqual(self.lookup()['entries'],[])

    def test_legacy_then_repair_fork_stays_denied_before_later_application_failure(self):
        self.fixture(); c = self.c
        self.legacy(1);c.stage()
        with patch.object(c.state,'_output_locked',side_effect=RepairWireError('synthetic_later_capacity')) as output:
            with self.assertRaisesRegex(RepairWireError,'repair_index_fact_conflict'):
                c.state.accept(c.request)
            output.assert_not_called()
        row = c.db.execute('SELECT status,second_record FROM open_provider_facts').fetchone()
        self.assertEqual(row[0],'conflict');self.assertIsNotNone(row[1])
        self.restart()
        with self.assertRaisesRegex(provider.ProviderError,'provider_fact_inactive'):
            self.legacy(2)
        with self.assertRaisesRegex(RepairWireError,'repair_index_fact_inactive'):
            c.state.accept(c.request)
        self.assertEqual(self.lookup()['entries'],[])

    def test_lower_repair_revision_cannot_replace_higher_legacy_fact(self):
        self.fixture();c = self.c
        self.legacy(2);c.stage()
        with self.assertRaisesRegex(RepairWireError,'repair_index_fact_rollback'):
            c.state.accept(c.request)
        self.assertIsNone(c.db.execute('SELECT 1 FROM open_repair_index_facts').fetchone())
        self.assertEqual(self.lookup()['entries'][0]['fact']['payload']['revision'],2)

    def test_lower_legacy_revision_cannot_replace_higher_repair_fact(self):
        self.fixture(repair_revision=2);c = self.c
        c.stage();c.state.accept(c.request)
        with self.assertRaisesRegex(provider.ProviderError,'provider_fact_rollback'):
            self.legacy(1)
        self.assertIsNone(c.db.execute('SELECT 1 FROM open_provider_facts').fetchone())
        self.assertEqual(self.lookup()['entries'][0]['fact']['payload']['revision'],2)

    def test_prior_cross_store_fork_survives_later_response_capacity_refusal(self):
        self.fixture();c = self.c
        c.stage();c.state.accept(c.request)
        # Reproduce an already stored pair admitted by the previous version's
        # two separate gates, using real signatures and real resource writes.
        with patch('memory_vault_open_provider_merge.observe_cross_fact',return_value=None):
            self.legacy(1)
        first = c.db.execute('SELECT fact_key FROM open_repair_index_facts').fetchone()[0]
        payload = json.loads(c.f.fact['raw'])['payload']
        for number in range(100000):
            custody = 'synthetic_later_candidate_' + str(number)
            if self.state._fact_key(dict(payload,custody_id=custody))>first:
                break
        else:
            self.fail('could not form a later opaque candidate')
        self.legacy(1,custody)
        with self.assertRaisesRegex(provider.ProviderError,'provider_response_budget'):
            self.lookup(maximum_bytes=4096)
        self.restart()
        for table in ('open_provider_facts','open_repair_index_facts'):
            row=c.db.execute('SELECT status,second_record FROM '+table+' WHERE fact_key=?',(first,)).fetchone()
            self.assertEqual(row[0],'conflict');self.assertIsNotNone(row[1])
        with self.assertRaisesRegex(provider.ProviderError,'provider_fact_inactive'):
            self.legacy(2)

    def test_higher_write_cannot_overwrite_preexisting_fork_before_any_lookup(self):
        self.fixture();c = self.c
        c.stage();c.state.accept(c.request)
        with patch('memory_vault_open_provider_merge.observe_cross_fact',return_value=None):
            self.legacy(1)
        self.restart()
        with self.assertRaisesRegex(provider.ProviderError,'provider_fact_conflict'):
            self.legacy(2)
        for table in ('open_provider_facts','open_repair_index_facts'):
            self.assertEqual(c.db.execute('SELECT revision,status FROM '+table).fetchone(),(1,'conflict'))


if __name__ == '__main__':
    unittest.main()
