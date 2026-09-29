"""Real HTTP root replica upload with durable restart and exact original storage."""
import json
import sqlite3
from pathlib import Path
import threading
import unittest
from unittest.mock import patch

from memory_vault_open_control import issue_node
from memory_vault_open_node import OpenParticipant, OpenHTTPServer
from memory_vault_open_transport import OpenHTTPTransport
from memory_vault_open_repair_copy_upload import make_copy_commit_request
from memory_vault_open_repair_index_state import decode_entry
from memory_vault_open_repair_mailbox_copy_state import MailboxCopyState
from memory_vault_open_repair_mailbox_copy_upload import MailboxRootCopyUpload
import memory_vault_open_repair_stage as stage
import memory_vault_open_repair_wire as wire
import memory_vault_open_repair_history as history
from memory_vault_open_repair_mailbox_copy_authority import verify_mailbox_root_replica
from tests import test_open_repair_mailbox_copy_authority as fixtures
from tests import test_open_repair_copy_upload as http_fixture


def entry(item):
    return dict(raw=item.raw, ref=item.ref.as_dict())


class MailboxRootCopyUploadTests(unittest.TestCase):
    send = http_fixture.CopyUploadHTTPTests.send
    send_frame = http_fixture.CopyUploadHTTPTests.send_frame
    stop = http_fixture.CopyUploadHTTPTests.stop
    restart = http_fixture.CopyUploadHTTPTests.restart

    def setUp(self):
        self.h = fixtures.MailboxRootCopyAuthorityTests()
        self.h.owner_budget_overrides = dict(max_meta_bytes=1048576)
        self.h.setUp(); self.addCleanup(self.h.doCleanups)
        self.h.verify()
        h = self.h; self.policy = h.p.state.policy; self.errors = []
        self.clock = patch('time.time', return_value=h.now); self.clock.start(); self.addCleanup(self.clock.stop)
        self.directory = Path(h.p.temp.name)
        for name in ('network.sqlite3', 'network.sqlite3-wal', 'network.sqlite3-shm'):
            path = self.directory / name
            if path.exists(): path.chmod(0o600)
        with patch('socket.getfqdn', return_value='localhost'):
            self.server = OpenHTTPServer(('127.0.0.1', 0), None)
        self.base = 'http://127.0.0.1:' + str(self.server.server_port)
        self.descriptor = issue_node(h.p.state.identity, base_url=self.base,
            storage_epoch=h.p.state.node['payload']['storage_epoch'], roles=['directory', 'router'],
            revision=2, issued_at=h.now, expires_at=h.now + 300)
        self.start(); self.addCleanup(self.stop)
        self.transport = OpenHTTPTransport(allow_loopback=True); self.addCleanup(self.transport.close)
        rows = [('history.mailbox_root', h.saved['manifest']), ('history.raw_pack', h.saved['pack']),
            ('root.custody', h.custody), ('copy.allocation', h.allocation), ('copy.offer', h.offer),
            ('copy.assignment', h.assignment), ('copy.reservation_consent', h.reservation),
            ('copy.owner_disclosure', h.consents[0]), ('copy.source_disclosure', h.consents[1])]
        rows.extend(('copy.current_status', e) for e in h.statuses)
        self.rows = sorted([dict(role=role, **e) for role, e in rows],
            key=lambda e: (e['role'], e['ref']['namespace'], e['ref']['key'], e['ref']['raw_sha256'], e['ref']['size']))
        manifest = stage.make_stage_manifest(root_key=h.root_key, scope=h.intent['scope'],
            children=[dict(index=i, role=row['role'], ref=row['ref']) for i, row in enumerate(self.rows)],
            consumer='mailbox_copy_root', policy=self.policy, budget=wire.RepairBudget(self.policy))
        self.intent = entry(stage.make_stage_intent(h.source.identity, allocation_id=h.intent['allocation_id'],
            manifest=manifest.value, expires_at=h.until, **self.options()))
        self.rid = json.loads(h.offer['raw'])['payload']['resource']['resource_id']
        MailboxRootCopyUpload(h.p.state).initialize()

    def options(self):
        return dict(expected_subject=self.h.source.target, expected_target=self.h.target,
            target_storage_epoch=self.h.intent['target_storage_epoch'], at=self.h.now,
            expected_consumer='mailbox_copy_root', policy=self.policy, budget=wire.RepairBudget(self.policy))

    def start(self):
        h = self.h
        self.participant = OpenParticipant(h.p.state.identity, self.directory, seeds=[], descriptor=self.descriptor,
            encryption_identity=h.p.state.encryption_identity, allow_loopback=True,
            provider_policy=dict(enabled=True),
            repair_policy=dict(enabled=True, limit_policy=h.source.limits))
        for name in ('handle_repair', 'handle_blob'):
            original = getattr(self.participant, name)
            def observed(*args, method=original):
                try: return method(*args)
                except Exception as error:
                    self.errors.append(getattr(error, 'code', type(error).__name__)); raise
            setattr(self.participant, name, observed)
        self.server.participant = self.participant
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs=dict(poll_interval=.02), daemon=True)
        self.thread.start()

    def test_root_http_upload_survives_restart_before_and_after_commit(self):
        h = self.h
        challenge = self.send(self.intent); self.restart()
        answer = entry(stage.solve_stage_challenge(self.intent, challenge, signer=h.source.identity,
            encryption_identity=h.source.encryption_identity, expires_at=h.until, **self.options()))
        handle = self.send(answer)
        stage.verify_stage_handle(handle, self.intent, **self.options())
        for i, row in enumerate(self.rows):
            for offset in range(0, len(row['raw']), stage.STAGE_CHUNK_BYTES):
                frame = stage.make_stage_child_frame(self.intent, handle, signer=h.source.identity, child_index=i,
                    offset=offset, chunk=row['raw'][offset:offset + stage.STAGE_CHUNK_BYTES],
                    expires_at=h.until, **self.options())
                returned = self.send_frame(frame)
                stage.verify_stage_child_response_frame(returned, frame, self.intent, handle, **self.options())
                if i == 0 and offset == 0:
                    self.restart()
                    self.assertEqual(self.send_frame(frame), returned)
        close = entry(stage.make_stage_close(self.intent, handle, signer=h.source.identity,
            expires_at=h.until, **self.options()))
        result = self.send(close); self.restart(); self.assertEqual(self.send(close), result)
        stage.verify_stage_result(result, close, self.intent, handle, **self.options())
        self.assertEqual(h.p.db.execute('SELECT count(*) FROM open_repair_copy_commits').fetchone()[0], 0)
        request = entry(make_copy_commit_request(h.source.identity, intent_entry=self.intent, result_entry=result,
            resource_id=self.rid, expected_owner=h.owner, expected_source=h.source.target,
            source_storage_epoch=h.source.node['payload']['storage_epoch'], expires_at=h.until, **self.options()))
        reply = self.send(request); self.restart(); self.assertEqual(self.send(request), reply)
        budget = wire.RepairBudget(self.policy)
        value = wire.parse_new_wire(reply['raw'], self.policy, budget).value
        self.assertEqual(value['kind'], 'mailbox.copy_committed')
        custody = decode_entry(value['custody'], self.policy, budget)
        manifest = decode_entry(value['manifest'], self.policy, budget)
        self.assertEqual(json.loads(custody['raw'])['payload']['original_custody_ref'], h.custody['ref'])
        def verify(original_manifest, original_custody):
            meter = wire.RepairBudget(self.policy); resolver = wire.LocalRawResolver(self.policy, meter)
            for row in self.rows: resolver.put(row['ref']['namespace'], row['ref']['key'], row['raw'])
            source = history.resolve_historical_inputs(h.saved['manifest']['raw'], resolver, self.policy, meter)
            for item in source.roles: resolver.put(item.original.ref.namespace, item.original.ref.key, item.original.raw)
            return verify_mailbox_root_replica(original_manifest, resolver, original_custody, expected_root=h.root_key,
                expected_owner=h.owner, expected_source=h.source.target, source_storage_epoch=h.source.node['payload']['storage_epoch'],
                expected_maintainer=h.source.target, expected_target=h.target, target_storage_epoch=h.intent['target_storage_epoch'],
                limit_policy=h.source.limits, policy=self.policy, budget=meter)
        checked = verify(manifest, custody)
        self.assertEqual(checked['source']['custody'].raw, h.custody['raw'])
        from memory_vault import canonical_bytes
        from tests.open_repair_ack_fixtures import reference, signed_entry
        changed = json.loads(manifest['raw'])
        changed['edges'] = [edge for edge in changed['edges'] if edge['relation'] != 'catalog-slot']
        raw = canonical_bytes(changed); false_manifest = dict(raw=raw, ref=reference(raw, 'synthetic_incomplete_root_graph'))
        payload = json.loads(custody['raw'])['payload']; payload['replica_manifest_ref'] = false_manifest['ref']
        false_custody = signed_entry(payload, h.p.state.identity, 'synthetic_forged_replica_graph')
        with self.assertRaisesRegex(wire.RepairWireError, 'repair_copy_commit_mismatch'):
            verify(false_manifest, false_custody)
        h.source.db.close()
        self.restart()
        with self.participant.state.db() as db:
            store = MailboxCopyState(self.participant._repair_service(db).state); store.initialize()
            for original in (*h.saved.values(), h.custody):
                self.assertEqual(store.read_local_original(self.rid, original['ref']), original['raw'])
            self.assertEqual(db.execute('SELECT count(*) FROM open_repair_copy_commits').fetchone()[0], 1)
        self.assertEqual(self.errors, [])

    def test_mailbox_upload_rejects_ack_consumer_before_stage_or_work(self):
        from memory_vault_open_repair_copy_upload import RepairCopyUpload
        with self.assertRaisesRegex(wire.RepairWireError, 'repair_copy_upload_mismatch'):
            RepairCopyUpload(self.h.p.state).intent(self.rid, self.intent)
        self.assertIsNone(MailboxRootCopyUpload(self.h.p.state)._session(self.rid))
        self.assertIsNone(self.h.p.db.execute('SELECT requests FROM open_repair_copy_work WHERE resource_id=?', (self.rid,)).fetchone())

    def client(self):
        from memory_vault_open_repair_mailbox_copy_prepare import MailboxRootCopyPreparation
        from memory_vault_open_repair_mailbox_copy_client import MailboxRootCopyUploadClient
        db = sqlite3.connect(self.directory / 'synthetic-copy-client.sqlite3')
        journal = MailboxRootCopyPreparation(db, self.h.source.identity, self.h.source.encryption_identity, policy=self.policy)
        client = MailboxRootCopyUploadClient(journal, encryption_identity=self.h.source.encryption_identity,
            transport=self.transport, allow_loopback=True)
        return client, db

    def run_client(self, client, statuses=None):
        from memory_vault import canonical_bytes
        from tests.open_repair_ack_fixtures import reference
        h = self.h
        node_raw = canonical_bytes(self.descriptor)
        return client.upload(self.base, h.saved['manifest'], h.resolver(wire.RepairBudget(self.policy)), h.custody,
            h.allocation, h.offer, h.assignment, h.reservation, *h.consents,
            target_node_entry=dict(raw=node_raw, ref=reference(node_raw, 'synthetic_copy_destination')), expected_root=h.root_key, expected_owner=h.owner,
            expected_source=h.source.target, source_storage_epoch=h.source.node['payload']['storage_epoch'],
            expected_target=h.target, target_storage_epoch=h.intent['target_storage_epoch'],
            current_statuses=h.statuses if statuses is None else statuses, limit_policy=h.source.limits)

    def test_client_resumes_exact_custody_after_lost_reply_and_both_restarts(self):
        from memory_vault import MemoryError
        client, db = self.client(); self.addCleanup(db.close)
        request = self.transport.request_repair
        lost = []
        def lose_commit(base, raw, **options):
            result = request(base, raw, **options)
            if json.loads(raw).get('payload', {}).get('kind') == 'mailbox.root_copy_commit' and not lost:
                lost.append(raw)
                raise MemoryError('open_network_unavailable', retryable=True)
            return result
        with patch.object(self.transport, 'request_repair', side_effect=lose_commit):
            with self.assertRaises(MemoryError): self.run_client(client)
        self.assertEqual(len(lost), 1)
        self.assertEqual(self.h.p.db.execute('SELECT count(*) FROM open_repair_copy_commits').fetchone()[0], 1)
        db.close(); self.restart()
        client, db = self.client(); self.addCleanup(db.close)
        result = self.run_client(client)
        self.assertEqual(result['state'], 'replica_committed')
        self.assertEqual(self.run_client(client), result)
        requests = [bytes(row[0]) for row in db.execute("SELECT request FROM ack_copy_client_steps WHERE mode='repair'")]
        self.assertIn(lost[0], requests)
        self.assertEqual(self.h.p.db.execute('SELECT count(*) FROM open_repair_copy_commits').fetchone()[0], 1)

    def test_authenticated_revocation_survives_client_restart_before_any_network_disclosure(self):
        from memory_vault_open_provider import issue_status
        from tests.test_open_repair_status import status_entry
        h = self.h; p = json.loads(h.statuses[0]['raw'])['payload']
        p['entries'][0]['status'] = 'revoked'
        revoked = status_entry(issue_status(h.owner_signer, root=h.root_key, revision=3,
            entries=p['entries'], issued_at=h.now, valid_until=h.until))
        with patch.object(self.transport, 'request', side_effect=AssertionError('unexpected disclosure')) as send:
            for values in ([revoked, h.statuses[1]], h.statuses):
                client, db = self.client()
                try:
                    with self.assertRaises(wire.RepairWireError): self.run_client(client, values)
                finally: db.close()
            send.assert_not_called()

    def test_owner_recovers_original_root_over_http_after_source_loss_and_replica_restart(self):
        from memory_vault import canonical_bytes
        from memory_vault_open_repair_mailbox_copy_service import MailboxRootReplicaReadService
        from memory_vault_open_repair_mailbox_copy_client import MailboxRootReplicaRecoveryClient
        from tests.open_repair_ack_fixtures import reference
        h = self.h
        store = MailboxCopyState(h.p.state); store.initialize(); custody = h.commit(store)
        rid = json.loads(custody['raw'])['payload']['resource']['resource_id']
        consents, current = h.read_permissions(custody)
        context = h.read_context(); context.pop('limit_policy')
        with self.participant.state.db() as db:
            service = MailboxRootReplicaReadService(self.participant._repair_service(db).state); service.initialize()
            self.assertEqual(service.configure(rid, context=context, consents=consents, current_statuses=current)['state'], 'configured')
        h.source.db.close(); self.restart()
        observed = []
        client = MailboxRootReplicaRecoveryClient(h.owner_signer, h.h.host.h.f['encryption']['owner'],
            policy=self.policy, limit_policy=h.source.limits, allow_loopback=True, transport=self.transport,
            clock=lambda: h.now, status_observer=observed.append)
        node = canonical_bytes(self.descriptor); setup = h.event['setup']['originals']
        result = client.recover(self.base, target_node_entry=dict(raw=node, ref=reference(node, 'synthetic_read_destination')),
            expected_target=h.target, expected_root=h.root_key, expected_source=h.source.target,
            source_storage_epoch=h.source.node['payload']['storage_epoch'], expected_maintainer=h.source.target,
            root_entry=entry(setup['root']), read_entry=entry(setup['read']), bootstrap_entry=entry(setup['bootstrap']), timeout=30)
        self.assertEqual(result.replica['custody'].raw, custody['raw'])
        self.assertEqual(result.replica['source']['custody'].raw, h.custody['raw'])
        self.assertEqual(result.replica['source']['setup']['originals']['catalog'].raw, setup['catalog'].raw)
        self.assertEqual(len(result.current_statuses), 3)
        self.assertEqual({item.ref for item in observed}, {item.ref for item in result.current_statuses})
        self.assertEqual(self.errors, [])
