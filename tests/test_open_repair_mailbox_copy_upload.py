"""Real HTTP root replica upload with durable restart and exact original storage."""
import json
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
        self.assertEqual(json.loads(custody['raw'])['payload']['original_custody_ref'], h.custody['ref'])
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
