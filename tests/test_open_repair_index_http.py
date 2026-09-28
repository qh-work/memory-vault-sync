"""Actual directory HTTP publication and bounded opaque lookup over both stores."""
import hashlib
import json
from pathlib import Path
import threading
import time
import unittest
from unittest.mock import patch

from memory_vault import MemoryError, canonical_bytes
from memory_vault_open_blob import decode_blob_frame, encode_blob_frame
from memory_vault_open_control import issue_node
from memory_vault_open_node import OpenHTTPServer, OpenParticipant
import memory_vault_open_provider as provider
from memory_vault_open_repair_index_state import encode_entry
import memory_vault_open_repair_stage as stage
from memory_vault_open_transport import OpenHTTPTransport
from tests.test_open_repair_index_state import DirectoryFixture
from tests.open_repair_ack_fixtures import signed_entry


class RepairIndexHTTPTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch('time.time', return_value=2_000_000_020))
        self.server = OpenHTTPServer(('127.0.0.1', 0), None)
        self.addCleanup(self.server.server_close)
        self.base = 'http://127.0.0.1:' + str(self.server.server_port)
        connect = DirectoryFixture.connect

        def protected(c):
            f = c.f
            c.node = issue_node(f.directory, base_url=self.base, storage_epoch=f.epoch,
                roles=['directory', 'router'], revision=1, issued_at=f.at-1, expires_at=f.at+600)
            self.directory = Path(c.temp.name).resolve() / 'protected-transport'
            self.participant = OpenParticipant(f.directory, self.directory, seeds=[], descriptor=c.node,
                encryption_identity=f.directory_encryption, allow_loopback=True,
                provider_policy=dict(enabled=True),
                repair_policy=dict(enabled=True, limit_policy=f.f['expected']['limit_policy']))
            self.addCleanup(self.participant.close)
            c.path = self.directory / 'network.sqlite3'
            connect(c)

        with patch.object(DirectoryFixture, 'connect', protected):
            self.c = DirectoryFixture(self)
        self.server.participant = self.participant
        self.thread = threading.Thread(target=self.server.serve_forever,
            kwargs=dict(poll_interval=0.02), daemon=True)
        self.thread.start()
        self.addCleanup(self.stop)
        self.transport = OpenHTTPTransport(allow_loopback=True)
        self.addCleanup(self.transport.close)

    def stop(self):
        self.server.shutdown()
        self.thread.join(timeout=3)

    def send(self, raw):
        return self.transport.request_repair(self.base, raw, deadline=time.monotonic()+10)

    @staticmethod
    def entry(raw):
        digest = hashlib.sha256(raw).hexdigest()
        return dict(raw=raw, ref=dict(namespace='meta', key=digest, raw_sha256=digest, size=len(raw)))

    def lookup(self, after=None):
        c = self.c
        request = provider.sign_rpc(c.f.f['signers']['owner'], node=c.node,
            action='provider.get', body=dict(ref=c.f.root['anchor_ref'], after=after,
                limit=1, maximum_bytes=49152), now=c.f.at)
        response = self.transport.request(self.base, request, deadline=time.monotonic()+10).response
        return provider.verify_response(response, request=request, node=c.node, now=c.f.at)['body']

    def publish(self):
        c = self.c
        allocation = dict(schema_version='memory-vault-open-repair/v1', kind='ack.index_allocate',
            allocation=encode_entry(c.f.allocation), owner=c.f.f['expected']['expected_owner'],
            receipt_writer=c.f.case.case.expected['expected_receipt_writer'])
        response = json.loads(self.send(canonical_bytes(allocation)))
        self.assertEqual(response['offer'], encode_entry(c.allocation['offer']))
        challenge = self.entry(self.send(c.intent.raw))
        answer = stage.solve_stage_challenge(c.entry(c.intent), challenge, signer=c.f.f['signers']['target'],
            encryption_identity=c.f.f['encryption']['target'], expires_at=c.f.at+60, **c.expected())
        c.handle = self.entry(self.send(answer.raw))
        for raw in c.frames():
            frame = decode_blob_frame(raw)
            reply = self.transport.request_blob(self.base, frame.header, frame.chunk, deadline=time.monotonic()+10)
            response = encode_blob_frame(reply.header, reply.chunk)
            stage.verify_stage_child_response_frame(response, raw, c.entry(c.intent), c.handle, **c.expected())
        self.assertEqual(self.lookup()['entries'], [])
        close = stage.make_stage_close(c.entry(c.intent), c.handle, signer=c.f.f['signers']['target'],
            expires_at=c.f.at+60, **c.expected())
        result = self.entry(self.send(close.raw))
        stage.verify_stage_result(result, c.entry(close), c.entry(c.intent), c.handle, **c.expected())
        payload = json.loads(c.f.request['raw'])['payload']
        payload.update(issued_at=c.f.at, resource_offer_ref=c.allocation['offer']['ref'],
            assignment_ref=c.assignment['ref'], stage_result_ref=result['ref'])
        request = signed_entry(payload, c.f.f['signers']['target'], 'http-index-publication')
        raw = self.send(request['raw'])
        lease = json.loads(raw)['index_lease']
        provider.verify_index_lease(lease, fact=json.loads(c.f.fact['raw']), node=c.node, now=c.f.at)
        self.assertEqual(self.send(request['raw']), raw)
        return lease

    def test_real_http_stage_commit_lookup_restart_and_closed_blob_gate(self):
        lease = self.publish()
        page = self.lookup()
        self.assertEqual(page['entries'], [dict(fact=json.loads(self.c.f.fact['raw']), index_lease=lease)])
        self.assertEqual(set(page['entries'][0]), {'fact', 'index_lease'})
        # Recreate the real participant over its protected transport database.
        self.participant.close()
        self.participant = OpenParticipant(self.c.f.directory, self.directory, seeds=[], descriptor=self.c.node,
            encryption_identity=self.c.f.directory_encryption, allow_loopback=True,
            provider_policy=dict(enabled=True), repair_policy=dict(enabled=True,
                limit_policy=self.c.f.f['expected']['limit_policy']))
        self.addCleanup(self.participant.close)
        self.server.participant = self.participant
        self.assertEqual(self.lookup()['entries'], page['entries'])
        self.participant.repair_policy['enabled'] = False
        frame = decode_blob_frame(next(self.c.frames()))
        with self.assertRaises(MemoryError):
            self.transport.request_blob(self.base, frame.header, frame.chunk, deadline=time.monotonic()+10)

    def test_inactive_rows_in_both_tables_do_not_hide_later_real_publication(self):
        self.publish()
        c = self.c
        row = c.state.lookup_candidates(c.f.root['anchor_ref'])[0]
        # Deliberately inactive synthetic storage rows exercise scan boundaries;
        # their placeholders are never emitted or treated as authority.
        columns = [entry[1] for entry in c.db.execute('PRAGMA table_info(open_provider_facts)')]
        for number in range(1, 70):
            key = f'{number:064x}'
            self.assertLess(key, row['fact_key'])
            if number % 2:
                c.db.execute('''INSERT INTO open_repair_index_facts
                    SELECT ?,namespace,opaque_key,provider,revision,digest,record,node,index_lease,
                    allocation_id,request,request_digest,obligations,root_digest,expires_at,'withdrawn',second_record
                    FROM open_repair_index_facts WHERE fact_key=?''', (key, row['fact_key']))
            else:
                values = dict(row, fact_key=key, provider_epoch=c.f.epoch, custody_id='synthetic_inactive',
                    status='withdrawn', resource_id='synthetic_absent', grant_record=b'{}',
                    grant_digest='0'*64, owner_status=b'{}', retain_until=c.f.at+60)
                c.db.execute('INSERT INTO open_provider_facts VALUES('+','.join('?' for _ in columns)+')',
                    tuple(values[name] for name in columns))
        c.db.commit()
        cursor, found, empty_pages = None, [], 0
        for _ in range(6):
            page = self.lookup(cursor)
            found.extend(page['entries'])
            empty_pages += not bool(page['entries'])
            if page['next_cursor'] is None:
                break
            self.assertGreater(page['next_cursor'], cursor or '')
            cursor = page['next_cursor']
        else:
            self.fail('lookup did not terminate')
        self.assertEqual(len(found), 1)
        self.assertGreaterEqual(empty_pages, 2)
