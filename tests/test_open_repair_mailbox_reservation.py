"""Real signed capacity requests from independent synthetic mailbox consent."""
import copy
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

from memory_vault import canonical_bytes
from memory_vault_open_provider import issue_status
from memory_vault_open_repair_mailbox_copy_prepare import MailboxRootCopyPreparation
import memory_vault_open_repair_status as status
import memory_vault_open_repair_wire as wire
from tests import test_open_repair_mailbox_copy_authority as root_fixtures
from tests.test_open_repair_status import status_entry
from tests.open_repair_ack_fixtures import signed_entry


class MailboxReservationTests(unittest.TestCase):
    def setUp(self):
        self.h = root_fixtures.MailboxRootCopyAuthorityTests(); self.h.setUp(); self.addCleanup(self.h.doCleanups)
        self.temp = tempfile.TemporaryDirectory(prefix='synthetic-mailbox-reservation-')
        self.addCleanup(self.temp.cleanup); self.path = Path(self.temp.name)/'network.sqlite3'
        self.connect(); self.addCleanup(lambda: self.db.close())
        self.configure_reservation(self.h)

    def configure_reservation(self, h):
        self.intent = copy.deepcopy(h.intent)
        self.intent.update(allocation_id='synthetic_client_allocation', job_id='synthetic_client_job')
        payload = json.loads(h.reservation['raw'])['payload']
        payload['consent_id'] = 'synthetic_client_reservation'
        payload['reservation_disclosure']['intent_sha256'] = hashlib.sha256(canonical_bytes(self.intent)).hexdigest()
        self.reservation = signed_entry(payload, h.owner_signer, 'synthetic_client_reservation')
        policy = h.source.policy; budget = wire.RepairBudget(policy)
        def scope(entry):
            p = json.loads(entry['raw'])['payload']
            return status.status_scope(h.root_key, 'authority',
                dict(authority_kind=p['kind'], authority_sha256=entry['ref']['raw_sha256']), policy, budget)
        old_scope, new_scope = scope(h.reservation), scope(self.reservation)
        allowed = {(e['scope_kind'], e['scope_id']) for item in h.event['statuses'] for e in item.payload['entries']}
        self.statuses = []
        for raw, signer in zip(h.statuses, (h.owner_signer, h.source.identity)):
            entries = []
            for e in json.loads(raw['raw'])['payload']['entries']:
                if e['scope_kind'] == 'authority' and e['scope_id'] == old_scope:
                    entries.append(dict(e, scope_id=new_scope))
                elif (e['scope_kind'], e['scope_id']) in allowed:
                    entries.append(e)
            entries.sort(key=lambda e: (e['scope_kind'], e['scope_id']))
            self.statuses.append(status_entry(issue_status(signer, root=h.root_key, revision=3,
                entries=entries, issued_at=h.now, valid_until=h.until)))

    def connect(self):
        self.db = sqlite3.connect(self.path)
        self.journal = MailboxRootCopyPreparation(self.db, self.h.source.identity,
            self.h.source.encryption_identity, policy=self.h.source.policy)
        self.journal.initialize()

    def prepare(self, **changes):
        h = self.h; budget = wire.RepairBudget(h.source.policy)
        options = dict(expected_root=h.root_key, expected_owner=h.owner, expected_source=h.source.target,
            source_storage_epoch=h.source.node['payload']['storage_epoch'], current_statuses=self.statuses,
            at=h.now, limit_policy=h.source.limits)
        options.update(changes)
        return self.journal.prepare_reservation(h.saved['manifest'], h.resolver(budget), h.custody,
            self.reservation, self.intent, **options)

    def test_real_offer_precedes_assignment_and_exact_requests_survive_restart(self):
        h = self.h
        before = h.p.state.capacity.usage()
        prepared = self.prepare()
        self.assertNotIn('assignment', prepared)
        self.assertEqual(h.p.state.capacity.usage(), before)
        offer = h.resources.allocate(prepared['allocation'], expected_caller=h.source.target)
        assigned = self.prepare(offer_entry=offer)
        self.assertNotEqual(h.p.state.capacity.usage(), before)
        payload = json.loads(assigned['assignment']['raw'])['payload']
        self.assertEqual(payload['operation_mask'], 70)
        self.assertEqual(payload['resource_offer_ref'], offer['ref'])
        self.assertEqual(payload['resource'], json.loads(offer['raw'])['payload']['resource'])
        self.db.close(); self.connect()
        repeated = self.prepare(offer_entry=offer)
        self.assertEqual(repeated['allocation'], prepared['allocation'])
        self.assertEqual(repeated['assignment'], assigned['assignment'])
        self.assertEqual(self.db.execute('SELECT count(*) FROM ack_copy_prepare_jobs').fetchone()[0], 1)

    def test_unapproved_intent_cannot_emit_allocation(self):
        self.intent['job_id'] = 'synthetic_not_consented'
        with self.assertRaises(wire.RepairWireError): self.prepare()
        self.assertEqual(self.db.execute('SELECT count(*) FROM ack_copy_prepare_jobs').fetchone()[0], 0)

    def test_observed_revocation_survives_failed_sibling_and_restart(self):
        h = self.h
        entries = json.loads(self.statuses[0]['raw'])['payload']['entries']
        entries[0]['status'] = 'revoked'
        revoked = status_entry(issue_status(h.owner_signer, root=h.root_key, revision=4,
            entries=entries, issued_at=h.now, valid_until=h.until))
        broken = dict(self.statuses[1], raw=b'{}')
        with self.assertRaises(wire.RepairWireError): self.prepare(current_statuses=[revoked, broken])
        self.assertIsNotNone(self.db.execute('SELECT 1 FROM ack_copy_prepare_status WHERE raw=?', (revoked['raw'],)).fetchone())
        self.db.close(); self.connect()
        with self.assertRaises(wire.RepairWireError): self.prepare()
        self.assertEqual(self.db.execute('SELECT count(*) FROM ack_copy_prepare_jobs').fetchone()[0], 0)

    def test_http_reservation_reuses_real_capacity_after_lost_reply_and_both_restarts(self):
        from memory_vault import MemoryError
        from memory_vault_open_control import issue_node
        from memory_vault_open_node import OpenHTTPServer, OpenParticipant
        from memory_vault_open_repair_mailbox_copy_client import MailboxRootCopyUploadClient
        from memory_vault_open_transport import OpenHTTPTransport
        h = self.h; address = ('127.0.0.1', 0)
        self.server = None; self.participant = None
        def stop():
            if self.server is not None:
                self.server.shutdown(); self.server.server_close(); self.thread.join(3)
                self.participant.close(); self.server = None
        self.addCleanup(stop)
        def start():
            self.server = OpenHTTPServer(address, None)
            base = 'http://127.0.0.1:'+str(self.server.server_port)
            descriptor = issue_node(h.p.state.identity, base_url=base,
                storage_epoch=self.intent['target_storage_epoch'], roles=['directory', 'router'],
                revision=1, issued_at=h.now, expires_at=h.now+300)
            self.participant = OpenParticipant(h.p.state.identity, Path(self.temp.name)/'target',
                seeds=[], descriptor=descriptor, encryption_identity=h.p.state.encryption_identity,
                allow_loopback=True, provider_policy=dict(enabled=True),
                repair_policy=dict(enabled=True, limit_policy=h.source.limits, remote_mailbox_copy=dict(enabled=True)))
            self.server.participant = self.participant
            self.thread = threading.Thread(target=self.server.serve_forever, kwargs=dict(poll_interval=.02), daemon=True)
            self.thread.start()
            raw = canonical_bytes(descriptor); digest = hashlib.sha256(raw).hexdigest()
            return base, dict(raw=raw, ref=dict(namespace='meta', key=digest, raw_sha256=digest, size=len(raw)))
        with patch('time.time', return_value=h.now):
            base, node = start(); address = self.server.server_address
            transport = OpenHTTPTransport(allow_loopback=True); self.addCleanup(transport.close)
            original = transport.request_repair; sent = []
            def lose_once(base_url, raw, **options):
                sent.append(raw)
                response = original(base_url, raw, **options)
                if len(sent) == 1: raise MemoryError('open_network_unavailable', retryable=True)
                return response
            def reserve():
                client = MailboxRootCopyUploadClient(self.journal, encryption_identity=h.source.encryption_identity,
                    transport=transport, allow_loopback=True)
                budget = wire.RepairBudget(h.source.policy)
                return client.reserve(base, h.saved['manifest'], h.resolver(budget), h.custody,
                    self.reservation, self.intent, target_node_entry=node, expected_root=h.root_key,
                    expected_owner=h.owner, expected_source=h.source.target,
                    source_storage_epoch=h.source.node['payload']['storage_epoch'],
                    current_statuses=self.statuses, limit_policy=h.source.limits)
            with patch.object(transport, 'request_repair', side_effect=lose_once):
                with self.assertRaisesRegex(MemoryError, 'open_network_unavailable'): reserve()
                with self.participant.state.db() as db:
                    self.assertEqual(db.execute('SELECT count(*) FROM open_repair_copy_resources').fetchone()[0], 1)
                stop(); self.db.close(); self.connect(); start()
                result = reserve()
            self.assertEqual(result['state'], 'capacity_reserved')
            self.assertEqual(sent[0], sent[1])
            assigned = self.prepare(offer_entry=result['offer'])
            self.assertEqual(assigned['allocation'], result['allocation'])
            with self.participant.state.db() as db:
                self.assertEqual(db.execute('SELECT count(*) FROM open_repair_copy_resources').fetchone()[0], 1)
                self.assertEqual(db.execute('SELECT count(*) FROM open_repair_copy_commits').fetchone()[0], 0)


class MailboxFeedReservationTests(unittest.TestCase):
    def exercise(self, h):
        from memory_vault_open_repair_mailbox_copy_prepare import MailboxFeedCopyPreparation, MailboxMessageCopyPreparation
        journal_type = MailboxMessageCopyPreparation if h.message else MailboxFeedCopyPreparation
        with tempfile.TemporaryDirectory(prefix='synthetic-mailbox-reserve-client-') as folder:
            path = Path(folder)/'network.sqlite3'
            db = sqlite3.connect(path)
            self.addCleanup(db.close)
            journal = journal_type(db, h.source.identity, h.source.encryption_identity, policy=h.policy)
            journal.initialize()
            intent = dict(h.intent, allocation_id='synthetic_new_allocation', job_id='synthetic_new_job')
            replacements = {}; reservations = {}
            budget = wire.RepairBudget(h.policy)
            def scope(entry):
                p = json.loads(entry['raw'])['payload']
                return status.status_scope(h.root, 'authority', dict(authority_kind=p['kind'],
                    authority_sha256=entry['ref']['raw_sha256']), h.policy, budget)
            for name, entry in h.reservations.items():
                p = json.loads(entry['raw'])['payload']; p['consent_id'] += '_new'
                p['reservation_disclosure']['intent_sha256'] = hashlib.sha256(canonical_bytes(intent)).hexdigest()
                changed = signed_entry(p, h.signers[name], 'synthetic_'+name)
                replacements[scope(entry)] = scope(changed); reservations[name] = changed
            historical = journal._source_statuses(h.event)
            allowed = {(e['scope_kind'], e['scope_id']) for item in historical for e in item.payload['entries']}
            statuses = []
            for old, name in zip(h.statuses, ('owner', 'sender', 'source')):
                p = json.loads(old['raw'])['payload']
                entries = [dict(e, scope_id=replacements.get(e['scope_id'], e['scope_id'])) for e in p['entries']
                    if e['scope_id'] in replacements or (e['scope_kind'], e['scope_id']) in allowed]
                statuses.append(status_entry(issue_status(h.signers[name], root=h.root, revision=p['revision']+1,
                    entries=sorted(entries, key=lambda e:(e['scope_kind'], e['scope_id'])),
                    issued_at=h.now, valid_until=h.until)))
            context = h.context(); context.pop('expected_maintainer')
            context.update(current_statuses=statuses, at=h.now, sender_reservation_entry=reservations['sender'])
            def prepare(**changes):
                return journal.prepare_reservation(h.manifest, h.resolver(), h.custody,
                    reservations['owner'], intent, **dict(context, **changes))
            with self.assertRaises(wire.RepairWireError): prepare(sender_reservation_entry=None)
            self.assertEqual(db.execute('SELECT count(*) FROM ack_copy_prepare_jobs').fetchone()[0], 0)
            prepared = prepare()
            offer = h.store.allocate(prepared['allocation'], expected_caller=h.source.target)
            assigned = prepare(offer_entry=offer)
            payload = json.loads(assigned['assignment']['raw'])['payload']
            self.assertEqual(payload['operation_mask'], 70)
            self.assertEqual(payload['scope'], intent['scope'])
            self.assertEqual(payload['parent_root_ref'], h.parent.ref.as_dict())
            db.close(); db = sqlite3.connect(path); self.addCleanup(db.close)
            journal = journal_type(db, h.source.identity, h.source.encryption_identity, policy=h.policy)
            journal.initialize()
            replay = prepare(offer_entry=offer)
            self.assertEqual(replay['allocation'], assigned['allocation'])
            self.assertEqual(replay['assignment'], assigned['assignment'])
            # A signed offer for another request cannot acquire this assignment.
            with self.assertRaises(wire.RepairWireError): prepare(offer_entry=h.offer)
            self.command_roundtrip(h, intent, reservations, statuses, assigned, offer)

    def command_roundtrip(self, h, intent, reservations, statuses, assigned, offer):
        from memory_vault_open_node import OpenHTTPServer, OpenParticipant
        from memory_vault_open_control import issue_node
        server = OpenHTTPServer(('127.0.0.1', 0), None)
        descriptor = issue_node(h.identity, base_url='http://127.0.0.1:'+str(server.server_port),
            storage_epoch=h.node['payload']['storage_epoch'], roles=['directory', 'router'], revision=2,
            issued_at=h.now, expires_at=h.now+300)
        participant = OpenParticipant(h.identity, h.directory, seeds=[], descriptor=descriptor,
            encryption_identity=h.encryption, allow_loopback=True, provider_policy=dict(enabled=True),
            repair_policy=dict(enabled=True, limit_policy=h.limits, remote_mailbox_copy=dict(enabled=True)))
        server.participant = participant
        thread = threading.Thread(target=server.serve_forever, kwargs=dict(poll_interval=.02), daemon=True)
        thread.start()
        try:
            network = h.client_config('source', descriptor)
            kind = 'message' if h.message else 'feed'
            request = dict(schema_version='memory-vault-open-mailbox-'+kind+'-copy-reservation-request/v1',
                node=h.encode(h.wrap(canonical_bytes(descriptor))), root_key=h.root,
                slot_key=h.slot, sender=h.sender, owner=h.owner, source=h.source.target,
                source_storage_epoch=h.source.node['payload']['storage_epoch'], intent=intent,
                manifest=h.encode(h.manifest), custody=h.encode(h.custody),
                reservation=h.encode(reservations['owner']), sender_reservation=h.encode(reservations['sender']),
                originals=[h.encode(h.entry(ref)) for role, ref in h.part.transfer if role=='history.raw_pack'],
                current_statuses=[h.encode(e) for e in statuses])
            if h.message: request['envelope_ref'] = h.envelope_ref
            before = h.db.execute('SELECT count(*) FROM open_repair_copy_resources').fetchone()[0]
            result = h.command('copy-reserve-'+kind, request, network)
            self.assertEqual(result['state'], 'capacity_reserved_and_assigned')
            self.assertEqual(result['allocation'], h.encode(assigned['allocation']))
            self.assertEqual(result['offer'], h.encode(offer))
            self.assertEqual(result['assignment'], h.encode(assigned['assignment']))
            self.assertEqual(h.command('copy-reserve-'+kind, request, network), result)
            self.assertEqual(h.db.execute('SELECT count(*) FROM open_repair_copy_resources').fetchone()[0], before)
        finally:
            server.shutdown(); server.server_close(); thread.join(3); participant.close()

    def test_feed_requires_both_reservations_before_real_offer(self):
        from tests.test_open_repair_mailbox_feed_copy import MailboxFeedCopyTests
        MailboxFeedCopyTests.run_fixture(self, self.exercise)

    def test_message_reserves_exact_ciphertext_with_both_original_parties(self):
        from tests.test_open_repair_mailbox_message_copy import MailboxMessageCopyTests
        MailboxMessageCopyTests.run_fixture(self, self.exercise)
