"""Real source-to-directory HTTP publication from freshly funded originals."""
import copy
import hashlib
import json
import threading
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from memory_vault import MemoryError, canonical_bytes
from memory_vault_open_repair_index_access import AckIndexSourceAccess
from memory_vault_open_repair_index_client import AckIndexPublicationClient
from memory_vault_open_repair_state import INDEX_WORKFLOW_LIMITS
import memory_vault_open_repair_wire as wire
from memory_vault_open_transport import OpenHTTPTransport
from tests import test_open_repair_state as source_tests
from tests import test_open_repair_index_http as http_tests
from tests.open_repair_ack_fixtures import reference, signed_entry


class RecordingHTTPTransport(OpenHTTPTransport):
    """Every successful response comes from the actual loopback HTTP server."""
    def __init__(self):
        super().__init__(allow_loopback=True)
        self.calls = []
        self.drop_kind = None
        self.before_send = None
        self.after_response = None

    def _record(self, kind, raw):
        self.calls.append((kind, raw))
        if self.before_send:
            self.before_send(kind, raw)

    def request(self, base, value, *, deadline):
        self._record(value['payload']['action'], canonical_bytes(value))
        return super().request(base, value, deadline=deadline)

    def request_repair(self, base, raw, *, child=False, deadline):
        p = json.loads(raw)
        kind = p.get('kind') or p['payload']['kind']
        self._record(kind, raw)
        reply = super().request_repair(base, raw, child=child, deadline=deadline)
        if self.drop_kind == kind:
            self.drop_kind = None
            raise MemoryError('open_network_unavailable')
        return reply

    def request_blob(self, base, header, chunk, *, deadline):
        from memory_vault_open_blob import encode_blob_frame
        self._record(header['payload']['kind'], encode_blob_frame(header, chunk))
        response = super().request_blob(base, header, chunk, deadline=deadline)
        if self.after_response:
            self.after_response(header['payload']['kind'])
        return response


class AckIndexPublicationClientTests(unittest.TestCase):
    workflow_limits = INDEX_WORKFLOW_LIMITS

    def setUp(self):
        fixture = source_tests.ack_unbound_fixture
        def funded(**options):
            f = fixture(**options)
            # Explicit new index profile, before allocation/root/read/bootstrap
            # signatures; old signed authorities are never edited in place.
            f['expected']['limit_policy'] = dict(self.workflow_limits)
            f['docs']['bootstrap']['payload']['limits'] = dict(self.workflow_limits)
            return f
        self.http = http_tests.RepairIndexHTTPTests()
        self.addCleanup(self.http.doCleanups)
        with patch.object(source_tests, 'ack_unbound_fixture', funded):
            self.http.setUp()
        self.c, self.f = self.http.c, self.http.c.f
        self.f.h.now[0] = self.f.at
        self.transport = RecordingHTTPTransport()
        self.addCleanup(self.transport.close)
        self.make_client()

    def make_client(self):
        self.access = AckIndexSourceAccess(self.f.h.state)
        self.access.initialize()
        self.client = AckIndexPublicationClient(self.access, encryption_identity=self.f.f['encryption']['target'],
            transport=self.transport, allow_loopback=True)

    def options(self):
        node_raw = canonical_bytes(self.c.node)
        provider_raw = canonical_bytes(self.f.f['docs']['descriptor'])
        return dict(target_node_entry=dict(raw=node_raw, ref=reference(node_raw, 'directory-node')),
            provider_node_entry=dict(raw=provider_raw, ref=reference(provider_raw, 'source-node')),
            expected_directory=self.f.directory_keys, provider_fact_entry=self.f.fact, intent=self.f.intent,
            owner_consent_entry=self.f.consents['owner'], recipient_consent_entry=self.f.consents['writer'],
            current_statuses=self.f.current, allocation_entry=self.f.allocation)

    def publish(self, **changes):
        return self.client.publish(self.f.h.resource_id, self.http.base, **(self.options() | changes))

    def test_actual_http_dual_proof_precedes_descriptor_and_only_real_lease_advertises(self):
        def journaled(kind, raw):
            found = self.f.h.db.execute('SELECT request FROM open_repair_index_steps WHERE resource_id=? AND request_digest=?',
                (self.f.h.resource_id, hashlib.sha256(raw).hexdigest())).fetchone()
            self.assertIsNotNone(found)
            self.assertEqual(bytes(found[0]), raw)
        self.transport.before_send = journaled
        key_type = type(Ed25519PublicKey.from_public_bytes(b'a' * 32))
        verify, checks, main_thread = key_type.verify, [], threading.get_ident()
        def count(key, signature, data):
            if threading.get_ident() == main_thread:
                checks.append(1)
            return verify(key, signature, data)
        with patch.object(key_type, 'verify', new=count):
            result = self.publish()
        signatures = self.f.h.db.execute('SELECT signatures FROM open_repair_bootstrap_usage WHERE resource_id=?',
            (self.f.h.resource_id,)).fetchone()[0]
        self.assertEqual(signatures, len(checks))
        self.assertEqual(result.state, 'advertised')
        self.assertFalse(result.metrics['usable'])
        self.assertFalse(result.metrics['from_local_history'])
        self.assertEqual([kind for kind, _ in self.transport.calls[:3]], ['target.get', 'target.answer', 'ack.index_allocate'])
        self.assertNotIn(self.f.root['root_id'].encode(), self.transport.calls[0][1])
        self.assertNotIn(self.f.root['root_id'].encode(), self.transport.calls[1][1])
        self.assertEqual(len(self.http.lookup()['entries']), 1)
        row = self.f.h.db.execute('SELECT state FROM open_repair_index_execution WHERE resource_id=?', (self.f.h.resource_id,)).fetchone()
        self.assertEqual(row[0], 'advertised')
        checks = self.f.h.db.execute('SELECT signature_checks,signature_allowance FROM open_repair_index_attempts').fetchall()
        self.assertTrue(all(actual is not None and 0 < actual <= limit <= 64 for actual, limit in checks))
        self.assertEqual(self.f.h.db.execute('SELECT count(*) FROM open_repair_ack_commits').fetchone()[0], 1)

    def test_committed_response_loss_restarts_with_exact_last_request(self):
        self.transport.drop_kind = 'ack.index_publish'
        with self.assertRaises(MemoryError):
            self.publish()
        before = list(self.transport.calls)
        self.assertEqual(len(self.http.lookup()['entries']), 1)
        self.f.h.db.close(); self.f.h.connect(); self.make_client()
        result = self.publish()
        self.assertEqual(self.transport.calls[len(before):], [('ack.index_publish', before[-1][1])])
        self.assertEqual(result.metrics['requests'], 1)
        self.assertEqual(result.state, 'advertised')
        self.assertFalse(result.metrics['from_local_history'])

    def test_lost_response_retries_exact_request_after_automatic_source_node_renewal(self):
        from pathlib import Path
        from memory_vault_open_control import issue_node
        from memory_vault_open_node import _NodePublication
        from memory_vault_trust import _write_new_private

        old = self.f.f['docs']['descriptor']['payload']
        descriptor = issue_node(self.f.f['signers']['target'], base_url=old['base_url'],
            storage_epoch=old['storage_epoch'], roles=old['roles'], revision=old['revision'] + 1,
            issued_at=self.f.at - 1, expires_at=self.f.at + 301)
        directory = Path(self.f.h.temp.name) / 'node-publication'
        directory.mkdir(mode=0o700)
        storage = directory / 'state'
        storage.mkdir(mode=0o700)
        path = directory / 'node-config.json'
        config = dict(node=descriptor, state_directory=str(storage), allow_loopback=True)
        _write_new_private(path, canonical_bytes(config))
        publication = _NodePublication(path, config, self.f.f['signers']['target'])
        self.f.f['docs']['descriptor'] = publication.refresh()
        self.f.h.db.close(); self.f.h.connect(); self.make_client()
        self.transport.drop_kind = 'ack.index_publish'
        with self.assertRaises(MemoryError):
            self.publish()
        before = list(self.transport.calls)
        snapshot = self.client.journal.snapshot(self.f.h.resource_id)
        self.assertEqual(len(self.http.lookup()['entries']), 1)

        # The real node renewal implementation persists the next signed
        # revision as its ordinary remaining-lifetime threshold is crossed.
        self.f.h.now[0] = self.f.at + 2
        with patch('time.time', return_value=self.f.at + 2):
            renewed = publication.refresh()
            self.assertEqual(renewed['payload']['revision'], descriptor['payload']['revision'] + 1)
            self.assertEqual(json.loads(path.read_bytes())['node'], renewed)
            self.assertGreater(descriptor['payload']['expires_at'], self.f.h.now[0])
            self.f.f['docs']['descriptor'] = renewed
            self.f.h.db.close(); self.f.h.connect(); self.make_client()
            result = self.publish()
        self.assertEqual(self.transport.calls[len(before):], [('ack.index_publish', before[-1][1])])
        self.assertEqual(result.state, 'advertised')
        after = self.client.journal.snapshot(self.f.h.resource_id)
        self.assertEqual(after['plan'], snapshot['plan'])
        self.assertEqual(after['deadline'], snapshot['deadline'])
        self.assertEqual(after['maximum_bytes'], snapshot['maximum_bytes'])
        self.assertGreater(after['attempts'], snapshot['attempts'])

    def test_cached_result_is_historical_and_expired_session_sends_nothing(self):
        result = self.publish()
        before = len(self.transport.calls)
        cached = self.publish()
        self.assertEqual(len(self.transport.calls), before)
        self.assertEqual(cached.index_lease, result.index_lease)
        self.assertTrue(cached.metrics['from_local_history'])
        self.assertFalse(cached.metrics['usable'])
        self.f.h.now[0] += 61
        with self.assertRaisesRegex(wire.RepairWireError, 'repair_access_expired'):
            self.publish()
        self.assertEqual(len(self.transport.calls), before)

    def test_source_builds_its_own_allocation_for_a_new_exactly_consented_directory_job(self):
        self.f.intent = dict(self.f.intent, allocation_id='new_network_allocation', job_id='new_network_job')
        intent_hash = hashlib.sha256(canonical_bytes(self.f.intent)).hexdigest()
        changes = {}
        for role in ('owner', 'writer'):
            old = self.f.consents[role]
            p = json.loads(old['raw'])['payload']
            p['reservation_disclosure']['intent_sha256'] = intent_hash
            updated = signed_entry(p, self.f.f['signers'][role], 'new_network_consent_' + role)
            changes[self.f.authority(old, 'ack.index_consent')] = self.f.authority(updated, 'ack.index_consent')
            self.f.consents[role] = updated
        current = []
        for item in self.f.current:
            p = json.loads(item['raw'])['payload']
            changed = False
            for scope in p['entries']:
                if scope['scope_id'] in changes:
                    scope['scope_id'] = changes[scope['scope_id']]
                    changed = True
            if changed:
                p['revision'] += 1
                p['entries'].sort(key=lambda e: (e['scope_kind'], e['scope_id']))
                signer = next(s for s in self.f.f['signers'].values() if s.key_id == p['signing_key']['key_id'])
                item = signed_entry(p, signer, 'new_network_current_' + signer.key_id)
            current.append(item)
        self.f.current = current
        result = self.publish(allocation_entry=None)
        self.assertEqual(result.state, 'advertised')
        raw = next(raw for kind, raw in self.transport.calls if kind == 'ack.index_allocate')
        import base64
        encoded = json.loads(raw)['allocation']['raw_base64url']
        allocation = json.loads(base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)))['payload']
        self.assertEqual(allocation['intent']['allocation_id'], 'new_network_allocation')
        self.assertEqual(allocation['signing_key']['key_id'], self.f.publisher['signing_key']['key_id'])

    def test_recipient_publication_revoke_is_persisted_and_stops_before_any_network(self):
        revoked = copy.deepcopy(self.f.current)
        wanted = self.f.authority(self.f.consents['writer'], 'ack.index_consent')
        for i, item in enumerate(revoked):
            p = json.loads(item['raw'])['payload']
            if (p['signing_key']['key_id'] == self.f.f['signers']['writer'].key_id
                    and any(e['scope_id'] == wanted for e in p['entries'])):
                p['revision'] += 1
                next(e for e in p['entries'] if e['scope_id'] == wanted).update(status='revoked', operation_mask=16)
                revoked[i] = signed_entry(p, self.f.f['signers']['writer'], 'new-publication-revoked')
        with self.assertRaisesRegex(wire.RepairWireError, 'repair_authority_revoked'):
            self.publish(current_statuses=revoked)
        self.assertEqual(self.transport.calls, [])
        self.f.h.db.close(); self.f.h.connect(); self.make_client()
        with self.assertRaisesRegex(wire.RepairWireError, 'repair_authority_revoked'):
            self.publish()
        self.assertEqual(self.transport.calls, [])

    def test_wrong_signed_directory_nonce_sends_no_private_descriptor(self):
        import memory_vault_open_provider_state as provider_state
        solve = provider_state.answer_target_challenge
        def wrong(signer, encryption_identity, **kwargs):
            answer = solve(signer, encryption_identity, **kwargs)
            p = dict(answer['payload'], answer='A' * 43)
            return dict(payload=p, proof=signer.sign_message(p))
        with patch.object(provider_state, 'answer_target_challenge', new=wrong):
            with self.assertRaisesRegex(wire.RepairWireError, 'repair_provider_proof_mismatch'):
                self.publish()
        self.assertEqual([kind for kind, _ in self.transport.calls], ['target.get', 'target.answer'])

    def test_assignment_revoke_between_frames_survives_restart_and_stops_upload(self):
        fired = []
        def revoke(kind):
            if kind != 'proof.stage_child' or fired:
                return
            fired.append(True)
            checked = self.access.assignment(self.client.prepared)
            current = []
            for item in checked.statuses:
                if item.payload['scope_key']['issuer_key_id'] == self.f.directory.key_id:
                    current.append(dict(raw=item.raw, ref=item.ref.as_dict()))
            old = self.client.journal.saved_artifact(self.f.h.resource_id, 'assignment_status')
            payload = json.loads(bytes(old['raw']))['payload']
            payload['revision'] += 1
            payload['entries'][0]['status'] = 'revoked'
            current.append(signed_entry(payload, self.f.f['signers']['target'], 'assignment-revocation'))
            prepared = self.access.prepare_assignment(self.client.prepared,
                allocation_entry=dict(raw=checked.allocation.raw, ref=checked.allocation.ref.as_dict()),
                offer_entry=dict(raw=checked.offer.raw, ref=checked.offer.ref.as_dict()),
                assignment_entry=dict(raw=checked.assignment.raw, ref=checked.assignment.ref.as_dict()), directory_statuses=current)
            with self.f.h.state._transaction():
                self.assertFalse(self.access.check_locked(prepared).allowed)
        self.transport.after_response = revoke
        with self.assertRaisesRegex(wire.RepairWireError, 'repair_authority_revoked'):
            self.publish()
        self.assertEqual(sum(kind == 'proof.stage_child' for kind, _ in self.transport.calls), 1)
        before = len(self.transport.calls)
        self.f.h.db.close(); self.f.h.connect(); self.make_client()
        with self.assertRaisesRegex(wire.RepairWireError, 'repair_authority_revoked|repair_status_rollback'):
            self.publish()
        self.assertEqual(len(self.transport.calls), before)
        self.assertEqual(self.http.lookup()['entries'], [])

    def test_original_small_signature_grant_refuses_without_being_enlarged(self):
        case = AckIndexPublicationClientTests()
        case.workflow_limits = dict(INDEX_WORKFLOW_LIMITS, max_signature_checks=64)
        case.setUp()
        self.addCleanup(case.doCleanups)
        with self.assertRaisesRegex(wire.RepairWireError, 'repair_index_job_capacity'):
            case.publish()
        self.assertEqual(case.transport.calls, [])
        stored = case.f.h.db.execute('SELECT activation_inputs FROM open_repair_ack_resources').fetchone()[0]
        self.assertEqual(json.loads(json.loads(bytes(stored))['bootstrap']['raw'])['payload']['limits']['max_signature_checks'], 64)


if __name__ == '__main__':
    unittest.main()
