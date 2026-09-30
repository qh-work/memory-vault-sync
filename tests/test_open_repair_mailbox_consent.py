"""Each participant signs only its own bounded reservation from real source history."""
import copy
import json
import sqlite3
import unittest

from memory_vault import canonical_bytes
from memory_vault_network_crypto import b64url, unb64url
from memory_vault_open_provider import issue_status
from memory_vault_open_repair_mailbox_consent import BUNDLE_SCHEMA, MailboxReservationConsentSigner
from memory_vault_open_repair_mailbox_copy_prepare import MailboxRootCopyPreparation
import memory_vault_open_repair_wire as wire
from tests import test_open_repair_mailbox_reservation as fixtures
from tests.test_open_repair_status import status_entry


def encoded(entry):
    return dict(raw_base64url=b64url(entry['raw']), ref=entry['ref'])


def decoded(entry):
    return dict(raw=unb64url(entry['raw_base64url'], maximum=2_000_000), ref=entry['ref'])


class MailboxConsentTests(unittest.TestCase):
    def setUp(self):
        self.material = fixtures.MailboxReservationTests(); self.material.setUp(); self.addCleanup(self.material.doCleanups)
        h = self.h = self.material.h
        self.expected = dict(root_key=h.root_key, owner=h.owner, source=h.source.target,
            source_storage_epoch=h.source.node['payload']['storage_epoch'], maintainer=h.source.target,
            intent=self.material.intent)
        allowed = {(e['scope_kind'], e['scope_id']) for item in h.event['statuses'] for e in item.payload['entries']}
        self.statuses = []
        for entry, signer in zip(self.material.statuses, (h.owner_signer, h.source.identity)):
            payload = json.loads(entry['raw'])['payload']
            self.statuses.append(status_entry(issue_status(signer, root=h.root_key, revision=3,
                entries=[e for e in payload['entries'] if (e['scope_kind'], e['scope_id']) in allowed],
                issued_at=h.now, valid_until=h.until)))
        self.bundle = dict(schema_version=BUNDLE_SCHEMA, kind='root', expected=self.expected,
            manifest=encoded(h.saved['manifest']), custody=encoded(h.custody),
            originals=[encoded(h.saved['pack'])], current_statuses=[encoded(e) for e in self.statuses])
        self.path = self.material.path.parent/'consent.sqlite3'
        self.connect(); self.addCleanup(lambda:self.db.close())

    def connect(self):
        self.db = sqlite3.connect(self.path)
        self.signer = MailboxReservationConsentSigner(self.h.owner_signer, self.h.h.host.h.f['encryption']['owner'],
            self.db, policy=self.h.source.policy, limit_policy=self.h.source.limits, clock=lambda:self.h.now)

    def sign(self, **options):
        return self.signer.sign_reservation(self.bundle, expected=self.expected, variant='owner',
            consent_id='synthetic_independent_owner', expires_at=self.h.until, **options)

    def test_independent_consent_drives_real_reservation_and_survives_restart(self):
        result = self.sign()
        reservation = decoded(result['consent'])
        self.assertEqual(json.loads(reservation['raw'])['payload']['signing_key'], self.h.owner['signing_key'])
        self.db.close(); self.connect()
        self.assertEqual(self.sign(), result)
        m = self.material
        m.reservation = reservation
        prepared = m.prepare(current_statuses=[*self.statuses, decoded(result['reservation_status'])])
        offer = self.h.resources.allocate(prepared['allocation'], expected_caller=self.h.source.target)
        assigned = m.prepare(current_statuses=[*self.statuses, decoded(result['reservation_status'])], offer_entry=offer)
        self.assertEqual(json.loads(assigned['assignment']['raw'])['payload']['operation_mask'], 70)

    def test_owner_command_keeps_keys_and_drives_http_reservation_after_lost_reply(self):
        import contextlib, io, stat
        from types import SimpleNamespace
        from unittest.mock import patch
        from memory_vault_open_repair_mailbox_consent import main
        from memory_vault_trust import _write_new_private
        from tests import test_open_repair_admin as admin_fixture
        original = self.h.h.host.h
        host = admin_fixture._AdminFixture()
        host.host = SimpleNamespace(source=SimpleNamespace(temp=original.folder, fixture=original.f))
        host.configure_owner('owner')
        bundle = host.directory/'consent-bundle.json'; expected = host.directory/'consent-expected.json'
        output = host.directory/'signed-consent.json'
        _write_new_private(bundle, canonical_bytes(self.bundle))
        _write_new_private(expected, canonical_bytes(self.expected))
        args = ['sign', '--network-config', str(host.network), '--bundle', str(bundle), '--expected', str(expected),
            '--variant', 'owner', '--consent-id', 'synthetic_command_consent', '--expires-at', str(self.h.until), '--output', str(output)]
        with patch('time.time', return_value=self.h.now), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(args), 0)
        result = json.loads(output.read_bytes())
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        self.assertEqual({p:p.read_bytes() for p in host.originals}, host.originals)
        self.assertFalse(host.vault.exists())
        error = io.StringIO()
        with contextlib.redirect_stderr(error): self.assertEqual(main(args), 1)
        self.assertEqual(json.loads(error.getvalue())['error'], 'repair_output_exists')
        maintainer = admin_fixture._AdminFixture()
        parent = self.material.path.parent/'maintainer'; parent.mkdir(mode=0o700)
        maintainer.host = SimpleNamespace(source=SimpleNamespace(temp=SimpleNamespace(name=str(parent)), fixture=original.f))
        maintainer.configure_owner('target')
        node = maintainer.directory/'node-entry.json'; assembled_path = maintainer.directory/'assembled.json'
        raw = canonical_bytes(self.h.p.state.node)
        import hashlib
        digest = hashlib.sha256(raw).hexdigest()
        _write_new_private(node, canonical_bytes(encoded(dict(raw=raw, ref=dict(namespace='meta', key=digest, raw_sha256=digest, size=len(raw))))))
        with patch('time.time', return_value=self.h.now), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(['assemble', '--network-config', str(maintainer.network),
                '--bundle', str(bundle), '--expected', str(expected), '--node', str(node),
                '--owner-consent', str(output), '--output', str(assembled_path)]), 0)
        assembled = json.loads(assembled_path.read_bytes())
        self.assertEqual(assembled['schema_version'], 'memory-vault-open-mailbox-root-copy-reservation-request/v1')
        self.assertEqual(stat.S_IMODE(assembled_path.stat().st_mode), 0o600)
        self.assertEqual({p:p.read_bytes() for p in maintainer.originals}, maintainer.originals)
        self.assertFalse(maintainer.vault.exists())
        self.material.reservation = decoded(assembled['reservation'])
        self.material.statuses = [decoded(e) for e in assembled['current_statuses']]
        self.material.test_http_reservation_reuses_real_capacity_after_lost_reply_and_both_restarts()

    def test_changed_expectation_or_reused_id_cannot_sign_new_target(self):
        self.sign()
        changed = copy.deepcopy(self.expected); changed['intent']['job_id'] = 'synthetic_other_job'
        with self.assertRaises(wire.RepairWireError):
            self.signer.sign_reservation(self.bundle, expected=changed, variant='owner',
                consent_id='synthetic_other', expires_at=self.h.until)
        self.bundle['expected'] = changed; self.expected = changed
        with self.assertRaises(wire.RepairWireError): self.sign()
        self.assertEqual(self.db.execute('SELECT count(*) FROM open_mailbox_reservation_consents').fetchone()[0], 1)

    def test_revocation_before_bad_sibling_survives_restart_and_denies_cached_consent(self):
        result = self.sign()
        payload = json.loads(decoded(result['reservation_status'])['raw'])['payload']
        revoked = status_entry(issue_status(self.h.owner_signer, root=self.h.root_key, revision=payload['revision']+1,
            entries=[dict(payload['entries'][0], status='revoked')], issued_at=self.h.now, valid_until=self.h.until))
        with self.assertRaises(wire.RepairWireError):
            self.sign(known_statuses=[encoded(revoked), dict(raw_base64url=b64url(b'{}'), ref=revoked['ref'])])
        self.db.close(); self.connect()
        with self.assertRaises(wire.RepairWireError): self.sign()


class MailboxFeedConsentTests(unittest.TestCase):
    def test_feed_owner_and_sender_consent_produces_actual_capacity(self):
        self.run_flow(False)

    def test_message_owner_and_sender_consent_produces_actual_capacity(self):
        self.run_flow(True)

    def run_flow(self, message):
        from unittest.mock import patch
        from tests import test_open_delivery_http as delivery_fixture
        from tests.test_open_repair_mailbox_feed_copy import FeedCopyFixture
        from memory_vault_open_repair_mailbox_copy_prepare import MailboxFeedCopyPreparation, MailboxMessageCopyPreparation
        fixture = delivery_fixture.MailboxStagingHTTPTests('test_actual_delivery_stages_exact_ciphertext_under_mailbox_resources')
        fixture.setUp(); self.addCleanup(fixture.doCleanups)
        def receive(staging, slot, head):
            h = FeedCopyFixture(self, fixture, staging, slot, head, message=message)
            kind = 'message' if message else 'feed'
            intent = json.loads(canonical_bytes(h.intent))
            intent.update(job_id='synthetic_participant_job', allocation_id='synthetic_participant_allocation')
            expected = dict(root_key=h.root, owner=h.owner, sender=h.sender, slot_key=h.slot,
                source=h.source.target, source_storage_epoch=h.source.node['payload']['storage_epoch'],
                maintainer=h.source.target, intent=intent)
            if message: expected['envelope_ref'] = h.envelope_ref
            historical = (*h.event['graph']['statuses'], *(item for member in h.event['graph']['members'] for item in member['statuses']))
            allowed = {(item.payload['signing_key']['key_id'], e['scope_kind'], e['scope_id']) for item in historical for e in item.payload['entries']}
            current = []
            for entry, role in zip(h.statuses, ('owner', 'sender', 'source')):
                p = json.loads(entry['raw'])['payload']; signer = h.signers[role]
                current.append(status_entry(issue_status(signer, root=h.root, revision=p['revision'],
                    entries=[e for e in p['entries'] if (signer.key_id, e['scope_kind'], e['scope_id']) in allowed],
                    issued_at=h.now, valid_until=h.until)))
            bundle = dict(schema_version=BUNDLE_SCHEMA, kind=kind, expected=expected,
                manifest=encoded(h.manifest), custody=encoded(h.custody),
                originals=[encoded(h.entry(ref)) for role, ref in h.part.transfer if role == 'history.raw_pack'],
                current_statuses=[encoded(e) for e in current])
            results = {}
            with patch('time.time', return_value=h.now):
                for variant, agent in (('owner', fixture.b), ('sender', fixture.a)):
                    with agent._network() as network, network.participant.state.db() as db:
                        signer = MailboxReservationConsentSigner(network.identity, network.encryption, db,
                            policy=h.policy, limit_policy=h.limits, clock=lambda:h.now)
                        options = dict(expected=expected, variant=variant, consent_id='synthetic_independent_'+variant, expires_at=h.until)
                        results[variant] = signer.sign_reservation(bundle, **options)
                        self.assertEqual(signer.sign_reservation(bundle, **options), results[variant])
                        with self.assertRaises(wire.RepairWireError):
                            signer.sign_reservation(bundle, **dict(options, variant='sender' if variant == 'owner' else 'owner'))
                journal_type = MailboxMessageCopyPreparation if message else MailboxFeedCopyPreparation
                db = sqlite3.connect(h.directory/'maintainer-consent.sqlite3'); self.addCleanup(db.close)
                journal = journal_type(db, h.source.identity, h.source.encryption_identity, policy=h.policy); journal.initialize()
                context = h.context(); context.pop('expected_maintainer')
                context.update(current_statuses=[*current, *(decoded(r['reservation_status']) for r in results.values())],
                    at=h.now, sender_reservation_entry=decoded(results['sender']['consent']))
                from memory_vault_open_repair_mailbox_consent import assemble_reservation
                assembled = assemble_reservation(journal, bundle, expected=expected,
                    node=encoded(h.wrap(canonical_bytes(h.node))), owner_result=results['owner'], sender_result=results['sender'],
                    at=h.now, limit_policy=h.limits)
                self.assertEqual(assembled['reservation'], results['owner']['consent'])
                self.assertEqual(assembled['sender_reservation'], results['sender']['consent'])
                args = (h.manifest, h.resolver(), h.custody, decoded(results['owner']['consent']), intent)
                prepared = journal.prepare_reservation(*args, **context)
                offer = h.store.allocate(prepared['allocation'], expected_caller=h.source.target)
                assigned = journal.prepare_reservation(h.manifest, h.resolver(), h.custody,
                    decoded(results['owner']['consent']), intent, offer_entry=offer, **context)
                self.assertEqual(json.loads(assigned['assignment']['raw'])['payload']['scope'], intent['scope'])
        fixture.inspect_committed_mailbox = receive
        fixture.test_actual_delivery_stages_exact_ciphertext_under_mailbox_resources()


if __name__ == '__main__': unittest.main()
