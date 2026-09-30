"""Participant-local permission to disclose one exact mailbox replica intent.

Each owner/sender uses its existing keys and transport DB. Signing reserves no
remote capacity, transmits nothing and grants no upload or replica return.
"""
import hashlib
import json

from memory_vault import canonical_bytes
from memory_vault_open_repair_copy_prepare import CONSENT_FIELDS, _require
from memory_vault_open_repair_index_prepare import AckIndexConsentSigner, _signed_entry, _encoded, _decoded, _table
from memory_vault_open_repair_mailbox_reservation import reservation_context
from memory_vault_open_repair_state import DEFAULT_POLICY, MAILBOX_WORKFLOW_LIMITS
import memory_vault_open_repair_empty as empty
import memory_vault_open_repair_index as index
import memory_vault_open_repair_resource as resource
import memory_vault_open_repair_status as status
import memory_vault_open_repair_wire as wire

BUNDLE_SCHEMA = 'memory-vault-open-mailbox-reservation-preparation/v1'
RESULT_SCHEMA = 'memory-vault-open-mailbox-reservation-consent/v1'


class MailboxReservationConsentSigner(AckIndexConsentSigner):
    """Reuse principal binding, observed-status storage and shared issuer sequence.

    The inherited ACK signing/renewal path is never invoked. Mailbox outputs have
    their own bounded journal and are checked against original mailbox history.
    """
    def __init__(self, identity, encryption_identity, protected_db, **kwargs):
        if (_table(protected_db, 'open_mailbox_reservation_consents')
                and protected_db.execute('SELECT 1 FROM open_mailbox_reservation_consents LIMIT 1').fetchone()
                and (not _table(protected_db, 'open_repair_index_signer_meta') or not protected_db.execute(
                    "SELECT 1 FROM open_repair_index_signer_meta WHERE name='binding'").fetchone())):
            wire._fail('repair_index_signer_binding_missing')
        kwargs.setdefault('limit_policy', MAILBOX_WORKFLOW_LIMITS)
        super().__init__(identity, encryption_identity, protected_db, **kwargs)
        with self._transaction():
            self.db.execute('''CREATE TABLE IF NOT EXISTS open_mailbox_reservation_consents(
                root_digest TEXT NOT NULL, consent_id TEXT NOT NULL,
                request_digest TEXT NOT NULL, issued_at INTEGER NOT NULL,
                status_revision INTEGER NOT NULL, raw BLOB,
                PRIMARY KEY(root_digest,consent_id))''')

    def _archive(self, root, signers, meter):
        digest = hashlib.sha256(canonical_bytes(root)).hexdigest()
        rows = self.db.execute('SELECT raw,ref FROM open_repair_index_signer_statuses WHERE root_digest=?', (digest,)).fetchall()
        if len(rows) > 32: wire._fail('repair_index_preparation_capacity')
        result = []
        for raw, ref in rows:
            entry = dict(raw=bytes(raw), ref=json.loads(bytes(ref)))
            p = wire.parse_new_wire(entry['raw'], self.policy, meter).value['payload']
            issuer = p['signing_key']['key_id']
            if issuer not in signers: continue
            result.append(status.authenticate_status_original(entry, expected_root=root,
                expected_signing_key=signers[issuer], at=p['issued_at'],
                allowed_scopes=[dict(scope_kind=e['scope_kind'], scope_id=e['scope_id']) for e in p['entries']],
                policy=self.policy, budget=meter))
        return digest, result, len(rows)

    def _check(self, root_digest, historical, previous, current, needs, version):
        if self.db.execute('SELECT count(*) FROM open_repair_index_signer_statuses WHERE root_digest=?', (root_digest,)).fetchone()[0] != version:
            wire._fail('repair_index_preparation_changed')
        blocked = self.db.execute("SELECT value FROM open_repair_index_signer_meta WHERE name=?", ('blocked:'+root_digest,)).fetchone()
        if blocked: wire._fail(blocked[0])
        empty._history_floors((*historical, *previous, *current), previous=(*historical, *previous), current=current)
        required = {(n['signer']['key_id'], n['scope_kind'], n['scope_id']): n for n in needs}
        for need in needs:
            matches = [e for item in current if item.payload['signing_key'] == need['signer']
                for e in item.payload['entries'] if (e['scope_kind'], e['scope_id']) == (need['scope_kind'], need['scope_id'])]
            if not matches: wire._fail('repair_status_missing')
            for e in matches:
                if e['status'] == 'revoked': wire._fail('repair_authority_revoked')
                if e['minimum_document_revision'] > need['revision']: wire._fail('repair_status_revision')
                if e['operation_mask'] & need['mask'] != need['mask']: wire._fail('repair_status_operation')
        for item in (*historical, *previous):
            for e in item.payload['entries']:
                need = required.get((item.payload['signing_key']['key_id'], e['scope_kind'], e['scope_id']))
                if need and e['status'] == 'revoked' and e['operation_mask'] & need['mask']:
                    wire._fail('repair_authority_revoked')
                if need and e['minimum_document_revision'] > need['revision']: wire._fail('repair_status_revision')
        for table in ('open_repair_access_floors', 'open_repair_index_floors', 'open_provider_status'):
            if not _table(self.db, table): continue
            columns = {r[1] for r in self.db.execute('PRAGMA table_info('+table+')')}
            if not {'issuer', 'root_digest', 'scope_kind', 'scope_id', 'revision', 'revoked_mask', 'conflict'} <= columns: continue
            minimum = 'minimum_revision' if 'minimum_revision' in columns else '0'
            for issuer, kind, scope, rev, floor, revoked, conflict in self.db.execute(
                    'SELECT issuer,scope_kind,scope_id,revision,'+minimum+',revoked_mask,conflict FROM '+table+' WHERE root_digest=?', (root_digest,)):
                need = required.get((issuer, kind, scope))
                if not need: continue
                if conflict: wire._fail('repair_status_conflict')
                if floor > need['revision']: wire._fail('repair_status_revision')
                if revoked & need['mask']: wire._fail('repair_authority_revoked')
                observed = max((v.payload['revision'] for v in current if v.payload['signing_key']['key_id'] == issuer
                    and any((e['scope_kind'], e['scope_id']) == (kind, scope) for e in v.payload['entries'])), default=0)
                if rev > observed: wire._fail('repair_status_rollback')

    def sign_reservation(self, bundle, *, expected, variant, consent_id, expires_at, known_statuses=()):
        policy = self.policy; meter = wire.RepairBudget(policy); now = wire.u53(int(self.clock()))
        value = wire.build_new_wire(bundle, policy, meter).value
        wire.object_fields(value, {'schema_version', 'kind', 'expected', 'manifest', 'custody', 'originals', 'current_statuses'})
        _require(value['schema_version'] == BUNDLE_SCHEMA and value['kind'] in ('root', 'feed', 'message'))
        kind = value['kind']; feed = kind != 'root'
        expected = wire.build_new_wire(expected, policy, meter).value
        wire.object_fields(expected, {'root_key', 'owner', 'source', 'source_storage_epoch', 'maintainer', 'intent'}
            | ({'slot_key', 'sender'} if feed else set()) | ({'envelope_ref'} if kind == 'message' else set()))
        _require(value['expected'] == expected and variant in (('owner', 'sender') if feed else ('owner',)))
        if self.subject != expected[variant]: wire._fail('repair_index_signer_identity')
        resource._opaque(consent_id); wire.u53(expires_at)
        from memory_vault_open_repair_copy_resources import INTENT_FIELDS
        resource._fields(expected['intent'], INTENT_FIELDS)
        _require(expected['intent']['root_key'] == expected['root_key'])
        if not isinstance(value['originals'], (list, wire._DraftList)) or not 1 <= len(value['originals']) <= 64:
            wire._fail('repair_invalid_request_bundle')
        resolver = wire.LocalRawResolver(policy, meter)
        for item in value['originals']:
            entry = _decoded(item, policy, meter); ref = wire.raw_ref(entry['ref'])
            _require(resolver.put(ref.namespace, ref.key, entry['raw']).ref == ref)
        selection = dict(expected_slot=expected['slot_key'], expected_sender=expected['sender']) if feed else dict(expected_root=expected['root_key'])
        if kind == 'message': selection['expected_envelope_ref'] = expected['envelope_ref']
        plan = reservation_context(_decoded(value['manifest'], policy, meter), resolver,
            _decoded(value['custody'], policy, meter), expected['intent'], maintainer=expected['maintainer'],
            purpose=kind+'_replica', expected_owner=expected['owner'], expected_source=expected['source'],
            source_storage_epoch=expected['source_storage_epoch'], selection=selection, at=now, limit_policy=self.limits)
        if not now < expires_at <= plan['maximum']: wire._fail('repair_access_expired')
        root = plan['root_key']; context = plan['context']; signers = plan['signers']
        root_digest, previous, version = self._archive(root, signers, meter)
        historical = plan['historical']; current = []; denial = None
        supplied = value['current_statuses']
        if not isinstance(supplied, (list, wire._DraftList)) or not 1 <= len(supplied) <= 16 or type(known_statuses) not in (list, tuple) or len(known_statuses) > 32:
            wire._fail('repair_status_missing')
        def observe(item):
            nonlocal version
            version = self._observe(root_digest, (item,), meter, version)
        # Archive each authenticated observation before rejecting another input.
        for entries, is_current in ((known_statuses, False), (supplied, True)):
            for encoded in entries:
                try:
                    entry = _decoded(encoded, policy, meter)
                    p = wire.parse_new_wire(entry['raw'], policy, meter).value['payload']
                    issuer = p['signing_key']['key_id']
                    if issuer not in signers: wire._fail('repair_status_disclosure')
                    # Locally supplied history grants nothing. Current scopes
                    # must come from authenticated source history.
                    allowed = plan['allowed'][issuer] if is_current else [dict(scope_kind=e['scope_kind'], scope_id=e['scope_id']) for e in p['entries']]
                    item = status.authenticate_status_original(entry, expected_root=root, expected_signing_key=signers[issuer],
                        at=now if is_current else p['issued_at'], allowed_scopes=allowed, policy=policy, budget=meter, on_authenticated=observe)
                    (current if is_current else previous).append(item)
                except (KeyError, TypeError): denial = denial or 'repair_invalid_status'
                except wire.RepairWireError as exc: denial = denial or exc.code
        if denial: wire._fail(denial)
        if len({item.ref for item in current}) != len(current): wire._fail('repair_duplicate_status')
        self._check(root_digest, historical, previous, current, plan['needs'], version)
        until = min(expires_at, *(item.payload['valid_until'] for item in current))
        request = dict(kind=kind, expected=expected, variant=variant, consent_id=consent_id,
            expires_at=expires_at, manifest=value['manifest']['ref'], custody=value['custody']['ref'])
        digest = hashlib.sha256(canonical_bytes(request)).hexdigest()
        with self._transaction():
            self._check(root_digest, historical, previous, current, plan['needs'], version)
            row = self.db.execute('SELECT request_digest,issued_at,status_revision,raw FROM open_mailbox_reservation_consents WHERE root_digest=? AND consent_id=?', (root_digest, consent_id)).fetchone()
            if row is None:
                if self.db.execute('SELECT count(*) FROM open_mailbox_reservation_consents').fetchone()[0] >= 16:
                    wire._fail('repair_index_preparation_capacity')
                revision = self._reserve_revisions(root_digest, (*historical, *previous, *current), 1)[0]
                # The first validity bound is durable, including after a crash.
                row = (digest, now, revision, None)
                pending = canonical_bytes(dict(until=until))
                self.db.execute('INSERT INTO open_mailbox_reservation_consents VALUES(?,?,?,?,?,?)', (root_digest, consent_id, digest, now, revision, pending))
                raw = pending
            else:
                _require(row[0] == digest); raw = bytes(row[3])
        saved = json.loads(raw); issued, revision = row[1], row[2]
        if 'schema_version' in saved:
            result = saved
        else:
            until = saved['until']
            if not now < until: wire._fail('repair_access_expired')
            payload = dict(schema_version=resource.SCHEMA, kind=context['reservation_kind'], signing_key=self.subject['signing_key'],
                issued_at=issued, expires_at=until, consent_id=consent_id, revision=1,
                root_authority_ref=plan['root'].ref.as_dict(), source_custody_ref=context['held']['custody'].ref.as_dict(),
                historical_manifest_ref=context['historical_ref'], maintainer=plan['ids']['maintainer'],
                target=plan['parties']['target'], target_storage_epoch=expected['intent']['target_storage_epoch'],
                reservation_disclosure=dict(intent_sha256=plan['digest'], until=until))
            if feed: payload['variant'] = variant
            consent = _signed_entry(payload, self.identity, policy, meter)
            scope = status.status_scope(root, 'authority', dict(authority_kind=context['reservation_kind'], authority_sha256=consent['ref']['raw_sha256']), policy, meter)
            observation = _signed_entry(dict(schema_version=status.SCHEMA, kind='authority.status', signing_key=self.subject['signing_key'],
                scope_key=dict(root_key=root, issuer_key_id=self.identity.key_id), revision=revision, issued_at=issued, valid_until=until,
                entries=[dict(scope_kind='authority', scope_id=scope, minimum_document_revision=1, status='active', operation_mask=4)]), self.identity, policy, meter)
            result = dict(schema_version=RESULT_SCHEMA, kind=kind, variant=variant, intent_sha256=plan['digest'],
                consent=_encoded(consent, meter), reservation_status=_encoded(observation, meter))
        consent = index._signed(_decoded(result['consent'], policy, meter), self.subject['signing_key'], context['reservation_kind'],
            CONSENT_FIELDS | ({'variant'} if feed else set()), policy, meter)
        index._timed(consent.payload, now)
        p = consent.payload
        until = p['expires_at']
        expected_payload = dict(schema_version=resource.SCHEMA, kind=context['reservation_kind'], signing_key=self.subject['signing_key'],
            issued_at=issued, expires_at=until, consent_id=consent_id, revision=1,
            root_authority_ref=plan['root'].ref.as_dict(), source_custody_ref=context['held']['custody'].ref.as_dict(),
            historical_manifest_ref=context['historical_ref'], maintainer=plan['ids']['maintainer'],
            target=plan['parties']['target'], target_storage_epoch=expected['intent']['target_storage_epoch'],
            reservation_disclosure=dict(intent_sha256=plan['digest'], until=until))
        if feed: expected_payload['variant'] = variant
        _require(p == expected_payload and until <= min(expires_at, plan['maximum']))
        _require(set(result) == {'schema_version', 'kind', 'variant', 'intent_sha256', 'consent', 'reservation_status'}
            and result['schema_version'] == RESULT_SCHEMA and result['kind'] == kind
            and result['variant'] == variant and result['intent_sha256'] == plan['digest'])
        scope = index._authority(root, consent, policy, meter)
        observation = status.authenticate_status_original(_decoded(result['reservation_status'], policy, meter),
            expected_root=root, expected_signing_key=self.subject['signing_key'], at=now,
            allowed_scopes=[dict(scope_kind='authority', scope_id=scope)], policy=policy, budget=meter)
        _require(observation.payload['revision'] == revision and observation.payload['issued_at'] == issued
            and observation.payload['valid_until'] == until and observation.payload['entries'] == [dict(
                scope_kind='authority', scope_id=scope, minimum_document_revision=1, status='active', operation_mask=4)])
        needs = [*plan['needs'], index._obligation(self.subject['signing_key'], 'authority', scope, 1, 4)]
        encoded = canonical_bytes(result)
        with self._transaction():
            if int(self.clock()) >= min(until, *(item.payload['valid_until'] for item in current)):
                wire._fail('repair_access_expired')
            self._check(root_digest, historical, previous, (*current, observation), needs, version)
            total = self.db.execute('SELECT coalesce(sum(length(raw)),0) FROM open_mailbox_reservation_consents').fetchone()[0]
            existing = bytes(self.db.execute('SELECT raw FROM open_mailbox_reservation_consents WHERE root_digest=? AND consent_id=?', (root_digest, consent_id)).fetchone()[0])
            if 'schema_version' in json.loads(existing): _require(existing == encoded)
            elif total + len(encoded) > 1048576: wire._fail('repair_index_preparation_capacity')
            else: self.db.execute('UPDATE open_mailbox_reservation_consents SET raw=? WHERE root_digest=? AND consent_id=?', (encoded, root_digest, consent_id))
        return result



def assemble_reservation(journal, bundle, *, expected, node, owner_result, sender_result=None, at, limit_policy):
    """Prepare the existing reservation command from separate signed outputs."""
    from memory_vault_open_control import verify_node
    policy = journal.policy; meter = wire.RepairBudget(policy)
    value = wire.build_new_wire(bundle, policy, meter).value
    wire.object_fields(value, {'schema_version', 'kind', 'expected', 'manifest', 'custody', 'originals', 'current_statuses'})
    expected = wire.build_new_wire(expected, policy, meter).value
    _require(value['schema_version'] == BUNDLE_SCHEMA and value['expected'] == expected)
    kind = value['kind']; feed = kind in ('feed', 'message')
    _require(kind in ('root', 'feed', 'message') and journal.purpose == kind+'_replica'
        and journal.keys == expected['maintainer'] and (sender_result is not None) == feed)
    wire.object_fields(expected, {'root_key', 'owner', 'source', 'source_storage_epoch', 'maintainer', 'intent'}
        | ({'slot_key', 'sender'} if feed else set()) | ({'envelope_ref'} if kind == 'message' else set()))
    from memory_vault_open_repair_copy_resources import INTENT_FIELDS
    resource._fields(expected['intent'], INTENT_FIELDS)
    target_entry = _decoded(node, policy, meter)
    target = verify_node(target_entry['raw'], now=at)
    _require(target['signing_key'] == expected['intent']['target']['signing_key']
        and target['storage_epoch'] == expected['intent']['target_storage_epoch'])
    ref = wire.raw_ref(target_entry['ref'])
    _require(ref.namespace == 'meta' and ref.raw_sha256 == hashlib.sha256(target_entry['raw']).hexdigest() and ref.size == len(target_entry['raw']))
    reservations = {}; statuses = list(value['current_statuses'])
    digest = hashlib.sha256(canonical_bytes(expected['intent'])).hexdigest()
    for variant, result in [('owner', owner_result)] + ([('sender', sender_result)] if feed else []):
        result = wire.build_new_wire(result, policy, meter).value
        wire.object_fields(result, {'schema_version', 'kind', 'variant', 'intent_sha256', 'consent', 'reservation_status'})
        _require(result['schema_version'] == RESULT_SCHEMA and result['kind'] == kind
            and result['variant'] == variant and result['intent_sha256'] == digest)
        reservations[variant] = result['consent']; statuses.append(result['reservation_status'])
    if len(statuses) > 16 or not 1 <= len(value['originals']) <= 64: wire._fail('repair_over_budget')
    resolver = wire.LocalRawResolver(policy, meter)
    for item in value['originals']:
        entry = _decoded(item, policy, meter); ref = wire.raw_ref(entry['ref'])
        _require(resolver.put(ref.namespace, ref.key, entry['raw']).ref == ref)
    context = dict(expected_owner=expected['owner'], expected_source=expected['source'],
        source_storage_epoch=expected['source_storage_epoch'], at=at, limit_policy=limit_policy,
        current_statuses=[_decoded(item, policy, meter) for item in statuses])
    if feed:
        context.update(expected_slot=expected['slot_key'], expected_sender=expected['sender'],
            sender_reservation_entry=_decoded(reservations['sender'], policy, meter))
    else: context['expected_root'] = expected['root_key']
    if kind == 'message': context['expected_envelope_ref'] = expected['envelope_ref']
    journal.prepare_reservation(_decoded(value['manifest'], policy, meter), resolver,
        _decoded(value['custody'], policy, meter), _decoded(reservations['owner'], policy, meter), expected['intent'], **context)
    result = {k: expected[k] for k in expected if k != 'maintainer'}
    result.update(schema_version='memory-vault-open-mailbox-'+kind+'-copy-reservation-request/v1', node=node,
        manifest=value['manifest'], custody=value['custody'], originals=value['originals'],
        current_statuses=statuses, reservation=reservations['owner'])
    if feed: result['sender_reservation'] = reservations['sender']
    return json.loads(canonical_bytes(result))


def main(argv=None):
    import argparse
    import sqlite3
    import sys
    import time
    from pathlib import Path
    from memory_vault import MemoryError
    from memory_vault_network_crypto import document, object_fields
    from memory_vault_open_client import OpenNetworkClient
    from memory_vault_open_repair_admin import MAX_COPY_BUNDLE_BYTES
    from memory_vault_open_repair_index_prepare_admin import _new_output, _write
    from memory_vault_trust import TrustError, _absolute_path, _read_private
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    sign = commands.add_parser('sign', help='owner or sender signs only its own bounded reservation consent')
    sign.add_argument('--variant', choices=('owner', 'sender'), required=True)
    sign.add_argument('--consent-id', required=True)
    sign.add_argument('--expires-at', type=int, required=True)
    sign.add_argument('--known-statuses', type=Path)
    assemble = commands.add_parser('assemble', help='maintainer prepares the existing reservation request from independent consents')
    assemble.add_argument('--node', type=Path, required=True, help='current public signed node as an encoded original entry')
    assemble.add_argument('--owner-consent', type=Path, required=True)
    assemble.add_argument('--sender-consent', type=Path)
    for command in (sign, assemble):
        command.add_argument('--network-config', type=Path, required=True)
        command.add_argument('--bundle', type=Path, required=True)
        command.add_argument('--expected', type=Path, required=True, help='independently selected source, participants and full bounded destination intent')
        command.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    def read(path):
        raw = _read_private(_absolute_path(path), MAX_COPY_BUNDLE_BYTES)
        if raw is None: wire._fail('repair_request_missing')
        return document(raw, maximum=MAX_COPY_BUNDLE_BYTES)
    try:
        output = _new_output(args.output)
        bundle, expected = read(args.bundle), read(args.expected)
        with OpenNetworkClient(_absolute_path(args.network_config)) as network, network.participant.state.db() as db:
            if args.command == 'sign':
                known = [] if args.known_statuses is None else object_fields(read(args.known_statuses), {'known_statuses'})['known_statuses']
                signer = MailboxReservationConsentSigner(network.identity, network.encryption, db)
                result = signer.sign_reservation(bundle, expected=expected, variant=args.variant,
                    consent_id=args.consent_id, expires_at=args.expires_at, known_statuses=known)
                state = 'mailbox_reservation_consent_signed'
            else:
                from memory_vault_open_repair_mailbox_copy_prepare import MailboxRootCopyPreparation, MailboxFeedCopyPreparation, MailboxMessageCopyPreparation
                classes = dict(root=MailboxRootCopyPreparation, feed=MailboxFeedCopyPreparation, message=MailboxMessageCopyPreparation)
                if type(bundle.get('kind')) is not str or bundle['kind'] not in classes: wire._fail('repair_invalid_request_bundle')
                journal = classes[bundle['kind']](db, network.identity, network.encryption, policy=DEFAULT_POLICY); journal.initialize()
                result = assemble_reservation(journal, bundle, expected=expected, node=read(args.node),
                    owner_result=read(args.owner_consent), sender_result=None if args.sender_consent is None else read(args.sender_consent),
                    at=int(time.time()), limit_policy=MAILBOX_WORKFLOW_LIMITS)
                state = 'mailbox_reservation_request_prepared'
        answer = _write(output, result, state)
    except (MemoryError, TrustError, wire.RepairWireError, OSError, sqlite3.Error) as exc:
        print(json.dumps(dict(error=getattr(exc, 'code', 'repair_storage_unavailable'))), file=sys.stderr)
        return 1
    print(json.dumps(answer, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
