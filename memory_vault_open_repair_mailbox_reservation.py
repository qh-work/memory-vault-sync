"""Maintainer-local mailbox copy reservations from exact original consent.

Preparation does not allocate remote capacity. Owner/sender permissions precede
disclosure of the opaque intent; a real destination offer precedes assignment.
The existing caller-bound journal retains requests and authenticated denials.
"""
import hashlib
import json

from memory_vault import canonical_bytes
from memory_vault_open_repair_copy_prepare import CONSENT_FIELDS, _require
from memory_vault_open_repair_copy_resources import INTENT_FIELDS
from memory_vault_open_repair_mailbox_copy import mailbox_copy_scope
import memory_vault_open_repair_empty as empty
import memory_vault_open_repair_history as history
import memory_vault_open_repair_index as index
import memory_vault_open_repair_resource as resource
import memory_vault_open_repair_status as status
import memory_vault_open_repair_wire as wire


def _source(journal, manifest, resolver, custody, selection, owner, source, epoch, limits, budget):
    policy = journal.policy
    if journal.purpose == 'root_replica':
        from memory_vault_open_repair_mailbox_root import verify_mailbox_root_source_event
        _require(set(selection) == {'expected_root'})
        held = verify_mailbox_root_source_event(manifest, resolver, custody,
            **selection, expected_owner=owner, expected_target=source,
            target_storage_epoch=epoch, limit_policy=limits, policy=policy, budget=budget)
        setup = held['setup']; root, read, bootstrap = (setup['originals'][k] for k in ('root', 'read', 'bootstrap'))
        active = setup['anchor']['active']
        scope = dict(kind='mailbox_root', root_key=root.payload['root_key'],
            root_authority_ref=root.ref.as_dict(), catalog_ref=setup['originals']['catalog'].ref.as_dict())
        needs = [index._obligation(v['signer'], v['kind'], v['scope_id'], v['revision'], v['bits'])
            for v in held['obligations']]
        return dict(held=held, root=root, read=read, bootstrap=bootstrap, active=active,
            controls=(root,), scope=scope, historical_ref=wire.raw_ref(manifest['ref']).as_dict(),
            maximum=min(held['read_until'], held['retain_until'], active.payload['windows']['copy_until']),
            needs=needs, reservation_kind='mailbox.copy_reservation_consent', variants=('owner',),
            stored_at=held['stored_at'])
    from memory_vault_open_repair_mailbox_activation import verify_mailbox_feed_source_event
    from memory_vault_open_repair_mailbox_feed_copy import feed_copy_scope
    message = journal.purpose == 'message_replica'
    _require(journal.purpose in ('feed_replica', 'message_replica')
        and set(selection) == ({'expected_slot', 'expected_sender', 'expected_envelope_ref'} if message
            else {'expected_slot', 'expected_sender'}))
    held = verify_mailbox_feed_source_event(manifest, resolver, custody,
        expected_slot=selection['expected_slot'], expected_sender=selection['expected_sender'],
        expected_owner=owner, expected_target=source, limit_policy=limits, policy=policy, budget=budget)
    if message:
        from memory_vault_open_repair_mailbox_message_copy import select_message_source
        held = select_message_source(held, selection['expected_envelope_ref'], policy, budget)
    scope = held['message_scope'] if message else feed_copy_scope(held)
    _require(scope['slot_key']['writer_storage_epoch'] == epoch)
    setup = held['graph']['members'][0]
    root, read, bootstrap, slot = (setup['originals'][k] for k in ('maintenance', 'read', 'bootstrap', 'slot'))
    active = setup['resources']['data' if message else 'metadata']['active']
    maximum = min(held['read_until'], held['retain_until'], active.payload['windows']['copy_until'],
        slot.payload['windows']['copy_until'])
    for member in held['graph']['members']:
        disclosure = member['disclosure']
        _require(disclosure['operation_mask'] & 70 == 70
            and all(member['originals'][k].ref == value.ref
                for k, value in (('maintenance', root), ('read', read), ('bootstrap', bootstrap), ('slot', slot))))
        maximum = min(maximum, disclosure['consent_until'], disclosure['expires_at'])
    needs = [index._obligation(v['signer'], v['scope_kind'], v['scope_id'], v['document_revision'],
        v['operation_mask'] | (4 if v['role'] in ('slot', 'maintenance', 'disclosure', 'metadata_resource', 'data_resource') else 0))
        for v in held['graph']['obligations']]
    return dict(held=held, root=root, read=read, bootstrap=bootstrap, active=active,
        controls=(slot, root, read), scope=scope,
        historical_ref=held['message_history_ref'] if message else wire.raw_ref(manifest['ref']).as_dict(),
        maximum=maximum, needs=needs,
        reservation_kind='mailbox.message_copy_reservation_consent' if message else 'mailbox.feed_copy_reservation_consent',
        variants=('owner', 'sender'), stored_at=max(held['custody'].payload['stored_at'],
            held.get('feed_custody', held['custody']).payload['stored_at']))


def prepare(journal, manifest_entry, resolver, custody_entry, reservation_entry, intent, *,
        expected_owner, expected_source, source_storage_epoch, current_statuses, at, limit_policy,
        selection, sender_reservation_entry=None, offer_entry=None):
    policy, budget, db = journal.policy, resolver.budget, journal.db
    wire._context(policy, budget); wire.u53(at)
    _require(not db.in_transaction and resolver.policy is policy and policy.max_signature_checks <= 64)
    selection = wire.build_new_wire(selection, policy, budget).value
    binding = db.execute('SELECT value FROM ack_copy_prepare_binding WHERE id=1').fetchone()
    _require(binding is not None and bytes(binding[0]) == canonical_bytes(journal.keys))
    value = wire.build_new_wire(intent, policy, budget).value
    resource._fields(value, INTENT_FIELDS)
    parties = wire.build_new_wire(dict(owner=expected_owner, source=expected_source,
        maintainer=journal.keys, target=value['target'], **({'sender': selection['expected_sender']}
            if 'expected_sender' in selection else {})), policy, budget).value
    ids = {name: resource._dual_key(keys, budget) for name, keys in parties.items()}
    context = _source(journal, manifest_entry, resolver, custody_entry, selection,
        parties['owner'], parties['source'], source_storage_epoch, limit_policy, budget)
    root, read, bootstrap, active = (context[k] for k in ('root', 'read', 'bootstrap', 'active'))
    root_key = value['root_key']; history._root(root_key)
    _require(root_key == (context['scope']['root_key'] if journal.purpose == 'root_replica'
        else context['scope']['slot_key']['root_key']))
    mailbox_copy_scope(value['scope'], root_key, value['purpose'])
    resource._budget(value['budget']); resource._windows(value['windows'], issued=at)
    for name in ('allocation_id', 'job_id', 'target_storage_epoch'): resource._opaque(value[name])
    _require(value['kind'] == 'resource.copy_intent' and value['purpose'] == journal.purpose
        and value['caller'] == parties['maintainer'] and value['scope'] == context['scope']
        and value['historical_manifest_ref'] == context['historical_ref']
        and ids['target'] not in (ids['source'], ids['maintainer'])
        and ids['maintainer'] in root.payload['maintainers'] and root.payload['operation_mask'] & 78 == 78
        and root.payload['max_delegate_depth'] >= 2 and root.payload['max_destinations_per_job'] > 0
        and root.payload['max_concurrent_jobs'] > 0)
    _require(all(value['budget'][name] > 0 for name in resource._BUDGET if name != 'max_live_bytes'))
    _require(value['budget']['max_live_bytes'] >= wire.raw_ref(context['scope']['envelope_ref']).size
        if journal.purpose == 'message_replica' else value['budget']['max_live_bytes'] == 0)
    for control in context['controls']:
        _require(all(value['budget'][k] <= control.payload['budget'][k] for k in resource._BUDGET)
            and all(value['windows'][k] <= control.payload['windows'][k] for k in resource._WINDOWS))
    parent_until = min(*(v.payload['expires_at'] for v in (*context['controls'], read, bootstrap)),
        read.payload['windows']['read_until'], *(bootstrap.payload[k] for k in ('probe_until', 'proof_until', 'upload_until')))
    maximum = min(context['maximum'], parent_until, root.payload['windows']['copy_until'], value['windows']['copy_until'])
    digest = budget._hash(wire._canonical(value, budget))
    needs = list(context['needs'])
    needs.extend((index._obligation(parties['owner']['signing_key'], 'authority',
        index._authority(root_key, root, policy, budget), root.payload['revision'], 78),
        index._obligation(parties['source']['signing_key'], 'resource',
            status.status_scope(root_key, 'resource', active.payload['resource'], policy, budget),
            active.payload['reservation_generation'], 4)))
    historical = journal._source_statuses(context['held'])
    signers = {keys['signing_key']['key_id']: keys['signing_key'] for keys in parties.values()}
    allowed = {key: [] for key in signers}
    for old in historical:
        issuer = old.payload['signing_key']['key_id']
        _require(issuer in signers and old.payload['signing_key'] == signers[issuer])
        allowed[issuer].extend(dict(scope_kind=e['scope_kind'], scope_id=e['scope_id']) for e in old.payload['entries'])
    reservations = {}
    _require((sender_reservation_entry is not None) == ('sender' in context['variants']))
    for variant in context['variants']:
        entry = reservation_entry if variant == 'owner' else sender_reservation_entry
        consent = index._signed(entry, parties[variant]['signing_key'], context['reservation_kind'],
            CONSENT_FIELDS | ({'variant'} if len(context['variants']) == 2 else set()), policy, budget)
        c = consent.payload; index._timed(c, at); resource._opaque(c['consent_id']); wire.u53(c['revision'], 1)
        disclosure = resource._fields(c['reservation_disclosure'], {'intent_sha256', 'until'})
        _require((len(context['variants']) == 1 or c['variant'] == variant)
            and c['root_authority_ref'] == root.ref.as_dict()
            and c['source_custody_ref'] == context['held']['custody'].ref.as_dict()
            and c['historical_manifest_ref'] == context['historical_ref'] and c['maintainer'] == ids['maintainer']
            and c['target'] == parties['target'] and c['target_storage_epoch'] == value['target_storage_epoch']
            and context['stored_at'] <= c['issued_at'] <= at and disclosure['intent_sha256'] == digest
            and at < wire.u53(disclosure['until']) <= min(maximum, c['expires_at']))
        maximum = min(maximum, disclosure['until'], c['expires_at']); reservations[variant] = consent
        scope = index._authority(root_key, consent, policy, budget)
        allowed[parties[variant]['signing_key']['key_id']].append(dict(scope_kind='authority', scope_id=scope))
        needs.append(index._obligation(parties[variant]['signing_key'], 'authority', scope, c['revision'], 4))
    allowed = {key: [dict(scope_kind=k, scope_id=v) for k, v in sorted({(e['scope_kind'], e['scope_id']) for e in rows})]
        for key, rows in allowed.items()}
    if type(current_statuses) not in (list, tuple) or not 1 <= len(current_statuses) <= 16:
        wire._fail('repair_status_missing')
    root_digest = budget._hash(wire._canonical(root_key, budget))
    checked, denial = [], None
    def observe(item):
        # Retain authentic observations before later siblings, budget checks,
        # offer validation or request conflicts can refuse the operation.
        checked.append(item)
        with journal._upload_transaction():
            if db.execute('SELECT 1 FROM ack_copy_prepare_status WHERE root_digest=? AND raw_digest=?', (root_digest, item.ref.raw_sha256)).fetchone(): return
            count, size = db.execute('SELECT count(*),coalesce(sum(length(raw)+length(ref)),0) FROM ack_copy_prepare_status').fetchone()
            reference = canonical_bytes(item.ref.as_dict())
            if count >= 64 or size + len(item.raw) + len(reference) > 1048576:
                db.execute("INSERT OR IGNORE INTO ack_copy_prepare_blocked VALUES('*','repair_copy_journal_capacity')")
                return
            db.execute('INSERT INTO ack_copy_prepare_status VALUES(?,?,?,?)',
                (root_digest, item.ref.raw_sha256, item.raw, reference))
    for entry in current_statuses:
        try:
            payload = wire.parse_new_wire(entry['raw'], policy, budget).value['payload']; issuer = payload['signing_key']['key_id']
            if issuer not in signers: wire._fail('repair_status_disclosure')
            status.authenticate_status_original(entry, expected_root=root_key, expected_signing_key=signers[issuer],
                at=at, allowed_scopes=allowed[issuer], policy=policy, budget=budget, on_authenticated=observe)
        except (KeyError, TypeError): denial = denial or 'repair_invalid_status'
        except wire.RepairWireError as error: denial = denial or error.code
    if len({item.ref for item in checked}) != len(checked): denial = denial or 'repair_duplicate_status'
    for need in needs:
        matches = [e for item in checked if item.payload['signing_key'] == need['signer'] for e in item.payload['entries']
            if (e['scope_kind'], e['scope_id']) == (need['scope_kind'], need['scope_id'])]
        if not matches: denial = denial or 'repair_status_missing'
        for e in matches:
            if e['status'] == 'revoked': denial = denial or 'repair_authority_revoked'
            elif e['minimum_document_revision'] > need['revision']: denial = denial or 'repair_status_revision'
            elif e['operation_mask'] & need['mask'] != need['mask']: denial = denial or 'repair_status_operation'
    consent_binding = canonical_bytes({name: item.ref.as_dict() for name, item in reservations.items()})
    with journal._upload_transaction():
        blocked = db.execute("SELECT reason FROM ack_copy_prepare_blocked WHERE root_digest IN (?, '*')", (root_digest,)).fetchone()
        if blocked: denial = blocked[0]
        exact = {(item.ref, item.raw): item for item in checked}; previous = []
        for raw, reference in db.execute('SELECT raw,ref FROM ack_copy_prepare_status WHERE root_digest=?', (root_digest,)):
            raw, ref = bytes(raw), wire.raw_ref(json.loads(bytes(reference)))
            if (ref, raw) in exact: previous.append(exact[(ref, raw)]); continue
            payload = wire.parse_new_wire(raw, policy, budget).value['payload']; issuer = payload['signing_key']['key_id']
            if issuer not in signers: continue
            previous.append(status.authenticate_status_original(dict(raw=raw, ref=ref.as_dict()),
                expected_root=root_key, expected_signing_key=signers[issuer], at=payload['issued_at'],
                allowed_scopes=[dict(scope_kind=e['scope_kind'], scope_id=e['scope_id']) for e in payload['entries']], policy=policy, budget=budget))
        try: empty._history_floors((*historical, *previous, *checked), previous=(*historical, *previous), current=checked)
        except wire.RepairWireError as error: denial = denial or error.code
        for item in checked:
            if db.execute('SELECT 1 FROM ack_copy_prepare_status WHERE root_digest=? AND raw_digest=?', (root_digest, item.ref.raw_sha256)).fetchone(): continue
            count, size = db.execute('SELECT count(*),coalesce(sum(length(raw)+length(ref)),0) FROM ack_copy_prepare_status').fetchone()
            ref = canonical_bytes(item.ref.as_dict())
            if count >= 64 or size + len(item.raw) + len(ref) > 1048576:
                denial = 'repair_copy_journal_capacity'
                db.execute("INSERT OR IGNORE INTO ack_copy_prepare_blocked VALUES('*','repair_copy_journal_capacity')"); break
            db.execute('INSERT INTO ack_copy_prepare_status VALUES(?,?,?,?)', (root_digest, item.ref.raw_sha256, item.raw, ref))
        for item in previous:
            for e in item.payload['entries']:
                if e['status'] == 'revoked' and any(item.payload['signing_key'] == need['signer']
                        and (e['scope_kind'], e['scope_id']) == (need['scope_kind'], need['scope_id']) for need in needs):
                    denial = denial or 'repair_authority_revoked'
        result = None
        if denial is None:
            old = db.execute('SELECT intent_digest,consent_ref,request,ref FROM ack_copy_prepare_jobs WHERE job_id=?', (value['job_id'],)).fetchone()
            if old:
                _require(old[0] == digest and bytes(old[1]) == consent_binding)
                allocation = dict(raw=bytes(old[2]), ref=json.loads(bytes(old[3])))
                held = index._signed(allocation, journal.keys['signing_key'], 'resource.allocate', index.ALLOCATE_FIELDS, policy, budget).payload
                index._timed(held, at)
                _require(held['intent'] == value and held['intent_sha256'] == digest
                    and held['target_node_key_id'] == ids['target']['signing_key_id']
                    and held['target_storage_epoch'] == value['target_storage_epoch'])
            else:
                count = db.execute('SELECT count(*) FROM ack_copy_prepare_jobs').fetchone()[0]
                root_count = db.execute('SELECT count(*) FROM ack_copy_prepare_jobs WHERE root_digest=?', (root_digest,)).fetchone()[0]
                _require(count < 16 and root_count < min(root.payload['max_concurrent_jobs'], root.payload['budget']['max_jobs']))
                payload = dict(schema_version=resource.SCHEMA, kind='resource.allocate', signing_key=journal.keys['signing_key'],
                    issued_at=at, expires_at=min(at+60, maximum, *value['windows'].values(), *(item.payload['valid_until'] for item in checked)),
                    request_id='copy_'+digest, target_node_key_id=ids['target']['signing_key_id'],
                    target_storage_epoch=value['target_storage_epoch'], intent=value, intent_sha256=digest)
                allocation = _sign(journal, payload)
                db.execute('INSERT INTO ack_copy_prepare_jobs VALUES(?,?,?,?,?,?)',
                    (value['job_id'], root_digest, digest, consent_binding, allocation['raw'], canonical_bytes(allocation['ref'])))
            result = dict(allocation=allocation)
            if offer_entry is not None:
                result['assignment'] = _assign(journal, allocation, offer_entry, value, root, bootstrap, parent_until, at, budget)
            result['status_stamp'] = tuple((bytes(r[0]), bytes(r[1])) for r in db.execute(
                'SELECT raw,ref FROM ack_copy_prepare_status WHERE root_digest=? ORDER BY raw_digest', (root_digest,)))
    if denial: wire._fail(denial)
    return result


def _sign(journal, payload):
    raw = canonical_bytes(dict(payload=payload, proof=journal.identity.sign_message(payload)))
    digest = hashlib.sha256(raw).hexdigest()
    return dict(raw=raw, ref=dict(namespace='meta', key=digest, raw_sha256=digest, size=len(raw)))


def _assign(journal, allocation, offer_entry, intent, root, bootstrap, parent_until, at, budget):
    policy, db = journal.policy, journal.db
    offer = index._signed(offer_entry, intent['target']['signing_key'], 'resource.offer', index.OFFER_FIELDS, policy, budget)
    p = offer.payload; a = wire.parse_new_wire(allocation['raw'], policy, budget).value['payload']
    resource._budget(p['budget']); resource._windows(p['windows']); history._resource(p['resource']); resource._opaque(p['offer_id'])
    _require(p['intent'] == intent and p['intent_sha256'] == a['intent_sha256'] and p['allocation_request_ref'] == allocation['ref']
        and p['target_encryption_key'] == intent['target']['encryption_key']
        and p['resource']['node_key_id'] == intent['target']['signing_key']['key_id']
        and p['resource']['storage_epoch'] == intent['target_storage_epoch']
        and p['budget'] == intent['budget'] and p['windows'] == intent['windows']
        and wire.u53(p['reservation_generation'], 1) == 1
        and a['issued_at'] <= wire.u53(p['issued_at']) <= at < wire.u53(p['reservation_until']) <= a['expires_at'])
    until = min(parent_until, *(intent['windows'][k] for k in ('read_until', 'copy_until', 'retain_until')))
    _require(at < until and all(v <= until for v in intent['windows'].values()))
    old = db.execute('SELECT offer_ref,raw,ref FROM ack_copy_prepare_assignments WHERE job_id=?', (intent['job_id'],)).fetchone()
    if old:
        _require(bytes(old[0]) == canonical_bytes(offer.ref.as_dict()))
        entry = dict(raw=bytes(old[1]), ref=json.loads(bytes(old[2])))
        held = index._signed(entry, journal.keys['signing_key'], 'maintenance.assignment', index.ASSIGNMENT_FIELDS, policy, budget)
        index._timed(held.payload, at)
        _require(held.payload['resource_offer_ref'] == offer.ref.as_dict() and held.payload['resource_intent_sha256'] == a['intent_sha256'])
        return entry
    payload = dict(schema_version=resource.SCHEMA, kind='maintenance.assignment', signing_key=journal.keys['signing_key'],
        issued_at=at, expires_at=until, assignment_id='assignment_'+a['intent_sha256'], job_id=intent['job_id'],
        root_key=intent['root_key'], parent_root_ref=root.ref.as_dict(), parent_assignment_ref=None, depth=2,
        subject=resource._dual_key(intent['target'], budget), target_node_key_id=intent['target']['signing_key']['key_id'],
        target_storage_epoch=intent['target_storage_epoch'], operation_mask=70, scope=intent['scope'],
        resource_intent_sha256=a['intent_sha256'], resource_offer_ref=offer.ref.as_dict(), resource=p['resource'],
        bootstrap_grant_refs=[bootstrap.ref.as_dict()], budget=p['budget'], windows=p['windows'])
    entry = _sign(journal, payload)
    db.execute('INSERT INTO ack_copy_prepare_assignments VALUES(?,?,?,?)',
        (intent['job_id'], canonical_bytes(offer.ref.as_dict()), entry['raw'], canonical_bytes(entry['ref'])))
    return entry
