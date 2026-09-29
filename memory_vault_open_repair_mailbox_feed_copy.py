"""Exact full-prefix feed replicas under independent B/A/S disclosure authority.

The selected slot maintenance root is the only delegation parent. Discovery
catalogs grant no feed rights. A feed replica contains historical metadata and
sealed recipient indexes, never message envelopes or new admission rights.
"""
from types import MappingProxyType

import memory_vault_open_repair_empty as empty
import memory_vault_open_repair_history as history
import memory_vault_open_repair_index as index
import memory_vault_open_repair_resource as resource
import memory_vault_open_repair_status as status
import memory_vault_open_repair_wire as wire
from memory_vault_open_repair_copy_authority import DISCLOSURE_FIELDS, _replica_container, _check_replica_closure
from memory_vault_open_repair_copy_prepare import CONSENT_FIELDS
from memory_vault_open_repair_copy_resources import INTENT_FIELDS
from memory_vault_open_repair_mailbox_activation import verify_mailbox_feed_source_event
from memory_vault_open_repair_mailbox_copy import mailbox_copy_scope
from memory_vault_open_repair_mailbox_copy_authority import MailboxRootCopyAuthority, _same

RESERVATION_KIND = 'mailbox.feed_copy_reservation_consent'
DISCLOSURE_KIND = 'mailbox.feed_copy_disclosure'
RETURN_KIND = 'mailbox.feed_replica_return_consent'


def feed_copy_scope(source):
    value = source['manifest'].manifest.value
    return dict(kind='mailbox_feed', slot_key=value['slot_key'], slot_ref=value['slot_ref'],
        feed_head_ref=value['feed_head_ref'], source_custody_ref=source['custody'].ref.as_dict(),
        subtree=dict(value['covered_interval'], **value['subtree']))


def feed_copy_histories(source, entry):
    """Retain the complete member histories as well as the feed manifest."""
    manifests = {row.original.raw: row.original for row in source['manifest'].roles if row.role == 'history.member'}
    return (('history.mailbox_feed', entry, source['manifest']), *(
        ('history.member', index._entry(manifests[child.manifest.raw]), child)
        for child in source['manifest'].predecessors))


def feed_copy_inventory(source, reservations, policy, budget):
    rows = {}
    values = [(row.role, row.original) for manifest in (source['manifest'], *source['manifest'].predecessors) for row in manifest.roles]
    values.extend((('feed.custody', source['custody']), ('copy.reservation_consent', reservations['owner']),
        ('copy.sender_reservation_consent', reservations['sender'])))
    for role, item in values:
        parsed = wire.parse_new_wire(item.raw, policy, budget).value
        issuer = parsed['payload']['signing_key']['key_id'] if 'payload' in parsed else ''
        rows[index._pair(role, item.ref)] = index.IndexOriginal(role, item, issuer)
    return tuple(rows[key] for key in sorted(rows))


def feed_disclosure_permissions(rows, issuer, root, policy, budget):
    originals, scopes = index._permissions(rows, issuer, policy, budget)
    for row in rows:
        if row.issuer == issuer and row.role in ('copy.reservation_consent', 'copy.sender_reservation_consent'):
            scopes.append(dict(scope_kind='authority', scope_id=index._authority(root, row.original, policy, budget)))
    return originals, [dict(scope_kind=k, scope_id=v) for k, v in sorted({(e['scope_kind'], e['scope_id']) for e in scopes})]


def verify_mailbox_feed_copy(manifest_entry, resolver, custody_entry, allocation_entry, offer_entry,
        assignment_entry, reservation_entry, sender_reservation_entry, owner_disclosure_entry,
        source_disclosure_entry, sender_disclosure_entry, *, expected_slot, expected_owner, expected_sender,
        expected_source, source_storage_epoch, expected_maintainer, expected_target, target_storage_epoch,
        current_statuses, at, limit_policy, policy, budget, on_observed=None):
    wire._context(policy, budget); wire.u53(at)
    parties = wire.build_new_wire(dict(owner=expected_owner, sender=expected_sender, source=expected_source,
        maintainer=expected_maintainer, target=expected_target), policy, budget).value
    ids = {name: resource._dual_key(keys, budget) for name, keys in parties.items()}
    source = verify_mailbox_feed_source_event(manifest_entry, resolver, custody_entry, expected_slot=expected_slot,
        expected_owner=parties['owner'], expected_sender=parties['sender'], expected_target=parties['source'],
        limit_policy=limit_policy, policy=policy, budget=budget)
    scope = feed_copy_scope(source); slot_key = scope['slot_key']; root_key = slot_key['root_key']
    _same(slot_key['writer_storage_epoch'] == source_storage_epoch)
    setup = source['graph']['members'][0]
    parent, read, bootstrap, slot = (setup['originals'][name] for name in ('maintenance', 'read', 'bootstrap', 'slot'))
    active = setup['resources']['metadata']['active']
    p = parent.payload
    _same(ids['maintainer'] in p['maintainers'] and p['operation_mask'] & 78 == 78
        and p['max_delegate_depth'] >= 2 and p['max_destinations_per_job'] > 0 and p['max_concurrent_jobs'] > 0
        and ids['target'] not in (ids['source'], ids['maintainer']))
    allocation = index._signed(allocation_entry, parties['maintainer']['signing_key'], 'resource.allocate', index.ALLOCATE_FIELDS, policy, budget)
    offer = index._signed(offer_entry, parties['target']['signing_key'], 'resource.offer', index.OFFER_FIELDS, policy, budget)
    assignment = index._signed(assignment_entry, parties['maintainer']['signing_key'], 'maintenance.assignment', index.ASSIGNMENT_FIELDS, policy, budget)
    a, o, m = (item.payload for item in (allocation, offer, assignment))
    index._timed(a, at); index._timed(m, at)
    for name, value in (('request_id', a), ('offer_id', o), ('assignment_id', m)): resource._opaque(value[name])
    intent = resource._fields(a['intent'], INTENT_FIELDS)
    resource._budget(intent['budget']); resource._windows(intent['windows'], issued=at)
    mailbox_copy_scope(intent['scope'], intent['root_key'], intent['purpose']); history._resource(o['resource'])
    for name in ('allocation_id', 'job_id', 'target_storage_epoch'): resource._opaque(intent[name])
    digest = budget._hash(wire._canonical(intent, budget))
    _same(intent['kind'] == 'resource.copy_intent' and intent['purpose'] == 'feed_replica'
        and intent['budget']['max_live_bytes'] == 0 and intent['caller'] == parties['maintainer']
        and intent['target'] == parties['target'] and intent['target_storage_epoch'] == target_storage_epoch
        and intent['root_key'] == root_key and intent['scope'] == scope
        and intent['historical_manifest_ref'] == wire.raw_ref(manifest_entry['ref']).as_dict()
        and o['intent'] == intent and a['intent_sha256'] == o['intent_sha256'] == digest
        and o['allocation_request_ref'] == allocation.ref.as_dict()
        and o['target_encryption_key'] == parties['target']['encryption_key']
        and o['resource']['node_key_id'] == ids['target']['signing_key_id'] and o['resource']['storage_epoch'] == target_storage_epoch
        and wire.u53(o['reservation_generation'], 1) == 1 and o['budget'] == intent['budget'] and o['windows'] == intent['windows']
        and a['issued_at'] <= wire.u53(o['issued_at']) <= m['issued_at'] <= at < wire.u53(o['reservation_until']) <= a['expires_at'])
    # Both B's slot and maintenance root limit this job. The original READ
    # grant and bootstrap are retained unchanged for B's later retrieval.
    for control in (slot, parent, read):
        _same(all(intent['budget'][name] <= control.payload['budget'][name] for name in resource._BUDGET)
            and all(intent['windows'][name] <= control.payload['windows'][name] for name in resource._WINDOWS))
    parent_until = min(*(item.payload['expires_at'] for item in (slot, parent, read, bootstrap)),
        read.payload['windows']['read_until'], *(bootstrap.payload[name] for name in ('probe_until', 'proof_until', 'upload_until')))
    _same(m['job_id'] == intent['job_id'] and m['root_key'] == root_key and m['parent_root_ref'] == parent.ref.as_dict()
        and m['parent_assignment_ref'] is None and wire.u53(m['depth']) == 2 and m['subject'] == ids['target']
        and wire.u53(m['operation_mask']) == 70 and m['scope'] == scope and m['resource_intent_sha256'] == digest
        and m['resource_offer_ref'] == offer.ref.as_dict() and m['resource'] == o['resource']
        and m['bootstrap_grant_refs'] == [bootstrap.ref.as_dict()] and m['budget'] == o['budget'] and m['windows'] == o['windows']
        and all(value <= m['expires_at'] for value in m['windows'].values()) and m['expires_at'] <= parent_until)
    for item in (a, m):
        _same(item['target_node_key_id'] == ids['target']['signing_key_id'] and item['target_storage_epoch'] == target_storage_epoch)
    maximum = min(source['read_until'], source['retain_until'], parent_until, active.payload['windows']['copy_until'],
        slot.payload['windows']['copy_until'], p['windows']['copy_until'], intent['windows']['copy_until'])
    # Every original A consent, including every distinct message in the
    # prefix, must expressly permit COPY. Original contact leases are checked
    # historically by the source verifier and are not renewed for this copy.
    for member in source['graph']['members']:
        d = member['disclosure']
        _same(d['operation_mask'] & 70 == 70 and member['originals']['maintenance'].ref == parent.ref
            and member['originals']['slot'].ref == slot.ref and member['originals']['read'].ref == read.ref
            and member['originals']['bootstrap'].ref == bootstrap.ref)
        maximum = min(maximum, d['consent_until'], d['expires_at'])
    reservations = {}
    for variant, entry in (('owner', reservation_entry), ('sender', sender_reservation_entry)):
        consent = index._signed(entry, parties[variant]['signing_key'], RESERVATION_KIND, CONSENT_FIELDS | {'variant'}, policy, budget)
        c = consent.payload; index._timed(c, at); resource._opaque(c['consent_id']); wire.u53(c['revision'], 1)
        d = resource._fields(c['reservation_disclosure'], {'intent_sha256', 'until'})
        _same(c['variant'] == variant and c['root_authority_ref'] == parent.ref.as_dict()
            and c['source_custody_ref'] == source['custody'].ref.as_dict() and c['historical_manifest_ref'] == intent['historical_manifest_ref']
            and c['maintainer'] == ids['maintainer'] and c['target'] == parties['target'] and c['target_storage_epoch'] == target_storage_epoch
            and source['custody'].payload['stored_at'] <= c['issued_at'] <= a['issued_at'] and d['intent_sha256'] == digest
            and at < wire.u53(d['until']) <= min(maximum, c['expires_at']))
        reservations[variant] = consent; maximum = min(maximum, d['until'])
    rows = feed_copy_inventory(source, reservations, policy, budget)
    signers = {parties[name]['signing_key']['key_id']: parties[name]['signing_key'] for name in ('owner', 'sender', 'source', 'maintainer')}
    allowed = {key: [] for key in signers}; consents = []; until = min(maximum, m['expires_at'])
    variants = ('owner', 'source', 'sender')
    for variant, entry in zip(variants, (owner_disclosure_entry, source_disclosure_entry, sender_disclosure_entry)):
        signer = parties[variant]['signing_key']
        consent = index._signed(entry, signer, DISCLOSURE_KIND, DISCLOSURE_FIELDS, policy, budget)
        c = consent.payload; index._timed(c, at); resource._opaque(c['consent_id']); wire.u53(c['revision'], 1)
        _same(c['variant'] == variant and c['root_key'] == root_key and c['assignment_ref'] == assignment.ref.as_dict()
            and c['source_custody_ref'] == source['custody'].ref.as_dict() and c['historical_manifest_ref'] == intent['historical_manifest_ref']
            and c['target'] == parties['target'] and c['target_storage_epoch'] == target_storage_epoch and m['issued_at'] <= c['issued_at'])
        d = resource._fields(c['disclosure'], {'originals', 'status_scopes', 'until'})
        originals, scopes = feed_disclosure_permissions(rows, signer['key_id'], root_key, policy, budget)
        _same(d['originals'] == originals and d['status_scopes'] == scopes and at < wire.u53(d['until']) <= min(maximum, c['expires_at']))
        allowed[signer['key_id']].extend(scopes)
        allowed[signer['key_id']].append(dict(scope_kind='authority', scope_id=index._authority(root_key, consent, policy, budget)))
        until = min(until, d['until'], c['expires_at']); consents.append(consent)
    obligations = []
    for item in source['graph']['obligations']:
        # No current ADMIT requirement; COPY adds to the original feed's
        # READ/RETAIN/discovery obligations without reusing a contact lease.
        bits = item['operation_mask'] | (4 if item['role'] in ('slot', 'maintenance', 'disclosure', 'metadata_resource') else 0)
        obligations.append(index._obligation(item['signer'], item['scope_kind'], item['scope_id'], item['document_revision'], bits))
    for variant, consent in reservations.items():
        signer = parties[variant]['signing_key']; scope_id = index._authority(root_key, consent, policy, budget)
        allowed[signer['key_id']].append(dict(scope_kind='authority', scope_id=scope_id))
        obligations.append(index._obligation(signer, 'authority', scope_id, consent.payload['revision'], 4))
    obligations.append(index._obligation(parties['owner']['signing_key'], 'authority', index._authority(root_key, parent, policy, budget), p['revision'], 78))
    assignment_scope = status.status_scope(root_key, 'assignment', dict(assignment_kind='maintenance.assignment', assignment_sha256=assignment.ref.raw_sha256), policy, budget)
    allowed[parties['maintainer']['signing_key']['key_id']].append(dict(scope_kind='assignment', scope_id=assignment_scope))
    obligations.append(index._obligation(parties['maintainer']['signing_key'], 'assignment', assignment_scope, 0, 70))
    obligations.extend(index._obligation(parties[variant]['signing_key'], 'authority', index._authority(root_key, consent, policy, budget), consent.payload['revision'], 4)
        for variant, consent in zip(variants, consents))
    allowed = {key: [dict(scope_kind=k, scope_id=v) for k, v in sorted({(e['scope_kind'], e['scope_id']) for e in values})] for key, values in allowed.items()}
    checked, denial = [], None
    def observe(item):
        checked.append(item)
        if on_observed is not None: on_observed(item)
    if not isinstance(current_statuses, (list, tuple)) or not 1 <= len(current_statuses) <= 16: wire._fail('repair_status_missing')
    for entry in current_statuses:
        try:
            p = wire.parse_new_wire(entry['raw'], policy, budget).value['payload']; issuer = p['signing_key']['key_id']
            if issuer not in signers: wire._fail('repair_status_disclosure')
            status.authenticate_status_original(entry, expected_root=root_key, expected_signing_key=signers[issuer], at=at,
                allowed_scopes=allowed[issuer], policy=policy, budget=budget, on_authenticated=observe)
        except (KeyError, TypeError): denial = denial or 'repair_invalid_status'
        except wire.RepairWireError as error: denial = denial or error.code
    if len({item.ref for item in checked}) != len(checked): denial = denial or 'repair_duplicate_status'
    previous = (*source['graph']['statuses'], *(item for member in source['graph']['members'] for item in member['statuses']))
    try: empty._history_floors((*previous, *checked), previous=previous, current=checked)
    except wire.RepairWireError as error: denial = denial or error.code
    for need in obligations:
        values = [e for item in checked if item.payload['signing_key'] == need['signer'] for e in item.payload['entries']
            if (e['scope_kind'], e['scope_id']) == (need['scope_kind'], need['scope_id'])]
        if not values: denial = denial or 'repair_status_missing'
        for e in values:
            if e['status'] == 'revoked': denial = denial or 'repair_authority_revoked'
            elif e['minimum_document_revision'] > need['revision']: denial = denial or 'repair_status_revision'
            elif e['operation_mask'] & need['mask'] != need['mask']: denial = denial or 'repair_status_operation'
    read_until = min(until, intent['windows']['read_until'])
    retain_until = min(until, intent['windows']['retain_until'])
    if checked: read_until = min(read_until, *(item.payload['valid_until'] for item in checked))
    if at >= min(read_until, retain_until): denial = denial or 'repair_resource_expired'
    return MailboxRootCopyAuthority(MappingProxyType(source), allocation, offer, assignment, reservations['owner'],
        tuple(consents), rows, tuple(checked), tuple(obligations), read_until, retain_until, denial)


def feed_copy_edges(source, policy, budget):
    """Typed edges supplement the exact whole historical manifest closures."""
    value = source['manifest'].manifest.value; edges = []
    by_role = {(row.role, row.original.ref): row.original for row in source['manifest'].roles}
    def edge(parent, relation, child): edges.append(dict(parent_ref=parent, relation=relation, child_ref=child))
    edge(value['slot_ref'], 'slot-feed', value['feed_head_ref'])
    edge(value['feed_head_ref'], 'head-checkpoint', source['graph']['head']['checkpoint_ref'])
    edge(value['feed_head_ref'], 'head-range', source['graph']['head']['range_root_ref'])
    for member in value['members']:
        for relation, field in (('link-core', 'admission_core_ref'), ('link-history', 'historical_manifest_ref')):
            edge(member['admission_link_ref'], relation, member[field])
        edge(member['source_custody_ref'], 'custody-link', member['admission_link_ref'])
    for (role, ref), item in by_role.items():
        if role not in ('range.index', 'range.repair_page'): continue
        p = wire.parse_new_wire(item.raw, policy, budget).value
        if role == 'range.index':
            for child in p['children']: edge(ref.as_dict(), 'range-child', child['ref'])
        else:
            edge(ref.as_dict(), 'page-sealed', p['sealed_page_ref'])
            for child in p['entries']: edge(ref.as_dict(), 'page-link', child['admission_link_ref'])
    return tuple(edges)


def verify_mailbox_feed_replica(manifest_entry, resolver, custody_entry, *, expected_slot, expected_owner,
        expected_sender, expected_source, source_storage_epoch, expected_maintainer, expected_target,
        target_storage_epoch, limit_policy, policy, budget):
    target, custody, value, entries = _replica_container(manifest_entry, resolver, custody_entry,
        expected_target=expected_target, target_storage_epoch=target_storage_epoch, policy=policy, budget=budget)
    def one(role):
        values = entries.get(role, ())
        if len(values) != 1: wire._fail('repair_copy_commit_mismatch')
        return values[0]
    source_manifest = one('history.mailbox_feed')
    plan = verify_mailbox_feed_copy(source_manifest, resolver, one('feed.custody'), one('copy.allocation'),
        one('copy.offer'), one('copy.assignment'), one('copy.reservation_consent'), one('copy.sender_reservation_consent'),
        one('copy.owner_disclosure'), one('copy.source_disclosure'), one('copy.sender_disclosure'), expected_slot=expected_slot,
        expected_owner=expected_owner, expected_sender=expected_sender, expected_source=expected_source,
        source_storage_epoch=source_storage_epoch, expected_maintainer=expected_maintainer, expected_target=target,
        target_storage_epoch=target_storage_epoch, current_statuses=entries.get('copy.current_status', ()),
        at=custody.payload['stored_at'], limit_policy=limit_policy, policy=policy, budget=budget)
    if plan.denial_code: wire._fail(plan.denial_code)
    _check_replica_closure(custody.payload, value, plan, source_custody=plan.source['custody'],
        source_histories=feed_copy_histories(plan.source, source_manifest),
        additional=(('copy.sender_disclosure', plan.disclosures[2]),), extra_edges=feed_copy_edges(plan.source, policy, budget))
    return dict(state='historical_replica', custody=custody, source=plan.source, authority=plan,
        entries=MappingProxyType({role: tuple(values) for role, values in entries.items()}))


def feed_return_permissions(plan, issuer, policy, budget):
    rows = {index._pair(row.role, row.original.ref): row for row in plan.originals if row.issuer == issuer}
    for role, item in (('copy.allocation', plan.allocation), ('copy.offer', plan.offer), ('copy.assignment', plan.assignment),
            *zip(('copy.owner_disclosure', 'copy.source_disclosure', 'copy.sender_disclosure'), plan.disclosures)):
        if item.payload['signing_key']['key_id'] == issuer: rows[index._pair(role, item.ref)] = index.IndexOriginal(role, item, issuer)
    originals, scopes = index._permissions(tuple(rows[key] for key in sorted(rows)), issuer, policy, budget)
    root = plan.assignment.payload['root_key']
    for row in rows.values():
        payload = wire.parse_new_wire(row.original.raw, policy, budget).value['payload']
        if payload['kind'] in (RESERVATION_KIND, DISCLOSURE_KIND):
            scopes.append(dict(scope_kind='authority', scope_id=index._authority(root, row.original, policy, budget)))
        elif payload['kind'] == 'maintenance.assignment':
            scopes.append(dict(scope_kind='assignment', scope_id=status.status_scope(root, 'assignment',
                dict(assignment_kind=payload['kind'], assignment_sha256=row.original.ref.raw_sha256), policy, budget)))
    return originals, [dict(scope_kind=k, scope_id=v) for k, v in sorted({(e['scope_kind'], e['scope_id']) for e in scopes})]


def _check_mailbox_feed_return(replica, consent_entries, *, expected_owner, expected_sender, expected_source,
        expected_maintainer, expected_target, target_storage_epoch, current_statuses, at, action, policy, budget, on_observed=None):
    """Fresh selected-slot READ and explicit A/B/S/M return disclosure to B."""
    from memory_vault_open_repair_copy_authority import RETURN_FIELDS
    wire._context(policy, budget); wire.u53(at)
    if action not in ('challenge', 'proof', 'child'): wire._fail('repair_access_action')
    source = replica['source']; plan = replica['authority']; custody = replica['custody']
    root = plan.assignment.payload['root_key']; setup = source['graph']['members'][0]['originals']; bootstrap = setup['bootstrap']
    parties = wire.build_new_wire(dict(owner=expected_owner, sender=expected_sender, source=expected_source,
        maintainer=expected_maintainer, target=expected_target), policy, budget).value
    owner_id = resource._dual_key(parties['owner'], budget)
    signers = {keys['signing_key']['key_id']: keys['signing_key'] for keys in parties.values()}
    variants = ('owner', 'source', 'maintainer', 'sender'); wire.object_fields(consent_entries, set(variants))
    allowed = {key: [] for key in signers}; obligations = []; consents = []; denial = None
    expires = min(custody.payload['read_until'], custody.payload['retain_until'], source['read_until'],
        bootstrap.payload['expires_at'], bootstrap.payload['probe_until'] if action == 'challenge' else bootstrap.payload['proof_until'])
    for member in source['graph']['members']:
        for name in ('slot', 'read', 'maintenance'):
            p = member['originals'][name].payload; expires = min(expires, p['expires_at'], p['windows']['read_until'], p['windows']['retain_until'])
        d = member['disclosure']; expires = min(expires, d['expires_at'], d['consent_until'], d['bootstrap_return']['until'])
    for variant in variants:
        signer = parties[variant]['signing_key']
        consent = index._signed(consent_entries[variant], signer, RETURN_KIND, RETURN_FIELDS, policy, budget)
        p = consent.payload; resource._lifetime(p); resource._opaque(p['consent_id']); wire.u53(p['revision'], 1)
        if not p['issued_at'] <= at < p['expires_at']: denial = denial or 'repair_access_expired'
        _same(p['variant'] == variant and p['root_key'] == root and p['source_custody_ref'] == source['custody'].ref.as_dict()
            and p['historical_manifest_ref'] == plan.allocation.payload['intent']['historical_manifest_ref']
            and p['assignment_ref'] == plan.assignment.ref.as_dict() and p['subject'] == owner_id
            and p['target'] == parties['target'] and p['target_storage_epoch'] == target_storage_epoch
            and p['bootstrap_grant_ref'] == bootstrap.ref.as_dict() and p['issued_at'] >= plan.assignment.payload['issued_at'])
        permission = wire.object_fields(p['return_permission'], {'originals', 'status_scopes', 'until'})
        originals, scopes = feed_return_permissions(plan, signer['key_id'], policy, budget)
        _same(permission['originals'] == originals and permission['status_scopes'] == scopes
            and p['issued_at'] < wire.u53(permission['until']) <= min(p['expires_at'],
                plan.assignment.payload['windows']['read_until'], source['read_until'], bootstrap.payload['proof_until']))
        expires = min(expires, permission['until'], p['expires_at'])
        scope = index._authority(root, consent, policy, budget)
        allowed[signer['key_id']].extend((*scopes, dict(scope_kind='authority', scope_id=scope)))
        obligations.append(index._obligation(signer, 'authority', scope, p['revision'], 2)); consents.append(consent)
    for item in source['graph']['obligations']:
        if item['role'] == 'metadata_resource': continue
        mask = 10 if item['role'] in ('slot', 'maintenance', 'bootstrap') else 2
        obligations.append(index._obligation(item['signer'], item['scope_kind'], item['scope_id'], item['document_revision'], mask))
    obligations.append(index._obligation(parties['maintainer']['signing_key'], 'assignment', status.status_scope(root, 'assignment',
        dict(assignment_kind='maintenance.assignment', assignment_sha256=plan.assignment.ref.raw_sha256), policy, budget), 0, 2))
    target_scope = status.status_scope(root, 'resource', custody.payload['resource'], policy, budget)
    allowed[parties['target']['signing_key']['key_id']].append(dict(scope_kind='resource', scope_id=target_scope))
    obligations.append(index._obligation(parties['target']['signing_key'], 'resource', target_scope, custody.payload['reservation_generation'], 2))
    allowed = {key: [dict(scope_kind=k, scope_id=v) for k, v in sorted({(e['scope_kind'], e['scope_id']) for e in values})] for key, values in allowed.items()}
    for item in plan.statuses:
        permitted = {(e['scope_kind'], e['scope_id']) for e in allowed[item.payload['signing_key']['key_id']]}
        if any((e['scope_kind'], e['scope_id']) not in permitted for e in item.payload['entries']): wire._fail('repair_status_disclosure')
    if type(current_statuses) not in (list, tuple) or not 1 <= len(current_statuses) <= 16: wire._fail('repair_status_missing')
    checked = []
    def observe(item):
        checked.append(item)
        if on_observed is not None: on_observed(item)
    for entry in current_statuses:
        try:
            p = wire.parse_new_wire(entry['raw'], policy, budget).value['payload']; issuer = p['signing_key']['key_id']
            if issuer not in signers: wire._fail('repair_status_disclosure')
            status.authenticate_status_original(entry, expected_root=root, expected_signing_key=signers[issuer], at=at,
                allowed_scopes=allowed[issuer], policy=policy, budget=budget, on_authenticated=observe)
        except (KeyError, TypeError): denial = denial or 'repair_invalid_status'
        except wire.RepairWireError as error: denial = denial or error.code
    if len({item.ref for item in checked}) != len(checked): denial = denial or 'repair_duplicate_status'
    previous = (*source['graph']['statuses'], *plan.statuses, *(item for member in source['graph']['members'] for item in member['statuses']))
    try: empty._history_floors((*previous, *checked), previous=previous, current=checked)
    except wire.RepairWireError as error: denial = denial or error.code
    for need in obligations:
        values = [e for item in checked if item.payload['signing_key'] == need['signer'] for e in item.payload['entries']
            if (e['scope_kind'], e['scope_id']) == (need['scope_kind'], need['scope_id'])]
        if not values: denial = denial or 'repair_status_missing'
        for e in values:
            if e['status'] == 'revoked': denial = denial or 'repair_authority_revoked'
            elif e['minimum_document_revision'] > need['revision']: denial = denial or 'repair_status_revision'
            elif e['operation_mask'] & need['mask'] != need['mask']: denial = denial or 'repair_status_operation'
    if checked: expires = min(expires, *(item.payload['valid_until'] for item in checked))
    if at >= expires: denial = denial or 'repair_access_expired'
    return dict(expires_at=expires, consents=tuple(consents), statuses=tuple(checked), obligations=tuple(obligations),
        subject=owner_id, bootstrap=bootstrap, denial_code=denial)
