"""Original owner/source authority for a bounded discovery-root replica.

This verifier returns authenticated status observations even on a current
denial. A storage caller must retain those observations before reporting the
denial, recheck actual local capacity, and commit real bytes before custody.
It provides no network disclosure or permission to copy a feed or message.
"""
from dataclasses import dataclass
from types import MappingProxyType

import memory_vault_open_repair_empty as empty
import memory_vault_open_repair_history as history
import memory_vault_open_repair_index as index
import memory_vault_open_repair_resource as resource
import memory_vault_open_repair_status as status
import memory_vault_open_repair_wire as wire
from memory_vault_open_repair_copy_authority import DISCLOSURE_FIELDS, disclosure_permissions
from memory_vault_open_repair_copy_prepare import CONSENT_FIELDS
from memory_vault_open_repair_copy_resources import INTENT_FIELDS
from memory_vault_open_repair_mailbox_copy import mailbox_copy_scope
from memory_vault_open_repair_mailbox_root import verify_mailbox_root_source_event


@dataclass(frozen=True)
class MailboxRootCopyAuthority:
    source: object
    allocation: object
    offer: object
    assignment: object
    reservation: object
    disclosures: tuple
    originals: tuple
    statuses: tuple
    obligations: tuple
    read_until: int
    retain_until: int
    denial_code: object


def _same(value):
    if not value:
        wire._fail('repair_copy_authority_mismatch')


def root_copy_inventory(source, reservation, policy, budget):
    """Exact signing inputs, never independent permission to disclose them."""
    rows = {}
    values = [(item.role, item.original) for item in source['manifest'].roles]
    values.extend((('root.custody', source['custody']), ('copy.reservation_consent', reservation)))
    for role, item in values:
        payload = wire.parse_new_wire(item.raw, policy, budget).value.get('payload')
        if payload is not None:
            rows[index._pair(role, item.ref)] = index.IndexOriginal(role, item, payload['signing_key']['key_id'])
    return tuple(rows[key] for key in sorted(rows))


def verify_mailbox_root_copy(manifest_entry, resolver, custody_entry, allocation_entry, offer_entry,
        assignment_entry, reservation_entry, owner_disclosure_entry, source_disclosure_entry, *,
        expected_root, expected_owner, expected_source, source_storage_epoch, expected_maintainer,
        expected_target, target_storage_epoch, current_statuses, at, limit_policy, policy, budget,
        on_observed=None):
    wire._context(policy, budget); wire.u53(at)
    context = wire.build_new_wire(dict(owner=expected_owner, source=expected_source,
        maintainer=expected_maintainer, target=expected_target), policy, budget).value
    ids = {name: resource._dual_key(value, budget) for name, value in context.items()}
    source = verify_mailbox_root_source_event(manifest_entry, resolver, custody_entry,
        expected_root=expected_root, expected_owner=context['owner'], expected_target=context['source'],
        target_storage_epoch=source_storage_epoch, limit_policy=limit_policy, policy=policy, budget=budget)
    root, read, bootstrap = (source['setup']['originals'][name] for name in ('root', 'read', 'bootstrap'))
    active = source['setup']['anchor']['active']
    root_key = root.payload['root_key']
    scope = dict(kind='mailbox_root', root_key=root_key, root_authority_ref=root.ref.as_dict(),
        catalog_ref=source['setup']['originals']['catalog'].ref.as_dict())
    _same(ids['maintainer'] in root.payload['maintainers'] and root.payload['operation_mask'] & 78 == 78
        and root.payload['max_delegate_depth'] >= 2 and root.payload['max_destinations_per_job'] > 0
        and root.payload['max_concurrent_jobs'] > 0 and ids['target'] not in (ids['source'], ids['maintainer']))
    allocation = index._signed(allocation_entry, context['maintainer']['signing_key'], 'resource.allocate', index.ALLOCATE_FIELDS, policy, budget)
    offer = index._signed(offer_entry, context['target']['signing_key'], 'resource.offer', index.OFFER_FIELDS, policy, budget)
    assignment = index._signed(assignment_entry, context['maintainer']['signing_key'], 'maintenance.assignment', index.ASSIGNMENT_FIELDS, policy, budget)
    a, o, m = (item.payload for item in (allocation, offer, assignment))
    index._timed(a, at); index._timed(m, at)
    for name, value in (('request_id', a), ('offer_id', o), ('assignment_id', m)):
        resource._opaque(value[name])
    intent = resource._fields(a['intent'], INTENT_FIELDS)
    resource._budget(intent['budget']); resource._windows(intent['windows'], issued=at)
    mailbox_copy_scope(intent['scope'], intent['root_key'], intent['purpose'])
    history._resource(o['resource'])
    for name in ('allocation_id', 'job_id', 'target_storage_epoch'):
        resource._opaque(intent[name])
    digest = budget._hash(wire._canonical(intent, budget))
    _same(intent['kind'] == 'resource.copy_intent' and intent['purpose'] == 'root_replica'
        and intent['budget']['max_live_bytes'] == 0 and intent['caller'] == context['maintainer']
        and intent['target'] == context['target'] and intent['target_storage_epoch'] == target_storage_epoch
        and intent['root_key'] == root_key and intent['scope'] == scope
        and intent['historical_manifest_ref'] == wire.raw_ref(manifest_entry['ref']).as_dict()
        and o['intent'] == intent and a['intent_sha256'] == o['intent_sha256'] == digest
        and o['allocation_request_ref'] == allocation.ref.as_dict()
        and o['target_encryption_key'] == context['target']['encryption_key']
        and o['resource']['node_key_id'] == ids['target']['signing_key_id']
        and o['resource']['storage_epoch'] == target_storage_epoch and wire.u53(o['reservation_generation'], 1) == 1
        and o['budget'] == intent['budget'] and o['windows'] == intent['windows']
        and a['issued_at'] <= wire.u53(o['issued_at']) <= m['issued_at'] <= at < wire.u53(o['reservation_until']) <= a['expires_at'])
    _same(all(intent['budget'][name] <= root.payload['budget'][name] for name in resource._BUDGET)
        and all(intent['windows'][name] <= root.payload['windows'][name] for name in resource._WINDOWS))
    parent_until = min(root.payload['expires_at'], read.payload['expires_at'], read.payload['windows']['read_until'],
        bootstrap.payload['expires_at'], *(bootstrap.payload[name] for name in ('probe_until', 'proof_until', 'upload_until')))
    _same(m['job_id'] == intent['job_id'] and m['root_key'] == root_key and m['parent_root_ref'] == root.ref.as_dict()
        and m['parent_assignment_ref'] is None and wire.u53(m['depth']) == 2 and m['subject'] == ids['target']
        and wire.u53(m['operation_mask']) == 70 and m['scope'] == scope
        and m['resource_intent_sha256'] == digest and m['resource_offer_ref'] == offer.ref.as_dict()
        and m['resource'] == o['resource'] and m['bootstrap_grant_refs'] == [bootstrap.ref.as_dict()]
        and m['budget'] == o['budget'] and m['windows'] == o['windows']
        and all(value <= m['expires_at'] for value in m['windows'].values()) and m['expires_at'] <= parent_until)
    for item in (a, m):
        _same(item['target_node_key_id'] == ids['target']['signing_key_id'] and item['target_storage_epoch'] == target_storage_epoch)
    reservation = index._signed(reservation_entry, context['owner']['signing_key'], 'mailbox.copy_reservation_consent', CONSENT_FIELDS, policy, budget)
    c = reservation.payload; index._timed(c, at); resource._opaque(c['consent_id']); wire.u53(c['revision'], 1)
    disclosure = resource._fields(c['reservation_disclosure'], {'intent_sha256', 'until'})
    maximum = min(source['read_until'], source['retain_until'], active.payload['windows']['copy_until'],
        root.payload['expires_at'], root.payload['windows']['copy_until'], c['expires_at'], intent['windows']['copy_until'])
    _same(c['root_authority_ref'] == root.ref.as_dict() and c['source_custody_ref'] == source['custody'].ref.as_dict()
        and c['historical_manifest_ref'] == intent['historical_manifest_ref'] and c['maintainer'] == ids['maintainer']
        and c['target'] == context['target'] and c['target_storage_epoch'] == target_storage_epoch
        and source['stored_at'] <= c['issued_at'] <= a['issued_at'] and disclosure['intent_sha256'] == digest
        and at < wire.u53(disclosure['until']) <= maximum)
    rows = root_copy_inventory(source, reservation, policy, budget)
    signers = {context[name]['signing_key']['key_id']: context[name]['signing_key'] for name in ('owner', 'source', 'maintainer')}
    allowed = {key: [] for key in signers}; consents = []; until = min(maximum, m['expires_at'])
    for variant, entry in (('owner', owner_disclosure_entry), ('source', source_disclosure_entry)):
        signer = context[variant]['signing_key']
        consent = index._signed(entry, signer, 'mailbox.copy_disclosure', DISCLOSURE_FIELDS, policy, budget)
        p = consent.payload; index._timed(p, at); resource._opaque(p['consent_id']); wire.u53(p['revision'], 1)
        _same(p['variant'] == variant and p['root_key'] == root_key and p['assignment_ref'] == assignment.ref.as_dict()
            and p['source_custody_ref'] == source['custody'].ref.as_dict() and p['historical_manifest_ref'] == intent['historical_manifest_ref']
            and p['target'] == context['target'] and p['target_storage_epoch'] == target_storage_epoch and m['issued_at'] <= p['issued_at'])
        d = wire.object_fields(p['disclosure'], {'originals', 'status_scopes', 'until'})
        originals, scopes = disclosure_permissions(rows, signer['key_id'], root_key, policy, budget)
        _same(d['originals'] == originals and d['status_scopes'] == scopes and at < wire.u53(d['until']) <= min(maximum, p['expires_at']))
        allowed[signer['key_id']].extend(scopes)
        allowed[signer['key_id']].append(dict(scope_kind='authority', scope_id=index._authority(root_key, consent, policy, budget)))
        until = min(until, d['until'], p['expires_at']); consents.append(consent)
    allowed[context['owner']['signing_key']['key_id']].append(dict(scope_kind='authority', scope_id=index._authority(root_key, reservation, policy, budget)))
    assignment_scope = status.status_scope(root_key, 'assignment', dict(assignment_kind='maintenance.assignment', assignment_sha256=assignment.ref.raw_sha256), policy, budget)
    allowed[context['maintainer']['signing_key']['key_id']].append(dict(scope_kind='assignment', scope_id=assignment_scope))
    allowed = {key: [dict(scope_kind=k, scope_id=v) for k, v in sorted({(e['scope_kind'], e['scope_id']) for e in values})] for key, values in allowed.items()}
    obligations = [index._obligation(item['signer'], item['kind'], item['scope_id'], item['revision'], item['bits']) for item in source['obligations']]
    obligations.extend((index._obligation(context['owner']['signing_key'], 'authority', index._authority(root_key, root, policy, budget), root.payload['revision'], 78),
        index._obligation(context['owner']['signing_key'], 'authority', index._authority(root_key, reservation, policy, budget), c['revision'], 4),
        index._obligation(context['source']['signing_key'], 'resource', status.status_scope(root_key, 'resource', active.payload['resource'], policy, budget), active.payload['reservation_generation'], 4),
        index._obligation(context['maintainer']['signing_key'], 'assignment', assignment_scope, 0, 70)))
    obligations.extend(index._obligation(context[variant]['signing_key'], 'authority', index._authority(root_key, item, policy, budget), item.payload['revision'], 4)
        for variant, item in zip(('owner', 'source'), consents))
    checked, denial = [], None
    def observe(item):
        checked.append(item)
        if on_observed is not None:
            on_observed(item)
    if not isinstance(current_statuses, (list, tuple)) or not 1 <= len(current_statuses) <= 16:
        wire._fail('repair_status_missing')
    for entry in current_statuses:
        try:
            p = wire.parse_new_wire(entry['raw'], policy, budget).value['payload']; issuer = p['signing_key']['key_id']
            if issuer not in signers:
                wire._fail('repair_status_disclosure')
            status.authenticate_status_original(entry, expected_root=root_key, expected_signing_key=signers[issuer], at=at,
                allowed_scopes=allowed[issuer], policy=policy, budget=budget, on_authenticated=observe)
        except (KeyError, TypeError):
            denial = denial or 'repair_invalid_status'
        except wire.RepairWireError as error:
            denial = denial or error.code
    if len({item.ref for item in checked}) != len(checked):
        denial = denial or 'repair_duplicate_status'
    try:
        empty._history_floors((*source['statuses'], *checked), previous=source['statuses'], current=checked)
    except wire.RepairWireError as error:
        denial = denial or error.code
    for need in obligations:
        observations = [e for item in checked if item.payload['signing_key'] == need['signer'] for e in item.payload['entries']
            if (e['scope_kind'], e['scope_id']) == (need['scope_kind'], need['scope_id'])]
        if not observations:
            denial = denial or 'repair_status_missing'
        for e in observations:
            if e['status'] == 'revoked':denial = denial or 'repair_authority_revoked'
            elif e['minimum_document_revision'] > need['revision']:denial = denial or 'repair_status_revision'
            elif e['operation_mask'] & need['mask'] != need['mask']:denial = denial or 'repair_status_operation'
    read_until = min(until, parent_until, intent['windows']['read_until'])
    retain_until = min(until, intent['windows']['retain_until'], root.payload['windows']['retain_until'])
    if checked:
        read_until = min(read_until, *(item.payload['valid_until'] for item in checked))
    if at >= min(read_until, retain_until):
        denial = denial or 'repair_resource_expired'
    return MailboxRootCopyAuthority(MappingProxyType(source), allocation, offer, assignment, reservation, tuple(consents),
        rows, tuple(checked), tuple(obligations), read_until, retain_until, denial)


def verify_mailbox_root_replica(manifest_entry, resolver, custody_entry, *, expected_root,
        expected_owner, expected_source, source_storage_epoch, expected_maintainer, expected_target,
        target_storage_epoch, limit_policy, policy, budget):
    """Independently authenticate stored discovery-root custody on any client.

    The original source and all copy permissions are checked at the actual copy
    time. Live READ and return disclosure remain separate, current decisions.
    """
    from memory_vault_open_repair_copy_authority import _replica_container, _check_replica_closure
    target, custody, value, entries = _replica_container(manifest_entry, resolver, custody_entry,
        expected_target=expected_target, target_storage_epoch=target_storage_epoch, policy=policy, budget=budget)
    def one(role):
        values = entries.get(role, ())
        if len(values) != 1: wire._fail('repair_copy_commit_mismatch')
        return values[0]
    source_manifest = one('history.mailbox_root')
    plan = verify_mailbox_root_copy(source_manifest, resolver, one('root.custody'),
        one('copy.allocation'), one('copy.offer'), one('copy.assignment'), one('copy.reservation_consent'),
        one('copy.owner_disclosure'), one('copy.source_disclosure'), expected_root=expected_root,
        expected_owner=expected_owner, expected_source=expected_source, source_storage_epoch=source_storage_epoch,
        expected_maintainer=expected_maintainer, expected_target=target, target_storage_epoch=target_storage_epoch,
        current_statuses=entries.get('copy.current_status', ()), at=custody.payload['stored_at'],
        limit_policy=limit_policy, policy=policy, budget=budget)
    if plan.denial_code: wire._fail(plan.denial_code)
    _check_replica_closure(custody.payload, value, plan, source_custody=plan.source['custody'],
        source_histories=(('history.mailbox_root', source_manifest, plan.source['manifest']),),
        extra_edges=root_copy_edges(plan.source))
    return dict(state='historical_replica', custody=custody, source=plan.source, authority=plan,
        entries=MappingProxyType({role: tuple(values) for role, values in entries.items()}))


def root_copy_edges(source):
    """Recompute typed discovery edges from the authenticated original graph."""
    setup = source['setup']; catalog = setup['originals']['catalog']; edges = []
    for slot in setup['slots']:
        original = slot['originals']['slot']; head = slot['genesis']['head']; checkpoint = slot['genesis']['checkpoint']
        for parent, relation, child in ((catalog, 'catalog-slot', original),
                (original, 'slot-feed', head), (head, 'head-checkpoint', checkpoint)):
            edges.append(dict(parent_ref=parent.ref.as_dict(), relation=relation, child_ref=child.ref.as_dict()))
    return tuple(edges)


def _check_mailbox_root_return(replica, consent_entries, *, expected_owner, expected_source, expected_maintainer,
        expected_target, target_storage_epoch, current_statuses, at, action, policy, budget, on_observed=None):
    """Current permission for B to read a fully reconstructed original root copy.

    Internal callers reconstruct the replica in this operation, retain authentic
    observations, and check actual storage plus recipient possession separately.
    Source and maintainer may share keys; each role still signs its exact consent.
    """
    from memory_vault_open_repair_copy_authority import RETURN_FIELDS, copy_return_permissions
    wire._context(policy, budget); wire.u53(at)
    if action not in ('challenge', 'proof', 'child'): wire._fail('repair_access_action')
    source = replica['source']; plan = replica['authority']; custody = replica['custody']
    root = plan.assignment.payload['root_key']; bootstrap = source['setup']['originals']['bootstrap']
    parties = wire.build_new_wire(dict(owner=expected_owner, source=expected_source, maintainer=expected_maintainer,
        target=expected_target), policy, budget).value
    owner_id = resource._dual_key(parties['owner'], budget)
    signers = {keys['signing_key']['key_id']: keys['signing_key'] for keys in parties.values()}
    variants = ('owner', 'source', 'maintainer'); wire.object_fields(consent_entries, set(variants))
    allowed = {key: [] for key in signers}; obligations = []; consents = []; denial = None
    expires = min(custody.payload['read_until'], custody.payload['retain_until'], bootstrap.payload['expires_at'],
        bootstrap.payload['probe_until'] if action == 'challenge' else bootstrap.payload['proof_until'])
    for variant in variants:
        signer = parties[variant]['signing_key']
        consent = index._signed(consent_entries[variant], signer, 'mailbox.replica_return_consent', RETURN_FIELDS, policy, budget)
        p = consent.payload; resource._opaque(p['consent_id']); wire.u53(p['revision'], 1); resource._lifetime(p)
        if not p['issued_at'] <= at < p['expires_at']: denial = denial or 'repair_access_expired'
        _same(p['variant'] == variant and p['root_key'] == root and p['source_custody_ref'] == source['custody'].ref.as_dict()
            and p['historical_manifest_ref'] == plan.allocation.payload['intent']['historical_manifest_ref']
            and p['assignment_ref'] == plan.assignment.ref.as_dict() and p['subject'] == owner_id
            and p['target'] == parties['target'] and p['target_storage_epoch'] == target_storage_epoch
            and p['bootstrap_grant_ref'] == bootstrap.ref.as_dict() and p['issued_at'] >= plan.assignment.payload['issued_at'])
        permission = wire.object_fields(p['return_permission'], {'originals', 'status_scopes', 'until'})
        originals, scopes = copy_return_permissions(plan, signer['key_id'], policy, budget)
        _same(permission['originals'] == originals and permission['status_scopes'] == scopes
            and p['issued_at'] < wire.u53(permission['until']) <= min(p['expires_at'],
                plan.assignment.payload['windows']['read_until'], source['read_until'], bootstrap.payload['proof_until']))
        expires = min(expires, permission['until'], p['expires_at'])
        scope = index._authority(root, consent, policy, budget)
        allowed[signer['key_id']].extend((*scopes, dict(scope_kind='authority', scope_id=scope)))
        obligations.append(index._obligation(signer, 'authority', scope, p['revision'], 2))
        consents.append(consent)
    # All B-authored discovery and selected-slot metadata remain under the
    # original live READ/DISCOVER conditions. The old source's storage capacity
    # is historical; P's actual resource below supplies present storage rights.
    obligations.extend(index._obligation(item['signer'], item['kind'], item['scope_id'], item['revision'], item['bits'])
        for item in source['obligations'] if item['signer'] == parties['owner']['signing_key'])
    obligations.append(index._obligation(parties['maintainer']['signing_key'], 'assignment',
        status.status_scope(root, 'assignment', dict(assignment_kind='maintenance.assignment',
            assignment_sha256=plan.assignment.ref.raw_sha256), policy, budget), 0, 2))
    target_scope = status.status_scope(root, 'resource', custody.payload['resource'], policy, budget)
    allowed[parties['target']['signing_key']['key_id']].append(dict(scope_kind='resource', scope_id=target_scope))
    obligations.append(index._obligation(parties['target']['signing_key'], 'resource', target_scope,
        custody.payload['reservation_generation'], 2))
    allowed = {key: [dict(scope_kind=kind, scope_id=scope) for kind, scope in sorted(
        {(e['scope_kind'], e['scope_id']) for e in values})] for key, values in allowed.items()}
    for item in plan.statuses:
        permitted = {(e['scope_kind'], e['scope_id']) for e in allowed[item.payload['signing_key']['key_id']]}
        if any((e['scope_kind'], e['scope_id']) not in permitted for e in item.payload['entries']):
            wire._fail('repair_status_disclosure')
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
    previous = (*source['statuses'], *plan.statuses)
    try: empty._history_floors((*previous, *checked), previous=previous, current=checked)
    except wire.RepairWireError as error: denial = denial or error.code
    for need in obligations:
        values = [entry for item in checked if item.payload['signing_key'] == need['signer'] for entry in item.payload['entries']
            if (entry['scope_kind'], entry['scope_id']) == (need['scope_kind'], need['scope_id'])]
        if not values: denial = denial or 'repair_status_missing'
        for value in values:
            if value['status'] == 'revoked': denial = denial or 'repair_authority_revoked'
            elif value['minimum_document_revision'] > need['revision']: denial = denial or 'repair_status_revision'
            elif value['operation_mask'] & need['mask'] != need['mask']: denial = denial or 'repair_status_operation'
    if checked: expires = min(expires, *(item.payload['valid_until'] for item in checked))
    if at >= expires: denial = denial or 'repair_access_expired'
    return dict(expires_at=expires, consents=tuple(consents), statuses=tuple(checked), obligations=tuple(obligations),
        subject=owner_id, bootstrap=bootstrap, denial_code=denial)
