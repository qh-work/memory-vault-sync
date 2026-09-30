"""Explicitly retained replica selections for ordinary bounded mailbox polling."""
from dataclasses import replace
import hashlib
import time

from memory_vault import MemoryError, canonical_bytes
from memory_vault_network_crypto import document, object_fields, opaque
from memory_vault_open_control import verify_node
from memory_vault_open_transport import endpoint
from memory_vault_open_repair_admin import _ReplicaStatusJournal
from memory_vault_open_repair_mailbox_activation import verify_mailbox_feed_bootstrap
from memory_vault_open_repair_original import verify_original_control, _node_shape
from memory_vault_open_repair_resource import _dual_key
from memory_vault_open_repair_state import DEFAULT_POLICY, MAILBOX_WORKFLOW_LIMITS
import memory_vault_open_repair_status as status
import memory_vault_open_repair_wire as wire

TABLE = 'open_mailbox_replica_receivers'
FIELDS = {'expected_slot', 'expected_sender', 'expected_target', 'expected_source', 'source_storage_epoch',
    'expected_maintainer', 'expected_envelope_ref', 'target_node_entry', 'slot_entries', 'known_statuses', 'archive_statuses'}


def initialize(network):
    network._mailbox_receivers_initialize()
    with network.participant.state.db() as db:
        db.execute('''CREATE TABLE IF NOT EXISTS open_mailbox_replica_receivers(
            receiver_id TEXT PRIMARY KEY, selection_digest TEXT NOT NULL, envelope_sha256 TEXT NOT NULL,
            body BLOB NOT NULL, body_sha256 TEXT NOT NULL, last_attempt INTEGER NOT NULL DEFAULT 0)''')


def decode(entry):
    object_fields(entry, {'raw', 'ref'})
    if type(entry['raw']) is not str: raise MemoryError('open_invalid_mailbox_receiver')
    return dict(raw=entry['raw'].encode('utf-8'), ref=entry['ref'])


def checked(network, value, *, current_node=True):
    object_fields(value, {'schema_version', 'action', 'base_url', 'repair_profile', 'request'})
    if value['schema_version'] != 'memory-vault-open-mailbox-connect/v1' or value['action'] != 'register_replica' or value['repair_profile'] != 'mailbox':
        raise MemoryError('open_invalid_mailbox_receiver')
    request = object_fields(value['request'], FIELDS)
    policy = replace(DEFAULT_POLICY, max_signature_checks=512); budget = wire.RepairBudget(policy)
    expected = wire.build_new_wire({k: request[k] for k in FIELDS - {'target_node_entry', 'slot_entries', 'known_statuses', 'archive_statuses'}}, policy, budget).value
    now = int(time.time())
    owner = dict(signing_key=network.identity.public_descriptor(), encryption_key=network.encryption.public_descriptor())
    parties = (owner,)+tuple(expected[k] for k in ('expected_sender', 'expected_target', 'expected_source', 'expected_maintainer'))
    for keys in parties: _dual_key(keys, budget)
    if _dual_key(expected['expected_target'], budget) in tuple(_dual_key(expected[k], budget) for k in ('expected_source', 'expected_maintainer')):
        raise MemoryError('open_invalid_mailbox_receiver')
    object_fields(request['slot_entries'], {'slot', 'read', 'maintenance', 'bootstrap'})
    setup = verify_mailbox_feed_bootstrap({k: decode(e) for k,e in request['slot_entries'].items()},
        expected_slot=expected['expected_slot'], expected_owner=owner, expected_target=expected['expected_source'],
        target_storage_epoch=expected['source_storage_epoch'], limit_policy=MAILBOX_WORKFLOW_LIMITS,
        at=now, policy=policy, budget=budget)
    if (setup['slot'].payload['sender'] != _dual_key(expected['expected_sender'], budget)
            or _dual_key(expected['expected_maintainer'], budget) not in setup['maintenance'].payload['maintainers']):
        raise MemoryError('open_invalid_mailbox_receiver')
    envelope = wire.raw_ref(expected['expected_envelope_ref'])
    if envelope.namespace != 'object': raise MemoryError('open_invalid_mailbox_receiver')
    entry = decode(request['target_node_entry']); ref = wire.raw_ref(entry['ref'])
    # An expired saved introduction only pins the same key/origin/epoch. A
    # current public introduction is fetched before any recovery exchange.
    node_at = now if current_node else document(entry['raw'])['payload']['issued_at']
    node = verify_original_control(entry['raw'], expected_signing_key=expected['expected_target']['signing_key'],
        expected_schema='memory-vault-open-control/v1', expected_kind='node', at=node_at, policy=policy, budget=budget)
    _node_shape(node, node_at, budget)
    if (ref.namespace != 'meta' or ref.size != len(entry['raw']) or ref.raw_sha256 != node.raw_sha256
            or endpoint(value['base_url'], allow_loopback=network.participant.transport.allow_loopback) !=
                endpoint(node.payload['base_url'], allow_loopback=network.participant.transport.allow_loopback)):
        raise MemoryError('open_invalid_mailbox_receiver')
    for name, maximum in (('known_statuses', 16), ('archive_statuses', 32)):
        if type(request[name]) is not list or len(request[name]) > maximum: raise MemoryError('repair_status_history_capacity')
    return expected, node.payload, parties, policy, budget


def connect(network, value):
    initialize(network); action = value['action']
    if action == 'list_replicas':
        object_fields(value, {'schema_version', 'action'})
        with network.participant.state.db() as db:
            ids = [r[0] for r in db.execute('SELECT receiver_id FROM '+TABLE+' ORDER BY receiver_id')]
        return dict(state='configured', replicas=ids, network_accessed=False)
    if action in ('remove_replica', 'inspect_replica'):
        object_fields(value, {'schema_version', 'action', 'receiver_id'} | ({'cursor'} if action=='inspect_replica' and 'cursor' in value else set()))
        receiver_id = opaque(value['receiver_id'])
        with network.participant.state.db() as db:
            if action == 'remove_replica':
                db.execute('DELETE FROM '+TABLE+' WHERE receiver_id=?', (receiver_id,))
                return dict(state='removed', receiver_id=receiver_id, network_accessed=False)
            row = db.execute('SELECT body,body_sha256 FROM '+TABLE+' WHERE receiver_id=?', (receiver_id,)).fetchone()
        if row is None: raise MemoryError('open_mailbox_receiver_missing')
        raw = bytes(row['body'])
        if hashlib.sha256(raw).hexdigest() != row['body_sha256']: raise MemoryError('open_invalid_mailbox_receiver')
        return network._mailbox_page(raw, receiver_id, value.get('cursor'), 'replica_configuration')
    expected, node, parties, policy, budget = checked(network, value)
    # Keep authenticated denials independently of this removable selection.
    signers = {p['signing_key']['key_id']: p['signing_key'] for p in parties}
    with network.participant.state.db() as db:
        journal = _ReplicaStatusJournal(db, expected['expected_slot']['root_key'])
        for name in ('known_statuses', 'archive_statuses'):
            for item in value['request'][name]:
                entry = decode(item); payload = wire.parse_new_wire(entry['raw'], policy, budget).value['payload']
                issuer = payload['signing_key']['key_id']
                if issuer not in signers: raise MemoryError('repair_status_disclosure')
                status.authenticate_status_original(entry, expected_root=expected['expected_slot']['root_key'],
                    expected_signing_key=signers[issuer], at=payload['issued_at'],
                    allowed_scopes=[dict(scope_kind=e['scope_kind'], scope_id=e['scope_id']) for e in payload['entries']],
                    policy=policy, budget=budget, on_authenticated=journal.observe)
    selection = hashlib.sha256(canonical_bytes(dict(slot=expected['expected_slot'], sender=expected['expected_sender'], envelope=expected['expected_envelope_ref']))).hexdigest()
    receiver_id = 'replica_'+hashlib.sha256(canonical_bytes(dict(selection=selection, target=expected['expected_target'], epoch=node['storage_epoch']))).hexdigest()
    raw = canonical_bytes(value)
    if len(raw) > 65536: raise MemoryError('open_mailbox_receiver_capacity')
    with network.participant.state.db() as db:
        db.execute('BEGIN IMMEDIATE')
        old = db.execute('SELECT body FROM '+TABLE+' WHERE receiver_id=?', (receiver_id,)).fetchone()
        if old is not None and bytes(old[0]) != raw: raise MemoryError('open_mailbox_receiver_conflict')
        if old is None:
            if (db.execute('SELECT count(*) FROM '+TABLE).fetchone()[0] >= 16
                    or db.execute('SELECT count(*) FROM '+TABLE+' WHERE envelope_sha256=?', (expected['expected_envelope_ref']['raw_sha256'],)).fetchone()[0] >= 2):
                raise MemoryError('open_mailbox_receiver_capacity')
            db.execute('INSERT INTO '+TABLE+'(receiver_id,selection_digest,envelope_sha256,body,body_sha256) VALUES(?,?,?,?,?)',
                (receiver_id, selection, expected['expected_envelope_ref']['raw_sha256'], raw, hashlib.sha256(raw).hexdigest()))
    return dict(state='registered', receiver_id=receiver_id, network_accessed=False, recovery='ordinary_receive', receipt_return='separate_authority_required')


def rows(network):
    initialize(network)
    with network.participant.state.db() as db:
        return db.execute('''SELECT receiver_id,body,last_attempt,'original' AS receiver_kind,NULL AS body_sha256
            FROM open_mailbox_receivers UNION ALL
            SELECT receiver_id,body,last_attempt,'replica' AS receiver_kind,body_sha256
            FROM open_mailbox_replica_receivers AS r WHERE NOT EXISTS(
                SELECT 1 FROM open_delivery_inbox AS i WHERE i.envelope_sha256=r.envelope_sha256 AND i.phase!='staged')
            ORDER BY last_attempt,receiver_id LIMIT 4''').fetchall()


def receive(network, row, *, deadline, accessed):
    raw = bytes(row['body'])
    if hashlib.sha256(raw).hexdigest() != row['body_sha256']: raise MemoryError('open_invalid_mailbox_receiver')
    value = document(raw, maximum=65536)
    expected, old_node, _, _, _ = checked(network, value, current_node=False)
    if time.monotonic() >= deadline: raise MemoryError('open_delivery_budget_exhausted', retryable=True)
    accessed()
    introduction = network.participant.transport.request_node(value['base_url'], deadline=deadline).response
    node = verify_node(introduction)
    if (node['status'] != 'active' or node['signing_key'] != expected['expected_target']['signing_key']
            or node['storage_epoch'] != old_node['storage_epoch'] or node['revision'] < old_node['revision']
            or endpoint(node['base_url'], allow_loopback=network.participant.transport.allow_loopback) !=
                endpoint(value['base_url'], allow_loopback=network.participant.transport.allow_loopback)):
        raise MemoryError('open_invalid_mailbox_receiver')
    current = canonical_bytes(introduction); digest = hashlib.sha256(current).hexdigest()
    value['request']['target_node_entry'] = dict(raw=current.decode('utf-8'), ref=dict(namespace='meta',key=digest,raw_sha256=digest,size=len(current)))
    value['action'] = 'receive_replica'
    remaining = deadline-time.monotonic()
    if remaining <= 0: raise MemoryError('open_delivery_budget_exhausted', retryable=True)
    return network._mailbox_receive_replica(value, timeout=min(60, remaining))
