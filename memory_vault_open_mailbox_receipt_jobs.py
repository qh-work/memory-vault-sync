"""Explicit per-message receipt destinations retained for ordinary receive."""
import hashlib
import time

from memory_vault import MemoryError, canonical_bytes
from memory_vault_network_crypto import document, object_fields
from memory_vault_open_control import coordinate
from memory_vault_open_delivery import _hex
from memory_vault_open_transport import endpoint

TABLE = 'open_mailbox_receipt_jobs'
ACTIONS = {'register_mailbox_receipt_return', 'list_mailbox_receipt_returns',
    'inspect_mailbox_receipt_return', 'remove_mailbox_receipt_return'}
FIELDS = {'schema_version','action','message_id','source_url','source_key_id','repair_profile'}


class ObservedTransport:
    def __init__(self, transport, observer, deadline=None):
        self.transport, self.observer, self.deadline = transport, observer, deadline

    def __getattr__(self, name):
        return getattr(self.transport, name)

    def request_repair(self, *args, **kwargs):
        if self.deadline is not None:
            if time.monotonic() >= self.deadline: raise MemoryError('open_delivery_budget_exhausted',retryable=True)
            kwargs['deadline'] = min(kwargs['deadline'], self.deadline)
        if self.observer is not None: self.observer()
        return self.transport.request_repair(*args, **kwargs)


def initialize(network):
    network._delivery()
    with network.participant.state.db() as db:
        db.execute('''CREATE TABLE IF NOT EXISTS open_mailbox_receipt_jobs(
            message_id TEXT PRIMARY KEY, body BLOB NOT NULL, body_sha256 TEXT NOT NULL,
            phase TEXT NOT NULL, result BLOB, result_sha256 TEXT,
            last_attempt INTEGER NOT NULL DEFAULT 0)''')


def checked(network, value):
    from memory_vault_open_client import ACK_CONNECT_SCHEMA
    from memory_vault_open_repair_provision import PROFILES
    object_fields(value, FIELDS)
    if value['schema_version'] != ACK_CONNECT_SCHEMA or value['action'] != 'register_mailbox_receipt_return':
        raise MemoryError('open_invalid_ack_request')
    _hex(value['message_id'], prefix='msg_'); coordinate(value['source_key_id'])
    if type(value['repair_profile']) is not str or value['repair_profile'] not in PROFILES:
        raise MemoryError('open_invalid_repair_policy')
    endpoint(value['source_url'], allow_loopback=network.participant.transport.allow_loopback)
    return dict(value, source_url=value['source_url'].rstrip('/'))


def read_body(row, name):
    raw = bytes(row[name])
    if hashlib.sha256(raw).hexdigest() != row[name+'_sha256']:
        raise MemoryError('open_ack_mailbox_return_corrupt')
    return document(raw, maximum=8192)


def connect(network, value):
    initialize(network); action = value['action']
    if action == 'register_mailbox_receipt_return':
        value = checked(network, value); raw = canonical_bytes(value)
        if len(raw) > 4096: raise MemoryError('open_ack_mailbox_return_capacity')
        with network.participant.state.db() as db:
            db.execute('BEGIN IMMEDIATE')
            old = db.execute('SELECT * FROM '+TABLE+' WHERE message_id=?', (value['message_id'],)).fetchone()
            if old is not None:
                if read_body(old, 'body') != value: raise MemoryError('open_ack_mailbox_return_conflict')
            else:
                if db.execute('SELECT count(*) FROM '+TABLE).fetchone()[0] >= 16:
                    raise MemoryError('open_ack_mailbox_return_capacity')
                db.execute('INSERT INTO '+TABLE+'(message_id,body,body_sha256,phase) VALUES(?,?,?,?)',
                    (value['message_id'],raw,hashlib.sha256(raw).hexdigest(),'pending'))
        return dict(state='registered',message_id=value['message_id'],network_accessed=False,
            receipt_return='ordinary_receive_after_saved_original_authority_check')
    if action == 'list_mailbox_receipt_returns':
        object_fields(value, {'schema_version','action'})
        with network.participant.state.db() as db:
            rows = db.execute('SELECT message_id,phase FROM '+TABLE+' ORDER BY message_id').fetchall()
        return dict(state='configured',returns=[dict(message_id=r['message_id'],state=r['phase']) for r in rows],network_accessed=False)
    object_fields(value, {'schema_version','action','message_id'}); _hex(value['message_id'],prefix='msg_')
    with network.participant.state.db() as db:
        if action == 'remove_mailbox_receipt_return':
            db.execute('DELETE FROM '+TABLE+' WHERE message_id=?',(value['message_id'],))
            return dict(state='removed',message_id=value['message_id'],network_accessed=False)
        row = db.execute('SELECT * FROM '+TABLE+' WHERE message_id=?',(value['message_id'],)).fetchone()
    if row is None: raise MemoryError('open_ack_mailbox_return_missing')
    return dict(state=row['phase'],selection=read_body(row,'body'),
        result=read_body(row,'result') if row['result'] is not None else None,network_accessed=False,source_rechecked=False)


def poll(network, result, *, deadline, attempted):
    """One ready job per call; at most two per ordinary receive invocation."""
    from memory_vault_open_repair_wire import RepairWireError
    initialize(network)
    if len(attempted) >= 2 or time.monotonic() >= deadline: return
    with network.participant.state.db() as db:
        rows = db.execute('''SELECT j.* FROM open_mailbox_receipt_jobs AS j
            JOIN open_delivery_inbox AS i ON i.message_id=j.message_id
            WHERE j.phase='pending' AND i.phase='saved'
            ORDER BY j.last_attempt,j.message_id LIMIT 3''').fetchall()
    row = next((r for r in rows if r['message_id'] not in attempted), None)
    if row is None: return
    message_id = row['message_id']; attempted.add(message_id)
    with network.participant.state.db() as db:
        db.execute('UPDATE '+TABLE+' SET last_attempt=? WHERE message_id=?',(time.time_ns(),message_id))
    try:
        value = checked(network, read_body(row,'body'))
        if value['message_id'] != message_id: raise MemoryError('open_ack_mailbox_return_corrupt')
        def accessed(): result['network_accessed'] = True
        returned = network._ack_return_mailbox_receipt(dict(value,action='return_mailbox_receipt'),
            _deadline=deadline,_network_observer=accessed)
        raw = canonical_bytes(returned)
        with network.participant.state.db() as db:
            db.execute("UPDATE "+TABLE+" SET phase='complete',result=?,result_sha256=? WHERE message_id=? AND body_sha256=?",
                (raw,hashlib.sha256(raw).hexdigest(),message_id,row['body_sha256']))
        result.setdefault('receipt_returns',[]).append(dict(message_id=message_id,state=returned['state'],
            from_local_history=returned['from_local_history']))
        result['network_accessed'] |= returned['network_accessed']
    except (MemoryError,RepairWireError) as error:
        phase = 'reconciliation_required' if error.code in {'repair_reconciliation_required','repair_saved_reconciliation_required'} else 'pending'
        raw=canonical_bytes(dict(state=phase,code=error.code,retryable=getattr(error,'retryable',False)))
        with network.participant.state.db() as db:
            db.execute("UPDATE "+TABLE+" SET phase=?,result=?,result_sha256=? WHERE message_id=? AND body_sha256=?",
                (phase,raw,hashlib.sha256(raw).hexdigest(),message_id,row['body_sha256']))
        result['errors'].append(dict(message_id=message_id,operation='return_mailbox_receipt',
            code=error.code,retryable=getattr(error,'retryable',False)))


def recover_prepared(network, delivery, arguments, *, deadline):
    """A repeated original send can use its separately prepared owner READ grant."""
    from memory_vault_open_control import verify_node
    from memory_vault_open_delivery import envelope_ref
    from memory_vault_open_repair_wire import RepairWireError
    result=dict(network_accessed=False)
    if set(arguments)-{'request_id','recipients','text','memory_ids','control'}:return result
    input_sha,_=delivery._send_input(arguments.get('request_id'),arguments.get('recipients'),
        arguments.get('text',''),arguments.get('memory_ids'),arguments.get('control'))
    row=delivery._outbox(arguments['request_id'])
    if row is None:return result
    if row['input_sha256'] != input_sha:raise MemoryError('network_request_id_conflict')
    if row['result'] is None or row['acknowledgement'] is not None:return result
    network._ack_preparations_initialize()
    with network.participant.state.db() as db:
        prepared=db.execute('SELECT result FROM open_ack_agent_preparations WHERE request_id=?',(arguments['request_id'],)).fetchone()
    if prepared is None or prepared['result'] is None:return result
    try:
        invitation=network._ack_preparation_value(arguments['request_id'],'owner_invitation')
        request=invitation['request']
        if (request['expected_message_id']!=row['message_id']
                or request['expected_envelope_ref']!=envelope_ref(bytes(row['envelope']))
                or request['expected_receipt_writer']['signing_key']['key_id']!=row['recipient']):
            raise MemoryError('open_ack_preparation_conflict')
        old=document(request['target_node_entry']['raw'].encode('utf-8'))['payload']
        if time.monotonic()>=deadline:raise MemoryError('open_delivery_budget_exhausted',retryable=True)
        result['network_accessed']=True
        current=network.participant.transport.request_node(invitation['base_url'],deadline=deadline).response
        node=verify_node(current)
        if (node['status']!='active' or node['signing_key']!=request['expected_target']['signing_key']
                or node['storage_epoch']!=old['storage_epoch'] or node['revision']<old['revision']
                or endpoint(node['base_url'],allow_loopback=network.participant.transport.allow_loopback)
                    !=endpoint(invitation['base_url'],allow_loopback=network.participant.transport.allow_loopback)):
            raise MemoryError('open_ack_preparation_conflict')
        raw=canonical_bytes(current);digest=hashlib.sha256(raw).hexdigest()
        request['target_node_entry']=dict(raw=raw.decode('utf-8'),ref=dict(namespace='meta',key=digest,raw_sha256=digest,size=len(raw)))
        recovered=network._ack_connect(invitation,_deadline=deadline)
        result['state']=recovered['state']
    except (MemoryError,RepairWireError) as error:
        result['error']=dict(code=error.code,retryable=getattr(error,'retryable',False))
    return result
