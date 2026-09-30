"""Retain explicitly selected ACK replicas for confirmation of an original send."""
import hashlib
import time

from memory_vault import MemoryError, canonical_bytes
from memory_vault_network_crypto import document, object_fields, opaque
from memory_vault_open_control import verify_node
from memory_vault_open_delivery import envelope_ref, _hex
from memory_vault_open_delivery_client import MAX_SESSION_BYTES
from memory_vault_open_repair_admin import _ReplicaStatusJournal
from memory_vault_open_repair_client import AckOwnerRecoveryClient
from memory_vault_open_repair_original import verify_original_control, _node_shape
from memory_vault_open_repair_resource import _dual_key, _opaque
from memory_vault_open_repair_state import DEFAULT_POLICY, RECEIPT_WORKFLOW_LIMITS, INDEX_WORKFLOW_LIMITS
from memory_vault_open_transport import endpoint
import memory_vault_open_repair_bootstrap as bootstrap
import memory_vault_open_repair_wire as wire

TABLE='open_ack_replica_senders'
ACTIONS=('register_replica_receipt','list_replica_receipts','inspect_replica_receipt','remove_replica_receipt')
FIELDS={'target_node_entry','expected_target','expected_ack_slot','root_entry','read_entry','bootstrap_entry',
        'expected_receipt_writer','expected_message_id','expected_envelope_ref','expected_source',
        'source_storage_epoch','expected_maintainer'}


def initialize(network):
    network._delivery()
    with network.participant.state.db() as db:
        db.execute('''CREATE TABLE IF NOT EXISTS open_ack_replica_senders(
            replica_id TEXT PRIMARY KEY,message_id TEXT NOT NULL,body BLOB NOT NULL,
            body_sha256 TEXT NOT NULL,last_attempt INTEGER NOT NULL DEFAULT 0,error TEXT)''')


def decode(entry):
    object_fields(entry,{'raw','ref'})
    if type(entry['raw']) is not str: raise MemoryError('open_invalid_ack_request')
    return dict(raw=entry['raw'].encode('utf-8'),ref=entry['ref'])


def checked(network,value,*,current_node=True):
    object_fields(value,{'schema_version','action','base_url','repair_profile','request'})
    if value['schema_version']!='memory-vault-open-ack-connect/v1' or value['action']!='register_replica_receipt':
        raise MemoryError('open_invalid_ack_request')
    profiles={'receipt':RECEIPT_WORKFLOW_LIMITS,'receipt-index':INDEX_WORKFLOW_LIMITS}
    if type(value['repair_profile']) is not str or value['repair_profile'] not in profiles:
        raise MemoryError('open_invalid_repair_policy')
    request=object_fields(value['request'],FIELDS|({'known_statuses'} if 'known_statuses' in value['request'] else set()))
    _hex(request['expected_message_id'],prefix='msg_');wire.raw_ref(request['expected_envelope_ref'])
    _opaque(request['source_storage_epoch'])
    budget=wire.RepairBudget(DEFAULT_POLICY); now=int(time.time())
    owner=dict(signing_key=network.identity.public_descriptor(),encryption_key=network.encryption.public_descriptor())
    parties=(owner,)+tuple(request[name] for name in ('expected_target','expected_source','expected_maintainer','expected_receipt_writer'))
    for keys in parties: _dual_key(keys,budget)
    setup=bootstrap.verify_ack_owner_bootstrap_original(decode(request['bootstrap_entry']),
        dict(root=decode(request['root_entry']),read=decode(request['read_entry'])),
        expected_ack_slot=request['expected_ack_slot'],expected_owner=owner,at=now,
        limit_policy=profiles[value['repair_profile']],policy=DEFAULT_POLICY,budget=budget)
    with network.participant.state.db() as db:
        row=db.execute('SELECT envelope,recipient,session FROM open_delivery_outbox WHERE message_id=?',
            (request['expected_message_id'],)).fetchone()
    if (row is None or envelope_ref(bytes(row['envelope']))!=request['expected_envelope_ref']
            or row['recipient']!=request['expected_receipt_writer']['signing_key']['key_id']):
        raise MemoryError('open_ack_replica_send_mismatch')
    keys=network._delivery()._keys(document(bytes(row['session']),maximum=MAX_SESSION_BYTES))
    if (request['expected_receipt_writer']!=dict(signing_key=keys['recipient_signing_key'],encryption_key=keys['recipient_encryption_key'])
            or owner!=dict(signing_key=keys['sender_signing_key'],encryption_key=keys['sender_encryption_key'])):
        raise MemoryError('open_ack_replica_send_mismatch')
    entry=decode(request['target_node_entry']); ref=wire.raw_ref(entry['ref'])
    node_at=now if current_node else document(entry['raw'])['payload']['issued_at']
    node=verify_original_control(entry['raw'],expected_signing_key=request['expected_target']['signing_key'],
        expected_schema='memory-vault-open-control/v1',expected_kind='node',at=node_at,policy=DEFAULT_POLICY,budget=budget)
    _node_shape(node,node_at,budget)
    if (ref.namespace!='meta' or ref.size!=len(entry['raw']) or ref.raw_sha256!=node.raw_sha256
            or endpoint(value['base_url'],allow_loopback=network.participant.transport.allow_loopback)!=
                endpoint(node.payload['base_url'],allow_loopback=network.participant.transport.allow_loopback)):
        raise MemoryError('open_ack_replica_send_mismatch')
    supplied=request.get('known_statuses',[])
    if type(supplied) is not list or len(supplied)>16: raise MemoryError('open_invalid_ack_request')
    with network.participant.state.db() as db:
        journal=_ReplicaStatusJournal(db,request['expected_ack_slot']['root_key'])
        reader=AckOwnerRecoveryClient(network.identity,network.encryption,limit_policy=profiles[value['repair_profile']],
            transport=network.participant.transport,status_observer=journal.observe)
        try:
            known=reader._known_replica([*journal.statuses(parties),*(decode(e) for e in supplied)],
                request['expected_ack_slot']['root_key'],parties,budget)
            reader._floors(known,(),reader._obligations(setup.originals,request['expected_ack_slot'],budget),probe_phase=True)
        finally: reader.close()
    return request,node.payload,parties


def connect(network,value):
    initialize(network); action=value['action']
    if action=='list_replica_receipts':
        object_fields(value,{'schema_version','action'})
        with network.participant.state.db() as db:
            rows=db.execute('SELECT replica_id,message_id,error FROM '+TABLE+' ORDER BY replica_id').fetchall()
        return dict(state='configured',replicas=[dict(r) for r in rows],network_accessed=False)
    if action in ('inspect_replica_receipt','remove_replica_receipt'):
        object_fields(value,{'schema_version','action','replica_id'}|({'cursor'} if action=='inspect_replica_receipt' and 'cursor' in value else set()))
        replica_id=opaque(value['replica_id'])
        with network.participant.state.db() as db:
            if action=='remove_replica_receipt':
                db.execute('DELETE FROM '+TABLE+' WHERE replica_id=?',(replica_id,))
                return dict(state='removed',replica_id=replica_id,network_accessed=False)
            row=db.execute('SELECT * FROM '+TABLE+' WHERE replica_id=?',(replica_id,)).fetchone()
        if row is None: raise MemoryError('open_ack_replica_missing')
        raw=bytes(row['body'])
        if hashlib.sha256(raw).hexdigest()!=row['body_sha256']: raise MemoryError('open_ack_replica_corrupt')
        result=network._mailbox_page(raw,replica_id,value.get('cursor'),'ack_replica_configuration')
        result['replica_id']=result.pop('receiver_id');result['last_error']=row['error']
        return result
    request,node,_=checked(network,value)
    replica_id='ackreplica_'+hashlib.sha256(canonical_bytes(dict(message_id=request['expected_message_id'],
        target=request['expected_target'],epoch=node['storage_epoch']))).hexdigest()
    raw=canonical_bytes(value)
    if len(raw)>65536: raise MemoryError('open_ack_replica_capacity')
    with network.participant.state.db() as db:
        db.execute('BEGIN IMMEDIATE')
        row=db.execute('SELECT body FROM '+TABLE+' WHERE replica_id=?',(replica_id,)).fetchone()
        if row is not None and bytes(row['body'])!=raw: raise MemoryError('open_ack_replica_conflict')
        if row is None:
            if (db.execute('SELECT count(*) FROM '+TABLE).fetchone()[0]>=16
                    or db.execute('SELECT count(*) FROM '+TABLE+' WHERE message_id=?',(request['expected_message_id'],)).fetchone()[0]>=2):
                raise MemoryError('open_ack_replica_capacity')
            db.execute('INSERT INTO '+TABLE+'(replica_id,message_id,body,body_sha256) VALUES(?,?,?,?)',
                (replica_id,request['expected_message_id'],raw,hashlib.sha256(raw).hexdigest()))
    return dict(state='registered',replica_id=replica_id,message_id=request['expected_message_id'],
        recovery='repeat_original_send',network_accessed=False)


def recover(network,delivery,arguments,*,deadline):
    """Try one explicitly registered destination within the original send budget."""
    initialize(network)
    if set(arguments)-{'request_id','recipients','text','memory_ids','control'}: return None
    digest,_=delivery._send_input(arguments.get('request_id'),arguments.get('recipients'),
        arguments.get('text',''),arguments.get('memory_ids'),arguments.get('control'))
    outbox=delivery._outbox(arguments['request_id'])
    if outbox is None: return None
    if outbox['input_sha256']!=digest: raise MemoryError('network_request_id_conflict')
    if outbox['result'] is None or outbox['acknowledgement'] is not None: return None
    with network.participant.state.db() as db:
        row=db.execute('SELECT * FROM '+TABLE+' WHERE message_id=? ORDER BY last_attempt,replica_id LIMIT 1',
            (outbox['message_id'],)).fetchone()
        if row is None: return None
        db.execute('UPDATE '+TABLE+' SET last_attempt=? WHERE replica_id=?',(time.time_ns(),row['replica_id']))
    result=dict(network_accessed=False,replica_id=row['replica_id'])
    try:
        raw=bytes(row['body'])
        if hashlib.sha256(raw).hexdigest()!=row['body_sha256']: raise MemoryError('open_ack_replica_corrupt')
        value=document(raw,maximum=65536)
        request,old,_=checked(network,value,current_node=False)
        if request['expected_message_id']!=outbox['message_id']: raise MemoryError('open_ack_replica_corrupt')
        if time.monotonic()>=deadline: raise MemoryError('open_delivery_budget_exhausted',retryable=True)
        result['network_accessed']=True
        current=network.participant.transport.request_node(value['base_url'],deadline=deadline).response
        node=verify_node(current)
        if (node['status']!='active' or node['signing_key']!=request['expected_target']['signing_key']
                or node['storage_epoch']!=old['storage_epoch'] or node['revision']<old['revision']
                or endpoint(node['base_url'],allow_loopback=network.participant.transport.allow_loopback)!=
                    endpoint(value['base_url'],allow_loopback=network.participant.transport.allow_loopback)):
            raise MemoryError('open_ack_replica_send_mismatch')
        network.participant._accept(current)
        encoded=canonical_bytes(current);sha=hashlib.sha256(encoded).hexdigest()
        request['target_node_entry']=dict(raw=encoded.decode('utf-8'),ref=dict(namespace='meta',key=sha,raw_sha256=sha,size=len(encoded)))
        value['action']='recover_replica_receipt'
        recovered=network._ack_connect(value,_deadline=deadline)
        result.update(state=recovered['state'],commit_ref=recovered['commit_ref'],replica_custody_ref=recovered['replica_custody_ref'])
        with network.participant.state.db() as db: db.execute('UPDATE '+TABLE+' SET error=NULL WHERE replica_id=?',(row['replica_id'],))
    except (MemoryError,wire.RepairWireError) as error:
        result['error']=dict(code=error.code,retryable=getattr(error,'retryable',False))
        with network.participant.state.db() as db: db.execute('UPDATE '+TABLE+' SET error=? WHERE replica_id=?',(error.code,row['replica_id']))
    return result
