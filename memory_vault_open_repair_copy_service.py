"""Persistent replica owner possession exchange and protected proof children.

Operator-installed configuration contains public originals only. Remote requests
reuse the bootstrap wire with an explicit unbound, empty or occupied replica state.
This read service grants no recipient ADMIT or automatic replacement selection.
"""
from contextlib import contextmanager
import secrets
from weakref import WeakKeyDictionary

from memory_vault_open_repair_access import AccessDecision, _Preparation
from memory_vault_open_repair_copy_state import RepairCopyState
from memory_vault_open_repair_service import RepairBootstrapService
from memory_vault_open_repair_state import ROW_CHARGE
import memory_vault_open_repair_probe as probe
import memory_vault_open_repair_proof as proof
import memory_vault_open_repair_wire as wire


def _encode(entry):
    return dict(raw=entry['raw'].decode('utf-8'),ref=entry['ref'])


def _decode(entry):
    wire.object_fields(entry,{'raw','ref'})
    if type(entry['raw']) is not str:wire._fail('repair_invalid_context')
    return dict(raw=entry['raw'].encode('utf-8'),ref=entry['ref'])


class ReplicaReadAccess:
    def __init__(self,service):
        self.service=service;self.store=service.store;self._prepared=WeakKeyDictionary()

    def initialize(self):
        self.store.initialize()
        with self.store.source._transaction():
            self.store.db.execute('CREATE TABLE IF NOT EXISTS open_repair_copy_read_config(resource_id TEXT PRIMARY KEY,owner TEXT NOT NULL,grant_sha256 TEXT NOT NULL,raw BLOB NOT NULL,digest TEXT NOT NULL)')

    def prepare(self,resource_id,*,action,current_statuses=None,expected_generation=None,policy=None,budget=None):
        if budget is None:budget=wire.RepairBudget(self.store.source.policy)
        if policy is not None:wire._context(policy,budget)
        cfg=self.service._configuration(resource_id,budget)
        if current_statuses is not None:wire._fail('repair_replica_config_update_required')
        held=self.service._prepare_read(resource_id,{k:_decode(v) for k,v in cfg['consents'].items()},
            **cfg['context'],current_statuses=[_decode(v) for v in cfg['statuses']],
            limit_policy=self.store.source.limits,action=action,_budget=budget,_include_replica=True)
        if _decode(cfg['bootstrap'])!=dict(raw=held['bootstrap'].raw,ref=held['bootstrap'].ref.as_dict()):
            wire._fail('repair_storage_corrupt')
        held['generation_error']=expected_generation not in (None,1)
        children=[]
        for role,entries in held['_replica']['entries'].items():
            children.extend(dict(role=role,raw=e['raw'],ref=wire.raw_ref(e['ref'])) for e in entries)
        with self.store.source._transaction():
            _,commit=self.store._committed(resource_id)
            for role,name in (('replica.manifest','manifest'),('replica.custody','custody')):
                entry=self.store.source._saved(commit,name)
                children.append(dict(role=role,raw=entry['raw'],ref=wire.raw_ref(entry['ref'])))
        names=('owner','source','maintainer')+(('recipient',) if self.service.resource_state=='replica_occupied' else ())
        for name,item in zip(names,held['consents']):
            children.append(dict(role='return.'+name,raw=item.raw,ref=item.ref))
        children.extend(dict(role='current.status.replica_read',raw=item.raw,ref=item.ref) for item in held['statuses'])
        if self.service.resource_state in ('replica_empty','replica_occupied'):
            # A byte container of these already authorized originals reduces
            # round trips without changing their refs, authority or byte charge.
            # Source history packs remain separate and retain their exact bytes.
            packed=wire.build_raw_pack([item['raw'] for item in children
                if item['role'] in proof.replica_read_pack_roles(self.service.resource_state)],budget.policy,budget)
            children.append(dict(role='replica.read_pack',raw=packed.raw,ref=packed.ref))
        children.sort(key=lambda e:(e['role'],e['ref'].namespace,e['ref'].key,e['ref'].raw_sha256,e['ref'].size))
        held['children']=tuple(children);token=_Preparation();self._prepared[token]=held
        return token

    def check_locked(self,prepared):
        held=self._prepared.get(prepared)
        if held is None:wire._fail('repair_invalid_context')
        s=self.store.source;code=None
        if held['generation_error']:code='repair_access_generation'
        elif s._now()>=held['expires_at']:code='repair_access_expired'
        else:
            try:
                if self.store._read_snapshot(held['resource_id'],held['_root_digest'])!=held['_stamp']:
                    code='repair_access_generation'
            except wire.RepairWireError as error:code=error.code
        grant=held['bootstrap']
        return AccessDecision(code is None,code,1,held['expires_at'],held['resource_id'],held['subject'],
            grant.payload['selector'],grant.ref,grant.payload['limits'])

    def proof_inputs(self,prepared):
        decision=self.check_locked(prepared)
        return decision,self._prepared[prepared]['children'] if decision.allowed else ()


class ReplicaReadService(RepairBootstrapService):
    resource_state='replica_unbound'
    bound_context=frozenset()

    def __init__(self,state):
        self.state,self.db=state,state.db;self.store=RepairCopyState(state)
        self.access=ReplicaReadAccess(self)

    def _prepare_read(self,*args,**options):
        return self.store.prepare_unbound_read(*args,**options)

    def configure(self,resource_id,*,context,consents,current_statuses):
        """Local operator action; denied status updates still retain revocations."""
        wire.object_fields(context,{'expected_ack_slot','expected_owner','expected_source',
            'source_storage_epoch','expected_maintainer'}|self.bound_context)
        budget=wire.RepairBudget(self.state.policy)
        decision=self._prepare_read(resource_id,consents,**context,current_statuses=current_statuses,
            limit_policy=self.state.limits,action='challenge',_budget=budget)
        value=dict(context=context,consents={key:_encode(entry) for key,entry in consents.items()},
            statuses=[_encode(entry) for entry in current_statuses],bootstrap=_encode(dict(
                raw=decision['bootstrap'].raw,ref=decision['bootstrap'].ref.as_dict())))
        if self.resource_state=='replica_occupied':value['source_state']=self.resource_state
        raw=wire.build_new_wire(value,budget.policy,budget).raw;digest=budget._hash(raw)
        with self.state._transaction() as now:
            row,held=self.store._committed(resource_id)
            if self.state._saved(held,'custody')['ref']!=decision['replica_custody_ref'] or now>=decision['expires_at']:
                wire._fail('repair_access_generation')
            caps=self._active_budget(row,budget)
            previous=self.state._one('SELECT * FROM open_repair_copy_read_config WHERE resource_id=?',(resource_id,))
            old_size=len(previous['raw'])+len(previous['digest'])+ROW_CHARGE if previous else 0
            if self.store._metadata(row)-old_size+len(raw)+len(digest)+ROW_CHARGE>caps['max_meta_bytes']:
                wire._fail('repair_service_capacity')
            self.db.execute('INSERT OR REPLACE INTO open_repair_copy_read_config VALUES(?,?,?,?,?)',
                (resource_id,context['expected_owner']['signing_key']['key_id'],decision['bootstrap'].ref.raw_sha256,raw,digest))
        return dict(state='configured',resource_id=resource_id)

    def _configuration(self,resource_id,budget):
        saved=self.state._one('SELECT * FROM open_repair_copy_read_config WHERE resource_id=?',(resource_id,))
        if saved is None:wire._fail('repair_service_unavailable')
        raw=bytes(saved['raw'])
        if budget._hash(raw)!=saved['digest']:wire._fail('repair_storage_corrupt')
        value=wire.parse_new_wire(raw,budget.policy,budget).value
        wire.object_fields(value,{'context','consents','statuses','bootstrap'}|({'source_state'} if self.resource_state=='replica_occupied' else set()))
        if self.resource_state=='replica_occupied' and value['source_state']!=self.resource_state:wire._fail('repair_storage_corrupt')
        if (value['context']['expected_owner']['signing_key']['key_id']!=saved['owner']
                or value['bootstrap']['ref']['raw_sha256']!=saved['grant_sha256']):wire._fail('repair_storage_corrupt')
        return value

    def _context(self,resource_id,budget):
        with self.state._transaction():row,_=self.store._committed(resource_id)
        cfg=self._configuration(resource_id,budget)
        grant=wire.parse_new_wire(cfg['bootstrap']['raw'].encode(),budget.policy,budget).value['payload']
        source=dict(row,metadata_bytes=self.store._metadata(row))
        return source,grant,dict(expected_subject=cfg['context']['expected_owner'],expected_target=self.state.target,
            target_storage_epoch=self.state.node['payload']['storage_epoch'],bootstrap_grant_sha256=cfg['bootstrap']['ref']['raw_sha256'],
            selector=grant['selector'],at=self.state._now(),policy=budget.policy,budget=budget,consumer=self.consumer)

    def _grant_entry(self,resource_id):
        return _decode(self._configuration(resource_id,wire.RepairBudget(self.state.policy))['bootstrap'])

    def _lookup_probe(self,payload):
        p=probe._fields(payload,probe._FIELDS['probe'])
        rows=self.db.execute('SELECT resource_id FROM open_repair_copy_read_config WHERE owner=? AND grant_sha256=? LIMIT 2',
            (p['subject']['signing_key']['key_id'],p['bootstrap_grant_sha256'])).fetchall()
        if len(rows)!=1:wire._fail('repair_service_unavailable')
        return rows[0][0]

    def _active_budget(self,source,budget):
        return wire.parse_new_wire(bytes(source['offer']),budget.policy,budget).value['payload']['budget']

    @contextmanager
    def _work(self,source,grant,active,reference,payload,budget):
        allowance=budget.policy.max_signature_checks;attempt='copy_work_'+secrets.token_hex(16)
        with self.state._transaction() as now:
            current,_=self.store._committed(source['resource_id'])
            if current['request_digest']!=source['request_digest']:wire._fail('repair_access_generation')
            usage,reserved=self._usage(source['resource_id'])
            current=dict(current,metadata_bytes=self.store._metadata(current))
            if (not self._room(current,grant,active,usage,reserved,allowance)
                    or current['metadata_bytes']+(1 if usage else 2)*ROW_CHARGE>active['max_meta_bytes']):
                wire._fail('repair_service_capacity')
            self.db.execute('INSERT INTO open_repair_bootstrap_usage VALUES(?,1,0,0,1) ON CONFLICT(resource_id) DO UPDATE SET requests=requests+1,replays=replays+1',(source['resource_id'],))
            self.db.execute('INSERT INTO open_repair_bootstrap_work VALUES(?,?,?,?,NULL,?,?)',
                (attempt,source['resource_id'],reference.raw_sha256,allowance,now,payload['expires_at']))
        try:yield
        finally:
            actual=budget.snapshot()['signature_checks']
            with self.state._transaction():
                held=self.state._one('SELECT * FROM open_repair_bootstrap_work WHERE attempt_id=?',(attempt,))
                if held is None or held['signature_checks'] is not None or not 1<=actual<=held['signature_allowance']:
                    wire._fail('repair_service_work_corrupt')
                self.db.execute('UPDATE open_repair_bootstrap_work SET signature_checks=? WHERE attempt_id=?',(actual,attempt))
                self.db.execute('UPDATE open_repair_bootstrap_usage SET signatures=signatures+? WHERE resource_id=?',(actual,source['resource_id']))

    def _charge_locked(self,decision,*,proof_bytes,metadata,capacity,replay=True):
        usage,_=self._usage(decision.resource_id);row,_=self.store._committed(decision.resource_id)
        if usage is None:wire._fail('repair_service_work_corrupt')
        # Base publication reserves raw payload lengths plus 1-KiB row charges.
        # Add conservative room for full references and our larger physical rows.
        extra=metadata+3*ROW_CHARGE if metadata else 0
        if (usage['proof_bytes']+proof_bytes>decision.limit_policy['max_proof_bytes']
                or usage['replays']+int(replay)>min(decision.limit_policy['max_replay_records'],capacity['max_replay_records'])
                or self.store._metadata(row)+extra>capacity['max_meta_bytes']):return False
        self.db.execute('UPDATE open_repair_bootstrap_usage SET proof_bytes=proof_bytes+?,replays=replays+? WHERE resource_id=?',
            (proof_bytes,int(replay),decision.resource_id))
        return True


class ReplicaEmptyReadService(ReplicaReadService):
    """Owner READ of a copied original binding, with independent return consents."""
    resource_state='replica_empty'
    bound_context=frozenset(('expected_receipt_writer','expected_message_id','expected_envelope_ref'))

    def _prepare_read(self,*args,**options):
        return self.store.prepare_empty_read(*args,**options)


class ReplicaOccupiedReadService(ReplicaEmptyReadService):
    """Return an existing receipt only under A/B/R/M permissions and P capacity."""
    resource_state='replica_occupied'

    def _prepare_read(self,*args,**options):
        return self.store.prepare_occupied_read(*args,**options)
