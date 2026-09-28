"""Explicit, finite remote creation of an original ACK-unbound source.

A signs its existing authorities. R retains exact request bytes and the real
pending/active/unbound stages. Only durable, currently readable unbound custody
is a ready result; A must independently recover it before creating E.
"""
import hashlib
import json
import secrets

from memory_vault import canonical_bytes
import memory_vault_open_repair_ack as ack
import memory_vault_open_repair_bootstrap as bootstrap
import memory_vault_open_repair_history as history
import memory_vault_open_repair_original as original
import memory_vault_open_repair_resource as resource
import memory_vault_open_repair_status as status
import memory_vault_open_repair_wire as wire
from memory_vault_open_repair_access import RepairAckAccess, STATE_CHARGE, DOCUMENT_CHARGE, FLOOR_CHARGE
from memory_vault_open_repair_bind import encode_entry, decode_entry
from memory_vault_open_repair_service import RepairBootstrapService
from memory_vault_open_repair_state import ROW_CHARGE

SCHEMA = 'memory-vault-open-repair/v1'
MAX_BYTES = 65536
SETUP_FIELDS = frozenset('schema_version kind signing_key issued_at expires_at request_id subject target target_storage_epoch allocation_ref offer_ref ack_slot node root read bootstrap activation owner_status read_until retain_until'.split())
DEFAULT_REMOTE_POLICY = dict(enabled=False, max_owners=16, max_owner_resources=4, max_pending=8,
    max_requests=256, max_signatures=16384, max_bytes=33554432, max_journal_bytes=4194304,
    max_lifetime=86400)


def remote_policy(value=None):
    if value is None:
        return dict(DEFAULT_REMOTE_POLICY)
    if type(value) is not dict or set(value)-set(DEFAULT_REMOTE_POLICY):
        wire._fail('repair_invalid_remote_policy')
    result = dict(DEFAULT_REMOTE_POLICY, **value)
    if type(result['enabled']) is not bool:
        wire._fail('repair_invalid_remote_policy')
    for key, ceiling in DEFAULT_REMOTE_POLICY.items():
        if key != 'enabled' and (type(result[key]) is not int or not 1 <= result[key] <= ceiling):
            wire._fail('repair_invalid_remote_policy')
    return result


def _ref(raw):
    digest = hashlib.sha256(raw).hexdigest()
    return dict(namespace='meta', key=digest, raw_sha256=digest, size=len(raw))


class RepairRemoteSetupService:
    def __init__(self, state, *, policy=None):
        self.state, self.db = state, state.db
        self.policy = remote_policy(policy)
        self.access = RepairAckAccess(state)

    def initialize(self):
        self.state.initialize()
        RepairBootstrapService(self.state).initialize()
        with self.state._transaction():
            if self.policy['enabled']:
                encoded=canonical_bytes({k:v for k,v in self.policy.items() if k!='enabled'}).decode()
                previous=self.state._one("SELECT value FROM open_repair_state WHERE name='remote_setup_policy'")
                if previous is not None and previous['value']!=encoded:
                    wire._fail('repair_remote_policy_mismatch')
                self.db.execute("INSERT OR IGNORE INTO open_repair_state VALUES('remote_setup_policy',?)",(encoded,))
            self.db.execute('''CREATE TABLE IF NOT EXISTS open_repair_remote_owners(
                owner TEXT PRIMARY KEY,requests INTEGER NOT NULL,signatures INTEGER NOT NULL,
                bytes INTEGER NOT NULL,metadata INTEGER NOT NULL)''')
            self.db.execute('''CREATE TABLE IF NOT EXISTS open_repair_remote_requests(
                owner TEXT NOT NULL,allocation_id TEXT NOT NULL,kind TEXT NOT NULL,request_id TEXT NOT NULL,
                digest TEXT NOT NULL,raw BLOB NOT NULL,resource_id TEXT,response BLOB,phase TEXT NOT NULL,
                PRIMARY KEY(owner,allocation_id,kind),UNIQUE(owner,request_id))''')
            self.db.execute('''CREATE TABLE IF NOT EXISTS open_repair_remote_attempts(
                attempt_id TEXT PRIMARY KEY,owner TEXT NOT NULL,allocation_id TEXT NOT NULL,
                request_id TEXT NOT NULL,resource_id TEXT,signature_allowance INTEGER NOT NULL,
                signature_checks INTEGER,byte_allowance INTEGER NOT NULL,byte_actual INTEGER,
                created_at INTEGER NOT NULL,retain_until INTEGER NOT NULL)''')

    def _admit(self, raw, budget):
        if not self.policy['enabled']:
            wire._fail('repair_remote_setup_closed')
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_BYTES:
            wire._fail('repair_remote_setup_too_large')
        parsed = wire.parse_new_wire(raw, budget.policy, budget)
        value = parsed.value
        if value.get('kind') == 'ack.source_allocate':
            wire.object_fields(value, {'schema_version','kind','allocation','owner'})
            if value['schema_version'] != SCHEMA:
                wire._fail('repair_remote_setup_mismatch')
            owner = value['owner']; resource._dual_key(owner,budget)
            entry = decode_entry(value['allocation'],budget.policy,budget)
            held, reference = self.state._entry(entry,budget)
            signed = wire.object_fields(held.value,{'payload','proof'})
            p = wire.object_fields(signed['payload'],resource.COMMON | set(resource._FIELDS[0].split()))
            if p['schema_version'] != SCHEMA or p['kind'] != 'resource.allocate':
                wire._fail('repair_remote_setup_mismatch')
            resource._role_shape('allocate',p)
            original._verify_control_signature(p,signed['proof'],owner['signing_key'],budget)
            intent = p['intent']; now = self.state._now()
            if (intent['owner'] != owner or intent['target'] != self.state.target
                    or intent['target_storage_epoch'] != self.state.node['payload']['storage_epoch']
                    or not p['issued_at'] <= now < p['expires_at']
                    or max(intent['windows'].values()) > now+self.policy['max_lifetime']):
                wire._fail('repair_remote_setup_mismatch')
            caps, limits = intent['budget'], self.state.limits
            ceilings = dict(max_live_bytes=131072,max_meta_bytes=limits['max_proof_bytes'],max_items=128,
                max_requests=limits['max_signature_checks'],max_pending=limits['max_pending'],
                max_replay_records=limits['max_replay_records'],max_jobs=16,max_job_bytes=limits['max_proof_bytes'])
            if any(caps[k]>v for k,v in ceilings.items()):
                wire._fail('repair_remote_setup_capacity')
            return dict(kind='allocate',owner=owner,allocation_id=intent['allocation_id'],request_id=p['request_id'],
                allocation=entry,entries=[entry],retain_until=intent['windows']['retain_until'],payload=p)
        signed = wire.object_fields(value,{'payload','proof'})
        p = wire.object_fields(signed['payload'],SETUP_FIELDS)
        if p['schema_version'] != SCHEMA or p['kind'] != 'ack.source_setup':
            wire._fail('repair_remote_setup_mismatch')
        resource._dual_key(p['subject'],budget); resource._dual_key(p['target'],budget)
        original._opaque(p['request_id'])
        original._verify_control_signature(p,signed['proof'],p['subject']['signing_key'],budget)
        now = self.state._now()
        if now >= wire.u53(p['expires_at']):
            wire._fail('repair_remote_setup_reconciliation_required')
        if (p['signing_key'] != p['subject']['signing_key'] or p['target'] != self.state.target
                or p['target_storage_epoch'] != self.state.node['payload']['storage_epoch']
                or not wire.u53(p['issued_at']) <= now < wire.u53(p['expires_at'])
                or not now < wire.u53(p['read_until']) <= wire.u53(p['retain_until'])
                or p['expires_at'] > p['retain_until'] or p['retain_until'] > now+self.policy['max_lifetime']):
            wire._fail('repair_remote_setup_mismatch')
        allocation_ref,offer_ref = ack._ref(p['allocation_ref']),ack._ref(p['offer_ref'])
        row = self.state._one('SELECT * FROM open_repair_ack_resources WHERE owner=? AND allocation_ref=?',
            (p['subject']['signing_key']['key_id'],canonical_bytes(allocation_ref.as_dict())))
        if row is None or json.loads(bytes(row['owner_keys'])) != p['subject'] or json.loads(bytes(row['offer_ref'])) != offer_ref.as_dict():
            wire._fail('repair_remote_setup_mismatch')
        entries = {name:decode_entry(p[name],budget.policy,budget) for name in ('node','root','read','bootstrap','activation','owner_status')}
        return dict(kind='setup',owner=p['subject'],allocation_id=row['allocation_id'],request_id=p['request_id'],
            resource_id=row['resource_id'],entries=list(entries.values()),setup=entries,
            retain_until=p['retain_until'],payload=p)

    def _begin(self, ctx, raw, budget):
        owner = ctx['owner']['signing_key']['key_id']; digest = budget._hash(raw)
        allowance = budget.policy.max_signature_checks
        transfer = len(raw)+sum(len(v['raw']) for v in ctx['entries'])+2*MAX_BYTES
        attempt = 'remote_'+secrets.token_hex(16)
        with self.state._transaction() as now:
            bound=self.state._one("SELECT value FROM open_repair_state WHERE name='remote_setup_policy'")
            if bound is None or bound['value']!=canonical_bytes({k:v for k,v in self.policy.items() if k!='enabled'}).decode():
                wire._fail('repair_remote_policy_mismatch')
            held = self.state._one('SELECT * FROM open_repair_remote_owners WHERE owner=?',(owner,))
            if held is None:
                if self.db.execute('SELECT count(*) FROM open_repair_remote_owners').fetchone()[0] >= self.policy['max_owners']:
                    wire._fail('repair_remote_setup_capacity')
                self.state.capacity.reserve('ack','setup_'+owner,hashlib.sha256(owner.encode()).hexdigest(),
                    self.policy['max_journal_bytes'],ctx['retain_until'],owner=owner,operation_id='remote_setup')
                self.db.execute('INSERT INTO open_repair_remote_owners VALUES(?,0,0,0,0)',(owner,))
                held=dict(requests=0,signatures=0,bytes=0,metadata=0)
            reservation=self.state._one("SELECT digest,charge_bytes,owner,operation_id FROM open_capacity_reservations WHERE service='ack' AND reservation_id=?",('setup_'+owner,))
            if (reservation is None or reservation['digest']!=hashlib.sha256(owner.encode()).hexdigest()
                    or reservation['charge_bytes']!=self.policy['max_journal_bytes']
                    or reservation['owner']!=owner or reservation['operation_id']!='remote_setup'):
                wire._fail('repair_remote_setup_corrupt')
            prior = self.state._one('SELECT * FROM open_repair_remote_requests WHERE owner=? AND allocation_id=? AND kind=?',
                (owner,ctx['allocation_id'],ctx['kind']))
            duplicate = self.state._one('SELECT digest FROM open_repair_remote_requests WHERE owner=? AND request_id=?',(owner,ctx['request_id']))
            if (prior and (prior['digest']!=digest or bytes(prior['raw'])!=raw)) or (duplicate and duplicate['digest']!=digest):
                wire._fail('repair_remote_setup_conflict')
            charge=512+(len(raw)+MAX_BYTES+1024 if prior is None else 0)
            if (held['requests']>=self.policy['max_requests'] or held['signatures']+allowance>self.policy['max_signatures']
                    or held['bytes']+transfer>self.policy['max_bytes'] or held['metadata']+charge>self.policy['max_journal_bytes']):
                wire._fail('repair_remote_setup_capacity')
            if prior is None and ctx['kind']=='allocate':
                if (self.db.execute('SELECT count(*) FROM open_repair_ack_resources WHERE owner=?',(owner,)).fetchone()[0]>=self.policy['max_owner_resources']
                        or self.db.execute("SELECT count(*) FROM open_repair_ack_resources WHERE status='pending'").fetchone()[0]>=self.policy['max_pending']):
                    wire._fail('repair_remote_setup_capacity')
            if prior is None:
                self.db.execute('INSERT INTO open_repair_remote_requests VALUES(?,?,?,?,?,?,?,NULL,?)',
                    (owner,ctx['allocation_id'],ctx['kind'],ctx['request_id'],digest,raw,ctx.get('resource_id'),'admitted'))
            self.db.execute('UPDATE open_repair_remote_owners SET requests=requests+1,signatures=signatures+?,bytes=bytes+?,metadata=metadata+? WHERE owner=?',
                (allowance,transfer,charge,owner))
            self.db.execute('INSERT INTO open_repair_remote_attempts VALUES(?,?,?,?,NULL,?,NULL,?,NULL,?,?)',
                (attempt,owner,ctx['allocation_id'],ctx['request_id'],allowance,transfer,now,ctx['retain_until']))
        ctx.update(attempt=attempt,reference=_ref(raw),owner_id=owner)
        if ctx.get('resource_id'):
            self._attach(ctx)

    def _attach(self,ctx):
        """Move every admitted attempt, including interrupted ones, into R's shared meter."""
        rid=ctx['resource_id']
        with self.state._transaction():
            source=self.state._row(rid)
            offered=json.loads(self.state._saved(source,'offer')['raw'])['payload']
            caps=offered['budget']; limits=self.state.limits
            if source['activation_inputs']:
                setup=json.loads(bytes(source['activation_inputs']))
                limits=json.loads(setup['bootstrap']['raw'])['payload']['limits']
            rows=self.db.execute('SELECT * FROM open_repair_remote_attempts WHERE owner=? AND allocation_id=? AND resource_id IS NULL',
                (ctx['owner_id'],ctx['allocation_id'])).fetchall()
            if not rows:return
            usage=self.state._one('SELECT * FROM open_repair_bootstrap_usage WHERE resource_id=?',(rid,))
            held=usage or dict(requests=0,signatures=0,proof_bytes=0,replays=0)
            pending=self.db.execute('SELECT coalesce(sum(signature_allowance),0) FROM open_repair_bootstrap_work WHERE resource_id=? AND signature_checks IS NULL',(rid,)).fetchone()[0]
            count=len(rows); signatures=sum(r[5] if r[6] is None else r[6] for r in rows)
            byte_charge=sum(r[7] if r[8] is None else r[8] for r in rows)
            metadata=ROW_CHARGE*(count+(usage is None))
            if (held['requests']+count>min(limits['max_requests'],caps['max_requests'])
                    or held['replays']+count>min(limits['max_replay_records'],caps['max_replay_records'])
                    or held['signatures']+pending+signatures>limits['max_signature_checks']
                    or held['proof_bytes']+byte_charge>limits['max_proof_bytes']
                    or source['metadata_bytes']+metadata>caps['max_meta_bytes']):
                wire._fail('repair_remote_setup_capacity')
            self.db.execute('INSERT OR IGNORE INTO open_repair_bootstrap_usage VALUES(?,0,0,0,0)',(rid,))
            for row in rows:
                request=self.state._one('SELECT digest FROM open_repair_remote_requests WHERE owner=? AND request_id=?',
                    (row[1],row[3]))
                if request is None:wire._fail('repair_remote_setup_corrupt')
                self.db.execute('INSERT INTO open_repair_bootstrap_work VALUES(?,?,?,?,?,?,?)',
                    (row[0],rid,request['digest'],row[5],row[6],row[9],row[10]))
                self.db.execute('UPDATE open_repair_remote_attempts SET resource_id=? WHERE attempt_id=?',(rid,row[0]))
            self.db.execute('UPDATE open_repair_bootstrap_usage SET requests=requests+?,signatures=signatures+?,proof_bytes=proof_bytes+?,replays=replays+? WHERE resource_id=?',
                (count,sum(r[6] or 0 for r in rows),byte_charge,count,rid))
            self.db.execute('UPDATE open_repair_ack_resources SET metadata_bytes=metadata_bytes+? WHERE resource_id=?',(metadata,rid))
            self.db.execute('UPDATE open_repair_remote_requests SET resource_id=? WHERE owner=? AND allocation_id=?',(rid,ctx['owner_id'],ctx['allocation_id']))

    def _settle(self,ctx,budget,response):
        if 'attempt' not in ctx:return
        actual=budget.snapshot()['signature_checks']
        with self.state._transaction():
            row=self.state._one('SELECT * FROM open_repair_remote_attempts WHERE attempt_id=?',(ctx['attempt'],))
            if row is None or row['signature_checks'] is not None or not 1<=actual<=row['signature_allowance']:
                wire._fail('repair_remote_setup_corrupt')
            transferred=row['byte_allowance'] if response is None else ctx['input_bytes']+len(response)+ctx.get('output_bytes',0)
            if transferred>row['byte_allowance']:wire._fail('repair_remote_setup_capacity')
            self.db.execute('UPDATE open_repair_remote_attempts SET signature_checks=?,byte_actual=? WHERE attempt_id=?',(actual,transferred,ctx['attempt']))
            self.db.execute('UPDATE open_repair_remote_owners SET signatures=signatures-?+?,bytes=bytes-?+? WHERE owner=?',
                (row['signature_allowance'],actual,row['byte_allowance'],transferred,ctx['owner_id']))
            if row['resource_id']:
                self.db.execute('UPDATE open_repair_bootstrap_work SET signature_checks=? WHERE attempt_id=?',(actual,ctx['attempt']))
                self.db.execute('UPDATE open_repair_bootstrap_usage SET signatures=signatures+?,proof_bytes=proof_bytes-?+? WHERE resource_id=?',
                    (actual,row['byte_allowance'],transferred,row['resource_id']))

    def _phase(self,ctx,phase,response=None):
        with self.state._transaction():
            self.db.execute('UPDATE open_repair_remote_requests SET phase=?,response=coalesce(?,response) WHERE owner=? AND allocation_id=? AND kind=?',
                (phase,response,ctx['owner_id'],ctx['allocation_id'],ctx['kind']))

    def _live(self,ctx):
        p=ctx['payload']; now=self.state._now()
        if not p['issued_at']<=now<p['expires_at']:
            return 'repair_remote_setup_reconciliation_required'
        return None

    def _grant_room(self,ctx,grant):
        with self.state._transaction():
            usage,pending=RepairBootstrapService(self.state)._usage(ctx['resource_id'])
            limits=grant['limits']
            if (usage is None or usage['requests']>limits['max_requests']
                    or usage['signatures']+pending>limits['max_signature_checks']
                    or usage['proof_bytes']>limits['max_proof_bytes']
                    or usage['replays']>limits['max_replay_records']):
                wire._fail('repair_remote_setup_capacity')

    def _observe(self,ctx,boot,budget):
        """Authenticate A's whole observation before persisting pre-unbound floors."""
        p=ctx['payload']; slot=p['ack_slot']; root=slot['root_key']; owner=ctx['owner']
        duties=[]
        for name,kind,mask in (('root','ack.root_authority',74),('read','ack.read_grant',2),('bootstrap','bootstrap.grant',10)):
            item=boot.originals[name]
            duties.append(dict(scope_kind='authority',scope_id=status.status_scope(root,'authority',
                dict(authority_kind=kind,authority_sha256=item.ref.raw_sha256),budget.policy,budget),revision=item.payload['revision'],mask=mask))
        duties.append(dict(scope_kind='ack_slot',scope_id=status.status_scope(root,'ack_slot',slot,budget.policy,budget),revision=boot.originals['root'].payload['revision'],mask=66))
        observation=status.authenticate_status_original(ctx['setup']['owner_status'],expected_root=root,
            expected_signing_key=owner['signing_key'],at=self.state._now(),
            allowed_scopes=[{k:item[k] for k in ('scope_kind','scope_id')} for item in duties],policy=budget.policy,budget=budget)
        root_digest=budget._hash(wire._canonical(root,budget)); code=None; rid=ctx['resource_id']
        with self.state._transaction():
            source=self.state._row(rid); caps=json.loads(self.state._saved(source,'offer')['raw'])['payload']['budget']
            state=self.state._one('SELECT * FROM open_repair_access_state WHERE resource_id=?',(rid,))
            marker='access:'+rid; binding=self.state._expected_binding()+'|'+root_digest
            observed_marker=self.state._one('SELECT value FROM open_repair_state WHERE name=?',(marker,))
            if state is None:
                if observed_marker is not None:wire._fail('repair_access_ledger_missing')
                blocked='repair_access_capacity' if source['metadata_bytes']+STATE_CHARGE>caps['max_meta_bytes'] else None
                self.db.execute('INSERT INTO open_repair_access_state VALUES(?,1,?,0,0)',(rid,blocked))
                self.db.execute('INSERT INTO open_repair_state VALUES(?,?)',(marker,binding))
                state=dict(generation=1,documents=0,floors=0,blocked=blocked)
                if blocked is None:
                    self.db.execute('UPDATE open_repair_ack_resources SET metadata_bytes=metadata_bytes+? WHERE resource_id=?',(STATE_CHARGE,rid))
                    source['metadata_bytes']+=STATE_CHARGE
            elif observed_marker is None or observed_marker['value']!=binding:
                wire._fail('repair_access_ledger_missing')
            counts=tuple(self.db.execute('SELECT (SELECT count(*) FROM open_repair_access_documents WHERE resource_id=?),(SELECT count(*) FROM open_repair_access_floors WHERE resource_id=?)',(rid,rid)).fetchone())
            if counts!=(state['documents'],state['floors']):wire._fail('repair_access_ledger_missing')
            value=observation.payload; issuer=value['scope_key']['issuer_key_id']; revision=value['revision']; digest=observation.canonical_sha256
            prior=self.state._one('SELECT raw,ref FROM open_repair_access_documents WHERE resource_id=? AND issuer=? AND revision=? AND digest=?',(rid,issuer,revision,digest))
            conflict=self.db.execute('SELECT 1 FROM open_repair_access_documents WHERE issuer=? AND root_digest=? AND revision=? AND digest<>? LIMIT 1',(issuer,root_digest,revision,digest)).fetchone() is not None
            floors={(row['scope_kind'],row['scope_id']):row for row in (dict(zip(('resource_id','issuer','root_digest','scope_kind','scope_id','revision','digest','minimum_revision','revoked_mask','conflict'),r)) for r in self.db.execute('SELECT * FROM open_repair_access_floors WHERE resource_id=? AND issuer=?',(rid,issuer)))}
            missing=sum((e['scope_kind'],e['scope_id']) not in floors for e in value['entries'])
            charge=(len(observation.raw)+DOCUMENT_CHARGE if prior is None else 0)+missing*FLOOR_CHARGE
            if (state['blocked'] or source['metadata_bytes']+charge>caps['max_meta_bytes'] or state['documents']+(prior is None)>boot.originals['bootstrap'].payload['limits']['max_replay_records']):
                code=state['blocked'] or 'repair_access_capacity'
                self.db.execute('UPDATE open_repair_access_state SET blocked=? WHERE resource_id=?',(code,rid))
                self.db.execute('INSERT OR IGNORE INTO open_repair_state VALUES(?,?)',('access_root_blocked:'+root_digest,code))
            else:
                if prior is None:
                    self.db.execute('INSERT INTO open_repair_access_documents VALUES(?,?,?,?,?,?,?,?)',
                        (rid,issuer,root_digest,revision,digest,observation.raw,canonical_bytes(observation.ref.as_dict()),value['valid_until']))
                elif bytes(prior['raw'])!=observation.raw or bytes(prior['ref'])!=canonical_bytes(observation.ref.as_dict()):
                    wire._fail('repair_storage_corrupt')
                for e in value['entries']:
                    key=e['scope_kind'],e['scope_id']; old=floors.get(key)
                    if old and (revision<old['revision'] or e['minimum_document_revision']<old['minimum_revision']):code=code or 'repair_status_rollback'
                    values=(rid,issuer,root_digest,*key,max(revision,old['revision'] if old else 0),old['digest'] if old and revision<old['revision'] else digest,
                        max(e['minimum_document_revision'],old['minimum_revision'] if old else 0),
                        (old['revoked_mask'] if old else 0)|(e['operation_mask'] if e['status']=='revoked' else 0),int(conflict or bool(old and old['conflict'])))
                    self.db.execute('INSERT INTO open_repair_access_floors VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(resource_id,issuer,scope_kind,scope_id) DO UPDATE SET revision=excluded.revision,digest=excluded.digest,minimum_revision=excluded.minimum_revision,revoked_mask=excluded.revoked_mask,conflict=excluded.conflict',values)
                self.db.execute('UPDATE open_repair_access_state SET generation=generation+1,documents=documents+?,floors=floors+? WHERE resource_id=?',(int(prior is None),missing,rid))
                self.db.execute('UPDATE open_repair_ack_resources SET metadata_bytes=metadata_bytes+? WHERE resource_id=?',(charge,rid))
                current={(e['scope_kind'],e['scope_id']):e for e in value['entries']}
                for duty in duties:
                    key=issuer,duty['scope_kind'],duty['scope_id']
                    global_floor=self.access._global_floor(dict(root_digest=root_digest),key)
                    e=current.get(key[1:])
                    if global_floor['conflict']:code='repair_status_conflict'
                    elif global_floor['revoked_mask']&duty['mask']:code='repair_authority_revoked'
                    elif global_floor['minimum_revision']>duty['revision']:code=code or 'repair_status_revision'
                    elif revision<global_floor['revision']:code=code or 'repair_status_rollback'
                    if e is None:code=code or 'repair_status_missing'
                    elif e['operation_mask']&duty['mask']!=duty['mask']:code=code or 'repair_status_operation'
        if code:wire._fail(code)

    def _setup(self,ctx,budget):
        p=ctx['payload']; entries=ctx['setup']; rid=ctx['resource_id']; source=self.state._row(rid)
        if source['status'] not in ('pending','active','unbound'):
            wire._fail('repair_resource_inactive')
        offer=self.state._saved(source,'offer'); offered=json.loads(offer['raw'])['payload']
        boot=bootstrap.verify_ack_owner_bootstrap_original(entries['bootstrap'],{k:entries[k] for k in ('root','read')},
            expected_ack_slot=p['ack_slot'],expected_owner=ctx['owner'],at=self.state._now(),limit_policy=self.state.limits,policy=budget.policy,budget=budget)
        root=boot.originals['root'].payload
        if (p['ack_slot']['root_key']!=offered['intent']['root_key'] or root['original_resource_ref']!=offered['resource']
                or root['original_resource_offer_ref']!=offer['ref']):wire._fail('repair_remote_setup_mismatch')
        self._observe(ctx,boot,budget)
        self._grant_room(ctx,boot.originals['bootstrap'].payload)
        node,ref=self.state._entry(entries['node'],budget)
        descriptor=original.verify_original_control(node.raw,expected_signing_key=self.state.target['signing_key'],
            expected_schema='memory-vault-open-control/v1',expected_kind='node',at=self.state._now(),policy=budget.policy,budget=budget)
        original._node_shape(descriptor,self.state._now(),budget)
        if descriptor.payload['storage_epoch']!=p['target_storage_epoch']:
            wire._fail('repair_remote_setup_mismatch')
        # Each stage is really durable; retry the same originals after a crash.
        active=self.state.activate(rid,{k:entries[k] for k in ('root','read','bootstrap','activation')},
            expected_ack_slot=p['ack_slot'],_budget=budget,_transaction_guard=lambda:self._live(ctx))
        self._phase(ctx,'active')
        roles={role:entries['owner_status'] for role in ack.ROLES if role.startswith('historical.status.')}
        roles.update({'ack.root_authority':entries['root'],'ack.read_grant':entries['read'],'bootstrap.ack_owner':entries['bootstrap'],
            'resource.ack_allocate':self.state._saved(source,'allocation'),'resource.ack_offer':offer,
            'resource.ack_activation':entries['activation'],'resource.ack_active':active['active'],
            'source.descriptor':entries['node'],'historical.status.ack_resource':active['status']})
        pack=wire.build_raw_pack(list(dict.fromkeys(item['raw'] for item in roles.values())),budget.policy,budget)
        positions={item.raw_sha256:i for i,item in enumerate(pack.entries)}
        h=dict(schema_version=history.SCHEMA,kind='historical.manifest',variant='ack_unbound',root_key=p['ack_slot']['root_key'],
            ack_slot=p['ack_slot'],root_authority_ref=entries['root']['ref'],roles=[dict(role=role,document_ref=item['ref'],
                pack_ref=pack.ref.as_dict(),entry_index=positions[item['ref']['raw_sha256']]) for role,item in sorted(roles.items())])
        manifest=wire.build_new_wire(h,budget.policy,budget).raw
        custody=self.state.finalize_unbound(rid,dict(raw=manifest,ref=_ref(manifest)),[dict(raw=pack.raw,ref=pack.ref.as_dict())],
            expected_ack_slot=p['ack_slot'],read_until=p['read_until'],retain_until=p['retain_until'],
            _budget=budget,_transaction_guard=lambda:self._live(ctx))
        prepared=self.access.prepare(rid,action='challenge',current_statuses=[entries['owner_status'],active['status']],policy=budget.policy,budget=budget)
        with self.state._transaction():decision=self.access.check_locked(prepared)
        if not decision.allowed:wire._fail(decision.code)
        ctx['output_bytes']=sum(len(v['raw']) for v in (active['active'],active['status'],custody))
        response=wire.build_new_wire(dict(schema_version=SCHEMA,kind='ack.source_ready',request_ref=ctx['reference'],
            active=encode_entry(active['active'],budget.policy,budget),status=encode_entry(active['status'],budget.policy,budget),
            custody=encode_entry(custody,budget.policy,budget)),budget.policy,budget).raw
        if len(response)>MAX_BYTES:wire._fail('repair_remote_setup_too_large')
        # Serialize the final authority/capacity recheck with publishing a reply.
        with self.state._transaction():
            decision=self.access.check_locked(prepared)
            expired=self._live(ctx)
            if decision.allowed and expired is None:
                self.db.execute("UPDATE open_repair_remote_requests SET phase='unbound',response=? WHERE owner=? AND allocation_id=? AND kind='setup'",(response,ctx['owner_id'],ctx['allocation_id']))
        if not decision.allowed:wire._fail(decision.code)
        if expired:wire._fail(expired)
        return response

    def handle(self,raw):
        budget=wire.RepairBudget(self.state.policy)
        ctx=self._admit(raw,budget)
        ctx['input_bytes']=len(raw)+sum(len(v['raw']) for v in ctx['entries'])
        response=None
        try:
            self._begin(ctx,raw,budget)
            if ctx['kind']=='allocate':
                offer=self.state.allocate(ctx['allocation'],expected_owner=ctx['owner'],_budget=budget,
                    _transaction_guard=lambda:self._live(ctx))
                ctx['resource_id']=json.loads(offer['raw'])['payload']['resource']['resource_id']
                self._attach(ctx)
                ctx['output_bytes']=len(offer['raw'])
                response=wire.build_new_wire(dict(schema_version=SCHEMA,kind='ack.source_allocation',request_ref=ctx['reference'],
                    offer=encode_entry(offer,budget.policy,budget)),budget.policy,budget).raw
                if len(response)>MAX_BYTES:wire._fail('repair_remote_setup_too_large')
                self._phase(ctx,'pending',response)
            else:
                response=self._setup(ctx,budget)
            return response
        finally:
            self._settle(ctx,budget,response)


class MailboxRemoteSetupService:
    """Finite opt-in remote mailbox allocation with resumable exact originals."""
    def __init__(self, state, *, policy=None):
        from memory_vault_open_repair_mailbox_resources import RepairMailboxResources
        self.state,self.db=state,state.db
        self.policy=remote_policy(policy)
        self.resources=RepairMailboxResources(state)

    def initialize(self):
        self.resources.initialize()
        with self.state._transaction():
            if self.policy['enabled']:
                encoded=canonical_bytes({k:v for k,v in self.policy.items() if k!='enabled'}).decode()
                old=self.state._one("SELECT value FROM open_repair_state WHERE name='mailbox_remote_setup_policy'")
                if old is not None and old['value']!=encoded:
                    wire._fail('repair_remote_policy_mismatch')
                self.db.execute("INSERT OR IGNORE INTO open_repair_state VALUES('mailbox_remote_setup_policy',?)",(encoded,))
            self.db.execute('''CREATE TABLE IF NOT EXISTS open_repair_mailbox_remote_owners(
                owner TEXT PRIMARY KEY,requests INTEGER NOT NULL,signatures INTEGER NOT NULL,
                bytes INTEGER NOT NULL,metadata INTEGER NOT NULL)''')
            self.db.execute('''CREATE TABLE IF NOT EXISTS open_repair_mailbox_remote_allocations(
                owner TEXT NOT NULL,root_digest TEXT NOT NULL,request_digest TEXT NOT NULL,
                request BLOB NOT NULL,response BLOB,retain_until INTEGER NOT NULL,
                PRIMARY KEY(owner,root_digest))''')

            self.db.execute('''CREATE TABLE IF NOT EXISTS open_repair_mailbox_remote_stages(
                owner TEXT NOT NULL,root_digest TEXT NOT NULL,kind TEXT NOT NULL,
                request_digest TEXT NOT NULL,request BLOB NOT NULL,response BLOB,
                PRIMARY KEY(owner,root_digest,kind))''')

    def handle(self, raw):
        from dataclasses import replace
        if not self.policy['enabled']:
            wire._fail('repair_remote_setup_closed')
        if type(raw) is not bytes or not 0<len(raw)<=MAX_BYTES:
            wire._fail('repair_remote_setup_too_large')
        s=self.state
        budget=wire.RepairBudget(replace(s.policy,max_signature_checks=min(s.policy.max_signature_checks,self.policy['max_signatures'])))
        request=wire.parse_new_wire(raw,budget.policy,budget)
        p=wire.object_fields(request.value,{'schema_version','kind','owner','allocations'})
        if p['schema_version']!=SCHEMA or p['kind']!='mailbox.source_allocate':
            wire._fail('repair_remote_setup_mismatch')
        owner=p['owner'];owner_id=resource._dual_key(owner,budget)['signing_key_id']
        if type(p['allocations']) is not wire._DraftList or len(p['allocations'])!=3:
            wire._fail('repair_invalid_resource')
        entries=[decode_entry(value,budget.policy,budget) for value in p['allocations']]
        # Author identity and intent are established before charging that owner.
        # The shared capacity transaction still authorizes every actual reserve.
        # Local mailbox operations currently use the node's exact wire policy.
        if budget.policy!=s.policy:
            wire._fail('repair_remote_setup_capacity')
        checked=[self.resources._validate(entry,owner,budget) for entry in entries]
        intents=[item[2]['intent'] for item in checked]
        if ({v['purpose'] for v in intents}!={'anchor_catalog','feed_metadata','mailbox_data'}
                or len({v['allocation_id'] for v in intents})!=3 or any(v['root_key']!=intents[0]['root_key'] for v in intents)):
            wire._fail('repair_remote_setup_mismatch')
        root_digest=budget._hash(wire._canonical(intents[0]['root_key'],budget));digest=budget._hash(request.raw)
        until=max(v['windows']['retain_until'] for v in intents)
        limit=s.limits
        for intent in intents:
            ceilings=dict(max_live_bytes=6*1024*1024,max_meta_bytes=4*limit['max_proof_bytes'],max_items=128,
                max_requests=limit['max_signature_checks'],max_pending=limit['max_pending'],max_replay_records=limit['max_replay_records'],
                max_jobs=16,max_job_bytes=limit['max_proof_bytes'])
            if any(intent['budget'][k]>v for k,v in ceilings.items()):
                wire._fail('repair_remote_setup_capacity')
        allowance=budget.policy.max_signature_checks
        byte_allowance=len(raw)+MAX_BYTES
        with s._transaction() as now:
            marker=s._one("SELECT value FROM open_repair_state WHERE name='mailbox_remote_setup_policy'")
            if marker is None or marker['value']!=canonical_bytes({k:v for k,v in self.policy.items() if k!='enabled'}).decode():
                wire._fail('repair_remote_policy_mismatch')
            old=s._one("SELECT * FROM open_repair_mailbox_remote_allocations WHERE owner=? AND root_digest=?",(owner_id,root_digest))
            if old is not None and old['request_digest']!=digest:
                wire._fail('repair_remote_setup_conflict')
            usage=s._one("SELECT * FROM open_repair_mailbox_remote_owners WHERE owner=?",(owner_id,))
            if usage is None:
                if old is not None:
                    wire._fail('repair_remote_setup_ledger_missing')
                if self.db.execute("SELECT count(*) FROM open_repair_mailbox_remote_owners").fetchone()[0]>=self.policy['max_owners']:
                    wire._fail('repair_remote_setup_capacity')
                s.capacity.reserve('mailbox','setup_'+owner_id,budget._hash(owner_id.encode()),self.policy['max_journal_bytes'],
                    until,owner=owner_id,operation_id='mailbox_remote_setup')
                self.db.execute("INSERT INTO open_repair_mailbox_remote_owners VALUES(?,0,0,0,0)",(owner_id,))
                usage=dict(requests=0,signatures=0,bytes=0,metadata=0)
            metadata=0 if old is not None else len(raw)+MAX_BYTES+2*ROW_CHARGE
            roots=self.db.execute("SELECT count(*) FROM open_repair_mailbox_remote_allocations WHERE owner=?",(owner_id,)).fetchone()[0]
            if (usage['requests']>=self.policy['max_requests'] or usage['signatures']+allowance>self.policy['max_signatures']
                    or usage['bytes']+byte_allowance>self.policy['max_bytes'] or usage['metadata']+metadata>self.policy['max_journal_bytes']
                    or (old is None and (roots+1)*3>self.policy['max_owner_resources'])):
                wire._fail('repair_remote_setup_capacity')
            if old is None:
                pending=self.db.execute("SELECT count(*) FROM open_repair_mailbox_remote_allocations WHERE owner=? AND response IS NULL",(owner_id,)).fetchone()[0]
                if pending>=self.policy['max_pending']:
                    wire._fail('repair_remote_setup_capacity')
                if any(not item[2]['issued_at']<=now<item[2]['expires_at'] for item in checked) or min(min(v['windows'].values()) for v in intents)<=now:
                    wire._fail('repair_resource_expired')
                if max(max(v['windows'].values()) for v in intents)>now+self.policy['max_lifetime']:
                    wire._fail('repair_remote_setup_mismatch')
                self.db.execute("INSERT INTO open_repair_mailbox_remote_allocations VALUES(?,?,?,?,NULL,?)",(owner_id,root_digest,digest,raw,until))
            self.db.execute("UPDATE open_repair_mailbox_remote_owners SET requests=requests+1,signatures=signatures+?,bytes=bytes+?,metadata=metadata+? WHERE owner=?",
                (allowance,byte_allowance,metadata,owner_id))
        response=None
        try:
            if old is not None and old['response'] is not None:
                response=bytes(old['response'])
                return response
            offers=self.resources.allocate_initial(entries,expected_owner=owner,_budget=budget)
            response=wire.build_new_wire(dict(schema_version=SCHEMA,kind='mailbox.source_offers',root_key=intents[0]['root_key'],
                offers={name:encode_entry(value,budget.policy,budget) for name,value in offers.items()}),budget.policy,budget).raw
            if len(response)>MAX_BYTES:
                wire._fail('repair_remote_setup_too_large')
            with s._transaction():
                self.db.execute("UPDATE open_repair_mailbox_remote_allocations SET response=? WHERE owner=? AND root_digest=? AND request_digest=?",
                    (response,owner_id,root_digest,digest))
            return response
        finally:
            with s._transaction():
                self.db.execute("UPDATE open_repair_mailbox_remote_owners SET signatures=signatures-?,bytes=bytes-? WHERE owner=?",
                    (allowance-budget.snapshot()['signature_checks'],MAX_BYTES-(len(response) if response is not None else 0),owner_id))

    def activate(self, raw):
        """Resume one recipient-signed slot/root stage using reserved resources."""
        from memory_vault_open_repair_mailbox_root import MailboxRootActivation
        if not self.policy['enabled']:
            wire._fail('repair_remote_setup_closed')
        if type(raw) is not bytes or not 0<len(raw)<=MAX_BYTES:
            wire._fail('repair_remote_setup_too_large')
        s=self.state;budget=wire.RepairBudget(s.policy)
        parsed=wire.parse_new_wire(raw,s.policy,budget)
        signed=resource._fields(parsed.value,{'payload','proof'})
        p=resource._fields(signed['payload'],resource.COMMON|{'issued_at','expires_at','owner','root_key','slot_key','entries'})
        if p['schema_version']!=SCHEMA or p['kind'] not in ('mailbox.source_slot','mailbox.source_root'):
            wire._fail('repair_remote_setup_mismatch')
        owner=resource._dual_key(p['owner'],budget)
        history._slot(p['slot_key'],p['root_key']);resource._lifetime(p)
        if p['root_key']['owner']!=owner or p['signing_key']!=p['owner']['signing_key']:
            wire._fail('repair_remote_setup_mismatch')
        original._verify_control_signature(p,signed['proof'],p['owner']['signing_key'],budget)
        root_digest=budget._hash(wire._canonical(p['root_key'],budget));digest=budget._hash(raw)
        owner_id=owner['signing_key_id'];kind=p['kind'];allowance=s.policy.max_signature_checks
        entries={name:decode_entry(value,s.policy,budget) for name,value in resource._fields(p['entries'],
            {'maintenance','read','slot','bootstrap','activation'} if kind=='mailbox.source_slot' else
            {'root','read','catalog','bootstrap','activation'}).items()}
        root=MailboxRootActivation(self.resources);root.initialize()
        with s._transaction() as now:
            allocation=s._one('SELECT * FROM open_repair_mailbox_remote_allocations WHERE owner=? AND root_digest=?',(owner_id,root_digest))
            if allocation is None or allocation['response'] is None:
                wire._fail('repair_unknown_resource')
            old=s._one('SELECT * FROM open_repair_mailbox_remote_stages WHERE owner=? AND root_digest=? AND kind=?',(owner_id,root_digest,kind))
            if old is not None and old['request_digest']!=digest:
                wire._fail('repair_remote_setup_conflict')
            usage=s._one('SELECT * FROM open_repair_mailbox_remote_owners WHERE owner=?',(owner_id,))
            if usage is None:
                wire._fail('repair_remote_setup_ledger_missing')
            charge=0 if old is not None else len(raw)+MAX_BYTES+2*ROW_CHARGE
            if (usage['requests']>=self.policy['max_requests'] or usage['signatures']+allowance>self.policy['max_signatures']
                    or usage['bytes']+len(raw)+MAX_BYTES>self.policy['max_bytes']
                    or usage['metadata']+charge>self.policy['max_journal_bytes']):
                wire._fail('repair_remote_setup_capacity')
            if old is None:
                if not p['issued_at']<=now<p['expires_at'] or p['expires_at']>allocation['retain_until']:
                    wire._fail('repair_resource_expired')
                self.db.execute('INSERT INTO open_repair_mailbox_remote_stages VALUES(?,?,?,?,?,NULL)',(owner_id,root_digest,kind,digest,raw))
            self.db.execute('UPDATE open_repair_mailbox_remote_owners SET requests=requests+1,signatures=signatures+?,bytes=bytes+?,metadata=metadata+? WHERE owner=?',
                (allowance,len(raw)+MAX_BYTES,charge,owner_id))
        response=None
        try:
            if old is not None and old['response'] is not None:
                response=bytes(old['response']);return response
            def guard():
                if not p['issued_at']<=s._now()<p['expires_at']:
                    return 'repair_resource_expired'
            if kind=='mailbox.source_slot':
                result=root.slots.activate(entries,expected_slot=p['slot_key'],_budget=budget,_transaction_guard=guard)
            else:
                result={'active':root.activate(entries,expected_root=p['root_key'],slot_keys=[p['slot_key']],_budget=budget,_transaction_guard=guard)}
            response=wire.build_new_wire(dict(schema_version=SCHEMA,kind=kind+'_active',request_sha256=digest,
                originals={name:encode_entry(value,s.policy,budget) for name,value in result.items()}),s.policy,budget).raw
            if len(response)>MAX_BYTES:
                wire._fail('repair_remote_setup_too_large')
            with s._transaction():
                self.db.execute('UPDATE open_repair_mailbox_remote_stages SET response=? WHERE owner=? AND root_digest=? AND kind=? AND request_digest=?',
                    (response,owner_id,root_digest,kind,digest))
            return response
        finally:
            with s._transaction():
                self.db.execute('UPDATE open_repair_mailbox_remote_owners SET signatures=signatures-?,bytes=bytes-? WHERE owner=?',
                    (allowance-budget.snapshot()['signature_checks'],MAX_BYTES-(len(response) if response is not None else 0),owner_id))
