"""Local and operator-enabled remote reservations for delegated ACK copies.

An offer reserves real shared capacity; it grants no copy, read or custody
permission. Remote admission verifies the caller signature under a finite operator policy.
The maintainer must verify advance reservation disclosure and destination dual
possession before sending an intent; caller dual possession precedes upload. Original copy authority and complete source evidence remain prerequisites
of a separate application commit. No replica service or GC is enabled here.
"""
from memory_vault import canonical_bytes
import memory_vault_open_repair_history as history
import memory_vault_open_repair_original as original
import memory_vault_open_repair_resource as resource
import memory_vault_open_repair_wire as wire
from memory_vault_open_repair_state import ROW_CHARGE, REPLAY_CHARGE

INTENT_FIELDS=frozenset('kind allocation_id job_id root_key caller target target_storage_epoch purpose scope historical_manifest_ref budget windows'.split())


def ack_copy_scope(value, root):
    if type(value) not in (dict,wire._DraftDict):wire._fail('repair_copy_scope')
    kinds={'ack_unbound':{'root_authority_ref'},'ack_empty':{'grant_ref','binding_ref'},
           'ack_occupied':{'grant_ref','binding_ref','receipt_ref','original_ack_commit_ref'}}
    kind=value.get('kind')
    if type(kind) is not str:wire._fail('repair_copy_scope')
    names=kinds.get(kind)
    if names is None:wire._fail('repair_copy_scope')
    resource._fields(value,{'kind','ack_slot'}|names)
    history._slot(value['ack_slot'],root,ack=True)
    for name in names:
        ref=wire.raw_ref(value[name])
        if name!='receipt_ref' and ref.namespace!='meta':wire._fail('repair_copy_scope')
        if name=='receipt_ref' and ref.namespace not in ('meta','object'):wire._fail('repair_copy_scope')


class RepairCopyResources:
    def __init__(self, source):
        self.source,self.db=source,source.db

    def initialize(self):
        self.source.initialize()
        with self.source._transaction():
            self.db.execute('''CREATE TABLE IF NOT EXISTS open_repair_copy_resources(
                resource_id TEXT PRIMARY KEY,caller TEXT NOT NULL,allocation_id TEXT NOT NULL,
                request BLOB NOT NULL,request_ref BLOB NOT NULL,request_digest TEXT NOT NULL,
                offer BLOB NOT NULL,offer_ref BLOB NOT NULL,charge_bytes INTEGER NOT NULL,
                reservation_until INTEGER NOT NULL,retain_until INTEGER NOT NULL,
                status TEXT NOT NULL CHECK(status='reserved'),UNIQUE(caller,allocation_id))''')

    def _validate_scope(self, intent):
        if intent['purpose'] != 'ack_replica':wire._fail('repair_copy_allocation_mismatch')
        ack_copy_scope(intent['scope'], intent['root_key'])

    def _validate_live_capacity(self, intent, caps):
        if intent['scope']['kind']=='ack_occupied' and caps['max_live_bytes']<wire.raw_ref(intent['scope']['receipt_ref']).size:
            wire._fail('repair_copy_capacity')

    def allocate(self, entry, *, expected_caller, _budget=None, _guard=None, _admitted=None):
        s=self.source;budget=_budget if _budget is not None else wire.RepairBudget(s.policy)
        wire._context(s.policy,budget)
        caller=wire.build_new_wire(expected_caller,s.policy,budget).value
        caller_id=resource._dual_key(caller,budget)['signing_key_id']
        parsed,ref=s._entry(entry,budget)
        if len(parsed.raw)>65536:wire._fail('repair_copy_capacity')
        signed=resource._fields(parsed.value,{'payload','proof'})
        p=resource._fields(signed['payload'],resource.COMMON|set(resource._FIELDS[0].split()))
        resource._lifetime(p)
        intent=resource._fields(p['intent'],INTENT_FIELDS)
        history._root(intent['root_key']);self._validate_scope(intent)
        for name in ('allocation_id','job_id'):resource._opaque(intent[name])
        resource._opaque(p['request_id'])
        manifest=wire.raw_ref(intent['historical_manifest_ref'])
        caps=intent['budget'];resource._budget(caps)
        resource._windows(intent['windows'],issued=p['issued_at'])
        if (p['schema_version']!=resource.SCHEMA or p['kind']!='resource.allocate'
                or p['signing_key']!=caller['signing_key'] or intent['caller']!=caller
                or intent['kind']!='resource.copy_intent'
                or intent['target']!=s.target or p['target_node_key_id']!=s.identity.key_id
                or p['target_storage_epoch']!=s.node['payload']['storage_epoch']
                or intent['target_storage_epoch']!=p['target_storage_epoch']
                or manifest.namespace!='meta'
                or p['intent_sha256']!=budget._hash(wire._canonical(intent,budget))):
            wire._fail('repair_copy_allocation_mismatch')
        original._verify_control_signature(p,signed['proof'],caller['signing_key'],budget)
        if (min(caps[name] for name in ('max_meta_bytes','max_items','max_requests','max_pending',
                'max_replay_records','max_jobs','max_job_bytes'))<=0):
            wire._fail('repair_copy_capacity')
        self._validate_live_capacity(intent, caps)
        charge=caps['max_live_bytes']+caps['max_meta_bytes']+caps['max_job_bytes']+caps['max_replay_records']*REPLAY_CHARGE+ROW_CHARGE
        wire.u53(charge,1)
        digest=budget._hash(wire._canonical(ref.as_dict(),budget))
        with s._transaction(guard=_guard) as now:
            old=s._one('SELECT * FROM open_repair_copy_resources WHERE caller=? AND allocation_id=?',(caller_id,intent['allocation_id']))
            if old is not None:
                if old['request_digest']!=digest or bytes(old['request'])!=parsed.raw:
                    wire._fail('repair_copy_allocation_conflict')
                reserved=s._one("SELECT * FROM open_capacity_reservations WHERE service='repair_copy' AND reservation_id=?",(old['resource_id'],))
                if (reserved is None or reserved['digest']!=digest or reserved['charge_bytes']!=charge
                        or reserved['retain_until']!=old['retain_until'] or reserved['owner']!=caller_id
                        or reserved['operation_id']!=intent['allocation_id']):
                    wire._fail('repair_copy_ledger_missing')
                if _admitted is not None:_admitted(old['resource_id'],caps)
                return s._saved(old,'offer')
            if not p['issued_at']<=now<p['expires_at'] or min(intent['windows'].values())<=now:
                wire._fail('repair_resource_expired')
            token=budget._hash(('copy:'+s._expected_binding()+':'+caller_id+':'+digest).encode())
            rid='copy_'+token
            reservation_until=min(now+60,p['expires_at'])
            res=dict(node_key_id=s.identity.key_id,storage_epoch=p['target_storage_epoch'],lease_id=rid,resource_id=rid)
            s.capacity.reserve('repair_copy',rid,digest,charge,intent['windows']['retain_until'],owner=caller_id,operation_id=intent['allocation_id'])
            offer=s._sign(dict(schema_version=resource.SCHEMA,kind='resource.offer',signing_key=s.identity.public_descriptor(),
                issued_at=now,reservation_until=reservation_until,offer_id='offer_'+token,allocation_request_ref=ref.as_dict(),
                intent=intent,intent_sha256=p['intent_sha256'],resource=res,target_encryption_key=s.encryption_identity.public_descriptor(),
                reservation_generation=1,budget=caps,windows=intent['windows']),'copy_offer',budget)
            if len(parsed.raw)+len(offer['raw'])+3*ROW_CHARGE>caps['max_meta_bytes']:
                wire._fail('repair_copy_capacity')
            self.db.execute('INSERT INTO open_repair_copy_resources VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
                (rid,caller_id,intent['allocation_id'],parsed.raw,canonical_bytes(ref.as_dict()),digest,
                 offer['raw'],canonical_bytes(offer['ref']),charge,reservation_until,intent['windows']['retain_until'],'reserved'))
            if _admitted is not None:_admitted(rid,caps)
            return offer


REMOTE_COPY_POLICY=dict(enabled=False,max_callers=16,max_caller_resources=4,max_requests=64,
    max_signatures=4096,max_bytes=8388608,max_journal_bytes=65536,max_lifetime=86400)


def remote_copy_policy(value=None):
    if value is None:return dict(REMOTE_COPY_POLICY)
    if type(value) is not dict or set(value)-set(REMOTE_COPY_POLICY):wire._fail('repair_invalid_remote_policy')
    result=dict(REMOTE_COPY_POLICY,**value)
    for name,maximum in REMOTE_COPY_POLICY.items():
        if name=='enabled':
            if type(result[name]) is not bool:wire._fail('repair_invalid_remote_policy')
        elif type(result[name]) is not int or not 1<=result[name]<=maximum:wire._fail('repair_invalid_remote_policy')
    return result


class RepairRemoteCopyAllocation:
    """Operator-enabled, finite reservations; caller possession precedes upload.

    Only M's allocation intent is transmitted here. Owner/source originals stay
    local until separate full disclosure checks and target possession succeed.
    """
    def __init__(self,state,*,policy=None):
        self.state,self.db,self.policy=state,state.db,remote_copy_policy(policy)

    def initialize(self):
        from memory_vault_open_repair_copy_state import RepairCopyState
        RepairCopyState(self.state).initialize()
        with self.state._transaction():
            self.db.execute('CREATE TABLE IF NOT EXISTS open_repair_copy_remote_callers(caller TEXT PRIMARY KEY,keys BLOB NOT NULL,retain_until INTEGER NOT NULL)')
            self.db.execute('CREATE TABLE IF NOT EXISTS open_repair_copy_remote_work(id TEXT PRIMARY KEY,caller TEXT NOT NULL,resource_id TEXT,allowance INTEGER NOT NULL,actual INTEGER,wire_bytes INTEGER NOT NULL)')
            if self.policy['enabled']:
                encoded=canonical_bytes({k:v for k,v in self.policy.items() if k!='enabled'}).decode()
                prior=self.state._one("SELECT value FROM open_repair_state WHERE name='remote_copy_policy'")
                if prior is not None and prior['value']!=encoded:wire._fail('repair_remote_policy_mismatch')
                self.db.execute("INSERT OR IGNORE INTO open_repair_state VALUES('remote_copy_policy',?)",(encoded,))

    def _live(self):
        now=self.state._now();p=self.state.node['payload']
        if not self.policy['enabled']:return 'repair_remote_copy_closed'
        if p['status']!='active' or not p['issued_at']<=now<p['expires_at']:return 'repair_resource_expired'
        bound=self.state._one("SELECT value FROM open_repair_state WHERE name='remote_copy_policy'")
        if bound is None or bound['value']!=canonical_bytes({k:v for k,v in self.policy.items() if k!='enabled'}).decode():return 'repair_remote_policy_mismatch'

    def handle(self,raw):
        import secrets
        from memory_vault_open_repair_index_state import decode_entry,encode_entry
        from memory_vault_open_repair_copy_state import RepairCopyState
        if not self.policy['enabled']:wire._fail('repair_remote_copy_closed')
        if type(raw) is not bytes or not 0<len(raw)<=65536:wire._fail('repair_control_too_large')
        s=self.state;b=wire.RepairBudget(s.policy)
        value=wire.parse_new_wire(raw,s.policy,b).value
        wire.object_fields(value,{'schema_version','kind','caller','allocation'})
        if value['schema_version']!=resource.SCHEMA or value['kind']!='ack.copy_allocate':wire._fail('repair_copy_allocation_mismatch')
        caller=value['caller'];caller_id=resource._dual_key(caller,b)['signing_key_id']
        allocation=decode_entry(value['allocation'],s.policy,b)
        parsed,ref=s._entry(allocation,b);signed=wire.object_fields(parsed.value,{'payload','proof'})
        p=wire.object_fields(signed['payload'],resource.COMMON|set(resource._FIELDS[0].split()))
        original._verify_control_signature(p,signed['proof'],caller['signing_key'],b)
        intent=wire.object_fields(p['intent'],INTENT_FIELDS);resource._windows(intent['windows'],issued=p['issued_at'])
        resource._budget(intent['budget']);resource._lifetime(p)
        now=s._now();retain=intent['windows']['retain_until']
        if (p['signing_key']!=caller['signing_key'] or intent['caller']!=caller or intent['target']!=s.target
                or intent['target_storage_epoch']!=s.node['payload']['storage_epoch']
                or not p['issued_at']<=now<p['expires_at'] or max(intent['windows'].values())>now+self.policy['max_lifetime']):
            wire._fail('repair_copy_allocation_mismatch')
        ticket=secrets.token_hex(16);charge=len(raw)+65536;response=None
        with s._transaction(guard=self._live):
            held=s._one('SELECT * FROM open_repair_copy_remote_callers WHERE caller=?',(caller_id,))
            digest=b._hash(canonical_bytes(caller));journal_id='copy_remote_'+caller_id
            if held is None:
                if self.db.execute('SELECT count(*) FROM open_repair_copy_remote_callers').fetchone()[0]>=self.policy['max_callers']:wire._fail('repair_copy_capacity')
                s.capacity.reserve('repair_copy',journal_id,digest,self.policy['max_journal_bytes'],now+self.policy['max_lifetime'],owner=caller_id,operation_id='remote_copy')
                self.db.execute('INSERT INTO open_repair_copy_remote_callers VALUES(?,?,?)',(caller_id,canonical_bytes(caller),now+self.policy['max_lifetime']))
                held=s._one('SELECT * FROM open_repair_copy_remote_callers WHERE caller=?',(caller_id,))
            reservation=s._one("SELECT * FROM open_capacity_reservations WHERE service='repair_copy' AND reservation_id=?",(journal_id,))
            if (bytes(held['keys'])!=canonical_bytes(caller) or retain>held['retain_until'] or now>=held['retain_until']
                    or reservation is None or reservation['digest']!=digest or reservation['charge_bytes']!=self.policy['max_journal_bytes']
                    or reservation['owner']!=caller_id or reservation['operation_id']!='remote_copy' or reservation['retain_until']!=held['retain_until']):wire._fail('repair_copy_ledger_missing')
            count,checks,used=self.db.execute('SELECT count(*),coalesce(sum(coalesce(actual,allowance)),0),coalesce(sum(wire_bytes),0) FROM open_repair_copy_remote_work WHERE caller=?',(caller_id,)).fetchone()
            if (count>=self.policy['max_requests'] or checks+s.policy.max_signature_checks>self.policy['max_signatures']
                    or used+charge>self.policy['max_bytes'] or (count+1)*512+len(held['keys'])+512>self.policy['max_journal_bytes']):wire._fail('repair_copy_work_capacity')
            self.db.execute('INSERT INTO open_repair_copy_remote_work VALUES(?,?,NULL,?,NULL,?)',(ticket,caller_id,s.policy.max_signature_checks,charge))
        def admitted(rid,caps):
            if self.db.execute('SELECT count(*) FROM open_repair_copy_resources WHERE caller=?',(caller_id,)).fetchone()[0]>self.policy['max_caller_resources']:wire._fail('repair_copy_capacity')
            work=s._one('SELECT requests FROM open_repair_copy_work WHERE resource_id=?',(rid,));count=work['requests'] if work else 0
            if count>=min(64,caps['max_requests'],caps['max_replay_records']):wire._fail('repair_copy_work_capacity')
            self.db.execute('INSERT OR REPLACE INTO open_repair_copy_work VALUES(?,?)',(rid,count+1))
            self.db.execute('UPDATE open_repair_copy_remote_work SET resource_id=? WHERE id=?',(rid,ticket))
        try:
            offer=RepairCopyResources(s).allocate(allocation,expected_caller=caller,_budget=b,_guard=self._live,_admitted=admitted)
            response=wire.build_new_wire(dict(schema_version=resource.SCHEMA,kind='ack.copy_allocation',offer=encode_entry(offer)),s.policy,b).raw
            if len(response)>65536:wire._fail('repair_control_too_large')
            return response
        finally:
            with s._transaction():
                row=s._one('SELECT * FROM open_repair_copy_remote_work WHERE id=?',(ticket,))
                if row is None or row['actual'] is not None:wire._fail('repair_service_work_corrupt')
                self.db.execute('UPDATE open_repair_copy_remote_work SET actual=?,wire_bytes=? WHERE id=?',
                    (b.snapshot()['signature_checks'],charge if response is None or len(response)>65536 else len(raw)+len(response),ticket))
