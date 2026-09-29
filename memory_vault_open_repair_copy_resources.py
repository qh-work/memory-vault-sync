"""Destination-local reservations for delegated ACK copies.

An offer reserves real shared capacity; it grants no copy, read or custody
permission. A future transport must authenticate admission and dual possession,
and the maintainer must verify advance reservation disclosure before sending an
intent. Original copy authority and complete source evidence remain prerequisites
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

    def allocate(self, entry, *, expected_caller):
        s=self.source;budget=wire.RepairBudget(s.policy)
        caller=wire.build_new_wire(expected_caller,s.policy,budget).value
        caller_id=resource._dual_key(caller,budget)['signing_key_id']
        parsed,ref=s._entry(entry,budget)
        if len(parsed.raw)>65536:wire._fail('repair_copy_capacity')
        signed=resource._fields(parsed.value,{'payload','proof'})
        p=resource._fields(signed['payload'],resource.COMMON|set(resource._FIELDS[0].split()))
        resource._lifetime(p)
        intent=resource._fields(p['intent'],INTENT_FIELDS)
        history._root(intent['root_key']);ack_copy_scope(intent['scope'],intent['root_key'])
        for name in ('allocation_id','job_id'):resource._opaque(intent[name])
        resource._opaque(p['request_id'])
        manifest=wire.raw_ref(intent['historical_manifest_ref'])
        caps=intent['budget'];resource._budget(caps)
        resource._windows(intent['windows'],issued=p['issued_at'])
        if (p['schema_version']!=resource.SCHEMA or p['kind']!='resource.allocate'
                or p['signing_key']!=caller['signing_key'] or intent['caller']!=caller
                or intent['kind']!='resource.copy_intent' or intent['purpose']!='ack_replica'
                or intent['target']!=s.target or p['target_node_key_id']!=s.identity.key_id
                or p['target_storage_epoch']!=s.node['payload']['storage_epoch']
                or intent['target_storage_epoch']!=p['target_storage_epoch']
                or manifest.namespace!='meta'
                or p['intent_sha256']!=budget._hash(wire._canonical(intent,budget))):
            wire._fail('repair_copy_allocation_mismatch')
        original._verify_control_signature(p,signed['proof'],caller['signing_key'],budget)
        if (min(caps[name] for name in ('max_meta_bytes','max_items','max_requests','max_pending',
                'max_replay_records','max_jobs','max_job_bytes'))<=0
                or (intent['scope']['kind']=='ack_occupied' and caps['max_live_bytes']<wire.raw_ref(intent['scope']['receipt_ref']).size)):
            wire._fail('repair_copy_capacity')
        charge=caps['max_live_bytes']+caps['max_meta_bytes']+caps['max_job_bytes']+caps['max_replay_records']*REPLAY_CHARGE+ROW_CHARGE
        wire.u53(charge,1)
        digest=budget._hash(wire._canonical(ref.as_dict(),budget))
        with s._transaction() as now:
            old=s._one('SELECT * FROM open_repair_copy_resources WHERE caller=? AND allocation_id=?',(caller_id,intent['allocation_id']))
            if old is not None:
                if old['request_digest']!=digest or bytes(old['request'])!=parsed.raw:
                    wire._fail('repair_copy_allocation_conflict')
                reserved=s._one("SELECT * FROM open_capacity_reservations WHERE service='repair_copy' AND reservation_id=?",(old['resource_id'],))
                if (reserved is None or reserved['digest']!=digest or reserved['charge_bytes']!=charge
                        or reserved['retain_until']!=old['retain_until'] or reserved['owner']!=caller_id
                        or reserved['operation_id']!=intent['allocation_id']):
                    wire._fail('repair_copy_ledger_missing')
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
            return offer
