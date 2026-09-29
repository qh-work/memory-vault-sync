"""Destination-local ACK-unbound copy commit; no network/read/GC endpoint.

Transport callers must independently authenticate the maintainer and disclosure
before upload. A reservation, staged bytes or a verifier result is not custody.
"""
import json

from memory_vault import canonical_bytes
import memory_vault_open_repair_copy_authority as authority
import memory_vault_open_repair_empty as empty
import memory_vault_open_repair_resource as resource
import memory_vault_open_repair_history as history
import memory_vault_open_repair_status as status
import memory_vault_open_repair_wire as wire
from memory_vault_open_repair_copy_resources import RepairCopyResources
from memory_vault_open_repair_state import ROW_CHARGE


class RepairCopyState(RepairCopyResources):
    def initialize(self):
        super().initialize()
        with self.source._transaction():
            for sql in (
                'CREATE TABLE IF NOT EXISTS open_repair_copy_objects(resource_id TEXT NOT NULL,ref_digest TEXT NOT NULL,raw BLOB NOT NULL,ref BLOB NOT NULL,PRIMARY KEY(resource_id,ref_digest))',
                'CREATE TABLE IF NOT EXISTS open_repair_copy_commits(resource_id TEXT PRIMARY KEY,input_digest TEXT NOT NULL,manifest BLOB NOT NULL,manifest_ref BLOB NOT NULL,custody BLOB NOT NULL,custody_ref BLOB NOT NULL,metadata_bytes INTEGER NOT NULL)',
                'CREATE TABLE IF NOT EXISTS open_repair_copy_observations(resource_id TEXT NOT NULL,root_digest TEXT NOT NULL,raw_digest TEXT NOT NULL,raw BLOB NOT NULL,ref BLOB NOT NULL,PRIMARY KEY(resource_id,raw_digest))',
                'CREATE TABLE IF NOT EXISTS open_repair_copy_blocks(resource_id TEXT PRIMARY KEY,root_digest TEXT NOT NULL,reason TEXT NOT NULL)',
                'CREATE TABLE IF NOT EXISTS open_repair_copy_work(resource_id TEXT PRIMARY KEY,requests INTEGER NOT NULL)'):
                self.db.execute(sql)

    def _metadata(self,row):
        rid=row['resource_id']
        total=len(row['request'])+len(row['request_ref'])+len(row['offer'])+len(row['offer_ref'])+5*ROW_CHARGE
        for table in ('objects','observations'):
            total+=self.db.execute('SELECT coalesce(sum(length(raw)+length(ref)+?),0) FROM open_repair_copy_'+table+' WHERE resource_id=?',(ROW_CHARGE,rid)).fetchone()[0]
        held=self.source._one('SELECT * FROM open_repair_copy_commits WHERE resource_id=?',(rid,))
        if held:total+=sum(len(held[name]) for name in ('manifest','manifest_ref','custody','custody_ref'))+ROW_CHARGE
        return total

    def _observe_single(self,row,caps,root_digest,item):
        # Persist before any later source/status/pack check can fail. Capacity
        # overflow latches this root instead of forgetting an authentic denial.
        rid=row['resource_id'];ref_raw=canonical_bytes(item.ref.as_dict());denial=None
        with self.source._transaction():
            if not self.source._one('SELECT 1 FROM open_repair_copy_observations WHERE resource_id=? AND raw_digest=?',(rid,item.ref.raw_sha256)):
                if self._metadata(row)+len(item.raw)+len(ref_raw)+ROW_CHARGE>caps['max_meta_bytes']:
                    denial='repair_copy_status_capacity'
                    self.db.execute('INSERT OR IGNORE INTO open_repair_copy_blocks VALUES(?,?,?)',(rid,root_digest,denial))
                else:
                    self.db.execute('INSERT INTO open_repair_copy_observations VALUES(?,?,?,?,?)',
                        (rid,root_digest,item.ref.raw_sha256,item.raw,ref_raw))
        if denial:wire._fail(denial)

    def commit_unbound(self,manifest_entry,resolver,custody_entry,allocation_entry,offer_entry,assignment_entry,
            reservation_entry,owner_disclosure_entry,source_disclosure_entry,*,expected_ack_slot,expected_owner,
            expected_source,source_storage_epoch,expected_maintainer,current_statuses,limit_policy):
        s=self.source;policy=s.policy;budget=resolver.budget
        wire._context(policy,budget)
        # The exact local allocation is mandatory; this cannot import a remote
        # promise or recreate missing shared capacity from a signed offer.
        offer=self.allocate(allocation_entry,expected_caller=expected_maintainer)
        if offer!=offer_entry:wire._fail('repair_copy_offer_mismatch')
        parsed=wire.parse_new_wire(offer['raw'],policy,budget).value['payload']
        rid=parsed['resource']['resource_id'];caps=parsed['budget']
        row=s._one('SELECT * FROM open_repair_copy_resources WHERE resource_id=?',(rid,))
        with s._transaction():
            work=s._one('SELECT requests FROM open_repair_copy_work WHERE resource_id=?',(rid,))
            count=work['requests'] if work else 0
            if count>=min(64,caps['max_requests'],caps['max_replay_records']):wire._fail('repair_copy_work_capacity')
            self.db.execute('INSERT OR REPLACE INTO open_repair_copy_work VALUES(?,?)',(rid,count+1))
        root_digest=budget._hash(wire._canonical(parsed['intent']['root_key'],budget))
        plan=authority.verify_unbound_copy(manifest_entry,resolver,custody_entry,allocation_entry,offer_entry,
            assignment_entry,reservation_entry,owner_disclosure_entry,source_disclosure_entry,
            expected_ack_slot=expected_ack_slot,expected_owner=expected_owner,expected_source=expected_source,
            source_storage_epoch=source_storage_epoch,expected_maintainer=expected_maintainer,
            expected_target=s.target,target_storage_epoch=s.node['payload']['storage_epoch'],
            current_statuses=current_statuses,at=s._now(),limit_policy=limit_policy,policy=policy,budget=budget,
            on_observed=lambda item:self._observe_single(row,caps,root_digest,item))
        root=plan.assignment.payload['root_key']
        objects={};roles=[];edges=[]
        def add(role,entry):
            if hasattr(entry,'raw'):entry=dict(raw=entry.raw,ref=entry.ref.as_dict())
            ref=wire.raw_ref(entry['ref']);raw=entry['raw']
            if len(raw)!=ref.size or budget._hash(raw)!=ref.raw_sha256:wire._fail('repair_ref_mismatch')
            ref_bytes=canonical_bytes(ref.as_dict());key=budget._hash(ref_bytes)
            if key in objects and objects[key]!=(raw,ref_bytes):wire._fail('repair_ref_conflict')
            objects[key]=(raw,ref_bytes);roles.append(dict(role=role,ref=ref.as_dict()))
        for item in plan.originals:add(item.role,item.original)
        add('history.ack_unbound',manifest_entry)
        for name,item in (('copy.allocation',plan.allocation),('copy.offer',plan.offer),('copy.assignment',plan.assignment),
                ('copy.owner_disclosure',plan.disclosures[0]),('copy.source_disclosure',plan.disclosures[1])):add(name,item)
        for member in plan.source.manifest.manifest.value['roles']:
            packed=resolver.resolve(member['pack_ref']);add('history.raw_pack',packed)
            for ref in (member['document_ref'],member['pack_ref']):
                edges.append(dict(parent_ref=manifest_entry['ref'],relation='manifest-member',child_ref=ref))
        roles=sorted({(value['role'],*history._ref_tuple(value['ref'])):value for value in roles}.values(),
            key=lambda value:(value['role'],*history._ref_tuple(value['ref'])))
        edges=sorted({(*history._ref_tuple(value['parent_ref']),value['relation'],*history._ref_tuple(value['child_ref'])):value for value in edges}.values(),
            key=lambda value:(*history._ref_tuple(value['parent_ref']),value['relation'],*history._ref_tuple(value['child_ref'])))
        input_digest=budget._hash(canonical_bytes(roles))
        denial=plan.denial_code;result=None
        with s._transaction() as now:
            # Allocation and every copied/status byte are charged to this same
            # physical reservation, even when raw-pack bytes duplicate originals.
            live=s._one("SELECT * FROM open_capacity_reservations WHERE service='repair_copy' AND reservation_id=?",(rid,))
            if live is None or live['digest']!=row['request_digest'] or live['charge_bytes']!=row['charge_bytes']:
                wire._fail('repair_copy_ledger_missing')
            blocked=s._one('SELECT reason FROM open_repair_copy_blocks WHERE root_digest=?',(root_digest,))
            if blocked:denial=denial or blocked['reason']
            previous=[]
            for raw,ref in self.db.execute('SELECT raw,ref FROM open_repair_copy_observations WHERE root_digest=?',(root_digest,)):
                p=wire.parse_new_wire(bytes(raw),policy,budget).value['payload']
                previous.append(status.authenticate_status_original(dict(raw=bytes(raw),ref=json.loads(bytes(ref))),
                    expected_root=root,expected_signing_key=p['signing_key'],at=p['issued_at'],
                    allowed_scopes=[dict(scope_kind=e['scope_kind'],scope_id=e['scope_id']) for e in p['entries']],policy=policy,budget=budget))
            try:empty._history_floors((*previous,*plan.statuses),previous=previous,current=plan.statuses)
            except wire.RepairWireError as error:denial=denial or error.code
            for item in previous:
                for e in item.payload['entries']:
                    if e['status']=='revoked' and any(item.payload['signing_key']==need['signer'] and
                            (e['scope_kind'],e['scope_id'])==(need['scope_kind'],need['scope_id']) for need in plan.obligations):
                        denial=denial or 'repair_authority_revoked'
            for item in plan.statuses:
                if s._one('SELECT 1 FROM open_repair_copy_observations WHERE resource_id=? AND raw_digest=?',(rid,item.ref.raw_sha256)):continue
                ref_raw=canonical_bytes(item.ref.as_dict())
                if self._metadata(row)+len(item.raw)+len(ref_raw)+ROW_CHARGE>caps['max_meta_bytes']:
                    denial='repair_copy_status_capacity'
                    self.db.execute('INSERT OR IGNORE INTO open_repair_copy_blocks VALUES(?,?,?)',(rid,root_digest,denial));break
                self.db.execute('INSERT INTO open_repair_copy_observations VALUES(?,?,?,?,?)',(rid,root_digest,item.ref.raw_sha256,item.raw,ref_raw))
            if (now>=min(plan.read_until,plan.retain_until,parsed['reservation_until'])
                    or any(now>=item.payload['valid_until'] for item in plan.statuses)
                    or not s.node['payload']['issued_at']<=now<s.node['payload']['expires_at']
                    or s.node['payload']['status']!='active'):
                denial=denial or 'repair_resource_expired'
            held=s._one('SELECT * FROM open_repair_copy_commits WHERE resource_id=?',(rid,))
            if denial is None and held:
                if held['input_digest']!=input_digest:denial='repair_copy_commit_conflict'
                else:
                    for key,(raw,ref_raw) in objects.items():
                        stored=s._one('SELECT raw,ref FROM open_repair_copy_objects WHERE resource_id=? AND ref_digest=?',(rid,key))
                        if stored is None or bytes(stored['raw'])!=raw or bytes(stored['ref'])!=ref_raw:
                            denial='repair_copy_objects_missing';break
                    if denial is None:result=s._saved(held,'custody')
            if denial is None and held is None:
                manifest=canonical_bytes(dict(schema_version=resource.SCHEMA,kind='replica.manifest',root_key=root,
                    scope=plan.assignment.payload['scope'],original_roles=roles,
                    physical_objects=roles,edges=edges))
                sha=budget._hash(manifest);mref=dict(namespace='meta',key=sha,raw_sha256=sha,size=len(manifest))
                custody=s._sign(dict(schema_version=resource.SCHEMA,kind='replica.custody',signing_key=s.identity.public_descriptor(),
                    root_key=root,scope=plan.assignment.payload['scope'],original_custody_ref=plan.source.custody.ref.as_dict(),
                    replica_manifest_ref=mref,assignment_ref=plan.assignment.ref.as_dict(),resource_offer_ref=plan.offer.ref.as_dict(),
                    resource=parsed['resource'],reservation_generation=1,stored_at=now,
                    read_until=plan.read_until,retain_until=plan.retain_until),'copy_custody',budget)
                size=self._metadata(row)+sum(len(raw)+len(ref)+ROW_CHARGE for raw,ref in objects.values())+len(manifest)+len(canonical_bytes(mref))+len(custody['raw'])+len(canonical_bytes(custody['ref']))+ROW_CHARGE
                if size>caps['max_meta_bytes'] or len(objects)>caps['max_items']:denial='repair_copy_capacity'
                else:
                    for key,(raw,ref_raw) in objects.items():self.db.execute('INSERT INTO open_repair_copy_objects VALUES(?,?,?,?)',(rid,key,raw,ref_raw))
                    self.db.execute('INSERT INTO open_repair_copy_commits VALUES(?,?,?,?,?,?,?)',
                        (rid,input_digest,manifest,canonical_bytes(mref),custody['raw'],canonical_bytes(custody['ref']),size))
                    result=custody
        if denial:wire._fail(denial)
        return result
