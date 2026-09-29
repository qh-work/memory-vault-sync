"""Destination-local ACK-unbound copy commit; no network/read/GC endpoint.

Transport callers must independently authenticate the maintainer and disclosure
before upload. A reservation, staged bytes or a verifier result is not custody.
"""
import json

from memory_vault import canonical_bytes
import memory_vault_open_repair_copy_authority as authority
import memory_vault_open_repair_copy_source as copy_source
import memory_vault_open_repair_empty as empty
import memory_vault_open_repair_resource as resource
import memory_vault_open_repair_history as history
import memory_vault_open_repair_index as index
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
        # Service rows use this same reservation; no separate uncharged store.
        for table,columns in (
                ('open_repair_copy_read_config','length(raw)+length(digest)'),
                ('open_repair_copy_upload_sessions','length(intent)+length(challenge)+length(nonce)+coalesce(length(answer),0)+coalesce(length(handle),0)+coalesce(length(closed),0)+coalesce(length(result),0)'),
                ('open_repair_copy_upload_chunks','length(response)'),
                ('open_repair_copy_upload_work','0'),
                ('open_repair_copy_upload_routes','0'),
                ('open_repair_bootstrap_usage','0'),('open_repair_bootstrap_work','0'),
                ('open_repair_bootstrap_challenges','length(probe)+length(probe_ref)+length(challenge)+length(challenge_ref)+length(nonce)+coalesce(length(response),0)+coalesce(length(handle_ref),0)'),
                ('open_repair_bootstrap_handles','length(response)'),('open_repair_bootstrap_requests','0')):
            if self.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone():
                total+=self.db.execute('SELECT coalesce(sum('+columns+'+?),0) FROM '+table+' WHERE resource_id=?',(ROW_CHARGE,rid)).fetchone()[0]
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

    def commit_unbound(self,*args,**options):
        return self._commit(*args,**options,source_state='unbound',bound={})

    def commit_empty(self,*args,expected_receipt_writer,expected_message_id,expected_envelope_ref,**options):
        return self._commit(*args,**options,source_state='empty',bound=dict(
            expected_receipt_writer=expected_receipt_writer,expected_message_id=expected_message_id,
            expected_envelope_ref=expected_envelope_ref))

    def _commit(self,manifest_entry,resolver,custody_entry,allocation_entry,offer_entry,assignment_entry,
            reservation_entry,owner_disclosure_entry,source_disclosure_entry,*,expected_ack_slot,expected_owner,
            expected_source,source_storage_epoch,expected_maintainer,current_statuses,limit_policy,source_state,bound):
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
        held=s._one('SELECT * FROM open_repair_copy_commits WHERE resource_id=?',(rid,))
        if held is not None:
            with s._transaction():self._load_inventory(row,held,budget)
        root_digest=budget._hash(wire._canonical(parsed['intent']['root_key'],budget))
        plan=authority._verify_copy(manifest_entry,resolver,custody_entry,allocation_entry,offer_entry,
            assignment_entry,reservation_entry,owner_disclosure_entry,source_disclosure_entry,
            expected_ack_slot=expected_ack_slot,expected_owner=expected_owner,expected_source=expected_source,
            source_storage_epoch=source_storage_epoch,expected_maintainer=expected_maintainer,
            expected_target=s.target,target_storage_epoch=s.node['payload']['storage_epoch'],
            current_statuses=current_statuses,at=s._now(),limit_policy=limit_policy,policy=policy,budget=budget,
            on_observed=lambda item:self._observe_single(row,caps,root_digest,item),source_state=source_state,bound=bound)
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
        for name,item in (('copy.allocation',plan.allocation),('copy.offer',plan.offer),('copy.assignment',plan.assignment),
                ('copy.owner_disclosure',plan.disclosures[0]),('copy.source_disclosure',plan.disclosures[1])):add(name,item)
        for role,entry,source_manifest in copy_source.source_histories(plan.source,manifest_entry):
            add(role,entry)
            for member in source_manifest.manifest.value['roles']:
                packed=resolver.resolve(member['pack_ref']);add('history.raw_pack',packed)
                for ref in (member['document_ref'],member['pack_ref']):
                    edges.append(dict(parent_ref=entry['ref'],relation='manifest-member',child_ref=ref))
        roles=sorted({(value['role'],*history._ref_tuple(value['ref'])):value for value in roles}.values(),
            key=lambda value:(value['role'],*history._ref_tuple(value['ref'])))
        edges=sorted({(*history._ref_tuple(value['parent_ref']),value['relation'],*history._ref_tuple(value['child_ref'])):value for value in edges}.values(),
            key=lambda value:(*history._ref_tuple(value['parent_ref']),value['relation'],*history._ref_tuple(value['child_ref'])))
        input_digest=budget._hash(canonical_bytes(roles))
        stable_keys=set(objects)
        for item in plan.statuses:add('copy.current_status',item)
        roles=sorted({(value['role'],*history._ref_tuple(value['ref'])):value for value in roles}.values(),
            key=lambda value:(value['role'],*history._ref_tuple(value['ref'])))
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
                    for key in stable_keys:
                        raw,ref_raw=objects[key]
                        stored=s._one('SELECT raw,ref FROM open_repair_copy_objects WHERE resource_id=? AND ref_digest=?',(rid,key))
                        if stored is None:stored=s._one('SELECT raw,ref FROM open_repair_copy_observations WHERE resource_id=? AND raw_digest=?',(rid,json.loads(ref_raw)['raw_sha256']))
                        if stored is None or bytes(stored['raw'])!=raw or bytes(stored['ref'])!=ref_raw:
                            denial='repair_copy_objects_missing';break
                    if denial is None:
                        self._load_inventory(row,held,budget)
                        result=s._saved(held,'custody')
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
                pending={}
                for key,(raw,ref_raw) in objects.items():
                    ref=json.loads(ref_raw)
                    observed=s._one('SELECT raw,ref FROM open_repair_copy_observations WHERE resource_id=? AND raw_digest=?',(rid,ref['raw_sha256']))
                    if observed is None or bytes(observed['raw'])!=raw or bytes(observed['ref'])!=ref_raw:
                        pending[key]=(raw,ref_raw)
                size=self._metadata(row)+sum(len(raw)+len(ref)+ROW_CHARGE for raw,ref in pending.values())+len(manifest)+len(canonical_bytes(mref))+len(custody['raw'])+len(canonical_bytes(custody['ref']))+ROW_CHARGE
                if size>caps['max_meta_bytes'] or len(objects)>caps['max_items']:denial='repair_copy_capacity'
                else:
                    for key,(raw,ref_raw) in pending.items():self.db.execute('INSERT INTO open_repair_copy_objects VALUES(?,?,?,?)',(rid,key,raw,ref_raw))
                    self.db.execute('INSERT INTO open_repair_copy_commits VALUES(?,?,?,?,?,?,?)',
                        (rid,input_digest,manifest,canonical_bytes(mref),custody['raw'],canonical_bytes(custody['ref']),size))
                    result=custody
        if denial:wire._fail(denial)
        return result

    def _load_inventory(self,row,held,budget):
        """Check the complete immutable storage snapshot, not live READ rights."""
        s=self.source;rid=row['resource_id'];policy=s._budget_policy(budget)
        manifest=s._saved(held,'manifest');custody=s._saved(held,'custody')
        fields=resource.COMMON|set('root_key scope original_custody_ref replica_manifest_ref assignment_ref resource_offer_ref resource reservation_generation stored_at read_until retain_until'.split())
        event=index._signed(custody,s.identity.public_descriptor(),'replica.custody',fields,policy,budget)
        history._resource(event.payload['resource'])
        wire.u53(event.payload['stored_at']);wire.u53(event.payload['read_until']);wire.u53(event.payload['retain_until'])
        wire.u53(event.payload['reservation_generation'],1)
        value=wire.parse_new_wire(manifest['raw'],policy,budget).value
        wire.object_fields(value,{'schema_version','kind','root_key','scope','original_roles','physical_objects','edges'})
        if (value['schema_version']!=resource.SCHEMA or value['kind']!='replica.manifest'
                or event.payload['replica_manifest_ref']!=manifest['ref'] or event.payload['root_key']!=value['root_key']
                or event.payload['scope']!=value['scope'] or event.payload['resource']['resource_id']!=rid
                or event.payload['resource']['node_key_id']!=s.identity.key_id
                or event.payload['resource']['storage_epoch']!=s.node['payload']['storage_epoch']
                or event.payload['reservation_generation']!=1):wire._fail('repair_copy_commit_mismatch')
        offer=s._saved(row,'offer');p=wire.parse_new_wire(offer['raw'],policy,budget).value['payload']
        if (event.payload['resource_offer_ref']!=offer['ref'] or event.payload['resource']!=p['resource']
                or value['root_key']!=p['intent']['root_key'] or value['scope']!=p['intent']['scope']
                or value['physical_objects']!=value['original_roles']):wire._fail('repair_copy_commit_mismatch')
        if not 1<=len(value['original_roles'])<=128:wire._fail('repair_copy_capacity')
        entries={};previous=None;used_objects=set()
        for item in value['original_roles']:
            wire.object_fields(item,{'role','ref'});ref=wire.raw_ref(item['ref'])
            if type(item['role']) is not str:wire._fail('repair_copy_commit_mismatch')
            order=item['role'],*history._ref_tuple(ref)
            if previous is not None and order<=previous:wire._fail('repair_copy_commit_mismatch')
            previous=order;key=budget._hash(canonical_bytes(ref.as_dict()))
            stored=s._one('SELECT raw,ref FROM open_repair_copy_objects WHERE resource_id=? AND ref_digest=?',(rid,key))
            if stored is not None:used_objects.add(key)
            else:stored=s._one('SELECT raw,ref FROM open_repair_copy_observations WHERE resource_id=? AND raw_digest=?',(rid,ref.raw_sha256))
            if stored is None or json.loads(bytes(stored['ref']))!=ref.as_dict():wire._fail('repair_copy_objects_missing')
            raw=bytes(stored['raw']);budget._bytes('input_bytes',len(raw))
            if len(raw)!=ref.size or budget._hash(raw)!=ref.raw_sha256:wire._fail('repair_ref_mismatch')
            entries.setdefault(item['role'],[]).append(dict(raw=raw,ref=ref.as_dict()))
        object_count=self.db.execute('SELECT count(*) FROM open_repair_copy_objects WHERE resource_id=?',(rid,)).fetchone()[0]
        expected_count=len({canonical_bytes(item['ref']) for item in value['original_roles']})
        if object_count!=len(used_objects) or expected_count>p['budget']['max_items'] or self._metadata(row)>p['budget']['max_meta_bytes']:
            wire._fail('repair_copy_commit_mismatch')
        stable=[item for item in value['original_roles'] if item['role']!='copy.current_status']
        if budget._hash(canonical_bytes(stable))!=held['input_digest'] or not entries.get('copy.current_status'):
            wire._fail('repair_copy_commit_mismatch')
        return value,event,entries

    def _committed(self,resource_id):
        """Caller holds the storage transaction; never rebuild missing capacity."""
        resource._opaque(resource_id);s=self.source
        row=s._one('SELECT * FROM open_repair_copy_resources WHERE resource_id=?',(resource_id,))
        held=s._one('SELECT * FROM open_repair_copy_commits WHERE resource_id=?',(resource_id,))
        if row is None or held is None:wire._fail('repair_copy_commit_missing')
        reserved=s._one("SELECT * FROM open_capacity_reservations WHERE service='repair_copy' AND reservation_id=?",(resource_id,))
        if (reserved is None or reserved['digest']!=row['request_digest'] or reserved['charge_bytes']!=row['charge_bytes']
                or reserved['retain_until']!=row['retain_until'] or reserved['owner']!=row['caller']
                or reserved['operation_id']!=row['allocation_id']):wire._fail('repair_copy_ledger_missing')
        return row,held

    def read_local_original(self,resource_id,reference,*,_budget=None):
        """Read only an exact committed original for the local service adapter.

        This grants no remote READ right. A service must check current authority,
        disclosure and possession before releasing any bytes. Later observations
        outside the immutable manifest cannot be fetched through this method.
        """
        s=self.source;budget=wire.RepairBudget(s.policy) if _budget is None else _budget
        s._budget_policy(budget);ref=wire.raw_ref(reference)
        with s._transaction():
            row,held=self._committed(resource_id)
            _,_,entries=self._load_inventory(row,held,budget)
            candidates=[s._saved(held,'manifest'),s._saved(held,'custody')]
            candidates.extend(entry for values in entries.values() for entry in values)
            for entry in candidates:
                if wire.raw_ref(entry['ref'])==ref:
                    budget._bytes('output_bytes',len(entry['raw']))
                    return entry['raw']
            wire._fail('repair_ref_missing')

    def restore_unbound(self,*args,**options):
        return self._restore(*args,**options,source_state='unbound',bound={})

    def restore_empty(self,*args,expected_receipt_writer,expected_message_id,expected_envelope_ref,**options):
        return self._restore(*args,**options,source_state='empty',bound=dict(
            expected_receipt_writer=expected_receipt_writer,expected_message_id=expected_message_id,
            expected_envelope_ref=expected_envelope_ref))

    def _restore(self,resource_id,*,expected_ack_slot,expected_owner,expected_source,
            source_storage_epoch,expected_maintainer,limit_policy,source_state,bound,_budget=None):
        """Operator-local historical reconstruction after restart, never READ.

        Only committed storage is used. Current remote serving rights and dual
        possession must be checked separately before exposing any returned bytes.
        """
        resource._opaque(resource_id);s=self.source
        budget=wire.RepairBudget(s.policy) if _budget is None else _budget;policy=s._budget_policy(budget)
        with s._transaction():
            row,held=self._committed(resource_id)
            _,_,entries=self._load_inventory(row,held,budget)
        resolver=wire.LocalRawResolver(policy,budget)
        for values in entries.values():
            for entry in values:
                ref=wire.raw_ref(entry['ref'])
                if resolver.put(ref.namespace,ref.key,entry['raw']).ref!=ref:wire._fail('repair_ref_mismatch')
        return authority._verify_replica_event(s._saved(held,'manifest'),resolver,s._saved(held,'custody'),
            expected_ack_slot=expected_ack_slot,expected_owner=expected_owner,expected_source=expected_source,
            source_storage_epoch=source_storage_epoch,expected_maintainer=expected_maintainer,
            expected_target=s.target,target_storage_epoch=s.node['payload']['storage_epoch'],
            limit_policy=limit_policy,policy=policy,budget=budget,source_state=source_state,bound=bound)

    def prepare_unbound_read(self,resource_id,consents,*,expected_ack_slot,expected_owner,expected_source,
            source_storage_epoch,expected_maintainer,current_statuses,limit_policy,action='proof',_budget=None,_include_replica=False):
        return self._prepare_read(resource_id,consents,expected_ack_slot=expected_ack_slot,expected_owner=expected_owner,
            expected_source=expected_source,source_storage_epoch=source_storage_epoch,expected_maintainer=expected_maintainer,
            current_statuses=current_statuses,limit_policy=limit_policy,action=action,_budget=_budget,
            _include_replica=_include_replica,source_state='unbound',bound={})

    def prepare_empty_read(self,*args,expected_receipt_writer,expected_message_id,expected_envelope_ref,**options):
        return self._prepare_read(*args,**options,source_state='empty',bound=dict(
            expected_receipt_writer=expected_receipt_writer,expected_message_id=expected_message_id,
            expected_envelope_ref=expected_envelope_ref))

    def _prepare_read(self,resource_id,consents,*,expected_ack_slot,expected_owner,expected_source,
            source_storage_epoch,expected_maintainer,current_statuses,limit_policy,source_state,bound,
            action='proof',_budget=None,_include_replica=False):
        """Durable current permission check for a future possession/read service.

        This is operator-local. It never claims caller key possession or publishes
        reconstructed bytes. Refused requests retain authentic status observations.
        """
        s=self.source;budget=wire.RepairBudget(s.policy) if _budget is None else _budget
        policy=s._budget_policy(budget)
        with s._transaction():
            row,held=self._committed(resource_id)
            offer=wire.parse_new_wire(s._saved(row,'offer')['raw'],policy,budget).value['payload']
            caps=offer['budget'];resource._budget(caps)
            work=s._one('SELECT requests FROM open_repair_copy_work WHERE resource_id=?',(resource_id,))
            count=work['requests'] if work else 0
            if count>=min(64,caps['max_requests'],caps['max_replay_records']):wire._fail('repair_copy_work_capacity')
            self.db.execute('INSERT OR REPLACE INTO open_repair_copy_work VALUES(?,?)',(resource_id,count+1))
        replica=self._restore(resource_id,expected_ack_slot=expected_ack_slot,expected_owner=expected_owner,
            expected_source=expected_source,source_storage_epoch=source_storage_epoch,expected_maintainer=expected_maintainer,
            limit_policy=limit_policy,_budget=budget,source_state=source_state,bound=bound)
        root=replica['custody'].payload['root_key'];root_digest=budget._hash(wire._canonical(root,budget))
        plan=authority._check_unbound_owner_return(replica,consents,expected_owner=expected_owner,
            expected_source=expected_source,expected_maintainer=expected_maintainer,expected_target=s.target,
            target_storage_epoch=s.node['payload']['storage_epoch'],current_statuses=current_statuses,at=s._now(),
            action=action,policy=policy,budget=budget,on_observed=lambda item:self._observe_single(row,caps,root_digest,item))
        denial=plan['denial_code']
        with s._transaction() as now:
            row,current=self._committed(resource_id)
            if s._saved(current,'custody')['raw']!=replica['custody'].raw:wire._fail('repair_copy_commit_mismatch')
            self._load_inventory(row,current,budget)
            blocked=s._one('SELECT reason FROM open_repair_copy_blocks WHERE root_digest=?',(root_digest,))
            if blocked:denial=denial or blocked['reason']
            previous=[]
            for raw,ref in self.db.execute('SELECT raw,ref FROM open_repair_copy_observations WHERE root_digest=?',(root_digest,)):
                payload=wire.parse_new_wire(bytes(raw),policy,budget).value['payload']
                previous.append(status.authenticate_status_original(dict(raw=bytes(raw),ref=json.loads(bytes(ref))),
                    expected_root=root,expected_signing_key=payload['signing_key'],at=payload['issued_at'],
                    allowed_scopes=[dict(scope_kind=e['scope_kind'],scope_id=e['scope_id']) for e in payload['entries']],policy=policy,budget=budget))
            try:empty._history_floors((*previous,*plan['statuses']),previous=previous,current=plan['statuses'])
            except wire.RepairWireError as error:denial=denial or error.code
            for item in previous:
                for entry in item.payload['entries']:
                    if entry['status']=='revoked' and any(item.payload['signing_key']==need['signer'] and
                            (entry['scope_kind'],entry['scope_id'])==(need['scope_kind'],need['scope_id']) for need in plan['obligations']):
                        denial=denial or 'repair_authority_revoked'
            if (now>=plan['expires_at'] or not s.node['payload']['issued_at']<=now<s.node['payload']['expires_at']
                    or s.node['payload']['status']!='active'):denial=denial or 'repair_access_expired'
            stamp=self._read_snapshot(resource_id,root_digest) if _include_replica and denial is None else None
        if denial:wire._fail(denial)
        result=dict(state='permission_checked',resource_id=resource_id,action=action,
            replica_custody_ref=replica['custody'].ref.as_dict(),**plan)
        if _include_replica:result.update(_replica=replica,_stamp=stamp,_root_digest=root_digest)
        return result

    def _read_snapshot(self,resource_id,root_digest):
        """Internal immutable permission/byte stamp, under the storage lock."""
        s=self.source;row,held=self._committed(resource_id)
        parts=[tuple(row.items()),tuple(held.items()),canonical_bytes(s.node),canonical_bytes(s.limits)]
        for table,where,value,order in (
                ('open_repair_copy_objects','resource_id',resource_id,'ref_digest'),
                ('open_repair_copy_observations','root_digest',root_digest,'resource_id,raw_digest'),
                ('open_repair_copy_blocks','root_digest',root_digest,'resource_id')):
            parts.append(tuple(tuple(r) for r in self.db.execute('SELECT * FROM '+table+' WHERE '+where+'=? ORDER BY '+order,(value,))))
        if self.db.execute("SELECT 1 FROM sqlite_master WHERE name='open_repair_copy_read_config'").fetchone():
            parts.append(tuple(tuple(r) for r in self.db.execute('SELECT * FROM open_repair_copy_read_config WHERE resource_id=?',(resource_id,))))
        return tuple(parts)
