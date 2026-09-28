"""One-directory ACK publication storage; staging is never application authority.

The shared transport database and CapacityAuthority own every reservation.
Crypto runs outside writers. Exact originals and authenticated denial floors
survive failed admission and restart; only a committed lease is discoverable.
"""
from contextlib import contextmanager
import base64
import hashlib
import json
import secrets

from memory_vault import canonical_bytes
from memory_vault_open_control import verify_node
import memory_vault_open_provider as provider
import memory_vault_open_repair_history as history
import memory_vault_open_repair_index as index
import memory_vault_open_repair_original as original
import memory_vault_open_repair_probe as probe
import memory_vault_open_repair_resource as resource
import memory_vault_open_repair_status as status
import memory_vault_open_repair_wire as wire
from memory_vault_open_repair_state import RepairAckState, ROW_CHARGE, REPLAY_CHARGE

MAX_STAGE_BYTES = 524288
MAX_REQUESTS = 128
MAX_SIGNATURES = 4096
SINGLE_ROLES = frozenset(('index.assignment', 'index.owner_consent', 'index.recipient_consent',
    'index.provider_fact', 'index.source_head', 'index.source_manifest', 'index.source_commit', 'provider.node'))
MULTIPLE_ROLES = frozenset(('current.status', 'directory.status', 'history.raw_pack'))


def _fail(code):
    wire._fail(code)


def _dump(value):
    return canonical_bytes(value)


def _load(value):
    return json.loads(bytes(value))


def encode_entry(value):
    if hasattr(value, 'raw'):
        value = dict(raw=value.raw, ref=value.ref.as_dict())
    return dict(ref=value['ref'], raw_base64url=base64.urlsafe_b64encode(value['raw']).rstrip(b'=').decode())


def decode_entry(value, policy, budget):
    wire.object_fields(value, {'ref', 'raw_base64url'})
    ref = wire.raw_ref(value['ref'])
    if ref.size > policy.max_document_bytes:
        _fail('repair_index_capacity')
    raw = original._decode64(value['raw_base64url'], ref.size, budget, url=True)
    if len(raw) != ref.size or budget._hash(raw) != ref.raw_sha256:
        _fail('repair_ref_mismatch')
    return dict(raw=raw, ref=ref.as_dict())


class RepairIndexState(RepairAckState):
    def initialize(self):
        super().initialize()
        with self._transaction():
            for sql in (
                '''CREATE TABLE IF NOT EXISTS open_repair_index_resources(
                    allocation_id TEXT PRIMARY KEY,digest TEXT NOT NULL,context BLOB NOT NULL,
                    allocation BLOB NOT NULL,offer BLOB NOT NULL,current_status BLOB NOT NULL,
                    budget BLOB NOT NULL,windows BLOB NOT NULL,metadata_bytes INTEGER NOT NULL,
                    requests INTEGER NOT NULL DEFAULT 0,wire_bytes INTEGER NOT NULL DEFAULT 0,
                    state TEXT NOT NULL DEFAULT 'reserved')''',
                '''CREATE TABLE IF NOT EXISTS open_repair_index_work(
                    id TEXT PRIMARY KEY,allocation_id TEXT NOT NULL,digest TEXT NOT NULL,
                    allowance INTEGER NOT NULL,actual INTEGER,wire_bytes INTEGER NOT NULL)''',
                '''CREATE TABLE IF NOT EXISTS open_repair_index_stages(
                    allocation_id TEXT PRIMARY KEY,intent_digest TEXT UNIQUE NOT NULL,
                    intent BLOB NOT NULL,challenge BLOB NOT NULL,nonce BLOB NOT NULL,
                    answer BLOB,handle BLOB,closed BLOB,result BLOB,expires_at INTEGER NOT NULL)''',
                '''CREATE TABLE IF NOT EXISTS open_repair_index_chunks(
                    allocation_id TEXT NOT NULL,child_index INTEGER NOT NULL,offset INTEGER NOT NULL,
                    digest TEXT NOT NULL,raw BLOB NOT NULL,response BLOB NOT NULL,
                    PRIMARY KEY(allocation_id,child_index,offset))''',
                '''CREATE TABLE IF NOT EXISTS open_repair_index_status_originals(
                    issuer TEXT NOT NULL,root_digest TEXT NOT NULL,revision INTEGER NOT NULL,
                    canonical_digest TEXT NOT NULL,raw_digest TEXT NOT NULL,record BLOB NOT NULL,
                    PRIMARY KEY(issuer,root_digest,revision,canonical_digest,raw_digest))''',
                '''CREATE TABLE IF NOT EXISTS open_repair_index_floors(
                    issuer TEXT NOT NULL,root_digest TEXT NOT NULL,scope_kind TEXT NOT NULL,scope_id TEXT NOT NULL,
                    revision INTEGER NOT NULL,minimum_revision INTEGER NOT NULL,revoked_mask INTEGER NOT NULL,
                    operation_mask INTEGER NOT NULL,valid_until INTEGER NOT NULL,conflict INTEGER NOT NULL,
                    PRIMARY KEY(issuer,root_digest,scope_kind,scope_id))''',
                '''CREATE TABLE IF NOT EXISTS open_repair_index_facts(
                    fact_key TEXT PRIMARY KEY,namespace TEXT NOT NULL,opaque_key TEXT NOT NULL,
                    provider TEXT NOT NULL,revision INTEGER NOT NULL,digest TEXT NOT NULL,record BLOB NOT NULL,
                    node BLOB NOT NULL,index_lease BLOB NOT NULL,allocation_id TEXT NOT NULL,
                    request BLOB NOT NULL,request_digest TEXT NOT NULL,obligations BLOB NOT NULL,
                    root_digest TEXT NOT NULL,expires_at INTEGER NOT NULL,status TEXT NOT NULL,
                    second_record BLOB)''',
                'CREATE INDEX IF NOT EXISTS open_repair_index_lookup ON open_repair_index_facts(namespace,opaque_key,fact_key)',
                'CREATE TABLE IF NOT EXISTS open_repair_index_blocked_roots(root_digest TEXT PRIMARY KEY,reason TEXT NOT NULL)',
                'CREATE TABLE IF NOT EXISTS open_repair_index_directory_revisions(root_digest TEXT PRIMARY KEY,revision INTEGER NOT NULL)',
            ):
                self.db.execute(sql)

    def _row(self, allocation_id):
        original._opaque(allocation_id)
        row = self._one('SELECT * FROM open_repair_index_resources WHERE allocation_id=?', (allocation_id,))
        if row is None:
            _fail('repair_index_allocation_missing')
        return row

    def _stored(self, value, budget):
        return decode_entry(_load(value), budget.policy, budget)

    def _context(self, row, budget):
        context = wire.parse_new_wire(bytes(row['context']), budget.policy, budget).value
        return dict(expected_subject=context['source'], expected_target=self.target,
            target_storage_epoch=self.node['payload']['storage_epoch'], at=self._now(),
            policy=budget.policy, budget=budget)

    def _directory_live(self, now):
        p=self.node['payload']
        return p['status']=='active' and p['issued_at']<=now<p['expires_at'] and 'directory' in p['roles']

    def _preview(self, entry, budget):
        wire.object_fields(entry, {'raw', 'ref'})
        ref = wire.raw_ref(entry['ref'])
        if ref.namespace != 'meta':
            _fail('repair_invalid_ref')
        parsed = wire.parse_new_wire(entry['raw'], budget.policy, budget)
        if len(parsed.raw) != ref.size or budget._hash(parsed.raw) != ref.raw_sha256:
            _fail('repair_ref_mismatch')
        signed = wire.object_fields(parsed.value, {'payload', 'proof'})
        return parsed, ref, signed['payload']

    def _caller(self, entry, row, budget):
        parsed, ref, payload = self._preview(entry, budget)
        context = _load(row['context'])
        original._verify_control_signature(payload, parsed.value['proof'], context['source']['signing_key'], budget)
        return ref, payload

    def _charge_locked(self, row, amount):
        current = self._row(row['allocation_id'])
        if current['metadata_bytes'] + amount > _load(current['budget'])['max_meta_bytes']:
            _fail('repair_index_capacity')
        self.db.execute('UPDATE open_repair_index_resources SET metadata_bytes=metadata_bytes+? WHERE allocation_id=?',
            (amount, row['allocation_id']))

    @contextmanager
    def _work(self, row, reference, budget, wire_bytes):
        # Only the cheap caller signature precedes admission. Every historical
        # signature and exact retry is under one durable reservation.
        attempt = secrets.token_hex(16)
        allowance = budget.policy.max_signature_checks
        with self._transaction() as now:
            if not self._directory_live(now):
                _fail('repair_index_directory_inactive')
            current = self._row(row['allocation_id'])
            if any(current[name] != row[name] for name in ('digest', 'context', 'allocation', 'offer', 'current_status')):
                _fail('repair_index_generation')
            limits, windows = _load(current['budget']), _load(current['windows'])
            used = self.db.execute('SELECT coalesce(sum(coalesce(actual,allowance)),0) FROM open_repair_index_work WHERE allocation_id=?',
                (row['allocation_id'],)).fetchone()[0]
            if (now >= windows['retain_until'] or current['requests'] >= min(MAX_REQUESTS, limits['max_requests'], limits['max_replay_records'])
                    or used + allowance > min(MAX_SIGNATURES, limits['max_requests'] * 64)
                    or current['wire_bytes'] + wire_bytes > limits['max_meta_bytes'] * 4):
                _fail('repair_index_work_capacity')
            self._charge_locked(row, ROW_CHARGE)
            self.db.execute('INSERT INTO open_repair_index_work VALUES(?,?,?,?,NULL,?)',
                (attempt,row['allocation_id'],reference.raw_sha256,allowance,wire_bytes))
            self.db.execute('UPDATE open_repair_index_resources SET requests=requests+1,wire_bytes=wire_bytes+? WHERE allocation_id=?',
                (wire_bytes,row['allocation_id']))
        try:
            yield
        finally:
            actual = budget.snapshot()['signature_checks']
            with self._transaction():
                held = self._one('SELECT * FROM open_repair_index_work WHERE id=?', (attempt,))
                if held is None or held['actual'] is not None or not 1 <= actual <= allowance:
                    _fail('repair_index_work_corrupt')
                self.db.execute('UPDATE open_repair_index_work SET actual=? WHERE id=?', (actual,attempt))

    def allocate(self, entry, *, expected_owner, expected_receipt_writer):
        if not self._directory_live(self._now()):
            _fail('repair_index_directory_inactive')
        budget = wire.RepairBudget(self.policy)
        parsed, ref, p = self._preview(entry,budget)
        wire.object_fields(p,index.ALLOCATE_FIELDS)
        intent = wire.object_fields(p['intent'],index.INTENT_FIELDS)
        owner = wire.build_new_wire(expected_owner,self.policy,budget).value
        writer = wire.build_new_wire(expected_receipt_writer,self.policy,budget).value
        owner_id, writer_id = resource._dual_key(owner,budget), resource._dual_key(writer,budget)
        resource._dual_key(intent['caller'],budget)
        resource._dual_key(intent['target'],budget)
        original._verify_control_signature(p,parsed.value['proof'],intent['caller']['signing_key'],budget)
        index._timed(p,self._now())
        history._root(intent['root_key'])
        scope = wire.object_fields(intent['scope'],{'kind','ack_slot','grant_ref','binding_ref','receipt_ref','original_ack_commit_ref'})
        history._slot(scope['ack_slot'],intent['root_key'],ack=True)
        for name in ('grant_ref','binding_ref','receipt_ref','original_ack_commit_ref'):
            wire.raw_ref(scope[name])
        for name in ('advertised_custody_ref','provider_fact_ref','historical_manifest_ref'):
            wire.raw_ref(intent[name])
        for name in ('allocation_id','job_id'):
            resource._opaque(intent[name])
        resource._opaque(p['request_id'])
        resource._budget(intent['budget']); resource._windows(intent['windows'],issued=self._now())
        if (p['schema_version'] != resource.SCHEMA or p['kind'] != 'resource.allocate'
                or intent['kind'] != 'resource.index_intent' or intent['purpose'] != 'provider_index'
                or intent['root_key']['owner'] != owner_id or scope['ack_slot']['receipt_writer'] != writer_id
                or scope['kind'] != 'ack_occupied' or intent['target'] != self.target
                or p['target_node_key_id'] != self.identity.key_id
                or intent['target_storage_epoch'] != self.node['payload']['storage_epoch']
                or p['target_storage_epoch'] != self.node['payload']['storage_epoch']
                or intent['advertised_custody_ref'] != scope['original_ack_commit_ref']
                or p['intent_sha256'] != budget._hash(wire._canonical(intent,budget))
                or intent['budget']['max_live_bytes'] != 0
                or not 1 <= intent['budget']['max_items'] <= 64
                or not ROW_CHARGE * 4 <= intent['budget']['max_meta_bytes'] <= 4 * MAX_STAGE_BYTES
                or intent['budget']['max_requests'] < 1 or intent['budget']['max_replay_records'] < 1
                or 'directory' not in self.node['payload']['roles']):
            _fail('repair_index_allocation_mismatch')
        context = _dump(dict(owner=owner,writer=writer,source=intent['caller']))
        old = self._one('SELECT * FROM open_repair_index_resources WHERE allocation_id=?',(intent['allocation_id'],))
        if old is not None:
            if old['digest'] != ref.raw_sha256 or bytes(old['context']) != context or self._stored(old['allocation'],budget) != entry:
                _fail('repair_index_allocation_conflict')
            with self._work(old,ref,budget,len(parsed.raw)):
                return dict(offer=self._stored(old['offer'],budget),status=self._stored(old['current_status'],budget))
        now = self._now()
        root_digest = budget._hash(wire._canonical(intent['root_key'],budget))
        sequence = self._one('SELECT revision FROM open_repair_index_directory_revisions WHERE root_digest=?',(root_digest,))
        status_revision = (sequence['revision'] if sequence else 0)+1
        rid = 'index_' + ref.raw_sha256
        res = dict(node_key_id=self.identity.key_id,storage_epoch=self.node['payload']['storage_epoch'],lease_id=rid,resource_id=rid)
        offer = self._sign(dict(schema_version=resource.SCHEMA,kind='resource.offer',signing_key=self.identity.public_descriptor(),
            issued_at=now,reservation_until=min(now+60,intent['windows']['admit_until']),offer_id=rid,
            allocation_request_ref=ref.as_dict(),intent=intent,intent_sha256=p['intent_sha256'],resource=res,
            target_encryption_key=self.target['encryption_key'],reservation_generation=1,budget=intent['budget'],windows=intent['windows']), 'index-offer', budget)
        scope_id = status.status_scope(intent['root_key'],'resource',res,self.policy,budget)
        current = self._sign(dict(schema_version=status.SCHEMA,kind='authority.status',signing_key=self.identity.public_descriptor(),
            scope_key=dict(root_key=intent['root_key'],issuer_key_id=self.identity.key_id),revision=status_revision,issued_at=now,
            valid_until=min(now+status.MAX_STATUS_SECONDS,intent['windows']['publish_until']),entries=[dict(scope_kind='resource',
                scope_id=scope_id,minimum_document_revision=1,status='active',operation_mask=16)]), 'index-status', budget)
        alloc_raw, offer_raw, current_raw = (_dump(encode_entry(item)) for item in (entry,offer,current))
        metadata = sum(map(len,(context,alloc_raw,offer_raw,current_raw)))+ROW_CHARGE
        input_bytes = len(_dump(dict(schema_version=resource.SCHEMA,kind='ack.index_allocate',
            allocation=encode_entry(entry),owner=owner,receipt_writer=writer)))
        metadata += ROW_CHARGE
        limits = intent['budget']
        if metadata > limits['max_meta_bytes']:
            _fail('repair_index_capacity')
        with self._transaction():
            if self._one('SELECT 1 FROM open_repair_index_resources WHERE allocation_id=?',(intent['allocation_id'],)):
                _fail('repair_index_allocation_race')
            if self._one('SELECT revision FROM open_repair_index_directory_revisions WHERE root_digest=?',(root_digest,)) != sequence:
                _fail('repair_index_allocation_race')
            charge = limits['max_meta_bytes']+limits['max_job_bytes']+limits['max_replay_records']*REPLAY_CHARGE+ROW_CHARGE
            self.capacity.reserve('repair_index',rid,ref.raw_sha256,charge,intent['windows']['retain_until'],
                owner=intent['caller']['signing_key']['key_id'],operation_id=intent['allocation_id'])
            self.db.execute('INSERT INTO open_repair_index_resources(allocation_id,digest,context,allocation,offer,current_status,budget,windows,metadata_bytes,requests,wire_bytes) VALUES(?,?,?,?,?,?,?,?,?,1,?)',
                (intent['allocation_id'],ref.raw_sha256,context,alloc_raw,offer_raw,current_raw,_dump(limits),_dump(intent['windows']),metadata,input_bytes))
            self.db.execute('INSERT OR REPLACE INTO open_repair_index_directory_revisions VALUES(?,?)',(root_digest,status_revision))
            self.db.execute('INSERT INTO open_repair_index_work VALUES(?,?,?,?,?,?)',
                (secrets.token_hex(16),intent['allocation_id'],ref.raw_sha256,self.policy.max_signature_checks,budget.snapshot()['signature_checks'],input_bytes))
        return dict(offer=offer,status=current)

    def _stage_row(self, digest):
        row = self._one('SELECT * FROM open_repair_index_stages WHERE intent_digest=?',(digest,))
        if row is None:
            _fail('repair_stage_missing')
        return row

    def _stage_entries(self, staged, budget):
        return {name:self._stored(staged[name],budget) for name in ('intent','challenge','answer','handle','closed','result')
            if staged[name] is not None}

    def _stage_live_locked(self, row, staged):
        current = self._one('SELECT * FROM open_repair_index_stages WHERE allocation_id=?',(row['allocation_id'],))
        resource_row = self._row(row['allocation_id'])
        if (current != staged or self._now() >= staged['expires_at']
                or any(resource_row[name] != row[name] for name in ('digest','context','allocation','offer','current_status'))):
            _fail('repair_index_generation')
        return current

    def _output_locked(self, row, raw):
        current = self._row(row['allocation_id'])
        if current['wire_bytes']+len(raw) > _load(current['budget'])['max_meta_bytes']*4:
            _fail('repair_index_work_capacity')
        self.db.execute('UPDATE open_repair_index_resources SET wire_bytes=wire_bytes+? WHERE allocation_id=?',
            (len(raw),row['allocation_id']))

    def _check_manifest(self, manifest):
        children = manifest['children']
        for role in SINGLE_ROLES:
            if sum(item['role']==role for item in children) != 1:
                _fail('repair_index_stage_inventory')
        if (any(item['role'] not in SINGLE_ROLES|MULTIPLE_ROLES for item in children)
                or sum(item['role']=='history.raw_pack' for item in children) != 3
                or sum(item['role']=='directory.status' for item in children) != 1
                or not 1 <= sum(item['role']=='current.status' for item in children) <= 16):
            _fail('repair_index_stage_inventory')

    def stage_intent(self, entry):
        import memory_vault_open_repair_stage as stage
        budget = wire.RepairBudget(self.policy)
        _,_,p = self._preview(entry,budget)
        row = self._row(p.get('allocation_id'))
        ref,_ = self._caller(entry,row,budget)
        with self._work(row,ref,budget,len(entry['raw'])):
            expected = self._context(row,budget)
            checked = stage.verify_stage_intent(entry,**expected)
            allocation = self._stored(row['allocation'],budget)
            intent = wire.parse_new_wire(allocation['raw'],self.policy,budget).value['payload']['intent']
            manifest = checked.payload['manifest']
            self._check_manifest(manifest)
            if (manifest['root_key'] != intent['root_key'] or manifest['scope'] != intent['scope']
                    or checked.payload['requested_bytes'] > min(MAX_STAGE_BYTES,intent['budget']['max_meta_bytes'])
                    or checked.payload['requested_items'] > intent['budget']['max_items']):
                _fail('repair_index_stage_mismatch')
            old = self._one('SELECT * FROM open_repair_index_stages WHERE allocation_id=?',(row['allocation_id'],))
            if old is not None:
                if old['intent_digest'] != ref.raw_sha256 or self._stored(old['intent'],budget) != entry:
                    _fail('repair_stage_replay_conflict')
                result = self._stored(old['challenge'],budget)
                stage.verify_stage_challenge(result,entry,**expected)
                with self._transaction():
                    self._stage_live_locked(row,old); self._output_locked(row,result['raw'])
                return result
            challenge = stage.issue_stage_challenge(entry,signer=self.identity,
                expires_at=checked.payload['expires_at'],**expected)
            intent_raw,challenge_raw = (_dump(encode_entry(item)) for item in (entry,challenge.original))
            with self._transaction():
                if self._one('SELECT 1 FROM open_repair_index_stages WHERE allocation_id=?',(row['allocation_id'],)):
                    _fail('repair_stage_replay_conflict')
                self._charge_locked(row,len(intent_raw)+len(challenge_raw)+len(challenge.nonce)+ROW_CHARGE)
                self.db.execute('INSERT INTO open_repair_index_stages VALUES(?,?,?,?,?,NULL,NULL,NULL,NULL,?)',
                    (row['allocation_id'],ref.raw_sha256,intent_raw,challenge_raw,challenge.nonce,checked.payload['expires_at']))
                self._output_locked(row,challenge.original.raw)
            return index._entry(challenge.original)

    def stage_answer(self, entry):
        import memory_vault_open_repair_stage as stage
        budget = wire.RepairBudget(self.policy)
        _,_,p = self._preview(entry,budget)
        staged = self._stage_row(wire.raw_ref(p['intent_ref']).raw_sha256)
        row = self._row(staged['allocation_id'])
        ref,_ = self._caller(entry,row,budget)
        with self._work(row,ref,budget,len(entry['raw'])):
            parents,expected = self._stage_entries(staged,budget),self._context(row,budget)
            stage.verify_stage_answer(parents['intent'],parents['challenge'],entry,caller_nonce=bytes(staged['nonce']),**expected)
            if staged['answer'] is not None:
                if parents['answer'] != entry:
                    _fail('repair_stage_replay_conflict')
                result = parents['handle']
                stage.verify_stage_handle(result,parents['intent'],**expected)
                with self._transaction():
                    self._stage_live_locked(row,staged); self._output_locked(row,result['raw'])
                return result
            result = stage.make_stage_handle(parents['intent'],parents['challenge'],entry,caller_nonce=bytes(staged['nonce']),
                signer=self.identity,reservation_generation=1,expires_at=p['expires_at'],**expected)
            answer_raw,handle_raw = (_dump(encode_entry(item)) for item in (entry,result))
            with self._transaction():
                self._stage_live_locked(row,staged)
                self._charge_locked(row,len(answer_raw)+len(handle_raw))
                self.db.execute('UPDATE open_repair_index_stages SET answer=?,handle=? WHERE allocation_id=?',
                    (answer_raw,handle_raw,row['allocation_id']))
                self._output_locked(row,result.raw)
            return index._entry(result)

    def _verify_stage_session(self, staged, budget):
        import memory_vault_open_repair_stage as stage
        row = self._row(staged['allocation_id'])
        parents,expected = self._stage_entries(staged,budget),self._context(row,budget)
        if 'answer' not in parents or 'handle' not in parents:
            _fail('repair_stage_possession_required')
        stage.verify_stage_answer(parents['intent'],parents['challenge'],parents['answer'],caller_nonce=bytes(staged['nonce']),**expected)
        stage.verify_stage_handle(parents['handle'],parents['intent'],**expected)
        return parents,expected

    def stage_child(self, frame):
        import memory_vault_open_repair_stage as stage
        budget = wire.RepairBudget(self.policy)
        entry,_ = stage._decode_frame(frame,self.policy,budget)
        _,_,p = self._preview(entry,budget)
        staged = self._stage_row(wire.raw_ref(p['intent_ref']).raw_sha256)
        row = self._row(staged['allocation_id'])
        ref,_ = self._caller(entry,row,budget)
        with self._work(row,ref,budget,len(frame)):
            parents,expected = self._verify_stage_session(staged,budget)
            checked = stage.verify_stage_child_frame(frame,parents['intent'],parents['handle'],**expected)
            params = (row['allocation_id'],checked.child_index,checked.offset)
            old = self._one('SELECT * FROM open_repair_index_chunks WHERE allocation_id=? AND child_index=? AND offset=?',params)
            if old is not None:
                if old['digest'] != ref.raw_sha256 or bytes(old['raw']) != checked.chunk:
                    _fail('repair_stage_replay_conflict')
                response = bytes(old['response'])
                stage.verify_stage_child_response_frame(response,frame,parents['intent'],parents['handle'],**expected)
                with self._transaction():
                    self._stage_live_locked(row,staged); self._output_locked(row,response)
                return response
            if staged['closed'] is not None:
                _fail('repair_stage_closed')
            prefix = self.db.execute('SELECT coalesce(sum(length(raw)),0) FROM open_repair_index_chunks WHERE allocation_id=? AND child_index=?',params[:2]).fetchone()[0]
            if prefix != checked.offset:
                _fail('repair_stage_range')
            response = stage.make_stage_child_response_frame(frame,parents['intent'],parents['handle'],signer=self.identity,
                durable_prefix=prefix+len(checked.chunk),expires_at=checked.header.payload['expires_at'],**expected)
            with self._transaction():
                self._stage_live_locked(row,staged)
                actual = self.db.execute('SELECT coalesce(sum(length(raw)),0) FROM open_repair_index_chunks WHERE allocation_id=? AND child_index=?',params[:2]).fetchone()[0]
                if actual != prefix:
                    _fail('repair_index_generation')
                self._charge_locked(row,len(checked.chunk)+len(response)+ROW_CHARGE)
                self.db.execute('INSERT INTO open_repair_index_chunks VALUES(?,?,?,?,?,?)',(*params,ref.raw_sha256,checked.chunk,response))
                self._output_locked(row,response)
            return response

    def _complete_children(self, staged, parents, budget):
        manifest = wire.parse_new_wire(parents['intent']['raw'],self.policy,budget).value['payload']['manifest']
        result = []
        for child in manifest['children']:
            rows = self.db.execute('SELECT offset,raw FROM open_repair_index_chunks WHERE allocation_id=? AND child_index=? ORDER BY offset',
                (staged['allocation_id'],child['index'])).fetchall()
            offset,parts = 0,[]
            for position,raw in rows:
                if position != offset:
                    _fail('repair_stage_incomplete')
                parts.append(bytes(raw));offset += len(raw)
            ref = wire.raw_ref(child['ref'])
            raw = b''.join(parts)
            if len(raw) != ref.size or budget._hash(raw) != ref.raw_sha256:
                _fail('repair_stage_incomplete')
            result.append(dict(role=child['role'],ref=ref.as_dict(),raw=raw))
        return result

    def _chunk_stamp(self, allocation_id):
        return tuple(tuple(row) for row in self.db.execute('SELECT child_index,offset,digest,raw,response FROM open_repair_index_chunks WHERE allocation_id=? ORDER BY child_index,offset',(allocation_id,)))

    def stage_close(self, entry):
        import memory_vault_open_repair_stage as stage
        budget = wire.RepairBudget(self.policy)
        _,_,p = self._preview(entry,budget)
        staged = self._stage_row(wire.raw_ref(p['intent_ref']).raw_sha256)
        row = self._row(staged['allocation_id'])
        ref,_ = self._caller(entry,row,budget)
        with self._work(row,ref,budget,len(entry['raw'])):
            parents,expected = self._verify_stage_session(staged,budget)
            checked = stage.verify_stage_close(entry,parents['intent'],parents['handle'],**expected)
            stamp = self._chunk_stamp(row['allocation_id'])
            self._complete_children(staged,parents,budget)
            if staged['closed'] is not None:
                if parents['closed'] != entry:
                    _fail('repair_stage_replay_conflict')
                result = parents['result']
                stage.verify_stage_result(result,entry,parents['intent'],parents['handle'],**expected)
                with self._transaction():
                    if self._chunk_stamp(row['allocation_id']) != stamp:
                        _fail('repair_index_generation')
                    self._stage_live_locked(row,staged); self._output_locked(row,result['raw'])
                return result
            result = stage.make_stage_result(entry,parents['intent'],parents['handle'],signer=self.identity,
                expires_at=checked.payload['expires_at'],**expected)
            close_raw,result_raw = (_dump(encode_entry(item)) for item in (entry,result))
            with self._transaction():
                if self._chunk_stamp(row['allocation_id']) != stamp:
                    _fail('repair_index_generation')
                self._stage_live_locked(row,staged)
                self._charge_locked(row,len(close_raw)+len(result_raw))
                self.db.execute('UPDATE open_repair_index_stages SET closed=?,result=? WHERE allocation_id=?',
                    (close_raw,result_raw,row['allocation_id']))
                self._output_locked(row,result.raw)
            return index._entry(result)

    def _admission(self, row, staged, parents, request, budget):
        children = self._complete_children(staged,parents,budget)
        by_role = {}
        resolver = wire.LocalRawResolver(self.policy,budget)
        for child in children:
            by_role.setdefault(child['role'],[]).append(dict(raw=child['raw'],ref=child['ref']))
            if child['role'] == 'history.raw_pack':
                loaded = resolver.put(child['ref']['namespace'],child['ref']['key'],child['raw'])
                if loaded.ref != wire.raw_ref(child['ref']):
                    _fail('repair_ref_mismatch')
        one = lambda role: by_role[role][0]
        allocation,offer = self._stored(row['allocation'],budget),self._stored(row['offer'],budget)
        intent = wire.parse_new_wire(allocation['raw'],self.policy,budget).value['payload']['intent']
        context = _load(row['context'])
        # Recover the exact tuple only from the stored A identity's signed
        # write original named by the independently retained allocation scope.
        draft = history.resolve_historical_inputs(one('index.source_manifest')['raw'],resolver,self.policy,budget)
        writes = []
        def walk(item):
            for role in item.roles:
                if role.role == 'ack.write_grant' and role.original.ref == wire.raw_ref(intent['scope']['grant_ref']):
                    writes.append(role.original)
            for prior in item.predecessors:
                walk(prior)
        walk(draft)
        if not writes or any(item.raw != writes[0].raw for item in writes):
            _fail('repair_index_tuple_missing')
        value = original.parse_original_control(writes[0].raw,self.policy,budget).value
        original._verify_control_signature(value['payload'],value['proof'],context['owner']['signing_key'],budget)
        write = value['payload']
        node_entry = one('provider.node')
        node_doc = wire.parse_new_wire(node_entry['raw'],self.policy,budget).value
        budget._signature_check()
        node = verify_node(dict(node_doc),now=self._now())
        if (node['signing_key'] != context['source']['signing_key'] or node['status'] != 'active'):
            _fail('repair_index_source_node')
        checked = index.verify_ack_index_admission(one('index.source_manifest'),resolver,one('index.source_commit'),
            one('index.source_head'),one('index.provider_fact'),intent,one('index.owner_consent'),one('index.recipient_consent'),
            expected_ack_slot=intent['scope']['ack_slot'],expected_owner=context['owner'],expected_receipt_writer=context['writer'],
            expected_message_id=write['message_id'],expected_envelope_ref=write['envelope_ref'],expected_source=context['source'],
            source_storage_epoch=node['storage_epoch'],expected_directory=self.target,directory_storage_epoch=self.node['payload']['storage_epoch'],
            current_statuses=by_role['current.status'],at=self._now(),limit_policy=self.limits,policy=self.policy,budget=budget,
            allocation_entry=allocation,offer_entry=offer,assignment_entry=one('index.assignment'),publication_request_entry=request,
            directory_statuses=[*by_role['directory.status'],self._stored(row['current_status'],budget)])
        # The three packs are exactly those consumed by this closure. An
        # unreferenced extra pack cannot be used as an undeclared side upload.
        required = set()
        def packs(item):
            required.update(wire.raw_ref(role['pack_ref']) for role in item.manifest.value['roles'])
            for prior in item.predecessors:
                packs(prior)
        packs(draft)
        if required != {wire.raw_ref(item['ref']) for item in by_role['history.raw_pack']}:
            _fail('repair_index_stage_inventory')
        return checked,node_doc

    def _status_records(self, checked, budget):
        source = checked.plan.source
        items = (*source.predecessor.predecessor.statuses,*source.predecessor.statuses,*source.statuses,*checked.statuses)
        records = {}
        for item in items:
            payload = item.payload
            root_digest = budget._hash(wire._canonical(payload['scope_key']['root_key'],budget))
            canonical = getattr(item,'canonical_sha256',None)
            if canonical is None:
                canonical = budget._hash(wire._canonical(wire.parse_new_wire(item.raw,self.policy,budget).value,budget))
            key = (payload['signing_key']['key_id'],root_digest,payload['revision'],canonical,item.ref.raw_sha256)
            records[key] = (key,_dump(encode_entry(item)),payload)
        return tuple(records.values())

    def _observe_locked(self, row, records, root_digest):
        missing = [record for record in records if self._one('SELECT 1 FROM open_repair_index_status_originals WHERE issuer=? AND root_digest=? AND revision=? AND canonical_digest=? AND raw_digest=?',record[0]) is None]
        charge = sum(len(record[1])+ROW_CHARGE for record in missing)
        current = self._row(row['allocation_id'])
        if current['metadata_bytes']+charge > _load(current['budget'])['max_meta_bytes']:
            # This constant marker is included in the initial row envelope.
            # Refusing an authenticated denial must never leave an older fact
            # usable merely because there was no room for its new original.
            self.db.execute('INSERT OR IGNORE INTO open_repair_index_blocked_roots VALUES(?,?)',(root_digest,'repair_index_status_capacity'))
            return 'repair_index_status_capacity'
        self._charge_locked(row,charge)
        code = None
        for key,raw,payload in records:
            issuer,root,revision,canonical,digest = key
            prior = self._one('SELECT canonical_digest FROM open_repair_index_status_originals WHERE issuer=? AND root_digest=? AND revision=? AND canonical_digest!=?',(issuer,root,revision,canonical))
            if prior is not None:
                code = 'repair_status_conflict'
                self.db.execute('UPDATE open_repair_index_floors SET conflict=1 WHERE issuer=? AND root_digest=?',(issuer,root))
            self.db.execute('INSERT OR IGNORE INTO open_repair_index_status_originals VALUES(?,?,?,?,?,?)',(*key,raw))
            conflicted = self._one('SELECT 1 FROM open_repair_index_status_originals WHERE issuer=? AND root_digest=? GROUP BY revision HAVING count(DISTINCT canonical_digest)>1 LIMIT 1',(issuer,root)) is not None
            for item in payload['entries']:
                params = issuer,root,item['scope_kind'],item['scope_id']
                old = self._one('SELECT * FROM open_repair_index_floors WHERE issuer=? AND root_digest=? AND scope_kind=? AND scope_id=?',params)
                revoked = item['operation_mask'] if item['status']=='revoked' else 0
                revision_now = revision
                floor,mask,until = item['minimum_document_revision'],item['operation_mask'],payload['valid_until']
                if old is not None:
                    revoked |= old['revoked_mask'];floor=max(floor,old['minimum_revision'])
                    if revision < old['revision']:
                        revision_now,mask,until = old['revision'],old['operation_mask'],old['valid_until']
                    conflicted = conflicted or bool(old['conflict'])
                self.db.execute('INSERT OR REPLACE INTO open_repair_index_floors VALUES(?,?,?,?,?,?,?,?,?,?)',
                    (*params,revision_now,floor,revoked,mask,until,int(conflicted)))
        return code

    def _floors_allow(self, root_digest, obligations, now):
        blocked = self._one('SELECT reason FROM open_repair_index_blocked_roots WHERE root_digest=?',(root_digest,))
        if blocked is not None:
            return blocked['reason']
        for item in obligations:
            row = self._one('SELECT * FROM open_repair_index_floors WHERE issuer=? AND root_digest=? AND scope_kind=? AND scope_id=?',
                (item['signer']['key_id'],root_digest,item['scope_kind'],item['scope_id']))
            if row is None:
                return 'repair_status_missing'
            if row['conflict']:
                return 'repair_status_conflict'
            if row['revoked_mask'] & item['mask']:
                return 'repair_authority_revoked'
            if row['minimum_revision'] > item['revision']:
                return 'repair_status_revision'
            if row['valid_until'] <= now or row['operation_mask'] & item['mask'] != item['mask']:
                return 'repair_status_operation'
        return None

    def _current_floors_allow(self, root_digest, checked):
        observed={}
        for item in checked.statuses:
            issuer=item.payload['signing_key']['key_id']
            for entry in item.payload['entries']:
                key=(issuer,entry['scope_kind'],entry['scope_id'])
                observed[key]=max(observed.get(key,0),item.payload['revision'])
        for need in checked.obligations:
            key=(need['signer']['key_id'],need['scope_kind'],need['scope_id'])
            row=self._one('SELECT revision FROM open_repair_index_floors WHERE issuer=? AND root_digest=? AND scope_kind=? AND scope_id=?',
                (key[0],root_digest,key[1],key[2]))
            if row is None or observed.get(key,0)<row['revision']:
                return 'repair_status_rollback'
        return None

    def accept(self, entry):
        import memory_vault_open_repair_stage as stage
        budget = wire.RepairBudget(self.policy)
        _,_,p = self._preview(entry,budget)
        reference = wire.raw_ref(p['allocation_request_ref'])
        row = self._one('SELECT * FROM open_repair_index_resources WHERE digest=?',(reference.raw_sha256,))
        if row is None:
            _fail('repair_index_allocation_missing')
        ref,_ = self._caller(entry,row,budget)
        with self._work(row,ref,budget,len(entry['raw'])):
            staged = self._one('SELECT * FROM open_repair_index_stages WHERE allocation_id=?',(row['allocation_id'],))
            if staged is None or staged['result'] is None:
                _fail('repair_stage_incomplete')
            parents,expected = self._verify_stage_session(staged,budget)
            result = stage.verify_stage_result(parents['result'],parents['closed'],parents['intent'],parents['handle'],**expected)
            if result.ref != wire.raw_ref(p['stage_result_ref']):
                _fail('repair_index_stage_mismatch')
            stamp = self._chunk_stamp(row['allocation_id'])
            checked,node = self._admission(row,staged,parents,entry,budget)
            records = self._status_records(checked,budget)
            plan,fact = checked.plan,checked.plan.fact
            fp = fact.payload
            root_digest = budget._hash(wire._canonical(plan.intent['root_key'],budget))
            fact_key = budget._hash(wire._canonical(dict(ref=fp['ref'],provider_key_id=fp['signing_key']['key_id'],
                storage_epoch=fp['storage_epoch'],custody_id=fp['custody_id']),budget))
            fact_doc = wire.parse_new_wire(fact.raw,self.policy,budget).value
            fact_digest = budget._hash(wire._canonical(fact_doc,budget))
            expires = min(checked.publish_until,node['payload']['expires_at'],self.node['payload']['expires_at'])
            now = self._now()
            if expires <= now:
                _fail('repair_index_expired')
            payload = dict(schema_version=provider.PROFILE,kind='provider.index_lease',signing_key=self.identity.public_descriptor(),
                issued_at=now,expires_at=expires,node_key_id=self.identity.key_id,storage_epoch=self.node['payload']['storage_epoch'],
                index_lease_id='index_'+ref.raw_sha256,fact_sha256=fact_digest,ref=fp['ref'],provider_key_id=fp['signing_key']['key_id'],
                provider_storage_epoch=fp['storage_epoch'],custody_id=fp['custody_id'])
            lease = dict(payload=payload,proof=self.identity.sign_message(payload))
            lease_raw,node_raw = _dump(lease),_dump(node)
            request_raw = _dump(encode_entry(entry))
            obligations_raw = _dump([dict(item) for item in checked.obligations])
            code = checked.denial_code
            from memory_vault_open_provider_merge import REPAIR, observe_cross_fact
            def cross_fact():
                refusal = observe_cross_fact(self.db, REPAIR, key=fact_key, revision=fp['revision'],
                    digest=fact_digest, raw=fact.raw)
                return 'repair_index_fact_' + refusal if refusal is not None else None
            # Authenticated observations commit separately. A subsequent lease
            # metadata/response failure may refuse publication but cannot undo
            # a revocation/floor learned while verifying that same request.
            with self._transaction() as locked_now:
                self._stage_live_locked(row,staged)
                if self._chunk_stamp(row['allocation_id']) != stamp:
                    _fail('repair_index_generation')
                code = self._observe_locked(row,records,root_digest) or code
                code = code or self._floors_allow(root_digest,checked.obligations,locked_now)
                code = code or self._current_floors_allow(root_digest,checked)
                code = code or cross_fact()
            if code is not None:
                _fail(code)
            with self._transaction() as locked_now:
                self._stage_live_locked(row,staged)
                if self._chunk_stamp(row['allocation_id']) != stamp or not self._directory_live(locked_now):
                    _fail('repair_index_generation')
                code = self._floors_allow(root_digest,checked.obligations,locked_now)
                code = code or self._current_floors_allow(root_digest,checked)
                code = code or cross_fact()
                old = self._one('SELECT * FROM open_repair_index_facts WHERE fact_key=?',(fact_key,))
                if old is not None:
                    if old['status'] != 'active':
                        code = code or 'repair_index_fact_inactive'
                    elif fp['revision'] < old['revision']:
                        code = code or 'repair_index_fact_rollback'
                    elif fp['revision']==old['revision'] and fact_digest != old['digest']:
                        charge=len(fact.raw) if old['second_record'] is None else 0
                        current=self._row(row['allocation_id'])
                        if current['metadata_bytes']+charge>_load(current['budget'])['max_meta_bytes']:
                            self.db.execute('INSERT OR IGNORE INTO open_repair_index_blocked_roots VALUES(?,?)',(root_digest,'repair_index_fact_capacity'))
                        else:
                            self._charge_locked(row,charge)
                            self.db.execute("UPDATE open_repair_index_facts SET second_record=coalesce(second_record,?),status='conflict' WHERE fact_key=?",(fact.raw,fact_key))
                        code = code or 'repair_index_fact_conflict'
                    elif old['allocation_id'] != row['allocation_id'] or old['request_digest'] != ref.raw_sha256 or bytes(old['request']) != request_raw:
                        code = code or 'repair_index_replay_conflict'
                    else:
                        lease_raw = bytes(old['index_lease'])
                        if old['expires_at'] <= locked_now:
                            code = code or 'repair_index_expired'
                if code is None:
                    if old is None:
                        self._charge_locked(row,len(fact.raw)+len(node_raw)+len(lease_raw)+len(request_raw)+len(obligations_raw)+ROW_CHARGE)
                        self.db.execute('INSERT INTO open_repair_index_facts VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL)',
                            (fact_key,fp['ref']['namespace'],fp['ref']['key'],fp['signing_key']['key_id'],fp['revision'],fact_digest,fact.raw,
                             node_raw,lease_raw,row['allocation_id'],request_raw,ref.raw_sha256,obligations_raw,root_digest,expires,'active'))
                        self.db.execute("UPDATE open_repair_index_resources SET state='active' WHERE allocation_id=?",(row['allocation_id'],))
                    self._output_locked(row,lease_raw)
            if code is not None:
                _fail(code)
            return json.loads(lease_raw)

    def lookup_candidates(self, ref, after=None, limit=33, at=None):
        """No crypto/writer nesting: a provider.get transaction calls this."""
        self._binding()
        now = self._now() if at is None else wire.u53(at)
        if not 1 <= limit <= 33:
            _fail('repair_index_lookup_limit')
        cursor = self.db.execute('SELECT * FROM open_repair_index_facts WHERE namespace=? AND opaque_key=? AND fact_key>? ORDER BY fact_key LIMIT ?',
            (ref['namespace'],ref['key'],after or '',limit))
        result = []
        for values in cursor.fetchall():
            row = dict(zip((column[0] for column in cursor.description),values))
            resource_row = self._row(row['allocation_id'])
            row['eligible'] = not (not self._directory_live(now) or row['status'] != 'active' or resource_row['state'] != 'active' or row['expires_at'] <= now
                    or now >= _load(resource_row['windows'])['retain_until']
                    or self._floors_allow(row['root_digest'],_load(row['obligations']),now) is not None)
            result.append(row)
        return result

    def lookup(self, ref, after=None, limit=33):
        with self._lock:
            rows = self.lookup_candidates(ref,after,limit)
            return [dict(fact=_load(row['record']),index_lease=_load(row['index_lease']),node=_load(row['node']),fact_key=row['fact_key']) for row in rows if row['eligible']]
