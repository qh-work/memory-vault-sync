"""Local preparation and independent signing for one ACK directory publication.

No network or initial source allocation is performed here. Exported bundles are
private originals, not permission to disclose them to another party. A and B
must independently hold the expected tuple and use only their own identity.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import time
from types import SimpleNamespace

from memory_vault import canonical_bytes
from memory_vault_open_control import verify_node
import memory_vault_open_provider as provider
import memory_vault_open_repair_access as access
import memory_vault_open_repair_empty as empty
import memory_vault_open_repair_index as index
from memory_vault_open_repair_index_access import AckIndexSourceAccess
from memory_vault_open_repair_index_journal import AckIndexJournal
import memory_vault_open_repair_occupied as occupied
import memory_vault_open_repair_original as original
import memory_vault_open_repair_probe as probe
import memory_vault_open_repair_resource as resource
from memory_vault_open_repair_state import DEFAULT_POLICY, INDEX_WORKFLOW_LIMITS, ROW_CHARGE
import memory_vault_open_repair_status as status
import memory_vault_open_repair_wire as wire

BUNDLE_SCHEMA = 'memory-vault-open-ack-index-preparation/v1'
CONSENT_SCHEMA = 'memory-vault-open-ack-index-signed-consent/v1'
REQUEST_SCHEMA = 'memory-vault-open-ack-index-publication-request/v1'
EXPECTED_FIELDS = frozenset(('expected_ack_slot', 'expected_owner', 'expected_receipt_writer',
    'expected_message_id', 'expected_envelope_ref', 'expected_source', 'source_storage_epoch',
    'expected_directory', 'directory_storage_epoch'))
BUNDLE_FIELDS = frozenset(('schema_version', 'resource_id', 'expected', 'directory_node',
    'manifest', 'commit', 'head', 'packs', 'fact', 'intent', 'current_statuses', 'inventory'))
MAX_LOCAL_RECORDS = 32
MAX_LOCAL_BYTES = 2 * 1024 * 1024


def _fail(code='repair_index_preparation_mismatch'):
    wire._fail(code)


def _entry(raw):
    digest = hashlib.sha256(raw).hexdigest()
    return dict(raw=raw, ref=dict(namespace='meta', key=digest, raw_sha256=digest, size=len(raw)))


def _signed_entry(payload, signer, policy, budget):
    return index._entry(probe._sign(_snapshot(payload, policy, budget), signer, policy, budget))


def _encoded(entry, budget):
    return dict(ref=entry['ref'], raw_base64url=probe._encode(entry['raw'], budget))


def _decoded(value, policy, budget):
    wire.object_fields(value, {'ref', 'raw_base64url'})
    ref = wire.raw_ref(value['ref'])
    if ref.size > policy.max_document_bytes:
        _fail('repair_over_budget')
    raw = original._decode64(value['raw_base64url'], ref.size, budget, url=True)
    if len(raw) != ref.size or budget._hash(raw) != ref.raw_sha256:
        _fail('repair_ref_mismatch')
    return dict(raw=raw, ref=ref.as_dict())


def _directory_budget(value):
    resource._budget(value)
    if (value['max_live_bytes']!=0 or not 1<=value['max_items']<=64
            or not ROW_CHARGE*4<=value['max_meta_bytes']<=2*1024*1024
            or value['max_requests']<1 or value['max_replay_records']<1):
        _fail('repair_index_allocation_mismatch')


def _snapshot(value, policy, budget):
    return wire.build_new_wire(value, policy, budget).value


def _source_options(expected, limit_policy, policy, budget):
    wire.object_fields(expected, EXPECTED_FIELDS)
    return dict(expected_ack_slot=expected['expected_ack_slot'], expected_owner=expected['expected_owner'],
        expected_receipt_writer=expected['expected_receipt_writer'], expected_message_id=expected['expected_message_id'],
        expected_envelope_ref=expected['expected_envelope_ref'], expected_target=expected['expected_source'],
        target_storage_epoch=expected['source_storage_epoch'], limit_policy=limit_policy, policy=policy, budget=budget)


def _history(source):
    return (*source.predecessor.predecessor.statuses, *source.predecessor.statuses, *source.statuses)


def _base(source, head, expected, current, at, policy, budget):
    prior = source.predecessor.predecessor
    root, active = (prior.resources.originals[name] for name in ('root', 'active'))
    slot, key = root.payload['ack_slot'], root.payload['ack_slot']['root_key']
    publisher = resource._dual_key(expected['expected_source'], budget)
    resource._dual_key(expected['expected_directory'], budget)
    if (publisher == resource._dual_key(expected['expected_directory'], budget)
            or publisher not in root.payload['maintainers'] or root.payload['operation_mask'] & 16 != 16):
        _fail('repair_ack_index_mismatch')
    until = min(source.read_until, source.retain_until, root.payload['expires_at'],
        root.payload['windows']['publish_until'], active.payload['windows']['publish_until'],
        source.inputs['disclosure'].payload['consent_until'])
    if not at < until:
        _fail('repair_access_expired')
    rows = index.source_original_inventory(source, head, policy=policy, budget=budget)
    allowed, signers = {}, {}
    for name in ('expected_owner', 'expected_receipt_writer', 'expected_source'):
        signer = expected[name]['signing_key']
        _, scopes = index._permissions(rows, signer['key_id'], policy, budget)
        allowed[signer['key_id']], signers[signer['key_id']] = scopes, signer
    obligations = [
        index._obligation(expected['expected_owner']['signing_key'], 'authority', index._authority(key, root, policy, budget), root.payload['revision'], 16),
        index._obligation(expected['expected_owner']['signing_key'], 'ack_slot', status.status_scope(key, 'ack_slot', slot, policy, budget), root.payload['revision'], 16),
        index._obligation(expected['expected_receipt_writer']['signing_key'], 'authority', index._authority(key, source.inputs['disclosure'], policy, budget), source.inputs['disclosure'].payload['revision'], 64),
        index._obligation(expected['expected_source']['signing_key'], 'resource', status.status_scope(key, 'resource', active.payload['resource'], policy, budget), active.payload['reservation_generation'], 80)]
    statuses, code = index._current(current, signers=signers, allowed=allowed, obligations=obligations,
        root=key, previous=_history(source), at=at, policy=policy, budget=budget)
    return SimpleNamespace(source=source, head=head, root=root, active=active, rows=rows,
        statuses=statuses, obligations=obligations, code=code,
        until=min(until, *(item.payload['valid_until'] for item in statuses)), allowed=allowed)


def _directory(entry, expected, at, policy, budget):
    ref = wire.raw_ref(entry['ref'])
    parsed = wire.parse_new_wire(entry['raw'], policy, budget)
    if ref.namespace != 'meta' or ref.size != len(parsed.raw) or budget._hash(parsed.raw) != ref.raw_sha256:
        _fail('repair_ref_mismatch')
    budget._signature_check()
    node = verify_node(parsed.raw, now=at)
    if (node['signing_key'] != expected['expected_directory']['signing_key']
            or node['storage_epoch'] != expected['directory_storage_epoch']
            or node['status'] != 'active' or 'directory' not in node['roles']):
        _fail('repair_wrong_node')
    return node


def _unpack_bundle(bundle, expected, policy, budget):
    value = _snapshot(bundle, policy, budget)
    wire.object_fields(value, BUNDLE_FIELDS)
    expected = _snapshot(expected, policy, budget)
    wire.object_fields(expected, EXPECTED_FIELDS)
    if value['schema_version'] != BUNDLE_SCHEMA or value['expected'] != expected:
        _fail()
    resource._opaque(value['resource_id'])
    if type(value['packs']) is not wire._DraftList or len(value['packs']) != 3:
        _fail('repair_unused_pack')
    resolver = wire.LocalRawResolver(policy, budget)
    seen = set()
    for encoded in value['packs']:
        item = _decoded(encoded, policy, budget)
        ref = wire.raw_ref(item['ref'])
        if ref in seen or ref.namespace != 'meta' or resolver.put(ref.namespace, ref.key, item['raw']).ref != ref:
            _fail('repair_unused_pack')
        seen.add(ref)
    entries = {name: _decoded(value[name], policy, budget) for name in ('manifest', 'commit', 'head', 'fact', 'directory_node')}
    return value, expected, resolver, entries, seen


def _verify_bundle(bundle, expected, at, limit_policy, policy, budget):
    value, expected, resolver, entries, seen = _unpack_bundle(bundle, expected, policy, budget)
    source = occupied.verify_ack_occupied_source_event(entries['manifest'], resolver, entries['commit'],
        **_source_options(expected, limit_policy, policy, budget))
    head = occupied.verify_ack_occupied_head(entries['head'], source, expected_target=expected['expected_source'], policy=policy, budget=budget)
    used = {wire.raw_ref(item['pack_ref']) for manifest in (source.manifest, source.predecessor.manifest,
        source.predecessor.predecessor.manifest) for item in manifest.manifest.value['roles']}
    if seen != used:
        _fail('repair_unused_pack')
    if type(value['current_statuses']) is not wire._DraftList or not 1 <= len(value['current_statuses']) <= 16:
        _fail('repair_status_missing')
    base = _base(source, head, expected, [_decoded(item, policy, budget) for item in value['current_statuses']], at, policy, budget)
    if value['inventory'] != [dict(role=item.role, ref=item.original.ref.as_dict(), issuer=item.issuer) for item in base.rows]:
        _fail('repair_index_inventory_mismatch')
    directory = _directory(entries['directory_node'], expected, at, policy, budget)
    fact = index._signed(entries['fact'], expected['expected_source']['signing_key'], 'provider.fact',
        provider.COMMON | provider.KINDS['provider.fact'], policy, budget, schema=provider.PROFILE)
    index._timed(fact.payload, at)
    if (fact.payload['ref'] != base.root.payload['ack_slot']['root_key']['anchor_ref']
            or fact.payload['storage_epoch'] != expected['source_storage_epoch']
            or fact.payload['status'] != 'active' or fact.payload['custody_id'] != 'ack_' + source.commit.ref.raw_sha256
            or len(fact.raw) > provider.CAPS['provider.fact']
            or fact.payload['expires_at'] - fact.payload['issued_at'] > provider.MAX_FACT_SECONDS):
        _fail('repair_ack_index_mismatch')
    wire.u53(fact.payload['revision'], 1)
    intent = value['intent']
    wire.object_fields(intent, index.INTENT_FIELDS)
    scope = dict(kind='ack_occupied', ack_slot=expected['expected_ack_slot'], grant_ref=source.commit.payload['grant_ref'],
        binding_ref=source.commit.payload['binding_ref'], receipt_ref=source.commit.payload['receipt_ref'], original_ack_commit_ref=source.commit.ref.as_dict())
    if (intent['kind'] != 'resource.index_intent' or intent['purpose'] != 'provider_index'
            or intent['root_key'] != base.root.payload['ack_slot']['root_key'] or intent['caller'] != expected['expected_source']
            or intent['target'] != expected['expected_directory'] or intent['target_storage_epoch'] != expected['directory_storage_epoch']
            or intent['scope'] != scope or intent['advertised_custody_ref'] != source.commit.ref.as_dict()
            or intent['historical_manifest_ref'] != source.commit.payload['historical_manifest_ref']
            or intent['provider_fact_ref'] != fact.ref.as_dict()):
        _fail('repair_ack_index_mismatch')
    for name in ('allocation_id', 'job_id'):
        resource._opaque(intent[name])
    _directory_budget(intent['budget']); resource._windows(intent['windows'], issued=at)
    if (intent['budget']['max_live_bytes'] != 0
            or any(intent['budget'][name] > base.root.payload['budget'][name] for name in resource._BUDGET)
            or any(intent['windows'][name] > base.root.payload['windows'][name] for name in resource._WINDOWS)):
        _fail('repair_ack_index_mismatch')
    base.until = min(base.until, fact.payload['expires_at'], intent['windows']['publish_until'], directory['expires_at'])
    base.value, base.entries, base.expected, base.resolver, base.fact = value, entries, expected, resolver, fact
    return base


class AckIndexPlanPreparer:
    """An explicit local source-operator API; it never sends this private bundle."""
    def __init__(self, source_state, *, clock=None):
        self.state, self.db, self.policy = source_state, source_state.db, source_state.policy
        self.clock = clock or source_state.clock
        self.gate = AckIndexSourceAccess(source_state)
        self.gate.initialize()
        with self.state._transaction():
            self.db.execute('''CREATE TABLE IF NOT EXISTS open_repair_index_prepare_exports(
                resource_id TEXT NOT NULL,job_id TEXT NOT NULL,request_digest TEXT NOT NULL,
                issued_at INTEGER NOT NULL,fact_revision INTEGER NOT NULL,raw BLOB,
                PRIMARY KEY(resource_id,job_id))''')

    def _refuse_existing_fact(self, commit_ref, anchor, epoch, policy, meter):
        # This narrow API starts one new publication. It cannot safely guess
        # the next fact revision of another publisher's existing session.
        custody='ack_'+commit_ref.raw_sha256
        key=hashlib.sha256(canonical_bytes(dict(ref=anchor,provider_key_id=self.state.identity.key_id,
            storage_epoch=epoch,custody_id=custody))).hexdigest()
        for table in ('open_provider_local_floors','open_provider_facts','open_repair_index_facts'):
            if _table(self.db,table) and self.db.execute('SELECT 1 FROM '+table+' WHERE fact_key=?',(key,)).fetchone():
                _fail('repair_index_existing_fact')
        if _table(self.db,'open_provider_local'):
            rows=self.db.execute("SELECT body FROM open_provider_local WHERE category='publish' LIMIT 33").fetchall()
            if len(rows)>32: _fail('repair_index_preparation_capacity')
            for (raw,) in rows:
                value=wire.parse_new_wire(bytes(raw),policy,meter).value
                p=value.get('body',{}).get('fact',{}).get('payload',{})
                if (p.get('ref')==anchor and p.get('signing_key',{}).get('key_id')==self.state.identity.key_id
                        and p.get('storage_epoch')==epoch and p.get('custody_id')==custody):
                    _fail('repair_index_existing_fact')

    def export(self, resource_id, *, expected_directory, directory_node_entry, allocation_id, job_id,
               budget_limits, windows, current_statuses=None):
        policy, meter = self.policy, wire.RepairBudget(self.policy)
        now = wire.u53(int(self.clock()))
        automatic_statuses = current_statuses is None
        with AckIndexJournal(self.state).preparation_work(resource_id, meter):
            with self.state._lock:
                row, stamp, pins = self.gate._snapshot(resource_id)
                saved = tuple(self.db.execute('''SELECT DISTINCT d.raw,d.ref FROM open_repair_access_floors f
                    JOIN open_repair_access_documents d ON d.resource_id=f.resource_id AND d.issuer=f.issuer
                    AND d.revision=f.revision AND d.digest=f.digest WHERE f.resource_id=?
                    ORDER BY d.issuer,d.revision,d.digest''', (resource_id,)))
            roles, entries, packs = {}, {}, []
            resolver = wire.LocalRawResolver(policy, meter)
            for role, ns, key, digest, size, raw in (*pins, *stamp[5]):
                body = wire._snapshot(bytes(raw), policy, meter); ref = wire.RawRef(ns,key,digest,size)
                if len(body) != size or meter._hash(body) != digest:
                    _fail('repair_storage_corrupt')
                item = dict(raw=body, ref=ref.as_dict())
                entries[ref] = item; roles.setdefault(role, []).append(item)
                if role in ('pack','empty:pack','occupied:pack'):
                    resolver.put(ns,key,body); packs.append(item)
            def stored_ref(raw):
                return entries[wire.raw_ref(wire.parse_new_wire(bytes(raw),policy,meter).value)]
            binding, committed = dict(stamp[1]), dict(stamp[3])
            write = original.parse_original_control(roles['empty:ack.write_grant'][0]['raw'],policy,meter).value['payload']
            root = original.parse_original_control(roles['ack.root_authority'][0]['raw'],policy,meter).value['payload']
            expected = dict(expected_ack_slot=root['ack_slot'], expected_owner=json.loads(bytes(row['owner_keys'])),
                expected_receipt_writer=json.loads(bytes(binding['writer_keys'])), expected_message_id=write['message_id'],
                expected_envelope_ref=write['envelope_ref'], expected_source=self.state.target,
                source_storage_epoch=self.state.node['payload']['storage_epoch'], expected_directory=expected_directory,
                directory_storage_epoch=wire.parse_new_wire(directory_node_entry['raw'],policy,meter).value['payload']['storage_epoch'])
            expected = _snapshot(expected,policy,meter)
            manifest, commit, head_entry = (stored_ref(committed[name+'_ref']) for name in ('manifest','commit','head'))
            source = occupied.verify_ack_occupied_source_event(manifest,resolver,commit,**_source_options(expected,self.state.limits,policy,meter))
            head = occupied.verify_ack_occupied_head(head_entry,source,expected_target=self.state.target,policy=policy,budget=meter)
            self.gate._validate_source(row,stamp,roles,SimpleNamespace(source=source),expected['expected_receipt_writer'],policy,meter)
            if current_statuses is None:
                rows = index.source_original_inventory(source,head,policy=policy,budget=meter)
                permitted = {key:index._permissions(rows,key,policy,meter)[1] for key in
                    (expected[name]['signing_key']['key_id'] for name in ('expected_owner','expected_receipt_writer','expected_source'))}
                candidates = [dict(raw=bytes(raw),ref=json.loads(bytes(ref))) for raw,ref in saved]
                candidates += [index._entry(item) for item in _history(source)]
                selected = {}
                for item in candidates:
                    p = original.parse_original_control(item['raw'],policy,meter).value['payload']; issuer=p['signing_key']['key_id']
                    scopes={(e['scope_kind'],e['scope_id']) for e in p['entries']}
                    allow={(e['scope_kind'],e['scope_id']) for e in permitted.get(issuer,())}
                    if scopes <= allow:
                        for scope in scopes:
                            key=(issuer,*scope)
                            if key not in selected or p['revision']>selected[key][0]: selected[key]=(p['revision'],item)
                current_statuses=list({wire.raw_ref(item['ref']):item for _,item in selected.values()}.values())
            base=_base(source,head,expected,current_statuses,now,policy,meter)
            prepared=access._Preparation()
            self.gate._prepared[prepared]=dict(resource_id=resource_id,stamp=stamp,pins=pins,action='index.prepare',
                root_digest=meter._hash(wire._canonical(root['ack_slot']['root_key'],meter)),
                obligations=tuple(dict(item,role='current.status') for item in base.obligations),statuses=base.statuses,
                status_refs={item.canonical_sha256:wire._canonical(item.ref.as_dict(),meter) for item in base.statuses},
                basis=(),expected_generation=None,expires=base.until,code=base.code,subject=self.state.target,
                selector=dict(kind='ack_occupied'),grant_ref=base.root.ref,limits=self.state.limits,
                capacity=base.active.payload['budget'],checked=False,proof=())
            def guard():
                decision=self.gate.check_locked(prepared)
                return decision.code
            with self.state._transaction(): code=guard()
            if code: _fail(code)
            node=_directory(directory_node_entry,expected,now,policy,meter)
            options=_snapshot(dict(directory=expected_directory,node=_encoded(directory_node_entry,meter),allocation_id=allocation_id,
                job_id=job_id,budget=budget_limits,windows=windows,current=[_encoded(index._entry(i),meter) for i in base.statuses]),policy,meter)
            resource._opaque(allocation_id); resource._opaque(job_id)
            _directory_budget(options['budget']); resource._windows(options['windows'],issued=now)
            if (options['budget']['max_live_bytes'] != 0 or any(options['budget'][n]>base.root.payload['budget'][n] for n in resource._BUDGET)
                    or any(options['windows'][n]>base.root.payload['windows'][n] for n in resource._WINDOWS)):
                _fail('repair_ack_index_mismatch')
            request_digest=meter._hash(wire.build_new_wire(dict(options,current=None if automatic_statuses else options['current']),policy,meter).raw)
            with self.state._transaction():
                code=guard()
                if code is None:
                    saved=self.state._one('SELECT * FROM open_repair_index_prepare_exports WHERE resource_id=? AND job_id=?',(resource_id,job_id))
                    if saved is not None and saved['request_digest']!=request_digest: _fail('repair_index_job_conflict')
                    execution=self.state._one('SELECT plan FROM open_repair_index_execution WHERE resource_id=?',(resource_id,))
                    if execution is not None:
                        if saved is None or saved['raw'] is None: _fail('repair_index_job_conflict')
                        previous=json.loads(bytes(saved['raw'])); semantic=json.loads(bytes(execution['plan']))['semantic']
                        if (semantic['intent']!=previous['intent'] or semantic['provider_fact']!=previous['fact']
                                or semantic['expected_directory']!=previous['expected']['expected_directory']):
                            _fail('repair_index_job_conflict')
                    if saved is None or saved['raw'] is None:
                        self._refuse_existing_fact(source.commit.ref,root['ack_slot']['root_key']['anchor_ref'],expected['source_storage_epoch'],policy,meter)
                    if saved is None:
                        if self.db.execute('SELECT count(*) FROM open_repair_index_prepare_exports WHERE resource_id=?',(resource_id,)).fetchone()[0]>=MAX_LOCAL_RECORDS:
                            _fail('repair_index_preparation_capacity')
                        live=self.state._row(resource_id)
                        if live['metadata_bytes']+ROW_CHARGE>base.active.payload['budget']['max_meta_bytes']: _fail('repair_index_preparation_capacity')
                        revision=self.db.execute('SELECT coalesce(max(fact_revision),0)+1 FROM open_repair_index_prepare_exports WHERE resource_id=?',(resource_id,)).fetchone()[0]
                        self.db.execute('INSERT INTO open_repair_index_prepare_exports VALUES(?,?,?,?,?,NULL)',(resource_id,job_id,request_digest,now,revision))
                        self.db.execute('UPDATE open_repair_ack_resources SET metadata_bytes=metadata_bytes+? WHERE resource_id=?',(ROW_CHARGE,resource_id))
                        saved=dict(issued_at=now,fact_revision=revision,raw=None)
            if code: _fail(code)
            if saved['raw'] is not None:
                value=wire.parse_new_wire(bytes(saved['raw']),policy,meter).value
                wire.object_fields(value,BUNDLE_FIELDS)
                if (value['schema_version']!=BUNDLE_SCHEMA or value['resource_id']!=resource_id or value['expected']!=expected
                        or value['manifest']!=_encoded(manifest,meter) or value['commit']!=_encoded(commit,meter)
                        or value['head']!=_encoded(head_entry,meter) or value['packs']!=[_encoded(p,meter) for p in packs]
                        or value['directory_node']!=options['node']
                        or value['inventory']!=[dict(role=item.role,ref=item.original.ref.as_dict(),issuer=item.issuer) for item in base.rows]):
                    _fail('repair_storage_corrupt')
                fact=index._signed(_decoded(value['fact'],policy,meter),self.state.target['signing_key'],'provider.fact',
                    provider.COMMON|provider.KINDS['provider.fact'],policy,meter,schema=provider.PROFILE)
                index._timed(fact.payload,now)
                if (fact.payload['revision']!=saved['fact_revision'] or fact.payload['issued_at']!=saved['issued_at']
                        or fact.payload['status']!='active' or fact.payload['storage_epoch']!=expected['source_storage_epoch']
                        or fact.payload['ref']!=root['ack_slot']['root_key']['anchor_ref']
                        or fact.payload['custody_id']!='ack_'+source.commit.ref.raw_sha256
                        or fact.payload['expires_at']-fact.payload['issued_at']>provider.MAX_FACT_SECONDS):
                    _fail('repair_storage_corrupt')
                intent=value['intent']; wire.object_fields(intent,index.INTENT_FIELDS)
                wanted=dict(kind='resource.index_intent',allocation_id=allocation_id,job_id=job_id,root_key=root['ack_slot']['root_key'],
                    caller=self.state.target,target=expected_directory,target_storage_epoch=expected['directory_storage_epoch'],purpose='provider_index',
                    scope=dict(kind='ack_occupied',ack_slot=expected['expected_ack_slot'],grant_ref=source.commit.payload['grant_ref'],
                        binding_ref=source.commit.payload['binding_ref'],receipt_ref=source.commit.payload['receipt_ref'],original_ack_commit_ref=source.commit.ref.as_dict()),
                    advertised_custody_ref=source.commit.ref.as_dict(),provider_fact_ref=fact.ref.as_dict(),historical_manifest_ref=source.commit.payload['historical_manifest_ref'],
                    budget=options['budget'],windows=options['windows'])
                if intent!=wanted: _fail('repair_storage_corrupt')
                cached=_base(source,head,expected,[_decoded(item,policy,meter) for item in value['current_statuses']],now,policy,meter)
                if cached.code: _fail(cached.code)
                with self.state._transaction(): code=guard()
                if code: _fail(code)
                return json.loads(bytes(saved['raw']))
            issued=saved['issued_at']; until=min(base.until,node['expires_at'],windows['publish_until'],issued+provider.MAX_FACT_SECONDS)
            if not now<until: _fail('repair_access_expired')
            fact_payload=dict(schema_version=provider.PROFILE,kind='provider.fact',signing_key=self.state.identity.public_descriptor(),
                ref=root['ack_slot']['root_key']['anchor_ref'],storage_epoch=expected['source_storage_epoch'],custody_id='ack_'+source.commit.ref.raw_sha256,
                revision=saved['fact_revision'],status='active',issued_at=issued,expires_at=until)
            fact=_signed_entry(fact_payload,self.state.identity,policy,meter)
            scope=dict(kind='ack_occupied',ack_slot=expected['expected_ack_slot'],grant_ref=source.commit.payload['grant_ref'],
                binding_ref=source.commit.payload['binding_ref'],receipt_ref=source.commit.payload['receipt_ref'],original_ack_commit_ref=source.commit.ref.as_dict())
            intent=dict(kind='resource.index_intent',allocation_id=allocation_id,job_id=job_id,root_key=root['ack_slot']['root_key'],
                caller=self.state.target,target=expected_directory,target_storage_epoch=expected['directory_storage_epoch'],purpose='provider_index',scope=scope,
                advertised_custody_ref=source.commit.ref.as_dict(),provider_fact_ref=fact['ref'],historical_manifest_ref=source.commit.payload['historical_manifest_ref'],
                budget=options['budget'],windows=options['windows'])
            value=dict(schema_version=BUNDLE_SCHEMA,resource_id=resource_id,expected=expected,directory_node=_encoded(directory_node_entry,meter),
                manifest=_encoded(manifest,meter),commit=_encoded(commit,meter),head=_encoded(head_entry,meter),packs=[_encoded(p,meter) for p in packs],
                fact=_encoded(fact,meter),intent=intent,current_statuses=options['current'],
                inventory=[dict(role=item.role,ref=item.original.ref.as_dict(),issuer=item.issuer) for item in base.rows])
            raw=wire.build_new_wire(value,policy,meter).raw
            with self.state._transaction():
                code=guard()
                if code is None:
                    live=self.state._row(resource_id)
                    old=self.state._one('SELECT raw FROM open_repair_index_prepare_exports WHERE resource_id=? AND job_id=?',(resource_id,job_id))
                    if old['raw'] is None:
                        if self.db.execute('SELECT 1 FROM open_repair_index_execution WHERE resource_id=?',(resource_id,)).fetchone(): _fail('repair_index_job_conflict')
                        self._refuse_existing_fact(source.commit.ref,root['ack_slot']['root_key']['anchor_ref'],expected['source_storage_epoch'],policy,meter)
                    if old['raw'] is not None:
                        if bytes(old['raw'])!=raw: _fail('repair_index_job_conflict')
                    elif live['metadata_bytes']+len(raw)>base.active.payload['budget']['max_meta_bytes']: _fail('repair_index_preparation_capacity')
                    else:
                        self.db.execute('UPDATE open_repair_index_prepare_exports SET raw=? WHERE resource_id=? AND job_id=?',(raw,resource_id,job_id))
                        self.db.execute('UPDATE open_repair_ack_resources SET metadata_bytes=metadata_bytes+? WHERE resource_id=?',(len(raw),resource_id))
            if code: _fail(code)
            return json.loads(raw)


def _table(db, name):
    return db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None


class AckIndexConsentSigner:
    """Use this principal's existing protected transport DB and its own two keys."""
    def __init__(self, identity, encryption_identity, protected_db, *, policy=DEFAULT_POLICY,
                 limit_policy=INDEX_WORKFLOW_LIMITS, clock=None):
        self.identity, self.encryption, self.db = identity, encryption_identity, protected_db
        self.policy, self.limits, self.clock = policy, limit_policy, clock or time.time
        self.subject = dict(signing_key=identity.public_descriptor(), encryption_key=encryption_identity.public_descriptor())
        with self._transaction():
            for sql in (
                'CREATE TABLE IF NOT EXISTS open_repair_index_signer_meta(name TEXT PRIMARY KEY,value TEXT NOT NULL)',
                '''CREATE TABLE IF NOT EXISTS open_repair_index_consent_outputs(
                    request_digest TEXT PRIMARY KEY,root_digest TEXT NOT NULL,issued_at INTEGER NOT NULL,
                    revisions BLOB NOT NULL,raw BLOB)''',
                '''CREATE TABLE IF NOT EXISTS open_repair_index_signer_statuses(
                    root_digest TEXT NOT NULL,issuer TEXT NOT NULL,revision INTEGER NOT NULL,
                    digest TEXT NOT NULL,raw BLOB NOT NULL,ref BLOB NOT NULL,
                    PRIMARY KEY(root_digest,issuer,revision,digest))''',
                'CREATE TABLE IF NOT EXISTS open_provider_client_meta(name TEXT PRIMARY KEY,value TEXT NOT NULL)',
                'CREATE TABLE IF NOT EXISTS open_provider_state(name TEXT PRIMARY KEY,value TEXT NOT NULL)',
                'CREATE TABLE IF NOT EXISTS open_repair_saved_ack_roots(root_digest TEXT PRIMARY KEY,revision INTEGER NOT NULL)',
                '''CREATE TABLE IF NOT EXISTS open_repair_index_issuer_sequence(
                    root_digest TEXT NOT NULL,issuer TEXT NOT NULL,revision INTEGER NOT NULL,PRIMARY KEY(root_digest,issuer))''',
            ):
                self.db.execute(sql)
            binding = identity.key_id + ':' + encryption_identity.key_id
            for table in ('open_repair_index_signer_meta', 'open_provider_client_meta'):
                old = self.db.execute('SELECT value FROM '+table+" WHERE name='binding'").fetchone()
                if old is not None and old[0] != binding:
                    _fail('repair_index_signer_identity')
                if old is None:
                    guarded = ('open_repair_index_consent_outputs', 'open_repair_index_signer_statuses') if table=='open_repair_index_signer_meta' else ('open_provider_local', 'open_provider_local_floors')
                    if any(_table(self.db, name) and self.db.execute('SELECT 1 FROM '+name+' LIMIT 1').fetchone() for name in guarded):
                        _fail('repair_index_signer_binding_missing')
                    self.db.execute('INSERT INTO '+table+" VALUES('binding',?)", (binding,))
            for table in ('open_provider_state','open_repair_state'):
                if _table(self.db,table):
                    row=self.db.execute('SELECT value FROM '+table+" WHERE name='binding'").fetchone()
                    if row and (not row[0].startswith(identity.key_id+':') or not row[0].endswith(':'+encryption_identity.key_id)):
                        _fail('repair_index_signer_identity')

    @contextmanager
    def _transaction(self):
        if self.db.in_transaction:
            _fail('repair_storage_transaction')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            yield
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise

    def _status_inputs(self, base, supplied, meter):
        if type(supplied) not in (list,tuple) or len(supplied)>32:
            _fail('repair_index_preparation_capacity')
        key=base.root.payload['ack_slot']['root_key']; digest=meter._hash(wire._canonical(key,meter))
        with self._transaction():
            stored=self.db.execute('SELECT raw,ref FROM open_repair_index_signer_statuses WHERE root_digest=? ORDER BY issuer,revision,digest LIMIT 33',(digest,)).fetchall()
        if len(stored)>32: _fail('repair_index_preparation_capacity')
        candidates=[dict(raw=bytes(raw),ref=json.loads(bytes(ref))) for raw,ref in stored]
        candidates.extend(supplied)
        already={item.ref:item for item in (*_history(base.source),*base.statuses)}
        checked=dict(already)
        signers={base.expected[name]['signing_key']['key_id']:base.expected[name]['signing_key'] for name in ('expected_owner','expected_receipt_writer','expected_source')}
        for entry in candidates:
            # Public API accepts the usual raw originals, not inferred summaries.
            wire.object_fields(entry,{'raw','ref'}); ref=wire.raw_ref(entry['ref'])
            if ref in checked:
                if entry['raw']!=checked[ref].raw: _fail('repair_ref_mismatch')
                continue
            parsed=original.parse_original_control(entry['raw'],self.policy,meter).value
            payload=wire.object_fields(parsed,{'payload','proof'})['payload']
            issuer=payload.get('scope_key',{}).get('issuer_key_id')
            if issuer not in signers: _fail('repair_status_mismatch')
            # This local archive may contain old publication scopes. It grants
            # nothing and is never included in the publication wire request.
            allowed=[dict(scope_kind=item['scope_kind'],scope_id=item['scope_id']) for item in payload.get('entries',())]
            checked[ref]=status.authenticate_status_original(entry,expected_root=key,expected_signing_key=signers[issuer],
                at=wire.u53(payload.get('issued_at')),allowed_scopes=allowed,policy=self.policy,budget=meter)
        if len(checked)>32: _fail('repair_index_preparation_capacity')
        return digest,tuple(checked.values()),len(stored)

    def _observe(self, root_digest, statuses, meter, version):
        # This transaction commits before any later refusal or output-capacity
        # error. Complete witnesses make old-revision forks permanently visible.
        with self._transaction():
            if self.db.execute('SELECT count(*) FROM open_repair_index_signer_statuses WHERE root_digest=?',(root_digest,)).fetchone()[0]!=version:
                _fail('repair_index_preparation_changed')
            old_count=self.db.execute('SELECT count(*) FROM open_repair_index_signer_statuses').fetchone()[0]
            old_bytes=self.db.execute('SELECT coalesce(sum(length(raw)+length(ref)),0) FROM open_repair_index_signer_statuses').fetchone()[0]
            additions=[]; seen=set()
            for item in statuses:
                p=item.payload
                key=(root_digest,p['signing_key']['key_id'],p['revision'],item.canonical_sha256)
                if key not in seen and not self.db.execute('SELECT 1 FROM open_repair_index_signer_statuses WHERE root_digest=? AND issuer=? AND revision=? AND digest=?',key).fetchone():
                    seen.add(key)
                    additions.append((*key,item.raw,wire._canonical(item.ref.as_dict(),meter)))
            if old_count+len(additions)>128 or old_bytes+sum(len(item[4])+len(item[5]) for item in additions)>MAX_LOCAL_BYTES:
                self.db.execute("INSERT OR REPLACE INTO open_repair_index_signer_meta VALUES(?,?)",('blocked:'+root_digest,'repair_index_preparation_capacity'))
            else:
                self.db.executemany('INSERT INTO open_repair_index_signer_statuses VALUES(?,?,?,?,?,?)',additions)
            return self.db.execute('SELECT count(*) FROM open_repair_index_signer_statuses WHERE root_digest=?',(root_digest,)).fetchone()[0]

    def _known_check(self, base, statuses, *, renew, version, extra=(), output_statuses=()):
        root_digest=hashlib.sha256(canonical_bytes(base.root.payload['ack_slot']['root_key'])).hexdigest()
        if self.db.execute('SELECT count(*) FROM open_repair_index_signer_statuses WHERE root_digest=?',(root_digest,)).fetchone()[0]!=version:
            _fail('repair_index_preparation_changed')
        blocked=self.db.execute('SELECT value FROM open_repair_index_signer_meta WHERE name=?',('blocked:'+root_digest,)).fetchone()
        if blocked: _fail(blocked[0])
        empty._history_floors(statuses,previous=statuses,current=base.statuses)
        required={(item['signer']['key_id'],item['scope_kind'],item['scope_id']):item for item in (*base.obligations,*extra)}
        renew_masks={}; renew_floors={}
        if renew:
            for item in base.statuses:
                if item.payload['signing_key']==self.subject['signing_key']:
                    for entry in item.payload['entries']:
                        renew_masks[(self.identity.key_id,entry['scope_kind'],entry['scope_id'])]=entry['operation_mask']
                        renew_floors[(self.identity.key_id,entry['scope_kind'],entry['scope_id'])]=entry['minimum_document_revision']
        for item in statuses:
            for entry in item.payload['entries']:
                key=(item.payload['signing_key']['key_id'],entry['scope_kind'],entry['scope_id'])
                need=required.get(key)
                mask=(need['mask'] if need else 0)|renew_masks.get(key,0)
                if entry['status']=='revoked' and entry['operation_mask'] & mask:
                    _fail('repair_authority_revoked')
                if need and entry['minimum_document_revision']>need['revision']:
                    _fail('repair_status_revision')
        # Durable other adapters may know observations not supplied by a caller.
        for table in ('open_repair_access_floors','open_repair_index_floors','open_provider_status'):
            if not _table(self.db,table): continue
            columns={row[1] for row in self.db.execute('PRAGMA table_info('+table+')')}
            if not {'issuer','root_digest','scope_kind','scope_id','revision','revoked_mask','conflict'}<=columns: continue
            minimum='minimum_revision' if 'minimum_revision' in columns else '0'
            for issuer,kind,scope,revision,revoked,conflict,floor in self.db.execute('SELECT issuer,scope_kind,scope_id,revision,revoked_mask,conflict,'+minimum+' FROM '+table+' WHERE root_digest=?',(root_digest,)):
                key=(issuer,kind,scope); need=required.get(key)
                if conflict: _fail('repair_status_conflict')
                if key in renew_floors and floor>renew_floors[key]: _fail('repair_status_revision')
                if revoked & ((need['mask'] if need else 0)|renew_masks.get(key,0)): _fail('repair_authority_revoked')
                if need:
                    if floor>need['revision']: _fail('repair_status_revision')
                    observed=max((item.payload['revision'] for item in (*base.statuses,*output_statuses) if item.payload['signing_key']['key_id']==issuer
                        and any((entry['scope_kind'],entry['scope_id'])==(kind,scope) for entry in item.payload['entries'])),default=0)
                    if revision>observed: _fail('repair_status_rollback')

    def _output_allowed(self, base, statuses, checked, meter, renew, version):
        consent, publication, renewed = checked
        scope = index._authority(base.root.payload['ack_slot']['root_key'],consent,self.policy,meter)
        need = index._obligation(consent.payload['signing_key'],'authority',scope,consent.payload['revision'],16)
        # Both cached and newly signed results are denied by later observations.
        self._known_check(base,statuses,renew=renew,version=version,extra=(need,),output_statuses=(*renewed,publication))
        current = (*renewed, publication)
        empty._history_floors((*statuses,*current),previous=statuses,current=current)
        if int(self.clock()) >= min(base.until, consent.payload['expires_at'], publication.payload['valid_until']):
            _fail('repair_access_expired')

    def _reserve_revisions(self, root_digest, statuses, count):
        issuer=self.identity.key_id
        maximum=max((item.payload['revision'] for item in statuses if item.payload['signing_key']['key_id']==issuer),default=0)
        for table,prefix in (('open_provider_client_meta','status:'),('open_provider_state','status_revision:')):
            row=self.db.execute('SELECT value FROM '+table+' WHERE name=?',(prefix+root_digest,)).fetchone()
            if row: maximum=max(maximum,wire.u53(int(row[0])))
        row=self.db.execute('SELECT revision FROM open_repair_saved_ack_roots WHERE root_digest=?',(root_digest,)).fetchone()
        if row: maximum=max(maximum,wire.u53(row[0]))
        row=self.db.execute('SELECT revision FROM open_repair_index_issuer_sequence WHERE root_digest=? AND issuer=?',(root_digest,issuer)).fetchone()
        if row: maximum=max(maximum,wire.u53(row[0]))
        for table in ('open_repair_access_documents','open_provider_status','open_repair_index_status_originals'):
            if _table(self.db,table):
                row=self.db.execute('SELECT coalesce(max(revision),0) FROM '+table+' WHERE root_digest=? AND issuer=?',(root_digest,issuer)).fetchone()
                maximum=max(maximum,wire.u53(row[0]))
        last=wire.u53(maximum+count,1)
        for table,prefix in (('open_provider_client_meta','status:'),('open_provider_state','status_revision:')):
            self.db.execute('INSERT INTO '+table+' VALUES(?,?) ON CONFLICT(name) DO UPDATE SET value=excluded.value',(prefix+root_digest,str(last)))
        self.db.execute('INSERT INTO open_repair_saved_ack_roots VALUES(?,?) ON CONFLICT(root_digest) DO UPDATE SET revision=excluded.revision',(root_digest,last))
        self.db.execute('INSERT INTO open_repair_index_issuer_sequence VALUES(?,?,?) ON CONFLICT(root_digest,issuer) DO UPDATE SET revision=excluded.revision',(root_digest,issuer,last))
        return list(range(maximum+1,last+1))

    def sign(self, bundle, *, variant, expected, known_statuses=(), renew_source_status=False):
        if variant not in ('owner','receipt_writer') or type(renew_source_status) is not bool:
            _fail('repair_invalid_context')
        meter=wire.RepairBudget(self.policy); now=wire.u53(int(self.clock()))
        base=_verify_bundle(bundle,expected,now,self.limits,self.policy,meter)
        name='expected_owner' if variant=='owner' else 'expected_receipt_writer'
        if self.subject!=base.expected[name]: _fail('repair_index_signer_identity')
        root_digest,statuses,version=self._status_inputs(base,known_statuses,meter)
        version=self._observe(root_digest,statuses,meter,version)
        if base.code: _fail(base.code)
        self._known_check(base,statuses,renew=renew_source_status,version=version)
        own=[item for item in base.statuses if item.payload['signing_key']==self.subject['signing_key']]
        if not own: _fail('repair_status_missing')
        request=dict(bundle_sha256=meter._hash(wire._canonical(base.value,meter)),variant=variant,renew_source_status=renew_source_status)
        request_digest=meter._hash(wire._canonical(request,meter))
        with self._transaction():
            self._known_check(base,statuses,renew=renew_source_status,version=version)
            row=self.db.execute('SELECT issued_at,revisions,raw FROM open_repair_index_consent_outputs WHERE request_digest=?',(request_digest,)).fetchone()
            if row is None:
                if self.db.execute('SELECT count(*) FROM open_repair_index_consent_outputs').fetchone()[0]>=MAX_LOCAL_RECORDS:
                    _fail('repair_index_preparation_capacity')
                revisions=self._reserve_revisions(root_digest,statuses,1+(len(own) if renew_source_status else 0))
                self.db.execute('INSERT INTO open_repair_index_consent_outputs VALUES(?,?,?,?,NULL)',(request_digest,root_digest,now,wire.build_new_wire(revisions,self.policy,meter).raw))
                issued,raw=now,None
            else:
                issued,revisions,raw=row; revisions=json.loads(bytes(revisions))
        if raw is not None:
            result=wire.parse_new_wire(bytes(raw),self.policy,meter).value
            checked=_verify_signed_result(result,base,variant,now,self.policy,meter)
            with self._transaction():
                self._output_allowed(base,statuses,checked,meter,renew_source_status,version)
            return json.loads(bytes(raw))
        until=base.until
        if not now<until or issued<max(base.source.stored_at,base.fact.payload['issued_at']): _fail('repair_access_expired')
        originals,scopes=index._permissions(base.rows,self.identity.key_id,self.policy,meter)
        source,root=base.source,base.root
        intent_sha=meter._hash(wire._canonical(base.value['intent'],meter))
        payload=dict(schema_version=index.SCHEMA,kind='ack.index_consent',signing_key=self.subject['signing_key'],variant=variant,
            issued_at=issued,expires_at=until,consent_id='index_'+request_digest,revision=1,ack_slot=base.expected['expected_ack_slot'],
            root_authority_ref=root.ref.as_dict(),grant_ref=source.commit.payload['grant_ref'],binding_ref=source.commit.payload['binding_ref'],
            receipt_ref=source.commit.payload['receipt_ref'],original_disclosure_ref=source.inputs['disclosure'].ref.as_dict(),
            original_ack_commit_ref=source.commit.ref.as_dict(),historical_manifest_ref=source.commit.payload['historical_manifest_ref'],
            publisher=resource._dual_key(base.expected['expected_source'],meter),target=base.expected['expected_directory'],
            target_storage_epoch=base.expected['directory_storage_epoch'],operation_mask=16,
            reservation_disclosure=dict(intent_sha256=intent_sha,until=until),
            post_assignment_disclosure=dict(originals=originals,status_scopes=scopes,until=until))
        consent=_signed_entry(payload,self.identity,self.policy,meter)
        scope=status.status_scope(root.payload['ack_slot']['root_key'],'authority',dict(authority_kind='ack.index_consent',authority_sha256=consent['ref']['raw_sha256']),self.policy,meter)
        source_statuses=[]
        if renew_source_status:
            for item,revision in zip(own,revisions[:-1]):
                p=dict(item.payload,revision=revision,issued_at=issued,valid_until=until)
                source_statuses.append(_signed_entry(p,self.identity,self.policy,meter))
        q_status=dict(schema_version=status.SCHEMA,kind='authority.status',signing_key=self.subject['signing_key'],
            scope_key=dict(root_key=root.payload['ack_slot']['root_key'],issuer_key_id=self.identity.key_id),revision=revisions[-1],
            issued_at=issued,valid_until=until,entries=[dict(scope_kind='authority',scope_id=scope,minimum_document_revision=1,status='active',operation_mask=16)])
        observation=_signed_entry(q_status,self.identity,self.policy,meter)
        result=dict(schema_version=CONSENT_SCHEMA,variant=variant,bundle_sha256=request['bundle_sha256'],
            consent=_encoded(consent,meter),publication_status=_encoded(observation,meter),
            source_statuses=[_encoded(item,meter) for item in source_statuses])
        checked=_verify_signed_result(result,base,variant,now,self.policy,meter)
        raw=wire.build_new_wire(result,self.policy,meter).raw
        with self._transaction():
            self._output_allowed(base,statuses,checked,meter,renew_source_status,version)
            total=self.db.execute('SELECT coalesce(sum(length(raw)),0) FROM open_repair_index_consent_outputs').fetchone()[0]
            existing=self.db.execute('SELECT raw FROM open_repair_index_consent_outputs WHERE request_digest=?',(request_digest,)).fetchone()[0]
            if existing is not None:
                if bytes(existing)!=raw: _fail('repair_index_job_conflict')
            elif total+len(raw)>MAX_LOCAL_BYTES: _fail('repair_index_preparation_capacity')
            else: self.db.execute('UPDATE open_repair_index_consent_outputs SET raw=? WHERE request_digest=?',(raw,request_digest))
        return json.loads(raw)


def _verify_signed_result(value, base, variant, at, policy, budget):
    value=_snapshot(value,policy,budget)
    wire.object_fields(value,{'schema_version','variant','bundle_sha256','consent','publication_status','source_statuses'})
    if (value['schema_version']!=CONSENT_SCHEMA or value['variant']!=variant
            or value['bundle_sha256']!=budget._hash(wire._canonical(base.value,budget))): _fail()
    expected=base.expected; source=base.source
    signer=expected['expected_owner' if variant=='owner' else 'expected_receipt_writer']['signing_key']
    consent=index._signed(_decoded(value['consent'],policy,budget),signer,'ack.index_consent',index.CONSENT_FIELDS,policy,budget)
    p=consent.payload; index._timed(p,at)
    resource._opaque(p['consent_id']); wire.u53(p['revision'],1)
    refs=dict(root_authority_ref=base.root.ref.as_dict(),grant_ref=source.commit.payload['grant_ref'],binding_ref=source.commit.payload['binding_ref'],
        receipt_ref=source.commit.payload['receipt_ref'],original_disclosure_ref=source.inputs['disclosure'].ref.as_dict(),
        original_ack_commit_ref=source.commit.ref.as_dict(),historical_manifest_ref=source.commit.payload['historical_manifest_ref'])
    if (p['variant']!=variant or p['ack_slot']!=expected['expected_ack_slot'] or p['operation_mask']!=16
            or p['target']!=expected['expected_directory'] or p['target_storage_epoch']!=expected['directory_storage_epoch']
            or p['publisher']!=resource._dual_key(expected['expected_source'],budget)
            or p['issued_at']<max(source.stored_at,base.fact.payload['issued_at'])
            or any(p[name]!=ref for name,ref in refs.items())): _fail()
    reserved=wire.object_fields(p['reservation_disclosure'],{'intent_sha256','until'})
    if (reserved['intent_sha256']!=budget._hash(wire._canonical(base.value['intent'],budget))
            or not at<wire.u53(reserved['until'])<=min(base.until,p['expires_at'])): _fail()
    scopes=index._disclosure(p['post_assignment_disclosure'],base.rows,signer['key_id'],min(base.until,p['expires_at']),at,policy,budget)
    root=base.root.payload['ack_slot']['root_key']; qscope=index._authority(root,consent,policy,budget)
    publication=status.verify_status_original(_decoded(value['publication_status'],policy,budget),expected_root=root,expected_signing_key=signer,
        at=at,allowed_scopes=[dict(scope_kind='authority',scope_id=qscope)],
        required=[dict(scope_kind='authority',scope_id=qscope,document_revision=p['revision'],operation_mask=16)],policy=policy,budget=budget)
    originals=[item for item in base.statuses if item.payload['signing_key']==signer]
    if type(value['source_statuses']) is not wire._DraftList or len(value['source_statuses']) not in (0,len(originals)): _fail()
    renewed=[]
    for encoded,old in zip(value['source_statuses'],originals):
        item=status.authenticate_status_original(_decoded(encoded,policy,budget),expected_root=root,expected_signing_key=signer,
            at=at,allowed_scopes=scopes,policy=policy,budget=budget)
        if (item.payload['entries']!=old.payload['entries'] or item.payload['revision']<=old.payload['revision']
                or item.payload['issued_at']!=p['issued_at'] or item.payload['valid_until']>base.until): _fail()
        renewed.append(item)
    empty._history_floors((*_history(source),*base.statuses,*renewed,publication),previous=(*_history(source),*base.statuses),current=(*renewed,publication))
    return consent,publication,tuple(renewed)


def assemble_publication(bundle, owner_result, recipient_result, *, expected,
                         policy=DEFAULT_POLICY, limit_policy=INDEX_WORKFLOW_LIMITS, at=None):
    """Authenticate both independent results with the actual publication verifier."""
    now=wire.u53(int(time.time()) if at is None else at); meter=wire.RepairBudget(policy)
    value,expected,resolver,entries,seen=_unpack_bundle(bundle,expected,policy,meter)
    results=[_snapshot(item,policy,meter) for item in (owner_result,recipient_result)]
    for result in results:
        wire.object_fields(result,{'schema_version','variant','bundle_sha256','consent','publication_status','source_statuses'})
        if type(result['source_statuses']) is not wire._DraftList or len(result['source_statuses'])>16:
            _fail('repair_index_preparation_capacity')
    if type(value['current_statuses']) is not wire._DraftList or not 1<=len(value['current_statuses'])<=16:
        _fail('repair_status_missing')
    original_current=[_decoded(item,policy,meter) for item in value['current_statuses']]
    replaced={expected[name]['signing_key']['key_id'] for name,result in zip(('expected_owner','expected_receipt_writer'),results)
        if result['source_statuses']}
    current=[]
    for item in original_current:
        # This is selection only. The complete old originals are authenticated
        # below even if a newly signed whole document replaces them on the wire.
        payload=original.parse_original_control(item['raw'],policy,meter).value['payload']
        if payload['signing_key']['key_id'] not in replaced: current.append(item)
    for result in results:
        current.extend(_decoded(item,policy,meter) for item in result['source_statuses'])
        current.append(_decoded(result['publication_status'],policy,meter))
    _directory_budget(value['intent']['budget'])
    checked=index.verify_ack_index_plan(entries['manifest'],resolver,entries['commit'],entries['head'],entries['fact'],value['intent'],
        _decoded(results[0]['consent'],policy,meter),_decoded(results[1]['consent'],policy,meter),**dict(expected),
        current_statuses=current,at=now,limit_policy=limit_policy,policy=policy,budget=meter)
    if checked.denial_code: _fail(checked.denial_code)
    source=checked.source
    used={wire.raw_ref(item['pack_ref']) for manifest in (source.manifest,source.predecessor.manifest,
        source.predecessor.predecessor.manifest) for item in manifest.manifest.value['roles']}
    if used!=seen: _fail('repair_unused_pack')
    base=_base(source,checked.head,expected,original_current,now,policy,meter)
    if base.code: _fail(base.code)
    if value['inventory']!=[dict(role=item.role,ref=item.original.ref.as_dict(),issuer=item.issuer) for item in base.rows]:
        _fail('repair_index_inventory_mismatch')
    node=_directory(entries['directory_node'],expected,now,policy,meter)
    base.until=min(base.until,checked.fact.payload['expires_at'],value['intent']['windows']['publish_until'],node['expires_at'])
    base.value,base.expected,base.fact=value,expected,checked.fact
    for variant,result in zip(('owner','receipt_writer'),results):
        _verify_signed_result(result,base,variant,now,policy,meter)
    result=dict(schema_version=REQUEST_SCHEMA,resource_id=value['resource_id'],directory=expected['expected_directory'],
        node=value['directory_node'],fact=value['fact'],intent=value['intent'],owner_consent=results[0]['consent'],
        recipient_consent=results[1]['consent'],current_statuses=[_encoded(item,meter) for item in current])
    return json.loads(wire.build_new_wire(result,policy,meter).raw)
