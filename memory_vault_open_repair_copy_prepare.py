"""Private maintainer preparation of an explicitly authorized ACK reservation.

This journal emits only the minimal allocation request. It neither uploads source
originals nor grants replica custody, reading, discovery, or receipt admission.
The caller must prove the destination's dual keys before transmitting its output.
"""
import hashlib
import json

from memory_vault import canonical_bytes
import memory_vault_open_repair_ack as ack
import memory_vault_open_repair_empty as empty
import memory_vault_open_repair_index as index
import memory_vault_open_repair_history as history
import memory_vault_open_repair_resource as resource
import memory_vault_open_repair_status as status
import memory_vault_open_repair_wire as wire
from memory_vault_open_repair_copy_resources import INTENT_FIELDS, ack_copy_scope

COPY = 4
CONSENT_FIELDS = resource.COMMON | frozenset('issued_at expires_at consent_id revision root_authority_ref source_custody_ref historical_manifest_ref maintainer target target_storage_epoch reservation_disclosure'.split())


def _require(value):
    if not value:
        wire._fail('repair_copy_preparation_mismatch')


class AckCopyPreparation:
    """Bounded, caller-owned local journal; never a remotely callable service."""
    def __init__(self, db, identity, encryption_identity, *, policy):
        self.db, self.identity, self.policy = db, identity, policy
        self.keys = dict(signing_key=identity.public_descriptor(),
                         encryption_key=encryption_identity.public_descriptor())

    def initialize(self):
        _require(not self.db.in_transaction)
        with self.db:
            self.db.execute('CREATE TABLE IF NOT EXISTS ack_copy_prepare_binding(id INTEGER PRIMARY KEY CHECK(id=1),value BLOB NOT NULL)')
            binding = canonical_bytes(self.keys)
            old = self.db.execute('SELECT value FROM ack_copy_prepare_binding WHERE id=1').fetchone()
            if old is not None:
                _require(bytes(old[0]) == binding)
            else:
                existing = self.db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('ack_copy_prepare_jobs','ack_copy_prepare_status')").fetchall()
                _require(not existing)
                self.db.execute('INSERT INTO ack_copy_prepare_binding VALUES(1,?)', (binding,))
            self.db.execute('CREATE TABLE IF NOT EXISTS ack_copy_prepare_jobs(job_id TEXT PRIMARY KEY,root_digest TEXT NOT NULL,intent_digest TEXT NOT NULL,consent_ref BLOB NOT NULL,request BLOB NOT NULL,ref BLOB NOT NULL)')
            self.db.execute('CREATE TABLE IF NOT EXISTS ack_copy_prepare_status(root_digest TEXT NOT NULL,raw_digest TEXT NOT NULL,raw BLOB NOT NULL,ref BLOB NOT NULL,PRIMARY KEY(root_digest,raw_digest))')
            self.db.execute('CREATE TABLE IF NOT EXISTS ack_copy_prepare_blocked(root_digest TEXT PRIMARY KEY,reason TEXT NOT NULL)')
            self.db.execute('CREATE TABLE IF NOT EXISTS ack_copy_prepare_assignments(job_id TEXT PRIMARY KEY,offer_ref BLOB NOT NULL,raw BLOB NOT NULL,ref BLOB NOT NULL)')

    def prepare_unbound(self, *args, **kwargs):
        return self._prepare_unbound(*args, **kwargs, offer_entry=None)

    def assign_unbound(self, *args, offer_entry, **kwargs):
        """Bind the verified real offer to one durable COPY/READ/RETAIN assignment.

        The caller must still obtain original disclosure permission before upload.
        This assignment neither commits replica bytes nor advertises a provider.
        """
        return self._prepare_unbound(*args, **kwargs, offer_entry=offer_entry)

    def _prepare_unbound(self, manifest_entry, resolver, custody_entry, consent_entry, intent, *,
                        expected_ack_slot, expected_owner, expected_source, source_storage_epoch,
                        current_statuses, at, limit_policy, budget, offer_entry):
        _require(not self.db.in_transaction)
        policy = self.policy
        wire._context(policy, budget)
        at = wire.u53(at)
        _require(self.keys['signing_key'] == self.identity.public_descriptor())
        binding = self.db.execute('SELECT value FROM ack_copy_prepare_binding WHERE id=1').fetchone()
        _require(binding is not None and bytes(binding[0]) == canonical_bytes(self.keys))
        source = ack.verify_ack_unbound_source_event(manifest_entry, resolver, custody_entry,
            expected_ack_slot=expected_ack_slot, expected_owner=expected_owner,
            expected_target=expected_source, target_storage_epoch=source_storage_epoch,
            limit_policy=limit_policy, policy=policy, budget=budget)
        root = source.resources.originals['root']
        active = source.resources.originals['active']
        root_key = root.payload['ack_slot']['root_key']
        owner = wire.build_new_wire(expected_owner, policy, budget).value
        source_keys = wire.build_new_wire(expected_source, policy, budget).value
        mine = wire.build_new_wire(self.keys, policy, budget).value
        caller_id = resource._dual_key(mine, budget)
        operations = COPY if offer_entry is None else 78  # Root COPY | READ | DISCOVER | RETAIN
        _require(caller_id in root.payload['maintainers']
            and root.payload['operation_mask'] & operations == operations)
        value = wire.build_new_wire(intent, policy, budget).value
        resource._fields(value, INTENT_FIELDS)
        ack_copy_scope(value['scope'], root_key)
        target_id = resource._dual_key(value['target'], budget)
        _require(target_id != resource._dual_key(source_keys, budget) and target_id != caller_id)
        for name in ('allocation_id', 'job_id', 'target_storage_epoch'):
            resource._opaque(value[name])
        resource._budget(value['budget']); resource._windows(value['windows'], issued=at)
        _require(all(value['budget'][key] > 0 for key in resource._BUDGET if key != 'max_live_bytes')
            and root.payload['max_delegate_depth'] >= 2)
        # Keep manifest and source-custody references distinct: H precedes custody.
        _require(value['kind'] == 'resource.copy_intent' and value['purpose'] == 'ack_replica'
            and value['root_key'] == root_key and value['caller'] == mine
            and value['scope'] == dict(kind='ack_unbound', ack_slot=root.payload['ack_slot'], root_authority_ref=root.ref.as_dict())
            and value['historical_manifest_ref'] == wire.raw_ref(manifest_entry['ref']).as_dict())
        _require(all(value['budget'][name] <= root.payload['budget'][name] for name in resource._BUDGET)
            and all(value['windows'][name] <= root.payload['windows'][name] for name in resource._WINDOWS))
        digest = budget._hash(wire._canonical(value, budget))
        consent = index._signed(consent_entry, owner['signing_key'], 'ack.copy_reservation_consent', CONSENT_FIELDS, policy, budget)
        c = consent.payload
        index._timed(c, at); resource._opaque(c['consent_id']); wire.u53(c['revision'], 1)
        maximum = min(source.read_until, source.retain_until, active.payload['windows']['copy_until'],
            root.payload['windows']['copy_until'], root.payload['expires_at'], c['expires_at'], value['windows']['copy_until'])
        disclosure = resource._fields(c['reservation_disclosure'], {'intent_sha256', 'until'})
        _require(c['root_authority_ref'] == root.ref.as_dict() and c['source_custody_ref'] == source.custody.ref.as_dict()
            and c['historical_manifest_ref'] == value['historical_manifest_ref'] and c['maintainer'] == caller_id
            and c['target'] == value['target'] and c['target_storage_epoch'] == value['target_storage_epoch']
            and c['issued_at'] >= source.stored_at and disclosure['intent_sha256'] == digest
            and at < wire.u53(disclosure['until']) <= maximum)
        signers = {key['signing_key']['key_id']:key['signing_key'] for key in (owner, source_keys)}
        allowed = {key:[] for key in signers}
        for item in source.statuses:
            allowed[item.payload['signing_key']['key_id']].extend(
                dict(scope_kind=e['scope_kind'], scope_id=e['scope_id']) for e in item.payload['entries'])
        allowed = {key:[dict(scope_kind=k, scope_id=v) for k,v in sorted({(e['scope_kind'],e['scope_id']) for e in rows})] for key,rows in allowed.items()}
        consent_scope = index._authority(root_key, consent, policy, budget)
        allowed[owner['signing_key']['key_id']].append(dict(scope_kind='authority', scope_id=consent_scope))
        obligations = (
            index._obligation(owner['signing_key'], 'authority', index._authority(root_key, root, policy, budget), root.payload['revision'], operations),
            index._obligation(owner['signing_key'], 'ack_slot', status.status_scope(root_key, 'ack_slot', root.payload['ack_slot'], policy, budget), root.payload['revision'], COPY if offer_entry is None else 70),
            index._obligation(owner['signing_key'], 'authority', consent_scope, c['revision'], COPY),
            index._obligation(source_keys['signing_key'], 'resource', status.status_scope(root_key, 'resource', active.payload['resource'], policy, budget), active.payload['reservation_generation'], COPY))
        if offer_entry is not None:
            for original, mask in ((source.resources.originals['read'], 2), (source.bootstrap.originals['bootstrap'], 10)):
                obligations += (index._obligation(owner['signing_key'], 'authority',
                    index._authority(root_key, original, policy, budget), original.payload['revision'], mask),)
        checked, denial = [], None
        if not isinstance(current_statuses, (tuple, list)) or not 1 <= len(current_statuses) <= 16:
            wire._fail('repair_status_missing')
        # Observe each authentic whole document even if a later sibling is bad.
        # Expired signed revocations are still retained before refusing live use.
        for entry in current_statuses:
            try:
                payload = wire.parse_new_wire(entry['raw'], policy, budget).value['payload']
                issuer = payload['signing_key']['key_id']
                if issuer not in signers:
                    wire._fail('repair_status_disclosure')
                status.authenticate_status_original(entry, expected_root=root_key,
                    expected_signing_key=signers[issuer], at=at, allowed_scopes=allowed[issuer],
                    policy=policy, budget=budget, on_authenticated=checked.append)
            except (KeyError, TypeError):
                denial = denial or 'repair_invalid_status'
            except wire.RepairWireError as error:
                denial = denial or error.code
        if len({item.ref for item in checked}) != len(checked):
            denial = denial or 'repair_duplicate_status'
        try:
            empty._history_floors((*source.statuses, *checked), previous=source.statuses, current=checked)
        except wire.RepairWireError as error:
            denial = denial or error.code
        for need in obligations:
            observations = [e for item in checked if item.payload['signing_key'] == need['signer']
                for e in item.payload['entries'] if (e['scope_kind'], e['scope_id']) == (need['scope_kind'], need['scope_id'])]
            if not observations:
                denial = denial or 'repair_status_missing'
            for e in observations:
                if e['status'] == 'revoked':
                    denial = denial or 'repair_authority_revoked'
                elif e['minimum_document_revision'] > need['revision']:
                    denial = denial or 'repair_status_revision'
                elif e['operation_mask'] & need['mask'] != need['mask']:
                    denial = denial or 'repair_status_operation'
        root_digest = budget._hash(wire._canonical(root_key, budget))
        # Serialize the durable floor observation with request creation. A denied
        # observation commits even though no allocation request is emitted.
        self.db.execute('BEGIN IMMEDIATE')
        try:
            blocked = self.db.execute("SELECT reason FROM ack_copy_prepare_blocked WHERE root_digest IN (?, '*')", (root_digest,)).fetchone()
            if blocked:
                denial = blocked[0]
            previous = []
            for raw, ref in self.db.execute('SELECT raw,ref FROM ack_copy_prepare_status WHERE root_digest=?', (root_digest,)):
                p = wire.parse_new_wire(bytes(raw), policy, budget).value['payload']
                previous.append(status.authenticate_status_original(dict(raw=bytes(raw), ref=json.loads(bytes(ref))),
                    expected_root=root_key, expected_signing_key=signers[p['signing_key']['key_id']], at=p['issued_at'],
                    allowed_scopes=[dict(scope_kind=e['scope_kind'], scope_id=e['scope_id']) for e in p['entries']], policy=policy, budget=budget))
            try:
                empty._history_floors((*source.statuses, *previous, *checked), previous=previous, current=checked)
            except wire.RepairWireError as error:
                denial = denial or error.code
            for item in checked:
                count, size = self.db.execute('SELECT count(*),coalesce(sum(length(raw)+length(ref)),0) FROM ack_copy_prepare_status').fetchone()
                if self.db.execute('SELECT 1 FROM ack_copy_prepare_status WHERE root_digest=? AND raw_digest=?', (root_digest,item.ref.raw_sha256)).fetchone():
                    continue
                ref_raw = canonical_bytes(item.ref.as_dict())
                if count >= 64 or size + len(item.raw) + len(ref_raw) > 1048576:
                    denial = 'repair_copy_journal_capacity'
                    self.db.execute('INSERT OR IGNORE INTO ack_copy_prepare_blocked VALUES(?,?)', ('*',denial))
                    break
                self.db.execute('INSERT INTO ack_copy_prepare_status VALUES(?,?,?,?)', (root_digest,item.ref.raw_sha256,item.raw,ref_raw))
            for old_status in previous:
                for e in old_status.payload['entries']:
                    for need in obligations:
                        if (old_status.payload['signing_key'] == need['signer'] and e['scope_kind'] == need['scope_kind']
                                and e['scope_id'] == need['scope_id'] and e['status'] == 'revoked'):
                            denial = denial or 'repair_authority_revoked'
            result = None
            if denial is None:
                old = self.db.execute('SELECT intent_digest,consent_ref,request,ref FROM ack_copy_prepare_jobs WHERE job_id=?', (value['job_id'],)).fetchone()
                if old:
                    _require(old[0] == digest and bytes(old[1]) == canonical_bytes(consent.ref.as_dict()))
                    result = dict(raw=bytes(old[2]),ref=json.loads(bytes(old[3])))
                    held = index._signed(result, mine['signing_key'], 'resource.allocate', index.ALLOCATE_FIELDS, policy, budget).payload
                    index._timed(held, at)
                    _require(held['intent'] == value and held['intent_sha256'] == digest
                        and held['target_node_key_id'] == target_id['signing_key_id']
                        and held['target_storage_epoch'] == value['target_storage_epoch'])
                else:
                    count = self.db.execute('SELECT count(*) FROM ack_copy_prepare_jobs').fetchone()[0]
                    root_count = self.db.execute('SELECT count(*) FROM ack_copy_prepare_jobs WHERE root_digest=?', (root_digest,)).fetchone()[0]
                    _require(count < 16 and root_count < min(root.payload['max_concurrent_jobs'], root.payload['budget']['max_jobs']))
                    payload = dict(schema_version=resource.SCHEMA,kind='resource.allocate',signing_key=mine['signing_key'],
                        issued_at=at,expires_at=min(at+60,maximum,disclosure['until'],*value['windows'].values(),*(s.payload['valid_until'] for s in checked)),
                        request_id='copy_'+digest,target_node_key_id=target_id['signing_key_id'],
                        target_storage_epoch=value['target_storage_epoch'],intent=value,intent_sha256=digest)
                    raw = canonical_bytes(dict(payload=payload,proof=self.identity.sign_message(payload)))
                    sha = hashlib.sha256(raw).hexdigest()
                    result = dict(raw=raw,ref=dict(namespace='meta',key=sha,raw_sha256=sha,size=len(raw)))
                    self.db.execute('INSERT INTO ack_copy_prepare_jobs VALUES(?,?,?,?,?,?)',
                        (value['job_id'],root_digest,digest,canonical_bytes(consent.ref.as_dict()),raw,canonical_bytes(result['ref'])))
            if result is not None and offer_entry is not None:
                result = self._assign_locked(result, offer_entry, source, value, digest, at, budget)
            self.db.commit()
        except wire.RepairWireError:
            self.db.commit(); raise
        except BaseException:
            self.db.rollback(); raise
        if denial:
            wire._fail(denial)
        return result

    def _assign_locked(self, allocation_entry, offer_entry, source, intent, digest, at, budget):
        """Called only after current observations were persisted in this writer."""
        policy = self.policy
        target = intent['target']
        target_id = resource._dual_key(target, budget)
        offer = index._signed(offer_entry, target['signing_key'], 'resource.offer', index.OFFER_FIELDS, policy, budget)
        p = offer.payload
        allocation = wire.parse_new_wire(allocation_entry['raw'], policy, budget).value['payload']
        resource._budget(p['budget']); resource._windows(p['windows']); history._resource(p['resource'])
        resource._opaque(p['offer_id'])
        _require(p['intent'] == intent and p['intent_sha256'] == digest
            and p['allocation_request_ref'] == allocation_entry['ref']
            and p['target_encryption_key'] == target['encryption_key']
            and p['resource']['node_key_id'] == target_id['signing_key_id']
            and p['resource']['storage_epoch'] == intent['target_storage_epoch']
            and p['budget'] == intent['budget'] and p['windows'] == intent['windows']
            and wire.u53(p['reservation_generation'], 1) == 1
            and allocation['issued_at'] <= wire.u53(p['issued_at']) <= at
            and at < wire.u53(p['reservation_until']) <= allocation['expires_at'])
        root = source.resources.originals['root']
        read = source.resources.originals['read']
        bootstrap = source.bootstrap.originals['bootstrap']
        expires = min(root.payload['expires_at'], read.payload['expires_at'],
            read.payload['windows']['read_until'], bootstrap.payload['expires_at'], bootstrap.payload['proof_until'],
            bootstrap.payload['probe_until'], bootstrap.payload['upload_until'],
            *(p['windows'][name] for name in ('read_until','copy_until','retain_until')))
        _require(at < expires and all(value <= expires for value in p['windows'].values()))
        old = self.db.execute('SELECT offer_ref,raw,ref FROM ack_copy_prepare_assignments WHERE job_id=?', (intent['job_id'],)).fetchone()
        if old:
            _require(bytes(old[0]) == canonical_bytes(offer.ref.as_dict()))
            result = dict(raw=bytes(old[1]), ref=json.loads(bytes(old[2])))
            held = index._signed(result, self.keys['signing_key'], 'maintenance.assignment', index.ASSIGNMENT_FIELDS, policy, budget)
            index._timed(held.payload, at)
            _require(held.payload['resource_offer_ref'] == offer.ref.as_dict()
                and held.payload['resource_intent_sha256'] == digest)
            return result
        payload = dict(schema_version=resource.SCHEMA,kind='maintenance.assignment',signing_key=self.keys['signing_key'],
            issued_at=at,expires_at=expires,assignment_id='assignment_'+digest,job_id=intent['job_id'],
            root_key=intent['root_key'],parent_root_ref=root.ref.as_dict(),parent_assignment_ref=None,depth=2,
            subject=target_id,target_node_key_id=target_id['signing_key_id'],target_storage_epoch=intent['target_storage_epoch'],
            operation_mask=70,scope=intent['scope'],resource_intent_sha256=digest,resource_offer_ref=offer.ref.as_dict(),
            resource=p['resource'],bootstrap_grant_refs=[bootstrap.ref.as_dict()],budget=p['budget'],windows=p['windows'])
        raw = canonical_bytes(dict(payload=payload,proof=self.identity.sign_message(payload)))
        sha = hashlib.sha256(raw).hexdigest()
        result = dict(raw=raw,ref=dict(namespace='meta',key=sha,raw_sha256=sha,size=len(raw)))
        self.db.execute('INSERT INTO ack_copy_prepare_assignments VALUES(?,?,?,?)',
            (intent['job_id'],canonical_bytes(offer.ref.as_dict()),raw,canonical_bytes(result['ref'])))
        return result
