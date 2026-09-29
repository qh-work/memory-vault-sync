"""Private maintainer preparation of an explicitly authorized ACK reservation.

This journal retains allocation requests and authorized outgoing upload stages.
It neither transmits originals nor grants custody, READ or receipt admission.
The caller must prove the destination's dual keys before transmitting its output.
"""
import hashlib
import json
import secrets
from contextlib import contextmanager

from memory_vault import canonical_bytes
import memory_vault_open_repair_ack as ack
import memory_vault_open_repair_empty as empty
import memory_vault_open_repair_index as index
import memory_vault_open_repair_history as history
import memory_vault_open_repair_resource as resource
import memory_vault_open_repair_status as status
import memory_vault_open_repair_wire as wire
import memory_vault_open_repair_copy_source as copy_source
from memory_vault_open_repair_copy_resources import INTENT_FIELDS, ack_copy_scope

COPY = 4
CONSENT_FIELDS = resource.COMMON | frozenset('issued_at expires_at consent_id revision root_authority_ref source_custody_ref historical_manifest_ref maintainer target target_storage_epoch reservation_disclosure'.split())


def _require(value):
    if not value:
        wire._fail('repair_copy_preparation_mismatch')



def _recipient_reservation(source,owner_consent,entry,at,policy,budget):
    """B authorizes exact opaque receipt associations before target allocation."""
    if not copy_source.occupied_source(source):
        if entry is not None:wire._fail('repair_copy_scope')
        return None
    item=index._signed(entry,source.receipt_writer['signing_key'],
        'ack.copy_recipient_reservation_consent',CONSENT_FIELDS,policy,budget)
    value=item.payload;owner=owner_consent.payload
    index._timed(value,at);resource._opaque(value['consent_id']);wire.u53(value['revision'],1)
    for name in ('root_authority_ref','source_custody_ref','historical_manifest_ref','maintainer','target','target_storage_epoch'):
        _require(value[name]==owner[name])
    permission=resource._fields(value['reservation_disclosure'],{'intent_sha256','until'})
    _require(permission['intent_sha256']==owner['reservation_disclosure']['intent_sha256']
        and source.stored_at<=value['issued_at']<=at
        and at<wire.u53(permission['until'])<=min(value['expires_at'],source.read_until,source.retain_until,
            *copy_source.additional_deadlines(source)))
    return item

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
            self.db.execute('CREATE TABLE IF NOT EXISTS ack_copy_prepare_uploads(job_id TEXT PRIMARY KEY,digest TEXT NOT NULL,raw BLOB NOT NULL)')
            self.db.execute('CREATE TABLE IF NOT EXISTS ack_copy_prepare_upload_work(id TEXT PRIMARY KEY,job_id TEXT NOT NULL,allowance INTEGER NOT NULL,actual INTEGER)')
            self.db.execute('CREATE TABLE IF NOT EXISTS ack_copy_prepare_assignments(job_id TEXT PRIMARY KEY,offer_ref BLOB NOT NULL,raw BLOB NOT NULL,ref BLOB NOT NULL)')

    def prepare_unbound(self, *args, **kwargs):
        return self._prepare(*args, **kwargs, offer_entry=None,source_state='unbound',bound={})

    def prepare_reservation_unbound(self,*args,**kwargs):
        """Return the allocation and its atomically checked observation snapshot."""
        return self._prepare(*args,**kwargs,offer_entry=None,with_status_snapshot=True,source_state='unbound',bound={})

    def assign_unbound(self, *args, offer_entry, **kwargs):
        """Bind the verified real offer to one durable COPY/READ/RETAIN assignment.

        The caller must still obtain original disclosure permission before upload.
        This assignment neither commits replica bytes nor advertises a provider.
        """
        return self._prepare(*args, **kwargs, offer_entry=offer_entry,source_state='unbound',bound={})

    def prepare_empty(self,*args,expected_receipt_writer,expected_message_id,expected_envelope_ref,**kwargs):
        return self._prepare(*args,**kwargs,offer_entry=None,source_state='empty',bound=dict(
            expected_receipt_writer=expected_receipt_writer,expected_message_id=expected_message_id,
            expected_envelope_ref=expected_envelope_ref))

    def prepare_occupied(self,*args,expected_receipt_writer,expected_message_id,expected_envelope_ref,**kwargs):
        return self._prepare(*args,**kwargs,offer_entry=None,source_state='occupied',bound=dict(
            expected_receipt_writer=expected_receipt_writer,expected_message_id=expected_message_id,
            expected_envelope_ref=expected_envelope_ref))

    def prepare_reservation_empty(self,*args,expected_receipt_writer,expected_message_id,expected_envelope_ref,**kwargs):
        return self._prepare(*args,**kwargs,offer_entry=None,with_status_snapshot=True,source_state='empty',bound=dict(
            expected_receipt_writer=expected_receipt_writer,expected_message_id=expected_message_id,
            expected_envelope_ref=expected_envelope_ref))

    def prepare_reservation_occupied(self,*args,expected_receipt_writer,expected_message_id,expected_envelope_ref,**kwargs):
        return self._prepare(*args,**kwargs,offer_entry=None,with_status_snapshot=True,source_state='occupied',bound=dict(
            expected_receipt_writer=expected_receipt_writer,expected_message_id=expected_message_id,
            expected_envelope_ref=expected_envelope_ref))

    def assign_empty(self,*args,offer_entry,expected_receipt_writer,expected_message_id,expected_envelope_ref,**kwargs):
        """Copy an existing binding without granting replacement receipt ADMIT."""
        return self._prepare(*args,**kwargs,offer_entry=offer_entry,source_state='empty',bound=dict(
            expected_receipt_writer=expected_receipt_writer,expected_message_id=expected_message_id,
            expected_envelope_ref=expected_envelope_ref))

    def assign_occupied(self,*args,offer_entry,expected_receipt_writer,expected_message_id,expected_envelope_ref,**kwargs):
        """Copy an existing binding without granting replacement receipt ADMIT."""
        return self._prepare(*args,**kwargs,offer_entry=offer_entry,source_state='occupied',bound=dict(
            expected_receipt_writer=expected_receipt_writer,expected_message_id=expected_message_id,
            expected_envelope_ref=expected_envelope_ref))

    def _prepare(self, manifest_entry, resolver, custody_entry, consent_entry, intent, *,
                        expected_ack_slot, expected_owner, expected_source, source_storage_epoch,
                        current_statuses, at, limit_policy, budget, offer_entry,source_state,bound,with_status_snapshot=False,recipient_reservation_entry=None):
        _require(not self.db.in_transaction)
        policy = self.policy
        wire._context(policy, budget)
        at = wire.u53(at)
        _require(self.keys['signing_key'] == self.identity.public_descriptor())
        binding = self.db.execute('SELECT value FROM ack_copy_prepare_binding WHERE id=1').fetchone()
        _require(binding is not None and bytes(binding[0]) == canonical_bytes(self.keys))
        source = copy_source.authenticate_source(manifest_entry, resolver, custody_entry,source_state=source_state,bound=bound,
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
            and value['scope'] == copy_source.source_scope(source)
            and value['historical_manifest_ref'] == wire.raw_ref(manifest_entry['ref']).as_dict())
        _require(all(value['budget'][name] <= root.payload['budget'][name] for name in resource._BUDGET)
            and all(value['windows'][name] <= root.payload['windows'][name] for name in resource._WINDOWS))
        digest = budget._hash(wire._canonical(value, budget))
        consent = index._signed(consent_entry, owner['signing_key'], 'ack.copy_reservation_consent', CONSENT_FIELDS, policy, budget)
        c = consent.payload
        index._timed(c, at); resource._opaque(c['consent_id']); wire.u53(c['revision'], 1)
        maximum = min(source.read_until, source.retain_until, active.payload['windows']['copy_until'],
            root.payload['windows']['copy_until'], root.payload['expires_at'], c['expires_at'], value['windows']['copy_until'],
            *copy_source.additional_deadlines(source))
        disclosure = resource._fields(c['reservation_disclosure'], {'intent_sha256', 'until'})
        _require(c['root_authority_ref'] == root.ref.as_dict() and c['source_custody_ref'] == source.custody.ref.as_dict()
            and c['historical_manifest_ref'] == value['historical_manifest_ref'] and c['maintainer'] == caller_id
            and c['target'] == value['target'] and c['target_storage_epoch'] == value['target_storage_epoch']
            and c['issued_at'] >= source.stored_at and disclosure['intent_sha256'] == digest
            and at < wire.u53(disclosure['until']) <= maximum)
        recipient_consent=_recipient_reservation(source,consent,recipient_reservation_entry,at,policy,budget)
        if recipient_consent is not None:
            maximum=min(maximum,recipient_consent.payload['expires_at'],recipient_consent.payload['reservation_disclosure']['until'])
        parties=(owner,source_keys,mine)+((source.receipt_writer,) if recipient_consent is not None else ())
        signers = {key['signing_key']['key_id']:key['signing_key'] for key in parties}
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
        obligations += copy_source.additional_obligations(source,owner,policy,budget)
        if recipient_consent is not None:
            signer=source.receipt_writer['signing_key']
            scope=index._authority(root_key,recipient_consent,policy,budget)
            allowed[signer['key_id']].append(dict(scope_kind='authority',scope_id=scope))
            obligations += (index._obligation(signer,'authority',scope,recipient_consent.payload['revision'],COPY),)
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
        consent_binding=consent.ref.as_dict() if recipient_consent is None else dict(owner=consent.ref.as_dict(),recipient=recipient_consent.ref.as_dict())
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
                    _require(old[0] == digest and bytes(old[1]) == canonical_bytes(consent_binding))
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
                        (value['job_id'],root_digest,digest,canonical_bytes(consent_binding),raw,canonical_bytes(result['ref'])))
            if result is not None and offer_entry is not None:
                result = self._assign_locked(result, offer_entry, source, value, digest, at, budget)
            if result is not None and with_status_snapshot:
                stamp=tuple((bytes(r[0]),bytes(r[1])) for r in self.db.execute('SELECT raw,ref FROM ack_copy_prepare_status WHERE root_digest=? ORDER BY raw_digest',(root_digest,)))
                result=dict(allocation=result,status_stamp=stamp)
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
            *(p['windows'][name] for name in ('read_until','copy_until','retain_until')),
            *copy_source.additional_deadlines(source))
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
            resource=p['resource'],bootstrap_grant_refs=copy_source.bootstrap_refs(source),budget=p['budget'],windows=p['windows'])
        raw = canonical_bytes(dict(payload=payload,proof=self.identity.sign_message(payload)))
        sha = hashlib.sha256(raw).hexdigest()
        result = dict(raw=raw,ref=dict(namespace='meta',key=sha,raw_sha256=sha,size=len(raw)))
        self.db.execute('INSERT INTO ack_copy_prepare_assignments VALUES(?,?,?,?)',
            (intent['job_id'],canonical_bytes(offer.ref.as_dict()),raw,canonical_bytes(result['ref'])))
        return result


    @contextmanager
    def _upload_transaction(self):
        _require(not self.db.in_transaction)
        self.db.execute('BEGIN IMMEDIATE')
        try:
            yield
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise

    def prepare_upload_unbound(self,*args,**options):
        return self._prepare_upload(*args,**options,source_state='unbound',bound={})

    def prepare_upload_empty(self,*args,expected_receipt_writer,expected_message_id,expected_envelope_ref,**options):
        return self._prepare_upload(*args,**options,source_state='empty',bound=dict(
            expected_receipt_writer=expected_receipt_writer,expected_message_id=expected_message_id,
            expected_envelope_ref=expected_envelope_ref))

    def prepare_upload_occupied(self,*args,expected_receipt_writer,expected_message_id,expected_envelope_ref,**options):
        return self._prepare_upload(*args,**options,source_state='occupied',bound=dict(
            expected_receipt_writer=expected_receipt_writer,expected_message_id=expected_message_id,
            expected_envelope_ref=expected_envelope_ref))

    def _prepare_upload(self,manifest_entry,resolver,custody_entry,allocation_entry,offer_entry,assignment_entry,
            reservation_entry,owner_disclosure_entry,source_disclosure_entry,*,expected_ack_slot,expected_owner,
            expected_source,source_storage_epoch,expected_target,target_storage_epoch,current_statuses,at,limit_policy,source_state,bound,recipient_reservation_entry=None,recipient_disclosure_entry=None):
        """Retain one exact outgoing stage only after original COPY/disclosure checks.

        No bytes are transmitted. Destination possession must precede any send.
        Authenticated denial observations survive even a later preparation failure.
        """
        import memory_vault_open_repair_copy_authority as authority
        import memory_vault_open_repair_stage as stage
        from memory_vault_open_repair_index_state import encode_entry,decode_entry
        policy=self.policy;budget=resolver.budget;wire._context(policy,budget);at=wire.u53(at)
        _require(not self.db.in_transaction and resolver.policy is policy and policy.max_signature_checks<=64)
        def freeze(entry):
            wire.object_fields(entry,{'raw','ref'})
            return dict(raw=wire._snapshot(entry['raw'],policy,budget),ref=wire.raw_ref(entry['ref']).as_dict())
        manifest_entry,custody_entry,allocation_entry,offer_entry,assignment_entry,reservation_entry,owner_disclosure_entry,source_disclosure_entry=map(freeze,
            (manifest_entry,custody_entry,allocation_entry,offer_entry,assignment_entry,reservation_entry,owner_disclosure_entry,source_disclosure_entry))
        if type(current_statuses) not in (list,tuple) or not 1<=len(current_statuses)<=16:wire._fail('repair_status_missing')
        if recipient_reservation_entry is not None:recipient_reservation_entry=freeze(recipient_reservation_entry)
        if recipient_disclosure_entry is not None:recipient_disclosure_entry=freeze(recipient_disclosure_entry)
        current_statuses=tuple(map(freeze,current_statuses))
        binding=wire.build_new_wire(dict(slot=expected_ack_slot,owner=expected_owner,source=expected_source,target=expected_target),policy,budget).value
        expected_ack_slot,expected_owner,expected_source,expected_target=(binding[k] for k in ('slot','owner','source','target'))
        local_binding=self.db.execute('SELECT value FROM ack_copy_prepare_binding WHERE id=1').fetchone()
        _require(local_binding is not None and bytes(local_binding[0])==canonical_bytes(self.keys))
        allocation=wire.parse_new_wire(allocation_entry['raw'],policy,budget).value['payload']
        intent=allocation['intent'];job=intent['job_id'];root=intent['root_key']
        root_digest=budget._hash(wire._canonical(root,budget))
        saved=self.db.execute('SELECT request,ref FROM ack_copy_prepare_jobs WHERE job_id=?',(job,)).fetchone()
        assigned=self.db.execute('SELECT raw,ref FROM ack_copy_prepare_assignments WHERE job_id=?',(job,)).fetchone()
        _require(saved is not None and assigned is not None
            and dict(raw=bytes(saved[0]),ref=json.loads(bytes(saved[1])))==allocation_entry
            and dict(raw=bytes(assigned[0]),ref=json.loads(bytes(assigned[1])))==assignment_entry)
        if source_state=='occupied':
            if recipient_reservation_entry is None:wire._fail('repair_copy_recipient_consent_missing')
            consent_binding=dict(owner=reservation_entry['ref'],recipient=recipient_reservation_entry['ref'])
            held_binding=self.db.execute('SELECT consent_ref FROM ack_copy_prepare_jobs WHERE job_id=?',(job,)).fetchone()
            _require(held_binding is not None and bytes(held_binding[0])==canonical_bytes(consent_binding))
        ticket=secrets.token_hex(16);allowance=policy.max_signature_checks
        with self._upload_transaction():
            blocked=self.db.execute("SELECT reason FROM ack_copy_prepare_blocked WHERE root_digest IN (?, '*')",(root_digest,)).fetchone()
            if blocked:wire._fail(blocked[0])
            count,used=self.db.execute('SELECT count(*),coalesce(sum(coalesce(actual,allowance)),0) FROM ack_copy_prepare_upload_work WHERE job_id=?',(job,)).fetchone()
            maximum=min(64,intent['budget']['max_requests'])
            if count>=maximum or used+allowance>maximum*64:wire._fail('repair_copy_work_capacity')
            self.db.execute('INSERT INTO ack_copy_prepare_upload_work VALUES(?,?,?,NULL)',(ticket,job,allowance))
        def observe(item):
            with self._upload_transaction():
                held=self.db.execute('SELECT raw,ref FROM ack_copy_prepare_status WHERE root_digest=? AND raw_digest=?',(root_digest,item.ref.raw_sha256)).fetchone()
                if held is not None:return
                count,size=self.db.execute('SELECT count(*),coalesce(sum(length(raw)+length(ref)),0) FROM ack_copy_prepare_status').fetchone()
                encoded=canonical_bytes(item.ref.as_dict())
                if count>=64 or size+len(item.raw)+len(encoded)>1048576:
                    self.db.execute("INSERT OR IGNORE INTO ack_copy_prepare_blocked VALUES('*','repair_copy_journal_capacity')")
                    return
                self.db.execute('INSERT INTO ack_copy_prepare_status VALUES(?,?,?,?)',(root_digest,item.ref.raw_sha256,item.raw,encoded))
        try:
            plan=authority._verify_copy(manifest_entry,resolver,custody_entry,allocation_entry,offer_entry,assignment_entry,
                reservation_entry,owner_disclosure_entry,source_disclosure_entry,expected_ack_slot=expected_ack_slot,
                expected_owner=expected_owner,expected_source=expected_source,source_storage_epoch=source_storage_epoch,
                expected_maintainer=self.keys,expected_target=expected_target,target_storage_epoch=target_storage_epoch,
                current_statuses=current_statuses,at=at,limit_policy=limit_policy,policy=policy,budget=budget,on_observed=observe,
                source_state=source_state,bound=bound,recipient_reservation_entry=recipient_reservation_entry,recipient_disclosure_entry=recipient_disclosure_entry)
            signers={p['signing_key']['key_id']:p['signing_key'] for p in (expected_owner,expected_source,self.keys)}
            if copy_source.occupied_source(plan.source):
                signer=plan.source.receipt_writer['signing_key'];signers[signer['key_id']]=signer
            previous=[]
            # All prior facts, including expired ones, remain lower bounds.
            status_rows=list(self.db.execute('SELECT raw,ref FROM ack_copy_prepare_status WHERE root_digest=? ORDER BY raw_digest',(root_digest,)))
            status_stamp=tuple((bytes(row[0]),bytes(row[1])) for row in status_rows)
            for raw,ref in status_rows:
                payload=wire.parse_new_wire(bytes(raw),policy,budget).value['payload']
                issuer=payload['signing_key']['key_id']
                if issuer not in signers:wire._fail('repair_status_mismatch')
                previous.append(status.authenticate_status_original(dict(raw=bytes(raw),ref=json.loads(bytes(ref))),
                    expected_root=root,expected_signing_key=signers[issuer],at=payload['issued_at'],
                    allowed_scopes=[dict(scope_kind=e['scope_kind'],scope_id=e['scope_id']) for e in payload['entries']],policy=policy,budget=budget))
            empty._history_floors((*plan.source.statuses,*previous,*plan.statuses),previous=previous,current=plan.statuses)
            if plan.denial_code:wire._fail(plan.denial_code)
            for old in previous:
                for e in old.payload['entries']:
                    if any(old.payload['signing_key']==need['signer'] and (e['scope_kind'],e['scope_id'])==(need['scope_kind'],need['scope_id'])
                           and e['status']=='revoked' for need in plan.obligations):wire._fail('repair_authority_revoked')
            rows={}
            def add(role,item):
                if hasattr(item,'raw'):item=index._entry(item)
                reference=wire.raw_ref(item['ref'])
                if len(item['raw'])!=reference.size or budget._hash(item['raw'])!=reference.raw_sha256:wire._fail('repair_ref_mismatch')
                rows[(role,*history._ref_tuple(reference))]=dict(role=role,entry=item)
            for item in plan.originals:add(item.role,item.original)
            for role,item in (('copy.allocation',plan.allocation),('copy.offer',plan.offer),
                    ('copy.assignment',plan.assignment),('copy.owner_disclosure',plan.disclosures[0]),('copy.source_disclosure',plan.disclosures[1])):add(role,item)
            if copy_source.occupied_source(plan.source):add('copy.recipient_disclosure',plan.disclosures[2])
            for role,entry,source_manifest in copy_source.source_histories(plan.source,manifest_entry):
                add(role,entry)
                for member in source_manifest.manifest.value['roles']:add('history.raw_pack',resolver.resolve(member['pack_ref']))
            for item in plan.statuses:add('copy.current_status',item)
            if copy_source.occupied_source(plan.source):
                rows={key:value for key,value in rows.items() if value['role'] in stage.OCCUPIED_COPY_ROLES}
            children=[rows[k] for k in sorted(rows)]
            manifest=stage.make_stage_manifest(root_key=root,scope=intent['scope'],consumer='ack_copy_'+source_state,
                children=[dict(index=i,role=e['role'],ref=e['entry']['ref']) for i,e in enumerate(children)],policy=policy,budget=budget)
            semantic=dict(allocation_ref=allocation_entry['ref'],assignment_ref=assignment_entry['ref'],manifest=manifest.value,
                children=[dict(role=e['role'],entry=encode_entry(e['entry'])) for e in children],target=expected_target,
                target_storage_epoch=target_storage_epoch)
            document=wire.build_new_wire(semantic,policy,budget);semantic=document.value
            digest=budget._hash(document.raw)
            until=min(at+60,plan.read_until,plan.retain_until,plan.offer.payload['reservation_until'],allocation['expires_at'])
            if at>=until:wire._fail('repair_resource_expired')
            options=dict(expected_subject=self.keys,expected_target=expected_target,target_storage_epoch=target_storage_epoch,
                at=at,expected_consumer='ack_copy_'+source_state,policy=policy,budget=budget)
            with self._upload_transaction():
                blocked=self.db.execute("SELECT reason FROM ack_copy_prepare_blocked WHERE root_digest IN (?, '*')",(root_digest,)).fetchone()
                if blocked:wire._fail(blocked[0])
                current_stamp=tuple((bytes(row[0]),bytes(row[1])) for row in self.db.execute('SELECT raw,ref FROM ack_copy_prepare_status WHERE root_digest=? ORDER BY raw_digest',(root_digest,)))
                if current_stamp!=status_stamp:wire._fail('repair_status_changed')
                prior=self.db.execute('SELECT digest,raw FROM ack_copy_prepare_uploads WHERE job_id=?',(job,)).fetchone()
                if prior is not None:
                    if prior[0]!=digest:wire._fail('repair_copy_upload_conflict')
                    held=wire.parse_new_wire(bytes(prior[1]),policy,budget).value
                    if held['semantic']!=semantic:wire._fail('repair_storage_corrupt')
                    outgoing=decode_entry(held['intent'],policy,budget)
                    checked=stage.verify_stage_intent(outgoing,**options)
                    if checked.payload['manifest']!=manifest.value or checked.payload['expires_at']>until:wire._fail('repair_copy_upload_conflict')
                    return dict(intent=outgoing,children=tuple(children),expires_at=checked.payload['expires_at'],status_stamp=status_stamp)
                outgoing=stage.make_stage_intent(self.identity,allocation_id=intent['allocation_id'],manifest=manifest.value,expires_at=until,**options)
                raw=wire.build_new_wire(dict(semantic=semantic,intent=encode_entry(outgoing)),policy,budget).raw
                count,size=self.db.execute('SELECT count(*),coalesce(sum(length(raw)),0) FROM ack_copy_prepare_uploads').fetchone()
                if count>=16 or size+len(raw)>4194304 or len(raw)>intent['budget']['max_job_bytes']:wire._fail('repair_copy_journal_capacity')
                self.db.execute('INSERT INTO ack_copy_prepare_uploads VALUES(?,?,?)',(job,digest,raw))
                return dict(intent=index._entry(outgoing),children=tuple(children),expires_at=until,status_stamp=status_stamp)
        finally:
            actual=budget.snapshot()['signature_checks']
            with self._upload_transaction():
                held=self.db.execute('SELECT allowance,actual FROM ack_copy_prepare_upload_work WHERE id=?',(ticket,)).fetchone()
                if held is None or held[1] is not None or not 0<=actual<=held[0]:wire._fail('repair_service_work_corrupt')
                self.db.execute('UPDATE ack_copy_prepare_upload_work SET actual=? WHERE id=?',(actual,ticket))
