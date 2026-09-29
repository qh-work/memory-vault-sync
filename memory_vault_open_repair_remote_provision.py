"""Prepare an independent ACK source with only A's own keys and network state.

R receives existing signed resource authorities, never message plaintext, the
approved contact session or either participant's private identity. The complete
live source is read before the first delivery ciphertext is permitted.
"""
import asyncio
import hashlib
import json
import time
from types import SimpleNamespace

from memory_vault import canonical_bytes
from memory_vault_open_agent_setup import fetch_introductions
from memory_vault_open_delivery_client import OpenDeliveryClient
from memory_vault_open_provider_client import OpenProviderClient
from memory_vault_open_repair_bind_client import OwnerAckBindClient
from memory_vault_open_repair_client import AckOwnerRecoveryClient
from memory_vault_open_repair_provision import (
    AckSourceProvisioner, PROFILES, MAX_RECORDS, MAX_RECORD_BYTES,
    _entry, _encoded, _decoded, _fail, encode_original,
)
from memory_vault_open_repair_index_state import decode_entry
from memory_vault_open_repair_state import DEFAULT_POLICY
import memory_vault_open_repair_original as original
import memory_vault_open_repair_resource as resource
import memory_vault_open_repair_wire as wire

SCHEMA = 'memory-vault-open-repair/v1'
MAX_CONTROL_BYTES = 65536
MAX_OBSERVED_STATUSES = 32
MAX_OBSERVED_BYTES = 512 * 1024
STATUS_ROW_BYTES = 256


class _RepairTransferMeter:
    """Persist each serialized request and worst-case response before IO.

    This body-byte measure excludes HTTP/TLS framing. A failed request keeps its
    entire allowance; successful small responses do not replenish the budget.
    """
    def __init__(self, owner):
        self.owner = owner

    def request_repair(self, base, raw, *, child=False, deadline):
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_CONTROL_BYTES:
            _fail('repair_control_too_large')
        self.owner._charge(1, len(raw) + MAX_CONTROL_BYTES)
        return self.owner.delivery.participant.transport.request_repair(base, raw, child=child, deadline=deadline)


class RemoteAckSourceProvisioner(AckSourceProvisioner):
    def __init__(self, delivery_client):
        if type(delivery_client) is not OpenDeliveryClient:
            _fail('repair_invalid_context')
        self.delivery = delivery_client
        self.owner = dict(signing_key=delivery_client.identity.public_descriptor(),
                          encryption_key=delivery_client.encryption.public_descriptor())
        self.policy = DEFAULT_POLICY
        self.transfer = _RepairTransferMeter(self)
        with self.delivery.participant.state.db() as db:
            db.execute('''CREATE TABLE IF NOT EXISTS open_repair_source_provision(
                request_id TEXT PRIMARY KEY,plan BLOB NOT NULL,steps BLOB NOT NULL)''')
            db.execute('''CREATE TABLE IF NOT EXISTS open_repair_remote_provision_work(
                request_id TEXT PRIMARY KEY,origin TEXT NOT NULL,node_key_id TEXT NOT NULL,
                calls INTEGER NOT NULL,requests INTEGER NOT NULL,wire_bytes INTEGER NOT NULL)''')
            db.execute('''CREATE TABLE IF NOT EXISTS open_repair_remote_status_state(
                request_id TEXT PRIMARY KEY,generation INTEGER NOT NULL,blocked_code TEXT)''')
            db.execute('''CREATE TABLE IF NOT EXISTS open_repair_remote_status_originals(
                request_id TEXT NOT NULL,observation_id TEXT NOT NULL,reference BLOB NOT NULL,original BLOB NOT NULL,
                PRIMARY KEY(request_id,observation_id))''')

    def _status_plan(self, db):
        row = db.execute('SELECT plan FROM open_repair_source_provision WHERE request_id=?',
                         (self.plan['request_id'],)).fetchone()
        if row is None or _decoded(json.loads(bytes(row[0]))) != self.plan:
            _fail('repair_provision_conflict')

    def _status_context(self, *entries):
        """Read one immutable archive snapshot for a finite recovery call."""
        request_id = self.plan['request_id']
        with self.delivery.participant.state.db() as db:
            db.execute('BEGIN IMMEDIATE')
            self._status_plan(db)
            db.execute('INSERT OR IGNORE INTO open_repair_remote_status_state VALUES(?,0,NULL)', (request_id,))
            state = db.execute('SELECT generation,blocked_code FROM open_repair_remote_status_state WHERE request_id=?',
                               (request_id,)).fetchone()
            if state['blocked_code']:
                _fail(state['blocked_code'])
            rows = db.execute('SELECT reference,original FROM open_repair_remote_status_originals WHERE request_id=? ORDER BY observation_id',
                              (request_id,)).fetchall()
        if (len(rows)>MAX_OBSERVED_STATUSES or
                sum(len(row['reference'])+len(row['original'])+STATUS_ROW_BYTES for row in rows)>MAX_OBSERVED_BYTES):
            _fail('repair_status_history_capacity')
        archived = [dict(raw=bytes(row['original']),ref=json.loads(bytes(row['reference']))) for row in rows]
        unique = {}
        for entry in (*archived,*(item for group in entries for item in group)):
            key = (entry['raw'],wire.raw_ref(entry['ref']))
            unique.setdefault(key,dict(raw=entry['raw'],ref=key[1].as_dict()))
        if len(unique)>MAX_OBSERVED_STATUSES:
            _fail('repair_status_history_capacity')
        return SimpleNamespace(generation=state['generation'],archive=tuple(unique.values()))

    def _observe_status(self, context, observed):
        """Private callback: only the complete source verifier calls this.

        The signature and every typed scope have already been authenticated.
        Persist before its operation/expiry decision; never infer active access
        from the callback, and never spend another signature check here.
        """
        p = self.plan
        if (observed.payload['scope_key']['root_key'] != p['slot']['root_key'] or
                observed.payload['scope_key']['issuer_key_id'] not in
                (p['owner']['signing_key']['key_id'],p['target']['signing_key']['key_id'])):
            _fail('repair_status_mismatch')
        reference,raw = canonical_bytes(observed.ref.as_dict()),observed.raw
        identity = hashlib.sha256(reference+raw).hexdigest()
        code = None
        with self.delivery.participant.state.db() as db:
            db.execute('BEGIN IMMEDIATE')
            self._status_plan(db)
            state = db.execute('SELECT generation,blocked_code FROM open_repair_remote_status_state WHERE request_id=?',
                               (p['request_id'],)).fetchone()
            if state is None:
                _fail('repair_provision_status_changed')
            if state['blocked_code']:
                _fail(state['blocked_code'])
            row = db.execute('SELECT reference,original FROM open_repair_remote_status_originals WHERE request_id=? AND observation_id=?',
                             (p['request_id'],identity)).fetchone()
            generation = state['generation']
            if row is None:
                usage = db.execute('SELECT count(*),coalesce(sum(length(reference)+length(original)+?),0) FROM open_repair_remote_status_originals WHERE request_id=?',
                                   (STATUS_ROW_BYTES,p['request_id'])).fetchone()
                if usage[0]>=MAX_OBSERVED_STATUSES or usage[1]+len(reference)+len(raw)+STATUS_ROW_BYTES>MAX_OBSERVED_BYTES:
                    code = 'repair_status_history_capacity'
                    db.execute('UPDATE open_repair_remote_status_state SET generation=generation+1,blocked_code=? WHERE request_id=?',
                               (code,p['request_id']))
                else:
                    db.execute('INSERT INTO open_repair_remote_status_originals VALUES(?,?,?,?)',
                               (p['request_id'],identity,reference,raw))
                    generation += 1
                    db.execute('UPDATE open_repair_remote_status_state SET generation=? WHERE request_id=?',
                               (generation,p['request_id']))
            elif bytes(row['reference'])!=reference or bytes(row['original'])!=raw:
                _fail('repair_ref_conflict')
            if code is None and state['generation'] != context.generation:
                code = 'repair_provision_status_changed'
        if code:
            _fail(code)
        context.generation = generation

    def _status_guard(self, context, db=None):
        if db is None:
            with self.delivery.participant.state.db() as connection:
                connection.execute('BEGIN IMMEDIATE')
                return self._status_guard(context,connection)
        self._status_plan(db)
        state = db.execute('SELECT generation,blocked_code FROM open_repair_remote_status_state WHERE request_id=?',
                           (self.plan['request_id'],)).fetchone()
        if state is None or state['generation'] != context.generation:
            _fail('repair_provision_status_changed')
        if state['blocked_code']:
            _fail(state['blocked_code'])

    def _charge(self, requests, wire_bytes):
        """Reserve worst-case work before IO; failures and crashes retain it."""
        with self.delivery.participant.state.db() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM open_repair_remote_provision_work WHERE request_id=?',
                             (self.request_id,)).fetchone()
            if row is None:
                if db.execute('SELECT count(*) FROM open_repair_remote_provision_work').fetchone()[0] >= MAX_RECORDS:
                    _fail('repair_provision_capacity')
                db.execute('INSERT INTO open_repair_remote_provision_work VALUES(?,?,?,0,0,0)',
                           (self.request_id, self.base_url, self.node_key_id))
                row = db.execute('SELECT * FROM open_repair_remote_provision_work WHERE request_id=?',
                                 (self.request_id,)).fetchone()
            if row['origin'] != self.base_url or row['node_key_id'] != self.node_key_id:
                _fail('repair_provision_conflict')
            if row['calls'] >= 1024 or row['requests'] + requests > 1024 or row['wire_bytes'] + wire_bytes > 64 * 1024 * 1024:
                _fail('repair_provision_work_exhausted')
            db.execute('UPDATE open_repair_remote_provision_work SET calls=calls+1,requests=requests+?,wire_bytes=wire_bytes+? WHERE request_id=?',
                       (requests, wire_bytes, self.request_id))

    def _remaining(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            _fail('repair_invalid_deadline')
        return min(30, remaining)

    async def queue_and_prepare(self, request_id, recipient, *, source_url, source_key_id,
                                text='', memory_ids=None, profile='receipt', lifetime=3600,copy_maintainer=None):
        digest, selected = self.delivery._send_input(request_id, [recipient], text, memory_ids, None)
        self.delivery._prepare_outbox(request_id, recipient, digest, text, selected)
        return await self.prepare_existing(request_id, source_url=source_url, source_key_id=source_key_id,
                                           profile=profile, lifetime=lifetime,copy_maintainer=copy_maintainer)

    async def prepare_existing(self, request_id, *, source_url, source_key_id, profile='receipt', lifetime=3600,copy_maintainer=None):
        if type(profile) is not str or profile not in PROFILES or type(lifetime) is not int or not 120 <= lifetime <= 86400:
            _fail('repair_invalid_request_bundle')
        resource._opaque(request_id)
        from memory_vault_open_repair_provision import _copy_maintainer
        copy_maintainer=_copy_maintainer(copy_maintainer,profile,self.policy)
        self._unsent(self.delivery._outbox(request_id))
        from memory_vault_open_transport import endpoint
        from memory_vault_open_control import coordinate
        endpoint(source_url, allow_loopback=self.delivery.participant.transport.allow_loopback)
        coordinate(source_key_id)
        self.request_id, self.base_url, self.node_key_id = request_id, source_url.rstrip('/'), source_key_id
        self.deadline = time.monotonic() + 120
        held = self._load(request_id)
        if held is not None:
            if held[0].get('copy_maintainer')!=copy_maintainer:_fail('repair_provision_conflict')
            if held[1] and 'remote_context' not in held[1]:
                _fail('repair_provision_context_mismatch')
            prior = json.loads(held[0]['node']['raw'])['payload']
            if prior['base_url'] != self.base_url or prior['signing_key']['key_id'] != source_key_id:
                _fail('repair_provision_conflict')
        self._charge(4, 8 * MAX_CONTROL_BYTES)
        node = (await asyncio.to_thread(fetch_introductions, self.delivery.identity,
            [(self.base_url, source_key_id)], allow_loopback=self.delivery.participant.transport.allow_loopback))[0]
        self.delivery.participant._accept(node)
        provider = OpenProviderClient(self.delivery.participant, self.delivery.encryption)
        target_record = await provider.prove_target(node)
        target = dict(signing_key=target_record['payload']['signing_key'],
                      encryption_key=target_record['payload']['targetEncryptionKey'])
        if held is not None:
            if held[0]['target'] != target or held[0]['epoch'] != node['payload']['storage_epoch']:
                _fail('repair_provision_conflict')
            frozen_node = json.loads(held[0]['node']['raw'])
        else:
            frozen_node = node
        self.source = SimpleNamespace(target=target, node=frozen_node, limits=PROFILES[profile],
                                      _now=lambda: int(time.time()))
        self.empty = SimpleNamespace(bind=self._remote_bind)
        return await super().prepare_existing(request_id, profile=profile, lifetime=lifetime,copy_maintainer=copy_maintainer)

    def _request(self, value, response_kind, fields):
        raw = canonical_bytes(value)
        if len(raw) > MAX_CONTROL_BYTES:
            _fail('repair_control_too_large')
        reference = _entry(raw)['ref']
        response = self.transfer.request_repair(self.base_url, raw,
            deadline=time.monotonic() + self._remaining())
        budget = wire.RepairBudget(self.policy)
        parsed = wire.parse_new_wire(response, self.policy, budget)
        result = wire.object_fields(parsed.value, {'schema_version', 'kind', 'request_ref'} | set(fields))
        if result['schema_version'] != SCHEMA or result['kind'] != response_kind or result['request_ref'] != reference:
            _fail('repair_provision_response_mismatch')
        return {name: decode_entry(result[name], self.policy, budget) for name in fields}

    def _verify_offer(self, offer, allocation):
        budget = wire.RepairBudget(self.policy)
        parsed = wire.parse_new_wire(offer['raw'], self.policy, budget)
        signed = wire.object_fields(parsed.value, {'payload', 'proof'})
        payload = resource._fields(signed['payload'], resource.COMMON | set(resource._FIELDS[1].split()))
        if payload['schema_version'] != resource.SCHEMA or payload['kind'] != 'resource.offer':
            _fail('repair_provision_response_mismatch')
        resource._role_shape('offer', payload)
        original._verify_control_signature(payload, signed['proof'], self.plan['target']['signing_key'], budget)
        expected = json.loads(allocation['raw'])['payload']
        if (budget._hash(parsed.raw) != offer['ref']['raw_sha256'] or len(offer['raw']) != offer['ref']['size']
                or payload['allocation_request_ref'] != allocation['ref'] or payload['intent'] != expected['intent']
                or payload['intent_sha256'] != expected['intent_sha256']
                or payload['target_encryption_key'] != self.plan['target']['encryption_key']
                or payload['resource']['node_key_id'] != self.node_key_id
                or payload['resource']['storage_epoch'] != self.plan['epoch']
                or payload['budget'] != self.plan['caps']
                or payload['windows'] != expected['intent']['windows']):
            _fail('repair_provision_response_mismatch')

    def _provision_unbound(self):
        p = self.plan
        self._step('remote_context', lambda: dict(origin=self.base_url, node_key_id=self.node_key_id))
        windows = {name: p['until'] for name in resource._WINDOWS}
        allocation = self._step('allocation', lambda: self._sign('resource.allocate', issued_at=p['created_at'],
            expires_at=p['until'], request_id='allocate_' + p['token'], target_node_key_id=self.node_key_id,
            target_storage_epoch=p['epoch'], **self._allocation(windows)))
        carrier = dict(schema_version=SCHEMA, kind='ack.source_allocate', owner=self.owner,
                       allocation=encode_original(allocation))
        offer = self._step('offer', lambda: self._request(carrier, 'ack.source_allocation', ('offer',))['offer'])
        self._verify_offer(offer, allocation)
        setup = self._step('setup', lambda: self._build_owner_setup(offer))
        base = [('ack.root_authority', setup['root']), ('ack.read_grant', setup['read']), ('bootstrap.grant', setup['bootstrap'])]
        held=self._load(p['request_id'])
        # Existing combined originals remain immutable on resumed setups.
        split='root_status' in held[1] or 'owner_status' not in held[1]
        root_status=self._step('root_status',lambda:self._status(base[:1],1,include_slot=False)) if split else None
        owner_status = self._step('owner_status', lambda: self._status(base[1:] if split else base, 2))
        def make_finish():
            now = int(time.time())
            payload = dict(schema_version=SCHEMA, kind='ack.source_setup', signing_key=self.owner['signing_key'],
                issued_at=now, expires_at=min(p['until'], now + 60), request_id='setup_' + p['token'],
                subject=self.owner, target=p['target'], target_storage_epoch=p['epoch'],
                allocation_ref=allocation['ref'], offer_ref=offer['ref'], ack_slot=p['slot'],
                node=encode_original(p['node']), owner_status=encode_original(owner_status),
                read_until=p['until'], retain_until=p['until'],
                **{name: encode_original(value) for name, value in setup.items()})
            if root_status is not None:payload['root_status']=encode_original(root_status)
            return dict(payload=payload, proof=self.delivery.identity.sign_message(payload))
        finish = self._step('remote_setup_request', make_finish)
        def finish_or_reconcile():
            if int(time.time()) < finish['payload']['expires_at']:
                return self._request(finish, 'ack.source_ready', ('active', 'status', 'custody'))
            # A lost success response never justifies re-signing an expired
            # setup request. Independently read the actual original source.
            context = self._status_context([owner_status])
            recovered = self._recovery(context).recover(self.base_url, target_node_entry=p['node'],
                expected_target=p['target'], expected_ack_slot=p['slot'], root_entry=setup['root'],
                read_entry=setup['read'], bootstrap_entry=setup['bootstrap'], known_statuses=[owner_status],
                archive_statuses=context.archive,
                timeout=self._remaining())
            self._status_guard(context)
            roles = {role.role: role.original for role in recovered.source.manifest.roles}
            def entry(value):
                return dict(raw=value.raw, ref=value.ref.as_dict())
            return dict(active=entry(roles['resource.ack_active']),
                        status=entry(roles['historical.status.ack_resource']), custody=entry(recovered.source.custody))
        response = self._step('remote_setup_response', finish_or_reconcile)
        self.unbound = dict(resource_id=json.loads(offer['raw'])['payload']['resource']['resource_id'], setup=setup,
            active=dict(active=response['active'], status=response['status']), owner_status=owner_status,
            custody=response['custody'], offer=offer, allocation=allocation)
        if root_status is not None:self.unbound['root_status']=root_status
        return self.unbound

    def _recovery(self, context, cls=AckOwnerRecoveryClient):
        from dataclasses import replace
        # Binding verifies both complete unbound and empty histories in one
        # local operation. Separate originals add real signature work. This
        # finite client CPU budget changes no signed service/resource limit.
        policy=replace(self.policy,max_signature_checks=96) if cls is OwnerAckBindClient else self.policy
        return cls(self.delivery.identity, self.delivery.encryption, policy=policy,
                   limit_policy=PROFILES[self.plan['profile']], transport=self.transfer,
                   allow_loopback=self.delivery.participant.transport.allow_loopback,
                   status_observer=lambda observed:self._observe_status(context,observed))

    def _recovery_inputs(self):
        setup = self.unbound['setup']
        return dict(target_node_entry=self.plan['node'], expected_target=self.plan['target'],
            expected_ack_slot=self.plan['slot'], root_entry=setup['root'], read_entry=setup['read'],
            bootstrap_entry=setup['bootstrap'])

    def _authorize_encryption(self, unbound):
        p = self.plan
        marker = dict(resource_id=unbound['resource_id'], custody_ref=unbound['custody']['ref'],
                      session_sha256=hashlib.sha256(p['session']).hexdigest())
        held = self._load(p['request_id'])
        actual = self.delivery._outbox(p['request_id']); self._unsent(actual)
        if held is None or held[0] != p:
            _fail('repair_provision_conflict')
        if 'encryption_authorized' in held[1]:
            if held[1]['encryption_authorized'] != marker:
                _fail('repair_provision_conflict')
            if actual['envelope'] is not None:
                return
        known = [unbound['owner_status'], unbound['active']['status']]+([unbound['root_status']] if 'root_status' in unbound else [])
        context = self._status_context(known)
        recovered = self._recovery(context).recover(self.base_url, **self._recovery_inputs(),
            known_statuses=known, archive_statuses=context.archive, timeout=self._remaining())
        if recovered.source.custody.raw != unbound['custody']['raw'] or recovered.source.custody.ref.as_dict() != marker['custody_ref']:
            _fail('repair_provision_response_mismatch')
        expected = {'ack.root_authority': unbound['setup']['root'], 'ack.read_grant': unbound['setup']['read'],
            'bootstrap.ack_owner': unbound['setup']['bootstrap'], 'resource.ack_activation': unbound['setup']['activation'],
            'resource.ack_allocate': unbound['allocation'], 'resource.ack_offer': unbound['offer'],
            'resource.ack_active': unbound['active']['active'], 'historical.status.ack_resource': unbound['active']['status'],
            'source.descriptor': p['node']}
        expected.update({name:unbound['owner_status'] for name in ('historical.status.ack_root',
            'historical.status.ack_read','historical.status.ack_owner_bootstrap','historical.status.ack_slot')})
        if 'root_status' in unbound:expected['historical.status.ack_root']=unbound['root_status']
        for role in recovered.source.manifest.roles:
            if role.role in expected and (role.original.raw != expected[role.role]['raw']
                    or role.original.ref.as_dict() != expected[role.role]['ref']):
                _fail('repair_provision_response_mismatch')
        with self.delivery.participant.state.db() as db:
            db.execute('BEGIN IMMEDIATE')
            self._status_guard(context,db)
            row = db.execute('SELECT plan,steps FROM open_repair_source_provision WHERE request_id=?', (p['request_id'],)).fetchone()
            if row is None or _decoded(json.loads(bytes(row[0]))) != p:
                _fail('repair_provision_conflict')
            steps = _decoded(json.loads(bytes(row[1])))
            current = db.execute('SELECT * FROM open_delivery_outbox WHERE request_id=?', (p['request_id'],)).fetchone()
            self._unsent(current)
            if current['envelope'] is not None or current['session'] is not None:
                _fail('repair_provision_preexisting_envelope')
            if (current['input_sha256'] != p['input_sha256'] or current['message_id'] != p['message_id']
                    or hashlib.sha256(bytes(current['body'])).hexdigest() != p['body_sha256']):
                _fail('repair_provision_outbox_mismatch')
            if 'encryption_authorized' in steps and steps['encryption_authorized'] != marker:
                _fail('repair_provision_conflict')
            steps['encryption_authorized'] = marker
            raw = canonical_bytes(_encoded(steps))
            if len(row[0]) + len(raw) > MAX_RECORD_BYTES:
                _fail('repair_provision_capacity')
            db.execute('UPDATE open_repair_source_provision SET steps=? WHERE request_id=?', (raw, p['request_id']))

    def _binding_statuses(self, base_authorities, write, bootstrap, active):
        # These two authorities are new. Retain the exact previously published
        # status of every old scope, so the live unbound preflight stays current.
        new_scopes = self._status([('ack.write_grant', write), ('bootstrap.grant', bootstrap)],
                                 3, include_slot=False)
        return [self.unbound['owner_status'], new_scopes, active['status']]+([self.unbound['root_status']] if 'root_status' in self.unbound else [])

    def _remote_bind(self, resource_id, write_entry, offer_bootstrap_entry, *, expected_receipt_writer,
                     expected_message_id, expected_envelope_ref, current_statuses, read_until, retain_until):
        from memory_vault_open_repair_bind_journal import OwnerBindJournal
        if resource_id != self.unbound['resource_id']:
            _fail('repair_provision_conflict')
        inputs = dict(**self._recovery_inputs(), write_entry=write_entry, offer_bootstrap_entry=offer_bootstrap_entry,
            expected_receipt_writer=expected_receipt_writer, expected_message_id=expected_message_id,
            expected_envelope_ref=expected_envelope_ref, current_statuses=current_statuses,
            read_until=read_until, retain_until=retain_until,
            known_statuses=[self.unbound['owner_status'], self.unbound['active']['status']]+([self.unbound['root_status']] if 'root_status' in self.unbound else []), timeout=self._remaining())
        context = self._status_context(inputs['known_statuses'])
        inputs['archive_statuses'] = context.archive
        with self.delivery.participant.state.db() as db:
            journal = OwnerBindJournal(db); journal.initialize()
            binder = self._recovery(context,OwnerAckBindClient)
            try:
                result = binder.bind(self.base_url, **inputs, journal=journal)
            except wire.RepairWireError as exc:
                if exc.code != 'repair_reconciliation_required':
                    raise
                # Reconciliation reads an actual matching empty source. It
                # neither extends the old bind carrier nor creates another E.
                key = binder.journal_key(expected_target=self.plan['target'], expected_ack_slot=self.plan['slot'])
                observations = journal.observations(key)
                context = self._status_context(current_statuses,observations)
                recovered = self._recovery(context).recover_empty(self.base_url, **self._recovery_inputs(),
                    expected_receipt_writer=expected_receipt_writer, expected_message_id=expected_message_id,
                    expected_envelope_ref=expected_envelope_ref, known_statuses=current_statuses,
                    archive_statuses=context.archive,
                    timeout=self._remaining())
                for name, expected in (('write', write_entry), ('bootstrap', offer_bootstrap_entry)):
                    actual = recovered.source.authorities.originals[name]
                    if actual.raw != expected['raw'] or actual.ref.as_dict() != expected['ref']:
                        _fail('repair_provision_response_mismatch')
                journal.guard(key, tuple(sorted(journal._observation_id(item) for item in observations)))
                self._status_guard(context)
                value = recovered.source.binding
                return dict(binding=dict(raw=value.raw, ref=value.ref.as_dict()))
        for observed in result.current_statuses:
            self._observe_status(context,observed)
        self._status_guard(context)
        return dict(result.originals)
