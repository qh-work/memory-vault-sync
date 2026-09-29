"""Explicit root-copy upload with target possession and durable exact retries."""
from dataclasses import dataclass
import math
import time
from types import MappingProxyType
from memory_vault_open_repair_client import MailboxRootRecoveryClient
from memory_vault_open_repair_mailbox_root import verify_mailbox_root_bootstrap
from memory_vault_open_repair_mailbox_copy_authority import _check_mailbox_root_return
from memory_vault_open_transport import endpoint
import memory_vault_open_repair_ack as ack
import memory_vault_open_repair_empty as empty
import memory_vault_open_repair_original as original


from memory_vault_open_repair_copy_client import AckCopyUploadClient, _raw_entry, _entry
from memory_vault_open_repair_copy_upload import make_copy_commit_request, COMMIT_FIELDS, FEED_COMMIT_FIELDS
from memory_vault_open_repair_index_state import decode_entry
from memory_vault_open_repair_mailbox_copy_prepare import MailboxRootCopyPreparation, MailboxFeedCopyPreparation
from memory_vault_open_repair_mailbox_copy_authority import verify_mailbox_root_replica
import memory_vault_open_repair_history as history
import memory_vault_open_repair_index as index
import memory_vault_open_repair_probe as probe
import memory_vault_open_repair_stage as stage
import memory_vault_open_repair_wire as wire


class MailboxRootCopyUploadClient(AckCopyUploadClient):
    journal_type = MailboxRootCopyPreparation
    upload_state = 'root'
    consumer = 'mailbox_copy_root'
    commit_kind = 'mailbox.root_copy_commit'
    commit_fields = COMMIT_FIELDS
    history_role = 'history.mailbox_root'
    verify_replica = staticmethod(verify_mailbox_root_replica)

    def _commit_bound(self):
        return None

    def _committed_originals(self, value, budget):
        wire.object_fields(value, {'schema_version', 'kind', 'manifest', 'custody'})
        if value['schema_version'] != stage.SCHEMA or value['kind'] != 'mailbox.copy_committed':
            wire._fail('repair_invalid_response')
        return tuple(decode_entry(value[name], self.policy, budget) for name in ('manifest', 'custody'))

    def upload(self, base, *args, target_node_entry, timeout=60, **context):
        return self._upload(base, *args, target_node_entry=target_node_entry,
            timeout=timeout, source_state=self.upload_state, **context)

    def _upload_context_keys(self, source_state):
        if source_state != 'root': wire._fail('repair_copy_scope')
        return ('expected_root', 'expected_owner', 'expected_source', 'source_storage_epoch',
            'expected_target', 'target_storage_epoch', 'limit_policy')

    def _upload_preparer(self, source_state):
        if source_state != 'root': wire._fail('repair_copy_scope')
        return self.journal.prepare_upload_root

    def _reserve(self, *args, **options):
        wire._fail('repair_copy_preparation_required')

    def _expected(self, budget):
        return dict(expected_subject=self.journal.keys, expected_target=self.plan.intent['target'],
            target_storage_epoch=self.plan.intent['target_storage_epoch'], expected_consumer=self.consumer,
            at=self._now(), policy=self.policy, budget=budget)

    def _commit(self, result, step):
        context = self.context
        offer = next(row['entry'] for row in self.children if row['role'] == 'copy.offer')
        rid = wire.parse_new_wire(offer['raw'], self.policy, self._budget()).value['payload']['resource']['resource_id']
        def build(budget):
            return make_copy_commit_request(self.identity, intent_entry=self.intent, result_entry=_entry(result),
                resource_id=rid, expected_owner=context['expected_owner'], expected_source=context['expected_source'],
                source_storage_epoch=context['source_storage_epoch'], expires_at=self.until, bound=self._commit_bound(), **self._expected(budget)).raw
        def check(raw, budget):
            item = index._signed(_raw_entry(raw, budget), self.journal.keys['signing_key'],
                self.commit_kind, self.commit_fields, self.policy, budget)
            p = item.payload; stage._window(p, self._now())
            wanted = dict(resource_id=rid, intent_ref=self.intent['ref'], stage_result_ref=result.ref.as_dict(),
                owner=context['expected_owner'], source=context['expected_source'], source_storage_epoch=context['source_storage_epoch'],
                subject=probe._dual(self.journal.keys), target_node_key_id=self.plan.intent['target']['signing_key']['key_id'],
                target_storage_epoch=self.plan.intent['target_storage_epoch'])
            if self._commit_bound() is not None: wanted.update(self._commit_bound())
            if any(p[name] != value for name, value in wanted.items()) or p['expires_at'] > self.until or p['issued_at'] < result.payload['closed_at']:
                wire._fail('repair_stage_mismatch')
        def verify(raw, request, budget):
            value = wire.parse_new_wire(raw, self.policy, budget).value
            manifest, custody = self._committed_originals(value, budget)
            resolver = wire.LocalRawResolver(self.policy, budget)
            for row in self.children:
                original = row['entry']; resolver.put(original['ref']['namespace'], original['ref']['key'], original['raw'])
            source_manifest = next(row['entry'] for row in self.children if row['role'] == self.history_role)
            source = history.resolve_historical_inputs(source_manifest['raw'], resolver, self.policy, budget)
            for source_history in (source, *source.predecessors):
                for item in source_history.roles:
                    resolver.put(item.original.ref.namespace, item.original.ref.key, item.original.raw)
            checked = self.verify_replica(manifest, resolver, custody,
                expected_maintainer=self.journal.keys, **context, policy=self.policy, budget=budget)
            if checked['custody'].payload['resource']['resource_id'] != rid: wire._fail('repair_ref_mismatch')
            return dict(state='replica_committed', manifest=manifest, custody=custody)
        return self._step(step, build, check, verify, response_allowance=131072)[2]


class MailboxFeedCopyUploadClient(MailboxRootCopyUploadClient):
    journal_type = MailboxFeedCopyPreparation
    upload_state = 'feed'
    consumer = 'mailbox_copy_feed'
    commit_kind = 'mailbox.feed_copy_commit'
    commit_fields = FEED_COMMIT_FIELDS
    history_role = 'history.mailbox_feed'

    @staticmethod
    def verify_replica(*args, **options):
        from memory_vault_open_repair_mailbox_feed_copy import verify_mailbox_feed_replica
        return verify_mailbox_feed_replica(*args, **options)

    def _upload_context_keys(self, source_state):
        if source_state != 'feed': wire._fail('repair_copy_scope')
        return ('expected_slot', 'expected_owner', 'expected_sender', 'expected_source', 'source_storage_epoch',
            'expected_target', 'target_storage_epoch', 'limit_policy')

    def _upload_preparer(self, source_state):
        if source_state != 'feed': wire._fail('repair_copy_scope')
        return self.journal.prepare_upload_feed

    def _commit_bound(self):
        return dict(sender=self.context['expected_sender'])

    def _accept_prepared(self, prepared):
        self.replica_manifest = prepared['replica_manifest']

    def _committed_originals(self, value, budget):
        wire.object_fields(value, {'schema_version', 'kind', 'manifest_ref', 'custody'})
        if (value['schema_version'] != stage.SCHEMA or value['kind'] != 'mailbox.feed_copy_committed'
                or wire.raw_ref(value['manifest_ref']) != wire.raw_ref(self.replica_manifest['ref'])):
            wire._fail('repair_copy_commit_mismatch')
        # Every original and edge is locally present from this invocation's
        # verified upload. P's custody binds these exact canonical manifest
        # bytes; the independent replica verifier below rechecks the whole DAG.
        return self.replica_manifest, decode_entry(value['custody'], self.policy, budget)



@dataclass(frozen=True)
class RecoveredMailboxRootReplica:
    replica: object
    proof: object
    current_statuses: tuple
    archive_statuses: tuple
    originals: object
    metrics: object


class MailboxRootReplicaRecoveryClient(MailboxRootRecoveryClient):
    """B reads its existing directory from P under the original finite grant."""

    def recover(self, base_url, *, target_node_entry, expected_target, expected_root, expected_source,
            source_storage_epoch, expected_maintainer, root_entry, read_entry, bootstrap_entry,
            known_statuses=(), archive_statuses=(), timeout=30):
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 60:
            wire._fail('repair_invalid_deadline')
        budget = wire.RepairBudget(self.policy); started = self._now(); deadline = time.monotonic() + timeout
        expected = wire.build_new_wire(dict(root=expected_root, target=expected_target, source=expected_source,
            maintainer=expected_maintainer), self.policy, budget).value
        root, target = expected['root'], expected['target']
        setup = verify_mailbox_root_bootstrap(dict(root=root_entry, read=read_entry, bootstrap=bootstrap_entry),
            expected_root=root, expected_owner=self.subject, limit_policy=self.limits, at=started, policy=self.policy, budget=budget)
        raw, ref = ack._entry(target_node_entry)
        node = original.verify_original_control(raw, expected_signing_key=target['signing_key'],
            expected_schema='memory-vault-open-control/v1', expected_kind='node', at=started, policy=self.policy, budget=budget)
        original._node_shape(node, started, budget)
        if ref.namespace != 'meta' or len(node.document.raw) != ref.size or node.raw_sha256 != ref.raw_sha256:
            wire._fail('repair_ref_mismatch')
        if endpoint(base_url, allow_loopback=self.allow_loopback) != endpoint(node.payload['base_url'], allow_loopback=self.allow_loopback):
            wire._fail('repair_proof_mismatch')
        retained = self._retained_inputs(known_statuses, archive_statuses, budget)
        known = self._known_replica(retained, root, (self.subject, target, expected['source'], expected['maintainer']),
            budget, _allow_role_aliases=True)
        requirements = []
        for name, mask in (('root', 10), ('read', 2), ('bootstrap', 10)):
            item = setup[name]
            requirements.append(dict(role='current.status.' + name, signer=self.subject['signing_key'], kind='authority',
                scope_id=index._authority(root, item, self.policy, budget), revision=item.payload['revision'], mask=mask))
        self._floors(known, (), requirements, probe_phase=True)
        grant = setup['bootstrap'].payload
        expiry = min(started + min(60, max(1, int(timeout))), node.payload['expires_at'], grant['probe_until'], grant['proof_until'],
            *(item.payload['expires_at'] for item in setup.values()))
        if expiry <= started: wire._fail('repair_access_expired')
        held, originals, roles, counts = self._download_mailbox(base_url, target=target, node_payload=node.payload,
            bootstrap_original=setup['bootstrap'], expiry=expiry, started=started, deadline=deadline, budget=budget,
            consumer='mailbox_root', source_state='replica_root',
            available={item.ref: item.raw for item in (*setup.values(), *known)})
        def entry(reference): return dict(raw=originals[reference], ref=reference.as_dict())
        def one(role):
            if len(roles.get(role, ())) != 1: wire._fail('repair_proof_mismatch')
            return entry(roles[role][0])
        resolver = wire.LocalRawResolver(self.policy, budget)
        for reference, raw in originals.items():
            if resolver.put(reference.namespace, reference.key, raw).ref != reference: wire._fail('repair_ref_mismatch')
        replica = verify_mailbox_root_replica(one('replica.manifest'), resolver, one('replica.custody'),
            expected_root=root, expected_owner=self.subject, expected_source=expected['source'], source_storage_epoch=source_storage_epoch,
            expected_maintainer=expected['maintainer'], expected_target=target, target_storage_epoch=node.payload['storage_epoch'],
            limit_policy=self.limits, policy=self.policy, budget=budget)
        source = replica['source']
        for name, item in setup.items():
            actual = source['setup']['originals'][name]
            if actual.ref != item.ref or actual.raw != item.raw: wire._fail('repair_proof_mismatch')
        # Refuse undeclared additions even if P signed the outer service proof.
        wanted = {(role, wire.raw_ref(item['ref'])) for role, values in replica['entries'].items() for item in values}
        extras = {'replica.manifest', 'replica.custody', 'replica.read_pack', 'return.owner', 'return.source',
            'return.maintainer', 'current.status.replica_read'}
        actual = {(role, ref) for role, refs in roles.items() for ref in refs if role not in extras}
        if actual != wanted: wire._fail('repair_proof_mismatch')
        permission = _check_mailbox_root_return(replica, {name: one('return.' + name) for name in ('owner', 'source', 'maintainer')},
            expected_owner=self.subject, expected_source=expected['source'], expected_maintainer=expected['maintainer'],
            expected_target=target, target_storage_epoch=node.payload['storage_epoch'],
            current_statuses=[entry(ref) for ref in roles['current.status.replica_read']], at=self._now(), action='proof',
            policy=self.policy, budget=budget, on_observed=self.status_observer)
        if permission['denial_code']: wire._fail(permission['denial_code'])
        previous = (*source['statuses'], *replica['authority'].statuses, *known)
        current = permission['statuses']
        empty._history_floors((*previous, *current), previous=previous, current=current)
        self._floors(known, current, [dict(item, kind=item['scope_kind']) for item in permission['obligations']])
        if self._now() >= min(expiry, held.handle.payload['expires_at'], permission['expires_at']) or time.monotonic() >= deadline:
            wire._fail('repair_access_expired')
        archive = {(item.raw, item.ref): item for item in (*previous, *current)}
        if len(archive) > 32: wire._fail('repair_status_history_capacity')
        return RecoveredMailboxRootReplica(MappingProxyType(replica), held, current, tuple(archive.values()),
            MappingProxyType(originals), MappingProxyType(dict(**counts, **budget.snapshot())))


@dataclass(frozen=True)
class RecoveredMailboxFeedReplica(RecoveredMailboxRootReplica):
    members: tuple


class MailboxFeedReplicaRecoveryClient(MailboxRootRecoveryClient):
    def recover(self, base_url, *, target_node_entry, expected_target, expected_slot, expected_sender,
            expected_source, source_storage_epoch, expected_maintainer, slot_entries,
            known_statuses=(), archive_statuses=(), timeout=30):
        from memory_vault_open_repair_mailbox_activation import verify_mailbox_feed_bootstrap
        from memory_vault_open_repair_mailbox_feed_copy import verify_mailbox_feed_replica, _check_mailbox_feed_return
        from memory_vault_open_repair_client import read_mailbox_index
        import memory_vault_open_repair_resource as resource
        import memory_vault_open_repair_status as status
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 60:
            wire._fail('repair_invalid_deadline')
        budget = wire.RepairBudget(self.policy); started = self._now(); deadline = time.monotonic() + timeout
        expected = wire.build_new_wire(dict(slot=expected_slot, target=expected_target, sender=expected_sender,
            source=expected_source, maintainer=expected_maintainer), self.policy, budget).value
        key, target, sender = (expected[name] for name in ('slot', 'target', 'sender')); root = key['root_key']
        if source_storage_epoch != key['writer_storage_epoch']: wire._fail('repair_proof_mismatch')
        setup = verify_mailbox_feed_bootstrap(slot_entries, expected_slot=key, expected_owner=self.subject,
            expected_target=expected['source'], target_storage_epoch=source_storage_epoch,
            limit_policy=self.limits, at=started, policy=self.policy, budget=budget)
        if setup['slot'].payload['sender'] != resource._dual_key(sender, budget): wire._fail('repair_proof_mismatch')
        raw, ref = ack._entry(target_node_entry)
        node = original.verify_original_control(raw, expected_signing_key=target['signing_key'],
            expected_schema='memory-vault-open-control/v1', expected_kind='node', at=started, policy=self.policy, budget=budget)
        original._node_shape(node, started, budget)
        if ref.namespace != 'meta' or len(node.document.raw) != ref.size or node.raw_sha256 != ref.raw_sha256: wire._fail('repair_ref_mismatch')
        if endpoint(base_url, allow_loopback=self.allow_loopback) != endpoint(node.payload['base_url'], allow_loopback=self.allow_loopback):
            wire._fail('repair_proof_mismatch')
        retained = self._retained_inputs(known_statuses, archive_statuses, budget)
        known = self._known_replica(retained, root, (self.subject, target, sender, expected['source'], expected['maintainer']), budget, _allow_role_aliases=True)
        requirements = []
        for name, mask in (('slot', 10), ('read', 2), ('maintenance', 10), ('bootstrap', 10)):
            item = setup[name]; kind = 'mailbox_slot' if name == 'slot' else 'authority'
            scope_id = status.status_scope(root, kind, key, self.policy, budget) if name == 'slot' else index._authority(root, item, self.policy, budget)
            requirements.append(dict(role='current.status.' + name, signer=self.subject['signing_key'], kind=kind,
                scope_id=scope_id, revision=item.payload['revision'], mask=mask))
        self._floors(known, (), requirements, probe_phase=True)
        grant = setup['bootstrap'].payload
        expiry = min(started + min(60, max(1, int(timeout))), node.payload['expires_at'], grant['probe_until'], grant['proof_until'],
            *(item.payload['expires_at'] for item in setup.values()))
        if expiry <= started: wire._fail('repair_access_expired')
        held, originals, roles, counts = self._download_mailbox(base_url, target=target, node_payload=node.payload,
            bootstrap_original=setup['bootstrap'], expiry=expiry, started=started, deadline=deadline, budget=budget,
            consumer='mailbox_feed', source_state='replica_feed', available={item.ref: item.raw for item in (*setup.values(), *known)})
        def entry(reference): return dict(raw=originals[reference], ref=reference.as_dict())
        def one(role):
            if len(roles.get(role, ())) != 1: wire._fail('repair_proof_mismatch')
            return entry(roles[role][0])
        resolver = wire.LocalRawResolver(self.policy, budget)
        for reference, raw in originals.items():
            if resolver.put(reference.namespace, reference.key, raw).ref != reference: wire._fail('repair_ref_mismatch')
        replica = verify_mailbox_feed_replica(one('replica.manifest'), resolver, one('replica.custody'), expected_slot=key,
            expected_owner=self.subject, expected_sender=sender, expected_source=expected['source'], source_storage_epoch=source_storage_epoch,
            expected_maintainer=expected['maintainer'], expected_target=target, target_storage_epoch=node.payload['storage_epoch'],
            limit_policy=self.limits, policy=self.policy, budget=budget)
        source = replica['source']
        for member in source['graph']['members']:
            if any(member['originals'][name].ref != item.ref or member['originals'][name].raw != item.raw for name, item in setup.items()):
                wire._fail('repair_proof_mismatch')
        wanted = {(role, wire.raw_ref(item['ref'])) for role, values in replica['entries'].items() for item in values}
        extras = {'replica.manifest', 'replica.custody', 'replica.read_pack', 'return.owner', 'return.source',
            'return.maintainer', 'return.sender', 'current.status.replica_read'}
        if {(role, ref) for role, refs in roles.items() for ref in refs if role not in extras} != wanted: wire._fail('repair_proof_mismatch')
        permission = _check_mailbox_feed_return(replica, {name: one('return.' + name) for name in ('owner', 'source', 'maintainer', 'sender')},
            expected_owner=self.subject, expected_sender=sender, expected_source=expected['source'], expected_maintainer=expected['maintainer'],
            expected_target=target, target_storage_epoch=node.payload['storage_epoch'],
            current_statuses=[entry(ref) for ref in roles['current.status.replica_read']], at=self._now(), action='proof',
            policy=self.policy, budget=budget, on_observed=self.status_observer)
        if permission['denial_code']: wire._fail(permission['denial_code'])
        previous = (*source['graph']['statuses'], *(item for member in source['graph']['members'] for item in member['statuses']),
            *replica['authority'].statuses, *known)
        current = permission['statuses']; empty._history_floors((*previous, *current), previous=previous, current=current)
        self._floors(known, current, [dict(item, kind=item['scope_kind']) for item in permission['obligations']])
        members = read_mailbox_index(one('feed.head'), one('feed.checkpoint'), expected_slot=key,
            expected_signing_key=expected['source']['signing_key'], encryption_identity=self.encryption_identity,
            read_original=lambda reference: originals[wire.raw_ref(reference)], at=self._now(),
            max_messages=setup['slot'].payload['max_appends'], policy=self.policy, budget=budget)
        if self._now() >= min(expiry, held.handle.payload['expires_at'], permission['expires_at']) or time.monotonic() >= deadline:
            wire._fail('repair_access_expired')
        archive = {(item.raw, item.ref): item for item in (*previous, *current)}
        if len(archive) > 32: wire._fail('repair_status_history_capacity')
        return RecoveredMailboxFeedReplica(MappingProxyType(replica), held, current, tuple(archive.values()),
            MappingProxyType(originals), MappingProxyType(dict(**counts, **budget.snapshot())), tuple(members))
