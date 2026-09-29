"""Private, durable preparation of fully authorized discovery-root uploads.

The input already contains M's allocation, P's real offer, M's assignment and
independent B/S disclosures. Importing that exact transcript cannot reserve
capacity, add a delegation or manufacture another participant's permission.
"""
import json
import secrets

from memory_vault import canonical_bytes
from memory_vault_open_repair_copy_prepare import AckCopyPreparation, _require
from memory_vault_open_repair_index_state import encode_entry, decode_entry
from memory_vault_open_repair_mailbox_copy_authority import verify_mailbox_root_copy
import memory_vault_open_repair_empty as empty
import memory_vault_open_repair_history as history
import memory_vault_open_repair_index as index
import memory_vault_open_repair_resource as resource
import memory_vault_open_repair_stage as stage
import memory_vault_open_repair_status as status
import memory_vault_open_repair_wire as wire


class MailboxRootCopyPreparation(AckCopyPreparation):
    """Use the existing caller-bound journal and its shared finite work limits."""

    purpose = 'root_replica'
    consumer = 'mailbox_copy_root'
    original_roles = ('history.mailbox_root', 'root.custody', 'copy.allocation', 'copy.offer',
        'copy.assignment', 'copy.reservation_consent', 'copy.owner_disclosure', 'copy.source_disclosure')
    verify_copy = staticmethod(verify_mailbox_root_copy)

    def _selection(self, binding):
        return dict(expected_root=binding['root'])

    def _source_statuses(self, source):
        return source['statuses']

    def _source_manifests(self, source):
        return (source['manifest'],)

    def _result_extra(self, plan, originals, budget):
        return {}

    def _body_children(self, plan, entry, budget):
        if entry is not None: wire._fail('repair_copy_scope')
        return ()

    def prepare_upload_root(self, manifest_entry, resolver, custody_entry, allocation_entry, offer_entry,
            assignment_entry, reservation_entry, owner_disclosure_entry, source_disclosure_entry, *,
            expected_root, expected_owner, expected_source, source_storage_epoch, expected_target,
            target_storage_epoch, current_statuses, at, limit_policy):
        return self._prepare_mailbox_upload((manifest_entry, custody_entry, allocation_entry, offer_entry,
            assignment_entry, reservation_entry, owner_disclosure_entry, source_disclosure_entry), resolver,
            binding=dict(root=expected_root, owner=expected_owner, source=expected_source, target=expected_target),
            source_storage_epoch=source_storage_epoch, target_storage_epoch=target_storage_epoch,
            current_statuses=current_statuses, at=at, limit_policy=limit_policy)

    def _prepare_mailbox_upload(self, entries, resolver, *, binding, source_storage_epoch,
            target_storage_epoch, current_statuses, at, limit_policy, body_entry=None):
        p = self.policy; b = resolver.budget; wire._context(p, b); wire.u53(at)
        _require(not self.db.in_transaction and resolver.policy is p and p.max_signature_checks <= 64)
        def freeze(entry):
            wire.object_fields(entry, {'raw', 'ref'})
            return dict(raw=wire._snapshot(entry['raw'], p, b), ref=wire.raw_ref(entry['ref']).as_dict())
        _require(len(entries) == len(self.original_roles))
        originals = tuple(map(freeze, entries))
        allocation_entry, assignment_entry = originals[2], originals[4]
        if type(current_statuses) not in (list, tuple) or not 1 <= len(current_statuses) <= 16:
            wire._fail('repair_status_missing')
        current_statuses = tuple(map(freeze, current_statuses))
        binding = wire.build_new_wire(binding, p, b).value
        allocation = index._signed(allocation_entry, self.keys['signing_key'], 'resource.allocate', index.ALLOCATE_FIELDS, p, b)
        intent = allocation.payload['intent']; root = intent['root_key']; job = intent['job_id']
        resource._opaque(job); history._root(root); resource._budget(intent['budget'])
        _require(root == binding['root'] and intent['purpose'] == self.purpose and intent['caller'] == self.keys)
        digest = b._hash(wire._canonical(root, b)); ticket = secrets.token_hex(16)
        with self._upload_transaction():
            held = self.db.execute('SELECT value FROM ack_copy_prepare_binding WHERE id=1').fetchone()
            _require(held is not None and bytes(held[0]) == canonical_bytes(self.keys))
            blocked = self.db.execute("SELECT reason FROM ack_copy_prepare_blocked WHERE root_digest IN (?, '*')", (digest,)).fetchone()
            if blocked: wire._fail(blocked[0])
            count, work = self.db.execute('SELECT count(*),coalesce(sum(coalesce(actual,allowance)),0) FROM ack_copy_prepare_upload_work WHERE job_id=?', (job,)).fetchone()
            maximum = min(64, intent['budget']['max_requests'])
            if (count >= maximum or work + p.max_signature_checks > 64 * maximum
                    or self.db.execute('SELECT count(*) FROM ack_copy_prepare_upload_work').fetchone()[0] >= 1024):
                wire._fail('repair_copy_work_capacity')
            self.db.execute('INSERT INTO ack_copy_prepare_upload_work VALUES(?,?,?,NULL)', (ticket, job, p.max_signature_checks))
        def observe(item):
            with self._upload_transaction():
                if self.db.execute('SELECT 1 FROM ack_copy_prepare_status WHERE root_digest=? AND raw_digest=?', (digest, item.ref.raw_sha256)).fetchone(): return
                count, size = self.db.execute('SELECT count(*),coalesce(sum(length(raw)+length(ref)),0) FROM ack_copy_prepare_status').fetchone()
                encoded = canonical_bytes(item.ref.as_dict())
                if count >= 64 or size + len(item.raw) + len(encoded) > 1048576:
                    self.db.execute("INSERT OR IGNORE INTO ack_copy_prepare_blocked VALUES('*','repair_copy_journal_capacity')")
                    return
                self.db.execute('INSERT INTO ack_copy_prepare_status VALUES(?,?,?,?)', (digest, item.ref.raw_sha256, item.raw, encoded))
        try:
            plan = self.verify_copy(originals[0], resolver, *originals[1:],
                **self._selection(binding), expected_owner=binding['owner'], expected_source=binding['source'],
                source_storage_epoch=source_storage_epoch, expected_maintainer=self.keys, expected_target=binding['target'],
                target_storage_epoch=target_storage_epoch, current_statuses=current_statuses, at=at,
                limit_policy=limit_policy, policy=p, budget=b, on_observed=observe)
            signers = {binding[name]['signing_key']['key_id']: binding[name]['signing_key']
                for name in ('owner', 'source', 'sender') if name in binding}
            signers[self.keys['signing_key']['key_id']] = self.keys['signing_key']
            stamp = tuple((bytes(row[0]), bytes(row[1])) for row in self.db.execute(
                'SELECT raw,ref FROM ack_copy_prepare_status WHERE root_digest=? ORDER BY raw_digest', (digest,)))
            # Observing this plan already persisted its authenticated statuses.
            # Reuse only those exact bytes and full references in this call;
            # older or changed journal entries still require authentication.
            checked_now = {(item.ref, item.raw): item for item in plan.statuses}
            previous = []
            for raw, reference in stamp:
                retained_ref = wire.raw_ref(json.loads(reference))
                checked = checked_now.get((retained_ref, raw))
                if checked is not None:
                    previous.append(checked)
                    continue
                payload = wire.parse_new_wire(raw, p, b).value['payload']; issuer = payload['signing_key']['key_id']
                # Other slots of this same mailbox may have authenticated
                # observations from different senders. Keep their durable
                # records; only this operation's parties enter its verifier.
                if issuer not in signers: continue
                previous.append(status.authenticate_status_original(dict(raw=raw, ref=json.loads(reference)),
                    expected_root=root, expected_signing_key=signers[issuer], at=payload['issued_at'],
                    allowed_scopes=[dict(scope_kind=e['scope_kind'], scope_id=e['scope_id']) for e in payload['entries']], policy=p, budget=b))
            empty._history_floors((*self._source_statuses(plan.source), *previous, *plan.statuses), previous=previous, current=plan.statuses)
            if plan.denial_code: wire._fail(plan.denial_code)
            for old in previous:
                for e in old.payload['entries']:
                    if e['status'] == 'revoked' and any(old.payload['signing_key'] == need['signer']
                            and (e['scope_kind'], e['scope_id']) == (need['scope_kind'], need['scope_id']) for need in plan.obligations):
                        wire._fail('repair_authority_revoked')
            rows = {}
            def add(role, entry):
                ref = wire.raw_ref(entry['ref'])
                if len(entry['raw']) != ref.size or b._hash(entry['raw']) != ref.raw_sha256: wire._fail('repair_ref_mismatch')
                rows[(role, *history._ref_tuple(ref))] = dict(role=role, entry=entry)
            for role, entry in zip(self.original_roles, originals): add(role, entry)
            for source_manifest in self._source_manifests(plan.source):
                for member in source_manifest.manifest.value['roles']:
                    add('history.raw_pack', index._entry(resolver.resolve(member['pack_ref'])))
            for item in plan.statuses: add('copy.current_status', index._entry(item))
            for role, entry in self._body_children(plan, body_entry, b): add(role, entry)
            children = tuple(rows[key] for key in sorted(rows))
            manifest = stage.make_stage_manifest(root_key=root, scope=plan.assignment.payload['scope'],
                children=[dict(index=i, role=row['role'], ref=row['entry']['ref']) for i, row in enumerate(children)],
                consumer=self.consumer, policy=p, budget=b)
            until = min(plan.read_until, plan.retain_until, plan.offer.payload['reservation_until'],
                plan.assignment.payload['windows']['copy_until'], *(item.payload['valid_until'] for item in plan.statuses))
            semantic = dict(manifest=manifest.value, allocation_ref=allocation_entry['ref'], assignment_ref=assignment_entry['ref'])
            semantic_digest = b._hash(wire._canonical(semantic, b))
            options = dict(expected_subject=self.keys, expected_target=binding['target'], target_storage_epoch=target_storage_epoch,
                at=at, expected_consumer=self.consumer, policy=p, budget=b)
            with self._upload_transaction():
                blocked = self.db.execute("SELECT reason FROM ack_copy_prepare_blocked WHERE root_digest IN (?, '*')", (digest,)).fetchone()
                if blocked: wire._fail(blocked[0])
                current_stamp = tuple((bytes(row[0]), bytes(row[1])) for row in self.db.execute(
                    'SELECT raw,ref FROM ack_copy_prepare_status WHERE root_digest=? ORDER BY raw_digest', (digest,)))
                if current_stamp != stamp: wire._fail('repair_status_changed')
                old = self.db.execute('SELECT digest,raw FROM ack_copy_prepare_uploads WHERE job_id=?', (job,)).fetchone()
                if old is not None:
                    held = wire.parse_new_wire(bytes(old[1]), p, b).value
                    if old[0] != semantic_digest or held['semantic'] != semantic: wire._fail('repair_copy_upload_conflict')
                    outgoing = decode_entry(held['intent'], p, b)
                    checked = stage.verify_stage_intent(outgoing, **options)
                    if checked.payload['manifest'] != manifest.value or checked.payload['expires_at'] > until: wire._fail('repair_copy_upload_conflict')
                else:
                    outgoing = index._entry(stage.make_stage_intent(self.identity, allocation_id=intent['allocation_id'],
                        manifest=manifest.value, expires_at=until, **options))
                    raw = wire.build_new_wire(dict(semantic=semantic, intent=encode_entry(outgoing)), p, b).raw
                    count, size = self.db.execute('SELECT count(*),coalesce(sum(length(raw)),0) FROM ack_copy_prepare_uploads').fetchone()
                    if count >= 16 or size + len(raw) > 4194304 or len(raw) > intent['budget']['max_job_bytes']: wire._fail('repair_copy_journal_capacity')
                    self.db.execute('INSERT INTO ack_copy_prepare_uploads VALUES(?,?,?)', (job, semantic_digest, raw))
                return dict(intent=outgoing, children=children, expires_at=until, status_stamp=stamp,
                    **self._result_extra(plan, originals, b))
        finally:
            actual = b.snapshot()['signature_checks']
            with self._upload_transaction():
                held = self.db.execute('SELECT allowance,actual FROM ack_copy_prepare_upload_work WHERE id=?', (ticket,)).fetchone()
                if held is None or held[1] is not None or not 0 <= actual <= held[0]: wire._fail('repair_service_work_corrupt')
                self.db.execute('UPDATE ack_copy_prepare_upload_work SET actual=? WHERE id=?', (actual, ticket))


class MailboxFeedCopyPreparation(MailboxRootCopyPreparation):
    purpose = 'feed_replica'
    consumer = 'mailbox_copy_feed'
    original_roles = ('history.mailbox_feed', 'feed.custody', 'copy.allocation', 'copy.offer',
        'copy.assignment', 'copy.reservation_consent', 'copy.sender_reservation_consent',
        'copy.owner_disclosure', 'copy.source_disclosure', 'copy.sender_disclosure')

    @staticmethod
    def verify_copy(*args, **options):
        from memory_vault_open_repair_mailbox_feed_copy import verify_mailbox_feed_copy
        return verify_mailbox_feed_copy(*args, **options)

    def _selection(self, binding):
        return dict(expected_slot=binding['slot'], expected_sender=binding['sender'])

    def _source_statuses(self, source):
        return (*source['graph']['statuses'], *(item for member in source['graph']['members'] for item in member['statuses']))

    def _source_manifests(self, source):
        return (source['manifest'], *source['manifest'].predecessors)

    def _result_extra(self, plan, originals, budget):
        from memory_vault_open_repair_copy_authority import _replica_manifest_value
        from memory_vault_open_repair_mailbox_feed_copy import feed_copy_histories, feed_copy_edges
        value = _replica_manifest_value(plan, source_histories=feed_copy_histories(plan.source, originals[0]),
            additional=(('copy.sender_disclosure', plan.disclosures[2]),),
            extra_edges=feed_copy_edges(plan.source, budget.policy, budget),
            extra_references=(('message.envelope', plan.source['message_scope']['envelope_ref']),) if 'message_scope' in plan.source else ())
        raw = wire.build_new_wire(value, budget.policy, budget).raw; digest = budget._hash(raw)
        return dict(replica_manifest=dict(raw=raw, ref=dict(namespace='meta', key=digest, raw_sha256=digest, size=len(raw))))

    def prepare_upload_feed(self, manifest_entry, resolver, custody_entry, allocation_entry, offer_entry,
            assignment_entry, reservation_entry, sender_reservation_entry, owner_disclosure_entry,
            source_disclosure_entry, sender_disclosure_entry, *, expected_slot, expected_owner, expected_sender,
            expected_source, source_storage_epoch, expected_target, target_storage_epoch, current_statuses, at, limit_policy):
        return self._prepare_mailbox_upload((manifest_entry, custody_entry, allocation_entry, offer_entry,
            assignment_entry, reservation_entry, sender_reservation_entry, owner_disclosure_entry,
            source_disclosure_entry, sender_disclosure_entry), resolver,
            binding=dict(root=expected_slot['root_key'], slot=expected_slot, owner=expected_owner,
                sender=expected_sender, source=expected_source, target=expected_target),
            source_storage_epoch=source_storage_epoch, target_storage_epoch=target_storage_epoch,
            current_statuses=current_statuses, at=at, limit_policy=limit_policy)


class MailboxMessageCopyPreparation(MailboxFeedCopyPreparation):
    purpose = 'message_replica'
    consumer = 'mailbox_copy_message'

    @staticmethod
    def verify_copy(*args, **options):
        from memory_vault_open_repair_mailbox_message_copy import verify_mailbox_message_copy
        return verify_mailbox_message_copy(*args, **options)

    def _selection(self, binding):
        return dict(super()._selection(binding), expected_envelope_ref=binding['envelope_ref'])

    def _body_children(self, plan, entry, budget):
        from memory_vault_open_repair_mailbox_message_copy import verify_message_body
        body = verify_message_body(entry, plan.source['message_scope']['envelope_ref'], budget.policy, budget)
        budget._bytes('input_bytes', len(body.raw)); budget._retain(len(body.raw))
        return (('message.envelope', index._entry(body)),)

    def prepare_upload_message(self, manifest_entry, resolver, custody_entry, allocation_entry, offer_entry,
            assignment_entry, reservation_entry, sender_reservation_entry, owner_disclosure_entry,
            source_disclosure_entry, sender_disclosure_entry, *, expected_slot, expected_owner, expected_sender,
            expected_source, source_storage_epoch, expected_target, target_storage_epoch, current_statuses, at,
            limit_policy, expected_envelope_ref, envelope_entry):
        return self._prepare_mailbox_upload((manifest_entry, custody_entry, allocation_entry, offer_entry,
            assignment_entry, reservation_entry, sender_reservation_entry, owner_disclosure_entry,
            source_disclosure_entry, sender_disclosure_entry), resolver,
            binding=dict(root=expected_slot['root_key'], slot=expected_slot, owner=expected_owner,
                sender=expected_sender, source=expected_source, target=expected_target, envelope_ref=expected_envelope_ref),
            source_storage_epoch=source_storage_epoch, target_storage_epoch=target_storage_epoch,
            current_statuses=current_statuses, at=at, limit_policy=limit_policy, body_entry=envelope_entry)
