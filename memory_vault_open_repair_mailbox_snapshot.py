"""Exact local mailbox snapshots for a later authorized replica transfer.

This storage primitive joins a committed discovery root, a selected committed
feed prefix and the original message ciphertexts. It does not grant network
disclosure, copying, read access or new admission. A transport consumer must
independently authenticate the original graphs and current replica authority.
No sender/recipient keys, Vault contents or unrelated node records are read.
"""
from dataclasses import dataclass
from types import MappingProxyType
import json

import memory_vault_open_repair_history as history
import memory_vault_open_repair_wire as wire


@dataclass(frozen=True)
class MailboxSnapshotPart:
    scope_raw: bytes
    manifest: wire.RawRef
    custody: wire.RawRef
    transfer: tuple
    envelopes: tuple

    @property
    def scope(self):
        return json.loads(self.scope_raw)


@dataclass(frozen=True)
class MailboxSourceSnapshot:
    root_manifest: wire.RawRef
    root_custody: wire.RawRef
    feed_manifest: wire.RawRef
    feed_custody: wire.RawRef
    originals: object
    transfer: tuple
    parts: tuple
    envelopes: tuple
    read_until: int
    retain_until: int

    def read(self, reference):
        """Return the exact retained bytes; this is not a remote read grant."""
        ref = wire.raw_ref(reference)
        if ref not in self.originals:
            wire._fail('repair_original_missing')
        return self.originals[ref]


class MailboxSnapshotSource:
    """Read a complete immutable prefix under the source's storage lock.

    The caller supplies the original root resource and exact signed feed head.
    Appends cannot replace that selection. The existing resource, custody and
    owner status ledgers remain prerequisites; there is no new custody event.
    """
    def __init__(self, staging):
        from memory_vault_open_repair_mailbox_source import MailboxMessageStaging
        if not isinstance(staging, MailboxMessageStaging):
            wire._fail('repair_invalid_context')
        self.staging, self.source, self.db = staging, staging.source, staging.db

    def load(self, resource_id, slot_key, head_ref, *, max_bytes, max_items):
        from memory_vault_open_repair_mailbox_source import MailboxRecoveryService
        from memory_vault_open_repair_mailbox_status import MailboxStatusLedger
        import memory_vault_open_repair_status as status
        import memory_vault_open_repair_original as original
        from memory_vault_open_repair_original import _opaque
        _opaque(resource_id)
        s = self.source
        budget = wire.RepairBudget(s.policy)
        # Explicit caller limits also remain inside the existing operation
        # byte/entry limits. Stored evidence cannot fund its own transfer.
        wire.u53(max_bytes, 1); wire.u53(max_items, 1)
        if max_bytes > min(s.policy.max_total_bytes, s.policy.max_retained_bytes) or max_items > min(256, s.policy.max_entries):
            wire._fail('repair_snapshot_capacity')
        key = wire.build_new_wire(slot_key, s.policy, budget).value
        history._slot(key, key['root_key'])
        head = wire.raw_ref(head_ref)
        if head.namespace != 'meta':
            wire._fail('repair_ref_mismatch')
        slot_digest = budget._hash(wire._canonical(key, budget))
        root_digest = budget._hash(wire._canonical(key['root_key'], budget))
        held = {}; total = 0; deadlines = []; retains = []; guards = []

        def guard():
            if deadlines and s._now() >= min(deadlines):
                return 'repair_resource_expired'
            for check in guards:
                code = check()
                if code:
                    return code

        def add(raw, reference):
            nonlocal total
            ref = wire.raw_ref(reference)
            if type(raw) is not bytes or len(raw) != ref.size or budget._hash(raw) != ref.raw_sha256:
                wire._fail('repair_ref_mismatch')
            if ref in held:
                if held[ref] != raw:
                    wire._fail('repair_ref_mismatch')
                return ref
            if len(held) >= max_items or total + len(raw) > max_bytes:
                wire._fail('repair_snapshot_capacity')
            budget._bytes('input_bytes', len(raw))
            budget._retain(len(raw))
            held[ref] = raw; total += len(raw)
            return ref

        def saved(row, name):
            entry = s._saved(row, name)
            add(entry['raw'], entry['ref'])
            return entry

        def pack(row):
            entry = saved(row, 'pack')
            return wire.parse_raw_pack(entry['raw'], entry['ref'], s.policy, budget)

        def manifest(row, packed):
            entry = saved(row, 'manifest')
            parsed = history.parse_historical_manifest(entry['raw'], s.policy, budget)
            for role in parsed.value['roles']:
                if wire.raw_ref(role['pack_ref']) != packed.ref:
                    wire._fail('repair_storage_corrupt')
                ref = wire.raw_ref(role['document_ref'])
                add(packed.entry(role['entry_index'], ref).raw, role['document_ref'])
            return entry, parsed.value

        def ordered(items):
            return tuple(sorted(set(items), key=lambda item: (item[0], item[1].namespace, item[1].key, item[1].raw_sha256, item[1].size)))

        def part(scope, manifest_entry, custody_ref, transfer, envelopes=()):
            return MailboxSnapshotPart(wire.build_new_wire(scope, s.policy, budget).raw,
                wire.raw_ref(manifest_entry['ref']), wire.raw_ref(custody_ref), ordered(transfer), tuple(envelopes))

        # Guard construction reads the original root in its own transaction.
        # Construct it before the snapshot transaction, then recheck the
        # immutable slot binding under that final lock.
        with s._transaction():
            for table in ('open_mailbox_feed_history', 'open_mailbox_feed_custody', 'open_mailbox_member_history'):
                if s._one("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)) is None:
                    wire._fail('repair_mailbox_history_missing')
            selection = s._one('SELECT * FROM open_repair_mailbox_slot_activations WHERE slot_digest=?', (slot_digest,))
            if selection is None:
                wire._fail('repair_mailbox_history_missing')
        root_service = MailboxRecoveryService(self.staging.root_source)
        feed_service = MailboxRecoveryService(self.staging.root_source, consumer='mailbox_feed')
        guards.extend((root_service._owner_guard(resource_id), feed_service._owner_guard(selection['metadata_resource_id'], head_ref=head.as_dict())))
        with s._transaction(guard=guard) as now:
            anchor = s._one('SELECT * FROM open_repair_mailbox_roots WHERE resource_id=?', (resource_id,))
            root_row = s._one('SELECT * FROM open_repair_mailbox_root_history WHERE resource_id=?', (resource_id,))
            root_event = s._one('SELECT * FROM open_repair_mailbox_root_custody WHERE resource_id=?', (resource_id,))
            slot = s._one('SELECT * FROM open_repair_mailbox_slot_activations WHERE slot_digest=?', (slot_digest,))
            if any(value is None for value in (anchor, root_row, root_event, slot)):
                wire._fail('repair_mailbox_history_missing')
            if anchor['root_digest'] != root_digest:
                wire._fail('repair_mailbox_root_mismatch')
            if any(slot[name] != selection[name] for name in ('input_digest', 'metadata_resource_id', 'data_resource_id')):
                wire._fail('repair_storage_corrupt')
            feed_row = s._one('SELECT * FROM open_mailbox_feed_history WHERE slot_digest=? AND head_digest=?', (slot_digest, head.raw_sha256))
            feed_event = s._one('SELECT * FROM open_mailbox_feed_custody WHERE slot_digest=? AND head_digest=?', (slot_digest, head.raw_sha256))
            if feed_row is None or feed_event is None:
                wire._fail('repair_mailbox_history_missing')
            root_pack = pack(root_row)
            root_manifest, root = manifest(root_row, root_pack)
            root_custody = saved(root_event, 'custody')
            root_payload = wire.parse_new_wire(root_custody['raw'], s.policy, budget).value['payload']
            feed_pack = pack(feed_row)
            feed_manifest, feed = manifest(feed_row, feed_pack)
            feed_custody = saved(feed_event, 'custody')
            feed_payload = wire.parse_new_wire(feed_custody['raw'], s.policy, budget).value['payload']
            if (root['variant'] != 'mailbox_root' or root['root_key'] != key['root_key']
                    or root_payload['historical_manifest_ref'] != root_manifest['ref']
                    or root_payload['root_key'] != key['root_key']
                    or feed['variant'] != 'mailbox_feed' or feed['slot_key'] != key
                    or feed['feed_head_ref'] != head.as_dict()
                    or feed_payload['historical_manifest_ref'] != feed_manifest['ref']
                    or any(feed_payload[name] != feed[name] for name in ('slot_key', 'slot_ref', 'feed_head_ref', 'covered_interval', 'subtree'))):
                wire._fail('repair_storage_corrupt')
            root_marker = s._one('SELECT value FROM open_repair_state WHERE name=?', ('mailbox_root_custody:' + resource_id,))
            feed_marker = s._one('SELECT value FROM open_repair_state WHERE name=?', ('mailbox_feed_custody:' + slot_digest + ':' + head.raw_sha256,))
            if (root_marker is None or root_marker['value'] != s._expected_binding() + '|' + root_event['input_digest'] + '|' + root_custody['ref']['raw_sha256']
                    or feed_marker is None or feed_marker['value'] != s._expected_binding() + '|' + feed_custody['ref']['raw_sha256']):
                wire._fail('repair_storage_corrupt')
            selected = [item for item in root_payload['resource_refs']['feeds'] if item['slot_key'] == key]
            if len(selected) != 1 or selected[0]['metadata']['resource_id'] != slot['metadata_resource_id']:
                wire._fail('repair_mailbox_slot_incomplete')
            slot_refs = {wire.raw_ref(role['document_ref']) for role in root['roles'] if role['role'] == 'mailbox.slot'}
            if wire.raw_ref(feed['slot_ref']) not in slot_refs:
                wire._fail('repair_mailbox_slot_incomplete')
            slot_payload = wire.parse_new_wire(held[wire.raw_ref(feed['slot_ref'])], s.policy, budget).value['payload']
            sender_id = slot_payload['sender']['signing_key_id']
            data = s._one('SELECT * FROM open_repair_mailbox_resources WHERE resource_id=?', (slot['data_resource_id'],))
            if data is None:
                wire._fail('repair_original_missing')
            data_offer = wire.parse_new_wire(s._saved(data, 'offer')['raw'], s.policy, budget).value['payload']
            if data_offer['resource'] != slot_payload['data_resource_ref']:
                wire._fail('repair_storage_corrupt')
            data_scope = status.status_scope(key['root_key'], 'resource', data_offer['resource'], s.policy, budget)
            data_required = [dict(issuer=s.identity.key_id, scope_kind='resource', scope_id=data_scope,
                document_revision=data_offer['reservation_generation'], operation_mask=2)]
            deadlines.extend(data_offer['windows'][name] for name in ('read_until', 'retain_until'))
            retains.append(data_offer['windows']['retain_until'])
            def data_guard():
                current = s._one('SELECT status FROM open_repair_mailbox_resources WHERE resource_id=?', (slot['data_resource_id'],))
                if current is None or current['status'] != 'active':
                    return 'repair_resource_inactive'
                return MailboxStatusLedger(self.staging.resources).check_locked(slot['data_resource_id'], data_required, _budget=budget)
            guards.append(data_guard)
            for payload in (root_payload, feed_payload):
                deadlines.extend((payload['read_until'], payload['retain_until']))
                retains.append(payload['retain_until'])
            # The feed's member list is the selected full prefix, not a query
            # for every message the node happens to hold for this sender.
            envelopes = []; members = []; member_packs = []
            for member in feed['members']:
                row = s._one('SELECT * FROM open_mailbox_member_history WHERE sender=? AND message_id=?', (sender_id, member['message_id']))
                job = s._one('SELECT * FROM open_mailbox_message_staging WHERE sender=? AND message_id=?', (sender_id, member['message_id']))
                if row is None or job is None or job['phase'] != 'committed':
                    wire._fail('repair_original_missing')
                member_pack = pack(row); member_packs.append(member_pack.ref)
                member_entry, member_history = manifest(row, member_pack)
                if (member_entry['ref'] != member['historical_manifest_ref'] or member_history['slot_key'] != key
                        or member_history['envelope_ref'] != member['envelope_ref']
                        or job['data_id'] != slot['data_resource_id'] or job['metadata_id'] != slot['metadata_resource_id']):
                    wire._fail('repair_storage_corrupt')
                core_raw = held[wire.raw_ref(member['admission_core_ref'])]
                signed = wire.parse_new_wire(core_raw, s.policy, budget).value
                core = signed['payload']
                original._verify_control_signature(core, signed['proof'], s.identity.public_descriptor(), budget)
                admission = s._one('SELECT * FROM open_mailbox_admissions WHERE slot_digest=? AND sequence=?', (slot_digest, member['sequence']))
                if admission is None:
                    wire._fail('repair_original_missing')
                artifacts = wire.parse_new_wire(bytes(admission['result']), s.policy, budget).value
                if (core['envelope_ref'] != member['envelope_ref'] or core['message_id'] != member['message_id']
                        or core['slot_key'] != key or core['data_resource_ref'] != data_offer['resource']
                        or artifacts['core']['raw'].encode() != core_raw
                        or admission['sender'] != sender_id or admission['message_id'] != member['message_id']):
                    wire._fail('repair_storage_corrupt')
                deadlines.extend((job['retain_until'], core['object_until'], core['enum_until']))
                retains.extend((job['retain_until'], core['object_until'], core['enum_until']))
                envelope = add(bytes(job['envelope']), member['envelope_ref']); envelopes.append(envelope)
                events = [('history.mailbox_member', wire.raw_ref(member_entry['ref'])),
                    ('history.raw_pack', member_pack.ref), ('message.envelope', envelope)]
                for role, field in (('member.core', 'admission_core_ref'), ('member.link', 'admission_link_ref'), ('member.custody', 'source_custody_ref')):
                    ref = wire.raw_ref(member[field])
                    if ref not in held:
                        wire._fail('repair_original_missing')
                    events.append((role, ref))
                for name in ('checkpoint', 'head', 'sealed_core'):
                    ref = wire.raw_ref(artifacts[name]['ref'])
                    if ref not in held or artifacts[name]['raw'].encode() != held[ref]:
                        wire._fail('repair_original_missing')
                    events.append(('member.' + name, ref))
                members.append(part(dict(kind='mailbox_member', slot_key=key, attempt_ref=member_history['attempt_ref'],
                    envelope_ref=member['envelope_ref'], admission_link_ref=member['admission_link_ref'],
                    source_custody_ref=member['source_custody_ref']), member_entry, member['source_custody_ref'], events, (envelope,)))
            code = guard()
            if code:
                wire._fail(code)
            # Keep the three R3 operation roots independent. A feed transfer
            # cannot disclose the owner's discovery catalog, and a root/feed
            # reservation cannot silently take on message ciphertext storage.
            root_part = part(dict(kind='mailbox_root', root_key=key['root_key'],
                root_authority_ref=root['root_authority_ref'], catalog_ref=root['catalog_ref']), root_manifest, root_custody['ref'], (
                    ('history.mailbox_root', wire.raw_ref(root_manifest['ref'])), ('root.custody', wire.raw_ref(root_custody['ref'])),
                    ('history.raw_pack', root_pack.ref)))
            feed_part = part(dict(kind='mailbox_feed', slot_key=key, slot_ref=feed['slot_ref'], feed_head_ref=head.as_dict(),
                source_custody_ref=feed_custody['ref'], subtree=dict(feed['covered_interval'], **feed['subtree'])),
                feed_manifest, feed_custody['ref'], [
                    ('history.mailbox_feed', wire.raw_ref(feed_manifest['ref'])), ('feed.custody', wire.raw_ref(feed_custody['ref'])),
                    ('history.raw_pack', feed_pack.ref), *(('history.raw_pack', ref) for ref in member_packs)], envelopes)
            parts = (root_part, feed_part, *members)
            transfer = ordered(item for value in parts for item in value.transfer)
            return MailboxSourceSnapshot(
                wire.raw_ref(root_manifest['ref']), wire.raw_ref(root_custody['ref']),
                wire.raw_ref(feed_manifest['ref']), wire.raw_ref(feed_custody['ref']),
                MappingProxyType(held), transfer, parts, tuple(envelopes), min(deadlines),
                min(retains))
