"""Durable mailbox-root uploads under independent real replica reservations.

The sender must authenticate both advance disclosure and destination possession
before transfer. A closed stage retains bytes provisionally; only the original
authority checks and atomic storage below produce replica custody.
"""
from memory_vault_open_repair_copy_upload import RepairCopyUpload
from memory_vault_open_repair_mailbox_copy_state import MailboxCopyState
import memory_vault_open_repair_stage as stage
import memory_vault_open_repair_wire as wire
import memory_vault_open_repair_history as history


class MailboxRootCopyUpload(RepairCopyUpload):
    consumers = {'mailbox_root': 'mailbox_copy_root'}
    commit_kinds = {'mailbox_root': 'mailbox.root_copy_commit'}
    committed_kind = 'mailbox.copy_committed'

    def __init__(self, state):
        super().__init__(state)
        self.store = MailboxCopyState(state)

    def _commit_scope(self, allocation):
        return dict(expected_root=allocation['root_key'])

    def _commit_closed(self, rid, row, allocation, parents, budget, *, expected_root,
            expected_owner, expected_source, source_storage_epoch, expected_maintainer, bound):
        if bound is not None or allocation['caller'] != expected_maintainer:
            wire._fail('repair_copy_upload_mismatch')
        stage.verify_stage_result(parents['result'], parents['closed'], parents['intent'], parents['handle'],
            **self._options(allocation, budget))
        roles = {}
        for child in self._children(rid, parents, budget):
            roles.setdefault(child['role'], []).append(dict(raw=child['raw'], ref=child['ref']))
        one = lambda role: roles[role][0]
        if (one('copy.allocation') != self.state._saved(row, 'request')
                or one('copy.offer') != self.state._saved(row, 'offer')):
            wire._fail('repair_copy_upload_mismatch')
        manifest = wire.parse_new_wire(one('history.mailbox_root')['raw'], budget.policy, budget).value
        required = {wire.raw_ref(member['pack_ref']) for member in manifest['roles']}
        if required != {wire.raw_ref(entry['ref']) for entry in roles['history.raw_pack']}:
            wire._fail('repair_copy_upload_mismatch')
        resolver = wire.LocalRawResolver(self.state.policy, budget)
        for entry in roles['history.raw_pack']:
            resolver.put(entry['ref']['namespace'], entry['ref']['key'], entry['raw'])
        return self.store.commit_root(one('history.mailbox_root'), resolver, one('root.custody'),
            one('copy.allocation'), one('copy.offer'), one('copy.assignment'), one('copy.reservation_consent'),
            one('copy.owner_disclosure'), one('copy.source_disclosure'), expected_root=expected_root,
            expected_owner=expected_owner, expected_source=expected_source, source_storage_epoch=source_storage_epoch,
            expected_maintainer=expected_maintainer, current_statuses=roles['copy.current_status'], limit_policy=self.state.limits)


class MailboxFeedCopyUpload(MailboxRootCopyUpload):
    consumers = {'mailbox_feed': 'mailbox_copy_feed'}
    commit_kinds = {'mailbox_feed': 'mailbox.feed_copy_commit'}

    def _commit_response(self, manifest, custody):
        from memory_vault_open_repair_index_state import encode_entry
        return dict(schema_version=stage.SCHEMA, kind='mailbox.feed_copy_committed',
            manifest_ref=manifest['ref'], custody=encode_entry(custody))

    def __init__(self, state):
        from memory_vault_open_repair_mailbox_feed_copy_state import MailboxFeedCopyState
        RepairCopyUpload.__init__(self, state)
        self.store = MailboxFeedCopyState(state)

    def _commit_scope(self, allocation):
        return dict(expected_slot=allocation['scope']['slot_key'])

    def _commit_closed(self, rid, row, allocation, parents, budget, *, expected_slot,
            expected_owner, expected_source, source_storage_epoch, expected_maintainer, bound):
        wire.object_fields(bound, {'expected_sender'})
        if allocation['caller'] != expected_maintainer: wire._fail('repair_copy_upload_mismatch')
        stage.verify_stage_result(parents['result'], parents['closed'], parents['intent'], parents['handle'], **self._options(allocation, budget))
        roles = {}
        for child in self._children(rid, parents, budget):
            roles.setdefault(child['role'], []).append(dict(raw=child['raw'], ref=child['ref']))
        one = lambda role: roles[role][0]
        if one('copy.allocation') != self.state._saved(row, 'request') or one('copy.offer') != self.state._saved(row, 'offer'):
            wire._fail('repair_copy_upload_mismatch')
        resolver = wire.LocalRawResolver(self.state.policy, budget)
        for entry in roles['history.raw_pack']: resolver.put(entry['ref']['namespace'], entry['ref']['key'], entry['raw'])
        source = history.resolve_historical_inputs(one('history.mailbox_feed')['raw'], resolver, budget.policy, budget)
        required = {wire.raw_ref(row['pack_ref']) for manifest in (source, *source.predecessors) for row in manifest.manifest.value['roles']}
        if required != {wire.raw_ref(entry['ref']) for entry in roles['history.raw_pack']}: wire._fail('repair_copy_upload_mismatch')
        return self.store.commit_feed(one('history.mailbox_feed'), resolver, one('feed.custody'), one('copy.allocation'),
            one('copy.offer'), one('copy.assignment'), one('copy.reservation_consent'), one('copy.sender_reservation_consent'),
            one('copy.owner_disclosure'), one('copy.source_disclosure'), one('copy.sender_disclosure'), expected_slot=expected_slot,
            expected_owner=expected_owner, expected_source=expected_source, source_storage_epoch=source_storage_epoch,
            expected_maintainer=expected_maintainer, **bound, current_statuses=roles['copy.current_status'], limit_policy=self.state.limits)
