"""Atomic full-prefix feed storage in independent real metadata reservations."""
import memory_vault_open_repair_wire as wire
from memory_vault_open_repair_mailbox_copy_state import MailboxCopyState
from memory_vault_open_repair_mailbox_feed_copy import (
    verify_mailbox_feed_copy, verify_mailbox_feed_replica, feed_copy_histories, feed_copy_edges)


class MailboxFeedCopyState(MailboxCopyState):
    verify_copy = staticmethod(verify_mailbox_feed_copy)
    verify_replica = staticmethod(verify_mailbox_feed_replica)

    def _return(self, *args, **options):
        from memory_vault_open_repair_mailbox_feed_copy import _check_mailbox_feed_return
        return _check_mailbox_feed_return(*args, **options)

    def _body_originals(self, plan, entry, budget):
        if entry is not None: wire._fail('repair_copy_scope')
        return ()

    def prepare_feed_read(self, resource_id, consents, *, expected_slot, expected_owner, expected_sender,
            expected_source, source_storage_epoch, expected_maintainer, current_statuses, limit_policy,
            action='proof', _budget=None, _include_replica=False, **bound):
        s = self.source; budget = wire.RepairBudget(s.policy) if _budget is None else _budget
        policy = s._budget_policy(budget)
        with s._transaction():
            row, _ = self._committed(resource_id)
            caps = wire.parse_new_wire(s._saved(row, 'offer')['raw'], policy, budget).value['payload']['budget']
            work = s._one('SELECT requests FROM open_repair_copy_work WHERE resource_id=?', (resource_id,))
            count = work['requests'] if work else 0
            if count >= min(64, caps['max_requests'], caps['max_replay_records']): wire._fail('repair_copy_work_capacity')
            self.db.execute('INSERT OR REPLACE INTO open_repair_copy_work VALUES(?,?)', (resource_id, count + 1))
        replica = self.restore_feed(resource_id, expected_slot=expected_slot, expected_owner=expected_owner,
            expected_sender=expected_sender, expected_source=expected_source, source_storage_epoch=source_storage_epoch,
            expected_maintainer=expected_maintainer, limit_policy=limit_policy, _budget=budget, **bound)
        root = replica['custody'].payload['root_key']; digest = budget._hash(wire._canonical(root, budget))
        plan = self._return(replica, consents, expected_owner=expected_owner, expected_sender=expected_sender,
            expected_source=expected_source, expected_maintainer=expected_maintainer, expected_target=s.target,
            target_storage_epoch=s.node['payload']['storage_epoch'], current_statuses=current_statuses, at=s._now(),
            action=action, policy=policy, budget=budget, on_observed=lambda item: self._observe_single(row, caps, digest, item))
        source_statuses = (*replica['source']['graph']['statuses'], *(item for member in replica['source']['graph']['members'] for item in member['statuses']))
        return self._finish_copy_read(resource_id, replica, plan, digest, budget,
            source_statuses=source_statuses, action=action, _include_replica=_include_replica)

    def commit_feed(self, manifest_entry, resolver, custody_entry, allocation_entry, offer_entry,
            assignment_entry, reservation_entry, sender_reservation_entry, owner_disclosure_entry,
            source_disclosure_entry, sender_disclosure_entry, *, expected_slot, expected_owner, expected_sender,
            expected_source, source_storage_epoch, expected_maintainer, current_statuses, limit_policy, body_entry=None, **bound):
        s = self.source; budget = resolver.budget; policy = s._budget_policy(budget)
        offer = self.allocate(allocation_entry, expected_caller=expected_maintainer)
        if offer != offer_entry: wire._fail('repair_copy_offer_mismatch')
        payload = wire.parse_new_wire(offer['raw'], policy, budget).value['payload']
        rid = payload['resource']['resource_id']; caps = payload['budget']
        row = s._one('SELECT * FROM open_repair_copy_resources WHERE resource_id=?', (rid,))
        with s._transaction():
            work = s._one('SELECT requests FROM open_repair_copy_work WHERE resource_id=?', (rid,))
            count = work['requests'] if work else 0
            if count >= min(64, caps['max_requests'], caps['max_replay_records']): wire._fail('repair_copy_work_capacity')
            self.db.execute('INSERT OR REPLACE INTO open_repair_copy_work VALUES(?,?)', (rid, count + 1))
            held = s._one('SELECT * FROM open_repair_copy_commits WHERE resource_id=?', (rid,))
            if held is not None: self._load_inventory(row, held, budget)
        root_digest = budget._hash(wire._canonical(payload['intent']['root_key'], budget))
        plan = self.verify_copy(manifest_entry, resolver, custody_entry, allocation_entry, offer_entry,
            assignment_entry, reservation_entry, sender_reservation_entry, owner_disclosure_entry,
            source_disclosure_entry, sender_disclosure_entry, expected_slot=expected_slot, expected_owner=expected_owner,
            expected_sender=expected_sender, expected_source=expected_source, source_storage_epoch=source_storage_epoch,
            expected_maintainer=expected_maintainer, expected_target=s.target,
            target_storage_epoch=s.node['payload']['storage_epoch'], current_statuses=current_statuses,
            at=s._now(), limit_policy=limit_policy, policy=policy, budget=budget,
            on_observed=lambda item: self._observe_single(row, caps, root_digest, item), **bound)
        return self._store_copy_plan(row, plan, resolver,
            source_histories=feed_copy_histories(plan.source, manifest_entry), source_custody=plan.source['custody'],
            additional=(('copy.sender_disclosure', plan.disclosures[2]),), extra_edges=feed_copy_edges(plan.source, policy, budget),
            live_originals=self._body_originals(plan, body_entry, budget))

    def restore_feed(self, resource_id, *, expected_slot, expected_owner, expected_sender, expected_source,
            source_storage_epoch, expected_maintainer, limit_policy, _budget=None, **bound):
        s = self.source; budget = wire.RepairBudget(s.policy) if _budget is None else _budget
        policy = s._budget_policy(budget)
        with s._transaction():
            row, held = self._committed(resource_id)
            _, _, entries = self._load_inventory(row, held, budget)
        resolver = wire.LocalRawResolver(policy, budget)
        for values in entries.values():
            for entry in values:
                ref = wire.raw_ref(entry['ref'])
                if ref.namespace == 'meta' and resolver.put(ref.namespace, ref.key, entry['raw']).ref != ref: wire._fail('repair_ref_mismatch')
        return self.verify_replica(s._saved(held, 'manifest'), resolver, s._saved(held, 'custody'),
            expected_slot=expected_slot, expected_owner=expected_owner, expected_sender=expected_sender,
            expected_source=expected_source, source_storage_epoch=source_storage_epoch, expected_maintainer=expected_maintainer,
            expected_target=s.target, target_storage_epoch=s.node['payload']['storage_epoch'],
            limit_policy=limit_policy, policy=policy, budget=budget, **bound)
