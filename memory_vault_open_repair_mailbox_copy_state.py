"""Commit original discovery-root replicas to actually reserved local storage.

Remote upload/disclosure and later recipient serving remain separate protocols.
No feed or message becomes readable merely because its root metadata is copied.
"""
import memory_vault_open_repair_wire as wire
from memory_vault_open_repair_copy_state import RepairCopyState
from memory_vault_open_repair_mailbox_copy import MailboxCopyResources
from memory_vault_open_repair_mailbox_copy_authority import (
    verify_mailbox_root_copy, root_copy_edges, verify_mailbox_root_replica, _check_mailbox_root_return)


class MailboxCopyState(RepairCopyState, MailboxCopyResources):
    def restore_root(self, resource_id, *, expected_root, expected_owner, expected_source, source_storage_epoch,
            expected_maintainer, limit_policy, _budget=None):
        """Reconstruct exact local history; this alone does not authorize reads."""
        s = self.source; budget = wire.RepairBudget(s.policy) if _budget is None else _budget
        policy = s._budget_policy(budget)
        with s._transaction():
            row, held = self._committed(resource_id)
            _, _, entries = self._load_inventory(row, held, budget)
        resolver = wire.LocalRawResolver(policy, budget)
        for values in entries.values():
            for entry in values:
                ref = wire.raw_ref(entry['ref'])
                if resolver.put(ref.namespace, ref.key, entry['raw']).ref != ref: wire._fail('repair_ref_mismatch')
        return verify_mailbox_root_replica(s._saved(held, 'manifest'), resolver, s._saved(held, 'custody'),
            expected_root=expected_root, expected_owner=expected_owner, expected_source=expected_source,
            source_storage_epoch=source_storage_epoch, expected_maintainer=expected_maintainer,
            expected_target=s.target, target_storage_epoch=s.node['payload']['storage_epoch'],
            limit_policy=limit_policy, policy=policy, budget=budget)

    def prepare_root_read(self, resource_id, consents, *, expected_root, expected_owner, expected_source,
            source_storage_epoch, expected_maintainer, current_statuses, limit_policy,
            action='proof', _budget=None, _include_replica=False):
        s = self.source; budget = wire.RepairBudget(s.policy) if _budget is None else _budget
        policy = s._budget_policy(budget)
        with s._transaction():
            row, _ = self._committed(resource_id)
            caps = wire.parse_new_wire(s._saved(row, 'offer')['raw'], policy, budget).value['payload']['budget']
            work = s._one('SELECT requests FROM open_repair_copy_work WHERE resource_id=?', (resource_id,))
            count = work['requests'] if work else 0
            if count >= min(64, caps['max_requests'], caps['max_replay_records']): wire._fail('repair_copy_work_capacity')
            self.db.execute('INSERT OR REPLACE INTO open_repair_copy_work VALUES(?,?)', (resource_id, count + 1))
        replica = self.restore_root(resource_id, expected_root=expected_root, expected_owner=expected_owner,
            expected_source=expected_source, source_storage_epoch=source_storage_epoch,
            expected_maintainer=expected_maintainer, limit_policy=limit_policy, _budget=budget)
        root = replica['custody'].payload['root_key']; digest = budget._hash(wire._canonical(root, budget))
        plan = _check_mailbox_root_return(replica, consents, expected_owner=expected_owner,
            expected_source=expected_source, expected_maintainer=expected_maintainer, expected_target=s.target,
            target_storage_epoch=s.node['payload']['storage_epoch'], current_statuses=current_statuses, at=s._now(),
            action=action, policy=policy, budget=budget, on_observed=lambda item: self._observe_single(row, caps, digest, item))
        return self._finish_copy_read(resource_id, replica, plan, digest, budget,
            source_statuses=replica['source']['statuses'], action=action, _include_replica=_include_replica)

    def commit_root(self, manifest_entry, resolver, custody_entry, allocation_entry, offer_entry,
            assignment_entry, reservation_entry, owner_disclosure_entry, source_disclosure_entry, *,
            expected_root, expected_owner, expected_source, source_storage_epoch, expected_maintainer,
            current_statuses, limit_policy):
        """Sign custody only after full verification and atomic byte storage."""
        s = self.source; budget = resolver.budget; policy = s._budget_policy(budget)
        offer = self.allocate(allocation_entry, expected_caller=expected_maintainer)
        if offer != offer_entry:
            wire._fail('repair_copy_offer_mismatch')
        payload = wire.parse_new_wire(offer['raw'], policy, budget).value['payload']
        rid = payload['resource']['resource_id']; caps = payload['budget']
        row = s._one('SELECT * FROM open_repair_copy_resources WHERE resource_id=?', (rid,))
        with s._transaction():
            work = s._one('SELECT requests FROM open_repair_copy_work WHERE resource_id=?', (rid,))
            count = work['requests'] if work else 0
            if count >= min(64, caps['max_requests'], caps['max_replay_records']):
                wire._fail('repair_copy_work_capacity')
            self.db.execute('INSERT OR REPLACE INTO open_repair_copy_work VALUES(?,?)', (rid, count + 1))
            held = s._one('SELECT * FROM open_repair_copy_commits WHERE resource_id=?', (rid,))
            if held is not None:
                self._load_inventory(row, held, budget)
        root_digest = budget._hash(wire._canonical(payload['intent']['root_key'], budget))
        plan = verify_mailbox_root_copy(manifest_entry, resolver, custody_entry, allocation_entry, offer_entry,
            assignment_entry, reservation_entry, owner_disclosure_entry, source_disclosure_entry,
            expected_root=expected_root, expected_owner=expected_owner, expected_source=expected_source,
            source_storage_epoch=source_storage_epoch, expected_maintainer=expected_maintainer,
            expected_target=s.target, target_storage_epoch=s.node['payload']['storage_epoch'],
            current_statuses=current_statuses, at=s._now(), limit_policy=limit_policy, policy=policy, budget=budget,
            on_observed=lambda item: self._observe_single(row, caps, root_digest, item))
        return self._store_copy_plan(row, plan, resolver,
            source_histories=(('history.mailbox_root', manifest_entry, plan.source['manifest']),),
            source_custody=plan.source['custody'], extra_edges=root_copy_edges(plan.source))
