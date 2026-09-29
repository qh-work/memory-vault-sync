"""Commit original discovery-root replicas to actually reserved local storage.

Remote upload/disclosure and later recipient serving remain separate protocols.
No feed or message becomes readable merely because its root metadata is copied.
"""
import memory_vault_open_repair_wire as wire
from memory_vault_open_repair_copy_state import RepairCopyState
from memory_vault_open_repair_mailbox_copy import MailboxCopyResources
from memory_vault_open_repair_mailbox_copy_authority import verify_mailbox_root_copy


class MailboxCopyState(RepairCopyState, MailboxCopyResources):
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


def root_copy_edges(source):
    """Recompute typed discovery edges from the authenticated original graph."""
    setup = source['setup']; catalog = setup['originals']['catalog']; edges = []
    for slot in setup['slots']:
        original = slot['originals']['slot']; head = slot['genesis']['head']; checkpoint = slot['genesis']['checkpoint']
        for parent, relation, child in ((catalog, 'catalog-slot', original),
                (original, 'slot-feed', head), (head, 'head-checkpoint', checkpoint)):
            edges.append(dict(parent_ref=parent.ref.as_dict(), relation=relation, child_ref=child.ref.as_dict()))
    return tuple(edges)
