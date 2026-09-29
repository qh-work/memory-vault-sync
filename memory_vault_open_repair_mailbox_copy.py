"""Real, separate mailbox replica reservations under the R3 closed scopes.

An operator invokes these local reservations before a maintainer can assign
copy work. Offers grant no disclosure, upload, custody or current read access.
The existing ACK allocation endpoint remains ACK-only.
"""
import memory_vault_open_repair_history as history
import memory_vault_open_repair_resource as resource
import memory_vault_open_repair_wire as wire
from memory_vault_open_repair_copy_resources import RepairCopyResources, RepairRemoteCopyAllocation


def mailbox_copy_scope(value, root, purpose):
    if type(value) not in (dict, wire._DraftDict):
        wire._fail('repair_copy_scope')
    kind = value.get('kind')
    fields = {
        'mailbox_root': {'root_key', 'root_authority_ref', 'catalog_ref'},
        'mailbox_feed': {'slot_key', 'slot_ref', 'feed_head_ref', 'source_custody_ref', 'subtree'},
        'mailbox_member': {'slot_key', 'attempt_ref', 'envelope_ref', 'admission_link_ref', 'source_custody_ref'},
    }
    purposes = {'mailbox_root': 'root_replica', 'mailbox_feed': 'feed_replica', 'mailbox_member': 'message_replica'}
    if type(kind) is not str or kind not in fields or purpose != purposes[kind]:
        wire._fail('repair_copy_scope')
    history._root(root)
    if root['root_kind'] != 'mailbox':
        wire._fail('repair_copy_scope')
    resource._fields(value, {'kind'} | fields[kind])
    if kind == 'mailbox_root':
        history._root(value['root_key'])
        if value['root_key'] != root:
            wire._fail('repair_copy_scope')
    else:
        history._slot(value['slot_key'], root)
    for name in fields[kind] - {'root_key', 'slot_key', 'subtree'}:
        ref = wire.raw_ref(value[name])
        if ref.namespace != ('object' if name == 'envelope_ref' else 'meta'):
            wire._fail('repair_copy_scope')
    if kind == 'mailbox_feed':
        subtree = resource._fields(value['subtree'], {'start', 'end', 'root_ref', 'parent_path_refs'})
        # The current source implementation commits complete prefixes only.
        # A reservation cannot advertise partial interval support in advance.
        if (wire.u53(subtree['start']) != 0 or not 1 <= wire.u53(subtree['end']) <= 65536
                or subtree['parent_path_refs'] != [] or wire.raw_ref(subtree['root_ref']).namespace != 'meta'):
            wire._fail('repair_copy_scope')


class MailboxCopyResources(RepairCopyResources):
    def _validate_scope(self, intent):
        mailbox_copy_scope(intent['scope'], intent['root_key'], intent['purpose'])

    def _validate_live_capacity(self, intent, caps):
        if intent['purpose'] in ('root_replica', 'feed_replica'):
            if caps['max_live_bytes'] != 0:
                wire._fail('repair_copy_capacity')
        elif caps['max_live_bytes'] < wire.raw_ref(intent['scope']['envelope_ref']).size:
            wire._fail('repair_copy_capacity')


class MailboxRemoteCopyAllocation(RepairRemoteCopyAllocation):
    """Explicit operator opt-in with its own durable finite request allowance.

    Capacity and per-resource work remain shared with other node services.
    Enabling ACK reservations does not enable this endpoint, or the reverse.
    Caller and destination dual possession remain prerequisites for upload.
    """
    callers_table='open_repair_mailbox_copy_remote_callers'
    work_table='open_repair_mailbox_copy_remote_work'
    policy_key='remote_mailbox_copy_policy'
    journal_prefix='mailbox_copy_remote_'
    operation_id='remote_mailbox_copy'
    request_kind='mailbox.copy_allocate'
    response_kind='mailbox.copy_allocation'
    resource_type=MailboxCopyResources
