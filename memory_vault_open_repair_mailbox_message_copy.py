"""One exact message replica with its complete original feed dependencies.

The feed snapshot proves the complete live range closure; its custody does not
substitute for the selected message's original custody. New A/B/S consents
explicitly cover the retained metadata. Message bytes use separate live capacity.
Metadata verification does not assert possession or successful receipt of E.
"""
import memory_vault_open_repair_resource as resource
import memory_vault_open_repair_wire as wire
from memory_vault_open_repair_mailbox_copy_authority import _same

RESERVATION_KIND = 'mailbox.message_copy_reservation_consent'
DISCLOSURE_KIND = 'mailbox.message_copy_disclosure'
RETURN_KIND = 'mailbox.message_replica_return_consent'


def select_message_source(feed, envelope_ref, policy, budget):
    from memory_vault_open_delivery import MAX_ENVELOPE_BYTES
    ref = wire.raw_ref(envelope_ref)
    _same(ref.namespace == 'object' and 0 < ref.size <= MAX_ENVELOPE_BYTES)
    value = feed['manifest'].manifest.value
    selected = [member for member in value['members'] if member['envelope_ref'] == ref.as_dict()]
    _same(len(selected) == 1)
    member = selected[0]
    rows = {(row.role, row.original.ref): row.original for row in feed['manifest'].roles}
    custody = rows[('member.custody', wire.raw_ref(member['source_custody_ref']))]
    p = wire.parse_new_wire(custody.raw, policy, budget).value['payload']
    core = wire.parse_new_wire(rows[('member.core', wire.raw_ref(member['admission_core_ref']))].raw, policy, budget).value['payload']
    setup = feed['graph']['members'][member['sequence']]
    _same(setup['attempt']['message_id'] == member['message_id'] and p['envelope_ref'] == ref.as_dict())
    active = setup['resources']['data']['active'].payload
    maximum = min(feed['read_until'], core['object_until'], active['windows']['read_until'])
    retain = min(feed['retain_until'], core['object_until'], active['windows']['retain_until'])
    data_need = next(item for item in setup['obligations'] if item['role'] == 'data_resource')
    scope = dict(kind='mailbox_member', slot_key=value['slot_key'], attempt_ref=core['attempt_ref'],
        envelope_ref=ref.as_dict(), admission_link_ref=member['admission_link_ref'], source_custody_ref=member['source_custody_ref'])
    return dict(feed, feed_custody=feed['custody'], custody=resource.AuthenticatedRepairOriginal(custody.raw, custody.ref, p),
        message_scope=scope, message_history_ref=member['historical_manifest_ref'], message_core_ref=member['admission_core_ref'],
        message_member=dict(sequence=member['sequence'], admission_link_ref=member['admission_link_ref'],
            sealed_core_ref=wire.parse_new_wire(rows[('member.link', wire.raw_ref(member['admission_link_ref']))].raw, policy, budget).value['payload']['sealed_core_ref']),
        graph=dict(feed['graph'], obligations=(*feed['graph']['obligations'], dict(data_need, operation_mask=70))),
        read_until=min(maximum, retain), retain_until=retain)


def verify_mailbox_message_copy(*args, expected_envelope_ref, **options):
    from memory_vault_open_repair_mailbox_feed_copy import _verify_mailbox_copy
    return _verify_mailbox_copy(*args, **options, message_ref=expected_envelope_ref)


def verify_mailbox_message_replica(*args, expected_envelope_ref, **options):
    """Verify complete metadata independently; the caller must retrieve E."""
    from memory_vault_open_repair_mailbox_feed_copy import _verify_mailbox_replica
    return _verify_mailbox_replica(*args, **options, message_ref=expected_envelope_ref)


def verify_message_body(entry, expected_envelope_ref, policy, budget):
    wire._context(policy, budget); wire.object_fields(entry, {'raw', 'ref'})
    ref = wire.raw_ref(expected_envelope_ref)
    from memory_vault_open_delivery import MAX_ENVELOPE_BYTES
    if ref.namespace != 'object' or not 0 < ref.size <= MAX_ENVELOPE_BYTES or wire.raw_ref(entry['ref']) != ref:
        wire._fail('repair_ref_mismatch')
    raw = entry['raw']
    if type(raw) is not bytes or len(raw) != ref.size or budget._hash(raw) != ref.raw_sha256:
        wire._fail('repair_ref_mismatch')
    return wire.RawOriginal(ref, raw)


def check_message_return(*args, **options):
    from memory_vault_open_repair_mailbox_feed_copy import _check_mailbox_feed_return
    return _check_mailbox_feed_return(*args, **options, _message=True)
