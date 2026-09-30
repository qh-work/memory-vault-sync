"""Private bundles for explicit directory-copy upload and recipient recovery."""
from dataclasses import replace
import hashlib
import math
import os
import time

from memory_vault import canonical_bytes
from memory_vault_network_crypto import document, object_fields, unb64url
from memory_vault_open_client import OpenNetworkClient
from memory_vault_open_repair_admin import _entry, _encoded, _ReplicaStatusJournal, MAX_COPY_BUNDLE_BYTES
from memory_vault_open_repair_mailbox_copy_client import MailboxRootCopyUploadClient, MailboxRootReplicaRecoveryClient, MailboxFeedCopyUploadClient, MailboxFeedReplicaRecoveryClient, MailboxMessageCopyUploadClient, MailboxMessageReplicaRecoveryClient
from memory_vault_open_repair_mailbox_copy_prepare import MailboxRootCopyPreparation, MailboxFeedCopyPreparation, MailboxMessageCopyPreparation
from memory_vault_open_repair_state import DEFAULT_POLICY, DEFAULT_LIMITS, RECEIPT_WORKFLOW_LIMITS, INDEX_WORKFLOW_LIMITS, MAILBOX_WORKFLOW_LIMITS
from memory_vault_trust import _absolute_path, _read_private, _write_new_private
import memory_vault_open_repair_history as history
import memory_vault_open_repair_resource as resource
import memory_vault_open_repair_wire as wire

UPLOAD_SCHEMA = 'memory-vault-open-mailbox-root-copy-request/v1'
FEED_UPLOAD_SCHEMA = 'memory-vault-open-mailbox-feed-copy-request/v1'
MESSAGE_UPLOAD_SCHEMA = 'memory-vault-open-mailbox-message-copy-request/v1'
RECOVER_SCHEMA = 'memory-vault-open-mailbox-root-replica-recovery-request/v1'
FEED_RECOVER_SCHEMA = 'memory-vault-open-mailbox-feed-replica-recovery-request/v1'
MESSAGE_RECOVER_SCHEMA = 'memory-vault-open-mailbox-message-replica-recovery-request/v1'
CONFIG_SCHEMA = 'memory-vault-open-mailbox-root-replica-read-config/v1'


def _request(path, output, schema, fields, profile):
    output = _absolute_path(output)
    if os.path.lexists(output): raise wire.RepairWireError('repair_output_exists')
    raw = _read_private(_absolute_path(path), MAX_COPY_BUNDLE_BYTES)
    if raw is None: raise wire.RepairWireError('repair_request_missing')
    request = object_fields(document(raw, maximum=MAX_COPY_BUNDLE_BYTES), fields | {'schema_version'})
    profiles = {'unbound': DEFAULT_LIMITS, 'receipt': RECEIPT_WORKFLOW_LIMITS, 'receipt-index': INDEX_WORKFLOW_LIMITS, 'mailbox': MAILBOX_WORKFLOW_LIMITS}
    if request['schema_version'] != schema or profile not in profiles: raise wire.RepairWireError('repair_invalid_request_bundle')
    history._root(request['root_key'])
    if request['root_key']['root_kind'] != 'mailbox': raise wire.RepairWireError('repair_invalid_request_bundle')
    return request, output, profiles[profile]


def _base(entry):
    node = document(entry['raw'], maximum=DEFAULT_POLICY.max_document_bytes)
    try: return node['payload']['base_url']
    except (KeyError, TypeError): raise wire.RepairWireError('repair_invalid_request_bundle') from None


def _output(path, evidence):
    raw = canonical_bytes(evidence) + b'\n'
    if len(raw) > MAX_COPY_BUNDLE_BYTES: raise wire.RepairWireError('repair_over_budget')
    _write_new_private(path, raw)
    return dict(state=evidence['state'], evidence_path=str(path), evidence_sha256=hashlib.sha256(raw).hexdigest(),
        vault_modified=evidence.get('vault_modified',False), recipient_saved=evidence.get('recipient_saved',False))


def upload_root(network_config, request_path, output, *, timeout=30, repair_profile=None):
    return _upload_mailbox(network_config, request_path, output, timeout=timeout, repair_profile=repair_profile, source_state='root')


def reserve_mailbox(network_config, request_path, output, *, source_state, timeout=30, repair_profile=None):
    """Reserve real target capacity, then sign only this maintainer's assignment."""
    if source_state not in ('root', 'feed', 'message'):
        raise wire.RepairWireError('repair_invalid_request_bundle')
    feed = source_state != 'root'
    names = ('node', 'manifest', 'custody', 'reservation') + (('sender_reservation',) if feed else ())
    request, output, limits = _request(request_path, output,
        'memory-vault-open-mailbox-'+source_state+'-copy-reservation-request/v1',
        set(names) | {'root_key', 'owner', 'source', 'source_storage_epoch', 'intent', 'originals', 'current_statuses'}
            | ({'slot_key', 'sender'} if feed else set()) | ({'envelope_ref'} if source_state == 'message' else set()),
        repair_profile or 'unbound')
    if feed: history._slot(request['slot_key'], request['root_key'])
    if type(request['originals']) is not list or not 1 <= len(request['originals']) <= 64:
        raise wire.RepairWireError('repair_invalid_request_bundle')
    if type(request['current_statuses']) is not list or not 1 <= len(request['current_statuses']) <= 16:
        raise wire.RepairWireError('repair_invalid_status')
    entries = {name: _entry(request[name]) for name in names}
    originals = [_entry(value) for value in request['originals']]
    statuses = [_entry(value) for value in request['current_statuses']]
    if type(request['intent']) is not dict or request['intent'].get('root_key') != request['root_key']:
        raise wire.RepairWireError('repair_invalid_request_bundle')
    def resolver():
        result = wire.LocalRawResolver(DEFAULT_POLICY, wire.RepairBudget(DEFAULT_POLICY))
        for entry in originals:
            ref = wire.raw_ref(entry['ref'])
            if result.put(ref.namespace, ref.key, entry['raw']).ref != ref:
                raise wire.RepairWireError('repair_ref_mismatch')
        return result
    context = dict(expected_owner=request['owner'], expected_source=request['source'],
        source_storage_epoch=request['source_storage_epoch'], current_statuses=statuses, limit_policy=limits)
    if feed:
        context.update(expected_slot=request['slot_key'], expected_sender=request['sender'],
            sender_reservation_entry=entries['sender_reservation'])
    else: context['expected_root'] = request['root_key']
    if source_state == 'message': context['expected_envelope_ref'] = request['envelope_ref']
    journal_type, client_type = {
        'root': (MailboxRootCopyPreparation, MailboxRootCopyUploadClient),
        'feed': (MailboxFeedCopyPreparation, MailboxFeedCopyUploadClient),
        'message': (MailboxMessageCopyPreparation, MailboxMessageCopyUploadClient)}[source_state]
    with OpenNetworkClient(_absolute_path(network_config)) as network, network.participant.state.db() as db:
        journal = journal_type(db, network.identity, network.encryption, policy=DEFAULT_POLICY)
        client = client_type(journal, encryption_identity=network.encryption,
            transport=network.participant.transport, allow_loopback=network.participant.transport.allow_loopback)
        try:
            result = client.reserve(_base(entries['node']), entries['manifest'], resolver(), entries['custody'],
                entries['reservation'], request['intent'], target_node_entry=entries['node'], timeout=timeout, **context)
            assigned = journal.prepare_reservation(entries['manifest'], resolver(), entries['custody'],
                entries['reservation'], request['intent'], offer_entry=result['offer'], at=int(time.time()), **context)
        finally: client.close()
    evidence = dict(schema_version='memory-vault-open-mailbox-'+source_state+'-copy-reservation-result/v1',
        state='capacity_reserved_and_assigned', root_key=request['root_key'],
        target=request['intent']['target'], target_storage_epoch=request['intent']['target_storage_epoch'],
        allocation=_encoded(result['allocation']['raw'], wire.raw_ref(result['allocation']['ref'])),
        offer=_encoded(result['offer']['raw'], wire.raw_ref(result['offer']['ref'])),
        assignment=_encoded(assigned['assignment']['raw'], wire.raw_ref(assigned['assignment']['ref'])),
        vault_modified=False, recipient_saved=False)
    return _output(output, evidence)


def upload_feed(network_config, request_path, output, *, timeout=30, repair_profile=None):
    return _upload_mailbox(network_config, request_path, output, timeout=timeout, repair_profile=repair_profile, source_state='feed')


def upload_message(network_config, request_path, output, *, timeout=30, repair_profile=None):
    return _upload_mailbox(network_config,request_path,output,timeout=timeout,repair_profile=repair_profile,source_state='message')


def _upload_mailbox(network_config, request_path, output, *, timeout, repair_profile, source_state):
    """Upload an already allocated and independently consented exact transcript."""
    feed = source_state in ('feed','message'); message=source_state=='message'
    names = ('node', 'manifest', 'custody', 'allocation', 'offer', 'assignment', 'reservation', 'owner_disclosure', 'source_disclosure')
    if feed: names += ('sender_reservation', 'sender_disclosure')
    request, output, limits = _request(request_path, output, MESSAGE_UPLOAD_SCHEMA if message else FEED_UPLOAD_SCHEMA if feed else UPLOAD_SCHEMA,
        set(names) | {'root_key', 'owner', 'source', 'source_storage_epoch', 'target', 'target_storage_epoch', 'originals', 'current_statuses'}
            | ({'slot_key', 'sender'} if feed else set()) | ({'envelope'} if message else set()), repair_profile or 'unbound')
    if feed: history._slot(request['slot_key'], request['root_key'])
    if type(request['originals']) is not list or not 1 <= len(request['originals']) <= 64: raise wire.RepairWireError('repair_invalid_request_bundle')
    if type(request['current_statuses']) is not list or not 1 <= len(request['current_statuses']) <= 16: raise wire.RepairWireError('repair_invalid_status')
    entries = {name: _entry(request[name]) for name in names}
    if message:
        from memory_vault_open_delivery import MAX_ENVELOPE_BYTES
        from memory_vault_open_repair_mailbox_message_copy import verify_message_body
        value=object_fields(request['envelope'],{'ref','raw_base64url'})
        envelope=dict(raw=unb64url(value['raw_base64url'],maximum=MAX_ENVELOPE_BYTES),ref=value['ref'])
        verify_message_body(envelope,value['ref'],DEFAULT_POLICY,wire.RepairBudget(DEFAULT_POLICY))
    base = _base(entries['node'])
    resolver = wire.LocalRawResolver(DEFAULT_POLICY, wire.RepairBudget(DEFAULT_POLICY))
    for value in request['originals']:
        entry = _entry(value); ref = wire.raw_ref(entry['ref'])
        if resolver.put(ref.namespace, ref.key, entry['raw']).ref != ref: raise wire.RepairWireError('repair_ref_mismatch')
    with OpenNetworkClient(_absolute_path(network_config)) as network, network.participant.state.db() as db:
        journal = (MailboxMessageCopyPreparation if message else MailboxFeedCopyPreparation if feed else MailboxRootCopyPreparation)(db, network.identity, network.encryption, policy=DEFAULT_POLICY)
        client = (MailboxMessageCopyUploadClient if message else MailboxFeedCopyUploadClient if feed else MailboxRootCopyUploadClient)(journal, encryption_identity=network.encryption,
            transport=network.participant.transport, allow_loopback=network.participant.transport.allow_loopback)
        try:
            originals = (entries['manifest'], resolver, entries['custody'], entries['allocation'], entries['offer'], entries['assignment'], entries['reservation'])
            if feed: originals += (entries['sender_reservation'],)
            originals += (entries['owner_disclosure'], entries['source_disclosure'])
            if feed: originals += (entries['sender_disclosure'],)
            selection = dict(expected_slot=request['slot_key'], expected_sender=request['sender']) if feed else dict(expected_root=request['root_key'])
            if message:selection.update(expected_envelope_ref=envelope['ref'],envelope_entry=envelope)
            result = client.upload(base, *originals, target_node_entry=entries['node'], **selection,
                expected_owner=request['owner'], expected_source=request['source'],
                source_storage_epoch=request['source_storage_epoch'], expected_target=request['target'],
                target_storage_epoch=request['target_storage_epoch'], current_statuses=[_entry(e) for e in request['current_statuses']],
                limit_policy=limits, timeout=timeout)
        finally: client.close()
    evidence = dict(schema_version='memory-vault-open-mailbox-'+source_state+'-copy-result/v1', state=result['state'],
        root_key=request['root_key'], target=request['target'], target_storage_epoch=request['target_storage_epoch'],
        manifest=_encoded(result['manifest']['raw'], wire.raw_ref(result['manifest']['ref'])),
        custody=_encoded(result['custody']['raw'], wire.raw_ref(result['custody']['ref'])), vault_modified=False, recipient_saved=False)
    return _output(output, evidence)


def recover_root(network_config, request_path, output, *, timeout=30, repair_profile=None):
    return _recover_mailbox(network_config, request_path, output, timeout=timeout, repair_profile=repair_profile, source_state='root')


def recover_feed(network_config, request_path, output, *, timeout=30, repair_profile=None):
    return _recover_mailbox(network_config, request_path, output, timeout=timeout, repair_profile=repair_profile, source_state='feed')


def receive_message(network_config, request_path, output, *, timeout=30, repair_profile=None):
    return _recover_mailbox(network_config,request_path,output,timeout=timeout,repair_profile=repair_profile,source_state='message')


def _recover_mailbox(network_config, request_path, output, *, timeout, repair_profile, source_state):
    """Retain authenticated status floors, including when recovery is denied."""
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 60:
        raise wire.RepairWireError('repair_invalid_deadline')
    deadline = time.monotonic() + timeout
    feed = source_state in ('feed','message');message=source_state=='message'
    request, output, limits = _request(request_path, output, MESSAGE_RECOVER_SCHEMA if message else FEED_RECOVER_SCHEMA if feed else RECOVER_SCHEMA,
        {'root_key', 'target', 'source', 'source_storage_epoch', 'maintainer', 'node', 'known_statuses', 'archive_statuses'}
            | ({'slot_key', 'sender', 'slot_entries'} if feed else {'root', 'read', 'bootstrap'}) | ({'envelope_ref'} if message else set()), repair_profile or 'unbound')
    if feed: history._slot(request['slot_key'], request['root_key'])
    for name, maximum in (('known_statuses', 16), ('archive_statuses', 32)):
        if type(request[name]) is not list or len(request[name]) > maximum: raise wire.RepairWireError('repair_status_history_capacity')
    entries = {name: _entry(request[name]) for name in (('node',) if feed else ('node', 'root', 'read', 'bootstrap'))}
    if feed:
        object_fields(request['slot_entries'], {'slot', 'read', 'maintenance', 'bootstrap'})
        slot_entries = {name: _entry(value) for name, value in request['slot_entries'].items()}
    base = _base(entries['node'])
    with OpenNetworkClient(_absolute_path(network_config)) as network, network.participant.state.db() as db:
        owner = dict(signing_key=network.identity.public_descriptor(), encryption_key=network.encryption.public_descriptor())
        parties = (owner, request['target'], request['source'], request['maintainer']) + ((request['sender'],) if feed else ())
        for party in parties: resource._dual_key(party, wire.RepairBudget(DEFAULT_POLICY))
        resource._opaque(request['source_storage_epoch'])
        journal = _ReplicaStatusJournal(db, request['root_key'])
        archived = {canonical_bytes(item['ref']): item for item in
            (*journal.statuses(parties), *[_entry(e) for e in request['archive_statuses']])}
        if len(archived) > 32: raise wire.RepairWireError('repair_status_history_capacity')
        client = (MailboxMessageReplicaRecoveryClient if message else MailboxFeedReplicaRecoveryClient if feed else MailboxRootReplicaRecoveryClient)(network.identity, network.encryption, limit_policy=limits,
            policy=replace(DEFAULT_POLICY, max_signature_checks=min(512, limits['max_signature_checks'])) if feed else DEFAULT_POLICY,
            transport=network.participant.transport, allow_loopback=network.participant.transport.allow_loopback,
            status_observer=journal.observe)
        try:
            selection = dict(expected_slot=request['slot_key'], expected_sender=request['sender'], slot_entries=slot_entries) if feed else dict(
                expected_root=request['root_key'], root_entry=entries['root'], read_entry=entries['read'], bootstrap_entry=entries['bootstrap'])
            if message:selection['expected_envelope_ref']=request['envelope_ref']
            result = client.recover(base, target_node_entry=entries['node'], expected_target=request['target'], **selection,
                expected_source=request['source'], source_storage_epoch=request['source_storage_epoch'], expected_maintainer=request['maintainer'],
                known_statuses=[_entry(e) for e in request['known_statuses']], archive_statuses=list(archived.values()), timeout=deadline-time.monotonic())
            for item in result.archive_statuses: journal.observe(item)
            if message:
                body=client.read_message(base,result,timeout=deadline-time.monotonic())
                delivery=network._delivery()
                received=delivery.receive_recovered_mailbox_replica(client,result,body,target_node_entry=entries['node'])
                saved=delivery._inbox(body['core']['message_id'])
                saved_result=document(bytes(saved['result']))
                return _output(output,dict(schema_version='memory-vault-open-mailbox-message-replica-receipt/v1',
                    state='mailbox_message_replica_received',message_id=body['core']['message_id'],envelope_ref=request['envelope_ref'],
                    replica_custody=_encoded(result.replica['custody'].raw,result.replica['custody'].ref),
                    recipient_saved=saved['phase']=='saved',recipient_receipt=delivery._saved_receipt(body['core']['message_id']),
                    vault_modified=bool(received['messages'] and saved_result.get('share') and saved_result['share']['records_added']),
                    result=saved_result,receipt_state='retained_for_independent_return'))
        finally: client.close()
    evidence = dict(schema_version='memory-vault-open-mailbox-'+source_state+'-replica-recovery-result/v1', state='mailbox_'+source_state+'_replica_recovered',
        root_key=request['root_key'], target=request['target'], source=request['source'], source_storage_epoch=request['source_storage_epoch'],
        maintainer=request['maintainer'], current_statuses=[_encoded(item.raw, item.ref) for item in result.current_statuses],
        archive_statuses=[_encoded(item.raw, item.ref) for item in result.archive_statuses],
        originals=[_encoded(raw, ref) for ref, raw in sorted(result.originals.items(), key=lambda item: history._ref_tuple(item[0]))],
        replica_custody=_encoded(result.replica['custody'].raw, result.replica['custody'].ref),
        vault_modified=False, recipient_saved=False, metrics=dict(result.metrics))
    if feed: evidence.update(slot_key=request['slot_key'], sender=request['sender'], members=list(result.members))
    return _output(output, evidence)
