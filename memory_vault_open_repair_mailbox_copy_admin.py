"""Private bundles for explicit directory-copy upload and recipient recovery."""
from dataclasses import replace
import hashlib
import os

from memory_vault import canonical_bytes
from memory_vault_network_crypto import document, object_fields
from memory_vault_open_client import OpenNetworkClient
from memory_vault_open_repair_admin import _entry, _encoded, _ReplicaStatusJournal, MAX_COPY_BUNDLE_BYTES
from memory_vault_open_repair_mailbox_copy_client import MailboxRootCopyUploadClient, MailboxRootReplicaRecoveryClient, MailboxFeedCopyUploadClient, MailboxFeedReplicaRecoveryClient
from memory_vault_open_repair_mailbox_copy_prepare import MailboxRootCopyPreparation, MailboxFeedCopyPreparation
from memory_vault_open_repair_state import DEFAULT_POLICY, DEFAULT_LIMITS, RECEIPT_WORKFLOW_LIMITS, INDEX_WORKFLOW_LIMITS, MAILBOX_WORKFLOW_LIMITS
from memory_vault_trust import _absolute_path, _read_private, _write_new_private
import memory_vault_open_repair_history as history
import memory_vault_open_repair_resource as resource
import memory_vault_open_repair_wire as wire

UPLOAD_SCHEMA = 'memory-vault-open-mailbox-root-copy-request/v1'
FEED_UPLOAD_SCHEMA = 'memory-vault-open-mailbox-feed-copy-request/v1'
RECOVER_SCHEMA = 'memory-vault-open-mailbox-root-replica-recovery-request/v1'
FEED_RECOVER_SCHEMA = 'memory-vault-open-mailbox-feed-replica-recovery-request/v1'
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
        vault_modified=False, recipient_saved=False)


def upload_root(network_config, request_path, output, *, timeout=30, repair_profile=None):
    return _upload_mailbox(network_config, request_path, output, timeout=timeout, repair_profile=repair_profile, source_state='root')


def upload_feed(network_config, request_path, output, *, timeout=30, repair_profile=None):
    return _upload_mailbox(network_config, request_path, output, timeout=timeout, repair_profile=repair_profile, source_state='feed')


def _upload_mailbox(network_config, request_path, output, *, timeout, repair_profile, source_state):
    """Upload an already allocated and independently consented exact transcript."""
    feed = source_state == 'feed'
    names = ('node', 'manifest', 'custody', 'allocation', 'offer', 'assignment', 'reservation', 'owner_disclosure', 'source_disclosure')
    if feed: names += ('sender_reservation', 'sender_disclosure')
    request, output, limits = _request(request_path, output, FEED_UPLOAD_SCHEMA if feed else UPLOAD_SCHEMA,
        set(names) | {'root_key', 'owner', 'source', 'source_storage_epoch', 'target', 'target_storage_epoch', 'originals', 'current_statuses'}
            | ({'slot_key', 'sender'} if feed else set()), repair_profile or 'unbound')
    if feed: history._slot(request['slot_key'], request['root_key'])
    if type(request['originals']) is not list or not 1 <= len(request['originals']) <= 64: raise wire.RepairWireError('repair_invalid_request_bundle')
    if type(request['current_statuses']) is not list or not 1 <= len(request['current_statuses']) <= 16: raise wire.RepairWireError('repair_invalid_status')
    entries = {name: _entry(request[name]) for name in names}
    base = _base(entries['node'])
    resolver = wire.LocalRawResolver(DEFAULT_POLICY, wire.RepairBudget(DEFAULT_POLICY))
    for value in request['originals']:
        entry = _entry(value); ref = wire.raw_ref(entry['ref'])
        if resolver.put(ref.namespace, ref.key, entry['raw']).ref != ref: raise wire.RepairWireError('repair_ref_mismatch')
    with OpenNetworkClient(_absolute_path(network_config)) as network, network.participant.state.db() as db:
        journal = (MailboxFeedCopyPreparation if feed else MailboxRootCopyPreparation)(db, network.identity, network.encryption, policy=DEFAULT_POLICY)
        client = (MailboxFeedCopyUploadClient if feed else MailboxRootCopyUploadClient)(journal, encryption_identity=network.encryption,
            transport=network.participant.transport, allow_loopback=network.participant.transport.allow_loopback)
        try:
            originals = (entries['manifest'], resolver, entries['custody'], entries['allocation'], entries['offer'], entries['assignment'], entries['reservation'])
            if feed: originals += (entries['sender_reservation'],)
            originals += (entries['owner_disclosure'], entries['source_disclosure'])
            if feed: originals += (entries['sender_disclosure'],)
            selection = dict(expected_slot=request['slot_key'], expected_sender=request['sender']) if feed else dict(expected_root=request['root_key'])
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


def _recover_mailbox(network_config, request_path, output, *, timeout, repair_profile, source_state):
    """Retain authenticated status floors, including when recovery is denied."""
    feed = source_state == 'feed'
    request, output, limits = _request(request_path, output, FEED_RECOVER_SCHEMA if feed else RECOVER_SCHEMA,
        {'root_key', 'target', 'source', 'source_storage_epoch', 'maintainer', 'node', 'known_statuses', 'archive_statuses'}
            | ({'slot_key', 'sender', 'slot_entries'} if feed else {'root', 'read', 'bootstrap'}), repair_profile or 'unbound')
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
        client = (MailboxFeedReplicaRecoveryClient if feed else MailboxRootReplicaRecoveryClient)(network.identity, network.encryption, limit_policy=limits,
            policy=replace(DEFAULT_POLICY, max_signature_checks=min(512, limits['max_signature_checks'])) if feed else DEFAULT_POLICY,
            transport=network.participant.transport, allow_loopback=network.participant.transport.allow_loopback,
            status_observer=journal.observe)
        try:
            selection = dict(expected_slot=request['slot_key'], expected_sender=request['sender'], slot_entries=slot_entries) if feed else dict(
                expected_root=request['root_key'], root_entry=entries['root'], read_entry=entries['read'], bootstrap_entry=entries['bootstrap'])
            result = client.recover(base, target_node_entry=entries['node'], expected_target=request['target'], **selection,
                expected_source=request['source'], source_storage_epoch=request['source_storage_epoch'], expected_maintainer=request['maintainer'],
                known_statuses=[_entry(e) for e in request['known_statuses']], archive_statuses=list(archived.values()), timeout=timeout)
            for item in result.archive_statuses: journal.observe(item)
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
