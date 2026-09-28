"""Explicit one-directory publication using an existing ACK source identity.

The private request carries separately signed A/B publication consent. The
operator signs only as the source, uses its existing transport database, and
resumes the same durable publication on retry. No listener or Vault is opened.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys

from memory_vault import MemoryError, canonical_bytes
from memory_vault_network_crypto import EncryptionIdentity, document, object_fields
from memory_vault_open_client import OpenNetworkClient
from memory_vault_open_node import NODE_CONFIG, OpenParticipant
from memory_vault_open_repair_admin import _entry, _encoded, _retained_statuses, MAX_BUNDLE_BYTES
from memory_vault_open_repair_index_access import AckIndexSourceAccess
from memory_vault_open_repair_index_client import AckIndexPublicationClient
from memory_vault_open_repair_state import RepairAckState
from memory_vault_open_repair_wire import RepairWireError
from memory_vault_open_repair_wire import raw_ref
from memory_vault_trust import Identity, TrustError, _absolute_path, _read_private, _write_new_private

REQUEST_SCHEMA = 'memory-vault-open-ack-index-publication-request/v1'
EVIDENCE_SCHEMA = 'memory-vault-open-ack-index-publication-evidence/v1'
RECOVERY_REQUEST_SCHEMA = 'memory-vault-open-ack-index-recovery-request/v1'
RECOVERY_EVIDENCE_SCHEMA = 'memory-vault-open-ack-index-recovery-evidence/v1'


def _node_config(path):
    raw = _read_private(_absolute_path(path), 65536)
    if raw is None:
        raise MemoryError('open_invalid_node_config')
    parsed = document(raw, maximum=65536)
    optional = {'contact_policy', 'delivery_policy', 'provider_policy'}
    config = object_fields(parsed, {'schema_version', 'identity_path', 'state_directory',
        'node', 'seeds', 'allow_loopback', 'index_policy', 'listen_host', 'listen_port',
        'repair_policy', 'encryption_key_path'} | (optional & set(parsed)))
    if (config['schema_version'] != NODE_CONFIG or type(config['repair_policy']) is not dict
            or config['repair_policy'].get('enabled') is not True):
        raise MemoryError('open_repair_closed')
    return config


def _original(raw):
    digest = hashlib.sha256(raw).hexdigest()
    return dict(raw=raw, ref=dict(namespace='meta', key=digest, raw_sha256=digest, size=len(raw)))


def _directory_node(value):
    entry = _entry(value)
    ref = raw_ref(entry['ref'])
    if (ref.namespace != 'meta' or len(entry['raw']) != ref.size
            or hashlib.sha256(entry['raw']).hexdigest() != ref.raw_sha256):
        raise RepairWireError('repair_ref_mismatch')
    return document(entry['raw'], maximum=4096)


def publish_index(node_config: Path, request_path: Path, output: Path, *, timeout=60):
    """Publish explicitly; the result is advertised until A reads independently."""
    output = _absolute_path(output)
    if os.path.lexists(output):
        raise RepairWireError('repair_output_exists')
    raw = _read_private(_absolute_path(request_path), MAX_BUNDLE_BYTES)
    if raw is None:
        raise RepairWireError('repair_request_missing')
    value = document(raw, maximum=MAX_BUNDLE_BYTES)
    request = object_fields(value, {'schema_version', 'resource_id', 'directory', 'node',
        'fact', 'intent', 'owner_consent', 'recipient_consent', 'current_statuses'}
        | ({'allocation'} if 'allocation' in value else set()))
    if (request['schema_version'] != REQUEST_SCHEMA or type(request['current_statuses']) is not list
            or not 1 <= len(request['current_statuses']) <= 16):
        raise RepairWireError('repair_invalid_request_bundle')
    config = _node_config(node_config)
    identity = Identity.load(_absolute_path(Path(config['identity_path'])))
    encryption = EncryptionIdentity.load(_absolute_path(Path(config['encryption_key_path'])))
    directory_entry = _entry(request['node'])
    directory_node = _directory_node(request['node'])
    try:
        base_url = directory_node['payload']['base_url']
    except (KeyError, TypeError):
        raise RepairWireError('repair_invalid_request_bundle') from None
    with OpenParticipant(identity, _absolute_path(Path(config['state_directory'])),
            seeds=config['seeds'], descriptor=config['node'], encryption_identity=encryption,
            allow_loopback=config['allow_loopback'], index_policy=config['index_policy'],
            contact_policy=config.get('contact_policy'), delivery_policy=config.get('delivery_policy'),
            provider_policy=config.get('provider_policy'), repair_policy=config['repair_policy']) as participant:
        with participant.state.db() as db:
            state = RepairAckState(db, identity, participant.descriptor, encryption_identity=encryption,
                limit_policy=config['repair_policy'].get('limit_policy'),
                capacity_policy=config['repair_policy'].get('capacity_policy'))
            access = AckIndexSourceAccess(state)
            access.initialize()
            client = AckIndexPublicationClient(access, encryption_identity=encryption,
                transport=participant.transport, allow_loopback=config['allow_loopback'])
            result = client.publish(request['resource_id'], base_url,
                target_node_entry=directory_entry,
                provider_node_entry=_original(canonical_bytes(participant.descriptor)),
                expected_directory=request['directory'], provider_fact_entry=_entry(request['fact']),
                intent=request['intent'], owner_consent_entry=_entry(request['owner_consent']),
                recipient_consent_entry=_entry(request['recipient_consent']),
                current_statuses=[_entry(item) for item in request['current_statuses']],
                allocation_entry=_entry(request['allocation']) if 'allocation' in request else None,
                timeout=timeout)
    evidence = dict(schema_version=EVIDENCE_SCHEMA, state=result.state,
        resource_id=request['resource_id'], index_lease=result.index_lease,
        fact=result.fact, directory=result.directory, metrics=dict(result.metrics),
        independent_readback_verified=False)
    encoded = canonical_bytes(evidence) + b'\n'
    if len(encoded) > MAX_BUNDLE_BYTES:
        raise RepairWireError('repair_over_budget')
    _write_new_private(output, encoded)
    return dict(state=result.state, evidence_path=str(output),
        evidence_sha256=hashlib.sha256(encoded).hexdigest(),
        independent_readback_verified=False, metrics=dict(result.metrics))


def recover_index(network_config: Path, request_path: Path, output: Path, *, timeout=30):
    """A's independent directory discovery and exact occupied receipt read."""
    output = _absolute_path(output)
    if os.path.lexists(output):
        raise RepairWireError('repair_output_exists')
    raw = _read_private(_absolute_path(request_path), MAX_BUNDLE_BYTES)
    if raw is None:
        raise RepairWireError('repair_request_missing')
    value = document(raw, maximum=MAX_BUNDLE_BYTES)
    request = object_fields(value, {'schema_version', 'directory', 'directory_node', 'target',
        'source_epoch', 'ack_slot', 'root', 'read', 'bootstrap', 'receipt_writer',
        'message_id', 'envelope_ref', 'known_statuses'}
        | ({'archive_statuses'} if 'archive_statuses' in value else set()))
    known, archived = request['known_statuses'], request.get('archive_statuses', [])
    if (request['schema_version'] != RECOVERY_REQUEST_SCHEMA or type(known) is not list
            or len(known)>16 or type(archived) is not list or len(archived)>32):
        raise RepairWireError('repair_invalid_request_bundle')
    with OpenNetworkClient(_absolute_path(network_config)) as network:
        result = network.recover_indexed_ack(
            expected_directory_node=_directory_node(request['directory_node']),
            expected_directory=request['directory'], expected_target=request['target'],
            expected_source_epoch=request['source_epoch'], expected_ack_slot=request['ack_slot'],
            root_entry=_entry(request['root']), read_entry=_entry(request['read']),
            bootstrap_entry=_entry(request['bootstrap']), expected_receipt_writer=request['receipt_writer'],
            expected_message_id=request['message_id'], expected_envelope_ref=request['envelope_ref'],
            known_statuses=[_entry(item) for item in known], archive_statuses=[_entry(item) for item in archived],
            timeout=timeout)
    recovered = result.recovery
    historical = []
    source = recovered.source
    while source is not None:
        historical.extend(source.statuses)
        source = getattr(source, 'predecessor', None)
    retained, archive = _retained_statuses([*archived, *known,
        *[_encoded(item.raw, item.ref) for item in historical],
        *[_encoded(item.raw, item.ref) for item in recovered.current_statuses]])
    receipt = recovered.source.inputs['receipt']
    evidence = dict(schema_version=RECOVERY_EVIDENCE_SCHEMA, state=result.state,
        ack_slot=request['ack_slot'], target=request['target'], receipt_writer=request['receipt_writer'],
        message_id=request['message_id'], envelope_ref=request['envelope_ref'],
        recipient_receipt=_encoded(receipt.raw, receipt.ref),
        source_commit=_encoded(recovered.source.commit.raw, recovered.source.commit.ref),
        index_lease=result.index_lease, fact=result.fact, directory=result.directory, source_node=result.source_node,
        originals=[_encoded(body, ref) for ref, body in sorted(recovered.originals.items(),
            key=lambda item:(item[0].namespace,item[0].key,item[0].raw_sha256,item[0].size))],
        known_statuses=retained, archive_statuses=archive, metrics=dict(result.metrics),
        independent_readback_verified=True, vault_modified=False)
    encoded = canonical_bytes(evidence)+b'\n'
    if len(encoded)>MAX_BUNDLE_BYTES:
        raise RepairWireError('repair_over_budget')
    _write_new_private(output, encoded)
    return dict(state=result.state, evidence_path=str(output), evidence_sha256=hashlib.sha256(encoded).hexdigest(),
        independent_readback_verified=True, vault_modified=False, metrics=dict(result.metrics))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    publication = commands.add_parser('publish', help='source publishes to one independently authorized directory')
    publication.add_argument('--node-config', required=True, type=Path)
    recovery = commands.add_parser('recover', help='owner discovers the source and reads the original receipt')
    recovery.add_argument('--network-config', required=True, type=Path)
    for command, seconds in ((publication,60), (recovery,30)):
        command.add_argument('--request', required=True, type=Path, help='private original authority bundle')
        command.add_argument('--output', required=True, type=Path, help='new private result file; never overwritten')
        command.add_argument('--timeout', type=float, default=seconds)
    args = parser.parse_args(argv)
    try:
        if args.command == 'publish':
            result = publish_index(args.node_config, args.request, args.output, timeout=args.timeout)
        else:
            result = recover_index(args.network_config, args.request, args.output, timeout=args.timeout)
    except (MemoryError, TrustError, RepairWireError, OSError, sqlite3.Error) as exc:
        print(json.dumps(dict(error=getattr(exc, 'code', 'repair_storage_unavailable'))), file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
