"""Prepare a private ACK-directory plan and sign it with separate participants.

Each command uses its operator's existing identity and protected transport
database. Source export, local consent and assembly perform no network request.
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
from memory_vault_open_node import OpenParticipant
from memory_vault_open_repair_admin import _entry, MAX_BUNDLE_BYTES
from memory_vault_open_repair_index_admin import _node_config
from memory_vault_open_repair_index_prepare import (
    AckIndexPlanPreparer, AckIndexConsentSigner, assemble_publication,
)
from memory_vault_open_repair_state import RepairAckState
from memory_vault_open_repair_wire import RepairWireError
from memory_vault_trust import Identity, TrustError, _absolute_path, _read_private, _write_new_private

EXPORT_SCHEMA = 'memory-vault-open-ack-index-export-request/v1'
EXPECTED_FIELDS = {'expected_ack_slot', 'expected_owner', 'expected_receipt_writer',
    'expected_message_id', 'expected_envelope_ref', 'expected_source', 'source_storage_epoch',
    'expected_directory', 'directory_storage_epoch'}


def _read(path):
    raw = _read_private(_absolute_path(Path(path)), MAX_BUNDLE_BYTES)
    if raw is None:
        raise RepairWireError('repair_request_missing')
    return document(raw, maximum=MAX_BUNDLE_BYTES)


def _new_output(path):
    path = _absolute_path(Path(path))
    if os.path.lexists(path):
        raise RepairWireError('repair_output_exists')
    return path


def _write(path, value, state):
    raw = canonical_bytes(value) + b'\n'
    if len(raw) > MAX_BUNDLE_BYTES:
        raise RepairWireError('repair_over_budget')
    _write_new_private(path, raw)
    return dict(state=state, output_path=str(path), output_sha256=hashlib.sha256(raw).hexdigest(),
        network_accessed=False, vault_modified=False)


def export_plan(node_config, request_path, output):
    output = _new_output(output)
    value = _read(request_path)
    request = object_fields(value, {'schema_version', 'resource_id', 'directory', 'directory_node',
        'allocation_id', 'job_id', 'budget_limits', 'windows'}
        | ({'current_statuses'} if 'current_statuses' in value else set()))
    if request['schema_version'] != EXPORT_SCHEMA:
        raise RepairWireError('repair_invalid_request_bundle')
    statuses = request.get('current_statuses')
    if statuses is not None and (type(statuses) is not list or not 1 <= len(statuses) <= 16):
        raise RepairWireError('repair_invalid_request_bundle')
    config = _node_config(node_config)
    identity = Identity.load(_absolute_path(Path(config['identity_path'])))
    encryption = EncryptionIdentity.load(_absolute_path(Path(config['encryption_key_path'])))
    with OpenParticipant(identity, _absolute_path(Path(config['state_directory'])),
            seeds=config['seeds'], descriptor=config['node'], encryption_identity=encryption,
            allow_loopback=config['allow_loopback'], index_policy=config['index_policy'],
            contact_policy=config.get('contact_policy'), delivery_policy=config.get('delivery_policy'),
            provider_policy=config.get('provider_policy'), repair_policy=config['repair_policy']) as participant:
        with participant.state.db() as db:
            state = RepairAckState(db, identity, participant.descriptor, encryption_identity=encryption,
                limit_policy=config['repair_policy'].get('limit_policy'),
                capacity_policy=config['repair_policy'].get('capacity_policy'))
            result = AckIndexPlanPreparer(state).export(request['resource_id'],
                expected_directory=request['directory'], directory_node_entry=_entry(request['directory_node']),
                allocation_id=request['allocation_id'], job_id=request['job_id'],
                budget_limits=request['budget_limits'], windows=request['windows'],
                current_statuses=None if statuses is None else [_entry(item) for item in statuses])
    return _write(output, result, 'publication_plan_prepared')


def sign_consent(network_config, bundle_path, expected_path, output, *, variant,
        known_statuses_path=None, renew_source_status=False):
    output = _new_output(output)
    bundle = _read(bundle_path)
    expected = object_fields(_read(expected_path), EXPECTED_FIELDS)
    known = ([] if known_statuses_path is None
        else object_fields(_read(known_statuses_path), {'known_statuses'})['known_statuses'])
    if type(known) is not list or len(known) > 32:
        raise RepairWireError('repair_invalid_request_bundle')
    with OpenNetworkClient(_absolute_path(Path(network_config))) as network:
        with network.participant.state.db() as db:
            signer = AckIndexConsentSigner(network.identity, network.encryption, db)
            result = signer.sign(bundle, variant=variant, expected=expected,
                known_statuses=[_entry(item) for item in known], renew_source_status=renew_source_status)
    return _write(output, result, 'publication_consent_signed')


def assemble_plan(bundle_path, owner_result_path, recipient_result_path, expected_path, output):
    output = _new_output(output)
    expected = object_fields(_read(expected_path), EXPECTED_FIELDS)
    result = assemble_publication(_read(bundle_path), _read(owner_result_path), _read(recipient_result_path),
        expected=expected)
    return _write(output, result, 'publication_request_prepared')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    export = commands.add_parser('export', help='source prepares one exact private publication plan')
    export.add_argument('--node-config', required=True, type=Path)
    export.add_argument('--request', required=True, type=Path)
    sign = commands.add_parser('sign', help='one participant signs only its own publication consent')
    sign.add_argument('--network-config', required=True, type=Path)
    sign.add_argument('--bundle', required=True, type=Path)
    sign.add_argument('--expected', required=True, type=Path, help='independently retained participant/message values')
    sign.add_argument('--variant', required=True, choices=('owner', 'receipt_writer'))
    sign.add_argument('--known-statuses', type=Path)
    sign.add_argument('--renew-source-status', action='store_true', help='explicitly renew only existing source scopes')
    assemble = commands.add_parser('assemble', help='validate both independent consents and prepare the publish request')
    assemble.add_argument('--bundle', required=True, type=Path)
    assemble.add_argument('--owner-consent', required=True, type=Path)
    assemble.add_argument('--recipient-consent', required=True, type=Path)
    assemble.add_argument('--expected', required=True, type=Path)
    for command in (export, sign, assemble):
        command.add_argument('--output', required=True, type=Path, help='new private file; never overwritten')
    args = parser.parse_args(argv)
    try:
        if args.command == 'export':
            result = export_plan(args.node_config, args.request, args.output)
        elif args.command == 'sign':
            result = sign_consent(args.network_config, args.bundle, args.expected, args.output,
                variant=args.variant, known_statuses_path=args.known_statuses,
                renew_source_status=args.renew_source_status)
        else:
            result = assemble_plan(args.bundle, args.owner_consent, args.recipient_consent, args.expected, args.output)
    except (MemoryError, TrustError, RepairWireError, OSError, sqlite3.Error) as exc:
        print(json.dumps(dict(error=getattr(exc, 'code', 'repair_storage_unavailable'))), file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
