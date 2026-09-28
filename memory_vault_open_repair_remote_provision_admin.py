"""Prepare an independent receipt source using only the sender's own config."""
import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys

from memory_vault import MemoryError, canonical_bytes
from memory_vault_open_client import OpenNetworkClient
from memory_vault_open_repair_admin import MAX_BUNDLE_BYTES
from memory_vault_open_repair_provision import PROFILES
from memory_vault_open_repair_remote_provision import RemoteAckSourceProvisioner
from memory_vault_open_repair_wire import RepairWireError
from memory_vault_trust import TrustError, _absolute_path, _write_new_private


def prepare_remote_source(network_config, output, *, source_url, source_key_id, request_id,
                          recipient=None, text='', memory_ids=None, profile='receipt', lifetime=3600):
    output = _absolute_path(Path(output))
    if os.path.lexists(output):
        raise RepairWireError('repair_output_exists')
    if recipient is None and (text or memory_ids):
        raise RepairWireError('repair_invalid_request_bundle')
    with OpenNetworkClient(_absolute_path(Path(network_config))) as network:
        provision = RemoteAckSourceProvisioner(network._delivery())
        options = dict(source_url=source_url, source_key_id=source_key_id, profile=profile, lifetime=lifetime)
        if recipient is None:
            result = asyncio.run(provision.prepare_existing(request_id, **options))
        else:
            result = asyncio.run(provision.queue_and_prepare(request_id, recipient,
                                text=text, memory_ids=memory_ids, **options))
    raw = canonical_bytes(result) + b'\n'
    if len(raw) > MAX_BUNDLE_BYTES:
        raise RepairWireError('repair_over_budget')
    _write_new_private(output, raw)
    return dict(state='empty', resource_id=result['resource_id'], message_id=result['message_id'],
                output_path=str(output), output_sha256=hashlib.sha256(raw).hexdigest(), delivery_uploaded=False)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    prepare = commands.add_parser('prepare', help='prepare the selected independent source before sending')
    prepare.add_argument('--recipient', required=True)
    prepare.add_argument('--text', default='')
    prepare.add_argument('--memory-id', action='append', default=[])
    commands.add_parser('resume', help='resume the exact saved source preparation without a new message')
    for command in commands.choices.values():
        command.add_argument('--network-config', required=True, type=Path)
        command.add_argument('--source-url', required=True)
        command.add_argument('--source-key-id', required=True)
        command.add_argument('--request-id', required=True)
        command.add_argument('--profile', choices=tuple(PROFILES), default='receipt')
        command.add_argument('--lifetime', type=int, default=3600)
        command.add_argument('--output', required=True, type=Path, help='new protected output; never overwritten')
    args = parser.parse_args(argv)
    try:
        result = prepare_remote_source(args.network_config, args.output,
            source_url=args.source_url, source_key_id=args.source_key_id, request_id=args.request_id,
            recipient=getattr(args, 'recipient', None), text=getattr(args, 'text', ''),
            memory_ids=getattr(args, 'memory_id', None), profile=args.profile, lifetime=args.lifetime)
    except (MemoryError, TrustError, RepairWireError, OSError, sqlite3.Error) as exc:
        print(json.dumps(dict(error=getattr(exc, 'code', 'repair_storage_unavailable'))), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
