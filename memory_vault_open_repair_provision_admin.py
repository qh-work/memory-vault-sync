"""Prepare one ACK source before sending, using existing local A/R identities.

The prepare command retains explicitly selected content, establishes unbound ACK
custody, then encrypts the delivery and binds its slot. No delivery upload occurs.
The private result contains A's
recovery request and B's saved-receipt publication request, never B's secret key.
"""
import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys

from memory_vault import MemoryError, canonical_bytes
from memory_vault_network_crypto import EncryptionIdentity
from memory_vault_open_client import OpenNetworkClient
from memory_vault_open_node import OpenParticipant
from memory_vault_open_repair_admin import MAX_BUNDLE_BYTES
from memory_vault_open_repair_index_admin import _node_config
from memory_vault_open_repair_provision import AckSourceProvisioner, PROFILES
from memory_vault_open_repair_state import RepairAckState
from memory_vault_open_repair_wire import RepairWireError
from memory_vault_trust import Identity, TrustError, _absolute_path, _write_new_private


def prepare_source(network_config, node_config, output, *, request_id, recipient=None,
        text='', memory_ids=None, profile='receipt', lifetime=3600):
    """Create a new private result; omission of recipient resumes a frozen item."""
    output=_absolute_path(Path(output))
    if os.path.lexists(output):
        raise RepairWireError('repair_output_exists')
    if recipient is None and (text or memory_ids):
        raise RepairWireError('repair_invalid_request_bundle')
    config=_node_config(_absolute_path(Path(node_config)))
    identity=Identity.load(_absolute_path(Path(config['identity_path'])))
    encryption=EncryptionIdentity.load(_absolute_path(Path(config['encryption_key_path'])))
    with OpenNetworkClient(_absolute_path(Path(network_config))) as network:
        with OpenParticipant(identity,_absolute_path(Path(config['state_directory'])),
                seeds=config['seeds'],descriptor=config['node'],encryption_identity=encryption,
                allow_loopback=config['allow_loopback'],index_policy=config['index_policy'],
                contact_policy=config.get('contact_policy'),delivery_policy=config.get('delivery_policy'),
                provider_policy=config.get('provider_policy'),repair_policy=config['repair_policy']) as source:
            with source.state.db() as db:
                state=RepairAckState(db,identity,source.descriptor,encryption_identity=encryption,
                    limit_policy=config['repair_policy'].get('limit_policy'),
                    capacity_policy=config['repair_policy'].get('capacity_policy'))
                provision=AckSourceProvisioner(network._delivery(),state)
                if recipient is None:
                    result=asyncio.run(provision.prepare_existing(request_id,profile=profile,lifetime=lifetime))
                else:
                    result=asyncio.run(provision.queue_and_prepare(request_id,recipient,text=text,
                        memory_ids=memory_ids,profile=profile,lifetime=lifetime))
    raw=canonical_bytes(result)+b'\n'
    if len(raw)>MAX_BUNDLE_BYTES:
        raise RepairWireError('repair_over_budget')
    _write_new_private(output,raw)
    return dict(state='empty',resource_id=result['resource_id'],message_id=result['message_id'],
        output_path=str(output),output_sha256=hashlib.sha256(raw).hexdigest(),delivery_uploaded=False)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    commands=parser.add_subparsers(dest='command',required=True)
    prepare=commands.add_parser('prepare',help='establish the ACK source, then encrypt and bind selected content')
    prepare.add_argument('--recipient',required=True)
    prepare.add_argument('--text',default='')
    prepare.add_argument('--memory-id',action='append',default=[])
    resume=commands.add_parser('resume',help='resume an unfinished prepared outbox item before upload')
    for command in (prepare,resume):
        command.add_argument('--network-config',required=True,type=Path)
        command.add_argument('--node-config',required=True,type=Path)
        command.add_argument('--request-id',required=True)
        command.add_argument('--profile',choices=tuple(PROFILES),default='receipt')
        command.add_argument('--lifetime',type=int,default=3600)
        command.add_argument('--output',required=True,type=Path,help='new protected file; never overwritten')
    args=parser.parse_args(argv)
    try:
        result=prepare_source(args.network_config,args.node_config,args.output,request_id=args.request_id,
            recipient=getattr(args,'recipient',None),text=getattr(args,'text',''),
            memory_ids=getattr(args,'memory_id',None),profile=args.profile,lifetime=args.lifetime)
    except (MemoryError,TrustError,RepairWireError,OSError,sqlite3.Error) as exc:
        print(json.dumps(dict(error=getattr(exc,'code','repair_storage_unavailable'))),file=sys.stderr)
        return 2
    print(json.dumps(result,sort_keys=True))
    return 0


if __name__=='__main__':
    raise SystemExit(main())
