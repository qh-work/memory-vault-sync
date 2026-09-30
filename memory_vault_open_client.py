"""Explicit open profile for the same six-operation Agent facade.

Contact discovery and explicitly approved encrypted delivery share the existing
open participant. Remember/recall stay in the existing Vault; no private network
authority or encryption downgrade is selected by a failed open operation.
"""
from __future__ import annotations

import asyncio
import hashlib
import time
from pathlib import Path

from memory_vault import MemoryError, canonical_bytes
from memory_vault_client import ClientConfig
from memory_vault_network import _read_private
from memory_vault_network_crypto import EncryptionIdentity, document, object_fields
from memory_vault_open_node import OpenParticipant
from memory_vault_trust import Identity

CONFIG_SCHEMA = "memory-vault-open-client-config/v1"
MAILBOX_CONNECT_SCHEMA = "memory-vault-open-mailbox-connect/v1"
ACK_CONNECT_SCHEMA = "memory-vault-open-ack-connect/v1"


class OpenNetworkClient:
    supports_targeted_discovery = True

    def __init__(self, config_path: Path, *, transport=None):
        if transport is not None:
            raise MemoryError("open_transport_override_unsupported")
        raw = _read_private(Path(config_path), 65536)
        if raw is None:
            raise MemoryError("network_not_configured")
        config = object_fields(document(raw, maximum=65536),
                               {"schema_version", "client_config_path", "state_directory", "encryption_key_path", "seeds", "allow_loopback"})
        if config["schema_version"] != CONFIG_SCHEMA:
            raise MemoryError("open_invalid_client_config")
        self.client_config = ClientConfig.load(Path(config["client_config_path"]))
        if self.client_config.identity_path is None:
            raise MemoryError("network_signing_identity_required")
        self.identity = Identity.load(self.client_config.identity_path)
        # Bind the same encryption identity; merely loading it does not claim a
        # remote live X25519 possession challenge or authorize memory sharing.
        self.encryption = EncryptionIdentity.load(Path(config["encryption_key_path"]))
        directory = Path(config["state_directory"])
        if not directory.is_absolute() or directory == self.client_config.vault_path.parent:
            raise MemoryError("network_separate_state_required")
        self.participant = OpenParticipant(self.identity, directory, seeds=config["seeds"],
                                           allow_loopback=config["allow_loopback"])

    def __enter__(self):
        return self

    def close(self):
        self.participant.close()

    def __exit__(self, *exc):
        self.close()

    def connect(self, *, invitation=None, request_id=None):
        if isinstance(invitation, dict) and invitation.get('schema_version') == ACK_CONNECT_SCHEMA:
            return self._ack_connect(invitation)
        if isinstance(invitation, dict) and invitation.get('schema_version') == MAILBOX_CONNECT_SCHEMA:
            return self._mailbox_connect(invitation)
        if invitation is not None:
            from memory_vault_open_contact_client import OpenContactClient, CONNECT_SCHEMA
            if not isinstance(invitation, dict) or invitation.get("schema_version") != CONNECT_SCHEMA:
                raise MemoryError("open_private_invitation_unsupported")
            result = asyncio.run(OpenContactClient(self.participant, self.encryption).dispatch(invitation, request_id))
            return {**result, "profile": "open-routing-v1", "network_accessed": True,
                    "open_messaging_supported": True}
        result = asyncio.run(self.participant.join())
        return {**result, "profile": "open-routing-v1", "network_accessed": True,
                "open_messaging_supported": True}

    def discover(self, *, online=True, key_id=None):
        if online is not True:
            if key_id is not None:
                raise MemoryError("invalid_client_arguments")
            return {"profile": "open-routing-v1", "state": "local", "network_accessed": False,
                    "discovery_grants_access": False}
        if key_id is None:
            return {"profile": "open-routing-v1", "state": "target_key_required",
                    "global_member_list": False, "network_accessed": False,
                    "discovery_grants_access": False}
        result = asyncio.run(self.participant.find_contact(key_id))
        # Full causality traces are available from the runtime/acceptance tools.
        # The common Agent response has its original bounded 8 KiB output.
        result.pop("route", None)
        return {**result, "profile": "open-routing-v1", "network_accessed": True}

    def send(self, **arguments):
        from memory_vault_open_mailbox_receipt_jobs import recover_prepared
        delivery=self._delivery();deadline=time.monotonic()+60
        from memory_vault_open_ack_replica_send import recover as recover_replica
        recovered=recover_replica(self,delivery,arguments,deadline=deadline)
        if recovered is None:
            recovered=recover_prepared(self,delivery,arguments,deadline=min(deadline,time.monotonic()+20))
        result=asyncio.run(delivery.send(**arguments,_deadline=deadline))
        result['network_accessed'] |= recovered['network_accessed']
        if recovered.get('state') is not None:result['ack_recovery']=recovered['state']
        if recovered.get('error') is not None:result['ack_recovery_error']=recovered['error']
        for name in ('replica_id','commit_ref','replica_custody_ref'):
            if name in recovered:result['ack_'+name]=recovered[name]
        return result

    def receive(self, limit=4):
        from memory_vault_open_repair_wire import RepairWireError
        delivery=self._delivery();deadline=time.monotonic()+60
        result=asyncio.run(delivery.receive(limit=limit,_pending_only=True,_deadline=deadline))
        from memory_vault_open_mailbox_receipt_jobs import poll as poll_receipt_returns
        receipt_attempts=set()
        poll_receipt_returns(self,result,deadline=min(deadline,time.monotonic()+30),attempted=receipt_attempts)
        from memory_vault_open_mailbox_replica_receive import rows as receiver_rows, receive as receive_replica
        rows=receiver_rows(self)
        for row in rows:
            remaining=deadline-time.monotonic()
            if len(result['messages'])>=limit or remaining<=0:break
            table='open_mailbox_replica_receivers' if row['receiver_kind']=='replica' else 'open_mailbox_receivers'
            with self.participant.state.db() as db:
                db.execute('UPDATE '+table+' SET last_attempt=? WHERE receiver_id=?',(time.time_ns(),row['receiver_id']))
            try:
                def accessed():result['network_accessed']=True
                if row['receiver_kind']=='replica':
                    received=receive_replica(self,row,deadline=deadline,accessed=accessed)
                else:
                    config=document(bytes(row['body']),maximum=65536)
                    options=self._mailbox_receiver_options(config)
                    received=self.receive_mailbox(config['base_url'],limit_policy=config['limit_policy'],
                        limit=limit-len(result['messages']),timeout=min(60,remaining),_network_observer=accessed,**options)
                result['messages'].extend(received['messages'])
                result['errors'].extend(received['errors'])
            except (MemoryError,RepairWireError) as error:
                result['errors'].append(dict(receiver_id=row['receiver_id'],code=error.code,retryable=getattr(error,'retryable',False)))
        if len(result['messages'])<limit and time.monotonic()<deadline:
            legacy=asyncio.run(delivery.receive(limit=limit-len(result['messages']),_skip_pending=True,_deadline=deadline))
            result['messages'].extend(legacy['messages']);result['errors'].extend(legacy['errors'])
            result['network_accessed']|=legacy['network_accessed']
        poll_receipt_returns(self,result,deadline=min(deadline,time.monotonic()+30),attempted=receipt_attempts)
        result['errors']=result['errors'][:4]
        return result

    def _mailbox_receivers_initialize(self):
        # Bind to the existing protected identity/config before retaining grants.
        self._delivery()
        with self.participant.state.db() as db:
            db.execute('CREATE TABLE IF NOT EXISTS open_mailbox_receivers(receiver_id TEXT PRIMARY KEY,body BLOB NOT NULL,last_attempt INTEGER NOT NULL DEFAULT 0)')

    def _mailbox_receiver_options(self, config):
        options={name:config[name] for name in ('expected_target','expected_sender','expected_slot')}
        def decode(entry):
            object_fields(entry,{'raw','ref'})
            if not isinstance(entry['raw'],str):raise MemoryError('open_invalid_mailbox_receiver')
            return dict(raw=entry['raw'].encode('utf-8'),ref=entry['ref'])
        options['target_node_entry']=decode(config['target_node_entry'])
        object_fields(config['slot_entries'],{'slot','read','maintenance','bootstrap'})
        options['slot_entries']={name:decode(entry) for name,entry in config['slot_entries'].items()}
        return options

    def _mailbox_saved_receiver(self, receiver_id):
        from memory_vault_network_crypto import opaque
        opaque(receiver_id)
        with self.participant.state.db() as db:
            row=db.execute('SELECT body FROM open_mailbox_receivers WHERE receiver_id=?',(receiver_id,)).fetchone()
        if row is None:raise MemoryError('open_mailbox_receiver_missing')
        config=document(bytes(row['body']),maximum=65536)
        if (config.get('schema_version')!=MAILBOX_CONNECT_SCHEMA or config.get('action')!='register'
                or 'mailbox_'+hashlib.sha256(canonical_bytes(config.get('expected_slot'))).hexdigest()!=receiver_id):
            raise MemoryError('open_invalid_mailbox_receiver')
        # Recheck the original signatures, identity binding and finite
        # grant windows before exposing reusable configuration. This is
        # local verification, not an observation of the remote source.
        registered=self._mailbox_connect(config)
        if registered['receiver_id']!=receiver_id:raise MemoryError('open_invalid_mailbox_receiver')
        return config

    @staticmethod
    def _mailbox_page(raw, receiver_id, cursor, kind):
        import base64
        digest=hashlib.sha256(raw).hexdigest();offset=0
        if cursor is not None:
            object_fields(cursor,{'sha256','offset'})
            offset=cursor['offset']
            if (cursor['sha256']!=digest or type(offset) is not int or not 0<offset<len(raw) or offset%3072):
                raise MemoryError('open_invalid_mailbox_cursor')
        end=min(offset+3072,len(raw))
        return dict(state='mailbox_'+kind,receiver_id=receiver_id,**{kind+'_sha256':digest},
            total_bytes=len(raw),offset=offset,**{kind+'_chunk':base64.b64encode(raw[offset:end]).decode('ascii')},
            next_cursor=None if end==len(raw) else dict(sha256=digest,offset=end),
            network_accessed=False,source_rechecked=False,receipt_return='separate_authority_required')

    def _mailbox_connect(self, invitation):
        from dataclasses import replace
        from memory_vault_open_transport import endpoint
        from memory_vault_open_repair_state import DEFAULT_POLICY
        from memory_vault_open_repair_mailbox_activation import verify_mailbox_feed_bootstrap
        from memory_vault_open_repair_wire import RepairBudget,RepairWireError,build_new_wire,raw_ref
        from memory_vault_open_repair_original import verify_original_control,_node_shape
        from memory_vault_open_repair_resource import _dual_key
        value=document(invitation,maximum=65536)
        action=value.get('action')
        if action in ('register_replica','list_replicas','inspect_replica','remove_replica'):
            from memory_vault_open_mailbox_replica_receive import connect as replica_connect
            try:return replica_connect(self,value)
            except RepairWireError as error:raise MemoryError(error.code) from error
            except (KeyError,TypeError) as error:raise MemoryError('open_invalid_mailbox_receiver') from error
        if action=='receive_replica':
            return self._mailbox_receive_replica(value)
        if action=='provision':
            object_fields(value,{'schema_version','action','base_url','target_node_entry','plan','sender','setup_until','read_until','retain_until'})
            from memory_vault_open_repair_client import MailboxSetupClient,MailboxSetupJournal,MailboxSetupBuilder
            from memory_vault_open_repair_bind import decode_entry
            object_fields(value['target_node_entry'],{'raw','ref'})
            if not isinstance(value['target_node_entry']['raw'],str):raise MemoryError('open_invalid_mailbox_request')
            policy=replace(DEFAULT_POLICY,max_signature_checks=512);budget=RepairBudget(policy)
            try:
                builder=MailboxSetupBuilder(self.identity,self.encryption,value['plan'],policy=policy)
                sender=build_new_wire(value['sender'],policy,budget).value
                if _dual_key(sender,budget)!=builder.plan['sender']:raise MemoryError('open_invalid_mailbox_receiver')
                owner=dict(signing_key=self.identity.public_descriptor(),encryption_key=self.encryption.public_descriptor())
                key=hashlib.sha256(build_new_wire(dict(owner=owner,root_key=builder.plan['root_key']),policy,budget).raw).hexdigest()
                binding=hashlib.sha256(canonical_bytes(value)).hexdigest()
                with self.participant.state.db() as db:
                    exists=db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='open_mailbox_setup_completions'").fetchone()
                    cached=None if exists is None else db.execute('SELECT binding,config,result FROM open_mailbox_setup_completions WHERE setup_id=?',(key,)).fetchone()
                if cached is not None:
                    if cached['binding']!=binding:raise MemoryError('repair_setup_journal_conflict')
                    self._mailbox_connect(document(bytes(cached['config']),maximum=65536))
                    return dict(document(bytes(cached['result']),maximum=8192),state='mailbox_configured',network_accessed=False,source_rechecked=False)
                client=MailboxSetupClient(self.identity,self.encryption,policy=policy,limit_policy=builder.plan['limits'],
                    allow_loopback=self.participant.transport.allow_loopback,transport=self.participant.transport)
                with self.participant.state.db() as db:
                    journal=MailboxSetupJournal(db)
                    result=client.provision(value['base_url'],target_node_entry=dict(raw=value['target_node_entry']['raw'].encode('utf-8'),ref=value['target_node_entry']['ref']),
                        plan=value['plan'],journal=journal,setup_until=value['setup_until'],read_until=value['read_until'],retain_until=value['retain_until'])
                    request=build_new_wire(document(journal.step(key,'slot')[0],maximum=65536),policy,RepairBudget(policy)).value
                    entries={name:decode_entry(request['payload']['entries'][name],policy,RepairBudget(policy)) for name in ('slot','read','maintenance','bootstrap')}
                config=dict(schema_version=MAILBOX_CONNECT_SCHEMA,action='register',base_url=value['base_url'],
                    limit_policy=value['plan']['limits'],expected_slot=value['plan']['slot_key'],expected_sender=value['sender'],expected_target=value['plan']['target'],
                    target_node_entry=value['target_node_entry'],slot_entries={name:dict(raw=item['raw'].decode('utf-8'),ref=item['ref']) for name,item in entries.items()})
                registered=self._mailbox_connect(config)
                ready=dict(state='mailbox_ready',setup_id=key,receiver_id=registered['receiver_id'],network_accessed=True,source_rechecked=True,
                    custody_ref=result.source['custody'].ref.as_dict(),receipt_return='separate_authority_required')
                with self.participant.state.db() as db:
                    db.execute('BEGIN IMMEDIATE')
                    db.execute('CREATE TABLE IF NOT EXISTS open_mailbox_setup_completions(setup_id TEXT PRIMARY KEY,binding TEXT NOT NULL,config BLOB NOT NULL,result BLOB NOT NULL)')
                    prior=db.execute('SELECT binding FROM open_mailbox_setup_completions WHERE setup_id=?',(key,)).fetchone()
                    if prior is not None and prior['binding']!=binding:raise MemoryError('repair_setup_journal_conflict')
                    db.execute('INSERT OR IGNORE INTO open_mailbox_setup_completions VALUES(?,?,?,?)',(key,binding,canonical_bytes(config),canonical_bytes(ready)))
            except RepairWireError as error:raise MemoryError(error.code) from error
            return ready
        if action=='retain':
            object_fields(value,{'schema_version','action','message_id','authorization','attempt_until','consent_until','expires_at','object_until','enum_until'}|({'ack_request_id'} if 'ack_request_id' in value else set()))
            authorization=object_fields(value['authorization'],{'destination_entry','owner_status_entry','slot_entries','target','target_node_entry','base_url'})
            # The same durable stages back both the individual operations and
            # this combined call. A failed remote admission leaves the exact
            # local preparation available to the next identical retry.
            self._mailbox_connect(dict(schema_version=MAILBOX_CONNECT_SCHEMA,action='prepare',message_id=value['message_id'],
                slot_entries=authorization['slot_entries'],destination_entry=authorization['destination_entry'],
                attempt_until=value['attempt_until'],consent_until=value['consent_until'],
                **({'ack_request_id':value['ack_request_id']} if 'ack_request_id' in value else {})))
            return self._mailbox_connect(dict(schema_version=MAILBOX_CONNECT_SCHEMA,action='admit',message_id=value['message_id'],
                **{name:authorization[name] for name in ('base_url','target','target_node_entry','owner_status_entry')},
                **{name:value[name] for name in ('expires_at','object_until','enum_until')}))
        if action=='prepare':
            object_fields(value,{'schema_version','action','message_id','slot_entries','destination_entry','attempt_until','consent_until'}|({'ack_request_id'} if 'ack_request_id' in value else set()))
            from memory_vault_open_repair_client import MailboxMessageDraftStore
            def entry(item):
                object_fields(item,{'raw','ref'})
                if not isinstance(item['raw'],str):raise MemoryError('open_invalid_mailbox_request')
                return dict(raw=item['raw'].encode('utf-8'),ref=item['ref'])
            delivery=self._delivery()
            object_fields(value['slot_entries'],{'slot','read','maintenance'})
            configuration=self._mailbox_ack_configuration(value['ack_request_id'],value['message_id']) if 'ack_request_id' in value else None
            try:
                with self.participant.state.db() as db:
                    row=db.execute('SELECT envelope,session FROM open_delivery_outbox WHERE message_id=?',(value['message_id'],)).fetchone()
                    if row is None or row['envelope'] is None or row['session'] is None:raise MemoryError('open_delivery_outbox_missing')
                    session=document(bytes(row['session']),maximum=65536);keys=delivery._keys(session)
                    recipient=dict(signing_key=keys['recipient_signing_key'],encryption_key=keys['recipient_encryption_key'])
                    docs={name:session[name] for name in ('node','policy','request','decision')}
                    grant=session['decision']['payload']['grant']
                    docs.update(knock_lease=session['lease'],grant=grant,delivery_lease=grant['payload']['resource_lease'])
                    result=MailboxMessageDraftStore(db,self.identity,self.encryption).prepare(bytes(row['envelope']),recipient=recipient,
                        slot_entries={name:entry(item) for name,item in value['slot_entries'].items()},destination_entry=entry(value['destination_entry']),
                        contact_originals={name:canonical_bytes(item) for name,item in docs.items()},at=int(time.time()),
                        attempt_until=value['attempt_until'],consent_until=value['consent_until'],ack_configuration=configuration)
            except RepairWireError as error:raise MemoryError(error.code) from error
            return dict(state='mailbox_draft_saved',message_id=value['message_id'],attempt_ref=result['attempt']['ref'],
                disclosure_ref=result['disclosure']['ref'],network_accessed=False)
        if action=='admit':
            object_fields(value,{'schema_version','action','base_url','message_id','target','target_node_entry','owner_status_entry','expires_at','object_until','enum_until'})
            from memory_vault_open_repair_client import MailboxMessageDraftStore
            def entry(item):
                object_fields(item,{'raw','ref'})
                if not isinstance(item['raw'],str):raise MemoryError('open_invalid_mailbox_request')
                return dict(raw=item['raw'].encode('utf-8'),ref=item['ref'])
            try:
                with self.participant.state.db() as db:
                    result=MailboxMessageDraftStore(db,self.identity,self.encryption).admit(value['base_url'],value['message_id'],
                        target_node_entry=entry(value['target_node_entry']),target=value['target'],owner_status_entry=entry(value['owner_status_entry']),
                        at=int(time.time()),expires_at=value['expires_at'],object_until=value['object_until'],enum_until=value['enum_until'],
                        transport=self.participant.transport,allow_loopback=self.participant.transport.allow_loopback)
            except RepairWireError as error:raise MemoryError(error.code) from error
            return dict(state='retained_at_mailbox',message_id=result['message_id'],stored_at=result['stored_at'],network_accessed=True,
                custody_ref=result['originals']['custody']['ref'],feed_custody_ref=result['originals']['feed_custody']['ref'],recipient_acknowledged=False)
        self._mailbox_receivers_initialize()
        if action=='list':
            object_fields(value,{'schema_version','action'})
            with self.participant.state.db() as db:
                ids=[v[0] for v in db.execute('SELECT receiver_id FROM open_mailbox_receivers ORDER BY receiver_id')]
            return dict(state='configured',mailboxes=ids,network_accessed=False)
        if action=='authorize':
            object_fields(value,{'schema_version','action','receiver_id','contact_request_ref','expires_at','status_revision','status_until'}|({'cursor'} if 'cursor' in value else set()))
            from memory_vault_open_contact_client import OpenContactClient
            from memory_vault_open_repair_client import MailboxDestinationStore
            config=self._mailbox_saved_receiver(value['receiver_id'])
            options=self._mailbox_receiver_options(config)
            contact=OpenContactClient(self.participant,self.encryption)
            incoming=contact._load('incoming',value['contact_request_ref'])
            decision=contact._load('decision',value['contact_request_ref'])['decision']
            if decision['payload']['decision']!='approved':raise MemoryError('open_delivery_not_authorized')
            grant=decision['payload']['grant']
            docs={name:incoming[name] for name in ('node','policy','request')}
            docs.update(decision=decision,knock_lease=incoming['lease'],grant=grant,delivery_lease=grant['payload']['resource_lease'])
            slot=document(options['slot_entries']['slot']['raw'],maximum=65536)['payload']
            plan=dict(root_key=slot['slot_key']['root_key'],slot_key=slot['slot_key'],sender=slot['sender'],
                target=config['expected_target'],limits=config['limit_policy'],
                **{name:slot[name] for name in ('budget','windows','max_appends','max_live_items')})
            try:
                with self.participant.state.db() as db:
                    bundle=MailboxDestinationStore(db,self.identity,self.encryption).prepare(plan,options['slot_entries'],
                        {name:canonical_bytes(item) for name,item in docs.items()},at=int(time.time()),expires_at=value['expires_at'],
                        status_revision=value['status_revision'],status_until=value['status_until'])
            except RepairWireError as error:raise MemoryError(error.code) from error
            payload=dict(destination_entry=dict(raw=bundle['destination']['raw'].decode('utf-8'),ref=bundle['destination']['ref']),
                owner_status_entry=dict(raw=bundle['owner_status']['raw'].decode('utf-8'),ref=bundle['owner_status']['ref']),
                slot_entries={name:config['slot_entries'][name] for name in ('slot','read','maintenance')},
                target=config['expected_target'],target_node_entry=config['target_node_entry'],base_url=config['base_url'])
            return self._mailbox_page(canonical_bytes(payload),value['receiver_id'],value.get('cursor'),'authorization')
        if action=='inspect':
            object_fields(value,{'schema_version','action','receiver_id'}|({'cursor'} if 'cursor' in value else set()))
            config=self._mailbox_saved_receiver(value['receiver_id'])
            return self._mailbox_page(canonical_bytes(config),value['receiver_id'],value.get('cursor'),'configuration')
        if action=='remove':
            object_fields(value,{'schema_version','action','receiver_id'})
            from memory_vault_network_crypto import opaque
            opaque(value['receiver_id'])
            with self.participant.state.db() as db:
                db.execute('DELETE FROM open_mailbox_receivers WHERE receiver_id=?',(value['receiver_id'],))
            return dict(state='removed',receiver_id=value['receiver_id'],network_accessed=False)
        object_fields(value,{'schema_version','action','base_url','limit_policy','expected_slot','expected_sender','expected_target','target_node_entry','slot_entries'})
        if action!='register':raise MemoryError('open_invalid_mailbox_receiver')
        try:
            options=self._mailbox_receiver_options(value)
            policy=replace(DEFAULT_POLICY,max_signature_checks=512);budget=RepairBudget(policy);now=int(time.time())
            expected=build_new_wire(dict(slot=value['expected_slot'],sender=value['expected_sender'],target=value['expected_target']),policy,budget).value
            owner=dict(signing_key=self.identity.public_descriptor(),encryption_key=self.encryption.public_descriptor())
            setup=verify_mailbox_feed_bootstrap(options['slot_entries'],expected_slot=expected['slot'],expected_owner=owner,
                expected_target=expected['target'],target_storage_epoch=expected['slot']['writer_storage_epoch'],
                limit_policy=value['limit_policy'],at=now,policy=policy,budget=budget)
            if setup['slot'].payload['sender']!=_dual_key(expected['sender'],budget):raise MemoryError('open_invalid_mailbox_receiver')
            entry=options['target_node_entry'];ref=raw_ref(entry['ref'])
            node=verify_original_control(entry['raw'],expected_signing_key=expected['target']['signing_key'],expected_schema='memory-vault-open-control/v1',
                expected_kind='node',at=now,policy=policy,budget=budget)
            _node_shape(node,now,budget)
            if (ref.namespace!='meta' or len(entry['raw'])!=ref.size or node.raw_sha256!=ref.raw_sha256 or node.payload['storage_epoch']!=expected['slot']['writer_storage_epoch']
                    or endpoint(value['base_url'],allow_loopback=self.participant.transport.allow_loopback)!=endpoint(node.payload['base_url'],allow_loopback=self.participant.transport.allow_loopback)):
                raise MemoryError('open_invalid_mailbox_receiver')
        except RepairWireError as error:
            raise MemoryError(error.code) from error
        receiver_id='mailbox_'+hashlib.sha256(canonical_bytes(value['expected_slot'])).hexdigest()
        raw=canonical_bytes(value)
        with self.participant.state.db() as db:
            db.execute('BEGIN IMMEDIATE')
            old=db.execute('SELECT body FROM open_mailbox_receivers WHERE receiver_id=?',(receiver_id,)).fetchone()
            if old is not None and bytes(old[0])!=raw:raise MemoryError('open_mailbox_receiver_conflict')
            if old is None:
                if db.execute('SELECT count(*) FROM open_mailbox_receivers').fetchone()[0]>=16:raise MemoryError('open_mailbox_receiver_capacity')
                db.execute('INSERT INTO open_mailbox_receivers(receiver_id,body) VALUES(?,?)',(receiver_id,raw))
        return dict(state='registered',receiver_id=receiver_id,network_accessed=False,receipt_return='separate_authority_required')

    def _mailbox_receive_replica(self, value, *, timeout=60):
        """Use original mailbox authority and retain observations across retries."""
        from dataclasses import replace
        from memory_vault_open_repair_admin import _ReplicaStatusJournal
        from memory_vault_open_repair_mailbox_copy_client import MailboxMessageReplicaRecoveryClient
        from memory_vault_open_repair_state import DEFAULT_POLICY, MAILBOX_WORKFLOW_LIMITS
        from memory_vault_open_repair_wire import RepairBudget, RepairWireError, build_new_wire
        from memory_vault_open_repair_history import _slot
        from memory_vault_open_repair_resource import _dual_key
        import math
        if type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0<timeout<=60:raise MemoryError('open_invalid_repair_policy')
        object_fields(value,{'schema_version','action','base_url','repair_profile','request'})
        if value['repair_profile']!='mailbox':raise MemoryError('open_invalid_repair_policy')
        fields={'expected_slot','expected_sender','expected_target','expected_source','source_storage_epoch',
            'expected_maintainer','expected_envelope_ref','target_node_entry','slot_entries','known_statuses','archive_statuses'}
        request=dict(object_fields(value['request'],fields))
        def decode(entry):
            object_fields(entry,{'raw','ref'})
            if not isinstance(entry['raw'],str):raise MemoryError('open_invalid_mailbox_receiver')
            return dict(raw=entry['raw'].encode('utf-8'),ref=entry['ref'])
        request['target_node_entry']=decode(request['target_node_entry'])
        object_fields(request['slot_entries'],{'slot','read','maintenance','bootstrap'})
        request['slot_entries']={name:decode(entry) for name,entry in request['slot_entries'].items()}
        for name,maximum in (('known_statuses',16),('archive_statuses',32)):
            if type(request[name]) is not list or len(request[name])>maximum:raise MemoryError('repair_status_history_capacity')
            request[name]=[decode(entry) for entry in request[name]]
        policy=replace(DEFAULT_POLICY,max_signature_checks=512);budget=RepairBudget(policy)
        owner=dict(signing_key=self.identity.public_descriptor(),encryption_key=self.encryption.public_descriptor())
        try:
            slot=build_new_wire(request['expected_slot'],policy,budget).value
            if not isinstance(slot,dict) or 'root_key' not in slot:raise MemoryError('open_invalid_mailbox_receiver')
            _slot(slot,slot['root_key'])
            parties=(owner,)+tuple(request[name] for name in ('expected_sender','expected_target','expected_source','expected_maintainer'))
            for keys in parties:_dual_key(keys,budget)
            with self.participant.state.db() as db:
                journal=_ReplicaStatusJournal(db,slot['root_key'])
                archive={canonical_bytes(item['ref']):item for item in (*journal.statuses(parties),*request['archive_statuses'])}
                if len(archive)>32:raise MemoryError('repair_status_history_capacity')
                request['archive_statuses']=list(archive.values())
                reader=MailboxMessageReplicaRecoveryClient(self.identity,self.encryption,policy=policy,
                    limit_policy=MAILBOX_WORKFLOW_LIMITS,transport=self.participant.transport,
                    allow_loopback=self.participant.transport.allow_loopback,status_observer=journal.observe)
                try:
                    result=asyncio.run(self._delivery().receive_mailbox_replica(reader,value['base_url'],timeout=timeout,**request))
                finally:reader.close()
            return dict(result,network_accessed=True)
        except RepairWireError as error:raise MemoryError(error.code) from error

    def receive_mailbox(self, base_url, *, limit_policy, status_observer=None, _network_observer=None, **arguments):
        """Receive an explicitly selected mailbox using retained original grants.

        The caller supplies the finite mailbox profile already used in its
        signed grants. Bodies come from the retained mailbox copy; receipts
        remain available for the independently authorized return operation.
        """
        from dataclasses import replace
        from memory_vault_open_repair_client import MailboxFeedRecoveryClient
        from memory_vault_open_repair_state import DEFAULT_POLICY
        transport=self.participant.transport
        if _network_observer is not None:
            actual=transport
            class ObservedTransport:
                def request_repair(self,*args,**kwargs):
                    _network_observer()
                    return actual.request_repair(*args,**kwargs)
            transport=ObservedTransport()
        reader = MailboxFeedRecoveryClient(self.identity, self.encryption,
            policy=replace(DEFAULT_POLICY, max_signature_checks=512), limit_policy=limit_policy,
            status_observer=status_observer, transport=transport,
            allow_loopback=self.participant.transport.allow_loopback)
        try:
            return asyncio.run(self._delivery().receive_mailbox(reader, base_url, **arguments))
        finally:
            reader.close()

    def read_message(self, **arguments):
        return self._delivery().read_message(**arguments)

    def recover_indexed_ack(self, **arguments):
        """Discover a consented source and read its original receipt as owner.

        Directory observations do not authorize this read. The caller supplies
        its independent original READ/bootstrap grants and exact A/B/source
        identities; success requires a real read matching the advertised commit.
        """
        from memory_vault_open_provider_client import OpenProviderClient
        from memory_vault_open_repair_client import AckOwnerRecoveryClient
        from memory_vault_open_repair_index_recovery import DiscoveredAckRecoveryClient
        from memory_vault_open_repair_state import INDEX_WORKFLOW_LIMITS
        reader = AckOwnerRecoveryClient(self.identity, self.encryption,
            limit_policy=INDEX_WORKFLOW_LIMITS, transport=self.participant.transport,
            allow_loopback=self.participant.transport.allow_loopback)
        discovered = DiscoveredAckRecoveryClient(OpenProviderClient(self.participant, self.encryption), reader)
        return asyncio.run(discovered.recover(**arguments))

    def _mailbox_ack_configuration(self, request_id, message_id):
        """Select whole A-owned originals from an explicitly prepared send."""
        from memory_vault_network_crypto import opaque
        from memory_vault_open_repair_admin import MAX_BUNDLE_BYTES
        from memory_vault_open_repair_provision import decode_saved_request
        from memory_vault_open_repair_wire import RepairWireError
        opaque(request_id);opaque(message_id)
        self._ack_preparations_initialize()
        with self.participant.state.db() as db:
            row=db.execute('SELECT result,result_sha256 FROM open_ack_agent_preparations WHERE request_id=?',(request_id,)).fetchone()
        if row is None or row['result'] is None:raise MemoryError('open_ack_preparation_incomplete')
        raw=bytes(row['result'])
        if len(raw)>MAX_BUNDLE_BYTES or hashlib.sha256(raw).hexdigest()!=row['result_sha256']:raise MemoryError('open_ack_preparation_corrupt')
        prepared=document(raw,maximum=MAX_BUNDLE_BYTES)
        if prepared['message_id']!=message_id:raise MemoryError('open_ack_preparation_conflict')
        try:bundle=decode_saved_request(prepared['recipient_request'])
        except RepairWireError as error:raise MemoryError(error.code) from error
        roles={name:bundle[field] for name,field in (('ack.root_authority','root_entry'),
            ('ack.write_grant','write_entry'),('bootstrap.ack_offer','bootstrap_entry'))}
        root=bundle['ack_slot']['root_key']
        for name,role in (('ack.root_authority','ack_root'),('ack.write_grant','ack_write'),('bootstrap.ack_offer','ack_offer_bootstrap')):
            entry=roles[name];kind=document(entry['raw'],maximum=65536)['payload']['kind']
            scope=hashlib.sha256(canonical_bytes(dict(kind='authority',root_key=root,authority_kind=kind,
                authority_sha256=entry['ref']['raw_sha256']))).hexdigest()
            matching=[value for value in bundle['current_statuses'] if any(row['scope_kind']=='authority' and row['scope_id']==scope
                for row in document(value['raw'],maximum=65536)['payload']['entries'])]
            if len(matching)!=1:raise MemoryError('open_ack_configuration_status_missing')
            roles['historical.status.'+role]=matching[0]
        # Draft preparation verifies every signature, binding and whole scope.
        return roles

    def _ack_preparations_initialize(self):
        delivery=self._delivery()
        with self.participant.state.db() as db:
            db.execute('CREATE TABLE IF NOT EXISTS open_ack_agent_preparations(request_id TEXT PRIMARY KEY,binding TEXT NOT NULL,result BLOB,result_sha256 TEXT)')
        return delivery

    def _ack_prepare(self, value):
        from memory_vault_open_repair_remote_provision import RemoteAckSourceProvisioner
        from memory_vault_open_repair_admin import MAX_BUNDLE_BYTES
        from memory_vault_open_control import coordinate
        from memory_vault_open_transport import endpoint
        object_fields(value,{'schema_version','action','source_url','source_key_id','request_id','recipient','text','memory_ids','repair_profile','lifetime'}
            |({'copy_maintainer'} if 'copy_maintainer' in value else set()))
        if (value['repair_profile'] not in ('receipt','receipt-index') or type(value['lifetime']) is not int
                or not 120<=value['lifetime']<=86400):raise MemoryError('open_invalid_ack_request')
        endpoint(value['source_url'],allow_loopback=self.participant.transport.allow_loopback);coordinate(value['source_key_id'])
        if 'copy_maintainer' in value:
            from memory_vault_open_repair_provision import _copy_maintainer
            from memory_vault_open_repair_state import DEFAULT_POLICY
            if value['copy_maintainer'] is None:raise MemoryError('open_invalid_ack_request')
            selected_copy=_copy_maintainer(value['copy_maintainer'],value['repair_profile'],DEFAULT_POLICY)
            if (selected_copy['signing_key']['key_id'] in (self.identity.key_id,value['recipient'],value['source_key_id'])
                    or selected_copy['encryption_key']['key_id']==self.encryption.key_id):
                raise MemoryError('repair_copy_maintainer_distinct_parties_required')
        delivery=self._ack_preparations_initialize()
        delivery._send_input(value['request_id'],[value['recipient']],value['text'],value['memory_ids'],None)
        binding=hashlib.sha256(canonical_bytes(value)).hexdigest()
        with self.participant.state.db() as db:
            db.execute('BEGIN IMMEDIATE')
            old=db.execute('SELECT binding,result,result_sha256 FROM open_ack_agent_preparations WHERE request_id=?',(value['request_id'],)).fetchone()
            if old is not None and old['binding']!=binding:raise MemoryError('open_ack_preparation_conflict')
            if old is None:
                if db.execute('SELECT count(*) FROM open_ack_agent_preparations').fetchone()[0]>=128:raise MemoryError('open_ack_preparation_capacity')
                db.execute('INSERT INTO open_ack_agent_preparations(request_id,binding) VALUES(?,?)',(value['request_id'],binding))
        cached=old is not None and old['result'] is not None
        if cached:
            raw=bytes(old['result'])
            if len(raw)>MAX_BUNDLE_BYTES or hashlib.sha256(raw).hexdigest()!=old['result_sha256']:raise MemoryError('open_ack_preparation_corrupt')
            result=document(raw,maximum=MAX_BUNDLE_BYTES)
        else:
            result=asyncio.run(RemoteAckSourceProvisioner(delivery).queue_and_prepare(value['request_id'],value['recipient'],
                text=value['text'],memory_ids=value['memory_ids'],source_url=value['source_url'],source_key_id=value['source_key_id'],
                profile=value['repair_profile'],lifetime=value['lifetime'],copy_maintainer=value.get('copy_maintainer')))
            raw=canonical_bytes(result)
            if len(raw)>MAX_BUNDLE_BYTES:raise MemoryError('open_ack_preparation_capacity')
            with self.participant.state.db() as db:
                db.execute('BEGIN IMMEDIATE')
                prior=db.execute('SELECT binding,result FROM open_ack_agent_preparations WHERE request_id=?',(value['request_id'],)).fetchone()
                if prior is None or prior['binding']!=binding:raise MemoryError('open_ack_preparation_conflict')
                if prior['result'] is not None and bytes(prior['result'])!=raw:raise MemoryError('open_ack_preparation_conflict')
                db.execute('UPDATE open_ack_agent_preparations SET result=?,result_sha256=? WHERE request_id=? AND result IS NULL',
                    (raw,hashlib.sha256(raw).hexdigest(),value['request_id']))
        return dict(state='ack_source_configured' if cached else 'ack_source_prepared',request_id=value['request_id'],
            message_id=result['message_id'],resource_id=result['resource_id'],preparation_delivery_uploaded=False,preparation_recipient_saved=False,
            from_local_history=cached,network_accessed=not cached,source_rechecked=not cached)

    def _ack_preparation_value(self, request_id, part):
        value=dict(request_id=request_id,part=part)
        from memory_vault_network_crypto import opaque
        from memory_vault_open_repair_admin import MAX_BUNDLE_BYTES
        opaque(value['request_id'])
        if value['part'] not in ('owner_request','recipient_request','owner_invitation','recipient_invitation'):raise MemoryError('open_invalid_ack_request')
        self._ack_preparations_initialize()
        with self.participant.state.db() as db:
            row=db.execute('SELECT result,result_sha256 FROM open_ack_agent_preparations WHERE request_id=?',(value['request_id'],)).fetchone()
        if row is None or row['result'] is None:raise MemoryError('open_ack_preparation_incomplete')
        stored=bytes(row['result'])
        if len(stored)>MAX_BUNDLE_BYTES or hashlib.sha256(stored).hexdigest()!=row['result_sha256']:raise MemoryError('open_ack_preparation_corrupt')
        prepared=document(stored,maximum=MAX_BUNDLE_BYTES)
        if value['part'] in ('owner_invitation','recipient_invitation'):
            from memory_vault_open_repair_admin import _entry as decode_original
            def encoded(entry):
                decoded=decode_original(entry)
                return dict(raw=decoded['raw'].decode('utf-8'),ref=decoded['ref'])
            recipient=prepared['recipient_request']
            if value['part']=='recipient_invitation':
                request={name:([encoded(entry) for entry in item] if name=='current_statuses' else
                    encoded(item) if name.endswith('_entry') else item) for name,item in recipient['request'].items()}
                exported=dict(schema_version=ACK_CONNECT_SCHEMA,action='return_receipt',
                    base_url=recipient['base_url'],repair_profile=recipient['repair_profile'],request=request)
            else:
                owner=prepared['owner_request']
                request=dict(target_node_entry=encoded(owner['node']),expected_target=owner['target'],
                    expected_ack_slot=owner['ack_slot'],root_entry=encoded(owner['root']),read_entry=encoded(owner['read']),
                    bootstrap_entry=encoded(owner['bootstrap']),expected_receipt_writer=owner['receipt_writer'],
                    expected_message_id=owner['message_id'],expected_envelope_ref=owner['envelope_ref'],
                    known_statuses=[encoded(entry) for entry in owner['known_statuses']])
                exported=dict(schema_version=ACK_CONNECT_SCHEMA,action='recover_receipt',
                    base_url=recipient['base_url'],repair_profile=recipient['repair_profile'],request=request)
        else:exported=prepared[value['part']]
        return exported

    def _ack_export_preparation(self, value):
        import base64
        object_fields(value,{'schema_version','action','request_id','part'}|({'cursor'} if 'cursor' in value else set()))
        exported=self._ack_preparation_value(value['request_id'],value['part'])
        raw=canonical_bytes(exported);digest=hashlib.sha256(raw).hexdigest();offset=0
        cursor=value.get('cursor')
        if cursor is not None:
            object_fields(cursor,{'sha256','offset'});offset=cursor['offset']
            if cursor['sha256']!=digest or type(offset) is not int or not 0<offset<len(raw) or offset%3072:raise MemoryError('open_invalid_ack_cursor')
        end=min(offset+3072,len(raw))
        return dict(state='ack_preparation_export',request_id=value['request_id'],part=value['part'],bundle_sha256=digest,
            total_bytes=len(raw),offset=offset,bundle_chunk=base64.b64encode(raw[offset:end]).decode('ascii'),
            next_cursor=None if end==len(raw) else dict(sha256=digest,offset=end),network_accessed=False,source_rechecked=False)

    def _ack_return_mailbox_receipt(self, value, *, _deadline=None, _network_observer=None):
        """Return one saved cold receipt using its original mailbox authority."""
        from memory_vault_open_control import coordinate
        from memory_vault_open_transport import endpoint
        from memory_vault_open_repair_provision import PROFILES,SAVED_REQUEST_SCHEMA,encode_original,decode_saved_request
        from memory_vault_open_repair_put_client import AckReceiptClient
        from memory_vault_open_repair_receipt import SavedAckReceiptPublisher
        from memory_vault_open_repair_client import _entry
        from memory_vault_open_delivery import _hex
        from memory_vault_open_repair_admin import MAX_BUNDLE_BYTES
        deadline = time.monotonic()+60 if _deadline is None else _deadline
        def remaining():
            value=deadline-time.monotonic()
            if value<=0:raise MemoryError('open_delivery_budget_exhausted',retryable=True)
            return min(60,value)
        object_fields(value,{'schema_version','action','message_id','source_url','source_key_id','repair_profile'})
        _hex(value['message_id'],prefix='msg_');coordinate(value['source_key_id'])
        if type(value['repair_profile']) is not str or value['repair_profile'] not in PROFILES:
            raise MemoryError('open_invalid_repair_policy')
        endpoint(value['source_url'],allow_loopback=self.participant.transport.allow_loopback)
        # Retain the caller's normalized origin, not a discovered redirect.
        base=value['source_url'].rstrip('/')
        delivery=self._delivery();row=delivery._inbox(value['message_id'])
        if row is None or row['phase']!='saved':raise MemoryError('repair_receipt_not_saved')
        session=delivery._inbox_session(bytes(row['session']))
        if 'mailbox' not in session:raise MemoryError('open_ack_mailbox_configuration_missing')
        verified=delivery._verify_mailbox_inbox(session,row)
        roles=verified['setup']['roles']
        if verified['setup']['ack_configuration'] is None:
            raise MemoryError('open_ack_mailbox_configuration_missing')
        owner=session['mailbox']['sender']
        root,write,bootstrap=(roles[name] for name in ('ack.root_authority','ack.write_grant','bootstrap.ack_offer'))
        wp=document(write['raw'],maximum=65536)['payload']
        plan=canonical_bytes(dict(message_id=value['message_id'],envelope_ref=wp['envelope_ref'],source_url=base,
            source_key_id=value['source_key_id'],repair_profile=value['repair_profile'],write_ref=write['ref']))
        binding=hashlib.sha256(plan).hexdigest()
        with self.participant.state.db() as db:
            db.execute('CREATE TABLE IF NOT EXISTS open_mailbox_ack_returns(message_id TEXT PRIMARY KEY,binding TEXT NOT NULL,request BLOB NOT NULL,request_sha256 TEXT NOT NULL)')
            held=db.execute('SELECT * FROM open_mailbox_ack_returns WHERE message_id=?',(value['message_id'],)).fetchone()
        accessed=False
        # Preserve the original bounded carrier retry window. The borrowed
        # transport independently clamps each exchange to this receive call's
        # deadline; a short poll must not shorten an already signed carrier.
        from memory_vault_open_mailbox_receipt_jobs import ObservedTransport
        reader=AckReceiptClient(self.identity,self.encryption,
            limit_policy=PROFILES[value['repair_profile']],transport=ObservedTransport(self.participant.transport,_network_observer,deadline),
            allow_loopback=self.participant.transport.allow_loopback)
        try:
            if held is not None:
                if held['binding']!=binding:raise MemoryError('open_ack_mailbox_return_conflict')
                raw=bytes(held['request'])
                if len(raw)>MAX_BUNDLE_BYTES or hashlib.sha256(raw).hexdigest()!=held['request_sha256']:
                    raise MemoryError('open_ack_mailbox_return_corrupt')
                request=decode_saved_request(document(raw,maximum=MAX_BUNDLE_BYTES))
            else:
                from memory_vault_open_provider_client import OpenProviderClient
                from memory_vault_open_agent_setup import fetch_introductions
                async def target_keys():
                    node=(await asyncio.to_thread(fetch_introductions,self.identity,[(base,value['source_key_id'])],
                        allow_loopback=self.participant.transport.allow_loopback,timeout=min(15,remaining())))[0]
                    self.participant._accept(node)
                    from memory_vault_open_routing import LookupBudget
                    target_record=await OpenProviderClient(self.participant,self.encryption).prove_target(node,
                        LookupBudget(maximum_seconds=min(10,remaining())))
                    return node,dict(signing_key=target_record['payload']['signing_key'],encryption_key=target_record['payload']['targetEncryptionKey'])
                if _network_observer is not None:_network_observer()
                node,target=asyncio.run(target_keys());accessed=True
                raw=canonical_bytes(node);digest=hashlib.sha256(raw).hexdigest()
                node_entry=dict(raw=raw,ref=dict(namespace='meta',key=digest,raw_sha256=digest,size=len(raw)))
                statuses={roles['historical.status.'+role]['ref']['raw_sha256']:roles['historical.status.'+role]
                    for role in ('ack_root','ack_write','ack_offer_bootstrap')}
                remaining()
                prepared=reader.prepare_return(base,target_node_entry=node_entry,expected_target=target,expected_ack_slot=wp['ack_slot'],
                    expected_owner=owner,expected_message_id=value['message_id'],expected_envelope_ref=wp['envelope_ref'],
                    root_entry=root,write_entry=write,bootstrap_entry=bootstrap,known_statuses=list(statuses.values()),timeout=30)
                request=dict(message_id=value['message_id'],envelope_ref=wp['envelope_ref'],ack_slot=wp['ack_slot'],owner=owner,target=target,
                    target_node_entry=node_entry,root_entry=root,write_entry=write,bootstrap_entry=bootstrap,
                    binding_entry=_entry(prepared.source.binding),current_statuses=[_entry(item) for item in prepared.current_statuses],
                    read_until=prepared.source.read_until,retain_until=prepared.source.retain_until)
                bundle=dict(schema_version=SAVED_REQUEST_SCHEMA,base_url=base,repair_profile=value['repair_profile'],
                    request={name:([encode_original(item) for item in item_value] if name=='current_statuses' else
                        encode_original(item_value) if name.endswith('_entry') else item_value) for name,item_value in request.items()})
                raw=canonical_bytes(bundle)
                if len(raw)>MAX_BUNDLE_BYTES:raise MemoryError('open_ack_mailbox_return_capacity')
                with self.participant.state.db() as db:
                    db.execute('BEGIN IMMEDIATE')
                    old=db.execute('SELECT binding,request,request_sha256 FROM open_mailbox_ack_returns WHERE message_id=?',(value['message_id'],)).fetchone()
                    if old is not None:
                        if old['binding']!=binding:raise MemoryError('open_ack_mailbox_return_conflict')
                        previous=bytes(old['request'])
                        if len(previous)>MAX_BUNDLE_BYTES or hashlib.sha256(previous).hexdigest()!=old['request_sha256']:
                            raise MemoryError('open_ack_mailbox_return_corrupt')
                        request=decode_saved_request(document(previous,maximum=MAX_BUNDLE_BYTES))
                    else:
                        if db.execute('SELECT count(*) FROM open_mailbox_ack_returns').fetchone()[0]>=16:
                            raise MemoryError('open_ack_mailbox_return_capacity')
                        db.execute('INSERT INTO open_mailbox_ack_returns VALUES(?,?,?,?)',
                            (value['message_id'],binding,raw,hashlib.sha256(raw).hexdigest()))
            remaining()
            result=SavedAckReceiptPublisher(delivery,reader).publish_saved(base,request,timeout=30)
            return dict(state='retained_at_ack_source',message_id=value['message_id'],
                receipt_ref=result.source.inputs['receipt'].ref.as_dict(),commit_ref=result.source.commit.ref.as_dict(),
                from_local_history=result.from_local_history,network_accessed=accessed or not result.from_local_history)
        finally:
            reader.close()

    def _ack_connect(self, invitation, *, _deadline=None, _network_observer=None):
        """Explicit original-grant operations through the existing Agent facade."""
        from memory_vault_open_repair_wire import RepairWireError
        from memory_vault_open_repair_state import RECEIPT_WORKFLOW_LIMITS,INDEX_WORKFLOW_LIMITS
        value=document(invitation,maximum=65536)
        try:
            from memory_vault_open_ack_replica_send import ACTIONS as REPLICA_ACTIONS, connect as replica_connect
            if value.get('action') in REPLICA_ACTIONS:return replica_connect(self,value)
            from memory_vault_open_mailbox_receipt_jobs import ACTIONS, connect as receipt_job_connect
            if value.get('action') in ACTIONS:return receipt_job_connect(self,value)
            if value.get('action')=='return_mailbox_receipt':return self._ack_return_mailbox_receipt(value)
            if value.get('action')=='prepare':return self._ack_prepare(value)
            if value.get('action')=='export_preparation':return self._ack_export_preparation(value)
        except RepairWireError as error:raise MemoryError(error.code) from error
        object_fields(value,{'schema_version','action','base_url','repair_profile','request'})
        profiles={'receipt':RECEIPT_WORKFLOW_LIMITS,'receipt-index':INDEX_WORKFLOW_LIMITS}
        if not isinstance(value['repair_profile'],str) or value['repair_profile'] not in profiles:raise MemoryError('open_invalid_repair_policy')
        request=dict(value['request'])
        def decode(entry):
            object_fields(entry,{'raw','ref'})
            if not isinstance(entry['raw'],str):raise MemoryError('open_invalid_ack_request')
            return dict(raw=entry['raw'].encode('utf-8'),ref=entry['ref'])
        try:
            if value['action']=='return_receipt':
                from memory_vault_open_repair_receipt import REQUEST_FIELDS
                object_fields(request,REQUEST_FIELDS)
                for name in REQUEST_FIELDS:
                    if name.endswith('_entry'):request[name]=decode(request[name])
                if not isinstance(request['current_statuses'],list):raise MemoryError('open_invalid_ack_request')
                request['current_statuses']=[decode(entry) for entry in request['current_statuses']]
                result=self.publish_saved_ack(value['base_url'],request,repair_profile=value['repair_profile'])
                return dict(state='retained_at_ack_source',message_id=request['message_id'],
                    receipt_ref=result.source.inputs['receipt'].ref.as_dict(),commit_ref=result.source.commit.ref.as_dict(),
                    from_local_history=result.from_local_history,network_accessed=not result.from_local_history)
            if value['action'] not in ('recover_receipt','recover_replica_receipt'):raise MemoryError('open_invalid_ack_request')
            replica=value['action']=='recover_replica_receipt'
            from memory_vault_open_repair_client import AckOwnerRecoveryClient,MailboxSetupJournal
            object_fields(request,{'target_node_entry','expected_target','expected_ack_slot','root_entry','read_entry','bootstrap_entry',
                'expected_receipt_writer','expected_message_id','expected_envelope_ref'}|({'known_statuses'} if 'known_statuses' in request else set())
                |({'expected_source','source_storage_epoch','expected_maintainer'} if replica else set()))
            supplied=request.pop('known_statuses',[])
            if type(supplied) is not list or len(supplied)>16:raise MemoryError('open_invalid_ack_request')
            supplied=[decode(entry) for entry in supplied]
            for name in ('target_node_entry','root_entry','read_entry','bootstrap_entry'):request[name]=decode(request[name])
            binding=('expected_target','expected_ack_slot','expected_receipt_writer','expected_message_id','expected_envelope_ref')
            if replica:binding+=('expected_source','source_storage_epoch','expected_maintainer')
            plan=canonical_bytes(dict(kind='ack.replica_owner_recovery' if replica else 'ack.owner_recovery',owner=self.identity.public_descriptor(),
                **{name:request[name] for name in binding},
                grants={name:request[name]['ref'] for name in ('root_entry','read_entry','bootstrap_entry')}))
            key=hashlib.sha256(plan).hexdigest()
            with self.participant.state.db() as db:
                journal=MailboxSetupJournal(db);journal.initialize()
                exists=db.execute('SELECT 1 FROM open_mailbox_setup_jobs WHERE job_key=?',(key,)).fetchone() is not None
                if exists:journal.start(key,plan)
                known=journal.statuses(key) if exists else ()
                from memory_vault_open_repair_admin import _ReplicaStatusJournal
                parties=(dict(signing_key=self.identity.public_descriptor(),encryption_key=self.encryption.public_descriptor()),)+tuple(
                    request[name] for name in (('expected_target','expected_source','expected_maintainer','expected_receipt_writer') if replica else
                                              ('expected_target','expected_receipt_writer')))
                replica_journal=_ReplicaStatusJournal(db,request['expected_ack_slot']['root_key'],original_source=not replica)
                known=list({canonical_bytes(e['ref']):e for e in [*known,*replica_journal.statuses(parties)]}.values())
                if len(known)>32:raise MemoryError('repair_status_history_capacity')
                def observed(value):
                    # Reserve a new journal only after a relevant signed status
                    # is authenticated; malformed invitations consume no slot.
                    journal.start(key,plan)
                    journal.observe(key,value)
                    replica_journal.observe(value)
                from memory_vault_open_mailbox_receipt_jobs import ObservedTransport
                reader=AckOwnerRecoveryClient(self.identity,self.encryption,limit_policy=profiles[value['repair_profile']],
                    transport=ObservedTransport(self.participant.transport,_network_observer,_deadline),
                    allow_loopback=self.participant.transport.allow_loopback,status_observer=observed)
                try:
                    recover=reader.recover_replica_occupied if replica else reader.recover_occupied
                    # Replica recovery authenticates the source histories plus
                    # independent copy/return authority. Give this complete
                    # Agent workflow the same finite 60s window as mailbox
                    # replica reception; signed expiry may still end it sooner.
                    timeout=60 if replica else 30
                    if _deadline is not None:
                        timeout=min(timeout,_deadline-time.monotonic())
                        if timeout<=0:raise MemoryError('open_delivery_budget_exhausted',retryable=True)
                    recovered=recover(value['base_url'],known_statuses=supplied,archive_statuses=known,
                        timeout=timeout,**request)
                    source=recovered.replica['source'].event if replica else recovered.source
                    result=self._delivery().accept_recovered_receipt(source.inputs['receipt'].raw)
                    extra=dict(replica_custody_ref=recovered.replica['custody'].ref.as_dict()) if replica else {}
                    return dict(result,commit_ref=source.commit.ref.as_dict(),network_accessed=True,**extra)
                finally:
                    reader.close()
        except RepairWireError as error:
            raise MemoryError(error.code) from error

    def publish_saved_ack(self, base_url, request, *, timeout=30, repair_profile="receipt"):
        """Explicitly share one actually saved receipt through an ACK source.

        The closed request supplies retained original authorities and binding.
        This call signs B's bounded receipt-return consent; receive() never
        invokes it automatically. The result distinguishes retained history
        from a newly verified network commit.
        """
        from memory_vault_open_repair_put_client import AckReceiptClient
        from memory_vault_open_repair_receipt import SavedAckReceiptPublisher
        from memory_vault_open_repair_state import RECEIPT_WORKFLOW_LIMITS, INDEX_WORKFLOW_LIMITS
        profiles = {"receipt": RECEIPT_WORKFLOW_LIMITS, "receipt-index": INDEX_WORKFLOW_LIMITS}
        if type(repair_profile) is not str or repair_profile not in profiles:
            raise MemoryError("open_invalid_repair_policy")
        client = AckReceiptClient(self.identity, self.encryption,
            limit_policy=profiles[repair_profile],
            allow_loopback=self.participant.transport.allow_loopback,
            transport=self.participant.transport)
        return SavedAckReceiptPublisher(self._delivery(), client).publish_saved(base_url, request, timeout=timeout)

    def _delivery(self):
        from memory_vault_open_delivery_client import OpenDeliveryClient
        return OpenDeliveryClient(self.participant, self.encryption, self.client_config)

    def respond_to(self, *arguments):
        raise MemoryError("open_hint_exchange_unsupported")
