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
        return asyncio.run(self._delivery().send(**arguments))

    def receive(self, limit=4):
        from memory_vault_open_repair_wire import RepairWireError
        delivery=self._delivery();deadline=time.monotonic()+60
        result=asyncio.run(delivery.receive(limit=limit,_pending_only=True))
        if len(result['messages'])>=limit:return result
        self._mailbox_receivers_initialize()
        with self.participant.state.db() as db:
            rows=db.execute('SELECT receiver_id,body FROM open_mailbox_receivers ORDER BY last_attempt,receiver_id LIMIT 4').fetchall()
        for row in rows:
            remaining=deadline-time.monotonic()
            if len(result['messages'])>=limit or remaining<=0:break
            with self.participant.state.db() as db:
                db.execute('UPDATE open_mailbox_receivers SET last_attempt=? WHERE receiver_id=?',(time.time_ns(),row['receiver_id']))
            try:
                config=document(bytes(row['body']),maximum=65536)
                options=self._mailbox_receiver_options(config)
                def accessed():result['network_accessed']=True
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
            object_fields(value,{'schema_version','action','message_id','authorization','attempt_until','consent_until','expires_at','object_until','enum_until'})
            authorization=object_fields(value['authorization'],{'destination_entry','owner_status_entry','slot_entries','target','target_node_entry','base_url'})
            # The same durable stages back both the individual operations and
            # this combined call. A failed remote admission leaves the exact
            # local preparation available to the next identical retry.
            self._mailbox_connect(dict(schema_version=MAILBOX_CONNECT_SCHEMA,action='prepare',message_id=value['message_id'],
                slot_entries=authorization['slot_entries'],destination_entry=authorization['destination_entry'],
                attempt_until=value['attempt_until'],consent_until=value['consent_until']))
            return self._mailbox_connect(dict(schema_version=MAILBOX_CONNECT_SCHEMA,action='admit',message_id=value['message_id'],
                **{name:authorization[name] for name in ('base_url','target','target_node_entry','owner_status_entry')},
                **{name:value[name] for name in ('expires_at','object_until','enum_until')}))
        if action=='prepare':
            object_fields(value,{'schema_version','action','message_id','slot_entries','destination_entry','attempt_until','consent_until'})
            from memory_vault_open_repair_client import MailboxMessageDraftStore
            def entry(item):
                object_fields(item,{'raw','ref'})
                if not isinstance(item['raw'],str):raise MemoryError('open_invalid_mailbox_request')
                return dict(raw=item['raw'].encode('utf-8'),ref=item['ref'])
            delivery=self._delivery()
            object_fields(value['slot_entries'],{'slot','read','maintenance'})
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
                        attempt_until=value['attempt_until'],consent_until=value['consent_until'])
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
        object_fields(value,{'schema_version','action','source_url','source_key_id','request_id','recipient','text','memory_ids','repair_profile','lifetime'})
        if (value['repair_profile'] not in ('receipt','receipt-index') or type(value['lifetime']) is not int
                or not 120<=value['lifetime']<=86400):raise MemoryError('open_invalid_ack_request')
        endpoint(value['source_url'],allow_loopback=self.participant.transport.allow_loopback);coordinate(value['source_key_id'])
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
                profile=value['repair_profile'],lifetime=value['lifetime']))
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

    def _ack_export_preparation(self, value):
        import base64
        from memory_vault_network_crypto import opaque
        from memory_vault_open_repair_admin import MAX_BUNDLE_BYTES
        object_fields(value,{'schema_version','action','request_id','part'}|({'cursor'} if 'cursor' in value else set()))
        opaque(value['request_id'])
        if value['part'] not in ('owner_request','recipient_request'):raise MemoryError('open_invalid_ack_request')
        self._ack_preparations_initialize()
        with self.participant.state.db() as db:
            row=db.execute('SELECT result,result_sha256 FROM open_ack_agent_preparations WHERE request_id=?',(value['request_id'],)).fetchone()
        if row is None or row['result'] is None:raise MemoryError('open_ack_preparation_incomplete')
        stored=bytes(row['result'])
        if len(stored)>MAX_BUNDLE_BYTES or hashlib.sha256(stored).hexdigest()!=row['result_sha256']:raise MemoryError('open_ack_preparation_corrupt')
        raw=canonical_bytes(document(stored,maximum=MAX_BUNDLE_BYTES)[value['part']]);digest=hashlib.sha256(raw).hexdigest();offset=0
        cursor=value.get('cursor')
        if cursor is not None:
            object_fields(cursor,{'sha256','offset'});offset=cursor['offset']
            if cursor['sha256']!=digest or type(offset) is not int or not 0<offset<len(raw) or offset%3072:raise MemoryError('open_invalid_ack_cursor')
        end=min(offset+3072,len(raw))
        return dict(state='ack_preparation_export',request_id=value['request_id'],part=value['part'],bundle_sha256=digest,
            total_bytes=len(raw),offset=offset,bundle_chunk=base64.b64encode(raw[offset:end]).decode('ascii'),
            next_cursor=None if end==len(raw) else dict(sha256=digest,offset=end),network_accessed=False,source_rechecked=False)

    def _ack_connect(self, invitation):
        """Explicit original-grant operations through the existing Agent facade."""
        from memory_vault_open_repair_wire import RepairWireError
        from memory_vault_open_repair_state import RECEIPT_WORKFLOW_LIMITS,INDEX_WORKFLOW_LIMITS
        value=document(invitation,maximum=65536)
        try:
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
            if value['action']!='recover_receipt':raise MemoryError('open_invalid_ack_request')
            from memory_vault_open_repair_client import AckOwnerRecoveryClient,MailboxSetupJournal
            object_fields(request,{'target_node_entry','expected_target','expected_ack_slot','root_entry','read_entry','bootstrap_entry',
                'expected_receipt_writer','expected_message_id','expected_envelope_ref'})
            for name in ('target_node_entry','root_entry','read_entry','bootstrap_entry'):request[name]=decode(request[name])
            plan=canonical_bytes(dict(kind='ack.owner_recovery',owner=self.identity.public_descriptor(),
                **{name:request[name] for name in ('expected_target','expected_ack_slot','expected_receipt_writer','expected_message_id','expected_envelope_ref')},
                grants={name:request[name]['ref'] for name in ('root_entry','read_entry','bootstrap_entry')}))
            key=hashlib.sha256(plan).hexdigest()
            with self.participant.state.db() as db:
                journal=MailboxSetupJournal(db);journal.initialize()
                exists=db.execute('SELECT 1 FROM open_mailbox_setup_jobs WHERE job_key=?',(key,)).fetchone() is not None
                if exists:journal.start(key,plan)
                known=journal.statuses(key) if exists else ()
                def observed(value):
                    # Reserve a new journal only after a relevant signed status
                    # is authenticated; malformed invitations consume no slot.
                    journal.start(key,plan)
                    journal.observe(key,value)
                reader=AckOwnerRecoveryClient(self.identity,self.encryption,limit_policy=profiles[value['repair_profile']],
                    transport=self.participant.transport,allow_loopback=self.participant.transport.allow_loopback,
                    status_observer=observed)
                try:
                    recovered=reader.recover_occupied(value['base_url'],known_statuses=known,**request)
                    result=self._delivery().accept_recovered_receipt(recovered.source.inputs['receipt'].raw)
                    return dict(result,commit_ref=recovered.source.commit.ref.as_dict(),network_accessed=True)
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
