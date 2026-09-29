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
        self._mailbox_receivers_initialize()
        if action=='list':
            object_fields(value,{'schema_version','action'})
            with self.participant.state.db() as db:
                ids=[v[0] for v in db.execute('SELECT receiver_id FROM open_mailbox_receivers ORDER BY receiver_id')]
            return dict(state='configured',mailboxes=ids,network_accessed=False)
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
