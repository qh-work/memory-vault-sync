"""Explicit open profile for the same six-operation Agent facade.

Contact discovery and explicitly approved encrypted delivery share the existing
open participant. Remember/recall stay in the existing Vault; no private network
authority or encryption downgrade is selected by a failed open operation.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

from memory_vault import MemoryError
from memory_vault_client import ClientConfig
from memory_vault_network import _read_private
from memory_vault_network_crypto import EncryptionIdentity, document, object_fields
from memory_vault_open_node import OpenParticipant
from memory_vault_trust import Identity

CONFIG_SCHEMA = "memory-vault-open-client-config/v1"


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

    def receive(self, **arguments):
        return asyncio.run(self._delivery().receive(**arguments))

    def receive_mailbox(self, base_url, *, limit_policy, status_observer=None, **arguments):
        """Receive an explicitly selected mailbox using retained original grants.

        The caller supplies the finite mailbox profile already used in its
        signed grants. Bodies come from the retained mailbox copy; receipts
        remain available for the independently authorized return operation.
        """
        from dataclasses import replace
        from memory_vault_open_repair_client import MailboxFeedRecoveryClient
        from memory_vault_open_repair_state import DEFAULT_POLICY
        reader = MailboxFeedRecoveryClient(self.identity, self.encryption,
            policy=replace(DEFAULT_POLICY, max_signature_checks=512), limit_policy=limit_policy,
            status_observer=status_observer, transport=self.participant.transport,
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
