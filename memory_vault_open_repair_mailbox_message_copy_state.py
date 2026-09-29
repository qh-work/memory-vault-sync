"""Atomic message custody only after exact ciphertext is physically retained."""
from memory_vault_open_repair_mailbox_feed_copy_state import MailboxFeedCopyState
from memory_vault_open_repair_mailbox_message_copy import (
    verify_mailbox_message_copy, verify_mailbox_message_replica, verify_message_body, check_message_return)


class MailboxMessageCopyState(MailboxFeedCopyState):
    verify_copy = staticmethod(verify_mailbox_message_copy)
    verify_replica = staticmethod(verify_mailbox_message_replica)
    _return = staticmethod(check_message_return)

    def _body_originals(self, plan, entry, budget):
        value = verify_message_body(entry, plan.source['message_scope']['envelope_ref'], budget.policy, budget)
        return (('message.envelope', value),)

    def commit_message(self, *args, expected_envelope_ref, envelope_entry, **options):
        return super().commit_feed(*args, expected_envelope_ref=expected_envelope_ref, body_entry=envelope_entry, **options)

    def restore_message(self, *args, expected_envelope_ref, **options):
        return super().restore_feed(*args, expected_envelope_ref=expected_envelope_ref, **options)

    def prepare_message_read(self, *args, expected_envelope_ref, **options):
        return super().prepare_feed_read(*args, expected_envelope_ref=expected_envelope_ref, **options)
