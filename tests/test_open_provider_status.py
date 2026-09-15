"""Signed status observations in a synthetic existing transport database.

These exercise the real provider transaction/observation adapter, not a new
repair route or a claim that a parsed status alone authorizes storage or reads.
"""
import copy
from pathlib import Path
import sqlite3
import tempfile
import unittest

from memory_vault import MemoryError, canonical_bytes
from memory_vault_network_crypto import EncryptionIdentity
from memory_vault_open_control import issue_node
import memory_vault_open_provider as provider
from memory_vault_open_provider_state import ProviderState
from memory_vault_trust import Identity


class OpenProviderStatusTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="memory-provider-status-synthetic-")
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name).resolve()
        self.server = Identity.generate(self.path / "node.json")
        self.owner = Identity.generate(self.path / "owner.json")
        self.encryption = EncryptionIdentity.generate()
        self.owner_encryption = EncryptionIdentity.generate()
        self.now = 2_000_000_000
        self.node = issue_node(self.server, base_url="http://127.0.0.1:18501",
            storage_epoch="synthetic_epoch", roles=["directory", "router"],
            revision=1, issued_at=self.now, expires_at=self.now + 3600)
        self.root = {"owner": {"signing_key_id": self.owner.key_id,
                             "encryption_key_id": self.owner_encryption.key_id},
                     "root_kind": "mailbox", "anchor_ref": {"namespace": "anchor", "key": "a" * 64},
                     "owner_epoch": "synthetic_owner_epoch", "root_id": "synthetic_root"}
        self.database = self.path / "existing_transport.sqlite3"
        self.db = sqlite3.connect(self.database)
        self.addCleanup(lambda: self.db.close())
        self.db.execute("CREATE TABLE synthetic_existing_marker(value TEXT)")
        self.db.execute("INSERT INTO synthetic_existing_marker VALUES('preserved')")
        self.db.commit()
        self.initialize()
        self.request = provider.sign_rpc(self.owner, node=self.node,
            action="provider.get", body={"ref": {"namespace": "object", "key": "b" * 64},
            "after": None, "limit": 1, "maximum_bytes": 16384}, now=self.now,
            request_id="synthetic_observation_transaction")

    def initialize(self):
        self.state = ProviderState(self.db, self.server, self.node,
            encryption_identity=self.encryption, enabled=True, clock=lambda: self.now)
        self.state.initialize()

    def signed(self, revision=1, *, scope="c", minimum=1, status="active", mask=16):
        return provider.issue_status(self.owner, root=self.root, revision=revision,
            issued_at=self.now, valid_until=self.now + 600,
            entries=[{"scope_kind": "authority", "scope_id": scope * 64,
                      "minimum_document_revision": minimum, "status": status, "operation_mask": mask}])

    def observe(self, signed, *, scope="c", required=1, issuer=None):
        # Exercise the actual transaction commit-before-refusal behavior, with
        # a verified RPC and the real _observe callback. This is not a new RPC.
        return self.state._transaction(self.request, lambda rpc, now:
            self.state._observe(signed, root=self.root, issuer=issuer or self.owner.key_id,
                kind="authority", scope_id=scope * 64, required_revision=required, now=now))

    def row(self, scope="c"):
        return self.state._one("SELECT * FROM open_provider_status WHERE scope_id=?", (scope * 64,))

    def restart(self):
        self.db.close()
        self.db = sqlite3.connect(self.database)
        self.initialize()
        self.assertEqual(self.db.execute("SELECT value FROM synthetic_existing_marker").fetchone()[0], "preserved")

    def test_revocation_commits_original_and_survives_restart_and_newer_active(self):
        self.observe(self.signed())
        revoked = self.signed(2, status="revoked", mask=provider.PUBLISH | provider.OPERATIONS["read"])
        with self.assertRaisesRegex(MemoryError, "provider_authority_revoked"):
            self.observe(revoked)
        self.assertEqual(bytes(self.row()["record"]), canonical_bytes(revoked))
        self.restart()
        newer = self.signed(3)
        with self.assertRaisesRegex(MemoryError, "provider_authority_revoked"):
            self.observe(newer)
        self.assertEqual(self.row()["revoked_mask"], 18)
        self.assertEqual(bytes(self.row()["record"]), canonical_bytes(newer))
        with self.assertRaisesRegex(MemoryError, "provider_status_rollback"):
            self.observe(revoked)
        self.assertEqual(self.row()["revision"], 3)

    def test_minimum_revision_refusal_is_durable_and_cannot_be_lowered(self):
        raised = self.signed(2, minimum=4)
        with self.assertRaisesRegex(MemoryError, "provider_status_revision"):
            self.observe(raised)
        self.restart()
        self.assertIsNone(self.observe(raised, required=4))
        with self.assertRaisesRegex(MemoryError, "provider_status_rollback"):
            self.observe(self.signed(3, minimum=3), required=4)
        self.assertEqual(bytes(self.row()["record"]), canonical_bytes(raised))

    def test_same_revision_other_scope_conflicts_whole_signed_original(self):
        original = self.signed(2)
        fork = self.signed(2, scope="d")
        self.observe(original)
        with self.assertRaisesRegex(MemoryError, "provider_status_conflict"):
            self.observe(fork, scope="d")
        self.assertIsNone(self.row("d"))
        self.assertEqual(bytes(self.row()["record"]), canonical_bytes(original))
        self.assertEqual(bytes(self.row()["second_record"]), canonical_bytes(fork))
        self.restart()
        with self.assertRaisesRegex(MemoryError, "provider_status_conflict"):
            self.observe(self.signed(3))
        self.assertEqual(self.row()["conflict"], 1)
        self.assertEqual(self.row()["revision"], 2)

    def test_provider_adapter_stays_publish_only_and_rejects_unverified_scope(self):
        for bit in (1, 2, 4, 8, 32, 64):
            with self.subTest(bit=bit), self.assertRaisesRegex(MemoryError, "provider_status_operation"):
                self.observe(self.signed(mask=bit))
        with self.assertRaisesRegex(MemoryError, "provider_status_scope_mismatch"):
            self.observe(self.signed(), issuer=self.server.key_id)
        with self.assertRaisesRegex(MemoryError, "provider_missing_status"):
            self.observe(self.signed(), scope="e")
        altered = copy.deepcopy(self.signed())
        altered["proof"] = self.server.sign_message(altered["payload"])
        with self.assertRaises(MemoryError):
            self.observe(altered)
        self.assertIsNone(self.row())

    def test_expiry_and_failed_storage_do_not_create_or_modify_observation(self):
        expired = self.signed()
        self.now += 600
        self.request = provider.sign_rpc(self.owner, node=self.node,
            action="provider.get", body=self.request["payload"]["body"], now=self.now,
            request_id="synthetic_later_transaction")
        with self.assertRaisesRegex(MemoryError, "network_control_expired"):
            self.observe(expired)
        current = self.signed(2)
        self.db.execute("CREATE TRIGGER synthetic_status_failure BEFORE INSERT ON open_provider_status BEGIN SELECT RAISE(ABORT,'synthetic failure'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            self.observe(current)
        self.assertIsNone(self.row())
        self.assertFalse(self.db.in_transaction)


if __name__ == "__main__":
    unittest.main()
