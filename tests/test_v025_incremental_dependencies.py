"""Synthetic v3 dependency/frontier cases, authored but not executed here.

All state and keys are created only inside TemporaryDirectory when a maintainer
explicitly runs a selected case. No provider, native host, installed plugin or
real Vault is selected. Artificial bounds and injected exceptions are functional
cases, not throughput, power-loss or platform certification.
"""
from __future__ import annotations

import contextlib
import importlib.util
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest import mock

from memory_vault import MemoryError, Vault
import memory_vault_dependency as dependency
from memory_vault_privacy import assert_publishable
import memory_vault_transfer as transfer
from memory_vault_transfer import DirectoryTransfer, _read, _write
from memory_vault_trust import Identity, TrustStore


@unittest.skipUnless(os.name == "posix" and importlib.util.find_spec("cryptography") is not None,
                     "synthetic signed fixtures require POSIX and cryptography")
class IncrementalDependencyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="memory-v025-incremental-synthetic-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.control = self.root / "control"
        self.control.mkdir(mode=0o700)
        self.identity_path = self.control / "identity.json"
        self.identity = Identity.generate(self.identity_path)
        self.trust_path = self.control / "trust.json"
        self.trust = TrustStore(self.trust_path)
        self.trust.add(self.identity.public_descriptor(), "synthetic publisher")
        self.path = self.root / "source.sqlite3"
        self.vault = Vault(self.path, signer=self.identity.sign_record, trust_check=self.trust.require_trusted)
        self.exchange = self.root / "exchange"
        self.sender = DirectoryTransfer(vault=self.path, exchange=self.exchange, state_directory=self.root / "send",
                                        trust_store=self.trust_path, identity=self.identity_path)
        self.receiver = DirectoryTransfer(vault=self.root / "destination.sqlite3", exchange=self.exchange,
                                          state_directory=self.root / "receive", trust_store=self.trust_path)

    def remember(self, text: str, target: str | None = None, *, vault: Vault | None = None) -> str:
        request = {"op": "remember", "kind": "continuity" if target else "fact", "text": text}
        if target is not None:
            request["relations"] = [{"type": "continues", "target": target}]
        response = (vault or self.vault).handle(request)
        self.assertTrue(response["ok"], response)
        return response["result"]["memory_id"]

    def latest(self) -> dict:
        state = self.sender._state()
        directory = self.exchange / self.identity.key_id / state["vault_store_id"]
        path = next(path for path in directory.iterdir() if path.name.endswith("-" + state["last_published"] + ".json"))
        return dict(_read(path))

    def receive(self, capsule: dict) -> dict:
        payload = capsule["payload"]
        return dict(self.receiver.receive_capsule(capsule, sender_key_id=payload["sender_key_id"],
                                                  source_store_id=payload["source_store_id"], after=payload["after"],
                                                  fragment_loader=lambda group, fragment: transfer._read_fragment(
                                                      self.exchange / payload["sender_key_id"] / payload["source_store_id"]
                                                      / "groups" / group["group_id"] / transfer._fragment_name(fragment))))

    def count(self) -> int:
        with contextlib.closing(sqlite3.connect(self.receiver.vault_path)) as connection:
            return int(connection.execute("SELECT COUNT(*) FROM memories").fetchone()[0])

    def assert_error(self, code: str, function, *args, **kwargs) -> None:
        with self.assertRaises(MemoryError) as caught:
            function(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def independent_grandparent(self) -> tuple[str, str, Identity]:
        author = Identity.generate(self.control / "ancestor-author.json")
        self.trust.add(author.public_descriptor(), "synthetic ancestor author")
        authored = Vault(self.path, signer=author.sign_record, trust_check=self.trust.require_trusted)
        grandparent = self.remember("Synthetic separately signed ancestor", vault=authored)
        parent = self.remember("Synthetic trusted parent", grandparent)
        self.sender.publish(limit=2)
        self.receive(self.latest())
        return grandparent, parent, author

    def test_continues_pages_reuse_verified_prefix_and_cold_receiver_replays_all(self) -> None:
        tail = None
        for index in range(32):
            tail = self.remember("Synthetic continuation " + str(index), tail)
        capsules = []
        for _ in range(4):
            self.sender.publish(limit=8)
            capsules.append(self.latest())
        self.assertEqual(capsules[0]["payload"]["schema_version"], transfer.CHAINED_DELTA_SCHEMA)
        for capsule in capsules[1:]:
            self.assertEqual(capsule["payload"]["schema_version"], transfer.INCREMENTAL_DELTA_SCHEMA)
            self.assertEqual(capsule["payload"]["dependency_mode"], "prior_stream")
            self.assertEqual(len(capsule["payload"]["records"]), 8)
        public = self.vault.handle({"op": "changes", "after": 8, "limit": 8})
        self.assertTrue(public["ok"], public)
        self.assertTrue(public["result"]["dependency_closure_included"])
        self.assertEqual(len(public["result"]["records"]), 16)
        self.assertEqual(self.receiver.receive(maximum_batches=16)["records_added"], 32)
        self.assertEqual(self.count(), 32)
        # Requeue remains a delivery root; published membership cannot drop it.
        self.vault.requeue_records([tail])
        self.sender.publish(limit=8)
        self.assertEqual([record["memory_id"] for record in self.latest()["payload"]["records"]], [tail])
        self.assertEqual(self.receiver.receive()["records_added"], 0)
        self.assertEqual(self.count(), 32)

    def test_unbacked_cursor_does_not_create_a_published_member_boundary(self) -> None:
        ancestor = self.remember("Synthetic unpublished ancestor")
        self.remember("Synthetic child with an unbacked cursor", ancestor)
        store = self.vault.handle({"op": "status"})["result"]["store_id"]
        result = dependency.incremental_changes(self.vault, self.trust, self.sender._dependency_index(),
                                                sender_key_id=self.identity.key_id, store_id=store, after=1,
                                                previous_digest="a" * 64, limit=1)
        self.assertTrue(result["dependency_closure_included"])
        self.assertEqual(len(result["records"]), 2)
        self.assertEqual(result["external_dependency_count"], 0)

    def test_copied_head_without_same_vault_atomic_receipt_cannot_admit_v3(self) -> None:
        ancestor = self.remember("Synthetic baseline for copied head")
        self.sender.publish(limit=1)
        base = self.latest()
        child = self.remember("Synthetic child for copied head", ancestor)
        self.sender.publish(limit=1)
        following = self.latest()
        self.assertEqual(following["payload"]["schema_version"], transfer.INCREMENTAL_DELTA_SCHEMA)
        # Actual baseline bytes exist, but an arbitrary copied head is not an
        # atomic transfer receipt from this receiving Vault.
        self.receiver.vault.ingest_records(base["payload"]["records"], admission="verified",
                                           attestations=base["payload"]["attestations"])
        state = self.receiver._state()
        self.receiver._bind_vault(state, missing_ok=False)
        digest = transfer.sha256(transfer.canonical_bytes(base["payload"]))
        self.receiver._remember_head(state, base["payload"], digest)
        self.receiver._received_evidence(base, digest)
        _write(self.receiver.state_path, state, replace=False)
        self.assert_error("dependency_base_receipt_missing", self.receive, following)
        self.assertEqual(self.count(), 1)
        self.assertFalse(self.receiver.vault.handle({"op": "get", "memory_id": child})["ok"])
        self.assertEqual(self.receiver._state(), state)

    def test_older_sql_writer_quarantine_invalidates_the_grandparent_certificate(self) -> None:
        grandparent, parent, _author = self.independent_grandparent()
        child = self.remember("Synthetic child after cached closure", parent)
        self.sender.publish(limit=1)
        capsule = self.latest()
        state = self.receiver._state()
        with contextlib.closing(sqlite3.connect(self.receiver.vault_path)) as connection, connection:
            connection.execute("UPDATE record_admissions SET state='quarantined' WHERE memory_id=?", (grandparent,))
        self.assert_error("dependency_not_admitted", self.receive, capsule)
        self.assertEqual(self.count(), 2)
        self.assertFalse(self.receiver.vault.handle({"op": "get", "memory_id": child})["ok"])
        self.assertEqual(self.receiver._state(), state)

    def test_revoked_grandparent_is_rechecked_despite_trusted_parent_and_envelope(self) -> None:
        _grandparent, parent, author = self.independent_grandparent()
        self.remember("Synthetic child before ancestor revocation", parent)
        self.sender.publish(limit=1)
        capsule = self.latest()
        self.trust.revoke(author.key_id)
        self.assert_error("dependency_not_admitted", self.receive, capsule)
        self.assertEqual(self.count(), 2)

    def test_operator_excluded_record_is_never_a_published_dependency(self) -> None:
        ancestor = self.remember("Synthetic private path /home/synthetic/private-reference.txt")

        def guard(payload):
            assert_publishable(self.sender.records_for_payload(payload)[0])

        self.assert_error("publication_local_path_detected", self.sender.publish, capsule_guard=guard)
        pending = _read(self.sender.pending_path, private=True)
        self.sender.resolve_pending(batch_sha256=transfer.sha256(transfer.canonical_bytes(pending["payload"])),
                                    request_id="req_incremental_exclude_01", exclude=[ancestor], keep=[])
        self.sender.publish(capsule_guard=guard)
        self.remember("Synthetic dependent cannot bypass exclusion", ancestor)
        self.assert_error("publication_local_path_detected", self.sender.publish, capsule_guard=guard)
        pending = _read(self.sender.pending_path, private=True)
        self.assertEqual(pending["payload"]["schema_version"], transfer.CHAINED_DELTA_SCHEMA)
        self.assertIn(ancestor, {record["memory_id"] for record in pending["payload"]["records"]})

    def test_publication_index_ahead_of_state_recovers_exact_frozen_batch(self) -> None:
        ancestor = self.remember("Synthetic publication crash baseline")
        original = transfer._write

        def fail_state(path, value, **keywords):
            if path == self.sender.state_path and value.get("published_cursor", 0):
                raise OSError("synthetic after index commit before state")
            return original(path, value, **keywords)

        with mock.patch.object(transfer, "_write", side_effect=fail_state):
            with self.assertRaises(OSError):
                self.sender.publish(limit=1)
        frozen = self.sender.pending_path.read_bytes()
        self.sender.publish(limit=1)
        self.assertEqual(transfer.canonical_bytes(self.latest()) + b"\n", frozen)
        self.remember("Synthetic post-recovery continuation", ancestor)
        self.sender.publish(limit=1)
        self.assertEqual(self.latest()["payload"]["schema_version"], transfer.INCREMENTAL_DELTA_SCHEMA)
        self.assertEqual(self.receiver.receive()["records_added"], 2)

    def test_committed_receive_before_head_write_replays_without_re_admission(self) -> None:
        ancestor = self.remember("Synthetic receive crash baseline")
        self.sender.publish(limit=1)
        capsule = self.latest()
        original = transfer._write

        def fail_state(path, value, **keywords):
            if path == self.receiver.state_path:
                raise OSError("synthetic after atomic receipt before head")
            return original(path, value, **keywords)

        with mock.patch.object(transfer, "_write", side_effect=fail_state):
            with self.assertRaises(OSError):
                self.receive(capsule)
        self.assertEqual(self.count(), 1)
        result = self.receive(capsule)
        self.assertTrue(result["receipt_replayed"])
        self.assertEqual(result["records_added"], 0)
        self.remember("Synthetic child after receiver replay", ancestor)
        self.sender.publish(limit=1)
        self.assertEqual(self.receive(self.latest())["records_added"], 1)

    def test_epoch_change_exhaustion_is_explicit_and_never_a_signed_size_skip(self) -> None:
        ancestor = self.remember("Synthetic bounded ancestor")
        tail = self.remember("Synthetic bounded parent", ancestor)
        tail = self.remember("Synthetic bounded tail", tail)
        self.sender.publish(limit=3)
        tail = self.remember("Synthetic cached frontier child", tail)
        with mock.patch.object(dependency, "MAX_BUNDLE_RECORDS", 2):
            self.sender.publish(limit=1)
        self.assertEqual(self.latest()["payload"]["schema_version"], transfer.INCREMENTAL_DELTA_SCHEMA)
        self.remember("Synthetic requires revalidation", tail)
        before = self.sender._state()
        # Even an older writer's harmless UPDATE conservatively invalidates the
        # epoch; it cannot bypass the trigger by omitting a Python API call.
        with contextlib.closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute("UPDATE record_admissions SET state=state WHERE memory_id=?", (ancestor,))
        with mock.patch.object(dependency, "MAX_BUNDLE_RECORDS", 2):
            self.assert_error("dependency_revalidation_required", self.sender.publish, limit=1)
        self.assertEqual(self.sender._state(), before)
        self.assertFalse(self.sender.pending_path.exists())

    def test_shared_read_budget_returns_complete_prefix_without_skipping_next_root(self) -> None:
        identifiers = [self.remember("Synthetic independently bounded body " + str(number) + " " + "z" * 1024)
                       for number in range(3)]
        records = [self.vault.handle({"op": "get", "memory_id": identifier})["result"]["record"]
                   for identifier in identifiers]
        budget = sum(len(transfer.canonical_bytes(record)) for record in records[:2])
        with mock.patch.object(dependency, "MAX_BUNDLE_BYTES", budget):
            first = self.sender.publish(limit=3)
            self.assertEqual(first["records"], 2)
            self.assertEqual(first["cursor"], 2)
            self.assertEqual(first["blocked"], [])
            self.assertEqual({record["memory_id"] for record in self.latest()["payload"]["records"]},
                             set(identifiers[:2]))
            second = self.sender.publish(limit=3)
            self.assertEqual(second["records"], 1)
            self.assertEqual(second["cursor"], 3)
            self.assertEqual(second["blocked"], [])
            self.assertEqual(self.latest()["payload"]["records"][0]["memory_id"], identifiers[2])
        self.assertEqual(self.receiver.receive()["records_added"], 3)
        self.assertEqual(self.count(), 3)

    def test_fragmented_v3_batch_keeps_atomic_dependency_admission(self) -> None:
        tail = None
        for number in range(3):
            tail = self.remember("Synthetic group " + str(number) + " " + "x" * 5120, tail)
        # Artificial inline threshold exercises the real fragment/group path
        # with small isolated data, not a large-file performance claim.
        with mock.patch.object(transfer, "MAX_CAPSULE_BYTES", 8192):
            self.sender.publish(limit=3)
            self.assertIsNotNone(self.latest()["payload"]["group"])
            self.assertEqual(self.receive(self.latest())["records_added"], 3)
            self.remember("Synthetic grouped continuation " + "y" * 5120, tail)
            self.sender.publish(limit=1)
            capsule = self.latest()
            self.assertEqual(capsule["payload"]["schema_version"], transfer.INCREMENTAL_DELTA_SCHEMA)
            self.assertEqual(capsule["payload"]["group"]["record_count"], 1)
            state = self.receiver._state()
            with mock.patch.object(self.receiver, "stage_group_fragments", return_value=False):
                pending = self.receive(capsule)
            self.assertEqual(pending["state"], "group_receiving_pending")
            self.assertEqual(self.count(), 3)
            self.assertEqual(self.receiver._state(), state)
            self.assertEqual(self.receive(capsule)["records_added"], 1)
            self.assertEqual(self.count(), 4)


if __name__ == "__main__":
    unittest.main()
