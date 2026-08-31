"""Synthetic operator-review, chained-sync and atomic-group contracts.

Initially authored without execution; selected methods now have source-pinned
results in docs/VALIDATION.md. Other methods remain unrun unless recorded there.
Fixtures create their own temporary keys/stores only when explicitly executed;
they must not use a real Vault or unapproved provider.
"""
from __future__ import annotations

import contextlib
import importlib.util
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from memory_vault import MemoryError, Vault, canonical_bytes, sha256
from memory_vault_privacy import assert_publishable, review_records
import memory_vault_sync as sync
from memory_vault_sync import CONFIG_SCHEMA, DEFAULT_LIMITS, SyncConfig, _push_pending, receive, requeue
from memory_vault_transfer import CHAINED_DELTA_SCHEMA, MAX_REVIEW_DOCUMENT, DirectoryTransfer, _fragment_name, _read, _write
from memory_vault_trust import Identity, TrustStore


class PublicationScanCompatibilityTests(unittest.TestCase):
    def test_legacy_content_scan_does_not_require_canonical_record_fields(self) -> None:
        assert_publishable([{"text": "Synthetic shareable legacy observation"}])
        with self.assertRaises(MemoryError) as captured:
            assert_publishable([{"text": "Synthetic path /home/synthetic/legacy-note.txt"}])
        self.assertEqual(captured.exception.code, "publication_local_path_detected")

    def test_content_only_scan_still_rejects_secrets_even_with_path_override(self) -> None:
        with self.assertRaises(MemoryError) as captured:
            assert_publishable([{"text": "Synthetic fixture only: ghp_" + "x" * 30}], allow_local_paths=True)
        self.assertEqual(captured.exception.code, "publication_secret_detected")

    def test_review_and_per_record_approval_still_require_immutable_identity(self) -> None:
        with self.assertRaises(MemoryError) as captured:
            review_records([{"text": "Synthetic clean text without an identity"}])
        self.assertEqual(captured.exception.code, "publication_invalid_record_identity")
        fake_id = "mem_" + "a" * 40
        with self.assertRaises(MemoryError) as captured:
            assert_publishable([{"text": "Synthetic path /home/synthetic/reference.txt", "memory_id": fake_id,
                                 "record_sha256": "b" * 64}], approved_local_path_ids=[fake_id])
        self.assertEqual(captured.exception.code, "publication_invalid_record_identity")


@unittest.skipUnless(os.name == "posix" and importlib.util.find_spec("cryptography") is not None,
                     "protected signed fixtures require POSIX and cryptography")
class SyncReviewTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="memory-vault-v025-synthetic-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.control = self.root / "control"
        self.control.mkdir(mode=0o700)
        self.identity_path = self.control / "sender.json"
        self.identity = Identity.generate(self.identity_path)
        self.trust_path = self.control / "trust.json"
        self.trust = TrustStore(self.trust_path)
        self.trust.add(self.identity.public_descriptor(), "synthetic sender")
        self.database = self.root / "sender.sqlite3"
        self.vault = Vault(self.database, signer=self.identity.sign_record, trust_check=self.trust.require_trusted)
        self.exchange = self.root / "exchange"
        self.sender = DirectoryTransfer(vault=self.database, exchange=self.exchange, state_directory=self.root / "send",
                                        trust_store=self.trust_path, identity=self.identity_path)
        self.receiver = DirectoryTransfer(vault=self.root / "receiver.sqlite3", exchange=self.exchange,
                                          state_directory=self.root / "receive", trust_store=self.trust_path)

    def remember(self, text: str, *, target: str | None = None) -> str:
        value = {"op": "remember", "kind": "fact", "text": text}
        if target is not None:
            value["relations"] = [{"type": "derived_from", "target": target}]
        response = self.vault.handle(value)
        self.assertTrue(response["ok"], response)
        return response["result"]["memory_id"]

    def guard(self, payload: dict) -> None:
        records, _ = self.sender.records_for_payload(payload)
        assert_publishable(records, approved_local_path_ids=self.sender.local_path_approvals(payload))

    def publish(self, **arguments: object) -> dict:
        return dict(self.sender.publish(capsule_guard=self.guard, **arguments))

    def pending_hash(self) -> str:
        return sha256(canonical_bytes(_read(self.sender.pending_path, private=True)["payload"]))

    def assert_error(self, code: str, action, *args, **kwargs) -> None:
        with self.assertRaises(MemoryError) as captured:
            action(*args, **kwargs)
        self.assertEqual(captured.exception.code, code)

    def test_review_is_content_free_read_only_and_does_not_load_private_key(self) -> None:
        identifier = self.remember("Synthetic private path /home/synthetic/project-notes.txt")
        self.assert_error("publication_local_path_detected", self.publish)
        before = {str(path.relative_to(self.root)): path.read_bytes() for path in self.root.rglob("*") if path.is_file()}
        with mock.patch.object(Identity, "load", side_effect=AssertionError("read-only review loaded an identity")):
            reader = DirectoryTransfer(vault=self.database, exchange=self.exchange, state_directory=self.root / "send", trust_store=self.trust_path)
            result = reader.review_pending()
        after = {str(path.relative_to(self.root)): path.read_bytes() for path in self.root.rglob("*") if path.is_file()}
        self.assertEqual(before, after)
        self.assertEqual(result["records"][0]["memory_id"], identifier)
        self.assertIn("publication_local_path_detected", result["records"][0]["reasons"])
        self.assertNotIn("/home/synthetic", canonical_bytes(result).decode())
        self.assertFalse(result["files_written"])

    def test_received_capsule_survives_failed_admission_as_evidence_not_a_cursor(self) -> None:
        self.remember("Synthetic authenticated recovery evidence")
        published = self.publish()
        state = self.sender._state()
        path = self.exchange / self.identity.key_id / state["vault_store_id"] / (
            f"{0:020d}-{published['cursor']:020d}-{published['batch_sha256']}.json")
        capsule = _read(path)
        arguments = {"sender_key_id": self.identity.key_id, "source_store_id": state["vault_store_id"], "after": 0}
        with mock.patch.object(self.receiver, "_admit_payload", side_effect=MemoryError("synthetic_admission_failure")):
            self.assert_error("synthetic_admission_failure", self.receiver.receive_capsule, capsule, **arguments)
        evidence = self.receiver.state_directory / "received-capsules" / (published["batch_sha256"] + ".json")
        self.assertEqual(_read(evidence, private=True), capsule)
        self.assertFalse(self.receiver.state_path.exists())
        received = self.receiver.receive_capsule(capsule, **arguments)
        self.assertEqual(received["records_added"], 1)
        self.assertEqual(_read(evidence, private=True), capsule)

    def test_explicit_exclusion_retains_memory_and_publishes_signed_disposition(self) -> None:
        private_id = self.remember("Synthetic reference /home/synthetic/private-note.txt")
        public_id = self.remember("Synthetic shareable fact")
        self.assert_error("publication_local_path_detected", self.publish)
        old_hash = self.pending_hash()
        result = self.sender.resolve_pending(batch_sha256=old_hash, request_id="req_review_exclude_01",
                                             exclude=[private_id], keep=[public_id])
        self.assertFalse(result["canonical_memory_changed"])
        self.assertTrue(self.vault.handle({"op": "get", "memory_id": private_id})["ok"])
        capsule = _read(self.sender.pending_path, private=True)
        self.assertEqual(capsule["payload"]["schema_version"], CHAINED_DELTA_SCHEMA)
        self.assertEqual(capsule["payload"]["blocked"][0]["reason"], "operator_excluded")
        replay = self.sender.resolve_pending(batch_sha256=old_hash, request_id="req_review_exclude_01",
                                             exclude=[private_id], keep=[public_id])
        self.assertTrue(replay["receipt_replayed"])
        self.assert_error("request_id_conflict", self.sender.resolve_pending, batch_sha256=old_hash,
                          request_id="req_review_exclude_01", exclude=[], keep=[private_id, public_id], allow_local_paths=True)
        self.publish()
        received = self.receiver.receive()
        self.assertEqual(received["records_added"], 1)
        self.assertEqual(received["sender_blocked_records"], 1)
        self.assertFalse(self.receiver.vault.handle({"op": "get", "memory_id": private_id})["ok"])

    def test_retaining_local_path_needs_local_operator_journal_and_secrets_cannot_override(self) -> None:
        identifier = self.remember("Synthetic location /home/synthetic/approved-reference.txt")
        self.assert_error("publication_local_path_detected", self.publish)
        batch = self.pending_hash()
        self.assert_error("publication_local_path_detected", self.sender.resolve_pending,
                          batch_sha256=batch, request_id="req_review_keep_path_01", exclude=[], keep=[identifier])
        self.sender.resolve_pending(batch_sha256=batch, request_id="req_review_keep_path_01", exclude=[], keep=[identifier], allow_local_paths=True)
        self.publish()
        self.assertEqual(self.receiver.receive()["records_added"], 1)
        secret = self.remember("Synthetic fixture only: ghp_" + "x" * 30)
        self.assert_error("publication_secret_detected", self.publish)
        self.assert_error("publication_secret_detected", self.sender.resolve_pending,
                          batch_sha256=self.pending_hash(), request_id="req_no_secret_override_01", exclude=[], keep=[secret], allow_local_paths=True)

    def test_dependency_cannot_be_implicitly_removed(self) -> None:
        parent = self.remember("Synthetic source /home/synthetic/record.txt")
        child = self.remember("Synthetic dependent decision", target=parent)
        self.assert_error("publication_local_path_detected", self.publish)
        self.assert_error("review_dependency_selection_conflict", self.sender.resolve_pending,
                          batch_sha256=self.pending_hash(), request_id="req_dependency_review_01", exclude=[parent], keep=[child])

    def test_interrupted_review_replays_without_different_signed_bytes(self) -> None:
        identifier = self.remember("Synthetic source /home/synthetic/review-crash.txt")
        self.assert_error("publication_local_path_detected", self.publish)
        old_hash = self.pending_hash()
        import memory_vault_transfer as transfer
        original_write = transfer._write

        def crash_completion(path, value, **keywords):
            if path.name == "completed.json":
                raise OSError("synthetic power loss before review completion")
            return original_write(path, value, **keywords)

        with mock.patch.object(transfer, "_write", side_effect=crash_completion):
            with self.assertRaises(OSError):
                self.sender.resolve_pending(batch_sha256=old_hash, request_id="req_review_crash_0001", exclude=[identifier], keep=[])
        replacement = self.sender.pending_path.read_bytes()
        self.assert_error("publication_review_incomplete", self.publish)
        completed = self.sender.resolve_pending(batch_sha256=old_hash, request_id="req_review_crash_0001", exclude=[identifier], keep=[])
        self.assertEqual(replacement, self.sender.pending_path.read_bytes())
        self.assertFalse(completed["receipt_replayed"])
        self.publish()

    def test_started_publication_is_not_rewritten_even_if_output_disappears(self) -> None:
        identifier = self.remember("Synthetic source /home/synthetic/unpublished.txt")
        self.assert_error("publication_local_path_detected", self.publish)
        capsule = _read(self.sender.pending_path, private=True)
        batch = self.pending_hash()
        _write(self.sender.started_path, {"batch_sha256": batch, "cursor": capsule["payload"]["cursor"]}, replace=False)
        self.assert_error("review_publication_already_started", self.sender.resolve_pending,
                          batch_sha256=batch, request_id="req_started_review_0001", exclude=[identifier], keep=[])

    def test_hash_chain_checks_prior_head_and_refuses_missing_history(self) -> None:
        self.remember("Synthetic first fact")
        first = self.publish()
        self.receiver.receive()
        self.remember("Synthetic second fact")
        self.publish()
        self.assertEqual(self.receiver.receive()["records_added"], 1)
        peer, head = next(iter(self.receiver._state()["received_heads"].items()))
        path = self.exchange.joinpath(*peer.split("/"), f"{head['after']:020d}-{head['cursor']:020d}-{head['batch_sha256']}.json")
        # Fixture removal simulates an untrusted provider losing its last head.
        path.unlink()
        report = self.receiver.receive()
        self.assertEqual(report["rejected"][0]["code"], "remote_history_missing_or_changed")
        self.assertNotEqual(first["batch_sha256"], head["batch_sha256"])

    def test_large_closed_group_is_resumable_and_never_partially_admitted(self) -> None:
        parent = None
        for ordinal in range(6):
            parent = self.remember(f"Synthetic large record {ordinal}: " + "z" * (850 * 1024), target=parent)
        first = self.publish(maximum_bytes=4096, maximum_fragments=1)
        self.assertEqual(first["state"], "group_publication_pending")
        self.assertEqual(self.sender._state()["published_cursor"], 0)
        second = self.publish(maximum_bytes=4096, maximum_fragments=1)
        self.assertEqual(second["state"], "published")
        self.assertEqual(second["records"], 6)
        initial = self.receiver.receive(maximum_fragments=1)
        self.assertEqual(initial["records_added"], 0)
        self.assertEqual(initial["groups_pending"], 1)
        self.assertFalse(self.receiver.vault_path.exists())
        final = self.receiver.receive(maximum_fragments=1)
        self.assertEqual(final["records_added"], 6)
        self.assertEqual(self.receiver.receive()["records_added"], 0)

    def test_corrupted_fragment_does_not_admit_any_record(self) -> None:
        for ordinal in range(6):
            self.remember(f"Synthetic corruption fixture {ordinal}: " + "q" * (850 * 1024))
        self.publish(maximum_bytes=4096)
        state = self.sender._state()
        manifest = self.exchange / self.identity.key_id / state["vault_store_id"] / f"{0:020d}-{state['published_cursor']:020d}-{state['last_published']}.json"
        group = _read(manifest)["payload"]["group"]
        fragment = manifest.parent / "groups" / group["group_id"] / _fragment_name(group["fragments"][0])
        original = fragment.read_bytes()
        fragment.write_bytes(b"!" + original[1:])
        report = self.receiver.receive()
        self.assertEqual(report["rejected"][0]["code"], "group_fragment_hash_mismatch")
        self.assertFalse(self.receiver.vault_path.exists())

    def test_atomic_group_receipt_recovers_cursor_write_crash_and_direct_replay(self) -> None:
        for ordinal in range(6):
            self.remember(f"Synthetic atomic receipt fixture {ordinal}: " + "a" * (850 * 1024))
        self.publish(maximum_bytes=4096)
        state = self.sender._state()
        manifest = self.exchange / self.identity.key_id / state["vault_store_id"] / f"{0:020d}-{state['published_cursor']:020d}-{state['last_published']}.json"
        import memory_vault_transfer as transfer
        original_write = transfer._write

        def crash_cursor(path, value, **keywords):
            if path == self.receiver.state_path:
                raise OSError("synthetic crash after atomic Vault admission")
            return original_write(path, value, **keywords)

        with mock.patch.object(transfer, "_write", side_effect=crash_cursor):
            with self.assertRaises(OSError):
                self.receiver.receive()
        self.assertEqual(self.receiver.vault.handle({"op": "status"})["result"]["records"], 6)
        resumed = self.receiver.receive()
        self.assertEqual(resumed["records_added"], 0)
        self.assertEqual(resumed["receipt_replays"], 1)
        with mock.patch.object(DirectoryTransfer, "stage_group_fragments", side_effect=AssertionError("committed replay fetched fragments")):
            replay = self.receiver.receive_capsule(_read(manifest), sender_key_id=self.identity.key_id,
                                                    source_store_id=state["vault_store_id"], after=0)
        self.assertTrue(replay["receipt_replayed"])
        self.assertEqual(replay["records_added"], 0)

    def test_review_selection_supports_a_full_hundred_thousand_record_group(self) -> None:
        identifiers = [f"mem_{ordinal:040x}" for ordinal in range(100_000)]
        self.assertEqual(len(DirectoryTransfer._review_ids(identifiers)), 100_000)
        # Complete IDs stay private; the public review holds only a digest and
        # counts, so a valid full-size selection never exceeds capsule limits.
        private_selection = {"batch_sha256": "a" * 64, "request_id": "req_full_selection_0001",
                             "exclude": [], "keep": identifiers, "allow_local_paths": False}
        self.assertLess(len(canonical_bytes(private_selection)), MAX_REVIEW_DOCUMENT)
        self.assert_error("invalid_review_record_ids", DirectoryTransfer._review_ids, identifiers + [identifiers[0]])

    def test_authenticated_fork_is_not_chosen_by_filename(self) -> None:
        self.remember("Synthetic fork fixture")
        published = self.publish()
        state = self.sender._state()
        directory = self.exchange / self.identity.key_id / state["vault_store_id"]
        original = _read(directory / f"{0:020d}-{state['published_cursor']:020d}-{published['batch_sha256']}.json")
        fork_payload = {**original["payload"], "cursor": state["published_cursor"] + 1}
        fork_hash = sha256(canonical_bytes(fork_payload))
        _write(directory / f"{0:020d}-{fork_payload['cursor']:020d}-{fork_hash}.json",
               {"payload": fork_payload, "proof": self.identity.sign_message(fork_payload)}, replace=False)
        report = self.receiver.receive()
        self.assertEqual(report["rejected"][0]["code"], "authenticated_stream_fork")
        self.assertFalse(self.receiver.vault_path.exists())

    def sync_config(self, *, remote: bool = False) -> Path:
        path = self.control / ("remote-sync.json" if remote else "sync.json")
        backend = ({"kind": "rclone", "executable": str(self.root / "synthetic-rclone"), "executable_sha256": "a" * 64,
                    "config_file": str(self.control / "rclone.ini"), "remote": "synthetic:memory", "peers": []}
                   if remote else {"kind": "directory", "exchange": str(self.exchange)})
        document = {"schema_version": CONFIG_SCHEMA, "vault": str(self.database), "identity": str(self.identity_path),
                    "trust_store": str(self.trust_path), "state_directory": str(self.root / "sync-state"),
                    "enabled": True, "automatic": False, "background": False, "backend": backend, "limits": dict(DEFAULT_LIMITS)}
        _write(path, document, replace=False)
        return path

    def test_explicit_receive_does_not_publish_and_requeue_is_idempotent(self) -> None:
        identifier = self.remember("Synthetic local-only fact")
        self.exchange.mkdir(mode=0o700)
        config = self.sync_config()
        with mock.patch.object(DirectoryTransfer, "publish", side_effect=AssertionError("receive-only uploaded")), \
                mock.patch.object(Identity, "load", side_effect=AssertionError("receive-only loaded a private key")):
            result = receive(config)
        self.assertFalse(result["outbound_attempted"])
        requeue(config, identifiers=[identifier], request_id="req_delivery_retry_0001")
        with contextlib.closing(sqlite3.connect(self.database)) as connection:
            before = connection.execute("SELECT COUNT(*) FROM delivery_log").fetchone()[0]
        requeue(config, identifiers=[identifier], request_id="req_delivery_retry_0001")
        with contextlib.closing(sqlite3.connect(self.database)) as connection:
            after = connection.execute("SELECT COUNT(*) FROM delivery_log").fetchone()[0]
        self.assertEqual(before, after)

    def test_signed_sync_review_requeue_and_receive_remain_independent(self) -> None:
        """One real signed directory workflow, not a signature/review mock.

        Two fresh fixture identities and independent trust files are explicitly
        enrolled in this TemporaryDirectory. Both clients disable automatic and
        background work. One guard refuses private-key loading during actual
        read-only review. A later wrapper injects a before-read budget failure
        after real admission; it does not simulate elapsed time. Neither mock
        supplies a signature, policy decision or receive result.
        """
        sender_config = self.sync_config()
        receiver_identity_path = self.control / "workflow-receiver.json"
        receiver_identity = Identity.generate(receiver_identity_path)
        receiver_trust_path = self.control / "workflow-receiver-trust.json"
        receiver_trust = TrustStore(receiver_trust_path)
        receiver_trust.add(self.identity.public_descriptor(), "explicit synthetic sender")
        receiver_trust.add(receiver_identity.public_descriptor(), "explicit synthetic receiver")
        self.trust.add(receiver_identity.public_descriptor(), "explicit synthetic peer")
        receiver_config = self.control / "workflow-receiver-sync.json"
        receiver_database = self.root / "workflow-receiver.sqlite3"
        receiver_state = self.root / "workflow-receiver-state"
        _write(receiver_config, {
            "schema_version": CONFIG_SCHEMA, "vault": str(receiver_database),
            "identity": str(receiver_identity_path), "trust_store": str(receiver_trust_path),
            "state_directory": str(receiver_state), "enabled": True,
            "automatic": False, "background": False,
            "backend": {"kind": "directory", "exchange": str(self.exchange)},
            "limits": dict(DEFAULT_LIMITS),
        }, replace=False)
        receiver_vault = Vault(receiver_database, signer=receiver_identity.sign_record,
                               trust_check=receiver_trust.require_trusted)

        def record(vault: Vault, memory_id: str) -> dict:
            response = vault.handle({"op": "get", "memory_id": memory_id})
            self.assertTrue(response["ok"], response)
            self.assertFalse(response["authority"]["execution_eligible"])
            self.assertEqual(response["result"]["verification"]["admission"], "verified")
            return dict(response["result"]["record"])

        def delivery_count(path: Path) -> int:
            with contextlib.closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as connection:
                return int(connection.execute("SELECT COUNT(*) FROM delivery_log").fetchone()[0])

        def fixture_hashes() -> dict[str, str]:
            # Hashes, not private fixture-key values, appear in an assertion.
            return {str(path.relative_to(self.root)): sha256(path.read_bytes())
                    for path in self.root.rglob("*") if path.is_file()}

        def verified_capsule(path: Path) -> dict:
            capsule = dict(_read(path, private=True))
            payload = capsule["payload"]
            self.assertEqual(receiver_trust.verify_message(payload, capsule["proof"]), self.identity.key_id)
            self.assertIsNone(payload["group"], "this is a small inline workflow, not a fragment-group trial")
            for item in payload["records"]:
                receiver_trust.verify_record(item, payload["attestations"][item["memory_id"]])
            return capsule

        private_id = self.remember("Synthetic private path /home/synthetic/workflow-note.txt")
        secret_id = self.remember("Synthetic noncredential fixture: ghp_" + "x" * 30)
        kept_id = self.remember("Synthetic shareable workflow fact")
        original = {identifier: record(self.vault, identifier) for identifier in (private_id, secret_id, kept_id)}
        inbound = receiver_vault.handle({"op": "remember", "kind": "fact",
                                         "text": "Synthetic independently signed incoming fact"})
        self.assertTrue(inbound["ok"], inbound)
        inbound_id = inbound["result"]["memory_id"]
        inbound_record = record(receiver_vault, inbound_id)
        initial_peer = sync.flush(receiver_config)
        self.assertIsNone(initial_peer["last_error"])
        self.assertEqual(initial_peer["counts"]["published_batches"], 1)

        blocked = sync.flush(sender_config)
        self.assertEqual(blocked["state"], "retry_pending")
        self.assertIn(blocked["last_error"], {"publication_local_path_detected", "publication_secret_detected"})
        self.assertEqual(blocked["counts"]["published_batches"], 0)
        self.assertEqual(blocked["counts"]["uploaded_batches"], 0)
        self.assertEqual(blocked["counts"]["blocked_records"], 0, "an unexposed review is not a signed disposition")
        self.assertEqual(blocked["counts"]["received_batches"], 1)
        self.assertEqual(blocked["counts"]["records_added"], 1)
        self.assertTrue(blocked["pending"])
        self.assertTrue(blocked["more_work_possible"])
        self.assertFalse(blocked["network_backend"])
        self.assertEqual(record(self.vault, inbound_id), inbound_record)
        sender_state = self.root / "sync-state" / "transfer"
        pending_path = sender_state / "publish.pending.json"
        frozen = pending_path.read_bytes()
        before_review = fixture_hashes()
        with mock.patch.object(Identity, "load", side_effect=AssertionError("read-only review loaded a private key")):
            reviewed = sync.review(sender_config)
        self.assertEqual(fixture_hashes(), before_review)
        self.assertTrue(reviewed["operator_action_required"])
        self.assertFalse(reviewed["files_written"])
        self.assertFalse(reviewed["network_accessed"])
        self.assertFalse(reviewed["memory_content_included"])
        self.assertFalse(reviewed["review_is_authorization"])
        findings = {item["memory_id"]: item for item in reviewed["records"]}
        self.assertEqual(set(findings), {private_id, secret_id, kept_id})
        self.assertIn("publication_local_path_detected", findings[private_id]["reasons"])
        self.assertIn("publication_secret_detected", findings[secret_id]["reasons"])
        self.assertTrue(all(item["signature_state"] == "verified_current_trust" for item in findings.values()))
        self.assertNotIn("/home/synthetic", canonical_bytes(reviewed).decode("utf-8"))
        self.assertNotIn("ghp_" + "x" * 30, canonical_bytes(reviewed).decode("utf-8"))
        self.assertEqual(pending_path.read_bytes(), frozen)
        batch = reviewed["batch_sha256"]
        self.assert_error("review_requires_complete_partition", sync.resolve, sender_config,
                          batch_sha256=batch, request_id="req_workflow_partial_01", exclude=[private_id], keep=[kept_id])
        self.assert_error("publication_secret_detected", sync.resolve, sender_config,
                          batch_sha256=batch, request_id="req_workflow_secret_01", exclude=[private_id],
                          keep=[kept_id, secret_id], allow_local_paths=True)
        self.assert_error("publication_local_path_detected", sync.resolve, sender_config,
                          batch_sha256=batch, request_id="req_workflow_path_01", exclude=[secret_id],
                          keep=[private_id, kept_id])

        request_id = "req_workflow_exclusion_01"
        applied = sync.resolve(sender_config, batch_sha256=batch, request_id=request_id,
                               exclude=[private_id, secret_id], keep=[kept_id])
        self.assertFalse(applied["canonical_memory_changed"])
        self.assertFalse(applied["published"])
        self.assertFalse(applied["worker_started"])
        self.assertFalse(applied["receipt_replayed"])
        replacement = pending_path.read_bytes()
        capsule = verified_capsule(pending_path)
        self.assertNotEqual(replacement, frozen)
        self.assertEqual([item["memory_id"] for item in capsule["payload"]["records"]], [kept_id])
        self.assertEqual({(item["memory_id"], item["reason"]) for item in capsule["payload"]["blocked"]},
                         {(private_id, "operator_excluded"), (secret_id, "operator_excluded")})
        self.assertEqual((sender_state / "publication-reviews" / sha256(request_id.encode("utf-8")) / "original.json").read_bytes(), frozen)
        replayed = sync.resolve(sender_config, batch_sha256=batch, request_id=request_id,
                                exclude=[secret_id, private_id], keep=[kept_id])
        self.assertTrue(replayed["receipt_replayed"])
        self.assertEqual(pending_path.read_bytes(), replacement)
        self.assert_error("request_id_conflict", sync.resolve, sender_config, batch_sha256=batch,
                          request_id=request_id, exclude=[private_id], keep=[kept_id, secret_id], allow_local_paths=True)
        for identifier, expected in original.items():
            self.assertEqual(record(self.vault, identifier), expected)
        published = sync.flush(sender_config)
        self.assertEqual(published["state"], "attention_required")
        self.assertIsNone(published["last_error"])
        self.assertEqual(published["counts"]["blocked_records"], 2)
        self.assertEqual(published["counts"]["published_batches"], 2)  # Kept fact, then the incoming fact's forwarding batch.
        self.assertFalse(pending_path.exists())
        payload = capsule["payload"]
        stream = self.exchange / self.identity.key_id / payload["source_store_id"]
        published_path = stream / f"{payload['after']:020d}-{payload['cursor']:020d}-{applied['replacement_batch_sha256']}.json"
        self.assertEqual(published_path.read_bytes(), replacement)

        received = sync.receive(receiver_config)
        self.assertFalse(received["outbound_attempted"])
        self.assertEqual(received["counts"]["received_batches"], 2)
        self.assertEqual(received["counts"]["records_added"], 1)
        self.assertEqual(received["counts"]["blocked_records"], 2)
        self.assertEqual(record(receiver_vault, kept_id), original[kept_id])
        for identifier in (private_id, secret_id):
            self.assertFalse(receiver_vault.handle({"op": "get", "memory_id": identifier})["ok"])
        before_retry = delivery_count(receiver_database)
        exact_receive = sync.receive(receiver_config)
        self.assertIsNone(exact_receive["last_error"])
        self.assertEqual(exact_receive["counts"]["received_batches"], 0)
        self.assertEqual(exact_receive["counts"]["records_added"], 0)
        self.assertEqual(delivery_count(receiver_database), before_retry)

        before_requeue = delivery_count(self.database)
        requeue_id = "req_workflow_requeue_01"
        queued = sync.requeue(sender_config, identifiers=[private_id], request_id=requeue_id)
        self.assertFalse(queued["worker_started"])
        self.assertFalse(queued["publication_review_reused"])
        self.assertEqual(delivery_count(self.database), before_requeue + 1)
        self.assertEqual(sync.requeue(sender_config, identifiers=[private_id, private_id], request_id=requeue_id), queued)
        self.assertEqual(delivery_count(self.database), before_requeue + 1)
        self.assert_error("request_id_conflict", sync.requeue, sender_config, identifiers=[kept_id], request_id=requeue_id)
        retried = sync.flush(sender_config)
        self.assertEqual(retried["last_error"], "publication_local_path_detected")
        self.assertEqual(retried["counts"]["published_batches"], 0)
        fresh_review = sync.review(sender_config)
        self.assertEqual([item["memory_id"] for item in fresh_review["records"]], [private_id])
        self.assertNotEqual(fresh_review["batch_sha256"], batch)
        approved = sync.resolve(sender_config, batch_sha256=fresh_review["batch_sha256"],
                                request_id="req_workflow_approve_path_01", exclude=[], keep=[private_id], allow_local_paths=True)
        self.assertFalse(approved["worker_started"])
        approved_capsule = verified_capsule(pending_path)
        self.assertEqual(approved_capsule["payload"]["blocked"], [])
        final_publication = sync.flush(sender_config)
        self.assertIsNone(final_publication["last_error"])
        self.assertEqual(final_publication["counts"]["published_batches"], 1)
        final_receive = sync.receive(receiver_config)
        self.assertIsNone(final_receive["last_error"])
        self.assertEqual(final_receive["counts"]["records_added"], 1)
        self.assertEqual(record(receiver_vault, private_id), original[private_id])
        self.assertFalse(receiver_vault.handle({"op": "get", "memory_id": secret_id})["ok"])
        self.assertEqual(record(self.vault, secret_id), original[secret_id])

        # Incoming signed review text is not this receiver's forwarding consent.
        forwarded = sync.flush(receiver_config)
        self.assertEqual(forwarded["last_error"], "publication_local_path_detected")
        self.assertEqual(forwarded["counts"]["published_batches"], 0)
        peer_pending = _read(receiver_state / "transfer" / "publish.pending.json", private=True)
        self.assertIsNone(peer_pending["payload"]["publication_review"])
        self.assertIn(private_id, {item["memory_id"] for item in peer_pending["payload"]["records"]})

        # Two actual signed batches allow a precise failure at the next read,
        # not a mock import or a claim about real clock/throughput exhaustion.
        first_later_id = self.remember("Synthetic first post-review incoming fact")
        first_later = sync.flush(sender_config)
        self.assertIsNone(first_later["last_error"])
        self.assertEqual(first_later["counts"]["published_batches"], 1)
        second_later_id = self.remember("Synthetic second post-review incoming fact")
        second_later = sync.flush(sender_config)
        self.assertIsNone(second_later["last_error"])
        self.assertEqual(second_later["counts"]["published_batches"], 1)
        receiver_pending_path = receiver_state / "transfer" / "publish.pending.json"
        receiver_frozen = receiver_pending_path.read_bytes()
        before_interruption = delivery_count(receiver_database)
        actual_receive = DirectoryTransfer.receive
        durable_progress: list[int] = []
        injected_reads: list[int] = []

        def interrupt_after_admission(endpoint: DirectoryTransfer, **arguments):
            before_read = arguments["before_read"]
            on_progress = arguments["on_progress"]

            def progress(report):
                on_progress(report)
                durable_progress.append(int(report["batches"]))

            def next_read():
                if durable_progress:
                    injected_reads.append(1)
                    raise MemoryError("sync_transfer_budget_exceeded", retryable=True)
                before_read()

            return actual_receive(endpoint, **{**arguments, "before_read": next_read, "on_progress": progress})

        with mock.patch.object(DirectoryTransfer, "receive", new=interrupt_after_admission):
            interrupted = sync.receive(receiver_config)
        self.assertEqual(injected_reads, [1])
        self.assertEqual(durable_progress, [1])
        self.assertEqual(interrupted["state"], "retry_pending")
        self.assertEqual(interrupted["last_error"], "sync_transfer_budget_exceeded")
        self.assertEqual(interrupted["counts"]["received_batches"], 1)
        self.assertEqual(interrupted["counts"]["records_added"], 1)
        self.assertEqual(interrupted["counts"]["receipt_replays"], 0)
        self.assertFalse(interrupted["outbound_attempted"])
        self.assertTrue(interrupted["more_work_possible"])
        self.assertTrue(interrupted["pending"])
        self.assertEqual(record(receiver_vault, first_later_id), record(self.vault, first_later_id))
        self.assertFalse(receiver_vault.handle({"op": "get", "memory_id": second_later_id})["ok"])
        self.assertEqual(delivery_count(receiver_database), before_interruption + 1)
        self.assertEqual(receiver_pending_path.read_bytes(), receiver_frozen)
        resumed = sync.receive(receiver_config)
        self.assertIsNone(resumed["last_error"])
        self.assertEqual(resumed["counts"]["received_batches"], 1)
        self.assertEqual(resumed["counts"]["records_added"], 1)
        self.assertEqual(resumed["counts"]["receipt_replays"], 0)
        self.assertEqual(record(receiver_vault, second_later_id), record(self.vault, second_later_id))
        self.assertEqual(delivery_count(receiver_database), before_interruption + 2)
        self.assertEqual(receiver_pending_path.read_bytes(), receiver_frozen)

    def test_remote_fragment_receipt_survives_interruption_before_manifest(self) -> None:
        for ordinal in range(6):
            self.remember(f"Synthetic remote fixture {ordinal}: " + "r" * (850 * 1024))
        self.publish(maximum_bytes=4096)
        config = SyncConfig.load(self.sync_config(remote=True))

        class FakeRemote:
            def __init__(self):
                self.fragments = []
                self.manifests = []
                self.fail_second_once = True

            def candidates(self, key, store, after):
                return []

            def upload_fragment(self, path, *, fragment, expected, **keywords):
                if fragment["index"] == 1 and self.fail_second_once:
                    self.fail_second_once = False
                    raise MemoryError("remote_timeout", retryable=True)
                self.fragments.append(fragment["index"])

            def upload(self, path, *, expected, **keywords):
                self.manifests.append(expected)

        remote = FakeRemote()
        self.assert_error("remote_timeout", _push_pending, config, self.sender, remote)
        self.assertEqual(remote.fragments, [0])
        self.assertEqual(remote.manifests, [])
        self.assertTrue(_push_pending(config, self.sender, remote))
        self.assertEqual(config.state_directory.stat().st_mode & 0o777, 0o700)
        self.assertEqual(remote.fragments, [0, 1])
        self.assertEqual(len(remote.manifests), 1)
        self.assertFalse(_push_pending(config, self.sender, remote))


if __name__ == "__main__":
    unittest.main()
