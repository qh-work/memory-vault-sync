"""Public synthetic recovery cases; executed evidence is recorded separately.

Only TemporaryDirectory fixtures are used. The fixtures are ordinary permitted
local memory operations, never real account data, installed hooks or a network.
The native Windows ACL/locking profile needs separate platform verification.
"""

from __future__ import annotations

import contextlib
import copy
import importlib.util
import json
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

import memory_vault_compat as compat
import memory_vault_hosts as hosts
import memory_vault_lifecycle as lifecycle
import memory_vault_manage as manage
import memory_vault_recovery as recovery
import memory_vault_storage as storage
from memory_vault import MemoryError, Vault, build_record, canonical_bytes, failure, sha256
from memory_vault_client import CONFIG_SCHEMA, ClientConfig, HookState, _digest


class RecoveryFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="memory-v025-recovery-synthetic-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.control = self.root / "control"
        self.control.mkdir(mode=0o700)
        self.config_path = self.control / "client.json"
        self.vault_path = self.root / "vault.sqlite3"
        self.document = {"schema_version": CONFIG_SCHEMA, "vault_path": str(self.vault_path), "capture_visible_turns": True}
        self.configure()
        result = Vault(self.vault_path).handle({"op": "remember", "kind": "fact", "text": "Synthetic durable baseline.",
                                               "request_id": "req_synthetic_recovery_baseline"})
        self.assertTrue(result["ok"], result)
        self.baseline_id = result["result"]["memory_id"]
        self.backup_path = self.root / "snapshot"
        self.recovered_path = self.root / "recovered"

    def configure(self, **values: object) -> None:
        self.document.update(values)
        storage.atomic_write(self.config_path, canonical_bytes(self.document) + b"\n", replace=self.config_path.exists())

    def config(self) -> ClientConfig:
        return ClientConfig.load(self.config_path)

    def hooks(self, *, conflict: bool = False) -> str:
        key = "a" * 64
        state = HookState(self.config())
        state.once("prompts", key, {"user": "Synthetic visible input."})
        state.once("outbox", key, {"user": "Synthetic visible input.", "assistant": "Synthetic visible final."})
        if conflict:
            state.once("conflicts", key, {"reason": "different_prompts_for_same_turn"})
        return key

    def backup(self, include: tuple[str, ...] = ("hooks",)) -> dict:
        return dict(recovery.backup_client(self.config_path, self.backup_path, include=list(include), quiesced=True))

    def restore(self, include: tuple[str, ...] = ("hooks",), *, accept_unsigned: bool = True) -> dict:
        self.backup(include)
        return dict(recovery.restore_client(self.backup_path, self.recovered_path, accept_unsigned=accept_unsigned))

    def activate(self, include: tuple[str, ...] = ("hooks",), **arguments: object) -> ClientConfig:
        output = self.recovered_path / "resumed-client.json"
        recovery.activate_recovery(self.recovered_path, output, include=list(include), authorize_local_resume=True, **arguments)
        return ClientConfig.load(output)

    def count(self, path: Path) -> int:
        with contextlib.closing(sqlite3.connect(path)) as connection:
            return int(connection.execute("SELECT COUNT(*) FROM memories").fetchone()[0])

    def assert_error(self, code: str, function, *args, **keywords) -> None:
        with self.assertRaises(MemoryError) as caught:
            function(*args, **keywords)
        self.assertEqual(caught.exception.code, code)

    def compat_request(self, operation: str, payload: dict, identifier: str) -> dict:
        return {"schema_version": compat.REQUEST_SCHEMA, "protocol_version": "1.0", "request_id": identifier,
                "operation": operation, "adapter": {"id": "synthetic-recovery", "version": "1.0.0", "host_family": "generic_stdio"},
                "payload": payload}

    def sync_configuration(self, identity_path: Path, trust_path: Path) -> Path:
        from memory_vault_sync import CONFIG_SCHEMA as SYNC_SCHEMA, DEFAULT_LIMITS
        sync_path = self.control / "sync.json"
        state = self.root / "sync-state"
        value = {"schema_version": SYNC_SCHEMA, "vault": str(self.vault_path), "identity": str(identity_path),
                 "trust_store": str(trust_path), "state_directory": str(state), "enabled": True,
                 "automatic": False, "background": False, "backend": {"kind": "directory", "exchange": str(self.root / "exchange")},
                 "limits": dict(DEFAULT_LIMITS)}
        storage.atomic_write(sync_path, canonical_bytes(value) + b"\n", replace=False)
        self.configure(identity_path=str(identity_path), trust_path=str(trust_path), sync_config_path=str(sync_path))
        return state


@unittest.skipUnless(os.name == "posix", "these synthetic file-mode fixtures use POSIX")
class ClientRecoveryTests(RecoveryFixture):
    def test_requires_explicit_quiesced_and_component_selection(self) -> None:
        self.assert_error("offline_quiesced_acknowledgement_required", recovery.backup_client,
                          self.config_path, self.backup_path, include=["hooks"])
        for selected in ([], ["hooks", "hooks"], ["unknown"]):
            self.assert_error("explicit_recovery_components_required", recovery.backup_client,
                              self.config_path, self.backup_path, include=selected, quiesced=True)
        self.assert_error("host_recovery_requires_lifecycle", recovery.backup_client,
                          self.config_path, self.backup_path, include=["hosts"], quiesced=True)
        self.assertFalse(self.backup_path.exists())

    def test_restore_is_inert_and_exact_original_control_evidence_survives(self) -> None:
        key = self.hooks()
        original = HookState(self.config()).path("outbox", key).read_bytes()
        with mock.patch("memory_vault_client.observe_turn", side_effect=AssertionError("must not replay")), \
                mock.patch("memory_vault_client.notify_sync", side_effect=AssertionError("must not start a worker")), \
                mock.patch("memory_vault_trust.Identity.load", side_effect=AssertionError("must not load a key")):
            response = self.restore()
        selected = ClientConfig.load(self.recovered_path / "client.json")
        self.assertFalse(selected.capture_visible_turns)
        self.assertIsNone(selected.identity_path)
        self.assertIsNone(selected.sync_config_path)
        self.assertFalse(selected.state_path.exists())
        self.assertEqual((self.recovered_path / "evidence" / "control" / "hooks" / "outbox" / (key + ".json")).read_bytes(), original)
        self.assertNotEqual(response["memory"]["new_store_id"], json.loads((self.backup_path / "manifest.json").read_text())["source"]["store_id"])
        self.assertEqual(self.count(selected.vault_path), 1)
        self.assertFalse(response["pending_replayed"])
        self.assertFalse(response["network_accessed"])

    def test_explicit_local_activation_then_retry_preserves_no_network_boundary(self) -> None:
        key = self.hooks()
        self.restore()
        selected = self.activate()
        self.assertEqual(self.count(selected.vault_path), 1)
        self.assertIsNone(selected.sync_config_path)
        original = self.recovered_path / "evidence" / "control" / "hooks" / "outbox" / (key + ".json")
        response = manage.retry(selected.path)
        self.assertEqual(response["saved"], 1)
        self.assertFalse(response["background_sync_may_run"])
        self.assertEqual(self.count(selected.vault_path), 3)
        self.assertTrue(HookState(selected).path("done", key).exists())
        self.assertTrue(original.exists())
        self.assertEqual(manage.retry(selected.path)["processed"], 0)

    def test_conflicts_stay_blocked_instead_of_being_silently_replayed(self) -> None:
        key = self.hooks(conflict=True)
        self.restore()
        selected = self.activate()
        result = manage.retry(selected.path)
        self.assertEqual(result["saved"], 0)
        self.assertEqual(result["failed"], 1)
        self.assertTrue(HookState(selected).path("conflicts", key).exists())
        self.assertEqual(self.count(selected.vault_path), 1)

    def test_new_source_directory_during_snapshot_invalidates_outer_manifest(self) -> None:
        self.hooks()
        original = recovery._snapshot
        changed = False

        def snapshot_then_new_prompt(*args, **keywords):
            nonlocal changed
            result = original(*args, **keywords)
            if not changed:
                changed = True
                HookState(self.config()).once("done", "b" * 64, {"not": "a validated active receipt"})
            return result

        with mock.patch.object(recovery, "_snapshot", side_effect=snapshot_then_new_prompt):
            self.assert_error("recovery_source_changed", self.backup)
        self.assertFalse((self.backup_path / "manifest.json").exists())
        self.assertTrue((self.backup_path / "memory" / "manifest.json").exists())

    def test_symlink_in_selected_queue_is_not_followed(self) -> None:
        state = HookState(self.config())
        state.once("prompts", "b" * 64, {"user": "Synthetic staged input"})
        external = self.root / "synthetic-secret.txt"
        external.write_text("synthetic secret that must not be followed", encoding="utf-8")
        external.chmod(0o600)
        state.path("prompts", "c" * 64).symlink_to(external)
        with self.assertRaises((MemoryError, OSError)):
            self.backup()
        self.assertFalse(self.backup_path.exists())

    def test_archive_tampering_or_path_escape_is_rejected_before_restore(self) -> None:
        self.hooks()
        self.backup()
        path = self.backup_path / "manifest.json"
        value = json.loads(path.read_text())
        value["entries"][0]["path"] = "../outside.json"
        storage.atomic_write(path, canonical_bytes(value) + b"\n", replace=True)
        self.assert_error("invalid_client_backup_path", recovery.restore_client, self.backup_path, self.recovered_path)
        self.assertFalse(self.recovered_path.exists())

    def test_changed_control_bytes_fail_hash_check(self) -> None:
        key = self.hooks()
        self.backup()
        path = self.backup_path / "control" / "hooks" / "outbox" / (key + ".json")
        value = json.loads(path.read_text())
        value["assistant"] = "Changed synthetic data after backup"
        storage.atomic_write(path, canonical_bytes(value) + b"\n", replace=True)
        with self.assertRaises(MemoryError):
            recovery.restore_client(self.backup_path, self.recovered_path)
        self.assertFalse((self.recovered_path / "client.json").exists())

    def test_existing_targets_and_activation_without_authorization_fail(self) -> None:
        self.hooks()
        self.restore()
        self.assert_error("recovery_output_exists", recovery.restore_client, self.backup_path, self.recovered_path)
        output = self.recovered_path / "resumed-client.json"
        self.assert_error("local_resume_authorization_required", recovery.activate_recovery,
                          self.recovered_path, output, include=["hooks"])
        self.assertFalse(output.exists())
        selected = self.activate()
        self.assert_error("recovery_requires_new_config_and_state", recovery.activate_recovery,
                          self.recovered_path, selected.path, include=["hooks"], authorize_local_resume=True)

    def test_signed_source_cannot_silently_resume_unsigned_and_keys_are_not_archived(self) -> None:
        key_path, trust_path = self.control / "identity.json", self.control / "trust.json"
        storage.atomic_write(key_path, b"synthetic-not-a-real-private-key\n", replace=False)
        storage.atomic_write(trust_path, b"synthetic-not-a-real-registry\n", replace=False)
        self.configure(identity_path=str(key_path), trust_path=str(trust_path))
        self.hooks()
        with mock.patch("memory_vault_trust.Identity.load", side_effect=AssertionError("must not read key")):
            self.restore()
        manifest = json.loads((self.backup_path / "manifest.json").read_text())
        self.assertTrue(manifest["source"]["signed_writes_configured"])
        self.assertFalse(any("identity" in item["path"] or "trust" in item["path"] for item in manifest["entries"]))
        self.assert_error("recovery_signing_identity_or_explicit_unsigned_required", recovery.activate_recovery,
                          self.recovered_path, self.recovered_path / "resumed-client.json", include=["hooks"], authorize_local_resume=True)
        selected = self.activate(allow_unsigned_local=True)
        self.assertIsNone(selected.identity_path)

    def test_staging_before_first_canonical_write_is_backed_up_without_initializing_source(self) -> None:
        empty = self.root / "never-written.sqlite3"
        self.vault_path = empty
        self.configure(vault_path=str(empty))
        self.hooks()
        self.restore()
        self.assertFalse(empty.exists())
        manifest = json.loads((self.backup_path / "manifest.json").read_text())
        self.assertFalse(manifest["source"]["memory_database_present"])
        selected = self.activate()
        self.assertEqual(self.count(selected.vault_path), 0)
        self.assertEqual(manage.retry(selected.path)["saved"], 1)
        self.assertEqual(self.count(selected.vault_path), 2)

    def test_lifecycle_frozen_commit_can_resume_only_with_exact_original_request(self) -> None:
        session = lifecycle.handle(self.config_path, {"schema_version": lifecycle.REQUEST_SCHEMA, "op": "session.open", "request_id": "req_synthetic_session"})["result"]["session_handle"]
        turn = lifecycle.handle(self.config_path, {"schema_version": lifecycle.REQUEST_SCHEMA, "op": "turn.input", "request_id": "req_synthetic_input",
                                                  "session_handle": session, "user": "Synthetic pending input"})["result"]["turn_handle"]
        request = {"schema_version": lifecycle.REQUEST_SCHEMA, "op": "turn.commit", "request_id": "req_synthetic_commit",
                   "turn_handle": turn, "assistant": "Synthetic frozen output"}
        with mock.patch.object(lifecycle, "observe_turn", return_value=failure("synthetic_retry", retryable=True)):
            failed = lifecycle.handle(self.config_path, request)
        self.assertTrue(failed["resume_same_request"])
        self.restore(("lifecycle",))
        selected = self.activate(("lifecycle",))
        changed = copy.deepcopy(request)
        changed["assistant"] = "Different text is not a recovery"
        self.assertEqual(lifecycle.handle(selected.path, changed)["error"]["code"], "request_id_conflict")
        self.assertEqual(self.count(selected.vault_path), 1)
        resumed = lifecycle.handle(selected.path, request)
        self.assertTrue(resumed["ok"], resumed)
        self.assertEqual(self.count(selected.vault_path), 3)
        self.assertTrue(lifecycle.handle(selected.path, request)["replayed"])

    def test_compat_pending_intent_and_historical_receipts_survive_rebinding(self) -> None:
        opened = compat.handle(self.config_path, self.compat_request("session.open", {"continuity_handle": None, "reason": "compact"}, "recovery.open"))
        session = opened["result"]["continuity_handle"]
        request = self.compat_request("turn.commit", {"continuity_handle": session, "turn_handle": None, "outcome": "final",
                                      "visible_user_text": "Synthetic old-wire input", "visible_assistant_text": "Synthetic old-wire final"}, "recovery.commit")
        with mock.patch.object(compat, "_materialize", side_effect=MemoryError("synthetic_retry", retryable=True)):
            response = compat.handle(self.config_path, request)
        self.assertEqual(response["result"]["queue_state"], "pending")
        self.restore(("compat",))
        selected = self.activate(("compat",))
        with mock.patch.object(compat, "_flush", side_effect=AssertionError("must not sync")):
            result = manage.retry_compat(selected.path)
        self.assertEqual(result["saved"], 1)
        self.assertEqual(result["pending"], 0)
        self.assertEqual(compat.handle(selected.path, request)["status"], "duplicate")
        self.assertEqual(self.count(selected.vault_path), 3)

    def test_host_exact_queued_request_resumes_after_local_activation(self) -> None:
        native = {"session_id": "synthetic-host-session", "turn_id": "synthetic-host-turn"}
        opened = hosts.handle(self.config(), "generic", "session.open", {"session_id": native["session_id"]})
        self.assertTrue(opened["ok"], opened)
        staged = hosts.handle(self.config(), "generic", "turn.input", {**native, "user": "Synthetic host input"})
        self.assertTrue(staged["ok"], staged)
        with mock.patch.object(lifecycle, "observe_turn", return_value=failure("synthetic_retry", retryable=True)):
            final = hosts.handle(self.config(), "generic", "turn.commit", {**native, "assistant": "Synthetic host output"})
        self.assertFalse(final["ok"])
        session_key = _digest([hosts.PROFILE, "generic", native["session_id"]])
        self.restore(("lifecycle", "hosts"))
        selected = self.activate(("lifecycle", "hosts"))
        result = manage.retry_host(selected.path, host="generic", session_key=session_key)
        self.assertEqual(result["confirmed"], 1)
        self.assertFalse(result["background_sync_may_run"])
        self.assertEqual(self.count(selected.vault_path), 3)

    def test_unknown_control_sqlite_program_is_rejected_before_copy(self) -> None:
        lifecycle.handle(self.config_path, {"schema_version": lifecycle.REQUEST_SCHEMA, "op": "session.open", "request_id": "req_synthetic_schema"})
        path = self.config().state_path / "lifecycle-v1.sqlite3"
        with contextlib.closing(sqlite3.connect(path)) as connection, connection:
            connection.execute("CREATE TRIGGER not_part_of_profile AFTER INSERT ON sessions BEGIN SELECT 1; END")
        self.assert_error("unsupported_client_control_schema", self.backup, ("lifecycle",))
        self.assertFalse(self.backup_path.exists())

    def test_sync_evidence_excludes_credentials_cache_and_external_exchange(self) -> None:
        identity, trust = self.control / "identity.json", self.control / "trust.json"
        storage.atomic_write(identity, b"synthetic-placeholder\n", replace=False)
        storage.atomic_write(trust, b"synthetic-placeholder\n", replace=False)
        state = self.sync_configuration(identity, trust)
        storage.atomic_write(state / "sync-state.json", canonical_bytes({"synthetic": "historical metadata"}), replace=False)
        storage.atomic_write(state / "transfer" / "publish.pending.json", canonical_bytes({"synthetic": "inert unvalidated capsule"}), replace=False)
        storage.atomic_write(state / "rclone" / "cache" / "not-backed-up", b"synthetic excluded cache", replace=False)
        storage.atomic_write(self.root / "exchange" / "not-backed-up", b"synthetic external exchange", replace=False)
        self.restore(("sync",))
        manifest = json.loads((self.backup_path / "manifest.json").read_text())
        paths = {entry["path"] for entry in manifest["entries"]}
        self.assertIn("control/sync/transfer/publish.pending.json", paths)
        self.assertFalse(any("rclone" in path or "identity" in path or "trust" in path or "not-backed-up" in path for path in paths))
        self.assertIsNone(ClientConfig.load(self.recovered_path / "client.json").sync_config_path)
        self.assert_error("explicit_recovery_components_required", recovery.activate_recovery,
                          self.recovered_path, self.recovered_path / "resumed-client.json", include=["sync"], authorize_local_resume=True)

    def test_known_active_worker_lock_rejects_offline_claim(self) -> None:
        identity, trust = self.control / "identity.json", self.control / "trust.json"
        storage.atomic_write(identity, b"synthetic-placeholder\n", replace=False)
        storage.atomic_write(trust, b"synthetic-placeholder\n", replace=False)
        state = self.sync_configuration(identity, trust)
        with storage.file_lock(state / "worker.lock"):
            with self.assertRaises(OSError) as raised:
                self.backup(("sync",))
            self.assertEqual(getattr(raised.exception, "code", None), "client_recovery_not_quiescent")
        self.assertFalse(self.backup_path.exists())

    def test_review_is_paginated_content_free_and_not_authorization(self) -> None:
        self.hooks()
        self.restore()
        first = recovery.review_recovery(self.recovered_path, limit=1)
        self.assertEqual(len(first["entries"]), 1)
        self.assertIsNotNone(first["next_offset"])
        self.assertFalse(first["review_is_authorization"])
        self.assertNotIn("Synthetic visible", json.dumps(first))
        second = recovery.review_recovery(self.recovered_path, offset=first["next_offset"], limit=1)
        self.assertNotEqual(first["entries"][0]["entry_id"], second["entries"][0]["entry_id"])
        self.assertEqual(first["evidence_manifest_sha256"], second["evidence_manifest_sha256"])


@unittest.skipUnless(os.name == "posix" and importlib.util.find_spec("cryptography") is not None,
                     "signed synthetic fixtures require optional cryptography and POSIX")
class SignedRecoveryTests(RecoveryFixture):
    def signed_source(self, *, group: bool = False, incomplete: bool = False) -> tuple[str, Path, str]:
        from memory_vault_trust import Identity, TrustStore
        from memory_vault_transfer import CHAINED_DELTA_SCHEMA, GROUP_SCHEMA, _fragment_name
        identity_path = self.control / "sender.json"
        identity = Identity.generate(identity_path)
        trust_path = self.control / "trust.json"
        TrustStore(trust_path).add(identity.public_descriptor(), "synthetic sender")
        state = self.sync_configuration(identity_path, trust_path)
        record = build_record(kind="fact", text="Synthetic received record not yet canonical.", created_at="2026-01-01T00:00:00Z")
        proof = identity.sign_record(record)
        descriptor = None
        if group:
            line = canonical_bytes({"record": record, "attestation": proof}) + b"\n"
            part = {"index": 0, "sha256": sha256(line), "bytes": len(line), "records": 1}
            descriptor = {"schema_version": GROUP_SCHEMA, "record_count": 1, "record_bytes": len(canonical_bytes(record)),
                          "encoded_bytes": len(line), "records_sha256": sha256(line), "fragments": [part]}
            descriptor["group_id"] = sha256(canonical_bytes(descriptor))
            if not incomplete:
                storage.atomic_write(state / "transfer" / "incoming-groups" / descriptor["group_id"] / _fragment_name(part), line, replace=False)
        payload = {"schema_version": CHAINED_DELTA_SCHEMA, "source_store_id": "store_" + "f" * 32,
                   "sender_key_id": identity.key_id, "after": 0, "cursor": 1,
                   "records": [] if group else [record], "attestations": {} if group else {record["memory_id"]: proof},
                   "blocked": [], "previous_batch_sha256": None, "publication_review": None, "group": descriptor}
        digest = sha256(canonical_bytes(payload))
        capsule = {"payload": payload, "proof": identity.sign_message(payload)}
        storage.atomic_write(state / "transfer" / "received-capsules" / (digest + ".json"), canonical_bytes(capsule) + b"\n", replace=False)
        self.restore(("sync",))
        result = recovery.review_recovery(self.recovered_path, component="sync")
        entry = next(item for item in result["entries"] if item["signed_memory_import_candidate"])
        return entry["entry_id"], trust_path, identity.key_id

    def test_signed_incoming_capsule_requires_independent_authorization(self) -> None:
        entry, trust, _ = self.signed_source()
        self.assert_error("recovery_memory_import_authorization_required", recovery.import_recovery,
                          self.recovered_path, entry_id=entry, trust_store=trust)
        self.assertEqual(self.count(self.recovered_path / "memory.sqlite3"), 1)

    def test_complete_incoming_signed_capsule_is_local_and_idempotent(self) -> None:
        entry, trust, _ = self.signed_source()
        with mock.patch("memory_vault_trust.Identity.load", side_effect=AssertionError("receive requires no private key")), \
                mock.patch("memory_vault_client.notify_sync", side_effect=AssertionError("must not start a worker")):
            result = recovery.import_recovery(self.recovered_path, entry_id=entry, trust_store=trust, authorize_memory_import=True)
            repeated = recovery.import_recovery(self.recovered_path, entry_id=entry, trust_store=trust, authorize_memory_import=True)
        self.assertEqual(result["memory"]["records_added"], 1)
        self.assertTrue(repeated["memory"]["receipt_replayed"])
        self.assertEqual(self.count(self.recovered_path / "memory.sqlite3"), 2)
        self.assertFalse(result["network_accessed"])
        self.assertFalse((self.recovered_path / "client.state").exists())

    def test_complete_group_is_assembled_and_admitted_as_one_transaction(self) -> None:
        entry, trust, _ = self.signed_source(group=True)
        result = recovery.import_recovery(self.recovered_path, entry_id=entry, trust_store=trust, authorize_memory_import=True)
        self.assertEqual(result["memory"]["records_added"], 1)
        self.assertEqual(self.count(self.recovered_path / "memory.sqlite3"), 2)
        self.assertFalse(result["old_publication_permissions_restored"])

    def test_missing_group_fragment_does_not_admit_a_partial_memory(self) -> None:
        entry, trust, _ = self.signed_source(group=True, incomplete=True)
        self.assert_error("recovery_group_incomplete", recovery.import_recovery, self.recovered_path,
                          entry_id=entry, trust_store=trust, authorize_memory_import=True)
        self.assertEqual(self.count(self.recovered_path / "memory.sqlite3"), 1)

    def test_current_revocation_wins_over_backup_time_signature(self) -> None:
        from memory_vault_trust import TrustStore, TrustError
        entry, trust, key = self.signed_source()
        TrustStore(trust).revoke(key)
        with self.assertRaises(TrustError):
            recovery.import_recovery(self.recovered_path, entry_id=entry, trust_store=trust, authorize_memory_import=True)
        self.assertEqual(self.count(self.recovered_path / "memory.sqlite3"), 1)


if __name__ == "__main__":
    unittest.main()
