"""Synthetic partial-capture recovery cases; NOT RUN in this change.

Every file and unsigned Vault belongs to a TemporaryDirectory. The injected
exceptions model local completion/acceptance boundaries, not actual process
crashes. No host, provider, signing identity, subprocess or network is used.
The full flow uses real capture, canonical saves, snapshots and local retries;
guards assert that restoring evidence itself never invokes those retries.
"""

from __future__ import annotations

import contextlib
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import memory_vault_backup as backup
import memory_vault_capture as capture
import memory_vault_client as client
import memory_vault_recovery as recovery
import memory_vault_storage as storage
from memory_vault import MemoryError, canonical_bytes, failure, strict_json_loads


class PartialCaptureRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="memory-v025-partial-recovery-synthetic-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.source = self.root / "source"
        self.control = self.source / "control"
        storage.private_directory(self.control)
        self.config_path = self.control / "client.json"
        self.vault_path = self.source / "memory.sqlite3"
        storage.atomic_write(self.config_path, canonical_bytes({
            "schema_version": client.CONFIG_SCHEMA, "vault_path": str(self.vault_path),
            "capture_visible_turns": True,
        }) + b"\n")

    def config(self) -> client.ClientConfig:
        return client.ClientConfig.load(self.config_path)

    def job(self, name: str, *, user: str | None = None, assistant: str | None = None,
            supplement: dict | None = None, scope: str = "synthetic-scope") -> tuple[str, dict]:
        turn_key = client._digest(["synthetic-partial-turn", name])
        key = turn_key if supplement is None else client.hook_supplement_key(turn_key)
        return key, client.HookState.validate("outbox", {
            "schema_version": client.FRAGMENT_STATE_SCHEMA,
            "scope_key": client._digest(["synthetic-partial-scope", scope]),
            "turn_key": turn_key, "user": user, "assistant": assistant,
            "supplement": supplement,
        })

    def journal(self, config: client.ClientConfig) -> capture.HookCaptureJournal:
        return capture.HookCaptureJournal(config.state_path, config.vault_path)

    def plan(self, key: str, config: client.ClientConfig) -> dict:
        with self.journal(config).transaction(writable=False) as connection:
            self.assertIsNotNone(connection)
            result = capture.load_capture(connection, key)
        self.assertIsNotNone(result)
        return dict(result)

    def reference(self, plan: dict) -> dict:
        return next(dict(item) for item in plan["record_refs"] if item["memory_id"] == plan["episode_id"])

    def queue(self, key: str, job: dict, config: client.ClientConfig) -> client.HookState:
        state = client.HookState(config)
        state.once("outbox", key, job)
        return state

    def persist(self, key: str, job: dict, config: client.ClientConfig) -> dict:
        state = self.queue(key, job, config)
        result = client._persist_job(config, state, key, job)
        self.assertTrue(result["ok"], result)
        return dict(result)

    def records(self, path: Path) -> dict[str, dict]:
        with contextlib.closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as connection:
            rows = connection.execute("SELECT record_json FROM memories ORDER BY ingest_seq")
            values = [strict_json_loads(row[0]) for row in rows]
        return {value["memory_id"]: value for value in values}

    def receipts(self, path: Path) -> list[tuple]:
        with contextlib.closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as connection:
            return list(connection.execute("SELECT request_id,request_sha256,response_json,created_at FROM receipts ORDER BY request_id"))

    def test_fragment_done_and_frozen_supplement_restore_without_source_and_retry_exactly(self) -> None:
        config = self.config()
        first_key, first_job = self.job("one", user="Synthetic visible user input: café.")
        state = self.queue(first_key, first_job, config)
        # The real atomic canonical write and done publication complete; only
        # the later local journal acknowledgement is interrupted synthetically.
        with mock.patch.object(capture, "mark_capture_saved", side_effect=MemoryError("synthetic_after_fragment_done")):
            with self.assertRaisesRegex(MemoryError, "synthetic_after_fragment_done"):
                client._persist_job(config, state, first_key, first_job)
        first = self.plan(first_key, config)
        self.assertEqual(first["state"], "pending")
        self.assertIsNone(state.read("outbox", first_key))
        self.assertIsNotNone(state.read("done", first_key))
        original_records = self.records(config.vault_path)
        self.assertEqual(len(original_records), 2)
        next_key, next_job = self.job("one", assistant="Synthetic later visible assistant response.",
                                      supplement=self.reference(first))
        self.queue(next_key, next_job, config)
        with mock.patch.object(client, "save_turn_projection", return_value=failure("synthetic_local_save_wait", retryable=True)):
            pending = client._persist_job(config, state, next_key, next_job)
        self.assertFalse(pending["ok"])
        frozen = self.plan(next_key, config)
        self.assertEqual(frozen["state"], "pending")
        snapshot, restored = self.root / "snapshot", self.root / "restored"
        recovery.backup_client(config.path, snapshot, include=["hooks"], quiesced=True)
        # Source configuration, queue and Vault all disappear from their old
        # paths. This is a rename of this fixture only, not real user state.
        self.source.rename(self.root / "source-offline")
        self.assertFalse(config.path.exists())
        self.assertFalse(config.vault_path.exists())
        output = restored / "resumed-client.json"
        with mock.patch.object(client, "save_turn_projection", side_effect=AssertionError("restore is not retry")), \
                mock.patch.object(client, "notify_sync", side_effect=AssertionError("restore is not sync")):
            result = recovery.restore_client(snapshot, restored, accept_unsigned=True)
            inert = client.ClientConfig.load(restored / "client.json")
            self.assertFalse(inert.capture_visible_turns)
            self.assertFalse(inert.state_path.exists())
            self.assertFalse(result["pending_replayed"])
            with self.assertRaisesRegex(MemoryError, "local_resume_authorization_required"):
                recovery.activate_recovery(restored, output, include=["hooks"])
            self.assertFalse(output.exists())
            activated = recovery.activate_recovery(restored, output, include=["hooks"], authorize_local_resume=True)
        self.assertFalse(activated["pending_replayed"])
        self.assertFalse(activated["network_accessed"])
        resumed = client.ClientConfig.load(output)
        self.assertIsNone(resumed.identity_path)
        self.assertIsNone(resumed.trust_path)
        self.assertIsNone(resumed.sync_config_path)
        self.assertEqual(self.plan(first_key, resumed), first)
        self.assertEqual(self.plan(next_key, resumed), frozen)
        retried = client.retry_pending(resumed, limit=4)
        self.assertTrue(retried["ok"], retried)
        self.assertEqual(retried["result"]["failed"], 0)
        self.assertGreaterEqual(retried["result"]["saved"], 1)
        self.assertFalse(retried["result"]["network_accessed"])
        after = self.records(resumed.vault_path)
        self.assertEqual(len(after), 4)
        self.assertTrue(all(after[key] == record for key, record in original_records.items()))
        for key, previous in ((first_key, first), (next_key, frozen)):
            retained = self.plan(key, resumed)
            self.assertEqual(retained["state"], "saved")
            self.assertEqual(retained["projection_sha256"], previous["projection_sha256"])
            self.assertEqual(retained["record_refs"], previous["record_refs"])
        fragment = capture.parse_hook_fragment(after[frozen["episode_id"]])
        self.assertEqual(fragment["supplement"], self.reference(first))
        self.assertEqual(fragment["missing_roles"], ["user"])
        self.assertIn({"type": "continues", "target": first["continuity_id"]}, after[frozen["continuity_id"]]["relations"])
        self.assertEqual(client.retry_pending(resumed, limit=4)["result"]["processed"], 0)
        # A memory-only snapshot has no outbox to infer the new profile from.
        # Both canonical fragment receipts and the complete anchor hash survive.
        memory_snapshot, memory_copy = self.root / "memory-only", self.root / "memory-copy.sqlite3"
        backup.backup_database(resumed.vault_path, memory_snapshot)
        backup.restore_database(memory_snapshot, memory_copy, accept_unsigned=True)
        self.assertEqual(self.records(memory_copy), after)
        self.assertEqual(self.receipts(memory_copy), self.receipts(resumed.vault_path))

    def test_unaccepted_supplement_uses_earlier_frozen_anchor_without_a_source_vault(self) -> None:
        config = self.config()
        first_key, first_job = self.job("pending", user="Synthetic pending user side.")
        self.queue(first_key, first_job, config)
        # Real acceptance, deliberately stopped before any canonical write.
        # These are production pure source/digest/builder functions, not a
        # fabricated control database or a mock of restoration/admission.
        with self.journal(config).transaction() as connection:
            first = capture.freeze_capture(
                connection, scope_key=first_job["scope_key"], job_key=first_key,
                input_sha256=client._fragment_input_digest(client._fragment_source(first_job)),
                builder_profile=capture.HOOK_FRAGMENT_PROFILE,
                canonical_request_id="req_hook_capture_" + first_key,
                created_at="2026-08-31T00:00:00Z",
                build_projection=lambda stamp, previous: capture.build_hook_fragment_projection(
                    first_job["user"], None, created_at=stamp, predecessor=previous),
            )
        self.assertFalse(config.vault_path.exists())
        next_key, next_job = self.job("pending", assistant="Synthetic queued opposite side.",
                                      supplement=self.reference(first))
        self.queue(next_key, next_job, config)
        with self.journal(config).transaction(writable=False) as connection:
            self.assertIsNone(capture.load_capture(connection, next_key))
        snapshot, restored = self.root / "snapshot", self.root / "restored"
        recovery.backup_client(config.path, snapshot, include=["hooks"], quiesced=True)
        recovery.restore_client(snapshot, restored, accept_unsigned=True)
        output = restored / "resumed-client.json"
        recovery.activate_recovery(restored, output, include=["hooks"], authorize_local_resume=True)
        resumed = client.ClientConfig.load(output)
        self.assertEqual(self.records(resumed.vault_path), {})
        self.assertEqual(self.plan(first_key, resumed), first)
        with self.journal(resumed).transaction(writable=False) as connection:
            self.assertIsNone(capture.load_capture(connection, next_key))
        result = client.retry_pending(resumed, limit=4)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["result"]["failed"], 0)
        records = self.records(resumed.vault_path)
        self.assertEqual(len(records), 4)
        late = self.plan(next_key, resumed)
        self.assertEqual(capture.parse_hook_fragment(records[late["episode_id"]])["supplement"], self.reference(first))
        self.assertEqual(self.plan(first_key, resumed)["projection_sha256"], first["projection_sha256"])
        self.assertFalse(config.vault_path.exists(), "resuming a new copy must not initialize the old source Vault")
        body = canonical_bytes(list(records.values())).decode("utf-8")
        self.assertNotIn(first_key, body)
        self.assertNotIn(first_job["scope_key"], body)

    def test_wrong_turn_scope_full_hash_or_role_cannot_activate_a_supplement(self) -> None:
        config = self.config()
        first_key, first_job = self.job("first", user="Synthetic first turn input.")
        other_key, other_job = self.job("other", user="Synthetic different turn input.")
        self.persist(first_key, first_job, config)
        self.persist(other_key, other_job, config)
        first, other = self.plan(first_key, config), self.plan(other_key, config)
        reference = self.reference(first)
        changed_hash = {**reference, "record_sha256": reference["record_sha256"][:-1]
                        + ("0" if reference["record_sha256"][-1] != "0" else "1")}
        variants = (
            ("other_turn", {"assistant": "Synthetic later side.", "supplement": self.reference(other)}, "hook_recovery_fragment_anchor_changed"),
            ("other_scope", {"assistant": "Synthetic later side.", "supplement": reference, "scope": "another-scope"}, "hook_recovery_fragment_turn_changed"),
            ("full_hash", {"assistant": "Synthetic later side.", "supplement": changed_hash}, "hook_recovery_fragment_anchor_changed"),
            ("same_role", {"user": "Synthetic repeated user side.", "supplement": reference}, "hook_recovery_fragment_anchor_changed"),
        )
        state = client.HookState(config)
        expected_records = self.records(config.vault_path)
        for name, fields, expected_error in variants:
            with self.subTest(name=name):
                key, document = self.job("first", **fields)
                path = state.path("outbox", key)
                # Deliberate modification of this synthetic unaccepted queue,
                # modelling an archive whose hashes alone are not authority.
                storage.private_directory(path.parent)
                storage.atomic_write(path, canonical_bytes(document) + b"\n", replace=path.exists())
                snapshot, restored = self.root / (name + "-snapshot"), self.root / (name + "-restored")
                recovery.backup_client(config.path, snapshot, include=["hooks"], quiesced=True)
                recovery.restore_client(snapshot, restored, accept_unsigned=True)
                output = restored / "resumed-client.json"
                with mock.patch.object(client, "save_turn_projection", side_effect=AssertionError("activation is not retry")), \
                        mock.patch.object(client, "notify_sync", side_effect=AssertionError("activation is not sync")):
                    with self.assertRaises(MemoryError) as caught:
                        recovery.activate_recovery(restored, output, include=["hooks"], authorize_local_resume=True)
                self.assertEqual(caught.exception.code, expected_error)
                self.assertFalse(output.exists())
                self.assertEqual(self.records(restored / "memory.sqlite3"), expected_records)
        with contextlib.closing(sqlite3.connect(config.vault_path.as_uri() + "?mode=ro", uri=True)) as memory:
            memory.row_factory = sqlite3.Row
            with self.assertRaisesRegex(MemoryError, "hook_recovery_capture_plan_missing"):
                recovery._hook_document(state.read("done", first_key), "done", memory, key=first_key, capture=None)


if __name__ == "__main__":
    unittest.main()
