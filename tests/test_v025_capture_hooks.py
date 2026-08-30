"""Synthetic frozen-hook cases; execution evidence is published separately.

Only temporary, explicitly configured unsigned Vaults are used. The one child
process touches its named temporary SQLite journal and exits mid-transaction;
it does not open a real host, key, provider, network connection or private Vault.
"""

from __future__ import annotations

import contextlib
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import memory_vault_capture as capture
import memory_vault_client as client
import memory_vault_recovery as recovery
import memory_vault_storage as storage
from memory_vault import MemoryError, Vault, canonical_bytes, failure, strict_json_loads


HOT_JOURNAL_CHILD = """
import os, sqlite3, sys
connection = sqlite3.connect(sys.argv[1])
connection.execute('PRAGMA journal_mode=DELETE')
connection.execute('PRAGMA synchronous=FULL')
connection.execute('PRAGMA cache_size=1')
connection.execute('PRAGMA cache_spill=ON')
connection.execute('BEGIN IMMEDIATE')
connection.execute('UPDATE capture_records SET record_json=? WHERE job_key=? AND ordinal=0',
                   ('synthetic interrupted staging ' * 65536, sys.argv[2]))
os._exit(73)
"""


class FrozenHookCaptureTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="memory-v025-hook-capture-synthetic-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.control = self.root / "control"
        self.control.mkdir(mode=0o700)
        self.config_path = self.control / "client.json"
        self.vault_path = self.root / "vault.sqlite3"
        self.document = {"schema_version": client.CONFIG_SCHEMA, "vault_path": str(self.vault_path), "capture_visible_turns": True}
        self.configure()

    def configure(self, **changes: object) -> None:
        self.document.update(changes)
        storage.atomic_write(self.config_path, canonical_bytes(self.document) + b"\n", replace=self.config_path.exists())

    def config(self) -> client.ClientConfig:
        return client.ClientConfig.load(self.config_path)

    def journal(self, config: client.ClientConfig | None = None) -> capture.HookCaptureJournal:
        chosen = config or self.config()
        return capture.HookCaptureJournal(chosen.state_path, chosen.vault_path)

    def plan(self, key: str, config: client.ClientConfig | None = None) -> dict:
        with self.journal(config).transaction(writable=False) as connection:
            self.assertIsNotNone(connection)
            result = capture.load_capture(connection, key)
        self.assertIsNotNone(result)
        return dict(result)

    def prompt(self, session: str, turn: str, text: str = "Synthetic visible input") -> str:
        event = {"hook_event_name": "UserPromptSubmit", "session_id": session, "turn_id": turn, "prompt": text}
        client.handle_hook(self.config(), "user-prompt-submit", event)
        return client._turn_key(event)

    def finish(self, session: str, turn: str, text: str = "Synthetic visible final") -> dict:
        return dict(client.handle_hook(self.config(), "stop", {
            "hook_event_name": "Stop", "session_id": session, "turn_id": turn, "last_assistant_message": text,
        }))

    def records(self, config: client.ClientConfig | None = None) -> dict[str, dict]:
        path = (config or self.config()).vault_path
        if not path.exists():
            return {}
        with contextlib.closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as connection:
            values = [strict_json_loads(row[0]) for row in connection.execute("SELECT record_json FROM memories ORDER BY ingest_seq")]
        return {record["memory_id"]: record for record in values}

    def assert_pending(self, session: str, turn: str, text: str = "Synthetic pending final") -> None:
        with mock.patch.object(client, "save_turn_projection", return_value=failure("synthetic_temporarily_unavailable", retryable=True)):
            response = self.finish(session, turn, text)
        self.assertIn("pending_retry", response["systemMessage"])

    def test_each_source_freezes_its_predecessor_and_exact_retry_never_rebuilds(self) -> None:
        first = self.prompt("synthetic-alpha", "one")
        self.finish("synthetic-alpha", "one", "Synthetic alpha first")
        first_plan = self.plan(first)
        other = self.prompt("synthetic-beta", "one")
        self.finish("synthetic-beta", "one", "Synthetic beta first")
        second = self.prompt("synthetic-alpha", "two")
        with mock.patch.object(capture, "utc_now", return_value="2026-08-01T00:00:00Z"):
            self.assert_pending("synthetic-alpha", "two")
        frozen = self.plan(second)
        self.assertEqual(frozen["previous_continuity_id"], first_plan["continuity_id"])
        self.assertNotEqual(frozen["previous_continuity_id"], self.plan(other)["continuity_id"])
        self.assertEqual(frozen["accepted_sequence"], 2)
        self.assertEqual(frozen["created_at"], "2026-08-01T00:00:00Z")
        with mock.patch.object(client, "build_turn_projection", side_effect=AssertionError("must not rebuild accepted capture")):
            result = client.retry_pending(self.config(), limit=1)
        self.assertEqual((result["processed"], result["saved"], result["failed"]), (1, 1, 0))
        saved = self.plan(second)
        self.assertEqual(saved["projection_sha256"], frozen["projection_sha256"])
        self.assertEqual(saved["record_refs"], frozen["record_refs"])
        self.assertEqual(saved["records"], [])
        records = self.records()
        self.assertEqual(len(records), 6)
        self.assertIn({"type": "continues", "target": first_plan["continuity_id"]}, records[saved["continuity_id"]]["relations"])
        self.assertNotIn("synthetic-alpha", canonical_bytes(list(records.values())).decode())
        self.assertNotIn("scope_key", canonical_bytes(list(records.values())).decode())

    def test_done_before_journal_ack_restores_and_retries_without_raw_source(self) -> None:
        first = self.prompt("synthetic-recovery", "one")
        self.finish("synthetic-recovery", "one", "Synthetic earlier context")
        key = self.prompt("synthetic-recovery", "two")
        with mock.patch.object(capture, "mark_capture_saved", side_effect=MemoryError("synthetic_after_done")):
            with self.assertRaisesRegex(MemoryError, "synthetic_after_done"):
                self.finish("synthetic-recovery", "two")
        frozen = self.plan(key)
        self.assertEqual(frozen["state"], "pending")
        state = client.HookState(self.config())
        self.assertIsNone(state.read("outbox", key))
        self.assertIsNone(state.read("prompts", key))
        self.assertIsNotNone(state.read("done", key))
        original_records = self.records()
        backup = self.root / "backup"
        restored = self.root / "restored"
        recovery.backup_client(self.config_path, backup, include=["hooks"], quiesced=True)
        recovery.restore_client(backup, restored, accept_unsigned=True)
        resumed_path = restored / "resumed-client.json"
        recovery.activate_recovery(restored, resumed_path, include=["hooks"], authorize_local_resume=True)
        resumed = client.ClientConfig.load(resumed_path)
        retained = self.plan(key, resumed)
        self.assertEqual(retained["scope_key"], frozen["scope_key"])
        self.assertEqual(retained["previous_continuity_id"], self.plan(first)["continuity_id"])
        self.assertEqual(retained["projection_sha256"], frozen["projection_sha256"])
        with mock.patch.object(client, "build_turn_projection", side_effect=AssertionError("must use retained projection")):
            result = client.retry_pending(resumed, limit=1)
        self.assertEqual(result["saved"], 1, result)
        self.assertEqual(self.plan(key, resumed)["state"], "saved")
        self.assertEqual(self.records(resumed), original_records)
        self.assertEqual(self.plan(key)["state"], "pending", "restoring must not mutate original control state")
        self.assertIsNone(resumed.sync_config_path)
        self.assertFalse(result["network_accessed"])

    def test_legacy_partial_outbox_keeps_original_receipts_and_has_no_new_head(self) -> None:
        key = "b" * 64
        state = client.HookState(self.config())
        state.prompt(key, "Synthetic legacy input")
        state.once("outbox", key, {"user": "Synthetic legacy input", "assistant": "Synthetic legacy final"})
        original = Vault.handle

        def first_part_only(vault: Vault, request: dict) -> dict:
            if request.get("op") == "remember" and request.get("kind") == "continuity":
                return failure("synthetic_between_legacy_writes", retryable=True)
            return original(vault, request)

        with mock.patch.object(Vault, "handle", autospec=True, side_effect=first_part_only):
            response = client._persist_job(self.config(), state, key, state.read("outbox", key))
        episode_id = response["partial_result"]["episode_id"]
        self.assertEqual(len(self.records()), 1)
        self.assertFalse(self.journal().path.exists())
        result = client.retry_pending(self.config(), limit=1)
        self.assertEqual(result["saved"], 1, result)
        self.assertEqual(state.read("done", key)["episode_id"], episode_id)
        self.assertEqual(state.read("done", key)["schema_version"], client.STATE_SCHEMA)
        self.assertEqual(len(self.records()), 2)
        self.assertFalse(self.journal().path.exists())
        with contextlib.closing(sqlite3.connect(self.vault_path)) as connection:
            receipts = {row[0] for row in connection.execute("SELECT request_id FROM receipts")}
        self.assertEqual(receipts, {client._request_id("req_hook_" + key, suffix) for suffix in ("episode", "continuity")})

    def test_bounded_ancestor_progress_notifies_without_claiming_target_saved(self) -> None:
        keys = []
        for number in range(5):
            turn = str(number)
            keys.append(self.prompt("synthetic-bounded", turn))
            self.assert_pending("synthetic-bounded", turn, "Synthetic final " + turn)
        with mock.patch.object(client, "notify_sync", return_value={"state": "synthetic_notification"}) as notify:
            response = self.finish("synthetic-bounded", "4", "Synthetic final 4")
        self.assertIn("pending_retry", response["systemMessage"])
        notify.assert_called_once()
        self.assertEqual(len(self.records()), 8)
        self.assertEqual([self.plan(key)["state"] for key in keys], ["saved"] * 4 + ["pending"])
        self.assertEqual(client.retry_pending(self.config(), limit=1)["saved"], 1)
        self.assertEqual(len(self.records()), 10)

    @unittest.skipUnless(os.name == "posix", "synthetic child-exit fixture currently covers POSIX")
    def test_authorized_retry_recovers_hot_journal_before_bounded_discovery(self) -> None:
        key = self.prompt("synthetic-hot-journal", "one")
        self.assert_pending("synthetic-hot-journal", "one")
        frozen = self.plan(key)
        journal = self.journal()
        child = subprocess.run([sys.executable, "-I", "-B", "-c", HOT_JOURNAL_CHILD, str(journal.path), key],
                               cwd=self.root, env={}, capture_output=True, timeout=10, check=False)
        self.assertEqual(child.returncode, 73, child.stderr.decode(errors="replace"))
        self.assertGreater(Path(str(journal.path) + "-journal").stat().st_size, 512)
        with self.assertRaises(sqlite3.OperationalError):
            with journal.transaction(writable=False):
                pass
        result = client.retry_pending(self.config(), limit=1)
        self.assertEqual((result["processed"], result["saved"], result["failed"]), (1, 1, 0))
        self.assertEqual(self.plan(key)["projection_sha256"], frozen["projection_sha256"])
        self.assertEqual(len(self.records()), 2)
        self.assertFalse(Path(str(journal.path) + "-journal").exists())

    def test_current_disabled_capture_does_not_create_journal_from_stale_config(self) -> None:
        stale = self.config()
        self.configure(capture_visible_turns=False)
        response = client.handle_hook(stale, "user-prompt-submit", {
            "hook_event_name": "UserPromptSubmit", "session_id": "synthetic-disabled", "turn_id": "one", "prompt": "Synthetic prompt",
        })
        self.assertEqual(response, {})
        with self.assertRaisesRegex(MemoryError, "automatic_capture_disabled"):
            client.retry_pending(stale, limit=1)
        self.assertFalse(stale.state_path.exists())
        self.assertFalse(self.vault_path.exists())


if __name__ == "__main__":
    unittest.main()
