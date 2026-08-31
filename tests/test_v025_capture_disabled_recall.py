"""Synthetic capture-opt-out recall workflow; authored, not executed.

The real local reader, compatibility envelopes and SQLite control paths are
used with temporary unsigned data. Two explicit pre-save exception injections
leave existing accepted jobs pending; negative guards forbid their resumption,
new capture projections, canonical writers and worker notifications during the
opt-out checks. No host, provider, process, signing key or network is used.
This is not a live-host, signed-revocation or complete recovery acceptance test.
"""

from __future__ import annotations

import contextlib
import copy
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import memory_vault_capture as capture
import memory_vault_client as client
import memory_vault_compat as compat
import memory_vault_install as install
import memory_vault_storage as storage
from memory_vault import MemoryError, Vault, canonical_bytes, failure


class CaptureDisabledRecallTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="memory-v025-disabled-recall-synthetic-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.config_path = self.root / "client.json"
        self.vault_path = self.root / "vault.sqlite3"
        self.sequence = 0
        self.configure(True)

    def configure(self, enabled: bool, *, path: Path | None = None) -> client.ClientConfig:
        selected = path or self.config_path
        document = {"schema_version": client.CONFIG_SCHEMA, "vault_path": str(self.vault_path),
                    "capture_visible_turns": enabled}
        if not enabled:
            # This deliberately missing file must not be loaded by input
            # recall; no independently authorized sync window is requested.
            document["sync_config_path"] = str(self.root / "unused-sync.json")
        storage.atomic_write(selected, canonical_bytes(document) + b"\n", replace=selected.exists())
        return client.ClientConfig.load(selected)

    def request(self, operation: str, payload: dict) -> dict:
        self.sequence += 1
        return {"schema_version": compat.REQUEST_SCHEMA, "protocol_version": "1.0",
                "request_id": "disabled-recall.synthetic." + str(self.sequence), "operation": operation,
                "adapter": {"id": "synthetic-adapter", "version": "1.0.0", "host_family": "generic_stdio"},
                "payload": payload}

    def control_row(self, turn: str) -> dict:
        state = compat.CompatState(client.ClientConfig.load(self.config_path))
        connection = state.connect(writable=False)
        self.assertIsNotNone(connection)
        with contextlib.closing(connection):
            row = connection.execute("SELECT * FROM turns WHERE handle=?", (turn,)).fetchone()
        self.assertIsNotNone(row)
        return dict(row)

    @staticmethod
    def tree(path: Path) -> dict[str, bytes | None]:
        if not path.exists():
            return {}
        return {str(entry.relative_to(path)): None if entry.is_dir() else entry.read_bytes()
                for entry in sorted(path.rglob("*"))}

    def test_disabled_capture_keeps_real_recall_and_noncommittable_legacy_handles(self) -> None:
        seeded = Vault(self.vault_path).handle({
            "op": "observe", "request_id": "req_disabled_recall_seed_0001",
            "user": "Synthetic Zephyr archived decision",
            "assistant": "Current goals, decisions, continuity and unresolved next actions: Zephyr library marker.",
        })
        self.assertTrue(seeded["ok"], seeded)
        stale = client.ClientConfig.load(self.config_path)

        # Existing hook and old-envelope intents were accepted while capture
        # was enabled. The only setup faults occur before canonical storage.
        client.handle_hook(stale, "user-prompt-submit", {
            "hook_event_name": "UserPromptSubmit", "session_id": "synthetic-hook", "turn_id": "pending",
            "prompt": "Synthetic earlier hook input",
        })
        stop = {"hook_event_name": "Stop", "session_id": "synthetic-hook", "turn_id": "pending",
                "last_assistant_message": "Synthetic earlier hook final"}
        with mock.patch.object(client, "save_turn_projection", return_value=failure("synthetic_pre_save", retryable=True)):
            pending_hook = client.handle_hook(stale, "stop", stop)
        self.assertIn("pending_retry", pending_hook["systemMessage"])

        opened = compat.handle(self.config_path, self.request("session.open", {"continuity_handle": None, "reason": "compact"}))
        self.assertEqual(opened["status"], "accepted_local", opened)
        session = opened["result"]["continuity_handle"]
        pending_request = self.request("turn.commit", {
            "continuity_handle": session, "turn_handle": None, "outcome": "final",
            "visible_user_text": "Synthetic earlier compatibility input",
            "visible_assistant_text": "Synthetic earlier compatibility final",
        })
        with mock.patch.object(compat, "_store_records", side_effect=MemoryError("synthetic_pre_save", retryable=True)):
            pending = compat.handle(self.config_path, pending_request)
        self.assertEqual(pending["result"]["queue_state"], "pending", pending)
        pending_turn = pending["result"]["turn_handle"]
        prior_pending = self.control_row(pending_turn)

        disabled = self.configure(False)
        canonical_before = self.vault_path.read_bytes()
        files_before_hooks = self.tree(self.root)
        original_vault = client.ClientConfig.vault

        def readonly_vault(config: client.ClientConfig, *, writing: bool = False,
                           host_visible: bool = False, storage_write: bool = False) -> Vault:
            self.assertFalse(writing, "recall may not construct a canonical signer/writer")
            self.assertFalse(storage_write, "recall may not recover canonical storage")
            return original_vault(config, writing=writing, host_visible=host_visible, storage_write=storage_write)

        guards = []
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(client.ClientConfig, "vault", new=readonly_vault))
            stack.enter_context(mock.patch.dict(os.environ, {"MEMORY_VAULT_MANAGED_ROOT": str(self.root / "unused-managed-root")}))
            for owner, name in ((client, "notify_sync"), (install, "notify"), (client, "retry_pending"),
                                (client, "_persist_job"), (compat, "_materialize"), (compat, "_store_records"),
                                (compat, "_flush"), (capture, "freeze_capture")):
                guards.append(stack.enter_context(mock.patch.object(owner, name, side_effect=AssertionError(name + " is forbidden"))))

            # The native callback uses the freshly reloaded opt-out even when
            # the caller still holds its old enabled ClientConfig instance.
            with mock.patch.object(client, "HookState", side_effect=AssertionError("no hook staging")) as hook_state:
                for action, event in (
                    ("session-start", {"hook_event_name": "SessionStart"}),
                    ("user-prompt-submit", {"hook_event_name": "UserPromptSubmit", "prompt": "Zephyr sapphire read-only query"}),
                ):
                    response = client.handle_hook(stale, action, event)
                    self.assertIn("Zephyr", response["hookSpecificOutput"]["additionalContext"])
                    self.assertIn("untrusted", response["hookSpecificOutput"]["additionalContext"])
                self.assertEqual(client.handle_hook(stale, "stop", stop), {})
                hook_state.assert_not_called()
            self.assertEqual(self.tree(self.root), files_before_hooks)

            query = "Zephyr sapphire new noncaptured input marker"
            read_request = self.request("turn.input", {"continuity_handle": session, "turn_handle": None,
                                                       "visible_user_text": query, "limit": 8})
            first = compat.handle(self.config_path, read_request)
            self.assertEqual(first["status"], "accepted_local", first)
            self.assertEqual(set(first["result"]), {"continuity_handle", "turn_handle", "evidence_context", "network_accessed"})
            readonly_turn = first["result"]["turn_handle"]
            self.assertRegex(readonly_turn, r"^mvt1_[A-Za-z0-9_-]{43}$")
            self.assertEqual(first["result"]["continuity_handle"], session)
            self.assertIn("Zephyr", first["result"]["evidence_context"]["text"])
            self.assertFalse(first["result"]["network_accessed"])
            self.assertFalse(first["authority"]["authorization_eligible"])
            row = self.control_row(readonly_turn)
            self.assertEqual((row["phase"], row["abort_reason"]), ("aborted", "capture_disabled"))
            self.assertTrue(all(row[field] is None for field in (
                "user_text", "assistant_text", "assistant_sha256", "receipt_id", "last_error", "memory_id")))
            with contextlib.closing(compat.CompatState(disabled).connect(writable=False)) as connection:
                self.assertIsNone(connection.execute("SELECT 1 FROM capture_jobs WHERE job_key=?", (readonly_turn,)).fetchone())
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM turns WHERE phase='pending'").fetchone()[0], 1)

            duplicate = compat.handle(self.config_path, copy.deepcopy(read_request))
            self.assertEqual(duplicate["status"], "duplicate", duplicate)
            self.assertEqual(duplicate["result"], first["result"])
            reused = self.request("turn.input", {**read_request["payload"], "turn_handle": readonly_turn})
            self.assertEqual(compat.handle(self.config_path, reused)["result"]["turn_handle"], readonly_turn)
            changed = self.request("turn.input", {**reused["payload"], "visible_user_text": query + " changed"})
            self.assertEqual(compat.handle(self.config_path, changed)["error"]["code"], "conflict")

            # The old bridge aborts the previous handle before its next input.
            # Both exact retry and a later abort reason confirm the empty seal.
            abort = self.request("turn.abort", {"continuity_handle": session, "turn_handle": readonly_turn, "reason": "user_interrupt"})
            self.assertTrue(compat.handle(self.config_path, abort)["result"]["aborted"])
            self.assertEqual(compat.handle(self.config_path, abort)["status"], "duplicate")
            again = self.request("turn.abort", {**abort["payload"], "reason": "host_error"})
            self.assertTrue(compat.handle(self.config_path, again)["result"]["aborted"])
            self.assertEqual(self.control_row(readonly_turn), row)

            old_ack = compat.handle(self.config_path, pending_request)
            self.assertEqual((old_ack["status"], old_ack["result"]["queue_state"]), ("duplicate", "pending"))
            new_commit = self.request("turn.commit", {**pending_request["payload"], "turn_handle": pending_turn})
            self.assertEqual(compat.handle(self.config_path, new_commit)["error"]["code"], "capture_not_enabled")
            self.assertEqual(self.control_row(pending_turn), prior_pending)

            # Starting with capture already off still supplies real local
            # opaque handles to an unchanged old bridge. Compact deliberately
            # avoids exercising the independently authorized sync-open path.
            cold_path = self.root / "readonly.json"
            cold = self.configure(False, path=cold_path)
            cold_open = compat.handle(cold_path, self.request("session.open", {"continuity_handle": None, "reason": "compact"}))
            self.assertEqual(cold_open["status"], "accepted_local", cold_open)
            cold_input = compat.handle(cold_path, self.request("turn.input", {
                "continuity_handle": cold_open["result"]["continuity_handle"], "turn_handle": None,
                "visible_user_text": query, "limit": 8,
            }))
            self.assertIn("Zephyr", cold_input["result"]["evidence_context"]["text"])
            self.assertRegex(cold_input["result"]["turn_handle"], r"^mvt1_[A-Za-z0-9_-]{43}$")
            for config in (disabled, cold):
                self.assertNotIn(query.encode("utf-8"), compat.CompatState(config).path.read_bytes())

            # Re-enabling capture is a new operator decision, not permission
            # to resurrect a handle that never accepted a visible turn.
            self.configure(True)
            sealed_commit = self.request("turn.commit", {"continuity_handle": session, "turn_handle": readonly_turn,
                                         "outcome": "final", "visible_user_text": None,
                                         "visible_assistant_text": "Synthetic late final must not be captured"})
            self.assertEqual(compat.handle(self.config_path, sealed_commit)["error"]["code"], "turn_aborted")
            sealed_input = self.request("turn.input", dict(reused["payload"]))
            self.assertEqual(compat.handle(self.config_path, sealed_input)["error"]["code"], "conflict")
            self.assertEqual(self.control_row(readonly_turn), row)
            self.assertEqual(self.vault_path.read_bytes(), canonical_before)
            for guard in guards:
                guard.assert_not_called()


if __name__ == "__main__":
    unittest.main()
