"""Synthetic host cancellation recovery cases; execution is recorded separately.

Every path belongs to an independent TemporaryDirectory. Configuration is
unsigned with no keys, sync, native host, installed plugin or external service.
Exceptions and retained artifacts model interruption boundaries; these are not
process-kill, power-loss, cryptographic or real-host acceptance tests.
"""

from __future__ import annotations

import contextlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest import mock

import memory_vault_hosts as hosts
import memory_vault_lifecycle as lifecycle
import memory_vault_manage as manage
from memory_vault_client import CONFIG_SCHEMA, ClientConfig, _digest


class HostCancellationRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="memory-v025-host-recovery-synthetic-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.control = self.root / "control"
        self.control.mkdir(mode=0o700)
        self.config_path = self.control / "client.json"
        self.vault_path = self.root / "vault.sqlite3"
        self.session_id = "synthetic-cancellation-session"
        self.session_key = _digest([hosts.PROFILE, "generic", self.session_id])
        self.configure(capture=True)
        opened = self.event("session.open")
        self.assertTrue(opened["ok"], opened)

    def configure(self, *, capture: bool) -> None:
        self.config_path.write_text(json.dumps({
            "schema_version": CONFIG_SCHEMA, "vault_path": str(self.vault_path),
            "capture_visible_turns": capture,
        }), encoding="utf-8")
        self.config_path.chmod(0o600)

    def config(self) -> ClientConfig:
        return ClientConfig.load(self.config_path)

    def state(self) -> hosts.HostSession:
        return hosts.HostSession(self.config(), "generic", self.session_key)

    def event(self, name: str, turn_id: str | None = None, **fields: object) -> dict:
        value = {"session_id": self.session_id, **fields}
        if turn_id is not None:
            value["turn_id"] = turn_id
        return dict(hosts.handle(self.config(), "generic", name, value))

    def turn_key(self, turn_id: str) -> str:
        return _digest([hosts.PROFILE, "generic", self.session_key, turn_id])

    def pending_path(self, turn_id: str) -> Path:
        request = hosts._request("turn.commit", self.turn_key(turn_id))
        return self.state().path("pending", _digest(request["request_id"]))

    def queue_before_freeze(self, turn_id: str) -> tuple[str, Path, dict]:
        staged = self.event("turn.input", turn_id, user="Synthetic input " + turn_id)
        self.assertTrue(staged["ok"], staged)
        original = hosts.lifecycle_handle

        def unavailable_before_commit(config_path: Path, request: dict) -> dict:
            if request["op"] == "turn.commit":
                return lifecycle._error("synthetic_before_commit", request=request, retryable=True)
            return dict(original(config_path, request))

        with mock.patch.object(hosts, "lifecycle_handle", side_effect=unavailable_before_commit):
            failed = self.event("turn.commit", turn_id, assistant="Synthetic final " + turn_id)
        self.assertFalse(failed["ok"], failed)
        self.assertEqual(failed["error"]["code"], "synthetic_before_commit")
        key = self.turn_key(turn_id)
        path = self.pending_path(turn_id)
        job = self.state().read(path)
        self.assertIsNotNone(job)
        self.assertEqual(self.state().turn(key)["phase"], "staged")
        return key, path, dict(job)

    def recover(self) -> dict:
        response = hosts.handle(self.config(), "generic", "recover", {"session_key": self.session_key})
        self.assertTrue(response["ok"], response)
        self.assertFalse(response["result"]["memory_saved"])
        return dict(response["result"]["recovery"])

    def canonical_count(self) -> int:
        if not self.vault_path.exists():
            return 0
        with contextlib.closing(sqlite3.connect(self.vault_path.as_uri() + "?mode=ro", uri=True)) as connection:
            return int(connection.execute("SELECT COUNT(*) FROM memories").fetchone()[0])

    def test_durable_abort_receipt_finishes_interrupted_cleanup_with_capture_disabled(self) -> None:
        key, path, _ = self.queue_before_freeze("cancel-before-cleanup")
        with mock.patch.object(hosts.HostSession, "finish_abort", side_effect=RuntimeError("synthetic_after_abort_receipt")):
            interrupted = self.event("turn.abort", "cancel-before-cleanup")
        self.assertFalse(interrupted["ok"], interrupted)
        self.assertTrue(path.exists())
        turn = self.state().turn(key)
        request = hosts._request("turn.abort", key, turn_handle=turn["turn_handle"])
        receipt = lifecycle.LifecycleState(self.config()).completed_receipt(request)
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt["result"]["current_state"], "aborted")
        self.configure(capture=False)
        with mock.patch.object(hosts, "lifecycle_handle", side_effect=AssertionError("cleanup must not invoke a lifecycle mutation")):
            result = manage.retry_host(self.config_path, host="generic", session_key=self.session_key)
            repeated = self.recover()
        self.assertEqual(result["processed"], 1)
        self.assertEqual(result["cancelled_cleaned"], 1)
        self.assertEqual(result["attempted"], 0)
        self.assertEqual(result["confirmed"], 0)
        self.assertEqual(result["remaining_jobs"], 0)
        self.assertEqual(result["error_codes"], [])
        self.assertFalse(result["background_sync_may_run"])
        self.assertFalse(path.exists())
        self.assertIsNone(self.state().session()["active_turn"])
        self.assertEqual(repeated["processed"], 0)
        self.assertEqual(repeated["cancelled_cleaned"], 0)
        self.assertEqual(repeated["confirmed"], 0)
        self.assertFalse(self.vault_path.exists())

    def test_phase_and_copied_host_receipt_cannot_authorize_cancellation(self) -> None:
        key, path, _ = self.queue_before_freeze("no-cancel-authority")
        state = self.state()
        turn = state.turn(key)
        turn["phase"] = "aborted"
        with state.locked():
            state.save(state.path("turns", key), turn)
        original_job = path.read_bytes()
        lifecycle_path = lifecycle.LifecycleState(self.config()).path
        original_lifecycle = lifecycle_path.read_bytes()
        request = hosts._request("turn.abort", key, turn_handle=turn["turn_handle"])
        for label, forged_receipt, capture in (("phase_only", False, True), ("copied_host_receipt", True, False)):
            with self.subTest(label=label):
                if forged_receipt:
                    response = lifecycle._ok("turn.abort", {
                        "state": "aborted", "current_state": "aborted",
                        "session_handle": turn["session_handle"], "turn_handle": turn["turn_handle"],
                        "memory_saved": False, "long_term_memory_deleted": False,
                    }, request["request_id"])
                    with state.locked():
                        state.once(state.path("receipts", _digest(request["request_id"])), {
                            "request_sha256": _digest(request), "response": response,
                        })
                self.configure(capture=capture)
                with mock.patch.object(hosts, "lifecycle_handle", side_effect=AssertionError("a phase or host receipt cannot request cancellation")):
                    result = self.recover()
                self.assertEqual(result["processed"], 1)
                self.assertEqual(result["cancelled_cleaned"], 0)
                self.assertEqual(result["attempted"], 0)
                self.assertEqual(result["confirmed"], 0)
                self.assertEqual(result["remaining_jobs"], 1)
                self.assertIn("pending_turn_unavailable_not_resumed", result["error_codes"])
                self.assertEqual(path.read_bytes(), original_job)
                self.assertEqual(lifecycle_path.read_bytes(), original_lifecycle)
                self.assertIsNone(lifecycle.LifecycleState(self.config()).completed_receipt(request))
        self.assertFalse(self.vault_path.exists())

    def test_cancelled_prefix_is_cleaned_in_bounded_batches_before_a_later_final(self) -> None:
        identifiers = sorted(("batch-a", "batch-b", "batch-c"), key=lambda value: self.pending_path(value).name)
        cancelled_jobs: list[tuple[Path, dict]] = []
        for identifier in identifiers[:2]:
            _, path, job = self.queue_before_freeze(identifier)
            aborted = self.event("turn.abort", identifier)
            self.assertTrue(aborted["ok"], aborted)
            self.assertFalse(path.exists())
            cancelled_jobs.append((path, job))
        _, later_path, _ = self.queue_before_freeze(identifiers[2])
        later_job = later_path.read_bytes()
        # Restore only exact synthetic pending artifacts to represent the
        # post-cancellation/pre-cleanup boundary. Lifecycle receipts are real;
        # no process kill, external host or fabricated cancellation is used.
        state = self.state()
        with state.locked():
            for path, job in cancelled_jobs:
                state.once(path, {name: job[name] for name in ("request", "request_sha256", "turn_key")})
        with mock.patch.object(hosts, "MAX_RECOVERY_PER_EVENT", 2):
            with mock.patch.object(hosts, "lifecycle_handle", side_effect=AssertionError("the first bounded batch is cleanup only")):
                first = self.recover()
            self.assertEqual(first["processed"], 2)
            self.assertEqual(first["cancelled_cleaned"], 2)
            self.assertEqual(first["attempted"], 0)
            self.assertEqual(first["confirmed"], 0)
            self.assertEqual(first["remaining_jobs"], 1)
            self.assertEqual(first["error_codes"], [])
            self.assertEqual(later_path.read_bytes(), later_job)
            self.assertEqual(self.canonical_count(), 0)
            self.configure(capture=False)
            disabled = self.recover()
            self.assertEqual(disabled["processed"], 1)
            self.assertEqual(disabled["attempted"], 1)
            self.assertEqual(disabled["confirmed"], 0)
            self.assertEqual(disabled["cancelled_cleaned"], 0)
            self.assertEqual(disabled["remaining_jobs"], 1)
            self.assertIn("capture_not_enabled", disabled["error_codes"])
            self.assertEqual(later_path.read_bytes(), later_job)
            self.assertEqual(self.canonical_count(), 0)
            self.configure(capture=True)
            original_receipt = lifecycle.LifecycleState.completed_receipt
            blocked_cancel_lookups: list[str] = []

            def readonly_cancel_lookup_unavailable(state: lifecycle.LifecycleState, request: dict):
                if request["op"] == "turn.abort":
                    blocked_cancel_lookups.append(request["request_id"])
                    raise sqlite3.OperationalError("synthetic read-only hot-journal boundary")
                return original_receipt(state, request)

            # A simulated read-only lookup error must not strand a legitimate
            # opt-in commit. This is not an actual SQLite/power-loss experiment.
            with mock.patch.object(lifecycle.LifecycleState, "completed_receipt", new=readonly_cancel_lookup_unavailable):
                second = self.recover()
            self.assertEqual(len(blocked_cancel_lookups), 1)
            self.assertEqual(second["processed"], 1)
            self.assertEqual(second["cancelled_cleaned"], 0)
            self.assertEqual(second["attempted"], 1)
            self.assertEqual(second["confirmed"], 1)
            self.assertEqual(second["remaining_jobs"], 0)
            self.assertEqual(second["error_codes"], [])
            self.assertEqual(self.canonical_count(), 2)
            self.assertEqual(self.recover()["confirmed"], 0)
            self.assertEqual(self.canonical_count(), 2)


if __name__ == "__main__":
    unittest.main()
