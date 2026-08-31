"""Synthetic frozen-capture contracts; NOT RUN while this file was authored.

Every runtime path is explicitly inside a resolved TemporaryDirectory. These
unsigned fixtures use no credentials, network, installed plugin or real host.
Threads and injected exceptions exercise selected local boundaries, not real
device/power-loss or full platform acceptance. Execution evidence belongs in a
separate, source-pinned report rather than being inferred from these cases.
"""

from __future__ import annotations

import concurrent.futures
import contextlib
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest import mock

import memory_vault_capture as capture
import memory_vault_hosts as hosts
import memory_vault_lifecycle as lifecycle
import memory_vault_manage as manage
import memory_vault_recovery as recovery
import memory_vault_storage as storage
from memory_vault import MemoryError, Vault, canonical_bytes, strict_json_loads
from memory_vault_client import CONFIG_SCHEMA, ClientConfig, _continuity, _digest, _request_id


class FrozenLifecycleCaptureTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="memory-v025-capture-synthetic-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.control = self.root / "control"
        storage.private_directory(self.control)
        self.config_path = self.control / "client.json"
        self.vault_path = self.root / "vault.sqlite3"
        self.configure(True)

    def configure(self, enabled: bool) -> None:
        storage.atomic_write(self.config_path, canonical_bytes({
            "schema_version": CONFIG_SCHEMA, "vault_path": str(self.vault_path),
            "capture_visible_turns": enabled,
        }) + b"\n", replace=self.config_path.exists())

    def config(self) -> ClientConfig:
        return ClientConfig.load(self.config_path)

    @staticmethod
    def request(op: str, identifier: str, **fields: object) -> dict:
        return {"schema_version": lifecycle.REQUEST_SCHEMA, "op": op,
                "request_id": "req_test_" + _digest(identifier), **fields}

    def send(self, request: dict, *, scope: str | None = None, config: Path | None = None) -> dict:
        return dict(lifecycle.handle(config or self.config_path, request, capture_scope=scope))

    def session(self, identifier: str = "synthetic.open", *, scope: str | None = None) -> str:
        response = self.send(self.request("session.open", identifier), scope=scope)
        self.assertTrue(response["ok"], response)
        return response["result"]["session_handle"]

    def stage(self, session: str, label: str, *, scope: str | None = None) -> dict:
        response = self.send(self.request("turn.input", label + ".input", session_handle=session,
                                          user="Synthetic input " + label), scope=scope)
        self.assertTrue(response["ok"], response)
        return self.request("turn.commit", label + ".commit", turn_handle=response["result"]["turn_handle"],
                            assistant="Synthetic final " + label)

    def prepare(self, request: dict, *, scope: str | None = None) -> dict:
        state = lifecycle.LifecycleState(self.config(), capture_scope=scope)
        response, job = state.prepare(lifecycle._validate(request))
        self.assertIsNone(response)
        self.assertIsNotNone(job)
        return dict(job)

    def plan(self, turn: str, *, config: ClientConfig | None = None) -> dict:
        state = lifecycle.LifecycleState(config or self.config())
        with contextlib.closing(sqlite3.connect(state.path.as_uri() + "?mode=ro", uri=True)) as connection:
            connection.row_factory = sqlite3.Row
            plan = capture.load_capture(connection, turn)
        self.assertIsNotNone(plan)
        return dict(plan)

    def record(self, memory_id: str, *, path: Path | None = None) -> dict:
        response = Vault(path or self.vault_path).handle({"op": "get", "memory_id": memory_id})
        self.assertTrue(response["ok"], response)
        self.assertFalse(response["authority"]["execution_eligible"])
        return response["result"]["record"]

    def count(self, *, path: Path | None = None) -> int:
        selected = path or self.vault_path
        if not selected.exists():
            return 0
        with contextlib.closing(sqlite3.connect(selected.as_uri() + "?mode=ro", uri=True)) as connection:
            return int(connection.execute("SELECT COUNT(*) FROM memories").fetchone()[0])

    def test_same_source_uses_frozen_predecessor_not_latest_vault_record(self) -> None:
        session = self.session()
        first_request = self.stage(session, "first")
        first = self.send(first_request)
        self.assertTrue(first["ok"], first)
        unrelated = Vault(self.vault_path).handle({
            "op": "remember", "kind": "continuity", "text": "Synthetic unrelated source.",
            "request_id": "req_synthetic_unrelated",
        })
        self.assertTrue(unrelated["ok"], unrelated)
        second = self.send(self.stage(session, "second"))
        self.assertTrue(second["ok"], second)
        continued = self.record(second["result"]["continuity_id"])
        self.assertEqual(continued["relations"], [
            {"type": "derived_from", "target": second["result"]["episode_id"]},
            {"type": "continues", "target": first["result"]["continuity_id"]},
        ])
        self.assertNotIn(session, canonical_bytes(continued).decode("utf-8"))
        self.assertNotIn(unrelated["result"]["memory_id"], canonical_bytes(continued).decode("utf-8"))
        closed = self.send(self.request("session.close", "synthetic.close", session_handle=session))
        self.assertTrue(closed["ok"], closed)
        self.assertEqual(self.count(), 5)
        self.assertEqual(self.record(first["result"]["episode_id"])["kind"], "episode")

    def test_exact_pending_replay_does_not_rebuild_time_text_or_parent(self) -> None:
        session = self.session()
        request = self.stage(session, "frozen")
        with mock.patch.object(capture, "utc_now", return_value="2026-01-02T03:04:05Z"):
            accepted = self.prepare(request)["capture_plan"]
        with mock.patch.object(lifecycle, "build_turn_projection", side_effect=AssertionError("must reuse frozen bytes")), \
                mock.patch.object(capture, "utc_now", return_value="2027-04-05T06:07:08Z"):
            replay = self.prepare(request)["capture_plan"]
        self.assertEqual(replay, accepted)
        changed = {**request, "assistant": "Different synthetic text"}
        rejected = self.send(changed)
        self.assertFalse(rejected["ok"])
        self.assertEqual(rejected["error"]["code"], "request_id_conflict")
        self.configure(False)
        disabled = self.send(request)
        self.assertFalse(disabled["ok"])
        self.assertEqual(disabled["error"]["code"], "capture_not_enabled")
        self.assertEqual(self.plan(request["turn_handle"]), accepted)
        self.configure(True)
        completed = self.send(request)
        self.assertTrue(completed["ok"], completed)
        self.assertEqual(self.record(completed["result"]["episode_id"])["created_at"], "2026-01-02T03:04:05Z")
        self.assertEqual(self.record(completed["result"]["continuity_id"])["created_at"], "2026-01-02T03:04:05Z")
        self.assertEqual(self.count(), 2)

    def test_two_simultaneous_accepts_share_one_source_sequence(self) -> None:
        session = self.session()
        requests = [self.stage(session, "parallel-a"), self.stage(session, "parallel-b")]
        barrier = threading.Barrier(2)

        def accept(request: dict) -> dict:
            barrier.wait(timeout=5)
            return self.prepare(request)["capture_plan"]

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            plans = list(executor.map(accept, requests))
        plans.sort(key=lambda plan: plan["accepted_sequence"])
        self.assertEqual([plan["accepted_sequence"] for plan in plans], [1, 2])
        self.assertIsNone(plans[0]["predecessor_job_key"])
        self.assertEqual(plans[1]["predecessor_job_key"], plans[0]["job_key"])
        self.assertEqual(plans[1]["previous_continuity_id"], plans[0]["continuity_id"])
        previous = next(ref for ref in plans[0]["record_refs"] if ref["memory_id"] == plans[0]["continuity_id"])
        self.assertEqual(plans[1]["previous_record_sha256"], previous["record_sha256"])
        self.assertEqual(self.count(), 0)

    def test_abort_and_changed_internal_scope_cannot_rewrite_head(self) -> None:
        session = self.session(scope="synthetic:source-a")
        cancelled = self.stage(session, "cancelled", scope="synthetic:source-a")
        aborted = self.send(self.request("turn.abort", "cancelled.abort", turn_handle=cancelled["turn_handle"]),
                            scope="synthetic:source-a")
        self.assertTrue(aborted["ok"], aborted)
        first = self.stage(session, "not-cancelled", scope="synthetic:source-a")
        plan = self.prepare(first, scope="synthetic:source-a")["capture_plan"]
        self.assertEqual(plan["accepted_sequence"], 1)
        self.assertIsNone(plan["previous_continuity_id"])
        before = canonical_bytes(plan)
        rejected = self.send(first, scope="synthetic:source-b")
        self.assertFalse(rejected["ok"])
        self.assertEqual(rejected["error"]["code"], "lifecycle_capture_scope_changed")
        self.assertEqual(canonical_bytes(self.plan(first["turn_handle"])), before)

    def test_bounded_ancestor_drain_keeps_original_outer_receipts_pending(self) -> None:
        session = self.session()
        requests = [self.stage(session, "backlog-" + str(index)) for index in range(7)]
        for request in requests:
            self.prepare(request)
        first_attempt = self.send(requests[-1])
        self.assertFalse(first_attempt["ok"])
        self.assertEqual(first_attempt["error"]["code"], "lifecycle_capture_dependency_pending")
        self.assertTrue(first_attempt["resume_same_request"])
        self.assertEqual(self.count(), 2 * lifecycle.MAX_CAPTURE_WRITES)
        first_plan = self.plan(requests[0]["turn_handle"])
        self.assertEqual(first_plan["state"], "saved")
        self.assertEqual(first_plan["records"], [])
        self.assertIsNone(lifecycle.LifecycleState(self.config()).completed_receipt(requests[0]))
        final = self.send(requests[-1])
        self.assertTrue(final["ok"], final)
        self.assertEqual(self.count(), 14)
        acknowledged = self.send(requests[0])
        self.assertTrue(acknowledged["ok"], acknowledged)
        self.assertEqual(acknowledged["result"]["continuity_id"], first_plan["continuity_id"])
        self.assertEqual(self.count(), 14)

    def test_atomic_canonical_failure_keeps_the_same_accepted_plan(self) -> None:
        session = self.session()
        request = self.stage(session, "atomic")
        accepted = self.prepare(request)["capture_plan"]
        original = Vault._insert_record
        inserted = 0

        def fail_second(connection, record, **arguments):
            nonlocal inserted
            inserted += 1
            if inserted == 2:
                raise MemoryError("synthetic_after_first_record", retryable=True)
            return original(connection, record, **arguments)

        with mock.patch.object(Vault, "_insert_record", new=staticmethod(fail_second)):
            failed = self.send(request)
        self.assertEqual(inserted, 2)
        self.assertFalse(failed["ok"])
        self.assertTrue(failed["resume_same_request"])
        self.assertEqual(self.count(), 0)
        self.assertEqual(self.plan(request["turn_handle"]), accepted)
        completed = self.send(request)
        self.assertTrue(completed["ok"], completed)
        self.assertEqual(completed["result"]["episode_id"], accepted["episode_id"])
        self.assertEqual(completed["result"]["continuity_id"], accepted["continuity_id"])
        self.assertEqual(self.count(), 2)

    def legacy_pending(self) -> tuple[dict, dict, str]:
        """Create a finite public v1 control fixture, not an old application."""
        state = lifecycle.LifecycleState(self.config())
        storage.private_directory(state.path.parent)
        descriptor = storage.open_file(state.path, os.O_CREAT | os.O_EXCL | os.O_RDWR, private=True)
        os.close(descriptor)
        session, turn = "ses_" + "1" * 32, "turn_" + "2" * 32
        opened = self.request("session.open", "legacy.open")
        request = self.request("turn.commit", "legacy.commit", turn_handle=turn, assistant="Synthetic old final")
        user = "Synthetic old input"
        continuity = _continuity(user, request["assistant"], host_visible=False)
        with contextlib.closing(sqlite3.connect(state.path)) as connection, connection:
            for statement in recovery._CONTROL_SQL["lifecycle"].values():
                connection.execute(statement)
            connection.executemany("INSERT INTO meta VALUES(?,?)", [
                ("schema_version", lifecycle.LEGACY_STATE_SCHEMA), ("vault_path_sha256", _digest(str(self.vault_path))),
            ])
            connection.execute("INSERT INTO sessions VALUES(?,'open')", (session,))
            connection.execute("INSERT INTO turns VALUES(?,?,'committing',?,?,?,?)",
                               (turn, session, user, request["assistant"], continuity, _digest(request["request_id"])))
            lifecycle.LifecycleState.save_receipt(connection, opened, {
                "state": "opened", "current_state": "open", "session_handle": session, "memory_saved": False,
            }, session=session)
            connection.execute("INSERT INTO requests VALUES(?,?,NULL,?,?)",
                               (_digest(request["request_id"]), _digest(request), session, turn))
            connection.execute("PRAGMA user_version=1")
        return opened, request, user

    def test_legacy_readonly_receipt_does_not_migrate_or_load_vault(self) -> None:
        opened, _, _ = self.legacy_pending()
        self.configure(False)
        path = lifecycle.LifecycleState(self.config()).path
        before = path.read_bytes()
        with mock.patch.object(ClientConfig, "vault", side_effect=AssertionError("historical receipt does not select a Vault")):
            response = self.send(opened)
            status = manage._lifecycle_status(self.config())
        self.assertTrue(response["ok"], response)
        self.assertTrue(response["replayed"])
        self.assertEqual(status["capture_plans"], {})
        self.assertEqual(path.read_bytes(), before)
        self.assertFalse(self.vault_path.exists())

    def test_legacy_partial_episode_keeps_original_id_and_receipt_after_migration(self) -> None:
        _, request, user = self.legacy_pending()
        legacy = _request_id(request["request_id"], "lifecycle-commit-v1")
        episode_request = _request_id(legacy, "episode")
        observed = self.config().vault(writing=True).handle({
            "op": "observe", "request_id": episode_request, "user": user, "assistant": request["assistant"],
            "provenance": {"source_ref": "lifecycle-caller-reported"},
        })
        self.assertTrue(observed["ok"], observed)
        original_record = self.record(observed["result"]["memory_id"])
        with contextlib.closing(sqlite3.connect(self.vault_path.as_uri() + "?mode=ro", uri=True)) as connection:
            original_receipt = connection.execute("SELECT response_json FROM receipts WHERE request_id=?", (episode_request,)).fetchone()[0]
        completed = self.send(request)
        self.assertTrue(completed["ok"], completed)
        self.assertEqual(completed["result"]["episode_id"], original_record["memory_id"])
        self.assertEqual(self.record(original_record["memory_id"]), original_record)
        self.assertEqual(self.record(completed["result"]["continuity_id"])["relations"], [
            {"type": "derived_from", "target": original_record["memory_id"]},
        ])
        with contextlib.closing(sqlite3.connect(self.vault_path.as_uri() + "?mode=ro", uri=True)) as connection:
            self.assertEqual(connection.execute("SELECT response_json FROM receipts WHERE request_id=?", (episode_request,)).fetchone()[0], original_receipt)
        with contextlib.closing(sqlite3.connect(lifecycle.LifecycleState(self.config()).path.as_uri() + "?mode=ro", uri=True)) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 2)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM capture_jobs").fetchone()[0], 0)
        self.assertEqual(self.count(), 2)

    def test_pending_chain_restore_retains_time_predecessor_and_new_store_boundary(self) -> None:
        session = self.session()
        requests = [self.stage(session, "restore-a"), self.stage(session, "restore-b")]
        for request in requests:
            self.prepare(request)
        originals = [self.plan(request["turn_handle"]) for request in requests]
        snapshot, restored = self.root / "snapshot", self.root / "restored"
        recovery.backup_client(self.config_path, snapshot, include=["lifecycle"], quiesced=True)
        self.assertFalse(self.vault_path.exists())
        report = recovery.restore_client(snapshot, restored, accept_unsigned=True)
        inert = ClientConfig.load(restored / "client.json")
        self.assertFalse(inert.capture_visible_turns)
        resumed_path = restored / "resumed.json"
        with mock.patch.object(lifecycle, "save_turn_projection", side_effect=AssertionError("activation must not replay")):
            recovery.activate_recovery(restored, resumed_path, include=["lifecycle"], authorize_local_resume=True)
        selected = ClientConfig.load(resumed_path)
        self.assertIsNone(selected.identity_path)
        self.assertIsNone(selected.sync_config_path)
        self.assertNotEqual(report["memory"]["new_store_id"], strict_json_loads((snapshot / "manifest.json").read_bytes())["source"]["store_id"])
        for request, original in zip(requests, originals):
            self.assertEqual(self.plan(request["turn_handle"], config=selected), original)
        completed = self.send(requests[-1], config=resumed_path)
        self.assertTrue(completed["ok"], completed)
        self.assertEqual(self.count(path=selected.vault_path), 4)
        continued = self.record(completed["result"]["continuity_id"], path=selected.vault_path)
        self.assertIn({"type": "continues", "target": originals[0]["continuity_id"]}, continued["relations"])
        self.assertFalse(completed["result"]["network_accessed"])

    def test_native_session_reopen_keeps_scope_without_memory_ownership(self) -> None:
        native = {"session_id": "synthetic-reopened-host"}

        def event(name: str, **fields: object) -> dict:
            response = dict(hosts.handle(self.config(), "generic", name, {**native, **fields}))
            self.assertTrue(response["ok"], response)
            return response

        event("session.open")
        event("turn.input", turn_id="first", user="Synthetic first native input")
        event("turn.commit", turn_id="first", assistant="Synthetic first native final")
        session_key = _digest([hosts.PROFILE, "generic", native["session_id"]])
        state = hosts.HostSession(self.config(), "generic", session_key)
        first_handle = state.session()["session_handle"]
        first_key = _digest([hosts.PROFILE, "generic", session_key, "first"])
        first_plan = self.plan(state.turn(first_key)["turn_handle"])
        event("session.close")
        event("session.open")
        second_handle = state.session()["session_handle"]
        self.assertNotEqual(first_handle, second_handle)
        event("turn.input", turn_id="second", user="Synthetic second native input")
        event("turn.commit", turn_id="second", assistant="Synthetic second native final")
        second_key = _digest([hosts.PROFILE, "generic", session_key, "second"])
        second_plan = self.plan(state.turn(second_key)["turn_handle"])
        self.assertEqual(second_plan["scope_key"], first_plan["scope_key"])
        self.assertEqual(second_plan["previous_continuity_id"], first_plan["continuity_id"])
        text = canonical_bytes(self.record(second_plan["continuity_id"])).decode("utf-8")
        for private_reference in (first_handle, second_handle, session_key, native["session_id"]):
            self.assertNotIn(private_reference, text)

if __name__ == "__main__":
    unittest.main()
