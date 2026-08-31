"""NOT RUN: synthetic compatibility-capture continuity regression cases.

All paths and unsigned records are fixture-local TemporaryDirectory data. No
real Vault, key/provider, host installation, child process or network is used.
Injected exceptions and local quarantine updates model individual boundaries;
they are not process-crash, cryptographic or cross-device certification. This
file has only been inspected/AST-parsed, not imported or collected as a suite.
Execution requires the reviewer's applicable authorization.
"""

from __future__ import annotations

import contextlib
import copy
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

import memory_vault_capture as capture
import memory_vault_compat as compat
from memory_vault import MemoryError, Vault, build_record, canonical_bytes, sha256
from memory_vault_client import ClientConfig, CONFIG_SCHEMA


@unittest.skipUnless(os.name == "posix", "these private unsigned fixtures use POSIX file modes")
class CompatibilityCaptureTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="memory-vault-compat-capture-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.config_path = self.root / "client.json"
        self.vault_path = self.root / "vault.sqlite3"
        self.sequence = 0
        self.configure(capture_enabled=True)

    def configure(self, *, capture_enabled: bool, path: Path | None = None) -> None:
        selected = path or self.config_path
        selected.write_text(json.dumps({
            "schema_version": CONFIG_SCHEMA, "vault_path": str(self.vault_path),
            "capture_visible_turns": capture_enabled,
        }), encoding="utf-8")
        selected.chmod(0o600)

    def request(self, operation: str, payload: dict) -> dict:
        self.sequence += 1
        return {
            "schema_version": compat.REQUEST_SCHEMA, "protocol_version": "1.0",
            "request_id": "synthetic.capture." + str(self.sequence), "operation": operation,
            "adapter": {"id": "synthetic-adapter", "version": "1.0.0", "host_family": "generic_stdio"},
            "payload": payload,
        }

    def opened(self, *, config_path: Path | None = None) -> str:
        result = compat.handle(config_path or self.config_path, self.request(
            "session.open", {"continuity_handle": None, "reason": "compact"},
        ))
        self.assertEqual(result["status"], "accepted_local", result)
        return result["result"]["continuity_handle"]

    def commit_request(self, session: str, *, label: str = "first", turn: str | None = None) -> dict:
        return self.request("turn.commit", {
            "continuity_handle": session, "turn_handle": turn, "outcome": "final",
            "visible_user_text": "Synthetic question " + label,
            "visible_assistant_text": "Synthetic visible reply " + label,
        })

    def accepted_pending(self, request: dict, *, timestamp: str = "2026-08-31T12:00:00Z") -> dict:
        with mock.patch.object(compat, "utc_now", return_value=timestamp), \
                mock.patch.object(compat, "_store_records", side_effect=MemoryError("synthetic_store_unavailable", retryable=True)):
            result = dict(compat.handle(self.config_path, request))
        self.assertEqual(result["status"], "degraded", result)
        self.assertEqual(result["result"]["queue_state"], "pending", result)
        return result

    def plan(self, turn: str, *, config_path: Path | None = None) -> tuple[dict, dict]:
        state = compat.CompatState(ClientConfig.load(config_path or self.config_path))
        connection = state.connect(writable=False)
        self.assertIsNotNone(connection)
        with contextlib.closing(connection):
            row = dict(connection.execute("SELECT * FROM turns WHERE handle=?", (turn,)).fetchone())
            frozen = capture.load_capture(connection, turn)
        self.assertIsNotNone(frozen)
        return row, frozen

    def record(self, memory_id: str) -> dict:
        result = Vault(self.vault_path).handle({"op": "get", "memory_id": memory_id})
        self.assertTrue(result["ok"], result)
        return dict(result["result"]["record"])

    def snapshot(self) -> tuple:
        with contextlib.closing(sqlite3.connect(self.vault_path.as_uri() + "?mode=ro", uri=True)) as connection:
            return (
                tuple(connection.execute("SELECT memory_id,record_sha256,record_json FROM memories ORDER BY memory_id")),
                tuple(connection.execute("SELECT request_id,request_sha256,response_json,created_at FROM receipts ORDER BY request_id")),
                tuple(connection.execute("SELECT memory_id,state,signer_key_id,attestation_json FROM record_admissions ORDER BY memory_id")),
            )

    def quarantine(self, memory_id: str) -> None:
        # Fixture-only metadata mutation, with no signing provider or key.
        with contextlib.closing(sqlite3.connect(self.vault_path)) as connection, connection:
            connection.execute(
                "UPDATE record_admissions SET state='quarantined',signer_key_id=NULL,attestation_json=NULL WHERE memory_id=?",
                (memory_id,),
            )

    def test_same_scope_adds_only_canonical_continues_and_clears_staging(self) -> None:
        session = self.opened()
        first = compat.handle(self.config_path, self.commit_request(session, label="alpha"))
        second = compat.handle(self.config_path, self.commit_request(session, label="beta"))
        self.assertEqual(first["result"]["queue_state"], "done", first)
        self.assertEqual(second["result"]["queue_state"], "done", second)
        first_row, first_plan = self.plan(first["result"]["turn_handle"])
        second_row, second_plan = self.plan(second["result"]["turn_handle"])
        for row, plan in ((first_row, first_plan), (second_row, second_plan)):
            compat.validate_capture_turn(row, plan)
            self.assertEqual(plan["records"], [])
            self.assertIsNone(row["user_text"])
            self.assertIsNone(row["assistant_text"])
            self.assertEqual(plan["state"], "saved")
            for reference in plan["record_refs"]:
                text = canonical_bytes(self.record(reference["memory_id"])).decode("utf-8")
                self.assertNotIn(session, text)
                self.assertNotIn(row["handle"], text)
                self.assertNotIn("scope_key", text)
        continuation = self.record(second_plan["continuity_id"])
        self.assertEqual({(edge["type"], edge["target"]) for edge in continuation["relations"]}, {
            ("derived_from", second_plan["episode_id"]), ("continues", first_plan["continuity_id"]),
        })
        self.assertEqual(self.record(second_plan["episode_id"])["relations"], [])
        self.assertEqual(second_plan["predecessor_job_key"], first_row["handle"])
        self.assertEqual((first_plan["accepted_sequence"], second_plan["accepted_sequence"]), (1, 2))
        self.assertEqual(set(second["result"]), {"continuity_handle", "turn_handle", "outcome", "receipt_id", "queue_state", "network_accessed"})
        self.assertFalse(second["result"]["network_accessed"])
        self.assertEqual(second["authority"], compat._authority())

    def test_distinct_scopes_and_configurations_do_not_choose_global_latest(self) -> None:
        first_session = self.opened()
        other_session = self.opened()
        first = compat.handle(self.config_path, self.commit_request(first_session, label="alpha"))
        other = compat.handle(self.config_path, self.commit_request(other_session, label="other"))
        peer_path = self.root / "peer.json"
        self.configure(capture_enabled=True, path=peer_path)
        peer_session = self.opened(config_path=peer_path)
        peer = compat.handle(peer_path, self.commit_request(peer_session, label="peer"))
        last = compat.handle(self.config_path, self.commit_request(first_session, label="omega"))
        _, first_plan = self.plan(first["result"]["turn_handle"])
        _, other_plan = self.plan(other["result"]["turn_handle"])
        _, peer_plan = self.plan(peer["result"]["turn_handle"], config_path=peer_path)
        _, last_plan = self.plan(last["result"]["turn_handle"])
        for plan in (first_plan, other_plan, peer_plan):
            self.assertIsNone(plan["predecessor_job_key"])
            self.assertIsNone(plan["previous_continuity_id"])
        self.assertEqual(last_plan["previous_continuity_id"], first_plan["continuity_id"])
        self.assertNotEqual(last_plan["previous_continuity_id"], peer_plan["continuity_id"])
        self.assertNotEqual(last_plan["previous_continuity_id"], other_plan["continuity_id"])

    def test_backwards_clock_flushes_accepted_dependency_before_child_with_limit_one(self) -> None:
        session = self.opened()
        first = self.accepted_pending(self.commit_request(session, label="alpha"), timestamp="2030-01-01T00:00:00Z")
        second = self.accepted_pending(self.commit_request(session, label="beta"), timestamp="2020-01-01T00:00:00Z")
        first_turn, second_turn = first["result"]["turn_handle"], second["result"]["turn_handle"]
        _, before_first = self.plan(first_turn)
        _, before_second = self.plan(second_turn)
        self.assertEqual(before_second["predecessor_job_key"], first_turn)
        with mock.patch.object(compat, "_capture_records", side_effect=AssertionError("must not rebuild a frozen turn")), \
                mock.patch.object(compat, "_episode_records", side_effect=AssertionError("must not rebuild a frozen turn")):
            first_flush = compat.flush_local(self.config_path, limit=1)
            self.assertEqual((first_flush["saved"], first_flush["pending"], first_flush["errors"]), (1, 1, []))
            self.assertEqual(self.plan(first_turn)[0]["phase"], "done")
            self.assertEqual(self.plan(second_turn)[1], before_second)
            second_flush = compat.flush_local(self.config_path, limit=1)
        self.assertEqual((second_flush["saved"], second_flush["pending"], second_flush["errors"]), (1, 0, []))
        self.assertEqual(self.record(before_first["episode_id"])["created_at"], "2030-01-01T00:00:00Z")
        self.assertEqual(self.record(before_second["episode_id"])["created_at"], "2020-01-01T00:00:00Z")
        self.assertIn({"type": "continues", "target": before_first["continuity_id"]}, self.record(before_second["continuity_id"])["relations"])

    def test_interruption_after_shared_commit_reuses_frozen_projection_and_receipt_bytes(self) -> None:
        request = self.commit_request(self.opened())
        with mock.patch.object(capture, "mark_capture_saved", side_effect=MemoryError("synthetic_after_shared_commit", retryable=True)):
            accepted = compat.handle(self.config_path, request)
        self.assertEqual(accepted["result"]["queue_state"], "pending", accepted)
        turn = accepted["result"]["turn_handle"]
        _, frozen = self.plan(turn)
        before = self.snapshot()
        self.assertEqual(len(before[0]), 2)
        with mock.patch.object(compat, "utc_now", return_value="2099-01-01T00:00:00Z"), \
                mock.patch.object(compat, "_capture_records", side_effect=AssertionError("frozen builder must not run")):
            flushed = compat.flush_local(self.config_path)
        self.assertEqual((flushed["saved"], flushed["pending"], flushed["errors"]), (1, 0, []))
        self.assertEqual(self.snapshot(), before)
        row, saved = self.plan(turn)
        self.assertEqual(saved["record_refs"], frozen["record_refs"])
        self.assertEqual(saved["projection_sha256"], frozen["projection_sha256"])
        compat.validate_capture_turn(row, saved)
        replayed = compat.handle(self.config_path, request)
        self.assertEqual(replayed["status"], "duplicate", replayed)
        self.assertEqual(replayed["result"]["turn_handle"], turn)
        self.assertEqual(replayed["result"]["receipt_id"], accepted["result"]["receipt_id"])
        self.assertEqual(replayed["result"]["queue_state"], "done")

    def test_shared_receipt_does_not_readmit_quarantined_nonanchor(self) -> None:
        with mock.patch.object(capture, "mark_capture_saved", side_effect=MemoryError("synthetic_after_shared_commit")):
            accepted = compat.handle(self.config_path, self.commit_request(self.opened()))
        _, plan = self.plan(accepted["result"]["turn_handle"])
        self.quarantine(plan["continuity_id"])
        before = self.snapshot()
        result = compat.flush_local(self.config_path)
        self.assertEqual(result["errors"], ["evidence_not_admitted"])
        self.assertEqual((result["saved"], result["pending"]), (0, 1))
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.plan(plan["job_key"])[1]["state"], "pending")

    def test_existing_quarantined_record_is_not_signed_or_promoted_by_new_receipt(self) -> None:
        accepted = self.accepted_pending(self.commit_request(self.opened()))
        _, plan = self.plan(accepted["result"]["turn_handle"])
        episode = next(record for record in plan["records"] if record["memory_id"] == plan["episode_id"])
        Vault(self.vault_path).ingest_records([episode], admission="quarantined")
        before = self.snapshot()
        with mock.patch.object(Vault, "_set_admission", side_effect=AssertionError("must not readmit existing evidence")):
            result = compat.flush_local(self.config_path)
        self.assertEqual(result["errors"], ["evidence_not_admitted"])
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(len(before[1]), 0)

    def test_predecessor_full_hash_is_checked_not_just_short_memory_id(self) -> None:
        session = self.opened()
        first = compat.handle(self.config_path, self.commit_request(session, label="alpha"))
        self.assertEqual(first["result"]["queue_state"], "done", first)
        accepted = self.accepted_pending(self.commit_request(session, label="beta"))
        turn, plan = self.plan(accepted["result"]["turn_handle"])
        changed = copy.deepcopy(plan)
        original = changed["previous_record_sha256"]
        changed["previous_record_sha256"] = original[:-1] + ("0" if original[-1] != "0" else "1")
        changed["projection_sha256"] = capture.capture_digest(changed, changed["records"])
        state = compat.CompatState(ClientConfig.load(self.config_path))
        with state.transaction() as connection:
            connection.execute("UPDATE capture_jobs SET previous_record_sha256=?,projection_sha256=? WHERE job_key=?", (
                changed["previous_record_sha256"], changed["projection_sha256"], turn["handle"],
            ))
        before = self.snapshot()
        result = compat.flush_local(self.config_path)
        self.assertEqual(result["errors"], ["invalid_capture_predecessor"])
        self.assertEqual(self.snapshot(), before)
        self.assertEqual((result["saved"], result["pending"]), (0, 1))

    def test_predecessor_current_quarantine_blocks_child_without_regrant(self) -> None:
        session = self.opened()
        first = compat.handle(self.config_path, self.commit_request(session, label="alpha"))
        _, first_plan = self.plan(first["result"]["turn_handle"])
        self.accepted_pending(self.commit_request(session, label="beta"))
        self.quarantine(first_plan["continuity_id"])
        before = self.snapshot()
        result = compat.flush_local(self.config_path)
        self.assertEqual(result["errors"], ["evidence_not_admitted"])
        self.assertEqual((result["saved"], result["pending"]), (0, 1))
        self.assertEqual(self.snapshot(), before)

    def test_legacy_v1_receipt_is_readonly_and_pending_keeps_old_projection(self) -> None:
        session = self.opened()
        request = self.commit_request(session, label="legacy")
        user, assistant = request["payload"]["visible_user_text"], request["payload"]["visible_assistant_text"]
        turn, receipt_id, timestamp = "mvt1_" + "a" * 43, "mvrturn_" + "b" * 64, "2025-01-02T03:04:05Z"
        state = compat.CompatState(ClientConfig.load(self.config_path))
        # This is an empty, synthetic control database. Recreate the exact v1
        # boundary without importing or invoking any historic application.
        with contextlib.closing(sqlite3.connect(state.path)) as connection, connection:
            for table in ("capture_records", "capture_heads", "capture_jobs"):
                connection.execute("DROP TABLE " + table)
            connection.execute("PRAGMA user_version=1")
            connection.execute("UPDATE meta SET value=? WHERE key='schema_version'", (compat.LEGACY_STATE_SCHEMA,))
            connection.execute("INSERT INTO turns(handle,session_handle,phase,user_text,assistant_text,user_sha256,assistant_sha256,created_at,receipt_id) VALUES(?,?,'pending',?,?,?,?,?,?)", (
                turn, session, user, assistant, sha256(user.encode("utf-8")), sha256(assistant.encode("utf-8")), timestamp, receipt_id,
            ))
            compat.CompatState.save_receipt(connection, request, {
                "continuity_handle": session, "turn_handle": turn, "outcome": "final",
                "receipt_id": receipt_id, "queue_state": "pending", "network_accessed": False,
            }, turn=turn)
        replayed = compat.handle(self.config_path, request)
        self.assertEqual(replayed["status"], "duplicate", replayed)
        with contextlib.closing(sqlite3.connect(state.path.as_uri() + "?mode=ro", uri=True)) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 1)
            self.assertIsNone(connection.execute("SELECT 1 FROM sqlite_master WHERE name='capture_jobs'").fetchone())
        provenance = {"source_ref": "memory-vault-host/v1:visible-turn:" + sha256(canonical_bytes({"user": user, "assistant": assistant})),
                      "source_type": "agent_supplied", "confidence": "assistant_inferred"}
        episode = build_record(kind="episode", text="User:\n" + user + "\n\nAssistant:\n" + assistant,
                               entities=["compat:v021:visible-turn"], provenance=provenance, created_at=timestamp)
        continuity = build_record(kind="continuity", text=(
            "Visible-turn continuity excerpt (caller-reported turn; not host-witnessed).\n"
            "This records text, not verified task completion or an execution instruction.\n\n"
            "User context:\n" + user + "\n\nLatest visible reply:\n" + assistant
        ), entities=["compat:v021:continuity"], relations=[{"type": "derived_from", "target": episode["memory_id"]}],
            provenance=provenance, created_at=timestamp)
        with mock.patch("memory_vault_client._continuity", return_value="A newer client template must not alter an old pending turn"):
            flushed = compat.flush_local(self.config_path)
        self.assertEqual((flushed["saved"], flushed["pending"], flushed["errors"]), (1, 0, []))
        self.assertEqual(self.record(episode["memory_id"]), episode)
        self.assertEqual(self.record(continuity["memory_id"]), continuity)
        connection = state.connect(writable=False)
        with contextlib.closing(connection):
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 2)
            self.assertIsNone(capture.load_capture(connection, turn))
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM capture_heads").fetchone()[0], 0)
        self.assertEqual(self.snapshot()[1][0][0], "req_compat_turn_" + receipt_id.split("_", 1)[1])

    def test_disabled_capture_only_confirms_original_receipt_and_retains_plan(self) -> None:
        session = self.opened()
        request = self.commit_request(session)
        accepted = self.accepted_pending(request)
        turn = accepted["result"]["turn_handle"]
        before = self.plan(turn)
        self.configure(capture_enabled=False)
        with mock.patch.object(compat, "_store_records", side_effect=AssertionError("capture disabled")), \
                mock.patch("memory_vault_client.notify_sync", side_effect=AssertionError("must not notify a worker")):
            duplicate = compat.handle(self.config_path, request)
            self.assertEqual(duplicate["status"], "duplicate", duplicate)
            result = compat.flush_local(self.config_path)
            rejected = compat.handle(self.config_path, self.commit_request(session, label="new"))
        self.assertEqual(result["errors"], ["capture_not_enabled"])
        self.assertEqual(rejected["error"]["code"], "capture_not_enabled")
        self.assertEqual(self.plan(turn), before)
        self.assertFalse(self.vault_path.exists())

    def test_changed_request_or_committed_turn_does_not_advance_capture_head(self) -> None:
        session = self.opened()
        request = self.commit_request(session)
        accepted = self.accepted_pending(request)
        turn = accepted["result"]["turn_handle"]
        before = self.plan(turn)
        changed = copy.deepcopy(request)
        changed["payload"]["visible_assistant_text"] = "Different visible reply"
        self.assertEqual(compat.handle(self.config_path, changed)["error"]["code"], "conflict")
        different_request = self.commit_request(session, turn=turn)
        different_request["payload"]["visible_assistant_text"] = "Different visible reply"
        self.assertEqual(compat.handle(self.config_path, different_request)["error"]["code"], "conflict")
        self.assertEqual(self.plan(turn), before)
        connection = compat.CompatState(ClientConfig.load(self.config_path)).connect(writable=False)
        with contextlib.closing(connection):
            self.assertEqual(tuple(connection.execute("SELECT accepted_sequence,last_job_key FROM capture_heads").fetchone()), (1, turn))
        self.assertFalse(self.vault_path.exists())


    def test_signing_configuration_failure_has_no_unsigned_fallback(self) -> None:
        # This is a failure-routing guard, not a cryptographic/provider test.
        # No key/trust file is created or opened; the write boundary fails
        # before any provider is entered.
        identity_path = self.root / "never-created-identity.json"
        trust_path = self.root / "never-created-trust.json"
        self.config_path.write_text(json.dumps({
            "schema_version": CONFIG_SCHEMA, "vault_path": str(self.vault_path),
            "capture_visible_turns": True, "identity_path": str(identity_path), "trust_path": str(trust_path),
        }), encoding="utf-8")
        self.config_path.chmod(0o600)
        session = self.opened()
        original = ClientConfig.vault
        writes: list[tuple[Path | None, Path | None]] = []

        def fail_configured_writer(config, *, writing=False, **keywords):
            if writing:
                writes.append((config.identity_path, config.trust_path))
                raise MemoryError("synthetic_signing_unavailable")
            return original(config, writing=writing, **keywords)

        with mock.patch.object(ClientConfig, "vault", new=fail_configured_writer):
            accepted = compat.handle(self.config_path, self.commit_request(session))
            self.assertEqual(accepted["result"]["queue_state"], "pending", accepted)
            result = compat.flush_local(self.config_path)
        self.assertEqual(result["errors"], ["synthetic_signing_unavailable"])
        self.assertEqual(writes, [(identity_path, trust_path), (identity_path, trust_path)])
        self.assertFalse(self.vault_path.exists())
        self.assertFalse(identity_path.exists())
        self.assertFalse(trust_path.exists())


if __name__ == "__main__":
    unittest.main()
