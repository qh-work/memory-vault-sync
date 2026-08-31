"""One temporary unsigned ten-operation host loop; NOT RUN while authored.

Contract reference: v0.21.0, commit
030ed411ed9ddb969a03f0b5caec87dac9b0dd57, HOST_ADAPTER_PROTOCOL.md and the
production memory_vault_runtime/core.py host_adapter_request implementation.

This exercises the current Python bridge, not the old Git runtime, another
language/model, a native host, crypto or cross-device delivery. The control and
canonical read failures below are injected exceptions, NOT actual hot-journal,
process-kill or power-loss experiments. All runtime paths belong to one explicit
TemporaryDirectory; no identity, trust, sync, account or plugin is configured.
Execution evidence, if subsequently recorded, must identify its exact source.
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

import memory_vault_compat as compat
from memory_vault import MemoryError, Vault, canonical_bytes
from memory_vault_client import CONFIG_SCHEMA, ClientConfig


@unittest.skipUnless(os.name == "posix", "this protected-storage fixture targets POSIX")
class HostProtocolWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="memory-v025-compat-workflow-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.config_path = self.root / "client.json"
        self.vault_path = self.root / "vault.sqlite3"
        self.state_path = self.root / "client.state" / "host-protocol-v1.sqlite3"
        self.sequence = 0
        self.operations: set[str] = set()
        self.configure(capture=True)
        guards = contextlib.ExitStack()
        self.addCleanup(guards.close)
        for target in ("subprocess.Popen", "socket.create_connection", "socket.socket.connect",
                       "memory_vault_client.notify_sync"):
            guards.enter_context(mock.patch(target, side_effect=AssertionError("local fixture must not launch or connect")))
        original = ClientConfig.vault

        def only_selected_fixture(config: ClientConfig, **options):
            self.assertEqual(config.path, self.config_path)
            self.assertEqual(config.vault_path, self.vault_path)
            self.assertIsNone(config.identity_path)
            self.assertIsNone(config.trust_path)
            self.assertIsNone(config.sync_config_path)
            return original(config, **options)

        guards.enter_context(mock.patch.object(ClientConfig, "vault", new=only_selected_fixture))

    def configure(self, *, capture: bool) -> None:
        self.config_path.write_text(json.dumps({
            "schema_version": CONFIG_SCHEMA, "vault_path": str(self.vault_path),
            "capture_visible_turns": capture,
        }), encoding="utf-8")
        self.config_path.chmod(0o600)

    def request(self, operation: str, payload: dict) -> dict:
        self.sequence += 1
        return {
            "schema_version": compat.REQUEST_SCHEMA, "protocol_version": "1.0",
            "request_id": "synthetic.workflow." + str(self.sequence), "operation": operation,
            # Adapter version identifies this fixture, not the tested application.
            "adapter": {"id": "synthetic-workflow", "version": "1.0.0", "host_family": "generic_stdio"},
            "payload": payload,
        }

    def send(self, request: dict) -> dict:
        response = dict(compat.handle(self.config_path, request))
        self.operations.add(request["operation"])
        self.assertEqual(response["request_id"], request["request_id"])
        self.assertEqual(response["operation"], request["operation"])
        self.assertEqual(response["schema_version"], compat.RESPONSE_SCHEMA)
        self.assertEqual(response["protocol_version"], "1.0")
        self.assertEqual(response["authority"], compat._authority())
        for name in ("instruction_eligible", "authorization_eligible", "execution_eligible", "policy_change_eligible"):
            self.assertFalse(response["authority"][name])
        if response["status"] != "rejected":
            self.assertFalse(response["result"].get("network_accessed", False))
            self.assertFalse(response["result"].get("remote_ai_read_verified", False))
        else:
            self.assertEqual(set(response["error"]), {"code", "retryable"})
        return response

    def snapshot(self) -> tuple:
        if not self.vault_path.exists():
            return (), (), ()
        with contextlib.closing(sqlite3.connect(self.vault_path.as_uri() + "?mode=ro", uri=True)) as connection:
            return (
                tuple(connection.execute("SELECT memory_id,record_sha256,record_json FROM memories ORDER BY memory_id")),
                tuple(connection.execute("SELECT request_id,request_sha256,response_json,created_at FROM receipts ORDER BY request_id")),
                tuple(connection.execute("SELECT memory_id,state,signer_key_id,attestation_json FROM record_admissions ORDER BY memory_id")),
            )

    def test_all_ten_operations_preserve_evidence_and_exact_retry(self) -> None:
        capabilities = self.send(self.request("capabilities", {}))
        self.assertEqual(set(capabilities["result"]["operations"]), set(compat.OPERATIONS))
        self.assertFalse(self.state_path.parent.exists())
        self.assertFalse(self.vault_path.exists())
        # A no-work explicit flush must not initialize either database.
        empty_flush = self.send(self.request("sync.flush", {}))
        self.assertEqual(empty_flush["result"]["publication"]["local"],
                         {"saved": 0, "pending": 0, "errors": [], "network_accessed": False})
        self.assertFalse(self.state_path.parent.exists())
        self.assertFalse(self.vault_path.exists())

        open_request = self.request("session.open", {"continuity_handle": None, "reason": "compact"})
        opened = self.send(open_request)
        self.assertEqual(opened["status"], "accepted_local", opened)
        session = opened["result"]["continuity_handle"]
        self.assertEqual(self.send(copy.deepcopy(open_request))["result"], opened["result"])
        user = "Preserve the synthetic Zephyr memory across sessions."
        input_request = self.request("turn.input", {
            "continuity_handle": session, "turn_handle": None, "visible_user_text": user, "limit": 8,
        })
        staged = self.send(input_request)
        self.assertEqual(staged["status"], "accepted_local", staged)
        self.assertIsNone(staged["result"]["evidence_context"])
        turn = staged["result"]["turn_handle"]
        replayed_input = self.send(copy.deepcopy(input_request))
        self.assertEqual(replayed_input["status"], "duplicate")
        self.assertEqual(replayed_input["result"], staged["result"])
        changed_input = copy.deepcopy(input_request)
        changed_input["payload"]["visible_user_text"] += " Different bytes."
        self.assertEqual(self.send(changed_input)["error"]["code"], "conflict")

        commit_request = self.request("turn.commit", {
            "continuity_handle": session, "turn_handle": turn, "outcome": "final",
            "visible_user_text": None, "visible_assistant_text": "Zephyr remains append-only without task ownership.",
        })
        with mock.patch.object(compat, "_store_records", side_effect=MemoryError("synthetic_store_unavailable", retryable=True)):
            accepted = self.send(commit_request)
        self.assertEqual(accepted["status"], "degraded", accepted)
        self.assertEqual(accepted["result"]["queue_state"], "pending")
        self.assertFalse(self.vault_path.exists())
        with mock.patch.object(compat, "_store_records", side_effect=AssertionError("exact ACK replay must not rematerialize")):
            replayed = self.send(copy.deepcopy(commit_request))
        self.assertEqual(replayed["status"], "duplicate")
        self.assertEqual(replayed["result"], accepted["result"])
        changed_commit = copy.deepcopy(commit_request)
        changed_commit["payload"]["visible_assistant_text"] = "A different final answer."
        self.assertEqual(self.send(changed_commit)["error"]["code"], "conflict")
        committed_abort = self.request("turn.abort", {
            "continuity_handle": session, "turn_handle": turn, "reason": "user_interrupt",
        })
        retained = self.send(committed_abort)
        self.assertFalse(retained["result"]["aborted"])
        self.assertEqual(retained["result"]["terminal_state"], "committed")
        self.assertEqual(retained["result"]["queue_state"], "pending")
        close_request = self.request("session.close", {"continuity_handle": session})
        self.assertTrue(self.send(close_request)["result"]["closed"])
        self.assertEqual(self.send(copy.deepcopy(close_request))["status"], "duplicate")

        # Disabled capture can confirm a durable ACK, but cannot turn a failed
        # read into an authorized database-recovery/write operation.
        self.configure(capture=False)
        self.assertEqual(self.send(commit_request)["result"]["queue_state"], "pending")
        with mock.patch.object(compat.CompatState, "connect", side_effect=sqlite3.OperationalError("synthetic read-only journal boundary")), \
                mock.patch.object(compat, "_existing_recovery_connection", side_effect=AssertionError("disabled capture must not recover")):
            disabled = self.send(self.request("sync.flush", {}))
        self.assertEqual(disabled["error"]["code"], "capture_not_enabled")
        self.assertFalse(self.vault_path.exists())
        self.configure(capture=True)

        original_connect = compat.CompatState.connect
        failed_reads = 0

        def first_control_read_fails(state: compat.CompatState, *, writable: bool):
            nonlocal failed_reads
            if not writable and failed_reads == 0:
                failed_reads += 1
                raise sqlite3.OperationalError("synthetic read-only journal boundary")
            return original_connect(state, writable=writable)

        flush_request = self.request("sync.flush", {})
        with mock.patch.object(compat.CompatState, "connect", new=first_control_read_fails), \
                mock.patch.object(compat, "_recover_flush_state", wraps=compat._recover_flush_state) as recovered:
            flushed = self.send(flush_request)
        self.assertEqual(failed_reads, 1)
        self.assertEqual(recovered.call_count, 1)
        self.assertEqual(flushed["status"], "accepted_local", flushed)
        self.assertEqual(flushed["result"]["publication"]["local"],
                         {"saved": 1, "pending": 0, "errors": [], "network_accessed": False})
        self.assertEqual(flushed["result"]["published"], 0)
        self.assertEqual(len(self.snapshot()[0]), 2)
        first_snapshot = self.snapshot()
        replayed = self.send(commit_request)
        self.assertEqual(replayed["result"]["receipt_id"], accepted["result"]["receipt_id"])
        self.assertEqual(replayed["result"]["queue_state"], "done")
        self.assertEqual(self.send(committed_abort)["result"]["queue_state"], "done")
        repeated_flush = self.send(flush_request)
        self.assertEqual(repeated_flush["status"], "accepted_local")
        self.assertEqual(repeated_flush["result"]["publication"]["local"]["saved"], 0)
        self.assertEqual(self.snapshot(), first_snapshot)

        # Same local handle can resume; replaying its old close receipt is not
        # a new close command and must not remove independent canonical Memory.
        resumed = self.send(self.request("session.open", {"continuity_handle": session, "reason": "compact"}))
        self.assertEqual(resumed["result"]["continuity_handle"], session)
        self.assertEqual(self.send(close_request)["status"], "duplicate")
        next_request = self.request("turn.commit", {
            "continuity_handle": session, "turn_handle": None, "outcome": "final",
            "visible_user_text": "Continue synthetic Zephyr evidence on another turn.",
            "visible_assistant_text": "Zephyr continuity refers to its accepted predecessor.",
        })
        with mock.patch.object(compat, "_store_records", side_effect=MemoryError("synthetic_store_unavailable", retryable=True)):
            next_pending = self.send(next_request)
        self.assertEqual(next_pending["status"], "degraded", next_pending)
        self.assertEqual(next_pending["result"]["queue_state"], "pending")

        # Read-only operations never use the explicit-flush recovery helper.
        with mock.patch.object(compat, "_recover_flush_state", side_effect=AssertionError("read path must not recover")):
            self.assertEqual(self.send(next_request)["status"], "duplicate")
            with mock.patch.object(compat.CompatState, "connect", side_effect=sqlite3.OperationalError("synthetic status read failure")):
                read_failure = self.send(self.request("memory.status", {}))
            self.assertEqual(read_failure["status"], "rejected")
        self.assertEqual(self.snapshot(), first_snapshot)

        # Model the second-stage failure too: core._connect wraps its SQLite
        # read error in MemoryError.__cause__. This is still an injected route,
        # not proof of physical rollback-journal or power-loss recovery.
        original_core_connect = Vault._connect
        canonical_failures = 0

        def canonical_read_needs_recovery(vault: Vault, *, writable: bool = True):
            nonlocal canonical_failures
            if not writable and canonical_failures < 2:
                canonical_failures += 1
                try:
                    raise sqlite3.OperationalError("synthetic canonical journal boundary")
                except sqlite3.OperationalError as cause:
                    raise MemoryError("storage_unavailable") from cause
            return original_core_connect(vault, writable=writable)

        with mock.patch.object(Vault, "_connect", new=canonical_read_needs_recovery), \
                mock.patch.object(compat, "_existing_recovery_connection", wraps=compat._existing_recovery_connection) as reopened:
            canonical_flushed = self.send(self.request("sync.flush", {}))
        self.assertEqual(canonical_failures, 2)
        self.assertEqual([call.args[0] for call in reopened.call_args_list], [self.state_path, self.vault_path])
        self.assertEqual(canonical_flushed["status"], "accepted_local", canonical_flushed)
        self.assertEqual(canonical_flushed["result"]["publication"]["local"]["saved"], 1)
        self.assertEqual(len(self.snapshot()[0]), 4)
        self.assertEqual(self.send(next_request)["result"]["queue_state"], "done")

        # Obtain usable episode/source identities from the public recall text,
        # not an internal alias-builder or a pre-seeded implementation fixture.
        recall_request = self.request("memory.recall", {"query": "Zephyr", "limit": 8, "maximum_context_bytes": 8192})
        evidence = self.send(recall_request)["result"]["evidence_context"]
        self.assertIsNotNone(evidence)
        self.assertEqual(evidence["authority"], "none")
        self.assertTrue(evidence["current_user_input_precedence"])
        self.assertLessEqual(len(evidence["text"].encode("utf-8")), 8192)
        labels = [json.loads(line[len("Evidence mapping: "):]) for line in evidence["text"].splitlines()
                  if line.startswith("Evidence mapping: ")]
        anchor = next(label for label in labels if label["legacy_id"].startswith("ep-"))
        proposal = {
            "schema_version": "memory-network-semantic-proposal/v1",
            "source_id": anchor["source_id"], "episode_id": anchor["legacy_id"],
            "kind": "decision", "claim_key": "zephyr-storage", "parents": [], "supersedes": [],
            "conflicts_with": [], "resolves": [],
            "payload": {"statement": "Zephyr storage stays append-only.", "reason": None, "concepts": ["Zephyr", "continuity"]},
        }
        before_remember = self.snapshot()
        mismatched = copy.deepcopy(proposal)
        mismatched["source_id"] = "src-" + "0" * 40
        mismatch = self.send(self.request("memory.remember", {"proposal": mismatched}))
        self.assertEqual(mismatch["error"]["code"], "legacy_evidence_source_mismatch")
        self.assertEqual(self.snapshot(), before_remember)
        remember_request = self.request("memory.remember", {"proposal": proposal})
        remembered = self.send(remember_request)
        self.assertEqual(remembered["status"], "accepted_local", remembered)
        self.assertIsNone(remembered["result"]["remote_commit_sha"])
        self.assertFalse(remembered["result"]["remote_publication_verified"])
        self.assertEqual(remembered["result"]["evidence_mapping"]["memory_id"], anchor["memory_id"])
        semantic_snapshot = self.snapshot()
        for retry in (copy.deepcopy(remember_request), self.request("memory.remember", {"proposal": copy.deepcopy(proposal)})):
            duplicate = self.send(retry)
            self.assertEqual(duplicate["status"], "duplicate")
            self.assertEqual(duplicate["result"]["canonical_memory_id"], remembered["result"]["canonical_memory_id"])
        self.assertEqual(self.snapshot(), semantic_snapshot)

        revision = copy.deepcopy(proposal)
        revision["parents"] = [remembered["result"]["memory_event_id"]]
        revision["supersedes"] = [remembered["result"]["memory_event_id"]]
        revision["payload"]["statement"] = "Zephyr memory remains independent after session closure."
        revised = self.send(self.request("memory.remember", {"proposal": revision}))
        self.assertEqual(revised["status"], "accepted_local", revised)
        records = [json.loads(row[2]) for row in self.snapshot()[0]]
        canonical = next(record for record in records if record["memory_id"] == revised["result"]["canonical_memory_id"])
        edges = {(edge["type"], edge["target"]) for edge in canonical["relations"]}
        self.assertIn(("derived_from", anchor["memory_id"]), edges)
        self.assertIn(("derived_from", remembered["result"]["canonical_memory_id"]), edges)
        self.assertIn(("supersedes", remembered["result"]["canonical_memory_id"]), edges)
        self.assertEqual(canonical["provenance"]["confidence"], "assistant_inferred")
        self.assertEqual(len(records), 6)
        durable_snapshot = self.snapshot()

        status = self.send(self.request("memory.status", {}))
        self.assertEqual(status["result"]["outbox"]["pending"], 0)
        self.assertEqual(status["result"]["outbox"]["done"], 2)
        self.assertEqual(status["result"]["index"]["documents"], 6)
        aborted_input = self.send(self.request("turn.input", {
            "continuity_handle": session, "turn_handle": None, "visible_user_text": "Cancel this incomplete Zephyr turn.", "limit": 8,
        }))
        self.assertNotEqual(aborted_input["status"], "rejected", aborted_input)
        cancel_turn = aborted_input["result"]["turn_handle"]
        abort_request = self.request("turn.abort", {"continuity_handle": session, "turn_handle": cancel_turn, "reason": "cancelled"})
        self.assertTrue(self.send(abort_request)["result"]["aborted"])
        self.assertEqual(self.send(abort_request)["status"], "duplicate")
        rejected_commit = self.send(self.request("turn.commit", {
            "continuity_handle": session, "turn_handle": cancel_turn, "outcome": "final",
            "visible_user_text": None, "visible_assistant_text": "Must not resurrect canceled input.",
        }))
        self.assertEqual(rejected_commit["error"]["code"], "turn_aborted")
        final_close = self.request("session.close", {"continuity_handle": session})
        self.assertTrue(self.send(final_close)["result"]["closed"])
        self.assertEqual(self.send(final_close)["status"], "duplicate")
        after_close = self.send(recall_request)["result"]["evidence_context"]
        self.assertIn(revised["result"]["canonical_memory_id"], after_close["text"])
        self.assertEqual(self.snapshot(), durable_snapshot)
        for record in records:
            encoded = canonical_bytes(record).decode("utf-8")
            for local_handle in (session, turn, next_pending["result"]["turn_handle"], cancel_turn):
                self.assertNotIn(local_handle, encoded)
        with contextlib.closing(sqlite3.connect(self.state_path.as_uri() + "?mode=ro", uri=True)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM turns WHERE user_text IS NOT NULL OR assistant_text IS NOT NULL").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT state FROM sessions WHERE handle=?", (session,)).fetchone()[0], "closed")
        self.assertEqual(self.operations, set(compat.OPERATIONS))


if __name__ == "__main__":
    unittest.main()
