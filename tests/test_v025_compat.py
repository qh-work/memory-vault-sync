"""Synthetic host-protocol contract cases, provided but NOT run for this release.

All filesystem data lives in temporary fixtures. No account, real Vault,
private signing key, host transcript, executable or network is required.
"""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import memory_vault_compat as compat
from memory_vault import MemoryError, Vault, build_record, canonical_bytes
from memory_vault_client import ClientConfig, CONFIG_SCHEMA


@unittest.skipUnless(os.name == "posix", "protected compatibility fixtures require POSIX")
class HostCompatibilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.config_path = self.root / "client.json"
        self.vault_path = self.root / "vault.sqlite3"
        self.sequence = 0
        self.configure(capture=True)

    def configure(self, *, capture: bool) -> None:
        self.config_path.write_text(json.dumps({
            "schema_version": CONFIG_SCHEMA, "vault_path": str(self.vault_path),
            "capture_visible_turns": capture,
        }), encoding="utf-8")
        self.config_path.chmod(0o600)

    def request(self, operation: str, payload: dict, *, identifier: str | None = None) -> dict:
        self.sequence += 1
        return {"schema_version": compat.REQUEST_SCHEMA, "protocol_version": "1.0",
                "request_id": identifier or "synthetic." + str(self.sequence),
                "operation": operation,
                "adapter": {"id": "synthetic-adapter", "version": "1.0.0", "host_family": "generic_stdio"},
                "payload": payload}

    def call(self, operation: str, payload: dict) -> dict:
        return dict(compat.handle(self.config_path, self.request(operation, payload)))

    def opened(self) -> str:
        response = self.call("session.open", {"continuity_handle": None, "reason": "compact"})
        self.assertEqual(response["status"], "accepted_local", response)
        return response["result"]["continuity_handle"]

    def commit_request(self, session: str, *, turn: str | None = None, user: str | None = "Synthetic question", assistant: str = "Synthetic final answer") -> dict:
        return self.request("turn.commit", {"continuity_handle": session, "turn_handle": turn,
                            "outcome": "final", "visible_user_text": user, "visible_assistant_text": assistant})

    def episode(self) -> dict:
        response = Vault(self.vault_path).handle({"op": "observe", "request_id": "req_fixture_episode_0001",
                                                "user": "Synthetic evidence", "assistant": "Synthetic final result"})
        self.assertTrue(response["ok"], response)
        return dict(Vault(self.vault_path).handle({"op": "get", "memory_id": response["result"]["memory_id"]})["result"]["record"])

    def proposal(self, episode: dict, *, kind: str = "decision", statement: str = "Preserve taskless memory", claim_key: str | None = "storage-direction") -> dict:
        aliases = compat.canonical_alias(episode)
        return {"schema_version": "memory-network-semantic-proposal/v1", "source_id": aliases["source_id"],
                "episode_id": aliases["legacy_id"], "kind": kind, "claim_key": claim_key,
                "parents": [], "supersedes": [], "conflicts_with": [], "resolves": [],
                "payload": {"statement": statement, "reason": None, "concepts": ["memory", "continuity"]}}

    def assert_envelope(self, response: dict) -> None:
        self.assertEqual(response["schema_version"], compat.RESPONSE_SCHEMA)
        self.assertEqual(response["protocol_version"], "1.0")
        self.assertEqual(response["authority"], compat._authority())
        self.assertFalse(response["authority"]["authorization_eligible"])
        self.assertFalse(response["authority"]["execution_eligible"])
        self.assertEqual(set(response), {"schema_version", "protocol_version", "request_id", "operation", "status", "authority",
                                        "error" if response["status"] == "rejected" else "result"})
        if response["status"] == "rejected":
            self.assertEqual(set(response["error"]), {"code", "retryable"})

    def test_capabilities_need_no_configuration_or_database(self) -> None:
        missing = self.root / "not-configured" / "client.json"
        response = dict(compat.handle(missing, self.request("capabilities", {})))
        self.assert_envelope(response)
        self.assertEqual(set(response["result"]["operations"]), set(compat.OPERATIONS))
        self.assertFalse(missing.parent.exists())
        self.assertFalse(self.vault_path.exists())

    def test_all_old_envelopes_are_closed_and_reject_floats(self) -> None:
        request = self.request("memory.recall", {"query": "synthetic", "limit": 1.0, "maximum_context_bytes": 8192})
        response = dict(compat.handle(self.config_path, request))
        self.assert_envelope(response)
        self.assertEqual(response["status"], "rejected")
        request = self.request("memory.status", {"task_id": "not-a-container"})
        self.assertEqual(compat.handle(self.config_path, request)["status"], "rejected")
        request = self.request("session.open", {"continuity_handle": None, "reason": []})
        response = compat.handle(self.config_path, request)
        self.assertFalse(response["error"]["retryable"])
        self.assertFalse(self.vault_path.exists())

    def test_handles_and_request_receipts_are_exact(self) -> None:
        request = self.request("session.open", {"continuity_handle": None, "reason": "compact"})
        first = compat.handle(self.config_path, request)
        second = compat.handle(self.config_path, copy.deepcopy(request))
        self.assertRegex(first["result"]["continuity_handle"], r"^mvc1_[A-Za-z0-9_-]{43}$")
        self.assertEqual(second["status"], "duplicate")
        self.assertEqual(first["result"], second["result"])
        changed = copy.deepcopy(request)
        changed["adapter"]["version"] = "1.0.1"
        conflict = compat.handle(self.config_path, changed)
        self.assertEqual(conflict["error"], {"code": "conflict", "retryable": False})

    def test_post_only_commit_is_local_and_abort_cannot_undo_it(self) -> None:
        session = self.opened()
        request = self.commit_request(session)
        with mock.patch("memory_vault_client.notify_sync", side_effect=AssertionError("must not start a worker")), \
                mock.patch.object(compat, "_flush", side_effect=AssertionError("must not open a sync window")):
            response = dict(compat.handle(self.config_path, request))
        self.assert_envelope(response)
        self.assertEqual(response["result"]["queue_state"], "done")
        self.assertFalse(response["result"]["network_accessed"])
        self.assertEqual(Vault(self.vault_path).handle({"op": "status"})["result"]["records"], 2)
        duplicate = compat.handle(self.config_path, request)
        self.assertEqual(duplicate["status"], "duplicate")
        self.assertEqual(duplicate["result"], response["result"])
        aborted = self.call("turn.abort", {"continuity_handle": session, "turn_handle": response["result"]["turn_handle"], "reason": "host_error"})
        self.assertFalse(aborted["result"]["aborted"])
        self.assertEqual(aborted["result"]["terminal_state"], "committed")
        self.assertEqual(aborted["result"]["queue_state"], "done")

    def test_staged_user_equality_is_nfc_only(self) -> None:
        session = self.opened()
        response = self.call("turn.input", {"continuity_handle": session, "turn_handle": None,
                                           "visible_user_text": "cafe\u0301\r\n", "limit": 8})
        turn = response["result"]["turn_handle"]
        changed = self.commit_request(session, turn=turn, user="café\n")
        self.assertEqual(compat.handle(self.config_path, changed)["error"]["code"], "conflict")
        exact = self.commit_request(session, turn=turn, user="café\r\n")
        self.assertEqual(compat.handle(self.config_path, exact)["result"]["queue_state"], "done")

    def test_abort_discards_only_unaccepted_input(self) -> None:
        session = self.opened()
        staged = self.call("turn.input", {"continuity_handle": session, "turn_handle": None, "visible_user_text": "Not complete", "limit": 8})
        turn = staged["result"]["turn_handle"]
        self.configure(capture=False)
        aborted = self.call("turn.abort", {"continuity_handle": session, "turn_handle": turn, "reason": "user_interrupt"})
        self.assertTrue(aborted["result"]["aborted"])
        closed = self.call("session.close", {"continuity_handle": session})
        self.assertTrue(closed["result"]["closed"])
        self.assertFalse(self.vault_path.exists())

    def test_pending_intent_survives_storage_failure_and_disabled_capture(self) -> None:
        session = self.opened()
        request = self.commit_request(session)
        with mock.patch.object(compat, "_store_records", side_effect=MemoryError("synthetic_storage_error", retryable=True)):
            accepted = compat.handle(self.config_path, request)
        self.assertEqual(accepted["status"], "degraded")
        self.assertEqual(accepted["result"]["queue_state"], "pending")
        self.configure(capture=False)
        duplicate = compat.handle(self.config_path, request)
        self.assertEqual(duplicate["status"], "duplicate")
        self.assertEqual(compat.flush_local(self.config_path)["errors"], ["capture_not_enabled"])
        self.assertFalse(self.vault_path.exists())
        self.configure(capture=True)
        flushed = compat.flush_local(self.config_path)
        self.assertEqual((flushed["saved"], flushed["pending"]), (1, 0))
        self.assertEqual(compat.handle(self.config_path, request)["result"]["queue_state"], "done")
        self.assertEqual(Vault(self.vault_path).handle({"op": "status"})["result"]["records"], 2)

    def test_semantic_claims_keep_typed_relations_and_do_not_claim_git(self) -> None:
        episode = self.episode()
        first = self.call("memory.remember", {"proposal": self.proposal(episode)})
        self.assertEqual(first["status"], "accepted_local")
        self.assertIsNone(first["result"]["remote_commit_sha"])
        self.assertFalse(first["result"]["remote_publication_verified"])
        prior = first["result"]["memory_event_id"]
        changed = self.proposal(episode, statement="Refine the same claim")
        for relation in ("parents", "supersedes", "conflicts_with", "resolves"):
            changed[relation] = [prior]
        stored = self.call("memory.remember", {"proposal": changed})
        record = Vault(self.vault_path).handle({"op": "get", "memory_id": stored["result"]["canonical_memory_id"]})["result"]["record"]
        self.assertIn("claim:v021:storage-direction", record["entities"])
        self.assertIn("semantic:v021:decision", record["entities"])
        self.assertEqual({edge["type"] for edge in record["relations"]}, {"derived_from", "supersedes", "conflicts_with", "resolves"})
        self.assertEqual(record["provenance"]["confidence"], "assistant_inferred")
        self.assertEqual(self.call("memory.remember", {"proposal": changed})["status"], "duplicate")

    def test_every_old_semantic_kind_is_implemented(self) -> None:
        episode = self.episode()
        for kind in compat._KINDS:
            with self.subTest(kind=kind):
                response = self.call("memory.remember", {"proposal": self.proposal(episode, kind=kind)})
                self.assertNotEqual(response["status"], "rejected", response)

    def test_unadmitted_or_mismatched_evidence_is_not_promoted(self) -> None:
        record = build_record(kind="episode", text="Synthetic imported episode", created_at="2026-08-30T00:00:00Z")
        Vault(self.vault_path).ingest_records([record], admission="quarantined")
        rejected = self.call("memory.remember", {"proposal": self.proposal(record)})
        self.assertEqual(rejected["error"]["code"], "evidence_not_admitted")
        episode = self.episode()
        proposal = self.proposal(episode)
        proposal["source_id"] = "src-" + "0" * 40
        self.assertEqual(self.call("memory.remember", {"proposal": proposal})["error"]["code"], "legacy_evidence_source_mismatch")

    def test_large_projection_is_lossless_and_contains_no_host_handles(self) -> None:
        user = "Synthetic visible user. " * 60_000
        assistant = "Synthetic final response. " * 40_000
        records, anchor = compat._episode_records({"user_text": user, "assistant_text": assistant, "created_at": "2026-08-30T00:00:00Z"})
        fragments = [record for record in records if "compat:v021:visible-fragment" in record["entities"]]
        self.assertGreater(len(fragments), 1)
        reconstructed = "".join(json.loads(record["text"].split(":\n", 1)[1]) for record in fragments)
        self.assertEqual(reconstructed, "User:\n" + user + "\n\nAssistant:\n" + assistant)
        root = next(record for record in records if record["memory_id"] == anchor)
        self.assertEqual({edge["target"] for edge in root["relations"]}, {record["memory_id"] for record in fragments})
        encoded = canonical_bytes(records)
        for forbidden in (b"mvc1_", b"mvt1_", b"synthetic-adapter", b"generic_stdio"):
            self.assertNotIn(forbidden, encoded)

    def test_old_512_target_limit_is_projected_without_edge_loss(self) -> None:
        anchor = build_record(kind="episode", text="Synthetic anchor", created_at="2026-08-30T00:00:00Z")
        proposal = self.proposal(anchor)
        targets = {}
        expected = set()
        for group, relation in enumerate(("parents", "supersedes", "conflicts_with", "resolves")):
            for ordinal in range(128):
                suffix = f"{group * 128 + ordinal + 1:040x}"
                alias, target = "evt-" + suffix, "mem_" + suffix
                proposal[relation].append(alias)
                targets[alias] = ({"memory_id": target}, {})
                expected.add((compat._RELATIONS[relation], target))
        records, _ = compat._semantic_records(proposal, anchor, targets, created_at="2026-08-30T00:00:01Z")
        observed = {(edge["type"], edge["target"]) for record in records for edge in record["relations"]}
        self.assertTrue(expected <= observed)
        self.assertTrue(all(len(record["relations"]) <= 256 for record in records))

    def test_recall_and_flush_use_honest_local_shapes(self) -> None:
        self.episode()
        recalled = self.call("memory.recall", {"query": "Synthetic evidence", "limit": 8, "maximum_context_bytes": 8192})
        self.assert_envelope(recalled)
        evidence = recalled["result"]["evidence_context"]
        self.assertIsNotNone(evidence)
        self.assertEqual(set(evidence), {"kind", "content_type", "authority", "instruction_eligible", "authorization_eligible",
                                         "execution_eligible", "current_user_input_precedence", "truncated", "omitted_count", "text"})
        self.assertIn("original_v021_identity", evidence["text"])
        self.assertLessEqual(len(evidence["text"].encode("utf-8")), 8192)
        flushed = self.call("sync.flush", {})
        self.assertEqual(flushed["status"], "accepted_local")
        self.assertEqual(flushed["result"]["published"], 0)
        self.assertFalse(flushed["result"]["remote_ai_read_verified"])

    def test_new_restored_store_cannot_reuse_old_handle_receipts(self) -> None:
        self.episode()
        session_request = self.request("session.open", {"continuity_handle": None, "reason": "compact"})
        self.assertEqual(compat.handle(self.config_path, session_request)["status"], "accepted_local")
        import sqlite3
        with sqlite3.connect(self.vault_path) as connection:
            connection.execute("UPDATE metadata SET value=? WHERE key='store_id'", ("store_" + "f" * 32,))
        response = compat.handle(self.config_path, session_request)
        self.assertEqual(response["status"], "rejected")
        self.assertEqual(response["error"]["code"], "host_vault_changed")


if __name__ == "__main__":
    unittest.main()
