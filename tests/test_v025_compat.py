"""Synthetic host-protocol contract cases, provided but NOT run for this release.

All filesystem data lives in temporary fixtures. No account, real Vault,
private signing key, host transcript, executable or network is required.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import contextlib
import copy
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
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

    def peer_configuration(self) -> Path:
        path = self.root / "peer.json"
        path.write_text(json.dumps({
            "schema_version": CONFIG_SCHEMA, "vault_path": str(self.vault_path),
            "capture_visible_turns": True,
        }), encoding="utf-8")
        path.chmod(0o600)
        return path

    def canonical_snapshot(self) -> tuple:
        with contextlib.closing(sqlite3.connect(self.vault_path.as_uri() + "?mode=ro", uri=True)) as connection:
            return (
                tuple(connection.execute("SELECT memory_id,record_sha256,record_json FROM memories ORDER BY memory_id")),
                tuple(connection.execute("SELECT request_id,request_sha256,response_json,created_at FROM receipts ORDER BY request_id")),
            )

    def semantic_job(self, config_path: Path) -> dict | None:
        connection = compat.CompatState(ClientConfig.load(config_path)).connect(writable=False)
        if connection is None:
            return None
        with contextlib.closing(connection):
            rows = connection.execute("SELECT * FROM semantic_jobs").fetchall()
        self.assertLessEqual(len(rows), 1)
        return dict(rows[0]) if rows else None

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

    def test_two_configurations_reuse_shared_semantic_record_and_original_receipt(self) -> None:
        peer = self.peer_configuration()
        proposal = self.proposal(self.episode())
        with mock.patch.object(compat, "utc_now", return_value="2026-08-30T00:00:01Z"):
            first = self.call("memory.remember", {"proposal": proposal})
        self.assertEqual(first["status"], "accepted_local", first)
        before = self.canonical_snapshot()
        with mock.patch.object(compat, "utc_now", return_value="2026-08-30T00:00:02Z"):
            second = compat.handle(peer, self.request("memory.remember", {"proposal": proposal}))
        self.assertEqual(second["status"], "duplicate", second)
        for field in ("canonical_memory_id", "record_sha256", "memory_event_id"):
            self.assertEqual(second["result"][field], first["result"][field])
        self.assertEqual(second["result"]["state"], "already_recorded")
        self.assertEqual(self.canonical_snapshot(), before)
        self.assertEqual(len(before[0]), 2)
        self.assertEqual(self.semantic_job(peer), self.semantic_job(self.config_path))
        self.assertEqual(self.semantic_job(peer)["created_at"], "2026-08-30T00:00:01Z")
        self.assert_envelope(second)

    def test_simultaneous_first_semantic_writers_share_one_canonical_effect(self) -> None:
        peer = self.peer_configuration()
        proposal = self.proposal(self.episode())
        requests = [self.request("memory.remember", {"proposal": copy.deepcopy(proposal)}) for _ in range(2)]
        rendezvous = threading.Barrier(2)
        local_clock = threading.local()
        original_store = compat._store_records

        def meet_before_shared_transaction(*arguments, **keywords):
            rendezvous.wait(timeout=10)
            return original_store(*arguments, **keywords)

        def writer(config_path: Path, request: dict, timestamp: str) -> dict:
            local_clock.timestamp = timestamp
            return dict(compat.handle(config_path, request))

        with mock.patch.object(compat, "_store_records", side_effect=meet_before_shared_transaction), \
                mock.patch.object(compat, "utc_now", side_effect=lambda: local_clock.timestamp), \
                ThreadPoolExecutor(max_workers=2) as executor:
            futures = [
                executor.submit(writer, self.config_path, requests[0], "2026-08-30T00:00:01Z"),
                executor.submit(writer, peer, requests[1], "2026-08-30T00:00:02Z"),
            ]
            responses = [future.result(timeout=20) for future in futures]
        self.assertCountEqual([response["status"] for response in responses], ["accepted_local", "duplicate"])
        self.assertEqual(responses[0]["result"]["canonical_memory_id"], responses[1]["result"]["canonical_memory_id"])
        self.assertEqual(self.semantic_job(peer), self.semantic_job(self.config_path))
        self.assertEqual(len(self.canonical_snapshot()[0]), 2)
        for response in responses:
            self.assert_envelope(response)

    def test_old_pending_semantic_timestamp_is_reconciled_without_rewriting_memory(self) -> None:
        peer = self.peer_configuration()
        proposal = self.proposal(self.episode())
        first = self.call("memory.remember", {"proposal": proposal})
        original = self.semantic_job(self.config_path)
        self.assertIsNotNone(original)
        with compat.CompatState(ClientConfig.load(peer)).transaction() as connection:
            connection.execute("INSERT INTO semantic_jobs VALUES(?,?,NULL)", (original["proposal_sha256"], "2001-01-01T00:00:00Z"))
        before = self.canonical_snapshot()
        second = compat.handle(peer, self.request("memory.remember", {"proposal": proposal}))
        self.assertEqual(second["status"], "duplicate", second)
        self.assertEqual(second["result"]["canonical_memory_id"], first["result"]["canonical_memory_id"])
        self.assertEqual(self.semantic_job(peer), original)
        self.assertEqual(self.canonical_snapshot(), before)

    def test_semantic_crash_after_shared_commit_reuses_effect_without_local_cache(self) -> None:
        proposal = self.proposal(self.episode())
        request = self.request("memory.remember", {"proposal": proposal})
        original_store = compat._store_records

        def fail_after_shared_commit(*arguments, **keywords):
            original_store(*arguments, **keywords)
            raise MemoryError("synthetic_after_shared_commit", retryable=True)

        with mock.patch.object(compat, "_store_records", side_effect=fail_after_shared_commit), \
                mock.patch.object(compat, "utc_now", return_value="2026-08-30T00:00:01Z"):
            unconfirmed = compat.handle(self.config_path, request)
        self.assertEqual(unconfirmed["status"], "rejected")
        self.assertTrue(unconfirmed["error"]["retryable"])
        self.assertIsNone(self.semantic_job(self.config_path))
        before = self.canonical_snapshot()
        self.assertEqual(len(before[0]), 2)
        with mock.patch.object(compat, "utc_now", return_value="2026-08-30T00:00:02Z"):
            replayed = compat.handle(self.config_path, request)
        self.assertEqual(replayed["status"], "duplicate", replayed)
        self.assertEqual(self.semantic_job(self.config_path)["created_at"], "2026-08-30T00:00:01Z")
        self.assertEqual(self.canonical_snapshot(), before)

    def test_local_completed_job_cannot_bypass_conflicting_shared_receipt(self) -> None:
        proposal = self.proposal(self.episode())
        self.assertEqual(self.call("memory.remember", {"proposal": proposal})["status"], "accepted_local")
        job = self.semantic_job(self.config_path)
        with contextlib.closing(sqlite3.connect(self.vault_path)) as connection, connection:
            connection.execute("UPDATE receipts SET request_sha256=? WHERE request_id=?", ("0" * 64, "req_compat_semantic_" + job["proposal_sha256"]))
        before = self.canonical_snapshot()
        rejected = self.call("memory.remember", {"proposal": proposal})
        self.assertEqual(rejected["status"], "rejected", rejected)
        self.assertEqual(rejected["error"]["code"], "conflict")
        self.assertEqual(self.canonical_snapshot(), before)
        self.assertEqual(self.semantic_job(self.config_path), job)

    def test_local_completed_job_cannot_recreate_a_missing_shared_receipt(self) -> None:
        proposal = self.proposal(self.episode())
        self.assertEqual(self.call("memory.remember", {"proposal": proposal})["status"], "accepted_local")
        job = self.semantic_job(self.config_path)
        with contextlib.closing(sqlite3.connect(self.vault_path)) as connection, connection:
            connection.execute("DELETE FROM receipts WHERE request_id=?", ("req_compat_semantic_" + job["proposal_sha256"],))
        before = self.canonical_snapshot()
        rejected = self.call("memory.remember", {"proposal": proposal})
        self.assertEqual(rejected["status"], "rejected", rejected)
        self.assertEqual(rejected["error"]["code"], "invalid_compat_receipt")
        self.assertEqual(self.canonical_snapshot(), before)

    def test_shared_semantic_receipt_rejects_redirected_anchor_and_extra_response_fields(self) -> None:
        peer = self.peer_configuration()
        episode = self.episode()
        proposal = self.proposal(episode)
        self.assertEqual(self.call("memory.remember", {"proposal": proposal})["status"], "accepted_local")
        request_id = "req_compat_semantic_" + self.semantic_job(self.config_path)["proposal_sha256"]
        with contextlib.closing(sqlite3.connect(self.vault_path.as_uri() + "?mode=ro", uri=True)) as connection:
            original = json.loads(connection.execute("SELECT response_json FROM receipts WHERE request_id=?", (request_id,)).fetchone()[0])
        redirected = copy.deepcopy(original)
        redirected["result"]["memory_id"] = episode["memory_id"]
        redirected["result"]["kind"] = "episode"
        extended = copy.deepcopy(original)
        extended["result"]["unexpected_field"] = False
        for label, response, error in (("anchor", redirected, "conflict"), ("response_fields", extended, "invalid_compat_receipt")):
            with self.subTest(label=label):
                with contextlib.closing(sqlite3.connect(self.vault_path)) as connection, connection:
                    connection.execute("UPDATE receipts SET response_json=? WHERE request_id=?", (canonical_bytes(response).decode("utf-8"), request_id))
                before = self.canonical_snapshot()
                rejected = compat.handle(peer, self.request("memory.remember", {"proposal": proposal}))
                self.assertEqual(rejected["status"], "rejected", rejected)
                self.assertEqual(rejected["error"]["code"], error)
                self.assertEqual(self.canonical_snapshot(), before)

    def _assert_shared_retry_checks_current_admission(self, selected: str) -> None:
        episode = self.episode()
        target = build_record(kind="decision", text="Synthetic earlier decision", created_at="2026-08-30T00:00:01Z")
        Vault(self.vault_path).ingest_records([target], admission="accepted_unsigned")
        proposal = self.proposal(episode)
        proposal["supersedes"] = [compat.canonical_alias(target)["legacy_id"]]
        first = self.call("memory.remember", {"proposal": proposal})
        self.assertEqual(first["status"], "accepted_local", first)
        identifier = {"episode": episode["memory_id"], "target": target["memory_id"],
                      "projection": first["result"]["canonical_memory_id"]}[selected]
        original_store = compat._store_records
        before = self.canonical_snapshot()
        boundary_reached = []

        def quarantine_at_shared_boundary(*arguments, **keywords):
            # Simulate an admission change after alias discovery. No key or
            # signature provider is involved in this unsigned local fixture.
            with contextlib.closing(sqlite3.connect(self.vault_path)) as connection, connection:
                connection.execute("UPDATE record_admissions SET state='quarantined',signer_key_id=NULL,attestation_json=NULL WHERE memory_id=?", (identifier,))
            boundary_reached.append(True)
            return original_store(*arguments, **keywords)

        with mock.patch.object(compat, "_store_records", side_effect=quarantine_at_shared_boundary):
            rejected = self.call("memory.remember", {"proposal": proposal})
        self.assertEqual(boundary_reached, [True])
        self.assertEqual(rejected["status"], "rejected", rejected)
        self.assertEqual(rejected["error"]["code"], "evidence_not_admitted")
        self.assertEqual(self.canonical_snapshot(), before)
        fetched = Vault(self.vault_path).handle({"op": "get", "memory_id": identifier})
        self.assertFalse(fetched["result"]["verification"]["eligible_for_context"])

    def test_semantic_replay_rechecks_episode_admission_in_shared_transaction(self) -> None:
        self._assert_shared_retry_checks_current_admission("episode")

    def test_semantic_replay_rechecks_typed_target_admission_in_shared_transaction(self) -> None:
        self._assert_shared_retry_checks_current_admission("target")

    def test_semantic_replay_does_not_readmit_quarantined_projection(self) -> None:
        self._assert_shared_retry_checks_current_admission("projection")

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
                record = build_record(kind="decision", text=f"Synthetic target {group}:{ordinal}", created_at="2026-08-30T00:00:01Z")
                alias, target = compat.canonical_alias(record)["legacy_id"], record["memory_id"]
                proposal[relation].append(alias)
                targets[alias] = (record, {})
                expected.add((compat._RELATIONS[relation], target))
        records, _ = compat._semantic_records(proposal, anchor, targets, created_at="2026-08-30T00:00:01Z")
        observed = {(edge["type"], edge["target"]) for record in records for edge in record["relations"]}
        self.assertTrue(expected <= observed)
        self.assertTrue(all(len(record["relations"]) <= 256 for record in records))
        Vault(self.vault_path).ingest_records([anchor, *(record for record, _ in targets.values())], admission="accepted_unsigned")
        first = self.call("memory.remember", {"proposal": proposal})
        self.assertEqual(first["status"], "accepted_local", first)
        identifier = first["result"]["canonical_memory_id"]
        root = Vault(self.vault_path).handle({"op": "get", "memory_id": identifier})["result"]["record"]
        parts = [edge["target"] for edge in root["relations"] if edge["target"] != anchor["memory_id"]]
        self.assertEqual(len(parts), 3)
        before = self.canonical_snapshot()
        duplicate = self.call("memory.remember", {"proposal": proposal})
        self.assertEqual(duplicate["status"], "duplicate", duplicate)
        self.assertEqual(duplicate["result"]["canonical_memory_id"], identifier)
        self.assertEqual(self.canonical_snapshot(), before)
        # Corrupt only a non-anchor projection. The valid anchor and shared
        # receipt cannot stand in for validating every stored projection row.
        with contextlib.closing(sqlite3.connect(self.vault_path)) as connection, connection:
            part = json.loads(connection.execute("SELECT record_json FROM memories WHERE memory_id=?", (parts[0],)).fetchone()[0])
            part["text"] = "Synthetic non-anchor corruption"
            connection.execute("UPDATE memories SET record_json=? WHERE memory_id=?", (canonical_bytes(part).decode("utf-8"), parts[0]))
        corrupted = self.canonical_snapshot()
        rejected = self.call("memory.remember", {"proposal": proposal})
        self.assertEqual(rejected["status"], "rejected", rejected)
        self.assertEqual(self.canonical_snapshot(), corrupted)

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
