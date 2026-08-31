"""Bounded retrieval-diversity regressions; NOT RUN while authored.

The old behavior reference is v0.21.0 / 030ed411ed9ddb969a03f0b5caec87dac9b0dd57,
memory_vault_runtime/memory_network.py:1480-1544: source/kind quotas and
token-set Jaccard near-duplicate suppression. These cases exercise the current
Python implementation against explicit resolved temporary SQLite paths only.
There is no old-runtime execution, model, native host, configuration, network,
installation, private memory or real signing key.

The last case uses an explicitly shape-only signer and injected trust callback:
it checks the core's admission policy, NOT cryptographic verification or key
custody. Apart from these documented injection seams and safety guards, no
retrieval, ranking, storage, source grouping or diversity result is replaced.
Execution evidence must be recorded separately against an exact source commit.
"""

from __future__ import annotations

import contextlib
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest import mock

import memory_vault as core


COMMON = "alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima mike november oscar papa quebec romeo sierra tango uniform victor whiskey xray yankee zulu"


class RetrievalDiversityTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="memory-v025-diversity-")
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name).resolve() / "vault.sqlite3"
        self.vault = core.Vault(self.path)
        guards = contextlib.ExitStack()
        self.addCleanup(guards.close)
        for target in ("subprocess.Popen", "socket.create_connection", "socket.socket.connect"):
            guards.enter_context(mock.patch(target, side_effect=AssertionError("synthetic retrieval must remain local")))

    def record(self, text: str, *, source: str | None = None, kind: str = "fact",
               relations: list[dict[str, str]] | None = None) -> dict:
        provenance = {"source_type": "agent_supplied", "confidence": "assistant_inferred"}
        if source is not None:
            provenance["source_ref"] = source
        return core.build_record(kind=kind, text=text, provenance=provenance,
                                 relations=relations or [], created_at="2026-01-01T00:00:00Z")

    def ingest(self, records: list[dict]) -> None:
        result = self.vault.ingest_records(records, admission="accepted_unsigned")
        self.assertEqual(result["records_added"], len(records))

    def recall(self, query: str, *, semantic: bool = False, limit: int = 8) -> dict:
        response = self.vault.handle({"op": "recall", "query": query, "semantic": semantic, "limit": limit})
        self.assertTrue(response["ok"], response)
        self.assertEqual(response["authority"], core.AUTHORITY)
        self.assertFalse(response["authority"]["execution_eligible"])
        return dict(response["result"])

    def snapshot(self) -> tuple:
        with contextlib.closing(sqlite3.connect(self.path.as_uri() + "?mode=ro", uri=True)) as connection:
            return (
                tuple(connection.execute("SELECT memory_id,record_sha256,record_json FROM memories ORDER BY memory_id")),
                tuple(connection.execute("SELECT memory_id,state,signer_key_id FROM record_admissions ORDER BY memory_id")),
                tuple(connection.execute("SELECT * FROM delivery_log ORDER BY sequence")),
            )

    def test_near_duplicates_leave_room_for_distinct_evidence_in_both_modes(self) -> None:
        duplicates = [self.record("Needle " + COMMON + f" variant-{index}") for index in range(8)]
        distinct = self.record("Needle " + " ".join(f"different-topic-{index}" for index in range(60)))
        self.ingest([*duplicates, distinct])
        original = self.snapshot()
        duplicate_ids = {record["memory_id"] for record in duplicates}
        for semantic in (True, False):
            # Disabled concept scoring must stay disabled; the diversity guard
            # checks polarity directly instead of silently invoking an adapter.
            guard = contextlib.nullcontext() if semantic else mock.patch.object(
                core, "semantic_features", side_effect=AssertionError("semantic mode is disabled"),
            )
            with self.subTest(semantic=semantic), guard:
                result = self.recall("Needle", semantic=semantic)
            identifiers = {hit["memory_id"] for hit in result["hits"]}
            self.assertEqual(len(identifiers & duplicate_ids), 1)
            self.assertIn(distinct["memory_id"], identifiers)
            self.assertEqual(len(identifiers), 2)
            self.assertEqual(result["retrieval"]["candidate_records"], 9)
            self.assertFalse(result["retrieval"]["truncated"])
            self.assertTrue(all(hit["verification"]["eligible_for_context"] for hit in result["hits"]))
        self.assertEqual(self.snapshot(), original)

    def test_source_quotas_do_not_own_memory_or_erase_polarity_and_states(self) -> None:
        source = "synthetic:visible-evidence-source"
        same_source = [self.record(f"QuotaNeedle independent-note-{index}", source=source) for index in range(6)]
        no_source = [self.record(f"AbsentNeedle independent-note-{index}") for index in range(6)]
        episodes = [self.record(f"EpisodeNeedle visible-round-{index}", source=source, kind="episode") for index in range(4)]
        positive = self.record("PolarityNeedle " + COMMON, source=source)
        negative = self.record("PolarityNeedle " + COMMON + " never", source=source)
        historical = self.record("PolarityNeedle " + COMMON + " historical", source=source)
        resolved = self.record("PolarityNeedle " + COMMON + " settled", source=source)
        conflicted = self.record("PolarityNeedle " + COMMON + " disputed", source=source)
        retire = self.record("Unrelated explicit historical retirement", relations=[
            {"type": "supersedes", "target": historical["memory_id"]},
            {"type": "resolves", "target": resolved["memory_id"]},
        ])
        alternative = self.record("Unrelated explicit disputed alternative", relations=[
            {"type": "conflicts_with", "target": conflicted["memory_id"]},
        ])
        all_records = [*same_source, *no_source, *episodes, positive, negative, historical, resolved, conflicted, retire, alternative]
        self.ingest(all_records)
        original = self.snapshot()
        self.assertEqual(len(self.recall("QuotaNeedle")["hits"]), 4)
        self.assertEqual(len(self.recall("EpisodeNeedle")["hits"]), 2)
        self.assertEqual({hit["memory_id"] for hit in self.recall("AbsentNeedle")["hits"]},
                         {record["memory_id"] for record in no_source})
        protected = {record["memory_id"] for record in (positive, negative, historical, resolved, conflicted)}
        for semantic in (True, False):
            result = self.recall("PolarityNeedle", semantic=semantic, limit=16)
            hits = {hit["memory_id"]: hit for hit in result["hits"]}
            self.assertTrue(protected.issubset(hits), hits)
            self.assertEqual(hits[positive["memory_id"]]["status"], "current")
            self.assertEqual(hits[negative["memory_id"]]["status"], "current")
            self.assertEqual(hits[historical["memory_id"]]["status"], "superseded")
            self.assertEqual(hits[resolved["memory_id"]]["status"], "resolved")
            self.assertEqual(hits[conflicted["memory_id"]]["status"], "conflicted")
        # Quotas are ephemeral ranking choices, not deletion/admission/ownership.
        self.assertEqual(self.snapshot(), original)
        for record in all_records:
            response = self.vault.handle({"op": "get", "memory_id": record["memory_id"]})
            self.assertTrue(response["ok"], response)
            self.assertEqual(response["result"]["record"], record)
            self.assertTrue(response["result"]["verification"]["eligible_for_context"])

    def test_current_stronger_evidence_survives_unsigned_copy_and_source_quota(self) -> None:
        active = [True]
        key_id = "ed25519_" + "1" * 64

        def current_trust(observed: str) -> None:
            self.assertEqual(observed, key_id)
            if not active[0]:
                raise ValueError("synthetic revoked signer")

        def shape_only_signer(record: dict) -> dict:
            return {"schema_version": core.ATTESTATION_SCHEMA, "key_id": key_id,
                    "record_sha256": record["record_sha256"],
                    "signature": "SYNTHETIC-SHAPE-ONLY-NOT-A-CRYPTOGRAPHIC-SIGNATURE"}

        source = "synthetic:shared-source-label-is-not-authority"
        signed = core.Vault(self.path, signer=shape_only_signer, trust_check=current_trust)
        protected = []
        for text in ("TrustNeedle " + COMMON + " original", "TrustNeedle independently-preserved signed-fact"):
            response = signed.handle({"op": "remember", "kind": "fact", "text": text,
                                      "provenance": {"source_ref": source}})
            self.assertTrue(response["ok"], response)
            protected.append(response["result"]["memory_id"])
        self.vault = core.Vault(self.path, trust_check=current_trust)
        # The copy has higher query frequency, but cannot suppress its stronger
        # near-duplicate. Other unsigned claims reuse the exact source label.
        copy = self.record("TrustNeedle " * 100 + COMMON + " copied", source=source)
        weaker = [self.record("TrustNeedle " * 8 + f"independent-unsigned-note-{index}", source=source) for index in range(6)]
        self.ingest([copy, *weaker])
        original = self.snapshot()
        result = self.recall("TrustNeedle")
        identifiers = {hit["memory_id"] for hit in result["hits"]}
        self.assertTrue(set(protected).issubset(identifiers), result)
        self.assertNotIn(copy["memory_id"], identifiers)
        self.assertEqual(len(identifiers), 4)
        self.assertTrue(all(hit["verification"]["current_trust_checked"]
                            for hit in result["hits"] if hit["memory_id"] in protected))
        active[0] = False
        revoked = self.recall("TrustNeedle")
        revoked_ids = {hit["memory_id"] for hit in revoked["hits"]}
        self.assertTrue(set(protected).isdisjoint(revoked_ids))
        self.assertIn(copy["memory_id"], revoked_ids)
        self.assertTrue(all(hit["verification"]["admission"] == "accepted_unsigned" for hit in revoked["hits"]))
        self.assertEqual(self.snapshot(), original)


if __name__ == "__main__":
    unittest.main()
