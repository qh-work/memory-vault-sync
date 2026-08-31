"""Synthetic entity/context-boundary cases; NOT RUN while this file was authored.

All data paths are explicit resolved TemporaryDirectory paths. No real client
configuration, memory, keys, host, network or installation is used. The shape-only
signer below exercises the injected admission boundary, not cryptographic proof.
Execution evidence, if any, must be recorded separately against exact source.
"""

from __future__ import annotations

import contextlib
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest import mock

import memory_vault as core


class EntityRetrievalTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="memory-v025-entity-synthetic-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.path = self.root / "vault.sqlite3"
        self.vault = core.Vault(self.path)

    def ask(self, operation: str, **arguments: object) -> dict:
        response = self.vault.handle({"op": operation, **arguments})
        self.assertTrue(response["ok"], response)
        self.assertFalse(response["authority"]["execution_eligible"])
        return dict(response["result"])

    def remember(self, text: str, *, kind: str = "fact", entities: list[str] | None = None,
                 relations: list[dict[str, str]] | None = None) -> str:
        return str(self.ask("remember", kind=kind, text=text, entities=entities or [],
                            relations=relations or [])["memory_id"])

    def delivery_count(self) -> int:
        with contextlib.closing(sqlite3.connect(self.path.as_uri() + "?mode=ro", uri=True)) as connection:
            return int(connection.execute("SELECT COUNT(*) FROM delivery_log").fetchone()[0])

    def test_plain_entity_only_match_survives_both_semantic_modes(self) -> None:
        label = "opaque-locator-731"
        body = "An unrelated fixture statement."
        memory_id = self.remember(body, entities=[label])
        original = self.ask("get", memory_id=memory_id)["record"]
        before = self.delivery_count()
        for semantic in (True, False):
            with self.subTest(semantic=semantic):
                result = self.ask("recall", query=label, semantic=semantic)
                self.assertEqual([hit["memory_id"] for hit in result["hits"]], [memory_id])
                hit = result["hits"][0]
                self.assertEqual(hit["text"], body)
                self.assertEqual(hit["fragment"]["text"], body)
                self.assertEqual(hit["matched_tokens"], 1)
                self.assertGreater(hit["score_components"]["entity_milli"], 0)
                self.assertEqual(hit["score_components"]["semantic_milli"], 0)
                self.assertIn("entity_lexical_match", hit["explanation"])
                self.assertFalse(result["retrieval"]["truncated"])
                self.assertEqual(result["retrieval"]["fragments_scanned"], 1)
        self.assertEqual(self.ask("get", memory_id=memory_id)["record"], original)
        self.assertEqual(self.delivery_count(), before)

    def test_opaque_claim_key_finds_the_same_entity_timeline(self) -> None:
        entity = "claim:v021:opaque-locator-731"
        memory_id = self.remember("A synthetic matter with an explicit association.", entities=[entity])
        exact = self.ask("memory.views", entity=entity)["views"][0]
        searched = self.ask("memory.views", query="opaque-locator-731")["views"][0]
        self.assertEqual(searched["view_id"], exact["view_id"])
        self.assertEqual([item["memory_id"] for item in searched["timeline"]], [memory_id])
        self.assertEqual(searched["grouping"], "exact_entity")
        self.assertFalse(searched["inferred_grouping_is_ownership"])
        self.assertEqual(searched["authority"], "none")

    def test_matching_entity_tail_is_not_lost_to_query_token_bound(self) -> None:
        # A valid short-byte CJK label can contain more tokens than a query.
        label = "甲" * 150 + "末尾"
        memory_id = self.remember("An unrelated synthetic label-tail fixture.", entities=[label])
        result = self.ask("recall", query="末尾", semantic=False)
        self.assertEqual([hit["memory_id"] for hit in result["hits"]], [memory_id])
        self.assertIn("entity_lexical_match", result["hits"][0]["explanation"])

    def test_text_match_uses_the_last_scoring_slot_before_entity_fallback(self) -> None:
        label = "opaque-locator-731"
        direct = self.remember(label + " appears in the visible statement.")
        fallback = self.remember("A separately associated synthetic statement.", entities=[label])
        self.remember("An unrelated synthetic statement with no association.")
        for semantic in (True, False):
            with self.subTest(semantic=semantic), mock.patch.object(core, "MAX_RERANK_FRAGMENTS", 1):
                result = self.ask("recall", query=label, semantic=semantic, limit=8)
                self.assertEqual([hit["memory_id"] for hit in result["hits"]], [direct])
                self.assertNotIn(fallback, [hit["memory_id"] for hit in result["hits"]])
                self.assertEqual(result["retrieval"]["fragments_scanned"], 1)
                self.assertTrue(result["retrieval"]["truncated"])

    def test_repeated_entity_terms_do_not_inflate_score_or_match_substrings(self) -> None:
        label = "opaque-locator-731"
        once = self.remember("Synthetic single-label statement.", entities=[label])
        repeated = self.remember("Synthetic many-label statement.",
                                 entities=[label + " alias" + str(index) for index in range(16)])
        unrelated = self.remember("Synthetic differently associated statement.", entities=[label + "-suffix"])
        result = self.ask("recall", query=label, semantic=False, limit=8)
        hits = {hit["memory_id"]: hit for hit in result["hits"]}
        self.assertEqual(set(hits), {once, repeated})
        self.assertNotIn(unrelated, hits)
        self.assertEqual(hits[once]["score_components"]["entity_milli"],
                         hits[repeated]["score_components"]["entity_milli"])
        self.assertEqual(hits[once]["matched_tokens"], 1)
        self.assertEqual(hits[repeated]["matched_tokens"], 1)

    def test_entity_match_does_not_admit_quarantined_content(self) -> None:
        label = "opaque-locator-731"
        hidden = core.build_record(kind="fact", text="A quarantined fixture statement.", entities=[label],
                                   created_at="2026-01-01T00:00:00Z")
        self.vault.ingest_records([hidden])
        before = self.delivery_count()
        for semantic in (True, False):
            self.assertEqual(self.ask("recall", query=label, semantic=semantic)["hits"], [])
        self.assertEqual(self.ask("memory.views", entity=label)["views"], [])
        self.assertEqual(self.ask("get", memory_id=hidden["memory_id"])["status"], "quarantined")
        self.assertEqual(self.delivery_count(), before)

    def test_handoff_filters_quarantined_target_without_changing_canonical_memory(self) -> None:
        hidden = core.build_record(kind="fact", text="A quarantined fixture target.",
                                   created_at="2026-01-01T00:00:00Z")
        self.vault.ingest_records([hidden])
        episode = self.ask("observe", user="Synthetic visible input.", assistant="Synthetic visible final.")["memory_id"]
        raw_relations = [{"type": "derived_from", "target": episode},
                         {"type": "related_to", "target": hidden["memory_id"]}]
        continued = self.remember("Synthetic continued visible state.", kind="continuity", relations=raw_relations)
        original = self.ask("get", memory_id=continued)["record"]
        before = self.delivery_count()
        result = self.ask("handoff", query="unmatched-token-842", limit=1, semantic=False)
        self.assertEqual([hit["memory_id"] for hit in result["hits"]], [continued])
        hit = result["hits"][0]
        self.assertEqual(hit["relations"], [raw_relations[0]])
        self.assertTrue(hit["relations_truncated"])
        recalled = self.ask("recall", query="Synthetic continued visible state", semantic=False)
        recalled_hit = next(item for item in recalled["hits"] if item["memory_id"] == continued)
        self.assertEqual(recalled_hit["relations"], hit["relations"])
        self.assertNotIn(hidden["memory_id"], core.canonical_bytes(result).decode("utf-8"))
        self.assertEqual(self.ask("get", memory_id=continued)["record"], original)
        self.assertEqual(original["relations"], raw_relations)
        self.assertEqual(self.delivery_count(), before)

    def test_handoff_rechecks_current_target_revocation(self) -> None:
        active = [True]

        def trust_check(_key_id: str) -> None:
            if not active[0]:
                raise ValueError("synthetic target revocation")

        def shape_only_signer(record: dict) -> dict:
            return {
                "schema_version": core.ATTESTATION_SCHEMA, "key_id": "ed25519_" + "1" * 64,
                "record_sha256": record["record_sha256"],
                "signature": "SYNTHETIC-SHAPE-ONLY-NOT-A-CRYPTOGRAPHIC-SIGNATURE",
            }

        writer = core.Vault(self.path, signer=shape_only_signer, trust_check=trust_check)
        written = writer.handle({"op": "remember", "kind": "fact", "text": "Synthetic target with injected admission."})
        self.assertTrue(written["ok"], written)
        target = written["result"]["memory_id"]
        self.vault = core.Vault(self.path, trust_check=trust_check)
        episode = self.ask("observe", user="Synthetic local input.", assistant="Synthetic local final.")["memory_id"]
        relations = [{"type": "derived_from", "target": episode}, {"type": "related_to", "target": target}]
        continued = self.remember("Synthetic current local continuity.", kind="continuity", relations=relations)
        original = self.ask("get", memory_id=continued)["record"]
        self.assertEqual(self.ask("handoff", query="unmatched-token-842", limit=1)["hits"][0]["relations"], relations)
        active[0] = False
        hit = self.ask("handoff", query="unmatched-token-842", limit=1)["hits"][0]
        self.assertEqual(hit["memory_id"], continued)
        self.assertEqual(hit["relations"], [relations[0]])
        self.assertTrue(hit["relations_truncated"])
        self.assertEqual(self.ask("get", memory_id=continued)["record"], original)


if __name__ == "__main__":
    unittest.main()
