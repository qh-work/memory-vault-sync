"""Public synthetic 0.25 conformance cases, supplied without execution evidence.

Only disposable temporary Vaults are used. The shape-only signing fixture tests
the core's injected admission boundary, NOT cryptography or real key custody.
"""

from __future__ import annotations

import contextlib
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest import mock

import memory_vault as core


class RetrievalAndViewTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "synthetic.sqlite3"
        self.vault = core.Vault(self.path)

    def ask(self, operation: str, **arguments: object) -> dict:
        response = self.vault.handle({"op": operation, **arguments})
        self.assertTrue(response["ok"], response)
        self.assertFalse(response["authority"]["execution_eligible"])
        return dict(response["result"])

    def remember(self, text: str, *, kind: str = "fact", entities: list[str] | None = None,
                 relations: list[dict[str, str]] | None = None) -> str:
        return str(self.ask("remember", kind=kind, text=text, entities=entities or [], relations=relations or [])["memory_id"])

    def count_delivery(self) -> int:
        with contextlib.closing(self.vault._connect(writable=False)) as connection:
            return int(connection.execute("SELECT COUNT(*) FROM delivery_log").fetchone()[0])

    def test_bilingual_concept_bridge_and_lexical_fallback(self) -> None:
        memory_id = self.remember("保存合成的历史事实")
        enabled = self.ask("recall", query="backup", limit=4)
        self.assertEqual(enabled["hits"][0]["memory_id"], memory_id)
        self.assertGreater(enabled["hits"][0]["score_components"]["semantic_milli"], 0)
        disabled = self.ask("recall", query="backup", semantic=False)
        self.assertEqual(disabled["hits"], [])
        self.assertEqual(disabled["retrieval"]["semantic_adapter"], "disabled")

    def test_expansion_cannot_evict_a_direct_match_with_a_unique_query_word(self) -> None:
        expected = self.remember("falcon backup")
        for index in range(128):
            self.remember(f"backup archive save synthetic note {index}")
        before = self.count_delivery()
        result = self.ask("recall", query="falcon backup", limit=8)
        self.assertEqual(result["hits"][0]["memory_id"], expected)
        self.assertEqual(result["hits"][0]["matched_tokens"], 2)
        self.assertEqual(result["retrieval"]["candidate_limit"], 128)
        self.assertEqual(result["retrieval"]["candidate_records"], 128)
        self.assertTrue(result["retrieval"]["truncated"])
        self.assertLessEqual(result["retrieval"]["fragments_scanned"], core.MAX_RERANK_FRAGMENTS)
        self.assertEqual(self.count_delivery(), before)

    def test_concept_fill_shares_the_candidate_limit_and_deduplicates_direct_records(self) -> None:
        direct = self.remember("backup save direct synthetic evidence")
        expanded = {self.remember("保存合成的历史事实"), self.remember("存档不同的合成事实")}
        # A smaller synthetic bound checks the route, not production scale.
        with mock.patch.object(core, "MAX_RETRIEVAL_CANDIDATES", 2):
            result = self.ask("recall", query="backup", limit=8)
        identifiers = {hit["memory_id"] for hit in result["hits"]}
        self.assertIn(direct, identifiers)
        self.assertEqual(len(identifiers & expanded), 1)
        self.assertEqual(result["retrieval"]["candidate_records"], 2)
        self.assertEqual(result["retrieval"]["candidate_limit"], 2)
        self.assertTrue(result["retrieval"]["truncated"])

    def test_fragment_locator_keeps_normalization_and_cjk_matches_without_full_scoring(self) -> None:
        cases = (
            ("RareMarker secondary", "Full-width ＲＡＲＥＭＡＲＫＥＲ evidence", True),
            ("Straße secondary", "STRASSE evidence", True),
            ("backup", "保存合成历史", True),
            ("历史存档", "需要保存证据", True),
            ("연결 기억", "연결된 기록", True),
            ("キロ", "記録キロメートル", True),
            ("x-y secondary", "Synthetic X-Y evidence", True),
            ("a" * 64 + " secondary", "a" * 80, True),  # Same Latin token chunks.
            ("marker secondary", "markerized fixture", False),
            ("检 marker", "检查", False),  # One-char tokens require a one-char run.
            ("mark", "Remarkable fixture", True),  # Existing phrase signal is a substring.
        )
        for query, text, expected in cases:
            with self.subTest(query=query):
                tokens = core.tokenize(query)
                features = core.semantic_features(query)
                locate = core._fragment_locator(core._expanded_query_tokens(tokens, features), core.normalize_text(query))
                with mock.patch.object(core, "tokenize", side_effect=AssertionError("prefilter cannot fully tokenize")), \
                        mock.patch.object(core, "semantic_features", side_effect=AssertionError("prefilter cannot extract semantic features")):
                    self.assertEqual(locate(text), expected)
                    self.assertFalse(locate("ordinary unrelated fixture"))

    def test_negative_polarity_is_a_soft_penalty(self) -> None:
        query = core.semantic_features("do not backup")
        same = core.semantic_similarity(query, core.semantic_features("不要保存"))
        opposite = core.semantic_similarity(query, core.semantic_features("保存"))
        self.assertGreater(same, opposite)
        self.assertEqual(opposite, same * 0.25)
        self.assertGreater(opposite, 0)

    def test_long_record_tail_is_indexed_and_returned_as_exact_fragment(self) -> None:
        text = "synthetic padding " * 7000 + "\nRareTailMarker persistent evidence at the end"
        memory_id = self.remember(text)
        result = self.ask("recall", query="RareTailMarker")
        hit = result["hits"][0]
        self.assertEqual(hit["memory_id"], memory_id)
        self.assertIn("RareTailMarker", hit["text"])
        fragment = hit["fragment"]
        self.assertGreater(fragment["start_character"], 10000)
        self.assertEqual(text[fragment["start_character"]:fragment["end_character"]], fragment["text"])
        self.assertTrue(hit["text_truncated"])
        self.assertTrue(result["retrieval"]["index"]["complete"])

    def test_seven_large_record_tails_do_not_spend_scoring_slots_on_unrelated_prefixes(self) -> None:
        # About 7 MiB total, below the unchanged 8-MiB canonical-read limit.
        # The unrelated prefixes contain more than 4096 cheap candidate spans.
        # This authored case is not a measured latency or a passed scale test.
        prefix = ("ordinary detail " * (core.MAX_TEXT_BYTES // 16))[:core.MAX_TEXT_BYTES - 96]
        originals: dict[str, str] = {}
        for index in range(7):
            text = prefix + f"\nNeedleMarker document-{index:02d}"
            originals[self.remember(text)] = text
        before = self.count_delivery()
        with mock.patch.object(core, "tokenize", wraps=core.tokenize) as tokenize, \
                mock.patch.object(core, "semantic_features", wraps=core.semantic_features) as semantics:
            result = self.ask("recall", query="NeedleMarker", limit=8)
        statistics = result["retrieval"]
        self.assertEqual({hit["memory_id"] for hit in result["hits"]}, set(originals))
        self.assertEqual(statistics["candidate_records"], 7)
        self.assertTrue(statistics["index"]["complete"])
        self.assertFalse(statistics["truncated"])
        self.assertGreater(statistics["fragment_spans_examined"], core.MAX_RERANK_FRAGMENTS)
        self.assertLess(statistics["fragments_scanned"], 64)
        self.assertLessEqual(statistics["record_bytes_scanned"], core.MAX_RERANK_BYTES)
        scoring_calls = [call for call in tokenize.call_args_list if call.kwargs.get("maximum") == 4096]
        self.assertEqual(len(scoring_calls), statistics["fragments_scanned"])
        self.assertLessEqual(len(scoring_calls), core.MAX_RERANK_FRAGMENTS)
        self.assertEqual(semantics.call_count, 1 + statistics["candidate_records"] + statistics["fragments_scanned"])
        for hit in result["hits"]:
            fragment = hit["fragment"]
            self.assertIn("NeedleMarker", hit["text"])
            self.assertGreater(fragment["start_character"], 900_000)
            self.assertEqual(originals[hit["memory_id"]][fragment["start_character"]:fragment["end_character"]], hit["text"])
        self.assertEqual(self.count_delivery(), before)

    def test_entity_and_related_evidence_keep_a_fallback_without_displacing_text_matches(self) -> None:
        related = self.remember("Unrelated supporting fixture excerpt")
        direct = self.remember("Synthetic backup anchor", relations=[{"type": "derived_from", "target": related}])
        entity_only = self.remember("A separately associated fixture statement", entities=["backup"])
        result = self.ask("recall", query="backup", limit=8)
        hits = {hit["memory_id"]: hit for hit in result["hits"]}
        self.assertEqual(set(hits), {direct, related, entity_only})
        self.assertGreater(hits[related]["score_components"]["graph_milli"], 0)
        self.assertGreater(hits[entity_only]["score_components"]["entity_milli"], 0)
        # Even when the newer entity-only row is selected first, its fallback
        # must not consume the only synthetic scoring slot before the anchor.
        with mock.patch.object(core, "MAX_RERANK_FRAGMENTS", 1):
            bounded = self.ask("recall", query="backup", limit=8)
        self.assertEqual([hit["memory_id"] for hit in bounded["hits"]], [direct])
        self.assertEqual(bounded["retrieval"]["fragments_scanned"], 1)
        self.assertTrue(bounded["retrieval"]["truncated"])

    def test_fragment_and_record_byte_limits_still_stop_scoring_with_honest_truncation(self) -> None:
        self.remember("backup synthetic evidence " * 300)
        with mock.patch.object(core, "MAX_RERANK_FRAGMENTS", 2), \
                mock.patch.object(core, "tokenize", wraps=core.tokenize) as tokenize:
            fragments = self.ask("recall", query="backup")
        statistics = fragments["retrieval"]
        self.assertEqual(statistics["fragments_scanned"], 2)
        self.assertEqual(sum(call.kwargs.get("maximum") == 4096 for call in tokenize.call_args_list), 2)
        self.assertTrue(statistics["truncated"])
        with mock.patch.object(core, "MAX_RERANK_BYTES", 1024):
            byte_limited = self.ask("recall", query="backup")
        self.assertEqual(byte_limited["hits"], [])
        self.assertEqual(byte_limited["retrieval"]["record_bytes_scanned"], 0)
        self.assertEqual(byte_limited["retrieval"]["fragments_scanned"], 0)
        self.assertEqual(byte_limited["retrieval"]["fragment_spans_examined"], 0)
        self.assertTrue(byte_limited["retrieval"]["truncated"])

    def test_scores_are_integer_explanations_not_authority(self) -> None:
        self.remember("local backup memory")
        result = self.ask("recall", query="save memory")
        hit = result["hits"][0]
        self.assertTrue(all(type(value) is int for value in hit["score_components"].values()))
        self.assertTrue(hit["explanation"])
        self.assertFalse(result["retrieval"]["ranking_is_authority"])
        self.assertFalse(result["network_accessed"])

    def test_episode_roles_are_explicitly_unauthenticated_hints(self) -> None:
        saved = self.ask("observe", user="same backup evidence", assistant="same backup evidence")
        hit = self.ask("recall", query="same backup evidence")["hits"][0]
        self.assertEqual(hit["memory_id"], saved["memory_id"])
        self.assertEqual(hit["fragment"]["role_hint"], "user")
        self.assertFalse(hit["fragment"]["role_hint_authenticated"])
        self.assertEqual(hit["provenance"]["source_type"], "agent_supplied")

    def test_superseded_history_remains_visible_but_ranks_lower(self) -> None:
        old = self.remember("stable backup choice")
        new = self.remember("stable backup choice", relations=[{"type": "supersedes", "target": old}])
        hits = self.ask("recall", query="stable backup choice", limit=8)["hits"]
        self.assertEqual(hits[0]["memory_id"], new)
        states = {hit["memory_id"]: hit["status"] for hit in hits}
        self.assertEqual(states[old], "superseded")
        self.assertEqual(states[new], "current")

    def test_claim_timeline_conflicts_resolution_and_proposal(self) -> None:
        entity = "claim:v021:synthetic-storage-choice"
        first = self.remember("Initial storage choice", entities=[entity])
        second = self.remember("Updated storage choice", entities=[entity], relations=[{"type": "supersedes", "target": first}])
        alternative = self.remember("Alternative storage choice", entities=[entity], relations=[{"type": "conflicts_with", "target": second}])
        conflict = self.ask("memory.views", entity=entity)
        self.assertEqual(conflict["views"][0]["state"], "conflicted")
        self.assertEqual(conflict["consolidation_proposals"], [])
        resolution = self.remember("Reviewed storage resolution", entities=[entity], relations=[
            {"type": "resolves", "target": second}, {"type": "resolves", "target": alternative},
        ])
        result = self.ask("memory.views", entity=entity)
        view = result["views"][0]
        states = {item["memory_id"]: item["status"] for item in view["timeline"]}
        self.assertEqual(states[first], "superseded")
        self.assertEqual(states[second], "resolved")
        self.assertEqual(states[alternative], "resolved")
        self.assertEqual(states[resolution], "current")
        self.assertFalse(view["truncated"])
        proposal = result["consolidation_proposals"][0]
        self.assertEqual(set(proposal["evidence_memory_ids"]), {first, second, alternative, resolution})
        self.assertEqual(proposal["status"], "proposal_only")
        self.assertFalse(proposal["executable"])
        self.assertFalse(result["records_changed"])

    def test_shared_episode_or_task_reference_does_not_merge_claims(self) -> None:
        episode = self.ask("observe", user="Synthetic shared evidence", assistant="Two independent matters")["memory_id"]
        one = self.remember("First independent matter", relations=[{"type": "derived_from", "target": episode}])
        two = self.remember("Second independent matter", relations=[{"type": "derived_from", "target": episode}])
        view = self.ask("memory.views", memory_id=one)["views"][0]
        self.assertEqual([item["memory_id"] for item in view["timeline"]], [one])
        self.assertNotIn(two, view["current_memory_ids"])
        self.assertFalse(view["inferred_grouping_is_ownership"])

    def test_resolution_is_explicit_even_without_a_conflict_record(self) -> None:
        original = self.remember("Synthetic open matter")
        self.remember("Synthetic replacement", relations=[{"type": "supersedes", "target": original}])
        self.remember("Synthetic explicit resolution", relations=[{"type": "resolves", "target": original}])
        self.assertEqual(self.ask("get", memory_id=original)["status"], "resolved")

    def test_entity_timeline_pages_cover_each_record_once(self) -> None:
        entity = "claim:v021:synthetic-pagination"
        identifiers = [self.remember(f"Synthetic revision {index}", entities=[entity]) for index in range(5)]
        request: dict | None = {"op": "memory.views", "entity": entity, "maximum_nodes": 2}
        observed: list[str] = []
        page_count = 0
        while request is not None:
            response = self.vault.handle(request)
            self.assertTrue(response["ok"], response)
            result = response["result"]
            view = result["views"][0]
            observed.extend(item["memory_id"] for item in view["timeline"])
            if page_count:
                self.assertTrue(view["earlier_pages_omitted"])
                self.assertTrue(view["state_is_page_local"])
                self.assertEqual(result["consolidation_proposals"], [])
            request = view["next_request"]
            page_count += 1
            self.assertLess(page_count, 10)
        self.assertEqual(observed, identifiers)
        self.assertEqual(len(observed), len(set(observed)))

    def test_subsecond_timeline_order_is_not_raw_timestamp_string_order(self) -> None:
        entity = "claim:v021:synthetic-clock"
        earlier = core.build_record(kind="fact", text="Whole second", entities=[entity], created_at="2026-01-01T00:00:00Z")
        later = core.build_record(kind="fact", text="One microsecond later", entities=[entity], created_at="2026-01-01T00:00:00.000001Z")
        self.vault.ingest_records([later, earlier], admission="accepted_unsigned")
        view = self.ask("memory.views", entity=entity)["views"][0]
        self.assertEqual([item["memory_id"] for item in view["timeline"]], [earlier["memory_id"], later["memory_id"]])

    @staticmethod
    def shape_only_signer(record: dict) -> dict:
        return {
            "schema_version": core.ATTESTATION_SCHEMA, "key_id": "ed25519_" + "1" * 64,
            "record_sha256": record["record_sha256"],
            "signature": "SYNTHETIC-SHAPE-ONLY-NOT-A-CRYPTOGRAPHIC-SIGNATURE",
        }

    def test_unsigned_relation_cannot_retire_verified_memory(self) -> None:
        signed = core.Vault(self.path, signer=self.shape_only_signer)
        original = signed.handle({"op": "remember", "kind": "fact", "text": "Signed synthetic choice"})
        self.assertTrue(original["ok"])
        original_id = original["result"]["memory_id"]
        low = self.remember("Unsigned replacement claim", relations=[{"type": "supersedes", "target": original_id}])
        self.assertEqual(self.ask("get", memory_id=original_id)["status"], "current")
        graph = self.ask("memory.graph", memory_id=original_id)
        edge = next(edge for edge in graph["edges"] if edge["source_id"] == low)
        self.assertFalse(edge["state_effective"])

    def test_current_trust_revocation_excludes_recall_and_views(self) -> None:
        active = [True]

        def trust_check(_key_id: str) -> None:
            if not active[0]:
                raise ValueError("synthetic revoked fixture")

        self.vault = core.Vault(self.path, signer=self.shape_only_signer, trust_check=trust_check)
        memory_id = self.remember("Synthetic revocation marker", entities=["claim:v021:revocation"])
        expanded_id = self.remember("保存合成的历史事实")
        self.assertEqual(self.ask("recall", query="revocation marker")["hits"][0]["memory_id"], memory_id)
        self.assertEqual(self.ask("recall", query="backup")["hits"][0]["memory_id"], expanded_id)
        active[0] = False
        self.assertEqual(self.ask("recall", query="revocation marker")["hits"], [])
        self.assertEqual(self.ask("recall", query="backup")["hits"], [])
        self.assertEqual(self.ask("memory.views", entity="claim:v021:revocation")["views"], [])
        response = self.vault.handle({"op": "memory.graph", "memory_id": memory_id})
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "record_not_admitted")

    def test_quarantined_neighbors_do_not_leak_into_retrieval_graph(self) -> None:
        hidden = core.build_record(kind="fact", text="Synthetic quarantined marker")
        self.vault.ingest_records([hidden])
        visible = self.remember("Admitted synthetic anchor", relations=[{"type": "related_to", "target": hidden["memory_id"]}])
        hit = self.ask("recall", query="Admitted synthetic anchor")["hits"][0]
        self.assertEqual(hit["relations"], [])
        graph = self.ask("memory.graph", memory_id=visible)
        self.assertEqual([node["memory_id"] for node in graph["nodes"]], [visible])
        self.assertEqual(graph["edges"], [])

    def test_bounded_graph_reports_frontier_and_no_write(self) -> None:
        first = self.remember("Synthetic graph root")
        second = self.remember("Synthetic graph successor", relations=[{"type": "continues", "target": first}])
        before = self.count_delivery()
        graph = self.ask("memory.graph", memory_id=first, maximum_depth=0)
        self.assertTrue(graph["truncated"])
        self.assertEqual(len(graph["nodes"]), 1)
        self.assertIn(second, graph["frontier_memory_ids"])
        self.assertFalse(graph["records_changed"])
        self.assertEqual(self.count_delivery(), before)

    def test_directed_cycle_detection_does_not_call_a_dag_a_cycle(self) -> None:
        dag = [{"source_id": "a", "target_id": "b"}, {"source_id": "a", "target_id": "c"}, {"source_id": "b", "target_id": "c"}]
        self.assertFalse(core._directed_cycle(["a", "b", "c"], dag))
        self.assertTrue(core._directed_cycle(["a", "b", "c"], [*dag, {"source_id": "c", "target_id": "a"}]))

    def test_explicit_reindex_repairs_old_index_without_rewriting_memory(self) -> None:
        entity = "claim:v021:reindex-fixture"
        memory_id = self.remember("Synthetic reindex marker", entities=[entity])
        before = self.ask("get", memory_id=memory_id)["record"]
        with sqlite3.connect(self.path) as connection:
            connection.execute("DROP TABLE retrieval_index")
            connection.execute("DROP TABLE memory_entities")
            connection.execute("DELETE FROM terms")
        recall = self.ask("recall", query="reindex marker")
        self.assertFalse(recall["retrieval"]["index"]["complete"])
        missing = self.vault.handle({"op": "memory.views", "entity": entity})
        self.assertEqual(missing["error"]["code"], "retrieval_index_required")
        repaired = self.ask("memory.reindex", limit=1, request_id="req_v025_reindex_fixture")
        self.assertTrue(repaired["index"]["complete"])
        self.assertFalse(repaired["canonical_records_changed"])
        self.assertEqual(self.ask("get", memory_id=memory_id)["record"], before)
        self.assertEqual(self.ask("memory.views", entity=entity)["views"][0]["timeline"][0]["memory_id"], memory_id)

    def test_reindex_snapshot_excludes_later_writes_until_next_pass(self) -> None:
        self.remember("Synthetic first index item")
        self.remember("Synthetic second index item")
        page = self.ask("memory.reindex", limit=1)
        self.assertIsNotNone(page["next_after"])
        self.remember("Synthetic newer item")
        final = self.ask("memory.reindex", after=page["next_after"], through=page["through"], limit=1)
        self.assertEqual(final["through"], page["through"])
        self.assertIsNone(final["next_after"])

    def test_reads_do_not_initialize_missing_vault(self) -> None:
        missing = core.Vault(Path(self.temporary.name) / "not-created" / "vault.sqlite3")
        for request in ({"op": "memory.views"}, {"op": "memory.graph", "memory_id": "mem_" + "0" * 40}):
            response = missing.handle(request)
            self.assertFalse(response["ok"])
            self.assertEqual(response["error"]["code"], "not_initialized")
        self.assertFalse(missing.path.parent.exists())

    def test_in_process_requeue_is_exact_effect_idempotent(self) -> None:
        first = self.remember("Synthetic delivery root")
        second = self.remember("Synthetic other root")
        before = self.count_delivery()
        one = self.vault.requeue_records([first], request_id="req_v025_requeue_fixture")
        two = self.vault.requeue_records([first, first], request_id="req_v025_requeue_fixture")
        self.assertEqual(one, two)
        self.assertEqual(self.count_delivery(), before + 1)
        with self.assertRaises(core.MemoryError) as caught:
            self.vault.requeue_records([second], request_id="req_v025_requeue_fixture")
        self.assertEqual(caught.exception.code, "request_id_conflict")

    def test_group_transfer_refuses_to_skip_oversized_complete_closure(self) -> None:
        first = self.remember("Synthetic transfer dependency")
        self.remember("Synthetic transfer root", relations=[{"type": "derived_from", "target": first}])
        with self.assertRaises(core.MemoryError) as caught:
            self.vault.transfer_changes(after=1, limit=1, maximum_records=1, require_verified=False)
        self.assertEqual(caught.exception.code, "dependency_budget_exceeded")


if __name__ == "__main__":
    unittest.main()
