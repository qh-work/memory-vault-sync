"""Unrun synthetic endpoint-resolution cases; no runtime acceptance claim.

Every Vault is disposable. The rank/revocation case uses the core's explicitly
injected shape-only signer and current-trust callback, not real cryptography,
key custody, a provider, a host installation or an independent implementation.
The database, status, graph and view projection remain real when a reviewer
separately authorizes running these cases. No mock supplies their results.
"""

from __future__ import annotations

import contextlib
from pathlib import Path
import tempfile
import unittest

import memory_vault as core


class ConflictResolutionTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="memory-v025-conflict-resolution-")
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name).resolve() / "synthetic.sqlite3"
        self.vault = core.Vault(self.path)

    def ask(self, operation: str, *, vault: core.Vault | None = None, **arguments: object) -> dict:
        response = (vault or self.vault).handle({"op": operation, **arguments})
        self.assertTrue(response["ok"], response)
        self.assertEqual(response["authority"], core.AUTHORITY)
        return dict(response["result"])

    def remember(self, text: str, *, relations: list[dict[str, str]] | None = None,
                 entities: list[str] | None = None, vault: core.Vault | None = None) -> str:
        return str(self.ask("remember", vault=vault, kind="fact", text=text,
                            relations=relations or [], entities=entities or [])["memory_id"])

    def snapshot(self) -> tuple[dict[str, str], int, int]:
        with contextlib.closing(self.vault._connect(writable=False)) as connection:
            records = {str(row[0]): str(row[1]) for row in connection.execute("SELECT memory_id,record_json FROM memories")}
            delivery = int(connection.execute("SELECT COUNT(*) FROM delivery_log").fetchone()[0])
            receipts = int(connection.execute("SELECT COUNT(*) FROM receipts").fetchone()[0])
        return records, delivery, receipts

    def graph(self, memory_id: str, **arguments: object) -> dict:
        return self.ask("memory.graph", memory_id=memory_id, maximum_nodes=32,
                        maximum_edges=64, maximum_depth=8, **arguments)

    @staticmethod
    def conflicts(graph: dict) -> dict[tuple[str, str], dict]:
        return {(edge["source_id"], edge["target_id"]): edge for edge in graph["edges"]
                if edge["type"] == "conflicts_with"}

    @staticmethod
    def shape_only_signer(key_id: str):
        def sign(record: dict) -> dict:
            return {"schema_version": core.ATTESTATION_SCHEMA, "key_id": key_id,
                    "record_sha256": record["record_sha256"],
                    "signature": "SYNTHETIC-SHAPE-ONLY-NOT-A-CRYPTOGRAPHIC-SIGNATURE"}
        return sign

    def test_resolution_closes_only_its_endpoint_edges_and_retains_the_complete_history(self) -> None:
        first = self.remember("Synthetic first possible choice")
        second = self.remember("Synthetic second possible choice")
        conflict = self.remember("Synthetic explicit conflict between choices", relations=[
            {"type": "conflicts_with", "target": first}, {"type": "conflicts_with", "target": second},
        ])
        originals = self.snapshot()[0]
        for memory_id in (first, second, conflict):
            self.assertEqual(self.ask("get", memory_id=memory_id)["status"], "conflicted")
        for edge in self.conflicts(self.graph(first)).values():
            self.assertTrue(edge["state_effective"])
            self.assertTrue(edge["source_state_effective"])
            self.assertEqual(edge["state_effective_reason"], "admitted_relation")
            self.assertIsNone(edge["resolution_memory_id"])
            self.assertIsNone(edge["resolution_target_id"])

        resolver = self.remember("Synthetic reviewed conflict resolution", relations=[{"type": "resolves", "target": conflict}])
        frozen = self.snapshot()
        graph = self.graph(first)
        self.assertEqual({node["memory_id"] for node in graph["nodes"]}, {first, second, conflict, resolver})
        edges = self.conflicts(graph)
        self.assertEqual(set(edges), {(conflict, first), (conflict, second)})
        for edge in edges.values():
            self.assertFalse(edge["state_effective"])
            self.assertFalse(edge["source_state_effective"])
            self.assertEqual(edge["state_effective_reason"], "explicit_endpoint_resolution")
            self.assertEqual(edge["resolution_memory_id"], resolver)
            self.assertEqual(edge["resolution_target_id"], conflict)
        views = self.ask("memory.views", memory_id=first, maximum_nodes=32, maximum_depth=8)
        view = views["views"][0]
        self.assertEqual(view["state"], "current")
        self.assertFalse(view["external_state_relations"])
        self.assertFalse(view["state_is_page_local"])
        timeline = {node["memory_id"]: node for node in view["timeline"]}
        self.assertEqual(set(timeline), {first, second, conflict, resolver})
        self.assertEqual({memory_id: item["status"] for memory_id, item in timeline.items()},
                         {first: "current", second: "current", conflict: "resolved", resolver: "current"})
        # Graph and timeline reasons must identify the same immutable edge and
        # the same currently admitted resolution, not a claim-wide flag.
        for item in timeline.values():
            for edge in item["state_relations"]:
                if edge["type"] == "conflicts_with":
                    self.assertEqual(edge, edges[(edge["source_id"], edge["target_id"])])
        self.assertEqual(len(views["consolidation_proposals"]), 1)
        proposal = views["consolidation_proposals"][0]
        self.assertEqual(set(proposal["evidence_memory_ids"]), set(timeline))
        self.assertEqual(proposal["status"], "proposal_only")
        self.assertFalse(proposal["executable"])
        self.assertFalse(views["records_changed"])
        self.assertEqual(self.snapshot(), frozen)

        independent = self.remember("Synthetic independent conflict still needs review", relations=[
            {"type": "conflicts_with", "target": first},
        ])
        edges = self.conflicts(self.graph(first))
        self.assertTrue(edges[(independent, first)]["state_effective"])
        self.assertIsNone(edges[(independent, first)]["resolution_memory_id"])
        self.assertFalse(edges[(conflict, first)]["state_effective"])
        self.assertEqual(self.ask("get", memory_id=first)["status"], "conflicted")
        self.assertEqual(self.ask("get", memory_id=second)["status"], "current")
        views = self.ask("memory.views", memory_id=first, maximum_nodes=32, maximum_depth=8)
        self.assertEqual(views["views"][0]["state"], "conflicted")
        self.assertEqual(views["consolidation_proposals"], [])

        # An explicit resolution may instead target the other endpoint; this
        # closes the source's conflict effect without pretending to resolve the
        # source record itself or deleting its historical relation.
        endpoint_resolution = self.remember("Synthetic explicit first-choice retirement", relations=[
            {"type": "resolves", "target": first},
        ])
        edge = self.conflicts(self.graph(first))[(independent, first)]
        self.assertFalse(edge["state_effective"])
        self.assertEqual(edge["resolution_memory_id"], endpoint_resolution)
        self.assertEqual(edge["resolution_target_id"], first)
        self.assertEqual(self.ask("get", memory_id=first)["status"], "resolved")
        self.assertEqual(self.ask("get", memory_id=independent)["status"], "current")
        current_records = self.snapshot()[0]
        self.assertEqual({memory_id: current_records[memory_id] for memory_id in originals}, originals)

    def test_weaker_and_quarantined_resolvers_cannot_close_a_stronger_edge_and_revocation_reopens_it(self) -> None:
        publisher, resolver_key = "ed25519_" + "1" * 64, "ed25519_" + "2" * 64
        admitted_keys = {publisher, resolver_key}

        def current_trust(key_id: str) -> None:
            if key_id not in admitted_keys:
                raise ValueError("synthetic current-trust refusal")

        self.vault = core.Vault(self.path, trust_check=current_trust)
        higher = core.Vault(self.path, signer=self.shape_only_signer(publisher), trust_check=current_trust)
        resolution_writer = core.Vault(self.path, signer=self.shape_only_signer(resolver_key), trust_check=current_trust)
        low_endpoint = self.remember("Synthetic unsigned endpoint")
        strong_conflict = self.remember("Synthetic stronger conflicting assertion", vault=higher,
                                       relations=[{"type": "conflicts_with", "target": low_endpoint}])
        self.remember("Synthetic weaker endpoint resolution", relations=[{"type": "resolves", "target": low_endpoint}])
        quarantined = core.build_record(kind="fact", text="Synthetic quarantined resolution",
            relations=[{"type": "resolves", "target": low_endpoint}], created_at="2026-01-01T00:00:00Z")
        self.vault.ingest_records([quarantined])
        self.assertEqual(self.ask("get", memory_id=quarantined["memory_id"])["status"], "quarantined")
        self.assertEqual(self.ask("get", memory_id=low_endpoint)["status"], "resolved")
        self.assertEqual(self.ask("get", memory_id=strong_conflict)["status"], "conflicted")
        edge = self.conflicts(self.graph(strong_conflict))[(strong_conflict, low_endpoint)]
        self.assertTrue(edge["state_effective"])
        self.assertIsNone(edge["resolution_memory_id"])
        views = self.ask("memory.views", memory_id=strong_conflict)
        self.assertEqual(views["views"][0]["state"], "conflicted")
        self.assertEqual(views["consolidation_proposals"], [])

        strong_resolver = self.remember("Synthetic independently admitted stronger resolution", vault=resolution_writer,
                                       relations=[{"type": "resolves", "target": low_endpoint}])
        frozen = self.snapshot()
        self.assertEqual(self.ask("get", memory_id=strong_conflict)["status"], "current")
        edge = self.conflicts(self.graph(strong_conflict))[(strong_conflict, low_endpoint)]
        self.assertFalse(edge["state_effective"])
        self.assertEqual(edge["resolution_memory_id"], strong_resolver)
        self.assertEqual(edge["resolution_target_id"], low_endpoint)
        self.assertEqual(self.ask("memory.views", memory_id=strong_conflict)["views"][0]["state"], "current")
        self.assertEqual(self.snapshot(), frozen)

        admitted_keys.remove(resolver_key)
        self.assertEqual(self.ask("get", memory_id=strong_resolver)["status"], "quarantined")
        self.assertEqual(self.ask("get", memory_id=strong_conflict)["status"], "conflicted")
        graph = self.graph(strong_conflict)
        self.assertNotIn(strong_resolver, {node["memory_id"] for node in graph["nodes"]})
        edge = self.conflicts(graph)[(strong_conflict, low_endpoint)]
        self.assertTrue(edge["state_effective"])
        self.assertTrue(edge["source_state_effective"])
        self.assertEqual(edge["state_effective_reason"], "admitted_relation")
        self.assertIsNone(edge["resolution_memory_id"])
        self.assertEqual(self.ask("memory.views", memory_id=strong_conflict)["views"][0]["state"], "conflicted")
        self.assertEqual(self.snapshot(), frozen)

    def test_weaker_conflict_keeps_its_source_effect_without_overriding_or_grouping_the_stronger_target(self) -> None:
        publisher, resolver_key = "ed25519_" + "3" * 64, "ed25519_" + "4" * 64
        admitted_keys = {publisher, resolver_key}

        def current_trust(key_id: str) -> None:
            if key_id not in admitted_keys:
                raise ValueError("synthetic current-trust refusal")

        self.vault = core.Vault(self.path, trust_check=current_trust)
        higher = core.Vault(self.path, signer=self.shape_only_signer(publisher), trust_check=current_trust)
        resolution_writer = core.Vault(self.path, signer=self.shape_only_signer(resolver_key), trust_check=current_trust)
        target = self.remember("Synthetic stronger independent target", vault=higher)
        source = self.remember("Synthetic weaker conflicting declaration", relations=[{"type": "conflicts_with", "target": target}])
        self.assertEqual(self.ask("get", memory_id=source)["status"], "conflicted")
        self.assertEqual(self.ask("get", memory_id=target)["status"], "current")
        edge = self.conflicts(self.graph(source))[(source, target)]
        self.assertFalse(edge["state_effective"])
        self.assertTrue(edge["source_state_effective"])
        self.assertEqual(edge["state_effective_reason"], "weaker_than_target")
        views = self.ask("memory.views", memory_id=source)
        view = views["views"][0]
        self.assertEqual([node["memory_id"] for node in view["timeline"]], [source])
        self.assertEqual(view["state"], "conflicted")
        self.assertEqual(view["timeline"][0]["state_relations"], [edge])
        self.assertTrue(view["external_state_relations"])
        self.assertEqual(views["consolidation_proposals"], [])

        resolver = self.remember("Synthetic stronger explicit endpoint resolution", vault=resolution_writer,
                                 relations=[{"type": "resolves", "target": source}])
        frozen = self.snapshot()
        self.assertEqual(self.ask("get", memory_id=source)["status"], "resolved")
        self.assertEqual(self.ask("get", memory_id=target)["status"], "current")
        edge = self.conflicts(self.graph(source))[(source, target)]
        self.assertFalse(edge["state_effective"])
        self.assertFalse(edge["source_state_effective"])
        self.assertEqual(edge["resolution_memory_id"], resolver)
        self.assertEqual(edge["resolution_target_id"], source)
        view = self.ask("memory.views", memory_id=source)["views"][0]
        self.assertEqual({node["memory_id"] for node in view["timeline"]}, {source, resolver})
        self.assertNotIn(target, view["current_memory_ids"])

        admitted_keys.remove(resolver_key)
        self.assertEqual(self.ask("get", memory_id=source)["status"], "conflicted")
        self.assertEqual(self.ask("get", memory_id=target)["status"], "current")
        edge = self.conflicts(self.graph(source))[(source, target)]
        self.assertFalse(edge["state_effective"])
        self.assertTrue(edge["source_state_effective"])
        self.assertIsNone(edge["resolution_memory_id"])
        self.assertEqual(self.snapshot(), frozen)

    def test_resolution_outside_the_selected_record_page_is_disclosed_and_cannot_authorize_a_proposal(self) -> None:
        claim = "claim:v021:synthetic-bounded-resolution"
        first = self.remember("Synthetic paged first choice", entities=[claim])
        second = self.remember("Synthetic paged second choice", entities=[claim])
        conflict = self.remember("Synthetic paged conflict", entities=[claim], relations=[
            {"type": "conflicts_with", "target": first}, {"type": "conflicts_with", "target": second},
        ])
        with contextlib.closing(self.vault._connect(writable=False)) as connection:
            through = int(connection.execute("SELECT MAX(ingest_seq) FROM memories").fetchone()[0])
        resolver = self.remember("Synthetic later resolution without a claim label", relations=[{"type": "resolves", "target": conflict}])
        frozen = self.snapshot()
        graph = self.graph(first, through=through)
        self.assertEqual({node["memory_id"] for node in graph["nodes"]}, {first, second, conflict})
        for edge in self.conflicts(graph).values():
            self.assertFalse(edge["state_effective"])
            self.assertEqual(edge["resolution_memory_id"], resolver)
            self.assertEqual(edge["resolution_target_id"], conflict)
        views = self.ask("memory.views", entity=claim, through=through)
        view = views["views"][0]
        self.assertEqual({node["memory_id"] for node in view["timeline"]}, {first, second, conflict})
        self.assertEqual(view["state"], "current")
        self.assertTrue(view["external_state_relations"])
        self.assertTrue(view["state_is_page_local"])
        self.assertEqual(views["consolidation_proposals"], [])
        closed_reasons = [edge for node in view["timeline"] for edge in node["state_relations"]
                          if edge["state_effective_reason"] == "explicit_endpoint_resolution"]
        self.assertTrue(closed_reasons)
        self.assertEqual({edge["resolution_memory_id"] for edge in closed_reasons}, {resolver})
        self.assertEqual(self.snapshot(), frozen)


if __name__ == "__main__":
    unittest.main()
