"""One small, complete unsigned MCP workflow using disposable local state.

This is an embedded JSON-RPC acceptance case, not a live host or second model.
All eleven advertised tools call their actual client/core implementations.
No network, subprocess, signer, installed plugin or default Vault is used.
Execution evidence, if any, is recorded separately in docs/VALIDATION.md.
"""

from __future__ import annotations

import argparse
import contextlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import memory_vault as core
import memory_vault_client as client


TOOLS = {
    "memory_capabilities", "memory_status", "memory_recall", "memory_handoff",
    "memory_get", "memory_views", "memory_graph", "memory_reindex",
    "memory_changes", "memory_remember", "memory_observe",
}


class MCPWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="memory-vault-v025-mcp-workflow-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.config = self.root / "client.json"
        self.database = self.root / "synthetic.sqlite3"
        self.number = 0
        self.called: set[str] = set()
        self.server = client.MCPServer(self.config)

    def rpc(self, method: str, params: dict | None = None) -> dict:
        self.number += 1
        # Serialize both sides to check the public JSON shape, not object
        # identities available only to an embedded Python caller.
        request = {"jsonrpc": "2.0", "id": self.number, "method": method,
                   "params": params or {}}
        response = self.server.handle(json.loads(core.canonical_bytes(request)))
        self.assertIsNotNone(response)
        self.assertLessEqual(len(core.canonical_bytes(response)) + 1, core.MAX_RESPONSE_BYTES)
        self.assertEqual(response["id"], self.number)
        return json.loads(core.canonical_bytes(response))

    def initialize(self) -> None:
        self.assertEqual(self.rpc("tools/list")["error"]["code"], -32002)
        response = self.rpc("initialize", {
            "protocolVersion": client.MCP_PROTOCOL, "capabilities": {},
            "clientInfo": {"name": "synthetic-full-workflow", "version": "fixture-1"},
        })
        self.assertEqual(response["result"]["protocolVersion"], client.MCP_PROTOCOL)
        self.assertIsNone(self.server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        self.assertEqual({item["name"] for item in self.rpc("tools/list")["result"]["tools"]}, TOOLS)

    def tool(self, name: str, arguments: dict | None = None, *, error: str | None = None) -> dict:
        self.called.add(name)
        frame = self.rpc("tools/call", {"name": name, "arguments": arguments or {}})
        self.assertNotIn("error", frame, frame)
        result = frame["result"]
        response = result["structuredContent"]
        self.assertEqual(json.loads(result["content"][0]["text"]), response)
        self.assertEqual(result["isError"], error is not None)
        self.assertEqual(response["ok"], error is None, response)
        self.assertEqual(response["authority"], core.AUTHORITY)
        if error is not None:
            self.assertEqual(response["error"]["code"], error)
            return response
        return response["result"]

    def test_eleven_tools_share_history_and_recover_only_disposable_indexes(self) -> None:
        self.initialize()
        self.tool("memory_capabilities")
        self.assertEqual(list(self.root.iterdir()), [])
        configured = client.configure(argparse.Namespace(
            sync_config=None, vault=self.database, identity=None, trust=None,
            capture_visible_turns=False,
        ), self.config)
        self.assertTrue(configured["ok"], configured)
        self.assertFalse(configured["result"]["host_installed"])
        self.assertFalse(configured["result"]["network_accessed"])
        self.assertEqual(self.tool("memory_status")["state"], "not_initialized")
        self.assertFalse(self.database.exists())

        turn = {"request_id": "req_synthetic_mcp_turn_01",
                "user": "Synthetic portable memory: preserve the backup history.",
                "assistant": "Use compact archives for synthetic backups."}
        observed = self.tool("memory_observe", turn)
        self.assertFalse(observed["host_attestation"])
        self.assertEqual(observed["capture_basis"], "caller_reported")
        self.assertEqual(self.tool("memory_observe", turn), observed)
        self.tool("memory_observe", {**turn, "assistant": "Changed synthetic reply"},
                  error="request_id_conflict")
        self.assertEqual(self.tool("memory_status")["records"], 2)
        episode, continuity = observed["episode_id"], observed["continuity_id"]
        claim = "claim:synthetic:mcp-backup-choice"

        def decision(number: int, text: str, relations: list[dict]) -> str:
            arguments = {"request_id": f"req_synthetic_mcp_decision_{number:02d}",
                         "kind": "decision", "text": text, "entities": [claim],
                         "relations": relations,
                         "provenance": {"agent_ref": "synthetic:caller",
                                        "task_ref": "synthetic:optional-reference-only"}}
            saved = self.tool("memory_remember", arguments)
            replay = self.tool("memory_remember", arguments)
            self.assertEqual(saved["memory_id"], replay["memory_id"])
            return saved["memory_id"]

        first = decision(1, "Synthetic backup choice: directory A",
                         [{"type": "derived_from", "target": episode}])
        second = decision(2, "Synthetic backup choice: directory B",
                          [{"type": "supersedes", "target": first}])
        alternative = decision(3, "Synthetic backup choice: directory C",
                               [{"type": "conflicts_with", "target": second}])
        conflicted = self.tool("memory_views", {"entity": claim})
        self.assertEqual(conflicted["views"][0]["state"], "conflicted")
        self.assertEqual(conflicted["consolidation_proposals"], [])
        resolution = decision(4, "Synthetic backup choice: reviewed directory B",
                              [{"type": "resolves", "target": second},
                               {"type": "resolves", "target": alternative}])
        identifiers = {episode, continuity, first, second, alternative, resolution}
        self.assertEqual(self.tool("memory_status")["records"], len(identifiers))

        # A fresh caller keeps no task/session binding and reads the same IDs.
        self.server = client.MCPServer(self.config)
        self.initialize()
        canonical = {}
        for identifier in identifiers:
            fetched = self.tool("memory_get", {"memory_id": identifier})
            canonical[identifier] = fetched["record"]
            self.assertEqual(core.validate_record(fetched["record"]), fetched["record"])
            direct = core.Vault(self.database).handle({"op": "get", "memory_id": identifier})
            self.assertTrue(direct["ok"], direct)
            self.assertEqual(direct["result"]["record"], fetched["record"])
            self.assertFalse(fetched["verification"]["grants_authority"])
        self.assertEqual(canonical[continuity]["relations"], [{"type": "derived_from", "target": episode}])
        self.assertEqual(self.tool("memory_get", {"memory_id": first})["status"], "superseded")
        self.assertEqual(self.tool("memory_get", {"memory_id": second})["status"], "resolved")
        self.assertEqual(self.tool("memory_get", {"memory_id": resolution})["status"], "current")

        recalled = self.tool("memory_recall", {"query": "synthetic backup", "limit": 16})
        self.assertIn(resolution, {hit["memory_id"] for hit in recalled["hits"]})
        self.assertFalse(recalled["network_accessed"])
        handoff = self.tool("memory_handoff", {"query": "synthetic backup", "limit": 16})
        self.assertIn(continuity, {hit["memory_id"] for hit in handoff["hits"]})
        self.assertFalse(handoff["evidence_context"]["instruction_eligible"])
        graph = self.tool("memory_graph", {"memory_id": resolution, "maximum_nodes": 16, "maximum_depth": 8})
        self.assertEqual({node["memory_id"] for node in graph["nodes"]}, identifiers)
        self.assertFalse(graph["truncated"])
        self.assertFalse(graph["records_changed"])

        arguments = {"entity": claim, "maximum_nodes": 2}
        seen: list[str] = []
        through = None
        for page in range(2):
            views = self.tool("memory_views", arguments)
            through = views["through"] if through is None else through
            self.assertEqual(views["through"], through)
            view = views["views"][0]
            seen.extend(item["memory_id"] for item in view["timeline"])
            self.assertFalse(view["inferred_grouping_is_ownership"])
            self.assertEqual(views["consolidation_proposals"], [])
            if page == 0:
                next_request = dict(view["next_request"])
                self.assertEqual(next_request.pop("op"), "memory.views")
                arguments = next_request
            else:
                self.assertIsNone(view["next_request"])
                self.assertTrue(view["earlier_pages_omitted"])
        self.assertEqual(set(seen), {first, second, alternative, resolution})
        self.assertEqual(len(seen), len(set(seen)))
        complete = self.tool("memory_views", {"entity": claim})
        self.assertEqual(complete["views"][0]["current_memory_ids"], [resolution])
        proposal = complete["consolidation_proposals"][0]
        self.assertEqual(set(proposal["evidence_memory_ids"]), set(seen))
        self.assertFalse(proposal["executable"])

        before = self.tool("memory_changes", {"limit": 16})
        self.assertEqual({item["memory_id"] for item in before["records"]}, identifiers)
        self.assertFalse(before["has_more"])
        self.assertEqual(before["attestations"], {})
        # Damage only a disposable index in this synthetic Vault, then repair
        # through the actual MCP operation without changing the delivery head.
        with contextlib.closing(core.Vault(self.database)._connect()) as connection, connection:
            connection.execute("DELETE FROM retrieval_index WHERE memory_id=?", (resolution,))
        self.tool("memory_views", {"entity": claim}, error="retrieval_index_required")
        rebuild = {"request_id": "req_synthetic_mcp_reindex_01", "limit": 16}
        repaired = self.tool("memory_reindex", rebuild)
        self.assertTrue(repaired["complete"])
        self.assertFalse(repaired["canonical_records_changed"])
        self.assertEqual(self.tool("memory_reindex", rebuild), repaired)
        self.tool("memory_reindex", {**rebuild, "limit": 8}, error="request_id_conflict")
        self.assertEqual(self.tool("memory_views", {"entity": claim}), complete)
        after = self.tool("memory_changes", {"limit": 16})
        self.assertEqual(after, before)
        self.assertEqual({record["memory_id"]: record for record in after["records"]}, canonical)
        self.assertEqual(self.called, TOOLS)
        self.assertFalse(client.ClientConfig.load(self.config).capture_visible_turns)
        self.assertFalse((self.root / "client.state").exists())


if __name__ == "__main__":
    unittest.main()
