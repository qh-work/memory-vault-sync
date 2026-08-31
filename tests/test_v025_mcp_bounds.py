"""Public synthetic client/schema cases, written but NOT run for this release.

No real Vault, installed host, credentials, signing key or network is used.
Application imports below happen only if a contributor explicitly runs these
tests. Optional JSON Schema cases require jsonschema and referencing; skipping
those cases is not schema-conformance evidence. Static parsing is not a test run.
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

import memory_vault as core
import memory_vault_client as client
import memory_vault_compat as compat

try:
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource
except ImportError:
    Draft202012Validator = None
    Registry = Resource = None


MEMORY_ID = "mem_" + "a" * 40
SESSION = "mvc1_" + "s" * 43
TURN = "mvt1_" + "t" * 43


def host_request(operation: str, payload: dict) -> dict:
    return {"schema_version": compat.REQUEST_SCHEMA, "protocol_version": "1.0",
            "request_id": "synthetic.schema.1", "operation": operation,
            "adapter": {"id": "synthetic-adapter", "version": "1.0.0", "host_family": "generic_stdio"},
            "payload": payload}


def semantic_proposal() -> dict:
    return {"schema_version": "memory-network-semantic-proposal/v1",
            "source_id": "src-" + "a" * 40, "episode_id": "ep-" + "a" * 40,
            "kind": "decision", "claim_key": None,
            "parents": [], "supersedes": [], "conflicts_with": [], "resolves": [],
            "payload": {"statement": "Synthetic durable fact", "reason": None, "concepts": ["memory"]}}


def schema_validator(name: str):
    resources = []
    selected = None
    for path in (ROOT / "schemas").glob("*.schema.json"):
        value = json.loads(path.read_text(encoding="utf-8"))
        value["$id"] = path.resolve().as_uri()
        resources.append((value["$id"], Resource.from_contents(value)))
        if path.name == name:
            selected = value
    assert selected is not None
    Draft202012Validator.check_schema(selected)
    return Draft202012Validator(selected, registry=Registry().with_resources(resources))


class MCPBoundsTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.server = client.MCPServer(self.root / "nonexistent-client.json")
        self.server.initialized = self.server.ready = True

    def invoke(self, name: str, arguments: dict | None = None, *, identifier=7):
        return self.server.handle({"jsonrpc": "2.0", "id": identifier, "method": "tools/call",
                                   "params": {"name": name, "arguments": arguments or {}}})

    def test_advertised_and_capability_limits_agree(self) -> None:
        limits = self.server.call("memory_capabilities", {})["client"]["response_limits"]
        for name in ("memory_views", "memory_graph"):
            nodes = self.server.tools[name]["inputSchema"]["properties"]["maximum_nodes"]
            self.assertEqual(nodes["default"], 64)
            self.assertEqual(nodes["maximum"], 64)
        edges = self.server.tools["memory_graph"]["inputSchema"]["properties"]["maximum_edges"]
        self.assertEqual(edges["default"], 512)
        self.assertEqual(edges["maximum"], 512)
        self.assertEqual(limits["views_maximum_nodes"], 64)
        self.assertEqual(limits["graph_maximum_edges"], 512)
        self.assertEqual(limits["maximum_frame_bytes"], core.MAX_RESPONSE_BYTES)

    def test_defaults_are_forwarded_not_just_advertised(self) -> None:
        config = mock.Mock()
        with mock.patch.object(client.ClientConfig, "load", return_value=config), \
                mock.patch.object(client, "_read_operation", return_value=core.success({})) as read:
            self.server.call("memory_views", {})
            self.assertEqual(read.call_args.args[1], {"op": "memory.views", "maximum_nodes": 64})
            self.server.call("memory_graph", {"memory_id": MEMORY_ID})
            self.assertEqual(read.call_args.args[1], {"op": "memory.graph", "memory_id": MEMORY_ID,
                                                    "maximum_nodes": 64, "maximum_edges": 512})

    def test_smaller_explicit_graph_page_is_preserved(self) -> None:
        arguments = {"memory_id": MEMORY_ID, "maximum_nodes": 3, "maximum_edges": 8, "through": 17}
        with mock.patch.object(client.ClientConfig, "load", return_value=mock.Mock()), \
                mock.patch.object(client, "_read_operation", return_value=core.success({})) as read:
            self.server.call("memory_graph", arguments)
            self.assertEqual(read.call_args.args[1], {"op": "memory.graph", **arguments})

    def test_oversized_graph_arguments_fail_before_config_access(self) -> None:
        with mock.patch.object(client.ClientConfig, "load", side_effect=AssertionError("No configuration read")):
            for arguments in ({"memory_id": MEMORY_ID, "maximum_nodes": 65},
                              {"memory_id": MEMORY_ID, "maximum_edges": 513}):
                with self.subTest(arguments=arguments), self.assertRaises(core.MemoryError):
                    self.server.call("memory_graph", arguments)

    def test_view_selectors_are_pairwise_exclusive(self) -> None:
        schema = self.server.tools["memory_views"]["inputSchema"]
        for arguments in ({"entity": "claim:synthetic", "memory_id": MEMORY_ID},
                          {"entity": "claim:synthetic", "query": "synthetic"},
                          {"memory_id": MEMORY_ID, "query": "synthetic"}):
            with self.subTest(arguments=arguments), self.assertRaises(core.MemoryError):
                client._validate_arguments(arguments, schema)
        for arguments in ({}, {"entity": "claim:synthetic"}, {"memory_id": MEMORY_ID}, {"query": "synthetic"}):
            client._validate_arguments(arguments, schema)

    def test_entity_cursor_dependency_is_enforced(self) -> None:
        schema = self.server.tools["memory_views"]["inputSchema"]
        with self.assertRaises(core.MemoryError):
            client._validate_arguments({"after_memory_id": MEMORY_ID}, schema)
        client._validate_arguments({"entity": "claim:synthetic", "after_memory_id": MEMORY_ID,
                                    "through": 27, "maximum_nodes": 4}, schema)

    def test_nonzero_sequence_cursor_is_only_for_enumeration(self) -> None:
        schema = self.server.tools["memory_views"]["inputSchema"]
        for selector in ({"entity": "claim:synthetic"}, {"memory_id": MEMORY_ID}, {"query": "synthetic"}):
            with self.subTest(selector=selector), self.assertRaises(core.MemoryError):
                client._validate_arguments({**selector, "after_sequence": 1}, schema)
            client._validate_arguments({**selector, "after_sequence": 0}, schema)
        client._validate_arguments({"after_sequence": 1, "through": 17}, schema)

    def test_reindex_uses_same_vault_without_signer_or_sync_notification(self) -> None:
        config = mock.Mock()
        config.vault_path.exists.return_value = True
        config.vault.return_value.handle.return_value = core.success({"state": "index_page_rebuilt"})
        arguments = {"request_id": "req_synthetic_index_01", "after": 3, "through": 21, "limit": 4}
        with mock.patch.object(client.ClientConfig, "load", return_value=config), \
                mock.patch.object(client, "notify_sync", side_effect=AssertionError("No sync notification")):
            self.server.call("memory_reindex", arguments)
            self.server.call("memory_reindex", arguments)
        self.assertEqual(config.vault.call_args_list, [mock.call(), mock.call()])
        expected = {"op": "memory.reindex", **arguments,
                    "request_id": client._request_id(arguments["request_id"], "reindex")}
        self.assertEqual(config.vault.return_value.handle.call_args_list, [mock.call(expected), mock.call(expected)])

    def test_capabilities_does_not_resolve_default_vault_or_config(self) -> None:
        with mock.patch.dict(os.environ, {"MEMORY_VAULT_PATH": "intentionally-relative"}), \
                mock.patch.object(client, "Vault", side_effect=AssertionError("No Vault selection")), \
                mock.patch.object(client.ClientConfig, "load", side_effect=AssertionError("No client load")):
            response = self.invoke("memory_capabilities")
        self.assertTrue(response["result"]["structuredContent"]["ok"])
        self.assertEqual(list(self.root.iterdir()), [])

    def test_ordinary_tool_result_keeps_both_complete_representations(self) -> None:
        original = core.success({"state": "synthetic", "memory_id": MEMORY_ID})
        with mock.patch.object(self.server, "call", return_value=original):
            response = self.invoke("memory_get", {"memory_id": MEMORY_ID})
        self.assertEqual(response["result"]["structuredContent"], original)
        self.assertEqual(json.loads(response["result"]["content"][0]["text"]), original)
        self.assertLessEqual(len(core.canonical_bytes(response)) + 1, core.MAX_RESPONSE_BYTES)

    def test_large_legal_record_keeps_exact_structured_content_and_hash(self) -> None:
        record = core.build_record(kind="fact", text="Synthetic escaped evidence: " + "\\" * 750_000,
                                   created_at="2026-01-01T00:00:00Z")
        self.assertLessEqual(len(core.canonical_bytes(record)), core.MAX_BUNDLE_LINE_BYTES)
        original = core.success({"record": record, "verification": {"eligible_for_context": True,
                                                                   "grants_authority": False}})
        with mock.patch.object(self.server, "call", return_value=original):
            response = self.invoke("memory_get", {"memory_id": record["memory_id"]}, identifier="large-record-1")
        self.assertEqual(response["id"], "large-record-1")
        self.assertIs(response["result"]["structuredContent"], original)
        self.assertIn("complete result is in structuredContent", response["result"]["content"][0]["text"])
        self.assertFalse(response["result"]["isError"])
        self.assertEqual(core.validate_record(response["result"]["structuredContent"]["result"]["record"]), record)
        self.assertLessEqual(len(core.canonical_bytes(response)) + 1, core.MAX_RESPONSE_BYTES)

    def test_complete_oversized_result_returns_bounded_error_with_original_id(self) -> None:
        original = core.success({"synthetic_multiple_record_page": "x" * core.MAX_RESPONSE_BYTES})
        with mock.patch.object(self.server, "call", return_value=original):
            response = self.invoke("memory_views", identifier="synthetic-size-error")
        self.assertEqual(response["id"], "synthetic-size-error")
        self.assertEqual(response["error"]["code"], -32603)
        self.assertNotIn("result", response)
        self.assertIn("No partial record", response["error"]["message"])
        self.assertLessEqual(len(core.canonical_bytes(response)) + 1, core.MAX_RESPONSE_BYTES)

    def test_final_newline_is_part_of_handle_frame_budget(self) -> None:
        exact = {"jsonrpc": "2.0", "id": 7, "result": {"padding": ""}}
        exact["result"]["padding"] = "x" * (core.MAX_RESPONSE_BYTES - len(core.canonical_bytes(exact)))
        self.assertEqual(len(core.canonical_bytes(exact)), core.MAX_RESPONSE_BYTES)
        with mock.patch.object(self.server, "_handle", return_value=exact):
            response = self.invoke("memory_capabilities")
        self.assertEqual(response["error"]["code"], -32603)
        self.assertLessEqual(len(core.canonical_bytes(response)) + 1, core.MAX_RESPONSE_BYTES)

    def test_tools_list_is_also_response_bounded(self) -> None:
        self.server.tools = {"synthetic": {"name": "synthetic", "description": "x" * core.MAX_RESPONSE_BYTES}}
        response = self.server.handle({"jsonrpc": "2.0", "id": 17, "method": "tools/list"})
        self.assertEqual(response["id"], 17)
        self.assertEqual(response["error"]["code"], -32603)
        self.assertLessEqual(len(core.canonical_bytes(response)) + 1, core.MAX_RESPONSE_BYTES)

    def test_invalid_inprocess_ids_cannot_make_an_unbounded_error(self) -> None:
        for identifier in (True, None, 1.5, "x" * (core.MAX_REQUEST_BYTES + 1), "\ud800"):
            with self.subTest(kind=type(identifier).__name__):
                response = self.server.handle({"jsonrpc": "2.0", "id": identifier, "method": "ping"})
                self.assertIsNone(response["id"])
                self.assertEqual(response["error"]["code"], -32600)
                self.assertLessEqual(len(core.canonical_bytes(response)) + 1, core.MAX_RESPONSE_BYTES)

    def test_notifications_remain_response_free(self) -> None:
        self.assertIsNone(self.server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}))

    def test_partial_observe_retains_failure_and_exact_episode_identity(self) -> None:
        config = mock.Mock()
        config.vault.return_value.handle.side_effect = [
            core.success({"memory_id": MEMORY_ID}), core.failure("synthetic_signer_unavailable", retryable=True),
        ]
        result = client.observe_turn(config, request_id="req_synthetic_partial_01", user="Synthetic question",
                                     assistant="Synthetic answer")
        self.assertFalse(result["ok"])
        self.assertEqual(result["partial_result"], {"episode_saved": True, "episode_id": MEMORY_ID,
                                                  "continuity_saved": False, "retry_same_request": True})
        self.assertNotIn("result", result)


@unittest.skipUnless(Draft202012Validator is not None, "optional jsonschema/referencing are not installed")
class ClientSchemaTests(unittest.TestCase):
    def test_advertised_mcp_schema_and_runtime_agree_on_view_selectors(self) -> None:
        schema = next(tool["inputSchema"] for tool in client.tool_definitions() if tool["name"] == "memory_views")
        validator = Draft202012Validator(schema)
        valid = ({}, {"entity": "claim:synthetic", "after_memory_id": MEMORY_ID},
                 {"query": "synthetic", "after_sequence": 0}, {"after_sequence": 2, "through": 12})
        invalid = ({"entity": "claim:synthetic", "query": "synthetic"}, {"after_memory_id": MEMORY_ID},
                   {"query": "synthetic", "after_sequence": 1}, {"maximum_nodes": 65})
        for value in valid:
            validator.validate(value)
            client._validate_arguments(value, schema)
        for value in invalid:
            self.assertFalse(validator.is_valid(value), value)
            with self.assertRaises(core.MemoryError):
                client._validate_arguments(value, schema)

    def test_capabilities_matches_shared_result_schema(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = client.MCPServer(Path(directory).resolve() / "absent.json").call("memory_capabilities", {})
        validator = schema_validator("result.schema.json")
        validator.validate(result)
        changed = copy.deepcopy(result)
        changed["client"]["external_provider_contracts"]["production_providers_configured_by_default"] = True
        self.assertFalse(validator.is_valid(changed))

    def test_client_health_and_partial_failure_match_shared_result_schema(self) -> None:
        validator = schema_validator("result.schema.json")
        status = {**core.success({"state": "not_initialized", "records": 0, "network_accessed": False}),
                  "client": {"configured": True, "capture_visible_turns": False, "signing_configured": False,
                             "sync_configured": False, "work_automatic_hooks_verified": False}}
        validator.validate(status)
        partial = {**core.failure("synthetic_pending", retryable=True), "partial_result": {
            "episode_saved": True, "episode_id": MEMORY_ID, "continuity_saved": False, "retry_same_request": True}}
        validator.validate(partial)
        self.assertFalse(validator.is_valid({**core.success({}), "partial_result": partial["partial_result"]}))
        self.assertFalse(validator.is_valid({**status, "unpublished_envelope_field": True}))

    def test_all_ten_host_requests_match_schema_and_closed_python_validator(self) -> None:
        validator = schema_validator("host-compat-request.schema.json")
        payloads = {
            "capabilities": {}, "memory.status": {}, "sync.flush": {},
            "session.open": {"continuity_handle": None, "reason": "compact"},
            "session.close": {"continuity_handle": SESSION},
            "turn.input": {"continuity_handle": SESSION, "turn_handle": None, "visible_user_text": "Synthetic", "limit": 8},
            "turn.commit": {"continuity_handle": SESSION, "turn_handle": None, "outcome": "final",
                            "visible_user_text": "Synthetic", "visible_assistant_text": "Synthetic final"},
            "turn.abort": {"continuity_handle": SESSION, "turn_handle": TURN, "reason": "cancelled"},
            "memory.recall": {"query": "synthetic", "limit": 8, "maximum_context_bytes": 8192},
            "memory.remember": {"proposal": semantic_proposal()},
        }
        self.assertEqual(set(payloads), set(compat.OPERATIONS))
        for operation, payload in payloads.items():
            with self.subTest(operation=operation):
                request = host_request(operation, payload)
                validator.validate(request)
                compat.validate_request(request)

    def test_post_only_commit_requires_visible_user_and_no_permission_field(self) -> None:
        validator = schema_validator("host-compat-request.schema.json")
        request = host_request("turn.commit", {"continuity_handle": SESSION, "turn_handle": None, "outcome": "final",
                                               "visible_user_text": None, "visible_assistant_text": "Synthetic"})
        self.assertFalse(validator.is_valid(request))
        request["payload"]["turn_handle"] = TURN
        validator.validate(request)
        request["payload"]["permission"] = "execute"
        self.assertFalse(validator.is_valid(request))

    def test_all_ten_host_result_shapes_and_negative_authority(self) -> None:
        validator = schema_validator("host-compat-result.schema.json")
        local = {"saved": 0, "pending": 0, "errors": [], "network_accessed": False}
        results = {
            "capabilities": compat.capability_result(),
            "session.open": {"continuity_handle": SESSION, "sync_state": "local_only", "network_accessed": False},
            "session.close": {"continuity_handle": SESSION, "closed": True, "network_accessed": False},
            "turn.input": {"continuity_handle": SESSION, "turn_handle": TURN, "evidence_context": None, "network_accessed": False},
            "turn.commit": {"continuity_handle": SESSION, "turn_handle": TURN, "outcome": "final", "receipt_id": "mvrturn_" + "d" * 64,
                            "queue_state": "pending", "network_accessed": False},
            "turn.abort": {"continuity_handle": SESSION, "turn_handle": TURN, "aborted": False,
                           "terminal_state": "committed", "queue_state": "pending", "network_accessed": False},
            "memory.recall": {"evidence_context": None, "network_accessed": False},
            "memory.status": {"plugin_version": core.VERSION, "enabled": True, "memory_model": "taskless_associative_append_only",
                              "outbox": {"pending": 0, "done": 0, "quarantine": 0, "recovery-v1": 0},
                              "index": {"available": False, "documents": 0, "fragments": 0, "edges": 0},
                              "network_accessed": False, "capture_enabled": False, "staged_turns": 0,
                              "legacy_index_counts_identical": False, "record_signatures_reverified": False,
                              "compatibility_profile": compat.ALIAS_PROFILE},
            "sync.flush": {"schema_version": "memory-network-flush/v1", "state": "local_only", "published": 0,
                           "publication": {"state": "local_only", "published": 0, "local": local}, "receive": None,
                           "network_accessed": False, "remote_ai_read_verified": False},
        }
        record = core.build_record(kind="decision", text="Synthetic schema fixture", created_at="2026-01-01T00:00:00Z")
        evidence = {"legacy_id": "ep-" + "a" * 40, "memory_id": MEMORY_ID, "record_sha256": "b" * 64,
                    "source_id": "src-" + "a" * 40, "evidence_anchor_sha256": "b" * 64, "original_v021_identity": False}
        results["memory.remember"] = compat._semantic_result(record, evidence, duplicate=False)
        self.assertEqual(set(results), set(compat.OPERATIONS))
        for operation, result in results.items():
            with self.subTest(operation=operation):
                response = compat._ok(host_request(operation, {}), result)
                validator.validate(response)
                changed = copy.deepcopy(response)
                changed["authority"]["execution_eligible"] = True
                self.assertFalse(validator.is_valid(changed))

    def test_host_errors_are_closed_and_can_have_null_correlation(self) -> None:
        validator = schema_validator("host-compat-result.schema.json")
        result = compat._error(None, "synthetic_rejected", retryable=False)
        validator.validate(result)
        self.assertIsNone(result["request_id"])
        changed = {**result, "result": {"state": "fake_success"}}
        self.assertFalse(validator.is_valid(changed))


if __name__ == "__main__":
    unittest.main()
