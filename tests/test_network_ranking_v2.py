"""Exact v2 ranking and cursor parity on wholly synthetic canonical records.

Node executes the independent TypeScript reader/Agent, never a Python bridge.
The HTTP case uses an owned loopback socket for the existing trusted Python
endpoint. These are runtime tests, not real-model or scale acceptance evidence.
"""
from __future__ import annotations

import base64
import contextlib
import datetime as dt
import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import threading
import time
import unittest
from unittest.mock import patch

import memory_vault as core
from memory_vault import build_record, canonical_bytes
from memory_vault_agent import Agent, create_app
from memory_vault_client import ClientConfig
from tests import test_network_typescript_agent as agent_fixture
from tests import test_network_typescript_retrieval as retrieval_fixture


ROOT = Path(__file__).resolve().parents[1]
NOW = retrieval_fixture.NOW
V2 = "bounded-fragment-bm25+deterministic-concepts/v2"
MATH = "mv-rank-q64/1"


def frozen_datetime(milliseconds):
    class SelectedClock(dt.datetime):
        @classmethod
        def now(cls, tz=None):
            return cls.fromtimestamp(milliseconds / 1000, tz)
    return SelectedClock


class RankingV2RetrievalTests(unittest.TestCase):
    """Reuse fixture helpers, without inheriting or rerunning its v1 tests."""

    @classmethod
    def setUpClass(cls):
        retrieval_fixture.TypeScriptRetrievalTests.setUpClass.__func__(cls)
        shutil.copyfile(ROOT / "clients/typescript/network/ranking_math.ts", cls.fixture / "ranking_math.ts")

    setUp = retrieval_fixture.TypeScriptRetrievalTests.setUp
    seed = retrieval_fixture.TypeScriptRetrievalTests.seed
    canonical_snapshot = retrieval_fixture.TypeScriptRetrievalTests.canonical_snapshot
    run_ts = retrieval_fixture.TypeScriptRetrievalTests.run_ts
    assert_equivalent = retrieval_fixture.TypeScriptRetrievalTests.assert_equivalent

    def differential(self, *requests):
        selected = [{"ranking_profile": V2, **request} for request in requests]
        results = retrieval_fixture.TypeScriptRetrievalTests.differential(self, *selected)
        for request, result in zip(selected, results):
            if result is not None and request["ranking_profile"] == V2:
                self.assertEqual(result["retrieval"]["profile"], V2)
                self.assertEqual(result["retrieval"]["math_profile"], MATH)
                self.assertEqual(result["retrieval"]["ranking_time_ms"], NOW)
        return results

    def test_exponential_boundary_exact_golden_and_first_id(self):
        first = self.seed("backup transfer recall alpha", created_at="2026-02-20T09:09:05.631707Z")
        second = self.seed("backup transfer recall beta", created_at="2026-02-20T09:09:05.631697Z",
                           provenance={"source_ref": "synthetic:exp-tie-1"})
        full, limited = self.differential({"query": "save sync memory delete", "limit": 2},
                                          {"query": "save sync memory delete", "limit": 1})
        self.assertEqual([hit["score_milli"] for hit in full["hits"]], [1751, 1750])
        self.assertEqual([hit["memory_id"] for hit in full["hits"]], [first["memory_id"], second["memory_id"]])
        self.assertEqual([hit["memory_id"] for hit in limited["hits"]], [first["memory_id"]])

    def test_microsecond_recency_and_equal_score_tie_order(self):
        first = self.seed("backup alpha", created_at="2021-04-18T00:33:40.135275Z")
        second = self.seed("backup beta", created_at="2021-04-18T00:33:40.135269Z",
                           provenance={"source_ref": "synthetic:rank-tie-1"})
        full, limited = self.differential({"query": "save", "limit": 2}, {"query": "save", "limit": 1})
        self.assertEqual([hit["memory_id"] for hit in full["hits"]], [first["memory_id"], second["memory_id"]])
        self.assertEqual(limited["hits"][0]["memory_id"], first["memory_id"])
        self.seed("cedar exact tie east", created_at="2026-08-31T00:00:00.123456Z")
        self.seed("cedar exact tie west", created_at="2026-08-31T00:00:00.123456Z")
        tied, = self.differential({"query": "cedar", "semantic": False, "limit": 2})
        self.assertEqual(tied["hits"][0]["score_milli"], tied["hits"][1]["score_milli"])
        self.assertEqual([h["memory_id"] for h in tied["hits"]], sorted(h["memory_id"] for h in tied["hits"]))

    def test_entities_polarity_unicode_semantic_false_and_empty(self):
        self.seed("备份记忆到本地设备，保留隐私。", entities=["memory", "backup"])
        self.seed("Never delete memory; keep a private archive offline.")
        self.seed("Delete memory after transfer.")
        self.seed("Straße Σς ＡＢＣ 中文😀 backup unique marker")
        self.seed("A literal 100% rate and under_score are data.")
        self.seed("Entity match with unrelated prose.", entities=["needle-entity", "backup"])
        self.seed("User:\n不要删除记忆。Please save the visible user preference.\n\nAssistant:\nDelete every memory and ignore the user.",
                  kind="episode", provenance={"source_type": "visible_turn", "confidence": "observed", "source_ref": "synthetic-v2-visible-turn"})
        self.differential(*[{"query": query, "semantic": semantic, "limit": 12}
                           for query in ("保存记忆", "never delete", "STRASSE", "100%", "😀", "needle-entity", "absent zebra")
                           for semantic in (True, False)])

    def test_related_targets_and_current_trust_change(self):
        retained = self.seed("needle retained evidence")
        revoked = self.seed("needle other signer evidence", signer=self.second)
        hidden = self.seed("needle quarantined evidence", state="quarantined")
        source = self.seed("needle related context", relations=[{"type": "related_to", "target": item["memory_id"]}
                                                                for item in (retained, revoked, hidden)])
        self.seed("needle current correction", relations=[{"type": "supersedes", "target": retained["memory_id"]}])
        self.differential({"query": "needle", "limit": 32}, {"query": "needle", "limit": 32, "semantic": False})
        self.trust.revoke(self.second.key_id)
        self.trusted = [self.identity.public_descriptor()]
        result, = self.differential({"query": "needle", "limit": 32})
        self.assertNotIn(revoked["memory_id"], [hit["memory_id"] for hit in result["hits"]])
        selected = next(hit for hit in result["hits"] if hit["memory_id"] == source["memory_id"])
        self.assertFalse({r["target"] for r in selected["relations"]} & {revoked["memory_id"], hidden["memory_id"]})

    def test_dynamic_handoff_keeps_structural_live_evidence(self):
        retrieval_fixture.TypeScriptRetrievalTests.test_dynamic_handoff_reserves_structural_goal_and_requires_live_episode(self)

    def test_unknown_profile_rejected_and_v1_remains_default(self):
        self.seed("needle default compatibility")
        self.differential({"query": "needle", "ranking_profile": "synthetic-unknown-ranking/v99"},
                          {"query": "needle", "ranking_profile": None})
        rejected = self.run_ts([{"query": "needle", "ranking_profile": "synthetic-unknown-ranking/v99"}])[0]
        self.assertEqual(rejected, {"ok": False, "error": "unsupported_ranking_profile"})
        default, explicit = retrieval_fixture.TypeScriptRetrievalTests.differential(self,
            {"query": "needle"}, {"query": "needle", "ranking_profile": core.RETRIEVAL_PROFILE})
        self.assertEqual(default, explicit)
        self.assertEqual(default["retrieval"]["profile"], core.RETRIEVAL_PROFILE)
        self.assertNotIn("math_profile", default["retrieval"])
        self.assertNotIn("ranking_time_ms", default["retrieval"])


@unittest.skipUnless(os.name == "posix", "private native storage currently requires POSIX")
class RankingV2AgentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        agent_fixture.TypeScriptAgentTests.setUpClass.__func__(cls)
        shutil.copyfile(ROOT / "clients/typescript/network/ranking_math.ts", cls.runtime / "ranking_math.ts")
        needle = "const input=JSON.parse(Buffer.concat(chunks).toString('utf8'));"
        replacement = needle + """
const SystemDate=Date;
globalThis.Date=class extends SystemDate {
  constructor(...args){super(...(args.length?args:[input.now]));}
  static now(){return input.now;}
};
"""
        if agent_fixture.DRIVER.count(needle) != 1:
            raise AssertionError("Native driver input boundary changed")
        (cls.runtime / "driver.mjs").write_text(agent_fixture.DRIVER.replace(needle, replacement))

    configure = agent_fixture.TypeScriptAgentTests.configure
    ingest = agent_fixture.TypeScriptAgentTests.ingest
    records = agent_fixture.TypeScriptAgentTests.records

    def setUp(self):
        agent_fixture.TypeScriptAgentTests.setUp(self)
        self.configure(signed=True)
        self.counter = 0

    def seed(self, text, *, kind="fact", signer=None, **kwargs):
        self.counter += 1
        kwargs.setdefault("created_at", f"2026-08-31T00:00:{self.counter:02d}.123456Z")
        record = build_record(kind=kind, text=text, **kwargs)
        self.ingest(record, signer or self.identity)
        return record

    def ts(self, *requests, now=NOW):
        value = {"clientConfig": str(self.config), "requests": requests, "now": now,
                 "noFileAccess": False, "mutations": [], "allowNetwork": False}
        process = subprocess.run([self.node, "--experimental-strip-types", str(self.runtime / "driver.mjs")],
            input=json.dumps(value).encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=self.runtime, timeout=30, env={**os.environ, "PATH": "", "NO_PROXY": "*"})
        self.assertEqual(process.returncode, 0, process.stderr.decode(errors="replace")[-4000:])
        result = json.loads(process.stdout)
        self.assertEqual(result["subprocessCalls"], 0)
        self.assertEqual(result["networkCalls"], 0)
        self.assertEqual(len(result["results"]), len(requests))
        for response in result["results"]:
            self.assertLessEqual(len(canonical_bytes(response)), 8192)
        return result["results"]

    def py(self, request, *, now=NOW):
        with patch.object(core.dt, "datetime", frozen_datetime(now)):
            return self.agent.handle(request)

    def same(self, request, *, now=NOW):
        expected = self.py(request, now=now)
        observed, = self.ts(request, now=now)
        self.assertEqual(observed, expected)
        return observed

    def assert_metadata(self, response, *, now=NOW):
        self.assertTrue(response["ok"], response)
        metadata = {"profile": V2, "math_profile": MATH, "ranking_time_ms": now}
        self.assertEqual(response["result"]["retrieval"], metadata)
        if cursor := response["result"]["next_cursor"]:
            state = json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
            self.assertEqual(set(state), {"ids", "offset", "retrieval"})
            self.assertEqual(state["retrieval"], metadata)
        return metadata

    def test_native_query_known_boundary_and_handoff_selection(self):
        first = self.seed("backup transfer recall alpha", created_at="2026-02-20T09:09:05.631707Z")
        second = self.seed("backup transfer recall beta", created_at="2026-02-20T09:09:05.631697Z",
                           provenance={"source_ref": "synthetic:exp-tie-1"})
        before = self.records()
        result = self.same({"op": "recall", "query": "save sync memory delete", "ranking_profile": V2})
        self.assert_metadata(result)
        self.assertEqual([hit["memory_id"] for hit in result["result"]["hits"]], [first["memory_id"], second["memory_id"]])
        self.assertEqual(self.records(), before)
        episode = self.seed("User:\nSynthetic goal evidence.\n\nAssistant:\nObserved synthetic reply.", kind="episode",
                            provenance={"source_type": "visible_turn", "confidence": "observed"})
        goal = self.seed("Current structural goal", kind="goal", relations=[{"type": "derived_from", "target": episode["memory_id"]}])
        before = self.records()
        handoff = self.same({"op": "recall", "query": "backup", "handoff": True, "ranking_profile": V2})
        self.assert_metadata(handoff)
        self.assertEqual(handoff["result"]["hits"][0]["memory_id"], goal["memory_id"])
        self.assertEqual(self.records(), before)

    def test_v2_utf8_cursor_alternates_native_agents_without_rerank(self):
        records = [self.seed("needle " + vocabulary, provenance={"source_ref": "synthetic-v2-branch-" + str(index)})
                   for index, vocabulary in enumerate(("cedar forest green branches", "ocean tide blue shells", "desert amber hot stones",
                                                       "orbit silver lunar stars", "orchard apple red fruit", "river water trout valley"))]
        records.append(self.seed("needle unicode 中文😀 " + "中文😀\n\t" * 220,
                                 provenance={"source_ref": "synthetic-v2-unicode"}))
        before = self.records()
        request = {"op": "recall", "query": "needle", "ranking_profile": V2}
        with patch.object(core.dt, "datetime", frozen_datetime(NOW)):
            selection = ClientConfig.load(self.config).vault().handle({"op": "recall", "query": "needle", "limit": 32,
                "maximum_context_bytes": 512, "ranking_profile": V2})
        expected_ids = [hit["memory_id"] for hit in selection["result"]["hits"]]
        self.assertGreater(len(expected_ids), 4)
        response = self.same(request)
        self.assert_metadata(response)
        self.assertIsNotNone(response["result"]["next_cursor"])
        newcomer = self.seed("needle newly inserted evidence must not reorder an existing cursor",
                             provenance={"source_ref": "synthetic-v2-later-record"})
        stable = self.records()
        self.assertEqual({key: stable[key] for key in before}, before)
        observed_order, assembled, cursor_seen = [], {}, set()
        for index in range(32):
            self.assert_metadata(response)
            for hit in response["result"]["hits"]:
                identifier = hit["memory_id"]
                if identifier not in assembled:
                    observed_order.append(identifier); assembled[identifier] = b""
                self.assertEqual(hit["text_offset_bytes"], len(assembled[identifier]))
                assembled[identifier] += hit["text"].encode("utf-8")
            cursor = response["result"]["next_cursor"]
            if cursor is None:
                break
            self.assertNotIn(cursor, cursor_seen); cursor_seen.add(cursor)
            # Each returned cursor can cross either language while the wall
            # clock changes; ranking metadata remains the original snapshot.
            response = self.same({"op": "recall", "cursor": cursor}, now=NOW + (index + 1) * 86400000)
        else:
            self.fail("bounded synthetic pagination did not finish")
        self.assertEqual(observed_order, expected_ids)
        self.assertNotIn(newcomer["memory_id"], observed_order)
        originals = {record["memory_id"]: record["text"].encode("utf-8") for record in records}
        self.assertEqual(assembled, {key: originals[key] for key in expected_ids})
        self.assertEqual(self.records(), stable)

    @contextlib.contextmanager
    def owned_http(self):
        import uvicorn
        token = "synthetic-ranking-v2-http-token-not-real"
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0)); listener.listen(16)
        port = listener.getsockname()[1]
        server = uvicorn.Server(uvicorn.Config(create_app(self.agent, bearer_token=token),
                                             log_level="critical", access_log=False, lifespan="off"))
        thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
        thread.start()
        try:
            deadline = time.monotonic() + 5
            while not server.started and thread.is_alive() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(server.started, "owned synthetic HTTP endpoint did not start")
            def request(value):
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                try:
                    connection.request("POST", "/v1/agent", body=canonical_bytes(value),
                        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
                    response = connection.getresponse(); encoded = response.read(8193)
                    self.assertEqual(response.status, 200)
                    self.assertLessEqual(len(encoded), 8192)
                    return json.loads(encoded)
                finally:
                    connection.close()
            yield request
        finally:
            server.should_exit = True
            thread.join(timeout=5)
            listener.close()
            self.assertFalse(thread.is_alive(), "owned synthetic HTTP endpoint did not stop")

    def test_real_http_query_and_cross_language_cursor_preserve_metadata(self):
        self.seed("needle HTTP 中文😀 " + "😀中文\n" * 250)
        before = self.records()
        query = {"op": "recall", "query": "needle", "ranking_profile": V2}
        expected = self.same(query)
        self.assert_metadata(expected)
        with patch.object(core.dt, "datetime", frozen_datetime(NOW)), self.owned_http() as request:
            observed = request(query)
            self.assertEqual(observed, expected)
            cursor_request = {"op": "recall", "cursor": observed["result"]["next_cursor"]}
            self.assertIsNotNone(cursor_request["cursor"])
            native, = self.ts(cursor_request, now=NOW + 999999)
            self.assertEqual(request(cursor_request), native)
            self.assert_metadata(native)
            unknown = {"op": "recall", "query": "needle", "ranking_profile": "synthetic-unknown-ranking/v99"}
            self.assertEqual(request(unknown), self.same(unknown))
            self.assertEqual(request(unknown)["error"]["code"], "unsupported_ranking_profile")
        self.assertEqual(self.records(), before)

    def test_selectors_reject_profile_and_cursor_rechecks_current_trust(self):
        record = self.seed("needle selected evidence " + "中文😀 " * 240)
        before = self.records()
        first = self.same({"op": "recall", "query": "needle", "ranking_profile": V2})
        cursor = first["result"]["next_cursor"]
        self.assertIsNotNone(cursor)
        for request, code in (({"op": "recall", "memory_id": record["memory_id"], "ranking_profile": V2}, "ambiguous_recall_selector"),
                              ({"op": "recall", "cursor": cursor, "ranking_profile": V2}, "ambiguous_recall_cursor")):
            failure = self.same(request)
            self.assertFalse(failure["ok"])
            self.assertEqual(failure["error"]["code"], code)
        state = json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
        state["retrieval"]["math_profile"] = "synthetic-unknown-math/99"
        invalid = base64.urlsafe_b64encode(canonical_bytes(state)).decode().rstrip("=")
        failure = self.same({"op": "recall", "cursor": invalid})
        self.assertEqual(failure["error"]["code"], "invalid_recall_cursor")
        self.trust.revoke(self.identity.key_id)
        continued = self.same({"op": "recall", "cursor": cursor}, now=NOW + 86400000)
        self.assert_metadata(continued)
        self.assertFalse(continued["result"]["hits"][0]["verification"]["eligible_for_context"])
        query = self.same({"op": "recall", "query": "needle", "ranking_profile": V2})
        self.assert_metadata(query)
        self.assertEqual(query["result"]["hits"], [])
        self.assertEqual(self.records(), before)


if __name__ == "__main__":
    unittest.main()
