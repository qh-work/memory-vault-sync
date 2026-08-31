"""Independent native Agent facade versus the real Python Agent.

Only disposable synthetic files are used. Node never launches Python, invokes
another subprocess, or accesses the network for the local cases. Python is the
separate test oracle and an alternating writer of the same canonical SQLite
records/receipts. Missing preinstalled Node/jose is a skip, never a pass.
"""
from __future__ import annotations

import base64
import contextlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile
import unittest

from memory_vault import AUTHORITY, build_record, canonical_bytes
from memory_vault_agent import Agent
from memory_vault_client import CONFIG_SCHEMA, ClientConfig
from memory_vault_storage import atomic_write
from memory_vault_trust import Identity, TrustStore


ROOT = Path(__file__).resolve().parents[1]
MODULES = ("crypto.ts", "control.ts", "nodes.ts", "records.ts", "vault.ts",
           "io.ts", "transport.ts", "peer.ts", "setup.ts", "agent.ts",
           "retrieval.ts", "retrieval_text.ts", "ranking_math.ts", "package.json")
DRIVER = r"""
import fs from 'node:fs';
import child from 'node:child_process';
import net from 'node:net';
import http from 'node:http';
import https from 'node:https';
import {syncBuiltinESMExports} from 'node:module';
const chunks=[];let size=0;
for await(const chunk of process.stdin){size+=chunk.length;if(size>4*1024*1024)throw Error('synthetic fixture input limit');chunks.push(chunk);}
const input=JSON.parse(Buffer.concat(chunks).toString('utf8'));
let subprocessCalls=0,networkCalls=0,fileCalls=0;
const denySubprocess=()=>{subprocessCalls++;throw Error('native Agent must not spawn subprocesses');};
const denyNetwork=()=>{networkCalls++;throw Error('local Agent must not access the network');};
for(const name of ['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork'])child[name]=denySubprocess;
const connect=net.Socket.prototype.connect;
net.Socket.prototype.connect=input.allowNetwork?function(...args){networkCalls++;return connect.apply(this,args);}:denyNetwork;
net.Server.prototype.listen=denyNetwork;
if(!input.allowNetwork)http.request=https.request=http.get=https.get=denyNetwork;
globalThis.fetch=denyNetwork;
syncBuiltinESMExports();
const {Agent}=await import('./agent.ts');
const {HTTPTransport}=await import('./transport.ts');
if(input.noFileAccess){
 const deny=()=>{fileCalls++;throw Error('constructor/offline discover must not access files');};
 for(const name of ['openSync','readFileSync','writeFileSync','appendFileSync','statSync','lstatSync','accessSync','existsSync','mkdirSync','readdirSync','realpathSync','open','readFile','writeFile','stat','lstat','access','mkdir','readdir','realpath'])fs[name]=deny;
 for(const name of ['open','readFile','writeFile','stat','lstat','access','mkdir','readdir','realpath'])fs.promises[name]=deny;
 syncBuiltinESMExports();
}
let agent;const results=[];
const transport=input.allowNetwork?new HTTPTransport():{request:denyNetwork,close(){}};
try{
 agent=new Agent(input.clientConfig,input.networkConfig,{transport});
 for(let index=0;index<input.requests.length;index++){
  // A controlled external trust update between calls on this same Agent.
  for(const change of input.mutations??[])if(change.before===index)fs.writeFileSync(change.path,change.contents,{mode:0o600});
  results.push(await agent.handle(input.requests[index]));
 }
}finally{agent?.close?.();transport.close();}
process.stdout.write(JSON.stringify({results,subprocessCalls,networkCalls,fileCalls}));
"""


@unittest.skipUnless(os.name == "posix", "native private storage currently requires POSIX")
class TypeScriptAgentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.node = os.environ.get("MEMORY_VAULT_NODE") or shutil.which("node")
        if cls.node is None:
            raise unittest.SkipTest("Existing Node >=22.19 is required")
        version = subprocess.check_output([cls.node, "--version"], text=True).strip()
        major, minor, *_ = map(int, version.lstrip("v").split("."))
        if major < 22 or (major == 22 and minor < 19):
            raise unittest.SkipTest("Existing Node >=22.19 is required")
        package = ROOT / "clients/typescript/network/node_modules/jose"
        selected = os.environ.get("MEMORY_VAULT_JOSE_MODULE")
        if selected:
            entry = Path(selected).resolve()
            if entry.parts[-3:] != ("dist", "webapi", "index.js"):
                raise RuntimeError("Expected explicit jose/dist/webapi/index.js")
            package = entry.parents[2]
        if not (package / "package.json").is_file():
            raise unittest.SkipTest("Existing locked jose required; tests never install")
        meta = json.loads((package / "package.json").read_bytes())
        if (meta.get("name"), meta.get("version")) != ("jose", "6.2.10"):
            raise RuntimeError("Exact locked jose 6.2.10 required")
        cls.temporary = tempfile.TemporaryDirectory(prefix="memory-vault-ts-agent-synthetic-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.runtime = Path(cls.temporary.name).resolve()
        for name in MODULES:
            shutil.copyfile(ROOT / "clients/typescript/network" / name, cls.runtime / name)
        (cls.runtime / "node_modules").mkdir()
        (cls.runtime / "node_modules/jose").symlink_to(package, target_is_directory=True)
        (cls.runtime / "driver.mjs").write_text(DRIVER)

    def setUp(self):
        self.directory = Path(tempfile.mkdtemp(prefix="case-", dir=self.runtime))
        self.config = self.directory / "client.json"
        self.database = self.directory / "vault.sqlite3"
        self.identity_path = self.directory / "identity.json"
        self.trust_path = self.directory / "trust.json"
        self.agent = Agent(self.config)

    def configure(self, *, signed=False):
        value = {"schema_version": CONFIG_SCHEMA, "vault_path": str(self.database),
                 "capture_visible_turns": False}
        if signed:
            self.identity = Identity.generate(self.identity_path)
            self.trust = TrustStore(self.trust_path)
            self.trust.add(self.identity.public_descriptor(), "synthetic facade signer")
            value.update(identity_path=str(self.identity_path), trust_path=str(self.trust_path))
        atomic_write(self.config, canonical_bytes(value), replace=False)

    def ts(self, *requests, network_config=None, no_file_access=False, mutations=(),
           client_config=None, allow_network=False):
        value = {"clientConfig": str(client_config or self.config), "requests": requests,
                 "noFileAccess": no_file_access, "mutations": mutations, "allowNetwork": allow_network}
        if network_config is not None:
            value["networkConfig"] = str(network_config)
        process = subprocess.run([self.node, "--experimental-strip-types", str(self.runtime / "driver.mjs")],
            input=json.dumps(value).encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=self.runtime, timeout=30, env={**os.environ, "PATH": "", "NO_PROXY": "*"})
        self.assertEqual(process.returncode, 0, process.stderr.decode(errors="replace")[-4000:])
        result = json.loads(process.stdout)
        self.assertEqual(result["subprocessCalls"], 0)
        if allow_network:
            self.assertGreater(result["networkCalls"], 0)
        else:
            self.assertEqual(result["networkCalls"], 0)
        if no_file_access:
            self.assertEqual(result["fileCalls"], 0)
        self.assertEqual(len(result["results"]), len(requests))
        for item in result["results"]:
            self.assertEqual(item["authority"], AUTHORITY)
            self.assertLessEqual(len(canonical_bytes(item)), 8192)
        return result["results"]

    def value(self, request):
        response, = self.ts(request)
        self.assertTrue(response["ok"], response)
        return response

    def same(self, *requests):
        expected = [self.agent.handle(request) for request in requests]
        observed = self.ts(*requests)
        self.assertEqual(observed, expected)
        return observed

    def records(self):
        with sqlite3.connect(self.database) as connection:
            return {row[0]: tuple(row[1:]) for row in connection.execute(
                "SELECT m.memory_id,m.record_json,a.state,a.signer_key_id,a.attestation_json "
                "FROM memories m JOIN record_admissions a USING(memory_id)")}

    def ingest(self, record, identity=None):
        proofs = {record["memory_id"]: identity.sign_record(record)} if identity else {}
        if identity:
            self.trust.verify_record(record, proofs[record["memory_id"]])
        return ClientConfig.load(self.config).vault().ingest_records(
            [record], admission="verified" if identity else "accepted_unsigned", attestations=proofs)

    def assert_evidence_usage(self, result):
        self.assertEqual(result["evidence_usage"], {
            "basis": "retrieved_historical_evidence",
            "attribution": "recorded_source_not_assumed_reader_experience",
            "provenance_claims_authenticated": False,
            "environment": "current_environment_not_checked",
            "prior_failure_policy": "revalidate_changed_or_uncertain_environment",
            "automatic_retry": False,
        })

    @staticmethod
    def cursor(ids, offset=0):
        return base64.urlsafe_b64encode(canonical_bytes({"ids": ids, "offset": offset})).decode().rstrip("=")

    @staticmethod
    def remember(suffix, text="Synthetic facade memory", **arguments):
        return {"op": "remember", "request_id": "req_synthetic_agent_" + suffix,
                "kind": "fact", "text": text, **arguments}

    def test_discover_without_configuration_or_constructor_side_effects(self):
        requests = ({"op": "discover"}, {"op": "discover", "online": False})
        expected = [self.agent.handle(request) for request in requests]
        self.assertEqual(self.ts(*requests, no_file_access=True), expected)
        self.assertEqual(list(self.directory.iterdir()), [])
        # Presence of a network pathname is a description, not permission to
        # read it, discover keys or create a local database.
        missing_network = self.directory / "absent-network.json"
        oracle = Agent(self.config, missing_network)
        self.assertEqual(self.ts(*requests, network_config=missing_network, no_file_access=True),
                         [oracle.handle(request) for request in requests])
        self.assertEqual(list(self.directory.iterdir()), [])
        atomic_write(self.config, b"not a configuration", replace=False)
        before = self.config.read_bytes()
        self.assertEqual(self.ts(*requests, no_file_access=True), expected)
        self.assertEqual(self.config.read_bytes(), before)
        self.assertFalse(self.database.exists())

    def test_unsigned_local_write_retry_and_cross_language_canonical_read(self):
        self.configure()
        command = self.remember("unsigned", "Synthetic unsigned Python ↔ TypeScript 中文😀")
        result, retry = self.ts(command, command, network_config=self.directory / "never-read-network.json")
        self.assertTrue(result["ok"], result)
        self.assertEqual(retry, result)
        self.assertEqual(self.agent.handle(command), result)
        memory_id = result["result"]["memory_id"]
        before = self.records()
        self.assertEqual(len(before), 1)
        self.assertEqual(before[memory_id][1], "local_unsigned")
        self.assertIsNone(before[memory_id][3])
        self.same({"op": "recall", "memory_id": memory_id}, {**command, "text": "conflicting retry"})
        self.assertEqual(self.records(), before)

    def test_signed_exact_retry_conflict_and_alternating_same_database(self):
        self.configure(signed=True)
        first = self.remember("signed_ts", "Synthetic signed TS origin", entities=["agent:test"])
        ts_first = self.value(first)
        self.assertEqual(self.agent.handle(first), ts_first)
        parent_id = ts_first["result"]["memory_id"]
        old = self.records()[parent_id]
        second = self.remember("signed_python", "Synthetic Python continuation",
                               relations=[{"type": "derived_from", "target": parent_id}])
        py_second = self.agent.handle(second)
        self.assertTrue(py_second["ok"], py_second)
        self.assertEqual(self.ts(second, first), [py_second, ts_first])
        self.same({**first, "text": "same request changed"},
                  {"op": "recall", "memory_id": py_second["result"]["memory_id"]})
        current = self.records()
        self.assertEqual(len(current), 2)
        self.assertEqual(current[parent_id], old)
        for raw, state, signer, proof in current.values():
            self.assertEqual(state, "verified")
            self.assertEqual(signer, self.identity.key_id)
            self.trust.verify_record(json.loads(raw), json.loads(proof))
        with contextlib.closing(ClientConfig.load(self.config).vault()._connect()) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM receipts").fetchone()[0], 2)
            self.assertEqual(db.execute("PRAGMA integrity_check").fetchone()[0], "ok")

    def test_revocation_blocks_writes_and_marks_id_or_cursor_evidence_ineligible(self):
        self.configure(signed=True)
        command = self.remember("revoked", "Synthetic revocable evidence " + "😀" * 400)
        written = self.value(command)
        memory_id = written["result"]["memory_id"]
        page = self.value({"op": "recall", "memory_id": memory_id})
        cursor = page["result"]["next_cursor"]
        self.assertIsNotNone(cursor)
        before = self.records()
        self.trust.revoke(self.identity.key_id)
        results = self.same(command, self.remember("after_revoke"),
                            {"op": "recall", "memory_id": memory_id},
                            {"op": "recall", "cursor": cursor},
                            {"op": "recall", "query": "revocable evidence"})
        self.assertFalse(results[0]["ok"])
        self.assertFalse(results[1]["ok"])
        self.assertEqual(results[0]["error"]["code"], "key_revoked")
        self.assertEqual(results[1]["error"]["code"], "key_revoked")
        # Explicit historical ID/cursor inspection remains readable in the
        # existing core. It must be marked ineligible, never silently admitted
        # to query/handoff context or treated as an execution permission.
        for result in results[2:4]:
            self.assertTrue(result["ok"], result)
            self.assertEqual(len(result["result"]["hits"]), 1)
            verification = result["result"]["hits"][0]["verification"]
            self.assertTrue(verification["current_trust_checked"])
            self.assertFalse(verification["eligible_for_context"])
            self.assertFalse(verification["grants_authority"])
        self.assertEqual(results[4]["result"]["hits"], [])
        self.assertEqual(self.records(), before)

    def test_one_agent_rechecks_trust_between_handles_after_external_revocation(self):
        self.configure(signed=True)
        command = self.remember("live_trust", "Synthetic live trust update evidence")
        written = self.agent.handle(command)
        self.assertTrue(written["ok"], written)
        read = {"op": "recall", "memory_id": written["result"]["memory_id"]}
        trusted_contents = self.trust_path.read_bytes()
        before = self.agent.handle(read)
        self.trust.revoke(self.identity.key_id)
        revoked_contents = self.trust_path.read_text()
        expected = [before, self.agent.handle(read), self.agent.handle(command)]
        # Restore only this synthetic trust file, then inject its already
        # produced revoked form between requests in the one native instance.
        atomic_write(self.trust_path, trusted_contents, replace=True)
        observed = self.ts(read, read, command, mutations=[
            {"before": 1, "path": str(self.trust_path), "contents": revoked_contents}])
        self.assertEqual(observed, expected)
        self.assertTrue(observed[0]["result"]["hits"][0]["verification"]["eligible_for_context"])
        self.assertFalse(observed[1]["result"]["hits"][0]["verification"]["eligible_for_context"])
        self.assertEqual(observed[2]["error"]["code"], "key_revoked")

    def test_utf8_id_pages_and_frozen_ids_cross_language(self):
        self.configure()
        text = "合成😀é" * 900
        command = self.remember("utf8", text)
        written = self.agent.handle(command)
        self.assertTrue(written["ok"], written)
        memory_id = written["result"]["memory_id"]
        request = {"op": "recall", "memory_id": memory_id}
        fragments = []
        for index in range(32):
            py_page = self.agent.handle(request)
            ts_page, = self.ts(request)
            self.assertEqual(ts_page, py_page)
            self.assertTrue(ts_page["ok"], ts_page)
            page = ts_page["result"]
            fragments.extend(hit["text"] for hit in page["hits"])
            self.assertTrue(all(len(hit["text"].encode()) <= 768 for hit in page["hits"]))
            if page["next_cursor"] is None:
                break
            # The actual next selector crosses runtime boundaries every time.
            request = {"op": "recall", "cursor": (ts_page if index % 2 == 0 else py_page)["result"]["next_cursor"]}
        else:
            self.fail("bounded UTF-8 fixture did not finish paging")
        self.assertEqual("".join(fragments), text)
        ids = []
        for index in range(6):
            result = self.agent.handle(self.remember("frozen_" + str(index), "Synthetic frozen item " + str(index)))
            self.assertTrue(result["ok"], result)
            ids.append(result["result"]["memory_id"])
        first, = self.same({"op": "recall", "cursor": self.cursor(ids)})
        self.assertEqual([hit["memory_id"] for hit in first["result"]["hits"]], ids[:4])
        added = self.value(self.remember("later", "Synthetic later matching frozen item"))
        final, = self.same({"op": "recall", "cursor": first["result"]["next_cursor"]})
        self.assertEqual([hit["memory_id"] for hit in final["result"]["hits"]], ids[4:])
        self.assertNotIn(added["result"]["memory_id"], ids)
        self.assertIsNone(final["result"]["next_cursor"])

    def test_invalid_stale_and_ambiguous_recall_selectors_match_python(self):
        self.configure()
        written = self.agent.handle(self.remember("cursor", "Synthetic cursor evidence"))
        memory_id = written["result"]["memory_id"]
        malformed = ["not base64!", self.cursor([memory_id], -1), self.cursor([memory_id], 99999),
                     self.cursor([memory_id] * 33), self.cursor(["not-a-memory-id"]),
                     self.cursor(["mem_" + "0" * 40]), self.cursor([memory_id], True)]
        requests = [{"op": "recall", "cursor": value} for value in malformed]
        requests += [{"op": "recall"}, {"op": "recall", "memory_id": memory_id, "query": "cursor"},
                     {"op": "recall", "cursor": self.cursor([memory_id]), "handoff": False},
                     {"op": "recall", "memory_id": "invalid"}]
        results = self.same(*requests)
        self.assertTrue(all(not item["ok"] for item in results))
        # An empty frozen selection is a valid exhausted page in Python.
        result, = self.same({"op": "recall", "cursor": self.cursor([])})
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["result"]["hits"], [])

    def test_query_ranking_and_structural_handoff_match_python_selection(self):
        self.configure(signed=True)
        episode = ClientConfig.load(self.config).vault(writing=True).handle({
            "op": "observe", "request_id": "req_synthetic_agent_episode",
            "user": "Synthetic continuing project", "assistant": "Synthetic prior evidence"})
        self.assertTrue(episode["ok"], episode)
        episode_id = episode["result"]["memory_id"]
        for kind, suffix in (("goal", "goal"), ("continuity", "continuity"), ("decision", "decision"), ("summary", "summary")):
            result = self.agent.handle(self.remember(suffix, "Synthetic structural " + kind,
                kind=kind, relations=[{"type": "derived_from", "target": episode_id}]))
            self.assertTrue(result["ok"], result)
        for index, (text, entities) in enumerate([
            ("Synthetic constellation ledger evidence repeated constellation ledger", []),
            ("Synthetic unrelated text with exact entity", ["project:constellation-ledger"]),
            ("Synthetic constellation observation", []),
            ("Synthetic unrelated gardening note", []),
        ]):
            result = self.agent.handle(self.remember("rank_" + str(index), text, entities=entities))
            self.assertTrue(result["ok"], result)
        before = self.records()
        requests = ({"op": "recall", "query": "constellation ledger"},
                    {"op": "recall", "query": "project:constellation-ledger"},
                    {"op": "recall", "query": "constellation ledger", "handoff": True},
                    {"op": "recall", "query": "zzzz-no-synthetic-match"})
        results = self.same(*requests)
        self.assertTrue(all(item["ok"] for item in results))
        self.assertEqual([hit["kind"] for hit in results[2]["result"]["hits"]],
                         ["goal", "continuity", "decision", "summary"])
        for item in results:
            if item["result"]["next_cursor"]:
                self.same({"op": "recall", "cursor": item["result"]["next_cursor"]})
        self.assertEqual(self.records(), before)

    def test_argument_errors_and_exact_64k_request_boundary(self):
        self.configure()
        command = self.remember("invalid")
        requests = [None, [], "synthetic", 1, {}, {"op": "missing"},
                    {"op": "discover", "online": 1}, {"op": "discover", "extra": True},
                    {"op": "receive", "limit": True}, {"op": "receive", "limit": 0},
                    {"op": "receive", "limit": 17}, {"op": "receive"}, {"op": "connect"},
                    {"op": "discover", "online": True},
                    {"op": "send", "request_id": "req_synthetic_agent_send", "recipients": []},
                    {**command, "text": " "}, {**command, "text": "synthetic\0text"},
                    {**command, "text": "😀" * 4097}, {**command, "kind": "episode"},
                    {**command, "request_id": "bad"}, {**command, "task_id": "not-authority"},
                    {**command, "entities": ["😀" * 129]}, {**command, "entities": ["a"] * 33},
                    {**command, "relations": [{}] * 33}, {"op": "recall", "query": "😀" * 4097}]
        base = {"op": "discover", "padding": ""}
        exact = {**base, "padding": "x" * (65536 - len(canonical_bytes(base)))}
        self.assertEqual(len(canonical_bytes(exact)), 65536)
        oversized = {**exact, "padding": exact["padding"] + "x"}
        requests += [exact, oversized]
        results = self.same(*requests)
        self.assertTrue(all(not item["ok"] for item in results))
        self.assertEqual(results[-2]["error"]["code"], "invalid_client_arguments")
        self.assertEqual(results[-1]["error"]["code"], "invalid_agent_request")
        self.assertFalse(self.database.exists())

    def test_8k_result_budget_pages_json_escape_expansion_without_record_loss(self):
        self.configure()
        ids = []
        for index in range(4):
            result = self.agent.handle(self.remember("escaped_" + str(index), "\x01" * 700 + str(index)))
            self.assertTrue(result["ok"], result)
            ids.append(result["result"]["memory_id"])
        before = self.records()
        request = {"op": "recall", "cursor": self.cursor(ids)}
        obtained, cursors = {}, set()
        for _ in range(16):
            response, = self.same(request)
            self.assertTrue(response["ok"], response)
            self.assert_evidence_usage(response["result"])
            for hit in response["result"]["hits"]:
                obtained[hit["memory_id"]] = obtained.get(hit["memory_id"], "") + hit["text"]
            cursor = response["result"]["next_cursor"]
            if cursor is None:
                break
            self.assertNotIn(cursor, cursors)
            cursors.add(cursor)
            request = {"op": "recall", "cursor": cursor}
        else:
            self.fail("escape-heavy evidence pagination did not progress")
        self.assertEqual(obtained, {memory_id: "\x01" * 700 + str(index) for index, memory_id in enumerate(ids)})
        self.assertEqual(self.records(), before)

    def test_inherited_failure_keeps_claimed_origin_time_and_original_proof(self):
        self.configure(signed=True)
        prior_identity = Identity.generate(self.directory / "prior-agent-identity.json")
        self.trust.add(prior_identity.public_descriptor(), "synthetic previous signer")
        provenance = {"agent_ref": "synthetic-previous-agent", "conversation_ref": "synthetic-previous-session",
                      "model_ref": "synthetic-model-not-an-agent-id", "source_ref": "synthetic-old-environment-check"}
        record = build_record(kind="observation", text=(
            "Synthetic previous attempt failed while the local fixture service was stopped. "
            "The old environment and cause are evidence of that attempt, not a permanent capability limit."),
            created_at="2026-01-01T00:00:00Z", provenance=provenance)
        self.ingest(record, prior_identity)
        before = self.records()
        response, = self.same({"op": "recall", "memory_id": record["memory_id"]})
        hit = response["result"]["hits"][0]
        self.assert_evidence_usage(response["result"])
        self.assertEqual(hit["recorded_at"], record["created_at"])
        self.assertEqual(hit["provenance_refs"], provenance)
        self.assertEqual(hit["provenance_status"], "claimed")
        self.assertFalse(hit["provenance_refs_truncated"])
        self.assertEqual(hit["verification"]["signer_key_id"], prior_identity.key_id)
        self.assertTrue(hit["verification"]["signature_verified_at_admission"])
        self.assertFalse(hit["verification"]["claimed_provenance_is_authenticated"])
        self.assertFalse(hit["verification"]["grants_authority"])
        self.assertNotIn("verified_at", hit)
        # Repeating an old failure read supplies the same policy, not a retry
        # of the old command, a new environment assertion, or a new record.
        self.assertEqual(self.ts({"op": "recall", "memory_id": record["memory_id"]}), [response])
        self.assertEqual(self.records(), before)
        raw, _, _, proof = before[record["memory_id"]]
        self.assertEqual(raw.encode(), canonical_bytes(record))
        self.trust.verify_record(json.loads(raw), json.loads(proof))

    def test_unknown_or_model_only_provenance_never_invents_an_agent_or_session(self):
        self.configure(signed=True)
        records = [build_record(kind="fact", text="Synthetic source not recorded", created_at="2026-01-02T00:00:00Z"),
                   build_record(kind="fact", text="Synthetic model claim only", created_at="2026-01-03T00:00:00Z",
                                provenance={"model_ref": "synthetic-shared-model-name"})]
        for record in records:
            self.ingest(record, self.identity)
        for index, record in enumerate(records):
            result, = self.same({"op": "recall", "memory_id": record["memory_id"]})
            hit = result["result"]["hits"][0]
            self.assert_evidence_usage(result["result"])
            self.assertEqual(hit["provenance_status"], "unknown" if index == 0 else "claimed")
            self.assertEqual(hit["provenance_refs"], record["provenance"])
            self.assertNotIn("agent_ref", hit["provenance_refs"])
            self.assertNotIn("conversation_ref", hit["provenance_refs"])
            # These are even signed by the currently configured local key;
            # the projection must not declare that another agent wrote them.
            self.assertEqual(hit["verification"]["signer_key_id"], self.identity.key_id)

    def test_long_source_claims_and_dense_cursor_stay_bounded_and_progress(self):
        self.configure(signed=True)
        refs = ("agent_ref", "conversation_ref", "source_ref", "model_ref",
                "device_ref", "request_ref", "project_ref", "task_ref")
        sources = []
        for index in range(8):
            record = build_record(kind="fact", text="Synthetic dependency " + str(index), created_at="2026-01-03T00:00:00Z")
            self.ingest(record, self.identity)
            sources.append({"type": "derived_from", "target": record["memory_id"]})
        ids, originals = [], {}
        for index in range(4):
            text = ("😀" * 190 + str(index)) if index % 2 else ("\x01" * 760 + str(index))
            provenance = {key: (("来源😀" * 180) if index % 2 else ("\x02" * 1000)) for key in refs}
            record = build_record(kind="observation", text=text, created_at="2026-01-04T00:00:00Z", provenance=provenance, relations=sources)
            self.ingest(record, self.identity)
            ids.append(record["memory_id"])
            originals[record["memory_id"]] = text
        before = self.records()
        # Repeating the fixed IDs is legal cursor input and makes the cursor
        # itself consume space, exercising first-fragment shortening as well.
        selected = ids * 8
        request = {"op": "recall", "cursor": self.cursor(selected)}
        fragments, completed, cursors = {}, [], set()
        shortened = False
        for _ in range(128):
            response, = self.same(request)
            self.assertTrue(response["ok"], response)
            self.assert_evidence_usage(response["result"])
            for hit in response["result"]["hits"]:
                self.assertTrue(hit["provenance_refs_truncated"])
                self.assertLessEqual(len(canonical_bytes(hit["provenance_refs"])), 256)
                self.assertTrue(all(len(value.encode()) <= 96 for value in hit["provenance_refs"].values()))
                memory_id = hit["memory_id"]
                shortened = shortened or hit["partial"]
                self.assertEqual(hit["text_offset_bytes"], len(fragments.get(memory_id, "").encode()))
                fragments[memory_id] = fragments.get(memory_id, "") + hit["text"]
                if not hit["partial"]:
                    self.assertEqual(fragments.pop(memory_id), originals[memory_id])
                    completed.append(memory_id)
            cursor = response["result"]["next_cursor"]
            if cursor is None:
                break
            self.assertNotIn(cursor, cursors)
            cursors.add(cursor)
            request = {"op": "recall", "cursor": cursor}
        else:
            self.fail("bounded source metadata pagination did not progress")
        self.assertEqual(completed, selected)
        self.assertTrue(shortened)
        self.assertEqual(fragments, {})
        self.assertEqual(self.records(), before)
        invalid, = self.same({"op": "recall", "cursor": self.cursor([ids[1]], 1)})
        self.assertEqual(invalid["error"]["code"], "invalid_recall_cursor")

    def test_receive_uses_same_evidence_policy_over_real_owned_http(self):
        from tests import test_network_node_runtime as runtime
        host = runtime.NetworkNodeRuntimeTests("test_independent_refresh_and_persistent_drain_fence_over_real_http")
        self.addCleanup(host.doCleanups)
        host.setUp()
        self.addCleanup(host.tearDown)
        host.join_receiver()
        sent = host.sender.send("req_synthetic_evidence_native_receive", [host.identities[1].key_id],
                                "Synthetic previous sender failure; changed conditions require a new check.")
        self.assertEqual(sent["stored_nodes"], 2)
        native, = self.ts({"op": "receive"}, client_config=host.configs[1],
                          network_config=host.net_configs[1], allow_network=True)
        self.assertTrue(native["ok"], native)
        self.assert_evidence_usage(native["result"])
        self.assertEqual(native["result"]["messages"][0]["sender_key_id"], host.identities[0].key_id)
        host.sender.send("req_synthetic_evidence_python_receive", [host.identities[1].key_id],
                         "Synthetic separate old attempt; this does not authorize an automatic retry.")
        python = Agent(host.configs[1], host.net_configs[1]).handle({"op": "receive"})
        self.assertTrue(python["ok"], python)
        self.assert_evidence_usage(python["result"])
        self.assertEqual(native["result"]["evidence_usage"], python["result"]["evidence_usage"])
        for message in native["result"]["messages"] + python["result"]["messages"]:
            self.assertNotIn("provenance_refs", message)
            self.assertNotIn("recorded_at", message)
            self.assertIn("text_memory_id", message)

    def test_read_only_signed_config_does_not_require_private_identity_file(self):
        self.configure(signed=True)
        command = self.remember("read_without_key")
        written = self.agent.handle(command)
        self.identity_path.unlink()
        read, = self.same({"op": "recall", "memory_id": written["result"]["memory_id"]})
        self.assertTrue(read["ok"], read)
        self.assertTrue(read["result"]["hits"][0]["verification"]["eligible_for_context"])
        self.assertFalse(self.identity_path.exists())

    def test_missing_database_recall_does_not_create_storage(self):
        self.configure()
        before = set(self.directory.iterdir())
        results = self.same({"op": "recall", "query": "synthetic absent database"},
                            {"op": "recall", "memory_id": "mem_" + "0" * 40})
        self.assertTrue(all(not result["ok"] for result in results))
        self.assertEqual(set(self.directory.iterdir()), before)
        self.assertFalse(self.database.exists())

    def test_missing_configured_signer_rejects_write_without_unsigned_downgrade(self):
        self.configure(signed=True)
        self.identity_path.unlink()
        result, = self.same(self.remember("missing_configured_key"))
        self.assertFalse(result["ok"])
        self.assertFalse(self.database.exists())


if __name__ == "__main__":
    unittest.main()
