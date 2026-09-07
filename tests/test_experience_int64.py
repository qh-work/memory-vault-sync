"""Exact int64 experience views; synthetic records and unchanged core crypto."""
import json
import shutil
import unittest
from unittest.mock import patch

import memory_vault as core
from memory_vault import canonical_bytes
from memory_vault_experience import encode, decode, normalize
from tests import test_network_typescript_retrieval as retrieval_fixture
from tests import test_network_typescript_agent as agent_fixture


class ExperienceInt64Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        retrieval_fixture.TypeScriptRetrievalTests.setUpClass.__func__(cls)
        driver = retrieval_fixture.DRIVER.replace(
            "import { canonicalRecordBytes, validateRecord }",
            "import { decodeExperience, encodeExperience, normalizeExperience, parseExperienceJSON, canonicalExperienceBytes, canonicalRecordBytes, validateRecord }")
        driver = "import { CanonicalVault } from './vault.ts';\n" + driver
        driver = driver.replace("if(value.test_status)",
            """if(value.test_decode) result.push({ok:true,result:decodeExperience(validateRecord(value.test_decode))});
      else if(value.test_codec) {
        const metadata = parseExperienceJSON(value.test_codec);
        result.push({ok:true,result:{normalized:normalizeExperience(metadata),
          encoded:encodeExperience(metadata, {source_ref:'synthetic:fixture'}, []),
          canonical:Buffer.from(canonicalExperienceBytes(metadata)).toString('utf8'),
          raw_integer:JSON.isRawJSON(metadata.observed_under?.build_id),
          wire:JSON.stringify(metadata)}});
      }
      else if(value.test_parse !== undefined) result.push({ok:true,result:parseExperienceJSON(value.test_parse)});
      else if(value.test_native) {
        const number = value.test_native === 'unsafe' ? Number('9223372036854775807') :
          value.test_native === 'NaN' ? NaN : value.test_native === 'Infinity' ? Infinity : BigInt(value.test_native);
        result.push({ok:true,result:parseExperienceJSON(canonicalExperienceBytes({observed_under:{build_id:number}}))});
      }
      else if(value.test_network) result.push({ok:true,result:document(Buffer.from(value.test_network))});
      else if(value.test_get) {
        const vault=new CanonicalVault({vaultPath:input.vault,trust:input.trusted,readOnly:true});
        try { result.push({ok:true,result:vault.inspect(value.test_get,true)}); } finally { vault.close(); }
      }
      else if(value.test_status)""")
        (cls.fixture / "driver.mjs").write_text(driver)
        shutil.copyfile(retrieval_fixture.ROOT / "clients/typescript/network/vault.ts", cls.fixture / "vault.ts")
        shutil.copyfile(retrieval_fixture.ROOT / "clients/typescript/network/privacy.ts", cls.fixture / "privacy.ts")

    setUp = retrieval_fixture.TypeScriptRetrievalTests.setUp
    seed = retrieval_fixture.TypeScriptRetrievalTests.seed
    run_ts = retrieval_fixture.TypeScriptRetrievalTests.run_ts
    canonical_snapshot = retrieval_fixture.TypeScriptRetrievalTests.canonical_snapshot
    differential = retrieval_fixture.TypeScriptRetrievalTests.differential
    assert_equivalent = retrieval_fixture.TypeScriptRetrievalTests.assert_equivalent

    def experience_seed(self, text, metadata, **kwargs):
        provenance, relations = encode(metadata, {}, [])
        return self.seed(text, provenance=provenance, relations=relations, **kwargs)

    def test_python_accepted_int64_retains_experiment_and_confirmation(self):
        root = self.seed("Synthetic observed failure under V1")
        metadata = {"epistemic_type": "experiment", "observed_under": {"build_id": 9223372036854775807},
                    "relations": [{"type": "independently_confirms", "target": root["memory_id"]}]}
        provenance, relations = encode(metadata, {}, [])
        record = self.seed("Synthetic independently confirmed failure under V1", provenance=provenance, relations=relations)
        before = self.canonical_snapshot()
        result, = self.run_ts([{"test_decode": record}])
        self.assertEqual(result, {"ok": True, "result": decode(record)})
        self.assertEqual(self.canonical_snapshot(), before)

    def test_safe_boundary_int64_extrema_and_unknown_fields_encode_without_rounding(self):
        values = [-(2**63), -(2**53), -(2**53 - 1), 0, 2**53 - 1, 2**53, 2**63 - 1]
        for integer in values:
            with self.subTest(integer=integer):
                metadata = {"epistemic_type": "experiment", "observed_under": {"build_id": integer},
                            "future_unknown": {"array": [integer, "Unicode 日本語 😀"], "negative": -1}}
                wire = canonical_bytes(metadata).decode()
                result, = self.run_ts([{"test_codec": wire}])
                self.assertTrue(result["ok"], result)
                output = result["result"]
                provenance, relations = encode(metadata, {"source_ref": "synthetic:fixture"}, [])
                self.assertEqual(output["normalized"], normalize(metadata))
                self.assertEqual(output["encoded"], {"provenance": provenance, "relations": relations})
                self.assertEqual(output["canonical"], wire)
                self.assertEqual(json.loads(output["wire"]), metadata)
                self.assertEqual(output["raw_integer"], abs(integer) > 2**53 - 1)

    def test_invalid_number_and_duplicate_json_are_rejected_without_relaxing_network(self):
        invalid = ['{"n":9223372036854775808}', '{"n":-9223372036854775809}',
                   '{"n":123456789012345678901}', '{"n":-123456789012345678901}',
                   '{"n":1.0}', '{"n":1e0}', '{"n":NaN}', '{"n":Infinity}',
                   '{"n":1,"n":2}', '{"n":1,"\\u006e":2}', '{"n":01}',
                   '{"n":1e}', '{"n":-}', '{"n":1,}', '{"x":"\\ud800"}',
                   '{"x":"\\u0000"}', '{"n":1} trailing']
        actual = self.run_ts([{"test_parse": text} for text in invalid])
        self.assertTrue(all(not result["ok"] for result in actual), actual)
        native = self.run_ts([{"test_native": text} for text in
                             ("unsafe", "NaN", "Infinity", "9223372036854775808", "-9223372036854775809")])
        self.assertTrue(all(not result["ok"] for result in native), native)
        exact, network = self.run_ts([{"test_native": "9223372036854775807"},
                                     {"test_network": '{"n":9223372036854775807}'}])
        self.assertEqual(exact, {"ok": True, "result": {"observed_under": {"build_id": 2**63 - 1}}})
        self.assertEqual(network, {"ok": False, "error": "network_invalid_integer"})

    def test_get_recall_handoff_profiles_preserve_int64_context_and_evidence_counts(self):
        a = self.experience_seed("Synthetic method X observed failure", {
            "epistemic_type": "observation", "observed_under": {"build_id": 2**63 - 1}})
        b = self.experience_seed("Synthetic method X independent confirmation", {
            "epistemic_type": "experiment", "observed_under": {"build_id": 2**63 - 1},
            "relations": [{"type": "independently_confirms", "target": a["memory_id"]}]}, signer=self.second)
        c = self.experience_seed("Synthetic method X contradiction with changed environment", {
            "epistemic_type": "experiment", "observed_under": {"build_id": -(2**63)},
            "relations": [{"type": "contradicts", "target": a["memory_id"]}]})
        d = self.experience_seed("Synthetic method X retelling", {
            "epistemic_type": "hearsay", "observed_under": {"build_id": 2**53},
            "source_memory_refs": [a["memory_id"]]})
        before = self.canonical_snapshot()
        for record in (a, b, c, d):
            actual, = self.run_ts([{"test_get": record["memory_id"]}])
            expected = self.vault.handle({"op": "get", "memory_id": record["memory_id"], "include_experience": True})
            self.assertEqual(actual, {"ok": True, "result": expected["result"]})
        for profile in ("bounded-fragment-bm25+deterministic-concepts/v1", "bounded-fragment-bm25+deterministic-concepts/v2"):
            for handoff in (False, True):
                for limit in (1, 4):
                    result = self.differential({"query": "Synthetic method X", "limit": limit,
                        "handoff": handoff, "ranking_profile": profile, "include_experience": True})[0]
                    self.assertEqual(len(result["hits"]), limit)
                    for hit in result["hits"]:
                        summary = hit["experience"]["provenance_summary"]
                        self.assertEqual(summary["independent_confirmation_count"], 1)
                        self.assertEqual(summary["contradiction_count"], 1)
                        self.assertEqual(summary["propagation_count"], 1)
                        self.assertNotIn("metadata_status", hit["experience"])
                    self.assertIn('"build_id":', result["evidence_context"]["text"])
        self.assertEqual(self.canonical_snapshot(), before)


class ExperienceInt64AgentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        agent_fixture.TypeScriptAgentTests.setUpClass.__func__(cls)
        # Fixture carrier contains JSON as a string so the ordinary driver JSON
        # parser cannot round the numeric token before the tested codec sees it.
        driver = agent_fixture.DRIVER.replace("const {Agent}=await import('./agent.ts');",
            "const {Agent}=await import('./agent.ts');\nconst {parseExperienceJSON}=await import('./records.ts');\nDate.now=()=>1788220800000;")
        driver = driver.replace("results.push(await agent.handle(input.requests[index]));", """const request=input.requests[index];
  if(request.fixture_experience_json !== undefined) {
    request.experience=parseExperienceJSON(request.fixture_experience_json);
    delete request.fixture_experience_json;
  }
  results.push(await agent.handle(request));""")
        (cls.runtime / "driver.mjs").write_text(driver)

    setUp = agent_fixture.TypeScriptAgentTests.setUp
    configure = agent_fixture.TypeScriptAgentTests.configure
    ts = agent_fixture.TypeScriptAgentTests.ts
    value = agent_fixture.TypeScriptAgentTests.value
    same = agent_fixture.TypeScriptAgentTests.same
    records = agent_fixture.TypeScriptAgentTests.records
    remember = staticmethod(agent_fixture.TypeScriptAgentTests.remember)

    def test_native_int64_remember_exact_python_retry_and_readback(self):
        self.configure(signed=True)
        metadata = {"epistemic_type": "experiment", "observed_under": {"build_id": 2**63 - 1},
                    "future_unknown": [-(2**63), 2**53]}
        request = self.remember("int64_native", "Synthetic method X experiment", experience=metadata)
        native = {**request, "fixture_experience_json": canonical_bytes(metadata).decode()}
        del native["experience"]
        written = self.value(native)
        self.assertEqual(self.agent.handle(request), written)
        before = self.records()
        page, = self.same({"op": "recall", "memory_id": written["result"]["memory_id"], "include_experience": True})
        self.assertEqual(page["result"]["hits"][0]["experience"]["observed_under"], metadata["observed_under"])
        self.assertEqual(page["result"]["hits"][0]["experience"]["future_unknown"], metadata["future_unknown"])
        self.assertEqual(self.records(), before)
        # An already-rounded JS Number has no recoverable original token.
        # Reject it explicitly, never pretend it is an exact int64 input.
        rejected, = self.ts({**request, "request_id": "req_synthetic_agent_int64_rounded"})
        self.assertFalse(rejected["ok"], rejected)
        self.assertEqual(rejected["error"]["code"], "unsafe_experience_integer")
        self.assertEqual(self.records(), before)

    def test_python_int64_signed_record_agent_query_handoff_and_cursor_exact(self):
        self.configure(signed=True)
        text = "Synthetic method X failure under V1 日本語 😀 " * 90
        metadata = {"epistemic_type": "observation", "observed_under": {"build_id": -(2**63)},
                    "retry_predicate": {"newer_build_than": 2**63 - 1}, "future_unknown": [2**53]}
        written = self.agent.handle(self.remember("int64_python", text, experience=metadata))
        self.assertTrue(written["ok"], written)
        before = self.records()
        selectors = [{"memory_id": written["result"]["memory_id"]}]
        for profile in ("bounded-fragment-bm25+deterministic-concepts/v1", "bounded-fragment-bm25+deterministic-concepts/v2"):
            for handoff in (False, True):
                selectors.append({"query": "Synthetic method X", "handoff": handoff, "ranking_profile": profile})
        for selector in selectors:
            request = {"op": "recall", **selector, "include_experience": True}
            fragments = []
            for _ in range(30):
                with patch.object(core.dt, "datetime", retrieval_fixture.FrozenDateTime):
                    page, = self.same(request)
                self.assertTrue(page["ok"], page)
                for hit in page["result"]["hits"]:
                    fragments.append(hit["text"])
                    self.assertEqual(hit["experience"]["content"], hit["text"])
                    self.assertEqual(hit["experience"]["observed_under"], metadata["observed_under"])
                    self.assertEqual(hit["experience"]["retry_predicate"], metadata["retry_predicate"])
                    self.assertEqual(hit["experience"]["future_unknown"], metadata["future_unknown"])
                cursor = page["result"]["next_cursor"]
                if cursor is None:
                    break
                request = {"op": "recall", "cursor": cursor}
            else:
                self.fail("bounded int64 Experience pagination did not finish")
            self.assertEqual("".join(fragments), text)
        self.assertEqual(self.records(), before)
