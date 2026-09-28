"""HTTP-free native repair draft wire checks; no authority/custody acceptance.

Node imports the real TypeScript module. The harness denies subprocess and
fetch delegation and uses the existing native-runtime fixture without installs.
All bytes, identities and policies below are synthetic local test material.
"""
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import unittest

import memory_vault_open_repair_wire as repair
from tests import test_network_typescript_agent_network as ts_runtime


ROOT = Path(__file__).resolve().parents[1]
POLICY = dict(max_document_bytes=131072, max_total_bytes=1048576,
              max_nodes=100000, max_depth=20000, max_string_bytes=32768,
              max_hash_bytes=1048576, max_hashes=100, max_entries=10,
              max_retained_bytes=131072)

DRIVER = r"""
import child from 'node:child_process';
import crypto from 'node:crypto';
import {syncBuiltinESMExports} from 'node:module';
let subprocessCalls=0,networkCalls=0,signatureCalls=0;
const deny=()=>{subprocessCalls++;throw Error('native repair cannot delegate');};
for(const name of ['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork'])child[name]=deny;
for(const name of ['sign','verify'])crypto[name]=()=>{signatureCalls++;throw Error('draft wire has no signatures');};
syncBuiltinESMExports();
globalThis.fetch=()=>{networkCalls++;throw Error('local repair must not fetch');};
const wire=await import('./open-repair-wire.ts'),chunks=[];let inputSize=0;
for await(const chunk of process.stdin){inputSize+=chunk.length;if(inputSize>2097152)throw Error('synthetic fixture limit');chunks.push(chunk);}
const input=JSON.parse(Buffer.concat(chunks).toString('utf8')),results=[];
for(const call of input){
  let budget;
  try{
    let value,raw_base64;
    if(call.op==='u53')value=wire.u53(call.value,call.minimum??0);
    else if(call.op==='ref')value=wire.rawRef(call.value);
    else if(call.op==='schema')value=wire.objectFields(call.value,call.fields);
    else if(call.op==='host_objects'){
      const failures=[];let getterCalls=0;
      const attempt=f=>{try{f();failures.push('accepted');}catch(error){failures.push(error.code??'untyped_error');}};
      attempt(()=>wire.objectFields(Object.create({field:1}),['field']));
      attempt(()=>wire.objectFields(Object.defineProperty({},'field',{enumerable:true,get(){getterCalls++;return 1;}}),['field']));
      attempt(()=>wire.objectFields(new Proxy({field:1},{get(){getterCalls++;return 1;}}),['field']));
      attempt(()=>wire.objectFields(Object.assign({field:1},{[Symbol('synthetic')]:2}),['field']));
      const ref={namespace:'meta',key:'a'.repeat(64),raw_sha256:'b'.repeat(64),size:1};
      attempt(()=>wire.rawRef(Object.create(ref)));
      attempt(()=>wire.rawRef({...ref,unexpected:true}));
      value={failures,getterCalls};
    }else{
      budget=new wire.RepairBudget(call.budget_policy??call.policy);
      if(call.op==='budget_instance'){
        const writes=[];
        for(const key of ['node','hash','input','output','canRetain','retain','assertPolicy','snapshot','policy']){
          writes.push(Reflect.set(budget,key,()=>{}));
          writes.push(Reflect.defineProperty(budget,key,{value:()=>{}}));
        }
        writes.push(Reflect.setPrototypeOf(budget,{}));
        writes.push(Reflect.set(budget.policy,'max_nodes',1000));
        const operations=[];
        const attempt=(policy,operation)=>{
          const meter=new wire.RepairBudget(policy);
          try{operation(meter);operations.push({code:null,work:meter.snapshot()});}
          catch(error){operations.push({code:error.code??'untyped_error',work:meter.snapshot()});}
        };
        const tiny={...call.policy,max_nodes:1};
        attempt(tiny,meter=>wire.buildNewWire({a:[1,2,3]},tiny,meter));
        attempt(tiny,meter=>wire.parseNewWire(Buffer.from('{"a":[1,2,3]}'),tiny,meter));
        const capped={...call.policy,max_hashes:1};
        attempt(capped,meter=>{const resolver=new wire.LocalRawResolver(capped,meter);
          resolver.put('object','a'.repeat(64),Buffer.from('x'));resolver.put('object','b'.repeat(64),Buffer.from('x'));});
        attempt(capped,meter=>wire.parseRawPack(Buffer.from(call.pack_base64,'base64'),call.pack_ref,capped,meter));
        attempt(capped,meter=>wire.buildRawPack([Buffer.from('x')],capped,meter));
        const invalid=[];let proxyCalls=0;
        class OtherBudget extends wire.RepairBudget {node(){}}
        const fake=Object.assign(Object.create(wire.RepairBudget.prototype),{assertPolicy(){}});
        for(const meter of [new OtherBudget(tiny),new Proxy(budget,{get(){proxyCalls++;throw Error('proxy callback');}}),fake]){
          try{wire.buildNewWire({a:[1,2,3]},tiny,meter);invalid.push('accepted');}
          catch(error){invalid.push(error.code??'untyped_error');}
        }
        value={writes,operations,invalid,proxyCalls,frozen:Object.isFrozen(budget)};
      }else if(call.op==='build'||call.op==='build_deep'||call.op==='build_aliases'){
        if(call.prior_raw)wire.parseNewJson(Buffer.from(call.prior_raw,'base64'),call.policy,budget);
        let input=call.value;
        if(call.op==='build_deep'){input=0;for(let i=0;i<call.depth;i++)input=[input];}
        if(call.op==='build_aliases'){const shared={x:[1]};input=[shared,shared];}
        const draft=wire.buildNewWire(input,call.policy,budget);
        value=draft.value;
        if(call.op==='build_deep'){
          let depth=0,part=value;while(Array.isArray(part)){depth++;part=part[0];}
          value={depth,leaf:part};
        }
        if(call.op==='build_aliases'){
          input[0].x.push(2);
          value={snapshot:draft.value,independent:draft.value[0]!==draft.value[1]&&draft.value[0].x!==draft.value[1].x};
        }
        if(call.mutate){
          input.a.push(2);const copy=draft.raw;copy.fill(0);
          value={snapshot:draft.value,frozen:Object.isFrozen(draft.value)&&Object.isFrozen(draft.value.a),
            write_rejected:!Reflect.set(draft.value.a,'0',99)};
        }
        if(call.raw_result)raw_base64=Buffer.from(draft.raw).toString('base64');
      }else if(call.op==='build_host'){
        const failures=[];let getterCalls=0;
        const attempt=value=>{try{wire.buildNewWire(value,call.policy,budget);failures.push('accepted');}
          catch(error){failures.push(error.code??'untyped_error');}};
        const cycle=[];cycle.push(cycle);const objectCycle={};objectCycle.self=objectCycle;
        attempt(cycle);attempt(objectCycle);
        attempt(new Proxy({a:1},{get(){getterCalls++;throw Error('proxy callback');}}));
        attempt(Object.defineProperty({},'a',{enumerable:true,get(){getterCalls++;throw Error('accessor');}}));
        attempt(Object.defineProperty({},'a',{get(){getterCalls++;throw Error('hidden accessor');}}));
        attempt(Object.create({a:1}));attempt(new Date(0));attempt(new Uint8Array([1]));
        attempt(new Array(1));attempt(Object.defineProperty([],0,{enumerable:true,get(){getterCalls++;throw Error('array accessor');}}));
        attempt({[Symbol('key')]:1});attempt({toJSON(){getterCalls++;throw Error('toJSON');}});
        attempt(undefined);attempt(1n);attempt(NaN);attempt(Infinity);attempt(-0);
        value={failures,getterCalls};
      }else if(call.op==='parse'||call.op==='deep'){
        const raw=call.op==='deep'?Buffer.from('['.repeat(call.depth)+'0'+']'.repeat(call.depth)):
          Buffer.from(call.raw_base64,'base64');
        const parse=call.mode==='strict'?wire.parseNewJson:wire.parseNewWire;
        const draft=parse(raw,call.policy,budget);
        value=draft.value;
        if(call.op==='deep'){
          let depth=0,part=value;while(Array.isArray(part)){depth++;part=part[0];}
          value={depth,leaf:part};
        }
        if(call.raw_result)raw_base64=Buffer.from(draft.raw).toString('base64');
        if(call.mutate){
          raw.fill(0);const first=draft.raw;first.fill(0);
          raw_base64=Buffer.from(draft.raw).toString('base64');
          value={snapshot:value,frozen:Object.isFrozen(draft.value),
            proto_is_null:Object.getPrototypeOf(draft.value)===null,
            has_proto_key:Object.hasOwn(draft.value,'__proto__'),
            top_write_rejected:!Reflect.set(draft.value,'extra',true),
            child_write_rejected:!Reflect.set(draft.value.value,'0',999)};
        }
      }else if(call.op==='resolver'){
        const resolver=new wire.LocalRawResolver(call.policy,budget),refs={},steps=[];
        for(const operation of call.operations){
          try{
            let original;
            if(operation.action==='put'){
              const raw=Buffer.from(operation.raw_base64,'base64');
              original=resolver.put(operation.namespace,operation.key,raw);
              if(operation.mutate_input)raw.fill(0);
              if(operation.id)refs[operation.id]=original.ref;
            }else{
              const reference=operation.ref??{...refs[operation.id],...(operation.patch??{})};
              original=resolver.resolve(reference);
            }
            const step={ok:true,ref:original.ref};
            if(operation.raw_result)step.raw_base64=Buffer.from(original.raw).toString('base64');
            if(operation.mutate_result){const copied=original.raw;copied.fill(0);}
            steps.push({...step,work:budget.snapshot()});
          }catch(error){steps.push({ok:false,code:error.code??'untyped_error',work:budget.snapshot()});}
        }
        value=steps;
      }else throw Error('unknown synthetic operation');
    }
    results.push({ok:true,value,...(raw_base64===undefined?{}:{raw_base64}),...(budget?{work:budget.snapshot()}:{})});
  }catch(error){results.push({ok:false,code:error.code??'untyped_error',...(budget?{work:budget.snapshot()}:{})});}
}
process.stdout.write(JSON.stringify({results,subprocessCalls,networkCalls,signatureCalls}));
"""


def b64(raw):
    return base64.b64encode(raw).decode("ascii")


class OpenRepairTypeScriptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ts_runtime.TypeScriptAgentNetworkTests.setUpClass.__func__(cls)
        (cls.fixture / "driver.mjs").write_text(DRIVER)

    def ts(self, calls):
        run = subprocess.run([self.node, "--experimental-strip-types", str(self.fixture / "driver.mjs")],
            input=json.dumps(calls).encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=30, cwd=self.fixture)
        self.assertEqual(run.returncode, 0, run.stderr.decode(errors="replace")[-6000:])
        result = json.loads(run.stdout)
        self.assertEqual(result["subprocessCalls"], 0)
        self.assertEqual(result["networkCalls"], 0)
        self.assertEqual(result["signatureCalls"], 0)
        self.assertEqual(len(result["results"]), len(calls))
        return result["results"]

    @staticmethod
    def parse(raw, *, mode="canonical", **extra):
        return dict(op="parse", mode=mode, policy=POLICY, raw_base64=b64(raw), **extra)

    def test_shared_strict_and_canonical_vectors_match_native_and_python(self):
        fixture = json.loads((ROOT / "examples/protocol/open-repair-wire-v1.json").read_text())
        self.assertEqual(fixture["schema_version"], "memory-vault-open-repair-wire-fixtures/v1")
        self.assertIs(fixture["synthetic_only"], True)
        calls = [dict(op="parse", mode=case["mode"], policy=POLICY,
                      raw_base64=case["raw_base64"]) for case in fixture["cases"]]
        results = self.ts(calls)
        for case, result in zip(fixture["cases"], results):
            with self.subTest(case=case["id"]):
                actual = {key: result[key] for key in ("ok", "value" if result["ok"] else "code")}
                self.assertEqual(actual, case["expected"])
                policy = repair.RepairPolicy(**POLICY)
                budget = repair.RepairBudget(policy)
                try:
                    parser = repair.parse_new_json if case["mode"] == "strict" else repair.parse_new_wire
                    value = parser(base64.b64decode(case["raw_base64"]), policy, budget).value
                    python = dict(ok=True, value=value)
                except repair.RepairWireError as error:
                    python = dict(ok=False, code=error.code)
                self.assertEqual(actual, python)
                self.assertEqual(result["work"], budget.snapshot())
                self.assertEqual(result["work"]["signature_checks"], 0)

    def test_each_local_parser_limit_is_enforced_without_budget_reset(self):
        scenarios = [
            (b"{}", "strict", dict(max_document_bytes=1), "repair_over_budget"),
            (b"{}", "canonical", dict(max_total_bytes=3), "repair_over_budget"),
            (b'[0]', "strict", dict(max_depth=1), "repair_over_budget"),
            (b'{"k":0}', "strict", dict(max_nodes=2), "repair_over_budget"),
            (b'{"k":0}', "canonical", dict(max_nodes=5), "repair_over_budget"),
            ('"🧪"'.encode(), "strict", dict(max_string_bytes=3), "repair_over_budget"),
            (b'"abc' + b'd' * 4096 + b'"', "strict", dict(max_string_bytes=3), "repair_over_budget"),
            (b'{"long":0}', "strict", dict(max_string_bytes=3), "repair_over_budget"),
        ]
        calls = [dict(op="parse", mode=mode, raw_base64=b64(raw), policy={**POLICY, **changes})
                 for raw, mode, changes, _ in scenarios]
        for scenario, result in zip(scenarios, self.ts(calls)):
            with self.subTest(raw=scenario[0][:40], limits=scenario[2]):
                self.assertEqual((result["ok"], result["code"]), (False, scenario[3]))
                policy = repair.RepairPolicy(**{**POLICY, **scenario[2]})
                meter = repair.RepairBudget(policy)
                with self.assertRaises(repair.RepairWireError):
                    (repair.parse_new_json if scenario[1] == "strict" else repair.parse_new_wire)(scenario[0], policy, meter)
                self.assertEqual(result["work"], meter.snapshot())
        success = self.ts([dict(op="parse", mode="canonical", raw_base64=b64(b"{}"),
                               policy={**POLICY, "max_total_bytes": 4})])[0]
        self.assertTrue(success["ok"])
        self.assertEqual((success["work"]["input_bytes"], success["work"]["output_bytes"]), (2, 2))

    def test_budget_instance_shadowing_cannot_disable_parser_builder_hash_or_hold(self):
        raw = b"MVRP1\0" + (1).to_bytes(4, "big") + (1).to_bytes(8, "big") + hashlib.sha256(b"x").digest() + b"x"
        digest = hashlib.sha256(raw).hexdigest()
        ref = dict(namespace="meta", key=digest, raw_sha256=digest, size=len(raw))
        result = self.ts([dict(op="budget_instance", policy=POLICY, pack_base64=b64(raw), pack_ref=ref)])[0]
        self.assertTrue(result["ok"], result)
        value = result["value"]
        self.assertTrue(value["frozen"])
        self.assertEqual(value["writes"], [False] * 20)
        self.assertEqual(value["invalid"], ["repair_invalid_policy"] * 3)
        self.assertEqual(value["proxyCalls"], 0)
        self.assertEqual([item["code"] for item in value["operations"]], ["repair_over_budget"] * 5)
        self.assertEqual([item["work"]["nodes"] for item in value["operations"][:2]], [1, 1])
        self.assertEqual([item["work"]["hashes"] for item in value["operations"][2:]], [1, 1, 1])
        self.assertEqual([item["work"]["entries"] for item in value["operations"][2:]], [1, 0, 0])

    def test_very_deep_native_json_uses_the_explicit_policy_not_host_recursion(self):
        deep = self.ts([dict(op="deep", mode="canonical", depth=12000, policy=POLICY)])[0]
        self.assertTrue(deep["ok"], deep)
        self.assertEqual(deep["value"], {"depth": 12000, "leaf": 0})
        self.assertEqual(deep["work"]["max_depth"], 12001)
        self.assertEqual(deep["work"]["nodes"], 24002)
        self.assertEqual(deep["work"]["signature_checks"], 0)

    def test_build_new_wire_matches_python_canonical_bytes_and_real_work(self):
        values = [{"a": [1]}, {"\ue000": 1, "\U00010000": 2, "2": 2, "10": 10,
                   "__proto__": {"constructor": True}, "control": '"\\\b\f\n\r\t\0'},
                  None, True, False, 0, 9007199254740991, ["é", "🧪", "\x1f"]]
        calls = [dict(op="build", value=value, policy=POLICY, raw_result=True) for value in values]
        for value, native in zip(values, self.ts(calls)):
            with self.subTest(value=value):
                self.assertTrue(native["ok"], native)
                policy = repair.RepairPolicy(**POLICY)
                meter = repair.RepairBudget(policy)
                draft = repair.build_new_wire(value, policy, meter)
                self.assertEqual(native["value"], draft.value)
                self.assertEqual(native["raw_base64"], b64(draft.raw))
                self.assertEqual(draft.raw, json.dumps(value, ensure_ascii=False,
                                 sort_keys=True, separators=(",", ":")).encode())
                self.assertEqual(native["work"], {**meter.snapshot(), "output_bytes": 2 * len(draft.raw)})
                self.assertEqual(native["work"]["input_bytes"], 0)
                self.assertEqual(native["work"]["signature_checks"], 0)

    def test_build_new_wire_bad_values_and_limits_reject_before_output(self):
        cases = [("\ud800", {}, "repair_invalid_unicode"),
                 ({"\udfff": 0}, {}, "repair_invalid_unicode"),
                 (-1, {}, "repair_invalid_integer"), (0.5, {}, "repair_invalid_integer"),
                 (9007199254740992, {}, "repair_invalid_integer"),
                 ("éxx", {"max_string_bytes": 3}, "repair_over_budget"),
                 ("\0", {"max_document_bytes": 7}, "repair_over_budget"),
                 ({"a": [1]}, {"max_document_bytes": 8}, "repair_over_budget"),
                 ({"a": [1]}, {"max_total_bytes": 8}, "repair_over_budget"),
                 ({"a": [1]}, {"max_nodes": 3}, "repair_over_budget"),
                 ({"a": [1]}, {"max_depth": 2}, "repair_over_budget")]
        calls = [dict(op="build", value=value, policy={**POLICY, **changes}) for value, changes, _ in cases]
        for (value, changes, code), native in zip(cases, self.ts(calls)):
            with self.subTest(value=value, limits=changes):
                self.assertEqual((native["ok"], native["code"]), (False, code))
                policy = repair.RepairPolicy(**{**POLICY, **changes})
                meter = repair.RepairBudget(policy)
                with self.assertRaises(repair.RepairWireError) as caught:
                    repair.build_new_wire(value, policy, meter)
                self.assertEqual(caught.exception.code, code)
                self.assertEqual(native["work"], meter.snapshot())
                self.assertEqual(native["work"]["output_bytes"], 0)
        native = self.ts([dict(op="build_host", policy=POLICY)])[0]
        self.assertEqual(native["value"], dict(failures=["repair_invalid_json"] * 14 +
                         ["repair_invalid_integer"] * 3, getterCalls=0))
        self.assertEqual(native["work"]["output_bytes"], 0)
        narrow = {**POLICY, "max_total_bytes": 4}
        native = self.ts([dict(op="build", value=None, prior_raw=b64(b"0"), policy=narrow)])[0]
        self.assertEqual(native["code"], "repair_over_budget")
        self.assertEqual(native["work"]["input_bytes"], 1)
        self.assertEqual(native["work"]["output_bytes"], 0)

    def test_build_new_wire_aliases_deep_values_and_immutable_snapshot(self):
        calls = [dict(op="build_aliases", policy=POLICY, raw_result=True),
                 dict(op="build_deep", depth=12000, policy=POLICY),
                 dict(op="build", value={"a": [1]}, policy=POLICY, mutate=True, raw_result=True)]
        alias, deep, snapshot = self.ts(calls)
        self.assertTrue(alias["ok"], alias)
        self.assertEqual(alias["value"], dict(snapshot=[{"x": [1]}, {"x": [1]}], independent=True))
        self.assertEqual(alias["work"]["nodes"], 18)
        self.assertEqual(alias["raw_base64"], b64(b'[{"x":[1]},{"x":[1]}]'))
        self.assertTrue(deep["ok"], deep)
        self.assertEqual(deep["value"], dict(depth=12000, leaf=0))
        self.assertEqual(deep["work"]["nodes"], 24002)
        self.assertEqual(deep["work"]["output_bytes"], 24001)
        self.assertEqual(deep["work"]["max_depth"], 12001)
        self.assertEqual(snapshot["value"], dict(snapshot={"a": [1]}, frozen=True, write_rejected=True))
        self.assertEqual(snapshot["raw_base64"], b64(b'{"a":[1]}'))
        self.assertEqual(snapshot["work"]["output_bytes"], 27)

    def test_field_policy_and_reference_shapes_reject_host_object_shortcuts(self):
        ref = dict(namespace="meta", key="a" * 64, raw_sha256="b" * 64, size=1)
        invalid_refs = [{**ref, field: value} for field, value in [
            ("namespace", "anchor"), ("key", "a" * 64 + "\n"), ("key", "a" * 64 + "\r\n"),
            ("raw_sha256", "b" * 64 + "\n"), ("raw_sha256", "b" * 64 + "\r\n"),
            ("size", True), ("size", 0), ("size", 9007199254740992),
        ]]
        calls = [dict(op="host_objects"), dict(op="u53", value=True), dict(op="u53", value=0),
                 dict(op="schema", value={"unexpected": 1}, fields=["wanted"])]
        calls += [dict(op="ref", value=value) for value in invalid_refs]
        calls += [dict(op="parse", mode="strict", policy={**POLICY, "max_nodes": True}, raw_base64=b64(b"{}")),
                  dict(op="parse", mode="strict", policy={**POLICY, "max_nodes": POLICY["max_nodes"] + 1},
                       budget_policy=POLICY, raw_base64=b64(b"{}"))]
        results = self.ts(calls)
        self.assertEqual(results[0]["value"], {"getterCalls": 0,
            "failures": ["repair_unknown_fields"] * 4 + ["repair_invalid_ref"] * 2})
        self.assertEqual(results[1]["code"], "repair_invalid_integer")
        self.assertEqual(results[2]["value"], 0)
        self.assertEqual(results[3]["code"], "repair_unknown_fields")
        for result in results[4:4 + len(invalid_refs)]:
            self.assertEqual(result["code"], "repair_invalid_ref")
        for result in results[-2:]:
            self.assertEqual(result["code"], "repair_invalid_policy")

    def test_raw_originals_are_immutable_snapshots_and_int64_stays_exact(self):
        raw = b' {"legacy_int64":9223372036854775807,"negative":-9223372036854775808}\n'
        key = "c" * 64
        calls = [dict(op="resolver", policy=POLICY, operations=[
            dict(action="put", id="legacy", namespace="object", key=key, raw_base64=b64(raw),
                 mutate_input=True, mutate_result=True),
            dict(action="resolve", id="legacy", raw_result=True),
            dict(action="put", namespace="object", key=key, raw_base64=b64(raw)),
            dict(action="put", namespace="object", key=key, raw_base64=b64(raw + b" ")),
            dict(action="resolve", id="legacy", patch={"namespace": "meta"}),
            dict(action="resolve", id="legacy", patch={"size": len(raw) + 1}),
            dict(action="resolve", id="legacy", patch={"raw_sha256": "0" * 64}),
            dict(action="resolve", id="legacy", raw_result=True),
        ])]
        steps = self.ts(calls)[0]["value"]
        self.assertEqual(steps[1]["raw_base64"], b64(raw))
        self.assertEqual(steps[7]["raw_base64"], b64(raw))
        self.assertEqual(steps[0]["ref"], dict(namespace="object", key=key,
                                             raw_sha256=hashlib.sha256(raw).hexdigest(), size=len(raw)))
        self.assertNotEqual(key, steps[0]["ref"]["raw_sha256"])
        self.assertEqual([step.get("code") for step in steps[3:7]],
                         ["repair_ref_conflict", "repair_ref_missing", "repair_ref_mismatch", "repair_ref_mismatch"])
        self.assertEqual(steps[7]["work"]["entries"], 1)
        self.assertEqual(steps[7]["work"]["retained_bytes"], len(raw))
        self.assertEqual(steps[7]["work"]["hashes"], 6)
        self.assertEqual(steps[7]["work"]["signature_checks"], 0)
        draft_raw = b'{"__proto__":{"synthetic":true},"value":[1]}'
        draft = self.ts([self.parse(draft_raw, mutate=True)])[0]
        self.assertEqual(draft["raw_base64"], b64(draft_raw))
        self.assertTrue(draft["value"]["frozen"])
        self.assertTrue(draft["value"]["proto_is_null"])
        self.assertTrue(draft["value"]["has_proto_key"])
        self.assertTrue(draft["value"]["top_write_rejected"])
        self.assertTrue(draft["value"]["child_write_rejected"])
        # The native getter allocates a defensive copy, unlike immutable Python
        # bytes. It must refuse before allocating when its output budget is full.
        copied = self.ts([dict(op="parse", mode="strict", raw_base64=b64(b"{}"), raw_result=True,
                              policy={**POLICY, "max_total_bytes": 3})])[0]
        self.assertEqual(copied["code"], "repair_over_budget")
        self.assertEqual((copied["work"]["input_bytes"], copied["work"]["output_bytes"]), (2, 0))

    def test_resolver_preflights_capacity_and_charges_only_real_hashes(self):
        def put(key, raw=b"x"):
            return dict(action="put", namespace="meta", key=key * 64, raw_base64=b64(raw))
        cases = [
            ({**POLICY, "max_entries": 1}, [put("a"), put("b"), put("a")]),
            ({**POLICY, "max_retained_bytes": 1}, [put("a"), put("b")]),
            ({**POLICY, "max_hashes": 1}, [put("a"), put("a")]),
            ({**POLICY, "max_hash_bytes": 1}, [put("a"), put("a")]),
        ]
        results = self.ts([dict(op="resolver", policy=policy, operations=ops) for policy, ops in cases])
        for index, result in enumerate(results):
            with self.subTest(case=index):
                self.assertTrue(result["ok"])
                steps = result["value"]
                self.assertEqual(steps[1]["code"], "repair_over_budget")
                self.assertEqual(steps[1]["work"]["hashes"], 1)
                self.assertEqual(steps[1]["work"]["entries"], 1)
                self.assertEqual(steps[1]["work"]["signature_checks"], 0)
                if index < 2:
                    self.assertEqual(steps[1]["work"]["input_bytes"], 1)
                else:
                    self.assertEqual(steps[1]["work"]["input_bytes"], 2)
        self.assertTrue(results[0]["value"][2]["ok"])
        self.assertEqual(results[0]["value"][2]["work"]["hashes"], 2)


if __name__ == "__main__":
    unittest.main()
