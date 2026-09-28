"""Real native MVRP1 byte integrity checks, entirely synthetic and HTTP-free.

The existing runtime fixture supplies Node without installing dependencies.
No pack in this suite represents verified authority or historical closure.
"""
import base64
import hashlib
import json
import subprocess
import unittest

import memory_vault_open_repair_wire as repair
from tests import test_network_typescript_agent_network as ts_runtime


POLICY = dict(max_document_bytes=131072, max_total_bytes=1048576,
              max_nodes=1000, max_depth=8, max_string_bytes=32768,
              max_hash_bytes=1048576, max_hashes=100, max_entries=32,
              max_retained_bytes=262144)
MAGIC = b"MVRP1\0"

DRIVER = r"""
import child from 'node:child_process';
import crypto from 'node:crypto';
import {syncBuiltinESMExports} from 'node:module';
let subprocessCalls=0,signatureCalls=0,networkCalls=0;
const deny=()=>{subprocessCalls++;throw Error('native pack cannot delegate');};
for(const name of ['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork'])child[name]=deny;
for(const name of ['sign','verify'])crypto[name]=()=>{signatureCalls++;throw Error('local pack has no signatures');};
syncBuiltinESMExports();
globalThis.fetch=()=>{networkCalls++;throw Error('local pack cannot fetch');};
const wire=await import('./open-repair-wire.ts'),chunks=[];let inputSize=0;
for await(const chunk of process.stdin){inputSize+=chunk.length;if(inputSize>2097152)throw Error('synthetic fixture limit');chunks.push(chunk);}
const calls=JSON.parse(Buffer.concat(chunks).toString('utf8')),results=[];
for(const call of calls){
  const policy=call.policy??null;let budget;
  try{
    budget=new wire.RepairBudget(call.budget_policy??policy);
    let value;
    if(call.op==='host_arrays'){
      const failures=[];let getterCalls=0;
      const attempt=raws=>{try{wire.buildRawPack(raws,policy,budget);failures.push('accepted');}
        catch(error){failures.push(error.code??'untyped_error');}};
      attempt(new Proxy([Buffer.from('a')],{get(){getterCalls++;throw Error('proxy');}}));
      attempt(Object.defineProperty([],0,{get(){getterCalls++;throw Error('getter');}}));
      attempt(new Array(1));
      attempt(Object.assign(Object.create({0:Buffer.from('a')}),{length:1}));
      attempt({0:Buffer.from('a'),length:1});
      attempt(new Array(0xffffffff));
      value={failures,getterCalls};
    }else{
      const inputs=(call.raws??[]).map(raw=>Buffer.from(raw,'base64'));
      const source=Buffer.from(call.raw_base64??'','base64');
      const make=()=>call.op==='build'?wire.buildRawPack(inputs,policy,budget):
        wire.parseRawPack(source,call.ref,policy,budget);
      const pack=make();
      value={ref:pack.ref,entries:pack.entries};
      if(call.mutate){
        for(const raw of inputs)raw.fill(0);source.fill(0);
        const copied=pack.raw;copied.fill(0);
        value.frozen=Object.isFrozen(pack)&&Object.isFrozen(pack.ref)&&Object.isFrozen(pack.entries)&&
          pack.entries.every(Object.isFrozen);
        value.write_rejected=!Reflect.set(pack.entries[0],'offset',0)&&!Reflect.set(pack.entries,0,null);
      }
      if(call.raw_result)value.raw_base64=Buffer.from(pack.raw).toString('base64');
      if(call.extract){
        value.extracted=[];
        for(const step of call.extract){
          try{
            const reference=step.ref??{namespace:step.namespace??'object',key:'a'.repeat(64),
              raw_sha256:pack.entries[0].raw_sha256,size:pack.entries[0].size};
            const original=pack.entry(step.index,reference);
            if(step.mutate){const copy=original.raw;copy.fill(0);reference.key='b'.repeat(64);}
            value.extracted.push({ok:true,ref:original.ref,raw_base64:Buffer.from(original.raw).toString('base64')});
          }catch(error){value.extracted.push({ok:false,code:error.code??'untyped_error'});}
        }
      }
      if(call.again){
        try{make();value.again={ok:true};}catch(error){value.again={ok:false,code:error.code??'untyped_error'};}
      }
      if(call.raw_until_exhausted){
        value.copies=[];
        for(let i=0;i<2;i++){
          try{value.copies.push({ok:true,size:pack.raw.length});}
          catch(error){value.copies.push({ok:false,code:error.code??'untyped_error'});}
        }
      }
    }
    results.push({ok:true,value,work:budget.snapshot()});
  }catch(error){results.push({ok:false,code:error.code??'untyped_error',...(budget?{work:budget.snapshot()}:{})});}
}
process.stdout.write(JSON.stringify({results,subprocessCalls,signatureCalls,networkCalls}));
"""


def b64(raw):
    return base64.b64encode(raw).decode("ascii")


def ref(raw, **patch):
    digest = hashlib.sha256(raw).hexdigest()
    return dict(namespace="meta", key=digest, raw_sha256=digest, size=len(raw), **patch)


def frame(raws):
    return MAGIC + len(raws).to_bytes(4, "big") + b"".join(
        len(raw).to_bytes(8, "big") + hashlib.sha256(raw).digest() + raw for raw in raws)


class OpenRepairPackTypeScriptTests(unittest.TestCase):
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
        for key in ("subprocessCalls", "signatureCalls", "networkCalls"):
            self.assertEqual(result[key], 0, key)
        self.assertEqual(len(result["results"]), len(calls))
        return result["results"]

    @staticmethod
    def build(raws, **extra):
        return dict(op="build", raws=[b64(raw) for raw in raws], policy=POLICY, **extra)

    @staticmethod
    def parse(raw, **extra):
        return dict(op="parse", raw_base64=b64(raw), ref=ref(raw), policy=POLICY, **extra)

    @staticmethod
    def py(call):
        policy = repair.RepairPolicy(**call["policy"])
        budget = repair.RepairBudget(policy)
        try:
            if call["op"] == "build":
                pack = repair.build_raw_pack([base64.b64decode(raw) for raw in call["raws"]], policy, budget)
            else:
                pack = repair.parse_raw_pack(base64.b64decode(call["raw_base64"]), call["ref"], policy, budget)
            value = dict(ref=pack.ref.as_dict(), entries=[dict(raw_sha256=entry.raw_sha256,
                         size=entry.size, offset=entry.offset) for entry in pack.entries])
            if call.get("raw_result"):
                value["raw_base64"] = b64(pack.raw)
            return dict(ok=True, value=value, work=budget.snapshot())
        except repair.RepairWireError as error:
            return dict(ok=False, code=error.code, work=budget.snapshot())

    def test_native_build_and_parse_match_python_exact_legacy_bytes(self):
        raws = [b'{"old":9223372036854775807}', b'{"old":-9223372036854775808}',
                b'\xff\x00\x80opaque', b'{ "whitespace":true }\n']
        built = self.build([*reversed(raws), raws[0]], raw_result=True)
        result = self.ts([built])[0]
        self.assertTrue(result["ok"], result)
        python = self.py(built)
        self.assertEqual(result["value"], python["value"])
        packed = base64.b64decode(result["value"]["raw_base64"])
        self.assertEqual(packed, frame(sorted(raws, key=lambda raw: (hashlib.sha256(raw).digest(), len(raw)))))
        self.assertEqual(len(result["value"]["entries"]), len(raws))
        # TS private buffer plus requested public copy; Python mutable buffer
        # plus frozen bytes. Both are real, equally sized copies in this call.
        self.assertEqual(result["work"], python["work"])
        parsed = self.parse(packed, raw_result=True)
        native = self.ts([parsed])[0]
        python = self.py(parsed)
        self.assertEqual(native["value"], python["value"])
        self.assertEqual(native["work"], {**python["work"], "output_bytes": len(packed)})
        self.assertEqual(native["work"]["hashes"], len(raws) + 1)

    def test_parser_rejects_frame_order_duplicates_nested_and_actual_hash_corruption(self):
        bodies = sorted([b"a", b"b"], key=lambda raw: hashlib.sha256(raw).digest())
        valid = frame(bodies)
        bad_size = MAGIC + (1).to_bytes(4, "big") + (2**53).to_bytes(8, "big") + bytes(32) + b"x"
        zero_size = MAGIC + (1).to_bytes(4, "big") + bytes(40) + b"x"
        corrupted_body = bytearray(valid)
        corrupted_body[50] ^= 1
        cases = [(b"X" + valid[1:], "repair_invalid_pack"),
                 (MAGIC + bytes(4), "repair_invalid_pack"),
                 (valid[:9], "repair_invalid_pack"),
                 (valid[:-1], "repair_invalid_pack"),
                 (valid + b"\0", "repair_invalid_pack"),
                 (frame(list(reversed(bodies))), "repair_invalid_pack"),
                 (frame([bodies[0], bodies[0]]), "repair_invalid_pack"),
                 (frame([valid]), "repair_invalid_pack"),
                 (bad_size, "repair_invalid_pack"), (zero_size, "repair_invalid_pack"),
                 (bytes(corrupted_body), "repair_ref_mismatch")]
        calls = [self.parse(raw) for raw, _ in cases]
        for call, result, (_, code) in zip(calls, self.ts(calls), cases):
            with self.subTest(raw=call["raw_base64"][:40], code=code):
                self.assertEqual((result["ok"], result["code"]), (False, code))
                python = self.py(call)
                self.assertEqual(result, python)
                self.assertEqual(result["work"]["entries"], 0)
                self.assertEqual(result["work"]["retained_bytes"], 0)

    def test_pack_ref_and_entry_ref_remain_independent_and_strict(self):
        packed = frame([b"synthetic"])
        patches = [dict(namespace="object"), dict(key="a" * 64), dict(size=len(packed) + 1),
                   dict(key="b" * 64, raw_sha256="b" * 64), dict(unexpected=1),
                   dict(key="a" * 64 + "\n")]
        calls = [{**self.parse(packed), "ref": {**ref(packed), **patch}} for patch in patches]
        for index, (call, result) in enumerate(zip(calls, self.ts(calls))):
            self.assertEqual(result["code"], "repair_invalid_ref" if index >= 4 else "repair_ref_mismatch")
            self.assertEqual(result, self.py(call))
        document = dict(namespace="object", key="c" * 64,
                        raw_sha256=hashlib.sha256(b"synthetic").hexdigest(), size=9)
        attempts = [dict(index=0, ref=document), dict(index=0, ref={**document, "namespace": "meta"}),
                    dict(index=0, ref={**document, "size": 8}),
                    dict(index=0, ref={**document, "raw_sha256": "d" * 64}),
                    dict(index=0, ref={**document, "unexpected": 1}),
                    *[dict(index=value, ref=document) for value in (-1, -0.0, True, 0.5, 2**53, 1)]]
        result = self.ts([self.parse(packed, extract=attempts)])[0]
        self.assertTrue(result["ok"], result)
        policy = repair.RepairPolicy(**POLICY)
        budget = repair.RepairBudget(policy)
        python = repair.parse_raw_pack(packed, ref(packed), policy, budget)
        for attempt, actual in zip(attempts, result["value"]["extracted"]):
            try:
                original = python.entry(attempt["index"], attempt["ref"])
                expected = dict(ok=True, ref=original.ref.as_dict(), raw_base64=b64(original.raw))
            except repair.RepairWireError as error:
                expected = dict(ok=False, code=error.code)
            self.assertEqual(actual, expected)
        self.assertEqual(result["value"]["extracted"][0]["ref"]["key"], "c" * 64)
        self.assertEqual(result["work"], budget.snapshot())

    def test_builder_rejects_empty_nested_and_host_array_callbacks(self):
        calls = [self.build([]), self.build([b""]), self.build([MAGIC + b"opaque"])]
        for call, result in zip(calls, self.ts(calls)):
            self.assertEqual(result["code"], "repair_invalid_pack")
            self.assertEqual(result, self.py(call))
        result = self.ts([dict(op="host_arrays", policy=POLICY)])[0]
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["value"], dict(failures=["repair_invalid_pack"] * 5 + ["repair_over_budget"], getterCalls=0))
        self.assertEqual(result["work"]["input_bytes"], 0)
        self.assertEqual(result["work"]["hashes"], 0)

    def test_holding_capacity_precedes_snapshot_or_hash_and_failure_does_not_retain(self):
        packed = frame(sorted([b"a", b"b"], key=lambda raw: hashlib.sha256(raw).digest()))
        cases = []
        for patch in (dict(max_entries=2), dict(max_retained_bytes=len(packed) + 79),
                      dict(max_document_bytes=len(packed) - 1)):
            for call in (self.build([b"a", b"b"]), self.parse(packed)):
                cases.append({**call, "policy": {**POLICY, **patch}})
        for call, result in zip(cases, self.ts(cases)):
            self.assertEqual(result["code"], "repair_over_budget")
            for key in ("input_bytes", "output_bytes", "hashes", "hash_bytes", "entries", "retained_bytes"):
                self.assertEqual(result["work"][key], 0, (key, result))
            self.assertEqual(result, self.py(call))
        calls = [{**self.parse(packed), "policy": {**POLICY, **patch}} for patch in
                 (dict(max_nodes=1), dict(max_hashes=1), dict(max_hash_bytes=1), dict(max_total_bytes=len(packed) - 1))]
        for call, result in zip(calls, self.ts(calls)):
            self.assertEqual(result["code"], "repair_over_budget")
            self.assertEqual(result["work"]["entries"], 0)
            self.assertEqual(result["work"]["retained_bytes"], 0)
            self.assertEqual(result, self.py(call))

    def test_defensive_bytes_frozen_index_and_cumulative_budget(self):
        raw = b"synthetic"
        packed = frame([raw])
        for call in (self.build([raw], raw_result=True, mutate=True, extract=[dict(index=0, mutate=True)]),
                     self.parse(packed, raw_result=True, mutate=True, extract=[dict(index=0, mutate=True)])):
            result = self.ts([call])[0]
            self.assertTrue(result["ok"], result)
            self.assertEqual(result["value"]["raw_base64"], b64(packed))
            self.assertTrue(result["value"]["frozen"])
            self.assertTrue(result["value"]["write_rejected"])
            self.assertEqual(result["value"]["extracted"][0]["raw_base64"], b64(raw))
            self.assertEqual(result["value"]["extracted"][0]["ref"]["key"], "a" * 64)
        result = self.ts([{**self.parse(packed, again=True), "policy": {**POLICY, "max_entries": 2}}])[0]
        self.assertEqual(result["value"]["again"], dict(ok=False, code="repair_over_budget"))
        self.assertEqual(result["work"]["input_bytes"], len(packed))
        self.assertEqual(result["work"]["hashes"], 2)
        self.assertEqual(result["work"]["entries"], 2)
        result = self.ts([{**self.parse(packed, raw_until_exhausted=True),
                          "policy": {**POLICY, "max_total_bytes": len(packed) * 2}}])[0]
        self.assertEqual(result["value"]["copies"], [dict(ok=True, size=len(packed)), dict(ok=False, code="repair_over_budget")])
        self.assertEqual(result["work"]["output_bytes"], len(packed))
        mismatch = {**self.build([raw]), "budget_policy": {**POLICY, "max_entries": 31}}
        self.assertEqual(self.ts([mismatch])[0]["code"], "repair_invalid_policy")


if __name__ == "__main__":
    unittest.main()
