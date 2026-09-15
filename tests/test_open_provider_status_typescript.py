"""Native/Python parity for the pure provider status-floor reducer only.

Inputs are synthetic internal summaries, not signed authority. No node, HTTP,
signature verifier, ledger mutation or subprocess delegation is exercised.
"""
import copy
import json
import subprocess
import unittest

import memory_vault_open_provider as provider
from tests import test_network_typescript_agent_network as ts_runtime


DRIVER = r"""
import child from 'node:child_process';
import crypto from 'node:crypto';
import {syncBuiltinESMExports} from 'node:module';
let subprocessCalls=0,signatureCalls=0,networkCalls=0;
const deny=()=>{subprocessCalls++;throw Error('native status reducer cannot delegate');};
for(const name of ['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork'])child[name]=deny;
for(const name of ['sign','verify'])crypto[name]=()=>{signatureCalls++;throw Error('summary is not signed authority');};
syncBuiltinESMExports();
globalThis.fetch=()=>{networkCalls++;throw Error('pure reducer must not fetch');};
const {reduceStatusObservation}=await import('./open-provider.ts'),chunks=[];let size=0;
for await(const chunk of process.stdin){size+=chunk.length;if(size>1048576)throw Error('synthetic fixture limit');chunks.push(chunk);}
const results=[];
for(const call of JSON.parse(Buffer.concat(chunks).toString('utf8'))){
  try{
    if(call.host_objects){
      const good=call.value,failures=[];let getterCalls=0;
      const check=value=>{try{reduceStatusObservation(value);failures.push('accepted');}catch(error){failures.push(error.code??'untyped_error');}};
      check(Object.create(good));
      check({...good,incoming:Object.create(good.incoming)});
      check({...good,prior:Object.create(good.prior)});
      check(Object.defineProperty({...good},'incoming',{enumerable:true,get(){getterCalls++;return good.incoming;}}));
      check({...good,incoming:new Proxy(good.incoming,{get(){getterCalls++;return 1;}})});
      check(Object.assign({...good},{[Symbol('synthetic')]:true}));
      results.push({ok:true,value:{failures,getterCalls}});continue;
    }
    const before=JSON.stringify(call.value);
    if(call.freeze_input&&call.value&&typeof call.value==='object'){
      Object.freeze(call.value.incoming);if(call.value.prior)Object.freeze(call.value.prior);Object.freeze(call.value);
    }
    const value=reduceStatusObservation(call.value);
    const frozen=Object.isFrozen(value),writeRejected=!Reflect.set(value,'revoked_mask',127);
    results.push({ok:true,value,frozen,writeRejected,inputUnchanged:before===JSON.stringify(call.value)});
  }catch(error){results.push({ok:false,code:error.code??'untyped_error'});}
}
process.stdout.write(JSON.stringify({results,subprocessCalls,signatureCalls,networkCalls}));
"""


def observation(*, operation=16, incoming=None, prior=None, required=0, conflict=False):
    return dict(incoming=incoming or dict(revision=2, digest="b" * 64,
                minimum_document_revision=0, status="active", operation_mask=127),
                prior=prior, required_revision=required, operation=operation,
                same_revision_conflict=conflict)


def previous(*, revision=1, digest="a" * 64, minimum=0, revoked=0, conflict=False):
    return dict(revision=revision, digest=digest, minimum_document_revision=minimum,
                revoked_mask=revoked, conflict=conflict)


class OpenProviderStatusTypeScriptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ts_runtime.TypeScriptAgentNetworkTests.setUpClass.__func__(cls)
        (cls.fixture / "driver.mjs").write_text(DRIVER)

    def ts(self, values, *, host_objects=False):
        calls = [dict(value=value, freeze_input=not host_objects, host_objects=host_objects) for value in values]
        run = subprocess.run([self.node, "--experimental-strip-types", str(self.fixture / "driver.mjs")],
            input=json.dumps(calls).encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=30, cwd=self.fixture)
        self.assertEqual(run.returncode, 0, run.stderr.decode(errors="replace")[-6000:])
        result = json.loads(run.stdout)
        for name in ("subprocessCalls", "signatureCalls", "networkCalls"):
            self.assertEqual(result[name], 0)
        self.assertEqual(len(result["results"]), len(values))
        return result["results"]

    def compare(self, values):
        results = self.ts(values)
        for value, result in zip(values, results):
            before = copy.deepcopy(value)
            try:
                expected = dict(ok=True, value=provider.reduce_status_observation(value))
            except provider.ProviderError as error:
                expected = dict(ok=False, code=error.code)
            self.assertEqual(value, before)
            actual = {key: result[key] for key in ("ok", "value" if result["ok"] else "code")}
            self.assertEqual(actual, expected, value)
            if result["ok"]:
                self.assertTrue(result["frozen"])
                self.assertTrue(result["writeRejected"])
                self.assertTrue(result["inputUnchanged"])
                self.assertEqual(set(result["value"]), {"action", "code", "revoked_mask"})
        return results

    def test_all_seven_operations_retain_revocation_and_floor_semantics(self):
        values, expected = [], []
        for operation in (1, 2, 4, 8, 16, 32, 64):
            def add(value, code=None, revoked=0):
                values.append(value)
                expected.append(dict(action="store", code=code, revoked_mask=revoked))
            add(observation(operation=operation))
            revoked = observation(operation=operation)
            revoked["incoming"].update(status="revoked", operation_mask=operation)
            add(revoked, "provider_authority_revoked", operation)
            add(observation(operation=operation, prior=previous(revoked=operation)),
                "provider_authority_revoked", operation)
            other = 2 if operation == 1 else 1
            add(observation(operation=operation, prior=previous(revoked=other)), revoked=other)
            floored = observation(operation=operation, prior=previous(minimum=1), required=1)
            floored["incoming"]["minimum_document_revision"] = 2
            add(floored, "provider_status_revision")
            union = observation(operation=operation, prior=previous(revoked=other))
            union["incoming"].update(status="revoked", operation_mask=operation)
            add(union, "provider_authority_revoked", operation | other)
        self.assertEqual([result["value"] for result in self.compare(values)], expected)

    def test_exact_conflict_rollback_operation_and_revocation_priority(self):
        values, expected = [], []
        def add(value, action, code, revoked):
            values.append(value)
            expected.append(dict(action=action, code=code, revoked_mask=revoked))
        missing_operation = observation(prior=previous(revision=5, minimum=4, revoked=64, conflict=True), conflict=True)
        missing_operation["incoming"].update(operation_mask=2, status="revoked")
        add(missing_operation, "reject", "provider_status_operation", 64)
        add(observation(conflict=True), "conflict", "provider_status_conflict", 0)
        add(observation(prior=previous(revision=5, revoked=4, conflict=True)),
            "conflict", "provider_status_conflict", 4)
        add(observation(prior=previous(revision=5, revoked=8), conflict=True),
            "conflict", "provider_status_conflict", 8)
        rolled = observation(prior=previous(revision=5, minimum=4, revoked=2))
        rolled["incoming"].update(status="revoked", operation_mask=16)
        add(rolled, "reject", "provider_status_rollback", 2)
        add(observation(prior=previous(revision=2, minimum=4, revoked=32)),
            "conflict", "provider_status_conflict", 32)
        add(observation(prior=previous(revision=2, digest="b" * 64, minimum=1, revoked=64)),
            "reject", "provider_status_rollback", 64)
        add(observation(prior=previous(minimum=1, revoked=1)), "reject", "provider_status_rollback", 1)
        precedence = observation(prior=previous(revoked=16), required=0)
        precedence["incoming"]["minimum_document_revision"] = 2
        add(precedence, "store", "provider_authority_revoked", 16)
        add(observation(prior=previous(revision=2, digest="b" * 64)), "store", None, 0)
        large = observation(prior=previous(revision=9007199254740990, minimum=9007199254740990),
                            required=9007199254740991)
        large["incoming"].update(revision=9007199254740991, minimum_document_revision=9007199254740991)
        add(large, "store", None, 0)
        self.assertEqual([result["value"] for result in self.compare(values)], expected)

    def test_invalid_summaries_are_typed_failures_in_both_runtimes(self):
        good = observation(prior=previous())
        values = [None, [], {}, {**good, "extra": True}]
        for key in good:
            missing = copy.deepcopy(good); del missing[key]; values.append(missing)
        invalid = {
            "incoming": {"revision": [True, 0, -1, 1.5, 9007199254740992, "2"],
                         "digest": ["b" * 63, "b" * 64 + "\n", "b" * 64 + "\r\n", "B" * 64, None],
                         "minimum_document_revision": [True, -1, 1.5, 9007199254740992],
                         "status": [None, True, "withdrawn"],
                         "operation_mask": [0, 128, True, 1.5]},
            "prior": {"revision": [0, True], "digest": ["a" * 64 + "\n"],
                      "minimum_document_revision": [-1, True],
                      "revoked_mask": [-1, 128, True], "conflict": [0, None]},
        }
        for section, fields in invalid.items():
            for field, bad_values in fields.items():
                for bad in bad_values:
                    value = copy.deepcopy(good); value[section][field] = bad; values.append(value)
            value = copy.deepcopy(good); value[section]["extra"] = 1; values.append(value)
            for field in good[section]:
                value = copy.deepcopy(good); del value[section][field]; values.append(value)
        for field, bad_values in {"required_revision": [True, -1, 1.5, 9007199254740992],
                                  "operation": [0, 3, 127, 128, True, 1.5, -1, "16"],
                                  "same_revision_conflict": [0, None]}.items():
            for bad in bad_values:
                value = copy.deepcopy(good); value[field] = bad; values.append(value)
        for result in self.compare(values):
            self.assertFalse(result["ok"])
            self.assertEqual(result["code"], "provider_invalid_status_observation")

    def test_native_host_objects_do_not_bypass_plain_own_data_shape(self):
        result = self.ts([observation(prior=previous())], host_objects=True)[0]
        self.assertEqual(result, {"ok": True, "value": {"getterCalls": 0,
            "failures": ["provider_invalid_status_observation"] * 6}})


if __name__ == "__main__":
    unittest.main()
