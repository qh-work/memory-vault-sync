"""Native historical status verification using actual synthetic signatures."""
import base64
import copy
import json
import subprocess
import unittest

import memory_vault_open_provider as provider
import memory_vault_open_repair_wire as wire
from tests import test_network_typescript_agent_network as ts_runtime
from tests.test_open_repair_status import (
    POLICY, NOW, historical_status_fixture, resign_status, scope_digest, status_entry,
)


DRIVER = r"""
import child from 'node:child_process';
import {syncBuiltinESMExports} from 'node:module';
let subprocessCalls=0;
const deny=()=>{subprocessCalls++;throw Error('native status must not delegate');};
for(const name of ['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork'])child[name]=deny;
syncBuiltinESMExports();
const s=await import('./open-repair-status.ts'),w=await import('./open-repair-wire.ts');
const chunks=[];for await(const chunk of process.stdin)chunks.push(chunk);
const calls=JSON.parse(Buffer.concat(chunks).toString('utf8')),results=[];
for(const c of calls){let budget;try{
  budget=new w.RepairBudget(c.policy);const options={...c.options,policy:c.policy,budget};
  if(c.op==='scope'){
    const hashes=c.cases.map(item=>s.statusScope(c.root,item.kind,item.subject,c.policy,budget));
    results.push({ok:true,result:{hashes},work:budget.snapshot(),subprocessCalls});continue;
  }
  const entry={raw:Buffer.from(c.entry.raw,'base64'),ref:c.entry.ref};
  if(c.op==='hostile'){
    let traps=0;const errors=[];
    const invoke=opts=>{try{s.verifyStatusOriginal(entry,opts);errors.push(null);}catch(e){errors.push(e.code??'untyped_error');}};
    invoke({...options,expectedRoot:new Proxy(options.expectedRoot,{ownKeys(){traps++;throw Error('proxy trap');}})});
    const accessor={...options};Object.defineProperty(accessor,'expectedSigningKey',{enumerable:true,get(){traps++;throw Error('getter');}});invoke(accessor);
    results.push({ok:true,result:{traps,errors},work:budget.snapshot(),subprocessCalls});continue;
  }
  if(c.op==='repeat'){
    const errors=[];for(let i=0;i<2;i++){try{s.verifyStatusOriginal(entry,options);errors.push(null);}catch(e){errors.push(e.code??'untyped_error');}}
    results.push({ok:true,result:{errors},work:budget.snapshot(),subprocessCalls});continue;
  }
  if(c.op==='authenticate')delete options.required;
  const value=c.op==='authenticate'?s.authenticateStatusOriginal(entry,options):s.verifyStatusOriginal(entry,options);
  const original=Buffer.from(value.raw).toString('base64');
  if(c.mutate){entry.raw.fill(0);entry.ref.key='00'.repeat(32);options.expectedRoot.root_id='changed';value.raw.fill(0);}
  results.push({ok:true,result:{raw:Buffer.from(value.raw).toString('base64'),raw_sha256:value.raw_sha256,
    canonical_sha256:value.canonical_sha256,at:value.at,ref:value.ref,payload:value.payload,
    immutable:original===Buffer.from(value.raw).toString('base64'),frozen:Object.isFrozen(value)&&Object.isFrozen(value.payload)},work:budget.snapshot(),subprocessCalls});
}catch(e){results.push({ok:false,code:e.code??'untyped_error',work:budget?.snapshot(),subprocessCalls});}}
process.stdout.write(JSON.stringify(results));
"""


class OpenRepairStatusTypeScriptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ts_runtime.TypeScriptAgentNetworkTests.setUpClass.__func__(cls)
        (cls.fixture / "driver.mjs").write_text(DRIVER)

    def setUp(self):
        (self.signed, self.entry, self.options, self.signers, self.subjects,
         self.expected, self.docs) = historical_status_fixture()

    def ts(self, calls):
        result = subprocess.run([self.node, "--experimental-strip-types", str(self.fixture / "driver.mjs")],
            cwd=self.fixture, input=json.dumps(calls).encode(), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace")[-5000:])
        values = json.loads(result.stdout)
        self.assertTrue(all(value["subprocessCalls"] == 0 for value in values))
        return values

    def call(self, entry=None, options=None, policy=None, **extra):
        entry = self.entry if entry is None else entry
        source = self.options if options is None else options
        names = {"expected_root": "expectedRoot", "expected_signing_key": "expectedSigningKey",
                 "allowed_scopes": "allowedScopes"}
        return dict(entry={"raw": base64.b64encode(entry["raw"]).decode(), "ref": entry["ref"]},
                    options={names.get(k, k): v for k, v in source.items()},
                    policy=policy or POLICY, **extra)

    def changed(self, mutate):
        return status_entry(resign_status(self.signed, self.signers["owner"], mutate))

    def test_authenticated_denial_original_is_retained_without_granting_permission(self):
        import memory_vault_open_repair_status as status
        entry = self.changed(lambda payload: payload["entries"][0].update(status="revoked"))
        native, denied = self.ts([self.call(entry, op="authenticate"), self.call(entry)])
        self.assertTrue(native["ok"], native)
        self.assertEqual(denied["code"], "repair_authority_revoked")
        local = wire.RepairPolicy(**POLICY)
        options = {key: value for key, value in self.options.items() if key != "required"}
        py = status.authenticate_status_original(entry, **options, policy=local, budget=wire.RepairBudget(local))
        self.assertEqual(base64.b64decode(native["result"]["raw"]), py.raw)
        self.assertEqual(native["result"]["canonical_sha256"], py.canonical_sha256)
        self.assertEqual(native["work"]["signature_checks"], 1)

    def test_original_raw_canonical_hashes_and_mutable_snapshots_match_python(self):
        import memory_vault_open_repair_status as status
        entry = status_entry(self.signed, pretty=True)
        native = self.ts([self.call(entry, mutate=True)])[0]
        self.assertTrue(native["ok"], native)
        local = wire.RepairPolicy(**POLICY)
        budget = wire.RepairBudget(local)
        py = status.verify_status_original(entry, **self.options, policy=local, budget=budget)
        value = native["result"]
        self.assertEqual(base64.b64decode(value["raw"]), py.raw)
        self.assertEqual(value["raw_sha256"], py.raw_sha256)
        self.assertEqual(value["canonical_sha256"], py.canonical_sha256)
        self.assertNotEqual(value["raw_sha256"], value["canonical_sha256"])
        self.assertEqual(value["ref"], entry["ref"])
        self.assertTrue(value["immutable"])
        self.assertTrue(value["frozen"])
        self.assertEqual(native["work"]["signature_checks"], 1)
        self.assertEqual(native["work"]["hashes"], budget.snapshot()["hashes"])
        self.assertEqual(native["work"]["hash_bytes"], budget.snapshot()["hash_bytes"])

    def test_closed_authority_ack_slot_and_resource_scope_hashes(self):
        root = self.options["expected_root"]
        cases = [("authority", self.subjects["root"]), ("authority", self.subjects["read"]),
                 ("authority", {"authority_kind": "bootstrap.grant", "authority_sha256": "ab" * 32}),
                 ("authority", {"authority_kind": "ack.disclosure", "authority_sha256": "ac" * 32}),
                 ("authority", {"authority_kind": "ack.copy_reservation_consent", "authority_sha256": "ad" * 32}),
                 ("authority", {"authority_kind": "ack.copy_disclosure", "authority_sha256": "ae" * 32}),
                 ("authority", {"authority_kind": "ack.replica_return_consent", "authority_sha256": "af" * 32}),
                 ("ack_slot", self.expected["expected_ack_slot"]),
                 ("resource", self.docs["active"]["payload"]["resource"])]
        call = self.call(op="scope", root=root, cases=[dict(kind=k, subject=s) for k, s in cases])
        value = self.ts([call])[0]
        self.assertTrue(value["ok"], value)
        self.assertEqual(value["result"]["hashes"], [scope_digest(root, k, s) for k, s in cases])
        self.assertEqual(value["work"]["hashes"], len(cases))
        self.assertEqual(value["work"]["signature_checks"], 0)

    def test_ack_disclosure_scope_matches_python_without_opening_future_authority_kinds(self):
        import memory_vault_open_repair_status as status
        root=self.options['expected_root'];subject=dict(authority_kind='ack.disclosure',authority_sha256='cd'*32)
        calls=[self.call(op='scope',root=root,cases=[dict(kind='authority',subject=subject)])]
        for name in ('ack.disclosure.future','ack.occupied','mailbox.disclosure'):
            calls.append(self.call(op='scope',root=root,cases=[dict(kind='authority',subject=subject|{'authority_kind':name})]))
        values=self.ts(calls);self.assertTrue(values[0]['ok'],values[0])
        local=wire.RepairPolicy(**POLICY)
        expected=status.status_scope(root,'authority',subject,local,wire.RepairBudget(local))
        self.assertEqual(values[0]['result']['hashes'],[expected])
        self.assertEqual([value['code'] for value in values[1:]],['repair_invalid_status']*3)

    def test_mailbox_catalog_slot_and_owner_authority_scopes_match_python(self):
        import memory_vault_open_repair_status as status
        root=copy.deepcopy(self.options['expected_root']);root['root_kind']='mailbox'
        slot=dict(root_key=root,slot_id='synthetic_mailbox_slot',writer=root['owner'],writer_storage_epoch='synthetic_epoch')
        cases=[dict(kind='catalog',subject=dict(root_key=root)),dict(kind='mailbox_slot',subject=slot)]
        cases += [dict(kind='authority',subject=dict(authority_kind=name,authority_sha256='ab'*32)) for name in
            ('mailbox.root_authority','mailbox.root_read_grant','mailbox.maintenance_root','mailbox.read_grant','mailbox.copy_reservation_consent','mailbox.copy_disclosure', 'mailbox.replica_return_consent','delivery.destination','message.disclosure')]
        actual=self.ts([self.call(op='scope',root=root,cases=cases)])[0]
        self.assertTrue(actual['ok'],actual)
        policy=wire.RepairPolicy(**POLICY);budget=wire.RepairBudget(policy)
        self.assertEqual(actual['result']['hashes'],[status.status_scope(root,c['kind'],c['subject'],policy,budget) for c in cases])

    def test_whole_status_disclosure_and_required_scope_presence(self):
        first = self.options["required"][0]
        partial = {**self.options, "allowed_scopes": [{k: first[k] for k in ("scope_kind", "scope_id")}],
                   "required": [first]}
        missing = self.changed(lambda p: p.update(entries=p["entries"][:1]))
        values = self.ts([self.call(options=partial), self.call(missing)])
        self.assertEqual([v["code"] for v in values], ["repair_status_disclosure", "repair_status_missing"])

    def test_revocation_full_operation_mask_and_minimum_document_revision(self):
        cases = [self.changed(lambda p: p["entries"][0].update(status="revoked")),
                 self.changed(lambda p: p["entries"][0].update(operation_mask=1)),
                 self.changed(lambda p: p["entries"][0].update(minimum_document_revision=2))]
        values = self.ts([self.call(entry) for entry in cases])
        self.assertEqual([v["code"] for v in values],
                         ["repair_authority_revoked", "repair_status_operation", "repair_status_revision"])
        allowed = self.ts([self.call(self.changed(lambda p: p.update(revision=900)))])[0]
        self.assertTrue(allowed["ok"], allowed)

    def test_independent_expected_issuer_root_and_original_hash(self):
        other_root = copy.deepcopy(self.options["expected_root"])
        other_root["root_id"] = "different_synthetic_root"
        bad = copy.deepcopy(self.entry)
        bad["ref"]["raw_sha256"] = "00" * 32
        values = self.ts([
            self.call(options={**self.options, "expected_signing_key": self.signers["target"].public_descriptor()}),
            self.call(options={**self.options, "expected_root": other_root}), self.call(bad)])
        self.assertEqual([v["code"] for v in values],
                         ["repair_wrong_issuer", "repair_status_mismatch", "repair_ref_mismatch"])

        root = self.options["expected_root"]
        node_scope = {"scope_kind": "resource", "scope_id": scope_digest(root, "resource",
                      self.docs["active"]["payload"]["resource"])}
        signed = provider.issue_status(self.signers["target"], root=root, revision=22,
            entries=[{**node_scope, "minimum_document_revision": 1, "status": "active", "operation_mask": 66}],
            issued_at=NOW, valid_until=NOW + 600)
        options = {**self.options, "expected_signing_key": self.signers["target"].public_descriptor(),
                   "allowed_scopes": [node_scope],
                   "required": [{**node_scope, "document_revision": 1, "operation_mask": 66}]}
        accepted = self.ts([self.call(status_entry(signed), options)])[0]
        self.assertTrue(accepted["ok"], accepted)

    def test_legacy_explicit_time_boundary_and_no_implicit_expiry_field(self):
        calls = [self.call(options={**self.options, "at": at}) for at in (NOW - 30, NOW - 31, NOW + 599, NOW + 600)]
        calls.append(self.call(self.changed(lambda p: p.update(expires_at=NOW + 600))))
        values = self.ts(calls)
        self.assertEqual([v["ok"] for v in values], [True, False, True, False, False])
        self.assertEqual(values[-1]["code"], "repair_invalid_status")

    def test_closed_entries_order_no_zero_mask_and_no_unknown_fields(self):
        changes = [lambda p: p["entries"].reverse(), lambda p: p.update(entries=[]),
                   lambda p: p["entries"].append(p["entries"][0]),
                   lambda p: p["entries"][0].update(operation_mask=0),
                   lambda p: p["entries"][0].update(scope_kind="unregistered_scope"),
                   lambda p: p.update(entries=[{**p["entries"][0], "scope_id": format(i, "064x")}
                                               for i in range(17)]),
                   lambda p: p["entries"][0].update(unexpected=True)]
        values = self.ts([self.call(self.changed(change)) for change in changes])
        self.assertTrue(all(not v["ok"] and v["code"] == "repair_invalid_status" for v in values), values)

    def test_real_failed_signature_and_repeat_budget_cannot_be_reset(self):
        signed = copy.deepcopy(self.signed)
        signed["proof"]["signature"] = base64.b64encode(bytes(64)).decode()
        failed, repeated = self.ts([self.call(status_entry(signed)),
            self.call(policy={**POLICY, "max_signature_checks": 1}, op="repeat")])
        self.assertEqual(failed["code"], "repair_invalid_signature")
        self.assertEqual(failed["work"]["signature_checks"], 1)
        self.assertEqual(repeated["result"]["errors"], [None, "repair_over_budget"])
        self.assertEqual(repeated["work"]["signature_checks"], 1)

    def test_expected_hostile_objects_do_not_execute_getters_or_proxies(self):
        value = self.ts([self.call(op="hostile")])[0]
        self.assertTrue(value["ok"], value)
        self.assertEqual(value["result"]["traps"], 0)
        self.assertTrue(all(code and code != "untyped_error" for code in value["result"]["errors"]))
        self.assertEqual(value["work"]["signature_checks"], 0)


if __name__ == "__main__":
    unittest.main()
