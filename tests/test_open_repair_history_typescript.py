"""Synthetic native historical shapes, never authority or graph acceptance."""
import base64
import copy
import hashlib
import json
import subprocess
import unittest

from tests import test_network_typescript_agent_network as ts_runtime


POLICY = dict(max_document_bytes=131072, max_total_bytes=2097152,
              max_nodes=100000, max_depth=100, max_string_bytes=32768,
              max_hash_bytes=1048576, max_hashes=100, max_entries=100,
              max_retained_bytes=131072)
VARIANTS = ("mailbox_root", "mailbox_feed", "mailbox_member", "ack_unbound",
            "ack_empty", "ack_occupied_inputs")


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def ref(number, namespace="meta"):
    digest = f"{number:064x}"
    return dict(namespace=namespace, key=digest, raw_sha256=digest, size=number + 1)


def identity(number):
    return dict(signing_key_id="ed25519_" + f"{number:064x}",
                encryption_key_id="x25519_" + f"{number + 1:064x}")


def role(name, number=20):
    return dict(role=name, document_ref=ref(number), pack_ref=ref(100), entry_index=0)


def manifest(variant):
    """Intentionally incomplete raw dependencies: local shape must stay Draft."""
    root = dict(owner=identity(1), root_kind="mailbox" if variant.startswith("mailbox_") else "ack_return",
                anchor_ref=dict(namespace="anchor", key="a" * 64), owner_epoch="synthetic:owner.1",
                root_id="synthetic-root")
    first_role = dict(mailbox_root="mailbox.root_authority", mailbox_feed="feed.head",
                      mailbox_member="contact.request", ack_unbound="ack.root_authority",
                      ack_empty="history.ack_unbound", ack_occupied_inputs="history.ack_empty")[variant]
    value = dict(schema_version="memory-vault-open-repair/v1", kind="historical.manifest",
                 variant=variant, root_key=root, roles=[role(first_role)])
    if variant == "mailbox_root":
        value.update(root_authority_ref=ref(1), catalog_ref=ref(2), genesis_head_refs=[ref(3), ref(4)])
    elif variant.startswith("mailbox_"):
        value["slot_key"] = dict(root_key=copy.deepcopy(root), slot_id="synthetic-slot",
                                 writer=identity(3), writer_storage_epoch="synthetic-writer")
        if variant == "mailbox_member":
            value.update(message_id="msg_" + "b" * 64, envelope_ref=ref(5, "object"), attempt_ref=ref(6))
        else:
            members = [dict(sequence=sequence, message_id="msg_" + f"{sequence:064x}",
                            envelope_ref=ref(10 + sequence, "object"), historical_manifest_ref=ref(20 + sequence),
                            admission_core_ref=ref(30 + sequence), admission_link_ref=ref(40 + sequence),
                            source_custody_ref=ref(50 + sequence)) for sequence in (4, 5)]
            value.update(slot_ref=ref(1), feed_head_ref=ref(2), covered_interval=dict(start=4, end=6),
                         subtree=dict(root_ref=ref(3), parent_path_refs=[ref(9), ref(8)]), members=members)
    else:
        value.update(ack_slot=dict(root_key=copy.deepcopy(root), slot_id="synthetic-ack",
                                   receipt_writer=identity(3), grant_id="synthetic-grant"), root_authority_ref=ref(1))
        if variant != "ack_unbound":
            value.update(grant_ref=ref(2), binding_ref=ref(3))
        if variant == "ack_occupied_inputs":
            value.update(receipt_ref=ref(4), put_ref=ref(5), disclosure_ref=ref(6),
                         admission_resource=dict(node_key_id="ed25519_" + "c" * 64,
                                                 storage_epoch="synthetic-node", lease_id="synthetic-lease",
                                                 resource_id="synthetic-resource"))
    return value


def packed_inputs(variant, *, unused=False, wrong_phase=False):
    """Real byte packs with intentionally unverified synthetic role bodies."""
    import memory_vault_open_repair_wire as wire
    packs = []

    def reference(raw):
        digest = hashlib.sha256(raw).hexdigest()
        return dict(namespace="meta", key=digest, raw_sha256=digest, size=len(raw))

    def body(name):
        # Exact original bytes must survive without parsing this int64 as JS Number.
        return b'{"synthetic_role":' + json.dumps(name).encode() + b',"legacy_int64":9223372036854775807}\n'

    def pack(value, originals, extra=False):
        policy = wire.RepairPolicy(**POLICY)
        content = [raw for _, raw in originals] + ([body("unused")] if extra else [])
        packed = wire.build_raw_pack(content, policy, wire.RepairBudget(policy))
        entries = {(entry.raw_sha256, entry.size): index for index, entry in enumerate(packed.entries)}
        value["roles"] = [dict(role=name, document_ref=reference(raw), pack_ref=packed.ref.as_dict(),
                               entry_index=entries[(reference(raw)["raw_sha256"], len(raw))]) for name, raw in originals]
        value["roles"].sort(key=lambda row: (row["role"], row["document_ref"]["namespace"],
                                           row["document_ref"]["key"], row["document_ref"]["raw_sha256"], row["document_ref"]["size"]))
        packs.append(dict(ref=packed.ref.as_dict(), raw_base64=base64.b64encode(packed.raw).decode()))
        return canonical(value)

    def build(selected, top=False):
        value = manifest(selected)
        if selected == "mailbox_root":
            root, catalog, head = body("root"), body("catalog"), body("head")
            value.update(root_authority_ref=reference(root), catalog_ref=reference(catalog), genesis_head_refs=[reference(head)])
            originals = [("mailbox.root_authority", root), ("mailbox.catalog", catalog), ("genesis.head", head)]
        elif selected == "mailbox_member":
            attempt = body("attempt"); value["attempt_ref"] = reference(attempt)
            originals = [("delivery.attempt", attempt)]
        elif selected == "mailbox_feed":
            child_raw = build("mailbox_member")
            child = json.loads(child_raw)
            slot, head, core, link, custody = [body(name) for name in ("slot", "head", "core", "link", "custody")]
            def index(level, child_ref):
                return canonical(dict(schema_version="memory-vault-open-repair/v1", kind="range.index",
                                      slot_key=value["slot_key"], level=level, start=4, end=5,
                                      children=[dict(start=4, end=5, ref=child_ref)]))
            leaf = index(0, ref(500))
            subtree_root = index(1, reference(leaf))
            parent = index(2, reference(subtree_root))
            value.update(slot_ref=reference(slot), feed_head_ref=reference(head), covered_interval=dict(start=4, end=5),
                         subtree=dict(root_ref=reference(subtree_root), parent_path_refs=[reference(parent)]),
                         members=[dict(sequence=4, message_id=child["message_id"], envelope_ref=child["envelope_ref"],
                                       historical_manifest_ref=reference(child_raw), admission_core_ref=reference(core),
                                       admission_link_ref=reference(link), source_custody_ref=reference(custody))])
            originals = [("history.member", child_raw), ("mailbox.slot", slot), ("feed.head", head),
                         ("member.core", core), ("member.link", link), ("member.custody", custody),
                         ("range.index", leaf), ("range.index", subtree_root), ("range.index", parent)]
        elif selected == "ack_unbound":
            root = body("ack-root"); value["root_authority_ref"] = reference(root)
            originals = [("ack.root_authority", root)]
        else:
            prior = "ack_unbound" if selected == "ack_empty" else "ack_empty"
            prior_raw = build(prior)
            child = json.loads(prior_raw)
            if top and wrong_phase:
                prior_raw = canonical(manifest("mailbox_member"))
            value["root_authority_ref"] = child["root_authority_ref"]
            originals = [("history." + prior, prior_raw)]
            if selected == "ack_empty":
                grant, binding = body("grant"), body("binding")
                value.update(grant_ref=reference(grant), binding_ref=reference(binding))
                originals += [("ack.write_grant", grant), ("ack.binding", binding)]
            else:
                value.update(grant_ref=child["grant_ref"], binding_ref=child["binding_ref"])
                for name, field in (("recipient.receipt", "receipt_ref"), ("ack.put", "put_ref"), ("ack.disclosure", "disclosure_ref")):
                    original = body(name); value[field] = reference(original); originals.append((name, original))
        return pack(value, originals, unused and top)

    raw = build(variant, True)
    return dict(op="resolve", policy=POLICY, raw_base64=base64.b64encode(raw).decode(), packs=packs)


DRIVER = r"""
import child from 'node:child_process';
import {syncBuiltinESMExports} from 'node:module';
let subprocessCalls=0,networkCalls=0;
const deny=()=>{subprocessCalls++;throw Error('native history cannot delegate');};
for(const name of ['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork'])child[name]=deny;
syncBuiltinESMExports();
globalThis.fetch=()=>{networkCalls++;throw Error('local history must not fetch');};
const wire=await import('./open-repair-wire.ts'),history=await import('./open-repair-history.ts');
const chunks=[];let inputSize=0;
for await(const chunk of process.stdin){inputSize+=chunk.length;if(inputSize>2097152)throw Error('synthetic input limit');chunks.push(chunk);}
const input=JSON.parse(Buffer.concat(chunks).toString('utf8')),results=[];
for(const call of input){
  let budget;
  try{
    budget=new wire.RepairBudget(call.budget_policy??call.policy);
    if(call.op==='resolve'){
      const resolver=new wire.LocalRawResolver(call.policy,budget);
      for(const pack of call.packs)resolver.put(pack.ref.namespace,pack.ref.key,Buffer.from(pack.raw_base64,'base64'));
      let overrideCalls=0,actual=resolver;
      if(call.override){
        Object.defineProperty(resolver,'resolve',{value:()=>{overrideCalls++;throw Error('must use original resolver');}});
        Object.defineProperty(resolver,'budget',{get(){overrideCalls++;throw Error('must use original getter');}});
        Object.defineProperty(resolver,'policy',{get(){overrideCalls++;throw Error('must use original getter');}});
      }
      if(call.fake==='proxy')actual=new Proxy(resolver,{});
      if(call.fake==='subclass'){class Sub extends wire.LocalRawResolver{};actual=new Sub(call.policy,budget);}
      if(call.fake==='object')actual=Object.create(wire.LocalRawResolver.prototype);
      const chosen=call.fake==='budget'?new wire.RepairBudget(call.policy):budget;
      const resolved=history.resolveHistoricalInputs(Buffer.from(call.raw_base64,'base64'),actual,call.policy,chosen);
      const work=budget.snapshot();
      const summarize=tree=>({manifest:tree.manifest.value,roles:tree.roles.map(row=>({role:row.role,ref:row.original.ref,
        raw_base64:Buffer.from(row.original.raw).toString('base64')})),predecessors:tree.predecessors.map(summarize)});
      const value=summarize(resolved);
      results.push({ok:true,value,work,overrideCalls,export_work:budget.snapshot(),
        frozen:Object.isFrozen(resolved)&&Object.isFrozen(resolved.roles)&&Object.isFrozen(resolved.predecessors)&&
          resolved.roles.every(row=>Object.isFrozen(row))});continue;
    }
    if(call.op==='host'){
      let getterCalls=0;const failures=[];
      const attempt=value=>{try{history.buildHistoricalManifest(value,call.policy,budget);failures.push('accepted');}
        catch(error){failures.push(error.code??'untyped_error');}};
      attempt(Object.defineProperty({},'variant',{enumerable:true,get(){getterCalls++;return 'mailbox_root';}}));
      attempt(new Proxy(call.value,{get(){getterCalls++;throw Error('must not read proxy');}}));
      const cycle={};cycle.self=cycle;attempt(cycle);
      results.push({ok:true,value:{getterCalls,failures},work:budget.snapshot()});continue;
    }
    if(call.op==='shared'){
      const steps=[];
      for(const value of call.values){try{history.buildHistoricalManifest(value,call.policy,budget);steps.push({ok:true,work:budget.snapshot()});}
        catch(error){steps.push({ok:false,code:error.code??'untyped_error',work:budget.snapshot()});}}
      results.push({ok:true,value:steps,work:budget.snapshot()});continue;
    }
    const raw=call.raw_base64===undefined?undefined:Buffer.from(call.raw_base64,'base64');
    const draft=call.op==='parse'?history.parseHistoricalManifest(raw,call.policy,budget):
      history.buildHistoricalManifest(call.value,call.policy,budget);
    const result={ok:true,value:draft.value,work:budget.snapshot()};
    if(call.mutate){
      const frozen=Object.isFrozen(draft.value)&&Object.isFrozen(draft.value.roles)&&Object.isFrozen(draft.value.root_key.owner);
      const rejected=!Reflect.set(draft.value.root_key,'root_id','changed')&&!Reflect.set(draft.value.roles,'0',{});
      if(raw)raw.fill(0);else{call.value.root_key.root_id='changed';call.value.roles.length=0;}
      const output=draft.raw;output.fill(0);
      result.snapshot={frozen,rejected,raw_base64:Buffer.from(draft.raw).toString('base64')};
    }
    results.push(result);
  }catch(error){results.push({ok:false,code:error.code??'untyped_error',...(budget?{work:budget.snapshot()}:{} )});}
}
process.stdout.write(JSON.stringify({results,subprocessCalls,networkCalls}));
"""


class OpenRepairHistoryTypeScriptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # The existing fixture copies every network/*.ts, including this module.
        ts_runtime.TypeScriptAgentNetworkTests.setUpClass.__func__(cls)
        (cls.fixture / "driver.mjs").write_text(DRIVER)

    def ts(self, calls):
        result = subprocess.run([self.node, "--experimental-strip-types", str(self.fixture / "driver.mjs")],
                                input=json.dumps(calls).encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                cwd=self.fixture, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace")[-6000:])
        value = json.loads(result.stdout)
        self.assertEqual((value["subprocessCalls"], value["networkCalls"]), (0, 0))
        self.assertEqual(len(value["results"]), len(calls))
        return value["results"]

    @staticmethod
    def call(value, op="build", **extra):
        result = {"op": op, "policy": POLICY, **extra}
        if op == "parse":
            result["raw_base64"] = base64.b64encode(canonical(value)).decode()
        else:
            result["value"] = value
        return result

    def assert_refusals(self, cases):
        results = self.ts([self.call(value) for _, value, _ in cases])
        for (label, _, code), result in zip(cases, results):
            with self.subTest(case=label):
                self.assertFalse(result["ok"], result)
                self.assertEqual(result["code"], code)
                self.assertEqual(result["work"]["signature_checks"], 0)

    def test_six_variants_parse_and_build_native_drafts_match_python(self):
        import memory_vault_open_repair_history as history
        import memory_vault_open_repair_wire as wire
        cases = [(op, manifest(variant)) for variant in VARIANTS for op in ("parse", "build")]
        results = self.ts([self.call(value, op) for op, value in cases])
        for (op, value), result in zip(cases, results):
            with self.subTest(op=op, variant=value["variant"]):
                self.assertTrue(result["ok"], result)
                self.assertEqual(result["value"], value)
                policy = wire.RepairPolicy(**POLICY)
                budget = wire.RepairBudget(policy)
                if op == "parse":
                    draft = history.parse_historical_manifest(canonical(value), policy, budget)
                else:
                    draft = history.build_historical_manifest(value, policy, budget)
                self.assertEqual(draft.value, value)
                self.assertEqual(result["work"], budget.snapshot())
                self.assertEqual(result["work"]["hashes"], 0)
                self.assertEqual(result["work"]["signature_checks"], 0)

    def test_variant_closed_fields_and_phase_roles_are_enforced(self):
        cases = []
        for variant in VARIANTS:
            for change in ("extra", "missing", "empty_roles", "unknown_role"):
                value = manifest(variant)
                if change == "extra": value["future_commit_ref"] = ref(99)
                elif change == "missing": del value["root_key"]
                elif change == "empty_roles": value["roles"] = []
                else: value["roles"][0]["role"] = "historical.status.*"
                cases.append((variant + "/" + change, value, "repair_invalid_history"))
        prohibited = dict(mailbox_root="member.core", mailbox_feed="mailbox.root_authority",
                          mailbox_member="member.custody", ack_unbound="ack.binding",
                          ack_empty="recipient.receipt", ack_occupied_inputs="ack.commit")
        for variant, name in prohibited.items():
            value = manifest(variant); value["roles"] = [role(name)]
            cases.append((variant + "/phase", value, "repair_invalid_history"))
        value = manifest("mailbox_root"); value["genesis_head_refs"] = []
        self.assertTrue(self.ts([self.call(value)])[0]["ok"])
        self.assert_refusals(cases)

    def test_exact_ref_order_identity_and_root_bindings(self):
        cases = []
        for label in ("role_reverse", "role_duplicate", "pack_namespace", "pack_key", "pack_size",
                      "raw_extra", "entry_boolean", "root_mismatch", "opaque_newline", "keyid_newline",
                      "message_id", "root_unknown"):
            value = manifest("mailbox_member"); code = "repair_invalid_history"
            if label == "role_reverse": value["roles"] = [role("contact.request", 21), role("contact.request", 20)]
            elif label == "role_duplicate": value["roles"] *= 2
            elif label == "pack_namespace": value["roles"][0]["pack_ref"]["namespace"] = "object"
            elif label == "pack_key": value["roles"][0]["pack_ref"]["key"] = "f" * 64
            elif label == "pack_size": value["roles"][0]["pack_ref"]["size"] = 0; code = "repair_invalid_ref"
            elif label == "raw_extra": value["envelope_ref"]["unexpected"] = True; code = "repair_invalid_ref"
            elif label == "entry_boolean": value["roles"][0]["entry_index"] = True; code = "repair_invalid_integer"
            elif label == "root_mismatch": value["slot_key"]["root_key"]["owner_epoch"] = "different"
            elif label == "opaque_newline": value["slot_key"]["slot_id"] += "\n"
            elif label == "keyid_newline": value["slot_key"]["writer"]["signing_key_id"] += "\n"
            elif label == "message_id": value["message_id"] = "synthetic-not-carrier-id"
            else: value["root_key"]["extra"] = True
            cases.append((label, value, code))
        for label, heads in (("genesis_reverse", [ref(4), ref(3)]), ("genesis_duplicate", [ref(3), ref(3)])):
            value = manifest("mailbox_root"); value["genesis_head_refs"] = heads
            cases.append((label, value, "repair_invalid_history"))
        self.assert_refusals(cases)
        value = manifest("mailbox_member")
        value["roles"] = [role("contact.request", 20), role("contact.request", 21)]
        value["envelope_ref"]["key"] = "f" * 64  # An opaque locator need not be the raw hash.
        self.assertTrue(self.ts([self.call(value)])[0]["ok"])

    def test_feed_complete_interval_shape_and_parent_path_order(self):
        cases = []
        for label in ("empty_interval", "missing_member", "sequence_gap", "duplicate_message",
                      "parent_duplicate", "parent_self", "member_extra", "sequence_boolean", "missing_raw"):
            value = manifest("mailbox_feed"); code = "repair_invalid_history"
            if label == "empty_interval": value["covered_interval"]["end"] = 4
            elif label == "missing_member": value["members"].pop()
            elif label == "sequence_gap": value["members"][1]["sequence"] = 6
            elif label == "duplicate_message": value["members"][1]["message_id"] = value["members"][0]["message_id"]
            elif label == "parent_duplicate": value["subtree"]["parent_path_refs"] *= 2
            elif label == "parent_self": value["subtree"]["parent_path_refs"].append(value["subtree"]["root_ref"])
            elif label == "member_extra": value["members"][0]["future_commit_ref"] = ref(1)
            elif label == "sequence_boolean": value["members"][0]["sequence"] = True; code = "repair_invalid_integer"
            else: del value["members"][0]["source_custody_ref"]
            cases.append((label, value, code))
        self.assert_refusals(cases)
        value = manifest("mailbox_feed")
        result = self.ts([self.call(value)])[0]
        self.assertEqual(result["value"]["subtree"]["parent_path_refs"], [ref(9), ref(8)])

    def test_wire_limits_errors_and_shared_budget_are_not_reset(self):
        value = manifest("ack_unbound")
        calls = [self.call(value, policy={**POLICY, "max_document_bytes": 1}),
                 self.call(value, policy={**POLICY, "max_nodes": True}),
                 self.call(value, budget_policy={**POLICY, "max_nodes": POLICY["max_nodes"] + 1}),
                 dict(op="parse", policy=POLICY, raw_base64=base64.b64encode(canonical(value) + b"\n").decode())]
        results = self.ts(calls)
        self.assertEqual([result["code"] for result in results],
                         ["repair_over_budget", "repair_invalid_policy", "repair_invalid_policy", "repair_noncanonical_json"])
        size = len(canonical(value))
        shared = self.ts([dict(op="shared", values=[value, value], policy={**POLICY, "max_total_bytes": size})])[0]
        self.assertTrue(shared["value"][0]["ok"])
        self.assertEqual(shared["value"][1]["code"], "repair_over_budget")
        self.assertGreater(shared["work"]["output_bytes"], 0)
        self.assertLessEqual(shared["work"]["output_bytes"], size)
        self.assertEqual(shared["work"]["signature_checks"], 0)

    def test_builder_never_invokes_host_getters_and_snapshots_stay_immutable(self):
        value = manifest("mailbox_root")
        host = self.ts([dict(op="host", value=value, policy=POLICY)])[0]
        self.assertEqual(host["value"], dict(getterCalls=0, failures=["repair_invalid_json"] * 3))
        for result in self.ts([self.call(value, op, mutate=True) for op in ("parse", "build")]):
            self.assertTrue(result["ok"], result)
            self.assertTrue(result["snapshot"]["frozen"])
            self.assertTrue(result["snapshot"]["rejected"])
            self.assertEqual(result["value"], value)
            self.assertEqual(base64.b64decode(result["snapshot"]["raw_base64"]), canonical(value))

    @staticmethod
    def python_inputs(call):
        import memory_vault_open_repair_history as history
        import memory_vault_open_repair_wire as wire
        policy = wire.RepairPolicy(**call["policy"])
        budget = wire.RepairBudget(policy)
        resolver = wire.LocalRawResolver(policy, budget)
        for packed in call["packs"]:
            resolver.put(packed["ref"]["namespace"], packed["ref"]["key"], base64.b64decode(packed["raw_base64"]))
        resolved = history.resolve_historical_inputs(base64.b64decode(call["raw_base64"]), resolver, policy, budget)

        def summarize(tree):
            return dict(manifest=tree.manifest.value,
                        roles=[dict(role=row.role, ref=row.original.ref.as_dict(), raw_base64=base64.b64encode(row.original.raw).decode())
                               for row in tree.roles], predecessors=[summarize(child) for child in tree.predecessors])
        return summarize(resolved), budget.snapshot()

    def test_local_pack_inputs_and_fixed_predecessors_match_python_bytes(self):
        calls = [packed_inputs(variant) for variant in VARIANTS]
        for variant, call, result in zip(VARIANTS, calls, self.ts(calls)):
            with self.subTest(variant=variant):
                self.assertTrue(result["ok"], result)
                expected, python_work = self.python_inputs(call)
                self.assertEqual(result["value"], expected)
                self.assertTrue(result["frozen"])
                for counter in ("hashes", "hash_bytes", "input_bytes", "entries", "retained_bytes"):
                    self.assertEqual(result["work"][counter], python_work[counter])
                # Native snapshot/export copies are real work, not parity padding.
                self.assertGreater(result["export_work"]["output_bytes"], result["work"]["output_bytes"])
                self.assertEqual(result["work"]["signature_checks"], 0)

    def test_local_pack_inputs_refuse_phase_binding_unused_and_corrupt_bytes(self):
        calls = [packed_inputs("ack_empty", wrong_phase=True), packed_inputs("mailbox_member", unused=True)]
        expected = ["repair_invalid_history", "repair_invalid_history"]
        for variant, field in (("mailbox_member", "attempt_ref"), ("ack_occupied_inputs", "grant_ref")):
            call = packed_inputs(variant); value = json.loads(base64.b64decode(call["raw_base64"]))
            value[field] = ref(999); call["raw_base64"] = base64.b64encode(canonical(value)).decode()
            calls.append(call); expected.append("repair_invalid_history")
        for field in ("message_id", "envelope_ref"):
            call = packed_inputs("mailbox_feed"); value = json.loads(base64.b64decode(call["raw_base64"]))
            value["members"][0][field] = "msg_" + "e" * 64 if field == "message_id" else ref(999)
            call["raw_base64"] = base64.b64encode(canonical(value)).decode()
            calls.append(call); expected.append("repair_invalid_history")
        call = packed_inputs("mailbox_member")
        raw = bytearray(base64.b64decode(call["packs"][0]["raw_base64"])); raw[-1] ^= 1
        call["packs"][0]["raw_base64"] = base64.b64encode(raw).decode()
        calls.append(call); expected.append("repair_ref_mismatch")
        results = self.ts(calls)
        for call, result, code in zip(calls, results, expected):
            with self.subTest(code=code, variant=json.loads(base64.b64decode(call["raw_base64"]))["variant"]):
                self.assertFalse(result["ok"], result); self.assertEqual(result["code"], code)
                with self.assertRaises(Exception) as error:
                    self.python_inputs(call)
                self.assertEqual(error.exception.code, code)

    def test_resolver_uses_real_local_storage_and_cumulative_budget(self):
        call = packed_inputs("ack_occupied_inputs"); call["override"] = True
        result = self.ts([call])[0]
        self.assertTrue(result["ok"], result); self.assertEqual(result["overrideCalls"], 0)
        calls = [{**packed_inputs("mailbox_member"), "fake": fake} for fake in ("proxy", "subclass", "object", "budget")]
        calls.append({**packed_inputs("ack_occupied_inputs"), "policy": {**POLICY, "max_hashes": 3}})
        results = self.ts(calls)
        self.assertEqual([row["code"] for row in results], ["repair_invalid_policy"] * 4 + ["repair_over_budget"])
        self.assertEqual(results[-1]["work"]["hashes"], 3)

    def test_feed_subtree_and_parent_refs_require_exact_packed_range_index_roles(self):
        call = packed_inputs("mailbox_feed")
        good = self.ts([call])[0]
        self.assertTrue(good["ok"], good)
        value = json.loads(base64.b64decode(call["raw_base64"]))
        # The covered subtree includes a descendant beyond root + parents.
        self.assertEqual(len([row for row in value["roles"] if row["role"] == "range.index"]), 3)
        self.assertEqual(len(value["subtree"]["parent_path_refs"]), 1)
        cases = []
        for target in ("root", "parent"):
            for mutation in ("missing", "wrong_role", "wrong_ref"):
                changed = copy.deepcopy(value)
                wanted = changed["subtree"]["root_ref"] if target == "root" else changed["subtree"]["parent_path_refs"][0]
                if mutation == "wrong_ref":
                    if target == "root": changed["subtree"]["root_ref"] = ref(999)
                    else: changed["subtree"]["parent_path_refs"][0] = ref(999)
                else:
                    row = next(row for row in changed["roles"] if row["role"] == "range.index" and row["document_ref"] == wanted)
                    if mutation == "missing": changed["roles"].remove(row)
                    else: row["role"] = "range.repair_page"
                    changed["roles"].sort(key=lambda row: (row["role"], row["document_ref"]["namespace"],
                                                        row["document_ref"]["key"], row["document_ref"]["raw_sha256"], row["document_ref"]["size"]))
                cases.append((target + "/" + mutation, {**call, "raw_base64": base64.b64encode(canonical(changed)).decode()}))
        for (label, changed), result in zip(cases, self.ts([item for _, item in cases])):
            with self.subTest(case=label):
                self.assertFalse(result["ok"], result)
                self.assertEqual(result["code"], "repair_invalid_history")
                with self.assertRaises(Exception) as error:
                    self.python_inputs(changed)
                self.assertEqual(error.exception.code, "repair_invalid_history")


if __name__ == "__main__":
    unittest.main()
