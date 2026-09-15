"""Real Python/native provider wire and target-possession interoperability.

Synthetic keys and the already installed locked JOSE runtime only. This verifies
protocol parity, not ciphertext custody, provider HTTP service or global repair.
"""
import base64
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from memory_vault import MemoryError, canonical_bytes
from memory_vault_trust import Identity
from memory_vault_network_crypto import EncryptionIdentity, document_sha256
from memory_vault_open_control import issue_node
import memory_vault_open_provider as provider
from tests import test_network_typescript_agent_network as ts_runtime


DRIVER = r"""
import child from 'node:child_process';
import {syncBuiltinESMExports} from 'node:module';
let subprocessCalls=0;
const deny=()=>{subprocessCalls++;throw Error('native provider cannot delegate');};
for(const name of ['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork'])child[name]=deny;
syncBuiltinESMExports();
const provider=await import('./open-provider.ts'),chunks=[];let size=0;
for await(const chunk of process.stdin){size+=chunk.length;if(size>2097152)throw Error('synthetic fixture limit');chunks.push(chunk);}
const results=[];
for(const call of JSON.parse(Buffer.concat(chunks).toString('utf8'))){
  try{
    if(call.name==='verifyTargetAnswer')call.args[1].nonce=Buffer.from(call.args[1].nonce,'base64');
    const value=await provider[call.name](...call.args);
    results.push({ok:true,value:call.name==='makeTargetChallenge'?
      {challenge:value[0],nonce:Buffer.from(value[1]).toString('base64')}:value});
  }catch(error){results.push({ok:false,code:error.code??'untyped_error'});}
}
process.stdout.write(JSON.stringify({results,subprocessCalls}));
"""


class OpenProviderTypeScriptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ts_runtime.TypeScriptAgentNetworkTests.setUpClass.__func__(cls)
        (cls.fixture / "driver.mjs").write_text(DRIVER)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="memory-vault-provider-wire-synthetic-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.server = Identity.generate(self.root / "node.json")
        self.owner = Identity.generate(self.root / "owner.json")
        self.encryption = EncryptionIdentity.generate()
        self.owner_encryption = EncryptionIdentity.generate()
        self.signers = {name: json.loads((self.root / (name + ".json")).read_text())
                        for name in ("node", "owner")}
        self.now = 2_000_000_000
        self.node = issue_node(self.server, base_url="http://127.0.0.1:18501",
            storage_epoch="synthetic_epoch", roles=["directory", "router"],
            revision=1, issued_at=self.now, expires_at=self.now + 3600)
        subject = dict(signing_key=self.owner.public_descriptor(),
                       encryption_key=self.owner_encryption.public_descriptor())
        self.root_key = dict(owner=provider.as_dual(subject), root_kind="mailbox",
            anchor_ref=dict(namespace="anchor", key="a" * 64),
            owner_epoch="synthetic_owner_epoch", root_id="synthetic_root")
        self.ref = dict(namespace="object", key="b" * 64)
        self.target = self.sign(self.server, "provider.target",
            node_key_id=self.server.key_id, storage_epoch="synthetic_epoch",
            targetEncryptionKey=self.encryption.public_descriptor())
        budget = dict(max_live_bytes=0, max_meta_bytes=98304, max_items=1,
            max_requests=8, max_pending=1, max_replay_records=8, max_jobs=0, max_job_bytes=0)
        windows = {name: self.now + 600 for name in provider.WINDOWS}
        self.intent = self.sign(self.owner, "root.resource.intent",
            allocation_id="synthetic_allocation", root_key=self.root_key, subject=subject,
            node_key_id=self.server.key_id, storage_epoch="synthetic_epoch",
            purpose="provider_index", budget=budget, windows=windows)
        self.lease = self.sign(self.server, "root.resource.lease",
            allocation_id="synthetic_allocation", intent_sha256=document_sha256(self.intent),
            root_key=self.root_key, subject=provider.as_dual(subject),
            resource=dict(node_key_id=self.server.key_id, storage_epoch="synthetic_epoch",
                          lease_id="synthetic_lease", resource_id="synthetic_resource"),
            targetEncryptionKey=self.encryption.public_descriptor(), reservation_generation=1,
            purpose="provider_index", budget=budget, windows=windows)
        self.grant = self.sign(self.owner, "provider.publication.grant",
            root_key=self.root_key, resource=self.lease["payload"]["resource"],
            resource_lease_sha256=document_sha256(self.lease),
            publisher=dict(signing_key_id=self.server.key_id, encryption_key_id=self.encryption.key_id),
            ref=self.ref, grant_id="synthetic_grant", revision=1,
            operation_mask=provider.PUBLISH, maximum_fact_seconds=600)
        self.fact = provider.issue_fact(self.server, ref=self.ref, storage_epoch="synthetic_epoch",
            custody_id="synthetic_custody", revision=1, issued_at=self.now, expires_at=self.now + 300)
        self.index = self.sign(self.server, "provider.index_lease", expires_at=self.now + 180,
            node_key_id=self.server.key_id, storage_epoch="synthetic_epoch", index_lease_id="synthetic_index",
            fact_sha256=document_sha256(self.fact), ref=self.ref, provider_key_id=self.server.key_id,
            provider_storage_epoch="synthetic_epoch", custody_id="synthetic_custody")
        self.status = provider.issue_status(self.owner, root=self.root_key, revision=1,
            entries=[dict(scope_kind="authority", scope_id=provider.authority_scope(
                self.root_key, "provider.publication.grant", document_sha256(self.grant)),
                minimum_document_revision=1, status="active", operation_mask=provider.PUBLISH)],
            issued_at=self.now, valid_until=self.now + 600)
        self.challenge, self.nonce = provider.make_target_challenge(self.owner,
            target=self.target, node=self.node, now=self.now)
        self.answer = provider.answer_target_challenge(self.server, self.encryption,
            target=self.target, challenge=self.challenge, node=self.node, now=self.now)
        self.rpc = provider.sign_rpc(self.owner, node=self.node, action="target.get",
            body={}, now=self.now, request_id="synthetic_rpc")
        self.response = provider.sign_response(self.server, request=self.rpc,
            node=self.node, body=dict(target=self.target), now=self.now)

    def sign(self, signer, kind, **values):
        options = dict(issued_at=self.now, expires_at=self.now + 600)
        options.update(values)
        return provider.sign_document(signer, kind, **options)

    @staticmethod
    def call(name, *args):
        return dict(name=name, args=list(args))

    def ts(self, calls):
        run = subprocess.run([self.node_runtime, "--experimental-strip-types", str(self.fixture / "driver.mjs")],
            input=json.dumps(calls).encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=30, cwd=self.fixture)
        self.assertEqual(run.returncode, 0, run.stderr.decode(errors="replace")[-6000:])
        result = json.loads(run.stdout)
        self.assertEqual(result["subprocessCalls"], 0)
        self.assertEqual(len(result["results"]), len(calls))
        return result["results"]

    @property
    def node_runtime(self):
        # self.node is the signed fixture descriptor; the runtime belongs to the class.
        return type(self).node

    def test_all_signed_kinds_and_owner_status_are_byte_identical(self):
        documents = [(self.fact, "node"), (self.target, "node"), (self.challenge, "owner"),
            (self.answer, "node"), (self.intent, "owner"), (self.lease, "node"),
            (self.grant, "owner"), (self.index, "node"), (self.rpc, "owner"), (self.response, "node")]
        self.assertEqual({value["payload"]["kind"] for value, _ in documents}, set(provider.KINDS))
        calls = []
        for value, signer in documents:
            payload = value["payload"]
            options = {key: item for key, item in payload.items()
                       if key not in {"schema_version", "kind", "signing_key"}}
            calls.extend([self.call("verifyDocument", value, payload["kind"], dict(now=self.now)),
                          self.call("signDocument", self.signers[signer], payload["kind"], options)])
        results = self.ts(calls)
        for (value, _), read, signed in zip(documents, results[::2], results[1::2]):
            with self.subTest(kind=value["payload"]["kind"]):
                self.assertTrue(read["ok"], read)
                self.assertTrue(signed["ok"], signed)
                self.assertEqual(canonical_bytes(read["value"]), canonical_bytes(value["payload"]))
                self.assertEqual(canonical_bytes(signed["value"]), canonical_bytes(value))
                provider.verify_document(signed["value"], value["payload"]["kind"], now=self.now)
        results = self.ts([self.call("verifyStatus", self.status, dict(now=self.now)),
            self.call("issueStatus", self.signers["owner"], dict(root=self.root_key, revision=1,
                entries=self.status["payload"]["entries"], issued_at=self.now, valid_until=self.now + 600))])
        for value in results:
            self.assertTrue(value["ok"], value)
        self.assertEqual(canonical_bytes(results[0]["value"]), canonical_bytes(self.status["payload"]))
        self.assertEqual(canonical_bytes(results[1]["value"]), canonical_bytes(self.status))

    def test_leases_response_and_scope_hashes_match_python(self):
        checks = [
            ("verifyResourceLease", (self.lease, dict(intent=self.intent, target=self.target, node=self.node, now=self.now)), self.lease["payload"]),
            ("verifyIndexLease", (self.index, dict(fact=self.fact, node=self.node, now=self.now)), self.index["payload"]),
            ("verifyResponse", (self.response, dict(request=self.rpc, node=self.node, now=self.now)), self.response["payload"]),
            ("routeTarget", (self.ref,), provider.route_target(self.ref)),
            ("authorityScope", (self.root_key, "provider.publication.grant", document_sha256(self.grant)),
                provider.authority_scope(self.root_key, "provider.publication.grant", document_sha256(self.grant))),
            ("resourceScope", (self.root_key, self.lease["payload"]["resource"]),
                provider.resource_scope(self.root_key, self.lease["payload"]["resource"])),
        ]
        for (name, _, expected), result in zip(checks, self.ts([self.call(name, *args) for name, args, _ in checks])):
            with self.subTest(check=name):
                self.assertTrue(result["ok"], result)
                self.assertEqual(result["value"], expected)

    def test_real_bidirectional_x25519_target_proof_and_wrong_nonce(self):
        results = self.ts([
            self.call("answerTargetChallenge", self.signers["node"], self.encryption.private_document(),
                dict(target=self.target, challenge=self.challenge, node=self.node, now=self.now)),
            self.call("makeTargetChallenge", self.signers["owner"], dict(target=self.target, node=self.node, now=self.now)),
        ])
        for result in results:
            self.assertTrue(result["ok"], result)
        provider.verify_target_answer(results[0]["value"], target=self.target, challenge=self.challenge,
            nonce=self.nonce, node=self.node, now=self.now)
        native = results[1]["value"]
        answer = provider.answer_target_challenge(self.server, self.encryption,
            target=self.target, challenge=native["challenge"], node=self.node, now=self.now)
        options = dict(target=self.target, challenge=native["challenge"], nonce=native["nonce"], node=self.node, now=self.now)
        passed, refused = self.ts([self.call("verifyTargetAnswer", answer, options),
            self.call("verifyTargetAnswer", answer, {**options, "nonce": base64.b64encode(b"\0" * 32).decode()})])
        self.assertTrue(passed["ok"], passed)
        self.assertEqual(passed["value"], self.target["payload"])
        with self.assertRaises(MemoryError) as rejected:
            provider.verify_target_answer(answer, target=self.target, challenge=native["challenge"],
                nonce=b"\0" * 32, node=self.node, now=self.now)
        self.assertEqual(refused, dict(ok=False, code=rejected.exception.code))
        self.assertNotEqual(base64.b64decode(native["nonce"]), self.nonce)

    def test_dual_keys_and_destination_resource_bindings_fail_closed(self):
        cases = []
        wrong_subject = copy.deepcopy(self.intent)
        wrong_subject["payload"]["subject"]["encryption_key"] = self.encryption.public_descriptor()
        wrong_subject["proof"] = self.owner.sign_message(wrong_subject["payload"])
        with self.assertRaises(MemoryError) as rejected:
            provider.verify_document(wrong_subject, "root.resource.intent", now=self.now)
        cases.append(("owner_encryption", self.call("verifyDocument", wrong_subject,
            "root.resource.intent", dict(now=self.now)), rejected.exception.code))
        options = dict(intent=self.intent, target=self.target, node=self.node, now=self.now)
        for field, replacement in (("targetEncryptionKey", self.owner_encryption.public_descriptor()),
                                   ("intent_sha256", "c" * 64),
                                   ("resource", {**self.lease["payload"]["resource"], "storage_epoch": "other_epoch"})):
            wrong_lease = copy.deepcopy(self.lease)
            wrong_lease["payload"][field] = replacement
            wrong_lease["proof"] = self.server.sign_message(wrong_lease["payload"])
            with self.subTest(runtime="python", binding=field), self.assertRaises(MemoryError) as rejected:
                provider.verify_resource_lease(wrong_lease, **options)
            cases.append((field, self.call("verifyResourceLease", wrong_lease, options), rejected.exception.code))
        for (label, _, expected), result in zip(cases, self.ts([case[1] for case in cases])):
            with self.subTest(runtime="typescript", binding=label):
                self.assertEqual(result, dict(ok=False, code=expected))

    def test_invalid_proofs_status_budget_and_time_fail_like_python(self):
        negatives = []

        def negative(label, value, name, args, check):
            with self.subTest(runtime="python", case=label), self.assertRaises(MemoryError) as rejected:
                check()
            negatives.append((label, self.call(name, value, *args), rejected.exception.code))

        for change in ("digest", "schema", "signature", "unknown"):
            bad = copy.deepcopy(self.fact)
            if change == "digest":
                bad["payload"]["revision"] = 2
            elif change == "schema":
                bad["proof"]["schema_version"] = "wrong"
            elif change == "signature":
                bad["proof"]["signature"] = base64.b64encode(b"\0" * 64).decode()
            else:
                bad["proof"]["extra"] = "wrong"
            negative(change, bad, "verifyDocument", ("provider.fact", dict(now=self.now)),
                     lambda: provider.verify_document(bad, "provider.fact", now=self.now))
        bad = copy.deepcopy(self.status)
        bad["payload"]["entries"] *= 2
        bad["proof"] = self.owner.sign_message(bad["payload"])
        negative("duplicate_status", bad, "verifyStatus", (dict(now=self.now),),
                 lambda: provider.verify_status(bad, now=self.now))
        for label, field, value in (("index_live_bytes", "max_live_bytes", 1),
                ("boolean_budget", "max_requests", True), ("excess_budget", "max_requests", 4097)):
            bad = copy.deepcopy(self.intent)
            bad["payload"]["budget"][field] = value
            bad["proof"] = self.owner.sign_message(bad["payload"])
            negative(label, bad, "verifyDocument", ("root.resource.intent", dict(now=self.now)),
                     lambda: provider.verify_document(bad, "root.resource.intent", now=self.now))
        bad = copy.deepcopy(self.intent)
        bad["payload"]["windows"]["publish_until"] = self.now + 601
        bad["proof"] = self.owner.sign_message(bad["payload"])
        negative("window", bad, "verifyDocument", ("root.resource.intent", dict(now=self.now)),
                 lambda: provider.verify_document(bad, "root.resource.intent", now=self.now))
        for label, now in (("expired", self.now + 300), ("future", self.now - 31)):
            negative(label, self.fact, "verifyDocument", ("provider.fact", dict(now=now)),
                     lambda: provider.verify_document(self.fact, "provider.fact", now=now))
        for (label, _, expected), result in zip(negatives, self.ts([row[1] for row in negatives])):
            with self.subTest(runtime="typescript", case=label):
                self.assertEqual(result, dict(ok=False, code=expected))
        # Omission defaults to active; an explicit invalid value is not omission.
        options = dict(ref=self.ref, storage_epoch="synthetic_epoch", custody_id="synthetic_custody",
                       revision=1, issued_at=self.now, expires_at=self.now + 300)
        default, invalid = self.ts([self.call("issueFact", self.signers["node"], options),
            self.call("issueFact", self.signers["node"], {**options, "status": None})])
        self.assertTrue(default["ok"], default)
        self.assertEqual(default["value"], self.fact)
        with self.assertRaises(MemoryError) as rejected:
            provider.issue_fact(self.server, **options, status=None)
        self.assertEqual(invalid, dict(ok=False, code=rejected.exception.code))


if __name__ == "__main__":
    unittest.main()
