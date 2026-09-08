"""Real Python/native TypeScript first-contact protocol interoperability.

Only ephemeral synthetic keys/documents and already installed locked JOSE.
The native driver denies subprocess delegation before importing product code.
These are protocol/runtime checks, not network or global-scale acceptance.
"""
import base64
import copy
import hashlib
import json
import subprocess
import unittest

from memory_vault import MemoryError, canonical_bytes
from memory_vault_network_crypto import unb64url
from memory_vault_open_contact import (
    MAX_REQUEST_BYTES, issue_challenge, sign_response, sign_rpc, solve_challenge,
    verify_challenge, verify_document, verify_policy, verify_request,
    verify_response, verify_rpc,
)
from tests import test_network_typescript_agent_network as ts_runtime
from tests import test_open_contact as py_fixture


DRIVER = r"""
import child from 'node:child_process';
import {syncBuiltinESMExports} from 'node:module';
let subprocessCalls=0;
const deny=()=>{subprocessCalls++;throw Error('native contact cannot delegate');};
for(const name of ['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork'])child[name]=deny;
syncBuiltinESMExports();
const c=await import('./open-contact.ts');
const chunks=[];let size=0;
for await(const chunk of process.stdin){size+=chunk.length;if(size>2097152)throw Error('synthetic fixture limit');chunks.push(chunk);}
const input=JSON.parse(Buffer.concat(chunks).toString('utf8')),results=[];
for(const call of input.calls){
  try{
    const args=call.args??[];
    if(call.raw!==undefined)args.unshift(Buffer.from(call.raw,'base64'));
    results.push({ok:true,value:await c[call.name](...args)});
  }catch(error){results.push({ok:false,code:error.code??'untyped_error',name:error.name});}
}
process.stdout.write(JSON.stringify({results,subprocessCalls}));
"""


class OpenContactTypeScriptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ts_runtime.TypeScriptAgentNetworkTests.setUpClass.__func__(cls)
        (cls.fixture / "driver.mjs").write_text(DRIVER)

    def setUp(self):
        self.py = py_fixture.OpenContactProtocolTests("test_valid_opt_in_request_and_explicit_finite_delivery_decision")
        self.addCleanup(self.py.doCleanups)
        self.py.setUp()
        self.options = dict(node=self.py.node, now=self.py.now)
        self.request_options = dict(**self.options, policy=self.py.policy, lease=self.py.lease)

    def signing_document(self, label):
        return json.loads((self.py.root / ("synthetic_" + label + ".json")).read_text())

    def ts(self, calls):
        process = subprocess.run([self.node, "--experimental-strip-types", str(self.fixture / "driver.mjs")],
            input=json.dumps(dict(calls=calls)).encode(), cwd=self.fixture,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=25)
        self.assertEqual(process.returncode, 0, process.stderr.decode(errors="replace")[-6000:])
        result = json.loads(process.stdout)
        self.assertEqual(result["subprocessCalls"], 0)
        self.assertEqual(len(result["results"]), len(calls))
        return result["results"]

    @staticmethod
    def call(name, *args):
        return dict(name=name, args=list(args))

    def assert_rejections(self, cases):
        """A shared signed input must fail through a typed protocol error in both runtimes."""
        calls = []
        for label, name, value, options, verify in cases:
            with self.subTest(runtime="python", case=label), self.assertRaises(MemoryError):
                verify(value)
            calls.append(self.call(name, value, options))
        for case, result in zip(cases, self.ts(calls)):
            with self.subTest(runtime="typescript", case=case[0]):
                self.assertFalse(result["ok"], result)
                self.assertNotEqual(result["code"], "untyped_error", result)

    def test_all_signed_documents_verify_and_serialize_identically(self):
        h = self.py
        challenge, _ = issue_challenge(h.server, request=h.request, node=h.node, purpose="submit", now=h.now)
        rpc = sign_rpc(h.sender, node=h.node, action="policy.get",
                       body=dict(recipient_key_id=h.recipient.key_id), now=h.now)
        response = sign_response(h.server, request=rpc, node=h.node,
                                 body=dict(lease=h.lease, policy=h.policy), now=h.now)
        documents = [(h.lease, "node"), (h.policy, "recipient"), (h.request, "sender"),
                     (challenge, "node"), (h.make_grant(), "recipient"),
                     (h.make_decision(), "recipient"), (h.make_decision(False), "recipient"),
                     (rpc, "sender"), (response, "node")]
        calls = []
        for value, signer in documents:
            payload = value["payload"]
            options = {key: item for key, item in payload.items()
                       if key not in {"schema_version", "kind", "signing_key"}}
            calls.append(self.call("verifyDocument", value, payload["kind"], dict(now=h.now)))
            calls.append(self.call("signDocument", self.signing_document(signer), payload["kind"], options))
        results = self.ts(calls)
        for index, (value, _) in enumerate(documents):
            with self.subTest(kind=value["payload"]["kind"]):
                checked, signed = results[index * 2:index * 2 + 2]
                self.assertTrue(checked["ok"], checked)
                self.assertTrue(signed["ok"], signed)
                self.assertEqual(canonical_bytes(checked["value"]), canonical_bytes(value["payload"]))
                self.assertEqual(canonical_bytes(signed["value"]), canonical_bytes(value))
                verify_document(signed["value"], value["payload"]["kind"], now=h.now)

    def test_bidirectional_real_jwe_and_fresh_challenges_for_both_purposes(self):
        h = self.py
        for purpose in ("submit", "result"):
            options = dict(**self.options, request=h.request, purpose=purpose)
            challenge, expected = issue_challenge(h.server, request=h.request, node=h.node, purpose=purpose, now=h.now)
            calls = [self.call("solveChallenge", challenge,
                              dict(**options, encryption_identity=h.sender_encryption.private_document())),
                     self.call("issueChallenge", self.signing_document("node"), options),
                     self.call("issueChallenge", self.signing_document("node"), options)]
            solved, issued, second = self.ts(calls)
            with self.subTest(purpose=purpose):
                for result in (solved, issued, second):
                    self.assertTrue(result["ok"], result)
                self.assertEqual(hashlib.sha256(unb64url(solved["value"], maximum=32, size=32)).hexdigest(), expected)
                native, native_hash = issued["value"]
                verify_challenge(native, request=h.request, node=h.node, purpose=purpose, now=h.now)
                answer = solve_challenge(native, request=h.request, node=h.node, purpose=purpose,
                                         encryption_identity=h.sender_encryption, now=h.now)
                self.assertEqual(hashlib.sha256(unb64url(answer, maximum=32, size=32)).hexdigest(), native_hash)
                self.assertNotEqual(native["payload"]["challenge_id"], second["value"][0]["payload"]["challenge_id"])
                self.assertNotEqual(native_hash, second["value"][1])

    def test_both_runtimes_reject_wrong_challenge_key_purpose_request_and_expiry(self):
        h = self.py
        challenge, _ = issue_challenge(h.server, request=h.request, node=h.node, purpose="submit", now=h.now)
        normal = dict(**self.options, request=h.request, purpose="submit",
                      encryption_identity=h.sender_encryption.private_document())
        cases = []
        for label, changed in [("wrong_key", dict(encryption_identity=h.other_encryption.private_document())),
                               ("wrong_purpose", dict(purpose="result")),
                               ("wrong_request", dict(request=h.make_request(request_id="other"))),
                               ("expired", dict(now=h.now + 60))]:
            options = {**normal, **changed}
            python_options = {**options, "encryption_identity": h.other_encryption if label == "wrong_key" else h.sender_encryption}
            cases.append((label, "solveChallenge", challenge, options,
                          lambda value, options=python_options: solve_challenge(value, **options)))
        rebound = h.changed(challenge, h.server, purpose="result")
        rebound_options = {**normal, "purpose": "result"}
        cases.append(("jwe_context_rebind", "solveChallenge", rebound, rebound_options,
                      lambda value: solve_challenge(value, request=h.request, node=h.node, purpose="result",
                          encryption_identity=h.sender_encryption, now=h.now)))
        self.assert_rejections(cases)

    def test_shared_request_schema_and_authorization_binding_negatives(self):
        h = self.py
        mutations = [("text", "synthetic forbidden"), ("payload", {}), ("request_class", []),
                     ("request_class", "__proto__"), ("request_class", "message\n"),
                     ("issued_at", True), ("expires_at", h.now), ("issued_at", h.now + 31),
                     ("request_id", "*"), ("request_id", "x" * 129), ("resource_id", False),
                     ("recipient_key_id", h.other.key_id), ("recipient_encryption_key_id", h.other_encryption.key_id),
                     ("policy_sha256", "f" * 64), ("node_key_id", h.other.key_id), ("storage_epoch", "other"),
                     ("kind", {}), ("schema_version", "wrong/v1")]
        cases = []
        for field, value in mutations:
            malformed = h.changed(h.request, h.sender, **{field: value})
            cases.append((str((field, value)), "verifyRequest", malformed, self.request_options, h.verify_request))
        self.assert_rejections(cases)
        # Unsafe integers and floats are invalid before the signature layer.
        for number in (9_007_199_254_740_992, 2.5):
            malformed = copy.deepcopy(h.request)
            malformed["payload"]["issued_at"] = number
            self.assert_rejections([(str(number), "verifyRequest", malformed, self.request_options, h.verify_request)])

    def test_shared_finite_grant_lease_and_policy_negative_controls(self):
        h = self.py
        cases = []
        grant = h.make_grant()
        for field, value in [("operations", ["*"]), ("operations", ["memory.remember"]),
                             ("resource_id", "*"), ("resource_id", "other"),
                             ("expires_at", h.now + 601), ("resource_lease", h.lease)]:
            changed = h.changed(grant, h.recipient, **{field: value})
            cases.append(("grant " + field, "verifyDocument", changed, "contact.grant",
                          lambda value: verify_document(value, "contact.grant", now=h.now)))
        # verifyDocument has a third options argument; call it directly here.
        calls = []
        for label, name, value, kind, verify in cases:
            with self.subTest(case=label), self.assertRaises(MemoryError):
                verify(value)
            calls.append(self.call(name, value, kind, dict(now=h.now)))
        for result in self.ts(calls):
            self.assertFalse(result["ok"], result)
            self.assertNotEqual(result["code"], "untyped_error", result)
        cases = []
        for field, value in [("revision", True), ("max_pending", 3), ("status", "active\n"),
                             ("lease_sha256", "f" * 64), ("encryption_key", h.other_encryption.public_descriptor())]:
            changed = h.changed(h.policy, h.recipient, **{field: value})
            cases.append(("policy " + field, "verifyPolicy", changed,
                          dict(**self.options, lease=h.lease),
                          lambda value: verify_policy(value, lease=h.lease, node=h.node, now=h.now)))
        self.assert_rejections(cases)

    def test_result_response_shared_rejection_of_signed_decision_swap(self):
        h = self.py
        rpc = h.result_rpc()
        original = h.make_decision(False)
        response = sign_response(h.server, request=rpc, node=h.node,
                                 body=dict(state="rejected", decision=original), now=h.now)
        options = dict(**self.options, request=rpc)
        valid = self.ts([self.call("verifyResponse", response, options)])[0]
        self.assertTrue(valid["ok"], valid)
        cases = []
        fields = dict(request_id="other", request_sha256="f" * 64, subject_key_id=h.other.key_id,
                      subject_encryption_key_id=h.other_encryption.key_id,
                      recipient_encryption_key_id=h.other_encryption.key_id, node_key_id=h.other.key_id,
                      storage_epoch="other", policy_sha256="f" * 64, expires_at=h.now + 601)
        for field, value in fields.items():
            changed = h.changed(original, h.recipient, **{field: value})
            swapped = h.changed(response, h.server, body=dict(state="rejected", decision=changed))
            cases.append((field, "verifyResponse", swapped, options,
                          lambda value: verify_response(value, request=rpc, node=h.node, now=h.now)))
        changed = h.changed(original, h.other, signing_key=h.other.public_descriptor())
        cases.append(("wrong_recipient_signer", "verifyResponse",
                      h.changed(response, h.server, body=dict(state="rejected", decision=changed)), options,
                      lambda value: verify_response(value, request=rpc, node=h.node, now=h.now)))
        self.assert_rejections(cases)

    def test_shared_rpc_invalid_enums_and_exact_policy_response_state(self):
        h = self.py
        rpc = sign_rpc(h.sender, node=h.node, action="challenge",
                       body=dict(request=h.request, purpose="submit"), now=h.now)
        cases = []
        for value in ("unknown", "__proto__", "toString", [], {}, True, None, "submit\n"):
            for field in ("action", "purpose"):
                changes = dict(action=value) if field == "action" else dict(body=dict(request=h.request, purpose=value))
                cases.append((str((field, value)), "verifyRpc", h.changed(rpc, h.sender, **changes), self.options,
                              lambda value: verify_rpc(value, node=h.node, now=h.now)))
        self.assert_rejections(cases)
        put = sign_rpc(h.recipient, node=h.node, action="policy.put",
                       body=dict(lease=h.lease, policy=h.policy), now=h.now)
        response = sign_response(h.server, request=put, node=h.node, body=dict(state="revoked"), now=h.now)
        self.assert_rejections([("opposite_policy_state", "verifyResponse", response, dict(**self.options, request=put),
                                lambda value: verify_response(value, request=put, node=h.node, now=h.now))])

    def test_strict_raw_json_duplicates_oversize_and_invalid_proofs(self):
        h = self.py
        encoded = canonical_bytes(h.request)
        raws = [b'{"payload":{},' + encoded[1:], encoded + b" " * MAX_REQUEST_BYTES]
        calls = []
        for raw in raws:
            with self.assertRaises(MemoryError):
                verify_request(raw, **self.request_options)
            calls.append(dict(name="verifyRequest", raw=base64.b64encode(raw).decode(), args=[self.request_options]))
        for result in self.ts(calls):
            self.assertFalse(result["ok"], result)
            self.assertNotEqual(result["code"], "untyped_error", result)
        wrong = copy.deepcopy(h.request)
        wrong["proof"] = h.other.sign_message(wrong["payload"])
        self.assert_rejections([("wrong_proof", "verifyRequest", wrong, self.request_options, h.verify_request)])

    def test_resource_cannot_extend_requester_lease_duration_in_either_runtime(self):
        h = self.py
        body = dict(encryption_key=h.recipient_encryption.public_descriptor(), purpose="knock",
                    max_items=2, max_bytes=h.lease["payload"]["max_bytes"],
                    lease_seconds=1, allocation_id="synthetic_one_second")
        rpc = sign_rpc(h.recipient, node=h.node, action="lease", body=body, now=h.now)
        response = sign_response(h.server, request=rpc, node=h.node, body=dict(lease=h.lease), now=h.now)
        self.assert_rejections([("lease_extension", "verifyResponse", response, dict(**self.options, request=rpc),
                                lambda value: verify_response(value, request=rpc, node=h.node, now=h.now))])


if __name__ == "__main__":
    unittest.main()
