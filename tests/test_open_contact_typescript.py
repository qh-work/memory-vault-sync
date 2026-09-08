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
from tests import test_open_contact_state as state_fixture


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


class ContactNativePollTests(unittest.TestCase):
    """Real native admission and bounded current-policy reads across restart."""

    @classmethod
    def setUpClass(cls):
        state_fixture.ContactNativeStateTests.setUpClass.__func__(cls)

    setUp = state_fixture.ContactStateTests.setUp
    call = state_fixture.ContactStateTests.call
    allocate = state_fixture.ContactStateTests.allocate
    make_policy = state_fixture.ContactStateTests.make_policy
    request = state_fixture.ContactStateTests.request
    decision = state_fixture.ContactStateTests.decision
    native = state_fixture.ContactNativeStateTests.native
    event = state_fixture.ContactNativeStateTests.event
    value = state_fixture.ContactNativeStateTests.value

    def revision_queue(self):
        self.b = state_fixture.Identity.generate(self.root / "native_revision_owner.json")
        self.b_enc = state_fixture.EncryptionIdentity.generate()
        self.lease = self.value(self.event(self.b, "lease", {
            "encryption_key": self.b_enc.public_descriptor(), "purpose": "knock",
            "max_items": 8, "max_bytes": 8 * state_fixture.SLOT_BYTES,
            "lease_seconds": 600, "allocation_id": "native_revision_knock"}))["lease"]
        self.put_revision(1)

    def put_revision(self, revision, *, status="active"):
        self.policy = self.make_policy(revision=revision, status=status)
        self.value(self.event(self.b, "policy.put", {"lease": self.lease, "policy": self.policy}))

    def admission(self, request_id, *, submit=True):
        signer = state_fixture.Identity.generate(self.root / (request_id + ".json"))
        encryption = state_fixture.EncryptionIdentity.generate()
        request = self.request(request_id=request_id, signer=signer, encryption=encryption)
        challenge = self.value(self.event(signer, "challenge", {"request": request, "purpose": "submit"}))["challenge"]
        proof = {"request": request, "challenge": challenge, "answer": solve_challenge(challenge,
            request=request, node=self.node, purpose="submit", encryption_identity=encryption, now=self.now)}
        if submit:
            self.assertEqual(self.value(self.event(signer, "submit", proof))["state"], "contact_queued")
        return request, signer, proof

    def rows(self):
        return [tuple(row) for row in self.db.execute(
            "SELECT * FROM open_contact_requests WHERE lease_id=? ORDER BY request_id,sender",
            (self.lease["payload"]["lease_id"],))]

    def poll_event(self):
        return self.event(self.b, "poll", {"lease_id": self.lease["payload"]["lease_id"]})

    def test_native_current_policy_filters_before_limit_and_preserves_old_evidence(self):
        self.revision_queue()
        old = [self.admission("a_old_" + str(index)) for index in range(4)]
        old_rows = self.rows()
        # Exact submit replay still works before the policy changes.
        self.value(self.event(old[0][1], "submit", old[0][2]))
        self.assertEqual(self.rows(), old_rows)
        self.put_revision(2)
        current, _, _ = self.admission("z_current")
        before = self.rows()
        results = self.native([self.poll_event(), {"op": "reopen"}, self.poll_event()])
        for result in (results[0], results[2]):
            self.assertEqual(result, {"ok": True, "value": {"requests": [current]}})
            self.assertLessEqual(len(canonical_bytes(result["value"]["requests"])), 16 * 1024)
        self.assertEqual(self.rows(), before)
        self.assertEqual(before[:4], old_rows)
        self.assertEqual(len(before), 5)
        delivery = self.value(self.event(self.b, "lease", {"encryption_key": self.b_enc.public_descriptor(),
            "purpose": "delivery", "max_items": 1, "max_bytes": 8192,
            "lease_seconds": 600, "allocation_id": "native_stale_decision"}))["lease"]
        stale = self.native([self.event(self.b, "decide", {"request": old[0][0],
            "decision": self.decision(old[0][0], delivery=delivery)}), self.event(old[0][1], "submit", old[0][2])])
        self.assertEqual(stale, [{"ok": False, "code": "contact_request_mismatch"}] * 2)
        self.assertEqual(self.rows(), before)
        self.assertIsNone(self.db.execute("SELECT grant_request FROM open_contact_resource_leases WHERE lease_id=?",
            (delivery["payload"]["lease_id"],)).fetchone()[0])

        # Retained stale rows still charge the eight-slot lease. Poll neither
        # releases quota nor removes the current response's four-item cap.
        more = [self.admission("z_current_" + str(index))[0] for index in range(3)]
        self.assertEqual(self.value(self.poll_event()), {"requests": [current, *more]})
        stranger = state_fixture.Identity.generate(self.root / "native_overflow.json")
        overflow = self.request(request_id="z_overflow", signer=stranger)
        self.assertEqual(self.native([self.event(stranger, "challenge", {"request": overflow, "purpose": "submit"})])[0],
            {"ok": False, "code": "contact_capacity"})
        self.assertEqual(len(self.rows()), 8)

    def test_native_policy_update_interleaves_poll_and_challenge_without_reviving_old_requests(self):
        self.revision_queue()
        old, _, _ = self.admission("a_old")
        _, sender, proof = self.admission("a_inflight", submit=False)
        self.policy = self.make_policy(revision=2)
        results = self.native([self.poll_event(), self.event(self.b, "policy.put", {"lease": self.lease, "policy": self.policy}),
            self.poll_event(), {"op": "reopen"}, self.poll_event(), self.event(sender, "submit", proof)])
        self.assertEqual(results[0], {"ok": True, "value": {"requests": [old]}})
        for index in (2, 4):
            self.assertEqual(results[index], {"ok": True, "value": {"requests": []}})
        self.assertEqual(results[5], {"ok": False, "code": "contact_request_mismatch"})
        current, _, _ = self.admission("z_current")
        self.assertEqual(self.value(self.poll_event()), {"requests": [current]})
        before = self.rows()
        self.put_revision(3)
        self.assertEqual(self.value(self.poll_event()), {"requests": []})
        self.assertEqual(self.rows(), before)
        self.put_revision(4, status="revoked")
        results = self.native([{"op": "revoke", "lease_id": self.lease["payload"]["lease_id"]},
            {"op": "reopen"}, self.poll_event()])
        self.assertEqual(results[2], {"ok": False, "code": "contact_lease_revoked"})
        self.assertEqual(self.rows(), before)

    def test_native_poll_four_item_cap_and_expired_rows_keep_retention(self):
        self.revision_queue()
        requests = [self.admission("current_" + str(index))[0] for index in range(5)]
        response = self.value(self.poll_event())
        self.assertEqual(response, {"requests": requests[:4]})
        self.assertLessEqual(len(canonical_bytes(response["requests"])), 16 * 1024)
        before = self.rows()
        self.now += 401  # Requests expired; their expires+30 evidence is live.
        self.assertEqual(self.value(self.poll_event()), {"requests": []})
        self.assertEqual(self.rows(), before)


if __name__ == "__main__":
    unittest.main()
