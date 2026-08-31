"""Independent TypeScript/Python topic control, using only synthetic identities.

These checks do not exercise an encrypted topic carrier, relay or real model.
No dependency installation, user configuration or network service is used.
"""
from __future__ import annotations

import base64
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from memory_vault import canonical_bytes
from memory_vault_trust import Identity
import memory_vault_network_crypto as crypto
import memory_vault_network_control as control
import memory_vault_topics as topics

ROOT = Path(__file__).resolve().parents[1]
DRIVER = r"""
import * as topics from './topics.ts';
import { NetworkCryptoError } from './crypto.ts';
const chunks=[];let length=0;
for await(const chunk of process.stdin){length+=chunk.length;if(length>24*1024*1024)throw Error('fixture input limit');chunks.push(chunk);}
const capture=operation=>{try{return {ok:true,result:operation()};}catch(error){return {ok:false,error:error instanceof NetworkCryptoError?error.code:'unexpected_error'};}};
const requests=JSON.parse(Buffer.concat(chunks).toString('utf8'));
const results=requests.map(item=>capture(()=>{
  if(item.function==='current'){
    const originalPerformance=globalThis.performance;let ticks=1000000;
    if(item.advance_monotonic_ms!==undefined)Object.defineProperty(globalThis,'performance',{value:{now:()=>ticks},configurable:true});
    try{
    const current=topics.verifyCurrentTopic(item.value,item.options);
    ticks+=item.advance_monotonic_ms??0;
    const receivers=(item.select??[]).map(choice=>capture(()=>topics.topicRecipients(choice.copy?JSON.parse(JSON.stringify(current)):current,{now:choice.now})));
    const publishers=(item.publish??[]).map(choice=>capture(()=>topics.authorizedTopicPublisher(choice.copy?JSON.parse(JSON.stringify(current)):current,choice.member_key_id,{now:choice.now,...(choice.grant_id===undefined?{}:{grant_id:choice.grant_id})})));
    return {current,receivers,publishers,immutable:Object.isFrozen(current)&&Object.isFrozen(current.policy.payload.subscriber_grants)};
    }finally{if(item.advance_monotonic_ms!==undefined)Object.defineProperty(globalThis,'performance',{value:originalPerformance,configurable:true});}
  }
  const args=[...(item.args??[])];
  if(item.raw!==undefined)args[0]=Buffer.from(item.raw,'base64url');
  return topics[item.function](...args);
}));
process.stdout.write(JSON.stringify(results));
"""


class TypeScriptTopicTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.node = os.environ.get("MEMORY_VAULT_NODE") or shutil.which("node")
        if cls.node is None:
            raise unittest.SkipTest("Existing Node >=22.19 required; no installation")
        version = subprocess.check_output([cls.node, "--version"], text=True).strip()
        if tuple(map(int, version.lstrip("v").split(".")[:2])) < (22, 19):
            raise unittest.SkipTest("Existing Node >=22.19 required")
        package = ROOT / "clients/typescript/network/node_modules/jose"
        selected = os.environ.get("MEMORY_VAULT_JOSE_MODULE")
        if selected:
            entry = Path(selected).resolve()
            if entry.parts[-3:] != ("dist", "webapi", "index.js"):
                raise RuntimeError("Expected exact jose/dist/webapi/index.js")
            package = entry.parents[2]
        if not (package / "package.json").is_file():
            raise unittest.SkipTest("Existing locked jose6.2.10 required; no installation")
        metadata = json.loads((package / "package.json").read_bytes())
        if (metadata.get("name"), metadata.get("version")) != ("jose", "6.2.10"):
            raise RuntimeError("Expected locked jose6.2.10")
        cls.temporary = tempfile.TemporaryDirectory(prefix="memory-vault-ts-topics-synthetic-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.fixture = Path(cls.temporary.name)
        for name in ("topics.ts", "crypto.ts", "control.ts", "package.json"):
            shutil.copyfile(ROOT / "clients/typescript/network" / name, cls.fixture / name)
        (cls.fixture / "node_modules").mkdir()
        (cls.fixture / "node_modules/jose").symlink_to(package, target_is_directory=True)
        (cls.fixture / "driver.mjs").write_text(DRIVER)

    @staticmethod
    def signing():
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        return Identity(Ed25519PrivateKey.generate())

    @staticmethod
    def secret(identity):
        from cryptography.hazmat.primitives import serialization
        secret = identity._private_key.private_bytes(serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw, serialization.NoEncryption())
        return {**identity.public_descriptor(), "schema_version": "universal-memory-identity/v1",
                "private_key": base64.b64encode(secret).decode("ascii")}

    def setUp(self):
        self.issuer, self.other_issuer, self.owner, self.subscriber = [self.signing() for _ in range(4)]
        self.now, self.network, self.topic = 2_000_000_000, "synthetic-topic-network", "synthetic-topic-routing"
        self.nonce = "synthetic-topic-fresh-nonce"
        self.issuers = crypto.PublicKeyTrust([self.issuer.public_descriptor(), self.other_issuer.public_descriptor()])
        self.options = {"network_id": self.network, "topic_id": self.topic,
            "issuer_key_id": self.issuer.key_id, "issuers": [self.issuer.public_descriptor(), self.other_issuer.public_descriptor()],
            "now": self.now}
        self.members = [{"signing_key": identity.public_descriptor(),
            "encryption_key": crypto.EncryptionIdentity.generate().public_descriptor(),
            "scope": ["receive", "send"], "status": "active"} for identity in (self.owner, self.subscriber)]
        self.roster = control.issue_roster(self.issuer, network_id=self.network, version=1, previous_sha256="0" * 64,
            members=self.members, issued_at=self.now - 10, expires_at=self.now + 290)
        self.policy = self.make_policy()
        self.change = self.make_change()
        self.snapshot = self.make_snapshot()

    def signed(self, payload, signer=None):
        return {"payload": payload, "proof": (signer or self.issuer).sign_message(payload)}

    def run_ts(self, *requests):
        result = subprocess.run([self.node, "--experimental-strip-types", str(self.fixture / "driver.mjs")],
            input=json.dumps(requests).encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=self.fixture, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace")[-2000:])
        output = json.loads(result.stdout)
        self.assertEqual(len(output), len(requests))
        return output

    def success(self, function, *args):
        result, = self.run_ts({"function": function, "args": args})
        self.assertTrue(result["ok"], result)
        return result["result"]

    def make_policy(self, *, version=1, previous=None, publishers=None, subscribers=None, status="active", issued=None):
        start = self.now - 10 if issued is None else issued
        return topics.issue_policy(self.issuer, network_id=self.network, topic_id=self.topic, issuer_key_id=self.issuer.key_id,
            version=version, previous_sha256="0" * 64 if previous is None else crypto.document_sha256(previous),
            status=status, publishers=publishers if publishers is not None else [
                {"member_key_id": self.owner.key_id, "grant_id": "synthetic-publisher-grant", "status": "active"}],
            subscriber_grants=subscribers if subscribers is not None else [
                {"member_key_id": self.subscriber.key_id, "grant_id": "synthetic-subscriber-grant", "status": "active"}],
            issued_at=start, expires_at=start + 300)

    def make_change(self, *, revision=1, previous=None, signer=None, grant="synthetic-subscriber-grant", state="subscribed", issued=None):
        start = self.now - 5 if issued is None else issued
        return topics.sign_subscription(signer or self.subscriber, network_id=self.network, topic_id=self.topic,
            grant_id=grant, revision=revision, previous_change_sha256="0" * 64 if previous is None else crypto.document_sha256(previous),
            state=state, request_id=f"synthetic-change-request-{revision}-{grant}", issued_at=start, expires_at=start + 300)

    def make_snapshot(self, *, version=1, previous=None, policy=None, entries=None, issued=None):
        selected = self.policy if policy is None else policy
        start = self.now - 1 if issued is None else issued
        return topics.issue_snapshot(self.issuer, network_id=self.network, topic_id=self.topic, issuer_key_id=self.issuer.key_id,
            version=version, previous_sha256="0" * 64 if previous is None else crypto.document_sha256(previous),
            policy_version=selected["payload"]["version"], policy_sha256=crypto.document_sha256(selected),
            subscriptions=entries if entries is not None else [{"member_key_id": self.subscriber.key_id,
                "grant_id": "synthetic-subscriber-grant", "change": self.change}], issued_at=start, expires_at=start + 300)

    def joint(self, *, policy=None, snapshot=None, roster=None, issued=None, expires=None):
        selected_policy = self.policy if policy is None else policy
        selected_snapshot = self.snapshot if snapshot is None else snapshot
        selected_roster = self.roster if roster is None else roster
        start = self.now if issued is None else issued
        end = start + 300 if expires is None else expires
        status = control.issue_status(self.issuer, network_id=self.network, nonce=self.nonce,
            roster_version=selected_roster["payload"]["version"], roster_sha256=crypto.document_sha256(selected_roster),
            issued_at=start, expires_at=end)
        topic_status = topics.issue_topic_status(self.issuer, network_id=self.network, topic_id=self.topic,
            issuer_key_id=self.issuer.key_id, nonce=self.nonce, policy_version=selected_policy["payload"]["version"],
            policy_sha256=crypto.document_sha256(selected_policy), snapshot_version=selected_snapshot["payload"]["version"],
            snapshot_sha256=crypto.document_sha256(selected_snapshot), roster_version=selected_roster["payload"]["version"],
            roster_sha256=crypto.document_sha256(selected_roster), issued_at=start, expires_at=end)
        return {"roster": selected_roster, "status": status, "policy": selected_policy, "snapshot": selected_snapshot, "topic_status": topic_status}

    def py(self, function, value, options):
        keywords = {key: child for key, child in options.items() if key != "issuers"}
        functions = {"verifyPolicy": topics.verify_policy, "verifySubscription": topics.verify_subscription,
            "verifySnapshot": topics.verify_snapshot, "verifyTopicStatus": topics.verify_topic_status,
            "verifySubscriptionReceipt": topics.verify_subscription_receipt, "verifyCurrentTopic": topics.verify_current_topic}
        try:
            if function == "verifySubscription":
                result = functions[function](value, **keywords)
            else:
                result = functions[function](value, self.issuers, **keywords)
            if function == "verifyCurrentTopic":
                result = self.current_wire(result)
            return {"ok": True, "result": result}
        except Exception as error:
            return {"ok": False, "error": getattr(error, "code", "unexpected_error")}

    def compare(self, function, value, options=None, *, error=None, raw=None):
        if options is None:
            options = self.options
        selected = value if raw is None else raw
        expected = self.py(function, selected, options)
        request = {"function": function, "args": [value, options]}
        if raw is not None:
            request["raw"] = base64.urlsafe_b64encode(raw).decode().rstrip("=")
        actual, = self.run_ts(request)
        self.assertEqual(actual, expected)
        self.assertNotEqual(actual.get("error"), "unexpected_error")
        if error is not None:
            self.assertEqual(actual, {"ok": False, "error": error})
        else:
            self.assertTrue(actual["ok"], actual)
        return actual.get("result")

    @staticmethod
    def current_wire(current):
        return {name: getattr(current, name) for name in
            ("roster", "status", "policy", "snapshot", "topic_status", "verified_at", "expires_at")}

    @staticmethod
    def captured(operation):
        try:
            return {"ok": True, "result": operation()}
        except Exception as error:
            return {"ok": False, "error": getattr(error, "code", "unexpected_error")}

    def current_case(self, value=None, options=None, select=None, publish=None, advance=None):
        if value is None:
            value = self.joint()
        if options is None:
            options = {**self.options, "nonce": self.nonce}
        current = topics.verify_current_topic(value, self.issuers,
            **{key: child for key, child in options.items() if key != "issuers"})
        request = {"function": "current", "value": value, "options": options,
            "select": select or [], "publish": publish or []}
        if advance is not None:
            request["advance_monotonic_ms"] = advance
        actual, = self.run_ts(request)
        self.assertTrue(actual["ok"], actual)
        observed = actual["result"]
        self.assertEqual(observed["current"], self.current_wire(current)); self.assertTrue(observed["immutable"])
        if advance is None:
            wanted = [self.captured(lambda choice=choice: topics.topic_recipients(
                copy.copy(current) if choice.get("copy") else current, now=choice["now"])) for choice in (select or [])]
            self.assertEqual(observed["receivers"], wanted)
        wanted = [self.captured(lambda choice=choice: topics.authorized_topic_publisher(
            copy.copy(current) if choice.get("copy") else current, choice["member_key_id"], now=choice["now"],
            grant_id=choice.get("grant_id"))) for choice in (publish or [])]
        self.assertEqual(observed["publishers"], wanted)
        return observed

    def mutation(self, signed, **changes):
        payload = copy.deepcopy(signed["payload"]); payload.update(changes)
        signer = self.subscriber if payload.get("schema_version") == topics.SUBSCRIPTION_SCHEMA else self.issuer
        return self.signed(payload, signer)

    def test_bidirectional_signed_bytes_and_all_document_verifiers(self):
        payloads = [("issuePolicy", self.policy, self.issuer), ("signSubscription", self.change, self.subscriber),
            ("issueSnapshot", self.snapshot, self.issuer), ("issueTopicStatus", self.joint()["topic_status"], self.issuer)]
        for function, expected, identity in payloads:
            with self.subTest(function=function):
                options = {key: value for key, value in expected["payload"].items() if key != "schema_version"}
                if function == "signSubscription":
                    options.pop("member_key_id"); options.pop("member_signing_key")
                actual = self.success(function, {**options, "signer": self.secret(identity)})
                self.assertEqual(canonical_bytes(actual), canonical_bytes(expected))
        self.compare("verifyPolicy", self.policy)
        self.compare("verifySubscription", self.change, {"network_id": self.network, "topic_id": self.topic, "now": self.now})
        self.compare("verifySnapshot", self.snapshot, {**self.options, "policy": self.policy})
        self.compare("verifyTopicStatus", self.joint()["topic_status"], {**self.options, "nonce": self.nonce,
            "policy_sha256": crypto.document_sha256(self.policy), "snapshot_version": 1})

    def test_policy_error_codes_and_retained_grants_match(self):
        first = self.policy["payload"]["subscriber_grants"][0]
        revoked = self.make_policy(version=2, previous=self.policy, subscribers=[{**first, "status": "revoked"}])
        regrant = self.make_policy(version=3, previous=revoked, subscribers=[{**first, "status": "revoked"},
            {**first, "grant_id": "synthetic-new-grant"}])
        self.compare("verifyPolicy", regrant, {**self.options, "previous_policy": revoked})
        fixtures = [
            (self.mutation(self.policy, previous_sha256="1" * 64), {}, "chain_mismatch"),
            (self.mutation(self.policy, schema_version="synthetic-wrong-domain/v1"), {}, "policy_binding_mismatch"),
            (self.mutation(self.policy, topic_id="synthetic-other-topic"), {}, "policy_binding_mismatch"),
            (self.mutation(self.policy, status="active_again"), {}, "invalid_status"),
            (self.mutation(self.policy, subscriber_grants=[first, first]), {}, "duplicate_grant"),
            (self.mutation(self.policy, subscriber_grants=[first, {**first, "grant_id": "synthetic-other-grant"}]), {}, "active_grant_conflict"),
            (self.make_policy(version=2, previous=self.policy, subscribers=[]), {"previous_policy": self.policy}, "tombstone_required"),
            (self.make_policy(version=3, previous=revoked), {"previous_policy": revoked}, "reactivation_forbidden"),
            (self.mutation(self.policy, status="revoked"), {"previous_policy": self.policy}, "version_conflict"),
            (self.policy, {"previous_policy": revoked}, "rollback"),
            (self.make_policy(version=3, previous=revoked), {"previous_policy": self.policy}, "gap_requires_current"),
            (self.mutation(revoked, previous_sha256="1" * 64), {"previous_policy": self.policy}, "chain_mismatch"),
        ]
        for value, options, code in fixtures:
            with self.subTest(code=code):
                self.compare("verifyPolicy", value, {**self.options, **options}, error="network_topic_" + code)
        forged = self.signed({**self.policy["payload"], "issuer_key_id": self.other_issuer.key_id}, self.other_issuer)
        self.compare("verifyPolicy", forged, error="network_topic_issuer_mismatch")
        self.compare("verifyPolicy", self.signed(self.policy["payload"], self.other_issuer), error="network_topic_issuer_mismatch")

    def test_subscription_history_chain_errors_and_descriptor_binding(self):
        options = {"network_id": self.network, "topic_id": self.topic, "now": self.now}
        second = self.make_change(revision=2, previous=self.change, state="unsubscribed")
        third = self.make_change(revision=3, previous=second)
        self.compare("verifySubscription", second, {**options, "previous_change": self.change})
        self.compare("verifySubscription", third, options)
        for value, extra, code in [
            (third, {"previous_change": self.change}, "change_gap_requires_current"),
            (self.change, {"previous_change": second}, "change_rollback"),
            (self.mutation(second, previous_change_sha256="1" * 64), {"previous_change": self.change}, "change_chain_mismatch"),
            (self.mutation(self.change, state="unsubscribed"), {"previous_change": self.change}, "change_conflict"),
            (self.mutation(self.change, state="hidden"), {}, "invalid_state"),
            (self.mutation(self.change, member_signing_key=self.owner.public_descriptor()), {}, "subscription_binding_mismatch"),
            (self.change, {"member_key_id": self.owner.key_id}, "subscription_binding_mismatch"),
        ]:
            with self.subTest(code=code):
                self.compare("verifySubscription", value, {**options, **extra}, error="network_topic_" + code)

    def test_member_clock_correction_can_unsubscribe_with_valid_chain(self):
        first = self.make_change(issued=self.now + 30)
        later = self.make_change(revision=2, previous=first, state="unsubscribed", issued=self.now + 1)
        self.compare("verifySubscription", later, {"network_id": self.network, "topic_id": self.topic,
            "now": self.now + 31, "previous_change": first})
        old = self.make_snapshot(entries=[{**self.snapshot["payload"]["subscriptions"][0], "change": first}], issued=self.now + 30)
        current = self.make_snapshot(version=2, previous=old,
            entries=[{**self.snapshot["payload"]["subscriptions"][0], "change": later}], issued=self.now + 31)
        result = self.current_case(value=self.joint(snapshot=current, issued=self.now + 31),
            options={**self.options, "now": self.now + 31, "nonce": self.nonce,
                "previous_policy": self.policy, "previous_snapshot": old}, select=[{"now": self.now + 31}])
        self.assertEqual(result["receivers"], [{"ok": True, "result": []}])

    def test_snapshot_completeness_changes_and_exact_code_table(self):
        options = {**self.options, "policy": self.policy}
        second_change = self.make_change(revision=2, previous=self.change, state="unsubscribed")
        second = self.make_snapshot(version=2, previous=self.snapshot, entries=[{**self.snapshot["payload"]["subscriptions"][0], "change": second_change}])
        self.compare("verifySnapshot", second, {**options, "previous_snapshot": self.snapshot})
        fixtures = [
            (self.mutation(self.snapshot, subscriptions=[]), {}, "snapshot_incomplete"),
            (self.mutation(self.snapshot, policy_sha256="1" * 64), {}, "snapshot_policy_mismatch"),
            (self.mutation(second, subscriptions=[{**second["payload"]["subscriptions"][0], "change": None}]), {"previous_snapshot": self.snapshot}, "change_missing"),
            (self.mutation(second, subscriptions=[{**second["payload"]["subscriptions"][0], "change": self.mutation(self.change, state="unsubscribed")}]), {"previous_snapshot": self.snapshot}, "change_conflict"),
            (self.mutation(self.snapshot, version=3, previous_sha256=crypto.document_sha256(second)), {"previous_snapshot": self.snapshot}, "gap_requires_current"),
        ]
        for value, extra, code in fixtures:
            with self.subTest(code=code):
                self.compare("verifySnapshot", value, {**options, **extra}, error="network_topic_" + code)

    def test_current_brand_selection_publisher_and_clock_lease(self):
        result = self.current_case(select=[{"now": self.now}, {"now": self.now, "copy": True},
            {"now": self.now - 1}, {"now": self.now + 300}], publish=[
            {"now": self.now, "member_key_id": self.owner.key_id},
            {"now": self.now, "member_key_id": self.owner.key_id, "grant_id": "synthetic-incorrect-grant"},
            {"now": self.now, "member_key_id": self.subscriber.key_id},
            {"now": self.now, "member_key_id": self.owner.key_id, "copy": True}])
        recipient = result["receivers"][0]["result"][0]
        self.assertEqual(recipient["member_key_id"], self.subscriber.key_id)
        self.assertEqual(recipient["change_sha256"], crypto.document_sha256(self.change))
        self.assertEqual([r.get("error") for r in result["receivers"]], [None, "network_topic_capability_required",
            "network_topic_clock_rollback", "network_control_expired"])

    def test_future_clock_skew_does_not_extend_monotonic_cap(self):
        response = self.joint(issued=self.now + 30, expires=self.now + 330)
        active = self.current_case(value=response, select=[{"now": self.now + 299}])
        self.assertEqual(active["current"]["expires_at"], self.now + 300)
        self.current_case(value=response, select=[{"now": self.now + 300}])
        for elapsed in (299999, 300000):
            actual = self.current_case(value=response, select=[{"now": self.now}], advance=elapsed)
            if elapsed == 299999:
                self.assertTrue(actual["receivers"][0]["ok"])
            else:
                self.assertEqual(actual["receivers"][0], {"ok": False, "error": "network_control_expired"})
        with patch.object(topics.time, "monotonic", return_value=1000):
            current = topics.verify_current_topic(response, self.issuers, network_id=self.network, topic_id=self.topic,
                issuer_key_id=self.issuer.key_id, nonce=self.nonce, now=self.now)
        with patch.object(topics.time, "monotonic", return_value=1300):
            self.assertEqual(self.captured(lambda: topics.topic_recipients(current, now=self.now)),
                {"ok": False, "error": "network_control_expired"})

    def test_fresh_nonce_is_only_gap_authority_and_changes_stay_exact(self):
        second_policy = self.make_policy(version=2, previous=self.policy)
        third_policy = self.make_policy(version=3, previous=second_policy)
        unsubscribe = self.make_change(revision=2, previous=self.change, state="unsubscribed")
        resubscribe = self.make_change(revision=3, previous=unsubscribe)
        second = self.make_snapshot(version=2, previous=self.snapshot, policy=second_policy,
            entries=[{**self.snapshot["payload"]["subscriptions"][0], "change": unsubscribe}])
        third = self.make_snapshot(version=3, previous=second, policy=third_policy,
            entries=[{**self.snapshot["payload"]["subscriptions"][0], "change": resubscribe}])
        options = {**self.options, "nonce": self.nonce, "previous_policy": self.policy, "previous_snapshot": self.snapshot}
        response = self.joint(policy=third_policy, snapshot=third)
        actual = self.current_case(value=response, options=options, select=[{"now": self.now}])
        self.assertEqual(actual["receivers"][0]["result"][0]["change_sha256"], crypto.document_sha256(resubscribe))
        self.assertNotEqual(crypto.document_sha256(resubscribe), crypto.document_sha256(self.change))
        self.compare("verifySnapshot", third, {**self.options, "policy": third_policy, "previous_snapshot": self.snapshot},
            error="network_topic_gap_requires_current")
        result, = self.run_ts({"function": "verifyPolicy", "args": [third_policy,
            {**self.options, "previous_policy": self.policy, "allow_gap": True}]})
        self.assertEqual(result, {"ok": False, "error": "network_topic_gap_requires_current"})
        self.compare("verifyCurrentTopic", response, {**options, "nonce": "synthetic-wrong-nonce"}, error="network_status_binding_mismatch")
        self.compare("verifyCurrentTopic", response, {**self.options, "nonce": self.nonce, "previous_policy": self.policy},
            error="network_topic_checkpoint_incomplete")

    def test_joint_nonce_root_and_checkpoint_failure_codes(self):
        response = self.joint(); options = {**self.options, "nonce": self.nonce}
        self.compare("verifyCurrentTopic", response, options)
        for field, replacement in (("policy_sha256", "1" * 64), ("snapshot_sha256", "1" * 64),
                                   ("roster_sha256", "1" * 64), ("policy_version", 2),
                                   ("snapshot_version", 2), ("nonce", "synthetic-incorrect-nonce")):
            altered = {**response, "topic_status": self.mutation(response["topic_status"], **{field: replacement})}
            self.compare("verifyCurrentTopic", altered, options, error="network_topic_status_binding_mismatch")
        self.compare("verifyCurrentTopic", response, {**options, "minimum_topic_status_issued_at": self.now + 1},
            error="network_topic_status_rollback")
        self.compare("verifyCurrentTopic", response, {**options, "minimum_status_issued_at": self.now + 1},
            error="network_topic_status_rollback")
        bad_roster = self.signed(self.roster["payload"], self.other_issuer)
        other = self.joint(roster=bad_roster)
        self.compare("verifyCurrentTopic", other, options, error="unknown_key")
        self.compare("verifyTopicStatus", self.joint(issued=self.now + 31)["topic_status"], options,
            error="network_control_from_future")

    def test_removed_roster_member_remains_historical_but_not_a_recipient(self):
        remaining = [member for member in self.members if member["signing_key"]["key_id"] == self.owner.key_id]
        roster = control.issue_roster(self.issuer, network_id=self.network, version=2,
            previous_sha256=crypto.document_sha256(self.roster), members=remaining,
            issued_at=self.now, expires_at=self.now + 300)
        result = self.current_case(value=self.joint(roster=roster), options={**self.options, "nonce": self.nonce,
            "previous_roster": self.roster}, select=[{"now": self.now}])
        self.assertEqual(result["receivers"], [{"ok": True, "result": []}])
        self.compare("verifySubscription", self.change, {"network_id": self.network, "topic_id": self.topic, "now": self.now})
        revoked = self.make_policy(version=2, previous=self.policy, status="revoked")
        snapshot = self.make_snapshot(version=2, previous=self.snapshot, policy=revoked)
        result = self.current_case(value=self.joint(policy=revoked, snapshot=snapshot), select=[{"now": self.now}])
        self.assertEqual(result["receivers"][0], {"ok": False, "error": "network_topic_inactive"})

    def test_historical_policy_and_changes_require_fresh_complete_status(self):
        policy = self.make_policy(issued=self.now - 400)
        change = self.make_change(issued=self.now - 390)
        snapshot = self.make_snapshot(policy=policy, entries=[{**self.snapshot["payload"]["subscriptions"][0], "change": change}])
        self.compare("verifyPolicy", policy, error="network_control_expired")
        self.compare("verifySnapshot", snapshot, {**self.options, "policy": policy})
        self.current_case(value=self.joint(policy=policy, snapshot=snapshot), select=[{"now": self.now}])
        expired = self.joint(policy=policy, snapshot=snapshot, issued=self.now - 300, expires=self.now)
        self.compare("verifyCurrentTopic", expired, {**self.options, "nonce": self.nonce}, error="network_control_expired")

    def test_receipt_is_historical_commit_and_binds_exact_change(self):
        receipt = topics.issue_subscription_receipt(self.issuer, network_id=self.network, topic_id=self.topic,
            issuer_key_id=self.issuer.key_id, member_key_id=self.subscriber.key_id, grant_id="synthetic-subscriber-grant",
            request_id=self.change["payload"]["request_id"], revision=1, change_sha256=crypto.document_sha256(self.change),
            snapshot_version=1, snapshot_sha256=crypto.document_sha256(self.snapshot), committed_at=self.now)
        options = {key: value for key, value in receipt["payload"].items() if key not in ("schema_version", "state")}
        observed = self.success("issueSubscriptionReceipt", {**options, "signer": self.secret(self.issuer)})
        self.assertEqual(canonical_bytes(observed), canonical_bytes(receipt))
        self.compare("verifySubscriptionReceipt", receipt, {**self.options, "now": self.now + 10000,
            "change": self.change, "snapshot": self.snapshot})
        self.compare("verifySubscriptionReceipt", self.mutation(receipt, change_sha256="1" * 64),
            {**self.options, "change": self.change}, error="network_topic_receipt_binding_mismatch")
        self.compare("verifySubscriptionReceipt", self.mutation(receipt, committed_at=self.now + 31),
            error="network_control_from_future")
        self.compare("verifySubscriptionReceipt", self.mutation(receipt, state="stored"), error="network_topic_invalid_state")
        late_commit = self.mutation(receipt, committed_at=self.now + 1000)
        self.compare("verifySubscriptionReceipt", late_commit, {**self.options, "now": self.now + 1000, "change": self.change},
            error="network_control_expired")

    def test_strict_json_and_serialized_wrapper_limits(self):
        raw = canonical_bytes(self.policy)
        duplicate = b'{"payload":{},' + raw[1:]
        self.compare("verifyPolicy", self.policy, raw=duplicate, error="duplicate_json_key")
        self.compare("verifyPolicy", self.policy, raw=b" " * (topics.MAX_POLICY_BYTES - len(raw) + 1) + raw,
            error="network_document_too_large")
        status = self.joint()["topic_status"]; raw_status = canonical_bytes(status)
        self.compare("verifyTopicStatus", status, {**self.options, "nonce": self.nonce},
            raw=b" " * (topics.MAX_TOPIC_STATUS_BYTES - len(raw_status) + 1) + raw_status, error="network_document_too_large")
        unsafe = copy.deepcopy(self.policy); unsafe["payload"]["version"] = 2**53
        self.compare("verifyPolicy", unsafe, raw=json.dumps(unsafe).encode(), error="network_invalid_integer")
        extra = self.mutation(self.policy, unexpected=True)
        self.compare("verifyPolicy", extra, error="network_invalid_document")

    def test_noninteger_host_value_and_raw_json_share_error_classification(self):
        fractional = copy.deepcopy(self.policy)
        fractional["payload"]["version"] = 0.5
        self.compare("verifyPolicy", fractional, error="network_nonportable_json")
        self.compare("verifyPolicy", fractional, raw=json.dumps(fractional).encode(), error="network_nonportable_json")
        # JavaScript cannot distinguish host values written as 1 and 1.0.
        # This regression covers nonintegral values and preserves integer overflow.
        unsafe = copy.deepcopy(self.policy)
        unsafe["payload"]["version"] = 2**53
        self.compare("verifyPolicy", unsafe, error="network_invalid_integer")
        self.compare("verifyPolicy", unsafe, raw=json.dumps(unsafe).encode(), error="network_invalid_integer")

    def test_recipient_and_grant_limits_never_truncate(self):
        members, grants, changes = [], [], []
        for index in range(17):
            identity = self.signing(); grant_id = f"synthetic-many-{index:02d}"
            members.append({"signing_key": identity.public_descriptor(),
                "encryption_key": crypto.EncryptionIdentity.generate().public_descriptor(), "scope": ["receive"], "status": "active"})
            grants.append({"member_key_id": identity.key_id, "grant_id": grant_id, "status": "active"})
            changes.append({"member_key_id": identity.key_id, "grant_id": grant_id,
                "change": self.make_change(signer=identity, grant=grant_id)})
        policy = self.make_policy(subscribers=grants)
        snapshot = self.make_snapshot(policy=policy, entries=sorted(changes, key=lambda item: (item["member_key_id"], item["grant_id"])))
        roster = control.issue_roster(self.issuer, network_id=self.network, version=1, previous_sha256="0" * 64,
            members=members, issued_at=self.now - 10, expires_at=self.now + 290)
        result = self.current_case(value=self.joint(policy=policy, snapshot=snapshot, roster=roster), select=[{"now": self.now}])
        self.assertEqual(result["receivers"], [{"ok": False, "error": "network_topic_recipient_limit"}])
        too_many = [{"member_key_id": self.subscriber.key_id, "grant_id": f"synthetic-limit-{index:03d}", "status": "revoked"}
                    for index in range(257)]
        self.compare("verifyPolicy", self.mutation(self.policy, publishers=[], subscriber_grants=too_many), error="network_topic_grant_limit")
