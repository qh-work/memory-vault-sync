"""Independent Node/jose hint protocol and real owned loopback exchange."""
import json
import subprocess
import time
import unittest

from memory_vault import MemoryError, canonical_bytes, strict_json_loads
from memory_vault_network_content import validate_content, content_text
from memory_vault_network_crypto import document_sha256, seal
from memory_vault_storage import atomic_write
from tests import test_network_typescript_agent_network as runtime
from tests.test_network_hints import control, policy, parser_vectors, outbox_row
from tests.test_network_message_semantics import vault_snapshot, records, proofs


CODEC_DRIVER = r"""
import fs from 'node:fs';
import {validateContent,contentText} from './content.ts';
const input=JSON.parse(fs.readFileSync(0,'utf8'));
const result=input.map(value=>{try{const content=validateContent(Buffer.from(value,'base64'));return {ok:true,content,text:contentText(content)};}
catch(error){return {ok:false,code:error.code};}});
process.stdout.write(JSON.stringify(result));
"""


class TypeScriptHintCodecTests(unittest.TestCase):
    setUpClass = classmethod(runtime.TypeScriptAgentNetworkTests.setUpClass.__func__)

    def test_python_typescript_closed_content_and_errors_match(self):
        import base64
        valid, invalid = parser_vectors()
        values = [json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode() for value in valid + invalid]
        values += [b'{"schema_version":"memory-vault-network-content/v2","kind":"hint_control","control":{"schema_version":"memory-vault-hint/v1","kind":"query","query":"one","query":"two"}}']
        expected = []
        for raw in values:
            try:
                decoded = validate_content(raw)
                expected.append({"ok": True, "content": decoded, "text": content_text(decoded)})
            except MemoryError as exc:
                expected.append({"ok": False, "code": exc.code})
        self.assertTrue(all(row["ok"] for row in expected[:len(valid)]))
        self.assertTrue(all(not row["ok"] for row in expected[len(valid):]))
        driver = self.fixture / "hint-codec.mjs"
        driver.write_text(CODEC_DRIVER)
        output = subprocess.run([self.node, "--experimental-strip-types", str(driver)],
            input=json.dumps([base64.b64encode(value).decode() for value in values]).encode(),
            cwd=self.fixture, capture_output=True, timeout=30)
        self.assertEqual(output.returncode, 0, output.stderr.decode(errors="replace")[-3000:])
        self.assertEqual(json.loads(output.stdout), expected)


class TypeScriptHintExchangeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        runtime.TypeScriptAgentNetworkTests.setUpClass.__func__(cls)
        driver = runtime.DRIVER.replace("const agent=new Agent", r"""
let policyResult;
if(input.policy!==undefined){
  const {NetworkPeer}=await import('./peer.ts');
  const owner=new NetworkPeer(input.network_config,{transport});
  try{policyResult={ok:true,result:await owner.setHintPolicy(input.policy)};}
  catch(error){policyResult={ok:false,code:error.code};}
  finally{owner.close();}
}
const agent=new Agent""").replace("{results,calls,subprocessCalls}", "{results,calls,subprocessCalls,policyResult}")
        (cls.fixture / "driver.mjs").write_text(driver)

    setUp = runtime.TypeScriptAgentNetworkTests.setUp
    ts_value = runtime.TypeScriptAgentNetworkTests.ts_value
    py_value = runtime.TypeScriptAgentNetworkTests.py_value

    def ts(self, index, *requests, policy_doc=None):
        value = {"client_config": str(self.host.configs[index]),
                 "network_config": str(self.host.net_configs[index]), "requests": requests}
        if policy_doc is not None:
            value["policy"] = policy_doc
        output = subprocess.run([self.node, "--experimental-strip-types", str(self.fixture / "driver.mjs")],
            input=json.dumps(value).encode(), cwd=self.fixture, capture_output=True, timeout=45)
        self.assertEqual(output.returncode, 0, output.stderr.decode(errors="replace")[-4000:])
        result = json.loads(output.stdout)
        self.assertEqual(result["subprocessCalls"], 0)
        self.assertEqual(len(result["results"]), len(requests))
        for response in result["results"]:
            self.assertLessEqual(len(canonical_bytes(response)), 8192)
            self.assertFalse(response["authority"]["execution_eligible"])
            self.assertFalse(response["authority"]["authorization_eligible"])
        return result

    def set_policy(self, owner, requester, hints, full, *, revision=1):
        endpoints = [self.host.sender, self.host.receiver]
        document = policy(endpoints[owner], endpoints[requester], hints, full, revision=revision)
        result = self.ts(owner, policy_doc=document)
        self.assertTrue(result["policyResult"]["ok"], result)
        self.assertFalse(result["calls"])
        return document

    def remember(self, endpoint, suffix, text, relations=None):
        return self.ts_value(endpoint, {"op": "remember", "request_id": "req_hint_ts_record_" + suffix,
            "kind": "observation", "text": text, "relations": relations or [],
            "experience": {"epistemic_type": "experiment", "observed_under": {"environment": "V1"}}})["memory_id"]

    def exchange_offer(self, owner, requester, owner_call, requester_call, suffix):
        host = self.host
        sent = requester_call(requester, {"op": "send", "request_id": "req_hint_ts_query_" + suffix,
            "recipients": [host.identities[owner].key_id], "control": control("query", query="Synthetic needle")})
        self.assertEqual(sent["stored_nodes"], 2)
        self.assertFalse(owner_call(owner, {"op": "receive"})["errors"])
        offered = owner_call(owner, {"op": "receive", "respond_to": sent["message_id"]})
        self.assertEqual(offered["stored_nodes"], 2, offered)
        self.assertFalse(requester_call(requester, {"op": "receive"})["errors"])
        read = requester_call(requester, {"op": "receive", "message_id": offered["message_id"]})
        self.assertFalse(read["network_accessed"])
        return sent, offered, read["control"]

    def test_both_languages_query_unknown_id_and_explicitly_transfer_original_closure(self):
        host = self.host
        host.join_receiver()
        endpoints = [host.sender, host.receiver]
        for owner, requester, owner_call, requester_call in (
                (0, 1, self.py_value, self.ts_value), (1, 0, self.ts_value, self.py_value)):
            with self.subTest(owner=owner):
                root = self.remember(owner, "root_" + str(owner), "Synthetic direct evidence " + str(owner))
                selected = self.remember(owner, "selected_" + str(owner), "Synthetic needle " + "😀" * 80,
                                         [{"type": "derived_from", "target": root}])
                hidden = self.remember(owner, "hidden_" + str(owner), "Synthetic needle HIDDEN-TS-EVIDENCE")
                self.set_policy(owner, requester, [selected], [root, selected])
                before = [vault_snapshot(endpoint) for endpoint in endpoints]
                originals, original_proofs = records(endpoints[owner]), proofs(endpoints[owner])
                queried, offered, hint = self.exchange_offer(owner, requester, owner_call, requester_call, str(owner))
                self.assertEqual(hint["kind"], "hints")
                self.assertEqual(hint["request_message_id"], queried["message_id"])
                self.assertEqual([item["memory_id"] for item in hint["hints"]], [selected])
                item, = hint["hints"]
                self.assertEqual(set(item), {"memory_id", "excerpt", "epistemic_type"})
                self.assertEqual(item["epistemic_type"], "experiment")
                self.assertLessEqual(len(item["excerpt"].encode()), 128)
                for secret in (root, hidden, "HIDDEN-TS-EVIDENCE"):
                    self.assertNotIn(secret, canonical_bytes(hint).decode())
                self.assertEqual([vault_snapshot(endpoint) for endpoint in endpoints], before)
                chosen = requester_call(requester, {"op": "send", "request_id": "req_hint_ts_select_" + str(owner),
                    "recipients": [host.identities[owner].key_id], "control": control("select",
                        offer_message_id=offered["message_id"], memory_id=item["memory_id"])})
                self.assertEqual(chosen["stored_nodes"], 2)
                self.assertFalse(owner_call(owner, {"op": "receive"})["errors"])
                transfer = owner_call(owner, {"op": "receive", "respond_to": chosen["message_id"]})
                self.assertEqual(transfer["stored_nodes"], 2, transfer)
                self.assertEqual([vault_snapshot(endpoint) for endpoint in endpoints], before)
                received = requester_call(requester, {"op": "receive"})
                self.assertFalse(received["errors"], received)
                message, = received["messages"]
                self.assertEqual(message["content_kind"], "hint_transfer")
                self.assertEqual(message["share"]["admission"], "verified")
                self.assertEqual(message["share"]["records_added"], 2)
                for memory_id in (root, selected):
                    self.assertEqual(records(endpoints[requester])[memory_id], originals[memory_id])
                    self.assertEqual(proofs(endpoints[requester])[memory_id], original_proofs[memory_id])
                self.assertNotIn(hidden, records(endpoints[requester]))
                frozen = outbox_row(endpoints[owner], transfer["message_id"])
                again = owner_call(owner, {"op": "receive", "respond_to": chosen["message_id"]})
                self.assertEqual(again["message_id"], transfer["message_id"])
                self.assertEqual(outbox_row(endpoints[owner], again["message_id"])["envelope"], frozen["envelope"])
                self.assertEqual(requester_call(requester, {"op": "receive"})["messages"], [])

    def test_typescript_hints_do_not_grant_full_record_or_dependency_access(self):
        host = self.host
        host.join_receiver()
        private = self.remember(1, "dependency", "HIDDEN-SYNTHETIC-DEPENDENCY")
        visible = self.remember(1, "root", "Synthetic needle visible hint", [{"type": "derived_from", "target": private}])
        for index, full in enumerate(([], [visible])):
            self.set_policy(1, 0, [visible], full, revision=index + 1)
            before = [vault_snapshot(endpoint) for endpoint in (host.sender, host.receiver)]
            _, offer, _ = self.exchange_offer(1, 0, self.ts_value, self.py_value, "denied_" + str(index))
            selected = self.py_value(0, {"op": "send", "request_id": "req_hint_ts_denied_select_" + str(index),
                "recipients": [host.identities[1].key_id], "control": control("select", offer_message_id=offer["message_id"], memory_id=visible)})
            self.assertFalse(self.ts_value(1, {"op": "receive"})["errors"])
            refused = self.ts_value(1, {"op": "receive", "respond_to": selected["message_id"]})
            self.assertFalse(self.py_value(0, {"op": "receive"})["errors"])
            body = self.py_value(0, {"op": "receive", "message_id": refused["message_id"]})["control"]
            self.assertEqual(body, control("refusal", request_message_id=selected["message_id"], reason="not_available"))
            self.assertNotIn(private, canonical_bytes(body).decode())
            self.assertEqual([vault_snapshot(endpoint) for endpoint in (host.sender, host.receiver)], before)

    def test_both_languages_refuse_secret_shaped_or_local_path_dependencies_without_leaks(self):
        from memory_vault_privacy import review_records
        host = self.host
        host.join_receiver()
        endpoints = [host.sender, host.receiver]
        # These values are deliberately assembled, wholly synthetic scanner
        # fixtures. No credential is loaded and no referenced file is accessed.
        cases = [("api_" + "key=" + "synthetic" * 4, "publication_secret_detected"),
                 ("/home/" + "synthetic-fixture/never-accessed.txt", "publication_local_path_detected")]
        for owner, requester, owner_call, requester_call in (
                (0, 1, self.py_value, self.ts_value), (1, 0, self.ts_value, self.py_value)):
            for index, (sensitive, reason) in enumerate(cases):
                with self.subTest(owner=owner, finding=reason):
                    suffix = str(owner) + "_" + str(index)
                    dependency = self.remember(owner, "privacy_dependency_" + suffix,
                                               "Synthetic publication guard dependency: " + sensitive)
                    selected = self.remember(owner, "privacy_root_" + suffix,
                        "Synthetic needle public root " + suffix, [{"type": "derived_from", "target": dependency}])
                    findings = review_records([strict_json_loads(records(endpoints[owner])[dependency])])
                    self.assertIn(reason, findings[0]["reasons"])
                    self.set_policy(owner, requester, [selected], [selected, dependency], revision=index + 1)
                    before = [vault_snapshot(endpoint) for endpoint in endpoints]
                    _, offered, hints = self.exchange_offer(owner, requester, owner_call, requester_call, "privacy_" + suffix)
                    self.assertEqual([hint["memory_id"] for hint in hints["hints"]], [selected])
                    self.assertNotIn(dependency, canonical_bytes(hints).decode())
                    self.assertNotIn(sensitive, canonical_bytes(hints).decode())
                    chosen = requester_call(requester, {"op": "send", "request_id": "req_hint_privacy_select_" + suffix,
                        "recipients": [host.identities[owner].key_id], "control": control("select",
                            offer_message_id=offered["message_id"], memory_id=selected)})
                    self.assertEqual(chosen["stored_nodes"], 2, chosen)
                    self.assertFalse(owner_call(owner, {"op": "receive"})["errors"])
                    refused = owner_call(owner, {"op": "receive", "respond_to": chosen["message_id"]})
                    self.assertEqual(refused["stored_nodes"], 2, refused)
                    delivered = requester_call(requester, {"op": "receive"})
                    self.assertFalse(delivered["errors"], delivered)
                    message, = delivered["messages"]
                    self.assertEqual(message["content_kind"], "hint_control")
                    self.assertIsNone(message["share"])
                    response = requester_call(requester, {"op": "receive", "message_id": refused["message_id"]})
                    self.assertEqual(response["control"], control("refusal",
                        request_message_id=chosen["message_id"], reason="not_available"))
                    body = strict_json_loads(outbox_row(endpoints[owner], refused["message_id"])["body"])
                    self.assertEqual(body["kind"], "hint_control")
                    for hidden in (dependency, sensitive, reason):
                        self.assertNotIn(hidden, canonical_bytes(body).decode())
                        self.assertNotIn(hidden, canonical_bytes(response).decode())
                    self.assertEqual([vault_snapshot(endpoint) for endpoint in endpoints], before)

    def test_typescript_frozen_transfer_cannot_retry_after_revocation(self):
        host = self.host
        host.join_receiver()
        dependency = self.remember(1, "retry_dependency", "Synthetic private retry dependency")
        mid = self.remember(1, "retry", "Synthetic needle guarded retry", [{"type": "derived_from", "target": dependency}])
        self.set_policy(1, 0, [mid], [mid, dependency])
        _, offer, _ = self.exchange_offer(1, 0, self.ts_value, self.py_value, "retry")
        selected = self.py_value(0, {"op": "send", "request_id": "req_hint_ts_guarded_selection",
            "recipients": [host.identities[1].key_id], "control": control("select", offer_message_id=offer["message_id"], memory_id=mid)})
        self.assertFalse(self.ts_value(1, {"op": "receive"})["errors"])
        host.relays[1].stop()
        pending = self.ts_value(1, {"op": "receive", "respond_to": selected["message_id"]})
        self.assertEqual(pending["stored_nodes"], 1, pending)
        frozen = outbox_row(host.receiver, pending["message_id"])
        self.assertIsNotNone(frozen["envelope"])
        self.set_policy(1, 0, [mid], [mid], revision=2)
        host.relays[1].start()
        before = [vault_snapshot(endpoint) for endpoint in (host.sender, host.receiver)]
        # A fresh TS process reads the existing queue and current local policy.
        result = self.ts(1, {"op": "receive", "respond_to": selected["message_id"]})
        self.assertFalse(any(call["path"] == "/v1/messages" for call in result["calls"]))
        self.assertEqual(outbox_row(host.receiver, pending["message_id"])["body"], frozen["body"])
        self.assertEqual(outbox_row(host.receiver, pending["message_id"])["envelope"], frozen["envelope"])
        self.assertEqual([vault_snapshot(endpoint) for endpoint in (host.sender, host.receiver)], before)

    def test_typescript_offer_expiration_and_policy_binding_fail_closed(self):
        host = self.host
        host.join_receiver()
        mid = self.remember(1, "expired", "Synthetic needle expired offer")
        current = self.set_policy(1, 0, [mid], [mid])
        path = host.receiver.directory / "hint-policy.json"
        original = path.read_bytes()
        bad = self.ts(1, policy_doc={**current, "owner_key_id": host.identities[0].key_id})
        self.assertFalse(bad["policyResult"]["ok"])
        self.assertEqual(path.read_bytes(), original)
        requested = self.py_value(0, {"op": "send", "request_id": "req_hint_ts_expired_query",
            "recipients": [host.identities[1].key_id], "control": control("query", query="Synthetic needle")})
        self.assertFalse(self.ts_value(1, {"op": "receive"})["errors"])
        for relay in host.relays:
            relay.stop()
        pending = self.ts_value(1, {"op": "receive", "respond_to": requested["message_id"]})
        self.assertEqual(pending["stored_nodes"], 0, pending)
        before = outbox_row(host.receiver, pending["message_id"])
        atomic_write(path, canonical_bytes({**current, "expires_at": int(time.time()) - 1}), replace=True)
        for relay in host.relays:
            relay.start()
        result = self.ts(1, {"op": "receive", "respond_to": requested["message_id"]})
        self.assertFalse(any(call["path"] == "/v1/messages" for call in result["calls"]))
        after = outbox_row(host.receiver, pending["message_id"])
        self.assertEqual((after["body"], after["envelope"]), (before["body"], before["envelope"]))
        self.assertIsNone(vault_snapshot(host.sender))

    def test_typescript_four_escaped_unicode_hints_read_within_budget_without_vault(self):
        host = self.host
        host.join_receiver()
        body = parser_vectors()[0][-2]
        identifier = "msg_" + "5" * 64
        envelope = seal(canonical_bytes(body), signer=host.identities[0], network_id=host.network_id,
            message_id=identifier, recipients=[{"signing_key_id": host.identities[1].key_id,
                "encryption_key": host.encryption[1].public_descriptor()}],
            roster_version=host.roster["payload"]["version"], roster_sha256=document_sha256(host.roster))
        for relay in host.relays:
            host.transports[0].request(relay.url, "POST", "/v1/messages", {"envelope": envelope, "roster": host.roster})
        self.assertFalse(self.ts_value(1, {"op": "receive"})["errors"])
        read = self.ts(1, {"op": "receive", "message_id": identifier})
        self.assertFalse(read["calls"])
        response, = read["results"]
        self.assertTrue(response["ok"], response)
        self.assertEqual(response["result"]["control"], body["control"])
        self.assertEqual(response["result"], self.py_value(1, {"op": "receive", "message_id": identifier}))
        self.assertLessEqual(len(canonical_bytes(response)), 8192)
        self.assertIsNone(vault_snapshot(host.sender))
        self.assertIsNone(vault_snapshot(host.receiver))


if __name__ == "__main__":
    unittest.main()
