"""Native TypeScript/Python Agents using two actual owned loopback relays.

The only services are disposable synthetic issuer/node processes. Node calls
Agent.handle directly and is prevented from delegating to Python/subprocesses.
This is independent runtime/protocol evidence, not a model/provider claim.
"""
from __future__ import annotations

from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from memory_vault import canonical_bytes, strict_json_loads
from memory_vault_agent import Agent
from memory_vault_client import ClientConfig
from memory_vault_relay import Relay
from tests import test_network_node_runtime as runtime


ROOT = Path(__file__).resolve().parents[1]
DRIVER = r"""
import child from 'node:child_process';
import {syncBuiltinESMExports} from 'node:module';
let subprocessCalls=0;
const deny=()=>{subprocessCalls++;throw Error('native Agent must not delegate to a subprocess');};
for(const name of ['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork'])child[name]=deny;
syncBuiltinESMExports();
const {Agent}=await import('./agent.ts');
const {HTTPTransport}=await import('./transport.ts');
const chunks=[];let size=0;
for await(const chunk of process.stdin){size+=chunk.length;if(size>1048576)throw Error('synthetic fixture limit');chunks.push(chunk);}
const input=JSON.parse(Buffer.concat(chunks).toString('utf8'));
const transport=new HTTPTransport(),calls=[],request=transport.request.bind(transport);
transport.request=async(base,method,path,value,deadline)=>{
  calls.push({base,method,path});
  return request(base,method,path,value,deadline);
};
const agent=new Agent(input.client_config,input.network_config,{transport}),results=[];
try{for(const value of input.requests)results.push(await agent.handle(value));}
finally{transport.close();}
process.stdout.write(JSON.stringify({results,calls,subprocessCalls}));
"""


@unittest.skipUnless(os.name == "posix", "owned HTTP services and private TS storage require POSIX")
class TypeScriptAgentNetworkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.node = os.environ.get("MEMORY_VAULT_NODE") or shutil.which("node")
        if not cls.node:
            raise unittest.SkipTest("Existing Node >=22.19 required")
        version = subprocess.check_output([cls.node, "--version"], text=True).strip()
        major, minor, *_ = map(int, version.lstrip("v").split("."))
        if major < 22 or (major == 22 and minor < 19):
            raise unittest.SkipTest("Existing Node >=22.19 required")
        package = ROOT / "clients/typescript/network/node_modules/jose"
        if selected := os.environ.get("MEMORY_VAULT_JOSE_MODULE"):
            entry = Path(selected).expanduser().resolve()
            if entry.parts[-3:] != ("dist", "webapi", "index.js"):
                raise RuntimeError("Expected explicit locked jose entry")
            package = entry.parents[2]
        if not (package / "package.json").is_file():
            raise unittest.SkipTest("Existing jose required; tests do not install packages")
        metadata = json.loads((package / "package.json").read_text())
        if metadata.get("name") != "jose" or metadata.get("version") != "6.2.10":
            raise RuntimeError("Locked jose 6.2.10 required")
        temporary = tempfile.TemporaryDirectory(prefix="memory-vault-ts-agent-network-synthetic-")
        cls.addClassCleanup(temporary.cleanup)
        cls.fixture = Path(temporary.name).resolve()
        source = ROOT / "clients/typescript/network"
        for file in [*source.glob("*.ts"), source / "package.json"]:
            shutil.copyfile(file, cls.fixture / file.name)
        (cls.fixture / "node_modules").mkdir()
        (cls.fixture / "node_modules/jose").symlink_to(package, target_is_directory=True)
        (cls.fixture / "driver.mjs").write_text(DRIVER)

    def setUp(self):
        # Composition reuses only the synthetic fixture, not another suite's
        # test methods. Cleanup verifies every owned service actually stopped.
        self.host = runtime.NetworkNodeRuntimeTests("test_independent_refresh_and_persistent_drain_fence_over_real_http")
        self.addCleanup(self.host.doCleanups)
        self.host.setUp()
        self.addCleanup(self.host.tearDown)

    def ts(self, index, *requests):
        process = subprocess.run([self.node, "--experimental-strip-types", str(self.fixture / "driver.mjs")],
            input=json.dumps({"client_config": str(self.host.configs[index]),
                              "network_config": str(self.host.net_configs[index]), "requests": requests}).encode(),
            cwd=self.fixture, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45)
        self.assertEqual(process.returncode, 0, process.stderr.decode(errors="replace")[-4000:])
        result = json.loads(process.stdout)
        self.assertEqual(result["subprocessCalls"], 0)
        self.assertEqual(len(result["results"]), len(requests))
        for response in result["results"]:
            self.assertLessEqual(len(canonical_bytes(response)), 8192)
            self.assertFalse(response["authority"]["authorization_eligible"])
            self.assertFalse(response["authority"]["execution_eligible"])
        return result

    def ts_value(self, index, request):
        response = self.ts(index, request)["results"][0]
        self.assertTrue(response["ok"], response)
        return response["result"]

    def py_value(self, index, request):
        response = Agent(self.host.configs[index], self.host.net_configs[index],
                         transport=self.host.transports[index]).handle(request)
        self.assertTrue(response["ok"], response)
        self.assertLessEqual(len(canonical_bytes(response)), 8192)
        return response["result"]

    def records(self, index):
        config = ClientConfig.load(self.host.configs[index])
        with closing(config.vault()._connect()) as db:
            return {row["memory_id"]: (row["record_json"], row["attestation_json"])
                    for row in db.execute("SELECT m.memory_id,m.record_json,a.attestation_json FROM memories m "
                                          "LEFT JOIN record_admissions a ON a.memory_id=m.memory_id")}

    def outbox(self, index):
        with (self.host.sender if index == 0 else self.host.receiver).db() as db:
            return {row["request_id"]: dict(row) for row in db.execute("SELECT * FROM outbox")}

    def assert_relay_bytes(self, sent):
        """Each node stores exactly the sender's frozen canonical envelope."""
        expected, original_receipts = {}, {}
        for row in sent:
            encoded = bytes(row["envelope"])
            self.assertEqual(canonical_bytes(strict_json_loads(encoded)), encoded)
            expected[row["message_id"]] = encoded
        for service in self.host.relays:
            relay = Relay(service.config)
            with relay._transaction() as db:
                messages = list(db.execute("SELECT * FROM messages ORDER BY sequence"))
                self.assertEqual(len(messages), len(expected))
                for row in messages:
                    encoded = expected[row["message_id"]]
                    self.assertEqual(hashlib.sha256(encoded).hexdigest(), row["envelope_sha256"])
                    self.assertEqual((relay.object_directory / (row["envelope_sha256"] + ".json")).read_bytes(), encoded)
                    self.assertEqual(db.execute("SELECT COUNT(*) FROM recipients WHERE message_id=?",
                                                (row["message_id"],)).fetchone()[0], 1)
                # Both recipients have already acknowledged their received
                # message, with no duplicate acknowledgement per second node.
                receipts = list(db.execute("SELECT * FROM receipts"))
                self.assertEqual(len(receipts), len(expected))
                for receipt in receipts:
                    proof = strict_json_loads(receipt["document"])
                    body = proof["payload"]["body"]
                    self.assertEqual(body["state"], "validated_saved")
                    self.assertEqual(body["envelope_sha256"], hashlib.sha256(expected[receipt["message_id"]]).hexdigest())
                    original_receipts.setdefault((receipt["message_id"], receipt["key_id"]), set()).add(bytes(receipt["document"]))
                    recipient = (self.host.sender if receipt["key_id"] == self.host.identities[0].key_id else self.host.receiver)
                    with recipient.db() as endpoint:
                        local = endpoint.execute("SELECT value FROM state WHERE key=?",
                            ("ack:" + service.url + ":" + receipt["message_id"],)).fetchone()
                        self.assertIsNotNone(local)
                        self.assertEqual(canonical_bytes(strict_json_loads(local[0])), bytes(receipt["document"]))
        for client in (self.host.sender, self.host.receiver):
            with client.db() as db:
                for acknowledgement in db.execute("SELECT * FROM acknowledgements"):
                    self.assertIn(bytes(acknowledgement["receipt"]), original_receipts[
                        (acknowledgement["message_id"], acknowledgement["recipient"])])

    def assert_delivered(self, result, text, selected_id):
        self.assertFalse(result["errors"], result)
        self.assertEqual(len(result["messages"]), 1, result)
        message = result["messages"][0]
        self.assertEqual(message["text"], text)
        self.assertEqual(message["state"], "validated_saved")
        self.assertFalse(message["understood"])
        self.assertTrue(message["text_memory_id"])
        self.assertGreaterEqual(message["share"]["records_added"], 2 if selected_id else 1)
        return message

    def test_native_six_operations_share_same_queue_records_and_proofs_across_languages(self):
        host = self.host
        connect = {"op": "connect", "invitation": host.invitation, "request_id": "req_native_synthetic_join"}
        self.assertEqual(self.ts_value(1, connect)["joined_nodes"], 2)
        self.assertEqual(self.py_value(1, connect)["joined_nodes"], 2)
        observed = self.ts(1, {"op": "discover", "online": True})
        discovered = observed["results"][0]
        self.assertTrue(discovered["ok"], discovered)
        self.assertTrue(discovered["result"]["network_accessed"])
        self.assertTrue(observed["calls"])
        self.assertTrue(self.py_value(0, {"op": "discover", "online": True})["network_accessed"])

        remember = {"op": "remember", "request_id": "req_native_ts_selected", "kind": "fact",
                    "text": "Synthetic selected TS memory — 火星站备用电源", "entities": ["synthetic power"]}
        remembered = self.ts_value(1, remember)
        selected = remembered["memory_id"]
        self.assertEqual(self.py_value(1, remember)["memory_id"], selected)
        self.assertEqual(self.py_value(1, {"op": "recall", "memory_id": selected})["hits"][0]["text"], remember["text"])
        text = "Synthetic TS→Python native message 👩🏽‍🚀"
        request = {"op": "send", "request_id": "req_native_ts_message", "recipients": [host.identities[0].key_id],
                   "text": text, "memory_ids": [selected]}
        sent = self.ts_value(1, request)
        self.assertEqual(sent["stored_nodes"], 2, sent)
        frozen = self.outbox(1)[request["request_id"]]
        self.assertEqual(self.py_value(1, request)["message_id"], sent["message_id"])
        self.assertEqual(self.outbox(1)[request["request_id"]]["envelope"], frozen["envelope"])
        delivered = self.assert_delivered(self.py_value(0, {"op": "receive"}), text, selected)
        self.assertEqual(self.py_value(0, {"op": "recall", "memory_id": selected})["hits"][0]["text"], remember["text"])
        self.assertEqual(self.py_value(0, {"op": "recall", "memory_id": delivered["text_memory_id"]})["hits"][0]["text"], text)
        self.assertFalse(self.ts_value(1, {"op": "receive"})["errors"])
        self.assertEqual(self.records(0), self.records(1))

        reverse = {"op": "remember", "request_id": "req_native_python_selected", "kind": "decision",
                   "text": "Synthetic Python decision: reserve backup battery.", "entities": ["synthetic power"]}
        reverse_id = self.py_value(0, reverse)["memory_id"]
        self.assertEqual(self.ts_value(0, reverse)["memory_id"], reverse_id)
        response_text = "Synthetic Python→TS native response"
        reply = {"op": "send", "request_id": "req_native_python_message", "recipients": [host.identities[1].key_id],
                 "text": response_text, "memory_ids": [reverse_id]}
        response = self.py_value(0, reply)
        frozen_reply = self.outbox(0)[reply["request_id"]]
        self.assertEqual(self.ts_value(0, reply)["message_id"], response["message_id"])
        self.assertEqual(self.outbox(0)[reply["request_id"]]["envelope"], frozen_reply["envelope"])
        self.assert_delivered(self.ts_value(1, {"op": "receive"}), response_text, reverse_id)
        restored = self.ts_value(1, {"op": "recall", "memory_id": reverse_id})
        self.assertEqual(restored["hits"][0]["text"], reverse["text"])
        self.assertTrue(restored["hits"][0]["verification"]["eligible_for_context"])
        self.assertFalse(self.py_value(0, {"op": "receive"})["errors"])
        self.assertEqual(self.records(0), self.records(1))
        self.assertEqual(len(self.records(0)), 4)
        self.assert_relay_bytes([frozen, frozen_reply])
        for index, client in enumerate((host.sender, host.receiver)):
            with client.db() as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM outbox").fetchone()[0], 1)
                self.assertEqual(db.execute("SELECT COUNT(*) FROM inbox").fetchone()[0], 1)
                self.assertEqual(db.execute("SELECT COUNT(*) FROM acknowledgements").fetchone()[0], 1)
                self.assertEqual(db.execute("SELECT COUNT(*) FROM quarantine").fetchone()[0], 0)
            self.assertEqual(self.ts_value(index, {"op": "receive"})["messages"], [])
            self.assertEqual(self.py_value(index, {"op": "receive"})["messages"], [])

    def test_native_offline_queue_restarts_in_other_language_without_reencryption(self):
        host = self.host
        self.assertEqual(self.py_value(1, {"op": "connect", "invitation": host.invitation,
                                          "request_id": "req_native_offline_join"})["joined_nodes"], 2)
        for relay in host.relays:
            relay.stop()
        request = {"op": "send", "request_id": "req_native_offline_send", "recipients": [host.identities[1].key_id],
                   "text": "Synthetic native offline queue survives independent processes."}
        queued = self.ts_value(0, request)
        self.assertEqual(queued["stored_nodes"], 0)
        self.assertTrue(queued["errors"])
        self.assertTrue(all(error["retryable"] for error in queued["errors"]))
        before = self.outbox(0)[request["request_id"]]
        self.assertIsNone(before["envelope"])
        host.relays[0].start()
        partial = self.py_value(0, request)
        self.assertEqual(partial["stored_nodes"], 1, partial)
        frozen = self.outbox(0)[request["request_id"]]
        self.assertIsNotNone(frozen["envelope"])
        self.assertEqual(frozen["body"], before["body"])
        host.relays[1].start()
        complete = self.ts_value(0, request)
        self.assertEqual(complete["stored_nodes"], 2, complete)
        after = self.outbox(0)[request["request_id"]]
        for key in ("message_id", "input_sha", "body", "envelope", "roster", "recipients"):
            self.assertEqual(after[key], frozen[key], key)
        self.assert_delivered(self.py_value(1, {"op": "receive"}), request["text"], None)
        self.assertFalse(self.ts_value(0, {"op": "receive"})["errors"])
        self.assertEqual(self.records(0), self.records(1))
        self.assert_relay_bytes([after])
        conflicted = self.ts(0, {**request, "text": "Synthetic conflicting retry must not replace frozen bytes"})["results"][0]
        self.assertFalse(conflicted["ok"])
        self.assertEqual(conflicted["error"]["code"], "network_request_id_conflict")
        self.assertEqual(self.outbox(0)[request["request_id"]]["envelope"], frozen["envelope"])
        with host.sender.db() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM outbox").fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM acknowledgements").fetchone()[0], 1)
        self.assertEqual(self.ts_value(1, {"op": "receive"})["messages"], [])


if __name__ == "__main__":
    unittest.main()
