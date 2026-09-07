"""Native Node/jose endpoints using three owned, independently signed relays.

All node membership comes from real invitation challenge/consume requests.
The tests use synthetic records and owned loopback services, not AI models.
"""
import json
import subprocess
import unittest

from memory_vault import canonical_bytes
from memory_vault_network import validate_relay_pool
from memory_vault_storage import atomic_write
from tests import test_network_typescript_agent_network as runtime
from tests.test_network_hints import control, outbox_row
from tests import test_network_hints_typescript as hint_runtime
from tests.test_network_message_semantics import records, proofs, vault_snapshot
from tests.test_network_relay_pool import PoolHost, stored_message


PUMP_DRIVER = r"""
import child from 'node:child_process';
import {syncBuiltinESMExports} from 'node:module';
let subprocessCalls=0;
const deny=()=>{subprocessCalls++;throw Error('native peer must not delegate');};
for(const key of ['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork'])child[key]=deny;
syncBuiltinESMExports();
const {NetworkPeer}=await import('./peer.ts');
const {HTTPTransport}=await import('./transport.ts');
const chunks=[];for await(const chunk of process.stdin)chunks.push(chunk);
const input=JSON.parse(Buffer.concat(chunks).toString('utf8'));
const transport=new HTTPTransport(),calls=[],request=transport.request.bind(transport);
transport.request=async(base,method,path,value,deadline)=>{calls.push({base,method,path});return request(base,method,path,value,deadline);};
const peer=new NetworkPeer(input.network_config,{transport});
try{const result=await peer.pump(...input.budget);process.stdout.write(JSON.stringify({result,calls,subprocessCalls}));}
finally{peer.close();transport.close();}
"""


class TypeScriptRelayPoolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        hint_runtime.TypeScriptHintExchangeTests.setUpClass.__func__(cls)
        (cls.fixture / "pool-pump.mjs").write_text(PUMP_DRIVER)

    ts = hint_runtime.TypeScriptHintExchangeTests.ts
    ts_value = runtime.TypeScriptAgentNetworkTests.ts_value
    py_value = runtime.TypeScriptAgentNetworkTests.py_value
    set_policy = hint_runtime.TypeScriptHintExchangeTests.set_policy

    def join_both(self):
        host = self.host
        for index in range(3):
            self.assertEqual(host.node_rows(index, "members"), [])
        joined = self.ts_value(0, {"op": "connect", "request_id": "req_synthetic_ts_pool_join",
                                   "invitation": host.invitations[0]})
        self.assertEqual((joined["joined_nodes"], joined["candidate_nodes"], joined["configured_nodes"]), (3, 3, 1), joined)
        self.assertFalse(joined["errors"])
        self.assertEqual(host.join(1)["joined_nodes"], 3)
        expected = {identity.key_id for identity in host.identities[:2]}
        for index in range(3):
            self.assertEqual({row["key_id"] for row in host.node_rows(index, "members")}, expected)

    def ts_pump(self, index, maximum_messages=1, maximum_seconds=1, receive_limit=0):
        process = subprocess.run([self.node, "--experimental-strip-types", str(self.fixture / "pool-pump.mjs")],
            input=json.dumps({"network_config": str(self.host.net_configs[index]),
                "budget": [maximum_messages, maximum_seconds, receive_limit]}).encode(),
            cwd=self.fixture, capture_output=True, timeout=15)
        self.assertEqual(process.returncode, 0, process.stderr.decode(errors="replace")[-4000:])
        result = json.loads(process.stdout)
        self.assertEqual(result["subprocessCalls"], 0)
        return result

    def test_real_join_different_bootstraps_and_both_language_transfers_after_exit(self):
        with PoolHost(self) as self.host:
            host = self.host
            self.join_both()
            refreshed = self.ts_value(0, {"op": "connect", "request_id": "req_synthetic_ts_pool_fresh_invite",
                "invitation": host.invitation_for(0, suffix="fresh")})
            self.assertEqual(refreshed["joined_nodes"], 3, refreshed)
            self.assertFalse(refreshed["errors"])
            self.assertEqual([len(host.node_rows(index, "members")) for index in range(3)], [2, 2, 2])
            discoveries = [self.ts_value(0, {"op": "discover", "online": True}),
                           self.py_value(1, {"op": "discover", "online": True})]
            for result in discoveries:
                self.assertEqual((result["configured_nodes"], result["candidate_nodes"], result["replica_target"]), (1, 3, 2))
                self.assertTrue(result["relay_pool_enabled"])
                self.assertFalse(result["pool_partial"])
            self.assertEqual(discoveries[0]["nodes"], discoveries[1]["nodes"])
            self.assertEqual(discoveries[0]["directory_version"], host.directory["payload"]["version"])
            host.relays[0].stop()
            endpoints = [host.sender, host.receiver]
            for owner, recipient, send, receive in ((0, 1, self.ts_value, self.py_value),
                                                   (1, 0, self.py_value, self.ts_value)):
                with self.subTest(owner=owner):
                    before = [vault_snapshot(endpoint) for endpoint in endpoints]
                    chat = send(owner, {"op": "send", "request_id": "req_synthetic_ts_pool_chat_" + str(owner),
                        "recipients": [host.identities[recipient].key_id], "text": "Synthetic chat after bootstrap exit."})
                    self.assertEqual((chat["stored_nodes"], chat["replica_target"]), (2, 2), chat)
                    self.assertFalse(chat["degraded"])
                    stored_message(self, receive(recipient, {"op": "receive"}), chat["message_id"])
                    self.assertEqual([vault_snapshot(endpoint) for endpoint in endpoints], before)
                    root = send(owner, {"op": "remember", "request_id": "req_synthetic_ts_pool_root_" + str(owner),
                        "kind": "observation", "text": "Synthetic independent source " + str(owner)})["memory_id"]
                    original, signatures = records(endpoints[owner]), proofs(endpoints[owner])
                    request = {"op": "send", "request_id": "req_synthetic_ts_pool_share_" + str(owner),
                        "recipients": [host.identities[recipient].key_id], "memory_ids": [root], "text": "Synthetic note."}
                    sent = send(owner, request)
                    self.assertEqual(sent["stored_nodes"], 2, sent)
                    saved = stored_message(self, receive(recipient, {"op": "receive"}), sent["message_id"])
                    self.assertEqual(saved["share"]["admission"], "verified")
                    self.assertEqual(records(endpoints[recipient])[root], original[root])
                    self.assertEqual(proofs(endpoints[recipient])[root], signatures[root])
                    send(owner, {"op": "receive"})
                    self.assertTrue(send(owner, request)["endpoint_validated"])
                    self.assertEqual(receive(recipient, {"op": "receive"})["messages"], [])
            host.unchanged_config()

    def test_both_languages_hint_batch_and_pure_local_batch_recall_after_seed_exit(self):
        with PoolHost(self) as self.host:
            host = self.host
            self.join_both()
            host.relays[0].stop()
            endpoints = [host.sender, host.receiver]
            for owner, requester, owner_call, requester_call in ((0, 1, self.py_value, self.ts_value),
                                                               (1, 0, self.ts_value, self.py_value)):
                with self.subTest(owner=owner):
                    def remember(suffix, text, relations=None):
                        return owner_call(owner, {"op": "remember", "request_id": "req_synthetic_ts_pool_hint_" + str(owner) + suffix,
                            "kind": "observation", "text": text, "relations": relations or []})["memory_id"]
                    dependency = remember("dep", "Synthetic pool setup " + str(owner))
                    roots = [remember("root" + str(index), "Synthetic pool hint experience " + str(owner) + str(index),
                        [{"type": "derived_from", "target": dependency}]) for index in range(2)]
                    self.set_policy(owner, requester, roots, [dependency, *roots])
                    before = [vault_snapshot(endpoint) for endpoint in endpoints]
                    query = requester_call(requester, {"op": "send", "request_id": "req_synthetic_ts_pool_query_" + str(owner),
                        "recipients": [host.identities[owner].key_id], "control": control("query", query="Synthetic pool hint")})
                    stored_message(self, owner_call(owner, {"op": "receive"}), query["message_id"])
                    offer = owner_call(owner, {"op": "receive", "respond_to": query["message_id"]})
                    stored_message(self, requester_call(requester, {"op": "receive"}), offer["message_id"])
                    self.assertEqual([vault_snapshot(endpoint) for endpoint in endpoints], before)
                    select = requester_call(requester, {"op": "send", "request_id": "req_synthetic_ts_pool_select_" + str(owner),
                        "recipients": [host.identities[owner].key_id], "control": control("select", query_message_id=query["message_id"],
                            selections=[{"offer_message_id": offer["message_id"], "memory_id": root} for root in roots[::-1]])})
                    stored_message(self, owner_call(owner, {"op": "receive"}), select["message_id"])
                    transfer = owner_call(owner, {"op": "receive", "respond_to": select["message_id"]})
                    self.assertEqual((transfer["stored_nodes"], transfer["replica_target"]), (2, 2), transfer)
                    result = stored_message(self, requester_call(requester, {"op": "receive"}), transfer["message_id"])
                    self.assertEqual(result["share"]["admission"], "verified")
                    for root in [*roots, dependency]:
                        self.assertEqual(records(endpoints[requester])[root], records(endpoints[owner])[root])
                        self.assertEqual(proofs(endpoints[requester])[root], proofs(endpoints[owner])[root])
                    if requester == 1:
                        read = self.ts(requester, {"op": "recall", "received_batch_message_id": transfer["message_id"]})
                        self.assertFalse(read["calls"])
                        self.assertTrue(read["results"][0]["ok"], read)
                        view = read["results"][0]["result"]
                    else:
                        count = len(host.transports[requester].calls)
                        view = requester_call(requester, {"op": "recall", "received_batch_message_id": transfer["message_id"]})
                        self.assertEqual(len(host.transports[requester].calls), count)
                    self.assertEqual(view["selected_memory_ids"], roots[::-1])
            host.unchanged_config()

    def test_native_frozen_retry_restart_uses_fair_pool_budget_and_preserves_receipts(self):
        with PoolHost(self) as self.host:
            host = self.host
            self.join_both()
            for index in range(3):
                host.fault(index, reject_messages=True)
            sent = self.ts_value(0, {"op": "send", "request_id": "req_synthetic_ts_pool_frozen",
                "recipients": [host.identities[1].key_id], "text": "Synthetic frozen pool message."})
            self.assertEqual(sent["stored_nodes"], 0, sent)
            prior = outbox_row(host.sender, sent["message_id"])
            self.assertIsNotNone(prior["envelope"])
            ordered = sorted(range(3), key=lambda index: host.node_entries[index]["signing_key"]["key_id"])
            slow = ordered[0]
            for index in range(3):
                host.relays[index].stop()
                host.relays[index].start()
            host.fault(slow, delay_status=True)
            passes = []
            for _ in range(3):
                checked = self.ts_pump(0)
                passes.append(checked)
                if checked["result"]["remaining_outbox"] == 0:
                    break
            self.assertEqual(passes[-1]["result"]["remaining_outbox"], 0, passes)
            self.assertTrue(any(item["code"] == "network_relay_attempt_budget" for checked in passes
                for result in checked["result"]["outbound"] for item in result["errors"]), passes)
            gets = [call for checked in passes for call in checked["calls"] if call["base"] != host.authority.url and call["method"] == "GET"]
            self.assertLessEqual(len(gets), 9)
            after = outbox_row(host.sender, sent["message_id"])
            self.assertEqual(bytes(after["body"]), bytes(prior["body"]))
            self.assertEqual(bytes(after["envelope"]), bytes(prior["envelope"]))
            self.assertEqual(len(json.loads(after["receipts"])), 2)
            self.assertEqual(stored_message(self, self.py_value(1, {"op": "receive"}), sent["message_id"])["text"], "Synthetic frozen pool message.")
            for index in range(3):
                host.relays[index].stop()
            before = bytes(after["receipts"], "utf8")
            checked = self.ts_pump(0)
            self.assertEqual(checked["result"]["remaining_outbox"], 0, checked)
            self.assertEqual(outbox_row(host.sender, sent["message_id"])["receipts"].encode(), before)
            local = self.ts(0, {"op": "discover"}, {"op": "recall", "query": "Synthetic"})
            self.assertFalse(local["calls"])
            host.unchanged_config()

    def test_exact_local_pool_config_and_fixed_opt_out_contact_boundary(self):
        vectors = [{"maximum_nodes": 2, "replica_target": 1}, {"maximum_nodes": 4, "replica_target": 2},
            None, {}, {"maximum_nodes": True, "replica_target": 1}, {"maximum_nodes": 1, "replica_target": 1},
            {"maximum_nodes": 5, "replica_target": 2}, {"maximum_nodes": 3, "replica_target": 3},
            {"maximum_nodes": 3, "replica_target": False}, {"maximum_nodes": 3, "replica_target": 1, "extra": 1}]
        driver = self.fixture / "pool-config.mjs"
        driver.write_text("import fs from 'node:fs';import{validateRelayPool}from'./nodes.ts';process.stdout.write(JSON.stringify(JSON.parse(fs.readFileSync(0,'utf8')).map(value=>{try{return{ok:true,value:validateRelayPool(value)};}catch(error){return{ok:false,code:error.code};}})));")
        expected = []
        for value in vectors:
            try:
                expected.append({"ok": True, "value": validate_relay_pool(value)})
            except Exception as error:
                expected.append({"ok": False, "code": error.code})
        process = subprocess.run([self.node, "--experimental-strip-types", str(driver)],
            input=json.dumps(vectors).encode(), cwd=self.fixture, capture_output=True, timeout=20)
        self.assertEqual(process.returncode, 0, process.stderr.decode(errors="replace")[-2000:])
        self.assertEqual(json.loads(process.stdout), expected)
        with PoolHost(self, pool=False) as self.host:
            host = self.host
            public = host.root / "synthetic-pool-setup-issuer.json"
            output = host.root / "synthetic-pool-setup-network.json"
            atomic_write(public, canonical_bytes(host.issuer.public_descriptor()), replace=False)
            existing = json.loads(host.net_configs[0].read_bytes())
            driver = self.fixture / "pool-setup.mjs"
            driver.write_text("import fs from 'node:fs';import{configureNetwork}from'./setup.ts';process.stdout.write(JSON.stringify(configureNetwork(JSON.parse(fs.readFileSync(0,'utf8')))));")
            configured = subprocess.run([self.node, "--experimental-strip-types", str(driver)],
                input=json.dumps({"clientConfig": str(host.configs[0]), "encryptionKey": existing["encryption_key_path"],
                    "issuerPublic": str(public), "networkId": host.network_id, "authorityUrl": host.authority.url,
                    "relays": [host.relays[0].url], "output": str(output),
                    "relayPool": {"maximum_nodes": 3, "replica_target": 2}}).encode(),
                cwd=self.fixture, capture_output=True, timeout=20)
            self.assertEqual(configured.returncode, 0, configured.stderr.decode(errors="replace")[-2000:])
            self.assertFalse(json.loads(configured.stdout)["network_accessed"])
            self.assertEqual(json.loads(output.read_bytes())["relay_pool"], {"maximum_nodes": 3, "replica_target": 2})
            result = self.ts(0, {"op": "connect", "request_id": "req_synthetic_ts_fixed_join", "invitation": host.invitations[0]},
                {"op": "discover", "online": True}, {"op": "send", "request_id": "req_synthetic_ts_fixed_send",
                    "recipients": [host.identities[1].key_id], "text": "Synthetic fixed-only message."})
            self.assertTrue(all(item["ok"] for item in result["results"]), result)
            self.assertEqual(result["results"][0]["result"]["joined_nodes"], 1)
            self.assertTrue(all("relay_pool_enabled" not in item["result"] for item in result["results"]))
            self.assertEqual({call["base"] for call in result["calls"] if call["base"] != host.authority.url}, {host.relays[0].url})
            self.assertEqual(host.node_rows(2, "members"), [])
            host.unchanged_config()
