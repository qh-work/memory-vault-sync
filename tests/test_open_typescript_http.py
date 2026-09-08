"""Native mixed-language sockets, shared restart state and the six-op Agent.

Only owned synthetic loopback services; no source-cap override or routing oracle.
Every native driver forbids subprocess delegation before importing project code.
"""
import asyncio
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import tempfile
import time
import unittest

from memory_vault import canonical_bytes
from memory_vault_agent import Agent
from memory_vault_network_crypto import EncryptionIdentity
from memory_vault_open_control import contact_key, issue_contact, issue_node, sign_request, verify_response
from memory_vault_open_node import OpenParticipant
from memory_vault_open_transport import OpenHTTPTransport
from memory_vault_storage import atomic_write
from memory_vault_trust import Identity
from tests.test_open_node import HTTPNodes
from tests import test_network_typescript_agent_network as ts_runtime

GUARD = r"""
import child from 'node:child_process';
import {syncBuiltinESMExports} from 'node:module';
let subprocessCalls=0;
for(const name of ['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork'])child[name]=()=>{subprocessCalls++;throw Error('native open endpoint cannot delegate');};
syncBuiltinESMExports();
"""
DRIVER = GUARD + r"""
const {Agent}=await import('./agent.ts');
const {OpenParticipant}=await import('./open-participant.ts');
const {OpenHTTPTransport,endpoint,permittedAddress}=await import('./open-transport.ts');
const {performance}=await import('node:perf_hooks');
const chunks=[];let size=0;
for await(const chunk of process.stdin){size+=chunk.length;if(size>1048576)throw Error('synthetic input limit');chunks.push(chunk);}
const input=JSON.parse(Buffer.concat(chunks).toString('utf8')),results=[],calls=[];
const original=OpenHTTPTransport.prototype.request;
OpenHTTPTransport.prototype.request=async function(base,value,deadline){
  const response=await original.call(this,base,value,deadline);
  calls.push({base,request:value,response:response.response,observed_address:response.observed_address});
  return response;
};
let participant;
try{
  if(input.mode==='dns'){
    const dns=(await import('node:dns')).default,originalDNS=dns.lookup;let lookups=0;
    const transport=new OpenHTTPTransport({allow_loopback:input.allow_loopback??false});
    try{
      if(input.test==='capacity'){
        const pending=[];
        dns.lookup=(_host,_options,callback)=>{lookups++;pending.push(callback);};
        const attempt=()=>transport.request('https://synthetic.example',{synthetic:true},performance.now()/1000+.08)
          .then(()=>({ok:true}),error=>({ok:false,code:error.code}));
        results.push(...await Promise.all([attempt(),attempt(),attempt()]));
        results.push(await attempt());
        for(const callback of pending)callback(null,[{address:'8.8.8.8',family:4}]);
      }else{
        dns.lookup=(_host,_options,callback)=>{lookups++;queueMicrotask(()=>callback(null,input.answers));};
        try{results.push({ok:true,value:await transport.request(input.base,{synthetic:true},performance.now()/1000+2)});}
        catch(error){results.push({ok:false,code:error.code});}
      }
    }finally{dns.lookup=originalDNS;transport.close();}
    results.push({lookups});
  }else if(input.mode==='agent'){
    const agent=new Agent(input.client_config,input.network_config);
    for(const request of input.requests)results.push(await agent.handle(request));
  }else if(input.mode==='transport'){
    const transport=new OpenHTTPTransport({allow_loopback:true});
    try{for(const operation of input.operations){try{
      results.push({ok:true,value:operation.endpoint?endpoint(operation.endpoint,operation.allow_loopback??false):
        operation.address?permittedAddress(operation.address,operation.allow_loopback??false):
        await transport.request(operation.base,{synthetic:true},performance.now()/1000+(operation.seconds??2))});
    }catch(error){results.push({ok:false,code:error.code,retryable:error.retryable??false});}}}finally{transport.close();}
  }else{
    participant=new OpenParticipant(input.identity,input.state,input.options);
    for(const operation of input.operations){try{
      const value=operation.op==='find'?await participant.findContact(operation.key_id):
        operation.op==='publish'?await participant.publishContact(operation.contact):
        operation.op==='join'?await participant.join():operation.op==='maintain'?await participant.maintain():
        operation.op==='pending'?{count:participant.pending.size,verified:participant.table.hasVerified(operation.node)}:
        operation.op==='fail'?participant.table.markFailed(operation.key_id):participant.handle(operation.request);
      results.push({ok:true,value});
    }catch(error){results.push({ok:false,code:error.code,retryable:error.retryable??false});}}
  }
}finally{participant?.close();}
process.stdout.write(JSON.stringify({results,calls,subprocessCalls}));
"""
NODE_DRIVER = GUARD + r"""
const {startOpenNode}=await import('./open-node.ts');
const running=await startOpenNode(process.argv[2]);
for(const signal of ['SIGTERM','SIGINT'])process.once(signal,()=>{void running.close();});
"""


class MixedNodes(HTTPNodes):
    def __init__(self, root, count, node, fixture, native=None):
        self.node, self.fixture, self.native = node, fixture, set(native if native is not None else range(1, count, 2))
        super().__init__(root, count)

    def command(self, index):
        if index in self.native:
            return [self.node, "--experimental-strip-types", str(self.fixture / "node-driver.mjs"), str(self.configs[index])]
        return super().command(index)


class OpenTypeScriptHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ts_runtime.TypeScriptAgentNetworkTests.setUpClass.__func__(cls)
        (cls.fixture / "driver.mjs").write_text(DRIVER)
        (cls.fixture / "node-driver.mjs").write_text(NODE_DRIVER)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="memory-open-mixed-http-synthetic-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    def host(self, count=2, native=None):
        host = MixedNodes(self.root, count, self.node, self.fixture, native)
        self.addCleanup(host.close)
        return host

    def ts(self, extra_env=None, **value):
        result = subprocess.run([self.node, "--experimental-strip-types", str(self.fixture / "driver.mjs")],
            input=json.dumps(value).encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=self.fixture, timeout=40,
            env={**os.environ, **(extra_env or {})})
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace")[-6000:])
        payload = json.loads(result.stdout)
        self.assertEqual(payload["subprocessCalls"], 0)
        return payload

    def participant(self, identity, state, seeds, operations):
        return self.ts(mode="participant", identity=json.loads(identity.read_bytes()), state=str(state),
                       options={"seeds": seeds, "allow_loopback": True}, operations=operations)

    def assert_trace(self, result, contact, seeds):
        value = result["results"][0]["value"]
        self.assertEqual(value["state"], "found", value)
        self.assertEqual(canonical_bytes(value["contact"]), canonical_bytes(contact))
        self.assertFalse(value["discovery_grants_access"])
        self.assertFalse(value["encryption_key_possession_proven"])
        self.assertLessEqual(value["metrics"]["requests"], 64)
        self.assertLessEqual(value["route"]["metrics"]["candidate_peak"], 32)
        self.assertLessEqual(value["route"]["metrics"]["concurrency_peak"], 3)
        # Verify every captured actual response and causal parent against the
        # exact signed request; the host supplies no discovered graph to Node.
        nodes = {node["payload"]["signing_key"]["key_id"]: node for node in seeds}
        introductions = set()
        for call in result["calls"]:
            request = call["request"]
            node = nodes[request["payload"]["node_key_id"]]
            self.assertEqual(call["observed_address"], "127.0.0.1")
            checked = verify_response(call["response"], request=request, node=node)
            for candidate in checked["body"].get("nodes", []):
                key = candidate["payload"]["signing_key"]["key_id"]
                introductions.add((node["payload"]["signing_key"]["key_id"], key))
                nodes[key] = candidate
        paths = value["route"]["metrics"]["paths"]
        deeper = [item for item in paths if item["state"] == "verified" and item["parent_key_id"] is not None]
        self.assertTrue(deeper, paths)
        for item in deeper:
            self.assertIn((item["parent_key_id"], item["key_id"]), introductions)

    def test_native_publish_python_read_and_python_publish_native_agent_read(self):
        host = self.host()
        owner = Identity.generate(self.root / "owner" / "identity.json")
        encryption = EncryptionIdentity.generate()
        encryption.save(self.root / "owner" / "encryption.json")
        contact = host.contact(owner, encryption)
        published = self.participant(self.root / "owner" / "identity.json", self.root / "owner-state", host.nodes,
                                     [{"op": "publish", "contact": contact}])["results"][0]
        self.assertTrue(published["ok"], published)
        self.assertEqual(published["value"]["state"], "degraded")
        self.assertEqual(published["value"]["confirmed_leases"], 2)
        reader = Identity.generate(self.root / "reader" / "identity.json")
        with OpenParticipant(reader, self.root / "reader-state", seeds=host.nodes, allow_loopback=True) as participant:
            found = asyncio.run(participant.find_contact(owner.key_id))
        self.assertEqual(canonical_bytes(found["contact"]), canonical_bytes(contact))
        second = host.contact(reader, EncryptionIdentity.generate())
        with OpenParticipant(reader, self.root / "reader-state", seeds=host.nodes, allow_loopback=True) as participant:
            self.assertEqual(asyncio.run(participant.publish_contact(second))["confirmed_leases"], 2)
        client = self.root / "owner" / "client.json"
        atomic_write(client, canonical_bytes({"schema_version": "memory-vault-client-config/v1", "vault_path": str(self.root / "vault.sqlite3"),
            "identity_path": str(self.root / "owner" / "identity.json"), "trust_path": str(self.root / "trust.json"), "capture_visible_turns": False}), replace=False)
        config = self.root / "open.json"
        atomic_write(config, canonical_bytes({"schema_version": "memory-vault-open-client-config/v1", "client_config_path": str(client),
            "state_directory": str(self.root / "owner-state"), "encryption_key_path": str(self.root / "owner" / "encryption.json"), "seeds": host.nodes, "allow_loopback": True}), replace=False)
        requests = [{"op": "connect"}, {"op": "discover", "online": True, "key_id": reader.key_id},
                    {"op": "discover", "online": True}, {"op": "send", "request_id": "req_synthetic_open_send", "recipients": [reader.key_id], "text": "synthetic"},
                    {"op": "receive"}, {"op": "connect", "invitation": {"synthetic": True}}]
        result = self.ts(mode="agent", client_config=str(client), network_config=str(config), requests=requests)
        self.assertTrue(result["results"][0]["ok"], result)
        self.assertEqual(canonical_bytes(result["results"][1]["result"]["contact"]), canonical_bytes(second))
        self.assertEqual(result["results"][2]["result"]["state"], "target_key_required")
        self.assertEqual([r["error"]["code"] for r in result["results"][3:]],
                         ["open_messaging_unsupported", "open_messaging_unsupported", "open_private_invitation_unsupported"])
        for response in result["results"]:
            self.assertLessEqual(len(canonical_bytes(response)), 8192)
            self.assertFalse(response["authority"]["authorization_eligible"])
        self.assertFalse((self.root / "vault.sqlite3").exists())
        self.assertFalse((self.root / "trust.json").exists())

    def test_eight_mixed_process_cold_multihop_bootstrap_exit_and_directory_restart(self):
        host = self.host(8)
        owner = Identity.generate(self.root / "owner" / "identity.json")
        contact = host.contact(owner, EncryptionIdentity.generate())
        self.assertIn("lease", host.put_only_last(owner, contact))
        observer = Identity.generate(self.root / "observer" / "identity.json")
        with OpenParticipant(observer, self.root / "observer-state", seeds=host.nodes[:2], allow_loopback=True) as participant:
            deadline = time.monotonic() + 25
            while time.monotonic() < deadline:
                found = asyncio.run(participant.find_contact(owner.key_id))
                if found["state"] == "found":
                    break
                time.sleep(.25)
            self.assertEqual(found["state"], "found", found)
        cold = Identity.generate(self.root / "cold" / "identity.json")
        state = self.root / "cold-state"
        self.assertFalse(state.exists())
        result = self.participant(self.root / "cold" / "identity.json", state, host.nodes[:2], [{"op": "find", "key_id": owner.key_id}])
        self.assert_trace(result, contact, host.nodes[:2])
        self.assertEqual([host.public_contacts(i) for i in range(8)], [0]*7+[1])
        host.stop(0); host.stop(1); host.stop(7)
        # A Python runtime opens the native directory's exact state and identity.
        host.native.remove(7); host.start(7)
        restarted = self.participant(self.root / "cold" / "identity.json", state, host.nodes[:2], [{"op": "find", "key_id": owner.key_id}])
        self.assertEqual(restarted["results"][0]["value"]["state"], "found", restarted)
        with OpenParticipant(cold, state, seeds=host.nodes[:2], allow_loopback=True) as python_restarted:
            found = asyncio.run(python_restarted.find_contact(owner.key_id))
        self.assertEqual(canonical_bytes(found["contact"]), canonical_bytes(contact))
        self.assertEqual([host.public_contacts(i) for i in range(2,8)], [0]*5+[1])

    def test_native_destination_policy_and_real_socket_failure_boundaries(self):
        from tests.test_open_transport import OpenTransportTests
        helper = OpenTransportTests(); self.addCleanup(helper.doCleanups)
        operations = [{"endpoint": value} for value in ["http://example.com", "https://10.1.2.3", "https://[::ffff:127.0.0.1]",
                      "https://2130706433", "https://127.1", "https://0177.0.0.1", "https://0x7f.0.0.1", "https://example.com@127.0.0.1"]]
        results = self.ts(mode="transport", operations=operations)["results"]
        self.assertTrue(all(not r["ok"] and r["code"] == "open_destination_rejected" for r in results), results)
        for mode, expected in [("ok", None), ("redirect", "open_request_rejected"), ("large", "open_response_too_large"), ("drip", "open_budget_exhausted")]:
            server, base = helper.server(mode)
            result = self.ts(mode="transport", operations=[{"base": base, "seconds": .2 if mode == "drip" else 2}])["results"][0]
            if expected:
                self.assertEqual(result["code"], expected, result)
            else:
                self.assertEqual(result["value"]["response"], {"ok": True})
            self.assertEqual(server.seen, ["/open/v1/rpc"])

    def test_native_dns_checks_all_answers_pins_socket_and_retains_timed_out_slots(self):
        from tests.test_open_transport import OpenTransportTests
        helper = OpenTransportTests(); self.addCleanup(helper.doCleanups)
        server, base = helper.server("ok")
        mixed = self.ts(mode="dns", test="mixed", base="https://synthetic.example",
                        answers=[{"address": "8.8.8.8", "family": 4}, {"address": "127.0.0.1", "family": 4}])
        self.assertEqual(mixed["results"][0]["code"], "open_destination_rejected")
        pinned = self.ts(mode="dns", test="pin", base=base.replace("127.0.0.1", "localhost"), allow_loopback=True,
                         answers=[{"address": "127.0.0.1", "family": 4}])
        self.assertEqual(pinned["results"][0]["value"]["observed_address"], "127.0.0.1")
        self.assertEqual(pinned["results"][1]["lookups"], 1)
        self.assertEqual(server.seen, ["/open/v1/rpc"])
        capacity = self.ts(mode="dns", test="capacity")["results"]
        self.assertEqual([row["code"] for row in capacity[:4]], ["open_budget_exhausted"]*3+["open_dns_capacity"])
        self.assertEqual(capacity[4]["lookups"], 3)

    def test_native_tls_checks_original_hostname_after_literal_pinning(self):
        import datetime
        import ssl
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        from tests.test_open_transport import OpenTransportTests
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic localhost only")])
        current = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(current-datetime.timedelta(minutes=1))
                .not_valid_after(current+datetime.timedelta(hours=1))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, hashes.SHA256()))
        certificate, private = self.root / "synthetic-ca.pem", self.root / "synthetic-key.pem"
        atomic_write(certificate, cert.public_bytes(serialization.Encoding.PEM), replace=False)
        atomic_write(private, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()), replace=False)
        helper = OpenTransportTests(); self.addCleanup(helper.doCleanups)
        server, base = helper.server("ok")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(certificate, private)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        https = base.replace("http:", "https:")
        result = self.ts(mode="transport", extra_env={"NODE_EXTRA_CA_CERTS": str(certificate)}, operations=[
            {"base": https.replace("127.0.0.1", "localhost")}, {"base": https}])["results"]
        self.assertTrue(result[0]["ok"], result)
        self.assertEqual(result[1]["code"], "open_network_unavailable")
        self.assertEqual(server.seen, ["/open/v1/rpc"])

    def test_open_agent_preserves_existing_memory_proofs_and_works_offline_in_both_languages(self):
        from tests.test_open_agent import configured_agent
        from memory_vault_client import ClientConfig
        host = self.host()
        python, owner, encryption, encryption_path = configured_agent(host)
        saved = python.handle({"op": "remember", "request_id": "req_synthetic_prior_memory", "kind": "observation", "text": "Synthetic original provenance retained."})
        self.assertTrue(saved["ok"], saved)
        config = ClientConfig.load(python.client_config)
        paths = [config.path, config.identity_path, config.trust_path, config.vault_path, encryption_path]
        before = {path: path.read_bytes() for path in paths}
        remote = Identity.generate(self.root / "remote" / "identity.json")
        contact = host.contact(remote, EncryptionIdentity.generate()); host.put_only_last(remote, contact)
        operations = [{"op": "connect"}, {"op": "discover", "online": True, "key_id": remote.key_id},
                      {"op": "receive"}, {"op": "recall", "memory_id": saved["result"]["memory_id"]}]
        result = self.ts(mode="agent", client_config=str(config.path), network_config=str(python.network_config), requests=operations)
        self.assertEqual(result["results"][1]["result"]["state"], "found", result)
        self.assertEqual(result["results"][2]["error"]["code"], "open_messaging_unsupported")
        self.assertTrue(result["results"][3]["ok"], result)
        self.assertEqual({path: path.read_bytes() for path in paths}, before)
        for index in range(2): host.stop(index)
        local = self.ts(mode="agent", client_config=str(config.path), network_config=str(python.network_config), requests=[
            {"op": "remember", "request_id": "req_synthetic_native_offline", "kind": "observation", "text": "Synthetic native offline memory."},
            {"op": "discover", "online": False}])
        self.assertEqual(local["calls"], [])
        self.assertTrue(local["results"][0]["ok"], local)
        recalled = python.handle({"op": "recall", "memory_id": local["results"][0]["result"]["memory_id"]})
        self.assertEqual(recalled["result"]["hits"][0]["text"], "Synthetic native offline memory.")

    def test_native_request_binding_signature_expiry_and_closed_index_refuse_without_floors(self):
        host = self.host(1, native={0})
        host.stop(0)
        config = json.loads(host.configs[0].read_bytes()); config["index_policy"] = {}
        atomic_write(host.configs[0], canonical_bytes(config), replace=True); host.start(0)
        identity = Identity.generate(self.root / "requester" / "identity.json")
        current = int(time.time())
        request = sign_request(identity, node=host.nodes[0], action="hello", body={"node": None}, request_id="synthetic_request_binding", issued_at=current, expires_at=current+60)
        malformed = []
        for field, value in [("schema_version", "memory-vault-request/v1"), ("request_id", "synthetic_changed_request"), ("storage_epoch", "wrong_epoch")]:
            altered = json.loads(canonical_bytes(request)); altered["payload"][field] = value; malformed.append(altered)
        expired = json.loads(canonical_bytes(request)); expired["payload"].update(issued_at=current-120, expires_at=current-60)
        expired["proof"] = identity.sign_message(expired["payload"]); malformed.append(expired)
        database = self.root / "node_0" / "transport" / "network.sqlite3"
        def floors():
            with sqlite3.connect(database) as db:
                return db.execute("SELECT kind,key_id,digest,status FROM open_control_floors ORDER BY kind,key_id").fetchall()
        before = floors()
        transport = OpenHTTPTransport(allow_loopback=True); self.addCleanup(transport.close)
        from memory_vault import MemoryError
        for value in malformed:
            with self.assertRaisesRegex(MemoryError, "open_request_rejected"):
                transport.request(host.nodes[0]["payload"]["base_url"], value, deadline=time.monotonic()+2)
        get = sign_request(identity, node=host.nodes[0], action="get", body={"key": contact_key(identity.key_id)}, request_id="synthetic_closed", issued_at=current, expires_at=current+60)
        reply = transport.request(host.nodes[0]["payload"]["base_url"], get, deadline=time.monotonic()+2)
        self.assertEqual(verify_response(reply.response, request=get, node=host.nodes[0])["body"]["error"]["code"], "open_index_closed")
        self.assertEqual(floors(), before)
        host.stop(0); config["index_policy"] = {"enabled": True}
        atomic_write(host.configs[0], canonical_bytes(config), replace=True); host.start(0)
        with sqlite3.connect(database) as db:
            db.execute("CREATE TRIGGER synthetic_write_failure BEFORE INSERT ON open_contacts BEGIN SELECT RAISE(ABORT,'synthetic interruption'); END")
        contact = host.contact(identity, EncryptionIdentity.generate())
        current = int(time.time())
        put = sign_request(identity, node=host.nodes[0], action="put", body={"contact": contact, "lease_seconds": 60},
                           request_id="synthetic_failed_put", issued_at=current, expires_at=current+60)
        with self.assertRaisesRegex(MemoryError, "open_request_rejected") as rejected:
            transport.request(host.nodes[0]["payload"]["base_url"], put, deadline=time.monotonic()+2)
        self.assertTrue(rejected.exception.retryable)
        with sqlite3.connect(database) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM open_contact_floors").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT count(*) FROM open_index_replay").fetchone()[0], 0)

    def test_native_old_seed_uses_new_cached_revision_after_restart(self):
        host = self.host(1, native={0})
        old = host.nodes[0]; current = int(time.time())
        higher = issue_node(host.identities[0], base_url=old["payload"]["base_url"], storage_epoch=old["payload"]["storage_epoch"],
            roles=["directory", "router"], revision=2, issued_at=current, expires_at=current+3600)
        host.stop(0)
        config = json.loads(host.configs[0].read_bytes()); config["node"] = higher
        atomic_write(host.configs[0], canonical_bytes(config), replace=True); host.start(0)
        identity_path = self.root / "new-reader" / "identity.json"
        Identity.generate(identity_path)
        state = self.root / "new-reader-state"
        for _ in range(2):
            joined = self.participant(identity_path, state, [old], [{"op": "join"}])
            self.assertTrue(joined["results"][0]["ok"], joined)
            self.assertEqual(joined["results"][0]["value"]["errors"], [], joined)
            with sqlite3.connect(state / "network.sqlite3") as db:
                cached = bytes(db.execute("SELECT node FROM open_peer_cache").fetchone()[0])
            self.assertEqual(cached, canonical_bytes(higher))

    def test_native_repeat_announcements_need_fresh_proof_after_failure_and_preserve_pending_capacity(self):
        host = self.host(1, native={0})
        identity_path = self.root / "participant" / "identity.json"
        identity = Identity.generate(identity_path); current = int(time.time())
        own = issue_node(identity, base_url="http://127.0.0.1:18590", storage_epoch="synthetic_observer_epoch", roles=["router"],
                         revision=1, issued_at=current, expires_at=current+3600)
        announcement = sign_request(host.identities[0], node=own, action="hello", body={"node": host.nodes[0]},
                                    request_id="synthetic_repeat_announcement", issued_at=current, expires_at=current+60)
        operations = [{"op": "handle", "request": announcement}, {"op": "maintain"},
                      {"op": "pending", "node": host.nodes[0]}]
        operations.extend({"op": "handle", "request": announcement} for _ in range(40))
        operations.extend([{"op": "pending", "node": host.nodes[0]}, {"op": "fail", "key_id": host.identities[0].key_id},
                           {"op": "handle", "request": announcement}, {"op": "pending", "node": host.nodes[0]},
                           {"op": "maintain"}, {"op": "pending", "node": host.nodes[0]}])
        from tests.test_open_typescript import synthetic_identity
        for index in range(33):
            signer, _ = synthetic_identity("synthetic pending " + str(index))
            node = issue_node(signer, base_url="http://127.0.0.1:"+str(18600+index), storage_epoch="synthetic_pending_epoch", roles=["router"],
                              revision=1, issued_at=current, expires_at=current+3600)
            request = sign_request(signer, node=own, action="hello", body={"node": node}, request_id="synthetic_pending_"+str(index),
                                   issued_at=current, expires_at=current+60)
            operations.append({"op": "handle", "request": request})
        operations.append({"op": "pending", "node": host.nodes[0]})
        result = self.ts(mode="participant", identity=json.loads(identity_path.read_bytes()), state=str(self.root / "participant-state"),
            options={"seeds": [], "descriptor": own, "allow_loopback": True}, operations=operations)
        values = [item["value"] for item in result["results"]]
        self.assertEqual(values[2], {"count": 0, "verified": True})
        self.assertEqual(values[43], {"count": 0, "verified": True})
        self.assertEqual(values[46], {"count": 1, "verified": False})
        self.assertEqual(values[48], {"count": 0, "verified": True})
        self.assertEqual(values[-2]["payload"]["body"]["error"], {"code": "open_pending_capacity", "retryable": True})
        self.assertEqual(values[-1]["count"], 32)


if __name__ == "__main__":
    unittest.main()
