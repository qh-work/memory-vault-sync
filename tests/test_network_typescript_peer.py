"""Independent TS process <-> Python peer over two owned loopback relays.

No actual model names are invented; these are protocol/runtime tests only.
The Node client imports no Python code and operates the same persistent files.
"""
from __future__ import annotations

from contextlib import closing
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest

from memory_vault import canonical_bytes, strict_json_loads
from memory_vault_client import ClientConfig
from memory_vault_network_control import issue_roster
from memory_vault_network_crypto import document_sha256
from memory_vault_network import NetworkClient
from memory_vault_network_recovery import backup_endpoint, restore_endpoint
from memory_vault_storage import atomic_write
from memory_vault_trust import TrustStore
from tests import test_network_node_runtime as runtime

ROOT = Path(__file__).resolve().parents[1]
DRIVER = r"""
import { NetworkPeer } from './peer.ts';
import { HTTPTransport } from './transport.ts';
import { NetworkError } from './io.ts';
const chunks=[];let size=0;
for await(const chunk of process.stdin){size+=chunk.length;if(size>1048576)throw Error('fixture_limit');chunks.push(chunk);}
const input=JSON.parse(Buffer.concat(chunks).toString('utf8'));
const transport=new HTTPTransport(),original=transport.request.bind(transport);let dropped=false;
transport.request=async(base,method,path,value,deadline)=>{
  const result=await original(base,method,path,value,deadline);
  if(input.drop_after_store===base&&path==='/v1/messages'&&!dropped){dropped=true;throw new NetworkError('network_unavailable',true);}
  return result;
};
let peer;const results=[];
try{
  peer=new NetworkPeer(input.config,{transport});
  for(const operation of input.operations){
    try{
      let result;
      if(operation.op==='connect')result=await peer.connect(operation.invitation,operation.request_id);
      else if(operation.op==='discover')result=await peer.discover();
      else if(operation.op==='send')result=await peer.send(operation.request_id,operation.recipients,operation.text,operation.memory_ids);
      else if(operation.op==='receive')result=await peer.receive(operation.limit);
      else if(operation.op==='pump')result=await peer.pump(operation.maximum_messages,operation.maximum_seconds,operation.receive_limit);
      else if(operation.op==='get')result=peer.vault.get(operation.memory_id);
      else throw Error('unsupported fixture operation');
      results.push({ok:true,result});
    }catch(error){results.push({ok:false,error:error.code||'unexpected_error'});}
  }
}finally{peer?.close();transport.close();}
process.stdout.write(JSON.stringify(results));
"""


@unittest.skipUnless(os.name == "posix", "owned HTTP fixture and private TS storage require POSIX")
class TypeScriptPeerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.node = shutil.which("node")
        if cls.node is None:
            raise unittest.SkipTest("Node 22.19 required for independent peer")
        selected = os.environ.get("MEMORY_VAULT_JOSE_MODULE")
        package = ROOT / "clients/typescript/network/node_modules/jose"
        if selected:
            entry = Path(selected).expanduser().resolve()
            if entry.parts[-3:] != ("dist", "webapi", "index.js"):
                raise RuntimeError("Expected explicit locked jose entry")
            package = entry.parents[2]
        if not (package / "package.json").is_file():
            raise unittest.SkipTest("Existing jose required, no installation by tests")
        metadata = json.loads((package / "package.json").read_text())
        if metadata.get("name") != "jose" or metadata.get("version") != "6.2.10":
            raise RuntimeError("Locked jose 6.2.10 required")
        cls.temporary = tempfile.TemporaryDirectory(prefix="memory-vault-ts-peer-synthetic-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.fixture = Path(cls.temporary.name).resolve()
        for name in ("crypto.ts", "control.ts", "nodes.ts", "records.ts", "vault.ts", "io.ts", "transport.ts", "peer.ts", "setup.ts", "retrieval.ts", "retrieval_text.ts", "package.json"):
            shutil.copyfile(ROOT / "clients/typescript/network" / name, cls.fixture / name)
        (cls.fixture / "node_modules").mkdir()
        (cls.fixture / "node_modules/jose").symlink_to(package, target_is_directory=True)
        (cls.fixture / "driver.mjs").write_text(DRIVER)

    def setUp(self):
        self.host = runtime.NetworkNodeRuntimeTests("test_independent_refresh_and_persistent_drain_fence_over_real_http")
        self.addCleanup(self.host.doCleanups)
        self.host.setUp()
        self.addCleanup(self.host.tearDown)

    def ts(self, index, *operations, **extra):
        process = subprocess.run([self.node, "--experimental-strip-types", str(self.fixture / "driver.mjs")],
            input=json.dumps({"config": str(self.host.net_configs[index]), "operations": operations, **extra}).encode(),
            cwd=self.fixture, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45)
        self.assertEqual(process.returncode, 0, process.stderr.decode(errors="replace")[-4000:])
        result = json.loads(process.stdout)
        self.assertEqual(len(result), len(operations))
        return result

    def value(self, index, operation, **extra):
        item, = self.ts(index, operation, **extra)
        self.assertTrue(item["ok"], item)
        return item["result"]

    def records(self, index):
        config = ClientConfig.load(self.host.configs[index])
        with closing(config.vault()._connect()) as db:
            return {row["memory_id"]: row["record_json"] for row in db.execute("SELECT * FROM memories")}

    def test_ts_invitation_and_two_way_python_messages_preserve_original_proofs(self):
        host = self.host
        joined = self.value(1, {"op": "connect", "invitation": host.invitation, "request_id": "req_ts_join_synthetic"})
        self.assertEqual(joined["joined_nodes"], 2, joined)
        # Restart into Python at the exact same transport DB; consumed invite
        # retries reuse the TS-signed request rather than another identity.
        self.assertEqual(host.receiver.connect(host.invitation)["joined_nodes"], 2)
        sent = self.value(1, {"op": "send", "request_id": "req_ts_synthetic_send", "recipients": [host.identities[0].key_id], "text": "Synthetic TS→Python 记忆 👩🏽‍🚀"})
        self.assertEqual(sent["stored_nodes"], 2, sent)
        received = host.sender.receive()
        self.assertFalse(received["errors"], received)
        self.assertEqual(len(received["messages"]), 1, received)
        original = self.records(1)
        for memory_id, record in original.items():
            self.assertEqual(self.records(0)[memory_id], record)
            result = ClientConfig.load(host.configs[0]).vault().handle({"op": "get", "memory_id": memory_id})
            self.assertTrue(result["result"]["verification"]["signature_verified_at_admission"])
        reply = host.sender.send("req_python_synthetic_reply", [host.identities[1].key_id], "Synthetic Python→TS persistent reply")
        self.assertEqual(reply["stored_nodes"], 2, reply)
        ts_received = self.value(1, {"op": "receive"})
        self.assertFalse(ts_received["errors"], ts_received)
        self.assertEqual(len(ts_received["messages"]), 1, ts_received)
        host.sender.receive()
        with host.receiver.db() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM acknowledgements").fetchone()[0], 1)
        self.assertEqual(self.records(0), self.records(1))
        conflict, = self.ts(1, {"op": "send", "request_id": "req_ts_synthetic_send", "recipients": [host.identities[0].key_id], "text": "changed synthetic retry"})
        self.assertEqual(conflict, {"ok": False, "error": "network_request_id_conflict"})

    def test_offline_ts_restart_then_python_pump_reuses_ciphertext_and_queue(self):
        host = self.host
        host.join_receiver()
        for relay in host.relays:
            relay.stop()
        pending = self.value(0, {"op": "send", "request_id": "req_ts_offline_queue", "recipients": [host.identities[1].key_id], "text": "Synthetic offline TS persisted memory"})
        self.assertEqual(pending["stored_nodes"], 0, pending)
        self.assertTrue(all(error["retryable"] for error in pending["errors"]))
        before = host.outbox()["req_ts_offline_queue"]
        self.assertIsNone(before["envelope"])
        host.relays[0].start()
        partial = self.value(0, {"op": "pump", "receive_limit": 0})
        self.assertEqual(partial["outbound"][0]["stored_nodes"], 1, partial)
        frozen = bytes(host.outbox()["req_ts_offline_queue"]["envelope"])
        host.relays[1].start()
        # The other language resumes the exact TS queue without import/export.
        done = host.sender.pump(receive_limit=0)
        self.assertEqual(done["remaining_outbox"], 0, done)
        after = host.outbox()["req_ts_offline_queue"]
        self.assertEqual(bytes(after["envelope"]), frozen)
        self.assertEqual(bytes(after["body"]), bytes(before["body"]))
        received = host.receiver.receive()
        self.assertFalse(received["errors"], received)
        self.assertEqual(len(received["messages"]), 1)
        acknowledged = self.value(0, {"op": "receive"})
        self.assertFalse(acknowledged["errors"], acknowledged)
        with host.sender.db() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM acknowledgements").fetchone()[0], 1)
        self.assertEqual(self.records(0), self.records(1))

    def test_python_queue_resumes_in_ts_and_revoked_authority_blocks_new_sends(self):
        host = self.host
        host.join_receiver()
        for relay in host.relays:
            relay.stop()
        original = host.sender.send("req_python_to_ts_resume", [host.identities[1].key_id], "Synthetic Python queued for TS recovery")
        self.assertEqual(original["stored_nodes"], 0)
        for relay in host.relays:
            relay.start()
        done = self.value(0, {"op": "pump", "receive_limit": 0}, drop_after_store=host.relays[0].url)
        self.assertEqual(done["remaining_outbox"], 1, done)
        frozen = bytes(host.outbox()["req_python_to_ts_resume"]["envelope"])
        retried = self.value(0, {"op": "pump", "receive_limit": 0})
        self.assertEqual(retried["remaining_outbox"], 0, retried)
        self.assertEqual(bytes(host.outbox()["req_python_to_ts_resume"]["envelope"]), frozen)
        self.assertEqual(len(host.receiver.receive()["messages"]), 1)
        members = copy.deepcopy(host.roster["payload"]["members"])
        for member in members:
            if member["signing_key"]["key_id"] == host.identities[0].key_id:
                member["status"] = "revoked"
        at = int(time.time())
        revoked = issue_roster(host.issuer, network_id=host.network_id, version=2, previous_sha256=document_sha256(host.roster), members=members, issued_at=at, expires_at=at+300)
        atomic_write(host.roster_path, canonical_bytes(revoked), replace=True)
        rejected = self.value(0, {"op": "send", "request_id": "req_ts_revoked_queue", "recipients": [host.identities[1].key_id], "text": "Synthetic locally kept after network revocation"})
        self.assertEqual(rejected["stored_nodes"], 0, rejected)
        self.assertEqual({error["code"] for error in rejected["errors"]}, {"unknown_key"})
        memory_id = next(memory_id for memory_id, text in self.records(0).items() if "locally kept" in text)
        self.assertEqual(self.value(0, {"op": "get", "memory_id": memory_id})["record"]["memory_id"], memory_id)

    def test_ts_offline_queue_survives_encrypted_endpoint_restore_and_requires_fresh_status(self):
        host = self.host
        host.join_receiver()
        host.authority.stop()
        for relay in host.relays:
            relay.stop()
        pending = self.value(0, {"op": "send", "request_id": "req_ts_recovery_offline", "recipients": [host.identities[1].key_id], "text": "Synthetic TS recovery with no prior control checkpoint"})
        self.assertEqual(pending["stored_nodes"], 0, pending)
        before = host.outbox()["req_ts_recovery_offline"]
        original = self.records(0)
        self.assertIsNone(before["envelope"])
        issuer = host.root / "independent-recovery-issuer.json"
        atomic_write(issuer, canonical_bytes(host.issuer.public_descriptor()), replace=False)
        package, secret = host.root / "encrypted-ts-endpoint", host.root / "separate-ts-recovery-key.json"
        snapshot = backup_endpoint(network_config=host.net_configs[0], output=package, secret_file=secret)
        self.assertFalse(snapshot["network_accessed"])
        self.assertEqual(snapshot["memory_records"], 1)
        restored = restore_endpoint(package=package, secret_file=secret, directory=host.root / "restored-ts-endpoint",
            confirm_network_id=host.network_id, issuer_public=issuer, authority_url=host.authority.url,
            relays=[relay.url for relay in host.relays], memory_trust=host.configs[0].parent / "trust.json")
        self.assertFalse(restored["network_accessed"])
        self.assertTrue(restored["requires_fresh_issuer_status"])
        config = restored["network_config"]
        marker = strict_json_loads((Path(config).parent / "recovery-state.json").read_bytes())
        self.assertIsNone(marker["last_verified_node_directory"])
        memory_id = next(iter(original))
        self.assertEqual(canonical_bytes(self.value(0, {"op": "get", "memory_id": memory_id}, config=config)["record"]).decode(), original[memory_id])
        for relay in host.relays:
            relay.start()
        # Available storage cannot activate keys from an old backup without the
        # independent authority, even for a never-uploaded persistent message.
        paused = self.value(0, {"op": "pump", "receive_limit": 0}, config=config)
        self.assertEqual(paused["remaining_outbox"], 1, paused)
        with NetworkClient(Path(config)) as recovered:
            with recovered.db() as db:
                self.assertIsNone(db.execute("SELECT envelope FROM outbox").fetchone()[0])
        host.authority.start()
        sent = self.value(0, {"op": "pump", "receive_limit": 0}, config=config)
        self.assertEqual(sent["remaining_outbox"], 0, sent)
        self.assertEqual(sent["outbound"][0]["stored_nodes"], 2, sent)
        received = host.receiver.receive()
        self.assertFalse(received["errors"], received)
        self.assertEqual(len(received["messages"]), 1, received)
        receipt = self.value(0, {"op": "receive"}, config=config)
        self.assertFalse(receipt["errors"], receipt)
        with NetworkClient(Path(config)) as recovered:
            with recovered.db() as db:
                self.assertEqual(bytes(db.execute("SELECT body FROM outbox").fetchone()[0]), bytes(before["body"]))
                self.assertEqual(db.execute("SELECT COUNT(*) FROM acknowledgements").fetchone()[0], 1)
        self.assertEqual(self.records(0), original)
        self.assertIsNone(host.outbox()["req_ts_recovery_offline"]["envelope"])
        self.assertEqual(self.records(1), original)

    def test_active_network_member_does_not_bypass_independent_memory_trust(self):
        host = self.host
        host.join_receiver()
        sent = host.sender.send("req_ts_independent_trust", [host.identities[1].key_id], "Synthetic signed member memory requiring separate admission")
        self.assertEqual(sent["stored_nodes"], 2, sent)
        trust_path = host.configs[1].parent / "trust.json"
        TrustStore(trust_path).revoke(host.identities[0].key_id)
        trust_before = trust_path.read_bytes()
        received = self.value(1, {"op": "receive"})
        self.assertFalse(received["errors"], received)
        self.assertEqual(len(received["messages"]), 1, received)
        message = received["messages"][0]
        self.assertEqual(message["share"]["admission"], "quarantined", message)
        self.assertFalse(message["understood"])
        self.assertEqual(trust_path.read_bytes(), trust_before)
        # The original proof and memory still persist, but do not become a
        # trusted recall candidate merely because the network accepted a peer.
        self.assertEqual(self.records(0), self.records(1))
        memory_id = next(iter(self.records(0)))
        self.assertIsNone(self.value(1, {"op": "get", "memory_id": memory_id}))


if __name__ == "__main__":
    unittest.main()
