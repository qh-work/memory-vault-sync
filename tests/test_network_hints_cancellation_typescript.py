"""Synthetic cancellation through real Node/jose and Python endpoints.

Only disposable loopback services and generated fixture identities are used.
The two timing probes retain real decrypt/parse/send implementations; they
observe existing method/transaction boundaries without replacing crypto.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import unittest

from memory_vault import canonical_bytes, strict_json_loads
from memory_vault_network import NetworkClient
import memory_vault_network_recovery as recovery
from memory_vault_relay import Relay
from tests import test_network_hints_typescript as harness
from tests.test_network_hints import control, outbox_row, single_select
from tests.test_network_message_semantics import inject_ciphertext, records, proofs, vault_snapshot
from tests.test_network_recovery import archive


DRIVER = r"""
import fs from 'node:fs';
import {NetworkPeer} from './peer.ts';
import {HTTPTransport} from './transport.ts';
import {NetworkError} from './io.ts';
const input=JSON.parse(fs.readFileSync(0,'utf8'));
const transport=new HTTPTransport(),calls=[],request=transport.request.bind(transport);
const peer=new NetworkPeer(input.config,{transport});
const send=value=>peer.send(value.request_id,value.recipients,'',[],value.control);
const state=()=>JSON.parse(peer.db().prepare('SELECT value FROM state WHERE key=?').get('hint-session:'+input.query_id).value);
let result;
transport.request=(base,method,path,value,deadline)=>{calls.push({path,message_id:value?.envelope?.message_id});return request(base,method,path,value,deadline);};
try{
  if(input.mode==='pump')result=await peer.pump(4,10,0);
  else if(input.mode==='postcommit'){
    peer.deliver=async()=>{throw new NetworkError('network_storage_unavailable',true);};
    result={cancel:await send(input.cancel),session:state()};
  }
  else if(input.mode==='serial'){
    let release,started,paused=false;
    const entered=new Promise(resolve=>{started=resolve;}),pause=new Promise(resolve=>{release=resolve;});
    const observed=transport.request.bind(transport);
    transport.request=(...args)=>{
      if(!paused&&args[1]==='GET'&&args[2]==='/v1/status'){paused=true;started();return pause.then(()=>observed(...args));}
      return observed(...args);
    };
    const inFlight=send(input.pending);
    await entered;
    const notice=send(input.cancel),localBeforeRelease=state();
    release();
    result={inFlight:await inFlight,cancel:await notice,localBeforeRelease};
  }else if(input.mode==='admission'){
    const original=peer.selectedTransfer.bind(peer),db=peer.db(),exec=db.exec.bind(db);
    let armed=false,triggered=false,notice;
    peer.selectedTransfer=(...args)=>{const value=original(...args);armed=true;return value;};
    db.exec=sql=>{
      if(armed&&!triggered&&sql==='BEGIN IMMEDIATE'){
        armed=false;triggered=true;notice=send(input.cancel);
      }
      return exec(sql);
    };
    const received=await peer.receive();
    result={received,triggered,cancel:notice?await notice:null,session:state()};
  }else throw Error('unknown synthetic mode');
}finally{peer.close();transport.close();}
process.stdout.write(JSON.stringify({result,calls}));
"""


class TypeScriptHintCancellationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        harness.TypeScriptHintExchangeTests.setUpClass.__func__(cls)
        (cls.fixture / "cancellation-driver.mjs").write_text(DRIVER)

    setUp = harness.TypeScriptHintExchangeTests.setUp
    ts = harness.TypeScriptHintExchangeTests.ts
    ts_value = harness.TypeScriptHintExchangeTests.ts_value
    py_value = harness.TypeScriptHintExchangeTests.py_value
    set_policy = harness.TypeScriptHintExchangeTests.set_policy
    remember = harness.TypeScriptHintExchangeTests.remember
    exchange_offer = harness.TypeScriptHintExchangeTests.exchange_offer

    def native(self, index, mode, **values):
        process = subprocess.run([self.node, "--experimental-strip-types", str(self.fixture / "cancellation-driver.mjs")],
            input=json.dumps({"config": str(self.host.net_configs[index]), "mode": mode, **values}).encode(),
            cwd=self.fixture, capture_output=True, timeout=45)
        self.assertEqual(process.returncode, 0, process.stderr.decode(errors="replace")[-3000:])
        return json.loads(process.stdout)

    def session(self, endpoint, query_id):
        with endpoint.db() as db:
            return strict_json_loads(db.execute("SELECT value FROM state WHERE key=?", ("hint-session:" + query_id,)).fetchone()[0])

    def cancel_request(self, owner, query, offer, page, suffix):
        return {"op": "send", "request_id": "req_hint_cancel_" + suffix,
                "recipients": [self.host.identities[owner].key_id],
                "control": control("cancel", query_message_id=query["message_id"],
                    offer_message_id=offer["message_id"], expires_at=page["expires_at"])}

    def prepared(self, owner=0, requester=1, owner_call=None, requester_call=None, suffix="initial"):
        owner_call = owner_call or self.py_value
        requester_call = requester_call or self.ts_value
        roots = [self.remember(owner, "cancel_" + suffix + "_" + str(index),
                              "Synthetic needle cancellable " + str(index)) for index in range(2)]
        self.set_policy(owner, requester, roots, roots)
        query, offer, page = self.exchange_offer(owner, requester, owner_call, requester_call, "cancel_" + suffix)
        return roots, query, offer, page

    def test_both_languages_offline_cancel_late_batch_explicit_ack_and_other_query_survive(self):
        host = self.host
        host.join_receiver()
        endpoints = [host.sender, host.receiver]
        for owner, requester, owner_call, requester_call in (
                (0, 1, self.py_value, self.ts_value), (1, 0, self.ts_value, self.py_value)):
            with self.subTest(requester=requester):
                suffix = str(owner)
                roots, query, offer, page = self.prepared(owner, requester, owner_call, requester_call, suffix)
                selected = requester_call(requester, {"op": "send", "request_id": "req_hint_before_cancel_" + suffix,
                    "recipients": [host.identities[owner].key_id], "control": single_select(query["message_id"], offer["message_id"], roots[0])})
                self.assertFalse(owner_call(owner, {"op": "receive"})["errors"])
                original_transfer = owner_call(owner, {"op": "receive", "respond_to": selected["message_id"]})
                self.assertFalse(requester_call(requester, {"op": "receive"})["errors"])
                original, original_proofs = records(endpoints[requester]), proofs(endpoints[requester])
                other, other_offer, _ = self.exchange_offer(owner, requester, owner_call, requester_call, "other_" + suffix)
                chosen = requester_call(requester, {"op": "send", "request_id": "req_hint_late_batch_" + suffix,
                    "recipients": [host.identities[owner].key_id], "control": single_select(query["message_id"], offer["message_id"], roots[1])})
                self.assertFalse(owner_call(owner, {"op": "receive"})["errors"])
                for relay in host.relays:
                    relay.stop()
                try:
                    pending = owner_call(owner, {"op": "receive", "respond_to": chosen["message_id"]})
                    self.assertEqual(pending["stored_nodes"], 0)
                    before = [vault_snapshot(endpoint) for endpoint in endpoints]
                    request = self.cancel_request(owner, query, offer, page, suffix)
                    cancelled = requester_call(requester, request)
                    self.assertEqual(cancelled["cancellation"], {"query_message_id": query["message_id"], "local_cancelled": True})
                    self.assertEqual(cancelled["stored_nodes"], 0)
                    self.assertEqual(self.session(endpoints[requester], query["message_id"])["state"], "cancelled")
                    notice = outbox_row(endpoints[requester], cancelled["message_id"])
                    again = requester_call(requester, request)
                    self.assertEqual(again["message_id"], cancelled["message_id"])
                    self.assertEqual(outbox_row(endpoints[requester], again["message_id"])["body"], notice["body"])
                    bad = self.ts(requester, {**request, "request_id": request["request_id"] + "_different"})["results"][0]
                    self.assertFalse(bad["ok"])
                    self.assertEqual(bad["error"]["code"], "network_hint_not_available")
                    self.assertEqual([vault_snapshot(endpoint) for endpoint in endpoints], before)
                finally:
                    for relay in host.relays:
                        relay.start()
                frozen = outbox_row(endpoints[owner], pending["message_id"])
                late_id = "msg_" + hashlib.sha256(("synthetic-late-cancel-" + suffix).encode()).hexdigest()
                inject_ciphertext(endpoints[owner], endpoints[requester], bytes(frozen["body"]), late_id)
                received = requester_call(requester, {"op": "receive"})
                self.assertFalse(received["errors"], received)
                late, = received["messages"]
                self.assertEqual((late["state"], late["code"]), ("rejected", "network_invalid_content"))
                self.assertEqual(records(endpoints[requester]), original)
                self.assertEqual(proofs(endpoints[requester]), original_proofs)
                historical = requester_call(requester, {"op": "receive", "message_id": original_transfer["message_id"]})
                self.assertEqual(historical["state"], "validated_saved")
                requester_call(requester, request)
                self.assertFalse(owner_call(owner, {"op": "receive"})["errors"])
                self.assertEqual(self.session(endpoints[owner], query["message_id"])["state"], "active")
                ack = owner_call(owner, {"op": "receive", "respond_to": cancelled["message_id"]})
                self.assertEqual(ack["cancellation"], cancelled["cancellation"])
                self.assertFalse(requester_call(requester, {"op": "receive"})["errors"])
                acknowledged = requester_call(requester, {"op": "receive", "message_id": ack["message_id"]})["control"]
                self.assertEqual(acknowledged, control("cancel_ack", request_message_id=cancelled["message_id"],
                    query_message_id=query["message_id"], expires_at=page["expires_at"]))
                stopped = owner_call(owner, {"op": "receive", "respond_to": chosen["message_id"]})
                self.assertEqual(stopped["state"], "stopped_query")
                after = outbox_row(endpoints[owner], pending["message_id"])
                self.assertEqual((after["body"], after["envelope"]), (frozen["body"], frozen["envelope"]))
                pump = self.native(owner, "pump")
                self.assertGreaterEqual(pump["result"]["stopped_query_messages"], 1)
                self.assertFalse(any(call["path"] == "/v1/messages" for call in pump["calls"]))
                self.assertEqual(self.session(endpoints[owner], other["message_id"])["state"], "active")
                surviving = requester_call(requester, {"op": "send", "request_id": "req_hint_surviving_query_" + suffix,
                    "recipients": [host.identities[owner].key_id], "control": single_select(other["message_id"], other_offer["message_id"], roots[1])})
                self.assertFalse(owner_call(owner, {"op": "receive"})["errors"])
                owner_call(owner, {"op": "receive", "respond_to": surviving["message_id"]})
                self.assertFalse(requester_call(requester, {"op": "receive"})["errors"])
                self.assertIn(roots[1], records(endpoints[requester]))

    def test_native_local_cancel_does_not_wait_for_serial_refresh(self):
        host = self.host
        host.join_receiver()
        roots, query, offer, page = self.prepared(suffix="serial")
        pending = {"request_id": "req_hint_serial_pending", "recipients": [host.identities[0].key_id],
                   "control": single_select(query["message_id"], offer["message_id"], roots[0])}
        before = [vault_snapshot(endpoint) for endpoint in (host.sender, host.receiver)]
        result = self.native(1, "serial", query_id=query["message_id"], pending=pending,
                             cancel=self.cancel_request(0, query, offer, page, "serial"))
        self.assertEqual(result["result"]["localBeforeRelease"]["state"], "cancelled")
        self.assertEqual(result["result"]["inFlight"]["state"], "stopped_query")
        blocked_id = result["result"]["inFlight"]["message_id"]
        self.assertFalse(any(call.get("message_id") == blocked_id for call in result["calls"]))
        self.assertTrue(result["result"]["cancel"]["cancellation"]["local_cancelled"])
        self.assertEqual([vault_snapshot(endpoint) for endpoint in (host.sender, host.receiver)], before)

    def test_both_owners_process_bound_cancel_after_memory_grant_revocation(self):
        host = self.host
        host.join_receiver()
        endpoints = [host.sender, host.receiver]
        for owner, requester, owner_call, requester_call in (
                (0, 1, self.py_value, self.ts_value), (1, 0, self.ts_value, self.py_value)):
            with self.subTest(owner=owner):
                _, query, offer, page = self.prepared(owner, requester, owner_call, requester_call, "grant_" + str(owner))
                self.set_policy(owner, requester, [], [], revision=2)
                before = [vault_snapshot(endpoint) for endpoint in endpoints]
                bad_id = "msg_" + hashlib.sha256(("synthetic-invalid-cancel-expiry-" + str(owner)).encode()).hexdigest()
                invalid = self.cancel_request(owner, query, offer, page, "wrong_expiry_" + str(owner))["control"]
                invalid["expires_at"] -= 1
                inject_ciphertext(endpoints[requester], endpoints[owner], canonical_bytes({
                    "schema_version": "memory-vault-network-content/v2", "kind": "hint_control", "control": invalid}), bad_id)
                self.assertFalse(owner_call(owner, {"op": "receive"})["errors"])
                refusal = owner_call(owner, {"op": "receive", "respond_to": bad_id})
                repeated_refusal = owner_call(owner, {"op": "receive", "respond_to": bad_id})
                self.assertEqual(repeated_refusal["message_id"], refusal["message_id"])
                self.assertFalse(requester_call(requester, {"op": "receive"})["errors"])
                self.assertEqual(requester_call(requester, {"op": "receive", "message_id": refusal["message_id"]})["control"],
                    control("refusal", request_message_id=bad_id, reason="not_available"))
                self.assertEqual(self.session(endpoints[owner], query["message_id"])["state"], "active")
                notice = requester_call(requester, self.cancel_request(owner, query, offer, page, "grant_" + str(owner)))
                self.assertFalse(owner_call(owner, {"op": "receive"})["errors"])
                ack = owner_call(owner, {"op": "receive", "respond_to": notice["message_id"]})
                self.assertEqual(ack["cancellation"], {"query_message_id": query["message_id"], "local_cancelled": True})
                frozen = outbox_row(endpoints[owner], ack["message_id"])
                again = owner_call(owner, {"op": "receive", "respond_to": notice["message_id"]})
                self.assertEqual(again["message_id"], ack["message_id"])
                repeated = outbox_row(endpoints[owner], again["message_id"])
                self.assertEqual((repeated["body"], repeated["envelope"]), (frozen["body"], frozen["envelope"]))
                self.assertFalse(requester_call(requester, {"op": "receive"})["errors"])
                self.assertEqual(requester_call(requester, {"op": "receive", "message_id": ack["message_id"]})["control"]["kind"], "cancel_ack")
                self.assertEqual(self.session(endpoints[owner], query["message_id"])["state"], "cancelled")
                self.assertEqual([vault_snapshot(endpoint) for endpoint in endpoints], before)

    def test_native_outbox_capacity_rolls_back_local_cancel_and_notification_together(self):
        host = self.host
        host.join_receiver()
        _, query, offer, page = self.prepared(suffix="capacity")
        initial = self.session(host.receiver, query["message_id"])
        request = self.cancel_request(0, query, offer, page, "capacity")
        body = canonical_bytes({"schema_version": "memory-vault-network-content/v2", "kind": "message", "text": "Synthetic queued capacity fixture"})
        with host.receiver.db() as db:
            existing = db.execute("SELECT COUNT(*) FROM outbox").fetchone()[0]
            rows = [("req_cancel_capacity_filler_" + str(i), "msg_" + hashlib.sha256(("synthetic-capacity-" + str(i)).encode()).hexdigest(),
                     "0" * 64, body, canonical_bytes([host.identities[0].key_id])) for i in range(1024 - existing)]
            db.executemany("INSERT INTO outbox(request_id,message_id,input_sha,body,recipients) VALUES(?,?,?,?,?)", rows)
        response = self.ts(1, request)
        self.assertFalse(response["calls"])
        self.assertFalse(response["results"][0]["ok"])
        self.assertEqual(response["results"][0]["error"]["code"], "network_outbox_capacity")
        self.assertEqual(self.session(host.receiver, query["message_id"]), initial)
        with host.receiver.db() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM outbox").fetchone()[0], 1024)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM outbox WHERE request_id=?", (request["request_id"],)).fetchone()[0], 0)

    def test_native_batch_rechecks_cancellation_after_real_parse_before_writer_admission(self):
        host = self.host
        host.join_receiver()
        roots, query, offer, page = self.prepared(suffix="admission")
        chosen = self.ts_value(1, {"op": "send", "request_id": "req_hint_admission_selection",
            "recipients": [host.identities[0].key_id], "control": single_select(query["message_id"], offer["message_id"], roots[0])})
        self.assertFalse(self.py_value(0, {"op": "receive"})["errors"])
        transfer = self.py_value(0, {"op": "receive", "respond_to": chosen["message_id"]})
        before = [vault_snapshot(endpoint) for endpoint in (host.sender, host.receiver)]
        result = self.native(1, "admission", query_id=query["message_id"],
                             cancel=self.cancel_request(0, query, offer, page, "admission"))["result"]
        self.assertTrue(result["triggered"])
        self.assertFalse(result["received"]["errors"], result)
        rejected, = result["received"]["messages"]
        self.assertEqual((rejected["state"], rejected["code"]), ("rejected", "network_invalid_content"))
        self.assertEqual(result["session"]["state"], "cancelled")
        self.assertEqual([vault_snapshot(endpoint) for endpoint in (host.sender, host.receiver)], before)
        for relay in host.relays:
            with Relay(relay.config)._transaction() as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM receipts WHERE message_id=?", (transfer["message_id"],)).fetchone()[0], 0)

    def test_encrypted_restored_cancel_and_ack_history_do_not_claim_current_cancellation_or_resume(self):
        host = self.host
        host.join_receiver()
        _, query, offer, page = self.prepared(suffix="restored")
        request = self.cancel_request(0, query, offer, page, "restored")
        notice = self.ts_value(1, request)
        self.assertFalse(self.py_value(0, {"op": "receive"})["errors"])
        ack = self.py_value(0, {"op": "receive", "respond_to": notice["message_id"]})
        self.assertFalse(self.ts_value(1, {"op": "receive"})["errors"])
        _, arguments = archive(host.receiver)
        restored_requester = recovery.restore_endpoint(directory=host.root / "cancel-restored-requester", **arguments)
        owner_package, owner_secret = host.root / "synthetic-owner-package", host.root / "synthetic-owner-recovery-secret.json"
        recovery.backup_endpoint(network_config=host.net_configs[0], output=owner_package, secret_file=owner_secret)
        restored_owner = recovery.restore_endpoint(directory=host.root / "cancel-restored-owner", **{
            **arguments, "package": owner_package, "secret_file": owner_secret, "memory_trust": host.sender.client_config.trust_path})
        for index, restored, operation, identifier in (
                (1, restored_requester, request, notice["message_id"]),
                (0, restored_owner, {"op": "receive", "respond_to": notice["message_id"]}, ack["message_id"])):
            with self.subTest(role=index), NetworkClient(Path(restored["network_config"]), transport=host.transports[index]) as endpoint:
                frozen = outbox_row(endpoint, identifier)
                before = vault_snapshot(endpoint)
                original_configs = host.configs[index], host.net_configs[index]
                try:
                    host.configs[index], host.net_configs[index] = Path(restored["client_config"]), Path(restored["network_config"])
                    response = self.ts(index, operation)
                    self.assertTrue(response["results"][0]["ok"], response)
                    self.assertNotIn("cancellation", response["results"][0]["result"])
                    self.assertEqual(response["results"][0]["result"]["message_id"], identifier)
                    self.assertFalse(any(call["path"] == "/v1/messages" for call in response["calls"]))
                    pump = self.native(index, "pump")
                    self.assertFalse(any(call["path"] == "/v1/messages" for call in pump["calls"]))
                finally:
                    host.configs[index], host.net_configs[index] = original_configs
                with endpoint.db() as db:
                    self.assertEqual(db.execute("SELECT COUNT(*) FROM state WHERE key LIKE 'hint-session:%'").fetchone()[0], 0)
                after = outbox_row(endpoint, identifier)
                self.assertEqual((after["body"], after["envelope"]), (frozen["body"], frozen["envelope"]))
                self.assertEqual(vault_snapshot(endpoint), before)

    def test_native_typed_delivery_failure_preserves_committed_cancel_without_inventing_storage_counts(self):
        host = self.host
        host.join_receiver()
        _, query, offer, page = self.prepared(suffix="postcommit")
        before = [vault_snapshot(endpoint) for endpoint in (host.sender, host.receiver)]
        result = self.native(1, "postcommit", query_id=query["message_id"],
                             cancel=self.cancel_request(0, query, offer, page, "postcommit"))
        self.assertFalse(result["calls"])
        response = result["result"]["cancel"]
        self.assertEqual(response["state"], "delivery_unknown")
        self.assertEqual(response["cancellation"], {"query_message_id": query["message_id"], "local_cancelled": True})
        self.assertEqual(response["errors"], [{"code": "network_storage_unavailable", "retryable": True}])
        for field in ("stored_nodes", "configured_nodes", "validated_recipients", "endpoint_validated"):
            self.assertNotIn(field, response)
        self.assertEqual(result["result"]["session"]["state"], "cancelled")
        frozen = outbox_row(host.receiver, response["message_id"])
        self.assertEqual(strict_json_loads(frozen["body"])["control"]["kind"], "cancel")
        self.assertIsNone(frozen["envelope"])
        self.assertEqual([vault_snapshot(endpoint) for endpoint in (host.sender, host.receiver)], before)


if __name__ == "__main__":
    unittest.main()
