"""Deterministic refresh/receive interleavings over real SQLite connections.

Uses real peer/nodes/crypto/io/vault/records imports and Python-signed controls.
Injects status/HTTP/recovery and receive admission/signing boundaries without
creating a full endpoint or executing Vault methods. This is not a multi-process
or full-peer acceptance; the real socket/end-to-end cases live in other tests.
"""
from __future__ import annotations

import unittest
from types import SimpleNamespace
from memory_vault_relay import Relay

from tests.test_network_typescript_transport import prepare_runtime, invoke
import tests.test_network_typescript_nodes as node_fixtures
from memory_vault_network_crypto import document_sha256


DRIVER = r"""
import fs from 'node:fs';
import path from 'node:path';
import { NetworkPeer } from './peer.ts';
import { verifyCurrentNodes } from './nodes.ts';
import { openPrivateDatabase } from './io.ts';
const input=JSON.parse(fs.readFileSync(0,'utf8'));
Date.now=()=>input.now*1000;
const folder=fs.mkdtempSync(path.join(process.cwd(),'race-'));fs.chmodSync(folder,0o700);
const file=path.join(folder,'state.sqlite3'),db=openPrivateDatabase(file);
db.exec('CREATE TABLE state(key TEXT PRIMARY KEY,value TEXT);CREATE TABLE outbox(request_id TEXT PRIMARY KEY,message_id TEXT,body BLOB,envelope BLOB,receipts TEXT);CREATE TABLE inbox(message_id TEXT PRIMARY KEY,body BLOB);');
const other=openPrivateDatabase(file);
const write=(connection,key,value)=>connection.prepare('INSERT OR REPLACE INTO state VALUES(?,?)').run(key,JSON.stringify(value));
const get=key=>{const row=db.prepare('SELECT value FROM state WHERE key=?').get(key);return row?JSON.parse(row.value):null;};
const body=Buffer.from('synthetic-frozen-body'),envelope=Buffer.from(JSON.stringify({synthetic:'frozen-envelope'})),inbox=Buffer.from('synthetic-retained-inbox');
db.prepare('INSERT INTO outbox VALUES(?,?,?,?,?)').run('synthetic-request','synthetic-message',body,envelope,'{}');
db.prepare('INSERT INTO inbox VALUES(?,?)').run('synthetic-message',inbox);
const peer=Object.create(NetworkPeer.prototype);
peer.networkId=input.network;peer.issuers=input.issuers;peer.localIdentity=input.local_identity;peer.relays=[input.url,input.other_url];peer.db=()=>db;peer.recovery=()=>({});
const options={network_id:input.network,issuers:input.issuers,nonce:input.nonce,now:input.now,local_identity:input.local_identity};
if(input.scenario.startsWith('receive_')){
 const old=verifyCurrentNodes(input.old_response,options);
 verifyCurrentNodes(input.new_response,{...options,previous_roster:input.old_response.roster,previous_directory:input.old_response.nodes});
 const replace=()=>{
  other.exec('BEGIN IMMEDIATE');
  try{
   write(other,'roster',input.new_response.roster);write(other,'node_directory',input.new_response.nodes);
   write(other,'node_status_issued_at',input.new_response.node_status.payload.issued_at);write(other,'node:'+input.url,input.new_binding);
   other.prepare('DELETE FROM state WHERE key=?').run('cursor:'+input.url);
   const prefix='ack:'+input.url+':';other.prepare('DELETE FROM state WHERE substr(key,1,?)=?').run(prefix.length,prefix);
   other.exec('COMMIT');
  }catch(error){other.exec('ROLLBACK');throw error;}
 };
 write(db,'roster',input.old_response.roster);write(db,'node_directory',input.old_response.nodes);
 write(db,'node:'+input.url,input.old_binding);write(db,'cursor:'+input.url,{cursor:7,receipt_cursor:0});
 write(db,'cursor:'+input.other_url,{cursor:22,receipt_cursor:4});
 peer.relays=[input.url];peer.identity={key_id:input.local_identity.signing_key.key_id};
 peer.refresh=async()=>({current:old.current_roster,node:input.old_binding});
 // Admission and request signatures are deliberately outside this scheduling
 // regression. Keep their boundary visible; do not claim crypto acceptance.
 peer.request=(action,body)=>({payload:{body}});
 let ackCalls=0,admissionCalls=0;
 peer.accept=async envelope=>{
  admissionCalls++;
  if(input.scenario==='receive_admission')replace();
  return {message_id:envelope.message_id,state:'validated_saved',understood:false};
 };
 peer.http=async(base,method,route,value)=>{
  if(route==='/v1/poll'){
   if(input.scenario==='receive_poll'){replace();return {messages:[],cursor:7,receipts:[],receipt_cursor:0,has_more:false};}
   if(input.scenario==='receive_same_node'){
    write(other,'cursor:'+input.url,{cursor:12,receipt_cursor:0});
    return {messages:[],cursor:7,receipts:[],receipt_cursor:0,has_more:false};
   }
   return {messages:[{message_id:'synthetic-poll-message'}],cursor:8,receipts:[],receipt_cursor:0,has_more:false};
  }
  if(route==='/v1/ack'){
   ackCalls++;if(input.scenario==='receive_ack')replace();
   return {...value.payload.body,recipient_key_id:peer.identity.key_id,receipt_sequence:1};
  }
  throw Error('unexpected synthetic route');
 };
 try{
  const result=await peer.receiveInternal(4);
  process.stdout.write(JSON.stringify({result,cursor:get('cursor:'+input.url),other_cursor:get('cursor:'+input.other_url),
   directory_version:get('node_directory').payload.version,binding_epoch:get('node:'+input.url).storage_epoch,
   ack_present:get('ack:'+input.url+':synthetic-poll-message')!==null,ack_calls:ackCalls,admission_calls:admissionCalls,
   frozen_body_retained:Buffer.from(db.prepare('SELECT body FROM outbox').get().body).equals(body),
   frozen_envelope_retained:Buffer.from(db.prepare('SELECT envelope FROM outbox').get().envelope).equals(envelope),
   inbox_bytes_retained:Buffer.from(db.prepare('SELECT body FROM inbox').get().body).equals(inbox)}));
 }finally{other.close();db.close();}
}else{
const selected=input.scenario==='replacement'?input.new_response:input.old_response;
const checked=verifyCurrentNodes(selected,options);
let statusPosted=0;
peer.http=async(base,method)=>{if(method==='GET')return input.scenario==='replacement'?input.new_challenge:input.old_challenge;statusPosted++;return {};};
peer.status=async()=>{
 // This second connection commits after the selected response was verified
 // and before refresh enters its incarnation write transaction.
 const later=input.scenario==='stale';
 const current=input.scenario==='same'?input.old_response:input.new_response;
 const binding=later?input.new_binding:input.old_binding;
 other.exec('BEGIN IMMEDIATE');
 try{
  write(other,'roster',current.roster);write(other,'node_directory',current.nodes);write(other,'node_status_issued_at',current.node_status.payload.issued_at);
  write(other,'node:'+input.url,binding);write(other,'cursor:'+input.url,{cursor:7,receipt_cursor:2});write(other,'cursor:'+input.other_url,{cursor:22,receipt_cursor:4});
  write(other,'ack:'+input.url+':synthetic-message',{synthetic:'ack'});write(other,'join:'+input.url+':synthetic-invite',{synthetic:'join'});
  other.prepare('UPDATE outbox SET receipts=?').run(JSON.stringify({[input.url]:input.old_receipt,[input.other_url]:input.other_receipt}));
  other.exec('COMMIT');
 }catch(error){other.exec('ROLLBACK');throw error;}
 return {response:selected,current:checked.current_roster,nodes:checked.nodes};
};
let code=null;
try{await peer.refresh(input.url);}catch(error){code=error.code||error.name;}
const row=db.prepare('SELECT body,envelope,receipts FROM outbox').get();
const result={code,directory_version:get('node_directory').payload.version,binding_epoch:get('node:'+input.url).storage_epoch,
 cursor:get('cursor:'+input.url),other_cursor:get('cursor:'+input.other_url),receipt_urls:Object.keys(JSON.parse(row.receipts)).sort(),
 ack_present:get('ack:'+input.url+':synthetic-message')!==null,join_present:get('join:'+input.url+':synthetic-invite')!==null,
 frozen_body_retained:Buffer.from(row.body).equals(body),frozen_envelope_retained:Buffer.from(row.envelope).equals(envelope),
 inbox_bytes_retained:Buffer.from(db.prepare('SELECT body FROM inbox').get().body).equals(inbox),status_posted:statusPosted};
other.close();db.close();process.stdout.write(JSON.stringify(result));
}
"""


class TypeScriptPeerRaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        prepare_runtime(cls, ("crypto.ts", "control.ts", "nodes.ts", "io.ts", "transport.ts", "peer.ts", "vault.ts", "records.ts", "setup.ts", "retrieval.ts", "retrieval_text.ts", "ranking_math.ts"), DRIVER)

    def setUp(self):
        # Reuse only synthetic key/document generation, not its test suite.
        fixture = node_fixtures.TypeScriptNodeTests()
        fixture.setUp()
        previous = fixture.make_directory(version=2, previous=fixture.directory)
        revoked = {**fixture.node_entry, "status": "revoked"}
        replacement = {**fixture.other_entry, "base_url": fixture.node_entry["base_url"]}
        current = fixture.make_directory(version=3, previous=previous, entries=[revoked, replacement])
        def descriptor(entry): return {key: entry[key] for key in ("signing_key", "base_url", "storage_epoch")}
        old_binding, new_binding = descriptor(fixture.node_entry), descriptor(replacement)
        def challenge(binding, signer):
            payload = {"schema_version": "memory-vault-node-challenge/v1", "network_id": fixture.network,
                "node": binding, "nonce": fixture.nonce, "issued_at": fixture.now, "expires_at": fixture.now + 300}
            return {"nonce": fixture.nonce, "expires_at": fixture.now + 300, "current_roster_version": 1,
                "current_roster_sha256": document_sha256(fixture.roster), "node_challenge": fixture.signed(payload, signer)}
        member = fixture.roster["payload"]["members"][0]
        receipt = {"state": "stored", "message_id": "synthetic-message", "sequence": 1,
                   "envelope_sha256": document_sha256({"synthetic": "frozen-envelope"})}
        relay = SimpleNamespace(node_identity=fixture.node_key, network_id=fixture.network,
                                node_descriptor=lambda: old_binding)
        old_receipt = Relay._stored_result(relay, receipt)
        self.data = {"old_receipt": old_receipt, "other_receipt": receipt, "network": fixture.network, "url": fixture.node_entry["base_url"], "other_url": fixture.other_entry["base_url"],
            "nonce": fixture.nonce, "now": fixture.now, "issuers": [fixture.issuer.public_descriptor()],
            "local_identity": {key: member[key] for key in ("signing_key", "encryption_key")},
            "old_response": fixture.make_response(previous), "new_response": fixture.make_response(current),
            "old_binding": old_binding, "new_binding": new_binding,
            "old_challenge": challenge(old_binding, fixture.node_key), "new_challenge": challenge(new_binding, fixture.other_node_key)}

    def result(self, scenario):
        result = invoke(self, {**self.data, "scenario": scenario})
        self.assertTrue(result["frozen_body_retained"])
        self.assertTrue(result["frozen_envelope_retained"])
        self.assertTrue(result["inbox_bytes_retained"])
        self.assertEqual(result["other_cursor"], {"cursor": 22, "receipt_cursor": 4})
        return result

    def test_stale_refresh_cannot_overwrite_a_later_observed_node(self):
        result = self.result("stale")
        self.assertEqual(result["code"], "network_node_directory_rollback")
        self.assertEqual(result["directory_version"], 3)
        self.assertEqual(result["binding_epoch"], self.data["new_binding"]["storage_epoch"])
        self.assertEqual(result["cursor"], {"cursor": 7, "receipt_cursor": 2})
        self.assertEqual(result["receipt_urls"], sorted([self.data["url"], self.data["other_url"]]))
        self.assertTrue(result["ack_present"] and result["join_present"])
        self.assertEqual(result["status_posted"], 0)

    def test_legitimate_replacement_resets_only_its_delivery_bookkeeping(self):
        result = self.result("replacement")
        self.assertIsNone(result["code"])
        self.assertEqual(result["binding_epoch"], self.data["new_binding"]["storage_epoch"])
        self.assertIsNone(result["cursor"])
        self.assertEqual(result["receipt_urls"], [self.data["other_url"]])
        self.assertFalse(result["ack_present"] or result["join_present"])
        self.assertEqual(result["status_posted"], 1)

    def test_same_node_retains_cursor_ack_join_and_storage_receipts(self):
        result = self.result("same")
        self.assertIsNone(result["code"])
        self.assertEqual(result["binding_epoch"], self.data["old_binding"]["storage_epoch"])
        self.assertEqual(result["cursor"], {"cursor": 7, "receipt_cursor": 2})
        self.assertEqual(result["receipt_urls"], sorted([self.data["url"], self.data["other_url"]]))
        self.assertTrue(result["ack_present"] and result["join_present"])
        self.assertEqual(result["status_posted"], 1)

    def assert_stale_receive_rejected(self, scenario, *, admissions, acknowledgements):
        result = self.result(scenario)
        self.assertEqual(result["directory_version"], 3)
        self.assertEqual(result["binding_epoch"], self.data["new_binding"]["storage_epoch"])
        self.assertIsNone(result["cursor"])
        self.assertFalse(result["ack_present"])
        self.assertEqual(result["admission_calls"], admissions)
        self.assertEqual(result["ack_calls"], acknowledgements)
        self.assertTrue(any(error["code"] == "network_node_changed" and error["retryable"]
                            for error in result["result"]["errors"]))

    def test_old_poll_response_cannot_restore_cursor_after_node_replacement(self):
        self.assert_stale_receive_rejected("receive_poll", admissions=0, acknowledgements=0)

    def test_node_replacement_during_admission_prevents_stale_ack_and_cursor(self):
        self.assert_stale_receive_rejected("receive_admission", admissions=1, acknowledgements=0)

    def test_node_replacement_during_ack_prevents_stale_cursor(self):
        self.assert_stale_receive_rejected("receive_ack", admissions=1, acknowledgements=1)

    def test_same_node_concurrent_progress_does_not_roll_cursor_backward(self):
        result = self.result("receive_same_node")
        self.assertEqual(result["directory_version"], 2)
        self.assertEqual(result["binding_epoch"], self.data["old_binding"]["storage_epoch"])
        self.assertEqual(result["cursor"], {"cursor": 12, "receipt_cursor": 0})
        self.assertEqual(result["result"]["errors"], [])


if __name__ == "__main__":
    unittest.main()
