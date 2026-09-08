"""Independent native TS open control/routing with synthetic keys and real HTTP.

No public network, real Vault, dependency installation or scale certification.
The graph tests expose adjacency only to the RPC fixture, never to lookup.
"""
from __future__ import annotations

import asyncio
import base64
import copy
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from memory_vault import MemoryError, canonical_bytes
from memory_vault_network_crypto import EncryptionIdentity
from memory_vault_open_control import (coordinate, contact_key, issue_node, issue_contact,
    issue_lease, sign_request, sign_response, verify_node, verify_contact, verify_request,
    verify_response, verify_lease)
from memory_vault_open_routing import (RoutingTable, LookupBudget, RpcReply, lookup,
    maintenance_target, source_group, distance)
from memory_vault_trust import Identity
from tests import test_network_typescript_agent_network as ts_runtime


DRIVER = r"""
import child from 'node:child_process';
import {syncBuiltinESMExports} from 'node:module';
let subprocessCalls=0;
const deny=()=>{subprocessCalls++;throw Error('native open routing cannot delegate');};
for(const name of ['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork'])child[name]=deny;
syncBuiltinESMExports();
const c=await import('./open-control.ts'),r=await import('./open-routing.ts');
const {canonicalBytes}=await import('./crypto.ts');
const chunks=[];let size=0;
for await(const chunk of process.stdin){size+=chunk.length;if(size>2097152)throw Error('fixture size');chunks.push(chunk);}
const input=JSON.parse(Buffer.concat(chunks).toString('utf8'));
let result;
const outcome=async(fn)=>{try{return {ok:true,value:await fn()};}catch(error){return {ok:false,code:error.code??'untyped_error'};}};
if(input.mode==='calls'){
  result=[];for(const call of input.calls)result.push(await outcome(()=>{
    const args=call.args??[];if(call.raw)args.unshift(Buffer.from(call.raw,'base64'));
    const value=(c[call.name]??r[call.name])(...args);
    return value instanceof Uint8Array?Buffer.from(value).toString('hex'):value;
  }));
}else if(input.mode==='agent'){
  const {Agent}=await import('./agent.ts');let networkCalls=0;
  const agent=new Agent(input.client_config,input.network_config,{transport:{request:()=>{networkCalls++;throw Error('no network permitted');}}});
  result={responses:[],networkCalls:0};for(const request of input.requests)result.responses.push(await agent.handle(request));result.networkCalls=networkCalls;
}else if(input.mode==='table'){
  let now=input.now;const table=new r.RoutingTable(input.self_key,{directory:input.directory,clock:()=>now});
  result=[];for(const event of input.events){
    const item=await outcome(()=>event.op==='learn'?table.learnVerified(event.node,event.address,event.allow_eviction??true):
      event.op==='fail'?table.markFailed(event.key):(now=event.now,null));
    result.push({...item,stats:table.stats(),closest:table.closest(input.target,input.view??'general').map(n=>n.payload.signing_key.key_id),
      ...(input.include_replies?{replies:table.replyCandidates(input.target,input.view??'general').map(n=>n.payload.signing_key.key_id)}:{})});
  }
}else if(input.mode==='lookup'||input.mode==='http'){
  const table=new r.RoutingTable(input.self_key,{directory:input.directory??false,clock:()=>input.now});
  const calls=[],signer=input.signer;let sequence=0;
  const signRequest=(node,action,body)=>c.signRequest(signer,{node,action,body,request_id:'synthetic_lookup_'+sequence++,issued_at:input.now,expires_at:input.now+60});
  let rpc;
  if(input.mode==='lookup')rpc=async(node,request)=>{
    const key=node.payload.signing_key.key_id;calls.push(key);
    const fixture=input.graph[key];
    if(fixture.delay)await new Promise(resolve=>setTimeout(resolve,fixture.delay));
    if(fixture.error)throw Object.assign(Error('synthetic unreachable'),{code:fixture.error});
    const response=c.signResponse(fixture.signer,{node,request,body:{nodes:fixture.nodes},issued_at:input.now,expires_at:input.now+60});
    return {response,observed_address:fixture.address,wire_bytes:canonicalBytes(response).length};
  };
  else{
    const http=await import('node:http'),{performance}=await import('node:perf_hooks');
    rpc=(node,request,deadline)=>new Promise((resolve,reject)=>{
      // This fixture transport permits ONLY an explicitly owned literal loopback.
      // It is not an implementation of production public DNS/TLS policy.
      const url=new URL(node.payload.base_url);if(url.protocol!=='http:'||url.hostname!=='127.0.0.1')throw Error('owned loopback only');
      calls.push(node.payload.signing_key.key_id);const data=canonicalBytes(request);
      const req=http.request(new URL('/open/v1/rpc',url),{method:'POST',headers:{'content-type':'application/json','content-length':data.length}},res=>{
        const address=res.socket.remoteAddress,parts=[];let count=0;
        res.on('data',part=>{count+=part.length;if(count>65536){req.destroy();reject(Error('response budget'));}else parts.push(part);});
        res.on('end',()=>{if(res.statusCode!==200)return reject(Error('HTTP status'));resolve({response:Buffer.concat(parts),observed_address:address,wire_bytes:count});});
      });
      req.setTimeout(Math.max(1,(deadline-performance.now()/1000)*1000),()=>req.destroy(Error('deadline')));
      req.on('error',reject);req.end(data);
    });
  }
  result=await r.lookup(table,input.target,{view:input.view??'general',rpc,signRequest,initialLanes:input.lanes,
    budget:new r.LookupBudget(input.budget??{})});
  const snapshot=table.stats();if(input.wait_after)await new Promise(resolve=>setTimeout(resolve,input.wait_after));
  result={...result,calls,stats:table.stats(),stats_at_return:snapshot};
}else throw Error('fixture mode');
process.stdout.write(JSON.stringify({result,subprocessCalls}));
"""


def synthetic_identity(label):
    secret = hashlib.sha256(("synthetic open fixture: " + label).encode()).digest()
    signer = Identity(Ed25519PrivateKey.from_private_bytes(secret))
    private = {**signer.public_descriptor(), "schema_version": "universal-memory-identity/v1",
               "private_key": base64.b64encode(secret).decode()}
    return signer, private


class OpenTypeScriptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Reuse only installed-runtime validation and disposable copying, not tests.
        ts_runtime.TypeScriptAgentNetworkTests.setUpClass.__func__(cls)
        (cls.fixture / "driver.mjs").write_text(DRIVER)

    def setUp(self):
        self.now = 2_000_000_000
        self.owner, self.owner_doc = synthetic_identity("owner")
        self.server, self.server_doc = synthetic_identity("server")
        self.other, self.other_doc = synthetic_identity("other")
        self.node = self.make_node(self.server)
        self.contact = issue_contact(self.owner, encryption_key=EncryptionIdentity.generate().public_descriptor(),
            revision=1, allow_discovery=True, endpoints=[], issued_at=self.now, expires_at=self.now + 3600)

    def make_node(self, signer, **changes):
        values = dict(base_url="http://127.0.0.1:18501", storage_epoch="synthetic_epoch",
            roles=["directory", "router"], revision=1, issued_at=self.now, expires_at=self.now + 3600)
        values.update(changes)
        return issue_node(signer, **values)

    def ts(self, **value):
        process = subprocess.run([self.node_runtime, "--experimental-strip-types", str(self.fixture / "driver.mjs")],
            input=json.dumps(value).encode(), cwd=self.fixture, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=25)
        self.assertEqual(process.returncode, 0, process.stderr.decode(errors="replace")[-6000:])
        result = json.loads(process.stdout)
        self.assertEqual(result["subprocessCalls"], 0)
        return result["result"]

    @property
    def node_runtime(self):
        return type(self).node

    def call(self, name, *args):
        return self.ts(mode="calls", calls=[dict(name=name, args=list(args))])[0]

    def request(self, action, body):
        return sign_request(self.owner, action=action, request_id="synthetic_request_" + action,
            node=self.node, body=body, issued_at=self.now, expires_at=self.now + 60)

    def test_exact_signed_bytes_all_actions_and_leases(self):
        options = {key: self.node["payload"][key] for key in ("base_url", "storage_epoch", "roles", "revision", "issued_at", "expires_at", "status")}
        calls = [dict(name="issueNode", args=[self.server_doc, options])]
        expected = [self.node]
        contact_options = {key: value for key, value in self.contact["payload"].items()
                           if key not in {"schema_version", "kind", "signing_key"}}
        calls.append(dict(name="issueContact", args=[self.owner_doc, contact_options])); expected.append(self.contact)
        for action, body in (("hello", {"node": None}), ("find", {"target": coordinate(self.other.key_id), "view": "directory"}),
                ("get", {"key": contact_key(self.owner.key_id)}), ("put", {"contact": self.contact, "lease_seconds": 120}),
                ("renew", {"contact": self.contact, "lease_id": "synthetic_lease", "lease_seconds": 120})):
            request = self.request(action, body)
            calls.append(dict(name="signRequest", args=[self.owner_doc, dict(action=action, request_id=request["payload"]["request_id"],
                node=self.node, body=body, issued_at=self.now, expires_at=self.now + 60)])); expected.append(request)
            if action in {"put", "renew"}:
                lease_options = dict(node=self.node, contact=self.contact, request=request, lease_id="synthetic_lease",
                    issued_at=self.now, expires_at=self.now + 120)
                lease = issue_lease(self.server, **lease_options)
                calls.append(dict(name="issueLease", args=[self.server_doc, lease_options])); expected.append(lease)
                response_body = {"lease": lease}
            else:
                response_body = {"node": self.node} if action == "hello" else {"nodes": [self.node]} if action == "find" else {"state": "not_found"}
            response_options = dict(request=request, node=self.node, body=response_body, issued_at=self.now, expires_at=self.now + 60)
            response = sign_response(self.server, **response_options)
            calls.append(dict(name="signResponse", args=[self.server_doc, response_options])); expected.append(response)
        results = self.ts(mode="calls", calls=calls)
        for result, value in zip(results, expected):
            self.assertTrue(result["ok"], result)
            self.assertEqual(canonical_bytes(result["value"]), canonical_bytes(value))

    def test_shared_raw_negative_vectors_error_parity(self):
        request = self.request("hello", {"node": None})
        response = sign_response(self.server, request=request, node=self.node, body={"node": self.node}, issued_at=self.now, expires_at=self.now+60)
        vectors = []
        def add(name, value, options, verifier):
            raw = value if isinstance(value, bytes) else canonical_bytes(value)
            try: expected = {"ok": True, "value": verifier(raw, **options)}
            except MemoryError as exc: expected = {"ok": False, "code": exc.code}
            vectors.append((dict(name=name, raw=base64.b64encode(raw).decode(), args=[options]), expected))
        for name, original, signer, options, verifier in (
                ("verifyNode", self.node, self.server, dict(now=self.now), verify_node),
                ("verifyContact", self.contact, self.owner, dict(now=self.now), verify_contact),
                ("verifyRequest", request, self.owner, dict(node=self.node, now=self.now), verify_request),
                ("verifyResponse", response, self.server, dict(node=self.node, request=request, now=self.now), verify_response)):
            add(name, original, options, verifier)
            add(name, b'{"payload":{},' + canonical_bytes(original)[1:], options, verifier)
            add(name, original, {**options,"now":original["payload"]["expires_at"]}, verifier)
            add(name, original, {**options,"now":self.now-31}, verifier)
            tampered=copy.deepcopy(original);tampered["proof"]["signature"]=base64.b64encode(bytes(64)).decode()
            add(name,tampered,options,verifier)
            for field,value in (("schema_version","other-proof/v1"),("payload_sha256","0"*64),
                                ("payload_sha256","invalid"),("signature","invalid"),("arbitrary",True)):
                changed=copy.deepcopy(original);changed["proof"][field]=value
                add(name,changed,options,verifier)
            for field, value in (("schema_version", "memory-vault-network-control/v1"), ("issued_at", True),
                                 ("expires_at", 2**53), ("expires_at", self.now), ("arbitrary", "synthetic")):
                changed = copy.deepcopy(original); changed["payload"][field] = value
                if value != 2**53: changed["proof"] = signer.sign_message(changed["payload"])
                add(name, changed, options, verifier)
        for field, value in (("request_sha256", "0"*64), ("storage_epoch", "other_epoch"), ("request_id", "other_request")):
            changed = copy.deepcopy(response); changed["payload"][field] = value
            changed["proof"] = self.server.sign_message(changed["payload"])
            add("verifyResponse", changed, dict(node=self.node, request=request, now=self.now), verify_response)
        results = self.ts(mode="calls", calls=[item[0] for item in vectors])
        for index, (actual, (_, expected)) in enumerate(zip(results, vectors)):
            with self.subTest(index=index): self.assertEqual(actual, expected)

    def test_coordinate_distance_source_groups_and_maintenance_vectors(self):
        calls, expected = [], []
        for key in (self.owner.key_id, self.server.key_id, self.other.key_id):
            for name, function in (("coordinate", coordinate), ("contactKey", contact_key)):
                calls.append(dict(name=name, args=[key])); expected.append({"ok": True, "value": function(key)})
            calls.append(dict(name="maintenanceTarget", args=[key, 2**53-1])); expected.append({"ok": True, "value": maintenance_target(key, 2**53-1)})
        for left, right in (("0"*64, "f"*64), (coordinate(self.owner.key_id), coordinate(self.server.key_id))):
            calls.append(dict(name="distance", args=[left,right])); expected.append({"ok":True,"value":f"{distance(left,right):064x}"})
        for address in ("192.0.2.9", "2001:db8:abcd:1234::1", "::ffff:192.0.2.9", "::1", "2001:0:0:1::2", "host.invalid", "fe80::1%lo0"):
            calls.append(dict(name="sourceGroup", args=[address]))
            try: expected.append({"ok":True,"value":source_group(address)})
            except MemoryError as exc: expected.append({"ok":False,"code":exc.code})
        self.assertEqual(self.ts(mode="calls", calls=calls), expected)

    def test_table_event_parity_source_caps_revisions_and_replacements(self):
        table = RoutingTable(self.owner.key_id, directory=True, now=lambda:self.now)
        events, expected, same_bucket = [], [], []
        wanted = None
        for index in range(80):
            signer, _ = synthetic_identity("table_"+str(index)); node = self.make_node(signer)
            bucket = distance(coordinate(self.owner.key_id), node["payload"]["coordinate"]).bit_length()-1
            if wanted is None: wanted = bucket
            if bucket == wanted: same_bucket.append((signer,node))
            if len(same_bucket) == 14: break
        self.assertEqual(len(same_bucket),14)
        for index, (_, node) in enumerate(same_bucket):
            events.append(dict(op="learn",node=node,address=f"192.0.{index//2}.1"))
        signer, original = same_bucket[0]
        updated = self.make_node(signer,revision=2,roles=["router"])
        events += [dict(op="learn",node=updated,address="198.51.100.1"),dict(op="learn",node=original,address="198.51.100.1")]
        events += [dict(op="fail",key=original["payload"]["signing_key"]["key_id"])]*2
        for event in events:
            try:
                value = table.learn_verified(event["node"],event["address"]) if event["op"]=="learn" else table.mark_failed(event["key"])
                item = {"ok":True,"value":value}
            except MemoryError as exc: item = {"ok":False,"code":exc.code}
            expected.append({**item,"stats":table.stats(),"closest":[n["payload"]["signing_key"]["key_id"] for n in table.closest("0"*64)]})
        self.assertEqual(self.ts(mode="table",self_key=self.owner.key_id,directory=True,now=self.now,target="0"*64,events=events),expected)

    def graph_fixture(self):
        pairs=[synthetic_identity("route_"+str(index)) for index in range(7)]
        nodes=[self.make_node(pair[0]) for pair in pairs]
        edges=[[2],[2,3],[4],[5],[6],[],[]]
        graph={node["payload"]["signing_key"]["key_id"]:dict(signer=pairs[index][1],nodes=[nodes[i] for i in edges[index]],
            address=f"192.0.{index}.1",delay=3 if index==2 else 1 if index<2 else 0) for index,node in enumerate(nodes)}
        return pairs,nodes,graph

    def test_verified_replacement_reply_parity_preserves_active_and_source_limits(self):
        nodes = []
        for index in range(100):
            signer, _ = synthetic_identity("reply_replacement_" + str(index))
            node = self.make_node(signer)
            if distance(coordinate(self.owner.key_id), node["payload"]["coordinate"]).bit_length() == 256:
                nodes.append(node)
            if len(nodes) == 10:
                break
        self.assertEqual(len(nodes), 10)
        target = nodes[-1]["payload"]["coordinate"]
        late_id = nodes[-1]["payload"]["signing_key"]["key_id"]
        for shared_source in (False, True):
            for view in ("general", "directory"):
                with self.subTest(shared_source=shared_source, view=view):
                    clock = [self.now]
                    table = RoutingTable(self.owner.key_id, directory=True, now=lambda: clock[0])
                    events = [dict(op="learn", node=node,
                        address=f"192.0.{0 if shared_source else i}.1") for i, node in enumerate(nodes)]
                    events.append(dict(op="clock", now=self.now + 3601))
                    expected = []
                    for event in events:
                        if event["op"] == "learn":
                            value = table.learn_verified(event["node"], event["address"])
                        else:
                            clock[0] = event["now"]
                            value = None
                        expected.append(dict(ok=True, value=value, stats=table.stats(),
                            closest=[n["payload"]["signing_key"]["key_id"] for n in table.closest(target, view)],
                            replies=[n["payload"]["signing_key"]["key_id"] for n in table.reply_candidates(target, view)]))
                    actual = self.ts(mode="table", self_key=self.owner.key_id, directory=True,
                        now=self.now, target=target, view=view, events=events, include_replies=True)
                    self.assertEqual(actual, expected)
                    self.assertNotIn(late_id, actual[-2]["closest"])
                    self.assertEqual(actual[-2]["replies"][0], late_id)
                    self.assertEqual(len(actual[-2]["replies"]), 2 if shared_source else 8)
                    self.assertEqual(actual[-2]["closest"], actual[7]["closest"])
                    self.assertEqual(actual[-1]["replies"], [])

    def test_expiry_promotes_only_previously_verified_live_replacement(self):
        now=[self.now]; table=RoutingTable(self.owner.key_id,now=lambda:now[0]); events=[]; expected=[]; nodes=[]
        for index in range(100):
            signer,_=synthetic_identity("expiry_"+str(index))
            node=self.make_node(signer,roles=["router"],expires_at=self.now+(10 if len(nodes)<8 else 120))
            if distance(coordinate(self.owner.key_id),node["payload"]["coordinate"]).bit_length()!=256:continue
            nodes.append(node)
            if len(nodes)==9:break
        self.assertEqual(len(nodes),9)
        events=[dict(op="learn",node=node,address=f"192.0.{i}.1") for i,node in enumerate(nodes)]
        events.append(dict(op="clock",now=self.now+11))
        for event in events:
            if event["op"]=="learn": value=table.learn_verified(event["node"],event["address"])
            else: now[0]=event["now"];value=None
            expected.append(dict(ok=True,value=value,stats=table.stats(),closest=[n["payload"]["signing_key"]["key_id"] for n in table.closest("0"*64)]))
        actual=self.ts(mode="table",self_key=self.owner.key_id,directory=False,now=self.now,target="0"*64,events=events)
        self.assertEqual(actual,expected)
        self.assertEqual(actual[-1]["closest"],[nodes[-1]["payload"]["signing_key"]["key_id"]])

    def test_lookup_replacement_retention_and_failed_spare_parity(self):
        nodes = []
        for index in range(100):
            signer, _ = synthetic_identity("retained_replacement_" + str(index))
            node = self.make_node(signer)
            if distance(coordinate(self.owner.key_id), node["payload"]["coordinate"]).bit_length() == 256:
                nodes.append(node)
            if len(nodes) == 12:
                break
        self.assertEqual(len(nodes), 12)
        table = RoutingTable(self.owner.key_id, directory=True, now=lambda: self.now)
        target = nodes[8]["payload"]["coordinate"]
        late_id = nodes[8]["payload"]["signing_key"]["key_id"]
        events = [dict(op="learn", node=node, address=f"192.0.{i}.1", allow_eviction=i < 10)
                  for i, node in enumerate(nodes)]
        events += [dict(op="fail", key=late_id)] * 2
        events += [dict(op="learn", node=nodes[10], address="192.0.10.1", allow_eviction=False)]
        expected = []
        for event in events:
            value = (table.learn_verified(event["node"], event["address"],
                        allow_replacement_eviction=event["allow_eviction"]) if event["op"] == "learn"
                     else table.mark_failed(event["key"]))
            expected.append(dict(ok=True, value=value, stats=table.stats(),
                closest=[n["payload"]["signing_key"]["key_id"] for n in table.closest(target)],
                replies=[n["payload"]["signing_key"]["key_id"] for n in table.reply_candidates(target)]))
        actual = self.ts(mode="table", self_key=self.owner.key_id, directory=True,
            now=self.now, target=target, events=events, include_replies=True)
        self.assertEqual(actual, expected)
        self.assertEqual(actual[11]["replies"][0], late_id)
        self.assertIn(late_id, actual[12]["replies"])
        self.assertNotIn(late_id, actual[13]["replies"])
        self.assertEqual(actual[-1]["stats"]["general_replacements"], 2)

    def test_multihop_two_lane_native_crypto_and_python_results(self):
        pairs,nodes,graph = self.graph_fixture()
        lanes=[[nodes[0]],[nodes[1]]]; target=nodes[6]["payload"]["coordinate"]
        actual=self.ts(mode="lookup",self_key=self.owner.key_id,now=self.now,signer=self.owner_doc,target=target,lanes=lanes,graph=graph)
        table=RoutingTable(self.owner.key_id,now=lambda:self.now); calls=[]; sequence=0
        def sign(node,action,body):
            nonlocal sequence
            request=sign_request(self.owner,node=node,action=action,body=body,request_id="synthetic_lookup_"+str(sequence),issued_at=self.now,expires_at=self.now+60)
            sequence+=1; return request
        async def rpc(node,request,deadline):
            key=node["payload"]["signing_key"]["key_id"];calls.append(key); fixture=graph[key]
            await asyncio.sleep(fixture["delay"]/1000)
            signer=pairs[nodes.index(node)][0]
            response=sign_response(signer,node=node,request=request,body={"nodes":fixture["nodes"]},issued_at=self.now,expires_at=self.now+60)
            return RpcReply(response,fixture["address"],len(canonical_bytes(response)))
        expected=asyncio.run(lookup(table,target,rpc=rpc,sign_request=sign,initial_lanes=lanes))
        self.assertEqual(actual["state"],"closest_known"); self.assertFalse(actual["partial"])
        self.assertEqual(actual["candidates"],expected["candidates"])
        self.assertEqual(set(actual["calls"]),set(calls)); self.assertEqual(len(actual["calls"]),7)
        self.assertEqual(len(set(actual["calls"])),7)
        for result in (actual,expected):
            self.assertLessEqual(result["metrics"]["candidate_peak"],32)
            self.assertLessEqual(result["metrics"]["concurrency_peak"],3)
            self.assertTrue(all(n>0 for n in result["metrics"]["lane_requests"]))
            self.assertTrue(any(path["depth"]>=3 for path in result["metrics"]["paths"]))
            shared=next(path for path in result["metrics"]["paths"] if path["key_id"]==nodes[2]["payload"]["signing_key"]["key_id"])
            self.assertEqual(shared["source_bits"],3)

    def test_timeout_has_no_late_table_mutation(self):
        _,nodes,graph=self.graph_fixture(); key=nodes[0]["payload"]["signing_key"]["key_id"]
        graph[key]["delay"]=120
        result=self.ts(mode="lookup",self_key=self.owner.key_id,now=self.now,signer=self.owner_doc,target="0"*64,
            lanes=[[nodes[0]]],graph=graph,budget={"maximum_seconds":0.02},wait_after=160)
        self.assertEqual(result["state"],"budget_exhausted")
        self.assertEqual(result["stats"],result["stats_at_return"])
        self.assertEqual(result["stats"]["general_active"],0)
        self.assertEqual(result["metrics"]["requests"],1)

    def test_shared_request_budget_drains_sent_work_and_bounds_bytes(self):
        _,nodes,graph=self.graph_fixture()
        result=self.ts(mode="lookup",self_key=self.owner.key_id,now=self.now,signer=self.owner_doc,target="0"*64,
            lanes=[[nodes[0]],[nodes[1]]],graph=graph,budget={"maximum_requests":2})
        self.assertEqual(result["state"],"budget_exhausted")
        self.assertEqual(result["metrics"]["requests"],2)
        self.assertEqual(len(result["metrics"]["paths"]),2)
        self.assertTrue(all(path["state"]=="verified" for path in result["metrics"]["paths"]))
        self.assertEqual(set(result["calls"]),{node["payload"]["signing_key"]["key_id"] for node in nodes[:2]})
        self.assertLessEqual(result["metrics"]["request_bytes"],2*65536)
        self.assertLessEqual(result["metrics"]["response_bytes"],4*1024*1024)
        small=self.ts(mode="lookup",self_key=self.owner.key_id,now=self.now,signer=self.owner_doc,target="0"*64,
            lanes=[[nodes[0]]],graph=graph,budget={"maximum_bytes":65535})
        self.assertEqual(small["state"],"budget_exhausted"); self.assertEqual(small["calls"],[])

    def test_native_agent_targeted_discovery_refuses_unsupported_runtime_without_network(self):
        with tempfile.TemporaryDirectory(prefix="memory-vault-open-selector-synthetic-") as temporary:
            root=Path(temporary).resolve(); private=root/"private.json"; opened=root/"open.json"
            private.write_text(json.dumps({"schema_version":"memory-vault-network-config/v1"}));private.chmod(0o600)
            opened.write_text(json.dumps({"schema_version":"memory-vault-open-client-config/v1"}));opened.chmod(0o600)
            for config, requests, codes in (
                (private,[{"op":"discover","key_id":self.owner.key_id},{"op":"discover","online":True,"key_id":"invalid"},
                    {"op":"discover","online":True,"key_id":self.owner.key_id+"\n"},
                    {"op":"discover","online":True,"key_id":self.owner.key_id}],
                    ["invalid_client_arguments","invalid_client_arguments","invalid_client_arguments","network_targeted_discovery_unsupported"]),
                (opened,[{"op":"connect"},{"op":"discover","online":True,"key_id":self.owner.key_id}],
                    ["open_profile_runtime_unsupported","open_profile_runtime_unsupported"])):
                snapshot={p.name:p.read_bytes() for p in root.iterdir()}
                result=self.ts(mode="agent",network_config=str(config),client_config=str(root/"absent-client.json"),requests=requests)
                self.assertEqual(result["networkCalls"],0)
                self.assertEqual([item["error"]["code"] for item in result["responses"]],codes)
                self.assertEqual({p.name:p.read_bytes() for p in root.iterdir()},snapshot)

    def test_directory_stage_follows_router_introduction_then_only_providers(self):
        pairs,nodes,graph=self.graph_fixture()
        nodes[0]=self.make_node(pairs[0][0],roles=["router"])
        nodes[1]=self.make_node(pairs[1][0],roles=["directory"])
        nodes[2]=self.make_node(pairs[2][0],roles=["router"])
        # Provider response also carries an ordinary-router decoy. Once this
        # lane has a provider it must not spend directory search on that decoy.
        graph[nodes[0]["payload"]["signing_key"]["key_id"]]["nodes"]=[nodes[1]]
        graph[nodes[1]["payload"]["signing_key"]["key_id"]]["nodes"]=[nodes[2]]
        result=self.ts(mode="lookup",self_key=self.owner.key_id,now=self.now,signer=self.owner_doc,target="0"*64,
            lanes=[[nodes[0]]],graph=graph,view="directory")
        self.assertEqual(result["candidates"],[nodes[1]])
        self.assertEqual(result["calls"],[node["payload"]["signing_key"]["key_id"] for node in nodes[:2]])
        self.assertEqual(result["stats"]["general_active"],1)
        self.assertEqual(result["stats"]["directory_introductions"],1)

    def test_native_ts_lookup_over_actual_python_http_multihop(self):
        from memory_vault_open_node import OpenParticipant, OpenHTTPServer
        self.now=int(time.time())
        with tempfile.TemporaryDirectory(prefix="memory-vault-open-http-synthetic-") as temporary:
            root=Path(temporary).resolve(); participants=[]; servers=[]; threads=[]; nodes=[]
            try:
                for index in range(3):
                    signer,_=synthetic_identity("http_"+str(index))
                    with socket.socket() as reserved:
                        reserved.bind(("127.0.0.1",0)); port=reserved.getsockname()[1]
                    node=self.make_node(signer,base_url=f"http://127.0.0.1:{port}")
                    participant=OpenParticipant(signer,root/str(index),descriptor=node,seeds=nodes[-1:],allow_loopback=True,index_policy={"enabled":True})
                    server=OpenHTTPServer(("127.0.0.1",port),participant)
                    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
                    participants.append(participant);servers.append(server);threads.append(thread);nodes.append(node)
                    asyncio.run(participant.join())
                # Only bounded real signed hello/maintenance learns remote endpoints.
                for participant in participants: asyncio.run(participant.maintain())
                result=self.ts(mode="http",self_key=self.owner.key_id,now=self.now,signer=self.owner_doc,
                    target=nodes[2]["payload"]["coordinate"],lanes=[[nodes[0]]],view="directory")
                self.assertEqual(result["state"],"closest_known",result)
                self.assertIn(nodes[2],result["candidates"])
                self.assertGreaterEqual(len(set(result["calls"])),2)
                self.assertTrue(any(path["depth"]>0 for path in result["metrics"]["paths"]))
                self.assertEqual(result["stats"]["directory_introductions"],2)  # one observed /24 permits two retained introductions
            finally:
                for server in servers:server.shutdown();server.server_close()
                for thread in threads:thread.join(3);self.assertFalse(thread.is_alive())
                for participant in participants:participant.close()


if __name__ == "__main__":
    unittest.main()
