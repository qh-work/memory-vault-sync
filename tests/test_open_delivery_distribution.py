"""Explicit independent grants distribute real encrypted delivery and receipts."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sqlite3
import tempfile
import time
from types import SimpleNamespace
import unittest

from memory_vault import canonical_bytes
from memory_vault_client import ClientConfig
from memory_vault_open_contact_client import CONNECT_SCHEMA, OpenContactClient
from memory_vault_open_delivery_client import OpenDeliveryClient
from memory_vault_open_routing import LookupBudget
from memory_vault_storage import atomic_write
from memory_vault_trust import TrustStore
from tests.test_open_agent import configured_agent
from tests.test_open_node import HTTPNodes


class DeliveryDistributionFixture:
    """A and B retain their own keys/Vaults; R0/R1 get distinct owner grants."""
    def __init__(self, directory, *, host_class=HTTPNodes, late_node=False):
        self.root = Path(directory).resolve()
        self.host = host_class(self.root, 2)
        for i in range(2):
            self.host.stop(i)
            config=json.loads(self.host.configs[i].read_bytes())
            config.update(contact_policy={"enabled":True},delivery_policy={"enabled":True})
            atomic_write(self.host.configs[i],canonical_bytes(config),replace=True)
            if not late_node or i == 0:
                self.host.start(i)
        self.a,self.ai,*_=configured_agent(SimpleNamespace(root=self.root/"a",nodes=self.host.nodes[:1]))
        self.b,self.bi,*_=configured_agent(SimpleNamespace(root=self.root/"b",nodes=self.host.nodes[:1]))
        TrustStore(ClientConfig.load(self.b.client_config).trust_path).add(self.ai.public_descriptor())
        self.approvals=[]
        self.setup_attempts=[]

    def close(self):
        self.host.close()

    @staticmethod
    def call(agent, **request):
        value=agent.handle(request)
        if not value["ok"]: raise AssertionError(value)
        return value["result"]

    def contact(self, agent, action, **values):
        request_id = values.pop("request_id") if action == "request" else None
        return self.call(agent,op="connect",**({"request_id":request_id} if request_id else {}),
            invitation={"schema_version":CONNECT_SCHEMA,"action":action,**values})

    def approve(self, index, *, items=4, bytes_limit=2*1024*1024):
        enabled=self.contact(self.b,"enable",node=self.host.nodes[index],
            allocation_id=f"req_synthetic_distribution_knock_{index}",max_pending=2,lease_seconds=3600,revision=index+1)
        request_id=f"req_synthetic_distribution_contact_{index}"
        # A newly started R may not have been challenged by its first neighbor
        # yet. These explicit fixture setup attempts are finite and retained.
        for attempt in range(6):
            value=self.a.handle({"op":"connect","request_id":request_id,"invitation":{
                "schema_version":CONNECT_SCHEMA,"action":"request","recipient_key_id":self.bi.key_id}})
            self.setup_attempts.append({"node":index,"attempt":attempt+1,"ok":value["ok"],
                "code":value.get("error",{}).get("code"),"time":time.monotonic()})
            if value["ok"]: break
            if not value["error"]["retryable"] or attempt==5: raise AssertionError(value)
            time.sleep(.5)
        pending=self.contact(self.b,"poll",lease_id=enabled["lease_id"])
        reference=next(row["request_ref"] for row in pending["requests"] if row["request_id"]==request_id)
        self.contact(self.b,"decide",request_ref=reference,decision="approved",max_items=items,max_bytes=bytes_limit)
        self.contact(self.a,"result",request_id=request_id)
        self.approvals.append(enabled)
        return enabled

    def send(self, i, *, memory_ids=None):
        return self.a.handle({"op":"send","request_id":f"req_synthetic_distribution_send_{i}",
            "recipients":[self.bi.key_id],"text":f"Synthetic distributed payload {i}","memory_ids":memory_ids or []})

    def stored(self):
        result=[]
        for i in range(2):
            with sqlite3.connect(self.root/f"node_{i}"/"transport/network.sqlite3") as db:
                result.append(db.execute("SELECT count(*) FROM open_delivery_messages").fetchone()[0])
        return result


class DeliveryDistributionTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(prefix="synthetic-delivery-distribution-")
        self.addCleanup(temporary.cleanup)
        self.fixture=DeliveryDistributionFixture(temporary.name)
        self.addCleanup(self.fixture.close)

    def test_late_independent_approval_carries_new_messages_and_saved_memory_receipts(self):
        f=self.fixture;f.approve(0,items=2)
        memory=f.call(f.a,op="remember",request_id="req_synthetic_distribution_memory",kind="observation",
            text="Synthetic shared observation retained through approved delivery.")
        first=f.send(0,memory_ids=[memory["memory_id"]]);self.assertTrue(first["ok"],first)
        f.approve(1,items=2)
        messages=[first]+[f.send(i,memory_ids=[memory["memory_id"]]) for i in range(1,4)]
        self.assertTrue(all(x["ok"] for x in messages),messages)
        self.assertEqual(f.stored(),[2,2])
        received=[]
        for _ in range(4):
            value=f.call(f.b,op="receive",limit=1)
            self.assertEqual(value["errors"],[])
            received+=value["messages"]
        self.assertEqual(len(received),4)
        self.assertEqual({x["state"] for x in received},{"validated_saved"})
        location={}
        for index in range(2):
            with sqlite3.connect(f.root/f"node_{index}"/"transport/network.sqlite3") as db:
                location.update((row[0],index) for row in db.execute("SELECT message_id FROM open_delivery_messages"))
        self.assertNotEqual(location[received[0]["message_id"]],location[received[1]["message_id"]])
        for i,result in enumerate(messages):
            ack=f.send(i,memory_ids=[memory["memory_id"]])
            self.assertTrue(ack["ok"],ack)
            self.assertTrue(ack["result"]["endpoint_validated"])
            read=f.call(f.b,op="receive",message_id=result["result"]["message_id"],offset=0)
            self.assertIn(f"payload {i}",read["text"])
        recalled=f.call(f.b,op="recall",memory_id=memory["memory_id"])
        self.assertIn("Synthetic shared observation",recalled["hits"][0]["text"])
        self.assertEqual(f.stored(),[2,2])
        extra=f.send(4)
        self.assertFalse(extra["ok"])
        self.assertEqual(extra["error"]["code"],"open_delivery_approval_capacity")
        self.assertEqual(f.stored(),[2,2])

    def test_atomic_new_send_placement_preserves_each_grant_and_frozen_retry(self):
        f=self.fixture;f.approve(0,items=2);f.approve(1,items=2)
        with f.a._network() as network:
            delivery=OpenDeliveryClient(network.participant,network.encryption,network.client_config)
            sessions=delivery._contact_sessions(outgoing=True,recipient=f.bi.key_id)
            rows=[]
            for i in range(4):
                request_id,text=f"synthetic_freeze_{i}",f"Synthetic frozen {i}"
                input_sha,_=delivery._send_input(request_id,[f.bi.key_id],text,[],None)
                rows.append(delivery._prepare_outbox(request_id,f.bi.key_id,input_sha,text,[]))
            with ThreadPoolExecutor(max_workers=4) as pool:
                frozen=list(pool.map(lambda row:delivery._freeze_dispatch(row,sessions),rows))
            counts={}
            for row in frozen:
                session=json.loads(row["session"])
                scope=delivery._session_scope(session);counts[scope]=counts.get(scope,0)+1
                retry=delivery._freeze_dispatch(row,list(reversed(sessions)))
                self.assertEqual(retry["session"],row["session"])
                self.assertEqual(retry["envelope"],row["envelope"])
            self.assertEqual(sorted(counts.values()),[2,2])

    def test_revoked_exact_policy_does_not_store_on_another_node_without_approval(self):
        f=self.fixture;enabled=f.approve(0,items=2)
        with f.b._network() as network:
            contact=OpenContactClient(network.participant,network.encryption)
            session=contact._load("policy",enabled["lease_id"])
            payload={**session["policy"]["payload"],"revision":2,"status":"revoked"}
            revoked={"payload":payload,"proof":f.bi.sign_message(payload)}
            asyncio.run(contact.call(f.host.nodes[0],"policy.put",{"lease":session["lease"],"policy":revoked},LookupBudget()))
        denied=f.send(0)
        self.assertFalse(denied["ok"])
        self.assertEqual(denied["error"]["code"],"open_delivery_revoked")
        self.assertEqual(f.stored(),[0,0])

    def test_duplicate_session_aliases_do_not_multiply_one_signed_resource(self):
        f=self.fixture;f.approve(0,items=1)
        with f.a._network() as network:
            delivery=OpenDeliveryClient(network.participant,network.encryption,network.client_config)
            session=delivery._contact_sessions(outgoing=True,recipient=f.bi.key_id)[0]
            rows=[]
            for i in range(2):
                request_id,text=f"synthetic_alias_{i}",f"Synthetic alias {i}"
                sha,_=delivery._send_input(request_id,[f.bi.key_id],text,[],None)
                rows.append(delivery._prepare_outbox(request_id,f.bi.key_id,sha,text,[]))
            delivery._freeze_dispatch(rows[0],[session,dict(session)])
            from memory_vault import MemoryError
            with self.assertRaises(MemoryError) as caught:
                delivery._freeze_dispatch(rows[1],[session,dict(session)])
            self.assertEqual(caught.exception.code,"open_delivery_approval_capacity")

    def test_known_old_node_revocation_preserves_frozen_send_and_independent_new_grant(self):
        from memory_vault import MemoryError
        from memory_vault_open_control import issue_node
        f=self.fixture;f.approve(0,items=2)
        first=f.send(0);self.assertTrue(first["ok"],first)
        f.approve(1,items=2)
        raw=f.host.nodes[0]["payload"];now=int(time.time())
        revoked=issue_node(f.host.identities[0],base_url=raw["base_url"],storage_epoch=raw["storage_epoch"],
            roles=raw["roles"],revision=2,status="revoked",issued_at=now,expires_at=now+600)
        with f.a._network() as network:
            with self.assertRaises(MemoryError):network.participant._accept(revoked)
        independent=f.send(1);self.assertTrue(independent["ok"],independent)
        self.assertEqual(f.stored(),[1,1])
        retry=f.send(0);self.assertTrue(retry["ok"],retry)
        self.assertEqual(retry["result"]["message_id"],first["result"]["message_id"])
        self.assertFalse(retry["result"]["endpoint_validated"])
        self.assertEqual(f.stored(),[1,1])

    def test_one_nodes_approved_grant_cannot_be_retargeted_to_another_node(self):
        from memory_vault_open_delivery import sign_rpc, verify_response
        f=self.fixture;f.approve(0,items=1)
        self.assertTrue(f.send(0)["ok"])
        with f.a._network() as network:
            with network.participant.state.db() as db:
                row=db.execute("SELECT intent FROM open_delivery_outbox WHERE request_id='req_synthetic_distribution_send_0'").fetchone()
            request=sign_rpc(f.ai,node=f.host.nodes[0],action="prepare",body={"intent":json.loads(row[0])})
            request["payload"]["node_key_id"]=f.host.nodes[1]["payload"]["signing_key"]["key_id"]
            request["payload"]["storage_epoch"]=f.host.nodes[1]["payload"]["storage_epoch"]
            request["proof"]=f.ai.sign_message(request["payload"])
            reply=network.participant.transport.request(f.host.nodes[1]["payload"]["base_url"],request,deadline=time.monotonic()+4)
            body=verify_response(reply.response,request=request,node=f.host.nodes[1])["body"]
            self.assertIn("error",body)
            self.assertEqual(body["error"]["code"],"contact_wrong_node")
            self.assertNotIn("challenge",body)
        self.assertEqual(f.stored(),[1,0])
