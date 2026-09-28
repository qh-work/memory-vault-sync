"""Approved delivery and denied authority over disposable, real loopback HTTP."""
import asyncio
import json
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest

from memory_vault import canonical_bytes
from memory_vault_agent import Agent
from memory_vault_client import ClientConfig
from memory_vault_open_contact_client import CONNECT_SCHEMA, OpenContactClient
from memory_vault_open_routing import LookupBudget
from memory_vault_storage import atomic_write
from memory_vault_trust import TrustStore
from tests.test_open_agent import configured_agent
from tests.test_open_node import HTTPNodes


class DeliveryHTTPTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="memory-delivery-http-synthetic-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.host = HTTPNodes(self.root, 1)
        self.addCleanup(self.host.close)
        self.host.stop(0)
        config = json.loads(self.host.configs[0].read_bytes())
        config.update(contact_policy={"enabled": True}, delivery_policy={"enabled": True})
        atomic_write(self.host.configs[0], canonical_bytes(config), replace=True)
        self.host.start(0)
        self.a, self.ai, *_ = configured_agent(SimpleNamespace(root=self.root / "a", nodes=self.host.nodes))
        self.b, self.bi, *_ = configured_agent(SimpleNamespace(root=self.root / "b", nodes=self.host.nodes))

    def call(self, agent, **request):
        result = agent.handle(request)
        self.assertTrue(result["ok"], result)
        return result["result"]

    def contact(self, agent, action, **values):
        return self.call(agent, op="connect", invitation={"schema_version": CONNECT_SCHEMA,
                         "action": action, **values})

    def request_contact(self):
        enabled = self.contact(self.b, "enable", node=self.host.nodes[0],
            allocation_id="synthetic_delivery_knock", max_pending=2, lease_seconds=3600, revision=1)
        self.call(self.a, op="connect", request_id="req_delivery_contact", invitation={
            "schema_version": CONNECT_SCHEMA, "action": "request", "recipient_key_id": self.bi.key_id})
        pending = self.contact(self.b, "poll", lease_id=enabled["lease_id"])
        return enabled, pending["requests"][0]["request_ref"]

    def decide(self, reference, decision):
        self.contact(self.b, "decide", request_ref=reference, decision=decision,
                     max_items=1, max_bytes=6291456)
        return self.contact(self.a, "result", request_id="req_delivery_contact")

    def stored_count(self):
        with sqlite3.connect(self.root / "node_0/transport/network.sqlite3") as db:
            return db.execute("SELECT count(*) FROM open_delivery_messages").fetchone()[0]

    def test_approved_memory_saved_receipt_and_restart_recall(self):
        # Author trust is a separate fixture choice, never inferred from consent.
        TrustStore(ClientConfig.load(self.b.client_config).trust_path).add(self.ai.public_descriptor())
        text = "Synthetic observation: service S was unavailable; check current evidence before reuse."
        memory = self.call(self.a, op="remember", request_id="req_delivery_memory",
                           kind="observation", text=text)
        _, reference = self.request_contact()
        self.assertTrue(self.decide(reference, "approved")["recipient_approved"])
        with sqlite3.connect(self.root / "node_0/transport/network.sqlite3") as db:
            lifecycle, signed = db.execute("SELECT state,decision FROM open_contact_requests").fetchone()
        self.assertEqual(lifecycle, "decided")
        self.assertEqual(json.loads(signed)["payload"]["decision"], "approved")
        request = {"op": "send", "request_id": "req_delivery_send", "recipients": [self.bi.key_id],
                   "text": "Synthetic selected memory", "memory_ids": [memory["memory_id"]]}
        sent = self.call(self.a, **request)
        self.assertTrue(sent["storage_accepted"])
        self.assertFalse(sent["endpoint_validated"])
        received = self.call(self.b, op="receive", limit=4)
        self.assertEqual(received["errors"], [])
        self.assertEqual(len(received["messages"]), 1)
        self.assertEqual(received["messages"][0]["state"], "validated_saved")
        self.assertIsNone(received["messages"][0]["text_memory_id"])
        self.host.stop(0)
        self.host.start(0)
        self.a = Agent(self.a.client_config, self.a.network_config)
        self.b = Agent(self.b.client_config, self.b.network_config)
        ack = self.call(self.a, **request)
        self.assertTrue(ack["endpoint_validated"])
        self.assertEqual(ack["message_id"], sent["message_id"])
        recalled = self.call(self.b, op="recall", memory_id=memory["memory_id"])
        self.assertEqual(recalled["hits"][0]["text"], text)
        changed = self.a.handle({**request, "text": "Changed under the same request ID"})
        self.assertFalse(changed["ok"])
        self.assertEqual(changed["error"]["code"], "network_request_id_conflict")
        self.assertEqual(self.stored_count(), 1)

    def test_pending_and_rejected_contact_cannot_store(self):
        _, reference = self.request_contact()
        request = {"op": "send", "request_id": "req_delivery_denied", "recipients": [self.bi.key_id],
                   "text": "Synthetic unapproved message"}
        for decision in (None, "rejected"):
            if decision is not None:
                self.assertFalse(self.decide(reference, decision)["recipient_approved"])
            denied = self.a.handle(request)
            self.assertFalse(denied["ok"])
            self.assertEqual(denied["error"]["code"], "open_contact_approval_required")
            self.assertEqual(self.stored_count(), 0)

    def test_policy_revoked_after_approval_cannot_store(self):
        enabled, reference = self.request_contact()
        self.assertTrue(self.decide(reference, "approved")["recipient_approved"])
        with self.b._network() as network:
            contact = OpenContactClient(network.participant, network.encryption)
            session = contact._load("policy", enabled["lease_id"])
            payload = {**session["policy"]["payload"], "revision": 2, "status": "revoked"}
            revoked = {"payload": payload, "proof": self.bi.sign_message(payload)}
            asyncio.run(contact.call(self.host.nodes[0], "policy.put",
                {"lease": session["lease"], "policy": revoked}, LookupBudget()))
        denied = self.a.handle({"op": "send", "request_id": "req_delivery_revoked",
                               "recipients": [self.bi.key_id], "text": "Synthetic revoked message"})
        self.assertFalse(denied["ok"])
        self.assertEqual(denied["error"]["code"], "open_delivery_revoked")
        self.assertEqual(self.stored_count(), 0)


if __name__ == "__main__":
    unittest.main()
