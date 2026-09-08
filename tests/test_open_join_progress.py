"""Bounded real-control regression for lost introductions; no public services."""
from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path
import tempfile
import time
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from memory_vault import MemoryError, canonical_bytes
from memory_vault_open_control import coordinate, issue_node, verify_response
from memory_vault_open_node import OpenParticipant
from memory_vault_open_routing import LookupBudget, RpcReply
from memory_vault_trust import Identity


class _LogicalTransport:
    """Resolve only the requested destination; all protocol code stays native.

    This is logical in-process transport, not an HTTP/physical network claim.
    It never chooses peers, returns global nearest nodes or fabricates signatures.
    """
    allow_loopback = False

    def __init__(self, network):
        self.network = network

    def request(self, url, request, deadline):
        if time.monotonic() >= deadline:
            raise MemoryError("open_lookup_budget_exhausted")
        destination = self.network.urls[url]
        node = self.network.participants[destination]
        response = node.handle(request)
        return RpcReply(response, f"10.77.{destination}.1", len(canonical_bytes(response)))

    def close(self):
        pass


class NativeJoinNetwork:
    def __init__(self, root, count=35):
        now = int(time.time())
        self.identities = [Identity(Ed25519PrivateKey.from_private_bytes(hashlib.sha256(
            f"synthetic-open-join-progress:{i}".encode()).digest())) for i in range(count)]
        self.nodes = [issue_node(identity, base_url=f"https://join-node-{i}.invalid",
            storage_epoch=f"synthetic-join-epoch-{i}", roles=["directory", "router"], revision=1,
            issued_at=now-1, expires_at=now+3599) for i, identity in enumerate(self.identities)]
        self.urls = {node["payload"]["base_url"]: i for i, node in enumerate(self.nodes)}
        self.participants = [OpenParticipant(identity, root/f"endpoint-{i}",
            seeds=[self.nodes[0]] if i else [], descriptor=self.nodes[i]) for i, identity in enumerate(self.identities)]
        for participant in self.participants:
            participant.transport.close()
            participant.transport = _LogicalTransport(self)

    def close(self):
        for participant in self.participants:
            participant.close()

    async def hello(self, sender, recipient, *, advertise=True):
        return await self.participants[sender]._call(self.nodes[recipient], "hello",
            {"node": self.nodes[sender] if advertise else None}, LookupBudget())

    async def fill_first_two_queues(self):
        await self.hello(0, 1, advertise=False)
        await self.hello(1, 0, advertise=False)
        # Thirty-two authentic, reachable nodes introduce themselves before the
        # receiver's next maintenance turn. The 35th endpoint arrives afterwards.
        for sender in range(2, 34):
            for recipient in (0, 1):
                await self.hello(sender, recipient)


class OpenJoinProgressTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="synthetic-open-join-progress-")
        self.addCleanup(self.temporary.cleanup)
        self.network = NativeJoinNetwork(Path(self.temporary.name).resolve())
        self.addCleanup(self.network.close)

    async def test_signed_queue_rejection_preserves_proven_seed_without_claiming_admission(self):
        net = self.network
        await net.fill_first_two_queues()
        late, receiver = net.participants[34], net.participants[0]
        before = list(receiver._pending)
        self.assertEqual(late.table.stats()["general_active"], 0)
        with self.assertRaises(MemoryError) as rejected:
            await net.hello(34, 0)
        self.assertEqual(rejected.exception.code, "open_pending_capacity")
        self.assertTrue(rejected.exception.retryable)
        self.assertEqual(list(receiver._pending), before)
        self.assertEqual(late.table.closest(coordinate(net.identities[0].key_id)), [net.nodes[0]])
        # Proving the receiver's endpoint does not admit our advertisement.
        self.assertNotIn(net.identities[34].key_id, receiver._pending)
        self.assertNotIn(net.nodes[34], receiver.table.reply_candidates(coordinate(net.identities[34].key_id)))

    async def test_maintenance_makes_owner_visible_to_its_verified_near_neighbours(self):
        net = self.network
        owner = net.participants[0]
        target = coordinate(net.identities[0].key_id)
        # Only successful signed hellos establish the owner's local neighbours;
        # none advertises the owner to those endpoints yet.
        for receiver in range(1, len(net.nodes)):
            await net.hello(0, receiver, advertise=False)
        closest = owner.table.closest(target, limit=8)
        self.assertEqual(len(closest), 8)
        by_key = {identity.key_id: i for i, identity in enumerate(net.identities)}
        neighbours = [net.participants[by_key[node["payload"]["signing_key"]["key_id"]]] for node in closest]
        for neighbour in neighbours:
            self.assertNotIn(owner.identity.key_id, neighbour._pending)
        for _ in range(4):
            result = await owner.maintain()
            self.assertLessEqual(result["metrics"]["requests"], 16)
            self.assertLessEqual(result["metrics"]["response_bytes"], 1024*1024)
        # Random refresh coordinates must not leave the owner's own XOR region
        # without introductions. Receivers still need their independent probe.
        for neighbour in neighbours:
            self.assertIn(owner.identity.key_id, neighbour._pending)
            self.assertNotIn(net.nodes[0], neighbour.table.closest(target))
            await neighbour.maintain()
            self.assertIn(net.nodes[0], neighbour.table.closest(target))

    async def test_full_pending_returns_signed_retryable_backpressure_without_discarding_existing(self):
        net = self.network
        await net.fill_first_two_queues()
        receiver, late = net.participants[0], net.participants[34]
        before = list(receiver._pending)
        request = late._request(net.nodes[0], "hello", {"node": net.nodes[34]})
        response = receiver.handle(request)
        payload = verify_response(response, request=request, node=net.nodes[0])
        self.assertEqual(payload["body"], {"error": {"code": "open_pending_capacity", "retryable": True}})
        self.assertEqual(list(receiver._pending), before)
        self.assertEqual(len(receiver._pending), 32)
        await net.hello(2, 0)
        self.assertEqual(list(receiver._pending), before)
        self.assertEqual(len(receiver._pending), 32)
        self.assertNotIn(net.identities[34].key_id,
                         [n["payload"]["signing_key"]["key_id"] for n in receiver.table.closest("0"*64, limit=32)])

    async def test_late_node_reannounces_and_becomes_discoverable_within_original_twenty_cycles(self):
        net = self.network
        await net.fill_first_two_queues()
        await net.participants[34].join()
        late_id = net.identities[34].key_id
        target = coordinate(late_id)
        for receiver in net.participants[:2]:
            self.assertNotIn(late_id, receiver._pending)
            self.assertNotIn(late_id, [n["payload"]["signing_key"]["key_id"]
                                      for n in receiver.table.closest(target, limit=32)])
        # Only actual runtime maintenance advances state. No route, pending
        # item, signature, neighbor address or target descriptor is injected.
        for _ in range(20):
            for index in (0, 1, 34):
                result = await net.participants[index].maintain()
                self.assertLessEqual(result["metrics"]["requests"], 16)
                self.assertLessEqual(result["metrics"]["request_bytes"], 16*65536)
                self.assertLessEqual(result["metrics"]["response_bytes"], 1024*1024)
                self.assertLessEqual(len(net.participants[index]._pending), 32)
        result = await net.participants[1]._lookup(target, "general", LookupBudget())
        self.assertIn(late_id, [n["payload"]["signing_key"]["key_id"] for n in result["candidates"]])
        # Discovery must also work for a different caller, initially knowing
        # only the old peers, rather than require every bounded bucket to hold L.
        independent = await net.participants[2]._lookup(target, "general", LookupBudget())
        self.assertIn(late_id, [n["payload"]["signing_key"]["key_id"] for n in independent["candidates"]])
        self.assertTrue(all(not (Path(self.temporary.name)/f"endpoint-{i}"/"vault.sqlite3").exists()
                            for i in range(35)))


if __name__ == "__main__":
    unittest.main()
