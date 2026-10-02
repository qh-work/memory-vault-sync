"""Bounded synthetic routing hints; exact signatures and checkpoints stay live."""
import asyncio
import copy
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from memory_vault import MemoryError, canonical_bytes
from memory_vault_open_control import coordinate, issue_node, sign_response, verify_request, verify_response
from memory_vault_open_node import OpenParticipant
from memory_vault_open_routing import LookupBudget
from memory_vault_trust import Identity


class NeighborTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.identities = [Identity.generate(Path(self.tmp.name).resolve() / str(i) / "identity.json") for i in range(4)]
        now = int(time.time())
        self.nodes = [issue_node(identity, base_url=f"https://synthetic-{i}.invalid",
            storage_epoch=f"synthetic_epoch_{i}", roles=["directory", "router"],
            revision=1, issued_at=now, expires_at=now+600) for i, identity in enumerate(self.identities[:3])]
        self.client = OpenParticipant(self.identities[3], Path(self.tmp.name).resolve()/"client", seeds=[self.nodes[0]])
        self.addCleanup(self.client.close)
        self.client.transport.close()
        self.offline = set()
        self.bad_proofs = set()
        self.calls = []
        self.reply_nodes = None
        self.client.transport = SimpleNamespace(request=self.request, close=lambda: None)
        self.target = coordinate(self.identities[3].key_id)

    def request(self, url, request, *, deadline):
        index = next(i for i, node in enumerate(self.nodes) if node["payload"]["base_url"] == url)
        self.calls.append((index, request["payload"]["action"]))
        if index in self.offline:
            raise OSError("synthetic offline")
        checked = verify_request(request, node=self.nodes[index])
        if checked["action"] == "hello":
            body = {"node": self.nodes[index]}
        else:
            body = {"nodes": self.reply_nodes if self.reply_nodes is not None else [self.nodes[(index+1) % 3]]}
        now = int(time.time())
        response = sign_response(self.identities[index], request=request, node=self.nodes[index], body=body,
            issued_at=now, expires_at=min(now+60, checked["expires_at"]))
        if index in self.bad_proofs:
            response = copy.deepcopy(response)
            response["payload"]["expires_at"] -= 1
        return SimpleNamespace(response=response, observed_address=f"10.{index}.0.1", wire_bytes=len(canonical_bytes(response)))

    def step(self, **kwargs):
        return asyncio.run(self.client.find_neighbors(self.target, **kwargs))

    def test_response_after_second_boundary_retains_original_request_deadline(self):
        request = self.client._request(self.nodes[0], "find", {"target": self.target, "view": "general"})
        now = request["payload"]["issued_at"] + 1
        # Only the synthetic responder clock moves; protocol verification stays live.
        with patch("tests.test_open_neighbors.time", SimpleNamespace(time=lambda: now)):
            reply = self.request(self.nodes[0]["payload"]["base_url"], request, deadline=float("inf"))
        response = verify_response(reply.response, request=request, node=self.nodes[0], now=now)
        self.assertEqual(response["issued_at"], now)
        self.assertEqual(response["expires_at"], request["payload"]["expires_at"])

    def test_new_neighbor_is_challenged_then_used_without_injecting_members(self):
        first = self.step(view="directory")
        self.assertEqual(first["state"], "introduced")
        self.assertFalse(first["introductions_verified"])
        self.assertFalse(first["discovery_grants_access"])
        self.assertEqual(self.calls, [(0, "find"), (1, "hello")])
        self.assertTrue(self.client.table.has_verified(self.nodes[1]))
        before = len(self.calls)
        for _ in range(6):
            self.step()
        reads = [index for index, action in self.calls[before:] if action == "find"]
        self.assertEqual(reads.count(0), 3)
        self.assertEqual(reads.count(1), 3)
        self.assertNotIn((2, "find"), self.calls)
        self.client._neighbor_probe_after = 0  # advance the bounded probe gate
        for _ in range(2):
            self.step()
        self.assertIn((2, "hello"), self.calls)
        for _ in range(3):
            self.step()
        self.assertIn((2, "find"), self.calls)

    def test_bad_introduction_proof_never_enters_dispatch_pool(self):
        self.bad_proofs.add(1)
        result = self.step()
        self.assertEqual(result["state"], "introduced")
        self.assertTrue(result["errors"])
        self.assertFalse(self.client.table.has_verified(self.nodes[1]))
        for _ in range(4):
            self.step()
        self.assertNotIn((1, "find"), self.calls)

    def test_offline_peer_fails_over_but_observed_revocation_is_not_usable(self):
        self.step()
        self.offline.add(0)
        for _ in range(3):
            self.assertEqual(self.step()["state"], "introduced")
        now = int(time.time())
        revoked = issue_node(self.identities[1], base_url=self.nodes[1]["payload"]["base_url"],
            storage_epoch="synthetic_epoch_1", roles=["directory", "router"], revision=2,
            status="revoked", issued_at=now, expires_at=now+600)
        with self.assertRaises(MemoryError):
            self.client._accept(revoked)
        self.assertEqual(self.step()["state"], "unreachable")

    def test_shared_budget_bounds_probe_and_invalid_target_sends_nothing(self):
        result = self.step(budget=LookupBudget(maximum_requests=1))
        self.assertEqual(result["state"], "introduced")
        self.assertEqual(result["metrics"]["requests"], 1)
        self.assertEqual(self.calls, [(0, "find")])
        self.assertFalse(self.client.table.has_verified(self.nodes[1]))
        before = len(self.calls)
        with self.assertRaises(MemoryError):
            asyncio.run(self.client.find_neighbors("not-a-digest"))
        with self.assertRaises(MemoryError):
            self.step(view="private")
        self.assertEqual(len(self.calls), before)

    def test_failed_old_peer_does_not_starve_a_new_introduction(self):
        self.step()
        self.client.table.mark_failed(self.nodes[1]["payload"]["signing_key"]["key_id"])
        self.reply_nodes = [self.nodes[1], self.nodes[2]]
        self.client._neighbor_probe_after = 0
        self.step()
        self.assertIn((2, "hello"), self.calls)
        self.assertTrue(self.client.table.has_verified(self.nodes[2]))

    def test_empty_reply_does_not_delay_the_first_actual_new_peer_probe(self):
        self.reply_nodes=[]
        self.step()
        self.assertEqual(self.client._neighbor_probe_after,0)
        self.reply_nodes=[self.nodes[1]]
        self.step()
        self.assertIn((1,"hello"),self.calls)
        self.assertGreater(self.client._neighbor_probe_after,0)
