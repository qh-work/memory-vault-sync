"""Synthetic Ed25519 control exchanges; no public services or Memory writes."""
from __future__ import annotations

import asyncio
import copy
import hashlib
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from memory_vault import MemoryError, canonical_bytes
from memory_vault_open_control import coordinate, issue_node, sign_request, sign_response, verify_request
from memory_vault_open_routing import (
    LookupBudget, RpcReply, RoutingTable, distance, lookup, maintenance_target, source_group,
)
from memory_vault_trust import Identity


class SyntheticRouting:
    """Transport resolves a requested address only; replies use that node's table.

    The host may observe the global graph for assertions, never to add routes.
    Fixed synthetic seeds generate real signing keys, not mock crypto.
    """
    def __init__(self, count=12, seed=17, directory=None):
        self.now = 2_000_000_000
        self.identities = [Identity(Ed25519PrivateKey.from_private_bytes(hashlib.sha256(
            f"synthetic-open-routing:{seed}:{i}".encode()).digest())) for i in range(count)]
        self.addresses = [f"10.{i // 256}.{i % 256}.1" for i in range(count)]
        self.nodes = [issue_node(identity, base_url=f"https://node-{i}.invalid", storage_epoch=f"synthetic-epoch-{i}",
            roles=["directory", "router"] if directory is None or i in directory else ["router"],
            revision=1, issued_at=self.now - 1, expires_at=self.now + 3599)
            for i, identity in enumerate(self.identities)]
        self.tables = [RoutingTable(identity.key_id, directory=(directory is None or i in directory),
            now=lambda: self.now) for i, identity in enumerate(self.identities)]
        self.by_key = {identity.key_id: i for i, identity in enumerate(self.identities)}
        self.pending = [[] for _ in self.nodes]
        self.offline = set()
        self.serial = self.rpc_count = self.response_bytes = self.request_bytes = 0
        self.active = self.peak = 0
        self.calls = []
        self.respond = None
        self.find_observations = None  # Optional passive synthetic diagnostics.

    def signer(self, caller):
        def sign(peer, action, body):
            self.serial += 1
            return sign_request(self.identities[caller], action=action,
                request_id=f"synthetic-request-{self.serial}", node=peer, body=body,
                issued_at=self.now, expires_at=self.now + 60)
        return sign

    def transport(self, caller):
        async def rpc(peer, request, deadline):
            destination = self.by_key[peer["payload"]["signing_key"]["key_id"]]
            self.rpc_count += 1
            self.request_bytes += len(canonical_bytes(request))
            self.calls.append((caller, destination, request["payload"]["action"]))
            if destination in self.offline:
                raise OSError("synthetic unavailable")
            self.active += 1
            self.peak = max(self.peak, self.active)
            try:
                await asyncio.sleep(0)
                original = verify_request(request, node=self.nodes[destination], now=self.now)
                if self.respond is not None:
                    body = self.respond(caller, destination, original)
                elif original["action"] == "hello":
                    introduced = original["body"]["node"]
                    body = {"node": self.nodes[destination]}
                    if introduced is not None:
                        key = introduced["payload"]["signing_key"]["key_id"]
                        prior = next((i for i, n in enumerate(self.pending[destination])
                            if n["payload"]["signing_key"]["key_id"] == key), None)
                        if self.tables[destination].has_verified(introduced):
                            if prior is not None:
                                del self.pending[destination][prior]
                        elif prior is not None:
                            self.pending[destination][prior] = introduced
                        elif len(self.pending[destination]) >= 32:
                            body = {"error": {"code": "open_pending_capacity", "retryable": True}}
                        else:
                            self.pending[destination].append(introduced)
                else:
                    body = {"nodes": self.tables[destination].reply_candidates(
                        original["body"]["target"], original["body"]["view"])}
                    if self.find_observations is not None:
                        self.find_observations.append({"peer": destination, "returned": [
                            self.by_key[n["payload"]["signing_key"]["key_id"]] for n in body["nodes"]]})
                response = sign_response(self.identities[destination], request=request,
                    node=self.nodes[destination], body=body, issued_at=self.now, expires_at=self.now + 60)
                size = len(canonical_bytes(response))
                self.response_bytes += size
                return RpcReply(response, self.addresses[destination], size)
            finally:
                self.active -= 1
        return rpc

    async def hello(self, caller, peer, budget, *, advertise=True):
        from memory_vault_open_control import verify_response
        request = self.signer(caller)(peer, "hello", {"node": self.nodes[caller] if advertise else None})
        budget.charge_request_bytes(len(canonical_bytes(request)))
        budget.charge_request()
        reply = await self.transport(caller)(peer, request, budget.deadline)
        budget.charge_bytes(reply.wire_bytes)
        payload = verify_response(reply.response, request=request, node=peer, now=self.now)
        # Match OpenParticipant._call: an authenticated hello error proves
        # endpoint reachability while retaining the failed admission outcome.
        self.tables[caller].learn_verified(peer, reply.observed_address)
        if "error" in payload["body"]:
            error = payload["body"]["error"]
            raise MemoryError(error["code"], retryable=error["retryable"])

    async def search(self, caller, target, *, lanes=None, view="general", budget=None):
        return await lookup(self.tables[caller], target, view=view, initial_lanes=lanes,
            rpc=self.transport(caller), sign_request=self.signer(caller), budget=budget)

    async def join_and_maintain(self, cycles=20, progress=None):
        for caller in range(len(self.nodes)):
            budget = LookupBudget()
            seeds = [i for i in (0, 1) if i != caller]
            for destination in seeds:
                try:
                    await self.hello(caller, self.nodes[destination], budget)
                except MemoryError:
                    pass  # Native join also preserves the error and proceeds to bounded lookup.
            result = await self.search(caller, coordinate(self.identities[caller].key_id), budget=budget)
            for peer in result["candidates"][:2]:
                if budget.remaining_requests:
                    try:
                        await self.hello(caller, peer, budget)
                    except MemoryError:
                        pass
            if progress is not None and (caller + 1) % 25 == 0:
                progress({"phase": "join", "nodes_completed": caller + 1, "requests": self.rpc_count})
        if progress is not None:
            progress({"phase": "join_complete", "requests": self.rpc_count})
        for cycle in range(cycles):
            for caller in range(len(self.nodes)):
                budget = LookupBudget(maximum_requests=16, maximum_bytes=1024*1024, maximum_seconds=5)
                pending = self.pending[caller][:2]
                del self.pending[caller][:2]
                for peer in pending:
                    try:
                        await self.hello(caller, peer, budget, advertise=False)
                    except MemoryError:
                        pass
                target = maintenance_target(self.identities[caller].key_id, cycle)
                # Same self-region announcements, periodic own/random refresh
                # target and shared RPC budget as native maintain.
                peers = self.tables[caller].closest(coordinate(self.identities[caller].key_id), "general", limit=8)
                for offset in range(min(2, len(peers))):
                    peer = peers[(cycle * 2 + offset) % len(peers)]
                    try:
                        await self.hello(caller, peer, budget)
                    except MemoryError:
                        pass
                result = await self.search(caller, target, budget=budget)
            if progress is not None and (cycle == 0 or (cycle + 1) % 5 == 0):
                progress({"phase": "maintenance", "cycles_completed": cycle + 1, "requests": self.rpc_count})


class OpenRoutingTests(unittest.IsolatedAsyncioTestCase):
    def reject(self, code, action):
        with self.assertRaises(MemoryError) as caught:
            action()
        self.assertEqual(caught.exception.code, code)

    async def test_rejected_join_can_start_table_only_lookup_through_verified_seed(self):
        net = SyntheticRouting(35)
        for sender in range(2, 34):
            await net.hello(sender, net.nodes[0], LookupBudget())
        before = list(net.pending[0])
        with self.assertRaises(MemoryError) as rejected:
            await net.hello(34, net.nodes[0], LookupBudget())
        self.assertEqual(rejected.exception.code, "open_pending_capacity")
        self.assertEqual(net.pending[0], before)
        self.assertEqual(net.tables[34].stats()["general_active"], 1)
        result = await net.search(34, coordinate(net.identities[0].key_id))
        self.assertEqual(result["candidates"], [net.nodes[0]])
        self.assertEqual(result["metrics"]["requests"], 1)

    def test_coordinate_source_groups_and_exact_distance(self):
        key = "ed25519_" + "1" * 64
        self.assertEqual(coordinate(key), hashlib.sha256(b"memory-vault-open-routing/v1\x00" + key.encode()).hexdigest())
        self.assertEqual(distance("0" * 64, "f" * 64), (1 << 256) - 1)
        self.assertEqual(source_group("192.0.2.254"), "4:192.0.2.0/24")
        self.assertEqual(source_group("::ffff:192.0.2.254"), "4:192.0.2.0/24")
        self.assertEqual(source_group("2001:db8:1:2::abcd"), "6:2001:db8:1::/48")
        for invalid in ("host.invalid", "fe80::1%en0", [], "127.0.0.1:8080"):
            self.reject("open_invalid_observed_address", lambda: source_group(invalid))
        self.reject("network_invalid_digest", lambda: distance("f" * 63, "0" * 64))
        self.assertNotEqual(maintenance_target(key, 0), maintenance_target(key, 1))

    async def test_only_verified_responder_becomes_active_not_its_introductions(self):
        net = SyntheticRouting(3)
        net.respond = lambda caller, dst, req: {"nodes": [net.nodes[2]] if dst == 1 else []}
        net.offline.add(2)
        result = await net.search(0, coordinate(net.identities[2].key_id), lanes=[[net.nodes[1]], []])
        self.assertEqual([n["payload"]["signing_key"]["key_id"] for n in result["candidates"]], [net.identities[1].key_id])
        self.assertEqual(net.tables[0].stats()["general_active"], 1)
        self.assertNotIn(net.nodes[2], net.tables[0].reply_candidates(coordinate(net.identities[2].key_id)))
        self.assertEqual(net.rpc_count, 2)
        self.assertEqual(result["metrics"]["requests"], net.rpc_count)
        self.assertEqual(result["metrics"]["response_bytes"], net.response_bytes)
        self.assertEqual(result["metrics"]["request_bytes"], net.request_bytes)

    def test_stable_bucket_source_cap_replacement_failure_and_revision(self):
        net = SyntheticRouting(60)
        table = net.tables[0]
        groups = {}
        for i in range(1, len(net.nodes)):
            bucket = distance(table.coordinate, coordinate(net.identities[i].key_id)).bit_length()
            groups.setdefault(bucket, []).append(i)
        chosen = next(indices for indices in groups.values() if len(indices) >= 12)
        for i in chosen[:8]:
            self.assertTrue(table.learn_verified(net.nodes[i], net.addresses[i]))
        original = table.closest("0" * 64, limit=32)
        for i in chosen[8:12]:
            self.assertFalse(table.learn_verified(net.nodes[i], net.addresses[i]))
        self.assertEqual(table.closest("0" * 64, limit=32), original)
        self.assertEqual(table.stats()["general_replacements"], 2)
        first = net.identities[chosen[0]].key_id
        self.assertFalse(table.mark_failed(first))
        self.assertTrue(table.mark_failed(first))
        self.assertEqual(table.stats()["general_active"], 8)
        other = RoutingTable(net.identities[0].key_id, now=lambda: net.now)
        for offset, i in enumerate(chosen[:4]):
            self.assertEqual(other.learn_verified(net.nodes[i], f"192.0.2.{offset+1}"), offset < 2)
        self.assertEqual(other.stats()["general_active"], 2)
        i = chosen[1]
        newer = issue_node(net.identities[i], base_url="https://updated.invalid", storage_epoch="synthetic-new-epoch",
            roles=["directory", "router"], revision=2, issued_at=net.now, expires_at=net.now+100)
        table.learn_verified(newer, net.addresses[i])
        self.reject("open_node_rollback", lambda: table.learn_verified(net.nodes[i], net.addresses[i]))
        conflict = issue_node(net.identities[i], base_url="https://different.invalid", storage_epoch="synthetic-new-epoch",
            roles=["directory", "router"], revision=2, issued_at=net.now, expires_at=net.now+100)
        self.reject("open_node_revision_conflict", lambda: table.learn_verified(conflict, net.addresses[i]))
        external = table.closest("0" * 64, limit=32)
        external[0]["payload"]["revision"] = 999
        self.assertNotIn(999, [node["payload"]["revision"] for node in table.closest("0"*64, limit=32)])

    def test_expired_active_slots_promote_only_still_valid_verified_replacements(self):
        net = SyntheticRouting(60)
        table = net.tables[0]
        buckets = {}
        for i in range(1, 60):
            buckets.setdefault(distance(table.coordinate, coordinate(net.identities[i].key_id)).bit_length(), []).append(i)
        selected = next(items for items in buckets.values() if len(items) >= 10)[:10]
        for offset, i in enumerate(selected):
            node = issue_node(net.identities[i], base_url=net.nodes[i]["payload"]["base_url"],
                storage_epoch=f"synthetic-expiry-{i}", roles=["directory", "router"], revision=1,
                issued_at=net.now, expires_at=net.now + (10 if offset < 8 else 100))
            table.learn_verified(node, net.addresses[i])
        self.assertEqual(table.stats()["general_active"], 8)
        self.assertEqual(table.stats()["general_replacements"], 2)
        net.now += 11
        active = table.closest("0" * 64, limit=32)
        self.assertEqual({node["payload"]["signing_key"]["key_id"] for node in active},
                         {net.identities[i].key_id for i in selected[8:]})
        self.assertEqual(table.stats()["general_replacements"], 0)
        net.now += 100
        self.assertEqual(table.closest("0" * 64), [])

    async def test_verified_replacement_is_discovered_by_third_party_without_active_eviction(self):
        net = SyntheticRouting(60)
        table = net.tables[0]
        selected = [i for i in range(1, 60) if distance(table.coordinate,
                    net.nodes[i]["payload"]["coordinate"]).bit_length() == 256][:10]
        self.assertEqual(len(selected), 10)
        for i in selected:
            await net.hello(0, net.nodes[i], LookupBudget(), advertise=False)
        active = table.closest("0" * 64, limit=32)
        late = net.nodes[selected[-1]]
        target = late["payload"]["coordinate"]
        self.assertNotIn(late, active)
        self.assertEqual(table.reply_candidates(target)[0], late)
        self.assertEqual(len(table.reply_candidates(target)), 8)
        caller = next(i for i in range(1, 60) if i not in selected)
        result = await net.search(caller, target, lanes=[[net.nodes[0]], []])
        self.assertEqual(result["candidates"][0], late)
        self.assertIn((caller, selected[-1], "find"), net.calls)
        self.assertEqual(table.closest("0" * 64, limit=32), active)
        # If the introduced endpoint does not answer, the caller cannot return
        # it as verified, even though the introducer remembers an older probe.
        net.offline.add(selected[-1])
        result = await net.search(caller, target, lanes=[[net.nodes[0]], []])
        self.assertNotIn(late, result["candidates"])

    def test_replacement_introductions_keep_source_role_expiry_and_copy_bounds(self):
        net = SyntheticRouting(60)
        table = net.tables[0]
        selected = [i for i in range(1, 60) if distance(table.coordinate,
                    net.nodes[i]["payload"]["coordinate"]).bit_length() == 256][:4]
        for i in selected:
            table.learn_verified(net.nodes[i], "192.0.2.1")
        target = net.nodes[selected[-1]]["payload"]["coordinate"]
        active = table.closest(target, limit=32)
        stats = table.stats()
        self.assertEqual(stats["general_active"], 2)
        self.assertEqual(stats["general_replacements"], 2)
        for view in ("general", "directory"):
            replies = table.reply_candidates(target, view)
            self.assertEqual(len(replies), 2)
            self.assertEqual(replies[0], net.nodes[selected[-1]])
            replies[0]["payload"]["revision"] = 999
            self.assertEqual(table.reply_candidates(target, view)[0]["payload"]["revision"], 1)
        self.assertEqual(table.closest(target, limit=32), active)
        self.assertEqual(table.stats(), stats)
        net.now += 3600
        self.assertEqual(table.reply_candidates(target), [])
        self.assertEqual(table.reply_candidates(target, "directory"), [])

    async def test_lookup_does_not_churn_hello_replacements_and_failed_spares_are_removed(self):
        net = SyntheticRouting(60)
        table = net.tables[0]
        selected = [i for i in range(1, 60) if distance(table.coordinate,
                    net.nodes[i]["payload"]["coordinate"]).bit_length() == 256][:12]
        self.assertEqual(len(selected), 12)
        for i in selected[:10]:
            await net.hello(0, net.nodes[i], LookupBudget(), advertise=False)
        late = net.nodes[selected[8]]
        target = late["payload"]["coordinate"]
        active = table.closest(target, limit=32)
        # These two reachable responders share the already-full bucket. Finds
        # return them as verified results without ejecting earlier join peers.
        result = await net.search(0, target, lanes=[[net.nodes[i] for i in selected[10:]], []])
        self.assertEqual(len(result["candidates"]), 2)
        self.assertEqual(table.reply_candidates(target)[0], late)
        self.assertEqual(table.closest(target, limit=32), active)
        net.offline.add(selected[8])
        for attempt in range(2):
            result = await net.search(0, target, lanes=[[late], []])
            self.assertEqual(result["candidates"], [])
            self.assertEqual(late in table.reply_candidates(target), attempt == 0)
        self.assertEqual(table.stats()["general_replacements"], 1)
        # Ordinary lookup can fill a vacancy after a proven failure.
        await net.search(0, target, lanes=[[net.nodes[selected[10]]], []])
        self.assertEqual(table.stats()["general_replacements"], 2)

    async def test_two_live_lanes_share_rpc_without_first_introducer_ownership(self):
        net = SyntheticRouting(6)
        # Both paths converge on node3, which alone introduces the target4.
        net.respond = lambda caller, dst, req: {"nodes": [net.nodes[3]] if dst in (1, 2)
            else ([net.nodes[4]] if dst == 3 else [])}
        result = await net.search(0, coordinate(net.identities[4].key_id), lanes=[[net.nodes[1]], [net.nodes[2]]])
        calls = [destination for _, destination, _ in net.calls]
        self.assertEqual(calls.count(3), 1)
        self.assertEqual(calls.count(4), 1)
        self.assertEqual(set(calls[:2]), {1, 2})
        self.assertEqual(result["candidates"][0]["payload"]["signing_key"]["key_id"], net.identities[4].key_id)
        paths = {entry["key_id"]: entry for entry in result["metrics"]["paths"]}
        self.assertEqual(paths[net.identities[3].key_id]["source_bits"], 3)
        self.assertLessEqual(result["metrics"]["concurrency_peak"], 3)
        self.assertTrue(all(n > 0 for n in result["metrics"]["lane_requests"]))

    async def test_budget_reserves_bytes_and_rejects_late_signed_result(self):
        net = SyntheticRouting(4)
        tiny = LookupBudget(maximum_requests=1)
        result = await net.search(0, "0" * 64, lanes=[[net.nodes[1]], [net.nodes[2]]], budget=tiny)
        self.assertEqual(result["state"], "budget_exhausted")
        self.assertEqual(net.rpc_count, 1)
        no_bytes = LookupBudget(maximum_bytes=65535)
        result = await net.search(0, "0" * 64, lanes=[[net.nodes[2]]], budget=no_bytes)
        self.assertEqual(result["state"], "budget_exhausted")
        self.assertEqual(no_bytes.requests, 0)
        clock = [0.0]
        budget = LookupBudget(clock=lambda: clock[0])
        real_rpc = net.transport(3)
        async def late(peer, request, deadline):
            reply = await real_rpc(peer, request, deadline)
            clock[0] = 11.0
            return reply
        result = await lookup(net.tables[3], "0"*64, initial_lanes=[[net.nodes[1]]],
            rpc=late, sign_request=net.signer(3), budget=budget)
        self.assertEqual(result["state"], "budget_exhausted")
        self.assertEqual(result["candidates"], [])
        self.assertEqual(net.tables[3].stats()["general_active"], 0)
        self.assertGreater(budget.bytes, 0)

    async def test_signed_challenge_tamper_and_bad_source_never_admit(self):
        net = SyntheticRouting(3)
        original = net.transport(0)
        for fault in ("tamper", "source", "size"):
            async def corrupt(peer, request, deadline):
                reply = await original(peer, request, deadline)
                response = copy.deepcopy(reply.response)
                if fault == "tamper":
                    response["payload"]["request_id"] = "synthetic-wrong-challenge"
                return RpcReply(response, "not-an-ip" if fault == "source" else reply.observed_address,
                                0 if fault == "size" else reply.wire_bytes)
            result = await lookup(net.tables[0], "0"*64, initial_lanes=[[net.nodes[1]]],
                rpc=corrupt, sign_request=net.signer(0))
            self.assertEqual(result["state"], "unreachable")
            self.assertEqual(net.tables[0].stats()["general_active"], 0)
        self.assertEqual(net.rpc_count, 3)

    async def test_shared_global_and_lane_budget_remain_bounded_on_nonconverging_paths(self):
        net = SyntheticRouting(70, directory=set())
        ordered = sorted(range(1, 70), key=lambda i: coordinate(net.identities[i].key_id), reverse=True)
        chains = (ordered[::2], ordered[1::2])
        successors = {chain[i]: chain[i + 1] for chain in chains for i in range(len(chain) - 1)}
        net.respond = lambda caller, dst, req: {"nodes": [net.nodes[successors[dst]]] if dst in successors else []}
        result = await net.search(0, "0" * 64, view="directory",
            lanes=[[net.nodes[chains[0][0]]], [net.nodes[chains[1][0]]]])
        self.assertEqual(result["state"], "budget_exhausted")
        self.assertEqual(result["candidates"], [])
        self.assertEqual(result["metrics"]["requests"], 64)
        self.assertEqual(result["metrics"]["lane_requests"], [32, 32])
        self.assertLessEqual(result["metrics"]["candidate_peak"], 32)
        self.assertEqual(len(net.calls), len(set((src, dst) for src, dst, _ in net.calls)))

    async def test_explicit_bootstrap_probe_cannot_evict_stable_source_capped_peers(self):
        net = SyntheticRouting(12)
        table = net.tables[0]
        groups = {}
        for i in range(1, 12):
            groups.setdefault(distance(table.coordinate, coordinate(net.identities[i].key_id)).bit_length(), []).append(i)
        selected = next(group for group in groups.values() if len(group) >= 3)
        for i in selected[:2]:
            table.learn_verified(net.nodes[i], "192.0.2.1")
        original = table.closest("0" * 64, limit=32)
        real_rpc = net.transport(0)
        async def shared_source(peer, request, deadline):
            reply = await real_rpc(peer, request, deadline)
            return RpcReply(reply.response, "192.0.2.2", reply.wire_bytes)
        result = await lookup(table, coordinate(net.identities[selected[2]].key_id),
            initial_lanes=[[net.nodes[selected[2]]]], rpc=shared_source, sign_request=net.signer(0))
        self.assertEqual(result["candidates"], [net.nodes[selected[2]]])
        self.assertEqual(table.closest("0"*64, limit=32), original)
        self.assertEqual(table.stats()["general_replacements"], 1)

    async def test_directory_hops_use_fixed_role_view_and_only_return_directories(self):
        net = SyntheticRouting(12, directory={8, 9, 10, 11})
        await net.join_and_maintain(cycles=20)
        result = await net.search(3, coordinate(net.identities[11].key_id), view="directory")
        self.assertEqual(result["state"], "closest_known")
        self.assertTrue(all("directory" in node["payload"]["roles"] for node in result["candidates"]))
        self.assertIn(net.identities[11].key_id, [n["payload"]["signing_key"]["key_id"] for n in result["candidates"]])
        self.assertLessEqual(net.tables[3].stats()["directory_introductions"], 4)
        self.assertEqual(net.tables[3].stats()["directory_active"], 0)
        self.assertLessEqual(result["metrics"]["requests"], 64)

    async def test_local_join_maintenance_and_bootstrap_exit_use_real_algorithm(self):
        net = SyntheticRouting(16)
        await net.join_and_maintain(cycles=20)
        net.offline.update((0, 1))
        for source, destination in ((2, 15), (3, 14), (4, 13), (5, 12)):
            result = await net.search(source, coordinate(net.identities[destination].key_id))
            self.assertIn(net.identities[destination].key_id,
                [n["payload"]["signing_key"]["key_id"] for n in result["candidates"]])
            self.assertLessEqual(result["metrics"]["candidate_peak"], 32)
            self.assertLessEqual(result["metrics"]["requests"], 64)
            self.assertLessEqual(result["metrics"]["concurrency_peak"], 3)
        self.assertTrue(any(entry["parent_key_id"] is not None for entry in result["metrics"]["paths"]))


if __name__ == "__main__":
    unittest.main()
