"""Bounded opt-in relay discovery over owned HTTP nodes and real invitations.

All identities, records, failures and services are disposable synthetic state.
No relay membership row is prefilled to make discovery look like admission.
"""
from contextlib import closing
import copy
import hashlib
import os
from pathlib import Path
import sqlite3
import time
import unittest
from unittest.mock import patch

from memory_vault import MemoryError, canonical_bytes, strict_json_loads
from memory_vault_agent import Agent
from memory_vault_network import HTTPTransport, NetworkClient
from memory_vault_network_control import issue_invite
from memory_vault_network_crypto import document_sha256
import memory_vault_network_recovery as recovery
from memory_vault_nodes import issue_directory
from memory_vault_storage import atomic_write
from memory_vault_trust import Identity
from tests import test_network_http as http_fixture
from tests import test_network_node_runtime as runtime
from tests.test_network_hints import control, policy, outbox_row
from tests.test_network_message_semantics import records, proofs, vault_snapshot
from tests.test_network_recovery import archive


class RecordedHTTP(HTTPTransport):
    def __init__(self):
        super().__init__()
        self.calls = []
        self.mutator = None

    def request(self, base, method, path, value=None, *, deadline=None):
        self.calls.append({"base": base, "method": method, "path": path})
        result = super().request(base, method, path, value, deadline=deadline)
        return self.mutator(base, method, path, result) if self.mutator else result


class PoolHost:
    """Reuse existing process lifecycle, adding a third initially empty relay."""
    def __init__(self, test, *, pool=True, maximum_nodes=3, replica_target=2, directory_count=3):
        self.test, self.pool, self.maximum_nodes = test, pool, maximum_nodes
        self.replica_target, self.directory_count = replica_target, directory_count
        self.base = runtime.NetworkNodeRuntimeTests("test_independent_refresh_and_persistent_drain_fence_over_real_http")

    def __getattr__(self, name):
        return getattr(self.base, name)

    def __enter__(self):
        try:
            self.base.setUp()
            # Existing fixture bootstrap is unused. Start fresh empty node
            # state and require actual dual-key joins for both members.
            for index, relay in enumerate(self.relays):
                relay.stop()
                config = {**self.relay_configs[index], "init_member_key_ids": [],
                          "state_directory": str(self.root / ("synthetic-pool-node-" + str(index)))}
                self.relay_configs[index] = config
                atomic_write(relay.config, canonical_bytes(config), replace=True)
                relay.start()
            self.add_relay()
            self.publish_nodes(self.node_entries[:self.directory_count])
            self.transports = [self.stack.enter_context(RecordedHTTP()) for _ in range(3)]
            for index, path in enumerate(self.net_configs[:2]):
                value = strict_json_loads(path.read_bytes())
                value["relays"] = [self.relays[index].url]
                if self.pool:
                    value["relay_pool"] = {"maximum_nodes": self.maximum_nodes, "replica_target": self.replica_target}
                atomic_write(path, canonical_bytes(value), replace=True)
            self.sender, self.receiver = [NetworkClient(path, transport=transport)
                for path, transport in zip(self.net_configs[:2], self.transports[:2])]
            self.invitations = [self.invitation_for(index) for index in range(2)]
            self.config_bytes = [path.read_bytes() for path in self.net_configs[:2]]
            return self
        except BaseException:
            self.base.doCleanups()
            raise

    def __exit__(self, *exc):
        try:
            self.base.tearDown()
        finally:
            self.base.doCleanups()

    def add_relay(self):
        index = len(self.relays)
        relay = self.base.service("synthetic-pool-relay-" + str(index), "relay")
        identity_path = self.root / ("synthetic-pool-node-key-" + str(index) + ".json")
        identity = Identity.generate(identity_path)
        entry = {"signing_key": identity.public_descriptor(), "base_url": relay.url,
                 "storage_epoch": "synthetic-pool-epoch-" + str(index),
                 "scope": ["export", "import", "node.status"], "status": "active"}
        config = {**self.relay_configs[0], "node_identity_path": str(identity_path), "base_url": relay.url,
                  "storage_epoch": entry["storage_epoch"], "state_directory": str(self.root / ("synthetic-pool-node-" + str(index))),
                  "init_member_key_ids": []}
        atomic_write(relay.config, canonical_bytes(config), replace=False)
        self.relays.append(relay)
        self.node_identities.append(identity)
        self.node_entries.append(entry)
        self.relay_configs.append(config)
        relay.start()
        return index

    def publish_nodes(self, entries):
        now = int(time.time())
        self.directory = issue_directory(self.issuer, network_id=self.network_id,
            version=self.directory["payload"]["version"] + 1, previous_sha256=document_sha256(self.directory),
            nodes=entries, issued_at=now, expires_at=now + 300)
        atomic_write(self.directory_path, canonical_bytes(self.directory), replace=True)
        return self.directory

    def invitation_for(self, index, *, expires_at=None, suffix="initial"):
        now = int(time.time())
        invite = issue_invite(self.issuer, network_id=self.network_id,
            invite_id="synthetic-pool-join-" + str(index) + "-" + suffix,
            candidate_signing_key=self.identities[index].public_descriptor(),
            candidate_encryption_key=self.encryption[index].public_descriptor(), scope=["receive", "send"],
            handoff_sha256=hashlib.sha256(b"").hexdigest(), roster_sha256=document_sha256(self.roster),
            issued_at=now - 1, expires_at=expires_at or now + 120)
        return {"invite": invite, "roster": self.roster}

    def endpoint(self, index):
        return (self.sender, self.receiver)[index]

    def join(self, index, *, invitation=None, request_id=None):
        return self.endpoint(index).connect(invitation or self.invitations[index],
            request_id=request_id or "req_synthetic_pool_join_" + str(index))

    def value(self, index, request):
        value = Agent(self.configs[index], self.net_configs[index], transport=self.transports[index]).handle(request)
        self.test.assertTrue(value["ok"], value)
        return value["result"]

    def node_rows(self, index, table):
        self.test.assertIn(table, {"members", "messages", "receipts"})
        database = Path(self.relay_configs[index]["state_directory"]) / "relay.sqlite3"
        with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)) as db:
            db.row_factory = sqlite3.Row
            return [dict(row) for row in db.execute("SELECT * FROM " + table)]

    def fault(self, index, *, reject_messages=False, delay_status=False):
        relay = self.relays[index]
        relay.stop()
        fault = f"""
import asyncio
from starlette.responses import JSONResponse
original_app = app
async def app(scope, receive, send):
    if {reject_messages!r} and scope['type'] == 'http' and scope['method'] == 'POST' and scope['path'] == '/v1/messages':
        response = JSONResponse({{'error': {{'code': 'synthetic_pool_unavailable', 'retryable': True}}}}, status_code=503)
        return await response(scope, receive, send)
    if {delay_status!r} and scope['type'] == 'http' and scope['method'] == 'GET' and scope['path'] == '/v1/status':
        await asyncio.sleep(2)
    return await original_app(scope, receive, send)
"""
        with patch.object(http_fixture, "_SERVE", http_fixture._SERVE.replace("listener = socket.socket", fault + "\nlistener = socket.socket")):
            relay.start()

    def unchanged_config(self):
        self.test.assertEqual([path.read_bytes() for path in self.net_configs[:2]], self.config_bytes)


def stored_message(test, response, identifier):
    found = [item for item in response["messages"] if item["message_id"] == identifier]
    test.assertEqual(len(found), 1, response)
    test.assertEqual(found[0]["state"], "validated_saved", response)
    return found[0]


def remembered(host, text, suffix, *, relations=None):
    value = host.value(0, {"op": "remember", "request_id": "req_synthetic_pool_record_" + suffix,
        "kind": "observation", "text": text, "relations": relations or [],
        "experience": {"epistemic_type": "observation", "source_agent": "synthetic-pool-owner",
                       "observed_under": {"environment": "V1"}}})
    return value["memory_id"]


@unittest.skipUnless(os.name == "posix", "owned loopback socket inheritance requires POSIX")
class RelayPoolTests(unittest.TestCase):
    def join_both(self, host, count=3):
        for index in range(len(host.relays)):
            self.assertEqual(host.node_rows(index, "members"), [])
        for index in range(2):
            result = host.join(index)
            self.assertEqual(result["joined_nodes"], count, result)
            self.assertFalse(result["errors"], result)
        expected = {identity.key_id for identity in host.identities[:2]}
        for index in range(count):
            self.assertEqual({row["key_id"] for row in host.node_rows(index, "members")}, expected)

    def test_different_seeds_discover_join_common_pool_and_exchange_after_seed_exit(self):
        with PoolHost(self) as host:
            self.join_both(host)
            discoveries = [host.value(index, {"op": "discover", "online": True}) for index in range(2)]
            expected = [{"key_id": entry["signing_key"]["key_id"]} for entry in
                        sorted(host.node_entries, key=lambda item: item["signing_key"]["key_id"])]
            for result in discoveries:
                self.assertEqual(result["nodes"], expected)
                self.assertEqual((result["configured_nodes"], result["candidate_nodes"], result["replica_target"]), (1, 3, 2))
                self.assertTrue(result["relay_pool_enabled"])
                self.assertFalse(result["pool_partial"])
                self.assertEqual(result["directory_version"], host.directory["payload"]["version"])
            host.relays[0].stop()
            before = [vault_snapshot(endpoint) for endpoint in (host.sender, host.receiver)]
            chat = host.value(0, {"op": "send", "request_id": "req_synthetic_pool_chat",
                "recipients": [host.identities[1].key_id], "text": "Synthetic chat over another authorized entry."})
            self.assertEqual((chat["stored_nodes"], chat["replica_target"]), (2, 2), chat)
            self.assertFalse(chat["degraded"], chat)
            self.assertEqual(sum(len(host.node_rows(index, "messages")) for index in (1, 2)), 2)
            stored_message(self, host.value(1, {"op": "receive"}), chat["message_id"])
            self.assertEqual([vault_snapshot(endpoint) for endpoint in (host.sender, host.receiver)], before)
            dependency = remembered(host, "Synthetic pool dependency", "dependency")
            root = remembered(host, "Synthetic explicit original experience", "root", relations=[{"type": "derived_from", "target": dependency}])
            original, signatures = records(host.sender), proofs(host.sender)
            request = {"op": "send", "request_id": "req_synthetic_pool_memory", "recipients": [host.identities[1].key_id],
                       "text": "Synthetic note, not another observation.", "memory_ids": [root]}
            sent = host.value(0, request)
            self.assertEqual(sent["stored_nodes"], 2, sent)
            received = stored_message(self, host.value(1, {"op": "receive"}), sent["message_id"])
            self.assertEqual(received["share"]["admission"], "verified")
            self.assertEqual(records(host.receiver), original)
            self.assertEqual(proofs(host.receiver), signatures)
            host.value(0, {"op": "receive"})
            self.assertTrue(host.value(0, request)["endpoint_validated"])
            self.assertEqual(host.value(1, {"op": "receive"})["messages"], [])
            host.unchanged_config()

    def test_hint_selection_and_original_dependency_batch_continue_when_seed_stops(self):
        with PoolHost(self) as host:
            self.join_both(host)
            dependency = remembered(host, "Synthetic pool batch setup", "hint_dependency")
            roots = [remembered(host, "Synthetic pool hint outcome " + str(index), "hint_" + str(index),
                relations=[{"type": "derived_from", "target": dependency}]) for index in range(2)]
            host.sender.set_hint_policy(policy(host.sender, host.receiver, roots, [*roots, dependency]))
            before = [vault_snapshot(endpoint) for endpoint in (host.sender, host.receiver)]
            queried = host.value(1, {"op": "send", "request_id": "req_synthetic_pool_hint_query",
                "recipients": [host.identities[0].key_id], "control": control("query", query="Synthetic pool hint")})
            stored_message(self, host.value(0, {"op": "receive"}), queried["message_id"])
            offer = host.value(0, {"op": "receive", "respond_to": queried["message_id"]})
            stored_message(self, host.value(1, {"op": "receive"}), offer["message_id"])
            hints = host.value(1, {"op": "receive", "message_id": offer["message_id"]})["control"]
            self.assertEqual({item["memory_id"] for item in hints["hints"]}, set(roots))
            self.assertEqual([vault_snapshot(endpoint) for endpoint in (host.sender, host.receiver)], before)
            selected = host.value(1, {"op": "send", "request_id": "req_synthetic_pool_hint_select",
                "recipients": [host.identities[0].key_id], "control": control("select", query_message_id=queried["message_id"],
                    selections=[{"offer_message_id": offer["message_id"], "memory_id": mid} for mid in roots[::-1]])})
            stored_message(self, host.value(0, {"op": "receive"}), selected["message_id"])
            host.relays[0].stop()
            transferred = host.value(0, {"op": "receive", "respond_to": selected["message_id"]})
            self.assertEqual((transferred["stored_nodes"], transferred["replica_target"]), (2, 2), transferred)
            result = stored_message(self, host.value(1, {"op": "receive"}), transferred["message_id"])
            self.assertEqual(result["share"]["records_added"], 3)
            self.assertEqual(result["share"]["admission"], "verified")
            self.assertEqual(records(host.receiver), records(host.sender))
            self.assertEqual(proofs(host.receiver), proofs(host.sender))
            snapshot = vault_snapshot(host.receiver)
            calls = len(host.transports[1].calls)
            view = host.value(1, {"op": "recall", "received_batch_message_id": transferred["message_id"]})
            self.assertEqual(view["selected_memory_ids"], roots[::-1])
            self.assertEqual(len(host.transports[1].calls), calls)
            self.assertEqual(vault_snapshot(host.receiver), snapshot)
            host.value(0, {"op": "receive"})
            with host.sender.db() as database:
                self.assertEqual(database.execute("SELECT COUNT(*) FROM acknowledgements WHERE message_id=?",
                    (transferred["message_id"],)).fetchone()[0], 1)
            self.assertEqual(host.value(1, {"op": "receive"})["messages"], [])
            host.unchanged_config()

    def test_frozen_queue_restarts_and_falls_back_with_finite_slow_node_budget(self):
        with PoolHost(self) as host:
            self.join_both(host)
            for index in range(3):
                host.fault(index, reject_messages=True)
            sent = host.value(0, {"op": "send", "request_id": "req_synthetic_pool_frozen",
                "recipients": [host.identities[1].key_id], "text": "Synthetic frozen body survives entry failure."})
            self.assertEqual(sent["stored_nodes"], 0, sent)
            prior = outbox_row(host.sender, sent["message_id"])
            self.assertIsNotNone(prior["envelope"])
            ordered = sorted(range(3), key=lambda index: host.node_entries[index]["signing_key"]["key_id"])
            slow = ordered[0]
            for index in range(3):
                host.relays[index].stop()
                host.relays[index].start()
            host.fault(slow, delay_status=True)
            with RecordedHTTP() as transport, NetworkClient(host.net_configs[0], transport=transport) as restarted:
                passes = []
                for _ in range(3):
                    outcome = restarted.pump(maximum_messages=1, maximum_seconds=1, receive_limit=0)
                    passes.append(outcome)
                    if outcome["remaining_outbox"] == 0:
                        break
                self.assertEqual(passes[-1]["remaining_outbox"], 0, passes)
                # Three candidates and a finite number of passes, not a retry
                # loop that grows until a desired outcome happens.
                relay_gets = [call for call in transport.calls if call["base"] != host.authority.url and call["path"] == "/v1/status" and call["method"] == "GET"]
                self.assertLessEqual(len(relay_gets), 9)
            after = outbox_row(host.sender, sent["message_id"])
            self.assertEqual(bytes(after["body"]), bytes(prior["body"]))
            self.assertEqual(bytes(after["envelope"]), bytes(prior["envelope"]))
            healthy = [index for index in range(3) if index != slow]
            self.assertEqual([len(host.node_rows(index, "messages")) for index in healthy], [1, 1])
            delivered = stored_message(self, host.value(1, {"op": "receive"}), sent["message_id"])
            self.assertEqual(delivered["text"], "Synthetic frozen body survives entry failure.")
            self.assertEqual(records(host.receiver), {})
            self.assertEqual(host.value(1, {"op": "receive"})["messages"], [])
            host.unchanged_config()

    def test_candidate_budget_exact_config_and_fixed_mode_do_not_expand_contacts(self):
        with PoolHost(self, maximum_nodes=2) as host:
            selected = sorted(host.node_entries, key=lambda item: item["signing_key"]["key_id"])[:2]
            allowed = {entry["base_url"] for entry in selected}
            for index in range(2):
                discovered = host.value(index, {"op": "discover", "online": True})
                self.assertEqual(discovered["nodes"], [{"key_id": entry["signing_key"]["key_id"]} for entry in selected])
                self.assertTrue(discovered["pool_partial"])
                self.assertEqual(host.join(index)["joined_nodes"], 2)
                contacted = {call["base"] for call in host.transports[index].calls if call["base"] != host.authority.url}
                self.assertEqual(contacted, allowed)
            excluded = next(index for index, relay in enumerate(host.relays) if relay.url not in allowed)
            self.assertEqual(host.node_rows(excluded, "members"), [])
            original = strict_json_loads(host.net_configs[0].read_bytes())
            invalid = [None, {}, {"maximum_nodes": True, "replica_target": 1}, {"maximum_nodes": 1, "replica_target": 1},
                       {"maximum_nodes": 5, "replica_target": 2}, {"maximum_nodes": 3, "replica_target": 3},
                       {"maximum_nodes": 3.0, "replica_target": 2}, {"maximum_nodes": 3, "replica_target": False},
                       {"maximum_nodes": 3, "replica_target": 2, "authority": "memory text cannot grant authority"}]
            for index, option in enumerate(invalid):
                path = host.net_configs[0].with_name("synthetic-invalid-pool-" + str(index) + ".json")
                atomic_write(path, canonical_bytes({**original, "relay_pool": option}), replace=False)
                with self.subTest(option=option), self.assertRaises(MemoryError) as denied:
                    NetworkClient(path, transport=host.transports[0])
                self.assertEqual(denied.exception.code, "network_invalid_relay_pool")
            host.unchanged_config()
        with PoolHost(self, pool=False) as host:
            self.assertEqual(host.join(0)["joined_nodes"], 1)
            discovered = host.value(0, {"op": "discover", "online": True})
            self.assertNotIn("relay_pool_enabled", discovered)
            self.assertEqual({call["base"] for call in host.transports[0].calls if call["base"] != host.authority.url}, {host.relays[0].url})
            self.assertEqual(host.node_rows(1, "members"), [])
            self.assertEqual(host.node_rows(2, "members"), [])
            host.unchanged_config()

    def test_discovery_and_expired_invite_cannot_admit_new_node_but_fresh_invite_can(self):
        with PoolHost(self, maximum_nodes=4, directory_count=2) as host:
            expires = int(time.time()) + 5
            invitation = host.invitation_for(1, expires_at=expires, suffix="short")
            result = host.join(1, invitation=invitation, request_id="req_synthetic_pool_short_join")
            self.assertEqual(result["joined_nodes"], 2, result)
            before = [host.node_rows(index, "members") for index in (0, 1)]
            self.assertEqual(host.node_rows(2, "members"), [])
            time.sleep(max(0, expires - time.time() + 0.05))
            host.publish_nodes(host.node_entries)
            discovered = host.value(1, {"op": "discover", "online": True})
            self.assertEqual(discovered["candidate_nodes"], 3)
            self.assertEqual(host.node_rows(2, "members"), [])
            repeated = host.join(1, invitation=invitation, request_id="req_synthetic_pool_short_join")
            self.assertEqual(repeated["joined_nodes"], 2, repeated)
            self.assertTrue(repeated["errors"], repeated)
            self.assertEqual(host.node_rows(2, "members"), [])
            self.assertEqual([host.node_rows(index, "members") for index in (0, 1)], before)
            checked = host.receiver.connect()
            self.assertEqual(checked["joined_nodes"], 2, checked)
            self.assertEqual(host.node_rows(2, "members"), [])
            before_calls = len(host.transports[1].calls)
            fresh = host.join(1, invitation=host.invitation_for(1, suffix="renewed"), request_id="req_synthetic_pool_fresh_join")
            self.assertEqual(fresh["joined_nodes"], 3, fresh)
            self.assertEqual(fresh["errors"], [])
            for index in (0, 1):
                checked_paths = {(call["method"], call["path"]) for call in host.transports[1].calls[before_calls:]
                                 if call["base"] == host.relays[index].url}
                self.assertIn(("GET", "/v1/status"), checked_paths)
                self.assertIn(("POST", "/v1/poll"), checked_paths)
            self.assertEqual(host.receiver.connect()["joined_nodes"], 3)
            self.assertEqual({row["key_id"] for row in host.node_rows(2, "members")}, {host.identities[1].key_id})
            host.unchanged_config()

    def test_forged_rollback_revoked_and_wrong_challenge_nodes_never_bypass_pool_authorization(self):
        with PoolHost(self) as host:
            self.join_both(host)
            host.value(0, {"op": "discover", "online": True})
            old = copy.deepcopy(host.directory)
            changed = host.publish_nodes([{**entry, "status": "revoked"} if index == 0 else entry
                                          for index, entry in enumerate(host.node_entries)])
            newer = host.value(0, {"op": "discover", "online": True})
            self.assertEqual(newer["candidate_nodes"], 2)
            self.assertNotIn({"key_id": host.node_identities[0].key_id}, newer["nodes"])
            for fault in ("tamper", "rollback"):
                with self.subTest(fault=fault):
                    broken = copy.deepcopy(changed if fault == "tamper" else old)
                    if fault == "tamper":
                        next(entry for entry in broken["payload"]["nodes"] if entry["status"] == "active")["storage_epoch"] = "synthetic-forged-pool-epoch"
                        self.assertNotEqual(canonical_bytes(broken), canonical_bytes(changed))
                    delivered = []
                    def altered_directory(base, method, path, result):
                        if base == host.authority.url and method == "POST" and path == "/v1/status":
                            result = copy.deepcopy(result)
                            self.assertEqual(result["nodes"], changed)
                            result["nodes"] = copy.deepcopy(broken)
                            delivered.append(canonical_bytes(result["nodes"]))
                        return result
                    before = len(host.transports[0].calls)
                    host.transports[0].mutator = altered_directory
                    try:
                        denied = Agent(host.configs[0], host.net_configs[0], transport=host.transports[0]).handle({"op": "discover", "online": True})
                    finally:
                        host.transports[0].mutator = None
                    self.assertEqual(delivered, [canonical_bytes(broken)])
                    self.assertFalse(denied["ok"], denied)
                    self.assertFalse(any(call["base"] != host.authority.url for call in host.transports[0].calls[before:]))
            # A signed authorized URL is not enough: the server must prove
            # that incarnation's key before any message is submitted to it.
            wrong = 1
            def wrong_challenge(base, method, path, result):
                if base == host.relays[wrong].url and method == "GET" and path == "/v1/status":
                    result = copy.deepcopy(result)
                    signature = result["node_challenge"]["proof"]["signature"]
                    result["node_challenge"]["proof"]["signature"] = ("A" if signature[0] != "A" else "B") + signature[1:]
                return result
            host.transports[0].calls.clear()
            host.transports[0].mutator = wrong_challenge
            try:
                sent = host.value(0, {"op": "send", "request_id": "req_synthetic_pool_wrong_node",
                    "recipients": [host.identities[1].key_id], "text": "Synthetic challenge-bound ciphertext."})
            finally:
                host.transports[0].mutator = None
            self.assertEqual(sent["stored_nodes"], 1, sent)
            self.assertTrue(sent["degraded"])
            self.assertFalse(any(call["base"] in {host.relays[0].url, host.relays[wrong].url} and
                                 call["path"] == "/v1/messages" for call in host.transports[0].calls))
            self.assertEqual(host.node_rows(0, "messages"), [])
            self.assertEqual(host.node_rows(wrong, "messages"), [])
            frozen = outbox_row(host.sender, sent["message_id"])
            host.authority.stop()
            before = len(host.transports[0].calls)
            failed = host.sender.pump(maximum_messages=1, maximum_seconds=2, receive_limit=0)
            self.assertTrue(failed["errors"], failed)
            self.assertFalse(any(call["base"] != host.authority.url for call in host.transports[0].calls[before:]))
            self.assertEqual(bytes(outbox_row(host.sender, sent["message_id"])["envelope"]), bytes(frozen["envelope"]))
            calls = len(host.transports[0].calls)
            local = remembered(host, "Synthetic local memory remains usable without authority", "offline")
            self.assertTrue(host.value(0, {"op": "recall", "memory_id": local})["hits"])
            self.assertEqual(len(host.transports[0].calls), calls)
            host.unchanged_config()


    def test_four_real_historical_receipts_restore_only_with_explicit_pool_and_current_control(self):
        with PoolHost(self, maximum_nodes=4, replica_target=1) as host:
            host.add_relay()
            host.publish_nodes(host.node_entries)
            self.join_both(host, count=4)
            request = {"op": "send", "request_id": "req_synthetic_pool_four_receipts",
                "recipients": [host.identities[1].key_id], "text": "Synthetic preserved four-node receipt history."}
            sent = host.value(0, request)
            self.assertEqual(sent["stored_nodes"], 1, sent)
            for _ in range(3):
                self.assertEqual(host.sender.pump(maximum_messages=1, maximum_seconds=3, receive_limit=0)["remaining_outbox"], 0)
            with host.sender.db() as database:
                cursor_before = strict_json_loads(database.execute("SELECT value FROM state WHERE key='pump_node_cursor'").fetchone()[0])
            self.assertEqual(cursor_before, 3)
            ordered = sorted(range(4), key=lambda index: host.node_entries[index]["signing_key"]["key_id"])
            original = outbox_row(host.sender, sent["message_id"])
            accumulated = strict_json_loads(original["receipts"])
            for count in range(1, 4):
                revoked = set(ordered[:count])
                host.publish_nodes([{**entry, "status": "revoked"} if index in revoked else entry
                                    for index, entry in enumerate(host.node_entries)])
                updated = host.value(0, request)
                self.assertEqual((updated["stored_nodes"], updated["candidate_nodes"], updated["replica_target"]), (1, 4 - count, 1), updated)
                row = outbox_row(host.sender, sent["message_id"])
                current = strict_json_loads(row["receipts"])
                self.assertEqual(len(current), count + 1)
                self.assertTrue(all(current[url] == receipt for url, receipt in accumulated.items()))
                accumulated = current
                self.assertEqual(bytes(row["body"]), bytes(original["body"]))
                self.assertEqual(bytes(row["envelope"]), bytes(original["envelope"]))
            self.assertEqual([len(host.node_rows(index, "messages")) for index in range(4)], [1, 1, 1, 1])
            final = outbox_row(host.sender, sent["message_id"])
            calls = len(host.transports[0].calls)
            source_vault = vault_snapshot(host.sender)
            _, arguments = archive(host.sender)
            self.assertEqual(len(host.transports[0].calls), calls)
            self.assertEqual(vault_snapshot(host.sender), source_vault)
            self.assertEqual(outbox_row(host.sender, sent["message_id"]), final)
            active = host.relays[ordered[-1]].url
            # Restored routing is an explicit operator choice. Archive data
            # alone does not reactivate dynamic connectivity.
            arguments["relays"] = [active]
            restored = {}
            for mode, options in (("fixed", {}), ("pool", {"relay_pool": {"maximum_nodes": 4, "replica_target": 1}})):
                result = recovery.restore_endpoint(directory=host.root / ("synthetic-four-history-" + mode), **arguments, **options)
                self.assertFalse(result["automatic_sending_enabled"])
                self.assertTrue(result["requires_fresh_issuer_status"])
                config_path = Path(result["network_config"])
                config = strict_json_loads(config_path.read_bytes())
                self.assertEqual("relay_pool" in config, mode == "pool")
                with NetworkClient(config_path, transport=host.transports[0]) as endpoint:
                    row = outbox_row(endpoint, sent["message_id"])
                    self.assertEqual(row["receipts"], final["receipts"])
                    self.assertEqual(bytes(row["body"]), bytes(final["body"]))
                    self.assertEqual(bytes(row["envelope"]), bytes(final["envelope"]))
                    with endpoint.db() as database:
                        self.assertEqual(strict_json_loads(database.execute("SELECT value FROM state WHERE key='pump_node_cursor'").fetchone()[0]), 3)
                    if mode == "fixed":
                        before_calls = len(host.transports[0].calls)
                        retried = endpoint.send(request["request_id"], request["recipients"], request["text"])
                        self.assertEqual(retried["stored_nodes"], 1, retried)
                        self.assertEqual(outbox_row(endpoint, sent["message_id"])["receipts"], final["receipts"])
                        self.assertTrue(all(call["base"] in {active, host.authority.url} for call in host.transports[0].calls[before_calls:]))
                restored[mode] = config_path
            host.publish_nodes([{**entry, "status": "revoked"} for entry in host.node_entries])
            with NetworkClient(restored["pool"], transport=host.transports[0]) as endpoint:
                before_calls = len(host.transports[0].calls)
                outcome = endpoint.pump(maximum_messages=1, maximum_seconds=3, receive_limit=0)
                self.assertTrue(outcome["errors"], outcome)
                self.assertFalse(any(call["base"] != host.authority.url for call in host.transports[0].calls[before_calls:]))
                self.assertEqual(outbox_row(endpoint, sent["message_id"])["receipts"], final["receipts"])
                self.assertEqual(records(endpoint), {})
            host.unchanged_config()

    def test_real_receipt_budget_failure_rolls_back_map_without_claiming_saved(self):
        import memory_vault_network as network
        import memory_vault_nodes as nodes
        with PoolHost(self, replica_target=1) as host:
            self.join_both(host)
            request = {"op": "send", "request_id": "req_synthetic_pool_receipt_budget",
                "recipients": [host.identities[1].key_id], "text": "Synthetic receipt budget rollback."}
            sent = host.value(0, request)
            self.assertEqual(sent["stored_nodes"], 1)
            prior = outbox_row(host.sender, sent["message_id"])
            old_map = strict_json_loads(prior["receipts"])
            old_url, = old_map
            host.publish_nodes([{**entry, "status": "revoked"} if entry["base_url"] == old_url else entry
                                for entry in host.node_entries])
            length = len(prior["receipts"].encode())
            for name, module, constant in (("row", network, "MAX_OUTBOX_RECEIPT_ROW_BYTES"),
                                           ("global", nodes, "MAX_OUTBOX_RECEIPTS_BYTES")):
                with self.subTest(budget=name), patch.object(module, constant, length + 1):
                    result = host.value(0, request)
                    self.assertEqual(result["stored_nodes"], 0, result)
                    self.assertNotEqual(result["state"], "stored")
                    self.assertIn("network_storage_receipt_capacity", {error["code"] for error in result["errors"]})
                after = outbox_row(host.sender, sent["message_id"])
                self.assertEqual(after["receipts"], prior["receipts"])
                self.assertEqual(bytes(after["body"]), bytes(prior["body"]))
                self.assertEqual(bytes(after["envelope"]), bytes(prior["envelope"]))
            retried = host.value(0, request)
            self.assertEqual(retried["stored_nodes"], 1, retried)
            self.assertEqual(len(strict_json_loads(outbox_row(host.sender, sent["message_id"])["receipts"])), 2)
            self.assertEqual(records(host.sender), {})
            self.assertEqual(records(host.receiver), {})
            host.unchanged_config()


if __name__ == "__main__":
    unittest.main()
