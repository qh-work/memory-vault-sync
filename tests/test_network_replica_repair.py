"""Bounded replica repair over owned loopback nodes and one shared endpoint DB.

Python and the independent TS peer both use real signed control responses and
real relay HTTP. Faults are bounded response delays or explicit HTTP 503s in
owned test servers. All keys, memories and nodes are synthetic fixtures.
"""
from __future__ import annotations

from contextlib import closing
import copy
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from memory_vault import canonical_bytes, strict_json_loads
from memory_vault_client import ClientConfig
from memory_vault_network import HTTPTransport, NetworkClient
from memory_vault_network_control import issue_roster
from memory_vault_network_crypto import document_sha256
from memory_vault_network_recovery import backup_endpoint, restore_endpoint
from memory_vault_nodes import issue_directory
from memory_vault_storage import atomic_write
from memory_vault_trust import Identity
from tests import test_network_http as http_fixture
from tests import test_network_node_runtime as runtime
from tests import test_network_typescript_peer as peers


DRIVER = r"""
import { NetworkPeer } from './peer.ts';
import { HTTPTransport } from './transport.ts';
import { existsSync, writeFileSync } from 'node:fs';
const chunks=[];let size=0;
for await(const chunk of process.stdin){size+=chunk.length;if(size>1048576)throw Error('fixture_limit');chunks.push(chunk);}
const input=JSON.parse(Buffer.concat(chunks).toString('utf8'));
const transport=new HTTPTransport(),original=transport.request.bind(transport);
const calls=[],started=performance.now();let delayed=false,paused=false,peer;
transport.request=async(base,method,path,value,deadline)=>{
  calls.push({base,method,path,elapsed_ms:performance.now()-started});
  const result=await original(base,method,path,value,deadline);
  if(input.gate&&!paused&&input.pause_after_store_base===base&&path==='/v1/messages'){
    paused=true;writeFileSync(input.gate+'/ready','ready',{mode:0o600});
    const end=performance.now()+15000;
    while(!existsSync(input.gate+'/continue')){
      if(performance.now()>=end)throw Error('synthetic_gate_timeout');
      await new Promise(resolve=>setTimeout(resolve,10));
    }
  }
  if(!delayed&&(input.delay_first||(input.delay_base===base&&method==='GET'&&path==='/v1/status'))){
    delayed=true;await new Promise(resolve=>setTimeout(resolve,1100));
  }
  return result;
};
try{
  peer=new NetworkPeer(input.config,{transport});
  const op=input.operation;let result;
  if(op.op==='pump')result=await peer.pump(op.maximum_messages,op.maximum_seconds,op.receive_limit);
  else if(op.op==='receive')result=await peer.receive(op.limit);
  else if(op.op==='connect')result=await peer.connect(op.invitation,op.request_id);
  else if(op.op==='send')result=await peer.send(op.request_id,op.recipients,op.text,op.memory_ids);
  else throw Error('unsupported_fixture_operation');
  process.stdout.write(JSON.stringify({result,calls}));
}finally{peer?.close();transport.close();}
"""


class _RecordedHTTP(HTTPTransport):
    def __init__(self, *, delay_first=False, delay_base=None, after_store=None, after_store_base=None):
        super().__init__()
        self.calls = []
        self.started = time.monotonic()
        self.delay_first = delay_first
        self.delay_base = delay_base
        self.delayed = False
        self.after_store = after_store
        self.after_store_base = after_store_base

    def request(self, base, method, path, value=None, *, deadline=None):
        self.calls.append({"base": base, "method": method, "path": path,
                           "elapsed_ms": (time.monotonic() - self.started) * 1000})
        result = super().request(base, method, path, value, deadline=deadline)
        if self.after_store is not None and base == self.after_store_base and path == "/v1/messages":
            callback, self.after_store = self.after_store, None
            callback()
        if not self.delayed and (self.delay_first or (
                base == self.delay_base and method == "GET" and path == "/v1/status")):
            self.delayed = True
            time.sleep(1.1)
        return result


class _ReplicaRepairCases:
    @classmethod
    def setUpClass(cls):
        # Reuse its locked, private Node/jose copy fixture, not its test suite.
        peers.TypeScriptPeerTests.setUpClass.__func__(cls)
        (cls.fixture / "repair-driver.mjs").write_text(DRIVER)

    def setUp(self):
        self.host = runtime.NetworkNodeRuntimeTests(
            "test_independent_refresh_and_persistent_drain_fence_over_real_http")
        self.addCleanup(self.host.doCleanups)
        self.host.setUp()
        self.addCleanup(self.host.tearDown)
        self.other_language = "typescript" if self.language == "python" else "python"

    def invoke(self, operation=None, *, index=0, language=None, delay_first=False,
               delay_base=None, network_config=None, after_store=None, after_store_base=None):
        operation = {"op": "pump", "receive_limit": 0} if operation is None else operation
        selected = language or self.language
        config = Path(network_config) if network_config else self.host.net_configs[index]
        if selected == "typescript":
            command = [self.node, "--experimental-strip-types", str(self.fixture / "repair-driver.mjs")]
            payload = {"config": str(config), "operation": operation,
                       "delay_first": delay_first, "delay_base": delay_base}
            if after_store is None:
                process = subprocess.run(command, input=json.dumps(payload).encode(), cwd=self.fixture,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=35)
                code, stdout, stderr = process.returncode, process.stdout, process.stderr
            else:
                with tempfile.TemporaryDirectory(prefix="synthetic-http-race-gate-", dir=self.host.root) as gate:
                    payload.update(gate=gate, pause_after_store_base=after_store_base)
                    process = subprocess.Popen(command, cwd=self.fixture,
                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    try:
                        process.stdin.write(json.dumps(payload).encode())
                        process.stdin.close()
                        process.stdin = None
                        end = time.monotonic() + 15
                        ready = Path(gate) / "ready"
                        while not ready.exists() and process.poll() is None and time.monotonic() < end:
                            time.sleep(0.01)
                        self.assertTrue(ready.exists(), "synthetic peer did not reach the post-store HTTP gate")
                        after_store()
                        (Path(gate) / "continue").write_text("continue")
                        stdout, stderr = process.communicate(timeout=35)
                        code = process.returncode
                    finally:
                        if process.poll() is None:
                            process.kill()
                        process.communicate(timeout=5)
            self.assertEqual(code, 0, stderr.decode(errors="replace")[-4000:])
            value = json.loads(stdout)
            return value["result"], value["calls"]
        with _RecordedHTTP(delay_first=delay_first, delay_base=delay_base,
                           after_store=after_store, after_store_base=after_store_base) as transport:
            with NetworkClient(config, transport=transport) as client:
                args = {key: value for key, value in operation.items() if key != "op"}
                result = getattr(client, operation["op"])(**args)
            return result, transport.calls

    def records(self, index):
        with closing(ClientConfig.load(self.host.configs[index]).vault()._connect()) as db:
            return {row["memory_id"]: row["record_json"] for row in db.execute("SELECT * FROM memories")}

    def state(self, key):
        with self.host.sender.db() as db:
            row = db.execute("SELECT value FROM state WHERE key=?", (key,)).fetchone()
            return strict_json_loads(row["value"]) if row else None

    def seed(self, count=1):
        self.host.join_receiver()
        for index in range(count):
            result, _ = self.invoke({"op": "send", "request_id": "req_synthetic_repair_" + str(index),
                "recipients": [self.host.identities[1].key_id],
                "text": "Synthetic replica evidence " + str(index)}, language=self.other_language)
            self.assertEqual(result["stored_nodes"], 2, result)
        received = self.host.receiver.receive()
        self.assertFalse(received["errors"], received)
        self.assertEqual(len(received["messages"]), count)
        return self.host.outbox()

    def replace(self, *, authorized=True, admitted_receiver=True, new_url=False):
        host = self.host
        old = host.relays[0]
        old.stop()
        target = host.service("different-address", "relay") if new_url else old
        identity_path = host.root / "repair-new-node-key.json"
        identity = Identity.generate(identity_path)
        entry = {**host.node_entries[0], "signing_key": identity.public_descriptor(),
                 "base_url": target.url, "storage_epoch": "synthetic-repair-new-epoch"}
        if authorized:
            at = int(time.time())
            directory = issue_directory(host.issuer, network_id=host.network_id, version=2,
                previous_sha256=document_sha256(host.directory),
                nodes=[{**host.node_entries[0], "status": "revoked"}, host.node_entries[1], entry],
                issued_at=at, expires_at=at + 300)
            atomic_write(host.directory_path, canonical_bytes(directory), replace=True)
        initial = host.identities[:2] if admitted_receiver else host.identities[:1]
        config = {**host.relay_configs[0], "node_identity_path": str(identity_path),
            "base_url": target.url, "storage_epoch": entry["storage_epoch"],
            "state_directory": str(host.root / "repair-new-node-state"),
            # Explicit operator bootstrap is permitted by this synthetic
            # fixture. The separate test keeps recipient admission absent.
            "init_member_key_ids": [identity.key_id for identity in initial]}
        atomic_write(target.config, canonical_bytes(config), replace=not new_url)
        target.start()
        return target, config, entry

    def node_rows(self, config, table):
        self.assertIn(table, ("members", "messages"))
        with sqlite3.connect(Path(config["state_directory"]) / "relay.sqlite3") as db:
            db.row_factory = sqlite3.Row
            return [dict(row) for row in db.execute("SELECT * FROM " + table)]

    def restart_with_http_fault(self, relay, *, delay_status=False, reject_messages=False):
        """Change only our child's HTTP behavior; keep its real identity/DB."""
        relay.stop()
        fault = f"""
import asyncio
from starlette.responses import JSONResponse
original_app = app
async def app(scope, receive, send):
    if {reject_messages!r} and scope['type'] == 'http' and scope['method'] == 'POST' and scope['path'] == '/v1/messages':
        response = JSONResponse({{'error': {{'code': 'synthetic_temporarily_unavailable', 'retryable': True}}}}, status_code=503)
        return await response(scope, receive, send)
    if {delay_status!r} and scope['type'] == 'http' and scope['method'] == 'GET' and scope['path'] == '/v1/status':
        await asyncio.sleep(2)
    return await original_app(scope, receive, send)
"""
        anchor = "listener = socket.socket"
        self.assertEqual(http_fixture._SERVE.count(anchor), 1)
        script = http_fixture._SERVE.replace(anchor, fault + "\n" + anchor)
        with patch.object(http_fixture, "_SERVE", script):
            relay.start()

    def assert_current_checks(self, result):
        self.assertEqual(sorted(result["replica_checks"], key=lambda item: item["node"]),
            [{"node": index, "state": "current", "node_identity_verified": True} for index in range(2)])

    def assert_frozen(self, before):
        after = self.host.outbox()
        self.assertEqual(set(after), set(before))
        for key, prior in before.items():
            self.assertEqual({k: v for k, v in after[key].items() if k != "receipts"},
                             {k: v for k, v in prior.items() if k != "receipts"})
        return after

    def test_authorized_same_url_repair_is_bounded_and_cross_language_deduplicated(self):
        before = self.seed(2)
        memory_before = self.records(1)
        target, config, entry = self.replace()
        partial, _ = self.invoke({"op": "pump", "maximum_messages": 1, "receive_limit": 0})
        self.assert_current_checks(partial)
        self.assertEqual(partial["outbound_attempted"], 1, partial)
        self.assertEqual(partial["remaining_outbox"], 1, partial)
        self.assertEqual(len(self.node_rows(config, "messages")), 1)
        self.assert_frozen(before)
        # A fresh process in the other runtime opens the exact same queue and
        # repairs the second message into an already nonempty replacement.
        complete, _ = self.invoke(language=self.other_language)
        self.assertEqual(complete["state"], "completed", complete)
        self.assertEqual(complete["remaining_outbox"], 0)
        after = self.assert_frozen(before)
        messages = self.node_rows(config, "messages")
        self.assertEqual({row["message_id"] for row in messages}, {row["message_id"] for row in before.values()})
        for row in before.values():
            envelope = strict_json_loads(row["envelope"])
            stored = next(item for item in messages if item["message_id"] == row["message_id"])
            self.assertEqual(stored["envelope_sha256"], document_sha256(envelope))
            objects = Path(config["state_directory"]) / "objects"
            self.assertIn(bytes(row["envelope"]), [path.read_bytes() for path in objects.iterdir()])
            old_receipts = strict_json_loads(row["receipts"])
            new_receipts = strict_json_loads(after[row["request_id"]]["receipts"])
            self.assertEqual(old_receipts[self.host.relays[1].url], new_receipts[self.host.relays[1].url])
        self.assertEqual(self.state("node:" + target.url)["storage_epoch"], entry["storage_epoch"])
        received, _ = self.invoke({"op": "receive"}, index=1)
        self.assertFalse(received["errors"], received)
        self.assertEqual({item["message_id"] for item in received["messages"]},
                         {item["message_id"] for item in before.values()})
        duplicate, _ = self.invoke({"op": "receive"}, index=1, language=self.other_language)
        self.assertEqual(duplicate["messages"], [])
        self.assertEqual(self.records(1), memory_before)
        self.assertEqual(self.records(0), memory_before)
        with self.host.receiver.db() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM inbox").fetchone()[0], 2)

    def test_repair_does_not_bypass_recipient_admission(self):
        before = self.seed()
        target, config, _ = self.replace(admitted_receiver=False)
        blocked, _ = self.invoke()
        self.assert_current_checks(blocked)
        self.assertEqual(blocked["remaining_outbox"], 1, blocked)
        self.assertIn("relay_membership_required", [error["code"] for row in blocked["outbound"] for error in row["errors"]])
        self.assertEqual(len(self.node_rows(config, "members")), 1)
        self.assertEqual(self.node_rows(config, "messages"), [])
        self.assertNotIn(target.url, strict_json_loads(self.assert_frozen(before)[next(iter(before))]["receipts"]))
        joined, _ = self.invoke({"op": "connect", "invitation": self.host.invitation,
            "request_id": "req_synthetic_repair_admission"}, index=1, language=self.other_language)
        self.assertEqual(joined["joined_nodes"], 2, joined)
        resumed, _ = self.invoke()
        self.assertEqual(resumed["remaining_outbox"], 0, resumed)
        self.assertEqual(len(self.node_rows(config, "messages")), 1)
        self.assert_frozen(before)

    def test_unauthorized_replacement_preserves_historical_receipt_and_binding(self):
        before = self.seed()
        url = self.host.relays[0].url
        binding = self.state("node:" + url)
        _, config, _ = self.replace(authorized=False)
        result, _ = self.invoke()
        failed = next(check for check in result["replica_checks"] if check["node"] == 0)
        self.assertEqual(failed["state"], "failed", result)
        self.assertIn({key: failed[key] for key in ("node", "code", "retryable")}, result["errors"])
        self.assertNotEqual(result["state"], "completed")
        self.assertEqual(self.state("node:" + url), binding)
        self.assertEqual(self.host.outbox(), before)
        self.assertEqual(self.node_rows(config, "messages"), [])

    def test_revoked_sender_cannot_repair_or_erase_earlier_receipts(self):
        before = self.seed()
        _, config, _ = self.replace()
        host = self.host
        members = copy.deepcopy(host.roster["payload"]["members"])
        next(member for member in members if member["signing_key"]["key_id"] == host.identities[0].key_id)["status"] = "revoked"
        at = int(time.time())
        revoked = issue_roster(host.issuer, network_id=host.network_id, version=2,
            previous_sha256=document_sha256(host.roster), members=members, issued_at=at, expires_at=at + 300)
        atomic_write(host.roster_path, canonical_bytes(revoked), replace=True)
        result, calls = self.invoke()
        self.assertTrue(result["replica_checks"])
        self.assertTrue(all(item["state"] == "failed" for item in result["replica_checks"]))
        self.assertNotEqual(result["state"], "completed", result)
        self.assertFalse(any(call["path"] == "/v1/messages" for call in calls))
        self.assertEqual(self.host.outbox(), before)
        self.assertEqual(self.node_rows(config, "messages"), [])

    def test_zero_budget_and_no_historical_receipts_make_no_preflight_requests(self):
        empty, calls = self.invoke()
        self.assertEqual(empty["replica_checks"], [])
        self.assertEqual(calls, [])
        self.host.join_receiver()
        for relay in self.host.relays:
            relay.stop()
        queued, _ = self.invoke({"op": "send", "request_id": "req_synthetic_no_receipts",
            "recipients": [self.host.identities[1].key_id], "text": "Synthetic never-uploaded evidence"})
        self.assertEqual(queued["stored_nodes"], 0)
        pending, calls = self.invoke()
        self.assertEqual(pending["replica_checks"], [])
        self.assertEqual(pending["outbound_attempted"], 1)
        self.assertTrue(calls)  # Actual delivery is attempted, not preflight.
        for relay in self.host.relays:
            relay.start()
        complete, _ = self.invoke(language=self.other_language)
        self.assertEqual(complete["remaining_outbox"], 0, complete)
        before = self.host.outbox()
        self.replace()
        result, calls = self.invoke({"op": "pump", "maximum_messages": 0, "receive_limit": 0})
        self.assertEqual(result["replica_checks"], [])
        self.assertEqual(result["outbound_attempted"], 0)
        self.assertEqual(calls, [])
        self.assertEqual(self.host.outbox(), before)

    def test_unavailable_node_is_retryable_without_erasing_storage_history(self):
        before = self.seed()
        self.host.relays[0].stop()
        result, _ = self.invoke()
        failed = next(check for check in result["replica_checks"] if check["node"] == 0)
        self.assertEqual(failed["state"], "failed")
        self.assertTrue(failed["retryable"], result)
        self.assertEqual(result["state"], "needs_retry", result)
        self.assertEqual(result["remaining_outbox"], 0)
        self.assertEqual(result["outbound_attempted"], 0)
        self.assertIn({key: failed[key] for key in ("node", "code", "retryable")}, result["errors"])
        self.assertEqual(self.host.outbox(), before)

    def test_preflight_sub_budget_defers_and_next_runtime_rotates_past_slow_node(self):
        before = self.seed()
        limited, calls = self.invoke({"op": "pump", "maximum_seconds": 2, "receive_limit": 0}, delay_first=True)
        self.assertFalse(limited["budget_exhausted"], limited)
        self.assertEqual(limited["state"], "needs_retry")
        self.assertEqual(limited["outbound_attempted"], 0)
        self.assertEqual([(item["node"], item["state"], item["code"]) for item in limited["replica_checks"]],
            [(0, "failed", "network_replica_check_budget"), (1, "deferred", "network_replica_check_budget")])
        for check in limited["replica_checks"]:
            self.assertTrue(check["retryable"])
            self.assertIn({key: check[key] for key in ("node", "code", "retryable")}, limited["errors"])
        self.assertEqual([(call["base"], call["path"]) for call in calls],
                         [(self.host.relays[0].url, "/v1/status")])
        self.assertEqual(self.state("pump_node_cursor"), 1)
        self.assertEqual(self.host.outbox(), before)
        resumed, following = self.invoke(language=self.other_language)
        self.assertEqual(following[0]["base"], self.host.relays[1].url)
        self.assertEqual(resumed["state"], "completed", resumed)
        self.assert_current_checks(resumed)

    def test_pending_delivery_rotates_to_healthy_node_across_two_runtime_pumps(self):
        host = self.host
        host.join_receiver()
        for relay in host.relays:
            relay.stop()
        queued, _ = self.invoke({"op": "send", "request_id": "req_synthetic_slow_first_replica",
            "recipients": [host.identities[1].key_id], "text": "Synthetic healthy-replica progress"})
        self.assertEqual(queued["stored_nodes"], 0)
        original = host.outbox()["req_synthetic_slow_first_replica"]
        self.assertEqual(strict_json_loads(original["receipts"]), {})
        for relay in host.relays:
            relay.start()
        operation = {"op": "pump", "maximum_messages": 1, "maximum_seconds": 1, "receive_limit": 0}
        first, calls = self.invoke(operation, delay_base=host.relays[0].url)
        self.assertEqual(first["replica_checks"], [])
        self.assertEqual(calls[0]["base"], host.relays[0].url)
        # A transport honoring the newly split per-node deadline may already
        # save at the healthy replica on this first pass. The borrowed delay
        # can overrun it; either way the next process must rotate legally.
        if first["outbound"][0]["stored_nodes"] == 0:
            self.assertTrue(first["budget_exhausted"], first)
        else:
            self.assertEqual(first["outbound"][0]["stored_nodes"], 1, first)
        second, calls = self.invoke(operation, delay_base=host.relays[0].url, language=self.other_language)
        self.assertEqual(calls[0]["base"], host.relays[1].url)
        self.assertEqual(second["outbound"][0]["stored_nodes"], 1, second)
        self.assertEqual(len(self.node_rows(host.relay_configs[1], "messages")), 1)
        after = host.outbox()["req_synthetic_slow_first_replica"]
        self.assertEqual(bytes(after["body"]), bytes(original["body"]))
        frozen = bytes(after["envelope"])
        final, _ = self.invoke()
        self.assertEqual(final["remaining_outbox"], 0, final)
        self.assertEqual(bytes(host.outbox()["req_synthetic_slow_first_replica"]["envelope"]), frozen)
        self.assertEqual(len(self.node_rows(host.relay_configs[0], "messages")), 1)
        self.assertEqual(len(self.node_rows(host.relay_configs[1], "messages")), 1)

    def test_two_pending_rows_do_not_starve_when_row_and_node_rotation_align(self):
        host = self.host
        host.join_receiver()
        # Real HTTP 503s happen after the clients have obtained valid control
        # and frozen the ciphertext, but before either server accepts it.
        for relay in host.relays:
            self.restart_with_http_fault(relay, reject_messages=True)
        for index in range(2):
            queued, _ = self.invoke({"op": "send", "request_id": "req_synthetic_correlated_rotation_" + str(index),
                "recipients": [host.identities[1].key_id],
                "text": "Synthetic correlated row/node rotation " + str(index)})
            self.assertEqual(queued["stored_nodes"], 0, queued)
        frozen = host.outbox()
        self.assertEqual(len(frozen), 2)
        for row in frozen.values():
            self.assertIsNotNone(row["envelope"])
            self.assertEqual(strict_json_loads(row["receipts"]), {})
        self.assertEqual(self.node_rows(host.relay_configs[1], "messages"), [])
        self.restart_with_http_fault(host.relays[0], delay_status=True)
        self.restart_with_http_fault(host.relays[1])
        observations = []
        operation = {"op": "pump", "maximum_messages": 1, "maximum_seconds": 1, "receive_limit": 0}
        for attempt in range(4):
            result, calls = self.invoke(operation,
                language=self.language if attempt % 2 == 0 else self.other_language)
            observations.append(result)
            self.assertEqual(result["outbound_attempted"], 1, result)
            self.assertEqual(self.state("pump_node_cursor"), (attempt + 1) % 2)
            self.assertFalse(any(call["path"] == "/v1/poll" for call in calls))
            self.assert_frozen(frozen)
        healthy = self.node_rows(host.relay_configs[1], "messages")
        self.assertEqual({row["message_id"] for row in healthy},
                         {row["message_id"] for row in frozen.values()}, observations)
        self.assertTrue(any(error["code"] == "network_replica_send_budget" and error["retryable"]
            for result in observations for outbound in result["outbound"] for error in outbound["errors"]), observations)
        healthy_objects = Path(host.relay_configs[1]["state_directory"]) / "objects"
        self.assertEqual({path.read_bytes() for path in healthy_objects.iterdir()},
                         {bytes(row["envelope"]) for row in frozen.values()})
        for row in host.outbox().values():
            self.assertIn(host.relays[1].url, strict_json_loads(row["receipts"]))
        self.restart_with_http_fault(host.relays[0])
        received, _ = self.invoke({"op": "receive"}, index=1)
        self.assertFalse(received["errors"], received)
        self.assertEqual({item["message_id"] for item in received["messages"]},
                         {row["message_id"] for row in frozen.values()})
        self.assertEqual(self.records(0), self.records(1))

    def test_concurrent_replacement_after_skipped_receipt_keeps_pump_retryable(self):
        host = self.host
        host.join_receiver()
        host.relays[1].stop()
        sent, _ = self.invoke({"op": "send", "request_id": "req_synthetic_repair_completion_race",
            "recipients": [host.identities[1].key_id], "text": "Synthetic concurrent replica replacement"})
        self.assertEqual(sent["stored_nodes"], 1, sent)
        frozen = host.outbox()
        self.assertEqual(set(strict_json_loads(next(iter(frozen.values()))["receipts"])), {host.relays[0].url})
        host.relays[1].start()
        replaced = []

        def after_real_store():
            # A was skipped using its old receipt. B really committed its
            # signed envelope, but this client's local merge has not happened.
            target, config, _ = self.replace()
            with NetworkClient(host.net_configs[0]) as concurrent:
                concurrent._refresh(target.url)
            self.assertEqual(strict_json_loads(next(iter(host.outbox().values()))["receipts"]), {})
            replaced.append(config)

        result, _ = self.invoke(after_store=after_real_store, after_store_base=host.relays[1].url)
        self.assertEqual(len(replaced), 1)
        self.assertEqual(result["remaining_outbox"], 1, result)
        self.assertEqual(result["outbound_attempted"], 1)
        self.assertEqual(result["outbound"][0]["errors"], [])
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["state"], "needs_retry", result)
        self.assertTrue(result["retryable"])
        self.assert_frozen(frozen)
        receipts = strict_json_loads(next(iter(host.outbox().values()))["receipts"])
        self.assertEqual(set(receipts), {host.relays[1].url})
        self.assertEqual(self.node_rows(replaced[0], "messages"), [])
        resumed, _ = self.invoke(language=self.other_language)
        self.assertEqual(resumed["remaining_outbox"], 0, resumed)
        self.assertEqual(resumed["state"], "completed", resumed)
        self.assert_frozen(frozen)
        self.assertEqual(len(self.node_rows(replaced[0], "messages")), 1)

    def test_rotation_checkpoint_survives_full_endpoint_backup_and_restore(self):
        self.seed()
        advanced, _ = self.invoke()
        self.assertEqual(advanced["state"], "completed", advanced)
        self.assertEqual(self.state("pump_node_cursor"), 1)
        host = self.host
        issuer_public = host.root / "repair-recovery-issuer.json"
        atomic_write(issuer_public, canonical_bytes(host.issuer.public_descriptor()), replace=False)
        package, secret = host.root / "repair-endpoint-backup", host.root / "repair-separate-recovery-key.json"
        backup = backup_endpoint(network_config=host.net_configs[0], output=package, secret_file=secret)
        self.assertFalse(backup["network_accessed"])
        restored = restore_endpoint(package=package, secret_file=secret, directory=host.root / "repair-restored-endpoint",
            confirm_network_id=host.network_id, issuer_public=issuer_public, authority_url=host.authority.url,
            relays=[relay.url for relay in host.relays], memory_trust=host.configs[0].parent / "trust.json")
        self.assertFalse(restored["automatic_sending_enabled"])
        self.assertTrue(restored["requires_fresh_issuer_status"])
        config = Path(restored["network_config"])
        with NetworkClient(config) as client:
            with client.db() as db:
                self.assertEqual(strict_json_loads(db.execute("SELECT value FROM state WHERE key='pump_node_cursor'").fetchone()[0]), 1)
        result, calls = self.invoke(network_config=config, language=self.other_language)
        self.assertEqual(calls[0]["base"], host.relays[1].url)
        self.assertTrue(any(call["base"] == host.authority.url and call["path"] == "/v1/status" for call in calls))
        self.assertEqual(result["state"], "completed", result)
        self.assert_current_checks(result)

    def test_legacy_receipts_do_not_claim_verified_node_identity(self):
        host = self.host
        authority = {key: value for key, value in host.authority_config.items() if key != "node_directory_path"}
        atomic_write(host.authority.config, canonical_bytes(authority), replace=True)
        for index, relay in enumerate(host.relays):
            relay.stop()
            config = {key: value for key, value in host.relay_configs[index].items()
                      if key not in {"node_identity_path", "storage_epoch"}}
            config["state_directory"] = str(host.root / ("repair-legacy-state-" + str(index)))
            atomic_write(relay.config, canonical_bytes(config), replace=True)
            relay.start()
        self.seed()
        result, _ = self.invoke()
        self.assertEqual(result["state"], "completed", result)
        self.assertEqual(sorted(result["replica_checks"], key=lambda item: item["node"]),
            [{"node": index, "state": "current", "node_identity_verified": False} for index in range(2)])

    def test_authorized_different_url_is_not_automatically_contacted(self):
        before = self.seed()
        target, config, _ = self.replace(new_url=True)
        result, calls = self.invoke()
        self.assertNotEqual(result["state"], "completed", result)
        self.assertNotIn(target.url, {call["base"] for call in calls})
        self.assertEqual(self.host.outbox(), before)
        self.assertEqual(self.node_rows(config, "messages"), [])


@unittest.skipUnless(os.name == "posix", "owned loopback sockets and private TS storage require POSIX")
class PythonReplicaRepairTests(_ReplicaRepairCases, unittest.TestCase):
    language = "python"


@unittest.skipUnless(os.name == "posix", "owned loopback sockets and private TS storage require POSIX")
class TypeScriptReplicaRepairTests(_ReplicaRepairCases, unittest.TestCase):
    language = "typescript"


if __name__ == "__main__":
    unittest.main()
