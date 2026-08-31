"""Synthetic storage assertions: strict wire contract and bounded local history.

Real HTTP cases use only inherited test-owned loopback listeners. A mutated
response is re-signed by the synthetic node after its real durable write.
"""
from __future__ import annotations

import base64
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from memory_vault import MemoryError, canonical_bytes, strict_json_loads
from memory_vault_network import NetworkClient
from memory_vault_network_crypto import document_sha256
import memory_vault_nodes as nodes
import memory_vault_network_recovery as recovery
from memory_vault_relay import Relay
from memory_vault_storage import atomic_write
from tests import test_network_typescript_nodes as node_tests
from tests import test_network_typescript_peer as peer_tests


class StorageReceiptContractTests(unittest.TestCase):
    setUpClass = classmethod(node_tests.TypeScriptNodeTests.setUpClass.__func__)
    run_ts = node_tests.TypeScriptNodeTests.run_ts

    def setUp(self):
        self.key = node_tests.TypeScriptNodeTests.signing()
        self.network = "synthetic-storage-receipt-network"
        self.binding = {"signing_key": self.key.public_descriptor(), "base_url": "http://127.0.0.1:18881",
                        "storage_epoch": "synthetic-storage-epoch"}
        self.receipt = {"state": "stored", "message_id": "synthetic-message", "envelope_sha256": "a" * 64, "sequence": 1}

    def signed(self, value):
        relay = SimpleNamespace(node_identity=self.key, network_id=self.network, node_descriptor=lambda: self.binding)
        return Relay._stored_result(relay, value)

    def compare(self, value, *, error=None, binding="default", legacy=False):
        binding = self.binding if binding == "default" else binding
        options = {"network_id": self.network, "message_id": self.receipt["message_id"],
                   "envelope_sha256": self.receipt["envelope_sha256"]}
        request = {"op": "receipt", "options": {**options, "node": binding, "allow_legacy_unsigned": legacy}}
        if isinstance(value, bytes):
            request["raw"] = base64.urlsafe_b64encode(value).decode()
        else:
            request["value"] = value
        result, = self.run_ts(request)
        if error is None:
            self.assertTrue(result["ok"], result)
            actual = nodes.verify_storage_receipt(value, **options, node_binding=binding, allow_legacy_unsigned=legacy)
            self.assertEqual(actual, result["result"])
        else:
            self.assertEqual(result, {"ok": False, "error": error})
            with self.assertRaises(MemoryError) as caught:
                nodes.verify_storage_receipt(value, **options, node_binding=binding, allow_legacy_unsigned=legacy)
            self.assertEqual(caught.exception.code, error)

    def test_resigned_extra_sequence_size_and_binding_rejected_in_both_runtimes(self):
        self.compare(self.signed(self.receipt))
        for value, error in (({**self.receipt, "extra": "synthetic"}, "network_invalid_document"),
                             ({**self.receipt, "sequence": 0}, "network_invalid_integer"),
                             ({**self.receipt, "sequence": -1}, "network_invalid_integer"),
                             ({**self.receipt, "sequence": True}, "network_invalid_integer"),
                             ({**self.receipt, "padding": "x" * 32768}, "network_document_too_large")):
            with self.subTest(error=error, sequence=value.get("sequence")):
                self.compare(self.signed(value), error=error)
        self.compare(self.signed(self.receipt), binding={**self.binding, "storage_epoch": "synthetic-other-epoch"},
                     error="network_node_receipt_mismatch")
        self.compare(self.signed({**self.receipt, "message_id": "synthetic-wrong-message"}), error="network_invalid_storage_receipt")

    def test_explicit_legacy_and_raw_wire_size_limit(self):
        self.compare(self.receipt, binding=None, legacy=True)
        self.compare(self.receipt, binding=None, error="network_node_identity_required")
        self.compare(self.receipt, error="network_node_identity_required")
        self.compare(self.signed(self.receipt), binding=None, legacy=True, error="network_node_identity_required")
        self.compare({**self.receipt, "extra": True}, binding=None, legacy=True, error="network_invalid_document")
        raw = canonical_bytes(self.signed(self.receipt))
        self.compare(raw + b" " * (nodes.MAX_STORAGE_RECEIPT_BYTES - len(raw)))
        self.compare(raw + b" " * (nodes.MAX_STORAGE_RECEIPT_BYTES + 1 - len(raw)), error="network_document_too_large")

    def test_lengths_rejected_before_receipt_or_envelope_materialization(self):
        client = object.__new__(NetworkClient)
        for count, size, expected in ((1, 65537, "network_storage_receipt_capacity"),
                                      (257, 65536, "network_storage_receipt_capacity"),
                                      (1025, 2, "network_outbox_capacity")):
            with self.subTest(count=count, size=size), sqlite3.connect(":memory:") as db:
                db.row_factory = sqlite3.Row
                db.execute("CREATE TABLE outbox(request_id TEXT,message_id TEXT,receipts TEXT,envelope BLOB)")
                db.executemany("INSERT INTO outbox VALUES(?,?,?,NULL)",
                               [(str(index), str(index), " " * size) for index in range(count)])
                db.commit()
                queries = []
                db.set_trace_callback(queries.append)
                with patch("memory_vault_network.strict_json_loads", side_effect=AssertionError("must not parse payload")):
                    with self.assertRaises(MemoryError) as caught:
                        client._outbox_rows(db)
                self.assertEqual(caught.exception.code, expected)
                self.assertTrue(queries[0].startswith("BEGIN"))
                self.assertTrue(any("length(CAST(receipts AS BLOB))" in query for query in queries))
                self.assertFalse(any("SELECT rowid" in query or "SELECT envelope" in query for query in queries))
                self.assertEqual(db.execute("SELECT COUNT(*) FROM outbox").fetchone()[0], count)


@unittest.skipUnless(os.name == "posix", "the fixture inherits test-owned POSIX sockets")
class StorageReceiptHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        peer_tests.TypeScriptPeerTests.setUpClass.__func__(cls)
        # The peer fixture stays independent of Python at runtime. Copy an
        # optional ranking module when the concurrent retrieval work adds it.
        ranking = peer_tests.ROOT / "clients/typescript/network/ranking_math.ts"
        if ranking.exists():
            shutil.copyfile(ranking, cls.fixture / ranking.name)
        driver = peer_tests.DRIVER.replace("import { NetworkPeer }", "import { readFileSync } from 'node:fs';\nimport { signMessage } from './crypto.ts';\nimport { NetworkPeer }")
        driver = driver.replace("  return result;", """
  if(input.receipt_mutation && base===input.receipt_node && path==='/v1/messages'){
    const receipt={...result};delete receipt.node_receipt;
    if(input.receipt_mutation==='extra')receipt.extra='synthetic';
    if(input.receipt_mutation==='zero')receipt.sequence=0;
    if(input.receipt_mutation==='large')receipt.padding='x'.repeat(32768);
    const payload={...result.node_receipt.payload,receipt};
    return {...receipt,node_receipt:{payload,proof:signMessage(payload,JSON.parse(readFileSync(input.node_key,'utf8')))}};
  }
  return result;""")
        (cls.fixture / "driver.mjs").write_text(driver)

    def setUp(self):
        peer_tests.TypeScriptPeerTests.setUp(self)
        self.host.join_receiver()
    ts = peer_tests.TypeScriptPeerTests.ts
    value = peer_tests.TypeScriptPeerTests.value

    def archive(self):
        host = self.host
        issuer = host.root / "independent-receipt-recovery-issuer.json"
        atomic_write(issuer, canonical_bytes(host.issuer.public_descriptor()), replace=False)
        package, secret = host.root / "signed-receipt-backup", host.root / "separate-receipt-recovery-key.json"
        snapshot = recovery.backup_endpoint(network_config=host.net_configs[0], output=package, secret_file=secret)
        self.assertFalse(snapshot["network_accessed"])
        return {"package": package, "secret_file": secret, "confirm_network_id": host.network_id,
                "issuer_public": issuer, "authority_url": host.authority.url,
                "relays": [relay.url for relay in host.relays], "memory_trust": host.configs[0].parent / "trust.json"}

    @staticmethod
    def snapshot(client):
        with client.db() as db:
            rows = {row["request_id"]: dict(row) for row in db.execute("SELECT * FROM outbox")}
            bindings = {row["key"]: row["value"] for row in db.execute("SELECT key,value FROM state WHERE key LIKE 'node:%'")}
        return rows, bindings

    def test_signed_backup_restore_keeps_node_proofs_and_resumes_each_runtime(self):
        host = self.host
        for request_id, dropped, expected in (("req_signed_recovery_complete", None, 2),
                                              ("req_signed_recovery_partial", host.relays[1].url, 1)):
            sent = self.value(0, {"op": "send", "request_id": request_id, "recipients": [host.identities[1].key_id],
                                 "text": "Synthetic signed endpoint recovery " + request_id}, drop_after_store=dropped)
            self.assertEqual(sent["stored_nodes"], expected, sent)
        before, bindings = self.snapshot(host.sender)
        self.assertEqual(len(bindings), 2)
        remote = {}
        for request_id, row in before.items():
            envelope_hash = document_sha256(strict_json_loads(row["envelope"]))
            receipts = strict_json_loads(row["receipts"])
            for url, receipt in receipts.items():
                nodes.verify_storage_receipt(receipt, network_id=host.network_id, message_id=row["message_id"],
                    envelope_sha256=envelope_hash, node_binding=strict_json_loads(bindings["node:" + url]))
                self.assertGreater(receipt["sequence"], 0)
            for index in range(2):
                state = host.root / ("node-state-" + str(index))
                with sqlite3.connect(state / "relay.sqlite3") as db:
                    sequence = db.execute("SELECT sequence FROM messages WHERE message_id=?", (row["message_id"],)).fetchone()[0]
                original = (state / "objects" / (envelope_hash + ".json")).read_bytes()
                self.assertEqual(original, row["envelope"])
                remote[request_id, index] = sequence, original
        arguments = self.archive()
        for runtime in ("python", "typescript"):
            with self.subTest(runtime=runtime):
                restored = recovery.restore_endpoint(directory=host.root / ("restored-signed-" + runtime), **arguments)
                self.assertFalse(restored["network_accessed"])
                self.assertTrue(restored["activation_disabled"])
                self.assertTrue(restored["requires_fresh_issuer_status"])
                config = Path(restored["network_config"])
                with NetworkClient(config) as client:
                    self.assertEqual(self.snapshot(client), (before, bindings))
                    if runtime == "python":
                        sent = client.pump(maximum_messages=1, maximum_seconds=5, receive_limit=0)
                if runtime == "typescript":
                    sent = self.value(0, {"op": "pump", "maximum_messages": 1, "maximum_seconds": 5,
                                          "receive_limit": 0}, config=str(config))
                self.assertEqual(sent["remaining_outbox"], 0, sent)
                self.assertEqual(sent["outbound_attempted"], 1, sent)
                self.assertEqual(sent["outbound"][0]["stored_nodes"], 2, sent)
                with NetworkClient(config) as client:
                    after, after_bindings = self.snapshot(client)
                self.assertEqual(after_bindings, bindings)
                for request_id, row in before.items():
                    current = after[request_id]
                    self.assertEqual({key: value for key, value in current.items() if key != "receipts"},
                                     {key: value for key, value in row.items() if key != "receipts"})
                    receipts = strict_json_loads(current["receipts"])
                    for url, receipt in strict_json_loads(row["receipts"]).items():
                        self.assertEqual(receipts[url], receipt)
                    for index, relay in enumerate(host.relays):
                        self.assertEqual(receipts[relay.url]["sequence"], remote[request_id, index][0])
                        envelope_hash = document_sha256(strict_json_loads(current["envelope"]))
                        original = (host.root / ("node-state-" + str(index)) / "objects" / (envelope_hash + ".json")).read_bytes()
                        self.assertEqual(original, remote[request_id, index][1])
                self.assertEqual(self.snapshot(host.sender), (before, bindings))

    def test_authenticated_backup_rejects_bad_signed_receipts_without_overwriting_source(self):
        host = self.host
        sent = host.sender.send("req_signed_recovery_reject", [host.identities[1].key_id], "Synthetic authenticated bad receipt")
        self.assertEqual(sent["stored_nodes"], 2, sent)
        before = self.snapshot(host.sender)
        source_configs = {path: path.read_bytes() for path in (host.configs[0], host.net_configs[0])}
        arguments = self.archive()
        for mutation, error in (("extra", "network_invalid_document"), ("wrong_epoch", "network_node_receipt_mismatch"),
                                ("unsigned", "network_node_identity_required")):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory(dir=host.root) as temporary:
                stage = Path(temporary)
                recovery._unseal(arguments["package"], arguments["secret_file"], stage, host.network_id, time.monotonic() + 30)
                source = stage / "transport.ndjson"
                rows = [strict_json_loads(line) for line in source.read_bytes().splitlines()]
                selected = next(row for row in rows[1:] if row["table"] == "outbox")
                index = recovery.COLUMNS["outbox"].index("receipts")
                receipts = strict_json_loads(selected["values"][index])
                original = receipts[host.relays[0].url]
                value = {key: item for key, item in original.items() if key != "node_receipt"}
                descriptor = dict(original["node_receipt"]["payload"]["node"])
                if mutation == "extra":
                    value["extra"] = "synthetic authenticated extension"
                if mutation == "wrong_epoch":
                    descriptor["storage_epoch"] = "synthetic-not-the-bound-epoch"
                relay = SimpleNamespace(node_identity=host.node_identities[0], network_id=host.network_id,
                                        node_descriptor=lambda: descriptor)
                receipts[host.relays[0].url] = value if mutation == "unsigned" else Relay._stored_result(relay, value)
                selected["values"][index] = canonical_bytes(receipts).decode()
                atomic_write(source, b"\n".join(canonical_bytes(row) for row in rows) + b"\n", replace=True)
                package, secret = host.root / ("bad-receipt-package-" + mutation), host.root / ("bad-receipt-key-" + mutation)
                recovery._seal(stage, package, secret, host.network_id, time.monotonic() + 30)
                altered = {**arguments, "package": package, "secret_file": secret}
                destination = host.root / ("rejected-signed-" + mutation)
                with self.assertRaises(MemoryError) as caught:
                    recovery.restore_endpoint(directory=destination, **altered)
                self.assertEqual(caught.exception.code, error)
                # Existing recovery leaves a NEW capture-off endpoint on late
                # validation failure, but its transport transaction rolls back.
                with NetworkClient(destination / "endpoint" / "network.json") as failed:
                    self.assertEqual(self.snapshot(failed), ({}, {}))
                    self.assertFalse(failed.client_config.capture_visible_turns)
                with self.assertRaises(MemoryError) as caught:
                    recovery.restore_endpoint(directory=host.configs[0].parent, **altered)
                self.assertEqual(caught.exception.code, "endpoint_backup_new_path_required")
                self.assertEqual(self.snapshot(host.sender), before)
                self.assertEqual({path: path.read_bytes() for path in source_configs}, source_configs)

    def test_real_durable_messages_reject_resigned_response_without_losing_frozen_bytes(self):
        host = self.host
        for runtime in ("python", "typescript"):
            for mutation, code in (("extra", "network_invalid_document"), ("zero", "network_invalid_integer"),
                                   ("large", "network_document_too_large")):
                with self.subTest(runtime=runtime, mutation=mutation):
                    request_id = "req_receipt_" + runtime + "_" + mutation
                    operation = {"op": "send", "request_id": request_id, "recipients": [host.identities[1].key_id],
                                 "text": "Synthetic durable receipt contract"}
                    def mutate(base, method, path, result):
                        if base != host.relays[0].url or path != "/v1/messages":
                            return result
                        value = {key: item for key, item in result.items() if key != "node_receipt"}
                        value.update({"extra": "synthetic"} if mutation == "extra" else
                                     {"sequence": 0} if mutation == "zero" else {"padding": "x" * 32768})
                        relay = SimpleNamespace(node_identity=host.node_identities[0], network_id=host.network_id,
                            node_descriptor=lambda: {key: host.node_entries[0][key] for key in ("signing_key", "base_url", "storage_epoch")})
                        return Relay._stored_result(relay, value)
                    host.transports[0].mutator = mutate
                    result = (host.sender.send(request_id, operation["recipients"], operation["text"]) if runtime == "python"
                        else self.value(0, operation, receipt_mutation=mutation, receipt_node=host.relays[0].url,
                                        node_key=host.relay_configs[0]["node_identity_path"]))
                    self.assertEqual(result["stored_nodes"], 1, result)
                    self.assertEqual([error["code"] for error in result["errors"]], [code])
                    before = host.outbox()[request_id]
                    digest = document_sha256(strict_json_loads(before["envelope"]))
                    object_path = host.root / "node-state-0" / "objects" / (digest + ".json")
                    original = object_path.read_bytes()
                    self.assertEqual(original, before["envelope"])
                    with sqlite3.connect(host.root / "node-state-0" / "relay.sqlite3") as db:
                        sequence = db.execute("SELECT sequence FROM messages WHERE message_id=?", (result["message_id"],)).fetchone()[0]
                    host.transports[0].mutator = None
                    retry = (host.sender.send(request_id, operation["recipients"], operation["text"]) if runtime == "python" else self.value(0, operation))
                    self.assertEqual(retry["stored_nodes"], 2, retry)
                    after = host.outbox()[request_id]
                    for field in ("body", "envelope", "roster", "message_id"):
                        self.assertEqual(before[field], after[field])
                    receipts = strict_json_loads(after["receipts"])
                    self.assertEqual(receipts[host.relays[0].url]["sequence"], sequence)
                    self.assertEqual(receipts[host.relays[1].url], strict_json_loads(before["receipts"])[host.relays[1].url])
                    self.assertEqual(object_path.read_bytes(), original)

    def test_historical_receipt_and_recovery_reject_without_mutating_rows(self):
        host = self.host
        request_id = "req_historical_receipt"
        host.sender.send(request_id, [host.identities[1].key_id], "Synthetic stored history")
        good = host.outbox()[request_id]
        receipts = strict_json_loads(good["receipts"])
        receipts[host.relays[0].url]["sequence"] = 0
        with host.sender.db() as db:
            db.execute("UPDATE outbox SET receipts=? WHERE request_id=?", (canonical_bytes(receipts).decode(), request_id))
        poisoned = host.outbox()[request_id]
        with self.assertRaises(MemoryError) as caught:
            host.sender._pending_outbox()
        self.assertEqual(caught.exception.code, "network_invalid_integer")
        result, = self.ts(0, {"op": "pump", "maximum_messages": 1, "maximum_seconds": 1, "receive_limit": 0})
        self.assertEqual(result, {"ok": False, "error": "network_invalid_integer"})
        with host.sender.db() as db, sqlite3.connect(":memory:") as memory:
            with self.assertRaises(MemoryError) as caught:
                recovery._validate_transport(db, host.sender, memory, time.monotonic() + 10)
            self.assertEqual(caught.exception.code, "network_invalid_integer")
        self.assertEqual(host.outbox()[request_id], poisoned)
        with host.sender.db() as db:
            db.execute("UPDATE outbox SET receipts=? WHERE request_id=?", (" " * 65537, request_id))
        oversized = host.outbox()[request_id]
        result, = self.ts(0, {"op": "pump", "maximum_messages": 1, "maximum_seconds": 1, "receive_limit": 0})
        self.assertEqual(result, {"ok": False, "error": "network_storage_receipt_capacity"})
        self.assertEqual(host.outbox()[request_id], oversized)


if __name__ == "__main__":
    unittest.main()
