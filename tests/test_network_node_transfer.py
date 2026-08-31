"""Issuer-directed migration over real, test-owned loopback HTTP nodes."""
from contextlib import contextmanager
import copy
import os
from pathlib import Path
import stat
import time
import unittest
from unittest.mock import patch

from memory_vault import MemoryError, canonical_bytes, strict_json_loads
from memory_vault_network import HTTPTransport, NetworkClient
from memory_vault_network_control import issue_roster
from memory_vault_node import refresh
from memory_vault_node_transfer import (
    EXPORT_KEY, IMPORT_KEY, issue_transfer_grant, prepare_export, receive_transfer, transfer,
)
from memory_vault_network_crypto import document_sha256
from memory_vault_nodes import issue_directory, sign_node_request
from memory_vault_relay import Relay
from memory_vault_storage import atomic_write
import tests.test_network_node_runtime as runtime
import memory_vault_node_transfer as node_transfer


@contextmanager
def fixture(*, expired_policy=False):
    host = runtime.NetworkNodeRuntimeTests("test_independent_refresh_and_persistent_drain_fence_over_real_http")
    try:
        if expired_policy:
            with patch("time.time", return_value=time.time() - 600):
                host.setUp()
        else:
            host.setUp()
        # Only the source admits the receiver or receives messages. The target
        # begins with its independently configured matching initial member.
        for path in host.net_configs[:2]:
            value = strict_json_loads(path.read_bytes())
            value["relays"] = [host.relays[0].url]
            atomic_write(path, canonical_bytes(value), replace=True)
        host.sender = NetworkClient(host.net_configs[0], transport=host.transports[0])
        host.receiver = NetworkClient(host.net_configs[1], transport=host.transports[1])
        connected = host.receiver.connect(host.invitation, request_id="req_synthetic_transfer_join")
        if connected["joined_nodes"] != 1:
            raise AssertionError(connected)
        yield host
    finally:
        host.doCleanups()
        for service in getattr(host, "services", []):
            if not all(process.poll() is not None for process in service.processes):
                raise AssertionError("test-owned service was not stopped")


def seed(host, count=3):
    for index in range(count):
        result = host.sender.send("req_synthetic_transfer_" + str(index), [host.receiver.identity.key_id],
                                  "Synthetic migration memory " + str(index))
        if result["stored_nodes"] != 1:
            raise AssertionError(result)
        if index == 0:
            host.receiver.receive()
            host.sender.receive()


def prepare(host):
    source = Relay(host.relays[0].config)
    target = Relay(host.relays[1].config)
    refresh(source, transport=host.transports[2])
    snapshot = prepare_export(source, "synthetic-node-transfer-001")
    grant = issue_transfer_grant(host.issuer, snapshot, target.node_descriptor(), host.roster, host.directory)
    return source, target, snapshot, grant


def message(host, source, grant, phase, *, snapshot=None, index=None):
    body = {"phase": phase, "transfer_id": grant["payload"]["transfer_id"], "snapshot_sha256": grant["payload"]["snapshot_sha256"],
            "grant_sha256": document_sha256(grant)}
    value = {"grant": grant}
    if phase == "begin":
        value["snapshot"] = snapshot
    if phase == "object":
        row = snapshot["payload"]["messages"][index]
        body.update(object_index=index, envelope_sha256=row["envelope_sha256"])
        value["envelope"] = strict_json_loads((source.object_directory / (row["envelope_sha256"] + ".json")).read_bytes())
    now = int(time.time())
    value["request"] = sign_node_request(source.node_identity, network_id=source.network_id, action="export",
        request_id="req_synthetic_transfer_" + phase + "_" + str(index), body=body, issued_at=now, expires_at=now + 60)
    return value


def table_rows(relay):
    with relay._transaction() as db:
        return {table: [tuple(row) for row in db.execute("SELECT * FROM " + table + " ORDER BY " + order)]
                for table, order in (("members", "key_id"), ("invitations", "invite_id"), ("messages", "sequence"),
                                     ("recipients", "message_id,key_id"), ("receipts", "sequence"))}


@unittest.skipUnless(os.name == "posix", "loopback process fixture uses inherited POSIX sockets")
class NetworkNodeTransferTests(unittest.TestCase):
    def test_real_http_partial_restart_source_exit_preserves_ids_bytes_members_and_old_receipts(self):
        with fixture() as host:
            seed(host)
            source, target, snapshot, grant = prepare(host)
            before = table_rows(source)
            first = transfer(source, grant, transport=host.transports[2], maximum_objects=1)
            self.assertEqual(first["state"], "pending", first)
            self.assertEqual(first["confirmed_objects"], 1)
            self.assertEqual(first["uploaded_objects"], 1)
            with target._transaction() as db:
                self.assertEqual(target._get(db, IMPORT_KEY)["state"], "receiving")
                self.assertEqual(db.execute("SELECT COUNT(*) FROM messages").fetchone()[0], 0)
                with self.assertRaises(MemoryError) as blocked:
                    target._writable(db)
                self.assertEqual(blocked.exception.code, "relay_node_import_in_progress")
            # Source draining preserves exact successful lookups, including
            # already signed acknowledgements; it does not admit new writes.
            old_ack = strict_json_loads(before["receipts"][0][5])
            answer = host.transports[2].request(host.relays[0].url, "POST", "/v1/ack", old_ack)
            self.assertEqual(answer, strict_json_loads(before["receipts"][0][6]))
            with self.assertRaises(MemoryError) as blocked:
                host.transports[2].request(host.relays[1].url, "POST", "/v1/join", {"invite": host.invite(2), "roster": host.roster})
            self.assertEqual(blocked.exception.code, "relay_node_import_in_progress")
            # Process restarts leave both the source snapshot and target
            # progress intact. No shared in-memory transfer object is reused.
            host.relays[1].stop()
            offline = transfer(Relay(host.relays[0].config), grant, transport=host.transports[2], maximum_objects=1)
            self.assertEqual(offline["state"], "pending", offline)
            self.assertTrue(offline["retryable"])
            host.relays[1].start()
            source, target = Relay(host.relays[0].config), Relay(host.relays[1].config)
            second = transfer(source, grant, transport=host.transports[2], maximum_objects=1)
            self.assertEqual(second["confirmed_objects"], 2, second)
            self.assertEqual(second["uploaded_objects"], 1)
            finished = transfer(source, grant, transport=host.transports[2], maximum_objects=1)
            self.assertEqual(finished["state"], "exit_ready", finished)
            self.assertFalse(finished["source_data_deleted"])
            self.assertFalse(finished["safe_to_remove"])
            self.assertEqual(finished["target_receipt"]["payload"]["counts"], snapshot["payload"]["counts"])
            self.assertEqual(table_rows(target), before)
            for row in snapshot["payload"]["messages"]:
                name = row["envelope_sha256"] + ".json"
                self.assertEqual((source.object_directory / name).read_bytes(), (target.object_directory / name).read_bytes())
            duplicate = transfer(Relay(host.relays[0].config), grant, transport=host.transports[2])
            self.assertEqual(duplicate["target_receipt"], finished["target_receipt"])
            self.assertEqual(duplicate["uploaded_objects"], 0)
            self.assertEqual(duplicate["confirmed_objects"], 3)
            repeated = host.transports[2].request(host.relays[1].url, "POST", "/v1/node-transfer",
                message(host, source, grant, "commit"))
            self.assertEqual(repeated["receipt"], finished["target_receipt"])
            self.assertEqual(table_rows(source), before)
            # Stop only our owned source process, then receive through the new
            # node. Existing endpoint memory and signed acks are reused.
            host.relays[0].stop()
            for path in host.net_configs[:2]:
                value = strict_json_loads(path.read_bytes())
                value["relays"] = [host.relays[1].url]
                atomic_write(path, canonical_bytes(value), replace=True)
            receiver = NetworkClient(host.net_configs[1], transport=host.transports[1])
            sender = NetworkClient(host.net_configs[0], transport=host.transports[0])
            received = receiver.receive()
            self.assertEqual(len(received["messages"]), 3, received)
            self.assertEqual({entry["text"] for entry in received["messages"]}, {"Synthetic migration memory " + str(i) for i in range(3)})
            self.assertFalse(received["errors"])
            acknowledgements = sender.receive()
            self.assertFalse(acknowledgements["errors"], acknowledgements)
            with sender.db() as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM acknowledgements").fetchone()[0], 3)
            with target._transaction() as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM messages").fetchone()[0], 3)
                self.assertEqual(db.execute("SELECT document FROM receipts ORDER BY sequence LIMIT 1").fetchone()[0], before["receipts"][0][5])

    def test_wrong_grant_node_cannot_create_admission_or_read_objects(self):
        with fixture() as host:
            seed(host, 1)
            source, target, snapshot, grant = prepare(host)
            refresh(target, transport=host.transports[2])
            forged = {"payload": grant["payload"], "proof": source.node_identity.sign_message(grant["payload"])}
            for bad in (forged, {**grant, "payload": {**grant["payload"], "snapshot_sha256": "0" * 64}}):
                with self.assertRaises(MemoryError):
                    host.transports[2].request(target.base_url, "POST", "/v1/node-transfer", message(host, source, bad, "begin", snapshot=snapshot))
            wrong = {**grant["payload"], "target": {**grant["payload"]["target"], "storage_epoch": "wrong-synthetic-epoch"}}
            wrong = {"payload": wrong, "proof": host.issuer.sign_message(wrong)}
            with self.assertRaises(MemoryError) as rejected:
                host.transports[2].request(target.base_url, "POST", "/v1/node-transfer", message(host, source, wrong, "begin", snapshot=snapshot))
            self.assertEqual(rejected.exception.code, "node_transfer_wrong_node")
            with target._transaction() as db:
                self.assertIsNone(target._get(db, IMPORT_KEY))
                self.assertEqual(db.execute("SELECT COUNT(*) FROM members").fetchone()[0], 1)
            # A source-node signature has no member-mailbox read permission.
            from memory_vault_network_control import sign_request
            now = int(time.time())
            poll = sign_request(source.node_identity, network_id=source.network_id, action="poll", request_id="synthetic-node-no-read",
                body={"cursor": 0, "receipt_cursor": 0, "limit": 1, "maximum_bytes": 8192}, issued_at=now, expires_at=now + 60)
            with self.assertRaises(MemoryError) as denied:
                host.transports[2].request(source.base_url, "POST", "/v1/poll", poll)
            self.assertEqual(denied.exception.code, "relay_membership_required")

    def test_orphans_count_toward_capacity_and_partial_commit_is_rejected(self):
        with fixture() as host:
            seed(host, 2)
            source, target, snapshot, grant = prepare(host)
            host.relays[1].stop()
            config = strict_json_loads(host.relays[1].config.read_bytes())
            config["limits"] = {"maximum_messages": 2}
            atomic_write(host.relays[1].config, canonical_bytes(config), replace=True)
            atomic_write(target.object_directory / "synthetic-orphan.json", b"synthetic crash orphan", replace=False)
            host.relays[1].start()
            result = transfer(source, grant, transport=host.transports[2])
            self.assertEqual(result["state"], "needs_attention", result)
            self.assertEqual(result["error"]["code"], "node_transfer_capacity")
            target = Relay(host.relays[1].config)
            with target._transaction() as db:
                self.assertIsNone(target._get(db, IMPORT_KEY))
            # Remove only the exact orphan created in this test, then begin a
            # zero-object pass and prove commit cannot publish missing data.
            (target.object_directory / "synthetic-orphan.json").unlink()
            pending = transfer(source, grant, transport=host.transports[2], maximum_objects=0)
            self.assertEqual(pending["confirmed_objects"], 0, pending)
            with self.assertRaises(MemoryError) as incomplete:
                host.transports[2].request(target.base_url, "POST", "/v1/node-transfer", message(host, source, grant, "commit"))
            self.assertEqual(incomplete.exception.code, "node_transfer_objects_incomplete")
            with target._transaction() as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM messages").fetchone()[0], 0)
            done = transfer(source, grant, transport=host.transports[2])
            self.assertEqual(done["state"], "exit_ready", done)

    def test_revoked_historical_recipient_is_preserved_but_cannot_receive(self):
        with fixture() as host:
            seed(host, 2)
            source, target, snapshot, _ = prepare(host)
            before = table_rows(source)
            members = copy.deepcopy(host.roster["payload"]["members"])
            for member in members:
                if member["signing_key"]["key_id"] == host.receiver.identity.key_id:
                    member["status"] = "revoked"
            now = int(time.time())
            host.roster = issue_roster(host.issuer, network_id=host.network_id, version=2,
                previous_sha256=document_sha256(host.roster), members=members, issued_at=now, expires_at=now + 300)
            atomic_write(host.roster_path, canonical_bytes(host.roster), replace=True)
            grant = issue_transfer_grant(host.issuer, snapshot, target.node_descriptor(), host.roster, host.directory)
            result = transfer(source, grant, transport=host.transports[2])
            self.assertEqual(result["state"], "exit_ready", result)
            self.assertEqual(table_rows(target), before)
            request = host.receiver._request("poll", {"cursor": 0, "receipt_cursor": 0, "limit": 1, "maximum_bytes": 8192})
            with self.assertRaises(MemoryError) as revoked:
                host.transports[2].request(target.base_url, "POST", "/v1/poll", request)
            self.assertEqual(revoked.exception.code, "relay_membership_required")

    def test_expired_policy_documents_work_only_with_current_grant_and_fresh_online_status(self):
        with fixture(expired_policy=True) as host:
            self.assertLess(host.roster["payload"]["expires_at"], int(time.time()))
            self.assertLess(host.directory["payload"]["expires_at"], int(time.time()))
            seed(host, 1)
            source, target, snapshot, grant = prepare(host)
            result = transfer(source, grant, transport=host.transports[2])
            self.assertEqual(result["state"], "exit_ready", result)
            self.assertEqual(result["confirmed_objects"], 1)
            expired = {**grant["payload"], "issued_at": int(time.time()) - 301, "expires_at": int(time.time()) - 1}
            expired = {"payload": expired, "proof": host.issuer.sign_message(expired)}
            refused = transfer(source, expired, transport=host.transports[2])
            self.assertEqual(refused["state"], "needs_attention", refused)
            self.assertEqual(refused["error"]["code"], "network_control_expired")

    def test_issuer_rejects_same_version_forks_and_adjacent_chain_breaks(self):
        with fixture() as host:
            seed(host, 1)
            source, target, snapshot, grant = prepare(host)
            altered = {**host.roster["payload"], "issued_at": host.roster["payload"]["issued_at"] + 1,
                       "expires_at": host.roster["payload"]["expires_at"] + 1}
            fork = {"payload": altered, "proof": host.issuer.sign_message(altered)}
            with self.assertRaises(MemoryError) as refused:
                issue_transfer_grant(host.issuer, snapshot, target.node_descriptor(), fork, host.directory)
            self.assertEqual(refused.exception.code, "node_transfer_checkpoint_fork")
            altered_nodes = {**host.directory["payload"], "version": 2, "previous_sha256": "f" * 64}
            broken = {"payload": altered_nodes, "proof": host.issuer.sign_message(altered_nodes)}
            with self.assertRaises(MemoryError) as refused:
                issue_transfer_grant(host.issuer, snapshot, target.node_descriptor(), host.roster, broken)
            self.assertEqual(refused.exception.code, "node_transfer_checkpoint_chain_mismatch")

    def test_target_key_proof_is_required_before_any_snapshot_upload(self):
        with fixture() as host:
            seed(host, 1)
            source, target, snapshot, grant = prepare(host)
            observed = host.transports[2]
            original = observed.request
            requests = []

            def corrupt(base, method, path, value=None, **kwargs):
                requests.append((base, method, path))
                result = original(base, method, path, value, **kwargs)
                if base == target.base_url and method == "GET" and path == "/v1/status":
                    result.pop("node_challenge")
                return result

            with patch.object(observed, "request", side_effect=corrupt):
                result = transfer(source, grant, transport=observed)
            self.assertEqual(result["state"], "needs_attention", result)
            self.assertFalse(any(path == "/v1/node-transfer" for _, _, path in requests))
            with target._transaction() as db:
                self.assertIsNone(target._get(db, IMPORT_KEY))

    def test_directory_fsync_failure_leaves_no_progress_and_retry_reestablishes_durability(self):
        with fixture() as host:
            seed(host, 1)
            source, target, snapshot, grant = prepare(host)
            started = transfer(source, grant, transport=host.transports[2], maximum_objects=0)
            self.assertEqual(started["state"], "pending", started)
            upload = message(host, source, grant, "object", snapshot=snapshot, index=0)
            original_fsync = os.fsync
            failed = []

            def fail_directory_once(fd):
                if stat.S_ISDIR(os.fstat(fd).st_mode) and not failed:
                    failed.append(True)
                    raise OSError(5, "synthetic directory fsync failure")
                return original_fsync(fd)

            with patch.object(node_transfer.storage.os, "fsync", side_effect=fail_directory_once):
                with self.assertRaises(MemoryError) as failed_write:
                    receive_transfer(target, upload)
            self.assertEqual(failed_write.exception.code, "node_transfer_storage_unavailable")
            self.assertTrue(failed_write.exception.retryable)
            self.assertEqual(failed, [True])
            name = snapshot["payload"]["messages"][0]["envelope_sha256"] + ".json"
            self.assertTrue((target.object_directory / name).exists())
            with target._transaction() as db:
                self.assertEqual(target._get(db, IMPORT_KEY)["next_object"], 0)
            observed = []

            def track(fd):
                observed.append("directory" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file")
                return original_fsync(fd)

            with patch.object(node_transfer.storage.os, "fsync", side_effect=track):
                retried = receive_transfer(target, upload)
            self.assertEqual(retried["progress"]["payload"]["next_object"], 1)
            self.assertIn("file", observed)
            self.assertIn("directory", observed)
            observed.clear()
            with patch.object(node_transfer.storage.os, "fsync", side_effect=track):
                completed = receive_transfer(target, message(host, source, grant, "commit"))
            self.assertEqual(completed["state"], "committed")
            self.assertTrue(completed["receipt"]["payload"]["all_objects_durable"])
            self.assertIn("file", observed)
            self.assertIn("directory", observed)


if __name__ == "__main__":
    unittest.main()
