"""One explicit synthetic fragmented-remote workflow; no live provider.

Only the provider command runner is replaced by exact in-memory byte carriage.
Configuration/pins, signed publication, fragment verification, receiving and
durable receipts are real. Injected copy/read/head errors and config disable
exercise recovery boundaries, not real network, process crashes or performance.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from memory_vault import MemoryError, Vault, canonical_bytes
import memory_vault_remote as remote
import memory_vault_sync as sync
import memory_vault_transfer as transfer
from memory_vault_trust import Identity, TrustStore


class FragmentedRemoteWorkflowTests(unittest.TestCase):
    def test_exact_group_resume_cancellation_and_durable_receive_reporting(self) -> None:
        with tempfile.TemporaryDirectory(prefix="vault-fragmented-remote-") as temporary:
            root = Path(temporary).resolve()
            control = root / "control"
            control.mkdir(mode=0o700)
            identity_path = control / "sender-identity.json"
            identity = Identity.generate(identity_path)
            sender_trust_path = control / "sender-trust.json"
            receiver_trust_path = control / "receiver-trust.json"
            sender_trust = TrustStore(sender_trust_path)
            receiver_trust = TrustStore(receiver_trust_path)
            sender_trust.add(identity.public_descriptor(), "synthetic source")
            receiver_trust.add(identity.public_descriptor(), "independently selected synthetic source")

            executable = root / "inert-rclone"
            executable.write_bytes(b"Synthetic pin fixture; this file must never execute.\n")
            executable.chmod(0o700)
            provider_config = control / "provider.conf"
            provider_config.write_text("[synthetic]\ntype = drive\n", encoding="utf-8")
            provider_config.chmod(0o600)
            sender_database = root / "sender.sqlite3"
            receiver_database = root / "receiver.sqlite3"
            sender = Vault(sender_database, signer=identity.sign_record,
                           trust_check=sender_trust.require_trusted)
            identifiers = []
            originals = {}
            for ordinal in range(6):
                value = {"op": "remember", "kind": "fact",
                         "text": f"Synthetic fragment {ordinal}: " + "x" * (850 * 1024)}
                if identifiers:
                    value["relations"] = [{"type": "derived_from", "target": identifiers[-1]}]
                response = sender.handle(value)
                self.assertTrue(response["ok"], response)
                memory_id = response["result"]["memory_id"]
                identifiers.append(memory_id)
                originals[memory_id] = canonical_bytes(sender.handle(
                    {"op": "get", "memory_id": memory_id})["result"]["record"])
            source_store = sender.handle({"op": "status"})["result"]["store_id"]

            def configuration(label: str, database: Path, trust: Path, peers: list) -> tuple[Path, dict]:
                path = control / (label + "-sync.json")
                document = {
                    "schema_version": sync.CONFIG_SCHEMA, "vault": str(database),
                    "identity": str(identity_path if label == "sender" else control / "unloaded-receiver-identity.json"),
                    "trust_store": str(trust), "state_directory": str(root / (label + "-state")),
                    "enabled": True, "automatic": False, "background": False,
                    "backend": {"kind": "rclone", "executable": str(executable),
                                "executable_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
                                "config_file": str(provider_config), "remote": "synthetic:memory",
                                "peers": peers},
                    "limits": {**sync.DEFAULT_LIMITS, "maximum_batches": 1,
                               "maximum_files": 32, "maximum_bytes": 32 * 1024 * 1024,
                               "maximum_seconds": 60, "batch_bytes": 4096, "record_limit": 6},
                }
                sync._write_control(path, document, replace=False)
                sync.SyncConfig.load(path)
                return path, document

            sender_config, _ = configuration("sender", sender_database, sender_trust_path, [])
            receiver_config, receiver_document = configuration(
                "receiver", receiver_database, receiver_trust_path,
                [{"key_id": identity.key_id, "store_id": source_store}])
            objects: dict[str, bytes] = {}
            calls: list[tuple[str, str]] = []
            faults = {"upload_second": True, "read_second": False, "cancel_after_second_read": False}

            class ByteCarrier(remote.RcloneBackend):
                # Keep the real constructor, path membership, budgets, upload
                # read-back checks and parsers. Substitute only _run; no actual
                # provider executable/process/network connection is allowed.
                def _run(carrier, arguments, *, output_limit, missing_ok=False):
                    carrier.active_check()
                    carrier.budget.remaining()
                    carrier.budget.commands += 1
                    if carrier.budget.commands > 128:
                        raise MemoryError("sync_command_budget_exceeded", retryable=True)
                    operation = arguments[0]
                    target = arguments[2] if operation == "copyto" else arguments[1]
                    calls.append((operation, target))
                    second_fragment = "/groups/" in target and target.rsplit("/", 1)[1].startswith("000001-")
                    if operation == "lsf":
                        prefix = target + "/"
                        listing = [(name[len(prefix):], data) for name, data in objects.items()
                                   if name.startswith(prefix) and "/" not in name[len(prefix):]]
                        result = "".join(f"{len(data)}\t{name}\n" for name, data in sorted(listing)).encode()
                        if not listing and missing_ok:
                            return None
                    elif operation == "copyto":
                        if second_fragment and faults["upload_second"]:
                            faults["upload_second"] = False
                            raise MemoryError("remote_timeout", retryable=True)
                        selected = Path(arguments[1]).resolve()
                        self.assertTrue(selected.is_relative_to(root))
                        value = selected.read_bytes()
                        if target in objects and objects[target] != value:
                            raise MemoryError("remote_command_failed", retryable=True)
                        objects[target] = value
                        result = b""
                    elif operation == "cat":
                        if second_fragment and faults["read_second"]:
                            faults["read_second"] = False
                            raise MemoryError("remote_timeout", retryable=True)
                        if target not in objects:
                            raise MemoryError("remote_command_failed", retryable=True)
                        result = objects[target][:int(arguments[arguments.index("--head") + 1])]
                        if second_fragment and faults["cancel_after_second_read"]:
                            faults["cancel_after_second_read"] = False
                            sync._write_control(receiver_config, {**receiver_document, "enabled": False})
                    else:
                        raise AssertionError("Unexpected simulated provider command: " + operation)
                    if len(result) > output_limit:
                        raise MemoryError("remote_output_limit")
                    return result

            def fragment_reads(start: int, index: int) -> int:
                return sum(operation == "cat" and "/groups/" in path and
                           path.rsplit("/", 1)[1].startswith(f"{index:06d}-")
                           for operation, path in calls[start:])

            with contextlib.ExitStack() as scope:
                scope.enter_context(mock.patch.object(sync, "RcloneBackend", ByteCarrier))
                scope.enter_context(mock.patch.object(sync, "_spawn", side_effect=AssertionError("unexpected worker")))
                scope.enter_context(mock.patch.object(sync.subprocess, "Popen", side_effect=AssertionError("unexpected process")))

                interrupted_send = sync.flush(sender_config)
                self.assertEqual(interrupted_send["last_error"], "remote_timeout")
                self.assertEqual(interrupted_send["counts"]["published_batches"], 1)
                self.assertEqual(interrupted_send["counts"]["uploaded_batches"], 0)
                self.assertEqual(len(objects), 1)
                self.assertTrue(all(path.endswith(".ndjson") for path in objects))
                first_object = next(iter(objects))
                first_object_bytes = objects[first_object]
                resumed_send = sync.flush(sender_config)
                self.assertIsNone(resumed_send["last_error"])
                self.assertEqual(resumed_send["counts"]["uploaded_batches"], 1)
                self.assertEqual(objects[first_object], first_object_bytes)
                self.assertEqual(sum(operation == "copyto" and path == first_object for operation, path in calls), 1)

                manifest_paths = [path for path in objects if path.endswith(".json")]
                self.assertEqual(len(manifest_paths), 1)
                capsule = json.loads(objects[manifest_paths[0]])
                payload = capsule["payload"]
                group = payload["group"]
                self.assertIsNotNone(group)
                self.assertEqual(group["record_count"], 6)
                self.assertEqual(len(group["fragments"]), 2)
                self.assertGreater(group["record_bytes"], transfer.MAX_CAPSULE_BYTES)
                self.assertEqual(payload["records"], [])
                self.assertEqual(payload["attestations"], {})
                self.assertEqual(receiver_trust.verify_message(payload, capsule["proof"]), identity.key_id)
                self.assertEqual([path for operation, path in calls if operation == "copyto"][-1], manifest_paths[0])

                # Receive-only must not load the configured but unused identity.
                scope.enter_context(mock.patch.object(Identity, "load", side_effect=AssertionError("receive loaded a private key")))
                faults["read_second"] = True
                receive_start = len(calls)
                interrupted_receive = sync.receive(receiver_config)
                self.assertEqual(interrupted_receive["last_error"], "remote_timeout")
                self.assertEqual(interrupted_receive["counts"]["records_added"], 0)
                self.assertFalse(receiver_database.exists())
                self.assertEqual(fragment_reads(receive_start, 0), 1)
                self.assertEqual(fragment_reads(receive_start, 1), 1)

                # Finish staging, then disable exactly after the final simulated
                # provider read. The real pre-admission active check must stop.
                faults["cancel_after_second_read"] = True
                cancelled = sync.receive(receiver_config)
                self.assertEqual(cancelled["state"], "cancelled")
                self.assertEqual(cancelled["last_error"], "sync_cancelled")
                self.assertEqual(cancelled["counts"]["records_added"], 0)
                self.assertFalse(receiver_database.exists())
                self.assertEqual(fragment_reads(receive_start, 0), 1)
                self.assertEqual(fragment_reads(receive_start, 1), 2)
                sync._write_control(receiver_config, receiver_document)

                # Now all fragments are real verified local files. Inject only
                # the later head-file rejection, after the atomic Vault receipt.
                receiver_state = root / "receiver-state" / "transfer" / "state.json"
                original_write = transfer._write
                head_failures = []

                def fail_head(path, value, **keywords):
                    if path == receiver_state and value.get("received") and not head_failures:
                        head_failures.append(str(path))
                        raise MemoryError("transfer_output_conflict")
                    return original_write(path, value, **keywords)

                with mock.patch.object(transfer, "_write", side_effect=fail_head):
                    admitted_before_head = sync.receive(receiver_config)
                self.assertEqual(len(head_failures), 1)
                self.assertEqual(admitted_before_head["last_error"], "transfer_output_conflict")
                self.assertEqual(admitted_before_head["counts"]["received_batches"], 1)
                self.assertEqual(admitted_before_head["counts"]["records_added"], 6)
                self.assertEqual(admitted_before_head["counts"]["peer_failures"], 0)
                self.assertTrue(admitted_before_head["more_work_possible"])
                receiver = Vault(receiver_database, trust_check=receiver_trust.require_trusted)
                self.assertEqual(receiver.handle({"op": "status"})["result"]["records"], 6)
                self.assertFalse(receiver_state.exists())

                resumed_receive = sync.receive(receiver_config)
                self.assertIsNone(resumed_receive["last_error"])
                self.assertEqual(resumed_receive["counts"]["received_batches"], 1)
                self.assertEqual(resumed_receive["counts"]["records_added"], 0)
                self.assertEqual(resumed_receive["counts"]["receipt_replays"], 1)
                self.assertEqual(fragment_reads(receive_start, 0), 1)
                self.assertEqual(fragment_reads(receive_start, 1), 2)
                head = transfer._read(receiver_state, private=True)
                self.assertEqual(head["received"][identity.key_id + "/" + source_store], payload["cursor"])
                for memory_id in identifiers:
                    response = receiver.handle({"op": "get", "memory_id": memory_id})
                    self.assertTrue(response["ok"], response)
                    self.assertEqual(canonical_bytes(response["result"]["record"]), originals[memory_id])
                final = sync.receive(receiver_config)
                self.assertIsNone(final["last_error"])
                self.assertEqual(final["counts"]["received_batches"], 0)
                self.assertEqual(final["counts"]["records_added"], 0)
                self.assertFalse(final["outbound_attempted"])
                self.assertFalse(any(operation == "copyto" for operation, _ in calls[receive_start:]))


if __name__ == "__main__":
    unittest.main()
