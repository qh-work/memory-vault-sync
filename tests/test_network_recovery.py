"""Full endpoint recovery uses only temporary synthetic identities and memory."""
from contextlib import closing, contextmanager
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from memory_vault import MemoryError, canonical_bytes, strict_json_loads
from memory_vault_network import NetworkClient
from memory_vault_network_control import issue_roster
from memory_vault_network_crypto import document_sha256
from memory_vault_storage import atomic_write
from memory_vault_trust import Identity, TrustStore
import memory_vault_network_recovery as recovery
from tests.test_network_worker import fixture as worker_fixture, Transport


class RecoveryTransport(Transport):
    """Match the HTTP client's documented string/object error handling."""
    def request(self, base, method, path, value=None):
        self.calls.append((base, method, path, None))
        if base in self.offline:
            raise MemoryError("network_unavailable", retryable=True)
        response = self.clients[base].request(method, path,
            content=None if value is None else canonical_bytes(value), headers={"content-type": "application/json"})
        result = response.json()
        if response.status_code != 200:
            error = result["error"]
            raise MemoryError(error if isinstance(error, str) else error["code"],
                              retryable=False if isinstance(error, str) else error.get("retryable", False))
        return result


@contextmanager
def fixture():
    with worker_fixture() as (sender, recipient, original):
        transport = RecoveryTransport(original.clients)
        sender.transport = recipient.transport = transport
        yield sender, recipient, transport


def rows(client):
    with client.db() as db:
        return {table: [tuple(row) for row in db.execute("SELECT rowid,* FROM " + table + " ORDER BY rowid")]
                for table in recovery.SQL}


def records(client):
    with closing(client.client_config.vault()._connect()) as db:
        return [tuple(row) for row in db.execute("SELECT memory_id,record_json FROM memories ORDER BY memory_id")]


def archive(sender):
    root = sender.config_path.parent.parent
    issuer_public = root / "independent-issuer.json"
    if not issuer_public.exists():
        atomic_write(issuer_public, canonical_bytes(Identity.load(root / "issuer.json").public_descriptor()), replace=False)
    package, secret = root / "encrypted-endpoint", root / "separate-recovery-secret.json"
    result = recovery.backup_endpoint(network_config=sender.config_path, output=package, secret_file=secret)
    arguments = dict(package=package, secret_file=secret, confirm_network_id=sender.network_id,
                     issuer_public=issuer_public, authority_url=sender.authority_url, relays=sender.relays,
                     memory_trust=sender.client_config.trust_path)
    return result, arguments


class NetworkRecoveryTests(unittest.TestCase):
    def test_full_offline_snapshot_restores_same_ids_frozen_bytes_caches_and_two_node_delivery(self):
        with fixture() as (sender, recipient, transport):
            sender.send("req_recovery_sent_001", [recipient.identity.key_id], "Synthetic acknowledged memory")
            recipient.receive()
            sender.receive()
            recipient.send("req_recovery_reply_001", [sender.identity.key_id], "Synthetic cached incoming memory")
            sender.receive()
            transport.offline.add(sender.relays[1])
            sender.send("req_recovery_frozen_001", [recipient.identity.key_id], "Synthetic partially uploaded memory")
            transport.offline.update(sender.relays)
            sender.send("req_recovery_offline_001", [recipient.identity.key_id], "Synthetic never uploaded memory")
            before_rows, before_records = rows(sender), records(sender)
            self.assertTrue(any(row[5] is None for row in before_rows["outbox"]))
            self.assertEqual(len(before_rows["inbox"]), 1)
            self.assertEqual(len(before_rows["acknowledgements"]), 1)
            calls = len(transport.calls)
            result, args = archive(sender)
            self.assertEqual(result["transport_rows"]["outbox"], 3)
            self.assertEqual(len(transport.calls), calls)
            for path in args["package"].iterdir():
                self.assertNotIn(b"Synthetic never uploaded memory", path.read_bytes())
            destination = sender.config_path.parent.parent / "restored-full"
            restored = recovery.restore_endpoint(directory=destination, **args)
            self.assertEqual(len(transport.calls), calls)
            self.assertTrue(restored["requires_fresh_issuer_status"])
            self.assertFalse(restored["automatic_sending_enabled"])
            with NetworkClient(Path(restored["network_config"]), transport=transport) as recovered:
                self.assertEqual(recovered.identity.public_descriptor(), sender.identity.public_descriptor())
                self.assertEqual(recovered.encryption.private_document(), sender.encryption.private_document())
                self.assertFalse(recovered.client_config.capture_visible_turns)
                self.assertIsNone(recovered.client_config.sync_config_path)
                self.assertEqual(records(recovered), before_records)
                after_rows = rows(recovered)
                for table in recovery.SQL:
                    if table != "state":
                        self.assertEqual(after_rows[table], before_rows[table], table)
                self.assertEqual([r for r in after_rows["state"] if r[1] != "configuration_binding"],
                                 [r for r in before_rows["state"] if r[1] != "configuration_binding"])
                transport.offline.clear()
                pumped = recovered.pump(maximum_messages=4, receive_limit=0)
                self.assertEqual(pumped["remaining_outbox"], 0, pumped)
                self.assertTrue(any(base == sender.authority_url for base, *_ in transport.calls[calls:]))
                after = rows(recovered)
                for old, new in zip(before_rows["outbox"], after["outbox"]):
                    self.assertEqual(old[:5], new[:5])
                    if old[5] is not None:
                        self.assertEqual(old[5], new[5], "frozen envelope bytes changed")
                for relay in recovered.relays:
                    with transport.clients[relay].app.state.relay._transaction() as db:
                        self.assertEqual(db.execute("SELECT COUNT(*) FROM messages").fetchone()[0], 4)
                incoming = recipient.receive()
                self.assertEqual(len(incoming["messages"]), 2, incoming)
                recovered.receive()
                self.assertEqual(len(rows(recovered)["acknowledgements"]), 3)
                self.assertEqual(records(recovered), before_records)

    def test_revoked_identity_and_unavailable_authority_cannot_send_restored_outbox(self):
        with fixture() as (sender, recipient, transport):
            sender.discover()
            transport.offline.update(sender.relays)
            sender.send("req_recovery_revoke_001", [recipient.identity.key_id], "Synthetic pending revoked memory")
            _, args = archive(sender)
            root = sender.config_path.parent.parent
            restored = recovery.restore_endpoint(directory=root / "restored-revoked", **args)
            with NetworkClient(Path(restored["network_config"]), transport=transport) as recovered:
                transport.offline.clear()
                transport.offline.add(sender.authority_url)
                start = len(transport.calls)
                unavailable = recovered.pump(receive_limit=0)
                self.assertTrue(unavailable["retryable"], unavailable)
                self.assertEqual(unavailable["remaining_outbox"], 1)
                self.assertFalse(any(path == "/v1/messages" for _, _, path, _ in transport.calls[start:]))
                transport.offline.clear()
                prior = strict_json_loads((root / "roster.json").read_bytes())
                previous_hash = document_sha256(prior)
                members = prior["payload"]["members"]
                for member in members:
                    if member["signing_key"]["key_id"] == sender.identity.key_id:
                        member["status"] = "revoked"
                now = int(time.time())
                revoked = issue_roster(Identity.load(root / "issuer.json"), network_id=sender.network_id,
                    version=2, previous_sha256=previous_hash, members=members, issued_at=now, expires_at=now + 300)
                atomic_write(root / "roster.json", canonical_bytes(revoked), replace=True)
                start = len(transport.calls)
                denied = recovered.pump(receive_limit=0)
                self.assertEqual(denied["remaining_outbox"], 1, denied)
                self.assertFalse(denied["retryable"], denied)
                # The live authority rejects the revoked request signer
                # before a fresh member status can be returned.
                self.assertEqual({error["code"] for item in denied["outbound"] for error in item["errors"]}, {"unknown_key"})
                self.assertFalse(any(path == "/v1/messages" for _, _, path, _ in transport.calls[start:]))
                self.assertEqual(len(records(recovered)), 1)
                recalled = recovered.client_config.vault().handle({"op": "recall", "query": "Synthetic pending revoked memory"})
                self.assertTrue(recalled["ok"], recalled)

    def test_both_databases_hold_actual_cross_process_write_reservations(self):
        with fixture() as (sender, recipient, transport):
            transport.offline.update(sender.relays)
            sender.send("req_recovery_locks_001", [recipient.identity.key_id], "Synthetic lock check")
            original = recovery.vault_backup.backup_database
            observed = []

            def inspect_locks(*args, **kwargs):
                script = """import sqlite3,sys
for path in sys.argv[1:]:
    db=sqlite3.connect(path,timeout=0)
    try:
        db.execute('BEGIN IMMEDIATE')
    except sqlite3.OperationalError:
        print('locked')
    else:
        print('UNLOCKED');db.rollback()
    finally:
        db.close()
"""
                result = subprocess.run([sys.executable, "-c", script, str(sender.directory / "network.sqlite3"),
                                         str(sender.client_config.vault_path)], capture_output=True, text=True, timeout=5, check=True)
                observed.extend(result.stdout.splitlines())
                return original(*args, **kwargs)

            with patch.object(recovery.vault_backup, "backup_database", side_effect=inspect_locks):
                result, _ = archive(sender)
            self.assertEqual(observed, ["locked", "locked"])
            self.assertFalse(result["all_host_files_globally_quiesced"])
            self.assertEqual(len(rows(sender)["outbox"]), 1)

    def test_tampering_file_set_budget_and_unknown_source_schema_fail_closed(self):
        with fixture() as (sender, recipient, transport):
            transport.offline.update(sender.relays)
            sender.send("req_recovery_tamper_001", [recipient.identity.key_id], "Synthetic tamper check")
            _, args = archive(sender)
            root = sender.config_path.parent.parent
            part = args["package"] / "000000.bin"
            original = part.read_bytes()
            atomic_write(part, original[:-1] + bytes([original[-1] ^ 1]), replace=True)
            with self.assertRaises(MemoryError) as invalid:
                recovery.restore_endpoint(directory=root / "tampered", **args)
            self.assertEqual(invalid.exception.code, "endpoint_backup_decryption_failed")
            self.assertFalse((root / "tampered").exists())
            atomic_write(part, original, replace=True)
            atomic_write(args["package"] / "extra", b"unexpected", replace=False)
            with self.assertRaises(MemoryError) as invalid:
                recovery.restore_endpoint(directory=root / "extra-file", **args)
            self.assertEqual(invalid.exception.code, "endpoint_backup_file_set_mismatch")
            with patch.object(recovery, "MAX_TOTAL_BYTES", 1):
                with self.assertRaises(MemoryError) as invalid:
                    recovery.backup_endpoint(network_config=sender.config_path, output=root / "over-limit", secret_file=root / "over-limit-secret")
            self.assertEqual(invalid.exception.code, "endpoint_backup_size_limit")
            self.assertFalse((root / "over-limit").exists())
            with self.assertRaises(MemoryError) as invalid:
                recovery._check(time.monotonic() - 1)
            self.assertEqual(invalid.exception.code, "endpoint_backup_time_budget")
            self.assertTrue(invalid.exception.retryable)
            with sender.db() as db:
                db.execute("CREATE TRIGGER unknown_code AFTER INSERT ON state BEGIN SELECT 1; END")
            with self.assertRaises(MemoryError) as invalid:
                recovery.backup_endpoint(network_config=sender.config_path, output=root / "schema-invalid", secret_file=root / "schema-secret")
            self.assertEqual(invalid.exception.code, "endpoint_backup_transport_schema")
            self.assertFalse((root / "schema-invalid").exists())

    def test_authenticated_transport_data_cannot_inject_sql_and_recovery_paths_are_new_only(self):
        with fixture() as (sender, recipient, transport):
            transport.offline.update(sender.relays)
            sender.send("req_recovery_closed_001", [recipient.identity.key_id], "Synthetic closed schema")
            _, args = archive(sender)
            root = sender.config_path.parent.parent
            before = records(sender)
            with tempfile.TemporaryDirectory(dir=root) as temporary:
                stage = Path(temporary)
                recovery._unseal(args["package"], args["secret_file"], stage, sender.network_id, time.monotonic() + 30)
                source = stage / "transport.ndjson"
                lines = source.read_bytes().splitlines()
                row = strict_json_loads(lines[1])
                row["table"] = "state); CREATE TABLE injected(value);--"
                lines[1] = canonical_bytes(row)
                atomic_write(source, b"\n".join(lines) + b"\n", replace=True)
                malicious_package, malicious_secret = root / "invalid-data", root / "invalid-data-secret"
                recovery._seal(stage, malicious_package, malicious_secret, sender.network_id, time.monotonic() + 30)
            altered = {**args, "package": malicious_package, "secret_file": malicious_secret}
            destination = root / "closed-schema-restore"
            with self.assertRaises(MemoryError) as invalid:
                recovery.restore_endpoint(directory=destination, **altered)
            self.assertEqual(invalid.exception.code, "endpoint_backup_invalid_transport_row")
            with NetworkClient(destination / "endpoint" / "network.json", transport=transport) as failed:
                with failed.db() as db:
                    self.assertIsNone(db.execute("SELECT name FROM sqlite_master WHERE name='injected'").fetchone())
                    self.assertEqual(db.execute("SELECT COUNT(*) FROM outbox").fetchone()[0], 0)
                self.assertFalse(failed.client_config.capture_visible_turns)
            with self.assertRaises(MemoryError) as invalid:
                recovery.restore_endpoint(directory=sender.config_path.parent, **args)
            self.assertEqual(invalid.exception.code, "endpoint_backup_new_path_required")
            self.assertEqual(records(sender), before)

    def test_shared_client_and_independent_cli_roundtrip_remain_inactive(self):
        with fixture() as (sender, recipient, transport):
            transport.offline.update(sender.relays)
            sender.send("req_recovery_cli_001", [recipient.identity.key_id], "Synthetic independent CLI")
            root = sender.config_path.parent.parent
            issuer_public = root / "cli-issuer-public.json"
            atomic_write(issuer_public, canonical_bytes(Identity.load(root / "issuer.json").public_descriptor()), replace=False)
            command = [sys.executable, "-m", "memory_vault_network_recovery"]
            client_command = [sys.executable, "-m", "memory_vault_client", "--config", str(sender.client_config.path), "network-recovery"]
            mismatch = subprocess.run(client_command + ["backup", "--network-config", str(recipient.config_path),
                "--output", str(root / "wrong-client-package"), "--secret-file", str(root / "wrong-client-secret")],
                cwd=Path(__file__).resolve().parents[1], capture_output=True, timeout=20)
            self.assertEqual(mismatch.returncode, 1)
            self.assertEqual(strict_json_loads(mismatch.stdout)["error"]["code"], "network_client_config_mismatch")
            self.assertFalse((root / "wrong-client-package").exists())
            self.assertFalse((root / "wrong-client-secret").exists())
            backup = subprocess.run(client_command + ["backup", "--network-config", str(sender.config_path),
                "--output", str(root / "cli-package"), "--secret-file", str(root / "cli-secret")],
                cwd=Path(__file__).resolve().parents[1], capture_output=True, timeout=20, check=True)
            self.assertTrue(strict_json_loads(backup.stdout)["ok"])
            restore = subprocess.run(command + ["restore", "--package", str(root / "cli-package"),
                "--secret-file", str(root / "cli-secret"), "--directory", str(root / "cli-restored"),
                "--confirm-network-id", sender.network_id, "--issuer-public", str(issuer_public),
                "--authority-url", sender.authority_url, "--relay", sender.relays[0], "--relay", sender.relays[1]],
                cwd=Path(__file__).resolve().parents[1], capture_output=True, timeout=20, check=True)
            restored = strict_json_loads(restore.stdout)["result"]
            self.assertFalse(restored["network_accessed"])
            self.assertFalse(restored["automatic_sending_enabled"])
            self.assertEqual(restored["memory"]["admissions"], {"verified": 0, "accepted_unsigned": 0, "quarantined": 1})
            with NetworkClient(Path(restored["network_config"]), transport=transport) as recovered:
                self.assertEqual(records(recovered), records(sender))
                self.assertEqual(len(rows(recovered)["outbox"]), 1)
                self.assertEqual(set(TrustStore(recovered.client_config.trust_path)._read()["keys"]), {sender.identity.key_id})
                written = recovered.client_config.vault(writing=True).handle({"op": "remember", "kind": "observation",
                    "text": "Synthetic restored local write", "request_id": "req_recovery_local_write"})
                self.assertTrue(written["ok"], written)

    def test_current_memory_trust_snapshot_controls_restored_and_future_admission(self):
        with fixture() as (sender, recipient, transport):
            recipient.send("req_recovery_trust_old", [sender.identity.key_id], "Synthetic historical remote author")
            sender.receive()
            _, args = archive(sender)
            root = sender.config_path.parent.parent
            current_path = root / "current-memory-trust.json"
            atomic_write(current_path, sender.client_config.trust_path.read_bytes(), replace=False)
            current = TrustStore(current_path)
            current.revoke(recipient.identity.key_id)
            selected_bytes = current_path.read_bytes()
            original = recovery.vault_backup.restore_database

            def change_original_after_snapshot(*values, **kwargs):
                # The operator's file changing after selection must not make
                # initial admission and future runtime use different policies.
                result = original(*values, **kwargs)
                atomic_write(current_path, sender.client_config.trust_path.read_bytes(), replace=True)
                return result

            with patch.object(recovery.vault_backup, "restore_database", side_effect=change_original_after_snapshot):
                restored = recovery.restore_endpoint(directory=root / "restored-current-trust", **{**args, "memory_trust": current_path})
            self.assertEqual(restored["memory"]["admissions"]["quarantined"], 1)
            with NetworkClient(Path(restored["network_config"]), transport=transport) as recovered:
                self.assertEqual(recovered.client_config.trust_path.read_bytes(), selected_bytes)
                self.assertEqual(TrustStore(recovered.client_config.trust_path)._read()["keys"][recipient.identity.key_id]["state"], "revoked")
                recipient.send("req_recovery_trust_new", [sender.identity.key_id], "Synthetic later remote author")
                received = recovered.receive()
                self.assertEqual(received["messages"], [], received)
                self.assertEqual({error["code"] for error in received["errors"]}, {"key_revoked"})
                with closing(recovered.client_config.vault()._connect()) as db:
                    admissions = db.execute("SELECT state FROM record_admissions").fetchall()
                    self.assertEqual([row[0] for row in admissions], ["quarantined"])
                    self.assertEqual(db.execute("SELECT COUNT(*) FROM memories WHERE text='Synthetic later remote author'").fetchone()[0], 0)

    def test_current_registry_does_not_silently_reenroll_revoked_self(self):
        with fixture() as (sender, recipient, transport):
            transport.offline.update(sender.relays)
            sender.send("req_recovery_self_revoked", [recipient.identity.key_id], "Synthetic self trust revocation")
            _, args = archive(sender)
            root = sender.config_path.parent.parent
            current_path = root / "self-revoked-trust.json"
            atomic_write(current_path, sender.client_config.trust_path.read_bytes(), replace=False)
            TrustStore(current_path).revoke(sender.identity.key_id)
            restored = recovery.restore_endpoint(directory=root / "restored-self-revoked", **{**args, "memory_trust": current_path})
            with NetworkClient(Path(restored["network_config"]), transport=transport) as recovered:
                self.assertEqual(TrustStore(recovered.client_config.trust_path)._read()["keys"][sender.identity.key_id]["state"], "revoked")
                self.assertEqual(records(recovered), records(sender))


if __name__ == "__main__":
    unittest.main()
