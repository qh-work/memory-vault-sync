"""Synthetic native-Drive queue compatibility; no account or real provider.

Only Drive HTTP is replaced. Cryptography, private local storage, signed queue
publication/admission, cursors and retry logic are real. All keys and memory
records are generated in a temporary directory when explicitly executed.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from memory_vault import MemoryError, Vault, canonical_bytes
import memory_vault_drive as drive
from memory_vault_network_crypto import EncryptionIdentity
import memory_vault_remote as remote
import memory_vault_recovery as recovery
import memory_vault_storage as storage
import memory_vault_sync as sync
from memory_vault_trust import Identity, TrustStore

REAL_DRIVE_CLIENT = drive.DriveClient


class SyntheticDrive:
    """In-memory Drive object bytes; never uses credentials or an HTTP client."""

    def __init__(self):
        self.objects = {"synthetic-root": {"id": "synthetic-root", "name": "synthetic-root",
            "mimeType": drive.FOLDER_MIME, "parents": [], "version": "1"}}
        self.data = {}
        self.uploads = []
        self.interrupt_next_blob = False

    def client(self, config, *, deadline, active_check):
        cloud = self

        class Client:
            def metadata(self, identifier):
                active_check()
                return dict(cloud.objects[identifier])

            def list_children(self, parent, *, name=None, page_token=None):
                active_check()
                return {"files": [dict(item) for item in cloud.objects.values()
                    if item["parents"] == [parent] and (name is None or item["name"] == name)], "next_page_token": None}

            def create_folder(self, parent, name):
                active_check()
                identifier = "synthetic-" + str(len(cloud.objects))
                cloud.objects[identifier] = {"id": identifier, "name": name, "mimeType": drive.FOLDER_MIME,
                                             "parents": [parent], "version": "1"}
                return dict(cloud.objects[identifier])

            def upload_bytes(self, parent, name, data):
                active_check()
                identifier = "synthetic-" + str(len(cloud.objects))
                cloud.objects[identifier] = {"id": identifier, "name": name, "mimeType": "application/octet-stream",
                                             "parents": [parent], "version": "1", "size": str(len(data))}
                cloud.data[identifier] = data
                cloud.uploads.append((identifier, name))
                if cloud.interrupt_next_blob and name.endswith(".bin"):
                    cloud.interrupt_next_blob = False
                    raise MemoryError("drive_write_outcome_unknown", retryable=True)
                return dict(cloud.objects[identifier])

            def read_range(self, identifier, offset, count):
                active_check()
                return cloud.data[identifier][offset:offset + count]

        return Client()


class NativeCloudCompatibilityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="vault-native-cloud-synthetic-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.control = self.root / "control"
        storage.private_directory(self.control)
        self.sender_key, self.receiver_key = EncryptionIdentity.generate(), EncryptionIdentity.generate()
        self.key_path = self.control / "sender-encryption.json"
        self.receiver_key_path = self.control / "receiver-encryption.json"
        self.sender_key.save(self.key_path)
        self.receiver_key.save(self.receiver_key_path)
        self.drive_path = self.control / "drive.json"
        storage.atomic_write(self.drive_path, canonical_bytes({"schema_version": drive.CONFIG_SCHEMA,
            "root_folder_id": "synthetic-root", "oauth_client_id": "synthetic-oauth-client",
            "credential_ref": {"kind": "macos-generic", "service": "synthetic-service", "account": "synthetic-account"}}), replace=False)
        self.spec = {"kind": "native-drive", "config_file": str(self.drive_path), "root_folder_id": "synthetic-root",
            "encryption_key_path": str(self.key_path), "recipient_keys": [self.sender_key.public_descriptor(), self.receiver_key.public_descriptor()],
            "peers": []}
        self.cloud = SyntheticDrive()
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(drive, "DriveClient", side_effect=self.cloud.client).start()
        mock.patch.object(drive, "config_password", side_effect=AssertionError("Synthetic fixture accessed a credential")).start()

    def backend(self, *, receiver=False, maximum_files=16):
        spec = {**self.spec, "encryption_key_path": str(self.receiver_key_path)} if receiver else self.spec
        return remote.NativeDriveBackend(spec, work_directory=self.root / ("receive-work" if receiver else "send-work"),
            budget=remote.Budget(seconds=60, maximum_bytes=24 * 1024 * 1024, maximum_files=maximum_files), active_check=lambda: None)

    def test_signed_queue_interrupted_upload_then_other_recipient_receive(self):
        identity_path = self.control / "signing.json"
        identity = Identity.generate(identity_path)
        trust_path = self.control / "trust.json"
        trust = TrustStore(trust_path)
        trust.add(identity.public_descriptor(), "synthetic approved sender")
        vault_path = self.root / "sender.sqlite3"
        vault = Vault(vault_path, signer=identity.sign_record, trust_check=trust.require_trusted)
        text = "Synthetic cloud backup statement: the copper fox remembers blue lanterns."
        remembered = vault.handle({"op": "remember", "kind": "fact", "text": text})
        self.assertTrue(remembered["ok"])
        memory_id = remembered["result"]["memory_id"]
        original = canonical_bytes(vault.handle({"op": "get", "memory_id": memory_id})["result"]["record"])
        store = vault.handle({"op": "status"})["result"]["store_id"]

        def configure(label, *, receiving=False):
            selected = self.control / (label + "-sync.json")
            backend = {**self.spec}
            if receiving:
                backend.update(encryption_key_path=str(self.receiver_key_path), peers=[{"key_id": identity.key_id, "store_id": store}])
            document = {"schema_version": sync.CONFIG_SCHEMA, "vault": str(self.root / (label + ".sqlite3")),
                "identity": str(self.control / "unused-signing.json") if receiving else str(identity_path),
                "trust_store": str(trust_path), "state_directory": str(self.root / (label + "-state")),
                "enabled": True, "automatic": False, "background": False, "backend": backend,
                "limits": {**sync.DEFAULT_LIMITS, "maximum_batches": 1}}
            sync._write_control(selected, document, replace=False)
            return selected

        sender, receiver = configure("sender"), configure("receiver", receiving=True)
        self.cloud.interrupt_next_blob = True
        interrupted = sync.flush(sender)
        self.assertEqual(interrupted["last_error"], "drive_write_outcome_unknown")
        self.assertEqual(interrupted["counts"]["uploaded_batches"], 0)
        before = dict(self.cloud.data)
        self.assertEqual(len(before), 1)
        stage = list((self.root / "sender-state" / "native-drive").glob("*.json"))
        self.assertEqual(len(stage), 1)
        self.assertNotIn(text.encode(), stage[0].read_bytes())
        # The existing offline sync-backup inventory must accept, but never
        # archive, this private retry cache. No network state is selected.
        sources, _, _ = recovery._inventory(SimpleNamespace(path=sender, vault_path=vault_path,
            state_path=self.root / "uninitialized-client-state"), ["sync"], sync.SyncConfig.load(sender), time.monotonic() + 5)
        self.assertFalse(any(stage[0].parent in entry.path.parents for entry in sources))
        resumed = sync.flush(sender)
        self.assertIsNone(resumed["last_error"], resumed)
        self.assertEqual(resumed["counts"]["uploaded_batches"], 1)
        for identifier, raw in before.items():
            self.assertEqual(self.cloud.data[identifier], raw)
        self.assertEqual(len(self.cloud.uploads), 2)  # One exact blob plus the final commit.
        self.assertEqual(list((self.root / "sender-state" / "native-drive").glob("*.json")), [])
        for raw in self.cloud.data.values():
            self.assertNotIn(text.encode(), raw)
            self.assertNotIn(memory_id.encode(), raw)
        with mock.patch.object(Identity, "load", side_effect=AssertionError("Receive loaded the signing private key")):
            received = sync.receive(receiver)
        self.assertIsNone(received["last_error"], received)
        self.assertEqual(received["counts"]["records_added"], 1)
        recovered = Vault(self.root / "receiver.sqlite3").handle({"op": "get", "memory_id": memory_id})
        self.assertEqual(canonical_bytes(recovered["result"]["record"]), original)
        retry = sync.receive(receiver)
        self.assertIsNone(retry["last_error"], retry)
        self.assertEqual(retry["counts"]["records_added"], 0)
        self.assertEqual(len(self.cloud.uploads), 2)

    def test_maximal_binary_bytes_split_and_tampering_fails(self):
        raw = (b"Synthetic binary backup\x00\xff" * 200000)[:4 * 1024 * 1024]
        self.assertEqual(len(raw), 4 * 1024 * 1024)
        source = self.control / "binary.bin"
        storage.atomic_write(source, raw, replace=False)
        key, store = "ed25519_" + "a" * 64, "store_" + "b" * 32
        name = f"{0:020d}-{1:020d}-" + hashlib.sha256(raw).hexdigest() + ".json"
        sender = self.backend(maximum_files=8)
        sender.upload(source, key_id=key, store_id=store, after=0, name=name, expected=raw)
        self.assertEqual(len(self.cloud.uploads), 3)
        self.assertEqual(sender.budget.files, 8)
        receiver = self.backend(receiver=True)
        self.assertEqual(receiver.candidates(key, store, 0), [(name, len(raw))])
        self.assertEqual(receiver.download(key, store, 0, name, len(raw)), raw)
        identifier = next(identifier for identifier, label in self.cloud.uploads if label.endswith(".bin"))
        saved = self.cloud.data[identifier]
        self.cloud.data[identifier] = bytes([saved[0] ^ 1]) + saved[1:]
        with self.assertRaises(MemoryError) as caught:
            self.backend(receiver=True).download(key, store, 0, name, len(raw))
        self.assertEqual(caught.exception.code, "native_drive_ciphertext_mismatch")
        self.assertEqual(len(self.cloud.uploads), 3)

    def test_missing_encryption_and_root_change_fail_closed_rclone_config_is_preserved(self):
        with mock.patch.object(drive, "DriveClient", side_effect=AssertionError("Unconfigured encryption touched Drive")):
            for change, code in (({"recipient_keys": []}, "native_drive_encryption_required"),
                                 ({"encryption_key_path": str(self.control / "absent-key.json")}, "network_encryption_identity_missing"),
                                 ({"recipient_keys": [self.receiver_key.public_descriptor()]}, "native_drive_self_recipient_required"),
                                 ({"root_folder_id": "different-synthetic-root"}, "sync_configuration_changed")):
                with self.subTest(code=code), self.assertRaises(MemoryError) as caught:
                    remote.NativeDriveBackend({**self.spec, **change}, work_directory=self.root / "uncreated-work",
                        budget=remote.Budget(seconds=60, maximum_bytes=24 * 1024 * 1024, maximum_files=16), active_check=lambda: None)
                self.assertEqual(caught.exception.code, code)
        self.assertFalse((self.root / "uncreated-work").exists())
        with mock.patch.object(drive, "DriveClient", REAL_DRIVE_CLIENT), \
                mock.patch.object(drive, "config_password", side_effect=MemoryError("synthetic_credential_locked")), \
                mock.patch.object(drive.urllib.request.OpenerDirector, "open", side_effect=AssertionError("Locked credential reached HTTP")):
            with self.assertRaises(MemoryError) as locked:
                self.backend().candidates("ed25519_" + "a" * 64, "store_" + "b" * 32, 0)
            self.assertEqual(locked.exception.code, "drive_credential_unavailable")
        document = {"schema_version": sync.CONFIG_SCHEMA, "vault": str(self.root / "vault.sqlite3"),
            "identity": str(self.control / "identity.json"), "trust_store": str(self.control / "trust.json"),
            "state_directory": str(self.root / "state"), "enabled": True, "automatic": False, "background": False,
            "backend": self.spec, "limits": dict(sync.DEFAULT_LIMITS)}
        path = self.control / "sync.json"
        old = sync.SyncConfig.from_document(path, document)
        changed = sync.SyncConfig.from_document(path, {**document, "backend": {**self.spec, "root_folder_id": "different-synthetic-root"}})
        self.assertNotEqual(old.binding, changed.binding)
        reference = {"kind": "macos-generic", "service": "synthetic-crypt-service", "account": "synthetic-crypt-account"}
        crypt = {"kind": "rclone", "executable": str(self.root / "inert-rclone"), "executable_sha256": "c" * 64,
            "config_file": str(self.control / "encrypted-rclone.conf"), "remote": "syntheticcrypt:backup", "peers": [],
            "config_password_ref": reference}
        configuration = sync.SyncConfig.from_document(path, {**document, "backend": crypt})
        self.assertEqual(configuration.backend, crypt)
        destination = {"kind": "rclone", "config_file": crypt["config_file"], "remote": crypt["remote"]}
        expected_binding = hashlib.sha256(canonical_bytes({key: str(getattr(configuration, key)) for key in
            ("vault", "identity", "trust_store", "state_directory")} | {"backend": destination})).hexdigest()
        self.assertEqual(configuration.binding, expected_binding)


if __name__ == "__main__":
    unittest.main()
