"""One small signed recovery workflow; execution evidence is recorded separately.

All state and the one signing identity are fresh TemporaryDirectory fixtures.
The two-fragment wire fixture is deliberately small: it does not exercise the
production 4 MiB splitter, a provider, near-limit throughput or a real crash.
Only a pre-admission cancellation is injected. Signatures, fragment staging,
operator dispatch, snapshot, restore and memory admission remain real.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import memory_vault_client as client
import memory_vault_manage as manage
import memory_vault_storage as storage
from memory_vault import MemoryError, Vault, build_record, canonical_bytes, sha256, strict_json_loads
from memory_vault_sync import CONFIG_SCHEMA as SYNC_SCHEMA, DEFAULT_LIMITS
from memory_vault_transfer import DirectoryTransfer, GROUP_SCHEMA, INCREMENTAL_DELTA_SCHEMA, _fragment_name
from memory_vault_trust import Identity, TrustStore


@unittest.skipUnless(os.name == "posix" and importlib.util.find_spec("cryptography") is not None,
                     "signed synthetic recovery requires optional cryptography and POSIX")
class SignedRecoveryWorkflowTests(unittest.TestCase):
    def test_staged_signed_group_survives_inert_restore_and_current_trust_import(self) -> None:
        with tempfile.TemporaryDirectory(prefix="memory-v025-signed-recovery-") as temporary:
            root = Path(temporary).resolve()
            control = root / "control"
            control.mkdir(mode=0o700)
            identity_path, trust_path = control / "identity.json", control / "trust.json"
            identity = Identity.generate(identity_path)
            trust = TrustStore(trust_path)
            trust.add(identity.public_descriptor(), "explicit synthetic recovery publisher")
            vault_path, state = root / "source.sqlite3", root / "sync-state"
            # Direct receiver calls do not run sync.run's private-state setup.
            state.mkdir(mode=0o700)
            config_path, sync_path = control / "client.json", control / "sync.json"

            def write_json(path: Path, value: dict) -> None:
                storage.atomic_write(path, canonical_bytes(value) + b"\n", replace=False)

            def rows(path: Path, query: str) -> list[tuple]:
                with contextlib.closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as connection:
                    return list(connection.execute(query))

            def tree_hashes(path: Path) -> dict[str, str]:
                return {str(item.relative_to(path)): sha256(item.read_bytes())
                        for item in path.rglob("*") if item.is_file()}

            def operator(*arguments, error: str | None = None) -> dict:
                # The real protocol writer uses stdout.buffer, not a mocked
                # response callback or a text-only StringIO stand-in.
                with io.BytesIO() as output, io.TextIOWrapper(output, encoding="utf-8") as stream, \
                        contextlib.redirect_stdout(stream):
                    code = manage.main([str(argument) for argument in arguments])
                    stream.flush()
                    encoded = output.getvalue()
                response = strict_json_loads(encoded)
                self.assertEqual(code, 0 if error is None else 1, response)
                self.assertFalse(response["authority"]["execution_eligible"])
                if error is not None:
                    self.assertFalse(response["ok"], response)
                    self.assertEqual(response["error"]["code"], error)
                    return dict(response)
                self.assertTrue(response["ok"], response)
                return dict(response["result"])

            write_json(config_path, {"schema_version": client.CONFIG_SCHEMA, "vault_path": str(vault_path),
                "capture_visible_turns": False, "identity_path": str(identity_path), "trust_path": str(trust_path),
                "sync_config_path": str(sync_path)})
            write_json(sync_path, {"schema_version": SYNC_SCHEMA, "vault": str(vault_path),
                "identity": str(identity_path), "trust_store": str(trust_path), "state_directory": str(state),
                "enabled": True, "automatic": False, "background": False,
                "backend": {"kind": "directory", "exchange": str(root / "external-exchange")},
                "limits": dict(DEFAULT_LIMITS)})

            # An actual received seed establishes an old cursor/receipt. The
            # later group depends on this signed record but not on its receipt
            # after explicit restore has created an independent Vault identity.
            seed = build_record(kind="fact", text="Synthetic already received seed.", created_at="2026-01-01T00:00:00Z")
            source_store = "store_" + "e" * 32
            seed_payload = {"schema_version": INCREMENTAL_DELTA_SCHEMA, "source_store_id": source_store,
                "sender_key_id": identity.key_id, "after": 0, "cursor": 1, "records": [seed],
                "attestations": {seed["memory_id"]: identity.sign_record(seed)}, "blocked": [],
                "previous_batch_sha256": None, "publication_review": None, "group": None, "dependency_mode": "closure"}
            seed_digest = sha256(canonical_bytes(seed_payload))
            seed_capsule = {"payload": seed_payload, "proof": identity.sign_message(seed_payload)}
            base = build_record(kind="event", text="Synthetic staged group continuation.",
                relations=[{"type": "continues", "target": seed["memory_id"]}], created_at="2026-01-02T00:00:00Z")
            child = build_record(kind="decision", text="Synthetic staged dependent decision.",
                relations=[{"type": "derived_from", "target": base["memory_id"]}], created_at="2026-01-03T00:00:00Z")
            # A forward reference crosses the fragment boundary; no fragment
            # alone is the complete group. Every record is actually signed.
            records = [child, base]
            fragment_data = [canonical_bytes({"record": item, "attestation": identity.sign_record(item)}) + b"\n"
                             for item in records]
            fragments = [{"index": index, "sha256": sha256(data), "bytes": len(data), "records": 1}
                         for index, data in enumerate(fragment_data)]
            group = {"schema_version": GROUP_SCHEMA, "record_count": len(records),
                "record_bytes": sum(len(canonical_bytes(item)) for item in records),
                "encoded_bytes": sum(map(len, fragment_data)), "records_sha256": sha256(b"".join(fragment_data)),
                "fragments": fragments}
            group["group_id"] = sha256(canonical_bytes(group))
            payload = {**seed_payload, "after": 1, "cursor": 3, "records": [], "attestations": {},
                "previous_batch_sha256": seed_digest, "group": group, "dependency_mode": "prior_stream"}
            digest = sha256(canonical_bytes(payload))
            capsule = {"payload": payload, "proof": identity.sign_message(payload)}
            endpoint = DirectoryTransfer(vault=vault_path, exchange=root / "external-exchange",
                                         state_directory=state / "transfer", trust_store=trust_path)
            incoming = state / "transfer" / "incoming-groups" / group["group_id"]
            loaded: list[int] = []
            cancelled: list[bool] = []

            def load_fragment(selected: dict, fragment: dict) -> bytes:
                self.assertEqual(selected["group_id"], group["group_id"])
                loaded.append(fragment["index"])
                return fragment_data[fragment["index"]]

            def cancel_after_staging() -> None:
                if len(loaded) == len(fragments):
                    self.assertTrue(all((incoming / _fragment_name(fragment)).is_file() for fragment in fragments))
                    cancelled.append(True)
                    raise MemoryError("sync_cancelled")

            # Negative guards do not furnish fake signature/admission results.
            with mock.patch.object(Identity, "load", side_effect=AssertionError("recovery loaded a private key")), \
                    mock.patch.object(client, "notify_sync", side_effect=AssertionError("recovery started sync")):
                seeded = endpoint.receive_capsule(seed_capsule, sender_key_id=identity.key_id,
                                                  source_store_id=source_store, after=0)
                self.assertEqual(seeded["records_added"], 1)
                original_store = rows(vault_path, "SELECT value FROM metadata WHERE key='store_id'")[0][0]
                old_state = endpoint.state_path.read_bytes()
                with self.assertRaises(MemoryError) as caught:
                    endpoint.receive_capsule(capsule, sender_key_id=identity.key_id, source_store_id=source_store,
                        after=1, fragment_loader=load_fragment, maximum_fragments=2, active_check=cancel_after_staging)
                self.assertEqual(caught.exception.code, "sync_cancelled")
                self.assertEqual(loaded, [0, 1])
                self.assertEqual(cancelled, [True])
                self.assertEqual(rows(vault_path, "SELECT memory_id FROM memories"), [(seed["memory_id"],)])
                self.assertEqual(rows(vault_path, "SELECT transfer_id FROM transfer_receipts"), [("xfer_" + seed_digest,)])
                self.assertEqual(endpoint.state_path.read_bytes(), old_state)
                for fragment, data in zip(fragments, fragment_data):
                    self.assertEqual((incoming / _fragment_name(fragment)).read_bytes(), data)
                capsule_path = state / "transfer" / "received-capsules" / (digest + ".json")
                self.assertEqual(capsule_path.read_bytes(), canonical_bytes(capsule) + b"\n")

                before_snapshot = tree_hashes(state)
                snapshot, recovered = root / "snapshot", root / "recovered"
                backed = operator("--config", config_path, "backup-client", "--output", snapshot, "--include", "sync", "--quiesced")
                self.assertFalse(backed["keys_copied"])
                self.assertFalse(backed["network_accessed"])
                self.assertEqual(tree_hashes(state), before_snapshot)
                manifest = strict_json_loads((snapshot / "manifest.json").read_bytes())
                paths = {entry["path"] for entry in manifest["entries"]}
                self.assertIn("control/sync/transfer/state.json", paths)
                self.assertIn("control/sync/transfer/received-capsules/" + digest + ".json", paths)
                self.assertFalse(any(Path(path).name in {"identity.json", "trust.json", "sync.json", "client.json", "dependency-index.sqlite3"}
                                     for path in paths))
                restored = operator("restore-client", "--backup", snapshot, "--output", recovered, "--trust-store", trust_path)
                self.assertEqual(restored["state"], "client_restored_inert")
                self.assertFalse(restored["pending_replayed"])
                self.assertFalse(restored["control_state_active"])
                self.assertFalse(restored["sync_enabled"])
                self.assertEqual(restored["memory"]["admissions"]["verified"], 1)
                new_store = restored["memory"]["new_store_id"]
                self.assertNotEqual(new_store, original_store)
                restored_vault = recovered / "memory.sqlite3"
                self.assertEqual(rows(restored_vault, "SELECT value FROM metadata WHERE key='store_id'"), [(new_store,)])
                self.assertEqual(rows(restored_vault, "SELECT transfer_id FROM transfer_receipts"), [])
                config = client.ClientConfig.load(recovered / "client.json")
                self.assertFalse(config.capture_visible_turns)
                self.assertIsNone(config.identity_path)
                self.assertIsNone(config.sync_config_path)
                self.assertEqual(config.trust_path, trust_path)
                self.assertFalse(config.state_path.exists())
                evidence = recovered / "evidence"
                self.assertEqual((evidence / "control" / "sync" / "transfer" / "state.json").read_bytes(), old_state)
                evidence_hashes = tree_hashes(evidence)
                inventory = operator("review-recovery", "--recovery", recovered, "--component", "sync", "--limit", 100)
                self.assertFalse(inventory["review_is_authorization"])
                chosen = next(entry for entry in inventory["entries"]
                              if entry["path"] == "control/sync/transfer/received-capsules/" + digest + ".json")
                self.assertTrue(chosen["signed_memory_import_candidate"])
                self.assertFalse(chosen["current_signature_trust_verified"])
                import_arguments = ("import-recovery", "--recovery", recovered, "--entry-id", chosen["entry_id"], "--trust-store", trust_path)
                operator(*import_arguments, error="recovery_memory_import_authorization_required")
                self.assertEqual(rows(restored_vault, "SELECT memory_id FROM memories"), [(seed["memory_id"],)])
                imported = operator(*import_arguments, "--authorize-memory-import")
                self.assertEqual(imported["memory"]["records_added"], 2)
                self.assertTrue(imported["current_signatures_verified"])
                for name in ("old_cursors_restored", "old_publication_permissions_restored", "network_accessed", "worker_started", "private_key_loaded"):
                    self.assertFalse(imported[name])
                reader = Vault(restored_vault, trust_check=trust.require_trusted)
                for expected in (seed, child, base):
                    value = reader.handle({"op": "get", "memory_id": expected["memory_id"]})
                    self.assertTrue(value["ok"], value)
                    self.assertFalse(value["authority"]["execution_eligible"])
                    self.assertEqual(value["result"]["record"], expected)
                    self.assertEqual(value["result"]["verification"]["admission"], "verified")
                repeated = operator(*import_arguments, "--authorize-memory-import")
                self.assertEqual(repeated["memory"]["records_added"], 0)
                self.assertTrue(repeated["memory"]["receipt_replayed"])
                self.assertEqual(rows(restored_vault, "SELECT COUNT(*) FROM transfer_receipts"), [(1,)])
                self.assertEqual(rows(restored_vault, "SELECT COUNT(*) FROM delivery_log"), [(3,)])
                # A historical import receipt must not bypass current revocation.
                before_revocation = sha256(restored_vault.read_bytes())
                trust.revoke(identity.key_id)
                operator(*import_arguments, "--authorize-memory-import", error="key_revoked")
                self.assertEqual(sha256(restored_vault.read_bytes()), before_revocation)
                self.assertEqual(tree_hashes(evidence), evidence_hashes)
                self.assertEqual(rows(restored_vault, "SELECT value FROM metadata WHERE key='store_id'"), [(new_store,)])
                self.assertFalse(config.state_path.exists())
                self.assertIsNone(client.ClientConfig.load(recovered / "client.json").sync_config_path)


if __name__ == "__main__":
    unittest.main()
