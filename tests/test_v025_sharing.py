"""Public synthetic sharing cases for reviewers; supplied WITHOUT execution.

All files and keys below are disposable fixtures. The optional Ed25519 cases
are separate from framing/checksum tests: a checksum never proves authorship.
No installed client, private Vault, network or external account is accessed.
"""

from __future__ import annotations

import base64
import contextlib
import copy
import hashlib
import importlib.util
import json
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

import memory_vault as core
import memory_vault_sharing as sharing
import memory_vault_storage as storage
from memory_vault_client import CONFIG_SCHEMA, ClientConfig


def synthetic_record(text: str, *, kind: str = "fact", entities=(), relations=(),
                     created_at: str = "2026-01-01T00:00:00Z") -> dict:
    return core.build_record(kind=kind, text=text, entities=entities, relations=relations,
                             created_at=created_at)


def write_packet(path: Path, records: list[dict], *, selected: set[str],
                 selector: dict | None = None, proofs: dict | None = None) -> None:
    """Build exact public wire bytes, including deliberately invalid closures."""
    choice = sharing.parse_selector(selector or {
        "schema_version": sharing.SELECTOR_SCHEMA, "memory_ids": sorted(selected),
    })
    header = {"type": "header", "schema_version": sharing.SHARE_SCHEMA,
              "hash_profile": core.HASH_PROFILE, "created_at": "2026-01-01T00:00:00Z",
              "selector": choice, "selector_sha256": core.sha256(core.canonical_bytes(choice))}
    frames = [core.canonical_bytes({"type": "record", "record": record,
                                   "attestation": (proofs or {}).get(record["memory_id"]),
                                   "selected": record["memory_id"] in selected}) + b"\n"
              for record in records]
    footer = {"type": "footer", "records": len(records),
              "selected_records": sum(record["memory_id"] in selected for record in records),
              "records_sha256": hashlib.sha256(b"".join(record["record_sha256"].encode("ascii") + b"\n"
                                                        for record in records)).hexdigest(),
              "lines_sha256": hashlib.sha256(b"".join(frames)).hexdigest()}
    storage.atomic_write(path, core.canonical_bytes(header) + b"\n" + b"".join(frames)
                         + core.canonical_bytes(footer) + b"\n", replace=path.exists())


class SharingFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="memory-v025-sharing-synthetic-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.sender = self.make_config("sender")
        self.receiver = self.make_config("receiver")
        self.source = self.root / "selected.ndjson"
        self.baseline = synthetic_record("Synthetic receiver baseline.")
        core.Vault(self.receiver.vault_path).ingest_records([self.baseline], admission="accepted_unsigned")

    def make_config(self, name: str, *, trust_path: Path | None = None,
                    identity_path: Path | None = None) -> ClientConfig:
        path = self.root / name / "client.json"
        value = {"schema_version": CONFIG_SCHEMA, "vault_path": str(self.root / name / "memory.sqlite3"),
                 "capture_visible_turns": False}
        if trust_path is not None:
            value["trust_path"] = str(trust_path)
        if identity_path is not None:
            value["identity_path"] = str(identity_path)
        storage.atomic_write(path, core.canonical_bytes(value) + b"\n", replace=path.exists())
        return ClientConfig.load(path)

    def add_source(self, records: list[dict], *, admission: str = "accepted_unsigned", proofs=None) -> None:
        core.Vault(self.sender.vault_path).ingest_records(records, admission=admission, attestations=proofs)

    def counts(self) -> tuple[int, int, int]:
        with contextlib.closing(sqlite3.connect(self.receiver.vault_path)) as connection:
            return tuple(int(connection.execute("SELECT COUNT(*) FROM " + table).fetchone()[0])
                         for table in ("memories", "transfer_receipts", "delivery_log"))

    def export(self, memory_id: str, *, output: Path | None = None, **options) -> dict:
        choice = {"schema_version": sharing.SELECTOR_SCHEMA, "memory_ids": [memory_id]}
        return dict(sharing.export_share(self.sender.path, output or self.source, choice, **options))

    def assert_error(self, code: str, function, *args, **kwargs) -> None:
        with self.assertRaises(core.MemoryError) as raised:
            function(*args, **kwargs)
        self.assertEqual(raised.exception.code, code)


@unittest.skipUnless(os.name == "posix", "disposable file-mode fixtures use POSIX")
class SharingTests(SharingFixture):
    def test_selector_is_explicit_and_cannot_select_an_owner_or_policy(self) -> None:
        for extra in ({}, {"task_id": "synthetic"}, {"project_id": "synthetic"},
                      {"all_records": True, "entities": ["synthetic"]},
                      {"all_records": "true"}, {"all_records": True, "trust": "packet-owned"}):
            with self.subTest(extra=extra), self.assertRaises(core.MemoryError):
                sharing.parse_selector({"schema_version": sharing.SELECTOR_SCHEMA, **extra})

    def test_claim_kind_and_utc_bounds_only_filter_roots(self) -> None:
        evidence = synthetic_record("Synthetic historical evidence.", created_at="2025-01-01T00:00:00Z")
        root = synthetic_record("Synthetic chosen decision.", kind="decision", entities=["claim:v021:storage-choice"],
                                relations=[{"type": "derived_from", "target": evidence["memory_id"]}])
        unrelated = synthetic_record("Synthetic other decision.", kind="decision", entities=["claim:v021:other-choice"])
        self.add_source([evidence, root, unrelated])
        choice = {"schema_version": sharing.SELECTOR_SCHEMA, "claim_keys": ["storage-choice"],
                  "kinds": ["decision"], "captured_after": "2026-01-01T08:00:00+08:00",
                  "captured_before": "2026-01-02T00:00:00Z"}
        result = sharing.export_share(self.sender.path, self.source, choice)
        self.assertEqual((result["selected_records"], result["dependency_records"]), (1, 1))
        frames = [json.loads(line) for line in self.source.read_bytes().splitlines()]
        self.assertEqual({frame["record"]["memory_id"] for frame in frames if frame["type"] == "record"},
                         {root["memory_id"], evidence["memory_id"]})

    def test_review_is_content_free_and_does_not_load_identity_or_start_worker(self) -> None:
        root = synthetic_record("Synthetic review-only record.")
        self.add_source([root])
        choice = {"schema_version": sharing.SELECTOR_SCHEMA, "memory_ids": [root["memory_id"]]}
        # A read-only WAL connection can create SQLite coordination sidecars;
        # establish the read baseline before testing the review's own effects.
        with contextlib.closing(core.Vault(self.sender.vault_path)._connect(writable=False)) as connection:
            connection.execute("SELECT COUNT(*) FROM memories").fetchone()
        before = {path.relative_to(self.root) for path in self.root.rglob("*")}
        with mock.patch("memory_vault_trust.Identity.load", side_effect=AssertionError("no private key")), \
                mock.patch("memory_vault_client.notify_sync", side_effect=AssertionError("no worker")):
            result = sharing.export_share(self.sender.path, None, choice)
        self.assertFalse(result["files_written"])
        self.assertFalse(result["network_accessed"])
        self.assertFalse(result["grants_authority"])
        self.assertNotIn(root["text"], json.dumps(result))
        self.assertEqual(before, {path.relative_to(self.root) for path in self.root.rglob("*")})

    def test_dependency_privacy_review_cannot_be_bypassed_by_selecting_only_root(self) -> None:
        dependency = synthetic_record("Synthetic API field: api_key=" + "fixture_value_" * 3)
        root = synthetic_record("Synthetic public-looking root.", relations=[{"type": "derived_from", "target": dependency["memory_id"]}])
        self.add_source([dependency, root])
        self.assert_error("publication_secret_detected", self.export, root["memory_id"], allow_local_paths=True)
        self.assertFalse(self.source.exists())

    def test_local_paths_need_explicit_export_choice_and_no_overwrite_occurs(self) -> None:
        root = synthetic_record("Synthetic reference /home/synthetic/example.txt")
        self.add_source([root])
        self.assert_error("publication_local_path_detected", self.export, root["memory_id"])
        self.export(root["memory_id"], allow_local_paths=True)
        original = self.source.read_bytes()
        self.assert_error("share_output_exists", self.export, root["memory_id"], allow_local_paths=True)
        self.assertEqual(original, self.source.read_bytes())

    def test_quarantined_dependency_prevents_incomplete_export(self) -> None:
        dependency = synthetic_record("Synthetic quarantined dependency.")
        self.add_source([dependency], admission="quarantined")
        root = synthetic_record("Synthetic admitted root.", relations=[{"type": "derived_from", "target": dependency["memory_id"]}])
        self.add_source([root])
        self.assert_error("share_dependency_not_admitted", self.export, root["memory_id"])
        self.assertFalse(self.source.exists())

    def test_forward_order_closure_imports_without_losing_canonical_bytes(self) -> None:
        dependency = synthetic_record("Synthetic dependency.")
        root = synthetic_record("Synthetic forward reference.", relations=[{"type": "derived_from", "target": dependency["memory_id"]}])
        write_packet(self.source, [root, dependency], selected={root["memory_id"]})
        result = sharing.import_share(self.receiver.path, self.source, accept_unsigned=True)
        self.assertEqual(result["records_added"], 2)
        with contextlib.closing(sqlite3.connect(self.receiver.vault_path)) as connection:
            for record in (root, dependency):
                stored = connection.execute("SELECT record_json FROM memories WHERE memory_id=?", (record["memory_id"],)).fetchone()[0]
                self.assertEqual(stored.encode("utf-8"), core.canonical_bytes(record))

    def test_unreachable_unselected_record_is_not_a_valid_selected_subgraph(self) -> None:
        root, extra = synthetic_record("Synthetic selected root."), synthetic_record("Synthetic unrelated extra.")
        write_packet(self.source, [root, extra], selected={root["memory_id"]})
        with self.assertRaises(core.MemoryError):
            sharing.verify_share_bundle(self.source)
        before = self.counts()
        with self.assertRaises(core.MemoryError):
            sharing.import_share(self.receiver.path, self.source, accept_unsigned=True)
        self.assertEqual(before, self.counts())

    def test_missing_dependency_and_duplicate_identity_are_rejected(self) -> None:
        absent = synthetic_record("Synthetic absent dependency.")
        root = synthetic_record("Synthetic dangling reference.", relations=[{"type": "derived_from", "target": absent["memory_id"]}])
        for records in ([root], [absent, absent]):
            with self.subTest(records=len(records)):
                selected = {record["memory_id"] for record in records}
                write_packet(self.source, records, selected=selected)
                with self.assertRaises(core.MemoryError):
                    sharing.verify_share_bundle(self.source)

    def test_default_import_is_quarantined_and_explicit_reimport_upgrades(self) -> None:
        root = synthetic_record("Synthetic quarantine marker.")
        write_packet(self.source, [root], selected={root["memory_id"]})
        with mock.patch("memory_vault_trust.Identity.load", side_effect=AssertionError("no private key")), \
                mock.patch("memory_vault_client.notify_sync", side_effect=AssertionError("no worker")):
            initial = sharing.import_share(self.receiver.path, self.source)
            admitted = sharing.import_share(self.receiver.path, self.source, accept_unsigned=True)
            repeated = sharing.import_share(self.receiver.path, self.source, accept_unsigned=True)
        self.assertEqual(initial["admission"], "quarantined")
        self.assertEqual(admitted["records_added"], 0)
        self.assertTrue(repeated["receipt_replayed"])
        self.assertFalse(repeated["network_accessed"])
        self.assertFalse(admitted["worker_started"])
        self.assertFalse(admitted["trust_policy_changed"])
        response = self.receiver.vault().handle({"op": "get", "memory_id": root["memory_id"]})
        self.assertTrue(response["ok"], response)
        self.assertFalse(response["authority"]["execution_eligible"])

    def test_failure_after_first_insert_rolls_back_records_and_receipt(self) -> None:
        one, two = synthetic_record("Synthetic import one."), synthetic_record("Synthetic import two.")
        write_packet(self.source, [one, two], selected={one["memory_id"], two["memory_id"]})
        before = self.counts()
        real_scan = sharing._scan

        def interrupted(path, deadline, *, visitor=None):
            if visitor is None:
                return real_scan(path, deadline)

            def receive_then_fail(record, proof):
                visitor(record, proof)
                raise core.MemoryError("synthetic_interrupt_after_insert")

            return real_scan(path, deadline, visitor=receive_then_fail)

        with mock.patch.object(sharing, "_scan", side_effect=interrupted):
            self.assert_error("synthetic_interrupt_after_insert", sharing.import_share,
                              self.receiver.path, self.source, accept_unsigned=True)
        self.assertEqual(before, self.counts())

    def test_trailing_bytes_tampered_record_and_noncanonical_frame_are_rejected(self) -> None:
        root = synthetic_record("Synthetic complete share.")
        write_packet(self.source, [root], selected={root["memory_id"]})
        original = self.source.read_bytes()
        variants = [original + b"extra\n", original.replace(b"Synthetic complete", b"Synthetic tampered"),
                    original.replace(b'"type":"header"', b'"type": "header"', 1)]
        for data in variants:
            with self.subTest(data=data[-30:]):
                self.source.write_bytes(data)
                with self.assertRaises(core.MemoryError):
                    sharing.verify_share_bundle(self.source)

    def test_structural_proof_is_not_a_signature_verification_claim(self) -> None:
        root = synthetic_record("Synthetic shape-only proof.")
        proof = {"schema_version": core.ATTESTATION_SCHEMA, "key_id": "ed25519_" + "1" * 64,
                 "record_sha256": root["record_sha256"], "signature": base64.b64encode(bytes(64)).decode("ascii")}
        write_packet(self.source, [root], selected={root["memory_id"]}, proofs={root["memory_id"]: proof})
        summary = sharing.verify_share_bundle(self.source).as_dict()
        self.assertEqual(summary["attestations"], 1)
        self.assertFalse(summary["signatures_cryptographically_verified"])
        self.assertFalse(summary["checksum_authenticates_sender"])
        malformed = copy.deepcopy(proof)
        malformed["signature"] = base64.b64encode(bytes(63)).decode("ascii")
        write_packet(self.source, [root], selected={root["memory_id"]}, proofs={root["memory_id"]: malformed})
        self.assert_error("invalid_share_attestation", sharing.verify_share_bundle, self.source)

    def test_large_share_path_is_independent_of_small_bundle_limits(self) -> None:
        records = [synthetic_record(f"Synthetic independent streaming record {index}.") for index in range(3)]
        write_packet(self.source, records, selected={record["memory_id"] for record in records})
        with mock.patch.object(core, "MAX_BUNDLE_RECORDS", 1), mock.patch.object(core, "MAX_BUNDLE_BYTES", 16):
            result = sharing.import_share(self.receiver.path, self.source, accept_unsigned=True)
        self.assertEqual(result["records_added"], 3)
        # This is a route-boundary check, not a 2-GiB performance measurement.

    def test_exact_id_selection_does_not_walk_unrelated_source_records(self) -> None:
        records = [synthetic_record(f"Synthetic unrelated source {index}.") for index in range(3)]
        self.add_source(records)
        with mock.patch.object(sharing, "MAX_SOURCE_RECORDS", 1):
            result = self.export(records[-1]["memory_id"])
        self.assertEqual(result["records"], 1)

    def test_source_symlink_and_hardlink_are_rejected(self) -> None:
        root = synthetic_record("Synthetic safe source.")
        write_packet(self.source, [root], selected={root["memory_id"]})
        symbolic = self.root / "symbolic.ndjson"
        symbolic.symlink_to(self.source)
        with self.assertRaises(core.MemoryError):
            sharing.verify_share_bundle(symbolic)
        alias = self.root / "hard.ndjson"
        os.link(self.source, alias)
        with self.assertRaises(core.MemoryError):
            sharing.verify_share_bundle(self.source)


@unittest.skipUnless(os.name == "posix" and importlib.util.find_spec("cryptography") is not None,
                     "signed disposable fixtures require optional cryptography and POSIX")
class SignedSharingTests(SharingFixture):
    def signed_packet(self) -> tuple[dict, dict, object, object]:
        from memory_vault_trust import Identity, TrustStore
        key_directory = self.root / "independent-keys"
        storage.private_directory(key_directory)
        identity = Identity.generate(key_directory / "fixture-key.json")
        trust_path = key_directory / "receiver-trust.json"
        registry = TrustStore(trust_path)
        registry.add(identity.public_descriptor(), "public synthetic fixture")
        self.receiver = self.make_config("receiver", trust_path=trust_path)
        record = synthetic_record("Synthetic independently signed memory.")
        proof = identity.sign_record(record)
        write_packet(self.source, [record], selected={record["memory_id"]}, proofs={record["memory_id"]: proof})
        return record, proof, identity, registry

    def test_verified_import_preserves_proof_and_rechecks_revocation_on_retry(self) -> None:
        from memory_vault_trust import TrustError
        record, proof, identity, registry = self.signed_packet()
        result = sharing.import_share(self.receiver.path, self.source, verify_signatures=True)
        self.assertTrue(result["current_trust_checked"])
        with contextlib.closing(sqlite3.connect(self.receiver.vault_path)) as connection:
            stored = connection.execute("SELECT attestation_json FROM record_admissions WHERE memory_id=?",
                                        (record["memory_id"],)).fetchone()[0]
        self.assertEqual(json.loads(stored), proof)
        registry.revoke(identity.key_id)
        before = self.counts()
        with self.assertRaises(TrustError):
            sharing.import_share(self.receiver.path, self.source, verify_signatures=True)
        self.assertEqual(before, self.counts())

    def test_bad_signature_does_not_partially_admit_other_valid_records(self) -> None:
        from memory_vault_trust import TrustError
        record, proof, identity, _ = self.signed_packet()
        second = synthetic_record("Synthetic invalid second signature.")
        bad = identity.sign_record(second)
        bad["signature"] = base64.b64encode(bytes(64)).decode("ascii")
        write_packet(self.source, [record, second], selected={record["memory_id"], second["memory_id"]},
                     proofs={record["memory_id"]: proof, second["memory_id"]: bad})
        before = self.counts()
        with self.assertRaises(TrustError):
            sharing.import_share(self.receiver.path, self.source, verify_signatures=True)
        self.assertEqual(before, self.counts())

    def test_verified_import_requires_independent_registry_and_every_record_proof(self) -> None:
        record, proof, _, _ = self.signed_packet()
        unsigned = synthetic_record("Synthetic unsigned extra root.")
        write_packet(self.source, [record, unsigned], selected={record["memory_id"], unsigned["memory_id"]},
                     proofs={record["memory_id"]: proof})
        before = self.counts()
        self.assert_error("share_record_signature_required", sharing.import_share,
                          self.receiver.path, self.source, verify_signatures=True)
        self.assertEqual(before, self.counts())
        no_registry = self.make_config("without-registry")
        self.assert_error("share_independent_trust_required", sharing.import_share,
                          no_registry.path, self.source, verify_signatures=True)

    def test_revocation_after_record_verification_is_caught_before_commit(self) -> None:
        from memory_vault_trust import TrustError, TrustStore
        _, _, identity, registry = self.signed_packet()
        original_verify = TrustStore.verify_record
        before = self.counts()

        def revoke_after_verification(current, record, proof):
            key = original_verify(current, record, proof)
            registry.revoke(identity.key_id)
            return key

        with mock.patch.object(TrustStore, "verify_record", revoke_after_verification):
            with self.assertRaises(TrustError):
                sharing.import_share(self.receiver.path, self.source, verify_signatures=True)
        self.assertEqual(before, self.counts())

    def test_revocation_during_export_prevents_final_file_publication(self) -> None:
        from memory_vault_trust import TrustError
        record, proof, identity, registry = self.signed_packet()
        self.sender = self.make_config("sender", trust_path=registry.path)
        self.add_source([record], admission="verified", proofs={record["memory_id"]: proof})
        output = self.root / "export-after-review.ndjson"
        original_proof = sharing._proof

        def revoke_after_admission_check(value, attestation):
            accepted = original_proof(value, attestation)
            registry.revoke(identity.key_id)
            return accepted

        with mock.patch.object(sharing, "_proof", side_effect=revoke_after_admission_check):
            with self.assertRaises(TrustError):
                self.export(record["memory_id"], output=output)
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
