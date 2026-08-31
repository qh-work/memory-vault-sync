"""One disposable signed-selection/current-trust workflow; evidence is separate.

Two newly generated test identities have no production authority. Real client
writes, Ed25519 signatures, share export/verification/import and current-trust
reads are used. The alternate attester's packet is assembled from the original
canonical frames with fresh real signatures, not by mocking admission. Guards
forbid private-key loading after the initial authoring and any sync notification.
No host, account, provider ceremony, network or default Vault is involved.
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import memory_vault as core
import memory_vault_client as client
import memory_vault_sharing as sharing
import memory_vault_storage as storage
from memory_vault_trust import Identity, TrustStore


@unittest.skipUnless((sys.platform == "darwin" or sys.platform.startswith("linux"))
                     and importlib.util.find_spec("cryptography") is not None,
                     "requires an authorized disposable macOS/Linux Ed25519 fixture")
class SignedSharingWorkflowTests(unittest.TestCase):
    def test_selection_quarantine_independent_trust_replay_and_revocation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="memory-v025-signed-share-workflow-") as temporary:
            base = Path(temporary).resolve()
            identity_a = Identity.generate(base / "keys" / "a.json")
            identity_b = Identity.generate(base / "keys" / "b.json")
            sender_trust = TrustStore(base / "sender" / "trust.json")
            sender_trust.add(identity_a.public_descriptor(), "synthetic authoring attester")
            trust_a = TrustStore(base / "receiver-a" / "trust.json")
            trust_b = TrustStore(base / "receiver-b" / "trust.json")
            trust_b.add(identity_b.public_descriptor(), "synthetic independent attester B")

            def configuration(name, registry, *, database=None, identity=None):
                path = base / name / "client.json"
                document = {"schema_version": client.CONFIG_SCHEMA,
                            "vault_path": str(database or base / name / "memory.sqlite3"),
                            "trust_path": str(registry.path), "capture_visible_turns": False}
                if identity is not None:
                    document["identity_path"] = str(identity)
                storage.atomic_write(path, core.canonical_bytes(document) + b"\n", replace=False)
                return client.ClientConfig.load(path)

            sender = configuration("sender", sender_trust, identity=base / "keys" / "a.json")
            receiver_a = configuration("receiver-a", trust_a)
            receiver_b = configuration("receiver-b", trust_b, database=receiver_a.vault_path)

            def request(config, operation):
                response = config.vault().handle(operation)
                self.assertTrue(response["ok"], response)
                self.assertEqual(response["authority"], core.AUTHORITY)
                return response["result"]

            def author(operation):
                response = sender.vault(writing=True).handle(operation)
                self.assertTrue(response["ok"], response)
                self.assertEqual(response["result"]["verification"]["admission"], "verified")
                return response["result"]["memory_id"]

            episode = author({"op": "observe", "request_id": "req_share_workflow_episode",
                              "user": "Synthetic portable share context.",
                              "assistant": "Synthetic historical evidence for a memory transfer."})
            decision = author({"op": "remember", "request_id": "req_share_workflow_decision",
                               "kind": "decision", "text": "Synthetic portable sharing decision.",
                               "entities": ["claim:v021:portable-choice"],
                               "relations": [{"type": "derived_from", "target": episode}],
                               "provenance": {"task_ref": "synthetic:reference-not-owner"}})
            unrelated = author({"op": "remember", "request_id": "req_share_workflow_unrelated",
                                "kind": "fact", "text": "Synthetic unrelated source memory."})
            identifiers = {episode, decision}
            canonical = {identifier: request(sender, {"op": "get", "memory_id": identifier})["record"]
                         for identifier in identifiers}
            choice = {"schema_version": sharing.SELECTOR_SCHEMA,
                      "claim_keys": ["portable-choice"], "kinds": ["decision"]}
            original_share = base / "selected-a.ndjson"

            def state():
                # Only this explicitly created receiver fixture is inspected.
                with contextlib.closing(receiver_a.vault()._connect(writable=False)) as connection:
                    records = tuple(tuple(row) for row in connection.execute(
                        "SELECT memory_id,record_json FROM memories ORDER BY memory_id"))
                    admissions = tuple(tuple(row) for row in connection.execute(
                        "SELECT memory_id,state,signer_key_id,attestation_json FROM record_admissions ORDER BY memory_id"))
                    receipts = tuple(tuple(row) for row in connection.execute(
                        "SELECT transfer_id,payload_sha256,result_json,created_at FROM transfer_receipts ORDER BY transfer_id"))
                    delivery = int(connection.execute("SELECT COUNT(*) FROM delivery_log").fetchone()[0])
                return records, admissions, receipts, delivery

            def cli_rejection(code):
                wire = io.BytesIO()
                output = io.TextIOWrapper(wire, encoding="utf-8")
                try:
                    with contextlib.redirect_stdout(output):
                        result = sharing.main(["import", "--source", str(original_share), "--verify-signatures"],
                                              config_path=receiver_a.path)
                    output.flush()
                    frame = json.loads(wire.getvalue())
                finally:
                    output.detach()
                self.assertEqual(result, 1)
                self.assertFalse(frame["ok"])
                self.assertEqual(frame["error"], {"code": code, "retryable": False})
                self.assertEqual(frame["authority"], core.AUTHORITY)

            def assert_ineligible():
                for identifier, record in canonical.items():
                    fetched = request(receiver_a, {"op": "get", "memory_id": identifier})
                    self.assertEqual(fetched["record"], record)
                    self.assertEqual(fetched["status"], "quarantined")
                    self.assertFalse(fetched["verification"]["eligible_for_context"])
                self.assertEqual(request(receiver_a, {"op": "recall", "query": "synthetic portable"})["hits"], [])
                self.assertEqual(request(receiver_a, {"op": "changes"})["records"], [])

            with mock.patch.object(Identity, "load", side_effect=AssertionError("share path loaded a private key")), \
                    mock.patch.object(client, "notify_sync", side_effect=AssertionError("share path started sync")):
                review = sharing.export_share(sender.path, None, choice)
                self.assertEqual((review["selected_records"], review["dependency_records"]), (1, 1))
                self.assertFalse(review["contents_included"])
                self.assertFalse(review["files_written"])
                published = sharing.export_share(sender.path, original_share, choice)
                self.assertEqual((published["records"], published["attestations"]), (2, 2))
                self.assertFalse(published["attestation_crypto_checked_on_export"])
                original_bytes = original_share.read_bytes()
                frames = [json.loads(line) for line in original_bytes.splitlines()]
                record_frames = [frame for frame in frames if frame["type"] == "record"]
                self.assertEqual({frame["record"]["memory_id"] for frame in record_frames}, identifiers)
                self.assertNotIn(unrelated, identifiers)
                self.assertEqual({frame["record"]["memory_id"] for frame in record_frames if frame["selected"]}, {decision})
                proofs_a = {frame["record"]["memory_id"]: frame["attestation"] for frame in record_frames}
                summary = sharing.verify_share_bundle(original_share).as_dict()
                self.assertFalse(summary["signatures_cryptographically_verified"])
                self.assertFalse(summary["checksum_authenticates_sender"])

                quarantined = sharing.import_share(receiver_a.path, original_share)
                self.assertEqual(quarantined["admission"], "quarantined")
                self.assertEqual(quarantined["records_added"], 2)
                self.assertFalse(quarantined["record_proofs_stored"])
                assert_ineligible()
                before_unknown = state()
                cli_rejection("unknown_key")
                self.assertFalse(trust_a.path.exists(), "an incoming proof enrolled its own key")
                self.assertEqual(state(), before_unknown)
                trust_a.add(identity_a.public_descriptor(), "synthetic independently approved attester A")
                trust_bytes = trust_a.path.read_bytes()
                admitted = sharing.import_share(receiver_a.path, original_share, verify_signatures=True)
                self.assertEqual(admitted["records_added"], 0)
                self.assertTrue(admitted["current_trust_checked"])
                self.assertTrue(admitted["record_proofs_stored"])
                self.assertFalse(admitted["worker_started"])
                self.assertFalse(admitted["trust_policy_changed"])
                for identifier in identifiers:
                    fetched = request(receiver_a, {"op": "get", "memory_id": identifier})
                    self.assertEqual(fetched["record"], canonical[identifier])
                    self.assertTrue(fetched["verification"]["eligible_for_context"])
                    self.assertFalse(fetched["verification"]["claimed_provenance_is_authenticated"])
                    self.assertFalse(fetched["verification"]["grants_authority"])
                forwarded = base / "forwarded-a.ndjson"
                sharing.export_share(receiver_a.path, forwarded, choice)
                for frame in (json.loads(line) for line in forwarded.read_bytes().splitlines()):
                    if frame["type"] == "record":
                        identifier = frame["record"]["memory_id"]
                        self.assertEqual(frame["record"], canonical[identifier])
                        self.assertEqual(frame["attestation"], proofs_a[identifier])
                        self.assertEqual(trust_a.verify_record(frame["record"], frame["attestation"]), identity_a.key_id)

                # Register an explicit unsigned receipt without demoting an
                # already verified copy. Its later replay must not re-admit a
                # revoked record merely because historical approval exists.
                sharing.import_share(receiver_a.path, original_share, accept_unsigned=True)
                stable = state()
                repeated = sharing.import_share(receiver_a.path, original_share, verify_signatures=True)
                self.assertTrue(repeated["receipt_replayed"])
                self.assertEqual(repeated["admissions_restored"], 0)
                self.assertEqual(state(), stable)

                # An independent attester may sign the same immutable bytes;
                # this neither changes their provenance nor proves authorship.
                alternate_lines = []
                for frame in record_frames:
                    proof = identity_b.sign_record(frame["record"])
                    self.assertEqual(trust_b.verify_record(frame["record"], proof), identity_b.key_id)
                    alternate_lines.append(core.canonical_bytes({**frame, "attestation": proof}) + b"\n")
                alternate = base / "selected-b.ndjson"
                footer = {**frames[-1], "lines_sha256": hashlib.sha256(b"".join(alternate_lines)).hexdigest()}
                with sharing._new_output(alternate) as stream:
                    stream.write(core.canonical_bytes(frames[0]) + b"\n")
                    for line in alternate_lines:
                        stream.write(line)
                    stream.write(core.canonical_bytes(footer) + b"\n")
                sharing.import_share(receiver_b.path, alternate, verify_signatures=True)
                assert_ineligible()  # A's configuration does not trust B.
                changed_attester = state()
                self.assertEqual({row[2] for row in changed_attester[1]}, {identity_b.key_id})
                restored = sharing.import_share(receiver_a.path, original_share, verify_signatures=True)
                self.assertTrue(restored["receipt_replayed"])
                self.assertFalse(restored["historical_receipt_is_current_admission"])
                self.assertTrue(restored["current_admission_rechecked"])
                self.assertEqual(restored["admissions_restored"], 2)
                self.assertEqual(restored["records_added"], 0)
                recovered = state()
                self.assertEqual(recovered[0], changed_attester[0])
                self.assertEqual(recovered[2], changed_attester[2], "a historical receipt was rewritten")
                self.assertGreater(recovered[3], changed_attester[3])
                self.assertEqual({row[2] for row in recovered[1]}, {identity_a.key_id})
                self.assertEqual({row[0]: json.loads(row[3]) for row in recovered[1]}, proofs_a)
                self.assertEqual(trust_a.path.read_bytes(), trust_bytes)
                self.assertEqual(sharing.import_share(receiver_a.path, original_share, verify_signatures=True)["admissions_restored"], 0)
                self.assertEqual(state(), recovered)
                self.assertEqual(request(receiver_a, {"op": "status"})["context_eligible_records"], 2)
                recovered_export = sharing.export_share(receiver_a.path, base / "forwarded-restored.ndjson", choice)
                self.assertEqual((recovered_export["records"], recovered_export["attestations"]), (2, 2))

                trust_a.revoke(identity_a.key_id)
                revoked = state()
                assert_ineligible()
                cli_rejection("key_revoked")
                for mode in ({}, {"accept_unsigned": True}):
                    replay = sharing.import_share(receiver_a.path, original_share, **mode)
                    self.assertTrue(replay["receipt_replayed"])
                    self.assertFalse(replay["current_admission_rechecked"])
                    self.assertEqual(replay["admissions_restored"], 0)
                with self.assertRaises(core.MemoryError) as rejected:
                    sharing.export_share(receiver_a.path, base / "must-not-forward.ndjson", choice)
                self.assertEqual(rejected.exception.code, "share_no_matching_records")
                self.assertFalse((base / "must-not-forward.ndjson").exists())
                self.assertEqual(state(), revoked)
                assert_ineligible()
                self.assertEqual(original_share.read_bytes(), original_bytes)
                self.assertFalse(sender.state_path.exists())
                self.assertFalse(receiver_a.state_path.exists())
                self.assertFalse(receiver_b.state_path.exists())


if __name__ == "__main__":
    unittest.main()
