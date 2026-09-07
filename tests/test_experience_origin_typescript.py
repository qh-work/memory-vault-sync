"""Real Python admission -> Node provenance after reattestation, synthetic only.

Node uses the production CanonicalVault with an independently supplied current
trust list, read-only SQLite, and actual Ed25519 verification in get(). No
crypto placeholders, installation, network, or copied alternate implementation.
"""
from __future__ import annotations

import contextlib
import sqlite3
import unittest

from memory_vault import AUTHORITY, RETRIEVAL_PROFILES, Vault, canonical_bytes
from memory_vault_trust import Identity
from tests import test_network_typescript_vault as vault_harness


class ExperienceOriginTypeScriptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        vault_harness.TypeScriptVaultTests.setUpClass.__func__(cls)
        driver = (cls.fixture / "driver.mjs").read_text()
        driver = driver.replace("const options = { vaultPath:request.vaultPath };",
                                "const options = { vaultPath:request.vaultPath, readOnly:true };")
        driver = driver.replace("else if (item.op === 'get')",
            "else if (item.op === 'inspect') value = vault.inspect(item.id,true);\n"
            "        else if (item.op === 'retrieve') value = vault.retrieve(item.value);\n"
            "        else if (item.op === 'get')")
        (cls.fixture / "driver.mjs").write_text(driver)

    run_ts = vault_harness.TypeScriptVaultTests.run_ts
    _run = vault_harness.TypeScriptVaultTests._run
    successful = vault_harness.TypeScriptVaultTests.successful

    def setUp(self):
        vault_harness.TypeScriptVaultTests.setUp(self)
        self.identities = {"A": self.identity}
        for name in ("P", "B", "C"):
            self.identities[name] = Identity.generate(self.directory / (name + ".json"))
            self.trust.add(self.identities[name].public_descriptor())
        self.current_names = set(self.identities)
        self.vault = Vault(self.path, signer=self.identity.sign_record, trust_check=self.trust.require_trusted)
        self.counter = 0

    def remember(self, name, text, *, experience=None):
        self.counter += 1
        writer = Vault(self.path, signer=self.identities[name].sign_record,
                       trust_check=self.trust.require_trusted)
        response = writer.handle({"op": "remember", "request_id": "req_origin_real_" + str(self.counter),
            "kind": "observation", "text": text, "experience": experience or {"epistemic_type": "observation"}})
        self.assertTrue(response["ok"], response)
        self.assertEqual(response["authority"], AUTHORITY)
        return self.inspect_python(response["result"]["memory_id"])["record"]

    def inspect_python(self, memory_id):
        response = self.vault.handle({"op": "get", "memory_id": memory_id, "include_experience": True})
        self.assertTrue(response["ok"], response)
        self.assertEqual(response["authority"], AUTHORITY)
        return response["result"]

    def active_trust(self):
        return [self.identities[name].public_descriptor() for name in sorted(self.current_names)]

    def snapshot(self):
        with sqlite3.connect(self.path) as db:
            return {table: db.execute("SELECT * FROM " + table + " ORDER BY 1").fetchall()
                    for table in ("metadata", "memories", "record_admissions", "relations")}

    def pins(self):
        with sqlite3.connect(self.path) as db:
            return dict(db.execute("SELECT key,value FROM metadata WHERE key LIKE 'state_author:%' ORDER BY key"))

    def inspect_typescript(self, root, records):
        # get() verifies the production signed record, then inspect() executes
        # the actual provenance path against the same read-only database.
        operations = [{"op": "get", "id": record["memory_id"]} for record in records]
        operations.append({"op": "inspect", "id": root["memory_id"]})
        before = self.snapshot()
        results = self.successful(self.run_ts(operations, trust=self.active_trust()))
        self.assertEqual(self.snapshot(), before)
        for record, actual in zip(records, results):
            if actual is not None:
                self.assertEqual(canonical_bytes(actual["record"]), canonical_bytes(record))
                if actual["attestation"] is not None:
                    self.trust.verify_record(record, actual["attestation"])
                else:
                    self.assertIn(self.inspect_python(record["memory_id"])["verification"]["admission"],
                                  {"accepted_unsigned", "local_unsigned"})
        return results[-1], results[:-1]

    def origin_records(self, relation):
        root = self.remember("A", "Synthetic origin review method X source observation")
        records = [root]
        for label in ("E1", "E2"):
            records.append(self.remember("P", "Synthetic origin review method X experiment " + label,
                experience={"epistemic_type": "experiment", "observed_under": {"environment": "V1"},
                            "relations": [{"type": relation, "target": root["memory_id"]}]}))
        return root, records

    def revoke(self, name):
        self.trust.revoke(self.identities[name].key_id)
        self.current_names.remove(name)

    def reattest(self, records):
        for name, record in zip(("B", "C"), records[1:]):
            proof = self.identities[name].sign_record(record)
            self.trust.verify_record(record, proof)
            self.vault.ingest_records([record], admission="verified", attestations={record["memory_id"]: proof})

    def assert_stable_republished_origin(self, relation, count_key):
        root, records = self.origin_records(relation)
        original_bytes = {record["memory_id"]: canonical_bytes(record) for record in records}
        original_pins = self.pins()
        before, signed = self.inspect_typescript(root, records)
        self.assertTrue(all(value is not None for value in signed))
        self.assertEqual(before["experience"]["provenance_summary"][count_key], 1)
        self.assertEqual(self.inspect_python(root["memory_id"])["experience"]["provenance_summary"][count_key], 1)

        self.revoke("P")
        revoked, signed = self.inspect_typescript(root, records)
        self.assertIsNotNone(signed[0])
        self.assertEqual(signed[1:], [None, None])
        self.assertEqual(revoked["experience"]["provenance_summary"][count_key], 0)
        self.assertEqual(self.inspect_python(root["memory_id"])["experience"]["provenance_summary"][count_key], 0)

        self.reattest(records)
        self.assertEqual(self.pins(), original_pins)
        for name, record in zip(("B", "C"), records[1:]):
            observed = self.inspect_python(record["memory_id"])
            self.assertEqual(observed["verification"]["signer_key_id"], self.identities[name].key_id)
            self.assertTrue(observed["verification"]["eligible_for_context"])
            self.assertEqual(self.pins()["state_author:" + record["memory_id"]], self.identities["P"].key_id)
            self.assertEqual(canonical_bytes(observed["record"]), original_bytes[record["memory_id"]])

        # The public defect was count 1 -> 2 despite the same three records,
        # unchanged bytes and both local historical origin pins still P.
        after, signed = self.inspect_typescript(root, records)
        self.assertTrue(all(value is not None for value in signed))
        ts_summary = after["experience"]["provenance_summary"]
        self.assertEqual(ts_summary[count_key], 1)
        py_summary = self.inspect_python(root["memory_id"])["experience"]["provenance_summary"]
        self.assertEqual(py_summary, ts_summary)
        self.assertEqual(ts_summary["records_considered"], 3)
        self.assertFalse(ts_summary["truncated"])
        self.assertFalse(ts_summary["independence_verified"])
        self.assertFalse(ts_summary["origin_identity_incomplete"])
        self.assertEqual(ts_summary["unattributed_evidence_count"], 0)
        self.assertEqual(ts_summary["origin_identity_basis"], "local_first_verified_signer_or_unsigned_record")
        self.assertIsNone(ts_summary["truth_score"])

        before_replay = self.snapshot()
        self.reattest(records)
        self.assertEqual(self.snapshot(), before_replay)
        replay, _ = self.inspect_typescript(root, records)
        self.assertEqual(replay["experience"]["provenance_summary"], ts_summary)

        before_reads = self.snapshot()
        for profile in RETRIEVAL_PROFILES:
            for handoff in (False, True):
                request = {"query": "Synthetic origin review", "limit": 4, "include_experience": True,
                           "ranking_profile": profile, "handoff": handoff}
                ts = self.successful(self.run_ts([{"op": "retrieve", "value": request}], trust=self.active_trust()))[0]
                py = self.vault.handle({"op": "handoff" if handoff else "recall",
                                       **{key: value for key, value in request.items() if key != "handoff"}})
                self.assertTrue(py["ok"], py)
                for hits in (ts["hits"], py["result"]["hits"]):
                    self.assertEqual({hit["memory_id"] for hit in hits}, set(original_bytes))
                    for hit in hits:
                        self.assertEqual(hit["experience"]["provenance_summary"][count_key], 1)
        self.assertEqual(self.snapshot(), before_reads)

        # An old origin pin is not current authorization. Removing both new
        # attesters still excludes their records from both language views.
        self.revoke("B")
        self.revoke("C")
        rejected, signed = self.inspect_typescript(root, records)
        self.assertEqual(signed[1:], [None, None])
        self.assertEqual(rejected["experience"]["provenance_summary"][count_key], 0)
        self.assertEqual(self.inspect_python(root["memory_id"])["experience"]["provenance_summary"][count_key], 0)
        self.assertEqual(self.pins(), original_pins)

    def test_python_to_typescript_reattestation_cannot_multiply_confirmations(self):
        self.assert_stable_republished_origin("independently_confirms", "independent_confirmation_count")

    def test_python_to_typescript_reattestation_cannot_multiply_contradictions(self):
        self.assert_stable_republished_origin("contradicts", "contradiction_count")

    def test_readonly_experience_views_do_not_backfill_missing_origin_pins(self):
        root, records = self.origin_records("independently_confirms")
        with contextlib.closing(self.vault._connect()) as db, db:
            for record in records[1:]:
                db.execute("DELETE FROM metadata WHERE key=?", ("state_author:" + record["memory_id"],))
        before = self.snapshot()
        actual, _ = self.inspect_typescript(root, records)
        expected = self.inspect_python(root["memory_id"])
        for summary in (actual["experience"]["provenance_summary"], expected["experience"]["provenance_summary"]):
            self.assertEqual(summary["independent_confirmation_count"], 0)
            self.assertEqual(summary["unattributed_evidence_count"], 2)
            self.assertTrue(summary["origin_identity_incomplete"])
            self.assertTrue(summary["truncated"])
        for profile in RETRIEVAL_PROFILES:
            for handoff in (False, True):
                request = {"query": "Synthetic origin review", "limit": 4, "include_experience": True,
                           "ranking_profile": profile, "handoff": handoff}
                ts = self.successful(self.run_ts([{"op": "retrieve", "value": request}], trust=self.active_trust()))[0]
                result = self.vault.handle({"op": "handoff" if handoff else "recall",
                    **{key: value for key, value in request.items() if key != "handoff"}})
                self.assertTrue(result["ok"], result)
                for hits in (ts["hits"], result["result"]["hits"]):
                    for hit in hits:
                        summary = hit["experience"]["provenance_summary"]
                        self.assertEqual(summary["independent_confirmation_count"], 0)
                        self.assertTrue(summary["origin_identity_incomplete"])
                        self.assertTrue(summary["truncated"])
        self.assertEqual(self.snapshot(), before)
        for record in records[1:]:
            self.assertNotIn("state_author:" + record["memory_id"], self.pins())

    def test_unsigned_readmission_does_not_discard_the_stable_signed_origin(self):
        root, records = self.origin_records("independently_confirms")
        original_pins = self.pins()
        self.revoke("P")
        self.vault.ingest_records(records[1:], admission="accepted_unsigned")
        self.assertEqual(self.pins(), original_pins)
        actual, signed = self.inspect_typescript(root, records)
        self.assertIsNone(signed[1]["attestation"])
        self.assertIsNone(signed[2]["attestation"])
        expected = self.inspect_python(root["memory_id"])
        self.assertEqual(actual["experience"]["provenance_summary"], expected["experience"]["provenance_summary"])
        self.assertEqual(actual["experience"]["provenance_summary"]["independent_confirmation_count"], 1)
        self.assertFalse(actual["experience"]["provenance_summary"]["origin_identity_incomplete"])
        for record in records[1:]:
            state = self.inspect_python(record["memory_id"])
            self.assertEqual(state["verification"]["admission"], "accepted_unsigned")
            self.assertFalse(state["verification"]["signature_verified_at_admission"])
            self.assertEqual(self.pins()["state_author:" + record["memory_id"]], self.identities["P"].key_id)

    def test_invalid_origin_pins_cannot_fall_back_to_current_attesters(self):
        root, records = self.origin_records("contradicts")
        with contextlib.closing(self.vault._connect()) as db, db:
            for record in records[1:]:
                db.execute("UPDATE metadata SET value=? WHERE key=?", ("synthetic-invalid-key-id",
                           "state_author:" + record["memory_id"]))
        before = self.snapshot()
        actual, signed = self.inspect_typescript(root, records)
        self.assertTrue(all(value is not None for value in signed))
        expected = self.inspect_python(root["memory_id"])
        for summary in (actual["experience"]["provenance_summary"], expected["experience"]["provenance_summary"]):
            self.assertEqual(summary["contradiction_count"], 0)
            self.assertEqual(summary["unattributed_evidence_count"], 2)
            self.assertTrue(summary["origin_identity_incomplete"])
            self.assertTrue(summary["truncated"])
        self.assertEqual(self.snapshot(), before)


if __name__ == "__main__":
    unittest.main()
