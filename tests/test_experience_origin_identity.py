"""Synthetic original-publisher identity remains distinct from re-attestation."""
from __future__ import annotations

from contextlib import closing
from pathlib import Path
import tempfile
import unittest

import memory_vault as core
import memory_vault_experience as experience
from memory_vault_trust import Identity, TrustStore
from memory_vault_agent import Agent
from memory_vault_client import CONFIG_SCHEMA
from memory_vault_storage import atomic_write


class ExperienceOriginIdentityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="experience-origin-identity-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()
        self.path = self.directory / "vault.sqlite3"
        self.trust = TrustStore(self.directory / "trust.json")
        self.identities = {name: Identity.generate(self.directory / (name + ".json")) for name in "APBC"}
        for identity in self.identities.values():
            self.trust.add(identity.public_descriptor())
        self.vaults = {name: core.Vault(self.path, signer=identity.sign_record,
                                      trust_check=self.trust.require_trusted)
                       for name, identity in self.identities.items()}
        self.vault = self.vaults["A"]

    def ask(self, operation, *, writer=None, **values):
        result = (writer or self.vault).handle({"op": operation, **values})
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["authority"], core.AUTHORITY)
        return result["result"]

    def remember(self, author, text, epistemic_type, relations=()):
        return self.ask("remember", writer=self.vaults[author], kind="observation", text=text,
            experience={"epistemic_type": epistemic_type, "relations": list(relations)})["memory_id"]

    def scenario(self, relation):
        root = self.remember("A", "Synthetic origin " + relation, "observation")
        records = []
        for index in range(2):
            memory_id = self.remember("P", f"Synthetic experiment {relation} number {index}", "experiment",
                                      [{"type": relation, "target": root}])
            records.append(self.ask("get", memory_id=memory_id)["record"])
        return root, records

    def summary(self, memory_id):
        return self.ask("get", memory_id=memory_id, include_experience=True)["experience"]["provenance_summary"]

    def pin(self, memory_id):
        with closing(self.vault._connect(writable=False)) as db:
            row = db.execute("SELECT value FROM metadata WHERE key=?", ("state_author:" + memory_id,)).fetchone()
        return row[0] if row is not None else None

    def reattest(self, author, record):
        proof = self.identities[author].sign_record(record)
        self.assertEqual(self.trust.verify_record(record, proof), self.identities[author].key_id)
        self.vault.ingest_records([record], admission="verified", attestations={record["memory_id"]: proof})
        return proof

    def assert_reaffirmed_origin(self, relation, count_field):
        root, records = self.scenario(relation)
        frozen = {record["memory_id"]: core.canonical_bytes(record) for record in records}
        self.assertEqual(self.summary(root)[count_field], 1)
        self.trust.revoke(self.identities["P"].key_id)
        self.assertEqual(self.summary(root)[count_field], 0)
        for author, record in zip("BC", records):
            self.reattest(author, record)
            self.reattest(author, record)  # duplicate import cannot create evidence
        result = self.summary(root)
        self.assertEqual(result[count_field], 1)
        self.assertFalse(result["truncated"])
        self.assertEqual(result["records_considered"], 3)
        for author, record in zip("BC", records):
            mid = record["memory_id"]
            self.assertEqual(self.pin(mid), self.identities["P"].key_id)
            current = self.ask("get", memory_id=mid)
            self.assertEqual(core.canonical_bytes(current["record"]), frozen[mid])
            self.assertEqual(current["verification"]["signer_key_id"], self.identities[author].key_id)
            self.assertTrue(current["verification"]["eligible_for_context"])
            self.assertFalse(current["verification"]["grants_authority"])
        # P remains revoked; pinning does not restore its signing/admission rights.
        with self.assertRaises(Exception):
            self.trust.require_trusted(self.identities["P"].key_id)
        self.trust.revoke(self.identities["B"].key_id)
        self.assertEqual(self.summary(root)[count_field], 1)
        self.trust.revoke(self.identities["C"].key_id)
        self.assertEqual(self.summary(root)[count_field], 0)

    def test_reaffirmed_confirmation_does_not_split_known_origin(self):
        self.assert_reaffirmed_origin("independently_confirms", "independent_confirmation_count")

    def test_reaffirmed_contradiction_does_not_split_known_origin(self):
        self.assert_reaffirmed_origin("contradicts", "contradiction_count")

    def test_verified_missing_pin_is_uncounted_and_explicitly_incomplete_without_write(self):
        root, records = self.scenario("independently_confirms")
        with closing(self.vault._connect()) as db, db:
            db.executemany("DELETE FROM metadata WHERE key=?", [("state_author:" + row["memory_id"],) for row in records])
        result = self.summary(root)
        self.assertEqual(result["independent_confirmation_count"], 0)
        self.assertEqual(result["unattributed_evidence_count"], 2)
        self.assertTrue(result["origin_identity_incomplete"])
        self.assertTrue(result["truncated"])
        for record in records:
            self.assertIsNone(self.pin(record["memory_id"]))
            self.assertEqual(self.ask("get", memory_id=record["memory_id"])["record"], record)

    def test_legacy_pin_can_be_preserved_from_old_proof_before_reaffirmation(self):
        root, records = self.scenario("contradicts")
        with closing(self.vault._connect()) as db, db:
            db.executemany("DELETE FROM metadata WHERE key=?", [("state_author:" + row["memory_id"],) for row in records])
        self.trust.revoke(self.identities["P"].key_id)
        for author, record in zip("BC", records):
            self.reattest(author, record)
            self.assertEqual(self.pin(record["memory_id"]), self.identities["P"].key_id)
        result = self.summary(root)
        self.assertEqual(result["contradiction_count"], 1)
        self.assertFalse(result["origin_identity_incomplete"])

    def test_unsigned_readmission_keeps_known_origin_without_state_authority(self):
        root, records = self.scenario("independently_confirms")
        self.trust.revoke(self.identities["P"].key_id)
        self.vault.ingest_records(records, admission="accepted_unsigned")
        self.assertEqual(self.summary(root)["independent_confirmation_count"], 1)
        for record in records:
            result = self.ask("get", memory_id=record["memory_id"])
            self.assertEqual(result["verification"]["admission"], "accepted_unsigned")
            self.assertFalse(result["verification"]["signature_verified_at_admission"])
            self.assertEqual(self.pin(record["memory_id"]), self.identities["P"].key_id)
            self.assertEqual(result["record"], record)
        # An unsigned imported state relation cannot retire a verified root.
        proposal = core.build_record(kind="decision", text="Synthetic unsigned proposal",
                                     relations=[{"type": "supersedes", "target": root}])
        self.vault.ingest_records([proposal], admission="accepted_unsigned")
        self.assertEqual(self.ask("get", memory_id=root)["status"], "current")

    def test_never_signed_records_keep_record_identity_without_authenticated_claim(self):
        vault = core.Vault(self.directory / "unsigned.sqlite3")
        response = vault.handle({"op": "remember", "kind": "observation", "text": "Synthetic unsigned origin",
                                 "experience": {"epistemic_type": "observation"}})
        root = response["result"]["memory_id"]
        records = [vault.handle({"op": "get", "memory_id": root})["result"]["record"]]
        for index in range(2):
            written = vault.handle({"op": "remember", "kind": "observation", "text": f"Synthetic unsigned experiment {index}",
                "experience": {"epistemic_type": "experiment", "relations": [{"type": "contradicts", "target": root}]}})
            self.assertTrue(written["ok"], written)
            records.append(vault.handle({"op": "get", "memory_id": written["result"]["memory_id"]})["result"]["record"])
        local = vault.handle({"op": "get", "memory_id": root, "include_experience": True})["result"]["experience"]
        accepted = core.Vault(self.directory / "accepted.sqlite3")
        accepted.ingest_records(records, admission="accepted_unsigned")
        copied = accepted.handle({"op": "get", "memory_id": root, "include_experience": True})["result"]["experience"]
        for result in (local, copied):
            self.assertEqual(result["contradiction_count"], 2)
            self.assertFalse(result["provenance_summary"]["independence_verified"])
            self.assertFalse(result["source"]["claims_authenticated"])
        direct = experience.summarize({record["memory_id"]: record for record in records}, root)
        self.assertEqual(direct["contradiction_count"], 2)


    def test_corrupted_present_pin_cannot_become_unsigned_record_fallback(self):
        root, records = self.scenario("contradicts")
        self.trust.revoke(self.identities["P"].key_id)
        self.vault.ingest_records(records, admission="accepted_unsigned")
        self.assertEqual(self.summary(root)["contradiction_count"], 1)
        with closing(self.vault._connect()) as db, db:
            db.executemany("UPDATE metadata SET value=? WHERE key=?",
                           [(bad, "state_author:" + record["memory_id"]) for bad, record in zip(("", "invalid"), records)])
        result = self.summary(root)
        self.assertEqual(result["contradiction_count"], 0)
        self.assertEqual(result["unattributed_evidence_count"], 2)
        self.assertTrue(result["origin_identity_incomplete"])
        self.assertTrue(result["truncated"])

    def test_one_unknown_identity_for_both_edge_types_is_not_double_counted(self):
        root = self.remember("A", "Synthetic mixed evidence root", "observation")
        claim = self.remember("P", "Synthetic mixed experimental claim", "experiment", [
            {"type": "independently_confirms", "target": root}, {"type": "contradicts", "target": root}])
        with closing(self.vault._connect()) as db, db:
            db.execute("DELETE FROM metadata WHERE key=?", ("state_author:" + claim,))
        result = self.summary(root)
        self.assertEqual(result["independent_confirmation_count"], 0)
        self.assertEqual(result["contradiction_count"], 0)
        self.assertEqual(result["unattributed_evidence_count"], 1)
        self.assertTrue(result["truncated"])

    def test_state_pins_do_not_override_current_ineligible_or_quarantined_proof(self):
        root, records = self.scenario("independently_confirms")
        graph = {record["memory_id"]: record for record in records}
        graph[root] = self.ask("get", memory_id=root)["record"]
        for rejected in ({"eligible_for_context": False}, {"admission": "quarantined"}):
            with self.subTest(rejected=rejected):
                proofs = {record["memory_id"]: {"local_origin_key_id": self.identities["P"].key_id,
                           "local_origin_key_present": True, **rejected} for record in records}
                self.assertEqual(experience.summarize(graph, root, proofs)["independent_confirmation_count"], 0)

    def test_core_profiles_and_agent_pages_share_stable_origin_summary(self):
        root = self.remember("A", "Synthetic origin workflow " + "evidence " * 250, "observation")
        records = []
        for index in range(2):
            memory_id = self.remember("P", f"Synthetic origin workflow experiment {index}", "experiment",
                                      [{"type": "independently_confirms", "target": root}])
            records.append(self.ask("get", memory_id=memory_id)["record"])
        self.trust.revoke(self.identities["P"].key_id)
        for author, record in zip("BC", records):
            self.reattest(author, record)
        for operation in ("recall", "handoff"):
            for profile in core.RETRIEVAL_PROFILES:
                for limit in (1, 4):
                    hits = self.ask(operation, query="Synthetic origin workflow", ranking_profile=profile,
                                    limit=limit, include_experience=True)["hits"]
                    self.assertTrue(hits)
                    self.assertTrue(all(hit["experience"]["independent_confirmation_count"] == 1 for hit in hits))
        config = self.directory / "client.json"
        atomic_write(config, core.canonical_bytes({"schema_version": CONFIG_SCHEMA, "vault_path": str(self.path),
                     "capture_visible_turns": False, "trust_path": str(self.trust.path)}), replace=False)
        agent = Agent(config)
        for handoff in (False, True):
            for profile in core.RETRIEVAL_PROFILES:
                response = agent.handle({"op": "recall", "query": "Synthetic origin workflow", "handoff": handoff,
                                         "ranking_profile": profile, "include_experience": True})
                pages = 0
                while True:
                    self.assertTrue(response["ok"], response)
                    self.assertTrue(all(hit["experience"]["independent_confirmation_count"] == 1
                                        for hit in response["result"]["hits"]))
                    pages += 1
                    cursor = response["result"]["next_cursor"]
                    if cursor is None:
                        break
                    self.assertLess(pages, 12)
                    response = agent.handle({"op": "recall", "cursor": cursor})
                self.assertGreater(pages, 1)


if __name__ == "__main__":
    unittest.main()
