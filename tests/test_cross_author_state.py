"""Synthetic signed cross-author state views; immutable record/v1 is unchanged."""
from __future__ import annotations

import contextlib
from pathlib import Path
import tempfile
import unittest

import memory_vault as core
from memory_vault_trust import Identity, TrustStore


class CrossAuthorStateTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="memory-cross-author-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()
        self.path = self.directory / "vault.sqlite3"
        self.trust = TrustStore(self.directory / "trust.json")
        self.identities = {name: Identity.generate(self.directory / (name + ".json")) for name in "ABC"}
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

    def remember(self, author, text, *, relations=()):
        return self.ask("remember", writer=self.vaults[author], kind="fact", text=text,
                        entities=["synthetic-state-boundary"], relations=list(relations))["memory_id"]

    def test_cross_author_cannot_retire_or_promote_a_replacement_witness(self):
        for relation in ("supersedes", "resolves"):
            with self.subTest(relation=relation):
                target = self.remember("A", "Synthetic marker " + relation)
                before = self.ask("get", memory_id=target)["record"]
                proposal = self.remember("B", "Other author's suggestion " + relation,
                                         relations=[{"type": relation, "target": target}])
                self.assertEqual(self.ask("get", memory_id=target)["status"], "current")
                with contextlib.closing(self.vault._connect(writable=False)) as db:
                    self.assertEqual(core.Vault._historical_memory_ids(db, [target]), set())
                    self.assertEqual(core.Vault._current_state_witness_ids(db, [target], through=None), ([], False))
                    proof = core.strict_json_loads(db.execute(
                        "SELECT attestation_json FROM record_admissions WHERE memory_id=?", (target,)).fetchone()[0])
                graph = self.ask("memory.graph", memory_id=target)
                edge = next(edge for edge in graph["edges"] if edge["source_id"] == proposal)
                self.assertFalse(edge["state_effective"])
                self.assertEqual(edge["state_effective_reason"], "cross_author_proposal")
                views = self.ask("memory.views", memory_id=target)["views"]
                self.assertEqual({node["memory_id"] for view in views for node in view["timeline"]}, {target})
                for operation in ("recall", "handoff"):
                    for profile in core.RETRIEVAL_PROFILES:
                        hits = self.ask(operation, query="Synthetic marker " + relation,
                                        ranking_profile=profile, limit=1)["hits"]
                        self.assertEqual(hits[0]["memory_id"], target)
                        self.assertEqual(hits[0]["status"], "current")
                self.assertEqual(self.ask("get", memory_id=target)["record"], before)
                self.trust.verify_record(before, proof)

    def test_same_signer_correction_remains_effective(self):
        for relation, status in (("supersedes", "superseded"), ("resolves", "resolved")):
            with self.subTest(relation=relation):
                target = self.remember("A", "Same author original " + relation)
                replacement = self.remember("A", "Same author revision " + relation,
                                             relations=[{"type": relation, "target": target}])
                self.assertEqual(self.ask("get", memory_id=target)["status"], status)
                with contextlib.closing(self.vault._connect(writable=False)) as db:
                    self.assertEqual(core.Vault._historical_memory_ids(db, [target]), {target})
                    self.assertEqual(core.Vault._current_state_witness_ids(db, [target], through=None), ([replacement], False))
                graph = self.ask("memory.graph", memory_id=target)
                self.assertTrue(next(edge for edge in graph["edges"] if edge["source_id"] == replacement)["state_effective"])

    def test_local_unsigned_corrections_do_not_authorize_unsigned_imports(self):
        local = core.Vault(self.path)
        target = self.ask("remember", writer=local, kind="fact", text="Locally written original")["memory_id"]
        imported = core.build_record(kind="fact", text="Unattributed imported replacement",
                                     relations=[{"type": "supersedes", "target": target}])
        local.ingest_records([imported], admission="accepted_unsigned")
        self.assertEqual(self.ask("get", memory_id=target)["status"], "current")
        imported_target = core.build_record(kind="fact", text="Unattributed imported original")
        imported_revision = core.build_record(kind="fact", text="Another unattributed import",
                                             relations=[{"type": "resolves", "target": imported_target["memory_id"]}])
        local.ingest_records([imported_target, imported_revision], admission="accepted_unsigned")
        self.assertEqual(self.ask("get", memory_id=imported_target["memory_id"])["status"], "current")
        self.ask("remember", writer=local, kind="fact", text="Local correction",
                 relations=[{"type": "supersedes", "target": target}])
        self.assertEqual(self.ask("get", memory_id=target)["status"], "superseded")

    def test_third_party_cannot_close_a_conflict_but_endpoint_signer_can(self):
        original = self.remember("A", "Synthetic original conclusion")
        dissent = self.remember("B", "Synthetic independent dissent",
                                relations=[{"type": "conflicts_with", "target": original}])
        self.remember("C", "Synthetic third-party resolution",
                      relations=[{"type": "resolves", "target": dissent}])
        for memory_id in (original, dissent):
            self.assertEqual(self.ask("get", memory_id=memory_id)["status"], "conflicted")
        graph = self.ask("memory.graph", memory_id=original)
        edge = next(edge for edge in graph["edges"] if edge["type"] == "conflicts_with")
        self.assertIsNone(edge["resolution_memory_id"])
        resolution = self.remember("B", "Synthetic reconsidered own dissent",
                                  relations=[{"type": "resolves", "target": dissent}])
        self.assertEqual(self.ask("get", memory_id=original)["status"], "current")
        self.assertEqual(self.ask("get", memory_id=dissent)["status"], "resolved")
        graph = self.ask("memory.graph", memory_id=original)
        edge = next(edge for edge in graph["edges"] if edge["type"] == "conflicts_with")
        self.assertEqual(edge["resolution_memory_id"], resolution)
        self.assertEqual(edge["state_effective_reason"], "explicit_endpoint_resolution")

    def test_reimport_cannot_replace_an_active_origin_attestation(self):
        target = self.remember("A", "Synthetic signed original attribution")
        record = self.ask("get", memory_id=target)["record"]
        alternate = self.identities["B"].sign_record(record)
        self.trust.verify_record(record, alternate)
        self.vault.ingest_records([record], admission="verified", attestations={target: alternate})
        self.remember("B", "Synthetic alternate attester correction",
                      relations=[{"type": "supersedes", "target": target}])
        result = self.ask("get", memory_id=target)
        self.assertEqual(result["verification"]["signer_key_id"], self.identities["A"].key_id)
        self.assertEqual(result["status"], "current")
        self.assertEqual(core.canonical_bytes(result["record"]), core.canonical_bytes(record))

    def test_reattesting_revoked_author_restores_reading_without_taking_state_authority(self):
        target = self.remember("A", "Synthetic revoked author's original")
        former_revision = self.remember("A", "Synthetic revoked author's revision",
                                        relations=[{"type": "supersedes", "target": target}])
        records = [self.ask("get", memory_id=value)["record"] for value in (target, former_revision)]
        self.trust.revoke(self.identities["A"].key_id)
        for record in records:
            proof = self.identities["B"].sign_record(record)
            self.trust.verify_record(record, proof)
            self.vault.ingest_records([record], admission="verified", attestations={record["memory_id"]: proof})
        self.remember("B", "Synthetic new claim by replacement attester",
                      relations=[{"type": "supersedes", "target": target}])
        self.assertEqual(self.ask("get", memory_id=target)["status"], "current")
        with contextlib.closing(self.vault._connect(writable=False)) as db:
            for record in records:
                pinned = db.execute("SELECT value FROM metadata WHERE key=?",
                                    ("state_author:" + record["memory_id"],)).fetchone()[0]
                self.assertEqual(pinned, self.identities["A"].key_id)
        for record in records:
            result = self.ask("get", memory_id=record["memory_id"])
            self.assertTrue(result["verification"]["eligible_for_context"])
            self.assertEqual(result["verification"]["signer_key_id"], self.identities["B"].key_id)
            self.assertEqual(core.canonical_bytes(result["record"]), core.canonical_bytes(record))
        graph = self.ask("memory.graph", memory_id=target)
        self.assertTrue(all(not edge["state_effective"] for edge in graph["edges"]))

    def test_legacy_admission_is_pinned_before_its_old_proof_is_replaced(self):
        target = self.remember("A", "Synthetic pre-extension signed record")
        original = self.ask("get", memory_id=target)["record"]
        with contextlib.closing(self.vault._connect()) as db, db:
            # Model a legacy 0.26 database that predates optional state pins.
            db.execute("DELETE FROM metadata WHERE key=?", ("state_author:" + target,))
        self.assertEqual(self.ask("get", memory_id=target)["record"], original)
        self.trust.revoke(self.identities["A"].key_id)
        proof = self.identities["B"].sign_record(original)
        self.trust.verify_record(original, proof)
        self.vault.ingest_records([original], admission="verified", attestations={target: proof})
        self.remember("B", "Synthetic legacy record retirement proposal",
                      relations=[{"type": "resolves", "target": target}])
        result = self.ask("get", memory_id=target)
        self.assertEqual(result["status"], "current")
        self.assertEqual(result["record"], original)
        with contextlib.closing(self.vault._connect(writable=False)) as db:
            self.assertEqual(db.execute("SELECT value FROM metadata WHERE key=?",
                                        ("state_author:" + target,)).fetchone()[0], self.identities["A"].key_id)


if __name__ == "__main__":
    unittest.main()
