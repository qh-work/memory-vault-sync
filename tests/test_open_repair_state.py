"""Actual local source writes, transaction failure and restart with fresh keys."""
import copy
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from memory_vault import canonical_bytes
from memory_vault_network_crypto import EncryptionIdentity
from memory_vault_open_repair_ack import verify_ack_unbound_source_event
from memory_vault_open_repair_state import RepairAckState
import memory_vault_open_repair_wire as wire
from tests.open_repair_ack_fixtures import ack_unbound_fixture, load_fixture, repack_fixture, signed_entry


class RepairStateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="memory-vault-synthetic-ack-")
        self.path = Path(self.temp.name) / "network.sqlite3"
        self.fixture = ack_unbound_fixture(capacity_overrides=getattr(self, "capacity_overrides", None),
            limit_overrides=getattr(self, "limit_overrides", None))
        self.now = [2_000_000_001]
        self.connect()

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def connect(self, **options):
        self.db = sqlite3.connect(self.path)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA trusted_schema=OFF")
        f = self.fixture
        self.state = RepairAckState(self.db, f["signers"]["target"], f["docs"]["descriptor"],
            encryption_identity=f["encryption"]["target"], limit_policy=f["expected"]["limit_policy"],
            clock=lambda: self.now[0], **options)
        self.state.initialize()

    def allocate(self):
        f = self.fixture
        offer = self.state.allocate(f["entries"]["allocate"], expected_owner=f["expected"]["expected_owner"])
        payload = json.loads(offer["raw"])["payload"]
        self.resource_id = payload["resource"]["resource_id"]
        f["entries"]["offer"], f["docs"]["offer"] = offer, json.loads(offer["raw"])
        return offer

    def owner_setup(self):
        f = self.fixture
        entries, docs = f["entries"], f["docs"]
        owner = f["signers"]["owner"]
        for name in ("root", "read", "bootstrap", "activation"):
            payload = copy.deepcopy(docs[name]["payload"])
            if name == "root":
                payload["original_resource_ref"] = docs["offer"]["payload"]["resource"]
                payload["original_resource_offer_ref"] = entries["offer"]["ref"]
            elif name == "read":
                payload["root_authority_ref"] = entries["root"]["ref"]
            elif name == "bootstrap":
                payload["parent_authority_ref"] = entries["root"]["ref"]
                payload["caller_authority_ref"] = entries["read"]["ref"]
                payload["selector"]["root_authority_sha256"] = entries["root"]["ref"]["raw_sha256"]
                payload["selector"]["read_grant_sha256"] = entries["read"]["ref"]["raw_sha256"]
            elif name == "activation":
                payload["scope"]["root_authority_ref"] = entries["root"]["ref"]
                payload["resource_offer_refs"] = [entries["offer"]["ref"]]
                payload["authority_refs"] = [{"role": "ack.read_grant", "ref": entries["read"]["ref"]},
                                              {"role": "ack.root_authority", "ref": entries["root"]["ref"]}]
            entries[name] = signed_entry(payload, owner, name)
            docs[name] = json.loads(entries[name]["raw"])
        return {name: entries[name] for name in ("root", "read", "bootstrap", "activation")}

    def activate(self):
        self.allocate()
        entries = self.owner_setup()
        self.now[0] = 2_000_000_005
        result = self.state.activate(self.resource_id, entries,
            expected_ack_slot=self.fixture["expected"]["expected_ack_slot"])
        f = self.fixture
        for name, held in (("active", result["active"]), ("target_status", result["status"])):
            f["entries"][name], f["docs"][name] = held, json.loads(held["raw"])
        root = f["expected"]["expected_ack_slot"]["root_key"]
        scopes = [dict(kind="authority", root_key=root, authority_kind=kind,
                       authority_sha256=f["entries"][name]["ref"]["raw_sha256"]) for name, kind in
                  (("root", "ack.root_authority"), ("read", "ack.read_grant"), ("bootstrap", "bootstrap.grant"))]
        scopes.append(dict(kind="ack_slot", root_key=root, ack_slot=f["expected"]["expected_ack_slot"]))
        payload = copy.deepcopy(f["docs"]["owner_status"]["payload"])
        payload["entries"] = sorted([dict(scope_kind=value["kind"],
            scope_id=hashlib.sha256(canonical_bytes(value)).hexdigest(), minimum_document_revision=0,
            status="active", operation_mask=127) for value in scopes], key=lambda v:(v["scope_kind"],v["scope_id"]))
        f["entries"]["owner_status"] = signed_entry(payload, f["signers"]["owner"], "owner_status")
        f["docs"]["owner_status"] = json.loads(f["entries"]["owner_status"]["raw"])
        repack_fixture(f)
        return result

    def finalize(self):
        self.now[0] = 2_000_000_006
        f = self.fixture
        return self.state.finalize_unbound(self.resource_id, f["manifest"], f["packs"],
            expected_ack_slot=f["expected"]["expected_ack_slot"], read_until=2_000_000_800, retain_until=2_000_000_950)

    def assertCode(self, code, callback, *args, **kwargs):
        with self.assertRaises(wire.RepairWireError) as caught:
            callback(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def test_allocate_activate_finalize_restart_reads_exact_pinned_originals(self):
        self.activate()
        custody = self.finalize()
        f = self.fixture
        resolver, policy, budget = load_fixture(f)
        verified = verify_ack_unbound_source_event(f["manifest"], resolver, custody,
            **f["expected"], policy=policy, budget=budget)
        self.assertEqual(verified.stored_at, self.now[0])
        self.assertEqual(self.db.execute("SELECT status FROM open_repair_ack_resources").fetchone()[0], "unbound")
        self.db.close()
        self.connect()
        for entry in [*f["entries"].values(), *f["packs"], f["manifest"], custody]:
            self.assertEqual(self.state.read_local_original(self.resource_id, entry["ref"]), entry["raw"])
        self.assertEqual(self.finalize(), custody)

    def test_offer_is_committed_exact_and_retry_does_not_rereserve(self):
        offer = self.allocate()
        before = self.db.execute("SELECT count(*) FROM open_capacity_reservations").fetchone()[0]
        self.db.close()
        self.connect()
        self.now[0] = 2_000_000_050
        self.assertEqual(self.allocate(), offer)
        self.assertEqual(self.db.execute("SELECT count(*) FROM open_capacity_reservations").fetchone()[0], before)
        self.assertFalse(self.db.in_transaction)

    def test_changed_request_locator_conflicts_even_with_identical_signed_bytes(self):
        self.allocate()
        entry = copy.deepcopy(self.fixture["entries"]["allocate"])
        entry["ref"]["key"] = "0" * 64
        self.assertCode("repair_allocation_conflict", self.state.allocate, entry,
                        expected_owner=self.fixture["expected"]["expected_owner"])

    def test_activation_retry_exact_bytes_and_changed_setup_conflicts(self):
        result = self.activate()
        inputs = {name: self.fixture["entries"][name] for name in ("root", "read", "bootstrap", "activation")}
        self.assertEqual(self.state.activate(self.resource_id, inputs,
            expected_ack_slot=self.fixture["expected"]["expected_ack_slot"]), result)
        slot = copy.deepcopy(self.fixture["expected"]["expected_ack_slot"])
        slot["slot_id"] = "different_expected_slot"
        self.assertCode("repair_activation_conflict", self.state.activate, self.resource_id, inputs,
                        expected_ack_slot=slot)
        changed = copy.deepcopy(inputs)
        changed["root"]["ref"]["key"] = "0" * 64
        self.assertCode("repair_activation_conflict", self.state.activate, self.resource_id, changed,
                        expected_ack_slot=self.fixture["expected"]["expected_ack_slot"])

    def test_failed_final_write_rolls_back_all_pins_and_custody(self):
        self.activate()
        self.db.execute("CREATE TRIGGER synthetic_fail BEFORE INSERT ON open_repair_ack_objects BEGIN SELECT RAISE(ABORT,'synthetic_failure'); END")
        self.db.commit()
        with self.assertRaises(sqlite3.IntegrityError):
            self.finalize()
        self.assertEqual(self.db.execute("SELECT count(*) FROM open_repair_ack_pins").fetchone()[0], 0)
        self.assertEqual(self.db.execute("SELECT count(*) FROM open_repair_ack_objects").fetchone()[0], 0)
        self.assertEqual(self.db.execute("SELECT status,custody FROM open_repair_ack_resources").fetchone(), ("active", None))
        self.db.execute("DROP TRIGGER synthetic_fail")
        self.db.commit()
        self.finalize()

    def test_changed_encryption_identity_cannot_rebind_persisted_state(self):
        self.allocate()
        other = RepairAckState(self.db, self.fixture["signers"]["target"], self.fixture["docs"]["descriptor"],
            encryption_identity=EncryptionIdentity.generate(), clock=lambda:self.now[0])
        self.assertCode("repair_storage_epoch_mismatch", other.initialize)

    def test_changed_stored_blob_is_detected_after_restart(self):
        self.activate()
        custody = self.finalize()
        self.db.execute("UPDATE open_repair_ack_objects SET raw=? WHERE opaque_key=?", (b"corrupt", custody["ref"]["key"]))
        self.db.commit()
        self.db.close()
        self.connect()
        self.assertCode("repair_storage_corrupt", self.state.read_local_original, self.resource_id, custody["ref"])

    def test_unrelated_local_reference_is_not_disclosed(self):
        self.activate(); self.finalize()
        ref = dict(self.fixture["manifest"]["ref"], key="0"*64)
        self.assertCode("repair_ref_missing", self.state.read_local_original, self.resource_id, ref)


if __name__ == "__main__":
    unittest.main()
