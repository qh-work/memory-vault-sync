"""Real local ACK binding/empty commits using fresh synthetic node databases."""
import copy
import hashlib
import json
import sqlite3
import unittest
from unittest.mock import patch

from memory_vault import canonical_bytes
import memory_vault_open_repair_empty as empty
import memory_vault_open_repair_history as history
from memory_vault_open_repair_empty_state import RepairAckEmptyState
import memory_vault_open_repair_access as access
import memory_vault_open_repair_wire as wire
from tests.open_repair_ack_fixtures import reference, signed_entry
from tests import test_open_repair_state as source_tests


def bound_inputs(f, *, message_id=None, envelope_ref=None, revision=2):
    owner = f["signers"]["owner"]
    slot = f["expected"]["expected_ack_slot"]
    root = slot["root_key"]
    caps = copy.deepcopy(f["docs"]["root"]["payload"]["budget"])
    envelope_raw = b"synthetic exact encrypted-message reference for ACK transition"
    envelope_ref = envelope_ref or dict(namespace="object", key="ed" * 32,
        raw_sha256=hashlib.sha256(envelope_raw).hexdigest(), size=len(envelope_raw))
    write = dict(schema_version="memory-vault-open-repair/v1", kind="ack.write_grant",
        signing_key=owner.public_descriptor(), issued_at=2_000_000_007, expires_at=2_000_000_750,
        grant_id=slot["grant_id"], ack_slot=slot, root_authority_ref=f["entries"]["root"]["ref"],
        owner=root["owner"], receipt_writer=slot["receipt_writer"], message_id=message_id or "msg_" + "aa" * 32,
        envelope_ref=envelope_ref, operation="receipt.put", max_receipts=1, budget=caps,
        windows={name:2_000_000_700 for name in ("admit_until", "read_until", "copy_until", "publish_until", "retain_until")}, revision=1)
    write_entry = signed_entry(write, owner, "bound-write-" + write["message_id"])
    grant = dict(schema_version="memory-vault-open-repair/v1", kind="bootstrap.grant",
        signing_key=owner.public_descriptor(), issued_at=2_000_000_007, expires_at=2_000_000_700,
        grant_id="synthetic_offer_bootstrap", revision=1, owner=root["owner"], subject=slot["receipt_writer"],
        root_key=root, consumer="ack_offer", selector=dict(
            root_key_sha256=hashlib.sha256(canonical_bytes(root)).hexdigest(),
            ack_slot_sha256=hashlib.sha256(canonical_bytes(slot)).hexdigest(),
            root_authority_sha256=f["entries"]["root"]["ref"]["raw_sha256"],
            write_grant_sha256=write_entry["ref"]["raw_sha256"]),
        parent_authority_ref=f["entries"]["root"]["ref"], caller_authority_ref=write_entry["ref"],
        probe_until=2_000_000_650, proof_until=2_000_000_650, upload_until=2_000_000_650,
        probe_profile="opaque_v1", response_profile="ack_offer_service_v1",
        upload_roles=["ack.root_authority", "ack.write_grant", "bootstrap.grant"],
        limits=copy.deepcopy(f["expected"]["limit_policy"]))
    offer = signed_entry(grant, owner, "offer-bootstrap-" + write["message_id"])
    scopes = []
    for kind, entry in (("ack.root_authority", f["entries"]["root"]), ("ack.read_grant", f["entries"]["read"]),
                        ("bootstrap.grant", f["entries"]["bootstrap"]), ("ack.write_grant", write_entry), ("bootstrap.grant", offer)):
        scopes.append(dict(kind="authority", root_key=root, authority_kind=kind, authority_sha256=entry["ref"]["raw_sha256"]))
    scopes.append(dict(kind="ack_slot", root_key=root, ack_slot=slot))
    owner_status = copy.deepcopy(f["docs"]["owner_status"]["payload"])
    owner_status.update(revision=revision, issued_at=2_000_000_007, entries=sorted([
        dict(scope_kind=item["kind"], scope_id=hashlib.sha256(canonical_bytes(item)).hexdigest(),
             minimum_document_revision=0, status="active", operation_mask=127) for item in scopes],
        key=lambda item:(item["scope_kind"], item["scope_id"])))
    statuses = [signed_entry(owner_status, owner, "bound-owner-status-" + str(revision)), f["entries"]["target_status"]]
    expected = dict(expected_receipt_writer=dict(signing_key=f["signers"]["writer"].public_descriptor(),
        encryption_key=f["encryption"]["writer"].public_descriptor()), expected_message_id=write["message_id"],
        expected_envelope_ref=envelope_ref, current_statuses=statuses, read_until=2_000_000_600, retain_until=2_000_000_950)
    return write_entry, offer, expected


class OpenRepairEmptyTests(unittest.TestCase):
    def setUp(self):
        self.h = source_tests.RepairStateTests()
        self.h.setUp()
        f = self.h.fixture
        # Reserving both real generations costs more than the original
        # unbound-only fixture. Change the actual A allocation first, then let
        # the source issue a correspondingly reserved offer/active result.
        allocation = copy.deepcopy(f["docs"]["allocate"]["payload"])
        allocation["intent"]["budget"]["max_meta_bytes"] = 524288
        allocation["intent_sha256"] = hashlib.sha256(canonical_bytes(allocation["intent"])).hexdigest()
        f["entries"]["allocate"] = signed_entry(allocation, f["signers"]["owner"], "allocate")
        f["docs"]["allocate"] = json.loads(f["entries"]["allocate"]["raw"])
        for name in ("root", "read"):
            f["docs"][name]["payload"]["budget"]["max_meta_bytes"] = 524288
        f["docs"]["root"]["payload"]["allowed_roles"] = sorted(set(f["docs"]["root"]["payload"]["allowed_roles"]) |
            {"ack_offer_service_v1", "bootstrap.ack_offer", "historical.status.ack_write", "historical.status.ack_offer_bootstrap"})
        self.h.activate()
        f["custody"] = self.h.finalize()
        self.h.now[0] = 2_000_000_007
        self.empty = RepairAckEmptyState(self.h.state)
        self.empty.initialize()
        self.write, self.offer, self.expected = bound_inputs(f)

    def tearDown(self):
        self.h.tearDown()

    def bind(self, **changes):
        return self.empty.bind(self.h.resource_id, self.write, self.offer, **(self.expected | changes))

    def assertCode(self, code, callback, *args, **kwargs):
        with self.assertRaises(wire.RepairWireError) as caught:
            callback(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def verify(self, result, additional_packs=()):
        policy = self.h.state.policy
        budget = wire.RepairBudget(policy)
        resolver = wire.LocalRawResolver(policy, budget)
        for namespace, key, raw in self.h.db.execute("""SELECT o.namespace,o.opaque_key,o.raw FROM open_repair_ack_objects o
            JOIN open_repair_ack_pins p ON o.namespace=p.namespace AND o.opaque_key=p.opaque_key
            WHERE p.resource_id=? AND p.role IN ('pack','empty:pack')""", (self.h.resource_id,)):
            resolver.put(namespace, key, bytes(raw))
        for entry in additional_packs:
            resolver.put(entry["ref"]["namespace"], entry["ref"]["key"], entry["raw"])
        f = self.h.fixture
        return empty.verify_ack_empty_source_event(result["manifest"], resolver, result["custody"],
            **f["expected"], **{name:self.expected[name] for name in
                ("expected_receipt_writer", "expected_message_id", "expected_envelope_ref")}, policy=policy, budget=budget)

    def rebuild_outer(self, result, *, binding_changes=None, binding_signer=None,
                      omit=(), replacements=None, custody_changes=None):
        policy = self.h.state.policy
        manifest = json.loads(result["manifest"]["raw"])
        roles = {}
        for row in manifest["roles"]:
            ref = row["document_ref"]
            raw = self.h.db.execute("SELECT raw FROM open_repair_ack_objects WHERE namespace=? AND opaque_key=?",
                (ref["namespace"], ref["key"])).fetchone()[0]
            roles[row["role"]] = dict(raw=bytes(raw), ref=ref)
        if binding_changes is not None or binding_signer is not None:
            payload = json.loads(roles["ack.binding"]["raw"])["payload"]
            payload.update(binding_changes or {})
            signer = binding_signer or self.h.fixture["signers"]["target"]
            payload["signing_key"] = signer.public_descriptor()
            roles["ack.binding"] = signed_entry(payload, signer, "changed-binding")
        roles.update(replacements or {})
        for role in omit:
            del roles[role]
        packed = wire.build_raw_pack(list({entry["raw"] for entry in roles.values()}), policy, wire.RepairBudget(policy))
        positions = {entry.raw_sha256:index for index, entry in enumerate(packed.entries)}
        rows = [dict(role=role, document_ref=entry["ref"], pack_ref=packed.ref.as_dict(),
            entry_index=positions[entry["ref"]["raw_sha256"]]) for role, entry in roles.items()]
        rows.sort(key=lambda item:(item["role"], *history._ref_tuple(item["document_ref"])))
        manifest.update(roles=rows, binding_ref=roles["ack.binding"]["ref"])
        raw = canonical_bytes(manifest)
        new_manifest = dict(raw=raw, ref=reference(raw, "changed-empty-manifest"))
        payload = json.loads(result["custody"]["raw"])["payload"]
        payload.update(historical_manifest_ref=new_manifest["ref"], binding_ref=roles["ack.binding"]["ref"])
        payload.update(custody_changes or {})
        custody = signed_entry(payload, self.h.fixture["signers"]["target"], "changed-empty-custody")
        return result | {"manifest":new_manifest, "custody":custody}, [dict(raw=packed.raw, ref=packed.ref.as_dict())]

    def test_real_bind_commit_independent_full_closure_and_restart_exact_retry(self):
        result = self.bind()
        checked = self.verify(result)
        self.assertEqual(checked.predecessor.custody.raw, self.h.fixture["custody"]["raw"])
        self.assertEqual(checked.binding.raw, result["binding"]["raw"])
        self.assertEqual(checked.authorities.originals["write"].raw, self.write["raw"])
        self.assertEqual(checked.stored_at, self.h.now[0])
        self.assertEqual(len(checked.manifest.roles), 12)
        self.assertEqual(self.h.db.execute("SELECT status FROM open_repair_ack_resources").fetchone()[0], "empty")
        before = self.h.db.execute("SELECT metadata_bytes FROM open_repair_ack_resources").fetchone()[0]
        self.assertEqual(self.bind(), result)
        self.assertEqual(self.h.db.execute("SELECT metadata_bytes FROM open_repair_ack_resources").fetchone()[0], before)
        self.h.db.close()
        self.h.connect()
        self.empty = RepairAckEmptyState(self.h.state)
        self.empty.initialize()
        self.assertEqual(self.bind(), result)
        with self.assertRaises(TypeError):
            checked.binding.payload["grant_ref"]["key"] = "0" * 64

    def test_existing_unbound_remote_service_explicitly_refuses_empty(self):
        self.bind()
        old_access = access.RepairAckAccess(self.h.state)
        self.assertCode("repair_resource_inactive", old_access.prepare, self.h.resource_id, action="proof")

    def test_invalid_caller_cannot_poison_existing_slot(self):
        self.assertCode("repair_ack_bound_mismatch", self.bind, expected_message_id="msg_" + "bb" * 32)
        self.assertEqual(self.h.db.execute("SELECT status FROM open_repair_ack_resources").fetchone()[0], "unbound")
        self.assertEqual(self.h.db.execute("SELECT count(*) FROM open_repair_ack_binding_conflicts").fetchone()[0], 0)
        self.bind()
        changed = json.loads(self.write["raw"])
        changed["payload"]["message_id"] = "msg_" + "cc" * 32
        forged = signed_entry(changed["payload"], self.h.fixture["signers"]["writer"], "forged")
        self.assertCode("repair_wrong_issuer", self.empty.bind, self.h.resource_id, forged, self.offer, **self.expected)
        self.assertEqual(self.h.db.execute("SELECT status FROM open_repair_ack_resources").fetchone()[0], "empty")
        self.assertEqual(self.h.db.execute("SELECT count(*) FROM open_repair_ack_binding_conflicts").fetchone()[0], 0)

    def test_valid_same_grant_changed_message_retains_conflict_and_denies_retry(self):
        original = self.bind()
        write, offer, expected = bound_inputs(self.h.fixture, message_id="msg_" + "bc" * 32, revision=3)
        self.assertCode("repair_binding_conflict", self.empty.bind, self.h.resource_id, write, offer, **expected)
        conflict = self.h.db.execute("SELECT raw,retained FROM open_repair_ack_binding_conflicts").fetchone()
        self.assertEqual((bytes(conflict[0]), conflict[1]), (write["raw"], 1))
        self.assertEqual(self.h.db.execute("SELECT status FROM open_repair_ack_resources").fetchone()[0], "conflicted")
        self.assertEqual(self.h.db.execute("SELECT count(*) FROM open_repair_ack_bindings").fetchone()[0], 1)
        with self.assertRaises(wire.RepairWireError):
            self.bind()
        self.assertEqual(self.verify(original).custody.raw, original["custody"]["raw"])

    def test_mutations_and_crypto_are_outside_writer_and_commit_failure_has_no_new_outputs(self):
        signer_type = type(self.h.state.identity)
        signer = signer_type.sign_message
        calls = []
        def checked_sign(identity, payload):
            self.assertFalse(self.h.db.in_transaction)
            calls.append(payload["kind"])
            return signer(identity, payload)
        self.h.db.execute("CREATE TRIGGER synthetic_empty_failure BEFORE INSERT ON open_repair_ack_bindings BEGIN SELECT RAISE(ABORT,'synthetic_failure'); END")
        self.h.db.commit()
        before = self.h.db.execute("SELECT count(*) FROM open_repair_ack_pins").fetchone()[0]
        with patch.object(signer_type, "sign_message", new=checked_sign):
            with self.assertRaises(sqlite3.IntegrityError):
                self.bind()
        self.assertEqual(calls, ["ack.binding", "ack.slot_custody", "ack.head"])
        self.assertEqual(self.h.db.execute("SELECT count(*) FROM open_repair_ack_pins").fetchone()[0], before)
        self.assertEqual(self.h.db.execute("SELECT status FROM open_repair_ack_resources").fetchone()[0], "unbound")
        self.assertEqual(self.h.db.execute("SELECT count(*) FROM open_repair_ack_bindings").fetchone()[0], 0)
        self.assertGreater(self.h.db.execute("SELECT count(*) FROM open_repair_access_documents").fetchone()[0], 0)
        self.h.db.execute("DROP TRIGGER synthetic_empty_failure")
        self.h.db.commit()
        hash_original = wire.RepairBudget._hash
        def checked_hash(meter, raw):
            self.assertFalse(self.h.db.in_transaction)
            return hash_original(meter, raw)
        with patch.object(wire.RepairBudget, "_hash", new=checked_hash):
            self.bind()

    def test_admit_revocation_is_persisted_and_stale_active_cannot_restore(self):
        payload = json.loads(self.expected["current_statuses"][0]["raw"])["payload"]
        payload["revision"] = 3
        for item in payload["entries"]:
            if item["scope_kind"] == "ack_slot":
                item.update(status="revoked", operation_mask=1)
        revoked = signed_entry(payload, self.h.fixture["signers"]["owner"], "revoked-admit")
        self.assertCode("repair_authority_revoked", self.bind,
                        current_statuses=[revoked, self.expected["current_statuses"][1]])
        self.assertEqual(self.h.db.execute("SELECT status FROM open_repair_ack_resources").fetchone()[0], "unbound")
        self.assertEqual(self.h.db.execute("SELECT count(*) FROM open_repair_ack_bindings").fetchone()[0], 0)
        self.assertCode("repair_authority_revoked", self.bind)

    def test_capacity_refusal_keeps_new_current_status_floors(self):
        # Keep enough room for the new small current-status ledger, but none
        # for the exact new pack/manifest/binding/custody commit.
        self.h.db.execute("UPDATE open_repair_ack_resources SET metadata_bytes=?", (507000,))
        self.h.db.commit()
        self.assertCode("repair_insufficient_capacity", self.bind)
        self.assertEqual(self.h.db.execute("SELECT status FROM open_repair_ack_resources").fetchone()[0], "unbound")
        self.assertEqual(self.h.db.execute("SELECT count(*) FROM open_repair_ack_bindings").fetchone()[0], 0)
        self.assertEqual(self.h.db.execute("SELECT max(revision) FROM open_repair_access_documents WHERE issuer=?",
            (self.h.fixture["signers"]["owner"].key_id,)).fetchone()[0], 2)

    def test_missing_new_pin_or_changed_original_is_incomplete_after_restart(self):
        result = self.bind()
        self.h.db.execute("DELETE FROM open_repair_ack_pins WHERE role='empty:head'")
        self.h.db.commit()
        self.assertCode("repair_storage_corrupt", self.bind)
        ref = result["head"]["ref"]
        self.h.db.execute("INSERT INTO open_repair_ack_pins VALUES(?,?,?,?)",
            (self.h.resource_id, ref["namespace"], ref["key"], "empty:head"))
        self.h.db.execute("UPDATE open_repair_ack_objects SET raw=? WHERE opaque_key=?", (b"corrupt", ref["key"]))
        self.h.db.commit()
        self.assertCode("repair_storage_corrupt", self.bind)

    def test_mid_assembly_admit_revocation_is_checked_before_publication(self):
        original_build = self.empty._build
        payload = json.loads(self.expected["current_statuses"][0]["raw"])["payload"]
        payload["revision"] = 3
        for item in payload["entries"]:
            if item["scope_kind"] == "ack_slot":
                item.update(status="revoked", operation_mask=1)
        revoked = signed_entry(payload, self.h.fixture["signers"]["owner"], "mid-build-revocation")
        def changed_during_build(held, budget):
            result = original_build(held, budget)
            other = self.empty.access.prepare_bind(self.h.resource_id, self.write, self.offer,
                **(self.expected | {"current_statuses": [revoked, self.expected["current_statuses"][1]]}),
                budget=wire.RepairBudget(self.h.state.policy))
            with self.h.state._transaction():
                decision = self.empty.access.check_locked(other)
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.code, "repair_authority_revoked")
            return result
        with patch.object(self.empty, "_build", side_effect=changed_during_build):
            self.assertCode("repair_authority_revoked", self.bind)
        self.assertEqual(self.h.db.execute("SELECT count(*) FROM open_repair_ack_bindings").fetchone()[0], 0)
        self.assertEqual(self.h.db.execute("SELECT count(*) FROM open_repair_ack_pins WHERE role LIKE 'empty:%'").fetchone()[0], 0)

    def test_source_generation_and_actual_capacity_reservation_cannot_change_mid_build(self):
        original_build = self.empty._build
        def changed_during_build(held, budget):
            result = original_build(held, budget)
            self.h.db.execute("UPDATE open_repair_ack_resources SET retain_until=retain_until+1")
            self.h.db.commit()
            return result
        with patch.object(self.empty, "_build", side_effect=changed_during_build):
            self.assertCode("repair_access_generation", self.bind)
        self.h.db.execute("UPDATE open_repair_ack_resources SET retain_until=retain_until-1")
        self.h.db.execute("UPDATE open_capacity_reservations SET charge_bytes=charge_bytes-1 WHERE service='ack'")
        self.h.db.commit()
        self.assertCode("repair_capacity_reservation_missing", self.bind)
        self.assertEqual(self.h.db.execute("SELECT count(*) FROM open_repair_ack_bindings").fetchone()[0], 0)

    def test_conflict_without_payload_capacity_records_explicit_denial(self):
        self.bind()
        # The current-status charge is pre-admitted before exhausting payload
        # capacity, so refusal here exercises the fixed conflict denial row.
        write, offer, expected = bound_inputs(self.h.fixture, message_id="msg_" + "cf" * 32, revision=3)
        prepared = self.empty.access.prepare_bind(self.h.resource_id, write, offer,
            **expected, budget=wire.RepairBudget(self.h.state.policy))
        with self.h.state._transaction():
            self.assertTrue(self.empty.access.check_locked(prepared).allowed)
            self.h.db.execute("UPDATE open_repair_ack_resources SET metadata_bytes=524288")
        self.assertCode("repair_binding_conflict_capacity", self.empty.bind, self.h.resource_id, write, offer, **expected)
        self.assertEqual(self.h.db.execute("SELECT raw,retained FROM open_repair_ack_binding_conflicts").fetchone(), (None, 0))
        self.assertEqual(self.h.db.execute("SELECT status FROM open_repair_ack_resources").fetchone()[0], "conflicted")

    def test_independent_verifier_rejects_wrong_binding_signer_ref_and_causal_order(self):
        result = self.bind()
        changes = (
            {"binding_signer": self.h.fixture["signers"]["owner"]},
            {"binding_changes": {"grant_ref": self.write["ref"] | {"key":"0" * 64}}},
            {"binding_changes": {"bound_at": 2_000_000_006}},
            {"binding_changes": {"retain_until": 2_000_000_800}},
            {"custody_changes": {"read_until": 2_000_000_701}},
        )
        for change in changes:
            altered, packs = self.rebuild_outer(result, **change)
            with self.subTest(change=change), self.assertRaises(wire.RepairWireError):
                self.verify(altered, packs)

    def test_independent_verifier_requires_real_predecessor_and_every_direct_role(self):
        result = self.bind()
        for role in ("ack.unbound_custody", "historical.status.ack_write", "historical.status.ack_offer_bootstrap"):
            altered, packs = self.rebuild_outer(result, omit=(role,))
            self.assertCode("repair_invalid_ack_empty", self.verify, altered, packs)
        summary = canonical_bytes(dict(verified=True, state="unbound", source_digest=self.h.fixture["manifest"]["ref"]["raw_sha256"]))
        altered, packs = self.rebuild_outer(result, replacements={"history.ack_unbound": dict(raw=summary, ref=reference(summary,"fake-summary"))})
        self.assertCode("repair_invalid_history", self.verify, altered, packs)

    def test_independent_verifier_checks_whole_multiscope_status_and_revision_conflict(self):
        result = self.bind()
        source = json.loads(self.expected["current_statuses"][0]["raw"])["payload"]
        for conflict in (False, True):
            payload = copy.deepcopy(source)
            if conflict:
                payload["revision"] = 1  # Different whole body from the real unbound R1.
            else:
                for item in payload["entries"]:
                    if item["scope_kind"] == "ack_slot":
                        item["operation_mask"] = 66  # READ/RETAIN do not imply ADMIT.
            changed = signed_entry(payload, self.h.fixture["signers"]["owner"], "changed-whole-owner-status")
            replacements = {role:changed for role in empty.STATUS_ROLES if role != "historical.status.ack_resource"}
            altered, packs = self.rebuild_outer(result, replacements=replacements)
            self.assertCode("repair_status_conflict" if conflict else "repair_status_operation", self.verify, altered, packs)


if __name__ == "__main__":
    unittest.main()
