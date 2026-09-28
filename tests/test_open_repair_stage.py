"""Real synthetic Ed25519/X25519 staging, with no publication authority."""
import copy
import hashlib
import json
import struct
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from memory_vault import canonical_bytes
import memory_vault_network_crypto as crypto
import memory_vault_open_blob as blob
import memory_vault_open_repair_stage as stage
import memory_vault_open_repair_wire as wire
from tests.test_open_repair_probe import entry, policy, probe_fixture


def raw_ref(raw, *, namespace="meta", key=None):
    digest = hashlib.sha256(raw).hexdigest()
    return dict(namespace=namespace, key=key or digest, raw_sha256=digest, size=len(raw))


def stage_fixture():
    signers, encryption, expected = probe_fixture()
    expected = {name: expected[name] for name in ("expected_subject", "expected_target", "target_storage_epoch", "at")}
    dual = lambda key: dict(signing_key_id=key["signing_key"]["key_id"], encryption_key_id=key["encryption_key"]["key_id"])
    root = dict(owner=dual(expected["expected_subject"]), root_kind="ack_return", anchor_ref=dict(namespace="anchor", key="1" * 64),
                owner_epoch="synthetic_owner_epoch", root_id="synthetic_root")
    slot = dict(root_key=root, slot_id="synthetic_slot", receipt_writer=dual(expected["expected_target"]), grant_id="synthetic_grant")
    scope = dict(kind="ack_occupied", ack_slot=slot, grant_ref=raw_ref(b"grant"), binding_ref=raw_ref(b"binding"),
                 receipt_ref=raw_ref(b"receipt", namespace="object", key="c" * 64), original_ack_commit_ref=raw_ref(b"commit"))
    return signers, encryption, expected, root, scope


class OpenRepairStageTests(unittest.TestCase):
    def setUp(self):
        self.signers, self.encryption, self.expected, self.root, self.scope = stage_fixture()
        self.raw = b"synthetic original bytes:" + b"x" * stage.STAGE_CHUNK_BYTES

    def options(self, local=None, budget=None, **changes):
        local = local or policy(max_signature_checks=256)
        return self.expected | dict(policy=local, budget=budget or wire.RepairBudget(local)) | changes

    def rows(self):
        rows = [(role, raw_ref(role.encode())) for role in sorted(stage.SINGLE_STAGE_ROLES | {"current.status", "directory.status"})]
        rows.extend(("history.raw_pack", raw_ref(raw, key=key)) for raw, key in
                    ((self.raw, "f" * 64), (b"prior pack one", "d" * 64), (b"prior pack two", "e" * 64)))
        return sorted(rows, key=lambda item: (item[0], item[1]["namespace"], item[1]["key"], item[1]["raw_sha256"], item[1]["size"]))

    def manifest(self, rows=None, **changes):
        local = changes.pop("policy", policy())
        budget = changes.pop("budget", wire.RepairBudget(local))
        rows = self.rows() if rows is None else rows
        return stage.make_stage_manifest(root_key=self.root, scope=self.scope,
            children=[dict(index=i, role=role, ref=ref) for i, (role, ref) in enumerate(rows)],
            policy=local, budget=budget, **changes)

    def intent(self, *, manifest=None, **options):
        return stage.make_stage_intent(self.signers["subject"], allocation_id="synthetic_allocation",
            manifest=(manifest or self.manifest()).value, expires_at=self.expected["at"] + 50, **self.options(**options))

    def exchange(self, *, local=None, budget=None, locator=False):
        options = self.options(local, budget)
        intent = self.intent(local=local, budget=options["budget"])
        intent_entry = entry(intent)
        if locator:
            intent_entry["ref"]["key"] = "a" * 64
        challenge = stage.issue_stage_challenge(intent_entry, signer=self.signers["target"],
            expires_at=self.expected["at"] + 45, **options)
        answer = stage.solve_stage_challenge(intent_entry, entry(challenge.original), signer=self.signers["subject"],
            encryption_identity=self.encryption["subject"], expires_at=self.expected["at"] + 40, **options)
        handle = stage.make_stage_handle(intent_entry, entry(challenge.original), entry(answer), caller_nonce=challenge.nonce,
            signer=self.signers["target"], reservation_generation=7, expires_at=self.expected["at"] + 35, **options)
        return intent_entry, challenge, answer, handle

    def frame(self, intent, handle, *, offset=0, chunk=None, **options):
        chunk = self.raw[offset:offset + stage.STAGE_CHUNK_BYTES] if chunk is None else chunk
        index = next(child["index"] for child in json.loads(intent["raw"])["payload"]["manifest"]["children"] if child["ref"]["key"] == "f" * 64)
        return stage.make_stage_child_frame(intent, entry(handle), signer=self.signers["subject"], child_index=index,
            offset=offset, chunk=chunk, expires_at=self.expected["at"] + 30, **self.options(**options))

    def mutate(self, value, change, signer="subject"):
        document = json.loads(value["raw"])
        change(document["payload"])
        document["proof"] = self.signers[signer].sign_message(document["payload"])
        raw = canonical_bytes(document)
        return dict(raw=raw, ref=raw_ref(raw, key=value["ref"]["key"]))

    def frame_mutate(self, frame, change, signer="subject", chunk_change=None):
        hlen, clen = struct.unpack_from(">II", frame, len(blob.MAGIC))
        header = frame[blob.BLOB_PREFIX_BYTES:blob.BLOB_PREFIX_BYTES + hlen]
        changed = self.mutate(dict(raw=header, ref=raw_ref(header)), change, signer)
        chunk = frame[-clen:] if clen else b""
        if chunk_change:
            chunk = chunk_change(chunk)
        return blob.encode_blob_frame(json.loads(changed["raw"]), chunk)

    def assertRejects(self, function, *args, **kwargs):
        with self.assertRaises(wire.RepairWireError):
            function(*args, **kwargs)

    def test_real_dual_possession_transfer_receipts_and_close_share_one_budget(self):
        key_type = type(Ed25519PublicKey.from_public_bytes(b"a" * 32))
        verify, checks = key_type.verify, []
        def count(key, signature, data):
            checks.append(1)
            return verify(key, signature, data)
        counter = patch.object(key_type, "verify", new=count)
        counter.start()
        self.addCleanup(counter.stop)
        local = policy(max_signature_checks=64)
        budget = wire.RepairBudget(local)
        options = self.options(local, budget)
        intent, challenge, answer, handle = self.exchange(local=local, budget=budget, locator=True)
        self.assertEqual(budget.snapshot()["signature_checks"], 6)
        self.assertNotEqual(intent["ref"]["key"], intent["ref"]["raw_sha256"])
        self.assertEqual(handle.payload["bootstrap_use_ref"], None)
        assembled = []
        for offset in range(0, len(self.raw), stage.STAGE_CHUNK_BYTES):
            frame = self.frame(intent, handle, offset=offset, local=local, budget=budget)
            checked = stage.verify_stage_child_frame(frame, intent, entry(handle), **options)
            assembled.append(checked.chunk)
            self.assertEqual(checked.child_ref.key, "f" * 64)
            response = stage.make_stage_child_response_frame(frame, intent, entry(handle), signer=self.signers["target"],
                durable_prefix=offset + len(checked.chunk), expires_at=self.expected["at"] + 25, **options)
            receipt = stage.verify_stage_child_response_frame(response, frame, intent, entry(handle), **options)
            self.assertEqual(receipt.payload["child_ref"], checked.child_ref.as_dict())
            self.assertEqual(receipt.payload["durable_prefix"], offset + len(checked.chunk))
        self.assertEqual(b"".join(assembled), self.raw)
        self.assertEqual(hashlib.sha256(b"".join(assembled)).hexdigest(), raw_ref(self.raw)["raw_sha256"])
        close = stage.make_stage_close(intent, entry(handle), signer=self.signers["subject"],
            expires_at=self.expected["at"] + 20, **options)
        stage.verify_stage_close(entry(close), intent, entry(handle), **options)
        result = stage.make_stage_result(entry(close), intent, entry(handle), signer=self.signers["target"],
            expires_at=self.expected["at"] + 15, **options)
        verified = stage.verify_stage_result(entry(result), entry(close), intent, entry(handle), **options)
        self.assertEqual(verified.payload["reservation_generation"], 7)
        self.assertEqual(verified.payload["bootstrap_use_ref"], None)
        self.assertEqual(budget.snapshot()["signature_checks"], 42)
        self.assertEqual(budget.snapshot()["signature_checks"], len(checks))
        self.assertGreater(budget.snapshot()["hash_bytes"], len(self.raw))

    def test_challenge_is_actual_jwe_for_exact_subject_and_aad(self):
        intent, challenge, answer, _ = self.exchange()
        p = json.loads(challenge.original.raw)["payload"]
        jwe = p.pop("jwe")
        self.assertEqual(crypto.decrypt_bytes(jwe, self.encryption["subject"], context=p), challenge.nonce)
        self.assertRejects(stage.solve_stage_challenge, intent, entry(challenge.original), signer=self.signers["subject"],
            encryption_identity=self.encryption["target"], expires_at=self.expected["at"] + 30, **self.options())
        self.assertRejects(stage.verify_stage_answer, intent, entry(challenge.original), entry(answer),
            caller_nonce=b"0" * 32, **self.options())

    def test_identity_epoch_and_original_locator_cannot_be_substituted(self):
        intent, challenge, answer, handle = self.exchange(locator=True)
        _, _, other, _, _ = stage_fixture()
        for changes in (dict(expected_subject=other["expected_subject"]), dict(expected_target=other["expected_target"]),
                        dict(target_storage_epoch="different_epoch")):
            self.assertRejects(stage.verify_stage_handle, entry(handle), intent, **self.options(**changes))
        forged = copy.deepcopy(intent)
        forged["ref"]["key"] = "b" * 64
        self.assertRejects(stage.verify_stage_handle, entry(handle), forged, **self.options())
        self.assertRejects(stage.verify_stage_answer, forged, entry(challenge.original), entry(answer),
            caller_nonce=challenge.nonce, **self.options())

    def test_manifest_is_closed_sorted_finite_and_not_a_general_upload_namespace(self):
        for change in (
            lambda p: p["manifest"].update(consumer="ack_owner"),
            lambda p: p["manifest"].update(consumer="custody_accept"),
            lambda p: p["manifest"].update(url="https://invalid.example"),
            lambda p: p["manifest"]["scope"].update(kind="mailbox_feed"),
            lambda p: p["manifest"]["scope"].update(arbitrary_ref=raw_ref(b"x")),
            lambda p: p["manifest"]["children"][0].update(index=1),
            lambda p: p["manifest"]["children"][0].update(role="ack.index_publish"),
            lambda p: p["manifest"]["children"][0].update(role="proof.stage_result"),
            lambda p: p["manifest"]["children"][0]["ref"].update(namespace="object"),
            lambda p: p.update(requested_bytes=p["requested_bytes"] + 1),
            lambda p: p.update(requested_items=True),
            lambda p: p.update(manifest_sha256="0" * 64),
        ):
            bad = self.mutate(entry(self.intent()), change)
            self.assertRejects(stage.verify_stage_intent, bad, **self.options())

    def test_role_aliases_and_multiple_statuses_preserve_exact_ref_but_charge_each_child(self):
        base = self.rows()
        ref = next(ref for role, ref in base if role == "index.source_head")
        rows = base + [("current.status", ref)]
        rows.sort(key=lambda item: (item[0], item[1]["namespace"], item[1]["key"], item[1]["raw_sha256"], item[1]["size"]))
        intent = self.intent(manifest=self.manifest(rows))
        self.assertEqual(intent.payload["requested_items"], 14)
        self.assertEqual(intent.payload["requested_bytes"], sum(ref["size"] for _, ref in base) + ref["size"])
        self.assertRejects(self.manifest, list(reversed(rows)))
        self.assertRejects(self.manifest, sorted(rows + [rows[0]], key=lambda item: (item[0], item[1]["key"])))
        self.assertRejects(self.manifest, sorted(base + [("current.status", ref | dict(size=ref["size"] + 1))], key=lambda item: (item[0], item[1]["key"])))

    def test_object_receipt_ref_is_preserved_without_allowing_envelopes(self):
        original = self.intent()
        checked = stage.verify_stage_intent(entry(original), **self.options())
        self.assertEqual(checked.payload["manifest"]["scope"]["receipt_ref"], self.scope["receipt_ref"])
        ref = self.scope["receipt_ref"]
        self.assertRejects(self.manifest, self.rows() + [("recipient.receipt", ref)])
        self.assertRejects(self.manifest, [("ack.put", ref)])
        self.assertRejects(self.manifest, [("message.envelope", ref)])

    def test_declared_stage_capacity_never_increases_policy(self):
        self.assertRejects(self.manifest, policy=policy(max_retained_bytes=len(self.raw) - 1))
        self.assertRejects(self.manifest, policy=policy(max_document_bytes=1000))
        rows = [("current.status", raw_ref(str(i).encode())) for i in range(65)]
        rows.sort(key=lambda item: item[1]["key"])
        self.assertRejects(self.manifest, rows)
        rows = [("history.raw_pack", raw_ref(b"x") | dict(size=stage.MAX_STAGE_BYTES + 1))]
        self.assertRejects(self.manifest, rows, policy=policy(max_document_bytes=2 * stage.MAX_STAGE_BYTES))

    def test_selected_index_roster_rejects_missing_extra_and_historical_aliases(self):
        rows = self.rows()
        self.assertRejects(self.manifest, rows[1:])
        for alias in ("ack.head", "index.current_status", "history.ack_occupied_inputs", "resource.ack_allocate"):
            changed = [(alias if role == "index.source_head" else role, ref) for role, ref in rows]
            changed.sort(key=lambda item: (item[0], item[1]["key"]))
            self.assertRejects(self.manifest, changed)
        extra = rows + [("current.status", raw_ref(str(i).encode())) for i in range(16)]
        extra.sort(key=lambda item: (item[0], item[1]["key"]))
        self.assertRejects(self.manifest, extra)
        oversized = [(role, ref | dict(size=65536)) for role, ref in extra[:-1]]
        self.assertRejects(self.manifest, oversized)

    def test_old_or_extended_windows_and_forged_handle_are_rejected(self):
        intent, _, _, handle = self.exchange()
        self.assertRejects(stage.verify_stage_handle, entry(handle), intent, **self.options(at=self.expected["at"] + 35))
        for change in (
            lambda p: p.update(expires_at=self.expected["at"] + 51),
            lambda p: p.update(issued_at=self.expected["at"] - 1),
            lambda p: p.update(reserved_bytes=p["reserved_bytes"] + 1),
            lambda p: p.update(reserved_items=2),
            lambda p: p.update(bootstrap_use_ref=raw_ref(b"other")),
            lambda p: p.update(reservation_generation=True),
        ):
            bad = self.mutate(entry(handle), change, "target")
            self.assertRejects(stage.verify_stage_handle, bad, intent, **self.options())

    def test_frame_range_chunk_integrity_and_exact_handle_generation_are_bound(self):
        intent, _, _, handle = self.exchange()
        frame = self.frame(intent, handle)
        for change in (
            lambda p: p["binding"].update(kind="blob"),
            lambda p: p["binding"].update(handle_id="different_handle"),
            lambda p: p["binding"].update(child_index=1),
            lambda p: p["binding"].update(offset=1),
            lambda p: p.update(reservation_generation=8),
            lambda p: p.update(length=p["length"] - 1),
            lambda p: p.update(chunk_sha256="0" * 64),
            lambda p: p["handle_ref"].update(key="0" * 64),
            lambda p: p["manifest_ref"].update(key="0" * 64),
        ):
            self.assertRejects(stage.verify_stage_child_frame, self.frame_mutate(frame, change), intent, entry(handle), **self.options())
        self.assertRejects(stage.verify_stage_child_frame, frame[:-1] + b"z", intent, entry(handle), **self.options())
        self.assertRejects(self.frame, intent, handle, offset=1)
        self.assertRejects(self.frame, intent, handle, chunk=self.raw[:5])

    def test_whole_single_chunk_ref_catches_signed_wrong_original(self):
        self.raw = b"one child"
        intent, _, _, handle = self.exchange()
        frame = self.frame(intent, handle)
        bad = self.frame_mutate(frame, lambda p: p.update(chunk_sha256=hashlib.sha256(b"bad child").hexdigest()), chunk_change=lambda _: b"bad child")
        self.assertRejects(stage.verify_stage_child_frame, bad, intent, entry(handle), **self.options())

    def test_existing_binary_prefix_header_chunk_caps_and_canonical_header_are_preserved(self):
        intent, _, _, handle = self.exchange()
        frame = self.frame(intent, handle)
        self.assertEqual(frame[:len(blob.MAGIC)], b"MVOB1\0")
        self.assertEqual(blob.BLOB_PREFIX_BYTES, 14)
        for bad in (frame + b"x", frame[:12], b"WRONG!" + frame[6:],
                    blob.MAGIC + struct.pack(">II", 8193, 0) + b"x" * 8193,
                    blob.MAGIC + struct.pack(">II", 1, 262145) + b"x" * 262146):
            self.assertRejects(stage.verify_stage_child_frame, bad, intent, entry(handle), **self.options())
        hlen, clen = struct.unpack_from(">II", frame, 6)
        header = b" " + frame[14:14 + hlen]
        bad = blob.MAGIC + struct.pack(">II", len(header), clen) + header + frame[14 + hlen:]
        self.assertRejects(stage.verify_stage_child_frame, bad, intent, entry(handle), **self.options())

    def test_child_receipt_is_signed_and_cannot_claim_other_request_or_prefix(self):
        intent, _, _, handle = self.exchange()
        frame = self.frame(intent, handle)
        response = stage.make_stage_child_response_frame(frame, intent, entry(handle), signer=self.signers["target"],
            durable_prefix=stage.STAGE_CHUNK_BYTES, expires_at=self.expected["at"] + 25, **self.options())
        for change in (
            lambda p: p["request_ref"].update(key="0" * 64),
            lambda p: p["child_ref"].update(key="0" * 64),
            lambda p: p.update(durable_prefix=0),
            lambda p: p.update(durable_prefix=len(self.raw) + 1),
            lambda p: p.update(offset=1),
            lambda p: p.update(chunk_sha256="0" * 64),
        ):
            bad = self.frame_mutate(response, change, "target")
            self.assertRejects(stage.verify_stage_child_response_frame, bad, frame, intent, entry(handle), **self.options())
        self.assertRejects(stage.verify_stage_child_response_frame, response, self.frame(intent, handle), intent, entry(handle), **self.options())

    def test_close_and_result_cannot_replace_manifest_handle_or_parent(self):
        intent, _, _, handle = self.exchange()
        close = stage.make_stage_close(intent, entry(handle), signer=self.signers["subject"], expires_at=self.expected["at"] + 20, **self.options())
        bad = self.mutate(entry(close), lambda p: p.update(children=[]))
        self.assertRejects(stage.verify_stage_close, bad, intent, entry(handle), **self.options())
        result = stage.make_stage_result(entry(close), intent, entry(handle), signer=self.signers["target"], expires_at=self.expected["at"] + 15, **self.options())
        for change in (
            lambda p: p.update(bootstrap_use_ref=raw_ref(b"use")),
            lambda p: p.update(reservation_generation=8),
            lambda p: p["manifest_ref"].update(key="0" * 64),
            lambda p: p.update(closed_at=self.expected["at"] - 1),
            lambda p: p.update(expires_at=self.expected["at"] + 21),
        ):
            bad = self.mutate(entry(result), change, "target")
            self.assertRejects(stage.verify_stage_result, bad, entry(close), intent, entry(handle), **self.options())

    def test_failed_work_and_retries_keep_actual_budget_charges(self):
        intent, challenge, answer, _ = self.exchange()
        local = policy(max_signature_checks=3)
        budget = wire.RepairBudget(local)
        self.assertRejects(stage.verify_stage_answer, intent, entry(challenge.original), entry(answer), caller_nonce=b"x" * 32,
                           **self.options(local, budget))
        self.assertEqual(budget.snapshot()["signature_checks"], 3)
        before = budget.snapshot()["input_bytes"]
        self.assertRejects(stage.verify_stage_answer, intent, entry(challenge.original), entry(answer), caller_nonce=challenge.nonce,
                           **self.options(local, budget))
        self.assertEqual(budget.snapshot()["signature_checks"], 3)
        self.assertGreater(budget.snapshot()["input_bytes"], before)

    def test_invalid_signature_is_actually_checked_and_metered(self):
        intent = entry(self.intent())
        document = json.loads(intent["raw"])
        document["proof"]["signature"] = "A" * 86 + "=="
        raw = canonical_bytes(document)
        local = policy(max_signature_checks=1)
        budget = wire.RepairBudget(local)
        self.assertRejects(stage.verify_stage_intent, dict(raw=raw, ref=raw_ref(raw)), **self.options(local, budget))
        self.assertEqual(budget.snapshot()["signature_checks"], 1)


if __name__ == "__main__":
    unittest.main()
