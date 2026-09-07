"""Synthetic, real-crypto v3 batch selections over the existing local Vault."""
from contextlib import closing
from pathlib import Path
import copy
import unittest
from unittest.mock import patch

from memory_vault import MemoryError, Vault, canonical_bytes, strict_json_loads
from memory_vault_network import NetworkClient
from memory_vault_network_crypto import unb64url
import memory_vault_network_recovery as recovery
from memory_vault_trust import TrustStore
from tests.test_network_hints import CONTENT_SCHEMA, control, policy, remember, query_offer, outbox_row
from tests.test_network_hints_pagination import page_offer, sessions
from tests.test_network_message_semantics import records, proofs, vault_snapshot, inject_ciphertext
from tests.test_network_recovery import archive
from tests.test_network_worker import fixture


def seed(test, owner, requester, transport, *, count=13, full_dependency=True):
    dependency = remember(test, owner, transport, "batch_dependency", "Synthetic shared V1 experiment.")
    ids = [remember(test, owner, transport, "batch_" + str(index), "Synthetic needle batch " + str(index),
        relations=[{"type": "derived_from", "target": dependency}], epistemic_type="experiment")
        for index in range(count)]
    hidden = remember(test, owner, transport, "batch_hidden", "Synthetic needle HIDDEN-BATCH-RECORD")
    owner.set_hint_policy(policy(owner, requester, ids, [*ids, *([dependency] if full_dependency else [])]))
    return dependency, ids, hidden


def gather(test, owner, requester, transport, *, suffix="batch"):
    query, offer, page = query_offer(test, owner, requester, transport, suffix=suffix)
    offers, pages = [offer], [page]
    while page["next_cursor"] is not None:
        _, offer, page = page_offer(test, owner, requester, query, page, suffix + "_" + str(len(pages)))
        offers.append(offer)
        pages.append(page)
    return query, offers, pages


def selection(query, offers, pages, *, across_pages=True):
    if across_pages:
        pairs = [(offer, page["hints"][0]) for offer, page in zip(offers, pages)]
    else:
        pairs = [(offer, hint) for offer, page in zip(offers, pages) for hint in page["hints"]][:4]
    # Caller ordering is deliberately different from canonical root ordering.
    return control("select", query_message_id=query["message_id"], selections=[
        {"offer_message_id": offer["message_id"], "memory_id": hint["memory_id"]}
        for offer, hint in reversed(pairs)])


def choose(test, owner, requester, choice, *, suffix="batch"):
    sent = requester.send("req_hint_batch_select_" + suffix, [owner.identity.key_id], control=choice)
    test.assertEqual(sent["stored_nodes"], 2, sent)
    test.assertFalse(owner.receive()["errors"])
    return sent


def share_frames(body):
    return [strict_json_loads(line) for line in unb64url(body["share"], maximum=2 * 1024 * 1024).splitlines()]


class HintBatchSelectionTests(unittest.TestCase):
    def assert_refusal(self, owner, requester, selected):
        response = owner.respond_to(selected["message_id"])
        self.assertEqual(response["stored_nodes"], 2, response)
        result = requester.receive()
        self.assertFalse(result["errors"], result)
        self.assertEqual(result["messages"][0]["content_kind"], "hint_control")
        self.assertEqual(requester.read_message(response["message_id"])["control"],
            control("refusal", request_message_id=selected["message_id"], reason="not_available"))
        return strict_json_loads(outbox_row(owner, response["message_id"])["body"])

    def test_four_roots_from_four_pages_share_dependency_once_with_exact_originals_and_retry(self):
        with fixture() as (owner, requester, transport):
            dependency, ids, hidden = seed(self, owner, requester, transport)
            remember(self, requester, transport, "batch_existing", "Synthetic existing requester Experience.")
            before = [vault_snapshot(endpoint) for endpoint in (owner, requester)]
            requester_original = records(requester)
            originals, original_proofs = records(owner), proofs(owner)
            query, offers, pages = gather(self, owner, requester, transport)
            self.assertEqual([len(page["hints"]) for page in pages], [4, 4, 4, 1])
            for page in pages:
                self.assertNotIn(hidden, canonical_bytes(page).decode())
                self.assertNotIn(dependency, canonical_bytes(page).decode())
            choice = selection(query, offers, pages)
            selected = choose(self, owner, requester, choice)
            self.assertEqual(strict_json_loads(outbox_row(requester, selected["message_id"])["body"])["control"], choice)
            self.assertEqual([vault_snapshot(endpoint) for endpoint in (owner, requester)], before)
            transport.offline.add(owner.relays[1])
            sent = owner.respond_to(selected["message_id"])
            self.assertEqual(sent["stored_nodes"], 1)
            frozen = outbox_row(owner, sent["message_id"])
            body = strict_json_loads(frozen["body"])
            self.assertEqual(set(body), {"schema_version", "kind", "request_message_id", "query_message_id", "expires_at", "share"})
            self.assertEqual(body["kind"], "hint_batch_transfer")
            self.assertEqual(body["request_message_id"], selected["message_id"])
            self.assertEqual(body["query_message_id"], query["message_id"])
            self.assertEqual(body["expires_at"], pages[0]["expires_at"])
            frames = [frame for frame in share_frames(body) if frame["type"] == "record"]
            roots = {item["memory_id"] for item in choice["selections"]}
            self.assertEqual({frame["record"]["memory_id"] for frame in frames if frame["selected"]}, roots)
            self.assertEqual(len(frames), 5)
            self.assertEqual(sum(frame["record"]["memory_id"] == dependency for frame in frames), 1)
            self.assertEqual([vault_snapshot(endpoint) for endpoint in (owner, requester)], before)
            transport.offline.clear()
            with NetworkClient(owner.config_path, transport=transport) as restarted:
                retried = restarted.respond_to(selected["message_id"])
                self.assertEqual(retried["stored_nodes"], 2, retried)
                for field in ("body", "envelope"):
                    self.assertEqual(outbox_row(restarted, sent["message_id"])[field], frozen[field])
            received = requester.receive()
            self.assertFalse(received["errors"], received)
            self.assertEqual(received["messages"][0]["share"]["records_added"], 5)
            self.assertEqual(received["messages"][0]["share"]["admission"], "verified")
            self.assertEqual(records(requester), {**requester_original, **{mid: originals[mid] for mid in roots | {dependency}}})
            for mid in roots | {dependency}:
                self.assertEqual(proofs(requester)[mid], original_proofs[mid])
            after = vault_snapshot(requester)
            self.assertEqual(requester.receive()["messages"], [])
            self.assertEqual(vault_snapshot(requester), after)
            self.assertEqual(vault_snapshot(owner), before[0])

    def test_one_unavailable_member_or_dependency_or_export_budget_refuses_entire_batch(self):
        for fault in ("denied_dependency", "missing_root", "unadmitted_dependency", "export_budget"):
            with self.subTest(fault=fault), fixture() as (owner, requester, transport):
                dependency, ids, hidden = seed(self, owner, requester, transport, count=4,
                                               full_dependency=fault != "denied_dependency")
                query, offers, pages = gather(self, owner, requester, transport)
                selected = choose(self, owner, requester, selection(query, offers, pages, across_pages=False))
                if fault == "missing_root":
                    # Simulate restoring an incomplete synthetic source. Keep
                    # the original file, and build an ordinary valid Vault with
                    # one omitted record; never bypass append-only triggers.
                    missing = ids[0]
                    admitted, signed = records(owner), proofs(owner)
                    database = owner.client_config.vault_path
                    database.rename(database.with_name(database.name + ".synthetic-preserved"))
                    remaining = [strict_json_loads(value) for mid, value in admitted.items() if mid != missing]
                    attestations = {mid: strict_json_loads(value[1]) for mid, value in signed.items() if mid != missing}
                    trust = TrustStore(owner.client_config.trust_path)
                    for record in remaining:
                        trust.verify_record(record, attestations[record["memory_id"]])
                    Vault(database).ingest_records(remaining, admission="verified", attestations=attestations)
                elif fault == "unadmitted_dependency":
                    # A dependency can remain append-only historical data but
                    # cease to be admitted. It must then make the whole batch
                    # unavailable, even though its ID is still locally granted.
                    with closing(owner.client_config.vault()._connect()) as db:
                        db.execute("UPDATE record_admissions SET state='quarantined' WHERE memory_id=?", (dependency,))
                        db.commit()
                before = [vault_snapshot(endpoint) for endpoint in (owner, requester)]
                if fault == "export_budget":
                    with patch("memory_vault_network_hints.export_share", side_effect=MemoryError("share_work_limit", retryable=True)):
                        body = self.assert_refusal(owner, requester, selected)
                else:
                    body = self.assert_refusal(owner, requester, selected)
                for value in [dependency, hidden, *ids, "share_work_limit", "HIDDEN-BATCH-RECORD"]:
                    self.assertNotIn(value, canonical_bytes(body).decode())
                self.assertEqual([vault_snapshot(endpoint) for endpoint in (owner, requester)], before)
                self.assertEqual(records(requester), {})

    def test_batch_validation_is_atomic_and_cross_query_offer_cannot_be_mixed(self):
        with fixture() as (owner, requester, transport):
            _, ids, _ = seed(self, owner, requester, transport, count=5)
            query, offers, pages = gather(self, owner, requester, transport)
            choice = selection(query, offers, pages, across_pages=False)
            other_query, other_offers, other_pages = gather(self, owner, requester, transport, suffix="other")
            variants = [dict(choice, selections=[]), dict(choice, selections=choice["selections"] * 2),
                dict(choice, selections=[*choice["selections"], {"offer_message_id": offers[1]["message_id"], "memory_id": pages[1]["hints"][0]["memory_id"]}]),
                dict(choice, selections=[*choice["selections"][:3], {**choice["selections"][3], "grant": "all"}]),
                dict(choice, query_message_id=other_query["message_id"])]
            mixed = copy.deepcopy(choice)
            mixed["selections"][0]["offer_message_id"] = other_offers[0]["message_id"]
            variants.append(mixed)
            before = [vault_snapshot(endpoint) for endpoint in (owner, requester)]
            with requester.db() as db:
                outbox_count = db.execute("SELECT COUNT(*) FROM outbox").fetchone()[0]
            for index, value in enumerate(variants):
                with self.subTest(index=index), self.assertRaises(MemoryError):
                    requester.send("req_invalid_batch_" + str(index), [owner.identity.key_id], control=value)
            with requester.db() as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM outbox").fetchone()[0], outbox_count)
            # A malicious, but genuinely signed/encrypted peer bypasses its
            # local API. The owner still refuses the mixed-query batch.
            identifier = "msg_" + "c" * 64
            inject_ciphertext(requester, owner, canonical_bytes({"schema_version": CONTENT_SCHEMA,
                "kind": "hint_control", "control": mixed}), identifier)
            self.assertFalse(owner.receive()["errors"])
            self.assert_refusal(owner, requester, {"message_id": identifier})
            self.assertEqual([vault_snapshot(endpoint) for endpoint in (owner, requester)], before)

    def test_incoming_missing_or_extra_selected_root_is_quarantined_before_any_vault_import(self):
        with fixture() as (owner, requester, transport):
            dependency, ids, hidden = seed(self, owner, requester, transport, count=5)
            query, offers, pages = gather(self, owner, requester, transport)
            choice = selection(query, offers, pages, across_pages=False)
            selected = choose(self, owner, requester, choice)
            roots = [item["memory_id"] for item in choice["selections"]]
            extra = next(mid for mid in ids if mid not in roots)
            before = [vault_snapshot(endpoint) for endpoint in (owner, requester)]
            for index, wrong_roots in enumerate((roots[:-1], [*roots, extra])):
                # Reuse the real portable export to produce an otherwise valid
                # signed complete share whose selected-root set is wrong.
                portable = strict_json_loads(owner._prepare_body("req_wrong_batch_" + str(index), "", wrong_roots))
                body = {"schema_version": CONTENT_SCHEMA, "kind": "hint_batch_transfer",
                    "request_message_id": selected["message_id"], "query_message_id": query["message_id"],
                    "expires_at": pages[0]["expires_at"], "share": portable["share"]}
                identifier = "msg_" + str(index + 5) * 64
                inject_ciphertext(owner, requester, canonical_bytes(body), identifier)
                with patch("memory_vault_sharing.import_share", side_effect=AssertionError("invalid batch must not open Vault")):
                    received = requester.receive()
                self.assertFalse(received["errors"], received)
                self.assertEqual(received["messages"][0]["state"], "rejected")
                with requester.db() as db:
                    self.assertIsNotNone(db.execute("SELECT 1 FROM quarantine WHERE message_id=?", (identifier,)).fetchone())
                    self.assertIsNone(db.execute("SELECT 1 FROM inbox WHERE message_id=?", (identifier,)).fetchone())
                self.assertEqual([vault_snapshot(endpoint) for endpoint in (owner, requester)], before)
                self.assertEqual(requester.receive()["messages"], [])
            sent = owner.respond_to(selected["message_id"])
            self.assertEqual(sent["stored_nodes"], 2)
            received = requester.receive()
            self.assertFalse(received["errors"], received)
            self.assertEqual(received["messages"][0]["share"]["records_added"], 5)
            self.assertNotIn(extra, records(requester))
            self.assertNotIn(hidden, records(requester))

    def test_four_root_frozen_batch_revocation_or_expiry_blocks_all_retry_posts(self):
        for fault in ("dependency_revocation", "expiry"):
            with self.subTest(fault=fault), fixture() as (owner, requester, transport):
                dependency, ids, _ = seed(self, owner, requester, transport, count=4)
                query, offers, pages = gather(self, owner, requester, transport)
                selected = choose(self, owner, requester, selection(query, offers, pages, across_pages=False))
                transport.offline.add(owner.relays[1])
                pending = owner.respond_to(selected["message_id"])
                self.assertEqual(pending["stored_nodes"], 1)
                frozen = outbox_row(owner, pending["message_id"])
                if fault == "dependency_revocation":
                    owner.set_hint_policy(policy(owner, requester, ids, ids, revision=2))
                transport.offline.clear()
                start = len(transport.calls)
                before = [vault_snapshot(endpoint) for endpoint in (owner, requester)]
                with NetworkClient(owner.config_path, transport=transport) as restarted:
                    if fault == "expiry":
                        with patch("memory_vault_network_hints.time.time", return_value=pages[0]["expires_at"] + 1):
                            result = restarted.pump(receive_limit=0)
                    else:
                        result = restarted.pump(receive_limit=0)
                    self.assertGreater(result["remaining_outbox"], 0)
                    self.assertFalse(any(call[2] == "/v1/messages" for call in transport.calls[start:]))
                    for field in ("body", "envelope"):
                        self.assertEqual(outbox_row(restarted, pending["message_id"])[field], frozen[field])
                self.assertEqual([vault_snapshot(endpoint) for endpoint in (owner, requester)], before)

    def test_four_root_recovery_keeps_originals_and_frozen_history_but_cannot_revive_batch(self):
        with fixture() as (owner, requester, transport):
            dependency, ids, _ = seed(self, owner, requester, transport, count=4)
            query, offers, pages = gather(self, owner, requester, transport)
            choice = selection(query, offers, pages, across_pages=False)
            selected = choose(self, owner, requester, choice)
            transport.offline.add(owner.relays[1])
            pending = owner.respond_to(selected["message_id"])
            self.assertEqual(pending["stored_nodes"], 1)
            frozen = outbox_row(owner, pending["message_id"])
            before, source_sessions = vault_snapshot(owner), sessions(owner)
            original, original_proofs = records(owner), proofs(owner)
            report, arguments = archive(owner)
            self.assertFalse(report["hint_sessions_included"])
            self.assertEqual(vault_snapshot(owner), before)
            self.assertEqual(sessions(owner), source_sessions)
            restored = recovery.restore_endpoint(directory=owner.config_path.parent.parent / "batch-restored", **arguments)
            self.assertFalse(restored["hint_sessions_restored"])
            with NetworkClient(Path(restored["network_config"]), transport=transport) as recovered:
                self.assertEqual(sessions(recovered), {})
                self.assertEqual(records(recovered), original)
                self.assertEqual(proofs(recovered), original_proofs)
                recovered.set_hint_policy(policy(recovered, requester, ids, [*ids, dependency]))
                transport.offline.clear()
                start = len(transport.calls)
                self.assertGreater(recovered.pump(receive_limit=0)["remaining_outbox"], 0)
                self.assertFalse(any(call[2] == "/v1/messages" for call in transport.calls[start:]))
                for field in ("body", "envelope"):
                    self.assertEqual(outbox_row(recovered, pending["message_id"])[field], frozen[field])
                # Drain a previously authorized replica, then establish a new
                # explicit query/session before a fresh batch may be sent.
                self.assertFalse(requester.receive()["errors"])
                query2, offers2, pages2 = gather(self, recovered, requester, transport, suffix="after_restore")
                fresh = choose(self, recovered, requester, selection(query2, offers2, pages2, across_pages=False), suffix="fresh")
                self.assertEqual(recovered.respond_to(fresh["message_id"])["stored_nodes"], 2)
                self.assertFalse(requester.receive()["errors"])
                self.assertEqual({mid: records(requester)[mid] for mid in [*ids, dependency]},
                                 {mid: original[mid] for mid in [*ids, dependency]})


if __name__ == "__main__":
    unittest.main()
