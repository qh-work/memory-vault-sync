"""Bounded, synthetic two-endpoint hint/query/select protocol regressions."""
import copy
import json
from pathlib import Path
import time
import unittest
from unittest.mock import patch

from memory_vault import MemoryError, canonical_bytes, strict_json_loads
from memory_vault_network import NetworkClient
from memory_vault_network_content import validate_content, content_text
from memory_vault_network_crypto import b64url, document_sha256, seal
from memory_vault_storage import atomic_write
from tests.test_network_worker import fixture
from tests.test_network_message_semantics import agent, records, proofs, vault_snapshot, saved_body, inject_ciphertext


CONTENT_SCHEMA = "memory-vault-network-content/v2"
HINT_SCHEMA = "memory-vault-hint/v3"
POLICY_SCHEMA = "memory-vault-hint-policy/v1"
MEMORY_ID = "mem_" + "a" * 40
MESSAGE_ID = "msg_" + "a" * 64


def control(kind, **values):
    if kind == "query":
        values.setdefault("expires_at", int(time.time()) + 300)
    elif kind == "hints":
        values.setdefault("query_message_id", values.get("request_message_id"))
        values.setdefault("page_index", 0)
        values.setdefault("policy_revision", 1)
        values.setdefault("next_cursor", None)
    return {"schema_version": HINT_SCHEMA, "kind": kind, **values}


def single_select(query_message_id, offer_message_id, memory_id):
    """Explicit one-item v3 fixture; never a production legacy conversion."""
    return control("select", query_message_id=query_message_id,
                   selections=[{"offer_message_id": offer_message_id, "memory_id": memory_id}])


def policy(owner, peer, hints, full, *, revision=1, expires_at=None):
    return {"schema_version": POLICY_SCHEMA, "network_id": owner.network_id,
        "owner_key_id": owner.identity.key_id, "revision": revision,
        "expires_at": int(time.time()) + 3600 if expires_at is None else expires_at,
        "peers": [{"key_id": peer.identity.key_id,
                   "hint_memory_ids": sorted(hints), "record_memory_ids": sorted(full)}]}


def remember(test, endpoint, transport, suffix, text, *, relations=None, epistemic_type="observation"):
    response = agent(endpoint, transport).handle({"op": "remember", "request_id": "req_hint_record_" + suffix,
        "kind": "observation", "text": text, "relations": relations or [],
        "experience": {"epistemic_type": epistemic_type, "observed_under": {"environment": "V1"}}})
    test.assertTrue(response["ok"], response)
    return response["result"]["memory_id"]


def query_offer(test, owner, requester, transport, *, query="Synthetic needle", suffix="initial"):
    # The requester supplies a textual query, never a pre-known owner record ID.
    request = requester.send("req_hint_query_" + suffix, [owner.identity.key_id], control=control("query", query=query))
    test.assertEqual(request["stored_nodes"], 2, request)
    test.assertFalse(owner.receive()["errors"])
    response = owner.respond_to(request["message_id"])
    test.assertEqual(response["stored_nodes"], 2, response)
    test.assertFalse(requester.receive()["errors"])
    return request, response, requester.read_message(response["message_id"])["control"]


def select_pending(test, owner, requester, offer, memory_id, *, suffix="initial"):
    query_id = requester.read_message(offer["message_id"])["control"]["query_message_id"]
    selected = requester.send("req_hint_select_" + suffix, [owner.identity.key_id],
        control=single_select(query_id, offer["message_id"], memory_id))
    test.assertEqual(selected["stored_nodes"], 2, selected)
    test.assertFalse(owner.receive()["errors"])
    return selected


def outbox_row(endpoint, message_id):
    with endpoint.db() as db:
        return dict(db.execute("SELECT * FROM outbox WHERE message_id=?", (message_id,)).fetchone())


def parser_vectors():
    expires = 2000000000
    hint = {"memory_id": MEMORY_ID, "excerpt": "Synthetic 😀", "epistemic_type": "hearsay"}
    controls = [control("query", query="中" * 85 + "x"),
        control("hints", request_message_id=MESSAGE_ID, expires_at=expires, hints=[hint]),
        single_select(MESSAGE_ID, MESSAGE_ID, MEMORY_ID),
        control("refusal", request_message_id=MESSAGE_ID, reason="not_available"),
        control("page", query_message_id=MESSAGE_ID, cursor="hintcur_" + "a" * 64)]
    good = [{"schema_version": CONTENT_SCHEMA, "kind": "hint_control", "control": item} for item in controls]
    good.append({"schema_version": CONTENT_SCHEMA, "kind": "hint_control", "control":
        control("hints", request_message_id=MESSAGE_ID, expires_at=expires, hints=[
            {"memory_id": "mem_" + str(i) * 40, "excerpt": "\0" * 64 + "😀" * 16,
             "epistemic_type": "unspecified"} for i in range(4)])})
    good += [{"schema_version": CONTENT_SCHEMA, "kind": "hint_batch_transfer", "request_message_id": MESSAGE_ID,
              "query_message_id": MESSAGE_ID, "expires_at": expires, "share": b64url(b"synthetic parser-only bytes\n")}]
    bad_controls = [control("query", query=""), control("query", query="中" * 86),
        control("query", query="x", key_id="payload cannot choose requester"),
        control("query", query="x", record_memory_ids=[MEMORY_ID]),
        {**controls[1], "hints": [hint, hint]},
        {**controls[1], "hints": [{**hint, "memory_id": "mem_" + str(n) * 40} for n in range(5)]},
        {**controls[1], "hints": [{**hint, "excerpt": "😀" * 33}]},
        {**controls[1], "hints": [{**hint, "relations": []}]},
        {**controls[1], "hints": [{**hint, "epistemic_type": "trusted_truth"}]},
        {**controls[1], "expires_at": True}, {**controls[1], "expires_at": 0}, {**controls[1], "expires_at": 2**53},
        {**controls[2], "memory_id": "mem_not_valid"},
        {**controls[2], "offer_message_id": "not-a-message"},
        {**controls[2], "selections": []},
        {**controls[2], "selections": controls[2]["selections"] * 2},
        {**controls[2], "selections": [{"offer_message_id": MESSAGE_ID, "memory_id": "mem_" + str(i) * 40} for i in range(5)]},
        {**controls[2], "selections": [{"offer_message_id": MESSAGE_ID, "memory_id": MEMORY_ID, "permission": "all"}]},
        control("select", offer_message_id=MESSAGE_ID, memory_id=MEMORY_ID),
        {**controls[0], "schema_version": "memory-vault-hint/v2"},
        {"schema_version": "memory-vault-hint/v2", "kind": "select",
         "offer_message_id": MESSAGE_ID, "memory_id": MEMORY_ID},
        {**controls[3], "reason": "secret dependency " + MEMORY_ID},
        {**controls[3], "missing_ids": [MEMORY_ID]},
        {**controls[0], "expires_at": 0},
        {key: value for key, value in controls[0].items() if key != "expires_at"},
        {**controls[1], "page_index": 4}, {**controls[1], "policy_revision": 0},
        {**controls[1], "page_index": 1, "hints": []},
        {**controls[1], "next_cursor": "hintcur_" + "a" * 64},
        {**controls[1], "total_count": 99},
        {**controls[4], "cursor": "hintcur_" + "a" * 63},
        {**controls[4], "query_message_id": "not-a-query"},
        {**controls[4], "offset": 4},
        control("set_policy", peers=[]), {**controls[0], "schema_version": "memory-vault-hint/v99"}]
    bad = [{"schema_version": CONTENT_SCHEMA, "kind": "hint_control", "control": item} for item in bad_controls]
    bad += [{**good[0], "text": "mixed body"}, {**good[-1], "note": "mixed transfer"},
            {**good[-1], "expires_at": 1.5}, {**good[-1], "memory_id": "mem_bad"},
            {"schema_version": CONTENT_SCHEMA, "kind": "hint_transfer", "request_message_id": MESSAGE_ID,
             "offer_message_id": MESSAGE_ID, "memory_id": MEMORY_ID, "expires_at": expires, "share": b64url(b"old preview")}]
    return good, bad


class HintContentTests(unittest.TestCase):
    def test_closed_control_and_transfer_shapes_and_byte_bounds(self):
        good, bad = parser_vectors()
        for value in good:
            with self.subTest(kind=value["kind"]):
                self.assertEqual(validate_content(canonical_bytes(value)), value)
                self.assertEqual(content_text(value), "")
        for value in bad:
            with self.subTest(value=value), self.assertRaises(MemoryError) as caught:
                validate_content(json.dumps(value, ensure_ascii=False).encode())
            self.assertIn(caught.exception.code, {"network_invalid_content", "network_invalid_content_json"})


class NetworkHintTests(unittest.TestCase):
    def test_unhashable_kind_with_unsafe_integer_is_quarantined_without_blocking_same_page(self):
        for malformed_kind in ([], {}):
            for number in (2**53, 2**63 - 1):
                with self.subTest(kind=malformed_kind, number=number), fixture() as (sender, recipient, transport):
                    sender_id = remember(self, sender, transport, "invalid_kind_sender", "Synthetic existing sender Experience.")
                    recipient_id = remember(self, recipient, transport, "invalid_kind_recipient", "Synthetic existing recipient Experience.")
                    sender.set_hint_policy(policy(sender, recipient, [sender_id], [sender_id]))
                    recipient.set_hint_policy(policy(recipient, sender, [recipient_id], [recipient_id]))
                    before = [vault_snapshot(endpoint) for endpoint in (sender, recipient)]
                    protected = [(endpoint.directory / "hint-policy.json", endpoint.client_config.trust_path)
                                 for endpoint in (sender, recipient)]
                    protected_bytes = {path: path.read_bytes() for paths in protected for path in paths}
                    # Authenticated peers can send arbitrary encrypted bytes.
                    # Do not normalize this malformed application body through
                    # a validating encoder before sealing the real JWE.
                    raw = json.dumps({"schema_version": CONTENT_SCHEMA, "kind": malformed_kind,
                                      "x": number}, separators=(",", ":")).encode()
                    malformed = inject_ciphertext(sender, recipient, raw, "msg_" + "6" * 64)
                    if number == 2**53:
                        following = sender.send("req_hint_after_unhashable_chat", [recipient.identity.key_id],
                                                "Synthetic valid chat after malformed content.")
                        expected_kind = "message"
                    else:
                        following = sender.send("req_hint_after_unhashable_query", [recipient.identity.key_id],
                            control=control("query", query="Synthetic existing recipient"))
                        expected_kind = "hint_control"
                    self.assertEqual(following["stored_nodes"], 2, following)
                    response = recipient.receive(limit=4)
                    self.assertFalse(response["errors"], response)
                    bad, good = response["messages"]
                    self.assertEqual(bad["message_id"], malformed["message_id"])
                    self.assertEqual(bad["state"], "rejected")
                    self.assertEqual(bad["code"], "network_invalid_content_json")
                    self.assertNotIn("text", bad)
                    self.assertEqual(good["message_id"], following["message_id"])
                    self.assertEqual(good["state"], "validated_saved")
                    self.assertEqual(good["content_kind"], expected_kind)
                    with recipient.db() as db:
                        rejected = db.execute("SELECT envelope FROM quarantine WHERE message_id=?",
                                              (malformed["message_id"],)).fetchone()
                        self.assertEqual(bytes(rejected[0]), canonical_bytes(malformed))
                        self.assertEqual(db.execute("SELECT COUNT(*) FROM quarantine").fetchone()[0], 1)
                        self.assertEqual([row[0] for row in db.execute("SELECT message_id FROM inbox")],
                                         [following["message_id"]])
                        for relay in sender.relays:
                            cursor = strict_json_loads(db.execute("SELECT value FROM state WHERE key=?",
                                ("cursor:" + relay,)).fetchone()[0])
                            self.assertEqual(cursor["cursor"], 2)
                            self.assertIsNone(db.execute("SELECT 1 FROM state WHERE key=?",
                                ("ack:" + relay + ":" + malformed["message_id"],)).fetchone())
                    for relay in sender.relays:
                        with transport.clients[relay].app.state.relay._transaction() as db:
                            self.assertEqual(db.execute("SELECT COUNT(*) FROM receipts WHERE message_id=?",
                                (malformed["message_id"],)).fetchone()[0], 0)
                            self.assertEqual(db.execute("SELECT COUNT(*) FROM receipts WHERE message_id=?",
                                (following["message_id"],)).fetchone()[0], 1)
                    for _ in range(2):
                        replay = recipient.receive(limit=4)
                        self.assertFalse(replay["errors"], replay)
                        self.assertEqual(replay["messages"], [])
                    later = sender.send("req_hint_after_quarantine_repoll", [recipient.identity.key_id],
                                        "Synthetic later message also makes progress.")
                    advanced = recipient.receive(limit=4)
                    self.assertFalse(advanced["errors"], advanced)
                    self.assertEqual([item["message_id"] for item in advanced["messages"]], [later["message_id"]])
                    with recipient.db() as db:
                        self.assertEqual(db.execute("SELECT COUNT(*) FROM quarantine").fetchone()[0], 1)
                        for relay in sender.relays:
                            self.assertEqual(strict_json_loads(db.execute("SELECT value FROM state WHERE key=?",
                                ("cursor:" + relay,)).fetchone()[0])["cursor"], 3)
                    self.assertEqual([vault_snapshot(endpoint) for endpoint in (sender, recipient)], before)
                    self.assertEqual({path: path.read_bytes() for path in protected_bytes}, protected_bytes)

    def test_unknown_id_query_is_bounded_readonly_and_explicit_selection_preserves_records(self):
        with fixture() as (owner, requester, transport):
            root = remember(self, owner, transport, "root", "Synthetic needle root with direct observation.")
            selected = remember(self, owner, transport, "child", "Synthetic needle " + "😀" * 80,
                relations=[{"type": "derived_from", "target": root}], epistemic_type="inference")
            hidden = remember(self, owner, transport, "hidden", "Synthetic needle HIDDEN-PRIVATE-TEXT")
            remember(self, requester, transport, "requester", "Synthetic existing requester experience.")
            owner.set_hint_policy(policy(owner, requester, [selected], [root, selected]))
            before = [vault_snapshot(endpoint) for endpoint in (owner, requester)]
            original, original_proofs = records(owner), proofs(owner)
            request, offer, hints = query_offer(self, owner, requester, transport)
            self.assertNotIn(selected.encode(), saved_body(requester, "outbox", request["message_id"]))
            self.assertEqual(hints["kind"], "hints")
            self.assertEqual(hints["request_message_id"], request["message_id"])
            self.assertEqual([item["memory_id"] for item in hints["hints"]], [selected])
            item, = hints["hints"]
            self.assertEqual(set(item), {"memory_id", "excerpt", "epistemic_type"})
            self.assertEqual(item["epistemic_type"], "inference")
            self.assertLessEqual(len(item["excerpt"].encode()), 128)
            self.assertTrue(strict_json_loads(original[selected])["text"].startswith(item["excerpt"]))
            for secret in (hidden, root, "HIDDEN-PRIVATE-TEXT"):
                self.assertNotIn(secret, canonical_bytes(hints).decode())
            self.assertEqual([vault_snapshot(endpoint) for endpoint in (owner, requester)], before)
            chosen = select_pending(self, owner, requester, offer, selected)
            self.assertEqual([vault_snapshot(endpoint) for endpoint in (owner, requester)], before)
            transferred = owner.respond_to(chosen["message_id"])
            self.assertEqual(transferred["stored_nodes"], 2, transferred)
            delivered = requester.receive()
            self.assertFalse(delivered["errors"], delivered)
            message, = delivered["messages"]
            self.assertEqual(message["content_kind"], "hint_batch_transfer")
            self.assertEqual(message["share"]["records_added"], 2)
            self.assertEqual(message["share"]["admission"], "verified")
            for mid in (root, selected):
                self.assertEqual(records(requester)[mid], original[mid])
                self.assertEqual(proofs(requester)[mid], original_proofs[mid])
            self.assertNotIn(hidden, records(requester))
            self.assertEqual(vault_snapshot(owner), before[0])
            after = vault_snapshot(requester)
            replay = owner.respond_to(chosen["message_id"])
            self.assertEqual(replay["message_id"], transferred["message_id"])
            self.assertEqual(requester.receive()["messages"], [])
            self.assertEqual(vault_snapshot(requester), after)
            with patch("memory_vault_network_hints.time.time", return_value=hints["expires_at"] + 1):
                # A previously validated inbox remains locally readable after
                # the offer expires; this does not authorize another transfer.
                local = requester.read_message(transferred["message_id"])
                self.assertEqual(local["content_kind"], "hint_batch_transfer")
                self.assertFalse(local["network_accessed"])

    def test_four_escaped_multibyte_hints_fit_local_read_budget_without_memory_writes(self):
        with fixture() as (owner, requester, transport):
            remember(self, requester, transport, "budget", "Synthetic existing requester Experience.")
            before = vault_snapshot(requester)
            body = parser_vectors()[0][-2]
            request = requester.send("req_hint_budget_query", [owner.identity.key_id],
                control=control("query", query="Synthetic budget"))
            body["control"].update(request_message_id=request["message_id"], query_message_id=request["message_id"],
                                   expires_at=int(time.time()) + 120)
            identifier = "msg_" + "4" * 64
            inject_ciphertext(owner, requester, canonical_bytes(body), identifier)
            self.assertFalse(requester.receive()["errors"])
            calls_before = len(transport.calls)
            response = agent(requester, transport).handle({"op": "receive", "message_id": identifier})
            self.assertTrue(response["ok"], response)
            self.assertEqual(response["result"]["control"], body["control"])
            self.assertLessEqual(len(canonical_bytes(response)), 8192)
            self.assertEqual(len(transport.calls), calls_before)
            self.assertEqual(vault_snapshot(requester), before)

    def test_authorized_exact_id_matching_and_offer_replay_do_not_recompute(self):
        with fixture() as (owner, requester, transport):
            ids = [remember(self, owner, transport, "match_" + str(i), "Synthetic needle item " + str(i)) for i in range(6)]
            hidden = remember(self, owner, transport, "not_granted", "Synthetic needle hidden " * 20)
            owner.set_hint_policy(policy(owner, requester, ids, []))
            before = vault_snapshot(owner)
            request, offer, hints = query_offer(self, owner, requester, transport)
            self.assertEqual([item["memory_id"] for item in hints["hints"]], sorted(ids)[:4])
            self.assertNotIn(hidden, canonical_bytes(hints).decode())
            self.assertEqual(vault_snapshot(owner), before)
            frozen = outbox_row(owner, offer["message_id"])
            later = remember(self, owner, transport, "later", "Synthetic needle later authorized record")
            owner.set_hint_policy(policy(owner, requester, [*ids, later], [], revision=2))
            start = len(transport.calls)
            replay = owner.respond_to(request["message_id"])
            self.assertEqual(replay["message_id"], offer["message_id"])
            self.assertFalse(any(call[2] == "/v1/messages" for call in transport.calls[start:]))
            for field in ("body", "envelope"):
                self.assertEqual(outbox_row(owner, replay["message_id"])[field], frozen[field])
            _, _, empty = query_offer(self, owner, requester, transport, query="synthetic needle", suffix="case_sensitive")
            self.assertEqual(empty["hints"], [])

    def test_hint_grant_does_not_authorize_full_record_or_hidden_dependency(self):
        for full_grant in ("none", "root_only"):
            with self.subTest(full_grant=full_grant), fixture() as (owner, requester, transport):
                private = remember(self, owner, transport, "private_dependency", "PRIVATE-DEPENDENCY-CONTENT")
                visible = remember(self, owner, transport, "visible", "Synthetic needle public hint",
                    relations=[{"type": "derived_from", "target": private}])
                owner.set_hint_policy(policy(owner, requester, [visible], [] if full_grant == "none" else [visible]))
                before = [vault_snapshot(endpoint) for endpoint in (owner, requester)]
                _, offer, _ = query_offer(self, owner, requester, transport)
                choice = select_pending(self, owner, requester, offer, visible)
                # Denial must happen before opening a plaintext export output.
                import memory_vault_sharing as sharing
                with patch.object(sharing, "_new_output", side_effect=AssertionError("denied closure serialized")):
                    refused = owner.respond_to(choice["message_id"])
                self.assertEqual(refused["stored_nodes"], 2, refused)
                self.assertFalse(requester.receive()["errors"])
                response = requester.read_message(refused["message_id"])["control"]
                self.assertEqual(response, control("refusal", request_message_id=choice["message_id"], reason="not_available"))
                self.assertNotIn(private, canonical_bytes(response).decode())
                self.assertNotIn("PRIVATE-DEPENDENCY", canonical_bytes(response).decode())
                self.assertEqual([vault_snapshot(endpoint) for endpoint in (owner, requester)], before)

    def test_full_record_grant_and_network_membership_do_not_grant_hint_visibility(self):
        with fixture() as (owner, requester, transport):
            mid = remember(self, owner, transport, "full_only", "Synthetic needle full-record grant only")
            for index, selected_policy in enumerate((None, policy(owner, requester, [], [mid]),
                    {**policy(owner, requester, [mid], [mid], revision=2), "peers": []})):
                if selected_policy is not None:
                    owner.set_hint_policy(selected_policy)
                _, _, response = query_offer(self, owner, requester, transport, suffix="no_visibility_" + str(index))
                self.assertNotIn(mid, canonical_bytes(response).decode())
                if response["kind"] == "hints":
                    self.assertEqual(response["hints"], [])
                else:
                    self.assertEqual(response["reason"], "not_available")
            self.assertIsNone(vault_snapshot(requester))

    def test_explicit_policy_revision_binding_and_remote_controls_cannot_change_policy(self):
        with fixture() as (owner, requester, transport):
            mid = remember(self, owner, transport, "policy", "Synthetic needle policy record")
            valid = policy(owner, requester, [mid], [mid], revision=2)
            owner.set_hint_policy(valid)
            path = owner.directory / "hint-policy.json"
            before, vault_before = path.read_bytes(), vault_snapshot(owner)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            owner.set_hint_policy(valid)
            invalid = [{**valid, "revision": 1}, {**valid, "peers": []},
                {**valid, "owner_key_id": requester.identity.key_id}, {**valid, "network_id": "another-network"},
                {**valid, "expires_at": int(time.time()) - 1},
                {**valid, "expires_at": int(time.time()) + 86401},
                {**valid, "peers": valid["peers"] * 2}]
            for value in invalid:
                with self.subTest(value=value), self.assertRaises(MemoryError):
                    owner.set_hint_policy(value)
                self.assertEqual(path.read_bytes(), before)
            inject_ciphertext(requester, owner, canonical_bytes({"schema_version": CONTENT_SCHEMA,
                "kind": "hint_control", "control": control("set_policy", policy=valid)}), "msg_" + "b" * 64)
            rejected = owner.receive()
            self.assertFalse(rejected["errors"], rejected)
            self.assertEqual(rejected["messages"][0]["state"], "rejected")
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual(vault_snapshot(owner), vault_before)

    def test_guarded_offline_and_frozen_retries_recheck_current_grant_and_expiration(self):
        for kind in ("hints", "hint_batch_transfer"):
            for frozen in (False, True):
                for revoke in (True, False):
                    with self.subTest(kind=kind, frozen=frozen, revoke=revoke), fixture() as (owner, requester, transport):
                        dependency = remember(self, owner, transport, "guarded_dependency", "Synthetic guarded dependency")
                        mid = remember(self, owner, transport, "guarded", "Synthetic needle guarded source",
                                       relations=[{"type": "derived_from", "target": dependency}])
                        current_policy = policy(owner, requester, [mid], [mid, dependency])
                        owner.set_hint_policy(current_policy)
                        if kind == "hints":
                            incoming = requester.send("req_hint_guard_query", [owner.identity.key_id],
                                control=control("query", query="Synthetic needle"))
                            self.assertFalse(owner.receive()["errors"])
                        else:
                            _, offer, _ = query_offer(self, owner, requester, transport)
                            incoming = select_pending(self, owner, requester, offer, mid)
                        transport.offline.update(owner.relays[1:] if frozen else owner.relays)
                        queued = owner.respond_to(incoming["message_id"])
                        self.assertEqual(queued["stored_nodes"], 1 if frozen else 0, queued)
                        prior = outbox_row(owner, queued["message_id"])
                        self.assertEqual(prior["envelope"] is not None, frozen)
                        if revoke:
                            owner.set_hint_policy(policy(owner, requester, [] if kind == "hints" else [mid],
                                                        [mid] if kind == "hint_batch_transfer" else [mid, dependency], revision=2))
                        else:
                            # Simulate an already-expired local policy without
                            # sleeping or bypassing the runtime policy loader.
                            atomic_write(owner.directory / "hint-policy.json",
                                canonical_bytes({**current_policy, "expires_at": int(time.time()) - 1}), replace=True)
                        before = [vault_snapshot(endpoint) for endpoint in (owner, requester)]
                        transport.offline.clear()
                        start = len(transport.calls)
                        with NetworkClient(owner.config_path, transport=transport) as restarted:
                            denied = restarted.pump(receive_limit=0)
                            self.assertGreater(denied["remaining_outbox"], 0, denied)
                            self.assertFalse(any(path == "/v1/messages" for _, _, path, _ in transport.calls[start:]))
                            after = outbox_row(restarted, queued["message_id"])
                            self.assertEqual(after["body"], prior["body"])
                            self.assertEqual(after["envelope"], prior["envelope"])
                        self.assertEqual([vault_snapshot(endpoint) for endpoint in (owner, requester)], before)

    def test_dependency_revocation_after_export_and_after_seal_blocks_actual_disclosure(self):
        for phase in ("after_export", "after_seal"):
            with self.subTest(phase=phase), fixture() as (owner, requester, transport):
                dependency = remember(self, owner, transport, "race_dependency", "Synthetic private dependency")
                mid = remember(self, owner, transport, "race_root", "Synthetic needle race root",
                    relations=[{"type": "derived_from", "target": dependency}])
                owner.set_hint_policy(policy(owner, requester, [mid], [mid, dependency]))
                _, offer, _ = query_offer(self, owner, requester, transport)
                selected = select_pending(self, owner, requester, offer, mid)
                before = [vault_snapshot(endpoint) for endpoint in (owner, requester)]
                import memory_vault_network as network
                import memory_vault_network_hints as hints
                target, name = (hints, "export_share") if phase == "after_export" else (network, "seal")
                original = getattr(target, name)
                changed = []
                def revoke_after_real_operation(*args, **kwargs):
                    result = original(*args, **kwargs)
                    if not changed:
                        owner.set_hint_policy(policy(owner, requester, [mid], [mid], revision=2))
                        changed.append(True)
                    return result
                start = len(transport.calls)
                with patch.object(target, name, side_effect=revoke_after_real_operation):
                    result = owner.respond_to(selected["message_id"])
                self.assertEqual(changed, [True])
                if phase == "after_export":
                    self.assertEqual(result["stored_nodes"], 2, result)
                    self.assertFalse(requester.receive()["errors"])
                    response = requester.read_message(result["message_id"])["control"]
                    self.assertEqual(response, control("refusal", request_message_id=selected["message_id"], reason="not_available"))
                else:
                    self.assertEqual(result["stored_nodes"], 0, result)
                    self.assertFalse(any(path == "/v1/messages" for _, _, path, _ in transport.calls[start:]))
                self.assertEqual([vault_snapshot(endpoint) for endpoint in (owner, requester)], before)

    def test_selection_is_recipient_bound_and_unknown_offer_refusal_reveals_no_ids(self):
        with fixture() as (owner, requester, transport):
            mid = remember(self, owner, transport, "bound_offer", "Synthetic needle offered record")
            hidden = remember(self, owner, transport, "bound_hidden", "Synthetic never offered private record")
            owner.set_hint_policy(policy(owner, requester, [mid], [mid, hidden]))
            query, offer, _ = query_offer(self, owner, requester, transport)
            for selected, offer_id in ((hidden, offer["message_id"]), (mid, "msg_" + "c" * 64)):
                before = vault_snapshot(owner)
                # A malicious authorized requester bypasses its own local
                # selection checks; the responder must independently reject.
                identifier = "msg_" + ("d" if selected == hidden else "e") * 64
                inject_ciphertext(requester, owner, canonical_bytes({"schema_version": CONTENT_SCHEMA,
                    "kind": "hint_control", "control": single_select(query["message_id"], offer_id, selected)}), identifier)
                self.assertFalse(owner.receive()["errors"])
                refused = owner.respond_to(identifier)
                self.assertFalse(requester.receive()["errors"])
                response = requester.read_message(refused["message_id"])["control"]
                self.assertEqual(response, control("refusal", request_message_id=identifier, reason="not_available"))
                self.assertNotIn(hidden, canonical_bytes(response).decode())
                self.assertEqual(vault_snapshot(owner), before)
            for recipient_id, selected in ((requester.identity.key_id, mid), (owner.identity.key_id, hidden)):
                result = agent(requester, transport).handle({"op": "send", "request_id": "req_hint_wrong_select_" + selected,
                    "recipients": [recipient_id], "control": single_select(query["message_id"], offer["message_id"], selected)})
                self.assertFalse(result["ok"], result)
            self.assertIsNone(vault_snapshot(requester))

    def test_tampered_control_ciphertext_cannot_create_inbox_response_or_policy(self):
        with fixture() as (owner, requester, transport):
            incoming = requester.send("req_hint_tamper", [owner.identity.key_id], control=control("query", query="Synthetic needle"))
            envelope = strict_json_loads(outbox_row(requester, incoming["message_id"])["envelope"])
            envelope["jwe"]["tag"] = b64url(b"\0" * 16)
            envelope["proof"] = requester.identity.sign_message({k: v for k, v in envelope.items() if k != "proof"})
            original = transport.request
            def changed_poll(base, method, path, value=None):
                response = original(base, method, path, value)
                if path == "/v1/poll":
                    response = {**response, "messages": [envelope], "cursor": 1}
                return response
            with patch.object(transport, "request", side_effect=changed_poll):
                result = owner.receive()
            self.assertEqual(result["messages"], [])
            self.assertTrue(result["errors"], result)
            with owner.db() as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM inbox").fetchone()[0], 0)
                self.assertEqual(db.execute("SELECT COUNT(*) FROM outbox").fetchone()[0], 0)
                self.assertEqual(db.execute("SELECT COUNT(*) FROM state WHERE key LIKE 'ack:%'").fetchone()[0], 0)
            self.assertFalse((owner.directory / "hint-policy.json").exists())
            self.assertIsNone(vault_snapshot(owner))

    def test_authenticated_unsolicited_transfer_is_rejected_before_vault_open(self):
        with fixture() as (owner, requester, transport):
            mid = remember(self, owner, transport, "unsolicited", "Synthetic valid but unsolicited Experience.")
            # Build a genuine signed share by explicit local owner action, then
            # send it as an unsolicited hint transfer with no requester select.
            share = strict_json_loads(owner._prepare_body("req_hint_unsolicited_share", "", [mid]))["share"]
            body = {"schema_version": CONTENT_SCHEMA, "kind": "hint_batch_transfer",
                "request_message_id": "msg_" + "1" * 64, "query_message_id": "msg_" + "2" * 64,
                "expires_at": int(time.time()) + 300, "share": share}
            identifier = "msg_" + "3" * 64
            inject_ciphertext(owner, requester, canonical_bytes(body), identifier)
            before = vault_snapshot(owner)
            import memory_vault_sharing as sharing
            with patch.object(sharing, "import_share", side_effect=AssertionError("unsolicited transfer opened Vault")):
                response = requester.receive()
            self.assertFalse(any(message.get("state") == "validated_saved" for message in response["messages"]), response)
            self.assertIsNone(vault_snapshot(requester))
            self.assertEqual(vault_snapshot(owner), before)
            with requester.db() as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM inbox").fetchone()[0], 0)
                self.assertEqual(db.execute("SELECT COUNT(*) FROM state WHERE key LIKE 'ack:%'").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
