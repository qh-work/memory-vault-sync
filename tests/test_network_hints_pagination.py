"""Synthetic frozen Hint pagination; no global discovery or scale claims."""
import copy
import hashlib
from pathlib import Path
import time
import unittest
from unittest.mock import patch

from memory_vault import MemoryError, build_record, canonical_bytes, strict_json_loads
from memory_vault_network import NetworkClient
from memory_vault_network_content import validate_content
from memory_vault_trust import TrustStore
import memory_vault_network_recovery as recovery
from tests.test_network_hints import (CONTENT_SCHEMA, control, policy, remember, query_offer,
                                     select_pending, outbox_row)
from tests.test_network_message_semantics import records, proofs, vault_snapshot, inject_ciphertext
from tests.test_network_worker import fixture
from tests.test_network_recovery import archive


def sessions(endpoint):
    with endpoint.db() as db:
        return {row["key"]: row["value"] for row in db.execute(
            "SELECT key,value FROM state WHERE key LIKE 'hint-session:%' ORDER BY key")}


def page_offer(test, owner, requester, query, previous, suffix):
    sent = requester.send("req_hint_page_" + suffix, [owner.identity.key_id], control=control("page",
        query_message_id=query["message_id"], cursor=previous["next_cursor"]))
    test.assertEqual(sent["stored_nodes"], 2, sent)
    test.assertFalse(owner.receive()["errors"])
    response = owner.respond_to(sent["message_id"])
    test.assertEqual(response["stored_nodes"], 2, response)
    test.assertFalse(requester.receive()["errors"])
    return sent, response, requester.read_message(response["message_id"])["control"]


class HintPaginationTests(unittest.TestCase):
    def test_session_capacity_and_expired_cleanup_are_bounded_without_vault_changes(self):
        with fixture() as (owner, requester, transport):
            remember(self, requester, transport, "session_limit", "Synthetic pre-existing persistent Experience.")
            before = vault_snapshot(requester)
            transport.offline.update(requester.relays)
            now = int(time.time())
            for index in range(64):
                result = requester.send("req_hint_capacity_" + str(index), [owner.identity.key_id],
                    control=control("query", query="Synthetic capacity", expires_at=now + 120))
                self.assertEqual(result["stored_nodes"], 0)
            full = sessions(requester)
            self.assertEqual(len(full), 64)
            with self.assertRaises(MemoryError):
                requester.send("req_hint_capacity_overflow", [owner.identity.key_id],
                    control=control("query", query="Synthetic overflow", expires_at=now + 120))
            self.assertEqual(sessions(requester), full)
            with patch("memory_vault_network_hints.time.time", return_value=now + 121):
                pending = requester.send("req_hint_capacity_after_expiry", [owner.identity.key_id],
                    control=control("query", query="Synthetic new session", expires_at=now + 240))
                self.assertEqual(pending["stored_nodes"], 0)
            self.assertEqual(len(sessions(requester)), 1)
            self.assertEqual(vault_snapshot(requester), before)

    def test_nine_frozen_matches_four_four_one_late_selection_and_retry(self):
        with fixture() as (owner, requester, transport):
            dependency = remember(self, owner, transport, "page_dependency", "Synthetic underlying V1 evidence")
            ids = [remember(self, owner, transport, "page_" + str(i), "Synthetic needle page " + str(i),
                relations=[{"type": "derived_from", "target": dependency}]) for i in range(9)]
            hidden = remember(self, owner, transport, "page_hidden", "Synthetic needle hidden unrelated")
            # Preauthorize an immutable signed record that is not yet admitted.
            # Its later admission must not require a policy revision change.
            future = build_record(kind="observation", text="Synthetic needle future admitted record", created_at="2026-01-01T00:00:00Z")
            future_proof = owner.identity.sign_record(future)
            owner.set_hint_policy(policy(owner, requester, [*ids, future["memory_id"]], [*ids, dependency]))
            before = [vault_snapshot(endpoint) for endpoint in (owner, requester)]
            query, offer, first = query_offer(self, owner, requester, transport, suffix="pages")
            self.assertEqual([vault_snapshot(endpoint) for endpoint in (owner, requester)], before)
            first_session = sessions(owner)
            self.assertEqual(len(first_session), 1)
            TrustStore(owner.client_config.trust_path).verify_record(future, future_proof)
            owner.client_config.vault().ingest_records([future], admission="verified",
                attestations={future["memory_id"]: future_proof})
            after_admission = [vault_snapshot(endpoint) for endpoint in (owner, requester)]
            pages, offered = [first], [offer]
            for index in (1, 2):
                sent, response, page = page_offer(self, owner, requester, query, pages[-1], "nine_" + str(index))
                pages.append(page)
                offered.append(response)
                frozen = outbox_row(owner, response["message_id"])
                replay = owner.respond_to(sent["message_id"])
                self.assertEqual(replay["message_id"], response["message_id"])
                self.assertEqual(outbox_row(owner, replay["message_id"])["body"], frozen["body"])
                self.assertEqual(outbox_row(owner, replay["message_id"])["envelope"], frozen["envelope"])
                self.assertEqual(requester.receive()["messages"], [])
            self.assertEqual([len(page["hints"]) for page in pages], [4, 4, 1])
            self.assertEqual([page["page_index"] for page in pages], [0, 1, 2])
            flattened = [item["memory_id"] for page in pages for item in page["hints"]]
            self.assertEqual(flattened, sorted(ids))
            self.assertIsNone(pages[-1]["next_cursor"])
            for page in pages:
                self.assertEqual(page["query_message_id"], query["message_id"])
                self.assertEqual(page["policy_revision"], 1)
                self.assertEqual(page["expires_at"], first["expires_at"])
                self.assertNotIn("total_count", page)
                for secret in (hidden, dependency, future["memory_id"]):
                    self.assertNotIn(secret, canonical_bytes(page).decode())
            self.assertEqual(sessions(owner), first_session)
            self.assertEqual([vault_snapshot(endpoint) for endpoint in (owner, requester)], after_admission)
            selected = flattened[-1]
            original, original_proofs = records(owner), proofs(owner)
            choice = select_pending(self, owner, requester, offered[-1], selected, suffix="late_page")
            sent = owner.respond_to(choice["message_id"])
            self.assertEqual(sent["stored_nodes"], 2, sent)
            self.assertFalse(requester.receive()["errors"])
            self.assertEqual(records(requester), {mid: original[mid] for mid in (dependency, selected)})
            self.assertEqual(proofs(requester), {mid: original_proofs[mid] for mid in (dependency, selected)})

    def test_seventeen_matches_stop_at_sixteen_and_four_pages(self):
        with fixture() as (owner, requester, transport):
            ids = [remember(self, owner, transport, "cap_" + str(i), "Synthetic needle capped " + str(i)) for i in range(17)]
            owner.set_hint_policy(policy(owner, requester, ids, []))
            before = vault_snapshot(owner)
            query, _, page = query_offer(self, owner, requester, transport, suffix="cap")
            seen = [page]
            for index in (1, 2, 3):
                _, _, page = page_offer(self, owner, requester, query, page, "cap_" + str(index))
                seen.append(page)
            self.assertEqual([len(page["hints"]) for page in seen], [4, 4, 4, 4])
            self.assertEqual([item["memory_id"] for page in seen for item in page["hints"]], sorted(ids)[:16])
            self.assertIsNone(seen[-1]["next_cursor"])
            self.assertEqual(vault_snapshot(owner), before)
            self.assertIsNone(vault_snapshot(requester))

    def test_forged_cursor_cross_query_and_changed_policy_refuse_without_hidden_ids(self):
        for attack in ("tamper", "cross_query", "revision", "network_binding"):
            with self.subTest(attack=attack), fixture() as (owner, requester, transport):
                ids = [remember(self, owner, transport, "attack_" + str(i), "Synthetic needle bound " + str(i)) for i in range(5)]
                owner.set_hint_policy(policy(owner, requester, ids, ids))
                query, _, first = query_offer(self, owner, requester, transport, suffix="binding")
                selected_query, cursor = query["message_id"], first["next_cursor"]
                if attack == "tamper":
                    cursor = cursor[:-1] + ("0" if cursor[-1] != "0" else "1")
                elif attack == "cross_query":
                    other, _, _ = query_offer(self, owner, requester, transport, suffix="other_binding")
                    selected_query = other["message_id"]
                elif attack == "revision":
                    owner.set_hint_policy(policy(owner, requester, ids, ids, revision=2))
                else:
                    # Structurally plausible local session from another
                    # network must not act as a usable cursor capability.
                    key = "hint-session:" + selected_query
                    value = strict_json_loads(sessions(owner)[key])
                    value["network_id"] = "synthetic-other-network"
                    with owner.db() as db:
                        db.execute("UPDATE state SET value=? WHERE key=?", (canonical_bytes(value).decode(), key))
                before = [vault_snapshot(endpoint) for endpoint in (owner, requester)]
                identifier = "msg_" + hashlib.sha256(attack.encode()).hexdigest()
                inject_ciphertext(requester, owner, canonical_bytes({"schema_version": CONTENT_SCHEMA, "kind": "hint_control",
                    "control": control("page", query_message_id=selected_query, cursor=cursor)}), identifier)
                self.assertFalse(owner.receive()["errors"])
                result = owner.respond_to(identifier)
                self.assertEqual(result["stored_nodes"], 2, result)
                self.assertFalse(requester.receive()["errors"])
                denied = requester.read_message(result["message_id"])["control"]
                self.assertEqual(denied, control("refusal", request_message_id=identifier, reason="not_available"))
                for mid in ids:
                    self.assertNotIn(mid, canonical_bytes(denied).decode())
                self.assertEqual([vault_snapshot(endpoint) for endpoint in (owner, requester)], before)

    def test_expired_requester_session_cannot_send_page_or_select(self):
        with fixture() as (owner, requester, transport):
            ids = [remember(self, owner, transport, "expiry_" + str(i), "Synthetic needle expiry " + str(i)) for i in range(5)]
            owner.set_hint_policy(policy(owner, requester, ids, ids))
            query, offer, first = query_offer(self, owner, requester, transport, suffix="expiry")
            before = [vault_snapshot(endpoint) for endpoint in (owner, requester)]
            start = len(transport.calls)
            with patch("memory_vault_network_hints.time.time", return_value=first["expires_at"] + 1):
                for index, selection in enumerate((control("page", query_message_id=query["message_id"], cursor=first["next_cursor"]),
                    control("select", offer_message_id=offer["message_id"], memory_id=first["hints"][0]["memory_id"]))):
                    with self.assertRaises(MemoryError):
                        requester.send("req_hint_expired_cursor_" + str(index), [owner.identity.key_id], control=selection)
                self.assertEqual(requester.read_message(offer["message_id"])["control"], first)
            self.assertEqual(len(transport.calls), start)
            self.assertEqual([vault_snapshot(endpoint) for endpoint in (owner, requester)], before)

    def test_late_page_selection_does_not_bypass_full_dependency_authorization(self):
        with fixture() as (owner, requester, transport):
            dependency = remember(self, owner, transport, "denied_dependency", "Synthetic hidden dependency")
            ids = [remember(self, owner, transport, "denied_page_" + str(i), "Synthetic needle late denied " + str(i),
                relations=[{"type": "derived_from", "target": dependency}]) for i in range(9)]
            owner.set_hint_policy(policy(owner, requester, ids, ids))
            before = [vault_snapshot(endpoint) for endpoint in (owner, requester)]
            query, offered, page = query_offer(self, owner, requester, transport, suffix="late_denied")
            for index in (1, 2):
                _, offered, page = page_offer(self, owner, requester, query, page, "denied_" + str(index))
            choice = select_pending(self, owner, requester, offered, page["hints"][0]["memory_id"], suffix="denied_late")
            refused = owner.respond_to(choice["message_id"])
            self.assertFalse(requester.receive()["errors"])
            body = requester.read_message(refused["message_id"])["control"]
            self.assertEqual(body, control("refusal", request_message_id=choice["message_id"], reason="not_available"))
            self.assertNotIn(dependency, canonical_bytes(body).decode())
            self.assertEqual([vault_snapshot(endpoint) for endpoint in (owner, requester)], before)

    def test_restore_drops_sessions_and_old_unanswered_queries_cannot_resume(self):
        for role in ("owner", "requester", "unanswered_owner"):
            with self.subTest(role=role), fixture() as (owner, requester, transport):
                ids = [remember(self, owner, transport, "restored_page_" + str(i), "Synthetic needle restore " + str(i)) for i in range(5)]
                owner.set_hint_policy(policy(owner, requester, ids, ids))
                if role == "unanswered_owner":
                    query = requester.send("req_hint_query_restore_unanswered", [owner.identity.key_id],
                        control=control("query", query="Synthetic needle"))
                    self.assertFalse(owner.receive()["errors"])
                else:
                    query, offer, first = query_offer(self, owner, requester, transport, suffix="restore")
                source = requester if role == "requester" else owner
                with source.db() as db:
                    source_state = [tuple(row) for row in db.execute("SELECT key,value FROM state ORDER BY key")]
                backed, args = archive(source)
                self.assertFalse(backed["hint_sessions_included"])
                with source.db() as db:
                    self.assertEqual([tuple(row) for row in db.execute("SELECT key,value FROM state ORDER BY key")], source_state)
                restored = recovery.restore_endpoint(directory=source.config_path.parent.parent / "pagination-restored", **args)
                self.assertFalse(restored["hint_sessions_restored"])
                self.assertTrue(restored["hint_discovery_requires_new_query"])
                with NetworkClient(Path(restored["network_config"]), transport=transport) as fresh:
                    self.assertEqual(sessions(fresh), {})
                    if role == "requester":
                        self.assertEqual(fresh.read_message(offer["message_id"])["control"], first)
                        prior = outbox_row(fresh, query["message_id"])
                        old_control = strict_json_loads(prior["body"])["control"]
                        start = len(transport.calls)
                        try:
                            fresh.send("req_hint_query_restore", [owner.identity.key_id], control=old_control)
                        except MemoryError:
                            pass
                        self.assertFalse(any(call[2] == "/v1/messages" for call in transport.calls[start:]))
                        current = outbox_row(fresh, query["message_id"])
                        self.assertEqual((current["body"], current["envelope"]), (prior["body"], prior["envelope"]))
                        self.assertEqual(sessions(fresh), {})
                        _, _, new_page = query_offer(self, owner, fresh, transport, suffix="fresh_requester")
                    else:
                        fresh.set_hint_policy(policy(fresh, requester, ids, ids))
                        before = sessions(fresh)
                        try:
                            denied = fresh.respond_to(query["message_id"])
                        except MemoryError:
                            pass
                        else:
                            body = strict_json_loads(outbox_row(fresh, denied["message_id"])["body"])
                            if role == "unanswered_owner":
                                self.assertEqual(body["control"]["kind"], "refusal")
                        self.assertEqual(sessions(fresh), before)
                        self.assertFalse(requester.receive()["errors"])
                        _, _, new_page = query_offer(self, fresh, requester, transport, suffix="fresh_owner")
                    self.assertEqual(new_page["page_index"], 0)
                    self.assertTrue(sessions(fresh))


if __name__ == "__main__":
    unittest.main()
