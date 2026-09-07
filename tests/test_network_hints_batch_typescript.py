"""Synthetic Python/Node batch selection through the official Agent entrypoint.

Real Ed25519/JWE and owned loopback relays are used. This is a bounded
interoperability regression, not a cross-host or real-model scale claim.
"""
import hashlib
import unittest

from memory_vault import canonical_bytes, strict_json_loads
from memory_vault_network_crypto import b64url, unb64url
from memory_vault_relay import Relay
from memory_vault_sharing import export_share
from tests import test_network_hints_typescript as hint_harness
from tests.test_network_hints import CONTENT_SCHEMA, control, outbox_row
from tests.test_network_message_semantics import inject_ciphertext, records, proofs, vault_snapshot


class TypeScriptHintBatchTests(unittest.TestCase):
    setUpClass = classmethod(hint_harness.TypeScriptHintExchangeTests.setUpClass.__func__)
    setUp = hint_harness.TypeScriptHintExchangeTests.setUp
    ts = hint_harness.TypeScriptHintExchangeTests.ts
    ts_value = hint_harness.TypeScriptHintExchangeTests.ts_value
    py_value = hint_harness.TypeScriptHintExchangeTests.py_value
    set_policy = hint_harness.TypeScriptHintExchangeTests.set_policy
    remember = hint_harness.TypeScriptHintExchangeTests.remember
    exchange_offer = hint_harness.TypeScriptHintExchangeTests.exchange_offer

    def pages(self, owner, requester, owner_call, requester_call, suffix):
        query, offered, page = self.exchange_offer(owner, requester, owner_call, requester_call, suffix)
        pages = [(offered, page)]
        while page["next_cursor"] is not None:
            self.assertLess(len(pages), 4)
            request = requester_call(requester, {"op": "send",
                "request_id": "req_hint_batch_page_" + suffix + "_" + str(len(pages)),
                "recipients": [self.host.identities[owner].key_id],
                "control": control("page", query_message_id=query["message_id"], cursor=page["next_cursor"])})
            self.assertEqual(request["stored_nodes"], 2, request)
            self.assertFalse(owner_call(owner, {"op": "receive"})["errors"])
            offered = owner_call(owner, {"op": "receive", "respond_to": request["message_id"]})
            self.assertEqual(offered["stored_nodes"], 2, offered)
            self.assertFalse(requester_call(requester, {"op": "receive"})["errors"])
            read_request = {"op": "receive", "message_id": offered["message_id"]}
            local_ts = self.ts(requester, read_request)
            self.assertFalse(local_ts["calls"])
            self.assertEqual(local_ts["results"][0]["result"], self.py_value(requester, read_request))
            page = local_ts["results"][0]["result"]["control"]
            pages.append((offered, page))
        return query, pages

    def test_both_languages_select_four_roots_from_four_pages_and_deduplicate_shared_dependency(self):
        host = self.host
        host.join_receiver()
        endpoints = [host.sender, host.receiver]
        for owner, requester, owner_call, requester_call in (
                (0, 1, self.py_value, self.ts_value), (1, 0, self.ts_value, self.py_value)):
            with self.subTest(owner=owner):
                suffix = "four_pages_" + str(owner)
                dependency = self.remember(owner, suffix + "_dep", "Synthetic shared original evidence")
                roots = [self.remember(owner, suffix + "_" + str(i),
                    "Synthetic needle batch root " + str(i),
                    [{"type": "derived_from", "target": dependency}]) for i in range(13)]
                self.set_policy(owner, requester, roots, [*roots, dependency])
                before = [vault_snapshot(endpoint) for endpoint in endpoints]
                originals, original_proofs = records(endpoints[owner]), proofs(endpoints[owner])
                requester_before = records(endpoints[requester])
                query, pages = self.pages(owner, requester, owner_call, requester_call, suffix)
                self.assertEqual([len(page["hints"]) for _, page in pages], [4, 4, 4, 1])
                self.assertEqual([page["page_index"] for _, page in pages], [0, 1, 2, 3])
                self.assertEqual([item["memory_id"] for _, page in pages for item in page["hints"]], sorted(roots))
                # Deliberately select in noncanonical order; the request retains
                # caller order while the response is checked as an exact root set.
                selections = [{"offer_message_id": pages[i][0]["message_id"],
                               "memory_id": pages[i][1]["hints"][0]["memory_id"]}
                              for i in (3, 0, 2, 1)]
                selected_ids = {item["memory_id"] for item in selections}
                self.assertEqual([vault_snapshot(endpoint) for endpoint in endpoints], before)
                send_request = {"op": "send", "request_id": "req_hint_batch_select_" + suffix,
                    "recipients": [host.identities[owner].key_id], "control": control("select",
                        query_message_id=query["message_id"], selections=selections)}
                chosen = requester_call(requester, send_request)
                self.assertEqual(chosen["stored_nodes"], 2, chosen)
                request_frozen = outbox_row(endpoints[requester], chosen["message_id"])
                self.assertEqual(strict_json_loads(request_frozen["body"])["control"], send_request["control"])
                self.assertFalse(owner_call(owner, {"op": "receive"})["errors"])
                transfer = owner_call(owner, {"op": "receive", "respond_to": chosen["message_id"]})
                self.assertEqual(transfer["stored_nodes"], 2, transfer)
                self.assertEqual(transfer["content_kind"], "hint_batch_transfer")
                self.assertEqual([vault_snapshot(endpoint) for endpoint in endpoints], before)
                frozen = outbox_row(endpoints[owner], transfer["message_id"])
                body = strict_json_loads(frozen["body"])
                self.assertEqual(set(body), {"schema_version", "kind", "request_message_id",
                    "query_message_id", "expires_at", "share"})
                self.assertEqual(body["schema_version"], CONTENT_SCHEMA)
                self.assertEqual(body["request_message_id"], chosen["message_id"])
                self.assertEqual(body["query_message_id"], query["message_id"])
                self.assertEqual(body["expires_at"], pages[0][1]["expires_at"])
                frames = [strict_json_loads(line) for line in unb64url(body["share"], maximum=2 * 1024 * 1024).splitlines()]
                entries = [frame for frame in frames if frame["type"] == "record"]
                self.assertEqual(len(entries), 5)
                self.assertEqual({frame["record"]["memory_id"] for frame in entries}, selected_ids | {dependency})
                self.assertEqual({frame["record"]["memory_id"] for frame in entries if frame["selected"]}, selected_ids)
                self.assertEqual(sum(frame["record"]["memory_id"] == dependency for frame in entries), 1)
                received = requester_call(requester, {"op": "receive"})
                self.assertFalse(received["errors"], received)
                message, = received["messages"]
                self.assertEqual(message["content_kind"], "hint_batch_transfer")
                self.assertEqual(message["share"]["admission"], "verified")
                self.assertEqual(message["share"]["records_added"], 5)
                self.assertEqual(set(records(endpoints[requester])) - set(requester_before), selected_ids | {dependency})
                for memory_id in selected_ids | {dependency}:
                    self.assertEqual(records(endpoints[requester])[memory_id], originals[memory_id])
                    self.assertEqual(proofs(endpoints[requester])[memory_id], original_proofs[memory_id])
                self.assertEqual(vault_snapshot(endpoints[owner]), before[owner])
                after = [vault_snapshot(endpoint) for endpoint in endpoints]
                repeat = requester_call(requester, send_request)
                self.assertEqual(repeat["message_id"], chosen["message_id"])
                request_again = outbox_row(endpoints[requester], repeat["message_id"])
                self.assertEqual((request_again["body"], request_again["envelope"]),
                                 (request_frozen["body"], request_frozen["envelope"]))
                repeated_transfer = owner_call(owner, {"op": "receive", "respond_to": chosen["message_id"]})
                self.assertEqual(repeated_transfer["message_id"], transfer["message_id"])
                response_again = outbox_row(endpoints[owner], repeated_transfer["message_id"])
                self.assertEqual((response_again["body"], response_again["envelope"]), (frozen["body"], frozen["envelope"]))
                self.assertEqual(requester_call(requester, {"op": "receive"})["messages"], [])
                self.assertEqual([vault_snapshot(endpoint) for endpoint in endpoints], after)

    def test_both_languages_refuse_entire_four_root_batch_when_one_dependency_is_not_granted(self):
        host = self.host
        host.join_receiver()
        endpoints = [host.sender, host.receiver]
        for owner, requester, owner_call, requester_call in (
                (0, 1, self.py_value, self.ts_value), (1, 0, self.ts_value, self.py_value)):
            with self.subTest(owner=owner):
                suffix = "whole_refusal_" + str(owner)
                dependency = self.remember(owner, suffix + "_dep", "Synthetic hidden dependency marker")
                roots = [self.remember(owner, suffix + "_" + str(i), "Synthetic needle refusal root " + str(i),
                    [{"type": "derived_from", "target": dependency}] if i == 3 else []) for i in range(4)]
                self.set_policy(owner, requester, roots, roots)
                before = [vault_snapshot(endpoint) for endpoint in endpoints]
                query, offered, page = self.exchange_offer(owner, requester, owner_call, requester_call, suffix)
                chosen = requester_call(requester, {"op": "send", "request_id": "req_hint_batch_select_" + suffix,
                    "recipients": [host.identities[owner].key_id], "control": control("select",
                        query_message_id=query["message_id"], selections=[{"offer_message_id": offered["message_id"],
                            "memory_id": item["memory_id"]} for item in page["hints"]])})
                self.assertEqual(chosen["stored_nodes"], 2, chosen)
                self.assertFalse(owner_call(owner, {"op": "receive"})["errors"])
                refused = owner_call(owner, {"op": "receive", "respond_to": chosen["message_id"]})
                self.assertEqual(refused["stored_nodes"], 2, refused)
                received = requester_call(requester, {"op": "receive"})
                self.assertFalse(received["errors"], received)
                message, = received["messages"]
                self.assertIsNone(message["share"])
                expected = control("refusal", request_message_id=chosen["message_id"], reason="not_available")
                self.assertEqual(requester_call(requester, {"op": "receive", "message_id": refused["message_id"]})["control"], expected)
                body = strict_json_loads(outbox_row(endpoints[owner], refused["message_id"])["body"])
                self.assertEqual(body, {"schema_version": CONTENT_SCHEMA, "kind": "hint_control", "control": expected})
                for hidden in [*roots, dependency, "Synthetic hidden dependency marker"]:
                    self.assertNotIn(hidden, canonical_bytes(body).decode())
                self.assertEqual([vault_snapshot(endpoint) for endpoint in endpoints], before)

    def test_both_receivers_reject_valid_signed_shares_with_missing_or_extra_selected_roots_without_ack(self):
        host = self.host
        host.join_receiver()
        endpoints = [host.sender, host.receiver]
        for owner, requester, owner_call, requester_call in (
                (0, 1, self.py_value, self.ts_value), (1, 0, self.ts_value, self.py_value)):
            with self.subTest(receiver=requester):
                suffix = "root_set_" + str(owner)
                roots = [self.remember(owner, suffix + "_" + str(i),
                    "Synthetic needle exact selected roots " + str(i)) for i in range(3)]
                self.set_policy(owner, requester, roots, roots)
                before = [vault_snapshot(endpoint) for endpoint in endpoints]
                query, offer, page = self.exchange_offer(owner, requester, owner_call, requester_call, suffix)
                selected_ids = [item["memory_id"] for item in page["hints"][:2]]
                chosen = requester_call(requester, {"op": "send", "request_id": "req_hint_batch_select_" + suffix,
                    "recipients": [host.identities[owner].key_id], "control": control("select",
                        query_message_id=query["message_id"], selections=[{"offer_message_id": offer["message_id"],
                            "memory_id": memory_id} for memory_id in selected_ids])})
                self.assertEqual(chosen["stored_nodes"], 2, chosen)
                self.assertFalse(owner_call(owner, {"op": "receive"})["errors"])
                # Obtain the real production response body without delivering
                # it. Only these disposable fixture relays are paused.
                for relay in host.relays:
                    relay.stop()
                try:
                    queued = owner_call(owner, {"op": "receive", "respond_to": chosen["message_id"]})
                    self.assertEqual(queued["stored_nodes"], 0, queued)
                    self.assertEqual(queued["content_kind"], "hint_batch_transfer")
                    body = strict_json_loads(outbox_row(endpoints[owner], queued["message_id"])["body"])
                finally:
                    for relay in host.relays:
                        relay.start()
                rejected_ids = []
                for name, returned_roots in (("missing", selected_ids[:1]), ("extra", roots)):
                    output = host.root / ("synthetic-" + suffix + "-" + name + ".share")
                    exported = export_share(host.configs[owner], output,
                        {"schema_version": "universal-memory-selection/v1", "memory_ids": returned_roots})
                    self.assertEqual(exported["selected_records"], len(returned_roots))
                    self.assertEqual(exported["attestations"], len(returned_roots))
                    invalid_body = {**body, "share": b64url(output.read_bytes())}
                    identifier = "msg_" + hashlib.sha256((suffix + name).encode()).hexdigest()
                    inject_ciphertext(endpoints[owner], endpoints[requester], canonical_bytes(invalid_body), identifier)
                    rejected_ids.append(identifier)
                followup = owner_call(owner, {"op": "send", "request_id": "req_hint_batch_followup_" + suffix,
                    "recipients": [host.identities[requester].key_id], "text": "Synthetic normal chat after refused batch"})
                self.assertEqual(followup["stored_nodes"], 2, followup)
                received = requester_call(requester, {"op": "receive"})
                self.assertFalse(received["errors"], received)
                messages = {message["message_id"]: message for message in received["messages"]}
                self.assertEqual(set(messages), {*rejected_ids, followup["message_id"]})
                for identifier in rejected_ids:
                    self.assertEqual(messages[identifier]["state"], "rejected")
                    self.assertEqual(messages[identifier]["code"], "network_invalid_content")
                    with endpoints[requester].db() as db:
                        self.assertEqual(db.execute("SELECT COUNT(*) FROM inbox WHERE message_id=?", (identifier,)).fetchone()[0], 0)
                        self.assertEqual(db.execute("SELECT COUNT(*) FROM quarantine WHERE message_id=?", (identifier,)).fetchone()[0], 1)
                        self.assertEqual(db.execute("SELECT COUNT(*) FROM state WHERE key LIKE ?", ("ack:%:" + identifier,)).fetchone()[0], 0)
                    for relay in host.relays:
                        with Relay(relay.config)._transaction() as db:
                            self.assertEqual(db.execute("SELECT COUNT(*) FROM receipts WHERE message_id=?", (identifier,)).fetchone()[0], 0)
                self.assertEqual(messages[followup["message_id"]]["state"], "validated_saved")
                self.assertEqual(messages[followup["message_id"]]["content_kind"], "message")
                self.assertIsNone(messages[followup["message_id"]]["share"])
                self.assertEqual([vault_snapshot(endpoint) for endpoint in endpoints], before)


if __name__ == "__main__":
    unittest.main()
