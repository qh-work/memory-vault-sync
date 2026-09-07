"""Actual Python/Node endpoints exchanging explicitly requested Hint pages."""
import unittest

from memory_vault import canonical_bytes
from memory_vault_network import NetworkClient
from tests.test_network_hints import CONTENT_SCHEMA, control, policy, outbox_row
from tests import test_network_hints_typescript as hint_harness
from tests.test_network_message_semantics import records, proofs, vault_snapshot, inject_ciphertext


class TypeScriptHintPaginationTests(unittest.TestCase):
    setUpClass = classmethod(hint_harness.TypeScriptHintExchangeTests.setUpClass.__func__)
    setUp = hint_harness.TypeScriptHintExchangeTests.setUp
    ts = hint_harness.TypeScriptHintExchangeTests.ts
    ts_value = hint_harness.TypeScriptHintExchangeTests.ts_value
    py_value = hint_harness.TypeScriptHintExchangeTests.py_value
    set_policy = hint_harness.TypeScriptHintExchangeTests.set_policy
    remember = hint_harness.TypeScriptHintExchangeTests.remember
    exchange_offer = hint_harness.TypeScriptHintExchangeTests.exchange_offer

    def test_both_languages_read_nine_hints_in_three_pages_and_select_last_page(self):
        host = self.host
        host.join_receiver()
        endpoints = [host.sender, host.receiver]
        for owner, requester, owner_call, requester_call in (
                (0, 1, self.py_value, self.ts_value), (1, 0, self.ts_value, self.py_value)):
            with self.subTest(owner=owner):
                dependency = self.remember(owner, "page_dep_" + str(owner), "Synthetic dependency evidence")
                ids = [self.remember(owner, "paged_" + str(owner) + "_" + str(i), "Synthetic needle page " + str(i),
                       [{"type": "derived_from", "target": dependency}]) for i in range(9)]
                hidden = self.remember(owner, "hidden_paged_" + str(owner), "Synthetic needle hidden extra")
                self.set_policy(owner, requester, ids, [*ids, dependency])
                before = [vault_snapshot(endpoint) for endpoint in endpoints]
                query, offered, page = self.exchange_offer(owner, requester, owner_call, requester_call, "pages_" + str(owner))
                pages = [page]
                for index in (1, 2):
                    request = {"op": "send", "request_id": "req_hint_ts_page_" + str(owner) + "_" + str(index),
                        "recipients": [host.identities[owner].key_id], "control": control("page",
                            query_message_id=query["message_id"], cursor=page["next_cursor"])}
                    sent = requester_call(requester, request)
                    self.assertEqual(sent["stored_nodes"], 2, sent)
                    self.assertFalse(owner_call(owner, {"op": "receive"})["errors"])
                    offered = owner_call(owner, {"op": "receive", "respond_to": sent["message_id"]})
                    self.assertEqual(offered["stored_nodes"], 2, offered)
                    self.assertFalse(requester_call(requester, {"op": "receive"})["errors"])
                    read_request = {"op": "receive", "message_id": offered["message_id"]}
                    local_ts = self.ts(requester, read_request)
                    self.assertFalse(local_ts["calls"])
                    self.assertEqual(local_ts["results"][0]["result"], self.py_value(requester, read_request))
                    page = local_ts["results"][0]["result"]["control"]
                    pages.append(page)
                    frozen = outbox_row(endpoints[owner], offered["message_id"])
                    retry = owner_call(owner, {"op": "receive", "respond_to": sent["message_id"]})
                    self.assertEqual(retry["message_id"], offered["message_id"])
                    self.assertEqual(outbox_row(endpoints[owner], retry["message_id"])["envelope"], frozen["envelope"])
                    self.assertEqual(requester_call(requester, {"op": "receive"})["messages"], [])
                self.assertEqual([len(value["hints"]) for value in pages], [4, 4, 1])
                self.assertEqual([value["page_index"] for value in pages], [0, 1, 2])
                self.assertEqual([item["memory_id"] for value in pages for item in value["hints"]], sorted(ids))
                self.assertIsNone(page["next_cursor"])
                for value in pages:
                    self.assertEqual(value["query_message_id"], query["message_id"])
                    self.assertEqual(value["policy_revision"], 1)
                    self.assertEqual(value["expires_at"], pages[0]["expires_at"])
                    self.assertNotIn("total_count", value)
                    self.assertNotIn(hidden, canonical_bytes(value).decode())
                    self.assertNotIn(dependency, canonical_bytes(value).decode())
                self.assertEqual([vault_snapshot(endpoint) for endpoint in endpoints], before)
                selected = page["hints"][0]["memory_id"]
                originals, original_proofs = records(endpoints[owner]), proofs(endpoints[owner])
                chosen = requester_call(requester, {"op": "send", "request_id": "req_hint_ts_last_page_" + str(owner),
                    "recipients": [host.identities[owner].key_id], "control": control("select",
                        offer_message_id=offered["message_id"], memory_id=selected)})
                self.assertFalse(owner_call(owner, {"op": "receive"})["errors"])
                transferred = owner_call(owner, {"op": "receive", "respond_to": chosen["message_id"]})
                self.assertEqual(transferred["stored_nodes"], 2, transferred)
                received = requester_call(requester, {"op": "receive"})
                self.assertFalse(received["errors"], received)
                self.assertEqual(received["messages"][0]["share"]["admission"], "verified")
                for memory_id in (selected, dependency):
                    self.assertEqual(records(endpoints[requester])[memory_id], originals[memory_id])
                    self.assertEqual(proofs(endpoints[requester])[memory_id], original_proofs[memory_id])
                self.assertNotIn(hidden, records(endpoints[requester]))

    def test_equally_authorized_third_peer_cannot_reuse_another_requesters_cursor(self):
        host = self.host
        host.join_receiver()
        with NetworkClient(host.net_configs[2], transport=host.transports[2]) as candidate:
            joined = candidate.connect({"invite": host.invite(2), "roster": host.roster}, request_id="req_hint_page_candidate_join")
            self.assertEqual(joined["joined_nodes"], 2, joined)
            ids = [self.remember(0, "peer_bound_" + str(i), "Synthetic needle peer-bound " + str(i)) for i in range(5)]
            document = policy(host.sender, host.receiver, ids, ids)
            document["peers"].extend(policy(host.sender, candidate, ids, ids)["peers"])
            result = self.ts(0, policy_doc=document)
            self.assertTrue(result["policyResult"]["ok"], result)
            original, _, page = self.exchange_offer(0, 1, self.ts_value, self.py_value, "peer_bound")
            before = [vault_snapshot(endpoint) for endpoint in (host.sender, host.receiver, candidate)]
            identifier = "msg_" + "a" * 64
            inject_ciphertext(candidate, host.sender, canonical_bytes({"schema_version": CONTENT_SCHEMA,
                "kind": "hint_control", "control": control("page", query_message_id=original["message_id"],
                                                             cursor=page["next_cursor"])}), identifier)
            self.assertFalse(self.ts_value(0, {"op": "receive"})["errors"])
            denied = self.ts_value(0, {"op": "receive", "respond_to": identifier})
            self.assertEqual(denied["stored_nodes"], 2, denied)
            self.assertFalse(candidate.receive()["errors"])
            body = candidate.read_message(denied["message_id"])["control"]
            self.assertEqual(body, control("refusal", request_message_id=identifier, reason="not_available"))
            for memory_id in ids:
                self.assertNotIn(memory_id, canonical_bytes(body).decode())
            self.assertEqual([vault_snapshot(endpoint) for endpoint in (host.sender, host.receiver, candidate)], before)


if __name__ == "__main__":
    unittest.main()
