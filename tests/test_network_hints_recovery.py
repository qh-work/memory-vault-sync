"""Synthetic Hint recovery: historical transport cannot restore local grants."""
from contextlib import closing
from pathlib import Path
import time
import unittest

from memory_vault import MemoryError, Vault
from memory_vault_network import NetworkClient
import memory_vault_network_recovery as recovery
from tests.test_network_message_semantics import agent, records, proofs, saved_body
from tests.test_network_recovery import archive, fixture


HINT = "memory-vault-hint/v1"


def policy(endpoint, peer, ids=(), revision=1):
    return {"schema_version": "memory-vault-hint-policy/v1", "network_id": endpoint.network_id,
            "owner_key_id": endpoint.identity.key_id, "revision": revision,
            "expires_at": int(time.time()) + 600, "peers": [{"key_id": peer.identity.key_id,
            "hint_memory_ids": list(ids), "record_memory_ids": list(ids)}]}


class HintRecoveryTests(unittest.TestCase):
    def save(self, endpoint, transport, request, text, relations=()):
        result = agent(endpoint, transport).handle({"op": "remember", "request_id": request,
            "kind": "observation", "text": text, "relations": list(relations),
            "experience": {"epistemic_type": "experiment", "observed_under": {"environment": "V1"}}})
        self.assertTrue(result["ok"], result)
        return result["result"]["memory_id"]

    def query(self, a, b, query="Synthetic"):
        sent = b.send("req_hint_recovery_query", [a.identity.key_id],
                      control={"schema_version": HINT, "kind": "query", "query": query})
        self.assertFalse(a.receive()["errors"])
        return sent["message_id"]

    def selected_request(self, a, b, root):
        queried = self.query(a, b)
        offer = a.respond_to(queried)
        self.assertEqual(offer["stored_nodes"], 2)
        self.assertFalse(b.receive()["errors"])
        selected = b.send("req_hint_recovery_select", [a.identity.key_id], control={
            "schema_version": HINT, "kind": "select", "offer_message_id": offer["message_id"], "memory_id": root})
        self.assertFalse(a.receive()["errors"])
        return selected["message_id"]

    def restore(self, source, arguments):
        return recovery.restore_endpoint(directory=source.config_path.parent.parent / "hint-restored", **arguments)

    def test_control_only_backup_does_not_create_vault_or_restore_sharing_policy(self):
        with fixture() as (a, b, transport):
            a.set_hint_policy(policy(a, b))
            queried = self.query(a, b)
            transport.offline.update(a.relays)
            offered = a.respond_to(queried)
            self.assertEqual(offered["stored_nodes"], 0)
            self.assertFalse(a.client_config.vault_path.exists())
            backed, arguments = archive(a)
            self.assertEqual(backed["memory_records"], 0)
            self.assertFalse(backed["hint_policy_included"])
            self.assertFalse(a.client_config.vault_path.exists())
            restored = self.restore(a, arguments)
            self.assertFalse(restored["hint_policy_restored"])
            self.assertTrue(restored["hint_sharing_requires_local_policy"])
            with NetworkClient(Path(restored["network_config"]), transport=transport) as c:
                self.assertFalse((c.directory / "hint-policy.json").exists())
                self.assertEqual(c.read_message(queried)["control"]["kind"], "query")
                transport.offline.clear()
                transport.calls.clear()
                blocked = c.pump(receive_limit=0)
                self.assertGreater(blocked["remaining_outbox"], 0)
                self.assertFalse(any(call[2] == "/v1/messages" for call in transport.calls))
                self.assertEqual(records(c), {})

    def test_pending_transfer_restores_frozen_bytes_but_requires_new_local_grant(self):
        with fixture() as (a, b, transport):
            parent = self.save(a, transport, "req_hint_recovery_parent", "Synthetic V1 evidence.")
            root = self.save(a, transport, "req_hint_recovery_root", "Synthetic V1 method failed.",
                             [{"type": "derived_from", "target": parent}])
            a.set_hint_policy(policy(a, b, [parent, root]))
            selected = self.selected_request(a, b, root)
            transport.offline.add(a.relays[1])
            pending = a.respond_to(selected)
            self.assertEqual(pending["stored_nodes"], 1)
            frozen = saved_body(a, "outbox", pending["message_id"])
            original, original_proofs = records(a), proofs(a)
            _, arguments = archive(a)
            restored = self.restore(a, arguments)
            with NetworkClient(Path(restored["network_config"]), transport=transport) as c:
                self.assertEqual(records(c), original)
                self.assertEqual(proofs(c), original_proofs)
                self.assertEqual(saved_body(c, "outbox", pending["message_id"]), frozen)
                transport.offline.clear()
                transport.calls.clear()
                c.pump(receive_limit=0)
                self.assertFalse(any(call[2] == "/v1/messages" for call in transport.calls))
                c.set_hint_policy(policy(c, b, [root]))
                transport.calls.clear()
                c.pump(receive_limit=0)
                self.assertFalse(any(call[2] == "/v1/messages" for call in transport.calls))
                c.set_hint_policy(policy(c, b, [parent, root], revision=2))
                self.assertEqual(c.pump(receive_limit=0)["remaining_outbox"], 0)
                self.assertEqual(saved_body(c, "outbox", pending["message_id"]), frozen)
                self.assertFalse(b.receive()["errors"])
                self.assertEqual(records(b), original)
                self.assertEqual(proofs(b), original_proofs)

    def test_received_hint_transfer_requires_original_records_in_snapshot(self):
        with fixture() as (a, b, transport):
            root = self.save(a, transport, "req_hint_recovery_original", "Synthetic original experiment.")
            a.set_hint_policy(policy(a, b, [root]))
            request = self.selected_request(a, b, root)
            self.assertEqual(a.respond_to(request)["stored_nodes"], 2)
            self.assertFalse(b.receive()["errors"])
            empty = Vault(a.config_path.parent.parent / "empty-check.sqlite3")
            with b.db() as db, closing(empty._connect()) as memory:
                with self.assertRaises(MemoryError) as denied:
                    recovery._validate_transport(db, b, memory, time.monotonic() + 10)
            self.assertEqual(denied.exception.code, "endpoint_backup_memory_reference_missing")
            _, arguments = archive(b)
            restored = self.restore(b, arguments)
            with NetworkClient(Path(restored["network_config"]), transport=transport) as c:
                self.assertEqual(records(c), records(b))
                self.assertEqual(proofs(c), proofs(b))


if __name__ == "__main__":
    unittest.main()
