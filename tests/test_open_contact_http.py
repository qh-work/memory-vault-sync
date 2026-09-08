"""Real HTTP first contact; synthetic keys, one physical failure domain."""
import asyncio
import hashlib
import http.client
import json
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest

from memory_vault import MemoryError, canonical_bytes
from memory_vault_network_crypto import EncryptionIdentity
from memory_vault_open_control import coordinate
from memory_vault_open_routing import LookupBudget
from memory_vault_open_contact_client import CONNECT_SCHEMA, OpenContactClient
from memory_vault_open_node import OpenParticipant
from memory_vault_storage import atomic_write
from memory_vault_trust import Identity
from tests.test_open_node import HTTPNodes


class ContactHTTPTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="memory-contact-http-synthetic-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    def host(self, count):
        host = HTTPNodes(self.root, count)
        self.addCleanup(host.close)
        last = count - 1
        host.stop(last)
        config = json.loads(host.configs[last].read_bytes())
        config["contact_policy"] = {"enabled": True}
        atomic_write(host.configs[last], canonical_bytes(config), replace=True)
        host.start(last)
        return host

    def client(self, name, seeds, identity=None, encryption=None):
        identity = identity or Identity.generate(self.root / name / "identity.json")
        encryption = encryption or EncryptionIdentity.generate()
        participant = OpenParticipant(identity, self.root / name / "transport", seeds=seeds, allow_loopback=True)
        self.addCleanup(participant.close)
        return OpenContactClient(participant, encryption)

    def test_current_policy_poll_and_decide_survive_old_queue_and_http_restart(self):
        host = self.host(1)
        owner = self.client("old-policy-owner", host.nodes)
        enabled = asyncio.run(owner.enable(host.nodes[0], allocation_id="revision_knock", max_pending=8))
        lease_id = enabled["lease_id"]
        session = owner._load("policy", lease_id)
        for index in range(4):
            sender = self.client("old-sender-" + str(index), host.nodes)
            submitted = asyncio.run(sender.request(owner.identity.key_id, request_id="a_old_" + str(index)))
            self.assertEqual(submitted["state"], "contact_queued")
        # Capture old inbox references through the official poll before P2.
        old_pending = asyncio.run(owner.poll(lease_id))["requests"]
        self.assertEqual([r["request_id"] for r in old_pending], ["a_old_" + str(i) for i in range(4)])
        # A separate persistent B client reuses the same dual keys and exact
        # allocation through official enable. R returns the same lease before
        # accepting signed P2; the old directory and admitted rows are intact.
        # This does not claim same-directory enable supports changing revision.
        current = self.client("current-policy-owner", host.nodes, owner.identity, owner.encryption)
        renewed = asyncio.run(current.enable(host.nodes[0], allocation_id="revision_knock", max_pending=8, revision=2))
        self.assertEqual(renewed["lease_id"], lease_id)
        current_session = current._load("policy", lease_id)
        self.assertEqual(current_session["lease"], session["lease"])
        self.assertEqual(current_session["policy"]["payload"]["revision"], 2)
        sender = self.client("current-sender", host.nodes)
        self.assertEqual(asyncio.run(sender.request(owner.identity.key_id, request_id="z_current"))["state"], "contact_queued")
        with sqlite3.connect(self.root / "node_0/transport/network.sqlite3") as db:
            old_rows = db.execute("SELECT request_id,record,state,decision,retain_until FROM open_contact_requests WHERE request_id LIKE 'a_old_%' ORDER BY request_id").fetchall()
            self.assertEqual(db.execute("SELECT count(*) FROM open_contact_requests WHERE lease_id=?", (lease_id,)).fetchone()[0], 5)
        current.participant.close()
        host.stop(0)
        host.start(0)
        current = self.client("current-policy-owner", host.nodes, owner.identity, owner.encryption)
        pending = asyncio.run(current.poll(lease_id))
        self.assertEqual([r["request_id"] for r in pending["requests"]], ["z_current"])
        decided = asyncio.run(current.decide(pending["requests"][0]["request_ref"], decision="approved", max_items=1, max_bytes=64))
        self.assertEqual(decided["state"], "decided")
        result = asyncio.run(sender.result("z_current"))
        self.assertEqual(result["state"], "approved")
        self.assertTrue(result["authority_verified"])
        self.assertEqual(asyncio.run(current.poll(lease_id))["requests"], [])
        with self.assertRaisesRegex(MemoryError, "contact_request_mismatch"):
            asyncio.run(owner.decide(old_pending[0]["request_ref"], decision="approved", max_items=1, max_bytes=64))
        with sqlite3.connect(self.root / "node_0/transport/network.sqlite3") as db:
            self.assertEqual(db.execute("SELECT request_id,record,state,decision,retain_until FROM open_contact_requests WHERE request_id LIKE 'a_old_%' ORDER BY request_id").fetchall(), old_rows)
            self.assertEqual(db.execute("SELECT count(*) FROM open_contact_resource_leases WHERE purpose='delivery' AND grant_request IS NOT NULL").fetchone()[0], 1)

    def test_offline_owner_then_new_sender_real_multihop_decision_and_restart(self):
        host = self.host(7)
        owner = self.client("owner", host.nodes[-2:])
        b_identity, b_encryption = owner.identity, owner.encryption
        enabled = asyncio.run(owner.enable(host.nodes[-1], allocation_id="synthetic_knock", max_pending=2))
        self.assertEqual(enabled["state"], "active")
        owner.participant.close()  # B is offline before A is created.
        observer = self.client("observer", host.nodes[:2])
        deadline = time.monotonic() + 25
        target = host.nodes[-1]["payload"]["signing_key"]["key_id"]
        while time.monotonic() < deadline:
            route = asyncio.run(observer.participant._lookup(coordinate(target), "general", LookupBudget()))
            if any(n["payload"]["signing_key"]["key_id"] == target for n in route["candidates"]):
                break
            time.sleep(.25)
        self.assertTrue(any(n["payload"]["signing_key"]["key_id"] == target for n in route["candidates"]), route)
        observer.participant.close()
        sender = self.client("new-sender", host.nodes[:2])
        a_identity, a_encryption = sender.identity, sender.encryption
        calls = []
        transport = sender.participant.transport
        original = transport.request
        def capture(base, request, **kwargs):
            reply = original(base, request, **kwargs)
            calls.append((request, reply.response))
            return reply
        transport.request = capture
        # Existing source/proof files are opaque to this transport flow.
        protected = self.root / "synthetic-memory-proof.bin"
        protected.write_bytes(b"synthetic original canonical record and provenance\x00\xff")
        before = hashlib.sha256(protected.read_bytes()).hexdigest()
        queued = asyncio.run(sender.request(b_identity.key_id, request_id="synthetic_first_contact"))
        self.assertEqual(queued["state"], "contact_queued")
        self.assertFalse(queued["recipient_approved"])
        self.assertFalse(queued["open_messaging_supported"])
        # A queried a node first learned from a real prior response.
        introduced = set()
        traversed = []
        configured = {n["payload"]["signing_key"]["key_id"] for n in host.nodes[:2]}
        for request, response in calls:
            target = request["payload"]["node_key_id"]
            if target in introduced and target not in configured:
                traversed.append(target)
            for node in response["payload"]["body"].get("nodes", []):
                introduced.add(node["payload"]["signing_key"]["key_id"])
        self.assertTrue(traversed, "No response-derived HTTP hop")
        self.assertEqual(asyncio.run(sender.result("synthetic_first_contact"))["state"], "pending")
        sender.participant.close()
        host.stop(6)
        host.start(6)  # R and A restart before B returns; no duplicate charge.
        sender = self.client("new-sender", host.nodes[:2], a_identity, a_encryption)
        self.assertEqual(asyncio.run(sender.request(b_identity.key_id, request_id="synthetic_first_contact"))["state"], "contact_queued")
        owner = self.client("owner", host.nodes[-2:], b_identity, b_encryption)
        pending = asyncio.run(owner.poll(enabled["lease_id"]))
        self.assertEqual(len(pending["requests"]), 1)
        self.assertFalse(pending["recipient_approved"])
        decided = asyncio.run(owner.decide(pending["requests"][0]["request_ref"], decision="approved"))
        self.assertEqual(decided["state"], "decided")
        result = asyncio.run(sender.result("synthetic_first_contact"))
        self.assertEqual(result["state"], "approved")
        self.assertTrue(result["authority_verified"])
        self.assertFalse(result["open_messaging_supported"])
        grant = result["grant"]["payload"]
        self.assertEqual(grant["subject_key_id"], a_identity.key_id)
        self.assertEqual(grant["subject_encryption_key_id"], a_encryption.key_id)
        self.assertEqual(grant["operations"], ["message.store"])
        resource = grant["resource_lease"]["payload"]
        self.assertEqual(resource["purpose"], "delivery")
        self.assertEqual(resource["max_items"], 1)
        self.assertEqual(resource["max_bytes"], 1048576)
        self.assertNotEqual(resource["lease_id"], enabled["lease_id"])
        self.assertEqual(hashlib.sha256(protected.read_bytes()).hexdigest(), before)
        for directory in (self.root / "owner/transport", self.root / "new-sender/transport", self.root / "node_6/transport"):
            with sqlite3.connect(directory / "network.sqlite3") as db:
                for table in ("outbox", "inbox", "acknowledgements", "quarantine"):
                    self.assertEqual(db.execute("SELECT count(*) FROM " + table).fetchone()[0], 0)

    def test_rejection_is_not_authority_and_other_sender_cannot_pull(self):
        host = self.host(1)
        owner = self.client("owner", host.nodes)
        enabled = asyncio.run(owner.enable(host.nodes[0], allocation_id="synthetic_knock", max_pending=1))
        sender = self.client("sender", host.nodes)
        asyncio.run(sender.request(owner.identity.key_id, request_id="same_id"))
        session = sender._load("outgoing", "same_id")
        attacker = self.client("attacker", host.nodes)
        with self.assertRaisesRegex(MemoryError, "contact_wrong_subject"):
            asyncio.run(attacker.call(host.nodes[0], "challenge", {"request": session["request"], "purpose": "result"}))
        pending = asyncio.run(owner.poll(enabled["lease_id"]))
        asyncio.run(owner.decide(pending["requests"][0]["request_ref"], decision="rejected"))
        result = asyncio.run(sender.result("same_id"))
        self.assertEqual(result["state"], "rejected")
        self.assertIsNone(result["grant"])
        self.assertFalse(result["authority_verified"])
        with self.assertRaisesRegex(MemoryError, "contact_local_conflict"):
            asyncio.run(owner.decide(pending["requests"][0]["request_ref"], decision="approved"))

    def test_default_closed_resource_cannot_issue_a_knock_lease(self):
        host = HTTPNodes(self.root, 1)
        self.addCleanup(host.close)
        owner = self.client("owner", host.nodes)
        with self.assertRaises(MemoryError) as caught:
            asyncio.run(owner.enable(host.nodes[0], allocation_id="synthetic_closed"))
        self.assertIn(caught.exception.code, {"contact_closed", "contact_unavailable"})

    def test_invalid_approval_quota_cannot_poison_durable_allocation(self):
        host = self.host(1)
        owner = self.client("owner", host.nodes)
        enabled = asyncio.run(owner.enable(host.nodes[0], allocation_id="synthetic_knock", max_pending=1))
        sender = self.client("sender", host.nodes)
        asyncio.run(sender.request(owner.identity.key_id, request_id="synthetic_quota_validation"))
        request_ref = asyncio.run(owner.poll(enabled["lease_id"]))["requests"][0]["request_ref"]
        for quota in (dict(max_items=0), dict(max_items=True), dict(max_items=[]),
                      dict(max_bytes=0), dict(max_bytes=16 * 1024 * 1024 + 1)):
            with self.subTest(quota=quota), self.assertRaises(MemoryError):
                asyncio.run(owner.decide(request_ref, decision="approved", **quota))
            with owner.participant.state.db() as db:
                self.assertEqual(db.execute("SELECT count(*) FROM open_contact_local WHERE category IN ('allocation','decision') AND reference=?",
                                            (request_ref,)).fetchone()[0], 0)
        result = asyncio.run(owner.decide(request_ref, decision="approved", max_items=1, max_bytes=64))
        self.assertEqual(result["state"], "decided")
        lease = asyncio.run(sender.result("synthetic_quota_validation"))["grant"]["payload"]["resource_lease"]["payload"]
        self.assertEqual((lease["max_items"], lease["max_bytes"]), (1, 64))

    def test_restarted_owner_rejects_changed_quota_on_immutable_decision_retry(self):
        host = self.host(1)
        owner = self.client("owner", host.nodes)
        enabled = asyncio.run(owner.enable(host.nodes[0], allocation_id="synthetic_knock", max_pending=1))
        sender = self.client("sender", host.nodes)
        asyncio.run(sender.request(owner.identity.key_id, request_id="synthetic_exact_approval"))
        request_ref = asyncio.run(owner.poll(enabled["lease_id"]))["requests"][0]["request_ref"]
        asyncio.run(owner.decide(request_ref, decision="approved", max_items=2, max_bytes=4096))
        identity, encryption = owner.identity, owner.encryption
        owner.participant.close()
        owner = self.client("owner", host.nodes, identity, encryption)
        for quota in (dict(max_items=1, max_bytes=4096), dict(max_items=2, max_bytes=1)):
            with self.subTest(quota=quota), self.assertRaisesRegex(MemoryError, "contact_local_conflict"):
                asyncio.run(owner.decide(request_ref, decision="approved", **quota))
        retry = asyncio.run(owner.decide(request_ref, decision="approved", max_items=2, max_bytes=4096))
        self.assertEqual(retry["state"], "decided")
        lease = asyncio.run(sender.result("synthetic_exact_approval"))["grant"]["payload"]["resource_lease"]["payload"]
        self.assertEqual((lease["max_items"], lease["max_bytes"]), (2, 4096))

    def test_invalid_connect_enums_are_typed_and_do_not_write_local_state(self):
        host = self.host(1)
        owner = self.client("owner", host.nodes)
        for value in ([], {}, True, None):
            with self.subTest(action=value), self.assertRaisesRegex(MemoryError, "contact_invalid_connect"):
                asyncio.run(owner.dispatch(dict(schema_version=CONNECT_SCHEMA, action=value)))
            with self.subTest(decision=value), self.assertRaisesRegex(MemoryError, "contact_invalid_decision"):
                asyncio.run(owner.decide("synthetic_missing_ref", decision=value))
        with owner.participant.state.db() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM open_contact_local").fetchone()[0], 0)

    def test_malformed_untrusted_payload_has_bounded_http_rejection(self):
        host = self.host(1)
        port = int(host.nodes[0]["payload"]["base_url"].rsplit(":", 1)[1])
        for payload in ([], None, "synthetic string", 1, True):
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
            try:
                body = canonical_bytes(dict(payload=payload, proof={}))
                connection.request("POST", "/open/v1/rpc", body=body,
                                   headers={"Content-Type": "application/json"})
                with self.subTest(payload=payload):
                    self.assertEqual(connection.getresponse().status, 400)
            finally:
                connection.close()

    def test_local_phase_capacity_reserved_before_remote_allocation_and_result_pull(self):
        host = self.host(1)
        owner = self.client("owner", host.nodes)
        enabled = asyncio.run(owner.enable(host.nodes[0], allocation_id="synthetic_knock", max_pending=1))
        sender = self.client("sender", host.nodes)
        request_id = "synthetic_reserved_phases"
        asyncio.run(sender.request(owner.identity.key_id, request_id=request_id))
        request_ref = asyncio.run(owner.poll(enabled["lease_id"]))["requests"][0]["request_ref"]
        expires = int(time.time()) + 600
        # Controlled occupancy fault injection: these synthetic rows stand for
        # unrelated live controls, without creating 125 extra network sessions.
        for index in range(125):
            owner._save("synthetic_capacity_fixture", "owner_" + str(index), {"synthetic": True}, expires)
        with owner.participant.state.db() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM open_contact_local").fetchone()[0], 127)
        with self.assertRaisesRegex(MemoryError, "contact_local_capacity"):
            asyncio.run(owner.decide(request_ref, decision="approved", max_items=1, max_bytes=64))
        with owner.participant.state.db() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM open_contact_local").fetchone()[0], 127)
            self.assertEqual(db.execute("SELECT count(*) FROM open_contact_local WHERE category IN ('allocation','decision') AND reference=?",
                                        (request_ref,)).fetchone()[0], 0)
            # Expire one owned fixture row, leaving room for both durable phases.
            db.execute("UPDATE open_contact_local SET expires_at=0 WHERE category='synthetic_capacity_fixture' AND reference='owner_124'")
        with sqlite3.connect(self.root / "node_0/transport/network.sqlite3") as db:
            self.assertEqual(db.execute("SELECT count(*) FROM open_contact_resource_leases WHERE purpose='delivery'").fetchone()[0], 0)
        result = asyncio.run(owner.decide(request_ref, decision="approved", max_items=1, max_bytes=64))
        self.assertEqual(result["state"], "decided")
        with owner.participant.state.db() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM open_contact_local").fetchone()[0], 128)
        with sqlite3.connect(self.root / "node_0/transport/network.sqlite3") as db:
            self.assertEqual(db.execute("SELECT count(*) FROM open_contact_resource_leases WHERE purpose='delivery' AND grant_request IS NOT NULL").fetchone()[0], 1)
        # A reserved its result while submitting. Unrelated controls may fill
        # remaining space, but cannot consume that result's existing slot.
        for index in range(126):
            sender._save("synthetic_capacity_fixture", "sender_" + str(index), {"synthetic": True}, expires)
        with self.assertRaisesRegex(MemoryError, "contact_local_capacity"):
            sender._save("synthetic_capacity_fixture", "overflow", {"synthetic": True}, expires)
        pulled = asyncio.run(sender.result(request_id))
        self.assertEqual(pulled["state"], "approved")
        self.assertEqual(sender._load("result", request_id)["decision"]["payload"]["decision"], "approved")
        with sender.participant.state.db() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM open_contact_local").fetchone()[0], 128)

    def test_enable_validates_before_side_effects_and_reserves_its_policy_slot(self):
        host = self.host(1)
        owner = self.client("owner", host.nodes)
        calls = []
        original = owner.participant.transport.request
        def capture(base, request, **kwargs):
            calls.append(request)
            return original(base, request, **kwargs)
        owner.participant.transport.request = capture
        for options in (dict(max_pending="x" * 8000), dict(max_pending=None), dict(revision=True)):
            with self.subTest(argument=next(iter(options))), self.assertRaises(MemoryError):
                asyncio.run(owner.enable(host.nodes[0], allocation_id="synthetic_enable", **options))
            self.assertEqual(calls, [])
        with owner.participant.state.db() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM open_contact_local").fetchone()[0], 0)
        expires = int(time.time()) + 600
        for index in range(128):
            owner._save("synthetic_capacity_fixture", "enable_" + str(index), {"synthetic": True}, expires)
        with self.assertRaisesRegex(MemoryError, "contact_local_capacity"):
            asyncio.run(owner.enable(host.nodes[0], allocation_id="synthetic_enable", max_pending=1))
        self.assertEqual(calls, [])
        with sqlite3.connect(self.root / "node_0/transport/network.sqlite3") as db:
            self.assertEqual(db.execute("SELECT count(*) FROM open_contact_resource_leases WHERE owner=?",
                                        (owner.identity.key_id,)).fetchone()[0], 0)
        with owner.participant.state.db() as db:
            db.execute("UPDATE open_contact_local SET expires_at=0 WHERE category='synthetic_capacity_fixture' AND reference='enable_127'")
        enabled = asyncio.run(owner.enable(host.nodes[0], allocation_id="synthetic_enable", max_pending=1))
        self.assertEqual(enabled["state"], "active")
        # Exact retry at capacity must reuse its existing local control record,
        # including after a lost final response and caller restart.
        identity, encryption = owner.identity, owner.encryption
        owner.participant.close()
        owner = self.client("owner", host.nodes, identity, encryption)
        retry = asyncio.run(owner.enable(host.nodes[0], allocation_id="synthetic_enable", max_pending=1))
        self.assertEqual(retry["lease_id"], enabled["lease_id"])
        with owner.participant.state.db() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM open_contact_local").fetchone()[0], 128)
            self.assertEqual(db.execute("SELECT count(*) FROM open_contact_local WHERE category='policy'").fetchone()[0], 1)
        with sqlite3.connect(self.root / "node_0/transport/network.sqlite3") as db:
            self.assertEqual(db.execute("SELECT count(*) FROM open_contact_resource_leases WHERE owner=?",
                                        (owner.identity.key_id,)).fetchone()[0], 1)


if __name__ == "__main__":
    unittest.main()
