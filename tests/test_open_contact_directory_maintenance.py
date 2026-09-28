"""Offline B discovery through actual HTTP, synthetic identities and clocks."""
import asyncio
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from memory_vault import MemoryError, canonical_bytes
from memory_vault_network_crypto import EncryptionIdentity, document, document_sha256
from memory_vault_open_contact import sign_document
from memory_vault_open_contact_client import OpenContactClient
from memory_vault_open_contact_directory import issue_authorization
from memory_vault_open_control import contact_key, issue_contact, issue_node
from memory_vault_open_node import OpenHTTPServer, OpenParticipant
from memory_vault_open_routing import LookupBudget
from memory_vault_trust import Identity


class DirectoryMaintenanceHTTPTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="synthetic-contact-maintenance-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.now = 2_000_000_000
        self.clock = patch("time.time", side_effect=lambda: self.now)
        self.clock.start()
        self.addCleanup(self.clock.stop)
        self.hosts = []
        self.d = self.host("directory", contact=False)
        self.r = self.host("publisher", contact=True, seeds=[self.d["node"]])
        self.b = self.client("recipient")
        self.a = self.client("discoverer")

    def host(self, name, *, contact, seeds=(), directory=None):
        directory = not contact if directory is None else directory
        with patch("socket.getfqdn", return_value="localhost"):
            server = OpenHTTPServer(("127.0.0.1", 0), None)
        signer = Identity.generate(self.root / name / "identity.json")
        node = issue_node(signer, base_url="http://127.0.0.1:" + str(server.server_port),
            storage_epoch="synthetic_" + name, roles=["directory", "router"] if directory else ["router"],
            revision=1, issued_at=self.now, expires_at=self.now + 3600)
        host = dict(server=server, signer=signer, node=node, name=name, seeds=list(seeds), contact=contact, directory=directory)
        self.start(host)
        self.hosts.append(host)
        self.addCleanup(lambda: self.stop(host))
        return host

    def start(self, host):
        participant = OpenParticipant(host["signer"], self.root / host["name"] / "transport",
            descriptor=host["node"], seeds=host["seeds"], allow_loopback=True,
            index_policy={"enabled": host["directory"]}, contact_policy={"enabled": host["contact"]})
        host["participant"] = participant
        participant.table.now = lambda: self.now
        host["server"].participant = participant
        host["thread"] = threading.Thread(target=host["server"].serve_forever,
                                          kwargs={"poll_interval": .01}, daemon=True)
        host["thread"].start()

    def stop(self, host):
        host["server"].shutdown()
        host["server"].server_close()
        host["thread"].join(timeout=2)
        host["participant"].close()

    def restart(self, host):
        address = host["server"].server_address
        self.stop(host)
        with patch("socket.getfqdn", return_value="localhost"):
            host["server"] = OpenHTTPServer(address, None)
        self.start(host)

    def client(self, name):
        signer = Identity.generate(self.root / name / "identity.json")
        participant = OpenParticipant(signer, self.root / name / "transport",
            seeds=[self.d["node"]], allow_loopback=True)
        self.addCleanup(participant.close)
        participant.table.now = lambda: self.now
        return OpenContactClient(participant, EncryptionIdentity.generate())

    def enable(self, maintain=True):
        return asyncio.run(self.b.enable(self.r["node"], allocation_id="synthetic_knock",
            lease_seconds=900, maintain_directory=maintain))

    def find(self):
        return asyncio.run(self.a.participant.find_contact(self.b.identity.key_id))

    def maintain(self):
        return asyncio.run(self.r["participant"].maintain())

    def job(self):
        with self.r["participant"].state.db() as db:
            return db.execute("SELECT state,attempts,requests,bytes,body FROM open_contact_directory_jobs").fetchone()

    def test_offline_recipient_restart_and_original_expiry_over_real_http(self):
        enabled = self.enable()
        self.assertEqual(enabled["directory_maintenance"]["state"], "pending")
        self.assertEqual(self.find()["state"], "found")
        original = self.b._load("policy", enabled["lease_id"])
        self.b.participant.close()  # B performs no renewal or later network work.
        self.now += 301
        self.assertNotEqual(self.find()["state"], "found")
        maintained = self.maintain()["directory_maintenance"]
        self.assertEqual(maintained["state"], "degraded")  # one D, never claim three.
        self.assertGreater(maintained["directory_expires_at"], self.now)
        self.assertEqual(self.find()["state"], "found")
        before = self.job()
        self.restart(self.r)
        self.now += 301
        self.maintain()
        after = self.job()
        self.assertGreater(after[1], before[1])
        self.assertGreater(after[2], before[2])
        self.assertGreater(after[3], before[3])
        found = self.find()
        self.assertEqual(found["state"], "found")
        self.assertLessEqual(found["lease"]["payload"]["expires_at"], enabled["expires_at"])
        with self.r["participant"].state.db() as db:
            self.assertEqual(document(bytes(db.execute("SELECT record FROM open_contact_resource_leases WHERE lease_id=?", (enabled["lease_id"],)).fetchone()[0])), original["lease"])
            self.assertEqual(document(bytes(db.execute("SELECT record FROM open_contact_policies WHERE owner=?", (self.b.identity.key_id,)).fetchone()[0])), original["policy"])
        self.now = enabled["expires_at"]
        self.maintain()
        self.assertEqual(self.job()[0], "stopped")
        self.assertNotEqual(self.find()["state"], "found")

    def test_legacy_opt_in_does_not_authorize_renewal(self):
        enabled = self.enable(False)
        self.assertIsNone(enabled["directory_maintenance"])
        self.assertIsNone(self.job())
        self.now += 301
        self.maintain()
        self.assertNotEqual(self.find()["state"], "found")

    def test_exact_enrollment_does_not_reset_budget_and_known_revocation_stops(self):
        enabled = self.enable()
        self.maintain()
        before = self.job()
        body = self.b._load("directory", enabled["lease_id"])
        result = asyncio.run(self.b.call(self.r["node"], "directory.maintain", body, LookupBudget()))
        self.assertEqual((result["attempts"], result["requests"], result["bytes"]), before[1:4])
        self.restart(self.r)
        policy = dict(body["policy"]["payload"])
        policy.pop("schema_version"); policy.pop("kind"); policy.pop("signing_key")
        policy.update(status="revoked", revision=2)
        revoked = sign_document(self.b.identity, "contact.policy", **policy)
        asyncio.run(self.b.call(self.r["node"], "policy.put", {"lease": body["lease"], "policy": revoked}, LookupBudget()))
        self.now += 250
        self.maintain()
        after = self.job()
        self.assertEqual(after[0], "stopped")
        self.assertEqual(after[1:4], before[1:4])

    def test_delegated_contact_fork_is_durable_and_old_owner_rule_remains(self):
        enabled = self.enable()
        self.maintain()
        body = self.b._load("directory", enabled["lease_id"])
        original = body["contact"]["payload"]
        fork = issue_contact(self.b.identity, encryption_key=original["encryption_key"], revision=1,
            allow_discovery=True, endpoints=original["endpoints"], issued_at=self.now,
            expires_at=original["expires_at"] - 1)
        authorization = issue_authorization(self.b.identity, contact=fork, policy=body["policy"],
            lease=body["lease"], node=self.r["node"])
        wrong = {**body, "contact": fork, "authorization": authorization, "publisher_node": self.r["node"], "lease_seconds": 300}
        with self.assertRaises(MemoryError):
            asyncio.run(self.a.participant._call(self.d["node"], "delegated_put", wrong, LookupBudget()))
        with self.assertRaisesRegex(MemoryError, "open_index_not_owner"):
            asyncio.run(self.r["participant"]._call(self.d["node"], "put", {"contact": fork, "lease_seconds": 300}, LookupBudget()))
        with self.assertRaisesRegex(MemoryError, "open_contact_conflict"):
            asyncio.run(self.r["participant"]._call(self.d["node"], "delegated_put", wrong, LookupBudget()))
        self.restart(self.d)
        self.assertNotEqual(self.find()["state"], "found")
        with self.d["participant"].state.db() as db:
            row = db.execute("SELECT status,second_record FROM open_contact_floors WHERE owner=?", (self.b.identity.key_id,)).fetchone()
            self.assertEqual(row[0], "conflict")
            self.assertEqual(document(bytes(row[1])), fork)

    def test_failed_work_exhausts_original_budget_across_restart(self):
        enabled = self.enable(False)
        session = self.b._load("policy", enabled["lease_id"])
        contact = self.find()["contact"]
        body = {"contact": contact, "policy": session["policy"], "lease": session["lease"]}
        body["authorization"] = issue_authorization(self.b.identity, **body, node=self.r["node"], max_attempts=1)
        asyncio.run(self.b.call(self.r["node"], "directory.maintain", body, LookupBudget()))
        self.d["participant"].index_policy["enabled"] = False  # A real signed service refusal.
        result = self.maintain()["directory_maintenance"]
        self.assertEqual(result["state"], "degraded")
        self.assertEqual(result["last_error"], "open_index_closed")
        self.assertGreater(result["requests"], 0)
        self.assertEqual(result["bytes"], result["requests"] * 131072)
        before = self.job()
        self.restart(self.r)
        self.now += 61
        self.maintain()
        after = self.job()
        self.assertEqual(after[0], "exhausted")
        self.assertEqual(after[1:4], before[1:4])
        repeated = asyncio.run(self.b.call(self.r["node"], "directory.maintain", body, LookupBudget()))
        self.assertEqual(repeated["state"], "exhausted")
        self.assertEqual(repeated["attempts"], 1)

    def test_publisher_epoch_change_cannot_reopen_original_job(self):
        self.enable()
        before = self.job()
        old = self.r["node"]["payload"]
        changed = issue_node(self.r["signer"], base_url=old["base_url"], storage_epoch="new_synthetic_epoch",
            roles=old["roles"], revision=2, issued_at=self.now, expires_at=self.now + 3600)
        with self.assertRaisesRegex(MemoryError, "network_state_configuration_mismatch"):
            OpenParticipant(self.r["signer"], self.root / "publisher" / "transport", descriptor=changed,
                seeds=[self.d["node"]], allow_loopback=True, contact_policy={"enabled": True})
        self.assertEqual(self.job(), before)

    def test_colocated_directory_rejects_its_known_revoked_resource(self):
        combined = self.host("combined", contact=True, directory=True)
        enabled = asyncio.run(self.b.enable(combined["node"], allocation_id="combined_knock",
            lease_seconds=900, maintain_directory=True))
        body = self.b._load("directory", enabled["lease_id"])
        carrier = {**body, "publisher_node": combined["node"], "lease_seconds": 300}
        asyncio.run(combined["participant"]._call(combined["node"], "delegated_put", carrier, LookupBudget()))
        policy = {key: value for key, value in body["policy"]["payload"].items()
                  if key not in {"schema_version", "kind", "signing_key"}}
        policy.update(status="revoked", revision=2)
        revoked = sign_document(self.b.identity, "contact.policy", **policy)
        asyncio.run(self.b.call(combined["node"], "policy.put", {"lease": body["lease"], "policy": revoked}, LookupBudget()))
        # B's old original grant still verifies cryptographically. R's signature
        # cannot bypass the local persisted resource/policy revocation at D.
        with self.assertRaisesRegex(MemoryError, "contact_directory_known_inactive"):
            asyncio.run(combined["participant"]._call(combined["node"], "delegated_put", carrier, LookupBudget()))
