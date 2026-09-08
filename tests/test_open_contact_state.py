"""Synthetic real-crypto transactional first contact in protected SQLite state."""
import concurrent.futures
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import subprocess
import unittest
from unittest.mock import patch

from memory_vault import MemoryError, canonical_bytes
from memory_vault_network_crypto import EncryptionIdentity, b64url, document_sha256
from memory_vault_open_contact import MAX_REQUEST_BYTES, SLOT_BYTES, sign_document, sign_rpc, solve_challenge
from memory_vault_open_contact_state import ContactState
from memory_vault_open_control import issue_node
from memory_vault_open_node import _TransportState
from memory_vault_trust import Identity


class ContactStateTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.now = 2_000_000_000
        self.node_id = Identity.generate(self.root / "node.json")
        self.b = Identity.generate(self.root / "owner.json")
        self.b_enc = EncryptionIdentity.generate()
        self.node = issue_node(self.node_id, base_url="http://127.0.0.1:18501", storage_epoch="contact_fixture",
            roles=["router"], revision=1, issued_at=self.now, expires_at=self.now + 3600)
        self.transport = _TransportState(self.root / "transport", self.node_id, "contact_fixture")
        self.db_context = self.transport.db()
        self.db = self.db_context.__enter__()
        self.addCleanup(self.db_context.__exit__, None, None, None)
        self.state = ContactState(self.db, self.node_id, self.node, enabled=True, clock=lambda: self.now)
        self.state.initialize()
        # B explicitly allocates before A even exists.
        self.lease = self.allocate()
        self.policy = self.make_policy()
        self.call(self.b, "policy.put", {"lease": self.lease, "policy": self.policy})
        self.a = Identity.generate(self.root / "newcomer.json")
        self.a_enc = EncryptionIdentity.generate()

    def call(self, signer, action, body, state=None):
        return (state or self.state).handle(sign_rpc(signer, node=self.node, action=action, body=body, now=self.now))

    def allocate(self, *, purpose="knock", items=2, allocation="allocation_fixture", signer=None, encryption=None, seconds=600):
        body = {"encryption_key": (encryption or self.b_enc).public_descriptor(), "purpose": purpose,
                "max_items": items, "max_bytes": items * SLOT_BYTES if purpose == "knock" else 8192,
                "lease_seconds": seconds, "allocation_id": allocation}
        return self.call(signer or self.b, "lease", body)["lease"]

    def make_policy(self, *, revision=1, status="active", lease=None, signer=None, encryption=None):
        lease = lease or self.lease
        raw = lease["payload"]
        return sign_document(signer or self.b, "contact.policy", issued_at=self.now, expires_at=raw["expires_at"],
            node_key_id=self.node_id.key_id, storage_epoch="contact_fixture", lease_id=raw["lease_id"],
            lease_sha256=document_sha256(lease), resource_id=raw["resource_id"], encryption_key=(encryption or self.b_enc).public_descriptor(),
            revision=revision, status=status, max_pending=raw["max_items"])

    def request(self, *, request_id="request_fixture", signer=None, encryption=None, expires_at=None,
                lease=None, policy=None, recipient=None, recipient_encryption=None):
        lease, policy = lease or self.lease, policy or self.policy
        return sign_document(signer or self.a, "contact.request", issued_at=self.now,
            expires_at=expires_at or self.now + 400, request_id=request_id,
            encryption_key=(encryption or self.a_enc).public_descriptor(), recipient_key_id=(recipient or self.b).key_id,
            recipient_encryption_key_id=(recipient_encryption or self.b_enc).key_id, node_key_id=self.node_id.key_id,
            storage_epoch="contact_fixture", lease_id=lease["payload"]["lease_id"],
            resource_id=lease["payload"]["resource_id"], policy_sha256=document_sha256(policy), request_class="message")

    def another_recipient(self):
        owner = Identity.generate(self.root / "another_owner.json")
        encryption = EncryptionIdentity.generate()
        lease = self.allocate(signer=owner, encryption=encryption, allocation="other_owner_allocation")
        policy = self.make_policy(lease=lease, signer=owner, encryption=encryption)
        self.call(owner, "policy.put", {"lease": lease, "policy": policy})
        return {"lease": lease, "policy": policy, "recipient": owner, "recipient_encryption": encryption}

    def proof(self, request, *, purpose="submit", signer=None, encryption=None):
        challenge = self.call(signer or self.a, "challenge", {"request": request, "purpose": purpose})["challenge"]
        answer = solve_challenge(challenge, request=request, node=self.node, purpose=purpose,
                                 encryption_identity=encryption or self.a_enc, now=self.now)
        return {"request": request, "challenge": challenge, "answer": answer}

    def decision(self, request, *, delivery=None, reason="declined"):
        original = request["payload"]
        values = dict(request_id=original["request_id"], request_sha256=document_sha256(request),
            subject_key_id=original["signing_key"]["key_id"], subject_encryption_key_id=original["encryption_key"]["key_id"],
            recipient_encryption_key_id=self.b_enc.key_id, node_key_id=self.node_id.key_id, storage_epoch="contact_fixture")
        grant = None
        if delivery is not None:
            grant = sign_document(self.b, "contact.grant", issued_at=self.now, expires_at=self.now + 300,
                **values, resource_id=delivery["payload"]["resource_id"], operations=["message.store"], resource_lease=delivery)
        return sign_document(self.b, "contact.decision", issued_at=self.now, expires_at=self.now + 300,
            **values, policy_sha256=document_sha256(self.policy), decision="approved" if grant else "rejected",
            reason="accepted" if grant else reason, grant=grant)

    def count(self, table):
        return self.db.execute("SELECT count(*) FROM " + table).fetchone()[0]

    def test_real_request_reserved_result_approved_resource_and_protected_store(self):
        request = self.request()
        result = self.call(self.a, "submit", self.proof(request))
        self.assertEqual(result["state"], "contact_queued")
        self.assertEqual(self.call(self.b, "poll", {"lease_id": self.lease["payload"]["lease_id"]}), {"requests": [request]})
        self.assertEqual(self.call(self.a, "result", self.proof(request, purpose="result")), {"state": "pending", "decision": None})
        delivery = self.allocate(purpose="delivery", allocation="delivery_fixture", items=1)
        decision = self.decision(request, delivery=delivery)
        self.call(self.b, "decide", {"request": request, "decision": decision})
        answer = self.call(self.a, "result", self.proof(request, purpose="result"))
        self.assertEqual(answer, {"state": "approved", "decision": decision})
        self.assertEqual(self.db.execute("SELECT grant_request FROM open_contact_resource_leases WHERE lease_id=?", (delivery["payload"]["lease_id"],)).fetchone()[0], document_sha256(request))
        for table in ("inbox", "outbox", "acknowledgements", "quarantine"):
            self.assertEqual(self.count(table), 0)

    def test_allocation_idempotent_conflict_default_closed_and_expiry_tail(self):
        self.assertEqual(canonical_bytes(self.allocate()), canonical_bytes(self.lease))
        with self.assertRaisesRegex(MemoryError, "contact_allocation_conflict"):
            self.allocate(items=3)
        with self.assertRaisesRegex(MemoryError, "contact_knock_exists"):
            self.allocate(allocation="second_knock")
        self.state.enabled = False
        with self.assertRaisesRegex(MemoryError, "contact_closed"):
            self.allocate(purpose="delivery", allocation="closed_delivery")
        self.state.enabled = True
        self.now += 600
        with self.assertRaises(MemoryError):
            self.allocate()
        self.assertEqual(self.count("open_contact_resource_leases"), 1)
        self.now += 30
        self.state.gc()
        self.assertEqual(self.count("open_contact_resource_leases"), 0)

    def test_request_replay_restart_conflict_and_fresh_result_dual_proof(self):
        request = self.request()
        proof = self.proof(request)
        original = self.call(self.a, "submit", proof)
        with self.transport.db() as db:
            restarted = ContactState(db, self.node_id, self.node, enabled=True, clock=lambda: self.now)
            restarted.initialize()
            self.assertEqual(self.call(self.a, "submit", proof, restarted), original)
        self.assertEqual(self.count("open_contact_requests"), 1)
        with self.assertRaisesRegex(MemoryError, "contact_request_conflict"):
            self.proof(self.request(expires_at=self.now + 399))
        with self.assertRaisesRegex(MemoryError, "contact_pending_exists"):
            self.proof(self.request(request_id="another_request"))
        result_proof = self.proof(request, purpose="result")
        self.call(self.a, "result", result_proof)
        with self.assertRaisesRegex(MemoryError, "contact_invalid_proof"):
            self.call(self.a, "result", result_proof)
        with self.assertRaisesRegex(MemoryError, "contact_wrong_subject"):
            self.call(self.b, "result", result_proof)

    def test_challenge_bad_answer_and_failed_submit_leave_no_partial_obligation(self):
        request = self.request()
        proof = self.proof(request)
        with self.assertRaisesRegex(MemoryError, "contact_invalid_proof"):
            self.call(self.a, "submit", {**proof, "answer": b64url(bytes(32))})
        self.db.execute("CREATE TRIGGER synthetic_contact_failure BEFORE INSERT ON open_contact_requests BEGIN SELECT RAISE(ABORT,'synthetic interruption'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            self.call(self.a, "submit", proof)
        self.assertEqual(self.count("open_contact_requests"), 0)
        self.assertEqual(self.db.execute("SELECT used FROM open_contact_challenges").fetchone()[0], 0)
        self.db.execute("DROP TRIGGER synthetic_contact_failure")
        self.assertEqual(self.call(self.a, "submit", proof)["state"], "contact_queued")

    def test_decision_reservation_rollback_immutable_and_no_delivery_oversubscription(self):
        request = self.request()
        self.call(self.a, "submit", self.proof(request))
        delivery = self.allocate(purpose="delivery", allocation="delivery_fixture", items=1)
        decision = self.decision(request, delivery=delivery)
        self.db.execute("CREATE TRIGGER synthetic_decision_failure BEFORE UPDATE ON open_contact_requests BEGIN SELECT RAISE(ABORT,'synthetic interruption'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            self.call(self.b, "decide", {"request": request, "decision": decision})
        self.assertIsNone(self.db.execute("SELECT grant_request FROM open_contact_resource_leases WHERE purpose='delivery'").fetchone()[0])
        self.db.execute("DROP TRIGGER synthetic_decision_failure")
        self.call(self.b, "decide", {"request": request, "decision": decision})
        self.call(self.b, "decide", {"request": request, "decision": decision})
        with self.assertRaisesRegex(MemoryError, "contact_decision_conflict"):
            self.call(self.b, "decide", {"request": request, "decision": self.decision(request)})
        second = self.request(request_id="second_after_decided")
        self.call(self.a, "submit", self.proof(second))
        with self.assertRaisesRegex(MemoryError, "contact_delivery_unavailable"):
            self.call(self.b, "decide", {"request": second, "decision": self.decision(second, delivery=delivery)})
        # Queue full, but each result was already reserved and rejection fits.
        self.call(self.b, "decide", {"request": second, "decision": self.decision(second)})
        self.assertEqual(self.call(self.a, "result", self.proof(second, purpose="result"))["state"], "rejected")

    def test_post_challenge_revocation_and_policy_floor_survive_restart(self):
        request = self.request()
        proof = self.proof(request)
        revoked = self.make_policy(revision=2, status="revoked")
        self.call(self.b, "policy.put", {"lease": self.lease, "policy": revoked})
        with self.assertRaisesRegex(MemoryError, "contact_unavailable"):
            self.call(self.a, "submit", proof)
        self.assertEqual(self.count("open_contact_requests"), 0)
        with self.transport.db() as db:
            state = ContactState(db, self.node_id, self.node, enabled=True, clock=lambda: self.now)
            state.initialize()
            with self.assertRaisesRegex(MemoryError, "contact_policy_rollback"):
                self.call(self.b, "policy.put", {"lease": self.lease, "policy": self.policy}, state)
            with self.assertRaisesRegex(MemoryError, "contact_lease_revoked"):
                self.call(self.b, "policy.put", {"lease": self.lease, "policy": self.make_policy(revision=3)}, state)

    def test_clock_rechecked_after_writer_lock_and_after_challenge_crypto(self):
        request = self.request()
        rpc = sign_rpc(self.a, node=self.node, action="challenge", body={"request": request, "purpose": "submit"}, now=self.now)
        times = iter([self.now, self.now + 61])
        self.state.clock = lambda: next(times)
        with self.assertRaises(MemoryError):
            self.state.handle(rpc)
        self.state.clock = lambda: self.now
        from memory_vault_open_contact import issue_challenge
        def delayed(*args, **kwargs):
            result = issue_challenge(*args, **kwargs)
            self.now += 61
            return result
        with patch("memory_vault_open_contact_state.issue_challenge", side_effect=delayed):
            with self.assertRaises(MemoryError):
                self.state.handle(rpc)
        self.assertEqual(self.count("open_contact_challenges"), 0)

    def test_challenge_budget_checked_before_crypto_and_retries_do_not_add_rows(self):
        self.state.maximum_challenges = 2
        first = self.request()
        one = self.call(self.a, "challenge", {"request": first, "purpose": "submit"})
        two = self.call(self.a, "challenge", {"request": first, "purpose": "submit"})
        self.assertEqual(one, two)
        with patch("memory_vault_open_contact_state.issue_challenge", side_effect=AssertionError("crypto not admitted")):
            with self.assertRaisesRegex(MemoryError, "contact_challenge_capacity"):
                self.call(self.a, "challenge", {"request": self.request(request_id="different_challenge"), "purpose": "submit"})
        self.assertEqual(self.count("open_contact_challenges"), 1)

    def test_subject_challenge_budget_and_shared_process_cpu_slots(self):
        from memory_vault_open_contact_state import _CHALLENGE_SLOTS
        self.assertTrue(_CHALLENGE_SLOTS["submit"].acquire(blocking=False))
        self.assertTrue(_CHALLENGE_SLOTS["result"].acquire(blocking=False))
        try:
            with self.transport.db() as db:
                other = ContactState(db, self.node_id, self.node, enabled=True, clock=lambda: self.now)
                other.initialize()
                with self.assertRaisesRegex(MemoryError, "contact_challenge_capacity"):
                    self.call(self.a, "challenge", {"request": self.request(), "purpose": "submit"}, other)
        finally:
            _CHALLENGE_SLOTS["submit"].release()
            _CHALLENGE_SLOTS["result"].release()
        self.assertEqual(self.count("open_contact_challenges"), 0)
        for index in range(2):
            self.proof(self.request(request_id="subject_request_" + str(index)))
        other = self.another_recipient()
        for index in range(2, 3):
            self.proof(self.request(request_id="subject_request_" + str(index), **other))
        with self.assertRaisesRegex(MemoryError, "contact_challenge_capacity"):
            self.proof(self.request(request_id="subject_overflow", **other))

    def test_submit_capacity_cannot_starve_reserved_result_or_owner_decision(self):
        from memory_vault_open_contact_state import _CHALLENGE_SLOTS
        self.state.maximum_challenges = 4
        request = self.request()
        self.call(self.a, "submit", self.proof(request))
        other = self.another_recipient()
        for index in range(2):
            self.proof(self.request(request_id="other_recipient_" + str(index), **other))
        self.assertEqual(self.count("open_contact_challenges"), 3)
        stranger = Identity.generate(self.root / "capacity_subject.json")
        with self.assertRaisesRegex(MemoryError, "contact_challenge_capacity"):
            self.proof(self.request(request_id="global_submit_overflow", signer=stranger), signer=stranger)
        decision = self.decision(request)
        self.call(self.b, "decide", {"request": request, "decision": decision})
        self.assertTrue(_CHALLENGE_SLOTS["submit"].acquire(blocking=False))
        try:
            proof = self.proof(request, purpose="result")
        finally:
            _CHALLENGE_SLOTS["submit"].release()
        self.assertEqual(self.call(self.a, "result", proof), {"state": "rejected", "decision": decision})
        self.assertEqual(self.count("open_contact_challenges"), 4)

    def test_single_challenge_configuration_denies_submit_and_per_owner_limit(self):
        self.state.maximum_challenges = 1
        with self.assertRaisesRegex(MemoryError, "contact_challenge_capacity"):
            self.proof(self.request())
        self.assertEqual(self.count("open_contact_challenges"), 0)
        self.state.maximum_challenges = 128
        for index in range(2):
            self.proof(self.request(request_id="owner_budget_" + str(index)))
        stranger = Identity.generate(self.root / "other_subject.json")
        with self.assertRaisesRegex(MemoryError, "contact_challenge_capacity"):
            self.proof(self.request(request_id="owner_overflow", signer=stranger), signer=stranger)
        self.assertEqual(self.count("open_contact_challenges"), 2)

    def test_submit_byte_allowance_preserves_result_challenge_space(self):
        request = self.request()
        self.call(self.a, "submit", self.proof(request))
        other = self.another_recipient()
        used = self.db.execute("SELECT sum(length(record)+256) FROM open_contact_challenges").fetchone()[0]
        # Exactly one conservative full challenge remains in the global budget;
        # it belongs to the reserved result lane, not another public submission.
        self.state.maximum_challenge_bytes = used + MAX_REQUEST_BYTES + 256
        with self.assertRaisesRegex(MemoryError, "contact_challenge_capacity"):
            self.proof(self.request(request_id="submit_byte_overflow", **other))
        proof = self.proof(request, purpose="result")
        self.assertEqual(self.call(self.a, "result", proof), {"state": "pending", "decision": None})

    def test_global_reservations_reject_without_partial_lease(self):
        self.state.maximum_knock_items = 2
        another_owner = Identity.generate(self.root / "another_owner.json")
        with self.assertRaisesRegex(MemoryError, "contact_capacity"):
            self.allocate(signer=another_owner, encryption=EncryptionIdentity.generate(), allocation="knock_overflow", items=1)
        self.assertEqual(self.count("open_contact_resource_leases"), 1)
        self.state.maximum_delivery_bytes = 8191
        with self.assertRaisesRegex(MemoryError, "contact_capacity"):
            self.allocate(purpose="delivery", allocation="delivery_overflow")
        self.assertEqual(self.count("open_contact_resource_leases"), 1)

    def test_policy_fork_is_durable_and_epoch_and_nested_transactions_refuse(self):
        changed = self.make_policy()
        changed["payload"]["max_pending"] = 1
        changed["proof"] = self.b.sign_message(changed["payload"])
        with self.assertRaisesRegex(MemoryError, "contact_policy_conflict"):
            self.call(self.b, "policy.put", {"lease": self.lease, "policy": changed})
        self.assertEqual(self.db.execute("SELECT status FROM open_contact_policies").fetchone()[0], "conflict")
        with self.transport.db() as db:
            restarted = ContactState(db, self.node_id, self.node, enabled=True, clock=lambda: self.now)
            restarted.initialize()
            with self.assertRaisesRegex(MemoryError, "contact_policy_conflict"):
                self.call(self.b, "policy.put", {"lease": self.lease, "policy": self.make_policy(revision=3)}, restarted)
        replacement = issue_node(self.node_id, base_url="http://127.0.0.1:18501", storage_epoch="new_epoch",
            roles=["router"], revision=2, issued_at=self.now, expires_at=self.now + 3600)
        with self.assertRaisesRegex(MemoryError, "contact_storage_epoch_mismatch"):
            ContactState(self.db, self.node_id, replacement, enabled=True, clock=lambda: self.now).initialize()
        self.db.execute("BEGIN IMMEDIATE")
        with self.assertRaisesRegex(MemoryError, "contact_storage_transaction"):
            self.state.gc()
        self.db.rollback()

    def test_two_connections_same_request_exactly_once(self):
        request = self.request()
        proof = self.proof(request)
        rpc = sign_rpc(self.a, node=self.node, action="submit", body=proof, now=self.now)
        barrier = threading.Barrier(2)
        def submit():
            with self.transport.db() as db:
                state = ContactState(db, self.node_id, self.node, enabled=True, clock=lambda: self.now)
                state.initialize()
                barrier.wait(timeout=5)
                return state.handle(rpc)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: submit(), range(2)))
        self.assertEqual(results[0], results[1])
        self.assertEqual(self.count("open_contact_requests"), 1)

    def test_two_connections_same_pair_only_one_pending(self):
        requests = [self.request(request_id="concurrent_" + str(index)) for index in range(2)]
        rpcs = [sign_rpc(self.a, node=self.node, action="submit", body=self.proof(request), now=self.now) for request in requests]
        barrier = threading.Barrier(2)
        def submit(rpc):
            with self.transport.db() as db:
                state = ContactState(db, self.node_id, self.node, enabled=True, clock=lambda: self.now)
                state.initialize()
                barrier.wait(timeout=5)
                try:
                    return state.handle(rpc)["state"]
                except MemoryError as error:
                    return error.code
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(submit, rpcs))
        self.assertCountEqual(results, ["contact_queued", "contact_pending_exists"])
        self.assertEqual(self.count("open_contact_requests"), 1)

    def test_request_gc_retains_original_validity_tail_and_delivery_revocation(self):
        request = self.request()
        self.call(self.a, "submit", self.proof(request))
        delivery = self.allocate(purpose="delivery", allocation="delivery_gc", items=1)
        self.call(self.b, "decide", {"request": request, "decision": self.decision(request, delivery=delivery)})
        self.state.revoke_lease(delivery["payload"]["lease_id"])
        with self.assertRaisesRegex(MemoryError, "contact_lease_revoked"):
            self.call(self.a, "result", self.proof(request, purpose="result"))
        self.now += 400
        self.state.gc()
        self.assertEqual(self.count("open_contact_requests"), 1)
        self.now += 29
        self.state.gc()
        self.assertEqual(self.count("open_contact_requests"), 1)
        self.now += 1
        self.state.gc()
        self.assertEqual(self.count("open_contact_requests"), 0)
        with self.assertRaises(MemoryError):
            self.proof(request)


NATIVE_STATE_DRIVER = r"""
import child from 'node:child_process';
import {syncBuiltinESMExports} from 'node:module';
let subprocessCalls=0;
const deny=()=>{subprocessCalls++;throw Error('native contact state cannot delegate');};
for(const name of ['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork'])child[name]=deny;
syncBuiltinESMExports();
const {ContactState}=await import('./open-contact-state.ts');
const {openTransportState}=await import('./transport-state.ts');
const parts=[];let size=0;
for await(const part of process.stdin){size+=part.length;if(size>2097152)throw Error('synthetic input limit');parts.push(part);}
const input=JSON.parse(Buffer.concat(parts).toString('utf8'));
const binding={profile:'open-routing-v1',signing_key:input.node.payload.signing_key,storage_epoch:input.node.payload.storage_epoch};
let db=openTransportState(input.directory,binding),state;
const construct=()=>{state=new ContactState(db,input.identity,input.node,{enabled:true,...input.options,clock:()=>input.now});state.initialize();};
construct();const results=[];
try{
 for(const event of input.events){
  try{
   let value=null;
   if(event.op==='handle')value=await state.handle(event.rpc);
   else if(event.op==='gc')value=state.gc();
   else if(event.op==='reopen'){db.close();db=openTransportState(input.directory,binding);construct();}
   else if(event.op==='fail_decision')db.exec("CREATE TRIGGER synthetic_native_decision_failure BEFORE UPDATE ON open_contact_requests BEGIN SELECT RAISE(ABORT,'synthetic interruption'); END");
   else if(event.op==='clear_failure')db.exec('DROP TRIGGER synthetic_native_decision_failure');
   else if(event.op==='revoke')value=state.revokeLease(event.lease_id);
   else throw Error('unknown synthetic event');
   results.push({ok:true,value});
  }catch(error){results.push({ok:false,code:error.code??'untyped_error'});}
 }
}finally{db.close();}
process.stdout.write(JSON.stringify({results,subprocessCalls}));
"""


class ContactNativeStateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tests import test_network_typescript_agent_network as native_runtime
        native_runtime.TypeScriptAgentNetworkTests.setUpClass.__func__(cls)
        cls.node_runtime = cls.node
        (cls.fixture / "driver.mjs").write_text(NATIVE_STATE_DRIVER)

    setUp = ContactStateTests.setUp
    call = ContactStateTests.call
    allocate = ContactStateTests.allocate
    make_policy = ContactStateTests.make_policy
    request = ContactStateTests.request
    another_recipient = ContactStateTests.another_recipient
    proof = ContactStateTests.proof
    decision = ContactStateTests.decision
    count = ContactStateTests.count

    def native(self, events, options=None):
        process = subprocess.run([self.node_runtime, "--experimental-strip-types", str(self.fixture / "driver.mjs")],
            input=json.dumps({"directory": str(self.transport.directory), "identity": json.loads((self.root / "node.json").read_text()),
                              "node": self.node, "now": self.now, "events": events, "options": options or {}}).encode(),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=self.fixture, timeout=15)
        self.assertEqual(process.returncode, 0, process.stderr.decode(errors="replace")[-4000:])
        result = json.loads(process.stdout)
        self.assertEqual(result["subprocessCalls"], 0)
        return result["results"]

    def event(self, signer, action, body):
        return {"op": "handle", "rpc": sign_rpc(signer, node=self.node, action=action, body=body, now=self.now)}

    def value(self, event):
        result = self.native([event])[0]
        self.assertTrue(result["ok"], result)
        return result["value"]

    def test_native_challenge_python_solve_native_admission_decision_python_result(self):
        request = self.request()
        challenge = self.value(self.event(self.a, "challenge", {"request": request, "purpose": "submit"}))["challenge"]
        proof = {"request": request, "challenge": challenge, "answer": solve_challenge(challenge, request=request,
            node=self.node, purpose="submit", encryption_identity=self.a_enc, now=self.now)}
        result = self.value(self.event(self.a, "submit", proof))
        self.assertEqual(result["state"], "contact_queued")
        self.assertEqual(self.call(self.b, "poll", {"lease_id": self.lease["payload"]["lease_id"]}), {"requests": [request]})
        delivery = self.value(self.event(self.b, "lease", {"encryption_key": self.b_enc.public_descriptor(),
            "purpose": "delivery", "max_items": 1, "max_bytes": 8192, "lease_seconds": 600, "allocation_id": "native_delivery"}))["lease"]
        decision = self.decision(request, delivery=delivery)
        self.value(self.event(self.b, "decide", {"request": request, "decision": decision}))
        self.assertEqual(self.call(self.a, "result", self.proof(request, purpose="result")), {"state": "approved", "decision": decision})
        self.assertEqual(self.native([{"op": "reopen"}, self.event(self.a, "submit", proof)])[1]["value"], result)
        self.assertEqual(self.count("open_contact_requests"), 1)

    def test_python_queue_native_failed_decision_rolls_back_resource_then_exact_result(self):
        request = self.request()
        self.call(self.a, "submit", self.proof(request))
        delivery = self.allocate(purpose="delivery", allocation="python_delivery", items=1)
        decision = self.decision(request, delivery=delivery)
        event = self.event(self.b, "decide", {"request": request, "decision": decision})
        results = self.native([{"op": "fail_decision"}, event, {"op": "clear_failure"}])
        self.assertFalse(results[1]["ok"])
        self.assertIsNone(self.db.execute("SELECT grant_request FROM open_contact_resource_leases WHERE purpose='delivery'").fetchone()[0])
        self.value(event)
        proof = self.proof(request, purpose="result")
        self.assertEqual(self.value(self.event(self.a, "result", proof)), {"state": "approved", "decision": decision})
        self.native([{"op": "revoke", "lease_id": delivery["payload"]["lease_id"]}])
        with self.assertRaisesRegex(MemoryError, "contact_lease_revoked"):
            self.call(self.a, "result", self.proof(request, purpose="result"))

    def test_native_submit_lane_full_preserves_result_and_single_slot_denies_submit(self):
        options = {"maximum_challenges": 4}
        self.state.maximum_challenges = 4
        request = self.request()
        self.call(self.a, "submit", self.proof(request))
        other = self.another_recipient()
        for index in range(2):
            item = self.request(request_id="native_other_" + str(index), **other)
            result = self.native([self.event(self.a, "challenge", {"request": item, "purpose": "submit"})], options)[0]
            self.assertTrue(result["ok"], result)
        stranger = Identity.generate(self.root / "native_capacity_subject.json")
        extra = self.event(stranger, "challenge", {"request": self.request(request_id="native_submit_overflow", signer=stranger), "purpose": "submit"})
        result = self.native([extra], options)[0]
        self.assertEqual(result, {"ok": False, "code": "contact_challenge_capacity"})
        decision = self.decision(request)
        results = self.native([self.event(self.b, "decide", {"request": request, "decision": decision}),
                              self.event(self.a, "challenge", {"request": request, "purpose": "result"})], options)
        self.assertTrue(results[0]["ok"], results)
        self.assertTrue(results[1]["ok"], results)
        challenge = results[1]["value"]["challenge"]
        proof = {"request": request, "challenge": challenge, "answer": solve_challenge(challenge, request=request,
            node=self.node, purpose="result", encryption_identity=self.a_enc, now=self.now)}
        self.assertEqual(self.native([self.event(self.a, "result", proof)], options)[0]["value"], {"state": "rejected", "decision": decision})
        result = self.native([extra], {"maximum_challenges": 1})[0]
        self.assertEqual(result, {"ok": False, "code": "contact_challenge_capacity"})


if __name__ == "__main__":
    unittest.main()
