"""Actual owner receipt recovery, with B's own bounded disclosure permission."""
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from memory_vault import MemoryError
from memory_vault_open_repair_client import AckOwnerRecoveryClient
from memory_vault_open_repair_occupied_state import RepairAckOccupiedState
from memory_vault_open_repair_occupied_access import RepairAckOccupiedAccess
import memory_vault_open_repair_occupied as occupied
import memory_vault_open_repair_proof as proof
import memory_vault_open_repair_status as status
import memory_vault_open_repair_wire as wire
from tests.open_repair_ack_fixtures import signed_entry
from tests.test_open_repair_client import RecordingTransport
from tests.test_open_repair_empty_http import EmptyHTTPFixture
from tests.test_open_repair_occupied import receipt_inputs


class OccupiedHTTPFixture:
    def __init__(self,case,*,full_return=True):
        # The three-generation service repeatedly authenticates all retained
        # dependencies. Its finite allowance is authorized before allocation.
        self.empty=EmptyHTTPFixture(case,signature_limit=1024)
        self.http,self.source,self.f=self.empty.http,self.empty.source,self.empty.f
        self.source.now[0]=2_000_000_008
        case.enterContext(patch("time.time",return_value=2_000_000_008))
        original=SimpleNamespace(h=self.source,expected=self.empty.expected,write=self.empty.write,bound=self.empty.result)
        self.receipt,self.disclosure,self.put,self.options=receipt_inputs(original,
            bootstrap_roles=occupied.RETURN_ROLES_FULL if full_return else occupied.RETURN_ROLES_LEGACY)
        self.state=RepairAckOccupiedState(self.source.state)
        self.state.initialize()
        self.result=self.state.put(self.source.resource_id,self.receipt,self.disclosure,self.put,**self.options)

    def verify(self):
        budget=wire.RepairBudget(self.source.state.policy)
        resolver=wire.LocalRawResolver(self.source.state.policy,budget)
        for namespace,key,raw in self.source.db.execute("""SELECT o.namespace,o.opaque_key,o.raw FROM open_repair_ack_objects o
            JOIN open_repair_ack_pins p ON p.namespace=o.namespace AND p.opaque_key=o.opaque_key
            WHERE p.resource_id=? AND p.role IN ('pack','empty:pack','occupied:pack')""",(self.source.resource_id,)):
            resolver.put(namespace,key,bytes(raw))
        return occupied.verify_ack_occupied_source_event(self.result["manifest"],resolver,self.result["commit"],
            **self.f["expected"],**{name:self.empty.expected[name] for name in
                ("expected_receipt_writer","expected_message_id","expected_envelope_ref")},
            policy=self.source.state.policy,budget=budget)


class OccupiedClientTests(unittest.TestCase):
    def start(self,*,full_return=True):
        self.host=OccupiedHTTPFixture(self,full_return=full_return)
        self.f=self.host.f
        self.transport=RecordingTransport(self.host.http.transport)
        self.client=AckOwnerRecoveryClient(self.f["signers"]["owner"],self.f["encryption"]["owner"],
            policy=self.host.source.state.policy,limit_policy=self.f["expected"]["limit_policy"],
            transport=self.transport,allow_loopback=True)
        self.args=dict(target_node_entry=self.f["entries"]["descriptor"],expected_target=self.f["expected"]["expected_target"],
            expected_ack_slot=self.f["expected"]["expected_ack_slot"],root_entry=self.f["entries"]["root"],
            read_entry=self.f["entries"]["read"],bootstrap_entry=self.f["entries"]["bootstrap"],
            **{name:self.host.empty.expected[name] for name in ("expected_receipt_writer","expected_message_id","expected_envelope_ref")})

    def recover(self,**changes):
        return self.client.recover_occupied(self.host.http.base,**(self.args|changes))

    def observe(self,entries):
        gate=RepairAckOccupiedAccess(self.host.source.state)
        gate.initialize()
        prepared=gate.prepare(self.host.source.resource_id,action="proof",current_statuses=entries)
        with self.host.source.state._transaction():
            return gate.check_locked(prepared)

    def test_actual_restart_reads_exact_receipt_object_and_three_complete_generations(self):
        self.start()
        self.host.http.restart()
        statuses=self.host.options["current_statuses"]
        result=self.recover(known_statuses=statuses,archive_statuses=statuses)
        self.assertEqual(result.source.inputs["receipt"].raw,self.host.receipt["raw"])
        self.assertEqual(result.source.inputs["receipt"].ref.as_dict(),self.host.receipt["ref"])
        self.assertEqual(result.source.inputs["receipt"].ref.namespace,"object")
        self.assertEqual(result.source.commit.raw,self.host.result["commit"]["raw"])
        self.assertEqual(result.source.predecessor.custody.raw,self.host.empty.result["custody"]["raw"])
        self.assertEqual(result.proof.manifest.value["response_profile"],"ack_owner_service_v1")
        children=result.proof.manifest.value["children"]
        self.assertEqual(len(children),25)
        self.assertEqual(len([row for row in children if row["role"]=="history.raw_pack"]),3)
        self.assertEqual(result.metrics["requests"],len(result.originals)+2)
        self.assertLessEqual(result.metrics["signature_checks"],self.client.policy.max_signature_checks)

    def test_legacy_two_role_consent_is_not_silently_upgraded_by_server_or_client(self):
        self.start(full_return=False)
        with self.assertRaises(MemoryError) as caught:
            self.recover()
        self.assertEqual(caught.exception.code,"open_request_rejected")
        self.assertEqual(len(self.transport.calls),1)
        source=self.host.verify()
        with self.assertRaises(wire.RepairWireError) as caught:
            self.current(source,self.host.options["current_statuses"])
        self.assertEqual(caught.exception.code,"repair_disclosure_permission")

    def test_wrong_independent_message_cannot_reinterpret_a_real_signed_receipt(self):
        self.start()
        with self.assertRaises(wire.RepairWireError) as caught:
            self.recover(expected_message_id="msg_"+"fd"*32)
        self.assertEqual(caught.exception.code,"repair_ack_bound_mismatch")
        self.assertEqual(self.host.source.db.execute("SELECT status FROM open_repair_ack_resources").fetchone()[0],"occupied")

    def test_corrupt_receipt_child_fails_without_changing_the_committed_receipt(self):
        self.start()
        corrupted=[]
        def alter(raw,reply,child):
            if child and reply==self.host.receipt["raw"]:
                corrupted.append(True)
                return bytes([reply[0]^1])+reply[1:]
            return reply
        self.transport.transform=alter
        with self.assertRaises(wire.RepairWireError) as caught:
            self.recover()
        self.assertEqual(caught.exception.code,"repair_ref_mismatch")
        self.assertEqual(corrupted,[True])
        self.assertEqual(self.host.verify().inputs["receipt"].raw,self.host.receipt["raw"])

    def test_empty_reader_cannot_silently_accept_an_occupied_source(self):
        self.start()
        with self.assertRaises(wire.RepairWireError) as caught:
            self.client.recover_empty(self.host.http.base,**self.args)
        self.assertEqual(caught.exception.code,"repair_proof_mismatch")
        self.assertEqual(len(self.transport.calls),2)

    def test_archived_expired_b_read_revocation_stops_before_any_probe(self):
        self.start()
        payload=json.loads(self.host.options["current_statuses"][-1]["raw"])["payload"]
        payload.update(revision=2,issued_at=2_000_000_007,valid_until=2_000_000_008)
        payload["entries"][0].update(status="revoked",operation_mask=2)
        revoked=signed_entry(payload,self.f["signers"]["writer"],"expired_b_read_revocation")
        with self.assertRaises(wire.RepairWireError) as caught:
            self.recover(archive_statuses=[revoked])
        self.assertEqual(caught.exception.code,"repair_authority_revoked")
        self.assertEqual(self.transport.calls,[])

    def test_old_revision_b_archive_fork_is_not_lost_among_three_generations(self):
        self.start()
        payload=json.loads(self.host.options["current_statuses"][-1]["raw"])["payload"]
        payload["valid_until"]-=1
        fork=signed_entry(payload,self.f["signers"]["writer"],"old_b_canonical_fork")
        with self.assertRaises(wire.RepairWireError) as caught:
            self.recover(archive_statuses=[self.host.options["current_statuses"][-1],fork])
        self.assertEqual(caught.exception.code,"repair_status_conflict")
        self.assertEqual(self.transport.calls,[])

    def test_write_admit_revocation_preserves_actual_owner_receipt_read(self):
        self.start()
        payload=json.loads(self.host.options["current_statuses"][0]["raw"])["payload"]
        payload["revision"]=3
        scope=status.status_scope(self.f["expected"]["expected_ack_slot"]["root_key"],"authority",
            dict(authority_kind="ack.write_grant",authority_sha256=self.host.empty.write["ref"]["raw_sha256"]),
            self.client.policy,wire.RepairBudget(self.client.policy))
        next(row for row in payload["entries"] if row["scope_id"]==scope).update(status="revoked",operation_mask=1)
        revoked=signed_entry(payload,self.f["signers"]["owner"],"occupied_write_admit_revocation")
        decision=self.observe([revoked,*self.host.options["current_statuses"][1:]])
        self.assertTrue(decision.allowed,decision.code)
        result=self.recover(known_statuses=[revoked])
        self.assertEqual(result.source.inputs["receipt"].raw,self.host.receipt["raw"])

    def test_b_current_read_revocation_between_children_stops_receipt_recovery(self):
        self.start()
        changed=[]
        def revoke(raw,reply,child):
            if child and not changed:
                payload=json.loads(self.host.options["current_statuses"][-1]["raw"])["payload"]
                payload["revision"]=2
                payload["entries"][0].update(status="revoked",operation_mask=2)
                signed=signed_entry(payload,self.f["signers"]["writer"],"midstream_b_read_revocation")
                decision=self.observe([*self.host.options["current_statuses"][:-1],signed])
                self.assertFalse(decision.allowed)
                changed.append(True)
            return reply
        self.transport.transform=revoke
        with self.assertRaises(MemoryError) as caught:
            self.recover()
        self.assertEqual(caught.exception.code,"open_request_rejected")
        self.assertEqual(changed,[True])

    def current(self,source,entries):
        by_issuer={json.loads(item["raw"])["payload"]["scope_key"]["issuer_key_id"]:item for item in entries}
        roles,originals={},{}
        for role in (*proof.CURRENT_ROLES,"current.status.ack_disclosure"):
            who="writer" if role.endswith("ack_disclosure") else "target" if role.endswith("ack_resource") else "owner"
            entry=by_issuer[self.f["signers"][who].key_id]
            ref=wire.raw_ref(entry["ref"])
            roles[role]=[ref]
            originals[ref]=entry["raw"]
        return self.client._current(source.predecessor.predecessor,roles,originals,self.f["expected"]["expected_target"],
            wire.RepairBudget(self.client.policy),extra_source=source.predecessor,occupied_source=source,
            receipt_writer=self.host.empty.expected["expected_receipt_writer"])


if __name__=="__main__":
    unittest.main()
