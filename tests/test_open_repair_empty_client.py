"""Independent owner expectations and READ-only current permission for empty ACKs."""
import json
import unittest

from memory_vault import MemoryError
from memory_vault_open_repair_client import AckOwnerRecoveryClient
import memory_vault_open_repair_proof as proof
import memory_vault_open_repair_status as status
import memory_vault_open_repair_wire as wire
from tests.open_repair_ack_fixtures import signed_entry
from tests import test_open_repair_empty as empty_fixture
from tests import test_open_repair_empty_http as http_fixture
from tests.test_open_repair_client import RecordingTransport


class EmptyClientCurrentTests(unittest.TestCase):
    def setUp(self):
        self.case=empty_fixture.OpenRepairEmptyTests()
        self.case.setUp()
        self.addCleanup(self.case.tearDown)
        self.result=self.case.bind()
        self.source=self.case.verify(self.result)
        self.f=self.case.h.fixture
        self.client=AckOwnerRecoveryClient(self.f["signers"]["owner"],self.f["encryption"]["owner"],
            policy=self.case.h.state.policy,limit_policy=self.f["expected"]["limit_policy"],clock=lambda:self.case.h.now[0])
        self.addCleanup(self.client.close)

    def check(self,owner_entry,*,known=()):
        target=next(item for item in self.source.statuses if
                    item.payload["scope_key"]["issuer_key_id"]==self.f["signers"]["target"].key_id)
        owner_ref=wire.raw_ref(owner_entry["ref"])
        originals={owner_ref:owner_entry["raw"],target.ref:target.raw}
        roles={role:[target.ref if role.endswith("ack_resource") else owner_ref] for role in proof.CURRENT_ROLES}
        return self.client._current(self.source.predecessor,roles,originals,self.f["expected"]["expected_target"],
            wire.RepairBudget(self.case.h.state.policy),known,extra_source=self.source)

    def owner_status(self,**changes):
        payload=json.loads(self.case.expected["current_statuses"][0]["raw"])["payload"]
        payload.update(revision=3,**changes)
        return payload

    def test_write_admission_revocation_remains_visible_without_granting_or_revoking_owner_read(self):
        payload=self.owner_status()
        grant=self.source.authorities.originals["write"]
        scope=status.status_scope(self.source.custody.payload["ack_slot"]["root_key"],"authority",
            dict(authority_kind="ack.write_grant",authority_sha256=grant.ref.raw_sha256),
            self.case.h.state.policy,wire.RepairBudget(self.case.h.state.policy))
        entry=next(item for item in payload["entries"] if item["scope_id"]==scope)
        entry.update(status="revoked",operation_mask=1,minimum_document_revision=2)
        signed=signed_entry(payload,self.f["signers"]["owner"],"current_write_revoked_read_allowed")
        checked=self.check(signed)
        owner=next(item for item in checked if item.payload["scope_key"]["issuer_key_id"]==self.f["signers"]["owner"].key_id)
        self.assertEqual(next(item for item in owner.payload["entries"] if item["scope_id"]==scope)["status"],"revoked")

    def test_owner_read_revocation_in_the_same_whole_original_is_rejected(self):
        payload=self.owner_status()
        next(item for item in payload["entries"] if item["scope_kind"]=="ack_slot").update(status="revoked",operation_mask=2)
        signed=signed_entry(payload,self.f["signers"]["owner"],"current_owner_read_revoked")
        with self.assertRaises(wire.RepairWireError) as caught:
            self.check(signed)
        self.assertEqual(caught.exception.code,"repair_authority_revoked")

    def test_unrelated_deferred_authority_scope_must_be_refused_after_exact_source_recovery(self):
        payload=self.owner_status()
        payload["entries"].append(dict(scope_kind="authority",scope_id="fe"*32,
            minimum_document_revision=0,status="active",operation_mask=1))
        payload["entries"].sort(key=lambda item:(item["scope_kind"],item["scope_id"]))
        signed=signed_entry(payload,self.f["signers"]["owner"],"current_unrelated_authority")
        with self.assertRaises(wire.RepairWireError) as caught:
            self.check(signed)
        self.assertEqual(caught.exception.code,"repair_status_disclosure")

    def test_signed_empty_head_must_match_the_authenticated_empty_event(self):
        payload=json.loads(self.result["head"]["raw"])["payload"]
        payload["binding_ref"]=dict(payload["binding_ref"],key="0"*64)
        changed=signed_entry(payload,self.f["signers"]["target"],"mismatched_empty_head")
        with self.assertRaises(wire.RepairWireError) as caught:
            self.client._empty_head(changed,self.source,self.f["expected"]["expected_target"],
                wire.RepairBudget(self.case.h.state.policy))
        self.assertEqual(caught.exception.code,"repair_ack_empty_mismatch")


class EmptyClientHTTPTests(unittest.TestCase):
    def setUp(self):
        self.host=http_fixture.EmptyHTTPFixture(self)
        self.f=self.host.f
        self.transport=RecordingTransport(self.host.http.transport)
        self.client=AckOwnerRecoveryClient(self.f["signers"]["owner"],self.f["encryption"]["owner"],
            policy=self.host.fixture.local,limit_policy=self.f["expected"]["limit_policy"],
            transport=self.transport,allow_loopback=True)

    def options(self):
        return dict(target_node_entry=self.f["entries"]["descriptor"],
            expected_target=self.f["expected"]["expected_target"],expected_ack_slot=self.f["expected"]["expected_ack_slot"],
            root_entry=self.f["entries"]["root"],read_entry=self.f["entries"]["read"],bootstrap_entry=self.f["entries"]["bootstrap"],
            **{name:self.host.expected[name] for name in ("expected_receipt_writer","expected_message_id","expected_envelope_ref")})

    def recover(self,**changes):
        return self.client.recover_empty(self.host.http.base,**(self.options()|changes))

    def test_actual_restart_recovery_authenticates_empty_tuple_and_both_history_generations(self):
        def restart(raw,reply,child):
            if json.loads(raw)["payload"]["kind"]=="bootstrap.probe":
                self.host.http.restart()
            return reply
        self.transport.transform=restart
        known=self.host.expected["current_statuses"]
        result=self.recover(known_statuses=known,archive_statuses=known)
        self.assertEqual(result.source.custody.payload["state"],"empty")
        self.assertEqual(result.source.binding.raw,self.host.result["binding"]["raw"])
        self.assertEqual(result.source.custody.raw,self.host.result["custody"]["raw"])
        self.assertEqual(result.source.authorities.originals["write"].raw,self.host.write["raw"])
        self.assertEqual(result.source.predecessor.bootstrap.originals["bootstrap"].payload["response_profile"],"ack_owner_service_v1")
        self.assertEqual(result.proof.manifest.value["response_profile"],"ack_owner_service_v1")
        self.assertEqual(len(result.proof.manifest.value["children"]),22)
        self.assertEqual(len(result.originals),12)
        self.assertEqual(result.metrics["requests"],12)
        self.assertEqual(result.metrics["signature_checks"],32)
        self.assertEqual(self.host.fixture.usage()[0:2],(12,314))

    def test_independent_writer_and_message_cannot_be_replaced_by_source_assertions(self):
        other=dict(signing_key=self.f["signers"]["owner"].public_descriptor(),
                   encryption_key=self.f["encryption"]["owner"].public_descriptor())
        with self.assertRaises(wire.RepairWireError) as caught:
            self.recover(expected_receipt_writer=other)
        self.assertEqual(caught.exception.code,"repair_ack_bound_mismatch")
        self.assertEqual(self.transport.calls,[])
        with self.assertRaises(wire.RepairWireError) as caught:
            self.recover(expected_message_id="msg_"+"fa"*32)
        self.assertEqual(caught.exception.code,"repair_ack_bound_mismatch")
        self.assertEqual(len(self.transport.calls),14)

    def test_independent_envelope_reference_cannot_be_replaced_by_source_assertion(self):
        changed=dict(self.host.expected["expected_envelope_ref"],raw_sha256="db"*32)
        with self.assertRaises(wire.RepairWireError) as caught:
            self.recover(expected_envelope_ref=changed)
        self.assertEqual(caught.exception.code,"repair_ack_bound_mismatch")
        self.assertEqual(len(self.transport.calls),14)

    def test_unbound_recovery_does_not_silently_accept_empty_phase(self):
        options=self.options()
        for name in ("expected_receipt_writer","expected_message_id","expected_envelope_ref"):
            options.pop(name)
        with self.assertRaises(wire.RepairWireError) as caught:
            self.client.recover(self.host.http.base,**options)
        self.assertEqual(caught.exception.code,"repair_proof_mismatch")
        self.assertEqual(len(self.transport.calls),2)

    def revoke(self,scope_kind,scope_id=None):
        payload=json.loads(self.host.expected["current_statuses"][0]["raw"])["payload"]
        payload["revision"]=3
        item=next(item for item in payload["entries"] if item["scope_kind"]==scope_kind and
                  (scope_id is None or item["scope_id"]==scope_id))
        item.update(status="revoked",operation_mask=2 if scope_kind=="ack_slot" else 1)
        signed=signed_entry(payload,self.f["signers"]["owner"],"empty_http_revocation_"+scope_kind)
        with self.assertRaises(wire.RepairWireError) as caught:
            self.host.empty.bind(self.host.source.resource_id,self.host.write,self.host.offer,
                **(self.host.expected|dict(current_statuses=[signed,self.host.expected["current_statuses"][1]])))
        self.assertEqual(caught.exception.code,"repair_authority_revoked")
        return signed

    def test_write_admit_revocation_keeps_actual_owner_http_read_available(self):
        scope=status.status_scope(self.f["expected"]["expected_ack_slot"]["root_key"],"authority",
            dict(authority_kind="ack.write_grant",authority_sha256=self.host.write["ref"]["raw_sha256"]),
            self.host.fixture.local,wire.RepairBudget(self.host.fixture.local))
        revoked=self.revoke("authority",scope)
        result=self.recover(known_statuses=[revoked])
        owner=next(item for item in result.current_statuses if item.payload["scope_key"]["issuer_key_id"]==self.f["signers"]["owner"].key_id)
        self.assertEqual(next(item for item in owner.payload["entries"] if item["scope_id"]==scope)["status"],"revoked")
        self.assertEqual(result.source.custody.payload["state"],"empty")

    def test_current_owner_read_revocation_between_children_stops_empty_http_recovery(self):
        first=[True]
        def change(raw,reply,child):
            if child and first[0]:
                first[0]=False
                self.revoke("ack_slot")
            return reply
        self.transport.transform=change
        with self.assertRaises(MemoryError) as caught:
            self.recover()
        self.assertEqual(caught.exception.code,"open_request_rejected")
        self.assertFalse(first[0])


if __name__=="__main__":
    unittest.main()
