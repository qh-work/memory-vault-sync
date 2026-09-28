"""Actual uncertain ACK publication and retained permission-floor regressions."""
import json
import unittest
from unittest.mock import patch

from memory_vault import canonical_bytes
from memory_vault_open_repair_offer_access import RepairAckOfferAccess
import memory_vault_open_repair_probe as probe
import memory_vault_open_repair_status as status
import memory_vault_open_repair_wire as wire
from tests.open_repair_ack_fixtures import signed_entry
from tests import test_open_repair_put_client as put_fixture
from tests import test_open_repair_receipt as saved_fixture
from tests import test_open_repair_offer_client as offer_fixture


class DropCommittedResponse:
    def __init__(self,underlying,*,drop=False):
        self.underlying,self.drop,self.calls=underlying,drop,[]

    def request_repair(self,base,raw,*,child=False,deadline):
        body=json.loads(raw);kind=body.get("kind",body.get("payload",{}).get("kind"))
        self.calls.append((kind,raw))
        response=self.underlying.request_repair(base,raw,child=child,deadline=deadline)
        if kind=="ack.put_request" and self.drop:
            self.drop=False
            raise ConnectionError("synthetic response lost after durable commit")
        return response

    def close(self):
        self.underlying.close()


class PutRecoveryTests(unittest.TestCase):
    def test_existing_object_receipt_replays_the_exact_carrier_and_preserves_namespace(self):
        with patch.object(offer_fixture.RepairOfferClientTests,"fixture_limits",dict(proof_limit=524288),create=True):
            case=put_fixture.RepairPutClientTests()
            self.addCleanup(case.doCleanups);case.setUp()
        client=case.client();client.transport=DropCommittedResponse(client.transport,drop=True)
        journal={}
        receipt,disclosure,put,options=case.inputs
        with self.assertRaises(ConnectionError):
            client.put(case.host.http.base,receipt,disclosure,put,**options,**case.case.args,
                _journal=lambda phase,raw:journal.__setitem__(phase,raw))
        carrier=client.transport.calls[-1][1];before=len(client.transport.calls)
        case.host.http.restart()
        with patch.object(probe,"_sign",side_effect=AssertionError("object retry signed a new request")):
            result=client.resume(case.host.http.base,journal["request"],receipt,disclosure,put,**options,**case.case.args)
        self.assertEqual(client.transport.calls[before:],[("ack.put_request",carrier)])
        self.assertEqual(result.source.inputs["receipt"].ref.namespace,"object")
        self.assertEqual(result.source.inputs["receipt"].ref.as_dict(),receipt["ref"])
        self.assertEqual(result.source.inputs["receipt"].raw,receipt["raw"])
        self.assertEqual(case.host.source.db.execute("SELECT count(*) FROM open_repair_ack_commits").fetchone()[0],1)

    def test_saved_receipt_lost_response_restarts_and_replays_only_the_original_carrier(self):
        case=saved_fixture.SavedReceiptPublicationTests()
        self.addCleanup(case.doCleanups);case.setUp();case.send();case.save_without_old_receipt_upload()
        first=case.publisher()
        # A failed preflight never uploaded private originals and can retry.
        with patch.object(first.client.transport,"request_repair",side_effect=ConnectionError("synthetic preflight unavailable")):
            with self.assertRaises(ConnectionError):
                first.publish_saved(case.ack.http.base,case.request)
        with first.delivery.participant.state.db() as db:
            row=db.execute("SELECT attempted,put_journal FROM open_repair_saved_acks").fetchone()
        self.assertEqual(tuple(row),(0,None))
        first.client.transport=DropCommittedResponse(first.client.transport,drop=True)
        with self.assertRaises(ConnectionError):
            first.publish_saved(case.ack.http.base,case.request)
        carrier=first.client.transport.calls[-1][1]
        before=case.ack.fixture.usage()
        self.assertEqual(case.ack.source.db.execute("SELECT status FROM open_repair_ack_resources").fetchone()[0],"occupied")
        with first.delivery.participant.state.db() as db:
            saved=dict(db.execute("SELECT * FROM open_repair_saved_acks").fetchone())
        self.assertIsNotNone(saved["put_journal"])
        self.assertIsNone(saved["put_response"])
        self.assertIsNone(saved["result"])

        case.ack.http.restart()
        other=case.publisher()
        other.client.transport=DropCommittedResponse(other.client.transport)
        # Tampered durable bytes must be authenticated again before replay.
        journal=json.loads(saved["put_journal"])
        encoded=journal["originals"][0]["raw_base64url"]
        journal["originals"][0]["raw_base64url"]=("A" if encoded[0]!="A" else "B")+encoded[1:]
        with other.delivery.participant.state.db() as db:
            db.execute("UPDATE open_repair_saved_acks SET put_journal=?",(canonical_bytes(journal),))
        with self.assertRaises(wire.RepairWireError):
            other.publish_saved(case.ack.http.base,case.request)
        self.assertEqual(other.client.transport.calls,[])
        with other.delivery.participant.state.db() as db:
            db.execute("UPDATE open_repair_saved_acks SET put_journal=?",(saved["put_journal"],))
        case.ack.source.now[0]=2_000_000_100
        with self.assertRaises(wire.RepairWireError) as caught:
            other.publish_saved(case.ack.http.base,case.request)
        self.assertEqual(caught.exception.code,"repair_reconciliation_required")
        self.assertEqual(other.client.transport.calls,[])
        case.ack.source.now[0]=2_000_000_008
        with patch.object(probe,"_sign",side_effect=AssertionError("retry minted a new signed request")):
            result=other.publish_saved(case.ack.http.base,case.request)
        self.assertFalse(result.from_local_history)
        self.assertEqual(other.client.transport.calls,[("ack.put_request",carrier)])
        self.assertEqual(case.ack.fixture.usage()[0],before[0]+1)
        self.assertGreater(case.ack.fixture.usage()[1],before[1])
        self.assertEqual(case.ack.source.db.execute("SELECT count(*) FROM open_repair_ack_commits").fetchone()[0],1)
        self.assertEqual(case.ack.source.db.execute("SELECT count(*) FROM open_repair_put_requests").fetchone()[0],1)
        self.assertEqual(result.source.inputs["receipt"].raw,bytes(first.delivery._inbox(case.message_id)["receipt"]))
        with other.delivery.participant.state.db() as db:
            durable=db.execute("SELECT put_journal,put_response,result FROM open_repair_saved_acks").fetchone()
        self.assertEqual(bytes(durable["put_journal"]),bytes(saved["put_journal"]))
        self.assertIsNotNone(durable["put_response"])
        self.assertIsNotNone(durable["result"])
        final=other.publish_saved(case.ack.http.base,case.request)
        self.assertTrue(final.from_local_history)
        self.assertEqual(final.source.commit.raw,result.source.commit.raw)
        self.assertEqual(len(other.client.transport.calls),1)

    def test_verified_response_survives_interruption_before_local_result_archive(self):
        case=saved_fixture.SavedReceiptPublicationTests()
        self.addCleanup(case.doCleanups);case.setUp();case.send();case.save_without_old_receipt_upload()
        first=case.publisher()
        with patch.object(first,"_archive",side_effect=RuntimeError("synthetic interruption before evidence archive")):
            with self.assertRaises(RuntimeError):
                first.publish_saved(case.ack.http.base,case.request)
        with first.delivery.participant.state.db() as db:
            saved=dict(db.execute("SELECT * FROM open_repair_saved_acks").fetchone())
        self.assertIsNotNone(saved["put_journal"])
        self.assertIsNotNone(saved["put_response"])
        self.assertIsNone(saved["result"])
        other=case.publisher();other.client.transport=DropCommittedResponse(other.client.transport)
        with patch.object(probe,"_sign",side_effect=AssertionError("retry resigned consent")):
            recovered=other.publish_saved(case.ack.http.base,case.request)
        self.assertFalse(recovered.from_local_history)
        self.assertEqual([kind for kind,_ in other.client.transport.calls],["ack.put_request"])
        with other.delivery.participant.state.db() as db:
            final=db.execute("SELECT put_response,result FROM open_repair_saved_acks").fetchone()
        self.assertEqual(bytes(final["put_response"]),bytes(saved["put_response"]))
        self.assertIsNotNone(final["result"])
        self.assertEqual(case.ack.source.db.execute("SELECT count(*) FROM open_repair_ack_commits").fetchone()[0],1)

    def test_offer_only_archive_read_revocation_is_rechecked_before_private_put(self):
        case=put_fixture.RepairPutClientTests()
        self.addCleanup(case.doCleanups);case.setUp()
        host,f=case.host,case.host.f
        active=json.loads(host.expected["current_statuses"][0]["raw"])["payload"]
        active["revision"]=4
        current=signed_entry(active,f["signers"]["owner"],"current_owner_four")
        revoked=json.loads(current["raw"])["payload"];revoked["revision"]=3
        scope=status.status_scope(f["expected"]["expected_ack_slot"]["root_key"],"authority",
            dict(authority_kind="ack.read_grant",authority_sha256=f["entries"]["read"]["ref"]["raw_sha256"]),
            host.fixture.local,wire.RepairBudget(host.fixture.local))
        revoked["entries"]=[item for item in revoked["entries"] if item["scope_id"]==scope]
        revoked["entries"][0].update(status="revoked",operation_mask=2)
        historical=signed_entry(revoked,f["signers"]["owner"],"caller_only_owner_read_revocation")
        gate=RepairAckOfferAccess(host.source.state);gate.initialize()
        prepared=gate.prepare(host.source.resource_id,action="proof",current_statuses=[current,host.expected["current_statuses"][1]])
        with host.source.state._transaction():
            self.assertTrue(gate.check_locked(prepared).allowed)
        receipt,consent,put,options=case.inputs
        options=dict(options,current_statuses=[current,*options["current_statuses"][1:]])
        client=case.client();client.transport=DropCommittedResponse(client.transport)
        with self.assertRaises(wire.RepairWireError) as caught:
            client.put(host.http.base,receipt,consent,put,archive_statuses=[historical],**options,**case.case.args)
        self.assertEqual(caught.exception.code,"repair_authority_revoked")
        self.assertFalse(any(kind=="ack.put_request" for kind,_ in client.transport.calls))
        self.assertGreater(len(client.transport.calls),0)
        self.assertEqual(host.source.db.execute("SELECT status FROM open_repair_ack_resources").fetchone()[0],"empty")


if __name__=="__main__":
    unittest.main()
