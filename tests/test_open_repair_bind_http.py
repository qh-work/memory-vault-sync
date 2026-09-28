"""Actual owner preflight, remote original-R bind and durable failed attempts."""
import json
import time
import unittest
from unittest.mock import patch

from memory_vault import MemoryError
from memory_vault_open_repair_bind_client import OwnerAckBindClient
from memory_vault_open_repair_client import AckOwnerRecoveryClient
from memory_vault_open_repair_access import RepairAckAccess
from memory_vault_open_repair_empty_state import RepairAckEmptyState
import memory_vault_open_repair_wire as wire
from tests.open_repair_ack_fixtures import signed_entry
from tests.test_open_repair_empty_http import EmptyHTTPFixture
from tests import test_open_repair_service as service_fixture


class StoppedUpload(RuntimeError):
    pass


class BindTransport:
    def __init__(self,underlying):
        self.underlying,self.calls,self.capture,self.corrupt = underlying,[],False,False

    def request_repair(self,base,raw,*,child=False,deadline):
        kind = json.loads(raw)["payload"]["kind"]
        self.calls.append((kind,raw))
        if kind=="ack.bind_request" and self.capture:
            raise StoppedUpload()
        value = self.underlying.request_repair(base,raw,child=child,deadline=deadline)
        if child and self.corrupt:
            self.corrupt = False
            return bytes([value[0]^1])+value[1:]
        return value


class OwnerBindHTTPTests(unittest.TestCase):
    def setUp(self):
        # Provision the original finite grant before source creation. Enough
        # for a complete preflight, bind, exact retry and later empty recovery.
        start = service_fixture.RepairServiceTests.start
        def provision(source_case,**limits):
            f = source_case.source.fixture
            f["docs"]["allocate"]["payload"]["intent"]["budget"]["max_job_bytes"] = 524288
            for role in ("root","read"):
                f["docs"][role]["payload"]["budget"]["max_job_bytes"] = 524288
            return start(source_case,**limits)
        self.enterContext(patch.object(service_fixture.RepairServiceTests,"start",provision))
        self.host = EmptyHTTPFixture(self,bind=False,signature_limit=1024,proof_limit=524288)
        self.f = self.host.f
        self.transport = BindTransport(self.host.http.transport)
        self.client = OwnerAckBindClient(self.f["signers"]["owner"],self.f["encryption"]["owner"],
            policy=self.host.fixture.local,limit_policy=self.f["expected"]["limit_policy"],
            transport=self.transport,allow_loopback=True)
        # Newly issued observations cover only the two new authorities. The
        # source's old-scope proof remains at the independently known floor.
        old = self.f["entries"]["owner_status"]
        old_scopes = {row["scope_id"] for row in json.loads(old["raw"])["payload"]["entries"]}
        fresh = json.loads(self.host.expected["current_statuses"][0]["raw"])["payload"]
        fresh["entries"] = [row for row in fresh["entries"] if row["scope_id"] not in old_scopes]
        self.statuses = [old,signed_entry(fresh,self.f["signers"]["owner"],"bind_new_authority_status"),
                         self.host.expected["current_statuses"][1]]

    def options(self):
        return dict(target_node_entry=self.f["entries"]["descriptor"],expected_target=self.f["expected"]["expected_target"],
            expected_ack_slot=self.f["expected"]["expected_ack_slot"],root_entry=self.f["entries"]["root"],
            read_entry=self.f["entries"]["read"],bootstrap_entry=self.f["entries"]["bootstrap"],
            write_entry=self.host.write,offer_bootstrap_entry=self.host.offer,
            **(self.host.expected|dict(current_statuses=self.statuses)))

    def execute(self,**changes):
        return self.client.bind(self.host.http.base,**(self.options()|changes))

    def phase(self):
        return self.host.source.db.execute("SELECT status FROM open_repair_ack_resources").fetchone()[0]

    def capture(self):
        self.transport.capture = True
        with self.assertRaises(StoppedUpload):
            self.execute()
        self.transport.capture = False
        return self.transport.calls[-1][1]

    def send(self,raw):
        return self.host.http.transport.request_repair(self.host.http.base,raw,deadline=time.monotonic()+10)

    def rejected(self,raw):
        with self.assertRaises(MemoryError) as caught:
            self.send(raw)
        self.assertEqual(caught.exception.code,"open_request_rejected")

    def test_owner_real_http_bind_restart_exact_retry_and_later_empty_recovery(self):
        result = self.execute()
        self.assertEqual(self.phase(),"empty")
        self.assertEqual(result.source.authorities.originals["write"].raw,self.host.write["raw"])
        self.assertEqual(result.source.authorities.originals["bootstrap"].raw,self.host.offer["raw"])
        self.assertEqual(self.transport.calls[-1][0],"ack.bind_request")
        self.assertTrue(all(kind.startswith("bootstrap.") for kind,_ in self.transport.calls[:-1]))
        self.host.http.restart()
        self.assertEqual(self.send(result.request.raw),result.response)
        row = self.host.source.db.execute("SELECT committed_generation,response FROM open_repair_owner_bind_requests").fetchone()
        self.assertGreater(row[0],result.request.payload["service_generation"])
        self.assertEqual(bytes(row[1]),result.response)
        reader = AckOwnerRecoveryClient(self.f["signers"]["owner"],self.f["encryption"]["owner"],
            policy=self.host.fixture.local,limit_policy=self.f["expected"]["limit_policy"],
            transport=self.host.http.transport,allow_loopback=True)
        options = self.options()
        for name in ("write_entry","offer_bootstrap_entry","current_statuses","read_until","retain_until"):
            options.pop(name)
        recovered = reader.recover_empty(self.host.http.base,**options)
        self.assertEqual(recovered.source.custody.raw,result.source.custody.raw)
        self.assertEqual(self.host.source.db.execute("SELECT count(*) FROM open_repair_ack_bindings").fetchone()[0],1)

    def test_bad_source_child_never_uploads_private_write_or_offer(self):
        self.transport.corrupt = True
        with self.assertRaises(wire.RepairWireError) as caught:
            self.execute()
        self.assertEqual(caught.exception.code,"repair_ref_mismatch")
        self.assertFalse(any(kind=="ack.bind_request" for kind,_ in self.transport.calls))
        self.assertEqual(self.phase(),"unbound")

    def test_newer_known_old_scope_status_cannot_be_ignored_to_enable_upload(self):
        with self.assertRaises(wire.RepairWireError) as caught:
            self.execute(current_statuses=self.host.expected["current_statuses"])
        self.assertEqual(caught.exception.code,"repair_status_rollback")
        self.assertFalse(any(kind=="ack.bind_request" for kind,_ in self.transport.calls))
        self.assertEqual(self.phase(),"unbound")

    def test_owner_signature_and_live_handle_are_required_before_historical_work(self):
        request = self.capture()
        before = self.host.fixture.usage()
        payload = json.loads(request)["payload"]
        forged = signed_entry(payload,self.f["signers"]["writer"],"forged_bind_owner")
        self.rejected(forged["raw"])
        self.assertEqual(self.host.fixture.usage(),before)
        self.assertEqual(self.phase(),"unbound")
        self.assertEqual(self.host.source.db.execute("SELECT count(*) FROM open_repair_owner_bind_requests").fetchone()[0],0)

    def test_failed_authenticated_tuple_consumes_work_and_request_id_without_binding(self):
        request = self.capture()
        payload = json.loads(request)["payload"]
        payload["message_id"] = "msg_"+"df"*32
        bad = signed_entry(payload,self.f["signers"]["owner"],"wrong_independent_bind_message")
        before = self.host.fixture.usage()
        self.rejected(bad["raw"])
        first = self.host.fixture.usage()
        self.assertEqual(first[0],before[0]+1)
        self.assertGreater(first[1],before[1]+1)
        self.assertEqual(self.phase(),"unbound")
        self.assertIsNone(self.host.source.db.execute("SELECT committed_generation FROM open_repair_owner_bind_requests").fetchone()[0])
        self.rejected(bad["raw"])
        second = self.host.fixture.usage()
        self.assertEqual(second[0],first[0]+1)
        self.assertLess(second[1]-first[1],first[1]-before[1])

    def test_current_generation_change_after_signing_cannot_publish_binding(self):
        request = self.capture()
        original_build = RepairAckEmptyState._build
        host = self.host

        def changed(state,held,budget):
            result = original_build(state,held,budget)
            payload = json.loads(self.f["entries"]["owner_status"]["raw"])["payload"]
            payload["revision"] = 3
            next(item for item in payload["entries"] if item["scope_kind"]=="ack_slot").update(status="revoked",operation_mask=1)
            revoked = signed_entry(payload,self.f["signers"]["owner"],"concurrent_bind_revoke")
            with host.http.participant.state.db() as db:
                service = host.http.participant._repair_service(db)
                access = RepairAckAccess(service.state)
                prepared = access.prepare(host.source.resource_id,action="proof",
                    current_statuses=[revoked,self.f["entries"]["target_status"]])
                with service.state._transaction():
                    access.check_locked(prepared)
            return result

        with patch.object(RepairAckEmptyState,"_build",changed):
            self.rejected(request)
        self.assertEqual(self.phase(),"unbound")
        self.assertEqual(self.host.source.db.execute("SELECT count(*) FROM open_repair_ack_bindings").fetchone()[0],0)
        self.assertIsNone(self.host.source.db.execute("SELECT response FROM open_repair_owner_bind_requests").fetchone()[0])


if __name__=="__main__":
    unittest.main()
