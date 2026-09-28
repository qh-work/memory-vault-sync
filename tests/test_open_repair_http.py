"""Actual fixed HTTP repair route over wholly synthetic protected source state."""
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import stat
import threading
import time
import unittest
from unittest.mock import patch

from memory_vault import MemoryError, canonical_bytes
from memory_vault_open_control import issue_node
from memory_vault_open_node import OpenHTTPServer, OpenParticipant
from memory_vault_open_repair_ack import verify_ack_unbound_source_event
import memory_vault_open_repair_probe as probe
import memory_vault_open_repair_proof as proof
from memory_vault_open_repair_resource import AuthenticatedRepairOriginal
import memory_vault_open_repair_wire as wire
from memory_vault_open_transport import OpenHTTPTransport, REPAIR_PATH
from tests.open_repair_ack_fixtures import signed_entry
from tests import test_open_repair_service as service_fixture


class RepairHTTPTests(unittest.TestCase):
    def setUp(self):
        # Synthetic event times are explicit and stable; network deadlines use
        # the real monotonic clock and all I/O uses actual loopback sockets.
        self.clock = patch("time.time", return_value=2_000_000_006)
        self.clock.start()
        self.addCleanup(self.clock.stop)
        self.fixture = service_fixture.RepairServiceTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.source = self.fixture.source
        # HTTPServer's display-only reverse lookup is unrelated to the pinned
        # transport resolver, which remains real and unpatched in these tests.
        with patch("socket.getfqdn", return_value="localhost"):
            self.server = OpenHTTPServer(("127.0.0.1", 0), None)
        self.base = "http://127.0.0.1:" + str(self.server.server_port)
        f = self.source.fixture
        descriptor = issue_node(f["signers"]["target"], base_url=self.base,
            storage_epoch=f["expected"]["target_storage_epoch"], roles=["directory", "router"],
            revision=1, issued_at=2_000_000_005, expires_at=2_000_003_600)
        f["docs"]["descriptor"] = descriptor
        f["entries"]["descriptor"] = signed_entry(descriptor["payload"], f["signers"]["target"], "descriptor")
        self.directory = Path(self.source.temp.name) / "protected-transport"
        self.node_policy = dict(enabled=True, limit_policy=f["expected"]["limit_policy"] |
                                dict(max_probe_bytes=8192, max_signature_checks=512))
        self.participant = self.participant_for(self.directory, self.node_policy)
        # Populate the protected network.sqlite3 created by OpenParticipant;
        # no second transport DB is used by the HTTP service.
        self.source.path = self.directory / "network.sqlite3"
        self.fixture.start()
        self.server.participant = self.participant
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs=dict(poll_interval=0.02), daemon=True)
        self.thread.start()
        self.addCleanup(self.stop)
        self.transport = OpenHTTPTransport(allow_loopback=True)
        self.addCleanup(self.transport.close)

    def participant_for(self, directory, policy):
        f = self.source.fixture
        return OpenParticipant(f["signers"]["target"], directory, seeds=[],
            descriptor=f["docs"]["descriptor"], encryption_identity=f["encryption"]["target"],
            allow_loopback=True, repair_policy=policy)

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self.participant.close()

    def restart(self, *, enabled=True):
        address = self.server.server_address
        self.stop()
        self.participant = self.participant_for(self.directory, self.node_policy if enabled else None)
        with patch("socket.getfqdn", return_value="localhost"):
            self.server = OpenHTTPServer(address, self.participant)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs=dict(poll_interval=0.02), daemon=True)
        self.thread.start()

    def send(self, raw, *, child=False):
        return self.transport.request_repair(self.base, raw, child=child, deadline=time.monotonic()+3)

    def control(self, raw):
        parsed = wire.parse_new_wire(raw, self.fixture.local, wire.RepairBudget(self.fixture.local))
        digest = hashlib.sha256(raw).hexdigest()
        return AuthenticatedRepairOriginal(raw, wire.RawRef("meta",digest,digest,len(raw)), parsed.value["payload"])

    def handshake(self, *, restart=False):
        first = self.fixture.make_probe()
        challenge = self.control(self.send(first.original.raw))
        if restart:
            self.restart()
        answer = self.fixture.solve(first, challenge)
        response_raw = self.send(answer.raw)
        response = wire.parse_new_wire(response_raw, self.fixture.local, wire.RepairBudget(self.fixture.local))
        accepted = self.fixture.authenticate_response(response, first, challenge, answer)
        return first, challenge, answer, accepted

    def assertRejected(self, function, *args, **kwargs):
        with self.assertRaises(MemoryError) as caught:
            function(*args, **kwargs)
        self.assertEqual(caught.exception.code, "open_request_rejected")

    def test_http_restart_and_every_unique_child_reconstruct_verified_source_event(self):
        first, challenge, answer, accepted = self.handshake(restart=True)
        self.assertEqual(self.send(first.original.raw), challenge.raw)
        self.restart()
        self.assertEqual(len(accepted.manifest.value["children"]), 21)
        fetched, roles = {}, {}
        for index, item in enumerate(accepted.manifest.value["children"]):
            ref = wire.raw_ref(item["ref"])
            if ref not in fetched:
                parts = []
                for offset in range(0, ref.size, proof.MAX_CHILD_BYTES):
                    request = self.fixture.child(accepted, index, offset)
                    parts.append(self.send(request.raw, child=True))
                raw = b"".join(parts)
                self.assertEqual((len(raw),hashlib.sha256(raw).hexdigest()), (ref.size,ref.raw_sha256))
                fetched[ref] = dict(raw=raw,ref=ref.as_dict())
            roles[item["role"]] = fetched[ref]
        meter = wire.RepairBudget(self.fixture.local)
        resolver = wire.LocalRawResolver(self.fixture.local,meter)
        for item in accepted.manifest.value["children"]:
            if item["role"] == "history.raw_pack":
                ref = wire.raw_ref(item["ref"])
                resolver.put(ref.namespace,ref.key,fetched[ref]["raw"])
        result = verify_ack_unbound_source_event(roles["history.ack_unbound"],resolver,
            roles["ack.unbound_custody"],**self.source.fixture["expected"],policy=self.fixture.local,budget=meter)
        self.assertEqual(result.stored_at,2_000_000_006)
        self.assertEqual(stat.S_IMODE(self.source.path.stat().st_mode),0o600)
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode),0o700)

    def test_disabled_route_refuses_existing_proof_state_and_requires_encryption_identity(self):
        first = self.fixture.make_probe()
        self.restart(enabled=False)
        self.assertRejected(self.send,first.original.raw)
        with self.assertRaises(MemoryError) as caught:
            OpenParticipant(self.source.fixture["signers"]["target"], self.directory / "missing-key", seeds=[],
                descriptor=self.source.fixture["docs"]["descriptor"], repair_policy=dict(enabled=True))
        self.assertEqual(caught.exception.code,"open_repair_identity_required")
        self.assertFalse((self.directory / "missing-key").exists())

    def test_wrong_key_answer_and_premature_child_never_obtain_proof(self):
        first = self.fixture.make_probe()
        challenge = self.control(self.send(first.original.raw))
        answer = self.fixture.solve(first,challenge)
        wrong = signed_entry(json.loads(answer.raw)["payload"],self.source.fixture["signers"]["writer"],"wrong_http_answer")
        self.assertRejected(self.send,wrong["raw"])
        f = self.source.fixture
        phantom = dict(namespace="meta",key="af"*32,raw_sha256="af"*32,size=2)
        payload = dict(schema_version=probe.SCHEMA,kind="bootstrap.proof_child_request",
            signing_key=f["expected"]["expected_owner"]["signing_key"],issued_at=2_000_000_006,expires_at=2_000_000_046,
            subject=probe._dual(f["expected"]["expected_owner"]),target=probe._dual(f["expected"]["expected_target"]),
            target_storage_epoch=f["expected"]["target_storage_epoch"],purpose="bootstrap.service_proof_child",consumer="ack_owner",
            request_id="synthetic_premature_child",probe_ref=first.original.ref.as_dict(),handle_ref=phantom,
            manifest_ref=phantom,service_generation=1,child_index=0,offset=0,requested_bytes=1)
        premature = signed_entry(payload,f["signers"]["owner"],"premature_http_child")
        self.assertRejected(self.send,premature["raw"],child=True)
        self.assertEqual(self.source.db.execute("SELECT count(*) FROM open_repair_bootstrap_handles").fetchone()[0],0)
        self.assertEqual(self.source.db.execute("SELECT count(*) FROM open_repair_bootstrap_requests").fetchone()[0],0)
        self.assertTrue(self.send(answer.raw))

    def test_exact_request_framing_and_canonical_json_are_required(self):
        raw = self.fixture.make_probe().original.raw
        self.assertRejected(self.send,b" "+raw)
        for headers in ((('Content-Type','application/octet-stream'),),
                        (('Content-Type','application/json'),('Content-Type','application/json')),
                        (('Content-Type','application/json'),('Content-Encoding','identity')),
                        (('Content-Type','application/json'),('Transfer-Encoding','identity'))):
            with self.subTest(headers=headers):
                connection = http.client.HTTPConnection(*self.server.server_address,timeout=3)
                connection.putrequest("POST",REPAIR_PATH)
                connection.putheader("Content-Length",str(len(raw)))
                for name,value in headers:
                    connection.putheader(name,value)
                connection.endheaders(raw)
                self.assertEqual(connection.getresponse().status,400)
                connection.close()
        self.assertEqual(self.source.db.execute("SELECT count(*) FROM open_repair_bootstrap_challenges").fetchone()[0],0)

    def test_capacity_configuration_is_shared_and_conflicts_fail_before_new_db(self):
        capacity = dict(maximum_reserved_bytes=512*1024*1024,maximum_reservations=2048)
        directory = self.directory.parent / "custom-capacity"
        participant = self.participant_for(directory,dict(enabled=True,capacity_policy=capacity))
        try:
            with participant.state.db() as db:
                self.assertEqual(tuple(db.execute("SELECT maximum_reserved_bytes,maximum_reservations FROM open_capacity_policy").fetchone()),tuple(capacity.values()))
        finally:
            participant.close()
        other = self.directory.parent / "conflicting-capacity"
        f = self.source.fixture
        with self.assertRaises(MemoryError) as caught:
            OpenParticipant(f["signers"]["target"],other,seeds=[],descriptor=f["docs"]["descriptor"],
                encryption_identity=f["encryption"]["target"],contact_policy=dict(capacity_policy=capacity | dict(maximum_reservations=1)),
                repair_policy=dict(enabled=True,capacity_policy=capacity))
        self.assertEqual(caught.exception.code,"open_capacity_policy_mismatch")
        self.assertFalse(other.exists())


class RepairResponseFramingTests(unittest.TestCase):
    def test_transport_requires_single_exact_content_type_length_and_bounded_headers(self):
        class Reply(BaseHTTPRequestHandler):
            selected = ()
            def log_message(self,*args):
                pass
            def do_POST(self):
                if self.path != REPAIR_PATH:
                    return self.send_error(404)
                self.rfile.read(int(self.headers["Content-Length"]))
                self.send_response(200)
                for name,value in self.selected:
                    self.send_header(name,value)
                self.end_headers()
                self.wfile.write(b"{}")
        with patch("socket.getfqdn", return_value="localhost"):
            server = ThreadingHTTPServer(("127.0.0.1",0),Reply)
        thread = threading.Thread(target=server.serve_forever,kwargs=dict(poll_interval=0.02),daemon=True)
        thread.start()
        transport = OpenHTTPTransport(allow_loopback=True)
        base = "http://127.0.0.1:"+str(server.server_port)
        try:
            for fields,code in (
                ((('Content-Type','application/json'),('Content-Length','2'),('Content-Type','application/json')),'open_repair_response_headers_rejected'),
                ((('Content-Type','application/json'),('Content-Length','2'),('Content-Length','2')),'open_repair_response_headers_rejected'),
                ((('Content-Type','application/octet-stream'),('Content-Length','2')),'open_repair_response_headers_rejected'),
                ((('Content-Type','application/json'),('Content-Length','02')),'open_repair_response_length_rejected'),
                ((('Content-Type','application/json'),('Content-Length','3')),'open_repair_response_length_rejected'),
                ((('Content-Type','application/json'),('Content-Length','65537')),'open_repair_response_length_rejected'),
                ((('Content-Type','application/json'),('Content-Length','2'),('X-Synthetic','x'*16500)),'open_response_headers_rejected')):
                Reply.selected = fields
                with self.subTest(code=code,fields=tuple(name for name,_ in fields)), self.assertRaises(MemoryError) as caught:
                    transport.request_repair(base,b"{}",deadline=time.monotonic()+2)
                self.assertEqual(caught.exception.code,code)
        finally:
            transport.close();server.shutdown();server.server_close();thread.join(timeout=3)

    def test_repair_transport_preserves_destination_deadline_and_input_bounds(self):
        transport = OpenHTTPTransport()
        try:
            for base in ("http://127.0.0.1:80", "https://192.168.1.2", "https://example.com/arbitrary"):
                with self.subTest(base=base), self.assertRaises(MemoryError) as caught:
                    transport.request_repair(base,b"{}",deadline=time.monotonic()+1)
                self.assertEqual(caught.exception.code,"open_destination_rejected")
            for raw in (b"",b"x"*65537,bytearray(b"{}")):
                with self.subTest(size=len(raw)), self.assertRaises(MemoryError) as caught:
                    transport.request_repair("https://example.com",raw,deadline=time.monotonic()+1)
                self.assertEqual(caught.exception.code,"open_invalid_repair_request")
            with self.assertRaises(MemoryError) as caught:
                transport.request_repair("https://example.com",b"{}",deadline=time.monotonic()-1)
            self.assertEqual(caught.exception.code,"open_budget_exhausted")
        finally:
            transport.close()


if __name__ == "__main__":
    unittest.main()
