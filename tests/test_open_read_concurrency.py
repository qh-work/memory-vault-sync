"""Read admission under real WAL writers and bounded real socket overload."""
import socket
import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path

from memory_vault import MemoryError
from memory_vault_open_node import OpenHTTPServer, _TransportState
from memory_vault_trust import Identity
from tests import test_open_index as index_fixture


class OpenReadConcurrencyTests(unittest.TestCase):
    def fixture(self):
        fixture = index_fixture.OpenIndexTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.db.execute("PRAGMA journal_mode=WAL")
        fixture.db.execute("PRAGMA busy_timeout=10")
        fixture.put()
        writer = sqlite3.connect(fixture.db_path, timeout=.01)
        self.addCleanup(writer.close)
        return fixture, writer

    def test_reader_observes_committed_revocation_without_waiting_for_uncommitted_writer(self):
        fixture, writer = self.fixture()
        writer.execute("BEGIN IMMEDIATE")
        writer.execute("UPDATE open_contact_floors SET status='revoked'")
        self.assertEqual(fixture.get()["state"], "found")
        writer.commit()
        self.assertEqual(fixture.get(), {"state": "revoked"})

    def test_expired_rows_are_invisible_without_mutation_and_reclaimed_on_next_write(self):
        fixture, writer = self.fixture()
        writer.execute("UPDATE open_contacts SET expires_at=?", (fixture.now,))
        writer.execute("UPDATE open_contact_floors SET retain_until=?", (fixture.now,))
        writer.execute("UPDATE open_index_replay SET retain_until=?", (fixture.now,))
        writer.commit()
        changes = fixture.db.total_changes
        self.assertEqual(fixture.get(), {"state": "not_found"})
        self.assertEqual(fixture.db.total_changes, changes)
        self.assertEqual(fixture.db.execute("SELECT count(*) FROM open_contact_floors").fetchone()[0], 1)
        fixture.put(request_id="synthetic_after_expiry")
        self.assertEqual(fixture.get()["state"], "found")
        self.assertEqual(fixture.db.execute("SELECT count(*) FROM open_index_replay").fetchone()[0], 1)

    def test_transport_open_remains_readable_under_writer_and_checks_binding_every_time(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            identity = Identity.generate(root/"synthetic_identity.json")
            state = _TransportState(root/"transport", identity, "synthetic_epoch")
            with state.db():
                pass
            writer = sqlite3.connect(root/"transport"/"network.sqlite3")
            try:
                writer.execute("BEGIN IMMEDIATE")
                writer.execute("INSERT INTO state VALUES('synthetic_writer','uncommitted')")
                with state.db() as reader:
                    self.assertIsNone(reader.execute("SELECT value FROM state WHERE key='synthetic_writer'").fetchone())
                writer.rollback()
                writer.execute("UPDATE state SET value='{}' WHERE key='configuration_binding'")
                writer.commit()
                with self.assertRaisesRegex(MemoryError, "network_state_configuration_mismatch"):
                    with state.db():
                        pass
            finally:
                writer.close()


class OpenHTTPAdmissionTests(unittest.TestCase):
    def test_occupied_listener_preserves_bind_error_without_starting_workers(self):
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1",0))
            reservation.listen()
            with self.assertRaises(OSError):
                OpenHTTPServer(reservation.getsockname(),None)

    def start(self, participant):
        server = OpenHTTPServer(("127.0.0.1", 0), participant)
        worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval":.01}, daemon=True)
        worker.start()
        def cleanup():
            server.shutdown();server.server_close();worker.join(1)
        self.addCleanup(cleanup)
        return server

    def connect(self, server, request=b"GET /open/v1/node HTTP/1.0\r\n\r\n"):
        connection=socket.create_connection(server.server_address,timeout=4)
        self.addCleanup(connection.close)
        connection.sendall(request)
        return connection

    def wait(self, check):
        deadline=time.monotonic()+2
        while time.monotonic()<deadline:
            if check():return
            time.sleep(.01)
        self.fail("synthetic admission condition not reached")

    def test_finite_queue_preserves_eight_execution_slots_and_overflow_is_retryable(self):
        release=threading.Event()
        self.addCleanup(release.set)
        lock=threading.Lock();active=0;peak=0
        class Participant:
            def current_introduction(self):
                nonlocal active,peak
                with lock:active+=1;peak=max(peak,active)
                release.wait(2)
                with lock:active-=1
                return {"synthetic":True}
        server=self.start(Participant())
        connections=[self.connect(server) for _ in range(8)]
        self.wait(lambda:active==8)
        connections.extend(self.connect(server) for _ in range(16))
        self.wait(lambda:server._requests.qsize()==16)
        overflow=self.connect(server)
        self.assertIn(b"503",overflow.recv(4096))
        release.set()
        for connection in connections:
            self.assertIn(b"200",connection.recv(4096))
        self.assertEqual(peak,8)

    def test_queue_wait_does_not_restart_slow_input_deadline(self):
        server=self.start(None)
        # Incomplete headers occupy all execution slots, with the ordinary
        # absolute deadline. A ninth connection waits behind those same slots.
        connections=[self.connect(server,b"GET /open/v1/node HTTP/1.0\r\n") for _ in range(8)]
        self.wait(lambda:len(server._deadlines)==8)
        start=time.monotonic()
        queued=self.connect(server,b"GET /open/v1/node HTTP/1.0\r\n")
        self.wait(lambda:server._requests.qsize()==1)
        queued.settimeout(3.8)
        try:
            reply=queued.recv(4096)
        except ConnectionResetError:
            reply=b""
        self.assertLess(time.monotonic()-start,3.7)
        self.assertTrue(not reply or b"503" in reply)


if __name__=="__main__":unittest.main()
