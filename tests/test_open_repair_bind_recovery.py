"""One actual lost-response and restart path with the existing owner DB."""
import hashlib
import json
import unittest
from unittest.mock import patch

from memory_vault_open_node import OpenParticipant
from memory_vault_open_repair_bind_client import OwnerAckBindClient
from memory_vault_open_repair_bind_journal import OwnerBindJournal
import memory_vault_open_repair_probe as probe
import memory_vault_open_repair_wire as wire
from tests import test_open_repair_bind_http as fixture


class LostBindResponseTests(unittest.TestCase):
    def test_committed_lost_response_restores_one_exact_carrier_after_restart(self):
        case = fixture.OwnerBindHTTPTests()
        case.setUp()
        self.addCleanup(case.doCleanups)
        owner = case.f["signers"]["owner"]
        directory = case.host.http.directory.parent / "owner-existing-transport"
        participant = OpenParticipant(owner,directory,seeds=[],allow_loopback=True)
        self.addCleanup(participant.close)
        underlying = case.transport.request_repair
        captured = {}
        def drop(base,raw,*,child=False,deadline):
            response = underlying(base,raw,child=child,deadline=deadline)
            if json.loads(raw)["payload"]["kind"]=="ack.bind_request":
                captured.update(request=raw,response=response)
                raise ConnectionError("synthetic committed response lost")
            return response
        with participant.state.db() as db:
            journal = OwnerBindJournal(db)
            with patch.object(case.transport,"request_repair",drop), self.assertRaises(ConnectionError):
                case.client.bind(case.host.http.base,journal=journal,**case.options())
            key = case.client.journal_key(expected_target=case.options()["expected_target"],expected_ack_slot=case.options()["expected_ack_slot"])
            saved = journal.load(key)
            request_id = journal.request_id(key)
            self.assertEqual(request_id,json.loads(captured["request"])["payload"]["request_id"])
            self.assertIsNone(db.execute("SELECT response FROM open_repair_owner_bind_journal").fetchone()[0])
        self.assertEqual(case.phase(),"empty")
        self.assertEqual(case.host.source.db.execute("SELECT count(*) FROM open_repair_ack_bindings").fetchone()[0],1)
        usage_before = case.host.fixture.usage()
        participant.close()
        case.host.http.restart()
        restored = OpenParticipant(owner,directory,seeds=[],allow_loopback=True)
        self.addCleanup(restored.close)
        client = OwnerAckBindClient(owner,case.f["encryption"]["owner"],policy=case.host.fixture.local,
            limit_policy=case.f["expected"]["limit_policy"],transport=case.transport,allow_loopback=True)
        before = len(case.transport.calls)
        with restored.state.db() as db:
            journal = OwnerBindJournal(db)
            with patch.object(probe,"_sign",side_effect=AssertionError("must not re-sign")):
                result = client.bind(case.host.http.base,journal=journal,**case.options())
            self.assertEqual(journal.load(key),saved)
            self.assertEqual(journal.request_id(key),request_id)
            self.assertEqual(bytes(db.execute("SELECT response FROM open_repair_owner_bind_journal").fetchone()[0]),result.response)
        self.assertEqual(case.transport.calls[before:],[("ack.bind_request",captured["request"])])
        self.assertEqual(result.request.raw,captured["request"])
        self.assertEqual(result.response,captured["response"])
        self.assertEqual(result.metrics["requests"],1)
        self.assertEqual(result.request.payload["message_id"],case.options()["expected_message_id"])
        self.assertEqual(case.host.source.db.execute("SELECT count(*) FROM open_repair_ack_bindings").fetchone()[0],1)
        self.assertGreater(case.host.fixture.usage()[0],usage_before[0])
        revoked = json.loads(case.statuses[0]["raw"])["payload"]
        revoked["revision"] = 3
        next(item for item in revoked["entries"] if item["scope_kind"]=="ack_slot").update(status="revoked",operation_mask=10)
        observation = fixture.signed_entry(revoked,owner,"journal_later_revocation")
        calls = len(case.transport.calls)
        with restored.state.db() as db:
            journal = OwnerBindJournal(db)
            with self.assertRaisesRegex(wire.RepairWireError,"repair_authority_revoked"):
                client.bind(case.host.http.base,journal=journal,**(case.options()|dict(known_statuses=[observation])))
            retained = journal.observations(key)
            self.assertTrue(any(item["raw"]==observation["raw"] for item in retained))
        # A later process omitting the new argument cannot forget a revocation
        # already authenticated and committed in this slot's private journal.
        with restored.state.db() as db:
            with self.assertRaisesRegex(wire.RepairWireError,"repair_authority_revoked"):
                client.bind(case.host.http.base,journal=OwnerBindJournal(db),**case.options())
        self.assertEqual(len(case.transport.calls),calls)
        # Distinct complete references are valid original evidence even when
        # their signed canonical content is identical. Fill the finite archive
        # through authentication, never by injecting rows into the private DB.
        with restored.state.db() as db:
            journal = OwnerBindJournal(db)
            available = 32-len(journal.observations(key))
            active = case.statuses[0]
            aliases = [dict(raw=active["raw"],ref=active["ref"]|dict(key=hashlib.sha256(f"journal_capacity_{i}".encode()).hexdigest()))
                       for i in range(available)]
            with self.assertRaisesRegex(wire.RepairWireError,"repair_authority_revoked"):
                client.bind(case.host.http.base,journal=journal,**(case.options()|dict(archive_statuses=aliases)))
            self.assertEqual(len(journal.observations(key)),32)
            revoked["revision"] = 4
            overflow = fixture.signed_entry(revoked,owner,"journal_capacity_revocation")
            with self.assertRaisesRegex(wire.RepairWireError,"repair_status_history_capacity"):
                client.bind(case.host.http.base,journal=journal,
                    **(case.options()|dict(known_statuses=[overflow],archive_statuses=journal.observations(key))))
            self.assertEqual(db.execute("SELECT blocked_code FROM open_repair_owner_bind_journal").fetchone()[0],
                             "repair_status_history_capacity")
        with restored.state.db() as db:
            with self.assertRaisesRegex(wire.RepairWireError,"repair_status_history_capacity"):
                client.bind(case.host.http.base,journal=OwnerBindJournal(db),**case.options())
        self.assertEqual(len(case.transport.calls),calls)
