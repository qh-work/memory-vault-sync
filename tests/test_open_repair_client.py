"""Owner recovery through real HTTP, using only fresh synthetic identities."""
import copy
import hashlib
import json
import unittest

from memory_vault import MemoryError
from memory_vault_open_repair_client import AckOwnerRecoveryClient
import memory_vault_open_repair_wire as wire
from tests.open_repair_ack_fixtures import signed_entry
from tests import test_open_repair_http as http_fixture


class RecordingTransport:
    def __init__(self, transport, transform=None):
        self.transport, self.transform, self.calls = transport, transform, []

    def request_repair(self, base, raw, *, child, deadline):
        self.calls.append((base, raw, child))
        reply = self.transport.request_repair(base, raw, child=child, deadline=deadline)
        return self.transform(raw, reply, child) if self.transform else reply


class RepairClientTests(unittest.TestCase):
    def setUp(self):
        self.http = http_fixture.RepairHTTPTests()
        self.addCleanup(self.http.doCleanups)
        self.http.setUp()
        self.f = self.http.source.fixture
        self.transport = RecordingTransport(self.http.transport)
        self.client = self.make_client()

    def make_client(self, **changes):
        options = dict(policy=self.http.fixture.local,
                       limit_policy=self.f["expected"]["limit_policy"],
                       allow_loopback=True, transport=self.transport)
        return AckOwnerRecoveryClient(self.f["signers"]["owner"],
            self.f["encryption"]["owner"], **(options | changes))

    def options(self):
        return dict(target_node_entry=self.f["entries"]["descriptor"],
            expected_target=self.f["expected"]["expected_target"],
            expected_ack_slot=self.f["expected"]["expected_ack_slot"],
            root_entry=self.f["entries"]["root"],read_entry=self.f["entries"]["read"],
            bootstrap_entry=self.f["entries"]["bootstrap"])

    def recover(self, **changes):
        return self.client.recover(self.http.base, **(self.options() | changes))

    def assertCode(self, code, function, *args, **kwargs):
        with self.assertRaises(wire.RepairWireError) as caught:
            function(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def authorities(self):
        # Service quotas and observation generations may legitimately change;
        # a failed read must not replace the source's actual authorization.
        db = self.http.source.db
        return (db.execute("SELECT allocation,offer,activation_inputs,active,custody,manifest_ref FROM open_repair_ack_resources ORDER BY resource_id").fetchall(),
                db.execute("SELECT * FROM open_repair_ack_objects ORDER BY namespace,opaque_key").fetchall(),
                db.execute("SELECT * FROM open_repair_ack_pins ORDER BY resource_id,namespace,opaque_key,role").fetchall(),
                copy.deepcopy(self.options()))

    def current(self, result, replacement):
        originals = dict(result.originals)
        roles = {}
        for item in result.proof.manifest.value["children"]:
            roles.setdefault(item["role"], []).append(wire.raw_ref(item["ref"]))
        reference = wire.raw_ref(replacement["ref"])
        originals[reference] = replacement["raw"]
        for role in ("current.status.ack_root", "current.status.ack_read",
                     "current.status.ack_owner_bootstrap", "current.status.ack_slot"):
            roles[role] = [reference]
        return self.client._current(result.source, roles, originals,
            self.f["expected"]["expected_target"], wire.RepairBudget(self.http.fixture.local))

    def test_actual_http_restart_recovers_every_exact_original_and_current_authority(self):
        def restart_after_challenge(raw, reply, child):
            if json.loads(raw)["payload"]["kind"] == "bootstrap.probe":
                self.http.restart()
            return reply
        self.transport.transform = restart_after_challenge
        before = self.authorities()
        result = self.recover()
        self.assertEqual(result.source.stored_at, 2_000_000_006)
        self.assertEqual(result.source.custody.raw, self.http.fixture.custody["raw"])
        self.assertEqual(len(result.proof.manifest.value["children"]), 21)
        self.assertEqual(len(result.originals), 13)
        self.assertEqual(len(result.current_statuses), 2)
        self.assertEqual(result.metrics["requests"], 11)
        self.assertEqual(result.metrics["signature_checks"], 22)
        for ref, raw in result.originals.items():
            self.assertEqual((len(raw),hashlib.sha256(raw).hexdigest()), (ref.size,ref.raw_sha256))
        for role in result.source.manifest.roles:
            self.assertEqual(result.originals[role.original.ref], role.original.raw)
        self.assertEqual(self.authorities(), before)
        with self.assertRaises(TypeError):
            result.originals[result.source.custody.ref] = b"changed"
        with self.assertRaises(TypeError):
            result.current_statuses[0].payload["revision"] = 2

    def test_independent_endpoint_and_target_key_mismatch_never_send_a_probe(self):
        wrong_base = "http://127.0.0.1:" + str(1 if self.http.server.server_port != 1 else 2)
        self.assertCode("repair_proof_mismatch", self.client.recover, wrong_base, **self.options())
        wrong_target = copy.deepcopy(self.f["expected"]["expected_target"])
        wrong_target["signing_key"] = self.f["signers"]["writer"].public_descriptor()
        with self.assertRaises(wire.RepairWireError):
            self.recover(expected_target=wrong_target)
        self.assertEqual(self.transport.calls, [])

    def damaged_child(self, corrupt):
        before = self.authorities()
        def damage(raw, reply, child):
            if not child:
                return reply
            return bytes((reply[0] ^ 1,)) + reply[1:] if corrupt else reply[:-1]
        self.transport.transform = damage
        self.assertCode("repair_ref_mismatch", self.recover)
        self.assertEqual(self.authorities(), before)

    def test_short_child_fails_without_mutating_authorization(self):
        self.damaged_child(False)

    def test_corrupt_child_fails_without_mutating_authorization(self):
        self.damaged_child(True)

    def test_current_revocation_between_children_stops_actual_http_recovery(self):
        first = [True]
        def revoke(raw, reply, child):
            if child and first[0]:
                first[0] = False
                decision = self.http.fixture.observe(self.http.fixture.statuses(revoked=True))
                self.assertEqual(decision.code, "repair_authority_revoked")
            return reply
        self.transport.transform = revoke
        before = self.authorities()
        with self.assertRaises(MemoryError) as caught:
            self.recover()
        self.assertEqual(caught.exception.code, "open_request_rejected")
        self.assertFalse(first[0])
        self.assertEqual(self.authorities(), before)

    def test_known_expired_owner_revocation_still_refuses_before_network(self):
        payload = copy.deepcopy(self.f["docs"]["owner_status"]["payload"])
        payload.update(revision=2, issued_at=1_999_999_900, valid_until=2_000_000_005)
        payload["entries"][0]["status"] = "revoked"
        known = signed_entry(payload, self.f["signers"]["owner"], "expired_revocation")
        self.assertCode("repair_authority_revoked", self.recover, known_statuses=[known])
        self.assertEqual(self.transport.calls, [])

    def test_known_original_wire_variation_preserves_canonical_identity_and_recovers(self):
        known = []
        for role in ("owner_status", "target_status"):
            raw = b" \n" + self.f["entries"][role]["raw"] + b"\n"
            digest = hashlib.sha256(raw).hexdigest()
            known.append(dict(raw=raw, ref=dict(namespace="meta", key=hashlib.sha256(role.encode()).hexdigest(),
                                               raw_sha256=digest, size=len(raw))))
        result = self.recover(known_statuses=known, archive_statuses=known)
        self.assertEqual(len(result.originals), 13)
        self.assertEqual(result.metrics["signature_checks"], 24)
        self.assertEqual(result.metrics["requests"], 11)

    def test_archived_old_revision_fork_is_rejected_before_network(self):
        known = self.http.fixture.statuses(revision=3)[0]
        old = self.http.fixture.statuses(revision=2)[0]
        payload = json.loads(old["raw"])["payload"]
        payload["valid_until"] -= 1
        fork = signed_entry(payload,self.f["signers"]["owner"],"archived_old_fork")
        self.assertCode("repair_status_conflict",self.recover,
                        known_statuses=[known],archive_statuses=[old,fork])
        self.assertEqual(self.transport.calls,[])

    def test_archived_revocation_is_not_ignored_by_a_newer_floor_subset(self):
        old = copy.deepcopy(self.f["docs"]["owner_status"]["payload"])
        old.update(revision=2,issued_at=1_999_999_900,valid_until=2_000_000_005)
        old["entries"][0]["status"]="revoked"
        revoked=signed_entry(old,self.f["signers"]["owner"],"archive_revocation")
        self.assertCode("repair_authority_revoked",self.recover,
            known_statuses=[self.http.fixture.statuses(revision=3)[0]],archive_statuses=[revoked])
        self.assertEqual(self.transport.calls,[])

    def test_archive_and_exact_union_capacities_refuse_before_network(self):
        original=self.f["entries"]["owner_status"]
        self.assertCode("repair_status_history_capacity",self.recover,archive_statuses=[original]*33)
        archive=[dict(raw=original["raw"],ref=dict(original["ref"],key=hashlib.sha256(str(i).encode()).hexdigest()))
                 for i in range(32)]
        self.assertCode("repair_status_history_capacity",self.recover,
                        known_statuses=[original],archive_statuses=archive)
        self.assertEqual(self.transport.calls,[])

    def test_known_owner_minimum_and_same_revision_conflict_refuse_before_network(self):
        payload = copy.deepcopy(self.f["docs"]["owner_status"]["payload"])
        payload["revision"] = 2
        payload["entries"][0]["minimum_document_revision"] = 2
        known = signed_entry(payload, self.f["signers"]["owner"], "known_newer_document")
        self.assertCode("repair_status_revision", self.recover, known_statuses=[known])
        first = self.http.fixture.statuses()[0]
        payload = json.loads(first["raw"])["payload"]
        payload["valid_until"] -= 1
        other = signed_entry(payload, self.f["signers"]["owner"], "same_revision_conflict")
        self.assertCode("repair_status_conflict", self.recover, known_statuses=[first,other])
        self.assertEqual(self.transport.calls, [])

    def test_known_target_revocation_refuses_before_resource_recovery(self):
        payload = copy.deepcopy(self.f["docs"]["target_status"]["payload"])
        payload["revision"] = 2
        payload["entries"][0]["status"] = "revoked"
        known = signed_entry(payload, self.f["signers"]["target"], "known_source_revocation")
        self.assertCode("repair_authority_revoked", self.recover, known_statuses=[known])
        self.assertEqual(self.transport.calls, [])

    def test_current_lower_revision_than_known_owner_or_target_is_rejected(self):
        before = self.authorities()
        self.assertCode("repair_status_rollback", self.recover,
                        known_statuses=self.http.fixture.statuses())
        self.assertEqual(len(self.transport.calls), 11)
        self.assertEqual(self.authorities(), before)

    def test_known_target_scope_is_checked_against_recovered_actual_resource(self):
        payload = copy.deepcopy(self.f["docs"]["target_status"]["payload"])
        payload["revision"] = 2
        payload["entries"][0]["scope_id"] = "ac" * 32
        known = signed_entry(payload, self.f["signers"]["target"], "different_resource")
        self.assertCode("repair_status_disclosure", self.recover, known_statuses=[known])
        self.assertEqual(len(self.transport.calls), 11)

    def test_retained_originals_cannot_equivocate_with_historical_source_status(self):
        payload = copy.deepcopy(self.f["docs"]["owner_status"]["payload"])
        payload["valid_until"] -= 1
        known = signed_entry(payload, self.f["signers"]["owner"], "historical_equivocation")
        self.assertCode("repair_status_conflict", self.recover, known_statuses=[known])
        self.assertEqual(len(self.transport.calls), 11)

    def test_malformed_current_entries_are_protocol_errors_not_python_type_errors(self):
        result = self.recover()
        for entries in (None, True, 7, "entries", {}, [], [None], [{}],
                        [self.f["docs"]["owner_status"]["payload"]["entries"][0]] * 17):
            payload = copy.deepcopy(self.f["docs"]["owner_status"]["payload"])
            payload["entries"] = entries
            malformed = signed_entry(payload, self.f["signers"]["owner"], "malformed_status")
            with self.subTest(entries=entries):
                self.assertCode("repair_invalid_status", self.current, result, malformed)

    def test_current_whole_original_revocation_cannot_hide_in_another_role(self):
        result = self.recover()
        payload = copy.deepcopy(self.f["docs"]["owner_status"]["payload"])
        payload["revision"] = 2
        payload["entries"][-1]["status"] = "revoked"
        revoked = signed_entry(payload, self.f["signers"]["owner"], "whole_body_revocation")
        self.assertCode("repair_authority_revoked", self.current, result, revoked)

    def test_deadline_expiring_during_final_checks_does_not_publish_a_result(self):
        now = [2_000_000_006]
        client = self.make_client(clock=lambda:now[0])
        check = client._current
        def advance_after_check(*args, **kwargs):
            result = check(*args, **kwargs)
            now[0] += 60
            return result
        client._current = advance_after_check
        self.assertCode("repair_access_expired", client.recover, self.http.base, **self.options())

    def test_injected_transport_mutable_body_and_invalid_timeout_are_rejected(self):
        for timeout in (True, 0, -1, 61, float("inf"), float("nan")):
            with self.subTest(timeout=timeout):
                self.assertCode("repair_invalid_deadline", self.recover, timeout=timeout)
        self.assertEqual(self.transport.calls, [])
        self.transport.transform = lambda raw,reply,child: bytearray(reply)
        self.assertCode("repair_invalid_response", self.recover)
        self.assertEqual(len(self.transport.calls), 1)


if __name__ == "__main__":
    unittest.main()
