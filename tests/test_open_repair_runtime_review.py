"""Focused regressions for reproduced public repair runtime defects."""
import copy
import hashlib
import http.client
import itertools
import json
import unittest
from unittest.mock import patch

from memory_vault_network_crypto import b64url
import memory_vault_open_repair_admin as admin
from memory_vault_open_transport import REPAIR_PATH
from tests.open_repair_ack_fixtures import signed_entry
from tests import test_open_repair_admin as admin_fixture
from tests import test_open_repair_http as http_fixture


class RepairRuntimeFramingTests(unittest.TestCase):
    def test_empty_first_encoding_header_cannot_hide_a_duplicate(self):
        host = http_fixture.RepairHTTPTests()
        self.addCleanup(host.doCleanups)
        host.setUp()
        raw = host.fixture.make_probe().original.raw
        for field, trailing in (("Transfer-Encoding", "chunked"), ("Content-Encoding", "gzip")):
            for values in (("",), ("", trailing)):
                with self.subTest(field=field, values=values):
                    connection = http.client.HTTPConnection(*host.server.server_address, timeout=3)
                    try:
                        connection.putrequest("POST", REPAIR_PATH)
                        connection.putheader("Content-Length", str(len(raw)))
                        connection.putheader("Content-Type", "application/json")
                        for value in values:
                            connection.putheader(field, value)
                        connection.endheaders(raw)
                        response = connection.getresponse()
                        self.assertEqual(response.status, 400)
                        response.read()
                    finally:
                        connection.close()
        self.assertEqual(host.source.db.execute("SELECT count(*) FROM open_repair_bootstrap_work").fetchone()[0], 0)
        self.assertEqual(host.source.db.execute("SELECT count(*) FROM open_repair_bootstrap_challenges").fetchone()[0], 0)


class RepairRuntimeHistoryTests(unittest.TestCase):
    def fixture(self, *, two_jobs=False):
        if two_jobs:
            # Two real recoveries need two explicitly reserved finite jobs.
            # Enlarge the synthetic authorities BEFORE their originals are
            # signed; never reset persisted usage or bypass an admission gate.
            start = http_fixture.service_fixture.RepairServiceTests.start
            participant = http_fixture.RepairHTTPTests.participant_for
            def larger_start(case, **limits):
                f=case.source.fixture
                f["docs"]["allocate"]["payload"]["intent"]["budget"]["max_meta_bytes"]=1024*1024
                for role in ("root","read"):
                    f["docs"][role]["payload"]["budget"]["max_meta_bytes"]=1024*1024
                return start(case,**(dict(max_signature_checks=1024,max_proof_bytes=262144)|limits))
            def larger_participant(host, directory, policy):
                policy=dict(policy,limit_policy=dict(policy["limit_policy"],max_signature_checks=1024,max_proof_bytes=262144))
                return participant(host,directory,policy)
            self.enterContext(patch.object(http_fixture.service_fixture.RepairServiceTests,"start",larger_start))
            self.enterContext(patch.object(http_fixture.RepairHTTPTests,"participant_for",larger_participant))
            self.enterContext(patch.object(admin,"DEFAULT_LIMITS",dict(admin.DEFAULT_LIMITS,max_signature_checks=1024)))
        case=admin_fixture.RepairAdminTests()
        self.addCleanup(case.doCleanups)
        case.setUp()
        return case

    @staticmethod
    def encoded(entry):
        return dict(raw_base64url=b64url(entry["raw"]),ref=entry["ref"])

    def test_two_actual_http_recoveries_reuse_compacted_floors_and_complete_archive(self):
        case=self.fixture(two_jobs=True)
        f=case.host.source.fixture
        for revision in range(1,9):
            for role,signer in (("owner_status","owner"),("target_status","target")):
                payload=copy.deepcopy(f["docs"][role]["payload"])
                payload["revision"]=revision
                entry=(f["entries"][role] if revision==1 else
                       signed_entry(payload,f["signers"][signer],f"retained_{revision}_{signer}"))
                case.request["known_statuses"].append(self.encoded(entry))
        self.assertTrue(case.host.fixture.observe(case.host.fixture.statuses(revision=9)).allowed)
        code,output,error=case.call()
        self.assertEqual((code,error),(0,""))
        first=json.loads(case.output.read_bytes())
        self.assertEqual(len(first["archive_statuses"]),18)
        self.assertEqual(len(first["known_statuses"]),2)
        self.assertEqual(json.loads(output)["requests"],17)
        usage_before=case.host.fixture.usage()
        case.request["known_statuses"]=first["known_statuses"]
        case.request["archive_statuses"]=first["archive_statuses"]
        case.request_path=case.directory/"request-second.json"
        case.output=case.directory/"evidence-second.json"
        code,output,error=case.call()
        self.assertEqual((code,error),(0,""))
        second=json.loads(case.output.read_bytes())
        self.assertEqual(len(second["archive_statuses"]),18)
        self.assertEqual(len(second["known_statuses"]),2)
        self.assertEqual(second["metrics"]["signature_checks"],40)
        self.assertEqual(json.loads(output)["requests"],17)
        self.assertGreater(case.host.fixture.usage()[1],usage_before[1])
        self.assertFalse(case.vault.exists())

    def test_compaction_preserves_old_non_read_revocation_despite_new_active_mask(self):
        case=self.fixture()
        f=case.host.source.fixture
        payload=copy.deepcopy(f["docs"]["owner_status"]["payload"])
        payload["revision"]=2
        scope=next(item for item in payload["entries"] if item["scope_kind"]=="ack_slot")
        scope.update(status="revoked",operation_mask=8)
        payload["entries"]=[scope]
        old=signed_entry(payload,f["signers"]["owner"],"retained_admission_revocation")
        case.request["known_statuses"]=[self.encoded(old)]
        self.assertTrue(case.host.fixture.observe(case.host.fixture.statuses(revision=3)).allowed)
        code,_,error=case.call()
        self.assertEqual((code,error),(0,""))
        output=json.loads(case.output.read_bytes())
        self.assertIn(self.encoded(old),output["known_statuses"])
        self.assertIn(self.encoded(old),output["archive_statuses"])
        self.assertEqual(len(output["known_statuses"]),3)

    def test_irreducible_history_capacity_never_writes_an_unusable_evidence_file(self):
        case=self.fixture()
        f=case.host.source.fixture
        # Fifteen incomparable revoked bit-pairs on the same ACK slot plus
        # one source-resource revocation remain relevant beyond this READ.
        # Current active records cannot erase those older denied operations.
        for revision,pair in enumerate(itertools.combinations((1,4,8,16,32,64),2),start=2):
            payload=copy.deepcopy(f["docs"]["owner_status"]["payload"])
            scope=next(item for item in payload["entries"] if item["scope_kind"]=="ack_slot")
            scope.update(status="revoked",operation_mask=sum(pair))
            payload.update(revision=revision,entries=[scope])
            case.request["known_statuses"].append(self.encoded(
                signed_entry(payload,f["signers"]["owner"],f"retained_revoked_pair_{revision}")))
        payload=copy.deepcopy(f["docs"]["target_status"]["payload"])
        payload["revision"]=2
        payload["entries"][0].update(status="revoked",operation_mask=64)
        case.request["known_statuses"].append(self.encoded(
            signed_entry(payload,f["signers"]["target"],"retained_resource_write_revocation")))
        self.assertEqual(len(case.request["known_statuses"]),16)
        self.assertTrue(case.host.fixture.observe(case.host.fixture.statuses(revision=100)).allowed)
        code,output,error=case.call()
        self.assertEqual((code,output),(1,""))
        self.assertEqual(json.loads(error)["error"],"repair_status_history_capacity")
        self.assertFalse(case.output.exists())
        self.assertFalse(case.vault.exists())


if __name__ == "__main__":
    unittest.main()
