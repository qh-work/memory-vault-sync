"""Fast report/command checks. These never start the actual routing experiment."""
import copy
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from scripts import run_open_network_ci as ci


def synthetic_report():
    phase={key:0 for key in ci.PHASE_FIELDS-{ "failures","passed" }}
    phase.update(queries=1000,successes=1000,success_rate=1.0,threshold=.99,passed=True,failures=[],
                 requests_p50=2,requests_p95=3,requests_max=4,candidate_peak=8,concurrency_peak=3)
    return {**ci.EXPECTED,"seed":17,"maintenance_and_join_requests":10,
        "maintenance_and_join_response_bytes":100,"maintenance_and_join_seconds":1.0,
        "phases":{"healthy":phase,"bootstrap_exit":{**copy.deepcopy(phase),"threshold":.97}},
        "max_per_node_routing_state":{k:1 for k in ci.ROUTING_STATS},
        "sum_per_node_routing_state":{k:100 for k in ci.ROUTING_STATS},"total_seconds":2.0,"passed":True}


class OpenNetworkCITests(unittest.TestCase):
    def test_complete_current_profile_and_complete_failure_remain_distinct(self):
        value=synthetic_report();self.assertIs(ci.validate_scale(value,17),value)
        failed=copy.deepcopy(value);phase=failed["phases"]["healthy"]
        phase.update(successes=980,success_rate=.98,passed=False,
            failures=[{"query":i,"source":2,"target":3,"state":"unreachable","requests":4} for i in range(20)])
        failed["passed"]=False
        self.assertFalse(ci.validate_scale(failed,17)["passed"])

    def test_empty_old_maintenance_extra_data_and_false_success_are_rejected(self):
        for change in ({"maintenance_requests_per_node_cycle":64},{"profile":"old-cancelled-run"},
                       {"private_key":"synthetic-prohibited"},{"seed":29},{"passed":1}):
            with self.subTest(change=list(change)),self.assertRaises(ci.InvalidReport):ci.validate_scale({**synthetic_report(),**change},17)
        for value in ({},None,[] ):
            with self.subTest(value=type(value).__name__),self.assertRaises(ci.InvalidReport):ci.validate_scale(value,17)
        bad=synthetic_report();bad["phases"]["healthy"]["queries"]=0
        with self.assertRaises(ci.InvalidReport):ci.validate_scale(bad,17)

    def test_progress_is_finite_typed_and_does_not_accept_paths_or_payloads(self):
        event={"seed":17,"elapsed_seconds":1.0,"phase":"maintenance","cycles_completed":1,"requests":16}
        self.assertEqual(ci.clean_progress(event,17),event)
        for changed in ({**event,"path":"/synthetic/private"},{**event,"payload":{"private_key":"synthetic"}},
                        {**event,"elapsed_seconds":float("nan")},{**event,"phase":"/synthetic/path"}):
            with self.assertRaises(ci.InvalidReport):ci.clean_progress(changed,17)

    def test_initial_and_interrupted_reports_never_finalize_as_passed(self):
        with tempfile.TemporaryDirectory() as temporary:
            reports=ci.Reports(temporary);ci.initialize(reports,"scale",17)
            self.assertEqual(set(p.name for p in Path(temporary).iterdir()),set(ci.FILES))
            self.assertFalse(ci.finalize(reports))
            reports.status("interrupted");self.assertFalse(ci.finalize(reports))
            value=synthetic_report();reports.write("results.json",value);reports.status("passed",True,True)
            self.assertTrue(ci.finalize(reports))
            self.assertLess(sum(p.stat().st_size for p in Path(temporary).iterdir()),1024*1024)
            with self.assertRaises(ci.InvalidReport):reports.write("results.json",{"oversized":"x"*ci.MAX_REPORT_BYTES})

    def test_light_failure_skip_and_empty_suite_cannot_hide_as_success(self):
        class Failure(unittest.TestCase):
            def test_synthetic(self):self.fail("synthetic secret /synthetic/private/file")
        class Skipped(unittest.TestCase):
            @unittest.skip("synthetic secret /synthetic/private/file")
            def test_synthetic(self):pass
        for suite in (unittest.TestSuite([Failure("test_synthetic")]),unittest.TestSuite([Skipped("test_synthetic")]),unittest.TestSuite()):
            with tempfile.TemporaryDirectory() as temporary, mock.patch.object(unittest.defaultTestLoader,"loadTestsFromNames",return_value=suite), mock.patch("sys.__stdout__",io.StringIO()):
                reports=ci.Reports(temporary)
                self.assertFalse(ci.run_light(reports))
                combined="".join(p.read_text() for p in Path(temporary).iterdir())
                self.assertNotIn("synthetic secret",combined);self.assertNotIn("/synthetic/private",combined)

    def test_scale_command_and_progress_capture_use_only_tiny_fake_child(self):
        original=subprocess.Popen;seen=[];value=synthetic_report()
        progress={"seed":17,"elapsed_seconds":1.0,"phase":"healthy","queries_completed":100,"failures":0,"requests":200}
        program="import json,sys;print("+repr(json.dumps(progress))+",file=sys.stderr);print("+repr(json.dumps(value))+")"
        def fake(command,**options):
            seen.append(command)
            return original([sys.executable,"-c",program],**options)
        with tempfile.TemporaryDirectory() as temporary,mock.patch.object(ci.subprocess,"Popen",side_effect=fake),mock.patch("sys.__stdout__",io.StringIO()):
            reports=ci.Reports(temporary);self.assertTrue(ci.run_scale(reports,17))
            self.assertEqual(json.loads((Path(temporary)/"results.json").read_text()),value)
        self.assertEqual(seen,[[sys.executable,"-m","tests.open_routing_acceptance","--seed","17","--queries","1000","--nodes","100"]])

    def test_empty_scale_stdout_fails_instead_of_reusing_old_result(self):
        original=subprocess.Popen
        with tempfile.TemporaryDirectory() as temporary,mock.patch.object(ci.subprocess,"Popen",side_effect=lambda command,**options:original([sys.executable,"-c","pass"],**options)):
            reports=ci.Reports(temporary)
            with self.assertRaises(ci.InvalidReport):ci.run_scale(reports,17)
            self.assertFalse((Path(temporary)/"results.json").exists())

    def test_failed_child_preserves_all_synthetic_failures_and_exit_one(self):
        original=subprocess.Popen
        program=("import json;v="+repr(synthetic_report())+";"
            "f=[dict(query=i,source=2,target=99,state='closest_known',requests=7) for i in range(702)];"
            "[p.update(successes=298,success_rate=.298,passed=False,failures=f) for p in v['phases'].values()];"
            "v['passed']=False;print(json.dumps(v));raise SystemExit(1)")
        with tempfile.TemporaryDirectory() as temporary,mock.patch.object(ci.subprocess,"Popen",side_effect=lambda command,**options:original([sys.executable,"-c",program],**options)):
            reports=ci.Reports(temporary);self.assertFalse(ci.run_scale(reports,17))
            saved=json.loads((Path(temporary)/"results.json").read_text())
            self.assertTrue(all(len(p["failures"])==702 for p in saved["phases"].values()))
            self.assertLess(sum(p.stat().st_size for p in Path(temporary).iterdir()),1024*1024)


if __name__=="__main__":unittest.main()
