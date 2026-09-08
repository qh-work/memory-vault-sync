"""Fast reports and four-node observer checks; never start the scale experiment."""
import copy
import contextlib
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
    graph=[{"node":i,"active":[],"spare":[],"pending":[]} for i in range(100)]
    diagnostics={"schema_version":"memory-vault-open-routing-diagnostics/v1", "maintenance_graph":graph,
        "phases":{name:{"graph":copy.deepcopy(graph),"failure_samples":[]} for name in ("healthy","bootstrap_exit")}}
    return {**ci.EXPECTED,"seed":17,"maintenance_and_join_requests":10,
        "maintenance_and_join_response_bytes":100,"maintenance_and_join_seconds":1.0,
        "phases":{"healthy":phase,"bootstrap_exit":{**copy.deepcopy(phase),"threshold":.97}},
        "max_per_node_routing_state":{k:1 for k in ci.ROUTING_STATS},
        "sum_per_node_routing_state":{k:100 for k in ci.ROUTING_STATS},"total_seconds":2.0,"passed":True,
        "routing_diagnostics":diagnostics}


class OpenNetworkCITests(unittest.TestCase):
    def test_maximal_failure_diagnostics_fit_child_and_report_caps(self):
        from tests import open_routing_acceptance as acceptance
        value=synthetic_report();graph=[]
        for i in range(100):
            peers=[j for j in range(100) if j!=i]
            graph.append({"node":i,"active":peers[:50],"spare":peers[50:],"pending":peers[:32]})
        value["routing_diagnostics"]["maintenance_graph"]=graph
        for name,phase in value["phases"].items():
            phase.update(successes=0,success_rate=0.,passed=False,failures=[
                {"query":i,"source":99,"target":2+i%97,"state":"closest_known","requests":64} for i in range(1000)])
            diagnostic=value["routing_diagnostics"]["phases"][name];diagnostic["graph"]=graph
            for query in range(8):
                holders=[i for i in range(100) if i!=query+2]
                diagnostic["failure_samples"].append({"query":query,"initial":list(range(16)),"returned":list(range(80,88)),
                    "replies":[{"peer":i,"returned":list(range(80,88))} for i in range(64)],
                    "paths":[{"peer":i,"parent":None if i==0 else i-1,"lane":0,"source_bits":3,"depth":i,"state":"verified"} for i in range(64)],
                    "target_holders":{"active":holders,"spare":[],"pending":holders}})
        value["passed"]=False;ci.validate_scale(value,17)
        async def fake_run(*args):return value  # Serializer-only test, no routing run.
        output=io.StringIO()
        with mock.patch.object(acceptance,"run",fake_run),mock.patch.object(sys,"argv",["acceptance"]),contextlib.redirect_stdout(output):
            with self.assertRaises(SystemExit) as stopped:acceptance.main()
        self.assertEqual(stopped.exception.code,1)
        self.assertEqual(json.loads(output.getvalue()),value)
        self.assertLessEqual(len(output.getvalue().encode()),750000)
        with tempfile.TemporaryDirectory() as temporary:
            reports=ci.Reports(temporary);reports.write("results.json",value);reports.status("failed",False,True)
            self.assertLess(sum(p.stat().st_size for p in Path(temporary).iterdir()),ci.MAX_REPORT_BYTES)

    def test_diagnostics_reject_payloads_indices_and_unbound_failure_samples(self):
        sample={"query":0,"initial":[0,1],"returned":[1],"replies":[{"peer":1,"returned":[0]}],
                "paths":[{"peer":1,"parent":None,"lane":0,"source_bits":1,"depth":0,"state":"verified"}],
                "target_holders":{"active":[],"spare":[],"pending":[0]}}
        value=synthetic_report(); phase=value["phases"]["healthy"]
        phase.update(successes=999,success_rate=.999,failures=[{"query":0,"source":2,"target":3,"state":"closest_known","requests":1}])
        value["routing_diagnostics"]["phases"]["healthy"]["failure_samples"]=[sample]
        ci.validate_scale(value,17)
        for field, replacement in (("query",1),("initial",[True]),("returned",[3]),("replies",[{"peer":1,"returned":[],"secret":"synthetic"}]),
                                   ("paths",[{**sample["paths"][0],"parent":"ed25519_synthetic"}])):
            bad=copy.deepcopy(value);bad["routing_diagnostics"]["phases"]["healthy"]["failure_samples"][0][field]=replacement
            with self.subTest(field=field),self.assertRaises(ci.InvalidReport):ci.validate_scale(bad,17)
        bad=copy.deepcopy(value);bad["routing_diagnostics"]["maintenance_graph"][0]["pending"]=list(range(1,34))
        with self.assertRaises(ci.InvalidReport):ci.validate_scale(bad,17)

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


class DiagnosticObservationTests(unittest.IsolatedAsyncioTestCase):
    async def test_passive_diagnostics_preserve_signed_lookup_and_storage(self):
        from tests.open_routing_acceptance import failure_sample, routing_graph
        from tests.test_open_routing import SyntheticRouting
        from memory_vault_open_control import coordinate
        from memory_vault_open_routing import LookupBudget
        networks=[SyntheticRouting(4,seed=43),SyntheticRouting(4,seed=43)]
        for network in networks:
            await network.hello(1,network.nodes[2],LookupBudget())
            await network.hello(0,network.nodes[1],LookupBudget())
        calls=copy.deepcopy(networks[1].calls)
        before=routing_graph(networks[1]);self.assertEqual(before,routing_graph(networks[1]))
        self.assertEqual(calls,networks[1].calls)
        networks[1].find_observations=[]
        target=coordinate(networks[0].identities[3].key_id)
        plain=await networks[0].search(0,target)
        observed=await networks[1].search(0,target)
        self.assertEqual(plain,observed)
        self.assertEqual(routing_graph(networks[0]),routing_graph(networks[1]))
        self.assertEqual(networks[0].calls,networks[1].calls)
        self.assertEqual(networks[1].find_observations,[{"peer":1,"returned":[2]},{"peer":2,"returned":[]}])
        snapshot=routing_graph(networks[1]);calls=copy.deepcopy(networks[1].calls)
        sample=failure_sample(networks[1],{"query":0,"target":3},[1],observed)
        self.assertEqual(sample["target_holders"],{"active":[],"spare":[],"pending":[]})
        self.assertEqual(sample["paths"][1]["parent"],1)
        self.assertEqual(snapshot,routing_graph(networks[1]));self.assertEqual(calls,networks[1].calls)


if __name__=="__main__":unittest.main()
