"""Bounded, synthetic-only CI reports; never package test keys or databases.

Reports begin as incomplete before dependencies/tests run. Only a complete,
validated result can become passed. SIGKILL/runner loss can prevent final upload;
the workflow uploads initial settings separately and retains CI event logs.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.metadata
import io
import json
import math
import os
from pathlib import Path
import platform
import re
import selectors
import signal
import sqlite3
import subprocess
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
FILES = ("settings.json", "status.json", "progress.jsonl", "errors.jsonl", "results.json")
MAX_REPORT_BYTES = 900_000  # All explicitly uploadable files together, <1 MiB.
MODULES = tuple("tests.test_open_" + name for name in (
    "control", "index", "state", "transport", "routing", "join_progress", "node", "agent", "typescript", "typescript_state", "network_ci"))
EXPECTED = {
    "schema_version": "memory-vault-open-routing-acceptance/v2", "logical_nodes": 100,
    "profile": "routing_core_table_initial_no_restart_cache", "checkpoints": False,
    "initial_closest_entries": 16, "full_runtime_benchmark": False, "real_ed25519": True,
    "transport": "in_process_signed_control", "actual_http": False, "ai_instances": 0,
    "physical_failure_domains_verified": False, "maintenance_cycles": 20,
    "maintenance_requests_per_node_cycle": 16, "maintenance_response_bytes_per_node_cycle": 1048576,
    "maintenance_seconds_per_node_cycle": 5, "maintenance_pending_probes": 2,
    "pending_capacity": 32, "join_notify_count": 2,
    "maintenance_announcements": 2, "pending_overflow": "signed_retryable_rejection",
    "maintenance_target_schedule": "own_coordinate_every_fourth_cycle_otherwise_random",
}
ROUTING_STATS = {"general_active", "general_replacements", "directory_active", "directory_replacements", "directory_introductions"}
PHASE_FIELDS = {"queries", "successes", "success_rate", "threshold", "passed", "failures",
    "unknown_initial_target_queries", "queries_with_new_causal_hops", "actual_requests", "actual_response_bytes",
    "requests_p50", "requests_p95", "requests_max", "latency_ms_p50", "latency_ms_p95", "candidate_peak", "concurrency_peak"}


class InvalidReport(ValueError):
    pass


def require(condition):
    if not condition:
        raise InvalidReport("invalid_or_incomplete_report")


def number(value):
    return type(value) in (int, float) and math.isfinite(value) and 0 <= value <= 10**15


def validate_diagnostics(value, phases):
    """Only finite synthetic indices and routing outcomes, never descriptors."""
    def index(value):
        return type(value) is int and 0 <= value < 100

    def indices(value, limit):
        require(type(value) is list and len(value) <= limit and all(index(i) for i in value))
        require(len(set(value)) == len(value))

    def graph(value):
        require(type(value) is list and len(value) == 100)
        require(all(type(row) is dict and set(row) == {"node", "active", "spare", "pending"} for row in value))
        require(all(index(row["node"]) for row in value))
        require({row["node"] for row in value} == set(range(100)))
        for row in value:
            for kind in ("active", "spare", "pending"):
                indices(row[kind], 32 if kind == "pending" else 99)
                require(row["node"] not in row[kind])
            require(not set(row["active"]) & set(row["spare"]))

    require(type(value) is dict and set(value) == {"schema_version", "maintenance_graph", "phases"})
    require(value["schema_version"] == "memory-vault-open-routing-diagnostics/v1")
    require(type(value["phases"]) is dict and set(value["phases"]) == set(phases))
    graph(value["maintenance_graph"])
    for name, diagnostic in value["phases"].items():
        require(type(diagnostic) is dict and set(diagnostic) == {"graph", "failure_samples"})
        graph(diagnostic["graph"])
        samples = diagnostic["failure_samples"]
        require(type(samples) is list and len(samples) <= 8)
        failures = {f["query"]: f for f in phases[name]["failures"]}
        sampled_targets = set()
        for sample in samples:
            require(type(sample) is dict and set(sample) == {"query", "initial", "returned", "replies", "paths", "target_holders"})
            require(type(sample["query"]) is int and sample["query"] in failures)
            failure = failures[sample["query"]]
            require(failure["target"] not in sampled_targets)
            sampled_targets.add(failure["target"])
            indices(sample["initial"], 16); indices(sample["returned"], 8)
            require(failure["target"] not in sample["returned"])
            holders = sample["target_holders"]
            require(type(holders) is dict and set(holders) == {"active", "spare", "pending"})
            for peers in holders.values():
                indices(peers, 99); require(failure["target"] not in peers)
            replies = sample["replies"]
            require(type(replies) is list and len(replies) <= failure["requests"])
            for reply in replies:
                require(type(reply) is dict and set(reply) == {"peer", "returned"} and index(reply["peer"]))
                indices(reply["returned"], 8)
            require(len({r["peer"] for r in replies}) == len(replies))
            paths = sample["paths"]
            require(type(paths) is list and len(paths) <= failure["requests"])
            for path in paths:
                require(type(path) is dict and set(path) == {"peer", "parent", "lane", "source_bits", "depth", "state"})
                require(index(path["peer"]) and (path["parent"] is None or index(path["parent"])))
                require(type(path["lane"]) is int and path["lane"] in (0, 1))
                require(type(path["source_bits"]) is int and 1 <= path["source_bits"] <= 3)
                require(type(path["depth"]) is int and 0 <= path["depth"] <= 128)
                require(path["state"] in {"verified", "failed"})
            require(len({p["peer"] for p in paths}) == len(paths))


def validate_scale(value, seed):
    """Exact public result inventory prevents accidental logs/keys/path fields."""
    extra = {"seed", "maintenance_and_join_requests", "maintenance_and_join_response_bytes", "maintenance_and_join_seconds",
             "phases", "max_per_node_routing_state", "sum_per_node_routing_state", "total_seconds", "passed", "routing_diagnostics"}
    require(type(value) is dict and set(value) == set(EXPECTED) | extra)
    for key, expected in EXPECTED.items():
        require(type(value[key]) is type(expected) and value[key] == expected)
    require(type(value["seed"]) is int and value["seed"] == seed)
    require(type(value["passed"]) is bool and set(value["phases"]) == {"healthy", "bootstrap_exit"})
    for key in ("maintenance_and_join_requests", "maintenance_and_join_response_bytes", "maintenance_and_join_seconds", "total_seconds"):
        require(number(value[key]))
    for key in ("max_per_node_routing_state", "sum_per_node_routing_state"):
        require(type(value[key]) is dict and set(value[key]) == ROUTING_STATS)
        require(all(type(n) is int and n >= 0 for n in value[key].values()))
    for name, phase in value["phases"].items():
        require(type(phase) is dict and set(phase) == PHASE_FIELDS)
        require(all(number(n) for key, n in phase.items() if key not in {"failures", "passed"}))
        require(type(phase["passed"]) is bool and type(phase["failures"]) is list)
        require(type(phase["queries"]) is int and phase["queries"] == 1000)
        require(type(phase["successes"]) is int and 0 <= phase["successes"] <= 1000)
        require(len(phase["failures"]) == 1000 - phase["successes"])
        threshold = .99 if name == "healthy" else .97
        require(phase["threshold"] == threshold and phase["success_rate"] == phase["successes"] / 1000)
        require(phase["passed"] == (phase["success_rate"] >= threshold))
        require(phase["candidate_peak"] <= 32 and phase["concurrency_peak"] <= 3 and phase["requests_max"] <= 64)
        seen = set()
        for failure in phase["failures"]:
            require(type(failure) is dict and set(failure) == {"query", "source", "target", "state", "requests"})
            require(type(failure["query"]) is int and 0 <= failure["query"] < 1000 and failure["query"] not in seen)
            seen.add(failure["query"])
            require(all(type(failure[k]) is int and 2 <= failure[k] < 100 for k in ("source", "target")))
            require(failure["state"] in {"closest_known", "budget_exhausted", "unreachable"})
            require(type(failure["requests"]) is int and 0 <= failure["requests"] <= 64)
    require(value["passed"] == all(phase["passed"] for phase in value["phases"].values()))
    validate_diagnostics(value["routing_diagnostics"], value["phases"])
    return value


def clean_progress(value, seed):
    fields = {"seed", "elapsed_seconds", "phase", "nodes_completed", "cycles_completed", "queries_completed", "failures", "requests"}
    require(type(value) is dict and set(value) <= fields and {"seed", "elapsed_seconds", "phase"} <= set(value))
    require(type(value["seed"]) is int and value["seed"] == seed)
    require(value["phase"] in {"join", "join_complete", "maintenance", "healthy", "bootstrap_exit"})
    require(all(number(v) for k, v in value.items() if k != "phase"))
    return value


class Reports:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)

    def write(self, name, value, append=False):
        require(name in FILES)
        encoded = (json.dumps(value, sort_keys=True, allow_nan=False) + "\n").encode()
        path = self.directory / name
        previous = path.read_bytes() if append and path.exists() else b""
        total = sum((self.directory / n).stat().st_size for n in FILES if n != name and (self.directory / n).exists())
        require(total + len(previous) + len(encoded) <= MAX_REPORT_BYTES - (0 if name == "status.json" else 4096))
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_bytes(previous + encoded)
        temporary.replace(path)

    def event(self, value, error=False):
        self.write("errors.jsonl" if error else "progress.jsonl", value, append=True)
        # Only structured allowlisted values reach GitHub's persisted CI log.
        print(json.dumps(value, sort_keys=True), file=sys.__stdout__, flush=True)

    def status(self, state, passed=False, complete=False):
        self.write("status.json", {"schema_version":"memory-vault-open-ci-status/v1", "state":state,
                                  "passed":passed, "complete":complete})


def initialize(reports, mode, seed):
    sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    require(re.fullmatch(r"[0-9a-f]{40}", sha) is not None)
    sources = ["scripts/run_open_network_ci.py", "tests/open_routing_acceptance.py", "tests/test_open_routing.py",
               "memory_vault_open_routing.py", "memory_vault_open_control.py", "requirements-network-lock.txt",
               "clients/typescript/network/package-lock.json", ".github/workflows/open-network.yml"]
    settings = {"schema_version":"memory-vault-open-ci-settings/v1", "commit_sha":sha, "mode":mode,
        "seed":seed if mode == "scale" else None, "source_sha256":{name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in sources},
        "bootstrap_python":sys.version.split()[0], "expected_node":"22.19.0" if mode=="light" else None,
        "expected_jose":"6.2.10" if mode=="light" else None,
        "requested_runner":"ubuntu-24.04-standard", "report_byte_limit":MAX_REPORT_BYTES, "synthetic_only":True,
        "scale_settings":{**EXPECTED,"queries_per_phase":1000} if mode == "scale" else None,
        "test_modules":list(MODULES) if mode == "light" else []}
    for name in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
        value=os.environ.get(name,"")
        if re.fullmatch(r"[0-9]{1,24}",value):settings[name.lower()]=value
    reports.write("settings.json",settings)
    reports.write("results.json",{"state":"not_run","passed":False,"result":None})
    reports.write("progress.jsonl",{"event":"initialized","commit_sha":sha})
    reports.write("errors.jsonl",{"event":"error_log_initialized"})
    reports.status("not_run")


def test_name(test):
    base=getattr(test,"test_case",test)
    value=base.id()
    return value if re.fullmatch(r"[A-Za-z0-9_.]{1,240}",value) else "unidentified_test"


def record_runtime(reports,mode,seed):
    settings=json.loads((reports.directory/"settings.json").read_text())
    require(settings["mode"]==mode and settings["seed"]==(seed if mode=="scale" else None))
    actual_sha=subprocess.check_output(["git","rev-parse","HEAD"],cwd=ROOT,text=True).strip()
    require(settings["commit_sha"]==actual_sha)
    for name,digest in settings["source_sha256"].items():
        require(hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==digest)
    runtime={"python":sys.version.split()[0],"sqlite":sqlite3.sqlite_version,"os":platform.system(),
             "architecture":platform.machine(),"logical_cpus":os.cpu_count(),
             "cryptography":importlib.metadata.version("cryptography"),"joserfc":importlib.metadata.version("joserfc")}
    if mode=="light":
        runtime["node"]=subprocess.check_output(["node","--version"],text=True).strip()
        runtime["jose"]=json.loads((ROOT/"clients/typescript/network/node_modules/jose/package.json").read_text())["version"]
        require(runtime["node"]=="v22.19.0" and runtime["jose"]=="6.2.10")
    reports.write("settings.json",{**settings,"actual_runtime":runtime})


class DiscardOutput(io.TextIOBase):
    def write(self,value):return len(value)


class SyntheticResult(unittest.TestResult):
    def __init__(self,reports):
        super().__init__();self.reports=reports;self.entries=[]

    def _exc_info_to_string(self,err,test):
        return err[0].__name__  # Never serialize assertion operands, keys or paths.

    def record(self,test,state,error=None):
        item={"test":test_name(test),"state":state}
        if error is not None:
            item["exception_type"]=error[0].__name__
            frames=[];trace=error[2]
            while trace is not None and len(frames)<16:
                source=Path(trace.tb_frame.f_code.co_filename)
                if source.is_absolute() and source.is_relative_to(ROOT):
                    frames.append({"source":source.relative_to(ROOT).as_posix(),"line":trace.tb_lineno})
                trace=trace.tb_next
            item["source_frames"]=frames
        self.entries.append(item);self.reports.event(item,error=state not in {"passed","subtest_passed"})

    def addSuccess(self,test):super().addSuccess(test);self.record(test,"passed")
    def addFailure(self,test,err):super().addFailure(test,err);self.record(test,"failed",err)
    def addError(self,test,err):super().addError(test,err);self.record(test,"error",err)
    def addSkip(self,test,reason):super().addSkip(test,"reason omitted");self.record(test,"skipped")
    def addExpectedFailure(self,test,err):super().addExpectedFailure(test,err);self.record(test,"expected_failure",err)
    def addUnexpectedSuccess(self,test):super().addUnexpectedSuccess(test);self.record(test,"unexpected_success")
    def addSubTest(self,test,subtest,err):
        super().addSubTest(test,subtest,err);self.record(test,"subtest_passed" if err is None else "subtest_failed",err)


def run_light(reports):
    if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
    result=SyntheticResult(reports)
    # Test exceptions remain classified, but raw provider errors/fixture paths
    # are not copied into either uploaded reports or public console output.
    with contextlib.redirect_stdout(DiscardOutput()),contextlib.redirect_stderr(DiscardOutput()):
        suite=unittest.defaultTestLoader.loadTestsFromNames(MODULES)
        suite.run(result)
    passed=result.testsRun>0 and result.wasSuccessful() and not result.skipped and not result.expectedFailures
    reports.write("results.json",{"schema_version":"memory-vault-open-ci-tests/v1","tests_run":result.testsRun,
        "passed":passed,"skipped":len(result.skipped),"failures":len(result.failures),"errors":len(result.errors),
        "expected_failures":len(result.expectedFailures),"unexpected_successes":len(result.unexpectedSuccesses),"tests":result.entries})
    return passed


def run_scale(reports,seed):
    command=[sys.executable,"-m","tests.open_routing_acceptance","--seed",str(seed),"--queries","1000","--nodes","100"]
    process=subprocess.Popen(command,cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
    selector=selectors.DefaultSelector(); buffers={"stdout":bytearray(),"stderr":bytearray()}; unexpected=False
    for name,stream in (("stdout",process.stdout),("stderr",process.stderr)):
        os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,name)
    try:
        while selector.get_map():
            for key,_ in selector.select(timeout=1):
                chunk=os.read(key.fileobj.fileno(),65536)
                if not chunk:selector.unregister(key.fileobj);continue
                buffer=buffers[key.data];buffer.extend(chunk);require(len(buffer)<=750_000)
                if key.data=="stderr":
                    while b"\n" in buffer:
                        line,_,tail=buffer.partition(b"\n");buffer[:]=tail
                        try:reports.event(clean_progress(json.loads(line),seed))
                        except (ValueError,TypeError,KeyError):
                            unexpected=True;reports.event({"event":"unstructured_stderr_omitted","bytes":len(line)},error=True)
        code=process.wait()
        require(not unexpected and not buffers["stderr"] and buffers["stdout"])
        value=validate_scale(json.loads(buffers["stdout"]),seed)
        require(code in (0,1) and (code==0)==value["passed"])
        reports.write("results.json",value)
        return value["passed"]
    finally:
        selector.close()
        if process.poll() is None:
            os.killpg(process.pid,signal.SIGTERM)
            try:process.wait(timeout=3)
            except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=3)
        process.stdout.close();process.stderr.close()


def finalize(reports):
    status=json.loads((reports.directory/"status.json").read_text())
    if status.get("complete") is not True:
        reports.status("incomplete");return False
    result=json.loads((reports.directory/"results.json").read_text())
    require(result.get("passed") is status.get("passed") and type(result.get("passed")) is bool)
    return status["passed"]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode",choices=("light","scale"),required=True)
    parser.add_argument("--phase",choices=("initialize","run","finalize"),required=True)
    parser.add_argument("--seed",type=int,choices=(17,29,43),default=17)
    parser.add_argument("--report-directory",type=Path,required=True)
    args=parser.parse_args();reports=Reports(args.report_directory)
    if args.phase=="initialize":initialize(reports,args.mode,args.seed);return 0
    if args.phase=="finalize":return 0 if finalize(reports) else 1
    def interrupted(signum,frame):raise KeyboardInterrupt
    for signum in (signal.SIGINT,signal.SIGTERM,signal.SIGALRM):signal.signal(signum,interrupted)
    signal.alarm(26*60 if args.mode=="scale" else 12*60)
    reports.status("running")
    try:
        record_runtime(reports,args.mode,args.seed)
        passed=run_scale(reports,args.seed) if args.mode=="scale" else run_light(reports)
        reports.status("passed" if passed else "failed",passed=passed,complete=True)
        return 0 if passed else 1
    except KeyboardInterrupt:
        reports.status("interrupted");reports.event({"event":"interrupted_or_timed_out"},error=True);return 130
    except Exception as exc:
        reports.status("incomplete");reports.event({"event":"ci_execution_error","exception_type":type(exc).__name__},error=True);return 1
    finally:signal.alarm(0)


if __name__=="__main__":
    try:code=main()
    except Exception as exc:
        print(json.dumps({"event":"ci_setup_or_finalization_error","exception_type":type(exc).__name__}),flush=True)
        code=1
    raise SystemExit(code)
