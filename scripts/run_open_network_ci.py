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
    "control", "index", "state", "transport", "routing", "join_progress", "node", "agent", "agent_setup", "typescript", "typescript_state", "typescript_http", "network_ci",
    "contact", "contact_state", "contact_http", "contact_directory_maintenance", "contact_typescript", "contact_typescript_http",
    "delivery_http", "provider_typescript", "provider_typescript_http", "provider_status", "provider_status_typescript",
    "repair_wire", "repair_typescript", "repair_pack", "repair_pack_typescript",
    "repair_history", "repair_history_typescript", "repair_original", "repair_original_typescript", "repair_contact_inputs",
    "repair_resource", "repair_resource_typescript", "repair_resource_inputs",
    "repair_bootstrap", "repair_bootstrap_typescript", "repair_status", "repair_status_typescript",
    "repair_ack", "repair_ack_typescript", "repair_state", "capacity", "capacity_typescript",
    "repair_probe",
    "repair_probe_typescript",
    "repair_proof",
    "repair_proof_typescript",
    "repair_access",
    "repair_service",
    "repair_service_budget",
    "repair_http",
    "repair_client", "repair_client_typescript", "repair_admin", "repair_admin_typescript", "repair_runtime_review", "repair_bound",
    "repair_bound_typescript", "repair_empty", "repair_empty_typescript", "repair_empty_review", "repair_empty_access", "repair_empty_http", "repair_empty_client", "repair_empty_client_typescript",
    "repair_bind_http", "repair_offer_access", "repair_offer_http", "repair_offer_client", "repair_offer_http_typescript", "repair_occupied", "repair_occupied_typescript", "repair_occupied_access", "repair_occupied_client", "repair_put_http", "repair_put_client", "repair_put_recovery", "repair_roundtrip", "repair_receipt", "repair_occupied_client_typescript")) + (
    "tests.test_open_repair_stage", "tests.test_open_repair_index", "tests.test_open_repair_index_access",
    "tests.test_open_repair_index_journal", "tests.test_open_repair_index_state", "tests.test_open_repair_index_http",
    "tests.test_open_repair_index_client", "tests.test_open_repair_index_recovery", "tests.test_open_repair_index_admin",
    "tests.test_open_repair_index_prepare", "tests.test_open_repair_index_prepare_admin",
    "tests.test_open_repair_provision", "tests.test_open_repair_onboarding",
    "tests.test_open_repair_bind_recovery", "tests.test_open_repair_remote_setup", "tests.test_open_repair_remote_provision",
    "tests.test_open_repair_status_observer", "tests.test_open_repair_mailbox_resources", "tests.test_open_repair_copy_resources", "tests.test_open_repair_copy_prepare", "tests.test_open_repair_copy_state", "tests.test_open_repair_copy_service", "tests.test_open_repair_copy_upload", "tests.test_open_repair_copy_empty", "tests.test_open_repair_copy_occupied", "tests.test_open_repair_mailbox_activation", "tests.test_open_repair_mailbox_range", "tests.test_open_repair_mailbox_root", "tests.test_open_repair_mailbox_status", "tests.test_open_repair_mailbox_source", "tests.test_open_repair_mailbox_snapshot", "tests.test_open_repair_mailbox_copy", "tests.test_open_repair_mailbox_copy_authority", "tests.test_open_repair_mailbox_copy_upload", "tests.test_open_repair_mailbox_reservation", "tests.test_open_repair_mailbox_consent", "tests.test_open_mailbox_replica_receive", "tests.test_open_mailbox_receipt_jobs", "tests.test_open_ack_replica_send", "tests.test_open_mailbox_copy_jobs", "tests.test_open_repair_mailbox_copy_admin", "tests.test_open_repair_mailbox_feed_copy", "tests.test_open_repair_mailbox_message_copy",
    "tests.test_open_provider_merge",
    "tests.test_continuation_trial", "tests.test_network_typescript_agent_network", "tests.test_network_packaging")
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


def selected_modules(partition_index=0, partition_count=1):
    require(type(partition_count) is int and 1 <= partition_count <= 8
        and type(partition_index) is int and 0 <= partition_index < partition_count)
    selected = MODULES[partition_index::partition_count]
    require(bool(selected))
    return selected


def initialize(reports, mode, seed, partition_index=0, partition_count=1):
    modules = selected_modules(partition_index, partition_count)
    require(mode == 'light' or (partition_index, partition_count) == (0, 1))
    sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    require(re.fullmatch(r"[0-9a-f]{40}", sha) is not None)
    sources = ["scripts/run_open_network_ci.py", "tests/open_routing_acceptance.py", "tests/test_open_routing.py",
               "memory_vault_open_routing.py", "memory_vault_open_control.py", "requirements-network-lock.txt",
               "clients/typescript/network/package-lock.json", ".github/workflows/open-network.yml"]
    if mode == "light":
        sources += ["clients/typescript/network/" + name for name in (
            "open-transport.ts", "open-participant.ts", "open-node.ts", "open-client.ts",
            "open-control.ts", "open-routing.ts", "open-state.ts", "client-config.ts", "transport-state.ts",
            "open-contact.ts", "open-contact-state.ts", "open-contact-client.ts",
            "open-provider.ts", "open-provider-client.ts", "open-blob.ts", "open-repair-wire.ts", "open-repair-history.ts", "open-repair-original.ts", "open-repair-resource.ts",
            "open-repair-bootstrap.ts", "open-repair-status.ts", "open-repair-mailbox-range.ts", "open-repair-ack.ts", "open-capacity.ts",
            "open-repair-probe.ts", "open-repair-proof.ts", "open-repair-client.ts", "open-repair-admin.ts",
            "open-repair-bound.ts", "open-repair-empty.ts", "open-repair-occupied.ts",
            "open-delivery.ts", "open-delivery-control.ts", "open-delivery-client.ts",
            "agent.ts", "peer.ts", "io.ts", "crypto.ts", "nodes.ts")]
        sources += ["requirements-network-server-lock.txt", "tests/test_open_typescript.py", "tests/test_open_typescript_http.py", "tests/test_open_typescript_state.py",
                    "memory_vault_open_contact.py", "memory_vault_open_contact_state.py", "memory_vault_open_contact_client.py", "memory_vault_open_contact_directory.py",
                    "memory_vault_open_client.py", "memory_vault_open_node.py", "memory_vault_open_transport.py", "memory_vault_open_setup.py",
                    "tests/test_open_contact.py", "tests/test_open_contact_state.py", "tests/test_open_contact_http.py",
                    "tests/test_open_contact_typescript.py", "tests/test_open_contact_typescript_http.py",
                    "tests/test_network_typescript_agent_network.py", "tests/test_network_packaging.py"]
        sources += ["memory_vault_open_provider.py", "memory_vault_open_provider_client.py", "memory_vault_open_provider_state.py",
                    "memory_vault_open_repair_wire.py", "memory_vault_open_repair_history.py",
                    "memory_vault_open_repair_original.py",
                    "memory_vault_open_repair_resource.py", "tests/open_repair_resource_fixtures.py",
                    "memory_vault_open_repair_bootstrap.py", "memory_vault_open_repair_status.py",
                    "memory_vault_open_repair_ack.py", "tests/open_repair_ack_fixtures.py",
                    "memory_vault_open_repair_state.py", "memory_vault_open_repair_mailbox_resources.py", "memory_vault_open_repair_copy_resources.py", "memory_vault_open_repair_copy_prepare.py", "memory_vault_open_repair_copy_authority.py", "memory_vault_open_repair_copy_source.py", "memory_vault_open_repair_copy_state.py", "memory_vault_open_repair_copy_service.py", "memory_vault_open_repair_copy_upload.py", "memory_vault_open_repair_copy_client.py", "memory_vault_open_repair_mailbox_activation.py", "memory_vault_open_repair_mailbox_range.py", "memory_vault_open_repair_mailbox_root.py", "memory_vault_open_repair_mailbox_status.py", "memory_vault_open_repair_mailbox_source.py", "memory_vault_open_repair_mailbox_snapshot.py", "memory_vault_open_repair_mailbox_copy.py", "memory_vault_open_repair_mailbox_copy_authority.py", "memory_vault_open_repair_mailbox_copy_state.py", "memory_vault_open_repair_mailbox_copy_upload.py", "memory_vault_open_repair_mailbox_copy_prepare.py", "memory_vault_open_repair_mailbox_reservation.py", "memory_vault_open_repair_mailbox_consent.py", "memory_vault_open_mailbox_replica_receive.py", "memory_vault_open_mailbox_receipt_jobs.py", "memory_vault_open_ack_replica_send.py", "memory_vault_open_mailbox_copy_jobs.py", "memory_vault_open_repair_mailbox_copy_client.py", "memory_vault_open_repair_mailbox_copy_service.py", "memory_vault_open_repair_mailbox_copy_admin.py", "memory_vault_open_repair_mailbox_feed_copy.py", "memory_vault_open_repair_mailbox_feed_copy_state.py", "memory_vault_open_repair_mailbox_message_copy.py", "memory_vault_open_repair_mailbox_message_copy_state.py", "memory_vault_open_repair_mailbox_message_inbox.py", "memory_vault_open_capacity.py", "memory_vault_open_capacity_schema.json",
                    "memory_vault_open_repair_probe.py",
                    "memory_vault_open_repair_proof.py",
                    "memory_vault_open_repair_access.py",
                    "memory_vault_open_repair_service.py",
                    "memory_vault_open_repair_client.py", "memory_vault_open_repair_admin.py",
                    "memory_vault_open_repair_bound.py", "tests/open_repair_bound_fixtures.py", "tests/open_repair_index_fixtures.py",
                    "memory_vault_open_repair_empty.py",
                    "memory_vault_open_repair_empty_state.py",
                    "memory_vault_open_repair_empty_access.py",
                    "memory_vault_open_repair_empty_service.py",
                    "memory_vault_open_repair_bind.py",
                    "memory_vault_open_repair_bind_client.py",
                    "memory_vault_open_repair_offer_access.py",
                    "memory_vault_open_repair_offer_service.py",
                    "memory_vault_open_repair_offer_client.py",
                    "memory_vault_open_repair_occupied.py",
                    "memory_vault_open_repair_occupied_state.py",
                    "memory_vault_open_repair_occupied_access.py",
                    "memory_vault_open_repair_put.py",
                    "memory_vault_open_repair_put_client.py",
                    "memory_vault_open_repair_receipt.py",
                    "memory_vault_open_repair_stage.py",
                    "memory_vault_open_repair_index.py",
                    "memory_vault_open_repair_index_access.py",
                    "memory_vault_open_repair_index_journal.py",
                    "memory_vault_open_repair_index_state.py",
                    "memory_vault_open_repair_index_service.py",
                    "memory_vault_open_repair_index_client.py",
                    "memory_vault_open_repair_index_recovery.py",
                    "memory_vault_open_repair_index_admin.py",
                    "memory_vault_open_repair_index_prepare.py",
                    "memory_vault_open_repair_index_prepare_admin.py",
                    "memory_vault_open_repair_provision.py",
                    "memory_vault_open_repair_provision_admin.py",
                    "memory_vault_open_repair_bind_journal.py",
                    "memory_vault_open_repair_remote_setup.py",
                    "memory_vault_open_repair_remote_provision.py",
                    "memory_vault_open_repair_remote_provision_admin.py",
                    "memory_vault_open_provider_merge.py",
                    "memory_vault.py", "memory_vault_update.py", "memory_vault_trust.py", "memory_vault_network_crypto.py",
                    "memory_vault_network_control.py", "memory_vault_nodes.py",
                    "examples/protocol/open-repair-wire-v1.json",
                    "memory_vault_open_blob.py", "memory_vault_open_delivery.py", "memory_vault_open_delivery_client.py",
                    "memory_vault_open_delivery_state.py", "scripts/continuation_trial.py",
                    "scripts/build_client_plugin.py", "scripts/build_release.py", "scripts/verify_client_package.py",
                    "plugins/memory-vault-client/scripts/launcher.py", "clients/typescript/network/package.json"]
        # The executed module inventory is also the test-source inventory. New
        # test modules must not silently lack a pre-run byte fingerprint.
        sources += [name.replace(".", "/") + ".py" for name in MODULES]
    sources = sorted(set(sources))
    settings = {"schema_version":"memory-vault-open-ci-settings/v1", "commit_sha":sha, "mode":mode,
        "seed":seed if mode == "scale" else None, "source_sha256":{name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in sources},
        "bootstrap_python":sys.version.split()[0], "expected_node":"22.19.0" if mode=="light" else None,
        "expected_jose":"6.2.10" if mode=="light" else None,
        "requested_runner":"ubuntu-24.04-standard", "report_byte_limit":MAX_REPORT_BYTES, "synthetic_only":True,
        "scale_settings":{**EXPECTED,"queries_per_phase":1000} if mode == "scale" else None,
        "test_modules":list(modules) if mode == "light" else [],
        "partition_index":partition_index, "partition_count":partition_count}
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


def record_runtime(reports,mode,seed,partition_index=0,partition_count=1):
    settings=json.loads((reports.directory/"settings.json").read_text())
    require(settings["mode"]==mode and settings["seed"]==(seed if mode=="scale" else None))
    require(settings['partition_index']==partition_index and settings['partition_count']==partition_count)
    require(settings['test_modules']==(list(selected_modules(partition_index,partition_count)) if mode=='light' else []))
    actual_sha=subprocess.check_output(["git","rev-parse","HEAD"],cwd=ROOT,text=True).strip()
    require(settings["commit_sha"]==actual_sha)
    for name,digest in settings["source_sha256"].items():
        require(hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==digest)
    runtime={"python":sys.version.split()[0],"sqlite":sqlite3.sqlite_version,"os":platform.system(),
             "architecture":platform.machine(),"logical_cpus":os.cpu_count(),
             "cryptography":importlib.metadata.version("cryptography"),"joserfc":importlib.metadata.version("joserfc")}
    if mode=="light":
        runtime["uvicorn"]=importlib.metadata.version("uvicorn")
        runtime["starlette"]=importlib.metadata.version("starlette")
        runtime["node"]=subprocess.check_output(["node","--version"],text=True).strip()
        runtime["jose"]=json.loads((ROOT/"clients/typescript/network/node_modules/jose/package.json").read_text())["version"]
        require(runtime["node"]=="v22.19.0" and runtime["jose"]=="6.2.10")
    reports.write("settings.json",{**settings,"actual_runtime":runtime})


class DiscardOutput(io.TextIOBase):
    def write(self,value):return len(value)


class SyntheticResult(unittest.TestResult):
    def __init__(self,reports):
        super().__init__();self.reports=reports;self.entries=[];self.failfast=True

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
            # Preserve a narrow protocol reason through assertion wrappers,
            # without ever printing exception text, operands or arbitrary codes.
            allowed={"repair_access_expired","repair_over_budget","repair_resource_expired","repair_service_capacity",
                "repair_status_mismatch","repair_status_operation","repair_status_rollback",
                "repair_status_conflict","repair_status_missing","repair_authority_revoked",
                "open_network_unavailable"}
            cause=error[1];seen=set()
            while cause is not None and len(seen)<8 and id(cause) not in seen:
                seen.add(id(cause));code=getattr(cause,"code",None)
                if type(code) is str and code in allowed:
                    item["protocol_code"]=code;break
                cause=cause.__cause__ or cause.__context__
        self.entries.append(item);self.reports.event(item,error=state not in {"passed","subtest_passed"})

    def addSuccess(self,test):super().addSuccess(test);self.record(test,"passed")
    def addFailure(self,test,err):super().addFailure(test,err);self.record(test,"failed",err)
    def addError(self,test,err):super().addError(test,err);self.record(test,"error",err)
    def addSkip(self,test,reason):super().addSkip(test,"reason omitted");self.record(test,"skipped");self.stop()
    def addExpectedFailure(self,test,err):super().addExpectedFailure(test,err);self.record(test,"expected_failure",err);self.stop()
    def addUnexpectedSuccess(self,test):super().addUnexpectedSuccess(test);self.record(test,"unexpected_success")
    def addSubTest(self,test,subtest,err):
        super().addSubTest(test,subtest,err);self.record(test,"subtest_passed" if err is None else "subtest_failed",err)


def run_light(reports,partition_index=0,partition_count=1):
    if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
    result=SyntheticResult(reports)
    # A rejected candidate cannot become accepted by running more cases. Stop
    # on the first disqualifying result, retaining cleanup and explicit coverage.
    # Test exceptions remain classified, but raw provider errors/fixture paths
    # are not copied into either uploaded reports or public console output.
    with contextlib.redirect_stdout(DiscardOutput()),contextlib.redirect_stderr(DiscardOutput()):
        suite=unittest.defaultTestLoader.loadTestsFromNames(selected_modules(partition_index,partition_count))
        planned=suite.countTestCases()
        suite.run(result)
    complete=planned>0 and result.testsRun==planned
    passed=complete and result.wasSuccessful() and not result.skipped and not result.expectedFailures
    reports.write("results.json",{"schema_version":"memory-vault-open-ci-tests/v1","tests_run":result.testsRun,
        "tests_planned":planned,"complete":complete,"stopped_early":result.testsRun<planned,
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
    parser.add_argument("--partition-index",type=int,default=0)
    parser.add_argument("--partition-count",type=int,default=1)
    args=parser.parse_args();reports=Reports(args.report_directory)
    selected_modules(args.partition_index,args.partition_count)
    require(args.mode=='light' or (args.partition_index,args.partition_count)==(0,1))
    if args.phase=="initialize":initialize(reports,args.mode,args.seed,args.partition_index,args.partition_count);return 0
    if args.phase=="finalize":return 0 if finalize(reports) else 1
    def interrupted(signum,frame):raise KeyboardInterrupt
    for signum in (signal.SIGINT,signal.SIGTERM,signal.SIGALRM):signal.signal(signum,interrupted)
    # The expanded real-HTTP suite exceeded its former 40-minute CI wall cap.
    # Keep a finite limit and leave time for finalization and bounded reports.
    signal.alarm((55 if args.mode == "light" else 26)*60)
    reports.status("running")
    try:
        record_runtime(reports,args.mode,args.seed,args.partition_index,args.partition_count)
        passed=run_scale(reports,args.seed) if args.mode=="scale" else run_light(reports,args.partition_index,args.partition_count)
        complete=args.mode=="scale" or json.loads((reports.directory/"results.json").read_text())["complete"]
        reports.status("passed" if passed else "failed",passed=passed,complete=complete)
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
