"""Reproducible logical routing acceptance, not an AI/HTTP/physical benchmark.

Run: python -m tests.open_routing_acceptance --seed 17 --queries 1000
Repeat seeds 29 and 43. No route is inserted by the host: only finite initial
hellos, production lookup and bounded periodic protocol maintenance create state.
The global identity map resolves requested destinations and checks outcomes only.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import random
import statistics
import sys
import time

from memory_vault_open_control import coordinate
from tests.test_open_routing import SyntheticRouting

MAX_FAILURE_SAMPLES = 8


def routing_graph(network):
    """Read already-created synthetic state; never add routes or probe peers."""
    def indices(entries):
        return [network.by_key[e.key] for bucket in entries.values() for e in bucket]
    return [{"node": i, "active": indices(table._active["general"]),
             "spare": indices(table._replacement["general"]),
             "pending": [network.by_key[n["payload"]["signing_key"]["key_id"]]
                         for n in network.pending[i]]} for i, table in enumerate(network.tables)]


def failure_sample(network, failure, initial, result):
    graph = routing_graph(network)
    target = failure["target"]
    return {"query": failure["query"], "initial": initial,
            "returned": [network.by_key[n["payload"]["signing_key"]["key_id"]]
                         for n in result["candidates"]],
            "replies": network.find_observations,
            "paths": [{"peer": network.by_key[p["key_id"]],
                       "parent": None if p["parent_key_id"] is None else network.by_key[p["parent_key_id"]],
                       **{k:p[k] for k in ("lane", "source_bits", "depth", "state")}}
                      for p in result["metrics"]["paths"]],
            "target_holders": {kind: [row["node"] for row in graph if target in row[kind]]
                               for kind in ("active", "spare", "pending")}}


def percentile(values, fraction):
    return sorted(values)[min(len(values) - 1, int((len(values) - 1) * fraction))]


async def run(seed=17, queries=1000, nodes=100):
    rng = random.Random(seed)
    # Targets/sources fixed before joining, and identical between fault phases.
    pairs = [tuple(rng.sample(range(2, nodes), 2)) for _ in range(queries)]
    network = SyntheticRouting(nodes, seed=seed)
    started = time.monotonic()
    def progress(event):
        print(json.dumps({"seed": seed, "elapsed_seconds": round(time.monotonic() - started, 3), **event}),
              file=sys.stderr, flush=True)
    await network.join_and_maintain(cycles=20, progress=progress)
    join_seconds = time.monotonic() - started
    join_requests, join_response_bytes = network.rpc_count, network.response_bytes
    phases = {}
    diagnostics = {"schema_version": "memory-vault-open-routing-diagnostics/v1",
                   "maintenance_graph": routing_graph(network), "phases": {}}
    for name in ("healthy", "bootstrap_exit"):
        if name == "bootstrap_exit":
            network.offline.update((0, 1))
        request_counts, durations, failures, peaks = [], [], [], []
        newly_introduced_paths = unknown_initial_targets = 0
        samples, sampled_targets = [], set()
        before_requests, before_bytes = network.rpc_count, network.response_bytes
        for index, (source, destination) in enumerate(pairs):
            target = coordinate(network.identities[destination].key_id)
            initial = network.tables[source].closest(target, limit=16)
            known = {n["payload"]["signing_key"]["key_id"] for n in initial}
            if network.identities[destination].key_id not in known:
                unknown_initial_targets += 1
            start = time.monotonic()
            network.find_observations = []
            result = await network.search(source, target)
            durations.append((time.monotonic() - start) * 1000)
            metrics = result["metrics"]
            request_counts.append(metrics["requests"])
            peaks.append((metrics["candidate_peak"], metrics["concurrency_peak"]))
            reached = network.identities[destination].key_id in {
                n["payload"]["signing_key"]["key_id"] for n in result["candidates"]}
            if not reached:
                failures.append({"query": index, "source": source, "target": destination,
                                 "state": result["state"], "requests": metrics["requests"]})
                if destination not in sampled_targets and len(samples) < MAX_FAILURE_SAMPLES:
                    samples.append(failure_sample(network, failures[-1], [
                        network.by_key[n["payload"]["signing_key"]["key_id"]] for n in initial], result))
                    sampled_targets.add(destination)
            network.find_observations = None
            if any(p["parent_key_id"] is not None and p["key_id"] not in known for p in metrics["paths"]):
                newly_introduced_paths += 1
            if (index + 1) % 100 == 0:
                progress({"phase": name, "queries_completed": index + 1, "failures": len(failures),
                          "requests": network.rpc_count - before_requests})
            if metrics["candidate_peak"] > 32 or metrics["concurrency_peak"] > 3 or metrics["requests"] > 64:
                raise AssertionError("production routing budget exceeded")
        success_rate = (queries - len(failures)) / queries
        threshold = .99 if name == "healthy" else .97
        phases[name] = {"queries": queries, "successes": queries - len(failures),
            "success_rate": success_rate, "threshold": threshold, "passed": success_rate >= threshold,
            "failures": failures, "unknown_initial_target_queries": unknown_initial_targets,
            "queries_with_new_causal_hops": newly_introduced_paths,
            "actual_requests": network.rpc_count - before_requests,
            "actual_response_bytes": network.response_bytes - before_bytes,
            "requests_p50": statistics.median(request_counts), "requests_p95": percentile(request_counts, .95),
            "requests_max": max(request_counts), "latency_ms_p50": statistics.median(durations),
            "latency_ms_p95": percentile(durations, .95), "candidate_peak": max(p[0] for p in peaks),
            "concurrency_peak": max(p[1] for p in peaks)}
        diagnostics["phases"][name] = {"graph": routing_graph(network), "failure_samples": samples}
    stats = [table.stats() for table in network.tables]
    return {"schema_version": "memory-vault-open-routing-acceptance/v2", "seed": seed, "logical_nodes": nodes,
        "profile": "routing_core_table_initial_no_restart_cache", "checkpoints": False,
        "initial_closest_entries": 16, "full_runtime_benchmark": False,
        "real_ed25519": True, "transport": "in_process_signed_control", "actual_http": False,
        "ai_instances": 0, "physical_failure_domains_verified": False, "maintenance_cycles": 20, "maintenance_requests_per_node_cycle": 16,
        "maintenance_response_bytes_per_node_cycle": 1048576, "maintenance_seconds_per_node_cycle": 5,
        "maintenance_pending_probes": 2, "maintenance_announcements": 2,
        "maintenance_target_schedule": "own_coordinate_every_fourth_cycle_otherwise_random",
        "pending_overflow": "signed_retryable_rejection", "pending_capacity": 32, "join_notify_count": 2,
        "maintenance_and_join_requests": join_requests, "maintenance_and_join_response_bytes": join_response_bytes,
        "maintenance_and_join_seconds": join_seconds, "phases": phases,
        "max_per_node_routing_state": {key: max(s[key] for s in stats) for key in stats[0]},
        "sum_per_node_routing_state": {key: sum(s[key] for s in stats) for key in stats[0]},
        "total_seconds": time.monotonic() - started, "routing_diagnostics": diagnostics,
        "passed": all(phase["passed"] for phase in phases.values())}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, choices=(17, 29, 43), default=17)
    parser.add_argument("--queries", type=int, default=1000)
    parser.add_argument("--nodes", type=int, choices=(100, 250, 500, 1000), default=100)
    options = parser.parse_args()
    if not 1 <= options.queries <= 1000:
        parser.error("queries must be 1..1000")
    result = asyncio.run(run(options.seed, options.queries, options.nodes))
    # Preserve every failure and bounded diagnostic within the CI pipe limit;
    # indentation alone can more than triple this public JSON document.
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    raise SystemExit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
