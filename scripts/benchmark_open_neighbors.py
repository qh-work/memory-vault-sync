"""Fixed-rate public routing-step workload, with an actual late peer join.

At most three loopback server processes, 24 seconds of offered load and sixteen
driver threads. A client receives ONE seed, never the observer's complete node
list. Baseline uses the prior one-hop signed find API at that fixed entry; the
new API discovers/challenges neighbors and distributes subsequent routing steps.
This is not a complete contact resolution, storage migration or delivery test.
"""
from __future__ import annotations

import argparse
import asyncio
from collections import Counter
from contextvars import ContextVar
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import multiprocessing
from pathlib import Path
import platform
import resource
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from memory_vault import MemoryError, canonical_bytes
from memory_vault_open_control import coordinate, issue_node
from memory_vault_open_node import OpenHTTPServer, OpenParticipant
from memory_vault_open_routing import LookupBudget
from memory_vault_trust import Identity


def identity(index):
    return Identity(Ed25519PrivateKey.from_private_bytes(hashlib.sha256(
        f"synthetic-neighbor-capacity:{index}".encode()).digest()))


def usage():
    value = resource.getrusage(resource.RUSAGE_SELF)
    return dict(user_cpu_seconds=value.ru_utime, system_cpu_seconds=value.ru_stime,
                max_rss_bytes=value.ru_maxrss if sys.platform == "darwin" else value.ru_maxrss*1024)


def serve(directory, index, seed, pipe):
    lock = threading.Lock()
    counts = Counter()
    class Participant(OpenParticipant):
        def handle(self, request):
            response = super().handle(request)
            with lock:
                counts["action_"+request["payload"]["action"]] += 1
                counts["request_bytes"] += len(canonical_bytes(request))
                counts["response_bytes"] += len(canonical_bytes(response))
            return response
    class Server(OpenHTTPServer):
        def admitted(self, address):
            accepted = super().admitted(address)
            with lock:
                counts["http_requests"] += 1
                counts["admitted" if accepted else "rate_refused"] += 1
            return accepted
        def _busy(self, request):
            with lock:
                counts["queue_refused"] += 1
            return super()._busy(request)
    server = Server(("127.0.0.1", 0), None)
    now = int(time.time())
    node = issue_node(identity(index), base_url=f"http://127.0.0.1:{server.server_port}",
        storage_epoch=f"synthetic_neighbors_{index}", roles=["directory", "router"],
        revision=1, issued_at=now, expires_at=now+3600)
    participant = Participant(identity(index), Path(directory), seeds=[seed] if seed else [],
                              descriptor=node, allow_loopback=True)
    server.participant = participant
    stop = threading.Event()
    def maintenance():
        try:
            asyncio.run(participant.join())
            while not stop.wait(2):
                asyncio.run(participant.maintain())
        except (MemoryError, OSError):
            with lock:
                counts["maintenance_error"] += 1
    def control():
        worker = None
        while not stop.is_set():
            command = pipe.recv()
            if command == "join":
                if worker is None:
                    worker = threading.Thread(target=maintenance, daemon=True)
                    worker.start()
                pipe.send({"joining": True})
            elif command == "snapshot":
                with lock:
                    snapshot = dict(counts)
                pipe.send(dict(counts=snapshot, usage=usage(), routing=participant.table.stats()))
            elif command == "stop":
                stop.set()
                server.shutdown()
    pipe.send(node)
    threading.Thread(target=control, daemon=True).start()
    try:
        server.serve_forever(poll_interval=.02)
    finally:
        stop.set()
        server.server_close()


def percentile(values, p):
    values = sorted(values)
    return values[min(len(values)-1, int((len(values)-1)*p))] if values else None


def summary(rows, seconds):
    success = [row for row in rows if row["status"] == "ok"]
    return dict(total=len(rows), successful=len(success), success_rate=len(success)/len(rows) if rows else None,
        window_seconds=seconds, successful_per_second=len(success)/seconds,
        statuses=dict(Counter(row["status"] for row in rows)),
        successful_p95_ms=percentile([r["latency_ms"] for r in success], .95),
        successful_p99_ms=percentile([r["latency_ms"] for r in success], .99),
        all_p95_ms=percentile([r["latency_ms"] for r in rows], .95),
        all_p99_ms=percentile([r["latency_ms"] for r in rows], .99),
        offer_lag_p99_ms=percentile([r["offer_lag_ms"] for r in rows], .99),
        successful_by_responder=dict(Counter(str(r["responder"]) for r in success)))


def run(args):
    ctx = multiprocessing.get_context("spawn")
    processes, pipes, nodes = [], [], []
    with tempfile.TemporaryDirectory(prefix="synthetic-neighbor-load-") as temporary:
        directory = Path(temporary).resolve()
        try:
            for index in range(3):
                parent, child = ctx.Pipe()
                process = ctx.Process(target=serve, args=(str(directory/str(index)), index,
                    nodes[0] if nodes else None, child))
                process.start(); processes.append(process); pipes.append(parent)
                if not parent.poll(10):
                    raise RuntimeError("bounded node startup timeout")
                nodes.append(parent.recv())
            # All three servers exist in both runs, but the additional two only
            # enter the network at join_after. No descriptor is injected client-side.
            client = OpenParticipant(identity(99), directory/"client", seeds=[nodes[0]], allow_loopback=True)
            urls = {node["payload"]["base_url"]: i for i, node in enumerate(nodes)}
            keys = {node["payload"]["signing_key"]["key_id"]: i for i, node in enumerate(nodes)}
            attempt_context = ContextVar("synthetic_attempts")
            original_request = client.transport.request
            def observe(url, request, **kwargs):
                action = request["payload"]["action"]
                try:
                    reply = original_request(url, request, **kwargs)
                    attempt_context.get().append(dict(node=urls.get(url, "outside_fixture"), action=action, status="answered"))
                    return reply
                except (MemoryError, OSError, TimeoutError) as exc:
                    attempt_context.get().append(dict(node=urls.get(url, "outside_fixture"), action=action,
                                               status=getattr(exc, "code", "network_error")))
                    raise
            client.transport.request = observe
            target = coordinate(identity(100).key_id)
            adaptive = hasattr(client, "find_neighbors")
            def operation(index, offered, start):
                attempts = []
                attempt_context.set(attempts)
                lag = (time.perf_counter()-offered)*1000
                responder = None
                try:
                    if adaptive:
                        result = asyncio.run(client.find_neighbors(target))
                        status = "ok" if result["state"] == "introduced" else "unreachable"
                        if result["responder"]:
                            responder = keys[result["responder"]["payload"]["signing_key"]["key_id"]]
                    else:
                        result = asyncio.run(client._call(nodes[0], "find", {"target":target,"view":"general"}, LookupBudget()))
                        status, responder = "ok", 0
                except Exception as exc:
                    status = getattr(exc, "code", type(exc).__name__)
                return dict(index=index, offered_seconds=offered-start, status=status, responder=responder,
                    latency_ms=(time.perf_counter()-offered)*1000, offer_lag_ms=lag, attempts=attempts)
            pipes[0].send("join"); pipes[0].recv()
            snapshots = []
            for pipe in pipes:
                pipe.send("snapshot"); snapshots.append(pipe.recv())
            driver_before = usage()
            start = time.perf_counter()
            joined = False
            with ThreadPoolExecutor(max_workers=16) as pool:
                futures = []
                for i in range(args.seconds*args.rate):
                    offered = start+i/args.rate
                    time.sleep(max(0, offered-time.perf_counter()))
                    if not joined and i/args.rate >= args.join_after:
                        for pipe in pipes[1:]:
                            pipe.send("join"); pipe.recv()
                        joined = True
                    futures.append(pool.submit(operation, i, offered, start))
                # Include the complete sustained offer window, without removing
                # scheduling gaps. Drain is reported separately and in total rate.
                time.sleep(max(0, start+args.seconds-time.perf_counter()))
                rows = [future.result() for future in futures]
            elapsed = time.perf_counter()-start
            driver_after = usage()
            per_node = []
            for i, pipe in enumerate(pipes):
                pipe.send("snapshot"); end = pipe.recv()
                per_node.append(dict(node=i, counts={key: value-snapshots[i]["counts"].get(key,0)
                    for key,value in end["counts"].items()}, routing=end["routing"],
                    user_cpu_seconds=end["usage"]["user_cpu_seconds"]-snapshots[i]["usage"]["user_cpu_seconds"],
                    system_cpu_seconds=end["usage"]["system_cpu_seconds"]-snapshots[i]["usage"]["system_cpu_seconds"],
                    max_rss_bytes=end["usage"]["max_rss_bytes"]))
            client.close()
            return dict(mode="automatic_neighbors" if adaptive else "prior_fixed_entry_find",
                offered_rate=args.rate, offer_window_seconds=args.seconds, elapsed_including_drain=elapsed,
                join_after_seconds=args.join_after, caller_initial_introductions=1,
                overall=summary(rows, elapsed),
                completed_during_offer_window=sum(r["status"] == "ok" and
                    r["offered_seconds"]+r["latency_ms"]/1000 <= args.seconds for r in rows),
                completed_during_last_eight_seconds=sum(r["status"] == "ok" and
                    args.seconds-8 <= r["offered_seconds"]+r["latency_ms"]/1000 <= args.seconds for r in rows),
                steady_last_eight_seconds=summary(
                    [r for r in rows if r["offered_seconds"] >= args.seconds-8],8),
                windows=[summary([r for r in rows if second <= r["offered_seconds"] < second+4],4)
                         for second in range(0,args.seconds,4)], per_node=per_node,
                driver=dict(user_cpu_seconds=driver_after["user_cpu_seconds"]-driver_before["user_cpu_seconds"],
                    system_cpu_seconds=driver_after["system_cpu_seconds"]-driver_before["system_cpu_seconds"],
                    max_rss_bytes=driver_after["max_rss_bytes"]), requests=rows)
        finally:
            for pipe in pipes:
                try: pipe.send("stop")
                except (OSError, BrokenPipeError): pass
            for process in processes:
                process.join(3)
                if process.is_alive(): process.terminate(); process.join(2)
                if process.is_alive(): process.kill(); process.join(2)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rate", type=int, default=80)
    parser.add_argument("--seconds", type=int, default=24)
    parser.add_argument("--join-after", type=int, default=6)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not 1<=args.rate<=96 or args.seconds not in (16,20,24) or not 2<=args.join_after<=6:
        parser.error("bounded load: rate <=96; seconds 16,20,24; join-after 2..6")
    report=dict(synthetic=True, real_models=0, physical_hosts=1, cpu_count=multiprocessing.cpu_count(),
        python=sys.version, platform=platform.platform(), source_hashes={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest()
        for name in ("memory_vault_network.py","memory_vault_open_index.py","memory_vault_open_node.py","memory_vault_open_routing.py")},
        scope="signed public neighbor query, not full contact resolution or message I/O", result=run(args))
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({key:value for key,value in report["result"].items() if key!="requests"}),flush=True)


if __name__ == "__main__":
    main()
