"""Bounded synthetic signed directory load on real local HTTP processes.

This measures transport/index capacity, not AI models, automatic placement or
physical fault domains. Each owner explicitly selects a shard from the supplied
nodes; the observer's node list is never passed to a routing participant.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import http.client
import json
import multiprocessing
from pathlib import Path
import platform
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from memory_vault import canonical_bytes
from memory_vault_network_crypto import EncryptionIdentity, document
from memory_vault_open_control import contact_key, issue_contact, issue_node, sign_request, verify_response
from memory_vault_open_node import OpenHTTPServer, OpenParticipant
from memory_vault_open_transport import RPC_PATH
from memory_vault_trust import Identity


def identity(label):
    return Identity(Ed25519PrivateKey.from_private_bytes(hashlib.sha256(
        ("synthetic-http-capacity:" + label).encode()).digest()))


def serve(directory, index, pipe):
    signer = identity("node:" + str(index))
    now = int(time.time())
    # Reserve the actual listening socket first, then bind its signed descriptor.
    server = OpenHTTPServer(("127.0.0.1", 0), None)
    node = issue_node(signer, base_url="http://127.0.0.1:" + str(server.server_port),
        storage_epoch="synthetic_capacity_" + str(index), roles=["directory", "router"],
        revision=1, issued_at=now, expires_at=now + 3600)
    participant = OpenParticipant(signer, Path(directory), seeds=[], descriptor=node,
        allow_loopback=True, index_policy={"enabled": True})
    server.participant = participant
    pipe.send(node)
    server.serve_forever(poll_interval=.02)


def request(node, signed):
    start = time.perf_counter()
    status, body = "connection_error", None
    connection = http.client.HTTPConnection("127.0.0.1",
        int(node["payload"]["base_url"].rsplit(":", 1)[1]), timeout=4)
    try:
        connection.request("POST", RPC_PATH, canonical_bytes(signed),
            {"Content-Type": "application/json"})
        reply = connection.getresponse()
        raw = reply.read()
        status = str(reply.status)
        if reply.status == 200:
            body = verify_response(document(raw), request=signed, node=node)["body"]
            status = body.get("error", {}).get("code", "ok")
    except (OSError, http.client.HTTPException):
        pass
    finally:
        connection.close()
    return {"status": status, "latency_ms": (time.perf_counter()-start)*1000,
            "found": bool(body and body.get("state") == "found")}


def run(count, args):
    processes, nodes = [], []
    with tempfile.TemporaryDirectory(prefix="synthetic-http-capacity-") as temporary:
        try:
            ctx = multiprocessing.get_context("spawn")
            for i in range(count):
                parent, child = ctx.Pipe()
                p = ctx.Process(target=serve, args=(str(Path(temporary).resolve()/str(i)), i, child))
                p.start(); processes.append(p)
                if not parent.poll(15):
                    raise RuntimeError("synthetic node startup timeout")
                nodes.append(parent.recv()); parent.close()
            encryption = EncryptionIdentity.generate()
            owners = [identity("owner:"+str(i)) for i in range(args.requests)]
            assignments = [min(range(count), key=lambda j: int(contact_key(owner.key_id),16)
                ^ int(nodes[j]["payload"]["coordinate"],16)) for owner in owners]
            shard_counts = [assignments.count(j) for j in range(count)]
            for i, owner in enumerate(owners):
                now = int(time.time()); node = nodes[assignments[i]]
                contact = issue_contact(owner, encryption_key=encryption.public_descriptor(),
                    revision=1, allow_discovery=True, endpoints=[], issued_at=now, expires_at=now+3600)
                put = sign_request(owner, action="put", node=node,
                    request_id="synthetic_setup_"+str(i), body={"contact": contact,"lease_seconds":600},
                    issued_at=now, expires_at=now+60)
                result = request(node, put)
                if result["status"] != "ok":
                    raise RuntimeError("synthetic setup refused: "+result["status"])
                time.sleep(.02)  # retain the ordinary per-source rate limits
            time.sleep(1.1)
            rounds = []
            for turn in range(args.rounds):
                inputs=[]
                for i, owner in enumerate(owners):
                    now=int(time.time());node=nodes[assignments[i]]
                    signed=sign_request(owner,action="get",node=node,
                        request_id=f"synthetic_get_{turn}_{i}",body={"key":contact_key(owner.key_id)},
                        issued_at=now,expires_at=now+60)
                    inputs.append((node,signed))
                start=time.perf_counter()
                with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
                    if args.arrival_rate:
                        futures=[]
                        for i,pair in enumerate(inputs):
                            time.sleep(max(0,start+i/args.arrival_rate-time.perf_counter()))
                            futures.append(pool.submit(request,*pair))
                        results=[future.result() for future in futures]
                    else:
                        results=list(pool.map(lambda pair:request(*pair), inputs))
                elapsed=time.perf_counter()-start
                ok=[r for r in results if r["status"]=="ok" and r["found"]]
                latency=sorted(r["latency_ms"] for r in ok)
                statuses={s:sum(r["status"]==s for r in results) for s in {r["status"] for r in results}}
                rounds.append({"seconds":elapsed,"successful_reads":len(ok),"requests":len(results),
                    "useful_reads_s":len(ok)/elapsed,"error_rate":1-len(ok)/len(results),
                    "p50_ms":latency[len(latency)//2] if latency else None,
                    "p95_ms":latency[min(len(latency)-1,int(len(latency)*.95))] if latency else None,
                    "statuses":statuses})
                if not args.arrival_rate:
                    time.sleep(1.1)
            return {"nodes":count,"concurrency":args.concurrency,"shard_contacts":shard_counts,
                "rounds":rounds,"successful_reads":sum(r["successful_reads"] for r in rounds),
                "requests":args.requests*args.rounds,
                "useful_reads_s":sum(r["successful_reads"] for r in rounds)/sum(r["seconds"] for r in rounds)}
        finally:
            for p in processes:
                p.terminate();p.join(3)
                if p.is_alive():p.kill();p.join(2)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nodes",type=int,nargs="+",default=[1,2,4])
    parser.add_argument("--requests",type=int,default=64)
    parser.add_argument("--rounds",type=int,default=4)
    parser.add_argument("--concurrency",type=int,default=32)
    parser.add_argument("--arrival-rate",type=int,default=0,
        help="optional paced total requests/s; zero selects bursts")
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    if (any(n not in [1,2,4] for n in args.nodes) or not 1<=args.requests<=64
            or not 1<=args.rounds<=8 or not 1<=args.concurrency<=64
            or not 0<=args.arrival_rate<=48):parser.error("bounded synthetic limits")
    report={"python":sys.version,"platform":platform.platform(),"baseline_commit":"c840617eb50e8856695234b482fed5560c0c72bf",
        "source_hashes":{n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in
            ["memory_vault_network.py","memory_vault_open_index.py","memory_vault_open_node.py"]},
        "synthetic":True,"real_models":0,"physical_hosts":1,
        "measured_phase":"paced requests" if args.arrival_rate else "bounded bursts; idle intervals and setup excluded from useful_reads_s",
        "arrival_rate":args.arrival_rate,
        "results":[]}
    for count in args.nodes:
        value=run(count,args);report["results"].append(value)
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(report,indent=2)+"\n")
        print(json.dumps(value),flush=True)


if __name__=="__main__":main()
