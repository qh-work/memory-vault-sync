> Recorded batch2 routing measurements. DELIVERY_CAPACITY.md documents the later probe fix and the separate real delivery implementation.

# Bounded public routing query distribution

`OpenParticipant.find_neighbors(target, view="general", budget=None)` distributes
one public routing step across a bounded pool of endpoint-proven routers. A caller
starts with its configured one or two introductions, receives a signed `find`
response and can challenge one returned new router with `hello` at most once per
five seconds. Future calls rotate proven peers. At most three peers are tried per
operation; any extra challenge uses the same finite lookup budget. New keys have
probe priority over temporarily failed old peers. Existing routing source, bucket,
expiry and durable rollback/revocation/fork limits apply. No global roster or new
admission authority is introduced, and the first entry is not required after other
peers have been proven.

```python
hints = await participant.find_neighbors(contact_key(owner_key_id), view="directory")
# hints["nodes"] are introductions. They do not grant access or certify a contact.
contact = await participant.find_contact(owner_key_id)
```

This is a public neighborhood query API, not a replacement for iterative lookup.
`find_contact` still observes all selected shards before choosing an eligible
contact, so a later shard's revocation or conflict cannot be bypassed by choosing a
convenient replica. The current Python/TypeScript message send and storage paths
have not been switched to this new API. This batch does not move memory records,
replicate ciphertext, redistribute private reads/writes, or raise the eight-worker
HTTP limit. It does not establish full contact resolution or message delivery
capacity. A future client can use these hints in a routing stage, but that complete
path needs separate implementation and measurement.

## Controlled before/after workload

The benchmark uses deterministic synthetic Ed25519 identities and real HTTP on
127.0.0.1. All three nodes run on one Mac mini (Apple M1, eight CPU cores, 8 GiB RAM,
macOS 27.2). The driver has sixteen threads and sends **80 queries/s for 24 seconds**,
1920 offered queries per run, with no removed idle gaps. Both runs have the same
three server processes. Nodes 1 and 2 enter the network at second 6 using existing
join and maintenance exchanges. The client receives only node 0; the observer's
full node list is used only to label measurements. New node descriptors are not
injected into the client. Requests query the same routing coordinate, and responses
are signature/request/node verified. No real memories, paid model calls or external
services participate.

Baseline is the prior one-hop `find` call at a fixed entry, executed on the preserved
batch1 runtime. After uses the new `find_neighbors` API. **This baseline is not the
existing complete `find_contact` operation.** The core source hashes are retained
in both reports. Success means a verified, non-error public routing response; hints
remain unverified until separately challenged. Endpoint proofs, maintenance and
failed attempts are additional wire work and are recorded.

| Full offer window plus drain | Before | After |
| --- | ---: | ---: |
| Offered queries | 1920 | 1920 |
| Successful queries | 1509 | 1766 |
| Success rate | 78.59% | 91.98% |
| Successful queries/s (including drain) | 62.85 | 73.55 |
| Successful p95, ms | 23.89 | 29.76 |
| Successful p99, ms | 27.80 | 44.91 |
| All outcomes p95, ms | 23.69 | 29.52 |
| All outcomes p99, ms | 27.47 | 44.66 |

Elapsed including drain: 24.0098s before, 24.0113s after.

| Last eight-second offered cohort (seconds 16..24) | Before | After |
| --- | ---: | ---: |
| Total / offered | 640 | 640 |
| Successful queries | 504 | 640 |
| Success rate | 78.75% | 100.00% |
| Successful queries/s | 63.00 | 80.00 |
| Successful p95, ms | 23.75 | 33.05 |
| Successful p99, ms | 26.43 | 45.56 |

Completions physically inside seconds 16..24: 504 before and 640 after (the same 8-second completion rate). Offered-cohort tail latencies include queueing, scheduling delay and final drain; every failed outcome is retained.

| Node | Driver successes before / after | Total server find work before / after | CPU seconds before / after | Max RSS MiB before / after |
| --- | ---: | ---: | ---: | ---: |
| 0 | 1509 / 1088 | 1522 / 1106 | 7.348 / 5.302 | 40.17 / 39.81 |
| 1 | 0 / 238 | 16 / 254 | 0.867 / 2.012 | 38.47 / 38.78 |
| 2 | 0 / 440 | 18 / 456 | 0.911 / 2.974 | 39.11 / 39.70 |

Driver CPU seconds: 17.948 before, 26.027 after. The last offered cohort uses nodes 0/1/2 for {'2': 214, '0': 213, '1': 213}.

## Interpretation and boundaries

The additional routers carry real client requests after being discovered through
normal protocol traffic. They reduce the original node's client workload without
raising its policy limit. At this offered rate the baseline's main observed
constraint is the unchanged per-source 64/s HTTP admission policy, plus maintenance
traffic sharing that allowance. This is **policy-bound public query capacity**;
CPU saturation, SQLite write capacity, wide-area limits and maximum sustainable
throughput have not been established. The new API increases client CPU work and
p95/p99 latency. During join/proof convergence the full after run still has 154
failed queries (8.02%); the final 12 seconds have zero failures, and the final eight
seconds distribute successful requests 213/213/214 across nodes 0/1/2. This short
finite observation is not a long-run reliability guarantee.

The trace shows the first useful query on node 2 around second 10 and node 1 around
second 15. These are bounded client probes, not immediate topology convergence.
A router can return a different local neighborhood than another router; this API
only returns hints and never labels them globally closest or authoritative.

No contact/control permission was weakened. Known revocation and conflict remain
blocking. Independently authorized replica placement and end-to-end storage or
message load balancing remain separate work. The next useful environment is at
least three independently hosted nodes with owner-operated HTTPS and explicit
finite resource grants, followed by a measured complete authorized read/write or
mailbox path. One shared Mac cannot demonstrate independent CPU/storage/failure
domains or thousand-agent capacity. Native SDK integration also remains.

## Validation and reproducibility

29 existing/new routing, real HTTP, directory revocation/conflict and concurrency
regression cases passed in 109.716 seconds before the final newcomer-priority
correction. Five neighbor boundary cases passed with the final correction; 30
distinct cases are covered. The latter includes corrupted signatures, late join,
old-peer failure, current revocation, failover and shared budget enforcement.
The final measured runtime hashes match the delivered source. The alpha39 native
mailbox branch (`3df5cf8e58c94c0c2f703d574321f3c2561ffcec`) changes none of the four
runtime files involved here; the cumulative patch applies without changing that
original worktree. Its new mailbox paths have not been performance certified here.

```sh
python scripts/benchmark_open_neighbors.py --rate 80 --seconds 24 --join-after 6 --output after.json
python -m unittest tests.test_open_neighbors -v
```

For baseline, use the batch1 source in the delivery and the same benchmark script;
it detects absence of `find_neighbors` and uses the prior fixed-entry signed find.
Per-request traces, four-second windows, all failure attempts, CPU/RSS and wire byte
counts are in the delivery's `neighbor-evidence/before.json` and `after.json`.
Pilot and pre-correction runs are excluded from the selected evidence. The runtime
model setting was accepted as `gpt-6.1-sol` with high reasoning; actual inference
model metadata is not exposed for independent confirmation. No model-switch
request was repeated in this batch.
