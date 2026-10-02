> Recorded batch1 transport/index measurements. Later code and complete message-chain results are in DELIVERY_CAPACITY.md.

# Bounded HTTP directory read capacity — development evidence

Baseline: `c840617eb50e8856695234b482fed5560c0c72bf` (main, rechecked against the remote). Development branch: `feat/bounded-directory-read-capacity`. No version bump, commit, push, deployment or live user configuration change was performed.

## Implemented behavior

- Each HTTP node uses eight fixed daemon execution workers and a queue of at most sixteen accepted sockets. No worker is created per incoming connection. Queue wait consumes the original three-second whole-input deadline; a queued request never receives a fresh input window. Expired/overflow work receives a best-effort 503 with Retry-After. Transport resets can still occur on an overloaded socket; existing transport errors remain retryable. Active repair-response deadlines retain their existing separate finite bound.
- An initialized transport database verifies its durable configuration binding on every open without acquiring the writer lock. First initialization and legacy migration still acquire and recheck under the writer lock. Existing protected-path and sidecar validation remain on each open.
- Directory `get` uses a consistent WAL read snapshot. Lease/floor/replay expiry and capacity checks use the same logical live rows without mutating storage. The next allocation prunes expired rows; reads cannot create unbounded state. Committed revocation/conflict floors remain effective, and an uncommitted concurrent writer is not treated as committed authority.

The eight execution slots, global 128 requests/s gate and per-source 64 requests/s gate remain. Owner consent, signed identity/node/epoch binding, retry receipts, resource ceilings and the six Agent operations retain their existing contracts.

## Actual experiment

One Mac mini, Apple M1, eight cores, 8 GiB RAM; macOS 27.2 (26B5091g). Python 3.12.0b4, SQLite 3.42.0, cryptography 50.0.1, joserfc 1.7.5, httpx 0.28.1. Node 22.19.0 / jose 6.2.10 were used for selected native SDK regression. All keys, contacts, messages and storage were disposable synthetic fixtures. No real model API was called.

`scripts/benchmark_open_http.py` runs real independent node processes and actual signed HTTP requests/responses. There are 64 deterministic synthetic contact owners, 32 concurrent requester threads and four rounds of 64 directory reads per topology (256 requests each). The same owners select their explicit directory shard by XOR distance over the configured experiment nodes. The observer's full node list is not installed into any routing participant; all server participants have empty initial introductions. Placement in this benchmark is explicit, not automatic migration or a global discovery acceptance claim. Per-node contact counts were `[64]`, `[34,30]`, and `[8,14,32,10]`.

| Node processes | Successful reads | Error rate | Burst service reads/s | Mean of per-round successful-read p95, ms |
| --- | --- | --- | --- | --- |
| 1 | 32/256 → 117/256 | 87.50% → 54.30% | 99.1 → 195.3 | 79.4 → 125.1 |
| 2 | 64/256 → 256/256 | 75.00% → 0.00% | 199.5 → 271.6 | 78.4 → 139.1 |
| 4 | 140/256 → 256/256 | 45.31% → 0.00% | 281.6 → 299.0 | 100.2 → 135.6 |

Burst service rate excludes setup and the 1.1-second quiet intervals required to keep the ordinary rate gates intact. It is not a sustained requests/s capacity claim. Successful-read latency omits failed requests, so the baseline percentiles describe a smaller surviving subset. More admitted work increases queue latency while greatly increasing completion. Two to four processes do not show linear throughput growth on this one host and one requester process. The experiment does not isolate a final CPU bottleneck.

A separate paced single-node control submitted 256 requests at 48 requests/s without inter-round quiet intervals (about 5.3 seconds). Both versions completed 256/256. Per-round p95 was approximately 14 ms in both; there is no demonstrated steady-load latency gain. JSON evidence retains every round, status count, source hash and measurement definition. Timing samples that overlapped regression workloads were discarded.

## Validation and limits

- Existing/index/network-race/transport/multihop/routing/contact regression: 68 reported tests, OK with one initially skipped native-state class, in 126.067 seconds. This includes real eight-process multihop lookup after bootstrap exit and independent committed owner revocation. It is a targeted campaign, not the full repository suite.
- Final boundary campaign: six tests pass. They exercise real WAL readers with an uncommitted writer then committed revocation, expired-row invisibility and later reclamation, binding changes on later opens, bounded live socket overload, preserved whole-input timeout after queuing, and bind-failure cleanup.
- Selected native Agent campaign: two tests pass in 9.314 seconds with real Node / JOSE and real Python HTTP resources. Each Node driver prevents subprocess delegation before importing production SDK code. Native approval/encrypted delivery/saved receipts and cold-sender/owner/resource restart are exercised. Python Agent separately saves selected canonical memory, restarts, confirms the original receipt and recalls the original evidence.

The broad and native campaigns preceded the final small listener-construction/cleanup guard; the final boundary campaign and the published performance JSON pin the delivered runtime sources. There is no combined whole-suite certification on one exact source. No load tests have been run against the unmerged alpha39 branch; its versions of the three touched runtime files match the baseline and the independent patch is applicable.

This batch improves finite burst admission and reader/writer coexistence. Single-node overflow still occurs. Process-local first-contact CPU slots, other service writer transactions, hot-shard migration, automatic placement/rebalancing, multi-host fault domains, long-duration demand growth and 1,000-model communication remain unverified or unfinished. Additional nodes demonstrably serve independently selected useful directory reads here; automatic redistribution is not implemented by this batch.

## Agent access and the next acceptance step

Existing Python hosts call `Agent(client_config, network_config).handle(request)` or use the six-operation NDJSON `serve` interface in `docs/OPEN_NETWORK_QUICKSTART.md`. Native Node hosts call `await Agent.handle(request)` using the same six-operation objects. A model host must expose that already-authorized endpoint as its tool and preserve the actual signed identities, independent recipient consent and current resource permissions. SDK tests do not establish a model's understanding or autonomous follow-through. No installed MCP/capture configuration was altered.

A harmless local inventory found no Ollama CLI and no listener on its ordinary loopback port. No model was downloaded and no external paid API was used. To run a real-model sustained acceptance next, select authorized existing Agent/model sessions or local models and the endpoints/resources they may use, with explicit permission for that integration. Keep new spending and external deployment separately authorized.

## Reproduce

Use an isolated Python environment with the repository's network/server dependency files. From the checkout, run:

```sh
python scripts/benchmark_open_http.py --output before-or-after.json
python scripts/benchmark_open_http.py --arrival-rate 48 --nodes 1 --output paced.json
python -m unittest -v tests.test_open_read_concurrency
```

The base bundle permits offline cloning of exact main and alpha36/alpha37 history. Apply `capacity.patch` in that main clone; new source files are included by the patch. `delivery-manifest.json` records SHA256 for all changed sources and evidence. The old dirty Mac checkout and separate unmerged alpha39 worktree remain intact.

Model selection was explicitly submitted and accepted for this same task using `gpt-6.1-sol` with high reasoning. The execution API does not return actual inference-model metadata, so independent runtime confirmation of the selected model is unavailable; no different model was silently selected.
