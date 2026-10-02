# MemoryVault bounded capacity and native replica handoff

This working change is based on the **alpha.0.39 branch**, commit
`3df5cf8e58c94c0c2f703d574321f3c2561ffcec`, including its native mailbox sender
and earlier authorization work. Fresh remote checks found main at
`c840617eb50e8856695234b482fed5560c0c72bf` and published alpha.0.37 at
`fe943c6466a6ef459ccb0d03e309b207b3b0fb95`. Alpha.0.39 is a branch, not a published
tag. Alpha.0.40 integrates this work through normal source checks and repository CI.
The earlier Library v4 migration remains an exact uncommitted historical snapshot.

## Changes

- Eight fixed Python HTTP workers, queue of 16, bounded retryable busy refusal,
  and queue time inside the three-second input deadline. Execution quota is unchanged.
- Existing transport DB bindings no longer require a writer transaction. WAL
  index reads use deferred transactions and logical expiry; writes reclaim expiry.
  Binding, signature and revocation checks remain active.
- Bounded public neighbor rotation: at most three find attempts and one fresh
  possession proof per five seconds. Empty replies do not consume that allowance.
- Python and native TypeScript atomically freeze new envelopes against separately
  approved resources. Exact signed lease hashes, unfinished uploads, and item/byte
  reservations prevent aliasing and overspend. Receive polling uses a persistent
  bounded cursor. Already frozen sends retain their original bytes and endpoint.
- Native **message replica** recovery independently verifies complete historical
  COPY closure and current READ authority, performs possession and exact bounded
  body reads, imports Memory, and reopens saved inbox evidence locally. Explicit
  registrations share Python's protected SQLite format. Authentic revocations
  survive later invalid input, selection removal and restart.

No global member list or unique admission/grant issuer is introduced. Independent
resources require actual applicable consent. Discovery grants no COPY/READ rights.

## Fresh alpha.0.39 comparison

Apple M1, eight cores, 8 GiB, macOS 27.2 (26B5091g); Python 3.12.0b4, SQLite
3.42.0, cryptography 50.0.1, Node 22.19.0, locked jose 6.2.10. Two loopback node
processes share one physical host and SSD. Native Agent subprocess delegation is
disabled and observed at zero calls. No model API is used.

After regressions finished, runs were measured sequentially with the same adapter:
**48 distinct selected Memories at 2/s for 24 seconds**, one pipeline worker and
the same finite drain allowance. R0 and R1 each receive independent approval for
24 items / 2 MiB. R1 starts at offer 12 (six seconds); clients initially know R0.
Join attempts and scheduled-offer waiting count. Success requires encrypted
storage, receive/decrypt/import, signed saved receipt, local read and Memory recall.

| Same 48 offers | Clean alpha.0.39 | Current working runtime |
| --- | ---: | ---: |
| Complete chains | 39 | 48 |
| Error rate | 18.75% | 0% |
| Complete chains/s, including drain | 1.6248 | 1.9991 |
| Successful p95 / p99, ms | 345.69 / 403.54 | 365.48 / 386.70 |
| R0 / R1 complete chains | 15 / 24 | 24 / 24 |
| R1 approval usable, seconds | 7.376 | 7.263 |

The baseline fills R1 and incurs nine quota errors while nine R0 slots remain
unused. The change uses all 24+24 separately approved slots. Both runs retain
one failed R1 contact attempt followed by success, with no HTTP admission/queue
refusal. The single-trial p95 increased; the p99 difference is not a statistically
established gain. This proves effective authorized capacity use, not a higher CPU,
SQLite or disk throughput ceiling. The unchanged source-rate cap is not reached.
All measured source hashes match the delivered source.

Public release evidence is in [before](evidence/capacity-alpha40/before.json),
[after](evidence/capacity-alpha40/after.json) and
[native replica](evidence/capacity-alpha40/native-replica.json). The earlier migration
summary additionally retains all working-source hashes. Earlier HTTP,
routing and Python/native results remain verbatim inside
`history/capacity-development-v3.zip`; they are not relabeled as fresh .39 runs.

## Original-source loss and finite old demand

A native send freezes a 7059-byte synthetic ciphertext. Separate owner, sender,
source and maintainer COPY/READ/return consents fund a real Python replica HTTP
service. A committed upload reply is deliberately lost. Restart/retry recovers
one committed identity. The original source is closed before native reception.

The native recipient checks the complete original proof, expected keys/epochs,
exact message/resource identity and current permissions, then reads the original
ciphertext and imports Memory once. Local saved read/recall uses zero HTTP calls.
The separately approved existing ACK workflow confirms the original native send;
saved replay uses zero HTTP. Wrong target epoch is refused before repair HTTP.
Owner READ revocation survives removal/restart and rejects retry before repair HTTP.

Three further empty private Vaults request this explicitly selected **known
message with the same owner permission**. They are not different owners or physical
failure domains; no unknown future ID is injected into a pre-message recipient.

| Additional demand | Completed | Repair HTTP calls | Durable COPY work | Elapsed, ms |
| --- | ---: | ---: | --- | ---: |
| Empty Vault 1 | 1 | 12 | 46 → 58 | 17902.78 |
| Empty Vault 2 | 0 | 7 | 58 → 64 | 9330.42 |
| Empty Vault 3 | 0 | 1 | 64 → 64 | 577.47 |

Earlier upload and proof checks consume that same persistent account. Its
existing 64-request ceiling includes child and body reads and is preserved.
The latter demands return `open_request_rejected`; observed server diagnostics
identify `repair_copy_work_capacity`. These failures are retained. A separate timing-only trial confirms CPU cost in full historical COPY/current
READ preparation: the successful cold read uses 12 requests and 13.55 seconds of
server-thread CPU in that layer. Across all 20 attempted requests, preparation
uses 20.31 CPU seconds / 20.36 wall seconds. HTTP packing and native client CPU
are excluded. See [the profile](evidence/capacity-alpha40/replica-profile.json).
This is an explicit experimental-alpha limitation: first recovery finishes within
the existing 60-second deadline and saved reads are local, but hot recovery at
scale is not established. The 64-request boundary is the original consented work
account; further demand needs independent funding, not a reset or relaxed check.

Current local validation passes **63 targeted cases**: 60 HTTP/WAL/routing/
distribution/packaging regressions and three native/Python replica cases. The
native proof fixture rejects six independently altered expected contexts. Earlier
integration logs preserve original mailbox/status regression results. Full cross-platform CI and all open-network partitions must pass on the candidate
commit before release; their authoritative results are linked by the release record.

## Migration restore and reproduce

Delivery contains an explicit source allowlist, complete baseline Git bundle,
uncommitted patch, hashes and synthetic evidence. Dependencies, private test
identities, credentials, sensitive environment files and real Vault data are
excluded. Unmanaged `memory_vault_network 2.py` and `memory_vault_open_node 2.py`
remain on the Mac and are excluded. Original Mac checkouts are retained.

```sh
git clone baseline.bundle memory-vault
cd memory-vault
git checkout --detach 3df5cf8e58c94c0c2f703d574321f3c2561ffcec
git apply ../capacity.patch
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cd clients/typescript/network
npm ci --ignore-scripts
cd ../../..
.venv/bin/python -m unittest tests.test_open_read_concurrency tests.test_open_neighbors tests.test_open_index tests.test_open_state tests.test_open_node tests.test_open_delivery_distribution tests.test_open_delivery_distribution_typescript tests.test_network_packaging tests.test_open_network_ci tests.test_capacity_replica_closure tests.test_open_mailbox_replica_typescript -v
.venv/bin/python scripts/benchmark_open_delivery.py --runtime native --messages 48 --rate 2 --join-after 12 --output after.json
```

Use existing Node >=22.19; `MEMORY_VAULT_NODE` may select it. The tests/adapter
accept `MEMORY_VAULT_JOSE_MODULE` for an existing locked jose distribution.
Dependency installation needs an approved source. For comparison, restore a
second baseline checkout and copy only the three files in `baseline-adapters.json`;
leave production code unchanged. Measure separately from regressions.

## Remaining work

- Frozen-message recovery requires retained original COPY/READ and independent
  return authority. It is not automatic universal replication, authority renewal,
  silent frozen-send relocation or an unlimited backlog.
- This native verifier covers message replicas. Native ACK, root and whole-feed
  replica clients remain separate work.
- Further old demand needs independently funded targets. Restart cannot reset
  quota. Profiling/caching must preserve exact immutable context, current status,
  revocation floors, epochs and transaction snapshots.
- Next: bounded higher-rate sweep, first-contact/SQLite/CPU attribution, a second
  independently consented old-message replica, and independent hosts/WAN. A local
  trial is not a maximum supported-agent count or global reliability result.
- No paid API, real model, host deployment or real grant/trust changes are needed.
  Repository publication follows the authorized normal CI/merge/release workflow.
  Existing gpt-6.1-sol/high task settings were accepted earlier; tools do not expose
  independently verifiable actual inference model metadata.
