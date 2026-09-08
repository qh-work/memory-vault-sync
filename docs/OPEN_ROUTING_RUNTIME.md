# Open routing foundation: implementation and validation boundary

This is the first executable part of the approved
[open architecture](OPEN_NETWORK_ARCHITECTURE.md), not completion of the
0.28 end-to-end network. It removes the common authority and roster from this
**explicit open contact-discovery profile**. The published private preview
and the existing `network-v1` message implementation remain available.

## What runs

`memory_vault_open_node.py` and native `clients/typescript/network/open-node.ts`
run independently configured HTTP processes.
An ordinary `OpenParticipant` needs its existing Ed25519 identity, its protected
transport-state directory and at most two signed introductions. A client does
not need to run a server. It finds another owner's signed contact using
`contact_key(owner_key_id)`, not a global member list or a shared relay pool.

Each newly introduced destination must answer its own random, signed request.
The outbound client checks DNS results, pins the selected connection address,
keeps TLS hostname verification, refuses redirects/proxy credentials and
rejects private destinations. Loopback HTTP is only allowed by explicit local
test policy. Signed advertisements prove control of a signing key, not a
human identity, honest behaviour, X25519 live possession or resource access.

The routing kernel uses two fixed views, XOR byte coordinates, at most 256
buckets per view with eight active and two replacement entries, and two peers
per observed IPv4 /24 or IPv6 /48 source group in a bucket. A router without a
directory role has at most four directory introductions. A lookup uses at most
32 candidates, 64 RPCs, three concurrent RPCs and a ten-second deadline, shared
across stages. Its two introduction lanes share results without duplicate
requests. Request bytes and response bytes are reported separately: each is
bounded by 64 times 64 KiB; this is not a claim of 4 MiB combined traffic.
Find responses can introduce live, previously challenge-verified replacements,
as well as active peers, while retaining eight descriptors and two peers per
bucket/source group. The recipient independently challenges every returned
endpoint. This does not evict stable active neighbors. Exploratory find probes
can refresh or fill replacement slots, but cannot churn a full replacement
list; direct hello probes can rotate it. Expiry or two failed probes remove a
replacement just as they remove an active peer.
OS DNS work uses at most three outstanding resolutions; a hung resolution can occupy a slot
but cannot create an unbounded queue or extend the caller's deadline.

Node maintenance takes at most two pending endpoint challenges, up to two
self-announcements rotating over the eight verified peers nearest its own
coordinate, then one bounded routing lookup, under a shared 16-RPC, 1 MiB
response, five-second budget. A full
32-entry introduction queue returns signed retryable backpressure without
discarding earlier pending nodes; later self-announcements allow retry.
An unchanged, still-valid descriptor already retained from an independent
successful challenge does not reenter that queue. This prevents repeated
proven neighbours from consuming all pending capacity ahead of new endpoints.
The inbound advertisement neither renews endpoint proof nor clears probe
failures; a changed descriptor or a previously failed probe still needs a new
challenge, as does a peer absent from the bounded routing table.
A verified, correctly bound hello error still proves that seed's endpoint and
can populate the caller's bounded routing table. The error remains an admission
failure; it does not put the rejected advertisement in the receiver's queue.
This lets a node start discovery even when its first announcement is refused.
Every fourth maintenance lookup refreshes the node's own coordinate; the other
three retain the independent deterministic random targets. This uses the same
single lookup and shared allowance, not an extra refresh RPC budget. Random
global lookups alone can miss a small local region after new neighbours become
discoverable, leaving announcements tied to old introductions. Periodic local
refresh gives later announcements fresh, independently verified neighbours.
Self-announcements
use the node's own region to help nearby routers introduce it during a lookup;
every receiving peer still challenges the endpoint.
The HTTP node runs that work independently from agent sessions. Incoming
connections, request rates, headers, bodies and total connection time are
bounded. This is resource containment, not an Internet DDoS certification.

Directory service is **closed by default**. An operator explicitly enables a
finite local quota. Only the contact owner can put/renew its contact. Public
entries contain typed opt-in contact metadata, not Memory IDs, message text,
private grants or mailbox relationships. Three distinct accepted leases are
the desired index replication count. Fewer are reported as degraded;
aliases of the same responding socket do not increase the count. Even three
confirmations do not establish three physical fault domains.
The owner can propagate its own signed contact revocation through
`publish_contact` after the local checkpoint records it. Only the expected
revocation refusal is handled for that propagation; foreign ownership,
rollback, conflict and storage failures still stop the operation. A lease
acknowledging withdrawal does not claim that the contact is publicly available.

## Storage and interfaces

Python and native TypeScript use the existing protected `network.sqlite3` mechanism. The
`open_*` tables hold routing/control checkpoints, a bounded restart cache,
contact leases and replay responses; they are not a second memory store.
Signed revision, revocation and same-revision conflict floors survive normal
restart. A conflict is not resolved by picking an arrival order or a larger
hash. Security floors are reserved separately from expendable routing caches;
full capacity causes an explicit refusal. See [the control contract](OPEN_CONTROL_V1.md).
When the configured seed, routing table and restart cache contain different
signed revisions of one key, initial lookup selects the newest known revision
while retaining the seed's bounded probe position. This does not grant endpoint
proof or bypass the persistent revision/conflict floor; the selected descriptor
must still answer a fresh challenge.

The official Python Agent/HTTP/MCP entry points and native TypeScript Agent keep
the six operations.
An explicitly selected `memory-vault-open-client-config/v1` config uses
`connect` to discover reachable peers and
`discover(online=true, key_id="ed25519_…")` for a known owner's contact.
`remember` and `recall` remain local. A key selector without `online=true`
is rejected. Private-profile targeted discovery is explicitly unsupported.

Open `send`, `receive`, message reads and private invitations currently return
explicit unsupported errors. They do not silently enter the private profile,
construct an empty roster, send plaintext or grant permission. Native
TypeScript reuses its independent control/routing/state kernels through
`OpenParticipant`, `OpenHTTPTransport`, `OpenNetworkClient` and a standalone
HTTP node. Both profiles share client-config validation and the existing
protected transport schema initializer. Open code never opens the Vault.
Node uses built-in HTTP/TLS/DNS/SQLite/crypto and the existing locked JOSE
dependency; it never invokes Python to implement a protocol operation.
See [native API and validation](NATIVE_OPEN_HTTP.md).

## Running a node

Use an existing authorized signing identity and a signed node descriptor from
`issue_node`. Keep the explicit configuration private (mode 0600). Its exact
fields are `schema_version` (`memory-vault-open-node-config/v1`),
`identity_path`, `state_directory`, `node`, `seeds`, `allow_loopback`,
`index_policy`, `listen_host`, and `listen_port`. A typical index policy is
`{"enabled": true, "maximum_records": 128}`; omission of `enabled` is closed.
The built-in listener is restricted to `127.0.0.1` on a nonprivileged port.
An operator serving public peers must provide HTTPS termination separately.

```sh
python memory_vault_open_node.py --config /absolute/private/open-node.json
node --experimental-strip-types clients/typescript/network/open-node.ts --config /absolute/private/open-node.json
```

No Docker, new dependencies, service installation, public server or paid
resources are required for the local synthetic tests. This command does not
generate identities or reconfigure an existing Vault.

## Reproducible checks and remaining gates

The test names below identify executable synthetic evidence, not real agents:

```sh
python -m unittest tests.test_open_control tests.test_open_index tests.test_open_state
python -m unittest tests.test_open_transport tests.test_open_node tests.test_open_agent
python -m unittest tests.test_open_routing tests.test_open_join_progress tests.test_open_typescript
python -m unittest tests.test_open_typescript_state tests.test_open_typescript_http tests.test_open_network_ci
```

Use the repository's locked network dependencies and Node runtime for native
TypeScript tests. The eight-process test supplies each node at most two
introductions. A cold A receives only its identity, two introductions and B's
key, finds a contact stored solely on the last node, then restarts after both
original introductions stop. It checks actual response-parent paths; it does
not preload routing tables. All local processes share one machine and one
observed source group. No source-diversity check is bypassed.

The 100-node runner is a **routing-kernel** experiment using actual signatures
and production lookup code. Its transport is synthetic and it does not measure
HTTP, SQLite, machine throughput, NAT, real model continuation or physical
fault domains. Its finite local tables are populated by introductions and
maintenance, not an omniscient nearest-node oracle. Raw failures belong in the
denominator. The 17/29/43 runs must report their actual outcomes before any
99%/97% reachability gate is called passed. An earlier stronger maintenance
schedule was cancelled and is not acceptance evidence.
The open-network CI jobs check out the exact PR head SHA and record the checked
out commit plus source hashes before running tests.
The v2 synthetic report also records bounded, passive diagnostics: table and
pending membership as synthetic node indices, actual returned indices and
causal paths for the first failure of at most eight distinct targets per phase.
All failures still remain in the full denominator. These observations never
add routes or make requests. The report validator rejects arbitrary payloads,
descriptors, keys, addresses and extra fields; the combined report byte limit
remains below 1 MiB. The child serializes compact JSON so indentation cannot
exhaust its output cap while preserving every failure and bounded sample.
Diagnostics themselves change no production routing policy or acceptance
budget. The current report explicitly records the periodic own-coordinate
schedule separately from the unchanged numeric maintenance limits.

Still outstanding: automatic signed
descriptor renewal/address changes beyond the current descriptor lifetime;
open first contact and recipient consent; encrypted mailboxes and receipts;
enumeration plus ciphertext leases and node-to-node repair; hostile-overlay
and independent growth-axis tests; 250/500/1,000-node runs and real multi-model
acceptance. An expired descriptor stops being usable; this slice must not be
advertised as unattended perpetual operation or global scale certification.

## Routing preview evidence: 0.28.0-alpha.0

The functional source is `dc485334f8ad8629db68ef25c7c618a732f15c6c`.
[Three-seed cloud run 34191451681](https://github.com/qh-work/memory-vault-sync/actions/runs/34191451681)
completed with the original 100-node, 20-cycle profile and predetermined
1,000 queries per phase. All recorded source hashes matched that commit.

| Seed | Healthy successes / queries | Bootstrap-exit successes / queries | Original 99% / 97% gates |
| --- | --- | --- | --- |
| 17 | 1,000 / 1,000 | 1,000 / 1,000 | PASS |
| 29 | 1,000 / 1,000 | 1,000 / 1,000 | PASS |
| 43 | 1,000 / 1,000 | 1,000 / 1,000 | PASS |

Each seed is evaluated independently; unsuccessful queries remain in the
denominator. Here all six full failure lists are empty. The report explicitly
records `own_coordinate_every_fourth_cycle_otherwise_random`; the schedule
changed while numeric budgets remained unchanged. The bootstrap-exit phase
inherits the healthy phase's learning; it is not an independently reset network.
The experiment uses real Ed25519 with `in_process_signed_control`,
`actual_http=false`, `checkpoints=false` and `ai_instances=0`. It measures the
routing kernel, not 100-node HTTP/SQLite or independent physical fault domains.
A faster job duration is not a controlled performance comparison.

[Light cloud run 34191411538](https://github.com/qh-work/memory-vault-sync/actions/runs/34191411538)
passed 84 distinct methods with zero failures, errors or skips, including real
native TypeScript vectors. Method counts do not include repeated subtest
events. [Protocol CI 34191411486](https://github.com/qh-work/memory-vault-sync/actions/runs/34191411486)
passed on Linux, macOS and Windows. These are separate from 50 selected local
methods and a bounded independent implementation review; counts are not added
together as distinct coverage. The local near-neighbour regression uses direct
signed participant calls, not sockets: 121 setup hellos establish three rows;
four maintenance cycles discover a neighbour, followed by later advertisement,
independent challenge and third-party lookup.

Complete public scale artifacts and their downloaded ZIP SHA-256 values:

| Seed | Artifact ID | SHA-256 |
| --- | --- | --- |
| 17 | 10042662646 | e5a0e8b09b4be03cd511d9ca2f4c27f277452613d71ba59c9690b7c22a7097e9 |
| 29 | 10042565658 | b35324bf3e64c3da85c1e00d1c9653538d87c8ddfcb3dc70aeb42072ff40f902 |
| 43 | 10042654978 | 822265de7271915d94ac795b3292185e3eee19dac598baf1ffc8b1b312e9bce2 |

The light artifact is 10042384060, SHA-256
`8c3d53ff5bb52a2dafca17dcb5c04ebb17b781dae48a192b65861c232337fa5d`.
Each artifact contains complete settings, status, progress, errors and results.
A checksum identifies supplied bytes; it is not a publisher signature or
independent runner attestation.

Earlier results remain failed evidence. On both `f3de510` and `52a233a`,
seeds 17/29/43 respectively returned 997/997, 1000/1000 and 983/986 healthy/exit
successes per 1,000. Seed43 failed the healthy gate; its diagnostic traces led
to the own-region refresh repair. Those runs are not relabelled as passes.
The `0.28.0-alpha.0` package identifies its own source commit and limited
packaging checks; this functional experiment remains pinned to `dc48533`.
It does not complete the `0.28.0-alpha.1` consent, encrypted delivery and repair
milestone or establish unbounded/global reliability.

## Upgrade and rollback

This is an explicit development profile. Do not point it at a private-profile
transport directory or a Vault directory. Existing bindings are checked, not
rewritten. Existing Memory records, IDs, canonical bytes, signatures, private
network keys/configuration and historical releases are unchanged. No old data
migration is required for local memory use. To stop this experiment, stop its
own configured node process and select the prior private configuration; retain
the experiment's control state for review. Do not delete a Vault or reuse a
stale control backup as fresh permission.
