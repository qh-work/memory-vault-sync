# Memory Vault v0.28.0-alpha.0.2 — explicit first-contact candidate

This candidate extends native Python/TypeScript open routing with fixed
first-contact requests, explicit approval/rejection and verifiable finite
resource authorization. It requires no common authority, global roster or
shared relay pool. At candidate preparation, 6 Pro review, cloud CI, final
archive checks and publication were pending; no final test count is declared
here. Use release evidence for the exact source commit for the final status,
and verify the release manifest and downloaded hashes against that source.

## New capability

- B explicitly acquires a finite knock lease and signs opt-in before going
  offline. A created afterward, with no B delivery grant, discovers the signed
  endpoint through bounded routing and proves possession of both signing and
  encryption keys with the existing real JWE primitives.
- The first request has fixed fields and no free text, callback, attachment or
  arbitrary ciphertext. R transactionally reserves the request, eventual result
  and replay state; a queued request is not a delivered message or approval.
- B polls and explicitly approves or rejects. Approval requires a real finite
  delivery reservation, exclusively bound to that request. A pulls and verifies
  B's decision against the original request, both parties, node/epoch, concrete
  resource, operation and expiry. A rejection has no grant.
- Local client records reserve future result and decision/allocation space before
  remote obligations are created. Exact retries and Python/TypeScript restarts
  reuse the same protected database. Admission limits preserve bounded result
  challenge capacity and separate submit/result encryption slots.
- The existing six-operation facade gains explicit first-contact controls under
  `connect`; ordinary join, local Memory operations and original record bytes,
  IDs, signatures and provenance remain intact. No grant creates author trust,
  Vault access or model execution. See [the exact candidate contract](../docs/OPEN_FIRST_CONTACT_V1.md).

## Retained routing and native HTTP baseline

- An explicitly configured Python or native TypeScript client joins from at most two signed
  introductions and discovers an owner's signed contact through actual
  response-derived routing steps. An ordinary client need not run a server.
- Independently configured Python and native TypeScript HTTP nodes use bounded two-view routing,
  verified replacement introductions and finite, opt-in contact index leases.
  Directory service is closed by default. A signature or introduction grants
  no memory access, mailbox permission or execution authority.
- Durable control state preserves revision, revocation and conflict floors.
  Rejoining selects the newest known signed seed revision before a fresh
  endpoint challenge. An owner can propagate its own signed withdrawal.
- Late joins retain progress when introduction queues are full. Exact live
  peers already proven by challenge do not refill pending capacity; changed,
  unknown or failed peers still require independent challenges. Every fourth
  maintenance lookup refreshes the owner's own region under the same numeric
  budget, so later announcements can reach newly discoverable neighbours.
- Native TypeScript supplies constrained outbound HTTP, finite node admission,
  native participant orchestration and open Agent dispatch. Python and TypeScript
  reuse the same client configuration, signing identity, protected transport DB
  and control/index tables. No Python subprocess implements the native path.
- Small real-HTTP tests cover bidirectional publication/discovery, seven mixed
  nodes plus one native client, cold causal multi-hop lookup, original bootstrap exit, endpoint restart
  and a directory reopened by the other language. They use synthetic loopback
  processes, not real AI or independent physical fault domains.

Open `send`, `receive` and message reads return explicit unsupported errors.
The retained private profile continues to provide authorized encrypted relay
exchange. Its issuer, roster and common pool are not dependencies of the open
contact-discovery profile. See [open setup and limits](../docs/OPEN_ROUTING_RUNTIME.md).

## Candidate verification and historical evidence

The first-contact suites exercise strict schemas and binding, actual dual-key
JWE, transactional capacity/rollback, local result reservations, explicit
decisions and native/Python HTTP and SQLite restarts. Match their actual execution
to the candidate source; test presence is not a pass. No new scale experiment,
real-model continuation, cross-region run or complete delivery claim is made.

The prior native HTTP preview **0.28.0-alpha.0.1** is pinned to
`0ddf0c5ac6aa8d12562c1df2a26ee25aeb851ed3`. Its native HTTP suite,
`tests.test_open_typescript_http`, review, CI and downloaded assets retain that
historical scope and do not certify the current first-contact candidate.

Earlier routing functional source: `dc485334f8ad8629db68ef25c7c618a732f15c6c`.
The [three-seed cloud experiment](https://github.com/qh-work/memory-vault-sync/actions/runs/34191451681)
passed the original 99% healthy and 97% bootstrap-exit gates independently:
seeds17/29/43 each returned 1,000/1,000 in both phases. Every seed uses 100
logical nodes, 20 maintenance cycles and predetermined queries; full failures
remain in the denominator. The new maintenance schedule is explicit in reports.

The [84-method open CI](https://github.com/qh-work/memory-vault-sync/actions/runs/34191411538)
and [three-platform protocol CI](https://github.com/qh-work/memory-vault-sync/actions/runs/34191411486)
passed. Actual commands, source hashes, original artifact digests, previous
failed runs and interpretation limits are recorded in
[the runtime evidence](../docs/OPEN_ROUTING_RUNTIME.md). Packaging-only source
changes do not turn this into a new execution on the release commit.

The scale experiment uses real Ed25519 and logical in-process transport:
`actual_http=false`, `checkpoints=false`, `ai_instances=0`. Bootstrap exit
inherits the healthy phase's learned state. It does not test 100 HTTP nodes,
SQLite throughput, physical fault domains, real-model continuation or global
reliability. Small real HTTP regressions and local signed-call counterexamples
are separate evidence. Earlier scale failures are preserved, not relabelled.

## Matching artifacts and retained data

- `memory-vault-protocol-v0.28.0-alpha.0.2.zip`: specification, structural schemas
  and synthetic vectors, with no executable code.
- `memory-vault-client-v0.28.0-alpha.0.2.zip`: source-built runtime, plugin and
  local marketplace catalog.
- `memory-vault-review-v0.28.0-alpha.0.2.zip`: public source and synthetic tests.
- `memory-vault-network-test-v0.28.0-alpha.0.2.zip`: retained private-profile
  synthetic endpoint template; service trust is unconfigured and requires
  operator provisioning. It is not an open-network delivery demo.
- `memory_vault.py`, `PROTOCOL.md`, `release-manifest.json`, `SHA256SUMS`:
  standalone core/agreement and exact artifact inventories. The complete
  runtime requires companion modules; checksums are not publisher signatures.

One model-neutral Vault retains the six operations and original record IDs,
canonical bytes and source signatures. Open transport checkpoints are not a
second memory store. Existing dependencies and encryption profiles are retained.
No private installation, configuration, Vault, key, invitation, hooks, public
service or paid resources are changed by extracting this release. Preserve old
runtime and private backups; automatic migration is not provided. Never reuse
a stale control backup as fresh permission.

Candidate-preparation review, CI and publication status is recorded above;
final outcomes require exact-source release evidence. Remaining implementation:
automatic signed descriptor renewal/address changes, encrypted mailboxes and
receipts, finite ciphertext leases and sender-independent replica repair,
hostile-overlay and larger independent growth-axis experiments, and actual
multi-model/cross-region acceptance. An expired descriptor is unusable; this
preview is not unattended perpetual operation or unlimited capacity.

Apache-2.0; previously published releases remain separate; this release does not overwrite their bytes.
