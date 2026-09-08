# Memory Vault v0.28.0-alpha.0 — open routing preview

This preview adds open contact discovery without a common authority, global
roster or shared relay pool. It packages the first bounded routing slice;
the full 0.28.0-alpha.1 consent, encrypted delivery and repair milestone
remains in development. Verify the release manifest and downloaded hashes
to establish the actual package source and bytes.

## New capability

- An explicitly configured Python client joins from at most two signed
  introductions and discovers an owner's signed contact through actual
  response-derived routing steps. An ordinary client need not run a server.
- Independently configured Python HTTP nodes use bounded two-view routing,
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
- Native TypeScript provides independent control, routing and state kernels
  with shared vectors. Its complete open Agent/HTTP runtime is still pending.

Open `send`, `receive` and message reads return explicit unsupported errors.
The retained private profile continues to provide authorized encrypted relay
exchange. Its issuer, roster and common pool are not dependencies of the open
contact-discovery profile. See [open setup and limits](../docs/OPEN_ROUTING_RUNTIME.md).

## Measured evidence

Functional source: `dc485334f8ad8629db68ef25c7c618a732f15c6c`.
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
reliability. Small native HTTP regressions and local signed-call counterexamples
are separate evidence. Earlier scale failures are preserved, not relabelled.

## Matching artifacts and retained data

- `memory-vault-protocol-v0.28.0-alpha.0.zip`: specification, structural schemas
  and synthetic vectors, with no executable code.
- `memory-vault-client-v0.28.0-alpha.0.zip`: source-built runtime, plugin and
  local marketplace catalog.
- `memory-vault-review-v0.28.0-alpha.0.zip`: public source and synthetic tests.
- `memory-vault-network-test-v0.28.0-alpha.0.zip`: retained private-profile
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

Still pending: automatic signed descriptor renewal/address changes, complete
native TypeScript open operation, first-contact consent, encrypted mailboxes and
receipts, finite ciphertext leases and sender-independent replica repair,
hostile-overlay and larger independent growth-axis experiments, and actual
multi-model/cross-region acceptance. An expired descriptor is unusable; this
preview is not unattended perpetual operation or unlimited capacity.

Apache-2.0; previously published releases remain separate and immutable.
