# Memory Vault v0.27.0-alpha.1 — signed relay pools

This bounded private-network preview extends the published alpha.5 baseline,
main `608d54578b9ce30f10fe450ad651f1cd8620a2e7`. A source declaration does not
establish publication or installation; verify the actual release manifest
and downloaded asset hashes.

## New network capability

- Opt into `relay_pool` in the existing endpoint configuration. A fresh,
  independently verified issuer-signed directory supplies a common bounded
  candidate set, even when endpoints start from different bootstrap URLs.
- Admit each endpoint on candidate relays through the existing dual-key
  invitation ceremony. A directory entry does not grant relay membership,
  memory access, decryption rights or execution permissions.
- Choose up to four candidates and request one or two storage confirmations.
  Sending tries other permitted candidates when one fails; receiving polls
  the common bounded pool. Results distinguish pool size, replica target and
  actual storage acknowledgements.
- Preserve frozen ciphertext, explicit per-node acknowledgements, cursors,
  deduplication and recovery. Old receipts remain historical evidence and do
  not prove live availability. Local memory and accepted-batch reads remain
  independent of discovery or authority availability.
- Without the explicit local opt-in, endpoints retain their fixed one or two
  relay addresses. Recovery does not silently opt into new connectivity.

See [relay-pool semantics, setup and measured verification](../docs/RELAY_POOL.md)
and the [operator quickstart](../docs/NETWORK_QUICKSTART.md).

## Retained memory and experience capabilities

The six operations remain `connect`, `remember`, `recall`, `discover`, `send`
and `receive`. Chat and transfer notes do not create long-term memory.
Separately authorized Hint v4 queries, frozen pages, explicit one-to-four-root
transfers, cancellation and local accepted-batch recall retain their semantics.
Experience views distinguish original observation, independent experiments,
hearsay and counterevidence; propagation is not independent verification.

No second memory database, identity system, content profile or encryption
profile is introduced. Existing record IDs, canonical bytes and Ed25519
source signatures are unchanged. X25519/JWE and outer signatures remain
inside network-v1. The existing MCP memory interface is retained; no new
MCP, A2A, Matrix, Nostr or Graphiti adapter or compatibility claim is added.

## Artifacts and safe upgrades

- `memory-vault-protocol-v0.27.0-alpha.1.zip`: specification, structural schemas
  and synthetic vectors, with no executable code.
- `memory-vault-client-v0.27.0-alpha.1.zip`: complete source-built runtime,
  plugin and local marketplace catalog.
- `memory-vault-review-v0.27.0-alpha.1.zip`: public source and synthetic tests;
  no automatic execution.
- `memory-vault-network-test-v0.27.0-alpha.1.zip`: isolated endpoint template,
  without Docker or a plugin. Service trust is unconfigured; an operator must
  provision reviewed service pins and a one-time code before use.
- `memory_vault.py`, `PROTOCOL.md`, `release-manifest.json`, `SHA256SUMS`:
  standalone core/agreement and exact artifact inventories. The full runtime
  requires its companion modules. Checksums are not publisher signatures.

Dependencies retain the separate existing client/server hash locks. Local
unsigned memory still has a standard-library path. Nothing in this release
replaces a private installation, reads private memory, activates hooks, starts
an agent, operates a public service or procures resources.

Preserve the old runtime, configuration, queues and backups before explicit
installation. Current content/v2 and Hint v4 controls reject older preview
forms; no automatic content/v1 migration is supplied. An old client may reject
expanded transport receipt maps. Keep the matching runtime or a pre-upgrade
backup instead of rewriting evidence to force an older reader to accept it.

## Verification and remaining limits

The final targeted developer run passed 74 distinct methods in 185.310 seconds,
with unchanged source/test hashes and no failures, errors or skips. Exact
commands and scope are in [RELAY_POOL.md](../docs/RELAY_POOL.md). Historical alpha.5, Experience and
v0.25 reports retain their original source pins and do not certify this build.
Source tests, independent 6 Pro review, required CI, final archive privacy,
publication and private installation are separate checks.

The authority still has a single configured address. The pool is a common
mailbox set, not a global router or relay-to-relay replication system. Member,
queue, ciphertext and retry budgets remain finite. This preview does not
complete the planned 24-hour endurance test, 1,000-active-agent/72-hour gate,
real-model or cross-machine acceptance. Local HTTP process failures are not
physical failure-domain tests. There is no open P2P, DHT, group gossip, global
consensus, automatic shard expansion, unlimited capacity or production-security
certification. Those require later bounded development and independent evidence.

Apache-2.0; existing releases and private backups remain separate.
