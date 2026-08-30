# Changelog

## 0.24.1 — Full authorized client alongside the lightweight protocol

- Corrected the v0.24.0 thin-client gap: added durable coalesced sync work,
  bounded event-triggered workers, offline retry, directory/rclone remote
  backends and content-free sync receipts. Local save/recall never waits for
  remote delivery; automatic sync is an independent operator opt-in.
- Added Claude Code, Gemini CLI and generic visible-event adapters around the
  shared lifecycle. Session correlation never becomes memory ownership.
- Added read-only diagnosis, consistent snapshot backup, restore to a new Vault
  with fresh delivery identity/current trust, compressed resumable file packs,
  and explicit release staging without installation or activation.
- Added a best-effort publication secret/path guard without restricting local
  persistence or turning the lightweight protocol into an installation format.
- Published an AI implementer start page, machine-readable discovery document,
  two-mode/capability maps and bounded independent review tasks.
- Kept one canonical protocol/core and independent signing/trust. No old
  Task/Git runtime, hidden transcripts, live private migration or key/policy
  auto-enrollment is restored. v0.24.0 release assets remain immutable.
- **No runtime tests, host installation or performance benchmarks were run.**
  Source syntax, public JSON, packaging and inventories were reviewed instead;
  independent executed verification remains required before production use.

## 0.24.0 — One protocol, two equal usage paths

- Made the language- and storage-independent protocol and the authorized plugin
  equal entry points, with shared immutable records and exchange rules.
- Added public JSON Schemas, synthetic portable records and canonical hash
  examples so another implementation does not need the Python runtime.
- Added an optional local session/turn lifecycle profile over the current core,
  configured protocol/bundle access, and a shared default Vault path.
- Distribute a protocol-only archive and a complete plugin archive with runtime
  inventory, a local marketplace catalog and checksums. Obtaining a package
  neither installs it nor enables hooks or migrates real data.
- Publication uses its own tag without changing protected-main requirements.
  Tests and real-host trials were not run; this is not production certification.

### Included shared-core integration work

- Kept the standalone standard-library core and taskless canonical record model;
  added optional client, trust, directory-transfer and offline-migration modules.
- Added eight stdio MCP tools and an opt-in Codex hook package that shares the
  same Vault. Capture reads documented visible event fields only; no transcripts,
  network prompt path, installation, hook self-trust or background daemon.
- Added optional PyCA Ed25519 record/message signatures, separate key enrollment
  and revocation, and read-time trust checks. Signing does not prove truth,
  original author identity, or execution permission. POSIX protected-key storage
  only; native Windows signing/ACL support remains open.
- Added SQLite v2 admission metadata, unsigned-import quarantine and
  trust-aware correction/handoff. V1 upgrades are additive and write-triggered;
  reads neither create nor migrate databases. Canonical records stay immutable.
- Changed direct `observe` provenance to caller-reported; only an explicitly
  configured local host adapter can label event fields host-visible.
- Added a bounded incremental feed with relation closure, explicit blocked
  dispositions and requeue. Added signed per-store batches, durable sender
  pending bytes, receiver receipts, replay checks and signed-fork detection.
- Added a one-way converter for the documented v0.21 export-network ZIP schemas,
  output mapping/loss reports and dry-run support. No live old-plugin, Task or
  Git state is imported. Logical export/delta order preserves local ingest order;
  migration uses dependency-first, preserved-time ordering.
- Fixed long visible-turn indexing rejection, signed-writer accidental downgrade,
  stale verification in retry responses, unsafe FIFO reads, and retry count
  inflation found during static review.
- Added client packaging, setup/trust/transfer/migration guides,
  implementation status and external review instructions. The prior release
  and installed private client are unchanged. **No tests, runtime
  benchmarks, live capture, installation or real migration were run.**

## 0.23.0 — Universal Agent Memory Protocol

- Replaced the client-plugin product with a model-neutral protocol.
- Replaced the 45,000-line runtime core with one readable, zero-dependency
  `memory_vault.py` reference implementation.
- Removed Task/Project binding, routing, projection, handoff directories,
  installers, hooks, Git synchronization, GitHub authentication, providers,
  plugin manifests, update checks, and legacy runtime compatibility.
- Added taskless `goal` and `continuity` records so objectives can cross models
  and agents without becoming Task containers.
- Added content-addressed append-only records, relation-aware local recall,
  exact request retry receipts, dynamic handoff, and cross-process SQLite sharing.
- Anchored automatic goal handoff to visible episode evidence and local ingest
  order rather than caller timestamps.
- Added current-schema-only streaming NDJSON export/import for explicit
  cross-device transfer, with full prevalidation and bounded input.
- Added fixed non-authority labels to every success and error response.
- Reduced CI to synthetic, no-network protocol conformance on Linux, macOS, and
  Windows.

Earlier plugin-oriented development remains available in Git history. The
v0.24 optional client is a new adapter over the current core, not a restored
legacy runtime or a second memory model.
