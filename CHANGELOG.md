# Changelog

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

Earlier plugin-oriented development remains available in Git history but is no
longer distributed or supported by the current architecture.
