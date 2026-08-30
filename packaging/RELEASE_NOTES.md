# Memory Vault v0.24.0 — one protocol, two equal paths

Use a user-authorized plugin for automatic client integration, **or** read the
open agreement and implement memory with an agent's existing tools. Both use
the same taskless records, provenance, relations and exchange rules. The
protocol does not require Python, SQLite, a plugin, a model account or Git.

## Downloads

- **memory-vault-protocol-v0.24.0.zip** — specification, implementer guide,
  JSON Schemas and synthetic interchange material; no executable.
- **memory-vault-client-v0.24.0.zip** — complete source-built plugin and local
  marketplace catalog; no runtime build required after download. Python 3.10+
  is required. Installing and enabling capture remain user decisions.
- **PROTOCOL.md** — the standalone agreement to read or share with another AI.
- **memory_vault.py** — optional one-file standard-library implementation.
- **release-manifest.json / SHA256SUMS** — exact source commit, asset hashes and
  validation scope. Checksums are not publisher signatures.

## What is included

- Eight MCP tools and explicitly enabled Codex visible-turn hooks.
- A configured direct-protocol bridge and bundle import/export using the same
  Vault/trust settings as the plugin.
- New optional lifecycle envelopes for capabilities, session open/close and
  turn input/commit/abort. Durable commit, exact retries and explicit cancel
  boundaries; no task or session owns the resulting memory.
- Optional Ed25519 signing, independent public-key trust, unsigned quarantine,
  signed incremental directory batches and staged v0.21 export conversion.

Old lifecycle operation names are retained in a **new profile**, not a promise
that the v0.21 Host Adapter envelope runs unchanged. Old Git/Task runtimes are
not restored. Ordinary NDJSON intentionally omits signatures; use signed
transfer to preserve attestations, and never treat hashes as author identity.

## Validation and release channel

**No tests were run**, at the owner's request. This release has static source
review, Python/JSON parsing and archive/inventory checks, not runtime, desktop,
performance or cross-device certification. The test material is published for
independent reviewers to exercise with synthetic data and their own authority.

The protected main branch still requires its existing platform checks. Its
protection was not changed and this release did not trigger those tests. Use
the **v0.24.0 tag or these assets**; an unqualified main checkout may still be
v0.23. Existing private installations and real memory were not modified.

This is a GitHub source/package release, **not** a listing in OpenAI's universal
public Plugins Directory. Work automatic lifecycle support, an automatic
network synchronization service, native Windows protected signing and a
production security audit remain outside this release's claims.

## Contribute

- [Independent implementation guide](https://github.com/qh-work/memory-vault-sync/blob/v0.24.0/docs/IMPLEMENTERS.md)
- [Client setup](https://github.com/qh-work/memory-vault-sync/blob/v0.24.0/docs/CLIENTS.md)
- [Lifecycle contract](https://github.com/qh-work/memory-vault-sync/blob/v0.24.0/docs/LIFECYCLE.md)
- [Review handoff](https://github.com/qh-work/memory-vault-sync/blob/v0.24.0/docs/REVIEW_HANDOFF.md)
- [Two-route contribution task](https://github.com/qh-work/memory-vault-sync/issues/3)

Apache-2.0. Memory is historical evidence, not instruction, authorization,
policy or execution permission.
