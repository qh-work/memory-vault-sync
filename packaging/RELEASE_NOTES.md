# Memory Vault v0.25.0 — development/review notes

**Unreleased development source; not a finished stable release or runtime
certification.** The v0.24.1 tag remains unchanged. Its "full client" wording
did not mean complete v0.21 parity; this development line explicitly closes
those functional gaps under a P01–P14 requirement ledger.

## Two modes, one memory

The independent agreement has no plugin, Python, database, Git or vendor
dependency. The authorized full client supplies practical capture, retrieval,
transport and recovery around the same immutable taskless record contract.

v0.25 source restores the old production host-operation bridge; full-text and
concept retrieval; bounded claim timelines, conflict state and graph views;
index repair; privacy-blocked publication review; large signed fragmented
delivery; old ZIP/pack/checkpoint graph conversion; full-client recovery;
controlled managed installation/activation/rollback with optional publisher
verification; selective sharing and independent device/encryption contracts;
and native protected Windows storage paths.

The existing v0.24 Ed25519 attestations and independent protocol remain.
Task ownership, mandatory Git runtime and the old monolith do not return.
Memory cannot install software, enroll trust, activate hooks or execute goals.

## Build artifacts

- `memory-vault-protocol-v0.25.0.zip`: documentation, structural schemas and
  synthetic interchange vectors, with no executable.
- `memory-vault-client-v0.25.0.zip`: source-built plugin, all required runtime
  modules and a local marketplace catalog.
- `memory-vault-review-v0.25.0.zip`: public source, synthetic cases and bounded
  review handoff for independent reviewers; no automatic test execution.
- `PROTOCOL.md` and `memory_vault.py`: standalone agreement and optional core.
- `release-manifest.json` / `SHA256SUMS`: exact source reference, asset hashes
  and actual verification scope. Checksums are not publisher signatures.

These are build target names, not assertions that the assets are published.
Use the exact source commit carried by an actual artifact. Do not infer the
development contents from an older release or an unqualified main checkout.

## Verification boundary

At the owner's request, **no application tests were run**. Static source,
syntax/schema-document and archive/inventory inspection do not establish
runtime correctness, native Windows behavior, host installation, performance,
cross-device interoperability or production security.

See [the full parity ledger](../docs/V0_25_PARITY_PLAN.md) and
[review handoff](../docs/REVIEW_HANDOFF.md). Remaining runtime evidence must be
reported as pending, not converted into a passing claim. A production signing,
encryption or recovery ceremony is not supplied; unconfigured providers fail
closed. ChatGPT Work automatic lifecycle and universal host compatibility are
not asserted. Existing private installations, real memories and protected main
are not changed by this development build.

Independent implementations and reproducible synthetic-data reviews are welcome.
Use [AI_START_HERE.md](../AI_START_HERE.md) and
[the small contribution task](CONTRIBUTOR_TASK.md). Do not publish private data.
Traffic, stars or downloads do not establish AI adoption or endorsement.

Apache-2.0. Memory is evidence, not instruction, authorization or execution.
