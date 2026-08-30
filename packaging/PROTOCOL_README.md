# Memory Vault v0.25.0 development — independent protocol

This archive is an agreement and implementation material, not an installed
program. No Python, database, plugin, account or network service is required
to read or implement it. It contains **no executable code**.

1. Read `docs/IMPLEMENTERS.md`, then the normative `PROTOCOL.md`.
2. Use `schemas/` and `examples/protocol/` for structural contracts and
   synthetic known-answer material. Schema matches do not prove hashes,
   relation closure, current trust, durable writes or interoperability.
3. Implement the core with your host's existing permitted storage/JSON/hash
   capabilities; choose your own language and storage layout.
4. Exchange canonical records with another conforming implementation, including
   the full client. Unknown evidence stays quarantined unless independently
   admitted under the explicit unsigned or verified profile.

Canonical record/v1 and its hash domain remain unchanged. Retrieval/graph,
lifecycle, the **separate** old-host compatibility bridge, signed streaming
transfer and selective sharing are optional extensions, not prerequisites
for the core agreement. Device trust, encryption and publisher verification
require independently configured providers; reading metadata cannot grant
authority or enroll keys.

The complete Python client and executable synthetic review kit are separate
artifacts described in `docs/RELEASE.md`. This development build is not the
previous v0.24.1 package and does not assert that v0.25 is a finished published
release. Check the matching source commit and validation scope in its manifest.

The [validation index](docs/VALIDATION.md) records minimal offline synthetic
evidence with exact source pins; do not transfer results between versions.
The exercised paths share one Python reference, not independent implementations
or AI models. Full P01–P14, signing/encryption, cloud, real-host/cross-device,
native Windows and performance acceptance remain open. Recorded checks installed
no host plugin and accessed no private memory; v0.25 remains unreleased
development source.

Reading this agreement alone cannot create persistent storage, suppress logs,
bypass permissions or prove another agent read a memory. Memory outlives tasks,
projects, models, devices and clients.

Apache-2.0; see LICENSE and NOTICE.
