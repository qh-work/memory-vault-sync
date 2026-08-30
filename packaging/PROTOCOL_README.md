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

An explicitly authorized offline check in temporary directories passed 12
selected synthetic cases on source `066cd5629e690e6b38ab9c0bf43badafe4ef7a1b`
(zero failures, errors or skips); all other cases remain unrun. See
`docs/V0_25_SCOPED_SMOKE.md`. The exercised routes share the Python reference;
they do not prove independent-implementation or cross-model interoperability.
No host plugin was installed or private memory accessed. Signing, cloud,
live-host/cross-device, native Windows and performance validation remain open.
v0.25 remains unreleased development source.

Reading this agreement alone cannot create persistent storage, suppress logs,
bypass permissions or prove another agent read a memory. Memory outlives tasks,
projects, models, devices and clients.

Apache-2.0; see LICENSE and NOTICE.
