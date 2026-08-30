# v0.25 contribution: prove the two routes share the same memory

Target the exact **v0.25 development/review source commit** supplied with the
review artifact, not the v0.24.1 tag or an unqualified main checkout. This is a
review task draft; no test execution or contributor contact is implied.

The independent implementation may use any permitted language/storage. The
authorized full client adds practical workflows without owning the memory.
Canonical records, hashes, relations, provenance and admission semantics must
agree across both.

## Small first contribution

1. Use [the synthetic exchange](../examples/protocol/README.md) to perform one
   import/recall/export round trip in an independent implementation.
2. Import the same records using the configured full client's `protocol`
   entry, inspect via MCP and export. Check exact canonical IDs and bytes,
   not live database file equality. Unknown unsigned input remains quarantined
   until explicitly accepted.
3. Report source commit, interpreter/host versions, commands and actual results.
   An unexecuted recipe is useful but must be labeled not run.

Keep the first contribution small. Other independent review slices are in
[REVIEW_HANDOFF.md](../docs/REVIEW_HANDOFF.md): retrieval/graph limits, old
production host envelopes, interrupted capture, signed sync/blocked review,
legacy packs/checkpoints, full recovery, update activation and native Windows.

The new [lifecycle](../docs/LIFECYCLE.md) and the
[v0.21 compatibility bridge](../docs/COMPATIBILITY.md) have separate envelopes.
The bridge now maps the ten production operations; matching names alone do not
make the new lifecycle profile wire-compatible. Old handles remain local
correlations; closing or deleting them must not delete long-term records.

An explicitly authorized offline check in temporary directories passed 12
selected synthetic cases on source `066cd5629e690e6b38ab9c0bf43badafe4ef7a1b`
(zero failures, errors or skips); all other cases remain unrun. See the exact
[scoped smoke evidence](../docs/V0_25_SCOPED_SMOKE.md). These entry paths use the
same Python reference, so independent-implementation and cross-model exchange
still need evidence. No host plugin was installed or private memory accessed;
signing, cloud, live-host/cross-device, native Windows and performance validation
remain open. v0.25 remains unreleased development source, not certification.
Exercise the review kit only with authorization and disposable stores.
Never publish real memories, hidden reasoning, credentials, production keys,
native identifiers or private paths. Memory grants no execution authority.
