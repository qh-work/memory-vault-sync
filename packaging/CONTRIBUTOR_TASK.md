# v0.26.0-alpha.1 contribution: prove the routes share the same memory

Target the exact **v0.26.0-alpha.1 source and byte inventory** supplied with the
review artifact, not an older tag or an unqualified main checkout. This is a
review task draft; no test execution or contributor contact is implied.

The independent implementation may use any permitted language/storage. The
authorized full client adds practical workflows without owning the memory.
Canonical records, hashes, relations, provenance and admission semantics must
agree across both.

## Small first contribution

1. Use [the synthetic exchange](../examples/protocol/README.md) to perform one
   import/recall/export round trip in an independent implementation.
2. Import the same records using the configured full client's `protocol`
   entry, inspect using native recall and export. Check exact canonical IDs and bytes,
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

An optional network review should exercise native send/receive and the explicit
bounded pump using the same Vault and independently provisioned identities.
Use the client/server dependency locks and disposable stores; do not build an
MCP, A2A, Matrix, Nostr or Graphiti adapter as part of this native-alpha task.

Consult the [validation index](../docs/VALIDATION.md) and
[alpha evidence](../docs/RELEASE_NOTES_V0_26_ALPHA.md) for exact source and
execution scope; do not relabel another version's results. Earlier two-mode
tests share one Python reference; independent crypto frames do not establish
independent real-model adoption. Full P01–P14, live-cloud, real-host/cross-device,
native Windows and performance acceptance remain open. This alpha draft does
not establish installation, publication or certification.
Exercise the review kit only with authorization and disposable stores.
Never publish real memories, hidden reasoning, credentials, production keys,
native identifiers or private paths. Memory grants no execution authority.
