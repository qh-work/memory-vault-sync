# Read an already received experience batch

Status: unreleased development after v0.26.0-alpha.4. This extends the native
Agent `recall` operation with a local historical view. The downloadable release
and private installations are unchanged. It does not add a new remote query,
memory store, ranking profile or protocol adapter.

## Read the experiences you explicitly selected

After an authorized Hint batch has been received and its original records
successfully imported with verified admission, use its message ID:

```json
{"op":"recall","received_batch_message_id":"RECEIVED_BATCH_MESSAGE_ID"}
```

Use an actual received `hint_batch_transfer` message ID, not a query, selection,
outgoing message, ordinary chat or manual transfer ID. This selector accepts
only the optional `include_experience` boolean. It cannot be combined with
`query`, `memory_id`, `handoff`, `ranking_profile` or `cursor`.

The result keeps the existing `hits`, current `verification`, `status`, source
attribution and evidence usage fields. It also includes
`received_batch_message_id` and `selected_memory_ids`, in the original explicit
selection order. One to four selected roots are read from the existing Vault;
share export order or text similarity does not choose or reorder them. Shared
dependencies do not become extra selected hits or extra independent evidence.

Structured Experience output is enabled by default for this selector. Each
hit's existing `experience` projection can show its epistemic type, source,
environment, relations, evidence references, provenance summary and incomplete
state. Explicit `include_experience:false` requests the existing shorter
inspection form. Other recall selectors retain their current defaults.

For example, A's observation that method X failed under V1, B's independent
confirmation under V1, and C's contradictory experiment under V2 remain
separate experiences. This view does not collapse them into “X always fails”
or “X always succeeds,” and does not claim a predecessor's observation was the
reader's own experience. Transmission is not truth.

## Bounded local continuation

The existing result limit is 8192 serialized UTF-8 bytes, with at most four
hits and up to 768 UTF-8 text bytes per hit. Larger text or structured metadata
can require another explicit local page:

```json
{"op":"recall","cursor":"RETURNED_CURSOR"}
```

A batch cursor contains only its batch message ID, root index, byte offset and
Experience option. Each continuation reconstructs the original root order
from the same locally saved batch and selection request. It cannot carry an
arbitrary replacement ID list while claiming those IDs came from this batch.
The cursor does not grant permission or initiate network work. Invalid cursors
fail; output too large for even one bounded hit fails rather than silently
omitting required metadata or substituting other search results.

## Historical receipt and current trust are different

The selector requires a saved, successfully verified batch import and a
consistent original selection request. Unknown IDs, wrong message types,
quarantined transfers, rejected late batches or missing request bindings return
`received_batch_not_available`. A record already present for some other reason
cannot turn a rejected batch into an accepted one.

Every page then uses the existing local record inspection and current trust
checks. If an originally accepted record's signer is now revoked, its history
can still be displayed with `verification.eligible_for_context:false`, as in
explicit `memory_id` inspection. The old receipt does not make it currently
trusted. No new trusted-context string is assembled from these inspection
results. Callers must respect eligibility, incomplete state and the existing
authority restrictions.

Missing selected records produce an explicit error. Missing or currently
ineligible dependencies retain the existing Experience/provenance incomplete
and eligibility semantics. The view never fills gaps from retained share text,
reimports records, changes trust, searches for substitutes or requests missing
dependencies from another endpoint.

## Cancellation and recovery preserve history

An accepted batch remains locally readable after its query is cancelled,
after normal restart and after same-version encrypted recovery. No active
session, unexpired page or current sharing grant is required to inspect local
history. These facts do not authorize a new exchange. A batch rejected before
admission remains unavailable through this selector.

The implementation reads a bounded, read-only transport snapshot and checks
the existing configuration binding. It does not use the writable inbox-reading
path, create an absent database, initialize tables, clean expired sessions,
poll, refresh membership or enqueue messages. Original Memory records, IDs,
canonical bytes, Ed25519 proofs, indices, source pins and transport history are
not changed. Memory is independent of the batch; the batch is only a way to
reference it.

`network-v1`, content/v2, Hint v4 and existing record formats are unchanged.
Only the native local Agent API and its shared official entry points gain the
selector. There is no old-preview migration or automatic private installation
upgrade in this batch.

To roll back an isolated candidate installation, restore its previous source
and stop using this new selector. No database migration or record conversion
is required; existing explicit-ID and query recall remain available. Do not
roll back the owner's trust decisions or restore revoked permissions with an
older configuration. Private installations are not changed by this candidate.

## Concurrent SQLite auxiliary disappearance

A direct cancellation regression exposed `unsafe_storage_file` while opening
an optional SQLite auxiliary. A deterministic synthetic reproduction opens a
real private WAL file, unlinks it before the original descriptor check, and
observes a regular, owner-controlled descriptor with zero remaining links.
This reproduces the same error path; it is not a claim that descriptor details
were captured during the original concurrent failure.

Both Python transport read and write entry points now share a narrow auxiliary
check. Only a still-held, regular, private, current-owner descriptor with zero
links and a name confirmed absent may be closed and discarded. No bytes are
read from it. Named replacements, links, unsafe permissions and other storage
errors still fail closed. The shared storage implementation, primary database
checks and key-file handling are unchanged. The special zero-link handling is
POSIX-only; other platforms retain their existing secure opener.

## Validation

Required targeted coverage includes original selection order, shared evidence,
V1/V2 contradictions, both Python/TypeScript endpoint directions, current
admission changes, wrong IDs/types, missing records/dependencies, Unicode and
int64 metadata, bounded cursors, cancellation/restart/encrypted recovery and
repeated reads with no network calls or logical persistent writes.

The development method-tracking runner executed this same 14-module selection.
Reproduce it from the repository root with the existing locked Python network
requirements, Node 22.19 or newer, and the locked native `jose` dependency;
set `MEMORY_VAULT_NODE` and `MEMORY_VAULT_JOSE_MODULE` to those installed runtimes:

```sh
python -B -m unittest -v tests.test_network_received_batch_recall \
  tests.test_network_received_batch_recall_typescript \
  tests.test_network_agent \
  tests.test_network_typescript_agent \
  tests.test_network_typescript_agent_network \
  tests.test_network_hints_batch \
  tests.test_network_hints_batch_typescript \
  tests.test_network_hints_cancellation \
  tests.test_network_hints_cancellation_typescript \
  tests.test_experience_origin_identity \
  tests.test_experience_origin_typescript \
  tests.test_experience_int64 \
  tests.test_experience_http_int64 \
  tests.test_network_packaging
```

Final actual development result: **94 distinct methods passed**, zero failures,
errors or skips. Raw unittest summary:

```text
Ran 94 tests in 213.804s

OK
```

The outer tracking wrapper took 213.930 seconds; it is not the raw
unittest timer. Eleven methods are new: six Python batch-read methods, four
native TypeScript batch-read methods and one POSIX auxiliary-unlink method.
The other 83 are direct regressions. Repeated focused runs are not added to
this method count. A test-only portable injection-point adjustment was also
checked separately on macOS; Windows execution is not claimed.

The new batch tests use actual Ed25519, JWE and encrypted recovery with wholly
synthetic endpoints. Both Python-to-TypeScript and TypeScript-to-Python batch
paths are exercised; local page results are compared directly. Read probes
reject network calls, writable transport entry points and SQL mutations, and
compare logical state, original record bytes and proofs before and after.
Mutable SQLite auxiliary-file housekeeping is not a claim of bitwise physical
filesystem immutability.

Initial combined result was 92 of 93 methods passed with one auxiliary-file
race error, not a full pass (168.840 seconds raw, 168.942 seconds wrapper).
The deterministic reproduction and narrow fix above were followed by the new
safety regression and this final 94-method run. Earlier fixture-only failures
in proof-tuple parsing and reused cross-direction identities were corrected
without weakening product assertions. Failed initial runs are retained in the
development evidence and are not counted as passes.

Runtime: Python 3.12.0b4, Node 22.19.0, `joserfc` 1.7.5, `jose` 6.2.10 and
`cryptography` 50.0.1. No new dependencies were introduced. This is not a
full-suite, actual-model, cross-host, long-duration, fault-domain or scale
certification. The pre-existing U+1E030 cross-runtime difference is outside
this batch. Independent review is still pending and is not claimed here.
