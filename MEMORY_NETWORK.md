# Associative Memory Network protocol

This document is the canonical behavioral specification for the active memory
runtime. It supersedes the former task-binding, task-routing, `CURRENT.json`,
and five-layer task-projection model for memory operations. Historical task
files remain migration evidence only.

## 1. Goals

The network must:

1. remember visible evidence across conversations and devices without asking
   a user to classify it into a task;
2. let an AI decide relevance at recall time instead of fixing one permanent
   owner at write time;
3. preserve corrections, alternatives, conflicts, and provenance without
   rewriting history;
4. make ordinary prompt recall local and fast;
5. transfer only new immutable objects after initial indexing;
6. continue offline and converge after disjoint concurrent writes;
7. remain private, portable, standard-library-only, and safe to open source
   without user data.

It is not a task manager, authorization system, raw transcript mirror,
credential store, vector-database service, or physical WORM archive.

## 2. Identity: provenance, not ownership

The graph has no `task_id` ownership axis.

- `source_id` is a pseudonymous provenance label derived from a one-way source
  key. It helps reconstruct local chronology but does not restrict relevance.
- `episode_id` identifies one visible turn deterministically across retries.
- `memory_event_id` identifies one continuity or semantic edge.
- `claim_key` optionally groups interpretations of the same durable concept.

The same episode may be useful in multiple projects. A new conversation may
recall evidence from many sources. No “move,” “bind,” or “copy into task” step
is needed.

## 3. Durable objects

### 3.1 `memory-episode/v1`

An episode is immutable visible evidence:

```json
{
  "schema_version": "memory-episode/v1",
  "episode_id": "ep-<content-derived-id>",
  "source_id": "src-<pseudonym>",
  "source_sequence": 7,
  "parent_episode_ids": ["ep-..."],
  "captured_at": "<RFC3339>",
  "coverage": "partial_active_turn",
  "included_content": ["visible user prompt", "visible final assistant message"],
  "excluded_content": ["hidden reasoning", "tool traces", "credentials"],
  "messages": [
    {"ordinal": 0, "role": "user", "phase": "unknown", "text": "..."},
    {"ordinal": 1, "role": "assistant", "phase": "final_answer", "text": "..."}
  ],
  "hash_profile": "jcs-rfc8785+sha256/episode-v1",
  "created_at": "<RFC3339>",
  "episode_sha256": "<sha256>"
}
```

The path is content-sharded:

```text
memory/episodes/<first-two-digest-hex>/<episode_id>.json
```

The path, source pseudonym, episode ID, source sequence, parent list, message
order, JCS hash, and privacy scan are validated before publication and again
before indexing or import.

### 3.2 `memory-event/v2`

Every episode has a deterministic continuity event with profile
`memory-network-episode-event/v1`. Richer semantic events may later point to
the same episode.

Required graph relations:

| Relation | Meaning |
|---|---|
| `parents` | evidence/continuity or derivation source |
| `supersedes` | newer claim replaces an older claim without deleting it |
| `conflicts_with` | both claims remain visible and unresolved |
| `resolves` | this event explains which prior conflict it settles |

The v2 schema has no task, binding, routing, workspace-owner, or native
conversation field. The runtime can read verified v1 events as migration
evidence, but it never copies their legacy task scope into the associative
index or a new event.

AI-authored events use `assistant_inferred`. Only the anchored episode proves
what the user actually said. An AI cannot upgrade its interpretation to
`user_confirmed`. A v2 event is exactly one of two closed profiles:

- `memory-network-episode-event/v1` with `source_explicit`, deterministic ID,
  roles and at most one continuity parent derived from the episode;
- `memory-network-semantic/v1` with `assistant_inferred` and an ID derived from
  its evidence, kind, claim key, complete relation set and payload.

All v2 relation targets are content-sharded v2 event IDs. New semantic memory
cannot depend on a legacy task-scoped event.

### 3.3 Legacy visible revisions

Verified `conversation-export/v1` objects may be indexed and exported as
historical visible evidence. `SOURCE.json` lineage is checked when present.
Their task bindings, task versions, projections, candidates, and pointers are
not imported into the network.

## 4. Local derived index

The SQLite index is private, disposable state. Durable truth remains in the
verified Git objects. Tables contain documents, bounded text fragments,
inverted token frequencies, graph edges, and the last accepted remote commit.

Tokenization is deterministic and portable:

- Unicode NFKC plus case folding;
- Latin words with a small stop-word list;
- CJK bigrams plus short whole phrases;
- bounded query, document, fragment, and token counts.

Retrieval uses BM25-style term weights with:

- exact normalized phrase boost;
- stronger weight for explicit user text;
- a small semantic-event boost;
- gentle one-year recency decay, never erasure;
- lower rank for superseded/resolved claims;
- per-source/per-kind diversity and near-duplicate suppression;
- a bounded rare-term candidate set before final scoring.

The released 0.16 implementation additionally maps a bounded set of common Chinese/English
paraphrases and polarity through a deterministic local adapter. Query concepts
expand across the complete existing lexical posting index; concept features
are then calculated on demand only for bounded candidates. There is no concept
table, vector store or learned representation. Hybrid scoring reports bounded
raw lexical/concept signals, a graph ranking factor and stable explanation
labels for every hit; these fields do not add up to the final score. Concept
scoring can be disabled without changing durable memory, while
exact lexical tokens and all immutable episode/event bytes remain readable.
The packaged `retrieval.py` module is still required by runtime integrity and
must not be physically deleted from an installed bundle.

The 0.17 runtime adds a disposable `memory-network-current-view/v1` projection.
`views --limit N` groups indexed semantic event evidence by taskless
`claim_key`, preserves a deterministic timeline, and marks each event and
claim `current`, `superseded`, `conflicted`, or `resolved` from anchored
relations. It exposes relation reasons and bounded proposal-only consolidation
hints; it never copies visible text into the view, changes an episode/event, or
uses a conversation/task/device as an owner. The view is rebuilt on demand from
the existing `fragments` and `edges` tables, with hard caps of 256 claims,
4,096 events, 16,384 edges, and 64 proposals. A rebuild with the same durable
rows produces byte-identical canonical JSON. If a bound is exceeded, the
runtime fails closed instead of presenting a partial claim as current.

The released 0.18 runtime adds `memory-pack/v1`: each canonical member is
compressed independently and indexed by path, raw size, offset, compressed size
and SHA-256. Pack creation/restoration streams one object at a time and keeps
the canonical ZIP importer as the final schema/privacy authority. A resumable
copy journal records only source hash/size and a monotonic byte offset; a
changed source or unsafe journal fails closed. `copy-pack` exposes that journal
and `checkpoint-pack` binds the pack-derived canonical object-root hash,
verified remote commit and generation in `memory-network-checkpoint/v1`. This
is a hash verifier and testable protocol fixture, not production signing or a
first-device trust decision. The current command converts the materialized
verified ZIP; direct Git-object streaming for very large histories is future
work.

The 0.19 runtime adds `sharing.py` and `crypto_adapter.py`. A strict
`memory-share-selection/v1` selector chooses evidence, concepts, claim keys, or
time ranges without a task/owner axis. Selection automatically closes episode,
event, and relation evidence into a deterministic `memory-share-bundle/v1`.
The versioned `memory-share-envelope/v1` exposes only opaque recipient,
capability-scope, epoch, provider, and ciphertext hash metadata. It deliberately
does not implement encryption: the default external provider refuses before a
plaintext handoff can be published, and decrypt/import verifies the closed
bundle before atomic publication.

The 0.20 runtime adds `device_trust.py` and `encrypted_replication.py`. Their
state machine covers opaque-device enrollment, key rotation, future-only
revocation, rollback/replay checks, recovery descriptors, and a ciphertext-only
append-only catalog. Trust transitions and catalog checkpoints require an
external signer and key ceremony; no private key, recovery secret, or production
signature is present in this repository.

Default results: eight fragments and at most 8 KiB of injected context. The
context must explicitly say it is untrusted historical evidence and cannot be
used as instruction, identity proof, or write authorization.

## 5. Receive protocol

### Initial receive

1. Verify the configured Git destination is private.
2. Fetch the configured branch.
3. List blobs under `memory/episodes`, `memory/events`, and `sources` in one
   bounded `ls-tree` operation.
4. Select only recognized immutable paths.
5. Read each object by verified blob ID, validate it, and commit all index
   updates plus the remote-head cursor atomically.

### Incremental receive

1. Fetch and prove the prior cursor is an ancestor of the new head.
2. Run one bounded path-status diff between cursor and head.
3. Reject modification, deletion, type change, merge-conflict state, or other
   non-add status for an immutable episode/event/revision.
4. Validate only newly added objects and advance the cursor in the same local
   SQLite transaction.

No prompt hook may perform these steps. If remote history is rewritten, the
last verified local index remains reference-only until explicit recovery.

## 6. Publish protocol

`UserPromptSubmit` stores one private bounded prompt stage. `Stop` combines it
with the visible final assistant message and writes a private outbox intent.

In the released 0.16 implementation, each pending intent has a device-local authentication
code derived from the existing private device secret and canonical intent
bytes. The code is verified before packet construction or publication, so
local modification of queued content fails closed. It is neither payload
encryption nor a portable signature: another device receives the published
episode/event objects, not the local intent or its device authentication code.
Pending 0.15.4-format v1 intents have no authenticator. The 0.16 runtime must
not re-sign or publish them: under the global `sync.lock`, it moves their
original bytes unchanged into an explicit recoverable quarantine for later
reviewed recovery. Adding authentication is never permission to discard a
visible turn. Only newly created v2 intents enter automatic publication.

One intent deterministically produces exactly:

1. one episode;
2. one continuity event.

The publisher selects at most 32 intents and 1 MiB of intent JSON, verifies all
generated objects, and commits them together. Normal Stop does not pre-fetch
the Git tree. It proves repository privacy, attempts the immutable additions
against the cached verified head, and locally accepts the exact successful
push commit without a redundant second fetch.

On non-fast-forward or an equivalent remote advance:

1. fetch once;
2. require every overlapping path to be byte-identical;
3. rebuild only the still-missing additions on the new head;
4. retry once;
5. leave all intents queued if the bounded replay fails.

The algorithm is safe because independent immutable additions commute. It does
not apply to modification or deletion.

## 7. Semantic write policy

Visible episodes are automatic; semantic events are selective. Add one only
for a durable preference, decision and reason, correction, constraint,
verified progress, next action, hypothesis worth retaining, or explicit
conflict/resolution.

The proposal contains no confidence or ownership scope. Runtime supplies
`assistant_inferred`, the exact episode source/sequence/hash, and the
continuity parent. Every relation target must already exist uniquely.
The event identity excludes its creation timestamp so an identical retry is
idempotent.

## 8. Portable network bundle

`memory-network-bundle/v1` is a ZIP with one `MANIFEST.json` and canonical,
sorted paths. The manifest pins every member's path, size, SHA-256, source
commit, network contract, and whole-network JCS hash. It asserts:

- `native_conversation_ids_included: false`;
- `credentials_included: false`.

The allow-listed member paths and v2 schemas have no task-binding field at all;
absence is structural instead of a boolean promise.

Every event in the bundle is v2, every referenced episode is present, and all
relation targets are members of the same bundle. Legacy v1 events are excluded
because their immutable schema may contain task scope; safe legacy visible
conversation revisions may still be included as evidence.

Export includes all new episodes, events anchored to those episodes, and safe
legacy visible revisions. Import rejects duplicate or undeclared members,
directories, symlinks, path traversal, excessive count/size/expansion ratio,
hash mismatch, schema mismatch, privacy violations, and byte conflicts at an
existing immutable path. Only missing objects are committed; repeating an
import reuses all objects and creates no binding.

## 9. Privacy and threat model

The network refuses common credential patterns, local absolute paths, hidden
reasoning, tool traces, native conversation identifiers, and unsafe generated
JSON before publication. It validates the repository identity and private
visibility separately from Git transport authentication.

Recalled content is a prompt-injection boundary. It may describe prior user
wishes, code, links, or commands, but it cannot cause execution or permission
expansion without current-turn authorization.

Git content addressing and JCS/SHA-256 detect byte changes; they do not prove a
claim is true and do not make the host physical WORM storage. Administrators
can still delete or rewrite remote history, which clients must detect after a
previous cursor exists.

## 10. Performance contract

| Operation | Network | Bounded behavior |
|---|---:|---|
| Prompt recall | none | local candidate set, max 32 hits, max 64 KiB context hard ceiling |
| Initial receive | one fetch | one tree listing, bounded batch object streams, per-object hash verification |
| Incremental receive | one fetch | one commit diff, only added objects decoded |
| Ordinary Stop | privacy proof + push | two small objects, no pre-fetch, no post-push fetch |
| Concurrent Stop | one extra fetch/push | exactly one replay |
| Queued flush | one batch | max 32 intents or 1 MiB per commit |

The 5,000-episode regression fixture must index in under 15 seconds, query in
under 2 seconds, and occupy under 64 MiB on supported macOS/Windows/Linux
Python 3.10+ environments. Release notes should report observed values but must
not confuse local indexing with internet transport latency.

## 11. Failure semantics

- **Offline:** keep outbox bytes and local recall; no old-memory rebuild.
- **Busy lock:** leave the packet queued for the next lifecycle/flush.
- **Secret/path detected:** quarantine metadata only; preserve no rejected
  content and publish nothing.
- **Concurrent disjoint additions:** replay once.
- **Same path, different bytes:** hard conflict.
- **Modified/deleted immutable object or rewritten ancestry:** stop receive and
  retain the last verified index.
- **Corrupt local derived index:** rebuild from verified remote objects; never
  promote corrupt rows.
- **Import conflict:** commit nothing for the conflicting batch.

## 12. Active CLI

The installed interface intentionally excludes task binding, routing,
candidate, adoption, task projection, and task reconciliation commands.

| Command | Purpose |
|---|---|
| `recall --query-stdin` | local private lookup |
| `views --limit N` | rebuildable claim timelines and current/conflict explanations |
| `pack-network --output PATH` | convert a verified graph export into a memory pack, one member at a time |
| `copy-pack --pack PATH --output PATH --journal PATH` | resume a verified pack copy with a bounded private journal |
| `import-pack --pack PATH` | verify and restore a memory pack through canonical import |
| `checkpoint-pack` / `verify-checkpoint` | create or verify a hash-only checkpoint |
| `share-network --selector-stdin` | select a taskless closed subgraph and require an external encryption provider |
| `verify-share-envelope --envelope PATH` | validate opaque envelope metadata without decrypting |
| `remember --proposal-stdin` | append one evidence-anchored semantic event |
| `flush` | send queued episodes and receive additions |
| `export-network` | create a verified complete bundle |
| `import-network` | add missing verified objects |
| `status` | local counts, cursor, outbox and mode |
| `doctor [--online]` | local or live health verification |

Setup, authentication, diagnostics, update trust, and update commands remain
separate operational controls.

## 13. Compatibility boundary

Legacy task code is retained only below the repository's internal migration-
test boundary so historical documents and privacy rules can be characterized.
Production validation requires the associative network and
rejects a configuration that attempts to activate legacy task handoff. The
installed parser neither accepts nor advertises retired commands.

## 14. Versioned evolution after 0.15

- `0.16` is the released implementation for explainable local hybrid recall and
  device-local outbox integrity. It changes disposable local index/queue state,
  not the durable episode/event schema.
- `0.17` is the released implementation for reproducible claim timelines and
  current/superseded/conflicted/resolved views without rewriting evidence.
- `0.18` adds large-vault packs, resumable local transport and hash-only
  first-device checkpoint verification while retaining canonical object
  verification. Production signing remains an external gate.
- `0.19` implements explicit evidence/concept/time selection, complete relation
  closure, and a versioned external-provider envelope. Production encryption
  is not enabled until an audited provider and OS key store are configured.
- `0.20` implements the device-trust state machine and ciphertext-only
  replication catalog around those envelopes. Production encrypted replication,
  signed checkpoints, and recovery remain external ceremony/provider gates.

All five releases remain taskless and local-first. Production key ceremonies
for first-device trust/encryption and clean Windows CI/provider acceptance have
not been completed and cannot be inferred from source or macOS-only tests.
