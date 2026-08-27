# Memory and backup design benchmarks

This note records design comparisons, not wire compatibility or claims that
another project implements this protocol.

## What we adopted

### Letta: memory should be composable context

Letta describes memory blocks as reusable units that can be attached across
agents and its context hierarchy as a way to manage what enters the model
context. That supports treating durable memory as reusable evidence rather than
as a transcript permanently owned by one chat.

Memory Network adopts reusable, independently addressable evidence and bounded
context injection. It differs by using immutable visible episodes, a private
local retrieval index, and no task/agent binding authority.

Primary sources:
[memory blocks](https://docs.letta.com/guides/core-concepts/memory/memory-blocks),
[context hierarchy](https://docs.letta.com/guides/core-concepts/memory/context-hierarchy).

### Mem0: selective memory and measurable retrieval

Mem0 presents memory as a layer that extracts, updates and retrieves useful
facts rather than replaying all conversation history, and publishes a separate
benchmark repository. This reinforces selective recall and the need for
repeatable quality/latency evaluation.

Memory Network adopts selective bounded retrieval and a future evaluation
track. It deliberately separates immutable source episodes from AI-inferred
semantic events so extraction mistakes cannot replace raw evidence.

Primary sources: [Mem0](https://github.com/mem0ai/mem0),
[memory benchmarks](https://github.com/mem0ai/memory-benchmarks).

### Graphiti: temporal knowledge and explicit change

Graphiti models an evolving temporal knowledge graph and emphasizes retaining
relationships as knowledge changes. This supports first-class supersession,
conflict, resolution and time rather than overwriting one flat summary.

Memory Network adopts append-only relation edges and computed current state.
It uses a much smaller standard-library local index and does not require a
graph database or hosted extraction service.

Primary source: [Graphiti](https://github.com/getzep/graphiti).

### restic: content-addressed, authenticated backup structure

restic's design separates content-addressed blobs, packs, indexes and snapshots
and validates stored content cryptographically. This supports immutable small
objects, deterministic hashes, indexes as rebuildable acceleration, and a
portable manifest that pins every member.

Memory Network adopts content-addressed evidence, verified indexes and exact
object reuse. Git is the current transport and audit graph; the protocol does
not claim restic repository compatibility or restic encryption.

Primary source: [restic design](https://github.com/restic/restic/blob/master/doc/design.rst).

### Borg: deduplication and transactional repository updates

Borg documents chunk/index structures, repository transactions and append-only
considerations. This supports batching many new immutable objects into one
transaction and treating derived indexes separately from durable content.

Memory Network adopts bounded batched publication and all-or-nothing local
cursor/index updates. It does not chunk small conversation episodes; the
existing artifact subsystem handles large binary data separately.

Primary source: [Borg data structures](https://borgbackup.readthedocs.io/en/master/internals/data-structures.html).

### Kopia: snapshots, deduplication and policy-controlled storage

Kopia documents snapshots, content-addressable deduplication, compression and
policy features. This supports keeping storage optimization orthogonal to the
logical memory graph and designing future packs as a reversible encoding, not
a new authority model.

Primary sources: [Kopia features](https://kopia.io/docs/features/),
[compression](https://kopia.io/docs/advanced/compression/).

## What we rejected

| Pattern | Reason |
|---|---|
| One chat or task owns each memory | real topics span conversations; write-time classification becomes friction and error |
| Full-library validation on every turn | latency grows with history instead of new data |
| Rewriting one canonical summary | loses corrections, rejected alternatives and provenance |
| Remote vector search on prompt path | adds latency, availability and privacy dependency |
| Embeddings as durable truth | model/version lock-in and no raw-evidence audit |
| Timestamp last-write-wins | clocks do not prove ancestry or semantic validity |
| Unlimited conflict retry | can hang hooks and amplify remote races |
| File hashes as task identity | byte equality proves bytes, not purpose or authorization |

## Resulting architecture

The combined design is deliberately simple:

1. immutable visible episodes are the durable evidence layer;
2. append-only semantic/temporal edges describe change;
3. Git ancestry and exact paths provide incremental replication;
4. a disposable local SQLite index provides fast recall;
5. the AI judges relevance and may append evidence-anchored structure;
6. task/binding records are not part of memory ownership;
7. full export/import transfers the graph without private account or task state.

## Benchmark plan

Quality and performance must be measured independently.

### Recall quality

- exact distinctive names;
- Chinese and English paraphrases;
- cross-language concepts;
- old preference plus later correction;
- unresolved and resolved conflicts;
- semantically nearby but unrelated conversations;
- malicious instruction text inside memory;
- sparse/no-result prompts.

Report precision/recall or ranking metrics on a versioned synthetic/consented
corpus. Do not use private user memory in public benchmarks.

### System performance

- 5k, 10k, 100k and eventually 1m episodes;
- cold index versus one-commit incremental receive;
- common-token versus rare-name query;
- context formatting and deduplication;
- immediate two-object Stop;
- 32-turn batch;
- disjoint concurrent replay;
- complete streaming export/import.

Separate CPU/index time, local Git time, privacy API time, upload time and
download time. A single aggregate “sync speed” hides regressions.

## Current synthetic result

[`benchmarks/memory-network-v1.json`](benchmarks/memory-network-v1.json) is a
credential-free run produced by
[`scripts/benchmark_memory_network.py`](scripts/benchmark_memory_network.py).
On the recorded Apple-silicon macOS environment, 5,000 turns (10,000 episode
and event documents, 15,000 fragments) built in 1.944 seconds. Applying one new
turn took 4.290 milliseconds. Twenty-five mixed distinctive/common local
queries had a 3.865 millisecond median and 219.941 millisecond p95, with no
network access. The 56,999,936-byte figure includes the SQLite database and
every remaining sidecar after each connection is explicitly closed; no WAL
sidecar remained after the measured operations.

These are synthetic local-index measurements, not promises about Git host or
internet latency. The release tests separately prove that an ordinary Stop
does no pre-fetch or post-push fetch, SessionStart uses commit-delta receive
after its first cursor, initial receive and full export use bounded Git batch
object reads with per-object hash verification, and a concurrent advance causes
at most one replay.
