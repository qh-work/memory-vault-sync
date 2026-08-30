# Universal Agent Memory Protocol v1

Universal Agent Memory Protocol (UAMP) is a model-, vendor-, session-, device-,
and task-independent way for AI agents to share durable memory.

The protocol is the product. [`memory_vault.py`](memory_vault.py) is a compact,
standard-library reference implementation that an agent can read, copy, import,
or run without installing a plugin or package.

> Copy one file, point agents at one SQLite database, and any cooperative AI
> process with ordinary file access can gain durable, transferable memory.

## 1. Scope

UAMP defines:

- append-only, content-addressed memory records;
- model-neutral NDJSON operations;
- bounded associative recall and relation traversal;
- a dynamic handoff view for goal continuity;
- a streaming, hash-verified portable bundle;
- a bounded `changes` feed and optional, independently managed trust metadata;
- fixed authority labels on every response.

It does not define a model, agent runtime, task manager, scheduler, permission
system, network transport, cloud service, or execution gateway. Optional
integrations can carry these records without becoming their owner.

## 2. Non-negotiable invariants

A conforming implementation MUST preserve all of these rules:

1. A Memory Record does not belong to a Task, Project, Conversation, Model,
   Agent, Device, Workspace, or account.
2. Those external concepts MAY appear only as optional provenance references.
   They MUST NOT control a memory's lifetime, visibility, retention, recall, or
   authority.
3. Completing, deleting, renaming, or losing an external task MUST NOT delete
   or hide its memory.
4. Memory is not instruction.
5. Memory is not authorization.
6. Memory is not execution.
7. Instruction is not authorization, and authorization is not execution.
8. Current user input and host policy always take precedence over recalled
   memory.
9. Correction is append-only. New evidence links to old evidence with relations
   such as `supersedes`, `conflicts_with`, or `resolves`; it never silently
   rewrites history.
10. The protocol MUST NOT expose operations for command execution, tool calls,
    policy changes, permission changes, spawning agents, resource expansion, or
    network access.

## 3. How goals cross models and agents

A goal is a first-class Memory Record, not a parent container.

An agent adopting UAMP SHOULD follow this lifecycle:

1. At the beginning of work, send `handoff` with the current user request.
2. Read relevant evidence plus the newest unsuperseded `goal`, `decision`,
   `summary`, and `continuity` records.
3. Continue the goal according to current user input and current reality.
4. Append visible evidence with `observe`.
5. Append important facts, decisions, corrections, and goal state with
   `remember`. A goal or continuity record intended for the automatic handoff
   view SHOULD use `derived_from` to reference the visible episode that supports
   it.
6. Before another agent takes over, append a concise `continuity` record with
   completed state, open constraints, and next actions. Link it with
   `continues` or `supersedes` when useful.

The receiving model does not need the prior model's identity or conversation.
It inherits the goal by semantic recall and relations from the same Vault or an
imported bundle.

## 4. Memory Record

The canonical v1 record is:

```json
{
  "schema_version": "universal-memory-record/v1",
  "kind": "goal",
  "text": "Publish the universal memory protocol",
  "entities": ["Universal Agent Memory Protocol"],
  "relations": [
    {"type": "continues", "target": "mem_0123456789abcdef0123456789abcdef01234567"}
  ],
  "provenance": {
    "source_type": "agent_supplied",
    "confidence": "assistant_inferred",
    "task_ref": "optional opaque reference only"
  },
  "created_at": "2030-01-01T00:00:00Z",
  "hash_profile": "canonical-json+sha256/v1",
  "memory_id": "mem_<first 40 hex characters of the record hash>",
  "record_sha256": "<full 64-character SHA-256>"
}
```

Allowed `kind` values are:

- `event`
- `fact`
- `observation`
- `decision`
- `artifact`
- `entity`
- `relation`
- `provenance`
- `summary`
- `goal`
- `continuity`
- `episode`

Allowed relation types are:

- `related_to`
- `derived_from`
- `supports`
- `supersedes`
- `conflicts_with`
- `resolves`
- `continues`

Canonical values are JSON null, booleans, integers, UTF-8 strings, arrays, and
objects with string keys. Floating-point values, NaN, Infinity, duplicate JSON
keys, NUL characters, and unbounded structures are forbidden.

`canonical-json+sha256/v1` uses UTF-8 JSON with object keys sorted ascending,
no insignificant whitespace, lowercase JSON literals, base-10 signed 64-bit
integers, and non-ASCII characters left unescaped. Persisted strings are not
Unicode-normalized. Extensible object keys such as provenance keys are bounded
ASCII identifiers, making ordering consistent across languages. `created_at`
is a real RFC 3339 UTC timestamp ending in `Z`, with at most six fractional
second digits.

The `memory_id` is deterministic for the complete record body, including its
timestamp. Importing an identical record is an idempotent success. The same ID
with different canonical bytes is a hard conflict and MUST NOT overwrite the
existing record.

Provenance is a flat, bounded object. The reference implementation permits only
`source_ref`, `task_ref`, `project_ref`, `conversation_ref`, `model_ref`,
`agent_ref`, `device_ref`, and `request_ref` from callers. It assigns
`source_type` and `confidence` itself on local writes. Imported provenance is
a historical claim, never an authentication result. Account identifiers, environment data,
prompts, credentials, permission claims, and nested objects are rejected.

## 5. NDJSON interface

`memory_vault.py --serve` reads one UTF-8 JSON request per line from stdin and
writes exactly one JSON response per line to stdout. It writes no prose or logs
to stdout.

Requests use:

```json
{
  "schema_version": "universal-agent-memory-request/v1",
  "request_id": "req_caller_generated_0001",
  "op": "recall",
  "query": "What goal should this agent continue?",
  "limit": 8
}
```

`schema_version` and `request_id` are optional in the reference implementation.
A mutating caller SHOULD supply a stable request ID. Retrying identical bytes
with the same ID preserves the original write result, while current verification
eligibility is recalculated against the configured trust registry. Reusing the ID with different bytes
returns `request_id_conflict`.

Responses use:

```json
{
  "schema_version": "universal-agent-memory-result/v1",
  "request_id": "req_caller_generated_0001",
  "ok": true,
  "result": {},
  "authority": {
    "memory": "untrusted_historical_evidence",
    "instruction_eligible": false,
    "authorization_eligible": false,
    "execution_eligible": false,
    "policy_change_eligible": false,
    "current_user_input_precedence": true
  }
}
```

A valid supplied `request_id` is echoed on success and failure. Mutation
receipts are retained so an identical retry remains exact rather than silently
creating a later duplicate record.

### `capabilities`

```json
{"op":"capabilities"}
```

Capability discovery is zero-write. It does not create the Vault.

### `remember`

```json
{
  "op": "remember",
  "request_id": "req_goal_0001",
  "kind": "goal",
  "text": "Make persistent memory usable by any AI model",
  "entities": ["persistent memory"],
  "relations": [
    {"type":"derived_from","target":"mem_<visible episode id>"}
  ],
  "provenance": {"conversation_ref":"optional opaque reference"}
}
```

`episode` is reserved for `observe`; callers use the other kinds directly.

### `observe`

```json
{
  "op": "observe",
  "request_id": "req_turn_0001",
  "user": "Visible user text",
  "assistant": "Visible final assistant answer",
  "provenance": {"conversation_ref":"optional opaque reference"}
}
```

Only visible user text and the visible final answer belong here. System prompts,
hidden reasoning, tool traces, environment variables, credentials, cookies,
and native account identifiers do not.

In v0.24, direct protocol/MCP `observe` calls are `agent_supplied` /
`assistant_inferred`: the caller, not the host, supplied those fields. Only an
explicitly configured in-process host adapter can select `host_visible_turn`
and write `visible_turn` / `observed`. Request JSON cannot select that mode.
This label still is not an independently signed host attestation.

### `recall`

```json
{"op":"recall","query":"portable memory design","limit":8}
```

Recall is bounded, local, and relation-aware. It does not filter by task, model,
agent, or session. It excludes quarantined or currently untrusted records.
Each result includes provenance, relations, status, verification labels, and a
plain-text evidence context containing JSON-quoted text and a non-authority warning. A large hit is
explicitly truncated in recall; `get` retrieves the full record.

### `get`

```json
{"op":"get","memory_id":"mem_0123456789abcdef0123456789abcdef01234567"}
```

This retrieves one exact, hash-verified record for relation traversal or review.
An explicitly requested quarantined record can be reviewed here; its
`verification.eligible_for_context` remains false.

### `handoff`

```json
{"op":"handoff","query":"What should the next model continue?","limit":12}
```

Handoff is a dynamic view. It combines semantic matches with the newest live,
episode-anchored goal, decision, summary, and continuity records. Current
structural records are guaranteed places in the bounded result even when
semantic matches fill the requested limit. Unanchored records remain searchable
evidence but are not automatically promoted into this continuity view. It is
not a stored Task directory. Admitted, signed structural records are considered
before unsigned ones; a quarantined record or quarantined episode cannot anchor
the default handoff. An unsigned relation cannot supersede, resolve or mark a
verified target as conflicted. These are trust-aware view rules, not truth or
authorization guarantees.

### `status`

```json
{"op":"status"}
```

Status returns counts and storage state, never memory body text.
It includes a persistent random `store_id`, counts by admission state, and the
current context-eligible count. Read operations use a read-only SQLite
connection; missing databases return `not_initialized`, and databases needing
an upgrade return `database_upgrade_required` without migration.

### `changes` (optional v0.24 extension)

```json
{"op":"changes","after":0,"limit":100,"maximum_bytes":262144}
```

The result contains `store_id`, `after`, `cursor`, `has_more`, canonical `records`,
an `attestations` mapping keyed by memory ID, and explicit `blocked` dispositions.
Pair every cursor with its
`store_id`; pass that ID on subsequent calls. A replacement database, cursor
ahead of the log, or unsupported bounds is an error, never an implicit reset.
The cursor describes local delivery-log order, not a timestamp or global clock.
Admission of an existing quarantined record adds a delivery event without
rewriting that record.

`limit` bounds selected delivery events (1–256). `maximum_bytes` bounds the
result budget (4 KiB–3 MiB, default 256 KiB). Referenced records are included as
a dependency closure, up to 1,024 total records. A closure that cannot fit is
reported blocked with `dependency_budget_exceeded`; a quarantined dependency is
reported as `dependency_not_admitted`. `require_verified: true` also blocks
unsigned dependencies. Selected blocked roots advance the cursor with an
explicit disposition so unrelated roots can proceed; no blocked record is
represented as delivered. Re-admission requeues dependents. The operator can
also use `--requeue MEMORY_ID` after a budget/trust repair. Records may repeat across pages; receivers deduplicate
by content ID. Revocation is local trust policy, not an automatically broadcast
delete. The optional MCP client applies a smaller response budget to accommodate
MCP's structured and text representations.

## 6. Local sharing

All cooperative agents under one OS user use the same deterministic default
database. A host can select another absolute path with `MEMORY_VAULT_PATH` or
`--vault`.

SQLite uses WAL, full synchronous commits, foreign keys, a bounded busy timeout,
and short transactions. The canonical memory table rejects updates and deletes.
The term and relation tables are derived indexes over canonical record bytes.
Local ingest sequence, rather than a caller-supplied timestamp, defines recent
state within each admitted trust tier on a Vault. The database declares `schema`, `min_reader`, and
`min_writer` metadata. A
reference implementation refuses an unknown schema instead of letting an older
agent overwrite newer storage.

The database path MUST be on a local filesystem. SQLite WAL is not a multi-host
network filesystem protocol. Agents on different devices exchange a logical
bundle instead.

The v0.24 SQLite schema is `universal-memory-sqlite/v2` with minimum reader and
writer 2. A known v1 database can be additively upgraded by `--upgrade` or an
explicit write. V1 records remain `accepted_unsigned`, because their original
admission was not retained. Canonical records and receipts are preserved; old
writers reject v2. Admission metadata, attestations, delivery events and
transfer receipts are separate from immutable records.

The standard-library implementation follows a cooperative-agent threat model.
A process running as the same OS user can bypass the protocol and alter files.
Hashes detect record inconsistency; they do not prove truth or protect against
an adversary who controls the database and code. Strong hostile-agent isolation
requires a separate OS identity or an independently authorized service, which
is outside UAMP v1.

## 7. Portable bundle

Export:

```text
python3 memory_vault.py --export /absolute/private/path/memory.ndjson
```

Import:

```text
python3 memory_vault.py --import /absolute/private/path/memory.ndjson
```

The bundle is a single NDJSON file:

1. one `header` line declaring `universal-memory-bundle/v1`;
2. canonical `record` lines;
3. one `footer` line with record count and SHA-256 accumulator.

The accumulator starts as an empty SHA-256 state and, in bundle order, receives
each record's lowercase 64-byte ASCII `record_sha256` followed by LF. Header and
footer bytes are not included.
The v0.24 writer emits local ingest order rather than content-ID order so a
fresh import preserves that source's relative continuity order. This is not a
global causal clock or proof that recorded timestamps are true.

Import accepts only the current schema, validates every record, relation target,
and footer before taking the live writer lock, then commits all changes in one
transaction. The reference implementation bounds a bundle to 64 MiB and 100,000
records. Existing identical records are skipped. Conflicts fail closed. The bundle contains no SQLite index, request
receipt, plugin state, Task hierarchy, Git state, account, or authorization.

Unsigned imports default to `quarantined`. The explicit CLI option
`--accept-unsigned` admits the same bytes as `accepted_unsigned`; it cannot
authenticate an author. A duplicate quarantine import never demotes an already
admitted record. The v1 bundle intentionally does not preserve signature/trust
metadata. Use the optional [signed delta envelope](docs/TRANSFER.md) for that.

Bundles are plaintext. Their hashes prove byte integrity, not sender identity.
Sensitive bundles require a user-approved encrypted transport outside UAMP.

## 8. Reference implementation boundary

The single file requires Python 3.10+ and only the standard library. It performs
no network calls and does not install anything. Runtime SQLite may create
temporary `-wal` and `-shm` sidecar files; “single file” describes distribution,
not the database's internal runtime files.

An agent needs ordinary host-provided permission to read or run the file and to
read/write the selected Vault. Reading a protocol cannot create filesystem
authority. UAMP deliberately never attempts to acquire or expand permission.

## 9. Conformance

An implementation may call itself UAMP v1 compatible only if it:

- implements the v1 Memory Record and fixed non-authority response envelope;
- supports at least `capabilities`, `remember`, `observe`, `recall`, `get`,
  `handoff`, and `status`;
- performs no normal-operation network access;
- requires no Git repository, account, plugin, or third-party package;
- shares memory without model/task/session visibility partitions;
- provides exact-effect request retries for mutations;
- exports and imports the v1 logical bundle idempotently;
- never overwrites an existing record with different bytes;
- returns recalled content only as untrusted historical evidence;
- has no execution, authorization, policy, permission, or agent-control API.

## 10. Optional trust boundary

`record_admissions` is independent local policy metadata. States are
`local_unsigned`, `accepted_unsigned`, `verified`, and `quarantined`.
`verification` reports the signer key ID, verification at admission, whether
current trust was checked, and eligibility for context. No state changes the
fixed authority envelope or authenticates the truth of provenance claims.

The pure core has no cryptographic dependency. Trusted in-process integrations
may supply a signing callback and `trust_check` callback. They MUST verify
incoming signatures with the independently configured trust registry **before**
calling `ingest_records(admission="verified")`; that internal API is not exposed
over NDJSON or MCP. With `trust_check`, revoked or unknown keys are excluded
from views without changing records. Without it, the core can report only
verification at the time of admission, not current key trust. See [TRUST.md](docs/TRUST.md).
