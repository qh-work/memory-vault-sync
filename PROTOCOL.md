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
- fixed authority labels on every response.

It does not define a model, agent runtime, task manager, scheduler, permission
system, network transport, cloud service, or execution gateway.

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
`source_type` and `confidence` itself. Account identifiers, environment data,
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
with the same ID returns the stored result. Reusing the ID with different bytes
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

### `recall`

```json
{"op":"recall","query":"portable memory design","limit":8}
```

Recall is bounded, local, and relation-aware. It does not filter by task, model,
agent, or session. Each result includes provenance, relations, status, and a
plain-text evidence context with the non-authority warning. A large hit is
explicitly truncated in recall; `get` retrieves the full record.

### `get`

```json
{"op":"get","memory_id":"mem_0123456789abcdef0123456789abcdef01234567"}
```

This retrieves one exact, hash-verified record for relation traversal or review.

### `handoff`

```json
{"op":"handoff","query":"What should the next model continue?","limit":12}
```

Handoff is a dynamic view. It combines semantic matches with the newest live,
episode-anchored goal, decision, summary, and continuity records. Current
structural records are guaranteed places in the bounded result even when
semantic matches fill the requested limit. Unanchored records remain searchable
evidence but are not automatically promoted into this continuity view. It is
not a stored Task directory.

### `status`

```json
{"op":"status"}
```

Status returns counts and storage state, never memory body text.

## 6. Local sharing

All cooperative agents under one OS user use the same deterministic default
database. A host can select another absolute path with `MEMORY_VAULT_PATH` or
`--vault`.

SQLite uses WAL, full synchronous commits, foreign keys, a bounded busy timeout,
and short transactions. The canonical memory table rejects updates and deletes.
The term and relation tables are derived indexes over canonical record bytes.
Local ingest sequence, rather than a caller-supplied timestamp, defines recent
state on each Vault. The database declares `schema`, `min_reader`, and
`min_writer` metadata. A
reference implementation refuses an unknown schema instead of letting an older
agent overwrite newer storage.

The database path MUST be on a local filesystem. SQLite WAL is not a multi-host
network filesystem protocol. Agents on different devices exchange a logical
bundle instead.

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

Import accepts only the current schema, validates every record, relation target,
and footer before taking the live writer lock, then commits all changes in one
transaction. The reference implementation bounds a bundle to 64 MiB and 100,000
records. Existing identical records are skipped. Conflicts fail closed. The bundle contains no SQLite index, request
receipt, plugin state, Task hierarchy, Git state, account, or authorization.

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
