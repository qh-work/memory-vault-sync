# Universal Agent Memory Protocol v1

Universal Agent Memory Protocol (UAMP) is a model-, vendor-, session-, device-,
and task-independent way for AI agents to share durable memory.

The protocol is the product, not a particular plugin, programming language or
database. `memory_vault.py` in the matching source/review distribution is one standard-library reference
implementation. Independent implementations MAY use another language, an
append-only file, another database or an already authorized storage service.
They exchange the same records, relations, provenance and logical bundles;
they do not have to share Python code or SQLite files.

There are two complete ways to use this agreement:

- A user-authorized client/plugin provides capture and memory tools.
- An agent directly follows the agreement using its host's existing permitted
  storage, JSON and hashing tools, or its own implementation.

Both ways preserve identical memory semantics. Reading this document alone
does not create storage, grant permissions or make a model remember forever.
Start with [IMPLEMENTERS.md](docs/IMPLEMENTERS.md) for the direct route and
[CLIENTS.md](docs/CLIENTS.md) for the optional client.

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

### Profiles and public artifacts

`core-v1` is the baseline record, authority, append/retry, recall/handoff and
bundle agreement in this document. Section 5 defines its standard JSON request
binding; implementing an always-running process, stdin transport or a particular
database is not required. Host-native tools can expose the same operations.
`changes` is an optional incremental-delivery extension, not a prerequisite for
ordinary record or bundle exchange.

`signed-v1` adds the independent trust and Ed25519 proofs in section 10 and
[TRUST.md](docs/TRUST.md). `lifecycle-v1` adds explicit client-session/turn
coordination in [LIFECYCLE.md](docs/LIFECYCLE.md), using
`universal-memory-lifecycle-request/v1` and
`universal-memory-lifecycle-result/v1`. Its `session.open`, `turn.input`,
`turn.commit`, `turn.abort` and `session.close` names do **not** assert wire
compatibility with the old v0.21 host adapter. Session handles are temporary
client coordination, never parents of memory. Neither optional profile is
needed to read, write or exchange core records.

The v0.25 reference also advertises optional `memory.views`, `memory.graph` and
`memory.reindex` operations. [Retrieval](docs/RETRIEVAL.md) and
[derived graph views](docs/GRAPH_VIEWS.md) define their bounds and pagination;
reindex changes derived local indexes, never canonical memory. Implementing
these extensions is not required to exchange core-v1 records. Query/ranking
algorithms are not part of the canonical record hash domain.

The [v0.21 host bridge](docs/COMPATIBILITY.md),
[signed/fragmented transfer](docs/TRANSFER.md),
[selected shares](docs/SHARING.md), and [external encryption/device contracts](docs/ENCRYPTION.md)
are separately scoped optional integrations. An old-host handle, stream cursor,
share selector or device trust entry does not become a parent of memory or an
execution permission. Their wire versions do not replace canonical record/v1.

Implementers MUST advertise only the operations/profiles they actually
implement. These profile names describe capability sets; they do not add a
`profile` field to existing strict request/record objects.

[JSON Schemas](schemas/README.md) describe the public shapes, and
[synthetic exchange and hash vectors](examples/protocol/README.md) provide
language-independent implementation material. Schema validation alone cannot
verify hashes, byte limits, key trust, relation closure or transactional behavior.

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

The canonical v1 record shape is below. Its IDs/hashes are illustrative
placeholders, not importable data; use the fully computed
[exchange example](examples/protocol/exchange.ndjson) for actual bytes:

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

Precisely, implementations MUST:

1. Decode UTF-8 without a BOM; reject duplicate keys, malformed Unicode, lone
   surrogates and numeric tokens with a decimal point or exponent. Integers are
   in `[-9223372036854775808, 9223372036854775807]`; canonical zero is `0`.
2. Sort object keys lexicographically by their ASCII characters. Core object
   keys match `[A-Za-z][A-Za-z0-9_.:-]{0,127}`; record fields are a fixed set.
3. Encode strings in double quotes. Escape quote as `\"`, backslash as `\\`,
   backspace/tab/LF/form-feed/CR as `\b`, `\t`, `\n`, `\f`, `\r`, and remaining
   permitted U+0001–U+001F controls as lowercase `\u00xx`. Do not escape `/`,
   non-ASCII characters, U+2028 or U+2029. U+0000 is forbidden. Do not normalize
   Unicode, trim text, change line endings inside text, or reformat timestamps.
4. Preserve array order. Canonical record `entities` and `relations` are arrays
   without duplicates; `provenance` is an object, including when empty. The
   Python core accepts some legacy null/duplicate-list input by normalizing it,
   but emitters MUST produce canonical shapes and signed verification rejects
   such normalization-dependent records.
5. Serialize without spaces or a trailing newline when computing a digest.
   A bundle line adds one LF **after** serialization; it is not part of the
   record's own digest.

To construct a record, hash the canonical object containing exactly
`schema_version`, `kind`, `text`, `entities`, `relations`, `provenance`,
`created_at`, and `hash_profile`. Set `record_sha256` to its 64-character
lowercase SHA-256 hex digest, and `memory_id` to `mem_` plus the first 40 hex
characters. These two derived fields are **not** part of that hash input. On
receipt, recompute both; do not trust a supplied ID or hash. Do not substitute
RFC 8785/JCS, a language's default JSON formatting, UTF-16 ordering, or rounded
JavaScript numbers for this profile. There are no floating-point record fields.

The `memory_id` is deterministic for the complete record body, including its
timestamp. Importing an identical record is an idempotent success. The same ID
with different canonical bytes is a hard conflict and MUST NOT overwrite the
existing record.

Provenance is a flat, bounded object. Core-v1 permits only
`source_ref`, `task_ref`, `project_ref`, `conversation_ref`, `model_ref`,
`agent_ref`, `device_ref`, and `request_ref` from callers. It assigns
`source_type` and `confidence` itself on local writes. Imported provenance is
a historical claim, never an authentication result. Account identifiers, environment data,
prompts, credentials, permission claims, and nested objects are rejected.

Portable records use nonblank `text` of at most 1 MiB UTF-8, at most 256 unique
entities (each nonblank and at most 512 UTF-8 bytes), at most 256 unique
relations, and nonblank provenance values of at most 2,048 UTF-8 bytes each.
The canonical provenance object is at most 64 KiB. Complete canonical records
must fit a 2 MiB bundle line, including its record wrapper and LF. Core request
trees are bounded to depth 12 and 16,384 value nodes; signed transport has its
own envelope bounds. These are byte limits, not Unicode character counts.
Real UTC dates have years 0001–9999 and no leap-second `:60` value in this
profile. Implementations MUST enforce semantic/date/byte checks even when their
JSON Schema validator treats `format` or `x-maxUtf8Bytes` as annotations.

## 5. NDJSON interface

The standard stream binding reads one UTF-8 JSON request per line and returns
one response per line. The optional `memory_vault.py --serve` reference reads from stdin and
writes exactly one JSON response per line to stdout. It writes no prose or logs
to stdout. This machine-readable output rule is not audit-log suppression;
normal host/operator logging remains outside the memory protocol.

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

`schema_version` and `request_id` are optional in the reference implementation;
portable callers SHOULD send the explicit schema and MUST supply a stable
request ID when they need exact-effect mutation retries. The ID matches
`req_[A-Za-z0-9_-]{8,96}`. Retry comparison uses the SHA-256 of the canonical
**entire request object**, including the ID and any supplied schema field.
Insignificant JSON whitespace and object-key order do not change it, but
adding/removing a field (even an optional schema field), reordering arrays, or
changing text does. Retrying the same canonical request with the same ID
preserves the original write result, while current verification eligibility is
recalculated against the configured trust registry. Reusing the ID for a
different canonical request returns `request_id_conflict`.

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
receipts are retained in the same durable commit as their effects so an
identical retry remains exact rather than silently creating a later duplicate
record. A receipt is local control state and is not exported in a bundle.
Receivers must not claim a successful write before it is durable; after an
uncertain result, retry the original request rather than inventing a new ID.
Without a request ID, a repeated `remember`/`observe` can create another record
because the implementation assigns a new timestamp. Retrying a record/bundle
with an already computed content ID is separately idempotent.

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

## 6. Storage-independent sharing and reference storage

Memory exchange is over canonical records, not physical database pages.
Independent implementations MUST preserve canonical bytes/IDs, append-only
history, atomic import, stable mutation receipts and explicit admission state.
Their query index, lock mechanism, transaction engine and local file layout
are implementation details. An index or generated handoff can be rebuilt; the
canonical evidence must not depend on a particular Task directory or model.

Different agents MAY share one authorized store, or keep separate stores and
exchange bundles. Permission to read one store does not grant access to another.
External access control can protect a store without making Task/Project IDs
memory owners. A model/agent identifier in provenance is not an ACL or a trust
grant. Retention/privacy administration is separate from a task's lifecycle.

### Python/SQLite reference only

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

This reference database path MUST be on a local filesystem. SQLite WAL is not
a multi-host network filesystem protocol. This restriction is not a mandate
that every UAMP implementation use SQLite; agents using this reference on
different devices exchange a logical bundle instead.

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

The normative interchange is the file format below, not these optional Python
commands. The commands require the separate source checkout/reference file;
the documentation-only protocol package does not contain executable code.

Reference export:

```text
python3 memory_vault.py --export /absolute/private/path/memory.ndjson
```

Import:

```text
python3 memory_vault.py --import /absolute/private/path/memory.ndjson
```

The bundle is a single UTF-8 NDJSON file without BOM, blank lines or trailing
data after its footer. Every line, including the footer, ends with LF:

1. one `header` line declaring `universal-memory-bundle/v1`;
2. canonical `record` lines;
3. one `footer` line with record count and SHA-256 accumulator.

The header has exactly `type: "header"`,
`schema_version: "universal-memory-bundle/v1"`, `created_at` (the same UTC
timestamp grammar as records), and `hash_profile: "canonical-json+sha256/v1"`.
A record line has exactly `type: "record"` and `record: <canonical record>`.
The footer has exactly `type: "footer"`, `record_count` (nonnegative integer),
and `records_sha256` (64 lowercase hex characters). See
[bundle-line.schema.json](schemas/bundle-line.schema.json) and the complete
[exchange.ndjson](examples/protocol/exchange.ndjson), not placeholder IDs, for
machine-readable material.

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

Within one bundle, repeated memory IDs are rejected even if byte-identical.
Across separate imports, identical IDs/bytes are idempotent. Every relation
target MUST exist either in this bundle or already in the recipient's validated
store. A standalone exchange SHOULD contain the transitive closure of every
referenced record. A recipient MUST reject unresolved targets without partial
admission; it must not invent targets, silently drop relations or turn them
into free text. Forward references within one atomic bundle are allowed.
Source line order is preserved as relative ingestion order where relevant,
but does not establish truth, global causal order or user authorization.

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

## 9. Conformance and honest capability claims

A `core-v1` implementation:

- implements the v1 Memory Record and fixed non-authority response envelope;
- supports at least `capabilities`, `remember`, `observe`, `recall`, `get`,
  `handoff`, and `status`;
- does not require a plugin, Git repository, particular model, language or
  database; an independently chosen storage/transport service may have its own
  dependencies and existing authorization, which must be disclosed;
- shares memory without model/task/session visibility partitions;
- provides exact-effect request retries for mutations;
- exports and imports the v1 logical bundle idempotently;
- never overwrites an existing record with different bytes;
- returns recalled content only as untrusted historical evidence;
- has no execution, authorization, policy, permission, or agent-control API.

The seven baseline operations may be exposed through the standard request
binding or equivalent existing host tools; an implementation claiming the
JSON binding must accept its documented wire shapes. A record/bundle encoder
without durable writes, query views or retry handling is useful, but should
claim **record/bundle interoperability**, not complete `core-v1` behavior.
Search ranking/index algorithms need not be byte-identical; preserved records,
authority boundaries, admission checks and dependency semantics do.

No profile requires an always-on service or background network access. Any
optional transport uses only the host's independently authorized capabilities;
it must not infer network, account or execution permission from a memory.
The supplied Python reference is offline and standard-library-only. That is
its implementation property, not a demand that unrelated implementations copy
its runtime choices.

Published schemas and known-answer vectors are implementation aids, not proof
that an implementation passed conformance or end-to-end tests. Declare the
profiles implemented and the verification actually performed separately.

## 10. Optional trust boundary

Admission is independent local policy metadata (`record_admissions` in the
reference database, not a mandated table). States are
`local_unsigned`, `accepted_unsigned`, `verified`, and `quarantined`.
`verification` reports the signer key ID, verification at admission, whether
current trust was checked, and eligibility for context. No state changes the
fixed authority envelope or authenticates the truth of provenance claims.
`local_unsigned` means a locally created unsigned record; `accepted_unsigned`
means explicitly admitted external bytes without author authentication.
`quarantined` bytes remain reviewable by exact ID but are ineligible for ordinary
context. `verified` requires actual signature verification plus an independent
trust decision, never a field asserted by a record or its sender.

An unknown, malformed, unverifiable or revoked signing key MUST NOT result in
`verified` admission. Reject the transfer or retain the bytes in quarantine for
explicit review; never auto-register an incoming public key or silently treat
failed signed verification as successful unsigned admission. Lack of a crypto
provider is a failure, not permission to skip verification. A receiver may
explicitly accept an unsigned core bundle without claiming to authenticate it.

The pure core has no cryptographic dependency. Trusted in-process integrations
may supply a signing callback and `trust_check` callback. They MUST verify
incoming signatures with the independently configured trust registry **before**
calling `ingest_records(admission="verified")`; that internal API is not exposed
over NDJSON or MCP. With `trust_check`, revoked or unknown keys are excluded
from views without changing records. Without it, the core can report only
verification at the time of admission, not current key trust. Revocation is
local policy; it does not remotely delete historical records or withdraw data
from every offline recipient. See
[TRUST.md](docs/TRUST.md).

### Signed-v1 wire primitives

Public descriptors and detached proofs are defined in
[signed.schema.json](schemas/signed.schema.json). A public descriptor contains
exactly `schema_version: "universal-memory-public-key/v1"`,
`algorithm: "Ed25519"`, `key_id` and `public_key`. The public key is 32 raw bytes
encoded with canonical padded standard Base64, not Base64url.
`key_id = "ed25519_" + lowercase_hex(SHA256(raw_public_key))`.

An attestation contains exactly `schema_version:
"universal-memory-attestation/v1"`, `key_id`, `record_sha256` and `signature`.
First validate the complete canonical record. The signature is ordinary
Ed25519 over the following bytes (not Ed25519ph):

```text
ASCII("UniversalAgentMemory") || 0x00 || ASCII("record-attestation") || 0x00
  || ASCII("v1") || 0x00
  || canonical({"schema_version":"universal-memory-attestation/v1",
                "key_id":key_id,"record_sha256":record_sha256})
```

`signature` encodes the resulting 64 bytes as canonical padded standard Base64.
The signed digest binds the full record body, including relations, provenance
and timestamp; the derived ID is validated too. A key attests bytes, not the
human/model identity claimed in their text and not that it originally authored
the evidence.

A message proof contains `schema_version:
"universal-memory-message-signature/v1"`, `key_id`, `payload_sha256` and
`signature`. Hash the canonical **whole payload object**, excluding the
detached proof. Sign its three-field proof body as above but replace
`record-attestation` with `message-signature` and use the message schema/hash
field. Independent domain strings prevent record/message proof substitution.
Verify both the envelope proof and each record proof for signed delta transfer;
a trusted relay cannot invent trust for an unregistered inner record signer.

Private keys, trust enrollment/revocation state and execution permissions are
not memory records and are never included in core bundles. A signature adds
source accountability, not ownership, truth, policy privileges or encryption.
