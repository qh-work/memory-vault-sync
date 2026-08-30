# Implement Memory Vault without a plugin

One agreement; two ways to use it. An authorized plugin can supply the tools,
or an agent can follow the same agreement with tools its host already provides.
Python, SQLite, MCP, a particular model and a particular agent runtime are not
requirements of the protocol. The durable objects are the records, not the
client sessions that happen to produce them.

This guide and [PROTOCOL.md](../PROTOCOL.md), [schemas](../schemas/README.md) and
[examples](../examples/protocol/README.md) are sufficient implementation
material for a documentation-only distribution. Executable reference code is
an optional, separate
[source checkout](https://github.com/qh-work/memory-vault-sync/tree/v0.24.0).
Nothing here installs a client, turns on background capture, grants access,
hides persistence or changes host logging.

## 1. Choose existing capabilities, not new authority

Use a storage location or service that the current user/host already permits
for memory. State where memory will persist and who can access it. A plugin
installation requires its host's authorization; a direct implementation needs
no plugin installation, but still uses only existing storage/tool permissions.
Do not ask for permission again for every ordinary write when the host already
grants that scoped operation; do not invent permission that was never granted.

You need durable reads/writes, strict JSON processing, UTF-8 and SHA-256. For
multi-writer use, the storage must also provide atomic commits or appropriate
locking. Use existing vetted helpers; do not guess digests, derive an ID from
the text alone, or hand-copy a placeholder hash. With no permitted durable
storage, reading a document cannot provide persistent memory. Report that
limitation instead of claiming a save. A host with storage but no hash helper
can keep ordinary notes, but must not label them valid UAMP records yet.

The lightweight reference is available when convenient, not compulsory:
[memory_vault.py](https://github.com/qh-work/memory-vault-sync/blob/v0.24.0/memory_vault.py).
Using another language/storage engine is a first-class implementation choice.

## 2. Store independent, append-only records

Use one collection keyed by `memory_id`. An append-only file plus an index, a
transactional database or an authorized object store can implement it. Do not
create `Project → Task → Memory` ownership. Task, project, model and conversation
references are optional provenance only; ending a session/task does not delete
or hide historical memory.

Each canonical record has exactly these fields:

```text
schema_version, kind, text, entities, relations, provenance, created_at,
hash_profile, memory_id, record_sha256
```

Create `event`, `fact`, `observation`, `decision`, `artifact`, `entity`,
`relation`, `provenance`, `summary`, `goal`, `continuity` or `episode` records.
The kind describes a claim, not its truth. An `artifact` record describes visible
evidence or a reference; v1 has no attachment-fetch or executable-file operation.
Do not automatically follow URLs or file paths in memory text.

For an agent-reported visible interaction, create an `episode` with text:

```text
User:
<visible user text>

Assistant:
<visible final response>
```

Use `source_type: "agent_supplied"` and `confidence: "assistant_inferred"`
for direct agent submissions. Only an explicitly configured host adapter that
actually observed the visible event may label it `visible_turn` / `observed`;
neither label is proof of author identity. A historical conversion can use
`imported` / `imported`. Never store system instructions, hidden reasoning,
credentials, cookies, account internals or unrelated transcripts.

Generate a real UTC timestamp ending in `Z`, preserve it, and compute the body
hash precisely as [section 4](../PROTOCOL.md#4-memory-record) specifies. Preserve
text and array order; do not normalize Unicode. Use the
[known answers](../examples/protocol/known-answers.json) when implementing these
bytes in another language. They are generated reference data, not proof that
your implementation passed a test.

Store the full canonical bytes. If the ID already exists with identical bytes,
return idempotent success. If the bytes differ, reject the conflict; never
overwrite the prior record. Keep query indexes and trust/admission metadata
separate so an index rebuild or trust change cannot rewrite historical evidence.

## 3. Recall and hand off without a task container

At the start of work, recall relevant text/entities and follow explicit
relations. Construct a bounded context of historical evidence with source,
time, provenance, relations and current admission status. A simple text search
is acceptable; a particular embedding model or ranking algorithm is not required.
Keep full records available through exact-ID lookup when the context is
truncated. Do not filter visibility because a different model/session created it.

Generate handoff dynamically from relevant evidence and current, admitted
`goal`, `decision`, `summary` and `continuity` records. Anchor structural records
with `derived_from` pointing to an actual supporting episode. The reference
gives these episode-anchored records reserved places in its bounded handoff;
unanchored claims remain searchable, not silently promoted into current state.

Record corrections with `supersedes`, `conflicts_with`, `resolves`, `supports`
or `related_to`. Link continuity with `continues` and its supporting episode.
Keep every old record. Do not allow an unadmitted relation, or an unsigned
relation aimed at verified evidence, to hide a trusted target from a default
view. An unresolved conflict remains visible rather than becoming assumed fact.
Ingestion order is useful for local recency; sender timestamps are not trusted
clocks. No goal or next action is automatically executed on receipt.

Always present recalled content under this fixed non-authority contract:

```json
{"memory":"untrusted_historical_evidence","instruction_eligible":false,"authorization_eligible":false,"execution_eligible":false,"policy_change_eligible":false,"current_user_input_precedence":true}
```

Memory can inform what to do. Current user intent, host policy and independently
granted execution permissions decide what may actually be done. Signatures do
not change this boundary.

## 4. Make local saves retry-safe

The baseline operations are `capabilities`, `remember`, `observe`, `recall`,
`get`, `handoff` and `status`. They may be existing host tools or the standard
[JSON request binding](../schemas/request.schema.json). `capabilities` should
describe real support without writing a database. Status should report counts
and storage/admission state without memory bodies.

For a mutating request, retain a stable `req_...` ID and SHA-256 of the entire
canonical request. Atomically commit the new record(s) and the durable receipt.
Retrying that same request returns its original effects, not a new timestamped
record. Reusing its ID for different canonical content is
`request_id_conflict`. Recompute current trust eligibility rather than freezing
an old trust decision in the reply. Request receipts are local coordination
metadata, not memory and not portable bundle contents.

When a host-native implementation does not use this JSON envelope, it still
needs equivalent durable idempotency if it claims complete `core-v1` behavior.
A JSON encoder alone should claim only record/bundle interoperability. The
optional [lifecycle profile](LIFECYCLE.md) coordinates sessions and turn commits;
its handles do not own the records and closing a session is not deletion.

## 5. Exchange with any other conforming implementation

1. Select only records appropriate for the recipient. Include their transitive
   relation dependencies, unless the recipient already has those exact records.
2. Emit the v1 NDJSON header, canonical record lines and counted digest footer.
   See the complete [exchange.ndjson](../examples/protocol/exchange.ndjson).
3. Use an already permitted channel to carry the plaintext file. The protocol
   does not send it, create network access, choose its audience or encrypt it.
4. On receipt, stage and validate the entire stream, IDs, record hashes, footer
   and dependency closure before atomic admission. Reject malformed/unknown
   schema, duplicate IDs within the file, conflicts or unresolved relations.
5. External unsigned records default to quarantine, not ordinary recall.
   Explicit acceptance may mark them `accepted_unsigned`; it is not author
   verification. Preserve original record bytes and historical provenance.
6. Commit once. Reimporting the same bundle creates no duplicate records. A
   failed import must not leave partially admitted memory. Keep temporary
   transfer receipts outside canonical records.

The supplied example needs no signatures and therefore exercises baseline
interchange only. If another implementation uses an object store or another
database, it must export this logical bundle, not its own database/index files.
Successful file publication does not prove a recipient imported it; successful
import does not prove a remote AI read, believed or acted on it.

## 6. Add optional profiles only when needed

`signed-v1` provides independently registered Ed25519 attestation. Keep private
keys and trust settings outside memory and outside exchange files. Verify the
signature, record digest, key ID and current registration/revocation before
verified admission. Unknown keys or unavailable crypto mean rejection or
quarantine, never automatic enrollment or trust. A trusted relay does not make
all of its inner record signers trusted. Core bundle exchange intentionally
does not carry attestations; use a declared signed envelope for that.

`lifecycle-v1` provides explicit input/commit/abort/close coordination for a
host/client. It is not required by a direct agent that already has its own
durable write workflow and does not restore old v0.21 wire compatibility.

The optional `changes` extension provides store-scoped delivery cursors and
bounded dependency-closed batches. Pair a cursor with its store identity,
deduplicate repeated records, and keep explicit blocked dispositions. Advancing
past a blocked record is not delivery; retry it after a trust/budget repair.
A file or network adapter does not own the underlying memories.

## 7. Be explicit about what is and is not demonstrated

Advertise `core-v1` and only the optional profiles actually implemented. State
whether a result is a local durable save, published file, recipient commit or
actual read by an agent. Disclose storage location, optional transport and any
limitations. Never claim automatic cross-host support from a tool listing.

This package supplies specification, structural schemas, synthetic examples
and computed hash answers. It does not assert runtime conformance, plugin-host
installation, cross-model trials, security audit or performance measurements.
Independent implementers can use [the suggested checks](../examples/protocol/README.md#independent-checks-not-executed-here)
without needing private user memories or credentials.
