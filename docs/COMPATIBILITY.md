# v0.21 host protocol compatibility bridge

`memory_vault_compat.py` accepts the original **host protocol 1.0** request
envelope used by the v0.21 Claude Code, Gemini CLI and generic host adapters.
It uses the same current canonical Vault, signer, trust registry, retrieval
index and append-only records as the independent protocol and current client.
It does not revive the old runtime, a Git repository or Task-owned memory.

This is source-implemented compatibility, **not complete protocol conformance
or real-host certification**. Four selected compatibility cases passed against
source commit `ecb83fdc3045545c9cfd1a07ea312dfadf8f314d` in the
[six-case offline follow-up](V0_25_FOLLOWUP_SMOKE.md). The complete compatibility
suite was not run. The earlier [12-case campaign](V0_25_SCOPED_SMOKE.md) targeted
`066cd56` and included no compatibility-specific cases; the two reports do not
establish an 18-case pass on one source version. Other reviewers must follow
their own execution authorization when extending or running these fixtures.

The automatic capture-chain behavior below describes source commit
`098b22c44ca299d1f889b41df9355511dfa2caf4`. The historical campaigns above predate
that change. Its focused review cases are in
[`tests/test_v025_capture_compat.py`](../tests/test_v025_capture_compat.py);
their presence is not a test result, performance measurement or release claim.

## What is compatible

The closed request envelope remains exactly:

```json
{
  "schema_version": "memory-vault-host-request/v1",
  "protocol_version": "1.0",
  "request_id": "example.opaque-request-1",
  "operation": "memory.status",
  "adapter": {"id": "example-adapter", "version": "1.0.0", "host_family": "generic_stdio"},
  "payload": {}
}
```

Responses use `memory-vault-host-response/v1`, the original status vocabulary,
fixed six-field negative-authority object and content-free error shape. The
closed lifecycle and recall result shapes are preserved. No native host ID,
Vault selector, credentials, task container, model owner, command, permission,
policy or execution field is accepted. Adapter metadata affects only the exact
local request receipt; it never enters a canonical record or its hash.

The machine-readable contracts are
[host-compat-request.schema.json](../schemas/host-compat-request.schema.json)
and [host-compat-result.schema.json](../schemas/host-compat-result.schema.json).
They close the ten operation payloads and corresponding result objects,
including nullable post-only handles, the twelve semantic proposal kinds,
typed relationship lists, alias/evidence mappings, pending/done receipts and
local-versus-exchange publication labels. These are **not** aliases for the
new `lifecycle-request.schema.json` or core `request.schema.json` formats.
The old `accepted_local` / `degraded` / `duplicate` status envelope does not have
the core's `ok` field.

JSON Schema validates structure, not UTF-8 byte lengths, canonical hashes,
current signer trust, handle correlation, duplicate JSON keys, NFC/privacy
checks or exact retry semantics. The `x-maxUtf8Bytes` annotations document
implementation-enforced limits; a generic schema engine does not enforce that
extension. A schema-valid request cannot pick a Vault, enroll an identity,
grant capture permission or bypass any runtime semantic check. Published
synthetic schema cases are in `tests/test_v025_mcp_bounds.py`; they were not run.

| Operation | Current implementation |
| --- | --- |
| `capabilities` | Zero-write, network-free original capability fields plus an explicit compatibility profile |
| `session.open` | Issue/reuse an opaque local continuity handle; non-compact reasons may retry local intents and enter one separately configured sync window |
| `turn.input` | Scan and NFC-normalize the visible prompt, stage it privately, return current local evidence |
| `turn.commit` | Atomically accept the visible intent, frozen projection and old-format receipt; then attempt local canonical materialization; never launch a worker or access a network |
| `turn.abort` | Abort an uncommitted input; an already accepted pending/done commit remains committed and is never falsely rolled back |
| `session.close` | Close local correlation, discard only staged text, retain accepted intents and all canonical memory |
| `memory.recall` | Current local retrieval rendered through the exact old evidence wrapper, with explicit evidence-ID mappings |
| `memory.remember` | Validate existing admitted evidence and typed relations, then atomically append a signed/unsigned-as-configured semantic projection |
| `memory.status` | Content-free current Vault/index and bridge queue counts; no key loading or network |
| `sync.flush` | Retry one bounded local intent batch and run one independently configured synchronization window |

The source entry point is:

```bash
python3 /absolute/source/memory_vault_compat.py \
  --config /absolute/private/control/client.json --serve
```

The configured client can route its compatibility command to the same module.
Programmatic integration uses:

```text
handle(config_path, request) -> original host-response envelope
run_stream(config_path, serve=False) -> exit code
main(argv=None, *, config_path=None) -> exit code
flush_local(config_path, limit=4) -> local-only retry report
```

The configuration is loaded exclusively through `ClientConfig.load`; a request
cannot choose another Vault. Existing installations must explicitly enable
`capture_visible_turns` before new `turn.input`/`turn.commit` operations. Explicit
memory reads and semantic writes do not imply automatic host capture.

## ID compatibility is a mapping, not an identity claim

Old `ep-…` / `evt-…` IDs were computed in different hash domains. They must not be
renamed into `mem_…` and represented as the original signed or hashed object.
Current record bytes and IDs remain unchanged.

For a **current** canonical record, the bridge offers a reversible alias:

```text
current episode: mem_<40 hex> -> ep-<same 40 hex>, source alias src-<same 40 hex>
other current record: mem_<40 hex> -> evt-<same 40 hex>
```

These are explicitly labeled `memory-vault-v021-canonical-alias/v1` and
`original_v021_identity: false`. The source alias is an evidence-addressing
convenience, not a source/session owner, author identity, visibility rule or
retention boundary. Another model can derive the same alias from the same
canonical record without transferring a host handle or a private session map.

Recall includes the canonical memory ID and full canonical record SHA-256 with
each alias. `memory.remember` checks that its episode exists, that the supplied
source alias matches, and that the evidence and every relation target remain
eligible under the selected current trust boundary. Quarantine, unknown IDs,
changed mappings and source mismatches are rejected, not auto-admitted.

**Actual old export IDs require an explicit verified migration mapping.**
The operator-only integration API is:

```text
register_legacy_aliases(config_path, rows)
row = {
  legacy_id, memory_id, record_sha256, source_id, evidence_anchor_sha256
}
```

The migration caller must first verify the old document hashes and graph.
Registration checks the new record ID/hash/kind, preserves the old evidence
anchor, refuses conflicting mappings and grants no trust. It is absent from
the host protocol, MCP memory operations and recalled instructions. Original
old handles and active staging receipts are not silently imported. Losing the
local old-ID map requires restoring it through the verified migration workflow;
the current canonical aliases remain derivable independently.

## Claims, evidence and relationships

The original `memory-network-semantic-proposal/v1` shape and all twelve kinds
are accepted. The bridge preserves:

- `claim_key` as the stable entity `claim:v021:<claim_key>`;
- the exact old semantic kind as `semantic:v021:<kind>`;
- concepts as `concept:v021:<concept>` entities and exact JSON data in the claim;
- the episode evidence anchor as a `derived_from` relation;
- `parents` as `derived_from` edges;
- `supersedes`, `conflicts_with` and `resolves` as their same-named directed edges.

The current top-level kind is a compatible record/v1 kind: decisions remain
decisions, continuity-like next actions/checkpoints become continuity, artifact
claims become artifacts, conflict declarations/resolutions become relations,
and other semantic observations remain observations. All are
`assistant_inferred`; adapter metadata and an old confidence claim cannot make
them user-confirmed or host-witnessed.

Old proposals permit four lists of 128 targets, exceeding record/v1's total
256-edge bound. Such proposals are represented by bounded relation records
plus the final claim record. Every original typed edge is retained; no list is
truncated. The projection parts share
`claim:v021:projection:<proposal SHA-256>` and retain the real claim-key marker
when supplied. This groups one compound projection, not memories belonging to
a Task, source, session or project. The parent links and evidence links do not
merge unrelated claims merely because they cite the same episode.

## Large visible turns are preserved, not truncated

The legacy framing limit is 3,145,728 bytes and each visible text field permits
2 MiB. A staged user input and later final response can therefore exceed the
current core's single-record text capacity.

Small turns become one canonical episode plus a linked continuity excerpt.
Larger or heavily JSON-escaped turns are split at UTF-8 boundaries into ordered,
JSON-quoted episode fragments, each carrying its position. One canonical
episode anchor references all fragments and records the full visible-pair
SHA-256; a continuity record references that anchor. The entire bounded set is
written in **one canonical SQLite transaction** with one core idempotency
receipt. No text is silently trimmed, no hidden/model/tool content is added,
and a fragment is never claimed to be an independently witnessed host event.

The JSON-quoted fragment portions concatenate to the exact NFC-normalized
`User:\n…\n\nAssistant:\n…` representation. The brief continuity text is a
derived excerpt, not a substitute for the preserved full visible bytes.

## Durability, cancellation and precise retries

Control state lives only in the selected client's private
`host-protocol-v1.sqlite3`. Its sessions and turns are temporary correlation,
not long-term-memory parents. Handles use cryptographically random 256-bit
values and an atomic local request receipt. They never embed native IDs,
adapter metadata, user text or a public hash of a native host identifier.

### Frozen capture for newly accepted turns

The filename remains unchanged, but the current control schema is
`memory-vault-host-compat-state/v2`. It adds the shared `capture_heads`,
`capture_jobs` and `capture_records` tables. The internal builder profile is
`compat-visible-turn+continues/v1`; it is neither a new host wire protocol nor
a change to canonical record/v1.

Within the same acceptance transaction, a new final turn fixes the complete
ordered canonical projection, its timestamp, the normalized visible-input
digest, its core request ID and the previous continuity record's ID **and full
SHA-256**. The previous record comes from the last accepted plan for that
explicit local continuity handle, including a still-pending predecessor. It is
not guessed from the Vault's newest timestamp, last recalled hit or another
client's most recent write. Acceptance order uses a local monotonic sequence,
not the wall clock.

The new continuity record keeps `derived_from` pointing to its episode and
adds `continues` pointing to that frozen predecessor, when present. Large-turn
episode fragments remain lossless as described above. The first new plan in a
scope has no inferred predecessor. Reopening the same continuity handle retains
its local sequence; another handle or client control directory does not select
that sequence automatically. Semantic `memory.remember` writes do not advance
the visible-turn capture head.

These handles, sequences and scope keys stay in private delivery metadata. They
do not enter canonical records, become Memory parents, decide visibility or
control retention. Removing a local session or control directory cannot delete
the canonical history or its `continues` edges. A native adapter's stable scope
across handle generations is a separate integration described in
[HOSTS.md](HOSTS.md), not a new field in this old request envelope.

The new turn path is:

```text
staged -> pending intent + frozen projection + old-format receipt -> done batch
   \-> aborted
```

A post-only commit with both visible texts atomically creates its turn handle,
complete pending intent, frozen projection and receipt. Required local
acceptance precedes any acknowledgement. The bridge then attempts local canonical storage; if storage
or signing is unavailable it returns `degraded`, with `queue_state: pending`,
and retains the exact accepted intent. It never falls back to unsigned writes
when configured signing fails.

The control DB and canonical Vault are deliberately **not** described as one
cross-database transaction. If a crash follows canonical commit but precedes
the control receipt update, retry uses the frozen bytes and original core
request ID; it does not rerun a newer text template or choose another timestamp
or predecessor. The canonical transaction checks the full projection and
predecessor hash against the actual Vault and current admission/trust. Existing
records are not re-signed or re-admitted merely because a capture plan or
historical receipt exists. Configured signing still fails closed.

After canonical success, the control transaction marks the plan saved, clears
its duplicate record bodies and the turn's staged text, and retains ordered
record IDs/full hashes plus the receipt metadata. A saved plan can therefore
be checked against actual canonical records without retaining a second copy of
the conversation. This is not an assertion that old evidence remains trusted
or that another agent received it.

`sync.flush`, non-compact session opens, or explicit `flush_local` can retry
pending intents. For new plans, the finite flush only materializes a child
after its accepted predecessor is saved; a backwards wall clock cannot reorder
the chain. A direct child attempt whose predecessor is pending remains pending,
and never recursively reacquires the control write lock. The default flush
budget is four intents; the explicit API accepts 1–16. A budget boundary is not
permission to drop a dependency, invent a new answer or overwrite old data.

### Existing v1 state and shared semantic receipts

Read-only v1 receipt lookups do not migrate the database. An authorized write
adds the v2 control tables without rewriting old turns, canonical records or
receipt bytes. An already accepted v1 turn with no capture plan continues
through its original projection, fixed acceptance time and core request domain, keeping
its original record IDs. Migration does not graft it onto a newly inferred
`continues` chain. A staged input with no accepted final projection can enter
the new profile when its final commit is subsequently accepted.

Semantic `memory.remember` idempotency belongs to the **shared canonical
Vault**, not to a client's `semantic_jobs` table. Two authorized client
configurations may have different private control directories and still submit
the same proposal against the same admitted episode and typed relation targets.
Its identity is derived from that proposal/evidence domain, not from the outer
host `request_id`, which correlates the response for this operation.
The canonical writer serializes first acceptance in one SQLite write
transaction, chooses its timestamp there, and stores the complete projection
and existing-format core receipt together. A later or simultaneous caller
reconstructs the expected projection using the first canonical record's time;
it must match the receipt digest, anchor, every canonical record and all current
evidence/target admission checks before receiving `duplicate`.

A local completed marker alone never proves success. Even its replay takes
the shared-receipt path; a missing, redirected or conflicting receipt fails
closed. An older pending local job with another timestamp can be reconciled to
the validated shared record without changing that record or the original
receipt bytes. The local cache update follows the canonical commit, so a crash
between the two is recovered by the same shared check. Reuse does not re-sign
or re-admit old records, and quarantined or currently untrusted projections
cannot become eligible merely because their historical receipt exists.
Replay still passes the configured signing/trust gate (`config.vault(writing=True)`);
it is not a key-free lifecycle ACK lookup. Current admission and key trust are
checked, but this does **not** mean every replay independently reruns all
Ed25519 signature verification. Configured signing/trust failures still fail
closed.

That shared-semantic receipt repair adds no wire fields, semantic tables or
receipt schema; the separate capture upgrade above adds only private control
tables. Canonical-memory snapshots retain their existing receipt format. Shared
semantic reuse operates within one shared Vault, not a distributed transaction
between independently writable
Vaults. Four methods in `test_v025_compat.py` passed in the
[offline follow-up](V0_25_FOLLOWUP_SMOKE.md) at source commit
`ecb83fdc3045545c9cfd1a07ea312dfadf8f314d`: sequential two-configuration reuse,
simultaneous first writes, recovery after an injected post-canonical-commit
exception, and rejection of redirected/extended shared receipt responses.
They used temporary shared SQLite, including two local fixture threads—not
separate devices or models—and an injected exception, not a real process,
power-loss or device failure. No signing keys, real host, network, private
memory or plugin installation was involved.

The other six newly added cases (stale local time, conflicting/missing shared
receipts and three current-admission boundaries), plus the expanded 512-target
multi-record projection case, remain **NOT RUN**. The successful subset does
not establish those boundaries, full-suite conformance, cryptographic
verification, cross-device operation or real-host integration.

For session/turn lifecycle operations, the same request ID plus different
canonical request fields is `conflict`, including changed adapter metadata.
Object key ordering and JSON whitespace are not part of the lifecycle receipt
identity. User-text equality uses NFC **only**: whitespace, newlines and trailing
spaces are not trimmed or rewritten. A different final answer under an accepted
turn handle is a hard conflict.

Exact completed **session/turn lifecycle** receipt lookup is read-only and still
works after capture is disabled. Disabled capture never materializes pending
turn text, resumes an incomplete turn write or loads a signing key merely to
replay that lifecycle ACK. Abort/close remain available to clear unaccepted
staged input. Once a turn intent is accepted, abort reports
`terminal_state: committed` with pending/done state; it cannot truthfully undo
durable acceptance. The explicit semantic `memory.remember` operation uses
the separate shared-canonical checks above, not this lifecycle receipt shortcut.

## Deliberate differences from the old transport

Wire compatibility does not imply Git-object or old runtime-file compatibility.

- `memory.remember` acknowledges a local durable semantic record as
  `accepted_local` (`duplicate` on exact semantic replay), never as a fabricated
  remote publication. Its result explicitly returns `remote_commit_sha: null`.
- `sync.flush` may report `published` only for verified publication into the
  configured exchange. Provider readback, recipient delivery and another AI's
  consumption are distinct; no response claims that an AI read the record.
- All `turn.commit` work is local. It deliberately does not call the current
  client's optional background notification, because the old protocol promises
  a network-free commit path. Operators use the old lifecycle/flush window or
  an explicit local-retry integration.
- `session.open` with `compact` performs no local flush, provider call or worker
  launch. Other reasons reuse the approved bounded sync configuration; they
  never enroll an identity or discover an account.
- Index counts describe current records/relations, not the old fragment-index
  implementation. Queue counts describe this bridge's accepted intents, not
  every other client adapter's queue.

The capability response advertises these differences instead of claiming that
all historical storage and publication semantics are unchanged. A host that
assumed a non-null Git commit must update that assumption; a host following
the negotiated protocol can use local durability and explicit flush results.

## Limits and recovery scope

The bridge caps active sessions at 128, staged/pending turns at 256, pending
visible text at 32 MiB, each control-receipt collection at 100,000 rows,
original-ID mappings at 250,000 rows, and its control DB at 256 MiB.
A local flush attempts at most four intents by default;
the explicit API allows 1–16. Each canonical projection has at most 64 records.
Frozen capture bodies have their own aggregate 32 MiB/256-pending-plan bound;
saved plans retain at most 100,000 historical headers, not duplicated bodies.
Limits fail visibly; there is no silent receipt eviction that could permit a
duplicate write. Local SQLite transactions are not hard real-time operations.

The existing [memory snapshot](BACKUP.md) preserves completed canonical records,
signatures and core receipts, but **not this live control database, temporary
visible text or old-ID migration map**. It is not a whole-client recovery image.
The bridge binds state to the selected Vault path and actual store ID; a new
restored store cannot silently reuse an old pending queue or its receipt map.

The separate [whole-client recovery workflow](BACKUP.md) can preserve explicitly
selected compatibility control state, including its pending visible intent
and verified original-ID mapping, as private inert evidence. V2 selections also
retain frozen plans and their ordered ID/hash references; saved projections
must resolve to the restored canonical records. It requires the
documented offline/quiesced boundary, restores to a new location and does not
restore signing credentials, host permissions or sync authorization. Explicit
local activation validates and rebinds that control state before any local
replay; pending uploads need a separately authorized new stream. Reading a
backup receipt is not a fresh current-trust or remote-delivery acknowledgement.

Protected compatibility state uses private files on POSIX and the shared native
ACL/handle profile on Windows local fixed NTFS volumes. Database and surviving
journal/WAL/SHM files are checked; private directory inheritance protects new
sidecars. Windows does not use simulated `chmod` protection and unsupported
volumes/ACLs fail closed. See [platform scope](PLATFORMS.md). This release has
source/static review of those branches, not a Windows runtime validation claim.

The shared publication/privacy scanner is best-effort: known secret/path matches
are blocked, but it is not comprehensive DLP. No message, error or callback can
turn remembered data into an instruction, authorization, execution permission,
agent launch or logging exemption.
