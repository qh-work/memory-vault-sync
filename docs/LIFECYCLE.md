# Local visible-turn lifecycle v1

This optional adapter lets an authorized local runtime stage a visible turn,
commit it to the shared Memory Vault, cancel an uncommitted turn, and read back
durable receipts after process restarts. It has no model/vendor dependency,
network connection, auto-start worker, transcript scanner or execution gateway.

This is a **new profile**, `universal-memory-lifecycle/v1`, with request schema
`universal-memory-lifecycle-request/v1` and result schema
`universal-memory-lifecycle-result/v1`. It is **not drop-in wire compatibility
with v0.21**: old envelope names, historical fields and Git/task runtime behavior
are not accepted. Operation names and visible-turn meanings are retained.

The implementation is supplied for review. No tests, runtime checks or host
installation checks were run for this change; publication is not evidence of
successful capture in a particular client.

## One store, optional local correlation

The adapter calls the same `Vault` as the lightweight core, configured protocol
and MCP client. A committed turn produces an `episode` and a `continuity` record
linked by `derived_from`. It does not create a task or project parent. Temporary
`session_handle` and `turn_handle` values never enter canonical records; closing
a session cannot delete, hide or invalidate its long-term memories.

The nearby lifecycle SQLite file is only private staging, state transitions and
content-free retry receipts. It is not a copy of the memory database. A session
is a local grouping of pending operations, not a memory ownership boundary.
Recall and current-state handoff remain dynamic core `recall` / `handoff` views,
queried independently of any session handle through the configured `protocol`
entry or MCP tools.

All supplied text is **caller-reported**, not host-witnessed. A successful commit
does not establish completion of a task, truth of the text, permission to act,
current signature trust or delivery to another device. The core's authority
envelope stays unchanged: memory is evidence, not instruction or authorization.

## Configure and launch explicitly

Use the same operator-controlled client configuration as the other adapters.
For a new configuration with visible-turn capture deliberately enabled:

```bash
python3 /absolute/path/memory-vault-sync/memory_vault_client.py configure \
  --capture-visible-turns
```

Omitting `--vault` selects the core's default path at configuration time.
Existing configuration files are never overwritten; review/edit the private
configuration explicitly when changing an existing installation. Optional
`--config`, `--vault`, signing and trust settings are described in
[CLIENTS.md](CLIENTS.md).

Start one foreground NDJSON process when the host authorizes it:

```bash
python3 /absolute/path/memory-vault-sync/memory_vault_client.py \
  --config /absolute/private/control/client.json lifecycle --serve
```

The equivalent standalone module, with its adjacent client/core modules, is:

```bash
python3 /absolute/path/memory-vault-sync/memory_vault_lifecycle.py \
  --config /absolute/private/control/client.json --serve
```

Without `--serve`, either entry reads one JSON request from stdin. With it, each
UTF-8 line contains one request and receives one response; EOF ends the process.
It is not MCP JSON-RPC. Stdout carries protocol results only; no response is a
host permission decision. The runtime must arrange its own authorized event
delivery. This does not claim that ChatGPT Work exposes automatic lifecycle
events, and it does not install or modify any client's hooks.

## Operations

Every request requires `schema_version` and `op`. Every operation except
`capabilities` also requires a stable `request_id` matching
`req_[A-Za-z0-9_-]{8,96}`. IDs must be unique to the logical operation; use a
random unique suffix in actual integrations. Preserve the exact request for
retries, including whether optional fields were omitted. Extra fields are
rejected. Task IDs, native conversation IDs and transcript paths are not inputs.

| Operation | Additional fields | Meaning of successful receipt |
| --- | --- | --- |
| `capabilities` | Optional `request_id` | Describes this profile; no config, directories or database created |
| `session.open` | None | Durably returns a local `ses_…` handle; no memory written |
| `turn.input` | `session_handle`, `user` | Durably stages only that visible prompt and returns `turn_…`; no memory written |
| `turn.commit` | `turn_handle`, `assistant`; optional `continuity` | Episode, linked continuity and completion receipt were committed locally |
| `turn.abort` | `turn_handle` | The turn did not enter commit; active staging was discarded |
| `session.close` | `session_handle` | All still-staged inputs in this session were cancelled; existing memory remains |

Capabilities example:

```json
{"schema_version":"universal-memory-lifecycle-request/v1","op":"capabilities"}
```

Open a session:

```json
{"schema_version":"universal-memory-lifecycle-request/v1","op":"session.open","request_id":"req_example_open_0001"}
```

Use the **returned** `session_handle` for input. The sample handles below are
placeholders, not predefined IDs:

```json
{"schema_version":"universal-memory-lifecycle-request/v1","op":"turn.input","request_id":"req_example_input_0001","session_handle":"ses_0123456789abcdef0123456789abcdef","user":"Please review the documented import boundaries."}
```

Use the returned `turn_handle` when the final visible reply is ready:

```json
{"schema_version":"universal-memory-lifecycle-request/v1","op":"turn.commit","request_id":"req_example_commit_0001","turn_handle":"turn_0123456789abcdef0123456789abcdef","assistant":"I reviewed the documentation. Portable unsigned imports are quarantined by default.","continuity":"Documentation review completed; runtime import behavior was not tested."}
```

If the turn was cancelled **before submitting commit**, abort it instead:

```json
{"schema_version":"universal-memory-lifecycle-request/v1","op":"turn.abort","request_id":"req_example_abort_0001","turn_handle":"turn_0123456789abcdef0123456789abcdef"}
```

Close when no commit is pending:

```json
{"schema_version":"universal-memory-lifecycle-request/v1","op":"session.close","request_id":"req_example_close_0001","session_handle":"ses_0123456789abcdef0123456789abcdef"}
```

`continuity` is visible summary text, not hidden reasoning. If absent, a bounded
excerpt of the supplied prompt/reply is frozen before writing. The adapter does
not invent a plan, next action or a verified success claim. Never pass secrets,
unapproved private material, hidden reasoning or unrelated conversations.

Machine-readable contracts are provided as
[request schema](../schemas/lifecycle-request.schema.json) and
[result schema](../schemas/lifecycle-result.schema.json). Schemas describe JSON
structure; the runtime also enforces UTF-8 byte limits, local handle existence,
state transitions and request-ID conflicts.

## Persistence, retries and cancellation

The state transitions are deliberately small:

```text
turn.input → staged → turn.commit → committing → committed
               └── turn.abort / session.close → aborted
```

Local SQLite transactions serialize the choice between `staged → committing`
and `staged → aborted`. The committing marker and complete final payload become
durable **before** any canonical write. The core then writes the episode and
linked continuity using distinct stable idempotency receipts. These are two
canonical transactions, not a fictitious distributed atomic transaction.

- After both writes and the lifecycle completion receipt are durable, the
  response has `ok: true`, `result.state: committed`, `memory_saved: true`, and
  `episode_id` / `continuity_id`. A lost response can be recovered by resending
  the exact original commit request.
- An interruption after the episode alone leaves the commit frozen. When
  available, an error's `partial_result` identifies the saved episode; retrying
  the same request resumes the continuity write without duplicating the episode.
  `resume_same_request: true` means the original operation must be resumed, not
  replaced with a fresh ID. A failure response never proves that no memory was
  written.
- An abort that wins before the committing marker prevents that turn from
  being saved. Later commit attempts return `turn_aborted`.
- Once commit starts, abort returns `commit_started_cannot_abort`, even if a
  temporary error happened before the first canonical write. This is a precise
  cancellation boundary, not an attempt to undo append-only memory. A committed
  turn returns `turn_already_committed` to a new abort.
- `session.close` refuses a session with any committing turn, returning
  `session_commit_in_progress`; it does not partly cancel other inputs and then
  claim the session closed. Resolve the frozen commit before closing.
- Reusing an accepted request ID with changed arguments returns
  `request_id_conflict`. Parallel exact retries have the same canonical effects.
  A second commit request ID for an already-committing turn is rejected.

Completion receipts contain IDs, digests and outcomes, not the visible text.
On replay `replayed: true` identifies a historical response and
`result.current_state` reports the handle's current local state. For example,
replaying a successful input after abort still shows its original `state:
staged`, but `current_state: aborted`; it never stages that prompt again.

The commit receipt's scope is explicitly
`local_save_not_current_trust_or_remote_delivery`. No stale `verification`
assertion is replayed. Query the configured protocol/MCP read interface for
current trust-aware views; a revoked key can remove an earlier record from
normal context without deleting its historical local-save receipt.

Disabling capture forbids new session/input/commit work and resuming incomplete
commits. An exact canonical-request match may still replay a completed receipt from existing
local state in SQLite read-only mode, without creating files or writing memory.
Explicit abort/close remain available for uncommitted staging. If a frozen
commit needs a repaired signing/trust configuration, its text is retained for a
deliberate same-request retry; nothing silently switches to unsigned writes.

## Local state and limits

The control file is `<client-config-stem>.state/lifecycle-v1.sqlite3` beside the
chosen configuration. On POSIX it is `0600` beneath a `0700` directory, owned by
the current user; symlink and nonregular-file paths are rejected. SQLite uses
full synchronization and bounded local lock waits. The unsigned route can use
the platform's ordinary filesystem access; protected Windows signing remains
subject to the trust module's documented ACL limitation.

Only explicitly supplied visible text is staged. After commit or abort, its
active staging fields are cleared and content-free receipts remain. This is
normal documented state management, **not secure erasure of backups/snapshots**,
and no host log is read, disabled or removed. Deleting this control file loses
its handle/retry history; do not delete it while a commit is unresolved.

The state is bound to the configured canonical Vault path. Changing that path
while reusing this state returns `lifecycle_vault_changed`; use a distinct
configuration for a different Vault. Do not copy an active SQLite database onto
a multi-host shared filesystem. Cross-device exchange remains the explicit
portable/signed transfer route, outside the lifecycle critical path.

Limits apply cumulatively: one request is at most 2 MiB; each user/assistant
part is at most 480 KiB; an explicit continuity is at most 32 KiB. All sizes are
UTF-8 bytes, not characters, and a frame's JSON escaping also counts toward its
frame limit. There may be at most 128 open sessions, 256 staged/committing turns
and 32 MiB of pending text. Resolve or explicitly abort staged work when a limit
is reached. Closed handles and completed receipts are retained for exact retries;
there is no automatic background cleanup or retry worker.

## Suggested independent acceptance checks

Contributors can verify these in temporary synthetic directories, with no real
conversations or credentials: configure without `--vault`; commit via lifecycle
and read via configured protocol/MCP; exact replay after response loss; abort
before commit; concurrent commit/abort; interruption between the two canonical
writes; capture disabled after a completed save; current trust after revocation;
and a full portable or signed exchange into another model's authorized runtime.
These are review/acceptance instructions, not tests run during this change.
