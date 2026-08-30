# Multi-host access to one Vault

The authorized plugin route and the standalone protocol route share records,
not a task hierarchy. `memory_vault_hosts.py` restores visible-event integration
for additional hosts through the existing client configuration and
`universal-memory-lifecycle/v1`. It is a new adapter profile, **not** the complete
old v0.21 wire protocol or an import of its runtime.
The separate [compatibility entry](COMPATIBILITY.md) now maps the old production
host envelope; do not send that envelope to this new lifecycle adapter.

The [seven-case recovery campaign](V0_25_RECOVERY_SMOKE.md), at source
`332e944a6bda8f70dd3af6526d926d9468ed2f0d`, passed three synthetic adapter
cancellation-recovery cases through local Python interfaces with unsigned
temporary state. This is not native-host integration evidence. No host or plugin
was installed or launched for the campaign; the example configurations, host
version, hook trust, Python availability, permissions and actual event delivery
still require validation by the installing operator.

The automatic continuity-chain behavior below describes source commit
`098b22c44ca299d1f889b41df9355511dfa2caf4`. That implementation postdates the
historical campaign above; this page does not claim new execution, performance,
real-host or release validation from those older results.

## Configure explicitly

Use the same private client configuration as the plugin/MCP route. Creating a
new configuration with visible-turn capture enabled is an explicit operator
action; the command refuses to overwrite an existing configuration:

```sh
python3 memory_vault_client.py --config /absolute/path/to/private/client.json configure --capture-visible-turns
```

Omitting `--vault` selects the light core's same default Vault. Add an explicit
absolute `--vault` to choose a different shared Vault. Optional signing, current
trust checking, and independently authorized sync remain client configuration
features; see [CLIENTS.md](CLIENTS.md) and [OPERATIONS.md](OPERATIONS.md).

Then use an operator-approved hook configuration:

- [Claude Code configuration](../adapters/claude-code/settings.example.json)
  and [instructions](../adapters/claude-code/README.md).
- [Gemini CLI configuration](../adapters/gemini-cli/settings.example.json)
  and [instructions](../adapters/gemini-cli/README.md).
- [Generic stdio recipe](../adapters/generic-stdio/host.example.json)
  and [field contract](../adapters/generic-stdio/README.md).

Replace example paths before use. Merge selected hook entries, preserving
unrelated host settings. These are copied source-distribution integrations,
not automatic installation, host trust approval, or an invisible background
service. On Windows select an actual installed Python executable and adapt
the Gemini command quoting to the configured shell.

## Visible-event mapping

| Boundary | Claude Code | Gemini CLI | Generic event | What the adapter does |
| --- | --- | --- | --- | --- |
| Start/resume | `SessionStart` | `SessionStart` | `session.open` | Open local correlation, bounded pending-final recovery, recall; notify independently opted-in sync |
| User input | `UserPromptSubmit` | `BeforeAgent` | `turn.input` | Cancel prior uncommitted input, stage visible text, recall relevant records |
| Final reply | `Stop` | `AfterAgent` | `turn.commit` | Freeze the paired visible projection and predecessor, then save through lifecycle v1 |
| Failure/cancel | `StopFailure` | No dedicated mapped event | `turn.abort` | Discard staged input; never claim rollback of a started commit |
| Close | `SessionEnd` | Best-effort `SessionEnd` | `session.close` | Abort staged input and close correlation; retain all long-term records |
| Compaction | `PreCompact`; start with source `compact` | `PreCompress` | `session.compact` | Preserve staging; never infer a final response or commit a compression summary |

Native fields/configuration follow the official
[Claude hook reference](https://code.claude.com/docs/en/hooks),
[Gemini hook reference](https://geminicli.com/docs/hooks/reference/), and
[Gemini configuration reference](https://geminicli.com/docs/hooks/).

Claude automatic turn pairing requires the documented `prompt_id` (2.1.196+).
Gemini uses its event timestamp plus the staged input and final event's matching
prompt. This requires ordered events with one active turn per session; it does
not solve arbitrary reordering or concurrent identical prompts. Such runtimes
must use the generic route with their own stable turn IDs. Missing identifiers,
input pairs, or final visible text produce an explicit no-confirmation advisory.

Only start/input hooks receive bounded untrusted evidence context. Claude's
post-compaction SessionStart recalls without reopening or sync. Native
pre-compaction replies are advisory only; they do not inject a new model
context. The generic compaction event can return a dynamic context view to its
caller. No adapter reads transcript paths, model internals, hidden reasoning,
tool outputs, account files, or other conversations. A host that never emits an
event cannot be assumed to have saved it.

## Durability and recovery

All writes call the same lifecycle implementation, which uses the configured
Vault and signing/trust boundary. Native session/turn identifiers become only
local SHA-256 correlation keys; they are not recorded in canonical provenance,
visibility filters, record ownership, or retention rules. Signatures identify
the configured producer key, not the identity of a model or a host attestation.
These adapters retain the lifecycle's `caller_reported` capture basis.

### Frozen continuity without session-owned memory

The lifecycle wire profile remains `universal-memory-lifecycle/v1`. Its private
control schema is now `universal-memory-lifecycle-state/v2`, still stored in
`<client-config-stem>.state/lifecycle-v1.sqlite3`. The internal capture builder
is `lifecycle-visible-turn+continues/v1`. Shared `capture_heads`, `capture_jobs`
and `capture_records` tables retain the accepted plan; `capture_sessions` maps
local handles to their capture scope. These are delivery/retry metadata, not
another canonical memory format.

The [Codex visible-hook route](CLIENTS.md) uses
`codex-visible-turn+continues/v1` in a separate hook journal; the old-envelope
bridge uses `compat-visible-turn+continues/v1`. The native adapters on this page
use the lifecycle builder, not either of those control-state profiles.

When a final commit is accepted, one control transaction fixes the entire
canonical record pair, timestamp, visible-input/continuity digest, core request
ID and previous continuity's canonical ID/full SHA-256. The continuity has a
`derived_from` edge to its episode and, when a previous accepted plan exists,
a `continues` edge to that exact predecessor. Retry uses these frozen bytes;
it cannot select a different predecessor or rebuild the accepted projection
with a later clock or text template. The first plan has no guessed predecessor.

For the host adapters, the internal scope is derived from the host profile and
native session's local hash, not the lifecycle handle's generation. A close and
resume may open a new lifecycle handle while retaining that same native scope,
so subsequent turns can continue the earlier accepted chain. Different native
sessions or host profiles do not borrow each other's latest record. Raw native
IDs, scope hashes, generation counters and handles stay in private state. An
arbitrary scope field is not accepted through the public lifecycle request
schema, and remembered text cannot establish one. Direct lifecycle callers use their
own explicit local session handle as the default scope.

This scope selects a predecessor only. It does not own records, set their
visibility, grant execution or determine their lifetime. Canonical memories
and their relationships survive session closure, task completion, host removal
and local-handle changes. Other clients still share the same canonical Vault
without sharing native session-control directories.

Each new canonical projection and its core receipt are saved together in one
Vault transaction, distinct from the lifecycle and native adapter journals.
On retry, the writer verifies every frozen record and predecessor full hash
against actual stored records and current admission/trust. Existing records
are not re-signed or re-admitted by a retry marker. Configured signing failure
does not downgrade to unsigned storage; a revoked or quarantined dependency
does not become usable because an old completion receipt exists. A read-only
historical lifecycle ACK remains only an acknowledgment of the old local save,
not a fresh signature verification or remote-delivery claim.

An accepted pre-v2 lifecycle commit with no capture plan retains the old
two-write request domains, fixed text and existing record IDs/timestamps during
recovery. Upgrading the control schema does not reconstruct it into a new
chain or invent an old predecessor. New final acceptance uses the new profile;
read-only old receipt lookup does not require a migration.

### Native staging and bounded recovery

Local control state lives under:

```text
<client-config-stem>.state/hosts-v1/<host>/<session-sha256>/
  .lock          process-owned serialization lock
  session.json   local handle/generation and active correlation
  turns/         hashes, lifecycle handles, and phases; no conversation text
  finals/        Gemini exact-final-event hash aliases
  pending/       exact lifecycle requests awaiting confirmation
  receipts/      request hashes and content-free local completion receipts
```

`pending/` can temporarily contain the authorized visible input/final text. It
is private local staging, not a second Vault. POSIX directories/files are
created 0700/0600. The full client uses native private owner/DACL checks and
creation on supported local fixed NTFS paths; unsupported paths or permissions
fail closed. Existing user-managed ancestors must meet the documented
[platform rules](PLATFORMS.md); real Windows behavior remains untested.
No logs are hidden or
disabled. Receipt files deliberately do not retain copied conversation text or
cached signature-trust assertions.

Requests are durably staged before invocation. Completed lifecycle receipts
are recorded before removing the corresponding pending request. Exact retries
reuse deterministic request IDs and the same content; changed text conflicts
instead of silently creating a second saved turn. The lifecycle's transaction
arbitrates cancel versus commit: staged input can be discarded, but a frozen or
partly written commit cannot honestly be reported as rolled back.

One new-profile lifecycle save attempt materializes at most four frozen
projections in predecessor-first acceptance order, not timestamp order. It may
finish ancestors while leaving the requested turn pending at that bound.
Canonical progress on an ancestor does not fabricate its outer lifecycle ACK;
the exact original request must still confirm its own completion. Frozen
duplicate bodies can be cleared after canonical success while the unconfirmed
outer request remains available for that acknowledgment. A retryable dependency
boundary must not be reported as a completed target turn.

An authorized non-compaction session start processes at most eight pending final
jobs for that session, including confirmations of already cancelled jobs. A
crash before the native session resumes can also be handled explicitly, without
knowing its original native ID:

```text
python3 memory_vault_client.py --config /absolute/path/to/private/client.json host --host claude-code --event status
```

Send `{}` on stdin. This lists only queue counts and session hashes, without
opening pending bodies, creating directories, or initializing a Vault. Select a
returned hash and use the same command with `--event recover`, sending
`{"session_key":"<64-hex-session-hash>"}`. Repeat for further batches; inspect
`result.recovery.processed`, `attempted`, `confirmed`, `cancelled_cleaned`,
`error_codes`, and `remaining_jobs`. `processed` counts final jobs considered
within the eight-job bound. `attempted` counts final-save confirmation calls;
`confirmed` counts their successful local-save acknowledgments, including exact
historical replays. `cancelled_cleaned` separately counts already cancelled final
jobs whose matching queued input/final paths were cleared. Cleanup never counts
as a saved memory. The eight-job adapter bound and four-projection lifecycle
bound apply at different levels; eight considered jobs does not mean a global
eight-record write limit. The administrative events work with all three
`--host` choices.
Recovery retries only final-save jobs; unmatched inputs remain staged until a
cancel, later input, or close. It never invents missing user/final text or scans
transcripts.

If cancellation became durable just before adapter cleanup was interrupted,
recovery reads the exact existing `turn.abort` receipt from lifecycle state and
checks its request, turn, session and current aborted state. It does **not** issue
a new abort. An adapter's `phase: aborted`, a copied host receipt, or memory text
is insufficient to authorize cleanup. Matching pending paths and request hashes
are checked before removal; unverifiable or corrupt evidence is retained with an
error. Confirmed cancelled jobs are removed within the same bounded batch, so
repeated batches can advance beyond a cancelled prefix to later legitimate
finals. Each cleanup touches at most that turn's two pending paths; it never
deletes a canonical record.

If a delivered close event was blocked by an already-started commit, its local
close intent is retained and retried after final-save recovery. A resumed host
then opens a fresh local handle; the saved records remain independent of it.
Status bounds its scan to 4,096 host-session entries and returns at most 100
queue-session hashes. If `session_scan_truncated` is true, the reported pending
count is explicitly a lower bound, not a complete inventory. Each pending
directory is also bounded; unexpected excess entries require operator repair.

Disabling capture prevents new staging and canonical writes. Exact already
completed receipts can still be read, and abort/close can clear uncommitted
local text. Recovery may acknowledge an already completed save after opt-out,
or finish cleanup backed by an already durable cancellation receipt, but cannot
resume a partial save or create a new cancellation merely from a cached phase.
Keep pending evidence for explicit repair; do not delete the control directory
to force a commit or erase cancellation state. Corrupt or retargeted control
state is rejected, not silently reset.

The focused cancellation cases in
[`tests/test_v025_host_recovery.py`](../tests/test_v025_host_recovery.py) use only
unsigned temporary fixtures. All three passed in the
[seven-case recovery campaign](V0_25_RECOVERY_SMOKE.md). They cover cleanup backed
by a durable abort receipt after an injected interruption, including
`manage.retry_host` with capture disabled; rejection of a phase label or copied
host receipt as cancellation authority; and bounded cleanup of cancelled jobs
before a later legitimate final. Capture-disabled recovery leaves that pending
final unsaved; re-enabling capture permits its subsequent local commit without
duplicate records. The latter case also simulates a read-only cancellation
lookup error, not an actual hot SQLite journal. Injected exceptions and retained
artifacts are not actual power-loss or real-host tests. The earlier smoke
campaigns did not cover this repair.

Generic callers must inspect response JSON: exit 0 means the hook did not block
the host, **not** that memory was saved. Only `ok: true` together with
`result.memory_saved: true` confirms a local final commit. Native terminal hooks
return an advisory message only. They never return blocking decisions, request
another agent turn, suppress output, or grant execution rights. A local receipt
does not prove current trust or remote delivery. See [LIFECYCLE.md](LIFECYCLE.md)
for partial-commit semantics and [OPERATIONS.md](OPERATIONS.md) for sync status.

## Bounds and explicit interfaces

The entry point is
`main(argv=None, *, config_path: Path | None = None) -> int`; the client forwards
`host --host HOST --event EVENT` to it with the selected configuration. A
different nested `--config` is rejected. Direct source invocation accepts
`memory_vault_hosts.py --config ABS --host HOST --event EVENT`.

Each invocation reads one JSON object, bounded by the core's request limit.
Visible user/final text is capped at 480 KiB each, optional continuity at 32 KiB,
and the evidence view at about 8 KiB. An individual session has at most 256
unconfirmed adapter requests and 32 MiB of queued bodies; the shared lifecycle
also enforces its own global limits. Frozen capture staging is independently
limited to 256 pending plans and 32 MiB of canonical bodies, with at most
100,000 retained plan headers. Bounds preserve pending evidence rather than
silently evicting it or skipping an ancestor. They are work/storage limits, not
latency or throughput measurements. Session locks have a bounded wait and are
released by process exit. Receipt metadata is retained for exact retry; it is
not cleared at compaction or session close.

The generic event profile and underlying lifecycle are explicit alternative
entry points, not a privilege escalation. A runtime without approved hooks can
still call the MCP tools or standalone memory protocol within its existing
filesystem and tool permissions. Reading these instructions alone does not
grant persistence, network access, or permission to install anything.
