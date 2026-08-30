# Multi-host access to one Vault

The authorized plugin route and the standalone protocol route share records,
not a task hierarchy. `memory_vault_hosts.py` restores visible-event integration
for additional hosts through the existing client configuration and
`universal-memory-lifecycle/v1`. It is a new adapter profile, **not** the complete
old v0.21 wire protocol or an import of its runtime.

These source adapters and example configurations received static review only.
No host was installed, launched, or integration-tested for this change. Host
version, hook trust, Python availability, permissions, and actual event delivery
still require validation by the installing operator.

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
| Final reply | `Stop` | `AfterAgent` | `turn.commit` | Commit the paired visible turn and source-linked continuity through lifecycle v1 |
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
created 0700/0600; Windows installations must restrict the configuration/state
directory using an appropriate operator-managed ACL. No logs are hidden or
disabled. Receipt files deliberately do not retain copied conversation text or
cached signature-trust assertions.

Requests are durably staged before invocation. Completed lifecycle receipts
are recorded before removing the corresponding pending request. Exact retries
reuse deterministic request IDs and the same content; changed text conflicts
instead of silently creating a second saved turn. The lifecycle's transaction
arbitrates cancel versus commit: staged input can be discarded, but a frozen or
partly written commit cannot honestly be reported as rolled back.

An authorized non-compaction session start retries at most eight pending final
saves for that session. A crash before the native session resumes can also be
handled explicitly, without knowing its original native ID:

```text
python3 memory_vault_client.py --config /absolute/path/to/private/client.json host --host claude-code --event status
```

Send `{}` on stdin. This lists only queue counts and session hashes, without
opening pending bodies, creating directories, or initializing a Vault. Select a
returned hash and use the same command with `--event recover`, sending
`{"session_key":"<64-hex-session-hash>"}`. Repeat for further batches; inspect
`result.recovery.confirmed`, `error_codes`, and `remaining_jobs`. The administrative
events work with all three `--host` choices. Recovery retries only final-save
jobs; unmatched inputs remain staged until a cancel, later input, or close.
It never invents missing user/final text or scans transcripts.
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
but cannot resume a partial save. Keep pending evidence for explicit repair;
do not delete the control directory to force a commit or erase cancellation
state. Corrupt or retargeted control state is rejected, not silently reset.

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
also enforces its own global limits. Session locks have a bounded wait and are
released by process exit. Receipt metadata is retained for exact retry; it is
not cleared at compaction or session close.

The generic event profile and underlying lifecycle are explicit alternative
entry points, not a privilege escalation. A runtime without approved hooks can
still call the MCP tools or standalone memory protocol within its existing
filesystem and tool permissions. Reading these instructions alone does not
grant persistence, network access, or permission to install anything.
