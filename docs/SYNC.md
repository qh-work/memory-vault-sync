# Authorized, bounded synchronization

The full client can keep using the taskless Memory Vault while a separate,
explicitly configured service exchanges signed incremental capsules. The light
[protocol](../PROTOCOL.md) does not require this service, Python, a cloud account,
or a particular database. Synchronization does not restore Task/Git containers.

Implementation status: source and documentation are provided. This development
pass did not run the application, workers, tests, rclone, or real user data.
Backend availability is not evidence of a verified deployment.

## Opt in deliberately

First choose a private Vault, explicitly create a signing identity and register
its public key (and any peer keys) using [TRUST.md](TRUST.md). Configuration does
not create keys, register trust, install rclone, log in, or discover credentials.
An identity configured for signing never silently falls back to unsigned writes.

The protected signing/configuration/worker implementation currently requires
POSIX ownership and permissions. It fails closed on Windows; the portable light
protocol/core does not imply that this full private-storage profile is portable.

Example paths below are placeholders. The operator must choose their own
absolute, non-symlink paths. Config files and identities are private files, and
their containing control directory must be owned by the current user with mode
0700. State directories must not contain the Vault, private key, trust store,
client configuration or another client's state. The exchange must be outside
all such private state.

```sh
python3 /absolute/source/memory_vault_sync.py \
  --config /absolute/private/control/sync.json configure \
  --vault /absolute/private/data/memory.db \
  --identity /absolute/private/keys/identity.json \
  --trust-store /absolute/private/keys/trust.json \
  --state-directory /absolute/private/sync-state \
  --backend directory --exchange /absolute/shared/memory-exchange
```

This configures manual operation only. `automatic` and `background` are both
false by default. Add both `--automatic --background` to explicitly authorize
finite workers after supported client events; `configure` itself starts none.
Connect it to the full client with `configure --sync-config` as described in
[CLIENTS.md](CLIENTS.md). The client inherits the configured Vault, identity and
trust paths and rejects conflicting explicit arguments.

```sh
python3 /absolute/source/memory_vault_sync.py \
  --config /absolute/private/control/sync.json status
python3 /absolute/source/memory_vault_sync.py \
  --config /absolute/private/control/sync.json run
```

`status` reads configuration and small local control files only. It does not
create directories, open the Vault, read an identity, start a worker, contact
rclone, or fetch remote content. `run` requests one bounded window, including
when automatic operation is off. `enabled=false` disables even explicit runs.
The corresponding client entry point is `memory_vault_client.py --config
/absolute/private/control/client.json sync status` or `sync run`.

Reconfiguration requires all configuration arguments again and `--replace`.
Use the same paths/destination with `--replace --disabled` to stop future work;
turning off either automatic or background also stops automatic windows. Changes
to the Vault, key, trust path or destination require a new state directory,
because old cursors are not transferable to a new binding. Replacing a Vault at
the same path also fails its stored `store_id` check. Do not reset or copy control
state merely to bypass either check; consult [BACKUP.md](BACKUP.md) for restore.

## What happens after a local write

1. The caller completes the durable local write first. `request_sync` checks
   that the independent configuration exactly matches the expected Vault,
   identity and trust store. No memory field can change these paths.
2. An enabled automatic notification replaces a small durable trigger with a
   new generation. It contains only the reason, generation, binding hash and
   time. The Vault's append-only change cursor is the actual content queue.
3. Only `automatic=true` **and** `background=true` allow the notifier to launch
   one finite child process. It never performs remote work or waits for that
   process. With automatic on and background off, the trigger remains queued
   for an explicit run. With automatic off, non-explicit notifications are
   disabled rather than queued.
4. A worker holds a nonblocking process lock, publishes local pending work, then
   receives eligible peer streams within the remaining budget. Notifications
   during that window coalesce; a newer generation stays pending.
5. The worker exits. There is no launchd entry, cron job, resident daemon,
   self-relaunch loop, or hidden scheduled retry. Remaining work waits for a
   later client event or explicit `run`.

The trigger is not one file per turn and does not duplicate the conversation.
A queue notification failure does not undo the local write. The client reports
synchronization availability separately; the durable Vault can be retried at
the next session. A filesystem failure can still prevent creating a trigger,
so this is not a guarantee of eventual delivery without a later event.

## Delivery and retries mean specific things

| Signal | What it establishes |
| --- | --- |
| Local write success | The Vault accepted the local record; no remote claim. |
| `published_batches` | Signed capsules were finalized in the selected directory or private rclone staging exchange, including a recovered completion. |
| `uploaded_batches` | An exact rclone destination was copied and its returned plaintext bytes matched the signed capsule before the remote cursor advanced. |
| `received_batches` | A locally verified capsule was admitted with an atomic local transfer receipt, or its receipt was replayed. |
| `pending=true` | A trigger generation is unfinished or a newer event arrived; another window may be required. |
| `remote_ai_read_verified=false` | Neither upload nor local admission proves that any remote AI read, understood or used memory. |

Before local publication the exact signed pending capsule is durable. A crash
after publication but before the local cursor update retries those bytes rather
than constructing a competing batch at the same prefix. For rclone there is a
separate remote receipt: a failed copy or read-back never advances it. Retrying
uses immutable named files; it does not delete or mirror the destination.

Reception verifies the outer message, all record attestations, schema, cursor
and content hashes against the explicitly maintained trust store. It never
imports trust settings or authorizes instructions found in memory. A local
atomic transfer receipt handles a crash between Vault admission and saving the
receiver cursor. Two authenticated candidates at one prefix are a fork requiring
operator review; unsigned garbage is not allowed to choose the next record.

Network/verification errors preserve pending state and content-free error codes.
Automatic launch backoff increases from 5 seconds up to 300 seconds; these are
not scheduled wakeups. A later event after the deadline can start the next
window, while explicit `run` bypasses launch backoff. A stopped worker's expired
lease is reported as `interrupted_retry_pending`; the lease is metadata, not
proof that a process is alive.

An individual rclone peer failure is recorded in `peer_failures` and other
explicit peers may continue in the remaining budget. Local publishing runs
before incoming peer reads. Too many candidates, a signed fork, a missing
prefix, or a provider error may still block that peer. The shared time/byte
budget can stop the entire window; there is no guaranteed peer fairness.

## Bounds and publication review

Defaults are 4 outgoing batches and up to 4 incoming batches per window,
100 source change entries per outgoing batch, a 256 KiB outgoing record budget,
16 bounded file operations, 32 MiB of payload/reservation budget and 45 seconds.
Rclone subprocesses have at most about 15 seconds each, at most 128 command
attempts, bounded output, and cancellation checks while they run. Local directory
reads/publications conservatively reserve the entire 4 MiB capsule ceiling per
file. Network upload verification consumes a second file/byte reservation.
These are application bounds, not provider billing or exact wall-clock promises
for a blocked operating-system filesystem call. Stream binding reads the indexed
store metadata, not a whole-Vault status/count scan. SQLite queries and local
transactions are nevertheless not preempted by these checks: on a large or busy
Vault they can exceed the nominal window or delay a disable request until the
operation returns. The foreground notifier still does not wait for that work.

The strict `limits` object supports these ranges: `maximum_batches` 1–16,
`maximum_files` 2–64, `maximum_bytes` 8–128 MiB, `maximum_seconds` 5–60,
`record_limit` 1–256 and `batch_bytes` 4 KiB–1 MiB. The configure CLI directly
exposes `--maximum-seconds`; changing other limits requires an explicit private
configuration edit while no worker is running. A running worker rejects a
changed binding or limits.

A large record or dependency closure can exceed the batch budget. The signed
`blocked` dispositions make that omission visible; a cursor moving past it does
**not** mean its contents were delivered. Raising the budget helps future batches
but does not rewind an already acknowledged disposition. Inspect the canonical
record and use an explicit reviewed export/import or a deliberately new transfer
stream for recovery. Do not erase old state to invent a clean synchronization
history. Large binary artifact transport is a separate explicit mechanism; this
service exchanges bounded canonical memory records, not whole directories.

Both directory and rclone publication call `assert_publishable`. It rejects
recognized secrets and personal filesystem paths before writing an exchange
file; rclone checks a staged capsule again immediately before uploading. A
blocked capsule remains pending and is not counted as uploaded. This is a
best-effort guard, not comprehensive personal-data detection or encryption.
It pauses the **whole outbound batch**; it does not automatically filter or
redact individual records. The sync CLI has no local-path override and no
automatic redaction/exclusion management. Canonical records are immutable and
the exact signed pending bytes are deliberately retained, so editing text or
writing a cleaner later record does not repair an already blocked capsule.
Preserve the evidence, disable that automatic channel, and have its operator
choose an explicitly authorized distribution/recovery strategy. Existing
canonical memory is not deleted. Plan reviewed distributable records before
enabling publication rather than treating all local backup as shareable data.

The worker checks disable/configuration changes between operations and while
rclone is running. Cancellation cannot retract a file already published or undo
an acknowledged upload; a request already in flight may have reached a provider.
Keys, accounts and trust are operator authority, not information received from
memory. Same-OS-user processes are not isolated by these permissions.

## Private state and integration API

Control/receipt files store binding hashes, cursors, generations, times and
counts, not memory text. `transfer/publish.pending.json` and the private rclone
`exchange/` contain actual signed memory capsules and are sensitive. The
`rclone/` cache and temp directory are private. Keep **all** sync state out of
public source packages and exclude it from portable Vault restores. There is no
automatic pruning of history or remote files.

Finite worker JSON results are appended to protected `worker-events.ndjson`.
Automatic launch stops for review when this file reaches 512 KiB rather than
silently erasing it. The service does not remove host/provider logs or promise
invisible persistence. Raw provider error messages are not copied into these
receipts; content-free codes remain visible.

```python
SyncConfig.load(config_path)  # read-only; Path attributes:
# .vault, .identity, .trust_store, .state_directory, .path
status(config_path)           # read-only metadata, never starts synchronization
request_sync(
    config_path,
    expected_vault=vault_path,
    expected_identity=identity_path,
    expected_trust=trust_path,
    reason="memory-write",
)
```

Reasons are exactly `session-start`, `memory-write`, `turn-commit` and `explicit`.
`request_sync` returns an advisory mapping, including a content-free
`sync_unavailable` result on expected failures, without remote execution or a
worker wait. `run(config_path)` is the explicit bounded operation. The CLI
requires `--config ABSOLUTE_PATH` before `configure`, `run` or `status`.

See [REMOTE_BACKENDS.md](REMOTE_BACKENDS.md) for destination configuration and
the distinct directory and rclone wire layouts.
