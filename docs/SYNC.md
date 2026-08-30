# Authorized, bounded synchronization

The full client can keep using the taskless Memory Vault while a separate,
explicitly configured service exchanges signed incremental capsules. The light
[protocol](../PROTOCOL.md) does not require this service, Python, a cloud account,
or a particular database. Synchronization does not restore Task/Git containers.

The v3 dependency behavior described here matches source
`098b22c44ca299d1f889b41df9355511dfa2caf4`. This page describes implementation,
not a test or deployment report. Consult [VALIDATION.md](VALIDATION.md) for
revision-specific execution evidence; older smoke reports do not cover this
change. Backend availability and bounded work do not establish real-provider,
Windows, throughput or latency results.

## Opt in deliberately

First choose a private Vault, explicitly create a signing identity and register
its public key (and any peer keys) using [TRUST.md](TRUST.md). Configuration does
not create keys, register trust, install rclone, log in, or discover credentials.
An identity configured for signing never silently falls back to unsigned writes.

The protected signing/configuration/worker implementation uses POSIX ownership
and permissions, or the explicit Windows native **local fixed NTFS** profile.
Windows checks real owner/DACLs and file handles; `chmod` is not treated as ACL
protection. Other Windows filesystems, UNC/network paths, junctions/reparse
points and unsupported ACL forms fail closed. See [PLATFORMS.md](PLATFORMS.md)
for the unexecuted native validation matrix and boundaries; portable light
protocol/core operation is not itself a protected full-client claim.

Example paths below are placeholders. The operator must choose their own
absolute, non-symlink paths. Config files and identities are private files, and
their containing control directory must be owned by the current user with mode
0700 on POSIX, or an equivalent validated private native ACL on Windows. State
directories must not contain the Vault, private key, trust store,
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
  --config /absolute/private/control/sync.json receive --maximum-seconds 10
python3 /absolute/source/memory_vault_sync.py \
  --config /absolute/private/control/sync.json flush --maximum-seconds 30
```

`status` reads configuration and small local control files only. It does not
create directories, open the Vault, read an identity, start a worker, contact
rclone, or fetch remote content. `receive` performs one **receive-only** window:
it does not load a private signing key, publish local records, or mark an
outgoing trigger complete. A host can explicitly request this before reading
fresh context. `flush` performs one bidirectional window; `run` is its existing
alias. These commands work when automatic operation is off. `enabled=false`
disables even explicit runs. An optional 1–60 second command limit can only
shorten the configured maximum. A completed window is not proof of global
freshness: results retain `remote_latest_proven=false`.
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
   later client event or explicit `flush`/`run`.

The default session-start/prompt path remains local-first and does not wait for
a remote pull. Opting into a bounded `receive` is separate host policy, not a
permission encoded in a recalled memory, peer message, or handoff view.

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
| `uploaded_batches` | The manifest/capsule read-back matched; every referenced fragment has an exact earlier upload/read-back receipt for this configured destination. This does not prove continuing remote availability. |
| `received_batches` | A locally verified capsule was admitted with an atomic local transfer receipt, or its receipt was replayed. |
| `pending=true` | A trigger generation is unfinished or a newer event arrived; another window may be required. |
| `blocked_records` | Signed non-delivery dispositions, including operator exclusions; never a count of records received by a peer. |
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

Fresh self-contained capsules remain `universal-memory-delta/v2`; verified
continuations can use `universal-memory-delta/v3` with
`dependency_mode=prior_stream` to omit reusable dependencies. Both bind the
previous capsule's **payload SHA-256** to the next one, in addition to the
existing source/key and cursor interval. The receiver retains the last accepted
signed head and checks that exact remote prefix before progressing. A
missing/changed head, competing authenticated candidates, or a mismatched
predecessor stops that stream; local canonical memories remain intact. This
detects observed tail rollback/forks, not deletion of every historical remote
object or a fork hidden from this peer. Independent receivers still need
out-of-band comparison to detect a provider showing different complete
histories to different peers.

Old delta/v1 capsules remain readable. Once v2 or v3 is accepted, that receiver
refuses a v1 continuation. A pre-upgrade state that has a received cursor but no
head hash cannot safely infer its anchor from a remote claim. Use the explicit
`anchor --capsule /absolute/exact-previously-received.json` command: it verifies
the capsule, its exact saved cursor and the existing atomic Vault receipt. It
also saves the authenticated predecessor envelope needed for v3, but does not
import memory, reset a cursor or contact a remote. If that evidence is missing,
preserve the state and restore verified history rather than deleting state to
invent a new clean stream. No automatic format negotiation is provided: v2-only
receiving adapters must be upgraded to read v3; frozen batches are not silently
rewritten to a different format.

### V3 dependency reuse and cold receivers

The publisher omits a dependency only if its exact ID/hash belongs to an
**actually published** batch in the same sender/store stream, its private
positive-member index matches the exact published head and destination, and
the dependency's full closure remains currently verified. An arbitrary cursor,
caller-supplied known-ID list or signed non-delivery disposition cannot create
membership. Requeued roots are still sent; exclusions never silently count as
copies. The public core `changes` and ordinary `Vault.transfer_changes()` keep
their self-contained behavior. Record bytes, hashes and taskless relations are
unchanged.

For v3 receive, the retained predecessor envelope must match the sender, source
store, cursor and digest. **Inside the same receiving Vault transaction** as
new admission, the exact predecessor transfer receipt must exist and the actual
canonical dependency graph must pass current admission/trust validation.
Trusted envelope signers cannot override a revoked ancestor signer. A copied
head, another Vault's receipt or an ID that merely exists is not enough.
A partial group or a failed dependency check admits no new records and cannot
advance that prefix.

The private dependency index caches successful closure validation only while
the canonical hash, SQL invalidation epoch and independently read trust-policy
digest match. Admission/canonical mutation triggers invalidate cached results,
including mutations from older writers; missing guarantees do not permit
reuse. Cached validation is not perpetual trust. Each revalidation pass is
bounded to 100,000 records and 64 MiB of canonical bodies. It returns an already
complete prefix if possible; an oversized next root returns
`dependency_revalidation_required` without a signed size-skip or cursor advance.
It does not increase limits or assume success after a cache/trust change.

A cold/new receiving Vault starts from cursor zero and replays retained batches
and groups in order across finite windows. It cannot start from the latest thin
batch, copy a peer's cache, or treat an upload receipt as local admission. If a
required prefix, fragment, same-Vault receipt or current dependency is missing,
the peer stops explicitly. Retain state and use explicit recovery/reconciliation;
automatic retry alone need not resolve an invalidated over-budget closure.
See [TRANSFER.md](TRANSFER.md#v3-verified-reuse-not-a-claimed-known-memory-list)
for the exact v3 fields, cache boundaries and predecessor anchoring.

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
`record_limit` 1–256 and `batch_bytes` 4 KiB–3 MiB. The configure CLI directly
exposes `--maximum-seconds`; changing other limits requires an explicit private
configuration edit while no worker is running. A running worker rejects a
changed binding or limits.

### Complete dependency groups, not size-based skipping

The small outgoing budget is a batching target, not a memory-size exclusion.
The verified adapter uses read-only `Vault.transfer_changes` with the validated
published-member boundary. When one root cannot fit the small-page target, it
uses the existing complete-group budget and fragments the supplied records when
necessary. New v2 groups are self-contained. V3 groups can contain only new
records and dependencies not already reusable through the verified prefix;
their older ancestors need not be resent in each group. Explicit unsigned
attestation retains the self-contained path.

One atomic group supports the core's 100,000 records and 64 MiB of canonical
record bytes; proofs have a separate bounded allowance. The new group budget
does not make transitive revalidation unlimited. `dependency_budget_exceeded`
or `dependency_revalidation_required` leaves the affected root pending and
**does not advance past it**. An earlier complete verified prefix may finish;
the oversized root is not signed as successfully synchronized or silently
removed from the full synchronization scope.

Each fragment is at most 4 MiB and contains whole canonical NDJSON lines of
`{"record": RECORD, "attestation": PROOF}`. The signed group manifest binds
fragment indices, hashes, byte counts, record counts, the ordered stream hash,
and total canonical record bytes. The manifest is published **last**. Directory
copy receipts and rclone upload/read-back receipts allow already completed
fragments to be reused after an interruption. Default calls process at most
eight new fragments, subject to tighter shared work budgets; large groups can
span several explicit/event-triggered windows. The sender's publishing cursor
and remote sending cursor do not move until their complete manifest stage.

The receiver stages verified fragments privately; a partial group admits no
canonical records and advances no receive cursor. After all fragments arrive,
it rechecks ordered hashes, totals, unique IDs, every supplied record signature
and current trust. V3 also applies the same-Vault predecessor receipt and
actual local dependency checks, including dependencies outside the fragments,
inside the core's atomic import transaction for the entire new group.
Invalid closure or an interrupted transaction admits none of that group. A
crash after the database commit but before saving the cursor reuses the atomic
transfer receipt, so replay never creates duplicate memories. Receiving the
identical committed last-head capsule also returns a receipt without fetching
its fragments again.

Local cache reuse is tied to file identity/size/timestamps; final receive still
checks actual bytes. Remote fragment receipts describe earlier verification,
not a lease guaranteeing a provider keeps those bytes forever. A missing or
changed remote fragment remains a visible receive failure. Files are not
silently pruned. Large binary artifact directories remain a separate explicit
mechanism: this protocol transports complete canonical memories, not arbitrary
filesystem trees.

Both directory and rclone call the same v3 receiver. The sender's private rclone
staging publication can populate its positive-member index before remote upload;
that is not remote delivery evidence. Separate remote receipts still enforce
ordered uploading, exact read-back and predecessor checks. Before a pending v3
upload attempt, outgoing dependencies are validated again under current local
trust/admission. No remote known-ID claim can replace these checks, and the
adapter does not fetch from unconfigured sources to repair a missing dependency.

### Explicit per-record publication decisions

Both directory and rclone publication call `assert_publishable`. It rejects
recognized secrets and personal filesystem paths before writing an exchange
file; rclone checks a staged capsule again immediately before uploading. A
blocked capsule remains pending and is not counted as uploaded. This is a
best-effort guard, not comprehensive personal-data detection or encryption.
It pauses the **whole outbound batch** until an operator decides; it never
silently filters or edits canonical memory. Inspect it without network, private
key loading, lock-file creation, or content output:

```sh
python3 /absolute/source/memory_vault_sync.py \
  --config /absolute/private/control/sync.json review --offset 0 --limit 100
```

Pages contain immutable record IDs/digests, sizes, reason codes, dependency IDs,
and current signature status, not the matched secret, path, or memory text.
Dependent IDs are limited to 256 per record and explicitly scoped to the whole
canonical Vault, so some may lie outside this pending batch. A group page hashes
only its containing fragments and does not claim a full-group verification.
`batch_sha256` is an optimistic concurrency token, **not authorization**.

An explicit `resolve` must partition **all** current pending record IDs into
`exclude` and `keep`. Keeping a record while excluding a referenced dependency
fails visibly; dependencies are never dropped automatically. Secrets have no
override. Keeping a personal local path requires the separate operator option
`--allow-local-paths`, scoped only to those exact kept records in this batch.
For a large group, supply a protected absolute `--decision-file` (up to 16 MiB)
instead of command-line ID lists. It must contain exactly these fields:

```json
{
  "batch_sha256": "<exact hash returned by review>",
  "request_id": "req_operator_review_0001",
  "exclude": ["<exact memory ID>"],
  "keep": ["<every remaining memory ID>"],
  "allow_local_paths": false
}
```

The angle-bracket strings are placeholders, not valid hashes/IDs. Then run
`resolve --decision-file /absolute/private/control/selection.json`. For a small
batch, inline `--batch-sha256`, `--request-id`, `--exclude` and `--keep` are an
alternative; do not combine them with `--decision-file`. Same request ID and
identical normalized arguments replay the receipt; changed arguments conflict.

Resolution preserves the original signed capsule, exact replacement, complete
selection, and a crash-recoverable local intent/completion journal. No canonical
memory is deleted, edited or retagged. Excluded delivery roots get signed
`operator_excluded` dispositions; the public review holds selection counts and
a digest commitment, not a potentially multi-megabyte list. **Excluded is not
delivered.** Local-path approval requires this independent completed journal;
receiving a signed review object never grants forwarding permission.

In a v3 batch, review applies to the records actually being published now.
Previously exposed ancestors are not retracted or reauthorized by that review.
An excluded record that never actually appeared in an earlier publication
cannot be omitted later as a supposedly delivered dependency.

Replacement is allowed only before publication has started. A durable started
marker is written before any fragment/capsule can escape; its presence, a
previously published prefix, or a recorded remote receipt forbids rewriting
that prefix. Cancellation or review cannot retract already exposed data.

`resolve` queues a later attempt but launches no worker. Use explicit `flush`
when ready. Later, `requeue --memory-id ID... --request-id req_retry_0001` adds
new delivery events for 1–256 selected canonical IDs, with atomic request
idempotency. It does not rewind history, change trust, reuse an earlier path
approval, or promise those records will pass review. An exclusion from an old
batch or an old size-blocked v1 disposition therefore has an explicit retry
path, without deleting state or creating a new Task/Git container.

The worker checks disable/configuration changes between operations and while
rclone is running. Cancellation cannot retract a file already published or undo
an acknowledged upload; a request already in flight may have reached a provider.
Keys, accounts and trust are operator authority, not information received from
memory. Same-OS-user processes are not isolated by these permissions.

## Private state and integration API

Ordinary control/receipt files store binding hashes, cursors, generations,
times, counts and IDs, not memory text. `transfer/publish.pending.json`,
`transfer/publication-reviews/` originals/replacements,
`transfer/outgoing-groups/`, `transfer/incoming-groups/`, and the private rclone
`exchange/` contain actual signed memory and are sensitive. The authenticated
inline/group envelopes in `transfer/received-capsules/<payload-sha256>.json`
are retained before staging/admission so private recovery does not require the
external exchange; they remain evidence, not a restored cursor or trust grant.
Group copy/remote
receipts and `publish.started.json` are recovery evidence, not disposable flags.
The `rclone/` cache and temp directory are private. Keep **all** sync state out
of public source packages. A portable **memory-only** restore intentionally
does not restore signing/configuration/stream state; do not mix it with an
arbitrary old cursor directory. See [BACKUP.md](BACKUP.md) for explicit recovery.
There is no automatic pruning of history or remote files.

`transfer/dependency-index.sqlite3` and its SQLite sidecars are a separate,
bounded derived cache of member IDs/hashes and validation stamps. They are not
canonical memory, signing keys, receive receipts or authority to resume a
stream. Explicit client backup only observes their metadata for quiescence;
it does not archive or activate them. Memory restore changes the store identity
and epoch nonce and removes old transfer receipts. An absent cache requires
bounded revalidation and cannot guess earlier publication membership; a corrupt
or mismatched cache is not silently reset. Do not copy cache/cursor directories
between independent Vaults or delete recovery state to bypass an error.

Finite worker JSON results are appended to protected `worker-events.ndjson`.
Automatic launch stops for review when this file reaches 512 KiB rather than
silently erasing it. The service does not remove host/provider logs or promise
invisible persistence. Raw provider error messages are not copied into these
receipts; content-free codes remain visible.

```python
SyncConfig.load(config_path)  # read-only; Path attributes:
# .vault, .identity, .trust_store, .state_directory, .path
status(config_path)           # read-only metadata, never starts synchronization
receive(config_path, maximum_seconds=10)  # explicit receive-only window
flush(config_path, maximum_seconds=30)    # explicit bidirectional window
review(config_path, offset=0, limit=100)  # read-only, no signing key loaded
resolve(config_path, batch_sha256=batch_hash, request_id=request_id,
        exclude=excluded_ids, keep=retained_ids, allow_local_paths=False)
requeue(config_path, identifiers=selected_ids, request_id=retry_request_id)
anchor(config_path, capsule=exact_historical_capsule_path)
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
worker wait. `run(config_path)` remains the explicit bidirectional alias. The
CLI requires `--config ABSOLUTE_PATH` before its subcommand. These are local
operator/runtime APIs, not fields accepted inside core memory request JSON.

The delta/v2 and delta/v3 wire and fragment descriptors are specified in
[delta-v2.schema.json](../schemas/delta-v2.schema.json),
[delta-v3.schema.json](../schemas/delta-v3.schema.json) and
[fragment-group.schema.json](../schemas/fragment-group.schema.json).
Schema validation alone does not verify signatures, cross-field sums, ordered
hashes, actual dependency membership, same-Vault receipts, operator decisions,
or current trust. Synthetic fault/replay cases are supplied in
`tests/test_v025_sync_review.py` and
`tests/test_v025_incremental_dependencies.py` in the separate source/review kit.
Authored cases are not execution evidence; consult [VALIDATION.md](VALIDATION.md)
for the exact methods and revisions actually run.

See [REMOTE_BACKENDS.md](REMOTE_BACKENDS.md) for destination configuration and
the distinct directory and rclone wire layouts.
