# Signed incremental transfer: v3 dependencies and v2/v1 compatibility

`memory_vault_transfer.py` exchanges signed logical memory batches through an
explicitly selected directory. It opens no sockets, starts no service, schedules
no future run and installs nothing. A separately authorized folder service can
carry that exchange; the optional [bounded sync client](SYNC.md) can also use an
explicit [rclone backend](REMOTE_BACKENDS.md).

Local save/recall does not wait for transfer. Canonical records and the delivery
log remain the durable memory source. Transfer cursors, review journals and
fragment receipts are transport/recovery state, not Task or Project containers.
Source store IDs and signer IDs do not own a memory or grant execution authority.

The v3 source described here is pinned to
`098b22c44ca299d1f889b41df9355511dfa2caf4`. Source inspection and supplied
synthetic cases do not themselves establish runtime success. Consult
[revision-specific validation evidence](VALIDATION.md); the earlier
[scoped smoke campaign](V0_25_SCOPED_SMOKE.md) does not cover this v3 change.
This page makes no Windows, remote deployment, throughput or latency claim.

## Explicit setup and basic commands

Use [trust setup](TRUST.md) to create an identity and independently register the
public descriptors of the envelope publisher and every record signer on the
recipient. The publisher registers its own key locally too. Never auto-enroll a
key from an incoming packet. Private keys are not part of memory or transfer.

Keep the local Vault, trust/identity files, private transfer-state directory and
exchange distinct. Vault/trust/identity files cannot be inside transfer state or
the exchange; transfer state and exchange cannot contain each other. Do not
synchronize a live SQLite file between devices. Synchronize canonical batches.

POSIX retains ownership/mode/plain-file checks. Windows now has an explicit
native profile using real DACLs, checked handles and nonblocking locks on local
**fixed NTFS**. UNC/network drives, unsupported filesystems, reparse points and
unsafe or unsupported ACLs fail closed; existing permissions are not repaired.
This is source support, not a tested Windows deployment. Read
[platform boundaries and official API references](PLATFORMS.md) before choosing
paths; a Windows cloud placeholder or junction is not accepted private storage.

These are examples for an authorized operator, not commands executed for this
release. Paths must be absolute and free of symlink/reparse components. Publisher:

```sh
python3 /absolute/source/memory_vault_transfer.py publish \
  --vault /absolute/private/memory/vault.sqlite3 \
  --exchange /absolute/shared/memory-exchange \
  --state-directory /absolute/private/send-state \
  --trust-store /absolute/private/control/trust.json \
  --identity /absolute/private/control/identity.json
```

Recipient; no private signing key is required:

```sh
python3 /absolute/source/memory_vault_transfer.py receive \
  --vault /absolute/private/memory/receiving.sqlite3 \
  --exchange /absolute/shared/memory-exchange \
  --state-directory /absolute/private/receive-state \
  --trust-store /absolute/private/control/trust.json
```

This low-level CLI is a signed transport. The full-client sync path additionally
supplies the best-effort publication privacy guard and operator review flow
described below. Do not assume a direct `publish` call performs DLP: library
callers choose `capsule_guard`/`publication_guard` explicitly.

The exchange contains plaintext memory, including signed content. Signatures
are not encryption. Audience, folder ACLs and encryption belong to the selected
transport and its operator; this adapter does not widen them.

## Signed envelope and stream history

Every capsule is exactly `{ "payload": ..., "proof": ... }`. Newly constructed
self-contained batches retain
[universal-memory-delta/v2](../schemas/delta-v2.schema.json). When the publisher
can omit already published dependencies under the checks below, it uses
[universal-memory-delta/v3](../schemas/delta-v3.schema.json). Both have these
top-level fields; only v3 has the additional `dependency_mode` field:

| Field | Meaning |
| --- | --- |
| `schema_version` | `universal-memory-delta/v2` or `universal-memory-delta/v3` |
| `source_store_id`, `sender_key_id` | Source delivery stream and registered envelope signer; not memory ownership |
| `after`, `cursor` | Contiguous delivery-log interval `(after, cursor]` |
| `records`, `attestations` | Inline canonical records and their individual record proofs, or empty when `group` is present |
| `blocked` | Explicit `{memory_id, sequence, reason}` delivery dispositions; not successful copies |
| `previous_batch_sha256` | Prior signed payload hash; null only for a stream beginning at `after=0` |
| `publication_review` | Null, or a compact signed commitment to a local operator's selection; not recipient authorization |
| `group` | Null for an inline capsule, otherwise a signed fragment-group descriptor |
| `dependency_mode` (v3 only) | `closure`: every relation target is supplied; `prior_stream`: dependencies may already exist through the validated prior stream |

The message signature covers the complete payload in a different domain from
record signatures. Relaying a registered signer does not replace record-level
verification. Filenames, model labels and public keys embedded in data are not
trusted. Inline capsules contain at most 1,024 records and the complete signed
file is bounded to 4 MiB.

Legacy `universal-memory-delta/v1` capsules remain readable with their original
eight payload fields and no history link/review/group. An existing immutable v1
pending batch may finish unchanged. Once a recipient has accepted a v2 or v3
head, a v1 continuation is rejected as a history downgrade. V3 can follow a v2
base; subsequent self-contained batches may still be v2 without dropping the
signed history link. The reader retains historical v1/v2 wire behavior; it does
not reinterpret an old capsule as a v3 dependency assertion.

The public core `changes` operation and ordinary `Vault.transfer_changes()`
remain self-contained: they do not accept a caller-supplied known-ID list or
cursor as permission to omit dependencies. Only the trusted signed integration
supplies a verified boundary. There is no automatic wire-version negotiation;
a v2-only receiving adapter needs v3 support before accepting thin v3 batches.

Directory layout is independent of tasks:

```text
exchange/<sender-key-id>/<source-store-id>/
  <after-20-digits>-<cursor-20-digits>-<payload-sha256>.json
  groups/<group-id>/<fragment-index-6-digits>-<fragment-sha256>.ndjson
```

Each receiver retains its last accepted head hash and cursor. Before progressing
an observed stream, the directory/rclone adapter checks that this head is still
present and uniquely authenticated. A missing/changed head, competing signed
payloads or a prefix gap stops that peer. No gap is silently skipped.
This detects observed rollback/forks; it does not prove global freshness,
discover a hidden alternate history or inspect every historical file each run.
Do not prune old exchange files or reset cursor state as an error workaround.

### Upgrade an old cursor without inventing a history anchor

A pre-v2 state file may contain a receive cursor but no saved head hash. For a
v2/v3 continuation it needs an explicit `anchor` operation, using the exact
capsule previously received. The same operation can retain missing predecessor
envelope evidence when an existing head already matches that exact capsule:

```sh
python3 /absolute/source/memory_vault_transfer.py anchor \
  --vault /absolute/private/memory/receiving.sqlite3 \
  --exchange /absolute/shared/memory-exchange \
  --state-directory /absolute/private/receive-state \
  --trust-store /absolute/private/control/trust.json \
  --capsule /absolute/private/recovery/previously-received.json
```

Anchoring verifies the current envelope trust, saved cursor and the existing
atomic Vault transfer receipt for the exact payload hash. It adds no memories,
does not reset a cursor, grants no trust and performs no network access. It also
retains that authenticated capsule in `received-capsules/`. An arbitrary old
file, copied cursor, or filename is insufficient evidence.

## V3: verified reuse, not a claimed known-memory list

An outgoing `prior_stream` batch may omit an ancestor only when all of the
following hold:

- the private positive-member index matches this sender key, source store,
  destination, cursor and exact previously published payload hash;
- the exact record ID/hash was included in an actual immutable publication in
  that stream, confirmed by reading the published capsule back;
- that record and its complete transitive dependencies are currently admitted
  and independently trusted, either freshly validated or covered by the
  invalidatable local validation cache below.

A cursor counts delivery entries, not successful record copies. Quarantined,
unsigned, missing-dependency and operator-excluded entries do not become
published members merely because the cursor passes them. An explicitly requeued
record remains a delivery root and is sent again even if it was sent before.
Canonical records, hashes and relations are never rewritten to shorten a batch.
For example, later `continues` records can reuse an accepted prefix without
resending every ancestor; this does not bind memories to a task or session.

The receiver does not trust the sender's member index. For a v3 continuation it
verifies the locally retained predecessor envelope against the same sender,
source store, cursor and payload hash. In **the same receiving Vault transaction**
that would admit the new records, it requires the exact predecessor transfer
receipt and validates the actual canonical dependency graph under current
admission and independently configured trust. A copied head, foreign Vault's
receipt, existing IDs alone, or historical signature verification is not enough.
Missing/quarantined/revoked dependencies stop admission; unsigned dependencies
cannot satisfy a verified boundary. A failed dependency check admits none of
the new batch. Missing predecessor evidence reports
`dependency_base_evidence_missing`; a missing same-Vault receipt reports
`dependency_base_receipt_missing`. Anchoring can restore authenticated envelope
evidence, but cannot manufacture a missing receipt or accepted memories.

`dependency_mode=closure` is also readable in v3, requires all targets in that
batch, and is mandatory for v3 at `after=0`. The current publisher chooses v2
for fresh self-contained batches and v3 `prior_stream` only when omitting
dependencies. A nonzero v3 closure batch still obeys the same history/receipt
checks; `closure` is not a history reset.

### Cold receivers and invalidated caches

A new receiving Vault starts at cursor zero and replays retained authenticated
batches in order, using as many bounded receive windows as needed. It cannot
start from a thin latest capsule or borrow another receiver's cursor/cache.
The exchange must retain the necessary prefix and fragments; absent history is
an explicit gap, not permission to invent an accepted baseline. A new/restored
Vault with a changed store identity requires its own correctly bound state.

The private `dependency-index.sqlite3` under transfer state (for sync,
`S/transfer/dependency-index.sqlite3`) contains member IDs/hashes, heads and
validation stamps, not canonical memory or keys. It is bounded to 512 MiB and
is **derived state, never portable stream authority**. Client backup observes
the index and its sidecars for quiescence but does not archive or reactivate
them. Memory restore changes the store identity and epoch nonce and discards
old transfer receipts.

Validation reuse requires an exact canonical hash, the actual Vault's SQL
invalidation epoch, and a fresh digest of the independently maintained trust
registry. Additive SQL triggers invalidate it on admission updates/deletions
and canonical updates/deletions/replacements, including writes made by an older
writer. Missing or changed trigger definitions cannot enable cache reuse.
Adding a genuinely new independent record does not invalidate every ancestor.
Positive certificates are persisted only after successful Vault validation and
commit; they do not survive a failed admission as trusted results.

An absent cache yields no guessed published members and requires bounded
revalidation. Corrupt or mismatched index state is not silently reset. Each
dependency-validation pass reads at most 100,000 records and 64 MiB of canonical bodies, including
dependencies inspected for reuse. It can return an already complete verified
prefix with more work pending. If even the next root cannot be safely validated
within that bound, `dependency_revalidation_required` stops it without a new
cursor or signed size-only disposition. Trust/epoch changes during validation
produce `dependency_validation_changed`. Larger page targets do not bypass
these checks. Retain canonical data and evidence for explicit reconciliation;
repeated automatic retries are not a guarantee of progress after cache loss or
policy changes. Do not delete cursor/receipt state or auto-retrust a signer.

## Complete dependency groups

The ordinary publication target is 100 delivery entries and, on the verified
path, 256 KiB of canonical record bytes. `--limit` accepts 1–256;
`--maximum-bytes` accepts 4 KiB–3 MiB.
These are small-page targets, **not an exclusion policy for large memories**.
The verified path uses the read-only `Vault.transfer_changes` integration with
the validated boundary above. When one root exceeds the small-page target, it
requests the existing complete-group budget and freezes the supplied records
into a group if they cannot fit inline. Explicit `--attest-unsigned` retains the
self-contained export path; it does not enable dependency pruning.

One atomic group supports up to **100,000 records and 64 MiB of canonical record
bytes**, matching the core transfer/import bounds. Each fragment is at most
4 MiB. The separate encoded group cap is 476,708,864 bytes, with at most 115
fragments; these ceilings also bound proof/envelope overhead. They are maxima,
not a claim that every group consumes that much space. New v2 groups carry a full
self-contained closure; v3 groups may carry only new records plus dependencies
not already reusable through the verified prefix. The referenced prefix can
span earlier batches, but one unvalidated closure does not get an unlimited
budget. Export beyond the core bound raises `dependency_budget_exceeded`, or
the bounded validator raises `dependency_revalidation_required`, without
advancing past that root. Neither is signed away as completed synchronization.

The [fragment-group schema](../schemas/fragment-group.schema.json) binds:

- `schema_version`, `group_id`, `record_count`, `record_bytes`, `encoded_bytes`,
  `records_sha256`, and the ordered `fragments` list;
- each fragment's exact `index`, `sha256`, `bytes` and `records` count;
- whole canonical NDJSON lines of `{"record": RECORD, "attestation": PROOF}`.

`group_id` hashes the canonical descriptor without `group_id`.
`records_sha256` hashes the raw fragment bytes concatenated in index order,
including line-ending newlines. No record line is split across fragments.
Grouped capsules have `records=[]` and `attestations={}`; mixing inline and
grouped records is rejected.

The sender freezes fragments privately and exposes the signed capsule
**last**, after all fragments. Directory-copy receipts and exact rclone
upload/read-back receipts support continuation after interruption. A call
normally copies at most eight new fragments, subject to tighter sync-window
budgets; subsequent explicit/event-triggered windows continue the same frozen
group. `group_publication_pending` is not a cursor advance or a delivered batch.

The recipient stages verified fragments privately. A partial group admits zero
canonical records and advances no cursor. Once complete, it checks hashes,
counts, unique IDs and every supplied signature against current trust. For v3,
the same-Vault predecessor receipt and actual dependency validation also apply;
old ancestors may be in the Vault, not in the new fragments. The entire new
group and its receipt commit in one Vault transaction.
Corruption or a failed transaction admits none of that group. Cached copy
receipts are tied to file identity/size/timestamps; final admission rechecks
actual bytes and proofs. A remote receipt records earlier observed bytes, not a
promise that the provider will retain them forever.

Directory and rclone use this same v3 admission boundary. The rclone staging
exchange's publication index is not proof of remote upload or recipient
admission. Remote sends retain their separate ordered upload/read-back receipts
and revalidate outgoing v3 dependencies before attempting upload. There is no
extra remote known-ID negotiation, background history reconstruction, or
permission to fetch a dependency from an unconfigured source.

This transports complete canonical memories, not arbitrary binary artifact
directories or filesystem trees. Larger external artifacts require their own
explicit transport and references.

## Finite work and explicit freshness

Direct reception defaults to 16 batches (`--maximum-batches` accepts 1–256).
Discovery is bounded to 256 peers, 20,000 directory entries and 256 candidate
checks per call. New fragment work is bounded separately. These limits are not
fairness guarantees or protection against every hostile-filesystem delay.

A host that needs a freshness attempt before using local context can explicitly
choose a bounded receive-only window. It need not load a private signing key or
publish pending local records. An explicit flush is bidirectional:

```sh
python3 /absolute/source/memory_vault_sync.py \
  --config /absolute/private/control/sync.json receive --maximum-seconds 10
python3 /absolute/source/memory_vault_sync.py \
  --config /absolute/private/control/sync.json flush --maximum-seconds 30
```

The override accepts 1–60 seconds and only shortens the configured window.
Byte/file/command limits and cooperative time checks still apply. SQLite work,
whole-group verification and blocking OS calls are not forcibly preempted, so
the number is not an exact wall-clock guarantee. Default local prompt/recall
does not wait for this work. No perpetual daemon or scheduled retry is created.
Even a completed receive window reports `remote_latest_proven=false`.

## Explicit privacy review and requeue

Full-client sync blocks an entire pending batch when the shared best-effort
scanner finds recognized credentials or personal paths. It does not silently
filter records, rewrite memories or promise comprehensive privacy detection.
Review is content-free and read-only: no network, private-key read, lock-file
creation or canonical memory mutation.

```sh
python3 /absolute/source/memory_vault_sync.py \
  --config /absolute/private/control/sync.json review --offset 0 --limit 100
```

The result identifies immutable record IDs/hashes, sizes, reasons and dependency
information, not matched secrets or text. A group page checks only its
containing fragments; it does not certify the whole group. An operator must
partition **all** pending record IDs into explicit `exclude` and `keep` lists.
Retaining a record while excluding its dependency is rejected. Secrets have no
override; retaining a local path requires a separately explicit, batch-bound
operator allowance. See [the complete decision-file format](SYNC.md#explicit-per-record-publication-decisions).

```sh
python3 /absolute/source/memory_vault_sync.py \
  --config /absolute/private/control/sync.json resolve \
  --decision-file /absolute/private/control/selection.json
```

The private decision file is bounded to 16 MiB. Its request ID gives exact
idempotency; changed arguments conflict. The local journal preserves original
signed bytes, selection, replacement and completion evidence. Excluded roots
receive signed `operator_excluded` dispositions, never a claim of delivery.
An incoming signed review cannot grant local publication permission.

V3 review covers the supplied records, not ancestors already exposed in prior
batches. It cannot retract those ancestors or turn a previously excluded record
into an actually published member. Future dependents must still include an
ancestor that was never published; normal review applies to those bytes again.

Default publication requires verified records/dependencies. Missing or
unadmitted dependencies and unsigned dependencies remain explicit dispositions;
their canonical memories remain intact. `--attest-unsigned` on direct publish
explicitly attests exact bytes as the current publisher, not as their historical
author. Historical size-blocked v1 records and deliberately excluded records
can be explicitly requeued after independent review/repair:

```sh
python3 /absolute/source/memory_vault_sync.py \
  --config /absolute/private/control/sync.json requeue \
  --memory-id mem_0123456789abcdef0123456789abcdef01234567 \
  --request-id req_operator_retry_0001
```

Use actual IDs; the example ID is illustrative. One request supports 1–256 IDs.
Requeue changes delivery metadata, not memory bytes, trust or admission. It does
not reuse an older path approval or rewind a stream. Resolution and requeue
enqueue work but start no worker; run an explicit flush when ready.

## Crash recovery, evidence and current trust

Before exposure, the publisher saves exact signed pending bytes. A durable
`publish.started.json` marker is saved before any fragment/capsule can escape.
Once exposure has started, review cannot rewrite that prefix, even if remote
files later disappear. Frozen bytes and receipts, not a new signature over
different content, determine retry behavior.

On supported macOS/Linux filesystems, private control files and complete
fragments/capsules use an exclusive rename, so an interruption does not leave a
published inode with a temporary hard-link alias. Existing private aliases are
not repaired automatically. Explicit exchange outputs retain their prior parent
permissions and exact-overlap behavior; this separate no-replace profile never
relaxes private-state or Windows checks. New output bytes remain 0600/single-linked.
See [platform limits](PLATFORMS.md) and the separately source-pinned
[publication repair evidence](V0_25_PARITY_REPAIR_SMOKE.md), which is not a full
signed-sync or real remote-provider trial.

The receiver first retains each uniquely authenticated inline/group capsule at
`received-capsules/<payload-sha256>.json` beneath its private transfer state.
For the sync client that is `S/transfer/received-capsules/`. These are immutable
recovery evidence, not trust decisions or restored cursors. Together with
`incoming-groups/` they preserve the authenticated envelope when admission
fails or an external exchange is unavailable. They can contain sensitive
content and belong only in an explicitly private backup, never a public export.

The Vault's record/receipt transaction commits before the external receive
cursor. A crash between them reuses that atomic receipt; replay adds no duplicate
memories. A repeated already-committed last-head capsule needs no fragment
download, but still requires current envelope verification and the saved core
receipt. Older accepted records are not silently re-admitted under changed trust.

Current trust applies before uncommitted publication and admission. A registered
relay cannot override a revoked or unregistered record signer. Other independent
streams may progress, but that authenticated prefix remains blocked. Revocation
does not rewrite immutable history or every offline recipient's trust policy.

For an uncommitted pending batch whose inner signer becomes untrusted, preserve
its bytes and state. If the identical already-published capsule exists, the
direct adapter's `acknowledge-published` action with the same path arguments can
record that observation without republishing or trusting its records. This is
historical publication acknowledgment, not proof of current fragment availability
or recipient admission. Publisher-key revocation still fails closed.

Missing state, a changed Vault/store identity, a fork or an uncertain prior
publication requires explicit reconciliation. Do not delete state to "fix"
it, auto-retrust old keys, or claim cancellation retracts exposed data. A
separately provisioned new stream can retain old evidence without pretending
that its predecessor was delivered. Cross-recipient policy/key rotation is
not automatically resolved by this transport.

## Meaning of success

`stored` / `saved_local` means local durable memory. `published` means the local
immutable exchange capsule was published after its fragments. `received`
reports this recipient's commits; inspect counts and any `rejected`, gaps,
blocked records, `groups_pending` or `more_possible` values. Size ceilings,
partial groups and operator exclusions are not a complete-sync claim.

None of these results proves that another AI read or agreed with a memory, or
that it may execute a remembered next action. Memory remains evidence, not
instruction, task ownership, authorization or execution.
