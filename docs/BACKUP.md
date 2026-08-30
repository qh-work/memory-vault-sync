# Memory snapshots and restore-to-new-copy recovery

There are two separate operations: **memory-only snapshots** and, below,
**explicit offline client-state snapshots**. Neither restores execution rights,
host approvals, private keys, or a task/project ownership hierarchy.

A portable NDJSON bundle preserves canonical records, not admission metadata,
record attestations or exact local write receipts. It is an interchange format,
**not a complete signed-memory recovery backup**.

`memory_vault_backup.py` implements a separate, explicit SQLite snapshot profile:
`universal-memory-sqlite-backup/v1`. It copies one transactionally consistent
view with SQLite's backup API, including a live Vault's committed WAL state.
It does not copy the SQLite pathname while a writer may be modifying it.

The [seven-case recovery campaign](V0_25_RECOVERY_SMOKE.md), at source
`332e944a6bda8f70dd3af6526d926d9468ed2f0d`, includes one passing unsigned
client-state case using actual snapshot, restore-to-new-copy, local activation
and hook retry through Python APIs. It is scoped synthetic evidence, not
acceptance of all backup/restore paths. Live concurrent-writer snapshots, signed
recovery, Windows behavior, power-loss durability and performance remain outside
that validation. Independently validate the required workflow before entrusting
production recovery to it.

## Create a new snapshot

```bash
python3 /absolute/source/memory_vault_manage.py \
  --config /absolute/private/control/client.json backup \
  --output /absolute/private/backups/snapshot-001 --timeout 60
```

The output directory must not exist. It must not be inside the client's
transient state directory. Existing Vaults, directories and snapshots are never
overwritten. A successful snapshot contains exactly:

```text
snapshot-001/
  memory.sqlite3
  manifest.json
```

The snapshot is consolidated to a standalone database with no external journal.
Its private files are written first; the strict manifest is published last as
the commit marker. A missing manifest means an incomplete snapshot and restore
refuses it. An interrupted new output can remain for operator inspection; the
module never recursively deletes an existing directory or resumes by replacing
an unknown file. Choose a new directory for a fresh attempt.

The manifest records the database SHA-256/length, source store ID, supported
schema, aggregate counts, included components and explicit exclusions. It never
contains an original local pathname, account, private key or trust registry.

## What recovery preserves

| Component | Snapshot | Restored new copy |
| --- | --- | --- |
| Canonical records, content IDs, hashes, provenance, relations | Preserved | Preserved; canonical bytes are checked |
| Record attestation bytes and signer IDs | Preserved | Preserved; not automatically trusted |
| Current admission flags | Recorded as historical snapshot state | Re-evaluated under the explicit restore choices |
| Canonical write-idempotency request receipts | Preserved | Preserved after structural validation; historical, not authorization |
| Derived terms/relations index | Snapshotted consistently | Rebuilt from canonical records |
| Source store identity/delivery log/transfer receipts | Snapshotted | New store identity and delivery stream; old transfer receipts discarded |
| Hook/lifecycle/host retry queues | **Excluded** | Not recreated or silently replayed |
| Sync configuration, remote credentials and cursor/pending state | **Excluded** | Never reused automatically |
| Private keys, current trust registry, client config, hook permissions | **Excluded** | Never imported or created |
| Files merely referenced by artifact records | **Excluded** | References remain; external file bytes need their own backup |

This is a **memory-database snapshot**, not an atomic snapshot of every client
process or the whole machine. A hook prompt/outbox and lifecycle control DB may
change while the memory snapshot is taken. They are deliberately excluded rather
than falsely represented as one consistent backup. An episode committed before
its continuity record can therefore be present as a legitimate partial local
save. Retain the original control queues separately when investigating a
partial capture; never claim this snapshot contains them.

## Restore only to a new database path

```bash
python3 /absolute/source/memory_vault_manage.py restore \
  --backup /absolute/private/backups/snapshot-001 \
  --output /absolute/private/recovered/vault.sqlite3
```

The command refuses an existing output, pre-existing output journal files, a
path inside the source backup, symbolic links and unsupported SQLite schemas.
It verifies checksum/length, expected schema objects, SQLite consistency and
canonical record bytes. Derived indexes are reconstructed instead of trusting
arbitrary indexes copied from a file. It does not load an existing client config
merely to recover memory; a lost old config is not a prerequisite for restoration.

**Default admission is quarantine.** This keeps a copied historical `verified`
flag from turning into a new trust decision. The restored bytes and signatures
remain available for explicit review, but do not enter normal context solely
because the backup declared them trusted.

To reverify signatures against an independently provisioned **current** public
key registry, explicitly select it:

```bash
python3 /absolute/source/memory_vault_manage.py restore \
  --backup /absolute/private/backups/snapshot-001 \
  --output /absolute/private/recovered/verified-vault.sqlite3 \
  --trust-store /absolute/private/control/current-trust.json
```

Valid signatures from currently registered keys can become verified. Unknown,
revoked, malformed or invalid signatures remain quarantined and are counted in
the result. A missing cryptographic provider or unusable protected registry
does not silently downgrade a requested verification path. No private signing
key is loaded and no new signature or key enrollment is created.

Add `--accept-unsigned` only to explicitly accept records whose backup admission
was `local_unsigned` or `accepted_unsigned` and that have no attestation. It does
not accept a bad signature, authenticate an author or automatically release
previously quarantined unsigned records. The snapshot itself is never modified.

After restoration, create a distinct client configuration pointing to the new
Vault and the intended current trust registry. No host is redirected, hook
enabled or configuration overwritten by restore. A bare core does not load a
registry and must not be described as continuously checking revocation.

## Replication identity is deliberately new

Copying an older database and retaining its old source identity/cursor can make
new records collide with a previously published stream or appear to roll it
back. Each restored copy receives a new random `store_id`; its delivery log is
recreated from the retained records, and old receiver transfer receipts are
discarded. Canonical memory IDs and signatures do not change.

Use a **new sync/transfer-state directory**. Do not restore or attach old cursors
or pending capsules to this new database. The existing transfer identity checks
must reject accidental reuse. The original database and its current remote
stream remain untouched. Receivers can deduplicate repeated canonical memory
IDs when the new, independently authenticated stream is deliberately connected.

## Checksums, receipts and trust are different

Anyone who can rewrite a backup can also recompute its plain SHA-256 manifest.
The manifest is not a publisher signature or proof of who created the snapshot.
Protect backup storage and compare the digest against a separately retained,
trusted backup receipt before recovering from an untrusted transport. Do not use
an arbitrary downloaded SQLite file as a trusted recovery source.

Record signatures authenticate particular record bytes, not the entire SQLite
snapshot or its request receipts. Preserving write-idempotency receipts assumes
the operator has established the backup's origin through storage/transport
controls. Their original responses are historical; current admission is
recalculated when the core replays a write receipt. Restore validates their
protocol envelope and fixed non-authority fields and does not import execution
permissions. A past `stored` result does not prove current signer trust, remote
delivery, model consumption or real-world task completion.

## Resource and storage limits

The profile accepts the current SQLite v2 schema only. Bounds are 2 GiB for the
database, 1,000,000 memory records, 2,000,000 write receipts and a 32 KiB manifest.
Work defaults to a 60-second deadline; `--timeout` permits 1–300 seconds. SQLite
progress and chunked checksumming are bounded, so large/busy Vaults can stop with
a work-limit response rather than wait indefinitely. This is not a throughput
guarantee. Use the old matching runtime/export converter for older layouts;
backup does not silently migrate them.

Snapshot/restore use protected local files and no-clobber publication. The full
client's Windows path uses native ACL/handle checks on local fixed NTFS storage,
not `chmod` as a substitute for access control; unsupported storage fails
closed. This platform path has not been exercised here. Files remain plaintext: use an
independently authorized encrypted storage/transport for sensitive backups.
The optional [pack format](PACKS.md) can carry bytes in bounded chunks, but
compression and hashes are not encryption or publisher authentication.

## Explicit offline client-state snapshots

`memory_vault_recovery.py` adds `universal-memory-client-backup/v1`. A memory
snapshot remains included, and the operator explicitly selects control
components. This is an additional full-client workflow, not a change to the
light record protocol or to the memory-only profile above.

| Component | Preserved private evidence |
| --- | --- |
| `hooks` | Exact `prompts`, `outbox`, `done`, and `conflicts` JSON files |
| `lifecycle` | Sessions, staged/frozen turns, exact request hashes and completed receipts |
| `hosts` | Generic/Claude/Gemini correlations, pending exact requests, receipts, final-message aliases; requires `lifecycle` |
| `compat` | Protocol 1.0 intents/receipts, semantic-job markers, and old-ID aliases |
| `sync` | Worker/trigger metadata, cursors, pending/started publication capsules, review intents/decisions/original bytes, received signed capsules, incoming/outgoing fragments, copy/upload receipts, and documented private exchange staging |

The selection is exact: no recursive catch-all copies of a home, account,
configuration, provider cache, or exchange directory. Private signing-key files,
trust registries, client/sync configuration files, rclone configuration/cache,
host approval state, code, and lock files are excluded. An external directory
backend's exchange is not included. The private sync staging tree has a closed
filename/layout allow-list. Unexpected entries in selected control layouts
stop the operation for review instead of being silently copied.

These are **private, plaintext backups**, not release artifacts. Visible-text
queues, original publication-review capsules, and rejected/pending memory can
contain sensitive text. Excluding credential *files* does not sanitize secrets
that were already written inside memory. Do not publish this backup.

### Establish the offline boundary, then capture

Stop or close **all writers to this chosen client and Vault** first: MCP
processes, approved host hooks/adapters, compatibility clients, direct memory
writers, and sync workers. Use the normal host/application controls; backup
does not stop processes or revoke other clients' access for you.

```bash
python3 /absolute/source/memory_vault_manage.py \
  --config /absolute/private/control/client.json backup-client \
  --include hooks lifecycle hosts compat sync --quiesced \
  --output /absolute/private/backups/client-001 --timeout 180
```

Omit `sync` when none is configured. `--quiesced` is a required **operator
acknowledgment**, not proof that arbitrary writers have stopped. The capture
also acquires existing known nonblocking host/sync locks, pins consistent
SQLite read transactions, inventories selected paths and directory entries,
and checks every selected source's fingerprint and bytes again before
publishing the manifest. Newly appearing queues/databases or changed entries
invalidate the capture. It never creates missing source lock files.

This is **not a global atomic multi-file snapshot**. Advisory locks do not
control an uncooperative process, and matching before/after checks are not a
replacement for the offline boundary. An active writer, a changing journal,
or a work limit can leave an incomplete new output, without a top-level
manifest. Keep it for inspection and use a different new output for a retry.

```text
client-001/
  manifest.json                 # overall commit marker; hashes every payload
  memory/
    manifest.json               # original memory-only profile
    memory.sqlite3
  control/
    hooks/{prompts,outbox,done,conflicts}/...
    lifecycle/lifecycle-v1.sqlite3
    hosts/<host>/<session-key>/...
    compat/host-protocol-v1.sqlite3
    sync/...                    # evidence, never executable configuration
```

Absent selected components need no empty placeholder files. Pending capture
before the first successful canonical write is supported: an empty snapshot
database is constructed in memory, `source.memory_database_present` is `false`,
and its store ID is a snapshot placeholder. The source Vault is not initialized.
Nothing invents an assistant reply for a prompt that never received one.

### Restore memory plus inert evidence

```bash
python3 /absolute/source/memory_vault_manage.py restore-client \
  --backup /absolute/private/backups/client-001 \
  --output /absolute/private/recovered-001 \
  --trust-store /absolute/independent/current-trust.json --timeout 180
```

The trust registry is optional and must be outside the backup/recovered tree.
The memory-only restore trust/quarantine rules still apply; unsigned acceptance
requires the separate `--accept-unsigned` flag. A new `store_id` and delivery
stream are created. Record identities and attestations remain unchanged.

The new directory contains `memory.sqlite3`, a **capture-disabled** `client.json`,
`recovery.json`, and `evidence/` containing the complete original backup,
including its original database and control bytes. The generated config has
no signing identity and no sync configuration. If the operator independently
selected a current trust registry, only its external path is used for ongoing
read-time revocation checks. No archived policy is adopted.

Restored control files are **not placed in the live `client.state` path**.
Opening the new client cannot drain an old queue, upload a capsule, install a
hook, or grant host permission. Original receipts remain historical evidence,
not confirmation of current trust, new network activity, or task completion.

### Review, then independently opt in to local resumption

```bash
python3 /absolute/source/memory_vault_manage.py review-recovery \
  --recovery /absolute/private/recovered-001 --limit 50

python3 /absolute/source/memory_vault_manage.py activate-recovery \
  --recovery /absolute/private/recovered-001 \
  --output /absolute/private/recovered-001/resumed-client.json \
  --include hooks lifecycle hosts compat --authorize-local-resume \
  --identity /absolute/independent/current-identity.json \
  --trust-store /absolute/independent/current-trust.json
```

Review is content-free, paginated by `next_offset`, and tied to the evidence
manifest digest. It does not authenticate a backup's origin or approve its
contents. Establish that origin through your own trusted backup receipt/storage.

Activation requires a **new config and new sibling state directory**. It
rebuilds only closed, known SQLite schemas; checks record references and
request envelopes; copies only validated local queue formats; and rewrites
Vault/store bindings to the new memory DB. It does not execute SQL programs or
follow paths supplied by an archived control file. A malformed component stops
activation before publishing a capture-enabled config. Partial staging remains
in its new location for inspection.

The explicit activation flag authorizes subsequent local capture/retry, not
remote transfer or host installation. `sync` cannot be selected here. Signing
identities are independently selected paths and are not read during activation.
If the original client used signing, omitting a new identity requires the
additional `--allow-unsigned-local` opt-in; there is no silent downgrade.
A sibling `.recovery-receipt.json` records this local activation decision.

Original control receipts remain byte-for-byte in evidence. In the *derived
active compatibility cache*, an old session-open network result becomes
`historical_restored_receipt` with `network_accessed: false`, so replay cannot
misreport an old upload as work performed now. A new local retry is still a
separate operation; see [OPERATIONS.md](OPERATIONS.md).

### Recover downloaded-but-not-admitted signed memory

Outgoing pending capsules were built from canonical records. Their memory
survives in the restored DB, and the new delivery log makes admitted records
available to a separately configured **new** sync stream. Old privacy decisions,
exclusions, peer cursors, upload receipts, and publication approvals remain
evidence only; review and authorize the new publication separately.

For incoming memory that had not yet reached the DB, receivers preserve a
verified envelope at `transfer/received-capsules/<payload-sha256>.json` **before**
fragment staging/admission. Complete local fragments plus that envelope can be
recovered without a remote connection:

```bash
python3 /absolute/source/memory_vault_manage.py review-recovery \
  --recovery /absolute/private/recovered-001 --component sync

python3 /absolute/source/memory_vault_manage.py import-recovery \
  --recovery /absolute/private/recovered-001 --entry-id item_FROM_REVIEW \
  --trust-store /absolute/independent/current-trust.json \
  --authorize-memory-import
```

Only a selected signed capsule candidate is accepted. Its envelope and **every
record attestation** are reverified against current independent trust; all
manifest-listed fragment hashes, counts and whole-group digest must match.
The core admits the complete group and an idempotency receipt in one transaction.
Missing fragments or unresolved record dependencies do not produce partial
admission. Evidence stays intact for another attempt. Incomplete downloads
require independently authorized retrieval of missing data; the backup cannot
recreate bytes that were never received.

This is an explicit **memory import**, not proof of continuous transport history:
old cursors/chain heads are not replayed, no publication permission is recovered,
and no network worker runs. It does not sign a record or load a private key.
New sync still requires its own fresh configuration, state directory and review.

### Client-state limits and validation status

The full snapshot bounds discovery to 20,000 files and 20,000 directories,
8 GiB of payload bytes, a 16 MiB outer manifest, 16 MiB per ordinary control file,
and at most 512 MiB per control database (the compatibility format retains its
stricter 256 MiB bound and 250,000-alias limit). Canonical memory keeps the independent
memory-only profile bounds. Control formats enforce their own row/field limits;
transfer envelopes/fragments keep their 4 MiB and complete-group bounds.
Read/copy/checksum and SQLite work use explicit deadlines; very large snapshots
can require several independently quiesced attempts, not an implicit unbounded
background backup. Restoring the original evidence **and** a new memory DB needs
additional disk space; the evidence copy is intentionally not deleted afterward.

Of the public synthetic cases in
[`tests/test_v025_client_recovery.py`](../tests/test_v025_client_recovery.py),
`ClientRecoveryTests.test_explicit_local_activation_then_retry_preserves_no_network_boundary`
passed in the [seven-case recovery campaign](V0_25_RECOVERY_SMOKE.md). Its actual
`backup_client` / `restore_client` / `activate_recovery` / `manage.retry` path
uses one unsigned baseline record and one pending `hooks` pair. The assertions
confirm one record after recovery/activation, three after retry, a completed
hook receipt, no sync configuration or background-sync permission, and zero
processed jobs on the repeated retry. Original outbox evidence still exists;
this selected case does not assert byte-for-byte evidence equality.

Other recovery methods and component combinations are not covered by that run.
No real private Vault, signing key, native host or provider was used. Database
crash/power-loss recovery, large-state timing, supported Windows ACL/locking,
and concurrent-writer behavior still require independent verification. This
narrow functional result is not complete disaster-recovery acceptance.
