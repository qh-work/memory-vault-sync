# Memory snapshots and restore-to-new-copy recovery

A portable NDJSON bundle preserves canonical records, not admission metadata,
record attestations or exact local write receipts. It is an interchange format,
**not a complete signed-memory recovery backup**.

`memory_vault_backup.py` implements a separate, explicit SQLite snapshot profile:
`universal-memory-sqlite-backup/v1`. It copies one transactionally consistent
view with SQLite's backup API, including a live Vault's committed WAL state.
It does not copy the SQLite pathname while a writer may be modifying it.

The implementation has not been executed against a live or synthetic Vault as
part of this release work. No crash-recovery, platform or performance result is
claimed. Independent maintainers should validate the documented workflow with
synthetic data before entrusting production recovery to it.

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

Snapshot/restore use protected POSIX files and no-clobber publication. Windows
protected recovery storage is not implemented; it fails closed rather than
claiming `chmod` provides Windows ACL protection. Files remain plaintext: use an
independently authorized encrypted storage/transport for sensitive backups.
The optional [pack format](PACKS.md) can carry bytes in bounded chunks, but
compression and hashes are not encryption or publisher authentication.
