# Encrypted chunk protocol v1

This document is the maintainer and interoperability contract for
`encrypted-fixed-chunks-v1`, introduced by Memory Vault Sync 0.14.0. The
protocol reduces repeated large-artifact transfer while retaining the existing
object-before-control-plane publication barrier. It is opt-in, provider-neutral
above rclone, and encrypted at rest by the already verified rclone/crypt
boundary.

## Compatibility and activation

- Existing whole objects remain readable and are never rewritten.
- Chunking applies only to new uploads through the active `rclone-crypt`
  object store. Google Drive and historical stores keep their established
  whole-object behavior.
- The safe default is disabled with a 32 MiB threshold. Enable it only after
  the rclone store is configured and the local outbox has no unfinished work:

  ```text
  vault_sync.py configure-chunking --enable
  vault_sync.py configure-chunking --enable --minimum-bytes 16777216
  ```

- `configure-chunking --disable` stops creating new chunked objects. It does
  not delete policy, chunk, manifest, whole-object, outbox, or task data, and
  every historical `chunked-v1` artifact remains readable.
- A pre-0.14.0 client rejects `storage_mode: chunked-v1` rather than treating
  it as a whole object. Upgrading the client restores compatibility; no remote
  migration is required.

## Fixed protocol bounds

| Property | v1 value |
| --- | --- |
| Reader protocol | `encrypted-fixed-chunks-v1` |
| Algorithm | `fixed-16m-domain-sha256-v1` |
| Encryption policy | `rclone-crypt-standard-v1` |
| Plaintext chunk size | 16 MiB (`16,777,216` bytes) |
| Maximum chunks per artifact | 4,096 |
| Maximum chunked artifact | 64 GiB |
| Maximum manifest | 2 MiB |
| Default minimum artifact | 32 MiB |
| Remote deletion | forbidden |

The final chunk may be shorter; every other chunk is exactly 16 MiB. A v1
reader rejects a changed algorithm, size, count, order, offset, total, policy
scope, unknown field, or oversized manifest. There is no negotiated downgrade.

## Encrypted remote layout

The following are logical plaintext paths visible only through the verified
crypt remote. rclone/crypt encrypts both directory/file names and file bytes on
the wrapped provider:

```text
.memory-vault-root.json
.memory-vault-chunk-policy.json
chunks/v1/<key-epoch>/<first-two-hex>/<content-id>
chunk-manifests/v1/<key-epoch>/<manifest-id>.json
objects/sha256/<first-two-hex>/<whole-object-sha256>
```

The policy is immutable and binds the reader protocol, algorithm, encryption
policy, vault ID, store ID, encrypted container ID, credential-free remote
fingerprint, random 256-bit key epoch, chunk size, count bound, and manifest
bound. Chunk roots without the policy marker are refused.

The key epoch is not an encryption key and cannot decrypt anything. It is a
random namespace binding that prevents a receipt or chunk reference from one
verified encrypted store/policy epoch being reused in another. The actual
crypt password and salt remain only in the encrypted rclone config and the
operating-system credential helper.

## Content and manifest identity

Chunk identities are lowercase SHA-256 over a versioned domain prefix followed
by the exact non-empty plaintext chunk bytes. Manifest identities are SHA-256
over a separate versioned domain prefix followed by the canonical,
newline-terminated manifest bytes. Domain separation prevents an ordinary
file hash, chunk hash, and manifest hash from being interchangeable.

A manifest contains the exact artifact SHA-256, size, MIME type, policy scope,
chunk count and total, plus one descriptor per ordered chunk:

```json
{
  "index": 0,
  "offset": 0,
  "size": 16777216,
  "content_id": "<64 lowercase hex characters>"
}
```

The task version stores `storage_mode: chunked-v1` and an
`artifact-storage-ref/v1` whose object ID is
`chunk-manifest-<manifest-id>`, driver is `rclone-crypt`, and verification
level is `rclone-crypt-chunk-manifest-sha256`. Any other combination is
invalid.

## Upload and reuse transaction

1. Verify the immutable local artifact size and whole-file SHA-256 while
   deriving every domain-separated chunk ID. The source's device/inode/mode,
   size, mtime, and ctime snapshot must remain stable.
2. List only the required content-addressed paths in batches of at most 128.
   Command lines and provider output remain bounded on Windows and POSIX.
3. Read and stage only chunks that are missing or need a new local verification
   receipt. A delta upload no longer rereads every unchanged chunk during
   staging.
4. Upload missing chunks with immutable-copy semantics and a strict transfer
   ceiling. A partial or lost-ack result may leave verified chunks but never a
   published manifest; retry lists and reuses those chunks.
5. Prove that remote encrypted bytes decode to the locally verified chunk:
   use rclone `cryptcheck` when the wrapped provider supplies a ciphertext
   checksum. This reads the encrypted nonce and compares provider-side
   ciphertext hashes without downloading the whole chunk. If that capability
   is absent or inconclusive, download only the affected chunks and verify
   their plaintext domain hash and size.
6. Persist a device-local receipt scoped to store ID, encrypted container,
   remote fingerprint, key epoch, algorithm, encryption policy, content ID,
   size, and exact verification method. A different device or policy has no
   receipt and must perform `cryptcheck` or the bounded download fallback
   before reuse.
7. Recheck the source snapshot, upload the canonical manifest immutably, read
   it back, verify its byte hash and domain-separated manifest identity, and
   recheck the source snapshot again.
8. Only after every object and manifest is verified may the Git transaction
   publish a task version that references it and compare-and-swap `CURRENT`.

No provider listing, file name, size, modification time, receipt alone, or
successful process exit can substitute for content verification.

## Restore transaction

1. Resolve the exact store and encrypted container from the artifact reference.
2. Read and validate the current encrypted policy and exact manifest identity.
3. Download the manifest's unique chunks in bounded batches into a private
   temporary directory.
4. Verify every plaintext chunk's domain-separated ID and declared size.
5. Reassemble chunks in manifest order into a temporary destination while
   calculating the final ordinary artifact SHA-256 and byte count.
6. Publish the destination exclusively only after the final identity matches.
   A missing, changed, truncated, duplicated, reordered, or extra chunk leaves
   no partial destination.

Successful restore refreshes device-local receipts because the exact remote
plaintext was verified again.

## Failure, tamper, and rollback behavior

- Interrupted uploads are append-only. Already present chunks are retained and
  reused; no manifest is created until the complete set is verified.
- Remote chunk, manifest, policy, encrypted root, rclone executable, config,
  destination, or local trust-file changes fail closed.
- Provider deletion or rollback can cause unavailability but cannot silently
  produce accepted bytes: manifest, chunk, and final artifact hashes are all
  checked.
- Disabling chunking is the operational rollback. Remote garbage collection,
  key rotation, rechunking, and policy replacement are intentionally absent
  from v1 because they would be destructive or require a new reader protocol.
- The wrapped provider can still observe ciphertext sizes, object counts, and
  transfer timing. Fixed 16 MiB chunks do not hide metadata or provide traffic
  padding.

## Reproducible benchmark evidence

`scripts/benchmark_chunk_protocol.py` uses the production scanner, selective
stager, manifest codec, chunk verifier, interrupted-retry logic, and atomic
restore against a disposable local content-addressed transport substitute.
It measures protocol work and exact transfer bytes, not Internet speed. The
credential-free live test separately executes the production rclone/crypt
process boundary.

The committed 2026-08-05 run is recorded in
`benchmarks/chunk-protocol-v1.json`:

| Artifact | Localized change | Cold transfer | Delta transfer | Retry after chunks reached store | Verified restore |
| --- | ---: | ---: | ---: | ---: | --- |
| 100 MiB | 1 MiB (1%) | 100 MiB | 16 MiB (16%) | 0 bytes | 100 MiB, final SHA-256 |
| 1 GiB | 10,737,419 bytes (1%) | 1 GiB | 16 MiB (1.5625%) | 0 bytes | 1 GiB, final SHA-256 |

Run it again with:

```text
python3 scripts/benchmark_chunk_protocol.py \
  --output benchmarks/chunk-protocol-v1.json
```

Timing varies by hardware; byte counts and protocol invariants are the durable
acceptance evidence.

## Known v1 limits

- Fixed boundaries optimize localized in-place edits. Inserting bytes near the
  start can shift every later boundary and transfer many chunks. A future
  content-defined algorithm requires a new policy and reader protocol; it
  cannot silently reinterpret v1 objects.
- One changed byte transfers one full 16 MiB chunk. This bounds object count
  and provider calls but is less efficient for tiny edits to medium files.
- Artifacts above 64 GiB retain whole-object behavior.
- The client keeps no background watcher and performs no remote deletion or
  automatic retention. Storage cleanup remains an explicit future protocol.
