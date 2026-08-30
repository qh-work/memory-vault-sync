# Explicit remote backends

This optional full-client transport uses the same signed canonical memory
records as the light [protocol](../PROTOCOL.md). Its job is bounded delivery,
not account creation, trust enrollment, Git synchronization or task ownership.
See [SYNC.md](SYNC.md) for opt-in, queues, receipts, limits and cancellation.

This code was not run against real directories or cloud accounts during this
development pass. The following describes the implemented contract, not a
tested support matrix or a deployment report.

## Directory exchange

Configure `--backend directory --exchange /absolute/shared/memory-exchange`.
The operator chooses who can access the directory and whether a separately
authorized folder-sharing service carries it elsewhere. Memory Vault starts no
network connection for this backend and does not configure that external service.

Only signed capsules/manifests and their exact committed fragments use this layout:

```text
exchange/
  ed25519_<public-key-sha256>/
    store_<source-store-id>/
      <after-20-digits>-<cursor-20-digits>-<payload-sha256>.json
      groups/
        <group-id-sha256>/
          <index-6-digits>-<fragment-sha256>.ndjson
```

Vaults, private keys, trust stores, configuration, turn journals and sync state
must remain outside the exchange. Outbound publication review applies even if
the destination is a local folder. A signature identifies a registered source;
it does not make a shared folder confidential or establish that its claims are
true. Files are created with private local permissions; cross-user sharing and
remote confidentiality remain the operator's responsibility.

Directory discovery is bounded to 20,000 examined entries, 256 source streams
and 256 candidate checks, with tighter per-window file/byte/time budgets in the
sync service. Untrusted sender directories are not automatically enrolled or
opened for import. The full sync wrapper skips its own store's published stream.
An oversized or hostile exchange can still prevent a completed scan; it is not
an anonymous public inbox with guaranteed denial-of-service resistance.

## Preconfigured rclone

The operator must already have an installed rclone executable and a deliberately
selected configuration file. The service neither installs it nor runs login,
configuration discovery, browser authentication, `rclone sync`, deletion,
mounting, serving, or remote-control commands. rclone's configuration model and
explicit `--config` selection are documented in the [official usage guide](https://rclone.org/docs/).

Supported selected backend types in this adapter are `drive`, `s3`, `webdav`,
`sftp`, and `crypt` wrapping one of those (at most four selected configuration
sections in the chain). Other rclone backend types are deliberately rejected;
this is not a claim that every rclone feature is available here.

```sh
python3 /absolute/source/memory_vault_sync.py \
  --config /absolute/private/control/sync.json configure \
  --vault /absolute/private/data/memory.db \
  --identity /absolute/private/keys/identity.json \
  --trust-store /absolute/private/keys/trust.json \
  --state-directory /absolute/private/sync-state \
  --backend rclone \
  --rclone-executable /absolute/tools/rclone \
  --rclone-config /absolute/private/provider/rclone.conf \
  --remote memoryremote:dedicated-memory-prefix
```

This is still manual-only. Add `--automatic --background` only with explicit
authorization. Add a repeated `--peer KEY_ID/STORE_ID` for each intended incoming
stream (at most 16). Receive-only membership is not discovered by listing the
remote root. Obtain the source's `store_id` from its operator's Vault status and
verify/register its public descriptor independently using [TRUST.md](TRUST.md).
An empty peer list publishes only. A peer identifier is a stream address, not a
grant of trust; both the sender and all record signer keys must be trusted.

The exact executable is hashed at configuration time, without executing it.
Workers verify that SHA-256 before use and watch its identity/size/mtime between
commands. An upgrade requires explicit reconfiguration with `--replace` and
retains cursors if the Vault/key/destination remain the same. Adding a peer also
retains stream state. Both changes invalidate a currently running window. Choose a
real absolute executable path, not a symlink such as a package-manager shim.
This file hash is a pin selected by the operator, not publisher verification or
a sandbox for arbitrary executables.

The rclone config must be an ordinary current-user-owned 0600 file on POSIX,
or a file with a validated private native ACL on Windows; no symlink/reparse or
hard-link alias, at most 1 MiB. The adapter rejects encrypted config containers
that require a password helper; this is distinct from a supported `crypt`
**remote**. Use a separate protected configuration file when necessary. It is
not copied into capsules, and the adapter never prints its contents.

The selected configuration chain cannot use arbitrary command/password/SSH
helpers or ambient cloud credential discovery. WebDAV requires HTTPS, custom S3
endpoints require HTTPS, and SFTP requires an explicit absolute known-hosts file.
SFTP hash commands and password prompts are disabled. Existing proxy routing is
preserved, but `RCLONE_*`, cloud credential environment variables and SSH agent
sockets are not inherited by the provider process. An explicitly selected config
can still reference its own credential files; it is operator-controlled input,
not a permissions sandbox. Provider token refresh may update the selected
rclone config through rclone's normal behavior.

## Exact-prefix wire layout

The rclone backend uses cursor buckets to avoid relisting an ever-growing
source history:

```text
memoryremote:dedicated-memory-prefix/
  ed25519_<public-key-sha256>/
    store_<source-store-id>/
      <after-20-digits>/
        <after-20-digits>-<cursor-20-digits>-<payload-sha256>.json
      groups/
        <group-id-sha256>/
          <index-6-digits>-<fragment-sha256>.ndjson
```

This bucket layer differs from the flat directory exchange. Pointing an rclone
backend at a directory exchange does not convert its layout. Peers sharing one
rclone stream must use this cursor-bucket transport contract. The capsules
inside use `universal-memory-delta/v2` and the standard record/message
attestations; v1 remains receive-compatible during explicit chain upgrade.
No task or database path is embedded in an address. `groups/` is a sibling of
cursor buckets, not a remotely listed directory or an address selected by
memory text.

Remote names are restricted ASCII identifiers and the prefix must contain at
least one dedicated relative path component. Inline backend specifications,
root destinations, empty prefixes, `.`/`..`, spaces and shell metacharacters
are rejected. The adapter constructs child key/store/cursor/filename components
from validated identifiers; memory text cannot select a remote path.

For an explicitly trusted peer, a worker lists its exact expected cursor bucket
and, if present, the exact previously accepted head bucket for rollback/fork
checks. It uses `lsf --files-only --max-depth 1 --disable ListR`, limits listing
output to 16 KiB and accepts at most 8 candidate files. Each candidate is at most
4 MiB. It reads exact names with `cat`, verifies all candidates at that prefix
before accepting one, then records a local transactional receipt. It never
skips a missing prefix or downloads an unverified directory tree. The flags'
nonrecursive/list formatting behavior is defined in [rclone lsf](https://rclone.org/commands/rclone_lsf/),
and bounded head reads in [rclone cat](https://rclone.org/commands/rclone_cat/).

Before uploading, the same bounded bucket lookup rejects an already signed,
different candidate at that prefix. This prevents common state-reset forks but
is not a remote compare-and-swap lock; use exactly one publisher state per
key/store/destination. Uploads use exact source/destination `copyto` paths with `--immutable`, no
traversal, bounded transfer sizes and one retry. A successful provider command
alone is insufficient: the worker reads the destination back and requires exact
plaintext bytes before advancing the remote receipt. This also applies through
`crypt`. Encryption remains a separately configured provider capability, not a
promise made by signatures. See the [official copyto flags](https://rclone.org/commands/rclone_copyto/)
and [crypt documentation](https://rclone.org/crypt/).

For a fragmented v2 capsule, the signed manifest contains every fragment's
index, hash, byte count and record count. The worker accepts only that exact
validated membership when constructing a fragment path; it does not list or
copy a remote `groups/` tree. Each fragment is at most 4 MiB. Uploads finish and
read back those exact plaintext bytes before persisting a per-fragment private
receipt. A retry reuses matching receipts bound to this destination; after all
fragments have such receipts, the manifest is uploaded and checked **last**.
Only then does the remote cursor advance. At most eight fresh fragments are
uploaded by one call, and the shared file/time/byte budget can stop it earlier.
Independent events or explicit `flush` calls continue pending work; there is
no self-relaunch loop.

The receiver similarly resumes verified private fragment staging. Partial,
missing, corrupt or untrusted groups admit no canonical memory and advance no
receive cursor. Complete ordered bytes, canonical record sizes/counts and all
current signatures are checked before one atomic Vault import. The limits are
the core's 100,000 records and 64 MiB of canonical record bodies, with bounded
proof overhead; exceeding a small outgoing batch target is no longer treated
as a reason to omit the memory. See [SYNC.md](SYNC.md) and the
[group schema](../schemas/fragment-group.schema.json) for the exact contract.

Cached upload receipts attest that a fragment was verified earlier; they are
not a lease on storage or proof that the provider still has the fragment. A
later provider deletion remains a visible receive failure, not successful
delivery. Likewise, the last-head check detects observed rollback/forks but
cannot prove that every older object is still present, or expose an unseen
split history shown only to a different peer.

Per-window limits cover attempted payload transfers and verification reads;
they are not byte-accurate network billing limits. A 64 KiB allowance above the
4 MiB capsule ceiling is used for the provider's hard transfer cap, allowing
framing/encryption overhead without setting the stop threshold exactly at EOF.
HTTP metadata requests, retries inside a provider SDK and encrypted headers can
add wire traffic. Directory-not-found exit code 3 means an empty expected bucket,
not permission to discover another root. Other nonzero statuses fail visibly.
Timeout and exit-code meanings follow [rclone's official documentation](https://rclone.org/docs/#list-of-exit-codes).

## Isolation, faults and remaining work

All subprocesses use fixed argument arrays with `shell=False`; stderr/stdout are
bounded and provider diagnostics are not persisted as unredacted account data.
Capsule/fragment plaintext may exist in the private staging exchange, review
journal, transfer cache and provider temp files, so protect the whole state
directory. No cache, key, config or arbitrary
artifact directory is ever uploaded wholesale.

Time and cancellation are checked between operations and while reading provider
output. Cancelling a request cannot undo a provider-side copy that already
completed. Retries leave immutable remote history in place; there is no automatic
remote garbage collection or pruning. A malicious destination can hide, delete,
delay or flood expected candidates and deny availability, but cannot mint trusted
signatures. Same-user filesystem replacement and a malicious configured rclone
binary are outside the isolation guarantees.

The Windows profile selects a real local `.exe` with a pinned hash and checked
readable/non-other-writable ACL. It uses native pipe availability checks instead
of attempting to select Windows subprocess pipes as sockets; byte/time limits
and cancellation remain explicit. Its child environment contains the Windows
runtime directory, selected private temporary paths and existing proxy routing,
not ambient cloud/rclone/SSH credentials. Cancellation targets only the exact
rclone process launched by this window; it is not a Windows Job Object sandbox
for arbitrary child executables. Native/provider calls and SQLite transactions
can still exceed a nominal deadline if the operating system stalls. See
[PLATFORMS.md](PLATFORMS.md); none of this has been validated by running a native
Windows deployment in this development pass.

Provider connectivity, account permissions, backend-specific flags, interruption,
OAuth refresh, replay and storage-full recovery still require independent runtime
validation on synthetic data. Publishing these source files is not evidence that
those checks passed. Upload is not proof of remote AI reception or use.
