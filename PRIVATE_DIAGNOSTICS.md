# Private diagnostics protocol

Memory Vault Sync 0.14.1 records bounded local metadata when a lifecycle hook
hits an unexpected internal exception. The record helps correlate a generic
user-visible warning with one operation and runtime version. It is not a log,
crash dump, task checkpoint, telemetry stream, or remote recovery authority.

## What creates a record

The runtime records an event only when an unexpected exception crosses one of
these reviewed boundaries:

- `hook.session-start`, `hook.user-prompt-submit`, or `hook.stop`;
- `hook.session-start.update-check` while the normal hook continues; or
- the corresponding `.setup` operation if initial local setup fails in an
  unexpected way.

Expected `VaultSyncError` categories such as offline transport, a privacy
refusal, conflict, invalid configuration, cancellation, or a busy lock keep
their existing generic handling and do not masquerade as internal failures.
No diagnostic event changes a task pointer, retries a write, or grants access.

## Exact record

Each `memory-vault-private-diagnostic/v1` JSON document has only:

| Field | Meaning |
| --- | --- |
| `correlation_id` | Random `diag-` plus 32 lowercase hexadecimal characters |
| `occurred_at` | Informational UTC recording time; never merge authority |
| `operation` | One reviewed lifecycle boundary |
| `runtime_version` | Exact plugin runtime version |
| `error_category` | Bounded reviewed category, currently `unexpected-internal` |
| `remote_pointer_moved` | Always `false` |
| `captured_sensitive_content` | Always `false` |

The writer has no parameter for exception text or traceback. It never reads or
stores exception arguments, stack frames, local paths, environment variables,
credentials, repository/provider identifiers, hostname, username, device ID,
conversation text, task content, artifacts, prompts, model output, or hidden
reasoning. A malformed local record is counted as corrupt without echoing its
bytes through the summary command.

## Private storage and retention

Records live only under the Codex-managed plugin data directory at
`diagnostics/records/`. The directory is mode `0700` and each exclusive regular
file is mode `0600` on POSIX. Symbolic links, hard-linked files, unexpected
entries, broad file permissions, oversized files, and changed identities are
refused.

Limits are fixed in the protocol:

- at most 4 KiB per record;
- at most 64 records;
- at most 256 KiB total;
- oldest local records rotate before a new record is committed.

Diagnostics are never copied to Git, an object store, an update bundle, a
public-source export, or another device. The public source tree includes only
the implementation, tests, and this contract.

## Operator view

The hook continues to return a generic safe warning. When persistence
succeeds, the warning also includes the opaque correlation ID. It never
includes the underlying exception.

Inspect the bounded path-free summary locally:

```text
vault_sync.py diagnostics --limit 10
```

The command works before provider configuration. `status` reports record and
corruption counts; `doctor` fails its `private_diagnostics` check when the
store is unavailable or contains a corrupt record. These commands return
metadata only and perform no network operation.

Do not paste raw files or the plugin data directory into an issue. If a
maintainer needs evidence, share only the command output after reviewing its
operation, timestamp, version, category, and correlation ID.

## Acceptance and limits

Automated tests cover exact fields, non-capture of secret/path-shaped values,
canonical bytes, POSIX permissions, symbolic-link refusal, rotation, total
size, corruption without echo, unexpected hook/setup/update failures,
expected-offline separation, the unconfigured CLI, status, doctor, modular
fallback inventory, and public export.

These tests do not prove a real macOS/Windows/Linux multi-device deployment or
live S3/WebDAV/SFTP/Drive credentials. Deployment acceptance must separately
record exact OS/Python/rclone/plugin versions and pass first authorization,
concurrent edit, offline queue, partial upload, credential expiry, updater,
rollback, and artifact byte-equality scenarios. Publish only reviewed redacted
receipts; do not label absent or billing-blocked CI as passed.
