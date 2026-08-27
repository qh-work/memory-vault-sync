# Memory Network failure recovery

## Offline or timeout

The visible episode intent is already in the private local outbox before a
network attempt. Continue working; local recall remains available. A later
SessionStart or explicit `flush` sends the original deterministic packet. Do
not reconstruct old memory or create a task checkpoint.

## Busy local lock

Another hook/flush owns the synchronization lock. Stop returns quickly and
leaves the packet queued. The next lifecycle event retries the batch.

## Remote branch advanced

The publisher fetches once, proves ancestry, verifies every overlapping path is
byte-identical and replays only missing immutable additions once. If that fails,
the outbox remains intact. Do not loop, force push, reset or select a winner by
timestamp.

## Same path has different bytes

This is an identity collision or tamper event. Stop publication/import. Preserve
the local intent/bundle and remote commit IDs for a private review. Never rename
the object to bypass the conflict.

## Remote memory modified, removed or history rewritten

Incremental receive accepts only additions. Keep the last verified local index
as reference-only, stop advancing its cursor and investigate repository audit
history. Do not accept the changed bytes, rebuild from the rewritten head or
reactivate task CURRENT as a fallback.

## Local index invalid

The SQLite index is derived, never durable truth. Move the invalid database
and its WAL/SHM files into a private local recovery directory, then rebuild from
the last verified remote head. Do not upload the database or include it in a
portable bundle. If remote validation fails during rebuild, retain both the old
index and failure category for manual review.

## Secret or absolute path detected

The content is not transmitted. Quarantine contains only transaction ID,
reason code, time and `content_preserved: false`. Remove or redact the sensitive
material in a new visible turn if the user wants the non-sensitive part saved;
never hash or encode the secret to bypass scanning.

## Import/export error

- Existing export target: choose a new private path; never overwrite.
- Invalid ZIP/path/symlink/duplicate/undeclared/bomb: reject the whole input.
- Entry hash or schema mismatch: reject before commit.
- Existing path, same bytes: count as reused.
- Existing path, different bytes: hard conflict.
- Network interruption between import batches: rerun the same bundle; already
  committed immutable objects are reused.

## Missing credentials or public repository

No publication is allowed. Re-authenticate the exact credential-helper host and
verify expected repository identity/private visibility with `doctor --online`.
Do not place a token in config or URL and do not temporarily switch to a public
remote.

## Plugin update or missing cached runtime

Hooks first require a complete regular-file runtime inventory. They may use the
installed plugin or an already verified fallback bundle with matching version
and hashes. If neither is complete, no memory pointer/object is written.
Reinstall the exact reviewed plugin version, verify entrypoint/core/manifest and
rerun `doctor`.

## Legacy task data

Old task, binding, projection and CURRENT files are never a recovery authority
for the new network. Safe visible revisions may be re-indexed; ownership and
routing metadata stay historical. Do not delete that history automatically and
do not use the retired binding commands—those commands are absent from the
installed CLI.

## Recovery evidence to retain

Keep only content-free details unless the user explicitly authorizes local
private inspection:

- plugin version;
- operation and bounded error category;
- opaque transaction/event/episode IDs;
- local and remote commit IDs;
- counts and byte sizes;
- whether the outbox remains present;
- whether any remote write was accepted.

Do not record exception text, memory content, file paths, environment, device
identity, credentials, hidden reasoning or tool transcript.
