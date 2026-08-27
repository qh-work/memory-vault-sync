# Provider adapter contract

Memory Vault separates synchronization semantics from provider APIs. The sync engine owns identity, privacy scanning, immutable manifests, provider pins, object-before-control-plane ordering, compare-and-swap, conflict candidates, and recovery. An adapter only supplies a bounded transport that meets this contract.

## Control-plane adapters

A production control-plane adapter must provide:

1. A credential-free canonical HTTPS repository identity.
2. A provider-specific, authenticated privacy check before every fetch or push window.
3. A stable branch reference and Git ancestry.
4. Exact blob lookup for `CURRENT.json` and fast-forward-only publication.
5. Redirect refusal for credentialed Git traffic.
6. Bounded commands with no shell interpolation, inherited hooks, or interactive credential prompts.

The bundled runtime supports private GitHub and GitLab.com repositories. Local Git is isolated to tests. Adding another Git host requires a fixed HTTPS host policy and an API check that proves the configured repository is private and is the exact expected repository. A user assertion such as `private: true` is not sufficient.

## Object-store adapters

An object-store adapter implements four required operations and one bounded
capability decision:

- `assert_private()` proves the configured root meets the adapter's confidentiality and ownership policy;
- `find_verified(sha256, size, mime_type)` returns an exact immutable object only after verifying content identity;
- `upload_and_verify(path, sha256, size, mime_type)` uploads one immutable object and verifies it before returning;
- `download_and_verify(artifact, destination)` retrieves the exact referenced object and verifies SHA-256 and size before exclusive publication.
- `should_chunk(size)` returns false unless the bundled adapter has an explicit,
  versioned chunk reader for that size and the user enabled it. The default
  base implementation is always false.

Each returned object supplies a stable `store_id`, `driver`, opaque `object_id`, opaque `container_id`, and `verification_level`. New task manifests encode these values as `artifact-storage-ref/v1`. Historical `drive_file_id` and `drive_parent_id` fields remain readable but are no longer emitted.

The sync engine may call `find_verified` and `upload_and_verify` concurrently for different content addresses. Adapters must therefore protect token refresh and mutable caches, avoid process-global state, and remain correct when the same immutable object is requested more than once. Concurrency is bounded by configuration and a hard runtime ceiling.

The bundled production registry currently contains `google-drive-v3` and
`rclone-crypt`. The rclone adapter accepts only a `crypt` remote wrapping one
reviewed S3-compatible, HTTPS WebDAV, SFTP, or local backend. Before every trust
window it verifies the exact executable SHA-256 and semantic version, the
owner-only encrypted config file, successful config decryption, redacted
crypt/base sections, standard filename and directory encryption, a custom
salt, strict names, safe TLS/redirect settings, and a credential-free remote
fingerprint. It then verifies an encrypted vault root marker. Object names are
content-addressed, uploads are immutable, and all downloads are streamed
through a fixed byte bound and checked against the manifest SHA-256 and size.
Device-local SFTP trust/key paths are excluded from portable provider pins;
the known-host bytes identify the destination, while every configured local
trust/key file and the encrypted config are re-hashed around each transfer
child-process call and across the complete configuration probe. External
provider commands and unreviewed cipher overrides are not an adapter extension
mechanism.

The bundled rclone adapter may emit `storage_mode: chunked-v1`. That is a
versioned storage protocol, not a generic adapter shortcut. Its encrypted
policy and manifest bind the store, remote fingerprint, key epoch, algorithm,
chunk order, total size, and final artifact identity. Reuse requires a scoped
local receipt created by ciphertext `cryptcheck` or plaintext-download
verification; unsupported checksum backends must fall back safely. Other
adapters cannot return `chunked-v1` until they implement the same reader and
exact schema contract under a separately reviewed protocol. See
`CHUNK_PROTOCOL.md`.

Switching a writable primary never rewrites historical references. The prior
store becomes a read-only archive and each `artifact-storage-ref/v1` routes by
its own `store_id` and `driver`. A switch is refused while pending, blocked, or
candidate outbox transactions still depend on the current provider pins.

## Credential and privacy boundary

- Credentials never appear in adapter configuration, provider pins, manifests, logs, exceptions, subprocess arguments, or export bundles.
- Credentials come from the operating-system credential helper or a provider-owned client.
- An encrypted rclone config password is passed only in the child process
  environment assembled from a fixed allow-list. Arbitrary inherited
  `RCLONE_*` values are stripped so they cannot replace reviewed remote
  settings.
- Redirects never forward authorization to an unapproved origin.
- Provider scope is pinned into each queued transaction. A changed adapter, store, repository, credential reference, or scope quarantines the retry before remote writes.
- An adapter must fail closed when privacy, ownership, identity, size, hash, or response bounds cannot be proved.

## Registration policy

The installable runtime uses an explicit adapter registry. It does not load arbitrary Python files, entry points, workspace code, or remote code at runtime. A new adapter is reviewed and shipped as part of the exact signed plugin bundle, with offline, redirect, tamper, retry, concurrency, and cross-platform tests.

This policy keeps a public fork easy to extend without turning provider configuration into a code-execution surface.
