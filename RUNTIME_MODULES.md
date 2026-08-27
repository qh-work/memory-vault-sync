# Runtime and validator module map

This map defines the supported dependency direction for maintainers. The
installable plugin remains standard-library-only and self-contained under
`plugins/memory-vault-sync`; the repository validator may reuse deterministic
protocol primitives from that package but never imports private vault state.

## Dependency direction

```text
hooks.json / windows_launcher.ps1
                |
                v
scripts/vault_sync.py                 scripts/validate_layout_v1.py
                |                                  |
                v                                  v
memory_vault_runtime.core             memory_vault_validator.core
   |       |       |       |       |       |        |          |
   v       v       v       v       v       v        v          |
 errors privacy bundle  chunks diagnostics memory  signed     |
   \       |      /       /       /      network   updates     |
    +------v-----+-------+-------+--------+---------+-----------+
                                     |
                                     v
                                  retrieval
             protocol
```

Lower modules must not import `core`. This prevents circular policy ownership
and keeps import-time work free of network and filesystem mutation.

## Plugin modules

| Module | Owns | Must not own |
| --- | --- | --- |
| `vault_sync.py` | Stable CLI/hook executable, literal package version, compatibility reads | Protocol rules, provider behavior, persistence |
| `memory_vault_runtime.core` | Command dispatch and orchestration of configuration, private Git transport, taskless lifecycle, outbox, network import/export, legacy visible-memory migration, providers and updates | Tokenization/ranking, duplicate error classes, secret patterns, JCS encoding, runtime file allow-list |
| `memory_vault_runtime.errors` | Expected failure categories and retryability | Logging, serialization, side effects |
| `memory_vault_runtime.privacy` | Secret patterns, absolute-path rejection, visible-text bounds, recursive remote-document safety | Credentials, network calls, local state |
| `memory_vault_runtime.protocol` | Strict JSON, persisted JSON bytes, integer-only RFC 8785 encoding, SHA-256 bytes | Vault-specific schemas or storage |
| `memory_vault_runtime.bundle` | Exact files, size bounds, modes, and ordered hash inventory for the fallback runtime | Copying files or choosing update sources |
| `memory_vault_runtime.chunks` | Fixed encrypted-chunk policy and manifest schemas, bounds, domain-separated content identities, and deterministic paths | Provider calls, credentials, receipts, or publication |
| `memory_vault_runtime.diagnostics` | Exact content-free diagnostic schema, private bounded persistence, rotation, corruption accounting, and path-free summaries | Exception text, traces, task/provider content, network calls, or runtime orchestration |
| `memory_vault_runtime.memory_network` | Stable taskless IDs, immutable episode/event construction, text fragmentation, CJK/Latin tokens, private SQLite inverted index, graph state, bounded ranking and recall rendering | Network/provider calls, credentials, durable authority, task ownership, external model calls |
| `memory_vault_runtime.graph_views` | Rebuildable claim timelines, bounded relation traversal, current/superseded/conflicted/resolved explanations, and proposal-only consolidation hints | Durable writes, visible text authority, task/conversation/device ownership, model inference, network calls |
| `memory_vault_runtime.checkpoint` | Canonical taskless hash checkpoints, monotonic chain validation, and explicit test-anchor verification | Production signing keys, key distribution, network calls, durable memory mutation, or automatic trust decisions |
| `memory_vault_runtime.packs` | Independently compressed object records, path/hash/offset index, bounded pack verification and ZIP restoration | Canonical authority, provider calls, credentials, plaintext encryption claims, or unbounded memory buffering |
| `memory_vault_runtime.transport` | Crash-safe resumable byte copies with source identity and monotonic journal offsets | Network/provider policy, remote trust, object mutation, credentials, or silent conflict resolution |
| `memory_vault_runtime.retrieval` | Versioned deterministic local concept/polarity features and similarity scoring; concept scoring may be disabled while lexical recall remains usable, but this file stays mandatory in the verified runtime inventory | Durable memory, filesystem/network I/O, learned-model claims, task ownership, or lexical fallback |
| `memory_vault_runtime.sharing` | Strict taskless evidence/concept/time selectors, deterministic relation/evidence closure, and `memory-share-bundle/v1` verification | Encryption, recipient private keys, task ownership, plaintext redaction claims, or network calls |
| `memory_vault_runtime.crypto_adapter` | External-provider file contract, opaque `memory-share-envelope/v1` framing, ciphertext hashes, and decrypt-then-verify atomic import | Hand-written cryptography, key storage, plaintext publication without a provider, or network calls |
| `memory_vault_runtime.device_trust` | Versioned opaque-device enrollment, key epochs, future-only revocation, monotonic transitions, and recovery descriptors | Private keys, signatures, threshold ceremony, automatic trust, or memory ownership |
| `memory_vault_runtime.encrypted_replication` | Ciphertext-only append-only catalog, external signer boundary, replay/rollback checks, and atomic envelope copies | Plaintext memory parsing, cryptography, signer keys, remote transport, or silent recovery |
| `memory_vault_runtime.signed_updates` | Narrow four-role signed-metadata profile, RSA-PSS public verification, canonical envelopes, root rotation, expiry/clock/rollback/mix-and-match state, target binding, and safe bounded metadata reads | Signing, private keys, network/Git/install calls, provider/task data, general TUF compatibility, or runtime orchestration |

`core` remains the compatibility home for mature orchestration APIs. Future
extractions move one characterized responsibility at a time and keep the
dependency direction above; a new module is not allowed to reach back into
`core` for mutable globals.

## Validator modules

`validate_layout_v1.py` is only the stable command/import boundary.
`memory_vault_validator.core` owns repository traversal, schemas, immutable
history checks, and issue reporting. Its deterministic event/checkpoint hash
domain calls `memory_vault_runtime.protocol`, so runtime and validator cannot
silently diverge on UTF-16 key ordering, safe integers, forbidden floats, or
SHA-256 input bytes.

## Verified fallback runtime

Runtime cache schema `memory-vault-sync-runtime-cache/v3` records an ordered
entry for every allow-listed runtime file. Activation performs these steps:

1. Read every source file through the bounded plain-file verifier.
2. Require the entrypoint and core to declare the exact same semantic version.
3. Atomically copy each file with its declared private mode.
4. Persist the exact path, size, and SHA-256 inventory plus release identity.
5. Read every activated file again and compare bytes and inventory before use.

A missing, linked, reordered, extra-metadata, or byte-changed required module
invalidates the cached identity. Hooks require the complete declared runtime
inventory, including signed-update verification, before choosing either the
installed package or the stable fallback. A routine refresh preserves an
already verified bundle/commit identity; it cannot replace that identity with
an unverified value merely because the running version is unchanged.

## Refactor safety checklist

- Add an observable characterization test before moving a public command,
  hook output, deterministic byte encoder, or persisted document.
- Add a new module to `RUNTIME_FILE_SPECS`; otherwise updates may work from the
  installed cache but fail after that cache is pruned.
- Keep the wrapper version, core version, and plugin manifest identical.
- Run plugin tests from the core module when mocking internals; test the small
  entrypoint separately as a subprocess boundary.
- Export and test the validator package together with its entrypoint.
