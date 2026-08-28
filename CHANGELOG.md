# Changelog

All notable public changes are documented here.

## 0.20.1 — 2026-08-27

Windows portability and release-CI maintenance patch.

### Fixed

- verify private Windows directory chains with native no-reparse directory
  handles and stable file IDs instead of the CRT file-only open API;
- compare path and handle metadata using the stable fields each Windows API
  actually guarantees, while retaining type, size, identity, and reparse
  checks;
- obtain fresh diagnostic file identity rather than cached zero-valued
  `DirEntry` identity fields on Windows;
- close incompatible SQLite indexes before recoverable quarantine, use native
  absolute paths in rclone fixtures, and close test connections deterministically
  so Windows can move or remove temporary files.

### Maintenance

- update pinned official GitHub Actions to their Node 24 releases without
  introducing floating action tags.

## 0.20.0 — 2026-08-27

Initial Apache-2.0 open-source release.

### Added

- taskless immutable episodes and append-only semantic/continuity relations;
- local-only associative recall with deterministic CJK/Latin lexical scoring,
  concept signals, graph state, and bounded explanations;
- incremental Git receive, immutable-history checks, bounded publication,
  offline outbox recovery, and one safe concurrency replay;
- rebuildable claim timelines and conflict/resolution views;
- verified network export/import, memory packs, resumable copy, and checkpoints;
- selective taskless subgraph closure and fail-closed external encryption
  boundary;
- opaque device trust and ciphertext-replication protocol contracts;
- private GitHub/GitLab destination verification;
- macOS, Windows, and Linux runtime paths for Python 3.10+;
- allowlisted public-source generation, synthetic benchmarks, privacy tests,
  community files, and cross-platform CI configuration.

### Security

- recalled memory is labeled untrusted historical evidence and cannot grant
  execution, write, credential, file, artifact, policy, or identity authority;
- durable objects reject common credential, native identifier, and local-path
  patterns;
- the public repository contains no live memory, conversation, task/binding
  state, instance, handoff, cache, outbox, diagnostic record, private trust
  state, production key, or private source history;
- production encryption, signing, key storage, enrollment, and recovery
  providers remain unconfigured and fail closed.

### Compatibility

Verified visible revisions from an earlier task-oriented vault may be imported
as historical evidence. Legacy tasks, bindings, projections, routing records,
and `CURRENT` pointers are migration-only and never own active memory.
