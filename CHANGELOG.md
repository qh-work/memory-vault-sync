# Changelog

All notable public changes are documented here.

## 0.21.0 — 2026-08-30

Released the model-neutral host protocol and public reference adapters for one
taskless Vault shared across AI runtimes.

### Added

- closed local stdio request/response schemas and bounded NDJSON framing;
- Vault-issued opaque continuity and turn handles with no native host IDs;
- zero-network prompt input, explicit recall, compact, abort, close, and status;
- durable local final-turn acknowledgement before optional receive/publication;
- exact canonical-byte retry reuse and hard conflict for changed bytes;
- fixed negative instruction/authorization/policy/execution authority labels;
- Claude Code, Gemini CLI, and generic local-runtime reference adapters;
- public protocol/schema examples and focused reference-adapter fixtures so
  other AI models and maintainers can extend interoperability cases without
  access to private memory or host accounts.

### Compatibility and scope

- existing Codex hooks remain compatible and use the same Vault;
- `memory-episode/v1` and `memory-event/v2` are unchanged;
- tasks, projects, conversations, adapters, devices, agents, and models remain
  provenance only and never own memory;
- the focused public fixtures establish a minimum conformance boundary, not
  high coverage or complete host certification;
- an MCP cognitive interface is planned for 0.22 and is not implemented here.

### Verification

- the allowlisted Apache-2.0 export contains 124 files and declares
  `private_state_included=false`;
- public CI runs the source/privacy contract and maintained plugin suite on
  Ubuntu Python 3.10/3.12, macOS Python 3.12, and Windows Python 3.12;
- public schemas, adapters, and synthetic fixtures are release evidence for
  the documented protocol boundary, not real-host or production certification.

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
