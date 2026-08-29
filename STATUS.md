# Public release status

Last updated: 2026-08-30

Current source release: `0.21.0+codex.20260830000842`

Current public tag: `v0.21.0`. The public workflow validates the source/privacy
contract and maintained plugin suite on Ubuntu Python 3.10/3.12, macOS Python
3.12, and Windows Python 3.12. The adapter fixtures remain synthetic and do
not establish real-host integration or production certification.

Memory Vault Sync is released as an Apache-2.0 source distribution. The public
repository is generated from an explicit allowlist into a new history and
contains no user memory, conversation source, task/binding state, device
instance, handoff, credential, local index, outbox, diagnostic record, private
trust state, or production key material.

The 0.21 release adds a model-neutral local stdio host protocol, Vault-issued
continuity/turn handles, and Claude Code, Gemini CLI, and generic local-runtime
reference adapters. All hosts use one Vault. Prompt/recall/compact paths stay
zero-network, final turns receive a durable local acknowledgement before any
optional publication, and exact retries require byte identity. It changes no
durable episode/event schema, memory ownership, or instruction model.

## Implemented

- immutable `memory-episode/v1` visible evidence;
- append-only taskless `memory-event/v2` continuity and semantic relations;
- evidence-anchored `assistant_inferred` decisions, corrections, preferences,
  constraints, progress, next actions, conflicts, and resolutions;
- local CJK/Latin lexical and deterministic concept recall with bounded,
  explicitly untrusted context;
- rebuildable current, superseded, conflicted, and resolved claim views;
- Git commit-cursor incremental receive with immutable mutation, rollback, and
  same-path conflict rejection;
- two-object ordinary publication, bounded batching, one safe concurrency
  replay, and an offline authenticated outbox;
- verified complete network export/import;
- independently hashed memory packs, resumable local pack copy, and hash-only
  checkpoints;
- taskless selective subgraph closure and an external encryption-provider
  envelope boundary;
- opaque device enrollment, key-epoch, rotation, revocation, and recovery
  contracts;
- private GitHub and GitLab destination verification;
- standard-library runtime for Python 3.10+ on macOS, Windows, and Linux;
- read-only migration of safe visible legacy revisions without transferring
  task ownership, bindings, routing, projections, or `CURRENT` pointers.
- closed model-neutral local stdio host requests and responses;
- Vault-issued opaque continuity/turn handles with no native host identifiers;
- durable local final-turn acknowledgement independent of public network
  latency;
- exact-byte retry reuse and hard conflict for changed request bytes;
- fixed negative authority labels on every response;
- reference adapters for Claude Code, Gemini CLI, and generic local runtimes,
  while retaining existing Codex hooks.

The production CLI has no task binding, task routing, projection, ownership, or
task-current command. Compatibility schemas and code that mention tasks are
migration-only and cannot be activated as the production memory model.

## Deliberate limitations

- The source repository is public, but every live memory control repository
  must remain separate and private.
- Git-host privacy protects the ordinary remote. Payload encryption and
  server-unreadability are not claimed unless a separately audited encryption
  provider is configured.
- Production signing keys, OS key-store integration, recovery authority, and
  real multi-device ceremonies are not bundled.
- A first client without an external signed checkpoint cannot independently
  detect history erased before its first verified cursor.
- Retrieval is deterministic lexical/graph recall with a small hand-authored
  concept bridge, not an embedding model or vector database.
- The current pack path first materializes a verified canonical export before
  converting it; direct Git-object streaming for unbounded histories remains
  future work.
- Internet startup and Stop latency still includes private-repository identity
  verification and Git transport.
- The public distribution remains a personal/local marketplace distribution and
  has not yet been submitted to the universal plugin directory.
- The optional MCP cognitive interface is future work; 0.21 does not implement
  or claim an MCP server.

## 0.21 publication evidence

The 0.21 release intentionally publishes its test material so other AI
models, agents, and maintainers can extend it. The reference-adapter tests,
closed schemas, examples, and synthetic golden fixtures are a small conformance
seed, not a high-coverage claim or complete host certification.

The bounded `v0.21.0` release gate is:

1. generate a fresh tree with the allowlisted exporter and retain Apache-2.0;
2. verify version equality, JSON/schema parsing, Python compilation, and the
   focused host-protocol/reference-adapter fixtures;
3. verify the export/privacy contract contains no private state, native IDs,
   account data, credentials, paths, transcripts, or live memory;
4. publish the exact fixtures and observed results in the public tree;
5. smoke-check the model-neutral CLI and retained Codex hook entrypoints.

Broader plugin, repository, platform, and real-host suites may be added when
risk or contributors justify them, but this status must list only checks that
actually ran. Passing the minimum gate must never be described as high
coverage, real-account integration, or full cross-platform certification.
