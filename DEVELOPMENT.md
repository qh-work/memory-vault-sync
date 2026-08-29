# Development guide

Read [`MEMORY_NETWORK.md`](MEMORY_NETWORK.md),
[`HOST_ADAPTER_PROTOCOL.md`](HOST_ADAPTER_PROTOCOL.md),
[`CLIENT_SYNC_CONTRACT.md`](CLIENT_SYNC_CONTRACT.md), and
[`SECURITY.md`](SECURITY.md) before changing the runtime.

## Supported production model

Production has exactly one memory model: the taskless associative network.
Host and model adapters are delivery boundaries over that one model, not new
memory modes or owners.
Historical task/binding code in `core.py` is a migration-characterization seam
for `_test_mode`; it is not an alternative product mode. Do not add a new CLI,
config switch, hook branch, or skill instruction that reactivates it.

## Code map

| Path | Responsibility |
|---|---|
| `plugins/memory-vault-sync/hooks/hooks.json` | verified lifecycle launch and user-facing progress text |
| `plugins/memory-vault-sync/scripts/vault_sync.py` | stable self-contained entrypoint/version boundary |
| `memory_vault_runtime/core.py` | Git/private remote, lifecycle, outbox, schema validation, import/export, semantic writes |
| `memory_vault_runtime/memory_network.py` | IDs, episodes, fragments, SQLite index, graph edges and recall |
| `memory_vault_runtime/host_adapter.py` | closed model-neutral request/response validation, opaque handle syntax, capabilities and negative authority envelopes; no I/O |
| `memory_vault_runtime/retrieval.py` | versioned deterministic local retrieval adapters; no I/O or durable authority |
| `memory_vault_runtime/privacy.py` | credential/path/remote publication guards |
| `memory_vault_runtime/protocol.py` | JCS/SHA-256 deterministic primitives |
| `memory_vault_runtime/bundle.py` | verified fallback runtime inventory |
| `skills/sync-memory-vault/SKILL.md` | agent operating policy |
| `tests/test_memory_network.py` | pure index/object/performance tests |
| `tests/test_vault_sync.py` | Git, lifecycle, concurrency, migration and bundle integration |
| `tests/test_runtime_module_contract.py` | installable CLI and version contract |
| `adapters/` | thin Claude Code, Gemini CLI and generic stdio lifecycle translators plus isolated conformance fixtures |

## Core invariants

Every change must preserve:

1. no production task binding, routing, task-current or projection operation;
2. episode/event existing paths never change bytes;
3. normal turn writes exactly one episode and one continuity event;
4. prompt recall performs no network operation;
5. incremental receive rejects any non-add immutable change;
6. remote privacy is proved before write;
7. outbox is durable before network and survives failure;
8. concurrent replay is bounded to one and requires exact overlap;
9. AI semantic claims are episode-anchored and `assistant_inferred`;
10. credentials, local paths, native conversation IDs, hidden reasoning and tool
    traces never enter durable network objects;
11. portable export includes no task/binding/pointer document;
12. derived local indexes are rebuildable and never become sole truth.
13. host/task/project/model/native identifiers never enter the adapter protocol,
    durable identity, recall filters, or ownership;
14. prompt/explicit recall and compact adapter paths are zero-network;
15. host turn completion is durable locally before acknowledgement and does not
    wait for optional publication;
16. request identity reuse is accepted only for exact canonical-byte retries;
17. adapter responses can never grant instruction, authorization, policy, tool,
    file, resource, or execution authority.

## Change impact matrix

| Change | Also review |
|---|---|
| Episode/event schema or path | validators, export/import, index, tests, protocol docs |
| Tokenization/ranking | recall bounds, quality cases, performance fixture, injection label |
| Receive cursor/diff | ancestry and mutation tests, offline behavior, Git host compatibility |
| Publish/outbox | crash order, batching, retry bound, concurrency tests, Stop latency |
| Semantic proposal | relation validation, idempotency, confidence, skill examples |
| CLI command | manifest/default prompt, skill, runtime contract, public export |
| Host adapter operation/schema | zero-network set, handle/receipt state, authority labels, reference adapters, conformance fixtures, `HOST_ADAPTER_PROTOCOL.md` |
| Runtime file | hooks Unix/Windows inventories, `bundle.py`, `RUNTIME_MODULES.md` |
| Version | entrypoint, core, manifest, marketplace, hooks, changelog, status |
| Public docs/assets | open-source exporter allowlist and exported-tree tests |

## Test sequence

Run focused checks while editing:

```text
python3 -m py_compile \
  plugins/memory-vault-sync/scripts/memory_vault_runtime/core.py \
  plugins/memory-vault-sync/scripts/memory_vault_runtime/host_adapter.py \
  plugins/memory-vault-sync/scripts/memory_vault_runtime/memory_network.py

python3 -m unittest -v \
  plugins.memory-vault-sync.tests.test_memory_network \
  plugins.memory-vault-sync.tests.test_graph_views
```

Then run the taskless integration cases for publication, second-client recall,
incremental receive, batching, concurrency, export/import, semantic
supersession, privacy and immutable-history rejection.

For a host-adapter change, also run the protocol/schema cases and the isolated
reference-adapter suite. Cover exact retry versus hard conflict, crash-safe
local acknowledgement, staged-prompt equality, offline operation, compact and
prompt zero-network behavior, malformed/oversized frames, native-ID exclusion,
negative authority labels, and Claude/Gemini final-turn mapping. Never use a
live user transcript or account identifier as a fixture.

### Public conformance seeds

The reference-adapter tests, protocol schemas, example frames, and synthetic
golden fixtures are part of the Apache-2.0 public export. They are deliberately
small interoperability seeds, not a claim of high coverage or certification of
every host version. Other AI models, agents, and maintainers may add focused
synthetic cases for new lifecycle shapes, platforms, interruption points, and
host releases without access to a private Vault, account, transcript, or
credential.

For the 0.21 candidate, the minimum publication gate is limited to version/JSON
consistency, Python compilation, focused host-protocol and reference-adapter
fixtures, and the allowlisted public-export/privacy contract. Record exactly
what ran and publish those fixtures/results. Do not describe that minimum as a
complete regression suite or high-coverage host acceptance. Broader suites may
be run when cheap or risk-relevant, but are not evidence unless observed.

Before release run all tests under `plugins/memory-vault-sync/tests`, then the
repository validator and public-source export suites documented by the current
CI configuration. Do not omit old security/provider/update tests merely because
task handoff was retired; those subsystems still protect the installed plugin.

## Performance method

Measure separately:

- cold index construction;
- no-change SessionStart;
- one-commit incremental receive;
- local query and context rendering;
- ordinary Stop publication;
- host `turn.input` local recall and host `turn.commit` durable-local ACK;
- bounded `session.open`/`sync.flush` receive-publication windows;
- 32-item queued batch;
- one concurrent replay;
- export/import throughput.

Record dataset size, object count, byte count, Python version, OS, hardware,
remote type and whether the value is local or internet-dependent. Avoid one
combined “sync time” number because it hides the cost being improved.

Regression ceilings in tests should be generous enough for supported CI but
must still catch accidental full scans or quadratic queries. Benchmark evidence
belongs under `benchmarks/` and must contain no user memory.

## Adding retrieval intelligence

A new tokenizer, embedder, reranker or graph traversal must be a derived local
adapter. It may not:

- change durable episode/event readability;
- require sending memory to an external model;
- make embeddings the only index;
- silently filter old conflicting evidence;
- infer file permissions;
- persist a task owner.

Ship a deterministic lexical fallback and evaluation cases for exact names,
Chinese/English paraphrases, negation, corrections, stale preferences,
conflicts, injection text and empty/sparse results.

## Documentation and release discipline

Code, installed skill, manifest, hook description, canonical docs, open-source
docs and changelog must describe the same active model. Historical task docs
must either be rewritten or carry an explicit migration-only banner.

Never claim a remote release, merged commit, installed acceptance, signature
channel or benchmark that has not been observed. Follow [`RELEASE.md`](RELEASE.md)
for version identity and rollback.
