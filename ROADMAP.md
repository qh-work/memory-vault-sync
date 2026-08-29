# Roadmap

The roadmap preserves one non-negotiable architecture: memory is an independent
evidence network. Tasks, projects, conversations, devices, models, adapters,
and agents may reference memory but never own it or determine its lifecycle or
visibility.

## 0.21 — one Vault across AI runtimes

Implementation complete in source candidate
`0.21.0+codex.20260830000842`; merge, public CI, installation, and `v0.21.0`
release evidence are still pending.

- model-neutral local stdio request/response protocol with bounded NDJSON;
- Vault-issued opaque continuity and turn handles, never native host IDs;
- zero-network prompt input, explicit recall, compact, abort, close, and status;
- durable local final-turn acknowledgement before optional publication;
- exact canonical-byte retry reuse and hard conflict for changed bytes;
- fixed negative instruction/authorization/policy/execution authority labels;
- Claude Code, Gemini CLI, and generic local-runtime reference adapters;
- unchanged taskless `memory-episode/v1` and `memory-event/v2`, with existing
  Codex hook compatibility.

## 0.22 — optional MCP cognitive interface and adapter hardening

Planned, not implemented:

- a minimal local stdio MCP surface limited to bounded recall,
  evidence-anchored remember, and content-free status;
- no task/project/model owner, permission, policy, execution, agent-spawn,
  resource-expansion, credential, filesystem, or tool-control interface;
- shared conformance vectors for hook adapters and MCP clients;
- clean cross-platform packaging, interruption/retry, hostile-memory, and
  latency acceptance for Claude Code, Gemini CLI, and local runtimes.

## 0.23 — portable trust and audited selective encryption

- integrate an audited OS key-store adapter and signed first-device checkpoint
  ceremony;
- ship an audited encryption-provider adapter for evidence/relation-closed
  selective bundles;
- verify enrollment, recipient, epoch, rotation, revocation, replay, atomic
  import, and recovery without making identity a memory owner.

## 0.24 — encrypted replication and recovery

- publish ciphertext-only replication catalogs signed by active devices;
- support multiple authorized devices, revocation, epoch rotation, and disaster
  recovery without placing private keys in Git, CI, plugin data, or memory;
- prove restore and revoked-device rejection across macOS, Windows, and Linux.

## 0.25 — scalable cognitive views

- generate taskless continuity/handoff views from immutable evidence;
- add deterministic hierarchical summaries as disposable caches;
- improve multilingual semantic retrieval while preserving local-only recall,
  provenance, conflict visibility, and lexical fallback;
- stream very large histories directly from verified Git objects with bounded
  memory use.

External task managers, agent runtimes, policy engines, authorization services,
and execution gateways remain separate systems. Memory may provide evidence to
them, but it never grants permission or starts execution.
