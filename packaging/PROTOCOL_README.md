# Memory Vault v0.24.1 — protocol-only package

This archive is the agreement, not an installed program. No Python, database,
plugin, account or network service is required to read or implement it.

1. Read `docs/IMPLEMENTERS.md`, then the normative `PROTOCOL.md`.
2. Use `schemas/` and `examples/protocol/` as public, synthetic interchange
   material. JSON Schema alone does not verify hashes, relation closure,
   duplicate keys, admission or durable writes; those rules are in the protocol.
3. Implement the core profile with the file/storage tools your host already
   permits. Storage layout and programming language are your choice.
4. Exchange canonical records with another conforming implementation, including
   the optional Memory Vault plugin. Import unknown evidence into quarantine
   unless explicitly admitted under the unsigned profile.

The optional lifecycle profile is in `docs/LIFECYCLE.md`. It defines new request
and result envelopes; matching old operation names does not make the v0.21 Host
Adapter wire format compatible.

The optional Python reference and complete client package are separate downloads:
[v0.24.1 release](https://github.com/qh-work/memory-vault-sync/releases/tag/v0.24.1).

Examples and schemas were structurally inspected, not executed as a cross-host
conformance test. Do not interpret this package as execution authorization,
permission to persist hidden state, or a claim that another agent read a memory.
Memory remains independent of tasks, projects, models and clients.

Licensed Apache-2.0. See LICENSE and NOTICE.
