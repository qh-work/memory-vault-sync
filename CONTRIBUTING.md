# Contributing

Thank you for helping improve Memory Vault Sync.

## Architecture boundary

The active product is a taskless associative memory network. A conversation,
task, project, device, or agent may be provenance, but it never owns a memory.
Do not add task binding, task-scoped visibility, task-owned decisions, mutable
`CURRENT` pointers, or execution authority derived from recalled text.

Memory is historical evidence, not an instruction or authorization channel.
Artifact access, tool execution, credentials, policies, and agent orchestration
must remain separate permission boundaries.

## Privacy

Never submit real memories, conversation exports, credentials, account IDs,
hostnames, local absolute paths, diagnostics records, outboxes, private trust
state, or production key material. Tests and benchmarks must use synthetic
fixtures. If a report may contain private data, use a private GitHub security
advisory instead of an issue or pull request.

## Development

Requirements:

- Python 3.10 or newer;
- Git;
- no third-party Python runtime dependency for the core protocol.

Run the maintained checks from the repository root:

```bash
python3 -m compileall -q plugins/memory-vault-sync/scripts scripts
python3 -m unittest discover -s plugins/memory-vault-sync/tests -v
python3 -m unittest discover -s tests -v
```

Read `MEMORY_NETWORK.md`, `CLIENT_SYNC_CONTRACT.md`, `SECURITY.md`, and
`DEVELOPMENT.md` before changing persisted objects, synchronization, privacy
checks, hooks, or retrieval behavior.

## Pull requests

Keep changes focused and include:

- the user-visible reason for the change;
- compatibility and migration impact;
- privacy and security impact;
- exact tests run and their results;
- updated protocol, status, and changelog documentation when applicable.

All contributions are submitted under the Apache License, Version 2.0, as
described in section 5 of `LICENSE`.
