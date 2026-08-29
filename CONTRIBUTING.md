# Contributing

Universal Agent Memory is intentionally small: one protocol, one readable
standard-library implementation, and one synthetic conformance suite.

## Preserve the product boundary

Contributions must not add:

- Task-, Project-, conversation-, model-, or agent-owned memory;
- plugins, vendor hooks, installer requirements, Git synchronization, accounts,
  OAuth, credential helpers, or automatic network access to the core;
- command execution, tool invocation, agent spawning, policy mutation,
  permission mutation, or authority derived from memory;
- silent mutation or deletion of canonical Memory Records;
- model/task/session visibility partitions in recall.

Goals and continuity are Memory Records connected by relations. They are not
Task containers.

## Privacy

Use synthetic fixtures only. Do not submit real memory, prompts, credentials,
account identifiers, hostnames, local paths, database files, or bundles.

## Minimal checks

Python 3.10+ is the only requirement:

```bash
python3 -m py_compile memory_vault.py
python3 -m unittest -v tests.test_memory_vault
```

Changes to persisted records, NDJSON operations, hashes, bundles, or authority
labels must update `PROTOCOL.md` and `CHANGELOG.md`.

All contributions are submitted under Apache-2.0 as described in `LICENSE`.
