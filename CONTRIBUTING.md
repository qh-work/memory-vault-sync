# Contributing

Universal Agent Memory keeps one readable standard-library core. Optional
clients, trust and transfer modules build on that core, never duplicate it.

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

Optional client hooks/MCP, externally provisioned signing, explicit transfer
adapters and offline export converters belong in separate modules. They must
leave the lightweight file independently usable and must not install, enable,
authorize or spawn themselves. An old format converter is not a license to
restore old Task/Git ownership or the old runtime.

## Privacy

Use synthetic fixtures only. Do not submit real memory, prompts, credentials,
account identifiers, hostnames, local paths, database files, or bundles.

## Minimal checks

The v0.24 preview was developed without running tests at the owner's request.
Do not describe that as a pass. The existing synthetic conformance specification
has been updated for quarantine; new integrations still need independent review.
See [the review handoff](docs/REVIEW_HANDOFF.md) for a bounded contribution task.
Run the following only when your own host/user authorizes it, with synthetic
temporary data rather than an installed private Vault:

Python 3.10+ is the only requirement:

```bash
python3 -m py_compile memory_vault.py
python3 -m unittest -v tests.test_memory_vault
```

Changes to persisted records, NDJSON operations, hashes, bundles, or authority
labels must update `PROTOCOL.md` and `CHANGELOG.md`.

All contributions are submitted under Apache-2.0 as described in `LICENSE`.
