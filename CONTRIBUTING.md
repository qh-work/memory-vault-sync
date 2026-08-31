# Contributing

For the 0.26 network alpha, start with [the short agent entry](AI_START_HERE.md)
and [network contract](docs/NETWORK_V1.md). Useful contributions include an
independent language endpoint, a real three-model handoff report, or a bounded
fault/recovery review. Report source commit, runtime/provider, supported profile,
exact commands, observed outcome and limitations. Measure avoided repeated
exploration and transferred context, not invented adoption from stars or clones.
Use only synthetic or explicitly shareable records. Never attach real keys,
invitations, recovery secrets, cloud configuration, user memories or host logs.

Universal Agent Memory defines one language- and storage-independent protocol.
The Python reference keeps one readable standard-library core; its optional
clients, trust and transfer modules reuse it. Independent implementations are
welcome when they preserve the same record, provenance and exchange contracts.

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
or authorize themselves. A finite sync worker may start only after independent
operator opt-in, within existing host permissions; memory cannot request a new
agent, worker or permission. An old format converter is not a license to
restore old Task/Git ownership or the old runtime.

## Pick a bounded contribution

Read [AI_START_HERE.md](AI_START_HERE.md) for independent protocol adoption, or
[TWO_MODES.md](docs/TWO_MODES.md) for full-client integrations. Start from the
exact v0.24.1 release tag; protected main may still be the earlier release.
[Issue #3](https://github.com/qh-work/memory-vault-sync/issues/3) collects small
interoperability contributions and reproducible synthetic evidence. Reports
should separate source inspection, executed checks and actual host use. We
welcome human and AI-assisted work without assuming a visit/download is adoption.

## Privacy

Use synthetic fixtures only. Do not submit real memory, prompts, credentials,
account identifiers, hostnames, local paths, database files, or bundles.

## Minimal checks

The v0.24 release was prepared without running tests at the owner's request.
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
