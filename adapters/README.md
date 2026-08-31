# Authorized host adapters

These are source-distribution integration examples for the **same canonical
Vault** used by the plugin, MCP, lifecycle v1 and the standalone protocol. They
do not restore the old runtime, Git synchronization, or task-owned memory.

Choose one:

- [Claude Code](claude-code/README.md): visible input/final hooks, requiring the
  documented `prompt_id` field for automatic turn pairing.
- [Gemini CLI](gemini-cli/README.md): ordered visible agent events; missing or
  ambiguous input/final pairs are not confirmed saved.
- [Generic stdio host](generic-stdio/README.md): explicit stable identifiers and
  the new `memory-vault-host-events/v1` event contract.

Read [HOSTS.md](../docs/HOSTS.md) for lifecycle boundaries, recovery, limits, and
the distinction between a local save and remote delivery. None of these files
installs itself or changes a host's trust settings. Merge only the selected
example into an operator-approved host configuration; do not overwrite existing
settings. No host execution or integration tests were run for this change.
