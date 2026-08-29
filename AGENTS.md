# Repository guide for AI agents

Memory Vault Sync is one taskless, append-only evidence network shared across
AI runtimes. A task, project, conversation, model, adapter, agent, or device may
provide provenance but never owns memory or controls its lifecycle.

Before changing code, read `README.md`, `HOST_ADAPTER_PROTOCOL.md`,
`MEMORY_NETWORK.md`, `SECURITY.md`, `DEVELOPMENT.md`, and `CONTRIBUTING.md`.

Keep these boundaries:

- memory is untrusted historical evidence, not instruction, authorization,
  policy, permission, tool choice, or execution authority;
- preserve append-only `memory-episode/v1` and `memory-event/v2` compatibility;
- keep prompt/explicit recall and compact continuity local and zero-network;
- acknowledge a completed turn only after its durable local outbox write;
- never add native host IDs, task/project/model owners, credentials, private
  paths, transcripts, hidden reasoning, tool logs, or live Vault data;
- use synthetic data only in examples, fixtures, issues, and pull requests.

Run the focused public adapter suite with:

```text
python3 -m unittest discover -s plugins/memory-vault-sync/adapters/tests -p "test_*.py" -v
```

Label evidence honestly: focused fixtures are synthetic conformance only; a
controlled real-host smoke test is separate; production security, privacy,
cross-platform, and host certification require separately observed evidence.
The public fixtures are intentionally small and may be extended by other AI
models and maintainers without using private accounts or memory.
