# Generic stdio / local-model adapter

This adapter lets a local inference runtime, desktop agent, or future model use
the same Memory Vault without a model-specific database. It accepts a small
local lifecycle event, keeps the runtime's native session identifier in an
HMAC-keyed private local map, and sends only Vault-issued `mvc1_` / `mvt1_`
handles plus visible text over the model-neutral Vault protocol.

It is a command-line process, not an HTTP daemon. One-shot mode reads one JSON
object from stdin and writes one result. `--serve` uses UTF-8 NDJSON and keeps
the same framing for multiple events:

```text
python adapters/generic-stdio/adapter.py < event.json
python adapters/generic-stdio/adapter.py --serve
```

## Local event envelope

Every input has exactly three top-level fields:

```json
{
  "schema_version": "memory-vault-local-host-event/v1",
  "event": "turn.input",
  "payload": {}
}
```

Supported events and exact payloads:

| Event | Payload |
| --- | --- |
| `capabilities` | `{}` |
| `session.open` | `native_session_id`, `reason=startup|resume|clear|compact` |
| `turn.input` | `native_session_id`, `visible_user_text`, `limit=1..32` |
| `turn.commit` | `native_session_id`, `outcome=final`, nullable user text, required visible assistant text |
| `turn.abort` | `native_session_id`, `reason` |
| `session.close` | `native_session_id` |
| `memory.recall` | `query`, `limit=1..32` |
| `memory.remember` | `proposal` |
| `memory.status` / `sync.flush` | `{}` |

Unknown fields are refused. In particular there is no transcript, hidden
reasoning, system prompt, tool record, task, project, permission, policy, model
configuration, authorization, or execution field. Recalled context remains
explicitly untrusted evidence and current user input has precedence.
The same exclusion is applied recursively inside `memory.remember.proposal`
before any Vault process is launched; ambiguous floating-point proposal values
are refused as well.

Inputs, visible text, state, result context, process output, and session count
all have hard bounds. State writes use a private directory, a bounded lock,
`0600` temporary files, fsync, and atomic replace. Raw native session IDs and
visible text are not stored. JSON and NDJSON reject duplicate keys, BOMs, and
non-finite numbers.

The default Vault command is:

```text
python <plugin>/scripts/vault_sync.py host-adapter --request-stdin
```

To point at another packaged stdio runtime, set
`MEMORY_VAULT_HOST_COMMAND_JSON` to a JSON array of arguments. No shell command
string and no HTTP service are used.
