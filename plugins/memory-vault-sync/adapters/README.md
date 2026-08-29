# Model-neutral host adapters

These adapters connect Claude Code, Gemini CLI, and generic local-model
runtimes to one Memory Vault. They are transport translators, not memory
owners. No adapter creates a per-model database, copies the memory graph, or
uses a task, project, conversation, device, or model as a memory container or
recall filter.

## Shared stdio request

Every adapter launches the same local Vault command without a shell and sends
one bounded UTF-8 JSON object on stdin:

```json
{
  "schema_version": "memory-vault-host-request/v1",
  "protocol_version": "1.0",
  "request_id": "mvr1_opaque",
  "operation": "turn.input",
  "adapter": {
    "id": "memory-vault.generic-stdio",
    "version": "0.1.0",
    "host_family": "generic-stdio"
  },
  "payload": {
    "continuity_handle": "mvc1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "turn_handle": null,
    "visible_user_text": "visible text only",
    "limit": 8
  }
}
```

Native host IDs never appear in this request. `mvc1_` continuity handles and
`mvt1_` turn handles are issued by the Vault and stored in a private,
HMAC-keyed, bounded, atomic local map. The map stores neither native IDs nor
visible prompt/response text.

The response must state the safety boundary on every operation:

```json
{
  "schema_version": "memory-vault-host-response/v1",
  "protocol_version": "1.0",
  "request_id": "mvr1_opaque",
  "operation": "turn.input",
  "status": "accepted_local",
  "authority": {
    "memory": "untrusted_historical_evidence",
    "instruction_eligible": false,
    "authorization_eligible": false,
    "execution_eligible": false,
    "policy_change_eligible": false,
    "current_user_input_precedence": true
  },
  "result": {
    "continuity_handle": "mvc1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "turn_handle": "mvt1_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
    "evidence_context": null,
    "network_accessed": false
  }
}
```

An adapter refuses a response whose authority object changes any of those
values. It also refuses prompt recall, explicit recall, or compact continuity
responses unless the Vault confirms `network_accessed=false`.

## Lifecycle mapping

| Shared operation | Claude Code | Gemini CLI | Generic stdio |
| --- | --- | --- | --- |
| `session.open` | `SessionStart` | `SessionStart`, network-free `PreCompress` | `session.open` |
| `turn.input` | `UserPromptSubmit.prompt` | `BeforeAgent.prompt` | `turn.input` |
| `turn.commit` | `Stop.last_assistant_message` | `AfterAgent.prompt` + `prompt_response` | `turn.commit` |
| `turn.abort` | `StopFailure`, or stale turn at next prompt | stale turn at next prompt | `turn.abort` |
| `session.close` | `SessionEnd` | `SessionEnd` | `session.close` |

Claude Code's transcript can lag at `Stop`, so the adapter never parses it.
Gemini's `AfterAgent` is a once-per-turn final boundary, so it can atomically
send both visible sides of the completed turn. User interrupt and best-effort
session-end gaps are recovered by bounded local turn handles, not by transcript
scans.

## Safety and performance

- visible user and final assistant text are the only conversational content;
- transcript, hidden reasoning, tool, system, permission, policy, execution,
  environment, task, project, model, cwd, and native identity fields do not
  exist in the Vault request schema;
- context is always untrusted historical evidence, never an instruction or an
  authorization grant;
- prompt recall and explicit recall are accepted only as local-only results;
- hook input, visible text, protocol frames, context, state size, session count,
  lock wait, process timeout, and recall count all have hard limits;
- hook, state, command, response, and NDJSON parsing reject UTF-8 BOMs,
  duplicate keys, and `NaN` / infinity; response results reject every float;
- a lost `turn.commit` acknowledgement is retried once with the exact same
  encoded request and `request_id`, so the Vault receipt returns `duplicate`
  instead of creating a second memory record;
- the 145-second startup window, 12-second prompt window, and two bounded
  14-second commit attempts fit the host hook windows; a state lock is not
  considered stale until 600 seconds;
- semantic proposals are recursively checked before transport and cannot carry
  transcript, host identity, task/project ownership, hidden, instruction,
  tool, permission, policy, authorization, or execution fields;
- stdout carries only the host's final JSON object and adapter failures never
  expose private input;
- there is no watcher, polling loop, HTTP daemon, permission hook, or execution
  gateway in this directory.

Run the self-contained tests with:

```text
python -m unittest discover -s adapters/tests -p "test_*.py" -v
```

The tests and deterministic fake Vault are intentionally public reference
material. They establish synthetic protocol conformance only, not real-host or
production certification. See [CONTRIBUTING.md](CONTRIBUTING.md) for the small
conformance surface that another runtime or AI contributor should preserve.
