# Generic stdio host profile

[host.example.json](host.example.json) is an integration recipe for your runtime,
not a settings format natively recognized by Claude, Gemini, Codex, or Work.
Replace its path placeholders and have your already-authorized runtime launch
the listed executable with the selected event name appended. Send exactly one
JSON object on stdin and close stdin. Capture must be explicitly enabled in the
shared client configuration.

For example, an embedding application can invoke the equivalent of:

```text
python3 /absolute/path/to/memory-vault-sync/memory_vault_hosts.py --config /absolute/path/to/private/client.json --host generic --event turn.input
```

The body goes through stdin, not shell interpolation:

```json
{"session_id":"example-session","turn_id":"example-turn-1","user":"Keep memory independent of tasks."}
```

The new `memory-vault-host-events/v1` profile has these boundaries:

| Event argument | Required body fields | Optional fields |
| --- | --- | --- |
| `session.open` | `session_id` | `query` |
| `turn.input` | `session_id`, `turn_id`, `user` | — |
| `turn.commit` | `session_id`, `turn_id`, `assistant` | `continuity` |
| `turn.abort` | `session_id`, `turn_id` | — |
| `session.close` | `session_id` | — |
| `session.compact` | `session_id` | `query` |
| `recall` | `session_id` | `query` |

Every body may additionally contain `schema_version` set to the profile name.
Unknown body fields are rejected. Use a new `turn_id` for every new user input,
including repeated identical text. For a retry, reuse the exact identifiers and
body bytes as JSON data; never assign a new ID to retry a save. Do not share a
native session ID across concurrent active turn streams. Reopening a closed
session requires an explicit `session.open`.

Stage input before generating a response. Send `turn.commit` only after the
visible final response exists; send `turn.abort` on cancellation instead.
Compaction preserves staging and returns a dynamic context view; it cannot
promote a partial reply into a final answer. This adapter translates to the
[lifecycle v1 profile](../../docs/LIFECYCLE.md), not the old v0.21 wire format.

Inspect JSON `ok`, and `result.memory_saved` for a final confirmation. Exit 0 is
deliberately non-blocking and alone proves nothing. Lifecycle responses use
`universal-memory-lifecycle-result/v1`; adapter status/advisory responses use
`memory-vault-host-event-result/v1`. A save receipt proves historical local
commit, not current trust, truth of the text, or remote delivery. Responses may
include untrusted `context`; only the embedding runtime decides whether to add
it to model input. No response authorizes tools or modifies policy.

For diagnostics send `{}` with `--event status` or `--event capabilities`.
For queue recovery use the session hash returned by status with `--event recover`:

```json
{"session_key":"replace-with-the-64-lowercase-hex-digits-returned-by-status"}
```

See [HOSTS.md](../../docs/HOSTS.md) for bounded recovery and disabled-capture rules.
The example is source-only; it has not been run as an integration test.
