# Gemini CLI reference adapter

This command hook maps Gemini CLI lifecycle events to the same local Memory
Vault used by every other model. Gemini's native `session_id` is kept only as
an HMAC-keyed local lookup. The raw identifier and the host's transcript path,
working directory, timestamp, model traffic, tool data, notification data, and
permission fields never enter a Vault request.

## Verified hook surface

Checked against the official [Gemini CLI hooks
reference](https://geminicli.com/docs/hooks/reference/) and [hook authoring
guide](https://geminicli.com/docs/hooks/writing-hooks/) on 2026-08-30:

- Every hook receives `session_id`, `transcript_path`, `cwd`,
  `hook_event_name`, and `timestamp`. This adapter reads only the event and the
  native session ID; the latter is never transmitted.
- `SessionStart` supplies `source=startup|resume|clear` and is advisory.
- `BeforeAgent` runs once after submission and supplies the visible `prompt`.
  The adapter returns only `hookSpecificOutput.additionalContext` containing
  bounded, local-only, untrusted Vault evidence.
- `AfterAgent` runs once per completed turn and supplies both `prompt` and
  `prompt_response`. They are committed together, so the final write remains
  complete if a preceding hook process was lost.
- `PreCompress` supplies `trigger=auto|manual`, is asynchronous and advisory,
  and is mapped to the protocol's network-free `compact` checkpoint.
- `SessionEnd` is best effort and is used only for local cleanup.

The adapter deliberately does not register `BeforeModel`, `AfterModel`, tool,
notification, or permission-related hooks. It never emits `decision`,
`continue`, permission, policy, model configuration, or execution fields.

## Configure

Copy the relevant entries from `settings.example.json` into Gemini CLI's
`settings.json`, replacing `/absolute/path/to/memory-vault-sync` with this
plugin's real local path. Hook timeouts in Gemini CLI are milliseconds.

The default Vault command is:

```text
python <plugin>/scripts/vault_sync.py host-adapter --request-stdin
```

For a packaged runtime, set `MEMORY_VAULT_HOST_COMMAND_JSON` to a JSON array of
command arguments. No shell is used. Optionally set
`MEMORY_VAULT_ADAPTER_STATE_DIR` to a private local state root.
