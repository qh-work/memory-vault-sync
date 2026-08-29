# Claude Code reference adapter

This command hook maps Claude Code lifecycle events to the shared local Memory
Vault protocol. It does not create a Claude-specific store. Claude's native
`session_id` is used only to select an HMAC-keyed entry in a private local state
file; the raw identifier, transcript path, working directory, model name,
permission mode, tool data, and system content are never sent to the Vault.

## Documented hook surface

Checked against the official [Claude Code hooks
reference](https://code.claude.com/docs/en/hooks) on 2026-08-30:

This mapping has synthetic fixture coverage only. It is not a real Claude Code
host test or production certification.

- `SessionStart` supplies `session_id`, `hook_event_name`, and `source`; current
  sources are `startup`, `resume`, `clear`, `compact`, and `fork`. The adapter
  maps `fork` to the protocol's non-owning `resume` provenance.
- `UserPromptSubmit` supplies the visible `prompt`. Its returned
  `hookSpecificOutput.additionalContext` is the only injected Vault evidence.
- `Stop` supplies `last_assistant_message`, which the official documentation
  recommends over transcript parsing because the transcript can lag. `Stop`
  does not run after a user interrupt; the next prompt safely aborts a stale
  local turn handle.
- API failures use `StopFailure`; this adapter only aborts the staged turn.
- `SessionEnd` is best effort and receives a reason. It is cleanup, not a
  durability boundary.

The adapter never reads `transcript_path`. It never registers a
`PermissionRequest`, `PreToolUse`, or other execution hook and never emits
`decision`, `continue`, permission, policy, or execution fields.

## Configure

Merge `settings.example.json` into a Claude Code plugin's `hooks` object. The
example uses the official exec-form `command` plus `args` and
`CLAUDE_PLUGIN_ROOT`, so the path is passed as one argument without shell
tokenization and the adapter can remain inside this plugin.
The default Vault command is:

```text
python <plugin>/scripts/vault_sync.py host-adapter --request-stdin
```

For a packaged runtime, set `MEMORY_VAULT_HOST_COMMAND_JSON` to a JSON array of
command arguments. No shell is used. Optionally set
`MEMORY_VAULT_ADAPTER_STATE_DIR` to a private local state root.

`SessionStart` with `source=compact` is explicitly sent as `reason=compact`.
The adapter accepts that response only when the Vault confirms
`network_accessed=false`.
