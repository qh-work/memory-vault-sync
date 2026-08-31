# Claude Code visible-turn adapter

Create an operator-owned client configuration with capture explicitly enabled
as described in [HOSTS.md](../../docs/HOSTS.md). Replace the two absolute path
placeholders in [settings.example.json](settings.example.json), select an
installed Python 3 executable, then merge the `hooks` entries into the approved
Claude Code settings. Keep existing unrelated entries. No configuration is
installed automatically.

The example requires support for the documented executable-plus-arguments hook
form; its timeouts are seconds. Automatic turn capture also needs `prompt_id`,
documented for Claude Code 2.1.196+. That is a lower bound for the identifier,
not a claim that every version since then supports this entire configuration.
If the installed host does not supply the identifier, this adapter
reports `host_turn_identity_required`; use explicit MCP/lifecycle calls instead
of transcript discovery. This is a source integration, not a claim of tested
compatibility with every Claude Code release. See the
[official hook reference](https://code.claude.com/docs/en/hooks).

For a host that supplies `prompt_id` but does not support `args`, use its shell
form instead: remove `args` and put the quoted script/config paths and the same
arguments in `command`. For example, the input handler becomes:

```json
{"type":"command","command":"python3 \"/absolute/path/to/memory-vault-sync/memory_vault_hosts.py\" --config \"/absolute/path/to/private/client.json\" --host claude-code --event UserPromptSubmit","timeout":20}
```

Apply that shape to the other event handlers, changing only the event name;
do not install a host configuration that silently ignores `args`.

Adapter behavior:

- Start and visible input receive bounded, untrusted local context.
- Input is staged; `Stop.last_assistant_message` completes the pair.
- `StopFailure` cancels staged input. Its error message is never saved as an
  assistant answer. Ordinary interruption without a failure event is cleaned
  up by the next input or session close, not guessed to be a completed answer.
- Compaction preserves local staging. `SessionStart` with source `compact`
  recalls context without reopening, committing, or triggering synchronization.
- Subagent events and recursive stop events are not captured by this adapter.
- Terminal hook replies contain only an advisory `systemMessage`, never an
  instruction to continue. See [durability and recovery](../../docs/HOSTS.md#durability-and-recovery).

Normal host trust/approval and logging remain in force. Configure only one copy
of these hooks for a given client configuration.
