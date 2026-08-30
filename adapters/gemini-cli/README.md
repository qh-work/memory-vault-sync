# Gemini CLI visible-turn adapter

Create the explicitly capture-enabled client configuration described in
[HOSTS.md](../../docs/HOSTS.md). Replace both absolute path placeholders in
[settings.example.json](settings.example.json), then merge its hooks into the
operator-approved Gemini CLI settings. The example uses a shell command string;
keep paths quoted and use a trusted Python executable. Its timeouts are
milliseconds. Nothing here installs a hook or suppresses host logging.

The mapping follows the official [hook input/output reference](https://geminicli.com/docs/hooks/reference/)
and [configuration reference](https://geminicli.com/docs/hooks/). This source
adapter has not been exercised inside a live Gemini CLI installation.

Adapter behavior:

- Start recalls current evidence. `BeforeAgent.prompt` stages visible input and
  recalls evidence relevant to it.
- `AfterAgent.prompt_response` supplies the final text. Its `prompt` must match
  the currently staged input; the event timestamp must not precede that input.
- Stable native timestamps correlate ordered events locally. They are not
  author authentication. Preserve an event's original timestamp on exact retry.
- `PreCompress` only preserves staging; it does not commit a generated summary
  or inject context into the compaction operation. The next input recalls again.
- There is no mapped native cancellation event. A later input or best-effort
  session close cancels an uncommitted input. Missing final events never become
  save confirmations; recursive retry responses are skipped.

This route expects the normal ordered, single-active-turn event stream per
session. It cannot disambiguate arbitrarily reordered/concurrent turns sharing
identical prompt text without a host-provided turn identifier. For such a
runtime use [generic stdio](../generic-stdio/README.md) with stable `turn_id`
values, not a text-matching fallback. Only one installed hook set should feed
one client configuration. Interrupted final saves can be retried using the
content-free queue listing in [HOSTS.md](../../docs/HOSTS.md#durability-and-recovery).
