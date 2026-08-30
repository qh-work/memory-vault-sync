# One Vault, optional client integrations — 0.24.0-alpha.1 preview

The lightweight file and the optional client use the same canonical records,
SQLite database, provenance rules and transfer format. There is no separate
"plugin memory" and no Task or Project parent container.

This is a prerelease, not a stable production release. The integration code is
an implementation candidate, **not a validated promise
of automatic saving in every desktop client**. Automated tests, live host
installation and functional capture checks were not run for this change. No
existing plugin, personal marketplace, private memory or host trust setting was
changed by adding these source files.

## Choose the entry point

| Entry point | What invokes it | What it can do |
| --- | --- | --- |
| `memory_vault.py` | An explicitly launched local process | Standard-library core protocol, same local Vault |
| `memory_vault_client.py mcp` | A host that supports local stdio MCP | Discoverable read/write memory tools |
| Optional Codex hooks | Reviewed/trusted host lifecycle events, plus capture opt-in | Stage the visible prompt, recall locally, save the visible final pair |
| Work MCP entry point | Work installations that support the packaged local MCP server | Explicit tool calls; automatic Work lifecycle capture is **not established** |

Reading instructions does not create storage access or install tools. Hosts
retain their authorization rules. A model's persistence needs do not grant it
new filesystem access, network access, execution rights, or hook trust.

## 1. Explicitly configure a shared Vault

Use Python 3.10 or newer. Choose absolute private paths; do not use the plugin
cache as the Vault or key directory. The following commands are setup examples,
not commands run by this release work:

```bash
python3 /absolute/path/memory-vault-sync/memory_vault_client.py \
  --config /absolute/private/control/client.json configure \
  --vault /absolute/private/memory/vault.sqlite3
```

This creates one new client configuration with automatic capture **off**. It
does not create a Vault, install a plugin, enroll a key or enable hooks. Existing
configuration files are never replaced. To change a configuration, review and
edit that operator-controlled file explicitly, preserving its private file
permissions, or create a distinct new configuration and point the host at it.

Set the light core's `--vault` to the same path to share one database. The
configuration stores the chosen absolute Vault path; an unrelated shell's
`MEMORY_VAULT_PATH` does not silently redirect an already-configured client.
Do not put a WAL-mode SQLite database on a multi-host shared filesystem.

Without `--config`, the client reads `MEMORY_VAULT_CLIENT_CONFIG` if set;
otherwise it reads `client.json` under:

- macOS: `~/Library/Application Support/UniversalAgentMemory/`
- Linux: `$XDG_CONFIG_HOME/universal-agent-memory/`, or
  `~/.config/universal-agent-memory/` when that variable is absent
- Windows: `%LOCALAPPDATA%/UniversalAgentMemory/`

The client does not discover all old plugins or conversations and does not
silently migrate another Vault. Use the explicit migration workflow separately.

## 2. Connect a local MCP host

Launch the client through the host's ordinary MCP configuration. This common
JSON shape illustrates the executable and arguments; the enclosing settings
format depends on the host:

```json
{
  "mcpServers": {
    "memory-vault": {
      "command": "python3",
      "args": [
        "/absolute/path/memory-vault-sync/memory_vault_client.py",
        "--config", "/absolute/private/control/client.json", "mcp"
      ]
    }
  }
}
```

On Windows select the installed interpreter, for example command `py` with
`-3` prepended to `args`. A host running remotely cannot access the desktop's
local files merely because it knows this configuration. No HTTP endpoint,
remote shell, proxy or network listener is created here.

The adapter implements newline-delimited UTF-8 JSON-RPC over stdio using the
[MCP transport contract](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports).
It negotiates protocol `2025-06-18`, requires initialization, and then accepts
`tools/list`, `tools/call` and `ping`. If a client proposes another version, the
server returns the version it supports; that client must decide whether to
continue. The host closes stdin to shut down the process. See the
[MCP lifecycle contract](https://modelcontextprotocol.io/specification/2025-06-18/basic/lifecycle).

Available tools:

- `memory_capabilities`, `memory_status`: capabilities or content-free counts.
- `memory_recall`, `memory_handoff`, `memory_get`: read evidence and its
  verification labels; past goals do not authorize future action.
- `memory_changes`: bounded incremental records and attestations; no transport
  or remote-delivery acknowledgment is implied. The MCP page budget is at most
  1 MiB (256 KiB by default), leaving room for both structured and escaped text
  representations inside the 4 MiB response frame.
- `memory_remember`: append a fact, decision, goal or other independent record.
- `memory_observe`: save an explicitly supplied visible user/final-assistant pair,
  then append a continuity excerpt linked to that episode.

The advertised [MCP tool annotations](https://modelcontextprotocol.io/specification/2025-06-18/server/tools)
distinguish read-only tools from writes. They are hints for the host, not
permission grants. No tool exposes key generation, trust enrollment, host
configuration, arbitrary file import, shell execution or agent spawning.

Every write requires a stable `request_id`, such as `req_review_turn_0001`.
Reuse the same ID **and the same arguments** after interruption. `memory_observe`
has separate stable receipts for its episode and continuity writes; if only the
first completes, retry resumes the second without duplicating the first. A
changed payload with an already-used ID is a conflict, not an overwrite.

The `continuity` argument can carry a concise visible progress summary. If it
is omitted, the client makes a bounded excerpt of the supplied text; it does
not invent progress, next actions or a claim of task completion. MCP-supplied
conversation text is recorded as caller-reported, not host-witnessed. Never
pass hidden reasoning, credentials, unapproved private material or unrelated
transcripts as "visible" evidence.

## 3. Optional signed records

Unsigned local mode has no extra Python package requirement. It is suitable
only within the existing same-user local trust boundary. For signed writes,
use the optional integration requirements, explicitly provision a local
identity and independently enroll its public descriptor in a trust store. Then
create a new client configuration adding:

```text
--identity /absolute/private/keys/client-identity.json
--trust /absolute/private/control/trusted-keys.json
```

An identity requires a trust store; a reader may configure only `--trust` and
receive revocation-aware views without holding any private signing key. Without
an identity, explicitly permitted writes remain unsigned. All configured paths
must differ from the Vault, configuration and transient client-state paths.
The client never creates or enrolls a key on
demand. It loads the identity only for writes, checks that its key remains
trusted and signs through the shared trust module. A configured signing failure
stops that write; it never silently falls back to unsigned storage.

Reads with a configured trust store ask the core to evaluate current trust.
This is a read-time filter, not a hidden write that rewrites admission metadata.
Revoking a key can therefore exclude its previously admitted records from
normal context views. Without a configured store, admission-time verification
must not be mistaken for a current revocation check. A signature proves which
key signed bytes, not whether a human or model is who it claims to be, whether
the text is true, or whether execution is authorized.

Protected signing-key storage currently requires the trust module's supported
POSIX protections; the Windows signing path fails closed until explicit ACL
support is implemented. The unsigned local core and client tool protocol do not
depend on that signing path. See [the security boundary](../SECURITY.md) and
[the trust module's explicit administrative interface](TRUST.md).

## 4. Optional Codex visible-turn hooks

The [official hooks documentation](https://learn.chatgpt.com/docs/hooks)
describes Codex lifecycle events and separate review/trust of their exact
definitions. It does not establish the same automatic event delivery for every
Work installation. This package does not bypass that review.

To opt in, use `--capture-visible-turns` when explicitly creating the client
configuration. Installing the plugin alone is not opt-in. In addition, the
host must deliver the documented fields and the operator must trust the hooks.

| Event | Local behavior |
| --- | --- |
| `SessionStart` | Read a bounded dynamic handoff view; no network request |
| `UserPromptSubmit` | Stage only `prompt` for the supplied `session_id` and `turn_id`, then recall relevant local evidence |
| `Stop` | Pair the staged prompt with `last_assistant_message`, save episode and continuity, report an advisory result |

The adapter deliberately ignores `transcript_path`, `cwd`, permission fields
and unknown fields. It never scans other chats, tool transcripts or hidden
reasoning. The opaque session/turn pair is hashed only for local staging and
retry correlation; raw IDs and device paths are not copied into canonical
memory provenance. This correlation is not memory ownership.

Staging files are published atomically without replacement with mode `0600`
under an operator-owned `0700` client-state directory on POSIX. Two simultaneous
events cannot overwrite each other's visible text. Different prompts or final
responses for the same event identity are rejected as conflicts instead of
guessing a pairing. If the host omits the necessary IDs or final visible text,
capture reports that it did not confirm saving. Use explicit MCP capture for
unsupported hosts or ambiguous events.

The capture marker describes the local hook code path, not cryptographic proof
that the host originated the event: another process with the same OS account
and access to the selected identity can invoke that code. Client isolation and
filesystem permissions remain the host's responsibility.

Before attempting the two canonical writes, Stop saves a local pending job.
After both writes and a completion receipt are durable, it removes only the
corresponding transient prompt and job. It retains content-free completion
receipts. Host logs and canonical memory remain untouched. A storage or signing
failure retains the pending job for an explicit bounded retry:

```bash
python3 /absolute/path/memory-vault-sync/memory_vault_client.py \
  --config /absolute/private/control/client.json retry --limit 16
```

This command retries local saving only; it does not synchronize with another
machine. Disabling capture also disables replay of these automatic jobs. No
daemon is installed, and there is no promise that a host will deliver an event
after being force-killed. A never-completed turn may leave its staged prompt;
there is no indiscriminate automatic cleanup of old private state.

Hook results are JSON advisories, including on errors. They never block an
action, return an allow decision, suppress logging, or request that the agent
continue working. Recalled context is bounded and labeled untrusted evidence.

## 5. Build the optional package without installing it

From a reviewed repository checkout:

```bash
python3 scripts/build_client_plugin.py \
  --output /absolute/new-packages/memory-vault-client
```

The output directory must not exist and must end in `memory-vault-client`.
The builder copies authoritative modules into that new package and writes a
runtime inventory last. Interrupted builds are left for inspection and are not
silently replaced on retry. The launcher refuses a missing or inconsistent
inventory; these hashes detect packaging drift, **not publisher authenticity**.

The default package selects `python3` for its MCP command. A Windows host may
need an explicit `py -3` or interpreter path in its MCP configuration. The
Windows hook override assumes a PowerShell-based host command launcher; that
host combination has not been functionally verified in this change.

The package MCP entry uses relative `cwd: "."` and
`args: ["scripts/launcher.py", "mcp"]`. Codex resolves that working directory
against the installed plugin root, as specified by its
[plugin configuration normalizer](https://github.com/openai/codex/blob/main/codex-rs/codex-mcp/src/plugin_config.rs#L281-L288).
It does not rely on an undocumented `${PLUGIN_ROOT}` substitution in MCP
arguments. The hook commands still use the documented host environment variable.

The builder does not edit a personal or repository marketplace, install a
plugin, restart an application, authorize a hook, run tests or access private
memory. Installation through a supported host is a separate operator action.
Keep the old installed plugin and old data until a deliberate migration and
client acceptance check establish that the new path is working.

## Operational limits and honest acceptance criteria

- Each input frame is bounded; large conversations must be intentionally split
  into relevant visible turns rather than dumping an entire chat history.
- Only a complete local-save receipt means the episode and continuity were
  both stored. "Configured", "installed" and "tool listed" are not proof of
  capture or cross-model continuation.
- Existing core databases may need the core's explicit supported schema upgrade
  before read-only tools can use them. A read-only tool does not silently migrate
  an old database: it returns `database_upgrade_required`. Use the core's
  explicit `--upgrade` operation, or allow a separately authorized next write
  to perform the supported incremental upgrade.
- Transport and old-data migration are optional components outside this
  lifecycle adapter. Hook latency never includes remote synchronization.
- Before production claims, another contributor should exercise an authorized
  Work/MCP save, a second model's read/write, signed transfer and revocation, and
  the original client's read-back. That acceptance work is still outstanding;
  the source implementation and this checklist are provided for review.
