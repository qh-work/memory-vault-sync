# One Vault, full authorized client

The lightweight file and the optional client use the same canonical records,
SQLite database, provenance rules and transfer format. There is no separate
"plugin memory" and no Task or Project parent container.

The v0.25 integration code is **not a validated promise of automatic saving in
every desktop client**. Publication does not establish host compatibility.
See [source-pinned validation evidence](VALIDATION.md) for the exact synthetic
workflows exercised; those results do not establish live-host installation,
cross-model acceptance or the complete client suite. No existing plugin,
personal marketplace, private memory or host trust setting was changed by
adding these source files.

## Choose the entry point

| Entry point | What invokes it | What it can do |
| --- | --- | --- |
| `memory_vault.py` | An explicitly launched local process | Standard-library core protocol, same local Vault |
| `memory_vault_client.py protocol` | An explicitly launched configured client | The same core wire protocol, with the client's exact path and current trust checks |
| `memory_vault_client.py mcp` | A host that supports local stdio MCP | Discoverable read/write memory tools |
| `memory_vault_client.py lifecycle` | An explicitly launched runtime adapter | Stage, commit or abort visible turns using the new optional lifecycle v1 profile |
| `memory_vault_client.py compat` | An explicitly configured old host integration | The ten production v0.21 host operations, translated into the same taskless Vault |
| `memory_vault_client.py host` | Approved Claude Code/Gemini CLI/generic events | Correlate documented visible events with the same lifecycle and Vault |
| `memory_vault_client.py sync` | Explicit operator run or separately opted-in finite worker | Signed incremental directory/rclone transfer; pending work and content-free receipts |
| `memory_vault_client.py manage` | Explicit operator command | Read-only diagnosis, bounded replay, snapshot and restore-to-new-path |
| `memory_vault_client.py pack` / `legacy-pack` | Explicit operator command | Compressed file packs / real old pack, ZIP and checkpoint compatibility |
| `memory_vault_client.py share` | Explicit operator command | Review and exchange a selected complete subgraph, with optional original proofs |
| `memory_vault_client.py device-trust` / `envelope` | Explicit operator command | Initialize/inspect a named private device metadata file; inspect new or explicitly selected old ciphertext framing without keys or decryption |
| `memory_vault_client.py update` / `install` | Explicit operator command | Independent publisher verification, staging / isolated activation, rollback and separately opted-in updates |
| Optional Codex hooks | Reviewed/trusted host lifecycle events, plus capture opt-in | Stage the visible prompt, recall locally, save the visible final pair |
| Work MCP entry point | Work installations that support the packaged local MCP server | Explicit tool calls; automatic Work lifecycle capture is **not established** |

Reading instructions does not create storage access or install tools. Hosts
retain their authorization rules. A model's persistence needs do not grant it
new filesystem access, network access, execution rights, or hook trust.

The runtime in the full plugin includes these adapters and operations. They are
optional for the independent protocol and standard-library core. See
[the two modes](TWO_MODES.md), [host setup](HOSTS.md) and
[old/new capability map](PARITY.md).

## 1. Explicitly configure a shared Vault

Use Python 3.10 or newer. Choose absolute private paths; do not use the plugin
cache as the Vault or key directory. The following commands are setup examples,
not commands run by this release work:

```bash
python3 /absolute/path/memory-vault-sync/memory_vault_client.py configure
```

Omitting `--vault` selects exactly the lightweight core's `default_vault_path()`:
`MEMORY_VAULT_PATH` when set, otherwise the core's user-data directory. It is not
a separate plugin database. To select explicit private paths instead:

```bash
python3 /absolute/path/memory-vault-sync/memory_vault_client.py \
  --config /absolute/private/control/client.json configure \
  --vault /absolute/private/memory/vault.sqlite3
```

Either form creates one new client configuration with automatic capture **off**. It
does not create a Vault, install a plugin, enroll a key or enable hooks. Existing
configuration files are never replaced. To change a configuration, review and
edit that operator-controlled file explicitly, preserving its private file
permissions, or create a distinct new configuration and point the host at it.

For a custom path, set the light core's `--vault` to the same path, or use the
configured `protocol` entry below so there is no second path to keep aligned. The
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

Default configuration is resolved only for operations that actually need it.
Core/protocol capability discovery and MCP initialization/listing/capabilities
do not open a Vault or read a client configuration. MCP and a configured protocol
stream pin their default configuration path at the first memory operation,
then reload that same configuration and current trust for each subsequent
operation; an invalid configured path is never replaced with another Vault.
Independent restore/recovery review, pack verification/conversion, update/install
and [metadata inspection](ENCRYPTION.md) remain available without an old client
configuration. Commands that do need one, such as sharing import/export or old
alias registration, retain the normal explicit-or-default configuration rules.

### Add automatic sharing without waiting for the network

Configure keys and independent trust using [TRUST.md](TRUST.md), then create an
explicit signed sync configuration using [SYNC.md](SYNC.md). Bind that existing
configuration when creating the client:

```bash
python3 /absolute/path/memory-vault-sync/memory_vault_client.py \
  --config /absolute/private/control/client.json configure \
  --sync-config /absolute/private/control/sync.json --capture-visible-turns
```

This inherits the sync configuration's exact Vault, signing identity and trust
registry. Supplying conflicting paths is refused. Existing client configuration
is not replaced; change the operator-controlled file or create a new one.
Capture and automatic sync are independent opt-ins: MCP/direct writes do not
require automatic visible-turn capture. A newly saved hook/lifecycle turn,
MCP write, configured protocol write or import notifies the sync queue; bare
`memory_vault.py` stays independent and never spawns a worker. An explicit sync
run also discovers unsent Vault changes if a notification was interrupted.

Notification performs no remote I/O and never waits for worker completion.
Only the independently enabled automatic/background configuration can launch a
finite transfer worker. The saved-local reply is not a delivery acknowledgement.
An event-triggered worker is not an always-on service; while no host is active,
use an explicit `sync run` when a transfer is wanted. Inspect `sync status` or
`manage doctor` for content-free health and pending/error information.

### Direct protocol access to the configured client's records

These commands do not copy the database. A plugin write is immediately a record
in the same local Vault available to this entry point:

```bash
python3 /absolute/path/memory-vault-sync/memory_vault_client.py \
  --config /absolute/private/control/client.json protocol --serve
```

Send the standard `universal-agent-memory-request/v1` JSON requests documented
in [PROTOCOL.md](../PROTOCOL.md), one line per request. Omit `--serve` for one JSON
request on stdin and one response. Core `observe` remains one episode write;
MCP `memory_observe` and lifecycle `turn.commit` are the explicitly named
episode-plus-continuity conveniences. The passthrough does not rename core
request IDs or invent a second record format.

The configured protocol entry retains the client's signing configuration for
new writes and its current trust-store checks for reads. Bare `memory_vault.py`
with the same path sees the same records but does **not** load the client's trust
registry or signing identity: admission-time verification alone is not a live
revocation check. Choose the configured entry when those checks are required.
Neither entry grants new host permissions. Explicit core/MCP writes do not
require the automatic-capture toggle; their host must separately authorize them.

Portable snapshots use the same client's exact Vault selection:

```bash
python3 /absolute/path/memory-vault-sync/memory_vault_client.py \
  --config /absolute/private/control/client.json protocol \
  --export /absolute/private/exchange/review.ndjson
python3 /absolute/path/memory-vault-sync/memory_vault_client.py \
  --config /absolute/private/control/other-client.json protocol \
  --import /absolute/private/exchange/review.ndjson
```

The export target must be new. This explicit snapshot contains all canonical
records, including quarantined records; it is not a filtered context view or a
proof of trust. Bundles preserve record hashes and relations, **not signed
admission metadata**. Import does not re-sign another author's records. Imports
are quarantined by default; add `--accept-unsigned` only after deliberately
reviewing and accepting that unsigned content. Use [signed transfer](TRANSFER.md)
when author verification and sender/receiver acknowledgments are needed. None
of these commands delivers a file over the network.

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
- `memory_views`, `memory_graph`: bounded claim timelines, graph traversal,
  conflict/supersession state and non-executing consolidation proposals. MCP
  uses at most **64 nodes per response** by default and as its maximum;
  `memory_graph` also defaults to and caps its page at **512 edges**.
- `memory_reindex`: explicit paginated disposable-index repair, with stable
  request receipts; no new memory, key load or automatic sync notification.
- `memory_changes`: bounded incremental records and attestations; no transport
  or remote-delivery acknowledgment is implied. The MCP page budget is at most
  1 MiB (256 KiB by default), leaving room for both structured and escaped text
  representations inside the 4 MiB response frame.
- `memory_remember`: append a fact, decision, goal or other independent record.
- `memory_observe`: save an explicitly supplied visible user/final-assistant pair,
  then append a continuity excerpt linked to that episode.

### Page and frame boundaries

`memory_views` accepts at most one of `entity`, `memory_id` or `query`. The
`after_memory_id` cursor requires the same exact `entity`; a nonzero
`after_sequence` is only for unselected whole-Vault enumeration. Keep `through`
fixed when following pages. Both the advertised MCP schema and the argument
validator enforce these rules. The 64-node limit covers all returned views
together, not 64 nodes for each view.

Use each view's `next_request` for more of that entity's timeline, and the
top-level `next_request` for later enumeration seeds. These are core requests:
for an MCP call, remove `op` and pass the remaining fields to `memory_views`.
Page-local state and omitted earlier pages are explicitly labeled; no bounded
page is presented as the complete history. A graph's `frontier_memory_ids` are
exploration seeds, **not an exhaustive edge-pagination cursor**. Re-rooting at
a frontier ID may revisit nodes/edges, so deduplicate by IDs and retain the
truncation flags. A very high-degree neighborhood can remain incomplete.

The configured direct `protocol` entry retains the full core bounds of
512 nodes and 4,096 graph edges when a larger local view is appropriate. Neither
interface silently rebuilds missing retrieval indexes: use the explicitly
authorized, paginated `memory_reindex` / `memory.reindex` operation when asked
to repair them. Index maintenance does not load a signing key, create a memory,
notify sync or confer trust.

Every MCP response, including embedded `MCPServer.handle` calls, is limited to
4 MiB of encoded UTF-8 **including the final newline**. Ordinarily a tool result
contains both its complete `structuredContent` and the same JSON as text. If
duplicating the text would exceed the limit but the complete structured result
fits, the adapter keeps that entire `structuredContent` and replaces only the
duplicate text rendering with an explicit notice. Canonical text, IDs, hashes,
relations, proofs, errors and continuation fields are never shortened to fit.
Text-only hosts must use the configured direct protocol for these large results;
the notice is not a substitute for the memory record. If the complete structured
result still cannot fit, an explicit JSON-RPC error retains the original valid
request ID and requests a smaller page or direct protocol. It does not report
a successful partial record.

The [shared response schema](../schemas/result.schema.json) describes the core
envelope inside `structuredContent`, including optional top-level `client`
capability/health metadata. A failed `memory_observe` may also have
`partial_result`: it identifies an already-saved episode while continuity
remains unsaved, with `retry_same_request: true`. It is still an error, not a
full-save acknowledgement. The enclosing JSON-RPC/MCP fields are a separate
transport envelope. `memory_capabilities` reports the MCP-specific bounds
without selecting a default Vault, opening a configuration or loading keys.

The advertised [MCP tool annotations](https://modelcontextprotocol.io/specification/2025-06-18/server/tools)
distinguish read-only tools from writes. They are hints for the host, not
permission grants. No tool exposes key generation, trust enrollment, host
configuration, arbitrary file import, shell execution or agent spawning.

Every write requires a stable `request_id`, such as `req_review_turn_0001`.
Reuse the same ID **and the same arguments** after interruption. `memory_observe`
has separate stable receipts for its episode and continuity writes; if only the
first completes, retry resumes the second without duplicating the first. A
changed payload with an already-used ID is a conflict, not an overwrite.
Unlike the automatic capture routes below, explicit MCP observation does not
infer a source chain from the latest Vault record. Core `observe` remains a
single episode operation.

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

Protected full-client storage uses POSIX ownership/modes or native Windows
local-fixed-NTFS ACL/handle checks. Unsupported filesystems and unprovable
permissions fail closed; Windows source implementation is not evidence of a
successful real-host run. The independent core remains standard-library-only.
See [platform limits](PLATFORMS.md), [the security boundary](../SECURITY.md) and
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
| `SessionStart` | Notify independently enabled sync, retry at most four local pending saves, read a bounded local handoff; never wait for network |
| `UserPromptSubmit` | Stage only `prompt` for the supplied `session_id` and `turn_id`, then recall relevant local evidence |
| `Stop` | Pair the staged prompt with `last_assistant_message`, save episode and continuity, report an advisory result |

The adapter deliberately ignores `transcript_path`, `cwd`, permission fields
and unknown fields. It never scans other chats, tool transcripts or hidden
reasoning. The opaque session/turn pair is hashed only for local staging and
retry correlation; raw IDs and device paths are not copied into canonical
memory provenance. This correlation is not memory ownership.

Staging files are published atomically without replacement with mode `0600`
under an operator-owned `0700` client-state directory on POSIX. macOS/Linux
control publication uses an exclusive rename, not a link/unlink pair that can
leave two names after an interrupted write. Unsupported exclusive-rename
platforms or filesystems fail closed; see [platform limits](PLATFORMS.md).
Two simultaneous
events cannot overwrite each other's visible text. Different prompts or final
responses for the same event identity are rejected as conflicts instead of
guessing a pairing. If the host omits the necessary IDs or final visible text,
capture reports that it did not confirm saving. Use explicit MCP capture for
unsupported hosts or ambiguous events.

The capture marker describes the local hook code path, not cryptographic proof
that the host originated the event: another process with the same OS account
and access to the selected identity can invoke that code. Client isolation and
filesystem permissions remain the host's responsibility.

For a newly accepted Stop, `hook-capture-v1.sqlite3` freezes the source order,
timestamp, previous continuity's ID/full hash and exact new record bytes in one
local transaction. A staged prompt or outbox alone does not advance that head.
The continuity records `derived_from` its episode and, when there is a previous
accepted turn in that source, `continues` that turn's continuity. A pending
predecessor is retained, not replaced by the newest record anywhere in the Vault.
The hashed local source scope is correlation only; it does not own memory or
appear in canonical records.

The new pair and its canonical receipt are saved in one Vault transaction;
local completion bookkeeping is separate. Stop processes at most four pending
plans, oldest first, and leaves a longer backlog for bounded retry. Exact retries
reuse frozen bytes, time and predecessor under the current capture/trust checks.
Old v1 outboxes keep their original two-write receipts and partial-save retry
behavior; they are not rewritten or assigned an invented predecessor.

After saving, the hook publishes a content-free `done` receipt, removes the
matching transient files, then marks the frozen plan saved. An interruption can
therefore leave no outbox but a matching `done` and a still-pending journal plan.
Retry and [full client-state recovery](BACKUP.md) retain this valid window and
verify the canonical effects before finishing it. Host logs and canonical memory
remain untouched. A storage or signing failure retains recoverable state for an
explicit bounded retry:

```bash
python3 /absolute/path/memory-vault-sync/memory_vault_client.py \
  --config /absolute/private/control/client.json retry --limit 16
```

This command retries local saving; successful writes may notify the independently
configured background sync worker. It never waits for remote delivery.
Disabling capture also disables replay of these automatic jobs. No always-on
daemon is installed, and there is no promise that a host will deliver an event
after being force-killed. A never-completed turn may leave its staged prompt;
there is no indiscriminate automatic cleanup of old private state.

Hook results are JSON advisories, including on errors. They never block an
action, return an allow decision, suppress logging, or request that the agent
continue working. Recalled context is bounded and labeled untrusted evidence.

### Portable runtime lifecycle, independently of Codex hooks

A runtime that already has authorized local process access can explicitly use:

```bash
python3 /absolute/path/memory-vault-sync/memory_vault_client.py \
  --config /absolute/private/control/client.json lifecycle --serve
```

This is the new `universal-memory-lifecycle/v1` profile: `capabilities`,
`session.open`, `turn.input`, `turn.commit`, `turn.abort`, `session.close`.
It retains the familiar operation meanings, **not the old v0.21 wire format**.
It calls the same core and stores neither Git state nor task-owned memory.
`--capture-visible-turns` is required for new lifecycle sessions/inputs/commits.

`turn.input` stages only the supplied visible prompt. New `turn.commit` accepts
freeze the reply, timestamp, exact pair and source-local `continues` predecessor
before saving. One call materializes at most four pending ancestor/target plans;
a still-pending target requires the same original request, not a new ID.
`turn.abort` cancels only before commit has begun; saved canonical effects cannot
honestly be reported as rolled back. Sessions and turns are local correlation
handles, not memory containers. Native host correlation stays stable across
lifecycle generations; old accepted v1 work retains its original retry path.
This explicit route labels supplied text caller-reported; it does not assert
that a host witnessed it. Complete schemas, cancellation and recovery details are in
[LIFECYCLE.md](LIFECYCLE.md).

Completed lifecycle receipts can be read back after capture is disabled,
without another memory write. Partial commits cannot resume while capture is
off. Explicit abort/close may still discard uncommitted staging. Receipt replay
confirms a historical local save, not current signature trust or remote receipt.

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

The package `.mcp.json` uses the `mcpServers` wrapper accepted by Codex's
plugin configuration loader and the plugin metadata validator. Its entry uses relative `cwd: "."` and
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
- The new lifecycle adapter uses a small private local staging/control database,
  not another canonical Vault. Keep this state for precise retry correlation;
  changing a configured Vault path does not silently retarget pending turns.
- Before production claims, another contributor should exercise an authorized
  Work/MCP save, a second model's read/write, signed transfer and revocation, and
  the original client's read-back. That acceptance work is still outstanding;
  the source implementation and this checklist are provided for review.

`tests/test_v025_mcp_bounds.py` supplies synthetic selector, response-size,
single-structured-content and schema cases for independent contributors. These
cases were written but **not executed** for this change; AST/JSON parsing alone
does not verify the runtime, a real MCP host or a production trust configuration.
