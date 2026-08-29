# Memory Vault model-neutral host adapter protocol 1.0

This document defines the local protocol used by Claude Code, Gemini CLI,
generic stdio agents, and future model runtimes to share one Memory Vault. The
host adapters translate lifecycle events; they do not create model-specific
copies of memory.

The normative schemas are:

- [`schemas/memory_host_request.schema.json`](schemas/memory_host_request.schema.json)
- [`schemas/memory_host_response.schema.json`](schemas/memory_host_response.schema.json)

`MUST`, `MUST NOT`, `SHOULD`, and `MAY` are normative requirements.

## 1. Scope and non-goals

This protocol carries four kinds of local cognitive operations:

1. receive and flush bounded incremental memory at safe lifecycle points;
2. stage visible user input and recall related local evidence;
3. durably queue a visible completed turn;
4. explicitly recall, remember, or inspect health.

It does not turn Memory Vault into an agent runtime or task orchestrator. The
following boundaries are unconditional:

```text
Memory != Task
Memory != Instruction
Instruction != Authorization
Authorization != Execution
```

A response contains cognitive evidence and durability state only. It cannot:

- create, elevate, or inherit permissions;
- change policy or bypass an execution gateway;
- start another agent, tool, process, or network request in the host;
- expand compute, storage, account, or repository access;
- turn recalled text into a system, developer, or tool message;
- make an adapter, host, model, session, task, project, or conversation the
  owner of memory.

The protocol has no task, project, owner, binding, routing, native
conversation, model-owner, system-message, developer-message, tool-message,
hidden-reasoning, permission, policy, command, execute, or Vault-selector
field. The single configured Vault and its credentials are selected outside
this protocol by the local installation.

Visible text may naturally discuss any topic. The field prohibition concerns
control metadata and message roles: only visible user text and the visible
final assistant text can be recorded. System/developer messages, tool input or
output, partial model streams, hidden reasoning, environment state, and host
logs are never memory input.

## 2. Memory remains taskless and model-neutral

The durable model remains the taskless append-only network defined by
[`MEMORY_NETWORK.md`](MEMORY_NETWORK.md):

```text
visible turn -> immutable memory-episode/v1
             -> immutable memory-event/v2 relations
```

Protocol 1.0 does **not** change `memory-episode/v1` or `memory-event/v2`.
Adapters call the same Vault runtime and the same local associative index.
There is no Claude memory, Gemini memory, or local-model memory to reconcile.

`adapter.id`, `adapter.version`, and `adapter.host_family` are local delivery
provenance only. An implementation MUST NOT use them in:

- `source_id`, `episode_id`, `memory_event_id`, or any durable hash domain;
- recall ranking, filtering, visibility, or a Vault partition;
- ownership, authorization, permission, retention, or lifecycle decisions;
- a remote episode, event, bundle, diagnostic, commit message, or export.

The adapter metadata may be retained in a bounded local receipt only for
compatibility diagnostics. Deleting or upgrading an adapter cannot delete,
hide, orphan, or reassign memory.

## 3. Transport and envelopes

### 3.1 Framing

The reference transport is local stdio NDJSON:

- encoding is UTF-8;
- one request JSON object occupies one line;
- one response JSON object occupies one line in the same order;
- a request line is at most 3,145,728 bytes;
- stdout contains protocol responses only;
- diagnostics on stderr contain no visible text, path, host identity, native
  identifier, credential, or exception string;
- all objects are closed and unknown fields are rejected;
- the protocol never accepts floating-point values and never returns recall
  scores as floats.

The request envelope is exactly:

```json
{
  "schema_version": "memory-vault-host-request/v1",
  "protocol_version": "1.0",
  "request_id": "mvr1_safe-opaque-id",
  "operation": "memory.status",
  "adapter": {
    "id": "example-adapter",
    "version": "1.0.0",
    "host_family": "generic_stdio"
  },
  "payload": {}
}
```

No native host session or turn identifier is legal in the envelope. A host
adapter that needs such a mapping keeps it in its own private local state and
sends only Vault-issued handles described below.

### 3.2 Response status

Every schema-valid response has one status:

| Status | Meaning |
|---|---|
| `accepted_local` | Required local work is durably accepted; no remote completion is claimed. |
| `published` | The exact immutable intent is verified as published. |
| `duplicate` | The same `request_id` and the same request bytes were already accepted; the prior semantic result is reused. |
| `degraded` | The safe local part completed, but an optional receive/flush or automatic context feature was unavailable. |
| `rejected` | No requested memory transition was accepted. |

Every response also repeats this exact fixed, closed authority object:

```json
{
  "memory": "untrusted_historical_evidence",
  "instruction_eligible": false,
  "authorization_eligible": false,
  "execution_eligible": false,
  "policy_change_eligible": false,
  "current_user_input_precedence": true
}
```

The object is an explicit negative capability statement, not a policy token.
The host still performs its ordinary permission and execution checks without
consulting memory as authority.

A rejected response has no `result`. Its `error` object contains exactly:

```json
{"code": "stable_machine_code", "retryable": false}
```

It contains no free-form message, exception, visible content, local path,
account, device, adapter-native identifier, or diagnostic reference. A parser
may return `null` for `request_id` or `operation` only when those fields could
not be safely recovered from a malformed envelope.

## 4. Opaque handles and local state

The adapter-facing session and turn identifiers are Vault-issued opaque local
handles:

```text
mvc1_<43 URL-safe characters>              continuity handle
mvt1_<43 URL-safe characters>              turn handle
```

The suffix carries a 256-bit opaque value as 43 URL-safe characters. The
reference runtime derives a retry-stable handle with a domain-separated
HMAC-SHA-256 over the safe request ID under the private local device secret.
An issuer may equivalently use a cryptographically secure random source with a
durable idempotency receipt. Handles MUST NOT contain, encrypt, hash without a
private key, or otherwise expose a native session, conversation, thread,
prompt, task, project, model, account, device, or workspace identifier.

Handles are private local transport state. They:

- address a bounded local session or staged turn receipt;
- never appear in a durable episode/event, remote Git object, export, commit
  message, or recall result;
- never become a memory owner or recall selector;
- grant no file, repository, model, tool, policy, or execution permission;
- are protected with local private-file permissions and may be removed by
  bounded local-state cleanup without affecting durable memory.

An adapter may keep a private mapping from a host-native lifecycle instance to
a Vault handle. That native key MUST stop at the adapter boundary. It must not
be copied into a request, log, error, durable ID, or request idempotency key.

Every `session.open` request contains `continuity_handle`, either a previously
Vault-issued handle or `null`. When it is `null`, the Vault issues a handle;
when it is present, the Vault validates and reuses it. This rule is the same
for `startup`, `resume`, `clear`, and `compact`. The lifecycle reason never
becomes memory ownership. `compact` performs no network I/O even when it needs
to issue a new local handle.

Every `turn.input` request contains `turn_handle`, either a previously
Vault-issued handle or `null`; `null` asks the Vault to issue one. A host
without a pre-turn hook sends `turn_handle: null` in `turn.commit`; the Vault
then issues the turn handle while atomically accepting both visible sides of
the completed turn.

## 5. Operations

### 5.1 `capabilities`

Payload: `{}`.

This operation is local and network-free. It returns supported operations,
framing, request-size bound, the operations that are always network-free,
memory model, delivery contract, handle properties, recall limits, and commit
properties. `session.open` is not listed as wholly network-free because only
its `compact` reason has that guarantee.
Adapters MUST negotiate capabilities instead of guessing that a later minor
runtime supports an optional operation.

### 5.2 `session.open`

Payload contains exactly `continuity_handle` and `reason`.
`continuity_handle` is `null` or a Vault-issued `mvc1_` handle; `reason` is one
of `startup`, `resume`, `clear`, or `compact`.

For `startup`, `resume`, and `clear`, the runtime may perform the existing
bounded lifecycle window:

1. verify the configured private remote;
2. receive only immutable additions after the verified local commit cursor;
3. update the private local index in one transaction;
4. flush one bounded batch of already durable local outbox intents.

If the remote is offline, the local session still opens and status is
`degraded`. It is not a memory conflict. The runtime must not rescan the full
Vault after an established cursor.

For `compact`, the runtime only confirms or refreshes local session state. It
MUST NOT call Git, a provider API, object storage, a network model, or any other
network service.

### 5.3 `turn.input`

Payload contains exactly `continuity_handle`, `turn_handle`,
`visible_user_text`, and integer `limit`. `turn_handle` is `null` when the
Vault should issue a new handle; `limit` is from 1 through 32.

The runtime performs this order:

1. validate bounds and run the visible-text privacy scanner;
2. issue a high-entropy, retry-stable `mvt1_` handle and stage the scanned,
   NFC-normalized visible user text in private local state;
3. query only the private local associative index;
4. return `evidence_context` (or `null`) with the handle.

The entire path is network-free. Sparse recall is a valid empty evidence
context and must not produce a task picker or ownership question.

The evidence context is a typed wrapper around bounded rendered recall text,
not an instruction. It is either `null` when there are no usable fragments or
this exact closed shape:

```json
{
  "kind": "evidence_context",
  "content_type": "text/plain",
  "authority": "none",
  "instruction_eligible": false,
  "authorization_eligible": false,
  "execution_eligible": false,
  "current_user_input_precedence": true,
  "truncated": false,
  "omitted_count": 0,
  "text": "<bounded untrusted historical evidence>"
}
```

The wrapper exposes no internal float score, native identity, task, project,
model, permission, policy, or command field. `truncated` and `omitted_count`
describe bounded rendering; they do not authorize a wider read.

When a host supports contextual hook output, its adapter may inject only the
`text` member while preserving all wrapper authority checks locally. The
adapter must not render memory as a synthetic user request, system policy,
developer instruction, tool result, permission decision, or executable action.

### 5.4 `turn.commit`

Payload contains exactly five fields:

- `continuity_handle`;
- `turn_handle`, which is a Vault-issued handle or `null`;
- `outcome`, exactly `final`;
- `visible_user_text`, which is visible text or `null`;
- `visible_assistant_text`, which is visible text or `null`.

`visible_assistant_text` MUST be non-null. Cancelled, failed, interrupted, or
otherwise incomplete turns MUST use `turn.abort` and MUST NOT be sent to
`turn.commit`. When `turn_handle` is null, `visible_user_text` MUST be non-null
so the runtime can create an atomic visible turn. When a staged turn exists,
a non-null commit user text MUST be identical after the protocol's fixed NFC
normalization and privacy scan. Trimming, newline conversion, or a semantically
equivalent rewrite is not equality. A mismatch is a hard conflict.

The visible final assistant text is mandatory. Partial streams, commentary
that was not part of the visible final result, tool output, hidden reasoning,
and a host transcript file are not substitutes.

After privacy validation, the runtime first makes the local outbox intent
durable, then makes the idempotency receipt durable before returning
`accepted_local`. A crash between those writes is recovered by exact replay;
the two files are not claimed as one filesystem transaction. The
acknowledgement MUST NOT wait for public network access, remote Git, a provider
API, or another model. Publication is a separate bounded lifecycle action
through `session.open` or `sync.flush`.

This ordering is intentional: a slow or unavailable network cannot extend the
host's final-response latency, and a crash after acknowledgement cannot lose
the accepted turn.

For a host without a pre-turn hook, send `turn_handle: null`, `outcome:
"final"`, and both visible texts once. The Vault creates the turn handle and
the durable episode intent in one local transaction. This atomic fallback
records the completed turn but cannot provide automatic pre-generation recall
for that turn.

### 5.5 `turn.abort`

Payload contains exactly `continuity_handle`, `turn_handle`, and `reason`.
Reason is `cancelled`, `host_error`, `user_interrupt`, or `unknown`. The
runtime marks the local staged turn terminal and ensures it cannot later be
committed under the same handle. It never creates an episode from incomplete
input. The path is network-free.

An abort after a completed commit is a safe local no-op that reports
`terminal_state: "committed"`; this lets an adapter recover after losing its
own post-commit state update. It does not delete or rewrite accepted memory.

### 5.6 `session.close`

Payload contains a Vault-issued `continuity_handle`. The operation performs only
bounded local cleanup. It does not publish incomplete turns and does not open a
network window. Session-end hooks are best effort: missing one cannot invalidate
already durable outbox intents or durable memory.

### 5.7 `memory.recall`

Payload contains exactly visible `query` text, integer `limit` from 1 through
32, and integer `maximum_context_bytes` from 512 through 65,536. It uses the
same local-only optional `evidence_context` wrapper as `turn.input`, but stages
no turn. At most three focused query variants should be used for one user
request. The operation is never a task or Vault selector.

### 5.8 `memory.remember`

Payload contains one closed `memory-network-semantic-proposal/v1` anchored to
an existing visible episode. The runtime verifies evidence, relations,
privacy, and append-only identity, then uses the existing bounded private
publication path. A new event returns `published`; an identical deterministic
event returns `duplicate`.

The proposal is an `assistant_inferred` interpretation even though that field
is enforced by the runtime rather than accepted from the adapter. It cannot
alter an episode, claim user confirmation, grant authority, change policy, or
refer to a task-scoped legacy event.

### 5.9 `memory.status`

Payload: `{}`. The operation is local and network-free. It reports only bounded
health metadata: plugin version, enabled state, taskless append-only memory
mode, counts for the local outbox states, local-index availability and counts,
and `network_accessed: false`. It returns no memory text, path, credential,
host identity, or native identifier.

### 5.10 `sync.flush`

Payload: `{}`. This is the explicit bounded network window. It attempts one
outbox batch using immutable-addition and exact-overlap rules. A disjoint
remote advance permits one fetch and one replay; there is no background loop
or unbounded retry. Offline work remains queued; an explicit flush may return
a sanitized retryable rejection, never a false publication or conflict.

## 6. Idempotency and conflicts

`request_id` is an adapter-issued safe opaque idempotency key matching
`[A-Za-z0-9][A-Za-z0-9._:@+-]{0,159}`. It is not a native host ID. A random,
locally generated value is recommended.

For `session.open`, `turn.input`, `turn.commit`, `turn.abort`, and
`session.close`, the runtime stores a private local receipt over the
JCS-canonical closed request document:

- same `request_id` + the same canonical request document: reuse the prior
  durable handles/effect and return `duplicate` without staging, remembering,
  or publishing twice; `turn.input` may recompute its current local-only
  evidence view;
- same `request_id` + a different canonical request document: reject as a
  non-retryable hard conflict;
- staged `visible_user_text` + byte-different commit user text: reject with
  `conflict`, `retryable=false`;
- exact immutable path overlap with equal bytes: reuse safely;
- exact immutable path overlap with different bytes: hard conflict, never
  overwrite and never silently choose one.

Reference adapters serialize a closed request deterministically and keep the
idempotency key stable for an actual retry. Whitespace or object member order
does not alter the canonical receipt domain; any changed field value does.

Terminal receipts are written before acknowledgement. Receipt cleanup is
bounded and may occur only after it cannot permit a duplicate durable write.

`capabilities`, `memory.recall`, and `memory.status` are safe reads and do not
need mutation receipts. `memory.remember` has deterministic event identity and
returns `duplicate` for an existing exact event. `sync.flush` intentionally
re-evaluates the current bounded outbox on each call; its `request_id` is for
response correlation, not a promise to suppress a later flush.

## 7. Host mappings

Host hook payloads remain inside the adapter. The adapter extracts only the
two allowed visible text fields and translates lifecycle state to Vault
handles.

### 7.1 Claude Code

| Claude Code hook | Protocol operation | Required behavior |
|---|---|---|
| `SessionStart` (`startup`, `resume`, `clear`) | `session.open` | Map the reason; keep Claude's session identifier only in adapter-local handle state. |
| `SessionStart` (`compact`) or `PreCompact` | `session.open` with `compact` | Reuse `mvc1_`; zero network. Do not parse a transcript. |
| `UserPromptSubmit` | `turn.input` | Send only the visible prompt; render returned evidence through documented additional context without authority fields. |
| `Stop` | `turn.commit` | Use locally staged user bytes plus `last_assistant_message`; do not read a lagging transcript for the final answer. |
| `StopFailure`, cancellation, or known interrupt | `turn.abort` | Abort only when no visible final response was committed. |
| `SessionEnd` | `session.close` | Best-effort local cleanup; never depend on it for durability. |

The adapter MUST NOT register `PermissionRequest` or emit hook decision,
allow, deny, command, or policy fields. Memory context never participates in
Claude Code permission handling.

### 7.2 Gemini CLI

| Gemini CLI hook | Protocol operation | Required behavior |
|---|---|---|
| `SessionStart` | `session.open` | Map startup/resume/clear locally; native session identity stays in the adapter. |
| `PreCompress` | `session.open` with `compact` | Reuse `mvc1_`; zero network. |
| `BeforeAgent` | `turn.input` | Send the visible prompt and return the fixed untrusted-evidence wrapper. |
| `AfterAgent` | `turn.commit` | Commit the exact staged prompt and visible `prompt_response`. |
| cancellation or an agent error with no final response | `turn.abort` | Do not construct a final answer from model/tool trace data. |
| `SessionEnd` | `session.close` | Best-effort local cleanup only. |

`BeforeModel` and `AfterModel` are not turn boundaries: an agent turn may make
multiple model calls. Using them would duplicate or partially record a turn.
Gemini hook stdout must contain only the host's documented final JSON object;
adapter diagnostics go to sanitized stderr.

### 7.3 Generic stdio and local models

A generic integration follows this sequence:

```text
capabilities
session.open
  turn.input -> local evidence -> model generation -> turn.commit
  turn.input -> cancellation                    -> turn.abort
session.close
```

If the runtime exposes only an after-generation callback, it uses the atomic
`turn.commit` fallback with both visible texts and `turn_handle: null`. If it
exposes neither lifecycle callback, it may still use explicit
`memory.recall`, `memory.remember`, `memory.status`, and `sync.flush`, but it
must not claim automatic turn backup.

A future MCP wrapper may expose only the cognitive `recall`, `remember`, and
`status` operations. No MCP server is implemented or claimed by protocol 1.0.
If added later, it must not expose policy mutation, permission, shell, tool
execution, agent spawning, resource expansion, or Vault-selection tools. MCP
transport identity is not memory ownership and cannot replace the lifecycle
receipt protocol.

## 8. Capability degradation

Adapters declare actual host capabilities and degrade explicitly:

| Available host surface | Safe capability | Required degradation |
|---|---|---|
| pre-turn + final-turn + session hooks | automatic local recall and complete visible-turn backup | none |
| final-turn hook with both visible texts | atomic completed-turn backup | no automatic recall for that turn |
| pre-turn hook but no reliable final callback | local recall only | abort/expire staged input; never invent a final reply |
| session hooks only | incremental receive/flush | no automatic recall or turn backup |
| no lifecycle hooks | explicit cognitive operations only | report automatic lifecycle unavailable |
| missing session-end callback | all already accepted memory remains safe | bounded local handle expiry replaces cleanup hook |
| offline remote | local recall, staging, commit and outbox remain available | `degraded`; never block final response waiting for network |

Degradation must reduce automation, not weaken privacy, idempotency, append-only
validation, or authority boundaries.

## 9. Conformance matrix

The complete target conformance matrix is:

| Case | Claude | Gemini | Generic | Expected invariant |
|---|:---:|:---:|:---:|---|
| capability negotiation | MUST | MUST | MUST | closed 1.0 response; no network |
| startup/resume receive | MUST | MUST | SHOULD | incremental paths only after cursor |
| null continuity handle gets a Vault handle | MUST | MUST | MUST when supported | native IDs absent from frame and durable data |
| compact/compress | MUST | MUST | MUST when supported | zero network; handle is issued or reused locally |
| pre-turn recall | MUST | MUST | SHOULD | local index only; optional fixed untrusted-evidence wrapper |
| sparse recall | MUST | MUST | MUST | empty context; no task selection |
| visible final commit | MUST | MUST | MUST | assistant text required; durable outbox before ACK |
| post-only atomic commit | N/A | N/A | MUST when needed | both visible texts, Vault issues `mvt1_` |
| exact canonical request retry | MUST | MUST | MUST | `duplicate`; no second durable object |
| changed canonical request under one ID | MUST | MUST | MUST | hard idempotency conflict |
| staged/commit user mismatch | MUST | MUST | MUST | hard `conflict` |
| cancellation without final | MUST | MUST | MUST | abort; no episode |
| offline commit | MUST | MUST | MUST | fast `accepted_local`; queued intent preserved |
| explicit flush conflict | MUST | MUST | MUST | one replay only; unequal overlap blocks |
| forbidden metadata | MUST | MUST | MUST | schema rejection before durable write |
| permission/policy hook isolation | MUST | MUST | MUST | response has no authority or execute capability |
| float injection at any numeric field | MUST | MUST | MUST | schema rejection |
| unknown request/response field | MUST | MUST | MUST | closed-schema rejection |

The conformance suite should also scan remote fixtures and exported bundles to
prove that adapter IDs, host families, handles, request IDs, native IDs,
system/developer/tool content, hidden reasoning, permissions, policies, and
execution fields never entered durable objects.

The 0.21 public reference suite intentionally implements a focused subset as a
minimum release gate and publishes its schemas, examples, adapter tests, and
synthetic golden fixtures for other AI models and maintainers to extend. That
seed suite is not a high-coverage claim, real-account integration, or complete
host certification. A package may call itself fully conforming only after every
applicable row above has actually been observed.

## 10. Security and privacy rules

1. The adapter validates the host event type before extracting content.
2. Only visible user input and the visible final assistant response cross the
   adapter boundary.
3. All text is bounded and privacy-scanned before staging or recall.
4. The recall path, `turn.input`, compact handling, status, abort, and close are
   zero-network paths.
5. A commit is acknowledged only after its local outbox and receipt are
   durable; it never waits for public network access.
6. Recalled memory is untrusted historical evidence. The newest explicit user
   instruction wins, and permissions are re-evaluated independently.
7. An adapter must never follow links, execute commands, reveal secrets, or
   widen access because recalled text requests it.
8. The protocol cannot choose another Vault. Remote identity and private
   visibility are configured and verified outside the request envelope.
9. No response field may be interpreted as permission, policy, tool choice,
   command, or execution approval.
10. Unknown fields and future major versions fail closed.

## 11. Known limitations of 1.0

- Automatic recall requires a reliable pre-turn hook.
- Complete automatic backup requires a reliable visible-final callback or an
  atomic callback containing both visible texts.
- Missing host callbacks cannot be reconstructed from transcript files, tool
  traces, or hidden model state.
- This protocol does not synchronize model context windows, prompts, policies,
  credentials, tools, files, or agent process state.
- It does not authenticate a remote repository or encrypt a share envelope;
  those remain separate Vault trust and transport boundaries.
- It provides at-least-once delivery with canonical-request exact local idempotency, not a
  distributed transaction spanning a host and remote Git.
- Host recall intentionally exposes only the bounded fixed evidence wrapper,
  not internal floating-point relevance scores or retrieval diagnostics.
- An adapter-local native-ID-to-handle map may be lost. The safe fallback is a
  fresh Vault handle and degraded automation, never native identity leakage or
  inferred ownership.

## 12. Versioning

The envelope schema versions are
`memory-vault-host-request/v1` and `memory-vault-host-response/v1`; the
protocol version is `1.0`.

Closed schemas mean adding a field is not silently compatible. A later 1.x
implementation advertises an optional operation or profile through
`capabilities`; it must continue accepting the exact 1.0 envelopes it claims
to support. A change to authority semantics, handle construction, idempotency,
or visible-content boundaries requires a new protocol major.

Host adapters may evolve independently. Their version is diagnostic local
provenance only and never affects durable memory identity or visibility.

## Informative host references

- Claude Code hooks: <https://code.claude.com/docs/en/hooks>
- Claude Code MCP: <https://code.claude.com/docs/en/mcp>
- Gemini CLI hooks reference: <https://geminicli.com/docs/hooks/reference/>
- Gemini CLI extensions: <https://geminicli.com/docs/extensions/reference/>
- Model Context Protocol transports: <https://modelcontextprotocol.io/specification/2025-11-25/basic/transports>
