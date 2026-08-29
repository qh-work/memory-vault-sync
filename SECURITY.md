# Security and privacy

## Reporting vulnerabilities

Use the public repository's **Security** tab to open a private GitHub security
advisory. Do not disclose a vulnerability in a public issue before a fix is
available, and never attach real memory text, credentials, account identifiers,
hostnames, local paths, diagnostics records, device trust state, or keys.

For a safe report, provide the plugin version, operating system, Python
version, a minimal synthetic reproduction, and content-free diagnostic reason
codes. Maintainers will acknowledge the report through the private advisory,
triage affected versions, coordinate a fix and disclosure, and publish a higher
version for recovery. The project does not rewrite released Git history as a
security rollback.

## Durable-data allowlist

The memory network may persist only bounded, privacy-scanned visible user text,
visible final assistant text, anonymous provenance, deterministic hashes,
timestamps, continuity/semantic relations, explicit confidence, and minimal
content-free diagnostics.

It must not persist:

- passwords, access/session/API tokens, cookies, private keys or recovery codes;
- a normal hash of a secret (short secrets remain guessable);
- browser sessions, keychains, authentication databases or password-manager
  exports;
- native chat/session/turn/account/subscription/model identifiers;
- direct hashes of native conversation IDs or local source keys; remote
  episodes contain only a domain-separated opaque source pseudonym;
- local absolute paths, usernames, hostnames or environment variables;
- hidden reasoning, system prompts, raw hook input, tool transcripts or stack
  traces;
- unrelated local files or automatically discovered workspace content;
- task bindings, task ownership, routing decisions or `CURRENT` pointers in new
  memory objects/bundles.

A rejected packet creates only bounded local quarantine metadata with an opaque
transaction ID, reason code, time and `content_preserved: false`.

## Remote destination

Authentication alone does not prove privacy. Before publication the runtime
must verify:

1. the configured HTTPS host and repository identity;
2. the expected owner/name scope;
3. private visibility through the pinned GitHub/GitLab API policy;
4. the credential helper boundary;
5. the cached Git remote exactly matches configuration;
6. redirects do not escape the allowlisted origin/policy.

Local test remotes require both the testing environment and `_test_mode`; they
cannot be selected by a production configuration.

## Prompt-injection boundary

Any episode/event/legacy revision may contain hostile commands, links, claims
of authority or requests for credentials. Recall output must label it
`untrusted historical evidence` and explicitly deny instruction, identity and
write authority.

The model may use it to remember facts and choices, but must obtain current
authorization before it executes, sends, deletes, publishes, reveals secrets,
opens files or expands scope. The newest explicit current user instruction
wins over recalled text.

## Cross-model adapter boundary

The 0.21 host protocol is local cognitive transport, not an agent-control or
permission channel. Its closed request schema has no task, project, model,
owner, native host ID, transcript, system/developer/tool role, credential,
permission, policy, authorization, command, agent-spawn, resource-expansion, or
execution field. Unknown fields are rejected rather than ignored.

Vault-issued continuity and turn handles are high-entropy local transport state. They
must never be derived from a host ID, copied into durable memory, used as a
recall selector, or treated as a bearer capability for files, tools, accounts,
repositories, policy, or execution. Adapter-native mappings remain bounded,
private, local, and content-free.

Every response repeats fixed negative authority labels. A host must treat
evidence as `untrusted_historical_evidence`, preserve newest-current-user-input
precedence, and apply its normal permission/execution gateway independently.
No memory text or response status can create, elevate, inherit, or imply
authorization.

Prompt/explicit recall and compact operations are zero-network. Final-turn
acceptance is durable locally before acknowledgement and before any optional
publication. Exact request retries require canonical byte identity; reuse with
different bytes fails closed. Error envelopes contain only stable codes and
retryability, never visible text, native identity, paths, or exceptions.

## Evidence versus interpretation

- Episodes prove the bytes of visible messages, not that their claims are true.
- AI semantic events are always `assistant_inferred` and anchored to an episode.
- JCS/SHA-256 proves byte identity, not truth, user confirmation or task
  membership.
- Old claims remain available after supersession/conflict/resolution.
- Source and time are ranking/provenance signals, not authorization.

## Append-only and rollback attacks

After a client has a trusted commit cursor, the new head must descend from it.
Known episode/event/revision paths may only appear as additions; modification,
deletion, type change or ambiguous merge state blocks receive. The local index
advances only in the same transaction as verified objects.

Git hosts are not physical WORM. A brand-new client lacks a prior cursor and
cannot independently detect history erased before its first observation. A
future signed-checkpoint design may strengthen first-bootstrap trust.

## Concurrency

Independent immutable additions commute. A failed push may fetch once and
replay once. Before replay:

- every same path must contain exact expected bytes;
- only missing paths may be regenerated in the worktree;
- no remote modification/deletion is merged;
- failure leaves original private intents queued.

There is no timestamp last-write-wins, unlimited retry, force push, reset or
automatic branch deletion.

## Local state

The SQLite index, staged prompts, outbox, receipts, locks, credentials and
diagnostics live under private local directories/files. The index is derived
and may be rebuilt from remote objects; it must not be included in source
exports or memory bundles.

The 0.16 outbox v2 authenticates canonical intent bytes with a device-local
secret before publication. This detects later accidental or lower-privilege
modification of a queued intent, but it is not encryption and does not defend
against a process that can also read the device secret. A legacy v1 intent has
no authenticator, so 0.16 never re-signs or publishes it. Under the global
`sync.lock`, its original bytes move unchanged into an explicit recoverable
quarantine for later reviewed recovery.

Crash order is:

1. validate/stage visible prompt locally;
2. write durable outbox intent;
3. build and validate immutable objects;
4. push exact commit;
5. verify/accept the commit;
6. write receipt;
7. remove pending intent.

Crashing before step 6 must be recoverable idempotently.

## Portable bundle

Export uses a new private file and never overwrites. Import rejects:

- duplicate, undeclared or directory members;
- symlinks and unsafe modes;
- absolute paths, `..`, alternate separators and paths outside the three
  memory allowlists;
- entry, member, total-size and expansion-ratio limit violations;
- invalid UTF-8/JSON/schema/JCS/hash/privacy fields;
- noncanonical entry order;
- legacy task-scoped memory events, missing episode evidence, or relation
  targets outside the same taskless v2 graph;
- existing immutable paths with different bytes.

Bundle assertions that no credential/native ID/task binding is included must
be backed by per-document validation, not trusted as declarations.

## Artifact isolation

The retained object-store/chunk subsystem may handle separately declared
artifacts. Memory recall or semantic similarity never grants artifact access.
Every artifact operation continues to require its own configured allowed root,
storage identity, object hash/size, credential boundary and explicit workflow
authorization.

## Updates and open source

Runtime entrypoint, core, module inventory, hook inventory, plugin manifest and
marketplace identity must match. Signed update trust, once configured, cannot
silently fall back to unsigned metadata.

The open-source exporter is allowlist-based. It must reject private vault
state, memories, tasks, bindings, instances, credentials, caches, outboxes,
diagnostics, handoffs and repository history. Public examples/benchmarks use
synthetic data only.

## Required security tests

- credential and local-path rejection for prompt, episode, semantic payload,
  export and import;
- recalled prompt-injection labeling;
- wrong/public/redirected remote refusal;
- immutable modification/deletion and rewritten ancestry refusal;
- same-path concurrent byte conflict;
- outbox tamper and crash recovery;
- ZIP traversal, symlink, duplicate, undeclared, bomb, hash and schema attacks;
- legacy visible revision integrity and privacy validation;
- installed CLI absence of task-binding operations;
- public export contains no user/private state;
- host schema rejects native IDs, ownership, permission, policy and execution
  fields, including unknown nested keys;
- Vault-issued handles do not appear in episode/event/export/recall bytes;
- prompt/recall/compact host paths prove zero network access;
- final-turn acknowledgement survives offline publication and crash/retry;
- exact duplicate requests reuse one result while changed bytes hard-conflict;
- every success/error response retains the fixed no-authority labels;
- Claude Code, Gemini CLI and generic adapter fixtures never read transcripts,
  hidden reasoning, tool records, environment, or permission hooks.
