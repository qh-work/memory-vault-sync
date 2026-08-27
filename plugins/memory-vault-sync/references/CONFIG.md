# Memory Network configuration

Production has one memory model: taskless associative memory. There is no
supported setting for task binding, automatic task matching, routing choices,
task CURRENT pointers or memory projection.

## Minimum setup

The control plane must be a private GitHub or GitLab HTTPS repository. Configure
its exact identity, branch, privacy verifier and credential-helper host:

```text
python3 "${PLUGIN_ROOT}/scripts/vault_sync.py" configure \
  --repo-url https://github.com/OWNER/PRIVATE-REPOSITORY.git \
  --branch main \
  --expected-repository OWNER/PRIVATE-REPOSITORY \
  --control-privacy-verifier github-private-v1 \
  --control-credential-host github.memory-vault-sync.local \
  --artifact-mode none
```

For GitLab use `gitlab-private-v1` and the exact namespace/repository. Production
rejects local paths, SSH URLs, unapproved hosts, public repositories, mismatched
API identity and redirect escapes.

Authenticate through the operating-system credential helper:

```text
python3 "${PLUGIN_ROOT}/scripts/vault_sync.py" auth-control
```

The token/password is read through bounded stdin or the trusted helper flow and
must never be placed in config, command arguments, Git URLs or manifests.

## Active memory settings

Validated configuration internally uses these defaults:

```json
{
  "sync": {
    "associative_recall_enabled": true,
    "memory_recall_limit": 8,
    "memory_recall_context_bytes": 8192,
    "startup_pull": true,
    "stop_publish": true,
    "conversation_backup": true
  }
}
```

- `associative_recall_enabled`: inject related local evidence on prompt submit.
- `memory_recall_limit`: 1–32 fragments.
- `memory_recall_context_bytes`: 512–65536 bytes; default 8 KiB.

Installed `0.18` uses deterministic lexical/graph recall plus a built-in
hand-authored Chinese/English concept and polarity bridge. It reports bounded
raw lexical/concept signals, a graph ranking factor and stable explanation
labels. They are not an additive final-score decomposition. It is not an
embedding model or vector search, has no cloud endpoint or credential, performs
  no prompt-time network request, and always retains lexical fallback. The
  current-view command derives bounded claim timelines and conflict explanations
from the local index without modifying durable episodes/events or assigning an
owner.

- `startup_pull`: receive remote additions at startup/resume/clear.
- `stop_publish`: attempt immediate small publication after durable local queue.
- `conversation_backup`: create visible episode packets.

Old `matching`, `projection`, `memory_network_enabled`, and
`legacy_task_handoff_enabled` fields are removed atomically when a production
config is loaded. A content-free private migration receipt records which
sections were removed. They are not active settings and no CLI can recreate
them.

## Performance bounds

The following are fixed protocol safety bounds rather than tuning knobs:

- 32 queued turns per Git commit;
- 1 MiB queued intent bytes per commit;
- 2 MiB indexed visible text per document;
- 1536-byte fragments with 192-byte overlap;
- 64 KiB query hard ceiling and 512 query tokens;
- 32 recall-hit hard ceiling;
- one concurrent replay;
- bundle/member/count/expansion bounds documented in `MEMORY_NETWORK.md`.

Do not raise a bound without tests for memory use, runtime, archive abuse and
cross-platform behavior.

## Lifecycle behavior

The installed hooks call:

```text
hook session-start
hook user-prompt-submit
hook stop
```

They require every listed runtime file to be a regular non-symlink file.
`memory_vault_runtime/memory_network.py` and its versioned local
`memory_vault_runtime/retrieval.py` adapter are part of both Unix and Windows
inventories and of the verified fallback bundle. Concept scoring may be
disabled while lexical recall remains available, but `retrieval.py` remains a
required integrity-checked runtime file and must not be physically omitted.

Session start opens the network. Prompt submit is local-only. Stop first queues
locally, then tries one immediate publish. Offline or busy packets stay queued
and will be sent at a later SessionStart or explicit `flush`.

The released 0.16 runtime authenticates each pending outbox intent with the existing
private device secret. Local modification is rejected before publication. The
authentication code is local-only, does not encrypt the intent, and is not a
portable device-to-device signature.

Pending 0.15.4-format v1 intents have no authenticator. The 0.16 runtime does
not re-sign or publish them; under the global `sync.lock`, it moves their
original bytes unchanged into an explicit recoverable quarantine for later
reviewed recovery. Configuration migration must not silently discard an
offline turn.

## Operational commands

```text
vault_sync.py status
vault_sync.py diagnostics --limit 10
vault_sync.py doctor
vault_sync.py doctor --online
vault_sync.py flush
vault_sync.py recall --query-stdin --limit 8
vault_sync.py views --limit 32
vault_sync.py pack-network --output <new-private-pack>
vault_sync.py copy-pack --pack <pack> --output <destination-pack> --journal <private-journal>
vault_sync.py import-pack --pack <existing-private-pack>
vault_sync.py checkpoint-pack --pack <pack> --output <checkpoint> --generation 1
vault_sync.py verify-checkpoint --checkpoint <checkpoint>
vault_sync.py share-network --selector-stdin --output <new-private-envelope> --recipient-fingerprint <opaque-recipient-key> --key-epoch 1
vault_sync.py verify-share-envelope --envelope <existing-private-envelope>
vault_sync.py remember --proposal-stdin
vault_sync.py export-network --output <new-private-path>
vault_sync.py import-network --bundle <existing-private-path>
```

Recall queries and semantic proposals use stdin to keep private content out of
process listings. `flush` has no task transaction/candidate selectors.

## Semantic proposal

The exact accepted schema is:

```json
{
  "schema_version": "memory-network-semantic-proposal/v1",
  "source_id": "src-...",
  "episode_id": "ep-...",
  "kind": "user_preference",
  "claim_key": "preferred-response-language",
  "parents": [],
  "supersedes": [],
  "conflicts_with": [],
  "resolves": [],
  "payload": {
    "statement": "Prefer Chinese responses"
  }
}
```

Allowed kinds: `decision`, `constraint`, `progress`, `next_action`,
`hypothesis`, `artifact_created`, `artifact_verified`, `correction`,
`user_preference`, `conflict_declared`, `conflict_resolved`, and
`checkpoint_note`. The proposal cannot set confidence or task scope. Runtime
forces `assistant_inferred`, anchors source/sequence/hash to the episode, adds
the continuity parent and validates every relation target as an existing
taskless v2 event.

## Optional artifact subsystem

Memory itself uses the private Git control plane and does not require Google
Drive, rclone, chunking, projection roots or workspace bindings. Existing users
may keep the separately configured object-store subsystem to read historical
large artifacts. Recalled memory never authorizes an artifact operation.

For a memory-only deployment use `--artifact-mode none` and do not configure an
object-store credential. If retained legacy configuration still requires one
writable primary store structurally, keep it inaccessible to normal memory
hooks and follow the provider-specific recovery documentation before changing
or deleting it.

## Updates

`update`, `update-trust-status`, and `configure-update-trust` remain independent
of memory semantics. Imported signed-update trust is one-way: once present,
threshold signatures, expiry, rollback/mix-and-match protection, release commit
and exact bundle identity remain mandatory.

## Healthy status

Expected values include:

```json
{
  "memory_network": {
    "enabled": true,
    "mode": "taskless_associative",
    "task_binding_required": false,
    "task_binding_active": false,
    "transport": "append_only_incremental_git",
    "receive_strategy": "commit_delta_after_initial_index",
    "ordinary_turn_objects": 2
  }
}
```

A queued outbox while offline is recoverable. An invalid index, remote history
rewrite, immutable byte conflict, public/mismatched repository or privacy scan
failure requires remediation rather than a forced retry.

## Future trust and encryption settings

The 0.18–0.20 roadmap adds first-device signed checkpoints, selective encrypted
subgraphs, and encrypted replication/device recovery in that order. No config
field for these unshipped features is accepted today. Production key material
must be created through a separately reviewed offline ceremony and must never
enter config, source, CI, command arguments or plugin data. The 0.19 selector
and `memory-share-envelope/v1` boundary are implemented, but the default
provider is intentionally unconfigured: share creation fails closed and leaves
no plaintext handoff. The 0.20 device-trust and ciphertext-only replication
contracts likewise require an external signer, OS key store, recovery package,
and real device ceremony. Clean Windows CI and cross-platform provider
acceptance remain release gates.
