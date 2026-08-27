# Windows setup

The Windows client uses the same taskless Memory Network protocol as macOS and
Linux. No task ID, binding ID, lineage ID or numbered route choice is required.

## Requirements

- supported Codex desktop/plugin runtime;
- Python 3.10 or newer available to the verified launcher;
- Git for Windows;
- access to the exact private GitHub/GitLab control-plane repository;
- an operating-system credential helper entry for that repository;
- NTFS/local storage that supports private user ACLs for plugin data.

## Runtime launch

`hooks.json` verifies every required regular file and invokes
`scripts/windows_launcher.ps1`. The inventory includes
`scripts\memory_vault_runtime\memory_network.py` and its versioned local
`scripts\memory_vault_runtime\retrieval.py` adapter. The launcher uses isolated
Python discovery and does not inherit arbitrary project modules.

Do not edit the installed cache in place. Install a new reviewed plugin version
and let the verified fallback runtime update through its normal activation
path.

## Configure the private Git control plane

From a trusted PowerShell session, resolve the installed `vault_sync.py` and
run its `configure` command with the exact HTTPS repository, branch, expected
owner/name, privacy verifier and credential-helper host. Use
`github-private-v1` or `gitlab-private-v1` to match the host.

Then run:

```text
py -3 -I <VaultSync.py> auth-control
py -3 -I <VaultSync.py> doctor --online
```

Never put the token in the command, Git URL, environment or config file. The
runtime reads it from the scoped credential helper.

For a memory-only installation choose artifact mode `none`. Historical object
store/rclone configuration may remain for separately authorized old artifacts;
it does not participate in memory recall.

## Expected lifecycle

- Opening/resuming a conversation receives only remote memory additions after
  the local cursor and flushes queued episodes.
- Sending a prompt searches the local SQLite index only and opens no network.
- Finishing a turn queues one episode plus one continuity event and attempts a
  small private Git push.
- Offline packets remain under the private local outbox and later converge.

The UI must never ask which task this conversation belongs to. Old task and
binding files are ignored as memory authority.

## Manual checks

```text
py -3 -I <VaultSync.py> status
py -3 -I <VaultSync.py> doctor
py -3 -I <VaultSync.py> flush
```

For private recall, pipe UTF-8 query text into `recall --query-stdin`; do not
place the query on the command line. For export/import, use a private local path
and preserve the generated bundle's user-only ACL.

Healthy status reports `taskless_associative`, no task binding, commit-delta
receive, local associative index counts and either an empty or recoverable
outbox.

## Windows-specific safety

- Generated paths are checked for symlinks and Windows reparse points.
- Git uses `core.longpaths=true` and a disabled hooks directory.
- Runtime files, config, index, staged prompts and outbox must not be links.
- ZIP imports reject unsafe path forms, alternate traversal and symlink modes.
- PowerShell alias/launcher resolution is pinned to the current trusted host;
  do not replace it with a project script.
- If antivirus temporarily holds the SQLite/outbox lock, leave the packet
  queued; do not copy private state to a shared directory.

## Troubleshooting

- **Python unavailable:** install/repair a supported Python and rerun `doctor`.
- **Git unavailable:** repair Git for Windows; do not switch to an unverified
  sync client.
- **Authentication/private check failed:** refresh only the scoped credential
  helper entry and confirm exact repository identity.
- **Offline:** continue using local recall; later run `flush`.
- **Immutable conflict/history rewrite:** stop, retain local outbox/index and
  investigate the remote history; do not force push.
- **Local index invalid:** rebuild the derived private index from verified
  remote objects; never upload the database.
- **Old binding prompt appears:** the client is running an old plugin. Verify
  installed/runtime versions, reinstall the new release and open a new
  lifecycle event; do not answer the obsolete prompt.

See `CONFIG.md`, `FAILURE_RECOVERY.md`, and the repository
`MEMORY_NETWORK.md` for the full contract.
