# Memory Vault v0.25.0 development — authorized full client

This is the full-client **review build**, not a claim of a finished or
runtime-verified stable release. The plugin is under
`plugins/memory-vault-client`; the local marketplace catalog is
`.agents/plugins/marketplace.json`. All 26 required runtime source modules
are included. No Git checkout or runtime build is needed to use the archive.

Python 3.10+ and a host supporting local stdio MCP are required. The ordinary
unsigned path uses only the standard library. Optional record signing requires
the separately installed integration dependency, explicit keys and independent
public-key trust. No production publisher/encryption/recovery provider is
provisioned by this package.

## Explicit setup

1. Extract into a location you control and keep it there.
2. Create a new private configuration; existing configuration is not overwritten:

   ```bash
   python3 -I -B plugins/memory-vault-client/scripts/launcher.py configure --vault /absolute/private/vault.sqlite3
   ```

   Omit `--vault` to use the reference default. Configuration does not create a
   Vault or install a host. Add `--capture-visible-turns` only to explicitly
   enable visible-turn capture; host hook approval remains separate.
3. For a compatible Codex installation, add the extracted **root directory** as
   a local marketplace source, then review and install `memory-vault-client`
   from `Memory Vault — Protocol and Client`. Review hooks separately. This
   package is not a listing in a universal public plugin directory.
4. For another local MCP host, use your Python executable with arguments
   `-I -B /absolute/path/to/plugins/memory-vault-client/scripts/launcher.py mcp`.
   Add `--config /absolute/private/client.json` before `mcp` when needed.

On Windows use `py -3 -I -B` or the absolute installed Python executable.
The packaged default command is `python3`; adapt the host command if it is not
available. Native protected storage/locking supports local fixed NTFS under
the documented owner/DACL rules. UNC, unsupported volumes, reparse points and
unverified permissions fail closed. **Real Windows behavior was not tested.**

## One Vault through either route

The same configured storage and trust work without MCP:

```bash
python3 -I -B plugins/memory-vault-client/scripts/launcher.py protocol --serve
```

An independent implementation can instead follow the documentation-only UAMP
protocol using another language or storage engine. Both exchange the same
canonical records; neither a task, session nor a plugin owns them.

The full client additionally includes:

- Eleven MCP tools, local visible-turn lifecycle and Codex/Claude Code/Gemini
  CLI/generic adapters. Host support requires actual approved event delivery.
- An explicit `compat` entry for the ten v0.21 production host operations;
  legacy handles are local correlations, not new memory owners.
- Full-record CJK/Latin retrieval, deterministic concept expansion, explained
  BM25 ranking, derived claim views, graphs and repairable indexes.
- Durable signed sync, explicit receive/flush, blocked-send review and selected
  resolution, directory/rclone backends and resumable large-transfer fragments.
- Memory snapshots plus separately explicit full-client recovery to new paths;
  no silent key, permission or remote-delivery trust transplant.
- Native portable chunks and v0.21 ZIP/pack/checkpoint verification/conversion,
  preserving original evidence and graph/alias mappings.
- Content-selected sharing, independent trust lifecycle and fail-closed
  externally provided encryption/catalog contracts; explicit device metadata
  init/status and new/old envelope inspection without a configured Vault.
- Controlled update staging, independently pinned publisher verification,
  isolated managed activation/rollback and separately opted-in finite updates.

See `plugins/memory-vault-client/docs/CLIENTS.md`, `COMPATIBILITY.md`,
`PARITY.md`, `PLATFORMS.md` and the full `V0_25_PARITY_PLAN.md` ledger.
Operational commands never derive permissions from memory. Ordinary recall and
local saves do not wait for network. No host setting, private installation,
startup service or real Vault is changed by extracting this package.

## Evidence and independent review

The packaged [validation index](plugins/memory-vault-client/docs/VALIDATION.md)
pins limited offline synthetic evidence to exact source commits. Match those
reports to this artifact; results from other versions do not certify its paths.
v0.25 remains unreleased development source. The exercised entry paths share one
Python reference, not independent implementations or models. Full P01–P14,
signing/encryption, cloud, real-host/cross-device, native Windows and performance
acceptance remain open; recorded checks installed no host plugin and accessed
no private memory. The separate review kit supplies synthetic cases and bounded
instructions for reviewers using their own authorization and disposable data.

Only allowlisted public source is packaged. No real memory, credentials, keys
or local user configuration is included. Inventory/archive checks establish
bytes, not publisher identity or production security.
