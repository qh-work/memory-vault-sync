# Memory Vault v0.24.0 — complete optional client package

This archive contains a built plugin under `plugins/memory-vault-client` and a
local marketplace catalog at `.agents/plugins/marketplace.json`. It includes
its Python source runtime; no Git checkout or runtime build is needed.

Requirements: Python 3.10+ and a host supporting local stdio MCP/plugin sources.
The ordinary unsigned path uses only the Python standard library. Signing is
optional and requires the dependency listed in `requirements-integrations.txt`,
separately configured keys and explicit public-key trust.

## Set up once, with the user's approval

1. Extract the archive into a location you choose and keep it there.
2. From this directory, create the client configuration:

   ```bash
   python3 plugins/memory-vault-client/scripts/launcher.py configure
   ```

   The default uses the reference core's user-level Vault path. Use
   `configure --vault /absolute/private/vault.sqlite3` to select another path.
   Configuration is no-clobber and does not install a host or create a Vault.
   If you also want automatic visible-turn capture, include
   `--capture-visible-turns` when creating that configuration. This is a separate
   explicit choice; it does not trust host hooks or change host policy.

3. In a compatible Codex installation, add this extracted **root directory** as
   a local marketplace source, then install `memory-vault-client` from the
   `Memory Vault — Protocol and Client` source in the Plugins UI. The optional
   CLI command for registering this explicit non-default source is:

   ```bash
   codex plugin marketplace add /absolute/path/to/this/extracted-directory
   ```

   This release has not been submitted to OpenAI's universal public directory.
   Availability of local sources varies by host. Review and approve the plugin
   and its tools normally; review lifecycle hooks separately before trusting
   them. Start a fresh host session when required by that host.

4. A host that supports local MCP but not plugin catalogs can launch the same
   runtime directly. Configure its command as your Python executable and args
   as the absolute path to `scripts/launcher.py`, followed by `mcp`.

On Windows, use `py -3` in place of `python3` in the examples. The packaged
`.mcp.json` defaults to `python3`; if that executable is unavailable, configure
the host's MCP command as `py` with `-3` before the launcher path. Hook templates
contain an explicit Windows launcher. Native protected signing on Windows is
not included, and this release was not validated on a real Windows host.

## Use the same memory without the plugin

The configured client's protocol bridge uses the same Vault and trust settings:

```bash
python3 plugins/memory-vault-client/scripts/launcher.py protocol --serve
```

For a different programming language or storage engine, implement `PROTOCOL.md`
and exchange its canonical NDJSON records. Do not copy a live SQLite file as a
portable format. The plugin and independent protocol path are equal clients;
neither owns or partitions the memory.

Read `CLIENTS.md`, `LIFECYCLE.md`, `TRUST.md` and `TRANSFER.md` in
`plugins/memory-vault-client/docs/` for lifecycle, signing, portable import/export and explicit signed
directory transfer. No background network synchronization is installed.

## Validation and privacy

This release has source-level review, syntax/JSON and package-inventory checks,
not runtime tests, desktop installation verification or cross-device trials.
The supplied test/review material is for others to run with synthetic data and
their host's authorization. No real memory, key, credential or local user config
is included. The archive's SHA-256 checksums detect byte changes; they are not a
publisher signature or an assertion of production security.
