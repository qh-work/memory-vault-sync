# Memory Vault client — v0.24.0

In the source checkout this directory is a **build template**. The v0.24.0
release ZIP contains the complete plugin, including `runtime/MANIFEST.json`
and the source modules. Download that package to avoid a local build. Developers
can build a fresh directory with `scripts/build_client_plugin.py`.
The package never installs itself, changes a host marketplace or trusts hooks.

The MCP tools and Codex hooks use the **same explicitly configured Vault path**
as the lightweight core. Client staging is not a second memory database.

- MCP: eight explicit local read/write tools; host permissions still apply.
- Protocol: the configured `protocol` command reads/writes and exports/imports
  the same canonical records for independent non-plugin implementations.
- Lifecycle: optional session/turn staging and commit through a new documented
  profile; old operation names are not a claim of old v0.21 wire compatibility.
- Codex: optional SessionStart, UserPromptSubmit and Stop hooks, disabled unless
  `capture_visible_turns=true` in an operator-created client configuration.
- Work: a candidate MCP tool entry point where the host supports local plugin
  MCP servers. This is **not** a claim that Work exposes Codex lifecycle events
  or that this package has been validated in a particular Work installation.

No Git transport, background service, transcript reader, automatic
permission grant, or audit-log suppression is included.

See `docs/CLIENTS.md` and `docs/LIFECYCLE.md` inside the built package, or
[client setup](https://github.com/qh-work/memory-vault-sync/blob/v0.24.0/docs/CLIENTS.md)
in the source repository. Review the package before
installing it, review host hook trust separately, and start a fresh session when
the host requires it. Merely reading this directory does not enable capture.
This release has structural/package checks, not runtime or host validation.
