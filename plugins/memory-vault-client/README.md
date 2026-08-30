# Optional Memory Vault client package — 0.24.0-alpha.1 preview

This directory is a **source template**, not a ready-to-install standalone
plugin. Build it with `scripts/build_client_plugin.py` from the repository root.
The builder adds reviewed core modules under `runtime/`; they are not duplicated
in this source tree. The package never installs itself or changes a marketplace.

The MCP tools and Codex hooks use the **same explicitly configured Vault path**
as the lightweight core. Client staging is not a second memory database.

- MCP: explicit local read/write tools over stdio; host permissions still apply.
- Codex: optional SessionStart, UserPromptSubmit and Stop hooks, disabled unless
  `capture_visible_turns=true` in an operator-created client configuration.
- Work: a candidate MCP tool entry point where the host supports local plugin
  MCP servers. This is **not** a claim that Work exposes Codex lifecycle events
  or that this package has been validated in a particular Work installation.

No Git transport, installer, background service, transcript reader, automatic
permission grant, or audit-log suppression is included.

See [client setup and limits](../../docs/CLIENTS.md) in the source repository or
the `docs/CLIENTS.md` copied into the built package. Review the package before
installing it, review host hook trust separately, and start a fresh session when
the host requires it. Merely reading this directory does not enable capture.
