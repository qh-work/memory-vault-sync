# Explicit updates, with the old installation preserved

The full client includes an operator-only release stager. Hooks, memory text,
MCP tools and synchronization never call it. It never changes an installed
plugin, the host's marketplace, a trust registry or the existing Vault.

From the packaged plugin root, these are **commands for the operator to run**;
they were not executed while preparing this release:

```bash
python3 scripts/launcher.py update check
python3 scripts/launcher.py update stage --version 0.24.1 --out /absolute/new/staged-update
```

`check` reads stable release metadata from the fixed public
`qh-work/memory-vault-sync` GitHub repository. It writes no local state and
loads no GitHub credential. `stage` pins an explicit version, reads the release
manifest, verifies the full-client ZIP's size/hash, validates its bounded
inventory and each listed runtime module's hash, and extracts into a **new**
directory. Existing output is refused. Downloaded modules are never imported,
executed or automatically installed. Failure may leave a new incomplete staging
directory for inspection, not overwrite the current package.

Downloads use certificate-verified HTTPS, an allowlist of GitHub release hosts,
redirect checking, bounded metadata/archive sizes and timeouts. Archive paths,
symlinks, duplicates, encryption and excessive expansion are refused. A
`STAGED.json` receipt is written only after the complete package is staged.

## Activation and rollback

Review the new code and release notes. Use the host's ordinary approved plugin
installation/update flow when you decide to activate it; host-specific approval
cannot be simulated by this stager. Keep the previous package and configuration
until the new installation has been checked. Re-select that previous package
through the host for rollback. Backup the Vault before any separately requested
schema upgrade; staging itself performs no database migration.

SHA-256 inventories are **not publisher signatures**. The release manifest and
the archive come from the same account; compromise of that account is outside
their authenticity guarantee. The stager does not claim a supply-chain audit,
vendor certification, automatic Work installation or native Windows key safety.
For an offline update, download the public assets through your ordinary approved
channel and review the same manifest/inventory; no account login is required.
