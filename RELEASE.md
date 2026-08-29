# Release guide

Use this checklist for any change to the installable plugin, lifecycle hooks, persisted protocol, schemas, or repository validator.

## Release identity

The current updater follows Semantic Versioning precedence. Build metadata after `+` does not affect precedence. Exact same-version bundle and marketplace-commit identity is enforced, but every change to executable behavior or packaged files must still increment major, minor, or patch. Do not publish a different bundle under only a new build-metadata timestamp.

A release is identified by all of the following evidence:

- precedence-bearing semantic version;
- exact marketplace Git commit;
- plugin bundle SHA-256 calculated by the updater;
- successful pull-request and `main` workflow runs;
- matching runtime and manifest versions.

## Files to review for a version change

- `plugins/memory-vault-sync/.codex-plugin/plugin.json`
- `plugins/memory-vault-sync/scripts/vault_sync.py` (`VERSION`)
- `plugins/memory-vault-sync/scripts/memory_vault_runtime/core.py` (`VERSION`)
- `plugins/memory-vault-sync/hooks/hooks.json` when its description names the release
- installed and repository-side Memory Vault skills when they name version-specific behavior
- `STATUS.md`
- `CHANGELOG.md`
- `CHUNK_PROTOCOL.md` and `benchmarks/chunk-protocol-v1.json` when chunk behavior changes
- `PRIVATE_DIAGNOSTICS.md` when diagnostic fields, bounds, persistence, or hook behavior changes
- `SIGNED_UPDATES.md` when trust bootstrap, metadata, bundle identity, root rotation, or release provenance changes
- `HOST_ADAPTER_PROTOCOL.md`, request/response schemas, reference adapters and
  their fixtures when host lifecycle behavior changes
- configuration, failure-recovery, setup, protocol, architecture, schema, and validator documents affected by the change

Search the repository for the previous exact version and capability names before declaring the version consistent.

## Before opening the release PR

1. Start from the current `main`; do not release from an older task checkpoint or stale marketplace cache.
2. Confirm the private control-plane repository and owner-controlled object-store requirements have not been weakened.
3. Confirm no credential, local absolute path, raw runtime database, hidden reasoning, test token, or private artifact entered the diff.
4. Update the version everywhere required.
5. Update `CHANGELOG.md` with user impact, protocol changes, compatibility, migrations, limitations, and validation evidence.
6. Update `STATUS.md` and move completed roadmap items to Done.
7. Run all checks in `DEVELOPMENT.md`.
8. Review the diff for deterministic JSON, line-ending, executable-bit, and generated-file changes.
9. If preparing public source, run the allow-listed exporter into a new directory with a reviewed license, inspect its hash manifest, and run the exported tests. Never publish the private checkout itself.
10. If signed metadata will be activated, require a separately approved offline
    key ceremony. Record public fingerprints, thresholds, custodians, expiries,
    independent canonical-byte review, and recovery. Never generate production
    keys inside this checkout, CI, a PR, or plugin data.

## Pull request requirements

Open the release as a draft first. The body must state:

- what changed and why;
- user and cross-device impact;
- persisted schema or protocol compatibility;
- migration and rollback behavior;
- security boundaries and explicit exclusions;
- exact local test counts;
- required GitHub Actions jobs;
- whether merge, squash, or rebase is safe for referenced immutable ancestors.

Do not merge while any required job is absent, skipped unexpectedly, or running against a different commit.

## Automated evidence

Broad runtime, storage, crypto, or migration changes normally require:

- plugin unit suite;
- repository validator unit suite;
- full active-layout validation against the correct base for a private vault
  checkout; public source runs validator unit tests because private data layers
  are intentionally absent;
- macOS, Ubuntu, and Windows plugin jobs;
- Python minimum-version job once that roadmap item is implemented;
- package manifest/runtime version consistency;
- diff and JSON parsing checks.

For the v0.21.0 model-neutral host-protocol release, require:

- entrypoint, core and manifest version
  `0.21.0+codex.20260830000842`, with public tag semantics `v0.21.0`;
- JSON/schema/runtime agreement, Python compilation, and one-shot/NDJSON CLI
  smoke checks;
- focused synthetic checks for prompt/recall/compact zero-network behavior,
  durable-local final-turn acknowledgement, exact retry versus hard conflict,
  negative authority labels, and native-ID exclusion;
- reference-adapter fixtures for Claude Code, Gemini CLI and generic local
  stdio hosts, without live transcripts, accounts or permissions;
- unchanged durable `memory-episode/v1` and `memory-event/v2` compatibility plus
  a retained Codex hook smoke check;
- a fresh allowlisted Apache-2.0 public export/privacy contract before creating
  the corresponding public release.

Publish those schemas, examples, focused adapter tests and synthetic golden
fixtures so other AI models and maintainers can extend them. Public CI is
source- and fixture-level conformance evidence only, not high coverage,
real-account integration, production certification, or proof of local
installation. Describe a release as merged, installed, CI-passed, or published
only when each corresponding artifact was actually observed.

When `rclone-crypt` changes, also run the credential-free live local-crypt
acceptance with a checksum-verified supported rclone release. Record the exact
rclone version and executable hash, large round-trip result, encrypted
name/content check, cancellation behavior, and ciphertext-tamper refusal.
Cloud S3/WebDAV/SFTP credentials remain separate deployment acceptance and
must never be copied into CI fixtures or pull-request text.

When the encrypted chunk policy, manifest, receipt, transfer planner, or
restore path changes, also run `scripts/benchmark_chunk_protocol.py` with both
100 MiB and 1 GiB scenarios. Require cold upload, a localized 1% change,
interruption after chunks but before manifest, zero-byte retry reuse, no remote
deletion, exact manifest bounds, and atomic final-SHA restore. A local provider
substitute proves protocol byte counts only; the live rclone/crypt test must
also prove `cryptcheck` avoids full upload verification downloads on a
checksum-capable backend and that plaintext-download fallback remains tested.

When private diagnostics change, force an unexpected hook failure with a
constructed secret/path-shaped exception and prove that only the reviewed
metadata fields persist. Verify generic output, correlation, 4 KiB/64-record/
256 KiB bounds, permissions, link refusal, corruption without echo, rotation,
expected-error separation, unconfigured CLI access, status/doctor, complete
fallback inventory, and public-export exclusion of runtime records.

When signed-update verification, deterministic bundle construction, or trust
state changes, test valid RSA-PSS signatures against an independent tool and
exercise missing thresholds, old/new-root rotation signatures, nonsequential
roots, expiry/future metadata, local clock rollback, role rollback, changed
same-version metadata, parent hash/length/version mix-and-match, target
version/hash/length/protocol mismatch, semantic-version rollback,
same-version bundle substitution, unsafe metadata links/hardlinks/races,
metadata-only descendant commits, changed plugin trees, atomic trust reload,
and mandatory failure with no metadata after trust is configured. Run the
same tests from the exported source. A verifier-only release must explicitly
say that production signing keys and a live signed channel are not provisioned.

Live Git-provider/object-store verification is separate evidence. Never claim it from filesystem-test results.

## After merge

1. Verify `main` contains the expected commit and exact manifest version.
2. Verify the `main` workflow run is successful.
3. Perform a bounded updater check on one controlled client.
4. Verify the stable runtime records the intended version and bundle.
5. Run `status` and `doctor --online` on a controlled device without publishing unrelated memory or artifact work.
6. Run `update-trust-status`. Do not import a test root on a production client;
   signed mode is accepted only with separately reviewed production metadata.
7. Update `STATUS.md` if final evidence differs from the release PR.
8. Do not create or move a Git tag unless a tag policy has been explicitly adopted.

## Rollback and hotfix

- Never force-push or rewrite the private vault history to roll back a plugin.
- Publish a new higher patch version that restores the last safe behavior.
- Keep historical memory events and all migration-era bindings, task versions,
  pointers and checkpoints immutable even though they no longer own memory.
- If remote history moved backwards or a bundle identity is ambiguous, clients must fail closed and require explicit review.
- Never delete or silently replace an imported signed-update root as rollback.
  Recover with a valid sequential rotation; loss of the root threshold requires
  a separately authorized out-of-band rebootstrap.
- Preserve pending and candidate work; do not move CURRENT merely to make a release appear successful.
- Record the rollback or hotfix in `CHANGELOG.md` with the affected versions and recovery action.
