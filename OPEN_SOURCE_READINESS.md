# Open-source release process

The plugin code is maintained so a public fork can be created without exporting this private vault's task state. Public release is intentionally a separate operation from normal repository publication.

## Safe export boundary

Run the allow-listed exporter from the private repository root:

```text
python3 scripts/export_open_source_bundle.py \
  --destination /new/empty/path \
  --repository-id qh-work/memory-vault-sync \
  --repository-url https://github.com/qh-work/memory-vault-sync.git \
  --author qh-work \
  --marketplace-name memory-vault-public \
  --marketplace-display-name "Memory Vault" \
  --license-file open_source/LICENSE
```

The destination must not exist. The exporter copies only the plugin,
protocol/schema material, provider and chunk contracts, reproducible synthetic
benchmark/code, relevant tests, and one public README. It never copies
`tasks/`, `sources/`, `bindings/`, `memory/`, `instances/`, `handoffs/`, or
`migration/`. It replaces the private deployment identity and writes
`.open-source-export.json` with exact file hashes.

The public source includes the reviewed diagnostic implementation, tests, and
`PRIVATE_DIAGNOSTICS.md`, but never a managed plugin data directory or any
`diagnostics/records/` runtime content. Diagnostic records remain private local
data even when the source itself is published.

The public source also includes the verifier, test-only signing fixtures, and
`SIGNED_UPDATES.md`, but never a private deployment trust store, production
root, or production signing key. Test RSA parameters have no release authority.
Rebranding does not transfer update trust: a public fork must define its own
offline root ceremony, thresholds, custodians, expiry monitoring, release
signer, and recovery process before enabling signed mode.

The repository URL must be credential-free HTTPS on GitHub.com or GitLab.com,
the two production control-plane privacy verifiers bundled in this release.
For GitLab, the exporter also changes the default verifier and credential host;
group/subgroup repository IDs are supported. Adding another host requires a
reviewed adapter and fixed privacy-verification policy, not a string-only edit.

The exporter includes the rclone adapter code and tests but never the rclone
binary, a provider config, a `known_hosts` file, or credentials. A public
release that advertises rclone support must separately record the reviewed
upstream source and license, supported version floor, clean-download checksum,
and provider-specific acceptance evidence. Users must be able to supply an
independently installed executable at an absolute path; the plugin verifies
its exact hash before every boundary probe.

This allow-list is safer than cloning the private repository and deleting selected paths: a newly added private directory remains excluded unless a maintainer explicitly adds it to the exporter and its tests.

Rebranding is intentionally re-entrant. The exporter stages source identities
behind reserved placeholders before inserting target identities, preventing a
target label that contains its source label from being rewritten again. The
same source-identity and private-state checks therefore remain usable by a
generated public fork that later changes ownership or marketplace branding.

## Approved public release decisions

- license: Apache License 2.0;
- copyright holder and public maintainer identity: `qh-work`;
- public repository: `qh-work/memory-vault-sync`;
- marketplace name: `memory-vault-public`;
- display name: `Memory Vault`;
- vulnerability reporting: private GitHub security advisories;
- update policy: exact public repository, commit, version, and bundle identity
  checks remain active; production signed-update trust is not provisioned and
  no signing or server-unreadability claim is made.

Every export still requires an explicit license file. The maintained Apache-2.0
text is `open_source/LICENSE`; forks may deliberately supply another reviewed
license but must not imply that rebranding transfers update trust.

## Publication evidence

- Public repository: [qh-work/memory-vault-sync](https://github.com/qh-work/memory-vault-sync),
  visible as a public Apache-2.0 repository with issues, discussions, secret
  scanning, push protection and Dependabot security updates enabled.
- Initial source release: [v0.20.0](https://github.com/qh-work/memory-vault-sync/releases/tag/v0.20.0).
  It is retained as immutable history and marked superseded for new installs by
  the Windows portability patch.
- Previous public release: [v0.20.1](https://github.com/qh-work/memory-vault-sync/releases/tag/v0.20.1),
  merged through public PR [#1](https://github.com/qh-work/memory-vault-sync/pull/1).
- Current public release: [v0.21.0](https://github.com/qh-work/memory-vault-sync/releases/tag/v0.21.0),
  merged through public PR [#2](https://github.com/qh-work/memory-vault-sync/pull/2).
- The earlier v0.20.1 acceptance run
  [33135361908](https://github.com/qh-work/memory-vault-sync/actions/runs/33135361908)
  passed the complete plugin suite on Ubuntu Python 3.10/3.12, macOS Python
  3.12 and Windows Python 3.12, together with the public-source contract.
  Windows executed 423 tests; the public source/schema suite executed 86.
- The v0.21 release workflow runs the same public source/privacy and maintained
  plugin boundaries, including the published synthetic host-protocol and
  reference-adapter fixtures. This is source- and fixture-level conformance,
  not real-host or production certification.
- The v0.21 release manifest records 124 exact allow-listed hashes and
  `private_state_included=false`. The public history was created independently
  rather than publishing or rewriting the private repository history.
- `main` requires the five release checks, up-to-date branches, linear history
  and resolved review conversations; force pushes and branch deletion are
  disabled. Only squash merging is enabled and merged branches are deleted.

These facts establish the public source and CI boundary. They do not provision
production keys, authorize recalled text, publish private memory data or make a
runtime/model/task an owner of memory.

## Release gate

Before publishing the exported tree:

1. Review `.open-source-export.json` and the complete diff from an empty repository.
2. Run the plugin suite, exporter tests, and repository validator unit tests
   inside the exported tree. Do not fabricate or copy a private vault merely
   to make full-layout validation run.
3. Search for deployment identifiers, credentials, account names, hostnames,
   absolute local paths, conversation/artifact content, and runtime diagnostic
   records.
4. Verify manifest/runtime versions and the public marketplace source.
5. Run Python 3.10 and 3.12 tests on Ubuntu, Python 3.12 on macOS and Windows, and all JSON/schema checks.
6. If rclone is advertised, verify a clean upstream executable and checksum,
   encrypted config, ciphertext-at-rest behavior, SFTP host-key pinning where
   applicable, exact restore bytes, cancellation, and tamper refusal. If chunk
   support is advertised, reproduce the 100 MiB and 1 GiB cold/delta/retry/
   restore benchmark, prove `cryptcheck` avoids a full verification download
   on a checksum-capable backend, and prove the plaintext-download fallback.
   Do not redistribute rclone unless its upstream license and notices are
   handled.
7. If signed updates are enabled, independently reproduce the deterministic
   bundle, verify root/targets/snapshot/timestamp signatures and expiries,
   exercise old/new-threshold root rotation and all fail-closed cases, and
   confirm `update-trust-status` reports required mode on the clean client.
   Keep all production private keys outside the source tree and CI.
8. Perform a clean install with newly scoped test credentials; never reuse private-vault credentials for public validation.
9. Publish only after the security policy, supported providers, known limits, and rollback process match the code.

Passing the exporter tests proves the source allow-list and rebranding mechanics. It does not itself grant permission to publish, choose a license, or prove live provider credentials.
