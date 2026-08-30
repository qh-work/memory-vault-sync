# v0.24.0 release scope

## One protocol, two equal usage paths

The protocol is independent of the implementation language and storage engine.
The optional user-authorized plugin automates that same memory contract. A
direct protocol implementation is not required to install the plugin or import
our Python module. Shared record bytes, relations and exchange rules connect
the two paths; a task, model, session or client never becomes a memory owner.

Published assets:

- `memory-vault-protocol-v0.24.0.zip`: specification, JSON Schemas, synthetic
  interchange examples and an independent implementation guide; no executable.
- `memory-vault-client-v0.24.0.zip`: complete source-built plugin runtime,
  explicit setup instructions and a local marketplace catalog.
- `memory_vault.py`: optional standard-library single-file reference.
- `PROTOCOL.md`: the standalone readable agreement.
- `release-manifest.json` and `SHA256SUMS`: source commit, build scope and asset
  integrity inventory. Checksums do not authenticate the publisher.

The plugin includes local MCP tools, explicit opt-in visible-turn hooks, a
configured direct-protocol bridge and the optional lifecycle profile. Signing,
quarantine, explicit signed directory batches and staged old-export conversion
remain optional modules, not protocol or installation prerequisites.

The lifecycle entry keeps recognizable `session.open`, `turn.input`,
`turn.commit`, `turn.abort` and `session.close` operation names in **new explicit
v1 envelopes**. It does not accept every old v0.21 Host Adapter envelope, record
schema or error code. The old runtime and Git synchronization are not restored.

## Publication is not runtime certification

At the owner's request, no unit, integration, conformance, host, performance or
cross-device tests were run for this release. Source inspection, static syntax
and JSON validation, packaging and archive/inventory verification are separate
activities, not a substitute for those tests. See the included manifest and
[review handoff](REVIEW_HANDOFF.md) for reproducible independent review scope.

The repository's protected main branch still requires three platform
conformance checks. Those protections are not weakened or bypassed. The
release is published from its exact version tag on the integration branch;
the prior main checkout may still be v0.23. Use `v0.24.0`, not an unqualified
main checkout, when reviewing or installing this release. No CI run is triggered
just to manufacture a passing result, and missing results are not successes.

## Explicit non-goals and remaining limitations

- No installation into the maintainer's existing private client and no live
  private-data migration were performed while preparing this release.
- No OpenAI universal-directory submission or vendor certification is claimed.
- Native Work automatic lifecycle capture is not established. MCP availability
  depends on the actual host; a model alone cannot create file/process tools.
- No automatic network daemon or new network privilege is added. Directory
  transfer needs separately authorized transport when devices differ.
- Ed25519 signatures identify an enrolled signing key, not the original human,
  model, truth of a statement or authority to execute a remembered action.
- Bare-core reads without a trust registry report ingestion-time verification;
  use a configured trusted client for current key-revocation checks.
- NDJSON exports intentionally omit signatures. Use the signed transfer
  profile for preserving the accepted record attestations; unsigned imports
  are quarantined unless explicitly accepted, never silently upgraded into
  trusted evidence.
- Native Windows protected key storage, multiple-proof recovery, production
  security audit and independently observed interoperability remain open.

## Build without running application tests

From a reviewed source checkout, use a new absolute output directory:

```bash
python3 scripts/build_release.py --output /absolute/new/release-directory --source-commit FULL_COMMIT_SHA
```

The builder reads only public source allowlists, parses source/JSON, assembles
the two packages and computes checksums. It does not import the application,
initialize a Vault, install a plugin, generate keys or run tests. Existing output
paths are never overwritten.
