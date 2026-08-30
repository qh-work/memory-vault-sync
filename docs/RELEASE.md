# v0.24.1 release scope

## One protocol, two equal usage paths

The protocol is independent of the implementation language and storage engine.
The optional user-authorized plugin automates that same memory contract. A
direct protocol implementation is not required to install the plugin or import
our Python module. Shared record bytes, relations and exchange rules connect
the two paths; a task, model, session or client never becomes a memory owner.

Published assets:

- `memory-vault-protocol-v0.24.1.zip`: specification, JSON Schemas, synthetic
  interchange examples and an independent implementation guide; no executable.
- `memory-vault-client-v0.24.1.zip`: complete source-built plugin runtime,
  explicit setup instructions and a local marketplace catalog.
- `memory_vault.py`: optional standard-library single-file reference.
- `PROTOCOL.md`: the standalone readable agreement.
- `release-manifest.json` and `SHA256SUMS`: source commit, build scope and asset
  integrity inventory. Checksums do not authenticate the publisher.

The full plugin includes MCP tools, opt-in visible-turn hooks, a configured
protocol bridge, the lifecycle profile and Codex/Claude Code/Gemini CLI/generic
host adapters. Independent sync opt-in adds queued signed transfer using a
finite worker and directory/rclone backends. Diagnostic, backup/restore, chunk
pack and controlled update-staging commands are included as separate modules.
Signing, remote transport and staged old-export conversion remain optional
features, not lightweight-protocol prerequisites. See [PARITY.md](PARITY.md).

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
the prior main checkout may still be v0.23. Use `v0.24.1`, not an unqualified
main checkout, when reviewing or installing this release. No CI run is triggered
just to manufacture a passing result, and missing results are not successes.

## Explicit non-goals and remaining limitations

- No installation into the maintainer's existing private client and no live
  private-data migration were performed while preparing this release.
- No OpenAI universal-directory submission or vendor certification is claimed.
- Native Work automatic lifecycle capture is not established. MCP availability
  depends on the actual host; a model alone cannot create file/process tools.
- No always-on network daemon or new network privilege is added. Full-mode
  synchronization can start a finite worker only after an independent operator
  opt-in, and uses the host's existing authorized transport. Local prompt/save
  paths never wait for network; receipts do not prove remote consumption.
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
