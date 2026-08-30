# v0.25 distribution scope and publication gate

## One protocol, two complete usage paths

The protocol is independent of language, storage, model, session, device and
task. The authorized full client automates the same canonical record contract;
an independent implementation is not required to install it or import Python.

This branch's source target is **0.25.0**. It is not evidence that a v0.25 tag,
GitHub release or installed client already exists. Previously published
v0.24.1 remains a separate immutable release.

The release builder produces:

- `memory-vault-protocol-v0.25.0.zip`: specification, schemas, synthetic
  interchange examples and implementer guides, **no executable files**.
- `memory-vault-client-v0.25.0.zip`: complete source-built runtime, plugin,
  local marketplace catalog and explicit setup instructions.
- `memory-vault-review-v0.25.0.zip`: public synthetic tests and source/build
  material for reviewers to run only with their user's authorization.
- `memory_vault.py`: optional standard-library single-file reference.
- `PROTOCOL.md`: standalone readable agreement.
- `release-manifest.json` and `SHA256SUMS`: source commit, exact byte
  inventories and the checks actually performed. Checksums are not publisher
  signatures.

The full client includes retrieval/graph tools, lifecycle/host adapters,
v0.21-compatible host operations, signed resumable synchronization, privacy
review, current-trust recovery, old packs/checkpoints, selected sharing and
controlled signed updates. [PARITY.md](PARITY.md) and the
[complete ledger](V0_25_PARITY_PLAN.md) define the scope and intentional Task/Git
exclusions.

The new lifecycle v1 and the v0.21 `compat` wire entry are **different profiles**.
Recognizable operation names alone do not make envelopes interchangeable.
Default encryption/device/update providers are not provisioned production
services; the source exposes explicit fail-closed boundaries.

## Publication is not certification

The owner authorized minimal offline synthetic acceptance in temporary
directories, without networking, plugin installation or private-memory access.
That permission was scope-limited, not a one-run or 12-case quota. Two separate
source-pinned campaigns completed within that scope:

- [12 selected cases passed](V0_25_SCOPED_SMOKE.md) on
  `066cd5629e690e6b38ab9c0bf43badafe4ef7a1b`.
- [6 selected cases passed](V0_25_FOLLOWUP_SMOKE.md) on
  `ecb83fdc3045545c9cfd1a07ea312dfadf8f314d`: two retrieval regressions and
  four shared-Vault semantic receipt/retry cases, including simultaneous first
  writes, interruption after commit and tampering rejection.

Each campaign had zero failures, errors or skips. They are not an 18-case pass
on the current source; the remaining suite was not run. This permission does
not extend to full-suite discovery, cloud CI, networking, installation or
publication. Source/AST/JSON, package structure and archive-byte inspection
remain separate evidence. No real Vault, installed private plugin, key, host
setting or remote account was used. The exercised entry paths share one Python
reference; independent-implementation or cross-model interoperability is unproven.

Full P01–P14 acceptance, broader crash/concurrency coverage, signing/encryption,
real-host, native-platform, throughput and cross-device validation remain
pending. Do not publish an unqualified stable/completed claim
without auditing all requirements. Review material may be shared as development
work with its precise validation limits; it does not replace a completion audit.

Protected main and existing tags must not be rewritten or bypassed to obtain
a green indicator. Tests are not silently triggered merely to manufacture a
result. The public release state must be checked independently at publication
time; this file does not assert current GitHub status.

## Build without running the application

From a reviewed source checkout, select a new absolute output directory:

```bash
python3 -B scripts/build_release.py --output /absolute/new/release-directory --source-commit FULL_COMMIT_SHA
```

The builder copies only public allowlists, parses source/JSON, builds both
usage packages and the separate review kit, then verifies archive member bytes.
It does not import the application, initialize memory, generate keys, connect
a host, run tests or install anything. Existing output paths are not overwritten.
The caller-supplied commit must actually identify the reviewed source; the
manifest explicitly states that the builder does not validate Git ancestry.

For review evidence, report the exact commit, OS/runtime/provider versions,
synthetic input and observed result. See [REVIEW_HANDOFF.md](REVIEW_HANDOFF.md).
