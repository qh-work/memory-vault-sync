# v0.25.1 distribution scope and publication gate

## One protocol, two complete usage paths

The protocol is independent of language, storage, model, session, device and
task. The authorized full client automates the same canonical record contract;
an independent implementation is not required to install it or import Python.

This source target is **0.25.1**, a bounded file-pack capacity patch. It is not
evidence that the patch tag, release assets or installed client already exist.
Previously published [v0.25.0](https://github.com/qh-work/memory-vault-sync/releases/tag/v0.25.0)
at `7f27953b27b9ecd453be19084808357c89731d20` remains immutable. Check the
[v0.25.1 release page](https://github.com/qh-work/memory-vault-sync/releases/tag/v0.25.1)
for publication status and the [patch notes](RELEASE_NOTES_V0_25_1.md) for scope.

The release builder produces:

- `memory-vault-protocol-v0.25.1.zip`: specification, schemas, synthetic
  interchange examples and implementer guides, **no executable files**.
- `memory-vault-client-v0.25.1.zip`: complete source-built runtime, plugin,
  local marketplace catalog and explicit setup instructions.
- `memory-vault-review-v0.25.1.zip`: public synthetic tests and source/build
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

The patch raises only the optional file-pack source limit from 512 MiB to 2 GiB,
with unchanged 4 MiB chunks, at most 512 descriptors and the existing default
32-uncached-chunk copy budget. Canonical record/protocol and signed-sync limits
are unchanged. The [capacity report](V0_25_PACK_CAPACITY_SMOKE.md) records one
opted-in 516 MiB synthetic pack/resume/unpack/hash case passing in 3.891763 seconds
on `2f67a7099e9eba0effb3483ed3a9ba3bf2f90f80`, plus a 2 GiB/512-entry manifest
acceptance and rejection of a sparse 2 GiB + 1 byte source before output. No
full 2 GiB transfer or throughput benchmark was run. No keys, network, private
Vault or child processes were used; the source stayed unchanged.

On 2026-08-31 the owner explicitly authorized minimal necessary verification
and prompt v0.25 publication. The local acceptance campaign uses temporary
directories without networking, plugin installation or private-memory access.
The [validation index](VALIDATION.md) records exact source commits and execution
scope; match each report to the artifact rather than combining results across
versions. Source/AST/JSON, package structure and archive-byte inspection are
separate evidence. Recorded checks use disposable synthetic Vaults and state,
not pre-existing private memory, installed plugins, production keys, existing
host settings or remote accounts. The exercised paths share one Python
reference, not independent implementations or models. The publication request
does not authorize arbitrary full-suite discovery, private-account testing or
changes to installed clients.

The earlier [minimal release report](V0_25_RELEASE_MINIMAL.md) records six distinct
methods across two runs: five passes and one fixture setup error on
`82ae4ac468007eed4555ea6f04a3a933899171df`, then the recovery-only pass on
`cb477db6fd1f8a34671a5d8045f313ef6dfac15c` after a fixture-only correction.
Runtime source hashes were unchanged; the first five methods were not rerun.
This is scoped evidence, not a current-source whole-suite pass.

Full P01–P14 acceptance, broader crash/concurrency coverage, production signing/encryption,
real-host, native-platform, throughput and cross-device validation remain
pending. Under the latest owner instruction, v0.25 may be published with these
explicit limits and exact source/artifact evidence. Publication is not an
unqualified full-parity, production-readiness or native-platform certification,
and does not close the complete acceptance ledger.

Protected main and existing tags must not be rewritten or bypassed to obtain
a green indicator. Existing protected-main CI requires eight base tests on each
of three platforms. The v0.25.0
[PR run 33374601764](https://github.com/qh-work/memory-vault-sync/actions/runs/33374601764)
and [main run 33374661273](https://github.com/qh-work/memory-vault-sync/actions/runs/33374661273)
passed. New v0.25.1 required CI is pending and remains a separate publication
gate; earlier passes are not patch evidence.
The public release state must be checked independently at publication
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
