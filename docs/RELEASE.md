# Distribution scope and publication gates

## One protocol, two complete usage paths

The protocol is independent of language, storage, model, session, device and
task. The authorized full client automates the same canonical record contract;
an independent implementation is not required to install it or import Python.

The current prerelease build target is **0.28.0-alpha.0.2**, a first-contact
candidate extending the native open routing/HTTP preview. Python and native
TypeScript add owner-enabled finite knock leases, strictly structured requests
with real dual-key possession, explicit approval/rejection, and result pulls
bound to the original request, parties, concrete resource, operation and expiry.
An approval requires an actual finite resource reservation; it does not grant
Vault access or execution authority. See [the candidate contract](OPEN_FIRST_CONTACT_V1.md).
Open encrypted messaging, receipts and sender-offline ciphertext repair remain
outside this preview. The retained private profile is separate.
The 0.28.0-alpha.1 full vertical milestone remains pending.
Publication must be independently verified at the
[target release page](https://github.com/qh-work/memory-vault-sync/releases/tag/v0.28.0-alpha.0.2);
at candidate preparation, 6 Pro review, cloud CI, final archive checks and
publication were pending. Use the release evidence for the exact source commit
for their final status. This source document is not proof of upload,
installation or certification.
The older v0.25 reports below are historical evidence, not current download
instructions or acceptance of this prerelease.

The release builder produces:

- `memory-vault-protocol-v0.28.0-alpha.0.2.zip`: specification, schemas, synthetic
  interchange examples and implementer guides, **no executable files**.
- `memory-vault-client-v0.28.0-alpha.0.2.zip`: complete source-built runtime, plugin,
  local marketplace catalog and explicit setup instructions.
- `memory-vault-review-v0.28.0-alpha.0.2.zip`: public synthetic tests and source/build
  material for reviewers to run only with their user's authorization.
- `memory-vault-network-test-v0.28.0-alpha.0.2.zip`: synthetic endpoint template;
  this release has unconfigured service trust and requires operator provisioning.
- `memory_vault.py`: core source; Experience use also needs the companion module
  included in the client/review packages.
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

The prior **0.28.0-alpha.0.1** native HTTP preview is pinned to
`0ddf0c5ac6aa8d12562c1df2a26ee25aeb851ed3`. Its review, cloud checks and asset
verification remain historical evidence for that source. They do not establish
a pass, final test count or publication for the first-contact candidate.

The source-pinned routing experiment on `dc485334f8ad8629db68ef25c7c618a732f15c6c`
passed all three original 99% healthy / 97% bootstrap-exit gates: seeds17/29/43
each returned 1,000/1,000 in both phases. The 84-method open CI and three-platform
protocol CI also passed. See [complete source/run/artifact bindings and limits](OPEN_ROUTING_RUNTIME.md).
This is logical in-process signed routing, not 100-node HTTP/SQLite, actual AI
or independent physical failure-domain acceptance. It does not establish global
reliability, unlimited capacity or production security. Release-only metadata
checks and actual downloaded bytes are recorded separately in the release body.
Historical relay-pool and Experience results retain their original source pins;
none is a whole-suite pass for this preview.

Current controls use content/v2 and Hint v4 within network-v1; old preview
forms are rejected. No automatic private upgrade, migration or plugin
replacement is supplied. Existing installations and backups remain separate;
extracting an artifact changes neither private state nor Git binding. The
synthetic trial's unconfigured service trust is not a hosted service: an
operator must provision reviewed pinned service material before use.

### Historical v0.25 capacity evidence

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
passed. The subsequent v0.25.1
[PR run 33376043040](https://github.com/qh-work/memory-vault-sync/actions/runs/33376043040)
and [main run 33376118903](https://github.com/qh-work/memory-vault-sync/actions/runs/33376118903)
also passed; [the ledger](V0_25_PARITY_PLAN.md) records its downloaded-asset check.
Any next patch requires its own checks; earlier passes are not current-branch evidence.
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
The development builders verify that the supplied commit is the actual current
HEAD and that every selected input is a regular, tracked file with exactly the
committed bytes. Untracked or ignored files found by a selected glob are refused
before their contents are read; modified selected files and a different commit
are also refused. Unrelated working changes do not enter the build. The builder
rechecks selected files and HEAD before completing. Git is only a build-source
provenance tool here, not a memory runtime or task-binding requirement.
Each ZIP is also limited to an exact independently declared member inventory:
committed source hashes plus explicitly generated manifest bytes. Extra or
missing staging files are refused, and archived bytes are checked against that
declaration, not merely against the same mutable staging directory. This
archive gate is separate from the source-helper test recorded below.

### Mandatory public-content review

The source gate does not detect private values that were already committed.
Both the selected source changes and the actual final archives require a
separate privacy review before any push or release. Publish only generic code,
documentation and deliberately synthetic fixtures. Real memories, transcripts,
artifacts, migrated catalogs/maps, cloud object IDs, local account paths,
configuration and credentials stay outside the public source/export directory.
Previously approved public publisher metadata is not private runtime state.

`private_state_included: false` is an inventory claim, not a privacy certificate.
The manifest explicitly limits its exclusion claim to selected public source
paths. Hold publication if any selected content has uncertain provenance or a
possible private value; a successful build or passing test does not waive this
gate. Never use an actual private catalog as a public test fixture.

One synthetic source-gate method passed on 2026-08-31 with Python 3.12.13 on
macOS. It creates a disposable Git repository and checks current committed
inputs, wrong existing commit, unrelated changes, selected same-size changes,
and selected untracked/ignored inputs. The tested helper SHA-256 is
`a5095740c8c69db0be1d502f446a7bf697c649357bcdb9dbc6c1c7c3cb36c7d0`;
the fixture SHA-256 is
`e37dab2f6a69fdf70522fa1cd797d33e2a34ad471a0f49c91a7398619463f5b6`.
The combined gate/catalog run passed two methods in 0.350 seconds. This did not
test real private data or prove the contents of a future release archive.

For review evidence, report the exact commit, OS/runtime/provider versions,
synthetic input and observed result. See [REVIEW_HANDOFF.md](REVIEW_HANDOFF.md).
