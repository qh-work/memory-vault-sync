# Distribution scope and publication gates

Published **[alpha.0.27](https://github.com/qh-work/memory-vault-sync/releases/tag/v0.28.0-alpha.0.27)** is fixed at `48334ec3921084394d7cd6eacb1d9283dd448d58`.

Maintainers can use `copy-reserve-root`, `copy-reserve-feed` and `copy-reserve-message` through their existing client configuration to reserve real replica capacity and retain the matching assignment. Owner and sender consent precedes the request; destination opt-in and separate upload/return permissions remain required.

Python recipients can [receive an original encrypted message and selected shared memories from an explicitly selected replica](OPEN_ACK_RECOVERY.md#receive-messages-and-shared-memories-from-a-replica-development-after-alpha025) after the mailbox source stops. Reception uses the existing durable inbox, original keys and trust policy; interrupted imports resume without duplication. Messages with independent ACK authority can return the recipient's signed receipt so the sender confirms its original send. Root, feed and message copies require separate capacity and original owner, sender, source and maintainer permission.

Thirteen checks passed using the extracted client; the published full client ZIP is byte-identical to that checked archive. The alpha.0.27 exact-source cloud regression passed 1170 tests across 124 modules in two exhaustive partitions, with all 282 reported source hashes matching `48334ec3921084394d7cd6eacb1d9283dd448d58`. Supported Python 3.10 and cross-platform conformance passed, and all eight public assets were downloaded anonymously and matched. These results do not establish independent external adoption, global reliability or thousand-agent capacity.

The HTTP repair path preserves bounded complete input and response processing. Installation retains the existing Vault, identities and protected state. Automatic replica selection, full native TypeScript mailbox workflows and independent external adoption remain unfinished.

Published **[alpha.0.25](https://github.com/qh-work/memory-vault-sync/releases/tag/v0.28.0-alpha.0.25)** is fixed at `ac3564467452c7d848dd665329851534cfd230b7`.

Twenty synthetic occupied-replica, restart, command, real-HTTP and Agent checks passed using the extracted alpha.0.25 client. Its exact-source full cloud regression passed 1116 tests across 116 modules, with all 259 reported source hashes matching `ac3564467452c7d848dd665329851534cfd230b7`. Supported Python 3.10 passed, and all eight public assets were downloaded anonymously and matched. These results do not establish independent external adoption, global reliability or thousand-agent capacity.

Python maintainers can
copy an existing saved-message receipt with all three original ACK histories.
Recipient authorization is required before reservation, during copy and for
subsequent owner reads, independently of owner/source/maintainer permission.
Original requests, used work, exact bytes and remembered revocations survive
restart. Compact transfer reuses the existing history packs within the unchanged
per-operation signature and per-replica work ceilings.

The `copy-reserve-occupied`, `copy-upload-occupied`, `configure-replica-occupied`
and `recover-replica-occupied` commands retain existing private configurations.
The Python Agent also accepts `recover_replica_receipt` through `connect`:
after validating the original recipient receipt against the actual local send,
it persists that send's saved acknowledgement. Later sends report the saved
state after restart while both original delivery and ACK sources are offline.
Selected memory remains in the recipient's Vault.

New Agent source preparation can explicitly name a distinct `copy_maintainer`
with the finite `receipt-index` profile. Default and existing grants remain
unchanged; changing a previously prepared selection is refused.

The source and extracted-package acceptance above passed for this fixed release.
Independent external adoption, global availability and thousand-agent capacity
remain unverified. Replacement
selection is explicit, and native Node replica commands remain unfinished.
See [occupied replica use](OPEN_ACK_RECOVERY.md#copy-and-recover-an-existing-saved-receipt).

Published **[alpha.0.24](https://github.com/qh-work/memory-vault-sync/releases/tag/v0.28.0-alpha.0.24)** is fixed at `b1a4e78bc8b7e8ac971d997a997bc6d5ced5904a`.

Fourteen synthetic bound-replica, restart, command and real-HTTP checks passed using the extracted alpha.0.24 runtime. Its exact-source full cloud regression passed 1099 tests across 115 modules, with all 258 reported source hashes matching `b1a4e78bc8b7e8ac971d997a997bc6d5ced5904a`. Supported Python 3.10 passed, and all eight public assets were downloaded anonymously and matched. These results do not establish independent external adoption, global reliability or thousand-agent capacity.

Python maintainers can now
reserve and copy a message-bound empty ACK slot to an explicitly selected
replacement, retaining both original history generations. Lost allocation or
commit replies resume exact durable requests after restart. Independently signed
return consents let the owner recover the original recipient/message/envelope
binding after the original node stops. The new `copy-reserve-empty`,
`copy-upload-empty`, `configure-replica-empty` and `recover-replica-empty` commands
use existing private configurations and transport journals.

The explicit `replica_empty` proof cannot be accepted as an original source or
unbound replica. A bounded metadata pack reduces network requests while every
original still counts toward the logical proof-byte ceiling. The assignment
remains COPY/READ/RETAIN only; the replacement gains no first-receipt admission.
The source and extracted-package acceptance above passed for this fixed release.
Occupied-receipt copying and automatic replacement selection remain unfinished.

Published **[alpha.0.23](https://github.com/qh-work/memory-vault-sync/releases/tag/v0.28.0-alpha.0.23)** is fixed at `d15be3af98e280938072113b62d620f99cc5921b`.

Thirty-five synthetic contact, directory, native Agent and receipt checks passed using the extracted alpha.0.23 runtime. Its exact-source full cloud regression passed 1087 tests across 114 modules, with all 256 reported source hashes matching `d15be3af98e280938072113b62d620f99cc5921b`. Supported Python 3.10 passed, and all eight public assets were downloaded anonymously and matched. These results do not establish independent external adoption, global reliability or thousand-agent capacity.

Native TypeScript agents
can now choose a configured contact node by its public key and explicitly
request finite offline directory maintenance. They refresh and challenge that
node, sign the same bounded authority as Python and retain the exact enrollment
in the existing transport database. Lost replies, restarts and language changes
preserve the node's existing job and used work. This adds no delivery approval,
trust, Vault access or permission extension. Directory workers still run on
supporting Python nodes; native Node hosts explicitly refuse the unimplemented
worker. This release passed its own source-bound and packaged acceptance as recorded above.
Thirty-three targeted protocol, native Agent, real-HTTP and directory-maintenance
checks passed on development source. They include a lost successful enrollment
reply, recipient exit, original directory expiry, node restart, Python takeover,
new-sender contact and final grant expiry. This is synthetic local traffic.

Published **[alpha.0.22](https://github.com/qh-work/memory-vault-sync/releases/tag/v0.28.0-alpha.0.22)** retains its separate source and acceptance record. Pending local delivery
and receipt work now rotates through a durable cursor shared by Python and
Node. Four older unavailable or independently authorized receipts no longer
prevent a later saved receipt from being retried. Each poll still attempts at
most four pending items; rotating changes neither receipt-sent state nor
permission. Restart and language switching retain the next retry position.

A real five-message HTTP regression failed on alpha.0.21: the fifth saved
receipt remained unsent after two restarted polls. Alpha.0.21 is therefore held
unpublished despite its earlier 32 packaged checks passing; those checks did
not cover this failure. Its immutable archives remain available for review.
The fix passed that scenario in Python and native Node, including the sender's
actual saved-receipt validation while all four blocked receipts remained unsent.
Twenty-nine direct-delivery, native HTTP and contact cases passed. Alpha.0.22 passed its own source-bound full CI and extracted-package acceptance.
Its immutable archives do not contain the later native directory enrollment work.
It retains native descriptor renewal, public introduction refresh and protected
Python/Node publication ownership from the held alpha.0.21 candidate.

Alpha.0.20 is now a published prerelease. It includes native Node commands for
unbound, empty and occupied ACK recovery, sharing authenticated status retention
with Python across failures and restarts. These commands export private evidence
through an existing identity and never open the content Vault.

The immutable alpha.0.19 candidate remains unpublished. Its full cloud run
completed 1,065 tests with one mailbox-staging failure, zero errors and zero
skips. The same failure was reproduced by delaying proof-child downloads:
the exhaustive non-ACK fixture had not funded its possession renewals and final
revocation check. Both exhaustive fixtures now request finite matching capacity
before signing their original grants; product limits and deadlines are unchanged.
This release passed its own source-bound and extracted-package acceptance as recorded below.

Alpha.0.18 remains unpublished: its complete cloud run executed 1,059 tests
with one ACK-bearing mailbox custody failure and no errors or skips. A slow
local download reproduced a possession handle expiring between child reads.
The exhaustive fixture now reads current-status originals first and renews
possession before expiry for the same exact historical references. Renewals
are bounded and charged; sufficient finite capacity is signed before setup.
Product permission windows and budgets are unchanged. Alpha.0.20 passed
separate package/privacy and exact-source full acceptance as recorded above. It also includes
packed-original reuse and persistent original-source recovery observations
from subsequent development; neither change is in alpha.0.18 archives.

Published **[alpha.0.20](https://github.com/qh-work/memory-vault-sync/releases/tag/v0.28.0-alpha.0.20)** is fixed at `24f93b04f78926d39e073ff5b3463cfc77ea64a6`.

Seventeen synthetic native-command, mailbox, receipt, restart and replica checks passed using the extracted alpha.0.20 runtime. Its exact-source full cloud regression passed 1072 tests across 114 modules, with all 256 reported source hashes matching `24f93b04f78926d39e073ff5b3463cfc77ea64a6`. Supported Python 3.10 passed, and all eight public assets were downloaded anonymously and matched. These results do not establish external adoption, global reliability or thousand-agent capacity.

This release includes packed replica original reuse and persistent original-source
recovery status across command restarts, including native TypeScript original-source
recovery commands in the installable client archive.

The release candidate below has now passed its own acceptance.
It includes the explicit remote unbound replica reservation/upload client,
independent custody verification, persistent work/status/retry state and
separately authorized replica READ recovery. Exact-source full cloud and
extracted-package acceptance passed as recorded above.

This release adds explicit `copy-reserve`, `copy-upload`, `configure-replica`,
and `recover-replica` commands. They use existing local identities and protected
transport state, preserve exact retry requests, and keep return permissions
separate from copy custody. Owner recovery remembers authenticated status facts
across failed commands and restarts. New-node setup can explicitly enable finite
remote copy reservations. No command opens the private content Vault. The replica
recovery example explicitly selects the existing 60-second client ceiling for
slower supported Python runtimes; signed deadlines and resource budgets remain
unchanged. These additions are later than the immutable alpha.0.16 candidate.

The alpha.0.16 full run was incomplete: one long mailbox fixture attempted to
sign a child request after its short handle expired, and the growing suite later
hit its 40-minute CI wall limit. Alpha.0.17 retained those same test/CI inputs and
its full run was cancelled after that diagnosis; both remain unpublished. The
fixture now performs a fresh, charged possession exchange before its independent
revocation check and reports only the current request's server errors. CI allows
55 minutes inside a 60-minute job; protocol deadlines and grants are unchanged.
Alpha.0.17 did pass 14 extracted-runtime workflows and supported Python 3.10.
Those results do not relabel either older candidate as a full-suite pass. This
alpha.0.20 release passed separate exact-source acceptance as recorded above.

The immutable alpha.0.15 candidate remains unpublished: full run
[36536522221](https://github.com/qh-work/memory-vault-sync/actions/runs/36536522221)
failed nine fixture setup cases and twelve later service-start cases. The
fixture wrapper and early cleanup registration are corrected in later source;
all 21 affected workflows passed sequentially locally. Those later results do
not relabel the old candidate bytes. Automatic replacement selection, complete
native TypeScript mailbox parity and global-scale reliability remain unfinished.

Published [alpha.0.14](https://github.com/qh-work/memory-vault-sync/releases/tag/v0.28.0-alpha.0.14), source `0eaf504e953be31b1844d6abfe57cd6f3c06aa29`, connects ACK-bearing mailbox retention to explicit receipt return after cold selected-memory delivery. A lost successful receipt response resumes from the original durable request; A then recovers the original receipt while the delivery node is offline. Four real-HTTP workflows passed using the extracted client runtime and child nodes. All eight public assets were anonymously downloaded and matched the reviewed candidate. [Exact-source full cloud regression](https://github.com/qh-work/memory-vault-sync/actions/runs/36523208918) failed two cases; scale and external adoption remain unverified.

Published [alpha.0.13](https://github.com/qh-work/memory-vault-sync/releases/tag/v0.28.0-alpha.0.13), source `7297b50f68d59649caf266be2e10515d19b5051e`, adds single-call mailbox retention and durable Agent ACK preparation with directly usable recipient/owner invitations. Five targeted HTTP workflows passed using the extracted client runtime; all eight public assets were anonymously downloaded and matched the reviewed candidate. [Exact-source cloud regression](https://github.com/qh-work/memory-vault-sync/actions/runs/36518360240) passed 934 tests, with all 242 reported source hashes matching this release commit. The supported Python 3.10 ACK check also passed; scale experiments were not run.

Published [alpha.0.12](https://github.com/qh-work/memory-vault-sync/releases/tag/v0.28.0-alpha.0.12), source `492360989a69901dc198afee9e6e7c12282b4632`, adds durable receiver authorization exchange, bounded configuration inspection/restoration and corrected completed-retry signature accounting. Four targeted extracted-client workflows passed; all eight public assets were anonymously downloaded and byte-matched. [Full exact-source cloud regression](https://github.com/qh-work/memory-vault-sync/actions/runs/36514556101) passed 934 open-network tests with zero failures/errors/skips; the separate supported-Python-3.10 ACK check passed. The report’s 242 source-file hashes match the release commit. Scale jobs were not run.

The preceding alpha.0.11 prerelease adds recipient mailbox provisioning and
registration, sender admission, retained ciphertext recovery, restart-safe memory
import and independent receipt operations through the Python Agent. Source
requests, budgets, history and observations remain persistent across retries.
Replacement-node copy/repair, partial feed recovery and complete native
TypeScript mailbox-client parity remain unfinished. Exact package validation
belongs to the source-bound release record.

Published [v0.28.0-alpha.0.11](https://github.com/qh-work/memory-vault-sync/releases/tag/v0.28.0-alpha.0.11) is built from `438f109595f4dd469fe8b4eee11c016a10d25558`. All eight public assets were anonymously downloaded and compared byte for byte with the reviewed packages. Four targeted synthetic HTTP workflows passed using the extracted client runtime, covering mailbox provisioning, interrupted two-message admission/recovery, cold selected-memory import/resume and independent receipt return/recovery. [Full exact-source cloud regression](https://github.com/qh-work/memory-vault-sync/actions/runs/36510116540) later reported two fixed-deadline HTTP fixture failures, corrected in alpha.0.12; this publication does not claim full-suite acceptance, external adoption or global availability.

Published [v0.28.0-alpha.0.10](https://github.com/qh-work/memory-vault-sync/releases/tag/v0.28.0-alpha.0.10) has eight assets, downloaded and compared byte for byte with the reviewed packages. The release is built from `7d844bea6f961ee714a236c61e352d6e9002d2fa`; [its cloud run](https://github.com/qh-work/memory-vault-sync/actions/runs/36474765248) completed 861 tests. The client archive also completed independent remote source setup, selected-memory delivery and original-receipt recovery after the delivery node stopped. These checks use synthetic data and do not establish external adoption or global-scale reliability.

## One protocol, two complete usage paths

The protocol is independent of language, storage, model, session, device and
task. The authorized full client automates the same canonical record contract;
an independent implementation is not required to install it or import Python.

The current prerelease build target is **0.28.0-alpha.0.23**, an open encrypted
delivery preview. Python and native TypeScript six-operation Agents connect explicit first-contact
approval to encrypted chat or selected original memories, durable local saving,
original-node storage receipts and separate recipient-save receipts. Setup
reuses the existing Vault and signing identity with independent transport state
and an X25519 key. See the [executable open quickstart](OPEN_NETWORK_QUICKSTART.md).
Participants publish their own real node introductions and operate their own
nodes; no project-operated public server, common issuer or fixed seed is supplied.

The first-contact controls remain available in Python and native TypeScript.
Approval still requires a concrete finite resource reservation and grants no
Vault read, trust or execution authority. Both clients use the same configured
Vault and protected transport state; native TypeScript performs the client work
without a Python subprocess. Hosting delivery currently uses the Python node,
not the TypeScript node. Original-node delivery and explicit original-receipt
recovery are implemented; message migration, automatic repair and the full
0.28.0-alpha.1 milestone remain unfinished. The private profile keeps its separate
authority and behavior. The alpha.0.4 approval fix remains in force. Earlier tests
and reviews remain historical evidence for their exact source.
Use the source-bound release manifest and actual published assets to establish
availability. This document is not proof of upload, installation, global
reliability or public adoption.
The older v0.25 reports below are historical evidence, not current download
instructions or acceptance of this prerelease.

The release builder produces:

- `memory-vault-protocol-v0.28.0-alpha.0.23.zip`: specification, schemas, synthetic
  interchange examples and implementer guides, **no executable files**.
- `memory-vault-client-v0.28.0-alpha.0.23.zip`: complete source-built runtime, plugin,
  local marketplace catalog and explicit setup instructions.
- `memory-vault-review-v0.28.0-alpha.0.23.zip`: public synthetic tests and source/build
  material for reviewers to run only with their user's authorization.
- `memory-vault-network-test-v0.28.0-alpha.0.23.zip`: synthetic endpoint template;
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
a pass, final test count or publication for the delivery preview. The intervening
0.28.0-alpha.0.2 first-contact release likewise keeps its own source-bound
review and validation; those results do not transfer to this new runtime.

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
