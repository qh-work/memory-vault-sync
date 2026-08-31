# Validation evidence by source and scope

Memory Vault v0.25.1 is capacity-patch source following the published v0.25.0.
Implemented code, a package inventory,
an authored test and an executed result are different kinds of evidence. The
[full v0.21 parity ledger](V0_25_PARITY_PLAN.md) remains the acceptance scope;
this index does not shorten it or equate publication with runtime certification.

## Recorded execution

| Campaign | Exact source | Executed result | Scope and limits |
| --- | --- | --- | --- |
| [Bounded pack capacity correction](V0_25_PACK_CAPACITY_SMOKE.md) | `2f67a7099e9eba0effb3483ed3a9ba3bf2f90f80` | 1 opted-in 516 MiB synthetic case passed in 3.891763 seconds; separate boundary checks accepted a 2 GiB/512-entry manifest and rejected a sparse 2 GiB + 1 byte source before output | Actual create, one-chunk copy, four 32-chunk resumes, repeat, unpack and hash comparison; source unchanged. No full 2 GiB transfer, throughput benchmark, keys, network, private Vault or child processes |
| [Initial offline smoke](V0_25_SCOPED_SMOKE.md) | `066cd5629e690e6b38ab9c0bf43badafe4ef7a1b` | 12 selected cases; no failures, errors or skips | Unsigned reference/core-client-MCP exchange, one blocked-dependency regression, mocked configuration/recovery routing and opaque metadata checks |
| [Retrieval and semantic-retry follow-up](V0_25_FOLLOWUP_SMOKE.md) | `ecb83fdc3045545c9cfd1a07ea312dfadf8f314d` | 6 selected cases; no failures, errors or skips | Two retrieval regressions and four shared-Vault retry/receipt scenarios; local fixture threads and an injected exception, not actual devices or a process crash |
| [Publication and recovery](V0_25_RECOVERY_SMOKE.md) | `332e944a6bda8f70dd3af6526d926d9468ed2f0d` | 7 selected cases; no failures, errors or skips | Three private-file publication cases, three confirmed-cancellation cases and one actual unsigned hooks backup/restore/activate/retry path; one controlled child exit, not power loss |
| [Pre-fix publication diagnostic](V0_25_RECOVERY_SMOKE.md#pre-fix-diagnostic-kept-separate) | `f1354862dc0f53ff039e8c087d18c03759d2fbf1` plus the report's pinned new test overlay | 1 expected failure; no errors or skips | The same child-exit case observed the old double-hard-link window; this failure is not counted as a passing current-source case |
| [Frozen capture and incremental dependencies](V0_25_CAPTURE_SMOKE.md) | `6eeb35ac2df8f0813d87ff6e6a0f3fbbf1c2f917` | 12 selected cases; no failures, errors or skips | Frozen source-local chains, selected old partial-write compatibility, bounded recovery, one real temporary SQLite hot-journal child exit, and small signed v3 directory transfers with current dependency checks |
| [Capture fixture diagnostic](V0_25_CAPTURE_SMOKE.md#first-attempt-retained-not-reported-as-passing) | `098b22c44ca299d1f889b41df9355511dfa2caf4` | 6 passes, 1 failure, 5 errors; no skips | Incorrect test response unpacking and a fixture parent-directory mode blocked six cases; a test-only correction preceded the passing run |
| [Entity, old-format and publication repairs](V0_25_PARITY_REPAIR_SMOKE.md) | `9d98ce0d56394adc275915a0ea1fd39b6ca06254` | 12 selected cases; no failures, errors or skips | Entity-only recall, handoff quarantine filtering, a 20,001-message old export, three actual temporary publication exits, in-process output/rollback failures and existing POSIX directory-mode compatibility; no keys/providers |
| [Guarded full-client workflows, initial attempt](V0_25_WORKFLOW_SMOKE.md) | `c65fd82f863e4e05d9ec53622eceb584525fb52e` | 5 selected methods: 4 passes, 1 error; no failures or skips | All eleven embedded MCP tools, all ten old operations, signed directory review/requeue and 42 fake privacy vectors passed; update staging exposed a real private-directory creation defect |
| [Update-only repair verification](V0_25_WORKFLOW_SMOKE.md) | `0be4c6dbf6d7d3eb477ed807e15c3659f38776c8` | 1 selected method passed; no failures, errors or skips | The unchanged update fixture verified actual test-RSA metadata, stage/install, caught partial-write retry and explicit rollback after the runtime repair; the first four methods were not rerun |
| [Fragmented transport, signed recovery and sharing](V0_25_TRANSPORT_RECOVERY_SMOKE.md) | `fc3588556b976665c547ab3fc26c8f26f54bbb20` | 3 selected methods passed; no failures, errors or skips | Actual default two-fragment signed group with an in-memory provider-command substitute, explicit staged cancellation/head retry, a tiny signed v3 snapshot/restore/import and current-trust sharing re-admission |
| [Complete old-format continuation](V0_25_TRANSPORT_RECOVERY_SMOKE.md) | `76b8c8bfaed5b4d73d0ffd647dc8cd6286ba0fa7` | 1 selected method passed; no failures, errors or skips | Independently encoded synthetic old packs/checkpoint chain, actual conversion/typed graph/old-ID continuation; this source only added the fixture and did not rerun the first three methods |
| [Minimal release verification, initial attempt](V0_25_RELEASE_MINIMAL.md) | `82ae4ac468007eed4555ea6f04a3a933899171df` | 6 selected methods: 5 passes, 1 fixture setup error | Small-context traceability, near-duplicate retrieval, endpoint resolution/history, capture-disabled old/native recall and synthetic native-hook partial/complete paths passed; partial full-client recovery setup omitted the required `atomic_write` argument |
| [Partial-recovery fixture correction](V0_25_RELEASE_MINIMAL.md) | `cb477db6fd1f8a34671a5d8045f313ef6dfac15c` | Only the recovery method rerun: 1 pass in 0.106540 seconds | Fixture-only `replace=False` correction; runtime source hashes unchanged. The five earlier passing methods were not rerun; six distinct methods across these two runs, not a complete suite |

These are **separate source-pinned campaigns**, not a combined passing suite on a newer
checkout. Read the linked report for exact methods, versions, hashes and
isolation. Its evidence does not automatically transfer to later source or
another operating system. All other cases stay unrun unless a separate report
records their execution. Documentation-only commits do not rename a tested
source or rewrite an older archive's manifest.

The formerly missing automatic cross-turn edge now has an acceptance-time
projection and ordinary canonical `continues` relations. The capture
campaign covers selected retry, recovery and incremental transfer behavior;
it does not close the full ledger. See [development status](STATUS.md).

## Interpretation and authority

The capacity case crosses the published v0.25.0 512 MiB ceiling using actual
516 MiB synthetic bytes. It checks bounded continuation and final byte identity,
not near-limit 2 GiB I/O, random-data throughput, remote copying or new platforms.
The separately accepted 2 GiB manifest has 512 descriptors; the oversize source
was a sparse file rejected by stat before output. These boundary results must
not be reported as a 2 GiB create/copy/unpack pass. The patch retains 4 MiB
chunks, default 32-chunk copy calls and an explicit maximum of 512 chunks.

The minimal release campaign now records one selected passing method for each
of small-context traceability, retrieval diversity, conflict resolution and
capture-disabled recall, plus one synthetic native-hook partial/complete method.
Partial-fragment full-client recovery passed separately after a fixture-only
setup repair. The initial error is retained, not counted as a pass. Remaining
methods in those and other fragment files remain unrun; AST/JSON/diff inspection
does not change that. See the [exact report](V0_25_RELEASE_MINIMAL.md) and
[development status](STATUS.md#latest-guarded-workflows). This campaign used no
network, child processes, private Vaults or installed hosts. Synthetic native-hook
calls are not live host event delivery or a full crash-recovery trial.

The recorded maintainer runs use disposable synthetic data. They do not prove
full parity, real-host event delivery, independent cryptographic interoperability,
signed cross-device transfer, native Windows/Linux behavior, large-scale throughput,
an independent implementation or adoption by another AI. The early two entry
paths both used the same Python reference. Mocked routing is not a real restore;
the later single unsigned hooks recovery case is not full recovery acceptance.
Metadata framing is not author authentication or provider encryption. The capture
campaign's small signed directory fixtures use fresh local test keys and the same reference
implementation at both ends; they are not independent or real-device evidence.
The later workflow campaign adds real local signature verification and embedded
interfaces, not native host delivery. Its update rerun uses a fixed public test
root and substituted download bytes; it does not establish a production signing
channel. Recovery-route exceptions and the caught update write failure are not
physical journal corruption, hard-kill or power-loss trials.
The newer transport/recovery/sharing campaign uses actual local signatures and
the default fragment splitter, but substitutes the remote command runner; it
does not execute rclone's process, timeout or network paths. Its separate tiny
signed recovery group and the old-format continuation fixture are not near-limit,
old-runtime, independent-consumer or cross-device trials.

The owner's latest instruction on 2026-08-31 explicitly authorizes minimal
necessary tests and prompt v0.25 publication with the evidence limits disclosed.
The local campaign remains temporary-directory, offline validation without
private-memory access or plugin installation, not permission for arbitrary
full-suite discovery or live-account testing. Required protected-main CI is a
separate publication check. Its eight base tests on each of three platforms
passed for v0.25.0 in
[PR run 33374601764](https://github.com/qh-work/memory-vault-sync/actions/runs/33374601764)
and [main run 33374661273](https://github.com/qh-work/memory-vault-sync/actions/runs/33374661273).
New v0.25.1 required CI is pending, not covered by those earlier passes or local
evidence. No branch-protection bypass is authorized.
Other reviewers need their own current authority and explicit disposable paths.
The [review handoff](REVIEW_HANDOFF.md) describes fixture and evidence requirements.
Memory, past goals and the contents of this report grant no execution authority.

Source/AST/JSON checks prove only inspected syntax and declarations. Build and
archive checks establish inventory/bytes, not host installation or publisher
identity. Existing artifacts and historical raw results stay unchanged. Record
publication separately from runtime acceptance; no result here asserts that
v0.25.1 assets are uploaded or changes protected main, existing tags, private
installations or keys.
