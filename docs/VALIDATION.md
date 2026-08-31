# Validation evidence by source and scope

Memory Vault v0.25 is development source. Implemented code, a package inventory,
an authored test and an executed result are different kinds of evidence. The
[full v0.21 parity ledger](V0_25_PARITY_PLAN.md) remains the acceptance scope;
this index does not shorten it or claim a stable release.

## Recorded execution

| Campaign | Exact source | Executed result | Scope and limits |
| --- | --- | --- | --- |
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

The later small-context, retrieval-diversity, conflict-resolution and
capture-disabled-recall fixtures have not been executed. Their accompanying
source repairs postdate every runtime campaign above. AST/JSON/diff inspection
does not turn these fixtures into passing tests; see the current
[development status](STATUS.md#latest-guarded-workflows).

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

The owner's allowance covers minimal offline validation in temporary directories,
without private-memory access or plugin installation; it is not a one-run/test
quota or permission to run the full suite, cloud CI, live accounts or deployment.
Other reviewers need their own current authority and explicit disposable paths.
The [review handoff](REVIEW_HANDOFF.md) describes fixture and evidence requirements.
Memory, past goals and the contents of this report grant no execution authority.

Source/AST/JSON checks prove only inspected syntax and declarations. Build and
archive checks establish inventory/bytes, not host installation or publisher
identity. Existing artifacts and historical raw results stay unchanged. Record
publication separately from runtime acceptance; no result here asserts current
GitHub status or changes protected main, tags, private installations or keys.
