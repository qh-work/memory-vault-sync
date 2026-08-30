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

These are **separate source-pinned campaigns**, not 25 passing cases on a newer
checkout. Read the linked report for exact methods, versions, hashes and
isolation. Its evidence does not automatically transfer to later source or
another operating system. All other cases stay unrun unless a separate report
records their execution. Documentation-only commits do not rename a tested
source or rewrite an older archive's manifest.

The publication and confirmed-cancellation fixes have the narrow evidence above.
Source review also identified missing automatic cross-turn continuity edges;
that is a real implementation gap, not merely an unrun test. See the full ledger
and [development status](STATUS.md).

## Interpretation and authority

The recorded maintainer runs use disposable synthetic data. They do not prove
full parity, real-host event delivery, cryptographic interoperability, signed
cross-device transfer, native Windows/Linux behavior, large-scale throughput,
an independent implementation or adoption by another AI. The early two entry
paths both used the same Python reference. Mocked routing is not a real restore;
the later single unsigned hooks recovery case is not full recovery acceptance.
Metadata framing is not author authentication or provider encryption.

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
