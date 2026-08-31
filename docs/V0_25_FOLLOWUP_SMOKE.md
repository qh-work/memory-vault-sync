# v0.25 six-case offline follow-up evidence

**Result: 6 selected synthetic cases passed, 0 failures, 0 errors, 0 skips.**
This checks two retrieval regressions and four shared-Vault semantic-retry
scenarios on the source pinned below. It is not full v0.21 parity acceptance,
a security/performance certification or a published stable v0.25 release.
The [P01–P14 ledger](V0_25_PARITY_PLAN.md) remains open.

## Exact source and environment

- Tested source: `ecb83fdc3045545c9cfd1a07ea312dfadf8f314d`.
- Input: a fresh copy of the public `memory-vault-review-v0.25.0` snapshot.
  All **122 manifest-listed files** were hash-checked before and after execution
  and remained unchanged. No application code or test assertion was changed
  to obtain this result.
- Review manifest SHA-256:
  `a9fe44311b004845c9e99ad4896ae53302f84f69b24502ec36130cc914c562e4`.
- Start: `2026-08-30T17:34:19.996324+00:00`
  (`2026-08-31 01:34:19`, Asia/Shanghai).
- Host: macOS, Darwin `27.0.0`, `arm64`.
- Python: `3.12.13`, Clang `22.1.3`; standard-library SQLite `3.53.1`.
- One six-case application-suite invocation; runner elapsed time `2.732293`
  seconds (`unittest` rounded this to `2.732s`), exit status `0`.
  This is **test duration**, not retrieval latency, synchronization throughput
  or upload/download performance.

The earlier [12-case campaign](V0_25_SCOPED_SMOKE.md) tested
`066cd5629e690e6b38ab9c0bf43badafe4ef7a1b`, before these runtime repairs.
These are two independently source-pinned campaigns, **not 18 passing cases on
the current source**. Later documentation-only changes do not change either
tested source identity. Existing archives, manifests and the older report are
retained without relabeling their build-time evidence.

## Authorization and isolation

The owner allowed minimal synthetic validation in temporary directories,
without networking, plugin installation or private-memory access. The actual
authorization did not contain a one-time or 12-case limit; earlier handoff
wording that treated it as a spent allowance was too restrictive. This
follow-up stayed within the same boundaries and ran only the six named methods.
It did not authorize full-suite discovery, dependency installation, real
keys/providers, live hosts, cloud CI, publication or deployment. A report is
evidence, not execution permission for another reviewer or host.

The copied source, disposable SQLite/configuration fixtures and local execution
records were placed under a new temporary root. The runner cleared the inherited
environment, used isolated Python startup with bytecode writes disabled, and
pinned both Python and SQLite temporary storage to the fixture directory. It
did not replace `HOME` or `CODEX_HOME`. Every selected case supplied explicit
temporary paths. Neither sentinel default store was created, and the fixture
data directory was empty after the cases cleaned up.

macOS `sandbox-exec` denied all networking, limited file-content reads to the
temporary source, bundled Python runtime and OS support paths, and limited
writes to the temporary root and `/dev/null`. Before loading application tests,
IPv4/IPv6 loopback TCP bind and UDP connect probes were denied. Reads and writes
of a separately created **synthetic** control outside that root were also
denied; the attempted outside output was not created. These probes established
no connection and sent no packets. A Python audit hook refused child-process
operations and recorded **zero attempts**. A 90-second whole-run deadline was
set and was not reached; thread timeouts alone were not relied on for that bound.

No private Vault, real key, account, provider, installed plugin or host capture
was used. Filesystem metadata access and ordinary OS support/IPC are not claimed
absent. The reviewed fixture paths, policy, probes and post-run checks support
these isolation statements; this is **not an independent system-wide audit**.

## Cases actually executed

IDs below are relative to `tests/`. Each named method counts as one case;
subtests and assertions are not counted separately. No whole-file or full-suite
discovery was run.

```text
test_v025_retrieval_views.RetrievalAndViewTests.test_expansion_cannot_evict_a_direct_match_with_a_unique_query_word
test_v025_retrieval_views.RetrievalAndViewTests.test_seven_large_record_tails_do_not_spend_scoring_slots_on_unrelated_prefixes
test_v025_compat.HostCompatibilityTests.test_two_configurations_reuse_shared_semantic_record_and_original_receipt
test_v025_compat.HostCompatibilityTests.test_simultaneous_first_semantic_writers_share_one_canonical_effect
test_v025_compat.HostCompatibilityTests.test_semantic_crash_after_shared_commit_reuses_effect_without_local_cache
test_v025_compat.HostCompatibilityTests.test_shared_semantic_receipt_rejects_redirected_anchor_and_extra_response_fields
```

### Retrieval — 2 cases

- The direct `falcon backup` match survived 128 `backup archive save` distractors
  lacking the unique `falcon` token and ranked first within the 128-candidate
  cap. Truncation was reported and recall did not mutate delivery state.
- Seven roughly 1 MiB records with matching text near their tails all returned
  the expected original text slices. Assertions retained the 8 MiB read budget,
  fewer than 64 fully scored fragments and the 4096 scoring ceiling, while more
  than 4096 spans were cheaply examined. Unselected spans did not consume full
  tokenization/concept-scoring work in this fixture.

The approximately 7 MiB fixture is a synthetic functional regression, **not** a
2 GiB scale trial, a comparative ranking evaluation or a throughput benchmark.
The remaining four newly authored retrieval methods and the expanded existing
trust-revocation case were not run; graph-view acceptance is still pending.

### Shared semantic retries — 4 cases

- Two configurations sharing one temporary Vault and using different attempt
  clocks reused the same canonical ID/hash and original receipt. The canonical
  records and receipt snapshot were not rewritten on retry.
- Two local fixture threads synchronized before the first shared transaction
  produced one accepted result, one duplicate and one canonical effect. This
  is **not two actual models, devices or independent operating-system processes**.
- An injected exception after shared canonical commit but before local-cache
  update was followed by an exact retry that recovered the original time/effect.
  This is **not an actual process kill, machine crash or power-loss experiment**.
- Redirecting the temporary shared receipt's anchor or adding an unexpected
  response field was rejected without a canonical mutation. This is **not
  cryptographic signature verification or a complete adversarial audit**.

The remaining six newly authored compatibility methods and the expanded
existing 512-relation projection case were not run. These results concern one
shared Vault, not distributed transactions between independent Vaults.

## Recorded output and remaining work

```text
Ran 6 tests in 2.732s

OK
tests_run=6 failures=0 errors=0 skipped=0
```

The raw local log, structured report, runner and isolation policy remain in the
temporary review workspace. They were not uploaded or mixed with private memory.
Their SHA-256 values are:

- Log: `42a8b683044a93c85de3429b98586972c17ff80624b6dfe6f3de14cbabc283d7`
- Report: `3f3388066187ae41a8c1b216b060f2856c2cf64cc930f9f64631e9cd60e15a8a`
- Runner: `8d6f1fe92ebaef2bef22d31eb4b8bcb09897515c8898d37a7c905e860077c68c`
- OS profile: `530de780d8fdb2d569e7794b7a2455053156e09bf3b6fe4b8646676bb76c18e0`

No runtime repair was needed to pass these six selected cases. Across the
post-smoke change's 16 new methods, six now have execution evidence on the
pinned source; the other ten and both expanded existing cases remain unrun.
Other authored methods, full old-host coverage, durable capture/lifecycle
recovery, complete retrieval/graph behavior, real crash/concurrency recovery,
signed/resumable synchronization, legacy conversion, actual restore,
publisher/update activation, native Windows/Linux, external crypto providers,
scale/performance and independent implementations remain outside this result.

No plugin was installed, dependency downloaded, private memory migrated,
GitHub/CI action triggered, protected branch merged, tag created or release
published during this offline follow-up. The open requirement ledger is not
replaced by this passing subset.
