# Minimal v0.25 release checks

The owner requested minimal necessary testing and prompt publication on
2026-08-31. Six specific methods were selected; no discovery or full v0.25
suite was run. The first run passed five methods and encountered one fixture
setup error. Only that fixture was corrected, and only its method was rerun.
This is six distinct methods with passing evidence across two source-pinned
runs, not a fresh passing suite on every later documentation commit.

## Sources and observed results

- Initial source: `82ae4ac468007eed4555ea6f04a3a933899171df`.
  Six methods, five passes, one error, no failures/skips; 0.250519 seconds.
- Recovery retry source: `cb477db6fd1f8a34671a5d8045f313ef6dfac15c`.
  One method passed, no errors/failures/skips; 0.106540 seconds.
- The intervening commit changes only the recovery fixture's initial
  `atomic_write` call to explicitly supply `replace=False`. All application
  modules are identical between these sources. Source hashes were unchanged
  during each execution.

The initial recovery error was `TypeError: atomic_write() missing 1 required
keyword-only argument: 'replace'` in `setUp`, before the recovery workflow
started. It is retained as an error, not reclassified as a passing attempt.

| Module / class | Exact method | Result and coverage |
| --- | --- | --- |
| `test_v025_context_budget.ContextBudgetTests` | `test_small_context_remains_traceable_for_recall_and_handoff` | Initial pass: real recall/handoff keeps a traceable excerpt within 512 bytes without changing stored evidence |
| `test_v025_retrieval_diversity.RetrievalDiversityTests` | `test_near_duplicates_leave_room_for_distinct_evidence_in_both_modes` | Initial pass: near duplicates leave room for distinct retrieved evidence in both modes |
| `test_v025_conflict_resolution.ConflictResolutionTests` | `test_resolution_closes_only_its_endpoint_edges_and_retains_the_complete_history` | Initial pass: explicit endpoint resolution, remaining independent conflicts and immutable history |
| `test_v025_capture_disabled_recall.CaptureDisabledRecallTests` | `test_disabled_capture_keeps_real_recall_and_noncommittable_legacy_handles` | Initial pass: native/old-host local recall remains available while automatic persistence stays disabled |
| `test_v025_partial_hook_capture.PartialHookCaptureTests` | `test_real_hooks_save_both_partial_orders_and_keep_the_original_pair_profile` | Initial pass: actual native hook calls, both one-sided arrival orders, append-only supplements, exact retry and unchanged complete-pair profile |
| `test_v025_partial_capture_recovery.PartialCaptureRecoveryTests` | `test_fragment_done_and_frozen_supplement_restore_without_source_and_retry_exactly` | Setup error initially; recovery-only retry passes real snapshot/inert restore/explicit activation/exact retry and memory-only receipt preservation |

## Isolation and limits

macOS, Python 3.12.13, the same reference implementation, disposable unsigned
Vaults and explicitly created configuration. A runner audit hook refused network
and child-process events, writes outside the temporary evidence directory and
SQLite connections outside that directory. No boundary violation occurred.
No installed host/plugin, private Vault, production key or remote provider was
used. Exception injection represents selected interruption boundaries, not
power loss or operating-system concurrency. Durations describe these fixtures,
not a performance benchmark.

Other new methods, including separate trust/revocation, queue-limit,
lock-concurrency and malformed-framing cases, remain unrun unless separately
recorded. Previous signed/host/migration results remain in the
[validation index](VALIDATION.md), pinned to their original sources. The
existing protected-main workflow independently requires only eight baseline
protocol tests on each of three platforms; its authoritative result is the
GitHub run linked from the release/PR, not this local report.

## Retained raw evidence

The first protected-main [CI run](https://github.com/qh-work/memory-vault-sync/actions/runs/33374465799)
passed seven of eight baseline methods on each platform and failed the same
bundle-transfer assertion: it required the selected recall fragment to include
the assistant-side `NDJSON bundle` text. The documented v0.25 recall contract
returns the best matching original-text fragment, which can be the user side.
The fixture now compares source and received canonical records through `get`,
checks the assistant text in that complete record, and checks that recall still
points to the same record with an actual original-text substring. It does not
relax quarantine, transfer or content-preservation checks, or change application
code. The subsequent required CI result is recorded on the PR/release.

The local `memory-vault-v025-release-minimal.p9SY7k` evidence directory retains
both runners, both output logs and both JSON reports. Reports include the exact
method names and source-file SHA-256 map. Raw reports contain machine-local
paths and are not bundled into public packages.

| Evidence file | SHA-256 |
| --- | --- |
| `run_minimal.py` | `cd2e341286605da002cd00064a6db479eaa803f3a5356d58ed21e80f09703f2c` |
| `result.json` | `0f754dfcb2f68737b3b0eb68ea3d144d739cc60aa5107d27f7d80e7e69430006` |
| `output.log` | `04c5b1578f2ad6daef488bbcf4284cf2b5028f3a4a461d9716749e8c7bcf4adc` |
| `run_recovery.py` | `892081efab87370575921628f38ceebb600948ddd79f73720fd68e739785a241` |
| `recovery-result.json` | `4c9cb668ae233ab85ade8e7496f3270e6327572c72ca56948e5e21814508ca49` |
| `recovery-output.log` | `6cb550bf9e7820b820c384c560c414c3c1090628c816e731e6f6a29fbd2c32bb` |
