# Scoped publication and recovery evidence

On **2026-08-31 (Asia/Shanghai)**, exactly seven selected synthetic cases passed
on source **`332e944a6bda8f70dd3af6526d926d9468ed2f0d`**: **0 failures, 0 errors,
0 skips**. A separate one-case diagnostic against pre-fix source
`f1354862dc0f53ff039e8c087d18c03759d2fbf1` reproduced the expected hard-link
publication failure. That diagnostic is a recorded failure, not an eighth pass.

This is narrow development evidence under the owner's minimal offline,
temporary-directory authorization. It does not complete [P01–P14](V0_25_PARITY_PLAN.md),
publish v0.25, install a client or establish real-host/cross-device acceptance.
The earlier [initial](V0_25_SCOPED_SMOKE.md) and
[retrieval/retry](V0_25_FOLLOWUP_SMOKE.md) campaigns keep their own source pins;
their cases must not be added to these seven as a passing current-source suite.

## Source and environment

| Item | Recorded value |
| --- | --- |
| Current source | `332e944a6bda8f70dd3af6526d926d9468ed2f0d`; clean local source commit, no overlay |
| Current inventory | 141 files copied by `git archive`; SHA-256 `1bf226dc2e87f6c210280f819776a9c671050d97219216202ce600f0d3cff993` |
| Pre-fix runtime | `f1354862dc0f53ff039e8c087d18c03759d2fbf1`, with only the new publication-test file overlaid |
| Pre-fix inventory | 139 files including that overlay; SHA-256 `a64de351851c4f1a5b15ad2c92a8d579aa088e52714419c3cfcbfbae9f407b78` |
| Test overlay | `tests/test_v025_publication_recovery.py`; SHA-256 `1bdbdd4c64f59d78c8e8cbaeed617422bc8d53739752df596af0af4879dda87e` |
| Runtime | Python 3.12.13, SQLite 3.53.1, Darwin 27.0.0 arm64 |
| Current run start / elapsed | `2026-08-30T18:09:03.539672+00:00` / 0.393645 seconds |
| Pre-fix diagnostic start / elapsed | `2026-08-30T18:08:56.893012+00:00` / 0.234015 seconds |

Elapsed time describes these small local cases only; it is not a throughput,
latency or scale benchmark. No native Windows/Linux execution occurred. Source
inventories were checked before and after each run, including absence of extra
files. The snapshots, raw logs and reports remain separate from older release
archives; no old manifest was relabeled or overwritten.

## Exact current-source selection

No full-suite discovery or full-file collection was used; only the named
methods were loaded into the selected suite. These method names are relative
to `tests/`:

```text
test_v025_publication_recovery.PublicationRecoveryTests.test_client_publication_survives_process_exit_without_hard_link_alias
test_v025_publication_recovery.PublicationRecoveryTests.test_no_clobber_concurrency_exact_retry_and_alias_checks_remain
test_v025_publication_recovery.PublicationRecoveryTests.test_unsupported_native_rename_has_no_unsafe_publication_fallback
test_v025_host_recovery.HostCancellationRecoveryTests.test_durable_abort_receipt_finishes_interrupted_cleanup_with_capture_disabled
test_v025_host_recovery.HostCancellationRecoveryTests.test_phase_and_copied_host_receipt_cannot_authorize_cancellation
test_v025_host_recovery.HostCancellationRecoveryTests.test_cancelled_prefix_is_cleaned_in_bounded_batches_before_a_later_final
test_v025_client_recovery.ClientRecoveryTests.test_explicit_local_activation_then_retry_preserves_no_network_boundary
```

| Selected behavior | What actually ran / limitation |
| --- | --- |
| Interrupted private-file publication | One new Python child called `os._exit(73)` after the real directory fsync and before normal cleanup. The current client published a single-link file, read it and exactly retried without changing bytes. This is a controlled process exit, not power loss |
| No-clobber and aliases | Two fixture threads competed at the exclusive-rename boundary; one publication and one existing-file result occurred. Exact retry, changed-payload conflict, explicit replacement and rejection of synthetic hard/symbolic links were checked |
| Unsupported native publication | The native helper was mocked to refuse; no hard-link or overwrite fallback occurred. This does not exercise each kernel/filesystem errno or missing-symbol path |
| Confirmed cancellation after cleanup interruption | A real lifecycle abort receipt was created; an injected exception interrupted host cleanup. Capture-disabled `manage.retry_host` cleared the exact cancelled job without invoking a lifecycle mutation, creating a Vault or allowing background sync |
| No authority from copied state | A local aborted phase and a fabricated host receipt could not authorize cleanup. Pending bytes and lifecycle bytes remained unchanged |
| Bounded cancelled-prefix progress | Two exact synthetic cancelled pending artifacts were retained/restored, then cleared in a two-job batch. A later final stayed pending with capture disabled and saved once after explicit re-enabling. A read-only lookup error was injected; no real hot-journal crash was performed |
| Actual unsigned full-client recovery | The real backup, restore, explicit activation and hook retry implementations ran on synthetic data. One baseline memory became three after the pending episode/continuity pair was saved; an exact repeat did no work. Original evidence remained, and the new configuration had no sync path. Other recovery components and signed/provider paths were not exercised |

The last case is more than the earlier mocked restore-routing check, but it is
still only one unsigned `hooks` workflow. The operator was not tested against a
lost real installation, live writers, real key material or cross-device state.

## Pre-fix diagnostic, kept separate

Only the first method above ran against the pre-fix source plus the pinned test
overlay. The child reached the same exit code and publication boundary, then
the parent observed:

```text
AssertionError: 2 != 1 : interrupted publication left a hard-link alias
Ran 1 test
FAILED (failures=1)
```

There were no errors or skips. The diagnostic runner required that exact
failure, rather than accepting any import, permission or child-start failure.
Its report preserves `successful: false` and separately records the diagnostic
outcome as expected. This supplies direct evidence for the specific link/unlink
window; it is not a comparison with every v0.21 behavior.

## Isolation and remaining limits

- Fresh public source copies and explicit independent temporary fixture paths
  were used. No private Vault, transcript, key, account, existing plugin or host
  configuration was selected. No application was stopped or installed.
- An operating-system sandbox denied networking and file contents outside the
  selected temporary root plus the runtime/system library allowlist. IPv4/IPv6
  loopback bind/UDP-connect denials and external **synthetic** read/write denials
  were checked before application imports. These probes sent no packets.
- Each run allowed one exact fixture-child command, source, working directory
  and environment through a parent Python audit hook; no other process attempt
  occurred. The child inherited the OS sandbox, not that Python hook. The OS
  profile did not itself enforce a one-child process-count limit.
- The child call had a 10-second timeout. The runner configured a 90-second
  deadline, exception-based child cleanup and a 5-second hard-exit grace. No
  timeout fired; the deadline cleanup path was reviewed, not fault-tested or
  certified as a hard real-time guarantee.
- Inherited account/proxy/client variables were cleared without repurposing
  `HOME` or `CODEX_HOME`. Default Vault/config sentinels were not created. Both
  disposable data directories were empty after their fixtures cleaned up.
- There was no cryptographic, publisher, provider, real-host, cross-model,
  cross-device, native Windows/Linux, large-data or full-suite acceptance.
  Generic unsigned calls do not identify an AI model or prove adoption.
- The publication repair covers the shared storage helper and client private
  state. Other independent hard-link publishers remain; old aliased files are
  not automatically trusted or repaired. See [PLATFORMS.md](PLATFORMS.md).
- Automatic cross-turn continuity is still an implementation gap, including
  stable predecessor projection and efficient incremental dependencies. A
  successful single-turn recovery does not close that requirement.

## Raw evidence hashes

Raw evidence is retained in the local `memory-vault-v025-recovery.jah81FMW`
temporary evidence directory. The following hashes identify those exact files;
this document does not embed machine-local runtime paths or private state.

After execution, the 26 runtime modules and all three selected test files were
byte-compared with the pinned snapshot and remained unchanged. The follow-up
documentation/package-list edits received syntax and local-link checks only:
51 Python ASTs, 26 strict JSON files, 95 local links and three heading anchors.
Those checks did not import the application, rerun tests or build a new package.

| Evidence file | SHA-256 |
| --- | --- |
| `current-report.json` | `42e3f0ebb539e8516c424ee7e3d0b328f68dd2b5e6a8a42c5b6d9aac86046138` |
| `current.log` | `053e51f2dd98cd772710043071d4c0efed223a9c674011a61462623cbc6986a2` |
| `baseline-report.json` | `1e36fb99ea4f5ba52a92179612c2cadd9e9d2af55d6edc56abab1a0e3072f439` |
| `baseline.log` | `74ecda7621fcbf28b51e96a824414f73728b15cae6bdbe049d419c0f59de4684` |
| `run_recovery.py` | `e343059c614f61440271da8f8120fffd588b983184a8c9ce36abfa2ef64c3b5e` |
| `offline.sb` | `68d2a3d19f9d9c18acbabf1cb46e68cb7f0f525f3d208488f79094c314b3bc15` |
| `campaigns.json` | `7650a487c353247b33ba833b752101b32f0e3f1cebb7a2d8975099c4ce359361` |
| `pin_sources.py` | `7d5e3c6a6caf09bc8b66a6bdbfbff8e56f4693e21abc4cc00abf3e8982b5594f` |

See [the validation index](VALIDATION.md) for all separately pinned campaigns
and [the review handoff](REVIEW_HANDOFF.md) for reviewer-owned authorization and
remaining acceptance work. These local results do not assert current GitHub
publication status or change protected main or published tags.
