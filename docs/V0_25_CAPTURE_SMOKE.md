# Frozen capture and incremental-dependency evidence

Status: **12 selected offline synthetic methods passed; full v0.25 acceptance
remains open.** This is not an installation, independent interoperability,
throughput or production-release claim. See the [validation index](VALIDATION.md)
and [complete v0.21 parity ledger](V0_25_PARITY_PLAN.md).

## Exact source and result

| Item | Recorded value |
| --- | --- |
| Implementation source | `098b22c44ca299d1f889b41df9355511dfa2caf4` |
| Passing source, including corrected fixtures | `6eeb35ac2df8f0813d87ff6e6a0f3fbbf1c2f917` |
| Passing source inventory | 149 archived files; no source overlay |
| Inventory SHA-256 | `d799439e15ff2e691ad6cb2752b40be361671a1a6107a1ad7180a02f16015260` |
| Started, UTC | `2026-08-30T18:50:13.220204+00:00` |
| Result | 12 run, 0 failures, 0 errors, 0 skips |
| Fixture duration | 0.902055 seconds; not a performance measurement |
| Environment | Python 3.12.13, SQLite 3.53.1, Darwin 27.0.0, arm64 |

Both runs used fresh copies of exact local Git archives, not a mutable working
directory or a downloaded release. The passing commit changes only the two
test files described below; it does not change the runtime to satisfy a test.
Source hashes were checked before and after each run. Later documentation or
package inventory changes do not rename this tested source.

A separate static delivery check parsed 57 Python files and 27 JSON files. The
builder, plugin launcher and managed updater declare the same 28 runtime modules,
including the new capture and dependency helpers. All 28 runtime files and the
four selected fixture modules remained byte-identical to the passing source.
These syntax/inventory checks did not import the application or execute tests.

## Executed methods

In [test_v025_capture_hooks.py](../tests/test_v025_capture_hooks.py), class
`FrozenHookCaptureTests`:

```text
test_each_source_freezes_its_predecessor_and_exact_retry_never_rebuilds
test_done_before_journal_ack_restores_and_retries_without_raw_source
test_legacy_partial_outbox_keeps_original_receipts_and_has_no_new_head
test_bounded_ancestor_progress_notifies_without_claiming_target_saved
test_authorized_retry_recovers_hot_journal_before_bounded_discovery
```

In [test_v025_capture_lifecycle.py](../tests/test_v025_capture_lifecycle.py),
class `FrozenLifecycleCaptureTests`:

```text
test_bounded_ancestor_drain_keeps_original_outer_receipts_pending
test_legacy_partial_episode_keeps_original_id_and_receipt_after_migration
```

In [test_v025_capture_compat.py](../tests/test_v025_capture_compat.py), class
`CompatibilityCaptureTests`:

```text
test_backwards_clock_flushes_accepted_dependency_before_child_with_limit_one
```

In [test_v025_incremental_dependencies.py](../tests/test_v025_incremental_dependencies.py),
class `IncrementalDependencyTests`:

```text
test_continues_pages_reuse_verified_prefix_and_cold_receiver_replays_all
test_copied_head_without_same_vault_atomic_receipt_cannot_admit_v3
test_older_sql_writer_quarantine_invalidates_the_grandparent_certificate
test_revoked_grandparent_is_rechecked_despite_trusted_parent_and_envelope
```

The four new fixture modules contain 39 methods; only these 12 were selected.
The other 27 were not run in this campaign. There was no whole-module or
whole-suite discovery, and older campaigns are not added to this run's count.

## What these cases establish

- Separate hook sources do not select the globally latest memory as their
  predecessor. An accepted pending projection retains its time, record hashes
  and `continues` edge on exact retry. Session/scope handles do not enter the
  canonical record as owners.
- An unsigned two-turn hook chain survives backup, inert restore, explicit
  activation and retry after its done file is durable but journal acknowledgement
  is not. Raw staging text is not reconstructed from an episode or another turn.
  The original store/control state remains unchanged.
- The selected old hook and v1 lifecycle partial-write fixtures keep their
  original episode IDs and receipts; upgrading does not invent historical edges.
- Bounded hook progress can notify the independently configured sync layer
  while the requested later turn remains pending. The notification assertion
  uses a mock; it does not launch or verify a background worker.
- Seven accepted lifecycle turns complete in bounded groups without inventing
  an earlier caller's outer acknowledgement. The compatibility queue follows
  accepted dependency order even when its synthetic clock moves backward.
- A real child process modifies one temporary SQLite journal and exits with
  code 73 before commit. A read-only reopen cannot recover that hot journal;
  the authorized bounded retry does recover it and preserves the frozen plan.
  This is a controlled process exit, not power loss or a real host crash.
- Thirty-two small signed records travel in four pages: the first v2 page is
  self-contained; subsequent v3 pages contain eight records each, not their
  entire earlier chain. A fresh receiving Vault replays all pages from zero;
  the ordinary public `changes` operation still includes complete dependencies.
  A requeued root is not erased by the published-member optimization.
- A copied receive head with real baseline records but no same-Vault atomic
  receipt cannot authorize v3 admission. A quarantined or independently revoked
  grandparent blocks a new child even when its immediate parent and envelope
  remain trusted.

These are small functional assertions, not proof that arbitrarily long chains
have bounded first-use cost. Cache loss or trust/epoch invalidation can require
full dependency revalidation; excessive work returns an explicit retryable
`dependency_revalidation_required` rather than advancing past unfinished data.

## First attempt retained, not reported as passing

The same 12-method selection first ran on
`098b22c44ca299d1f889b41df9355511dfa2caf4`, at
`2026-08-30T18:48:35.627269+00:00`, taking 2.740913 seconds. It produced **6
passes, 1 failure and 5 errors**, with no skips. Its 149-file inventory hash is
`846bf4ce1f25e007161ea01378742c2a5d52a527bd6869cc47407f81644061f1`.

Five hook tests incorrectly read counters from the outer response instead of
the documented `result` object. The copied-head fixture created its private
state parent indirectly, so the ordinary protection check rejected that parent
before reaching the missing-receipt check. The correction unwraps the response
after asserting success and explicitly creates the fixture's protected local
directory. It does not weaken production permissions, bypass receipt checks or
discard assertions. The original log/report and archive are retained separately.

## Isolation and raw artifacts

An OS sandbox denied network access and file contents outside the fresh
temporary campaign plus the selected runtime/system libraries. IPv4/IPv6 bind
and UDP-connect denial probes sent no packets; an outside synthetic control file
also proved that unrelated reads and writes were denied. No private user file
was used as a probe. Explicit fixture paths were used; neither default Vault nor
default client configuration was selected.

A parent audit hook admitted exactly one declared child command for the hot
journal fixture, with a ten-second child timeout. That child inherited the OS
sandbox. Other process creation was denied. The campaign had a 90-second
deadline and five-second cleanup grace; neither timeout fired. Temporary fixture
data and fresh synthetic Ed25519 keys were cleaned after the run. Real keys,
providers, accounts, installed plugins and private memories were not accessed.

Raw artifacts remain local; these are their content hashes, not publisher
signatures or claims that the artifacts were uploaded:

| Artifact | SHA-256 |
| --- | --- |
| Passing `report.json` | `b5b440a27ce312deea2135b7b6f934dbec26d5e90d861ecb2d1668d0f89c723d` |
| Passing `run.log` | `822a2e25372b172e1b75182bdafeaf8e24780b179c8c1f08423c76036a39d833` |
| `run_scoped.py` | `9a9e222ff4fff4c40436e9c30a74d7b5b7a20437303284bbe89e634826e3360e` |
| Passing `offline.sb` | `4032dfadc23c8c0e18c8ef9a5c4ade91f25742ee57fd9a7549a40be6e26f7435` |
| Passing `campaign.json` | `b8f65a56d007336886f4dc458d4b684206ff17bb01ef64050b5e03200b265b19` |
| `pin_source.py` | `c4cf7894b1d7936dcedba3bc537b5fb4d7f405d06b353a8c2f221590011f4404` |
| Static `static-delivery.json` | `0daa0de4bce66b621b6fe4e91f62a6c262e153175b77f1ed4d05f8ba400d424e` |
| Static `audit_delivery.py` | `50fe27bf2ca565e440b6eab86a9a87373e9b4b8def08dbd3cc1d4e990dc929bb` |
| Earlier failing `report.json` | `38559c91abbf3d632e4937236165d686954f53353afc9f8804b97a15c93ec6ea` |
| Earlier failing `run.log` | `b30ca06cb10097c69e40087d9d4ab51747715506791d0ddc385732a577b63312` |

## Still outside this evidence

Native host delivery, real client installation, Windows/Linux execution,
independent protocol implementations, cross-device/model use, remote providers,
large fragment groups, workload benchmarks and power-loss recovery were not
exercised. Neither source code nor these results prove adoption by another AI.
The remaining capture, stream, graph, conversion, update and provider cases
remain explicitly unrun unless another source-pinned report records them.
The full P01–P14 ledger is unchanged; no main branch, release tag, public asset,
private installation or external account was changed by this campaign.
