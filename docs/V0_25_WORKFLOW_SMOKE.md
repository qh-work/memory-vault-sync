# Full-client workflow acceptance, with the failed update attempt retained

Status: **four selected workflows passed on the first source; the fifth passed
after a runtime repair and a one-method rerun.** This is not a five-test pass on
one newer source, a complete v0.25 acceptance result, or a public release. The
[full parity ledger](V0_25_PARITY_PLAN.md) remains open.

## Exact source and execution

| Item | Initial workflow campaign | Update-only repair verification |
| --- | --- | --- |
| Source | `c65fd82f863e4e05d9ec53622eceb584525fb52e` | `0be4c6dbf6d7d3eb477ed807e15c3659f38776c8` |
| Archived source | 160 files, no overlay; 66 Python files parsed | 160 files, no overlay; 66 Python files parsed |
| Inventory SHA-256 | `50384987e404e082d115fbbe3789ecfd942556e4426cb20cb71c950b0e27a017` | `b77b06119ba8a654ef8e01e09c2b6f69e6b7261da1c3494559c295f32b060849` |
| Started, UTC | `2026-08-31T01:03:14.479991+00:00` | `2026-08-31T01:05:15.947276+00:00` |
| Result | 5 run: 4 passes, 0 failures, 1 error, 0 skips | 1 run: 1 pass, 0 failures/errors/skips |
| Fixture duration | 1.141553 seconds | 0.576647 seconds |

Both used Python 3.12.13, SQLite 3.53.1, Darwin 27.0.0, arm64. Durations are
fixture observations, not performance benchmarks. No whole-file/suite discovery
ran. The second source changed only `memory_vault_update.py` and its update
documentation; the first four methods were not rerun. Later documentation does
not rename the tested sources or turn their results into a combined current-suite
pass.

The initial fifth method failed during real `stage()` extraction with
`client_directory_not_private`. The old directory helper created only a leaf
with mode 0700; missing intermediate directories inherited ordinary modes.
Later archive members then hit those non-private parents. This was a runtime
defect, not a fixture/assertion error. The fix uses the existing protected
directory creator for **every missing segment**, preserving pre-existing modes
and rejecting non-private leaf directories. The same unchanged update method
then passed in a fresh source archive and temporary workspace.

## What the selected workflows established

- **Eleven MCP tools:** actual embedded JSON-RPC initialization/discovery,
  observe/remember retries and conflicts, a fresh caller using the same Vault,
  exact canonical reads, recall/handoff, six-node graph, claim conflict and
  resolution, two-page timeline, non-executing proposals, changes, and explicit
  repair of a deliberately removed derived-index row. Repair leaves canonical
  bytes and the delivery page unchanged. No client feature result is mocked.
- **Ten old host operations:** actual closed v0.21 envelopes, durable pending
  acknowledgments, exact retry versus changed-byte conflict, abort/close behavior,
  flush recovery, public recall evidence mappings, evidence-backed semantic
  writes and typed supersession. Closing a session keeps its memory. Injected
  save/read exceptions exercise both control and canonical recovery routing;
  disabled capture and ordinary read paths do not acquire recovery permission.
- **Signed directory sync:** two fresh Ed25519 identities and independent trust
  files; actual signature verification, incoming admission while outgoing data
  needs review, content-free read-only review, explicit keep/exclude, signed
  non-delivery dispositions, original-evidence retention, exact resolve/requeue
  retries, a fresh path-specific approval and receiver-side forwarding checks.
  A real first admission remains counted when the next read injects a budget
  error; a later window receives only the remaining batch. Neither signatures
  nor privacy/admission results are mocked. A sender's approval never becomes
  another receiver's publication permission.
- **Publication guard:** 42 synthetic token/path vectors exercise restored old
  families and newer checks, including original versus NFC text. Local canonical
  records remain byte-identical; recognized secrets have no path-override bypass.
  Unknown secrets/personal data remain outside this best-effort detector. The
  old host envelope retains its separate historical input/output restrictions;
  ordinary core/MCP local persistence does not inherit them.
- **Controlled update, after repair:** independently pinned public test root,
  actual RSA-PSS metadata verification and signed stage, inert managed install,
  bad signer/digest rejection, one caught partial-file write, exact activation
  retry and explicitly approved rollback. Trust floors do not roll back with
  retained runtime code; an old historical receipt is not new publisher trust.

The bidirectional-window and progress-reporting fixes are v0.25 usability
improvements, not claims that v0.21 already handled those failures. Old privacy
families are restored as detection, not as Task routing or execution authority.
The MCP description now explains how to remove the core `op` field when reusing
a returned view-page request; the core wire format is unchanged.

## Exact selected methods and substitutions

Only these methods ran; imported fixture helpers do not mean their other test
methods ran. Source/review archives contain the executable fixtures; the
protocol-only archive intentionally contains none.

| Fixture under `tests/` | Class and method | Result / substituted boundary |
| --- | --- | --- |
| [test_v025_mcp_workflow.py](../tests/test_v025_mcp_workflow.py) | `MCPWorkflowTests.test_eleven_tools_share_history_and_recover_only_disposable_indexes` | Initial pass; no feature mocks; embedded calls, not a stdio/live-host session |
| [test_v025_compat_workflow.py](../tests/test_v025_compat_workflow.py) | `HostProtocolWorkflowTests.test_all_ten_operations_preserve_evidence_and_exact_retry` | Initial pass; injected first-save and read errors, exact-path and no-network/worker guards; not an actual hot journal |
| [test_v025_sync_review.py](../tests/test_v025_sync_review.py) | `SyncReviewTests.test_signed_sync_review_requeue_and_receive_remain_independent` | Initial pass; private-key-load prohibition during review, then a next-read error after actual admission; not a real timeout |
| [test_v025_privacy_parity.py](../tests/test_v025_privacy_parity.py) | `PrivacyParityTests.test_old_guard_families_block_publication_without_rewriting_local_memory` | Initial pass; fake values only, not real credentials or a DLP benchmark |
| [test_v025_update_lifecycle.py](../tests/test_v025_update_lifecycle.py) | `ControlledUpdateLifecycleTests.test_pinned_signed_stage_install_partial_write_retry_and_explicit_rollback` | Initial error; repair-only pass. Explicit download-byte map, fixed test clock, no-subprocess guard and one partial-write EIO; real verifier/stage/install/rollback functions |

Update helper imports use the existing inert package builder in
`test_v025_install.py` and fixed public test-RSA integers in
`test_v025_update_trust.py`. No OpenSSL cross-check or other method from either
module ran. Configuring automatic-update eligibility in the temporary managed
fixture starts no worker; rollback disables it. No package code executes.

## Isolation and retained evidence

Each run used a fresh exact Git archive with inventory checks before and after.
An OS sandbox denied network and file contents outside that workspace plus the
selected runtime/system libraries. IPv4/IPv6 bind and UDP-connect probes and an
outside **synthetic** file verified denial without sending packets. An audit
guard prohibited child processes and subsequent network attempts. Cleared
environment, explicit paths and untouched default-Vault/config sentinels kept
the fixtures independent of user installations. Both runs used a 90-second
deadline plus five-second cleanup grace; neither limit was reached.

All disposable fixture data, including generated test identities, was cleaned.
Source archives and raw reports remain separately retained:

- Initial: `/private/tmp/memory-vault-v025-workflows.y2dLBM`
- Repair: `/private/tmp/memory-vault-v025-update-verified.o1JM6X`

| Raw evidence | Initial SHA-256 | Repair SHA-256 |
| --- | --- | --- |
| `report.json` | `2d0388c097c97ce0c096cb465f60c590e15520ebd785497e981613ef1a4bbd3b` | `4401f8013ee23df0455cece52ebe54e8aa02bae8575a9b94de97ac87c943aff0` |
| `run.log` | `986d0362c772b6c476e15cd59e181850d9f5f810ff360c5aeeb1519cf372a04a` | `e6028df82aa258a529951deeba8cef2d0d5d8d06bbfa7f77287d54c07c1a4369` |
| `run_scoped.py` | `2e858819cb9e7632922167978fb96db0250209489c652f5e351df95da80f880b` | `45dc35b8a018226776b9af0d4e0ec667d7bbcf5cef737c20117754427b913b9f` |
| `cases.json` | `8d488ba23638e56e8ac43cff6745559547d21321cfc397925c05eaa23a0e3d9a` | `3bc2a5a88fd3a13549648f8ffaf2b32303d190b68f92b1f0fba25995ceb46489` |
| `offline.sb` | `b27f9b506682b390576eff353c35bc2f32959162e3c1eb80715a8bd7d0d85b2b` | `e6b32389f6f3c4bdaedc90a9cab72f9f160506358db8f4dfff22abf4bf8083ca` |

Both inventory scripts have SHA-256
`21cd292c6eeac468a8021a0d9fb7bbab392188eae0fc27371f80ddab99a739ce`.
No real/private Vault, installed plugin, account, production signing key,
provider, host setting, GitHub state, branch protection or published tag changed.

## Still outside this evidence

This does not certify full P01–P14 parity, native Windows/Linux behavior, an
actual host integration, an independent model/implementation, production
publisher ceremony, cloud/rclone transport, large fragment groups, all
concurrent/crash paths, power loss or scale/latency. The update interruption is
a caught exception; unknown temporary files after a hard kill still cause a
visible refusal instead of automatic cleanup. The compatibility exceptions
exercise recovery routing, not physical journal corruption/recovery. Current
trust, authorization and explicit release approval remain independent of all
memory and test results.
