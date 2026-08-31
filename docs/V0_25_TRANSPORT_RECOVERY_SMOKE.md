# Fragmented transport, signed recovery, sharing and old-format continuation

Status: **three selected workflows passed on one source, and one old-format
workflow passed separately on the next source.** This is not a combined
four-method pass on the newer source, full P01–P14 acceptance, a native-host
certification or a public release. The [full parity ledger](V0_25_PARITY_PLAN.md)
remains the scope.

## Exact execution

| Item | Transport / recovery / sharing | Old-format continuation |
| --- | --- | --- |
| Source | `fc3588556b976665c547ab3fc26c8f26f54bbb20` | `76b8c8bfaed5b4d73d0ffd647dc8cd6286ba0fa7` |
| Archived files, no overlay | 164 | 165 |
| Python files statically parsed | 69 | 70 |
| Inventory SHA-256 | `57a2bac193358e50cec6d5d944a324944ee8ec38a10d5dc62d19c725b776bb3f` | `0d88970605f8a6de6bcfb83903e7b6fa495ff7f78788ecf2935cffb5f0950ce4` |
| Started, UTC | `2026-08-31T01:32:24.116758+00:00` | `2026-08-31T01:34:17.549099+00:00` |
| Result | 3 run, 3 passes; no failures/errors/skips | 1 run, 1 pass; no failures/errors/skips |
| Fixture duration | 7.347418 seconds | 0.143193 seconds |

Both used Python 3.12.13, SQLite 3.53.1, Darwin 27.0.0, arm64. Durations describe
these small fixtures, not latency/throughput benchmarks. The second commit
added only the old-format fixture; the first three methods were not rerun.
No whole-file or whole-suite discovery ran. Later documentation does not
rename either tested source.

## Actual repairs and their boundaries

The remote receive path now reports durable Vault admission before a separate
stream-head write can fail. The sync wrapper counts this per-capsule report
exactly once, retains the pending generation, and does not mislabel a local
post-admission failure as an offline peer. It also rechecks current operation
configuration/cancellation and the shared budget after fragment staging, before
admitting memory. A cancelled group may remain as verified staging evidence,
not as canonical memory or automatic permission to resume.

Verified share retry now validates the entire incoming share and all signatures
before changing admission. After a historical receipt, it checks unchanged
canonical bytes and can restore current admission from the freshly verified
input if another independently configured client replaced the stored proof.
It does not rewrite the old receipt, change trust or sign the record again.
Default/quarantine and unsigned historical retries cannot restore admission.
Unknown/revoked-key and invalid-signature errors retain their specific,
non-retryable trust code. The store still holds one current proof per record;
this is not a new multi-attester model.

No runtime change was needed for the selected signed recovery or complete
old-format conversion paths. Their new fixtures establish actual selected
workflows, not a claim that their entire modules have passed. The small
`memory_vault_migrate.py` compatibility profile remains distinct from the
complete `legacy-pack` route and retains its documented limitations/ID domain.

## Exact selected methods

Executable fixtures are in the source/review kit, not the protocol-only ZIP.

| Fixture under `tests/` | Exact class and method | Observed scope |
| --- | --- | --- |
| [test_v025_fragmented_remote_workflow.py](../tests/test_v025_fragmented_remote_workflow.py) | `FragmentedRemoteWorkflowTests.test_exact_group_resume_cancellation_and_durable_receive_reporting` | Six actually signed records, about 5 MiB of text and the real default 4 MiB splitter producing two fragments; interrupted upload/read, staged cancellation, post-admission head failure and exact receipt retry |
| [test_v025_signed_recovery_workflow.py](../tests/test_v025_signed_recovery_workflow.py) | `SignedRecoveryWorkflowTests.test_staged_signed_group_survives_inert_restore_and_current_trust_import` | A signed seed plus a two-record/two-fragment tiny v3 group; real staging, cancellation, operator backup/restore/review/import, fresh store identity, retry and current revocation |
| [test_v025_sharing_workflow.py](../tests/test_v025_sharing_workflow.py) | `SignedSharingWorkflowTests.test_selection_quarantine_independent_trust_replay_and_revocation` | Two selected dependency-complete records from three, actual signatures, quarantine, independent enrollment, verified import/forward, alternative attester, current admission restoration and revocation |
| [test_v025_legacy_workflow.py](../tests/test_v025_legacy_workflow.py) | `LegacyWorkflowTests.test_checkpoint_chain_conversion_preserves_claims_and_reusable_old_ids` | Two different old packs and a hash-checkpoint chain, repack/convert/extract, eight old-ID mappings, exact raw evidence, typed relations/claim timeline, explicit unsigned admission and continued old-ID semantic writes |

### What was real, and what was substituted

- **Fragmented remote:** the actual rclone adapter constructor checked the
  explicitly selected inert executable hash and synthetic configuration. Its
  exact member-path, budget reservation, listing parser, size/hash/read-back
  logic, signing and admission ran. Only `RcloneBackend._run` was replaced by
  exact in-memory byte carriage. No real rclone process or cloud provider ran;
  per-command executable/config checks inside `_run`, its environment,
  process timeout, termination and actual network behavior were not exercised.
  The second fragment copy/read errors and the later head-file rejection were
  injected. Config disable after the final simulated read used the real
  pre-admission active check. Resumption reused the completed first fragment
  and admitted the complete group once; receipt replay added no duplicate memory.
- **Signed recovery:** one fresh key and three records. The tiny two-fragment
  fixture was independently assembled, not emitted by the large splitter.
  Real `manage.main` dispatch wrote through a real captured `stdout.buffer`.
  Snapshot/restore preserved the signed seed but assigned a new store ID and
  did not restore old transfer receipts, queues as active state, keys or sync
  permission. The staged v3 group referenced that seed and crossed a fragment
  boundary. Explicit import verified current trust; a historical import receipt
  did not bypass subsequent revocation. Only pre-admission cancellation and
  negative private-key-load/sync guards were substituted.
- **Sharing:** two fresh keys and independently selected trust files. An
  alternative packet used the same canonical records, real signatures from the
  second key and a recomputed framing checksum. This was not a mocked success
  or proof of original authorship. Verified retry restored the first client's
  current admission without rewriting canonical records, old receipts or trust.
  A further retry did not add delivery work. Revocation hid records from recall
  and forwarding while retaining inspectable quarantined evidence; default and
  unsigned historical retries did not revive them. Only negative
  private-key-load/notification guards were mocked.
- **Old formats:** a separate encoder constructed the inspected v0.21
  pack/index/footer and integer-only, ASCII-key checksum domain. It did not run
  the old runtime or use a real export. Actual checkpoint validation rejected a
  mismatched pack and reverse chain. Conversion preserved original bytes,
  claim grouping and `continues`, `derived_from`, `supersedes`,
  `conflicts_with` and `resolves` edges. Old ep/event IDs remained usable for
  a new evidence-backed semantic write; alias registration granted no trust.
  Path/notification/network/process guards and the scratch-root selection were
  the only substitutions. Checkpoint hashes are not signatures.

## Isolation and raw evidence

Each run used a fresh exact Git archive, before/after inventory checks and an
OS sandbox denying network and file contents outside that workspace plus the
selected runtime/system libraries. IPv4/IPv6 bind and UDP-connect denial and an
outside synthetic read/write denial were checked without sending packets.
An audit guard prohibited subsequent network and child-process attempts;
neither occurred. Default Vault/config sentinels stayed unused. A 90-second
deadline plus five-second cleanup grace was not reached.

Disposable fixture data was cleaned, including four fresh test identities
across the first three methods. The last method generated no keys. Source
archives and raw results are separately retained at:

- Transport / recovery / sharing: `/private/tmp/memory-vault-v025-transport-recovery.9PVCsy`
- Old formats: `/private/tmp/memory-vault-v025-legacy-workflow.2GUpKE`

| Raw evidence | Transport / recovery / sharing SHA-256 | Old-format SHA-256 |
| --- | --- | --- |
| `report.json` | `012bcee56ed7397e0d62b9c8ab8bee53aa5a102e6efef3b7b891c76c9e94075e` | `68f1bc03ce0ffed4888eeba77e9329301cb4f408c895e73bbd6ea29fc7fea483` |
| `run.log` | `47cc134052e533c5e3b29aa57add825cf9ce117a51cecd33e1e94ace3abf62bc` | `6c113c394a04a061f76c0a85315e156ee0cc475e9ca0f25b5354d33e189d4679` |
| `run_scoped.py` | `1721fa471a84dacd1fd80f310e046ed35a6d6f5383389526dc0a4692463929e8` | `ff5cbc1c57c8c9d14c3e7b3beef23a60c13997a6940f645a296fb69faa229a0c` |
| `cases.json` | `7b0bdc31bc4875392636fcf9442dcf752d5d7a98306aef2a272d6bf108cdff7e` | `d0e4d03660761ac5b3824697995d215c4efcaadf12114728701ba9b9bc27191e` |
| `offline.sb` | `b6bb4b88fe529b4c388078cc6003853dfb03b28253206214c01e6c8c2b52373b` | `07644011ffe84a86fb0076df5d1f771df68e55fd8ebea5cc3459a826af3ffe88` |

Both inventory scripts have SHA-256
`21cd292c6eeac468a8021a0d9fb7bbab392188eae0fc27371f80ddab99a739ce`.
No real/private Vault, installed plugin, host setting, real key, account,
provider, remote branch, protected main, tag or public release was changed.

## Still not established

These fixtures do not prove full parity, an independent model/implementation,
actual cloud or second-device delivery, native Windows/Linux behavior, 2 GiB or
near-limit operation, production encryption/recovery/publisher ceremonies,
complete crash/concurrency coverage or measured performance. Simulated errors
and explicit cancellation are not process kills or power loss. No authorization
comes from a fixture, receipt, remembered goal or this report.

