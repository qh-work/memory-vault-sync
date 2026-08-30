# v0.25 scoped offline smoke evidence

**Result: 12 selected synthetic cases passed, 0 failures, 0 errors, 0 skips.**
This is a narrow executed result, not full v0.21 parity acceptance or a stable
v0.25 release. The [P01–P14 ledger](V0_25_PARITY_PLAN.md) remains open.

## Exact source and environment

- Tested source: `066cd5629e690e6b38ab9c0bf43badafe4ef7a1b`.
- Input: a copied public `memory-vault-review-v0.25.0` snapshot; all 121
  inventoried files were hash-checked before and after the run. No application
  or test assertions were changed to obtain this result.
- Review manifest SHA-256:
  `fc960805844fe328218a2602a287acc9326dac36daeebb1f47f2a63620477dc5`.
- Start: `2026-08-30T16:55:08.063384+00:00`
  (`2026-08-31 00:55:08`, Asia/Shanghai).
- Host: macOS, Darwin `27.0.0`, `arm64`.
- Python: `3.12.13`, Clang `22.1.3`; standard-library SQLite `3.53.1`.
- One application-suite invocation; runner elapsed time `8.157968` seconds
  (`unittest` rounded this to `8.158s`). This is **test duration**, not a
  synchronization, upload/download, latency or throughput benchmark.

Documentation updates after this snapshot do not change the tested source
identity. An older/newer artifact or a different platform does not inherit this
result merely because it has the same version string.

## Authorization and isolation

The owner explicitly allowed only a minimal synthetic check in temporary
directories, without networking, plugin installation or private-memory access.
That permission did not authorize full test discovery, dependency installation,
real keys/providers, host integration, cloud CI, publishing or deployment.

The public snapshot, disposable databases/configurations, opaque metadata
fixtures and local execution records were placed under a new temporary root.
The runner used an empty inherited environment, isolated Python startup and
disabled bytecode writes. It provided only synthetic explicit memory/config
paths, pinned the test temporary directory and SQLite temporary directory, and
verified that neither sentinel default store was selected. Existing host
configuration and installed plugins were not used.

macOS `sandbox-exec` denied all networking, restricted file-content reads to
the public temporary snapshot, selected Python runtime and OS support paths,
and restricted writes to the temporary root and `/dev/null`. Before loading
application tests, IPv4/IPv6 loopback TCP bind and UDP connect probes were
denied, as were reads/writes of a separately created **synthetic** file outside
the allowed root. The probes established no network connection and sent no
packets. Filesystem metadata access and normal OS support were not claimed to
be absent. Policy/probe observations are isolation evidence, **not an
independent system-wide audit**.

Initial isolation setup required correcting OS-loader access and the assumption
that macOS denies socket creation itself; macOS enforces the tested network
restrictions at bind/connect. Those preflight attempts stopped before loading
any application tests. No application-suite failure or retry is hidden here.

## Cases actually executed

All case IDs below are relative to the public `tests/` directory. Each named
method counts as one case; its subtests/assertions are not counted as additional
coverage. No discovery of the remaining suite was executed.

### Protocol/client interoperability — 4 cases

File: `test_v025_protocol_client_interop.py`, class `ProtocolClientInteropTests`.

1. `test_published_exchange_matches_known_answers`
2. `test_core_import_recall_export_round_trip`
3. `test_client_protocol_mcp_round_trip`
4. `test_core_to_client_to_new_core_preserves_history_and_new_mcp_memory`

These checked the published vectors and actual subprocess/SQLite exchanges,
including core export → configured client import → MCP write → export → a
**new** core store. Three original records and a new synthetic decision retained
their complete canonical records, IDs, relations and provenance. Unknown
unsigned imports remained quarantined until explicit acceptance; repeated
acceptance did not duplicate records or fabricate authentication/authority.

Both routes use the **same Python reference implementation**. This is not an
independently implemented protocol, cross-model understanding, real-host
integration, external adoption or signature-interoperability result. The
contributor's earlier v0.24.1 report remains separately attributed in the
[review handoff](REVIEW_HANDOFF.md#external-contribution-intake-pr-11).

### Core blocked-dependency regression — 1 case

File: `test_memory_vault.py`, class `UniversalMemoryTests`.

1. `test_blocked_dependency_does_not_freeze_later_memory`

Actual CLI processes checked that a memory with an unadmitted dependency does
not block an independent later memory, and becomes available to the change
stream after explicit admission. This also executed the previously repaired
recall/authority assertion. It does not certify signed delivery or concurrency.

### Configuration and operator routing — 4 cases

File: `test_v025_configuration_independence.py`.

1. `StatelessCoreTests.test_core_stream_can_self_describe_without_any_vault`
2. `ClientConfigurationTests.test_configured_protocol_capabilities_do_not_load_config_or_default_vault`
3. `ClientConfigurationTests.test_mcp_pins_default_path_on_first_data_tool_but_reloads_current_config`
4. `ClientConfigurationTests.test_manage_restore_through_client_does_not_need_original_configuration`

These use mocks to check lazy configuration/entrypoint boundaries. In particular,
the restore case proves command routing without the old client configuration;
**it does not restore a backup** or verify full-client recovery/resumption.

### Inert device/envelope metadata — 3 cases

File: `test_v025_operator_metadata.py`, class `OperatorMetadataTests`.

1. `test_device_cli_uses_only_the_explicit_state_path`
2. `test_legacy_epoch_domain_requires_explicit_legacy_inspection`
3. `test_both_envelopes_reject_ciphertext_tampering_truncation_and_trailing_bytes`

These used temporary POSIX files and manually framed opaque bytes. The selected
state path, explicit legacy-only epoch acceptance, and rejection of altered,
truncated or trailing bytes were checked. No real ciphertext, key ownership,
author signature, enrollment ceremony or encryption provider was validated.

## Recorded output and remaining work

```text
Ran 12 tests in 8.158s

OK
tests_run=12 failures=0 errors=0 skipped=0
```

The complete local log and structured report were retained with the temporary
review workspace, not uploaded or mixed with private memory. Their SHA-256s are:

- Log: `c8a00bef90e9b30b5c8c305b1c730674fe19cf35c006803919fa0ecdd957c827`
- Report: `3b906e4f41750c8027aa11942a902009156d06419e28c07141f1a0d84c05c387`
- Runner: `74dae397cd9483b668189a11bd4a13552410b9728eabc4a28618d0114984b788`
- OS profile: `2ef63260fbd5ef2bf3ea086ccc0eaafa1eb0126139f18193a7005f6c2d87ec5d`

The other authored cases were **not run** in this campaign. In particular,
full old-host operation parity, capture interruption, complete retrieval/graph
behavior, signed/resumable synchronization, genuine legacy conversion, actual
recovery, publisher/update activation, native Windows/Linux, scale/performance,
external providers and independent implementations remain outside this result.

No application fix was necessary for these 12 selected cases. No host plugin
was installed, private data migrated, dependency downloaded, GitHub/CI action
triggered, tag created, protected branch merged or release published during
this offline campaign. Future review requires its own scoped authorization;
reading this report is not permission to execute anything.
