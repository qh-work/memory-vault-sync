# Entity retrieval, old-format and publication repair evidence

Status: **12 selected offline synthetic methods passed; full v0.25 acceptance
remains open.** This is a narrow repair campaign, not a full test-suite,
installation, provider, performance or public-release certification. See the
[validation index](VALIDATION.md) and [complete parity ledger](V0_25_PARITY_PLAN.md).

## Exact source and result

| Item | Recorded value |
| --- | --- |
| Tested source | `9d98ce0d56394adc275915a0ea1fd39b6ca06254` |
| Source inventory | 155 archived files; no overlay |
| Inventory SHA-256 | `80cd8aaad67163f8d002afb447e980883a1055b2d024e9053f389f7f89f11835` |
| Started, UTC | `2026-08-30T19:17:23.259114+00:00` |
| Result | 12 run, 0 failures, 0 errors, 0 skips |
| Fixture duration | 2.443497 seconds; not a benchmark |
| Environment | Python 3.12.13, SQLite 3.53.1, Darwin 27.0.0, arm64 |

The runner used a fresh archive of this exact local commit, not the working
directory or an unpinned download. Its inventory was checked before and after
execution. No pre-fix test run was performed in this campaign; the defects were
identified in source. Later documentation commits do not rename the tested
source, and earlier reports are not added to this run's pass count.

## Repairs and observed boundaries

- Ordinary entity names can retrieve their associated text with or without
  concept expansion. A one-slot scoring budget still favors a matching text
  fragment over an entity-only fallback. Canonical records and delivery counts
  remain unchanged by recall.
- Structural handoff and ordinary recall filter relations to quarantined
  targets consistently. The visible continuity and its admitted episode remain
  usable; the original complete canonical relation list is not rewritten.
  This case did not verify real signatures or a remote trust registry.
- A valid old `conversation-export/v1` containing 20,001 short visible messages
  fits the existing 2 MiB member budget. The complete old-pack path verifies,
  repacks and converts it without the small ZIP tool's unrelated 20,000-message
  cap. The case reconstructs the exact original bytes and all ordered visible
  messages. Invalid ordinal and role fields after message 20,000 still fail.
  The retained small converter keeps its original explicit limit.
- Three controlled children exit with code 73 immediately after real publication:
  a private transfer pending file, a copied pack chunk and an unpacked output.
  Their complete targets have one link, not a stranded temporary alias. Exact
  transfer retry preserves its inode/bytes; copy verifies the existing chunk
  before completing its manifest; unpack never overwrites the completed output.
- Separate in-process failures observe the old-pack, sharing and backup output
  boundaries. The new file has one name before cleanup. Small-converter paired
  output tests interrupt each directory-fsync boundary after rename; rollback
  tracks the actual published inode and removes only this invocation's outputs.
  These are not additional process-exit or power-loss experiments.
- Explicit POSIX shared exchange and unpack output retain selected 0755/0775
  parent modes and existing 0644 exact-overlap files. Newly written files remain
  0600/single-linked. Private-state writes still reject those shared parents,
  and the explicit shared profile cannot perform a replacement. Backup and
  small migration preserve their stricter owned/non-writable 0755 parent contract.

The full-client output paths use the shared exclusive publisher. The independent
single-file core's raw unsigned bundle exporter still has its own publication
path and is not covered by these guarantees. Existing abandoned private aliases
are rejected rather than automatically removed. No private or real user data
was recovered, migrated, inspected or cleaned up by this campaign.

## Exact executed methods

Fixture links below resolve in the source checkout and executable review kit.
The separate protocol-only archive intentionally contains no Python tests.

In [test_v025_entity_retrieval.py](../tests/test_v025_entity_retrieval.py),
class `EntityRetrievalTests`:

```text
test_plain_entity_only_match_survives_both_semantic_modes
test_text_match_uses_the_last_scoring_slot_before_entity_fallback
test_handoff_filters_quarantined_target_without_changing_canonical_memory
```

In [test_v025_conversation_limits.py](../tests/test_v025_conversation_limits.py),
class `ConversationLimitTests`:

```text
test_many_short_messages_verify_repack_and_convert_losslessly
test_full_converter_still_checks_every_message_after_twenty_thousand
test_full_pack_publication_has_single_name_at_directory_fsync
```

In [test_v025_sharing_publication.py](../tests/test_v025_sharing_publication.py),
class `SharingPublicationTests`:

```text
test_interrupted_directory_fsync_has_no_temporary_hard_link_alias
```

In [test_v025_transport_publication.py](../tests/test_v025_transport_publication.py),
class `TransportPublicationTests`:

```text
test_transfer_pending_publication_survives_process_exit_and_exact_retry
test_pack_copy_and_unpack_survive_process_exit_without_hard_link_aliases
test_explicit_shared_outputs_keep_permissions_and_exact_retry
```

In [test_v025_backup_publication.py](../tests/test_v025_backup_publication.py),
class `BackupPublicationTests`:

```text
test_backup_publication_interruption_leaves_one_private_file_in_0755_parent
test_pair_0755_contract_and_rollback_after_each_directory_fsync_failure
```

These five modules contain 22 authored methods. Only the listed 12 ran; the
other ten remain unrun in this campaign. There was no whole-file or whole-suite
discovery. Public review packaging includes the additional cases for separately
authorized review, not as a claim that they passed.

## Isolation and retained raw evidence

An OS sandbox denied network access and file contents outside the fresh campaign
directory plus the selected runtime/system libraries. IPv4/IPv6 bind and
UDP-connect denial probes sent no packets. An outside **synthetic** control file
confirmed unrelated read/write denial; no private file was used as a probe.
Fixtures used explicit paths, with default Vault/config sentinels left untouched.

The parent audit hook admitted only the fixed synthetic child program for the
three declared modes and paths, once each. Each child inherited the OS sandbox
and had a ten-second timeout. Other process creation was denied. The whole run
had a 90-second deadline and five-second cleanup grace; neither fired. Temporary
fixture data was cleaned; the source archive and raw report/log remain retained.
There were no signing keys, crypto providers, host/plugin installations, account
access, cloud CI, remote writes or changes to protected main/tags.

Raw artifacts remain in the maintainer's private temporary campaign directory;
the paths are not advertised as public downloads. Digests identify the retained
evidence, not publisher signatures:

| Artifact | SHA-256 |
| --- | --- |
| `report.json` | `2031bcac2182dd966693ecb56fd5950f5278453d1f2a8df02072e64fd6b81462` |
| `run.log` | `16d57eb6f7fe8edda22ba089d149c598f2e5a778bc1c7678461c35762363e59f` |
| `run_scoped.py` | `f0f4f4a662f68a727be74a08f38872fb92540d46c2663425a1bb7cc57b7f644e` |
| `offline.sb` | `707a993ff7841a3dfc403c2ba169440a8f99a057786155b028d90a53fe1081c7` |
| `pin_source.py` | `dbf401d14a0c51cfe1b22a62add187f86fe71d41731a9b29cf01c4a5fe674c86` |
| `campaign.json` | `3251c5dfb2021617c808f3a20ba1c9bbce2f9790e634003c9d345beacfec7df7` |
| Fixed child program | `4ff289b35633430511517f03a7759733fd0b3598652390dec1a525e5ccc13f34` |

A separate pre-execution static pass parsed 62 Python source files and the
runner without importing application code. Packaging/inventory checks are
recorded separately in the built artifact manifest. Neither source parsing nor
archive verification is a runtime or installation test.

## Remaining acceptance work

These small cases do not establish complete graph/claim pagination, all MCP/old
host operations, signed privacy-review/requeue/group workflows, real cloud
transport, all recovery components, managed installation/update, independent
cryptographic interoperability, native Windows/Linux, a 2 GiB conversion,
performance or a second implementation/model using the protocol. The old-format
fixture is a message-count regression, not a large-scale trial. A controlled
process exit is not power loss. The complete P01–P14 ledger remains the scope;
this report does not reduce it to the repairs selected here.
