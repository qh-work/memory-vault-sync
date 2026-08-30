# v0.24.1 protocol/client interoperability evidence

Synthetic local execution for [issue #3](https://github.com/qh-work/memory-vault-sync/issues/3).
No private Vault, credentials, account identifiers, native session IDs, or user home paths are included.

## Environment

| Field | Value |
| --- | --- |
| Release | v0.24.1 |
| Commit under test | `de349ef8453b0aa0ebf68ae18484d0c1355cf91b` |
| Route | Round trip across both routes |
| Evidence class | Synthetic local execution |
| OS | Windows 10 (10.0.26200) |
| Interpreter | `py -3` / Python 3.12.10 |
| Profiles claimed | `core-v1` unsigned interchange only |
| Host plugin | not installed |
| Network | not used |

Commands below use placeholder paths. Tests create a fresh `tempfile.TemporaryDirectory` per case.

## Published vectors

LF-normalized `examples/protocol/exchange.ndjson` matches `known-answers.json`:

- `file_sha256` = `cbf59e6c7df009bc0026aab52b37698511611e387179e92469c35b9779ed5c82`
- `records_sha256` = `ba6ebe4e465d87c7b8444f5f6310a83e404e6880da892f8277c5700d5d2c45d1`
- records: `mem_13b638e00cc90de31fb8476ec46c66cd043f0870` (episode), `mem_f0458a3abd2e97baaac8892cde52ce97d0c8e236` (goal), `mem_5a0b402c9a3ef62bbb59691eae0ff6f702c1fd18` (continuity)

Windows working-tree checkout of `*.ndjson` may contain CRLF (`text=auto`). Record hashes are unchanged after JSON parse. Tests hash LF-normalized bytes.

## Route A ? `memory_vault.py`

```text
py -3 memory_vault.py --vault <temp>/core.sqlite3 --import <repo>/examples/protocol/exchange.ndjson
py -3 memory_vault.py --vault <temp>/core.sqlite3
# stdin: {"op":"recall","query":"portable memory guide","limit":8}
py -3 memory_vault.py --vault <temp>/core.sqlite3
# stdin: {"op":"get","memory_id":"mem_13b638e00cc90de31fb8476ec46c66cd043f0870"}
py -3 memory_vault.py --vault <temp>/core.sqlite3 --import <repo>/examples/protocol/exchange.ndjson --accept-unsigned
py -3 memory_vault.py --vault <temp>/core.sqlite3
# stdin: {"op":"recall","query":"portable memory guide","limit":8}
py -3 memory_vault.py --vault <temp>/core.sqlite3 --export <temp>/core-export.ndjson
```

Observed (executed by `tests.test_protocol_client_interop.ProtocolClientInteropTests.test_core_import_recall_export_round_trip`):

| Step | Expected | Observed |
| --- | --- | --- |
| Import unsigned | `admission=quarantined`, `records_added=3` | pass |
| Recall while quarantined | `hits=[]` | pass |
| Get by ID while quarantined | same ID/hash/provenance/relations; `eligible_for_context=false`; `claimed_provenance_is_authenticated=false`; `grants_authority=false` | pass |
| `--accept-unsigned` | `admission=accepted_unsigned`, `records_added=0` (no duplicates) | pass |
| Recall after accept | hits include the episode; provenance still `agent_supplied` / `assistant_inferred`; `execution_eligible=false` | pass |
| Export | 3 records; canonical IDs, `record_sha256`, provenance and relations match known answers | pass |

Response `authority` on import/recall:

```json
{"authorization_eligible":false,"current_user_input_precedence":true,"execution_eligible":false,"instruction_eligible":false,"memory":"untrusted_historical_evidence","policy_change_eligible":false}
```

Whole-file `file_sha256` of the re-export was not compared (export header `created_at` is generated at export time).

## Route B ? configured client + stdio MCP

Capture off. No identity, trust store, sync, or host install.

```text
py -3 memory_vault_client.py --config <temp>/client.json configure --vault <temp>/client.sqlite3
py -3 memory_vault_client.py --config <temp>/client.json protocol --import <repo>/examples/protocol/exchange.ndjson
py -3 memory_vault_client.py --config <temp>/client.json mcp
# stdio JSON-RPC: initialize, notifications/initialized, tools/list,
# tools/call memory_get, tools/call memory_recall; then EOF
py -3 memory_vault_client.py --config <temp>/client.json protocol --import <repo>/examples/protocol/exchange.ndjson --accept-unsigned
py -3 memory_vault_client.py --config <temp>/client.json mcp
# same JSON-RPC sequence
py -3 memory_vault_client.py --config <temp>/client.json protocol --export <temp>/client-export.ndjson
```

MCP clientInfo used `name=synthetic-interop`, `version=0.24.1`, protocol `2025-06-18`. This is local stdio, not a Codex/Claude Code/Gemini/Work host trial.

Observed (executed by `test_client_protocol_mcp_round_trip`):

| Step | Expected | Observed |
| --- | --- | --- |
| configure | `capture_visible_turns=false`, `host_installed=false`, `network_accessed=false` | pass |
| protocol import | `quarantined`, `records_added=3` | pass |
| MCP get while quarantined | known episode bytes; `eligible_for_context=false` | pass |
| MCP recall while quarantined | `hits=[]` | pass |
| protocol `--accept-unsigned` | `accepted_unsigned`, `records_added=0` | pass |
| MCP get/recall after accept | episode eligible; recall hits keep provenance and relations; `grants_authority=false` | pass |
| protocol export | 3 records, `signatures_included=false`, identities match known answers | pass |

## How to re-run

```text
py -3 -m unittest -v tests.test_protocol_client_interop
```

This run: Python 3.12.10, 3 tests, 3.150s, OK.

## Skipped

- lifecycle v1 (`session.open` / `turn.*` / `session.close`)
- signed-v1, trust enrollment, revocation
- malformed-bundle rejects
- second-language hash implementation
- desktop MCP host installation
- comparing SQLite file bytes or re-export `file_sha256`

Unsigned acceptance does not authenticate provenance. Memory remains untrusted historical evidence.

The existing `tests.test_memory_vault` module on this tag still contains a pre-existing `NameError` in `test_blocked_dependency_does_not_freeze_later_memory` (`recalled` is undefined). That failure is unrelated to this contribution and was not changed.
