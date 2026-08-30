# Operating the optional full client

The full client adds operator workflows around the same Memory Vault as the
independent protocol. None of these workflows makes a Task, Project, model,
session or device the owner of a memory. Configuration and retry handles are
local control state, not another memory hierarchy.

These commands are implementation interfaces, not evidence of a successful
installation. This release work did **not** run the application, tests, a real
backup/restore, a key ceremony or a private-data migration. Use synthetic data
for independent validation before relying on recovery in production.

## Read-only doctor

```bash
python3 /absolute/source/memory_vault_manage.py \
  --config /absolute/private/control/client.json doctor
```

The configured client also exposes the same operator command through its
`manage` entry. `doctor(config_path)` is a reusable Python interface returning
a content-free report; it does not initialize a missing Vault or upgrade one.

The report distinguishes:

- configuration loaded, capture enabled, signing/trust paths configured;
- supported database schema, record/index/relation/admission/receipt counts;
- a present index from a content-checked, correct index;
- previously verified records from records whose signer remains registered now;
- cryptography package discovery from loading a key or verifying signatures;
- pending prompts, hook outbox, explicit conflicts and completed hook receipts;
- staged/committing lifecycle turns and incomplete commit receipts;
- documented host-adapter pending queues, without opening their messages;
- optional synchronization configuration and local status, without performing
  publication, reception, account login or a network request.

Doctor never selects memory text, raw prompts, final answers, signature payloads
or private-key contents. It does not parse outbox bodies or scan host transcripts.
It opens SQLite in `mode=ro` with query-only access. Ordinary SQLite read locks
and WAL coordination are still used: this is not a claim that a live filesystem
has no transient SQLite coordination activity. A full integrity scan and
signature re-verification are **not** performed by doctor.

Discovery is limited to 5,000 entries across the documented queue locations;
SQLite metadata work has a five-second bound per database. A limit, unknown
schema, unsafe path or unavailable component is reported instead of guessed.
Inspect `issues` and per-component fields, not only the command's exit status.
`attention_required` is a successfully produced diagnostic report, not a repair.

## Retry pending local saves explicitly

```bash
python3 /absolute/source/memory_vault_manage.py \
  --config /absolute/private/control/client.json retry --limit 16
```

The accepted limit is 1–64. This reuses the client's existing exact-request
hook-outbox retry implementation. It does not invent a pairing, ignore a
conflict, enable capture or load unrelated conversations. Unsafe or overly
large directory inventories require review before retry begins.

`saved` means the visible episode and its linked continuity were durably stored
locally. It does not mean another device received or another model read them.
If separately configured automatic synchronization is enabled, the normal
client save path may notify that approved synchronization workflow; this is
not a synchronous remote-delivery confirmation.

This command does **not** replay arbitrary lifecycle requests or host-adapter
requests. For a lifecycle turn in `committing`, replay the exact original
`turn.commit` request, including its ID and content. Do not change the final
answer while reusing its ID. Before commit starts, an explicit `turn.abort` or
`session.close` can clear staged text; after commit starts they cannot honestly
claim that canonical writes were rolled back. See [LIFECYCLE.md](LIFECYCLE.md).

## Interpreting common states

| Evidence | Meaning | Safe next action |
| --- | --- | --- |
| Missing Vault, no pending work | Configuration exists; no local memory has been created | Save through the authorized protocol/client |
| Hook outbox present | A visible pair may still need a local retry | Retry with the same configuration and capture permission |
| Hook conflict marker | Two incompatible event payloads share an event identity | Review the explicit conflict; do not auto-overwrite or guess |
| Lifecycle `committing` | Canonical write may be partial or response may have been lost | Replay the original commit; inspect its receipt |
| Registry missing/key revoked | Current trust is unavailable or has changed | Repair independent operator policy; never enroll a key from memory |
| Transfer blocked/gap/rejected | A complete authenticated delivery has not been established | Use the signed-transfer recovery workflow, retaining pending evidence |
| Unsupported database schema | This binary cannot safely interpret the selected file | Use the matching release or an explicit supported migration |

The operator module does not delete conflict evidence, reset a cursor, relax
permissions, erase host logs or repair a trust store merely to make status green.

## Memory snapshots and new-copy recovery

Use [BACKUP.md](BACKUP.md), not a plain NDJSON export, when recovery must preserve
record signatures and canonical write-idempotency receipts. Backups exclude
keys, trust policy and control queues. Restore always creates a new database
identity and must not automatically reuse old synchronization state.

The source entry points are:

```text
doctor(config_path) -> report
retry(config_path, limit=16) -> local hook-outbox result
retry_compat(config_path, limit=4) -> exact protocol-1.0 pending-intent result
retry_host(config_path, host=..., session_key=...) -> one exact queued host session
main(argv=None, *, config_path=None) -> exit code
```

The module imports client configuration lazily and only through
`ClientConfig.load`; it does not maintain a second configuration format.

## Platform and validation boundary

Aggregate diagnostics are read-only and do not load protected signing keys.
The existing trust provider may refuse unsupported storage platforms; that is
reported instead of silently disabling configured trust. The protected full
client uses POSIX private-file protections or native Windows ACL/handle checks
on supported local fixed NTFS storage; unsupported storage fails closed. The
Windows implementation and recovery sequence are not runtime-verified here.

See [PARITY.md](PARITY.md) for the distinction between capabilities retained,
replacement workflows implemented, intentionally removed dependencies and
features that remain unimplemented or unvalidated.

## Full client recovery is a separate, explicit workflow

`backup`/`restore` retain their memory-only behavior. The additional full-client
commands are `backup-client`, `restore-client`, `review-recovery`,
`activate-recovery`, and `import-recovery`. See [BACKUP.md](BACKUP.md) for exact
component selection, manifest/storage bounds and the required offline boundary.

`backup-client --quiesced` requires the operator to have stopped all relevant
writers. It does not stop applications, install a maintenance hook, or pretend
that several files have become globally atomic. Existing locks, source hashes
and directory-entry checks catch detected changes; an uncooperative writer is
outside that guarantee.

`restore-client` creates a new memory DB and a capture-disabled client. It
retains all selected old control bytes under inert `evidence/`, not under that
client's active `.state` directory. No old pending job runs and no old network
configuration is adopted. `review-recovery` is a bounded inventory, not approval.

Only `activate-recovery --authorize-local-resume` can create a different,
capture-enabled configuration and its new state directory. It rebinds known
local formats, preserves historical receipts, and performs **no retry itself**.
Host approval and current signing identity remain independent. Its generated
configuration has no sync path, so the following recovery retries stay local:

```bash
# Retry preserved visible-hook outbox entries, not conflicts.
python3 /absolute/source/memory_vault_manage.py \
  --config /absolute/private/recovered/resumed-client.json \
  retry --scope hooks --limit 16

# Drain only exact protocol-1.0 pending local intents, never sync.flush.
python3 /absolute/source/memory_vault_manage.py \
  --config /absolute/private/recovered/resumed-client.json \
  retry --scope compat --limit 4

# Resume one explicitly selected generic/Claude/Gemini session's saved requests.
python3 /absolute/source/memory_vault_manage.py \
  --config /absolute/private/recovered/resumed-client.json \
  retry --scope hosts --host generic --session-key HASH_FROM_RECOVERY_INVENTORY
```

For `hosts`, use the 64-hex session directory key shown in a `control/hosts/...`
inventory path; it is local correlation, not a Memory owner. One invocation
uses the adapter's bounded recovery loop (up to eight queued commits). The
`--limit` option applies to hooks/compat, not this host limit. Pending
`turn.input` without a visible final response is not converted into a completed
turn. Host recovery never fabricates the missing response.

| Preserved state | Usable continuation |
| --- | --- |
| Hook `outbox` with matching visible text | Explicit `retry --scope hooks` after local activation |
| Hook `conflicts` | Kept blocked; review original evidence rather than delete a conflict to force a save |
| Lifecycle `committing` + a host's exact queued request | Explicit host-session recovery replays that same request |
| Direct lifecycle `committing` without a host queue | Caller resends the exact original `turn.commit` request/ID; hashes cannot reconstruct a lost request ID |
| Compatibility `pending` turn | Explicit `retry --scope compat` uses its frozen visible intent |
| Compatibility incomplete `semantic_jobs` marker | Caller must resubmit its exact original proposal; the marker stores a digest, not the proposal body |
| Completed hook/lifecycle/compat receipt | Historical local acknowledgment, not proof of current trust, remote use, or task completion |
| Sync outgoing pending | Its canonical records survive; publish only through a separately authorized new stream/review |
| Complete incoming signed capsule + fragments | Explicit `import-recovery`, current-trust verification, then one atomic local memory import |
| Incomplete incoming fragment group | Keep evidence; independently retrieve the missing bytes. No partial admission or cursor advance |

An existing non-recovery config can already have independent automatic sync
enabled. Hook/host retries through **that** config may notify it, as documented
above. The recovery path avoids this by creating a local-only config; it does
not silently disable or modify another working client's settings.

Old transfer cursors, peer state, privacy approvals and upload receipts are
never copied into a new active sync directory. Preserve them for audit; use the
normal explicit sync configuration flow with a fresh directory and the new
Vault/store identity. Do not overwrite a current state file with archived JSON.

New in-process recovery API, all operator-only (not Memory JSON operations):

```text
backup_client(config_path, output, include=[...], quiesced=True, timeout=60)
restore_client(backup, output, trust_store=None, accept_unsigned=False, timeout=60)
review_recovery(recovery, component=None, offset=0, limit=50, timeout=60)
activate_recovery(recovery, output_config, include=[...], authorize_local_resume=True,
                  identity=None, trust_store=None, allow_unsigned_local=False, timeout=60)
import_recovery(recovery, entry_id=..., trust_store=..., authorize_memory_import=True, timeout=60)
```

The source includes public synthetic recovery cases. They were **not run** in
this release work, and no real private Vault or service was accessed to claim
validation. Byte-preserving backup, functional resumption and platform/crash
behavior must be verified independently before relying on recovery in production.
