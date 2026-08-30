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
main(argv=None, *, config_path=None) -> exit code
```

The module imports client configuration lazily and only through
`ClientConfig.load`; it does not maintain a second configuration format.

## Platform and validation boundary

Aggregate diagnostics are read-only and do not load protected signing keys.
The existing trust provider may refuse unsupported storage platforms; that is
reported instead of silently disabling configured trust. Snapshot/restore
currently require POSIX private-file protections. Windows needs an explicit
ACL-backed implementation for these protected recovery artifacts; the
independent unsigned core remains separate from that limitation.

See [PARITY.md](PARITY.md) for the distinction between capabilities retained,
replacement workflows implemented, intentionally removed dependencies and
features that remain unimplemented or unvalidated.
