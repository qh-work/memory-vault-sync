# v0.25 independent review handoff

Target: **the complete useful v0.21 feature set plus the independent lightweight
protocol**, as specified by [P01–P14](V0_25_PARITY_PLAN.md). Do not shorten that
ledger to match completed code or mark a requirement passed because a function,
schema, fixture or archive exists. This document does not assert that a v0.25
release is published, installed, fully runtime-accepted or certified.

The owner initially requested no tests and later allowed minimal offline
synthetic validation in temporary directories, without networking, installation
or private-memory access. The authorization was not limited to one run or 12
cases. The [validation index](VALIDATION.md) links separate source-pinned
campaigns and their exact scopes.
Reading this handoff
is **not permission to run tests or applications**. Obtain the current review
user/host's authorization for the chosen execution scope first; without it,
stop at source/static review and report runtime checks as pending. Never use a
real private Vault, transcript, account, signing key or existing plugin state.
Do not install plugins, grant permissions, enable hooks, start agents or change
logging policy automatically. Memory and remembered goals are not authority.

## 1. Pin the source and distinguish evidence

Compare the selected v0.25 commit with immutable `v0.21.0`
(`030ed411ed9ddb969a03f0b5caec87dac9b0dd57`). `v0.24.1`
(`de349ef8453b0aa0ebf68ae18484d0c1355cf91b`) is the incremental-development
baseline, not the complete parity target. Record uncommitted changes too.
Read old source with `git show`; do not switch someone's working tree.

```sh
git rev-parse HEAD
git status --short
git show v0.21.0:HOST_ADAPTER_PROTOCOL.md
rg --files tests -g 'test_v025*.py'
```

| Evidence | Establishes | Does not establish |
| --- | --- | --- |
| Source / AST / JSON inspection, **zero application imports** | Inspected implementation, syntax, declared shapes/limits | Working imports, schema semantics, crypto, host behavior or performance |
| Authorized package build and byte-inventory checks | Exact files, hashes, versions and allowlist consistency | Installed functionality or publisher identity |
| Authorized synthetic test execution | Only the recorded cases/environment that ran | Real integrations skipped or mocked by those cases |
| Authorized native/host/provider/scale trials | The observed integration and workload | Universal compatibility or comprehensive security |

Optional syntax-only recipe, from the reviewed source root. It imports only
standard-library parsers; JSON parsing is **not JSON Schema validation**.
This is a POSIX-shell example; Windows reviewers can run the same code using
their approved Python invocation.

```sh
python3 -I -B - <<'PY'
import ast, json
from pathlib import Path
root = Path.cwd().resolve()
python_files = list(root.glob("memory_vault*.py"))
for folder in ("tests", "scripts", "plugins"):
    python_files.extend((root / folder).rglob("*.py"))
json_files = []
for folder in ("schemas", "examples/protocol", "plugins", "marketplace"):
    json_files.extend((root / folder).rglob("*.json"))
for path in python_files + json_files:
    if path.is_symlink() or not path.resolve().is_relative_to(root):
        raise SystemExit("source path outside reviewed checkout")
    content = path.read_text(encoding="utf-8")
    if path.suffix == ".py":
        ast.parse(content, filename=str(path.relative_to(root)))
    else:
        json.loads(content)
print("Syntax only; no project imports, tests, keys, Vaults or host calls")
PY
```

Do not substitute application `--help`, module import, unittest discovery or
pytest collection for this tier: these can execute project code. For authorized
packaging, follow [RELEASE.md](RELEASE.md) using a new output directory and the
actual source SHA. Check that the protocol archive has no executables, the full
client has its complete runtime, and the separate review archive has the tests
below. `SHA256SUMS` is not a publisher signature. Verify claimed public assets
independently; local files are not proof of upload or adoption.

## 2. Full coverage map

Read [PROTOCOL.md](../PROTOCOL.md), [SECURITY.md](../SECURITY.md),
[TWO_MODES.md](TWO_MODES.md), [PARITY.md](PARITY.md) and the complete ledger.
Use these slices for focused review without dropping any requirement.

| Requirements | Contract / implementation | Required outcome |
| --- | --- | --- |
| P01, P14 | Core, configured protocol, [implementer material](IMPLEMENTERS.md), [release inventory](RELEASE.md) | Identical canonical IDs/bytes across modes; complete distributions; no Task/Project owner or imported execution authority |
| P02, P05 | Client/lifecycle/hosts/compat; [CLIENTS.md](CLIENTS.md), [HOSTS.md](HOSTS.md), [COMPATIBILITY.md](COMPATIBILITY.md) | Durable visible-pair capture, exact retry/cancel/recovery and all ten old operations through one Vault/trust |
| P03, P04 | Core index/retrieval/views; [RETRIEVAL.md](RETRIEVAL.md), [GRAPH_VIEWS.md](GRAPH_VIEWS.md) | Bilingual/fragment recall, explained ranking, complete claim timelines, trust-aware graph state and non-executing proposals |
| P06, P07, P08 | Sync/transfer/privacy/remote/pack; [SYNC.md](SYNC.md), [REMOTE_BACKENDS.md](REMOTE_BACKENDS.md) | Bounded signed delivery, offline retention, privacy resolution, replay/fork handling, resumable groups and scoped cloud transport |
| P09 | Legacy pack converter; [LEGACY_PACKS.md](LEGACY_PACKS.md) | Actual old packs/ZIPs/checkpoints; complete visible evidence, claims, typed relations, multipart order and truthful ID mapping |
| P10 | Manage/backup/recovery; [OPERATIONS.md](OPERATIONS.md), [BACKUP.md](BACKUP.md) | Read-only doctor, explicit index/queue recovery, consistent snapshots, inert restore and separately authorized resume |
| P11 | Update trust/updater/managed installation; [UPDATES.md](UPDATES.md) | Independent publisher pins, expiry/rollback/threshold checks, verified stage, explicit activation and recoverable rollback |
| P12 | Sharing/trust/crypto/device/catalog APIs; [SHARING.md](SHARING.md), [TRUST.md](TRUST.md), [ENCRYPTION.md](ENCRYPTION.md) | Complete selected subgraphs, current trust, real signatures and honest fail-closed external-provider boundaries |
| P13 | Native storage and every consumer; [PLATFORMS.md](PLATFORMS.md), [PACKS.md](PACKS.md) | macOS/Linux and native Windows protected read/write/lock/publication, without insecure fallback or lost workflows |

Mandatory Git control, Task directories and the old monolith stay removed.
These exclusions do not justify omitting useful v0.21 features. Old ordinary
records were hash-addressed, **not individually author-signed**; update
signatures and Git commit identities are different evidence.

An actual gap remains in automatic capture: its episode/continuity pair lacks
the preceding turn's canonical continuity edge. Review acceptance-time freezing,
exact retry, restored control state and bounded incremental dependency transfer
together. A session/source handle can correlate requests, never own memories.
Do not mistake a single saved turn or unlinked imported history for this full
v0.21 behavior. See [current status](STATUS.md) and P01/P02/P05/P06 in the ledger.

### External contribution intake: PR #11

[PR #11](https://github.com/qh-work/memory-vault-sync/pull/11) from
`jagadeepmamidi` adds three unsigned-interchange cases and a
[v0.24.1 execution report](https://github.com/jagadeepmamidi/memory-vault-sync/blob/7121ba388178eb11eff8274aa65d20c16af9a24c/examples/protocol/interop-v0.24.1.md).
The report identifies tested commit
`de349ef8453b0aa0ebf68ae18484d0c1355cf91b`, Windows/Python 3.12.10 and three
passing cases. This is **contributor-reported execution on v0.24.1**, not a
maintainer reproduction, a v0.25 result or independent implementation evidence.

At intake on 2026-08-30, its
[GitHub run](https://github.com/qh-work/memory-vault-sync/actions/runs/33317756756)
was terminal with `action_required` and zero jobs. That run supplies no
executed CI result. No run was approved or triggered during this review.
The PR targets older protected main; the
[exact comparison from v0.24.1](https://github.com/qh-work/memory-vault-sync/compare/de349ef8453b0aa0ebf68ae18484d0c1355cf91b...7121ba388178eb11eff8274aa65d20c16af9a24c)
contains only the test, report and CI command, not the many cumulative runtime
changes shown against main. Do not merge that cumulative diff to transplant
the tests into v0.25.

The adapted `test_v025_protocol_client_interop.py` retains attribution to the
pinned contribution and adds a real core-export → client-import/MCP-write →
new-core-import route, using synthetic data. All four subsequently passed in
the scoped offline campaign on `066cd5629e690e6b38ab9c0bf43badafe4ef7a1b`.
Both routes still use the same Python reference implementation;
this does not supply a second-language implementation or an AI adoption claim.
The reported undefined `recalled` variable in the existing blocked-dependency
test was confirmed in source and repaired by requesting recall before the
authority assertion, not by removing that assertion. That specific regression
also passed in the recorded campaign; the source repair alone was not proof.

### Current v0.25 synthetic source inventory

This is an **authored inventory, not a passing full-suite result**. Only the
exact methods in the [validation index](VALIDATION.md) have execution evidence
on their respective source commits; the other cases remain unrun. Re-list the selected commit
before reporting coverage; retain `tests/test_memory_vault.py` for shared
core/client regressions too. Asserting a size constant is not a scale trial.

| File under `tests/` | Main slice |
| --- | --- |
| `test_v025_compat.py` | Closed old envelopes, opaque handles, receipts, semantic/large-turn projection; shared-Vault cross-client first-write/retry and receipt/evidence validation |
| `test_v025_retrieval_views.py` | Bilingual/BM25/fragments, direct-query candidate retention and long-record tail budgets, claim timelines, trust-aware edges, graph bounds, reindex/requeue |
| `test_v025_index_state.py` | One index-completeness check per views request; no stale cross-request cache |
| `test_v025_mcp_bounds.py` | Transport-specific graph/view bounds, schema agreement and complete bounded MCP responses |
| `test_v025_configuration_independence.py` | Strict stateless discovery; deferred/default configuration pinning; independent recovery/pack/operator routing without a lost old config |
| `test_v025_protocol_client_interop.py` | Contributor-derived public-vector/core/MCP checks plus actual core → client write → new-core exchange; explicit unsigned admission and unchanged record identities |
| `test_v025_sync_review.py` | Privacy review, explicit dispositions, chained streams, groups and interruption |
| `test_v025_legacy_pack.py` | Old wire fixtures, checkpoints, exact evidence, ordered parts and aliases |
| `test_v025_legacy_pack_edges.py` | Escaped secrets, same-kind alias misdirection, cycles/missing targets, cross-part replay |
| `test_v025_client_recovery.py` | Quiesced snapshots, inert restore, activation, queues and current-trust signed recovery |
| `test_v025_host_recovery.py` | Exact durable cancellation proof, bounded stale-job cleanup, disabled-capture safety and later-final progress |
| `test_v025_publication_recovery.py` | One bounded synthetic child exiting after publication, no-clobber fixture threads, exact retries, aliases and unsupported-native failure |
| `test_v025_install.py` | Isolated install, pinned inventory, activation journal, rollback, automation gates |
| `test_v025_update_trust.py` | RSA-PSS, independent verifier comparison, thresholds/rotation/expiry/rollback |
| `test_v025_update_edges.py` | Activation expiry, complete runtime inventory, external bytecode paths and physical-key quorum uniqueness |
| `test_v025_sharing.py` | Selection closure, atomic import, original proofs, current trust, large-share bounds |
| `test_v025_device_trust.py` | Externally authorized enrollment/revocation/epochs/recovery transitions |
| `test_v025_operator_metadata.py` | Explicit new-state init/status, no overwrite/default Vault dependency, new/old envelope inspection and no automatic decryption |
| `test_v025_encryption.py` | Provider framing, authenticated-data bindings, ciphertext catalogs |
| `test_v025_storage.py` | Pure ACL/path policy and separately gated native file/lock/publication |
| `test_v025_portable_packs.py` | Resumable packs, small-ZIP interface and native protected publication |

After execution is authorized, inspect the selected file's imports, fixtures,
subprocess/provider needs and platform skips first. For example:

```sh
python3 -B -m unittest discover -s tests -p 'test_v025_retrieval_views.py'
```

That command **executes application code**. It grants no permission to run every
file, install dependencies, generate real keys or invoke OpenSSL/rclone/hosts.
Record skips and missing dependencies rather than silently counting them as
passes. The linked scoped report supplies only its named execution results;
the example commands in this handoff were not run as a full campaign.

The cross-client semantic-retry and candidate/fragment-budget regressions were
authored after the initial pinned campaign. Six now have their own execution
evidence below; neither their runtime repairs nor other unrun cases inherit the
older passing result. Review the shared transaction, complete canonical
projection binding, current admission, bounded direct versus expanded
candidates and separately reported span/scoring work before any further
execution within an authorized scope.

### Six-case follow-up — executed on pinned newer source

For the post-smoke retrieval and shared-Vault semantic-retry changes, exactly
these six methods passed on `ecb83fdc3045545c9cfd1a07ea312dfadf8f314d`, with
zero failures, errors or skips:

```text
test_v025_retrieval_views.RetrievalAndViewTests.test_expansion_cannot_evict_a_direct_match_with_a_unique_query_word
test_v025_retrieval_views.RetrievalAndViewTests.test_seven_large_record_tails_do_not_spend_scoring_slots_on_unrelated_prefixes
test_v025_compat.HostCompatibilityTests.test_two_configurations_reuse_shared_semantic_record_and_original_receipt
test_v025_compat.HostCompatibilityTests.test_simultaneous_first_semantic_writers_share_one_canonical_effect
test_v025_compat.HostCompatibilityTests.test_semantic_crash_after_shared_commit_reuses_effect_without_local_cache
test_v025_compat.HostCompatibilityTests.test_shared_semantic_receipt_rejects_redirected_anchor_and_extra_response_fields
```

The [follow-up evidence report](V0_25_FOLLOWUP_SMOKE.md) records the environment,
isolation, raw-output hashes and limitations. The original minimal-validation
authorization covered this follow-up; the previous claim that these six cases
needed a new allowance was not supported by the actual scope. Execution used a
fresh source copy and isolated temporary synthetic paths, preserving the
offline/no-install/no-private-state boundary. It did not expand to whole-file
discovery or other cases. The long-tail fixture contained about 7 MiB of
synthetic text; it was not a throughput trial. The concurrency case used two
local fixture threads; the interrupted-cache case injected an exception, not a
real process crash. The other ten newly authored methods and both expanded
existing cases remain unrun. All full ledger requirements stay open; these six
passing results do not replace independent cross-model or cross-device evidence
or authorize native hosts, real keys/providers, cloud CI or publication.

### Publication and recovery follow-up — seven selected cases

The [recovery report](V0_25_RECOVERY_SMOKE.md) records seven passing methods on
`332e944a6bda8f70dd3af6526d926d9468ed2f0d`, with zero failures, errors or skips.
They cover three publication cases, three confirmed-cancellation cases and one
actual unsigned hooks backup/restore/activation/retry path. The same first
publication test, overlaid onto the pinned pre-fix runtime, separately produced
the expected hard-link failure; it is not counted as a pass.

One controlled temporary child exited at a real directory-fsync boundary. The
host cleanup and read-only hot-journal boundaries used injected failures or
retained synthetic artifacts, not actual host crashes. All execution remained
offline, without installation, keys or private data. The report identifies
exact methods, source/overlay inventories and raw hashes. Do not generalize its
single unsigned recovery path to all components, native platforms or live
installations. That older source did not yet implement automatic cross-turn
continuity; the newer source and its distinct evidence are described below.

### Frozen capture and dependency reuse — twelve selected cases

The [capture report](V0_25_CAPTURE_SMOKE.md) records twelve passing methods on
`6eeb35ac2df8f0813d87ff6e6a0f3fbbf1c2f917`, with zero failures, errors or skips.
They cover source-local frozen chains, selected old partial-write identities,
bounded recovery, a done-before-journal-ack restore window and a real temporary
SQLite hot-journal child exit. Four cases exercise small signed directory
streams, including a fresh receiver, missing atomic prefix receipt, older SQL
writer quarantine and ancestor revocation. Fresh fixture keys are not real
credentials or independent cross-device evidence.

The initial attempt is retained with six passes, one failure and five errors;
only fixture response unpacking and private-directory setup changed before the
passing rerun. Runtime checks were not weakened. The four new test modules have
39 methods; the other 27 were not selected. Public review material includes
those cases, but authorship is not execution. Exact case names, source inventory,
isolation, output hashes and outstanding limits are in the report. Whole-suite,
real-host/provider, scale, native Windows/Linux and independent implementation
acceptance remain open, as does the full P01–P14 ledger.

## 3. Review campaigns — scoped authorization required

Use a fresh reviewer-owned temporary workspace with explicit Vault/config/
trust/exchange paths. Never rely on defaults or environment variables pointing
to a real installation. Fresh test keys remain in that workspace. Kill/restart
only fixture processes created for the authorized case.

### A. Two-route round trip and separate protocols — P01/P02/P05/P14

1. Use [known-answer material](../examples/protocol/README.md) in an independent
   implementation that does not import `memory_vault.py`. Compare exact UTF-8,
   hashes, record IDs and bundle accumulators. Round-trip through the configured
   client's `protocol` entry and MCP initialize → initialized → discovery →
   save → recall. Default quarantine must remain; explicit unsigned acceptance
   must not fabricate authorship or duplicate records.
2. Keep these routes distinct, and exercise wrong-envelope rejection:

   | Route | Wire |
   | --- | --- |
   | Core / configured `protocol` | UAMP core requests and `universal-memory-record/v1` |
   | `lifecycle` | New `universal-memory-lifecycle-request/v1`, `op`, `ses_…` / `turn_…` handles |
   | `compat` | Old `memory-vault-host-request/v1`, protocol `1.0`, `operation`, `adapter`, `payload` |
   | `mcp` | MCP JSON-RPC, not either lifecycle NDJSON envelope |

3. Exercise all ten old operations in [COMPATIBILITY.md](COMPATIBILITY.md),
   exact retries and changed-request conflicts. New reversible aliases are not
   original `ep-…`/`evt-…` identities; real old IDs need checked migration.
4. Interrupt intent/canonical-write/receipt boundaries; race commit with
   abort/close; disable capture before retry. Completed receipts may be read,
   but partial saves cannot resume with capture off. Closing correlation cannot
   hide/delete memory. Test documented event fields only on an approved host;
   missing pairs must not cause transcript discovery. Work automatic capture
   needs actual supported-host evidence, not inference from an MCP listing.

### B. Retrieval and cognitive state — P03/P04

Build unrelated claims sharing an episode/task reference, bilingual synonyms,
negation, a match near a long record's tail, supersession, conflict and explicit
resolution. Check exact fragments, ranking explanations, complete paged
timelines and bounded graph frontiers/cycle reports. General relations must not
merge unrelated claims. Revoke a signer and repeat recall/views: ineligible
edges cannot retire verified history. Corrupt only fixture derived indexes,
rebuild bounded pages while adding later records, and confirm canonical
bytes/signatures stay unchanged and a later pass handles the new range.

### C. Delivery, privacy and provider I/O — P06/P07/P08

1. Start two isolated Vaults with explicitly registered fresh test keys and a
   local exchange. Send dependent graphs; test duplicate replay, missing
   prefixes, forged-before-valid candidates, signed forks and revocation.
   Crash at pending/publish/cursor and record/receipt/cursor boundaries. Complete
   groups admit atomically; cursor movement cannot conceal partial data.
2. Put synthetic secrets/local paths in dependencies, not only roots. Review
   must be content-free/read-only. Resolve exact keep/exclude sets; secrets have
   no override, path decisions stay local/record-specific, and begun publication
   cannot be rewritten. Retry/requeue without deleting evidence, duplicating
   memories or reinstating an old approval.
3. Exceed budgets and interrupt fragments; resume missing work. Corrupt cached
   chunks and require final unpack/reception verification. Receive-only must
   not publish. Disable/rebind config during a worker/provider call; inspect
   exit/pending state, launch suppression and retained data. Local save/recall
   must not wait for remote I/O. SQLite/OS calls are not hard-real-time deadlines.
4. Only with backend authorization, use a pinned reviewed executable and a
   disposable provider namespace for advertised rclone backends. Check real
   list/read/write integrity, pipe/output/time limits and transient failures.
   A fixture executable does not validate a cloud backend. Distinguish local
   saved, exchange published, receiver committed and independently witnessed
   agent-read results; transport receipts do not prove another AI read memory.

### D. Genuine old formats and scale — P09

Independently construct frames/catalogs from the inspected v0.21 grammar; do not
use private exports or load the old runtime. Exercise near the declared
**2 GiB / 250,000-document** limits and separate just-over-limit cases. Use a
streaming fixture generator, not the small tests' read-all helpers. Record peak
memory/disk/time, object counts and failures. The retained 64 MiB small migrator
is not a substitute for this gate.

Include long visible bodies, claim groups, all four 256-edge lists, Unicode,
source/anchor metadata and escaped secret metadata. Compare original bytes and
every mapped visible/typed relation. Import NDJSON parts in order: skipping
required predecessors must fail without partial admission; replay adds nothing.
Try a rehashed mapping that substitutes a same-kind relation fragment for its
anchor; registration must reject it. Check checkpoint pins/generation links as
**hash-only evidence**, not signatures. `verify`/`repack` check closure/anchors;
`convert`, including dry run, additionally rejects cycles before publication.
Follow [LEGACY_PACKS.md](LEGACY_PACKS.md), not a generic ZIP-only exercise.

### E. Recover memory, then separately resume state — P10

Create pending, committed, aborted and conflicting hook/lifecycle/host/compat
jobs, including a canonical write interrupted before its final receipt.
For `backup-client`, stop those fixture writers and assert `--quiesced`; also
try a held lock or changing inventory and require refusal. Memory-only backup
must not claim to include control queues.

Restore to a **new** directory/Vault. Verify a new `store_id`, exact canonical
records/proofs/receipt evidence and capture-off config. Original keys, trust,
permissions, sync config, cursors and workers must not become active. Use an
independent current trust store: backup-time admission/cached receipts are not
current trust. Bad SQL/schema/path/checksum or missing references must stop
usable activation.

Remove only the fixture's old config, or set an invalid fixture default path.
Independent recovery inspection/restore and pack/envelope verification must
still be reachable through the full client. Stateless capabilities must retain
strict envelope validation and valid request-ID echo without opening storage.
Actual memory operations must fail for a bad selected configuration, not fall
back to another Vault; a running MCP/protocol stream must not follow a changed
default path after selecting its first store.

Use `review-recovery`, then separately authorize `activate-recovery` with new
config/state paths; activation alone replays nothing. Retry one explicit scope
from [OPERATIONS.md](OPERATIONS.md), preserving exact requests/evidence. A
previously signed client cannot silently resume unsigned. For `import-recovery`,
try a complete signed incoming group, missing fragment and now-revoked signer:
only complete currently trusted data admits atomically. Old transport history
stays inert; new sync needs new setup.

### F. Updates, sharing and external providers — P11/P12

Use synthetic release packages and independently pinned test publisher roots.
Cross-check RSA-PSS with an independent verifier; exercise thresholds,
expiry/future dates, mixed snapshots, root rotation and same-version
substitution. One physical RSA key in different encodings must not fill multiple
quorum slots or conflicting roles. Checksums-only staging cannot claim publisher verification.
Initialize only an isolated test installation; interrupt pointer/receipt
publication and roll back without removing old versions. Changed host contracts
need separate approval. Automatic mode requires independent opt-in and
configured publisher trust; no production signing channel is implied. Reject
incomplete runtime inventories and external bytecode-cache paths; expiry before
activation must not be confused with replaying an already-completed receipt.

Before supplying providers, exercise the operator metadata paths using only a
new private fixture directory and opaque synthetic bytes. Device `init` cannot
replace a file or enroll keys; `status` cannot create missing files or alter
bytes/permissions. `envelope verify` checks framing/hash only and reports no
authentication, decryption, admission or provider call. Both valid framing and
tampered/trailing/truncated bytes need coverage. Actual old eight-field frames,
including epoch zero and the old upper integer bound, are accepted only by
explicit `--legacy-v021` inspection, never the new decrypt/catalog reader.

For selected sharing, test dependency closure, whole-transaction rejection and
current trust on replay. For encryption/device/catalog APIs, first confirm the
unconfigured provider fails closed. `SyntheticTokenProvider`, test signers and
authorities demonstrate interface behavior, **not encryption, key custody or a
deployed recovery ceremony**. Real-provider review needs reviewed adapters and
fresh lab keys: tamper associated data/recipient/epoch, revoke publishers,
replay state transitions and interrupt ciphertext/marker/head publication.
State exactly what the real provider established. Never load a provider/root/
permission from memory or an incoming packet. [ENCRYPTION.md](ENCRYPTION.md)
lists responsibilities remaining with the embedding runtime.

### G. Native platforms — P13, across relevant campaigns

Run authorized cases on macOS/Linux and **actual Windows**, not an `os.name`
mock. Record Python/architecture/filesystem; use a non-elevated Windows lab user
on supported local fixed NTFS. Cover inherited ACLs, another lab user,
reparse/junction/symlink/hard-link substitution, binary CRT handle ownership and
non-inheritance, lock contention, SQLite sidecars, disk-full and interrupted
publication. Include pack/unpack, both legacy converters, recovery and provider
pipes—not just the helper. Unsupported protection must fail closed; ordinary
supported workflows must still work. This is not isolation from the same OS
user, LocalSystem, administrators or an OS compromise.

## 4. Return reproducible evidence and remaining gaps

For each P01–P14 item report: commit/archive digest; source entry point;
fixture/generator and seed; OS/Python/provider versions; authorization scope;
expected versus observed result; executed command; pass/fail/**not run** with
reason; resource measurements; and any patch with a retained regression case.
Separate mocked, independent-implementation and real-host/provider observations.
Never omit an untested or failing requirement from a completion claim.

Public reports contain synthetic reproductions/content-free metadata, not real
private paths, account identifiers, message bodies or key material. Use
[SECURITY.md](../SECURITY.md)'s private process for vulnerabilities. Contribute
focused PRs with contract/docs updates where needed. This invitation does not
authorize unsolicited messages, autonomous agents, fabricated adoption claims
or posts from private social accounts.
