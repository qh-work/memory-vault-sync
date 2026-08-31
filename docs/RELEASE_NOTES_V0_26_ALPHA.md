# 0.26.0-alpha.1 development evidence

Date: 2026-08-31. The earlier sections record pre-publication candidate work
on `feat/v0.26-network-alpha`, originally based on
`e03de3ec02026f3c13c6af3cb194318f87beec28`.
[0.26.0-alpha.1 is now published](https://github.com/qh-work/memory-vault-sync/releases/tag/v0.26.0-alpha.1).
Later development below does not replace those published assets. This source
report does not attest to installation or cloud authorization on any user's
machine, and is not an immutable release attestation. Each built candidate
has a separate source manifest and package verification result.

## What this iteration changes

- Keep the interrupted network implementation, then enforce the latest
  [0.26 baseline](V0_26_PLAN.md): native `connect`, `remember`, `recall`,
  `discover`, `send`, `receive`; one Python/NDJSON/HTTP implementation.
- Remove the unshipped six-tool MCP facade and A2A message/AgentCard adapter.
  Preserve the existing eleven MCP memory tools, core protocol, capture,
  personal backups, selective share/handoff and configured sync behavior.
- New setup separates authority signing credentials from ordinary endpoint
  signing credentials. Existing explicit shared-key configurations remain
  readable and return a warning; they are not silently migrated.
- Recovered endpoints can receive old messages and authenticated old receipts
  without being stuck at an empty cursor. Unmatched receipts do not prove a
  local send. Relays reject a broken immediately preceding roster link.
- Authenticated and decrypted messages with invalid application JSON/shape
  are retained as bounded rejected ciphertext, without a successful save
  receipt or memory import, so a malformed message does not block good ones.
- Native agent requests close owned HTTP connections and retain borrowed
  transports. Client dependencies are separate from optional server packages.
- An explicit bounded pump retries persisted requests and ciphertext, with no
  scheduler or automatic startup. Older unfrozen queues lacking recipients
  require the original request rather than guessing the destination.
- The dependency-free TypeScript HTTP entry uses the same six operations and
  trusted endpoint core. Explicit retry preserves the original request bytes.
- Serialized UTF-8 previews keep multi-message receive results bounded;
  `text_memory_id`, when present, supports full local recall after delivery.
  Old larger cached previews are projected without rewriting stored evidence.
- Client and optional server dependencies now have complete wheel-only hash
  locks; the separate TypeScript crypto fixture has its npm integrity lock.
- Align repository discovery and onboarding with the actual alpha source.
  The introductory agent guide remains below 4 KiB.
- Full endpoint recovery now includes the existing canonical Vault, committed
  offline outbox, frozen ciphertext, inbox and historical delivery receipts.
  Two SQLite write reservations and configuration rechecks bound the snapshot;
  current operator-selected memory trust takes precedence over archived trust.
- Independent nodes have their own signing identity, signed directory and
  fresh issuer control. Node replacement at the same URL invalidates transport
  cursors and storage confirmations without deleting canonical memories.
  `node-init` and `node-authorize` separate storage enrollment from agent
  membership; `inspect`, `refresh` and persistent draining need no member key.
- A callable independent TypeScript crypto module implements the fixed wire
  profile. Its single-recipient path uses only supported jose APIs; its README
  records the library-specific construction and the tested runtime scope.
- The independent TypeScript endpoint validates issuer state, member and node
  keys/scopes, invitations, signed requests and join proofs. It adds explicit
  local setup, the existing canonical SQLite Vault, bounded HTTP transport and
  persistent queues. Python and TypeScript can resume each other's queue and
  read the same records without conversion or a Python subprocess in Node.
  The native six-operation facade adds the same bounded retrieval and structural
  handoff selection. Complete graph/view management and old cloud-worker parity
  remain unimplemented.
- Recall and receive label historical evidence, preserve bounded original
  provenance claims and distinguish record time from a current environment
  check. Prior failures require revalidation when relevant conditions change;
  these outputs do not execute retries. Recall accounts for escaped text and
  metadata within its 8 KiB page without discarding remaining content.
- Directed node transfer uses a frozen source snapshot and explicit issuer
  grant. It preserves admission history, original ciphertext and signed
  receipts, resumes bounded HTTP passes and verifies a target completion
  receipt. It neither deletes source data nor automatically redirects clients.
- Matching crash-orphan ciphertext is republished through the storage
  durability barrier before a new message reference is committed. An injected
  directory-flush failure cannot produce a successful save acknowledgement.
- Python and TypeScript keep the authenticated node binding through network
  waits. Late refresh/poll/ack results cannot restore delivery state from a
  replaced node; concurrent progress on the same node remains monotonic.
  These checks preserve both schemas and original memory/ciphertext bytes.
- Redistributed Unicode 14 tables retain the Unicode attribution and complete
  permission notice in `NOTICE`; the project's own code remains Apache-2.0.

## Verified scope

The targeted campaign uses synthetic identities and memories in temporary
directories. It does not run the whole repository suite or read private data.
The initial takeover run completed **16 tests, zero failures/errors/skips**, in
6.210 seconds: 13 network tests plus three selected existing memory/MCP tests.
This duration is a local test-run observation, not a throughput benchmark.

The subsequent package-preparation run completed **23 tests with zero
failures/errors/skips**, in 8.467 seconds, under a new stable CPython **3.11.4**
environment installed from the complete server hash lock. It adds four pump
regressions, two TypeScript native HTTP entry checks, and the multi-message
Unicode response-budget regression, including replay of older cached previews.
The previously described checks remain included. Node 22.19.0 executed both
TypeScript campaigns; this does not claim a TypeScript static type check.

| Check | Observed scope |
|---|---|
| Native entries | Python, existing client command and HTTP read/write the same Vault; exact retries and conflicts agree; UTF-8 recall pagination remains bounded |
| Cryptography | Real JWE encryption and Ed25519 verification; wrong keys, tampering, algorithms and duplicate JSON refused; independent Python/TypeScript seal/open both ways |
| Setup and recovery | Separate issuer/member keys, invitations, inactive new-path recovery, old explicit configuration warnings, endpoint backup does not contain separate issuer key |
| Stateful delivery | Two ASGI relay instances, lost responses, retry deduplication, permission/roster checks and same-identity recovery with empty transport state |
| Invalid application content | Authenticated bad JSON followed by valid memory, no bad-content import or success receipt, cross-node deduplication and bounded quarantine; cryptographic and storage failures still stop processing |
| Actual HTTP | Independent authority and two relay child processes on loopback; invited join, selected-memory transfer and receipts; stop/restart one owned relay, single-copy degradation then exact retry to two copies |
| Cloud compatibility | Real signatures/JWE with substituted Drive HTTP: interrupted upload/resume, recipient byte recovery, 4 MiB split/tamper refusal, configuration and cache exclusion |
| Existing memory | Old eleven-tool MCP journey; core → client → fresh-core byte preservation; exact request retry/conflict handling |
| Static source checks | Plugin manifest validator, module allowlist agreement, Python/JSON parsing and obvious private-path/key-header checks |

The loopback check confirms termination of all child processes it created. It
does not establish HTTPS, separate machines, power-loss behavior, physical
failure domains, a production deployment or any model's understanding.

A later scoped source run completed **15 tests, zero failures/errors/skips**
in 5.673 seconds on CPython 3.11.4: eight complete endpoint-recovery checks,
four existing setup/recovery checks and three node-runtime checks. A separate
three-test node setup run passed in 0.285 seconds. These cover recovery through
the shared client CLI and standalone restore, selected-client mismatch refusal,
real cross-process snapshot write locks, revoked/absent authority, immutable
record bytes, private node registration and real loopback node replacement.
They are source checks, not a new archive or installed-plugin attestation.

The integrated node/recovery candidate completed **70 targeted tests, zero
failures/errors/skips**, in 35.188 seconds on CPython 3.11.4 / Node 22.19.0.
The selected campaign covered the changed network modules and three existing
MCP/canonical-record compatibility checks; it did not run the entire old suite.
Source fingerprints were unchanged during the run. The added checks include
15 independent TypeScript crypto/control tests, eight real-loopback node
transfer tests, the actual prepare/authorize/partial/complete migration CLI,
and file/directory flush fault injection. All test-owned services terminated.
Runtime duration is a local observation, not capacity or throughput evidence.
Static TypeScript compilation, TLS deployment, physical power loss, real cloud
authorization and real-model collaboration were not established by this run.

The subsequent independent-endpoint campaign completed **126 targeted tests,
zero failures/errors/skips**, in 75.229 seconds on CPython 3.11.4 / Node
22.19.0 / macOS arm64. Runtime source fingerprints did not change during the
campaign. It includes independent TS canonical/share/storage/setup checks,
five real-loopback TS/Python peer cases, seven deterministic TS concurrency
cases and five Python concurrent-client schedules over real loopback nodes.
The latter reproduced node replacement and late-page faults before the fix.
Encrypted endpoint recovery resumes a TS-authored queue without changing
canonical bytes, and independent revoked memory trust keeps imported records
quarantined even for active network members. The three original memory/MCP
compatibility checks remain included; the complete old test suite was not run.

A separate strict static check passed all nine network TS modules and the
parent HTTP SDK with TypeScript 5.9.3 and `@types/node` 22.18.6, using `noEmit`,
`NodeNext`, `allowImportingTsExtensions` and ES2022. The isolated compiler and
transitive type package were integrity-checked; they are not runtime package
dependencies. Source tests and type checks do not attest to package installation,
full high-level TS parity, live cloud accounts, real models or cluster capacity.

The earlier base-alpha run used Python 3.12 with cryptography 50.0.1, joserfc 1.7.5,
Starlette 1.6.0, Uvicorn 0.52.4 and HTTPX 0.28.1; the later integrated candidate
used the separately recorded CPython 3.11.4 environment. Independent crypto uses Node
22.19.0 and the existing jose 6.2.10 installation. A supplied interoperability
module now fails explicitly if Node or that module is unavailable. The test
fixture's Starlette/HTTPX deprecation warning is not a test failure; no automatic
dependency upgrade was performed.

## Development after publication: bounded sender replica repair

Python and the independent TypeScript peer now check configured node
incarnations before selecting pending sends, including with receive disabled.
Authenticated replacement invalidates only the affected node's bookkeeping;
the sender reuses persisted ciphertext and request IDs within its budget.
Checks reserve delivery time, node order rotates, and each missing replica
gets a share of remaining delivery time. Concurrent replacement cannot turn
pending work without an explanatory error into an unqualified completed pass.
The new rotation checkpoint is included in full endpoint recovery validation.

The added synthetic tests use real owned HTTP processes, both runtime orders,
nonempty replacement targets, signed current authorization, unchanged record
bytes, slow-node deadlines and a controlled concurrent replacement. No model
is impersonated, no real cloud account is used, and no physical failure-domain
or large-cluster guarantee follows from these checks.

The final related source campaign passed **62 tests with zero failures, errors
or skips** (99.482 seconds), including 26 new Python/TypeScript repair cases.
The selected runtime hashes stayed fixed throughout the run. All twelve network
TypeScript modules also passed strict/no-emit checking using the existing
TypeScript 5.9.3 toolchain. This does not close the separate ranking boundary
or attest that the post-publication changes are installed or released.

This repair requires retained sender outbox data, configured addresses and
current membership/admission. Node-to-node repair without the sender,
automatic rerouting and complete node retirement remain separate work.

## Development after publication: opt-in ranking and storage proofs

The source now offers explicit
`bounded-fragment-bm25+deterministic-concepts/v2` recall/handoff using
[`mv-rank-q64/1` integer arithmetic](RETRIEVAL_V2.md) in Python and TypeScript.
The default v1 is unchanged, including its known expected-failure fixture.
V2 native results and continuation cursors retain the original math profile,
captured clock and selected IDs, while each page rechecks current trust.
Canonical memory, source signatures and the existing index stay unchanged.

Node storage assertions now use the same bounded closed response shape,
positive safe-integer sequence and authenticated node binding in both
implementations. The checks also apply to historical outbox receipts and
complete endpoint backup/restore. Bad or oversized historical proof data is
rejected without silently deleting records, acknowledgments or ciphertext.
The new 64 KiB per-row / 16 MiB aggregate receipt limits can reject oversized
historical state previously accepted by the Python client; automatic repair
of such state is not implemented.

The final integrated campaign selected **98 tests: 97 passed and one existing
v1 boundary remained an expected failure**, with no unexpected failures,
errors or skips (136.679 seconds, CPython 3.11.4 / Node 22.19.0 on macOS).
Runtime and selected-test source fingerprints were unchanged during that run.
It includes ten new v2 cases, seven new storage-proof cases, real owned HTTP
nodes, signed backup/restore followed by both Python and TypeScript retry,
node replacement/replica repair, native six-operation interoperability,
original-record preservation, legacy cloud interface checks and packaging
allowlists. All thirteen network TypeScript modules plus the parent HTTP SDK
also passed strict/no-emit TypeScript 5.9.3 checking (fourteen files).

Restoration still refuses to overwrite an existing destination. A late failed
restore can retain a newly created capture-disabled keys/Vault directory while
its transport transaction rolls back; this is not atomic publication of the
entire destination directory. The malformed signed recovery-package cases
verify rejection after valid AEAD decryption, not only an invalid outer tag.

This is source validation with synthetic data, not a statement that the
post-publication changes are in existing alpha attachments or installed on
any user's machine. It does not establish universal Unicode/runtime parity,
model quality, live cloud authorization or cluster/fault-domain acceptance.

## Development after publication: topic control foundation

The [topic control contract](NETWORK_TOPICS.md) now has independent Python and
TypeScript validators and signers. It reuses the existing identities, strict
JSON and Ed25519 message proofs. Complete signed snapshots preserve withdrawn
grants and member consent; only fresh, same-nonce issuer status can authorize
current recipient selection or cross a checkpoint gap. The process-local
authorization result has both a monotonic deadline and a five-minute maximum,
including when a member's clock is slightly ahead.

An explicitly configured private authority state commits policy/snapshot,
subscription revision, historical idempotency receipt, clock and roster
checkpoint together. Restoring only an old roster cannot revive revoked
membership. New subscription acceptance checks current membership and grant;
an exact old request can retrieve its historical receipt without renewing any
permission. Member clock correction does not block a valid chained withdrawal.
State, topic, request and recipient bounds reject work explicitly and never
evict consent or revocation history to create capacity.

Optional HTTP subscription/status routes reuse that store through a bounded
worker entry, with JSON/encoding checks, body size/time limits and explicit
retryable contention/unknown-commit results. Existing member/node status and
administrative configuration remain compatible. Ordinary clients gain no
server dependency, service startup or automatic installation.

This is not encrypted topic delivery: the six-operation facade, frozen topic
ciphertext, relay polling/acknowledgements and topic-aware recovery/transfer
still need integration. Authorized proof readers can see the complete grant
and consent lists. The next work order is refresh amortization, queue lifecycle,
snapshot deduplication and relay concurrency before routing, complete topic
delivery and node-driven replica repair; see the [development plan](V0_26_PLAN.md).

Scoped integration validation passed **82 tests** with no failure, error, skip
or expected failure; tested source hashes remained fixed. This includes the
new topic control/store/HTTP and independent cross-language checks, plus the
affected crypto, packaging, administration, node and synthetic cloud checks.
All **15 TypeScript sources** passed strict TypeScript 5.9.3 checks. Noninteger
host-object JSON errors now agree between implementations without changing
valid wire bytes or pretending JavaScript distinguishes numeric `1` from `1.0`.
A prior private runner lacked the multiprocessing entry guard; that failed
attempt is retained separately and is not counted as passing evidence.

The store checks include two real competing writer processes, injected durable
write failures, 32 topics, 16 effective recipients and the 4 MiB incoming-state
boundary. Cache exhaustion and complete-poststate capacity failures use reduced
test budgets; they are not production-capacity or throughput certification.
HTTP checks use in-process ASGI, not public services or actual topic ciphertext
delivery. Real cloud authorization, models and physical failure domains remain
outside this campaign. Final archive inspection/execution is separate from
these source tests, and published alpha assets are unchanged.

## Open delivery and release gates

The later native-agent campaign selected **89 tests: 88 passed and one known
ranking test remained an expected failure**, with no unexpected failures,
errors or skips (66.611 seconds, CPython 3.11.4 and Node 22.19.0). It includes
source attribution/freshness metadata, escaped-text pagination, private-key-free
reads, the shared canonical Vault and receipts, real two-node native six-operation
exchange, offline retry, and the unchanged legacy interface checks. The tested
runtime source hashes stayed fixed. A fresh strict check of all twelve network
TS modules plus the parent HTTP SDK passed with zero diagnostics under
TypeScript 5.9.3 / Node types 22.18.6. These are source checks, not proof of a
new plugin installation or real-model behavior. The expected failure below is
not counted as a pass.

- **Default v1 still has a cross-runtime ranking boundary.** A timestamp precision defect
  is fixed, but a separate real fixture still changes first-hit selection at a
  platform floating-point `exp` boundary. Its strict expected-failure regression
  is an open gate, never a passing case. No epsilon or widened score tolerance
  masks the difference. Post-alpha source adds an explicit deterministic v2
  profile; its scoped evidence does not certify every runtime or change v1.
- **No 0.25.2 live-cloud acceptance.** Existing directory/rclone configuration
  is preserved. Native Drive queue checks substitute HTTP; actual account
  authorization, upload, independent download and readback remain unverified.
- **No complete old-client parity or real-model acceptance.** The TS HTTP entry
  shares the Python core; the separate independent endpoint now has a native
  six-operation facade and bounded fragment recall/handoff. Old cloud-worker
  notifications and complete graph/view management are not ported. Three actual models, two
  providers and a local/open-weight runtime still need all-direction handoff tests.
- **No scale certification.** The alpha currently bounds its roster at 256,
  outbox at 1,024 and inbox at 4,096 entries. Those limits do not satisfy the
  planned 1,000 active agents / 72 hours or real multi-day collaboration gate.
- **No automatic replica repair certification.** Two nodes are explicitly sent
  the same ciphertext by a client. Full endpoint recovery now includes
  never-uploaded committed outbox data; the smaller identity-only backup does
  not. Retain original queues until the selected recovery is verified. A drain
  fence or node identity test alone does not demonstrate complete node exit.
  The directed transfer requires an empty target and explicit snapshot-bound
  issuer grant. The post-publication sender repair above can resend into a
  nonempty configured replacement; repair without the sender's retained
  outbox and automatic client rerouting still require separate implementation
  and verification.
- **Bounded rejection, not unlimited resilience to malicious peers.** Local
  rejected-ciphertext bookkeeping is limited to 128 entries / 16 MiB. A full
  quarantine stops cursor advancement. Deeper share structure, record signature
  or import failures still fail closed and may require operator intervention;
  they are not silently skipped or acknowledged.
- **No implicit authority recovery.** Separately back up the issuer key.
  File separation alone does not isolate processes sharing an OS identity.
- **Preserve pre-upgrade backups.** New code reads old client-backup manifests;
  old releases may reject new manifests with the additional native-cache
  exclusion. New-to-old backup compatibility has not been established.
- **Separate publication and installation evidence.** The builders require
  selected source bytes to match committed HEAD; that source gate is preserved.
  Dependency hashes are recorded in the new locks. Final archive privacy review,
  source/asset hashes and actual package execution are separate evidence from
  source tests. Run `scripts/verify_client_package.py` against the built plugin
  to check local save/recall, visible-turn hooks and inert backup restoration
  with synthetic data. Keep real-host upgrade/rollback evidence privately.

Follow [operator setup](NETWORK_QUICKSTART.md) for explicitly provisioned private
test environments. A user-authorized local alpha upgrade additionally requires
preserving the previous installation and configuration, a private memory backup,
and checks against the actual selected package. It does not establish the later
real-model or scale gates, nor require waiting for thousand-agent certification.
