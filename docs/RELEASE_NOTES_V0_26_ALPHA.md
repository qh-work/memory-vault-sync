# 0.26.0-alpha.1 development evidence

Date: 2026-08-31. This is an **unreleased development candidate**
on the existing `feat/v0.26-network-alpha` branch, based on
`e03de3ec02026f3c13c6af3cb194318f87beec28`. This source report does not attest
to installation or cloud authorization on any user's machine. A built
candidate has a separate source manifest and package verification result.
This report is not an immutable release attestation.

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
  Full ranking, graph and dynamic handoff parity remain unimplemented.
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

## Open delivery and release gates

- **No 0.25.2 live-cloud acceptance.** Existing directory/rclone configuration
  is preserved. Native Drive queue checks substitute HTTP; actual account
  authorization, upload, independent download and readback remain unverified.
- **No full TypeScript high-level parity or real-model acceptance.** The native
  TS HTTP entry shares the Python core; the separate independent endpoint has
  persistent storage and delivery, but its bounded local text matching is not
  Python ranking, graph or dynamic handoff parity. Three actual models, two
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
  issuer grant; automatic repair into a nonempty peer and client rerouting
  still require separate implementation and verification.
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
- **No public publication or blanket installation claim.** The builders require
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
