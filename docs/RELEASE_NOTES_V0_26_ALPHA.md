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

The observed test runtime is Python 3.12 with cryptography 50.0.1, joserfc 1.7.5,
Starlette 1.6.0, Uvicorn 0.52.4 and HTTPX 0.28.1. Independent crypto uses Node
22.19.0 and the existing jose 6.2.10 installation. A supplied interoperability
module now fails explicitly if Node or that module is unavailable. The test
fixture's Starlette/HTTPX deprecation warning is not a test failure; no automatic
dependency upgrade was performed.

## Open delivery and release gates

- **No 0.25.2 live-cloud acceptance.** Existing directory/rclone configuration
  is preserved. Native Drive queue checks substitute HTTP; actual account
  authorization, upload, independent download and readback remain unverified.
- **No independent full TypeScript peer or real-model acceptance.** The native
  TS HTTP entry shares the Python core; a separate TS crypto fixture verifies
  the wire primitives. Three actual models, two providers
  and a local/open-weight runtime still need all-direction handoff tests.
- **No scale certification.** The alpha currently bounds its roster at 256,
  outbox at 1,024 and inbox at 4,096 entries. Those limits do not satisfy the
  planned 1,000 active agents / 72 hours or real multi-day collaboration gate.
- **No automatic replica repair or complete endpoint backup.** Two nodes are
  explicitly sent the same ciphertext by a client. Replaying old delivery state
  does not recover never-uploaded outbox data. Keep original offline queues.
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
