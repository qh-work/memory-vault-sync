# Memory Vault 0.26 implementation baseline

Confirmed by the project owner on 2026-08-31. This baseline supersedes older
planning text that proposed new MCP or A2A network adapters. It preserves old
client interfaces and the existing Git checkout, configuration and history.

## Product and invariants

An authorized agent should read a short guide, connect using its existing
tools, exchange information and preserve memories another model can continue
using. The network is optional for local memory. Memory is an independent
first-class object: tasks, sessions, agents, models, projects, inboxes and
relay nodes may reference it but cannot own it as a parent container.

- The six native operations are `connect`, `remember`, `recall`, `discover`,
  `send`, `receive`. Python, CLI/NDJSON and trusted HTTP call one implementation.
- Preserve canonical memory IDs, bytes, relations and Ed25519 source proofs.
  `network-v1` adds separate transmission/control bookkeeping, not a second
  canonical database or a new endpoint identity registry.
- MCP, A2A, Nostr, Matrix and Graphiti are design references only. Do not add
  protocol adapters, compatibility claims, task/room ownership, NIP semantics
  or a graph-database dependency. The already shipped MCP memory tools remain.
- Signing and encryption keys are separate. New setups also separate network
  administration keys from the ordinary endpoint signing identity.
- JWE General JSON uses mature libraries and the fixed X25519 /
  `ECDH-ES+A256KW` / `A256GCM` profile. Relays cannot decrypt content; necessary
  routing, time and size metadata remain visible. No anonymity claim.
- Short-lived single-use invitations bind both recipient keys, permissions
  and selected handoff content. Trust roots are configured independently.
  Signed membership changes reject rollback; publishing requires current
  issuer status valid for at most 300 seconds. Local reads/writes stay offline.
- All entries share storage, identity, authorization, encryption, message,
  receipt, retry and error semantics. Memory text cannot change any of them.

## State when development resumed

The existing branch is `feat/v0.26-network-alpha`, based on
`e03de3ec02026f3c13c6af3cb194318f87beec28`. Recent commits restored bounded
original-file transfer, explicitly unlocked encrypted rclone configuration,
private artifact migration and the committed-source release gate. None is
replaced or rebound by this development work.

The interrupted working tree already contained native network crypto, issuer
control, relay, client, setup/recovery, an agent facade, TypeScript crypto
interop fixtures and native Drive queue integration. These were uncommitted
implementation candidates. They were reviewed before changing them; their
existence was not treated as completed delivery or production acceptance.

## Current work and evidence gates

| Work | Delivery criterion |
|---|---|
| Native interface | Same records and exact retry/error behavior through Python, independent TypeScript, NDJSON and HTTP; no new external adapter |
| Inherited evidence | Attribute prior attempts to known original sources; do not invent an origin or claim the reader performed them. Revalidate old failure causes when the environment changes or applicability is uncertain; no automatic execution or new permission. |
| Trust and recovery | Separate authority/member keys; member cannot issue trusted rosters; old explicit configurations remain readable with warnings |
| Delivery | Invited clients exchange selected memory, verify/save locally, acknowledge, retry offline and resume after transport-state recovery |
| Private relay | Real loopback HTTP with two separately controlled relay processes; degradation and restart observed, without claiming independent hardware failure domains |
| Cross-language crypto | Independent Python/TypeScript seal/open in both directions, exact opaque bytes including Unicode and 64-bit values; rejection of malformed input |
| Existing users | Old memory bytes and source proofs preserved; personal backup, handoff, old MCP and configured sync continue; old backups retained for rollback |
| 0.25.x cloud maintenance | Keep current directory/rclone behavior; verify optional native encrypted Drive separately; real authorization/upload/readback is a distinct open gate |
| Release preparation | Review public allowlist, exact source, pinned dependencies/hashes and package contents; do not weaken the committed-source gate or include private material |

The TypeScript companion now includes an independent persistent endpoint as
well as the HTTP entry. It reuses the existing identity documents, canonical
SQLite Vault and network queue schema; real loopback tests continue the same
queue between Python and TypeScript. The native six-operation facade now uses
the same bounded fragment ranking and structural handoff selection. It shares
the Vault, identity, permissions and errors; it is not a second data system.
Default-v1 numerical ranking parity remains open: a reproducible platform
`exp` boundary changes the first selected ID. Post-alpha source preserves its
expected-failure test and adds an explicit [integer v2 profile](RETRIEVAL_V2.md),
shared by both implementations without a tolerance or default-formula change.
Node storage-response shape, signature/binding and size checks are also shared;
malformed historical receipts remain preserved and fail explicitly.
Whole-endpoint recovery includes committed transport state and has targeted
synthetic recovery tests. Development after the alpha adds bounded sender
repair: pump checks configured node incarnations before selecting pending
outbox work, then reuses ciphertext after an authenticated replacement. This
does not implement node-to-node repair without sender state or client rerouting.
Complete legacy graph/view and cloud-worker parity, scheduled pumping,
topics/subscriptions, resource leases and automatic replica repair/exit remain
separate work. Interfaces or examples alone must not mark them delivered;
see the [TypeScript scope](NETWORK_TYPESCRIPT.md) and current evidence below.

Post-alpha [topic control](NETWORK_TOPICS.md) adds independently pinned signed
policies, complete consent snapshots and bounded durable subscription changes.
It reuses network identities and leaves canonical memory ownership unchanged.
This is the control foundation only: encrypted topic fan-out, native facade
integration, relay polling/acknowledgement and topic recovery/transfer remain
unfinished. The published alpha assets are not replaced by these source changes.

## Next priority: sustained operation before expansion

The next sequence is authorization refresh, queue lifecycle, deduplicated
member snapshots, then relay concurrency. Sharded routing, complete topic
delivery and node-to-node replica repair follow those foundations. Finishing
topic control does not promote encrypted topic delivery ahead of this sequence.

Source inspection confirms the following current limits. They are bounded
preview behavior, not evidence of sustained operation at their numerical caps.

| Area | Current behavior | Next acceptance requirement |
|---|---|---|
| Refresh | Sends, receives and replica checks refresh each selected relay. Its 256 status-nonce rows remain occupied until 300-second expiry, including completed challenges. | Amortize authenticated refresh and concurrent refresh attempts without extending five-minute authority, losing node binding or accepting rollback/replayed challenges. Test sustained polling beyond the current cumulative challenge limit. |
| Lifecycle | Endpoint outbox retains up to 1,024 rows; relay defaults bound 4,096 ciphertext objects. Saved receipts do not currently retire completed history. | Separate live pending work from bounded replay/receipt evidence and explicitly retained memory. Reclaim only eligible transport state, with offline recipients, exact retries and restore semantics preserved. |
| Member snapshots | Each relay message and frozen sender row stores its full historical signed roster. | Store each verified canonical snapshot once by digest; reference it without changing signed bytes or deleting snapshots still required by retained messages/recovery. |
| Concurrency | Relay reads and writes share a nonblocking process/file lock; each new message scans the entire ciphertext directory for usage. | Establish durable incremental accounting and bounded recovery reconciliation, then separate safe reads from write transactions. Test concurrent readers/writers, crash windows and accurate capacity rejection. |
| Routing and repair | Roster cap is 256, endpoints configure one or two relays, sender repair requires its retained outbox. | Add measured sharding/routing and node-driven repair with verifiable retained replicas. Raising a cap does not count as delivery or scale acceptance. |

Authorized network memory discovery, reference location and retrieval remain a
separate missing capability beyond local recall and selected memory exchange.
Its design must retain encrypted queries and explicit sharing permissions;
no relay plaintext search index or parent memory container is implied. Topic
control and encrypted topic delivery continue to have separate acceptance gates.

## Sequence and limits

0.26 network development is the main line; 0.25.x cloud maintenance runs in
parallel without removing old capabilities or rewriting published releases.
The current alpha is not automatically installed over the user's stable client.
No public server, resource purchase, automatic agent launch or autostart item
is part of this phase. Nodes may run only within their owner's prior resource
authorization. HTTP-only hosts need a trusted endpoint with encryption keys;
an untrusted relay is never a substitute for that endpoint.

After the functional alpha, prove three real models from at least two providers,
including a local/open-weight runtime, can hand off in all directions and resume.
Then verify 10–100 actual agents, 1,000 concurrently active agents for 72 hours,
and the separately retained multi-day requirement of 1,200 real run instances
and 70,000 deduplicated meaningful messages/artifacts with verifiable outcomes.
Simulated clients, renamed identities or heartbeat volume cannot satisfy those
gates. Physical sharding and federation require their own measured evidence.

See [network semantics](NETWORK_V1.md), [setup](NETWORK_QUICKSTART.md) and
[actual alpha evidence](RELEASE_NOTES_V0_26_ALPHA.md) for implementation status.
