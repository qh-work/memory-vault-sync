# Independent TypeScript endpoint preview

The `clients/typescript/network` implementation provides the native `Agent`,
`NetworkPeer` and `CanonicalVault`. It uses the existing Memory Vault record bytes, Ed25519 and
X25519 identities, SQLite schemas and persistent network queues directly. It
does not start a Python subprocess or delegate its cryptography, record checks,
storage, or network delivery to a Python bridge.

This is a scoped independent endpoint preview. Native `Agent.recall` uses the
same bounded fragment BM25/concept ranking and structural handoff selection as
Python. **The default v1 still has a known floating-point boundary:**
one real fixture still differs by one integer score after platform `exp`
rounding and changes the first selected ID. The test records this as an open
expected failure, not a pass; no epsilon hides it. The separate microsecond
date-conversion defect is fixed. Post-alpha source adds explicit
`ranking_profile: 'bounded-fragment-bm25+deterministic-concepts/v2'`, using the
same [specified integer arithmetic](RETRIEVAL_V2.md) in both implementations.
This does not replace v1 or establish parity for every host Unicode/runtime
version. V2 native cursors preserve the original profile and ranking clock
alongside the selected IDs, with current trust checked on every page.
`CanonicalVault.retrieve` exposes the current profile; the older low-level
`CanonicalVault.recall` is still a bounded substring utility and explicitly
reports `python_ranking_equivalent: false`. Full graph/view management and the
legacy cloud worker have not been ported. The current
network still has a 256-member roster limit; this is not a thousand-agent
certification or evidence of unlimited shared storage.

## Two distinct TypeScript entry points

| Entry | What runs locally | Trust boundary |
| --- | --- | --- |
| `clients/typescript/index.ts` | Dependency-free HTTP SDK for the six operations at `/v1/agent` | An explicitly trusted endpoint receives plaintext and uses the shared Python core. This entry remains supported. |
| `clients/typescript/network/peer.ts` and `vault.ts` | Independent protocol, encryption, canonical records, private SQLite storage and persistent queues | Keys and plaintext stay at this endpoint; ordinary relays hold ciphertext and necessary routing metadata. |
| `clients/typescript/network/agent.ts` | The six native operations over those same records, current trust and persistent queues, including local retrieval/handoff | No Python subprocess or trusted remote plaintext bridge is used by this native entry. |

The first entry has not silently changed into a direct relay client. A host
that can only issue HTTP requests still needs its explicitly trusted endpoint
or a trusted local encryption/key bridge. A relay is not that bridge.

## Runtime and dependencies

The tested runtime is Node 22.19.0 on macOS, using built-in TypeScript stripping
and experimental `node:sqlite`. Private storage currently requires POSIX owner,
permission and no-symlink checks; Windows is rejected rather than given a weaker
storage mode. Support for every POSIX platform or later Node release has not
been demonstrated by the current tests.

The network package's only external dependency is `jose` 6.2.10, pinned by its
`package.json` and integrity-bearing `package-lock.json`. Dependency installation
is a separate, explicit operator action. Importing these modules never installs
packages, reads ambient account credentials, creates a service, or sends a
message. Python server dependencies are not ordinary TypeScript or Python client
dependencies. The public package includes selected source files, not
`node_modules` or a machine's installed dependency tree.

Examples below assume a script run from the source checkout with an explicitly
prepared dependency and private configuration. Node 22.19 uses
`node --experimental-strip-types your-script.mts`. All paths, domains, request
IDs and text below are synthetic placeholders.

## Native six-operation entry

```ts
import { Agent } from './clients/typescript/network/agent.ts';
const agent = new Agent('/absolute/private/client.json', '/absolute/private/network.json');
const info = await agent.handle({op: 'discover'});
const saved = await agent.handle({op: 'remember', kind: 'observation',
  text: 'Synthetic historical attempt; current environment must be checked.',
  request_id: 'req_synthetic_agent_note_01'});
const recalled = await agent.handle({op: 'recall', query: 'historical attempt', handoff: true});
```

Construction and offline discovery do not read configuration, open files, load
keys or access the network. Local reads do not create a missing Vault or load a
signing private key. A configured signing failure never downgrades a write to
unsigned; a client deliberately configured without an identity may save the
same `local_unsigned` records as Python. The facade shares exact write receipts
and frozen recall cursors with Python; query selection and each later page use
current independent trust. Explicit ID inspection may return revoked historical
evidence with `eligible_for_context: false`; query recall excludes it. Neither
case grants execution authority.

The native facade does not start the old Python cloud worker or emit its sync
notification. Keep the existing Python client for automatic 0.25.x cloud sync;
this preview does not silently rewrite that configuration or claim old-client
feature parity. Local writes remain durable in the same Vault.

Inherited attempts must be attributed to their known original source rather
than called the reader's own experience. Unknown provenance stays unknown;
signer verification does not independently verify claimed agent/model/session
labels. Record creation time is not a fresh environment check. Revalidate old
failure causes when relevant conditions change or applicability is uncertain,
using only existing authorized tools. Recall and receive do not execute retries.
See [the agent usage contract](../AI_START_HERE.md#attribute-inherited-evidence-and-recheck-old-failures).

Recall hits include `recorded_at`, bounded `provenance_refs`, an explicit
truncation flag and `provenance_status`. Recall and receive both include
`evidence_usage`: historical evidence, no assumed personal experience, current
environment not checked, and no automatic retry of remembered failures. The
reference fields are claims; the original `verification` still separately
reports signer admission. Their combined JSON budget is 256 bytes per hit;
canonical records retain full provenance. Pagination accounts for JSON escapes
and all metadata before consuming text, so a full page leaves the unconsumed
ID and byte offset in `next_cursor`.

## Explicit provisioning

`setup.ts` exposes synchronous, local-only helpers:

* `createIdentity(directory)` creates a **new** private endpoint directory with
  `identity.json`, `encryption.json`, `trust.json`, `member-public.json` and
  `client.json`. It creates no Vault, issuer authority, network membership or
  service. The two keys retain the existing identity schemas and key IDs.
* `configureNetwork({clientConfig, encryptionKey, issuerPublic, networkId,
  authorityUrl, relays, output})` writes a **new** network configuration after
  validating the explicit local inputs. It does not consume an invitation,
  contact a node, create a Vault or enroll a key.

New private directories use mode `0700` and new files use `0600`; existing
outputs are not overwritten. A fresh configuration filename cannot silently
adopt an already existing matching transport-state directory. Use the explicit
recovery or migration workflow for old state. Setup does not rewrite an existing
client configuration, trust registry or Vault.

```ts
import { createIdentity, configureNetwork } from './clients/typescript/network/setup.ts';

// The owner has already prepared a protected parent directory and independently
// obtained the correct issuer public descriptor. These are explicit local writes.
const created = createIdentity('/absolute/private/synthetic-agent-new');
const configured = configureNetwork({
  clientConfig: created.client_config,
  encryptionKey: created.encryption_key,
  issuerPublic: '/absolute/private/pinned-issuer-public.json',
  networkId: 'synthetic-network',
  authorityUrl: 'https://authority.example.invalid',
  relays: ['https://relay.example.invalid'],
  output: '/absolute/private/synthetic-agent-new/network.json',
});
```

Only the public member descriptor is intended for candidate registration.
Do not share the private endpoint directory. Do not trust an issuer merely
because an invitation carried its public key. Configuring an already explicitly
selected issuer with the same signing key as the endpoint reports a warning;
it does not create or recommend that arrangement. Prefer a separate owner-held
issuer identity.

## Local memory and explicit communication

Constructing `NetworkPeer` reads the supplied private configuration and keys and
opens its local Vault. Opening an empty Vault can initialize its schema; opening
a compatible Vault can add missing derived state. Construction is therefore
local I/O, not a read-only inspection. It does not connect to the network.

```ts
import { NetworkPeer } from './clients/typescript/network/peer.ts';

const peer = new NetworkPeer('/absolute/private/synthetic-agent-new/network.json');
try {
  const saved = peer.vault.remember({
    requestId: 'req_synthetic_note_0001',
    kind: 'observation',
    text: 'Synthetic observation; historical evidence, not execution authority.',
  });
  const exact = peer.vault.get(saved.memory_id);
  const matches = peer.vault.recall('synthetic', {
    limit: 4, maximumScanned: 100, maximumBytes: 65536, maximumSeconds: 2,
  });
  // matches.partial and matches.nextAfter describe a bounded local scan.
} finally {
  peer.close();
}
```

`CanonicalVault` is also directly available from `vault.ts`, with
`new CanonicalVault({vaultPath, identity, trust})`. Its `trust` option accepts
explicit public signing descriptors or a function returning the current set.
Supplying a trust policy never implicitly adds the local key to that policy.
By default writing requires a trusted local signer; verified reads and share release use
current independently selected trust. `get`, `verification`, `remember`,
`recall`, `exportShare` and `importShare` preserve the existing record/signature
domains. Untrusted share authors do not become trusted because a network member
sent their records. Quarantined data does not grant execution permission.
`retrieve({query, handoff, limit, maximum_context_bytes})` exposes the original
bounded retrieval profile. Its disposable full-record index uses the same
token frequencies, entities and timeline keys as Python. Read-only retrieval
does not repair indexes or change canonical records.

These network methods are separate explicit actions on an open `peer`:

| Method | Action |
| --- | --- |
| `await peer.connect(invitation, stableJoinRequestId)` | Verify the pinned issuer/candidate binding and consume the invitation at configured nodes. Without an invitation, check existing admission. |
| `await peer.discover()` | Refresh signed control state and return a bounded view of active members. |
| `await peer.send(stableRequestId, recipientKeyIds, text, memoryIds)` | Save selected local content, persist an outbox entry, and attempt encrypted delivery. |
| `await peer.receive(4)` | Fetch, verify, decrypt and persist a bounded batch, then submit signed endpoint-storage acknowledgements. |
| `await peer.pump(4, 10, 4)` | Perform one explicit retry/receive pass: at most four outbox attempts, a ten-second cooperative deadline and up to four incoming messages. |

Reuse a request ID only for the exact same original input. A persisted envelope
is reused on retry; changing inputs under an existing ID fails. Close the peer
after awaiting its work. A caller-supplied transport remains caller-owned and
must implement the same transport contract; only the built-in transport has the
documented hard HTTP timeout/response bounds.

The outbox may report `queued_local` even when one relay has stored a copy.
Check `stored_nodes`, `configured_nodes`, `degraded` and errors. A `stored`
receipt is a signed storage assertion, not proof of future retention or an
independent physical fault domain. `validated_saved` means receiver persistence
and verification; it never means model understanding or task completion.
Post-alpha source verifies the complete stored response with the same closed
4-field legacy or 5-field signed shape as Python, a positive safe-integer
sequence and a 16 KiB limit. The signed form must match an independently
authenticated node binding, never a key supplied by the receipt itself. The
low-level verifier requires an explicit flag for unsigned legacy responses;
native peers retain their existing unbound legacy-node path. An established
node binding never permits an unsigned downgrade. No new operator approval
or legacy-mode configuration is introduced by this change.
Received text previews can be truncated; inspect `text_partial` and
`text_memory_id` instead of treating the preview as complete content. Starting
an endpoint does not launch other
agents, run received instructions, or subscribe to an unlimited background loop.

## Bounds and private state

| Area | Current bound |
| --- | --- |
| Configured relays | One or two explicit origins; no network scanning |
| Member/node directory | At most 256 members and 256 storage-node entries |
| One peer send | At most 16 recipients, 16 KiB UTF-8 text and 32 explicitly selected memory IDs; network share at most 2 MiB |
| Crypto carrier / HTTP document | At most 4 MiB plaintext, 6 MiB envelope, 8 MiB HTTP body |
| Peer queues | At most 1,024 outbox rows and 4,096 inbox rows, with 256 MiB content budgets; quarantine at most 128 rows / 16 MiB |
| Stored responses | 16 KiB each; historical per-message receipt JSON at most 64 KiB and all outbox receipt JSON at most 16 MiB, checked before materializing those payloads |
| HTTP | No redirects or decompression; verified HTTPS except explicit loopback HTTP; at most ten seconds per built-in request or the earlier caller deadline |
| Pump | Zero to 16 outgoing attempts, one to 60 seconds, zero to four incoming messages per call |
| Native recall/handoff | At most 32 selected IDs, four hits per page, up to 768 UTF-8 text bytes per hit within the 8 KiB response; follow `next_cursor` |
| Bounded substring utility | `CanonicalVault.recall`: one to 64 results, one to 1,024 scanned rows, one to 30 seconds, and an explicit result-byte limit; follow `nextAfter` when `partial` |
| Local share | At most 256 records / 8 MiB, with bounded dependency closure and an explicit time limit; the peer's smaller network-share limit still applies |

Filesystem-backed state uses explicit absolute paths, protected ownership and
permissions, SQLite WAL and full synchronization. Memory and transport databases
are separate. Existing compatible Python and TypeScript endpoints can reuse the
same schemas, signing identity and frozen outbox rows; a configuration-binding
mismatch fails rather than retargeting old state. Node key/URL/storage-epoch
bindings and fresh signed directory checkpoints govern delivery cursors and
receipts. A legitimate node replacement resets only that URL's delivery state;
a lagging refresh cannot overwrite a later directory already stored locally.

Keep private keys, configurations, Vaults, transport databases, recovery files
and invitations out of source trees and public archives. Do not copy only a live
SQLite main file while WAL data may be pending. Use the explicit
[backup and inactive restore workflow](NETWORK_RECOVERY.md); restored keys do
not bypass current revocation checks. Long-term memory IDs do not become children
of a node, inbox, model or task.

## Evidence and limits

The current synthetic runtime evidence includes Python-to-TypeScript and
TypeScript-to-Python canonical record/share verification, private Vault and trust
checks, and real loopback HTTP communication between independently running
Python and TypeScript endpoints. The five peer cases cover invitation/join,
bidirectional messages with original proofs, interrupted reply/retry and restart,
Python/TypeScript continuation of the same queue, and revocation blocking sends.
They also restore an encrypted TS endpoint snapshot through the Python recovery
tool and resume it in TS only after fresh issuer status. Active network
membership cannot admit a sender's memory when independent memory trust has
revoked that sender; the original record is kept in quarantine.

The focused suites are `test_network_typescript_crypto.py`, `control.py`,
`nodes.py`, `records.py`, `vault.py`, `peer.py`, `transport.py`, `peer_race.py` and `setup.py`
under `tests/`, all with the `test_network_typescript_` filename prefix. The
transport tests use real owned loopback sockets, including self-signed TLS
rejection despite an ambient TLS-disable setting. The race tests use real
signatures and two SQLite connections in **one process**, with deterministic
interleavings during refresh, poll, admission and acknowledgement. They reject
late results from replaced nodes and preserve monotonic progress for concurrent
reads from the same node; they are not a multi-process stress test.

No dependency is installed by these tests. When Node or an explicitly supplied
existing `jose` is unavailable, a skipped test is not verification evidence.
An independent static check on 2026-08-31 passed all nine network TypeScript
modules and the parent HTTP SDK with TypeScript 5.9.3 and `@types/node` 22.18.6,
using `strict`, `noEmit`, `NodeNext`, `allowImportingTsExtensions` and ES2022.
The isolated development toolchain was integrity-checked and is not a runtime
dependency or part of the distributed package.

The subsequent native-agent campaign on the same runtime selected 89 tests:
88 passed and the explicit `exp` ranking boundary remained one expected failure;
there were no unexpected failures, errors or skips. It also checked all twelve
network TS modules plus the parent HTTP SDK under the strict compiler settings
above with zero diagnostics. The native facade tests cover both languages'
source/freshness metadata, budget-aware complete pagination and signed/unsigned
read/write behavior; two real-loopback cases exercise all six operations and
offline recovery with original ciphertext and signed receipts. A separate
review preserved the default signed receipt trust isolation.

These checks do not establish exact cross-runtime ranking at all numerical
boundaries, complete legacy-client parity, Windows support,
three-model/two-provider acceptance, physical fault-domain durability, or
large-cluster capacity. Those gates remain separate from this preview.
