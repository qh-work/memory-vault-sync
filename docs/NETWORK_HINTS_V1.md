# Authorized Memory Hint exchange

Historical v1 design and validation notes. The current candidate uses
[Hint v2 frozen pagination](NETWORK_HINTS_V2.md); v1 control shapes are no longer accepted.

Status: **unreleased candidate after v0.26.0-alpha.4**. This is a bounded
exchange between known, configured endpoints. It is not global search, open
P2P, a public service, or a capacity certification. Test only with isolated
synthetic state; private installation upgrades remain deferred.

## Discover before selecting an ID

A recipient can know another endpoint's signing identity without knowing its
memory IDs. It sends a typed query, reads at most four permitted hints, and
explicitly selects one. The provider checks its current local sharing policy
and current network membership before responding. Hint visibility and full
record access are independent grants.

All operations reuse `network-v1`, the existing separate signing/encryption
keys, authenticated JWE carrier, outbox, inbox and receipts. No additional
memory database, relay index or authority is introduced. The six native
operations remain `connect`, `remember`, `recall`, `discover`, `send`, `receive`.
This exchange uses typed controls on `send` and an explicit `respond_to`
selector on `receive`; ordinary chat strings are never parsed as commands.

A trusted local host configures the provider with `set_hint_policy` in Python
or `setHintPolicy` in TypeScript. This is a local configuration method, not a
remote Agent operation. A policy has this exact shape (values below are
placeholders, not usable credentials or granted identities):

```json
{
  "schema_version": "memory-vault-hint-policy/v1",
  "network_id": "CONFIGURED_NETWORK_ID",
  "owner_key_id": "PROVIDER_SIGNING_KEY_ID",
  "revision": 1,
  "expires_at": 0,
  "peers": [{
    "key_id": "RECIPIENT_SIGNING_KEY_ID",
    "hint_memory_ids": ["EXPLICITLY_HINT_VISIBLE_MEMORY_ID"],
    "record_memory_ids": ["EXPLICITLY_SHAREABLE_ROOT_AND_DEPENDENCY_IDS"]
  }]
}
```

Replace the expiry with a future Unix time, at most 24 hours from the setter
call. The private file is `hint-policy.json` in the endpoint's transport state
directory. There can be at most 16 peers, 128 unique IDs in each grant list,
and 65,536 canonical JSON bytes in the whole policy. Revisions are increasing
safe integers; the same revision permits only an identical retry. Empty grants
revoke access. Missing, expired or invalid policy denies access. Network
membership, a query, a hint and remembered prose cannot create these grants.

Granting a hint discloses its memory ID, a text excerpt and epistemic type.
Those fields are not public by default. Full-record grants must explicitly
include every dependency; seeing a hint never grants that closure. A normal
local `send(memory_ids=...)` remains a separately explicit sharing decision.
No remote control can invoke that unrestricted local path.

## Small explicit workflow

1. B sends to known A using `send` with `request_id`, one `recipients` entry,
   and `control:{schema_version:"memory-vault-hint/v1",kind:"query",query:"X"}`.
   The request contains no memory ID.
2. A polls `receive`, then calls `receive(respond_to:QUERY_MESSAGE_ID)` to
   handle that one already authenticated inbox request. This does not start a
   background agent or infer execution authority from the message.
3. B polls, then reads `receive(message_id:OFFER_MESSAGE_ID)`. Its `control`
   contains zero to four hints. Queries only match admitted records in A's
   explicitly bounded hint grant set. Matching is a case-sensitive Unicode
   substring of the original text, with memory-ID ordering. It does not scan
   unrelated memories or claim relevance, current-goal, truth or trust ranking.
4. B explicitly sends `control:{schema_version:"memory-vault-hint/v1",
   kind:"select",offer_message_id:OFFER_MESSAGE_ID,memory_id:CHOSEN_MEMORY_ID}`
   to A. Its local endpoint checks the received offer and its sender first.
5. A polls and calls `receive(respond_to:SELECTION_MESSAGE_ID)`. A checks its
   own original offer, the authenticated recipient and all current grants.
   It computes the complete closure in the same read snapshot used for export,
   authorizes every root and dependency, and only then serializes the share.
6. B polls the resulting transfer. Before import, B checks that its own stored
   selection matches this sender, request, offer and root. Existing canonical
   records, original Ed25519 proofs and independent local admission still apply.

A denied or unavailable selection returns the same bounded `refusal` with
`reason:"not_available"`; it does not disclose missing dependency IDs or counts.
The selected original closure also passes the existing finite publication
guard in Python and its equivalent in the new TypeScript Hint export path.
Obvious secret patterns or local paths produce the same content-free refusal.
This heuristic is not comprehensive DLP or a substitute for owner grants; it
does not scan or classify all personal information. Old manual TypeScript
exports are outside this incremental Hint guard change.

A denied dependency rejects the whole transfer. The implementation never drops
a relation, rewrites evidence or substitutes a new record to make it fit a grant.

## Closed, bounded control payloads

The extension adds two explicit variants to the existing
`memory-vault-network-content/v2` union:

- `hint_control`: exact outer fields `schema_version`, `kind`, `control`.
- `hint_transfer`: exact outer fields `schema_version`, `kind`,
  `request_message_id`, `offer_message_id`, `memory_id`, `expires_at`, `share`.

The inner `memory-vault-hint/v1` control shapes are:

| Kind | Fields besides schema_version and kind |
| --- | --- |
| `query` | `query`, nonempty and at most 256 UTF-8 bytes |
| `hints` | `request_message_id`, `expires_at`, `hints` |
| `select` | `offer_message_id`, `memory_id` |
| `refusal` | `request_message_id`, `reason:"not_available"` |

Each hint contains exactly `memory_id`, `excerpt` (at most 128 UTF-8 bytes,
without splitting a code point), and the supported `epistemic_type` enum.
There are at most four unique hints. No relation IDs, provenance graphs,
evidence references or arbitrary Experience metadata are projected. The
original share, if separately authorized, still contains the complete record.
Controls are limited to 4,096 canonical JSON bytes; Agent results retain the
8,192-byte limit. Unknown/mixed/extra/duplicate fields are rejected. `send`
accepts only query/select controls, one recipient, and no simultaneous text
or memory selection. Responses come from `receive(respond_to=...)`.

`respond_to` cannot be combined with polling limits, local message selection
or offsets. A control's full bounded structure is read using `message_id`;
chat and transfer-note paging keep their existing semantics. Control text and
hint-transfer notes are empty, and `text_memory_id` stays null.

## Retry, revocation and recovery

An offer expires no later than five minutes after it is generated or the
policy expiry, whichever comes first. Selection and first transfer acceptance
check expiry. Repeated handling of the same inbox request reuses the same
persisted response; it cannot refresh a stale offer or choose new records.
A new query needs a new request ID. Accepted historical inbox evidence remains
readable after offer expiry.

Current network scope and local policy are checked during request handling and
again at every actual send start, including a frozen outbox retry or `pump`.
The final local grant check occurs after asynchronous membership refresh and
sealing, directly before passing bytes to the transport. That is the
send-start boundary: revocation cannot retract a transmission that has already
started, a stored relay copy, or a recipient's plaintext. Missing grants pause
the existing response; a retry never silently exports different bytes.

Guarding derives from the typed response body, including the complete bounded
share and recipient-bound original offer. There is no removable sidecar whose
absence downgrades a policy-bound transfer into a normal local send.

Endpoint backup preserves supported controls and frozen transfers, but
**excludes the local hint policy**. Restore into a new endpoint does not revive
old sharing rights. Policy-dependent pending responses require a new explicit
local grant, in addition to fresh network authority checks. Control-only
snapshots do not create a source Vault; received original transfers still
require matching canonical records in the snapshot. Restored transport remains
historical evidence, not permission to execute tasks.

## Evidence, privacy and scope

Queries, offers, selections and refusals only occupy bounded transport state.
They never create an observation, a retrieval-index entry or an independent
confirmation. Importing original records preserves their authors; B does not
acquire A's first-person experience. The hint's epistemic type describes a
record's claimed knowledge type, not validation or permission.

The relay sees necessary routing, timing and sizes, not hint text, queries or
record bodies. This is not traffic anonymity. A permitted hint is already a
disclosure; do not grant it merely because a peer belongs to the network.

This candidate adds no global discovery, subscription gossip, new truth score,
automatic memory promotion, runtime execution permission or private migration.
Older preview endpoints can reject the new typed content; no unsafe downgrade
or conversion is attempted. Existing record IDs, canonical bytes and signature
formats are unchanged.

## Validation

The first three groups below describe initial candidate
`0262409694b604f9a08c2276a06c565ce4d5a593`; the subsequent R1 section records the
focused repair and its separately executed regression set.

The focused synthetic tests are `test_network_hints`,
`test_network_hints_typescript`, and `test_network_hints_recovery`. They exercise
actual existing cryptographic libraries and temporary endpoints; those endpoints
are not real-model or cross-host scale evidence. Exact executed commands and
results follow, with existing regressions kept separate from new test counts.

Executed on 2026-09-07 with Python 3.12.0b4, Node 22.19.0, real `jose` 6.2.10,
`joserfc` 1.7.5, `cryptography` 50.0.1, `httpx` 0.28.1 and `starlette` 1.6.0.
No replacement crypto, new paid resources or private deployment was used.
Set `MEMORY_VAULT_NODE` to that runtime and `MEMORY_VAULT_JOSE_MODULE` to the
installed pinned jose webapi entry as described in the dependency guide.
`PYTHONDONTWRITEBYTECODE=1` was set. Below, `python` denotes that test interpreter;
these are the actual test selections, with environment-specific paths omitted.

### New Hint flow and recovery

```sh
python -B -m unittest -v \
  tests.test_network_hints \
  tests.test_network_hints_typescript \
  tests.test_network_hints_recovery
```

Verbatim unittest summary:

```text
Ran 22 tests in 40.719s

OK
```

### Direct message, delivery, entrypoint and packaging regressions

```sh
python -B -m unittest -v \
  tests.test_network_message_semantics \
  tests.test_network_message_typescript \
  tests.test_network_agent \
  tests.test_network_typescript_agent \
  tests.test_network_typescript_agent_network \
  tests.test_network_client \
  tests.test_network_worker \
  tests.test_network_recovery \
  tests.test_network_typescript_peer_race \
  tests.test_network_packaging
```

Verbatim unittest summary:

```text
Ran 76 tests in 60.320s

OK
```

### Experience, immutable sharing and signature regressions

```sh
python -B -m unittest -v \
  tests.test_experience_origin_identity \
  tests.test_experience_origin_typescript \
  tests.test_experience_int64 \
  tests.test_experience_http_int64 \
  tests.test_v025_sharing \
  tests.test_network_typescript_records.TypeScriptRecordTests.test_original_bytes_ids_and_domain_separated_signatures_both_directions \
  tests.test_network_typescript_records.TypeScriptRecordTests.test_python_export_is_parsed_and_typescript_share_is_python_verified \
  tests.test_network_typescript_records.TypeScriptRecordTests.test_share_checksum_does_not_grant_trust_and_closure_cannot_smuggle
```

Verbatim unittest summary:

```text
Ran 53 tests in 17.147s

OK
```

The three groups contain **151 distinct test methods**, all passing with no
skips. Repeated runs and subcases are not added to this count. The new Hint
privacy regression first failed in the two TypeScript responder subcases and
passed in Python; after the finite TypeScript guard, all four subcases passed.
An intermediate evidence run exposed a missing `privacy.ts` in a copied test
runtime; the fixture import closure was corrected and the unchanged assertions
passed. This was not waived or counted as a successful run.

The record/Experience codecs, source-signature implementation, network crypto
and control modules and retrieval implementation (eight inspected core files)
are byte-identical to base `f5b09dc0ed89fcbe23e9720221413d7910950cb9`.
This is not the whole repository suite. Prior disclosed Unicode normalization
limits, physical fault domains, real-model exchanges, cross-host deployments
and long-running scale targets were not revalidated or certified here.

### R1: malformed content must not interrupt receiving

Independent review found that the Python fallback error classifier used an
untrusted `kind` in a set lookup. An array or object `kind`, combined with an
integer outside the network safe-integer range, escaped as `TypeError` instead
of the existing bounded content error. The fix checks that `kind` is a string
before the Hint-specific lookup. It does not broadly swallow receive errors or
relax JSON, integer, signature, encryption, authorization or admission checks.

Before the fix, the new parser matrix on `0262409` produced eight error events
across twelve subcases: `kind=[]/{}`, integers `2**53-1`, `2**53`, `2**63-1`,
and bytes/mapping forms. The real-crypto receive regression independently
produced four `TypeError` events: both non-string kinds and both unsafe integers.
Those are two failed test methods, not twelve different failed methods.
The same assertions pass after the fix; neither test was weakened to accept
an unexpected exception.

The shared Python/TypeScript vectors carry identical original bytes into the
independent parsers, without first converting large integers through a
JavaScript number. Safe-integer inputs with an invalid kind still produce
`network_invalid_content`; the malformed unsafe-integer inputs produce
`network_invalid_content_json`. Valid Hint payloads and the separate
`network_invalid_content` classification for out-of-range Hint numbers retain
their prior behavior. No TypeScript production code changed for this repair.

With actual JWE and signed envelopes from an authorized synthetic sender, the
receiver quarantines each malformed item without a successful receipt and
continues to the normal chat or Hint on the same page. Both relay cursors
advance; repeat polls do not replay or stall, and a later normal message also
arrives. Existing Vault tables, indexes, origin pins, local Hint policies and
trust files remain byte/row-identical. This is two local ASGI relays, not a
cross-host or physical fault-domain experiment.

Four new methods cover the parser matrix, the real receive sequence, shared
raw-byte parsing and preserved Hint number classification. Their focused
reruns are included in the final regression count, not added to it. Using the
same real runtimes and dependencies documented above, the final selection was:

```sh
python -B -m unittest \
  tests.test_network_hints \
  tests.test_network_hints_typescript \
  tests.test_network_hints_recovery \
  tests.test_network_message_semantics \
  tests.test_network_message_typescript \
  tests.test_network_agent \
  tests.test_network_typescript_agent \
  tests.test_network_typescript_agent_network \
  tests.test_network_recovery \
  tests.test_network_packaging -v
```

Verbatim final summary, executed on 2026-09-07:

```text
Ran 90 tests in 92.997s

OK
```

All 90 distinct methods passed with zero skips. This repair reran the direct
Hint/content/message/Agent/recovery/packaging paths, not the whole repository
or the earlier 53-method Experience/signature group. The only production
change is the string guard in the Python content error classifier; record
bytes, IDs, source signatures and cryptographic implementations are unchanged.
