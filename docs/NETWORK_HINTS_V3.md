# Authorized Memory Hint v3: explicit batch selection

Status: **unreleased development after v0.26.0-alpha.4**. This extends the
reviewed frozen pagination design between already known, authorized endpoints.
It is not open discovery, a global index, Gossip or a scale certification.
The downloadable release and private installations are not replaced.

B can explicitly choose one to four different original experiences from pages
it has already received from A within one live query. A explicitly processes
that one request. There is no automatic paging, selection, fetching, forwarding
or promotion of chat to long-term memory.

## One query, one bounded selection

The existing policy and session rules remain: separate local visibility and
full-record grants, at most sixteen frozen projections in four pages of four,
a maximum five-minute lifetime and at most 64 sessions per endpoint. The same
transport state table holds sessions; there is no second experience database.
Matching remains a case-sensitive substring over explicitly permitted IDs,
ordered by memory ID. A Hint is a locator, not a truth or current-goal ranking.

All control objects use `memory-vault-hint/v3`, with exact fields and at most
4096 canonical bytes. Unknown fields and unsafe integers are rejected.

| kind | Fields in addition to schema_version and kind |
| --- | --- |
| query | query, expires_at |
| page | query_message_id, cursor |
| hints | request_message_id, query_message_id, page_index, policy_revision, expires_at, hints, next_cursor |
| select | query_message_id, selections |
| refusal | request_message_id, reason (always not_available) |

`selections` is an array of one to four exact objects, each containing
`offer_message_id` and `memory_id`. Memory IDs must be distinct. Multiple roots
from the same page are allowed; roots from different pages must still refer to
the same provider, requester and query. The request preserves the caller's
array order. The returned selected roots are compared as a set, not by export
ordering. The requester must have received each specific offer and the named
memory must actually appear in that offer.

Each query still binds the network, participant identities, expiry, frozen
results, local policy revision and complete policy hash. Each page uses its
persisted opaque cursor. New records cannot enter an existing frozen query.
Changing policy invalidates the old query instead of silently refreshing it.

The encrypted response is a distinct `hint_batch_transfer` inside the existing
`memory-vault-network-content/v2` carrier. It has exactly these fields:

| Field | Meaning |
| --- | --- |
| schema_version | memory-vault-network-content/v2 |
| kind | hint_batch_transfer |
| request_message_id | The persisted batch select request |
| query_message_id | The common original query |
| expires_at | The unchanged expiry of the selected offers |
| share | Base64url of the existing universal-memory-share/v1 bundle |

The response does not introduce a second list of page bindings: the request
already records the exact offers and roots. Every selected root in the bundle
must match that request, with neither missing nor extra roots. Existing share
and content byte budgets remain; selecting four roots does not multiply them.

## Complete dependency authorization

A rechecks every selected page against its active session. The existing
multi-root share exporter computes the complete dependency union in one
read-only Vault transaction and checks every ID against the recipient's
full-record grant before creating export output. It writes shared dependencies
once by original memory ID, preserving original canonical records and proofs.

If any root or dependency is missing, unauthorized or over the response's work
or byte budget, the whole response is the same `not_available` refusal. No
authorized subset is sent, no reference is dropped and no hidden ID or count
is disclosed by the refusal. Preparation uses a temporary private share;
the exact selected root set is checked before it can enter the outbox.

On receipt, B checks its persisted select request, provider, live query, every
received offer, expiry and exact selected root set before using the existing
canonical/share verifier and independent Vault trust/admission path. A member's
valid network signature does not grant its source records local trust.

This deduplicates transmission of a shared dependency; it does not create a
new observation, experiment or independent confirmation. The original author,
record ID, canonical bytes, Ed25519 proof and provenance remain unchanged.
Transmission is not truth, and inherited evidence is not the reader's personal
recollection. Query, page, selection and refusal controls never become memories
automatically or grant execution authority.

## Same six native operations

Python, independent TypeScript and the trusted HTTP/NDJSON Agent entry points
use the same `send(control=...)`, `receive(respond_to=...)` and local
`receive(message_id=...)` semantics. The HTTP host still needs a trusted
endpoint that holds the keys; the relay cannot decrypt the content.

1. B sends a new query to A; A receives it and explicitly responds with page 0.
2. B receives and reads the offer. It can explicitly request and receive later
   pages under the same query.
3. B sends one v3 select, naming the original query and one to four pairs of
   actually received offer IDs and their memory IDs.
4. A receives and explicitly responds once, producing the whole original
   dependency union or a generic refusal.
5. B receives the response through the existing validation/admission path.

## Retry, revocation, restart and restore

Every actual send and retry rechecks current signed membership, local policy,
recipient and live session. A frozen request, share or ciphertext cannot extend
expiry or expand a grant. Repeating a request ID with the same arguments reuses
its persisted body and ciphertext; changed arguments conflict. A queued
response is not rewritten into a partial share after revocation.

An ordinary restart may continue an unexpired local query. Backup excludes
live discovery sessions and local sharing policy. Restore preserves historical
messages and source records but cannot revive old queries, pages or batch
requests, even after new grants are installed. Start a new query instead.
Already delivered bytes cannot be retracted.

## Preview version boundary

Hint v1/v2 controls and the earlier single-root `hint_transfer` payload are
unsupported by this candidate. They are not silently converted, re-signed or
deleted. Base content/v2 `message` and explicit `memory_transfer` are unchanged.
The [v2 document](NETWORK_HINTS_V2.md) is historical design and validation
evidence, not the current control contract.

Use isolated synthetic state for this preview. Preserve old directories,
runtime, private configuration and backups; upgrade and migration design are
deferred. This version change does not change existing memory canonical bytes,
IDs, signatures, source trust or the `network-v1` encryption profile.

## Validation scope

The bounded gates cover Python/TypeScript exchange in both directions, four
roots across seen pages, shared dependencies, whole refusal, exact returned
roots, current authorization, replay/expiry/restore boundaries and no automatic
memory writes. Retain the pagination, parser, Agent, message, recovery and
packaging regressions. Use only synthetic endpoints and the existing real
cryptographic libraries. No real-model, cross-host, long-duration, physical
fault-domain or thousand-agent test is implied.

### Executed development regression, 2026-09-07

Runtime: Python 3.12.0b4, Node 22.19.0, joserfc 1.7.5, jose 6.2.10,
cryptography 50.0.1, httpx 0.28.1 and Starlette 1.6.0. No dependencies were
added. Set `MEMORY_VAULT_NODE` to the existing Node executable and
`MEMORY_VAULT_JOSE_MODULE` to the installed jose 6.2.10 entry, then run:

```sh
PYTHONDONTWRITEBYTECODE=1 python -B -m unittest \
  tests.test_network_hints tests.test_network_hints_typescript \
  tests.test_network_hints_recovery tests.test_network_hints_pagination \
  tests.test_network_hints_pagination_typescript \
  tests.test_network_hints_batch tests.test_network_hints_batch_typescript \
  tests.test_network_message_semantics tests.test_network_message_typescript \
  tests.test_network_agent tests.test_network_typescript_agent \
  tests.test_network_typescript_agent_network \
  tests.test_network_recovery tests.test_network_packaging -v
```

Final raw summary:

```text
Ran 108 tests in 161.782s

OK
```

These are 108 distinct methods with zero skips, failures or errors, including
nine new batch methods (six Python and three cross-runtime integration methods).
The new coverage includes four pages of 4/4/4/1 hints, explicitly selecting one
root from each page in noncanonical request order, one shared dependency,
original record/proof preservation, and both Python/TypeScript receiver paths.
A single denied or unadmitted dependency, missing root or preparation work
budget refuses the whole batch. Missing/extra selected roots are rejected with
no Vault write or successful acknowledgement; a later normal message still
passes. Replay, expiry, revocation, full encrypted backup/restore and existing
pagination/Agent/message/parser gates are included. Former preview v2 controls
and the old single-transfer payload are explicitly rejected in shared vectors.

Intermediate fixture probes first used a keyword-only helper incorrectly and
tried to create a missing-dependency state that the existing append-only/closure
constraints correctly rejected. Only the disposable fixtures were corrected:
keep the original file, build a valid source missing one root, and separately
quarantine an existing dependency. No trigger or signature verification was
bypassed. Their failed preliminary runs are not counted as passes or added to
the final 108. The final command ran after production and test files froze.

Eleven memory, Experience, sharing, trust, crypto, retrieval, Vault and recovery
core files were also compared byte-for-byte with the merged base and remained
unchanged. Recovery production code already covered transfer records and
session exclusion, so this batch reused it and added the batch regression.
The known earlier U+1E030 normalization difference remains outside this batch;
this is not a claim that every repository test passes. Independent review is
pending and cannot be inferred from these development-side results.
