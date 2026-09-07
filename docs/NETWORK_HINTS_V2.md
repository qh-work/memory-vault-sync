# Authorized Memory Hint v2: frozen, explicit pages

Historical specification and test evidence for the merged v2 batch. The
**alpha.5 release target** uses [Hint v4 cancellation](NETWORK_HINTS_V4.md) and
rejects v2 controls. The design below describes v2, not the current API.

This was an unreleased candidate for already known, authorized endpoints. It is
not global discovery, Gossip, a public search index or a capacity certification.
Alpha.4 artifacts remain historical. Preview v1 Hint controls are deliberately
unsupported; private upgrades and migration are separate work. See the
[alpha.5 release target](RELEASE.md) for packaging and publication status.

A requester B can ask provider A for a small permitted view, explicitly request
another page and select one original experience from a page it has received.
Each page contains at most four hints. One query freezes at most sixteen hints,
so it has at most four distinct pages. There is no automatic paging, memory
fetching, forwarding or permission expansion.

## Authorization and a single memory system

Reuse the existing local `memory-vault-hint-policy/v1` policy: separate
`hint_memory_ids` from `record_memory_ids`, with an owner, network, recipient,
increasing revision and expiry. Only the trusted local host can set it using
Python `set_hint_policy` or TypeScript `setHintPolicy`. Membership alone grants
neither visibility nor a full share. Queries and message text cannot set policy.

A reads only explicitly hint-authorized, admitted record IDs in one read-only
Vault transaction. Matching is the existing case-sensitive substring match,
ordered by memory ID. It does not run unrestricted recall and then filter it.
Only the ID, at most 128 UTF-8 bytes of excerpt, and epistemic type are projected.
The view discloses no hidden count, dependency ID, environment or relation.
It is a locator, not a current-goal selector or a truth ranking.

The first response freezes the permitted projections in expiring transport
state. Later pages slice that same view; new records do not enter it. Changing
policy invalidates the view, rather than silently refreshing it. A missing
projection is not proof that no other matching memory exists.

Sessions use the existing endpoint `state` table, not a second experience
database. At most 64 sessions exist per endpoint, each at most 32 KiB and with
at most a five-minute lifetime. Creating a new session collects expired session
rows only. It never deletes memories, signatures, admissions or provenance.
Corrupt or over-budget state fails closed. Existing bounded message queues
still apply to repeated requests.

## Closed wire shapes

The encrypted carrier remains `memory-vault-network-content/v2` inside the
existing signed, recipient-bound `network-v1` JWE envelope. The inner control
schema is now `memory-vault-hint/v2`; all control objects are at most 4096
canonical bytes. Unknown control fields are rejected. Integer values are safe
integers, never rounded across Python and TypeScript.

| kind | Fields in addition to schema_version and kind |
| --- | --- |
| query | query, expires_at |
| page | query_message_id, cursor |
| hints | request_message_id, query_message_id, page_index, policy_revision, expires_at, hints, next_cursor |
| select | offer_message_id, memory_id |
| refusal | request_message_id, reason (always not_available) |

`query` is 1–256 UTF-8 bytes. Its fixed `expires_at` must be in the next 300
seconds when used. A shorter policy expiry shortens the response, never extends
the query. Expiry is not renewed by retrying an old query.

`page_index` ranges from 0 through 3. Every hint has exactly `memory_id`,
`excerpt`, and `epistemic_type`. `next_cursor` is either null or an opaque
`hintcur_` token containing 256 random bits. A non-final page has four hints;
page 3 is always final. Null means this bounded view has ended, not that the
whole Vault or network has been searched.

Each cursor is matched against the provider's persisted snapshot, bound to
the network, A and B identities, original query, frozen results, policy revision
and expiry. A page number, another query's token or a different authorized peer
cannot grant access. The complete policy hash is also checked so changing a
policy file without changing its revision cannot silently reuse a snapshot.

## Explicit sequence through the six native operations

Use the same `send` and `receive` interface in Python, independent TypeScript,
the NDJSON entry and the trusted HTTP endpoint. No new operation or adapter is
added. The following values describe protocol objects, not usable identities
or authorization.

1. B sends a query control with the schema above, a textual query and an expiry
   such as the current Unix time plus 300 seconds. B chooses a fresh request ID.
2. A polls with `receive`, then explicitly calls `receive(respond_to=QUERY_ID)`.
   A returns page 0 or a generic refusal under its local policy.
3. B polls and reads the saved control with `receive(message_id=OFFER_ID)`.
4. If `next_cursor` is not null, B can explicitly send a `page` control to A
   carrying the original `query_message_id` and that cursor. A explicitly
   responds to this new request. No operation fetches the next page itself.
5. B can select a memory from any received, still-active page using a `select`
   control with that page's exact `offer_message_id` and one of its memory IDs.
6. A checks the original page and current session, then checks every member of
   the selected record's dependency closure against its full-record grant.
   A sends the unchanged original share or refuses the entire transfer.

Receiving a control never creates a Memory Record. A selected transfer still
passes the original canonical-record, proof, independent trust and admission
checks. The successor inherits recorded evidence, not personal recollection.
Received text is not execution authority and transmission is not truth.

## Retries, revocation and restoration

The initial query's requester session and new outbox row are saved in the same
transaction. Provider snapshot creation is serialized before queuing a response,
so a crash between these steps cannot cause a different frozen result on retry.
Network I/O is outside the snapshot transaction.

Repeating the same request ID reuses persisted body and ciphertext. A new request
ID for a previously seen cursor can obtain the same logical page; it does not
add pages, re-query the Vault or extend expiry. Repeated requests still consume
the existing bounded transport queue budget.

Each actual page/transfer send and retry checks current signed membership,
recipient, local policy revision and expiry. A snapshot cannot bypass a revoked
grant. An invalid incoming page request receives only `not_available`; invalid
local requests fail without disclosing hidden reasons. Previously queued bytes
are never rewritten into a different response just to report revocation.

Backup keeps historical messages, admitted memories and original signatures,
but excludes both participants' live discovery sessions and the local sharing
policy. Restore cannot recreate a session from old inbox or outbox entries,
including an old query that had not yet been answered. Even after granting
access again, the endpoints must start a new query. An ordinary restart can
continue a still-unexpired local session; a restored backup cannot. Already
delivered bytes cannot be retracted.

## Validation scope

Use only isolated synthetic endpoints and the existing real cryptographic
libraries. Pagination validation covers a 4/4/1 exchange and late-page selection,
the 16-hint cap, stable snapshots, duplicate requests, cursor and identity
bindings, expiry/revocation, dependency authorization, no memory writes from
controls, and restoration without session revival. Parser and direct message
regressions remain in scope. The executed command and results below are development-side evidence;
they are not an independent reviewer certification.

No real-model, cross-host, long-duration, physical-failure-domain or thousand-agent
benchmark is claimed. No global routing, authority changes, public service,
automatic installation or private data migration is part of this batch.

### Executed development regression, 2026-09-07

Existing runtime: Python 3.12.0b4, Node 22.19.0, joserfc 1.7.5, jose 6.2.10,
cryptography 50.0.1, httpx 0.28.1, Starlette 1.6.0. No dependencies were added.
Set `MEMORY_VAULT_NODE` to the existing Node executable and
`MEMORY_VAULT_JOSE_MODULE` to the installed jose 6.2.10 entry before running:

```sh
PYTHONDONTWRITEBYTECODE=1 python -B -m unittest \
  tests.test_network_hints tests.test_network_hints_typescript \
  tests.test_network_hints_recovery tests.test_network_hints_pagination \
  tests.test_network_hints_pagination_typescript \
  tests.test_network_message_semantics tests.test_network_message_typescript \
  tests.test_network_agent tests.test_network_typescript_agent \
  tests.test_network_typescript_agent_network \
  tests.test_network_recovery tests.test_network_packaging -v
```

Raw final summary:

```text
Ran 99 tests in 121.316s

OK
```

These are 99 distinct methods, zero skips, failures or errors. Preliminary
probes and repeated runs are not added to this count. Nine new pagination
methods cover both runtime directions, a third equally authorized peer, frozen
4/4/1 results, the 16-hint and 64-session budgets, closure refusal, and backup
restoration of requester/provider and previously unanswered queries. Existing
Hint codec, R1 malformed-message progression, selected transfer, Agent, offline
restart, recovery and packaging regressions are included. A known Starlette
httpx deprecation warning did not skip any tests or change dependencies.

The first recovery precheck required updating the expected extra local restore
boundary; the final assertion verifies its exact values and all remaining
historical rows. An intermediate packaging check ran before both new fixture
files existed. Neither preliminary result is reported as a successful run; the
final command above ran after all production and test files were frozen.

Nine record/trust/sharing/crypto/retrieval core files were also compared with
the merged base and remained byte-identical. The TypeScript Vault change is
limited to the bounded read-only Hint match count. This batch does not rewrite
existing record IDs, canonical bytes or Ed25519 proofs.
