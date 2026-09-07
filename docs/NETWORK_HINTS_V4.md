# Authorized Memory Hint v4: cancel an established query

Status: **included in the alpha.5 release target** after review and merge in
PR #27. This profile adds explicit cancellation between two already known,
authorized endpoints. It
retains the reviewed pagination and complete batch-dependency authorization
semantics. It is not open discovery, Gossip, task orchestration or a capacity
certification. See [release scope](RELEASE.md) for publication evidence;
packaging does not upgrade private installations.

## One bounded conversation, explicit actions

The native operations remain `connect`, `remember`, `recall`, `discover`,
`send` and `receive`. Python, native TypeScript and trusted HTTP/NDJSON entry
points share the same content, identity, permission and error semantics.
Hint visibility and full-record access still require separate local grants.
Each query freezes at most sixteen projections in four explicitly requested
pages of four. A requester can select one to four distinct roots from pages
it has actually received; the owner sends the complete authorized dependency
union or refuses the whole batch. Shared dependencies retain one original ID.
Matching remains a case-sensitive substring over explicitly permitted IDs,
ordered by memory ID; it is not current-goal or truth ranking.

All controls use `memory-vault-hint/v4` inside the existing encrypted
`memory-vault-network-content/v2` carrier. Controls use exact fields, existing
ID formats, safe positive integers and a 4096-byte canonical limit.

| kind | Fields besides schema_version and kind |
| --- | --- |
| query | query, expires_at |
| page | query_message_id, cursor |
| hints | request_message_id, query_message_id, page_index, policy_revision, expires_at, hints, next_cursor |
| select | query_message_id, selections |
| refusal | request_message_id, reason (not_available) |
| cancel | query_message_id, offer_message_id, expires_at |
| cancel_ack | request_message_id, query_message_id, expires_at |

`selections` remains one to four exact `{offer_message_id, memory_id}` objects,
with distinct roots from the same live query. The distinct `hint_batch_transfer`
payload still contains `schema_version`, `kind`, `request_message_id`,
`query_message_id`, `expires_at` and `share`. Its selected root set must exactly
match the persisted request before admission. Existing share/content byte
limits do not increase. Every dependency is checked against current full-record
grants, and the receiver still independently validates canonical records and
source trust. No partial authorized subset is substituted for a refused batch.

## Cancel locally, then notify the owner

B must first have received at least one valid Hint page from A. B can then use
the ordinary `send` operation, supplying a new request ID, A as the sole
recipient, and this control (replace the illustrative IDs with actual IDs):

```text
schema_version: memory-vault-hint/v4
kind: cancel
query_message_id: the original query message ID
offer_message_id: one Hint page B actually received for that query
expires_at: that page's unchanged expiry
```

The expiry may be shorter than the initial query because the owner's policy
expires earlier. Cancellation never extends either expiry.

The endpoint validates the original query, actual received page, provider and
expiry, then commits the cancellation and notification outbox together in one
transport transaction. A queue-capacity or request-ID conflict rolls both back.
This local operation precedes network refresh and does not wait for an online
owner or for an in-flight network request to finish. A successful local result
includes `cancellation: {query_message_id, local_cancelled:true}` even if its
notification is only queued because the network is unavailable.
If the local transaction committed but a subsequent supported typed local-storage
failure prevents establishing the delivery result, the cancellation-only path
returns `state: delivery_unknown` with that committed local cancellation and
a bounded error. It omits unknown storage counts and recipient confirmations;
it does not undo cancellation, suppress the error or claim remote success.
Failures before the local commit still fail without a partial cancellation.
The Python endpoint also tolerates an optional SQLite sidecar disappearing
between its existence check and secure open, but only when a second `lstat`
confirms that the name is still absent. Existing entries, dangling links,
hard links, unsafe permissions and other storage errors still fail; this does
not relax the shared storage validator or promise freedom from all OS races.

After local cancellation, this query cannot request another page, select
another batch or admit a not-yet-admitted incoming batch. Other queries, chat
and manual transfers are unaffected. Repeating the same cancel request ID and
arguments is idempotent; a different request ID cannot create a second
cancellation for the same session. A fresh query can still proceed under
current explicit grants.

## Remote processing is a separate fact

A receiving a cancel notification saves communication only. A must explicitly
process that message through `receive(respond_to=cancel_message_id)`.
The original requester, existing owner session, original query, frozen offer
and unchanged expiry must match. The cancel path does not depend on a still
active memory grant: withdrawing a grant must not prevent cancellation.
Neither cancellation nor acknowledgment can grant new access.

A marks the session cancelled and queues `cancel_ack` in one transaction.
Duplicate processing reuses the original acknowledgment. Unknown queries,
wrong peers, wrong offers and expired requests produce a generic refusal
without changing other sessions. Public `send` cannot manufacture cancel_ack.
Only this bound responder path generates it.

The ack names the cancel notification in `request_message_id`, the original
query and its established page expiry. B validates it against its own persisted
cancelled session and notification before accepting it. Reading this typed
ack confirms that A processed the cancellation. A relay's `stored` receipt or
an inbox's `validated_saved` receipt alone does **not** confirm that processing.
It also does not mean that a model understood a request or completed a task.

## Bounded state, immutable history and concurrency

Cancellation extends the existing transport session, not a Memory Record or a
new database. `memory-vault-hint-session/v2` adds `state: active|cancelled` and
`cancellation`: null while active, otherwise exactly the notification
`message_id`, `offer_message_id` and `expires_at`. Existing network, participant,
query and frozen-page bindings remain. Cancelled sessions count within the
same 64-session, 32 KiB per-session and maximum five-minute budgets. They do
not receive a new lifetime or permanent unbounded tombstone.

Normal query, page, select, hints and batch delivery require active sessions.
The cancel and ack paths are narrow exceptions bound to the stored cancelled
session; their actual delivery still checks current signed membership and
communication scope. The pump omits stopped query work so other live work can
progress. Original body, frozen ciphertext, signatures, IDs and historical
receipts are retained, not replaced with cancellation text.

The endpoint checks again immediately before starting each actual network
request, including retries and each relay. Requests already started cannot be
recalled. No database lock is held while waiting for HTTP. Cancellation does
not promise withdrawal of already transmitted bytes.

Incoming share parsing occurs before the final admission reservation. The
final active-session check, existing Vault import and inbox-result save use
the same transport writer reservation as local cancellation, with transport
before Vault lock ordering. If cancellation commits first, new batch admission
is rejected before opening the Vault. An admission that already began under
that reservation may finish before cancellation commits. This is not a claim
of atomic crash commit across both SQLite databases. Previously admitted
records and historical duplicate reads remain unchanged.

An ordinary restart retains cancelled state. Backup/restore deliberately
excludes all Hint sessions, active or cancelled, and local sharing policy.
Historical queries, batches, cancels and acknowledgments cannot reactivate a
session after restore; even a new grant requires a new query/request ID.
Existing recovery boundaries continue to reject answering an old query.

## Experience and preview boundaries

Cancel and ack are communication, not observation, independent evidence,
truth, execution authority or deletion of an author's history. Original
record IDs, canonical bytes, Ed25519 proofs and provenance are unchanged.
Transmission is not truth; transferred memory does not manufacture personal
recollection. This does not create a second experience store or bind memory
ownership to a query, task, model or relay.

Earlier Hint v1/v2/v3 controls and older preview sessions are unsupported by
this candidate; there is no downgrade wrapper. Base content/v2 chat and manual
memory transfers, original record serialization and `network-v1` encryption
remain. Use isolated synthetic state, retaining old directories, private
configuration and backups. Upgrade/migration tooling remains deferred.

## Validation

Required gates cover both actual cryptographic runtimes, both endpoint
directions and official entry points: local offline cancellation, two-query
isolation, duplicate cancellation, atomic queue failure, delayed valid signed
batch rejection, preserved prior records/receipts, invalid bindings, stopped
frozen retries, ordinary restart and encrypted recovery. Direct batch,
pagination, parser, Agent, message and packaging regressions remain required.
This scope does not include actual-model, cross-host, physical fault-domain,
long-duration or large-cluster validation.

Developer validation on 2026-09-07 used the existing Python 3.12.0b4 and
Node 22.19.0 runtimes with joserfc 1.7.5, jose 6.2.10 and cryptography 50.0.1.
No new dependency was installed. With those dependencies available, run from
the repository root (`MEMORY_VAULT_NODE` and `MEMORY_VAULT_JOSE_MODULE` may
point to the existing Node binary and jose module):

```sh
python -B -m unittest -v \
  tests.test_network_hints \
  tests.test_network_hints_typescript \
  tests.test_network_hints_recovery \
  tests.test_network_hints_pagination \
  tests.test_network_hints_pagination_typescript \
  tests.test_network_hints_batch \
  tests.test_network_hints_batch_typescript \
  tests.test_network_hints_cancellation \
  tests.test_network_hints_cancellation_typescript \
  tests.test_network_message_semantics \
  tests.test_network_message_typescript \
  tests.test_network_agent \
  tests.test_network_typescript_agent \
  tests.test_network_typescript_agent_network \
  tests.test_network_recovery \
  tests.test_network_packaging
```

The same sixteen-module suite, recorded with a method-level unittest result
collector, selected and ran **125 distinct methods: 125 passed, zero failures,
errors or skips**. The collection wrapper measured 207.588 seconds; the raw
unittest runner measured 207.476 seconds:

```text
Ran 125 tests in 207.476s

OK
```

This comprises 108 direct regressions from the preceding batch, ten new
Python cancellation methods and seven new native TypeScript cancellation
methods. Repeated runs and test subcases are not added to that count. The
new coverage includes both endpoint directions, explicit remote acknowledgment,
postcommit typed-storage delivery failures, cancellation/admission ordering,
optional sidecar disappearance and continued rejection of unsafe file names.
Real JWE/signature paths use generated synthetic identities and local relays;
timing and typed-storage fault probes instrument explicit boundaries without
substituting cryptographic implementations.

The initial 124-method run had 123 passes and one error: concurrent receive
observed a real optional-WAL disappearance between existence and secure open.
The absent-only fix described above and its deterministic safe/unsafe-file
regression precede this final 125-method result. An earlier observation fixture
was corrected to use a read-only observer instead of requesting a writer;
neither failed run is represented as a passing result. A separate concrete
postcommit storage failure motivated the cancellation-result preservation test.

The eleven existing Memory/Experience/trust/sharing/network crypto/control/
recovery and TypeScript crypto/records/retrieval/Vault core files remain
byte-identical to the preceding main commit. Shared storage validation is also
unchanged. These are targeted developer results, not an independent reviewer
PASS or a full-suite certification. The previously documented U+1E030 runtime
normalization discrepancy remains outside this batch. No actual-model,
cross-host, physical fault-domain, long-duration or scale result is claimed.
