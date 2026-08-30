# Content-selected memory sharing

The full client restores v0.21's selective-subgraph workflow using the same
canonical records as both 0.25 modes. A share is bounded NDJSON, not a Task or
project container. Selection never changes memory's lifetime, ownership, record
ID, visibility policy or authorization.

The operator has `share review`, `share export`, `share verify` and `share import`.
These are explicit local actions, not automatic MCP side effects. The following
are reviewer examples; they were not executed for release validation.

## Select and inspect

Example selector:

```json
{"schema_version":"universal-memory-selection/v1","claim_keys":["storage-format"],"kinds":["decision","observation"],"captured_after":"2026-01-01T00:00:00Z"}
```

```bash
python3 scripts/launcher.py --config /absolute/private/client.json share review --selector /absolute/reviewed/selector.json
python3 scripts/launcher.py --config /absolute/private/client.json share export --selector /absolute/reviewed/selector.json --out /absolute/private/selected-memory.ndjson
```

Supported axes: memory IDs, claim keys, exact entities, literal normalized
concepts, kinds, inclusive captured_after and exclusive captured_before. IDs,
claims, entities and concepts are alternatives within the content choice; kind
and time bounds additionally filter roots. Claims recognize claim:<key> and
preserved claim:v021:<key> entity markers. Concept selection is literal and
case-normalized, not an embedding service. `all_records:true` explicitly selects
all currently admitted records and cannot combine with narrower axes. Empty
selectors and unknown fields are refused.

There are no Task, project, session, model, agent-owner or device-owner axes.
Those identifiers may remain unchanged provenance in a record. Every selected
root brings its complete outgoing evidence/relation closure; dependencies can
fall outside the original kind/time filter. Missing, quarantined or currently
revoked dependencies stop export, not silently disappear. Cycles are bounded
and deduplicated.

Review returns counts, sample IDs and content-free privacy findings. Export
re-evaluates the choice in its own consistent read transaction: a review is not
an authorization token for later changed data. Recognizable credentials and
local paths are blocked across roots and dependencies. `--allow-local-paths`
is an explicit local export choice, never an incoming field; recognizable
credentials have no override. This scanner is not complete DLP. Review the
intended audience independently.
When current trust is configured, export rechecks each distinct signer against
that registry again immediately before publishing the complete file. This is
a final trust checkpoint, not an atomic transaction with the external registry.

## Wire contract and limits

`universal-memory-share/v1` is canonical UTF-8 NDJSON, ending in LF:

1. Header: record hash profile, creation time, normalized selector and its hash.
2. Record lines: unchanged canonical record, optional original Ed25519 proof,
   and whether it was a selected root.
3. Footer: counts, ordered record-hash aggregate and exact record-line hash,
   including proofs and root labels.

Verification checks all bytes, identities, duplicate IDs, root predicates,
footer and dependency closure, and refuses source changes. Hashes do not
authenticate the sender. Proofs remain available for independent verification.
No key, policy or runtime instruction is transported as authority.

The large-share path supports 250,000 records and 2 GiB within an explicit
operator time budget. Import streams through one transaction instead of
holding all plaintext in one JSON object. Verification uses bounded integer
adjacency and checks that every extra record is reachable from a selected root;
an unrelated unselected record is rejected, even with valid independent proofs.
Exact-ID-only selections use indexed lookup instead of scanning unrelated
memories. Ordinary lightweight bundles and
small MCP/delta limits are unchanged. Over-budget or incomplete data fails;
there is no silent truncation.

## Admission and retries

```bash
python3 scripts/launcher.py share verify --source /absolute/inbox/selected-memory.ndjson
python3 scripts/launcher.py --config /absolute/private/receiver.json share import --source /absolute/inbox/selected-memory.ndjson
python3 scripts/launcher.py --config /absolute/private/receiver.json share import --source /absolute/inbox/selected-memory.ndjson --verify-signatures
```

Default import quarantines records. Verified import requires every proof and
checks every signer against the receiver's independently configured current
registry. It does not enroll packet keys or rely solely on a relay signature.
A key identifies a signer/attester, not a proven model, human, original author
or factual truth.

The separate `--accept-unsigned` choice admits bytes as unauthenticated evidence;
it does not validate included signatures. Quarantine/unsigned import does not
store an unverified proof as verified database state: the original share retains
it. Verified re-import is a distinct operation and can upgrade earlier
quarantine; duplicate imports never demote stronger admission.

The source is checked before import and again inside an atomic record/receipt
transaction. Failure rolls back the batch. Exact retry uses a source-hash and
admission receipt. Verified imports recheck distinct signer keys immediately
before commit; exact verified retries still recheck current trust. Registry
changes cannot be made atomic with a separate database transaction, so later
recall continues to enforce current trust. No import
starts a worker, opens a network or proves another AI read/agreed with memory.

Plaintext shares are not encrypted. They are written only to a new private
local file. Use a separately approved transport or the explicit
[encryption provider boundary](ENCRYPTION.md) for confidentiality outside it.
