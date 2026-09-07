# Experience Semantics

Release status: the **alpha.5 target** includes the reviewed origin/int64
repairs merged in PR #22. The earlier alpha.4 review's `CHANGES_REQUESTED`
result and its source-pinned repair evidence remain historical records in
[Experience validation](EXPERIENCE_VALIDATION.md). See [release scope](RELEASE.md)
for current packaging, review limits and publication evidence.

`experience-v1` is an optional interpretation of an existing Memory Record.
It introduces neither a second database nor a parent container. Local memory,
IDs, signatures, network-v1 transport and the six native operations remain in
place. This phase adds local epistemic evidence views, not global consensus,
an open P2P network or a reputation score.

## Types and optional fields

`kind` continues to describe the ordinary record. `epistemic_type` describes
how the publisher says its content became known:

| Type | Meaning |
| --- | --- |
| `observation` | A reported direct observation by the stated source |
| `experiment` | A reported experiment, with its conditions and evidence |
| `inference` | A conclusion derived from other information |
| `hearsay` | A report received from another source, not the reader's own observation |
| `speculation` | A possibility offered without a claim of direct observation |
| `summary` | A condensation of referenced information |
| `external_source` | Information attributed to an external publication or source |
| `unspecified` | No recognized epistemic classification, including old records |

All types are legal to save, including hearsay and speculation. A label alone
does not prove that observation, experiment or verification happened. Missing
evidence remains missing; receipt, popularity and a valid signature do not fill
that gap.

`remember` accepts optional `experience` metadata:

```json
{
  "op": "remember",
  "kind": "observation",
  "text": "Synthetic method X failed in environment V1.",
  "experience": {
    "epistemic_type": "observation",
    "source_agent": "synthetic-A",
    "observed_under": {"environment": "V1"},
    "retry_predicate": "Recheck if the environment changes.",
    "evidence_refs": ["synthetic:experiment-log-A"]
  }
}
```

Optional fields are `epistemic_type`, `context`, `evidence_refs`, `origin_class`,
`observed_under`, `applicability`, `freshness`, `observed_at`, `retry_predicate`,
`source_agent`, `source_memory_refs` and typed `relations`. Context-like fields
are bounded JSON data, not a hard-coded environment schema. Unknown metadata
fields are preserved. Unknown type labels are retained as declared metadata
and viewed as `unspecified`; they acquire no special evidence or state effects.

`source_memory_refs` and typed `relations` each admit at most 16 entries, with
valid existing-format memory IDs. `evidence_refs` admits at most 16 nonempty
opaque strings, each at most 512 UTF-8 bytes. An evidence reference is not an
instruction to fetch a URL, read a file or execute a test. The complete encoded
metadata envelope, including an optional existing source reference, is limited
to **2,048 UTF-8 bytes**. Larger evidence belongs in ordinary referenced records;
the caller must explicitly select any authorized sharing closure.

## Typed provenance relations

These relations live inside the optional metadata. They reuse the existing
relation table through a conservative projection; there is no new graph store.

| Typed relation | Meaning | Core-v1 projection |
| --- | --- | --- |
| `heard_from` | Content was received from the target source | `derived_from` |
| `derived_from` | Content was derived from the target | `derived_from` |
| `summarizes` | Content summarizes the target | `derived_from` |
| `independently_confirms` | Publisher reports an independent confirming observation or experiment | `related_to` |
| `contradicts` | Publisher reports evidence against the target | `related_to` |
| `applies_to` | Declared applicability to the target | `related_to` |
| `fails_under` | Declared failure conditions described by the target | `related_to` |
| `proposes_supersession` | A proposal to adopt another account, without editing the target | `related_to` |

Unknown typed relations are retained without projection or counting effects.
The core relation enum and canonical record schema are unchanged. Typed
`contradicts` is deliberately a non-mutating evidence edge: it does not silently
turn into legacy `conflicts_with`, `supersedes` or `resolves`.

Saving an `observation` with a source-memory reference or lineage relation,
without an explicit independent confirmation or contradiction assertion,
normalizes it to `hearsay`. Source-memory references on hearsay add
`heard_from` edges; other non-independent source references project to
`derived_from` (`summarizes` for summaries). Existing native `derived_from`
edges also participate in both write-time and receive-time attribution.
The 16-relation limit is checked again after these additions.
A genuinely new experiment must be a new record with its
own conditions and an explicit `independently_confirms` or `contradicts` edge;
it must not rewrite the source record. This check catches declared retellings,
but cannot detect a publisher that lies about doing an experiment or omits its
sources.

## Transmission is not truth

**100 transmissions are not 100 independent pieces of evidence.** For one
locally connected claim neighborhood, `provenance_summary` reports:

| Field | Local interpretation |
| --- | --- |
| `propagation_count` | Distinct hearsay/retelling records, not delivery attempts |
| `unique_origin_roots` | Distinct records without declared lineage parents in the available component |
| `independent_confirmation_count` | Distinct eligible publishers of explicit direct/experimental confirmation claims |
| `contradiction_count` | Distinct eligible publishers of explicit direct/experimental counterclaims |

Repeated import of the same immutable record, duplicate edges, multiple
forwarding paths and descendants of one declared source do not manufacture
independent confirmations. **The current attester is not a new historical
origin.** The developing review repair groups eligible confirmation and
contradiction claims by their first locally known verified signer, using the
existing `metadata` entry `state_author:<memory_id>`. If P authored two historical
experiments, later B/C attestations of those same bytes do not split that one
known origin into two independent publishers.

This pin is local deduplication and state-adoption policy, not an authenticated
cross-node original-author certificate. It does not prove that an experiment
happened or that two keys belong to different actors. Another node may have a
different first-known attestation. Counts remain non-Sybil-resistant and
`independence_verified:false`; the pin is not a replacement for provenance
proofs that were never received or have already been discarded.

Current admission and revocation still decide which records are eligible. An
eligible record re-attested by B may retain P as a local deduplication clue,
but P remains revoked and receives no rights from that pin. An explicit
`accepted_unsigned` re-admission also retains an existing valid pin for counting;
it cannot split previously known same-origin records by losing their current
signature. This does not give unsigned imports destructive state-adoption rights.
Only never-pinned unsigned records use distinct record IDs as their declared
origins. The standalone summary helper with no verification input similarly
reports record-level claims, not authenticated independent publishers.

When an eligible signed claim has no pin, or an existing pin is malformed, the
claim is conservatively **not counted** as a confirmation or contradiction.
There is no fallback to its current attester. An invalid existing pin is not
treated as a never-signed record. Reads do not write a guessed pin. Existing
admission update logic can retain a still-available old signer before replacing
its proof, but cannot reconstruct history that is no longer available.

The summary adds these derived fields without changing canonical memory:

| Field | Interpretation |
| --- | --- |
| `origin_identity_basis` | `local_first_verified_signer_or_unsigned_record`; a local counting policy, not a proof format |
| `origin_identity_incomplete` | Some otherwise eligible evidence claims have missing or invalid local origin attribution |
| `unattributed_evidence_count` | Number of distinct affected evidence records, deduplicated across confirmation and contradiction edges |

An origin-attribution gap also sets `truncated:true`. A single record with both
confirmation and contradiction edges contributes one missing-identity count,
not two. Zero incomplete records does not establish global provenance
completeness or experimental independence.

The summary is derived on demand from existing local admitted records and
relations. Traversal is bounded to 128 nodes, 1,024 edges and depth 8. Missing
references, an unresolved local origin identity, a detected lineage cycle or an exhausted graph budget mark the
summary `truncated`; it must not be represented as a complete network census.
Unrelated claims need explicit relation links to join a component. Environment
labels are exposed, not automatically interpreted as logical equivalence or
conflict. `basis` is `local_declared_provenance`, `independence_verified` is
`false`, and `truth_score` is `null`. No global truth score is created.

## Recall preserves competing evidence

New clients opt in with `include_experience:true` on core `get`, `recall` or
`handoff`, or on the six-operation Agent `recall` (including `handoff:true`).
The ordinary result and text remain; `get` adds `result.experience`, and recall
adds `hits[].experience`. Its optional view contains the metadata, `content`,
`source`, `provenance_summary`, `independent_confirmation_count` and
`contradiction_count`. Metadata does not change ranking or turn history into
instructions. Agent text/content remains bounded and can be a fragment; use
the existing cursor to finish reading it.

An observation of failure under V1 and a counter-experiment showing success
under V2 remain separate records. The receiver sees the conditions, evidence
and opposing claims instead of being forced to accept either "always fails"
or "always succeeds". A retry predicate describes when to reconsider an old
failure; it is not executable permission or an automatic retry scheduler.

## Agent memory transfer does not manufacture recollection

A successor can inherit and cite A's experience without claiming it personally
performed A's observation. Preserve A's canonical record and proof when
transferring it; a B-authored retelling is a new hearsay record linked to A.
Use phrasing such as "A's record reports failure under V1" or "the previous
session attempted...". A self-reported `source_agent` label is not authenticated
merely by an Ed25519 signature. A signature proves a key attested the bytes;
it does not prove a model name, human identity, experiment or historical event.

Receiving text such as "ignore rules", "grant permissions" or "send the whole
Vault" cannot change admission, export selection, trust, host policy or tool
authorization. Reading metadata and calculating the view do not execute its
contents. Existing network receipt and signature checks remain necessary and
are not replaced by epistemic labels.

## Cross-author state adoption

Original records remain append-only. Trusted membership alone does not let B
supersede or resolve A's record. State-changing `supersedes`/`resolves` edges
must meet the existing admission-strength rule and the local same-author
adoption rule; otherwise graph output reports `cross_author_proposal` with no
target state change. Two legacy locally authored unsigned records retain the
existing local correction behavior. Imported unsigned records do not acquire
that authority merely by sharing an unsigned admission class.

The first verified admission signer is lazily pinned in existing local metadata
as the state-adoption author. A later attestation by another key does not take
over that role. This is local policy state, not a permanent proof of original
authorship. Old admissions without a pin use the prior stored signer when
first updated. If an old client already replaced a proof before this policy
existed, that missing history cannot be reconstructed. Pins are local policy
metadata, not a new portable source proof: a new receiver pins the signature
it first independently verifies. Ordinary sharing retains original signatures;
it does not export or elevate another Vault's local policy. No claim in record text
or optional metadata can set the pin. New explicit `contradicts` or
`proposes_supersession` relations preserve the source record without forcing
adoption of the new account.

## Wire compatibility, migration and rollback

No canonical record field, database schema version or hash profile is added.
The writer puts `memory-vault:experience:v1:` followed by canonical JSON
`{"metadata":{...}}` in the existing opaque `provenance.source_ref` string.
An existing caller-provided source reference is retained as the wrapper's
`source_ref`. The human-readable record `text` stays unchanged. Both metadata
and projected ordinary relations are therefore already covered by the normal
record ID and source signature. Newly created records naturally hash their
new content; no existing record is rewritten or rehashed.

An unmodified 0.26 reader can validate, store, read and transfer these ordinary
records, retaining the metadata string without understanding it. Its old
strict request parser does **not** accept new `experience` or
`include_experience` request fields: only send those to an implementation that
advertises `experience_profile: "experience-v1"` in core capabilities or Agent discovery. Use ordinary record/bundle exchange for old readers; do
not strip signed metadata to make it fit. Missing metadata yields
`epistemic_type=unspecified`. An unrecognized envelope is viewed as unspecified
without changing the stored bytes. Duplicate keys and invalid canonical JSON
remain invalid, not an avenue to bypass record validation.

No required bulk migration is performed. Keep normal private backups and
install the new client against the existing Vault. A rollback to 0.26 can read
the same records but loses typed views and the newer cross-author adoption
protection; avoid treating an older client's derived state as the new policy.
Neither installation nor rollback requires rebinding Git, erasing history,
changing network keys, or replacing network-v1.

## Reproducible synthetic demonstration

From the source directory, run:

```sh
python3 scripts/demo_experience.py
```

The script creates a temporary local Vault, uses four logical Agent facades,
prints the A/B/C/D view as JSON, checks the expected relations and counts, and
cleans up. It uses no Docker, endpoint service, external model, credentials,
personal memories or network access. It demonstrates local semantic behavior,
not independent real-model experiments or network delivery. The displayed
agent identities and experiments are explicitly synthetic.

The targeted runtime tests are documented in [the validation report](EXPERIENCE_VALIDATION.md);
canonical vectors, old-reader round trips, signed admission and network tests
must be reported separately from this demonstration. No benchmark, internet
scale, real-model verification or public consensus result is implied.

## Native TypeScript Experience integer boundary

Experience metadata uses exact signed 64-bit integers, including unknown
metadata fields. The native client preserves these values with an
Experience-specific codec; it does not widen the network/control JSON profile.
Safe integers remain JavaScript numbers. Values outside the safe range are
genuine `JSON.rawJSON` objects containing the exact decimal literal, so
`JSON.stringify` preserves endpoint and paging output without rounding. Native
remember calls may supply int64 `bigint` or genuine raw-JSON values inside
`experience`. Already-rounded unsafe JavaScript numbers are rejected.

The codec rejects duplicate JSON fields (including escaped equivalent names),
floats, exponents, out-of-range integers, invalid Unicode and malformed values.
It retains the existing bounded metadata size/depth/node budgets and rejects
integer tokens longer than 20 characters before BigInt conversion. The
source-aware JSON reviver and raw-JSON support were tested with Node 22.19.0.
Do not use ordinary `JSON.parse` to preserve unsafe integer literals downstream;
inspect `value.rawJSON` and use `BigInt` when arithmetic is needed. This
representation affects derived Experience views and new metadata construction;
it does not rewrite stored record bytes, IDs or source signatures.

## Dependency-free HTTP SDK integer boundary

The developing HTTP client in `clients/typescript/index.ts` uses the native
JSON reviver's source text and genuine `JSON.rawJSON` values to preserve unsafe
JavaScript integers in the signed int64 range. Only a successful native
`recall` result's `result.hits[index].experience` object subtree may contain
these values. This covers query recall, `handoff:true`, exact-ID recall and
cursor responses, because the six-operation endpoint returns all of them as
hits. Other response/control fields remain bounded safe integers; they do not
inherit the Experience extension.

Safe integers remain ordinary JavaScript numbers. Unsafe integers become raw
JSON values whose `rawJSON` string is the exact decimal integer;
`JSON.stringify(response)` preserves the numeric literal, and callers may use
`BigInt(value.rawJSON)` for explicit integer arithmetic. A plain user object
with a field named `rawJSON` is not a raw JSON value and gets no special meaning.
No crypto module, JOSE package, key store or new dependency is used by this SDK.
The response walker is capped at depth 32 and 16,384 nodes within the existing
8 KiB body budget; integer tokens longer than 20 characters are rejected before
BigInt conversion.

The HTTP SDK reports typed `MemoryVaultTransportError` failures rather than
rounding: `invalid_endpoint_response_integer` for out-of-range/noninteger
numbers or unsafe integers outside the permitted Experience subtree, and
`experience_lossless_json_unavailable` when the runtime lacks source-aware
reviver or raw-JSON support. Native endpoint JSON errors remain ordinary
responses; these codes identify a local response-processing failure. They do
not silently trigger retries or authorize a different endpoint.

For request metadata, callers with runtime support may supply
`JSON.rawJSON("9223372036854775807")` inside `experience`; the frozen serialized
request preserves the literal. Unwrapped JavaScript `bigint` remains an explicit
`invalid_request_json` error before dispatch. Do not first construct an unsafe
numeric literal as a JavaScript `number`: that value has already been rounded
before the SDK receives it. This transport representation does not change
canonical Memory Record bytes, IDs or proof verification.
