# Experience Semantics

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
independent confirmations. Where an admitted signature is available, a
publisher's repeated confirming records are grouped by signer key; unsigned
independent claims can only be distinguished by record ID. These counts are
not Sybil resistant, cannot prove experimental independence, and do not certify
that two keys belong to different actors.

The summary is derived on demand from existing local admitted records and
relations. Traversal is bounded to 128 nodes, 1,024 edges and depth 8. Missing
references, a detected lineage cycle or an exhausted graph budget mark the
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
