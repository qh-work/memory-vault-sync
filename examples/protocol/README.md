# Synthetic protocol exchange and known answers

All content here is invented. There are no user memories, private keys,
accounts, real session identifiers or external transport operations. Files are
implementation material for any language/storage engine, not captured runtime
results. Generating their JSON and SHA-256 values did not import or run the
Memory Vault application or its tests.

## Files

- `exchange.ndjson`: a complete three-record bundle: an agent-reported visible
  episode, a goal derived from that episode, and continuity linked to both.
  All referenced records are included. Five LF-terminated lines contain one
  header, three records and one footer. Some text is Unicode.
- `known-answers.json`: exact canonical text, UTF-8 hex, byte counts, full body
  SHA-256 and derived IDs; the footer accumulator input/result and whole-file
  digest are separately labeled. Generic cases cover control-character
  escaping, UTF-8, signed 64-bit extremes and Unicode non-normalization.
- `requests.ndjson`: independent sample capability, remember, identical retry,
  and handoff requests. These are not a script executed during publication.
  Their newly created goal would receive the implementation's current time;
  do not expect its ID to match the fixed-time bundle's goal.

The bundle has no signatures. A v0.24-style receiver defaults its records to
`quarantined`; this keeps them out of ordinary recall until explicit unsigned
acceptance. Their preserved `agent_supplied` / `assistant_inferred` provenance
does not change into authenticated evidence after import.

## Reproduce the hash inputs in your own implementation

For each `record_vectors` entry:

```text
bytes  = canonical_utf8(body)                # no newline
digest = lowercase_hex(SHA256(bytes))
id     = "mem_" + digest[0:40]
```

The listed `canonical_utf8_hex` disambiguates actual UTF-8 bytes from how a
viewer displays escaped JSON. Body hashes exclude `memory_id` and
`record_sha256`. The Unicode example deliberately preserves composed and
decomposed forms; do not normalize either.

For the bundle footer:

```text
input = ASCII(record_1.record_sha256) || LF
     || ASCII(record_2.record_sha256) || LF
     || ASCII(record_3.record_sha256) || LF
footer.records_sha256 = lowercase_hex(SHA256(input))
```

This is not a hash of the file or concatenated canonical records. The separate
`file_sha256` is only a distribution-byte known answer. Changing line endings
or serialization changes that file digest even if record body digests match.

For the mutation retry, lines 2 and 3 are the same complete canonical request,
including the same ID. The expected total is one committed mutation, not two.
Its expected request digest is included; `observed_result` is deliberately null.
No captured response claims are supplied.

## Independent checks (not executed here)

Use an isolated synthetic store, never a private user's data:

1. Reproduce the canonical UTF-8 bytes and hashes in a second language.
2. Stage this bundle, verify all records and footer, and import atomically.
   Quarantine must exclude the records from ordinary context. Explicit unsigned
   acceptance should admit them without claiming authenticated provenance.
3. Repeat import: no extra records. Retry the identical mutating request: one
   durable effect. Reuse its ID for changed text: an explicit conflict.
4. Remove a dependency, repeat a record ID, change one text byte, truncate the
   footer, omit final LF or insert an unknown field: reject without partial
   admission. Reordering valid record lines requires a new footer accumulator.
5. Confirm a remembered next action cannot authorize execution, trust-store
   edits or permission changes. Unknown signatures must not become trusted.
6. If claiming signed/lifecycle profiles, use their separate documented
   contracts and publish independent results; these unsigned examples alone
   cannot establish those profiles work.

Report source revision, implementation language, declared profiles, observed
outcomes and limitations separately. Do not infer cross-model interoperability,
plugin installation, secure isolation or benchmark results from a generated
known-answer file.
