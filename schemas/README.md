# Public UAMP structural schemas

These documents use
[JSON Schema Draft 2020-12](https://json-schema.org/draft/2020-12/json-schema-core).
They belong to the protocol distribution and require no Python or database.
Relative references resolve within this directory; pre-register the local
documents in your validator instead of fetching schemas named by untrusted
memory. The meta-schema URL identifies the schema dialect, not permission to
make a network request.

| File | Scope |
| --- | --- |
| `common.schema.json` | Shared IDs, text bounds, types, relations, provenance and fixed authority |
| `record.schema.json` | Complete canonical v1 record shape; no signatures or admission fields inside it |
| `request.schema.json` | Seven core request operations and optional `changes`; unknown fields rejected |
| `result.schema.json` | Success/error envelope, echoed request ID and fixed non-authority flags |
| `bundle-line.schema.json` | One header, record or footer line; stream ordering is checked separately |
| `signed.schema.json` | Optional public descriptor, detached record proof or detached message proof |
| `lifecycle-request.schema.json` | Optional explicit session/turn coordination, separate from core requests |
| `lifecycle-result.schema.json` | Optional lifecycle result envelope and operation results |

The result schema intentionally validates the common envelope rather than
requiring SQLite-specific status metadata or a particular search ranking.
Operation semantics remain in [PROTOCOL.md](../PROTOCOL.md). Lifecycle objects
use a different request/result schema described by [LIFECYCLE.md](../docs/LIFECYCLE.md);
they are not accepted as core requests merely because operation names overlap.

## Mandatory checks beyond JSON Schema

- Strict UTF-8, no BOM or duplicate JSON keys; reject NUL/lone surrogates and
  lexical decimal/exponent numbers. Schema `integer` is a mathematical type
  and alone may accept a JSON token such as `1.0`.
- Reject blank text and invalid real UTC dates, including year zero and leap
  seconds. `format` may be annotation-only in a validator.
- Enforce UTF-8 byte limits, depth/node budgets and whole-stream limits.
  `maxLength` is a character count; `x-maxUtf8Bytes` is a documentation-only
  extension, not an assertion in Draft 2020-12.
- Require canonical arrays/objects, exact body hash and derived memory ID.
  The reference accepts some null/list-duplicate convenience inputs; canonical
  emitters must not use them in stored/signed records.
- Validate each bundle's header/record/footer order, final LF, unique IDs,
  ordered digest accumulator and dependency closure. Check atomically before
  admission; do not discard unknown fields or relations to make input pass.
- For signed objects, decode and canonically re-encode Base64; check byte
  lengths, SHA-derived key IDs, domain-separated Ed25519 proofs and independently
  provisioned current trust. Base64 syntax or a schema match is not verification.
- Keep explicit quarantine/admission outside records; recalled evidence always
  retains the fixed authority boundary.

This follows the distinction between structural assertions and annotations in
[the official validation specification](https://json-schema.org/draft/2020-12/json-schema-validation).
There is no custom executable validator or automatic schema downloader here.
These schemas and vectors were authored as public implementation material;
their presence is not a claim that any implementation passed runtime tests.
