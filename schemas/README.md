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
| `request.schema.json` | Seven core operations plus optional `changes`, `memory.views`, `memory.graph`, `memory.reindex`; unknown fields rejected |
| `result.schema.json` | Success/error envelope, echoed request ID, fixed non-authority flags and explicit client/partial-result extensions |
| `bundle-line.schema.json` | One header, record or footer line; stream ordering is checked separately |
| `signed.schema.json` | Optional public descriptor, detached record proof or detached message proof |
| `lifecycle-request.schema.json` | Optional explicit session/turn coordination, separate from core requests |
| `lifecycle-result.schema.json` | Optional lifecycle result envelope and operation results |
| `host-compat-request.schema.json` | Separate v0.21 host v1 / protocol 1.0 requests for ten production operations |
| `host-compat-result.schema.json` | Separate old-host results and mapped local handles/receipts; not the new lifecycle response |
| `hook-fragment.schema.json` | Optional single-sided capture's bounded text-metadata line; not a canonical record field or a nullable `observe` request |
| `delta-v2.schema.json` | Optional signed chained delta payload/proof, including privacy disposition and fragmented-group reference |
| `delta-v3.schema.json` | Optional chained delta with explicit `closure` / `prior_stream` dependency mode; current trust, actual dependencies and same-Vault prefix receipts require separate semantic validation |
| `fragment-group.schema.json` | Signed large-transfer descriptor; fragment paths/bytes and complete atomic admission are checked separately |
| `selection.schema.json` | Content-only selected-share roots; no Task/Project ownership or permission selector |
| `share-line.schema.json` | Selected-share header/record/footer, unchanged canonical records and optional detached proofs |
| `share-envelope.schema.json` | External-provider encrypted-share header; complete file framing and AEAD bindings are separate |
| `device-trust.schema.json` | Independently provisioned device state, transition and recovery descriptor; not an incoming enrollment instruction |
| `encrypted-catalog.schema.json` | Ciphertext catalog, exact envelope-header binding and independently enrolled signer fingerprint |

The result schema intentionally validates the common envelope rather than
requiring SQLite-specific status metadata or a particular search ranking.
Operation semantics remain in [PROTOCOL.md](../PROTOCOL.md). Lifecycle objects
use a different request/result schema described by [LIFECYCLE.md](../docs/LIFECYCLE.md);
they are not accepted as core requests merely because operation names overlap.
The old-host bridge is a third envelope; see [COMPATIBILITY.md](../docs/COMPATIBILITY.md).
The core graph limits (512 nodes / 4,096 edges) and the full client's smaller
MCP limits (64 nodes / 512 edges) are intentionally different transport bounds.
An implementation must advertise its supported operations and bounds; it need
not implement every optional extension to exchange canonical core records.

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
- For fragmented deltas and selected shares, verify the full signed/hashed
  stream, selected-root predicates and transitive closure; reject unrelated
  unselected records and incomplete groups. No cursor moves past missing data.
- V3 `prior_stream` is not a caller-provided list of trusted IDs. The sender
  uses actual published members of the exact stream; the receiver requires its
  own atomic prefix receipt and current validation of actual stored dependencies.
  A schema-valid cursor, cached head or source scope cannot grant admission.
- Device transitions, publisher roots, encrypted catalog proofs and share
  providers require independently configured current trust. Validate cross-field
  state/epoch/generation, physical key uniqueness, path collisions, total byte
  budgets and deadlines. Canonical metadata JCS is not canonical record hashing.
  Structural schemas neither provision providers nor grant authority.

This follows the distinction between structural assertions and annotations in
[the official validation specification](https://json-schema.org/draft/2020-12/json-schema-validation).
There is no custom executable validator or automatic schema downloader here.
These schemas and vectors were authored as public implementation material;
their presence is not a claim that any implementation passed runtime tests.
