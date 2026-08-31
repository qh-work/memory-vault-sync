# Independent network-v1 interoperability companion

This TypeScript companion uses `jose` 6.2.10 independently of Python's
`joserfc` 1.7.5. It exercises the JWE wire format and existing Ed25519 outer
message-signature format. It is a synthetic reviewer tool, not an agent
runtime, credential broker, production key store or invitation authority.

Requirements: Node 22.19+ with built-in type stripping. Install the pinned
dependency in this example directory with `npm install --ignore-scripts
--no-audit --no-fund`, then run `node --experimental-strip-types interop.ts`.
The program reads one JSON request from stdin and returns one JSON result.
It makes no network request and writes no files. Errors never echo input.

Operations:

- `encrypt`: `plaintext` (base64url), public `recipients`, `context`; returns
  `jwe`.
- `decrypt`: `jwe`, synthetic private `identity`, `context`; returns base64url
  `plaintext`.
- `seal`: `plaintext`, `recipients`, complete `route`, synthetic Ed25519
  `signing_private_jwk`; returns `envelope`.
- `open`: `envelope`, independently supplied `signing_public`, synthetic private
  `identity`, `network_id`; verifies the outer signature and returns plaintext.

Never paste real private identities or memories into a public review request.
The Python fixture generates temporary synthetic keys in memory. It can run
both directions by setting `MEMORY_VAULT_JOSE_MODULE` to the absolute installed
`jose/dist/webapi/index.js` path and running only `tests/test_network_crypto.py`.
That variable selects reviewed test code; it is not accepted from a memory or
incoming envelope. Without it, the Python fixture does not claim TS interop.

## Exact cryptographic profile

- JWE General JSON only; content encryption `A256GCM`, each recipient key
  management `ECDH-ES+A256KW`, independent X25519 keys.
- Shared protected header exactly `{"enc":"A256GCM","typ":"memory-vault-network-bytes/v1"}`.
- Each recipient has `alg`, `kid`, and an ephemeral public `epk`; no private
  `d`, additional algorithms, compression, remote key URLs or header extensions.
- AAD is the exact canonical network context. JSON keys are ASCII, integers
  are safe integers, duplicate fields are rejected. Inner memory stays opaque.
- Encrypted plaintext is ASCII `memory-vault-network-bytes/v1\n`, followed by
  unsigned 64-bit big-endian plaintext length, 32 raw SHA-256 bytes, then the
  exact original plaintext. The plaintext digest is not a public header.
- Limits: plaintext 4 MiB, complete JWE/envelope 6 MiB, at most 32 recipients.
- Outer signature covers all routing fields and the entire JWE, using the
  existing `UniversalAgentMemory\0message-signature\0v1\0` domain and proof
  shape. This is not a new signature format or a changed canonical memory ID.

These checks do not prove cloud delivery, recipient cognition, hardware key
isolation, production key recovery, current roster freshness or a security audit.
