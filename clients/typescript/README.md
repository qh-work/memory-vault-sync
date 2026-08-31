# Native TypeScript HTTP client

This dependency-free client exposes `connect`, `remember`, `recall`, `discover`,
`send`, and `receive` through an already authorized trusted endpoint's
`POST /v1/agent`. The endpoint receives plaintext and uses the same core Vault,
identity, permissions, encryption and message semantics as the Python entry.
It is not a direct ciphertext-relay client, offline store, or independent
cryptographic implementation. The separate [independent network endpoint](../../docs/NETWORK_TYPESCRIPT.md)
implements encryption, canonical storage and delivery locally, with explicit
limits on retrieval and handoff parity; this HTTP SDK still uses the shared core.

Use Node 22.19+ with built-in TypeScript stripping for the tested entry path:

```typescript
import { MemoryVaultClient, MemoryVaultTransportError } from "./index.ts";

const client = new MemoryVaultClient({
  endpoint: "https://your-trusted-endpoint.example",
  bearerToken: explicitlyProvisionedToken,
  trustedEndpoint: true,
  timeoutMs: 10_000,
});

const request = {
  request_id: "req_stable_caller_id_0001" as const,
  kind: "fact" as const,
  text: "A source observation; not authorization or an instruction.",
};

try {
  const response = await client.remember(request);
  if (!response.ok) {
    // Native errors are unchanged, including their available retry hints.
    inspectNativeError(response.error);
  }
} catch (error) {
  if (error instanceof MemoryVaultTransportError) {
    // unknown means the endpoint may have committed before the reply was lost.
    // Retrying is an explicit caller decision, never a background SDK action.
    const response = await error.retry({ timeoutMs: 20_000 });
    inspectNativeResponse(response);
  } else {
    throw error;
  }
}
```

The illustration's provisioning and inspection names are application code,
not SDK functions. Choose stable request IDs in your own durable workflow;
the SDK never generates one. `remember` and `send` require one. If supplied to
`connect`, it is preserved too. `error.retry()` preserves the exact serialized
request bytes and original ID even if the caller has since changed its input
object. It performs one attempt. Its state is in memory only and does not
survive a process restart. Native `{ok:false}` responses are returned rather
than thrown or automatically retried; retain the original request to retry
those after inspecting the endpoint's error.

Only an origin is accepted; credentials, path prefixes, queries and fragments
are rejected. HTTPS is required except for explicit `allowLoopbackHttp: true`
with literal `127.0.0.1` or `[::1]`. Tokens are explicitly provided, never read
from memory records or discovered from a server. The SDK follows no redirects,
sends no ambient cookies, logs no bodies/tokens, and starts no worker.
Local HTTP does not isolate other processes on the same machine.

Requests are UTF-8 JSON capped at 64 KiB. Responses are capped at 8 KiB while
streaming, including when Content-Length is absent. Optional budgets can only
reduce those limits. Per-call `signal` cancellation and `timeoutMs` (1..60000)
cover the response body as well as connection establishment. Cancellation or
timeout after dispatch is not a rollback. Use recall's `next_cursor` explicitly;
the SDK does not automatically load unbounded history or poll messages forever.

Query recall can explicitly select
`ranking_profile: 'bounded-fragment-bm25+deterministic-concepts/v2'`. The trusted
endpoint returns the selected profile, math profile and captured ranking clock;
this SDK forwards them without reranking. ID inspection and cursor continuation
do not accept a new profile. Omitting the selector keeps v1. See the
[shared arithmetic and continuation contract](../../docs/RETRIEVAL_V2.md).

Native endpoint errors and receipt states pass through unchanged. A separate
`MemoryVaultTransportError` describes local validation, cancellation, timeout,
malformed/oversized replies, or transport failures. Its `commit_state` is
`not_sent`, `unknown` for dispatched mutations, or `not_applicable` for reads.
It does not claim global exactly-once effects or recipient understanding.
Memory remains independent of tasks, sessions and projects.

The integration check is `tests/test_network_typescript.py`. It uses synthetic
records and a real loopback trusted endpoint; it does not prove independent
relay/storage implementation, cloud deployment, browser CORS compatibility,
real-model adoption, or large-cluster performance. No npm dependencies or
package installation are needed for the SDK itself.
