/** Native HTTP entry point to an explicitly trusted Memory Vault endpoint.
 *
 * The endpoint receives plaintext and retains all storage, identity, trust,
 * permission and encryption responsibilities. This client is not a relay
 * implementation, key store, offline Vault or background retry worker.
 */

export const MAX_REQUEST_BYTES = 64 * 1024;
export const MAX_RESPONSE_BYTES = 8 * 1024;
export const OPERATIONS = ["connect", "remember", "recall", "discover", "send", "receive"] as const;

export type Operation = typeof OPERATIONS[number];
export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };
export type JsonObject = { [key: string]: JsonValue };
export type RequestId = `req_${string}`;
export type MemoryKind = "event" | "fact" | "observation" | "decision" | "artifact" |
  "entity" | "relation" | "provenance" | "summary" | "goal" | "continuity";

export interface ConnectArguments {
  invitation?: JsonObject;
  request_id?: RequestId;
}
export interface RememberArguments {
  request_id: RequestId;
  kind: MemoryKind;
  text: string;
  entities?: string[];
  relations?: JsonObject[];
}
export type RecallArguments = { query: string; handoff?: boolean; ranking_profile?: string } |
  { memory_id: string } | { cursor: string };
export interface DiscoverArguments { online?: boolean }
export interface SendArguments {
  request_id: RequestId;
  recipients: string[];
  text?: string;
  memory_ids?: string[];
}
export interface ReceiveArguments { limit?: number }

export interface NativeError {
  code: string;
  retryable: boolean;
  retry_after_ms?: number | null;
  commit_state?: string;
  [key: string]: unknown;
}
export type AgentResponse<T = Record<string, unknown>> = {
  schema_version: "universal-agent-memory-result/v1";
  authority: JsonObject;
  request_id?: RequestId;
} & ({ ok: true; result: T } | { ok: false; error: NativeError });

export interface RememberResult {
  state: "accepted_local";
  memory_id: string;
  verification: JsonValue;
  network_accessed: false;
}
export interface RecallHit {
  memory_id: string;
  record_sha256: string;
  kind: string;
  text: string;
  text_offset_bytes: number;
  partial: boolean;
  verification: JsonValue;
  source_ids: string[];
}
export interface RecallResult {
  hits: RecallHit[];
  next_cursor: string | null;
  partial: boolean;
  query_candidate_limit: number;
  network_accessed: false;
  retrieval?: { profile: string; math_profile: string; ranking_time_ms: number };
}

export interface ClientOptions {
  /** Origin only, without credentials, a path, query, or fragment. */
  endpoint: string;
  bearerToken: string;
  /** Acknowledge that this configured endpoint is allowed to see plaintext. */
  trustedEndpoint: true;
  /** Explicit opt-in for http://127.0.0.1 or http://[::1], never remote HTTP. */
  allowLoopbackHttp?: boolean;
  /** 1..60000 ms, covering connection, headers and the entire response body. */
  timeoutMs?: number;
  /** May reduce, but never increase, the core interface budgets. */
  maxRequestBytes?: number;
  maxResponseBytes?: number;
}
export interface CallOptions {
  signal?: AbortSignal;
  timeoutMs?: number;
}

type CommitState = "not_sent" | "unknown" | "not_applicable";
type Retry = (options?: CallOptions) => Promise<AgentResponse>;

/** Local/transport failures only. Native endpoint errors are returned untouched.
 *
 * retry() is explicit and reuses the frozen request body, including request_id.
 * It never generates an ID, waits, schedules a worker, or retries automatically.
 * A timeout/cancellation after dispatch cannot prove a write did not commit.
 */
export class MemoryVaultTransportError extends Error {
  readonly code: string;
  readonly commit_state: CommitState;
  readonly request_id?: RequestId;
  readonly retryable: boolean;
  readonly http_status?: number;
  #retry?: Retry;

  constructor(code: string, commitState: CommitState = "not_sent", details: {
    requestId?: RequestId; retryable?: boolean; httpStatus?: number; retry?: Retry;
  } = {}) {
    super(code);
    this.name = "MemoryVaultTransportError";
    this.code = code;
    this.commit_state = commitState;
    this.request_id = details.requestId;
    this.retryable = details.retryable ?? false;
    this.http_status = details.httpStatus;
    this.#retry = details.retry;
  }

  retry(options: CallOptions = {}): Promise<AgentResponse> {
    if (!this.#retry) return Promise.reject(this);
    return this.#retry(options);
  }
}

function integerOption(value: number | undefined, fallback: number, maximum: number): number {
  const selected = value ?? fallback;
  if (!Number.isSafeInteger(selected) || selected < 1 || selected > maximum) {
    throw new MemoryVaultTransportError("invalid_client_budget");
  }
  return selected;
}

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function endpointUrl(options: ClientOptions): string {
  if (!record(options) || options.trustedEndpoint !== true || typeof options.endpoint !== "string") {
    throw new MemoryVaultTransportError("trusted_endpoint_required");
  }
  let url: URL;
  try { url = new URL(options.endpoint); }
  catch { throw new MemoryVaultTransportError("invalid_endpoint_origin"); }
  if (url.username || url.password || url.search || url.hash || url.pathname !== "/") {
    throw new MemoryVaultTransportError("invalid_endpoint_origin");
  }
  const loopback = url.hostname === "127.0.0.1" || url.hostname === "[::1]";
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback && options.allowLoopbackHttp === true)) {
    throw new MemoryVaultTransportError("endpoint_https_required");
  }
  return url.origin + "/v1/agent";
}

async function readBounded(response: Response, maximum: number): Promise<unknown> {
  const length = response.headers.get("content-length");
  if (length !== null && /^\d+$/.test(length) && Number(length) > maximum) {
    void response.body?.cancel().catch(() => {});
    throw new Error("response_too_large");
  }
  if (!/^application\/json(?:\s*;|$)/i.test(response.headers.get("content-type") ?? "")) {
    void response.body?.cancel().catch(() => {});
    throw new Error("invalid_endpoint_response");
  }
  if (!response.body) throw new Error("invalid_endpoint_response");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const next = await reader.read();
      if (next.done) break;
      size += next.value.byteLength;
      if (size > maximum) {
        void reader.cancel().catch(() => {});
        throw new Error("response_too_large");
      }
      chunks.push(next.value);
    }
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  try { return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); }
  catch { throw new Error("invalid_endpoint_response"); }
}

/** Six operations sharing the already configured endpoint's native core. */
export class MemoryVaultClient {
  #endpoint: string;
  #token: string;
  #timeout: number;
  #requestLimit: number;
  #responseLimit: number;

  constructor(options: ClientOptions) {
    this.#endpoint = endpointUrl(options);
    if (typeof options.bearerToken !== "string" || options.bearerToken.length < 32 ||
        options.bearerToken.length > 4096 || !/^[A-Za-z0-9._~+\/-]+=*$/.test(options.bearerToken)) {
      throw new MemoryVaultTransportError("invalid_bearer_token");
    }
    this.#token = options.bearerToken;
    this.#timeout = integerOption(options.timeoutMs, 10_000, 60_000);
    this.#requestLimit = integerOption(options.maxRequestBytes, MAX_REQUEST_BYTES, MAX_REQUEST_BYTES);
    this.#responseLimit = integerOption(options.maxResponseBytes, MAX_RESPONSE_BYTES, MAX_RESPONSE_BYTES);
  }

  connect(args: ConnectArguments = {}, options: CallOptions = {}): Promise<AgentResponse> {
    return this.#request("connect", args, options);
  }
  remember(args: RememberArguments, options: CallOptions = {}): Promise<AgentResponse<RememberResult>> {
    return this.#request<RememberResult>("remember", args, options);
  }
  recall(args: RecallArguments, options: CallOptions = {}): Promise<AgentResponse<RecallResult>> {
    return this.#request<RecallResult>("recall", args, options);
  }
  discover(args: DiscoverArguments = {}, options: CallOptions = {}): Promise<AgentResponse> {
    return this.#request("discover", args, options);
  }
  send(args: SendArguments, options: CallOptions = {}): Promise<AgentResponse> {
    return this.#request("send", args, options);
  }
  receive(args: ReceiveArguments = {}, options: CallOptions = {}): Promise<AgentResponse> {
    return this.#request("receive", args, options);
  }

  async #request<T = Record<string, unknown>>(operation: Operation, args: object, options: CallOptions): Promise<AgentResponse<T>> {
    if (!record(args)) throw new MemoryVaultTransportError("invalid_request_arguments");
    let body: string;
    try {
      body = JSON.stringify({ ...args, op: operation }, (_key, value) => {
        if (value === undefined || typeof value === "function" || typeof value === "symbol" ||
            typeof value === "bigint" || (typeof value === "number" && !Number.isFinite(value))) {
          throw new Error();
        }
        return value;
      });
      if (typeof body !== "string") throw new Error();
    } catch { throw new MemoryVaultTransportError("invalid_request_json"); }
    const snapshot = JSON.parse(body);
    if (!record(snapshot) || snapshot.op !== operation) {
      throw new MemoryVaultTransportError("invalid_request_json");
    }
    const requestId = snapshot.request_id;
    if (((operation === "remember" || operation === "send") && requestId === undefined) ||
        (requestId !== undefined && (typeof requestId !== "string" || !/^req_[A-Za-z0-9_-]{8,96}$/.test(requestId)))) {
      throw new MemoryVaultTransportError("invalid_request_id");
    }
    if (new TextEncoder().encode(body).byteLength > this.#requestLimit) {
      throw new MemoryVaultTransportError("request_too_large", "not_sent", { requestId: requestId as RequestId | undefined });
    }
    // Freeze serialized bytes before I/O, so an explicit retry cannot pick up
    // later mutations to caller-owned objects or generate a different ID.
    return this.#post(body, operation, requestId as RequestId | undefined, options) as Promise<AgentResponse<T>>;
  }

  async #post(body: string, operation: Operation, requestId: RequestId | undefined,
              options: CallOptions): Promise<AgentResponse> {
    const timeout = integerOption(options.timeoutMs, this.#timeout, 60_000);
    const controller = new AbortController();
    const abort = () => controller.abort();
    let dispatched = false;
    let timedOut = false;
    let status: number | undefined;
    const timer = setTimeout(() => { timedOut = true; controller.abort(); }, timeout);
    options.signal?.addEventListener("abort", abort, { once: true });
    try {
      if (options.signal?.aborted) throw new Error("request_cancelled");
      dispatched = true;
      const response = await fetch(this.#endpoint, {
        method: "POST", body, redirect: "error", credentials: "omit", cache: "no-store",
        headers: { authorization: "Bearer " + this.#token, "content-type": "application/json", accept: "application/json" },
        signal: controller.signal,
      });
      status = response.status;
      const value = await readBounded(response, this.#responseLimit);
      if (!record(value) || value.schema_version !== "universal-agent-memory-result/v1" ||
          !record(value.authority) || typeof value.ok !== "boolean" ||
          (value.ok ? !record(value.result) : (!record(value.error) || typeof value.error.code !== "string" || typeof value.error.retryable !== "boolean")) ||
          (value.request_id !== undefined && value.request_id !== requestId) || (!response.ok && value.ok)) {
        throw new Error("invalid_endpoint_response");
      }
      // Includes valid 4xx/5xx native failures. Do not reinterpret ok, add
      // commit_state, hide retry hints, or turn queued_local into delivery.
      return value as AgentResponse;
    } catch (error) {
      const known = error instanceof Error && ["request_cancelled", "response_too_large", "invalid_endpoint_response"].includes(error.message);
      const code = timedOut ? "request_timeout" : options.signal?.aborted ? "request_cancelled" : known ? (error as Error).message : "transport_failed";
      const mutation = operation === "remember" || operation === "send" || operation === "connect" || operation === "receive";
      throw new MemoryVaultTransportError(code, !dispatched ? "not_sent" : mutation ? "unknown" : "not_applicable", {
        requestId, httpStatus: status, retryable: code === "request_timeout" || code === "transport_failed",
        retry: (next = {}) => this.#post(body, operation, requestId, next),
      });
    } finally {
      clearTimeout(timer);
      options.signal?.removeEventListener("abort", abort);
    }
  }
}
