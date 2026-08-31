/** Bounded HTTP transport. No cookies, redirects, decompression or ambient auth. */
import http from 'node:http';
import https from 'node:https';
import { performance } from 'node:perf_hooks';
import { canonicalBytes, document, MAX_DOCUMENT_BYTES } from './crypto.ts';
import type { DocumentInput, JsonValue } from './crypto.ts';
import { NetworkError } from './io.ts';
export type WireDocument = Record<string, JsonValue>;
export interface Transport {
  request(base: string, method: 'GET'|'POST', route: string, value?: DocumentInput, deadline?: number): Promise<WireDocument>;
  close?(): void;
}
export function origin(value: unknown): string {
  if (typeof value !== 'string' || value.length > 2048 || /\s|\\/.test(value)) throw new NetworkError('network_invalid_url');
  const raw = /^(https?):\/\/(\[[^\]]+\]|[^/:?#@]+)(?::([0-9]+))?\/?$/i.exec(value);
  if (!raw || (raw[3] !== undefined && (!Number.isSafeInteger(Number(raw[3])) || Number(raw[3]) < 1 || Number(raw[3]) > 65535))) throw new NetworkError('network_invalid_url');
  let url: URL;
  try { url = new URL(value); } catch { throw new NetworkError('network_invalid_url'); }
  if (url.username || url.password || url.search || url.hash || !['','/'].includes(url.pathname) ||
      !(url.protocol === 'https:' || (url.protocol === 'http:' && ['127.0.0.1','localhost','[::1]'].includes(raw[2].toLowerCase())))) throw new NetworkError('network_https_required');
  return value.replace(/\/$/, '');
}
export class HTTPTransport implements Transport {
  private closed = false;
  private readonly plain = new http.Agent({ keepAlive: true, maxSockets: 8, maxTotalSockets: 8, maxFreeSockets: 8, timeout: 30000 });
  private readonly tls = new https.Agent({ keepAlive: true, maxSockets: 8, maxTotalSockets: 8, maxFreeSockets: 8, timeout: 30000, rejectUnauthorized: true });
  close(): void { this.closed = true; this.plain.destroy(); this.tls.destroy(); }
  request(base: string, method: 'GET'|'POST', route: string, value?: DocumentInput, deadline?: number): Promise<WireDocument> {
    if (this.closed) throw new NetworkError('network_transport_closed');
    if (!/^\/v1\/[a-z-]+$/.test(route)) throw new NetworkError('network_invalid_url');
    const url = new URL(origin(base) + route), remaining = deadline === undefined ? 10000 : Math.min(10000, deadline - performance.now());
    if (remaining <= 0) throw new NetworkError('network_budget_exhausted', true);
    const raw = value === undefined ? undefined : canonicalBytes(value, MAX_DOCUMENT_BYTES);
    return new Promise((resolve, reject) => {
      let done = false, bytes = 0; const chunks: Buffer[] = [];
      const finish = (error?: unknown, result?: WireDocument) => {
        if (done) return; done = true; clearTimeout(timer);
        if (error) { request.destroy(); reject(error); } else resolve(result!);
      };
      const request = (url.protocol === 'https:' ? https : http).request(url, {
        method, agent: url.protocol === 'https:' ? this.tls : this.plain, rejectUnauthorized: true,
        headers: { 'content-type': 'application/json', 'accept-encoding': 'identity', ...(raw ? {'content-length': String(raw.length)} : {}) },
      }, response => {
        const encoding = response.headers['content-encoding'];
        if (encoding && encoding.trim().toLowerCase() !== 'identity') { response.destroy(); finish(new NetworkError('network_response_encoding_rejected')); return; }
        const length = response.headers['content-length'];
        if (length && (!/^\d+$/.test(length) || Number(length) > MAX_DOCUMENT_BYTES)) { response.destroy(); finish(new NetworkError('network_response_too_large')); return; }
        response.on('data', (chunk: Buffer) => {
          bytes += chunk.length;
          if (bytes > MAX_DOCUMENT_BYTES) { response.destroy(); finish(new NetworkError('network_response_too_large')); return; }
          chunks.push(chunk);
        });
        response.on('aborted', () => finish(new NetworkError('network_unavailable', true)));
        response.on('error', () => finish(new NetworkError('network_unavailable', true)));
        response.on('end', () => {
          if (done) return;
          try {
            const result = document(Buffer.concat(chunks), MAX_DOCUMENT_BYTES);
            if (response.statusCode !== 200 || 'error' in result) {
              const detail = result.error;
              const object: WireDocument = detail && typeof detail === 'object' && !Array.isArray(detail) ? detail as WireDocument : {};
              const code = typeof detail === 'string' ? detail : object.code;
              finish(new NetworkError(typeof code === 'string' && /^[a-z][a-z0-9_]{0,95}$/.test(code) ? code : 'network_request_rejected',
                response.statusCode === 429 || (response.statusCode ?? 0) >= 500 || object.retryable === true));
            } else finish(undefined, result);
          } catch (error) { finish(error); }
        });
      });
      const timer = setTimeout(() => finish(new NetworkError(deadline !== undefined && performance.now() >= deadline ? 'network_budget_exhausted' : 'network_body_deadline_exceeded', true)), remaining);
      request.on('error', () => finish(new NetworkError('network_unavailable', true)));
      request.end(raw);
    });
  }
}
