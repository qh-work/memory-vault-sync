/** Disjoint encrypted payloads. Chat transport never manufactures memory. */
import { document, objectFields, decodeBase64url, NetworkCryptoError } from './crypto.ts';
import type { DocumentInput } from './crypto.ts';

export const CONTENT_SCHEMA = 'memory-vault-network-content/v2';
export const MAX_CONTENT_TEXT_BYTES = 16384;
export const MAX_CONTENT_SHARE_BYTES = 2 * 1024 * 1024;
export const MAX_CONTENT_BYTES = 4 * 1024 * 1024;
export const MAX_MESSAGE_CHUNK_BYTES = 1024;

export interface MessageContent {
  readonly schema_version: typeof CONTENT_SCHEMA;
  readonly kind: 'message';
  readonly text: string;
}
export interface MemoryTransferContent {
  readonly schema_version: typeof CONTENT_SCHEMA;
  readonly kind: 'memory_transfer';
  readonly note: string;
  readonly share: string;
}
export type NetworkContent = MessageContent | MemoryTransferContent;

function fail(code: string): never { throw new NetworkCryptoError(code); }

/** Strict parsing precedes type validation, including for restored queue data.
 * The early-preview v1 shape is deliberately unsupported, not guessed from
 * text/share values. A valid transfer still needs the existing share verifier.
 */
export function validateContent(value: DocumentInput): NetworkContent {
  let content: Record<string, unknown>;
  try { content = document(value, MAX_CONTENT_BYTES); }
  catch { fail('network_invalid_content_json'); }
  if (content.schema_version !== CONTENT_SCHEMA) fail('network_unsupported_content_schema');
  if (content.kind === 'message') {
    objectFields(content, ['schema_version', 'kind', 'text'], 'network_invalid_content');
    if (typeof content.text !== 'string' || !content.text.length || Buffer.byteLength(content.text) > MAX_CONTENT_TEXT_BYTES) fail('network_invalid_content');
  } else if (content.kind === 'memory_transfer') {
    objectFields(content, ['schema_version', 'kind', 'note', 'share'], 'network_invalid_content');
    if (typeof content.note !== 'string' || Buffer.byteLength(content.note) > MAX_CONTENT_TEXT_BYTES) fail('network_invalid_content');
    try { decodeBase64url(content.share, MAX_CONTENT_SHARE_BYTES); }
    catch { fail('network_invalid_content_share_encoding'); }
  } else fail('network_invalid_content');
  return content as unknown as NetworkContent;
}

export function contentText(content: NetworkContent): string {
  return content.kind === 'message' ? content.text : content.note;
}

/** Offsets count Unicode code points in both runtimes, not JS UTF-16 units. */
export function contentChunk(text: string, offset = 0): {text: string; offset: number; next_offset: number | null; total_characters: number; text_partial: boolean} {
  const characters = Array.from(text);
  if (!Number.isSafeInteger(offset) || offset < 0 || offset > characters.length) fail('network_invalid_message_offset');
  let end = offset, bytes = 0;
  while (end < characters.length) {
    const size = Buffer.byteLength(characters[end]);
    if (bytes + size > MAX_MESSAGE_CHUNK_BYTES) break;
    bytes += size; end++;
  }
  return {text: characters.slice(offset, end).join(''), offset, next_offset: end < characters.length ? end : null,
    total_characters: characters.length, text_partial: offset !== 0 || end !== characters.length};
}
