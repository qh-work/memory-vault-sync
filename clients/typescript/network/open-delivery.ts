/** Immutable, recipient-bound open messages. Transport authorization is separate.
 * This module preserves original Memory/share bytes and never grants Vault trust.
 */
import {
  NetworkCryptoError, canonicalBytes, document, objectFields, safeInteger, digestHex,
  validateSigningPublic, validateSigningIdentity, validateEncryptionPublic,
  validateEncryptionIdentity, signMessage, verifyMessage, validateJwe,
  encryptBytes, decryptBytes,
} from './crypto.ts';
import type {
  DocumentInput, SigningIdentityDocument, SigningPublicDescriptor,
  EncryptionIdentityDocument, EncryptionPublicDescriptor, MessageProof,
} from './crypto.ts';
import type { GeneralJWE } from 'jose';
import {
  CONTENT_SCHEMA, MAX_CONTENT_BYTES, validateContent,
} from './content.ts';
import type { MessageContent, MemoryTransferContent } from './content.ts';

export const ENVELOPE_SCHEMA = 'memory-vault-open-message-envelope/v1';
export const CONTEXT_SCHEMA = 'memory-vault-open-message-context/v1';
export const MAX_ENVELOPE_BYTES = 6 * 1024 * 1024;
export const MAX_CONTEXT_BYTES = 4096;
export const FUTURE_SKEW_SECONDS = 30;

export interface EnvelopeContext {
  readonly schema_version: typeof CONTEXT_SCHEMA;
  readonly message_id: string;
  readonly object_ref: { readonly namespace: 'object'; readonly key: string };
  readonly sender_signing_key: SigningPublicDescriptor;
  readonly sender_encryption_key: EncryptionPublicDescriptor;
  readonly recipient_signing_key: SigningPublicDescriptor;
  readonly recipient_encryption_key: EncryptionPublicDescriptor;
  readonly created_at: number;
  readonly content_schema: typeof CONTENT_SCHEMA;
  readonly content_kind: 'message' | 'memory_transfer';
}
export interface EnvelopePayload {
  readonly schema_version: typeof ENVELOPE_SCHEMA;
  readonly kind: 'message.envelope';
  readonly context: EnvelopeContext;
  readonly jwe: GeneralJWE;
}
export interface OpenEnvelope {
  readonly payload: EnvelopePayload;
  readonly proof: MessageProof;
}
export interface CreateEnvelopeOptions {
  readonly signer: SigningIdentityDocument;
  readonly sender_encryption_key: EncryptionPublicDescriptor;
  readonly recipient_signing_key: SigningPublicDescriptor;
  readonly recipient_encryption_key: EncryptionPublicDescriptor;
  readonly message_id: string;
  /** Persist an independently generated random key for the logical message. */
  readonly object_key: string;
  readonly created_at: number;
}
export interface VerifyEnvelopeOptions {
  /** Expected identities must come from authenticated caller state. */
  readonly sender_signing_key: SigningPublicDescriptor;
  readonly sender_encryption_key: EncryptionPublicDescriptor;
  readonly recipient_signing_key: SigningPublicDescriptor;
  readonly recipient_encryption_key: EncryptionPublicDescriptor;
  /** Supply at first admission. Omit for historical cryptographic validation. */
  readonly now?: number;
}
export interface DecryptEnvelopeOptions extends VerifyEnvelopeOptions {
  readonly encryption_identity: EncryptionIdentityDocument;
}
export class OpenDeliveryError extends NetworkCryptoError {
  constructor(code: string) { super(code); this.name = 'OpenDeliveryError'; }
}
function fail(code: string): never { throw new OpenDeliveryError(code); }
function input(value: unknown): DocumentInput { return value as DocumentInput; }
function same(left: unknown, right: unknown): boolean {
  return Buffer.from(canonicalBytes(left)).equals(Buffer.from(canonicalBytes(right)));
}

/** Incoming immutable wire is already canonical; never erase alternate bytes. */
function canonicalDocument(value: DocumentInput, maximum: number): Record<string, unknown> {
  const raw = value instanceof Uint8Array ? Buffer.from(value) : canonicalBytes(value, maximum);
  const parsed = document(raw, maximum);
  if (!Buffer.from(raw).equals(Buffer.from(canonicalBytes(parsed, maximum)))) {
    fail('open_delivery_noncanonical_document');
  }
  let nodes = 0;
  function visit(item: unknown, depth: number): void {
    if (++nodes > 1024 || depth > 16) fail('open_delivery_document_complexity');
    if (item !== null && typeof item === 'object') {
      for (const child of Object.values(item)) visit(child, depth + 1);
    }
  }
  visit(parsed, 0);
  return parsed;
}

function contentBytes(value: DocumentInput): {
  bytes: Uint8Array; content: MessageContent | MemoryTransferContent;
} {
  const parsed = canonicalDocument(value, MAX_CONTENT_BYTES);
  const content = validateContent(parsed);
  if (content.kind !== 'message' && content.kind !== 'memory_transfer') {
    fail('open_delivery_unsupported_content_kind');
  }
  // Preserve the original encoded share here. The client durably stages the
  // inbox first, then validates the share and applies normal Vault import/trust
  // rules. A rejected share must not block later messages in the same lease.
  return { bytes: canonicalBytes(parsed, MAX_CONTENT_BYTES), content };
}

function contextDocument(value: DocumentInput): EnvelopeContext {
  const context = objectFields(canonicalDocument(value, MAX_CONTEXT_BYTES), [
    'schema_version', 'message_id', 'object_ref', 'sender_signing_key',
    'sender_encryption_key', 'recipient_signing_key', 'recipient_encryption_key',
    'created_at', 'content_schema', 'content_kind',
  ], 'open_delivery_invalid_context');
  if (context.schema_version !== CONTEXT_SCHEMA || context.content_schema !== CONTENT_SCHEMA) {
    fail('open_delivery_wrong_schema');
  }
  if (typeof context.message_id !== 'string' ||
      /^msg_[0-9a-f]{64}$/.exec(context.message_id)?.[0] !== context.message_id) {
    fail('open_delivery_invalid_message_id');
  }
  const object = objectFields(context.object_ref, ['namespace', 'key'], 'open_delivery_invalid_object_ref');
  if (object.namespace !== 'object') fail('open_delivery_invalid_object_ref');
  digestHex(object.key);
  validateSigningPublic(input(context.sender_signing_key));
  validateEncryptionPublic(input(context.sender_encryption_key));
  validateSigningPublic(input(context.recipient_signing_key));
  validateEncryptionPublic(input(context.recipient_encryption_key));
  safeInteger(context.created_at);
  if (context.content_kind !== 'message' && context.content_kind !== 'memory_transfer') {
    fail('open_delivery_unsupported_content_kind');
  }
  return context as unknown as EnvelopeContext;
}

/** Create once, then persist its exact canonical bytes for retries and repair. */
export async function createEnvelope(value: DocumentInput, options: CreateEnvelopeOptions): Promise<OpenEnvelope> {
  const { bytes, content } = contentBytes(value);
  // Snapshot every caller-owned value before the first asynchronous JOSE call.
  const signer = document(input(options.signer), 4096) as unknown as SigningIdentityDocument;
  const context = contextDocument({
    schema_version: CONTEXT_SCHEMA,
    message_id: options.message_id,
    object_ref: { namespace: 'object', key: options.object_key },
    sender_signing_key: validateSigningIdentity(signer),
    sender_encryption_key: validateEncryptionPublic(options.sender_encryption_key),
    recipient_signing_key: validateSigningPublic(options.recipient_signing_key),
    recipient_encryption_key: validateEncryptionPublic(options.recipient_encryption_key),
    created_at: options.created_at,
    content_schema: CONTENT_SCHEMA,
    content_kind: content.kind,
  });
  const jwe = await encryptBytes(bytes, [context.recipient_encryption_key], { context: input(context) });
  const payload: EnvelopePayload = { schema_version: ENVELOPE_SCHEMA, kind: 'message.envelope', context, jwe };
  const envelope: OpenEnvelope = { payload, proof: signMessage(input(payload), signer) };
  canonicalBytes(envelope, MAX_ENVELOPE_BYTES);
  return envelope;
}

/** Verify original signature and exact dual-key binding; this grants no storage. */
export function verifyEnvelope(value: DocumentInput | OpenEnvelope, options: VerifyEnvelopeOptions): EnvelopePayload {
  const envelope = objectFields(canonicalDocument(input(value), MAX_ENVELOPE_BYTES),
    ['payload', 'proof'], 'open_delivery_invalid_envelope');
  const payload = objectFields(envelope.payload, ['schema_version', 'kind', 'context', 'jwe'],
    'open_delivery_invalid_envelope');
  if (payload.schema_version !== ENVELOPE_SCHEMA || payload.kind !== 'message.envelope') {
    fail('open_delivery_wrong_schema');
  }
  const context = contextDocument(input(payload.context));
  const expected = {
    sender_signing_key: validateSigningPublic(options.sender_signing_key),
    sender_encryption_key: validateEncryptionPublic(options.sender_encryption_key),
    recipient_signing_key: validateSigningPublic(options.recipient_signing_key),
    recipient_encryption_key: validateEncryptionPublic(options.recipient_encryption_key),
  };
  for (const name of Object.keys(expected) as (keyof typeof expected)[]) {
    if (!same(context[name], expected[name])) fail('open_delivery_identity_mismatch');
  }
  if (options.now !== undefined && context.created_at - safeInteger(options.now) > FUTURE_SKEW_SECONDS) {
    fail('open_delivery_from_future');
  }
  const jwe = validateJwe(input(payload.jwe), { context: input(context) });
  if (jwe.recipients.length !== 1 || jwe.recipients[0].header?.kid !== context.recipient_encryption_key.key_id) {
    fail('open_delivery_recipient_mismatch');
  }
  verifyMessage(input(payload), input(envelope.proof), [expected.sender_signing_key]);
  return { schema_version: ENVELOPE_SCHEMA, kind: 'message.envelope', context, jwe };
}

/** Return validated original content bytes. Saving and trust stay with the caller. */
export async function decryptEnvelope(value: DocumentInput | OpenEnvelope,
  options: DecryptEnvelopeOptions): Promise<Uint8Array> {
  const payload = verifyEnvelope(value, options);
  const identity = document(input(options.encryption_identity), 4096) as unknown as EncryptionIdentityDocument;
  if (!same(validateEncryptionIdentity(identity), payload.context.recipient_encryption_key)) {
    fail('open_delivery_identity_mismatch');
  }
  const bytes = await decryptBytes(payload.jwe, identity, { context: input(payload.context) });
  const checked = contentBytes(bytes);
  if (checked.content.kind !== payload.context.content_kind) fail('open_delivery_content_kind_mismatch');
  return bytes;
}
