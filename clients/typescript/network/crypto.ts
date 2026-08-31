/** Independent network-v1 cryptography. No I/O, enrollment, key store or transport. */
import {
  createHash, createPrivateKey, createPublicKey, sign as edSign,
  verify as edVerify, timingSafeEqual,
} from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import { GeneralEncrypt, generalDecrypt, importJWK } from 'jose';
import type { GeneralJWE, JWK } from 'jose';

export const MAX_PLAINTEXT_BYTES = 4 * 1024 * 1024;
export const MAX_ENVELOPE_BYTES = 6 * 1024 * 1024;
// A poll page may contain several envelopes. This explicit document ceiling
// does not change the default or per-envelope cryptographic profile.
export const MAX_DOCUMENT_BYTES = 8 * 1024 * 1024;
export const MAX_RECIPIENTS = 32;
export const ALG = 'ECDH-ES+A256KW';
export const ENC = 'A256GCM';
export const BYTES_SCHEMA = 'memory-vault-network-bytes/v1';
export const ENVELOPE_SCHEMA = 'memory-vault-network-envelope/v1';
const SIGNING_PUBLIC_SCHEMA = 'universal-memory-public-key/v1';
const SIGNING_PRIVATE_SCHEMA = 'universal-memory-identity/v1';
const ENCRYPTION_PUBLIC_SCHEMA = 'memory-vault-network-encryption-key/v1';
const ENCRYPTION_PRIVATE_SCHEMA = 'memory-vault-network-encryption-identity/v1';
const PROOF_SCHEMA = 'universal-memory-message-signature/v1';
const MAGIC = Buffer.from(BYTES_SCHEMA + '\n', 'ascii');
const MESSAGE_DOMAIN = Buffer.from('UniversalAgentMemory\0message-signature\0v1\0', 'ascii');
const CONTEXT_LIMIT = 16 * 1024;
const ROUTE_FIELDS = ['schema_version', 'network_id', 'message_id', 'sender_key_id',
  'recipient_key_ids', 'roster_version', 'roster_sha256', 'created_at'];
const PUBLIC_FIELDS = ['schema_version', 'algorithm', 'key_id', 'public_key'];
type Obj = Record<string, unknown>;

export type JsonValue = null | boolean | number | string | readonly JsonValue[] |
  { readonly [key: string]: JsonValue };
export type DocumentInput = Readonly<Record<string, unknown>> | Uint8Array;
export interface SigningPublicDescriptor {
  readonly schema_version: 'universal-memory-public-key/v1';
  readonly algorithm: 'Ed25519';
  readonly key_id: string;
  /** Canonical standard padded Base64, unlike X25519 descriptors. */
  readonly public_key: string;
}
export interface SigningIdentityDocument extends Omit<SigningPublicDescriptor, 'schema_version'> {
  readonly schema_version: 'universal-memory-identity/v1';
  readonly private_key: string;
}
export interface EncryptionPublicDescriptor {
  readonly schema_version: 'memory-vault-network-encryption-key/v1';
  readonly algorithm: 'X25519';
  readonly key_id: string;
  /** Canonical unpadded Base64url. */
  readonly public_key: string;
}
export interface EncryptionIdentityDocument extends Omit<EncryptionPublicDescriptor, 'schema_version'> {
  readonly schema_version: 'memory-vault-network-encryption-identity/v1';
  readonly private_key: string;
}
/** These associations must come from an already authenticated member roster. */
export interface RecipientBinding {
  readonly signing_key_id: string;
  readonly encryption_key: EncryptionPublicDescriptor;
}
export interface Route {
  readonly schema_version: typeof ENVELOPE_SCHEMA;
  readonly network_id: string;
  readonly message_id: string;
  readonly sender_key_id: string;
  readonly recipient_key_ids: readonly string[];
  readonly roster_version: number;
  readonly roster_sha256: string;
  readonly created_at: number;
}
export interface MessageProof {
  readonly schema_version: typeof PROOF_SCHEMA;
  readonly key_id: string;
  readonly payload_sha256: string;
  readonly signature: string;
}
export interface VerifiedEnvelope extends Route { readonly jwe: GeneralJWE }
export interface Envelope extends VerifiedEnvelope { readonly proof: MessageProof }
export interface SealOptions {
  readonly signer: SigningIdentityDocument;
  readonly network_id: string;
  readonly message_id: string;
  readonly recipients: readonly RecipientBinding[];
  readonly roster_version: number;
  readonly roster_sha256: string;
  /** Explicit host clock: this layer does not decide freshness or authorization. */
  readonly created_at: number;
}
export interface VerifyOptions {
  readonly network_id: string;
  /** Explicit trusted keys; never inferred from the incoming envelope. */
  readonly trusted_signers: readonly SigningPublicDescriptor[];
  /** Optional exact recipient set selected from an authenticated roster. */
  readonly recipient_bindings?: readonly RecipientBinding[];
}
export interface OpenOptions extends VerifyOptions { readonly identity: EncryptionIdentityDocument }

/** Content-free failures: private key bytes and provider messages are not included. */
export class NetworkCryptoError extends Error {
  readonly code: string;
  constructor(code: string) { super(code); this.name = 'NetworkCryptoError'; this.code = code; }
}
function fail(code = 'network_invalid_document'): never { throw new NetworkCryptoError(code); }
function hash(raw: Uint8Array): string { return createHash('sha256').update(raw).digest('hex'); }
function b64url(raw: Uint8Array): string { return Buffer.from(raw).toString('base64url'); }
function matches(value: unknown, pattern: RegExp): value is string {
  return typeof value === 'string' && pattern.exec(value)?.[0] === value;
}
function ascii(value: string): boolean { return /^[\x00-\x7f]*$/.test(value); }
function isObject(value: unknown): value is Obj {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}
function fields(value: unknown, names: readonly string[], code = 'network_invalid_document'): Obj {
  if (!isObject(value)) fail(code);
  const keys = Object.keys(value);
  if (keys.length !== names.length || keys.some(key => !names.includes(key))) fail(code);
  return value;
}
function integer(value: unknown, minimum = 0): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < minimum) fail('network_invalid_integer');
  return value;
}
function opaque(value: unknown): string {
  if (!matches(value, /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}/)) fail('network_invalid_identifier');
  return value;
}
function signingId(value: unknown): string {
  if (!matches(value, /^ed25519_[0-9a-f]{64}/)) fail('invalid_key_id');
  return value;
}
function digest(value: unknown): string {
  if (!matches(value, /^[0-9a-f]{64}/)) fail('network_invalid_digest');
  return value;
}
function unb64url(value: unknown, maximum: number, size?: number): Buffer {
  if (!matches(value, /^[A-Za-z0-9_-]*/) || value.length > Math.ceil(maximum * 4 / 3)) fail('network_invalid_base64url');
  const raw = Buffer.from(value, 'base64url');
  if (raw.length > maximum || (size !== undefined && raw.length !== size) || b64url(raw) !== value) fail('network_invalid_base64url');
  return raw;
}
function unbase64(value: unknown, size: number, code: string): Buffer {
  if (typeof value !== 'string' || value.length !== Math.ceil(size / 3) * 4) fail(code);
  const raw = Buffer.from(value, 'base64');
  if (raw.length !== size || raw.toString('base64') !== value) fail(code);
  return raw;
}
function equal(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && timingSafeEqual(left, right);
}
// Shared network/control validation primitives; no alternate JSON/key profile.
export { fields as objectFields, integer as safeInteger, opaque as opaqueId,
  digest as digestHex, signingId as signingKeyId, unb64url as decodeBase64url,
  hash as sha256, b64url as encodeBase64url };

/** The existing Python canonical profile, NOT JCS: ASCII keys, UTF-8 strings,
 * safe integers, sorted keys, no whitespace, floats or Unicode normalization.
 * Plaintext is never passed through this encoder. A uint64 inside opaque memory
 * bytes therefore stays exact even when it cannot be represented by JS Number.
 */
export function canonicalBytes(value: unknown, maximum = MAX_ENVELOPE_BYTES): Uint8Array {
  if (!Number.isSafeInteger(maximum) || maximum < 0 || maximum > MAX_DOCUMENT_BYTES) fail('network_document_too_large');
  const chunks: string[] = [];
  let size = 0;
  function emit(chunk: string): void {
    size += Buffer.byteLength(chunk, 'utf8');
    if (size > maximum) fail('network_document_too_large');
    chunks.push(chunk);
  }
  function string(value: string): void {
    if (value.length > maximum) fail('network_document_too_large');
    if (Buffer.from(value, 'utf8').toString('utf8') !== value) fail('network_nonportable_json');
    emit(JSON.stringify(value));
  }
  function encode(current: unknown, depth: number): void {
    if (depth > 24) fail('network_json_depth');
    if (current === null || typeof current === 'boolean') { emit(JSON.stringify(current)); return; }
    if (typeof current === 'string') { string(current); return; }
    if (typeof current === 'number') {
      if (!Number.isSafeInteger(current)) fail('network_invalid_integer');
      emit(JSON.stringify(current)); return;
    }
    if (Array.isArray(current)) {
      const properties = Object.getOwnPropertyDescriptors(current);
      if (Reflect.ownKeys(current).length !== current.length + 1) fail('network_nonportable_json');
      emit('[');
      for (let i = 0; i < current.length; i++) {
        const property = properties[String(i)];
        if (!property || !('value' in property) || !property.enumerable) fail('network_nonportable_json');
        if (i) emit(','); encode(property.value, depth + 1);
      }
      emit(']'); return;
    }
    if (isObject(current)) {
      const keys = Reflect.ownKeys(current);
      if (keys.some(key => typeof key !== 'string' || !ascii(key))) fail('network_nonportable_json');
      const properties = Object.getOwnPropertyDescriptors(current);
      emit('{'); let first = true;
      for (const key of (keys as string[]).sort()) {
        const property = properties[key];
        if (!('value' in property) || !property.enumerable) fail('network_nonportable_json');
        if (!first) emit(','); first = false;
        string(key); emit(':'); encode(property.value, depth + 1);
      }
      emit('}'); return;
    }
    fail('network_nonportable_json');
  }
  encode(value, 0);
  return Buffer.from(chunks.join(''), 'utf8');
}

// Native JSON.parse erases duplicate names and rounds unsafe integers. Validate
// tokens before conversion, including escaped duplicate names and invalid UTF-8.
function parseStrict(raw: Uint8Array, maximum: number): unknown {
  if (raw.byteLength > maximum) fail('network_document_too_large');
  if (raw.length >= 3 && raw[0] === 0xef && raw[1] === 0xbb && raw[2] === 0xbf) fail('json_bom_forbidden');
  let source: string;
  try { source = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(raw); }
  catch { fail('network_nonportable_json'); }
  let position = 0;
  function whitespace(): void {
    while (position < source.length && /[ \t\r\n]/.test(source[position])) position++;
  }
  function readString(): string {
    const start = position++;
    while (position < source.length) {
      if (source[position] === '\\') { position += 2; continue; }
      if (source[position++] === '"') {
        try { return JSON.parse(source.slice(start, position)); }
        catch { fail('network_nonportable_json'); }
      }
    }
    fail('network_nonportable_json');
  }
  function value(depth: number): unknown {
    if (depth > 24) fail('network_json_depth');
    whitespace();
    if (source[position] === '"') return readString();
    if (source[position] === '{') {
      position++; whitespace(); const result: Obj = Object.create(null);
      if (source[position] === '}') { position++; return result; }
      while (true) {
        if (source[position] !== '"') fail('network_nonportable_json');
        const key = readString(); whitespace();
        if (Object.hasOwn(result, key)) fail('duplicate_json_key');
        if (source[position++] !== ':') fail('network_nonportable_json');
        result[key] = value(depth + 1); whitespace();
        if (source[position] === '}') { position++; return result; }
        if (source[position++] !== ',') fail('network_nonportable_json');
        whitespace();
      }
    }
    if (source[position] === '[') {
      position++; whitespace(); const result: unknown[] = [];
      if (source[position] === ']') { position++; return result; }
      while (true) {
        result.push(value(depth + 1)); whitespace();
        if (source[position] === ']') { position++; return result; }
        if (source[position++] !== ',') fail('network_nonportable_json');
      }
    }
    const token = /^(?:true|false|null|-?(?:0|[1-9][0-9]*))/.exec(source.slice(position));
    if (!token) fail('network_nonportable_json');
    position += token[0].length;
    const result: unknown = JSON.parse(token[0]);
    if (typeof result === 'number' && !Number.isSafeInteger(result)) fail('network_invalid_integer');
    return result;
  }
  const result = value(0); whitespace();
  if (position !== source.length) fail('network_nonportable_json');
  canonicalBytes(result, maximum);
  return result;
}

/** Copy into a validated plain document before any asynchronous provider call. */
export function document(value: DocumentInput, maximum = MAX_ENVELOPE_BYTES): Record<string, JsonValue> {
  if (value instanceof Uint8Array && value.byteLength > maximum) fail('network_document_too_large');
  const raw = value instanceof Uint8Array ? Buffer.from(value) : canonicalBytes(value, maximum);
  const result = parseStrict(raw, maximum);
  if (!isObject(result)) fail('network_invalid_document');
  return result as Record<string, JsonValue>;
}
export function documentSha256(value: DocumentInput): string { return hash(canonicalBytes(document(value))); }

export function validateSigningPublic(value: SigningPublicDescriptor | DocumentInput): SigningPublicDescriptor {
  const raw = fields(document(value as DocumentInput, 4096), PUBLIC_FIELDS, 'invalid_public_descriptor');
  if (raw.schema_version !== SIGNING_PUBLIC_SCHEMA || raw.algorithm !== 'Ed25519') fail('unsupported_public_key_schema');
  const publicBytes = unbase64(raw.public_key, 32, 'invalid_public_key');
  signingId(raw.key_id);
  if (raw.key_id !== 'ed25519_' + hash(publicBytes)) fail('key_id_mismatch');
  return raw as unknown as SigningPublicDescriptor;
}
export function validateEncryptionPublic(value: EncryptionPublicDescriptor | DocumentInput): EncryptionPublicDescriptor {
  const raw = fields(document(value as DocumentInput, 4096), PUBLIC_FIELDS);
  if (raw.schema_version !== ENCRYPTION_PUBLIC_SCHEMA || raw.algorithm !== 'X25519') fail('network_unsupported_encryption_key');
  const publicBytes = unb64url(raw.public_key, 32, 32);
  if (raw.key_id !== 'x25519_' + hash(publicBytes)) fail('network_encryption_key_mismatch');
  return raw as unknown as EncryptionPublicDescriptor;
}
function privateKey(secret: Uint8Array, curve: 'Ed25519' | 'X25519'): KeyObject {
  // RFC 8410 PKCS#8 contains only the raw private bytes. Derive the public key
  // with the provider; importing a caller-supplied public JWK is not a pair check.
  const prefix = curve === 'Ed25519' ? '302e020100300506032b657004220420' : '302e020100300506032b656e04220420';
  try { return createPrivateKey({ key: Buffer.concat([Buffer.from(prefix, 'hex'), secret]), format: 'der', type: 'pkcs8' }); }
  catch { fail('network_private_key_invalid'); }
}
function signingIdentity(value: SigningIdentityDocument): { descriptor: SigningPublicDescriptor; key: KeyObject } {
  const raw = fields(document(value as unknown as DocumentInput, 4096), [...PUBLIC_FIELDS, 'private_key']);
  if (raw.schema_version !== SIGNING_PRIVATE_SCHEMA) fail('unsupported_identity_schema');
  const descriptor = validateSigningPublic({ schema_version: SIGNING_PUBLIC_SCHEMA, algorithm: raw.algorithm,
    key_id: raw.key_id, public_key: raw.public_key });
  const key = privateKey(unbase64(raw.private_key, 32, 'invalid_private_key'), 'Ed25519');
  const actual = createPublicKey(key).export({ format: 'jwk' });
  if (actual.x !== b64url(unbase64(descriptor.public_key, 32, 'invalid_public_key'))) fail('network_private_key_mismatch');
  return { descriptor, key };
}
function encryptionIdentity(value: EncryptionIdentityDocument): { descriptor: EncryptionPublicDescriptor; jwk: JWK } {
  const raw = fields(document(value as unknown as DocumentInput, 4096), [...PUBLIC_FIELDS, 'private_key']);
  if (raw.schema_version !== ENCRYPTION_PRIVATE_SCHEMA) fail('network_unsupported_private_key');
  const descriptor = validateEncryptionPublic({ schema_version: ENCRYPTION_PUBLIC_SCHEMA, algorithm: raw.algorithm,
    key_id: raw.key_id, public_key: raw.public_key });
  const key = privateKey(unb64url(raw.private_key, 32, 32), 'X25519');
  const actual = createPublicKey(key).export({ format: 'jwk' });
  if (actual.x !== descriptor.public_key) fail('network_private_key_mismatch');
  return { descriptor, jwk: { kty: 'OKP', crv: 'X25519', x: descriptor.public_key,
    d: raw.private_key as string, kid: descriptor.key_id } };
}
function publicEncryptionJWK(descriptor: EncryptionPublicDescriptor): JWK {
  return { kty: 'OKP', crv: 'X25519', x: descriptor.public_key, kid: descriptor.key_id };
}

/** Validate the existing private document and its actual provider-derived pair. */
export function validateSigningIdentity(value: SigningIdentityDocument): SigningPublicDescriptor {
  return signingIdentity(value).descriptor;
}
export function validateEncryptionIdentity(value: EncryptionIdentityDocument): EncryptionPublicDescriptor {
  return encryptionIdentity(value).descriptor;
}

/** Existing universal-memory message proof, also used by network control. */
export function signMessage(value: DocumentInput, signer: SigningIdentityDocument): MessageProof {
  const payload = document(value);
  const local = signingIdentity(signer);
  const proof = { schema_version: PROOF_SCHEMA, key_id: local.descriptor.key_id,
    payload_sha256: hash(canonicalBytes(payload)) };
  let signature: string;
  try { signature = edSign(null, Buffer.concat([MESSAGE_DOMAIN, canonicalBytes(proof)]), local.key).toString('base64'); }
  catch { fail('network_signing_failed'); }
  return { ...proof, signature } as MessageProof;
}

/** Return only the signer ID proven by an explicit host-supplied trust set. */
export function verifyMessage(value: DocumentInput, valueProof: MessageProof | DocumentInput,
  trustedSigners: readonly SigningPublicDescriptor[]): string {
  const payload = document(value);
  const proof = fields(document(valueProof as DocumentInput, 4096),
    ['schema_version', 'key_id', 'payload_sha256', 'signature'], 'invalid_proof');
  if (!Array.isArray(trustedSigners)) fail('network_invalid_document');
  const trusted = new Map<string, SigningPublicDescriptor>();
  for (const item of trustedSigners) {
    const key = validateSigningPublic(item);
    if (trusted.has(key.key_id)) fail('network_duplicate_signer');
    trusted.set(key.key_id, key);
  }
  if (proof.schema_version !== PROOF_SCHEMA) fail('unsupported_proof_schema');
  const keyId = signingId(proof.key_id); digest(proof.payload_sha256);
  const descriptor = trusted.get(keyId);
  if (!descriptor) fail('unknown_key');
  if (proof.payload_sha256 !== hash(canonicalBytes(payload))) fail('payload_digest_mismatch');
  const signature = unbase64(proof.signature, 64, 'invalid_signature');
  const proofBody = { schema_version: proof.schema_version, key_id: proof.key_id, payload_sha256: proof.payload_sha256 };
  let valid = false;
  try {
    const publicKey = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519',
      x: b64url(unbase64(descriptor.public_key, 32, 'invalid_public_key')) }, format: 'jwk' });
    valid = edVerify(null, Buffer.concat([MESSAGE_DOMAIN, canonicalBytes(proofBody)]), publicKey, signature);
  } catch { fail('invalid_signature'); }
  if (!valid) fail('invalid_signature');
  return keyId;
}
function contextBytes(value: DocumentInput): Uint8Array { return canonicalBytes(document(value, CONTEXT_LIMIT), CONTEXT_LIMIT); }

export function validateJwe(value: DocumentInput | GeneralJWE, options: { context: DocumentInput }): GeneralJWE {
  const raw = fields(document(value as DocumentInput), ['protected', 'recipients', 'aad', 'iv', 'ciphertext', 'tag']);
  const protectedHeader = document(unb64url(raw.protected, 1024), 1024);
  if (!equal(canonicalBytes(protectedHeader), canonicalBytes({ enc: ENC, typ: BYTES_SCHEMA }))) fail('network_jwe_profile_mismatch');
  if (!equal(unb64url(raw.aad, CONTEXT_LIMIT), contextBytes(options.context))) fail('network_context_mismatch');
  unb64url(raw.iv, 12, 12); unb64url(raw.tag, 16, 16);
  const ciphertext = unb64url(raw.ciphertext, MAX_PLAINTEXT_BYTES + MAGIC.length + 40);
  if (ciphertext.length < MAGIC.length + 40) fail('network_ciphertext_truncated');
  if (!Array.isArray(raw.recipients) || raw.recipients.length < 1 || raw.recipients.length > MAX_RECIPIENTS) fail('network_recipient_limit');
  const seen = new Set<string>();
  for (const item of raw.recipients) {
    const entry = fields(item, ['header', 'encrypted_key']);
    const header = fields(entry.header, ['alg', 'kid', 'epk']);
    if (header.alg !== ALG || !matches(header.kid, /^x25519_[0-9a-f]{64}/)) fail('network_jwe_algorithm_rejected');
    if (seen.has(header.kid)) fail('network_duplicate_recipient');
    seen.add(header.kid);
    const ephemeral = fields(header.epk, ['kty', 'crv', 'x']);
    if (ephemeral.kty !== 'OKP' || ephemeral.crv !== 'X25519') fail('network_ephemeral_key_rejected');
    unb64url(ephemeral.x, 32, 32); unb64url(entry.encrypted_key, 40, 40);
  }
  return raw as unknown as GeneralJWE;
}

export async function encryptBytes(plaintext: Uint8Array, recipients: readonly EncryptionPublicDescriptor[],
  options: { context: DocumentInput }): Promise<GeneralJWE> {
  if (!(plaintext instanceof Uint8Array) || plaintext.byteLength > MAX_PLAINTEXT_BYTES) fail('network_plaintext_limit');
  const bytes = Buffer.from(plaintext);
  if (!Array.isArray(recipients) || recipients.length < 1 || recipients.length > MAX_RECIPIENTS) fail('network_recipient_limit');
  const keys = recipients.map(value => validateEncryptionPublic(value));
  if (new Set(keys.map(key => key.key_id)).size !== keys.length) fail('network_duplicate_recipient');
  const context = document(options.context, CONTEXT_LIMIT);
  const length = Buffer.alloc(8); length.writeBigUInt64BE(BigInt(bytes.length));
  const frame = Buffer.concat([MAGIC, length, Buffer.from(hash(bytes), 'hex'), bytes]);
  let result: GeneralJWE;
  try {
    const builder = new GeneralEncrypt(frame).setProtectedHeader({ enc: ENC, typ: BYTES_SCHEMA })
      .setAdditionalAuthenticatedData(contextBytes(context));
    keys.sort((left, right) => left.key_id < right.key_id ? -1 : left.key_id > right.key_id ? 1 : 0);
    // jose 6.2.10's single-recipient shortcut adds epk to the protected header.
    // Its public multi-recipient API keeps epk per recipient, as network-v1
    // requires. For one destination wrap twice to the SAME authorized key,
    // then discard the redundant wrap before validation and the outer signature.
    // No other key receives the CEK; protected/AAD/ciphertext/tag stay unchanged.
    const wrappingKeys = keys.length === 1 ? [keys[0], keys[0]] : keys;
    for (const key of wrappingKeys) {
      builder.addRecipient(await importJWK(publicEncryptionJWK(key), ALG)).setUnprotectedHeader({ alg: ALG, kid: key.key_id });
    }
    result = await builder.encrypt();
    if (keys.length === 1) result.recipients = result.recipients.slice(0, 1);
  } catch { fail('network_encryption_failed'); }
  return validateJwe(result, { context });
}

export async function decryptBytes(value: DocumentInput | GeneralJWE, identity: EncryptionIdentityDocument,
  options: { context: DocumentInput }): Promise<Uint8Array> {
  const context = document(options.context, CONTEXT_LIMIT);
  const raw = validateJwe(value, { context });
  const local = encryptionIdentity(identity);
  if (!raw.recipients.some(item => item.header?.kid === local.descriptor.key_id)) fail('network_not_a_recipient');
  let frame: Buffer;
  try {
    const result = await generalDecrypt(raw, await importJWK(local.jwk, ALG), {
      keyManagementAlgorithms: [ALG], contentEncryptionAlgorithms: [ENC],
    });
    frame = Buffer.from(result.plaintext);
  } catch { fail('network_decryption_failed'); }
  if (frame.length < MAGIC.length + 40 || !equal(frame.subarray(0, MAGIC.length), MAGIC)) fail('network_plaintext_frame_invalid');
  const plaintext = frame.subarray(MAGIC.length + 40);
  if (frame.readBigUInt64BE(MAGIC.length) !== BigInt(plaintext.length) || plaintext.length > MAX_PLAINTEXT_BYTES ||
      !equal(frame.subarray(MAGIC.length + 8, MAGIC.length + 40), Buffer.from(hash(plaintext), 'hex'))) fail('network_plaintext_integrity_failed');
  return Buffer.from(plaintext);
}

function routing(raw: Obj): Route {
  const route: Obj = Object.fromEntries(ROUTE_FIELDS.map(name => [name, raw[name]]));
  if (route.schema_version !== ENVELOPE_SCHEMA) fail('network_envelope_schema_mismatch');
  opaque(route.network_id); opaque(route.message_id);
  if (!matches(route.sender_key_id, /^ed25519_[0-9a-f]{64}/)) fail('network_invalid_sender');
  const recipients = route.recipient_key_ids;
  if (!Array.isArray(recipients) || recipients.length < 1 || recipients.length > MAX_RECIPIENTS ||
      recipients.some((key, index) => !matches(key, /^ed25519_[0-9a-f]{64}/) || (index > 0 && key <= recipients[index - 1]))) fail('network_invalid_recipients');
  integer(route.roster_version, 1); digest(route.roster_sha256); integer(route.created_at);
  return route as unknown as Route;
}
function bindings(value: readonly RecipientBinding[]): RecipientBinding[] {
  if (!Array.isArray(value) || value.length < 1 || value.length > MAX_RECIPIENTS) fail('network_recipient_limit');
  const checked = value.map(item => {
    const raw = fields(document(item as unknown as DocumentInput, 8192), ['signing_key_id', 'encryption_key']);
    return { signing_key_id: signingId(raw.signing_key_id), encryption_key: validateEncryptionPublic(raw.encryption_key as DocumentInput) };
  });
  if (new Set(checked.map(item => item.signing_key_id)).size !== checked.length ||
      new Set(checked.map(item => item.encryption_key.key_id)).size !== checked.length) fail('network_duplicate_recipient');
  return checked;
}

export async function seal(plaintext: Uint8Array, options: SealOptions): Promise<Envelope> {
  const checked = fields(document(options as unknown as DocumentInput, 64 * 1024),
    ['signer', 'network_id', 'message_id', 'recipients', 'roster_version', 'roster_sha256', 'created_at']);
  const local = signingIdentity(checked.signer as unknown as SigningIdentityDocument);
  const recipients = bindings(checked.recipients as unknown as RecipientBinding[]);
  const route = routing({ schema_version: ENVELOPE_SCHEMA, network_id: checked.network_id,
    message_id: checked.message_id, sender_key_id: local.descriptor.key_id,
    recipient_key_ids: recipients.map(item => item.signing_key_id).sort(), roster_version: checked.roster_version,
    roster_sha256: checked.roster_sha256, created_at: checked.created_at });
  const jwe = await encryptBytes(plaintext, recipients.map(item => item.encryption_key), { context: route as unknown as DocumentInput });
  const payload = { ...route, jwe };
  const proof = signMessage(payload as unknown as DocumentInput, checked.signer as unknown as SigningIdentityDocument);
  return document({ ...payload, proof }) as unknown as Envelope;
}

/** Verify syntax, AAD binding and signature. Does NOT authenticate a roster,
 * enforce freshness/revocation/replay, or give plaintext permission to execute.
 */
export function verify(value: DocumentInput | Envelope, options: VerifyOptions): VerifiedEnvelope {
  const raw = fields(document(value as DocumentInput), [...ROUTE_FIELDS, 'jwe', 'proof']);
  const route = routing(raw);
  if (route.network_id !== opaque(options.network_id)) fail('network_wrong_network');
  const jwe = validateJwe(raw.jwe as DocumentInput, { context: route as unknown as DocumentInput });
  if (jwe.recipients.length !== route.recipient_key_ids.length) fail('network_recipient_binding_mismatch');
  const proof = fields(raw.proof, ['schema_version', 'key_id', 'payload_sha256', 'signature'], 'invalid_proof');
  if (proof.key_id !== route.sender_key_id) fail('network_sender_signature_mismatch');
  const payload = { ...route, jwe };
  verifyMessage(payload as unknown as DocumentInput, proof, options.trusted_signers);
  if (options.recipient_bindings !== undefined) {
    const selected = bindings(options.recipient_bindings);
    const signing = selected.map(item => item.signing_key_id).sort();
    const encryption = selected.map(item => item.encryption_key.key_id).sort();
    const actual = jwe.recipients.map(item => item.header!.kid as string).sort();
    if (!equal(canonicalBytes(signing), canonicalBytes(route.recipient_key_ids)) ||
        !equal(canonicalBytes(encryption), canonicalBytes(actual))) fail('network_recipient_binding_mismatch');
  }
  return payload;
}

/** Verify first, then decrypt with the one host-injected local X25519 identity. */
export async function open(value: DocumentInput | Envelope, options: OpenOptions): Promise<Uint8Array> {
  const payload = verify(value, options);
  return decryptBytes(payload.jwe, options.identity, { context: routing(payload as unknown as Obj) as unknown as DocumentInput });
}
