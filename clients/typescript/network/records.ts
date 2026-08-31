/** Independent 0.25 canonical records and private share codec.
 * No storage, identity creation, enrollment, transport or admission policy.
 * Parsing a share proves its shape/closure/checksums, never sender authority.
 */
import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import {
  canonicalBytes, document, objectFields, sha256, validateSigningPublic,
  validateSigningIdentity, NetworkCryptoError,
} from './crypto.ts';
import type { DocumentInput, SigningIdentityDocument, SigningPublicDescriptor } from './crypto.ts';

export const RECORD_SCHEMA = 'universal-memory-record/v1';
export const HASH_PROFILE = 'canonical-json+sha256/v1';
export const ATTESTATION_SCHEMA = 'universal-memory-attestation/v1';
export const SHARE_SCHEMA = 'universal-memory-share/v1';
export const SELECTOR_SCHEMA = 'universal-memory-selection/v1';
export const NORMALIZATION_UNICODE_VERSION = '14.0.0';
export const MAX_RECORD_BYTES = 2 * 1024 * 1024;
export const MAX_SHARE_BYTES = 2 * 1024 * 1024 * 1024;
export const MAX_SHARE_RECORDS = 250_000;
const MAX_LINE_BYTES = MAX_RECORD_BYTES + 4096;
const MAX_TEXT_BYTES = 1024 * 1024;
const MAX_SELECTOR_BYTES = 16 * 1024;
const DOMAIN = Buffer.from('UniversalAgentMemory\0record-attestation\0v1\0', 'ascii');
const KINDS = ['event', 'fact', 'observation', 'decision', 'artifact', 'entity', 'relation',
  'provenance', 'summary', 'goal', 'continuity', 'episode'] as const;
const RELATIONS = ['related_to', 'derived_from', 'supports', 'supersedes', 'conflicts_with',
  'resolves', 'continues'] as const;
const PROVENANCE = ['source_ref', 'task_ref', 'project_ref', 'conversation_ref', 'model_ref',
  'agent_ref', 'device_ref', 'request_ref', 'source_type', 'confidence'];
const RECORD_FIELDS = ['schema_version', 'hash_profile', 'kind', 'text', 'entities', 'relations',
  'provenance', 'created_at', 'memory_id', 'record_sha256'];
const PROOF_FIELDS = ['schema_version', 'key_id', 'record_sha256', 'signature'];
const SELECTOR_LISTS = ['memory_ids', 'claim_keys', 'concepts', 'entities', 'kinds'] as const;
const SELECTOR_FIELDS = ['schema_version', ...SELECTOR_LISTS, 'captured_after', 'captured_before', 'all_records'];
// Python str.isspace/re \s includes these controls and excludes U+FEFF.
const SPACE = /[\u0009-\u000d\u001c-\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+/gu;
const ONLY_SPACE = /^[\u0009-\u000d\u001c-\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]*$/u;
type Obj = Record<string, unknown>;
export type MemoryKind = typeof KINDS[number];
export type RelationType = typeof RELATIONS[number];
export interface MemoryRelation { readonly type: RelationType; readonly target: string }
export interface MemoryRecord {
  readonly schema_version: typeof RECORD_SCHEMA;
  readonly hash_profile: typeof HASH_PROFILE;
  readonly kind: MemoryKind;
  readonly text: string;
  readonly entities: readonly string[];
  readonly relations: readonly MemoryRelation[];
  /** Existing v1 provenance values are strings, not arbitrary JSON or integers. */
  readonly provenance: Readonly<Record<string, string>>;
  readonly created_at: string;
  readonly memory_id: string;
  readonly record_sha256: string;
}
export interface RecordAttestation {
  readonly schema_version: typeof ATTESTATION_SCHEMA;
  readonly key_id: string;
  readonly record_sha256: string;
  readonly signature: string;
}
/** The legacy share format permits unsigned records. Admission must require a
 * proof and call verifyRecord with the current host-authorized signer set. */
export interface SignedMemory { readonly record: MemoryRecord; readonly attestation: RecordAttestation | null }
export interface BuildRecordInput {
  readonly kind: MemoryKind;
  readonly text: string;
  readonly entities?: readonly string[] | null;
  readonly relations?: readonly MemoryRelation[] | null;
  readonly provenance?: Readonly<Record<string, string>> | null;
  readonly created_at?: string | null;
}
export interface ShareSelector {
  readonly schema_version: typeof SELECTOR_SCHEMA;
  readonly memory_ids: readonly string[];
  readonly claim_keys: readonly string[];
  readonly concepts: readonly string[];
  readonly entities: readonly string[];
  readonly kinds: readonly string[];
  readonly captured_after: string | null;
  readonly captured_before: string | null;
  readonly all_records: boolean;
}
export interface ShareHeader {
  readonly type: 'header'; readonly schema_version: typeof SHARE_SCHEMA;
  readonly hash_profile: typeof HASH_PROFILE; readonly created_at: string;
  readonly selector: ShareSelector; readonly selector_sha256: string;
}
export interface ShareSummary {
  readonly schema_version: typeof SHARE_SCHEMA;
  readonly records: number; readonly selected_records: number; readonly dependency_records: number;
  readonly attestations: number; readonly raw_bytes: number; readonly sha256: string;
  readonly selector_sha256: string; readonly records_sha256: string;
  readonly dependency_closure_verified: true; readonly signatures_cryptographically_verified: false;
  readonly checksum_authenticates_sender: false; readonly grants_authority: false;
}
export interface ParsedShare {
  readonly records: SignedMemory[]; readonly roots: string[];
  readonly header: ShareHeader; readonly summary: ShareSummary;
}
export class NetworkRecordsError extends Error {
  readonly code: string;
  constructor(code: string) { super(code); this.name = 'NetworkRecordsError'; this.code = code; }
}
function fail(code: string): never { throw new NetworkRecordsError(code); }
function checked<T>(operation: () => T): T {
  try { return operation(); }
  catch (error) {
    if (error instanceof NetworkRecordsError) throw error;
    if (error instanceof NetworkCryptoError) fail(error.code);
    fail('invalid_record_value');
  }
}
function match(value: unknown, pattern: RegExp): value is string {
  return typeof value === 'string' && pattern.exec(value)?.[0] === value;
}
function memoryId(value: unknown): string {
  if (!match(value, /^mem_[0-9a-f]{40}/)) fail('invalid_memory_id');
  return value;
}
function text(value: unknown, maximum: number, code: string): string {
  if (typeof value !== 'string' || ONLY_SPACE.test(value) || value.includes('\0') ||
      Buffer.from(value).toString('utf8') !== value) fail(code);
  if (Buffer.byteLength(value, 'utf8') > maximum) fail(code === 'invalid_text' ? 'text_too_large' : code);
  return value;
}
function entities(value: unknown): string[] {
  if (value === null || value === undefined) return [];
  if (!Array.isArray(value) || value.length > 256) fail('invalid_entities');
  return [...new Set(value.map(item => text(item, 512, 'invalid_entities')))];
}
function relations(value: unknown): MemoryRelation[] {
  if (value === null || value === undefined) return [];
  if (!Array.isArray(value) || value.length > 256) fail('invalid_relations');
  const result: MemoryRelation[] = [], seen = new Set<string>();
  for (const item of value) {
    const raw = objectFields(item, ['type', 'target'], 'invalid_relation');
    if (!RELATIONS.includes(raw.type as RelationType)) fail('invalid_relation');
    const target = memoryId(raw.target), key = raw.type + ':' + target;
    if (!seen.has(key)) { result.push({ type: raw.type as RelationType, target }); seen.add(key); }
  }
  return result;
}
function provenance(value: unknown): Record<string, string> {
  if (value === null || value === undefined) return {};
  if (value === null || typeof value !== 'object' || Array.isArray(value)) fail('invalid_provenance');
  const result: Record<string, string> = {};
  for (const [key, item] of Object.entries(value)) {
    if (!PROVENANCE.includes(key)) fail('forbidden_provenance_field');
    result[key] = text(item, 2048, 'invalid_provenance');
  }
  if (result.source_type !== undefined && !['visible_turn', 'agent_supplied', 'imported'].includes(result.source_type)) fail('invalid_provenance');
  if (result.confidence !== undefined && !['observed', 'assistant_inferred', 'imported'].includes(result.confidence)) fail('invalid_provenance');
  if (canonicalBytes(result).length > 64 * 1024) fail('provenance_too_large');
  return result;
}

/** Exact microsecond comparison, without Date's invalid-day normalization or
 * millisecond rounding. BigInt is private arithmetic, never network JSON. */
function timestamp(value: unknown, share = false): { normalized: string; micros: bigint } {
  const pattern = share
    ? /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,6}))?(Z|[+-][0-9]{2}:[0-9]{2})/
    : /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,6}))?(Z)/;
  const code = share ? 'invalid_share_timestamp' : 'invalid_timestamp';
  if (typeof value !== 'string') fail(code);
  const parts = pattern.exec(value);
  if (!parts || parts[0] !== value) fail(code);
  const [year, month, day, hour, minute, second] = parts.slice(1, 7).map(Number);
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (year < 1 || month < 1 || month > 12 || day < 1 || day > days[month - 1] ||
      hour > 23 || minute > 59 || second > 59) fail(code);
  let offset = 0;
  if (parts[8] !== 'Z') {
    const h = Number(parts[8].slice(1, 3)), m = Number(parts[8].slice(4, 6));
    // Python accepts offset minute overflow, provided the total is <24 hours.
    offset = (h * 60 + m) * (parts[8][0] === '+' ? 1 : -1);
    if (Math.abs(offset) >= 24 * 60) fail(code);
  }
  const utc = new Date(0);
  utc.setUTCFullYear(year, month - 1, day); utc.setUTCHours(hour, minute - offset, second, 0);
  if (utc.getUTCFullYear() < 1 || utc.getUTCFullYear() > 9999) fail(code);
  const fraction = (parts[7] || '').padEnd(6, '0');
  const normalized = utc.toISOString().slice(0, 19) + (Number(fraction) ? '.' + fraction : '') + 'Z';
  return { normalized, micros: BigInt(utc.getTime()) * 1000n + BigInt(fraction) };
}
function record(value: unknown): MemoryRecord {
  const raw = objectFields(document(value as DocumentInput, MAX_RECORD_BYTES), RECORD_FIELDS, 'invalid_record');
  if (raw.schema_version !== RECORD_SCHEMA || raw.hash_profile !== HASH_PROFILE) fail('unsupported_record_schema');
  if (!KINDS.includes(raw.kind as MemoryKind)) fail('invalid_kind');
  const body: Omit<MemoryRecord, 'memory_id' | 'record_sha256'> = { schema_version: RECORD_SCHEMA, hash_profile: HASH_PROFILE, kind: raw.kind as MemoryKind,
    text: text(raw.text, MAX_TEXT_BYTES, 'invalid_text'), entities: entities(raw.entities),
    relations: relations(raw.relations), provenance: provenance(raw.provenance), created_at: raw.created_at as string };
  timestamp(body.created_at);
  memoryId(raw.memory_id);
  if (!match(raw.record_sha256, /^[0-9a-f]{64}/)) fail('invalid_record_hash');
  const digest = sha256(canonicalBytes(body, MAX_RECORD_BYTES));
  if (raw.record_sha256 !== digest || raw.memory_id !== 'mem_' + digest.slice(0, 40)) fail('record_hash_mismatch');
  return { ...body, memory_id: raw.memory_id as string, record_sha256: digest };
}
export function validateRecord(value: unknown): MemoryRecord { return checked(() => record(value)); }
/** Core validation normalizes duplicate entities/relations. Author signatures
 * must reject such unbound variants, exactly as Python trust._record_digest. */
export function canonicalRecordBytes(value: unknown): Uint8Array {
  return checked(() => {
    const raw = document(value as DocumentInput, MAX_RECORD_BYTES), normalized = record(raw);
    const result = canonicalBytes(normalized, MAX_RECORD_BYTES);
    if (!Buffer.from(result).equals(Buffer.from(canonicalBytes(raw, MAX_RECORD_BYTES)))) fail('non_canonical_record');
    return result;
  });
}
export function buildRecord(input: BuildRecordInput): MemoryRecord {
  return checked(() => {
    // Allow ordinary TS optional properties with undefined, but never getters,
    // hidden properties, custom prototypes, or unknown input fields.
    if (!input || typeof input !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(input))) fail('invalid_record');
    const allowed = ['kind', 'text', 'entities', 'relations', 'provenance', 'created_at'];
    const clean: Obj = {};
    for (const key of Reflect.ownKeys(input)) {
      if (typeof key !== 'string' || !allowed.includes(key)) fail('invalid_record');
      const descriptor = Object.getOwnPropertyDescriptor(input, key)!;
      if (!descriptor.enumerable || !('value' in descriptor)) fail('invalid_record');
      if (descriptor.value !== undefined) clean[key] = descriptor.value;
    }
    const raw = document(clean, MAX_RECORD_BYTES);
    if (!KINDS.includes(raw.kind as MemoryKind)) fail('invalid_kind');
    const body: Omit<MemoryRecord, 'memory_id' | 'record_sha256'> = { schema_version: RECORD_SCHEMA, hash_profile: HASH_PROFILE, kind: raw.kind as MemoryKind,
      text: text(raw.text, MAX_TEXT_BYTES, 'invalid_text'), entities: entities(raw.entities),
      relations: relations(raw.relations), provenance: provenance(raw.provenance),
      created_at: (raw.created_at ?? new Date().toISOString()) as string };
    timestamp(body.created_at);
    const digest = sha256(canonicalBytes(body, MAX_RECORD_BYTES));
    const result: MemoryRecord = { ...body, memory_id: 'mem_' + digest.slice(0, 40), record_sha256: digest };
    canonicalBytes(result, MAX_RECORD_BYTES);
    return result;
  });
}
function base64(value: unknown, size: number, code: string): Buffer {
  if (typeof value !== 'string' || value.length !== Math.ceil(size / 3) * 4) fail(code);
  const bytes = Buffer.from(value, 'base64');
  if (bytes.length !== size || bytes.toString('base64') !== value) fail(code);
  return bytes;
}
function attestation(value: unknown, digest: string): RecordAttestation {
  const raw = objectFields(document(value as DocumentInput, 2048), PROOF_FIELDS, 'invalid_signature_proof');
  if (raw.schema_version !== ATTESTATION_SCHEMA) fail('unsupported_signature_schema');
  if (!match(raw.key_id, /^ed25519_[0-9a-f]{64}/)) fail('invalid_key_id');
  if (!match(raw.record_sha256, /^[0-9a-f]{64}/)) fail('invalid_signature_digest');
  if (raw.record_sha256 !== digest) fail('signature_digest_mismatch');
  base64(raw.signature, 64, 'invalid_signature');
  return raw as unknown as RecordAttestation;
}
export function signRecord(value: MemoryRecord, identity: SigningIdentityDocument): RecordAttestation {
  return checked(() => {
    const normalized = record(canonicalRecordBytes(value));
    const rawIdentity = document(identity as unknown as DocumentInput, 4096);
    const publicKey = validateSigningIdentity(rawIdentity as unknown as SigningIdentityDocument);
    const secret = base64(rawIdentity.private_key, 32, 'invalid_private_key');
    const key = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), secret]),
      format: 'der', type: 'pkcs8' });
    const body: Omit<RecordAttestation, 'signature'> = { schema_version: ATTESTATION_SCHEMA, key_id: publicKey.key_id, record_sha256: normalized.record_sha256 };
    return { ...body, signature: sign(null, Buffer.concat([DOMAIN, canonicalBytes(body)]), key).toString('base64') };
  });
}
/** Signature validity alone does not grant admission: the caller supplies an
 * explicit current authorized key set, never keys learned from this share. */
export function verifyRecord(value: MemoryRecord, proof: RecordAttestation | null,
                             trustedPublicKeys: readonly SigningPublicDescriptor[]): string {
  return checked(() => {
    const normalized = record(canonicalRecordBytes(value)), validated = attestation(proof, normalized.record_sha256);
    if (!Array.isArray(trustedPublicKeys)) fail('invalid_trusted_keys');
    const keys = trustedPublicKeys.map(item => validateSigningPublic(item));
    const descriptor = keys.find(item => item.key_id === validated.key_id);
    if (!descriptor) fail('unknown_key');
    const key = createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'),
      base64(descriptor.public_key, 32, 'invalid_public_key')]), format: 'der', type: 'spki' });
    const body = { schema_version: ATTESTATION_SCHEMA, key_id: validated.key_id, record_sha256: validated.record_sha256 };
    if (!verify(null, Buffer.concat([DOMAIN, canonicalBytes(body)]), key, base64(validated.signature, 64, 'invalid_signature'))) fail('signature_invalid');
    return descriptor.key_id;
  });
}

// UNICODE_TABLES: generated from CPython 3.11 unicodedata 14.0.0, without a
// runtime Python dependency. Only normalization/search uses these tables;
// canonical bytes, record IDs, original text and attestations never do.
const CASEFOLD_DATA = [
  '41:61 42:62 43:63 44:64 45:65 46:66 47:67 48:68 49:69 4a:6a 4b:6b 4c:6c 4d:6d 4e:6e 4f:6f 50:70 51:71 52:72',
  '53:73 54:74 55:75 56:76 57:77 58:78 59:79 5a:7a b5:3bc c0:e0 c1:e1 c2:e2 c3:e3 c4:e4 c5:e5 c6:e6 c7:e7 c8:e8',
  'c9:e9 ca:ea cb:eb cc:ec cd:ed ce:ee cf:ef d0:f0 d1:f1 d2:f2 d3:f3 d4:f4 d5:f5 d6:f6 d8:f8 d9:f9 da:fa db:fb',
  'dc:fc dd:fd de:fe df:73,73 100:101 102:103 104:105 106:107 108:109 10a:10b 10c:10d 10e:10f 110:111 112:113',
  '114:115 116:117 118:119 11a:11b 11c:11d 11e:11f 120:121 122:123 124:125 126:127 128:129 12a:12b 12c:12d 12e:12f',
  '130:69,307 132:133 134:135 136:137 139:13a 13b:13c 13d:13e 13f:140 141:142 143:144 145:146 147:148 149:2bc,6e',
  '14a:14b 14c:14d 14e:14f 150:151 152:153 154:155 156:157 158:159 15a:15b 15c:15d 15e:15f 160:161 162:163 164:165',
  '166:167 168:169 16a:16b 16c:16d 16e:16f 170:171 172:173 174:175 176:177 178:ff 179:17a 17b:17c 17d:17e 17f:73',
  '181:253 182:183 184:185 186:254 187:188 189:256 18a:257 18b:18c 18e:1dd 18f:259 190:25b 191:192 193:260 194:263',
  '196:269 197:268 198:199 19c:26f 19d:272 19f:275 1a0:1a1 1a2:1a3 1a4:1a5 1a6:280 1a7:1a8 1a9:283 1ac:1ad 1ae:288',
  '1af:1b0 1b1:28a 1b2:28b 1b3:1b4 1b5:1b6 1b7:292 1b8:1b9 1bc:1bd 1c4:1c6 1c5:1c6 1c7:1c9 1c8:1c9 1ca:1cc 1cb:1cc',
  '1cd:1ce 1cf:1d0 1d1:1d2 1d3:1d4 1d5:1d6 1d7:1d8 1d9:1da 1db:1dc 1de:1df 1e0:1e1 1e2:1e3 1e4:1e5 1e6:1e7 1e8:1e9',
  '1ea:1eb 1ec:1ed 1ee:1ef 1f0:6a,30c 1f1:1f3 1f2:1f3 1f4:1f5 1f6:195 1f7:1bf 1f8:1f9 1fa:1fb 1fc:1fd 1fe:1ff',
  '200:201 202:203 204:205 206:207 208:209 20a:20b 20c:20d 20e:20f 210:211 212:213 214:215 216:217 218:219 21a:21b',
  '21c:21d 21e:21f 220:19e 222:223 224:225 226:227 228:229 22a:22b 22c:22d 22e:22f 230:231 232:233 23a:2c65',
  '23b:23c 23d:19a 23e:2c66 241:242 243:180 244:289 245:28c 246:247 248:249 24a:24b 24c:24d 24e:24f 345:3b9',
  '370:371 372:373 376:377 37f:3f3 386:3ac 388:3ad 389:3ae 38a:3af 38c:3cc 38e:3cd 38f:3ce 390:3b9,308,301 391:3b1',
  '392:3b2 393:3b3 394:3b4 395:3b5 396:3b6 397:3b7 398:3b8 399:3b9 39a:3ba 39b:3bb 39c:3bc 39d:3bd 39e:3be 39f:3bf',
  '3a0:3c0 3a1:3c1 3a3:3c3 3a4:3c4 3a5:3c5 3a6:3c6 3a7:3c7 3a8:3c8 3a9:3c9 3aa:3ca 3ab:3cb 3b0:3c5,308,301 3c2:3c3',
  '3cf:3d7 3d0:3b2 3d1:3b8 3d5:3c6 3d6:3c0 3d8:3d9 3da:3db 3dc:3dd 3de:3df 3e0:3e1 3e2:3e3 3e4:3e5 3e6:3e7 3e8:3e9',
  '3ea:3eb 3ec:3ed 3ee:3ef 3f0:3ba 3f1:3c1 3f4:3b8 3f5:3b5 3f7:3f8 3f9:3f2 3fa:3fb 3fd:37b 3fe:37c 3ff:37d 400:450',
  '401:451 402:452 403:453 404:454 405:455 406:456 407:457 408:458 409:459 40a:45a 40b:45b 40c:45c 40d:45d 40e:45e',
  '40f:45f 410:430 411:431 412:432 413:433 414:434 415:435 416:436 417:437 418:438 419:439 41a:43a 41b:43b 41c:43c',
  '41d:43d 41e:43e 41f:43f 420:440 421:441 422:442 423:443 424:444 425:445 426:446 427:447 428:448 429:449 42a:44a',
  '42b:44b 42c:44c 42d:44d 42e:44e 42f:44f 460:461 462:463 464:465 466:467 468:469 46a:46b 46c:46d 46e:46f 470:471',
  '472:473 474:475 476:477 478:479 47a:47b 47c:47d 47e:47f 480:481 48a:48b 48c:48d 48e:48f 490:491 492:493 494:495',
  '496:497 498:499 49a:49b 49c:49d 49e:49f 4a0:4a1 4a2:4a3 4a4:4a5 4a6:4a7 4a8:4a9 4aa:4ab 4ac:4ad 4ae:4af 4b0:4b1',
  '4b2:4b3 4b4:4b5 4b6:4b7 4b8:4b9 4ba:4bb 4bc:4bd 4be:4bf 4c0:4cf 4c1:4c2 4c3:4c4 4c5:4c6 4c7:4c8 4c9:4ca 4cb:4cc',
  '4cd:4ce 4d0:4d1 4d2:4d3 4d4:4d5 4d6:4d7 4d8:4d9 4da:4db 4dc:4dd 4de:4df 4e0:4e1 4e2:4e3 4e4:4e5 4e6:4e7 4e8:4e9',
  '4ea:4eb 4ec:4ed 4ee:4ef 4f0:4f1 4f2:4f3 4f4:4f5 4f6:4f7 4f8:4f9 4fa:4fb 4fc:4fd 4fe:4ff 500:501 502:503 504:505',
  '506:507 508:509 50a:50b 50c:50d 50e:50f 510:511 512:513 514:515 516:517 518:519 51a:51b 51c:51d 51e:51f 520:521',
  '522:523 524:525 526:527 528:529 52a:52b 52c:52d 52e:52f 531:561 532:562 533:563 534:564 535:565 536:566 537:567',
  '538:568 539:569 53a:56a 53b:56b 53c:56c 53d:56d 53e:56e 53f:56f 540:570 541:571 542:572 543:573 544:574 545:575',
  '546:576 547:577 548:578 549:579 54a:57a 54b:57b 54c:57c 54d:57d 54e:57e 54f:57f 550:580 551:581 552:582 553:583',
  '554:584 555:585 556:586 587:565,582 10a0:2d00 10a1:2d01 10a2:2d02 10a3:2d03 10a4:2d04 10a5:2d05 10a6:2d06',
  '10a7:2d07 10a8:2d08 10a9:2d09 10aa:2d0a 10ab:2d0b 10ac:2d0c 10ad:2d0d 10ae:2d0e 10af:2d0f 10b0:2d10 10b1:2d11',
  '10b2:2d12 10b3:2d13 10b4:2d14 10b5:2d15 10b6:2d16 10b7:2d17 10b8:2d18 10b9:2d19 10ba:2d1a 10bb:2d1b 10bc:2d1c',
  '10bd:2d1d 10be:2d1e 10bf:2d1f 10c0:2d20 10c1:2d21 10c2:2d22 10c3:2d23 10c4:2d24 10c5:2d25 10c7:2d27 10cd:2d2d',
  '13f8:13f0 13f9:13f1 13fa:13f2 13fb:13f3 13fc:13f4 13fd:13f5 1c80:432 1c81:434 1c82:43e 1c83:441 1c84:442',
  '1c85:442 1c86:44a 1c87:463 1c88:a64b 1c90:10d0 1c91:10d1 1c92:10d2 1c93:10d3 1c94:10d4 1c95:10d5 1c96:10d6',
  '1c97:10d7 1c98:10d8 1c99:10d9 1c9a:10da 1c9b:10db 1c9c:10dc 1c9d:10dd 1c9e:10de 1c9f:10df 1ca0:10e0 1ca1:10e1',
  '1ca2:10e2 1ca3:10e3 1ca4:10e4 1ca5:10e5 1ca6:10e6 1ca7:10e7 1ca8:10e8 1ca9:10e9 1caa:10ea 1cab:10eb 1cac:10ec',
  '1cad:10ed 1cae:10ee 1caf:10ef 1cb0:10f0 1cb1:10f1 1cb2:10f2 1cb3:10f3 1cb4:10f4 1cb5:10f5 1cb6:10f6 1cb7:10f7',
  '1cb8:10f8 1cb9:10f9 1cba:10fa 1cbd:10fd 1cbe:10fe 1cbf:10ff 1e00:1e01 1e02:1e03 1e04:1e05 1e06:1e07 1e08:1e09',
  '1e0a:1e0b 1e0c:1e0d 1e0e:1e0f 1e10:1e11 1e12:1e13 1e14:1e15 1e16:1e17 1e18:1e19 1e1a:1e1b 1e1c:1e1d 1e1e:1e1f',
  '1e20:1e21 1e22:1e23 1e24:1e25 1e26:1e27 1e28:1e29 1e2a:1e2b 1e2c:1e2d 1e2e:1e2f 1e30:1e31 1e32:1e33 1e34:1e35',
  '1e36:1e37 1e38:1e39 1e3a:1e3b 1e3c:1e3d 1e3e:1e3f 1e40:1e41 1e42:1e43 1e44:1e45 1e46:1e47 1e48:1e49 1e4a:1e4b',
  '1e4c:1e4d 1e4e:1e4f 1e50:1e51 1e52:1e53 1e54:1e55 1e56:1e57 1e58:1e59 1e5a:1e5b 1e5c:1e5d 1e5e:1e5f 1e60:1e61',
  '1e62:1e63 1e64:1e65 1e66:1e67 1e68:1e69 1e6a:1e6b 1e6c:1e6d 1e6e:1e6f 1e70:1e71 1e72:1e73 1e74:1e75 1e76:1e77',
  '1e78:1e79 1e7a:1e7b 1e7c:1e7d 1e7e:1e7f 1e80:1e81 1e82:1e83 1e84:1e85 1e86:1e87 1e88:1e89 1e8a:1e8b 1e8c:1e8d',
  '1e8e:1e8f 1e90:1e91 1e92:1e93 1e94:1e95 1e96:68,331 1e97:74,308 1e98:77,30a 1e99:79,30a 1e9a:61,2be 1e9b:1e61',
  '1e9e:73,73 1ea0:1ea1 1ea2:1ea3 1ea4:1ea5 1ea6:1ea7 1ea8:1ea9 1eaa:1eab 1eac:1ead 1eae:1eaf 1eb0:1eb1 1eb2:1eb3',
  '1eb4:1eb5 1eb6:1eb7 1eb8:1eb9 1eba:1ebb 1ebc:1ebd 1ebe:1ebf 1ec0:1ec1 1ec2:1ec3 1ec4:1ec5 1ec6:1ec7 1ec8:1ec9',
  '1eca:1ecb 1ecc:1ecd 1ece:1ecf 1ed0:1ed1 1ed2:1ed3 1ed4:1ed5 1ed6:1ed7 1ed8:1ed9 1eda:1edb 1edc:1edd 1ede:1edf',
  '1ee0:1ee1 1ee2:1ee3 1ee4:1ee5 1ee6:1ee7 1ee8:1ee9 1eea:1eeb 1eec:1eed 1eee:1eef 1ef0:1ef1 1ef2:1ef3 1ef4:1ef5',
  '1ef6:1ef7 1ef8:1ef9 1efa:1efb 1efc:1efd 1efe:1eff 1f08:1f00 1f09:1f01 1f0a:1f02 1f0b:1f03 1f0c:1f04 1f0d:1f05',
  '1f0e:1f06 1f0f:1f07 1f18:1f10 1f19:1f11 1f1a:1f12 1f1b:1f13 1f1c:1f14 1f1d:1f15 1f28:1f20 1f29:1f21 1f2a:1f22',
  '1f2b:1f23 1f2c:1f24 1f2d:1f25 1f2e:1f26 1f2f:1f27 1f38:1f30 1f39:1f31 1f3a:1f32 1f3b:1f33 1f3c:1f34 1f3d:1f35',
  '1f3e:1f36 1f3f:1f37 1f48:1f40 1f49:1f41 1f4a:1f42 1f4b:1f43 1f4c:1f44 1f4d:1f45 1f50:3c5,313 1f52:3c5,313,300',
  '1f54:3c5,313,301 1f56:3c5,313,342 1f59:1f51 1f5b:1f53 1f5d:1f55 1f5f:1f57 1f68:1f60 1f69:1f61 1f6a:1f62',
  '1f6b:1f63 1f6c:1f64 1f6d:1f65 1f6e:1f66 1f6f:1f67 1f80:1f00,3b9 1f81:1f01,3b9 1f82:1f02,3b9 1f83:1f03,3b9',
  '1f84:1f04,3b9 1f85:1f05,3b9 1f86:1f06,3b9 1f87:1f07,3b9 1f88:1f00,3b9 1f89:1f01,3b9 1f8a:1f02,3b9 1f8b:1f03,3b9',
  '1f8c:1f04,3b9 1f8d:1f05,3b9 1f8e:1f06,3b9 1f8f:1f07,3b9 1f90:1f20,3b9 1f91:1f21,3b9 1f92:1f22,3b9 1f93:1f23,3b9',
  '1f94:1f24,3b9 1f95:1f25,3b9 1f96:1f26,3b9 1f97:1f27,3b9 1f98:1f20,3b9 1f99:1f21,3b9 1f9a:1f22,3b9 1f9b:1f23,3b9',
  '1f9c:1f24,3b9 1f9d:1f25,3b9 1f9e:1f26,3b9 1f9f:1f27,3b9 1fa0:1f60,3b9 1fa1:1f61,3b9 1fa2:1f62,3b9 1fa3:1f63,3b9',
  '1fa4:1f64,3b9 1fa5:1f65,3b9 1fa6:1f66,3b9 1fa7:1f67,3b9 1fa8:1f60,3b9 1fa9:1f61,3b9 1faa:1f62,3b9 1fab:1f63,3b9',
  '1fac:1f64,3b9 1fad:1f65,3b9 1fae:1f66,3b9 1faf:1f67,3b9 1fb2:1f70,3b9 1fb3:3b1,3b9 1fb4:3ac,3b9 1fb6:3b1,342',
  '1fb7:3b1,342,3b9 1fb8:1fb0 1fb9:1fb1 1fba:1f70 1fbb:1f71 1fbc:3b1,3b9 1fbe:3b9 1fc2:1f74,3b9 1fc3:3b7,3b9',
  '1fc4:3ae,3b9 1fc6:3b7,342 1fc7:3b7,342,3b9 1fc8:1f72 1fc9:1f73 1fca:1f74 1fcb:1f75 1fcc:3b7,3b9',
  '1fd2:3b9,308,300 1fd3:3b9,308,301 1fd6:3b9,342 1fd7:3b9,308,342 1fd8:1fd0 1fd9:1fd1 1fda:1f76 1fdb:1f77',
  '1fe2:3c5,308,300 1fe3:3c5,308,301 1fe4:3c1,313 1fe6:3c5,342 1fe7:3c5,308,342 1fe8:1fe0 1fe9:1fe1 1fea:1f7a',
  '1feb:1f7b 1fec:1fe5 1ff2:1f7c,3b9 1ff3:3c9,3b9 1ff4:3ce,3b9 1ff6:3c9,342 1ff7:3c9,342,3b9 1ff8:1f78 1ff9:1f79',
  '1ffa:1f7c 1ffb:1f7d 1ffc:3c9,3b9 2126:3c9 212a:6b 212b:e5 2132:214e 2160:2170 2161:2171 2162:2172 2163:2173',
  '2164:2174 2165:2175 2166:2176 2167:2177 2168:2178 2169:2179 216a:217a 216b:217b 216c:217c 216d:217d 216e:217e',
  '216f:217f 2183:2184 24b6:24d0 24b7:24d1 24b8:24d2 24b9:24d3 24ba:24d4 24bb:24d5 24bc:24d6 24bd:24d7 24be:24d8',
  '24bf:24d9 24c0:24da 24c1:24db 24c2:24dc 24c3:24dd 24c4:24de 24c5:24df 24c6:24e0 24c7:24e1 24c8:24e2 24c9:24e3',
  '24ca:24e4 24cb:24e5 24cc:24e6 24cd:24e7 24ce:24e8 24cf:24e9 2c00:2c30 2c01:2c31 2c02:2c32 2c03:2c33 2c04:2c34',
  '2c05:2c35 2c06:2c36 2c07:2c37 2c08:2c38 2c09:2c39 2c0a:2c3a 2c0b:2c3b 2c0c:2c3c 2c0d:2c3d 2c0e:2c3e 2c0f:2c3f',
  '2c10:2c40 2c11:2c41 2c12:2c42 2c13:2c43 2c14:2c44 2c15:2c45 2c16:2c46 2c17:2c47 2c18:2c48 2c19:2c49 2c1a:2c4a',
  '2c1b:2c4b 2c1c:2c4c 2c1d:2c4d 2c1e:2c4e 2c1f:2c4f 2c20:2c50 2c21:2c51 2c22:2c52 2c23:2c53 2c24:2c54 2c25:2c55',
  '2c26:2c56 2c27:2c57 2c28:2c58 2c29:2c59 2c2a:2c5a 2c2b:2c5b 2c2c:2c5c 2c2d:2c5d 2c2e:2c5e 2c2f:2c5f 2c60:2c61',
  '2c62:26b 2c63:1d7d 2c64:27d 2c67:2c68 2c69:2c6a 2c6b:2c6c 2c6d:251 2c6e:271 2c6f:250 2c70:252 2c72:2c73',
  '2c75:2c76 2c7e:23f 2c7f:240 2c80:2c81 2c82:2c83 2c84:2c85 2c86:2c87 2c88:2c89 2c8a:2c8b 2c8c:2c8d 2c8e:2c8f',
  '2c90:2c91 2c92:2c93 2c94:2c95 2c96:2c97 2c98:2c99 2c9a:2c9b 2c9c:2c9d 2c9e:2c9f 2ca0:2ca1 2ca2:2ca3 2ca4:2ca5',
  '2ca6:2ca7 2ca8:2ca9 2caa:2cab 2cac:2cad 2cae:2caf 2cb0:2cb1 2cb2:2cb3 2cb4:2cb5 2cb6:2cb7 2cb8:2cb9 2cba:2cbb',
  '2cbc:2cbd 2cbe:2cbf 2cc0:2cc1 2cc2:2cc3 2cc4:2cc5 2cc6:2cc7 2cc8:2cc9 2cca:2ccb 2ccc:2ccd 2cce:2ccf 2cd0:2cd1',
  '2cd2:2cd3 2cd4:2cd5 2cd6:2cd7 2cd8:2cd9 2cda:2cdb 2cdc:2cdd 2cde:2cdf 2ce0:2ce1 2ce2:2ce3 2ceb:2cec 2ced:2cee',
  '2cf2:2cf3 a640:a641 a642:a643 a644:a645 a646:a647 a648:a649 a64a:a64b a64c:a64d a64e:a64f a650:a651 a652:a653',
  'a654:a655 a656:a657 a658:a659 a65a:a65b a65c:a65d a65e:a65f a660:a661 a662:a663 a664:a665 a666:a667 a668:a669',
  'a66a:a66b a66c:a66d a680:a681 a682:a683 a684:a685 a686:a687 a688:a689 a68a:a68b a68c:a68d a68e:a68f a690:a691',
  'a692:a693 a694:a695 a696:a697 a698:a699 a69a:a69b a722:a723 a724:a725 a726:a727 a728:a729 a72a:a72b a72c:a72d',
  'a72e:a72f a732:a733 a734:a735 a736:a737 a738:a739 a73a:a73b a73c:a73d a73e:a73f a740:a741 a742:a743 a744:a745',
  'a746:a747 a748:a749 a74a:a74b a74c:a74d a74e:a74f a750:a751 a752:a753 a754:a755 a756:a757 a758:a759 a75a:a75b',
  'a75c:a75d a75e:a75f a760:a761 a762:a763 a764:a765 a766:a767 a768:a769 a76a:a76b a76c:a76d a76e:a76f a779:a77a',
  'a77b:a77c a77d:1d79 a77e:a77f a780:a781 a782:a783 a784:a785 a786:a787 a78b:a78c a78d:265 a790:a791 a792:a793',
  'a796:a797 a798:a799 a79a:a79b a79c:a79d a79e:a79f a7a0:a7a1 a7a2:a7a3 a7a4:a7a5 a7a6:a7a7 a7a8:a7a9 a7aa:266',
  'a7ab:25c a7ac:261 a7ad:26c a7ae:26a a7b0:29e a7b1:287 a7b2:29d a7b3:ab53 a7b4:a7b5 a7b6:a7b7 a7b8:a7b9',
  'a7ba:a7bb a7bc:a7bd a7be:a7bf a7c0:a7c1 a7c2:a7c3 a7c4:a794 a7c5:282 a7c6:1d8e a7c7:a7c8 a7c9:a7ca a7d0:a7d1',
  'a7d6:a7d7 a7d8:a7d9 a7f5:a7f6 ab70:13a0 ab71:13a1 ab72:13a2 ab73:13a3 ab74:13a4 ab75:13a5 ab76:13a6 ab77:13a7',
  'ab78:13a8 ab79:13a9 ab7a:13aa ab7b:13ab ab7c:13ac ab7d:13ad ab7e:13ae ab7f:13af ab80:13b0 ab81:13b1 ab82:13b2',
  'ab83:13b3 ab84:13b4 ab85:13b5 ab86:13b6 ab87:13b7 ab88:13b8 ab89:13b9 ab8a:13ba ab8b:13bb ab8c:13bc ab8d:13bd',
  'ab8e:13be ab8f:13bf ab90:13c0 ab91:13c1 ab92:13c2 ab93:13c3 ab94:13c4 ab95:13c5 ab96:13c6 ab97:13c7 ab98:13c8',
  'ab99:13c9 ab9a:13ca ab9b:13cb ab9c:13cc ab9d:13cd ab9e:13ce ab9f:13cf aba0:13d0 aba1:13d1 aba2:13d2 aba3:13d3',
  'aba4:13d4 aba5:13d5 aba6:13d6 aba7:13d7 aba8:13d8 aba9:13d9 abaa:13da abab:13db abac:13dc abad:13dd abae:13de',
  'abaf:13df abb0:13e0 abb1:13e1 abb2:13e2 abb3:13e3 abb4:13e4 abb5:13e5 abb6:13e6 abb7:13e7 abb8:13e8 abb9:13e9',
  'abba:13ea abbb:13eb abbc:13ec abbd:13ed abbe:13ee abbf:13ef fb00:66,66 fb01:66,69 fb02:66,6c fb03:66,66,69',
  'fb04:66,66,6c fb05:73,74 fb06:73,74 fb13:574,576 fb14:574,565 fb15:574,56b fb16:57e,576 fb17:574,56d ff21:ff41',
  'ff22:ff42 ff23:ff43 ff24:ff44 ff25:ff45 ff26:ff46 ff27:ff47 ff28:ff48 ff29:ff49 ff2a:ff4a ff2b:ff4b ff2c:ff4c',
  'ff2d:ff4d ff2e:ff4e ff2f:ff4f ff30:ff50 ff31:ff51 ff32:ff52 ff33:ff53 ff34:ff54 ff35:ff55 ff36:ff56 ff37:ff57',
  'ff38:ff58 ff39:ff59 ff3a:ff5a 10400:10428 10401:10429 10402:1042a 10403:1042b 10404:1042c 10405:1042d',
  '10406:1042e 10407:1042f 10408:10430 10409:10431 1040a:10432 1040b:10433 1040c:10434 1040d:10435 1040e:10436',
  '1040f:10437 10410:10438 10411:10439 10412:1043a 10413:1043b 10414:1043c 10415:1043d 10416:1043e 10417:1043f',
  '10418:10440 10419:10441 1041a:10442 1041b:10443 1041c:10444 1041d:10445 1041e:10446 1041f:10447 10420:10448',
  '10421:10449 10422:1044a 10423:1044b 10424:1044c 10425:1044d 10426:1044e 10427:1044f 104b0:104d8 104b1:104d9',
  '104b2:104da 104b3:104db 104b4:104dc 104b5:104dd 104b6:104de 104b7:104df 104b8:104e0 104b9:104e1 104ba:104e2',
  '104bb:104e3 104bc:104e4 104bd:104e5 104be:104e6 104bf:104e7 104c0:104e8 104c1:104e9 104c2:104ea 104c3:104eb',
  '104c4:104ec 104c5:104ed 104c6:104ee 104c7:104ef 104c8:104f0 104c9:104f1 104ca:104f2 104cb:104f3 104cc:104f4',
  '104cd:104f5 104ce:104f6 104cf:104f7 104d0:104f8 104d1:104f9 104d2:104fa 104d3:104fb 10570:10597 10571:10598',
  '10572:10599 10573:1059a 10574:1059b 10575:1059c 10576:1059d 10577:1059e 10578:1059f 10579:105a0 1057a:105a1',
  '1057c:105a3 1057d:105a4 1057e:105a5 1057f:105a6 10580:105a7 10581:105a8 10582:105a9 10583:105aa 10584:105ab',
  '10585:105ac 10586:105ad 10587:105ae 10588:105af 10589:105b0 1058a:105b1 1058c:105b3 1058d:105b4 1058e:105b5',
  '1058f:105b6 10590:105b7 10591:105b8 10592:105b9 10594:105bb 10595:105bc 10c80:10cc0 10c81:10cc1 10c82:10cc2',
  '10c83:10cc3 10c84:10cc4 10c85:10cc5 10c86:10cc6 10c87:10cc7 10c88:10cc8 10c89:10cc9 10c8a:10cca 10c8b:10ccb',
  '10c8c:10ccc 10c8d:10ccd 10c8e:10cce 10c8f:10ccf 10c90:10cd0 10c91:10cd1 10c92:10cd2 10c93:10cd3 10c94:10cd4',
  '10c95:10cd5 10c96:10cd6 10c97:10cd7 10c98:10cd8 10c99:10cd9 10c9a:10cda 10c9b:10cdb 10c9c:10cdc 10c9d:10cdd',
  '10c9e:10cde 10c9f:10cdf 10ca0:10ce0 10ca1:10ce1 10ca2:10ce2 10ca3:10ce3 10ca4:10ce4 10ca5:10ce5 10ca6:10ce6',
  '10ca7:10ce7 10ca8:10ce8 10ca9:10ce9 10caa:10cea 10cab:10ceb 10cac:10cec 10cad:10ced 10cae:10cee 10caf:10cef',
  '10cb0:10cf0 10cb1:10cf1 10cb2:10cf2 118a0:118c0 118a1:118c1 118a2:118c2 118a3:118c3 118a4:118c4 118a5:118c5',
  '118a6:118c6 118a7:118c7 118a8:118c8 118a9:118c9 118aa:118ca 118ab:118cb 118ac:118cc 118ad:118cd 118ae:118ce',
  '118af:118cf 118b0:118d0 118b1:118d1 118b2:118d2 118b3:118d3 118b4:118d4 118b5:118d5 118b6:118d6 118b7:118d7',
  '118b8:118d8 118b9:118d9 118ba:118da 118bb:118db 118bc:118dc 118bd:118dd 118be:118de 118bf:118df 16e40:16e60',
  '16e41:16e61 16e42:16e62 16e43:16e63 16e44:16e64 16e45:16e65 16e46:16e66 16e47:16e67 16e48:16e68 16e49:16e69',
  '16e4a:16e6a 16e4b:16e6b 16e4c:16e6c 16e4d:16e6d 16e4e:16e6e 16e4f:16e6f 16e50:16e70 16e51:16e71 16e52:16e72',
  '16e53:16e73 16e54:16e74 16e55:16e75 16e56:16e76 16e57:16e77 16e58:16e78 16e59:16e79 16e5a:16e7a 16e5b:16e7b',
  '16e5c:16e7c 16e5d:16e7d 16e5e:16e7e 16e5f:16e7f 1e900:1e922 1e901:1e923 1e902:1e924 1e903:1e925 1e904:1e926',
  '1e905:1e927 1e906:1e928 1e907:1e929 1e908:1e92a 1e909:1e92b 1e90a:1e92c 1e90b:1e92d 1e90c:1e92e 1e90d:1e92f',
  '1e90e:1e930 1e90f:1e931 1e910:1e932 1e911:1e933 1e912:1e934 1e913:1e935 1e914:1e936 1e915:1e937 1e916:1e938',
  '1e917:1e939 1e918:1e93a 1e919:1e93b 1e91a:1e93c 1e91b:1e93d 1e91c:1e93e 1e91d:1e93f 1e91e:1e940 1e91f:1e941',
  '1e920:1e942 1e921:1e943',
].join(' ');
const UNASSIGNED_DATA = [
  '378-379 380-383 38b-38b 38d-38d 3a2-3a2 530-530 557-558 58b-58c 590-590 5c8-5cf 5eb-5ee 5f5-5ff 70e-70e 74b-74c',
  '7b2-7bf 7fb-7fc 82e-82f 83f-83f 85c-85d 85f-85f 86b-86f 88f-88f 892-897 984-984 98d-98e 991-992 9a9-9a9 9b1-9b1',
  '9b3-9b5 9ba-9bb 9c5-9c6 9c9-9ca 9cf-9d6 9d8-9db 9de-9de 9e4-9e5 9ff-a00 a04-a04 a0b-a0e a11-a12 a29-a29 a31-a31',
  'a34-a34 a37-a37 a3a-a3b a3d-a3d a43-a46 a49-a4a a4e-a50 a52-a58 a5d-a5d a5f-a65 a77-a80 a84-a84 a8e-a8e a92-a92',
  'aa9-aa9 ab1-ab1 ab4-ab4 aba-abb ac6-ac6 aca-aca ace-acf ad1-adf ae4-ae5 af2-af8 b00-b00 b04-b04 b0d-b0e b11-b12',
  'b29-b29 b31-b31 b34-b34 b3a-b3b b45-b46 b49-b4a b4e-b54 b58-b5b b5e-b5e b64-b65 b78-b81 b84-b84 b8b-b8d b91-b91',
  'b96-b98 b9b-b9b b9d-b9d ba0-ba2 ba5-ba7 bab-bad bba-bbd bc3-bc5 bc9-bc9 bce-bcf bd1-bd6 bd8-be5 bfb-bff c0d-c0d',
  'c11-c11 c29-c29 c3a-c3b c45-c45 c49-c49 c4e-c54 c57-c57 c5b-c5c c5e-c5f c64-c65 c70-c76 c8d-c8d c91-c91 ca9-ca9',
  'cb4-cb4 cba-cbb cc5-cc5 cc9-cc9 cce-cd4 cd7-cdc cdf-cdf ce4-ce5 cf0-cf0 cf3-cff d0d-d0d d11-d11 d45-d45 d49-d49',
  'd50-d53 d64-d65 d80-d80 d84-d84 d97-d99 db2-db2 dbc-dbc dbe-dbf dc7-dc9 dcb-dce dd5-dd5 dd7-dd7 de0-de5 df0-df1',
  'df5-e00 e3b-e3e e5c-e80 e83-e83 e85-e85 e8b-e8b ea4-ea4 ea6-ea6 ebe-ebf ec5-ec5 ec7-ec7 ece-ecf eda-edb ee0-eff',
  'f48-f48 f6d-f70 f98-f98 fbd-fbd fcd-fcd fdb-fff 10c6-10c6 10c8-10cc 10ce-10cf 1249-1249 124e-124f 1257-1257',
  '1259-1259 125e-125f 1289-1289 128e-128f 12b1-12b1 12b6-12b7 12bf-12bf 12c1-12c1 12c6-12c7 12d7-12d7 1311-1311',
  '1316-1317 135b-135c 137d-137f 139a-139f 13f6-13f7 13fe-13ff 169d-169f 16f9-16ff 1716-171e 1737-173f 1754-175f',
  '176d-176d 1771-1771 1774-177f 17de-17df 17ea-17ef 17fa-17ff 181a-181f 1879-187f 18ab-18af 18f6-18ff 191f-191f',
  '192c-192f 193c-193f 1941-1943 196e-196f 1975-197f 19ac-19af 19ca-19cf 19db-19dd 1a1c-1a1d 1a5f-1a5f 1a7d-1a7e',
  '1a8a-1a8f 1a9a-1a9f 1aae-1aaf 1acf-1aff 1b4d-1b4f 1b7f-1b7f 1bf4-1bfb 1c38-1c3a 1c4a-1c4c 1c89-1c8f 1cbb-1cbc',
  '1cc8-1ccf 1cfb-1cff 1f16-1f17 1f1e-1f1f 1f46-1f47 1f4e-1f4f 1f58-1f58 1f5a-1f5a 1f5c-1f5c 1f5e-1f5e 1f7e-1f7f',
  '1fb5-1fb5 1fc5-1fc5 1fd4-1fd5 1fdc-1fdc 1ff0-1ff1 1ff5-1ff5 1fff-1fff 2065-2065 2072-2073 208f-208f 209d-209f',
  '20c1-20cf 20f1-20ff 218c-218f 2427-243f 244b-245f 2b74-2b75 2b96-2b96 2cf4-2cf8 2d26-2d26 2d28-2d2c 2d2e-2d2f',
  '2d68-2d6e 2d71-2d7e 2d97-2d9f 2da7-2da7 2daf-2daf 2db7-2db7 2dbf-2dbf 2dc7-2dc7 2dcf-2dcf 2dd7-2dd7 2ddf-2ddf',
  '2e5e-2e7f 2e9a-2e9a 2ef4-2eff 2fd6-2fef 2ffc-2fff 3040-3040 3097-3098 3100-3104 3130-3130 318f-318f 31e4-31ef',
  '321f-321f a48d-a48f a4c7-a4cf a62c-a63f a6f8-a6ff a7cb-a7cf a7d2-a7d2 a7d4-a7d4 a7da-a7f1 a82d-a82f a83a-a83f',
  'a878-a87f a8c6-a8cd a8da-a8df a954-a95e a97d-a97f a9ce-a9ce a9da-a9dd a9ff-a9ff aa37-aa3f aa4e-aa4f aa5a-aa5b',
  'aac3-aada aaf7-ab00 ab07-ab08 ab0f-ab10 ab17-ab1f ab27-ab27 ab2f-ab2f ab6c-ab6f abee-abef abfa-abff d7a4-d7af',
  'd7c7-d7ca d7fc-d7ff fa6e-fa6f fada-faff fb07-fb12 fb18-fb1c fb37-fb37 fb3d-fb3d fb3f-fb3f fb42-fb42 fb45-fb45',
  'fbc3-fbd2 fd90-fd91 fdc8-fdce fdd0-fdef fe1a-fe1f fe53-fe53 fe67-fe67 fe6c-fe6f fe75-fe75 fefd-fefe ff00-ff00',
  'ffbf-ffc1 ffc8-ffc9 ffd0-ffd1 ffd8-ffd9 ffdd-ffdf ffe7-ffe7 ffef-fff8 fffe-ffff 1000c-1000c 10027-10027',
  '1003b-1003b 1003e-1003e 1004e-1004f 1005e-1007f 100fb-100ff 10103-10106 10134-10136 1018f-1018f 1019d-1019f',
  '101a1-101cf 101fe-1027f 1029d-1029f 102d1-102df 102fc-102ff 10324-1032c 1034b-1034f 1037b-1037f 1039e-1039e',
  '103c4-103c7 103d6-103ff 1049e-1049f 104aa-104af 104d4-104d7 104fc-104ff 10528-1052f 10564-1056e 1057b-1057b',
  '1058b-1058b 10593-10593 10596-10596 105a2-105a2 105b2-105b2 105ba-105ba 105bd-105ff 10737-1073f 10756-1075f',
  '10768-1077f 10786-10786 107b1-107b1 107bb-107ff 10806-10807 10809-10809 10836-10836 10839-1083b 1083d-1083e',
  '10856-10856 1089f-108a6 108b0-108df 108f3-108f3 108f6-108fa 1091c-1091e 1093a-1093e 10940-1097f 109b8-109bb',
  '109d0-109d1 10a04-10a04 10a07-10a0b 10a14-10a14 10a18-10a18 10a36-10a37 10a3b-10a3e 10a49-10a4f 10a59-10a5f',
  '10aa0-10abf 10ae7-10aea 10af7-10aff 10b36-10b38 10b56-10b57 10b73-10b77 10b92-10b98 10b9d-10ba8 10bb0-10bff',
  '10c49-10c7f 10cb3-10cbf 10cf3-10cf9 10d28-10d2f 10d3a-10e5f 10e7f-10e7f 10eaa-10eaa 10eae-10eaf 10eb2-10eff',
  '10f28-10f2f 10f5a-10f6f 10f8a-10faf 10fcc-10fdf 10ff7-10fff 1104e-11051 11076-1107e 110c3-110cc 110ce-110cf',
  '110e9-110ef 110fa-110ff 11135-11135 11148-1114f 11177-1117f 111e0-111e0 111f5-111ff 11212-11212 1123f-1127f',
  '11287-11287 11289-11289 1128e-1128e 1129e-1129e 112aa-112af 112eb-112ef 112fa-112ff 11304-11304 1130d-1130e',
  '11311-11312 11329-11329 11331-11331 11334-11334 1133a-1133a 11345-11346 11349-1134a 1134e-1134f 11351-11356',
  '11358-1135c 11364-11365 1136d-1136f 11375-113ff 1145c-1145c 11462-1147f 114c8-114cf 114da-1157f 115b6-115b7',
  '115de-115ff 11645-1164f 1165a-1165f 1166d-1167f 116ba-116bf 116ca-116ff 1171b-1171c 1172c-1172f 11747-117ff',
  '1183c-1189f 118f3-118fe 11907-11908 1190a-1190b 11914-11914 11917-11917 11936-11936 11939-1193a 11947-1194f',
  '1195a-1199f 119a8-119a9 119d8-119d9 119e5-119ff 11a48-11a4f 11aa3-11aaf 11af9-11bff 11c09-11c09 11c37-11c37',
  '11c46-11c4f 11c6d-11c6f 11c90-11c91 11ca8-11ca8 11cb7-11cff 11d07-11d07 11d0a-11d0a 11d37-11d39 11d3b-11d3b',
  '11d3e-11d3e 11d48-11d4f 11d5a-11d5f 11d66-11d66 11d69-11d69 11d8f-11d8f 11d92-11d92 11d99-11d9f 11daa-11edf',
  '11ef9-11faf 11fb1-11fbf 11ff2-11ffe 1239a-123ff 1246f-1246f 12475-1247f 12544-12f8f 12ff3-12fff 1342f-1342f',
  '13439-143ff 14647-167ff 16a39-16a3f 16a5f-16a5f 16a6a-16a6d 16abf-16abf 16aca-16acf 16aee-16aef 16af6-16aff',
  '16b46-16b4f 16b5a-16b5a 16b62-16b62 16b78-16b7c 16b90-16e3f 16e9b-16eff 16f4b-16f4e 16f88-16f8e 16fa0-16fdf',
  '16fe5-16fef 16ff2-16fff 187f8-187ff 18cd6-18cff 18d09-1afef 1aff4-1aff4 1affc-1affc 1afff-1afff 1b123-1b14f',
  '1b153-1b163 1b168-1b16f 1b2fc-1bbff 1bc6b-1bc6f 1bc7d-1bc7f 1bc89-1bc8f 1bc9a-1bc9b 1bca4-1ceff 1cf2e-1cf2f',
  '1cf47-1cf4f 1cfc4-1cfff 1d0f6-1d0ff 1d127-1d128 1d1eb-1d1ff 1d246-1d2df 1d2f4-1d2ff 1d357-1d35f 1d379-1d3ff',
  '1d455-1d455 1d49d-1d49d 1d4a0-1d4a1 1d4a3-1d4a4 1d4a7-1d4a8 1d4ad-1d4ad 1d4ba-1d4ba 1d4bc-1d4bc 1d4c4-1d4c4',
  '1d506-1d506 1d50b-1d50c 1d515-1d515 1d51d-1d51d 1d53a-1d53a 1d53f-1d53f 1d545-1d545 1d547-1d549 1d551-1d551',
  '1d6a6-1d6a7 1d7cc-1d7cd 1da8c-1da9a 1daa0-1daa0 1dab0-1deff 1df1f-1dfff 1e007-1e007 1e019-1e01a 1e022-1e022',
  '1e025-1e025 1e02b-1e0ff 1e12d-1e12f 1e13e-1e13f 1e14a-1e14d 1e150-1e28f 1e2af-1e2bf 1e2fa-1e2fe 1e300-1e7df',
  '1e7e7-1e7e7 1e7ec-1e7ec 1e7ef-1e7ef 1e7ff-1e7ff 1e8c5-1e8c6 1e8d7-1e8ff 1e94c-1e94f 1e95a-1e95d 1e960-1ec70',
  '1ecb5-1ed00 1ed3e-1edff 1ee04-1ee04 1ee20-1ee20 1ee23-1ee23 1ee25-1ee26 1ee28-1ee28 1ee33-1ee33 1ee38-1ee38',
  '1ee3a-1ee3a 1ee3c-1ee41 1ee43-1ee46 1ee48-1ee48 1ee4a-1ee4a 1ee4c-1ee4c 1ee50-1ee50 1ee53-1ee53 1ee55-1ee56',
  '1ee58-1ee58 1ee5a-1ee5a 1ee5c-1ee5c 1ee5e-1ee5e 1ee60-1ee60 1ee63-1ee63 1ee65-1ee66 1ee6b-1ee6b 1ee73-1ee73',
  '1ee78-1ee78 1ee7d-1ee7d 1ee7f-1ee7f 1ee8a-1ee8a 1ee9c-1eea0 1eea4-1eea4 1eeaa-1eeaa 1eebc-1eeef 1eef2-1efff',
  '1f02c-1f02f 1f094-1f09f 1f0af-1f0b0 1f0c0-1f0c0 1f0d0-1f0d0 1f0f6-1f0ff 1f1ae-1f1e5 1f203-1f20f 1f23c-1f23f',
  '1f249-1f24f 1f252-1f25f 1f266-1f2ff 1f6d8-1f6dc 1f6ed-1f6ef 1f6fd-1f6ff 1f774-1f77f 1f7d9-1f7df 1f7ec-1f7ef',
  '1f7f1-1f7ff 1f80c-1f80f 1f848-1f84f 1f85a-1f85f 1f888-1f88f 1f8ae-1f8af 1f8b2-1f8ff 1fa54-1fa5f 1fa6e-1fa6f',
  '1fa75-1fa77 1fa7d-1fa7f 1fa87-1fa8f 1faad-1faaf 1fabb-1fabf 1fac6-1facf 1fada-1fadf 1fae8-1faef 1faf7-1faff',
  '1fb93-1fb93 1fbcb-1fbef 1fbfa-1ffff 2a6e0-2a6ff 2b739-2b73f 2b81e-2b81f 2cea2-2ceaf 2ebe1-2f7ff 2fa1e-2ffff',
  '3134b-e0000 e0002-e001f e0080-e00ff e01f0-effff ffffe-fffff 10fffe-10ffff',
].join(' ');
const CASEFOLD = new Map<number, string>(CASEFOLD_DATA.split(' ').filter(Boolean).map(item => {
  const [source, target] = item.split(':');
  return [parseInt(source, 16), String.fromCodePoint(...target.split(',').map(part => parseInt(part, 16)))] as [number, string];
}));
const UNASSIGNED = UNASSIGNED_DATA.split(' ').filter(Boolean).map(item => item.split('-').map(part => parseInt(part, 16)));
function unassigned(codepoint: number): boolean {
  let low = 0, high = UNASSIGNED.length - 1;
  while (low <= high) {
    const middle = (low + high) >> 1, [start, end] = UNASSIGNED[middle];
    if (codepoint < start) high = middle - 1;
    else if (codepoint > end) low = middle + 1;
    else return true;
  }
  return false;
}
/** Python 3.11 NFKC+casefold+whitespace, pinned to Unicode 14.0.0. Newer Node
 * Unicode assignments cannot change this profile: formerly unassigned code
 * points remain inert normalization boundaries. Existing assigned characters
 * use the platform's Unicode normalization (which preserves earlier versions).
 * This helper is not a tokenizer, retrieval index, or locale-specific casing. */
export function normalizeText(value: string): string {
  return checked(() => {
    if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') > MAX_RECORD_BYTES || Buffer.from(value).toString('utf8') !== value) fail('invalid_text');
    const pieces: string[] = []; let segment = '';
    const flush = () => { if (segment) { pieces.push(segment.normalize('NFKC')); segment = ''; } };
    for (const character of value) {
      if (unassigned(character.codePointAt(0)!)) { flush(); pieces.push(character); }
      else segment += character;
    }
    flush();
    const folded: string[] = [];
    for (const character of pieces.join('')) folded.push(CASEFOLD.get(character.codePointAt(0)!) ?? character);
    return folded.join('').replace(SPACE, ' ').replace(/^ +| +$/g, '');
  });
}
function codepointOrder(left: string, right: string): number {
  const a = Array.from(left, char => char.codePointAt(0)!), b = Array.from(right, char => char.codePointAt(0)!);
  for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
}
function selector(value: unknown): ShareSelector {
  const raw = document(value as DocumentInput, MAX_SELECTOR_BYTES);
  if (Object.keys(raw).some(key => !SELECTOR_FIELDS.includes(key)) || raw.schema_version !== SELECTOR_SCHEMA) fail('invalid_share_selector');
  const result: Obj = { schema_version: SELECTOR_SCHEMA };
  for (const name of SELECTOR_LISTS) {
    const items = raw[name] ?? [];
    if (!Array.isArray(items) || items.length > 64 || items.some(item => typeof item !== 'string' ||
        !item || Buffer.byteLength(item, 'utf8') > 512 || /[\0\r\n]/u.test(item)) || new Set(items).size !== items.length) fail('invalid_share_selector');
    if (name === 'memory_ids' && items.some(item => !match(item, /^mem_[0-9a-f]{40}/))) fail('invalid_share_memory_id');
    if (name === 'claim_keys' && items.some(item => !match(item, /^[a-z0-9][a-z0-9_-]{1,63}/))) fail('invalid_share_claim_key');
    if (name === 'kinds' && items.some(item => !KINDS.includes(item as MemoryKind))) fail('invalid_share_kind');
    result[name] = (items as string[]).slice().sort(codepointOrder);
  }
  for (const name of ['captured_after', 'captured_before']) result[name] = raw[name] == null ? null : timestamp(raw[name], true).normalized;
  if (result.captured_after && result.captured_before && timestamp(result.captured_after, true).micros >= timestamp(result.captured_before, true).micros) fail('invalid_share_time_range');
  result.all_records = raw.all_records ?? false;
  if (typeof result.all_records !== 'boolean') fail('invalid_share_selector');
  const hasAxis = SELECTOR_LISTS.some(name => (result[name] as string[]).length) || result.captured_after || result.captured_before;
  if (!result.all_records && !hasAxis) fail('empty_share_selector');
  if (result.all_records && hasAxis) fail('ambiguous_share_selector');
  return result as unknown as ShareSelector;
}
function selected(record: MemoryRecord, selection: ShareSelector): boolean {
  if (selection.all_records) return true;
  if (selection.kinds.length && !selection.kinds.includes(record.kind)) return false;
  const captured = timestamp(record.created_at, true).micros;
  if (selection.captured_after && captured < timestamp(selection.captured_after, true).micros) return false;
  if (selection.captured_before && captured >= timestamp(selection.captured_before, true).micros) return false;
  const axes: boolean[] = [];
  if (selection.memory_ids.length) axes.push(selection.memory_ids.includes(record.memory_id));
  if (selection.claim_keys.length) axes.push(selection.claim_keys.some(key => record.entities.includes('claim:' + key) || record.entities.includes('claim:v021:' + key)));
  if (selection.entities.length) axes.push(selection.entities.some(item => record.entities.includes(item)));
  if (selection.concepts.length) {
    const content = normalizeText([record.text, ...record.entities].join(' '));
    axes.push(selection.concepts.some(concept => content.includes(normalizeText(concept))));
  }
  return !axes.length || axes.some(Boolean);
}
function closure(records: readonly SignedMemory[], roots: readonly string[]): void {
  if (!roots.length || !records.length || records.length > MAX_SHARE_RECORDS) fail('share_footer_or_closure_mismatch');
  const byId = new Map<string, MemoryRecord>(); let edges = 0;
  for (const { record } of records) {
    if (byId.has(record.memory_id)) fail('share_duplicate_or_record_limit');
    byId.set(record.memory_id, record); edges += record.relations.length;
    if (edges > MAX_SHARE_RECORDS * 256) fail('share_dependency_edge_limit');
  }
  if (new Set(roots).size !== roots.length) fail('share_footer_or_closure_mismatch');
  for (const { record } of records) for (const relation of record.relations) {
    if (!byId.has(relation.target)) fail('share_footer_or_closure_mismatch');
  }
  const reached = new Set<string>(roots), pending = roots.slice();
  for (let i = 0; i < pending.length; i++) {
    const id = pending[i];
    const next = byId.get(id);
    if (!next) fail('share_footer_or_closure_mismatch');
    for (const relation of next.relations) if (!reached.has(relation.target)) {
      reached.add(relation.target); pending.push(relation.target);
    }
  }
  if (reached.size !== records.length) fail('share_contains_unselected_non_dependency');
}
function signed(value: unknown): SignedMemory {
  const raw = objectFields(document(value as DocumentInput, MAX_LINE_BYTES), ['record', 'attestation'], 'invalid_share_record_frame');
  const normalized = record(canonicalRecordBytes(raw.record));
  return { record: normalized, attestation: raw.attestation === null ? null : attestation(raw.attestation, normalized.record_sha256) };
}
/** Parse canonical NDJSON, preserve record order/proofs, and check the complete
 * relation closure rooted at selected frames. No key is enrolled or trusted. */
export function parseShare(value: Uint8Array | string): ParsedShare {
  return checked(() => {
    if (!(value instanceof Uint8Array) && typeof value !== 'string') fail('unsafe_share_source');
    if (typeof value === 'string' && (Buffer.byteLength(value, 'utf8') > MAX_SHARE_BYTES || Buffer.from(value).toString('utf8') !== value)) fail('unsafe_share_source');
    const raw = typeof value === 'string' ? Buffer.from(value, 'utf8') : value;
    if (!raw.byteLength || raw.byteLength > MAX_SHARE_BYTES) fail('unsafe_share_source');
    // Buffer view, not another full-share copy. Parsing is synchronous; callers
    // must not concurrently mutate a SharedArrayBuffer-backed input.
    if (raw.buffer instanceof SharedArrayBuffer) fail('unsafe_share_source');
    const bytes = Buffer.from(raw.buffer, raw.byteOffset, raw.byteLength);
    let position = 0;
    function frame(): { value: Obj; line: Uint8Array } {
      // Search only a bounded line window, even when an attacker omits LF.
      const window = bytes.subarray(position, Math.min(bytes.length, position + MAX_LINE_BYTES));
      const end = window.indexOf(10);
      if (end < 0) fail('invalid_share_frame');
      const line = window.subarray(0, end + 1);
      const value = document(line, MAX_LINE_BYTES);
      if (!Buffer.concat([canonicalBytes(value, MAX_LINE_BYTES), Buffer.from('\n')]).equals(line)) fail('noncanonical_share_frame');
      position += line.length;
      return { value, line };
    }
    const first = frame().value;
    objectFields(first, ['type', 'schema_version', 'hash_profile', 'created_at', 'selector', 'selector_sha256'], 'invalid_share_header');
    if (first.type !== 'header' || first.schema_version !== SHARE_SCHEMA || first.hash_profile !== HASH_PROFILE) fail('invalid_share_header');
    timestamp(first.created_at, true);
    const selection = selector(first.selector);
    if (!Buffer.from(canonicalBytes(selection)).equals(Buffer.from(canonicalBytes(first.selector))) || first.selector_sha256 !== sha256(canonicalBytes(selection))) fail('share_selector_hash_mismatch');
    const records: SignedMemory[] = [], roots: string[] = [];
    const linesDigest = createHash('sha256'), recordsDigest = createHash('sha256');
    let proofs = 0;
    while (true) {
      const { value, line } = frame();
      if (value.type === 'footer') {
        const digest = recordsDigest.digest('hex');
        const expected = { type: 'footer', records: records.length, selected_records: roots.length,
          records_sha256: digest, lines_sha256: linesDigest.digest('hex') };
        if (!Buffer.from(canonicalBytes(value)).equals(Buffer.from(canonicalBytes(expected))) || position !== bytes.length || !roots.length) fail('share_footer_or_closure_mismatch');
        closure(records, roots);
        const header = first as unknown as ShareHeader;
        return { records, roots, header, summary: { schema_version: SHARE_SCHEMA, records: records.length,
          selected_records: roots.length, dependency_records: records.length - roots.length, attestations: proofs,
          raw_bytes: bytes.length, sha256: sha256(bytes), selector_sha256: header.selector_sha256,
          records_sha256: digest, dependency_closure_verified: true, signatures_cryptographically_verified: false,
          checksum_authenticates_sender: false, grants_authority: false } };
      }
      objectFields(value, ['type', 'record', 'attestation', 'selected'], 'invalid_share_record_frame');
      if (value.type !== 'record' || typeof value.selected !== 'boolean') fail('invalid_share_record_frame');
      if (records.length >= MAX_SHARE_RECORDS) fail('share_duplicate_or_record_limit');
      const item = signed({ record: value.record, attestation: value.attestation });
      if (value.selected) {
        if (!selected(item.record, selection)) fail('share_selected_record_mismatch');
        roots.push(item.record.memory_id);
      }
      records.push(item); proofs += item.attestation !== null ? 1 : 0;
      linesDigest.update(line); recordsDigest.update(item.record.record_sha256 + '\n', 'ascii');
    }
  });
}
/** Encode the same v1 share frames using an exact memory_ids selector. Its
 * existing 64-ID selector limit applies to roots; dependencies are additional.
 * All supplied records must belong to their transitive closure. Input order is
 * retained. This in-memory codec is not the Python streaming export or a DLP
 * scanner; the caller must approve recipients/content before transmission. */
export function encodeShare(values: readonly SignedMemory[], rootValues: readonly string[]): Uint8Array {
  return checked(() => {
    if (!Array.isArray(values) || values.length > MAX_SHARE_RECORDS || !Array.isArray(rootValues) || rootValues.length > 64) fail('invalid_share_selector');
    const records = values.map(item => signed(item)), roots = rootValues.map(memoryId);
    closure(records, roots);
    const selection = selector({ schema_version: SELECTOR_SCHEMA, memory_ids: roots });
    const rootSet = new Set(roots), parts: Uint8Array[] = [];
    let size = 0;
    function emit(value: unknown): Uint8Array {
      const encoded = Buffer.concat([canonicalBytes(value, MAX_LINE_BYTES), Buffer.from('\n')]);
      size += encoded.length;
      if (encoded.length > MAX_LINE_BYTES || size > MAX_SHARE_BYTES) fail('share_byte_limit');
      parts.push(encoded); return encoded;
    }
    emit({ type: 'header', schema_version: SHARE_SCHEMA, hash_profile: HASH_PROFILE,
      created_at: new Date().toISOString(), selector: selection, selector_sha256: sha256(canonicalBytes(selection)) });
    const linesDigest = createHash('sha256'), recordsDigest = createHash('sha256');
    for (const item of records) {
      linesDigest.update(emit({ type: 'record', record: item.record, attestation: item.attestation, selected: rootSet.has(item.record.memory_id) }));
      recordsDigest.update(item.record.record_sha256 + '\n', 'ascii');
    }
    emit({ type: 'footer', records: records.length, selected_records: roots.length,
      records_sha256: recordsDigest.digest('hex'), lines_sha256: linesDigest.digest('hex') });
    return Buffer.concat(parts, size);
  });
}
