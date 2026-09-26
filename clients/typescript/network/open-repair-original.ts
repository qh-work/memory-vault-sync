/** Bounded original-control inspection. Authenticated inputs only: no repair,
 * resource activation, status observation, Vault access or transport authority.
 * Memory/envelopes remain opaque; this parser is only for portable old controls.
 */
import {createPublicKey, verify as edVerify} from 'node:crypto';
import {isProxy, isUint8Array} from 'node:util/types';
import {RepairBudget, RepairError, objectFields, u53} from './open-repair-wire.ts';
import type {DraftValue, RepairPolicy} from './open-repair-wire.ts';
import {validateNodeUrl} from './nodes.ts';

type Obj = Readonly<Record<string, DraftValue>>;
export interface DraftOriginalControl {
  readonly value: DraftValue;
  readonly raw: Uint8Array;
  nestedRaw(path: readonly string[]): Uint8Array;
}
export interface VerifiedOriginalControl {
  readonly document: DraftOriginalControl;
  readonly payload: Obj;
  readonly raw_sha256: string;
  readonly canonical_sha256: string;
}
export interface OriginalControlOptions {
  readonly expectedSigningKey: string | Readonly<Record<string, unknown>>;
  readonly expectedSchema: string; readonly expectedKind: string;
  /** Explicit caller time, not itself proof of an authenticated source event. */
  readonly at: number; readonly policy: RepairPolicy; readonly budget: RepairBudget;
}
const PATHS = [['payload','grant'], ['payload','resource_lease'], ['payload','grant','payload','resource_lease']] as const;
const PUBLIC_FIELDS = ['schema_version', 'algorithm', 'key_id', 'public_key'];
const DOMAIN = Buffer.from('UniversalAgentMemory\0message-signature\0v1\0', 'ascii');
const CONTROL_SCHEMA = 'memory-vault-open-control/v1';
const CONTACT_SCHEMA = 'memory-vault-open-contact-control/v1';
const COMMON = ['schema_version','kind','signing_key','issued_at','expires_at'];
const KINDS: Record<string, readonly string[]> = {
  node: ['revision','status','coordinate','base_url','storage_epoch','roles'],
  'resource.lease': ['node_key_id','storage_epoch','owner_key_id','owner_encryption_key','lease_id','resource_id','purpose','max_items','max_bytes'],
  'contact.policy': ['node_key_id','storage_epoch','lease_id','lease_sha256','resource_id','encryption_key','revision','status','max_pending'],
  'contact.request': ['request_id','encryption_key','recipient_key_id','recipient_encryption_key_id','node_key_id','storage_epoch','lease_id','resource_id','policy_sha256','request_class'],
  'contact.grant': ['request_id','request_sha256','subject_key_id','subject_encryption_key_id','recipient_encryption_key_id','node_key_id','storage_epoch','resource_id','operations','resource_lease'],
  'contact.decision': ['request_id','request_sha256','subject_key_id','subject_encryption_key_id','recipient_encryption_key_id','node_key_id','storage_epoch','policy_sha256','decision','reason','grant'],
};
const originalState = new WeakMap<DraftOriginalControl, {bytes: Buffer; spans: Map<string, readonly [number, number]>}>();
const arrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
const byteLength = Object.getOwnPropertyDescriptor(arrayPrototype, 'byteLength')!.get!;
const byteOffset = Object.getOwnPropertyDescriptor(arrayPrototype, 'byteOffset')!.get!;
const arrayBuffer = Object.getOwnPropertyDescriptor(arrayPrototype, 'buffer')!.get!;
function fail(code = 'repair_invalid_original'): never {throw new RepairError(code);}
function context(policy: RepairPolicy, budget: RepairBudget): RepairPolicy {
  if (budget === null || typeof budget !== 'object' || isProxy(budget) || Object.getPrototypeOf(budget) !== RepairBudget.prototype) fail('repair_invalid_policy');
  try {RepairBudget.prototype.assertPolicy.call(budget, policy);}
  catch {fail('repair_invalid_policy');}
  return budget.policy;
}
function fields(value: unknown, names: readonly string[], code = 'repair_invalid_original'): Obj {
  try {return objectFields(value, names) as Obj;} catch {fail(code);}
}
function copy(raw: Uint8Array, budget: RepairBudget): Uint8Array {
  budget.output(raw.byteLength); return Uint8Array.from(raw);
}
function buffer(text: string, budget: RepairBudget, encoding: BufferEncoding = 'utf8'): Buffer {
  const size = Buffer.byteLength(text, encoding); budget.output(size); return Buffer.from(text, encoding);
}
function record(value: unknown): Obj {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) fail();
  return value as Obj;
}

/** Lossless fixed-path spans are offsets into the same private UTF-8 snapshot.
 * Nodes, strings and byte copies are bounded before construction; host decoder
 * and object overhead are not represented as complete heap/CPU accounting.
 */
export function parseOriginalControl(raw: Uint8Array, policy: RepairPolicy, budget: RepairBudget): DraftOriginalControl {
  policy = context(policy, budget);
  if (!isUint8Array(raw)) fail('repair_invalid_bytes');
  const size = byteLength.call(raw) as number; budget.input(size);
  let bytes: Buffer;
  try {bytes = Buffer.from(new Uint8Array(arrayBuffer.call(raw), byteOffset.call(raw), size));}
  catch {fail('repair_invalid_bytes');}
  let source: string;
  try {source = new TextDecoder('utf-8', {fatal: true, ignoreBOM: true}).decode(bytes);}
  catch {fail('repair_invalid_utf8');}
  let position = 0, offset = 0;
  const spans = new Map<string, readonly [number, number]>();
  const ascii = (count = 1): void => {position += count; offset += count;};
  const whitespace = (): void => {while (' \r\n\t'.includes(source[position] ?? '\0')) ascii();};
  const string = (): string => {
    if (source[position] !== '"') fail('repair_invalid_json'); ascii();
    const pieces: string[] = []; let length = 0;
    const hex = (): number => {
      const value = source.slice(position, position + 4);
      if (!/^[0-9a-fA-F]{4}$/.test(value)) fail('repair_invalid_json');
      ascii(4); return Number.parseInt(value, 16);
    };
    while (position < source.length) {
      let code = source.codePointAt(position)!;
      position += code > 0xffff ? 2 : 1;
      offset += code < 0x80 ? 1 : code < 0x800 ? 2 : code < 0x10000 ? 3 : 4;
      if (code === 34) return pieces.join('');
      if (code < 32) fail('repair_invalid_json');
      if (code === 92) {
        const escape = source[position]; ascii();
        if (escape === 'u') {
          code = hex();
          if (code >= 0xd800 && code <= 0xdbff) {
            if (source.slice(position, position + 2) !== '\\u') fail('repair_invalid_unicode');
            ascii(2); const low = hex();
            if (low < 0xdc00 || low > 0xdfff) fail('repair_invalid_unicode');
            code = 0x10000 + (code - 0xd800) * 1024 + low - 0xdc00;
          } else if (code >= 0xdc00 && code <= 0xdfff) fail('repair_invalid_unicode');
        } else {
          const escapes: Record<string, number> = {'"':34,'\\':92,'/':47,b:8,f:12,n:10,r:13,t:9};
          if (!Object.hasOwn(escapes, escape)) fail('repair_invalid_json'); code = escapes[escape];
        }
      }
      const amount = code < 0x80 ? 1 : code < 0x800 ? 2 : code < 0x10000 ? 3 : 4;
      if (amount > policy.max_string_bytes - length) fail('repair_over_budget');
      budget.stringBytes(amount); length += amount; pieces.push(String.fromCodePoint(code));
    }
    fail('repair_invalid_json');
  };
  const value = (depth: number, path: readonly string[] | null): DraftValue => {
    if (depth > 24) fail(); budget.node(depth + 1); whitespace();
    const start = offset, token = source[position]; let result: DraftValue;
    if (token === '"') result = string();
    else if (token === '{') {
      ascii(); whitespace(); const object: Record<string, DraftValue> = Object.create(null);
      if (source[position] !== '}') while (true) {
        budget.node(depth + 2); const key = string();
        if (!/^[\x00-\x7f]*$/.test(key)) fail();
        if (Object.hasOwn(object, key)) fail('repair_invalid_json');
        whitespace(); if (source[position] !== ':') fail('repair_invalid_json'); ascii();
        const candidate = path === null ? null : [...path,key];
        const childPath = candidate !== null && PATHS.some(target => candidate.length <= target.length && candidate.every((item,index) => item === target[index])) ? candidate : null;
        object[key] = value(depth + 1, childPath); whitespace();
        if (source[position] === '}') break;
        if (source[position] !== ',') fail('repair_invalid_json'); ascii(); whitespace();
      }
      if (source[position] !== '}') fail('repair_invalid_json'); ascii(); result = Object.freeze(object);
    } else if (token === '[') {
      ascii(); whitespace(); const array: DraftValue[] = [];
      if (source[position] !== ']') while (true) {
        array.push(value(depth + 1, null)); whitespace();
        if (source[position] === ']') break;
        if (source[position] !== ',') fail('repair_invalid_json'); ascii(); whitespace();
      }
      if (source[position] !== ']') fail('repair_invalid_json'); ascii(); result = Object.freeze(array);
    } else {
      const first = position;
      while (position < source.length && !' \r\n\t,]}'.includes(source[position])) ascii();
      const literal = source.slice(first, position);
      if (literal === 'true') result = true;
      else if (literal === 'false') result = false;
      else if (literal === 'null') result = null;
      else {
        if (!/^-?(?:0|[1-9][0-9]*)$/.test(literal)) fail('repair_invalid_json');
        const digits = literal[0] === '-' ? literal.slice(1) : literal;
        if (digits.length > 16 || (digits.length === 16 && digits > '9007199254740991')) fail('repair_invalid_integer');
        result = Number(literal); if (Object.is(result, -0)) result = 0;
      }
    }
    if (path !== null && PATHS.some(target => path.length === target.length && path.every((item,index) => item === target[index]))) spans.set(path.join('/'), Object.freeze([start, offset]));
    return result;
  };
  const parsed = value(0, []); whitespace();
  if (position !== source.length) fail('repair_invalid_json');
  record(parsed);
  const result = Object.freeze({value: parsed, get raw(): Uint8Array {return copy(bytes, budget);},
    nestedRaw(path: readonly string[]): Uint8Array {
      if (!Array.isArray(path) || isProxy(path) || (path.length !== 2 && path.length !== 4)) fail();
      const selected: string[] = [];
      for (let i = 0; i < path.length; i++) {
        const property = Object.getOwnPropertyDescriptor(path, String(i));
        if (!property || !Object.hasOwn(property, 'value') || typeof property.value !== 'string' || property.value.length > 14 || property.value.includes('/')) fail();
        selected.push(property.value);
      }
      const span = spans.get(selected.join('/')); if (!span) fail();
      return copy(bytes.subarray(span[0], span[1]), budget);
    }});
  originalState.set(result, {bytes, spans}); return result;
}

/** Same old signed-safe integer/ASCII-key encoding, with real shared charges. */
function canonical(value: DraftValue, budget: RepairBudget): Buffer {
  const chunks: string[] = []; let size = 0;
  const emit = (text: string): void => {
    const amount = Buffer.byteLength(text);
    if (amount > budget.policy.max_document_bytes - size) fail('repair_over_budget');
    budget.output(amount); size += amount; chunks.push(text);
  };
  const string = (text: string): void => {
    budget.stringBytes(Buffer.byteLength(text)); emit('"');
    const escapes: Record<string,string> = {'"':'\\"','\\':'\\\\','\b':'\\b','\f':'\\f','\n':'\\n','\r':'\\r','\t':'\\t'};
    for (const char of text) emit(Object.hasOwn(escapes, char) ? escapes[char] : char.charCodeAt(0) < 32 ? '\\u' + char.charCodeAt(0).toString(16).padStart(4,'0') : char);
    emit('"');
  };
  const write = (current: DraftValue, depth: number): void => {
    if (depth > 24) fail(); budget.node(depth + 1);
    if (typeof current === 'string') string(current);
    else if (current === null || typeof current === 'boolean' || typeof current === 'number') emit(JSON.stringify(current));
    else if (Array.isArray(current)) {
      emit('['); current.forEach((item,index) => {if (index) emit(','); write(item, depth + 1);}); emit(']');
    } else {
      emit('{'); const object = current as Obj;
      Object.keys(object).sort().forEach((key,index) => {
        if (index) emit(','); budget.node(depth + 2); string(key); emit(':'); write(object[key], depth + 1);
      }); emit('}');
    }
  };
  write(value, 0); return Buffer.from(chunks.join(''), 'utf8');
}
function decode(text: unknown, size: number, budget: RepairBudget, encoding: 'base64'|'base64url' = 'base64'): Buffer {
  const wanted = encoding === 'base64' ? Math.ceil(size / 3) * 4 : Math.ceil(size * 4 / 3);
  if (typeof text !== 'string' || text.length !== wanted) fail();
  const padding = encoding === 'base64' ? (3 - size % 3) % 3 : 0;
  const alphabet = encoding === 'base64' ? '[A-Za-z0-9+/]' : '[A-Za-z0-9_-]';
  const pattern = new RegExp('^' + alphabet + '{' + (wanted - padding) + '}' + '='.repeat(padding) + '$');
  if (pattern.exec(text)?.[0] !== text) fail(); // Before allocating: exactly size decoded bytes.
  budget.output(size); const raw = Buffer.from(text, encoding);
  budget.output(wanted); const encoded = raw.toString(encoding);
  if (raw.length !== size || encoded !== text) fail(); return raw;
}
function descriptor(value: unknown, budget: RepairBudget, encryption = false): {value: Obj; bytes: Buffer} {
  const raw = fields(value, PUBLIC_FIELDS);
  if (raw.schema_version !== (encryption ? 'memory-vault-network-encryption-key/v1' : 'universal-memory-public-key/v1') ||
      raw.algorithm !== (encryption ? 'X25519' : 'Ed25519')) fail();
  const bytes = decode(raw.public_key, 32, budget, encryption ? 'base64url' : 'base64');
  if (raw.key_id !== (encryption ? 'x25519_' : 'ed25519_') + budget.hash(bytes)) fail();
  return {value: raw, bytes};
}
function identity(value: unknown, encryption = false): string {
  if (typeof value !== 'string' || (encryption ? /^x25519_[0-9a-f]{64}$/ : /^ed25519_[0-9a-f]{64}$/).exec(value)?.[0] !== value) fail();
  return value;
}
function time(raw: Obj, at: number, maximum?: number): void {
  let issued: number, expires: number;
  try {issued = u53(raw.issued_at); expires = u53(raw.expires_at); u53(at);} catch {fail();}
  if (expires <= issued || (maximum !== undefined && expires - issued > maximum) || issued - at > 30 || expires <= at) fail();
}
export function verifyOriginalControl(raw: Uint8Array, options: OriginalControlOptions): VerifiedOriginalControl {
  return verifyControl(raw, options);
}
function verifyControl(raw: Uint8Array, options: OriginalControlOptions, payloadFields?: readonly string[]): VerifiedOriginalControl {
  const {policy, budget, at} = options; context(policy, budget); u53(at);
  if (typeof options.expectedSchema !== 'string' || options.expectedSchema.length < 1 || options.expectedSchema.length > 128 ||
      typeof options.expectedKind !== 'string' || options.expectedKind.length < 1 || options.expectedKind.length > 128) fail();
  const expected = typeof options.expectedSigningKey === 'string' ? options.expectedSigningKey : fields(options.expectedSigningKey, PUBLIC_FIELDS);
  const expectedId = identity(typeof expected === 'string' ? expected : expected.key_id);
  const document = parseOriginalControl(raw, policy, budget), signed = fields(document.value, ['payload','proof']);
  const payload = record(signed.payload), proof = fields(signed.proof, ['schema_version','key_id','payload_sha256','signature']);
  if (payload.schema_version !== options.expectedSchema || payload.kind !== options.expectedKind ||
      typeof options.expectedSchema !== 'string' || typeof options.expectedKind !== 'string') fail();
  if (COMMON.some(name => !Object.hasOwn(payload,name))) fail();
  if (payloadFields) fields(payload, payloadFields);
  const actual = descriptor(payload.signing_key, budget);
  if (actual.value.key_id !== expectedId || (typeof expected !== 'string' && PUBLIC_FIELDS.some(key => expected[key] !== actual.value[key]))) fail('repair_wrong_issuer');
  time(payload, at);
  if (proof.schema_version !== 'universal-memory-message-signature/v1') fail();
  if (identity(proof.key_id) !== expectedId) fail('repair_wrong_issuer');
  if (typeof proof.payload_sha256 !== 'string' || /^[0-9a-f]{64}$/.exec(proof.payload_sha256)?.[0] !== proof.payload_sha256) fail();
  if (budget.hash(canonical(payload, budget)) !== proof.payload_sha256) fail('repair_invalid_signature');
  const signature = decode(proof.signature, 64, budget);
  const body = canonical({schema_version:proof.schema_version, key_id:proof.key_id, payload_sha256:proof.payload_sha256}, budget);
  budget.output(DOMAIN.length + body.length); const message = Buffer.concat([DOMAIN, body]);
  // RFC 8410 public DER; no hidden descriptor hash or alternative verifier.
  budget.output(44); const der = Buffer.alloc(44); der.write('302a300506032b6570032100', 0, 'hex'); actual.bytes.copy(der, 12);
  let key;
  try {key = createPublicKey({key: der, format:'der', type:'spki'});} catch {fail('repair_invalid_signature');}
  budget.signatureCheck(); // Adjacent to the real call; bad signatures consume it too.
  let valid = false;
  try {valid = edVerify(null, message, key, signature);} catch {fail('repair_invalid_signature');}
  if (!valid) fail('repair_invalid_signature');
  const raw_sha256 = budget.hash(originalState.get(document)!.bytes);
  const canonical_sha256 = budget.hash(canonical(document.value, budget));
  return Object.freeze({document, payload, raw_sha256, canonical_sha256});
}

export const CONTACT_ROLES = ['node','knock_lease','policy','request','decision','grant','delivery_lease'] as const;
export interface ContactOriginalOptions {
  readonly senderKeyId: string; readonly senderEncryptionKeyId: string;
  readonly recipientKeyId: string; readonly recipientEncryptionKeyId: string;
  readonly nodeKeyId: string; readonly storageEpoch: string;
  readonly at: number; readonly policy: RepairPolicy; readonly budget: RepairBudget;
}
export interface VerifiedContactOriginals {
  readonly originals: Readonly<Record<typeof CONTACT_ROLES[number], VerifiedOriginalControl>>;
  readonly at: number;
}
function equal(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((value,index) => value === right[index]);
}
function same(left: unknown, right: unknown): boolean {
  if (left === right) return true;
  if (left === null || right === null || typeof left !== 'object' || typeof right !== 'object') return false;
  const a = Object.keys(left), b = Object.keys(right);
  return a.length === b.length && a.every(key => Object.hasOwn(right,key) && same((left as Obj)[key], (right as Obj)[key]));
}
function opaque(value: unknown): void {if (typeof value !== 'string' || /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.exec(value)?.[0] !== value) fail();}
function limit(value: unknown, max: number, min = 1): void {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < min || value > max) fail();
}
function contactShape(original: VerifiedOriginalControl, budget: RepairBudget, at: number): Obj {
  const payload = original.payload, kind = payload.kind as string;
  fields(payload, [...COMMON,...KINDS[kind]]);
  const bytes = originalState.get(original.document)!.bytes;
  const maximum = kind === 'contact.decision' ? 8192 : 4096;
  if (bytes.length > maximum || canonical(original.document.value,budget).length > maximum) fail();
  time(payload, at, kind === 'node' ? 3600 : 86400);
  for (const name of ['node_key_id','owner_key_id','subject_key_id','recipient_key_id']) if (name in payload) identity(payload[name]);
  for (const name of ['subject_encryption_key_id','recipient_encryption_key_id']) if (name in payload) identity(payload[name],true);
  for (const name of ['lease_id','resource_id','request_id','storage_epoch']) if (name in payload) opaque(payload[name]);
  for (const name of ['lease_sha256','request_sha256','policy_sha256']) if (name in payload && (typeof payload[name] !== 'string' || /^[0-9a-f]{64}$/.exec(payload[name] as string)?.[0] !== payload[name])) fail();
  for (const name of ['encryption_key','owner_encryption_key']) if (name in payload) descriptor(payload[name], budget, true);
  if (kind === 'node') {
    limit(payload.revision, Number.MAX_SAFE_INTEGER);
    if (payload.status !== 'active') fail();
    const key = record(payload.signing_key).key_id;
    if (payload.coordinate !== budget.hash(buffer('memory-vault-open-routing/v1\0' + key, budget))) fail();
    if (typeof payload.base_url !== 'string' || Array.from(payload.base_url).length > 512) fail();
    try {validateNodeUrl(payload.base_url);} catch {fail();}
    const roles = payload.roles;
    if (!Array.isArray(roles) || !roles.length || roles.some((role,index) => !['router','directory'].includes(role as string) || (index > 0 && (role as string) <= (roles[index-1] as string)))) fail();
  } else if (kind === 'resource.lease') {
    limit(payload.max_items,32); limit(payload.max_bytes,16*1024*1024);
    if (!['knock','delivery'].includes(payload.purpose as string) ||
        (payload.purpose === 'knock' && payload.max_bytes !== (payload.max_items as number) * 12800) ||
        record(payload.signing_key).key_id !== payload.node_key_id) fail();
  } else if (kind === 'contact.policy') {
    limit(payload.revision,Number.MAX_SAFE_INTEGER); limit(payload.max_pending,32);
    if (!['active','revoked'].includes(payload.status as string)) fail();
  } else if (kind === 'contact.request') {
    if (payload.request_class !== 'message' || record(payload.signing_key).key_id === payload.recipient_key_id) fail();
  } else if (kind === 'contact.grant') {
    if (!same(payload.operations,['message.store'])) fail();
  } else if (kind === 'contact.decision') {
    if (payload.decision !== 'approved' || payload.reason !== 'accepted' || payload.grant === null) fail();
  }
  return payload;
}
/** One real proof per supplied original. Exact nested bytes prove which supplied
 * grant and lease the signed decision contains, without reserializing substitutes.
 * This does not authenticate the caller's event time or complete the R3 graph.
 */
export function verifyContactOriginals(input: unknown, options: ContactOriginalOptions): VerifiedContactOriginals {
  const {policy,budget,at} = options; context(policy,budget);
  const raws = fields(input, CONTACT_ROLES), result = Object.create(null) as Record<typeof CONTACT_ROLES[number],VerifiedOriginalControl>;
  const {senderKeyId:a,senderEncryptionKeyId:ax,recipientKeyId:b,recipientEncryptionKeyId:bx,nodeKeyId:r,storageEpoch:epoch} = options;
  identity(a); identity(ax,true); identity(b); identity(bx,true); identity(r); opaque(epoch);
  u53(at); if (a === b) fail('repair_contact_mismatch');
  const kinds = ['node','resource.lease','contact.policy','contact.request','contact.decision','contact.grant','resource.lease'];
  const signers = [r,r,b,a,b,b,r];
  const values: Obj[] = [];
  for (let i = 0; i < CONTACT_ROLES.length; i++) {
    const role = CONTACT_ROLES[i];
    const raw = raws[role] as unknown as Uint8Array;
    if (!isUint8Array(raw)) fail('repair_invalid_bytes');
    if (byteLength.call(raw) > (role === 'decision' ? 8192 : 4096)) fail();
    result[role] = verifyControl(raw, {expectedSigningKey:signers[i],expectedSchema:i===0?CONTROL_SCHEMA:CONTACT_SCHEMA,expectedKind:kinds[i],at,policy,budget}, [...COMMON,...KINDS[kinds[i]]]);
    values.push(contactShape(result[role],budget,at));
  }
  const [node,knock,p,request,decision,grant,delivery] = values;
  if (!equal(result.decision.document.nestedRaw(['payload','grant']), result.grant.document.raw) ||
      !equal(result.grant.document.nestedRaw(['payload','resource_lease']), result.delivery_lease.document.raw)) fail('repair_original_mismatch');
  const mismatch = (): never => fail('repair_contact_mismatch');
  if (node.status !== 'active' || node.storage_epoch !== epoch || !same(knock.signing_key,node.signing_key) || !same(delivery.signing_key,node.signing_key)) mismatch();
  for (const value of values.slice(1)) if (value.node_key_id !== r || value.storage_epoch !== epoch) mismatch();
  if (knock.purpose !== 'knock' || delivery.purpose !== 'delivery' ||
      knock.owner_key_id !== b || delivery.owner_key_id !== b || record(knock.owner_encryption_key).key_id !== bx ||
      record(delivery.owner_encryption_key).key_id !== bx || record(p.encryption_key).key_id !== bx || record(request.encryption_key).key_id !== ax) mismatch();
  if (p.status !== 'active' || !same(p.encryption_key,knock.owner_encryption_key) || p.lease_sha256 !== result.knock_lease.canonical_sha256 ||
      (p.max_pending as number) > (knock.max_items as number) || (p.expires_at as number) > (knock.expires_at as number) ||
      ['node_key_id','storage_epoch','lease_id','resource_id'].some(name => p[name] !== knock[name])) mismatch();
  if (request.recipient_key_id !== b || request.recipient_encryption_key_id !== bx || request.policy_sha256 !== result.policy.canonical_sha256 ||
      (request.expires_at as number) > (p.expires_at as number) || ['node_key_id','storage_epoch','lease_id','resource_id'].some(name => request[name] !== p[name])) mismatch();
  if (!same(decision.signing_key,p.signing_key) || decision.request_sha256 !== result.request.canonical_sha256 || decision.subject_key_id !== a || decision.subject_encryption_key_id !== ax ||
      (decision.expires_at as number) > (request.expires_at as number) ||
      ['request_id','recipient_encryption_key_id','node_key_id','storage_epoch','policy_sha256'].some(name => decision[name] !== request[name])) mismatch();
  if (['request_id','request_sha256','signing_key','subject_key_id','subject_encryption_key_id','recipient_encryption_key_id'].some(name => !same(decision[name],grant[name])) ||
      (grant.expires_at as number) > (decision.expires_at as number) || (grant.expires_at as number) > (delivery.expires_at as number) ||
      ['node_key_id','storage_epoch','resource_id'].some(name => grant[name] !== delivery[name])) mismatch();
  return Object.freeze({originals:Object.freeze(result),at});
}
