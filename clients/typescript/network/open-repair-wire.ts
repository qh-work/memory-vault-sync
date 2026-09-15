/** Local repair draft bytes only. No network, trust, signatures or authority.
 * Legacy originals are opaque bytes; never parse/reserialize them as JS Number.
 * Every call uses an explicit finite policy and a shared cumulative work budget.
 */
import {createHash} from 'node:crypto';
import {isProxy, isUint8Array} from 'node:util/types';

export type DraftValue = null | boolean | number | string | readonly DraftValue[] |
  {readonly [key: string]: DraftValue};
export interface RepairPolicy {
  readonly max_document_bytes: number;
  readonly max_total_bytes: number;
  readonly max_nodes: number;
  readonly max_depth: number;
  readonly max_string_bytes: number;
  readonly max_hash_bytes: number;
  readonly max_hashes: number;
  readonly max_entries: number;
  readonly max_retained_bytes: number;
}
export interface RepairWork {
  readonly input_bytes: number; readonly output_bytes: number;
  readonly nodes: number; readonly string_bytes: number; readonly max_depth: number;
  readonly hash_bytes: number; readonly hashes: number;
  readonly entries: number; readonly retained_bytes: number;
  readonly signature_checks: 0;
}
export interface DraftJson {readonly raw: Uint8Array; readonly value: DraftValue;}
export interface RawRef {
  readonly namespace: 'meta' | 'object'; readonly key: string;
  readonly raw_sha256: string; readonly size: number;
}
export interface RawOriginal {readonly ref: RawRef; readonly raw: Uint8Array;}
const draftBytes = new WeakMap<DraftJson, Buffer>();
const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
const byteLengthOf = Object.getOwnPropertyDescriptor(typedArrayPrototype, 'byteLength')!.get!;
const byteOffsetOf = Object.getOwnPropertyDescriptor(typedArrayPrototype, 'byteOffset')!.get!;
const bufferOf = Object.getOwnPropertyDescriptor(typedArrayPrototype, 'buffer')!.get!;

export class RepairError extends Error {
  readonly code: string;
  constructor(code: string) {super(code); this.name = 'RepairError'; this.code = code;}
}
function fail(code: string): never {throw new RepairError(code);}
const POLICY_FIELDS = ['max_document_bytes', 'max_total_bytes', 'max_nodes', 'max_depth',
  'max_string_bytes', 'max_hash_bytes', 'max_hashes', 'max_entries', 'max_retained_bytes'] as const;

/** Only own, enumerable data properties of a plain object; never invoke getters. */
export function objectFields(value: unknown, expected: readonly string[]): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value) || isProxy(value)) fail('repair_unknown_fields');
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) fail('repair_unknown_fields');
  const keys = Reflect.ownKeys(value), names = new Set(expected);
  if (names.size !== expected.length || keys.length !== names.size ||
      keys.some(key => typeof key !== 'string' || !names.has(key))) fail('repair_unknown_fields');
  for (const key of keys) {
    const property = Object.getOwnPropertyDescriptor(value, key)!;
    if (!property.enumerable || !Object.hasOwn(property, 'value')) fail('repair_unknown_fields');
  }
  return value as Record<string, unknown>;
}
export function u53(value: unknown, minimum = 0): number {
  if (typeof minimum !== 'number' || !Number.isSafeInteger(minimum) || minimum < 0 ||
      typeof value !== 'number' || !Number.isSafeInteger(value) || Object.is(value, -0) || value < minimum)
    fail('repair_invalid_integer');
  return value;
}
function policyCopy(value: RepairPolicy): RepairPolicy {
  try {
    const raw = objectFields(value, POLICY_FIELDS), result = Object.create(null);
    for (const name of POLICY_FIELDS) result[name] = u53(raw[name], 1);
    return Object.freeze(result) as RepairPolicy;
  } catch {fail('repair_invalid_policy');}
}

/** Counters describe this module's work, not total heap/CPU or live capacity.
 * retained_bytes counts resolver bytes and pack bytes/fixed index records.
 * It does not describe host object overhead. Public byte copies count as
 * output_bytes. Refused work is not performed/charged; earlier work remains.
 */
export class RepairBudget {
  readonly #policy: RepairPolicy;
  readonly #work = {input_bytes: 0, output_bytes: 0, nodes: 0, string_bytes: 0,
    max_depth: 0, hash_bytes: 0, hashes: 0, entries: 0, retained_bytes: 0,
    signature_checks: 0 as const};
  constructor(policy: RepairPolicy) {this.#policy = policyCopy(policy);}
  get policy(): RepairPolicy {return this.#policy;}
  snapshot(): RepairWork {return Object.freeze({...this.#work});}
  assertPolicy(policy: RepairPolicy): void {
    const checked = policyCopy(policy);
    if (POLICY_FIELDS.some(name => checked[name] !== this.#policy[name])) fail('repair_invalid_policy');
  }
  #fits(current: number, amount: number, maximum: number): void {
    u53(amount);
    if (amount > maximum - current) fail('repair_over_budget');
  }
  input(amount: number): void {
    this.#fits(0, amount, this.#policy.max_document_bytes);
    this.#fits(this.#work.input_bytes + this.#work.output_bytes, amount, this.#policy.max_total_bytes);
    this.#work.input_bytes += amount;
  }
  output(amount: number): void {
    this.#fits(this.#work.input_bytes + this.#work.output_bytes, amount, this.#policy.max_total_bytes);
    this.#work.output_bytes += amount;
  }
  node(depth: number): void {
    u53(depth, 1);
    if (depth > this.#policy.max_depth) fail('repair_over_budget');
    this.#fits(this.#work.nodes, 1, this.#policy.max_nodes);
    this.#work.nodes++;
    this.#work.max_depth = Math.max(depth, this.#work.max_depth);
  }
  stringBytes(length: number): void {
    this.#fits(0, length, this.#policy.max_string_bytes);
    this.#fits(this.#work.string_bytes, length, Number.MAX_SAFE_INTEGER);
    this.#work.string_bytes += length;
  }
  hash(raw: Uint8Array): string {
    this.#fits(this.#work.hash_bytes, raw.byteLength, this.#policy.max_hash_bytes);
    this.#fits(this.#work.hashes, 1, this.#policy.max_hashes);
    // Count only this actual native hash, never an inferred signature check.
    this.#work.hash_bytes += raw.byteLength;
    this.#work.hashes++;
    return createHash('sha256').update(raw).digest('hex');
  }
  canRetain(length: number, count = 1): void {
    this.#fits(this.#work.entries, count, this.#policy.max_entries);
    this.#fits(this.#work.retained_bytes, length, this.#policy.max_retained_bytes);
  }
  retain(length: number, count = 1): void {
    this.canRetain(length, count);
    this.#work.entries += count;
    this.#work.retained_bytes += length;
  }
}

function checkBudget(policy: RepairPolicy, budget: RepairBudget): void {
  if (!(budget instanceof RepairBudget)) fail('repair_invalid_policy');
  budget.assertPolicy(policy);
}
function rawSize(raw: Uint8Array): number {
  if (!isUint8Array(raw)) fail('repair_invalid_bytes');
  return byteLengthOf.call(raw) as number;
}
function snapshotInput(raw: Uint8Array, budget: RepairBudget): Buffer {
  const size = rawSize(raw); budget.input(size);
  // Read intrinsic typed-array fields, not caller-overridden accessors/species.
  let view: Uint8Array;
  try {view = new Uint8Array(bufferOf.call(raw), byteOffsetOf.call(raw), size);}
  catch {fail('repair_invalid_bytes');}
  return Buffer.from(view);
}
function copyOutput(raw: Uint8Array, budget: RepairBudget): Uint8Array {
  budget.output(raw.byteLength);
  return Uint8Array.from(raw);
}
type Obj = {[key: string]: DraftValue};
type Frame = {kind: 'array'; value: DraftValue[]; depth: number; state: 'first'|'value'|'after'} |
  {kind: 'object'; value: Obj; depth: number; state: 'first'|'key'|'colon'|'value'|'after'; key?: string};

/** Syntactic draft parser only. New repair wire must use parseCanonicalJson.
 * An explicit stack checks nodes/depth before allocating each container/value.
 */
export function parseNewJson(raw: Uint8Array, policy: RepairPolicy, budget: RepairBudget): DraftJson {
  checkBudget(policy, budget);
  policy = budget.policy;
  const bytes = snapshotInput(raw, budget);
  let source: string;
  try {source = new TextDecoder('utf-8', {fatal: true, ignoreBOM: true}).decode(bytes);}
  catch {fail('repair_invalid_utf8');}
  let position = 0;
  const stack: Frame[] = [];
  const space = (): void => {
    while (position < source.length && ' \t\r\n'.includes(source[position])) position++;
  };
  const string = (): string => {
    if (source[position] !== '"') fail('repair_invalid_json');
    position++;
    const pieces: string[] = []; let size = 0;
    const hex4 = (): number => {
      const digits = source.slice(position, position + 4);
      if (digits.length !== 4 || !/^[0-9a-fA-F]{4}$/.test(digits)) fail('repair_invalid_json');
      position += 4; return Number.parseInt(digits, 16);
    };
    while (position < source.length) {
      let code = source.codePointAt(position)!;
      position += code > 0xffff ? 2 : 1;
      if (code === 0x22) return pieces.join('');
      if (code < 0x20) fail('repair_invalid_json');
      if (code === 0x5c) {
        const escape = source[position++];
        if (escape === 'u') {
          code = hex4();
          if (code >= 0xd800 && code <= 0xdbff) {
            if (source.slice(position, position + 2) !== '\\u') fail('repair_invalid_unicode');
            position += 2; const low = hex4();
            if (low < 0xdc00 || low > 0xdfff) fail('repair_invalid_unicode');
            code = 0x10000 + (code - 0xd800) * 0x400 + low - 0xdc00;
          } else if (code >= 0xdc00 && code <= 0xdfff) fail('repair_invalid_unicode');
        } else {
          const escapes: Record<string, number> = {'"': 34, '\\': 92, '/': 47,
            b: 8, f: 12, n: 10, r: 13, t: 9};
          if (escape === undefined || !Object.hasOwn(escapes, escape)) fail('repair_invalid_json');
          code = escapes[escape];
        }
      }
      const length = code < 0x80 ? 1 : code < 0x800 ? 2 : code < 0x10000 ? 3 : 4;
      if (length > policy.max_string_bytes - size) fail('repair_over_budget');
      budget.stringBytes(length); size += length;
      // No whole-string decoding/allocation precedes its independent byte cap.
      pieces.push(String.fromCodePoint(code));
    }
    fail('repair_invalid_json');
  };
  const atom = (depth: number): DraftValue => {
    space(); if (position === source.length) fail('repair_invalid_json'); budget.node(depth);
    const token = source[position];
    if (token === '"') return string();
    if (token === '{') {
      position++; const value: Obj = Object.create(null);
      stack.push({kind: 'object', value, depth, state: 'first'}); return value;
    }
    if (token === '[') {
      position++; const value: DraftValue[] = [];
      stack.push({kind: 'array', value, depth, state: 'first'}); return value;
    }
    const start = position;
    while (position < source.length && !' \t\r\n,]}'.includes(source[position])) position++;
    const literal = source.slice(start, position);
    if (literal === 'true') return true;
    if (literal === 'false') return false;
    if (literal === 'null') return null;
    if (!/^(?:0|[1-9][0-9]*)$/.test(literal)) fail('repair_invalid_json');
    if (literal.length > 16 || (literal.length === 16 && literal > '9007199254740991'))
      fail('repair_invalid_integer');
    return Number(literal);
  };
  const value = atom(1);
  while (stack.length) {
    const frame = stack[stack.length - 1]; space();
    if (frame.kind === 'array') {
      if ((frame.state === 'first' || frame.state === 'after') && source[position] === ']') {
        position++; Object.freeze(frame.value); stack.pop(); continue;
      }
      if (frame.state === 'after') {
        if (source[position++] !== ',') fail('repair_invalid_json');
        frame.state = 'value'; continue;
      }
      frame.state = 'after'; frame.value.push(atom(frame.depth + 1));
    } else {
      if ((frame.state === 'first' || frame.state === 'after') && source[position] === '}') {
        position++; Object.freeze(frame.value); stack.pop(); continue;
      }
      if (frame.state === 'after') {
        if (source[position++] !== ',') fail('repair_invalid_json');
        frame.state = 'key'; continue;
      }
      if (frame.state === 'first' || frame.state === 'key') {
        budget.node(frame.depth + 1); frame.key = string();
        if (Object.hasOwn(frame.value, frame.key)) fail('repair_invalid_json');
        frame.state = 'colon'; continue;
      }
      if (frame.state === 'colon') {
        if (source[position++] !== ':') fail('repair_invalid_json');
        frame.state = 'value'; continue;
      }
      frame.state = 'after'; frame.value[frame.key!] = atom(frame.depth + 1);
    }
  }
  space(); if (position !== source.length) fail('repair_invalid_json');
  const draft = Object.freeze({get raw(): Uint8Array {return copyOutput(bytes, budget);}, value});
  draftBytes.set(draft, bytes); return draft;
}

function codepointOrder(left: string, right: string): number {
  let a = 0, b = 0;
  while (a < left.length && b < right.length) {
    const x = left.codePointAt(a)!, y = right.codePointAt(b)!;
    if (x !== y) return x - y;
    a += x > 0xffff ? 2 : 1; b += y > 0xffff ? 2 : 1;
  }
  return (a < left.length ? 1 : 0) - (b < right.length ? 1 : 0);
}
type EmitTask = {text: string} | {value: DraftValue; depth: number} | {key: string; depth: number};
function encodeParsed(value: DraftValue, policy: RepairPolicy, budget: RepairBudget): Buffer {
  const tasks: EmitTask[] = [{value, depth: 1}], chunks: string[] = [];
  let size = 0;
  const emit = (text: string): void => {
    const length = Buffer.byteLength(text, 'utf8');
    if (length > policy.max_document_bytes - size) fail('repair_over_budget');
    budget.output(length); size += length; chunks.push(text);
  };
  const string = (value: string): void => {
    budget.stringBytes(Buffer.byteLength(value, 'utf8')); emit('"');
    const escapes: Record<string, string> = {'"': '\\"', '\\': '\\\\', '\b': '\\b',
      '\f': '\\f', '\n': '\\n', '\r': '\\r', '\t': '\\t'};
    for (const char of value) {
      if (Object.hasOwn(escapes, char)) emit(escapes[char]);
      else if (char.codePointAt(0)! < 0x20) emit('\\u' + char.charCodeAt(0).toString(16).padStart(4, '0'));
      else emit(char);
    }
    emit('"');
  };
  while (tasks.length) {
    const task = tasks.pop()!;
    if ('text' in task) {emit(task.text); continue;}
    budget.node(task.depth);
    if ('key' in task) {string(task.key); continue;}
    const current = task.value;
    if (typeof current === 'string') string(current);
    else if (current === null || typeof current === 'boolean' || typeof current === 'number') emit(JSON.stringify(current));
    else if (Array.isArray(current)) {
      emit('['); tasks.push({text: ']'});
      for (let index = current.length - 1; index >= 0; index--) {
        tasks.push({value: current[index], depth: task.depth + 1});
        if (index > 0) tasks.push({text: ','});
      }
    } else {
      emit('{'); tasks.push({text: '}'});
      const keys = Object.keys(current).sort(codepointOrder), object = current as Obj;
      for (let index = keys.length - 1; index >= 0; index--) {
        const key = keys[index];
        tasks.push({value: object[key], depth: task.depth + 1}, {text: ':'}, {key, depth: task.depth + 1});
        if (index > 0) tasks.push({text: ','});
      }
    }
  }
  return Buffer.from(chunks.join(''), 'utf8');
}

/** Mandatory canonical new-wire boundary. Still a draft, never authority. */
export function parseCanonicalJson(raw: Uint8Array, policy: RepairPolicy, budget: RepairBudget): DraftJson {
  const draft = parseNewJson(raw, policy, budget);
  const encoded = encodeParsed(draft.value, budget.policy, budget);
  // Compare the exact snapshot used by the parser, not mutable caller input.
  const original = draftBytes.get(draft)!;
  if (!encoded.equals(original)) fail('repair_noncanonical_json');
  return draft;
}
export const parseNewWire = parseCanonicalJson;

function refAddress(namespace: unknown, key: unknown): {namespace: 'meta'|'object'; key: string} {
  if ((namespace !== 'meta' && namespace !== 'object') || typeof key !== 'string' ||
      key.length !== 64 || !/^[0-9a-f]{64}$/.test(key)) fail('repair_invalid_ref');
  return {namespace, key};
}
export function rawRef(value: unknown): RawRef {
  let raw: Record<string, unknown>;
  try {raw = objectFields(value, ['namespace', 'key', 'raw_sha256', 'size']);}
  catch {fail('repair_invalid_ref');}
  const address = refAddress(raw.namespace, raw.key);
  if (typeof raw.raw_sha256 !== 'string' || raw.raw_sha256.length !== 64 || !/^[0-9a-f]{64}$/.test(raw.raw_sha256) ||
      typeof raw.size !== 'number' || !Number.isSafeInteger(raw.size) || raw.size < 1)
    fail('repair_invalid_ref');
  return Object.freeze({...address, raw_sha256: raw.raw_sha256, size: raw.size});
}

/** A finite in-memory raw-byte map, not a Vault, network fetcher or authority.
 * Locator key is opaque and need not equal raw_sha256. Namespace is binding.
 */
export class LocalRawResolver {
  readonly #policy: RepairPolicy; readonly #budget: RepairBudget;
  readonly #entries = new Map<string, {bytes: Buffer; original: RawOriginal}>();
  constructor(policy: RepairPolicy, budget: RepairBudget) {
    checkBudget(policy, budget); this.#policy = policyCopy(policy); this.#budget = budget;
  }
  get policy(): RepairPolicy {return this.#policy;}
  get budget(): RepairBudget {return this.#budget;}
  put(namespace: 'meta'|'object', key: string, raw: Uint8Array): RawOriginal {
    const address = refAddress(namespace, key);
    const size = rawSize(raw);
    if (size > this.#policy.max_document_bytes) fail('repair_over_budget');
    if (size === 0) fail('repair_invalid_ref');
    const locator = namespace + ':' + key, previous = this.#entries.get(locator);
    if (!previous) this.#budget.canRetain(size);
    const bytes = snapshotInput(raw, this.#budget);
    const ref = Object.freeze({...address, raw_sha256: this.#budget.hash(bytes), size: bytes.length});
    if (previous) {
      if (previous.original.ref.raw_sha256 !== ref.raw_sha256 || !previous.bytes.equals(bytes))
        fail('repair_ref_conflict');
      return previous.original;
    }
    this.#budget.retain(bytes.length);
    const budget = this.#budget;
    const original = Object.freeze({ref, get raw(): Uint8Array {return copyOutput(bytes, budget);}});
    this.#entries.set(locator, {bytes, original}); return original;
  }
  resolve(value: unknown): RawOriginal {
    const ref = rawRef(value), entry = this.#entries.get(ref.namespace + ':' + ref.key);
    if (!entry) fail('repair_ref_missing');
    if (ref.size !== entry.bytes.length) fail('repair_ref_mismatch');
    this.#budget.input(entry.bytes.length);
    const digest = this.#budget.hash(entry.bytes);
    if (ref.raw_sha256 !== digest) fail('repair_ref_mismatch');
    return entry.original;
  }
  get(value: unknown): RawOriginal {return this.resolve(value);}
}

const PACK_MAGIC = Buffer.from('MVRP1\0', 'ascii');
const PACK_PREFIX = 10, PACK_HEADER = 40, U32_MAX = 0xffffffff;
export interface PackEntry {
  readonly raw_sha256: string; readonly size: number; readonly offset: number;
}
/** Local byte integrity only; no historical closure or disclosure verdict. */
export interface DraftPack {
  readonly ref: RawRef; readonly raw: Uint8Array;
  readonly entries: readonly PackEntry[];
  entry(index: number, documentRef: RawRef): RawOriginal;
}
function packSize(total: number, amount: number, policy: RepairPolicy): number {
  if (amount > Number.MAX_SAFE_INTEGER - total || amount > policy.max_document_bytes - total)
    fail('repair_over_budget');
  return total + amount;
}
function packCapacity(size: number, count: number, budget: RepairBudget): number {
  if (!Number.isInteger(count) || count < 1 || count > U32_MAX) fail('repair_invalid_pack');
  if (size > budget.policy.max_document_bytes) fail('repair_over_budget');
  const indexBytes = PACK_HEADER * count;
  if (indexBytes > Number.MAX_SAFE_INTEGER - size) fail('repair_over_budget');
  const retained = size + indexBytes;
  budget.canRetain(retained, count + 1);
  return retained;
}
function startsPack(raw: Uint8Array): boolean {
  return raw.length >= PACK_MAGIC.length && PACK_MAGIC.every((byte, index) => raw[index] === byte);
}
function byteView(raw: Uint8Array): Uint8Array {
  const size = rawSize(raw);
  try {return new Uint8Array(bufferOf.call(raw), byteOffsetOf.call(raw), size);}
  catch {fail('repair_invalid_bytes');}
}
function packCount(bytes: Uint8Array): number {
  if (bytes.length < PACK_PREFIX || !startsPack(bytes)) fail('repair_invalid_pack');
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(6, false);
}
function checkPackCount(size: number, count: number, budget: RepairBudget): void {
  packCapacity(size, count, budget);
  if (count > Math.floor((size - PACK_PREFIX) / (PACK_HEADER + 1))) fail('repair_invalid_pack');
}
function draftPack(bytes: Buffer, ref: RawRef, records: PackEntry[], budget: RepairBudget): DraftPack {
  const entries = Object.freeze(records);
  const result: DraftPack = {
    ref, entries,
    get raw(): Uint8Array {return copyOutput(bytes, budget);},
    entry(index: number, documentRef: RawRef): RawOriginal {
      u53(index);
      if (index >= entries.length) fail('repair_invalid_pack');
      const reference = rawRef(documentRef), selected = entries[index];
      if (reference.size !== selected.size || reference.raw_sha256 !== selected.raw_sha256)
        fail('repair_ref_mismatch');
      // A private view avoids allocating body bytes merely to hash them.
      const body = bytes.subarray(selected.offset, selected.offset + selected.size);
      if (body.length !== reference.size || budget.hash(body) !== reference.raw_sha256)
        fail('repair_ref_mismatch');
      return Object.freeze({ref: reference, get raw(): Uint8Array {return copyOutput(body, budget);}});
    },
  };
  return Object.freeze(result);
}

/** Parse exact binary originals, without applying a JSON/authority schema. */
export function parseRawPack(raw: Uint8Array, expectedPackRef: RawRef,
                             policy: RepairPolicy, budget: RepairBudget): DraftPack {
  checkBudget(policy, budget); policy = budget.policy;
  const reference = rawRef(expectedPackRef);
  if (reference.namespace !== 'meta' || reference.key !== reference.raw_sha256)
    fail('repair_ref_mismatch');
  const size = rawSize(raw);
  if (size > policy.max_document_bytes) fail('repair_over_budget');
  if (size !== reference.size) fail('repair_ref_mismatch');
  // Inspect only the fixed prefix before any byte copy, hash or index allocation.
  const view = byteView(raw);
  if (view.length !== size) fail('repair_invalid_pack');
  const count = packCount(view);
  checkPackCount(size, count, budget);
  const bytes = snapshotInput(view, budget);
  // Concurrently mutable backing stores cannot change the checked count/size.
  if (bytes.length !== size || packCount(bytes) !== count) fail('repair_invalid_pack');
  const entries: PackEntry[] = [];
  let offset = PACK_PREFIX, previousDigest = '', previousSize = 0;
  for (let index = 0; index < count; index++) {
    budget.node(1);
    if (bytes.length - offset < PACK_HEADER) fail('repair_invalid_pack');
    const exactSize = bytes.readBigUInt64BE(offset);
    if (exactSize < 1n || exactSize > BigInt(Number.MAX_SAFE_INTEGER)) fail('repair_invalid_pack');
    const length = Number(exactSize), digest = bytes.toString('hex', offset + 8, offset + PACK_HEADER);
    offset += PACK_HEADER;
    if (length > bytes.length - offset) fail('repair_invalid_pack');
    if (index > 0 && (digest < previousDigest || (digest === previousDigest && length <= previousSize)))
      fail('repair_invalid_pack');
    const body = bytes.subarray(offset, offset + length);
    if (startsPack(body)) fail('repair_invalid_pack');
    if (budget.hash(body) !== digest) fail('repair_ref_mismatch');
    entries.push(Object.freeze({raw_sha256: digest, size: length, offset}));
    offset += length; previousDigest = digest; previousSize = length;
  }
  if (offset !== bytes.length) fail('repair_invalid_pack');
  if (budget.hash(bytes) !== reference.raw_sha256) fail('repair_ref_mismatch');
  budget.retain(packCapacity(size, count, budget), count + 1);
  return draftPack(bytes, reference, entries, budget);
}

/** Snapshot each original and build its canonical binary pack. No trust verdict. */
export function buildRawPack(raws: readonly Uint8Array[], policy: RepairPolicy,
                             budget: RepairBudget): DraftPack {
  checkBudget(policy, budget); policy = budget.policy;
  if (!Array.isArray(raws) || isProxy(raws)) fail('repair_invalid_pack');
  const count = Object.getOwnPropertyDescriptor(raws, 'length')!.value as number;
  packCapacity(PACK_PREFIX, count, budget); // Before making any count-sized list.
  const inputs: Uint8Array[] = [];
  let total = PACK_PREFIX;
  for (let index = 0; index < count; index++) {
    const property = Object.getOwnPropertyDescriptor(raws, String(index));
    if (!property || !Object.hasOwn(property, 'value')) fail('repair_invalid_pack');
    // Fixed-length intrinsic views keep a growable backing store from expanding
    // the already checked snapshot allocation; this does not copy body bytes.
    const input = byteView(property.value as Uint8Array), size = rawSize(input);
    if (size === 0) fail('repair_invalid_pack');
    total = packSize(total, PACK_HEADER + size, policy);
    inputs.push(input);
  }
  // Conservative before deduplication: no snapshot/hash precedes holding caps.
  packCapacity(total, count, budget);
  const unique = new Map<string, {digest: string; bytes: Buffer}>();
  for (const input of inputs) {
    budget.node(1);
    const bytes = snapshotInput(input, budget);
    if (bytes.length === 0 || startsPack(bytes)) fail('repair_invalid_pack');
    const digest = budget.hash(bytes), identity = digest + ':' + bytes.length, prior = unique.get(identity);
    if (prior && !prior.bytes.equals(bytes)) fail('repair_ref_conflict');
    if (!prior) unique.set(identity, {digest, bytes});
  }
  total = PACK_PREFIX;
  for (const {bytes} of unique.values()) total = packSize(total, PACK_HEADER + bytes.length, policy);
  const retained = packCapacity(total, unique.size, budget);
  const ordered = [...unique.values()].sort((left, right) =>
    left.digest < right.digest ? -1 : left.digest > right.digest ? 1 : left.bytes.length - right.bytes.length);
  budget.output(total); // The sole private construction buffer, before allocation.
  const bytes = Buffer.alloc(total), entries: PackEntry[] = [];
  PACK_MAGIC.copy(bytes); bytes.writeUInt32BE(ordered.length, 6);
  let offset = PACK_PREFIX;
  for (const {digest, bytes: body} of ordered) {
    bytes.writeBigUInt64BE(BigInt(body.length), offset);
    bytes.write(digest, offset + 8, 32, 'hex'); offset += PACK_HEADER;
    body.copy(bytes, offset);
    entries.push(Object.freeze({raw_sha256: digest, size: body.length, offset}));
    offset += body.length;
  }
  const digest = budget.hash(bytes);
  const reference = Object.freeze({namespace: 'meta' as const, key: digest, raw_sha256: digest, size: total});
  budget.retain(retained, entries.length + 1);
  return draftPack(bytes, reference, entries, budget);
}
