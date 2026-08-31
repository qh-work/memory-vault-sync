/** Pure text helpers for the existing bounded-fragment retrieval profile.
 * Ported from memory_vault.py; no storage, network, model, or Python runtime.
 * Callers supply admitted canonical records. Embedded roles remain untrusted.
 */
import { normalizeText } from './records.ts';
import { canonicalBytes, document, NetworkCryptoError } from './crypto.ts';

export { normalizeText } from './records.ts';
export const MAX_BUNDLE_LINE_BYTES = 2 * 1024 * 1024;
export const MAX_QUERY_TOKENS = 256;
export const MAX_RECALL_LIMIT = 32;
export const MAX_CONTEXT_BYTES = 64 * 1024;
export const MAX_HIT_TEXT_BYTES = 48 * 1024;
export const MAX_RETRIEVAL_CANDIDATES = 512;
export const MAX_RERANK_BYTES = 8 * 1024 * 1024;
export const MAX_RERANK_FRAGMENTS = 4096;
export const MAX_FRAGMENT_CHARACTERS = 1600;
export const RETRIEVAL_PROFILE = 'bounded-fragment-bm25+deterministic-concepts/v1';
export const RETRIEVAL_INDEX_PROFILE = 'full-record-terms+entities/v1';
export const LATIN_PATTERN = '[a-z0-9][a-z0-9_+.-]{0,63}';
export const CJK_RUN_PATTERN = '[\\u3400-\\u4dbf\\u4e00-\\u9fff\\uf900-\\ufaff\\u3040-\\u30ff\\uac00-\\ud7af]+';
export const CONCEPT_GROUPS: readonly ReadonlySet<string>[] = Object.freeze([
  new Set(['备份', '保存', '存档', 'backup', 'archive', 'save']),
  new Set(['同步', '传输', '复制', 'sync', 'transfer', 'replicate']),
  new Set(['快速', '高效', '性能', '等待', '延迟', 'fast', 'efficient', 'latency', 'performance']),
  new Set(['记忆', '回忆', '召回', 'memory', 'recall', 'remember']),
  new Set(['删除', '移除', '清理', 'delete', 'remove', 'cleanup']),
  new Set(['冲突', '矛盾', '不一致', 'conflict', 'contradiction']),
  new Set(['偏好', '喜欢', '习惯', 'preference', 'prefer']),
  new Set(['更正', '纠正', '修正', 'correction', 'correct', 'fix']),
  new Set(['本地', '离线', '设备', 'local', 'offline', 'device']),
  new Set(['加密', '隐私', '安全', 'encrypt', 'privacy', 'secure']),
]);
export const NEGATION_MARKERS: ReadonlySet<string> = new Set([
  '不', '不要', '无需', '无须', '没有', '不能', '禁止', 'not', 'never', 'without', 'no',
]);
export const STOPWORDS: ReadonlySet<string> = new Set([
  'about', 'after', 'also', 'and', 'are', 'but', 'can', 'for', 'from', 'have', 'into',
  'not', 'that', 'the', 'their', 'then', 'this', 'was', 'were', 'will', 'with', 'you', 'your',
]);
// Python str.strip(), not JavaScript trim(): U+FEFF is not whitespace here.
const ONLY_SPACE = /^[\u0009-\u000d\u001c-\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]*$/u;

export class NetworkRetrievalTextError extends NetworkCryptoError {
  constructor(code: string) { super(code); this.name = 'NetworkRetrievalTextError'; }
}
export interface TokenizeOptions { readonly maximum?: number; readonly maximumInputBytes?: number }
export interface TextRecord {
  readonly text: string;
  readonly memory_id: string;
  readonly kind?: string;
  readonly provenance?: unknown;
}
export type FragmentRole = 'user' | 'assistant';
export type FragmentRegion = [number, number, FragmentRole];
export interface MemoryFragment {
  readonly fragment_id: string;
  readonly start_character: number;
  readonly end_character: number;
  readonly text: string;
  readonly role_hint: FragmentRole | null;
  readonly role_hint_authenticated: false;
}
function utf8(value: string): Buffer {
  if (typeof value !== 'string') throw new NetworkRetrievalTextError('invalid_text');
  const result = Buffer.from(value, 'utf8');
  if (result.toString('utf8') !== value) throw new NetworkRetrievalTextError('invalid_text');
  return result;
}
/** UTF-8 prefix with incomplete trailing code points discarded, as in Python. */
export function boundedText(value: string, maximum = MAX_HIT_TEXT_BYTES): [string, boolean] {
  const encoded = utf8(value);
  if (encoded.length <= maximum) return [value, false];
  if (!Number.isSafeInteger(maximum)) throw new TypeError('integer byte budget required');
  let end = encoded.subarray(0, maximum).length;
  while (end > 0 && end < encoded.length && (encoded[end] & 0xc0) === 0x80) end--;
  return [encoded.subarray(0, end).toString('utf8'), true];
}
function isCJK(character: string): boolean {
  const point = character.codePointAt(0)!;
  return (point >= 0x3400 && point <= 0x4dbf) || (point >= 0x4e00 && point <= 0x9fff) ||
    (point >= 0xf900 && point <= 0xfaff) || (point >= 0x3040 && point <= 0x30ff) ||
    (point >= 0xac00 && point <= 0xd7af);
}
/** Order and duplicate token counts match Python, including Latin-first order. */
export function tokenize(value: unknown, options: TokenizeOptions = {}): string[] {
  if (typeof value !== 'string' || ONLY_SPACE.test(value)) return [];
  const { maximum = MAX_QUERY_TOKENS, maximumInputBytes = 64 * 1024 } = options;
  if (utf8(value).length > maximumInputBytes) throw new NetworkRetrievalTextError('query_too_large');
  const normalized = normalizeText(value), result: string[] = [];
  for (const match of normalized.matchAll(new RegExp(LATIN_PATTERN, 'gu'))) {
    if (!STOPWORDS.has(match[0])) {
      result.push('w:' + match[0]);
      if (result.length >= maximum) return result;
    }
  }
  let run: string[] = [];
  const flush = () => {
    if (!run.length) return;
    if (run.length === 1) result.push('c:' + run[0]);
    else {
      for (let index = 0; index < run.length - 1; index++) result.push('c:' + run[index] + run[index + 1]);
      if (run.length <= 8) result.push('p:' + run.join(''));
    }
    run = [];
  };
  for (const character of normalized) {
    if (isCJK(character)) run.push(character); else flush();
    if (result.length >= maximum) return result.slice(0, maximum);
  }
  flush();
  return result.slice(0, maximum);
}
/** Small deterministic bilingual hints; these are not authority or an embedding. */
export function semanticFeatures(value: string): ReadonlySet<string> {
  const normalized = normalizeText(value);
  const words = new Set(Array.from(normalized.matchAll(new RegExp(LATIN_PATTERN, 'gu')), match => match[0]));
  const contains = (term: string) => /^[\x00-\x7f]*$/u.test(term) ? words.has(term) : normalized.includes(term);
  const result = new Set<string>();
  CONCEPT_GROUPS.forEach((terms, index) => { if (Array.from(terms).some(contains)) result.add('concept:' + index); });
  if (Array.from(NEGATION_MARKERS).some(contains)) result.add('polarity:negative');
  return result;
}
export function semanticSimilarity(query: ReadonlySet<string>, candidate: ReadonlySet<string>): number {
  const left = new Set(Array.from(query).filter(value => value.startsWith('concept:')));
  const right = new Set(Array.from(candidate).filter(value => value.startsWith('concept:')));
  let overlap = 0;
  for (const value of left) if (right.has(value)) overlap++;
  if (!overlap) return 0;
  let score = overlap / new Set([...left, ...right]).size;
  if (query.has('polarity:negative') !== candidate.has('polarity:negative')) score *= 0.25;
  return score;
}
/** Python sorts strings by Unicode scalar value, not UTF-16 code units. */
function codepointOrder(left: string, right: string): number {
  const a = Array.from(left, point => point.codePointAt(0)!);
  const b = Array.from(right, point => point.codePointAt(0)!);
  for (let index = 0; index < Math.min(a.length, b.length); index++) if (a[index] !== b[index]) return a[index] - b[index];
  return a.length - b.length;
}
export function expandedQueryTokens(tokens: readonly string[], features: ReadonlySet<string>): string[] {
  const result = new Set(tokens);
  CONCEPT_GROUPS.forEach((terms, index) => {
    if (features.has('concept:' + index)) for (const term of Array.from(terms).sort(codepointOrder)) {
      for (const token of tokenize(term)) result.add(token);
    }
  });
  return Array.from(result).sort(codepointOrder);
}
export function entityQueryMatches(entities: readonly string[], queryTokens: ReadonlySet<string>): ReadonlySet<string> {
  const matched = new Set<string>();
  for (const entity of entities) {
    if (matched.size === queryTokens.size) break;
    for (const token of tokenize(entity, { maximum: MAX_BUNDLE_LINE_BYTES * 2, maximumInputBytes: 512 })) {
      if (queryTokens.has(token)) matched.add(token);
    }
  }
  return matched;
}
/** Linear span prefilter, separate from full scoring/token budgets. */
export function fragmentLocator(tokens: readonly string[], normalizedQuery: string): (text: string) => boolean {
  const latin = new Set(tokens.filter(token => token.startsWith('w:')).map(token => token.slice(2)));
  const cjk = new Set(tokens.filter(token => token.startsWith('c:')).map(token => token.slice(2)));
  const phrases = new Set(tokens.filter(token => token.startsWith('p:')).map(token => token.slice(2)));
  return (text: string) => {
    const normalized = normalizeText(text);
    if (normalizedQuery && normalized.includes(normalizedQuery)) return true;
    if (latin.size) for (const match of normalized.matchAll(new RegExp(LATIN_PATTERN, 'gu'))) {
      if (latin.has(match[0])) return true;
    }
    if (cjk.size || phrases.size) for (const match of normalized.matchAll(new RegExp(CJK_RUN_PATTERN, 'gu'))) {
      const run = Array.from(match[0]);
      if (run.length === 1) { if (cjk.has(run[0])) return true; }
      else {
        if (run.length <= 8 && phrases.has(match[0])) return true;
        for (let index = 0; index < run.length - 1; index++) if (cjk.has(run[index] + run[index + 1])) return true;
      }
    }
    return false;
  };
}
function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function exactFields(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
}
function sequenceAt(points: readonly string[], needle: readonly string[], start: number): boolean {
  return start >= 0 && start + needle.length <= points.length && needle.every((point, index) => points[start + index] === point);
}
function findSequence(points: readonly string[], needle: readonly string[], start = 0, end = points.length): number {
  for (let index = start; index + needle.length <= Math.min(end, points.length); index++) {
    if (sequenceAt(points, needle, index)) return index;
  }
  return -1;
}
function visibleRegion(record: TextRecord, points: readonly string[]): FragmentRegion | null {
  if (record.kind !== 'episode' || !object(record.provenance) ||
      record.provenance.source_ref !== 'codex-visible-fragment/v1') return null;
  const prefix = Array.from('Memory Vault visible fragment/v1\n');
  if (!sequenceAt(points, prefix, 0)) return null;
  const boundary = findSequence(points, ['\n', '\n'], prefix.length, prefix.length + 1026);
  if (boundary < 0) return null;
  const encoded = points.slice(prefix.length, boundary).join('');
  let role: FragmentRole;
  try {
    const bytes = utf8(encoded);
    if (bytes.length > 1024) return null;
    const header = document(bytes, 1024);
    if (!exactFields(header, ['coverage', 'observed_role', 'missing_roles', 'supplement']) ||
        header.coverage !== 'partial_active_turn' || (header.observed_role !== 'user' && header.observed_role !== 'assistant') ||
        !Array.isArray(header.missing_roles) || header.missing_roles.length !== 1 ||
        header.missing_roles[0] !== (header.observed_role === 'user' ? 'assistant' : 'user') ||
        Buffer.from(canonicalBytes(header)).toString('utf8') !== encoded) return null;
    const supplement = header.supplement;
    if (supplement !== null && (!object(supplement) || !exactFields(supplement, ['memory_id', 'record_sha256']) ||
        typeof supplement.record_sha256 !== 'string' || supplement.record_sha256.length !== 64 || !/^[0-9a-f]{64}$/u.test(supplement.record_sha256) ||
        supplement.memory_id !== 'mem_' + supplement.record_sha256.slice(0, 40))) return null;
    role = header.observed_role;
  } catch { return null; }
  const label = Array.from(role === 'user' ? 'User:\n' : 'Assistant:\n'), begin = boundary + 2;
  if (!sequenceAt(points, label, begin) || ONLY_SPACE.test(points.slice(begin + label.length).join(''))) return null;
  return [begin + label.length, points.length, role];
}
/** Recognize one canonical public frame as an unauthenticated ranking hint. */
export function visibleFragmentRegion(record: TextRecord): FragmentRegion | null {
  return visibleRegion(record, Array.from(record.text));
}
/** Overlapping spans of original text, with code-point offsets and no summaries. */
export function* memoryFragments(record: TextRecord): Generator<MemoryFragment> {
  const points = Array.from(record.text);
  let regions: [number, number, FragmentRole | null][] = [[0, points.length, null]];
  const delimiter = Array.from('\n\nAssistant:\n'), split = findSequence(points, delimiter);
  if (record.kind === 'episode' && sequenceAt(points, Array.from('User:\n'), 0) && split >= 6) {
    regions = [[6, split, 'user'], [split + delimiter.length, points.length, 'assistant']];
  } else {
    const visible = visibleRegion(record, points);
    if (visible !== null) regions = [visible];
  }
  let ordinal = 0;
  for (const [begin, end, role] of regions) {
    let offset = begin;
    while (offset < end) {
      let stop = Math.min(end, offset + MAX_FRAGMENT_CHARACTERS);
      if (stop < end) for (let boundary = stop - 1; boundary >= offset + Math.floor(MAX_FRAGMENT_CHARACTERS / 2); boundary--) {
        if (points[boundary] === '\n') { if (boundary > offset) stop = boundary + 1; break; }
      }
      const excerpt = points.slice(offset, stop).join('');
      if (!ONLY_SPACE.test(excerpt)) {
        yield { fragment_id: record.memory_id + ':' + ordinal, start_character: offset, end_character: stop,
          text: excerpt, role_hint: role, role_hint_authenticated: false };
        ordinal++;
      }
      if (stop === end) break;
      offset = Math.max(offset + 1, stop - 128);
    }
  }
}
/** Sort key for an already-valid canonical record timestamp; no precision loss. */
export function timelineKey(value: string): string {
  const match = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,6}))?Z$/u.exec(value);
  if (!match || match[0] !== value) throw new NetworkRetrievalTextError('invalid_timestamp');
  const [year, month, day, hour, minute, second] = match.slice(1, 7).map(Number);
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (year < 1 || month < 1 || month > 12 || day < 1 || day > days[month - 1] || hour > 23 || minute > 59 || second > 59) {
    throw new NetworkRetrievalTextError('invalid_timestamp');
  }
  return match.slice(1, 4).join('-') + 'T' + match.slice(4, 7).join(':') + '.' + (match[7] ?? '').padEnd(6, '0') + 'Z';
}
