/** Normative mv-rank-q64/1 arithmetic. No platform log/exp or floating score.
 * This finite Q64 profile is opt-in; changing its rounding sites is a new
 * profile. BigInt values stay internal and never enter network JSON.
 */
export const RANKING_MATH_PROFILE = 'mv-rank-q64/1';
export const Q64_SCALE = 18446744073709551616n;
export const LN2_Q64 = 12786308645202655660n;
export const YEAR_MICROSECONDS = 31536000000000n;
const MAX_SAFE_INTEGER = 9007199254740991n;

export class RankingMathError extends Error {
  readonly code: string;
  constructor(code: string) { super(code); this.name = 'RankingMathError'; this.code = code; }
}
function fail(code = 'ranking_math_domain'): never { throw new RankingMathError(code); }

/** Nonnegative exact division, nearest with ties to the even quotient. */
export function roundQ(numerator: bigint, denominator: bigint): bigint {
  if (numerator < 0n || denominator <= 0n) fail();
  const quotient = numerator / denominator, remainder = numerator % denominator;
  return quotient + (2n * remainder > denominator ||
    2n * remainder === denominator && quotient % 2n === 1n ? 1n : 0n);
}

/** The bounded retrieval caller supplies n/d <= 8194. Exactly 32 terms. */
export function logQ(numerator: bigint, denominator: bigint): bigint {
  if (denominator <= 0n || numerator < denominator) fail();
  let powerOfTwo = 0n;
  while (numerator >= 2n * denominator) { denominator *= 2n; powerOfTwo++; }
  const z = roundQ((numerator - denominator) * Q64_SCALE, numerator + denominator);
  const square = roundQ(z * z, Q64_SCALE);
  let power = z, sum = 0n;
  for (let index = 0n; index < 32n; index++) {
    sum += roundQ(power, 2n * index + 1n);
    power = roundQ(power * square, Q64_SCALE);
  }
  return powerOfTwo * LN2_Q64 + 2n * sum;
}

/** Finite alternating series and repeated squaring; range reduction <=9. */
export function expNegQ(value: bigint): bigint {
  if (value < 0n) fail();
  if (value >= 64n * Q64_SCALE) return 0n;
  let reductions = 0n, threshold = Q64_SCALE / 8n;
  while (value > threshold) { threshold *= 2n; reductions++; }
  const reduced = roundQ(value, 1n << reductions);
  let term = Q64_SCALE, total = Q64_SCALE;
  for (let index = 1n; index <= 20n; index++) {
    term = roundQ(term * reduced, index * Q64_SCALE);
    total += index % 2n === 0n ? term : -term;
  }
  for (let index = 0n; index < reductions; index++) total = roundQ(total * total, Q64_SCALE);
  return total < 0n ? 0n : total > Q64_SCALE ? Q64_SCALE : total;
}

/** Capture/validate once per ranking, retaining the Python datetime range. */
export function rankingTimeMicros(milliseconds: number): bigint {
  if (!Number.isSafeInteger(milliseconds) || milliseconds < -62135596800000 || milliseconds > 253402300799999) {
    fail('invalid_ranking_clock');
  }
  return BigInt(milliseconds) * 1000n;
}

const MONTH_DAYS: Readonly<Record<string, bigint>> = {
  '01': 31n, '02': 28n, '03': 31n, '04': 30n, '05': 31n, '06': 30n,
  '07': 31n, '08': 31n, '09': 30n, '10': 31n, '11': 30n, '12': 31n,
};
const MONTH_OFFSETS: Readonly<Record<string, bigint>> = {
  '01': 0n, '02': 31n, '03': 59n, '04': 90n, '05': 120n, '06': 151n,
  '07': 181n, '08': 212n, '09': 243n, '10': 273n, '11': 304n, '12': 334n,
};

/** Gregorian calendar arithmetic; no Date.parse or epoch-float subtraction. */
export function canonicalTimestampMicros(value: string): bigint {
  const parts = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,6}))?Z$/.exec(value);
  if (!parts) fail('invalid_timestamp');
  const year = BigInt(parts[1]), day = BigInt(parts[3]), hour = BigInt(parts[4]);
  const minute = BigInt(parts[5]), second = BigInt(parts[6]), month = parts[2];
  const leap = year % 4n === 0n && (year % 100n !== 0n || year % 400n === 0n);
  const maximumDay = MONTH_DAYS[month];
  if (year < 1n || year > 9999n || maximumDay === undefined || day < 1n ||
      day > maximumDay + (month === '02' && leap ? 1n : 0n) || hour > 23n || minute > 59n || second > 59n) {
    fail('invalid_timestamp');
  }
  const previousYear = year - 1n;
  const days = 365n * previousYear + previousYear / 4n - previousYear / 100n + previousYear / 400n +
    MONTH_OFFSETS[month] + (month > '02' && leap ? 1n : 0n) + day - 1n - 719162n;
  return ((days * 24n + hour) * 60n + minute) * 60000000n +
    second * 1000000n + BigInt((parts[7] ?? '').padEnd(6, '0'));
}

export function timeFactorQ(nowMicros: bigint, createdMicros: bigint): bigint {
  const age = nowMicros > createdMicros ? nowMicros - createdMicros : 0n;
  const decay = expNegQ(roundQ(age * Q64_SCALE, YEAR_MICROSECONDS));
  return roundQ(41n * Q64_SCALE + 9n * decay, 50n);
}

/** The caller caches logQ per df; this term has exactly one final division. */
export function lexicalTermQ(inverseQ: bigint, documents: bigint, totalLength: bigint,
  length: bigint, frequency: bigint): bigint {
  if (inverseQ < 0n || documents < 1n || documents > 4096n || totalLength < documents ||
      totalLength > documents * 4096n || length < 1n || length > 4096n || frequency < 1n || frequency > length) fail();
  return roundQ(inverseQ * 1175n * frequency * totalLength,
    500n * frequency * totalLength + 27n * (7n * totalLength + 18n * length * documents));
}

export interface FeatureCardinality {
  readonly overlap: number; readonly union: number; readonly polarity_denominator: 1 | 4;
}
function cardinality(value: FeatureCardinality): readonly [bigint, bigint] {
  if (!Number.isSafeInteger(value.overlap) || !Number.isSafeInteger(value.union) ||
      value.overlap < 0 || value.union < 1 || value.overlap > value.union ||
      (value.polarity_denominator !== 1 && value.polarity_denominator !== 4)) fail();
  return [BigInt(value.overlap), BigInt(value.union) * BigInt(value.polarity_denominator)];
}
function jsonInteger(value: bigint): number {
  if (value < 0n || value > MAX_SAFE_INTEGER) fail('ranking_score_out_of_range');
  return Number(value);
}
const milli = (value: bigint): number => jsonInteger(roundQ(value * 1000n, Q64_SCALE));

export interface V2ScoreInput {
  readonly lexicalQ: bigint;
  readonly concept: FeatureCardinality;
  readonly entityConcept: FeatureCardinality;
  readonly entityMatches: bigint;
  readonly queryTokens: bigint;
  readonly phrase: boolean;
  readonly related: boolean;
  readonly userHint: boolean;
  readonly episode: boolean;
  readonly deprecated: boolean;
  readonly recencyQ: bigint;
}
export interface V2Score {
  readonly eligible: boolean;
  readonly concept_positive: boolean;
  readonly score_milli: number;
  readonly score_components: Readonly<Record<string, number>>;
}

/** Exact rational components; preserve each normative rounding boundary. */
export function scoreV2(input: V2ScoreInput): V2Score {
  if (input.lexicalQ < 0n || input.entityMatches < 0n || input.queryTokens < 0n ||
      input.queryTokens > 256n || input.entityMatches > input.queryTokens ||
      input.recencyQ < 0n || input.recencyQ > Q64_SCALE) fail();
  const [overlap, semanticDenominator] = cardinality(input.concept);
  const [entityOverlap, entityDenominator] = cardinality(input.entityConcept);
  const tokenDenominator = input.queryTokens > 0n ? input.queryTokens : 1n;
  const concept = roundQ(9n * overlap * Q64_SCALE, 4n * semanticDenominator);
  const entity = roundQ(Q64_SCALE * (input.entityMatches * entityDenominator + entityOverlap * tokenDenominator),
    2n * tokenDenominator * entityDenominator);
  const phrase = input.phrase ? roundQ(27n * Q64_SCALE, 20n) : 0n;
  const graph = input.related ? roundQ(Q64_SCALE, 5n) : 0n;
  const base = input.lexicalQ + concept + entity + phrase + graph;
  const roleP = input.userHint ? 71n : 1n, roleQ = input.userHint ? 50n : 1n;
  const kindP = input.episode ? 1n : 28n, kindQ = input.episode ? 1n : 25n;
  const stateP = input.deprecated ? 18n : 1n, stateQ = input.deprecated ? 25n : 1n;
  const score = roundQ(base * roleP * kindP * stateP * input.recencyQ * 1000n,
    roleQ * kindQ * stateQ * Q64_SCALE * Q64_SCALE);
  return { eligible: base > 0n, concept_positive: concept > 0n, score_milli: jsonInteger(score),
    score_components: { lexical_milli: milli(input.lexicalQ), semantic_milli: milli(concept),
      entity_milli: milli(entity), phrase_milli: milli(phrase), graph_milli: milli(graph),
      role_factor_milli: jsonInteger(roundQ(roleP * 1000n, roleQ)),
      kind_factor_milli: jsonInteger(roundQ(kindP * 1000n, kindQ)),
      graph_factor_milli: jsonInteger(roundQ(stateP * 1000n, stateQ)), recency_factor_milli: milli(input.recencyQ) } };
}
