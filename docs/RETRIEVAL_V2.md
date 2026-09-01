# Opt-in deterministic ranking v2

This is a post-alpha source capability, not a replacement of the published
v0.26.0-alpha.1 attachments. It changes derived local retrieval scores only.
Canonical memory bytes, IDs, Ed25519 source attestations, current trust,
SQLite storage and the disposable index profile stay unchanged. No migration,
new database, embedding model or network access is required.

## Selection and shared entries

The default remains `bounded-fragment-bm25+deterministic-concepts/v1`.
Its known cross-runtime floating-point `exp` boundary remains a strict expected
failure; v2 does not silently repair or redefine v1. Select v2 explicitly:

```json
{"op":"recall","query":"save sync memory delete","ranking_profile":"bounded-fragment-bm25+deterministic-concepts/v2"}
```

The core `recall` and `handoff` operations, Python native `Agent`, independent
TypeScript `Agent`/`CanonicalVault.retrieve`, existing client command and trusted
HTTP `/v1/agent` entry use that selector. Native handoff remains
`{"op":"recall","query":"current goal","handoff":true,"ranking_profile":"bounded-fragment-bm25+deterministic-concepts/v2"}`.
Existing memory-tool schemas expose the same optional selector; this adds no
new MCP tools or external protocol adapter. The HTTP SDK forwards the selector
to its trusted endpoint and does not independently rerank results.

Unknown profile strings return `unsupported_ranking_profile`. Profiles cannot
be combined with native explicit-ID inspection or a continuation cursor.
Core capabilities and offline native discovery advertise the default and the
supported `retrieval_profiles` list without opening a Vault or using a network.

V2 query results include `retrieval.profile`, `math_profile: "mv-rank-q64/1"`
and integer `ranking_time_ms`. The core also retains its existing retrieval
statistics. The native result includes these three fields and carries them in
its cursor. The cursor freezes selected IDs and the original clock; continuing
does not rerank, even after a restart or when the other native runtime resumes
it. Current trust is still rechecked on each page. Old v1 cursor bytes remain
valid and unchanged. Cursor metadata is unauthenticated local continuation data,
not proof of a prior search or an authorization token.

## Arithmetic contract: mv-rank-q64/1

All arithmetic below is integer arithmetic. Python uses integers and the
independent TypeScript implementation uses `BigInt`. There is no runtime
`log`, `exp`, floating-point date conversion or per-language score tolerance
in v2's scoring formula. Do not change a constant, approximation, iteration
count or rounding site under this profile name.

Let `Q = 2^64`. `R(n,d)` divides a nonnegative integer `n` by positive integer
`d`, rounding to nearest with exact ties to even. Let
`LN2Q = 12786308645202655660`. Q-scaled values represent a real value times Q.

`logQ(n,d)`, for `n >= d > 0`:

1. Start `k=0`; while `n >= 2*d`, double `d` and increment `k`.
2. Set `z=R((n-d)*Q,n+d)`, `zz=R(z*z,Q)`, `power=z`, `sum=0`.
3. For `j=0..31`, add `R(power,2*j+1)` to `sum`, then set
   `power=R(power*zz,Q)`.
4. Return `k*LN2Q + 2*sum`.

`expNegQ(x)`, for `x >= 0`:

1. Return zero when `x >= 64*Q`. Otherwise choose the smallest nonnegative
   `k` with `x <= (Q/8)*2^k`, then set `y=R(x,2^k)`.
2. Set `term=total=Q`. For `j=1..20`, set `term=R(term*y,j*Q)`;
   subtract it for odd `j`, add it for even `j`.
3. Square `total` exactly `k` times, each time setting
   `total=R(total*total,Q)`. Clamp the result to `[0,Q]`.

These are specified approximations, not claims of correctly rounded
transcendental functions. An alternative approximation needs a different
profile even if its numerical error is smaller.

### Selected corpus and contributions

Keep the [existing bounded candidate and fragment selection](RETRIEVAL.md).
Let `N` be the actual scored fragment count, `T` the sum of their integer
lengths, `L >= 1` a fragment's length, `f` an original query token's frequency
in that fragment and `df` its document frequency in the same selected corpus.
For each matching original token, in ascending Unicode code-point order
(not locale collation or UTF-16 code-unit order):

```text
idfQ = logQ(2*(N+1), 2*df+1)
termQ = R(idfQ*1175*f*T, 500*f*T + 27*(7*T+18*L*N))
lexicalQ = sum(termQ)
```

This is the existing `k1=1.35, b=0.72` BM25 ratio with explicit Q64 rounding.
The index, concept expansion and working-set selection remain separate from
the arithmetic profile; this is not full-Vault or global-network BM25.

For concept sets, `o` is intersection cardinality, `u` is union cardinality
and `p` is 4 on a negation mismatch, otherwise 1. A zero intersection is
normalized to `(o,u,p)=(0,1,1)`. With `semantic:false`, semantic contributions
are zero while lexical, entity-token and graph evidence remain eligible.

```text
conceptQ = R(9*o*Q, 4*u*p)
entityQ  = R(Q*(m*u_e*p_e + o_e*t), 2*t*u_e*p_e)
phraseQ  = R(27*Q,20) if the normalized query phrase matches, else 0
graphQ   = R(Q,5) if related evidence is present, else 0
baseQ    = lexicalQ + conceptQ + entityQ + phraseQ + graphQ
```

Here `t=max(1, distinct original query token count)`, `m` is the count of
distinct original tokens matched by all entity labels, and `(o_e,u_e,p_e)`
is the concept cardinality of the entity features. Entity lexical and semantic
fractions are combined before that single rounding step. A zero base is
excluded. Explanations, unauthenticated role hints and matched-token semantics
are unchanged.

### Time, final score and ties

Capture the runtime clock once per search as integer milliseconds since the
Unix epoch, rounding downward. Valid clock range is years 0001 through 9999:
`[-62135596800000,253402300799999]`. The clock is not a public caller option;
an out-of-range clock returns `invalid_ranking_clock`.
Python truncates its UTC microsecond clock downward to milliseconds; native
TypeScript uses the already-integer `Date.now()`. An explicitly injected
TypeScript retrieval-host clock must itself return an in-range integer;
fractional values, NaN and infinities are rejected, not rounded for the caller.

Convert the already-validated canonical UTC `created_at` by integer Gregorian
calendar arithmetic, preserving all six fractional digits as epoch microseconds.
Then:

```text
ageUs = max(0, ranking_time_ms*1000-createdAtUs)
decayQ = expNegQ(R(ageUs*Q,31536000000000))
timeQ = R(41*Q+9*decayQ,50)
```

Role is `71/50` for the existing user role hint, otherwise `1/1`. Kind is
`28/25` for non-episodes, otherwise `1/1`. State is `18/25` for superseded or
resolved evidence, otherwise `1/1`. Multiply these exact ratios to `a/b`:

```text
score_milli = R(baseQ*a*timeQ*1000, b*Q*Q)
```

Reject a result above the JSON safe-integer maximum. Report additive component
thousandths as `R(componentQ*1000,Q)`, ratio-factor thousandths as
`R(numerator*1000,denominator)`, and recency as `R(timeQ*1000,Q)`.

Keep the highest integer fragment score for each record; retain the existing
first-fragment tie behavior. Current/conflicted records sort before
superseded/resolved history; inside each tier records sort by descending integer
score, then ascending ASCII memory ID. Current admission, evidence diversity
and dynamic structural handoff selection still apply. V2 may intentionally choose a
different result than v1; neither score is an authority or a truth probability.

## Verification boundary

`tests/test_network_ranking_v2.py` uses real synthetic SQLite records and the
independent Node reader/native Agent. It checks full result equality, the
known exponential boundary (1751/1750), exact ties and microseconds, Unicode,
negation, entity-only matching, current trust, related evidence, structural
handoff, cross-runtime continuation and the existing trusted HTTP entry.
Canonical records are compared before and after. The old v1 expected failure
remains separate. Test source presence alone is not a passing execution report;
the development release notes record the actual executed scope.

Deterministic arithmetic requires the same admitted candidate corpus, index
state, query, selection order and captured clock. It is not consensus between
replicas with different data or trust. Host Unicode tables may differ across
runtime versions. No all-platform guarantee, model-quality result, live-cloud
acceptance, thousand-agent load result or physical fault-domain guarantee is
established by these local checks. Existing bounds remain: at most 512 indexed
candidates plus bounded related evidence, 8 MiB of record bytes, 4096 scored
fragments and native 8 KiB responses. This profile adds no unbounded search.
