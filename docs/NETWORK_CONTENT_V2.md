# Network content/v2: messages and explicit memory transfer

Status: **included in the alpha.5 release target** after review and merge.
See [release scope](RELEASE.md) for publication evidence; no automatic private
upgrade or migration is provided. The first change separates communication
from long-term memory. The subsequent
[authorized Memory Hint extension](NETWORK_HINTS_V4.md) adds bounded queries
and explicit selection between known peers. Group chat, open P2P and scale
work remain later stages.

## Base payloads and the Hint extension

The existing `network-v1` carrier, identity files, X25519/JWE encryption,
Ed25519 outer signature, current membership checks, relay receipts and durable
outbox/inbox remain. Inside the encrypted body, `memory-vault-network-content/v2`
uses the following base shapes. The [Hint extension](NETWORK_HINTS_V4.md) adds
closed `hint_control` and `hint_batch_transfer` variants without interpreting chat:

```json
{"schema_version":"memory-vault-network-content/v2","kind":"message","text":"Synthetic chat, not a permanent observation."}
```

```json
{"schema_version":"memory-vault-network-content/v2","kind":"memory_transfer","note":"Synthetic selected evidence for review.","share":"BASE64URL_ENCODED_SHARE_BYTES"}
```

The second example uses a placeholder, not a valid share. `share` must encode a
complete `universal-memory-share/v1` bundle; the existing verifier still checks
canonical records, hashes, signature admission and dependency closure.

`message` requires nonempty text and forbids `note` or `share`. `memory_transfer`
requires `note` and `share`, permits an empty note and forbids `text`. Unknown
kinds, duplicate fields, extra fields and malformed content are rejected. The
text/note limit is 16,384 UTF-8 bytes, the decoded share limit is 2 MiB, and the
complete plaintext content limit is 4 MiB. These limits apply together.

Malformed share records, hashes or dependency closure are checked before any
Vault import. They follow the bounded `network_invalid_content_share` rejection
path, without a successful storage acknowledgement or memory side effect.
Budget exhaustion and local storage/I/O faults remain operational errors, not
proof that a peer sent malformed data.

The shared native `send` interface selects the payload without asking a model
to construct ciphertext:

| Native request | Encrypted kind | Long-term-memory effect |
| --- | --- | --- |
| Nonempty `text`, absent or empty `memory_ids` | `message` | None at sender or receiver |
| Nonempty `memory_ids`, optional accompanying `text` | `memory_transfer` | Transfer the explicitly selected original record closure under existing local trust; accompanying text is only `note` |
| No text and no memory IDs | Rejected | None |

The new code does not first save chat as a canonical observation. Chat and notes
remain in transport state, including when their text equals an existing record.
The result includes `content_kind` and keeps `text_memory_id:null`; equality of
text cannot manufacture a memory reference. To retain new knowledge, separately
call `remember`, use the appropriate epistemic type and preserve attribution.
When explicitly saving a retelling, use `epistemic_type: "hearsay"`, preserve
`source_agent` and an `evidence_refs` entry identifying the received message,
and sign the new retelling with the saving endpoint's own identity. These
source fields are claims/references; they do not turn the retelling into the
sender's original signed memory or independently verified evidence. The
message remains a transport object after the explicit save.

The message signature authenticates transport bytes, not a claim of direct
observation. Nothing in a message can change permissions or enroll a trusted key.

Explicit transfer retains the existing full dependency-closure rule. Selecting
one record can include its referenced records; this change does not implement
per-recipient remote-discovery grants or a restricted-closure sharing protocol.
Do not treat a remote request, hint or the existing selector as authorization to
export private dependencies.

## Read saved communication without creating memory

Polling `receive` still obtains a bounded network page, durably saves accepted
transport content and submits signed storage acknowledgements. Returned text is
a preview. A separate selector on the same operation reads the complete local
message or transfer note:

```json
{"op":"receive","message_id":"RETURNED_MESSAGE_ID","offset":0}
```

This returns one saved-message result, rather than a newly polled message list:

- `text`: at most 1,024 UTF-8 bytes, ending on a Unicode code-point boundary;
- `offset`: starting position in Unicode code points;
- `next_offset`: the next code-point position, or null when there is no suffix;
- `total_characters`: the complete text/note length in Unicode code points;
- `text_partial`: true whenever the fragment is not the whole text;
- `network_accessed:false`, together with the stored sender, content kind and
  delivery result.

Repeat with `next_offset` until null. A final page can still have
`text_partial:true` because it omits the prefix; use `next_offset` to determine
completion. These offsets are neither UTF-8 byte positions nor JavaScript
UTF-16 code units. Unicode combining characters are separate code points; no
grapheme-cluster segmentation is promised. The ordinary native operation's
8 KiB serialized result budget still applies.

The local selector cannot include polling `limit`. An `offset` without
`message_id` is invalid; negative, fractional or out-of-range offsets fail.
`NetworkClient.read_message(message_id, offset)` and TypeScript
`NetworkPeer.readMessage(messageId, offset)` implement the same local behavior.
The read makes no network request and does not refresh remote authorization,
execute received text or add a Vault record. It reads previously stored local
plaintext subject to the host's existing access boundary.

## Old preview state is not silently upgraded

This batch prioritizes the explicit content model over compatibility with the
earlier preview payload. Content/v1 bodies are rejected with
`network_unsupported_content_schema`, including when encountered in persisted
outbox/inbox bodies or full endpoint recovery data. Unsupported incoming bodies
are retained through the bounded rejection path without importing memory or
issuing a successful `validated_saved` acknowledgement. There is no automatic
v1-to-v2 conversion, resealing, fallback, deletion or migration shim.

Do not run the development version against the only copy of real old transport
state. Preserve original directories, the original runtime, private configuration
and encrypted backups. Use isolated synthetic state for new-content testing.
Upgrade design and validation come later; disabling a legacy body does not
authorize deleting its data. Supported v2 retries reuse original request IDs and
frozen ciphertext.

A chat-only endpoint can have transport state without ever creating its source
Vault. Full endpoint backup uses a temporary empty snapshot in the existing
Vault format for that case, leaves the absent source Vault absent, and restores
zero memory records. It does not invent a record just to make backup succeed.

This change does not alter canonical memory record IDs, bytes, existing Ed25519
record proofs, the local Memory Vault, or the separate personal Vault backup
format. It does not introduce a second memory database. Messages may outlive an
agent session in the transport store, but that alone does not promote them into
long-term memory or prevent future transport retention policies.

## Existing synthetic trial

The trial keeps its existing synthetic nonce text format. Its reference peer
now explicitly remembers the synthetic reply and sends its memory ID. The
trial reads exactly one selected original record from the already validated
local transfer bundle; it checks that record's sender signature and local
canonical bytes before exact-ID inspection. Matching note or dependency text
cannot choose a record, and multiple selected records are rejected.

This does not enroll member keys into Vault trust. The result marks
`local_recall.inspection_only:true` and `trusted_context_asserted:false`.
A record may remain quarantined; exact-ID byte/proof inspection is not a claim
that ordinary trusted recall admitted it. No real trial service is configured
or operated by this change.

The previously existing real-crypto trial journey initially failed after
message separation (`trial_reference_reply_timeout`, 5.419 seconds). After
the minimal adaptation, `tests.test_network_trial` and
`tests.test_network_trial_coordinator` passed **12 tests in 1.244 seconds**.
Four new cases cover plain chat not triggering a trial, dependency-text
matching not substituting for the selected record, ambiguous selections and
revocation without restored trust or changed evidence bytes.

## Validation scope

This candidate selectively reuses the previous local prototype, starting from
the reviewed Experience corrections. It does not merge that prototype as a
whole. The bounded local inbox reader is retained so requests and notes can be
read completely without promoting them into memories. The larger trial/v2
control protocol is excluded; the existing synthetic trial uses a minimal adjustment to explicit
original-record transfer without a second control protocol.

The source starts from main `f3693c1` (same tree as the independently reviewed
`0afd7cb` Experience repair). The old parked prototype is not a merge parent.
The two Experience repairs remain part of the regression gates.

A direct synthetic comparison used the existing two-ASGI-relay fixture and the
same ordinary send/receive request, without an explicit remember operation:

| State | Reviewed pre-change source | This candidate |
| --- | --- | --- |
| Memory counts before, sender/recipient | `[0, 0]` | `[0, 0]` |
| Memory counts after, sender/recipient | `[1, 1]` | `[0, 0]` |
| Accepted messages | `1` | `1` |
| Content kind | No explicit discriminator | `message` |
| Receive errors | `[]` | `[]` |

This is local handler-level evidence with real encryption, not a cross-host or
real-model experiment. It establishes the intended behavior change, not a
performance claim.

Initial selected regression commands used Python 3.12.0b4, Node 22.19.0 and the
existing hash-locked JOSE dependency. Set `MEMORY_VAULT_NODE` and
`MEMORY_VAULT_JOSE_MODULE` to those installed runtimes when the harness does not
automatically discover them.

```sh
python -m unittest \
  tests.test_network_agent tests.test_network_client tests.test_network_recovery \
  tests.test_network_packaging tests.test_network_typescript_agent \
  tests.test_network_typescript_agent_network tests.test_network_typescript_peer \
  tests.test_network_typescript_peer_race tests.test_experience_origin_identity \
  tests.test_experience_origin_typescript tests.test_experience_int64 \
  tests.test_experience_http_int64 -q

python -m unittest tests.test_network_worker tests.test_network_client_race \
  tests.test_network_storage_receipts tests.test_network_ranking_v2 \
  tests.test_cross_author_state -q
```

Actual results: **78 passed in 58.118 seconds**, then **33 passed in 23.028
seconds**; no skips in either run. These results are scoped to the commands,
not the full repository suite. The message-specific run passed **28 tests in 25.816 seconds, no skips**,
including nonempty Experience/index snapshots, explicit hearsay attribution
and rejected messages leaving no inbox or success acknowledgements. The
final message/trial/packaging combination passed **45 tests in 27.044 seconds,
no skips**, using the command below; this includes the focused 28-message and
12-trial results, so those are not extra tests to add again. The previously disclosed U+1E030 baseline
normalization difference is not fixed by this transport change.

No real-model, cross-host, uninterrupted-duration or scale result is implied.
No dependencies, private plugins or real deployments are installed or migrated
by this development batch.

Final candidate message and trial validation:

```sh
PYTHONDONTWRITEBYTECODE=1 python -m unittest \
  tests.test_network_message_semantics tests.test_network_message_typescript \
  tests.test_network_trial tests.test_network_trial_coordinator \
  tests.test_network_trial_packaging -q
```

The actual final unittest summary (environment-specific warning paths omitted):

```text
Ran 45 tests in 27.044s

OK
```

All three selected groups (78, 33 and 45 tests) completed successfully. The
focused 28-message and 12-trial runs are subsets of the final group, not
additional independent counts. The validation remains bounded to this feature
and its direct regressions; independent review of this new source is pending.
