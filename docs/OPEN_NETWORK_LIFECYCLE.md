# Contact discovery and ciphertext custody lifecycle

Status: **proposed architecture and acceptance targets, not implemented or measured capability**. This document completes the lifecycle described in [OPEN_NETWORK_ARCHITECTURE.md](OPEN_NETWORK_ARCHITECTURE.md); experiments belong to [OPEN_NETWORK_ACCEPTANCE.md](OPEN_NETWORK_ACCEPTANCE.md). It does not change the capabilities of the released private relay pool. Wire schemas and exact error names remain subject to protocol review.

## The failure this design must prevent

Durable bytes can become unusable when their location disappears. Three ciphertext copies do not help a new authorized reader if every directory entry expires, the only publisher stops, or migration removes the old node before advertising its replacement. Conversely, a discoverable location is not proof that the object is stored, that the reader may retrieve it, or that a model has understood it.

The end-to-end obligation is to retain authorized, discoverable access for an explicit period. It is not an unconditional promise against all copies being destroyed, permissions expiring, keys being lost, or permanent network isolation. No mailbox or custody lifecycle owns or deletes a long-term Memory record.

Preserving an object at `K_m` does not preserve discovery by a recipient who has never learned `K_m`. The required starting point is the recipient's durable **pre-offline** state, captured before the new message exists. Mailbox enumeration links are retained transport evidence, not disposable caches. This revision addresses the design counterexample ARCH-01; implementation and experiments remain **NOT RUN**.

## Separate records, authority and clocks

| Record | Who signs and may change it | Meaning of expiry |
| --- | --- | --- |
| Owner contact | The identity owner binds identity/encryption keys, an owner revision, permitted contact methods and an opaque mailbox-index key. | The signed contact is no longer current. Copying it cannot extend its validity or increase its owner revision. |
| Directory storage lease | An index provider commits finite storage for exact signed record bytes/digest and an authorized namespace. | That index replica may expire. Renewing this lease does not renew the owner's contact or create permission. |
| Object provider fact | A custodian binds its own node key/incarnation, opaque object or segment key, live custody lease, retrieval permission, provider-local revision and expiry. It includes the required publication delegation. | The advertised location no longer proves usable custody after its validity window. Another provider's valid fact is unaffected. |
| Mailbox anchor policy | B signs the stable opaque mailbox anchor `K_B`, a finite epoch and bounded authorized writer/feed slots, recipient read keys, limits and maintenance delegation. | No new owner epoch, writer or permission may be invented. Existing obligations depend on explicit validity, not a cached contact TTL. |
| Admission entry and feed checkpoint | An authorized mailbox writer signs its own append evidence and cumulative checkpoint, binding the original sender's delivery attempt and B's grant. | Append authority cannot be renewed by copying. Accepted evidence remains readable/repairable for its separately authorized retention window. |
| Enumeration custody lease | A metadata custodian commits exact anchor/feed/page/entry evidence and finite read/repair obligations, independently of ciphertext custody. | A necessary enumeration link may become unavailable even if every ciphertext copy survives; report message discovery incomplete. |

The existing identity key is not an expiring directory cache entry. Object repair/publication delegations are independently owner-signed, finite and scoped; they must not accidentally inherit a short cache TTL or survive their own revocation/expiry. A custodian may update its own possession fact within this delegation and its accepted lease. It cannot sign a fresh owner contact, change recipients or grant a new mailbox operation.

For every advertised location:

```text
advertisement_until <= min(custody_until, retrieval_grant_until,
                           publication_delegation_until)
```

The serving directory lease must also be valid. Schedule republication early enough to cover lookup, reservation, publication, retry and clock uncertainty. Expiry is not reset merely because another node copied or observed the same signed bytes.

An offline owner therefore needs a previously authorized maintainer and resource budget if discovery must continue. When all such delegations expire or all maintainers disappear, report the resulting discovery/repair limitation. Do not manufacture renewed owner authority. Locally admitted Memory remains readable; an independently still-valid grant may permit retrieval from a known object location.

## Who keeps the directory alive

Maintain separate replica policies for directory records (`r_index`) and ciphertext (`r_data`). Both consume actual local leases and have independent failure and renewal work. One directory copy pointing to three data copies is not equivalent to three independently discoverable copies.

- The owner or an explicitly delegated publisher obtains bounded index candidates through the overlay and reserves index resources. No index provider stores a global contact roster.
- Custodians keep the limited signed anchors and delegation material needed to reconstruct their objects' provider facts. The only copy must not live in the original sender's process or a volatile cache.
- Accepted index obligations create persistent, budgeted maintenance jobs. Triggers include due time, failed read/possession checks, lease loss, address or incarnation change, an observed placement-neighborhood change and explicit drain.
- An index replica may copy exact authorized bytes within its scope. It cannot advance an owner's revision or signed expiry. A delegated custodian can republish its own provider facts without the owner's process running.
- Republication uses a fresh bounded placement lookup, not only the original index addresses. New eligible index providers must receive records when old ones disappear.
- Placement and metadata are paged and quota-limited. Maintenance cannot become a whole-network inventory or unbounded gossip queue.

A normal address change is a new signed contact revision from the same node with its persisted storage incarnation. Loss of persistent state requires a new incarnation and reauthorization. Resolve the signed node contact rather than editing an address inside old ciphertext or following unchecked redirects.

Use the stable opaque resource key already available to authorized readers. Publishing a repaired copy under an unrelated new key that nobody knows does not restore discovery. A successful directory PUT is insufficient: verify the new fact through independent lookup paths, not the publisher's local cache.

If all index replicas disappear but an authorized custodian and a reachable introduction survive, the custodian can republish the facts. If no permitted path or publisher delegation remains, return an explicit unavailable/expired/incomplete result. Neither a timeout nor an empty lookup proves that all ciphertext is lost.

Provider republication and expiry are established separate concerns in the [maintained DHT specification](https://github.com/libp2p/specs/blob/master/kad-dht/README.md#content-provider-advertisement-and-discovery). Its timings depend on churn and overhead; Memory Vault does not inherit that protocol, its constants or its measured guarantees.

## Authorization follows custody without changing the message

Keep the immutable end-to-end envelope/JWE separate from a signed delivery attempt and from custody metadata. The former binds the original message, content and encryption recipients. A new custodian receives exact ciphertext; it cannot alter associated data or add decryption recipients.

Before movement, the owner authorizes a finite repair/retrieval delegation for the object or bounded segment. It identifies the permitted recipient keys, operations, scope, expiry, delegation-depth bound and resource constraints. Repair spending uses destination-bound tickets or preallocated credit, not a reusable global spending token.

During PREPARE, the target verifies the complete effective chain: owner authorization, any permitted custodian delegation, exact object/destination/incarnation binding, live retrieval scope, its own resource lease and current local policy. The original recipient proves possession of its authorized key on retrieval. Copying ciphertext alone never supplies retrieval authority.

If the chain cannot authorize the new destination without further owner action, repair remains blocked there. Sender-independent repair means a valid delegation was arranged beforehand; it does not mean any holder may invent a grant. A new mailbox delivery event needs the recipient's separate mailbox permission. Custody access cannot create a recipient admission ACK, trigger Memory export or execute message text.

## Cold mailbox discovery is part of custody

Freeze B's local identity, decryption keys, `K_B`, owner epoch/checkpoint and existing read authority **before** A creates message `m`. B has neither `K_m`, a new page/segment ID, a future writer checkpoint nor a replacement node address. A successful return must acquire each new fact through the protocol:

```text
pre-offline K_B + read authority
  -> owner-signed epoch policy and its finite writer/feed anchors
  -> writer-signed cumulative checkpoint and paged range index
  -> original immutable admission entry (attempt + mailbox permission evidence)
  -> stable opaque object key K_m
  -> current authorized provider facts -> original ciphertext
```

### Finite anchors and append responsibility

B authorizes a bounded set of writer/incarnation slots for one offline epoch. Each slot has a stable opaque feed key, a finite append/byte budget, accepted-retention deadline and explicit metadata read/repair/publication delegation. The signed anchor map fits the local epoch policy limit; it contains **slots, not all messages**, and is retained under `K_B` by leased metadata custodians. Independent slots can accept concurrently. A new writer slot or epoch requires B's authorization and resources; a custodian cannot install itself as an append writer just because it repaired bytes. Multiple independent mailbox slots avoid a sole mailbox writer requirement; exhausting or losing all authorized writers can stop new acceptance without invalidating retained reads. These are recipient-local resource limits, not a network population cap.

Within its slot a writer serializes its own admissions with a persistent sequence. It checks the complete sender attempt, B's permission, current revocation and resource usage before appending. An immutable signed **admission entry** binds the profile, anchor/epoch/slot/incarnation, sequence, original attempt and envelope digests, stable object key, object size/digest and accepted retention. It carries the original sender signature and recipient grant evidence needed for independent checking. It is evidence of that original node's authorized acceptance, never B's `validated_saved` and never a new Memory record. Same attempt/message retries are idempotent within their bound scope; parallel valid attempts in different slots remain traceable and deduplicate by the immutable message identity at the receiver.

The writer's signed cumulative checkpoint commits the accepted contiguous sequence range, sealed page count, exact active-tail hash and an authenticated range-index root. Pages have fixed maximum bytes/entries; a tail update creates new immutable bytes, never mutates an already committed page. A bounded-fanout hash-linked range index lets the checkpoint stay constant-size without embedding every page hash. Each node in that index is a separately retained metadata object. Repeated delivery cannot allocate a new sequence or enlarge the range; after a writer loses its durable sequence/revocation ledger, it needs a new B-authorized incarnation, not a reset counter.

The writer publishes each committed checkpoint at the **same stable feed key**. Authorized maintainers can republish its exact bytes and reconstruct the relevant index paths without the writer or sender running. Every accepted message retains a bounded path capsule: exact owner anchor/slot delegation, original admission proof, signed checkpoint, authenticated range path/page and object/retrieval references. The capsule's size includes the index depth and all required proof bytes; finite admission limits can refuse an oversized capsule. It is persisted in the existing transport store and covered by custody, not placed in another experience database.

New checkpoints extend the previously committed range. A maintainer accepting a new head verifies the append consistency proof against its persisted checkpoint before advancing it; a cold reader verifies the original writer authorization and the returned range evidence. Copying an older capsule does not lower a known head, and head advancement cannot release older page/path evidence still needed by any live admission. A higher head does not prove it is globally latest: partitions and a dishonest writer may conceal entries. Report the observed checkpoint, missing ranges, conflicts and freshness; never turn a missing feed or empty response into a claim that the mailbox has no messages. An old authentic empty prefix can only describe that observed prefix with unconfirmed freshness, not complete current receipt or global absence.

### Who may maintain each edge

| Edge / retained material | Authority to create it | Authority and obligation after the writer/sender stops |
| --- | --- | --- |
| `K_B` to epoch policy / finite feed keys | B's original signature, bound to its epoch and limits | Metadata custodians retain and republish exact policy bytes under their live scope. They cannot add slots, sign a new epoch or extend B's expiry. |
| Stable feed key to checkpoint / range index | The specific B-authorized writer/incarnation signs its own cumulative admissions | Delegated metadata custodians retain the signed checkpoint and index paths; publish exact heads and their own provider facts. No fresh append permission follows from repair. |
| Range page to admission / `K_m` | Writer's signed admission plus the bound original sender attempt and recipient permission | Copy immutable evidence and authenticated paths. A new node can prove an **old** delivery belonged to this feed; it cannot create a new delivery event, sender signature or recipient receipt. |
| `K_m` to provider / ciphertext | Each destination's scoped custody and retrieval chain | Destination signs only its own provider/lease fact, preserves ciphertext and grants access only to the original authorized reader. |

Append admission validity is checked at the original acceptance boundary and retained as signed evidence. Later copying does not re-execute that append or pretend its expired send permission is fresh. **Current** metadata/object read, repair, publication and local resource authority must still be valid. Revoking an append grant stops future appends, not automatically erases old history; a separate scoped read/custody revocation or expiry can make the network copy unavailable. Local Vault history is unaffected.

Public directory replies contain only opaque lookup keys, bounded provider facts and necessary routing/lease information. Full mailbox policies, writer lists, index edges, admission entries, recipient grants and object membership are fetched through authenticated, scoped metadata reads, not public enumeration. Provider-publication authorization is checked in the index provider's protected admission path; its private authorization chain is not echoed in public lookup responses. Seal private membership details to B with the existing mature JWE primitives; persist and copy exact ciphertext. Authorized metadata custodians can see the minimum opaque handles, dependency digests and signed maintenance scope needed to repair; they receive no message/Memory decryption keys. Node-visible opaque linkage and access timing are metadata leakage, not traffic anonymity. B decrypts and verifies the internal entry/attempt binding; server verification cannot replace it.

### Retention, merge and completion

Define an enumeration replica target `r_enum` separately from object `r_data` and directory-location `r_index`. One message's accepted discovery deadline cannot exceed the shortest accepted anchor, checkpoint/path/page, admission, object, read and maintenance obligation it depends on. Directory leases may be shorter only when authorized persistent renewal work is arranged. Metadata custodians retain exact reconstruction capsules and budgeted jobs; objects alone are not reconstruction sources. A repair-capable set must cover every necessary link with surviving evidence and valid authority. It need not require each node to hold the entire mailbox, but it must not rely on the original sender, one original writer or an uncharged volatile index.

Message admission first persists ciphertext, then atomically commits the local admission entry, updated immutable index/head, usage and pending replication/publication jobs after required files are durable. There is no cross-node atomic transaction claim. A crash before the admission commit leaves charged staged/orphan object bytes; recovery cannot infer a delivery event from those bytes alone. A crash after admission but before directory publication resumes the exact persisted evidence. A raw object receipt can precede full discovery, but a message-level custody result must name the committed enumeration evidence and actual replica/dependency status. Insufficient metadata reservation refuses a new full-message obligation rather than silently accepting ciphertext-only storage as offline-delivery success.

Independent slot histories merge by **set union of signed admission identities**, never one last-writer-wins mailbox head. Each honest writer's sequence orders only its own slot. Same-writer same-sequence or nonextending-head forks remain conflicts; do not discard one branch merely because its revision is higher. Conflict evidence/branches are quota bounded, with explicit conflict/backpressure on overflow, not a false complete result. Index pages are immutable representations of these admissions; compaction must preserve live entries and verifiable paths, and cannot let another slot's absent entry act as a deletion. Scoped expiry/revocation evidence and replay floors survive their dependent windows.

A read operates on the finite policy slots and observed authenticated checkpoint ranges. It fetches only required index paths/pages under one overall receive work budget, persists missing ranges/continuations and deduplicates stable entries. A gap does not falsely complete the range or prevent other already-known ranges/slots from making bounded progress. Catching up `N` messages requires corresponding work; it is not an O(1) operation. Retention permits pruning expired page ranges using writer-authorized compaction evidence, while retaining live paths; without such evidence report a gap instead of pretending an old cursor covered it. No global network scan or unbounded chain of newly invented owner manifests is required.

Keep three outcomes separate:

- `object_readable`: an authorized reader already knowing `K_m` can retrieve exact bytes. This says nothing about discovering an unseen message.
- `message_discoverable`: under the observed scoped policy/checkpoints, a path from B's pre-offline `K_B` reaches that message's valid original admission and a usable object provider. All required enumeration and data obligations meet the stated policy. It is a time-bound observation about that message, not global mailbox completeness or B's receipt.
- `validated_saved`: B actually follows the path, decrypts/verifies and saves under its independent admission rules, then signs its own receipt. A repairer cannot sign this for B.

A maintenance probe can verify exact signed linkage, scope and current possession without B's private keys, using a separately delegated read/probe scope that exposes only necessary opaque evidence. Label it a repairer's path observation, never actual B retrieval. The strong acceptance test must later resume the real B from the frozen state, with no injected future message/key/page/address, to demonstrate the entire receive chain. If any necessary link or its maintenance authority is absent, report `message_discovery_incomplete` even when object-level repair succeeded. Error names here remain proposed, not frozen wire fields.

## Migration and repair state machine

Persist the operation ID, ciphertext digest/size, source and destination keys/incarnations, policy/delegation digest, finite ticket/reservation, target lease, progress, receipts and publication evidence. For message repair include its original admission and the full required enumeration-path obligations; label an object-only operation explicitly. Restart resumes the same operation. A different destination or authorization is a new bound operation; it cannot spend an old reservation twice. Network I/O stays outside local writer locks.

| State | Actor and work | Evidence required to progress |
| --- | --- | --- |
| PREPARE | A live authorized custodian or draining source selects a bounded candidate. Target validates copy/publication/retrieval scope and reserves quota. | Durable target-bound reservation and ticket. No replica-success claim; source obligations remain. |
| COPY | Source streams original ciphertext in bounded chunks; target checks size, digest and original proof without decryption. | Persisted staged progress. Retries do not double-charge; staged/orphan bytes remain charged. The destination need not be empty. |
| COMMIT | Target rechecks the live reservation, incarnation and authorization; flushes and publishes bytes, then commits custody/accounting and the signed result. | A stable exact-object storage receipt. State is **committed_unadvertised**, not migration completion or permission to delete the source. |
| ADVERTISE | Target or another delegated custodian publishes provider facts and the required exact enumeration evidence under the preexisting opaque keys to leased index replicas. | Directory acceptance, independent lookup readback from the original anchor, correct target/lease binding and current authorized possession of every required link. Verify recipient read/retrieval chains; do not fabricate an offline recipient's actual retrieval. |
| USABLE | The operation observes the required live custody/enumeration/index policy and publication evidence. | Explicitly distinguish `object_readable` from `message_discoverable`. Only the latter counts toward message repair/availability. The real receiver still must decrypt, verify and save before signing `validated_saved`. |
| RETIRE | Source reaches permitted lease expiry or receives an explicit owner-authorized early release. | Recheck every local reference/pin/lease and retirement generation; tombstone, unlink and flush the directory, then release physical quota. A target receipt alone never releases a still-promised copy. |

Failure states remain pending, blocked authorization, blocked capacity, unreachable, expired or aborted. None becomes USABLE merely because a retry budget ends. Aborting cannot refund quota while staged bytes still exist or discard a source's retention promise.

At an honestly advertised lease expiry, the provider may reclaim unreferenced bytes even if a partition prevented successful migration. That remains an expired or failed custody obligation, never a successful lossless handoff. Requiring finite quotas while retaining every expired object until the network recovers would create an unbounded promise.

Directory-replica movement uses the same sequence for exact signed pointer bytes. Its discovery verification queries the stable key through the overlay. It must not depend on an infinite chain of global locator manifests: surviving authorized custodians retain bounded republication material as a reconstruction source.

## Crash, concurrency and partition behavior

| Injected failure or race | Required behavior |
| --- | --- |
| Crash after reservation, before copying | Reservation remains bounded, then resumes or expires safely. Source still serves; no storage success. |
| Crash after file publication, before metadata commit | Orphan bytes remain charged. Exact retry verifies/republishes and commits once. Bytes alone do not count as acknowledged custody. |
| Crash after COMMIT, before receipt delivery or advertising | Another already-authorized actor can recover the stable target result and finish publication from persisted metadata, without the sender's key/process. |
| Object durable, mailbox admission not committed | Retain charged orphan/staged bytes and replay only the original authorized append transaction. No entry is inferred from the object; no message-discoverable receipt. |
| Admission committed, enumeration replication/publication incomplete | Resume its exact checkpoint/path/admission jobs within retained authority. Report pending/degraded enumeration separately from object custody. |
| Directory accepts a fact but independent readback fails | Stay committed_unadvertised and retry within valid authority and budget. Do not claim receiver reachability or retire the source early. |
| All old index locations disappear during migration | Republish through another reachable introduction. No path/delegation means locator unavailable, not successful repair. |
| Two actors copy to the same target | Object/target-incarnation/lease/ticket dedup gives one physical charge and stable results; independent accepted references remain separately accounted. |
| Partitions select different authorized targets | Keep additive signed facts within preallocated credits. A scalar last-writer-wins provider set must not erase the only reachable valid location. |
| Partitions merge; facts arrive out of order | Merge by provider identity/incarnation/lease and provider-local revision. Preserve same-revision conflicts; apply scoped revocations/tombstones. Do not invent a global latest provider set. |
| GC races a pin/renewal or another lease expiry | Fence with a local generation check. Existing live obligations retain the bytes. A request after retirement requires a new durable put. |
| Restore loses current usage/revocation checkpoints | Old evidence cannot issue fresh spending/publication. Require current scoped state or new incarnation/reauthorization. |

A provider may withdraw only its own offered location unless given separate owner-scoped authority. Anti-entropy cannot resurrect expired/revoked facts. Keep security high-water marks and tombstones through their dependent replay horizons; ordinary cache eviction cannot erase them early.

Initial repair is additive. A later quorum-based early handoff needs a separately reviewed small-group membership-transition protocol. A handful of ad hoc signatures cannot prevent two partitions from both deleting their last copies.

GC removes only transport copies whose obligations permit it. Multiple independent leases on one deduplicated object must all be respected. Accepted Hint-batch history retains its immutable local admission capsule before transport compaction. None of these transitions rewrites canonical Memory bytes, IDs, origin signatures or Experience relations.

## Reliability assumptions and measurable targets

Count route availability, mailbox enumeration, locator availability, ciphertext availability, read/retrieval authority and decryption keys separately. Shared operators, DNS, accounts, storage and power can correlate them. Three signed receipts do not prove three independent physical domains. Record each domain claim and its evidence: synthetic label, self-asserted, operator-attested or independently checked. Several processes on one laptop remain one physical fault domain.

Failure-domain placement is an explicit design choice in [Ceph's CRUSH documentation](https://docs.ceph.com/en/latest/rados/operations/crush-map/#crush-rules). That reference does not establish independence for Memory Vault nodes or supply field failure rates.

```text
exposure window W = detection + scheduling + copy + commit + advertise/anchor-path readback
copy time >= (missing ciphertext + required enumeration bytes) / effective repair bandwidth
approximate replacement demand = independent copy-loss rate * replicas * retained bytes
stable repair requires service above loss/migration demand, plus spare capacity
```

An independence-only model with per-copy loss probability `p` during a specified window gives `p^r` for all `r` copies lost. After one is already lost, the remaining exposure is `p^(r-1)` under the same assumptions. A common-loss event with probability `c` changes a simple mixture to `c + (1-c)*p^r`. These are illustrative models, not annual durability estimates or measured service guarantees.

The proposed fixture assumptions below are test configuration, not global limits or deployment defaults. All targets remain **unrun**.

| Parameter | Proposed controlled fixture |
| --- | --- |
| Data/enumeration/index replicas | `r_data=r_enum=r_index=3`, recorded independently for each necessary link; shared physical storage is not charged twice |
| Provider-advertisement/index-lease TTL | 180 seconds; no longer than relevant live authority |
| Republication | Every 30 seconds with bounded ±20% jitter; failure-triggered jobs also allowed |
| Owner contact / independent repair-publication delegation | Each valid for 3,600 seconds; copying cannot renew signed validity |
| Object and necessary enumeration custody | 600 seconds; at least 1,200 seconds in the 600-second churn campaign, with valid read/repair scope through that horizon |
| Detection / repair scheduling | At most 20 / 10 seconds in scripted healthy-budget cases |
| Directory rediscovery target | **60 seconds total**: detection ≤20, scheduling ≤10, publication plus independent cold-anchor enumeration readback ≤30 |
| Full message repair target | **90 seconds total**: detection ≤20, scheduling ≤10, 1 MiB ciphertext plus ≤64 KiB of required enumeration/proof material at reserved aggregate effective ≥256 KiB/s, all commits ≤10, publication and cold-anchor path readback ≤40 |

The 60-second target concerns loss of directory replicas or an authorized address update when ciphertext, retained enumeration evidence, delegation and a routing path remain available. It includes republication of every needed location and a cold-anchor discovery walk, not a fixture-supplied object-key lookup; it does not measure copying the message. The 90-second fixture permits at most 64 KiB of necessary enumeration/proof material in addition to the 1 MiB ciphertext, giving copy ≤4.25 seconds under the reserved aggregate bandwidth and a total budget ≤84.25 seconds. All dependencies, index paths, retries and parallel jobs share that aggregate budget; it is not a fresh 90 seconds per object or metadata link. Larger histories/deeper indexes are separately measured on the N growth axis, not silently truncated to fit this fixture.

The message target ends at `message_discoverable`, not object-only USABLE or COMMIT. In the timed strong demo, B resumes from its frozen pre-message state at a **predeclared time relative to the fault**, and its actual cold-anchor enumeration/provider readback is included within the same 60/90-second total as applicable. Waiting for background success and then resetting the clock is forbidden. A repairer's path observation alone cannot pass that acceptance; B's subsequent full decryption/save has a separate `validated_saved` time. Measure enumeration/data repair, publication, readback and all failures individually and in total; unmet scheduler, chain-size or bandwidth assumptions must be reported. These are conditional recovery objectives, not hard-real-time or arbitrary-Internet promises.

## Required demonstrations

1. **Directory survives owner exit:** eight owned synthetic HTTP nodes, separate index/data roles where feasible; stop the owner and original bootstrap, then remove two initial index replicas. A delegated survivor republishes. Clear reader caches and resolve through independent paths within the directory target. Test both identity lookup through the still-valid owner contact and already-authorized opaque object-key lookup.
2. **Expiry is real:** stop all delegated republishers or expire their authority. After the relevant horizon, return expired/incomplete instead of forging a current contact. Separately validate any still-authorized known object path and unchanged local Memory access.
3. **Sender-offline repair is actually usable:** freeze B before `m` exists, retaining only its identity/keys, `K_B`, finite policy/checkpoint and preexisting authority. A later sends `m` and stops. Repair ciphertext **and its necessary enumeration chain** to nonempty replacement nodes, then stop every original mailbox writer, enumeration holder and data holder. B resumes only from the frozen state and discovers pages/admission/`K_m`/new providers through actual protocol responses; the test must not inject any future ID, key, checkpoint or address. Retrieve original bytes and verify Memory IDs/signatures. Separately show that a diagnostic known-`K_m` read can pass while missing enumeration, expired metadata repair authority or total association loss yields `message_discovery_incomplete`, never message-level success. No new recipient or mailbox permission is inferred from copying.
4. **Crash every transition:** inject failures around reservation, copying, fsync/publication, metadata commit, receipt delivery, index acceptance/readback and retirement. Another pre-authorized actor resumes. No COMMIT-only repair becomes a safe early exit; quota remains conservative through cleanup.
5. **Partition and correlated loss:** merge concurrent valid provider facts without losing the only accessible location. Remove a logical domain containing both index and data replicas. Surviving policy/path conditions must determine the result; three same-domain receipts cannot claim three-domain health. Only the test oracle may label known destruction of all valid copies as irrecoverable.
6. **Churn exceeds or fits repair capacity:** fixed seeds 17/29/43, 100 then 1,000 logical providers; ten 30-second rounds each losing 1%, then ten recovery rounds. Keep original objects and all necessary enumeration evidence retained for ≥1,200 seconds to prevent vacuous success through expiry. With spare capacity and repair service ≥2× measured offered data **and metadata** repair demand, recoverable original messages must regain three usable data/enumeration/index commitments and a path from their original mailbox anchors. Report all oracle-confirmed permanent losses separately, including lost associations with surviving ciphertext. Provision below demand as a negative case: expose backlog/under-replication or backpressure, never false healthy status.
7. **Authority and GC races:** wrong destination/incarnation, replayed ticket, missing retrieval scope, conflicting revision, expired lease, index overload and GC versus renewal must preserve quotas, permissions and original Memory. Index facts may advertise only authorized usable locations.

Logical topology, simulated bytes, actual HTTP processes, physical fault domains and real AI behavior remain separate evidence classes. No new experiment has been run by this document. Failure requires a recorded design/assumption correction or an explicitly justified target change; it cannot be hidden by changing seeds, counting COMMIT as USABLE or dropping expired/lost objects from the denominator.
