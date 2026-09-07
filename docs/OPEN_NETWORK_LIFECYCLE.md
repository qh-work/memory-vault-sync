# Contact discovery and ciphertext custody lifecycle

Status: **proposed architecture and acceptance targets, not implemented or measured capability**. This document completes the lifecycle described in [OPEN_NETWORK_ARCHITECTURE.md](OPEN_NETWORK_ARCHITECTURE.md); experiments belong to [OPEN_NETWORK_ACCEPTANCE.md](OPEN_NETWORK_ACCEPTANCE.md). It does not change the capabilities of the released private relay pool. Wire schemas and exact error names remain subject to protocol review.

## The failure this design must prevent

Durable bytes can become unusable when their location disappears. Three ciphertext copies do not help a new authorized reader if every directory entry expires, the only publisher stops, or migration removes the old node before advertising its replacement. Conversely, a discoverable location is not proof that the object is stored, that the reader may retrieve it, or that a model has understood it.

The end-to-end obligation is to retain authorized, discoverable access for an explicit period. It is not an unconditional promise against all copies being destroyed, permissions expiring, keys being lost, or permanent network isolation. No mailbox or custody lifecycle owns or deletes a long-term Memory record.

## Separate records, authority and clocks

| Record | Who signs and may change it | Meaning of expiry |
| --- | --- | --- |
| Owner contact | The identity owner binds identity/encryption keys, an owner revision, permitted contact methods and an opaque mailbox-index key. | The signed contact is no longer current. Copying it cannot extend its validity or increase its owner revision. |
| Directory storage lease | An index provider commits finite storage for exact signed record bytes/digest and an authorized namespace. | That index replica may expire. Renewing this lease does not renew the owner's contact or create permission. |
| Object provider fact | A custodian binds its own node key/incarnation, opaque object or segment key, live custody lease, retrieval permission, provider-local revision and expiry. It includes the required publication delegation. | The advertised location no longer proves usable custody after its validity window. Another provider's valid fact is unaffected. |

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

## Migration and repair state machine

Persist the operation ID, ciphertext digest/size, source and destination keys/incarnations, policy/delegation digest, finite ticket/reservation, target lease, progress, receipts and publication evidence. Restart resumes the same operation. A different destination or authorization is a new bound operation; it cannot spend an old reservation twice. Network I/O stays outside local writer locks.

| State | Actor and work | Evidence required to progress |
| --- | --- | --- |
| PREPARE | A live authorized custodian or draining source selects a bounded candidate. Target validates copy/publication/retrieval scope and reserves quota. | Durable target-bound reservation and ticket. No replica-success claim; source obligations remain. |
| COPY | Source streams original ciphertext in bounded chunks; target checks size, digest and original proof without decryption. | Persisted staged progress. Retries do not double-charge; staged/orphan bytes remain charged. The destination need not be empty. |
| COMMIT | Target rechecks the live reservation, incarnation and authorization; flushes and publishes bytes, then commits custody/accounting and the signed result. | A stable exact-object storage receipt. State is **committed_unadvertised**, not migration completion or permission to delete the source. |
| ADVERTISE | Target or another delegated custodian publishes the provider fact under the preexisting opaque key to leased index replicas. | Directory acceptance, independent lookup readback, correct target/lease binding and a current authorized possession read. Verify the recipient's retrieval chain; do not fabricate an offline recipient's actual retrieval. |
| USABLE | The operation observes the required live custody/index policy and publication evidence. | The target counts as a discoverable replacement under that observed view and time. The real receiver still must decrypt, verify and save before signing `validated_saved`. |
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

Count route availability, locator availability, ciphertext availability, retrieval authority and decryption keys separately. Shared operators, DNS, accounts, storage and power can correlate them. Three signed receipts do not prove three independent physical domains. Record each domain claim and its evidence: synthetic label, self-asserted, operator-attested or independently checked. Several processes on one laptop remain one physical fault domain.

Failure-domain placement is an explicit design choice in [Ceph's CRUSH documentation](https://docs.ceph.com/en/latest/rados/operations/crush-map/#crush-rules). That reference does not establish independence for Memory Vault nodes or supply field failure rates.

```text
exposure window W = detection + scheduling + copy + commit + advertise/readback
copy time >= missing bytes / effective repair bandwidth
approximate replacement demand = independent copy-loss rate * replicas * retained bytes
stable repair requires service above loss/migration demand, plus spare capacity
```

An independence-only model with per-copy loss probability `p` during a specified window gives `p^r` for all `r` copies lost. After one is already lost, the remaining exposure is `p^(r-1)` under the same assumptions. A common-loss event with probability `c` changes a simple mixture to `c + (1-c)*p^r`. These are illustrative models, not annual durability estimates or measured service guarantees.

The proposed fixture assumptions below are test configuration, not global limits or deployment defaults. All targets remain **unrun**.

| Parameter | Proposed controlled fixture |
| --- | --- |
| Data/index replicas | `r_data=r_index=3`, recorded independently |
| Provider-advertisement/index-lease TTL | 180 seconds; no longer than relevant live authority |
| Republication | Every 30 seconds with bounded ±20% jitter; failure-triggered jobs also allowed |
| Owner contact / independent repair-publication delegation | Each valid for 3,600 seconds; copying cannot renew signed validity |
| Object custody | 600 seconds; at least 1,200 seconds in the 600-second churn campaign |
| Detection / repair scheduling | At most 20 / 10 seconds in scripted healthy-budget cases |
| Directory rediscovery target | **60 seconds**: detection ≤20, scheduling ≤10, publication plus independent readback ≤30 |
| Full object repair target | **90 seconds**: detection ≤20, scheduling ≤10, 1 MiB at reserved effective ≥256 KiB/s, commit ≤10, publication/readback ≤40 |

The 60-second target concerns loss of directory replicas or an authorized address update when the data, delegation and a routing path remain available. It does not measure copying the object. The 90-second target ends at USABLE, not merely COMMIT. Measure all terms and failures; a scheduler or bandwidth assumption that is not met must be reported. These are conditional recovery objectives, not hard-real-time or arbitrary-Internet promises.

## Required demonstrations

1. **Directory survives owner exit:** eight owned synthetic HTTP nodes, separate index/data roles where feasible; stop the owner and original bootstrap, then remove two initial index replicas. A delegated survivor republishes. Clear reader caches and resolve through independent paths within the directory target. Test both identity lookup through the still-valid owner contact and already-authorized opaque object-key lookup.
2. **Expiry is real:** stop all delegated republishers or expire their authority. After the relevant horizon, return expired/incomplete instead of forging a current contact. Separately validate any still-authorized known object path and unchanged local Memory access.
3. **Sender-offline repair is actually usable:** stop the sender, lose a ciphertext replica, and repair a 1 MiB object to a nonempty node. After USABLE, stop every original data holder and clear reader caches. The authorized receiver must discover the replacement, retrieve exact bytes and validate original Memory IDs/signatures. No new recipient or mailbox permission is inferred from copying.
4. **Crash every transition:** inject failures around reservation, copying, fsync/publication, metadata commit, receipt delivery, index acceptance/readback and retirement. Another pre-authorized actor resumes. No COMMIT-only repair becomes a safe early exit; quota remains conservative through cleanup.
5. **Partition and correlated loss:** merge concurrent valid provider facts without losing the only accessible location. Remove a logical domain containing both index and data replicas. Surviving policy/path conditions must determine the result; three same-domain receipts cannot claim three-domain health. Only the test oracle may label known destruction of all valid copies as irrecoverable.
6. **Churn exceeds or fits repair capacity:** fixed seeds 17/29/43, 100 then 1,000 logical providers; ten 30-second rounds each losing 1%, then ten recovery rounds. Keep original objects retained for ≥1,200 seconds to prevent vacuous success through expiry. With spare capacity and repair service ≥2× measured offered repair demand, recoverable original objects must regain three usable data/index commitments. Report all oracle-confirmed permanent losses separately. Provision below demand as a negative case: expose backlog/under-replication or backpressure, never false healthy status.
7. **Authority and GC races:** wrong destination/incarnation, replayed ticket, missing retrieval scope, conflicting revision, expired lease, index overload and GC versus renewal must preserve quotas, permissions and original Memory. Index facts may advertise only authorized usable locations.

Logical topology, simulated bytes, actual HTTP processes, physical fault domains and real AI behavior remain separate evidence classes. No new experiment has been run by this document. Failure requires a recorded design/assumption correction or an explicitly justified target change; it cannot be hidden by changing seeds, counting COMMIT as USABLE or dropping expired/lost objects from the denominator.
