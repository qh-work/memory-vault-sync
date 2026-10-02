> This records the batch3 Python measurement. The native completion and existing
> full native replica recovery and fresh alpha.0.39 comparison are documented in
> [CAPACITY_HANDOFF.md](CAPACITY_HANDOFF.md).

# Approved resource distribution for real message delivery

The Python Agent `send/receive` path now distributes **new** messages over
independently approved, currently valid contact resource leases. Selection and
ciphertext/session freezing happen in one SQLite writer transaction. All frozen
outbox records, including unfinished uploads, count against their exact signed
resource lease. Among slots with enough item/byte capacity, selection uses relative
reserved item count, then byte usage and a stable scope tie-breaker. The server
still independently enforces its live policy, grant, resource budget, possession
proof and per-node capacity. Aliases of one lease cannot multiply its quota.

The pool includes only local, actual recipient-approved decisions for the same
sender and recipient encryption identities. Discovering a node does not authorize
sending it messages. The recipient must explicitly obtain that node's resource,
receive the sender's first-contact request and approve its finite grant. No real
user permission or signing/encryption identity is created by the dispatch change.
The synthetic fixture makes those separate owner decisions using existing protocol
operations. New grants are learned by the ordinary explicit result workflow.

Existing frozen messages keep their immutable envelope, node/epoch, exact authority
and request/message IDs on retries, interruption or revocation. The implementation
does not silently migrate a frozen send after ambiguous remote commit. A known
revoked old node can be excluded for a **new** send when another independent valid
grant exists; the old frozen send is still bound to its original node. Existing
repair callers retain their former first-valid-session behavior.

Receive polling rotates approved sessions with one persisted bounded cursor.
Per-resource sequence cursors, signature and possession checks, receipt identity,
content validation, explicit Memory selection/import and author trust stay intact.
The same Agent API reads the saved message and recalls imported Memory. Approval
does not infer author trust: the fixture separately and explicitly trusts A's
Memory author key in B's test TrustStore. No model calls participate.

## Fixed-load complete-chain comparison

Mac mini / Apple M1 / eight CPU cores / 8 GiB / macOS 27.2. Python 3.12.0b4,
SQLite 3.42.0, cryptography 50.0.1. Two independent loopback HTTP processes share
one physical computer/SSD and one source group. This is not proof of independent
failure domains or hardware scalability.

Both runs offer **48 messages at 2/s for 24 seconds**, without dropping or pausing
scheduled offers. There is one bounded pipeline worker; measured latency starts
at the intended offer time, so driver queueing and join delays are included. Each
message selects a different pre-created signed Memory observation. Local source
Memory creation is outside the offer window; export, encryption, remote storage,
decryption/validation, recipient Memory import, signed saved receipt, message read
and Memory recall are inside the measured chain. Success requires every one of
those stages, not just a server accepting ciphertext.

R0 initially has a separately approved lease for 24 items and 2 MiB. R1 starts at
second 6, joins using R0 and receives another explicitly approved lease for exactly
24 items and 2 MiB. A and B only have R0 in their initial network configuration.
The observer never assigns individual messages to nodes. Offers continue while
the new resource becomes usable. Both runs use the same fixture, timing, payload
shape, limits and protocol; synthetic key material is newly generated per run.
Baseline is preserved batch2 source with the original first-session selection.
After is the measured final dispatch implementation.

| Whole 24-second offer window, including drain | Before | After |
| --- | ---: | ---: |
| Offered messages | 48 | 48 |
| Complete verified chains | 40 | 48 |
| Success rate | 83.33% | 100.00% |
| Complete chains/s | 1.667 | 2.000 |
| Successful p95, ms | 398.24 | 406.25 |
| Successful p99, ms | 400.94 | 417.96 |
| All outcomes p95, ms | 388.23 | 406.25 |
| All outcomes p99, ms | 400.94 | 417.96 |
| Offer queue lag p99, ms | 10.34 | 10.16 |
| Recipient saved inbox + sent receipt | 40 | 48 |
| Imported and recalled distinct Memories | 40 | 48 |

Elapsed including drain: 24.001678s before, 24.003349s after. R1 approval was usable at 7.953s / 7.946s.

| Node | Stored/read/saved-receipt chains before / after | Stored ciphertext bytes before / after | CPU seconds before / after | Peak HTTP requests/s before / after |
| --- | ---: | ---: | ---: | ---: |
| 0 | 16 / 24 | 113234 / 169866 | 2.199 / 2.785 | 32 / 33 |
| 1 | 24 / 24 | 169896 / 169896 | 2.960 / 2.897 | 26 / 26 |

Before has eight `open_delivery_quota` failures: the newest first session fills R1's
24-item grant while eight R0 slots remain unused. After uses all 24+24 individually
approved slots, and all 48 chains complete. The additional storage/receipt/read work
on R0 is visible in node counters and actual rows; R1 also stores 24 complete
messages. This proves finite authorized storage capacity is usable across nodes
with automatic assignment. It does **not** measure higher CPU or SQLite maximum
throughput. There are zero HTTP admission/queue refusals in either delivery run,
and observed peak traffic is below the unchanged 64/s per-source cap.

Tail latency increases slightly. Before's successful-only percentiles exclude its
eight failed messages; all-outcome percentiles and every stage failure are retained.
This result describes all 48 offers, including joining; it is not a best tail window.
The new node's first-contact setup has two `contact_unavailable` attempts before a
successful third attempt in each run. These are visible in setup_attempts and wire
counts. Fixture retries are at most six, 0.5 seconds apart, use the same logical
request ID, and do not auto-approve anything. They are not hidden successful message
chains. The eight-message pilot had one capacity failure before its second resource
was approved; it is excluded from the selected capacity comparison.

## Interpreting the prior routing result and reducing discovery failures

The prior 80/s public-query workload exceeded one node's 64/s same-source HTTP
admission allowance. Distributing queries among node-level rate gates improved
admission, not proven compute/storage throughput. Those guards remain per-node;
there is no invented network-wide identity rate service. Routing/source bounds and
the lookup/application request and byte budgets were not increased. Message grants
remain independently node/epoch bound, and their finite quotas are never multiplied
by routing to another node. A retargeted, freshly signed sender request still gets
an exact signed `contact_wrong_node` denial and no upload challenge/storage.

The routing API consumed a five-second probe delay even when a reply had no new
neighbor. It now consumes the delay only for an actual eligible challenge, with the
same maximum of one new proof per five seconds, at most three find attempts and the
same shared finite lookup budget. It does not add an unbounded retry queue.

| Full public-query run: 1920 offers, 80/s, 24s, join at 6s | Batch2 | Final fix |
| --- | ---: | ---: |
| Successful queries | 1766 | 1828 |
| Failures | 154 | 92 |
| Success rate | 91.98% | 95.21% |
| Successful p95, ms | 29.76 | 30.04 |
| Successful p99, ms | 44.91 | 37.24 |

First useful new-peer offer times from window start:

| Joining peer | Batch2, seconds | Final, seconds |
| --- | ---: | ---: |
| R1 | 15.088 | 6.112 |
| R2 | 10.038 | 11.125 |

The remaining 92 failures are explicit node0 HTTP admission refusals before enough
proven peers are available. A single allowed 64/s entry cannot complete a sustained
80/s offer without deferral or rejection. The fix reduces unnecessary convergence
delay; it does not hide errors, relax rate gates or claim that all startup offers
succeed. A finite caller retry/admission policy would need a separately measured
latency and request budget; it is not added to disguise overload here.

## Verification, delivery and remaining scope

The final-code combined regression run passed all 51 distinct cases (225.143s),
including Python/native contact state interoperability, existing mailbox HTTP
flows, delivery, consent, revocation, quotas, saved receipts and repair
compatibility. Focused intermediate logs are also preserved. The final run covers
actual HTTP, late independent approval, all-chain Memory saving/recall, receive
fairness, atomic concurrent freezing, duplicate aliases, capacity refusal, policy
and known node revocation, immutable retries, and foreign-node grant rejection. The final measured protocol
runtime hashes match the delivered code. The benchmark's added finite watchdog
caps the offer window plus 30s drain and stops only its disposable child processes.
That watchdog branch was not triggered in measured runs.

```sh
python -m unittest tests.test_open_delivery_distribution tests.test_open_delivery_http tests.test_open_repair_provision tests.test_open_neighbors tests.test_open_contact_state -v
python scripts/benchmark_open_delivery.py --messages 48 --rate 2 --join-after 12 --output after.json
python scripts/benchmark_open_neighbors.py --rate 80 --seconds 24 --join-after 6 --output discovery-after.json
```

The bundle plus cumulative patch gives the complete source without fetching Git.
All selected per-offer traces, setup failures, RPC/blob counts, stored bytes,
receipts, resource leases, CPU/RSS and source hashes are in delivery-evidence/.
Earlier two batches remain archived in this same Library artifact/version history.

This implementation covers the Python common Agent direct delivery carrier. Native
TypeScript selection/receive fairness was unchanged in that batch3 measurement;
the completion batch aligns it with Python and records its own full fixed-load run. It does not move an
already frozen message to a replica, dynamically copy all stored Memory, prove a
multi-host compute/storage capacity increase, or demonstrate thousand-agent scale.
Independent hosts/SSDs with owner-operated HTTPS are needed for WAN and resource
scaling validation, not for the local implementation delivered here. Real-model
conversation/semantic reuse remains untested; no paid API was called. No persistent
real credential, new user grant, trust change, push, merge or deployment occurred.
Actual deployment/new real grants or credential setup need user authorization.
The thread's gpt-6.1-sol/high setting was accepted earlier; the runtime does not
expose actual inference model metadata for independent confirmation.
