# Authorized relay pool and automatic failover

Development target: **0.27.0-alpha.1**. This is a bounded private-network
feature, not the previous 24-hour endurance gate, thousand-agent acceptance,
open P2P or an unlimited-capacity claim. Publication and actual test results
must be checked separately.

## Different entry points, one permitted pool

An endpoint previously contacted only its one or two configured relay URLs.
The issuer could publish more signed nodes, but the endpoint would not discover
and use their addresses. Two endpoints with disjoint relay lists had no shared
mailbox or automatic forwarding path.

The optional local network-config field below permits using a bounded common
set from the existing independently trusted issuer's signed node directory:

```json
"relay_pool": {"maximum_nodes": 4, "replica_target": 2}
```

This fragment belongs in the existing network configuration; it is not a new
Memory Record or a message command. `maximum_nodes` is an integer from two to
four. `replica_target` is one or two, no greater than `maximum_nodes`.
Booleans, fractions, extra fields and out-of-range values are rejected.
Python setup/restore helpers accept `relay_pool`; native TypeScript setup uses
`relayPool` to write the same field. CLI `configure`, `keys-restore` and
endpoint `restore` accept `--relay-pool-maximum-nodes` together with
`--replica-target`; neither option alone establishes a valid pool policy.
Omitting `relay_pool` keeps the original fixed-address behavior: merely
receiving a signed directory must not silently authorize new connections.

The configured relay URLs remain bootstrap addresses. In pool mode, eligible
nodes are active entries with `node.status` scope, selected in signing-key-ID
order from the verified directory, bounded by `maximum_nodes`. Selection does
not depend on which bootstrap URL the endpoint originally knew. Endpoints
using the same trusted directory and pool limit can find a common set.

The candidate set is frozen for each operation. Existing current-status,
node-challenge, key, URL and storage-epoch checks still apply during actual
communication. Forged, stale, rolled-back, revoked or mismatched node claims
do not become fallback destinations. Failed fresh control-state verification
does not authorize using an old cached directory. No address scanning or
redirect following is introduced.

## Discovery is not admission

`connect` with a valid invitation performs the existing dual-key join ceremony
at each candidate. A signed directory does not populate a relay's local
membership table and does not grant a mailbox, memory visibility or decryption
keys. Both communicating endpoints must actually be admitted on a relay used
for their exchange.

`connect` without an invitation checks existing relay-local membership. An
expired invitation can only retry the original consumed proof at its original
node incarnation; it cannot enroll on a newly discovered relay. Obtain new
authorized admission when needed. Node migration keeps its existing separate
operator authorization and is not turned into automatic background copying.

The six native operations stay `connect`, `remember`, `recall`, `discover`,
`send` and `receive`. Discovery exposes bounded node IDs/counts and pool
metadata, not a new permission or a claim that every candidate is reachable.
The authority still has one independently configured URL. This feature removes
dependence on fixed relay entries, **not the authority's availability limit**.

## Replica targets, retries and offline delivery

The pool size and requested number of storage confirmations are separate.
With four candidates and a target of two, sending tries other permitted nodes
when an earlier node fails; two valid storage confirmations satisfy that
target. Results distinguish `replica_target`, candidates and `stored_nodes`.
They do not claim that all candidates saved the message.

Receivers poll the bounded pool, including nodes outside a sender's first
successful pair. Polling, explicit acknowledgements, node-specific cursors and
deduplication reuse the existing transport database. This is a common-pool
design, not global mailbox routing or relay-to-relay forwarding.

Queued retries reuse the original persisted ciphertext, message ID and record
proofs. A timeout does not erase a historical storage receipt; a receipt also
does not certify current reachability, physical failure independence or
indefinite retention. Only eligible current-pool receipts count toward the
pool target, with the existing node-incarnation checks. Receipt counts remain
bounded, and existing row-byte, total-byte, message and retry limits remain.
No full queue is reported as successfully saved.

`pump` retains its explicit cooperative time/message budget and fair node
attempts. It starts no daemon or other agent. Authority unavailability, expired
control state or missing admission can still prevent network progress. Local
`remember`, `recall`, and inspection of accepted batches do not require or
trigger pool discovery.

## Data, recovery and rollback

No new memory database, identity, network envelope, content profile, Hint
profile, canonical record format or origin-signature format is introduced.
Candidate connectivity and delivery accounting belong to transport control.
Chat still does not automatically become long-term memory; sharing does not
grant independent local trust or execution permissions.

Preserve existing backups and runtime before opting in. Restoring a backup
does not automatically grant dynamic-connectivity permission; the caller must
choose the new local policy explicitly and obtain current independent control
state. Previously cancelled/expired Hint sessions cannot be revived by pool
discovery. Historical records and sources remain readable locally.

To stop dynamic contacts, remove the opt-in from a stopped endpoint and use
the existing fixed configuration. This is not an automatic downgrade of a
newer transport backup: old clients may reject expanded receipt maps. Keep the
matching runtime or a pre-upgrade backup; do not delete or rewrite evidence to
force an older reader to accept it. No private installation is upgraded by
publishing this preview.

## Acceptance scope

The required demonstration uses a real local HTTP authority, three actual
relay processes, and Python/native-TypeScript endpoints with different single
bootstrap entries. Real invitations admit both endpoints to the common pool;
after an original entry stops, new messages and selected original memories,
acknowledgements, frozen retries and restart must continue without editing
endpoint relay configuration. Security cases cover directory/node rejection,
missing/expired admission, opt-out and budgets.

The new test methods are:

| Runtime | Case |
| --- | --- |
| Python | Different bootstrap entries, real joins, seed exit, chat and original memory delivery |
| Python | Authorized Hint selection and complete dependency batch after seed exit |
| Python | Frozen offline retry, slow-node budget, restart and deduplication |
| Python | Exact local configuration, candidate budget and fixed-address opt-out |
| Python | Discovery without admission; expired invite rejection; fresh invite with existing members |
| Python | Tampered/rolled-back directory, revoked node, wrong challenge and failed authority |
| Python | Four real historical receipts, rotation cursor, encrypted recovery and explicit opt-in |
| Python | Per-row/global receipt budget failure rolls back without claiming local confirmation |
| Native TypeScript | Different entry points, fresh invitation and both language directions after exit |
| Native TypeScript | Both directions of authorized Hint batch transfer and pure local batch recall |
| Native TypeScript | Frozen retry, process restart, fair budget and preserved receipts |
| Native TypeScript | Exact local config/setup and fixed-address contact boundary |

The fixed alpha.5 baseline `608d54578b9ce30f10fe450ad651f1cd8620a2e7`
was extracted into an isolated source snapshot. The first new positive test
failed with `network_invalid_config` after the real HTTP fixtures started
(one test, 2.329 seconds). That is expected missing-feature evidence, not a
failed service fixture.

Developer commands, using existing locked dependencies in an isolated synthetic
environment (no installation or real account access):

```sh
python3 -B -m unittest -v \
  tests.test_network_relay_pool \
  tests.test_network_relay_pool_typescript \
  tests.test_release_source_gate \
  tests.test_network_packaging \
  tests.test_network_trial_packaging \
  tests.test_memory_vault \
  tests.test_network_received_batch_recall \
  tests.test_network_received_batch_recall_typescript \
  tests.test_network_typescript_setup \
  tests.test_network_replica_repair
```

Use an existing Node runtime and the separately pinned JOSE dependency as
described in [TypeScript setup](NETWORK_TYPESCRIPT.md); skipped dependencies
are not successful coverage. The new Python eight-method run passed in
37.776 seconds; the final native TypeScript four-method run passed in 26.110
seconds. The 62 directly selected previous regressions also passed before the
last narrow pool-admission/receipt fixes; those earlier passes are not a final
frozen-source combined result. The final combined run of the exact command above passed **74 distinct methods
in 185.310 seconds** (tracking wrapper: 185.456 seconds), with zero failures,
errors, skips or expected failures. All tracked Python/TypeScript source and
test hashes matched before and after the run, and were rechecked before commit.
The runtime was Python 3.12.0b4, Node 22.19.0, joserfc 1.7.5, jose 6.2.10 and
cryptography 50.0.1. This is a targeted collection, not a whole-suite or scale
benchmark. Prior focused runs are not added again to the 74-method total.

Initial development attempts are not counted as final passes. Test fixture
corrections made online discovery explicit, guaranteed that malformed
signed-directory bytes actually reached the client, and avoided accidentally
collecting an imported test class. The unintended old-class run had one
`network_unavailable` error; it was retained, not silently counted as passing.
The pool's fresh-invitation/already-member result was corrected by performing
an actual refreshed signed membership poll, never by ignoring the error.

Only disposable synthetic memory and generated test identities were used.
These are local HTTP process-failure and encrypted-interchange checks, not
cross-machine, physical failure-domain or actual-model evidence. The
256-member/control limits, bounded queues, single authority, lack of open
P2P/group chat and lack of continuous replica repair remain future work.
