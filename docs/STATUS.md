# Memory Vault development status

Published **[v0.28.0-alpha.0.40](https://github.com/qh-work/memory-vault-sync/releases/tag/v0.28.0-alpha.0.40)** includes bounded delivery distribution and native message-replica recovery. [Final-source CI](https://github.com/qh-work/memory-vault-sync/actions/runs/37045141611) passed 1270 tests across 147 modules; three Python 3.10 suites and three-platform protocol conformance passed. Eight release assets were downloaded and matched, including an anonymous client download. Release source: `431ee0d2588273ecb2d8305b82ad73a3ce0375c7`. Same-host capacity results and slow, finite-work cold recovery remain experimental; independent-host/WAN and thousand-agent capacity are unverified.

Alpha.0.40 adds bounded HTTP admission, WAL read concurrency, separately approved resource distribution and native full message-replica COPY/READ recovery. The isolated 48-Memory/2-per-second workload completes 39 → 48 chains; this proves authorized quota use, not a CPU/SQLite ceiling. Replica cold reads remain slow and stop at the existing finite work allowance. See [capacity evidence and limits](CAPACITY_HANDOFF.md).

Alpha.0.40 candidate assets are validated against their exact source commit by `release-manifest.json` and `SHA256SUMS`; use the [release record](https://github.com/qh-work/memory-vault-sync/releases/tag/v0.28.0-alpha.0.40) for publication and CI evidence. Earlier release results below remain historical.

Published **[alpha.0.37](https://github.com/qh-work/memory-vault-sync/releases/tag/v0.28.0-alpha.0.37)** is fixed at `fe943c6466a6ef459ccb0d03e309b207b3b0fb95`.

Native TypeScript recipients can now retain an explicitly authorized receipt destination for a cold-mailbox message. Ordinary Agent `receive` returns its actual saved receipt, reusing the exact upload after a lost reply or restart. Python and TypeScript share jobs and completed history; revocation stops retries and expired uncertain uploads stop for reconciliation. See [native mailbox receipt returns](../clients/typescript/network/README.md).

Twelve checks passed using the extracted alpha.0.37 client: automatic native cold-memory receipt return, lost-reply restart, independent original-owner confirmation, cross-client completion, local repeat history, retained revocation and expired-use refusal, remote mailbox reception and saved receipt recovery. Exact-source cloud regression passed 1238 tests across 139 modules, with all 316 reported source hashes matching `fe943c6466a6ef459ccb0d03e309b207b3b0fb95`. All three Python 3.10 suites and cross-platform conformance passed. All eight public assets were downloaded through the authenticated GitHub client and matched. These results do not establish independent external adoption, global reliability or thousand-agent capacity.

Published **[alpha.0.36](https://github.com/qh-work/memory-vault-sync/releases/tag/v0.28.0-alpha.0.36)** is fixed at `bd3ca97ee56ca59a85c87eb1395e738e1a8c56ca`.

Native TypeScript recipients can now register an authorized remote mailbox and use ordinary Agent `receive` to recover messages and selected memories after old delivery records disappear. Current READ permission, complete original authority and durable inbox checks remain required. Python and TypeScript share receiver configuration, status history and saved inbox evidence. See [native mailbox recovery](../clients/typescript/network/README.md).

Nine checks passed using the extracted alpha.0.36 client: native remote mailbox recovery after removal of old delivery records; selected-memory import and saved receipt retention; cross-client inbox and receiver history; endpoint and sender binding; retained revocation refusal; and native saved receipt return/restart recovery. Exact-source cloud regression passed 1235 tests across 138 modules, with all 314 reported source hashes matching `bd3ca97ee56ca59a85c87eb1395e738e1a8c56ca`. All three Python 3.10 suites and cross-platform conformance passed. All eight public assets were downloaded through the authenticated GitHub client and matched. These results do not establish independent external adoption, global reliability or thousand-agent capacity.

Published **[alpha.0.35](https://github.com/qh-work/memory-vault-sync/releases/tag/v0.28.0-alpha.0.35)** is fixed at `d86d62083566a30804f3cae5ad6643da73e28f9a`.

Native TypeScript recipients can now return an actual saved receipt through `connect/return_receipt`, using separate original owner, recipient and storage permissions. The native client shares the bounded pending/completed journal with Python and can resume the exact pending upload after restart without consuming new consent. See [independent receipt return](OPEN_ACK_PROVISIONING.md#native-saved-receipt-return-development-after-alpha034).

Six checks passed using the extracted alpha.0.35 client: native saved-memory receipt return and original-owner confirmation with the old delivery node unavailable; shared completed history reopened by either client; native recovery of a Python-staged pending return; exact upload replay after a lost reply and restart; refusal of unsaved or mismatched messages; and retained denial/expiry enforcement. Exact-source cloud regression passed 1224 tests across 135 modules, with all 303 reported source hashes matching `d86d62083566a30804f3cae5ad6643da73e28f9a`. All three Python 3.10 suites and cross-platform conformance passed. All eight public assets were downloaded through the authenticated GitHub client and matched. These results do not establish independent external adoption, global reliability or thousand-agent capacity.

Published **[alpha.0.34](https://github.com/qh-work/memory-vault-sync/releases/tag/v0.28.0-alpha.0.34)** is fixed at `bb46c554539aae2acd21cab70322ae3b7c556808`.

Sources can now republish an original ACK location through another independently consented directory while preserving earlier publication histories and shared resource limits. Python and native TypeScript `connect/recover_routed_receipt` discover directories through existing seeds and routing state, then independently retrieve the actual receipt from the originally authorized source. See [directory republication and routed recovery](OPEN_ACK_DIRECTORY.md#publish-through-another-directory-development-after-alpha033).

Six checks passed using the extracted alpha.0.34 client: actual Agent memory delivery and original-send confirmation after the delivery node and first directory stop, through another router; both routed Agent facades refusing receipts without an original send; Python routed SDK recovery; separate publication histories surviving restart under the shared ledger; concurrent jobs refusing shared-budget overspend; and existing native prepared-send recovery with source replacement refusal. Exact-source cloud regression passed 1198 tests across 132 modules, with all 298 reported source hashes matching `bb46c554539aae2acd21cab70322ae3b7c556808`. All three Python 3.10 suites and cross-platform conformance passed. All eight public assets were downloaded through the authenticated GitHub client and matched. These results do not establish independent external adoption, global reliability or thousand-agent capacity.

Published **[alpha.0.33](https://github.com/qh-work/memory-vault-sync/releases/tag/v0.28.0-alpha.0.33)** is fixed at `d06d829a8978c267c34a37730d48f2d2fb7f5e1d`.

Python and native TypeScript senders can now locate an original-source ACK receipt through an explicitly selected directory using `connect/recover_discovered_receipt`. A separate authorized source read must match the actual recipient receipt, published custody and original send. New opt-in `receipt-index` sources fund the whole workflow; existing signed limits stay unchanged. See [directory receipt recovery](OPEN_ACK_DIRECTORY.md#agent-directory-recovery-development-after-alpha032).

Five checks passed using the extracted alpha.0.33 client: complete Agent message and memory delivery followed by native directory recovery with the delivery node offline; exact directory SDK recovery; missing-fact refusal; signed wrong-custody refusal; and both Agent facades refusing a receipt without its original send. Exact-source cloud regression passed 1189 tests across 132 modules, with all 298 reported source hashes matching `d06d829a8978c267c34a37730d48f2d2fb7f5e1d`. All three Python 3.10 suites and cross-platform conformance passed. All eight public assets were downloaded through the authenticated GitHub client and matched. These results do not establish independent external adoption, global reliability or thousand-agent capacity.

Published **[alpha.0.32](https://github.com/qh-work/memory-vault-sync/releases/tag/v0.28.0-alpha.0.32)** is fixed at `f8413a0619e00a7b079591053c3ef74c750559c1`.

Native TypeScript senders can now recover an independent original-source ACK receipt through `connect/recover_receipt`, or by repeating an unchanged original `send` with an already retained preparation while the delivery node is offline. Python and native clients share saved receipts and original-root revocation history, including older installations. Preparation, recipient return and full replica/mailbox workflows still use Python. See [native ACK confirmation](OPEN_ACK_PROVISIONING.md#native-agent-receipt-recovery-source-after-alpha031).

Three checks passed using the extracted alpha.0.32 client: native explicit receipt recovery with retained revocations across new invitations and older journals; ordinary-send confirmation with source replacement refusal; and native approved delivery with a saved receipt. Exact-source cloud regression passed 1184 tests across 130 modules, with all 295 reported source hashes matching `f8413a0619e00a7b079591053c3ef74c750559c1`. All three Python 3.10 suites and cross-platform conformance passed. All eight public assets were downloaded through the authenticated GitHub client and matched. These results do not establish independent external adoption, global reliability or thousand-agent capacity.

Published **[alpha.0.31](https://github.com/qh-work/memory-vault-sync/releases/tag/v0.28.0-alpha.0.31)** is fixed at `8ee27f7478388e7611e3293e628e96e481da673f`.

Python maintainers can retain exact authorized mailbox copies in a [finite persistent worker](OPEN_ACK_RECOVERY.md). Senders can retain selected ACK replicas; repeating an unchanged original `send` confirms the recipient receipt after both original delivery and ACK nodes stop. Exact requests and signed refusal history survive restart. Destination selection and independent permissions remain explicit. See [ACK replica confirmation](OPEN_ACK_PROVISIONING.md).

Five checks passed using the extracted alpha.0.31 client: persistent copy recovery through the public CLI after source loss, response loss and worker/target restart; original-send confirmation after both original nodes stop; retained signed revocation after refusal/removal/restart; ordinary independent receipt retry; and replica-memory reception followed by receipt return and original-send confirmation. Exact-source cloud regression passed 1182 tests across 129 modules, with all 292 reported source hashes matching `8ee27f7478388e7611e3293e628e96e481da673f`. All three Python 3.10 suites and cross-platform conformance passed. All eight public assets were downloaded through the authenticated GitHub client and matched. These results do not establish independent external adoption, global reliability or thousand-agent capacity.

Published **[alpha.0.30](https://github.com/qh-work/memory-vault-sync/releases/tag/v0.28.0-alpha.0.30)** is fixed at `bebd7f1b8b9c4a9079a02b233a738dc9cfa2002d`.

Python recipients can retain an independent ACK destination for an exact message. Ordinary `receive` returns the actual saved receipt under its original authorization; a repeated original `send` can use its already prepared owner READ grant to confirm that receipt. Lost replies and restart reuse durable requests, completed repeats remain local, and pending return failures are inspectable. See [ordinary independent receipt return](OPEN_ACK_PROVISIONING.md#retain-a-receipt-destination-for-ordinary-receive-source-after-alpha029).

Five checks passed using the extracted alpha.0.30 client: ordinary replica memory reception and independent receipt confirmation through the original send; lost-return/restart recovery and reconciliation; explicit cold-mailbox receipt return; approved delivery and restart recall; and pending-receipt fairness. The exact-source cloud regression passed 1179 tests across 127 modules, with all 288 reported source hashes matching `bebd7f1b8b9c4a9079a02b233a738dc9cfa2002d`. All three supported Python 3.10 suites and cross-platform conformance passed. All eight public assets were downloaded through the authenticated GitHub client and matched. These results do not establish independent external adoption, global reliability or thousand-agent capacity.

Published **[alpha.0.29](https://github.com/qh-work/memory-vault-sync/releases/tag/v0.28.0-alpha.0.29)** is fixed at `20b53a5d664b622c01ffe209c65557ea2a1d2d04`.

Python recipients can retain an already authorized message replica with `connect/register_replica`. Ordinary `receive` then recovers the original message and selected memories after source storage loss, including after restart. Current destination key/epoch and original permissions remain checked; saved ciphertext is not downloaded again. This polls explicitly selected copies and does not create replacements or grant receipt-return permission. See [ordinary replica reception](OPEN_ACK_RECOVERY.md#retain-a-replica-for-ordinary-receive-source-after-alpha028).

Four checks passed using the extracted alpha.0.29 client: registered replica recovery through ordinary receive, original delivery and restart recall, pending-receipt fairness, and replica-memory reception followed by independent receipt return. The exact-source cloud regression passed 1177 tests across 126 modules in two exhaustive partitions, with all 286 reported source hashes matching `20b53a5d664b622c01ffe209c65557ea2a1d2d04`. Supported Python 3.10 and cross-platform conformance passed, and all eight public assets were downloaded through the authenticated GitHub client and matched. These results do not establish independent external adoption, global reliability or thousand-agent capacity.

Published **[alpha.0.28](https://github.com/qh-work/memory-vault-sync/releases/tag/v0.28.0-alpha.0.28)** is fixed at `3663b284d9b22363a8ee228713b55e1eb3554895`.

Owner and sender can independently sign mailbox replica reservation consent with their own existing identities. The maintainer assembles those signed outputs into the existing capacity reservation commands. Original grants, exact copy intent, selected destination and expiry remain checked; signing grants no upload or receipt-return permission. See the [consent commands](OPEN_ACK_RECOVERY.md#prepare-independent-mailbox-reservation-consent-source-after-alpha027).

Thirteen checks passed using the extracted alpha.0.28 client, including independent consent commands, real replica reservation, restart recovery and shared-memory reception. The exact-source cloud regression passed 1176 tests across 125 modules in two exhaustive partitions, with all 284 reported source hashes matching `3663b284d9b22363a8ee228713b55e1eb3554895`. Supported Python 3.10 and cross-platform conformance passed, and all eight public assets were downloaded through the authenticated GitHub client and matched. These results do not establish independent external adoption, global reliability or thousand-agent capacity.

Published **[alpha.0.27](https://github.com/qh-work/memory-vault-sync/releases/tag/v0.28.0-alpha.0.27)** is fixed at `48334ec3921084394d7cd6eacb1d9283dd448d58`.

Maintainers can use `copy-reserve-root`, `copy-reserve-feed` and `copy-reserve-message` through their existing client configuration to reserve real replica capacity and retain the matching assignment. Owner and sender consent precedes the request; destination opt-in and separate upload/return permissions remain required.

Python recipients can [receive an original encrypted message and selected shared memories from an explicitly selected replica](OPEN_ACK_RECOVERY.md#receive-messages-and-shared-memories-from-a-replica-development-after-alpha025) after the mailbox source stops. Reception uses the existing durable inbox, original keys and trust policy; interrupted imports resume without duplication. Messages with independent ACK authority can return the recipient's signed receipt so the sender confirms its original send. Root, feed and message copies require separate capacity and original owner, sender, source and maintainer permission.

Thirteen checks passed using the extracted client; the published full client ZIP is byte-identical to that checked archive. The alpha.0.27 exact-source cloud regression passed 1170 tests across 124 modules in two exhaustive partitions, with all 282 reported source hashes matching `48334ec3921084394d7cd6eacb1d9283dd448d58`. Supported Python 3.10 and cross-platform conformance passed, and all eight public assets were downloaded anonymously and matched. These results do not establish independent external adoption, global reliability or thousand-agent capacity.

The HTTP repair path preserves bounded complete input and response processing. Installation retains the existing Vault, identities and protected state. Automatic replica selection, full native TypeScript mailbox workflows and independent external adoption remain unfinished.

Published **[alpha.0.25](https://github.com/qh-work/memory-vault-sync/releases/tag/v0.28.0-alpha.0.25)** is fixed at `ac3564467452c7d848dd665329851534cfd230b7`.

Twenty synthetic occupied-replica, restart, command, real-HTTP and Agent checks passed using the extracted alpha.0.25 client. Its exact-source full cloud regression passed 1116 tests across 116 modules, with all 259 reported source hashes matching `ac3564467452c7d848dd665329851534cfd230b7`. Supported Python 3.10 passed, and all eight public assets were downloaded anonymously and matched. These results do not establish independent external adoption, global reliability or thousand-agent capacity.

Python maintainers can
copy an existing saved-message receipt with all three original ACK histories.
Recipient authorization is required before reservation, during copy and for
subsequent owner reads, independently of owner/source/maintainer permission.
Original requests, used work, exact bytes and remembered revocations survive
restart. Compact transfer reuses the existing history packs within the unchanged
per-operation signature and per-replica work ceilings.

The `copy-reserve-occupied`, `copy-upload-occupied`, `configure-replica-occupied`
and `recover-replica-occupied` commands retain existing private configurations.
The Python Agent also accepts `recover_replica_receipt` through `connect`:
after validating the original recipient receipt against the actual local send,
it persists that send's saved acknowledgement. Later sends report the saved
state after restart while both original delivery and ACK sources are offline.
Selected memory remains in the recipient's Vault.

New Agent source preparation can explicitly name a distinct `copy_maintainer`
with the finite `receipt-index` profile. Default and existing grants remain
unchanged; changing a previously prepared selection is refused.

The source and extracted-package acceptance above passed for this fixed release.
Independent external adoption, global availability and thousand-agent capacity
remain unverified. Replacement
selection is explicit, and native Node replica commands remain unfinished.
See [occupied replica use](OPEN_ACK_RECOVERY.md#copy-and-recover-an-existing-saved-receipt).

Published **[alpha.0.24](https://github.com/qh-work/memory-vault-sync/releases/tag/v0.28.0-alpha.0.24)** is fixed at `b1a4e78bc8b7e8ac971d997a997bc6d5ced5904a`.

Fourteen synthetic bound-replica, restart, command and real-HTTP checks passed using the extracted alpha.0.24 runtime. Its exact-source full cloud regression passed 1099 tests across 115 modules, with all 258 reported source hashes matching `b1a4e78bc8b7e8ac971d997a997bc6d5ced5904a`. Supported Python 3.10 passed, and all eight public assets were downloaded anonymously and matched. These results do not establish independent external adoption, global reliability or thousand-agent capacity.

Python maintainers can now
reserve and copy a message-bound empty ACK slot to an explicitly selected
replacement, retaining both original history generations. Lost allocation or
commit replies resume exact durable requests after restart. Independently signed
return consents let the owner recover the original recipient/message/envelope
binding after the original node stops. The new `copy-reserve-empty`,
`copy-upload-empty`, `configure-replica-empty` and `recover-replica-empty` commands
use existing private configurations and transport journals.

The explicit `replica_empty` proof cannot be accepted as an original source or
unbound replica. A bounded metadata pack reduces network requests while every
original still counts toward the logical proof-byte ceiling. The assignment
remains COPY/READ/RETAIN only; the replacement gains no first-receipt admission.
The source and extracted-package acceptance above passed for this fixed release.
Occupied-receipt copying and automatic replacement selection remain unfinished.

Published **[alpha.0.23](https://github.com/qh-work/memory-vault-sync/releases/tag/v0.28.0-alpha.0.23)** is fixed at `d15be3af98e280938072113b62d620f99cc5921b`.

Thirty-five synthetic contact, directory, native Agent and receipt checks passed using the extracted alpha.0.23 runtime. Its exact-source full cloud regression passed 1087 tests across 114 modules, with all 256 reported source hashes matching `d15be3af98e280938072113b62d620f99cc5921b`. Supported Python 3.10 passed, and all eight public assets were downloaded anonymously and matched. These results do not establish independent external adoption, global reliability or thousand-agent capacity.

Native TypeScript agents
can now choose a configured contact node by its public key and explicitly
request finite offline directory maintenance. They refresh and challenge that
node, sign the same bounded authority as Python and retain the exact enrollment
in the existing transport database. Lost replies, restarts and language changes
preserve the node's existing job and used work. This adds no delivery approval,
trust, Vault access or permission extension. Directory workers still run on
supporting Python nodes; native Node hosts explicitly refuse the unimplemented
worker. This release passed its own source-bound and packaged acceptance as recorded above.
Thirty-three targeted protocol, native Agent, real-HTTP and directory-maintenance
checks passed on development source. They include a lost successful enrollment
reply, recipient exit, original directory expiry, node restart, Python takeover,
new-sender contact and final grant expiry. This is synthetic local traffic.

Published **[alpha.0.22](https://github.com/qh-work/memory-vault-sync/releases/tag/v0.28.0-alpha.0.22)** retains its separate source and acceptance record. Pending local delivery
and receipt work now rotates through a durable cursor shared by Python and
Node. Four older unavailable or independently authorized receipts no longer
prevent a later saved receipt from being retried. Each poll still attempts at
most four pending items; rotating changes neither receipt-sent state nor
permission. Restart and language switching retain the next retry position.

A real five-message HTTP regression failed on alpha.0.21: the fifth saved
receipt remained unsent after two restarted polls. Alpha.0.21 is therefore held
unpublished despite its earlier 32 packaged checks passing; those checks did
not cover this failure. Its immutable archives remain available for review.
The fix passed that scenario in Python and native Node, including the sender's
actual saved-receipt validation while all four blocked receipts remained unsent.
Twenty-nine direct-delivery, native HTTP and contact cases passed. Alpha.0.22 passed its own source-bound full CI and extracted-package acceptance.
Its immutable archives do not contain the later native directory enrollment work.
It retains native descriptor renewal, public introduction refresh and protected
Python/Node publication ownership from the held alpha.0.21 candidate.

Alpha.0.20 is now a published prerelease. It includes native Node commands for
unbound, empty and occupied ACK recovery, sharing authenticated status retention
with Python across failures and restarts. These commands export private evidence
through an existing identity and never open the content Vault.

The immutable alpha.0.19 candidate remains unpublished. Its full cloud run
completed 1,065 tests with one mailbox-staging failure, zero errors and zero
skips. The same failure was reproduced by delaying proof-child downloads:
the exhaustive non-ACK fixture had not funded its possession renewals and final
revocation check. Both exhaustive fixtures now request finite matching capacity
before signing their original grants; product limits and deadlines are unchanged.
This release passed its own source-bound and extracted-package acceptance as recorded below.

Alpha.0.18 remains unpublished: its complete cloud run executed 1,059 tests
with one ACK-bearing mailbox custody failure and no errors or skips. A slow
local download reproduced a possession handle expiring between child reads.
The exhaustive fixture now reads current-status originals first and renews
possession before expiry for the same exact historical references. Renewals
are bounded and charged; sufficient finite capacity is signed before setup.
Product permission windows and budgets are unchanged. Alpha.0.20 passed
separate package/privacy and exact-source full acceptance as recorded above. It also includes
packed-original reuse and persistent original-source recovery observations
from subsequent development; neither change is in alpha.0.18 archives.

Published **[alpha.0.20](https://github.com/qh-work/memory-vault-sync/releases/tag/v0.28.0-alpha.0.20)** is fixed at `24f93b04f78926d39e073ff5b3463cfc77ea64a6`.

Seventeen synthetic native-command, mailbox, receipt, restart and replica checks passed using the extracted alpha.0.20 runtime. Its exact-source full cloud regression passed 1072 tests across 114 modules, with all 256 reported source hashes matching `24f93b04f78926d39e073ff5b3463cfc77ea64a6`. Supported Python 3.10 passed, and all eight public assets were downloaded anonymously and matched. These results do not establish external adoption, global reliability or thousand-agent capacity.

This release includes packed replica original reuse and persistent original-source
recovery status across command restarts, including native TypeScript original-source
recovery commands in the installable client archive.

The release candidate below has now passed its own acceptance.

This release adds explicit `copy-reserve`, `copy-upload`, `configure-replica`,
and `recover-replica` commands. They use existing local identities and protected
transport state, preserve exact retry requests, and keep return permissions
separate from copy custody. Owner recovery remembers authenticated status facts
across failed commands and restarts. New-node setup can explicitly enable finite
remote copy reservations. No command opens the private content Vault. The replica
recovery example explicitly selects the existing 60-second client ceiling for
slower supported Python runtimes; signed deadlines and resource budgets remain
unchanged. These additions are later than the immutable alpha.0.16 candidate.

The alpha.0.16 full run was incomplete: one long mailbox fixture attempted to
sign a child request after its short handle expired, and the growing suite later
hit its 40-minute CI wall limit. Alpha.0.17 retained those same test/CI inputs and
its full run was cancelled after that diagnosis; both remain unpublished. The
fixture now performs a fresh, charged possession exchange before its independent
revocation check and reports only the current request's server errors. CI allows
55 minutes inside a 60-minute job; protocol deadlines and grants are unchanged.
Alpha.0.17 did pass 14 extracted-runtime workflows and supported Python 3.10.
Those results do not relabel either older candidate as a full-suite pass. This
alpha.0.20 release passed separate exact-source acceptance as recorded above.

The immutable **alpha.0.15 candidate remains unpublished**. Its full cloud run
[36536522221](https://github.com/qh-work/memory-vault-sync/actions/runs/36536522221)
failed nine fixture setup cases and twelve later service-start cases. Seven
extracted-runtime HTTP checks and archive/privacy checks passed, but do not
replace full acceptance. A fixture wrapper did not forward newly added options;
its failed setup also missed cleanup registration. Later source corrects both.
The earlier full pass at `fed27adc38e7eeacd1f1ba15546b778c364ae231`
([36531179438](https://github.com/qh-work/memory-vault-sync/actions/runs/36531179438))
does not cover the replica changes.

The current branch additionally implements explicit remote unbound replica
capacity reservation, durable upload/commit retries, and independent signed
custody verification. Operators opt into finite remote copy admission; a capacity
offer never substitutes for owner/source disclosure or READ permission. These
changes are not in the immutable alpha.0.15 candidate. Automatic replacement
selection, occupied/empty replica transfer, full native TypeScript mailbox
parity and global scale remain unfinished.

Published [alpha.0.14](https://github.com/qh-work/memory-vault-sync/releases/tag/v0.28.0-alpha.0.14), source `0eaf504e953be31b1844d6abfe57cd6f3c06aa29`, connects ACK-bearing mailbox retention to explicit receipt return after cold selected-memory delivery. A lost successful receipt response resumes from the original durable request; A then recovers the original receipt while the delivery node is offline. Four real-HTTP workflows passed using the extracted client runtime and child nodes. All eight public assets were anonymously downloaded and matched the reviewed candidate. [Exact-source full cloud regression](https://github.com/qh-work/memory-vault-sync/actions/runs/36523208918) failed two cases; scale and external adoption remain unverified.

Published [alpha.0.13](https://github.com/qh-work/memory-vault-sync/releases/tag/v0.28.0-alpha.0.13), source `7297b50f68d59649caf266be2e10515d19b5051e`, adds single-call mailbox retention and durable Agent ACK preparation with directly usable recipient/owner invitations. Five targeted HTTP workflows passed using the extracted client runtime; all eight public assets were anonymously downloaded and matched the reviewed candidate. [Exact-source cloud regression](https://github.com/qh-work/memory-vault-sync/actions/runs/36518360240) passed 934 tests, with all 242 reported source hashes matching alpha.0.13.

Published [alpha.0.12](https://github.com/qh-work/memory-vault-sync/releases/tag/v0.28.0-alpha.0.12) adds bounded mailbox configuration inspection/restoration, durable receiver authorization from an already approved contact, and corrected completed-retry signature accounting. Four targeted workflows passed using the extracted client; all eight assets were anonymously downloaded and byte-matched. [Exact-source full cloud regression](https://github.com/qh-work/memory-vault-sync/actions/runs/36514556101) passed 934 open-network tests with zero failures/errors/skips; the separate supported-Python-3.10 ACK check passed. The report’s 242 source-file hashes match the release commit. Scale jobs were not run. The broader network gaps below remain open.

Published [alpha.0.11](https://github.com/qh-work/memory-vault-sync/releases/tag/v0.28.0-alpha.0.11) adds Python Agent mailbox provisioning, durable remote admission, cold message/memory recovery and independent receipt operations. Its eight public assets match the reviewed packages, and four targeted packaged workflows passed. Its full cloud run later reported two HTTP fixture deadline failures, corrected in alpha.0.12; publication does not complete the global network objective. Replacement-node repair, scalable partial feeds, ACK-bound mailbox attempts and full native mailbox-client parity remain open.

The preceding alpha.0.10 release added independent remote source preparation using
only the sender's configuration and a selected public origin/key, plus durable
setup and bind recovery across lost replies. The Python Agent can enable contact
using an already configured node's public key ID. These workflows connect
ordinary memory delivery to independent original-receipt recovery. Source
requests, used work, authority observations and exact retry responses survive
restart. Separate A/B publication consents are required; a directory lease alone
is never a read capability. See the [directory guide](OPEN_ACK_DIRECTORY.md).
Message movement, automatic repair and global reliability remain unfinished.
The earlier encrypted delivery, selected-memory sharing and current-fact scorer
are retained. Exact validation belongs to the source-bound release record.

**Current development priority:** a globally decentralized network with bounded
local routing and sharded resource growth, not a larger private relay pool.
The [open-network roadmap](OPEN_NETWORK_ROADMAP.md) and its architecture,
first-contact/custody flows and falsifiable acceptance model supersede the older
private-first sequence. The first executable open routing slice now has
source-pinned implementation and cloud evidence; the full architecture remains
a development target, not a global reliability claim.

This source includes explicit [ACK recovery](OPEN_ACK_RECOVERY.md), with remote
binding, recipient-authorized upload, three-generation source verification,
independent signed-receipt reads and a private recovery command. The release
manifest and uploaded assets establish publication separately.

Current source target: **0.28.0-alpha.0.23**, an open encrypted-delivery preview.
The Python and native TypeScript Agents now connect explicit first-contact approval to encrypted
`send`, `receive`, durable local message reads, original-node storage receipts
and separately verified recipient-save receipts. Selected original memories use
the existing exporter/importer and trust/quarantine policy; ordinary chat stays
in the inbox. The same Vault, signing identity and six Agent operations remain.
The [open quickstart](OPEN_NETWORK_QUICKSTART.md) provides explicit setup using
one or two real signed introductions and participant-operated nodes. No hosted
project server, fixed seed, common issuer or global member roster is supplied.

The native TypeScript client uses its own crypto, Vault and protected transport
code without a Python subprocess. Delivery hosting currently uses the Python
node implementation; the TypeScript node does not yet host delivery. Message
migration, automatic repair and the full 0.28.0-alpha.1 milestone remain pending.
The alpha.0.4 delivery-approval fix is retained. Historical tests remain evidence
for their own exact source. Current results belong to the source-bound release
record; they do not establish global reliability or public adoption.

The prior **0.28.0-alpha.0.2** first-contact release added finite knock opt-in,
real dual-key challenge, explicit approval/rejection and request-bound results
with actual resource reservations. Its evidence applies to that source, not the
new delivery runtime. See [the first-contact contract](OPEN_FIRST_CONTACT_V1.md).

The prior native HTTP preview **0.28.0-alpha.0.1** is pinned to
`0ddf0c5ac6aa8d12562c1df2a26ee25aeb851ed3`; its review, CI and publication evidence
does not transfer to the new candidate. The earlier three
100-node routing seeds passed their 99% healthy/97% bootstrap-exit gates on
`dc485334f8ad8629db68ef25c7c618a732f15c6c`; each phase returned 1,000/1,000.
See [the exact evidence and limits](OPEN_ROUTING_RUNTIME.md). The experiment
uses logical signed control, not actual HTTP, SQLite, real AI or physical
failure domains.

The retained private communication-memory network
has a six-operation endpoint, independent issuer control, signed invitations,
JWE encryption, bounded relay-pool delivery, durable retries and endpoint receipts.
Existing core records, personal backups, handoff packages and plugin entrypoints
remain. Native encrypted Drive is wired to the existing queue; live cloud
credentials/upload/readback remain unverified. See
[current alpha evidence](RELEASE_NOTES_V0_26_ALPHA.md) and
[private network setup](NETWORK_QUICKSTART.md). No real-model acceptance is claimed.

The 0.27.0-alpha.1 feature adds opt-in signed relay discovery, a common bounded
pool across different bootstrap entries, and fallback until the requested one
or two storage confirmations are obtained. See [relay-pool scope](RELAY_POOL.md).
Fresh issuer control and relay-local invitation admission remain necessary.
This does not complete the earlier 24-hour or thousand-agent acceptance targets.

Published alpha.5 packaged reviewed mainline work: chat/memory separation, separately
authorized Memory Hints, frozen pages, explicit batch selection, cancellation
and local received-batch recall with current trust information. See the
[release scope](RELEASE.md), [Hint profile](NETWORK_HINTS_V4.md) and
[local batch view](RECEIVED_BATCH_RECALL.md). This does not provide global
discovery, unlimited capacity or an automatic private-installation upgrade.
Preserve old transport state and backups; migration from content/v1 is not provided.

Historical alpha.4 added optional Experience Semantics, bounded local provenance summaries
and cross-author state protection. The [Experience report](EXPERIENCE_VALIDATION.md)
records 37 new passes, 132 selected regression passes, five socket cases blocked
by the sandbox and a pre-existing Unicode runtime mismatch. No whole-suite pass
is claimed by that campaign. The trial service remains unconfigured and requires operator provisioning.

Alpha.3 fixes current-state recall priority across Python and TypeScript and adds
an isolated, all-synthetic endpoint trial package. The trial needs a separately
operated HTTPS service and one-time code, and proves only one bounded exchange.

The takeover iteration preserves existing code and configuration, removes
unshipped external network adapters, separates new issuer/member keys, fixes
recovery receipt progress and bounds rejected-content handling. Its final
16-test targeted campaign passed, including real loopback relay processes;
see the [current baseline](V0_26_PLAN.md). Subsequent committed checkpoints add
full endpoint recovery, authenticated node migration and separately verified
candidate archives. Current source also includes an independent TypeScript
persistent endpoint and native six-operation facade with bounded retrieval and
dynamic handoff. [Its scope](NETWORK_TYPESCRIPT.md) still excludes complete old
graph/cloud-worker parity and scale certification. The earlier first-contact
[prerelease](https://github.com/qh-work/memory-vault-sync/releases/tag/v0.28.0-alpha.0.2)
does not establish the new delivery preview's publication or asset availability;
those require their own source-pinned release evidence.
The current source also includes opt-in [deterministic v2 retrieval](RETRIEVAL_V2.md),
bounded sender repair and aligned signed-storage-response validation; those
features do not imply they have been installed locally. Actual package and local
upgrade evidence is separate. Historical reports below do not become
current-version validation by inclusion here.

Older withdrawn release pages/assets remain nonpublic drafts and their old public
tags/development branches were removed at the owner's request. The sanitized
main history remains. This does not remove read-only PR refs, forks, caches or
already downloaded copies; do not treat the cleanup as proof of zero exposure.

## Historical v0.25.1 capacity-patch status

Source target: **0.25.1**, a bounded file-pack capacity patch. The previous
[v0.25.0 release](https://github.com/qh-work/memory-vault-sync/releases/tag/v0.25.0)
was originally published at `7f27953b27b9ecd453be19084808357c89731d20`.
That is a historical source reference; subsequent privacy remediation changed
public history/assets and the old release is now withdrawn from public access.
This document does not assert that v0.25.1 assets are already uploaded or that
the new required CI has passed. No private installation, real Vault, key or
remote account is changed by preparing these sources.

The target is the full useful v0.21 taskless feature set plus an independent
lightweight protocol. See [the complete requirement ledger](V0_25_PARITY_PLAN.md)
and [old/new capability mapping](PARITY.md), not a smaller renamed subset.

## Capacity correction and bounded evidence

The optional file-pack source limit rises from the published v0.25.0 ceiling of
512 MiB to 2 GiB. Chunks remain 4 MiB, with at most 512 descriptors; copy still
defaults to 32 uncached chunks per call and accepts an explicit maximum of 512.
This restores the old taskless export byte range, not arbitrarily large copies,
new record-size limits or a complete parity certification.

One explicitly opted-in 516 MiB synthetic create/one-chunk-copy/four 32-chunk
resumes/repeat/unpack/hash case passed in 3.891763 seconds on
`2f67a7099e9eba0effb3483ed3a9ba3bf2f90f80`. Source bytes remained unchanged.
A 2 GiB/512-entry manifest was accepted and a sparse 2 GiB + 1 byte source was
rejected by its size before output. These boundary checks are **not a full
2 GiB transfer**. No keys, network, private Vault or child processes were used;
the timing is not a throughput benchmark. See the
[capacity report](V0_25_PACK_CAPACITY_SMOKE.md) and
[patch notes](RELEASE_NOTES_V0_25_1.md). Earlier reports below keep their original
source pins and are not reclassified as patch validation.

## Implemented source

- Shared immutable records, existing IDs/attestations and SQLite v2 remain the
  common foundation. The single-file core still imports no optional client.
- Full local retrieval adds fragments, bounded BM25, bilingual concepts,
  polarity/explanations and explicit paginated reindex. Graph/claim views expose
  timelines, conflicts, supersession and non-executing proposals. Ordinary entity
  labels do not require a concept-group match; structural handoff filters relation
  targets with the same current admission checks as ordinary recall.
- Eleven MCP tools, direct protocol, visible-event adapters, the new lifecycle
  profile and a separate ten-operation v0.21 wire adapter share one Vault/trust.
- New automatic captures freeze their time, complete record projection and
  source-local predecessor at acceptance, then append an ordinary `continues`
  relation. Exact retry does not choose a new predecessor or become a task-owned
  memory. Previously pending v1 captures retain their original behavior.
- Native Codex capture can now retain either visible side by itself. A late
  opposite side appends a linked supplement, never edits the initial episode.
  The [optional fragment profile](VISIBLE_FRAGMENTS.md) remains ordinary
  canonical memory, readable without a plugin or source-session handles.
- Signed chained synchronization includes receive-only/flush, reviewed
  exclusions, requeue, complete resumable fragment groups and directory/rclone
  backends. Optional v3 dependency reuse requires actual prior published members,
  current trust and the receiving Vault's atomic prefix receipt. Public `changes`
  and v2 remain self-contained. Prompt/save/recall paths do not perform remote delivery.
  A local publication-review block no longer prevents bounded incoming delivery;
  durable received batches remain counted if the next read fails. The original
  outgoing review error and frozen evidence remain visible.
- Memory snapshots and separately selected full-client recovery preserve
  evidence. Reactivation is explicit, uses a new configuration and does not
  restore keys, remote publication permission or host trust.
- Real v0.21 packs/ZIPs and checkpoint chains can be inspected/repacked and
  converted through a disk index into complete split canonical parts with
  original-byte evidence and validated old-ID mappings. Full conversation imports
  use checked member-byte bounds instead of the small converter's message cap.
- Content-selected sharing preserves complete dependency closure and optional
  proofs. Imports default to quarantine; verified import uses independent
  current trust. Encryption/device/catalog contracts remain external-provider
  APIs whose unconfigured defaults refuse work.
- Publisher verification, isolated managed installation, journaled activation,
  retained rollback and separately opted-in finite automatic updates are
present. A production publisher root/channel is not provisioned.
- Native Windows local-fixed-NTFS protection is implemented alongside POSIX
  protection. It does not isolate a hostile process running as the same user.
- Client control, transfer, sharing, pack, migration and backup publication use
  a single exclusive rename on supported macOS/Linux filesystems. This avoids
  leaving a complete file linked to its temporary name and unreadable on retry.
  Explicit output-directory contracts are preserved. Existing private aliases
  remain rejected; the independent core's raw bundle exporter is a separate
  path. See [the platform limits](PLATFORMS.md).
- Host recovery can finish interrupted cleanup only after verifying the exact
  lifecycle cancellation receipt and pending requests. Cleanup is bounded and
  does not count as a successful memory save. Disabling capture still blocks
  new commits; the operator can reconcile already confirmed cancellation.
  Explicit old-host `sync.flush` can recover existing local SQLite journals
  after rechecking current capture permission/configuration; ordinary reads do
  not silently acquire this recovery permission.

## Latest guarded workflows

The current source also contains four later behavior repairs: traceable excerpts
when a whole hit exceeds a small context budget; bounded near-duplicate/source
diversity; endpoint-specific conflict resolution with current-trust witnesses;
and local recall while automatic capture is disabled, including valid but
noncommittable old-host handles. The corresponding fixtures are
`test_v025_context_budget.py`, `test_v025_retrieval_diversity.py`,
`test_v025_conflict_resolution.py` and `test_v025_capture_disabled_recall.py`.
The [minimal release campaign](V0_25_RELEASE_MINIMAL.md) selected one method
from each, and all four passed on
`82ae4ac468007eed4555ea6f04a3a933899171df`. This covers small-context
traceability, near-duplicate retrieval, endpoint-specific resolution/history
and capture-disabled old/native recall, not every case in those files. Older
campaigns and packages built from `91111c518d62` do not validate these repairs.

The additional v0.21 single-sided native Stop gap has also been implemented:
new frozen fragments, append-only late supplementation, the shared untrusted
retrieval role hint, memory-only receipt validation and full-client recovery.
Normal complete pairs and old accepted v1/v2 identities remain unchanged.
Lock acquisition rechecks capture permission; existing prepared queues can be
recovered one item at a time even if they exceed the new preparation budget.
The same initial minimal run passed one native-hook method covering both
single-sided arrival orders, late supplementation and the complete-pair path
with synthetic visible events. Its sixth selected method, partial-fragment
full-client recovery, errored in fixture setup because `atomic_write` lacked
the required `replace` argument. Only the fixture changed to `replace=False`
in `cb477db6fd1f8a34671a5d8045f313ef6dfac15c`; only that recovery method was
rerun, and it passed in 0.106540 seconds. Runtime source hashes were unchanged.
These are **six distinct methods across two runs: five passes and one setup
error, then one recovery-only pass**, not a whole-suite pass on either source.
Other fragment methods remain unrun. No network, child process, private Vault
or installed host was used. Visible input coverage and interrupted persistence
remain different requirements; the older partial-**write** campaign alone did
not establish the former.

The [workflow report](V0_25_WORKFLOW_SMOKE.md) records four passing methods on
`c65fd82f863e4e05d9ec53622eceb584525fb52e`: all eleven embedded MCP tools, all ten
old host operations, signed directory review/resolve/requeue with independent
receiving, and 42 synthetic privacy vectors. Old secret/path families are
restored as publication detection, not task routing or execution permissions.

The fifth method exposed a real update extraction defect: newly created
intermediate directories were not all private. After repairing that runtime
path, only the unchanged update method was rerun on
`0be4c6dbf6d7d3eb477ed807e15c3659f38776c8` and passed. It exercised real test-RSA
verification, staging, inert installation, caught partial-write retry and
explicit rollback. Existing modes are preserved; unknown leftovers after a hard
kill still cause a visible refusal. These are separate runs, not a five-method
pass on the newer source. No full-suite, live-host/provider or production-key
acceptance follows, and the full ledger remains open.

## Fragmented transport, signed recovery and old-format continuation

The [next workflow report](V0_25_TRANSPORT_RECOVERY_SMOKE.md) records three
passing methods on `fc3588556b976665c547ab3fc26c8f26f54bbb20`: the real default
two-fragment splitter and signed sync using a simulated provider command runner,
a tiny signed v3 staged-group snapshot/restore/import, and selective sharing
with current-trust re-admission and revocation. Remote progress survives a
post-admission head-file failure, and cancellation is checked before admission.
Verified share retry can restore currently acceptable proof without rewriting
canonical memory or old receipts; default/unsigned retries cannot do so.

One old-format method separately passed on
`76b8c8bfaed5b4d73d0ffd647dc8cd6286ba0fa7`, which only added that fixture. It
checks two distinct packs/checkpoints, original-byte preservation, typed claim
relations, old-ID mapping and continued semantic writes. The first three methods
were not rerun. Actual rclone processes, live accounts/devices, near-limit scale,
native Windows/Linux and full recovery/compatibility acceptance remain pending.

## Evidence actually available

Source review and independent static cross-reviews identified concrete
integration, trust, alias, closure, recovery and packaging issues and led to
source fixes. Python AST and JSON parsing were performed without importing the
application. These checks prove only the parsed source/format properties.

The [validation index](VALIDATION.md) records each executed campaign with its
exact source, selected methods and limitations. The initial unsigned exchange
and metadata campaign and the later retrieval/shared-retry campaign are separate
results, not one passing suite on current source. Build/inventory checks remain
separate evidence in their original manifests. Existing artifacts are unchanged.

The [publication and recovery campaign](V0_25_RECOVERY_SMOKE.md) now records seven
passing cases on its pinned source, including one controlled child-process exit
and one actual unsigned hooks backup/restore/activation/retry path. A separate
pre-fix run of the same publication case reproduced the exact double-link
failure. Remaining retrieval, compatibility and other authored cases stay unrun
unless the index links an actual execution report.

## Automatic cross-turn continuity and dependency reuse

The formerly missing v0.21 source-local predecessor behavior is implemented by
frozen plans in `memory_vault_capture.py` and the hook/lifecycle/compatibility
entries. The [capture campaign](V0_25_CAPTURE_SMOKE.md) records twelve passing
methods on its exact source, including unchanged legacy partial-write identities,
bounded predecessor completion, restore from a done-before-ack window and one
real temporary SQLite hot-journal process exit. The initial fixture errors are
retained separately; they are not silently counted as passes.

Only canonical relations travel. Private source correlation does not decide
memory ownership, lifetime, visibility or authorization. New captures do not
guess predecessors from a global latest record, and old pending jobs are not
retroactively given a new history.

The new v3 transfer path can omit dependencies actually published on the exact
stream, with current trust/epoch validation and receiving-store receipt checks.
The small signed fixture confirms four pages of a 32-record chain and rejects
copied heads or newly untrusted ancestors. This is not a throughput benchmark:
cache loss and trust changes can still require bounded full revalidation and
return `dependency_revalidation_required`. First-use near-limit closures, large
fragment groups, real remote providers and independent receivers remain
unverified; the later workflow covers a small default-split signed group only.

## Still unverified / release gate

The scoped campaigns did not cover live capture, installed-host compatibility,
device/power-loss recovery, complete process/concurrency recovery, cryptographic
interoperability, Windows/Linux native behavior, full 2 GiB transfer, throughput,
two-device delivery or a cross-language round trip. Earlier configuration/recovery
routing used mocks; the later actual unsigned hooks recovery case does not
establish every restore component or real-installation recovery. Metadata checks
do not authenticate an author or verify an encryption provider. The retrieval
follow-up used fixture threads and an injected exception; its roughly 7 MiB
long-tail fixture is not a scale or performance certification. The later
publication case used one real temporary child exit, not a power-loss trial.
The newer hot-journal case likewise does not simulate device power loss; the
small signed directory fixtures use the same reference implementation at both ends.

The [parity-repair campaign](V0_25_PARITY_REPAIR_SMOKE.md) separately records twelve
passing methods on `9d98ce0d56394adc275915a0ea1fd39b6ca06254`: entity recall,
handoff relation filtering, a 20,001-message old export, selected publication
interruptions/rollback and POSIX directory compatibility. Only three tiny
publication children exited; the other failures were injected in-process. The
backup case exercised its file publisher, not a complete snapshot/restore. No
keys or providers were used. The five new modules contain ten additional methods
that were not selected, and the whole ledger remains open.

The work also does not establish native Work automatic events, production
encryption/recovery ceremonies, a security audit, vendor certification or
independent adoption. A matching host must actually expose the integration.

On 2026-08-31 the owner explicitly authorized minimal necessary verification
and prompt v0.25 publication with its limits disclosed. Publication does not
close the requirement-by-requirement completion audit. The v0.25.0 protected-main
requirement (eight base tests on each of three platforms) passed in
[PR CI 33374601764](https://github.com/qh-work/memory-vault-sync/actions/runs/33374601764)
and [main CI 33374661273](https://github.com/qh-work/memory-vault-sync/actions/runs/33374661273).
The new v0.25.1 required CI is pending; earlier passes do not validate the patch.
Branch protection and the published v0.25.0 tag remain unchanged.
See [release scope](RELEASE.md), the
[minimal campaign](V0_25_RELEASE_MINIMAL.md) and [review handoff](REVIEW_HANDOFF.md).
