# Open delivery repair R3: cold mailboxes and independent ACK roots

Status: **unimplemented protocol candidate for joint review**. This document
replaces the unresolved repair choices in the R1/R2 working proposals. It is
neither a protocol freeze nor a successful review, test, release, or deployment.
The published alpha.0.5 delivery path still uses the original approved Python
node. Its contact approval and saved receipt do not authorize this new profile.

The five prior joint-review findings are treated together: one original
authorization model; an acyclic cold locator; complete initial empty roots and
resources; independently maintainable ACKs; and accounting for the full proof
and storage closure. The architecture requirements remain those of
[OPEN_NETWORK_ARCHITECTURE.md](../OPEN_NETWORK_ARCHITECTURE.md),
[OPEN_NETWORK_LIFECYCLE.md](../OPEN_NETWORK_LIFECYCLE.md), and
[OPEN_NETWORK_ACCEPTANCE.md](../OPEN_NETWORK_ACCEPTANCE.md). Their acceptance
targets are not measurements of this candidate.

This revision also proposes resolutions for the two R3 review blockers:
phase-specific historical inputs, including a complete feed interval; and
owner-permitted dual-key service preflight before private original uploads.
These resolutions still require joint review and implementation. A review of
existing native provider code is not a review pass for this repair protocol.

## 1. Required outcome and explicit non-upgrade boundary

A and B retain one existing Vault each and their existing signing identities.
Transport state, source proofs, routing, resource ledgers, and repair jobs stay
in the existing protected transport store. No mailbox, model, session, or repair
process owns a Memory. Original Memory IDs, package bytes, and author proofs are
unchanged. Ordinary messages and protocol controls do not become Memory.

The complete required result has two independent recovery paths:

1. B, restored from a state captured before an unknown message existed, learns
   that message through its original mailbox anchor, verifies the original
   admission and current access chain, retrieves unchanged ciphertext from
   replacement providers, and actually saves the validated content.
2. A, restored from its state after freezing the message and its ACK permission
   but before B produced a receipt, finds that exact receipt through A's own
   ACK anchor after the original ACK holder has disappeared.

Both paths require surviving authorized custody and maintenance resources.
Neither promises recovery after every copy or necessary association is lost,
all relevant authority expires, keys are lost, or no permitted network path
survives. No original node, sender process, global inventory, common issuer, or
project-operated server is a required repair coordinator.

Existing contact documents remain unchanged. A new, explicitly selected
`repair_v1` profile adds the roots and consent below **before** initial
repairable admission. Existing alpha.0.5 messages remain under their original
permissions. They cannot be relabelled repairable by a later maintainer or
retroactive certificate. An operator may create a new explicitly authorized
delivery using unchanged E when its recipient keys still match, but that is a
new sender-signed attempt, not repair of an old admission.

## 2. Types, signatures, and schema ownership

`Signed` is exactly `{payload,proof}` using the existing Ed25519 message
signature primitive and domain `UniversalAgentMemory\0message-signature\0v1\0`
(actual zero bytes). A valid self-supplied key is verification material; the
expected signer comes from the complete authorized chain or preheld local
expectation. Transport verification never enrolls a key in Vault author trust.

New signed payloads have exactly `schema_version`, `kind`, `signing_key` and
the fields specified for that kind below. They use the new candidate schema
`memory-vault-open-repair/v1`; this does not alter an existing kind's schema.
There are **no implicit time or revision fields**. Authority documents have
explicit windows; historical event documents retain their original event and
promise times without acquiring a new artificial expiry.

| Type | Closed representation |
|---|---|
| U53 / Time | JSON integer 0..9007199254740991; bool, float, exponent spelling, negative, nonfinite and string forms rejected; narrower ranges below apply |
| H | 64 lowercase hexadecimal characters |
| O | Existing bounded opaque identifier; a stable ID never substitutes for a raw-content digest |
| DualID / DualKey | Existing exact signing/encryption key IDs or complete public descriptors; IDs recomputed from key bytes |
| OpaqueRef | `{namespace,key:H}` with namespace `anchor`, `feed`, `meta`, or `object` |
| RawRef | `{namespace,key:H,raw_sha256:H,size:U53}`; namespace `meta` or `object`, size positive; hashes full original bytes |
| RootKey | `{owner:DualID,root_kind:mailbox|ack_return,anchor_ref:OpaqueRef(anchor),owner_epoch:O,root_id:O}` |
| ResourceRef | `{node_key_id,storage_epoch,lease_id,resource_id}` |
| SlotKey | `{root_key:RootKey,slot_id:O,writer:DualID,writer_storage_epoch:O}`; root_kind must be mailbox |
| AckSlot | `{root_key:RootKey,slot_id:O,receipt_writer:DualID,grant_id:O}`; root_kind must be ack_return |
| Window | `{admit_until,read_until,copy_until,publish_until,retain_until}`; each relevant operation ends no later than retention |
| Budget | `{max_live_bytes,max_meta_bytes,max_items,max_requests,max_pending,max_replay_records,max_jobs,max_job_bytes}`; all finite U53 |

The parser rejects duplicate keys, unknown fields/kinds, noncanonical new wire,
invalid UTF-8, unpaired surrogates, and out-of-policy nesting/node counts before
signature work. Historical Memory/share bytes retain their independent lossless
int64 rules; native TypeScript must not reserialize them through JavaScript
Number. A referenced signed document is its original full wire, not a projected
summary. Payload hash, full wire hash, and random opaque lookup key are distinct.

All arrays below are finite, contain unique entries, and have a specified order:
identifier arrays lexicographic, operation/role sets lexicographic, sequence
arrays ascending, proof hashes in the algorithm's prescribed order. Every
consumer rejects unexpected roles. A capability URL, arbitrary callback, lazy
proof URL, or unchecked raw hash is never a read permission.

## 3. Authority and status are separate from discovery

For `repair_v1`, **selected-slot is the mailbox operation root; catalog is only
discovery**. All implementations use this rule at the original admission.
Removing a catalog reference is not an implicit slot revocation. A catalog
update cannot remove the last local entry required by an unexpired promised
discovery obligation. An explicit scoped status can stop new admission,
discovery, reading, copying, publication, or retention separately. A local Vault
record is not deleted by any of those transport operations.

Use the existing seven operation bits, with meaning scoped by the exact kind and
resource: admit=1, read=2, copy=4, discover=8, publish=16, renew=32, retain=64.
For example, admit on an ACK slot permits only the defined B receipt operation;
it never permits chat or memory transfer. An assignment narrows, never expands,
the allowed set and horizons of every parent.

`authority.status` retains the existing closed provider representation:
`scope_key={root_key,issuer_key_id},revision,issued_at,valid_until,entries`;
each entry is `{scope_kind,scope_id,minimum_document_revision,status,
operation_mask}`. Scope kinds are catalog/mailbox_slot/ack_slot/authority/
resource/assignment/contact_policy. The scope ID is the canonical digest of a
typed stable scope: catalog uses RootKey, slot uses SlotKey/AckSlot, resource
uses RootKey+ResourceRef, and immutable authority/assignment uses its kind and
full original raw digest. Status is active or revoked.

Only the expected issuer may sign its status: A for A consent/ACK authority, B
for B slot/consent/root authority, M for its assignments, and each R/P/D for its
own resource. B cannot sign a node's resource state. Required status documents
are actual proof roles, including historical observations used at admission;
they are not folded into an unregistered fixed number of current-status slots.

Each verifier durably preserves highest observed revision, minimum document
revision, revoked operation bits, and same-revision conflicts for all dependent
windows. Lower or conflicting observations cannot restore authority. For an
immutable authority scope, a revoked operation cannot be reinstated by raising
its status revision; renewed permission needs a new original authority.

Historical verification uses the original accepted/stored time, original
authority bytes and retained original observations. It proves consistency with
the signer's asserted event, not an external trusted timestamp or knowledge of
every remote revocation. Current operations separately intersect their current
authority, resource ledger/generation, time, and highest known observations.
Original R allocation, offer, owner activation, resource.active, binding and
resource.status are checked at their actual source activation/binding/commit
time. The offer's reservation_until gates activation, not every later read.
After a legitimate P commit, R being offline, its old resource status expiring
or its own custody promise ending does not by itself invalidate P's independent
live obligation. Current checks instead apply to original owner/consent rights,
required current owner/consent statuses, exact M→P assignment, P resource/epoch/
generation/status and the operation's windows. Any source dependency still
used for today's service must itself remain available under a live commitment.
New P retention cannot extend an original owner's or consent signer's deadline;
it also cannot rewrite R's original event/promise times. Thus neither a blanket
verify(now) of historical evidence nor a P receipt renewing owner authority is
valid. Offline A/B need not produce a new signature every minute. A long finite
authorization entails a possible unknown-remote-revocation window; no global
instant revocation claim is made. Expired required status or authority cannot be
silently refreshed by M. Local state loss requires a new node storage epoch.

## 4. Real resource allocation precedes obligations

Provider-index leases and contact knock/delivery leases do not allocate repair
storage or permit private evidence disclosure. The root resource mechanism
already implemented in `memory_vault_open_provider.py` is reusable only for its
actual defined owner-allocation branch. Its current publisher-only status check
is not a general read/copy verifier.

R3 defines these separate resource intent kinds. Every intent is a canonical
object signed by the enclosing allocation RPC, retained verbatim inside its
node-signed offer; it is not another root of authority.

| Intent kind | Exact fields beyond `kind` |
|---|---|
| `resource.owner_intent` | allocation_id, root_key, owner:DualKey, target:DualKey, target_storage_epoch, purpose, budget, windows |
| `resource.copy_intent` | allocation_id, job_id, root_key, caller:DualKey, target:DualKey, target_storage_epoch, purpose, scope, historical_manifest_ref, budget, windows |
| `resource.index_intent` | allocation_id, job_id, root_key, caller:DualKey, target:DualKey, target_storage_epoch, purpose=`provider_index`, scope, advertised_custody_ref, provider_fact_ref, historical_manifest_ref, budget, windows |

Owner intent purposes are `anchor_catalog`, `feed_metadata`, `mailbox_data`,
and `ack_slot`. `mailbox_data` requires a mailbox root, positive live-byte and
item reservations, and its own metadata/control/work reservation. The original
R must still match the exact contact delivery target and storage epoch; a new
P receives delegated copy authority, never the original contact lease.
Copy intent purposes are `root_replica`, `feed_replica`, `message_replica`, and
`ack_replica`. A message replica's data/meta budgets are independent fields;
index/catalog-only purposes fix max_live_bytes=0. An ACK replica's live data can
contain only the exact signed B receipt, never E or arbitrary content. Every
purpose also reserves its actual metadata, replay, pending and job costs.

Original admission checks both the unchanged contact ingress grant/lease and
the new B-authorized active data/metadata resources. It charges both obligations
without silently converting, refunding or renewing either. All reservations
share the node's actual physical-capacity ledger. Exact immutable bytes may be
physically deduplicated only after proving identity; their pins, deadlines and
logical obligations remain separate. Conservative double reservation is valid;
independent ledgers overselling the same disk are not. Old contact GC releases
only its own obligation and cannot unlink E while repair custody still pins it.
Later copies verify contact authority historically at original accepted_at;
their current authority is the exact repair root/consent/resource chain.

Scope is a closed union:

- `{kind:mailbox_root,root_key,root_authority_ref,catalog_ref}`;
- `{kind:mailbox_feed,slot_key,slot_ref,feed_head_ref,source_custody_ref,
  subtree:{start,end,root_ref,parent_path_refs}}`;
- `{kind:mailbox_member,slot_key,attempt_ref,envelope_ref,admission_link_ref,
  source_custody_ref}`;
- `{kind:ack_unbound,ack_slot,root_authority_ref}`;
- `{kind:ack_empty,ack_slot,grant_ref,binding_ref}`;
- `{kind:ack_occupied,ack_slot,grant_ref,binding_ref,receipt_ref,
  original_ack_commit_ref}`.

Each branch contains only already-existing refs. An unbound ACK scope does not
claim a future message or grant binding. The transition to empty requires the
owner's exact grant and durable binding, not a nullable placeholder field.
The feed subtree is a nonempty represented range with exact authenticated paths
to the already signed head; an empty genesis feed is part of mailbox_root
custody instead. Parent-path refs cannot grant another range or an arbitrary
child object.

Each copy/index intent's historical_manifest_ref must select exactly the
corresponding section 7 historical variant: mailbox_root, mailbox_feed,
mailbox_member, ack_unbound, ack_empty, or ack_occupied_inputs respectively.
Input manifests precede their source commit. A copy scope is constructed only
after the source event exists and can reference it; the input manifest never
points forward to that event. Directory input also precedes its own index
commit and retains the same original variant as the advertised custody.

The owner root and, for member work, original A/B disclosure expressly permit
M to send this minimal reservation descriptor to a freshly dual-key-proved
candidate before assignment: RootKey/public identities, opaque scope refs and
requested finite budgets/windows. This exposes those limited associations to
that candidate. It does not permit sending original private signed evidence
before the exact offer and assignment exist. If the root lacks this advance
reservation-disclosure scope, obtaining new targets is blocked, not implicit.

`resource.allocate` is requester Signed with
`issued_at,expires_at,request_id,target_node_key_id,target_storage_epoch,
intent,intent_sha256`. Its signer is owner for owner_intent or the exact M
caller for copy/index intent. Retain this full original request, not a node's
summary of its contents.

`resource.offer` is node Signed with `issued_at,reservation_until,offer_id,
allocation_request_ref,intent,intent_sha256,resource:ResourceRef,target_encryption_key,
reservation_generation,budget,windows`. The target first checks its enabled
finite policy and durably reserves the actual amounts. The offer is a
conditional reservation, not application custody. Its activation deadline is
separate from the requested long read/retention horizons. Every target proves
both keys before receiving private original evidence.

The offer's request and embedded intent must match exact original bytes,
requester, target, epoch and hash. The request and offer are earlier than the
owner authorities that bind this reservation. An existing contact/index lease
cannot fill either role.

For initial setup, owner Signed `resource.activation` has
`issued_at,expires_at,activation_id,subject:DualKey,target_node_key_id,
target_storage_epoch,root_key,scope,resource_offer_refs,authority_refs`.
The sorted unique offers are for one actual target/root and still within their
activation deadline. authority_refs entries are `{role,ref}` with this closed
scope/role table; mailbox_slot here is an activation selector, not a copy scope:

| Activation purpose / exact scope | Exact owner authority inputs |
|---|---|
| anchor_catalog / `{kind:mailbox_root,root_key,root_authority_ref,catalog_ref}` | B root_authority, root_read_grant, catalog and each exact catalog slot/read_grant/maintenance_root |
| mailbox_data + feed_metadata / `{kind:mailbox_slot,slot_key,slot_ref}` | B exact slot/read_grant/maintenance_root; exactly its data and metadata offers |
| ack_slot / `{kind:ack_unbound,ack_slot,root_authority_ref}` | A root_authority and read_grant |

The data/meta activation does not reference catalog, root authority or anchor
activation. Thus selected-slot remains the sole mailbox operation root even
when a verifier follows every activation dependency. Anchor activation may
depend on already completed slots; the reverse edge is forbidden. Reusing an
activation ID with different bytes or binding an offer to a different activation
is a conflict. Exact retries return the original result.

`resource.active` is node Signed with
`activated_at,offer_ref,activation_ref,resource,reservation_generation,root_key,
purpose,budget,windows`. Each offer gets its own result after actual ledger
activation. It references no future genesis, historical manifest, custody,
grant binding or receipt. An unactivated short offer is no pre-offline promise.
The enclosing setup RPC releases active/custody success only after its complete
required local commit; a partial setup is not S1 or S_ACK0.

For delegated copies, M next signs `maintenance.assignment` with
`issued_at,expires_at,assignment_id,job_id,root_key,parent_root_ref,
parent_assignment_ref=null,depth=2,subject:DualID,target_node_key_id,
target_storage_epoch,operation_mask,scope,resource_intent_sha256,
resource_offer_ref,resource:ResourceRef,bootstrap_grant_refs,budget,windows`.
Only an M explicitly named by the original root may do so. P and D need separate
exact assignments and resources. No P receipt makes P another maintainer.
bootstrap_grant_refs is a sorted unique list of earlier owner bootstrap grants
defined in section 9. A service assignment names each permitted subject/profile;
a pure index assignment fixes this list to empty. The signature permits returning
this exact M assignment and its exact referenced allocation request signed by
the same M, plus complete M authority.status documents whose entries all concern
this exact immutable assignment scope, to those subjects. The status scope is
computed from the completed assignment's raw digest; no self hash is inserted
into the assignment. It cannot permit another signer's originals, other M
requests/jobs or unrelated status entries. A multi-entry original requires
permission for every entry; otherwise it cannot be returned or projected.

The acyclic order is `frozen intent → real target offer → M assignment →
target application commit`. Neither the offer nor assignment references the
future proof group or its own custody result. The directory intent is created
after P custody and fact exist; D's new index lease is a result, not input.

On a successful copy, P signs `replica.custody` with
`root_key,scope,original_custody_ref,replica_manifest_ref,assignment_ref,
resource_offer_ref,resource:ResourceRef,reservation_generation,stored_at,
read_until,retain_until`. It is an event, not a new owner authorization.
`replica.manifest` is an unsigned exact object containing
`schema_version,kind,root_key,scope,original_roles,physical_objects,edges`;
original_roles entries are `{role,ref}`, physical_objects entries are
`{role,ref}`, and edges are `{parent_ref,relation,child_ref}`. Relations come
only from the closed typed parent parsers in this document: catalog-slot,
slot-feed, head-checkpoint, head-range, range-child, repair-page-sealed-page,
repair-page-link, link-core, link-history, core-envelope, ack-binding-grant,
ack-commit-receipt, and manifest-member. Each edge is recomputed from the
original parent bytes, never trusted because it appears in this manifest.
Original_roles include the exact historical source event and its necessary
authorization; physical_objects identify actual local or separately committed
dependencies, with their concrete valid resources resolved before success.
The manifest contains no future P custody/fact or D lease reference. P's later
fact may name only a location actually covered by that custody commitment.

For mailbox_member and ack_occupied, original_custody_ref designates the
original message.custody or ack.commit. For mailbox_root it designates the
original root.custody; for mailbox_feed it designates a source feed.custody
covering that exact complete interval, as defined in section 7. A message.custody
for one appended member cannot stand in for the full interval. For ack_unbound/ack_empty it
designates the initial ack.slot_custody below. Copies retain the original event,
not an unbounded chain of intermediate custodians. A direct M assignment and
P's fresh real commitment authorize the replacement; original evidence still
proves what it belongs to.

Reservations are local promises, not transferable global credit. A max-targets
budget constrains an honest M and each signed job; it is not a proof that a
malicious M cannot spend unrelated resources at multiple independent nodes.
Each node checks its own actual allocation and charges every accepted reference.

## 5. Mailbox setup before the message exists

Use three distinct points in time:

- S0: B has explicitly enabled finite first contact before unknown A exists.
- Approval: B resumes and approves A through the unchanged contact protocol.
- S1: B has completed the new mailbox setup below, retaining K_B, owner epoch,
  exact slot/read authority, root/feed bootstrap grants, observed floors and
  normal routing state, before E/message_id/K_m exists. B may go offline again.

Choose RootKey, SlotKey, stable read/maintenance IDs and opaque feed_ref first.
Obtain actual R anchor, mailbox_data and feed_metadata offers next. Then form the following
closed owner authorities; their raw refs only point to earlier objects.

| B-signed kind | Exact fields beyond common fields |
|---|---|
| `mailbox.root_authority` | issued_at,expires_at,root_key,authority_id,original_resource_ref,original_resource_offer_ref,slot_ids,maintainers:[DualID],operation_mask,allowed_roles,budget,windows,max_delegate_depth=2,max_destinations_per_job,max_concurrent_jobs,revision |
| `mailbox.maintenance_root` | issued_at,expires_at,root_key,authority_id,slot_key,sender:DualID,recipient:DualID,maintainers:[DualID],operation_mask,allowed_roles,budget,windows,max_delegate_depth=2,max_destinations_per_job,max_concurrent_jobs,revision |
| `mailbox.read_grant` | issued_at,expires_at,grant_id,root_key,slot_key,reader:DualID,serving_authority_id,operation_mask,budget,windows,revision |
| `mailbox.slot` | issued_at,expires_at,revision,slot_key,feed_ref,sender:DualID,recipient:DualID,data_resource_ref,data_resource_offer_ref,metadata_resource_ref,metadata_resource_offer_ref,read_grant_ref,maintenance_root_ref,max_appends,max_live_items,budget,windows |
| `mailbox.catalog` | root_key,revision,issued_at,expires_at,slot_refs,root_authority_ref |
| `mailbox.root_read_grant` | issued_at,expires_at,grant_id,root_key,reader:DualID,root_authority_ref,operation_mask,budget,windows,revision |
| `delivery.destination` | issued_at,expires_at,destination_id,sender:DualID,recipient:DualID,contact_request_ref,contact_policy_ref,contact_knock_lease_ref,contact_decision_ref,store_grant_ref,slot_key,slot_ref,data_resource_ref,data_resource_offer_ref,metadata_resource_ref,metadata_resource_offer_ref,read_grant_ref,maintenance_root_ref,budget,windows |

The sender scope in one message maintenance root is exactly the approved A, so
disclosing its required original bytes does not accidentally reveal a roster
of other senders. Maintainer lists remain visible to authorized verifiers;
they are not claimed to be hidden. A new slot or sender requires B's new
authority. `serving_authority_id` is chosen before root/read documents and
matches the maintenance root ID; it is not a future raw hash.

The slot is the original R verifier's operation root. It authorizes that exact
writer incarnation and links independent data/meta resources to the exact
approved sender, B read grant and maintenance root. The catalog references the
completed slots; a slot never references the catalog that contains it. A legacy
profile that originally required a full policy must retain it under its old
rules; repair_v1 does not have an optional policy-as-operation-root branch.

All renamed offer_ref fields above refer to the actual earlier resource.offer,
not resource.active; old lease_ref aliases are rejected in this new schema.
The data/meta offers must match the selected slot's original R, epoch and exact
purposes. The owner activation and node active records preserve that binding.

The durable order is:

```text
B slot/read/maintenance originals → B mailbox_feed bootstrap grant
→ B slot activation → R data/meta active + count-zero checkpoint/feed_head
→ atomic slot commit
→ B root/read/catalog originals → B mailbox_root bootstrap grant
→ B anchor activation → R anchor active
→ historical.manifest(mailbox_root) → R root.custody → atomic root result → S1
```

The bootstrap grants reference already existing authorities; neither an owner
authority nor activation references a future grant. R must durably hold the
applicable grants and full preflight service chain before it can be a cold
entry. S1 retains both owner grants locally along with the exact roots/read
originals and observed floors, without any future message ID. Sources and
replicas retain these grants with their live dependencies. The initial resource
and empty-head branches contain no future contact attempt. R commits pins,
usage and real jobs before releasing success. S1 records actual observations,
including partial replication; requested redundancy is not asserted as achieved.

## 6. Immutable message and explicit A disclosure consent

Reuse the existing immutable E and its existing context/JWE/profile, including
the single B recipient, original content bytes, 6 MiB envelope bound and
4 KiB context bound. E contains no delivery location, replaceable lease, ACK
grant, provider fact or maintenance assignment. Repair never changes E.

A signs `message.disclosure` **after E and before the attempt** with
`issued_at,expires_at,consent_id,root_key,slot_key,sender:DualID,
recipient:DualID,envelope_ref,maintenance_root_ref,allowed_roles,
operation_mask,consent_until,bootstrap_return,revision`. bootstrap_return is
specified in section 9 and permits this consent and its narrowly scoped
original status to the exact B reader during preflight. The ordinary allowed_roles separately permits the
necessary original A documents to the finite selected-slot B→M→P/D chain.
Neither signature grants plaintext access, new recipients or Vault trust.

Let S be the exact slot, M its maintenance_root and D this disclosure. Their
root/slot/sender/recipient and D.maintenance_root_ref must match; S's read grant
serving_authority_id equals M.authority_id. Require
`D.issued_at < D.consent_until <= D.expires_at`,
`D.expires_at <= min(S.expires_at,M.expires_at)` and
`D.consent_until <= min(S.windows.retain_until,M.windows.retain_until)`.
For each operation, intersect these deadlines with S/M's corresponding window,
applicable read grant, current status, exact assignment and resource windows.
This uses selected-slot authority only; discovery root/catalog is not a fallback.
It neither inherits nor extends the short original contact store window.
For the five Window operations use their exact matching field; discover uses
both read_until and publish_until, and renew may not extend any existing signed
window or promise. A renewal requiring a longer window needs new originals.
All seven operations still need their explicit allowed bit and current status.

A signs new `delivery.attempt` with `issued_at,expires_at,attempt_id,message_id,
envelope_ref,sender:DualID,recipient:DualID,destination_ref,slot_key,
operation=message.store,disclosure_ref,ack_grant_ref|null`. All refs already
exist. repair_v1 requires non-null disclosure; lack of consent cannot be
silently accepted as this profile's repair promise. ACK is optional for a
message, but a run without the independent ACK branch cannot satisfy ACK
recovery acceptance.

Original R independently verifies the complete original contact request,
policy, knock lease, approved decision, nested exact grant/delivery lease,
destination, selected slot, A consent, sender dual possession and current
original statuses. A recipient approval is not a replacement for R's real
resources. The original contact operation remains message.store only.
Data/meta reservations must cover actual E and the complete constructed
admission/enumeration closure before releasing custody success.

Idempotency keys are `(A signing ID,attempt_id)` for an exact attempt digest and
`(A signing ID,message_id)` for exact E. A changed attempt body conflicts; exact
retry returns the same sequence and result without renewed expiry or charge.
Repair copies an already admitted event under a different operation, with no
new A attempt or mailbox append.

## 7. Acyclic admission and cold range location

The construction DAG is normative; every RawRef must refer to bytes frozen
before the referring object. Implementations must reject a self-reference or
cycle rather than substituting a random key and an unspecified resolver.

```text
original A/B/R authorities + A attempt + historical statuses
    → H packs → historical.manifest
    → admission.core → B sealed_core → prefix checkpoint
    → admission.link → B sealed page + restricted repair_page
    → bounded range index → mailbox.feed_head
    → source custody event → reconstruction capsule
```

`historical.manifest` is an unsigned canonical **input** object with common
fields `schema_version,kind,variant,root_key,roles` and exactly the additional
fields of one of these six branches. No variant has nullable substitutes for
another phase. Each roles entry is `{role,document_ref,pack_ref,entry_index}`;
the registry determines its exact schema, expected signer and phase. Signed
entries preserve full original Signed wire; unsigned manifests/range objects
preserve their original canonical bytes and acquire authority only from their
validated typed signed parents. A pack is a finite ordered raw-byte container,
not an authority; no pack contains this referring manifest. Exact duplicate
bytes may share storage only after byte identity and fixed entry position are
proven. Otherwise both copies are charged. Sections 7.1–7.2 fix the candidate
role registry, repetition rules and exact pack representation used here.

| variant | Exact additional fields | Required originals, signer and temporal boundary |
|---|---|---|
| mailbox_root | root_authority_ref,catalog_ref,genesis_head_refs | B root/root_read/catalog and every catalog slot/read/maintenance, B root/feed bootstrap grants; original B allocation/activation and R offer/active/descriptor/status inputs; R count-zero checkpoints/heads. Every genesis head is count 0. Created after those bytes, before root.custody. No E, attempt, link or future custody. |
| mailbox_feed | slot_key,slot_ref,feed_head_ref,covered_interval:{start,end},subtree:{root_ref,parent_path_refs},members | Already signed R head/checkpoint, complete authenticated range/index/repair/sealed-page closure for the half-open nonempty interval, exact B selected slot/read/maintenance/bootstrap and resource chain, every covered member's existing historical manifest, A/B/R original roles and message.custody. Created after every covered member commit and head, before feed.custody. No future feed/P custody. |
| mailbox_member | slot_key,message_id,envelope_ref,attempt_ref | Exact original A/B/R admission inputs in the role table below, including A attempt/consent and selected-slot resource chain. Constructed before admission.core; no core/checkpoint/link/head/message.custody or future receipt. |
| ack_unbound | ack_slot,root_authority_ref | A root/read/ack_owner bootstrap, A allocation/activation, R offer/active/descriptor and required original statuses. Constructed before unbound ack.slot_custody. No E, write grant body, binding, B consent/receipt or future head/commit. |
| ack_empty | ack_slot,root_authority_ref,grant_ref,binding_ref | Complete earlier ack_unbound input closure plus its real unbound custody; A write grant/ack_offer bootstrap, R binding and applicable original statuses. Created after binding, before empty ack.slot_custody. No B receipt/disclosure/put or future occupied commit. |
| ack_occupied_inputs | ack_slot,root_authority_ref,grant_ref,binding_ref,receipt_ref,put_ref,disclosure_ref,admission_resource:ResourceRef | Complete existing empty closure and custody; exact B recipient.receipt/ack.disclosure/ack.put; A root/read/grant/bootstrap and actual receiver resource/current observations used at first admission. If first receiver is P, additionally the original M ACK-admit assignment/allocation, P offer, already committed empty replica.custody and resource generation/status. Created before this ack.commit. No future/self ack.commit, occupied head or replica result. |

Every role belongs to that root/slot/phase. Historical statuses use the actual
original event time and expected issuer, not a current replacement's summary.
Current operation statuses are resolved separately; an old historical status
is not silently reused as currently valid. Retain the original authority and
status raw bytes, not only their hashes. Manifest kind/variant substitution,
unknown roles, missing dependencies and excess objects are refusals.

mailbox_feed.members is an ordered complete array of
`{sequence,message_id,envelope_ref,historical_manifest_ref,admission_core_ref,
admission_link_ref,source_custody_ref}`. It contains exactly one entry per
sequence in `[start,end)`, all linked by the existing signed checkpoint and
range parents, with no gaps, duplicates or unrelated members. Each member
manifest must be mailbox_member and independently verifies that member's full
original admission; one last-message history cannot represent the interval.
The union also retains every applicable A consent and required observations.
Parent paths authenticate only the claimed subtree: they do not promise the
bytes or authorization of outside siblings. The represented interval and
checkpoint count must agree; a requested full-prefix promise requires complete
coverage from 0 to count. Empty genesis belongs only to mailbox_root. A source
may form this manifest only when its entire claimed interval is locally durable
or backed by concrete verified live dependency commitments under the same
budget; a signed head or a successful one-member read is insufficient.

mailbox_member has this fixed logical role registry (indexed resource/status
entries have exact schema/scope cardinality, not arbitrary bag semantics):

| Roles | Expected signer and checks |
|---|---|
| contact.request, delivery.attempt, message.disclosure | A; exact original request, attempt/message/E and selected-slot consent |
| contact.policy, contact.decision, contact.store_grant | B; approved exact decision and its unchanged nested grant |
| contact.knock_lease, contact.delivery_lease | Original R; exact original purposes/target/epoch and nested lease bytes |
| delivery.destination, mailbox.slot, mailbox.read_grant, mailbox.maintenance_root, bootstrap.mailbox_feed | B; one selected slot and its exact mailbox_feed bootstrap grant, never discovery root/catalog |
| resource.data_allocate, resource.metadata_allocate | B; actual mailbox_data/feed_metadata requests |
| resource.data_offer, resource.metadata_offer | Original R; exact request/intent/resource binding |
| resource.slot_activation | B; activation-only mailbox_slot with exactly the slot's two offers and slot/read/maintenance inputs |
| resource.data_active, resource.metadata_active, source.descriptor | Original R; same target/epoch, exact offers and existing slot activation |
| historical.status.disclosure | A; exact message.disclosure authority scope |
| historical.status.slot, historical.status.destination, historical.status.read, historical.status.maintenance, historical.status.bootstrap | B; exact selected slot and authority scopes |
| historical.status.data_resource, historical.status.metadata_resource | Original R; exact RootKey+ResourceRef scopes |

A single original status can satisfy several entries only if all scopes match
and disclosure of its **entire** raw document is authorized; no signed entry
projection is invented. Contact validity follows the unchanged contact rules
at accepted_at; neither an invented attempt.status nor current contact renewal
is required later. When attempt.ack_grant_ref is non-null, add only A's exact
ack.root_authority, ack.write_grant, ack_offer bootstrap grant and necessary
A-signed historical authority statuses as B's ACK lookup configuration. A's
message.disclosure must explicitly allow those exact A-owned configuration
roles to the message's permitted verifiers. Verify their A/B/message/E/root
bindings; do not include R ACK binding/custody/resource history in the mailbox
admission promise or give mailbox M the ACK maintainer's authority.

This deliberately separates configuration from actual ACK service validation.
A establishes and retains real S_ACK1 independently; the message custody result
makes no ACK availability assertion. B later verifies the **complete** independent
ACK service/resource/binding closure through ack_offer preflight and snapshot,
and cold A does so through ack_owner. Source ACK metadata is disclosed only
under its own original signer permissions. An A-signed pointer cannot stand in
for that later service check. Each historical branch retains its own explicit
bootstrap grants/statuses; no phase is filled with dummy or future documents.

### 7.1 Candidate closed role registry

The following registry and pack format are an explicit subsequent candidate
choice, not a claim that this increment has been reviewed or frozen. They fix
representation and phase dependencies without changing admission, disclosure,
preflight or snapshot authority. A constructor uses this registry, never a
caller-selected allowlist. Shape, byte identity and an acyclic local graph are
not signature, historical authority, current permission or custody acceptance.

Schema abbreviations below are exact: **Q** = memory-vault-open-repair/v1;
**C** = memory-vault-open-contact-control/v1; **D** =
memory-vault-open-delivery-control/v1; **N** = memory-vault-open-control/v1;
**T** = memory-vault-open-authority/v1. Except rows marked unsigned/JWE, an
entry is the complete original Signed object with the indicated payload schema
and kind. A means the exact message sender/ACK owner, B its recipient/mailbox
owner, R the node/epoch selected by the corresponding original resource or
SlotKey, and M/P the exact existing assignment issuer/target. These are derived
from original typed parents, never from the entry's self-provided signing key.

The existing mailbox_member role names above remain unchanged. Their exact
schema/kind mapping, plus the additional registered names, is closed here:

| Role names (each listed name is literal) | Exact schema / kind | Expected signer and logical scope |
|---|---|---|
| contact.request, contact.policy, contact.decision | C / same kind as role | A request; B policy/decision; exact attempt's original contact chain |
| contact.store_grant | C / contact.grant | B; exact decision.payload.grant, no substituted grant |
| contact.knock_lease, contact.delivery_lease | C / resource.lease | Original contact R; purpose knock/delivery respectively; delivery lease is exact grant.payload.resource_lease |
| delivery.destination, delivery.attempt, message.disclosure | Q / same kind as role | B destination; A attempt/disclosure; exact SlotKey/message/E |
| mailbox.root_authority, mailbox.root_read_grant, mailbox.catalog | Q / same kind as role | B; exact root/catalog version named by this manifest |
| mailbox.slot, mailbox.read_grant, mailbox.maintenance_root | Q / same kind as role | B; exact selected slot, or each exact catalog slot for mailbox_root |
| bootstrap.mailbox_root, bootstrap.mailbox_feed | Q / bootstrap.grant | B; consumer mailbox_root/mailbox_feed and exact corresponding root/read or slot/maintenance/read originals |
| ack.root_authority, ack.read_grant, ack.write_grant | Q / same kind as role | A; exact AckSlot and existing root/read/write binding |
| bootstrap.ack_owner, bootstrap.ack_offer | Q / bootstrap.grant | A; exact ack_owner/ack_offer consumer and its parent/caller originals |
| resource.anchor_allocate, resource.data_allocate, resource.metadata_allocate, resource.ack_allocate | Q / resource.allocate | B for anchor_catalog/mailbox_data/feed_metadata; A for ack_slot; exact original owner_intent |
| resource.anchor_offer, resource.data_offer, resource.metadata_offer, resource.ack_offer | Q / resource.offer | Corresponding original R/epoch; exact allocate request and purpose above |
| resource.anchor_activation, resource.slot_activation, resource.ack_activation | Q / resource.activation | B anchor or selected slot; A ack_unbound; exact section 4 activation scope and offers |
| resource.anchor_active, resource.data_active, resource.metadata_active, resource.ack_active | Q / resource.active | Corresponding original R/epoch; exact offer/activation/resource/purpose |
| source.descriptor | N / node | Required original R/epoch; the actual descriptor observation for the input event |
| genesis.head, genesis.checkpoint | Q / mailbox.feed_head, mailbox.checkpoint respectively | Each catalog slot's original R; count zero, exact head→checkpoint |
| feed.head, feed.checkpoint | Q / mailbox.feed_head, mailbox.checkpoint respectively | Exact SlotKey R; manifest.feed_head_ref and its checkpoint |
| history.member | Q / historical.manifest, unsigned, variant mailbox_member | Exactly members[i].historical_manifest_ref; derived scope is that member's SlotKey/sequence/message/E |
| member.core, member.link, member.custody | Q / admission.core, admission.link, message.custody respectively | Exact SlotKey R; each members[i]'s three explicit refs |
| member.checkpoint, member.head | Q / mailbox.checkpoint, mailbox.feed_head respectively | Original R; exact existing checkpoint/head referenced by that member's link/custody |
| range.index, range.repair_page | Q / range.index, range.repair_page respectively, unsigned | Exact authenticated current subtree/parent path or covered page; no independent signer |
| member.sealed_core, range.sealed_page | Existing byte-JWE profile described below; no outer Q kind/signature | Exact link.sealed_core_ref or repair_page.sealed_page_ref; recipient only B, authority comes from original typed signed parents |
| history.ack_unbound, history.ack_empty | Q / historical.manifest, unsigned, variant ack_unbound/ack_empty respectively | Exact predecessor manifest referenced by the corresponding original slot custody |
| ack.unbound_custody, ack.empty_custody | Q / ack.slot_custody | Original allocator R; exact state unbound/empty and AckSlot |
| ack.binding | Q / ack.binding | Original binding R; exact AckSlot/root/grant/resource |
| recipient.receipt | D / recipient.receipt | Exact B; unchanged validated_saved receipt bound to A/B/message/E |
| ack.disclosure, ack.put | Q / same kind as role | Exact B; manifest receipt/grant/binding and disclosure refs |
| admission.assignment, admission.allocate, admission.offer | Q / maintenance.assignment, resource.allocate, resource.offer respectively | M assignment/request; exact P offer; already committed empty replica's target/resource and ACK-admit scope |
| admission.empty_replica_manifest, admission.empty_replica_custody | Q / replica.manifest unsigned, replica.custody Signed respectively | Existing ack_empty replica; manifest is bound by exact P custody; not an occupied result |
| admission.descriptor | N / node | Exact P/epoch that will receive this first ACK |

All historical status roles map to **T / authority.status**, with complete
original Signed wire. The following names and target scopes are the complete
status registry; there is no wildcard historical.status.* role:

| Literal roles | Exact required scope / issuer |
|---|---|
| historical.status.disclosure | Authority scope of the exact message.disclosure / A |
| historical.status.slot | Stable SlotKey mailbox_slot scope / B |
| historical.status.destination, historical.status.read, historical.status.maintenance, historical.status.bootstrap | Authority scope of exact destination, selected read grant, maintenance root, mailbox_feed bootstrap respectively / B |
| historical.status.root, historical.status.root_read, historical.status.root_bootstrap | Authority scope of exact mailbox root, root read, mailbox_root bootstrap / B |
| historical.status.catalog | Catalog scope of this RootKey / B |
| historical.status.data_resource, historical.status.metadata_resource, historical.status.anchor_resource | RootKey + exact corresponding ResourceRef / that resource's original R |
| historical.status.ack_root, historical.status.ack_read, historical.status.ack_write, historical.status.ack_owner_bootstrap, historical.status.ack_offer_bootstrap | Authority scope of exact A ACK root/read/write/owner-bootstrap/offer-bootstrap respectively / A |
| historical.status.ack_slot | Stable AckSlot scope / A |
| historical.status.ack_resource | RootKey + original ack_slot ResourceRef / original R |
| historical.status.ack_disclosure | Authority scope of this exact B ack.disclosure / B |
| historical.status.admission_assignment | Immutable scope of exact M admission.assignment / M |
| historical.status.admission_resource | RootKey + actual admission_resource / its R or P issuer |

An authority scope is computed from the authority's exact kind and full wire
digest using section 3; a role alias is never used instead of the real kind.
Each required observation is the one used at its enclosing source event's
historical time. Nested predecessor manifests retain their own earlier event
observations; they are not flattened into the outer event or refreshed by it.
Resource offer/activation inputs are checked at their original event times,
not all at the outer event's time. Current operations still use the separate
current-status chain. Whole multi-entry status documents require every original
disclosure permission; matching one entry never authorizes exposing the rest.

The finite bundles below are notation expanded by implementations, not wire
roles. No bundle name appears in a roles entry:

- **SLOT_INPUT(slot)**: mailbox.slot, mailbox.read_grant,
  mailbox.maintenance_root, bootstrap.mailbox_feed; resource.data_allocate,
  resource.metadata_allocate, resource.data_offer, resource.metadata_offer,
  resource.slot_activation, resource.data_active, resource.metadata_active;
  source.descriptor for each actual original node/epoch required by these inputs.
- **SLOT_OWNER_OBS(slot)**: historical.status.slot, historical.status.read,
  historical.status.maintenance, historical.status.bootstrap.
- **ACK_OWNER_OBS(slot)**: historical.status.ack_root,
  historical.status.ack_read, historical.status.ack_owner_bootstrap,
  historical.status.ack_slot.
- **ACK_BOUND_OBS(slot)**: ACK_OWNER_OBS plus historical.status.ack_write and
  historical.status.ack_offer_bootstrap.

These six direct role sets are exhaustive. A nested history role recursively
uses its own same fixed variant table, with the same aggregate budget; it does
not import arbitrary outer roles. Referenced source events and their historical
manifests must agree byte-for-byte on every common binding.

| Variant | Required direct entries and exact repetition scope |
|---|---|
| mailbox_root | One each mailbox.root_authority, mailbox.root_read_grant, mailbox.catalog, bootstrap.mailbox_root; resource.anchor_allocate/offer/activation/active; historical.status.root/root_read/root_bootstrap/catalog/anchor_resource; source.descriptor for the anchor. For each distinct catalog.slot_ref, exactly SLOT_INPUT + SLOT_OWNER_OBS + historical.status.data_resource/metadata_resource + genesis.head/checkpoint for that slot. genesis_head_refs must identify exactly this head set; no nonzero head. |
| mailbox_member | Exactly the unchanged mailbox_member role table above, once per this message/selected slot/resource scope. If and only if attempt.ack_grant_ref is non-null, additionally ack.root_authority, ack.write_grant, bootstrap.ack_offer, historical.status.ack_root/ack_write/ack_offer_bootstrap for its exact A-owned configuration. No ACK read/resource/binding/custody role enters this variant. |
| mailbox_feed | Exactly SLOT_INPUT + SLOT_OWNER_OBS, historical.status.metadata_resource, feed.head/checkpoint. For each members entry: history.member, member.core/link/custody, member.checkpoint/head/sealed_core, and historical.status.disclosure for that member's original A consent at this feed source event. Include range.index for precisely the current covered subtree plus authenticated parent_path_refs, range.repair_page for every represented page, and range.sealed_page for each such page. Old member checkpoints/heads establish those existing member events; their outside-prefix children add no claimed range or permission. Original data-resource observations remain in history.member; no current old-R data lease is invented for a metadata-only feed promise. |
| ack_unbound | One each ack.root_authority, ack.read_grant, bootstrap.ack_owner; resource.ack_allocate/offer/activation/active; source.descriptor; ACK_OWNER_OBS and historical.status.ack_resource for the actual pre-E slot. |
| ack_empty | One each history.ack_unbound, ack.unbound_custody, ack.write_grant, bootstrap.ack_offer, ack.binding; ACK_BOUND_OBS and historical.status.ack_resource. Root/read/resource originals are reached through the exact predecessor; do not duplicate them as extra direct roles. |
| ack_occupied_inputs | One each history.ack_empty, ack.empty_custody, recipient.receipt, ack.disclosure, ack.put; ACK_BOUND_OBS, historical.status.ack_disclosure, historical.status.admission_resource. If admission_resource equals the original empty custody resource, the receiver is that R and all admission.* entries are forbidden. Otherwise require exactly admission.assignment/allocate/offer/empty_replica_manifest/empty_replica_custody/descriptor plus historical.status.admission_assignment; all must refer to the same already committed P empty replica and actual admission_resource. No future occupied commit/head is an input. |

For the P ACK branch, its original replica.manifest must cover exactly the
referenced original ack_empty closure and source event under section 4. All of
its physical_objects/edges are recomputed from those typed originals and the
same existing assignment/offer; no extra job, scope or body is permitted. It is
not a second role registry or a way to carry an unlisted occupied input. Its
replica.custody and assignment precede the new B receipt admission; assignment
must include the original root's exact ACK-only ADMIT/READ and earlier bootstrap
grants. A P resource receipt never substitutes for A/B/M originals.

Cardinality is per **logical obligation** in the table, derived from the
manifest fields and the complete original typed parents: a specific catalog
slot, member sequence, immutable authority digest, ResourceRef/node epoch or
page/path ref. Each obligation resolves to exactly one original observation,
not a list of alternative candidates. A single original may satisfy several
obligations only when every binding and historical observation matches. Emit
one roles entry per distinct `(role,document_ref)`; the same document may occur
under different required role names or scope obligations, but not twice under
the same role. No caller-supplied scope label or count overrides this derivation.

Order roles by `(role,document_ref.namespace,document_ref.key,
document_ref.raw_sha256,document_ref.size)` using Unicode code-point string
order and numeric size order. Order otherwise unordered RawRef sets, including
genesis_head_refs, by the same ref tuple without role. members remains ascending
sequence; parent_path_refs remains the range algorithm's root-to-subtree path
order, not hash order. Every referenced subtree/page must account for exactly
its covered entries; siblings present only as path commitments are not fetched
or authorized as members. Duplicate mappings, missing obligations, unsupported
roles/kinds or unresolved referenced raw originals are explicit refusal/pending
outcomes, never a complete accepted historical closure.

To remove unsigned-kind ambiguity, this candidate names the existing range
node kind `range.index`, and the existing B-private page plaintext kind
`range.private_page`, without changing their section 7 fields or range rules.
member.sealed_core and range.sealed_page are the unchanged General JSON byte-JWE
format of memory_vault_network_crypto: exact outer fields protected, recipients,
aad, iv, ciphertext, tag; protected typ memory-vault-network-bytes/v1 and enc
A256GCM; existing ECDH-ES+A256KW recipient framing and byte plaintext wrapper,
with exactly B's existing encryption key as recipient. They are not new Q
Signed documents or a new cryptographic profile. All existing sealer limits
and exact JWE validation remain in force.

The concrete context choice for the previously unnamed core seal is canonical
`{schema_version:Q,kind:admission.sealed_core,slot_key,sequence,
plaintext_sha256,plaintext_size}`, where plaintext is the already existing
full original Signed admission.core. For the page, the already specified AAD
fields use kind=range.sealed_page and hash/size of the canonical private page
plaintext; its start/end/slot must equal the exact repair page. These are
candidate context/kind assignments for new repair metadata only, never a
rewrite or upgrade of existing signed/encrypted artifacts. B later decrypts
and validates the original plaintext; an M/P parser checks the original JWE,
its parent ref/recipient/context and bytes without claiming decryption success.

### 7.2 Candidate original-byte pack framing

A pack has no signature, authority, compression, URLs, dictionary references
or mutable index. Its exact binary format is:

```text
ASCII "MVRP1" + 0x00                       (6 bytes)
entry_count                               (4 bytes, unsigned big-endian)
repeat entry_count times:
    raw_size                              (8 bytes, unsigned big-endian)
    raw_sha256                            (32 digest bytes)
    raw                                   (exactly raw_size bytes)
```

entry_count is positive and at most the uint32 representation bound and the
explicit finite enabled policy limit. Each raw_size is positive U53 and within
the explicit finite per-entry limit. Total pack size, entry count, decoded
metadata and aggregate work are checked against explicit policy **before**
allocation, buffering or hashing that work; these integer widths are format
bounds, not a claim that their maxima are feasible live policies. There is no
padding, trailing byte, optional field or alternate format. Validate the whole
frame length as `10 + sum(40 + raw_size)` using checked arithmetic. Native code
reads the uint64 length exactly and rejects values above U53 before conversion
to Number or allocation; rounding a length to fit is forbidden.

Entries are strictly ordered by `(raw_sha256 bytes,raw_size numeric)` and unique
by that pair. Identical original bytes occur once in a pack and may satisfy
several registered roles; differing bytes claiming the same digest/size are
rejected. Every entry in a pack presented for a manifest must be used by that
manifest's fixed direct or allowed transitive historical closure; no unrelated
entry is allowed. A request for one role grants no read of its entire pack:
full-pack transfer requires the original signers' permissions for every entry
under the actual consumer. A service-proof consumer may return permitted
individual original bytes from a locally verified pack; this does not certify
pack membership or historical closure without their later complete validation.
entry_index is zero-based and less than entry_count; offsets are derived by
checked accumulation of the preceding lengths, never taken from a caller's
untrusted offset table. Entry headers and their body bytes participate in the
full pack hash. The MVRP1 prefix is reserved: no entry body may start with
`MVRP1\0`, including an embedded pack.

pack_ref has namespace=meta, key=raw_sha256 of the **whole pack**, and its exact
full size/hash. Resolve and verify that whole pack, then the selected entry's
actual SHA-256/length against both its entry header and document_ref. The
original document_ref namespace/key remain exactly those named by the typed
parent; they are not silently replaced by the pack address or content hash.
A pack proves neither ownership of an opaque locator nor authorization to read
it. Distinct original refs sharing identical body bytes may point to the same
entry only after each independent parent/ref binding has been checked.

New Q unsigned/Signed metadata entries must retain their original canonical
wire. Old C/D/N/T originals retain their actual complete original bytes and
original schema validation; do not normalize, reinterpret int64 content as
U53, strip proof fields or reserialize nested originals. contact.store_grant
must equal the losslessly located original Signed object at decision.payload.grant;
contact.delivery_lease must likewise equal grant.payload.resource_lease. A
parsed projection or freshly serialized equivalent is insufficient. Parent and
nested bytes count as separate physical copies when both are in the pack.

All document bytes are frozen before the containing pack; all packs are frozen
before the referring historical.manifest; the source commit is later still.
A nested predecessor historical.manifest may be packed only after its own
packs exist, under the exact allowed earlier-phase role above. It cannot
reference this containing pack, itself or the outer/future manifest/commit.
Resolve typed references with a bounded active-path cycle check and one shared
visited/work ledger; aliases with the same full raw hash/size cannot evade a
cycle check by changing their opaque key. Existence in a caller's list or a
self-asserted timestamp does not establish original historical validity.

Charge every full original and every duplicate physical copy, pack header and
entry header, each actual entry hash and full-pack hash, encoded/decoded metadata,
index construction, temporary buffering/parse overlap and retained pins to the
same section 11 aggregate budget. Nested packs through historical references,
repeated roles and retries never reset it. Deduplication avoids only a physical
copy that is actually shared; it cannot erase independent obligations or
unperformed cryptographic work. No successful parse/pack construction issues
AcceptedAuthority, a resource promise, a snapshot handle or a custody result.

The local `build_raw_pack` / `buildRawPack` and `parse_raw_pack` /
`parseRawPack` implement this byte framing and derived index in the existing
draft wire modules. They return DraftPack only. They do not yet derive the six
variant obligations, inspect nested Signed/schema/phase references, enforce
complete role usage or graph acyclicity, verify signatures, or authorize any
network read. These checks remain required at the later manifest consumer.
Original node descriptors supply signing identity and epoch; the separate
encryption-key source and possession proof remain required for dual identity.
The old provider authority-kind allowlist does not accept the new Q kinds.

Their explicit local policy bounds the whole pack by max_document_bytes.
Each held pack and each derived index entry consume max_entries from the same
budget as the local resolver; retained_bytes accounts for pack bytes plus the
fixed 40-byte-per-entry index representation, not actual interpreter heap.
Builder inputs are conservatively checked before deduplication, every input
is read/hashed, and only byte-identical duplicates share final storage. Pack
index decoding consumes nodes. Input snapshots, construction buffers and actual
defensive/final output copies consume the shared cumulative input/output work
budget; language-specific physical copies are charged when they occur. Failed
work is not refunded; retained counters increase only for successful holdings.
This local meter does not claim to measure signature, disk/WAL, HTTP, allocator
overhead or the complete legal graph; enabled live policy still requires those
measurements and the full authority consumer.

Input/event/copy order is consequently:

```text
root originals + active + genesis → H(mailbox_root) → root.custody → root copy scope
message inputs → H(mailbox_member) → core/checkpoint/link/range/head → message.custody
complete existing interval + all member histories/custodies → H(mailbox_feed)
    → feed.custody → feed copy scope
A pre-E originals + active → H(ack_unbound) → unbound custody
A grant + real binding + unbound closure → H(ack_empty) → empty custody
B receipt/put/disclosure + actual existing admission resource → H(ack_occupied_inputs)
    → ack.commit → occupied copy scope
```

R signs these exact event payloads:

| Kind | Exact fields beyond common fields |
|---|---|
| `admission.core` | core_id,slot_key,sequence,message_id,envelope_ref,attempt_ref,historical_manifest_ref,data_resource_ref,metadata_resource_ref,accepted_at,object_until,enum_until |
| `mailbox.checkpoint` | slot_key,slot_binding,count,leaf_root,frontier,committed_at,retain_until |
| `admission.link` | slot_key,sequence,message_id,envelope_ref,core_ref,sealed_core_ref,historical_manifest_ref,checkpoint_ref,inclusion_path |
| `mailbox.feed_head` | slot_key,checkpoint_ref,count,range_root_ref|null,catalog_generation,committed_at,retain_until |
| `message.custody` | root_key,slot_key,message_id,envelope_ref,admission_link_ref,checkpoint_ref,feed_head_ref,resource_refs,stored_at,object_until,enum_until |

For this table, `resource_refs` is exactly
`{data:ResourceRef,metadata:ResourceRef}`. `root.custody` is the initial R-signed
event with `root_key,root_authority_ref,catalog_ref,genesis_head_refs,
historical_manifest_ref,resource_refs,stored_at,read_until,retain_until`; its `resource_refs` is exactly
`{anchor:ResourceRef,feeds:[{slot_key,data:ResourceRef,metadata:ResourceRef}]}`. Each feed resource corresponds to an
already authorized catalog slot; all refs precede the event. These are distinct
closed representations, not a generic bag of interchangeable resource kinds.
root.custody.historical_manifest_ref must be mailbox_root; core/link references
must be the same exact mailbox_member input manifest.

`feed.custody` is source Signed with
`root_key,slot_key,slot_ref,feed_head_ref,covered_interval:{start,end},
subtree:{root_ref,parent_path_refs},historical_manifest_ref,resource_refs,
stored_at,read_until,retain_until`. resource_refs is exactly
`{metadata:ResourceRef,dependencies:[{ref:RawRef,custody_ref:RawRef,resource:ResourceRef}]}`,
ordered by ref then resource. Its historical manifest is mailbox_feed and all
interval/head/subtree fields match. The source's original slot authority and
actual metadata resource authorize this service; each separately placed child
has a real already committed custody/resource/read-retention chain. The event
follows its manifest and local durable pins/index/usage, never precedes them.
It promises the whole declared interval's live dependency closure; it does not
pretend one message event promises the prefix. Its copy scope adds
`source_custody_ref` naming this existing feed.custody. Future feed replicas
retain this original source event, full interval history and direct M→P chain.

The current range-kernel design uses a depth-16 fixed tree, sequences 0..65535,
and the independently derived slot binding. Leaves commit sealed-core hash and
sequence; interior/empty domains remain distinct. Checkpoint commits the
accepted prefix only. **It has no active_tail_ref, page, link, head, custody or
capsule reference.** Inclusion proofs and prefix extension proofs use the
existing deterministic alignment/padding rules; unknown/forked heads are not
made trustworthy by a higher count. The full-count frontier case must be
specified identically in both runtimes.

After link exists, each B-private page has exact plaintext
`schema_version,kind,slot_key,start,end,entries`; each of at most 16 entries is
`{sequence,admission_link_ref,sealed_core_ref}`. It contains no future head or
its own ciphertext hash. Seal it to B using exact AAD
`{schema_version,kind,slot_key,start,end,plaintext_sha256,plaintext_size}`.
This digest describes transport metadata, not message plaintext. A changed
tail creates new immutable bytes.

`range.repair_page` is restricted metadata with
`schema_version,kind,slot_key,start,end,sealed_page_ref,entries`;
entries are the same finite tuples. It allows authorized M/P to copy opaque
dependencies without B's decryption key. It is never public provider output.
B decrypts the page and checks the two representations match. Inconsistent
tuples or missing complete original link/core evidence yield incomplete, not
an inferred admission.

The range index has fanout 16 and at most three levels over 4096 pages. Each
node has `schema_version,kind,slot_key,level,start,end,children`, whose entries
are `{start,end,ref}`. At level zero refs designate repair pages; otherwise
they designate the next lower level. Children are ordered, nonoverlapping and
cover their parent's represented prefix without gaps. The committed count
determines valid terminal ranges; each parent is checked before a child becomes
read-authorized. Index roots and changed paths are immutable and charged.

Index and page placement can be sharded. A feed custodian may retain a charged
subtree plus authenticated parent paths rather than every message or one huge
proof group. Each shard advertises its existing opaque key under an exact
finite assignment; the set of live obligations must still cover the complete
represented cold enumeration path. A signed head with unavailable children is
incomplete. Admission keeps bounded per-message paths, but one arbitrary path
is not assumed sufficient to reconstruct a whole prefix or every warm extension
proof. Moving a shard that discloses original member evidence requires every
included member's applicable A/B consent; a root allocation is not blanket
permission for unrelated originals. Per-shard work is metered within its parent
campaign, so splitting cannot reset total budgets.

feed_head is signed last, has count equal to its checkpoint, and a null range
root exactly at count zero. A nonzero head requires the real complete range
path. Same-generation conflicting heads, same-count different prefix roots,
and nonextending observed heads remain bounded conflicts. Catalog generation
is local to that writer incarnation, not a global mailbox ordering.

The custody event is released only after E, all required original evidence,
sealed metadata, link/checkpoint/range/head, usage, stable result, dependency
pins and jobs are durable. The reconstruction capsule refers to the completed
custody event and predecessor objects; predecessors do not reference it.
Response loss returns the original event bytes. Copying cannot extend its
historical promises. A provider-only storage event does not assert that a cold
recipient has walked this graph.

Cold B executes the actual chain:

```text
S1 K_B + root read authority
→ provider lookup(K_B) → protected root snapshot → B catalog/slots
→ provider lookup(stable feed_ref) → protected feed_head/checkpoint
→ range index → repair_page/B sealed page → original admission.link
→ original H/core/attempt/approval/consent → K_m
→ current scoped provider/custody/read chain → unchanged E
→ actual B decrypt/validate/save → signed B recipient receipt
```

Every new identifier and location comes from a verified parent or protocol
response. A test driver, diagnostic known-K_m read, publisher cache, or manually
injected replacement address cannot stand in for this chain. Independent slots
merge by signed admission identities; one slot's absence never deletes another.

## 8. Independent ACK: unbound, empty and occupied

ACK authority belongs to A, not B's mailbox or the original delivery node.
Its payload is only the existing exact signed B `recipient.receipt`, bound to
A, B, message_id and E raw ref. It is not encrypted chat, Memory, arbitrary
JSON or permission to reply. There is no ACK-of-ACK.

R3 makes this explicit privacy choice: authorized A-direct M and assigned P/D
may inspect the necessary original A/B/R signed receipt metadata for independent
verification. They do not receive E/plaintext/Memory/decryption keys. A-only
metadata confidentiality is **not** claimed while those verifiers receive
originals. A's root and B's later consent must both authorize their respective
original evidence. If this disclosure model is rejected at review, change the
protocol before implementation rather than claim an extra JWE hides disclosed
plaintext.

Choose AckSlot and grant_id before E. A allocates a real independent ack_slot
resource, then signs the following documents:

| A-signed kind | Exact fields beyond common fields |
|---|---|
| `ack.root_authority` | issued_at,expires_at,ack_slot,authority_id,owner:DualID,receipt_writer:DualID,original_resource_ref,original_resource_offer_ref,maintainers:[DualID],operation_mask,allowed_roles,max_bindings=1,max_receipts=1,budget,windows,max_delegate_depth=2,max_destinations_per_job,max_concurrent_jobs,revision |
| `ack.read_grant` | issued_at,expires_at,grant_id,ack_slot,reader:DualID,root_authority_ref,operation_mask,budget,windows,revision |
| `ack.write_grant` | issued_at,expires_at,grant_id,ack_slot,root_authority_ref,owner:DualID,receipt_writer:DualID,message_id,envelope_ref,operation=receipt.put,max_receipts=1,budget,windows,revision |

Root authority and read grant are created pre-E. The write grant is created
after E and refers back to the frozen root, using AckSlot's preselected grant_id.
The root never contains its future raw hash. One stable grant_id may bind only
one exact owner-signed grant body; another body is a retained conflict, not a
second message or last-writer-wins update.

Before S_ACK0, A creates the ack_owner bootstrap grant from its existing
root/read originals, signs the unbound resource activation, and the source
commits its actual active resource, complete ack_unbound input manifest and
unbound custody. A and each serving source/replica retain this grant and full
preflight service chain. S_ACK0 retains A's root/read/bootstrap/floors, without
E, a write grant or binding. The unbound slot can be copied under that phase.

After E exists, A creates its exact write grant and then the ack_offer bootstrap
grant for B; both precede submission and any bound commitment. The source
verifies and durably retains them before signing `ack.binding` with
`ack_slot,root_authority_ref,grant_ref,bound_at,resource_ref,retain_until` and
atomically publishes the empty-slot head. Only then is S_ACK1 captured: A
retains its root/read/write grant, both bootstrap grants, actual binding and
empty custody observations, E/message ID, anchor, floors and ordinary routing. A does not know any future B receipt,
ACK commit, replacement location or future head hash. A pre-E S_ACK0 cannot be
passed off as S_ACK1.

The initial node signs `ack.slot_custody` with
`ack_slot,root_authority_ref,historical_manifest_ref,resource_ref,stored_at,read_until,retain_until,state`
and exactly one state branch: unbound has no extra fields; empty has
`grant_ref,binding_ref`. The node issues the unbound event only after real
root/resource commit and the empty event only after real grant binding commit.
Its manifest variant is ack_unbound for unbound and ack_empty for empty.
The later empty commitment is not obtained by editing the original event.
An empty replica retains the actual empty commitment; an earlier unbound-only
replica cannot claim it has the binding just because A owns the root.

B receives the original root/write grant and ack_offer bootstrap grant through
the authorized delivery evidence before any cold probe. To learn the
preconfigured ACK offer/root, B completes section 9's locally authorized probe,
mutual possession and independent service-proof verification first. It then
reads only that limited offer closure. This is a
separate `ack_offer` purpose, not A's receipt-read permission. A grant with no
configured matching root, actual resource, or exact binding is unsupported.

After B's actual validated local save, B signs its original recipient receipt
and new `ack.disclosure` with `issued_at,expires_at,consent_id,ack_slot,
root_authority_ref,grant_ref,receipt_ref,recipient:DualID,owner:DualID,
allowed_roles,operation_mask,consent_until,bootstrap_return,revision`. The
closed bootstrap_return in section 9 permits returning this exact B consent
and its narrowly scoped original status to A; it does not grant a node
permission to receive B's receipt. B then signs `ack.put`
with `issued_at,expires_at,put_id,ack_slot,grant_ref,binding_ref,receipt_ref,
disclosure_ref,operation=receipt.put`.
Both documents precede any ACK custody result. The storage target verifies
actual A authority, B signature/dual possession, exact E/message binding,
the permitted receipt schema, B consent and its own active resources.

`ack.commit` is target Signed with `ack_slot,grant_ref,binding_ref,receipt_ref,
put_ref,disclosure_ref,historical_manifest_ref,resource_ref,stored_at,
read_until,retain_until`. Its manifest is exactly ack_occupied_inputs and
contains existing authority/receipt inputs but not this future commit. The source atomically commits
receipt bytes, exact originals, tuple→commit index, usage/result/pins/jobs,
then publishes an occupied head. No replica infers a put from a loose receipt
file or from B's statement that it saved something.

`ack.head` has `ack_slot,generation,observed_at,retain_until,state` plus exactly
the fields for its closed state variant:

| state | Additional fields |
|---|---|
| unbound | root_authority_ref |
| empty | root_authority_ref,grant_ref,binding_ref |
| occupied | root_authority_ref,grant_ref,binding_ref,original_ack_commit_ref,receipt_ref |
| conflicted | root_authority_ref,conflict_refs |
| incomplete | root_authority_ref,missing_role_codes |

There are no optional receipt placeholders. Empty/unbound are observations of
that provider's retained state, not proof of global absence. A reader holding
the S_ACK1 grant rejects an unbound/mismatched observation as insufficient.
Missing binding, tuple index, original proof or payload is incomplete, never
empty. An occupied replica preserves the original B/R evidence and signs only
its own later custody/head observation. It never signs a new B receipt.

A root can authorize M to move an empty slot to an unknown P **and to serve the
exact future B receipt under the already-bound A grant**. That future receipt
still requires B's new original signature and explicit disclosure consent.
This admit operation is ACK-only and is part of the root and exact target
assignment; plain copy permission does not imply it. Concurrent valid B retries
at multiple providers preserve the same logical identity and deduplicate at A;
different valid bytes for the same fixed slot remain conflicts. No cross-node
single transaction or global unique-writer claim is made.

If the empty slot moved before the first B receipt, the receiving P is the
original committer of that ACK event, while R remains the original allocator
and grant-binding witness. Its historical ACK closure therefore additionally
retains the exact M→P admit assignment and its allocation request, P offer,
actual earlier empty replica.custody, and current resource generation/status
used at that first commit. This is delegated activation by a real prior empty
replica commit; it is not a fabricated owner-signed resource.activation/active.
P signs its own ack.commit; the vanished R is not
required to sign or validate a future receipt. Later copies verify this direct
owner→M→P historical admission branch and the retained original A/R binding,
not a fabricated R receipt. These extra original roles must be included in
that branch's measured closure and cannot be hidden as only-current evidence.

Occupied repair copies receipt payload, historical manifest, original commit,
root/grant/binding, statuses, and the fixed lookup association. A replica is
complete only when all are durable. D advertises the stable ACK anchor and
validates its exact P and D authority chains. Cold A uses its original anchor
and preheld read grant to obtain a snapshot and learns the new commit/receipt
refs from that response. It independently validates originals and current
custody, then records receipt observed locally. No mailbox read grant, reverse
chat grant, or future-hash injection is required.

## 9. Bootstrap reads and complete proof snapshots

### 9.1 Owner permission before the first probe

All four cold entries have this mandatory order: caller locally validates its
complete owner-granted probe authority; a minimal permitted probe completes
mutual dual-key possession; the server returns its already-held complete
current service permission proof; the caller independently validates it and
each original signer's upload permission; only then can any private original,
stage descriptor/child, or B receipt be uploaded. TLS, an address, provider fact,
reservation, key possession or a node's boolean assertion never replaces this
proof. A server missing its required original proof refuses; it cannot ask the
caller to upload those originals in order to obtain that same proof.

Owner Signed `bootstrap.grant` has exactly
`issued_at,expires_at,grant_id,revision,owner:DualID,subject:DualID,root_key,
consumer,selector,parent_authority_ref,caller_authority_ref,probe_until,
proof_until,upload_until,probe_profile=opaque_v1,response_profile,upload_roles,
limits`. limits is exactly
`{max_probe_bytes,max_proof_bytes,max_proof_items,max_signature_checks,
max_requests,max_pending,max_replay_records,max_concurrent_handles,
max_candidate_attempts}` with finite positive U53 values bounded by the parent
budget and node policy. No absent field means infinity. All roles are ordered
unique entries of that branch's closed registry.

| consumer / response_profile | Exact opaque selector | Owner / subject; exact parent / caller authority |
|---|---|---|
| mailbox_root / mailbox_root_service_v1 | `{root_key_sha256,anchor_ref,root_authority_sha256,read_grant_sha256}` | B / root read reader; B root_authority / root_read_grant |
| mailbox_feed / selected_slot_service_v1 | `{root_key_sha256,slot_key_sha256,feed_ref,slot_sha256,read_grant_sha256,maintenance_root_sha256}` | B / selected read reader; exact B maintenance_root / read_grant |
| ack_owner / ack_owner_service_v1 | `{root_key_sha256,ack_slot_sha256,root_authority_sha256,read_grant_sha256}` | A / A; A root_authority / read_grant |
| ack_offer / ack_offer_service_v1 | `{root_key_sha256,ack_slot_sha256,root_authority_sha256,write_grant_sha256}` | A / exact B receipt_writer; A root_authority / write_grant |

Scope hashes use the canonical completed typed scope and raw-authority hashes
use full original wire. The caller already holds the exact grant and parent/
caller originals; the server recomputes hashes from its own full originals.
A hash is not a capability. mailbox_feed never falls back to discovery root or
catalog. ack_owner can be created pre-E with no future grant/binding field;
A's S_ACK1 local expectation still requires the exact later grant/binding.
ack_offer can be created only after the write grant exists. This new A grant
expressly gives B limited offer-service-proof READ; A's ack.read_grant does not.

Every bootstrap grant has its own required authority.status scope derived from
`bootstrap.grant` and its complete raw digest, signed by the expected owner.
All four profiles check that current exact grant status and durable floors as
well as parent/caller statuses. Historical manifests retain the observation
used at their original event. A still-active parent/read grant does not excuse
absent bootstrap grant status. The existing status bits have this exact mapping:

| Grant action | Required bootstrap-grant status bit, in addition to all actual parent/caller/target checks |
|---|---|
| opaque probe | DISCOVER (8); grants no head/content enumeration |
| proof challenge/manifest/handle/child service | READ (2), the limited service-proof purpose only |
| head.read and its evidence stage/upload | READ (2), for all four profiles and only their exact head purpose |
| B receipt.put and its original receipt/evidence upload | ADMIT (1), only ack_offer and ACK-only actual target admission |

The closed grant profile permits DISCOVER/READ for root/feed/owner and adds
ADMIT for ack_offer; it implies no other operation. Its owner parent must
explicitly permit that profile/action. The caller read/write authority still
narrows its own role: a write grant does not become a general read grant.
READ revocation stops both service-proof reads and head requests/uploads;
those cannot be independently revoked with this same bit. DISCOVER and ACK
ADMIT can be revoked independently where applicable. Separate deadlines can
narrow phases, but cannot relabel a revoked operation as another bit. A global
revoked status or known conflict denies all affected actions.

opaque_v1 authorizes this subject to expose only grant wire hash, exact selector,
consumer, subject/target public dual keys, target epoch, finite IDs/times and
possession nonce ciphertext/answers to a not-yet-authorized candidate. Opaque
anchor/feed lookup values and hashes disclose limited association and request
existence; they do not promise anonymity. First-round fields exclude full
RootKey/SlotKey/AckSlot and root/read/slot/grant/binding originals, private child
lists, metadata graphs, E/receipt bytes and callback URLs. The caller must
locally validate original grant/parents, expected keys, all windows and known
status floors before even this probe. Without that exact owner permission it
cannot send this selector to an unknown node.

This local first-step check concerns the still-valid original grant/parent
signatures, explicit probe_until and already-known revocation/conflict floors;
it does not require the unknown P's current assignment/resource/status first.
opaque_v1 expressly permits only this finite minimal probe when a previously
valid cached status has aged out but original grant/parent probe permission
has not expired and no known floor revokes it. That limited exposure is the
owner's explicit choice under the unknown-remote-revocation boundary in section
3, not renewal of an expired owner grant. It authorizes no private read/upload.
P still needs the complete currently valid local chain before returning proof;
C independently validates that current chain before any private transfer.

Every probe/proof/upload deadline is greater than issued_at and no later than
grant.expires_at, which is bounded by parent/caller expiry. Proof time also
intersects parent read/retain and caller read windows; ack_offer instead uses
its expressly granted offer-proof READ and the write grant's expiry/admit
window. Upload time intersects its actual operation: READ for root/feed/owner,
ACK-only ADMIT for receipt.put. All per-original signer consent, assignment,
resource/current status and retention windows still intersect these bounds.
Candidate attempts accumulate in one durable cold-run budget across retries;
this is not a global anti-abuse guarantee against a malicious caller.

### 9.2 Closed disclosure registry for service proof and uploads

An owner may permit only its own originals. M and every node must separately
permit their original request/assignment/event/status bytes, and A/B consent
must permit any cross-owner evidence. The owner's parent allowed_roles must
explicitly include the applicable bootstrap grant and service profile; a
replacement's exact maintenance.assignment names this earlier grant. Pure
index assignments do not get service roles through their publication purpose.
Original R service follows owner activation, actual resource and committed
source state, not a retroactive M assignment.

| Profile | Owner originals permitted in the service proof | Owner upload_roles (ordered subset only) |
|---|---|---|
| mailbox_root_service_v1 | B bootstrap/root/root_read, actual anchor activation inputs: exact B catalog/slots/read/maintenance, allocation and required historical/current B statuses | mailbox.root_authority, mailbox.root_read_grant, bootstrap.grant |
| selected_slot_service_v1 | B selected slot/read/maintenance/bootstrap, exact slot allocation/activation and B statuses; no catalog or discovery root | mailbox.slot, mailbox.read_grant, mailbox.maintenance_root, bootstrap.grant |
| ack_owner_service_v1 | A root/read/bootstrap, existing exact phase write grant, A allocation/activation and A statuses | ack.root_authority, ack.read_grant, ack.write_grant, bootstrap.grant |
| ack_offer_service_v1 | A root/write/bootstrap, A allocation/activation and A statuses; exact A read grant only if needed as original activation input | ack.root_authority, ack.write_grant, bootstrap.grant |

Service proofs include only actual permission dependencies and necessary current
service resource events, not all documents in a storage pack. Node-created
resource.offer/active/binding/custody and exact scoped resource statuses may be
returned only under their original signer's explicit service permission, not
a replacement P's assertion about what an offline R would have permitted.
Signing root.custody, message.custody, ack.slot_custody or ack.commit explicitly
permits return of that original signer's own complete resource.offer,
resource.active, exact ack.binding where applicable, source descriptor, source
custody/ack.commit, same-scope already-referenced mailbox.feed_head,
mailbox.checkpoint or ack.head where present, and narrowly scoped resource
authority.status under the subject/profile of the **earlier**
bootstrap grants in its exact historical closure. message.custody obtains that
closure through core/link→mailbox_member; it never points to a future feed
manifest. feed.custody makes the same commitment for its covered interval
without extending an earlier signer's permission. Empty ACK custody can name
its already existing ack_offer grant; unbound custody cannot authorize a
future grant. These signatures permit return of the event itself without
embedding a future self hash. The permission for referenced heads/checkpoints
covers only existing same-scope originals signed by that same issuer and
already included in the commitment's closure; it cannot point to a future head
or authorize another signer's bytes. An ack.commit's original issuer may be P
when P received the first receipt. A later P never grants permission on behalf
of an offline R or any other original issuer.

A replica.custody preserves those original finite permissions and permits its
own offer/custody/resource-status evidence only to the exact earlier grants
in its assignment. No replica can add a reader/profile/role for the offline
source. Source/replica statuses containing unrelated entries need independent
permission for every entry. This signed event semantics, same root/slot,
authorized subject/profile and current node authority are all required.
R's ack.binding may be transferred after preflight
only under that rule and the exact A grant/current P chain; A cannot sign R's
permission. M's assignment permission is limited to its own exact assignment,
its referenced allocation request and exact assignment-scope statuses as in
section 4. Neither may reveal another signer or unrelated job.

A message.disclosure and B ack.disclosure each have mandatory closed
`bootstrap_return={subject:DualID,consumer,roles,until}`:

- message.disclosure fixes subject to its original recipient B, consumer to
  mailbox_feed and roles to `[authority.status.disclosure,message.disclosure]`.
- ack.disclosure fixes subject to its original owner A, consumer to ack_owner
  and roles to `[ack.disclosure,authority.status.disclosure]`.

The disclosure role means this one complete original consent. The status role
means only complete original authority.status documents signed by that same
consent signer whose entries all concern this immutable consent's authority
scope. The scope digest is computed from the completed consent raw bytes;
no future self hash is embedded in bootstrap_return. For a multi-entry status,
every entry must independently have permission from that same original signer
to this exact subject/profile, otherwise reject the complete status; never
strip entries and present the result as its original signature. These same
rules apply to M assignment status and node resource status. Thus B's grant
cannot authorize A's status, nor A's grant B's status.

until intersects consent expiry/consent_until, selected maintenance or ACK root
read/retain windows and current status. This permits returning the consent
and narrowly scoped status, not A contact/attempt or B receipt/put. It does not
permit uploading that consent to an unknown P. Old signed consents without
this field do not support this profile; no node may infer or add it. The normal
content/historical phase still uses its exact original disclosure/read roles.

### 9.3 Two-way possession and protected service proof

Every message below has the signed common fields plus exactly the listed
fields. IDs are fresh bounded opaque IDs, nonces are fresh random 32 bytes,
nonce answers are canonical Base64url, and keys/epoch match the exact target.

| Kind / signer | Exact additional fields |
|---|---|
| bootstrap.probe / caller C | issued_at,expires_at,probe_id,subject:DualKey,target:DualKey,target_storage_epoch,purpose=bootstrap.service_proof,consumer,selector,bootstrap_grant_sha256,target_nonce_jwe |
| bootstrap.challenge / target P | issued_at,expires_at,challenge_id,probe_ref,subject:DualID,target:DualID,target_storage_epoch,purpose=bootstrap.service_proof,consumer,bootstrap_grant_sha256,target_nonce_answer,caller_nonce_jwe |
| bootstrap.answer / C | issued_at,expires_at,challenge_ref,probe_ref,subject:DualID,target:DualID,target_storage_epoch,purpose=bootstrap.service_proof,consumer,bootstrap_grant_sha256,answer |
| bootstrap.proof_handle / P | issued_at,expires_at,handle_id,probe_ref,challenge_ref,answer_ref,subject:DualID,target:DualID,target_storage_epoch,purpose=bootstrap.service_proof,consumer,bootstrap_grant_sha256,service_generation,manifest_ref,child_count |
| bootstrap.proof_child_request / C | issued_at,expires_at,request_id,subject:DualID,target:DualID,target_storage_epoch,purpose=bootstrap.service_proof_child,consumer,probe_ref,handle_ref,manifest_ref,service_generation,child_index,offset,requested_bytes |

C encrypts its nonce to P's exact X25519 key; probe AAD is all payload fields
except target_nonce_jwe. P checks bounded parser/target/epoch/signature/time/
replay, then resolves its **local complete** grant, expected owner/caller,
original/current service authority, consent, exact resources and known floors
by `(grant hash,subject,consumer,selector)`. All parsing/network/crypto stays
outside writer locks; under lock it rechecks state and reserves bounded
challenge/response/pin charges. Missing local raw authority, required historical
input, committed custody or active resource yields generic unavailable or
incomplete, with no upload request or private head/child/state output.

P decrypts and returns C's nonce, and encrypts a new nonce to C's X25519 key;
challenge AAD is every payload field except caller_nonce_jwe. The challenge
contains only the authorized probe binding and nonce fields, never a head
state, receipt ID or private child list. C verifies exact P signature/dual IDs/
epoch/probe hash/grant hash/window and its own nonce before decrypting P's
nonce. C then signs the answer. P constant-time checks exact bindings and nonce,
consuming one-use durable state. These are separate domains from contact,
delivery, stage and snapshot challenges. Both sides proving their keys still
is not service authority.

Only after caller possession, P rechecks the pinned current generation, full
authority, budget and floor/resource state. It freezes an unsigned
`bootstrap.proof_manifest` with exactly
`schema_version,kind,probe_ref,subject:DualID,target:DualID,target_storage_epoch,
consumer,selector,bootstrap_grant_ref,service_generation,response_profile,
children:[{index,role,ref:RawRef}]`, then signs the handle referring to it.
The manifest has no future handle ref. Children are the permitted exact full
original bytes, never projected signatures. Manifest and bytes are available
only to this authenticated subject under this profile.

The successful response is the exact unsigned canonical
`bootstrap.proof_response={schema_version,kind,handle_raw_base64url,
manifest_raw_base64url}`. It returns both the full original Signed handle wire
and the full frozen canonical manifest wire **inline in this same response**,
only after mutual possession. Decode both exactly; verify the P signature,
all probe/answer/subject/target/generation bindings, handle.manifest_ref size/hash,
manifest expected selector/profile/grant and handle.child_count before using
any child identifier. Both encoded and decoded sizes count to the original
response/proof budget. This complete response must fit the existing control
response limit and enabled measured policy. If its manifest cannot fit, refuse
before issuing a usable handle; do not return a handle alone, require a private
upload, or invent an unbounded manifest locator. The child request therefore
starts from a manifest the caller has actually received and validated.

Each proof_child_request is fresh Signed, binds the **full original handle**
and manifest refs, and retains the same subject/target/epoch/probe/consumer/
generation. It requests a positive finite range within one declared child;
requested_bytes fits the existing frame cap. The signed request itself stays
within existing control/header bounds. P checks request uniqueness, handle
window and current generation on every read, charges the shared work ledger,
and returns exactly that child range. The client checks child size/hash after
assembly. This is not a head.intent or a bearer handle. Changed or missing
bytes invalidate the generation; never switch silently to another proof.

### 9.4 Complete permission closure at the client

The client verifies its local grant and every full original RawRef needed for
permission: expected owner/caller parents, current owner/consent/status chain,
actual target descriptor/epoch and resource ledger evidence. Replacements
add exact original owner→M authority, M→this P assignment naming this grant,
M allocation request, P offer, live generation/resource statuses and already
committed scope custody. Original R adds owner activation/active, their complete
inputs, and real source custody. Neither provider facts nor unactivated offers
substitute. READ is necessary for root/feed/owner; ack_offer additionally
requires explicit ACK-only ADMIT for that exact bound slot and real capacity.
A READ/COPY-only replica cannot receive the first B receipt.

Root uses its exact anchor scope. Feed uses only selected slot/read/maintenance
and the exact covered feed/member scope; each necessary A consent/status also
passes its bootstrap_return rule. ACK owner uses A root/read and the phase
matching A's retained grant/binding; occupied permission needing B consent
requires B's explicit return rule. ACK offer uses A's exact write/bootstrap
grants, original binding, actual empty source custody and, at P, already
committed exact empty replica.custody plus M ACK-admit/read authority. If
original activation references A's read grant, the new A bootstrap grant must
expressly permit returning it to B as a historical activation input. Its reader
stays A; B gains no general ACK-owner read scope.

An unbound-only replica cannot serve ack_offer merely because A later bound
the grant elsewhere. It must first commit the full exact empty closure with a
new applicable assignment naming the already existing ack_offer grant, real
resources and valid ACK-admit/read operations. The old unbound assignment and
pre-E grant confer no binding or receipt permission by implication.

No RawRef actually used to derive an assignment's scope, delegation permission,
consent membership, resource activation or current serving right may be omitted.
Its whole dependency chain and each original signer's exact disclosure permit
must close within the applicable profile. A claimed custody event does not
excuse a missing historical premise of that permission. If a particular chain
requires A contact/attempt, B receipt/put or any other raw input excluded by this
profile, it is unsupported/incomplete at preflight, rather than permission
success based on an unexplained hash. Implementation must enumerate and review
these edges for every original/copy variant; it cannot relabel them content-only.

Only references that do **not** participate in any such permission inference
may await the later content-integrity snapshot (for example an already separately
authorized opaque payload's bytes). Their bytes/admission/history are not marked
verified at preflight. The server nevertheless needs its complete local original,
historical and current evidence before offering service proof. Successful
preflight grants neither content validity, object readability, global freshness,
observed empty ACK nor a validated B save.

### 9.5 Bind every subsequent request before uploading

After complete client verification, record the local non-authority tuple
`(probe_ref,manifest_ref,target,epoch,consumer,selector,service_generation,
verification_deadline)`. Recheck each outgoing original's signer permission
and current exact target scope before transfer, including B's own receipt and
ack.disclosure. A's ACK grant cannot permit B's originals on B's behalf.

Caller Signed `bootstrap.use` has
`issued_at,expires_at,use_id,subject:DualID,target:DualID,target_storage_epoch,
consumer,operation,bootstrap_probe_ref,bootstrap_manifest_ref,request_ref`.
operation is exactly head.read, proof.stage or ack.put; ack.put is permitted
only with consumer=ack_offer. request_ref names the already-frozen original
head.intent, proof.stage_intent or ack.put respectively, with the same signer.
Both endpoints bind it to the verified selector/target/epoch/generation and
unexpired proof context before accepting any body or child. There is no
cross-root/profile use and no use whose request points to itself.

An immutable B ack.put remains target-independent: a new P requires a new
verified preflight and outer bootstrap.use, not a changed receipt/disclosure/
put body. Before sending any of those originals or their stage descriptor,
B verifies actual ACK-admit authority and its own exact disclosure consent.
A failed preflight cannot be bypassed by calling receipt.put directly.

### 9.6 Protected head and inline/staged evidence

`head.intent` is reader Signed with `issued_at,expires_at,intent_id,
subject:DualKey,target_node_key_id,target_storage_epoch,purpose,root_key,
selector,preheld_authority`.

Purpose and selector are closed pairs:

- mailbox_root: `{anchor_ref,minimum_catalog_revision}`;
- mailbox_feed: `{slot_key,feed_ref,checkpoint:null|{count,leaf_root,slot_binding}}`;
- ack_owner: `{ack_slot,phase:unbound,root_authority_ref}` or
  `{ack_slot,phase:bound,grant_ref,binding_ref}`;
- ack_offer: `{ack_slot,grant_ref,root_authority_ref}`.

preheld_authority is one of two exact representations of this purpose's
originals, and is sent only with an already-authorized bootstrap.use:

- inline: `{mode:inline,manifest_ref,manifest,children}` where manifest is the
  exact proof.stage_manifest defined below and children is the complete ordered
  array `{index,raw_base64url}` for every declared child. Verify the manifest's
  full canonical hash/size, each decoded child's exact bytes and declared ref,
  fixed role/order and complete set within existing control limits.
- staged: `{mode:staged,manifest_ref,stage_result_ref}` with no embedded children.
  The result is the target's original Signed proof.stage_result for that exact
  manifest, consumer, root/selector, subject/target/epoch and same bootstrap
  probe/manifest context. Resolve its full raw bytes and still-live pinned
  children locally, not a bearer token or cross-session stage ID.

The manifest contains B root/read/bootstrap originals for mailbox_root;
selected B slot/read/maintenance/bootstrap for mailbox_feed; A root/read/
bootstrap for unbound ack_owner and additionally its exact write grant and
authorized binding for bound ack_owner; A root/write/
bootstrap for ack_offer. Required current observations follow the closed role
registry and original signer permissions. Any additional required permitted
original has its exact typed role; arbitrary surplus refs are refused.
P reuses already held exact bytes instead of demanding redundant uploads.
All transmitted, staged and target-local originals count toward one budget.

Before issuing a snapshot, the server verifies this expected caller, target,
root and purpose, resolves and pins its own **complete** current serving chain,
checks highest known floors/resources, and resolves the requested stable
index. No network fetch occurs under its validation/SQLite lock. Missing local
proof produces incomplete; the server cannot defer a required permission
check until after disclosing private data.

If the complete preheld pack exceeds the existing control limit, use a
purpose-specific protected proof stage only after the complete section 9.1–9.5
preflight, not merely target dual-key proof.
Stage permission is only bounded provisional storage, never application
authority. It does not authorize disclosure of an unrelated root or any
private third-party evidence. Failure must remain explicit; silently widening
the control limit is not the fallback.

The staged variant is closed as follows. `proof.stage_manifest` is an unsigned
object with `schema_version,kind,consumer,root_key,scope,children`; consumer is
one of mailbox_root/mailbox_feed/ack_owner/ack_offer/custody_accept/index_admit,
and each child is `{index,role,ref}`. The scope is exactly that consumer's
selector or resource scope, not a general metadata URL. A caller signs
`proof.stage_intent` with `issued_at,expires_at,allocation_id,
subject:DualKey,target_node_key_id,target_storage_epoch,manifest,
manifest_sha256,requested_bytes,requested_items` before allocation. The full
intent remains inside the control limit; excessive descriptor complexity is
refused, not recursively split into another unbounded descriptor network.

After its own finite staging reservation and caller dual-key challenge, the
node signs `proof.stage_handle` with `issued_at,expires_at,handle_id,
intent_ref,subject:DualID,target_node_key_id,target_storage_epoch,
manifest_ref,bootstrap_use_ref,reservation_generation,reserved_bytes,reserved_items`.
For the four cold consumers bootstrap_use_ref names the already verified exact
proof.stage use, whose request is this stage_intent and whose verified context
matches the manifest. For custody_accept/index_admit it is null: those separate
M-initiated consumers require full original owner/consent→M→exact target
allocation/assignment disclosure authority and target dual possession locally
before staging; null never permits bypassing a cold consumer's preflight.
The preceding `proof.stage_challenge` has exact fields
`issued_at,expires_at,challenge_id,intent_ref,subject:DualID,
target_node_key_id,target_storage_epoch,purpose=proof.stage,jwe`;
all fields except jwe form its AAD for a fresh 32-byte subject nonce. The
subject's `proof.stage_answer` has `issued_at,expires_at,challenge_ref,
intent_ref,subject:DualID,target_node_key_id,target_storage_epoch,
purpose=proof.stage,answer`. Its canonical nonce, exact intent/target/purpose,
one-use durable state and finite intersected window are verified before a
handle is released. Neither object references the future handle or result.
Binary child transfers have only the new binding
`{kind:repair_proof_child,handle_id,child_index,offset}` and use fresh signed
headers within the existing frame/header limits. This is a new binding to
implement, not something the old blob parser is assumed to accept. It cannot
write an undeclared child, read existing stored data, or upload E through a
metadata allocation. Exact child size/hash and total stage charges are checked.

`proof.stage_close` takes the same intent/handle identity and no new child list;
it returns a node-signed `proof.stage_result` with
`subject:DualID,target_node_key_id,target_storage_epoch,intent_ref,
manifest_ref,bootstrap_use_ref,reservation_generation,closed_at,expires_at` only when all named
original bytes are locally complete. This result means completed provisional
bytes, never verified application authority. The subsequent semantic consumer
combines those exact pinned bytes with required target-local evidence, verifies
the complete original/current chain under the parent budget, then either
atomically promotes the required objects and their charges or refuses.
A staged head.intent is created only after stage_result exists, then gets its
own head.read bootstrap.use. Its manifest_ref equals both stage_intent's
manifest hash and stage_result.manifest_ref. The original stage bootstrap.use
and later head use must name the same verified bootstrap probe/manifest and
exact target/epoch/profile; their inner request refs differ as prescribed.
No stage_result or head intent is a prerequisite of its earlier stage intent.
The stage handle, child transfers, close and result stay bound to that original
stage use and its pinned generation. An expired stage is not reused under
another consumer, root, subject, epoch or preflight context. Any promoted live
proof survives stage cleanup under its real resource pins.

A snapshot manifest is an unsigned closed object with
`schema_version,kind,root_key,selector,generation,state,children`;
each child is `{index,role,ref}` in contiguous index order starting at zero.
Its children cannot include this manifest itself, any future handle or future
proof. Only the exact purpose/state's closed role set and existing original
bytes are permitted. The manifest is frozen before the challenge. The server signs a fresh challenge binding the complete intent raw hash, subject,
target keys/epoch, purpose, snapshot raw ref and a fresh encrypted nonce. The
subject signs the answer to that exact challenge. This challenge domain is
distinct from contact submit/result and ordinary delivery/blob challenges.

The target-signed `snapshot.challenge` exact fields are
`issued_at,expires_at,challenge_id,intent_ref,subject:DualID,
target_node_key_id,target_storage_epoch,purpose,root_key,selector,generation,
snapshot_ref,jwe`; JWE encrypts one fresh 32-byte nonce to the authorized
subject X25519 key with all other payload fields as exact AAD. The
subject-signed `snapshot.answer` fields are
`issued_at,expires_at,challenge_ref,intent_ref,subject:DualID,
target_node_key_id,target_storage_epoch,purpose,answer` where answer is the
canonical Base64url nonce. Compare all bindings and nonce in constant time;
use one-use, durably charged challenge state. Expiry intersects original
intent, current read scope, snapshot pin and node's finite challenge policy.
An answer cannot extend any of them. No future final RPC hash appears in its
own challenge.

After accepting the exact one-use snapshot.answer, recheck the pinned
generation, current authority/floors, read pins and quota. The target signs
`snapshot.handle` with exact additional fields
`issued_at,expires_at,handle_id,intent_ref,bootstrap_use_ref,subject:DualID,
target_node_key_id,target_storage_epoch,purpose,root_key,selector,generation,
snapshot_ref,child_count`. bootstrap_use_ref is the already verified head.read
use from section 9.5, not a new permission or a future request reference.

Success returns the unsigned canonical control object
`snapshot.response={schema_version,kind,handle_raw_base64url,
snapshot_manifest_raw_base64url}`. Both fields contain **all original bytes**:
the exact target Signed handle and the already frozen canonical snapshot
manifest, inline in the same authenticated response. A handle alone or a
manifest hash alone is not success and cannot require an undisclosed locator
or a preliminary child read. The full encoded response, decoded originals and
retained response/pin overlap must fit the existing control limit and the same
enabled cold-run budget. If they do not fit, refuse **before issuing a usable
handle**; no usable partial response, silent cap increase or upload-first
fallback is allowed.

C first bounds and strictly decodes both byte strings, verifies canonical
closed schemas and the expected target's full handle signature, then checks
intent_ref, bootstrap_use_ref, subject, target/epoch, purpose, root/selector,
generation, windows and the exact snapshot_ref against its accepted challenge
and preflight/head context. Verify manifest full original size/SHA-256 against
snapshot_ref, its own root/selector/generation/state, contiguous child indexes,
child_count and the complete closed role set before using any child identifier.
Check original-signer disclosure permission for each role. A manifest entry
only names a child; it does not validate the child's contents or expand read
scope. In particular, an unknown E, ACK commit or receipt ref is learned here
only through this validated response and later authorized typed children.

Each chunk read uses a fresh caller Signed `snapshot.child_request` with exact
additional fields
`issued_at,expires_at,request_id,subject:DualID,target_node_key_id,
target_storage_epoch,purpose,intent_ref,bootstrap_use_ref,handle_ref:RawRef,
snapshot_ref:RawRef,generation,child_index,offset,requested_bytes`.
The purpose is the same one of the four head purposes, never a general blob
read. handle_ref binds the complete original Signed handle bytes, not just its
handle_id. For locally constructed references to this handle or a child request,
use namespace=meta, key=raw_sha256 of its complete original wire and the exact
size; this content binding grants no network lookup permission. snapshot_ref
is the exact ref already authenticated by the handle, not a guessed hash.
The request's subject signature, all identities, intent/use/handle/snapshot refs
and generation must match the retained context. No request, handle or result
can be reused with another preflight, even if its root and target are unchanged.

Use the existing MVOB1 binary frame envelope from memory_vault_open_blob.py
and open-blob.ts: magic bytes, two big-endian uint32 lengths, full canonical
Signed header bytes and the exact raw chunk. A snapshot.child_request frame
has its Signed request as header and an empty chunk. This new repair-schema
consumer must explicitly validate these kinds; the old blob.request/response
verifier does not thereby accept them. Keep the existing prefix, header and
chunk bounds and fixed aligned download ranges: offset is U53, less than the
selected child size and a multiple of MAX_BLOB_CHUNK_BYTES; requested_bytes is
positive and exactly min(MAX_BLOB_CHUNK_BYTES, child.size-offset). This selects
one existing frame/range convention without widening the old transport limits.

The target's response frame has a Signed `snapshot.child_response` header with
exact additional fields
`issued_at,expires_at,request_ref:RawRef,subject:DualID,target_node_key_id,
target_storage_epoch,purpose,bootstrap_use_ref,handle_ref:RawRef,
snapshot_ref:RawRef,generation,child_index,child_ref:RawRef,offset,length,
chunk_sha256:H`, followed by exactly length raw bytes. request_ref binds the
entire fresh Signed request; child_ref equals the selected manifest entry;
length equals requested_bytes. Response expiry cannot exceed the request,
handle, preflight/read or pin window. C verifies the expected target signature,
all request/context/child/range bindings and actual chunk length/SHA-256 before
accepting bytes, and verifies the full child's RawRef when assembly completes.
Neither a valid frame nor a chunk hash substitutes for the child's original
signatures and semantic authority checks.

Before **every** read, the server rechecks current authority/floors, exact
preflight/use binding, target epoch, generation, read pins, declared role/range,
request replay state and shared remaining budget. Changed or missing bytes
invalidate that snapshot; do not silently switch generations. Requests,
responses, encoded/decoded control copies, both frame headers/prefixes, actual
chunk bytes, work and response/pin overlap all charge the original cold-run
budget with finite node/subject concurrency and one parent deadline. A chunk,
retry or internal consumer never resets that budget.

At the reader, downloaded refs must match exact size/hash, expected signatures,
root/scope/time/resource chain and verified parent membership before gaining
any new read scope. Snapshot signatures prove what the server supplied, not
that the contents are true or globally latest. Completion labels distinguish
observed prefix, observed empty, incomplete, conflict and exhausted budget.

## 10. Provider publication and lifecycle

Public provider responses stay opaque: lookup ref, provider node/epoch,
custody alias, provider-local revision, short validity and actual index lease.
They never contain the mailbox membership graph, private proof packs, grant
lists, receipt metadata or message plaintext. A provider fact is an availability
claim, not proof of stored bytes or permission to retrieve them.

Before a directory accepts a repair_v1 fact it verifies the full applicable
historical owner/consent chain, P's current exact custody/resource/assignment,
its own distinct M→D assignment/resource, publication scope and highest known
status. Existing owner-only `provider.publication.grant` can remain for the
already implemented branch; it cannot be silently used as the M-delegated
branch or as a signed assertion that original admission was valid.

The source/target state machine is:

| State | Required durable condition |
|---|---|
| PREPARE | exact job/intent, finite local and target reservations, valid root/consent and current target proof |
| COPY | charged staged bytes, verified size/hash prefixes, cumulative work ledger; no public custody success |
| COMMIT | exact bytes, originals, membership/slot index, pins, usage, stable result and necessary jobs atomically published locally after durable files |
| ADVERTISE | actual bounded directory acceptance under a real lease; no assumed reachability |
| USABLE | independent lookup and permitted exact-byte readback; for messages the original cold-anchor enumeration chain also succeeds |
| RETIRE | explicit release or applicable expiry permits retiring source obligations; live promises never disappear solely because another node says COMMIT |

Object-readable, message-discoverable, B-validated-saved and A-receipt-observed
are separate recorded predicates/times. A completed data copy cannot stand in
for enumeration or ACK recovery. Index/data/enumeration replica counts are
independent. Multiple processes on one machine are one physical fault domain.

Repair jobs are durable due-index work with original job ID, scope, immutable
source refs, parent authorizations, requested replica targets, deadline,
attempt/byte/work totals, per-target stable allocation/result, next_due and
state. Trigger on due renewal, failed allowed probe, source drain, observed
resource/epoch loss, or placement change. Preserve original counters across
restart/pump. A new campaign cannot reset an earlier acceptance stopwatch.

Merge provider facts additively by provider key/epoch/custody ID and its local
revision. One provider cannot withdraw another. Merge independent slot
admissions by signed identities; retain same-writer forks and status conflicts.
No scalar last-writer-wins provider set or global repair leader is introduced.

If a required original object or association is no longer reachable, expose
the exact incomplete dependency. A timeout is not proof of permanent loss.
Only an external fault oracle in a controlled experiment can declare all valid
copies destroyed. Copying or re-signing a provider fact never renews owner
authority or historical data promises.

## 11. Proof roles, byte budgets and GC

The old 31-Signed/C512 estimate is **not carried forward** as a sufficient
bound. No new fixed aggregate byte cap in this candidate is claimed feasible
without real serialization and complete semantic validation in both runtimes.
The existing control limit, 8 KiB blob header, 256 KiB chunk, and 6 MiB E limit
remain constraints of the current transport; new proof staging and every new
kind need their own closed, finite negotiated node policy before acceptance.

Required proof sets are derived by phase, not by filling absent authority with
dummy documents:

| Phase | Required originals/current dependencies |
|---|---|
| empty mailbox root | B root/catalog/read, selected slots and relevant maintenance/read roots, actual original resources, genesis checkpoint/head, original statuses, current serving resource/assignment/status if copied |
| initial message | exact contact request/policy/knock lease/decision/nested grant/delivery lease, B destination/slot/read/maintenance root, A attempt/disclosure, applicable ACK grant, original descriptor/resource/status observations, E and generated admission/range/custody closure |
| message copy | all required original admission evidence plus complete live range dependency closure, M→P exact assignment/offer, current owner/consent/assignment/resource observations |
| directory publication | relevant originals plus committed P custody/fact and its chain, separate M→D offer/assignment/status; the new D index lease is output |
| unbound ACK | A root/read, actual original resource and state, original/current required statuses; no future grant or B receipt |
| empty ACK | unbound originals plus A write grant and source binding; no fabricated B consent/receipt/commit |
| occupied ACK | exact A root/read/grant/binding, B receipt/put/disclosure, original ACK commit/manifest/resource/status and complete current serving chain |
| mailbox feed interval | H(mailbox_feed), every covered H(mailbox_member)/core/link/custody and original roles, complete exact head/range/path/page closure, independent feed.custody, actual live dependency resources and member consents |
| service preflight (each of four profiles) | locally held owner bootstrap/parent/caller/status chain; full allowed current owner/consent/M/node service closure; mutual nonce objects, proof manifest/handle/requests and original status return permissions; no uploaded private originals before completion |
| cold read | actual inline/staged preheld originals after preflight, complete target-local proof, bound bootstrap.use and stage results, snapshot.response with full original handle/manifest inline, Signed snapshot.child_request/response frames, assembled children and decoded metadata, with all encoded/decoded copies and pins accounted |

The role registry must distinguish historical and current status, original and
replacement resource, message and ACK roots, checkpoint and feed_head, repair
and sealed pages, range indexes, manifests, source versus replica custody and
conflict witnesses. Each allowed role names one exact schema and expected
signer/phase. Node receipt summaries cannot replace original A/B signatures.
Every consumer resolves the union of caller-supplied and pinned local evidence
under one budget; an internal sub-verifier does not reset that budget.

Before freezing concrete policy values, construct real minimum and maximum
legal fixtures for every branch, including long IDs, all required status
issuers, largest supported authority sets, native signed wire, real JOSE,
binary pack framing, manifests, duplicated sealed/original metadata, range
paths and control wrappers. Record for each phase: original signed count and
bytes, generated bytes, physical stored copies, decoded bytes, signature/parse
work, actual request/response/frame bytes, largest complete control, requests,
temporary overlap, disk/WAL and elapsed work. One-over vectors must refuse
before an obligation. Padding arbitrary blobs is not a maximum legal fixture.

Then freeze mutually consistent finite policy maxima and refusal codes. Include
all six historical variants and four preflight profiles, whole-interval histories,
scoped consent/bootstrap/assignment/resource statuses, full original allocation
and activation inputs, Signed child requests, inline and staged wrappers, and
failed challenge/expired stage overlap. Pack vectors additionally measure the
MVRP1 prefix/count and every length/digest header, exact nested Signed duplicates,
actual entry and full-pack hashes, multiple roles sharing one entry, nested
historical packs and temporary parse/index overlap. Reject wrong entry_index,
unknown role, missing scope obligation, out-of-order/duplicate entries, invalid
uint64/U53 lengths, digest/size mismatches, trailing data and indirect cycles
before an accepted closure. Snapshot vectors must include the
complete encoded snapshot.response, decoded original Signed handle and manifest,
all Signed child request/response headers, existing frame prefixes, aligned
full/final chunks, per-child assembly and full-ref validation, and simultaneous
snapshot response/read pins. Measure largest legal inline manifest responses
for every head state; a one-over response must refuse before a usable handle.
Include wrong full handle/request refs, missing manifest bytes, wrong role/index/
child_count, self/future manifest children, signature or chunk-size/hash mismatch,
and cross-preflight/epoch/generation reuse. Bootstrap handles, snapshots, stages
and semantic consumers share the original job/cold-run budget: no phase or retry
resets it.

Before that measurement/review, local strict parsers, serializers, DAG builders,
role/dependency planners, signature/nonce primitives and real byte/work counters
may accept an explicit finite LocalPolicy and produce only Draft/UnverifiedPlan
or unsupported/over_budget. They do not produce AcceptedAuthority/LiveResource.
Do not expose live bootstrap/stage handles, upload permission or active/custody/
index availability through these constructors. The sole live commit boundary
must require both complete independent authority validation and a measured,
enabled node policy. Neither can be replaced by the other; proof cannot be
dropped to fit an inherited cap. This is a resource gate,
not a reason to replace the full cold mailbox/ACK goal with object-only repair.

Resource accounting includes committed bytes, staged/orphan bytes, references,
metadata originals and sealed copies, reserved response/result/replay slots,
jobs, read pins and conservative database/file overhead. Two leases can pin
one deduplicated blob but retain separate references/obligations. Unknown
unlink results and temporary rewrites remain charged. Network/crypto work
happens outside writer locks; lock-time policy/epoch/floor/generation checks
precede atomic publication. Bulk work leaves bounded control and GC progress.

GC uses due/expiry indexes and bounded batches, never a full global inventory
or repeated complete mailbox scan. Transition to retiring generation, prevent
new unpromised use, check all live pins/obligations, durably unlink and fsync,
recheck generation, then release charge. Group/handle/index TTL expiry does
not erase live promoted evidence or custody. Higher feed heads do not remove
older live page/proof paths. Floors/conflicts outlive every dependent authority
and replay horizon. Honest resource expiry can end an obligation even when
repair failed; report expired/lost availability, not successful migration.
No transport GC operation deletes existing local Vault Memory.

## 12. Implementation order and review questions

Implement the following coupled slices in the existing repository; each adds
real parts of the final chain without claiming the whole chain complete:

1. Shared Python/native strict local types and original-byte resolver; all six
   historical variants, exact role/status/operation tables and dependency DAGs;
   allocation/activation, consent and bootstrap constructors with explicit
   finite draft policy. Measure actual complete legal closure before enabling
   a live acceptance boundary.
2. Real finite source root/slot/unbound-ACK allocation and persistence, separate
   slot/anchor activation, pre-E owner bootstrap grants and genesis. Add exact
   A grant/offer-bootstrap/binding/empty transition. Complete S1/S_ACK0/S_ACK1
   with durable local grants/floors and no future object IDs.
3. Implement the four preflight profiles and their full original-signer return
   permissions, two-way possession, protected Signed proof-child reads, and
   inline/staged bootstrap.use binding. Implement snapshot.response's complete
   inline original handle/manifest and the exact Signed snapshot.child_request/
   response MVOB1 frames before enabling cold snapshots. The minimal positive
   vector starts only from frozen cold inputs and actual protocol responses:
   snapshot.answer → snapshot.response → validated manifest children → fresh
   child request → bound response frame → validated original child. It must
   not inject unknown child refs, server files or future handle refs from a
   driver. This is an implementation requirement, not a run performed by this
   document. Keep unsupported permission closures disabled; original owner
   offline is not an excuse to request upload first.
4. Mailbox admission core/checkpoint/link, private and repair pages, range
   index and separate feed_head; exact original closure and atomic source
   result. Form complete interval H(mailbox_feed) only after member histories
   and custody exist, then sign independent feed.custody. Meter full intervals
   and dependency overlap rather than a single last-message proof.
5. Independent ACK empty→occupied put and full fixed-slot closure, A cold read,
   explicit future-B-write permission at repaired empty slots, and conflicts.
6. M→new P/D finite resource negotiation, complete replica commit, publication,
   independent cold readback, persistent retry/renewal/drain and dependency GC.
   Connect the existing six-operation clients without creating another Vault.
7. Perform bounded protocol/interoperability/crash regressions, exact-source
   code review/CI/privacy gates, then the original fault-domain/model/scale/
   long-duration acceptance. Smaller fixture success is not completion.

The next real joint review must decide or reject these explicit choices:

- The new repair_v1 wire and direct-authority disclosure model; old alpha
  permissions are not upgraded. Selected-slot is the single operational root.
- A-direct empty ACK copies may accept the same future B receipt only under
  exact grant/assignment admit scope and B's later consent. Concurrent fixed
  slot conflicts remain visible; no globally serialized ACK write is promised.
- Mailbox H_member retains only A-owned ACK lookup configuration, while the
  complete ACK resource/binding/history remains under its independent root.
  Confirm this exact boundary in the coupled review; never treat configuration
  as an ACK custody claim or require mailbox M to inherit ACK M's rights.
- Every concrete service-proof branch must demonstrate a complete permission
  dependency closure inside the disclosed profile. If an assignment needs an
  excluded historical original as authority, the branch remains unsupported;
  review must approve an explicit original-signer permission before enabling it.
- Concrete role registry and actual policy maxima after complete legal-wire
  measurements. This document deliberately does not approve 31 signatures,
  C512 or any new aggregate-size assertion by arithmetic alone.
- Exact status freshness windows suitable for offline operation, retained
  high-water marks and documented unknown-revocation exposure. A/B are not
  required to remain online as a hidden authority service.
- Full-prefix range custody costs and warm-prefix consistency proof retention
  under the existing depth-16 algorithm, including count 0/1/15/16/17/65536,
  tails, forks and multi-slot merge. Ref retention must close actual paths.

Required falsifiers include invalid original approval behind valid R/P receipts;
missing/expired A or B disclosure; wrong-target offers/assignments; replayed
floors and lost ledgers; a stale bootstrap grant with active parent; P missing
local proof asking for a stage upload; possessing both keys without serving
permission; cross-owner status disclosure, multi-entry status projection,
wrong-target/generation or cross-profile bootstrap.use; a staged result from
another preflight; expired old R offer with valid current P custody; original-node
removal with only E surviving; root/head
or tuple-index loss; empty ACK repair followed by actual B save/put; occupied
ACK repair with A/B and every original holder stopped; all cold inputs frozen
before the unknown refs existed; and crashes around every commit/publication/
unlink boundary. Correct failures remain part of the results. No receipt,
syntax parse, construction DAG or release archive alone proves those outcomes.
