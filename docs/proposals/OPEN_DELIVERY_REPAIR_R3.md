# Open delivery repair R3: cold mailboxes and independent ACK roots

Status: **unimplemented protocol candidate for joint review**. This document
replaces the unresolved repair choices in the R1/R2 working proposals. It is
neither a protocol freeze nor a successful review, test, release, or deployment.
The published alpha.0.5 delivery path still uses the original approved Python
node. Its contact approval and saved receipt do not authorize this new profile.

The five prior joint-review findings are addressed together: one original
authorization model; an acyclic cold locator; complete initial empty roots and
resources; independently maintainable ACKs; and accounting for the full proof
and storage closure. The architecture requirements remain those of
[OPEN_NETWORK_ARCHITECTURE.md](../OPEN_NETWORK_ARCHITECTURE.md),
[OPEN_NETWORK_LIFECYCLE.md](../OPEN_NETWORK_LIFECYCLE.md), and
[OPEN_NETWORK_ACCEPTANCE.md](../OPEN_NETWORK_ACCEPTANCE.md). Their acceptance
targets are not measurements of this candidate.

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
Offline A/B need not produce a new signature every minute. A long finite
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

Owner intent purposes are `anchor_catalog`, `feed_metadata`, and `ack_slot`.
Copy intent purposes are `root_replica`, `feed_replica`, `message_replica`, and
`ack_replica`. A message replica's data/meta budgets are independent fields;
index/catalog-only purposes fix max_live_bytes=0. An ACK replica's live data can
contain only the exact signed B receipt, never E or arbitrary content. Every
purpose also reserves its actual metadata, replay, pending and job costs.

Scope is a closed union:

- `{kind:mailbox_root,root_key,root_authority_ref,catalog_ref}`;
- `{kind:mailbox_feed,slot_key,slot_ref,feed_head_ref,
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

The owner root and, for member work, original A/B disclosure expressly permit
M to send this minimal reservation descriptor to a freshly dual-key-proved
candidate before assignment: RootKey/public identities, opaque scope refs and
requested finite budgets/windows. This exposes those limited associations to
that candidate. It does not permit sending original private signed evidence
before the exact offer and assignment exist. If the root lacks this advance
reservation-disclosure scope, obtaining new targets is blocked, not implicit.

`resource.offer` is node Signed with `issued_at,reservation_until,offer_id,
intent, intent_sha256,resource:ResourceRef,target_encryption_key,
reservation_generation,budget,windows`. The target first checks its enabled
finite policy and durably reserves the actual amounts. The offer is a
conditional reservation, not application custody. Its activation deadline is
separate from the requested long read/retention horizons. Every target proves
both keys before receiving private original evidence.

For initial owner setup, a separate `resource.active` is node Signed with
`activated_at,offer_ref,resource,reservation_generation,root_key,purpose,
budget,windows`. It is returned only after the owner setup and actual local
root/empty-slot resource are durably activated. An unactivated short offer must
not be treated as the pre-offline empty-root promise. It contains no future
catalog, grant binding, receipt, or custody reference.

For delegated copies, M next signs `maintenance.assignment` with
`issued_at,expires_at,assignment_id,job_id,root_key,parent_root_ref,
parent_assignment_ref=null,depth=2,subject:DualID,target_node_key_id,
target_storage_epoch,operation_mask,scope,resource_intent_sha256,
resource_offer_ref,resource:ResourceRef,budget,windows`.
Only an M explicitly named by the original root may do so. P and D need separate
exact assignments and resources. No P receipt makes P another maintainer.

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
original root.custody; for mailbox_feed it designates the source message.custody
whose exact feed_head includes that range. For ack_unbound/ack_empty it
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
  exact slot/read authority, observed floors and normal routing state, before
  E/message_id/K_m exists. B may then go offline again.

Choose RootKey, SlotKey, stable read/maintenance IDs and opaque feed_ref first.
Allocate actual R anchor and metadata resources next. Then form the following
closed owner authorities; their raw refs only point to earlier objects.

| B-signed kind | Exact fields beyond common fields |
|---|---|
| `mailbox.root_authority` | issued_at,expires_at,root_key,authority_id,original_resource_ref,original_resource_lease_ref,slot_ids,maintainers:[DualID],operation_mask,allowed_roles,budget,windows,max_delegate_depth=2,max_destinations_per_job,max_concurrent_jobs,revision |
| `mailbox.maintenance_root` | issued_at,expires_at,root_key,authority_id,slot_key,sender:DualID,recipient:DualID,maintainers:[DualID],operation_mask,allowed_roles,budget,windows,max_delegate_depth=2,max_destinations_per_job,max_concurrent_jobs,revision |
| `mailbox.read_grant` | issued_at,expires_at,grant_id,root_key,slot_key,reader:DualID,serving_authority_id,operation_mask,budget,windows,revision |
| `mailbox.slot` | issued_at,expires_at,revision,slot_key,feed_ref,sender:DualID,recipient:DualID,data_resource_ref,data_resource_lease_ref,metadata_resource_ref,metadata_resource_lease_ref,read_grant_ref,maintenance_root_ref,max_appends,max_live_items,budget,windows |
| `mailbox.catalog` | root_key,revision,issued_at,expires_at,slot_refs,root_authority_ref |
| `mailbox.root_read_grant` | issued_at,expires_at,grant_id,root_key,reader:DualID,root_authority_ref,operation_mask,budget,windows,revision |
| `delivery.destination` | issued_at,expires_at,destination_id,sender:DualID,recipient:DualID,contact_request_ref,contact_policy_ref,contact_knock_lease_ref,contact_decision_ref,store_grant_ref,slot_key,slot_ref,data_resource_ref,data_resource_lease_ref,metadata_resource_ref,metadata_resource_lease_ref,read_grant_ref,maintenance_root_ref,budget,windows |

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

After slot verification, R signs the count-zero checkpoint and feed_head defined
below. R durably stores the catalog/slot/root/read/genesis closure, pins its
dependencies, commits usage and publication/replication jobs, and signs an
initial root custody event. The initial resources, exact original authority and
empty-head branches contain no contact attempt for a future message. S1 records
the actual resulting observations, including partial replication if present;
setup does not assert redundancy that was only requested.

## 6. Immutable message and explicit A disclosure consent

Reuse the existing immutable E and its existing context/JWE/profile, including
the single B recipient, original content bytes, 6 MiB envelope bound and
4 KiB context bound. E contains no delivery location, replaceable lease, ACK
grant, provider fact or maintenance assignment. Repair never changes E.

A signs `message.disclosure` **after E and before the attempt** with
`issued_at,expires_at,consent_id,root_key,slot_key,sender:DualID,
recipient:DualID,envelope_ref,maintenance_root_ref,allowed_roles,
operation_mask,consent_until,revision`. Its expiry/consent_until are independently
bounded by the original B root; they do not inherit or extend the short store
window. It explicitly permits the necessary original A documents to the
finite B→M→P/D chain. B's root separately authorizes B's original metadata.
Neither signature grants plaintext access, new recipients or Vault trust.

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

`historical.manifest` is an unsigned canonical object with
`schema_version,kind,root_key,slot_key,message_id,envelope_ref,roles`.
Each role entry is `{role,document_ref,pack_ref,entry_index}` and resolves an
exact original signed document. It contains no core/checkpoint/link/head/custody
or future capsule ref. Original documents are retained in typed packs preserving
full raw bytes. Nested original documents may share storage only if the exact
fixed child position and byte identity are proven; otherwise both are charged.
Authorized verifiers receive necessary originals after disclosure checks; B-only
sealed copies do not make originals invisible to those authorized verifiers.

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
resource_refs,stored_at,read_until,retain_until`; its `resource_refs` is exactly
`{anchor:ResourceRef,feeds:[ResourceRef]}`. Each feed resource corresponds to an
already authorized catalog slot; all refs precede the event. These are distinct
closed representations, not a generic bag of interchangeable resource kinds.

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
| `ack.root_authority` | issued_at,expires_at,ack_slot,authority_id,owner:DualID,receipt_writer:DualID,original_resource_ref,original_resource_lease_ref,maintainers:[DualID],operation_mask,allowed_roles,max_bindings=1,max_receipts=1,budget,windows,max_delegate_depth=2,max_destinations_per_job,max_concurrent_jobs,revision |
| `ack.read_grant` | issued_at,expires_at,grant_id,ack_slot,reader:DualID,root_authority_ref,operation_mask,budget,windows,revision |
| `ack.write_grant` | issued_at,expires_at,grant_id,ack_slot,root_authority_ref,owner:DualID,receipt_writer:DualID,message_id,envelope_ref,operation=receipt.put,max_receipts=1,budget,windows,revision |

Root authority and read grant are created pre-E. The write grant is created
after E and refers back to the frozen root, using AckSlot's preselected grant_id.
The root never contains its future raw hash. One stable grant_id may bind only
one exact owner-signed grant body; another body is a retained conflict, not a
second message or last-writer-wins update.

The source initially commits and can replicate an **unbound** slot containing
only real pre-E root/read/resource evidence. A then submits its exact write
grant; the source durably commits `ack.binding` with
`ack_slot,root_authority_ref,grant_ref,bound_at,resource_ref,retain_until` and
atomically publishes the empty-slot head. Only then is S_ACK1 captured: A
retains its root/read/write grant, actual binding observation, E/message ID,
anchor, floors and ordinary routing. A does not know any future B receipt,
ACK commit, replacement location or future head hash. A pre-E S_ACK0 cannot be
passed off as S_ACK1.

The initial node signs `ack.slot_custody` with
`ack_slot,root_authority_ref,resource_ref,stored_at,read_until,retain_until,state`
and exactly one state branch: unbound has no extra fields; empty has
`grant_ref,binding_ref`. The node issues the unbound event only after real
root/resource commit and the empty event only after real grant binding commit.
The later empty commitment is not obtained by editing the original event.
An empty replica retains the actual empty commitment; an earlier unbound-only
replica cannot claim it has the binding just because A owns the root.

B receives the original grant through the authorized delivery evidence. To
learn the preconfigured ACK offer/root, it proves its two keys against the
exact grant/root/slot and reads only that limited offer closure. This is a
separate `ack_offer` purpose, not A's receipt-read permission. A grant with no
configured matching root, actual resource, or exact binding is unsupported.

After B's actual validated local save, B signs its original recipient receipt
and new `ack.disclosure` with `issued_at,expires_at,consent_id,ack_slot,
root_authority_ref,grant_ref,receipt_ref,recipient:DualID,owner:DualID,
allowed_roles,operation_mask,consent_until,revision`. B then signs `ack.put`
with `issued_at,expires_at,put_id,ack_slot,grant_ref,binding_ref,receipt_ref,
disclosure_ref,operation=receipt.put`.
Both documents precede any ACK custody result. The storage target verifies
actual A authority, B signature/dual possession, exact E/message binding,
the permitted receipt schema, B consent and its own active resources.

`ack.commit` is target Signed with `ack_slot,grant_ref,binding_ref,receipt_ref,
put_ref,disclosure_ref,historical_manifest_ref,resource_ref,stored_at,
read_until,retain_until`. Historical manifest contains the existing authority
and receipt inputs but not this future commit. The source atomically commits
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
retains the exact M→P admit assignment, P offer/activated resource and status
used at that first commit. P signs its own ack.commit; the vanished R is not
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

Cold readers cannot upload a replacement node's still-unknown current proof in
order to read that same proof. Use explicit typed bootstrap branches rather
than pretending that a raw reference or partial evidence group is authority.

`head.intent` is reader Signed with `issued_at,expires_at,intent_id,
subject:DualKey,target_node_key_id,target_storage_epoch,purpose,root_key,
selector,preheld_authority`.

Purpose and selector are closed pairs:

- mailbox_root: `{anchor_ref,minimum_catalog_revision}`;
- mailbox_feed: `{slot_key,feed_ref,checkpoint:null|{count,leaf_root,slot_binding}}`;
- ack_owner: `{ack_slot,grant_ref,binding_ref}`;
- ack_offer: `{ack_slot,grant_ref,root_authority_ref}`.

`preheld_authority` is a typed local pack, not arbitrary refs: mailbox_root uses
B root/read originals and baseline status; mailbox_feed uses the exact selected
slot/read/root originals already acquired through the root; ack_owner uses A
root/read/write grant/binding and baseline status; ack_offer uses B's received
A grant and root plus the original expected identities. All transmitted and
target-local originals count toward the same actual proof budget.

Before issuing a snapshot, the server verifies this expected caller, target,
root and purpose, resolves and pins its own **complete** current serving chain,
checks highest known floors/resources, and resolves the requested stable
index. No network fetch occurs under its validation/SQLite lock. Missing local
proof produces incomplete; the server cannot defer a required permission
check until after disclosing private data.

If the complete preheld pack exceeds the existing control limit, use a
purpose-specific protected proof stage after fresh target dual-key proof.
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
manifest_ref,reservation_generation,reserved_bytes,reserved_items`.
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
headers within the existing frame/header limits. This is a newly implemented
binding, not something the old blob parser is assumed to accept. It cannot
write an undeclared child, read existing stored data, or upload E through a
metadata allocation. Exact child size/hash and total stage charges are checked.

`proof.stage_close` takes the same intent/handle identity and no new child list;
it returns a node-signed `proof.stage_result` with
`subject:DualID,target_node_key_id,target_storage_epoch,intent_ref,
manifest_ref,reservation_generation,closed_at,expires_at` only when all named
original bytes are locally complete. This result means completed provisional
bytes, never verified application authority. The subsequent semantic consumer
combines those exact pinned bytes with required target-local evidence, verifies
the complete original/current chain under the parent budget, then either
atomically promotes the required objects and their charges or refuses.
An expired stage is not reused under another consumer, root, subject or epoch.
Any promoted live proof survives stage cleanup under its real resource pins.

A snapshot manifest is an unsigned closed object with
`schema_version,kind,root_key,selector,generation,state,children`;
each child is `{index,role,ref}`. It references no handle or future proof. The
server signs a fresh challenge binding the complete intent raw hash, subject,
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

After proof of both caller keys, recheck the pinned generation, current
authority and quota; return `snapshot.handle` with
`issued_at,expires_at,handle_id,intent_ref,subject:DualID,target_node_key_id,
target_storage_epoch,purpose,root_key,selector,generation,snapshot_ref,
child_count`. The handle is not a bearer capability. Every chunk needs fresh
subject authentication and exact handle/child/offset binding; only declared
typed children are readable. Changed/missing bytes invalidate that snapshot,
not transparently switch to another generation. Read concurrency and pins have
finite node/subject bounds and a shared parent deadline.

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
| cold read | actual preheld originals plus target-local complete applicable serving proof, snapshot, transferred children and decoded private metadata, with duplicate physical copies accounted |

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

Then freeze mutually consistent finite policy maxima and refusal codes. Until
that measurement/review exists, implementations may build parsers/constructors
and reject unsupported consumers; they must not enable an unmeasured full
custody promise or drop proof to fit an inherited cap. This is a resource gate,
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

1. Shared Python/native strict types, original-byte resolver, general scoped
   status evaluation, selected-slot/catalog distinction, A/B consent and
   owner/copy/index intent variants. Freeze exact role and operation tables.
2. Real finite root/empty-ACK allocation and persistence, target proof,
   protected bootstrap snapshots, genesis mailbox/head and A grant binding.
   Complete S1/S_ACK1 without future object IDs.
3. Mailbox admission core/checkpoint/link, private and repair pages, range
   index and separate feed_head; exact original closure and atomic source
   result. Add real byte/work metering and maximum-legal constructors.
4. Independent ACK empty→occupied put and full fixed-slot closure, A cold read,
   explicit future-B-write permission at repaired empty slots, and conflicts.
5. M→new P/D finite resource negotiation, complete replica commit, publication,
   independent cold readback, persistent retry/renewal/drain and dependency GC.
   Connect the existing six-operation clients without creating another Vault.
6. Perform bounded protocol/interoperability/crash regressions, exact-source
   code review/CI/privacy gates, then the original fault-domain/model/scale/
   long-duration acceptance. Smaller fixture success is not completion.

The next real joint review must decide or reject these explicit choices:

- The new repair_v1 wire and direct-authority disclosure model; old alpha
  permissions are not upgraded. Selected-slot is the single operational root.
- A-direct empty ACK copies may accept the same future B receipt only under
  exact grant/assignment admit scope and B's later consent. Concurrent fixed
slot conflicts remain visible; no globally serialized ACK write is promised.
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
floors and lost ledgers; original-node removal with only E surviving; root/head
or tuple-index loss; empty ACK repair followed by actual B save/put; occupied
ACK repair with A/B and every original holder stopped; all cold inputs frozen
before the unknown refs existed; and crashes around every commit/publication/
unlink boundary. Correct failures remain part of the results. No receipt,
syntax parse, construction DAG or release archive alone proves those outcomes.
