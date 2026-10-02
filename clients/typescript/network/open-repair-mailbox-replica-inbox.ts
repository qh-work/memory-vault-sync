/** Verify the exact replica proof retained with an inbox entry at receipt time.
 * Local reopening grants no later network access or renewed COPY/READ rights. */
import {RepairBudget,LocalRawResolver,buildNewWire,parseNewWire,rawRef,u53} from './open-repair-wire.ts';
import {DEFAULT_REPAIR_CLIENT_POLICY} from './open-repair-client.ts';
import {decodeBase64url} from './crypto.ts';
import {authenticateStatusOriginal} from './open-repair-status.ts';
import {verifyMailboxAdmissionMetadata} from './open-repair-mailbox-read.ts';
import {MAILBOX_REPLICA_LIMITS} from './open-mailbox-replica-client.ts';
import {replicaFields as fields,replicaFail as fail,replicaSame as same,replicaRefKey as key,replicaFloors,verifyMailboxMessageReplica,checkMailboxMessageReturn} from './open-repair-mailbox-replica.ts';
type Obj=Record<string,any>;
export async function verifyMailboxReplicaInboxEvidence(evidence:unknown,envelope:Uint8Array,a:Obj):Promise<Readonly<Obj>>{
  fields(a,['owner','encryptionIdentity','stagedAt']);const v=fields(evidence,'schema_version received_at slot sender source target maintainer target_storage_epoch envelope_ref limits manifest_ref custody_ref consent_refs originals status_refs archive_status_refs'.split(' '));
  if(v.schema_version!=='memory-vault-mailbox-replica-inbox/v1'||u53(v.received_at)>u53(a.stagedAt))fail('repair_invalid_context');const at=v.received_at,policy=Object.freeze({...DEFAULT_REPAIR_CLIENT_POLICY,max_signature_checks:512}),budget=new RepairBudget(policy);
  const limits=buildNewWire(v.limits,policy,budget).value as Obj;fields(limits,Object.keys(MAILBOX_REPLICA_LIMITS));for(const [name,maximum] of Object.entries(MAILBOX_REPLICA_LIMITS))if(u53(limits[name],1)>maximum)fail('repair_over_budget');
  if(!Array.isArray(v.originals)||v.originals.length<1||v.originals.length>limits.max_proof_items||!Array.isArray(v.status_refs)||v.status_refs.length<1||v.status_refs.length>16||!Array.isArray(v.archive_status_refs)||v.archive_status_refs.length>32)fail('repair_over_budget');
  const resolver=new LocalRawResolver(policy,budget),originals=new Map<string,Obj>();let total=envelope.length;
  for(const item of v.originals){fields(item,['ref','raw_base64url']);const ref=rawRef(item.ref);if(ref.namespace!=='meta'||ref.size>policy.max_document_bytes||originals.has(key(ref)))fail('repair_ref_mismatch');const raw=decodeBase64url(item.raw_base64url,policy.max_document_bytes);total+=raw.length;if(total>limits.max_proof_bytes)fail('repair_over_budget');if(!same(resolver.put(ref.namespace,ref.key,raw).ref,ref))fail('repair_ref_mismatch');originals.set(key(ref),{ref,raw});}
  const entry=(ref:unknown)=>{const item=originals.get(key(ref));if(!item)fail('repair_original_missing');return item;};
  const context={expectedSlot:v.slot,expectedOwner:a.owner,expectedSender:v.sender,expectedSource:v.source,sourceStorageEpoch:v.slot.writer_storage_epoch,expectedMaintainer:v.maintainer,expectedTarget:v.target,targetStorageEpoch:v.target_storage_epoch,expectedEnvelopeRef:v.envelope_ref,limitPolicy:limits,policy,budget};
  const replica=verifyMailboxMessageReplica(entry(v.manifest_ref),resolver,entry(v.custody_ref),context);if(replica.custody.payload.stored_at>at)fail('repair_access_expired');fields(v.consent_refs,['owner','source','maintainer','sender']);
  const permission=checkMailboxMessageReturn(replica,Object.fromEntries(Object.entries(v.consent_refs).map(([n,ref])=>[n,entry(ref)])),{...context,currentStatuses:v.status_refs.map(entry),at,action:'child'});
  const signers=new Map([a.owner,v.sender,v.source,v.maintainer,v.target].map(v=>[v.signing_key.key_id,v.signing_key])),archive:Obj[]=[];
  for(const ref of v.archive_status_refs){const saved=entry(ref),p=(parseNewWire(saved.raw,policy,budget).value as Obj).payload;if(!same(signers.get(p.signing_key.key_id),p.signing_key)||u53(p.issued_at)>at)fail('repair_status_disclosure');archive.push(authenticateStatusOriginal(saved,{expectedRoot:v.slot.root_key,expectedSigningKey:p.signing_key,at:p.issued_at,allowedScopes:p.entries.map((v:Obj)=>({scope_kind:v.scope_kind,scope_id:v.scope_id})),policy,budget}));}
  replicaFloors(archive,permission.statuses,permission.obligations);
  const checked=await verifyMailboxAdmissionMetadata(replica.source.message_member,{expectedSlot:v.slot,expectedSigningKey:v.source.signing_key,encryptionIdentity:a.encryptionIdentity,readOriginal:ref=>entry(ref).raw,at,policy,budget,expectedOwner:a.owner,expectedSender:v.sender,expectedTarget:v.source,limitPolicy:limits,currentStatuses:[],knownStatuses:[],statusObligations:[]});
  const ref=rawRef(checked.core.envelope_ref);if(!same(ref,v.envelope_ref)||envelope.length!==ref.size||budget.hash(envelope)!==ref.raw_sha256)fail('repair_ref_mismatch');return Object.freeze({...checked,envelope,originals:[...checked.originals,{ref,raw:envelope}],current_statuses:permission.statuses});
}
