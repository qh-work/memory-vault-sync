/** Reopen an actually retained mailbox transfer at its recorded receipt time.
 * No network operation or new permission is implied by local historical bytes. */
import {buildNewWire,objectFields,rawRef,u53,RepairError,RepairBudget,LocalRawResolver} from './open-repair-wire.ts';
import {DEFAULT_REPAIR_CLIENT_POLICY,DEFAULT_REPAIR_CLIENT_LIMITS} from './open-repair-client.ts';
import {decodeBase64url} from './crypto.ts';
import type {EncryptionIdentityDocument} from './crypto.ts';
import {verifyMailboxFeedSourceEvent} from './open-repair-mailbox-feed.ts';
import {readMailboxIndex,readMailboxAdmission} from './open-repair-mailbox-read.ts';
import {verifyMailboxReplicaInboxEvidence} from './open-repair-mailbox-replica-inbox.ts';
type Obj=Record<string,any>;
const fields=(v:unknown,n:readonly string[]):Obj=>objectFields(v,n);
const key=(value:unknown)=>{const r=rawRef(value);return [r.namespace,r.key,r.raw_sha256,r.size].join(':');};
function fail(code:string):never{throw new RepairError(code);}
function same(a:unknown,b:unknown):boolean{if(a===b)return true;if(!a||!b||typeof a!=='object'||typeof b!=='object'||Array.isArray(a)!==Array.isArray(b))return false;const keys=Object.keys(a);return keys.length===Object.keys(b).length&&keys.every(k=>Object.hasOwn(b,k)&&same((a as Obj)[k],(b as Obj)[k]));}
export async function verifyMailboxInboxEvidence(evidence:unknown,envelope:Uint8Array,options:{owner:unknown;encryptionIdentity:EncryptionIdentityDocument;stagedAt:number}):Promise<Readonly<Obj>>{
  if((evidence as Obj)?.schema_version==='memory-vault-mailbox-replica-inbox/v1')return verifyMailboxReplicaInboxEvidence(evidence,envelope,options);
  const a=fields(options,['owner','encryptionIdentity','stagedAt']);
  const value=fields(evidence,['schema_version','received_at','slot','sender','target','limits','member','manifest_ref','custody_ref','originals','status_refs']);
  if(value.schema_version!=='memory-vault-mailbox-inbox/v1')fail('repair_invalid_context');
  const at=u53(value.received_at);if(at>u53(a.stagedAt))fail('repair_invalid_context');
  const policy=Object.freeze({...DEFAULT_REPAIR_CLIENT_POLICY,max_signature_checks:512}),budget=new RepairBudget(policy);
  const selected=buildNewWire({slot:value.slot,sender:value.sender,target:value.target,owner:a.owner,member:value.member,limits:value.limits,manifest_ref:value.manifest_ref,custody_ref:value.custody_ref,status_refs:value.status_refs},policy,budget).value as Obj;
  const limits=fields(selected.limits,Object.keys(DEFAULT_REPAIR_CLIENT_LIMITS));for(const n of Object.keys(limits))u53(limits[n],1);
  if(!Array.isArray(value.originals)||value.originals.length<1||value.originals.length>limits.max_proof_items||!Array.isArray(selected.status_refs)||selected.status_refs.length<1||selected.status_refs.length>16)fail('repair_over_budget');
  const originals=new Map<string,{ref:ReturnType<typeof rawRef>;raw:Uint8Array}>(),resolver=new LocalRawResolver(policy,budget);let total=0;
  for(const item of value.originals){const v=fields(item,['ref','raw_base64url']),ref=rawRef(v.ref),id=key(ref);
    if(ref.namespace!=='meta'||originals.has(id)||ref.size>policy.max_document_bytes)fail('repair_ref_mismatch');
    const raw=decodeBase64url(v.raw_base64url,policy.max_document_bytes);total+=raw.length;if(total>limits.max_proof_bytes)fail('repair_over_budget');
    if(raw.length!==ref.size||budget.hash(raw)!==ref.raw_sha256)fail('repair_ref_mismatch');
    if(!same(resolver.put(ref.namespace,ref.key,raw).ref,ref))fail('repair_ref_mismatch');originals.set(id,{raw,ref});
  }
  const entry=(ref:unknown)=>{const v=originals.get(key(ref));if(!v)fail('repair_original_missing');return v;};
  const source=verifyMailboxFeedSourceEvent(entry(selected.manifest_ref),resolver,entry(selected.custody_ref),{expectedSlot:selected.slot,expectedOwner:selected.owner,expectedSender:selected.sender,expectedTarget:selected.target,limitPolicy:limits,policy,budget});
  if(!(source.custody.payload.stored_at<=at&&at<Math.min(source.read_until,source.retain_until)))fail('repair_access_expired');
  const roles=new Map(source.manifest.roles.map((v:Obj)=>[v.role,{ref:v.original.ref,raw:v.original.raw}]));
  const members=await readMailboxIndex(roles.get('feed.head'),roles.get('feed.checkpoint'),{expectedSlot:selected.slot,expectedSigningKey:selected.target.signing_key,encryptionIdentity:a.encryptionIdentity,readOriginal:ref=>entry(ref).raw,at,maxMessages:65536,policy,budget});
  if(!members.some(v=>same(v,selected.member)))fail('repair_mailbox_member_mismatch');
  return readMailboxAdmission(selected.member,{expectedSlot:selected.slot,expectedSigningKey:selected.target.signing_key,expectedOwner:selected.owner,expectedSender:selected.sender,expectedTarget:selected.target,
    encryptionIdentity:a.encryptionIdentity,readOriginal:ref=>ref.namespace==='object'?envelope:entry(ref).raw,at,currentStatuses:selected.status_refs.map(entry),knownStatuses:[],statusObligations:source.graph.obligations,limitPolicy:limits,policy,budget});
}
