/** Authenticate retained mailbox owner controls and initial node history.
 * Resource-offer signatures, live status and source custody are separate checks.
 * No authority is created and no network or local storage is accessed here. */
import {buildNewWire,parseNewWire,objectFields,rawRef,u53,RepairError} from './open-repair-wire.ts';
import type {RepairPolicy,RepairBudget,RawOriginal} from './open-repair-wire.ts';
import type {AuthenticatedRepairOriginal} from './open-repair-resource.ts';
import {originalPublicDescriptor,verifyBoundedControlSignature} from './open-repair-original.ts';
import {knownHistoricalRoles} from './open-repair-history.ts';
import {emptyMailboxState} from './open-repair-mailbox-range.ts';
type Obj=Record<string,any>;
const COMMON=['schema_version','kind','signing_key'];
const FIELDS={
  maintenance:'issued_at expires_at root_key authority_id slot_key sender recipient maintainers operation_mask allowed_roles budget windows max_delegate_depth max_destinations_per_job max_concurrent_jobs revision',
  read:'issued_at expires_at grant_id root_key slot_key reader serving_authority_id operation_mask budget windows revision',
  slot:'issued_at expires_at revision slot_key feed_ref sender recipient data_resource_ref data_resource_offer_ref metadata_resource_ref metadata_resource_offer_ref read_grant_ref maintenance_root_ref max_appends max_live_items budget windows',
  bootstrap:'issued_at expires_at grant_id revision owner subject root_key consumer selector parent_authority_ref caller_authority_ref probe_until proof_until upload_until probe_profile response_profile upload_roles limits',
  activation:'issued_at expires_at activation_id subject target_node_key_id target_storage_epoch root_key scope resource_offer_refs authority_refs',
};
const KINDS={maintenance:'mailbox.maintenance_root',read:'mailbox.read_grant',slot:'mailbox.slot',bootstrap:'bootstrap.grant',activation:'resource.activation'};
const BUDGET=['max_live_bytes','max_meta_bytes','max_items','max_requests','max_pending','max_replay_records','max_jobs','max_job_bytes'];
const WINDOWS=['admit_until','read_until','copy_until','publish_until','retain_until'];
const PARENT_CAPS:Record<string,string[]>={max_probe_bytes:['max_meta_bytes','max_job_bytes'],max_proof_bytes:['max_meta_bytes','max_job_bytes'],
  max_proof_items:['max_items'],max_signature_checks:['max_requests'],max_requests:['max_requests'],max_pending:['max_pending'],
  max_replay_records:['max_replay_records'],max_concurrent_handles:['max_pending','max_jobs'],max_candidate_attempts:['max_requests','max_jobs']};
const ROLES=new Set([...knownHistoricalRoles,'bootstrap.grant','mailbox_root_service_v1','selected_slot_service_v1','ack_owner_service_v1','ack_offer_service_v1']);
const UPLOAD=new Set(['mailbox.slot','mailbox.read_grant','mailbox.maintenance_root','bootstrap.grant']);
const CONTROL_NAMES=['maintenance','read','slot','bootstrap'] as const;
export interface MailboxAuthorityOptions{
  readonly expectedSlot:unknown;readonly expectedOwner:unknown;readonly expectedTarget:unknown;readonly targetStorageEpoch:string;
  readonly limitPolicy:unknown;readonly at:number;readonly policy:RepairPolicy;readonly budget:RepairBudget;
}
export type AuthenticatedMailboxControls=Readonly<Record<typeof CONTROL_NAMES[number],AuthenticatedRepairOriginal>>;
function fail(code='repair_mailbox_activation_mismatch'):never{throw new RepairError(code);}
const fields=(v:unknown,n:readonly string[]):Obj=>objectFields(v,n);
function same(a:unknown,b:unknown):boolean{
  if(a===b)return true;if(!a||!b||typeof a!=='object'||typeof b!=='object'||Array.isArray(a)!==Array.isArray(b))return false;
  const names=Object.keys(a);return names.length===Object.keys(b).length&&names.every(n=>Object.hasOwn(b,n)&&same((a as Obj)[n],(b as Obj)[n]));
}
function pattern(value:unknown,re:RegExp):string{if(typeof value!=='string'||re.exec(value)?.[0]!==value)fail();return value;}
const opaque=(v:unknown)=>pattern(v,/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/);
function dual(value:unknown):Obj{const v=fields(value,['signing_key_id','encryption_key_id']);pattern(v.signing_key_id,/^ed25519_[0-9a-f]{64}$/);pattern(v.encryption_key_id,/^x25519_[0-9a-f]{64}$/);return v;}
function dualKey(value:unknown,budget:RepairBudget):Obj{const v=fields(value,['signing_key','encryption_key']);originalPublicDescriptor(v.signing_key,budget);originalPublicDescriptor(v.encryption_key,budget,true);return {signing_key_id:v.signing_key.key_id,encryption_key_id:v.encryption_key.key_id};}
function limits(value:unknown):Obj{const v=fields(value,Object.keys(PARENT_CAPS));for(const n of Object.keys(PARENT_CAPS))u53(v[n],1);return v;}
function ordered(value:unknown,get:(v:any)=>string,check:(v:any)=>unknown):void{
  if(!Array.isArray(value))fail();let prior:string|undefined;for(const item of value){check(item);const next=get(item);if(prior!==undefined&&next<=prior)fail();prior=next;}
}
function roles(value:unknown):void{ordered(value,v=>v,v=>{if(typeof v!=='string'||!ROLES.has(v))fail();});}
function original(value:unknown,policy:RepairPolicy,budget:RepairBudget):RawOriginal{
  const v=fields(value,['raw','ref']),ref=rawRef(v.ref),raw=parseNewWire(v.raw,policy,budget).raw;
  if(ref.namespace!=='meta'||raw.length!==ref.size||budget.hash(raw)!==ref.raw_sha256)fail('repair_ref_mismatch');return {raw,ref};
}
function authenticate(value:unknown,name:keyof typeof FIELDS,expected:Obj,policy:RepairPolicy,budget:RepairBudget):AuthenticatedRepairOriginal{
  const held=original(value,policy,budget),signed=fields(parseNewWire(held.raw,policy,budget).value,['payload','proof']);
  const p=fields(signed.payload,[...COMMON,...FIELDS[name].split(' ')]);
  if(p.schema_version!=='memory-vault-open-repair/v1'||p.kind!==KINDS[name]||u53(p.issued_at)>=u53(p.expires_at))fail();
  if(!(p.issued_at<=expected.at&&expected.at<p.expires_at))fail('repair_resource_expired');
  verifyBoundedControlSignature(p,signed.proof,expected.owner.signing_key,budget);
  return Object.freeze({ref:held.ref,payload:p,get raw(){budget.output(held.raw.length);return Uint8Array.from(held.raw);}});
}
function context(value:unknown):{expected:Obj;policy:RepairPolicy;budget:RepairBudget}{
  const a=fields(value,['expectedSlot','expectedOwner','expectedTarget','targetStorageEpoch','limitPolicy','at','policy','budget']);
  const {policy,budget}=a,expected=buildNewWire({slot:a.expectedSlot,owner:a.expectedOwner,target:a.expectedTarget,epoch:a.targetStorageEpoch,limits:a.limitPolicy,at:a.at},policy,budget).value as Obj;
  emptyMailboxState(expected.slot,policy,budget);opaque(expected.epoch);u53(expected.at);limits(expected.limits);
  dualKey(expected.owner,budget);dualKey(expected.target,budget);return {expected,policy,budget};
}
function chain(held:Obj,e:Obj,offers:Record<string,RawOriginal>|undefined,policy:RepairPolicy,budget:RepairBudget):void{
  const key=e.slot,root=key.root_key,owner=dualKey(e.owner,budget),target=dualKey(e.target,budget),now=e.at;
  const p=Object.fromEntries(Object.entries(held).map(([n,v])=>[n,(v as AuthenticatedRepairOriginal).payload]));
  const {maintenance:m,read:r,slot:s,bootstrap:g,activation:a}=p;
  if(!same(root.owner,owner)||!same(key.writer,target)||key.writer_storage_epoch!==e.epoch)fail();
  for(const name of ['maintenance','read','slot']){
    const v=p[name];emptyMailboxState(v.slot_key,policy,budget);u53(v.revision);
    fields(v.budget,BUDGET);fields(v.windows,WINDOWS);for(const n of BUDGET)u53(v.budget[n]);
    for(const n of WINDOWS)if(!(v.issued_at<u53(v.windows[n])&&v.windows[n]<=v.expires_at&&v.windows[n]<=v.windows.retain_until))fail();
    if(!same(v.slot_key,key)||(name!=='slot'&&!same(v.root_key,root)))fail();
  }
  for(const v of [m,r])if(u53(v.operation_mask)>127)fail();
  for(const v of [m,s]){dual(v.sender);if(!same(dual(v.recipient),owner))fail();}
  dual(r.reader);for(const v of [m.authority_id,r.grant_id,r.serving_authority_id])opaque(v);
  if(!same(r.reader,owner)||!same(s.sender,m.sender)||r.serving_authority_id!==m.authority_id||!same(s.read_grant_ref,held.read.ref)||!same(s.maintenance_root_ref,held.maintenance.ref))fail();
  fields(s.feed_ref,['namespace','key']);if(s.feed_ref.namespace!=='feed')fail();pattern(s.feed_ref.key,/^[0-9a-f]{64}$/);
  if(!(1<=u53(s.max_live_items)&&s.max_live_items<=u53(s.max_appends,1)&&s.max_appends<=65536&&s.max_live_items<=s.budget.max_items)||u53(m.max_delegate_depth)!==2)fail();
  u53(m.max_destinations_per_job);u53(m.max_concurrent_jobs);ordered(m.maintainers,v=>v.signing_key_id+':'+v.encryption_key_id,dual);roles(m.allowed_roles);
  if((m.operation_mask&10)!==10||(r.operation_mask&2)!==2||(r.operation_mask&~m.operation_mask)!==0||
    !['bootstrap.grant','selected_slot_service_v1'].every(v=>m.allowed_roles.includes(v))||BUDGET.some(n=>r.budget[n]>m.budget[n])||WINDOWS.some(n=>r.windows[n]>m.windows[n])||r.expires_at>m.expires_at)fail();
  if(offers)for(const [name,purpose] of [['data','mailbox_data'],['metadata','feed_metadata']]){
    const offer=offers[name],v=(parseNewWire(offer.raw,policy,budget).value as Obj).payload,intent=v.intent;
    if(!same(s[name+'_resource_ref'],v.resource)||!same(s[name+'_resource_offer_ref'],offer.ref)||intent.purpose!==purpose||!same(intent.root_key,root)||
      !same(intent.owner,e.owner)||!same(intent.target,e.target)||v.issued_at>Math.min(m.issued_at,r.issued_at,s.issued_at)||Math.min(...Object.values(intent.windows) as number[])<=now)fail();
  }
  fields(g.selector,['root_key_sha256','slot_key_sha256','feed_ref','slot_sha256','read_grant_sha256','maintenance_root_sha256']);opaque(g.grant_id);u53(g.revision);
  const selector={root_key_sha256:budget.hash(buildNewWire(root,policy,budget).raw),slot_key_sha256:budget.hash(buildNewWire(key,policy,budget).raw),feed_ref:s.feed_ref,
    slot_sha256:held.slot.ref.raw_sha256,read_grant_sha256:held.read.ref.raw_sha256,maintenance_root_sha256:held.maintenance.ref.raw_sha256};
  if(!same(g.owner,owner)||!same(g.subject,owner)||!same(g.root_key,root)||g.consumer!=='mailbox_feed'||g.probe_profile!=='opaque_v1'||g.response_profile!=='selected_slot_service_v1'||
    !same(g.parent_authority_ref,held.maintenance.ref)||!same(g.caller_authority_ref,held.read.ref)||!same(g.selector,selector))fail();
  roles(g.upload_roles);if(g.upload_roles.some((v:string)=>!UPLOAD.has(v)||!m.allowed_roles.includes(v)))fail();limits(g.limits);
  for(const [n,parents] of Object.entries(PARENT_CAPS))if(g.limits[n]>e.limits[n]||[m,r].some(v=>parents.some(k=>g.limits[n]>v.budget[k])))fail();
  const activated=offers?a.issued_at:now;
  if(!(m.issued_at<=r.issued_at&&r.issued_at<=s.issued_at&&s.issued_at<=g.issued_at&&g.issued_at<=activated&&activated<=now&&g.expires_at<=Math.min(m.expires_at,r.expires_at)))fail();
  for(const n of ['probe_until','proof_until','upload_until'])if(!(now<u53(g[n])&&g[n]<=g.expires_at))fail();
  if(['proof_until','upload_until'].some(n=>[m,r].some(v=>['read_until','retain_until'].some(w=>g[n]>v.windows[w]))))fail();
  if(!offers)return;
  opaque(a.activation_id);const compare=(x:Obj,y:Obj)=>{for(const n of ['namespace','key','raw_sha256','size']){if(x[n]<y[n])return -1;if(x[n]>y[n])return 1;}return 0;};
  const refs=Object.values(offers).map(v=>v.ref).sort(compare),authorities=['maintenance','read','slot'].map(n=>({role:KINDS[n as keyof typeof KINDS],ref:held[n].ref}));
  if(!same(a.subject,e.owner)||a.target_node_key_id!==e.target.signing_key.key_id||a.target_storage_epoch!==key.writer_storage_epoch||!same(a.root_key,root)||
    !same(a.scope,{kind:'mailbox_slot',slot_key:key,slot_ref:held.slot.ref})||!same(a.resource_offer_refs,refs)||!same(a.authority_refs,authorities))fail();
}
export function verifyMailboxFeedBootstrap(entries:unknown,options:MailboxAuthorityOptions):AuthenticatedMailboxControls{
  const {expected:e,policy,budget}=context(options),v=fields(entries,CONTROL_NAMES),held:Obj={};
  for(const name of CONTROL_NAMES)held[name]=authenticate(v[name],name,e,policy,budget);
  chain(held,e,undefined,policy,budget);return Object.freeze(held) as AuthenticatedMailboxControls;
}
export function verifyMailboxSlotOwnerInputs(entries:unknown,offers:unknown,options:MailboxAuthorityOptions):Readonly<Record<keyof typeof FIELDS,AuthenticatedRepairOriginal>>{
  const {expected:e,policy,budget}=context(options),v=fields(entries,Object.keys(FIELDS)),held:Obj={},supplied=fields(offers,['data','metadata']);
  for(const name of Object.keys(FIELDS) as (keyof typeof FIELDS)[])held[name]=authenticate(v[name],name,e,policy,budget);
  const frozen={data:original(supplied.data,policy,budget),metadata:original(supplied.metadata,policy,budget)};
  chain(held,e,frozen,policy,budget);return Object.freeze(held) as Readonly<Record<keyof typeof FIELDS,AuthenticatedRepairOriginal>>;
}
export function verifyMailboxGenesis(entries:unknown,options:{expectedSlot:unknown;expectedSigningKey:unknown;committedAt:number;at:number;policy:RepairPolicy;budget:RepairBudget}):Readonly<Record<'head'|'checkpoint',AuthenticatedRepairOriginal>>{
  const a=fields(options,['expectedSlot','expectedSigningKey','committedAt','at','policy','budget']),{policy,budget}=a;
  const e=buildNewWire({slot:a.expectedSlot,key:a.expectedSigningKey,committed:a.committedAt,at:a.at},policy,budget).value as Obj;
  u53(e.committed);u53(e.at);const initial=emptyMailboxState(e.slot,policy,budget),v=fields(entries,['checkpoint','head']),held:Obj={};
  for(const name of ['checkpoint','head']){
    const item=original(v[name],policy,budget),signed=fields(parseNewWire(item.raw,policy,budget).value,['payload','proof']);
    const p=fields(signed.payload,[...COMMON,'slot_key','committed_at','retain_until',...(name==='checkpoint'?Object.keys(initial):['checkpoint_ref','count','range_root_ref','catalog_generation'])]);
    if(p.schema_version!=='memory-vault-open-repair/v1'||p.kind!==(name==='checkpoint'?'mailbox.checkpoint':'mailbox.feed_head')||!same(p.slot_key,e.slot)||p.committed_at!==e.committed||!(u53(p.committed_at)<=e.at&&e.at<u53(p.retain_until)))fail();
    verifyBoundedControlSignature(p,signed.proof,e.key,budget);
    if(name==='checkpoint'){if(Object.entries(initial).some(([k,value])=>!same(p[k],value)))fail();}
    else if(!same(p.checkpoint_ref,held.checkpoint.ref)||u53(p.count)!==0||p.range_root_ref!==null||u53(p.catalog_generation)!==0||p.retain_until!==held.checkpoint.payload.retain_until)fail();
    held[name]=Object.freeze({ref:item.ref,payload:p,get raw(){budget.output(item.raw.length);return Uint8Array.from(item.raw);}});
  }
  return Object.freeze(held) as Readonly<Record<'head'|'checkpoint',AuthenticatedRepairOriginal>>;
}

export interface MailboxResourceOptions{
  readonly expectedRoot:unknown;readonly expectedOwner:unknown;readonly expectedTarget:unknown;readonly targetStorageEpoch:string;
  readonly expectedPurpose:string;readonly expectedScope:unknown;readonly expectedAuthorityRefs:unknown;readonly expectedOfferRefs:unknown;
  readonly at:number;readonly policy:RepairPolicy;readonly budget:RepairBudget;
}
/** Scope and authority refs must come from the independently checked owner chain. */
export function verifyMailboxResourceInputs(entries:unknown,options:MailboxResourceOptions):Readonly<Record<'allocate'|'offer'|'activation'|'active',AuthenticatedRepairOriginal>>{
  const a=fields(options,['expectedRoot','expectedOwner','expectedTarget','targetStorageEpoch','expectedPurpose','expectedScope','expectedAuthorityRefs','expectedOfferRefs','at','policy','budget']);
  const {policy,budget}=a,e=buildNewWire({root:a.expectedRoot,owner:a.expectedOwner,target:a.expectedTarget,epoch:a.targetStorageEpoch,purpose:a.expectedPurpose,
    scope:a.expectedScope,authorities:a.expectedAuthorityRefs,offers:a.expectedOfferRefs,at:a.at},policy,budget).value as Obj;
  const mismatch=()=>fail('repair_resource_mismatch');
  const root=(v:unknown):Obj=>{const r=fields(v,['owner','root_kind','anchor_ref','owner_epoch','root_id']);dual(r.owner);
    const anchor=fields(r.anchor_ref,['namespace','key']);if(r.root_kind!=='mailbox'||anchor.namespace!=='anchor')mismatch();
    pattern(anchor.key,/^[0-9a-f]{64}$/);opaque(r.owner_epoch);opaque(r.root_id);return r;};
  root(e.root);opaque(e.epoch);u53(e.at);const owner=dualKey(e.owner,budget),target=dualKey(e.target,budget);
  if(!same(e.root.owner,owner)||!['anchor_catalog','feed_metadata','mailbox_data'].includes(e.purpose))mismatch();
  const shapes={allocate:'issued_at expires_at request_id target_node_key_id target_storage_epoch intent intent_sha256',
    offer:'issued_at reservation_until offer_id allocation_request_ref intent intent_sha256 resource target_encryption_key reservation_generation budget windows',
    activation:FIELDS.activation,active:'activated_at offer_ref activation_ref resource reservation_generation root_key purpose budget windows'};
  const v=fields(entries,Object.keys(shapes)),checked:Obj={};
  for(const name of Object.keys(shapes) as (keyof typeof shapes)[]){
    const item=original(v[name],policy,budget),signed=fields(parseNewWire(item.raw,policy,budget).value,['payload','proof']);
    const p=fields(signed.payload,[...COMMON,...shapes[name].split(' ')]);
    if(p.schema_version!=='memory-vault-open-repair/v1'||p.kind!=='resource.'+name)fail('repair_invalid_resource');
    verifyBoundedControlSignature(p,signed.proof,(name==='offer'||name==='active'?e.target:e.owner).signing_key,budget);
    checked[name]=Object.freeze({ref:item.ref,payload:p,get raw(){budget.output(item.raw.length);return Uint8Array.from(item.raw);}});
  }
  const [allocate,offer,activation,active]=['allocate','offer','activation','active'].map(n=>checked[n].payload);
  for(const p of [allocate,activation]){
    if(u53(p.issued_at)>=u53(p.expires_at))fail('repair_invalid_resource');
    if(p.target_node_key_id!==target.signing_key_id||p.target_storage_epoch!==e.epoch)mismatch();
  }
  opaque(allocate.request_id);opaque(activation.activation_id);opaque(offer.offer_id);
  const amounts=(v:unknown)=>{const p=fields(v,BUDGET);for(const n of BUDGET)u53(p[n]);};
  const windows=(v:unknown,issued?:number)=>{const p=fields(v,WINDOWS);for(const n of WINDOWS){u53(p[n]);if(p[n]>p.retain_until||(issued!==undefined&&p[n]<=issued))fail('repair_invalid_resource');}};
  for(const p of [allocate,offer]){
    const intent=fields(p.intent,['kind','allocation_id','root_key','owner','target','target_storage_epoch','purpose','budget','windows']);
    if(intent.kind!=='resource.owner_intent'||intent.purpose!==e.purpose)fail('repair_invalid_resource');
    opaque(intent.allocation_id);opaque(intent.target_storage_epoch);root(intent.root_key);dualKey(intent.owner,budget);dualKey(intent.target,budget);amounts(intent.budget);windows(intent.windows);
    if(p.intent_sha256!==budget.hash(buildNewWire(intent,policy,budget).raw))mismatch();
  }
  const intent=allocate.intent;
  if(!same(offer.intent,intent)||!same(intent.root_key,e.root)||!same(intent.owner,e.owner)||!same(intent.target,e.target)||intent.target_storage_epoch!==e.epoch||intent.purpose!==e.purpose)mismatch();
  windows(intent.windows,allocate.issued_at);
  const resource=fields(offer.resource,['node_key_id','storage_epoch','lease_id','resource_id']);pattern(resource.node_key_id,/^ed25519_[0-9a-f]{64}$/);
  for(const n of ['storage_epoch','lease_id','resource_id'])opaque(resource[n]);
  if(resource.node_key_id!==target.signing_key_id||resource.storage_epoch!==e.epoch||!same(offer.target_encryption_key,e.target.encryption_key)||
    !same(rawRef(offer.allocation_request_ref),checked.allocate.ref)||!same(rawRef(active.offer_ref),checked.offer.ref)||!same(rawRef(active.activation_ref),checked.activation.ref))mismatch();
  if(!Array.isArray(e.offers)||!same(activation.subject,e.owner)||!same(activation.root_key,e.root)||!same(activation.scope,e.scope)||
    !same(activation.authority_refs,e.authorities)||!same(activation.resource_offer_refs,e.offers)||!e.offers.some((ref:unknown)=>same(ref,checked.offer.ref))||!same(active.root_key,e.root)||active.purpose!==e.purpose)mismatch();
  amounts(offer.budget);windows(offer.windows);u53(offer.reservation_generation,1);
  if(['budget','windows'].some(n=>!same(offer[n],intent[n]))||['resource','reservation_generation','budget','windows'].some(n=>!same(active[n],offer[n])))mismatch();
  const issued=u53(offer.issued_at),reserved=u53(offer.reservation_until),activated=u53(active.activated_at);
  if(!(allocate.issued_at<=issued&&issued<allocate.expires_at&&issued<=activation.issued_at&&activation.issued_at<=activated&&activated<=e.at&&
    activated<Math.min(reserved,activation.expires_at,...Object.values(offer.windows) as number[])))mismatch();
  return Object.freeze(checked) as Readonly<Record<'allocate'|'offer'|'activation'|'active',AuthenticatedRepairOriginal>>;
}
