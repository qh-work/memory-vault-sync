/** Authenticate a retained mailbox member at its original admission time.
 * Current permission, source custody and ciphertext are verified by the reader.
 */
import {buildNewWire,parseNewWire,objectFields,rawRef,u53,RepairError} from './open-repair-wire.ts';
import type {RepairPolicy,RepairBudget,LocalRawResolver,RawOriginal} from './open-repair-wire.ts';
import {resolveHistoricalInputs} from './open-repair-history.ts';
import type {DraftHistoryInputs} from './open-repair-history.ts';
import {originalPublicDescriptor,verifyContactOriginals,verifyBoundedControlSignature} from './open-repair-original.ts';
import {verifyMailboxSlotOwnerInputs,verifyMailboxResourceInputs} from './open-repair-mailbox-authority.ts';
import {verifyAckOfferBootstrapOriginal} from './open-repair-bound.ts';
import {statusScope,verifyStatusOriginal} from './open-repair-status.ts';
import type {AuthenticatedStatusOriginal} from './open-repair-status.ts';
type Obj=Record<string,any>;
const ACK=['ack.root_authority','ack.write_grant','bootstrap.ack_offer','historical.status.ack_root','historical.status.ack_write','historical.status.ack_offer_bootstrap'];
const BASE=('mailbox.slot mailbox.read_grant mailbox.maintenance_root bootstrap.mailbox_feed resource.data_allocate resource.metadata_allocate resource.data_offer resource.metadata_offer resource.slot_activation resource.data_active resource.metadata_active source.descriptor historical.status.slot historical.status.read historical.status.maintenance historical.status.bootstrap contact.request delivery.attempt message.disclosure contact.policy contact.decision contact.store_grant contact.knock_lease contact.delivery_lease delivery.destination historical.status.disclosure historical.status.destination historical.status.data_resource historical.status.metadata_resource').split(' ');
const CAPS='max_live_bytes max_meta_bytes max_items max_requests max_pending max_replay_records max_jobs max_job_bytes'.split(' ');
const WINDOWS='admit_until read_until copy_until publish_until retain_until'.split(' ');
const INDEX_LIMITS={max_probe_bytes:8192,max_proof_bytes:4194304,max_proof_items:64,max_signature_checks:4096,max_requests:256,max_pending:8,max_replay_records:256,max_concurrent_handles:8,max_candidate_attempts:8};
export interface MailboxMemberOptions{
  readonly expectedSlot:unknown;readonly expectedOwner:unknown;readonly expectedSender:unknown;readonly expectedTarget:unknown;
  readonly targetStorageEpoch:string;readonly acceptedAt:number;readonly limitPolicy:unknown;readonly policy:RepairPolicy;readonly budget:RepairBudget;
}
function fail(code='repair_mailbox_activation_mismatch'):never{throw new RepairError(code);}
const fields=(v:unknown,n:readonly string[]):Obj=>objectFields(v,n);
function same(a:unknown,b:unknown):boolean{
  if(a===b)return true;if(!a||!b||typeof a!=='object'||typeof b!=='object'||Array.isArray(a)!==Array.isArray(b))return false;
  const names=Object.keys(a);return names.length===Object.keys(b).length&&names.every(n=>Object.hasOwn(b,n)&&same((a as Obj)[n],(b as Obj)[n]));
}
function dual(v:unknown,budget:RepairBudget):Obj{const k=fields(v,['signing_key','encryption_key']);originalPublicDescriptor(k.signing_key,budget);originalPublicDescriptor(k.encryption_key,budget,true);return {signing_key_id:k.signing_key.key_id,encryption_key_id:k.encryption_key.key_id};}
function opaque(v:unknown):void{if(typeof v!=='string'||/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.exec(v)?.[0]!==v)fail();}
function roleSet(roles:Obj,names:string[]):boolean{return same(Object.keys(roles).sort(),[...names].sort());}
function setup(resolved:DraftHistoryInputs,e:Obj,policy:RepairPolicy,budget:RepairBudget):Obj{
  const m=resolved.manifest.value as Obj,roles:Record<string,RawOriginal>=Object.create(null);
  if(m.variant!=='mailbox_member'||!same(m.slot_key,e.slot)||!same(m.root_key,e.slot.root_key)||resolved.predecessors.length)fail();
  for(const row of resolved.roles){if(Object.hasOwn(roles,row.role))fail();roles[row.role]=row.original;}
  const get=(role:string)=>{if(!Object.hasOwn(roles,role))fail('repair_original_missing');return {raw:roles[role].raw,ref:roles[role].ref};};
  const entries=Object.fromEntries(Object.entries({slot:'mailbox.slot',read:'mailbox.read_grant',maintenance:'mailbox.maintenance_root',bootstrap:'bootstrap.mailbox_feed',activation:'resource.slot_activation'}).map(([n,r])=>[n,get(r)]));
  const resources=Object.fromEntries(['data','metadata'].map(n=>[n,Object.fromEntries(['allocate','offer','active'].map(p=>[p,get('resource.'+n+'_'+p)]))]));
  const active=['data','metadata'].map(n=>fields(parseNewWire(resources[n].active.raw,policy,budget).value,['payload','proof']).payload);
  const activated=u53(active[0]?.activated_at);if(active[1]?.activated_at!==activated||activated>e.at)fail();
  const originals=verifyMailboxSlotOwnerInputs(entries,{data:resources.data.offer,metadata:resources.metadata.offer},{expectedSlot:e.slot,expectedOwner:e.owner,
    expectedTarget:e.target,targetStorageEpoch:e.epoch,limitPolicy:e.limits,at:activated,policy,budget});
  const slot=originals.slot.payload,activation=originals.activation.payload;
  if(!same(slot.sender,dual(e.sender,budget))||!same(slot.recipient,dual(e.owner,budget)))fail();
  for(const name of ['slot','read','maintenance','bootstrap'] as const){const p=originals[name].payload;
    if(!(p.issued_at<=e.at&&e.at<p.expires_at)||(p.windows&&e.at>=Math.min(p.windows.admit_until,p.windows.retain_until)))fail('repair_resource_expired');}
  const checked:Obj={};
  for(const [name,purpose] of [['data','mailbox_data'],['metadata','feed_metadata']]){
    checked[name]=verifyMailboxResourceInputs({...resources[name],activation:entries.activation},{expectedRoot:e.slot.root_key,expectedOwner:e.owner,expectedTarget:e.target,
      targetStorageEpoch:e.epoch,expectedPurpose:purpose,expectedScope:activation.scope,expectedAuthorityRefs:activation.authority_refs,expectedOfferRefs:activation.resource_offer_refs,at:e.at,policy,budget});
    if(!same(checked[name].active.payload.resource,slot[name+'_resource_ref']))fail();
  }
  const contact=verifyContactOriginals(Object.fromEntries(Object.entries({node:'source.descriptor',request:'contact.request',policy:'contact.policy',decision:'contact.decision',grant:'contact.store_grant',knock_lease:'contact.knock_lease',delivery_lease:'contact.delivery_lease'}).map(([n,r])=>[n,get(r).raw])),
    {senderKeyId:e.sender.signing_key.key_id,senderEncryptionKeyId:e.sender.encryption_key.key_id,recipientKeyId:e.owner.signing_key.key_id,
      recipientEncryptionKeyId:e.owner.encryption_key.key_id,nodeKeyId:e.target.signing_key.key_id,storageEpoch:e.epoch,at:e.at,policy,budget});
  return {originals,resources:Object.freeze(checked),contact,roles:Object.freeze(roles),accepted_at:e.at};
}
/** Each observation must cover its duty, and every scope it contains belongs to
 * that signer. Reuse is bounded to exact bytes plus context in this invocation. */
function historicalStatuses(roles:Obj,duties:Obj[],root:unknown,at:number,policy:RepairPolicy,budget:RepairBudget):readonly AuthenticatedStatusOriginal[]{
  const statuses:AuthenticatedStatusOriginal[]=[],cache=new Map<string,AuthenticatedStatusOriginal>(),revisions=new Map<string,string>(),floors=new Map<string,number[][]>();
  for(const duty of duties){
    const permitted=duties.filter(v=>same(v.signer,duty.signer)),entry=roles['historical.status.'+duty.role];if(!entry)fail('repair_original_missing');
    const raw=entry.raw,preview=fields(parseNewWire(raw,policy,budget).value,['payload','proof']).payload;
    if(!preview||!Array.isArray(preview.entries))fail('repair_invalid_status');
    const present=new Set(preview.entries.map((v:Obj)=>{if(!v||typeof v.scope_kind!=='string'||typeof v.scope_id!=='string')fail('repair_invalid_status');return v.scope_kind+':'+v.scope_id;}));
    const required=permitted.filter(v=>present.has(v.scope_kind+':'+v.scope_id)).map(v=>({scope_kind:v.scope_kind,scope_id:v.scope_id,document_revision:v.document_revision,operation_mask:v.operation_mask}));
    if(!required.some(v=>v.scope_kind===duty.scope_kind&&v.scope_id===duty.scope_id))fail('repair_status_missing');
    const context={expectedRoot:root,expectedSigningKey:duty.signer,at,allowedScopes:permitted.map(v=>({scope_kind:v.scope_kind,scope_id:v.scope_id})),required};
    const contextRaw=buildNewWire(context,policy,budget).raw,ref=rawRef(entry.ref);
    if(ref.namespace!=='meta'||raw.length!==ref.size||budget.hash(raw)!==ref.raw_sha256)fail('repair_ref_mismatch');
    const identity=budget.hash(buildNewWire({ref,context},policy,budget).raw);let observed=cache.get(identity);
    if(!observed){observed=verifyStatusOriginal({raw,ref},{...context,policy,budget});budget.retain(raw.length+contextRaw.length);cache.set(identity,observed);}
    const rev=duty.signer.key_id+':'+observed.payload.revision,prior=revisions.get(rev);
    if(prior!==undefined&&prior!==observed.canonical_sha256)fail('repair_status_conflict');revisions.set(rev,observed.canonical_sha256);statuses.push(observed);
    for(const row of observed.payload.entries){const key=duty.signer.key_id+':'+row.scope_kind+':'+row.scope_id,held=floors.get(key)??[];
      held.push([observed.payload.revision,row.minimum_document_revision]);floors.set(key,held);}
  }
  for(const values of floors.values()){let minimum=0;for(const [,value] of values.sort((a,b)=>a[0]-b[0]||a[1]-b[1])){if(value<minimum)fail('repair_status_rollback');minimum=value;}}
  return Object.freeze(statuses);
}
function ackConfiguration(roles:Obj,e:Obj,m:Obj,policy:RepairPolicy,budget:RepairBudget):Obj{
  const write=fields(parseNewWire(roles['ack.write_grant'].raw,policy,budget).value,['payload','proof']).payload;
  if(!write||typeof write!=='object')fail();
  const entry=(n:string)=>({raw:roles[n].raw,ref:roles[n].ref});
  const checked=verifyAckOfferBootstrapOriginal(entry('bootstrap.ack_offer'),{root:entry('ack.root_authority'),write:entry('ack.write_grant')},
    {expectedAckSlot:write.ack_slot,expectedOwner:e.sender,expectedReceiptWriter:e.owner,expectedMessageId:m.message_id,expectedEnvelopeRef:m.envelope_ref,at:e.at,limitPolicy:INDEX_LIMITS,policy,budget});
  const root=checked.originals.root.payload.ack_slot.root_key,duties=[];
  for(const [name,role,mask] of [['root','ack_root',3],['write','ack_write',1],['bootstrap','ack_offer_bootstrap',3]] as const){const item=checked.originals[name];
    duties.push({role,scope_kind:'authority',scope_id:statusScope(root,'authority',{authority_kind:item.payload.kind,authority_sha256:item.ref.raw_sha256},policy,budget),document_revision:item.payload.revision,operation_mask:mask,signer:e.sender.signing_key});}
  return Object.freeze({originals:checked.originals,statuses:historicalStatuses(roles,duties,root,e.at,policy,budget)});
}
/** Sender preparation verifies the same complete independent receipt originals. */
export function verifyMailboxAckConfiguration(roles:Obj,options:{sender:Obj;recipient:Obj;messageId:string;envelopeRef:unknown;at:number;policy:RepairPolicy;budget:RepairBudget}):Obj{
  if(!roleSet(roles,ACK))fail('repair_original_missing');
  return ackConfiguration(roles,{sender:options.sender,owner:options.recipient,at:options.at},
    {message_id:options.messageId,envelope_ref:options.envelopeRef},options.policy,options.budget);
}
function member(resolved:DraftHistoryInputs,e:Obj,policy:RepairPolicy,budget:RepairBudget):Obj{
  const graph=setup(resolved,e,policy,budget),{roles,originals}=graph,m=resolved.manifest.value as Obj,root=m.root_key,key=m.slot_key,at=e.at;
  if(!roleSet(roles,BASE)&&!roleSet(roles,[...BASE,...ACK]))fail();
  const control=(role:string,names:string,signer:Obj):Obj=>{const signed=fields(parseNewWire(roles[role].raw,policy,budget).value,['payload','proof']);
    const p=fields(signed.payload,['schema_version','kind','signing_key',...names.split(' ')]);
    if(p.schema_version!=='memory-vault-open-repair/v1'||p.kind!==role||u53(p.issued_at)>=u53(p.expires_at))fail();
    if(!(p.issued_at<=at&&at<p.expires_at))fail('repair_resource_expired');verifyBoundedControlSignature(p,signed.proof,signer,budget);return p;};
  const dp=control('delivery.destination','issued_at expires_at destination_id sender recipient contact_request_ref contact_policy_ref contact_knock_lease_ref contact_decision_ref store_grant_ref slot_key slot_ref data_resource_ref data_resource_offer_ref metadata_resource_ref metadata_resource_offer_ref read_grant_ref maintenance_root_ref budget windows',e.owner.signing_key);
  const ap=control('delivery.attempt','issued_at expires_at attempt_id message_id envelope_ref sender recipient destination_ref slot_key operation disclosure_ref ack_grant_ref',e.sender.signing_key);
  const cp=control('message.disclosure','issued_at expires_at consent_id root_key slot_key sender recipient envelope_ref maintenance_root_ref allowed_roles operation_mask consent_until bootstrap_return revision',e.sender.signing_key);
  const slot=originals.slot.payload,maintenance=originals.maintenance.payload;
  for(const [p,id] of [[dp,'destination_id'],[ap,'attempt_id'],[cp,'consent_id']] as const){opaque(p[id]);if(!same(p.slot_key,key)||!same(p.sender,slot.sender)||!same(p.recipient,slot.recipient))fail();}
  if(ap.operation!=='message.store'||ap.message_id!==m.message_id||!same(ap.envelope_ref,m.envelope_ref)||!same(cp.envelope_ref,m.envelope_ref)||
    !same(m.attempt_ref,roles['delivery.attempt'].ref)||!same(ap.destination_ref,roles['delivery.destination'].ref)||!same(ap.disclosure_ref,roles['message.disclosure'].ref)||!same(dp.slot_ref,roles['mailbox.slot'].ref))fail();
  for(const n of ['data_resource_ref','metadata_resource_ref','data_resource_offer_ref','metadata_resource_offer_ref','read_grant_ref','maintenance_root_ref'])if(!same(dp[n],slot[n]))fail();
  fields(dp.budget,CAPS);fields(dp.windows,WINDOWS);
  if(CAPS.some(n=>u53(dp.budget[n])>slot.budget[n])||WINDOWS.some(n=>u53(dp.windows[n])>slot.windows[n]||dp.windows[n]>dp.windows.retain_until)||at>=Math.min(dp.windows.admit_until,dp.windows.retain_until))fail();
  for(const [n,r] of [['contact_request_ref','contact.request'],['contact_policy_ref','contact.policy'],['contact_knock_lease_ref','contact.knock_lease'],['contact_decision_ref','contact.decision'],['store_grant_ref','contact.store_grant']])if(!same(dp[n],roles[r].ref))fail();
  u53(cp.revision,1);if(u53(cp.operation_mask)>127||rawRef(cp.envelope_ref).namespace!=='object')fail();
  if(!same(cp.root_key,root)||!same(cp.maintenance_root_ref,roles['mailbox.maintenance_root'].ref)||cp.issued_at>ap.issued_at||(cp.operation_mask&65)!==65||
    !(at<u53(cp.consent_until)&&cp.consent_until<=cp.expires_at&&cp.expires_at<=Math.min(slot.expires_at,maintenance.expires_at))||cp.consent_until>Math.min(slot.windows.retain_until,maintenance.windows.retain_until))fail();
  const required=['contact.request','delivery.attempt','message.disclosure','authority.status.disclosure'],allowed=cp.allowed_roles;
  if(!Array.isArray(allowed)||allowed.some((v:any,i:number)=>typeof v!=='string'||(i>0&&v<=allowed[i-1])||![...required,...ACK].includes(v))||required.some(n=>!allowed.includes(n)))fail('repair_status_disclosure');
  const returned=fields(cp.bootstrap_return,['subject','consumer','roles','until']);
  if(!same(returned.subject,slot.recipient)||returned.consumer!=='mailbox_feed'||!same(returned.roles,['authority.status.disclosure','message.disclosure'])||!(at<u53(returned.until)&&returned.until<=cp.consent_until))fail('repair_status_disclosure');
  let ack=null;
  if(ap.ack_grant_ref===null){if(!roleSet(roles,BASE))fail();}
  else{if(!roleSet(roles,[...BASE,...ACK])||ACK.some(n=>!allowed.includes(n)))fail('repair_status_disclosure');if(!same(ap.ack_grant_ref,roles['ack.write_grant'].ref))fail();ack=ackConfiguration(roles,e,m,policy,budget);}
  const duties:Obj[]=[],add=(role:string,kind:string,subject:unknown,revision:number,mask:number,signer:Obj)=>duties.push({role,scope_kind:kind,scope_id:statusScope(root,kind,subject,policy,budget),document_revision:revision,operation_mask:mask,signer});
  add('slot','mailbox_slot',key,slot.revision,65,e.owner.signing_key);
  for(const [name,role,p,mask,signer] of [['read','mailbox.read_grant',originals.read.payload,2,e.owner.signing_key],['maintenance','mailbox.maintenance_root',maintenance,65,e.owner.signing_key],
    ['bootstrap','bootstrap.mailbox_feed',originals.bootstrap.payload,10,e.owner.signing_key],['destination','delivery.destination',dp,1,e.owner.signing_key],['disclosure','message.disclosure',cp,65,e.sender.signing_key]] as const){
    add(name,'authority',{authority_kind:p.kind,authority_sha256:roles[role].ref.raw_sha256},p.revision??1,mask,signer);}
  for(const n of ['data','metadata']){const p=graph.resources[n].active.payload;add(n+'_resource','resource',p.resource,p.reservation_generation,65,e.target.signing_key);}
  return Object.freeze({...graph,destination:dp,attempt:ap,disclosure:cp,statuses:historicalStatuses(roles,duties,root,at,policy,budget),obligations:Object.freeze(duties.map(Object.freeze)),ack_configuration:ack});
}
export function verifyMailboxMemberInputs(manifest:unknown,resolver:LocalRawResolver,options:MailboxMemberOptions):Readonly<Obj>{
  const a=fields(options,['expectedSlot','expectedOwner','expectedSender','expectedTarget','targetStorageEpoch','acceptedAt','limitPolicy','policy','budget']),{policy,budget}=a;
  const e=buildNewWire({slot:a.expectedSlot,owner:a.expectedOwner,sender:a.expectedSender,target:a.expectedTarget,epoch:a.targetStorageEpoch,at:a.acceptedAt,limits:a.limitPolicy},policy,budget).value as Obj;
  u53(e.at);for(const k of [e.owner,e.sender,e.target])dual(k,budget);
  const entry=fields(manifest,['raw','ref']),ref=rawRef(entry.ref),raw=parseNewWire(entry.raw,policy,budget).raw;
  if(ref.namespace!=='meta'||ref.size!==raw.length||ref.raw_sha256!==budget.hash(raw))fail('repair_ref_mismatch');
  return member(resolveHistoricalInputs(raw,resolver,policy,budget),e,policy,budget);
}
