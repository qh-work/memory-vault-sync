/** Exact post-envelope ACK write and limited offer-bootstrap originals.
 * These checks authenticate assertions for independently selected keys/slot/E.
 * They do not bind a slot, consult current status, admit a receipt or perform IO.
 */
import {buildNewWire,parseNewWire,rawRef,objectFields,u53,RepairError} from './open-repair-wire.ts';
import type {RawRef,RepairPolicy,RepairBudget} from './open-repair-wire.ts';
import {canonicalOriginalControl,originalPublicDescriptor,verifyBoundedControlSignature} from './open-repair-original.ts';
import {knownHistoricalRoles} from './open-repair-history.ts';
import type {AuthenticatedRepairOriginal} from './open-repair-resource.ts';

type Obj=Record<string,any>;
const SCHEMA='memory-vault-open-repair/v1',COMMON=['schema_version','kind','signing_key'];
const ROOT=['issued_at','expires_at','ack_slot','authority_id','owner','receipt_writer','original_resource_ref','original_resource_offer_ref',
  'maintainers','operation_mask','allowed_roles','max_bindings','max_receipts','budget','windows','max_delegate_depth','max_destinations_per_job','max_concurrent_jobs','revision'];
const WRITE=['issued_at','expires_at','grant_id','ack_slot','root_authority_ref','owner','receipt_writer','message_id','envelope_ref','operation','max_receipts','budget','windows','revision'];
const OFFER=['issued_at','expires_at','grant_id','revision','owner','subject','root_key','consumer','selector','parent_authority_ref','caller_authority_ref',
  'probe_until','proof_until','upload_until','probe_profile','response_profile','upload_roles','limits'];
const SELECTOR=['root_key_sha256','ack_slot_sha256','root_authority_sha256','write_grant_sha256'];
const BUDGET=['max_live_bytes','max_meta_bytes','max_items','max_requests','max_pending','max_replay_records','max_jobs','max_job_bytes'];
const WINDOWS=['admit_until','read_until','copy_until','publish_until','retain_until'];
const LIMITS=['max_probe_bytes','max_proof_bytes','max_proof_items','max_signature_checks','max_requests','max_pending','max_replay_records','max_concurrent_handles','max_candidate_attempts'];
const UPLOAD=new Set(['ack.root_authority','ack.write_grant','bootstrap.grant']);
const ROLES=new Set([...knownHistoricalRoles,'bootstrap.grant','mailbox_root_service_v1','selected_slot_service_v1','ack_owner_service_v1','ack_offer_service_v1']);
const OPTIONS=['expectedAckSlot','expectedOwner','expectedReceiptWriter','expectedMessageId','expectedEnvelopeRef','at','policy','budget'];
export interface AckWriteOptions{readonly expectedAckSlot:unknown;readonly expectedOwner:unknown;readonly expectedReceiptWriter:unknown;
  readonly expectedMessageId:string;readonly expectedEnvelopeRef:unknown;readonly at:number;readonly policy:RepairPolicy;readonly budget:RepairBudget;}
export interface AckOfferBootstrapOptions extends AckWriteOptions{readonly limitPolicy:unknown;}
export interface AuthenticatedAckWriteInputs{readonly originals:Readonly<{root:AuthenticatedRepairOriginal;write:AuthenticatedRepairOriginal}>;readonly at:number;}
export interface AuthenticatedAckOfferBootstrapInputs{readonly originals:Readonly<{root:AuthenticatedRepairOriginal;write:AuthenticatedRepairOriginal;bootstrap:AuthenticatedRepairOriginal}>;readonly at:number;}
function fail(code='repair_invalid_ack_bound'):never{throw new RepairError(code);}
function mismatch():never{fail('repair_ack_bound_mismatch');}
function fields(value:unknown,names:readonly string[]):Obj{try{return objectFields(value,names);}catch{fail();}}
function number(value:unknown,min=0):number{try{return u53(value,min);}catch{fail();}}
function pattern(value:unknown,expression:RegExp):string{if(typeof value!=='string'||expression.exec(value)?.[0]!==value)fail();return value;}
function opaque(value:unknown):void{pattern(value,/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/);}
function digest(value:unknown):void{pattern(value,/^[0-9a-f]{64}$/);}
function key(value:unknown,encryption=false):void{pattern(value,encryption?/^x25519_[0-9a-f]{64}$/:/^ed25519_[0-9a-f]{64}$/);}
function same(a:unknown,b:unknown):boolean{
  if(a===b)return true;if(a===null||b===null||typeof a!=='object'||typeof b!=='object'||Array.isArray(a)!==Array.isArray(b))return false;
  const names=Object.keys(a);return names.length===Object.keys(b).length&&names.every(name=>Object.hasOwn(b,name)&&same((a as Obj)[name],(b as Obj)[name]));
}
function dual(value:unknown):Obj{const raw=fields(value,['signing_key_id','encryption_key_id']);key(raw.signing_key_id);key(raw.encryption_key_id,true);return raw;}
function dualShape(value:unknown):Obj{const raw=fields(value,['signing_key','encryption_key']);for(const name of ['signing_key','encryption_key'])fields(raw[name],['schema_version','algorithm','key_id','public_key']);return raw;}
function dualKey(value:Obj,budget:RepairBudget):Obj{originalPublicDescriptor(value.signing_key,budget);originalPublicDescriptor(value.encryption_key,budget,true);return {signing_key_id:value.signing_key.key_id,encryption_key_id:value.encryption_key.key_id};}
function rootKey(value:unknown):Obj{
  const raw=fields(value,['owner','root_kind','anchor_ref','owner_epoch','root_id']);dual(raw.owner);if(raw.root_kind!=='ack_return')fail();
  const anchor=fields(raw.anchor_ref,['namespace','key']);if(anchor.namespace!=='anchor')fail();digest(anchor.key);opaque(raw.owner_epoch);opaque(raw.root_id);return raw;
}
function slot(value:unknown):Obj{const raw=fields(value,['root_key','slot_id','receipt_writer','grant_id']);rootKey(raw.root_key);opaque(raw.slot_id);dual(raw.receipt_writer);opaque(raw.grant_id);return raw;}
function reference(value:unknown,metadata=true):RawRef{
  const held=fields(value,['namespace','key','raw_sha256','size']);let result:RawRef;try{result=rawRef(held);}catch{fail();}
  if(metadata&&result.namespace!=='meta')fail();return result;
}
function lifetime(payload:Obj):void{if(number(payload.expires_at)<=number(payload.issued_at))fail();}
function amounts(value:unknown):Obj{const raw=fields(value,BUDGET);for(const name of BUDGET)number(raw[name]);return raw;}
function limits(value:unknown):Obj{const raw=fields(value,LIMITS);for(const name of LIMITS)number(raw[name],1);return raw;}
function windows(value:unknown,payload:Obj):void{const raw=fields(value,WINDOWS);for(const name of WINDOWS){const n=number(raw[name]);if(n<=payload.issued_at||n>payload.expires_at||n>raw.retain_until)fail();}}
function ordered(value:unknown,allowed:ReadonlySet<string>):void{
  if(!Array.isArray(value))fail();let previous='';for(const name of value){if(typeof name!=='string'||!allowed.has(name)||name<=previous)fail();previous=name;}
}
function rootShape(payload:Obj):void{
  lifetime(payload);slot(payload.ack_slot);opaque(payload.authority_id);dual(payload.owner);dual(payload.receipt_writer);
  const resource=fields(payload.original_resource_ref,['node_key_id','storage_epoch','lease_id','resource_id']);key(resource.node_key_id);for(const name of ['storage_epoch','lease_id','resource_id'])opaque(resource[name]);
  reference(payload.original_resource_offer_ref);if(number(payload.operation_mask)>127)fail();ordered(payload.allowed_roles,ROLES);amounts(payload.budget);windows(payload.windows,payload);
  for(const name of ['max_destinations_per_job','max_concurrent_jobs','revision'])number(payload[name]);
  if(number(payload.max_bindings)!==1||number(payload.max_receipts)!==1||number(payload.max_delegate_depth)!==2)fail();
  if(!Array.isArray(payload.maintainers))fail();let previous='';for(const item of payload.maintainers){const id=dual(item),current=id.signing_key_id+':'+id.encryption_key_id;if(current<=previous)fail();previous=current;}
}
function writeShape(payload:Obj):void{
  lifetime(payload);number(payload.revision);opaque(payload.grant_id);slot(payload.ack_slot);dual(payload.owner);dual(payload.receipt_writer);
  pattern(payload.message_id,/^msg_[0-9a-f]{64}$/);reference(payload.root_authority_ref);reference(payload.envelope_ref,false);
  if(payload.operation!=='receipt.put'||number(payload.max_receipts)!==1)fail();amounts(payload.budget);windows(payload.windows,payload);
}
function offerShape(payload:Obj):void{
  for(const name of ['issued_at','expires_at','revision','probe_until','proof_until','upload_until'])number(payload[name]);
  opaque(payload.grant_id);dual(payload.owner);dual(payload.subject);rootKey(payload.root_key);
  if(payload.consumer!=='ack_offer'||payload.probe_profile!=='opaque_v1'||payload.response_profile!=='ack_offer_service_v1')fail();
  const selector=fields(payload.selector,SELECTOR);for(const name of SELECTOR)digest(selector[name]);reference(payload.parent_authority_ref);reference(payload.caller_authority_ref);
  ordered(payload.upload_roles,UPLOAD);limits(payload.limits);
}
function verify(value:unknown,role:'root'|'write'|'bootstrap',owner:Obj,policy:RepairPolicy,budget:RepairBudget):AuthenticatedRepairOriginal{
  const entry=fields(value,['raw','ref']),ref=reference(entry.ref),parsed=parseNewWire(entry.raw,policy,budget),raw=parsed.raw;
  if(raw.length!==ref.size||budget.hash(raw)!==ref.raw_sha256)fail('repair_ref_mismatch');
  const signed=fields(parsed.value,['payload','proof']),names=role==='root'?ROOT:role==='write'?WRITE:OFFER,payload=fields(signed.payload,[...COMMON,...names]);
  if(payload.schema_version!==SCHEMA||payload.kind!==(role==='root'?'ack.root_authority':role==='write'?'ack.write_grant':'bootstrap.grant'))fail();
  if(role==='root')rootShape(payload);else if(role==='write')writeShape(payload);else offerShape(payload);
  verifyBoundedControlSignature(payload,signed.proof,owner.signing_key,budget);
  return Object.freeze({ref,payload,get raw():Uint8Array{budget.output(raw.length);return Uint8Array.from(raw);}});
}
function expected(args:Obj,offer=false):{value:Obj;owner:Obj;writer:Obj;policy:RepairPolicy;budget:RepairBudget}{
  const policy=args.policy as RepairPolicy,budget=args.budget as RepairBudget;
  const value=buildNewWire({ack_slot:args.expectedAckSlot,owner:args.expectedOwner,receipt_writer:args.expectedReceiptWriter,
    message_id:args.expectedMessageId,envelope_ref:args.expectedEnvelopeRef,at:args.at,...(offer?{limit_policy:args.limitPolicy}:{})},policy,budget).value as Obj;
  const ackSlot=slot(value.ack_slot),ownerKeys=dualShape(value.owner),writerKeys=dualShape(value.receipt_writer);
  const owner=dualKey(ownerKeys,budget),writer=dualKey(writerKeys,budget);pattern(value.message_id,/^msg_[0-9a-f]{64}$/);reference(value.envelope_ref,false);number(value.at);
  if(!same(ackSlot.root_key.owner,owner)||!same(ackSlot.receipt_writer,writer))mismatch();return {value,owner,writer,policy,budget};
}
function writeInputs(entry:unknown,rootEntry:unknown,context:ReturnType<typeof expected>):{root:AuthenticatedRepairOriginal;write:AuthenticatedRepairOriginal}{
  const {value:e,owner,writer,policy,budget}=context,root=verify(rootEntry,'root',e.owner,policy,budget),write=verify(entry,'write',e.owner,policy,budget);
  const r=root.payload as Obj,w=write.payload as Obj;
  if(!same(r.ack_slot,e.ack_slot)||!same(w.ack_slot,e.ack_slot)||[r,w].some(v=>!same(v.owner,owner)||!same(v.receipt_writer,writer))||
    w.grant_id!==e.ack_slot.grant_id||!same(w.root_authority_ref,root.ref)||w.message_id!==e.message_id||!same(w.envelope_ref,e.envelope_ref)||
    (r.operation_mask&1)!==1||BUDGET.some(name=>w.budget[name]>r.budget[name])||WINDOWS.some(name=>w.windows[name]>r.windows[name]))mismatch();
  if(!(r.issued_at<=w.issued_at&&w.issued_at<=e.at&&e.at<w.expires_at&&w.expires_at<=r.expires_at))fail();return {root,write};
}
export function verifyAckWriteGrantOriginal(entry:unknown,rootEntry:unknown,options:AckWriteOptions):AuthenticatedAckWriteInputs{
  const args=fields(options,OPTIONS),ctx=expected(args),originals=writeInputs(entry,rootEntry,ctx);
  return Object.freeze({originals:Object.freeze(originals),at:ctx.value.at});
}
export function verifyAckOfferBootstrapOriginal(entry:unknown,parents:unknown,options:AckOfferBootstrapOptions):AuthenticatedAckOfferBootstrapInputs{
  const args=fields(options,[...OPTIONS,'limitPolicy']),held=fields(parents,['root','write']),ctx=expected(args,true),{value:e,owner,writer,policy,budget}=ctx;
  const local=limits(e.limit_policy),originals={...writeInputs(held.write,held.root,ctx),bootstrap:verify(entry,'bootstrap',e.owner,policy,budget)};
  const r=originals.root.payload as Obj,w=originals.write.payload as Obj,g=originals.bootstrap.payload as Obj;
  if(!same(g.owner,owner)||!same(g.subject,writer)||!same(g.root_key,e.ack_slot.root_key)||!same(g.parent_authority_ref,originals.root.ref)||
    !same(g.caller_authority_ref,originals.write.ref)||(r.operation_mask&11)!==11||!['bootstrap.grant','ack_offer_service_v1'].every(name=>r.allowed_roles.includes(name))||
    g.upload_roles.some((name:string)=>!r.allowed_roles.includes(name)))mismatch();
  const selector={root_key_sha256:budget.hash(canonicalOriginalControl(e.ack_slot.root_key,budget)),ack_slot_sha256:budget.hash(canonicalOriginalControl(e.ack_slot,budget)),
    root_authority_sha256:originals.root.ref.raw_sha256,write_grant_sha256:originals.write.ref.raw_sha256};if(!same(g.selector,selector))mismatch();
  if(!(w.issued_at<=g.issued_at&&g.issued_at<=e.at&&e.at<g.expires_at&&g.expires_at<=Math.min(r.expires_at,w.expires_at)))fail();
  for(const name of ['probe_until','proof_until','upload_until'])if(!(g.issued_at<g[name]&&g[name]<=g.expires_at))fail();
  if(g.proof_until>Math.min(r.windows.read_until,r.windows.retain_until,w.windows.admit_until,w.windows.retain_until)||
    g.upload_until>Math.min(r.windows.admit_until,r.windows.retain_until,w.windows.admit_until,w.windows.retain_until))mismatch();
  for(const parent of [r.budget,w.budget]){
    const caps:Obj={max_probe_bytes:Math.min(parent.max_meta_bytes,parent.max_job_bytes),max_proof_bytes:Math.min(parent.max_meta_bytes,parent.max_job_bytes),
      max_proof_items:parent.max_items,max_signature_checks:parent.max_requests,max_requests:parent.max_requests,max_pending:parent.max_pending,
      max_replay_records:parent.max_replay_records,max_concurrent_handles:Math.min(parent.max_pending,parent.max_jobs),max_candidate_attempts:Math.min(parent.max_requests,parent.max_jobs)};
    if(LIMITS.some(name=>g.limits[name]>local[name]||g.limits[name]>caps[name]))mismatch();
  }
  return Object.freeze({originals:Object.freeze(originals),at:e.at});
}
