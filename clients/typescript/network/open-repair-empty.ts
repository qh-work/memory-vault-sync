/** Original empty ACK source event with its complete unbound predecessor.
 * No summarized predecessor, caller-authenticated wrapper, present permission
 * or receipt replaces the exact historical originals and shared work meter.
 */
import {buildNewWire,parseNewWire,rawRef,objectFields,u53,RepairError} from './open-repair-wire.ts';
import type {RawRef,RawOriginal,RepairPolicy,RepairBudget,LocalRawResolver} from './open-repair-wire.ts';
import {resolveHistoricalInputs} from './open-repair-history.ts';
import type {DraftHistoryInputs} from './open-repair-history.ts';
import {verifyAckUnboundSourceEvent} from './open-repair-ack.ts';
import type {AuthenticatedAckUnboundSourceEvent} from './open-repair-ack.ts';
import {verifyAckOfferBootstrapOriginal} from './open-repair-bound.ts';
import type {AuthenticatedAckOfferBootstrapInputs} from './open-repair-bound.ts';
import type {AuthenticatedRepairOriginal} from './open-repair-resource.ts';
import {parseOriginalControl,verifyBoundedControlSignature} from './open-repair-original.ts';
import {statusScope,verifyStatusOriginal} from './open-repair-status.ts';
import type {AuthenticatedStatusOriginal} from './open-repair-status.ts';

type Obj=Record<string,any>;
export const ACK_EMPTY_STATUS_ROLES=Object.freeze(['historical.status.ack_root','historical.status.ack_read','historical.status.ack_owner_bootstrap',
  'historical.status.ack_write','historical.status.ack_offer_bootstrap','historical.status.ack_slot','historical.status.ack_resource']);
const ROLES=new Set([...ACK_EMPTY_STATUS_ROLES,'history.ack_unbound','ack.unbound_custody','ack.write_grant','bootstrap.ack_offer','ack.binding']);
const COMMON=['schema_version','kind','signing_key'];
const BINDING=[...COMMON,'ack_slot','root_authority_ref','grant_ref','bound_at','resource_ref','retain_until'];
const CUSTODY=[...COMMON,'ack_slot','root_authority_ref','historical_manifest_ref','resource_ref','stored_at','read_until','retain_until','state','grant_ref','binding_ref'];
const OPTIONS=['expectedAckSlot','expectedOwner','expectedReceiptWriter','expectedMessageId','expectedEnvelopeRef','expectedTarget','targetStorageEpoch','limitPolicy','policy','budget'];
const STATUS_PAYLOAD=['schema_version','kind','signing_key','scope_key','revision','issued_at','valid_until','entries'];
const STATUS_ENTRY=['scope_kind','scope_id','minimum_document_revision','status','operation_mask'];
export interface AckEmptySourceEventOptions{readonly expectedAckSlot:unknown;readonly expectedOwner:unknown;readonly expectedReceiptWriter:unknown;
  readonly expectedMessageId:string;readonly expectedEnvelopeRef:unknown;readonly expectedTarget:unknown;readonly targetStorageEpoch:string;
  readonly limitPolicy:unknown;readonly policy:RepairPolicy;readonly budget:RepairBudget;}
export interface AuthenticatedAckEmptySourceEvent{readonly manifest:DraftHistoryInputs;readonly custody:AuthenticatedRepairOriginal;
  readonly predecessor:AuthenticatedAckUnboundSourceEvent;readonly binding:AuthenticatedRepairOriginal;readonly authorities:AuthenticatedAckOfferBootstrapInputs;
  readonly statuses:readonly AuthenticatedStatusOriginal[];readonly stored_at:number;readonly read_until:number;readonly retain_until:number;}
function fail(code='repair_invalid_ack_empty'):never{throw new RepairError(code);}
function mismatch():never{fail('repair_ack_empty_mismatch');}
function fields(value:unknown,names:readonly string[],code='repair_invalid_ack_empty'):Obj{try{return objectFields(value,names);}catch{fail(code);}}
function same(a:unknown,b:unknown):boolean{
  if(a===b)return true;if(a===null||b===null||typeof a!=='object'||typeof b!=='object'||Array.isArray(a)!==Array.isArray(b))return false;
  const names=Object.keys(a);return names.length===Object.keys(b).length&&names.every(name=>Object.hasOwn(b,name)&&same((a as Obj)[name],(b as Obj)[name]));
}
function pattern(value:unknown,expression:RegExp,code='repair_invalid_history'):void{if(typeof value!=='string'||expression.exec(value)?.[0]!==value)fail(code);}
function opaque(value:unknown,code='repair_invalid_history'):void{pattern(value,/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/,code);}
function dual(value:unknown):void{const v=fields(value,['signing_key_id','encryption_key_id'],'repair_invalid_history');pattern(v.signing_key_id,/^ed25519_[0-9a-f]{64}$/);pattern(v.encryption_key_id,/^x25519_[0-9a-f]{64}$/);}
function slot(value:unknown):void{
  const v=fields(value,['root_key','slot_id','receipt_writer','grant_id'],'repair_invalid_history'),root=fields(v.root_key,['owner','root_kind','anchor_ref','owner_epoch','root_id'],'repair_invalid_history');
  dual(root.owner);if(root.root_kind!=='ack_return')fail('repair_invalid_history');const anchor=fields(root.anchor_ref,['namespace','key'],'repair_invalid_history');
  if(anchor.namespace!=='anchor')fail('repair_invalid_history');pattern(anchor.key,/^[0-9a-f]{64}$/);opaque(root.owner_epoch);opaque(root.root_id);opaque(v.slot_id);dual(v.receipt_writer);opaque(v.grant_id);
}
function resource(value:unknown):void{const v=fields(value,['node_key_id','storage_epoch','lease_id','resource_id'],'repair_invalid_history');pattern(v.node_key_id,/^ed25519_[0-9a-f]{64}$/);for(const name of ['storage_epoch','lease_id','resource_id'])opaque(v[name]);}
function dualShape(value:unknown):void{const v=fields(value,['signing_key','encryption_key'],'repair_invalid_resource');for(const name of ['signing_key','encryption_key'])fields(v[name],['schema_version','algorithm','key_id','public_key'],'repair_invalid_resource');}
function reference(value:unknown):RawRef{const ref=rawRef(fields(value,['namespace','key','raw_sha256','size'],'repair_invalid_ack'));if(ref.namespace!=='meta')fail('repair_invalid_ack');return ref;}
function entry(value:unknown):{raw:Uint8Array;ref:RawRef}{const v=fields(value,['raw','ref'],'repair_invalid_ack');return {raw:v.raw,ref:reference(v.ref)};}
function refKey(ref:RawRef):string{return `${ref.namespace}:${ref.key}:${ref.raw_sha256}:${ref.size}`;}
function scopeKey(value:Obj):string{
  if(!['catalog','mailbox_slot','ack_slot','authority','resource','assignment','contact_policy'].includes(value.scope_kind))fail('repair_invalid_status');
  pattern(value.scope_id,/^[0-9a-f]{64}$/,'repair_invalid_status');return value.scope_kind+':'+value.scope_id;
}
function signed(value:unknown,target:Obj,kind:string,policy:RepairPolicy,budget:RepairBudget):AuthenticatedRepairOriginal{
  const item=entry(value),parsed=parseNewWire(item.raw,policy,budget),raw=parsed.raw;
  if(raw.length!==item.ref.size||budget.hash(raw)!==item.ref.raw_sha256)fail('repair_ref_mismatch');
  const doc=fields(parsed.value,['payload','proof']),p=fields(doc.payload,kind==='ack.binding'?BINDING:CUSTODY);
  if(p.schema_version!=='memory-vault-open-repair/v1'||p.kind!==kind)fail();fields(p.ack_slot,['root_key','slot_id','receipt_writer','grant_id']);slot(p.ack_slot);resource(p.resource_ref);
  reference(p.root_authority_ref);reference(p.grant_ref);u53(p.retain_until);
  if(kind==='ack.binding'){if(!(u53(p.bound_at)<p.retain_until))fail();}
  else{reference(p.historical_manifest_ref);reference(p.binding_ref);if(p.state!=='empty'||!(u53(p.stored_at)<u53(p.read_until)&&p.read_until<=p.retain_until))fail();}
  verifyBoundedControlSignature(p,doc.proof,target.signing_key,budget);
  return Object.freeze({ref:item.ref,payload:p,get raw():Uint8Array{budget.output(raw.length);return Uint8Array.from(raw);}});
}
function obligations(prior:AuthenticatedAckUnboundSourceEvent,authorities:AuthenticatedAckOfferBootstrapInputs,owner:Obj,target:Obj,ackSlot:Obj,policy:RepairPolicy,budget:RepairBudget):Obj[]{
  const originals=prior.resources.originals,result:Obj[]=[];
  for(const [role,item,kind,mask] of [
    ['ack_root',originals.root,'ack.root_authority',75],['ack_read',originals.read,'ack.read_grant',2],
    ['ack_owner_bootstrap',prior.bootstrap.originals.bootstrap,'bootstrap.grant',10],['ack_write',authorities.originals.write,'ack.write_grant',1],
    ['ack_offer_bootstrap',authorities.originals.bootstrap,'bootstrap.grant',11]] as const){
    result.push({role:'historical.status.'+role,signer:owner.signing_key,scope_kind:'authority',scope_id:statusScope(ackSlot.root_key,'authority',
      {authority_kind:kind,authority_sha256:item.ref.raw_sha256},policy,budget),revision:item.payload.revision,mask});
  }
  const active=originals.active.payload as Obj;
  for(const [role,kind,subject,revision,signer] of [['ack_slot','ack_slot',ackSlot,originals.root.payload.revision,owner.signing_key],
    ['ack_resource','resource',active.resource,active.reservation_generation,target.signing_key]] as const){
    result.push({role:'historical.status.'+role,signer,scope_kind:kind,scope_id:statusScope(ackSlot.root_key,kind,subject,policy,budget),revision,mask:67});
  }return result;
}
function statuses(roles:Map<string,RawOriginal>,required:Obj[],root:Obj,at:number,policy:RepairPolicy,budget:RepairBudget):AuthenticatedStatusOriginal[]{
  const groups=new Map<string,{entry:RawOriginal;signer:Obj;required:Obj[]}>();
  for(const item of required){const original=roles.get(item.role)!,key=refKey(original.ref),group=groups.get(key)??{entry:{raw:original.raw,ref:original.ref},signer:item.signer,required:[] as Obj[]};
    if(!same(group.signer,item.signer))mismatch();group.required.push({scope_kind:item.scope_kind,scope_id:item.scope_id,document_revision:item.revision,operation_mask:item.mask});groups.set(key,group);}
  const checked:AuthenticatedStatusOriginal[]=[];
  for(const group of groups.values()){
    const permitted=required.filter(item=>same(item.signer,group.signer)),doc=fields(parseOriginalControl(group.entry.raw,policy,budget).value,['payload','proof'],'repair_invalid_status');
    const payload=fields(doc.payload,STATUS_PAYLOAD,'repair_invalid_status');if(!Array.isArray(payload.entries)||payload.entries.length<1||payload.entries.length>16)fail('repair_invalid_status');
    const present=new Set<string>();for(const value of payload.entries)present.add(scopeKey(fields(value,STATUS_ENTRY,'repair_invalid_status')));
    const obligations=new Map(group.required.map(item=>[scopeKey(item),item]));
    for(const item of permitted)if(present.has(scopeKey(item)))obligations.set(scopeKey(item),{scope_kind:item.scope_kind,scope_id:item.scope_id,document_revision:item.revision,operation_mask:item.mask});
    checked.push(verifyStatusOriginal(group.entry,{expectedRoot:root,expectedSigningKey:group.signer,at,allowedScopes:permitted.map(item=>({scope_kind:item.scope_kind,scope_id:item.scope_id})),required:[...obligations.values()],policy,budget}));
  }return checked;
}
function historyFloors(previous:readonly AuthenticatedStatusOriginal[],current:readonly AuthenticatedStatusOriginal[]):void{
  const revisions=new Map<string,string>(),observations=new Map<string,[number,number][]>(),prior=new Map<string,[number,number]>();
  for(const observed of [...previous,...current]){
    const p=observed.payload as Obj,issuer=p.scope_key.issuer_key_id,key=issuer+':'+p.revision;
    if(revisions.has(key)&&revisions.get(key)!==observed.canonical_sha256)fail('repair_status_conflict');revisions.set(key,observed.canonical_sha256);
    for(const item of p.entries){const scope=issuer+':'+scopeKey(item);observations.set(scope,[...(observations.get(scope)??[]),[p.revision,item.minimum_document_revision]]);}
  }
  for(const values of observations.values()){let floor=0;for(const [,minimum] of values.sort((a,b)=>a[0]-b[0]||a[1]-b[1])){if(minimum<floor)fail('repair_status_rollback');floor=minimum;}}
  for(const observed of previous){const p=observed.payload as Obj;for(const item of p.entries){const scope=p.scope_key.issuer_key_id+':'+scopeKey(item),held=prior.get(scope)??[0,0];prior.set(scope,[Math.max(held[0],p.revision),Math.max(held[1],item.minimum_document_revision)]);}}
  for(const observed of current){const p=observed.payload as Obj;for(const item of p.entries){const held=prior.get(p.scope_key.issuer_key_id+':'+scopeKey(item));
    if(held&&(p.revision<held[0]||item.minimum_document_revision<held[1]))fail('repair_status_rollback');}}
}
export function verifyAckEmptySourceEvent(manifestEntry:unknown,resolver:LocalRawResolver,custodyEntry:unknown,options:AckEmptySourceEventOptions):AuthenticatedAckEmptySourceEvent{
  const args=fields(options,OPTIONS),policy=args.policy as RepairPolicy,budget=args.budget as RepairBudget;
  const expected=buildNewWire({ack_slot:args.expectedAckSlot,owner:args.expectedOwner,receipt_writer:args.expectedReceiptWriter,message_id:args.expectedMessageId,
    envelope_ref:args.expectedEnvelopeRef,target:args.expectedTarget,epoch:args.targetStorageEpoch,limit_policy:args.limitPolicy},policy,budget).value as Obj;
  const ackSlot=expected.ack_slot,owner=expected.owner,target=expected.target;fields(ackSlot,['root_key','slot_id','receipt_writer','grant_id']);slot(ackSlot);dualShape(owner);dualShape(target);opaque(expected.epoch,'repair_invalid_original');
  const custody=signed(custodyEntry,target,'ack.slot_custody',policy,budget),event=custody.payload as Obj,at=event.stored_at;
  const input=entry(manifestEntry),parsed=parseNewWire(input.raw,policy,budget),raw=parsed.raw;if(raw.length!==input.ref.size||budget.hash(raw)!==input.ref.raw_sha256)fail('repair_ref_mismatch');
  if(!same(event.ack_slot,ackSlot)||!same(reference(event.historical_manifest_ref),input.ref))mismatch();
  const manifest=resolveHistoricalInputs(raw,resolver,policy,budget),value=manifest.manifest.value as Obj;
  if(value.variant!=='ack_empty'||manifest.predecessors.length!==1||!same(value.ack_slot,ackSlot))mismatch();
  const roles=new Map<string,RawOriginal>();for(const item of manifest.roles){if(!ROLES.has(item.role)||roles.has(item.role))fail();roles.set(item.role,item.original);}
  if(roles.size!==ROLES.size)fail();const original=(role:string):RawOriginal=>{const held=roles.get(role)!;return {raw:held.raw,ref:held.ref};};
  const prior=verifyAckUnboundSourceEvent(original('history.ack_unbound'),resolver,original('ack.unbound_custody'),{expectedAckSlot:ackSlot,expectedOwner:owner,
    expectedTarget:target,targetStorageEpoch:expected.epoch,limitPolicy:expected.limit_policy,policy,budget});
  const root=prior.resources.originals.root;
  const authorities=verifyAckOfferBootstrapOriginal(original('bootstrap.ack_offer'),{root:{raw:root.raw,ref:root.ref},write:original('ack.write_grant')},
    {expectedAckSlot:ackSlot,expectedOwner:owner,expectedReceiptWriter:expected.receipt_writer,expectedMessageId:expected.message_id,expectedEnvelopeRef:expected.envelope_ref,
      at,limitPolicy:expected.limit_policy,policy,budget});
  const binding=signed(original('ack.binding'),target,'ack.binding',policy,budget),b=binding.payload as Obj,w=authorities.originals.write.payload as Obj,g=authorities.originals.bootstrap.payload as Obj;
  const resourceRef=(prior.resources.originals.active.payload as Obj).resource;
  for(const [field,wanted] of [['root_authority_ref',root.ref],['grant_ref',authorities.originals.write.ref],['binding_ref',binding.ref]] as const)
    if(!same(reference(event[field]),wanted)||!same(reference(value[field]),wanted))mismatch();
  if(!same(b.ack_slot,ackSlot)||!same(b.resource_ref,resourceRef)||!same(event.resource_ref,resourceRef)||!same(reference(b.root_authority_ref),root.ref)||
    !same(reference(b.grant_ref),authorities.originals.write.ref)||!(prior.stored_at<=w.issued_at&&w.issued_at<=g.issued_at&&g.issued_at<=b.bound_at&&b.bound_at<=at)||event.retain_until>b.retain_until)mismatch();
  const r=prior.resources.originals.root.payload as Obj,read=prior.resources.originals.read.payload as Obj,active=prior.resources.originals.active.payload as Obj,ownerBoot=prior.bootstrap.originals.bootstrap.payload as Obj;
  if((r.operation_mask&75)!==75)mismatch();
  const readUntil=Math.min(r.windows.read_until,read.windows.read_until,active.windows.read_until,w.windows.admit_until,
    ...[r,read,w,ownerBoot,g].map(item=>item.expires_at),...[ownerBoot,g].flatMap(item=>[item.probe_until,item.proof_until,item.upload_until]));
  const retainUntil=Math.min(r.windows.retain_until,active.windows.retain_until);
  if(event.read_until>readUntil||b.retain_until>retainUntil||at>=Math.min(r.windows.admit_until,active.windows.admit_until,w.windows.admit_until))mismatch();
  const observed=statuses(roles,obligations(prior,authorities,owner,target,ackSlot,policy,budget),ackSlot.root_key,at,policy,budget);historyFloors(prior.statuses,observed);
  return Object.freeze({manifest,custody,predecessor:prior,binding,authorities,statuses:Object.freeze(observed),stored_at:at,read_until:event.read_until,retain_until:event.retain_until});
}
