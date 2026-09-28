/** Original recipient receipt admission with three authenticated generations.
 * Receipt save remains the recipient's signed assertion. Exact consent and put
 * do not replace the live caller's independent possession/access checks.
 */
import {isUint8Array} from 'node:util/types';
import {buildNewWire,parseNewWire,rawRef,objectFields,u53,RepairError} from './open-repair-wire.ts';
import type {RawRef,RawOriginal,RepairPolicy,RepairBudget,LocalRawResolver} from './open-repair-wire.ts';
import {knownHistoricalRoles,resolveHistoricalInputs} from './open-repair-history.ts';
import type {DraftHistoryInputs} from './open-repair-history.ts';
import {ACK_EMPTY_STATUS_ROLES,verifyAckEmptySourceEvent} from './open-repair-empty.ts';
import type {AckEmptySourceEventOptions,AuthenticatedAckEmptySourceEvent} from './open-repair-empty.ts';
import type {AuthenticatedRepairOriginal} from './open-repair-resource.ts';
import {parseOriginalControl,verifyBoundedControlSignature} from './open-repair-original.ts';
import {statusScope,verifyStatusOriginal} from './open-repair-status.ts';
import type {AuthenticatedStatusOriginal} from './open-repair-status.ts';
import {PROFILE as RECEIPT_PROFILE,RECEIPT_FIELDS,verifyRecipientReceipt} from './open-delivery-control.ts';

type Obj=Record<string,any>;
const SCHEMA='memory-vault-open-repair/v1',COMMON=['schema_version','kind','signing_key'];
export const ACK_OCCUPIED_STATUS_ROLES=Object.freeze([...ACK_EMPTY_STATUS_ROLES.filter(role=>role!=='historical.status.ack_resource'),
  'historical.status.ack_disclosure','historical.status.admission_resource']);
const ROLES=new Set([...ACK_OCCUPIED_STATUS_ROLES,'history.ack_empty','ack.empty_custody','recipient.receipt','ack.disclosure','ack.put']);
const B_ROLES=['recipient.receipt','ack.disclosure','ack.put','historical.status.ack_disclosure'];
const DISCLOSURE=[...COMMON,'issued_at','expires_at','consent_id','ack_slot','root_authority_ref','grant_ref','receipt_ref','recipient','owner',
  'allowed_roles','operation_mask','consent_until','bootstrap_return','revision'];
const PUT=[...COMMON,'issued_at','expires_at','put_id','ack_slot','grant_ref','binding_ref','receipt_ref','disclosure_ref','operation'];
const COMMIT=[...COMMON,'ack_slot','grant_ref','binding_ref','receipt_ref','put_ref','disclosure_ref','historical_manifest_ref','resource_ref','stored_at','read_until','retain_until'];
const HEAD=[...COMMON,'ack_slot','generation','observed_at','retain_until','state','root_authority_ref','grant_ref','binding_ref','original_ack_commit_ref','receipt_ref'];
const STATUS_PAYLOAD=['schema_version','kind','signing_key','scope_key','revision','issued_at','valid_until','entries'];
const STATUS_ENTRY=['scope_kind','scope_id','minimum_document_revision','status','operation_mask'];
const OPTIONS=['expectedAckSlot','expectedOwner','expectedReceiptWriter','expectedMessageId','expectedEnvelopeRef','expectedTarget','targetStorageEpoch','limitPolicy','policy','budget'];
const byteLength=Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint8Array.prototype),'byteLength')!.get!;
const occupiedBrand=new WeakSet<object>();
export interface AuthenticatedAckOccupiedSourceEvent{readonly manifest:DraftHistoryInputs;readonly commit:AuthenticatedRepairOriginal;
  readonly predecessor:AuthenticatedAckEmptySourceEvent;readonly inputs:Readonly<{receipt:AuthenticatedRepairOriginal;disclosure:AuthenticatedRepairOriginal;put:AuthenticatedRepairOriginal}>;
  readonly statuses:readonly AuthenticatedStatusOriginal[];readonly stored_at:number;readonly read_until:number;readonly retain_until:number;}
function fail(code='repair_invalid_ack_occupied'):never{throw new RepairError(code);}
function mismatch():never{fail('repair_ack_occupied_mismatch');}
function fields(value:unknown,names:readonly string[],code?:string):Obj{try{return objectFields(value,names);}catch(error){if(code)fail(code);throw error;}}
function same(a:unknown,b:unknown):boolean{if(a===b)return true;if(a===null||b===null||typeof a!=='object'||typeof b!=='object'||Array.isArray(a)!==Array.isArray(b))return false;
  const names=Object.keys(a);return names.length===Object.keys(b).length&&names.every(name=>Object.hasOwn(b,name)&&same((a as Obj)[name],(b as Obj)[name]));}
function pattern(value:unknown,re:RegExp,code='repair_invalid_history'):void{if(typeof value!=='string'||re.exec(value)?.[0]!==value)fail(code);}
function opaque(value:unknown,code='repair_invalid_original'):void{pattern(value,/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/,code);}
function dual(value:unknown):void{const v=fields(value,['signing_key_id','encryption_key_id'],'repair_invalid_history');pattern(v.signing_key_id,/^ed25519_[0-9a-f]{64}$/);pattern(v.encryption_key_id,/^x25519_[0-9a-f]{64}$/);}
function slot(value:unknown,expectedRoot:Obj):void{const v=fields(value,['root_key','slot_id','receipt_writer','grant_id'],'repair_invalid_history'),root=fields(v.root_key,['owner','root_kind','anchor_ref','owner_epoch','root_id'],'repair_invalid_history');
  dual(root.owner);const anchor=fields(root.anchor_ref,['namespace','key'],'repair_invalid_history');if(anchor.namespace!=='anchor')fail('repair_invalid_history');
  pattern(anchor.key,/^[0-9a-f]{64}$/);opaque(root.owner_epoch,'repair_invalid_history');opaque(root.root_id,'repair_invalid_history');
  if(root.root_kind!=='ack_return'||!same(root,expectedRoot))fail('repair_invalid_history');opaque(v.slot_id,'repair_invalid_history');opaque(v.grant_id,'repair_invalid_history');dual(v.receipt_writer);}
function meta(value:unknown):RawRef{const ref=rawRef(fields(value,['namespace','key','raw_sha256','size'],'repair_invalid_ack'));if(ref.namespace!=='meta')fail('repair_invalid_ack');return ref;}
function entry(value:unknown,receipt=false):RawOriginal{const v=fields(value,['raw','ref']);return {raw:v.raw,ref:receipt?rawRef(v.ref):meta(v.ref)};}
function refKey(ref:RawRef):string{return `${ref.namespace}:${ref.key}:${ref.raw_sha256}:${ref.size}`;}
function scopeKey(value:Obj):string{if(!['catalog','mailbox_slot','ack_slot','authority','resource','assignment','contact_policy'].includes(value.scope_kind))fail('repair_invalid_status');
  pattern(value.scope_id,/^[0-9a-f]{64}$/,'repair_invalid_status');return value.scope_kind+':'+value.scope_id;}
function signed(value:unknown,signer:Obj,kind:string,names:readonly string[],policy:RepairPolicy,budget:RepairBudget,receipt=false):AuthenticatedRepairOriginal{
  const input=entry(value,receipt),parsed=parseNewWire(input.raw,policy,budget),raw=parsed.raw;
  if(raw.length!==input.ref.size||budget.hash(raw)!==input.ref.raw_sha256)fail('repair_ref_mismatch');
  const doc=fields(parsed.value,['payload','proof']),p=fields(doc.payload,names);
  if(p.schema_version!==(receipt?RECEIPT_PROFILE:SCHEMA)||p.kind!==kind)fail();verifyBoundedControlSignature(p,doc.proof,signer,budget);
  return Object.freeze({ref:input.ref,payload:p,get raw():Uint8Array{budget.output(raw.length);return Uint8Array.from(raw);}});
}
function receipt(value:unknown,writer:Obj,owner:Obj,messageId:string,envelopeRef:unknown,policy:RepairPolicy,budget:RepairBudget):AuthenticatedRepairOriginal{
  const input=entry(value,true);if(!isUint8Array(input.raw)||Reflect.apply(byteLength,input.raw,[])>4096)fail('repair_invalid_receipt');
  const item=signed(value,writer.signing_key,'recipient.receipt',[...COMMON,...RECEIPT_FIELDS],policy,budget,true),p=item.payload as Obj;
  u53(p.saved_at);pattern(p.message_id,/^msg_[0-9a-f]{64}$/);pattern(p.sender_key_id,/^ed25519_[0-9a-f]{64}$/,'repair_invalid_original');pattern(p.recipient_key_id,/^ed25519_[0-9a-f]{64}$/,'repair_invalid_original');
  if(p.status!=='validated_saved'||p.message_id!==messageId||!same(rawRef(p.envelope_ref),rawRef(envelopeRef))||p.sender_key_id!==owner.signing_key.key_id||p.recipient_key_id!==writer.signing_key.key_id)mismatch();
  // Reuse the existing delivery verifier on exact original bytes. This is a
  // second real Ed25519 check, charged before entering the bounded legacy API.
  const raw=item.raw;budget.signatureCheck();try{verifyRecipientReceipt(raw,{recipient_signing_key:writer.signing_key,sender_key_id:owner.signing_key.key_id,message_id:messageId,envelope_ref:envelopeRef});}
  catch(error){if(error instanceof RepairError)throw error;fail('repair_invalid_receipt');}return item;
}
function inputs(prior:AuthenticatedAckEmptySourceEvent,receiptEntry:unknown,disclosureEntry:unknown,putEntry:unknown,owner:Obj,writer:Obj,at:number,policy:RepairPolicy,budget:RepairBudget):AuthenticatedAckOccupiedSourceEvent['inputs']{
  const root=prior.predecessor.resources.originals.root,write=prior.authorities.originals.write,ackSlot=root.payload.ack_slot as Obj;
  const r=receipt(receiptEntry,writer,owner,write.payload.message_id as string,write.payload.envelope_ref,policy,budget),
    disclosure=signed(disclosureEntry,writer.signing_key,'ack.disclosure',DISCLOSURE,policy,budget),put=signed(putEntry,writer.signing_key,'ack.put',PUT,policy,budget);
  const d=disclosure.payload as Obj,p=put.payload as Obj;
  for(const [value,id] of [[d,'consent_id'],[p,'put_id']] as const){if(u53(value.expires_at)<=u53(value.issued_at))fail('repair_invalid_resource');opaque(value[id]);slot(value.ack_slot,ackSlot.root_key);
    if(!same(value.ack_slot,ackSlot)||!same(meta(value.grant_ref),write.ref)||!same(rawRef(value.receipt_ref),r.ref)||!(value.issued_at<=at&&at<value.expires_at))mismatch();}
  u53(d.revision);if(u53(d.operation_mask)>127)fail('repair_invalid_resource');
  const roles=d.allowed_roles;if(!Array.isArray(roles)||!roles.length||roles.some((role:any,index:number)=>typeof role!=='string'||!knownHistoricalRoles.includes(role)||(index>0&&roles[index-1]>=role))||!B_ROLES.every(role=>roles.includes(role))||(d.operation_mask&67)!==67)fail('repair_disclosure_permission');
  dual(d.owner);dual(d.recipient);const returned=fields(d.bootstrap_return,['subject','consumer','roles','until']);dual(returned.subject);
  const until=u53(returned.until),consentUntil=u53(d.consent_until),windows=(root.payload as Obj).windows;
  if(!same(d.owner,ackSlot.root_key.owner)||!same(d.recipient,ackSlot.receipt_writer)||!same(meta(d.root_authority_ref),root.ref)||
    !same(returned.subject,d.owner)||returned.consumer!=='ack_owner'||!(same(returned.roles,['ack.disclosure','authority.status.disclosure'])||
      same(returned.roles,['ack.disclosure','ack.put','authority.status.disclosure','recipient.receipt']))||
    !(d.issued_at<until&&until<=Math.min(consentUntil,d.expires_at,windows.read_until,windows.retain_until))||!(d.issued_at<consentUntil&&consentUntil<=d.expires_at)||
    !same(meta(p.binding_ref),prior.binding.ref)||!same(meta(p.disclosure_ref),disclosure.ref)||p.operation!=='receipt.put'||
    !(prior.stored_at<=(r.payload.saved_at as number)&&(r.payload.saved_at as number)<=d.issued_at&&d.issued_at<=p.issued_at&&p.issued_at<=at))mismatch();
  return Object.freeze({receipt:r,disclosure,put});
}
function obligations(prior:AuthenticatedAckEmptySourceEvent,originals:AuthenticatedAckOccupiedSourceEvent['inputs'],owner:Obj,writer:Obj,target:Obj,ackSlot:Obj,policy:RepairPolicy,budget:RepairBudget):Obj[]{
  const old=prior.predecessor.resources.originals,result:Obj[]=[];
  for(const [role,item,kind,mask,signer] of [
    ['ack_root',old.root,'ack.root_authority',75,owner.signing_key],['ack_read',old.read,'ack.read_grant',2,owner.signing_key],
    ['ack_owner_bootstrap',prior.predecessor.bootstrap.originals.bootstrap,'bootstrap.grant',10,owner.signing_key],
    ['ack_write',prior.authorities.originals.write,'ack.write_grant',1,owner.signing_key],['ack_offer_bootstrap',prior.authorities.originals.bootstrap,'bootstrap.grant',11,owner.signing_key]] as const)
    result.push({role:'historical.status.'+role,signer,scope_kind:'authority',scope_id:statusScope(ackSlot.root_key,'authority',{authority_kind:kind,authority_sha256:item.ref.raw_sha256},policy,budget),revision:item.payload.revision,mask});
  const active=old.active.payload as Obj;
  for(const [role,kind,subject,revision,signer] of [['ack_slot','ack_slot',ackSlot,old.root.payload.revision,owner.signing_key],
    ['admission_resource','resource',active.resource,active.reservation_generation,target.signing_key]] as const)
    result.push({role:'historical.status.'+role,signer,scope_kind:kind,scope_id:statusScope(ackSlot.root_key,kind,subject,policy,budget),revision,mask:67});
  result.push({role:'historical.status.ack_disclosure',signer:writer.signing_key,scope_kind:'authority',scope_id:statusScope(ackSlot.root_key,'authority',
    {authority_kind:'ack.disclosure',authority_sha256:originals.disclosure.ref.raw_sha256},policy,budget),revision:originals.disclosure.payload.revision,mask:67});
  return result;
}
function statuses(roles:Map<string,RawOriginal>,required:Obj[],root:Obj,at:number,policy:RepairPolicy,budget:RepairBudget):AuthenticatedStatusOriginal[]{
  const groups=new Map<string,{entry:RawOriginal;signer:Obj;required:Obj[]}>();
  for(const item of required){const original=roles.get(item.role)!,key=refKey(original.ref),group=groups.get(key)??{entry:{raw:original.raw,ref:original.ref},signer:item.signer,required:[] as Obj[]};
    if(!same(group.signer,item.signer))fail('repair_ack_empty_mismatch');group.required.push({scope_kind:item.scope_kind,scope_id:item.scope_id,document_revision:item.revision,operation_mask:item.mask});groups.set(key,group);}
  const checked:AuthenticatedStatusOriginal[]=[];
  for(const group of groups.values()){const permitted=required.filter(item=>same(item.signer,group.signer)),doc=fields(parseOriginalControl(group.entry.raw,policy,budget).value,['payload','proof'],'repair_invalid_status');
    const payload=fields(doc.payload,STATUS_PAYLOAD,'repair_invalid_status');if(!Array.isArray(payload.entries)||payload.entries.length<1||payload.entries.length>16)fail('repair_invalid_status');
    const present=new Set<string>();for(const value of payload.entries)present.add(scopeKey(fields(value,STATUS_ENTRY,'repair_invalid_status')));
    const held=new Map(group.required.map(item=>[scopeKey(item),item]));for(const item of permitted)if(present.has(scopeKey(item)))held.set(scopeKey(item),{scope_kind:item.scope_kind,scope_id:item.scope_id,document_revision:item.revision,operation_mask:item.mask});
    checked.push(verifyStatusOriginal(group.entry,{expectedRoot:root,expectedSigningKey:group.signer,at,allowedScopes:permitted.map(item=>({scope_kind:item.scope_kind,scope_id:item.scope_id})),required:[...held.values()],policy,budget}));}
  return checked;
}
function floors(previous:readonly AuthenticatedStatusOriginal[],current:readonly AuthenticatedStatusOriginal[]):void{
  const revisions=new Map<string,string>(),observations=new Map<string,[number,number][]>(),prior=new Map<string,[number,number]>();
  for(const observed of [...previous,...current]){const p=observed.payload as Obj,issuer=p.scope_key.issuer_key_id,key=issuer+':'+p.revision;
    if(revisions.has(key)&&revisions.get(key)!==observed.canonical_sha256)fail('repair_status_conflict');revisions.set(key,observed.canonical_sha256);
    for(const item of p.entries){const scope=issuer+':'+scopeKey(item);observations.set(scope,[...(observations.get(scope)??[]),[p.revision,item.minimum_document_revision]]);}}
  for(const values of observations.values()){let floor=0;for(const [,minimum] of values.sort((a,b)=>a[0]-b[0]||a[1]-b[1])){if(minimum<floor)fail('repair_status_rollback');floor=minimum;}}
  for(const observed of previous){const p=observed.payload as Obj;for(const item of p.entries){const scope=p.scope_key.issuer_key_id+':'+scopeKey(item),held=prior.get(scope)??[0,0];prior.set(scope,[Math.max(held[0],p.revision),Math.max(held[1],item.minimum_document_revision)]);}}
  for(const observed of current){const p=observed.payload as Obj;for(const item of p.entries){const held=prior.get(p.scope_key.issuer_key_id+':'+scopeKey(item));if(held&&(p.revision<held[0]||item.minimum_document_revision<held[1]))fail('repair_status_rollback');}}
}
function windows(prior:AuthenticatedAckEmptySourceEvent,values:AuthenticatedAckOccupiedSourceEvent['inputs'],at:number):{readUntil:number;retainUntil:number}{
  const old=prior.predecessor.resources.originals,r=old.root.payload as Obj,read=old.read.payload as Obj,a=old.active.payload as Obj,
    w=prior.authorities.originals.write.payload as Obj,g=prior.authorities.originals.bootstrap.payload as Obj,owner=prior.predecessor.bootstrap.originals.bootstrap.payload as Obj,
    d=values.disclosure.payload as Obj,p=values.put.payload as Obj;
  const admit=Math.min(r.windows.admit_until,a.windows.admit_until,w.windows.admit_until,r.expires_at,w.expires_at,g.expires_at,g.upload_until,d.expires_at,d.consent_until,p.expires_at),
    readUntil=Math.min(prior.read_until,d.consent_until,d.expires_at,d.bootstrap_return.until,r.windows.read_until,read.windows.read_until,a.windows.read_until,owner.proof_until),
    retainUntil=Math.min(prior.retain_until,r.windows.retain_until,a.windows.retain_until,w.windows.retain_until,d.consent_until);
  if(!(prior.stored_at<=at&&at<Math.min(admit,readUntil,retainUntil)))fail('repair_access_expired');return {readUntil:Math.min(readUntil,retainUntil),retainUntil};
}
export function verifyAckOccupiedSourceEvent(manifestEntry:unknown,resolver:LocalRawResolver,commitEntry:unknown,options:AckEmptySourceEventOptions):AuthenticatedAckOccupiedSourceEvent{
  const args=fields(options,OPTIONS),policy=args.policy as RepairPolicy,budget=args.budget as RepairBudget;
  const expected=buildNewWire({slot:args.expectedAckSlot,owner:args.expectedOwner,writer:args.expectedReceiptWriter,message_id:args.expectedMessageId,envelope_ref:args.expectedEnvelopeRef,target:args.expectedTarget},policy,budget).value as Obj;
  const {slot:ackSlot,owner,writer,target}=expected,commit=signed(commitEntry,target.signing_key,'ack.commit',COMMIT,policy,budget),event=commit.payload as Obj,at=u53(event.stored_at);
  const input=entry(manifestEntry),parsed=parseNewWire(input.raw,policy,budget),raw=parsed.raw;if(raw.length!==input.ref.size||budget.hash(raw)!==input.ref.raw_sha256)fail('repair_ref_mismatch');
  if(!same(event.ack_slot,ackSlot)||!same(meta(event.historical_manifest_ref),input.ref))mismatch();
  const manifest=resolveHistoricalInputs(raw,resolver,policy,budget),value=manifest.manifest.value as Obj;
  if(value.variant!=='ack_occupied_inputs'||manifest.predecessors.length!==1||!same(value.ack_slot,ackSlot))mismatch();
  const roles=new Map<string,RawOriginal>();for(const item of manifest.roles){if(!ROLES.has(item.role)||roles.has(item.role))fail();roles.set(item.role,item.original);}if(roles.size!==ROLES.size)fail();
  const original=(role:string):RawOriginal=>{const item=roles.get(role)!;return {raw:item.raw,ref:item.ref};};
  const prior=verifyAckEmptySourceEvent(original('history.ack_empty'),resolver,original('ack.empty_custody'),{expectedAckSlot:ackSlot,expectedOwner:owner,
    expectedReceiptWriter:writer,expectedMessageId:expected.message_id,expectedEnvelopeRef:expected.envelope_ref,expectedTarget:target,
    targetStorageEpoch:args.targetStorageEpoch,limitPolicy:args.limitPolicy,policy,budget});
  const checked=inputs(prior,original('recipient.receipt'),original('ack.disclosure'),original('ack.put'),owner,writer,at,policy,budget),root=prior.predecessor.resources.originals.root;
  const refs:Record<string,RawRef>={root_authority_ref:root.ref,grant_ref:prior.authorities.originals.write.ref,binding_ref:prior.binding.ref,receipt_ref:checked.receipt.ref,put_ref:checked.put.ref,disclosure_ref:checked.disclosure.ref};
  for(const [name,wanted] of Object.entries(refs))if(!same(rawRef(value[name]),wanted)||(name!=='root_authority_ref'&&!same(rawRef(event[name]),wanted)))mismatch();
  const resource=prior.predecessor.resources.originals.active.payload.resource;if(!same(value.admission_resource,resource)||!same(event.resource_ref,resource))mismatch();
  const maximum=windows(prior,checked,at);if(!(at<u53(event.read_until)&&event.read_until<=u53(event.retain_until)&&event.retain_until<=maximum.retainUntil)||event.read_until>maximum.readUntil)mismatch();
  const observed=statuses(roles,obligations(prior,checked,owner,writer,target,ackSlot,policy,budget),ackSlot.root_key,at,policy,budget);
  floors([...prior.predecessor.statuses,...prior.statuses],observed);
  const result=Object.freeze({manifest,commit,predecessor:prior,inputs:checked,statuses:Object.freeze(observed),stored_at:at,read_until:event.read_until,retain_until:event.retain_until});occupiedBrand.add(result);return result;
}
export function verifyAckOccupiedHead(value:unknown,checked:AuthenticatedAckOccupiedSourceEvent,options:{expectedTarget:unknown;policy:RepairPolicy;budget:RepairBudget}):AuthenticatedRepairOriginal{
  if(!occupiedBrand.has(checked))fail();const args=fields(options,['expectedTarget','policy','budget']),policy=args.policy as RepairPolicy,budget=args.budget as RepairBudget;
  const target=buildNewWire(args.expectedTarget,policy,budget).value as Obj,head=signed(value,target.signing_key,'ack.head',HEAD,policy,budget),p=head.payload as Obj,c=checked.commit.payload as Obj;
  if(p.state!=='occupied'||u53(p.generation,1)!==2||p.observed_at!==checked.stored_at||p.retain_until!==checked.retain_until||!same(p.ack_slot,c.ack_slot)||
    !same(rawRef(p.original_ack_commit_ref),checked.commit.ref)||!same(rawRef(p.root_authority_ref),checked.predecessor.predecessor.resources.originals.root.ref)||
    ['grant_ref','binding_ref','receipt_ref'].some(name=>!same(p[name],c[name])))mismatch();return head;
}
