/** Exact historical status originals. No current ledger or live capability.
 * Callers derive expected scopes from authenticated typed parents and preserve
 * separate original-event and current-operation observations.
 */
import {buildNewWire, objectFields, rawRef, u53, RepairError} from './open-repair-wire.ts';
import type {RepairPolicy, RepairBudget, RawRef, DraftValue} from './open-repair-wire.ts';
import {parseOriginalControl, canonicalOriginalControl, verifyBoundedControlSignature} from './open-repair-original.ts';

type Obj = Record<string, any>;
const SCHEMA = 'memory-vault-open-authority/v1';
const MAX_BYTES = 16384, MAX_SECONDS = 604800;
const AUTHORITY_KINDS = new Set(['ack.root_authority','ack.read_grant','ack.write_grant','ack.disclosure','bootstrap.grant',
  'ack.index_consent','ack.copy_reservation_consent','ack.copy_disclosure','mailbox.root_authority','mailbox.root_read_grant','mailbox.maintenance_root','mailbox.read_grant',
  'delivery.destination','message.disclosure']);
const SCOPE_KINDS = new Set(['catalog','mailbox_slot','ack_slot','authority','resource','assignment','contact_policy']);
const PAYLOAD = ['schema_version','kind','signing_key','scope_key','revision','issued_at','valid_until','entries'];
const ENTRY = ['scope_kind','scope_id','minimum_document_revision','status','operation_mask'];
const BYTE_LENGTH = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint8Array.prototype),'byteLength')!.get!;

function fail(code='repair_invalid_status'): never {throw new RepairError(code);}
function fields(value:unknown,names:readonly string[]):Obj {try{return objectFields(value,names);}catch{fail();}}
function number(value:unknown,minimum=0):number {try{return u53(value,minimum);}catch{fail();}}
function dualId(value:unknown):Obj {
  const raw=fields(value,['signing_key_id','encryption_key_id']);
  pattern(raw.signing_key_id,/^ed25519_[0-9a-f]{64}$/);pattern(raw.encryption_key_id,/^x25519_[0-9a-f]{64}$/);return raw;
}
function root(value:unknown):Obj {
  const raw=fields(value,['owner','root_kind','anchor_ref','owner_epoch','root_id']);dualId(raw.owner);
  if(raw.root_kind!=='mailbox'&&raw.root_kind!=='ack_return')fail();
  const anchor=fields(raw.anchor_ref,['namespace','key']);if(anchor.namespace!=='anchor')fail();digest(anchor.key);
  opaque(raw.owner_epoch);opaque(raw.root_id);return raw;
}
function resourceRef(value:unknown):Obj {
  const raw=fields(value,['node_key_id','storage_epoch','lease_id','resource_id']);
  pattern(raw.node_key_id,/^ed25519_[0-9a-f]{64}$/);for(const name of ['storage_epoch','lease_id','resource_id'])opaque(raw[name]);return raw;
}
function pattern(value:unknown,expression:RegExp):string {
  if(typeof value!=='string'||expression.exec(value)?.[0]!==value)fail();return value;
}
function digest(value:unknown):string{return pattern(value,/^[0-9a-f]{64}$/);}
function opaque(value:unknown):string{return pattern(value,/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/);}
function same(a:unknown,b:unknown):boolean {
  if(a===b)return true;
  if(a===null||b===null||typeof a!=='object'||typeof b!=='object'||Array.isArray(a)!==Array.isArray(b))return false;
  const names=Object.keys(a);return names.length===Object.keys(b).length&&names.every(name=>Object.hasOwn(b,name)&&same((a as Obj)[name],(b as Obj)[name]));
}
function scopeKey(value:Obj):string {
  if(typeof value.scope_kind!=='string'||!SCOPE_KINDS.has(value.scope_kind))fail();
  return value.scope_kind+':'+digest(value.scope_id);
}
function mask(value:unknown):number {const n=number(value,1);if(n>127)fail();return n;}

export function statusScope(expectedRoot:unknown,kind:unknown,subject:unknown,
  policy:RepairPolicy,budget:RepairBudget):string {
  const value=buildNewWire({root:expectedRoot,scope_kind:kind,subject},policy,budget).value as Obj;
  const r=root(value.root),s=value.subject;let payload:Obj;
  if(value.scope_kind==='authority'){
    fields(s,['authority_kind','authority_sha256']);
    if(typeof s.authority_kind!=='string'||!AUTHORITY_KINDS.has(s.authority_kind))fail();digest(s.authority_sha256);
    payload={kind:'authority',root_key:r,authority_kind:s.authority_kind,authority_sha256:s.authority_sha256};
  }else if(value.scope_kind==='resource'){
    try{resourceRef(s);}catch{fail();}payload={kind:'resource',root_key:r,resource:s};
  }else if(value.scope_kind==='ack_slot'){
    fields(s,['root_key','slot_id','receipt_writer','grant_id']);root(s.root_key);
    if(r.root_kind!=='ack_return'||!same(s.root_key,r))fail();opaque(s.slot_id);opaque(s.grant_id);
    try{dualId(s.receipt_writer);}catch{fail();}payload={kind:'ack_slot',root_key:r,ack_slot:s};
  }else if(value.scope_kind==='mailbox_slot'){
    fields(s,['root_key','slot_id','writer','writer_storage_epoch']);root(s.root_key);
    if(r.root_kind!=='mailbox'||!same(s.root_key,r))fail();opaque(s.slot_id);opaque(s.writer_storage_epoch);
    try{dualId(s.writer);}catch{fail();}payload={kind:'mailbox_slot',root_key:r,slot_key:s};
  }else if(value.scope_kind==='catalog'){
    fields(s,['root_key']);if(r.root_kind!=='mailbox'||!same(s.root_key,r))fail();
    payload={kind:'catalog',root_key:r};
  }else fail();
  return budget.hash(canonicalOriginalControl(payload,budget));
}

export interface StatusOriginalOptions {
  readonly expectedRoot:unknown;readonly expectedSigningKey:unknown;readonly at:number;
  readonly allowedScopes:unknown;readonly required:unknown;readonly policy:RepairPolicy;readonly budget:RepairBudget;
}
export interface AuthenticatedStatusOriginal {
  readonly raw:Uint8Array;readonly ref:RawRef;readonly payload:Readonly<Record<string,DraftValue>>;
  readonly raw_sha256:string;readonly canonical_sha256:string;readonly at:number;
}
function statusOriginal(entry:unknown,options:StatusOriginalOptions,enforceRequired:boolean):AuthenticatedStatusOriginal {
  const args=fields(options,['expectedRoot','expectedSigningKey','at','allowedScopes','required','policy','budget']);
  const input=fields(entry,['raw','ref']),policy=args.policy as RepairPolicy,budget=args.budget as RepairBudget;
  // Use the native typed-array getter directly; never invoke an input getter.
  let size:number;try{size=Reflect.apply(BYTE_LENGTH,input.raw,[]);}catch{fail();}
  if(size>MAX_BYTES)fail();
  const expected=buildNewWire({root:args.expectedRoot,signing_key:args.expectedSigningKey,at:args.at,
    allowed_scopes:args.allowedScopes,required:args.required,ref:input.ref},policy,budget).value as Obj;
  root(expected.root);const at=number(expected.at),ref=rawRef(fields(expected.ref,['namespace','key','raw_sha256','size']));
  if(ref.namespace!=='meta')fail();
  const allowed=new Map<string,Obj>(),obligations=new Map<string,Obj>();
  for(const [name,names,target] of [
    ['allowed_scopes',['scope_kind','scope_id'],allowed],
    ['required',['scope_kind','scope_id','document_revision','operation_mask'],obligations],
  ] as const){
    const values=expected[name],minimum=name==='required'&&!enforceRequired?0:1;
    if(!Array.isArray(values)||values.length<minimum||values.length>16)fail();
    for(const value of values){fields(value,names);const key=scopeKey(value);if(target.has(key))fail();
      if(name==='required'){number(value.document_revision);mask(value.operation_mask);}target.set(key,value);}
  }
  if([...obligations.keys()].some(key=>!allowed.has(key)))fail();
  const document=parseOriginalControl(input.raw,policy,budget),raw=document.raw;
  const rawHash=budget.hash(raw);if(raw.length!==ref.size||rawHash!==ref.raw_sha256)fail('repair_ref_mismatch');
  const signed=fields(document.value,['payload','proof']),payload=fields(signed.payload,PAYLOAD);
  if(payload.schema_version!==SCHEMA||payload.kind!=='authority.status')fail();
  const scope=fields(payload.scope_key,['root_key','issuer_key_id']);root(scope.root_key);
  if(!same(scope.root_key,expected.root)||payload.signing_key===null||typeof payload.signing_key!=='object'||
      Array.isArray(payload.signing_key)||scope.issuer_key_id!==payload.signing_key.key_id)fail('repair_status_mismatch');
  number(payload.revision,1);const issued=number(payload.issued_at),until=number(payload.valid_until);
  if(!(until-issued>=1&&until-issued<=MAX_SECONDS&&issued<=at+30&&at<until))fail('repair_status_mismatch');
  if(!Array.isArray(payload.entries)||payload.entries.length<1||payload.entries.length>16)fail();
  const seen=new Map<string,Obj>();let previous='';
  for(const value of payload.entries){fields(value,ENTRY);const key=scopeKey(value);
    if(previous&&key<=previous)fail();previous=key;number(value.minimum_document_revision);mask(value.operation_mask);
    if(!['active','revoked'].includes(value.status))fail();seen.set(key,value);}
  const canonical=canonicalOriginalControl(signed,budget);if(canonical.length>MAX_BYTES)fail();
  // Independent expected descriptor/ID selection is separate from proof math.
  const expectedKey=typeof expected.signing_key==='string'?payload.signing_key:expected.signing_key;
  if(typeof expected.signing_key==='string'){
    pattern(expected.signing_key,/^ed25519_[0-9a-f]{64}$/);
    if(payload.signing_key.key_id!==expected.signing_key)fail('repair_wrong_issuer');
  }
  verifyBoundedControlSignature(payload,signed.proof,expectedKey,budget);
  const canonicalHash=budget.hash(canonical);
  if([...seen.keys()].some(key=>!allowed.has(key)))fail('repair_status_disclosure');
  if([...obligations.keys()].some(key=>!seen.has(key)))fail('repair_status_missing');
  for(const [key,obligation] of obligations){const observation=seen.get(key)!;
    if(observation.status==='revoked')fail('repair_authority_revoked');
    if(observation.minimum_document_revision>obligation.document_revision)fail('repair_status_revision');
    if((observation.operation_mask&obligation.operation_mask)!==obligation.operation_mask)fail('repair_status_operation');
  }
  return Object.freeze({payload,ref,raw_sha256:rawHash,canonical_sha256:canonicalHash,at,
    get raw():Uint8Array{budget.output(raw.length);return Uint8Array.from(raw);}});
}

/** Authenticate exact denial observations for retention before access refusal.
 * Allowed scopes must still come from the independently verified parent chain.
 * This return value grants no operation and does not maintain a status ledger.
 */
export function authenticateStatusOriginal(entry:unknown,
  options:Omit<StatusOriginalOptions,'required'>):AuthenticatedStatusOriginal {
  const args=fields(options,['expectedRoot','expectedSigningKey','at','allowedScopes','policy','budget']);
  return statusOriginal(entry,{expectedRoot:args.expectedRoot,expectedSigningKey:args.expectedSigningKey,
    at:args.at,allowedScopes:args.allowedScopes,required:[],policy:args.policy,budget:args.budget},false);
}

export function verifyStatusOriginal(entry:unknown,options:StatusOriginalOptions):AuthenticatedStatusOriginal {
  return statusOriginal(entry,options,true);
}
