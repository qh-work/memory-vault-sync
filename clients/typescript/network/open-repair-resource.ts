/** Authenticated pre-message ACK resource inputs, not active local resources.
 * No network, status acceptance, possession proof, durable ledger, custody or
 * repair authority is obtained by verifying these six signed originals.
 */
import {buildNewWire, parseNewWire, rawRef, objectFields, u53, RepairError} from './open-repair-wire.ts';
import type {DraftValue, RawRef, RepairPolicy, RepairBudget} from './open-repair-wire.ts';
import {canonicalOriginalControl, originalPublicDescriptor, verifyBoundedControlSignature} from './open-repair-original.ts';
import {knownHistoricalRoles} from './open-repair-history.ts';

type Obj = Record<string, any>;
const SCHEMA = 'memory-vault-open-repair/v1';
export const ACK_RESOURCE_ROLES = Object.freeze(['allocate','offer','root','read','activation','active'] as const);
const COMMON = ['schema_version','kind','signing_key'];
const KINDS = ['resource.allocate','resource.offer','ack.root_authority','ack.read_grant','resource.activation','resource.active'];
const FIELDS = [
  ['issued_at','expires_at','request_id','target_node_key_id','target_storage_epoch','intent','intent_sha256'],
  ['issued_at','reservation_until','offer_id','allocation_request_ref','intent','intent_sha256','resource','target_encryption_key','reservation_generation','budget','windows'],
  ['issued_at','expires_at','ack_slot','authority_id','owner','receipt_writer','original_resource_ref','original_resource_offer_ref','maintainers','operation_mask','allowed_roles','max_bindings','max_receipts','budget','windows','max_delegate_depth','max_destinations_per_job','max_concurrent_jobs','revision'],
  ['issued_at','expires_at','grant_id','ack_slot','reader','root_authority_ref','operation_mask','budget','windows','revision'],
  ['issued_at','expires_at','activation_id','subject','target_node_key_id','target_storage_epoch','root_key','scope','resource_offer_refs','authority_refs'],
  ['activated_at','offer_ref','activation_ref','resource','reservation_generation','root_key','purpose','budget','windows'],
];
const BUDGET = ['max_live_bytes','max_meta_bytes','max_items','max_requests','max_pending','max_replay_records','max_jobs','max_job_bytes'];
const WINDOWS = ['admit_until','read_until','copy_until','publish_until','retain_until'];
const ROLE_NAMES = new Set([...knownHistoricalRoles,'bootstrap.grant','mailbox_root_service_v1',
  'selected_slot_service_v1','ack_owner_service_v1','ack_offer_service_v1']);
export interface AuthenticatedRepairOriginal {
  readonly raw: Uint8Array; readonly ref: RawRef; readonly payload: Readonly<Record<string,DraftValue>>;
}
export interface AuthenticatedAckResourceInputs {
  readonly originals: Readonly<Record<typeof ACK_RESOURCE_ROLES[number],AuthenticatedRepairOriginal>>;
  readonly activated_at: number;
}
export interface AckResourceOptions {
  readonly expectedAckSlot: unknown; readonly expectedOwner: unknown; readonly expectedTarget: unknown;
  readonly targetStorageEpoch: string; readonly policy: RepairPolicy; readonly budget: RepairBudget;
}
function fail(code = 'repair_invalid_resource'): never {throw new RepairError(code);}
function mismatch(): never {fail('repair_resource_mismatch');}
function fields(value: unknown, names: readonly string[]): Obj {
  try {return objectFields(value,names);} catch {fail();}
}
function number(value: unknown, minimum=0): number {try {return u53(value,minimum);} catch {fail();}}
function pattern(value: unknown, expression: RegExp): string {
  if (typeof value !== 'string' || expression.exec(value)?.[0] !== value) fail(); return value;
}
function opaque(value: unknown): string {return pattern(value,/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/);}
function key(value: unknown, encryption=false): string {return pattern(value,encryption ? /^x25519_[0-9a-f]{64}$/ : /^ed25519_[0-9a-f]{64}$/);}
function digest(value: unknown): string {return pattern(value,/^[0-9a-f]{64}$/);}
function same(a: unknown,b: unknown): boolean {
  if (a===b) return true;
  if (a===null || b===null || typeof a!=='object' || typeof b!=='object' || Array.isArray(a)!==Array.isArray(b)) return false;
  const names=Object.keys(a); return names.length===Object.keys(b).length && names.every(name=>Object.hasOwn(b,name)&&same((a as Obj)[name],(b as Obj)[name]));
}
function dualId(value: unknown): Obj {
  const raw=fields(value,['signing_key_id','encryption_key_id']); key(raw.signing_key_id);key(raw.encryption_key_id,true);return raw;
}
function dualKey(value: unknown): Obj {
  const raw=fields(value,['signing_key','encryption_key']);
  for(const [name,algorithm,schema] of [['signing_key','Ed25519','universal-memory-public-key/v1'],['encryption_key','X25519','memory-vault-network-encryption-key/v1']]){
    const descriptor=fields(raw[name],['schema_version','algorithm','key_id','public_key']);
    if(descriptor.algorithm!==algorithm || descriptor.schema_version!==schema || typeof descriptor.public_key!=='string')fail();
    key(descriptor.key_id,name==='encryption_key');
  }
  return raw;
}
function rootKey(value: unknown): Obj {
  const raw=fields(value,['owner','root_kind','anchor_ref','owner_epoch','root_id']);dualId(raw.owner);
  if(raw.root_kind!=='ack_return')fail();const anchor=fields(raw.anchor_ref,['namespace','key']);
  if(anchor.namespace!=='anchor')fail();digest(anchor.key);opaque(raw.owner_epoch);opaque(raw.root_id);return raw;
}
function ackSlot(value: unknown): Obj {
  const raw=fields(value,['root_key','slot_id','receipt_writer','grant_id']);rootKey(raw.root_key);
  opaque(raw.slot_id);dualId(raw.receipt_writer);opaque(raw.grant_id);return raw;
}
function resource(value: unknown): Obj {
  const raw=fields(value,['node_key_id','storage_epoch','lease_id','resource_id']);key(raw.node_key_id);
  opaque(raw.storage_epoch);opaque(raw.lease_id);opaque(raw.resource_id);return raw;
}
function meta(value: unknown): RawRef {
  const ref=rawRef(value);if(ref.namespace!=='meta')fail();return ref;
}
function amounts(value: unknown): Obj {
  const raw=fields(value,BUDGET);for(const name of BUDGET)number(raw[name]);return raw;
}
function windows(value: unknown): Obj {
  const raw=fields(value,WINDOWS);for(const name of WINDOWS)number(raw[name]);
  if(WINDOWS.some(name=>raw[name]>raw.retain_until))fail();return raw;
}
function ownerIntent(value: unknown): Obj {
  const raw=fields(value,['kind','allocation_id','root_key','owner','target','target_storage_epoch','purpose','budget','windows']);
  if(raw.kind!=='resource.owner_intent'||raw.purpose!=='ack_slot')fail();opaque(raw.allocation_id);rootKey(raw.root_key);
  dualKey(raw.owner);dualKey(raw.target);opaque(raw.target_storage_epoch);amounts(raw.budget);windows(raw.windows);return raw;
}
function mask(value: unknown): number {const result=number(value);if(result>127)fail();return result;}
function sortedNames(value: unknown): void {
  if(!Array.isArray(value))fail();let previous='';
  for(const name of value){if(typeof name!=='string'||!ROLE_NAMES.has(name)||name<=previous)fail();previous=name;}
}
function maintainers(value: unknown): void {
  if(!Array.isArray(value))fail();let previous='';
  for(const item of value){const id=dualId(item),current=id.signing_key_id+':'+id.encryption_key_id;if(current<=previous)fail();previous=current;}
}
function shape(raw: Obj, index: number): void {
  if(index!==5)number(raw.issued_at);if([0,2,3,4].includes(index))number(raw.expires_at);
  if(index===0){opaque(raw.request_id);key(raw.target_node_key_id);opaque(raw.target_storage_epoch);ownerIntent(raw.intent);digest(raw.intent_sha256);}
  else if(index===1){number(raw.reservation_until);opaque(raw.offer_id);meta(raw.allocation_request_ref);ownerIntent(raw.intent);digest(raw.intent_sha256);resource(raw.resource);number(raw.reservation_generation);amounts(raw.budget);windows(raw.windows);}
  else if(index===2){ackSlot(raw.ack_slot);opaque(raw.authority_id);dualId(raw.owner);dualId(raw.receipt_writer);resource(raw.original_resource_ref);meta(raw.original_resource_offer_ref);maintainers(raw.maintainers);mask(raw.operation_mask);sortedNames(raw.allowed_roles);amounts(raw.budget);windows(raw.windows);number(raw.max_destinations_per_job);number(raw.max_concurrent_jobs);number(raw.revision);if(raw.max_bindings!==1||raw.max_receipts!==1||raw.max_delegate_depth!==2)fail();}
  else if(index===3){opaque(raw.grant_id);ackSlot(raw.ack_slot);dualId(raw.reader);meta(raw.root_authority_ref);mask(raw.operation_mask);amounts(raw.budget);windows(raw.windows);number(raw.revision);}
  else if(index===4){opaque(raw.activation_id);dualKey(raw.subject);key(raw.target_node_key_id);opaque(raw.target_storage_epoch);rootKey(raw.root_key);const scope=fields(raw.scope,['kind','ack_slot','root_authority_ref']);if(scope.kind!=='ack_unbound')fail();ackSlot(scope.ack_slot);meta(scope.root_authority_ref);if(!Array.isArray(raw.resource_offer_refs)||raw.resource_offer_refs.length!==1)fail();meta(raw.resource_offer_refs[0]);if(!Array.isArray(raw.authority_refs)||raw.authority_refs.length!==2)fail();raw.authority_refs.forEach((entry: unknown,i: number)=>{const item=fields(entry,['role','ref']);if(item.role!==['ack.read_grant','ack.root_authority'][i])fail();meta(item.ref);});}
  else{number(raw.activated_at);meta(raw.offer_ref);meta(raw.activation_ref);resource(raw.resource);number(raw.reservation_generation);rootKey(raw.root_key);if(raw.purpose!=='ack_slot')fail();amounts(raw.budget);windows(raw.windows);}
}
function compatibleWindow(window: Obj, issued: number, expires?: number): void {
  if(WINDOWS.some(name=>window[name]<=issued||(expires!==undefined&&window[name]>expires)))fail();
}

export function verifyAckResourceInputs(entries: unknown, options: AckResourceOptions): AuthenticatedAckResourceInputs {
  // Reject caller accessors/proxies before reading even policy/budget/expected.
  const args=fields(options,['expectedAckSlot','expectedOwner','expectedTarget','targetStorageEpoch','policy','budget']);
  const policy=args.policy as RepairPolicy,budget=args.budget as RepairBudget;
  const expected=buildNewWire({ack_slot:args.expectedAckSlot,owner:args.expectedOwner,target:args.expectedTarget,
    target_storage_epoch:args.targetStorageEpoch},policy,budget).value as Obj;
  const slot=ackSlot(expected.ack_slot),owner=dualKey(expected.owner),target=dualKey(expected.target),epoch=opaque(expected.target_storage_epoch);
  for(const item of [owner,target]){originalPublicDescriptor(item.signing_key,budget);originalPublicDescriptor(item.encryption_key,budget,true);}
  const ownerId={signing_key_id:owner.signing_key.key_id,encryption_key_id:owner.encryption_key.key_id};
  if(!same(slot.root_key.owner,ownerId))mismatch();
  const inputs=fields(entries,ACK_RESOURCE_ROLES),originals=Object.create(null) as Record<typeof ACK_RESOURCE_ROLES[number],AuthenticatedRepairOriginal>;
  const values:Obj[]=[];
  for(let i=0;i<ACK_RESOURCE_ROLES.length;i++){
    const role=ACK_RESOURCE_ROLES[i],entry=fields(inputs[role],['raw','ref']),ref=meta(entry.ref);
    const parsed=parseNewWire(entry.raw as Uint8Array,policy,budget),raw=parsed.raw;
    if(raw.length!==ref.size||budget.hash(raw)!==ref.raw_sha256)fail('repair_ref_mismatch');
    const signed=fields(parsed.value,['payload','proof']),payload=fields(signed.payload,[...COMMON,...FIELDS[i]]);
    if(payload.schema_version!==SCHEMA||payload.kind!==KINDS[i])fail();shape(payload,i);
    verifyBoundedControlSignature(payload,signed.proof,(i===1||i===5?target:owner).signing_key,budget);
    originals[role]=Object.freeze({payload,ref,get raw():Uint8Array{budget.output(raw.length);return Uint8Array.from(raw);}});
    values.push(payload);
  }
  const [allocate,offer,root,read,activation,active]=values;
  const first=canonicalOriginalControl(allocate.intent,budget),second=canonicalOriginalControl(offer.intent,budget);
  const firstHash=budget.hash(first),secondHash=budget.hash(second);
  if(first.length!==second.length||!first.equals(second)||firstHash!==allocate.intent_sha256||secondHash!==offer.intent_sha256)mismatch();
  const intent=allocate.intent;
  if(!same(intent.root_key,slot.root_key)||!same(intent.owner,owner)||!same(intent.target,target)||intent.target_storage_epoch!==epoch)mismatch();
  for(const value of [allocate,activation])if(value.target_node_key_id!==target.signing_key.key_id||value.target_storage_epoch!==epoch)mismatch();
  if(offer.resource.node_key_id!==target.signing_key.key_id||offer.resource.storage_epoch!==epoch||!same(offer.target_encryption_key,target.encryption_key)||
      !same(offer.allocation_request_ref,originals.allocate.ref)||!same(offer.budget,intent.budget)||!same(offer.windows,intent.windows))mismatch();
  if(!same(root.ack_slot,slot)||!same(root.owner,ownerId)||!same(root.receipt_writer,slot.receipt_writer)||
      !same(root.original_resource_ref,offer.resource)||!same(root.original_resource_offer_ref,originals.offer.ref))mismatch();
  if(!same(read.ack_slot,slot)||!same(read.reader,ownerId)||!same(read.root_authority_ref,originals.root.ref)||
      (read.operation_mask&root.operation_mask)!==read.operation_mask||read.expires_at>root.expires_at||
      BUDGET.some(name=>read.budget[name]>root.budget[name])||WINDOWS.some(name=>read.windows[name]>root.windows[name]))mismatch();
  if(!same(activation.subject,owner)||!same(activation.root_key,slot.root_key)||!same(activation.scope.ack_slot,slot)||
      !same(activation.scope.root_authority_ref,originals.root.ref)||!same(activation.resource_offer_refs[0],originals.offer.ref)||
      !same(activation.authority_refs[0].ref,originals.read.ref)||!same(activation.authority_refs[1].ref,originals.root.ref))mismatch();
  if(!same(active.offer_ref,originals.offer.ref)||!same(active.activation_ref,originals.activation.ref)||!same(active.resource,offer.resource)||
      !same(active.root_key,slot.root_key)||active.reservation_generation!==offer.reservation_generation||
      !same(active.budget,offer.budget)||!same(active.windows,offer.windows))mismatch();
  const at=active.activated_at;
  if(!(allocate.issued_at<=offer.issued_at&&offer.issued_at<allocate.expires_at&&offer.issued_at<offer.reservation_until&&
      offer.issued_at<=root.issued_at&&root.issued_at<=read.issued_at&&read.issued_at<=activation.issued_at&&activation.issued_at<=at&&
      at<root.expires_at&&at<read.expires_at&&at<activation.expires_at&&at<offer.reservation_until))fail();
  compatibleWindow(intent.windows,allocate.issued_at);compatibleWindow(root.windows,root.issued_at,root.expires_at);
  compatibleWindow(read.windows,read.issued_at,read.expires_at);
  return Object.freeze({originals:Object.freeze(originals),activated_at:at});
}
