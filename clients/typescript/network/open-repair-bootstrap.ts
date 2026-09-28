/** Authenticate an ACK owner's existing bootstrap grant and its exact parents.
 * No probe/upload, current status, resource, custody or live capability follows.
 * `at` is an explicit external event time; this function does not authenticate it.
 */
import {buildNewWire, parseNewWire, rawRef, objectFields, u53, RepairError} from './open-repair-wire.ts';
import type {DraftValue, RawRef, RepairPolicy, RepairBudget} from './open-repair-wire.ts';
import {canonicalOriginalControl, originalPublicDescriptor, verifyBoundedControlSignature} from './open-repair-original.ts';
import {knownHistoricalRoles} from './open-repair-history.ts';
import type {AuthenticatedRepairOriginal} from './open-repair-resource.ts';

type Obj = Record<string, any>;
const SCHEMA = 'memory-vault-open-repair/v1';
const COMMON = ['schema_version','kind','signing_key'];
const ROOT_FIELDS = ['issued_at','expires_at','ack_slot','authority_id','owner','receipt_writer',
  'original_resource_ref','original_resource_offer_ref','maintainers','operation_mask','allowed_roles',
  'max_bindings','max_receipts','budget','windows','max_delegate_depth','max_destinations_per_job','max_concurrent_jobs','revision'];
const READ_FIELDS = ['issued_at','expires_at','grant_id','ack_slot','reader','root_authority_ref','operation_mask','budget','windows','revision'];
const GRANT_FIELDS = ['issued_at','expires_at','grant_id','revision','owner','subject','root_key','consumer','selector',
  'parent_authority_ref','caller_authority_ref','probe_until','proof_until','upload_until','probe_profile','response_profile','upload_roles','limits'];
const LIMIT_FIELDS = ['max_probe_bytes','max_proof_bytes','max_proof_items','max_signature_checks','max_requests',
  'max_pending','max_replay_records','max_concurrent_handles','max_candidate_attempts'];
const BUDGET_FIELDS = ['max_live_bytes','max_meta_bytes','max_items','max_requests','max_pending','max_replay_records','max_jobs','max_job_bytes'];
const WINDOW_FIELDS = ['admit_until','read_until','copy_until','publish_until','retain_until'];
const UPLOAD_ROLES = ['ack.read_grant','ack.root_authority','ack.write_grant','bootstrap.grant'];
const KNOWN_ROLES = new Set([...knownHistoricalRoles,'bootstrap.grant','mailbox_root_service_v1',
  'selected_slot_service_v1','ack_owner_service_v1','ack_offer_service_v1']);
export interface AckOwnerBootstrapOptions {
  readonly expectedAckSlot: unknown; readonly expectedOwner: unknown;
  readonly at: number; readonly limitPolicy: unknown; readonly policy: RepairPolicy; readonly budget: RepairBudget;
}
export interface AuthenticatedAckOwnerBootstrapInputs {
  readonly originals: Readonly<{root:AuthenticatedRepairOriginal;read:AuthenticatedRepairOriginal;bootstrap:AuthenticatedRepairOriginal}>;
  readonly at: number;
}
function fail(code='repair_invalid_bootstrap'):never {throw new RepairError(code);}
function mismatch():never {fail('repair_bootstrap_mismatch');}
function fields(value:unknown,names:readonly string[]):Obj {try{return objectFields(value,names);}catch{fail();}}
function number(value:unknown,min=0):number {try{return u53(value,min);}catch{fail();}}
function pattern(value:unknown,re:RegExp):string {if(typeof value!=='string'||re.exec(value)?.[0]!==value)fail();return value;}
function opaque(value:unknown):string{return pattern(value,/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/);}
function digest(value:unknown):string{return pattern(value,/^[0-9a-f]{64}$/);}
function key(value:unknown,encryption=false):string{return pattern(value,encryption?/^x25519_[0-9a-f]{64}$/:/^ed25519_[0-9a-f]{64}$/);}
function same(a:unknown,b:unknown):boolean{
  if(a===b)return true;if(a===null||b===null||typeof a!=='object'||typeof b!=='object'||Array.isArray(a)!==Array.isArray(b))return false;
  const names=Object.keys(a);return names.length===Object.keys(b).length&&names.every(name=>Object.hasOwn(b,name)&&same((a as Obj)[name],(b as Obj)[name]));
}
function dualId(value:unknown):Obj {const raw=fields(value,['signing_key_id','encryption_key_id']);key(raw.signing_key_id);key(raw.encryption_key_id,true);return raw;}
function dualKey(value:unknown):Obj{
  const raw=fields(value,['signing_key','encryption_key']);
  for(const [name,algorithm,schema] of [['signing_key','Ed25519','universal-memory-public-key/v1'],['encryption_key','X25519','memory-vault-network-encryption-key/v1']]){
    const part=fields(raw[name],['schema_version','algorithm','key_id','public_key']);
    if(part.algorithm!==algorithm||part.schema_version!==schema||typeof part.public_key!=='string')fail();key(part.key_id,name==='encryption_key');
  }return raw;
}
function rootKey(value:unknown):Obj{
  const root=fields(value,['owner','root_kind','anchor_ref','owner_epoch','root_id']);dualId(root.owner);
  if(root.root_kind!=='ack_return')fail();const anchor=fields(root.anchor_ref,['namespace','key']);
  if(anchor.namespace!=='anchor')fail();digest(anchor.key);opaque(root.owner_epoch);opaque(root.root_id);return root;
}
function ackSlot(value:unknown):Obj{const slot=fields(value,['root_key','slot_id','receipt_writer','grant_id']);rootKey(slot.root_key);opaque(slot.slot_id);dualId(slot.receipt_writer);opaque(slot.grant_id);return slot;}
function meta(value:unknown):RawRef{const ref=rawRef(value);if(ref.namespace!=='meta')fail();return ref;}
function limits(value:unknown):Obj{const raw=fields(value,LIMIT_FIELDS);for(const name of LIMIT_FIELDS)number(raw[name],1);return raw;}
function mask(value:unknown):number{const result=number(value);if(result>127)fail();return result;}
function ordered(value:unknown,allowed:ReadonlySet<string>):void{
  if(!Array.isArray(value))fail();let previous='';for(const item of value){if(typeof item!=='string'||!allowed.has(item)||item<=previous)fail();previous=item;}
}
function parentShape(payload:Obj,root:boolean):void{
  number(payload.issued_at);number(payload.expires_at);number(payload.revision);ackSlot(payload.ack_slot);mask(payload.operation_mask);
  const budget=fields(payload.budget,BUDGET_FIELDS);for(const name of BUDGET_FIELDS)number(budget[name]);
  const windows=fields(payload.windows,WINDOW_FIELDS);for(const name of WINDOW_FIELDS)number(windows[name]);
  for(const name of WINDOW_FIELDS)if(windows[name]<=payload.issued_at||windows[name]>payload.expires_at||windows[name]>windows.retain_until)fail();
  if(root){
    opaque(payload.authority_id);dualId(payload.owner);dualId(payload.receipt_writer);
    const resource=fields(payload.original_resource_ref,['node_key_id','storage_epoch','lease_id','resource_id']);key(resource.node_key_id);
    for(const name of ['storage_epoch','lease_id','resource_id'])opaque(resource[name]);meta(payload.original_resource_offer_ref);
    if(!Array.isArray(payload.maintainers))fail();let previous='';for(const item of payload.maintainers){const id=dualId(item),text=id.signing_key_id+':'+id.encryption_key_id;if(text<=previous)fail();previous=text;}
    ordered(payload.allowed_roles,KNOWN_ROLES);number(payload.max_destinations_per_job);number(payload.max_concurrent_jobs);
    if(payload.max_bindings!==1||payload.max_receipts!==1||payload.max_delegate_depth!==2)fail();
  }else{opaque(payload.grant_id);dualId(payload.reader);meta(payload.root_authority_ref);}
}
function grantShape(payload:Obj):void{
  for(const name of ['issued_at','expires_at','revision','probe_until','proof_until','upload_until'])number(payload[name]);
  opaque(payload.grant_id);dualId(payload.owner);dualId(payload.subject);rootKey(payload.root_key);
  if(payload.consumer!=='ack_owner'||payload.probe_profile!=='opaque_v1'||payload.response_profile!=='ack_owner_service_v1')fail();
  const selector=fields(payload.selector,['root_key_sha256','ack_slot_sha256','root_authority_sha256','read_grant_sha256']);for(const name of Object.keys(selector))digest(selector[name]);
  meta(payload.parent_authority_ref);meta(payload.caller_authority_ref);ordered(payload.upload_roles,new Set(UPLOAD_ROLES));limits(payload.limits);
}
function verify(entry:unknown,kind:string,names:readonly string[],owner:Obj,policy:RepairPolicy,budget:RepairBudget):AuthenticatedRepairOriginal{
  const value=fields(entry,['raw','ref']),ref=meta(value.ref),parsed=parseNewWire(value.raw as Uint8Array,policy,budget),raw=parsed.raw;
  if(raw.length!==ref.size||budget.hash(raw)!==ref.raw_sha256)fail('repair_ref_mismatch');
  const signed=fields(parsed.value,['payload','proof']),payload=fields(signed.payload,[...COMMON,...names]);
  if(payload.schema_version!==SCHEMA||payload.kind!==kind)fail();
  if(kind==='bootstrap.grant')grantShape(payload);else parentShape(payload,kind==='ack.root_authority');
  verifyBoundedControlSignature(payload,signed.proof,owner.signing_key,budget);
  return Object.freeze({ref,payload,get raw():Uint8Array{budget.output(raw.length);return Uint8Array.from(raw);}});
}

export function verifyAckOwnerBootstrapOriginal(entry:unknown,parents:unknown,options:AckOwnerBootstrapOptions):AuthenticatedAckOwnerBootstrapInputs{
  const args=fields(options,['expectedAckSlot','expectedOwner','at','limitPolicy','policy','budget']);
  const policy=args.policy as RepairPolicy,budget=args.budget as RepairBudget;
  const expected=buildNewWire({ack_slot:args.expectedAckSlot,owner:args.expectedOwner,at:args.at,limit_policy:args.limitPolicy},policy,budget).value as Obj;
  const slot=ackSlot(expected.ack_slot),owner=dualKey(expected.owner),at=number(expected.at),limitPolicy=limits(expected.limit_policy);
  originalPublicDescriptor(owner.signing_key,budget);originalPublicDescriptor(owner.encryption_key,budget,true);
  const ownerId={signing_key_id:owner.signing_key.key_id,encryption_key_id:owner.encryption_key.key_id};if(!same(slot.root_key.owner,ownerId))mismatch();
  const held=fields(parents,['root','read']);
  const root=verify(held.root,'ack.root_authority',ROOT_FIELDS,owner,policy,budget),read=verify(held.read,'ack.read_grant',READ_FIELDS,owner,policy,budget);
  const bootstrap=verify(entry,'bootstrap.grant',GRANT_FIELDS,owner,policy,budget);
  const r=root.payload as Obj,c=read.payload as Obj,g=bootstrap.payload as Obj;
  if(!same(r.ack_slot,slot)||!same(c.ack_slot,slot)||!same(r.owner,ownerId)||!same(r.receipt_writer,slot.receipt_writer)||
      !same(c.reader,ownerId)||!same(c.root_authority_ref,root.ref)||!same(g.owner,ownerId)||!same(g.subject,ownerId)||
      !same(g.root_key,slot.root_key)||!same(g.parent_authority_ref,root.ref)||!same(g.caller_authority_ref,read.ref))mismatch();
  if((r.operation_mask&10)!==10||(c.operation_mask&2)!==2||(c.operation_mask&r.operation_mask)!==c.operation_mask||
      !r.allowed_roles.includes('bootstrap.grant')||!r.allowed_roles.includes('ack_owner_service_v1')||g.upload_roles.some((name:string)=>!r.allowed_roles.includes(name))||
      BUDGET_FIELDS.some(name=>c.budget[name]>r.budget[name])||WINDOW_FIELDS.some(name=>c.windows[name]>r.windows[name]))mismatch();
  const rootHash=budget.hash(canonicalOriginalControl(slot.root_key,budget)),slotHash=budget.hash(canonicalOriginalControl(slot,budget));
  if(g.selector.root_key_sha256!==rootHash||g.selector.ack_slot_sha256!==slotHash||g.selector.root_authority_sha256!==root.ref.raw_sha256||g.selector.read_grant_sha256!==read.ref.raw_sha256)mismatch();
  if(!(r.issued_at<=c.issued_at&&c.issued_at<=g.issued_at&&g.issued_at<=at&&
      at<r.expires_at&&at<c.expires_at&&at<g.expires_at&&c.expires_at<=r.expires_at&&
      g.expires_at<=c.expires_at&&g.expires_at<=r.expires_at))fail();
  for(const name of ['probe_until','proof_until','upload_until'])if(g[name]<=g.issued_at||g[name]>g.expires_at)fail();
  const readUntil=Math.min(r.windows.read_until,r.windows.retain_until,c.windows.read_until,c.windows.retain_until);
  if(g.proof_until>readUntil||g.upload_until>readUntil)mismatch();
  // Phase deadlines do not all have to outlive the external event. This is
  // input authentication; a later consumer checks its actual operation time.
  if(LIMIT_FIELDS.some(name=>g.limits[name]>limitPolicy[name]))mismatch();
  // Conservative resource-to-bootstrap cap profile: caller read authority may
  // narrow every parent amount. Local parsing/verification work is separate.
  for(const parent of [r.budget,c.budget]){
    const caps:Obj={max_probe_bytes:Math.min(parent.max_meta_bytes,parent.max_job_bytes),
      max_proof_bytes:Math.min(parent.max_meta_bytes,parent.max_job_bytes),max_proof_items:parent.max_items,
      max_signature_checks:parent.max_requests,max_requests:parent.max_requests,max_pending:parent.max_pending,
      max_replay_records:parent.max_replay_records,max_concurrent_handles:Math.min(parent.max_pending,parent.max_jobs),
      max_candidate_attempts:Math.min(parent.max_requests,parent.max_jobs)};
    if(LIMIT_FIELDS.some(name=>g.limits[name]>caps[name]))mismatch();
  }
  return Object.freeze({originals:Object.freeze({root,read,bootstrap}),at});
}
