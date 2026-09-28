/** Complete inline bootstrap proof containers and signed finite child ranges.
 * Authentication of this container is not authentication of its children and
 * does not grant live read permission or make a handle a bearer capability.
 */
import {randomBytes} from 'node:crypto';
import {isUint8Array} from 'node:util/types';
import {buildNewWire,parseNewWire,rawRef,objectFields,u53,RepairError} from './open-repair-wire.ts';
import type {DraftJson,RawRef,RepairPolicy,RepairBudget} from './open-repair-wire.ts';
import {originalPublicDescriptor,verifyBoundedControlSignature} from './open-repair-original.ts';
import {signBoundedBootstrapOriginal} from './open-repair-probe.ts';
import type {AuthenticatedRepairOriginal} from './open-repair-resource.ts';

type Obj=Record<string,any>;
const SCHEMA='memory-vault-open-repair/v1',MAX_RESPONSE=65536,MAX_CHILD=65536;
const FIXED_ROLES=Object.freeze(['ack.root_authority','ack.read_grant','bootstrap.ack_owner','resource.ack_allocate','resource.ack_offer',
  'resource.ack_activation','resource.ack_active','source.descriptor','historical.status.ack_root','historical.status.ack_read',
  'historical.status.ack_owner_bootstrap','historical.status.ack_slot','historical.status.ack_resource','current.status.ack_root',
  'current.status.ack_read','current.status.ack_owner_bootstrap','current.status.ack_slot','current.status.ack_resource','history.ack_unbound','ack.unbound_custody']);
const COMMON=['schema_version','kind','signing_key','issued_at','expires_at','subject','target','target_storage_epoch','purpose','consumer'];
const HANDLE=[...COMMON,'bootstrap_grant_sha256','handle_id','probe_ref','challenge_ref','answer_ref','service_generation','manifest_ref','child_count'];
const CHILD=[...COMMON,'request_id','probe_ref','handle_ref','manifest_ref','service_generation','child_index','offset','requested_bytes'];
const MANIFEST=['schema_version','kind','probe_ref','subject','target','target_storage_epoch','consumer','selector','bootstrap_grant_ref','service_generation','response_profile','children'];
const SELECTOR=['root_key_sha256','ack_slot_sha256','root_authority_sha256','read_grant_sha256'];
const EXPECTED=['expectedSubject','expectedTarget','targetStorageEpoch','selector','bootstrapGrantRef','probeRef','challengeRef','answerRef','at'];
const proofBrand=new WeakSet<object>();
const byteLength=Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint8Array.prototype),'byteLength')!.get!;
export interface AuthenticatedBootstrapProof{
  readonly handle:AuthenticatedRepairOriginal;readonly manifest:DraftJson;readonly manifest_ref:RawRef;
}
export interface BootstrapProofOptions{
  readonly expectedSubject:unknown;readonly expectedTarget:unknown;readonly targetStorageEpoch:string;readonly selector:unknown;
  readonly bootstrapGrantRef:unknown;readonly probeRef:unknown;readonly challengeRef:unknown;readonly answerRef:unknown;
  readonly at:number;readonly maxProofItems:number;readonly maxProofBytes:number;readonly policy:RepairPolicy;readonly budget:RepairBudget;
}
function fail(code='repair_invalid_proof'):never{throw new RepairError(code);}
function mismatch():never{fail('repair_proof_mismatch');}
function fields(value:unknown,names:readonly string[]):Obj{try{return objectFields(value,names);}catch{fail();}}
function pattern(value:unknown,re:RegExp):string{if(typeof value!=='string'||re.exec(value)?.[0]!==value)fail();return value;}
function opaque(value:unknown):void{pattern(value,/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/);}
function same(a:unknown,b:unknown):boolean{
  if(a===b)return true;if(a===null||b===null||typeof a!=='object'||typeof b!=='object'||Array.isArray(a)!==Array.isArray(b))return false;
  const keys=Object.keys(a);return keys.length===Object.keys(b).length&&keys.every(key=>Object.hasOwn(b,key)&&same((a as Obj)[key],(b as Obj)[key]));
}
function meta(value:unknown):RawRef{const ref=rawRef(value);if(ref.namespace!=='meta')fail();return ref;}
function ids(value:Obj):Obj{return {signing_key_id:value.signing_key.key_id,encryption_key_id:value.encryption_key.key_id};}
function dual(value:unknown,budget:RepairBudget):Obj{
  const key=fields(value,['signing_key','encryption_key']);originalPublicDescriptor(key.signing_key,budget);originalPublicDescriptor(key.encryption_key,budget,true);return key;
}
function window(payload:Obj,at:number):void{
  const issued=u53(payload.issued_at),expires=u53(payload.expires_at);u53(at);
  if(!(issued<=at&&at<expires&&expires-issued>=1&&expires-issued<=60))fail('repair_invalid_probe');
}
function expected(args:Obj,policy:RepairPolicy,budget:RepairBudget):Obj{
  const value=buildNewWire(Object.fromEntries(EXPECTED.map(name=>[name,args[name]])),policy,budget).value as Obj;
  for(const name of ['bootstrapGrantRef','probeRef','challengeRef','answerRef'])meta(value[name]);
  dual(value.expectedSubject,budget);dual(value.expectedTarget,budget);u53(value.at);opaque(value.targetStorageEpoch);
  fields(value.selector,SELECTOR);for(const name of SELECTOR)pattern(value.selector[name],/^[0-9a-f]{64}$/);return value;
}
function manifestShape(value:unknown,expected:Obj,maximumItems:number):Obj{
  const m=fields(value,MANIFEST);
  if(m.schema_version!==SCHEMA||m.kind!=='bootstrap.proof_manifest'||m.consumer!=='ack_owner'||m.response_profile!=='ack_owner_service_v1'||
      !same(m.subject,ids(expected.expectedSubject))||!same(m.target,ids(expected.expectedTarget))||m.target_storage_epoch!==expected.targetStorageEpoch||
      !same(m.selector,expected.selector)||!same(meta(m.bootstrap_grant_ref),meta(expected.bootstrapGrantRef))||!same(meta(m.probe_ref),meta(expected.probeRef)))mismatch();
  u53(m.service_generation,1);
  if(!Array.isArray(m.children)||m.children.length<FIXED_ROLES.length+1||m.children.length>maximumItems)fail();
  const counts=new Map<string,number>(),packs=new Set<string>();
  for(const [index,value] of m.children.entries()){
    const item=fields(value,['index','role','ref']);
    if(u53(item.index)!==index||typeof item.role!=='string'||(item.role!=='history.raw_pack'&&!FIXED_ROLES.includes(item.role)))fail();
    const ref=meta(item.ref);counts.set(item.role,(counts.get(item.role)??0)+1);
    if(item.role==='history.raw_pack'){
      const identity=`${ref.namespace}:${ref.key}:${ref.raw_sha256}:${ref.size}`;
      if(packs.has(identity)||ref.key!==ref.raw_sha256)fail();packs.add(identity);
    }
  }
  if(FIXED_ROLES.some(name=>counts.get(name)!==1)||packs.size===0)fail();return m;
}
function encode(raw:Uint8Array,budget:RepairBudget):string{
  budget.output(Math.ceil(raw.length*4/3));return Buffer.from(raw.buffer,raw.byteOffset,raw.byteLength).toString('base64url');
}
function decodedSize(value:unknown):number{
  if(typeof value!=='string'||value.length===0||value.length>MAX_RESPONSE||/^[A-Za-z0-9_-]+$/.exec(value)?.[0]!==value||value.length%4===1)fail();
  return Math.floor(value.length*3/4);
}
function decode(value:string,size:number,budget:RepairBudget):Buffer{
  budget.output(size);const raw=Buffer.from(value,'base64url');if(raw.length!==size||encode(raw,budget)!==value)fail('repair_invalid_original');return raw;
}
function parsed(raw:Uint8Array,policy:RepairPolicy,budget:RepairBudget):{document:DraftJson;ref:RawRef}{
  const document=parseNewWire(raw,policy,budget),bytes=document.raw,digest=budget.hash(bytes);
  return {document,ref:meta({namespace:'meta',key:digest,raw_sha256:digest,size:bytes.length})};
}
function held(raw:Uint8Array,ref:RawRef,payload:Obj,budget:RepairBudget):AuthenticatedRepairOriginal{
  return Object.freeze({ref,payload,get raw():Uint8Array{budget.output(raw.length);return Uint8Array.from(raw);}});
}
function checkedProof(value:unknown):AuthenticatedBootstrapProof{
  if(value===null||typeof value!=='object'||!proofBrand.has(value))fail();return value as AuthenticatedBootstrapProof;
}
function childParents(value:unknown,subject:unknown,target:unknown,at:unknown,policy:RepairPolicy,budget:RepairBudget):{proof:AuthenticatedBootstrapProof;subject:Obj;target:Obj;at:number}{
  const proof=checkedProof(value),cloned=buildNewWire({subject,target,at},policy,budget).value as Obj;
  const s=dual(cloned.subject,budget),t=dual(cloned.target,budget),h=proof.handle.payload as Obj,m=proof.manifest.value as Obj;
  if(!same(h.subject,ids(s))||!same(h.target,ids(t))||!same(m.subject,h.subject)||!same(m.target,h.target))mismatch();
  return {proof,subject:s,target:t,at:u53(cloned.at)};
}
export function makeBootstrapProofResponse(signer:unknown,manifestPayload:unknown,options:{
  probeRef:unknown;challengeRef:unknown;answerRef:unknown;subject:unknown;target:unknown;at:number;expiresAt:number;
  handleId:string;policy:RepairPolicy;budget:RepairBudget}):DraftJson{
  const args=fields(options,['probeRef','challengeRef','answerRef','subject','target','at','expiresAt','handleId','policy','budget']),policy=args.policy as RepairPolicy,budget=args.budget as RepairBudget;
  const manifest=buildNewWire(manifestPayload,policy,budget),body=fields(manifest.value,MANIFEST);
  const e=expected({expectedSubject:args.subject,expectedTarget:args.target,targetStorageEpoch:body.target_storage_epoch,selector:body.selector,
    bootstrapGrantRef:body.bootstrap_grant_ref,probeRef:args.probeRef,challengeRef:args.challengeRef,answerRef:args.answerRef,at:args.at},policy,budget);
  manifestShape(body,e,policy.max_entries);opaque(args.handleId);
  const bytes=manifest.raw,digest=budget.hash(bytes),ref=meta({namespace:'meta',key:digest,raw_sha256:digest,size:bytes.length});
  const payload={schema_version:SCHEMA,kind:'bootstrap.proof_handle',signing_key:e.expectedTarget.signing_key,issued_at:e.at,expires_at:u53(args.expiresAt),
    handle_id:args.handleId,probe_ref:e.probeRef,challenge_ref:e.challengeRef,answer_ref:e.answerRef,subject:body.subject,target:body.target,
    target_storage_epoch:body.target_storage_epoch,purpose:'bootstrap.service_proof',consumer:'ack_owner',bootstrap_grant_sha256:body.bootstrap_grant_ref.raw_sha256,
    service_generation:body.service_generation,manifest_ref:ref,child_count:body.children.length};
  window(payload,e.at);const handle=signBoundedBootstrapOriginal(payload,signer,policy,budget);
  const response=buildNewWire({schema_version:SCHEMA,kind:'bootstrap.proof_response',handle_raw_base64url:encode(handle.raw,budget),manifest_raw_base64url:encode(bytes,budget)},policy,budget);
  if(response.raw.length>MAX_RESPONSE)fail('repair_proof_too_large');return response;
}
export function verifyBootstrapProofResponse(raw:Uint8Array,options:BootstrapProofOptions):AuthenticatedBootstrapProof{
  const args=fields(options,[...EXPECTED,'maxProofItems','maxProofBytes','policy','budget']),policy=args.policy as RepairPolicy,budget=args.budget as RepairBudget;
  const maximumItems=u53(args.maxProofItems,1),maximumBytes=u53(args.maxProofBytes,1);
  if(!isUint8Array(raw))fail();const inputSize=Reflect.apply(byteLength,raw,[]) as number;
  if(inputSize>Math.min(MAX_RESPONSE,maximumBytes))fail('repair_proof_too_large');
  const e=expected(args,policy,budget),response=parseNewWire(raw,policy,budget),wrapper=fields(response.value,['schema_version','kind','handle_raw_base64url','manifest_raw_base64url']);
  if(wrapper.schema_version!==SCHEMA||wrapper.kind!=='bootstrap.proof_response')fail();
  const hs=decodedSize(wrapper.handle_raw_base64url),ms=decodedSize(wrapper.manifest_raw_base64url);
  if(inputSize+hs+ms>maximumBytes)fail('repair_proof_too_large');
  const h=parsed(decode(wrapper.handle_raw_base64url,hs,budget),policy,budget),signed=fields(h.document.value,['payload','proof']),payload=fields(signed.payload,HANDLE);
  window(payload,e.at);opaque(payload.handle_id);
  if(payload.schema_version!==SCHEMA||payload.kind!=='bootstrap.proof_handle'||payload.purpose!=='bootstrap.service_proof'||payload.consumer!=='ack_owner'||
      !same(payload.subject,ids(e.expectedSubject))||!same(payload.target,ids(e.expectedTarget))||payload.target_storage_epoch!==e.targetStorageEpoch||
      payload.bootstrap_grant_sha256!==e.bootstrapGrantRef.raw_sha256||['probe_ref','challenge_ref','answer_ref'].some((name,index)=>!same(meta(payload[name]),meta(e[['probeRef','challengeRef','answerRef'][index]]))))mismatch();
  verifyBoundedControlSignature(payload,signed.proof,e.expectedTarget.signing_key,budget);
  const manifestRef=meta(payload.manifest_ref),m=parsed(decode(wrapper.manifest_raw_base64url,ms,budget),policy,budget);
  if(m.ref.raw_sha256!==manifestRef.raw_sha256||m.ref.size!==manifestRef.size)fail('repair_ref_mismatch');
  const body=manifestShape(m.document.value,e,maximumItems);
  if(u53(payload.child_count)!==body.children.length||u53(payload.service_generation,1)!==body.service_generation)mismatch();
  const result=Object.freeze({handle:held(h.document.raw,h.ref,payload,budget),manifest:m.document,manifest_ref:manifestRef});proofBrand.add(result);return result;
}
function childRange(payload:Obj,children:readonly Obj[]):void{
  const index=u53(payload.child_index),offset=u53(payload.offset),size=u53(payload.requested_bytes,1);
  if(index>=children.length||size>MAX_CHILD||offset>children[index].ref.size-size)fail('repair_invalid_range');
}
export function makeBootstrapChildRequest(signer:unknown,value:AuthenticatedBootstrapProof,options:{subject:unknown;target:unknown;at:number;expiresAt:number;
  childIndex:number;offset:number;requestedBytes:number;policy:RepairPolicy;budget:RepairBudget}):AuthenticatedRepairOriginal{
  const args=fields(options,['subject','target','at','expiresAt','childIndex','offset','requestedBytes','policy','budget']),policy=args.policy as RepairPolicy,budget=args.budget as RepairBudget;
  const {proof,subject,target,at}=childParents(value,args.subject,args.target,args.at,policy,budget),handle=proof.handle.payload as Obj;
  budget.output(16);const token=randomBytes(16);budget.output(38);const requestId='child_'+token.toString('hex');
  const payload={schema_version:SCHEMA,kind:'bootstrap.proof_child_request',signing_key:subject.signing_key,issued_at:at,expires_at:u53(args.expiresAt),request_id:requestId,
    subject:ids(subject),target:ids(target),target_storage_epoch:handle.target_storage_epoch,purpose:'bootstrap.service_proof_child',consumer:'ack_owner',probe_ref:handle.probe_ref,
    handle_ref:proof.handle.ref,manifest_ref:proof.manifest_ref,service_generation:handle.service_generation,child_index:args.childIndex,offset:args.offset,requested_bytes:args.requestedBytes};
  window(payload,at);childRange(payload,(proof.manifest.value as Obj).children);
  if(payload.issued_at<handle.issued_at||payload.expires_at>handle.expires_at)mismatch();
  return signBoundedBootstrapOriginal(payload,signer,policy,budget);
}
export function verifyBootstrapChildRequest(entry:unknown,value:AuthenticatedBootstrapProof,options:{expectedSubject:unknown;expectedTarget:unknown;at:number;policy:RepairPolicy;budget:RepairBudget}):AuthenticatedRepairOriginal{
  const args=fields(options,['expectedSubject','expectedTarget','at','policy','budget']),policy=args.policy as RepairPolicy,budget=args.budget as RepairBudget;
  const {proof,subject,target,at}=childParents(value,args.expectedSubject,args.expectedTarget,args.at,policy,budget),input=fields(entry,['raw','ref']),ref=meta(input.ref);
  if(!isUint8Array(input.raw)||Reflect.apply(byteLength,input.raw,[])>MAX_RESPONSE)fail();
  const document=parseNewWire(input.raw,policy,budget),raw=document.raw;
  if(raw.length!==ref.size||budget.hash(raw)!==ref.raw_sha256)fail('repair_ref_mismatch');
  const signed=fields(document.value,['payload','proof']),payload=fields(signed.payload,CHILD),handle=proof.handle.payload as Obj;
  window(payload,at);opaque(payload.request_id);
  if(payload.schema_version!==SCHEMA||payload.kind!=='bootstrap.proof_child_request'||payload.purpose!=='bootstrap.service_proof_child'||payload.consumer!=='ack_owner'||
      !same(payload.subject,ids(subject))||!same(payload.target,ids(target))||payload.target_storage_epoch!==handle.target_storage_epoch||
      !same(meta(payload.handle_ref),proof.handle.ref)||!same(meta(payload.manifest_ref),proof.manifest_ref)||!same(meta(payload.probe_ref),meta(handle.probe_ref))||
      payload.service_generation!==handle.service_generation||payload.issued_at<handle.issued_at||payload.expires_at>handle.expires_at)mismatch();
  childRange(payload,(proof.manifest.value as Obj).children);verifyBoundedControlSignature(payload,signed.proof,subject.signing_key,budget);return held(raw,ref,payload,budget);
}
