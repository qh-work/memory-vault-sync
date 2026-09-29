/** Complete inline bootstrap proof containers and signed finite child ranges.
 * Authentication of this container is not authentication of its children and
 * does not grant live read permission or make a handle a bearer capability.
 */
import {randomBytes} from 'node:crypto';
import {isUint8Array,isProxy} from 'node:util/types';
import {buildNewWire,parseNewWire,rawRef,objectFields,u53,RepairError} from './open-repair-wire.ts';
import type {DraftJson,RawRef,RepairPolicy,RepairBudget} from './open-repair-wire.ts';
import {originalPublicDescriptor,verifyBoundedControlSignature} from './open-repair-original.ts';
import {signBoundedBootstrapOriginal} from './open-repair-probe.ts';
import type {BootstrapConsumer} from './open-repair-probe.ts';
import type {AuthenticatedRepairOriginal} from './open-repair-resource.ts';

type Obj=Record<string,any>;
const SCHEMA='memory-vault-open-repair/v1',MAX_RESPONSE=65536,MAX_CHILD=65536;
const FIXED_ROLES=Object.freeze(['ack.root_authority','ack.read_grant','bootstrap.ack_owner','resource.ack_allocate','resource.ack_offer',
  'resource.ack_activation','resource.ack_active','source.descriptor','historical.status.ack_root','historical.status.ack_read',
  'historical.status.ack_owner_bootstrap','historical.status.ack_slot','historical.status.ack_resource','current.status.ack_root',
  'current.status.ack_read','current.status.ack_owner_bootstrap','current.status.ack_slot','current.status.ack_resource','history.ack_unbound','ack.unbound_custody']);
const EMPTY_FIXED_ROLES=Object.freeze(['historical.status.ack_root','historical.status.ack_read','historical.status.ack_owner_bootstrap',
  'historical.status.ack_write','historical.status.ack_offer_bootstrap','historical.status.ack_slot','historical.status.ack_resource',
  'history.ack_unbound','ack.unbound_custody','ack.write_grant','bootstrap.ack_offer','ack.binding','history.ack_empty','ack.empty_custody','ack.head',
  'current.status.ack_root','current.status.ack_read','current.status.ack_owner_bootstrap','current.status.ack_slot','current.status.ack_resource']);
const OCCUPIED_FIXED_ROLES=Object.freeze(['historical.status.ack_root','historical.status.ack_read','historical.status.ack_owner_bootstrap',
  'historical.status.ack_write','historical.status.ack_offer_bootstrap','historical.status.ack_slot','historical.status.admission_resource','historical.status.ack_disclosure',
  'history.ack_empty','ack.empty_custody','recipient.receipt','ack.disclosure','ack.put','history.ack_occupied_inputs','ack.commit','ack.head',
  'current.status.ack_root','current.status.ack_read','current.status.ack_owner_bootstrap','current.status.ack_slot','current.status.ack_resource','current.status.ack_disclosure']);
const REPLICA_FIXED_ROLES=Object.freeze([...FIXED_ROLES.filter(role=>!role.startsWith('current.')&&role!=='ack.unbound_custody'),
  'ack.slot_custody','copy.reservation_consent','copy.allocation','copy.offer','copy.assignment','copy.owner_disclosure',
  'copy.source_disclosure','copy.current_status','replica.manifest','replica.custody','return.owner','return.source',
  'return.maintainer','current.status.replica_read']);
const REPLICA_EMPTY_FIXED_ROLES=Object.freeze([...new Set([...REPLICA_FIXED_ROLES.filter(role=>role!=='ack.slot_custody'),
  ...EMPTY_FIXED_ROLES.filter(role=>!role.startsWith('current.')&&role!=='ack.head'),'replica.read_pack'])]);
const REPLICA_EMPTY_REPEATED=Object.freeze(['historical.status.ack_root','historical.status.ack_read',
  'historical.status.ack_owner_bootstrap','historical.status.ack_slot','historical.status.ack_resource']);
const REPLICA_OCCUPIED_FIXED_ROLES=Object.freeze([...new Set([...REPLICA_EMPTY_FIXED_ROLES,
  ...OCCUPIED_FIXED_ROLES.filter(role=>!role.startsWith('current.')&&role!=='ack.head'),
  'copy.recipient_reservation_consent','copy.recipient_disclosure','return.recipient'])]);
const REPLICA_OCCUPIED_REPEATED=new Map<string,number>([
  ['historical.status.ack_root',3],['historical.status.ack_read',3],['historical.status.ack_owner_bootstrap',3],
  ['historical.status.ack_slot',3],['historical.status.ack_resource',2],
  ['historical.status.ack_write',2],['historical.status.ack_offer_bootstrap',2]]);
const SOURCE_STATES=new Map<string,{roles:readonly string[];minimumPacks:number}>([
  ['replica_occupied',{roles:REPLICA_OCCUPIED_FIXED_ROLES,minimumPacks:3}],
  ['replica_empty',{roles:REPLICA_EMPTY_FIXED_ROLES,minimumPacks:2}],
  ['unbound',{roles:FIXED_ROLES,minimumPacks:1}],['replica_unbound',{roles:REPLICA_FIXED_ROLES,minimumPacks:1}],['empty',{roles:EMPTY_FIXED_ROLES,minimumPacks:2}],['occupied',{roles:OCCUPIED_FIXED_ROLES,minimumPacks:3}]]);
const OFFER_FIXED_ROLES=Object.freeze(EMPTY_FIXED_ROLES.map(role=>role==='current.status.ack_read'?'current.status.ack_write':
  role==='current.status.ack_owner_bootstrap'?'current.status.ack_offer_bootstrap':role));
const MAILBOX_ROOT_ROLES=Object.freeze(["bootstrap.mailbox_feed", "bootstrap.mailbox_root", "current.status.anchor_resource", "current.status.bootstrap", "current.status.catalog", "current.status.data_resource", "current.status.maintenance", "current.status.metadata_resource", "current.status.read", "current.status.root", "current.status.root_bootstrap", "current.status.root_read", "current.status.slot", "genesis.checkpoint", "genesis.head", "historical.status.anchor_resource", "historical.status.bootstrap", "historical.status.catalog", "historical.status.data_resource", "historical.status.maintenance", "historical.status.metadata_resource", "historical.status.read", "historical.status.root", "historical.status.root_bootstrap", "historical.status.root_read", "historical.status.slot", "history.mailbox_root", "mailbox.catalog", "mailbox.maintenance_root", "mailbox.read_grant", "mailbox.root_authority", "mailbox.root_read_grant", "mailbox.slot", "resource.anchor_activation", "resource.anchor_active", "resource.anchor_allocate", "resource.anchor_offer", "resource.data_active", "resource.data_allocate", "resource.data_offer", "resource.metadata_active", "resource.metadata_allocate", "resource.metadata_offer", "resource.slot_activation", "root.custody", "source.descriptor"]);
const MAILBOX_ACK_CONFIGURATION_ROLES=Object.freeze(['ack.root_authority','ack.write_grant','bootstrap.ack_offer','historical.status.ack_root','historical.status.ack_write','historical.status.ack_offer_bootstrap']);
const MAILBOX_FEED_ROLES=Object.freeze(["bootstrap.mailbox_feed", "contact.decision", "contact.delivery_lease", "contact.knock_lease", "contact.policy", "contact.request", "contact.store_grant", "current.status.bootstrap", "current.status.disclosure", "current.status.maintenance", "current.status.metadata_resource", "current.status.read", "current.status.slot", "delivery.attempt", "delivery.destination", "feed.checkpoint", "feed.custody", "feed.head", "historical.status.bootstrap", "historical.status.data_resource", "historical.status.destination", "historical.status.disclosure", "historical.status.maintenance", "historical.status.metadata_resource", "historical.status.read", "historical.status.slot", "history.mailbox_feed", "history.member", "mailbox.maintenance_root", "mailbox.read_grant", "mailbox.slot", "member.checkpoint", "member.core", "member.custody", "member.head", "member.link", "member.sealed_core", "message.disclosure", "range.index", "range.repair_page", "range.sealed_page", "resource.data_active", "resource.data_allocate", "resource.data_offer", "resource.metadata_active", "resource.metadata_allocate", "resource.metadata_offer", "resource.slot_activation", "source.descriptor"]);
const MAILBOX_ROOT_REPLICA_EXTRA=Object.freeze([...REPLICA_FIXED_ROLES.filter(role=>role.startsWith('copy.')||role.startsWith('replica.')||role.startsWith('return.')||role==='current.status.replica_read'),'replica.read_pack']);
const MAILBOX_ROOT_REPLICA_ROLES=Object.freeze([...MAILBOX_ROOT_ROLES.filter(role=>!role.startsWith('current.')),...MAILBOX_ROOT_REPLICA_EXTRA]);
const MAILBOX_FEED_REPLICA_EXTRA=Object.freeze([...MAILBOX_ROOT_REPLICA_EXTRA,'copy.sender_reservation_consent','copy.sender_disclosure','return.sender']);
const MAILBOX_FEED_REPLICA_ROLES=Object.freeze([...MAILBOX_FEED_ROLES.filter(role=>!role.startsWith('current.')),...MAILBOX_FEED_REPLICA_EXTRA]);
const CONSUMER_STATES=new Map<string,Map<string,{roles:readonly string[];minimumPacks:number}>>([
  ['ack_owner',SOURCE_STATES],['ack_offer',new Map([['empty',{roles:OFFER_FIXED_ROLES,minimumPacks:2}]])],['mailbox_root',new Map([['root',{roles:MAILBOX_ROOT_ROLES,minimumPacks:1}],['replica_root',{roles:MAILBOX_ROOT_REPLICA_ROLES,minimumPacks:1}]])],['mailbox_feed',new Map([['feed',{roles:MAILBOX_FEED_ROLES,minimumPacks:2}],['replica_feed',{roles:MAILBOX_FEED_REPLICA_ROLES,minimumPacks:2}]])]]);
export type BootstrapProofSourceState='replica_unbound'|'replica_empty'|'replica_occupied'|'unbound'|'empty'|'occupied'|'root'|'feed'|'replica_root'|'replica_feed';
const COMMON=['schema_version','kind','signing_key','issued_at','expires_at','subject','target','target_storage_epoch','purpose','consumer'];
const HANDLE=[...COMMON,'bootstrap_grant_sha256','handle_id','probe_ref','challenge_ref','answer_ref','service_generation','manifest_ref','child_count'];
const CHILD=[...COMMON,'request_id','probe_ref','handle_ref','manifest_ref','service_generation','child_index','offset','requested_bytes'];
const MANIFEST=['schema_version','kind','probe_ref','subject','target','target_storage_epoch','consumer','selector','bootstrap_grant_ref','service_generation','response_profile','children'];
const SELECTOR=['root_key_sha256','ack_slot_sha256','root_authority_sha256','read_grant_sha256'];
const MAILBOX_ROOT_SELECTOR=['root_key_sha256','anchor_ref','root_authority_sha256','read_grant_sha256'];
const MAILBOX_FEED_SELECTOR=['root_key_sha256','slot_key_sha256','feed_ref','slot_sha256','read_grant_sha256','maintenance_root_sha256'];
const OFFER_SELECTOR=['root_key_sha256','ack_slot_sha256','root_authority_sha256','write_grant_sha256'];
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
  readonly expectedSourceState?:BootstrapProofSourceState;
  readonly consumer?:BootstrapConsumer;
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
  const consumer=Object.hasOwn(args,'consumer')?args.consumer:'ack_owner';
  if(consumer!=='ack_owner'&&consumer!=='ack_offer'&&consumer!=='mailbox_root'&&consumer!=='mailbox_feed')fail('repair_invalid_probe');
  const value=buildNewWire(Object.fromEntries(EXPECTED.map(name=>[name,args[name]])),policy,budget).value as Obj;
  for(const name of ['bootstrapGrantRef','probeRef','challengeRef','answerRef'])meta(value[name]);
  dual(value.expectedSubject,budget);dual(value.expectedTarget,budget);u53(value.at);opaque(value.targetStorageEpoch);
  const selector=consumer==='ack_owner'?SELECTOR:consumer==='ack_offer'?OFFER_SELECTOR:consumer==='mailbox_root'?MAILBOX_ROOT_SELECTOR:MAILBOX_FEED_SELECTOR;
  fields(value.selector,selector);for(const name of selector){
    if(name==='anchor_ref'||name==='feed_ref'){const locator=fields(value.selector[name],['namespace','key']);if(locator.namespace!==(name==='anchor_ref'?'anchor':'feed'))fail();pattern(locator.key,/^[0-9a-f]{64}$/);}
    else pattern(value.selector[name],/^[0-9a-f]{64}$/);
  }return {...value,consumer};
}
function manifestShape(value:unknown,expected:Obj,maximumItems:number,expectedSourceState?:BootstrapProofSourceState):Obj{
  const m=fields(value,MANIFEST);if(m.response_profile!==expected.consumer+'_service_v1')mismatch();
  if(!Array.isArray(m.children)||m.children.length<1||m.children.length>maximumItems)fail();
  const roles=new Set<string>();for(const value of m.children){const item=fields(value,['index','role','ref']);
    if(typeof item.role!=='string')fail();if(item.role!=='history.raw_pack')roles.add(item.role);}
  const optional=expected.consumer==='mailbox_feed'?MAILBOX_ACK_CONFIGURATION_ROLES:[];
  if(optional.some(role=>roles.has(role))&&!optional.every(role=>roles.has(role)))fail();
  const requiredRoles=new Set([...roles].filter(role=>!optional.includes(role)));
  const states=[...CONSUMER_STATES.get(expected.consumer)!].filter(([,phase])=>phase.roles.length===requiredRoles.size&&phase.roles.every(role=>requiredRoles.has(role)));
  if(states.length!==1)fail();const [state,profile]=states[0];if(expectedSourceState!==undefined&&state!==expectedSourceState)mismatch();
  if(m.schema_version!==SCHEMA||m.kind!=='bootstrap.proof_manifest'||m.consumer!==expected.consumer||
      !same(m.subject,ids(expected.expectedSubject))||!same(m.target,ids(expected.expectedTarget))||m.target_storage_epoch!==expected.targetStorageEpoch||
      !same(m.selector,expected.selector)||!same(meta(m.bootstrap_grant_ref),meta(expected.bootstrapGrantRef))||!same(meta(m.probe_ref),meta(expected.probeRef)))mismatch();
  u53(m.service_generation,1);
  if(!Array.isArray(m.children)||m.children.length<profile.roles.length+profile.minimumPacks||m.children.length>maximumItems)fail();
  const counts=new Map<string,number>(),packs=new Set<string>(),identities=new Set<string>();
  for(const [index,value] of m.children.entries()){
    const item=fields(value,['index','role','ref']);
    if(u53(item.index)!==index||typeof item.role!=='string'||(item.role!=='history.raw_pack'&&!profile.roles.includes(item.role)&&!optional.includes(item.role)))fail();
    // The existing delivery receipt alone may retain its original object ref.
    const ref=item.role==='recipient.receipt'?rawRef(item.ref):meta(item.ref);counts.set(item.role,(counts.get(item.role)??0)+1);
    const identity=`${item.role}:${ref.namespace}:${ref.key}:${ref.raw_sha256}:${ref.size}`;
    if(identities.has(identity))fail();identities.add(identity);
    if(item.role==='history.raw_pack'){
      const identity=`${ref.namespace}:${ref.key}:${ref.raw_sha256}:${ref.size}`;
      if(packs.has(identity)||ref.key!==ref.raw_sha256)fail();packs.add(identity);
    }else if(item.role==='replica.read_pack'&&ref.key!==ref.raw_sha256)fail();
  }
  if(expected.consumer==='mailbox_root'){
    const singletons=['mailbox.root_authority','mailbox.root_read_grant','mailbox.catalog','bootstrap.mailbox_root',
      'resource.anchor_allocate','resource.anchor_offer','resource.anchor_activation','resource.anchor_active','source.descriptor','history.mailbox_root','root.custody'];
    if(state==='replica_root'){
      const repeated=['copy.current_status','current.status.replica_read'];
      singletons.push(...MAILBOX_ROOT_REPLICA_EXTRA.filter(role=>!repeated.includes(role)));
      if(repeated.some(role=>(counts.get(role)??0)<1||(counts.get(role)??0)>16))fail();
    }
    if(singletons.some(name=>counts.get(name)!==1)||profile.roles.some(name=>(counts.get(name)??0)<1))fail();
  }else if(expected.consumer==='mailbox_feed'){
    const singletons=['mailbox.slot','mailbox.read_grant','mailbox.maintenance_root','bootstrap.mailbox_feed','resource.data_allocate','resource.metadata_allocate','resource.data_offer','resource.metadata_offer','resource.slot_activation','resource.data_active','resource.metadata_active','feed.head','feed.checkpoint','history.mailbox_feed','feed.custody'];
    if(state==='replica_feed'){
      const repeated=['copy.current_status','current.status.replica_read'];
      singletons.push(...MAILBOX_FEED_REPLICA_EXTRA.filter(role=>!repeated.includes(role)));
      if(repeated.some(role=>(counts.get(role)??0)<1||(counts.get(role)??0)>16))fail();
    }
    if(singletons.some(name=>counts.get(name)!==1)||profile.roles.some(name=>(counts.get(name)??0)<1))fail();
  }else if(state==='replica_unbound'||state==='replica_empty'||state==='replica_occupied'){
    const repeated=['copy.current_status','current.status.replica_read'];
    const historical=state==='replica_occupied'?REPLICA_OCCUPIED_REPEATED:new Map((state==='replica_empty'?REPLICA_EMPTY_REPEATED:[]).map(role=>[role,2]));
    if(profile.roles.filter(name=>!repeated.includes(name)&&!historical.has(name)).some(name=>counts.get(name)!==1)||
      repeated.some(name=>(counts.get(name)??0)<1||(counts.get(name)??0)>16)||
      [...historical].some(([name,maximum])=>(counts.get(name)??0)<1||(counts.get(name)??0)>maximum))fail();
  }else if(profile.roles.some(name=>counts.get(name)!==1))fail();
  if(packs.size<profile.minimumPacks)fail();return m;
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
    bootstrapGrantRef:body.bootstrap_grant_ref,probeRef:args.probeRef,challengeRef:args.challengeRef,answerRef:args.answerRef,at:args.at,consumer:body.consumer},policy,budget);
  manifestShape(body,e,policy.max_entries);opaque(args.handleId);
  const bytes=manifest.raw,digest=budget.hash(bytes),ref=meta({namespace:'meta',key:digest,raw_sha256:digest,size:bytes.length});
  const payload={schema_version:SCHEMA,kind:'bootstrap.proof_handle',signing_key:e.expectedTarget.signing_key,issued_at:e.at,expires_at:u53(args.expiresAt),
    handle_id:args.handleId,probe_ref:e.probeRef,challenge_ref:e.challengeRef,answer_ref:e.answerRef,subject:body.subject,target:body.target,
    target_storage_epoch:body.target_storage_epoch,purpose:'bootstrap.service_proof',consumer:body.consumer,bootstrap_grant_sha256:body.bootstrap_grant_ref.raw_sha256,
    service_generation:body.service_generation,manifest_ref:ref,child_count:body.children.length};
  window(payload,e.at);const handle=signBoundedBootstrapOriginal(payload,signer,policy,budget);
  const response=buildNewWire({schema_version:SCHEMA,kind:'bootstrap.proof_response',handle_raw_base64url:encode(handle.raw,budget),manifest_raw_base64url:encode(bytes,budget)},policy,budget);
  if(response.raw.length>MAX_RESPONSE)fail('repair_proof_too_large');return response;
}
export function verifyBootstrapProofResponse(raw:Uint8Array,options:BootstrapProofOptions):AuthenticatedBootstrapProof{
  if(options===null||typeof options!=='object'||isProxy(options))fail();
  const args=fields(options,[...EXPECTED,'maxProofItems','maxProofBytes','policy','budget',...['expectedSourceState','consumer'].filter(name=>Object.hasOwn(options,name))]),policy=args.policy as RepairPolicy,budget=args.budget as RepairBudget;
  const sourceState=Object.hasOwn(args,'expectedSourceState')?args.expectedSourceState:'unbound';
  const consumer=Object.hasOwn(args,'consumer')?args.consumer:'ack_owner';
  if(typeof consumer!=='string'||typeof sourceState!=='string'||!CONSUMER_STATES.get(consumer)?.has(sourceState))fail();
  const maximumItems=u53(args.maxProofItems,1),maximumBytes=u53(args.maxProofBytes,1);
  if(!isUint8Array(raw))fail();const inputSize=Reflect.apply(byteLength,raw,[]) as number;
  if(inputSize>Math.min(MAX_RESPONSE,maximumBytes))fail('repair_proof_too_large');
  const e=expected(args,policy,budget),response=parseNewWire(raw,policy,budget),wrapper=fields(response.value,['schema_version','kind','handle_raw_base64url','manifest_raw_base64url']);
  if(wrapper.schema_version!==SCHEMA||wrapper.kind!=='bootstrap.proof_response')fail();
  const hs=decodedSize(wrapper.handle_raw_base64url),ms=decodedSize(wrapper.manifest_raw_base64url);
  if(inputSize+hs+ms>maximumBytes)fail('repair_proof_too_large');
  const h=parsed(decode(wrapper.handle_raw_base64url,hs,budget),policy,budget),signed=fields(h.document.value,['payload','proof']),payload=fields(signed.payload,HANDLE);
  window(payload,e.at);opaque(payload.handle_id);
  if(payload.schema_version!==SCHEMA||payload.kind!=='bootstrap.proof_handle'||payload.purpose!=='bootstrap.service_proof'||payload.consumer!==consumer||
      !same(payload.subject,ids(e.expectedSubject))||!same(payload.target,ids(e.expectedTarget))||payload.target_storage_epoch!==e.targetStorageEpoch||
      payload.bootstrap_grant_sha256!==e.bootstrapGrantRef.raw_sha256||['probe_ref','challenge_ref','answer_ref'].some((name,index)=>!same(meta(payload[name]),meta(e[['probeRef','challengeRef','answerRef'][index]]))))mismatch();
  verifyBoundedControlSignature(payload,signed.proof,e.expectedTarget.signing_key,budget);
  const manifestRef=meta(payload.manifest_ref),m=parsed(decode(wrapper.manifest_raw_base64url,ms,budget),policy,budget);
  if(m.ref.raw_sha256!==manifestRef.raw_sha256||m.ref.size!==manifestRef.size)fail('repair_ref_mismatch');
  const body=manifestShape(m.document.value,e,maximumItems,sourceState as BootstrapProofSourceState);
  if(u53(payload.child_count)!==body.children.length||u53(payload.service_generation,1)!==body.service_generation)mismatch();
  const result=Object.freeze({handle:held(h.document.raw,h.ref,payload,budget),manifest:m.document,manifest_ref:manifestRef});proofBrand.add(result);return result;
}
function childRange(payload:Obj,children:readonly Obj[]):void{
  const index=u53(payload.child_index),offset=u53(payload.offset),size=u53(payload.requested_bytes,1);
  if(index>=children.length||size>MAX_CHILD||offset>children[index].ref.size-size)fail('repair_invalid_range');
}
function makeChildRequest(signer:unknown,value:AuthenticatedBootstrapProof,options:{subject:unknown;target:unknown;at:number;expiresAt:number;
  childIndex:number;offset:number;requestedBytes:number;policy:RepairPolicy;budget:RepairBudget},envelopeRef?:unknown):AuthenticatedRepairOriginal{
  const args=fields(options,['subject','target','at','expiresAt','childIndex','offset','requestedBytes','policy','budget']),policy=args.policy as RepairPolicy,budget=args.budget as RepairBudget;
  const {proof,subject,target,at}=childParents(value,args.subject,args.target,args.at,policy,budget),handle=proof.handle.payload as Obj;
  budget.output(16);const token=randomBytes(16);budget.output(38);const requestId='child_'+token.toString('hex');
  const payload:Obj={schema_version:SCHEMA,kind:'bootstrap.proof_child_request',signing_key:subject.signing_key,issued_at:at,expires_at:u53(args.expiresAt),request_id:requestId,
    subject:ids(subject),target:ids(target),target_storage_epoch:handle.target_storage_epoch,purpose:'bootstrap.service_proof_child',consumer:handle.consumer,probe_ref:handle.probe_ref,
    handle_ref:proof.handle.ref,manifest_ref:proof.manifest_ref,service_generation:handle.service_generation,child_index:args.childIndex,offset:args.offset,requested_bytes:args.requestedBytes};
  if(envelopeRef!==undefined){payload.kind='mailbox.body_read';payload.purpose='mailbox.message_body';payload.envelope_ref=envelopeRef;
    bodyRange(payload,(proof.manifest.value as Obj).children);}
  else childRange(payload,(proof.manifest.value as Obj).children);
  window(payload,at);
  if(payload.issued_at<handle.issued_at||payload.expires_at>handle.expires_at)mismatch();
  return signBoundedBootstrapOriginal(payload,signer,policy,budget);
}
function verifyChildRequest(entry:unknown,value:AuthenticatedBootstrapProof,options:{expectedSubject:unknown;expectedTarget:unknown;at:number;policy:RepairPolicy;budget:RepairBudget},body=false):AuthenticatedRepairOriginal{
  const args=fields(options,['expectedSubject','expectedTarget','at','policy','budget']),policy=args.policy as RepairPolicy,budget=args.budget as RepairBudget;
  const {proof,subject,target,at}=childParents(value,args.expectedSubject,args.expectedTarget,args.at,policy,budget),input=fields(entry,['raw','ref']),ref=meta(input.ref);
  if(!isUint8Array(input.raw)||Reflect.apply(byteLength,input.raw,[])>MAX_RESPONSE)fail();
  const document=parseNewWire(input.raw,policy,budget),raw=document.raw;
  if(raw.length!==ref.size||budget.hash(raw)!==ref.raw_sha256)fail('repair_ref_mismatch');
  const signed=fields(document.value,['payload','proof']),payload=fields(signed.payload,body?[...CHILD,'envelope_ref']:CHILD),handle=proof.handle.payload as Obj;
  window(payload,at);opaque(payload.request_id);
  if(payload.schema_version!==SCHEMA||payload.kind!==(body?'mailbox.body_read':'bootstrap.proof_child_request')||payload.purpose!==(body?'mailbox.message_body':'bootstrap.service_proof_child')||payload.consumer!==handle.consumer||
      !same(payload.subject,ids(subject))||!same(payload.target,ids(target))||payload.target_storage_epoch!==handle.target_storage_epoch||
      !same(meta(payload.handle_ref),proof.handle.ref)||!same(meta(payload.manifest_ref),proof.manifest_ref)||!same(meta(payload.probe_ref),meta(handle.probe_ref))||
      payload.service_generation!==handle.service_generation||payload.issued_at<handle.issued_at||payload.expires_at>handle.expires_at)mismatch();
  (body?bodyRange:childRange)(payload,(proof.manifest.value as Obj).children);verifyBoundedControlSignature(payload,signed.proof,subject.signing_key,budget);return held(raw,ref,payload,budget);
}

function bodyRange(payload:Obj,children:readonly Obj[]):void{
  const index=u53(payload.child_index),offset=u53(payload.offset),size=u53(payload.requested_bytes,1),ref=rawRef(payload.envelope_ref);
  if(payload.consumer!=='mailbox_feed'||index>=children.length||children[index].role!=='member.core'||ref.namespace!=='object'||
      ref.size>6*1024*1024||size>MAX_CHILD||offset>ref.size-size)fail('repair_invalid_range');
}
export function makeBootstrapChildRequest(signer:unknown,value:AuthenticatedBootstrapProof,options:Parameters<typeof makeChildRequest>[2]):AuthenticatedRepairOriginal{
  return makeChildRequest(signer,value,options);
}
export function makeMailboxBodyRequest(signer:unknown,value:AuthenticatedBootstrapProof,envelopeRef:unknown,
    options:Parameters<typeof makeChildRequest>[2]):AuthenticatedRepairOriginal{
  return makeChildRequest(signer,value,options,envelopeRef);
}
export function verifyBootstrapChildRequest(entry:unknown,value:AuthenticatedBootstrapProof,
    options:Parameters<typeof verifyChildRequest>[2]):AuthenticatedRepairOriginal{
  return verifyChildRequest(entry,value,options);
}
export function verifyMailboxBodyRequest(entry:unknown,value:AuthenticatedBootstrapProof,
    options:Parameters<typeof verifyChildRequest>[2]):AuthenticatedRepairOriginal{
  return verifyChildRequest(entry,value,options,true);
}
