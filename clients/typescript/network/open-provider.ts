/** Native opaque provider controls and finite owner-authorized node resources.
 * Advertisements do not grant object reads, prove custody or open a Vault.
 * Wire fields and validity boundaries match memory_vault_open_provider.py.
 */
import {randomBytes,timingSafeEqual} from 'node:crypto';
import {
  NetworkCryptoError,canonicalBytes,document,documentSha256,objectFields,
  safeInteger,opaqueId,digestHex,signingKeyId,sha256,validateSigningPublic,validateSigningIdentity,
  validateEncryptionPublic,validateEncryptionIdentity,signMessage,verifyMessage,
  validateJwe,encryptBytes,decryptBytes,decodeBase64url,encodeBase64url,
} from './crypto.ts';
import type {DocumentInput,SigningIdentityDocument,EncryptionIdentityDocument} from './crypto.ts';
import {verifyNode} from './open-control.ts';
import type {SignedNode,SignedOpen} from './open-control.ts';

export const PROFILE='memory-vault-open-provider/v1';
export const MAX_CONTROL_BYTES=65536,MAX_SECONDS=604800,MAX_FACT_SECONDS=600,MAX_STATUS_BYTES=16384;
export const PUBLISH=16;
export const OPERATIONS={admit:1,read:2,copy:4,discover:8,publish:PUBLISH,renew:32,retain:64} as const;
export const ALL_OPERATIONS=Object.values(OPERATIONS).reduce((total,value)=>total+value,0);
export const BUDGET_LIMITS={max_live_bytes:64*1024*1024,max_meta_bytes:64*1024*1024,
  max_items:1024,max_requests:4096,max_pending:128,max_replay_records:4096,max_jobs:1024,max_job_bytes:4*1024*1024} as const;
export const WINDOWS=['admit_until','read_until','copy_until','publish_until','retain_until'] as const;
export const COMMON=['schema_version','kind','signing_key','issued_at','expires_at'] as const;
export const KINDS:Readonly<Record<string,readonly string[]>>={
  'provider.fact':['ref','storage_epoch','custody_id','revision','status'],
  'provider.target':['node_key_id','storage_epoch','targetEncryptionKey'],
  'provider.target.challenge':['challenge_id','target_sha256','node_key_id','storage_epoch','jwe'],
  'provider.target.answer':['challenge_sha256','target_sha256','requester_key_id','node_key_id','storage_epoch','answer'],
  'root.resource.intent':['allocation_id','root_key','subject','node_key_id','storage_epoch','purpose','budget','windows'],
  'root.resource.lease':['allocation_id','intent_sha256','root_key','subject','resource','targetEncryptionKey','reservation_generation','purpose','budget','windows'],
  'provider.publication.grant':['root_key','resource','resource_lease_sha256','publisher','ref','grant_id','revision','operation_mask','maximum_fact_seconds'],
  'provider.index_lease':['node_key_id','storage_epoch','index_lease_id','fact_sha256','ref','provider_key_id','provider_storage_epoch','custody_id'],
  'provider.rpc':['request_id','node_key_id','storage_epoch','action','body'],
  'provider.response':['request_id','request_sha256','node_key_id','storage_epoch','body'],
};
export const ACTIONS:Readonly<Record<string,readonly string[]>>={
  'target.get':[],'target.answer':['target','challenge'],
  'resource.allocate':['intent'],'resource.revoke':['lease_id'],
  'provider.put':['fact','provider_node','publication_grant','resource_lease','owner_status','allocation_id','lease_seconds'],
  'provider.get':['ref','after','limit','maximum_bytes'],
  'provider.withdraw':['fact'],'provider.status':['status'],'provider.result':['allocation_id','operation'],
};
export const CAPS:Readonly<Record<string,number>>={
  'provider.fact':2048,'provider.index_lease':2048,'provider.target':4096,
  'provider.target.challenge':8192,'provider.target.answer':4096,
  'root.resource.intent':8192,'root.resource.lease':8192,'provider.publication.grant':8192,
};
type Obj=Record<string,any>;
export interface ProviderOptions {now?:number;allow_expired?:boolean;}
export interface NodeOptions extends ProviderOptions {node:SignedNode;}
export class ProviderError extends NetworkCryptoError {
  readonly retryable:boolean;
  constructor(code:string,retryable=false){super(code);this.name='ProviderError';this.retryable=retryable;}
}
export function fail(code:string):never{throw new ProviderError(code);}
const input=(value:unknown)=>value as DocumentInput;
const same=(left:unknown,right:unknown)=>Buffer.from(canonicalBytes(left)).equals(Buffer.from(canonicalBytes(right)));
export function nowValue(now?:number):number{return now===undefined?Math.floor(Date.now()/1000):safeInteger(now);}
export function fields(value:unknown,expected:readonly string[]):Obj{return objectFields(value,expected,'provider_invalid_document');}
export function choice(value:unknown,values:readonly string[]|Readonly<Record<string,unknown>>):string{
  if(typeof value!=='string'||!(Array.isArray(values)?values.includes(value):Object.hasOwn(values,value)))fail('provider_invalid_enum');
  return value;
}
export function keyId(value:unknown,prefix='ed25519'):string{
  if(typeof value!=='string'||new RegExp('^'+prefix+'_[0-9a-f]{64}$').exec(value)?.[0]!==value)fail('provider_invalid_key');
  return value;
}
export function bounded(value:unknown,maximum:number,minimum=1):number{
  const result=safeInteger(value,minimum);if(result>maximum)fail('provider_invalid_limit');return result;
}
export function dualId(value:unknown):Obj{
  const raw=fields(value,['signing_key_id','encryption_key_id']);keyId(raw.signing_key_id);keyId(raw.encryption_key_id,'x25519');return raw;
}
export function dualKey(value:unknown):Obj{
  const raw=fields(value,['signing_key','encryption_key']);validateSigningPublic(raw.signing_key);validateEncryptionPublic(raw.encryption_key);return raw;
}
export function asDual(value:unknown):Obj{
  const raw=dualKey(value);return {signing_key_id:raw.signing_key.key_id,encryption_key_id:raw.encryption_key.key_id};
}
export function opaqueRef(value:unknown,namespaces:readonly string[]=['anchor','feed','meta','object']):Obj{
  const raw=fields(value,['namespace','key']);choice(raw.namespace,namespaces);digestHex(raw.key);return raw;
}
export function rootKey(value:unknown):Obj{
  const raw=fields(value,['owner','root_kind','anchor_ref','owner_epoch','root_id']);dualId(raw.owner);choice(raw.root_kind,['mailbox','ack_return']);
  opaqueRef(raw.anchor_ref,['anchor']);opaqueId(raw.owner_epoch);opaqueId(raw.root_id);return raw;
}
export function resourceRef(value:unknown):Obj{
  const raw=fields(value,['node_key_id','storage_epoch','lease_id','resource_id']);keyId(raw.node_key_id);
  for(const name of ['storage_epoch','lease_id','resource_id'])opaqueId(raw[name]);return raw;
}
export function routeTarget(ref:unknown):string{
  const raw=opaqueRef(ref);return sha256(Buffer.concat([Buffer.from('memory-vault-open-provider-key/v1\0'+raw.namespace+'\0','ascii'),Buffer.from(raw.key,'hex')]));
}
export function authorityScope(root:unknown,authorityKind:string,authoritySha256:string):string{
  rootKey(root);choice(authorityKind,['provider.publication.grant','mailbox.slot','mailbox.read_grant','maintenance.root',
    'root.authority','root.read_grant','ack.slot.grant','ack.read.grant','ack.maintenance.root','message.disclosure','contact.grant','delivery.destination']);
  digestHex(authoritySha256);return documentSha256({kind:'authority',root_key:root,authority_kind:authorityKind,authority_sha256:authoritySha256} as DocumentInput);
}
export function resourceScope(root:unknown,resource:unknown):string{
  rootKey(root);resourceRef(resource);return documentSha256({kind:'resource',root_key:root,resource} as DocumentInput);
}
function window(raw:Obj,maximum:number,options:ProviderOptions):void{
  const issued=safeInteger(raw.issued_at),expires=safeInteger(raw.expires_at);
  if(expires-issued<1||expires-issued>maximum)fail('network_invalid_validity');
  const current=nowValue(options.now);if(issued>current+30)fail('network_control_from_future');
  if(!options.allow_expired&&expires<=current)fail('network_control_expired');
}
function budget(raw:Obj):void{
  const limits=fields(raw.budget,Object.keys(BUDGET_LIMITS));
  for(const [name,ceiling] of Object.entries(BUDGET_LIMITS))bounded(limits[name],ceiling,0);
  if(!limits.max_meta_bytes||!limits.max_items||!limits.max_requests||!limits.max_replay_records)fail('provider_invalid_budget');
  choice(raw.purpose,['anchor_catalog','feed_metadata','ack_slot','provider_index']);
  if(['anchor_catalog','feed_metadata','provider_index'].includes(raw.purpose)&&limits.max_live_bytes!==0)fail('provider_invalid_budget');
  if(raw.purpose==='ack_slot'&&raw.root_key.root_kind!=='ack_return')fail('provider_wrong_root');
  const windows=fields(raw.windows,WINDOWS);
  for(const value of Object.values(windows)){
    safeInteger(value);if(!(raw.issued_at<value&&value<=raw.expires_at))fail('provider_invalid_window');
  }
  if(Object.values(windows).some(value=>value>windows.retain_until))fail('provider_invalid_window');
}
function signed(payload:Obj,signer:SigningIdentityDocument):SignedOpen{
  const checked=document(input(payload),MAX_CONTROL_BYTES);return {payload:checked,proof:signMessage(input(checked),signer)};
}
function proof(value:Obj,signing:Obj):void{
  // Match the core Python proof boundary before the native primitive checks
  // signer membership; malformed proofs must not be reported as trust misses.
  const supplied=objectFields(value.proof,['schema_version','key_id','payload_sha256','signature'],'invalid_signature_proof');
  if(supplied.schema_version!=='universal-memory-message-signature/v1')fail('unsupported_signature_schema');
  signingKeyId(supplied.key_id);
  try{digestHex(supplied.payload_sha256);}catch(error){
    if((error as any)?.code==='network_invalid_digest')fail('invalid_signature_digest');throw error;
  }
  if(supplied.payload_sha256!==documentSha256(input(value.payload)))fail('signature_digest_mismatch');
  const signature=supplied.signature;
  if(typeof signature!=='string'||signature.length!==88)fail('invalid_signature');
  const decoded=Buffer.from(signature,'base64');
  if(decoded.length!==64||decoded.toString('base64')!==signature)fail('invalid_signature');
  try{verifyMessage(input(value.payload),input(value.proof),[signing as any]);}
  catch(error){if((error as any)?.code==='invalid_signature')fail('signature_invalid');throw error;}
}
export function verifyStatus(value:unknown,options:ProviderOptions={}):Obj{
  const signed=fields(document(input(value),MAX_STATUS_BYTES),['payload','proof']);
  const raw=fields(signed.payload,['schema_version','kind','signing_key','scope_key','revision','issued_at','valid_until','entries']);
  if(raw.schema_version!=='memory-vault-open-authority/v1'||raw.kind!=='authority.status')fail('provider_invalid_status');
  const signing=validateSigningPublic(raw.signing_key),scope=fields(raw.scope_key,['root_key','issuer_key_id']);rootKey(scope.root_key);
  if(scope.issuer_key_id!==signing.key_id)fail('provider_wrong_issuer');safeInteger(raw.revision,1);
  window({issued_at:raw.issued_at,expires_at:raw.valid_until},MAX_SECONDS,options);
  if(!Array.isArray(raw.entries)||raw.entries.length<1||raw.entries.length>16)fail('provider_invalid_status');
  let previous:[string,string]|undefined;
  for(const entry of raw.entries){
    const item=fields(entry,['scope_kind','scope_id','minimum_document_revision','status','operation_mask']);
    choice(item.scope_kind,['catalog','mailbox_slot','ack_slot','authority','resource','assignment','contact_policy']);
    digestHex(item.scope_id);safeInteger(item.minimum_document_revision);choice(item.status,['active','revoked']);bounded(item.operation_mask,ALL_OPERATIONS);
    if(previous&&(item.scope_kind<previous[0]||(item.scope_kind===previous[0]&&item.scope_id<=previous[1])))fail('provider_invalid_status');
    previous=[item.scope_kind,item.scope_id];
  }
  proof(signed,signing);return raw;
}
export function issueStatus(signer:SigningIdentityDocument,options:{root:unknown;revision:number;entries:unknown[];issued_at:number;valid_until:number}):SignedOpen{
  const signing=validateSigningIdentity(signer),result=signed({schema_version:'memory-vault-open-authority/v1',kind:'authority.status',signing_key:signing,
    scope_key:{root_key:options.root,issuer_key_id:signing.key_id},revision:options.revision,issued_at:options.issued_at,
    valid_until:options.valid_until,entries:options.entries},signer);verifyStatus(result,{now:options.issued_at});return result;
}
export function verifyDocument(value:unknown,kind:string,options:ProviderOptions={}):Obj{
  choice(kind,KINDS);const signed=fields(document(input(value),CAPS[kind]??MAX_CONTROL_BYTES),['payload','proof']);
  const raw=fields(signed.payload,[...COMMON,...KINDS[kind]]);
  if(raw.schema_version!==PROFILE||raw.kind!==kind)fail('provider_unsupported_document');validateSigningPublic(raw.signing_key);
  let maximum=['provider.fact','provider.index_lease','provider.target'].includes(kind)?MAX_FACT_SECONDS:MAX_SECONDS;
  if(['provider.rpc','provider.response','provider.target.challenge','provider.target.answer'].includes(kind))maximum=60;
  window(raw,maximum,options);
  if(kind==='provider.fact'){
    opaqueRef(raw.ref);opaqueId(raw.storage_epoch);opaqueId(raw.custody_id);safeInteger(raw.revision,1);choice(raw.status,['active','withdrawn']);
  }else if(kind==='provider.target'){
    keyId(raw.node_key_id);opaqueId(raw.storage_epoch);validateEncryptionPublic(raw.targetEncryptionKey);
    if(raw.node_key_id!==raw.signing_key.key_id)fail('provider_wrong_node');
  }else if(kind.startsWith('provider.target.')){
    keyId(raw.node_key_id);opaqueId(raw.storage_epoch);digestHex(raw.target_sha256);
    if(kind.endsWith('challenge')){opaqueId(raw.challenge_id);validateJwe(raw.jwe,{context:Object.fromEntries(Object.entries(raw).filter(([key])=>key!=='jwe')) as DocumentInput});}
    else{digestHex(raw.challenge_sha256);keyId(raw.requester_key_id);decodeBase64url(raw.answer,32,32);
      if(raw.node_key_id!==raw.signing_key.key_id)fail('provider_wrong_node');}
  }else if(kind==='root.resource.intent'||kind==='root.resource.lease'){
    rootKey(raw.root_key);opaqueId(raw.allocation_id);budget(raw);
    if(kind.endsWith('intent')){
      dualKey(raw.subject);keyId(raw.node_key_id);opaqueId(raw.storage_epoch);
      if(!same(asDual(raw.subject),raw.root_key.owner)||!same(raw.subject.signing_key,raw.signing_key))fail('provider_wrong_owner');
    }else{
      dualId(raw.subject);resourceRef(raw.resource);digestHex(raw.intent_sha256);validateEncryptionPublic(raw.targetEncryptionKey);safeInteger(raw.reservation_generation,1);
      if(raw.resource.node_key_id!==raw.signing_key.key_id||!same(raw.subject,raw.root_key.owner))fail('provider_wrong_owner');
    }
  }else if(kind==='provider.publication.grant'){
    rootKey(raw.root_key);resourceRef(raw.resource);dualId(raw.publisher);opaqueRef(raw.ref);digestHex(raw.resource_lease_sha256);opaqueId(raw.grant_id);safeInteger(raw.revision,1);
    if(raw.operation_mask!==PUBLISH)fail('provider_wrong_operation');bounded(raw.maximum_fact_seconds,MAX_FACT_SECONDS);
    if(raw.signing_key.key_id!==raw.root_key.owner.signing_key_id)fail('provider_wrong_owner');
  }else if(kind==='provider.index_lease'){
    for(const name of ['node_key_id','provider_key_id'])keyId(raw[name]);
    for(const name of ['storage_epoch','provider_storage_epoch','index_lease_id','custody_id'])opaqueId(raw[name]);
    digestHex(raw.fact_sha256);opaqueRef(raw.ref);if(raw.node_key_id!==raw.signing_key.key_id)fail('provider_wrong_node');
  }else if(kind==='provider.rpc'||kind==='provider.response'){
    opaqueId(raw.request_id);keyId(raw.node_key_id);opaqueId(raw.storage_epoch);
    if(kind.endsWith('rpc'))requestBody(raw.action,raw.body,options.now);
    else{digestHex(raw.request_sha256);if(raw.body===null||typeof raw.body!=='object'||Array.isArray(raw.body))fail('provider_invalid_document');}
  }
  proof(signed,raw.signing_key);return raw;
}
export function signDocument(signer:SigningIdentityDocument,kind:string,options:{issued_at:number;expires_at:number;[name:string]:any}):SignedOpen{
  const result=signed({schema_version:PROFILE,kind,signing_key:validateSigningIdentity(signer),...options},signer);
  verifyDocument(result,kind,{now:options.issued_at});return result;
}
function requestBody(action:unknown,value:unknown,now?:number):Obj{
  const name=choice(action,ACTIONS),raw=fields(value,ACTIONS[name]);
  if(name==='target.answer'){verifyDocument(raw.target,'provider.target',{now});verifyDocument(raw.challenge,'provider.target.challenge',{now});}
  else if(name==='resource.allocate')verifyDocument(raw.intent,'root.resource.intent',{now});
  else if(name==='resource.revoke')opaqueId(raw.lease_id);
  else if(name==='provider.put'){
    for(const [field,kind] of [['fact','provider.fact'],['publication_grant','provider.publication.grant'],['resource_lease','root.resource.lease']])verifyDocument(raw[field],kind,{now});
    verifyNode(raw.provider_node,{now});verifyStatus(raw.owner_status,{now});opaqueId(raw.allocation_id);bounded(raw.lease_seconds,MAX_FACT_SECONDS);
  }else if(name==='provider.get'){
    opaqueRef(raw.ref);bounded(raw.limit,4);bounded(raw.maximum_bytes,49152,4096);if(raw.after!==null)digestHex(raw.after);
  }else if(name==='provider.withdraw'){
    if(verifyDocument(raw.fact,'provider.fact',{now}).status!=='withdrawn')fail('provider_wrong_operation');
  }else if(name==='provider.status')verifyStatus(raw.status,{now});
  else if(name==='provider.result'){opaqueId(raw.allocation_id);choice(raw.operation,['resource.allocate','provider.put']);}
  return raw;
}
export function nodeBinding(raw:Obj,node:SignedNode,now?:number):Obj{
  const target=verifyNode(node,{now});
  if(target.status!=='active'||raw.node_key_id!==target.signing_key.key_id||raw.storage_epoch!==target.storage_epoch)fail('provider_wrong_node');
  return target;
}
export function signRpc(signer:SigningIdentityDocument,options:NodeOptions&{action:string;body:unknown;request_id?:string}):SignedOpen{
  const current=nowValue(options.now),target=verifyNode(options.node,{now:current});
  return signDocument(signer,'provider.rpc',{issued_at:current,expires_at:safeInteger(current+60),request_id:options.request_id||'rpc_'+randomBytes(32).toString('hex'),
    node_key_id:target.signing_key.key_id,storage_epoch:target.storage_epoch,action:options.action,body:options.body});
}
export function verifyRpc(value:unknown,options:NodeOptions):Obj{
  const raw=verifyDocument(value,'provider.rpc',{now:options.now});nodeBinding(raw,options.node,options.now);return raw;
}
export function signResponse(signer:SigningIdentityDocument,options:NodeOptions&{request:unknown;body:unknown}):SignedOpen{
  const current=nowValue(options.now),original=verifyRpc(options.request,{node:options.node,now:current});
  if(!same(validateSigningIdentity(signer),options.node.payload.signing_key))fail('provider_wrong_node');
  responseBody(options.body,{request:document(input(options.request)),node:options.node,now:current});
  return signDocument(signer,'provider.response',{issued_at:current,expires_at:Math.min(current+60,original.expires_at),
    request_id:original.request_id,request_sha256:documentSha256(input(options.request)),node_key_id:original.node_key_id,storage_epoch:original.storage_epoch,body:options.body});
}
export function verifyResponse(value:unknown,options:NodeOptions&{request:unknown}):Obj{
  const raw=verifyDocument(value,'provider.response',{now:options.now}),original=verifyRpc(options.request,options),target=nodeBinding(raw,options.node,options.now);
  if(!same(raw.signing_key,target.signing_key)||raw.request_id!==original.request_id||raw.request_sha256!==documentSha256(input(options.request))||raw.expires_at>original.expires_at)fail('provider_response_mismatch');
  responseBody(raw.body,{request:document(input(options.request)),node:options.node,now:options.now});
  if(original.action==='provider.get'&&canonicalBytes(document(input(value))).length>original.body.maximum_bytes)fail('provider_response_budget');return raw;
}
export function issueFact(signer:SigningIdentityDocument,options:{ref:unknown;storage_epoch:string;custody_id:string;revision:number;issued_at:number;expires_at:number;status?:string}):SignedOpen{
  return signDocument(signer,'provider.fact',{...options,status:options.status===undefined?'active':options.status});
}
/** Freeze inputs before JOSE yields; private grants follow a proven target. */
export async function makeTargetChallenge(signer:SigningIdentityDocument,options:NodeOptions&{target:unknown}):Promise<[SignedOpen,Uint8Array]>{
  const local=document(input(signer),4096) as unknown as SigningIdentityDocument;
  const target=document(input(options.target),CAPS['provider.target']),node=document(input(options.node),4096) as unknown as SignedNode;
  const current=nowValue(options.now),raw=verifyDocument(target,'provider.target',{now:current}),expected=nodeBinding(raw,node,current);
  if(!same(raw.signing_key,expected.signing_key))fail('provider_wrong_node');
  const context={schema_version:PROFILE,kind:'provider.target.challenge',signing_key:validateSigningIdentity(local),
    issued_at:current,expires_at:Math.min(current+60,raw.expires_at),challenge_id:'challenge_'+randomBytes(32).toString('hex'),
    target_sha256:documentSha256(input(target)),node_key_id:raw.node_key_id,storage_epoch:raw.storage_epoch};
  const nonce=randomBytes(32),jwe=await encryptBytes(nonce,[raw.targetEncryptionKey],{context});
  const challenge=signed({...context,jwe},local);verifyDocument(challenge,'provider.target.challenge',{now:current});return [challenge,nonce];
}
export async function answerTargetChallenge(signer:SigningIdentityDocument,encryptionIdentity:EncryptionIdentityDocument,
  options:NodeOptions&{target:unknown;challenge:unknown}):Promise<SignedOpen>{
  const local=document(input(signer),4096) as unknown as SigningIdentityDocument;
  const encryption=document(input(encryptionIdentity),4096) as unknown as EncryptionIdentityDocument;
  const target=document(input(options.target),CAPS['provider.target']),challenge=document(input(options.challenge),CAPS['provider.target.challenge']);
  const node=document(input(options.node),4096) as unknown as SignedNode,current=nowValue(options.now);
  const descriptor=verifyDocument(target,'provider.target',{now:current}),original=verifyDocument(challenge,'provider.target.challenge',{now:current});
  nodeBinding(descriptor,node,current);nodeBinding(original,node,current);
  if(!same(descriptor.signing_key,validateSigningIdentity(local))||!same(descriptor.targetEncryptionKey,validateEncryptionIdentity(encryption))||original.target_sha256!==documentSha256(input(target)))fail('provider_target_mismatch');
  const recipients=original.jwe.recipients;
  if(recipients.length!==1||recipients[0].header.kid!==descriptor.targetEncryptionKey.key_id)fail('provider_target_mismatch');
  const nonce=await decryptBytes(original.jwe,encryption,{context:Object.fromEntries(Object.entries(original).filter(([key])=>key!=='jwe')) as DocumentInput});
  if(nonce.length!==32)fail('provider_invalid_challenge');
  return signDocument(local,'provider.target.answer',{issued_at:current,expires_at:Math.min(current+60,original.expires_at),
    challenge_sha256:documentSha256(input(challenge)),target_sha256:documentSha256(input(target)),requester_key_id:original.signing_key.key_id,
    node_key_id:descriptor.node_key_id,storage_epoch:descriptor.storage_epoch,answer:encodeBase64url(nonce)});
}
export function verifyTargetAnswer(answer:unknown,options:NodeOptions&{target:unknown;challenge:unknown;nonce:Uint8Array}):Obj{
  const raw=verifyDocument(answer,'provider.target.answer',{now:options.now}),descriptor=verifyDocument(options.target,'provider.target',{now:options.now});
  const original=verifyDocument(options.challenge,'provider.target.challenge',{now:options.now}),expected=nodeBinding(raw,options.node,options.now);
  nodeBinding(descriptor,options.node,options.now);nodeBinding(original,options.node,options.now);
  if(!same(raw.signing_key,expected.signing_key)||!same(descriptor.signing_key,expected.signing_key)||raw.target_sha256!==documentSha256(input(options.target))||
    original.target_sha256!==documentSha256(input(options.target))||raw.challenge_sha256!==documentSha256(input(options.challenge))||raw.requester_key_id!==original.signing_key.key_id||
    raw.expires_at>original.expires_at||!(options.nonce instanceof Uint8Array)||options.nonce.length!==32||!timingSafeEqual(decodeBase64url(raw.answer,32,32),options.nonce))fail('provider_invalid_target_proof');
  return descriptor;
}
export function verifyResourceLease(value:unknown,options:ProviderOptions&{intent?:unknown;node?:SignedNode;target?:unknown}={}):Obj{
  const raw=verifyDocument(value,'root.resource.lease',options);
  if(options.node!=null){const expected=verifyNode(options.node,{now:options.now});
    if(!same(raw.signing_key,expected.signing_key)||raw.resource.storage_epoch!==expected.storage_epoch)fail('provider_wrong_resource');}
  if(options.target!=null){const proven=verifyDocument(options.target,'provider.target',{now:options.now});
    if(!same(raw.signing_key,proven.signing_key)||raw.resource.storage_epoch!==proven.storage_epoch||!same(raw.targetEncryptionKey,proven.targetEncryptionKey))fail('provider_target_mismatch');}
  if(options.intent!=null){const wanted=verifyDocument(options.intent,'root.resource.intent',options);
    if(raw.intent_sha256!==documentSha256(input(options.intent))||!same(raw.subject,asDual(wanted.subject))||raw.resource.node_key_id!==wanted.node_key_id||
      raw.resource.storage_epoch!==wanted.storage_epoch||raw.expires_at!==wanted.expires_at||raw.issued_at<wanted.issued_at||
      ['allocation_id','root_key','purpose','budget','windows'].some(key=>!same(raw[key],wanted[key])))fail('provider_lease_mismatch');}
  return raw;
}
export function verifyIndexLease(value:unknown,options:NodeOptions&{fact:unknown}):Obj{
  const raw=verifyDocument(value,'provider.index_lease',options),advertisement=verifyDocument(options.fact,'provider.fact',options),expected=nodeBinding(raw,options.node,options.now);
  if(!same(raw.signing_key,expected.signing_key)||raw.fact_sha256!==documentSha256(input(options.fact))||!same(raw.ref,advertisement.ref)||raw.provider_key_id!==advertisement.signing_key.key_id||
    raw.provider_storage_epoch!==advertisement.storage_epoch||raw.custody_id!==advertisement.custody_id||raw.expires_at>advertisement.expires_at)fail('provider_index_lease_mismatch');return raw;
}
function responseBody(body:unknown,options:{request:Obj;node:SignedNode;now?:number}):void{
  const original=options.request.payload,action=original.action,wanted=original.body,{node,now}=options;
  if(body!==null&&typeof body==='object'&&!Array.isArray(body)&&Object.keys(body).length===1&&Object.hasOwn(body,'error')){
    const error=fields((body as Obj).error,['code','retryable']);
    if(typeof error.code!=='string'||/^[a-z][a-z0-9_]{1,63}$/.exec(error.code)?.[0]!==error.code||typeof error.retryable!=='boolean')fail('provider_invalid_response');return;
  }
  if(action==='provider.get'){
    const raw=fields(body,['ref','observed_at','entries','nodes','next_cursor','state']);
    if(!same(raw.ref,wanted.ref)||!Array.isArray(raw.entries)||raw.entries.length>wanted.limit||!Array.isArray(raw.nodes)||raw.nodes.length>4)fail('provider_invalid_response');
    safeInteger(raw.observed_at);choice(raw.state,['observed','not_observed']);
    if((raw.state==='observed')!==(raw.entries.length>0))fail('provider_invalid_response');if(raw.next_cursor!==null)digestHex(raw.next_cursor);
    const nodes=new Set<string>();
    for(const record of raw.nodes){const candidate=verifyNode(record,{now}),key=JSON.stringify([candidate.signing_key.key_id,candidate.storage_epoch]);
      if(candidate.status!=='active'||nodes.has(key))fail('provider_invalid_candidates');nodes.add(key);}
    const keys:string[]=[];
    for(const entry of raw.entries){const item=fields(entry,['fact','index_lease']),fact=verifyDocument(item.fact,'provider.fact',{now});
      if(!same(fact.ref,wanted.ref)||fact.status!=='active'||!nodes.has(JSON.stringify([fact.signing_key.key_id,fact.storage_epoch])))fail('provider_invalid_candidates');
      verifyIndexLease(item.index_lease,{fact:item.fact,node,now});keys.push(documentSha256({ref:fact.ref,provider_key_id:fact.signing_key.key_id,storage_epoch:fact.storage_epoch,custody_id:fact.custody_id}));}
    if(keys.some((key,index)=>index>0&&key<=keys[index-1])||(keys.length>0&&(keys[0]<=(wanted.after||'')||raw.next_cursor!==keys[keys.length-1])))fail('provider_invalid_cursor');
    if(!keys.length&&raw.next_cursor!==null)fail('provider_invalid_cursor');
  }else if(action==='target.get'){
    const raw=fields(body,['target']),target=verifyDocument(raw.target,'provider.target',{now}),expected=nodeBinding(target,node,now);
    if(!same(target.signing_key,expected.signing_key))fail('provider_target_mismatch');
  }else if(action==='target.answer'){
    const raw=verifyDocument(fields(body,['answer']).answer,'provider.target.answer',{now}),expected=nodeBinding(raw,node,now);
    if(!same(raw.signing_key,expected.signing_key)||raw.challenge_sha256!==documentSha256(wanted.challenge)||raw.target_sha256!==documentSha256(wanted.target)||raw.requester_key_id!==original.signing_key.key_id)fail('provider_target_mismatch');
    // The caller must still verifyTargetAnswer against its retained nonce.
  }else if(action==='resource.allocate'||action==='provider.result'&&wanted.operation==='resource.allocate'){
    const raw=fields(body,['lease','status','current_state']);choice(raw.current_state,['active','expired','revoked']);
    const lease=verifyResourceLease(raw.lease,{intent:action==='resource.allocate'?wanted.intent:undefined,node,now,allow_expired:raw.current_state!=='active'});
    const status=verifyStatus(raw.status,{now,allow_expired:raw.current_state!=='active'});
    if(lease.subject.signing_key_id!==original.signing_key.key_id||!same(status.scope_key,{root_key:lease.root_key,issuer_key_id:lease.signing_key.key_id}))fail('provider_lease_mismatch');
    const expected=resourceScope(lease.root_key,lease.resource);
    if(status.entries.length!==1||status.entries[0].scope_kind!=='resource'||status.entries[0].scope_id!==expected)fail('provider_status_scope_mismatch');
    if(raw.current_state==='active'&&status.entries[0].status!=='active')fail('provider_resource_inactive');
  }else if(action==='provider.put'||action==='provider.result'){
    const bodyValue=fields(body,['index_lease','current_state']);choice(bodyValue.current_state,['active','expired','revoked','conflict','superseded']);
    const raw=verifyDocument(bodyValue.index_lease,'provider.index_lease',{now,allow_expired:bodyValue.current_state!=='active'}),expected=nodeBinding(raw,node,now);
    if(!same(raw.signing_key,expected.signing_key)||raw.provider_key_id!==original.signing_key.key_id)fail('provider_index_lease_mismatch');
    if(action==='provider.put'){
      verifyIndexLease(bodyValue.index_lease,{fact:wanted.fact,node,now,allow_expired:bodyValue.current_state!=='active'});
      if(raw.expires_at-raw.issued_at>wanted.lease_seconds)fail('provider_index_lease_mismatch');}
  }else if(action==='resource.revoke'){
    const raw=fields(body,['status','state']);choice(raw.state,['revoked']);const status=verifyStatus(raw.status,{now,allow_expired:true});
    if(!same(status.signing_key,node.payload.signing_key))fail('provider_wrong_issuer');
  }else{const raw=fields(body,['state']);choice(raw.state,action==='provider.withdraw'?['withdrawn']:['observed']);}
}
