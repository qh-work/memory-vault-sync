/** Strict first-contact controls. These documents never authorize Vault actions.
 * Directory leases do not authorize requests or delivery. A delivery grant must
 * name an actual finite reservation at its authenticated resource node. */
import { randomBytes } from 'node:crypto';
import {
  NetworkCryptoError, canonicalBytes, document, documentSha256, objectFields,
  safeInteger, opaqueId, digestHex, validateSigningPublic, validateSigningIdentity,
  validateEncryptionPublic, signMessage, verifyMessage, validateJwe, encryptBytes,
  decryptBytes, decodeBase64url, encodeBase64url, sha256,
} from './crypto.ts';
import type {DocumentInput, SigningIdentityDocument, EncryptionIdentityDocument} from './crypto.ts';
import {verifyNode} from './open-control.ts';
import type {SignedNode, SignedOpen} from './open-control.ts';

export const PROFILE = 'memory-vault-open-contact-control/v1';
export const MAX_REQUEST_BYTES = 4096;
export const MAX_DECISION_BYTES = 8192;
export const MAX_CONTROL_BYTES = 65536;
export const MAX_SECONDS = 86400;
export const CHALLENGE_SECONDS = 60;
export const SLOT_BYTES = MAX_REQUEST_BYTES + MAX_DECISION_BYTES + 512;
export const KINDS: Readonly<Record<string, readonly string[]>> = {
  'resource.lease': ['node_key_id','storage_epoch','owner_key_id','owner_encryption_key','lease_id','resource_id','purpose','max_items','max_bytes'],
  'contact.policy': ['node_key_id','storage_epoch','lease_id','lease_sha256','resource_id','encryption_key','revision','status','max_pending'],
  'contact.request': ['request_id','encryption_key','recipient_key_id','recipient_encryption_key_id','node_key_id','storage_epoch','lease_id','resource_id','policy_sha256','request_class'],
  'contact.challenge': ['request_id','request_sha256','subject_key_id','subject_encryption_key_id','recipient_key_id','node_key_id','storage_epoch','policy_sha256','purpose','challenge_id','jwe'],
  'contact.grant': ['request_id','request_sha256','subject_key_id','subject_encryption_key_id','recipient_encryption_key_id','node_key_id','storage_epoch','resource_id','operations','resource_lease'],
  'contact.decision': ['request_id','request_sha256','subject_key_id','subject_encryption_key_id','recipient_encryption_key_id','node_key_id','storage_epoch','policy_sha256','decision','reason','grant'],
  'contact.rpc': ['request_id','node_key_id','storage_epoch','action','body'],
  'contact.response': ['request_id','request_sha256','node_key_id','storage_epoch','body'],
};
export const COMMON = ['schema_version','kind','signing_key','issued_at','expires_at'] as const;
export const ACTIONS: Readonly<Record<string, readonly string[]>> = {
  lease: ['encryption_key','purpose','max_items','max_bytes','lease_seconds','allocation_id'],
  'policy.put': ['lease','policy'], 'policy.get': ['recipient_key_id'],
  challenge: ['request','purpose'], submit: ['request','challenge','answer'],
  poll: ['lease_id'], decide: ['request','decision'], result: ['request','challenge','answer'],
};
type Obj = Record<string, any>;
export interface ContactOptions {now?:number;}
export interface NodeOptions extends ContactOptions {node:SignedNode;}
export interface PolicyOptions extends NodeOptions {lease:unknown;}
export interface RequestOptions extends PolicyOptions {policy:unknown;}
export interface ChallengeOptions extends NodeOptions {request:unknown;purpose:string;}
export interface DecisionOptions extends RequestOptions {request:unknown;}
export class ContactError extends NetworkCryptoError {
  readonly retryable:boolean;
  constructor(code:string,retryable=false) {super(code);this.name='ContactError';this.retryable=retryable;}
}
export function fail(code:string):never {throw new ContactError(code);}
export function currentTime(now?:number):number {return now===undefined?Math.floor(Date.now()/1000):safeInteger(now);}
export function fields(value:unknown,names:readonly string[]):Obj {
  return objectFields(value,names,'contact_invalid_document');
}
export function key(value:unknown,prefix='ed25519'):string {
  if(typeof value!=='string'||new RegExp('^'+prefix+'_[0-9a-f]{64}$').exec(value)?.[0]!==value)fail('contact_invalid_key');
  return value;
}
export function oneOf(value:unknown,choices:readonly string[]):string {
  if(typeof value!=='string'||!choices.includes(value))fail('contact_invalid_enum');
  return value;
}
export function limit(value:unknown,maximum:number,minimum=1):number {
  const checked=safeInteger(value,minimum);if(checked>maximum)fail('contact_invalid_limit');return checked;
}
function same(left:unknown,right:unknown):boolean {
  return Buffer.from(canonicalBytes(left)).equals(Buffer.from(canonicalBytes(right)));
}
function limits(raw:Obj):void {
  oneOf(raw.purpose,['knock','delivery']);limit(raw.max_items,32);limit(raw.max_bytes,16*1024*1024);
  if(raw.purpose==='knock'&&raw.max_bytes!==raw.max_items*SLOT_BYTES)fail('contact_invalid_reservation');
}
function window(raw:Obj,maximum:number,now?:number):void {
  const issued=safeInteger(raw.issued_at),expires=safeInteger(raw.expires_at),current=currentTime(now);
  if(expires-issued<1||expires-issued>maximum)throw new NetworkCryptoError('network_invalid_validity');
  if(issued>current+30)throw new NetworkCryptoError('network_control_from_future');
  if(expires<=current)throw new NetworkCryptoError('network_control_expired');
}
function body(action:unknown,value:unknown,now?:number):Obj {
  const selected=oneOf(action,Object.keys(ACTIONS)),raw=fields(value,ACTIONS[selected]);
  if(selected==='lease'){
    validateEncryptionPublic(raw.encryption_key);limits(raw);limit(raw.lease_seconds,MAX_SECONDS);opaqueId(raw.allocation_id);
  }else if(selected==='policy.put'){
    verifyDocument(raw.lease,'resource.lease',{now});verifyDocument(raw.policy,'contact.policy',{now});
  }else if(selected==='policy.get')key(raw.recipient_key_id);
  else if(selected==='poll')opaqueId(raw.lease_id);
  else{
    verifyDocument(raw.request,'contact.request',{now});
    if(selected==='challenge')oneOf(raw.purpose,['submit','result']);
    else if(selected==='decide')verifyDocument(raw.decision,'contact.decision',{now});
    else{verifyDocument(raw.challenge,'contact.challenge',{now});decodeBase64url(raw.answer,32,32);}
  }
  return raw;
}

/** Shape, budget and proof validation; callers must also check resource bindings. */
export function verifyDocument(value:unknown,kind:string,options:ContactOptions={}):Obj {
  if(!Object.hasOwn(KINDS,kind))fail('contact_unsupported_kind');
  const maximum=['contact.rpc','contact.response'].includes(kind)?MAX_CONTROL_BYTES:kind==='contact.decision'?MAX_DECISION_BYTES:MAX_REQUEST_BYTES;
  const signed=fields(document(value as DocumentInput,maximum),['payload','proof']);
  const raw=fields(signed.payload,[...COMMON,...KINDS[kind]]),now=options.now;
  if(raw.schema_version!==PROFILE||raw.kind!==kind)fail('contact_wrong_profile');
  validateSigningPublic(raw.signing_key);
  window(raw,['contact.rpc','contact.response','contact.challenge'].includes(kind)?CHALLENGE_SECONDS:MAX_SECONDS,now);
  for(const name of ['node_key_id','owner_key_id','subject_key_id','recipient_key_id'])if(name in raw)key(raw[name]);
  for(const name of ['subject_encryption_key_id','recipient_encryption_key_id'])if(name in raw)key(raw[name],'x25519');
  for(const name of ['lease_id','resource_id','request_id','challenge_id','storage_epoch'])if(name in raw)opaqueId(raw[name]);
  for(const name of ['lease_sha256','request_sha256','policy_sha256'])if(name in raw)digestHex(raw[name]);
  for(const name of ['encryption_key','owner_encryption_key'])if(name in raw)validateEncryptionPublic(raw[name]);
  if(kind==='resource.lease'){
    limits(raw);if(raw.signing_key.key_id!==raw.node_key_id)fail('contact_wrong_node');
  }else if(kind==='contact.policy'){
    safeInteger(raw.revision,1);oneOf(raw.status,['active','revoked']);limit(raw.max_pending,32);
  }else if(kind==='contact.request'){
    oneOf(raw.request_class,['message']);if(raw.signing_key.key_id===raw.recipient_key_id)fail('contact_self_request');
  }else if(kind==='contact.challenge'){
    oneOf(raw.purpose,['submit','result']);
    const context=Object.fromEntries(Object.entries(raw).filter(([name])=>name!=='jwe'));
    const jwe=validateJwe(raw.jwe,{context});
    if(jwe.recipients.length!==1||jwe.recipients[0].header?.kid!==raw.subject_encryption_key_id||decodeBase64url(jwe.ciphertext,256).length>128)fail('contact_invalid_challenge');
  }else if(kind==='contact.grant'){
    if(!same(raw.operations,['message.store']))fail('contact_invalid_scope');
    const lease=verifyDocument(raw.resource_lease,'resource.lease',{now});
    if(lease.purpose!=='delivery'||lease.owner_key_id!==raw.signing_key.key_id||lease.owner_encryption_key.key_id!==raw.recipient_encryption_key_id||
      ['node_key_id','storage_epoch','resource_id'].some(name=>raw[name]!==lease[name])||raw.expires_at>lease.expires_at)fail('contact_grant_mismatch');
  }else if(kind==='contact.decision'){
    oneOf(raw.decision,['approved','rejected']);oneOf(raw.reason,['accepted','declined','unavailable']);
    if(raw.decision==='approved'){
      if(raw.reason!=='accepted')fail('contact_invalid_decision');
      const grant=verifyDocument(raw.grant,'contact.grant',{now});
      for(const name of ['request_id','request_sha256','signing_key','subject_key_id','subject_encryption_key_id','recipient_encryption_key_id'])if(!same(raw[name],grant[name]))fail('contact_grant_mismatch');
      if(grant.expires_at>raw.expires_at)fail('contact_grant_mismatch');
    }else if(raw.grant!==null||raw.reason==='accepted')fail('contact_invalid_decision');
  }else if(kind==='contact.rpc')body(raw.action,raw.body,now);
  else if(kind==='contact.response')document(raw.body,MAX_CONTROL_BYTES);
  try{verifyMessage(raw,signed.proof,[raw.signing_key]);}
  catch(error){if(error instanceof NetworkCryptoError)fail('contact_invalid_signature');throw error;}
  return raw;
}
export function signDocument(signer:SigningIdentityDocument,kind:string,options:{issued_at:number;expires_at:number;[name:string]:any}):SignedOpen {
  const raw={schema_version:PROFILE,kind,signing_key:validateSigningIdentity(signer),...options};
  const checked=document(raw,MAX_CONTROL_BYTES),result={payload:checked,proof:signMessage(checked,signer)};
  verifyDocument(result,kind,{now:options.issued_at});return result;
}
export function nodeBinding(raw:Obj,node:SignedNode,options:ContactOptions={}):Obj {
  const target=verifyNode(node,{now:options.now});
  if(target.status!=='active'||raw.node_key_id!==target.signing_key.key_id||raw.storage_epoch!==target.storage_epoch)fail('contact_wrong_node');
  return target;
}
export function verifyLease(value:unknown,options:NodeOptions):Obj {
  const raw=verifyDocument(value,'resource.lease',options),target=nodeBinding(raw,options.node,options);
  if(!same(raw.signing_key,target.signing_key))fail('contact_wrong_node');return raw;
}
export function verifyPolicy(value:unknown,options:PolicyOptions):Obj {
  const raw=verifyDocument(value,'contact.policy',options),resource=verifyLease(options.lease,options);
  if(resource.purpose!=='knock'||raw.signing_key.key_id!==resource.owner_key_id||!same(raw.encryption_key,resource.owner_encryption_key)||
    raw.lease_sha256!==documentSha256(options.lease as DocumentInput)||raw.max_pending>resource.max_items||raw.expires_at>resource.expires_at||
    ['node_key_id','storage_epoch','lease_id','resource_id'].some(name=>raw[name]!==resource[name]))fail('contact_policy_mismatch');
  return raw;
}
export function verifyRequest(value:unknown,options:RequestOptions):Obj {
  const raw=verifyDocument(value,'contact.request',options),owner=verifyPolicy(options.policy,options);
  if(owner.status!=='active'||raw.recipient_key_id!==owner.signing_key.key_id||raw.recipient_encryption_key_id!==owner.encryption_key.key_id||
    raw.policy_sha256!==documentSha256(options.policy as DocumentInput)||raw.expires_at>owner.expires_at||
    ['node_key_id','storage_epoch','lease_id','resource_id'].some(name=>raw[name]!==owner[name]))fail('contact_request_mismatch');
  return raw;
}
export function verifyChallenge(value:unknown,options:ChallengeOptions):Obj {
  const raw=verifyDocument(value,'contact.challenge',options),original=verifyDocument(options.request,'contact.request',options);
  const target=nodeBinding(raw,options.node,options);
  if(!same(raw.signing_key,target.signing_key)||raw.purpose!==options.purpose||raw.request_sha256!==documentSha256(options.request as DocumentInput)||
    raw.subject_key_id!==original.signing_key.key_id||raw.subject_encryption_key_id!==original.encryption_key.key_id||raw.expires_at>original.expires_at||
    ['request_id','recipient_key_id','node_key_id','storage_epoch','policy_sha256'].some(name=>raw[name]!==original[name]))fail('contact_challenge_mismatch');
  return raw;
}
export async function issueChallenge(signer:SigningIdentityDocument,options:ChallengeOptions):Promise<[SignedOpen,string]> {
  const now=currentTime(options.now),original=verifyDocument(options.request,'contact.request',{now}),target=nodeBinding(original,options.node,{now});
  const signing=validateSigningIdentity(signer);if(!same(signing,target.signing_key))fail('contact_wrong_node');
  const answer=randomBytes(32),context={schema_version:PROFILE,kind:'contact.challenge',signing_key:signing,
    issued_at:now,expires_at:Math.min(now+CHALLENGE_SECONDS,original.expires_at),request_id:original.request_id,
    request_sha256:documentSha256(options.request as DocumentInput),subject_key_id:original.signing_key.key_id,
    subject_encryption_key_id:original.encryption_key.key_id,recipient_key_id:original.recipient_key_id,node_key_id:original.node_key_id,
    storage_epoch:original.storage_epoch,policy_sha256:original.policy_sha256,purpose:oneOf(options.purpose,['submit','result']),challenge_id:'ch_'+randomBytes(16).toString('hex')};
  const raw={...context,jwe:await encryptBytes(answer,[original.encryption_key],{context})};
  const result={payload:raw,proof:signMessage(raw,signer)};
  verifyChallenge(result,{...options,now});return [result,sha256(answer)];
}
export async function solveChallenge(value:unknown,options:ChallengeOptions&{encryption_identity:EncryptionIdentityDocument}):Promise<string> {
  const raw=verifyChallenge(value,options);
  if(options.encryption_identity.key_id!==raw.subject_encryption_key_id)fail('contact_wrong_subject');
  const context=Object.fromEntries(Object.entries(raw).filter(([name])=>name!=='jwe'));
  const answer=await decryptBytes(raw.jwe,options.encryption_identity,{context});
  if(answer.length!==32)fail('contact_invalid_challenge');return encodeBase64url(answer);
}
export function verifyDecision(value:unknown,options:DecisionOptions):Obj {
  const raw=verifyDocument(value,'contact.decision',options),original=verifyRequest(options.request,options);
  const owner=verifyDocument(options.policy,'contact.policy',options);
  if(!same(raw.signing_key,owner.signing_key)||raw.request_sha256!==documentSha256(options.request as DocumentInput)||
    raw.subject_key_id!==original.signing_key.key_id||raw.subject_encryption_key_id!==original.encryption_key.key_id||raw.expires_at>original.expires_at||
    ['request_id','recipient_encryption_key_id','node_key_id','storage_epoch','policy_sha256'].some(name=>raw[name]!==original[name]))fail('contact_decision_mismatch');
  // This slice requires an actual lease at this same concrete resource node.
  if(raw.grant!==null)verifyLease(raw.grant.payload.resource_lease,options);return raw;
}
export function signRpc(signer:SigningIdentityDocument,options:NodeOptions&{action:string;body:Obj;request_id?:string}):SignedOpen {
  const now=currentTime(options.now),target=verifyNode(options.node,{now});
  return signDocument(signer,'contact.rpc',{issued_at:now,expires_at:now+60,request_id:options.request_id||'rpc_'+randomBytes(16).toString('hex'),
    node_key_id:target.signing_key.key_id,storage_epoch:target.storage_epoch,action:options.action,body:options.body});
}
export function verifyRpc(value:unknown,options:NodeOptions):Obj {
  const raw=verifyDocument(value,'contact.rpc',options);nodeBinding(raw,options.node,options);
  const body=raw.body;
  if(['challenge','submit','result'].includes(raw.action)&&!same(body.request.payload.signing_key,raw.signing_key))fail('contact_wrong_subject');
  if(['policy.put','decide'].includes(raw.action)){
    const inner=raw.action==='policy.put'?body.policy:body.decision;
    if(!same(inner.payload.signing_key,raw.signing_key))fail('contact_wrong_subject');
  }
  return raw;
}
export function signResponse(signer:SigningIdentityDocument,options:NodeOptions&{request:unknown;body:Obj}):SignedOpen {
  const now=currentTime(options.now),original=verifyRpc(options.request,{...options,now});
  return signDocument(signer,'contact.response',{issued_at:now,expires_at:Math.min(now+60,original.expires_at),request_id:original.request_id,
    request_sha256:documentSha256(options.request as DocumentInput),node_key_id:original.node_key_id,storage_epoch:original.storage_epoch,body:options.body});
}
export function verifyResponse(value:unknown,options:NodeOptions&{request:unknown}):Obj {
  const raw=verifyDocument(value,'contact.response',options),original=verifyRpc(options.request,options),target=nodeBinding(raw,options.node,options);
  if(!same(raw.signing_key,target.signing_key)||raw.request_id!==original.request_id||raw.request_sha256!==documentSha256(options.request as DocumentInput)||raw.expires_at>original.expires_at)fail('contact_response_mismatch');
  const body=raw.body;
  if(Object.hasOwn(body,'error')){
    const error=fields(fields(body,['error']).error,['code','retryable']);
    if(typeof error.code!=='string'||/^[a-z][a-z0-9_]{1,63}$/.exec(error.code)?.[0]!==error.code||typeof error.retryable!=='boolean')fail('contact_invalid_document');
  }else{
    const action=original.action,expected:Record<string,string[]>={lease:['lease'],'policy.put':['state'],'policy.get':['lease','policy'],
      challenge:['challenge'],submit:['state','request_sha256'],poll:['requests'],decide:['state','request_sha256'],result:['state','decision']};
    fields(body,expected[action]);
    if(action==='lease'){
      const lease=verifyLease(body.lease,options),wanted=original.body;
      if(lease.owner_key_id!==original.signing_key.key_id||!same(lease.owner_encryption_key,wanted.encryption_key)||
        ['purpose','max_items','max_bytes'].some(name=>lease[name]!==wanted[name])||lease.expires_at-lease.issued_at>wanted.lease_seconds)fail('contact_lease_mismatch');
    }else if(action==='policy.get'){
      const policy=verifyPolicy(body.policy,{...options,lease:body.lease});
      if(policy.status!=='active'||policy.signing_key.key_id!==original.body.recipient_key_id)fail('contact_policy_mismatch');
    }else if(action==='policy.put'){
      oneOf(body.state,['active','revoked']);
      if(body.state!==original.body.policy.payload.status)fail('contact_policy_mismatch');
    }
    else if(action==='challenge')verifyChallenge(body.challenge,{...options,request:original.body.request,purpose:original.body.purpose});
    else if(['submit','decide'].includes(action)){
      oneOf(body.state,action==='submit'?['contact_queued','decided']:['decided']);
      if(body.request_sha256!==documentSha256(original.body.request))fail('contact_request_mismatch');
    }else if(action==='poll'){
      if(!Array.isArray(body.requests)||body.requests.length>4)fail('contact_invalid_limit');
      for(const item of body.requests){
        const request=verifyDocument(item,'contact.request',options);
        if(request.recipient_key_id!==original.signing_key.key_id||request.lease_id!==original.body.lease_id)fail('contact_wrong_subject');
      }
    }else if(action==='result'){
      oneOf(body.state,['pending','approved','rejected']);
      if(body.state==='pending'){if(body.decision!==null)fail('contact_invalid_decision');}
      else{
        const decision=verifyDocument(body.decision,'contact.decision',options);if(decision.decision!==body.state)fail('contact_invalid_decision');
        const requested=original.body.request,logical=requested.payload;
        if(decision.request_sha256!==documentSha256(requested)||decision.signing_key.key_id!==logical.recipient_key_id||
          decision.subject_key_id!==logical.signing_key.key_id||decision.subject_encryption_key_id!==logical.encryption_key.key_id||decision.expires_at>logical.expires_at||
          ['request_id','recipient_encryption_key_id','node_key_id','storage_epoch','policy_sha256'].some(name=>decision[name]!==logical[name]))fail('contact_decision_mismatch');
        if(decision.grant!==null)verifyLease(decision.grant.payload.resource_lease,options);
      }
    }
  }
  return raw;
}
