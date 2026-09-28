/** Open delivery controls. Original contact authority, storage acceptance and
 * recipient validation/save remain separate; no transport key grants Vault trust. */
import {randomBytes} from 'node:crypto';
import {
  canonicalBytes,document,objectFields,safeInteger,opaqueId,validateSigningPublic,
  validateSigningIdentity,validateEncryptionPublic,validateEncryptionIdentity,
  signMessage,verifyMessage,encryptBytes,decryptBytes,encodeBase64url,decodeBase64url,sha256,
} from './crypto.ts';
import type {DocumentInput,SigningIdentityDocument,EncryptionIdentityDocument,EncryptionPublicDescriptor} from './crypto.ts';
import {verifyNode} from './open-control.ts';
import type {SignedNode} from './open-control.ts';
import {verifyDecision} from './open-contact.ts';
import {MAX_ENVELOPE_BYTES,OpenDeliveryError} from './open-delivery.ts';
export {createEnvelope,verifyEnvelope,decryptEnvelope,ENVELOPE_SCHEMA,CONTEXT_SCHEMA,
  MAX_ENVELOPE_BYTES,MAX_CONTEXT_BYTES,OpenDeliveryError} from './open-delivery.ts';

export const PROFILE='memory-vault-open-delivery-control/v1';
export const MAX_CONTROL_BYTES=65536;
export const CHUNK_BYTES=262144;
export const ACTIONS:Readonly<Record<string,readonly string[]>>={
  'node.info':[],prepare:['intent'],start:['intent','challenge','answer'],
  commit:['handle_id'],status:['handle_id'],'stored.get':['message_id','envelope_ref'],
  'list.prepare':['lease_id'],list:['lease_id','challenge','answer','after_sequence','limit'],
  'read.prepare':['message_id','lease_id'],'read.start':['message_id','lease_id','challenge','answer'],
  'receipt.put':['message_id','receipt'],'receipt.get':['message_id'],
};
export const INTENT_FIELDS=['operation_id','message_id','envelope_ref','authority','issued_at','expires_at'] as const;
export const RECEIPT_FIELDS=['message_id','envelope_ref','sender_key_id','recipient_key_id','saved_at','status'] as const;
export const STORAGE_FIELDS=['message_id','envelope_ref','upload_intent_sha256','sender_key_id','recipient_key_id',
  'node_key_id','storage_epoch','lease_id','sequence','stored_at','retain_until','status'] as const;
type Obj=Record<string,any>;
export interface DeliveryOptions {node:SignedNode;now?:number;}
function fail(code:string):never{throw new OpenDeliveryError('open_delivery_'+code);}
function input(value:unknown):DocumentInput{return value as DocumentInput;}
function fields(value:unknown,names:readonly string[]):Obj{return objectFields(value,names);}
function same(left:unknown,right:unknown):boolean{return Buffer.from(canonicalBytes(left)).equals(Buffer.from(canonicalBytes(right)));}
function current(now?:number):number{return now===undefined?Math.floor(Date.now()/1000):safeInteger(now);}
function hex(value:unknown,prefix=''):string{
  if(typeof value!=='string'||new RegExp('^'+prefix+'[0-9a-f]{64}$').exec(value)?.[0]!==value)fail('invalid_identifier');
  return value;
}

/** Strict original canonical bytes, copied before callers can mutate objects. */
export function originalDocument(value:unknown,options:{maximum?:number}={}):Obj{
  const maximum=options.maximum??MAX_ENVELOPE_BYTES,parsed=document(input(value),maximum),encoded=canonicalBytes(parsed,maximum);
  if(value instanceof Uint8Array&&!Buffer.from(value).equals(Buffer.from(encoded)))fail('noncanonical_document');
  return parsed;
}
export function rawSha256(value:unknown):string{return sha256(canonicalBytes(value));}
export function immutableRef(value:unknown,options:{maximum?:number}={}):Obj{
  const raw=fields(value,['namespace','key','raw_sha256','size']);
  if(raw.namespace!=='object'&&raw.namespace!=='meta')fail('wrong_object_namespace');
  hex(raw.key);hex(raw.raw_sha256);
  if(safeInteger(raw.size,1)>(options.maximum??MAX_ENVELOPE_BYTES))fail('document_too_large');
  return raw;
}
export function envelopeRef(value:unknown):Obj{
  const envelope=originalDocument(value),raw=canonicalBytes(envelope);
  return {namespace:'object',key:envelope.payload.context.object_ref.key,raw_sha256:sha256(raw),size:raw.length};
}
function signed(signer:SigningIdentityDocument,kind:string,values:Obj):Obj{
  const payload=document({schema_version:PROFILE,kind,signing_key:validateSigningIdentity(signer),...values},MAX_CONTROL_BYTES);
  return originalDocument({payload,proof:signMessage(payload,signer)},{maximum:MAX_CONTROL_BYTES});
}
function verified(value:unknown,kind:string,names:readonly string[],options:{expected_signer?:unknown;maximum?:number}={}):Obj{
  const raw=fields(originalDocument(value,{maximum:options.maximum??MAX_CONTROL_BYTES}),['payload','proof']);
  const payload=fields(raw.payload,['schema_version','kind','signing_key',...names]);
  if(payload.schema_version!==PROFILE||payload.kind!==kind)fail('wrong_schema');
  const key=validateSigningPublic(input(payload.signing_key));
  if(options.expected_signer!==undefined&&!same(key,options.expected_signer))fail('key_binding_mismatch');
  verifyMessage(payload,raw.proof,[key]);return payload;
}
function window(payload:Obj,now?:number,maximum=60):void{
  const time=current(now),issued=safeInteger(payload.issued_at),expires=safeInteger(payload.expires_at);
  if(expires-issued<1||expires-issued>maximum||issued-time>30||expires<=time)fail('expired');
}
function nodeBinding(payload:Obj,node:SignedNode,now?:number):Obj{
  const target=verifyNode(node,{now});
  if(target.status!=='active')fail('inactive_node');
  if(payload.node_key_id!==target.signing_key.key_id||payload.storage_epoch!==target.storage_epoch)fail('wrong_target');
  return target;
}
function bodyValue(action:unknown,value:unknown):Obj{
  if(typeof action!=='string'||!Object.hasOwn(ACTIONS,action))fail('unsupported_action');
  const body=fields(value,ACTIONS[action]);
  for(const name of ['handle_id','lease_id'])if(name in body)opaqueId(body[name]);
  if('message_id'in body)hex(body.message_id,'msg_');
  if('envelope_ref'in body)immutableRef(body.envelope_ref);
  if(action==='list'){
    safeInteger(body.after_sequence);
    if(safeInteger(body.limit,1)>4)fail('invalid_limit');
  }
  if('answer'in body)decodeBase64url(body.answer,32,32);
  return body;
}

export function signRpc(signer:SigningIdentityDocument,options:DeliveryOptions&{action:string;body:unknown;request_id?:string}):Obj{
  const now=current(options.now),target=verifyNode(options.node,{now});
  if(target.status!=='active')fail('inactive_node');
  return signed(signer,'delivery.rpc',{issued_at:now,expires_at:safeInteger(now+60),
    request_id:options.request_id||'rpc_'+randomBytes(32).toString('hex'),node_key_id:target.signing_key.key_id,
    storage_epoch:target.storage_epoch,action:options.action,body:bodyValue(options.action,options.body)});
}
export function verifyRpc(value:unknown,options:DeliveryOptions):Obj{
  const payload=verified(value,'delivery.rpc',['issued_at','expires_at','request_id','node_key_id','storage_epoch','action','body']);
  window(payload,options.now);nodeBinding(payload,options.node,options.now);
  opaqueId(payload.request_id);bodyValue(payload.action,payload.body);return payload;
}
export function signResponse(signer:SigningIdentityDocument,options:DeliveryOptions&{request:unknown;body:Obj}):Obj{
  const now=current(options.now),original=verifyRpc(options.request,{node:options.node,now});
  return signed(signer,'delivery.response',{issued_at:now,expires_at:Math.min(safeInteger(now+60),original.expires_at),
    request_id:original.request_id,request_sha256:rawSha256(options.request),requester_key_id:original.signing_key.key_id,
    node_key_id:original.node_key_id,storage_epoch:original.storage_epoch,action:original.action,body:options.body});
}
export function verifyResponse(value:unknown,options:DeliveryOptions&{request:unknown}):Obj{
  const original=verifyRpc(options.request,options);
  const payload=verified(value,'delivery.response',['issued_at','expires_at','request_id','request_sha256',
    'requester_key_id','node_key_id','storage_epoch','action','body'],{expected_signer:options.node.payload.signing_key});
  window(payload,options.now);nodeBinding(payload,options.node,options.now);
  if(payload.request_id!==original.request_id||payload.request_sha256!==rawSha256(options.request)||
    payload.requester_key_id!==original.signing_key.key_id||payload.action!==original.action||payload.expires_at>original.expires_at)fail('response_mismatch');
  if(payload.body===null||typeof payload.body!=='object'||Array.isArray(payload.body))fail('invalid_response');
  if('error'in payload.body){
    fields(payload.body,['error']);const error=fields(payload.body.error,['code','retryable']);
    if(typeof error.code!=='string'||typeof error.retryable!=='boolean')fail('invalid_response');
  }
  return payload;
}

export function issueUploadIntent(signer:SigningIdentityDocument,options:{operation_id:string;envelope_ref:unknown;
  message_id:string;authority:unknown;issued_at:number;expires_at:number}):Obj{
  opaqueId(options.operation_id);hex(options.message_id,'msg_');const ref=immutableRef(options.envelope_ref);
  const authority=fields(options.authority,['request','policy','lease','decision']);
  return signed(signer,'delivery.upload.intent',{operation_id:options.operation_id,message_id:options.message_id,
    envelope_ref:ref,authority,issued_at:options.issued_at,expires_at:options.expires_at});
}
export function verifyUploadIntent(value:unknown,options:DeliveryOptions):Obj{
  if(verifyNode(options.node,{now:options.now}).status!=='active')fail('inactive_node');
  const payload=verified(value,'delivery.upload.intent',INTENT_FIELDS,{maximum:49152});
  window(payload,options.now,3600);opaqueId(payload.operation_id);hex(payload.message_id,'msg_');
  const ref=immutableRef(payload.envelope_ref);if(ref.namespace!=='object')fail('wrong_object_namespace');
  const authority=fields(payload.authority,['request','policy','lease','decision']);
  const decision=verifyDecision(authority.decision,{request:authority.request,policy:authority.policy,
    lease:authority.lease,node:options.node,now:options.now});
  const request=authority.request.payload;
  if(decision.decision!=='approved'||decision.grant===null)fail('not_authorized');
  if(!same(payload.signing_key,request.signing_key)||payload.expires_at>decision.expires_at)fail('not_authorized');
  const grant=decision.grant.payload;
  if(!same(grant.operations,['message.store'])||ref.size>grant.resource_lease.payload.max_bytes)fail('quota');
  return payload;
}
export function readerIntent(action:string,options:{lease_id:string;caller_key_id:string;message_id?:string}):Obj{
  opaqueId(options.lease_id);
  const result:Obj={action,lease_id:options.lease_id,caller_key_id:options.caller_key_id};
  if(action==='read')result.message_id=hex(options.message_id,'msg_');
  else if(action!=='list')fail('unsupported_action');
  return result;
}

export async function issueChallenge(signer:SigningIdentityDocument,options:DeliveryOptions&{
  intent:unknown;subject_key_id:string;encryption_key:EncryptionPublicDescriptor}):Promise<[Obj,string]>{
  const now=current(options.now),target=verifyNode(options.node,{now});
  if(target.status!=='active')fail('inactive_node');
  const local=document(input(signer),4096) as unknown as SigningIdentityDocument;
  const encryption=validateEncryptionPublic(options.encryption_key),nonce=randomBytes(32);
  const context={schema_version:PROFILE,kind:'delivery.possession.context',challenge_id:'challenge_'+randomBytes(32).toString('hex'),
    intent_sha256:rawSha256(options.intent),subject_key_id:options.subject_key_id,encryption_key_id:encryption.key_id,
    node_key_id:target.signing_key.key_id,storage_epoch:target.storage_epoch,issued_at:now,expires_at:safeInteger(now+60)};
  const jwe=await encryptBytes(nonce,[encryption],{context});
  return [signed(local,'delivery.challenge',{context,jwe}),sha256(nonce)];
}
export async function solveChallenge(challenge:unknown,options:DeliveryOptions&{
  encryption_identity:EncryptionIdentityDocument;intent:Obj}):Promise<string>{
  const payload=verified(challenge,'delivery.challenge',['context','jwe'],{expected_signer:options.node.payload.signing_key,maximum:8192});
  const context=fields(payload.context,['schema_version','kind','challenge_id','intent_sha256',
    'subject_key_id','encryption_key_id','node_key_id','storage_epoch','issued_at','expires_at']);
  if(context.schema_version!==PROFILE||context.kind!=='delivery.possession.context')fail('wrong_schema');
  window(context,options.now);nodeBinding(context,options.node,options.now);
  const identity=document(input(options.encryption_identity),4096) as unknown as EncryptionIdentityDocument;
  const encryption=validateEncryptionIdentity(identity),intent=options.intent;
  const subject='payload'in intent?intent.payload.signing_key.key_id:intent.caller_key_id;
  if(context.intent_sha256!==rawSha256(intent)||context.encryption_key_id!==encryption.key_id||context.subject_key_id!==subject)fail('challenge_mismatch');
  const plain=await decryptBytes(payload.jwe,identity,{context});
  if(plain.length!==32)fail('challenge_mismatch');return encodeBase64url(plain);
}

export function issueRecipientReceipt(signer:SigningIdentityDocument,options:{message_id:string;envelope_ref:unknown;
  sender_key_id:string;saved_at?:number}):Obj{
  return signed(signer,'recipient.receipt',{message_id:hex(options.message_id,'msg_'),envelope_ref:immutableRef(options.envelope_ref),
    sender_key_id:options.sender_key_id,recipient_key_id:validateSigningIdentity(signer).key_id,
    saved_at:current(options.saved_at),status:'validated_saved'});
}
export function verifyRecipientReceipt(value:unknown,options:{recipient_signing_key:Obj;sender_key_id:string;
  message_id:string;envelope_ref:unknown}):Obj{
  const payload=verified(value,'recipient.receipt',RECEIPT_FIELDS,{expected_signer:options.recipient_signing_key,maximum:4096});
  safeInteger(payload.saved_at);
  if(payload.status!=='validated_saved'||payload.message_id!==options.message_id||!same(payload.envelope_ref,options.envelope_ref)||
    payload.sender_key_id!==options.sender_key_id||payload.recipient_key_id!==options.recipient_signing_key.key_id)fail('receipt_mismatch');
  return payload;
}
export function issueStorageReceipt(signer:SigningIdentityDocument,options:{node:SignedNode;intent:unknown;
  sequence:number;stored_at:number;retain_until:number}):Obj{
  const original=verifyUploadIntent(options.intent,{node:options.node,now:options.stored_at}),authority=original.authority;
  const lease=authority.decision.payload.grant.payload.resource_lease.payload;
  if(options.retain_until>lease.expires_at||options.retain_until<=options.stored_at)fail('expired');
  return signed(signer,'storage.receipt',{message_id:original.message_id,envelope_ref:original.envelope_ref,
    upload_intent_sha256:rawSha256(options.intent),sender_key_id:original.signing_key.key_id,
    recipient_key_id:authority.policy.payload.signing_key.key_id,node_key_id:lease.node_key_id,
    storage_epoch:lease.storage_epoch,lease_id:lease.lease_id,sequence:safeInteger(options.sequence,1),
    stored_at:safeInteger(options.stored_at),retain_until:safeInteger(options.retain_until),status:'storage_accepted'});
}
export function verifyStorageReceipt(value:unknown,options:{node:SignedNode;intent:unknown}):Obj{
  const payload=verified(value,'storage.receipt',STORAGE_FIELDS,{expected_signer:options.node.payload.signing_key,maximum:4096});
  const stored=safeInteger(payload.stored_at),original=verifyUploadIntent(options.intent,{node:options.node,now:stored});
  const lease=original.authority.decision.payload.grant.payload.resource_lease.payload;
  safeInteger(payload.sequence,1);
  if(payload.message_id!==original.message_id||!same(payload.envelope_ref,original.envelope_ref)||
    payload.upload_intent_sha256!==rawSha256(options.intent)||payload.sender_key_id!==original.signing_key.key_id||
    payload.recipient_key_id!==original.authority.policy.payload.signing_key.key_id||
    ['node_key_id','storage_epoch','lease_id'].some(name=>payload[name]!==lease[name])||
    !(stored<safeInteger(payload.retain_until)&&payload.retain_until<=lease.expires_at)||payload.status!=='storage_accepted')fail('receipt_mismatch');
  return payload;
}
