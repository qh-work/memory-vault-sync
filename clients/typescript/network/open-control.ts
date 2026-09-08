/** Native open-control/v1. Self-authentication is not Vault trust or authority. */
import {
  NetworkCryptoError, canonicalBytes, document, documentSha256, objectFields,
  safeInteger, opaqueId, digestHex, sha256, validateSigningPublic,
  validateSigningIdentity, validateEncryptionPublic, signMessage, verifyMessage,
} from './crypto.ts';
import type {
  DocumentInput, MessageProof, SigningIdentityDocument, SigningPublicDescriptor,
  EncryptionPublicDescriptor,
} from './crypto.ts';
import {validateNodeUrl} from './nodes.ts';

export const CONTROL_SCHEMA = 'memory-vault-open-control/v1';
export const REQUEST_SCHEMA = 'memory-vault-open-request/v1';
export const RESPONSE_SCHEMA = 'memory-vault-open-response/v1';
export const LEASE_SCHEMA = 'memory-vault-open-index-lease/v1';
export const MAX_CONTROL_BYTES = 65_536;
export const MAX_DESCRIPTOR_BYTES = 4_096;
export const MAX_DESCRIPTOR_SECONDS = 3_600;
export const MAX_REQUEST_SECONDS = 60;
export const MAX_LEASE_SECONDS = 600;
export const MAX_REPLY_NODES = 8;
type Obj = Record<string, any>;
export type OpenView = 'general' | 'directory';
export type OpenAction = 'hello' | 'find' | 'get' | 'put' | 'renew';
export interface SignedOpen<T = Obj> {readonly payload: T; readonly proof: MessageProof;}
export interface OpenNode extends Obj {
  readonly schema_version: typeof CONTROL_SCHEMA; readonly kind: 'node';
  readonly signing_key: SigningPublicDescriptor; readonly coordinate: string;
  readonly base_url: string; readonly storage_epoch: string;
  readonly roles: readonly ('router'|'directory')[]; readonly revision: number;
  readonly status: 'active'|'revoked'; readonly issued_at: number; readonly expires_at: number;
}
export interface OpenContact extends Obj {
  readonly schema_version: typeof CONTROL_SCHEMA; readonly kind: 'contact';
  readonly signing_key: SigningPublicDescriptor; readonly encryption_key: EncryptionPublicDescriptor;
  readonly revision: number; readonly status: 'active'|'revoked'; readonly allow_discovery: boolean;
  readonly endpoints: readonly {kind:'node';node_key_id:string;base_url:string;storage_epoch:string}[];
  readonly issued_at: number; readonly expires_at: number;
}
export type SignedNode = SignedOpen<OpenNode>;
export type SignedContact = SignedOpen<OpenContact>;
export interface VerificationOptions {readonly now?: number; readonly allow_expired?: boolean;}
export class OpenControlError extends NetworkCryptoError {
  constructor(code: string) {super(code);this.name='OpenControlError';}
}
function fail(code: string): never {throw new OpenControlError(code);}
/** The old crypto primitive uses a few different error labels. Normalize only
 * this new profile's proof boundary; cryptographic verification is unchanged. */
function verifyProof(payload:Obj,proof:MessageProof,signer:SigningPublicDescriptor):void {
  try{verifyMessage(payload,proof,[signer]);}
  catch(error){
    const code=(error as {code?:string})?.code;
    const aliases:Record<string,string>={invalid_proof:'invalid_signature_proof',
      unsupported_proof_schema:'unsupported_signature_schema',network_invalid_digest:'invalid_signature_digest',
      payload_digest_mismatch:'signature_digest_mismatch'};
    if(code&&aliases[code])fail(aliases[code]);
    if(code==='invalid_signature'&&typeof proof?.signature==='string'){
      const bytes=Buffer.from(proof.signature,'base64');
      if(bytes.length===64&&bytes.toString('base64')===proof.signature)fail('signature_invalid');
    }
    throw error;
  }
}
function keyId(value: unknown): string {
  if (typeof value!=='string'||/^ed25519_[0-9a-f]{64}$/.exec(value)?.[0]!==value) fail('open_invalid_key');
  return value;
}
export function coordinate(value: string): string {
  return sha256(Buffer.from('memory-vault-open-routing/v1\0'+keyId(value),'utf8'));
}
export function contactKey(value: string): string {
  return sha256(Buffer.from('memory-vault-open-contact/v1\0'+keyId(value),'utf8'));
}
function url(value: unknown): string {
  if (typeof value!=='string'||Array.from(value).length>512) fail('open_invalid_url');
  return validateNodeUrl(value);
}
function signed(value: unknown, maximum: number): Obj {
  return objectFields(document(value as DocumentInput,maximum),['payload','proof']);
}
function window(raw: Obj,maximum: number,options: VerificationOptions={}): void {
  const issued=safeInteger(raw.issued_at),expires=safeInteger(raw.expires_at);
  if(expires-issued<1||expires-issued>maximum)throw new NetworkCryptoError('network_invalid_validity');
  const now=options.now===undefined?Math.floor(Date.now()/1000):safeInteger(options.now);
  if(issued>now+30)throw new NetworkCryptoError('network_control_from_future');
  if(!options.allow_expired&&expires<=now)throw new NetworkCryptoError('network_control_expired');
}
function descriptorPayload(value: unknown,kind: 'node'|'contact',options: VerificationOptions): Obj {
  const common=['schema_version','kind','signing_key','revision','status','issued_at','expires_at'];
  const raw=objectFields(value,[...common,...(kind==='node'?['coordinate','base_url','storage_epoch','roles']
    :['encryption_key','allow_discovery','endpoints'])]);
  if(raw.schema_version!==CONTROL_SCHEMA||raw.kind!==kind)fail('open_unsupported_control');
  const signing=validateSigningPublic(raw.signing_key as DocumentInput);
  safeInteger(raw.revision,1);
  if(raw.status!=='active'&&raw.status!=='revoked')fail('open_invalid_status');
  window(raw,MAX_DESCRIPTOR_SECONDS,options);
  if(kind==='node'){
    if(raw.coordinate!==coordinate(signing.key_id))fail('open_coordinate_mismatch');
    url(raw.base_url);opaqueId(raw.storage_epoch);
    if(!Array.isArray(raw.roles)||!raw.roles.length||raw.roles.some((role,index)=>
      !['router','directory'].includes(role)||(index>0&&role<=raw.roles[index-1])))fail('open_invalid_roles');
  }else{
    validateEncryptionPublic(raw.encryption_key as DocumentInput);
    if(typeof raw.allow_discovery!=='boolean')fail('open_invalid_discovery');
    if(!Array.isArray(raw.endpoints)||raw.endpoints.length>4)fail('open_invalid_endpoints');
    const seen=new Set<string>();
    for(const entry of raw.endpoints){
      const item=objectFields(entry,['kind','node_key_id','base_url','storage_epoch']);
      if(item.kind!=='node')fail('open_unsupported_endpoint');
      const binding=JSON.stringify([keyId(item.node_key_id),url(item.base_url),opaqueId(item.storage_epoch)]);
      if(seen.has(binding))fail('open_duplicate_endpoint');seen.add(binding);
    }
  }
  return raw;
}
function verifyDescriptor(value: unknown,kind: 'node'|'contact',options: VerificationOptions): Obj {
  const wrapper=signed(value,MAX_DESCRIPTOR_BYTES),raw=descriptorPayload(wrapper.payload,kind,options);
  verifyProof(raw,wrapper.proof,raw.signing_key);
  return raw;
}
export function verifyNode(value: unknown,options: VerificationOptions={}): OpenNode {
  return verifyDescriptor(value,'node',options) as OpenNode;
}
export function verifyContact(value: unknown,options: VerificationOptions={}): OpenContact {
  return verifyDescriptor(value,'contact',options) as OpenContact;
}
function sign(payload: Obj,signer: SigningIdentityDocument,maximum=MAX_CONTROL_BYTES): SignedOpen {
  const raw=document(payload,maximum),result={payload:raw,proof:signMessage(raw,signer)};
  document(result,maximum);return result;
}
export interface IssueNodeOptions {
  base_url:string;storage_epoch:string;roles:readonly ('router'|'directory')[];
  revision:number;issued_at:number;expires_at:number;status?:'active'|'revoked';
}
export function issueNode(signer:SigningIdentityDocument,options:IssueNodeOptions):SignedNode {
  const signing=validateSigningIdentity(signer);
  const raw={schema_version:CONTROL_SCHEMA,kind:'node',signing_key:signing,coordinate:coordinate(signing.key_id),
    base_url:options.base_url,storage_epoch:options.storage_epoch,roles:options.roles,
    revision:options.revision,status:options.status??'active',issued_at:options.issued_at,expires_at:options.expires_at};
  return sign(descriptorPayload(raw,'node',{now:options.issued_at}),signer,MAX_DESCRIPTOR_BYTES) as SignedNode;
}
export interface IssueContactOptions {
  encryption_key:EncryptionPublicDescriptor;revision:number;allow_discovery:boolean;
  endpoints:OpenContact['endpoints'];issued_at:number;expires_at:number;status?:'active'|'revoked';
}
export function issueContact(signer:SigningIdentityDocument,options:IssueContactOptions):SignedContact {
  const raw={schema_version:CONTROL_SCHEMA,kind:'contact',signing_key:validateSigningIdentity(signer),
    encryption_key:options.encryption_key,revision:options.revision,status:options.status??'active',
    allow_discovery:options.allow_discovery,endpoints:options.endpoints,
    issued_at:options.issued_at,expires_at:options.expires_at};
  return sign(descriptorPayload(raw,'contact',{now:options.issued_at}),signer,MAX_DESCRIPTOR_BYTES) as SignedContact;
}
function requestBody(action:unknown,value:unknown,now?:number):Obj {
  if(typeof action!=='string'||!['hello','find','get','put','renew'].includes(action))fail('open_unsupported_action');
  const sets:Record<string,string[]>={hello:['node'],find:['target','view'],get:['key'],
    put:['contact','lease_seconds'],renew:['contact','lease_id','lease_seconds']};
  const raw=objectFields(value,sets[action]);
  if(action==='hello'){
    if(raw.node!==null)verifyNode(raw.node,{now});
  }else if(action==='find'){
    digestHex(raw.target);if(raw.view!=='general'&&raw.view!=='directory')fail('open_invalid_view');
  }else if(action==='get')digestHex(raw.key);
  else{
    verifyContact(raw.contact,{now});
    if(safeInteger(raw.lease_seconds,1)>MAX_LEASE_SECONDS)fail('open_invalid_lease');
    if(action==='renew')opaqueId(raw.lease_id);
  }
  return raw;
}
export interface RequestOptions {
  action:OpenAction;request_id:string;node:SignedNode;body:Obj;issued_at:number;expires_at:number;
}
export function signRequest(signer:SigningIdentityDocument,options:RequestOptions):SignedOpen {
  const target=verifyNode(options.node,{now:options.issued_at});
  const result=sign({schema_version:REQUEST_SCHEMA,action:options.action,request_id:options.request_id,
    signer:validateSigningIdentity(signer),node_key_id:target.signing_key.key_id,storage_epoch:target.storage_epoch,
    issued_at:options.issued_at,expires_at:options.expires_at,body:options.body},signer);
  verifyRequest(result,{node:options.node,now:options.issued_at});return result;
}
export function verifyRequest(value:unknown,options:{node:SignedNode;now?:number}):Obj {
  const wrapper=signed(value,MAX_CONTROL_BYTES),raw=objectFields(wrapper.payload,
    ['schema_version','action','request_id','signer','node_key_id','storage_epoch','issued_at','expires_at','body']);
  if(raw.schema_version!==REQUEST_SCHEMA)fail('open_unsupported_request');
  opaqueId(raw.request_id);validateSigningPublic(raw.signer as DocumentInput);
  const target=verifyNode(options.node,{now:options.now});
  if(target.status!=='active'||raw.node_key_id!==target.signing_key.key_id||raw.storage_epoch!==target.storage_epoch)fail('open_wrong_node');
  window(raw,MAX_REQUEST_SECONDS,{now:options.now});
  const body=requestBody(raw.action,raw.body,options.now);
  if(raw.action==='hello'&&body.node!==null&&
    Buffer.compare(Buffer.from(canonicalBytes(body.node.payload.signing_key)),Buffer.from(canonicalBytes(raw.signer))))fail('open_sender_mismatch');
  verifyProof(raw,wrapper.proof,raw.signer);return raw;
}
export interface LeaseOptions {
  node:SignedNode;contact:SignedContact;request:SignedOpen;lease_id:string;issued_at:number;expires_at:number;
}
export function issueLease(signer:SigningIdentityDocument,options:LeaseOptions):SignedOpen {
  const target=verifyNode(options.node,{now:options.issued_at}),owner=verifyContact(options.contact,{now:options.issued_at});
  const request=verifyRequest(options.request,{node:options.node,now:options.issued_at});
  const result=sign({schema_version:LEASE_SCHEMA,node_key_id:target.signing_key.key_id,storage_epoch:target.storage_epoch,
    owner_key_id:owner.signing_key.key_id,contact_sha256:documentSha256(options.contact as DocumentInput),
    contact_revision:owner.revision,lease_id:opaqueId(options.lease_id),request_id:request.request_id,
    request_sha256:documentSha256(options.request as DocumentInput),issued_at:options.issued_at,expires_at:options.expires_at},signer);
  verifyLease(result,{node:options.node,contact:options.contact,now:options.issued_at});return result;
}
export function verifyLease(value:unknown,options:{node:SignedNode;contact:SignedContact;now?:number}):Obj {
  const wrapper=signed(value,MAX_DESCRIPTOR_BYTES),raw=objectFields(wrapper.payload,
    ['schema_version','node_key_id','storage_epoch','owner_key_id','contact_sha256','contact_revision','lease_id',
      'request_id','request_sha256','issued_at','expires_at']);
  const target=verifyNode(options.node,{now:options.now}),owner=verifyContact(options.contact,{now:options.now});
  safeInteger(raw.contact_revision,1);
  if(raw.schema_version!==LEASE_SCHEMA||raw.node_key_id!==target.signing_key.key_id||raw.storage_epoch!==target.storage_epoch||
    raw.owner_key_id!==owner.signing_key.key_id||raw.contact_sha256!==documentSha256(options.contact as DocumentInput)||
    raw.contact_revision!==owner.revision||safeInteger(raw.expires_at)>owner.expires_at)fail('open_lease_mismatch');
  opaqueId(raw.lease_id);opaqueId(raw.request_id);digestHex(raw.request_sha256);
  window(raw,MAX_LEASE_SECONDS,{now:options.now});verifyProof(raw,wrapper.proof,target.signing_key);return raw;
}
function responseBody(value:unknown,request:Obj,node:SignedNode,now?:number):Obj {
  if(value!==null&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).length===1&&Object.hasOwn(value,'error')){
    const raw=value as Obj,error=objectFields(raw.error,['code','retryable']);
    if(typeof error.code!=='string'||/^[a-z][a-z0-9_]{1,63}$/.exec(error.code)?.[0]!==error.code||typeof error.retryable!=='boolean')fail('open_invalid_error');
    return raw;
  }
  let raw:Obj;
  if(request.action==='hello'){
    raw=objectFields(value,['node']);const answer=verifyNode(raw.node,{now}),expected=verifyNode(node,{now});
    if(Buffer.compare(Buffer.from(canonicalBytes(answer.signing_key)),Buffer.from(canonicalBytes(expected.signing_key)))||
      answer.storage_epoch!==expected.storage_epoch)fail('open_wrong_node');
  }else if(request.action==='find'){
    raw=objectFields(value,['nodes']);
    if(!Array.isArray(raw.nodes)||raw.nodes.length>MAX_REPLY_NODES)fail('open_invalid_candidates');
    const seen=new Set<string>();for(const candidate of raw.nodes){
      const key=verifyNode(candidate,{now}).signing_key.key_id;
      if(seen.has(key))fail('open_duplicate_candidate');seen.add(key);
    }
  }else if(request.action==='get'){
    if(value===null||typeof value!=='object'||Array.isArray(value)||typeof (value as Obj).state!=='string')fail('open_invalid_result');
    if((value as Obj).state==='found'){
      raw=objectFields(value,['state','contact','lease']);const owner=verifyContact(raw.contact,{now});
      if(owner.status!=='active'||!owner.allow_discovery||contactKey(owner.signing_key.key_id)!==request.body.key)fail('open_contact_mismatch');
      verifyLease(raw.lease,{node,contact:raw.contact,now});
    }else if(['not_found','revoked','conflict'].includes((value as Obj).state))raw=objectFields(value,['state']);
    else fail('open_invalid_result');
  }else{
    raw=objectFields(value,['lease']);const lease=verifyLease(raw.lease,{node,contact:request.body.contact,now});
    if(lease.request_id!==request.request_id)fail('open_lease_mismatch');
  }
  return raw;
}
export function signResponse(signer:SigningIdentityDocument,options:{request:SignedOpen;node:SignedNode;body:Obj;issued_at:number;expires_at:number}):SignedOpen {
  const original=verifyRequest(options.request,{node:options.node,now:options.issued_at}),target=verifyNode(options.node,{now:options.issued_at});
  const result=sign({schema_version:RESPONSE_SCHEMA,request_id:original.request_id,
    request_sha256:documentSha256(options.request as DocumentInput),node_key_id:target.signing_key.key_id,
    storage_epoch:target.storage_epoch,issued_at:options.issued_at,expires_at:options.expires_at,
    body:responseBody(options.body,original,options.node,options.issued_at)},signer);
  verifyResponse(result,{request:options.request,node:options.node,now:options.issued_at});return result;
}
export function verifyResponse(value:unknown,options:{request:SignedOpen;node:SignedNode;now?:number}):Obj {
  const wrapper=signed(value,MAX_CONTROL_BYTES),raw=objectFields(wrapper.payload,
    ['schema_version','request_id','request_sha256','node_key_id','storage_epoch','issued_at','expires_at','body']);
  const target=verifyNode(options.node,{now:options.now}),original=verifyRequest(options.request,{node:options.node,now:options.now});
  if(raw.schema_version!==RESPONSE_SCHEMA||raw.request_id!==original.request_id||
    raw.request_sha256!==documentSha256(options.request as DocumentInput)||raw.node_key_id!==target.signing_key.key_id||
    raw.storage_epoch!==target.storage_epoch)fail('open_response_mismatch');
  window(raw,MAX_REQUEST_SECONDS,{now:options.now});
  if(raw.expires_at>original.expires_at)fail('open_response_mismatch');
  verifyProof(raw,wrapper.proof,target.signing_key);responseBody(raw.body,original,options.node,options.now);
  if(['put','renew'].includes(original.action)&&Object.hasOwn(raw.body,'lease')&&
    raw.body.lease.payload.request_sha256!==documentSha256(options.request as DocumentInput))fail('open_lease_mismatch');
  return raw;
}
