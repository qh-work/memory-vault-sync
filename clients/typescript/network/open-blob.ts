/** Fixed binary framing only. Callers must verify header signatures, authority
 * and chunk bindings before using or storing the decoded bytes. */
import {randomBytes} from 'node:crypto';
import {NetworkCryptoError,canonicalBytes,document,objectFields,safeInteger,digestHex,opaqueId,
  validateSigningPublic,validateSigningIdentity,signMessage,verifyMessage,sha256} from './crypto.ts';
import type {DocumentInput,JsonValue,SigningIdentityDocument} from './crypto.ts';
import {verifyNode} from './open-control.ts';
import type {SignedNode} from './open-control.ts';

export const BLOB_PATH='/open/v1/blob';
export const PROFILE='memory-vault-open-blob/v1';
export const MAX_BLOB_HEADER_BYTES=8192;
export const MAX_BLOB_CHUNK_BYTES=262144;
export const BLOB_PREFIX_BYTES=14;
export const MAX_BLOB_FRAME_BYTES=BLOB_PREFIX_BYTES+MAX_BLOB_HEADER_BYTES+MAX_BLOB_CHUNK_BYTES;
export const MAX_BLOB_OBJECT_BYTES=6*1024*1024;
const MAGIC=Buffer.from('MVOB1\0','ascii');
export interface BlobFrame {
  readonly header:Record<string,JsonValue>;
  readonly chunk:Uint8Array;
}
export class OpenBlobError extends NetworkCryptoError {
  constructor(code:string){super(code);this.name='OpenBlobError';}
}
function fail(code:string):never{throw new OpenBlobError(code);}

function signedHeader(value:DocumentInput):{header:Record<string,JsonValue>;raw:Uint8Array}{
  const raw=value instanceof Uint8Array?Buffer.from(value):canonicalBytes(value,MAX_BLOB_HEADER_BYTES);
  if(raw.length<1||raw.length>MAX_BLOB_HEADER_BYTES)fail('open_blob_header_size');
  const header=document(raw,MAX_BLOB_HEADER_BYTES);
  objectFields(header,['payload','proof'],'open_blob_invalid_header');
  for(const name of ['payload','proof']){
    if(header[name]===null||typeof header[name]!=='object'||Array.isArray(header[name]))fail('open_blob_invalid_header');
  }
  if(!Buffer.from(raw).equals(Buffer.from(canonicalBytes(header,MAX_BLOB_HEADER_BYTES))))fail('open_blob_noncanonical_header');
  // Application-specific payload/proof validation belongs to the signed blob
  // protocol, not this codec. Limit parsing complexity before it reaches that layer.
  let nodes=0;
  function visit(item:unknown,depth:number):void{
    if(++nodes>1024||depth>16)fail('open_blob_header_complexity');
    if(item!==null&&typeof item==='object')for(const child of Object.values(item))visit(child,depth+1);
  }
  visit(header,0);
  return {header,raw};
}

export function encodeBlobFrame(header:DocumentInput,chunk:Uint8Array):Uint8Array{
  if(!(chunk instanceof Uint8Array)||chunk.byteLength>MAX_BLOB_CHUNK_BYTES)fail('open_blob_chunk_size');
  const checked=signedHeader(header);
  const raw=Buffer.allocUnsafe(BLOB_PREFIX_BYTES+checked.raw.length+chunk.byteLength);
  MAGIC.copy(raw,0);
  raw.writeUInt32BE(checked.raw.length,6);
  raw.writeUInt32BE(chunk.byteLength,10);
  raw.set(checked.raw,BLOB_PREFIX_BYTES);
  raw.set(chunk,BLOB_PREFIX_BYTES+checked.raw.length);
  return raw;
}

export function decodeBlobFrame(value:Uint8Array):BlobFrame{
  if(!(value instanceof Uint8Array)||value.byteLength<BLOB_PREFIX_BYTES+1||
    value.byteLength>MAX_BLOB_FRAME_BYTES)fail('open_blob_frame_size');
  // Validate declared lengths before slicing or allocating header/chunk copies.
  const frame=Buffer.from(value.buffer,value.byteOffset,value.byteLength);
  if(!frame.subarray(0,MAGIC.length).equals(MAGIC))fail('open_blob_frame_magic');
  const headerLength=frame.readUInt32BE(6),chunkLength=frame.readUInt32BE(10);
  if(headerLength<1||headerLength>MAX_BLOB_HEADER_BYTES)fail('open_blob_header_size');
  if(chunkLength>MAX_BLOB_CHUNK_BYTES)fail('open_blob_chunk_size');
  if(BLOB_PREFIX_BYTES+headerLength+chunkLength!==frame.length)fail('open_blob_frame_length');
  const {header}=signedHeader(frame.subarray(BLOB_PREFIX_BYTES,BLOB_PREFIX_BYTES+headerLength));
  return {header,chunk:Buffer.from(frame.subarray(BLOB_PREFIX_BYTES+headerLength))};
}

type Obj=Record<string,any>;
const COMMON=['schema_version','kind','signing_key','issued_at','expires_at',
  'request_id','node_key_id','storage_epoch','action','body'];
export interface BlobOptions {node:SignedNode;now?:number;}
export interface SignBlobRequestOptions extends BlobOptions {
  action:'upload.chunk'|'download.chunk';handle_id:string;ref:DocumentInput;
  offset:number;length:number;chunk?:Uint8Array;
}
export interface SignBlobResponseOptions extends BlobOptions {request:DocumentInput;body:DocumentInput;}
export interface VerifyBlobResponseOptions extends BlobOptions {request:DocumentInput;}
function nowValue(now?:number):number{return now===undefined?Math.floor(Date.now()/1000):safeInteger(now);}
function identifier(value:unknown,prefix:string):string{
  if(typeof value!=='string'||new RegExp('^'+prefix+'[0-9a-f]{64}$').exec(value)?.[0]!==value)fail('open_blob_invalid_identifier');
  return value;
}
function refValue(value:unknown):Obj{
  const raw=objectFields(value,['namespace','key','raw_sha256','size'],'open_blob_invalid_ref');
  if(raw.namespace!=='object'&&raw.namespace!=='meta')fail('open_blob_invalid_ref');
  digestHex(raw.key);digestHex(raw.raw_sha256);
  if(safeInteger(raw.size,1)>MAX_BLOB_OBJECT_BYTES)fail('open_blob_object_size');
  return raw;
}
function chunkRange(body:Obj):void{
  identifier(body.handle_id,'blob_');const ref=refValue(body.ref);
  const offset=safeInteger(body.offset),length=safeInteger(body.length,1);
  if(offset>=ref.size||offset%MAX_BLOB_CHUNK_BYTES!==0||length!==Math.min(MAX_BLOB_CHUNK_BYTES,ref.size-offset))fail('open_blob_invalid_chunk_range');
}
function requestBody(action:unknown,value:unknown):Obj{
  if(action!=='upload.chunk'&&action!=='download.chunk')fail('open_blob_invalid_action');
  const body=objectFields(value,['handle_id','ref','offset','length',...(action==='upload.chunk'?['chunk_sha256']:[])],'open_blob_invalid_body');
  chunkRange(body);if(action==='upload.chunk')digestHex(body.chunk_sha256);return body;
}
function same(left:unknown,right:unknown):boolean{
  return Buffer.from(canonicalBytes(left)).equals(Buffer.from(canonicalBytes(right)));
}
function responseBody(action:string,value:unknown,wanted:Obj):Obj{
  if(value!==null&&typeof value==='object'&&Object.hasOwn(value,'error')){
    const body=objectFields(value,['error'],'open_blob_invalid_body');
    const error=objectFields(body.error,['code','retryable'],'open_blob_invalid_body');
    if(typeof error.code!=='string'||/^[a-z][a-z0-9_]{1,63}$/.exec(error.code)?.[0]!==error.code||typeof error.retryable!=='boolean')fail('open_blob_invalid_body');
    return body;
  }
  const body=objectFields(value,['handle_id','ref','offset','length','chunk_sha256',...(action==='upload.chunk'?['durable_prefix']:[])],'open_blob_invalid_body');
  chunkRange(body);digestHex(body.chunk_sha256);
  for(const name of ['handle_id','ref','offset','length'])if(!same(body[name],wanted[name]))fail('open_blob_response_mismatch');
  if(action==='upload.chunk'){
    const prefix=safeInteger(body.durable_prefix),size=refValue(body.ref).size;
    if(body.chunk_sha256!==wanted.chunk_sha256||prefix<(body.offset as number)+(body.length as number)||prefix>size||
      (prefix!==size&&prefix%MAX_BLOB_CHUNK_BYTES!==0))fail('open_blob_response_mismatch');
  }
  return body;
}
function verifyHeader(value:DocumentInput,kind:'blob.request'|'blob.response',node:SignedNode,now:number):Obj{
  const {header}=signedHeader(value);
  const raw=objectFields(header.payload,[...COMMON,...(kind==='blob.response'?['request_sha256','requester_key_id']:[])],'open_blob_invalid_header');
  if(raw.schema_version!==PROFILE||raw.kind!==kind)fail('open_blob_wrong_schema');
  const signer=validateSigningPublic(raw.signing_key as DocumentInput);
  const issued=safeInteger(raw.issued_at),expires=safeInteger(raw.expires_at);
  if(expires-issued<1||expires-issued>60)throw new NetworkCryptoError('network_invalid_validity');
  if(issued-now>30)throw new NetworkCryptoError('network_control_from_future');
  if(expires<=now)throw new NetworkCryptoError('network_control_expired');
  identifier(raw.request_id,'rpc_');identifier(raw.node_key_id,'ed25519_');opaqueId(raw.storage_epoch);
  if(raw.action!=='upload.chunk'&&raw.action!=='download.chunk')fail('open_blob_invalid_action');
  const target=verifyNode(node,{now});
  if(target.status!=='active'||raw.node_key_id!==target.signing_key.key_id||raw.storage_epoch!==target.storage_epoch)fail('open_blob_wrong_node');
  if(kind==='blob.response'){
    digestHex(raw.request_sha256);identifier(raw.requester_key_id,'ed25519_');
    if(!same(signer,target.signing_key))fail('open_blob_wrong_node');
  }
  verifyMessage(raw,header.proof as DocumentInput,[signer]);return raw;
}

/** Identity and range binding; handles still require local authorization checks. */
export function signBlobRequest(signer:SigningIdentityDocument,options:SignBlobRequestOptions):Record<string,JsonValue>{
  const now=nowValue(options.now),target=verifyNode(options.node,{now});
  const body:Obj={handle_id:options.handle_id,ref:options.ref,offset:options.offset,length:options.length};
  if(options.action==='upload.chunk'){
    if(!(options.chunk instanceof Uint8Array)||options.chunk.length!==options.length||options.chunk.length>MAX_BLOB_CHUNK_BYTES)fail('open_blob_chunk_size');
    body.chunk_sha256=sha256(options.chunk);
  }else if(options.chunk!==undefined&&(!(options.chunk instanceof Uint8Array)||options.chunk.length!==0))fail('open_blob_unexpected_chunk');
  requestBody(options.action,body);
  const payload=document({schema_version:PROFILE,kind:'blob.request',signing_key:validateSigningIdentity(signer),
    issued_at:now,expires_at:safeInteger(now+60),request_id:'rpc_'+randomBytes(32).toString('hex'),
    node_key_id:target.signing_key.key_id,storage_epoch:target.storage_epoch,action:options.action,body},MAX_BLOB_HEADER_BYTES);
  const signed=document({payload,proof:signMessage(payload,signer)},MAX_BLOB_HEADER_BYTES);
  verifyBlobRequest(signed,{node:options.node,now});return signed;
}
export function verifyBlobRequest(value:DocumentInput,options:BlobOptions):Obj{
  const raw=verifyHeader(value,'blob.request',options.node,nowValue(options.now));
  requestBody(raw.action,raw.body);return raw;
}
export function signBlobResponse(signer:SigningIdentityDocument,options:SignBlobResponseOptions):Record<string,JsonValue>{
  const now=nowValue(options.now),original=verifyBlobRequest(options.request,{node:options.node,now});
  responseBody(original.action,options.body,original.body);
  const payload=document({schema_version:PROFILE,kind:'blob.response',signing_key:validateSigningIdentity(signer),
    issued_at:now,expires_at:Math.min(safeInteger(now+60),original.expires_at),request_id:original.request_id,
    request_sha256:sha256(signedHeader(options.request).raw),requester_key_id:original.signing_key.key_id,
    node_key_id:original.node_key_id,storage_epoch:original.storage_epoch,action:original.action,body:options.body},MAX_BLOB_HEADER_BYTES);
  const signed=document({payload,proof:signMessage(payload,signer)},MAX_BLOB_HEADER_BYTES);
  verifyBlobResponse(signed,{request:options.request,node:options.node,now});return signed;
}
export function verifyBlobResponse(value:DocumentInput,options:VerifyBlobResponseOptions):Obj{
  const now=nowValue(options.now),original=verifyBlobRequest(options.request,{node:options.node,now});
  const raw=verifyHeader(value,'blob.response',options.node,now);
  if(raw.request_id!==original.request_id||raw.request_sha256!==sha256(signedHeader(options.request).raw)||
    raw.requester_key_id!==original.signing_key.key_id||raw.action!==original.action||raw.expires_at>original.expires_at)fail('open_blob_response_mismatch');
  responseBody(raw.action,raw.body,original.body);return raw;
}
