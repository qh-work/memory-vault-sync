/** Bounded original bootstrap possession messages; no service authorization.
 * The meter counts explicit wire/frame hashes and signature verification.
 * Provider-internal curve, KDF and AES work is fixed-size, not a claimed SHA count.
 */
import {createPrivateKey,createPublicKey,randomBytes,sign,timingSafeEqual} from 'node:crypto';
import type {KeyObject} from 'node:crypto';
import {isUint8Array,isProxy} from 'node:util/types';
import {GeneralEncrypt,generalDecrypt,importJWK} from 'jose';
import type {GeneralJWE} from 'jose';
import {buildNewWire,parseNewWire,rawRef,objectFields,u53,RepairError} from './open-repair-wire.ts';
import type {RepairPolicy,RepairBudget,RawRef} from './open-repair-wire.ts';
import {canonicalOriginalControl,originalPublicDescriptor,parseOriginalControl,verifyBoundedControlSignature} from './open-repair-original.ts';
import type {AuthenticatedRepairOriginal} from './open-repair-resource.ts';

type Obj=Record<string,any>;
const SCHEMA='memory-vault-open-repair/v1',PURPOSE='bootstrap.service_proof';
const BYTES='memory-vault-network-bytes/v1',MAGIC=Buffer.from(BYTES+'\n'),DOMAIN=Buffer.from('UniversalAgentMemory\0message-signature\0v1\0');
const MAX_RAW=65536,MAX_AAD=16384,FRAME_BYTES=MAGIC.length+40+32;
const COMMON=['schema_version','kind','signing_key','issued_at','expires_at'];
const BINDING=['subject','target','target_storage_epoch','purpose','consumer','bootstrap_grant_sha256'];
const OPTIONS=['expectedSubject','expectedTarget','targetStorageEpoch','bootstrapGrantSha256','selector','at','policy','budget'];
const SELECTOR=['root_key_sha256','ack_slot_sha256','root_authority_sha256','read_grant_sha256'];
const OFFER_SELECTOR=['root_key_sha256','ack_slot_sha256','root_authority_sha256','write_grant_sha256'];
const MAILBOX_ROOT_SELECTOR=['root_key_sha256','anchor_ref','root_authority_sha256','read_grant_sha256'];
const MAILBOX_FEED_SELECTOR=['root_key_sha256','slot_key_sha256','feed_ref','slot_sha256','read_grant_sha256','maintenance_root_sha256'];
export type BootstrapConsumer='ack_owner'|'ack_offer'|'mailbox_root'|'mailbox_feed';
const byteLength=Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint8Array.prototype),'byteLength')!.get!;
export interface BootstrapProbeOptions{
  readonly expectedSubject:unknown;readonly expectedTarget:unknown;readonly targetStorageEpoch:string;
  readonly bootstrapGrantSha256:string;readonly selector:unknown;readonly at:number;
  readonly policy:RepairPolicy;readonly budget:RepairBudget;
  readonly consumer?:BootstrapConsumer;
}
export interface PreparedBootstrapProbe{readonly original:AuthenticatedRepairOriginal;readonly nonce:Uint8Array;}
export interface AuthenticatedBootstrapAnswer{
  readonly originals:Readonly<{probe:AuthenticatedRepairOriginal;challenge:AuthenticatedRepairOriginal;answer:AuthenticatedRepairOriginal}>;
  readonly at:number;
}
interface Context{expected:Obj;policy:RepairPolicy;budget:RepairBudget;at:number;}
function fail(code='repair_invalid_probe'):never{throw new RepairError(code);}
function mismatch():never{fail('repair_probe_mismatch');}
function fields(value:unknown,names:readonly string[]):Obj{try{return objectFields(value,names);}catch{fail();}}
function number(value:unknown):number{try{return u53(value);}catch{fail();}}
function pattern(value:unknown,re:RegExp):string{if(typeof value!=='string'||re.exec(value)?.[0]!==value)fail();return value;}
function opaque(value:unknown):void{pattern(value,/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/);}
function digest(value:unknown):void{pattern(value,/^[0-9a-f]{64}$/);}
function same(a:unknown,b:unknown):boolean{
  if(a===b)return true;if(a===null||b===null||typeof a!=='object'||typeof b!=='object'||Array.isArray(a)!==Array.isArray(b))return false;
  const names=Object.keys(a);return names.length===Object.keys(b).length&&names.every(key=>Object.hasOwn(b,key)&&same((a as Obj)[key],(b as Obj)[key]));
}
function equal(a:Uint8Array,b:Uint8Array):boolean{return a.length===b.length&&timingSafeEqual(a,b);}
function outputRoom(size:number,budget:RepairBudget):void{
  const work=budget.snapshot();if(size>budget.policy.max_total_bytes-work.input_bytes-work.output_bytes)fail('repair_over_budget');
}
function clone(value:unknown,context:Context):Obj{return buildNewWire(value,context.policy,context.budget).value as Obj;}
function context(options:unknown,extra:readonly string[]=[]):{args:Obj;ctx:Context}{
  if(options===null||typeof options!=='object'||isProxy(options))fail();
  const args=fields(options,[...OPTIONS,...extra,...(Object.hasOwn(options,'consumer')?['consumer']:[])]),policy=args.policy as RepairPolicy,budget=args.budget as RepairBudget;
  const consumer=Object.hasOwn(args,'consumer')?args.consumer:'ack_owner';if(consumer!=='ack_owner'&&consumer!=='ack_offer'&&consumer!=='mailbox_root'&&consumer!=='mailbox_feed')fail();
  const value=buildNewWire({subject:args.expectedSubject,target:args.expectedTarget,target_storage_epoch:args.targetStorageEpoch,
    bootstrap_grant_sha256:args.bootstrapGrantSha256,selector:args.selector,at:args.at},policy,budget).value as Obj;
  const expected:Obj={...value,consumer},selector=consumer==='ack_owner'?SELECTOR:consumer==='ack_offer'?OFFER_SELECTOR:consumer==='mailbox_root'?MAILBOX_ROOT_SELECTOR:MAILBOX_FEED_SELECTOR;
  for(const key of ['subject','target']){
    const dual=fields(expected[key],['signing_key','encryption_key']);
    originalPublicDescriptor(dual.signing_key,budget);originalPublicDescriptor(dual.encryption_key,budget,true);
  }
  fields(expected.selector,selector);for(const name of selector){
    if(name==='anchor_ref'||name==='feed_ref'){
      const locator=fields(expected.selector[name],['namespace','key']);
      if(locator.namespace!==(name==='anchor_ref'?'anchor':'feed'))fail();digest(locator.key);
    }else digest(expected.selector[name]);
  }
  opaque(expected.target_storage_epoch);digest(expected.bootstrap_grant_sha256);const at=number(expected.at);
  return {args,ctx:{expected,policy,budget,at}};
}
function ids(value:Obj):Obj{return {signing_key_id:value.signing_key.key_id,encryption_key_id:value.encryption_key.key_id};}
function times(payload:Obj,ctx:Context,parent?:Obj):void{
  const issued=number(payload.issued_at),expires=number(payload.expires_at);
  if(!(issued<=ctx.at&&ctx.at<expires&&expires-issued>=1&&expires-issued<=60))fail();
  if(parent&&(issued<parent.issued_at||expires>parent.expires_at))mismatch();
}
function base(kind:string,signer:Obj,expires:unknown,ctx:Context):Obj{
  const result={schema_version:SCHEMA,kind,signing_key:signer,issued_at:ctx.at,expires_at:number(expires)};
  times(result,ctx);return result;
}
function binding(ctx:Context,full=false):Obj{
  const value=ctx.expected;return {subject:full?value.subject:ids(value.subject),target:full?value.target:ids(value.target),
    target_storage_epoch:value.target_storage_epoch,purpose:PURPOSE,consumer:value.consumer,bootstrap_grant_sha256:value.bootstrap_grant_sha256};
}
function checkBinding(payload:Obj,ctx:Context,full=false):void{
  if(payload.purpose!==PURPOSE||payload.consumer!==ctx.expected.consumer)fail();
  const expected=binding(ctx,full);if(BINDING.some(name=>!same(payload[name],expected[name])))mismatch();
}
function encode(raw:Uint8Array,budget:RepairBudget,url=true):string{
  const size=url?Math.ceil(raw.length*4/3):Math.ceil(raw.length/3)*4;budget.output(size);
  return (raw as Buffer).toString(url?'base64url':'base64');
}
function decode(value:unknown,budget:RepairBudget,size?:number,maximum=65536,url=true):Buffer{
  if(typeof value!=='string'||value.length>Math.ceil(maximum*4/3)+3)fail('repair_invalid_original');
  if(url){if(/^[A-Za-z0-9_-]*$/.exec(value)?.[0]!==value||value.length%4===1)fail('repair_invalid_original');}
  else if(size===undefined||value.length!==Math.ceil(size/3)*4||new RegExp('^[A-Za-z0-9+/]{'+(value.length-(3-size%3)%3)+'}'+'='.repeat((3-size%3)%3)+'$').exec(value)?.[0]!==value)fail('repair_invalid_original');
  const actual=url?Math.floor(value.length*3/4):size!;
  if(actual>maximum||(size!==undefined&&actual!==size))fail('repair_invalid_original');
  budget.output(actual);const raw=Buffer.from(value,url?'base64url':'base64');
  if(encode(raw,budget,url)!==value||raw.length!==actual)fail('repair_invalid_original');return raw;
}
function nonce(value:unknown,budget:RepairBudget):Buffer{
  if(!isUint8Array(value)||Reflect.apply(byteLength,value,[])!==32)fail('repair_invalid_nonce');
  budget.input(32);budget.output(32);const result=Buffer.alloc(32);Reflect.apply(Uint8Array.prototype.set,result,[value]);return result;
}
function freshNonce(ctx:Context):Buffer{ctx.budget.output(32);return randomBytes(32);}
function freshId(prefix:string,ctx:Context):string{ctx.budget.output(16);const bytes=randomBytes(16);ctx.budget.output(prefix.length+32);return prefix+bytes.toString('hex');}
function privateKey(value:unknown,expected:Obj,ctx:Context,encryption=false):{key:KeyObject;value:Obj}{
  const raw=fields(clone(value,ctx),['schema_version','algorithm','key_id','public_key','private_key']);
  if(raw.schema_version!==(encryption?'memory-vault-network-encryption-identity/v1':'universal-memory-identity/v1')||
      raw.algorithm!==expected.algorithm||raw.key_id!==expected.key_id||raw.public_key!==expected.public_key)mismatch();
  const secret=decode(raw.private_key,ctx.budget,32,32,encryption),publicBytes=decode(raw.public_key,ctx.budget,32,32,encryption);
  ctx.budget.output(48);const der=Buffer.alloc(48);der.write(encryption?'302e020100300506032b656e04220420':'302e020100300506032b657004220420',0,'hex');secret.copy(der,16);
  let key:KeyObject,actual:Buffer;
  try{key=createPrivateKey({key:der,format:'der',type:'pkcs8'});ctx.budget.output(44);actual=createPublicKey(key).export({format:'der',type:'spki'});}
  catch(error){if(error instanceof RepairError)throw error;mismatch();}
  if(!equal(actual.subarray(-32),publicBytes))mismatch();return {key,value:raw};
}
function aad(payload:Obj,omitted:string,ctx:Context):Buffer{
  const bytes=canonicalOriginalControl(Object.fromEntries(Object.entries(payload).filter(([name])=>name!==omitted)),ctx.budget);
  if(bytes.length>MAX_AAD)fail();return bytes;
}
function jwe(value:unknown,payload:Obj,omitted:string,expected:Obj,ctx:Context):GeneralJWE{
  const raw=fields(value,['protected','recipients','aad','iv','ciphertext','tag']),headerBytes=decode(raw.protected,ctx.budget,undefined,1024);
  const header=fields(parseOriginalControl(headerBytes,ctx.policy,ctx.budget).value,['enc','typ']);
  if(header.enc!=='A256GCM'||header.typ!==BYTES)fail();
  const expectedAad=aad(payload,omitted,ctx);if(!equal(decode(raw.aad,ctx.budget,expectedAad.length,MAX_AAD),expectedAad))mismatch();
  decode(raw.iv,ctx.budget,12,12);decode(raw.tag,ctx.budget,16,16);decode(raw.ciphertext,ctx.budget,FRAME_BYTES,FRAME_BYTES);
  if(!Array.isArray(raw.recipients)||raw.recipients.length!==1)fail();
  const recipient=fields(raw.recipients[0],['header','encrypted_key']),rh=fields(recipient.header,['alg','kid','epk']);
  if(rh.alg!=='ECDH-ES+A256KW'||rh.kid!==expected.key_id)mismatch();
  const epk=fields(rh.epk,['kty','crv','x']);if(epk.kty!=='OKP'||epk.crv!=='X25519')fail();
  decode(epk.x,ctx.budget,32,32);decode(recipient.encrypted_key,ctx.budget,40,40);return raw as GeneralJWE;
}
async function encrypt(answer:Buffer,contextPayload:Obj,recipient:Obj,ctx:Context):Promise<Obj>{
  const contextBytes=canonicalOriginalControl(contextPayload,ctx.budget);if(contextBytes.length>MAX_AAD)fail();
  const hash=ctx.budget.hash(answer);ctx.budget.output(FRAME_BYTES);const frame=Buffer.alloc(FRAME_BYTES);
  MAGIC.copy(frame);frame.writeBigUInt64BE(32n,MAGIC.length);frame.write(hash,MAGIC.length+8,'hex');answer.copy(frame,MAGIC.length+40);
  let encrypted:GeneralJWE;
  try{
    const builder=new GeneralEncrypt(frame).setProtectedHeader({enc:'A256GCM',typ:BYTES}).setAdditionalAuthenticatedData(contextBytes);
    // JOSE's single-recipient shortcut moves epk into the protected header.
    // Two wraps to the same authorized key preserve the existing wire profile.
    for(let index=0;index<2;index++)builder.addRecipient(await importJWK({kty:'OKP',crv:'X25519',x:recipient.public_key},'ECDH-ES+A256KW'))
      .setUnprotectedHeader({alg:'ECDH-ES+A256KW',kid:recipient.key_id});
    encrypted=await builder.encrypt();encrypted.recipients=encrypted.recipients.slice(0,1);
  }catch{fail('repair_encryption_failed');}
  return clone(encrypted,ctx);
}
async function decrypt(value:GeneralJWE,identity:Obj,ctx:Context):Promise<Buffer>{
  outputRoom(FRAME_BYTES,ctx.budget);
  let frame:Buffer;
  try{
    const key=await importJWK({kty:'OKP',crv:'X25519',x:identity.public_key,d:identity.private_key,kid:identity.key_id},'ECDH-ES+A256KW');
    const result=await generalDecrypt(value,key,{keyManagementAlgorithms:['ECDH-ES+A256KW'],contentEncryptionAlgorithms:['A256GCM']});
    ctx.budget.output(result.plaintext.length);frame=Buffer.from(result.plaintext);
  }catch(error){if(error instanceof RepairError)throw error;fail('repair_decryption_failed');}
  if(frame.length!==FRAME_BYTES||!equal(frame.subarray(0,MAGIC.length),MAGIC)||frame.readBigUInt64BE(MAGIC.length)!==32n)fail('repair_invalid_nonce');
  ctx.budget.output(32);const answer=Buffer.from(frame.subarray(MAGIC.length+40));
  ctx.budget.output(32);const expected=Buffer.from(ctx.budget.hash(answer),'hex');
  if(!equal(expected,frame.subarray(MAGIC.length+8,MAGIC.length+40)))fail('repair_invalid_nonce');return answer;
}
function held(raw:Uint8Array,ref:RawRef,payload:Obj,ctx:Context):AuthenticatedRepairOriginal{
  return Object.freeze({payload,ref,get raw():Uint8Array{ctx.budget.output(raw.length);return Uint8Array.from(raw);}});
}
function signOriginal(payload:Obj,key:KeyObject,ctx:Context):AuthenticatedRepairOriginal{
  const checked=clone(payload,ctx),proof={schema_version:'universal-memory-message-signature/v1',key_id:checked.signing_key.key_id,
    payload_sha256:ctx.budget.hash(canonicalOriginalControl(checked,ctx.budget))};
  const proofBytes=canonicalOriginalControl(proof,ctx.budget);ctx.budget.output(DOMAIN.length+proofBytes.length);const message=Buffer.concat([DOMAIN,proofBytes]);
  outputRoom(64,ctx.budget);let signature:Buffer;try{signature=sign(null,message,key);}catch{fail('repair_signing_failed');}
  ctx.budget.output(signature.length);
  const result=buildNewWire({payload:checked,proof:{...proof,signature:encode(signature,ctx.budget,false)}},ctx.policy,ctx.budget),raw=result.raw;
  if(raw.length>MAX_RAW)fail();const hash=ctx.budget.hash(raw),ref=rawRef({namespace:'meta',key:hash,raw_sha256:hash,size:raw.length});
  return held(raw,ref,(result.value as Obj).payload,ctx);
}
/** Shared builder math. Callers close their own message schema and bindings. */
export function signBoundedBootstrapOriginal(payload:unknown,signer:unknown,policy:RepairPolicy,budget:RepairBudget):AuthenticatedRepairOriginal{
  const ctx:Context={expected:{},policy,budget,at:0},checked=clone(payload,ctx);
  const descriptor=originalPublicDescriptor(checked.signing_key,budget).value;
  return signOriginal(checked,privateKey(signer,descriptor,ctx).key,ctx);
}
function original(entry:unknown,kind:string,additional:readonly string[],expected:Obj,ctx:Context,validate:(payload:Obj)=>void):AuthenticatedRepairOriginal{
  const input=fields(entry,['raw','ref']);if(!isUint8Array(input.raw)||Reflect.apply(byteLength,input.raw,[])>MAX_RAW)fail();
  const ref=rawRef(input.ref);if(ref.namespace!=='meta')fail();
  const parsed=parseNewWire(input.raw,ctx.policy,ctx.budget),raw=parsed.raw;
  if(raw.length!==ref.size||ctx.budget.hash(raw)!==ref.raw_sha256)fail('repair_ref_mismatch');
  const signed=fields(parsed.value,['payload','proof']),payload=fields(signed.payload,[...COMMON,...BINDING,...additional]);
  if(payload.schema_version!==SCHEMA||payload.kind!==kind)fail();times(payload,ctx);validate(payload);
  verifyBoundedControlSignature(payload,signed.proof,expected,ctx.budget);return held(raw,ref,payload,ctx);
}
function probe(entry:unknown,ctx:Context):AuthenticatedRepairOriginal{
  return original(entry,'bootstrap.probe',['probe_id','selector','target_nonce_jwe'],ctx.expected.subject.signing_key,ctx,payload=>{
    opaque(payload.probe_id);checkBinding(payload,ctx,true);if(!same(payload.selector,ctx.expected.selector))mismatch();
    jwe(payload.target_nonce_jwe,payload,'target_nonce_jwe',ctx.expected.target.encryption_key,ctx);
  });
}
function challenge(entry:unknown,parent:AuthenticatedRepairOriginal,ctx:Context):AuthenticatedRepairOriginal{
  const result=original(entry,'bootstrap.challenge',['challenge_id','probe_ref','target_nonce_answer','caller_nonce_jwe'],ctx.expected.target.signing_key,ctx,payload=>{
    opaque(payload.challenge_id);checkBinding(payload,ctx);rawRef(payload.probe_ref);decode(payload.target_nonce_answer,ctx.budget,32,32);
    jwe(payload.caller_nonce_jwe,payload,'caller_nonce_jwe',ctx.expected.subject.encryption_key,ctx);
  }),payload=result.payload as Obj;
  times(payload,ctx,parent.payload as Obj);if(!same(payload.probe_ref,parent.ref))mismatch();return result;
}
function prepared(original:AuthenticatedRepairOriginal,answer:Buffer,ctx:Context):PreparedBootstrapProbe{
  return Object.freeze({original,get nonce():Uint8Array{ctx.budget.output(32);return Uint8Array.from(answer);}});
}
export async function makeBootstrapProbe(signer:unknown,options:BootstrapProbeOptions&{expiresAt:number}):Promise<PreparedBootstrapProbe>{
  const {args,ctx}=context(options,['expiresAt']),key=privateKey(signer,ctx.expected.subject.signing_key,ctx).key;
  const payload={...base('bootstrap.probe',ctx.expected.subject.signing_key,args.expiresAt,ctx),...binding(ctx,true),
    probe_id:freshId('probe_',ctx),selector:ctx.expected.selector},answer=freshNonce(ctx);
  const encrypted=await encrypt(answer,payload,ctx.expected.target.encryption_key,ctx);
  return prepared(signOriginal({...payload,target_nonce_jwe:encrypted},key,ctx),answer,ctx);
}
export function verifyBootstrapProbe(entry:unknown,options:BootstrapProbeOptions):AuthenticatedRepairOriginal{return probe(entry,context(options).ctx);}
export async function issueBootstrapChallenge(probeEntry:unknown,options:BootstrapProbeOptions&{signer:unknown;encryptionIdentity:unknown;expiresAt:number}):Promise<PreparedBootstrapProbe>{
  const {args,ctx}=context(options,['signer','encryptionIdentity','expiresAt']),parent=probe(probeEntry,ctx);
  const key=privateKey(args.signer,ctx.expected.target.signing_key,ctx).key,local=privateKey(args.encryptionIdentity,ctx.expected.target.encryption_key,ctx,true).value;
  const payload={...base('bootstrap.challenge',ctx.expected.target.signing_key,args.expiresAt,ctx),...binding(ctx),challenge_id:freshId('challenge_',ctx),probe_ref:parent.ref};
  times(payload,ctx,parent.payload as Obj);const targetAnswer=await decrypt((parent.payload as Obj).target_nonce_jwe,local,ctx);
  const contextPayload={...payload,target_nonce_answer:encode(targetAnswer,ctx.budget)},answer=freshNonce(ctx);
  const encrypted=await encrypt(answer,contextPayload,ctx.expected.subject.encryption_key,ctx);
  return prepared(signOriginal({...contextPayload,caller_nonce_jwe:encrypted},key,ctx),answer,ctx);
}
export async function solveBootstrapChallenge(probeEntry:unknown,challengeEntry:unknown,options:BootstrapProbeOptions&{
  signer:unknown;encryptionIdentity:unknown;targetNonce:Uint8Array;expiresAt:number}):Promise<AuthenticatedRepairOriginal>{
  const {args,ctx}=context(options,['signer','encryptionIdentity','targetNonce','expiresAt']),p=probe(probeEntry,ctx),c=challenge(challengeEntry,p,ctx);
  const expected=nonce(args.targetNonce,ctx.budget),received=decode(c.payload.target_nonce_answer,ctx.budget,32,32);
  if(!equal(expected,received))fail('repair_invalid_nonce');
  const key=privateKey(args.signer,ctx.expected.subject.signing_key,ctx).key,local=privateKey(args.encryptionIdentity,ctx.expected.subject.encryption_key,ctx,true).value;
  const payload={...base('bootstrap.answer',ctx.expected.subject.signing_key,args.expiresAt,ctx),...binding(ctx),probe_ref:p.ref,challenge_ref:c.ref};
  times(payload,ctx,c.payload as Obj);const answer=await decrypt((c.payload as Obj).caller_nonce_jwe,local,ctx);
  return signOriginal({...payload,answer:encode(answer,ctx.budget)},key,ctx);
}
export function verifyBootstrapAnswer(probeEntry:unknown,challengeEntry:unknown,answerEntry:unknown,options:BootstrapProbeOptions&{callerNonce:Uint8Array}):AuthenticatedBootstrapAnswer{
  const {args,ctx}=context(options,['callerNonce']),p=probe(probeEntry,ctx),c=challenge(challengeEntry,p,ctx),a=original(answerEntry,'bootstrap.answer',
    ['challenge_ref','probe_ref','answer'],ctx.expected.subject.signing_key,ctx,payload=>{
      checkBinding(payload,ctx);rawRef(payload.probe_ref);rawRef(payload.challenge_ref);decode(payload.answer,ctx.budget,32,32);
    }),payload=a.payload as Obj;
  checkBinding(payload,ctx);times(payload,ctx,c.payload as Obj);
  if(!same(payload.probe_ref,p.ref)||!same(payload.challenge_ref,c.ref))mismatch();
  if(!equal(decode(payload.answer,ctx.budget,32,32),nonce(args.callerNonce,ctx.budget)))fail('repair_invalid_nonce');
  return Object.freeze({originals:Object.freeze({probe:p,challenge:c,answer:a}),at:ctx.at});
}
