/** Read and decrypt a complete mailbox directory through an authorized reader.
 * Enumeration alone grants no message access; each admission still needs its
 * original authority, source history and current status before object reads. */
import {isUint8Array} from 'node:util/types';
import {buildNewWire,parseNewWire,objectFields,rawRef,u53,RepairError} from './open-repair-wire.ts';
import type {RepairPolicy,RepairBudget,RawRef} from './open-repair-wire.ts';
import {verifyBoundedControlSignature} from './open-repair-original.ts';
import {emptyMailboxState,appendMailboxState} from './open-repair-mailbox-range.ts';
import {decryptBytes,validateEncryptionIdentity} from './crypto.ts';
import type {EncryptionIdentityDocument} from './crypto.ts';
type Obj=Record<string,any>;
export interface MailboxIndexReadOptions{
  readonly expectedSlot:unknown;readonly expectedSigningKey:unknown;readonly encryptionIdentity:EncryptionIdentityDocument;
  readonly readOriginal:(reference:RawRef)=>Uint8Array|Promise<Uint8Array>;
  readonly at:number;readonly maxMessages:number;readonly policy:RepairPolicy;readonly budget:RepairBudget;
}
function fail(code='repair_mailbox_range_mismatch'):never{throw new RepairError(code);}
const fields=(v:unknown,n:readonly string[]):Obj=>objectFields(v,n);
function same(a:unknown,b:unknown):boolean{if(a===b)return true;if(!a||!b||typeof a!=='object'||typeof b!=='object'||Array.isArray(a)!==Array.isArray(b))return false;const keys=Object.keys(a);return keys.length===Object.keys(b).length&&keys.every(k=>Object.hasOwn(b,k)&&same((a as Obj)[k],(b as Obj)[k]));}
export async function readMailboxIndex(headEntry:unknown,checkpointEntry:unknown,options:MailboxIndexReadOptions):Promise<readonly Obj[]>{
  const a=fields(options,['expectedSlot','expectedSigningKey','encryptionIdentity','readOriginal','at','maxMessages','policy','budget']),{policy,budget}=a;
  const e=buildNewWire({slot:a.expectedSlot,key:a.expectedSigningKey,at:a.at,max:a.maxMessages,identity:a.encryptionIdentity},policy,budget).value as Obj;
  const reader=a.readOriginal;u53(e.at);u53(e.max,1);if(e.max>65536||typeof reader!=='function')fail('repair_invalid_context');
  validateEncryptionIdentity(e.identity);const identity=e.identity as EncryptionIdentityDocument;
  const checked=(raw:unknown,reference:unknown):Obj=>{const ref=rawRef(reference),doc=parseNewWire(raw as Uint8Array,policy,budget),held=doc.raw;
    if(ref.namespace!=='meta'||held.length!==ref.size||budget.hash(held)!==ref.raw_sha256)fail('repair_ref_mismatch');return doc.value as Obj;};
  const event=(entry:unknown,kind:string,names:string):Obj=>{const v=fields(entry,['raw','ref']),signed=fields(checked(v.raw,v.ref),['payload','proof']);
    const p=fields(signed.payload,['schema_version','kind','signing_key','slot_key','committed_at','retain_until',...names.split(' ')]);
    if(p.schema_version!=='memory-vault-open-repair/v1'||p.kind!==kind||!same(p.slot_key,e.slot))fail();
    verifyBoundedControlSignature(p,signed.proof,e.key,budget);if(!(u53(p.committed_at)<=e.at&&e.at<u53(p.retain_until)))fail('repair_resource_expired');return p;};
  const head=event(headEntry,'mailbox.feed_head','checkpoint_ref count range_root_ref catalog_generation'),cp=event(checkpointEntry,'mailbox.checkpoint','slot_binding count leaf_root frontier'),count=u53(head.count);
  u53(head.catalog_generation);
  if(count>e.max||count!==cp.count||!same(head.checkpoint_ref,fields(checkpointEntry,['raw','ref']).ref)||head.committed_at!==cp.committed_at||head.retain_until!==cp.retain_until)fail();
  const state=Object.fromEntries(['slot_binding','count','leaf_root','frontier'].map(n=>[n,cp[n]]));
  let accumulated=emptyMailboxState(e.slot,policy,budget);const entries:Obj[]=[],seen=new Set<string>();
  const load=async(reference:unknown):Promise<Obj>=>{const ref=rawRef(reference);if(ref.namespace!=='meta')fail('repair_ref_mismatch');if(seen.has(ref.key))fail();seen.add(ref.key);return checked(await reader(ref),ref);};
  const walk=async(reference:unknown,level:number,start:number,end:number):Promise<void>=>{
    const value=fields(await load(reference),['schema_version','kind','slot_key','start','end',...(level>=0?['level','children']:['sealed_page_ref','entries'])]);
    if(value.schema_version!=='memory-vault-open-repair/v1'||!same(value.slot_key,e.slot)||u53(value.start)!==start||u53(value.end)!==end)fail();
    if(level>=0){
      if(value.kind!=='range.index'||u53(value.level)!==level||!Array.isArray(value.children)||value.children.length<1||value.children.length>16)fail();let cursor=start;const span=16**(level+1);
      for(const child of value.children){fields(child,['start','end','ref']);const stop=Math.min(cursor+span,end);if(u53(child.start)!==cursor||u53(child.end)!==stop||stop<=cursor)fail();await walk(child.ref,level-1,cursor,stop);cursor=stop;}
      if(cursor!==end)fail();return;
    }
    if(value.kind!=='range.repair_page'||!Array.isArray(value.entries)||value.entries.length!==end-start||end-start<1||end-start>16)fail();
    for(let i=0;i<value.entries.length;i++){const row=fields(value.entries[i],['sequence','admission_link_ref','sealed_core_ref']);if(u53(row.sequence)!==start+i)fail();for(const n of ['admission_link_ref','sealed_core_ref'])if(rawRef(row[n]).namespace!=='meta')fail('repair_ref_mismatch');}
    const privateRaw=buildNewWire({schema_version:'memory-vault-open-repair/v1',kind:'range.private_page',slot_key:e.slot,start,end,entries:value.entries},policy,budget).raw;
    const context={schema_version:'memory-vault-open-repair/v1',kind:'range.sealed_page',slot_key:e.slot,start,end,plaintext_sha256:budget.hash(privateRaw),plaintext_size:privateRaw.length};
    const sealed=await load(value.sealed_page_ref);if(!Array.isArray(sealed.recipients)||sealed.recipients.length!==1)fail();let plain:Uint8Array;
    try{plain=await decryptBytes(sealed,identity,{context});}catch{fail();}
    budget.output(plain.length);if(plain.length!==privateRaw.length||plain.some((v,i)=>v!==privateRaw[i]))fail();
    for(const row of value.entries){accumulated=appendMailboxState(accumulated,row.sealed_core_ref.raw_sha256,e.slot,policy,budget);entries.push(row);}
  };
  if(count){let level=0;while(count>16**(level+2))level++;await walk(head.range_root_ref,level,0,count);}
  else if(head.range_root_ref!==null)fail();
  if(!same(accumulated,state))fail();return Object.freeze(entries);
}

import {LocalRawResolver} from './open-repair-wire.ts';
import {parseHistoricalManifest} from './open-repair-history.ts';
import {verifyMailboxMemberInputs} from './open-repair-mailbox-member.ts';
import {verifyMailboxInclusion} from './open-repair-mailbox-range.ts';
import {authenticateStatusOriginal} from './open-repair-status.ts';
import type {AuthenticatedStatusOriginal} from './open-repair-status.ts';
export interface MailboxAdmissionReadOptions extends Omit<MailboxIndexReadOptions,'maxMessages'>{
  readonly expectedOwner:unknown;readonly expectedSender:unknown;readonly expectedTarget:unknown;readonly limitPolicy:unknown;
  readonly currentStatuses:readonly unknown[];readonly knownStatuses:readonly unknown[];readonly statusObligations:readonly unknown[];
  readonly onStatusAuthenticated?: (item:AuthenticatedStatusOriginal)=>void;
}
function currentRead(setup:Obj,entries:readonly unknown[],known:readonly unknown[],additional:readonly unknown[],at:number,
  policy:RepairPolicy,budget:RepairBudget,onAuthenticated?: (item:AuthenticatedStatusOriginal)=>void):readonly AuthenticatedStatusOriginal[]{
  if(!Array.isArray(entries)||entries.length<1||entries.length>16||!Array.isArray(known)||known.length>32||!Array.isArray(additional)||additional.length>80||
    (onAuthenticated!==undefined&&typeof onAuthenticated!=='function'))fail('repair_invalid_status');
  const root=setup.originals.slot.payload.slot_key.root_key;
  const obligations=setup.obligations.map((v:Obj)=>({...v,operation_mask:v.role==='destination'?0:v.role==='bootstrap'?10:2}));
  for(const n of ['read','maintenance'])if((setup.originals[n].payload.operation_mask&2)!==2)fail('repair_authority_revoked');
  if((setup.disclosure.operation_mask&2)!==2)fail('repair_authority_revoked');
  const required=new Map<string,Obj>(obligations.map((v:Obj)=>[[v.signer.key_id,v.scope_kind,v.scope_id].join(':'),v]));
  const added=buildNewWire(additional,policy,budget).value as Obj[];
  for(const duty of added){fields(duty,['role','scope_kind','scope_id','document_revision','operation_mask','signer']);fields(duty.signer,['schema_version','algorithm','key_id','public_key']);}
  const disclosed=[...obligations,...added];
  const authenticate=(entry:unknown,current:boolean):AuthenticatedStatusOriginal=>{const v=fields(entry,['raw','ref']),preview=fields(parseNewWire(v.raw,policy,budget).value,['payload','proof']).payload;
    if(!preview||!preview.scope_key)fail('repair_invalid_status');const issuer=preview.scope_key.issuer_key_id,permitted=disclosed.filter(v=>v.signer.key_id===issuer);
    if(!permitted.length||u53(preview.issued_at)>at)fail('repair_status_mismatch');
    const scopes=new Map<string,Obj>();for(const duty of permitted)scopes.set(duty.scope_kind+':'+duty.scope_id,{scope_kind:duty.scope_kind,scope_id:duty.scope_id});
    return authenticateStatusOriginal(v,{expectedRoot:root,expectedSigningKey:permitted[0].signer,at:current?at:preview.issued_at,
      allowedScopes:[...scopes].sort(([a],[b])=>a<b?-1:a>b?1:0).map(([,v])=>v),policy,budget},onAuthenticated);};
  const retained=[...setup.statuses,...known.map(v=>authenticate(v,false))],current=entries.map(v=>authenticate(v,true));
  const seen=new Map<string,string>(),floors=new Map<string,number[][]>(),covered=new Set<string>();
  for(const observed of [...retained,...current]){const p=observed.payload,issuer=p.scope_key.issuer_key_id,revision=p.revision,id=issuer+':'+revision;
    if(seen.has(id)&&seen.get(id)!==observed.canonical_sha256)fail('repair_status_conflict');seen.set(id,observed.canonical_sha256);
    for(const row of p.entries){const key=[issuer,row.scope_kind,row.scope_id].join(':'),wanted=required.get(key);if(!wanted)continue;
      const mask=wanted.operation_mask;if(row.status==='revoked'&&(row.operation_mask&mask))fail('repair_authority_revoked');
      if(mask&&row.minimum_document_revision>wanted.document_revision)fail('repair_status_revision');
      const held=floors.get(key)??[];held.push([revision,row.minimum_document_revision]);floors.set(key,held);}
  }
  for(const values of floors.values()){let minimum=0;for(const [,floor] of values.sort((a,b)=>a[0]-b[0]||a[1]-b[1])){if(floor<minimum)fail('repair_status_rollback');minimum=floor;}}
  for(const observed of current){const p=observed.payload as Obj,issuer=p.scope_key.issuer_key_id;
    for(const row of p.entries){const key=[issuer,row.scope_kind,row.scope_id].join(':'),wanted=required.get(key);if(!wanted)continue;
      if(floors.get(key)!.some(v=>v[0]>p.revision))fail('repair_status_rollback');
      const mask=wanted.operation_mask;if(mask&&row.status==='active'&&(row.operation_mask&mask)===mask)covered.add(key);}}
  const expected=[...required].filter(([,v])=>v.operation_mask).map(([k])=>k);if(covered.size!==expected.length||expected.some(k=>!covered.has(k)))fail('repair_status_missing');
  return Object.freeze(current);
}
/** Authenticate/decrypt metadata and check present authority before fetching
 * the envelope. The enclosing verified feed determines which member to select. */
export async function readMailboxAdmission(member:unknown,options:MailboxAdmissionReadOptions):Promise<Readonly<Obj>>{
  const metadata=await verifyMailboxAdmissionMetadata(member,options);
  const {policy,budget}=options;
  const statuses=currentRead(metadata.setup,options.currentStatuses,options.knownStatuses,options.statusObligations,options.at,policy,budget,options.onStatusAuthenticated);
  const ref=rawRef(metadata.core.envelope_ref),raw=await options.readOriginal(ref);
  if(!isUint8Array(raw)||ref.namespace!=='object'||ref.size>6291456||raw.length!==ref.size||budget.hash(raw)!==ref.raw_sha256)fail('repair_ref_mismatch');
  budget.input(raw.length);budget.retain(raw.length);const envelope=Uint8Array.from(raw);
  return Object.freeze({...metadata,current_statuses:statuses,originals:Object.freeze([...metadata.originals,{ref,raw:envelope}]),get envelope(){budget.output(envelope.length);return Uint8Array.from(envelope);}});
}
/** Original source authentication and recipient decryption, without asserting
 * current source READ. Replica callers must establish independent live READ
 * before fetching the envelope; this function performs no object fetch. */
export async function verifyMailboxAdmissionMetadata(member:unknown,options:MailboxAdmissionReadOptions):Promise<Readonly<Obj>>{
  const names=['expectedSlot','expectedSigningKey','encryptionIdentity','readOriginal','at','policy','budget','expectedOwner','expectedSender','expectedTarget','limitPolicy','currentStatuses','knownStatuses','statusObligations'];
  const a=fields(options,Object.hasOwn(options,'onStatusAuthenticated')?[...names,'onStatusAuthenticated']:names),{policy,budget}=a;
  const e=buildNewWire({slot:a.expectedSlot,key:a.expectedSigningKey,owner:a.expectedOwner,sender:a.expectedSender,target:a.expectedTarget,limits:a.limitPolicy,at:a.at,identity:a.encryptionIdentity,member},policy,budget).value as Obj;
  if(typeof a.readOriginal!=='function')fail('repair_invalid_context');u53(e.at);validateEncryptionIdentity(e.identity);
  if(!same(e.key,e.target.signing_key))fail('repair_mailbox_member_mismatch');
  const item=fields(e.member,['sequence','admission_link_ref','sealed_core_ref']),sequence=u53(item.sequence);if(sequence>=65536)fail('repair_invalid_context');
  const originals=new Map<string,{ref:RawRef;raw:Uint8Array}>();
  const load=async(reference:unknown,namespace='meta'):Promise<Uint8Array>=>{const ref=rawRef(reference);if(ref.namespace!==namespace||(namespace==='object'&&ref.size>6291456))fail('repair_ref_mismatch');
    const input=await a.readOriginal(ref);let size:number;try{size=Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint8Array.prototype),'byteLength')!.get!.call(input);}catch{fail('repair_invalid_bytes');}
    if(size!==ref.size)fail('repair_ref_mismatch');budget.input(size);budget.retain(size);if(!isUint8Array(input))fail('repair_invalid_bytes');
    const proto=Object.getPrototypeOf(Uint8Array.prototype),buffer=Object.getOwnPropertyDescriptor(proto,'buffer')!.get!.call(input),offset=Object.getOwnPropertyDescriptor(proto,'byteOffset')!.get!.call(input);
    const raw=Uint8Array.from(Buffer.from(buffer,offset,size));
    if(budget.hash(raw)!==ref.raw_sha256)fail('repair_ref_mismatch');const key=ref.namespace+':'+ref.key,prior=originals.get(key);if(prior&&!same(prior.ref,ref))fail('repair_ref_mismatch');originals.set(key,{ref,raw});return raw;};
  const event=async(reference:unknown,kind:string,names:string):Promise<[Uint8Array,Obj]>=>{const raw=await load(reference),signed=fields(parseNewWire(raw,policy,budget).value,['payload','proof']);
    const p=fields(signed.payload,['schema_version','kind','signing_key','slot_key',...names.split(' ')]);
    if(p.schema_version!=='memory-vault-open-repair/v1'||p.kind!==kind||!same(p.slot_key,e.slot))fail('repair_mailbox_member_mismatch');verifyBoundedControlSignature(p,signed.proof,e.key,budget);return [raw,p];};
  const [,link]=await event(item.admission_link_ref,'admission.link','sequence message_id envelope_ref core_ref sealed_core_ref historical_manifest_ref checkpoint_ref inclusion_path');
  if(u53(link.sequence)!==sequence||!same(link.sealed_core_ref,item.sealed_core_ref))fail('repair_mailbox_member_mismatch');
  const [coreRaw,core]=await event(link.core_ref,'admission.core','core_id sequence message_id envelope_ref attempt_ref historical_manifest_ref data_resource_ref metadata_resource_ref accepted_at object_until enum_until');
  for(const id of [core.core_id,core.message_id])if(typeof id!=='string'||/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.exec(id)?.[0]!==id)fail('repair_mailbox_member_mismatch');
  if(u53(core.sequence)!==sequence||['message_id','envelope_ref','historical_manifest_ref'].some(n=>!same(core[n],link[n]))||!(u53(core.accepted_at)<=e.at&&e.at<u53(core.object_until)&&core.object_until<=u53(core.enum_until)))fail('repair_mailbox_member_mismatch');
  const context={schema_version:'memory-vault-open-repair/v1',kind:'admission.sealed_core',slot_key:e.slot,sequence,plaintext_sha256:link.core_ref.raw_sha256,plaintext_size:coreRaw.length};
  const sealed=parseNewWire(await load(item.sealed_core_ref),policy,budget).value as Obj;
  if(!Array.isArray(sealed.recipients)||sealed.recipients.length!==1)fail('repair_mailbox_member_mismatch');let plain:Uint8Array;
  try{plain=await decryptBytes(sealed,e.identity,{context});}catch{fail('repair_mailbox_member_mismatch');}
  budget.output(plain.length);if(plain.length!==coreRaw.length||plain.some((v,i)=>v!==coreRaw[i]))fail('repair_mailbox_member_mismatch');
  const [,checkpoint]=await event(link.checkpoint_ref,'mailbox.checkpoint','slot_binding count leaf_root frontier committed_at retain_until');
  if(u53(checkpoint.count)!==sequence+1||!(core.accepted_at<=u53(checkpoint.committed_at)&&checkpoint.committed_at<=e.at)||u53(checkpoint.retain_until)<core.enum_until)fail('repair_mailbox_member_mismatch');
  verifyMailboxInclusion(Object.fromEntries(['slot_binding','count','leaf_root','frontier'].map(n=>[n,checkpoint[n]])),sequence,item.sealed_core_ref.raw_sha256,link.inclusion_path,e.slot,policy,budget);
  const manifestRaw=await load(core.historical_manifest_ref),manifest=parseHistoricalManifest(manifestRaw,policy,budget),m=manifest.value as Obj;
  if(m.variant!=='mailbox_member'||!same(m.root_key,e.slot.root_key)||!same(m.slot_key,e.slot)||['message_id','envelope_ref','attempt_ref'].some(n=>!same(m[n],core[n])))fail('repair_mailbox_member_mismatch');
  const resolver=new LocalRawResolver(policy,budget),packs=new Map<string,RawRef>();
  for(const row of m.roles){const ref=rawRef(row.pack_ref),prior=packs.get(ref.key);if(prior&&!same(prior,ref))fail('repair_ref_mismatch');if(!prior){resolver.put('meta',ref.key,await load(ref));packs.set(ref.key,ref);}}
  const setup=verifyMailboxMemberInputs({raw:manifestRaw,ref:core.historical_manifest_ref},resolver,{expectedSlot:e.slot,expectedOwner:e.owner,expectedSender:e.sender,expectedTarget:e.target,targetStorageEpoch:e.slot.writer_storage_epoch,acceptedAt:core.accepted_at,limitPolicy:e.limits,policy,budget});
  for(const n of ['data','metadata'])if(!same(core[n+'_resource_ref'],setup.resources[n].active.payload.resource))fail('repair_mailbox_member_mismatch');
  const deadlines=[setup.disclosure.consent_until,setup.disclosure.bootstrap_return.until,setup.destination.windows.retain_until];
  for(const n of ['slot','read','maintenance','bootstrap']){const p=setup.originals[n].payload;deadlines.push(p.expires_at);if(p.windows)deadlines.push(p.windows.read_until,p.windows.retain_until);if(n==='bootstrap')deadlines.push(p.probe_until,p.proof_until,p.upload_until);}
  for(const n of ['data','metadata']){const p=setup.resources[n].active.payload;deadlines.push(p.windows.read_until,p.windows.retain_until);}
  if(core.enum_until>Math.min(...deadlines))fail('repair_mailbox_member_mismatch');
  const retained=Object.freeze([...originals.values()].map(v=>Object.freeze({ref:v.ref,get raw(){budget.output(v.raw.length);return Uint8Array.from(v.raw);}})));
  return Object.freeze({core,link,checkpoint,setup,history:manifest,originals:retained});
}
