/** Native ACK-owner recovery over exact, bounded HTTP originals.
 * Caller-owned keys/authorities and retained status originals are explicit.
 * This returns authenticated source evidence; it writes no Vault or identity.
 */
import {performance} from 'node:perf_hooks';
import {isProxy} from 'node:util/types';
import {OpenHTTPTransport,endpoint} from './open-transport.ts';
import {RepairBudget,RepairError,buildNewWire,objectFields,rawRef,u53,LocalRawResolver,parseNewWire} from './open-repair-wire.ts';
import type {RepairPolicy,RepairWork,RawRef,RawOriginal} from './open-repair-wire.ts';
import {verifyAckOwnerBootstrapOriginal} from './open-repair-bootstrap.ts';
import {verifyAckUnboundSourceEvent} from './open-repair-ack.ts';
import type {AuthenticatedAckUnboundSourceEvent} from './open-repair-ack.ts';
import {parseOriginalControl,verifySourceNodeOriginal} from './open-repair-original.ts';
import {makeBootstrapProbe,solveBootstrapChallenge} from './open-repair-probe.ts';
import {verifyBootstrapProofResponse,makeBootstrapChildRequest} from './open-repair-proof.ts';
import type {AuthenticatedBootstrapProof} from './open-repair-proof.ts';
import {statusScope,verifyStatusOriginal,authenticateStatusOriginal} from './open-repair-status.ts';
import type {AuthenticatedStatusOriginal} from './open-repair-status.ts';

type Obj=Record<string,any>;
const clock=()=>performance.now()/1000;
export const DEFAULT_REPAIR_CLIENT_POLICY:RepairPolicy=Object.freeze({max_document_bytes:524288,max_total_bytes:16000000,
  max_nodes:400000,max_depth:64,max_string_bytes:262144,max_hash_bytes:16000000,max_hashes:2000,max_entries:2000,
  max_retained_bytes:16000000,max_signature_checks:64});
export const DEFAULT_REPAIR_CLIENT_LIMITS=Object.freeze({max_probe_bytes:8192,max_proof_bytes:262144,max_proof_items:64,
  max_signature_checks:512,max_requests:64,max_pending:8,max_replay_records:128,max_concurrent_handles:8,max_candidate_attempts:8});
export interface AckOwnerRecoveryOptions{readonly policy?:RepairPolicy;readonly limitPolicy?:unknown;readonly allowLoopback?:boolean;
  readonly transport?:OpenHTTPTransport;readonly clock?:()=>number;}
export interface AckOwnerRecoverOptions{readonly targetNodeEntry:unknown;readonly expectedTarget:unknown;readonly expectedAckSlot:unknown;
  readonly rootEntry:unknown;readonly readEntry:unknown;readonly bootstrapEntry:unknown;readonly knownStatuses?:readonly unknown[];readonly archiveStatuses?:readonly unknown[];readonly timeout?:number;}
export interface RecoveredAckOwnerProof{readonly source:AuthenticatedAckUnboundSourceEvent;readonly proof:AuthenticatedBootstrapProof;
  readonly current_statuses:readonly AuthenticatedStatusOriginal[];readonly originals:readonly RawOriginal[];
  readonly metrics:Readonly<RepairWork&{requests:number;wire_bytes:number;proof_bytes:number}>;}
interface Obligation{role:string;kind:string;subject:unknown;revision:number;signer:Obj;scope_id:string;}
function fail(code:string):never{throw new RepairError(code);}
function fields(value:unknown,names:readonly string[]):Obj{return objectFields(value,names);}
function options(value:unknown,required:readonly string[],optional:readonly string[]):Obj{
  if(value===null||typeof value!=='object'||isProxy(value))fail('repair_unknown_fields');
  const names=Reflect.ownKeys(value);if(names.some(name=>typeof name!=='string'||![...required,...optional].includes(name)))fail('repair_unknown_fields');
  return fields(value,[...required,...optional.filter(name=>Object.hasOwn(value,name))]);
}
function same(a:unknown,b:unknown):boolean{
  if(a===b)return true;if(a===null||b===null||typeof a!=='object'||typeof b!=='object'||Array.isArray(a)!==Array.isArray(b))return false;
  const names=Object.keys(a);return names.length===Object.keys(b).length&&names.every(name=>Object.hasOwn(b,name)&&same((a as Obj)[name],(b as Obj)[name]));
}
function refKey(ref:RawRef):string{return `${ref.namespace}:${ref.key}:${ref.raw_sha256}:${ref.size}`;}
function scopeKey(item:Obj):string{return item.scope_kind+':'+item.scope_id;}
function checkedStatus(raw:Uint8Array,policy:RepairPolicy,budget:RepairBudget):Obj{
  const signed=fields(parseOriginalControl(raw,policy,budget).value,['payload','proof']);
  const payload=fields(signed.payload,['schema_version','kind','signing_key','scope_key','revision','issued_at','valid_until','entries']);
  if(!Array.isArray(payload.entries)||payload.entries.length<1||payload.entries.length>16)fail('repair_invalid_status');
  for(const item of payload.entries)fields(item,['scope_kind','scope_id','minimum_document_revision','status','operation_mask']);
  return payload;
}
function snapshotEntry(value:unknown,policy:RepairPolicy,budget:RepairBudget,legacy=false):RawOriginal{
  const held=fields(value,['raw','ref']),ref=rawRef(held.ref),document=legacy?parseOriginalControl(held.raw,policy,budget):parseNewWire(held.raw,policy,budget);
  const raw=document.raw;if(ref.namespace!=='meta'||raw.length!==ref.size||budget.hash(raw)!==ref.raw_sha256)fail('repair_ref_mismatch');
  return {raw,ref};
}
export class AckOwnerRecoveryClient{
  readonly #identity:Obj;readonly #encryption:Obj;readonly #subject:Obj;readonly #policy:RepairPolicy;readonly #limits:Obj;
  readonly #transport:OpenHTTPTransport;readonly #allowLoopback:boolean;readonly #clock:()=>number;readonly #ownTransport:boolean;
  constructor(identity:unknown,encryptionIdentity:unknown,value:AckOwnerRecoveryOptions={}){
    const args=options(value,[],['policy','limitPolicy','allowLoopback','transport','clock']);
    const meter=new RepairBudget(args.policy??DEFAULT_REPAIR_CLIENT_POLICY);this.#policy=meter.policy;
    const held=buildNewWire({identity,encryption:encryptionIdentity,limits:args.limitPolicy??DEFAULT_REPAIR_CLIENT_LIMITS},this.#policy,meter).value as Obj;
    this.#identity=fields(held.identity,['schema_version','algorithm','key_id','public_key','private_key']);
    this.#encryption=fields(held.encryption,['schema_version','algorithm','key_id','public_key','private_key']);
    this.#limits=fields(held.limits,Object.keys(DEFAULT_REPAIR_CLIENT_LIMITS));for(const amount of Object.values(this.#limits))u53(amount,1);
    this.#subject=buildNewWire({signing_key:{schema_version:'universal-memory-public-key/v1',algorithm:this.#identity.algorithm,
      key_id:this.#identity.key_id,public_key:this.#identity.public_key},encryption_key:{schema_version:'memory-vault-network-encryption-key/v1',
      algorithm:this.#encryption.algorithm,key_id:this.#encryption.key_id,public_key:this.#encryption.public_key}},this.#policy,meter).value as Obj;
    if(args.allowLoopback!==undefined&&typeof args.allowLoopback!=='boolean')fail('repair_invalid_policy');
    if(args.clock!==undefined&&typeof args.clock!=='function')fail('repair_invalid_policy');
    this.#allowLoopback=args.allowLoopback??false;this.#clock=args.clock??(()=>Date.now()/1000);
    this.#transport=args.transport??new OpenHTTPTransport({allow_loopback:this.#allowLoopback});this.#ownTransport=args.transport===undefined;
    Object.freeze(this);
  }
  close():void{if(this.#ownTransport)this.#transport.close();}
  #now():number{return u53(Math.floor(this.#clock()));}
  async recover(baseUrl:string,value:AckOwnerRecoverOptions):Promise<RecoveredAckOwnerProof>{
    const args=options(value,['targetNodeEntry','expectedTarget','expectedAckSlot','rootEntry','readEntry','bootstrapEntry'],['knownStatuses','archiveStatuses','timeout']);
    const timeout=args.timeout??30;if(typeof timeout!=='number'||!Number.isFinite(timeout)||timeout<=0||timeout>60)fail('repair_invalid_deadline');
    const policy=this.#policy,budget=new RepairBudget(policy),started=this.#now(),deadline=clock()+timeout;
    const expected=buildNewWire({target:args.expectedTarget,slot:args.expectedAckSlot},policy,budget).value as Obj;
    const setup=verifyAckOwnerBootstrapOriginal(args.bootstrapEntry,{root:args.rootEntry,read:args.readEntry},
      {expectedAckSlot:expected.slot,expectedOwner:this.#subject,at:started,limitPolicy:this.#limits,policy,budget});
    const nodeEntry=snapshotEntry(args.targetNodeEntry,policy,budget,true),nodePayload=checkedNodePayload(nodeEntry.raw,policy,budget);
    const node=verifySourceNodeOriginal(nodeEntry.raw,{expectedSigningKey:expected.target.signing_key,expectedStorageEpoch:nodePayload.storage_epoch,at:started,policy,budget});
    if(!same(endpoint(baseUrl,this.#allowLoopback),endpoint(node.payload.base_url,this.#allowLoopback)))fail('repair_proof_mismatch');
    const grant=setup.originals.bootstrap.payload as Obj;
    const expiry=Math.min(started+Math.min(60,Math.max(1,Math.floor(timeout))),grant.probe_until,grant.proof_until,grant.expires_at,
      node.payload.expires_at as number,setup.originals.root.payload.expires_at as number,setup.originals.read.payload.expires_at as number);
    if(expiry<=started)fail('repair_access_expired');
    const history=this.#statusHistory(args.knownStatuses??[],args.archiveStatuses??[],budget);
    const known=this.#known(history,this.#obligations(setup.originals,expected.slot,budget),expected.slot.root_key,expected.target,budget);
    const binding={expectedSubject:this.#subject,expectedTarget:expected.target,targetStorageEpoch:node.payload.storage_epoch as string,
      bootstrapGrantSha256:setup.originals.bootstrap.ref.raw_sha256,selector:grant.selector,policy,budget};
    let requests=0,wireBytes=0,proofBytes=0;
    const request=async(body:Uint8Array,child=false):Promise<Uint8Array>=>{
      if(requests>=grant.limits.max_requests||clock()>=deadline)fail('repair_over_budget');requests++;
      const reply=await this.#transport.requestRepair(baseUrl,body,deadline,{child});wireBytes+=body.length+reply.length;return reply;
    };
    const outgoing=await makeBootstrapProbe(this.#identity,{...binding,at:started,expiresAt:expiry}),outgoingRaw=outgoing.original.raw;
    if(outgoingRaw.length>grant.limits.max_probe_bytes)fail('repair_over_budget');
    const challengeRaw=await request(outgoingRaw),challengeDigest=budget.hash(challengeRaw);
    const challenge={raw:challengeRaw,ref:rawRef({namespace:'meta',key:challengeDigest,raw_sha256:challengeDigest,size:challengeRaw.length})};
    const answer=await solveBootstrapChallenge({raw:outgoingRaw,ref:outgoing.original.ref},challenge,
      {...binding,signer:this.#identity,encryptionIdentity:this.#encryption,targetNonce:outgoing.nonce,at:this.#now(),expiresAt:expiry});
    const response=await request(answer.raw),held=verifyBootstrapProofResponse(response,{expectedSubject:this.#subject,expectedTarget:expected.target,
      targetStorageEpoch:node.payload.storage_epoch as string,selector:grant.selector,bootstrapGrantRef:setup.originals.bootstrap.ref,
      probeRef:outgoing.original.ref,challengeRef:challenge.ref,answerRef:answer.ref,at:this.#now(),maxProofItems:grant.limits.max_proof_items,
      maxProofBytes:grant.limits.max_proof_bytes,policy,budget});
    proofBytes=response.length+held.handle.raw.length+held.manifest.raw.length;
    const originals=new Map<string,RawOriginal>(),roles=new Map<string,RawRef[]>(),manifest=held.manifest.value as Obj;
    for(const item of manifest.children){
      const reference=rawRef(item.ref),key=refKey(reference);roles.set(item.role,[...(roles.get(item.role)??[]),reference]);if(originals.has(key))continue;
      if(reference.size>policy.max_document_bytes||proofBytes+reference.size>grant.limits.max_proof_bytes)fail('repair_over_budget');
      const chunks:Uint8Array[]=[];let offset=0;
      while(offset<reference.size){
        const count=Math.min(65536,reference.size-offset),child=makeBootstrapChildRequest(this.#identity,held,{subject:this.#subject,target:expected.target,
          at:this.#now(),expiresAt:held.handle.payload.expires_at as number,childIndex:item.index,offset,requestedBytes:count,policy,budget});
        const received=await request(child.raw,true);if(received.length!==count)fail('repair_ref_mismatch');budget.input(received.length);chunks.push(received);offset+=count;
      }
      budget.output(reference.size);const assembled=Buffer.concat(chunks);if(budget.hash(assembled)!==reference.raw_sha256)fail('repair_ref_mismatch');
      proofBytes+=assembled.length;originals.set(key,{raw:assembled,ref:reference});
    }
    if(this.#now()>=(held.handle.payload.expires_at as number)||clock()>=deadline)fail('repair_access_expired');
    const entry=(role:string):RawOriginal=>originals.get(refKey(roles.get(role)![0]))!;
    const resolver=new LocalRawResolver(policy,budget);
    for(const reference of roles.get('history.raw_pack')!){const item=originals.get(refKey(reference))!;if(!same(resolver.put(reference.namespace,reference.key,item.raw).ref,reference))fail('repair_ref_mismatch');}
    const source=verifyAckUnboundSourceEvent(entry('history.ack_unbound'),resolver,entry('ack.unbound_custody'),{expectedAckSlot:expected.slot,expectedOwner:this.#subject,
      expectedTarget:expected.target,targetStorageEpoch:node.payload.storage_epoch as string,limitPolicy:this.#limits,policy,budget});
    for(const item of source.manifest.roles){const actual=originals.get(refKey(item.original.ref));if(!same(roles.get(item.role),[item.original.ref])||!actual||!Buffer.from(actual.raw).equals(Buffer.from(item.original.raw)))fail('repair_proof_mismatch');}
    if(!same(source.resources.originals.root.ref,setup.originals.root.ref)||!same(source.resources.originals.read.ref,setup.originals.read.ref)||
      !same(source.bootstrap.originals.bootstrap.ref,setup.originals.bootstrap.ref))fail('repair_proof_mismatch');
    const current=this.#current(source,roles,originals,expected.target,budget,known),now=this.#now();
    if(now>=Math.min(expiry,held.handle.payload.expires_at as number,source.read_until,...current.map(item=>item.payload.valid_until as number))||clock()>=deadline)fail('repair_access_expired');
    // Copy-on-read preserves exact originals against consumer buffer mutation.
    const saved=Object.freeze([...originals.values()].map(item=>Object.freeze({ref:item.ref,get raw(){return Uint8Array.from(item.raw);}})));
    return Object.freeze({source,proof:held,current_statuses:Object.freeze(current),originals:saved,
      metrics:Object.freeze({requests,wire_bytes:wireBytes,proof_bytes:proofBytes,...budget.snapshot()})});
  }
  #obligations(originals:Obj,slot:Obj,budget:RepairBudget):Obligation[]{
    const root=slot.root_key,result:Obligation[]=[];
    for(const [name,role,kind] of [['root','current.status.ack_root','ack.root_authority'],['read','current.status.ack_read','ack.read_grant'],['bootstrap','current.status.ack_owner_bootstrap','bootstrap.grant']]){
      const item=originals[name],subject={authority_kind:kind,authority_sha256:item.ref.raw_sha256};
      result.push({role,kind:'authority',subject,revision:item.payload.revision,signer:this.#subject.signing_key,scope_id:statusScope(root,'authority',subject,this.#policy,budget)});
    }
    result.push({role:'current.status.ack_slot',kind:'ack_slot',subject:slot,revision:originals.root.payload.revision,
      signer:this.#subject.signing_key,scope_id:statusScope(root,'ack_slot',slot,this.#policy,budget)});return result;
  }
  #statusHistory(known:unknown,archive:unknown,budget:RepairBudget):RawOriginal[]{
    // Both sets remain signed evidence. Archive entries carry old conflict
    // witnesses as well as revocation/floor observations; no summary is trusted.
    const merged=new Map<string,RawOriginal>();
    for(const [values,maximum] of [[known,16],[archive,32]] as const){
      if(!Array.isArray(values)||isProxy(values))fail('repair_invalid_status');
      if(values.length>maximum)fail(maximum===16?'repair_invalid_status':'repair_status_history_capacity');
      const descriptors=Object.getOwnPropertyDescriptors(values);
      for(let index=0;index<values.length;index++){
        if(!descriptors[index]||!Object.hasOwn(descriptors[index],'value'))fail('repair_invalid_status');
        const item=snapshotEntry(descriptors[index].value,this.#policy,budget,true),key=refKey(item.ref),previous=merged.get(key);
        if(previous){if(!Buffer.from(previous.raw).equals(Buffer.from(item.raw)))fail('repair_ref_conflict');continue;}
        if(merged.size>=32)fail('repair_status_history_capacity');merged.set(key,item);
      }
    }
    return [...merged.values()];
  }
  #known(values:unknown,obligations:Obligation[],root:Obj,target:Obj,budget:RepairBudget):AuthenticatedStatusOriginal[]{
    // Copy raw entries before the first asynchronous operation.
    if(!Array.isArray(values)||isProxy(values)||values.length>32)fail('repair_invalid_status');
    const descriptors=Object.getOwnPropertyDescriptors(values);for(let index=0;index<values.length;index++)if(!descriptors[index]||!Object.hasOwn(descriptors[index],'value'))fail('repair_invalid_status');
    const checked:AuthenticatedStatusOriginal[]=[];
    for(let index=0;index<values.length;index++){
      const item=snapshotEntry(descriptors[index].value,this.#policy,budget,true),payload=checkedStatus(item.raw,this.#policy,budget);
      const issuer=fields(payload.scope_key,['root_key','issuer_key_id']).issuer_key_id,issued=u53(payload.issued_at);
      if(issued>this.#now()+30)fail('repair_status_mismatch');let signer:Obj,allowed:Obj[];
      if(issuer===this.#subject.signing_key.key_id){signer=this.#subject.signing_key;allowed=obligations.map(v=>({scope_kind:v.kind,scope_id:v.scope_id}));
        if(issuer===target.signing_key.key_id)allowed.push(...payload.entries.filter((v:Obj)=>v.scope_kind==='resource').map((v:Obj)=>({scope_kind:v.scope_kind,scope_id:v.scope_id})));}
      else if(issuer===target.signing_key.key_id){signer=target.signing_key;if(payload.entries.some((v:Obj)=>v.scope_kind!=='resource'))fail('repair_status_disclosure');allowed=payload.entries.map((v:Obj)=>({scope_kind:v.scope_kind,scope_id:v.scope_id}));}
      else fail('repair_status_mismatch');
      checked.push(authenticateStatusOriginal(item,{expectedRoot:root,expectedSigningKey:signer,at:issued,allowedScopes:allowed,policy:this.#policy,budget}));
    }
    this.#floors(checked,[],obligations,true);return checked;
  }
  #floors(known:readonly AuthenticatedStatusOriginal[],current:readonly AuthenticatedStatusOriginal[],obligations:Obligation[],probePhase=false):void{
    const seen=new Map<string,string>(),floors=new Map<string,[number,number][]>(),required=new Map(obligations.map(v=>[v.signer.key_id+':'+v.kind+':'+v.scope_id,v]));
    for(const observed of [...known,...current]){
      const payload=observed.payload as Obj,issuer=payload.scope_key.issuer_key_id,revision=payload.revision,id=issuer+':'+revision;
      if(seen.has(id)&&seen.get(id)!==observed.canonical_sha256)fail('repair_status_conflict');seen.set(id,observed.canonical_sha256);
      for(const entry of payload.entries){const key=issuer+':'+scopeKey(entry),wanted=required.get(key),mask=probePhase&&wanted&&['current.status.ack_root','current.status.ack_owner_bootstrap'].includes(wanted.role)?10:2;
        if(entry.status==='revoked'&&(entry.operation_mask&mask))fail('repair_authority_revoked');
        if(wanted&&entry.minimum_document_revision>wanted.revision)fail('repair_status_revision');
        floors.set(key,[...(floors.get(key)??[]),[revision,entry.minimum_document_revision]]);
      }
    }
    for(const values of floors.values()){let minimum=0;for(const [,floor] of values.sort((a,b)=>a[0]-b[0]||a[1]-b[1])){if(floor<minimum)fail('repair_status_rollback');minimum=floor;}}
    for(const observed of current){const payload=observed.payload as Obj;for(const entry of payload.entries){const values=floors.get(payload.scope_key.issuer_key_id+':'+scopeKey(entry))!;
      if(payload.revision<Math.max(...values.map(v=>v[0])))fail('repair_status_rollback');}}
  }
  #current(source:AuthenticatedAckUnboundSourceEvent,roles:Map<string,RawRef[]>,originals:Map<string,RawOriginal>,target:Obj,budget:RepairBudget,known:AuthenticatedStatusOriginal[]):AuthenticatedStatusOriginal[]{
    const slot=source.custody.payload.ack_slot as Obj,root=slot.root_key,policy=this.#policy;
    const obligations=this.#obligations({...source.resources.originals,bootstrap:source.bootstrap.originals.bootstrap},slot,budget),active=source.resources.originals.active.payload as Obj;
    obligations.push({role:'current.status.ack_resource',kind:'resource',subject:active.resource,revision:active.reservation_generation,signer:target.signing_key,scope_id:statusScope(root,'resource',active.resource,policy,budget)});
    const permitted=new Set(obligations.map(v=>v.signer.key_id+':'+v.kind+':'+v.scope_id));
    for(const observed of known){const p=observed.payload as Obj;if(p.entries.some((v:Obj)=>!permitted.has(p.scope_key.issuer_key_id+':'+scopeKey(v))))fail('repair_status_disclosure');}
    const groups=new Map<string,{ref:RawRef;signer:Obj;required:Obj[]}>();
    for(const item of obligations){const ref=roles.get(item.role)![0],key=refKey(ref),group=groups.get(key)??{ref,signer:item.signer,required:[]};
      if(!same(group.signer,item.signer))fail('repair_proof_mismatch');group.required.push({scope_kind:item.kind,scope_id:item.scope_id,document_revision:item.revision,operation_mask:2});groups.set(key,group);}
    const checked:AuthenticatedStatusOriginal[]=[];
    for(const [key,group] of groups){
      const allowed=obligations.filter(v=>same(v.signer,group.signer)),entry=originals.get(key)!,payload=checkedStatus(entry.raw,policy,budget),present=new Set(payload.entries.map(scopeKey)),required=new Map(group.required.map(v=>[scopeKey(v),v]));
      for(const item of allowed)if(present.has(item.kind+':'+item.scope_id))required.set(item.kind+':'+item.scope_id,{scope_kind:item.kind,scope_id:item.scope_id,document_revision:item.revision,operation_mask:2});
      checked.push(verifyStatusOriginal(entry,{expectedRoot:root,expectedSigningKey:group.signer,at:this.#now(),allowedScopes:allowed.map(v=>({scope_kind:v.kind,scope_id:v.scope_id})),required:[...required.values()],policy,budget}));
    }
    this.#floors([...source.statuses,...known],checked,obligations);return checked;
  }
}
function checkedNodePayload(raw:Uint8Array,policy:RepairPolicy,budget:RepairBudget):Obj{return fields(parseOriginalControl(raw,policy,budget).value,['payload','proof']).payload;}
