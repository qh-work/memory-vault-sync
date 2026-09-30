/** Native receipt-writer preflight over independently authorized empty sources.
 * This reads original source evidence only; it does not authorize or upload a receipt.
 */
import {performance} from 'node:perf_hooks';
import {isProxy} from 'node:util/types';
import {OpenHTTPTransport,endpoint} from './open-transport.ts';
import {RepairBudget,RepairError,buildNewWire,objectFields,rawRef,u53,LocalRawResolver,parseNewWire} from './open-repair-wire.ts';
import type {RepairPolicy,RawRef,RawOriginal} from './open-repair-wire.ts';
import {verifyAckOfferBootstrapOriginal} from './open-repair-bound.ts';
import {DEFAULT_REPAIR_CLIENT_POLICY,DEFAULT_REPAIR_CLIENT_LIMITS} from './open-repair-client.ts';
import type {AckOwnerRecoveryOptions,RecoveredAckOwnerEmptyProof} from './open-repair-client.ts';
import {verifyAckEmptySourceEvent} from './open-repair-empty.ts';
import type {AuthenticatedAckEmptySourceEvent} from './open-repair-empty.ts';
import {parseOriginalControl,verifySourceNodeOriginal,verifyBoundedControlSignature} from './open-repair-original.ts';
import {makeBootstrapProbe,solveBootstrapChallenge} from './open-repair-probe.ts';
import {verifyBootstrapProofResponse,makeBootstrapChildRequest} from './open-repair-proof.ts';
import {statusScope,verifyStatusOriginal,authenticateStatusOriginal} from './open-repair-status.ts';
import type {AuthenticatedStatusOriginal} from './open-repair-status.ts';

type Obj=Record<string,any>;
const clock=()=>performance.now()/1000;
export interface AckOfferOptions {
  readonly targetNodeEntry:unknown;readonly expectedTarget:unknown;readonly expectedAckSlot:unknown;
  readonly expectedOwner:unknown;readonly expectedMessageId:string;readonly expectedEnvelopeRef:unknown;
  readonly rootEntry:unknown;readonly writeEntry:unknown;readonly bootstrapEntry:unknown;
  readonly knownStatuses?:readonly unknown[];readonly archiveStatuses?:readonly unknown[];readonly timeout?:number;
}
export type PreparedAckOffer=RecoveredAckOwnerEmptyProof;
interface Obligation{role:string|null;kind:string;subject:unknown;revision:number;signer:Obj;scope_id:string;mask?:number;}
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
export class AckOfferClient{
  readonly #identity:Obj;readonly #encryption:Obj;readonly #subject:Obj;readonly #policy:RepairPolicy;readonly #limits:Obj;
  readonly #statusObserver?: (item:AuthenticatedStatusOriginal)=>void;
  readonly #transport:OpenHTTPTransport;readonly #allowLoopback:boolean;readonly #clock:()=>number;readonly #ownTransport:boolean;
  constructor(identity:unknown,encryptionIdentity:unknown,value:AckOwnerRecoveryOptions={}){
    const args=options(value,[],['policy','limitPolicy','allowLoopback','transport','clock','statusObserver']);
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
    if(args.statusObserver!==undefined&&typeof args.statusObserver!=='function')fail('repair_invalid_policy');
    this.#allowLoopback=args.allowLoopback??false;this.#clock=args.clock??(()=>Date.now()/1000);
    this.#transport=args.transport??new OpenHTTPTransport({allow_loopback:this.#allowLoopback});this.#ownTransport=args.transport===undefined;
    this.#statusObserver=args.statusObserver;
    Object.freeze(this);
  }
  close():void{if(this.#ownTransport)this.#transport.close();}
  #now():number{return u53(Math.floor(this.#clock()));}
  async preflight(baseUrl:string,value:AckOfferOptions):Promise<PreparedAckOffer>{
    const args=options(value,['targetNodeEntry','expectedTarget','expectedAckSlot','expectedOwner','expectedMessageId',
      'expectedEnvelopeRef','rootEntry','writeEntry','bootstrapEntry'],['knownStatuses','archiveStatuses','timeout']);
    const timeout=args.timeout??30;if(typeof timeout!=='number'||!Number.isFinite(timeout)||timeout<=0||timeout>60)fail('repair_invalid_deadline');
    const policy=this.#policy,budget=new RepairBudget(policy),started=this.#now(),deadline=clock()+timeout;
    const expected=buildNewWire({target:args.expectedTarget,slot:args.expectedAckSlot,owner:args.expectedOwner,
      message:args.expectedMessageId,envelope:args.expectedEnvelopeRef},policy,budget).value as Obj;
    const checks=new OfferStatusChecks(expected.owner,policy,this.#clock,this.#statusObserver);
    const history=checks.history(args.knownStatuses??[],args.archiveStatuses??[],budget);
    const setup=verifyAckOfferBootstrapOriginal(args.bootstrapEntry,{root:args.rootEntry,write:args.writeEntry},
      {expectedAckSlot:expected.slot,expectedOwner:expected.owner,expectedReceiptWriter:this.#subject,
        expectedMessageId:expected.message,expectedEnvelopeRef:expected.envelope,at:started,limitPolicy:this.#limits,policy,budget});
    const nodeEntry=snapshotEntry(args.targetNodeEntry,policy,budget,true),nodePayload=checkedNodePayload(nodeEntry.raw,policy,budget);
    const node=verifySourceNodeOriginal(nodeEntry.raw,{expectedSigningKey:expected.target.signing_key,
      expectedStorageEpoch:nodePayload.storage_epoch,at:started,policy,budget});
    if(!same(endpoint(baseUrl,this.#allowLoopback),endpoint(node.payload.base_url,this.#allowLoopback)))fail('repair_proof_mismatch');
    const grant=setup.originals.bootstrap.payload as Obj;
    const known=checks.known(history,checks.obligations(setup.originals,expected.slot,budget),expected.slot.root_key,expected.target,budget,true);
    const expiry=Math.min(started+Math.min(60,Math.max(1,Math.floor(timeout))),grant.probe_until,grant.proof_until,grant.expires_at,
      node.payload.expires_at as number,setup.originals.root.payload.expires_at as number,setup.originals.write.payload.expires_at as number);
    if(expiry<=started)fail('repair_access_expired');
    const binding={expectedSubject:this.#subject,expectedTarget:expected.target,targetStorageEpoch:node.payload.storage_epoch as string,
      bootstrapGrantSha256:setup.originals.bootstrap.ref.raw_sha256,selector:grant.selector,policy,budget,consumer:'ack_offer' as const};
    let requests=0,wireBytes=0,proofBytes=0;
    const request=async(body:Uint8Array,child=false):Promise<Uint8Array>=>{
      if(requests>=grant.limits.max_requests||clock()>=deadline)fail('repair_over_budget');requests++;
      const reply=await this.#transport.requestRepair(baseUrl,body,deadline,{child});wireBytes+=body.length+reply.length;return reply;
    };
    const outgoing=await makeBootstrapProbe(this.#identity,{...binding,at:started,expiresAt:expiry});
    if(outgoing.original.raw.length>grant.limits.max_probe_bytes)fail('repair_over_budget');
    const challengeRaw=await request(outgoing.original.raw),challengeDigest=budget.hash(challengeRaw);
    const challenge={raw:challengeRaw,ref:rawRef({namespace:'meta',key:challengeDigest,raw_sha256:challengeDigest,size:challengeRaw.length})};
    const challengeValue=fields(parseNewWire(challengeRaw,policy,budget).value,['payload','proof']);
    const answer=await solveBootstrapChallenge({raw:outgoing.original.raw,ref:outgoing.original.ref},challenge,
      {...binding,signer:this.#identity,encryptionIdentity:this.#encryption,targetNonce:outgoing.nonce,at:this.#now(),
        expiresAt:Math.min(expiry,u53((challengeValue.payload as Obj)?.expires_at))});
    const response=await request(answer.raw),held=verifyBootstrapProofResponse(response,{expectedSubject:this.#subject,expectedTarget:expected.target,
      targetStorageEpoch:node.payload.storage_epoch as string,selector:grant.selector,bootstrapGrantRef:setup.originals.bootstrap.ref,
      probeRef:outgoing.original.ref,challengeRef:challenge.ref,answerRef:answer.ref,at:this.#now(),maxProofItems:grant.limits.max_proof_items,
      maxProofBytes:grant.limits.max_proof_bytes,expectedSourceState:'empty',consumer:'ack_offer',policy,budget});
    proofBytes=response.length+held.handle.raw.length+held.manifest.raw.length;
    // Reuse only exact already-held originals. Verification below still checks
    // the complete independently authenticated source and both history events.
    const available=new Map<string,Uint8Array>();
    for(const item of [...Object.values(setup.originals),...history,nodeEntry] as RawOriginal[])available.set(refKey(item.ref),item.raw);
    const originals=new Map<string,RawOriginal>(),roles=new Map<string,RawRef[]>();
    for(const item of (held.manifest.value as Obj).children){
      const reference=rawRef(item.ref),key=refKey(reference);roles.set(item.role,[...(roles.get(item.role)??[]),reference]);if(originals.has(key))continue;
      if(reference.size>policy.max_document_bytes||proofBytes+reference.size>grant.limits.max_proof_bytes)fail('repair_over_budget');
      let assembled:Uint8Array;
      if(available.has(key)){assembled=available.get(key)!;budget.input(assembled.length);}
      else{
        const chunks:Uint8Array[]=[];let offset=0;
        while(offset<reference.size){
          const count=Math.min(65536,reference.size-offset),child=makeBootstrapChildRequest(this.#identity,held,{subject:this.#subject,target:expected.target,
            at:this.#now(),expiresAt:held.handle.payload.expires_at as number,childIndex:item.index,offset,requestedBytes:count,policy,budget});
          const received=await request(child.raw,true);if(received.length!==count)fail('repair_ref_mismatch');budget.input(received.length);chunks.push(received);offset+=count;
        }
        budget.output(reference.size);assembled=Buffer.concat(chunks);
      }
      if(budget.hash(assembled)!==reference.raw_sha256)fail('repair_ref_mismatch');
      proofBytes+=assembled.length;originals.set(key,{raw:assembled,ref:reference});
    }
    if(this.#now()>=(held.handle.payload.expires_at as number)||clock()>=deadline)fail('repair_access_expired');
    const entry=(role:string):RawOriginal=>originals.get(refKey(roles.get(role)![0]))!;
    const resolver=new LocalRawResolver(policy,budget);
    for(const reference of roles.get('history.raw_pack')!){const item=originals.get(refKey(reference))!;
      if(!same(resolver.put(reference.namespace,reference.key,item.raw).ref,reference))fail('repair_ref_mismatch');}
    const source=verifyAckEmptySourceEvent(entry('history.ack_empty'),resolver,entry('ack.empty_custody'),{
      expectedAckSlot:expected.slot,expectedOwner:expected.owner,expectedTarget:expected.target,
      targetStorageEpoch:node.payload.storage_epoch as string,expectedReceiptWriter:this.#subject,
      expectedMessageId:expected.message,expectedEnvelopeRef:expected.envelope,limitPolicy:this.#limits,policy,budget});
    this.#emptyHead(entry('ack.head'),source,expected.target,budget);
    const prior=source.predecessor;
    for(const item of source.manifest.roles){const actual=originals.get(refKey(item.original.ref));
      if(!same(roles.get(item.role),[item.original.ref])||!actual||!Buffer.from(actual.raw).equals(Buffer.from(item.original.raw)))fail('repair_proof_mismatch');}
    if(!same(prior.resources.originals.root.ref,setup.originals.root.ref)||!same(source.authorities.originals.write.ref,setup.originals.write.ref)||
      !same(source.authorities.originals.bootstrap.ref,setup.originals.bootstrap.ref))fail('repair_proof_mismatch');
    const usedPacks=new Set<string>();for(const manifest of [source.manifest,prior.manifest])
      for(const row of (manifest.manifest.value as Obj).roles)usedPacks.add(refKey(rawRef(row.pack_ref)));
    const suppliedPacks=roles.get('history.raw_pack')!.map(refKey);
    if(suppliedPacks.length!==usedPacks.size||suppliedPacks.some(key=>!usedPacks.has(key)))fail('repair_unused_pack');
    const current=checks.current(source,roles,originals,expected.target,budget,known),now=this.#now();
    if(now>=Math.min(expiry,held.handle.payload.expires_at as number,source.read_until,...current.map(item=>item.payload.valid_until as number))||clock()>=deadline)fail('repair_access_expired');
    const saved=Object.freeze([...originals.values()].map(item=>Object.freeze({ref:item.ref,get raw(){return Uint8Array.from(item.raw);}})));
    return Object.freeze({source,proof:held,current_statuses:Object.freeze(current),originals:saved,
      metrics:Object.freeze({requests,wire_bytes:wireBytes,proof_bytes:proofBytes,...budget.snapshot()})});
  }
  #emptyHead(entry:RawOriginal,source:AuthenticatedAckEmptySourceEvent,target:Obj,budget:RepairBudget):void{
    const input=snapshotEntry(entry,this.#policy,budget),signed=fields(parseNewWire(input.raw,this.#policy,budget).value,['payload','proof']);
    const p=fields(signed.payload,['schema_version','kind','signing_key','ack_slot','generation','observed_at','retain_until','state','root_authority_ref','grant_ref','binding_ref']);
    if(p.schema_version!=='memory-vault-open-repair/v1'||p.kind!=='ack.head'||p.state!=='empty'||u53(p.generation,1)!==1||
      !same(p.ack_slot,source.custody.payload.ack_slot)||p.observed_at!==source.stored_at||p.retain_until!==source.retain_until||
      ['root_authority_ref','grant_ref','binding_ref'].some(name=>!same(p[name],source.custody.payload[name])))fail('repair_ack_empty_mismatch');
    verifyBoundedControlSignature(p,signed.proof,target.signing_key,budget);
  }
}
class OfferStatusChecks{
  readonly #subject:Obj;readonly #policy:RepairPolicy;readonly #clock:()=>number;
  readonly #statusObserver?: (item:AuthenticatedStatusOriginal)=>void;
  constructor(owner:Obj,policy:RepairPolicy,now:()=>number,observer?: (item:AuthenticatedStatusOriginal)=>void){
    this.#subject=owner;this.#policy=policy;this.#clock=now;this.#statusObserver=observer;
  }
  #now():number{return u53(Math.floor(this.#clock()));}
  obligations(originals:Obj,slot:Obj,budget:RepairBudget):Obligation[]{
    const result:Obligation[]=[];
    for(const [name,role,kind,mask] of [['root','current.status.ack_root','ack.root_authority',3],
      ['write','current.status.ack_write','ack.write_grant',1],['bootstrap','current.status.ack_offer_bootstrap','bootstrap.grant',3]] as const){
      const item=originals[name],subject={authority_kind:kind,authority_sha256:item.ref.raw_sha256};
      result.push({role,kind:'authority',subject,revision:item.payload.revision,signer:this.#subject.signing_key,mask,
        scope_id:statusScope(slot.root_key,'authority',subject,this.#policy,budget)});
    }
    result.push({role:'current.status.ack_slot',kind:'ack_slot',subject:slot,revision:originals.root.payload.revision,
      signer:this.#subject.signing_key,mask:3,scope_id:statusScope(slot.root_key,'ack_slot',slot,this.#policy,budget)});return result;
  }
  history(known:unknown,archive:unknown,budget:RepairBudget):RawOriginal[]{
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
  known(values:unknown,obligations:Obligation[],root:Obj,target:Obj,budget:RepairBudget,deferredAuthorities=false):AuthenticatedStatusOriginal[]{
    // Copy raw entries before the first asynchronous operation.
    if(!Array.isArray(values)||isProxy(values)||values.length>32)fail('repair_invalid_status');
    const descriptors=Object.getOwnPropertyDescriptors(values);for(let index=0;index<values.length;index++)if(!descriptors[index]||!Object.hasOwn(descriptors[index],'value'))fail('repair_invalid_status');
    const checked:AuthenticatedStatusOriginal[]=[];
    for(let index=0;index<values.length;index++){
      const item=snapshotEntry(descriptors[index].value,this.#policy,budget,true),payload=checkedStatus(item.raw,this.#policy,budget);
      const issuer=fields(payload.scope_key,['root_key','issuer_key_id']).issuer_key_id,issued=u53(payload.issued_at);
      if(issued>this.#now()+30)fail('repair_status_mismatch');let signer:Obj,allowed:Obj[];
      if(issuer===this.#subject.signing_key.key_id){signer=this.#subject.signing_key;allowed=obligations.map(v=>({scope_kind:v.kind,scope_id:v.scope_id}));
        if(deferredAuthorities){const scopes=new Map(allowed.map(item=>[scopeKey(item),item]));
          for(const item of payload.entries)if(item.scope_kind==='authority')scopes.set(scopeKey(item),{scope_kind:item.scope_kind,scope_id:item.scope_id});allowed=[...scopes.values()];}
        if(issuer===target.signing_key.key_id)allowed.push(...payload.entries.filter((v:Obj)=>v.scope_kind==='resource').map((v:Obj)=>({scope_kind:v.scope_kind,scope_id:v.scope_id})));}
      else if(issuer===target.signing_key.key_id){signer=target.signing_key;
        if(payload.entries.some((v:Obj)=>v.scope_kind!=='resource'))fail('repair_status_disclosure');
        allowed=payload.entries.map((v:Obj)=>({scope_kind:v.scope_kind,scope_id:v.scope_id}));}
      else fail('repair_status_mismatch');
      checked.push(authenticateStatusOriginal(item,{expectedRoot:root,expectedSigningKey:signer,at:issued,allowedScopes:allowed,policy:this.#policy,budget},this.#statusObserver));
    }
    // Activation's historical owner READ grant is checked against the exact
    // recovered history below; it cannot revoke the writer's independent ADMIT.
    this.#floors(checked,[],obligations,true,deferredAuthorities);return checked;
  }
  #floors(known:readonly AuthenticatedStatusOriginal[],current:readonly AuthenticatedStatusOriginal[],obligations:Obligation[],probePhase=false,deferredAuthorities=false):void{
    const seen=new Map<string,string>(),floors=new Map<string,[number,number][]>(),required=new Map(obligations.map(v=>[v.signer.key_id+':'+v.kind+':'+v.scope_id,v]));
    for(const observed of [...known,...current]){
      const payload=observed.payload as Obj,issuer=payload.scope_key.issuer_key_id,revision=payload.revision,id=issuer+':'+revision;
      if(seen.has(id)&&seen.get(id)!==observed.canonical_sha256)fail('repair_status_conflict');seen.set(id,observed.canonical_sha256);
      for(const entry of payload.entries){const key=issuer+':'+scopeKey(entry),wanted=required.get(key);
        let mask=wanted?.mask??2;
        if(probePhase&&wanted&&['current.status.ack_root','current.status.ack_offer_bootstrap'].includes(wanted.role??''))mask|=8;
        if(deferredAuthorities&&!wanted&&issuer===this.#subject.signing_key.key_id&&entry.scope_kind==='authority')mask=0;
        if(entry.status==='revoked'&&(entry.operation_mask&mask))fail('repair_authority_revoked');
        if(wanted&&mask&&entry.minimum_document_revision>wanted.revision)fail('repair_status_revision');
        floors.set(key,[...(floors.get(key)??[]),[revision,entry.minimum_document_revision]]);
      }
    }
    for(const values of floors.values()){let minimum=0;for(const [,floor] of values.sort((a,b)=>a[0]-b[0]||a[1]-b[1])){if(floor<minimum)fail('repair_status_rollback');minimum=floor;}}
    for(const observed of current){const payload=observed.payload as Obj;for(const entry of payload.entries){const values=floors.get(payload.scope_key.issuer_key_id+':'+scopeKey(entry))!;
      if(payload.revision<Math.max(...values.map(v=>v[0])))fail('repair_status_rollback');}}
  }
  current(source:AuthenticatedAckEmptySourceEvent,roles:Map<string,RawRef[]>,originals:Map<string,RawOriginal>,target:Obj,
    budget:RepairBudget,known:AuthenticatedStatusOriginal[]):AuthenticatedStatusOriginal[]{
    const prior=source.predecessor,slot=source.custody.payload.ack_slot as Obj,root=slot.root_key,policy=this.#policy;
    const obligations=this.obligations(source.authorities.originals,slot,budget),active=prior.resources.originals.active.payload as Obj;
    obligations.push({role:'current.status.ack_resource',kind:'resource',subject:active.resource,revision:active.reservation_generation,
      signer:target.signing_key,mask:3,scope_id:statusScope(root,'resource',active.resource,policy,budget)});
    for(const [item,kind] of [[prior.resources.originals.read,'ack.read_grant'],[prior.bootstrap.originals.bootstrap,'bootstrap.grant']] as const){
      const subject={authority_kind:kind,authority_sha256:item.ref.raw_sha256};
      obligations.push({role:null,kind:'authority',subject,revision:item.payload.revision as number,signer:this.#subject.signing_key,mask:0,
        scope_id:statusScope(root,'authority',subject,policy,budget)});
    }
    const permitted=new Set(obligations.map(v=>v.signer.key_id+':'+v.kind+':'+v.scope_id));
    for(const observed of known){const p=observed.payload as Obj;
      if(p.entries.some((v:Obj)=>!permitted.has(p.scope_key.issuer_key_id+':'+scopeKey(v))))fail('repair_status_disclosure');}
    const groups=new Map<string,{ref:RawRef;signer:Obj;required:Obj[]}>();
    for(const item of obligations){if(item.role===null)continue;const ref=roles.get(item.role)![0],key=refKey(ref),group=groups.get(key)??{ref,signer:item.signer,required:[]};
      if(!same(group.signer,item.signer))fail('repair_proof_mismatch');
      group.required.push({scope_kind:item.kind,scope_id:item.scope_id,document_revision:item.revision,operation_mask:item.mask});groups.set(key,group);}
    const checked:AuthenticatedStatusOriginal[]=[];
    for(const [key,group] of groups){
      const allowed=obligations.filter(v=>same(v.signer,group.signer)),entry=originals.get(key)!;
      checked.push(verifyStatusOriginal(entry,{expectedRoot:root,expectedSigningKey:group.signer,at:this.#now(),
        allowedScopes:allowed.map(v=>({scope_kind:v.kind,scope_id:v.scope_id})),required:group.required,policy,budget},this.#statusObserver));
    }
    this.#floors([...prior.statuses,...source.statuses,...known],checked,obligations);
    if(this.#now()>=Math.min(...['admit_until','read_until','retain_until'].map(n=>active.windows[n])))fail('repair_access_expired');
    return checked;
  }
}
function checkedNodePayload(raw:Uint8Array,policy:RepairPolicy,budget:RepairBudget):Obj{return fields(parseOriginalControl(raw,policy,budget).value,['payload','proof']).payload;}
