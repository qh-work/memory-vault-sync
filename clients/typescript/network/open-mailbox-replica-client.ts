/** Native bounded replica recovery. All controls and original ciphertext are
 * obtained through the selected endpoint, with independent dual possession. */
import {performance} from 'node:perf_hooks';
import {OpenHTTPTransport,endpoint} from './open-transport.ts';
import {RepairBudget,buildNewWire,parseNewWire,rawRef,u53,LocalRawResolver,parseRawPack} from './open-repair-wire.ts';
import type {RawOriginal,RepairPolicy} from './open-repair-wire.ts';
import {DEFAULT_REPAIR_CLIENT_POLICY,DEFAULT_REPAIR_CLIENT_LIMITS} from './open-repair-client.ts';
import {validateSigningIdentity,validateEncryptionIdentity,encodeBase64url} from './crypto.ts';
import {verifySourceNodeOriginal} from './open-repair-original.ts';
import {verifyMailboxFeedBootstrap} from './open-repair-mailbox-authority.ts';
import {resolveHistoricalInputs} from './open-repair-history.ts';
import {makeBootstrapProbe,solveBootstrapChallenge} from './open-repair-probe.ts';
import {verifyBootstrapProofResponse,makeBootstrapChildRequest,makeMailboxBodyRequest} from './open-repair-proof.ts';
import {authenticateStatusOriginal,statusScope} from './open-repair-status.ts';
import {readMailboxIndex,verifyMailboxAdmissionMetadata} from './open-repair-mailbox-read.ts';
import {ReplicaStatusJournal} from './open-ack-status.ts';
import {replicaFields as fields,replicaFail as fail,replicaSame as same,replicaRefKey as id,replicaEntry,replicaFloors,verifyMailboxMessageReplica,checkMailboxMessageReturn} from './open-repair-mailbox-replica.ts';
type Obj=Record<string,any>;
export const MAILBOX_REPLICA_LIMITS=Object.freeze({...DEFAULT_REPAIR_CLIENT_LIMITS,max_signature_checks:4096,max_proof_bytes:4194304,max_requests:256,max_replay_records:256,max_proof_items:128});
const monotonic=()=>performance.now()/1000;
function boundedTimeout(v:unknown):number{if(typeof v!=='number'||!Number.isFinite(v)||v<=0||v>60)fail('repair_invalid_deadline');return v;}
/** Authenticate retained observations before considering current access. */
export function knownReplicaStatuses(entries:unknown,e:Obj,owner:Obj,at:number,policy:RepairPolicy,budget:RepairBudget,observe?: (v:any)=>void):Obj[]{
  if(!Array.isArray(entries)||entries.length>32)fail('repair_status_history_capacity');const parties={...e,owner},signers=new Map(Object.values(parties).filter((v:Obj)=>v?.signing_key).map((v:Obj)=>[v.signing_key.key_id,v.signing_key])),result:Obj[]=[];let denial:unknown;
  for(const input of entries)try{const entry=replicaEntry(input,policy,budget),p=(parseNewWire(entry.raw,policy,budget).value as Obj).payload,signer=p.signing_key;
    if(!same(signers.get(signer.key_id),signer)||u53(p.issued_at)>at||!Array.isArray(p.entries))fail('repair_status_disclosure');
    const permitted=new Set<string>();if(same(signer,owner.signing_key)){permitted.add('authority');permitted.add('mailbox_slot');}if(same(signer,e.sender.signing_key)||same(signer,e.source.signing_key)||same(signer,e.maintainer.signing_key))permitted.add('authority');if(same(signer,e.source.signing_key)||same(signer,e.target.signing_key))permitted.add('resource');if(same(signer,e.maintainer.signing_key))permitted.add('assignment');
    if(p.entries.some((v:Obj)=>!permitted.has(v.scope_kind)))fail('repair_status_disclosure');
    result.push(authenticateStatusOriginal(entry,{expectedRoot:e.slot.root_key,expectedSigningKey:signer,at:p.issued_at,allowedScopes:p.entries.map((v:Obj)=>({scope_kind:v.scope_kind,scope_id:v.scope_id})),policy,budget},observe));
  }catch(error){denial??=error;}
  if(denial)throw denial;return result;
}
export interface MessageReplicaRecoverOptions{targetNodeEntry:unknown;expectedTarget:unknown;expectedSender:unknown;expectedSlot:unknown;expectedSource:unknown;sourceStorageEpoch:string;expectedMaintainer:unknown;expectedEnvelopeRef:unknown;slotEntries:unknown;journal:ReplicaStatusJournal;knownStatuses?:readonly unknown[];archiveStatuses?:readonly unknown[];timeout?:number;}
export class MailboxMessageReplicaRecoveryClient{
  readonly #identity:Obj;readonly #encryption:Obj;readonly #subject:Obj;readonly #policy:RepairPolicy;readonly #transport:OpenHTTPTransport;readonly #loopback:boolean;readonly #clock:()=>number;readonly #observer?:()=>void;
  readonly #recovered=new WeakMap<object,Obj>();
  constructor(identity:unknown,encryption:unknown,a:{transport:OpenHTTPTransport;allowLoopback:boolean;clock?:()=>number;networkObserver?:()=>void}){
    this.#policy=Object.freeze({...DEFAULT_REPAIR_CLIENT_POLICY,max_signature_checks:512});const budget=new RepairBudget(this.#policy),e=buildNewWire({identity,encryption},this.#policy,budget).value as Obj;
    this.#identity=e.identity;this.#encryption=e.encryption;this.#subject={signing_key:validateSigningIdentity(e.identity),encryption_key:validateEncryptionIdentity(e.encryption)};this.#transport=a.transport;this.#loopback=a.allowLoopback;this.#clock=a.clock??(()=>Date.now()/1000);this.#observer=a.networkObserver;Object.freeze(this);
  }
  get subject():Readonly<Obj>{return this.#subject;}
  close():void{}
  #now():number{return u53(Math.floor(this.#clock()));}
  async recover(baseUrl:string,a:MessageReplicaRecoverOptions):Promise<Readonly<Obj>>{
    if(!(a.journal instanceof ReplicaStatusJournal))fail('repair_invalid_context');
    const policy=this.#policy,budget=new RepairBudget(policy),started=this.#now(),timeout=boundedTimeout(a.timeout??60),deadline=monotonic()+timeout;
    const e=buildNewWire({slot:a.expectedSlot,sender:a.expectedSender,target:a.expectedTarget,source:a.expectedSource,maintainer:a.expectedMaintainer},policy,budget).value as Obj;
    if(e.slot.writer_storage_epoch!==a.sourceStorageEpoch)fail('repair_proof_mismatch');const envelopeRef=rawRef(a.expectedEnvelopeRef);
    const setup=verifyMailboxFeedBootstrap(a.slotEntries,{expectedSlot:e.slot,expectedOwner:this.#subject,expectedTarget:e.source,targetStorageEpoch:a.sourceStorageEpoch,limitPolicy:MAILBOX_REPLICA_LIMITS,at:started,policy,budget});
    if(!same(setup.slot.payload.sender,{signing_key_id:e.sender.signing_key.key_id,encryption_key_id:e.sender.encryption_key.key_id}))fail('repair_proof_mismatch');
    const nodeEntry=replicaEntry(a.targetNodeEntry,policy,budget),np=(parseNewWire(nodeEntry.raw,policy,budget).value as Obj).payload,node=verifySourceNodeOriginal(nodeEntry.raw,{expectedSigningKey:e.target.signing_key,expectedStorageEpoch:np.storage_epoch,at:started,policy,budget});
    if(!same(endpoint(baseUrl,this.#loopback),endpoint(node.payload.base_url,this.#loopback)))fail('repair_proof_mismatch');const epoch=node.payload.storage_epoch as string;
    const retained=new Map<string,RawOriginal>();for(const group of [a.knownStatuses??[],a.archiveStatuses??[],a.journal.load(new Set([this.#subject,...[e.sender,e.target,e.source,e.maintainer]].map(v=>v.signing_key.key_id)))]){if(!Array.isArray(group)||group.length>32)fail('repair_status_history_capacity');for(const item of group){const entry=replicaEntry(item,policy,budget);retained.set(id(entry.ref),entry);}}
    const known=knownReplicaStatuses([...retained.values()],e,this.#subject,started,policy,budget,v=>a.journal.observe(v));
    const probeNeeds=['slot','read','maintenance','bootstrap'].map(n=>({signer:this.#subject.signing_key,scope_kind:n==='slot'?'mailbox_slot':'authority',scope_id:statusScope(e.slot.root_key,n==='slot'?'mailbox_slot':'authority',n==='slot'?e.slot:{authority_kind:setup[n].payload.kind,authority_sha256:setup[n].ref.raw_sha256},policy,budget),revision:setup[n].payload.revision,mask:n==='read'?2:10}));replicaFloors(known,[],probeNeeds);
    const grant=setup.bootstrap.payload,expiry=Math.min(started+Math.min(60,Math.max(1,Math.floor(timeout))),node.payload.expires_at as number,grant.probe_until,grant.proof_until,...Object.values(setup).map(v=>v.payload.expires_at as number));if(expiry<=started)fail('repair_access_expired');
    const counts={requests:0,wire_bytes:0,proof_bytes:0},request=async(raw:Uint8Array,child=false)=>{if(counts.requests>=grant.limits.max_requests||monotonic()>=deadline)fail('repair_over_budget');counts.requests++;this.#observer?.();const reply=await this.#transport.requestRepair(baseUrl,raw,deadline,{child});counts.wire_bytes+=raw.length+reply.length;return reply;};
    const binding={expectedSubject:this.#subject,expectedTarget:e.target,targetStorageEpoch:epoch,bootstrapGrantSha256:setup.bootstrap.ref.raw_sha256,selector:grant.selector,consumer:'mailbox_feed' as const,policy,budget};
    const outgoing=await makeBootstrapProbe(this.#identity,{...binding,at:started,expiresAt:expiry});if(outgoing.original.raw.length>grant.limits.max_probe_bytes)fail('repair_over_budget');
    const challengeRaw=await request(outgoing.original.raw),digest=budget.hash(challengeRaw),challenge={raw:challengeRaw,ref:rawRef({namespace:'meta',key:digest,raw_sha256:digest,size:challengeRaw.length})};
    const preview=(parseNewWire(challengeRaw,policy,budget).value as Obj).payload,answer=await solveBootstrapChallenge({raw:outgoing.original.raw,ref:outgoing.original.ref},challenge,{...binding,signer:this.#identity,encryptionIdentity:this.#encryption,targetNonce:outgoing.nonce,at:this.#now(),expiresAt:Math.min(expiry,u53(preview.expires_at))});
    const response=await request(answer.raw),held=verifyBootstrapProofResponse(response,{expectedSubject:this.#subject,expectedTarget:e.target,targetStorageEpoch:epoch,selector:grant.selector,bootstrapGrantRef:setup.bootstrap.ref,probeRef:outgoing.original.ref,challengeRef:challenge.ref,answerRef:answer.ref,at:this.#now(),maxProofItems:grant.limits.max_proof_items,maxProofBytes:grant.limits.max_proof_bytes,expectedSourceState:'replica_message',consumer:'mailbox_feed',policy,budget});
    counts.proof_bytes=response.length+held.handle.raw.length+held.manifest.raw.length;
    const originals=new Map<string,RawOriginal>(),roles=new Map<string,any[]>(),available=new Map<string,Uint8Array>(),children=(held.manifest.value as Obj).children;
    for(const item of [...Object.values(setup),...known])available.set(id(item.ref),item.raw);for(const item of children)roles.set(item.role,[...(roles.get(item.role)??[]),rawRef(item.ref)]);
    const download=async(item:Obj)=>{const ref=rawRef(item.ref),k=id(ref);if(originals.has(k))return;if(ref.size>policy.max_document_bytes||counts.proof_bytes+ref.size>grant.limits.max_proof_bytes)fail('repair_over_budget');let raw=available.get(k);
      if(raw)budget.input(raw.length);else{let offset=0;const parts:Uint8Array[]=[];while(offset<ref.size){const count=Math.min(65536,ref.size-offset),packet=makeBootstrapChildRequest(this.#identity,held,{subject:this.#subject,target:e.target,at:this.#now(),expiresAt:held.handle.payload.expires_at as number,childIndex:item.index,offset,requestedBytes:count,policy,budget}),received=await request(packet.raw,true);if(received.length!==count)fail('repair_ref_mismatch');budget.input(received.length);parts.push(received);offset+=count;}budget.output(ref.size);raw=Buffer.concat(parts);}
      if(raw.length!==ref.size||budget.hash(raw)!==ref.raw_sha256)fail('repair_ref_mismatch');budget.retain(raw.length);originals.set(k,{raw,ref});counts.proof_bytes+=raw.length;};
    const packedChildren=children.filter((v:Obj)=>v.role==='replica.read_pack');if(packedChildren.length!==1)fail('repair_proof_mismatch');await download(packedChildren[0]);const packedItem=originals.get(id(packedChildren[0].ref))!,pack=parseRawPack(packedItem.raw,packedItem.ref,policy,budget);
    const packRoles=new Set(['replica.manifest','replica.custody','copy.allocation','copy.offer','copy.assignment','copy.reservation_consent','copy.owner_disclosure','copy.source_disclosure','copy.current_status','return.owner','return.source','return.maintainer','current.status.replica_read','copy.sender_reservation_consent','copy.sender_disclosure','return.sender']);
    const wanted=new Map<string,any>();for(const item of children)if(packRoles.has(item.role)){const ref=rawRef(item.ref);wanted.set(ref.raw_sha256+':'+ref.size,ref);}
    if(wanted.size!==pack.entries.length||pack.entries.some(v=>!wanted.has(v.raw_sha256+':'+v.size)))fail('repair_proof_mismatch');
    for(const [i,item] of pack.entries.entries()){const ref=wanted.get(item.raw_sha256+':'+item.size),raw=pack.entry(i,ref).raw,old=available.get(id(ref));if(old&&!Buffer.from(old).equals(Buffer.from(raw)))fail('repair_ref_conflict');available.set(id(ref),raw);}
    for(const item of children)if(['history.raw_pack','history.mailbox_feed'].includes(item.role))await download(item);
    const packed=new LocalRawResolver(policy,budget);for(const ref of roles.get('history.raw_pack')??[]){const item=originals.get(id(ref))!;if(!same(packed.put(ref.namespace,ref.key,item.raw).ref,ref))fail('repair_ref_mismatch');}
    const reuse=(tree:Obj)=>{for(const row of tree.roles){const ref=row.original.ref,raw=row.original.raw,old=available.get(id(ref));if(old&&!Buffer.from(old).equals(Buffer.from(raw)))fail('repair_ref_conflict');available.set(id(ref),raw);}for(const prior of tree.predecessors)reuse(prior);};
    for(const ref of roles.get('history.mailbox_feed')??[]){const tree=resolveHistoricalInputs(originals.get(id(ref))!.raw,packed,policy,budget);if((tree.manifest.value as Obj).variant!=='mailbox_feed')fail('repair_proof_mismatch');reuse(tree);}for(const item of children)await download(item);
    const entry=(ref:unknown)=>{const v=originals.get(id(ref));if(!v)fail('repair_original_missing');return v;},one=(role:string)=>{const refs=roles.get(role);if(refs?.length!==1)fail('repair_proof_mismatch');return entry(refs[0]);};
    const resolver=new LocalRawResolver(policy,budget);for(const item of originals.values())if(!same(resolver.put(item.ref.namespace,item.ref.key,item.raw).ref,item.ref))fail('repair_ref_mismatch');
    const context={expectedSlot:e.slot,expectedOwner:this.#subject,expectedSender:e.sender,expectedSource:e.source,sourceStorageEpoch:a.sourceStorageEpoch,expectedMaintainer:e.maintainer,expectedTarget:e.target,targetStorageEpoch:epoch,expectedEnvelopeRef:envelopeRef,limitPolicy:MAILBOX_REPLICA_LIMITS,policy,budget};
    const replica=verifyMailboxMessageReplica(one('replica.manifest'),resolver,one('replica.custody'),context);
    for(const member of replica.source.graph.members)for(const [n,parent] of Object.entries(setup)){if(!same(member.originals[n].ref,parent.ref)||!Buffer.from(member.originals[n].raw).equals(Buffer.from(parent.raw)))fail('repair_proof_mismatch');}
    const extras=new Set(['replica.manifest','replica.custody','replica.read_pack','return.owner','return.source','return.maintainer','return.sender','current.status.replica_read']),actual=new Set<string>(),expected=new Set<string>();
    for(const [role,refs] of roles)if(!extras.has(role))for(const ref of refs)actual.add(role+'|'+id(ref));for(const [role,items] of replica.entries)for(const item of items)expected.add(role+'|'+id(item.ref));if(actual.size!==expected.size||[...expected].some(v=>!actual.has(v)))fail('repair_proof_mismatch');
    const consents=Object.fromEntries(['owner','source','maintainer','sender'].map(n=>[n,one('return.'+n)])),current=(roles.get('current.status.replica_read')??[]).map(entry),permission=checkMailboxMessageReturn(replica,consents,{...context,currentStatuses:current,at:this.#now(),action:'proof',onObserved:(v:any)=>a.journal.observe(v)});
    const previous=[...replica.source.graph.statuses,...replica.source.graph.members.flatMap((v:Obj)=>v.statuses),...replica.authority.statuses,...known];replicaFloors(previous,permission.statuses,permission.obligations);
    const members=await readMailboxIndex(one('feed.head'),one('feed.checkpoint'),{expectedSlot:e.slot,expectedSigningKey:e.source.signing_key,encryptionIdentity:this.#encryption as any,readOriginal:ref=>entry(ref).raw,at:this.#now(),maxMessages:setup.slot.payload.max_appends,policy,budget});
    const until=Math.min(expiry,held.handle.payload.expires_at as number,permission.expires_at);if(this.#now()>=until||monotonic()>=deadline)fail('repair_access_expired');
    const archive=new Map([...previous,...permission.statuses].map(v=>[id(v.ref),v]));if(archive.size>32)fail('repair_status_history_capacity');
    const result=Object.freeze({replica,proof:held,current_statuses:permission.statuses,archive_statuses:[...archive.values()],entries:members,metrics:{...counts,...budget.snapshot()},base_url:baseUrl});this.#recovered.set(result,{e,context,setup,held,originals,consents,current,archive:[...archive.values()],counts,until,journal:a.journal});return result;
  }
  async readMessage(baseUrl:string,recovered:object,timeout=30):Promise<Readonly<Obj>>{
    const c=this.#recovered.get(recovered);if(!c||!same(endpoint(baseUrl,this.#loopback),endpoint((recovered as Obj).base_url,this.#loopback)))fail('repair_invalid_context');const deadline=monotonic()+boundedTimeout(timeout),policy=this.#policy,budget=new RepairBudget(policy),context={...c.context,policy,budget};
    const resolver=new LocalRawResolver(policy,budget);for(const item of c.originals.values())if(!same(resolver.put(item.ref.namespace,item.ref.key,item.raw).ref,item.ref))fail('repair_ref_mismatch');
    const child=(role:string)=>{const rows=(c.held.manifest.value as Obj).children.filter((v:Obj)=>v.role===role);if(rows.length!==1)fail('repair_proof_mismatch');return c.originals.get(id(rows[0].ref));};
    const replica=verifyMailboxMessageReplica(child('replica.manifest'),resolver,child('replica.custody'),context),permission=checkMailboxMessageReturn(replica,c.consents,{...context,currentStatuses:c.current,at:this.#now(),action:'child',onObserved:(v:any)=>c.journal.observe(v)});
    const retained=knownReplicaStatuses(c.journal.load(new Set([this.#subject,c.e.sender,c.e.target,c.e.source,c.e.maintainer].map(v=>v.signing_key.key_id))),c.e,this.#subject,this.#now(),policy,budget,v=>c.journal.observe(v));replicaFloors([...c.archive,...retained],permission.statuses,permission.obligations);
    const checked=await verifyMailboxAdmissionMetadata(replica.source.message_member,{expectedSlot:c.e.slot,expectedSigningKey:c.e.source.signing_key,expectedOwner:this.#subject,expectedSender:c.e.sender,expectedTarget:c.e.source,encryptionIdentity:this.#encryption as any,readOriginal:ref=>{const v=c.originals.get(id(ref));if(!v)fail('repair_original_missing');return v.raw;},at:this.#now(),limitPolicy:MAILBOX_REPLICA_LIMITS,policy,budget,currentStatuses:[],knownStatuses:[],statusObligations:[]});
    const ref=rawRef(context.expectedEnvelopeRef),children=(c.held.manifest.value as Obj).children.filter((v:Obj)=>v.role==='member.core'&&same(v.ref,checked.link.core_ref));if(children.length!==1||!same(ref,checked.core.envelope_ref))fail('repair_proof_mismatch');
    if(ref.size+c.counts.proof_bytes>MAILBOX_REPLICA_LIMITS.max_proof_bytes)fail('repair_over_budget');let offset=0;const parts:Uint8Array[]=[];
    const guard=()=>{if(this.#now()>=Math.min(c.until,permission.expires_at)||monotonic()>=deadline)fail('repair_access_expired');};
    while(offset<ref.size){guard();if(c.counts.requests>=MAILBOX_REPLICA_LIMITS.max_requests)fail('repair_over_budget');const count=Math.min(65536,ref.size-offset),packet=makeMailboxBodyRequest(this.#identity,c.held,ref,{subject:this.#subject,target:c.e.target,at:this.#now(),expiresAt:c.held.handle.payload.expires_at,childIndex:children[0].index,offset,requestedBytes:count,policy,budget});c.counts.requests++;this.#observer?.();const raw=await this.#transport.requestRepair(baseUrl,packet.raw,deadline,{child:true});if(raw.length!==count)fail('repair_ref_mismatch');budget.input(raw.length);parts.push(raw);offset+=count;}
    guard();budget.output(ref.size);const envelope=Buffer.concat(parts);if(budget.hash(envelope)!==ref.raw_sha256)fail('repair_ref_mismatch');return Object.freeze({...checked,envelope,replica,current_statuses:permission.statuses});
  }
  inboxEvidence(recovered:object):Readonly<Obj>{
    const c=this.#recovered.get(recovered);if(!c)fail('repair_invalid_context');const reference=(role:string)=>{const found=(c.held.manifest.value as Obj).children.filter((v:Obj)=>v.role===role);if(found.length!==1)fail('repair_proof_mismatch');return found[0].ref;};
    const selected=new Map<string,RawOriginal>();for(const items of (recovered as Obj).replica.entries.values())for(const item of items)selected.set(id(item.ref),item);
    for(const role of ['replica.manifest','replica.custody','return.owner','return.source','return.maintainer','return.sender']){const ref=reference(role);selected.set(id(ref),c.originals.get(id(ref)));}
    for(const item of [...(recovered as Obj).current_statuses,...c.archive])selected.set(id(item.ref),item);
    return Object.freeze({schema_version:'memory-vault-mailbox-replica-inbox/v1',received_at:this.#now(),slot:c.e.slot,sender:c.e.sender,source:c.e.source,target:c.e.target,maintainer:c.e.maintainer,target_storage_epoch:c.context.targetStorageEpoch,envelope_ref:c.context.expectedEnvelopeRef,limits:MAILBOX_REPLICA_LIMITS,manifest_ref:reference('replica.manifest'),custody_ref:reference('replica.custody'),consent_refs:Object.fromEntries(['owner','source','maintainer','sender'].map(n=>[n,reference('return.'+n)])),originals:[...selected.values()].sort((a,b)=>id(a.ref)<id(b.ref)?-1:1).map(v=>({ref:v.ref,raw_base64url:encodeBase64url(v.raw)})),status_refs:(recovered as Obj).current_statuses.map((v:Obj)=>v.ref),archive_status_refs:c.archive.map((v:Obj)=>v.ref)});
  }
}
