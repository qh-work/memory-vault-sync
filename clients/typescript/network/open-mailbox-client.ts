/** Bounded native HTTP recovery of an original mailbox feed and message body. */
import {performance} from 'node:perf_hooks';
import {OpenHTTPTransport,endpoint} from './open-transport.ts';
import {RepairBudget,RepairError,buildNewWire,parseNewWire,objectFields,rawRef,u53,LocalRawResolver} from './open-repair-wire.ts';
import type {RawOriginal,RawRef,RepairPolicy} from './open-repair-wire.ts';
import {DEFAULT_REPAIR_CLIENT_POLICY,DEFAULT_REPAIR_CLIENT_LIMITS} from './open-repair-client.ts';
import {validateSigningIdentity,validateEncryptionIdentity,encodeBase64url} from './crypto.ts';
import {verifySourceNodeOriginal} from './open-repair-original.ts';
import {verifyMailboxFeedBootstrap} from './open-repair-mailbox-authority.ts';
import {verifyMailboxFeedSourceEvent} from './open-repair-mailbox-feed.ts';
import {resolveHistoricalInputs} from './open-repair-history.ts';
import {makeBootstrapProbe,solveBootstrapChallenge} from './open-repair-probe.ts';
import {verifyBootstrapProofResponse,makeBootstrapChildRequest,makeMailboxBodyRequest} from './open-repair-proof.ts';
import {authenticateStatusOriginal,verifyStatusOriginal} from './open-repair-status.ts';
import type {AuthenticatedStatusOriginal} from './open-repair-status.ts';
import {readMailboxIndex,readMailboxAdmission} from './open-repair-mailbox-read.ts';
import {MailboxSetupJournal} from './open-mailbox-journal.ts';
type Obj=Record<string,any>;
const monotonic=()=>performance.now()/1000;
const fields=(v:unknown,n:readonly string[]):Obj=>objectFields(v,n);
function fail(code:string):never{throw new RepairError(code);}
function options(v:unknown,required:string[],optional:string[]):Obj{
  if(!v||typeof v!=='object')fail('repair_invalid_context');return fields(v,[...required,...optional.filter(n=>Object.hasOwn(v,n))]);
}
function same(a:unknown,b:unknown):boolean{if(a===b)return true;if(!a||!b||typeof a!=='object'||typeof b!=='object'||Array.isArray(a)!==Array.isArray(b))return false;const keys=Object.keys(a);return keys.length===Object.keys(b).length&&keys.every(k=>Object.hasOwn(b,k)&&same((a as Obj)[k],(b as Obj)[k]));}
const id=(v:unknown)=>{const r=rawRef(v);return [r.namespace,r.key,r.raw_sha256,r.size].join(':');};
function snapshot(v:unknown,policy:RepairPolicy,budget:RepairBudget):RawOriginal{const e=fields(v,['raw','ref']),ref=rawRef(e.ref),raw=parseNewWire(e.raw,policy,budget).raw;if(ref.namespace!=='meta'||ref.size!==raw.length||budget.hash(raw)!==ref.raw_sha256)fail('repair_ref_mismatch');return {ref,raw};}
function statusPreview(raw:Uint8Array,policy:RepairPolicy,budget:RepairBudget):Obj{
  const p=fields(fields(parseNewWire(raw,policy,budget).value,['payload','proof']).payload,['schema_version','kind','signing_key','scope_key','revision','issued_at','valid_until','entries']);
  if(!Array.isArray(p.entries)||p.entries.length<1||p.entries.length>16)fail('repair_invalid_status');for(const row of p.entries)fields(row,['scope_kind','scope_id','status','minimum_document_revision','operation_mask']);return p;
}
function floors(retained:readonly Obj[],current:readonly Obj[],obligations:readonly Obj[]):void{
  const required=new Map(obligations.map(v=>[[v.signer.key_id,v.kind,v.scope_id].join(':'),v])),seen=new Map<string,string>(),values=new Map<string,number[][]>();
  for(const observed of [...retained,...current]){const p=observed.payload,issuer=p.scope_key.issuer_key_id,revision=p.revision,key=issuer+':'+revision;
    if(seen.has(key)&&seen.get(key)!==observed.canonical_sha256)fail('repair_status_conflict');seen.set(key,observed.canonical_sha256);
    for(const row of p.entries){const k=[issuer,row.scope_kind,row.scope_id].join(':'),wanted=required.get(k);
      if(wanted&&row.status==='revoked'&&(row.operation_mask&wanted.mask))fail('repair_authority_revoked');
      if(wanted&&row.minimum_document_revision>wanted.revision)fail('repair_status_revision');
      const held=values.get(k)??[];held.push([revision,row.minimum_document_revision]);values.set(k,held);}
  }
  for(const held of values.values()){let minimum=0;for(const [,v] of held.sort((a,b)=>a[0]-b[0]||a[1]-b[1])){if(v<minimum)fail('repair_status_rollback');minimum=v;}}
  for(const observed of current)for(const row of observed.payload.entries){const p=observed.payload,key=[p.scope_key.issuer_key_id,row.scope_kind,row.scope_id].join(':');if(values.get(key)!.some(v=>v[0]>p.revision))fail('repair_status_rollback');}
}
export interface MailboxClientOptions{readonly policy?:RepairPolicy;readonly limitPolicy?:unknown;readonly allowLoopback?:boolean;readonly transport?:OpenHTTPTransport;readonly clock?:()=>number;readonly statusObserver?:(item:AuthenticatedStatusOriginal)=>void;readonly networkObserver?:()=>void;}
export interface MailboxRecoverOptions{readonly targetNodeEntry:unknown;readonly expectedTarget:unknown;readonly expectedSender:unknown;readonly expectedSlot:unknown;readonly slotEntries:unknown;readonly journal:MailboxSetupJournal;readonly knownStatuses?:readonly unknown[];readonly archiveStatuses?:readonly unknown[];readonly timeout?:number;}
export interface RecoveredMailboxFeed{readonly source:Readonly<Obj>;readonly proof:Obj;readonly current_statuses:readonly AuthenticatedStatusOriginal[];readonly originals:readonly RawOriginal[];readonly entries:readonly Obj[];readonly metrics:Readonly<Obj>;readonly base_url:string;}
export class MailboxFeedRecoveryClient{
  readonly #identity:Obj;readonly #encryption:Obj;readonly #subject:Obj;readonly #policy:RepairPolicy;readonly #limits:Obj;
  readonly #transport:OpenHTTPTransport;readonly #ownTransport:boolean;readonly #loopback:boolean;readonly #clock:()=>number;readonly #observer?: (v:AuthenticatedStatusOriginal)=>void;readonly #networkObserver?:()=>void;
  readonly #feeds=new WeakMap<object,Obj>();
  constructor(identity:unknown,encryptionIdentity:unknown,value:MailboxClientOptions={}){
    const a=options(value,[],['policy','limitPolicy','allowLoopback','transport','clock','statusObserver','networkObserver']);const budget=new RepairBudget(a.policy??{...DEFAULT_REPAIR_CLIENT_POLICY,max_signature_checks:512});this.#policy=budget.policy;
    const held=buildNewWire({identity,encryption:encryptionIdentity,limits:a.limitPolicy??DEFAULT_REPAIR_CLIENT_LIMITS},this.#policy,budget).value as Obj;
    this.#identity=held.identity;this.#encryption=held.encryption;this.#subject=buildNewWire({signing_key:validateSigningIdentity(held.identity),encryption_key:validateEncryptionIdentity(held.encryption)},this.#policy,budget).value as Obj;
    this.#limits=fields(held.limits,Object.keys(DEFAULT_REPAIR_CLIENT_LIMITS));for(const n of Object.keys(this.#limits))u53(this.#limits[n],1);
    if((a.allowLoopback!==undefined&&typeof a.allowLoopback!=='boolean')||(a.clock!==undefined&&typeof a.clock!=='function')||(a.statusObserver!==undefined&&typeof a.statusObserver!=='function')||(a.networkObserver!==undefined&&typeof a.networkObserver!=='function'))fail('repair_invalid_policy');
    this.#loopback=a.allowLoopback??false;this.#clock=a.clock??(()=>Date.now()/1000);this.#observer=a.statusObserver;this.#networkObserver=a.networkObserver;this.#transport=a.transport??new OpenHTTPTransport({allow_loopback:this.#loopback});this.#ownTransport=a.transport===undefined;Object.freeze(this);
  }
  get subject():Readonly<Obj>{return this.#subject;}
  get limits():Readonly<Obj>{return this.#limits;}
  inboxEvidence(feed:RecoveredMailboxFeed,member:unknown):Readonly<Obj>{
    const c=this.#feeds.get(feed);if(!c||!feed.entries.some(v=>same(v,member)))fail('repair_invalid_context');
    const children=(c.held.manifest.value as Obj).children,reference=(role:string)=>{const found=children.filter((v:Obj)=>v.role===role);if(found.length!==1)fail('repair_proof_mismatch');return found[0].ref;};
    return Object.freeze({schema_version:'memory-vault-mailbox-inbox/v1',received_at:this.#now(),slot:c.e.slot,sender:c.e.sender,target:c.e.target,limits:this.#limits,member,
      manifest_ref:reference('history.mailbox_feed'),custody_ref:reference('feed.custody'),originals:feed.originals.map(v=>({ref:v.ref,raw_base64url:encodeBase64url(v.raw)})),status_refs:feed.current_statuses.map(v=>v.ref)});
  }
  close():void{if(this.#ownTransport)this.#transport.close();}
  #now():number{return u53(Math.floor(this.#clock()));}
  #timeout(v:unknown):number{if(typeof v!=='number'||!Number.isFinite(v)||v<=0||v>60)fail('repair_invalid_deadline');return v;}
  #observe(journal:MailboxSetupJournal,key:string,item:AuthenticatedStatusOriginal):void{journal.observe(key,item);this.#observer?.(item);}
  #known(entries:readonly unknown[],e:Obj,at:number,budget:RepairBudget,journal:MailboxSetupJournal,key:string):AuthenticatedStatusOriginal[]{
    if(!Array.isArray(entries)||entries.length>32)fail('repair_status_history_capacity');const result=[];
    for(const item of entries){const entry=snapshot(item,this.#policy,budget),p=statusPreview(entry.raw,this.#policy,budget),signer=p.signing_key,permitted=new Set<string>();
      if(same(signer,this.#subject.signing_key)){permitted.add('mailbox_slot');permitted.add('authority');}
      if(same(signer,e.sender.signing_key))permitted.add('authority');if(same(signer,e.target.signing_key))permitted.add('resource');
      if(!permitted.size||p.entries.some((v:Obj)=>!permitted.has(v.scope_kind))||u53(p.issued_at)>at)fail('repair_status_disclosure');
      const observed=authenticateStatusOriginal(entry,{expectedRoot:e.slot.root_key,expectedSigningKey:signer,at:p.issued_at,allowedScopes:p.entries.map((v:Obj)=>({scope_kind:v.scope_kind,scope_id:v.scope_id})),policy:this.#policy,budget},v=>this.#observe(journal,key,v));
      result.push(observed);if(p.entries.some((v:Obj)=>v.status==='revoked'&&(v.operation_mask&10)))fail('repair_authority_revoked');
    }return result;
  }
  async recover(baseUrl:string,value:MailboxRecoverOptions):Promise<RecoveredMailboxFeed>{
    const a=options(value,['targetNodeEntry','expectedTarget','expectedSender','expectedSlot','slotEntries','journal'],['knownStatuses','archiveStatuses','timeout']);
    if(!(a.journal instanceof MailboxSetupJournal))fail('repair_invalid_context');const journal=a.journal as MailboxSetupJournal;
    const timeout=this.#timeout(a.timeout??60),policy=this.#policy,budget=new RepairBudget(policy),started=this.#now(),deadline=monotonic()+timeout;
    const e=buildNewWire({slot:a.expectedSlot,target:a.expectedTarget,sender:a.expectedSender},policy,budget).value as Obj;
    const setup=verifyMailboxFeedBootstrap(a.slotEntries,{expectedSlot:e.slot,expectedOwner:this.#subject,expectedTarget:e.target,targetStorageEpoch:e.slot.writer_storage_epoch,limitPolicy:this.#limits,at:started,policy,budget});
    if(!same(setup.slot.payload.sender,{signing_key_id:e.sender.signing_key.key_id,encryption_key_id:e.sender.encryption_key.key_id}))fail('repair_proof_mismatch');
    const nodeEntry=snapshot(a.targetNodeEntry,policy,budget),node=verifySourceNodeOriginal(nodeEntry.raw,{expectedSigningKey:e.target.signing_key,expectedStorageEpoch:e.slot.writer_storage_epoch,at:started,policy,budget});
    if(!same(endpoint(baseUrl,this.#loopback),endpoint(node.payload.base_url,this.#loopback)))fail('repair_proof_mismatch');
    const journalKey=journal.start({kind:'mailbox.feed_recovery',slot_key:e.slot,owner:this.#subject,sender:e.sender,target:e.target,entries:Object.fromEntries(Object.entries(setup).map(([n,v])=>[n,v.ref]))});
    const retained=new Map<string,RawOriginal>();for(const group of [a.knownStatuses??[],a.archiveStatuses??[],journal.statuses(journalKey)]){
      if(!Array.isArray(group)||group.length>32)fail('repair_status_history_capacity');for(const item of group){const entry=snapshot(item,policy,budget);retained.set(entry.ref.raw_sha256+':'+entry.ref.size,entry);}}
    const known=this.#known([...retained.values()],e,started,budget,journal,journalKey),grant=setup.bootstrap.payload;
    const expiry=Math.min(started+Math.min(60,Math.max(1,Math.floor(timeout))),node.payload.expires_at as number,grant.probe_until,grant.proof_until,...Object.values(setup).map(v=>v.payload.expires_at as number));if(expiry<=started)fail('repair_access_expired');
    const counts={requests:0,wire_bytes:0,proof_bytes:0};
    const request=async(raw:Uint8Array,child=false):Promise<Uint8Array>=>{if(counts.requests>=grant.limits.max_requests||monotonic()>=deadline)fail('repair_over_budget');counts.requests++;
      this.#networkObserver?.();const reply=await this.#transport.requestRepair(baseUrl,raw,deadline,{child});counts.wire_bytes+=raw.length+reply.length;return reply;};
    const binding={expectedSubject:this.#subject,expectedTarget:e.target,targetStorageEpoch:e.slot.writer_storage_epoch,bootstrapGrantSha256:setup.bootstrap.ref.raw_sha256,selector:grant.selector,consumer:'mailbox_feed' as const,policy,budget};
    const outgoing=await makeBootstrapProbe(this.#identity,{...binding,at:started,expiresAt:expiry}),outgoingRaw=outgoing.original.raw;if(outgoingRaw.length>grant.limits.max_probe_bytes)fail('repair_over_budget');
    const challengeRaw=await request(outgoingRaw),digest=budget.hash(challengeRaw),challenge={raw:challengeRaw,ref:rawRef({namespace:'meta',key:digest,raw_sha256:digest,size:challengeRaw.length})};
    const preview=fields(parseNewWire(challengeRaw,policy,budget).value,['payload','proof']);
    const answer=await solveBootstrapChallenge({raw:outgoingRaw,ref:outgoing.original.ref},challenge,{...binding,signer:this.#identity,encryptionIdentity:this.#encryption,targetNonce:outgoing.nonce,at:this.#now(),expiresAt:Math.min(expiry,u53(preview.payload?.expires_at))});
    const response=await request(answer.raw),held=verifyBootstrapProofResponse(response,{expectedSubject:this.#subject,expectedTarget:e.target,targetStorageEpoch:e.slot.writer_storage_epoch,selector:grant.selector,bootstrapGrantRef:setup.bootstrap.ref,
      probeRef:outgoing.original.ref,challengeRef:challenge.ref,answerRef:answer.ref,at:this.#now(),maxProofItems:grant.limits.max_proof_items,maxProofBytes:grant.limits.max_proof_bytes,expectedSourceState:'feed',consumer:'mailbox_feed',policy,budget});
    counts.proof_bytes=response.length+held.handle.raw.length+held.manifest.raw.length;
    const originals=new Map<string,RawOriginal>(),roles=new Map<string,RawRef[]>(),available=new Map<string,Uint8Array>();
    for(const entry of [...Object.values(setup),...known,nodeEntry])available.set(id(entry.ref),entry.raw);
    const children=(held.manifest.value as Obj).children;
    for(const item of children){const reference=rawRef(item.ref);roles.set(item.role,[...(roles.get(item.role)??[]),reference]);}
    const download=async(item:Obj):Promise<void>=>{const ref=rawRef(item.ref),key=id(ref);if(originals.has(key))return;
      if(ref.size>policy.max_document_bytes||counts.proof_bytes+ref.size>grant.limits.max_proof_bytes)fail('repair_over_budget');let raw=available.get(key);
      if(raw)budget.input(raw.length);else{const chunks:Uint8Array[]=[];let offset=0;while(offset<ref.size){const count=Math.min(65536,ref.size-offset),packet=makeBootstrapChildRequest(this.#identity,held,{subject:this.#subject,target:e.target,at:this.#now(),expiresAt:held.handle.payload.expires_at as number,childIndex:item.index,offset,requestedBytes:count,policy,budget});
          const received=await request(packet.raw,true);if(received.length!==count)fail('repair_ref_mismatch');budget.input(received.length);chunks.push(received);offset+=count;}
        budget.output(ref.size);raw=Buffer.concat(chunks);}
      if(raw.length!==ref.size||budget.hash(raw)!==ref.raw_sha256)fail('repair_ref_mismatch');budget.retain(raw.length);originals.set(key,{raw,ref});counts.proof_bytes+=raw.length;};
    for(const item of children)if(['history.raw_pack','history.mailbox_feed'].includes(item.role))await download(item);
    const packed=new LocalRawResolver(policy,budget);for(const ref of roles.get('history.raw_pack')??[]){const item=originals.get(id(ref))!;if(!same(packed.put(ref.namespace,ref.key,item.raw).ref,ref))fail('repair_ref_mismatch');}
    const reuse=(tree:Obj):void=>{for(const row of tree.roles){const key=id(row.original.ref),raw=row.original.raw,prior=available.get(key);if(prior&&!Buffer.from(prior).equals(Buffer.from(raw)))fail('repair_ref_conflict');available.set(key,raw);}for(const child of tree.predecessors)reuse(child);};
    for(const ref of roles.get('history.mailbox_feed')??[]){const tree=resolveHistoricalInputs(originals.get(id(ref))!.raw,packed,policy,budget);if((tree.manifest.value as Obj).variant!=='mailbox_feed')fail('repair_proof_mismatch');reuse(tree);}
    for(const item of children)await download(item);
    const entry=(ref:unknown)=>{const item=originals.get(id(ref));if(!item)fail('repair_original_missing');return item;};
    const one=(role:string)=>{const refs=roles.get(role);if(!refs||refs.length!==1)fail('repair_proof_mismatch');return entry(refs[0]);};
    const source=verifyMailboxFeedSourceEvent(one('history.mailbox_feed'),packed,one('feed.custody'),{expectedSlot:e.slot,expectedOwner:this.#subject,expectedSender:e.sender,expectedTarget:e.target,limitPolicy:this.#limits,policy,budget});
    for(const member of source.graph.members)for(const [name,parent] of Object.entries(setup)){const actual=member.originals[name];if(!same(actual.ref,parent.ref)||!Buffer.from(actual.raw).equals(Buffer.from(parent.raw)))fail('repair_proof_mismatch');}
    const actual=new Set<string>(),wanted=new Set<string>();for(const [role,refs] of roles)if(!role.startsWith('current.status.'))for(const ref of refs)actual.add(role+'|'+id(ref));
    for(const tree of [source.manifest,...source.manifest.predecessors]){for(const row of tree.roles)wanted.add(row.role+'|'+id(row.original.ref));for(const row of tree.manifest.value.roles)wanted.add('history.raw_pack|'+id(row.pack_ref));}
    for(const role of ['history.mailbox_feed','feed.custody'])wanted.add(role+'|'+id(one(role).ref));if(actual.size!==wanted.size||[...actual].some(k=>!wanted.has(k)))fail('repair_proof_mismatch');
    const duties=source.graph.obligations.map((v:Obj)=>({role:'current.status.'+v.role,kind:v.scope_kind,scope_id:v.scope_id,revision:v.document_revision,signer:v.signer,mask:['slot','maintenance','bootstrap'].includes(v.role)?10:2}));
    const allowed=new Map<string,Obj>();for(const member of source.graph.members)for(const v of member.obligations)allowed.set([v.signer.key_id,v.scope_kind,v.scope_id].join(':'),v);
    const current:AuthenticatedStatusOriginal[]=[],covered=new Set<string>();
    for(const [role,refs] of roles){if(!role.startsWith('current.status.'))continue;for(const ref of refs){const item=entry(ref),p=statusPreview(item.raw,policy,budget),present=new Set(p.entries.map((v:Obj)=>v.scope_kind+':'+v.scope_id)),permitted=duties.filter((v:Obj)=>same(v.signer,p.signing_key)),matched=permitted.filter((v:Obj)=>v.role===role&&present.has(v.kind+':'+v.scope_id));
      if(!matched.length)fail('repair_status_disclosure');const observed=verifyStatusOriginal(item,{expectedRoot:e.slot.root_key,expectedSigningKey:matched[0].signer,at:this.#now(),allowedScopes:[...allowed.values()].filter(v=>v.signer.key_id===p.signing_key.key_id).map(v=>({scope_kind:v.scope_kind,scope_id:v.scope_id})),
        required:permitted.filter((v:Obj)=>present.has(v.kind+':'+v.scope_id)).map((v:Obj)=>({scope_kind:v.kind,scope_id:v.scope_id,document_revision:v.revision,operation_mask:v.mask})),policy,budget},v=>this.#observe(journal,journalKey,v));
      current.push(observed);for(const v of matched)covered.add([v.role,v.kind,v.scope_id].join(':'));}}
    const expectedCoverage=new Set(duties.map((v:Obj)=>[v.role,v.kind,v.scope_id].join(':')));if(covered.size!==expectedCoverage.size||[...expectedCoverage].some(k=>!covered.has(k)))fail('repair_status_missing');
    const historic=[...source.graph.statuses,...source.graph.members.flatMap((v:Obj)=>v.statuses)];floors([...known,...historic],current,duties);
    const members=await readMailboxIndex(one('feed.head'),one('feed.checkpoint'),{expectedSlot:e.slot,expectedSigningKey:e.target.signing_key,encryptionIdentity:this.#encryption as any,readOriginal:ref=>entry(ref).raw,at:this.#now(),maxMessages:setup.slot.payload.max_appends,policy,budget});
    const until=Math.min(expiry,held.handle.payload.expires_at as number,source.read_until,source.retain_until,...current.map(v=>v.payload.valid_until as number));if(this.#now()>=until||monotonic()>=deadline)fail('repair_access_expired');
    verifyMailboxFeedBootstrap(Object.fromEntries(Object.entries(setup).map(([n,v])=>[n,{ref:v.ref,raw:v.raw}])),{expectedSlot:e.slot,expectedOwner:this.#subject,expectedTarget:e.target,targetStorageEpoch:e.slot.writer_storage_epoch,limitPolicy:this.#limits,at:this.#now(),policy,budget});
    const result=Object.freeze({source,proof:held,current_statuses:Object.freeze(current),originals:Object.freeze([...originals.values()].map(v=>Object.freeze({ref:v.ref,get raw(){return Uint8Array.from(v.raw);}}))),entries:members,metrics:Object.freeze({...counts,...budget.snapshot()}),base_url:baseUrl});
    this.#feeds.set(result,{e,setup,source,held,originals,journal,journalKey,current,counts,until,budget});return result;
  }
  async readMember(baseUrl:string,feed:RecoveredMailboxFeed,member:unknown,value:{knownStatuses?:readonly unknown[];timeout?:number}={}):Promise<Readonly<Obj>>{
    const c=this.#feeds.get(feed),a=options(value,[],['knownStatuses','timeout']);if(!c||!same(endpoint(baseUrl,this.#loopback),endpoint(feed.base_url,this.#loopback)))fail('repair_proof_mismatch');
    const {e,source,held,originals,journal,journalKey,current,counts,budget}=c,policy=this.#policy,timeout=this.#timeout(a.timeout??30),deadline=monotonic()+timeout;
    const selected=buildNewWire(member,policy,budget).value;if(!feed.entries.some(v=>same(v,selected)))fail('repair_invalid_context');
    const guard=()=>{if(this.#now()>=c.until||monotonic()>=deadline)fail('repair_access_expired');};guard();
    const known=a.knownStatuses??[];if(!Array.isArray(known)||known.length>32)fail('repair_status_history_capacity');
    const retained=new Map<string,RawOriginal>();for(const item of [...known,...journal.statuses(journalKey)]){const entry=snapshot(item,policy,budget);retained.set(entry.ref.raw_sha256+':'+entry.ref.size,entry);}if(retained.size>32)fail('repair_status_history_capacity');
    const item=selected as Obj;const link=originals.get(id(item.admission_link_ref));if(!link)fail('repair_original_missing');const linkValue=fields(parseNewWire(link.raw,policy,budget).value,['payload','proof']).payload;
    const children=(held.manifest.value as Obj).children.filter((v:Obj)=>v.role==='member.core'&&same(v.ref,linkValue.core_ref));if(children.length!==1)fail('repair_proof_mismatch');
    const readOriginal=async(ref:RawRef):Promise<Uint8Array>=>{if(ref.namespace==='meta'){const original=originals.get(id(ref));if(!original)fail('repair_original_missing');return original.raw;}
      guard();if(counts.proof_bytes+ref.size>c.setup.bootstrap.payload.limits.max_proof_bytes)fail('repair_over_budget');const chunks:Uint8Array[]=[];let offset=0;
      while(offset<ref.size){guard();if(counts.requests>=c.setup.bootstrap.payload.limits.max_requests)fail('repair_over_budget');const count=Math.min(65536,ref.size-offset),packet=makeMailboxBodyRequest(this.#identity,held,ref,{subject:this.#subject,target:e.target,at:this.#now(),expiresAt:held.handle.payload.expires_at as number,childIndex:children[0].index,offset,requestedBytes:count,policy,budget});
        counts.requests++;this.#networkObserver?.();const raw=await this.#transport.requestRepair(baseUrl,packet.raw,deadline,{child:true});counts.wire_bytes+=packet.raw.length+raw.length;if(raw.length!==count)fail('repair_ref_mismatch');budget.input(raw.length);chunks.push(raw);counts.proof_bytes+=raw.length;offset+=raw.length;}
      guard();budget.output(ref.size);return Buffer.concat(chunks);};
    const result=await readMailboxAdmission(selected,{expectedSlot:e.slot,expectedSigningKey:e.target.signing_key,expectedOwner:this.#subject,expectedSender:e.sender,expectedTarget:e.target,encryptionIdentity:this.#encryption as any,readOriginal,at:this.#now(),
      currentStatuses:current.map((v:AuthenticatedStatusOriginal)=>({ref:v.ref,raw:v.raw})),knownStatuses:[...retained.values()],statusObligations:source.graph.obligations,onStatusAuthenticated:v=>this.#observe(journal,journalKey,v),limitPolicy:this.#limits,policy,budget});guard();return result;
  }
}
