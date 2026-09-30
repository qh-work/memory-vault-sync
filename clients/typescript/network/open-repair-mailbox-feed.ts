/** Original feed custody and complete retained prefix. This authenticates
 * ciphertext layout; recipient decryption and current access remain separate. */
import {buildNewWire,parseNewWire,objectFields,rawRef,u53,RepairError} from './open-repair-wire.ts';
import type {RepairPolicy,RepairBudget,LocalRawResolver,RawOriginal} from './open-repair-wire.ts';
import {resolveHistoricalInputs} from './open-repair-history.ts';
import {verifyBoundedControlSignature} from './open-repair-original.ts';
import {verifyMailboxMemberInputs} from './open-repair-mailbox-member.ts';
import {emptyMailboxState,appendMailboxState,verifyMailboxInclusion} from './open-repair-mailbox-range.ts';
import {verifyStatusOriginal} from './open-repair-status.ts';
import {validateJwe} from './crypto.ts';
type Obj=Record<string,any>;
const COMMON=['schema_version','kind','signing_key'];
const SLOT_INPUT='mailbox.slot mailbox.read_grant mailbox.maintenance_root bootstrap.mailbox_feed resource.data_allocate resource.metadata_allocate resource.data_offer resource.metadata_offer resource.slot_activation resource.data_active resource.metadata_active source.descriptor'.split(' ');
export interface MailboxFeedOptions{readonly expectedSlot:unknown;readonly expectedOwner:unknown;readonly expectedSender:unknown;readonly expectedTarget:unknown;readonly limitPolicy:unknown;readonly policy:RepairPolicy;readonly budget:RepairBudget;}
const fields=(v:unknown,n:readonly string[]):Obj=>objectFields(v,n);
function fail(code='repair_mailbox_activation_mismatch'):never{throw new RepairError(code);}
function same(a:unknown,b:unknown):boolean{if(a===b)return true;if(!a||!b||typeof a!=='object'||typeof b!=='object'||Array.isArray(a)!==Array.isArray(b))return false;const keys=Object.keys(a);return keys.length===Object.keys(b).length&&keys.every(k=>Object.hasOwn(b,k)&&same((a as Obj)[k],(b as Obj)[k]));}
const refKey=(v:unknown)=>{const r=rawRef(v);return [r.namespace,r.key,r.raw_sha256,r.size].join(':');};
function parse(v:unknown,policy:RepairPolicy,budget:RepairBudget):RawOriginal{
  const entry=fields(v,['raw','ref']),ref=rawRef(entry.ref),raw=parseNewWire(entry.raw,policy,budget).raw;
  if(ref.namespace!=='meta'||ref.size!==raw.length||ref.raw_sha256!==budget.hash(raw))fail('repair_ref_mismatch');return {raw,ref};
}
export function verifyMailboxFeedSourceEvent(manifestEntry:unknown,resolver:LocalRawResolver,custodyEntry:unknown,options:MailboxFeedOptions):Readonly<Obj>{
  const args=fields(options,['expectedSlot','expectedOwner','expectedSender','expectedTarget','limitPolicy','policy','budget']),{policy,budget}=args;
  const e=buildNewWire({slot:args.expectedSlot,owner:args.expectedOwner,sender:args.expectedSender,target:args.expectedTarget,limits:args.limitPolicy},policy,budget).value as Obj,key=e.slot;
  emptyMailboxState(key,policy,budget);
  const custody=parse(custodyEntry,policy,budget),signed=fields(parseNewWire(custody.raw,policy,budget).value,['payload','proof']);
  const p=fields(signed.payload,[...COMMON,...'root_key slot_key slot_ref feed_head_ref covered_interval subtree historical_manifest_ref resource_refs stored_at read_until retain_until'.split(' ')]);
  if(p.schema_version!=='memory-vault-open-repair/v1'||p.kind!=='feed.custody'||!same(p.slot_key,key)||!same(p.root_key,key.root_key))fail();
  verifyBoundedControlSignature(p,signed.proof,e.target.signing_key,budget);
  const at=u53(p.stored_at);if(!(at<u53(p.read_until)&&p.read_until<=u53(p.retain_until)))fail();
  const original=parse(manifestEntry,policy,budget);if(!same(p.historical_manifest_ref,original.ref))fail();
  const resolved=resolveHistoricalInputs(original.raw,resolver,policy,budget),m=resolved.manifest.value as Obj;
  if(m.variant!=='mailbox_feed'||!same(m.slot_key,key)||!same(m.root_key,key.root_key))fail();
  for(const n of ['slot_ref','feed_head_ref','covered_interval','subtree'])if(!same(p[n],m[n]))fail();
  const byRef=new Map<string,{role:string;original:RawOriginal}>(),wanted=new Set<string>();
  for(const row of resolved.roles){const id=row.role+'|'+refKey(row.original.ref);if(byRef.has(id))fail();byRef.set(id,row);}
  const get=(role:string,ref:unknown):RawOriginal=>{const id=role+'|'+refKey(ref),row=byRef.get(id);if(!row)fail('repair_original_missing');wanted.add(id);
    const raw=row.original.raw;if(raw.length!==row.original.ref.size||budget.hash(raw)!==row.original.ref.raw_sha256)fail('repair_ref_mismatch');return {raw,ref:row.original.ref};};
  const event=(role:string,ref:unknown,kind:string,names:string):Obj=>{const entry=get(role,ref),signed=fields(parseNewWire(entry.raw,policy,budget).value,['payload','proof']);
    const value=fields(signed.payload,[...COMMON,'slot_key',...names.split(' ')]);
    if(value.schema_version!=='memory-vault-open-repair/v1'||value.kind!==kind||!same(value.slot_key,key))fail();verifyBoundedControlSignature(value,signed.proof,e.target.signing_key,budget);return value;};
  const HEAD='checkpoint_ref count range_root_ref catalog_generation committed_at retain_until',CHECKPOINT='slot_binding count leaf_root frontier committed_at retain_until';
  const head=event('feed.head',m.feed_head_ref,'mailbox.feed_head',HEAD),checkpoint=event('feed.checkpoint',head.checkpoint_ref,'mailbox.checkpoint',CHECKPOINT),count=u53(head.count,1);
  if(!same(m.covered_interval,{start:0,end:count})||!same(m.subtree,{root_ref:head.range_root_ref,parent_path_refs:[]})||checkpoint.count!==count||head.committed_at!==checkpoint.committed_at||head.retain_until!==checkpoint.retain_until||!(u53(head.committed_at)<=at&&at<u53(head.retain_until)))fail();
  const sealed=(role:string,ref:unknown,raw:Uint8Array,kind:string,extra:Obj):void=>{
    const entry=get(role,ref),context={schema_version:'memory-vault-open-repair/v1',kind,slot_key:key,plaintext_sha256:budget.hash(raw),plaintext_size:raw.length,...extra};
    let value;try{value=validateJwe(entry.raw,{context});}catch{fail();}
    if(value.recipients.length!==1||value.recipients[0].header?.kid!==e.owner.encryption_key.key_id)fail();};
  const predecessors=new Map(resolved.predecessors.map(v=>[budget.hash(v.manifest.raw),v])),members=new Map<number,Obj>(),setups:Obj[]=[],deadlines=[head.retain_until];
  for(const member of m.members){
    const sequence=u53(member.sequence),manifest=get('history.member',member.historical_manifest_ref),child=predecessors.get(manifest.ref.raw_sha256);
    if(!child)fail();const childValue=child.manifest.value as Obj;
    const core=event('member.core',member.admission_core_ref,'admission.core','core_id sequence message_id envelope_ref attempt_ref historical_manifest_ref data_resource_ref metadata_resource_ref accepted_at object_until enum_until');
    if(core.sequence!==sequence||['message_id','envelope_ref','historical_manifest_ref'].some(n=>!same(core[n],member[n]))||['message_id','envelope_ref','attempt_ref'].some(n=>!same(core[n],childValue[n]))||!(u53(core.accepted_at)<=at&&at<u53(core.enum_until)&&core.accepted_at<u53(core.object_until)&&core.object_until<=core.enum_until))fail();
    const setup=verifyMailboxMemberInputs(manifest,resolver,{expectedSlot:key,expectedOwner:e.owner,expectedSender:e.sender,expectedTarget:e.target,targetStorageEpoch:key.writer_storage_epoch,acceptedAt:core.accepted_at,limitPolicy:e.limits,policy,budget});
    setups.push(setup);deadlines.push(core.enum_until,setup.disclosure.consent_until,setup.disclosure.bootstrap_return.until);
    for(const role of SLOT_INPUT)get(role,setup.roles[role].ref);if(!same(setup.roles['mailbox.slot'].ref,m.slot_ref))fail();
    for(const n of ['data','metadata'])if(!same(core[n+'_resource_ref'],setup.resources[n].active.payload.resource))fail();
    const link=event('member.link',member.admission_link_ref,'admission.link','sequence message_id envelope_ref core_ref sealed_core_ref historical_manifest_ref checkpoint_ref inclusion_path');
    if(!same(link.core_ref,member.admission_core_ref)||link.sequence!==sequence||['message_id','envelope_ref','historical_manifest_ref'].some(n=>!same(link[n],core[n])))fail();
    sealed('member.sealed_core',link.sealed_core_ref,get('member.core',member.admission_core_ref).raw,'admission.sealed_core',{sequence});
    const cp=event('member.checkpoint',link.checkpoint_ref,'mailbox.checkpoint',CHECKPOINT);
    if(cp.count!==sequence+1||!(core.accepted_at<=u53(cp.committed_at)&&cp.committed_at<=head.committed_at)||u53(cp.retain_until)<core.enum_until)fail();
    verifyMailboxInclusion(Object.fromEntries(['slot_binding','count','leaf_root','frontier'].map(n=>[n,cp[n]])),sequence,link.sealed_core_ref.raw_sha256,link.inclusion_path,key,policy,budget);
    const custody=event('member.custody',member.source_custody_ref,'message.custody','root_key message_id envelope_ref admission_link_ref checkpoint_ref feed_head_ref resource_refs stored_at object_until enum_until');
    if(!same(custody.root_key,key.root_key)||!same(custody.admission_link_ref,member.admission_link_ref)||!same(custody.checkpoint_ref,link.checkpoint_ref)||custody.stored_at!==cp.committed_at||!same(custody.resource_refs,{data:core.data_resource_ref,metadata:core.metadata_resource_ref})||['message_id','envelope_ref','object_until','enum_until'].some(n=>!same(custody[n],core[n])))fail();
    const oldHead=event('member.head',custody.feed_head_ref,'mailbox.feed_head',HEAD);
    if(!same(oldHead.checkpoint_ref,link.checkpoint_ref)||oldHead.count!==sequence+1||oldHead.committed_at!==cp.committed_at||oldHead.retain_until!==cp.retain_until)fail();
    if(members.has(sequence))fail();members.set(sequence,{sequence,admission_link_ref:member.admission_link_ref,sealed_core_ref:link.sealed_core_ref});
  }
  if(members.size!==count||predecessors.size!==count)fail();
  let state=emptyMailboxState(key,policy,budget);
  const walk=(ref:unknown,level:number,start:number,end:number):void=>{
    const role=level>=0?'range.index':'range.repair_page',entry=get(role,ref),value=fields(parseNewWire(entry.raw,policy,budget).value,['schema_version','kind','slot_key','start','end',...(level>=0?['level','children']:['entries','sealed_page_ref'])]);
    if(value.schema_version!=='memory-vault-open-repair/v1'||value.kind!==role||!same(value.slot_key,key)||u53(value.start)!==start||u53(value.end)!==end)fail();
    if(level>=0){
      if(u53(value.level)!==level||!Array.isArray(value.children)||value.children.length<1||value.children.length>16)fail();let cursor=start;const span=16**(level+1);
      for(const row of value.children){fields(row,['start','end','ref']);const stop=Math.min(cursor+span,end);if(u53(row.start)!==cursor||u53(row.end)!==stop||cursor>=stop)fail();walk(row.ref,level-1,cursor,stop);cursor=stop;}
      if(cursor!==end)fail();
    }else{
      if(end-start<1||end-start>16||!same(value.entries,Array.from({length:end-start},(_,i)=>members.get(start+i))))fail();
      const plain=buildNewWire({schema_version:'memory-vault-open-repair/v1',kind:'range.private_page',slot_key:key,start,end,entries:value.entries},policy,budget).raw;
      sealed('range.sealed_page',value.sealed_page_ref,plain,'range.sealed_page',{start,end});
      for(const row of value.entries)state=appendMailboxState(state,row.sealed_core_ref.raw_sha256,key,policy,budget);
    }
  };
  let level=0;while(count>16**(level+2))level++;walk(head.range_root_ref,level,0,count);
  if(Object.keys(state).some(n=>!same((state as unknown as Obj)[n],checkpoint[n])))fail();
  const obligations=new Map<string,Obj>(),allowed=new Map<string,Obj>();
  const dutyKey=(v:Obj)=>[v.signer.key_id,v.scope_kind,v.scope_id].join(':');
  for(const setup of setups){
    for(const duty of setup.obligations){const id=dutyKey(duty);allowed.set(id,duty);if(!['destination','data_resource'].includes(duty.role))obligations.set(id,{...duty,operation_mask:duty.role==='read'?2:duty.role==='bootstrap'?10:66});}
    for(const n of ['slot','read','maintenance','bootstrap']){const v=setup.originals[n].payload;deadlines.push(v.expires_at);if(v.windows)deadlines.push(v.windows.read_until,v.windows.retain_until);}
    const v=setup.resources.metadata.active.payload;deadlines.push(v.windows.read_until,v.windows.retain_until);
  }
  const covered=new Set<string>(),statuses:Obj[]=[],revisions=new Map<string,string>(),cache=new Map<string,Obj>();
  for(const [id,{role,original:entry}] of byRef){
    if(!role.startsWith('historical.status.'))continue;
    const raw=entry.raw,preview=fields(parseNewWire(raw,policy,budget).value,['payload','proof']).payload;
    if(!preview||!preview.signing_key||!Array.isArray(preview.entries))fail('repair_invalid_status');const issuer=preview.signing_key.key_id;
    const present=new Set(preview.entries.map((v:Obj)=>{if(!v||typeof v.scope_kind!=='string'||typeof v.scope_id!=='string')fail('repair_invalid_status');return v.scope_kind+':'+v.scope_id;}));
    const included=([...obligations] as [string,Obj][]).filter(([,v])=>v.signer.key_id===issuer&&present.has(v.scope_kind+':'+v.scope_id)),matches=included.filter(([,v])=>role==='historical.status.'+v.role);
    if(!matches.length)fail();
    const context={expectedRoot:key.root_key,expectedSigningKey:matches[0][1].signer,at,allowedScopes:[...allowed.values()].filter(v=>v.signer.key_id===issuer).map(v=>({scope_kind:v.scope_kind,scope_id:v.scope_id})),
      required:included.map(([,v])=>({scope_kind:v.scope_kind,scope_id:v.scope_id,document_revision:v.document_revision,operation_mask:v.operation_mask}))};
    const contextRaw=buildNewWire(context,policy,budget).raw,cacheKey=refKey(entry.ref)+':'+budget.hash(contextRaw);let observed=cache.get(cacheKey);
    if(!observed){observed=verifyStatusOriginal({raw,ref:entry.ref},{...context,policy,budget});budget.retain(raw.length+contextRaw.length);cache.set(cacheKey,observed);}
    const revision=issuer+':'+observed.payload.revision;if(revisions.has(revision)&&revisions.get(revision)!==observed.canonical_sha256)fail('repair_status_conflict');
    revisions.set(revision,observed.canonical_sha256);for(const [identity] of matches)covered.add(identity);statuses.push(observed);wanted.add(id);
  }
  if(covered.size!==obligations.size||[...obligations.keys()].some(id=>!covered.has(id)))fail('repair_status_missing');
  const floors=new Map<string,number[][]>();
  for(const observed of [...statuses,...setups.flatMap(v=>v.statuses)]){
    const issuer=observed.payload.scope_key.issuer_key_id,revision=observed.payload.revision,id=issuer+':'+revision;
    if(revisions.has(id)&&revisions.get(id)!==observed.canonical_sha256)fail('repair_status_conflict');revisions.set(id,observed.canonical_sha256);
    for(const row of observed.payload.entries){const identity=[issuer,row.scope_kind,row.scope_id].join(':'),required=obligations.get(identity);
      if(required&&row.status==='revoked'&&(row.operation_mask&required.operation_mask))fail('repair_authority_revoked');
      if(required&&row.minimum_document_revision>required.document_revision)fail('repair_status_revision');
      const held=floors.get(identity)??[];held.push([revision,row.minimum_document_revision]);floors.set(identity,held);}
  }
  for(const values of floors.values()){let min=0;for(const [,floor] of values.sort((a,b)=>a[0]-b[0]||a[1]-b[1])){if(floor<min)fail('repair_status_rollback');min=floor;}}
  for(const observed of statuses)for(const row of observed.payload.entries){const values=floors.get([observed.payload.scope_key.issuer_key_id,row.scope_kind,row.scope_id].join(':'))!;
    if(values.some(v=>v[0]>observed.payload.revision))fail('repair_status_rollback');}
  if(wanted.size!==byRef.size||at>=Math.min(...deadlines))fail();
  const graph=Object.freeze({head,checkpoint,members:Object.freeze(setups),statuses:Object.freeze(statuses),obligations:Object.freeze([...obligations.values()].map(Object.freeze)),retain_until:Math.min(...deadlines),metadata_resource:setups[0].resources.metadata.active.payload.resource});
  if(!same(p.resource_refs,{metadata:graph.metadata_resource,dependencies:[]})||p.retain_until>graph.retain_until)fail();
  return Object.freeze({manifest:resolved,graph,custody:Object.freeze({ref:custody.ref,payload:p,get raw(){budget.output(custody.raw.length);return Uint8Array.from(custody.raw);}}),read_until:p.read_until,retain_until:p.retain_until});
}
