/** Complete original message COPY closure and independent present READ.
 * A target custody signature alone never authorizes disclosure or decryption.
 * This verifier has no storage, transport, admission or publication effects. */
import {buildNewWire,parseNewWire,objectFields,rawRef,u53,RepairError} from './open-repair-wire.ts';
import type {RepairPolicy,RepairBudget,RawOriginal,LocalRawResolver} from './open-repair-wire.ts';
import {verifyBoundedControlSignature} from './open-repair-original.ts';
import {statusScope,authenticateStatusOriginal} from './open-repair-status.ts';
import {verifyMailboxFeedSourceEvent} from './open-repair-mailbox-feed.ts';
type Obj=Record<string,any>;
const COMMON=['schema_version','kind','signing_key'],SCHEMA='memory-vault-open-repair/v1';
const BUDGET='max_live_bytes max_meta_bytes max_items max_requests max_pending max_replay_records max_jobs max_job_bytes'.split(' ');
const WINDOWS='admit_until read_until copy_until publish_until retain_until'.split(' ');
const ALLOCATE='issued_at expires_at request_id target_node_key_id target_storage_epoch intent intent_sha256';
const OFFER='issued_at reservation_until offer_id allocation_request_ref intent intent_sha256 resource target_encryption_key reservation_generation budget windows';
const ASSIGNMENT='issued_at expires_at assignment_id job_id root_key parent_root_ref parent_assignment_ref depth subject target_node_key_id target_storage_epoch operation_mask scope resource_intent_sha256 resource_offer_ref resource bootstrap_grant_refs budget windows';
const RESERVATION='issued_at expires_at consent_id revision variant root_authority_ref source_custody_ref historical_manifest_ref maintainer target target_storage_epoch reservation_disclosure';
const DISCLOSURE='issued_at expires_at consent_id revision variant root_key assignment_ref source_custody_ref historical_manifest_ref target target_storage_epoch disclosure';
const RETURN='issued_at expires_at consent_id revision variant root_key source_custody_ref historical_manifest_ref assignment_ref subject target target_storage_epoch bootstrap_grant_ref return_permission';
const CUSTODY='root_key scope original_custody_ref replica_manifest_ref assignment_ref resource_offer_ref resource reservation_generation stored_at read_until retain_until';
export const replicaFields=objectFields;
export function replicaFail(code='repair_copy_authority_mismatch'):never{throw new RepairError(code);}
export function replicaSame(a:unknown,b:unknown):boolean{if(a===b)return true;if(!a||!b||typeof a!=='object'||typeof b!=='object'||Array.isArray(a)!==Array.isArray(b))return false;const keys=Object.keys(a);return keys.length===Object.keys(b).length&&keys.every(k=>Object.hasOwn(b,k)&&replicaSame((a as Obj)[k],(b as Obj)[k]));}
export const replicaRefKey=(v:unknown)=>{const r=rawRef(v);return [r.namespace,r.key,r.raw_sha256,r.size].join(':');};
const pair=(role:string,ref:unknown)=>role+'|'+replicaRefKey(ref);
const sorted=<T>(values:T[],key:(v:T)=>string)=>values.sort((a,b)=>key(a)<key(b)?-1:key(a)>key(b)?1:0);
const require=(v:unknown,code='repair_copy_authority_mismatch')=>{if(!v)replicaFail(code);};
const opaque=(v:unknown)=>{require(typeof v==='string'&&/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.exec(v)?.[0]===v);return v;};
const ids=(v:Obj)=>({signing_key_id:v.signing_key.key_id,encryption_key_id:v.encryption_key.key_id});
function windows(v:Obj,at?:number):void{objectFields(v,WINDOWS);for(const n of WINDOWS){u53(v[n]);require(v[n]<=v.retain_until&&(at===undefined||v[n]>at));}}
function capacity(v:Obj):void{objectFields(v,BUDGET);for(const n of BUDGET)u53(v[n]);}
function lifetime(v:Obj,at?:number):void{u53(v.issued_at);u53(v.expires_at);require(v.issued_at<v.expires_at&&(at===undefined||v.issued_at<=at&&at<v.expires_at));}
function resource(v:Obj):void{objectFields(v,['node_key_id','storage_epoch','lease_id','resource_id']);require(/^ed25519_[0-9a-f]{64}$/.test(v.node_key_id));for(const n of ['storage_epoch','lease_id','resource_id'])opaque(v[n]);}
export function replicaEntry(v:unknown,policy:RepairPolicy,budget:RepairBudget):RawOriginal{
  const e=objectFields(v,['raw','ref']),ref=rawRef(e.ref);const raw=parseNewWire(e.raw as Uint8Array,policy,budget).raw;
  require(ref.namespace==='meta'&&raw.length===ref.size&&budget.hash(raw)===ref.raw_sha256,'repair_ref_mismatch');return {ref,raw};
}
function signed(v:unknown,key:unknown,kind:string,names:string,policy:RepairPolicy,budget:RepairBudget):Obj{
  const entry=replicaEntry(v,policy,budget);require(entry.raw.length<=16384,'repair_invalid_index_control');
  const doc=objectFields(parseNewWire(entry.raw,policy,budget).value,['payload','proof']),p=objectFields(doc.payload,[...COMMON,...names.split(' ')]);
  require(p.schema_version===SCHEMA&&p.kind===kind);verifyBoundedControlSignature(p,doc.proof,key,budget);return {...entry,payload:p};
}
const authority=(root:unknown,item:Obj,policy:RepairPolicy,budget:RepairBudget)=>statusScope(root,'authority',{authority_kind:item.payload.kind,authority_sha256:item.ref.raw_sha256},policy,budget);
const assignment=(root:unknown,item:Obj,policy:RepairPolicy,budget:RepairBudget)=>statusScope(root,'assignment',{assignment_kind:'maintenance.assignment',assignment_sha256:item.ref.raw_sha256},policy,budget);
const duty=(signer:Obj,scope_kind:string,scope_id:string,revision:number,mask:number)=>({signer,scope_kind,scope_id,revision,mask});
const scopes=(values:Obj[])=>sorted([...new Map(values.map(v=>[v.scope_kind+':'+v.scope_id,{scope_kind:v.scope_kind,scope_id:v.scope_id}])).values()],v=>v.scope_kind+':'+v.scope_id);
/** Conflict, monotonically increasing floors, stale current views, and known
 * revocations are checked across every authentic observation. */
export function replicaFloors(previous:readonly Obj[],current:readonly Obj[],obligations:readonly Obj[]=[]):void{
  const required=new Map(obligations.map(v=>[[v.signer.key_id,v.scope_kind,v.scope_id].join(':'),v])),seen=new Map<string,string>(),values=new Map<string,number[][]>();
  for(const item of [...previous,...current]){const p=item.payload,issuer=p.scope_key.issuer_key_id,revision=p.revision,k=issuer+':'+revision;
    if(seen.has(k)&&seen.get(k)!==item.canonical_sha256)replicaFail('repair_status_conflict');seen.set(k,item.canonical_sha256);
    for(const row of p.entries){const key=[issuer,row.scope_kind,row.scope_id].join(':'),need=required.get(key);
      if(need&&row.status==='revoked'&&(row.operation_mask&need.mask))replicaFail('repair_authority_revoked');
      if(need&&row.minimum_document_revision>need.revision)replicaFail('repair_status_revision');
      const held=values.get(key)??[];held.push([revision,row.minimum_document_revision]);values.set(key,held);}}
  for(const held of values.values()){let minimum=0;for(const [,v] of held.sort((a,b)=>a[0]-b[0]||a[1]-b[1])){if(v<minimum)replicaFail('repair_status_rollback');minimum=v;}}
  for(const item of current)for(const row of item.payload.entries){const p=item.payload,k=[p.scope_key.issuer_key_id,row.scope_kind,row.scope_id].join(':');if(values.get(k)!.some(v=>v[0]>p.revision))replicaFail('repair_status_rollback');}
}
function observations(entries:unknown,parties:Obj,allowed:Map<string,Obj[]>,needs:Obj[],root:unknown,at:number,previous:Obj[],policy:RepairPolicy,budget:RepairBudget,onObserved?: (v:Obj)=>void):Obj[]{
  if(!Array.isArray(entries)||entries.length<1||entries.length>16)replicaFail('repair_status_missing');const checked:Obj[]=[],signers=new Map(Object.values(parties).map((v:Obj)=>[v.signing_key.key_id,v.signing_key]));let denial:unknown;
  // Persist each authentic status even when a later supplied document is bad.
  for(const entry of entries)try{const p=(parseNewWire((entry as Obj).raw,policy,budget).value as Obj).payload,key=p.signing_key.key_id;
    if(!signers.has(key))replicaFail('repair_status_disclosure');authenticateStatusOriginal(entry,{expectedRoot:root,expectedSigningKey:signers.get(key),at,allowedScopes:scopes(allowed.get(key)??[]),policy,budget},v=>{checked.push(v);onObserved?.(v);});
  }catch(error){denial??=error;}
  if(new Set(checked.map(v=>replicaRefKey(v.ref))).size!==checked.length)denial??=new RepairError('repair_duplicate_status');
  try{replicaFloors(previous,checked);}catch(error){denial??=error;}
  for(const need of needs){const rows=checked.filter(v=>replicaSame(v.payload.signing_key,need.signer)).flatMap(v=>v.payload.entries).filter(v=>v.scope_kind===need.scope_kind&&v.scope_id===need.scope_id);
    if(!rows.length)denial??=new RepairError('repair_status_missing');for(const row of rows){if(row.status==='revoked')denial??=new RepairError('repair_authority_revoked');else if(row.minimum_document_revision>need.revision)denial??=new RepairError('repair_status_revision');else if((row.operation_mask&need.mask)!==need.mask)denial??=new RepairError('repair_status_operation');}}
  if(denial)throw denial;return checked;
}
function inventory(source:Obj,reservations:Obj,policy:RepairPolicy,budget:RepairBudget):Obj[]{
  const rows=new Map<string,Obj>(),add=(role:string,item:Obj)=>{const p=(parseNewWire(item.raw,policy,budget).value as Obj).payload;rows.set(pair(role,item.ref),{role,original:item,issuer:p?.signing_key.key_id??''});};
  for(const tree of [source.manifest,...source.manifest.predecessors])for(const row of tree.roles)add(row.role,row.original);
  add('feed.custody',source.feed_custody);add('message.custody',source.custody);add('copy.reservation_consent',reservations.owner);add('copy.sender_reservation_consent',reservations.sender);
  return sorted([...rows.values()],v=>pair(v.role,v.original.ref));
}
function permissions(rows:Obj[],issuer:string,root:unknown,mode:'copy'|'return',policy:RepairPolicy,budget:RepairBudget):Obj{
  const selected=rows.filter(v=>v.issuer===issuer),allowed:Obj[]=[];
  for(const row of selected){const p=(parseNewWire(row.original.raw,policy,budget).value as Obj).payload,item={...row.original,payload:p};
    if(p.kind==='authority.status')allowed.push(...p.entries.map((v:Obj)=>({scope_kind:v.scope_kind,scope_id:v.scope_id})));
    if(['copy.reservation_consent','copy.sender_reservation_consent'].includes(row.role)||mode==='return'&&['mailbox.message_copy_disclosure','mailbox.feed_copy_disclosure'].includes(p.kind))allowed.push({scope_kind:'authority',scope_id:authority(root,item,policy,budget)});
    if(mode==='return'&&p.kind==='maintenance.assignment')allowed.push({scope_kind:'assignment',scope_id:assignment(root,item,policy,budget)});}
  return {originals:selected.map(v=>({role:v.role,ref:v.original.ref})),status_scopes:scopes(allowed)};
}
export interface MessageReplicaOptions {expectedSlot:unknown;expectedOwner:unknown;expectedSender:unknown;expectedSource:unknown;sourceStorageEpoch:string;expectedMaintainer:unknown;expectedTarget:unknown;targetStorageEpoch:string;expectedEnvelopeRef:unknown;limitPolicy:unknown;policy:RepairPolicy;budget:RepairBudget;}
export function verifyMailboxMessageReplica(manifestEntry:unknown,resolver:LocalRawResolver,custodyEntry:unknown,a:MessageReplicaOptions):Readonly<Obj>{
  const {policy,budget}=a;const e=buildNewWire({slot:a.expectedSlot,owner:a.expectedOwner,sender:a.expectedSender,source:a.expectedSource,maintainer:a.expectedMaintainer,target:a.expectedTarget},policy,budget).value as Obj;
  const envelope=rawRef(a.expectedEnvelopeRef);require(envelope.namespace==='object'&&envelope.size>0&&envelope.size<=6291456);
  const custody=signed(custodyEntry,e.target.signing_key,'replica.custody',CUSTODY,policy,budget),p=custody.payload;resource(p.resource);
  const at=u53(p.stored_at);require(at<u53(p.read_until)&&p.read_until<=u53(p.retain_until)&&u53(p.reservation_generation,1)===1&&p.resource.node_key_id===e.target.signing_key.key_id&&p.resource.storage_epoch===a.targetStorageEpoch,'repair_copy_commit_mismatch');
  const manifest=replicaEntry(manifestEntry,policy,budget),v=objectFields(parseNewWire(manifest.raw,policy,budget).value,['schema_version','kind','root_key','scope','original_roles','physical_objects','edges']);
  require(v.schema_version===SCHEMA&&v.kind==='replica.manifest'&&replicaSame(p.replica_manifest_ref,manifest.ref)&&replicaSame(p.root_key,v.root_key)&&replicaSame(p.scope,v.scope)&&replicaSame(v.physical_objects,v.original_roles)&&Array.isArray(v.original_roles)&&v.original_roles.length>0&&v.original_roles.length<=128,'repair_copy_commit_mismatch');
  const entries=new Map<string,RawOriginal[]>();let last='';
  for(const row of v.original_roles){objectFields(row,['role','ref']);require(typeof row.role==='string');const ref=rawRef(row.ref),k=pair(row.role,ref);require(!last||k>last,'repair_copy_commit_mismatch');last=k;
    if(row.role==='message.envelope'){require(replicaSame(ref,envelope),'repair_copy_commit_mismatch');continue;}
    const item=resolver.resolve(ref);entries.set(row.role,[...(entries.get(row.role)??[]),{raw:item.raw,ref:item.ref}]);}
  const one=(role:string):RawOriginal=>{const values=entries.get(role);if(values?.length!==1)replicaFail('repair_copy_commit_mismatch');return values[0];};
  const feed=verifyMailboxFeedSourceEvent(one('history.mailbox_feed'),resolver,one('feed.custody'),{expectedSlot:e.slot,expectedOwner:e.owner,expectedSender:e.sender,expectedTarget:e.source,limitPolicy:a.limitPolicy,policy,budget});
  const selected=(feed.manifest.manifest.value as Obj).members.filter((v:Obj)=>replicaSame(v.envelope_ref,envelope));require(selected.length===1);const member=selected[0];
  const role=(name:string,ref:unknown):RawOriginal=>{const rows=feed.manifest.roles.filter((v:Obj)=>v.role===name&&replicaSame(v.original.ref,ref));require(rows.length===1);return rows[0].original;};
  const messageCustody=role('member.custody',member.source_custody_ref),mc=(parseNewWire(messageCustody.raw,policy,budget).value as Obj).payload,core=(parseNewWire(role('member.core',member.admission_core_ref).raw,policy,budget).value as Obj).payload;
  const setup=feed.graph.members[member.sequence];require(setup.attempt.message_id===member.message_id&&replicaSame(mc.envelope_ref,envelope));
  const active=setup.resources.data.active.payload,readUntil=Math.min(feed.read_until,core.object_until,active.windows.read_until),retainUntil=Math.min(feed.retain_until,core.object_until,active.windows.retain_until);
  const data=setup.obligations.find((v:Obj)=>v.role==='data_resource');require(data);
  const scope={kind:'mailbox_member',slot_key:e.slot,attempt_ref:core.attempt_ref,envelope_ref:envelope,admission_link_ref:member.admission_link_ref,source_custody_ref:member.source_custody_ref};
  const source={...feed,feed_custody:feed.custody,custody:{...messageCustody,payload:mc},message_scope:scope,message_history_ref:member.historical_manifest_ref,message_core_ref:member.admission_core_ref,
    message_member:{sequence:member.sequence,admission_link_ref:member.admission_link_ref,sealed_core_ref:(parseNewWire(role('member.link',member.admission_link_ref).raw,policy,budget).value as Obj).payload.sealed_core_ref},graph:{...feed.graph,obligations:[...feed.graph.obligations,{...data,operation_mask:70}]},read_until:Math.min(readUntil,retainUntil),retain_until:retainUntil};
  const originals=feed.graph.members[0].originals,parent=originals.maintenance,read=originals.read,bootstrap=originals.bootstrap,slot=originals.slot,root=e.slot.root_key,pr=parent.payload;
  require(e.slot.writer_storage_epoch===a.sourceStorageEpoch&&pr.maintainers.some((v:Obj)=>replicaSame(v,ids(e.maintainer)))&&(pr.operation_mask&78)===78&&pr.max_delegate_depth>=2&&pr.max_destinations_per_job>0&&pr.max_concurrent_jobs>0&&!replicaSame(ids(e.target),ids(e.source))&&!replicaSame(ids(e.target),ids(e.maintainer)));
  const allocation=signed(one('copy.allocation'),e.maintainer.signing_key,'resource.allocate',ALLOCATE,policy,budget),offer=signed(one('copy.offer'),e.target.signing_key,'resource.offer',OFFER,policy,budget),assign=signed(one('copy.assignment'),e.maintainer.signing_key,'maintenance.assignment',ASSIGNMENT,policy,budget),ap=allocation.payload,op=offer.payload,mp=assign.payload;
  lifetime(ap,at);lifetime(mp,at);for(const [n,v] of [['request_id',ap],['offer_id',op],['assignment_id',mp]] as const)opaque(v[n]);
  const intent=objectFields(ap.intent,'kind allocation_id job_id root_key caller target target_storage_epoch purpose scope historical_manifest_ref budget windows'.split(' '));capacity(intent.budget);windows(intent.windows,at);resource(op.resource);
  for(const n of ['allocation_id','job_id','target_storage_epoch'])opaque(intent[n]);const digest=budget.hash(buildNewWire(intent,policy,budget).raw);
  require(intent.kind==='resource.copy_intent'&&intent.purpose==='message_replica'&&intent.budget.max_live_bytes>=envelope.size&&replicaSame(intent.caller,e.maintainer)&&replicaSame(intent.target,e.target)&&intent.target_storage_epoch===a.targetStorageEpoch&&replicaSame(intent.root_key,root)&&replicaSame(intent.scope,scope)&&replicaSame(intent.historical_manifest_ref,member.historical_manifest_ref)&&replicaSame(op.intent,intent)&&ap.intent_sha256===digest&&op.intent_sha256===digest&&replicaSame(op.allocation_request_ref,allocation.ref)&&replicaSame(op.target_encryption_key,e.target.encryption_key)&&op.resource.node_key_id===e.target.signing_key.key_id&&op.resource.storage_epoch===a.targetStorageEpoch&&u53(op.reservation_generation,1)===1&&replicaSame(op.budget,intent.budget)&&replicaSame(op.windows,intent.windows)&&ap.issued_at<=u53(op.issued_at)&&op.issued_at<=mp.issued_at&&at<u53(op.reservation_until)&&op.reservation_until<=ap.expires_at);
  for(const control of [slot,parent,read])require(BUDGET.every(n=>intent.budget[n]<=control.payload.budget[n])&&WINDOWS.every(n=>intent.windows[n]<=control.payload.windows[n]));
  const parentUntil=Math.min(...[slot,parent,read,bootstrap].map(v=>v.payload.expires_at),read.payload.windows.read_until,bootstrap.payload.probe_until,bootstrap.payload.proof_until,bootstrap.payload.upload_until);
  require(mp.job_id===intent.job_id&&replicaSame(mp.root_key,root)&&replicaSame(mp.parent_root_ref,parent.ref)&&mp.parent_assignment_ref===null&&u53(mp.depth)===2&&replicaSame(mp.subject,ids(e.target))&&u53(mp.operation_mask)===70&&replicaSame(mp.scope,scope)&&mp.resource_intent_sha256===digest&&replicaSame(mp.resource_offer_ref,offer.ref)&&replicaSame(mp.resource,op.resource)&&replicaSame(mp.bootstrap_grant_refs,[bootstrap.ref])&&replicaSame(mp.budget,op.budget)&&replicaSame(mp.windows,op.windows)&&Object.values(mp.windows).every(v=>u53(v)<=mp.expires_at)&&mp.expires_at<=parentUntil);
  for(const v of [ap,mp])require(v.target_node_key_id===e.target.signing_key.key_id&&v.target_storage_epoch===a.targetStorageEpoch);
  let maximum=Math.min(source.read_until,source.retain_until,parentUntil,active.windows.copy_until,slot.payload.windows.copy_until,pr.windows.copy_until,intent.windows.copy_until);
  for(const item of feed.graph.members){const d=item.disclosure;require((d.operation_mask&70)===70&&['maintenance','slot','read','bootstrap'].every(n=>replicaSame(item.originals[n].ref,originals[n].ref)));maximum=Math.min(maximum,d.consent_until,d.expires_at);}
  const reservations:Obj={};for(const variant of ['owner','sender']){const item=signed(one(variant==='owner'?'copy.reservation_consent':'copy.sender_reservation_consent'),e[variant].signing_key,'mailbox.message_copy_reservation_consent',RESERVATION,policy,budget),c=item.payload;lifetime(c,at);opaque(c.consent_id);u53(c.revision,1);const d=objectFields(c.reservation_disclosure,['intent_sha256','until']);
    require(c.variant===variant&&replicaSame(c.root_authority_ref,parent.ref)&&replicaSame(c.source_custody_ref,source.custody.ref)&&replicaSame(c.historical_manifest_ref,intent.historical_manifest_ref)&&replicaSame(c.maintainer,ids(e.maintainer))&&replicaSame(c.target,e.target)&&c.target_storage_epoch===a.targetStorageEpoch&&Math.max(mc.stored_at,feed.custody.payload.stored_at)<=c.issued_at&&c.issued_at<=ap.issued_at&&d.intent_sha256===digest&&at<u53(d.until)&&d.until<=Math.min(maximum,c.expires_at));reservations[variant]=item;maximum=Math.min(maximum,d.until);}
  const rows=inventory(source,reservations,policy,budget),allowed=new Map<string,Obj[]>(),consents:Obj[]=[];for(const name of ['owner','sender','source','maintainer'])allowed.set(e[name].signing_key.key_id,[]);let until=Math.min(maximum,mp.expires_at);
  for(const variant of ['owner','source','sender']){const item=signed(one('copy.'+variant+'_disclosure'),e[variant].signing_key,'mailbox.message_copy_disclosure',DISCLOSURE,policy,budget),c=item.payload;lifetime(c,at);opaque(c.consent_id);u53(c.revision,1);
    require(c.variant===variant&&replicaSame(c.root_key,root)&&replicaSame(c.assignment_ref,assign.ref)&&replicaSame(c.source_custody_ref,source.custody.ref)&&replicaSame(c.historical_manifest_ref,intent.historical_manifest_ref)&&replicaSame(c.target,e.target)&&c.target_storage_epoch===a.targetStorageEpoch&&mp.issued_at<=c.issued_at);
    const d=objectFields(c.disclosure,['originals','status_scopes','until']),expected=permissions(rows,e[variant].signing_key.key_id,root,'copy',policy,budget);require(replicaSame(d.originals,expected.originals)&&replicaSame(d.status_scopes,expected.status_scopes)&&at<u53(d.until)&&d.until<=Math.min(maximum,c.expires_at));allowed.get(e[variant].signing_key.key_id)!.push(...expected.status_scopes,{scope_kind:'authority',scope_id:authority(root,item,policy,budget)});until=Math.min(until,d.until,c.expires_at);consents.push(item);}
  const needs=source.graph.obligations.map((v:Obj)=>duty(v.signer,v.scope_kind,v.scope_id,v.document_revision,v.operation_mask|(['slot','maintenance','disclosure','metadata_resource','data_resource'].includes(v.role)?4:0)));
  for(const variant of ['owner','sender']){const item=reservations[variant],id=authority(root,item,policy,budget);allowed.get(e[variant].signing_key.key_id)!.push({scope_kind:'authority',scope_id:id});needs.push(duty(e[variant].signing_key,'authority',id,item.payload.revision,4));}
  needs.push(duty(e.owner.signing_key,'authority',authority(root,parent,policy,budget),pr.revision,78));const as=assignment(root,assign,policy,budget);allowed.get(e.maintainer.signing_key.key_id)!.push({scope_kind:'assignment',scope_id:as});needs.push(duty(e.maintainer.signing_key,'assignment',as,0,70));
  for(const [i,variant] of ['owner','source','sender'].entries())needs.push(duty(e[variant].signing_key,'authority',authority(root,consents[i],policy,budget),consents[i].payload.revision,4));
  const previous=[...feed.graph.statuses,...feed.graph.members.flatMap((v:Obj)=>v.statuses)],statuses=observations(entries.get('copy.current_status'),{owner:e.owner,sender:e.sender,source:e.source,maintainer:e.maintainer},allowed,needs,root,at,previous,policy,budget);
  const read_until=Math.min(until,intent.windows.read_until,...statuses.map(v=>v.payload.valid_until)),retain_until=Math.min(until,intent.windows.retain_until);require(at<Math.min(read_until,retain_until),'repair_resource_expired');
  const plan={source,allocation,offer,assignment:assign,reservations,disclosures:consents,originals:rows,statuses,obligations:needs,read_until,retain_until};
  require(replicaSame(p.assignment_ref,assign.ref)&&replicaSame(p.original_custody_ref,source.custody.ref)&&replicaSame(p.resource_offer_ref,offer.ref)&&replicaSame(p.resource,op.resource)&&replicaSame(p.root_key,root)&&replicaSame(p.scope,scope)&&p.read_until===read_until&&p.retain_until===retain_until,'repair_copy_commit_mismatch');
  const closure=new Map<string,Obj>(),edges=new Map<string,Obj>(),add=(role:string,ref:unknown)=>{const r=rawRef(ref);closure.set(pair(role,r),{role,ref:r});},edge=(parent:unknown,relation:string,child:unknown)=>{const v={parent_ref:rawRef(parent),relation,child_ref:rawRef(child)};edges.set(replicaRefKey(parent)+'|'+relation+'|'+replicaRefKey(child),v);};
  for(const row of rows)add(row.role,row.original.ref);for(const [role,item] of [['copy.allocation',allocation],['copy.offer',offer],['copy.assignment',assign],...consents.map((item,i)=>['copy.'+['owner','source','sender'][i]+'_disclosure',item])] as [string,Obj][])add(role,item.ref);
  add('message.envelope',envelope);for(const item of statuses)add('copy.current_status',item.ref);
  for(const tree of [feed.manifest,...feed.manifest.predecessors]){
    let ref=one('history.mailbox_feed').ref;
    if(tree!==feed.manifest){const rows=feed.manifest.roles.filter((v:Obj)=>v.role==='history.member'&&Buffer.from(v.original.raw).equals(Buffer.from(tree.manifest.raw)));require(rows.length===1,'repair_copy_commit_mismatch');ref=rows[0].original.ref;}
    add(tree===feed.manifest?'history.mailbox_feed':'history.member',ref);
    for(const row of tree.manifest.value.roles){add('history.raw_pack',row.pack_ref);edge(ref,'manifest-member',row.document_ref);edge(ref,'manifest-member',row.pack_ref);}
  }
  const fm=feed.manifest.manifest.value;edge(fm.slot_ref,'slot-feed',fm.feed_head_ref);edge(fm.feed_head_ref,'head-checkpoint',feed.graph.head.checkpoint_ref);edge(fm.feed_head_ref,'head-range',feed.graph.head.range_root_ref);
  for(const item of fm.members){edge(item.admission_link_ref,'link-core',item.admission_core_ref);edge(item.admission_link_ref,'link-history',item.historical_manifest_ref);edge(item.source_custody_ref,'custody-link',item.admission_link_ref);}
  for(const row of feed.manifest.roles)if(['range.index','range.repair_page'].includes(row.role)){const p=(parseNewWire(row.original.raw,policy,budget).value as Obj);if(row.role==='range.index')for(const child of p.children)edge(row.original.ref,'range-child',child.ref);else{edge(row.original.ref,'page-sealed',p.sealed_page_ref);for(const child of p.entries)edge(row.original.ref,'page-link',child.admission_link_ref);}}
  edge(member.admission_core_ref,'core-envelope',envelope);
  const expected={schema_version:SCHEMA,kind:'replica.manifest',root_key:root,scope,original_roles:sorted([...closure.values()],v=>pair(v.role,v.ref)),physical_objects:sorted([...closure.values()],v=>pair(v.role,v.ref)),edges:sorted([...edges.values()],v=>replicaRefKey(v.parent_ref)+'|'+v.relation+'|'+replicaRefKey(v.child_ref))};
  require(replicaSame(v,expected)&&new Set(v.original_roles.map((v:Obj)=>replicaRefKey(v.ref))).size<=op.budget.max_items,'repair_copy_commit_mismatch');
  return Object.freeze({state:'historical_replica',custody,source,authority:plan,entries});
}
export function checkMailboxMessageReturn(replica:Obj,consentEntries:Obj,a:Obj):Readonly<Obj>{
  const {policy,budget}=a,source=replica.source,plan=replica.authority,custody=replica.custody,root=plan.assignment.payload.root_key,setup=source.graph.members[0].originals,bootstrap=setup.bootstrap;
  require(['challenge','proof','child'].includes(a.action),'repair_access_action');u53(a.at);
  const e=buildNewWire({owner:a.expectedOwner,sender:a.expectedSender,source:a.expectedSource,maintainer:a.expectedMaintainer,target:a.expectedTarget},policy,budget).value as Obj,variants=['owner','source','maintainer','sender'];objectFields(consentEntries,variants);
  const allowed=new Map<string,Obj[]>();for(const p of Object.values(e) as Obj[])allowed.set(p.signing_key.key_id,[]);const needs:Obj[]=[],consents:Obj[]=[];
  let expires=Math.min(custody.payload.read_until,custody.payload.retain_until,source.read_until,bootstrap.payload.expires_at,bootstrap.payload[a.action==='challenge'?'probe_until':'proof_until']);
  for(const item of source.graph.members){for(const n of ['slot','read','maintenance']){const p=item.originals[n].payload;expires=Math.min(expires,p.expires_at,p.windows.read_until,p.windows.retain_until);}const d=item.disclosure;expires=Math.min(expires,d.expires_at,d.consent_until,d.bootstrap_return.until);}
  const rows=new Map(plan.originals.map((v:Obj)=>[pair(v.role,v.original.ref),v]));for(const [role,item] of [['copy.allocation',plan.allocation],['copy.offer',plan.offer],['copy.assignment',plan.assignment],...plan.disclosures.map((v:Obj,i:number)=>['copy.'+['owner','source','sender'][i]+'_disclosure',v])] as [string,Obj][])rows.set(pair(role,item.ref),{role,original:item,issuer:item.payload.signing_key.key_id});
  for(const variant of variants){const item=signed(consentEntries[variant],e[variant].signing_key,'mailbox.message_replica_return_consent',RETURN,policy,budget),p=item.payload;lifetime(p,a.at);opaque(p.consent_id);u53(p.revision,1);
    require(p.variant===variant&&replicaSame(p.root_key,root)&&replicaSame(p.source_custody_ref,source.custody.ref)&&replicaSame(p.historical_manifest_ref,plan.allocation.payload.intent.historical_manifest_ref)&&replicaSame(p.assignment_ref,plan.assignment.ref)&&replicaSame(p.subject,ids(e.owner))&&replicaSame(p.target,e.target)&&p.target_storage_epoch===a.targetStorageEpoch&&replicaSame(p.bootstrap_grant_ref,bootstrap.ref)&&p.issued_at>=plan.assignment.payload.issued_at);
    const d=objectFields(p.return_permission,['originals','status_scopes','until']),expected=permissions(sorted([...rows.values()],v=>pair(v.role,v.original.ref)),e[variant].signing_key.key_id,root,'return',policy,budget);
    require(replicaSame(d.originals,expected.originals)&&replicaSame(d.status_scopes,expected.status_scopes)&&p.issued_at<u53(d.until)&&d.until<=Math.min(p.expires_at,plan.assignment.payload.windows.read_until,source.read_until,bootstrap.payload.proof_until));
    expires=Math.min(expires,d.until,p.expires_at);const id=authority(root,item,policy,budget);allowed.get(e[variant].signing_key.key_id)!.push(...expected.status_scopes,{scope_kind:'authority',scope_id:id});needs.push(duty(e[variant].signing_key,'authority',id,p.revision,2));consents.push(item);}
  for(const v of source.graph.obligations)if(!['metadata_resource','data_resource'].includes(v.role))needs.push(duty(v.signer,v.scope_kind,v.scope_id,v.document_revision,['slot','maintenance','bootstrap'].includes(v.role)?10:2));
  needs.push(duty(e.maintainer.signing_key,'assignment',assignment(root,plan.assignment,policy,budget),0,2));const targetScope=statusScope(root,'resource',custody.payload.resource,policy,budget);allowed.get(e.target.signing_key.key_id)!.push({scope_kind:'resource',scope_id:targetScope});needs.push(duty(e.target.signing_key,'resource',targetScope,custody.payload.reservation_generation,2));
  for(const item of plan.statuses){const permitted=new Set(scopes(allowed.get(item.payload.signing_key.key_id)??[]).map(v=>v.scope_kind+':'+v.scope_id));if(item.payload.entries.some((v:Obj)=>!permitted.has(v.scope_kind+':'+v.scope_id)))replicaFail('repair_status_disclosure');}
  const previous=[...source.graph.statuses,...plan.statuses,...source.graph.members.flatMap((v:Obj)=>v.statuses)],statuses=observations(a.currentStatuses,e,allowed,needs,root,a.at,previous,policy,budget,a.onObserved);expires=Math.min(expires,...statuses.map(v=>v.payload.valid_until));require(a.at<expires,'repair_access_expired');
  return Object.freeze({expires_at:expires,consents,statuses,obligations:needs,subject:ids(e.owner),bootstrap});
}
