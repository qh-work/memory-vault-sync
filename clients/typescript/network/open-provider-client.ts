/** Routed provider observations and owner-authorized directory publication.
 * Native crypto, routing and protected transport state only. An index lease
 * never authorizes object reads, ciphertext custody or access to a Vault. */
import {
  canonicalBytes,document,documentSha256,opaqueId,safeInteger,NetworkCryptoError,
  validateSigningIdentity,validateEncryptionIdentity,
} from './crypto.ts';
import type {DocumentInput,EncryptionIdentityDocument,SigningIdentityDocument} from './crypto.ts';
import {transaction} from './io.ts';
import {coordinate,verifyNode} from './open-control.ts';
import type {SignedNode} from './open-control.ts';
import {LookupBudget} from './open-routing.ts';
import type {OpenParticipant} from './open-participant.ts';
import {
  MAX_CONTROL_BYTES,PUBLISH,ProviderError,asDual,authorityScope,bounded,dualId,fields,
  issueStatus,makeTargetChallenge,opaqueRef,rootKey,routeTarget,signDocument,signRpc,
  verifyDocument,verifyIndexLease,verifyResourceLease,verifyResponse,verifyRpc,
  verifyStatus,verifyTargetAnswer,
} from './open-provider.ts';

export const LOCAL_MAX_RECORDS=128,LOCAL_MAX_BYTES=131072;
export const DEFAULT_RESOURCE_BUDGET={max_live_bytes:0,max_meta_bytes:98304,max_items:1,
  max_requests:8,max_pending:1,max_replay_records:8,max_jobs:0,max_job_bytes:0} as const;
type Obj=Record<string,any>;
type ProviderBudget=LookupBudget&{provider_unmeasured_failures?:number};
export interface PublicationOptions{budget?:LookupBudget;lease_seconds?:number;resource_seconds?:number;directory_count?:number;}
export interface PublishOptions extends PublicationOptions{authorizations?:unknown[];}
export interface FindOptions{budget?:LookupBudget;maximum_candidates?:number;maximum_directories?:number;}
const now=()=>Math.floor(Date.now()/1000);
const same=(a:unknown,b:unknown)=>Buffer.from(canonicalBytes(a)).equals(Buffer.from(canonicalBytes(b)));
const digest=(value:unknown)=>documentSha256(value as DocumentInput);
const doc=(value:unknown,maximum=LOCAL_MAX_BYTES):Obj=>document(value as DocumentInput,maximum);
const binding=(node:SignedNode)=>node.payload.signing_key.key_id+':'+node.payload.storage_epoch;
const expectedError=(error:unknown)=>error instanceof NetworkCryptoError||
  (error instanceof Error&&(/^E[A-Z]+$/.test(String((error as any).code))||error.name==='TimeoutError'));

export class OpenProviderClient{
  readonly participant:OpenParticipant;readonly encryption:EncryptionIdentityDocument;
  readonly identity:SigningIdentityDocument;readonly subject:Obj;
  private provenTargets=new Map<string,{target:Obj;expires_at:number}>();
  constructor(participant:OpenParticipant,encryption:EncryptionIdentityDocument){
    this.participant=participant;this.encryption=doc(encryption,4096) as EncryptionIdentityDocument;this.identity=participant.identity;
    this.subject={signing_key:validateSigningIdentity(this.identity),encryption_key:validateEncryptionIdentity(this.encryption)};
    asDual(this.subject);
    participant.providerStorage(db=>transaction(db,()=>{
      db.exec(`CREATE TABLE IF NOT EXISTS open_provider_client_meta(name TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS open_provider_local(category TEXT NOT NULL,reference TEXT NOT NULL,
          body BLOB NOT NULL,retain_until INTEGER NOT NULL,PRIMARY KEY(category,reference));
        CREATE INDEX IF NOT EXISTS open_provider_local_expiry ON open_provider_local(retain_until);
        CREATE TABLE IF NOT EXISTS open_provider_local_floors(fact_key TEXT PRIMARY KEY,revision INTEGER NOT NULL,
          digest TEXT NOT NULL,record BLOB NOT NULL,second_record BLOB,status TEXT NOT NULL,retain_until INTEGER NOT NULL);
        CREATE INDEX IF NOT EXISTS open_provider_local_floor_expiry ON open_provider_local_floors(retain_until);`);
      const key=this.subject.signing_key.key_id+':'+this.subject.encryption_key.key_id;
      const old=db.prepare("SELECT value FROM open_provider_client_meta WHERE name='binding'").get() as Obj|undefined;
      if(old&&old.value!==key)throw new ProviderError('provider_client_identity_mismatch');
      if(!old){
        if(db.prepare('SELECT 1 FROM open_provider_local LIMIT 1').get()||db.prepare('SELECT 1 FROM open_provider_local_floors LIMIT 1').get())
          throw new ProviderError('provider_client_binding_missing');
        db.prepare("INSERT INTO open_provider_client_meta VALUES('binding',?)").run(key);
      }
    }));
  }
  private budget(value?:LookupBudget):ProviderBudget{
    const result=value===undefined?new LookupBudget():value;
    if(!(result instanceof LookupBudget))throw new ProviderError('provider_invalid_budget');
    result.check();return result;
  }
  private metrics(budget:ProviderBudget):Obj{return {requests:budget.requests,request_bytes:budget.request_bytes,
    response_bytes:budget.response_bytes,response_bytes_are_upper_bound:!!budget.provider_unmeasured_failures};}
  private error(node:SignedNode,error:any):Obj{return {node_key_id:node.payload.signing_key.key_id,code:error.code??'provider_unreachable'};}
  private factKey(raw:Obj):string{return digest({ref:raw.ref,provider_key_id:raw.signing_key.key_id,
    storage_epoch:raw.storage_epoch,custody_id:raw.custody_id});}
  private session(category:string,reference:string,semantic:Obj,initial?:Obj,retainUntil?:number):Obj{
    return this.participant.providerStorage(db=>transaction(db,()=>{
      db.prepare('DELETE FROM open_provider_local WHERE rowid IN (SELECT rowid FROM open_provider_local WHERE retain_until<=? ORDER BY retain_until LIMIT 32)').run(now());
      const old=db.prepare('SELECT body FROM open_provider_local WHERE category=? AND reference=?').get(category,reference) as Obj|undefined;
      if(old){const result=doc(old.body);if(!same(result.semantic,semantic))throw new ProviderError('provider_local_conflict');return result;}
      if(initial===undefined||retainUntil===undefined)throw new ProviderError('provider_local_missing');
      if((db.prepare('SELECT count(*) AS n FROM open_provider_local').get() as Obj).n>=LOCAL_MAX_RECORDS)
        throw new ProviderError('provider_local_capacity',true);
      const result=doc({semantic,...initial});
      db.prepare('INSERT INTO open_provider_local VALUES(?,?,?,?)').run(category,reference,canonicalBytes(result),safeInteger(retainUntil));
      return result;
    }));
  }
  private append(category:string,reference:string,additions:Obj):Obj{
    return this.participant.providerStorage(db=>transaction(db,()=>{
      const row=db.prepare('SELECT body FROM open_provider_local WHERE category=? AND reference=?').get(category,reference) as Obj|undefined;
      if(!row)throw new ProviderError('provider_local_missing');
      const result=doc(row.body);
      for(const [key,value] of Object.entries(additions)){
        if(Object.hasOwn(result,key)&&!same(result[key],value))throw new ProviderError('provider_local_conflict');result[key]=value;
      }
      const checked=doc(result);
      db.prepare('UPDATE open_provider_local SET body=? WHERE category=? AND reference=?').run(canonicalBytes(checked),category,reference);
      return checked;
    }));
  }
  private observeFact(fact:unknown):void{
    const raw=verifyDocument(fact,'provider.fact'),key=this.factKey(raw),hash=digest(fact);let refusal:ProviderError|undefined;
    this.participant.providerStorage(db=>transaction(db,()=>{
      db.prepare('DELETE FROM open_provider_local_floors WHERE rowid IN (SELECT rowid FROM open_provider_local_floors WHERE retain_until<=? ORDER BY retain_until LIMIT 32)').run(now());
      const old=db.prepare('SELECT revision,digest,status,retain_until FROM open_provider_local_floors WHERE fact_key=?').get(key) as Obj|undefined;
      if(old&&['conflict','withdrawn'].includes(old.status))throw new ProviderError('provider_fact_inactive');
      if(old&&raw.revision<old.revision)throw new ProviderError('provider_fact_rollback');
      if(old&&raw.revision===old.revision&&hash!==old.digest){
        db.prepare("UPDATE open_provider_local_floors SET second_record=?,status='conflict',retain_until=max(retain_until,?) WHERE fact_key=?")
          .run(canonicalBytes(fact),raw.expires_at+60,key);
        refusal=new ProviderError('provider_fact_conflict');
      }else{
        if(!old&&(db.prepare('SELECT count(*) AS n FROM open_provider_local_floors').get() as Obj).n>=LOCAL_MAX_RECORDS)
          throw new ProviderError('provider_local_capacity',true);
        db.prepare(`INSERT INTO open_provider_local_floors VALUES(?,?,?,?,NULL,?,?) ON CONFLICT(fact_key) DO UPDATE SET
          revision=excluded.revision,digest=excluded.digest,record=excluded.record,status=excluded.status,
          retain_until=max(retain_until,excluded.retain_until)`).run(key,raw.revision,hash,canonicalBytes(fact),raw.status,raw.expires_at+60);
      }
    }));
    // Persist equivocation before reporting refusal; rollback must not erase it.
    if(refusal)throw refusal;
  }
  private factCurrent(fact:unknown):boolean{
    const raw=verifyDocument(fact,'provider.fact');
    const row=this.participant.providerStorage(db=>db.prepare('SELECT digest,status FROM open_provider_local_floors WHERE fact_key=?').get(this.factKey(raw))) as Obj|undefined;
    return !!row&&row.digest===digest(fact)&&row.status==='active';
  }
  async call(node:SignedNode,action:string,body:Obj,value?:LookupBudget):Promise<Obj>{
    node=doc(node,4096) as SignedNode;body=doc(body,MAX_CONTROL_BYTES);
    const budget=this.budget(value);this.participant.acceptProviderControl(node);
    if(['resource.allocate','resource.revoke','provider.put','provider.status','provider.result'].includes(action)){
      const proof=this.provenTargets.get(binding(node));
      if(!proof||proof.expires_at<=now())throw new ProviderError('provider_target_proof_required');
      verifyDocument(proof.target,'provider.target');
      if(action==='provider.put')verifyResourceLease(body.resource_lease,{node,target:proof.target});
    }
    const request=signRpc(this.identity,{node,action,body});verifyRpc(request,{node});
    if(budget.remaining_bytes<MAX_CONTROL_BYTES)throw new ProviderError('provider_budget_exhausted',true);
    budget.chargeRequest();budget.chargeRequestBytes(canonicalBytes(request).length);budget.chargeBytes(MAX_CONTROL_BYTES);
    let reply;
    try{reply=await this.participant.transport.request(node.payload.base_url,request as unknown as DocumentInput,budget.deadline);}
    catch(error){budget.provider_unmeasured_failures=(budget.provider_unmeasured_failures??0)+1;throw error;}
    budget.bytes-=MAX_CONTROL_BYTES;budget.chargeBytes(reply.wire_bytes);
    if(reply.wire_bytes>MAX_CONTROL_BYTES||reply.wire_bytes<canonicalBytes(reply.response).length)throw new ProviderError('provider_response_size');
    const checked=verifyResponse(reply.response,{request,node});this.participant.acceptProviderControl(node);
    this.participant.table.learnVerified(node,reply.observed_address);this.participant.cacheVerifiedProviderNode(node);
    if(checked.body.error)throw new ProviderError(checked.body.error.code,checked.body.error.retryable);
    return checked.body;
  }
  async proveTarget(node:SignedNode,value?:LookupBudget):Promise<Obj>{
    node=doc(node,4096) as SignedNode;
    const budget=this.budget(value),target=(await this.call(node,'target.get',{},budget)).target;
    const [challenge,nonce]=await makeTargetChallenge(this.identity,{target,node});
    const answer=(await this.call(node,'target.answer',{target,challenge},budget)).answer;
    verifyTargetAnswer(answer,{target,challenge,nonce,node});budget.check();this.participant.acceptProviderControl(node);
    for(const [key,proof] of this.provenTargets)if(proof.expires_at<=now())this.provenTargets.delete(key);
    if(this.provenTargets.size>=32)this.provenTargets.delete(this.provenTargets.keys().next().value!);
    this.provenTargets.set(binding(node),{target:doc(target,4096),expires_at:Math.min(answer.payload.expires_at,target.payload.expires_at)});
    return target;
  }
  private async directories(ref:Obj,budget:LookupBudget,maximum:number):Promise<{nodes:SignedNode[];partial:boolean}>{
    const target=routeTarget(ref),route=await this.participant.lookupProviderDirectory(target,budget),nodes=[...route.candidates];
    if(this.participant.descriptor&&verifyNode(this.participant.descriptor).roles.includes('directory'))nodes.push(this.participant.descriptor);
    const unique=new Map<string,SignedNode>();
    for(const node of nodes){try{
      const raw=verifyNode(node);this.participant.acceptProviderControl(node);
      if(raw.status==='active'&&raw.roles.includes('directory'))unique.set(binding(node),node);
    }catch(error){if(!expectedError(error))throw error;}}
    const ordered=[...unique.values()].sort((a,b)=>{
      const left=BigInt('0x'+a.payload.coordinate)^BigInt('0x'+target),right=BigInt('0x'+b.payload.coordinate)^BigInt('0x'+target);
      return left<right?-1:left>right?1:a.payload.signing_key.key_id.localeCompare(b.payload.signing_key.key_id);
    });
    return {nodes:ordered.slice(0,maximum),partial:route.partial||route.state==='budget_exhausted'};
  }
  private async resolveDirectory(old:SignedNode,budget:LookupBudget):Promise<SignedNode>{
    try{const raw=verifyNode(old);this.participant.acceptProviderControl(old);
      if(raw.status==='active'&&raw.roles.includes('directory'))return old;
    }catch(error){if(!expectedError(error))throw error;}
    const wanted=verifyNode(old,{now:old.payload.issued_at,allow_expired:true});
    const route=await this.participant.lookupProviderDirectory(coordinate(wanted.signing_key.key_id),budget),nodes=[...route.candidates];
    if(this.participant.descriptor)nodes.push(this.participant.descriptor);
    for(const node of nodes){const raw=verifyNode(node);
      if(same(raw.signing_key,wanted.signing_key)&&raw.storage_epoch===wanted.storage_epoch&&raw.roles.includes('directory')&&raw.status==='active'){
        this.participant.acceptProviderControl(node);return node;
      }
    }
    throw new ProviderError('provider_directory_unresolved',true);
  }
  async find(reference:unknown,options:FindOptions={}):Promise<Obj>{
    const ref=opaqueRef(doc(reference)),budget=this.budget(options.budget),maximum=options.maximum_candidates??8,directoryCount=options.maximum_directories??3;
    bounded(maximum,16);bounded(directoryCount,3);
    const candidates=new Map<string,Obj>(),errors:Obj[]=[];let partial=false,directories:SignedNode[];
    try{const route=await this.directories(ref,budget,directoryCount);directories=route.nodes;partial=route.partial;}
    catch(error){if(!expectedError(error))throw error;return {state:'not_observed',candidates:[],errors:[{code:(error as any).code??'provider_unreachable'}],partial:true,...this.metrics(budget)};}
    for(const directory of directories){
      let cursor:string|null=null,stopped=false;
      for(let count=0;count<8;count++){
        try{
          const page=await this.call(directory,'provider.get',{ref,after:cursor,limit:4,maximum_bytes:49152},budget);
          const nodes=new Map<string,SignedNode>((page.nodes as SignedNode[]).map(node=>[binding(node),node]));
          for(const entry of page.entries){
            const fact=entry.fact,raw=verifyDocument(fact,'provider.fact'),key=raw.signing_key.key_id+':'+raw.storage_epoch;
            try{
              this.observeFact(fact);const node=nodes.get(key);if(!node)throw new ProviderError('provider_response_binding');
              if(!candidates.has(key)){
                if(candidates.size>=maximum){partial=true;break;}
                candidates.set(key,{node,target:await this.proveTarget(node,budget),facts:[]});
              }
              const observation={fact,index_lease:entry.index_lease,directory},records=candidates.get(key)!.facts;
              if(records.length<6&&!records.some((record:Obj)=>same(record,observation)))records.push(observation);
            }catch(error){if(!expectedError(error))throw error;errors.push(this.error(nodes.get(key)??directory,error));partial=true;}
          }
          if(page.next_cursor===null){stopped=true;break;}
          if(cursor!==null&&page.next_cursor<=cursor)throw new ProviderError('provider_invalid_cursor');
          cursor=page.next_cursor;if(candidates.size>=maximum){partial=true;stopped=true;break;}
        }catch(error){if(!expectedError(error))throw error;errors.push(this.error(directory,error));partial=true;stopped=true;break;}
      }
      if(!stopped)partial=true;if(candidates.size>=maximum)break;
    }
    const result:Obj[]=[];
    for(const candidate of candidates.values()){
      try{
        this.participant.acceptProviderControl(candidate.node);verifyDocument(candidate.target,'provider.target');
        const current=[];
        for(const observation of candidate.facts)if(this.factCurrent(observation.fact)){
          verifyIndexLease(observation.index_lease,{fact:observation.fact,node:observation.directory});current.push(observation);
        }
        if(current.length){candidate.facts=current;result.push(candidate);}
      }catch(error){if(!expectedError(error))throw error;errors.push(this.error(candidate.node,error));partial=true;}
    }
    return {state:result.length?'observed':'not_observed',candidates:result,errors:errors.slice(0,64),partial,...this.metrics(budget)};
  }
  private async authorizeOne(ref:Obj,root:Obj,publisher:Obj,allocationId:string,node:SignedNode,
    resourceSeconds:number,leaseSeconds:number,budget:LookupBudget):Promise<Obj>{
    const target=await this.proveTarget(node,budget),raw=verifyNode(node);
    const semantic={ref,root_key:root,publisher,allocation_id:allocationId,node_key_id:raw.signing_key.key_id,
      storage_epoch:raw.storage_epoch,resource_seconds:resourceSeconds,lease_seconds:leaseSeconds};
    const reference=digest({allocation_id:allocationId,node_key_id:semantic.node_key_id,storage_epoch:semantic.storage_epoch});
    const issued=now(),until=issued+resourceSeconds;
    let intent=signDocument(this.identity,'root.resource.intent',{issued_at:issued,expires_at:until,
      allocation_id:'resource_'+reference,root_key:root,subject:this.subject,node_key_id:semantic.node_key_id,
      storage_epoch:semantic.storage_epoch,purpose:'provider_index',budget:{...DEFAULT_RESOURCE_BUDGET},
      windows:{admit_until:until,read_until:until,copy_until:until,publish_until:until,retain_until:until}});
    let session=this.session('authorize',reference,semantic,{node,intent},until+60);
    intent=session.intent;verifyDocument(intent,'root.resource.intent');
    if(!session.lease){
      const response=await this.call(node,'resource.allocate',{intent},budget);
      if(response.current_state!=='active')throw new ProviderError('provider_resource_inactive');
      verifyResourceLease(response.lease,{intent,node,target});
      session=this.append('authorize',reference,{lease:response.lease,resource_status:response.status});
    }
    const lease=verifyResourceLease(session.lease,{intent,node,target});
    if(!session.grant){
      const issued=now(),grant=signDocument(this.identity,'provider.publication.grant',{issued_at:issued,expires_at:lease.windows.publish_until,
        root_key:root,resource:lease.resource,resource_lease_sha256:digest(session.lease),publisher,ref,
        grant_id:'grant_'+reference,revision:1,operation_mask:PUBLISH,maximum_fact_seconds:leaseSeconds});
      const revision=this.participant.providerStorage(db=>transaction(db,()=>{
        const name='status:'+digest(root),row=db.prepare('SELECT value FROM open_provider_client_meta WHERE name=?').get(name) as Obj|undefined;
        const next=safeInteger(row?Number(row.value)+1:1);
        db.prepare('INSERT INTO open_provider_client_meta VALUES(?,?) ON CONFLICT(name) DO UPDATE SET value=excluded.value').run(name,String(next));return next;
      }));
      const status=issueStatus(this.identity,{root,revision,issued_at:issued,valid_until:grant.payload.expires_at,
        entries:[{scope_kind:'authority',scope_id:authorityScope(root,'provider.publication.grant',digest(grant)),
          minimum_document_revision:1,status:'active',operation_mask:PUBLISH}]});
      session=this.append('authorize',reference,{grant,owner_status:status});
    }
    return {node,intent:session.intent,resource_lease:session.lease,resource_status:session.resource_status,
      publication_grant:session.grant,owner_status:session.owner_status};
  }
  async authorizePublication(reference:unknown,rootValue:unknown,publisherValue:unknown,allocationId:string,
    options:PublicationOptions={}):Promise<Obj>{
    const ref=opaqueRef(doc(reference)),root=rootKey(doc(rootValue)),publisher=dualId(doc(publisherValue));opaqueId(allocationId);
    if(!same(root.owner,asDual(this.subject)))throw new ProviderError('provider_wrong_owner');
    const leaseSeconds=options.lease_seconds??180,resourceSeconds=options.resource_seconds??600,directoryCount=options.directory_count??3;
    bounded(leaseSeconds,600);bounded(resourceSeconds,604800);bounded(directoryCount,3);
    if(resourceSeconds<leaseSeconds)throw new ProviderError('provider_invalid_window');
    const budget=this.budget(options.budget);
    this.participant.providerStorage(db=>transaction(db,()=>{
      const name='status:'+digest(root);
      if(!db.prepare('SELECT 1 FROM open_provider_client_meta WHERE name=?').get(name)){
        if((db.prepare("SELECT count(*) AS n FROM open_provider_client_meta WHERE name LIKE 'status:%'").get() as Obj).n>=LOCAL_MAX_RECORDS)
          throw new ProviderError('provider_local_capacity',true);
        db.prepare("INSERT INTO open_provider_client_meta VALUES(?,'0')").run(name);
      }
    }));
    const semantic={ref,root_key:root,publisher,allocation_id:allocationId,lease_seconds:leaseSeconds,
      resource_seconds:resourceSeconds,directory_count:directoryCount};
    const key=digest({allocation_id:allocationId,owner:this.subject.signing_key.key_id});let plan:Obj;
    try{plan=this.session('authorize_plan',key,semantic);}
    catch(error){
      if(!(error instanceof ProviderError)||error.code!=='provider_local_missing')throw error;
      const {nodes}=await this.directories(ref,budget,directoryCount);
      if(!nodes.length)return {state:'not_observed',authorizations:[],errors:[],partial:true,...this.metrics(budget)};
      plan=this.session('authorize_plan',key,semantic,{nodes},now()+resourceSeconds+60);
    }
    const results:Obj[]=[],errors:Obj[]=[];
    for(const old of plan.nodes){try{
      const node=await this.resolveDirectory(old,budget);
      results.push(await this.authorizeOne(ref,root,publisher,allocationId,node,resourceSeconds,leaseSeconds,budget));
    }catch(error){if(!expectedError(error))throw error;errors.push(this.error(old,error));}}
    return {state:results.length?'authorized':'pending',authorizations:results,errors,partial:results.length<directoryCount,...this.metrics(budget)};
  }
  async publish(reference:unknown,rootValue:unknown,providerFact:unknown,allocationId:string,
    options:PublishOptions={}):Promise<Obj>{
    providerFact=doc(providerFact,MAX_CONTROL_BYTES);
    const ref=opaqueRef(doc(reference)),root=rootKey(doc(rootValue)),fact=verifyDocument(providerFact,'provider.fact');opaqueId(allocationId);
    if(!same(fact.signing_key,this.subject.signing_key)||!same(fact.ref,ref)||fact.status!=='active')throw new ProviderError('provider_wrong_publisher');
    if(!this.participant.descriptor)throw new ProviderError('provider_node_required');
    const own=verifyNode(this.participant.descriptor);
    if(!same(own.signing_key,fact.signing_key)||own.storage_epoch!==fact.storage_epoch)throw new ProviderError('provider_wrong_publisher');
    const leaseSeconds=options.lease_seconds??180,directoryCount=options.directory_count??3;
    bounded(leaseSeconds,600);bounded(directoryCount,3);
    const budget=this.budget(options.budget),errors:Obj[]=[];
    let authorizations=options.authorizations===undefined?undefined:doc({authorizations:options.authorizations}).authorizations;
    if(authorizations===undefined){
      const prepared=await this.authorizePublication(ref,root,asDual(this.subject),allocationId,{...options,budget});
      authorizations=prepared.authorizations;errors.push(...prepared.errors);
    }
    if(!Array.isArray(authorizations)||authorizations.length>3)throw new ProviderError('provider_invalid_authorizations');
    const results:Obj[]=[],seen=new Set<string>();
    for(const value of authorizations){
      const authorization=fields(value,['node','intent','resource_lease','resource_status','publication_grant','owner_status']),old=authorization.node;
      try{
        const node=await this.resolveDirectory(old,budget),raw=verifyNode(node),key=binding(node);
        if(seen.has(key))throw new ProviderError('provider_duplicate_directory');seen.add(key);
        const target=await this.proveTarget(node,budget),lease=verifyResourceLease(authorization.resource_lease,{intent:authorization.intent,node,target});
        const grant=verifyDocument(authorization.publication_grant,'provider.publication.grant'),status=verifyStatus(authorization.owner_status);
        const scope=authorityScope(root,'provider.publication.grant',digest(authorization.publication_grant));
        if(!same(lease.root_key,root)||lease.purpose!=='provider_index'||!same(grant.root_key,root)||!same(grant.ref,ref)||
          !same(grant.publisher,asDual(this.subject))||!same(grant.resource,lease.resource)||grant.resource_lease_sha256!==digest(authorization.resource_lease)||
          !same(status.scope_key,{root_key:root,issuer_key_id:root.owner.signing_key_id})||
          !status.entries.some((entry:Obj)=>entry.scope_kind==='authority'&&entry.scope_id===scope&&entry.status==='active'&&
            entry.minimum_document_revision<=grant.revision&&(entry.operation_mask&PUBLISH)))throw new ProviderError('provider_publication_not_authorized');
        if(leaseSeconds>grant.maximum_fact_seconds)throw new ProviderError('provider_invalid_limit');
        const semantic={allocation_id:allocationId,ref,root_key:root,fact_sha256:digest(providerFact),node_key_id:raw.signing_key.key_id,
          storage_epoch:raw.storage_epoch,lease_seconds:leaseSeconds,grant_sha256:digest(authorization.publication_grant)};
        const reference=digest({allocation_id:allocationId,publisher:this.subject.signing_key.key_id,node_key_id:raw.signing_key.key_id,storage_epoch:raw.storage_epoch});
        const body={fact:providerFact,provider_node:this.participant.descriptor,publication_grant:authorization.publication_grant,
          resource_lease:authorization.resource_lease,owner_status:authorization.owner_status,allocation_id:'publication_'+reference,lease_seconds:leaseSeconds};
        const session=this.session('publish',reference,semantic,{body},lease.expires_at+60);
        const response=session.index_lease?await this.call(node,'provider.result',{allocation_id:session.body.allocation_id,operation:'provider.put'},budget):
          await this.call(node,'provider.put',session.body,budget);
        const index=verifyIndexLease(response.index_lease,{fact:providerFact,node,allow_expired:response.current_state!=='active'});
        if(session.index_lease&&!same(session.index_lease,response.index_lease))throw new ProviderError('provider_local_conflict');
        this.append('publish',reference,{index_lease:response.index_lease});
        results.push({directory:node,fact:providerFact,index_lease:response.index_lease,current_state:response.current_state,expires_at:index.expires_at});
      }catch(error){if(!expectedError(error))throw error;errors.push(this.error(old,error));}
    }
    const active=results.filter(result=>result.current_state==='active').length;
    return {state:active?'published':'pending',publications:results,errors:errors.slice(0,64),partial:active<directoryCount,...this.metrics(budget)};
  }
}
