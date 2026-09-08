/** Explicit first-contact client over the existing native participant and DB.
 * Bounded local control records never become Vault memory or agent authority. */
import {
  canonicalBytes,document,documentSha256,objectFields,opaqueId,NetworkCryptoError,
  validateEncryptionIdentity,
} from './crypto.ts';
import type {DocumentInput,EncryptionIdentityDocument} from './crypto.ts';
import {transaction} from './io.ts';
import {coordinate,issueContact,verifyContact,verifyNode} from './open-control.ts';
import type {SignedNode} from './open-control.ts';
import {LookupBudget} from './open-routing.ts';
import {SLOT_BYTES,ContactError,limit,signDocument,signRpc,solveChallenge,verifyDecision,verifyPolicy,verifyResponse,verifyRequest,verifyRpc} from './open-contact.ts';
import type {OpenParticipant} from './open-participant.ts';

export const CONNECT_SCHEMA='memory-vault-open-contact-connect/v1';
export const LOCAL_RESERVATION=canonicalBytes({state:'reserved_contact_control'});
type Obj=Record<string,any>;
const now=()=>Math.floor(Date.now()/1000);
const same=(a:unknown,b:unknown)=>Buffer.from(canonicalBytes(a)).equals(Buffer.from(canonicalBytes(b)));
export class OpenContactClient{
  readonly participant:OpenParticipant;
  readonly encryption:EncryptionIdentityDocument;
  constructor(participant:OpenParticipant,encryption:EncryptionIdentityDocument){
    this.participant=participant;this.encryption=encryption;validateEncryptionIdentity(encryption);
    participant.contactStorage(db=>db.exec(`CREATE TABLE IF NOT EXISTS open_contact_local(
      category TEXT NOT NULL,reference TEXT NOT NULL,body BLOB NOT NULL,expires_at INTEGER NOT NULL,PRIMARY KEY(category,reference));
      CREATE INDEX IF NOT EXISTS open_contact_local_expiry ON open_contact_local(expires_at);`));
  }
  private save(category:string,reference:string,value:Obj,expires:number):void{
    const raw=canonicalBytes(document(value,24576));
    this.participant.contactStorage(db=>transaction(db,()=>{
      db.prepare('DELETE FROM open_contact_local WHERE rowid IN (SELECT rowid FROM open_contact_local WHERE expires_at<=? ORDER BY expires_at LIMIT 32)').run(now());
      const prior=db.prepare('SELECT body FROM open_contact_local WHERE category=? AND reference=?').get(category,reference) as Obj|undefined;
      if(prior){
        if(Buffer.from(prior.body).equals(Buffer.from(LOCAL_RESERVATION)))
          db.prepare('UPDATE open_contact_local SET body=?,expires_at=? WHERE category=? AND reference=?').run(raw,expires,category,reference);
        else if(!Buffer.from(prior.body).equals(Buffer.from(raw)))throw new ContactError('contact_local_conflict');
      }
      else{
        if((db.prepare('SELECT count(*) AS n FROM open_contact_local').get() as Obj).n>=128)throw new ContactError('contact_local_capacity',true);
        db.prepare('INSERT INTO open_contact_local VALUES(?,?,?,?)').run(category,reference,raw,expires);
      }
    }));
  }
  private reserve(entries:Array<[string,string]>,expires:number):void{
    this.participant.contactStorage(db=>transaction(db,()=>{
      db.prepare('DELETE FROM open_contact_local WHERE rowid IN (SELECT rowid FROM open_contact_local WHERE expires_at<=? ORDER BY expires_at LIMIT 32)').run(now());
      const missing=entries.filter(([category,reference])=>!db.prepare('SELECT 1 FROM open_contact_local WHERE category=? AND reference=?').get(category,reference));
      if((db.prepare('SELECT count(*) AS n FROM open_contact_local').get() as Obj).n+missing.length>128)throw new ContactError('contact_local_capacity',true);
      for(const [category,reference] of missing)
        db.prepare('INSERT INTO open_contact_local VALUES(?,?,?,?)').run(category,reference,LOCAL_RESERVATION,expires);
    }));
  }
  private load(category:string,reference:string):Obj{
    opaqueId(reference);
    const row=this.participant.contactStorage(db=>db.prepare('SELECT body,expires_at FROM open_contact_local WHERE category=? AND reference=?').get(category,reference)) as Obj|undefined;
    if(!row||Buffer.from(row.body).equals(Buffer.from(LOCAL_RESERVATION)))throw new ContactError('contact_local_missing');
    if(row.expires_at<=now())throw new ContactError('contact_expired');return document(row.body,24576);
  }
  private savePolicy(reservationRef:string,leaseId:string,value:Obj,expires:number):void{
    const raw=canonicalBytes(document(value,24576));
    this.participant.contactStorage(db=>transaction(db,()=>{
      const old=db.prepare("SELECT body FROM open_contact_local WHERE category='policy' AND reference=?").get(leaseId) as Obj|undefined;
      if(old){
        if(!Buffer.from(old.body).equals(Buffer.from(raw)))throw new ContactError('contact_local_conflict');
        db.prepare("DELETE FROM open_contact_local WHERE category='policy_pending' AND reference=? AND body=?").run(reservationRef,LOCAL_RESERVATION);
      }else{
        const changed=db.prepare("UPDATE open_contact_local SET category='policy',reference=?,body=?,expires_at=? WHERE category='policy_pending' AND reference=? AND body=?")
          .run(leaseId,raw,expires,reservationRef,LOCAL_RESERVATION);
        if(changed.changes!==1)throw new ContactError('contact_local_capacity',true);
      }
    }));
  }
  private knownPolicy(allocationRef:string):Obj|null{
    const rows=this.participant.contactStorage(db=>db.prepare("SELECT body FROM open_contact_local WHERE category='policy' AND expires_at>? LIMIT 128").all(now())) as Obj[];
    for(const row of rows){const value=document(row.body,24576) as Obj;if(value.allocation_ref===allocationRef)return value;}
    return null;
  }
  async call(node:SignedNode,action:string,body:Obj,budget=new LookupBudget()):Promise<Obj>{
    budget.check();this.participant.acceptContactControl(node);
    const request=signRpc(this.participant.identity,{node,action,body});verifyRpc(request,{node});
    budget.chargeRequestBytes(canonicalBytes(request).length);budget.chargeRequest();
    const reply=await this.participant.transport.request(node.payload.base_url,request as DocumentInput,budget.deadline);
    budget.chargeBytes(reply.wire_bytes);
    const checked=verifyResponse(reply.response,{request,node});this.participant.acceptContactControl(node);
    if(checked.body.error)throw new ContactError(checked.body.error.code,checked.body.error.retryable);
    this.participant.table.learnVerified(node,reply.observed_address);return checked.body;
  }
  private async resolve(endpoint:Obj,budget:LookupBudget):Promise<SignedNode>{
    const route=await this.participant.lookupContactResource(coordinate(endpoint.node_key_id),budget);
    const candidates=this.participant.descriptor?[...route.candidates,this.participant.descriptor]:route.candidates;
    for(const node of candidates){
      const raw=verifyNode(node);
      if(raw.signing_key.key_id===endpoint.node_key_id&&raw.base_url===endpoint.base_url&&raw.storage_epoch===endpoint.storage_epoch)return node;
    }
    throw new ContactError('contact_resource_unresolved',true);
  }
  private async sessionNode(session:Obj,budget:LookupBudget):Promise<SignedNode>{
    const old=session.node.payload;
    try{verifyNode(session.node);this.participant.acceptContactControl(session.node);return session.node;}
    catch(error){if(!(error instanceof NetworkCryptoError))throw error;
      return this.resolve({node_key_id:old.signing_key.key_id,base_url:old.base_url,storage_epoch:old.storage_epoch},budget);}
  }
  async enable(node:SignedNode,options:{allocation_id:string;max_pending?:number;lease_seconds?:number;revision?:number}):Promise<Obj>{
    const maxPending=options.max_pending===undefined?4:options.max_pending,leaseSeconds=options.lease_seconds===undefined?600:options.lease_seconds,
      revision=options.revision===undefined?1:options.revision;
    limit(maxPending,32);limit(leaseSeconds,86400);limit(revision,9007199254740991);opaqueId(options.allocation_id);
    const budget=new LookupBudget(),publicKey=validateEncryptionIdentity(this.encryption);
    const allocation={encryption_key:publicKey,purpose:'knock',max_items:maxPending,max_bytes:maxPending*SLOT_BYTES,
      lease_seconds:leaseSeconds,allocation_id:options.allocation_id};
    signRpc(this.participant.identity,{node,action:'lease',body:allocation});
    const reservationRef=documentSha256({node_key_id:node.payload.signing_key.key_id,storage_epoch:node.payload.storage_epoch,allocation_id:options.allocation_id});
    const session=this.knownPolicy(reservationRef);let lease:Obj,policy:Obj;
    if(session){
      if(!same(session.allocation,allocation)||session.policy.payload.revision!==revision)throw new ContactError('contact_local_conflict');
      lease=session.lease;policy=session.policy;verifyPolicy(policy,{lease,node});
    }else{
      this.reserve([['policy_pending',reservationRef]],now()+leaseSeconds+60);
      lease=(await this.call(node,'lease',allocation,budget)).lease;
      const raw=lease.payload;
      policy=signDocument(this.participant.identity,'contact.policy',{issued_at:raw.issued_at,expires_at:raw.expires_at,
        node_key_id:raw.node_key_id,storage_epoch:raw.storage_epoch,lease_id:raw.lease_id,lease_sha256:documentSha256(lease),
        resource_id:raw.resource_id,encryption_key:publicKey,revision,status:'active',max_pending:maxPending});
      this.savePolicy(reservationRef,raw.lease_id,{node,lease,policy,allocation_ref:reservationRef,allocation},raw.expires_at);
    }
    const raw=lease.payload;
    await this.call(node,'policy.put',{lease,policy},budget);
    const contact=issueContact(this.participant.identity,{encryption_key:publicKey,revision,allow_discovery:true,
      endpoints:[{kind:'node',node_key_id:raw.node_key_id,base_url:node.payload.base_url,storage_epoch:raw.storage_epoch}],
      issued_at:raw.issued_at,expires_at:Math.min(raw.issued_at+3600,raw.expires_at)});
    const published=await this.participant.publishContact(contact,Math.min(300,leaseSeconds));
    return {state:'active',lease_id:raw.lease_id,expires_at:raw.expires_at,directory_state:published.state,
      confirmed_index_leases:published.confirmed_leases,open_messaging_supported:false};
  }
  async request(recipientKeyId:string,options:{request_id:string}):Promise<Obj>{
    const requestId=opaqueId(options.request_id),budget=new LookupBudget();let session:Obj;
    try{session=this.load('outgoing',requestId);
      if(session.request.payload.recipient_key_id!==recipientKeyId)throw new ContactError('contact_local_conflict');
    }catch(error){
      if(!(error instanceof ContactError)||error.code!=='contact_local_missing')throw error;
      const found=await this.participant.findContact(recipientKeyId,budget);
      if(found.state!=='found')throw new ContactError('contact_unavailable',true);
      const contact=verifyContact(found.contact);this.participant.acceptContactControl(found.contact);
      if(!contact.endpoints.length)throw new ContactError('contact_unavailable');
      let bundle:Obj|null=null,node:SignedNode|null=null,policy:Obj|null=null;
      for(const endpoint of contact.endpoints){
        try{
          node=await this.resolve(endpoint,budget);bundle=await this.call(node,'policy.get',{recipient_key_id:recipientKeyId},budget);
          policy=verifyPolicy(bundle.policy,{lease:bundle.lease,node});
          if(!same(policy.encryption_key,contact.encryption_key))throw new ContactError('contact_policy_mismatch');break;
        }catch(error){if(!(error instanceof NetworkCryptoError))throw error;bundle=null;}
      }
      if(bundle===null||node===null||policy===null)throw new ContactError('contact_unavailable',true);
      const issued=now(),logical=signDocument(this.participant.identity,'contact.request',{issued_at:issued,expires_at:Math.min(issued+86400,policy.expires_at),
        request_id:requestId,encryption_key:validateEncryptionIdentity(this.encryption),recipient_key_id:recipientKeyId,
        recipient_encryption_key_id:policy.encryption_key.key_id,node_key_id:policy.node_key_id,storage_epoch:policy.storage_epoch,
        lease_id:policy.lease_id,resource_id:policy.resource_id,policy_sha256:documentSha256(bundle.policy),request_class:'message'});
      session={...bundle,node,request:logical};
      this.reserve([['outgoing',requestId],['result',requestId]],logical.payload.expires_at);
      this.save('outgoing',requestId,session,logical.payload.expires_at);
    }
    const node=await this.sessionNode(session,budget),request=session.request;
    verifyRequest(request,{policy:session.policy,lease:session.lease,node});
    const challenge=(await this.call(node,'challenge',{request,purpose:'submit'},budget)).challenge;
    const answer=await solveChallenge(challenge,{request,node,purpose:'submit',encryption_identity:this.encryption});
    const result=await this.call(node,'submit',{request,challenge,answer},budget);
    return {...result,request_id:requestId,expires_at:request.payload.expires_at,open_messaging_supported:false,recipient_approved:false,
      metrics:{requests:budget.requests,request_bytes:budget.request_bytes,response_bytes:budget.response_bytes}};
  }
  async poll(leaseId:string):Promise<Obj>{
    const session=this.load('policy',leaseId),budget=new LookupBudget(),node=await this.sessionNode(session,budget);
    const response=await this.call(node,'poll',{lease_id:leaseId},budget);
    for(const request of response.requests){
      verifyRequest(request,{policy:session.policy,lease:session.lease,node});
      this.save('incoming',documentSha256(request),{...session,request},request.payload.expires_at);
    }
    return {state:'unreviewed',requests:response.requests.map((request:Obj)=>({request_id:request.payload.request_id,
      sender_key_id:request.payload.signing_key.key_id,sender_encryption_key_id:request.payload.encryption_key.key_id,
      request_sha256:documentSha256(request),request_ref:documentSha256(request),request_class:request.payload.request_class,
      expires_at:request.payload.expires_at})),recipient_approved:false};
  }
  async decide(requestRef:string,options:{decision:string;max_items?:number;max_bytes?:number}):Promise<Obj>{
    const {decision}=options;if(!['approved','rejected'].includes(decision))throw new ContactError('contact_invalid_decision');
    const maxItems=options.max_items===undefined?1:options.max_items,maxBytes=options.max_bytes===undefined?1048576:options.max_bytes;
    limit(maxItems,32);limit(maxBytes,16*1024*1024);
    const session=this.load('incoming',requestRef),budget=new LookupBudget(),node=await this.sessionNode(session,budget);
    const request=session.request,requestId=request.payload.request_id,original=verifyRequest(request,{policy:session.policy,lease:session.lease,node});
    let signed:Obj;
    try{
      signed=this.load('decision',requestRef).decision;if(signed.payload.decision!==decision)throw new ContactError('contact_local_conflict');
      if(decision==='approved'){
        const promised=signed.payload.grant.payload.resource_lease.payload;
        if(promised.max_items!==maxItems||promised.max_bytes!==maxBytes)throw new ContactError('contact_local_conflict');
      }
    }
    catch(error){
      if(!(error instanceof ContactError)||error.code!=='contact_local_missing')throw error;
      const entries:Array<[string,string]>=[['decision',requestRef]];if(decision==='approved')entries.push(['allocation',requestRef]);
      this.reserve(entries,original.expires_at);
      const issued=now(),common={request_id:requestId,request_sha256:documentSha256(request),subject_key_id:original.signing_key.key_id,
        subject_encryption_key_id:original.encryption_key.key_id,recipient_encryption_key_id:this.encryption.key_id};
      let grant:Obj|null=null;
      if(decision==='approved'){
        let allocation:Obj;
        try{
          allocation=this.load('allocation',requestRef);
          if(allocation.max_items!==maxItems||allocation.max_bytes!==maxBytes)throw new ContactError('contact_local_conflict');
        }catch(missing){
          if(!(missing instanceof ContactError)||missing.code!=='contact_local_missing')throw missing;
          allocation={encryption_key:validateEncryptionIdentity(this.encryption),purpose:'delivery',max_items:maxItems,max_bytes:maxBytes,
            lease_seconds:original.expires_at-issued,allocation_id:'delivery_'+documentSha256(request)};
          this.save('allocation',requestRef,allocation,original.expires_at);
        }
        const resource=(await this.call(node,'lease',allocation,budget)).lease;
        grant=signDocument(this.participant.identity,'contact.grant',{issued_at:issued,expires_at:original.expires_at,...common,
          node_key_id:resource.payload.node_key_id,storage_epoch:resource.payload.storage_epoch,resource_id:resource.payload.resource_id,
          operations:['message.store'],resource_lease:resource});
      }
      signed=signDocument(this.participant.identity,'contact.decision',{issued_at:issued,expires_at:original.expires_at,...common,
        node_key_id:original.node_key_id,storage_epoch:original.storage_epoch,policy_sha256:original.policy_sha256,
        decision,reason:decision==='approved'?'accepted':'declined',grant});
      verifyDecision(signed,{request,policy:session.policy,lease:session.lease,node});this.save('decision',requestRef,{decision:signed},original.expires_at);
    }
    const result=await this.call(node,'decide',{request,decision:signed},budget);
    return {...result,request_id:requestId,decision,open_messaging_supported:false};
  }
  async result(requestId:string):Promise<Obj>{
    const session=this.load('outgoing',requestId),budget=new LookupBudget(),node=await this.sessionNode(session,budget),request=session.request;
    const challenge=(await this.call(node,'challenge',{request,purpose:'result'},budget)).challenge;
    const answer=await solveChallenge(challenge,{request,node,purpose:'result',encryption_identity:this.encryption});
    const response=await this.call(node,'result',{request,challenge,answer},budget);
    if(response.decision!==null){
      verifyDecision(response.decision,{request,policy:session.policy,lease:session.lease,node});
      this.save('result',requestId,{decision:response.decision},request.payload.expires_at);
    }
    return {state:response.state,request_id:requestId,recipient_approved:response.state==='approved',authority_verified:response.state==='approved',
      open_messaging_supported:false,grant:response.decision?.payload.grant??null};
  }
  async dispatch(invitation:unknown,requestId?:string):Promise<Obj>{
    const raw=document(invitation as DocumentInput,8192) as Obj,action=raw.action;
    const variants:Record<string,string[]>={enable:['node','allocation_id','max_pending','lease_seconds','revision'],request:['recipient_key_id'],poll:['lease_id'],
      decide:['request_ref','decision','max_items','max_bytes'],result:['request_id']};
    if(raw.schema_version!==CONNECT_SCHEMA||typeof action!=='string'||!Object.hasOwn(variants,action))throw new ContactError('contact_invalid_connect');
    objectFields(raw,['schema_version','action',...variants[action]]);
    if(action==='enable')return this.enable(raw.node,{allocation_id:raw.allocation_id,max_pending:raw.max_pending,lease_seconds:raw.lease_seconds,revision:raw.revision});
    if(action==='request')return this.request(raw.recipient_key_id,{request_id:requestId!});
    if(action==='poll')return this.poll(raw.lease_id);
    if(action==='decide')return this.decide(raw.request_ref,{decision:raw.decision,max_items:raw.max_items,max_bytes:raw.max_bytes});
    return this.result(raw.request_id);
  }
}
