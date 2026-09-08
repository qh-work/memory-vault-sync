/** Finite first-contact obligations in the existing protected transport SQLite.
 * Native implementation: no subprocesses, Vault records, trust or message ACKs. */
import {timingSafeEqual} from 'node:crypto';
import type {DatabaseSync} from 'node:sqlite';
import {canonicalBytes,document,documentSha256,safeInteger,sha256,decodeBase64url,validateSigningIdentity} from './crypto.ts';
import type {DocumentInput,SigningIdentityDocument} from './crypto.ts';
import {verifyNode} from './open-control.ts';
import type {SignedNode} from './open-control.ts';
import {ContactError,MAX_REQUEST_BYTES,fail,issueChallenge,signDocument,verifyChallenge,
  verifyDecision,verifyDocument,verifyLease,verifyPolicy,verifyRequest,verifyRpc} from './open-contact.ts';

type Obj=Record<string,any>;
export const RETENTION_SECONDS=30,GC_BATCH=128,MAX_SUBJECT_CHALLENGES=4,MAX_OWNER_SUBMIT_CHALLENGES=16;
// Shared across per-request state instances. Increment/decrement has no await;
// only JWE creation between them yields, and holds no SQLite transaction.
const challengeSlots:Record<string,number>={submit:0,result:0};
export interface ContactStateOptions {
  enabled?:boolean;maximum_leases?:number;maximum_knock_items?:number;maximum_knock_bytes?:number;
  maximum_delivery_items?:number;maximum_delivery_bytes?:number;maximum_challenges?:number;
  maximum_challenge_bytes?:number;clock?:()=>number;
}
const parsed=(value:Uint8Array):Obj=>document(value) as Obj;
const same=(a:unknown,b:unknown)=>Buffer.from(canonicalBytes(a)).equals(Buffer.from(canonicalBytes(b)));

export class ContactState {
  readonly db:DatabaseSync;readonly identity:SigningIdentityDocument;readonly node:SignedNode;
  enabled:boolean;clock:()=>number;
  maximum_leases!:number;maximum_knock_items!:number;maximum_knock_bytes!:number;
  maximum_delivery_items!:number;maximum_delivery_bytes!:number;maximum_challenges!:number;maximum_challenge_bytes!:number;
  constructor(db:DatabaseSync,identity:SigningIdentityDocument,node:SignedNode,options:ContactStateOptions={}){
    if(!options||typeof options!=='object'||Array.isArray(options))fail('contact_invalid_local_policy');
    this.enabled=options.enabled===undefined?false:options.enabled;if(typeof this.enabled!=='boolean')fail('contact_invalid_local_policy');
    const ceilings={maximum_leases:128,maximum_knock_items:1024,maximum_knock_bytes:16*1024*1024,
      maximum_delivery_items:1024,maximum_delivery_bytes:64*1024*1024,maximum_challenges:128,maximum_challenge_bytes:1024*1024};
    if(Object.keys(options).some(name=>!['enabled','clock',...Object.keys(ceilings)].includes(name)))fail('contact_invalid_local_policy');
    for(const [name,ceiling] of Object.entries(ceilings)){
      const supplied=(options as Obj)[name],value=supplied===undefined?ceiling:supplied;if(safeInteger(value,1)>ceiling)fail('contact_invalid_local_policy');
      (this as any)[name]=value;
    }
    const target=verifyNode(node,{now:node.payload.issued_at});
    if(!same(target.signing_key,validateSigningIdentity(identity)))fail('contact_wrong_node');
    this.db=db;this.identity=document(identity as unknown as DocumentInput) as unknown as SigningIdentityDocument;
    this.node=document(node as unknown as DocumentInput) as unknown as SignedNode;
    this.clock=options.clock??(()=>Date.now()/1000);
  }
  private now():number{return safeInteger(Math.floor(this.clock()));}
  private one(sql:string,...values:any[]):Obj|undefined{return this.db.prepare(sql).get(...values) as Obj|undefined;}
  private binding():void{
    const row=this.one("SELECT value FROM open_contact_state WHERE name='binding'");
    if(!row||row.value!==this.identity.key_id+':'+this.node.payload.storage_epoch)fail('contact_storage_epoch_mismatch');
  }
  private tx(operation:(now:number)=>any,rpc?:unknown):any{
    if(this.db.isTransaction)fail('contact_storage_transaction');
    this.db.exec('BEGIN IMMEDIATE');let result:any;
    try{
      const now=this.now();this.binding();if(rpc!==undefined)verifyRpc(rpc,{node:this.node,now});
      this.prune(now);result=operation(now);this.db.exec('COMMIT');
    }catch(error){this.db.exec('ROLLBACK');throw error;}
    if(result instanceof ContactError)throw result;return result;
  }
  initialize():void{
    if(this.db.isTransaction)fail('contact_storage_transaction');this.db.exec('BEGIN IMMEDIATE');
    try{
      this.db.exec(`CREATE TABLE IF NOT EXISTS open_contact_state(name TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS open_contact_resource_leases(
          lease_id TEXT PRIMARY KEY,owner TEXT NOT NULL,allocation_id TEXT NOT NULL,
          allocation_sha256 TEXT NOT NULL,purpose TEXT NOT NULL,record BLOB NOT NULL,
          max_items INTEGER NOT NULL,max_bytes INTEGER NOT NULL,expires_at INTEGER NOT NULL,
          retain_until INTEGER NOT NULL,status TEXT NOT NULL,grant_request TEXT,UNIQUE(owner,allocation_id));
        CREATE TABLE IF NOT EXISTS open_contact_policies(
          owner TEXT PRIMARY KEY,lease_id TEXT NOT NULL,revision INTEGER NOT NULL,digest TEXT NOT NULL,
          record BLOB NOT NULL,second_record BLOB,status TEXT NOT NULL,retain_until INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS open_contact_requests(
          sender TEXT NOT NULL,request_id TEXT NOT NULL,digest TEXT NOT NULL,owner TEXT NOT NULL,
          lease_id TEXT NOT NULL,record BLOB NOT NULL,state TEXT NOT NULL,decision BLOB,
          decision_sha256 TEXT,expires_at INTEGER NOT NULL,retain_until INTEGER NOT NULL,PRIMARY KEY(sender,request_id));
        CREATE TABLE IF NOT EXISTS open_contact_challenges(
          sender TEXT NOT NULL,request_id TEXT NOT NULL,purpose TEXT NOT NULL,request_sha256 TEXT NOT NULL,
          record BLOB NOT NULL,digest TEXT NOT NULL,answer_sha256 TEXT NOT NULL,expires_at INTEGER NOT NULL,
          retain_until INTEGER NOT NULL,used INTEGER NOT NULL,PRIMARY KEY(sender,request_id,purpose));
        CREATE INDEX IF NOT EXISTS open_resource_expiry ON open_contact_resource_leases(retain_until);
        CREATE INDEX IF NOT EXISTS open_policy_expiry ON open_contact_policies(retain_until);
        CREATE INDEX IF NOT EXISTS open_request_expiry ON open_contact_requests(retain_until);
        CREATE INDEX IF NOT EXISTS open_request_lease ON open_contact_requests(lease_id,state,expires_at);
        CREATE INDEX IF NOT EXISTS open_request_pair ON open_contact_requests(sender,owner,state,expires_at);
        CREATE INDEX IF NOT EXISTS open_challenge_expiry ON open_contact_challenges(retain_until);
        CREATE INDEX IF NOT EXISTS open_challenge_purpose ON open_contact_challenges(purpose);`);
      const previous=this.one("SELECT value FROM open_contact_state WHERE name='binding'");
      if(!previous){
        if(['open_contact_resource_leases','open_contact_policies','open_contact_requests','open_contact_challenges']
          .some(table=>this.one('SELECT 1 FROM '+table+' LIMIT 1')))fail('contact_storage_binding_missing');
        this.db.prepare("INSERT INTO open_contact_state VALUES('binding',?)").run(this.identity.key_id+':'+this.node.payload.storage_epoch);
      }
      this.binding();this.db.exec('COMMIT');
    }catch(error){this.db.exec('ROLLBACK');throw error;}
  }
  private prune(now:number):void{
    for(const table of ['open_contact_challenges','open_contact_requests'])
      this.db.prepare('DELETE FROM '+table+' WHERE rowid IN (SELECT rowid FROM '+table+
        ' WHERE retain_until<=? ORDER BY retain_until LIMIT ?)').run(now,GC_BATCH);
    this.db.prepare(`DELETE FROM open_contact_policies WHERE rowid IN (
      SELECT rowid FROM open_contact_policies WHERE retain_until<=? AND lease_id NOT IN
      (SELECT lease_id FROM open_contact_requests) ORDER BY retain_until LIMIT ?)`).run(now,GC_BATCH);
    this.db.prepare(`DELETE FROM open_contact_resource_leases WHERE rowid IN (
      SELECT rowid FROM open_contact_resource_leases WHERE retain_until<=? AND lease_id NOT IN
      (SELECT lease_id FROM open_contact_requests) AND lease_id NOT IN
      (SELECT lease_id FROM open_contact_policies) ORDER BY retain_until LIMIT ?)`).run(now,GC_BATCH);
  }
  gc():Obj{return this.tx(()=>({state:'collected'}));}
  /** Explicit local node-owner action, never available through the public RPC. */
  revokeLease(leaseId:string):Obj{return this.tx(()=>{
    this.db.prepare("UPDATE open_contact_resource_leases SET status='revoked' WHERE lease_id=?").run(leaseId);
    this.db.prepare("UPDATE open_contact_policies SET status='revoked' WHERE lease_id=?").run(leaseId);
    return {state:'revoked'};
  });}
  private open():void{if(!this.enabled)fail('contact_closed');}
  private lease(leaseId:string,now:number,active=true):Obj{
    const row=this.one('SELECT * FROM open_contact_resource_leases WHERE lease_id=?',leaseId);
    if(!row)fail('contact_lease_not_found');verifyLease(parsed(row.record),{node:this.node,now});
    if(active&&row.status!=='active')fail('contact_lease_revoked');return row;
  }
  private policy(owner:string,now:number):[Obj,Obj]{
    const row=this.one('SELECT * FROM open_contact_policies WHERE owner=?',owner);
    if(!row||row.status!=='active')fail('contact_unavailable');
    const lease=this.lease(row.lease_id,now),policy=parsed(row.record),resource=parsed(lease.record);
    verifyPolicy(policy,{lease:resource,node:this.node,now});return [policy,resource];
  }
  private request(signed:unknown,now:number):[Obj,Obj,Obj,Obj|undefined]{
    const original=verifyDocument(signed,'contact.request',{now}),[policy,lease]=this.policy(original.recipient_key_id,now);
    const raw=verifyRequest(signed,{policy,lease,node:this.node,now});
    const old=this.one('SELECT * FROM open_contact_requests WHERE sender=? AND request_id=?',raw.signing_key.key_id,raw.request_id);
    if(old&&old.digest!==documentSha256(signed as DocumentInput))fail('contact_request_conflict');return [raw,policy,lease,old];
  }
  private requestCapacity(raw:Obj,policy:Obj):void{
    if(this.one("SELECT 1 FROM open_contact_requests WHERE sender=? AND owner=? AND state='pending' AND expires_at>? LIMIT 1",
      raw.signing_key.key_id,raw.recipient_key_id,this.now()))fail('contact_pending_exists');
    const count=this.one('SELECT count(*) AS n FROM open_contact_requests WHERE lease_id=?',raw.lease_id)!.n;
    if(count>=policy.payload.max_pending)fail('contact_capacity');
  }
  private existingChallenge(request:Obj,purpose:string,now:number):Obj|null{
    const [raw,policy,_lease,old]=this.request(request,now);
    if(purpose==='submit'&&!old){this.open();this.requestCapacity(raw,policy);}
    else if(purpose==='result'&&!old)fail('contact_request_not_found');
    const row=this.one('SELECT * FROM open_contact_challenges WHERE sender=? AND request_id=? AND purpose=?',raw.signing_key.key_id,raw.request_id,purpose);
    if(row&&row.request_sha256!==documentSha256(request))fail('contact_request_conflict');
    if(row&&row.expires_at>now&&!row.used)return parsed(row.record);
    const usage=this.one('SELECT count(*) AS n,coalesce(sum(length(record)+256),0) AS bytes FROM open_contact_challenges')!;
    const subject=this.one('SELECT count(*) AS n FROM open_contact_challenges WHERE sender=?',raw.signing_key.key_id)!.n;
    const added=MAX_REQUEST_BYTES+256-(row?row.record.length+256:0);
    if(subject+(row?0:1)>MAX_SUBJECT_CHALLENGES||usage.n+(row?0:1)>this.maximum_challenges||usage.bytes+added>this.maximum_challenge_bytes)
      fail('contact_challenge_capacity');
    if(purpose==='submit'){
      const submissions=this.one("SELECT count(*) AS n,coalesce(sum(length(record)+256),0) AS bytes FROM open_contact_challenges WHERE purpose='submit'")!;
      const senderSubmissions=this.one("SELECT count(*) AS n FROM open_contact_challenges WHERE sender=? AND purpose='submit'",raw.signing_key.key_id)!.n;
      // At most 128 persisted rows: count retained/consumed submit challenges
      // against B without changing the already shared storage schema.
      const ownerCount=(this.db.prepare("SELECT record FROM open_contact_challenges WHERE purpose='submit' LIMIT 128").all() as Obj[])
        .filter(item=>parsed(item.record).payload.recipient_key_id===raw.recipient_key_id).length;
      if(senderSubmissions+(row?0:1)>Math.floor(MAX_SUBJECT_CHALLENGES*3/4)||
        ownerCount+(row?0:1)>Math.min(MAX_OWNER_SUBMIT_CHALLENGES,policy.payload.max_pending)||
        submissions.n+(row?0:1)>Math.floor(this.maximum_challenges*3/4)||submissions.bytes+added>Math.floor(this.maximum_challenge_bytes*3/4))
        fail('contact_challenge_capacity');
    }
    return null;
  }
  private challengeCapacity():void{
    const row=this.one('SELECT count(*) AS n,coalesce(sum(length(record)+256),0) AS bytes FROM open_contact_challenges')!;
    if(row.n>this.maximum_challenges||row.bytes>this.maximum_challenge_bytes)fail('contact_challenge_capacity');
    const submit=this.one("SELECT count(*) AS n,coalesce(sum(length(record)+256),0) AS bytes FROM open_contact_challenges WHERE purpose='submit'")!;
    if(submit.n>Math.floor(this.maximum_challenges*3/4)||submit.bytes>Math.floor(this.maximum_challenge_bytes*3/4))fail('contact_challenge_capacity');
  }
  private async challenge(rpc:unknown,checked:Obj):Promise<Obj>{
    const body=checked.body,existing=this.tx(now=>this.existingChallenge(body.request,body.purpose,now),rpc);
    if(existing)return {challenge:existing};
    if(challengeSlots[body.purpose]>=1)fail('contact_challenge_capacity');
    challengeSlots[body.purpose]++;let challenge:Obj,answerDigest:string;
    try{[challenge,answerDigest]=await issueChallenge(this.identity,{request:body.request,node:this.node,purpose:body.purpose,now:this.now()});}
    finally{challengeSlots[body.purpose]--;}
    return this.tx(now=>{
      const existing=this.existingChallenge(body.request,body.purpose,now);if(existing)return {challenge:existing};
      const raw=verifyChallenge(challenge,{request:body.request,node:this.node,purpose:body.purpose,now});
      this.db.prepare(`INSERT INTO open_contact_challenges VALUES(?,?,?,?,?,?,?,?,?,0)
        ON CONFLICT(sender,request_id,purpose) DO UPDATE SET request_sha256=excluded.request_sha256,
        record=excluded.record,digest=excluded.digest,answer_sha256=excluded.answer_sha256,
        expires_at=excluded.expires_at,retain_until=excluded.retain_until,used=0`).run(
        raw.subject_key_id,raw.request_id,raw.purpose,raw.request_sha256,canonicalBytes(challenge),documentSha256(challenge),answerDigest,
        raw.expires_at,raw.expires_at+RETENTION_SECONDS);
      this.challengeCapacity();return {challenge};
    },rpc);
  }
  private proof(body:Obj,purpose:string,now:number,replay=false):void{
    const challenge=verifyChallenge(body.challenge,{request:body.request,node:this.node,purpose,now});
    const row=this.one('SELECT * FROM open_contact_challenges WHERE sender=? AND request_id=? AND purpose=?',challenge.subject_key_id,challenge.request_id,purpose);
    const answer=sha256(decodeBase64url(body.answer,32,32));
    if(!row||row.digest!==documentSha256(body.challenge)||row.request_sha256!==documentSha256(body.request)||(row.used&&!replay)||
      row.answer_sha256.length!==answer.length||!timingSafeEqual(Buffer.from(row.answer_sha256),Buffer.from(answer)))fail('contact_invalid_proof');
    this.db.prepare('UPDATE open_contact_challenges SET used=1 WHERE sender=? AND request_id=? AND purpose=?').run(challenge.subject_key_id,challenge.request_id,purpose);
  }
  private allocate(rpc:Obj,now:number):Obj{
    this.open();const body=rpc.body,owner=rpc.signing_key.key_id,digest=documentSha256(body);
    const previous=this.one('SELECT * FROM open_contact_resource_leases WHERE owner=? AND allocation_id=?',owner,body.allocation_id);
    if(previous){if(previous.allocation_sha256!==digest)fail('contact_allocation_conflict');this.lease(previous.lease_id,now);return {lease:parsed(previous.record)};}
    if(body.purpose==='knock'&&this.one("SELECT 1 FROM open_contact_resource_leases WHERE owner=? AND purpose='knock' AND status='active' AND expires_at>? LIMIT 1",owner,now))fail('contact_knock_exists');
    const total=this.one('SELECT count(*) AS n FROM open_contact_resource_leases')!.n;
    const used=this.one('SELECT coalesce(sum(max_items),0) AS items,coalesce(sum(max_bytes),0) AS bytes FROM open_contact_resource_leases WHERE purpose=?',body.purpose)!;
    const [maximumItems,maximumBytes]=body.purpose==='knock'?[this.maximum_knock_items,this.maximum_knock_bytes]:[this.maximum_delivery_items,this.maximum_delivery_bytes];
    if(total>=this.maximum_leases||used.items+body.max_items>maximumItems||used.bytes+body.max_bytes>maximumBytes)fail('contact_capacity');
    const token=sha256(Buffer.from(this.identity.key_id+':'+this.node.payload.storage_epoch+':'+owner+':'+digest));
    const lease=signDocument(this.identity,'resource.lease',{issued_at:now,expires_at:now+body.lease_seconds,
      node_key_id:this.identity.key_id,storage_epoch:this.node.payload.storage_epoch,owner_key_id:owner,owner_encryption_key:body.encryption_key,
      lease_id:'lease_'+token,resource_id:'resource_'+token,purpose:body.purpose,max_items:body.max_items,max_bytes:body.max_bytes});
    this.db.prepare('INSERT INTO open_contact_resource_leases VALUES(?,?,?,?,?,?,?,?,?,?,?,NULL)').run(
      lease.payload.lease_id,owner,body.allocation_id,digest,body.purpose,canonicalBytes(lease),body.max_items,body.max_bytes,
      now+body.lease_seconds,now+body.lease_seconds+RETENTION_SECONDS,'active');
    return {lease};
  }
  private putPolicy(rpc:Obj,now:number):Obj|ContactError{
    const body=rpc.body,raw=verifyPolicy(body.policy,{lease:body.lease,node:this.node,now}),lease=this.lease(raw.lease_id,now,false);
    if(documentSha256(parsed(lease.record))!==documentSha256(body.lease))fail('contact_lease_mismatch');
    const owner=raw.signing_key.key_id,digest=documentSha256(body.policy),previous=this.one('SELECT * FROM open_contact_policies WHERE owner=?',owner);
    if(previous){
      if(previous.status==='conflict')fail('contact_policy_conflict');
      if(raw.revision<previous.revision)fail('contact_policy_rollback');
      if(raw.revision===previous.revision){
        if(previous.digest===digest){if(previous.status!==raw.status)fail('contact_lease_revoked');return {state:raw.status};}
        this.db.prepare("UPDATE open_contact_policies SET status='conflict',second_record=?,retain_until=max(retain_until,?) WHERE owner=?")
          .run(canonicalBytes(body.policy),lease.retain_until,owner);
        this.db.prepare("UPDATE open_contact_resource_leases SET status='revoked' WHERE lease_id=?").run(previous.lease_id);
        return new ContactError('contact_policy_conflict');
      }
    }
    if(raw.status==='active'){this.open();if(lease.status!=='active')fail('contact_lease_revoked');}
    if(raw.status==='revoked')this.db.prepare("UPDATE open_contact_resource_leases SET status='revoked' WHERE lease_id=?").run(raw.lease_id);
    this.db.prepare(`INSERT INTO open_contact_policies VALUES(?,?,?,?,?,NULL,?,?) ON CONFLICT(owner)
      DO UPDATE SET lease_id=excluded.lease_id,revision=excluded.revision,digest=excluded.digest,record=excluded.record,
      second_record=NULL,status=excluded.status,retain_until=max(retain_until,excluded.retain_until)`).run(
      owner,raw.lease_id,raw.revision,digest,canonicalBytes(body.policy),raw.status,lease.retain_until);
    return {state:raw.status};
  }
  private submit(rpc:Obj,now:number):Obj{
    const body=rpc.body,[raw,policy,_lease,old]=this.request(body.request,now);this.proof(body,'submit',now,Boolean(old));
    if(old)return {state:'contact_queued',request_sha256:old.digest};
    this.open();this.requestCapacity(raw,policy);const digest=documentSha256(body.request);
    this.db.prepare("INSERT INTO open_contact_requests VALUES(?,?,?,?,?,?,'pending',NULL,NULL,?,?)").run(
      raw.signing_key.key_id,raw.request_id,digest,raw.recipient_key_id,raw.lease_id,canonicalBytes(body.request),raw.expires_at,raw.expires_at+RETENTION_SECONDS);
    return {state:'contact_queued',request_sha256:digest};
  }
  private poll(rpc:Obj,now:number):Obj{
    const lease=this.lease(rpc.body.lease_id,now);
    if(lease.owner!==rpc.signing_key.key_id||lease.purpose!=='knock')fail('contact_wrong_subject');this.policy(lease.owner,now);
    const requests:Obj[]=[];let size=0;
    for(const row of this.db.prepare("SELECT record FROM open_contact_requests WHERE lease_id=? AND state='pending' AND expires_at>? ORDER BY request_id,sender LIMIT 4").all(lease.lease_id,now) as Obj[]){
      const record=parsed(row.record),amount=canonicalBytes(record).length;if(size+amount>16*1024)break;requests.push(record);size+=amount;
    }
    return {requests};
  }
  private decide(rpc:Obj,now:number):Obj{
    const body=rpc.body,[raw,policy,lease,old]=this.request(body.request,now);if(!old)fail('contact_request_not_found');
    const decision=verifyDecision(body.decision,{request:body.request,policy,lease,node:this.node,now}),digest=documentSha256(body.decision);
    if(old.decision!==null){if(old.decision_sha256!==digest)fail('contact_decision_conflict');return {state:'decided',request_sha256:old.digest};}
    if(decision.grant!==null){
      const grant=decision.grant.payload,delivery=this.lease(grant.resource_lease.payload.lease_id,now);
      if(delivery.purpose!=='delivery'||delivery.owner!==raw.recipient_key_id||documentSha256(parsed(delivery.record))!==documentSha256(grant.resource_lease)||delivery.grant_request!==null)
        fail('contact_delivery_unavailable');
      this.db.prepare('UPDATE open_contact_resource_leases SET grant_request=? WHERE lease_id=?').run(old.digest,delivery.lease_id);
    }
    this.db.prepare("UPDATE open_contact_requests SET state='decided',decision=?,decision_sha256=? WHERE sender=? AND request_id=?")
      .run(canonicalBytes(body.decision),digest,raw.signing_key.key_id,raw.request_id);
    return {state:'decided',request_sha256:old.digest};
  }
  private result(rpc:Obj,now:number):Obj{
    const body=rpc.body,[_raw,policy,lease,old]=this.request(body.request,now);if(!old)fail('contact_request_not_found');this.proof(body,'result',now);
    if(old.decision===null)return {state:'pending',decision:null};
    const signed=parsed(old.decision),decision=verifyDecision(signed,{request:body.request,policy,lease,node:this.node,now});
    if(decision.grant!==null){const delivery=this.lease(decision.grant.payload.resource_lease.payload.lease_id,now);
      if(delivery.grant_request!==old.digest)fail('contact_delivery_unavailable');}
    return {state:decision.decision,decision:signed};
  }
  async handle(rpc:unknown):Promise<Obj>{
    const signed=document(rpc as DocumentInput,65536),checked=verifyRpc(signed,{node:this.node,now:this.now()});
    if(checked.action==='challenge')return this.challenge(signed,checked);
    return this.tx(now=>{
      if(checked.action==='policy.get'){const [policy,lease]=this.policy(checked.body.recipient_key_id,now);return {policy,lease};}
      const actions:Record<string,(rpc:Obj,now:number)=>Obj|ContactError>={lease:this.allocate.bind(this),'policy.put':this.putPolicy.bind(this),
        submit:this.submit.bind(this),poll:this.poll.bind(this),decide:this.decide.bind(this),result:this.result.bind(this)};
      return actions[checked.action](checked,now);
    },signed);
  }
}
