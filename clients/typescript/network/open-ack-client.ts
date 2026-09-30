/** Explicit native ACK recovery, sharing the protected Python journal and outbox. */
import {performance} from 'node:perf_hooks';
import {verifyNode} from './open-control.ts';
import {endpoint} from './open-transport.ts';
import {envelopeRef} from './open-delivery-control.ts';
import {OriginalAckStatusJournal} from './open-ack-status.ts';
import type {DatabaseSync} from 'node:sqlite';
import {canonicalBytes,document,objectFields,sha256,validateSigningIdentity,decodeBase64url} from './crypto.ts';
import {NetworkError,transaction} from './io.ts';
import {AckOwnerRecoveryClient,DEFAULT_REPAIR_CLIENT_LIMITS} from './open-repair-client.ts';
import type {AuthenticatedStatusOriginal} from './open-repair-status.ts';
import type {OpenParticipant} from './open-participant.ts';
import type {OpenDeliveryClient} from './open-delivery-client.ts';
import type {EncryptionIdentityDocument} from './crypto.ts';

type Obj=Record<string,any>;
export const ACK_CONNECT_SCHEMA='memory-vault-open-ack-connect/v1';
const PROFILES={receipt:{...DEFAULT_REPAIR_CLIENT_LIMITS,max_signature_checks:2048,max_proof_bytes:1048576},
  'receipt-index':{...DEFAULT_REPAIR_CLIENT_LIMITS,max_signature_checks:4096,max_proof_bytes:4194304,max_requests:128,max_replay_records:256}};
function fail(code:string):never{throw new NetworkError(code);}
function decode(value:unknown):Obj{
  const entry=objectFields(value,['raw','ref']);
  if(typeof entry.raw!=='string')fail('open_invalid_ack_request');
  return {raw:Buffer.from(entry.raw,'utf8'),ref:entry.ref};
}
class Journal{
  private readonly access:<T>(operation:(db:DatabaseSync)=>T)=>T;
  constructor(access:<T>(operation:(db:DatabaseSync)=>T)=>T){
    this.access=access;
    access(db=>transaction(db,()=>db.exec(`CREATE TABLE IF NOT EXISTS open_mailbox_setup_jobs(
      job_key TEXT PRIMARY KEY,plan BLOB NOT NULL,blocked INTEGER NOT NULL DEFAULT 0);
      CREATE TABLE IF NOT EXISTS open_mailbox_setup_steps(job_key TEXT NOT NULL,stage TEXT NOT NULL,
      request BLOB NOT NULL,response BLOB,PRIMARY KEY(job_key,stage));
      CREATE TABLE IF NOT EXISTS open_mailbox_setup_statuses(job_key TEXT NOT NULL,digest TEXT NOT NULL,
      raw BLOB NOT NULL,PRIMARY KEY(job_key,digest));`)));
  }
  private check(db:DatabaseSync,key:string):void{
    const row=db.prepare('SELECT blocked FROM open_mailbox_setup_jobs WHERE job_key=?').get(key) as Obj|undefined;
    if(!row||row.blocked)fail('repair_setup_journal_unavailable');
  }
  start(key:string,plan:Uint8Array):void{
    if(!/^[0-9a-f]{64}$/.test(key)||!plan.length||plan.length>65536)fail('repair_invalid_context');
    this.access(db=>transaction(db,()=>{
      const row=db.prepare('SELECT plan,blocked FROM open_mailbox_setup_jobs WHERE job_key=?').get(key) as Obj|undefined;
      if(row){if(!Buffer.from(row.plan).equals(Buffer.from(plan)))fail('repair_setup_journal_conflict');
        if(row.blocked)fail('repair_setup_journal_capacity');return;}
      if((db.prepare('SELECT count(*) AS n FROM open_mailbox_setup_jobs').get() as Obj).n>=16)fail('repair_setup_journal_capacity');
      db.prepare('INSERT INTO open_mailbox_setup_jobs(job_key,plan) VALUES(?,?)').run(key,plan);
    }));
  }
  prior(key:string,plan:Uint8Array):Obj[]{
    const exists=this.access(db=>db.prepare('SELECT 1 FROM open_mailbox_setup_jobs WHERE job_key=?').get(key));
    if(!exists)return [];this.start(key,plan);
    return this.access(db=>{
      this.check(db,key);
      const rows=db.prepare('SELECT digest,raw FROM open_mailbox_setup_statuses WHERE job_key=? ORDER BY digest').all(key) as Obj[];
      if(rows.length>32||rows.reduce((n,r)=>n+r.raw.length,0)>262144)fail('repair_setup_journal_capacity');
      return rows.map(row=>({raw:row.raw,ref:{namespace:'meta',key:row.digest,raw_sha256:row.digest,size:row.raw.length}}));
    });
  }
  observe(key:string,plan:Uint8Array,item:AuthenticatedStatusOriginal):void{
    this.start(key,plan);
    const saved=this.access(db=>transaction(db,()=>{
      this.check(db,key);
      if(db.prepare('SELECT 1 FROM open_mailbox_setup_statuses WHERE job_key=? AND digest=?').get(key,item.raw_sha256))return true;
      const size=db.prepare('SELECT count(*) AS n,coalesce(sum(length(raw)),0) AS bytes FROM open_mailbox_setup_statuses WHERE job_key=?').get(key) as Obj;
      if(size.n>=32||size.bytes+item.raw.length>262144){
        db.prepare('UPDATE open_mailbox_setup_jobs SET blocked=1 WHERE job_key=?').run(key);return false;}
      db.prepare('INSERT INTO open_mailbox_setup_statuses VALUES(?,?,?)').run(key,item.raw_sha256,item.raw);return true;
    }));
    if(!saved)fail('repair_setup_journal_capacity');
  }
}
export async function recoverReceipt(participant:OpenParticipant,encryption:EncryptionIdentityDocument,
  delivery:OpenDeliveryClient,invitation:unknown,deadline?:number):Promise<Obj>{
  const value=objectFields(document(invitation as any,65536),['schema_version','action','base_url','repair_profile','request']);
  if(value.schema_version!==ACK_CONNECT_SCHEMA||value.action!=='recover_receipt')fail('open_invalid_ack_request');
  if(typeof value.repair_profile!=='string'||!Object.hasOwn(PROFILES,value.repair_profile))fail('open_invalid_repair_policy');
  const names=['target_node_entry','expected_target','expected_ack_slot','root_entry','read_entry','bootstrap_entry',
    'expected_receipt_writer','expected_message_id','expected_envelope_ref'];
  const request=objectFields(value.request,[...names,...(Object.hasOwn(value.request??{},'known_statuses')?['known_statuses']:[])]) as Obj;
  const supplied=request.known_statuses??[];
  if(!Array.isArray(supplied)||supplied.length>16)fail('open_invalid_ack_request');
  const entries=Object.fromEntries(['target_node_entry','root_entry','read_entry','bootstrap_entry'].map(name=>[name,decode(request[name])]));
  const binding=Object.fromEntries(['expected_target','expected_ack_slot','expected_receipt_writer','expected_message_id','expected_envelope_ref'].map(name=>[name,request[name]]));
  const plan=canonicalBytes({kind:'ack.owner_recovery',owner:validateSigningIdentity(participant.identity),...binding,
    grants:Object.fromEntries(['root_entry','read_entry','bootstrap_entry'].map(name=>[name,entries[name].ref]))});
  const key=sha256(plan),journal=new Journal(operation=>participant.contactStorage(operation)),archive=journal.prior(key,plan);
  const roots=new OriginalAckStatusJournal(participant,request.expected_ack_slot.root_key);
  const issuers=new Set<string>([participant.identity.key_id,request.expected_target.signing_key.key_id,request.expected_receipt_writer.signing_key.key_id]);
  const retained=new Map<string,any>();
  for(const entry of [...roots.load(issuers),...archive])retained.set(Buffer.from(canonicalBytes(entry.ref)).toString('utf8'),entry);
  if(retained.size>32)fail('repair_status_history_capacity');
  const reader=new AckOwnerRecoveryClient(participant.identity,encryption,{limitPolicy:PROFILES[value.repair_profile as keyof typeof PROFILES],
    transport:participant.transport,allowLoopback:participant.transport.allow_loopback,statusObserver:item=>{journal.observe(key,plan,item);roots.observe(item);}});
  try{
    const timeout=deadline===undefined?30:Math.min(30,deadline-performance.now()/1000);
    if(timeout<=0)throw new NetworkError('open_delivery_budget_exhausted',true);
    const recovered=await reader.recoverOccupied(value.base_url as string,{targetNodeEntry:entries.target_node_entry,
      expectedTarget:request.expected_target,expectedAckSlot:request.expected_ack_slot,rootEntry:entries.root_entry,
      readEntry:entries.read_entry,bootstrapEntry:entries.bootstrap_entry,expectedReceiptWriter:request.expected_receipt_writer,
      expectedMessageId:request.expected_message_id,expectedEnvelopeRef:request.expected_envelope_ref,
      knownStatuses:supplied.map(decode),archiveStatuses:[...retained.values()],timeout});
    return {...delivery.acceptRecoveredReceipt(recovered.source.inputs.receipt.raw),commit_ref:recovered.source.commit.ref,network_accessed:true};
  }finally{reader.close();}
}

/** Read only an existing successful preparation; never mint or renew authority. */
export async function recoverPrepared(participant:OpenParticipant,encryption:EncryptionIdentityDocument,
  delivery:OpenDeliveryClient,row:Obj,operationDeadline:number):Promise<Obj>{
  const result:Obj={network_accessed:false};
  const held=participant.contactStorage(db=>{
    if(!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='open_ack_agent_preparations'").get())return undefined;
    return db.prepare('SELECT result,result_sha256 FROM open_ack_agent_preparations WHERE request_id=?').get(row.request_id) as Obj|undefined;
  });
  if(!held?.result)return result;
  try{
    if(held.result.length>1048576||sha256(held.result)!==held.result_sha256)fail('open_ack_preparation_corrupt');
    const prepared=document(held.result,1048576) as Obj,owner=prepared.owner_request,recipient=prepared.recipient_request;
    const encoded=(value:unknown)=>{
      const entry=objectFields(value,['raw_base64url','ref']);
      return {raw:new TextDecoder('utf-8',{fatal:true}).decode(decodeBase64url(entry.raw_base64url,524288)),ref:entry.ref};
    };
    const request:Obj={target_node_entry:encoded(owner.node),expected_target:owner.target,expected_ack_slot:owner.ack_slot,
      root_entry:encoded(owner.root),read_entry:encoded(owner.read),bootstrap_entry:encoded(owner.bootstrap),
      expected_receipt_writer:owner.receipt_writer,expected_message_id:owner.message_id,expected_envelope_ref:owner.envelope_ref,
      known_statuses:owner.known_statuses.map(encoded)};
    const same=(a:unknown,b:unknown)=>Buffer.from(canonicalBytes(a)).equals(Buffer.from(canonicalBytes(b)));
    if(request.expected_message_id!==row.message_id||!same(request.expected_envelope_ref,envelopeRef(row.envelope))||
      request.expected_receipt_writer.signing_key.key_id!==row.recipient)fail('open_ack_preparation_conflict');
    const old=(document(Buffer.from(request.target_node_entry.raw,'utf8')) as Obj).payload;
    const deadline=Math.min(operationDeadline,performance.now()/1000+20);
    if(deadline<=performance.now()/1000)throw new NetworkError('open_delivery_budget_exhausted',true);
    result.network_accessed=true;
    const current=(await participant.transport.requestNode(recipient.base_url,deadline)).response,node=verifyNode(current);
    if(node.status!=='active'||!same(node.signing_key,request.expected_target.signing_key)||node.storage_epoch!==old.storage_epoch||
      node.revision<old.revision||!same(endpoint(node.base_url,participant.transport.allow_loopback),endpoint(recipient.base_url,participant.transport.allow_loopback)))
      fail('open_ack_preparation_conflict');
    participant.acceptContactControl(current);
    const raw=canonicalBytes(current),digest=sha256(raw);
    request.target_node_entry={raw:Buffer.from(raw).toString('utf8'),ref:{namespace:'meta',key:digest,raw_sha256:digest,size:raw.length}};
    const recovered=await recoverReceipt(participant,encryption,delivery,{schema_version:ACK_CONNECT_SCHEMA,action:'recover_receipt',
      base_url:recipient.base_url,repair_profile:recipient.repair_profile,request},deadline);
    result.state=recovered.state;
  }catch(error){
    result.error={code:(error as any)?.code??'open_ack_preparation_corrupt',retryable:(error as any)?.retryable===true};
  }
  return result;
}
