/** Explicit native ACK recovery, sharing the protected Python journal and outbox. */
import type {DatabaseSync} from 'node:sqlite';
import {canonicalBytes,document,objectFields,sha256,validateSigningIdentity} from './crypto.ts';
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
  delivery:OpenDeliveryClient,invitation:unknown):Promise<Obj>{
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
  const reader=new AckOwnerRecoveryClient(participant.identity,encryption,{limitPolicy:PROFILES[value.repair_profile as keyof typeof PROFILES],
    transport:participant.transport,allowLoopback:participant.transport.allow_loopback,statusObserver:item=>journal.observe(key,plan,item)});
  try{
    const recovered=await reader.recoverOccupied(value.base_url as string,{targetNodeEntry:entries.target_node_entry,
      expectedTarget:request.expected_target,expectedAckSlot:request.expected_ack_slot,rootEntry:entries.root_entry,
      readEntry:entries.read_entry,bootstrapEntry:entries.bootstrap_entry,expectedReceiptWriter:request.expected_receipt_writer,
      expectedMessageId:request.expected_message_id,expectedEnvelopeRef:request.expected_envelope_ref,
      knownStatuses:supplied.map(decode),archiveStatuses:archive,timeout:30});
    return {...delivery.acceptRecoveredReceipt(recovered.source.inputs.receipt.raw),commit_ref:recovered.source.commit.ref,network_accessed:true};
  }finally{reader.close();}
}
