/** Explicit retained receipt destinations and original-authority cold returns. */
import {performance} from 'node:perf_hooks';
import {canonicalBytes,document,objectFields,sha256,encodeBase64url,decodeBase64url} from './crypto.ts';
import type {EncryptionIdentityDocument} from './crypto.ts';
import {NetworkError,transaction} from './io.ts';
import type {OpenParticipant} from './open-participant.ts';
import type {OpenDeliveryClient} from './open-delivery-client.ts';
import {endpoint} from './open-transport.ts';
import type {OpenHTTPTransport} from './open-transport.ts';
import {coordinate,verifyNode} from './open-control.ts';
import {LookupBudget} from './open-routing.ts';
import {OpenProviderClient} from './open-provider-client.ts';
import {AckReceiptClient} from './open-repair-offer-client.ts';
import {SavedAckReceiptPublisher,SAVED_ACK_REQUEST_FIELDS} from './open-repair-receipt.ts';
import {ACK_CONNECT_SCHEMA,ACK_REPAIR_PROFILES} from './open-ack-client.ts';
import {OriginalAckStatusJournal} from './open-ack-status.ts';
type Obj=Record<string,any>;
const monotonic=()=>performance.now()/1000;
const FIELDS=['schema_version','action','message_id','source_url','source_key_id','repair_profile'];
const SCHEMA='memory-vault-open-saved-ack-request/v1',MAX_BUNDLE=1048576;
export const MAILBOX_RECEIPT_ACTIONS=new Set(['return_mailbox_receipt','register_mailbox_receipt_return','list_mailbox_receipt_returns','inspect_mailbox_receipt_return','remove_mailbox_receipt_return']);
function fail(code:string,retryable=false):never{throw new NetworkError(code,retryable);}
function message(v:unknown):string{if(typeof v!=='string'||!/^msg_[0-9a-f]{64}$/.test(v))fail('open_invalid_ack_request');return v;}
const equal=(a:unknown,b:unknown)=>Buffer.from(canonicalBytes(a)).equals(Buffer.from(canonicalBytes(b)));
function selection(v:unknown,participant:OpenParticipant,action:string):Obj{
  const r=objectFields(v,FIELDS);if(r.schema_version!==ACK_CONNECT_SCHEMA||r.action!==action)fail('open_invalid_ack_request');
  message(r.message_id);coordinate(r.source_key_id);
  if(typeof r.repair_profile!=='string'||!Object.hasOwn(ACK_REPAIR_PROFILES,r.repair_profile))fail('open_invalid_repair_policy');
  endpoint(r.source_url,participant.transport.allow_loopback);return {...r,source_url:r.source_url.replace(/\/$/,'')};
}
function decodedBundle(raw:Uint8Array,base:string,profile:string):Obj{
  const bundle=objectFields(document(raw,MAX_BUNDLE),['schema_version','base_url','repair_profile','request']);
  if(bundle.schema_version!==SCHEMA||bundle.base_url!==base||bundle.repair_profile!==profile)fail('open_ack_mailbox_return_corrupt');
  const r=objectFields(bundle.request,SAVED_ACK_REQUEST_FIELDS),decode=(v:unknown)=>{const e=objectFields(v,['ref','raw_base64url']);return {ref:e.ref,raw:decodeBase64url(e.raw_base64url,MAX_BUNDLE)};};
  if(!Array.isArray(r.current_statuses)||r.current_statuses.length>7)fail('open_ack_mailbox_return_corrupt');
  return Object.fromEntries(Object.entries(r).map(([n,v])=>[n,n==='current_statuses'?v.map(decode):n.endsWith('_entry')?decode(v):v]));
}
export async function returnMailboxReceipt(participant:OpenParticipant,encryption:EncryptionIdentityDocument,delivery:OpenDeliveryClient,value:unknown,
  options:{deadline?:number;networkObserver?:()=>void}={}):Promise<Obj>{
  objectFields(options,[...(Object.hasOwn(options,'deadline')?['deadline']:[]),...(Object.hasOwn(options,'networkObserver')?['networkObserver']:[])]);
  if((options.deadline!==undefined&&!Number.isFinite(options.deadline))||(options.networkObserver!==undefined&&typeof options.networkObserver!=='function'))fail('repair_invalid_deadline');
  const deadline=Math.min(monotonic()+60,options.deadline??Infinity),remaining=()=>{const n=deadline-monotonic();if(n<=0)fail('open_delivery_budget_exhausted',true);return Math.min(60,n);};
  remaining();
  const v=selection(document(value as any,4096),participant,'return_mailbox_receipt'),base=v.source_url;
  const saved=await delivery.savedMailboxForAck(v.message_id),roles=saved.roles,owner=saved.owner;
  const [root,write,bootstrap]=['ack.root_authority','ack.write_grant','bootstrap.ack_offer'].map(n=>roles[n]);
  const wp=document(write.raw,65536).payload as Obj,binding=sha256(canonicalBytes({message_id:v.message_id,envelope_ref:wp.envelope_ref,source_url:base,source_key_id:v.source_key_id,repair_profile:v.repair_profile,write_ref:write.ref}));
  participant.providerStorage(db=>db.exec('CREATE TABLE IF NOT EXISTS open_mailbox_ack_returns(message_id TEXT PRIMARY KEY,binding TEXT NOT NULL,request BLOB NOT NULL,request_sha256 TEXT NOT NULL)'));
  const held=participant.providerStorage(db=>db.prepare('SELECT * FROM open_mailbox_ack_returns WHERE message_id=?').get(v.message_id)) as Obj|undefined;
  const decodeHeld=(row:Obj)=>{if(row.binding!==binding)fail('open_ack_mailbox_return_conflict');if(row.request.length>MAX_BUNDLE||sha256(row.request)!==row.request_sha256)fail('open_ack_mailbox_return_corrupt');return decodedBundle(row.request,base,v.repair_profile);};
  const statuses=new OriginalAckStatusJournal(participant,wp.ack_slot.root_key),authorityHistory=()=>statuses.load(new Set([owner.signing_key.key_id,v.source_key_id]));
  let accessed=false;const observe=()=>{accessed=true;options.networkObserver?.();};
  const transport={requestRepair:async(url:string,raw:Uint8Array,until:number,o:unknown)=>{remaining();observe();return participant.transport.requestRepair(url,raw,Math.min(until,deadline),o as any);}} as OpenHTTPTransport;
  const reader=new AckReceiptClient(participant.identity,encryption,{transport,statusObserver:item=>statuses.observe(item),allowLoopback:participant.transport.allow_loopback,limitPolicy:ACK_REPAIR_PROFILES[v.repair_profile as keyof typeof ACK_REPAIR_PROFILES]});
  try{
    let request:Obj;
    if(held)request=decodeHeld(held);
    else{
      remaining();observe();const node=(await participant.transport.requestNode(base,Math.min(deadline,monotonic()+15))).response,p=verifyNode(node);
      if(p.status!=='active'||p.signing_key.key_id!==v.source_key_id||!equal(endpoint(p.base_url,participant.transport.allow_loopback),endpoint(base,participant.transport.allow_loopback)))fail('open_ack_mailbox_return_conflict');
      participant.acceptProviderControl(node);const targetRecord=await new OpenProviderClient(participant,encryption).proveTarget(node,new LookupBudget({maximum_seconds:Math.min(10,remaining())}));
      const target={signing_key:targetRecord.payload.signing_key,encryption_key:targetRecord.payload.targetEncryptionKey},raw=canonicalBytes(node),digest=sha256(raw),nodeEntry={raw,ref:{namespace:'meta',key:digest,raw_sha256:digest,size:raw.length}};
      const statuses=new Map<string,Obj>();for(const role of ['ack_root','ack_write','ack_offer_bootstrap']){const e=roles['historical.status.'+role];statuses.set(e.ref.raw_sha256,e);}
      remaining();const prepared=await reader.prepareReturn(base,{targetNodeEntry:nodeEntry,expectedTarget:target,expectedAckSlot:wp.ack_slot,expectedOwner:owner,expectedMessageId:v.message_id,expectedEnvelopeRef:wp.envelope_ref,rootEntry:root,writeEntry:write,bootstrapEntry:bootstrap,knownStatuses:[...statuses.values()],archiveStatuses:authorityHistory(),timeout:30});
      request={message_id:v.message_id,envelope_ref:wp.envelope_ref,ack_slot:wp.ack_slot,owner,target,target_node_entry:nodeEntry,root_entry:root,write_entry:write,bootstrap_entry:bootstrap,binding_entry:{ref:prepared.source.binding.ref,raw:prepared.source.binding.raw},current_statuses:prepared.current_statuses.map(e=>({ref:e.ref,raw:e.raw})),read_until:prepared.source.read_until,retain_until:prepared.source.retain_until};
      const encode=(e:Obj)=>({ref:e.ref,raw_base64url:encodeBase64url(e.raw)}),bundle=canonicalBytes({schema_version:SCHEMA,base_url:base,repair_profile:v.repair_profile,request:Object.fromEntries(Object.entries(request).map(([n,e])=>[n,n==='current_statuses'?e.map(encode):n.endsWith('_entry')?encode(e):e]))},MAX_BUNDLE);
      request=participant.providerStorage(db=>transaction(db,()=>{const old=db.prepare('SELECT * FROM open_mailbox_ack_returns WHERE message_id=?').get(v.message_id) as Obj|undefined;if(old)return decodeHeld(old);
        if((db.prepare('SELECT count(*) AS n FROM open_mailbox_ack_returns').get() as Obj).n>=16)fail('open_ack_mailbox_return_capacity');db.prepare('INSERT INTO open_mailbox_ack_returns VALUES(?,?,?,?)').run(v.message_id,binding,bundle,sha256(bundle));return request;
      }));
    }
    remaining();const result=await new SavedAckReceiptPublisher(delivery,reader).publishSaved(base,request,30,{archiveStatuses:authorityHistory(),knownDisclosureStatuses:statuses.load(new Set([participant.identity.key_id]))});
    return {state:'retained_at_ack_source',message_id:v.message_id,receipt_ref:result.source.inputs.receipt.ref,commit_ref:result.source.commit.ref,from_local_history:result.from_local_history,network_accessed:accessed};
  }finally{reader.close();}
}
export class MailboxReceiptJobs{
  readonly participant:OpenParticipant;readonly encryption:EncryptionIdentityDocument;readonly delivery:OpenDeliveryClient;
  constructor(participant:OpenParticipant,encryption:EncryptionIdentityDocument,delivery:OpenDeliveryClient){
    this.participant=participant;this.encryption=encryption;this.delivery=delivery;
    participant.providerStorage(db=>db.exec('CREATE TABLE IF NOT EXISTS open_mailbox_receipt_jobs(message_id TEXT PRIMARY KEY,body BLOB NOT NULL,body_sha256 TEXT NOT NULL,phase TEXT NOT NULL,result BLOB,result_sha256 TEXT,last_attempt INTEGER NOT NULL DEFAULT 0)'));
  }
  #body(row:Obj,name:string):Obj{const raw=row[name];if(!raw||sha256(raw)!==row[name+'_sha256'])fail('open_ack_mailbox_return_corrupt');return document(raw,8192) as Obj;}
  connect(value:unknown):Obj{
    const v=document(value as any,4096) as Obj;if(v.schema_version!==ACK_CONNECT_SCHEMA)fail('open_invalid_ack_request');
    if(v.action==='register_mailbox_receipt_return'){
      const body=selection(v,this.participant,v.action),raw=canonicalBytes(body,4096);
      this.participant.providerStorage(db=>transaction(db,()=>{const old=db.prepare('SELECT message_id,body,body_sha256,phase,result,result_sha256 FROM open_mailbox_receipt_jobs WHERE message_id=?').get(v.message_id) as Obj|undefined;
        if(old){if(!equal(this.#body(old,'body'),body))fail('open_ack_mailbox_return_conflict');return;}
        if((db.prepare('SELECT count(*) AS n FROM open_mailbox_receipt_jobs').get() as Obj).n>=16)fail('open_ack_mailbox_return_capacity');db.prepare("INSERT INTO open_mailbox_receipt_jobs(message_id,body,body_sha256,phase) VALUES(?,?,?,'pending')").run(v.message_id,raw,sha256(raw));
      }));return {state:'registered',message_id:v.message_id,network_accessed:false,receipt_return:'ordinary_receive_after_saved_original_authority_check'};
    }
    if(v.action==='list_mailbox_receipt_returns'){objectFields(v,['schema_version','action']);const rows=this.participant.providerStorage(db=>db.prepare('SELECT message_id,phase FROM open_mailbox_receipt_jobs ORDER BY message_id LIMIT 17').all()) as Obj[];
      if(rows.length>16)fail('open_ack_mailbox_return_capacity');return {state:'configured',returns:rows.map(r=>({message_id:r.message_id,state:r.phase})),network_accessed:false};}
    objectFields(v,['schema_version','action','message_id']);message(v.message_id);
    if(v.action==='remove_mailbox_receipt_return'){this.participant.providerStorage(db=>db.prepare('DELETE FROM open_mailbox_receipt_jobs WHERE message_id=?').run(v.message_id));return {state:'removed',message_id:v.message_id,network_accessed:false};}
    if(v.action!=='inspect_mailbox_receipt_return')fail('open_invalid_ack_request');
    const row=this.participant.providerStorage(db=>db.prepare('SELECT message_id,body,body_sha256,phase,result,result_sha256 FROM open_mailbox_receipt_jobs WHERE message_id=?').get(v.message_id)) as Obj|undefined;if(!row)fail('open_ack_mailbox_return_missing');
    return {state:row.phase,selection:this.#body(row,'body'),result:row.result===null?null:this.#body(row,'result'),network_accessed:false,source_rechecked:false};
  }
  async poll(result:Obj,deadline:number,attempted:Set<string>):Promise<void>{
    if(attempted.size>=2||monotonic()>=deadline)return;
    // Keep nanosecond scheduling timestamps in SQLite; they exceed JS safe integers.
    const rows=this.participant.providerStorage(db=>db.prepare("SELECT j.message_id,j.body,j.body_sha256,j.phase,j.result,j.result_sha256 FROM open_mailbox_receipt_jobs AS j JOIN open_delivery_inbox AS i ON i.message_id=j.message_id WHERE j.phase='pending' AND i.phase='saved' ORDER BY j.last_attempt,j.message_id LIMIT 3").all()) as Obj[];
    const row=rows.find(r=>!attempted.has(r.message_id));if(!row)return;const mid=row.message_id;attempted.add(mid);
    this.participant.providerStorage(db=>db.prepare('UPDATE open_mailbox_receipt_jobs SET last_attempt=? WHERE message_id=?').run(BigInt(Date.now())*1000000n,mid));
    const store=(phase:string,v:Obj)=>{const raw=canonicalBytes(v,8192);this.participant.providerStorage(db=>db.prepare('UPDATE open_mailbox_receipt_jobs SET phase=?,result=?,result_sha256=? WHERE message_id=? AND body_sha256=?').run(phase,raw,sha256(raw),mid,row.body_sha256));};
    try{
      const selected=selection(this.#body(row,'body'),this.participant,'register_mailbox_receipt_return');if(selected.message_id!==mid)fail('open_ack_mailbox_return_corrupt');
      const returned=await returnMailboxReceipt(this.participant,this.encryption,this.delivery,{...selected,action:'return_mailbox_receipt'},{deadline,networkObserver:()=>{result.network_accessed=true;}});
      store('complete',returned);(result.receipt_returns??=[]).push({message_id:mid,state:returned.state,from_local_history:returned.from_local_history});result.network_accessed ||=returned.network_accessed;
    }catch(error){const e=error as any,code=e?.code??'network_storage_unavailable',retryable=e?.retryable===true,phase=['repair_reconciliation_required','repair_saved_reconciliation_required'].includes(code)?'reconciliation_required':'pending';
      store(phase,{state:phase,code,retryable});result.errors.push({message_id:mid,operation:'return_mailbox_receipt',code,retryable});}
  }
}
