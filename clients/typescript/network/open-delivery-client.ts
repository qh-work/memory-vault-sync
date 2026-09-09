/** Native open delivery over the existing participant, transport DB and Vault.
 * Original share bytes and author trust remain separate from network identity.
 */
import {randomBytes} from 'node:crypto';
import {performance} from 'node:perf_hooks';
import type {DatabaseSync} from 'node:sqlite';
import {canonicalBytes,document,objectFields,sha256,encodeBase64url,decodeBase64url,opaqueId,safeInteger,
  validateSigningIdentity,validateEncryptionIdentity,NetworkCryptoError} from './crypto.ts';
import type {DocumentInput,EncryptionIdentityDocument} from './crypto.ts';
import {NetworkError,transaction} from './io.ts';
import {CanonicalVault} from './vault.ts';
import {parseShare} from './records.ts';
import {readTrustedKeys} from './setup.ts';
import type {Client} from './client-config.ts';
import {CONTENT_SCHEMA,MAX_CONTENT_SHARE_BYTES,validateContent,contentText,contentChunk} from './content.ts';
import {coordinate,verifyNode} from './open-control.ts';
import type {SignedNode} from './open-control.ts';
import type {OpenParticipant} from './open-participant.ts';
import {LookupBudget} from './open-routing.ts';
import {OpenContactClient,LOCAL_RESERVATION} from './open-contact-client.ts';
import {verifyDecision,solveChallenge as solveContactChallenge} from './open-contact.ts';
import {signBlobRequest,verifyBlobResponse} from './open-blob.ts';
import {CHUNK_BYTES,originalDocument,envelopeRef,immutableRef,issueUploadIntent,verifyUploadIntent,
  signRpc,verifyRpc,verifyResponse,solveChallenge,readerIntent,issueRecipientReceipt,
  verifyRecipientReceipt,verifyStorageReceipt} from './open-delivery-control.ts';
import {createEnvelope,verifyEnvelope,decryptEnvelope,MAX_ENVELOPE_BYTES} from './open-delivery.ts';

type Obj=Record<string,any>;
const now=()=>Math.floor(Date.now()/1000);
const same=(a:unknown,b:unknown)=>Buffer.from(canonicalBytes(a)).equals(Buffer.from(canonicalBytes(b)));
const raw=(value:Uint8Array)=>Buffer.from(value);
const input=(value:unknown)=>value as DocumentInput;
function fail(code:string,retryable=false):never{throw new NetworkError(code,retryable);}
function errorData(error:unknown):Obj{return {code:(error as any)?.code??'network_storage_unavailable',retryable:(error as any)?.retryable===true};}
function preview(text:string):string{
  let chars=Array.from(text).slice(0,512);
  while(Buffer.byteLength(JSON.stringify(chars.join('')))>512)chars=chars.slice(0,Math.max(1,Math.floor(chars.length/2)));
  return chars.join('');
}
const MAX_LOCAL_BYTES=256*1024*1024,MAX_SESSION_BYTES=32768,MAX_INBOX_SESSION_BYTES=65536,
  MAX_INTENT_BYTES=49152,MAX_RESULT_BYTES=16384;
class DeliveryBudget{
  readonly deadline=performance.now()/1000+60;
  requests=0;requestBytes=0;responseBytes=0;
  check(){if(performance.now()/1000>=this.deadline||this.requests>256||this.requestBytes+this.responseBytes>64*1024*1024)fail('open_delivery_budget_exhausted',true);}
  request(bytes:number){this.check();if(this.requests>=256||this.requestBytes+this.responseBytes+bytes>64*1024*1024)fail('open_delivery_budget_exhausted',true);this.requests++;this.requestBytes+=bytes;}
  response(bytes:number){this.responseBytes+=bytes;this.check();}
  routing(){this.check();return new LookupBudget({maximum_seconds:Math.min(10,(this.deadline-performance.now()/1000))});}
  merge(child:LookupBudget){this.requests+=child.requests;this.requestBytes+=child.request_bytes;this.responseBytes+=child.response_bytes;this.check();}
}

export class OpenDeliveryClient{
  readonly participant:OpenParticipant;readonly encryption:EncryptionIdentityDocument;readonly clientConfig:Client;
  private readonly contact:OpenContactClient;
  private openedVault:CanonicalVault|null=null;
  private tail:Promise<unknown>=Promise.resolve();private closed=false;
  constructor(participant:OpenParticipant,encryption:EncryptionIdentityDocument,clientConfig:Client){
    this.participant=participant;this.encryption=encryption;this.clientConfig=clientConfig;
    const signer=validateSigningIdentity(participant.identity),recipient=validateEncryptionIdentity(encryption);
    this.contact=new OpenContactClient(participant,encryption);
    const binding=canonicalBytes({schema_version:'memory-vault-open-delivery-client-state/v1',signing_key_id:signer.key_id,
      encryption_key_id:recipient.key_id,client_config_path:clientConfig.path,vault_path:clientConfig.vault});
    this.db(db=>{
      db.exec(`CREATE TABLE IF NOT EXISTS open_delivery_client_state(key TEXT PRIMARY KEY,body BLOB NOT NULL);
        CREATE TABLE IF NOT EXISTS open_delivery_outbox(request_id TEXT PRIMARY KEY,message_id TEXT NOT NULL UNIQUE,
          input_sha256 TEXT NOT NULL,recipient TEXT NOT NULL,body BLOB NOT NULL,envelope BLOB,session BLOB,intent BLOB,
          result BLOB,acknowledgement BLOB,upload_offset INTEGER NOT NULL DEFAULT 0,created_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS open_delivery_inbox(message_id TEXT PRIMARY KEY,envelope_sha256 TEXT NOT NULL,
          sender TEXT NOT NULL,envelope BLOB NOT NULL,body BLOB NOT NULL,session BLOB NOT NULL,phase TEXT NOT NULL,
          result BLOB,receipt BLOB,receipt_sent INTEGER NOT NULL DEFAULT 0,created_at INTEGER NOT NULL);
        CREATE INDEX IF NOT EXISTS open_delivery_inbox_phase ON open_delivery_inbox(phase,created_at,message_id);`);
      const columns=new Set((db.prepare('PRAGMA table_info(open_delivery_outbox)').all() as Obj[]).map(row=>row.name));
      for(const name of ['intent','acknowledgement'])if(!columns.has(name))db.exec('ALTER TABLE open_delivery_outbox ADD COLUMN '+name+' BLOB');
      if(!(db.prepare('PRAGMA table_info(open_delivery_inbox)').all() as Obj[]).some(row=>row.name==='receipt_sent'))
        db.exec('ALTER TABLE open_delivery_inbox ADD COLUMN receipt_sent INTEGER NOT NULL DEFAULT 0');
      transaction(db,()=>{
        const previous=db.prepare("SELECT body FROM open_delivery_client_state WHERE key='binding'").get() as Obj|undefined;
        if(previous){if(!raw(previous.body).equals(raw(binding)))fail('open_delivery_state_binding_mismatch');}
        else{
          if(['open_delivery_outbox','open_delivery_inbox'].some(table=>db.prepare('SELECT 1 FROM '+table+' LIMIT 1').get()))fail('open_delivery_state_binding_missing');
          db.prepare("INSERT INTO open_delivery_client_state VALUES('binding',?)").run(binding);
        }
      });
    });
  }
  close():void{this.closed=true;this.openedVault?.close();this.openedVault=null;}
  private ready(){if(this.closed)fail('network_transport_closed');}
  private db<T>(operation:(db:DatabaseSync)=>T):T{this.ready();return this.participant.contactStorage(operation);}
  private serial<T>(operation:()=>Promise<T>):Promise<T>{const next=this.tail.then(()=>{this.ready();return operation();});this.tail=next.catch(()=>undefined);return next;}
  private get vault():CanonicalVault{
    this.ready();return this.openedVault??=new CanonicalVault({vaultPath:this.clientConfig.vault,identity:this.participant.identity,
      trust:()=>this.clientConfig.trust?readTrustedKeys(this.clientConfig.trust):[]});
  }
  private outbox(id:string):Obj|undefined{return this.db(db=>db.prepare('SELECT * FROM open_delivery_outbox WHERE request_id=?').get(id)) as Obj|undefined;}
  private inbox(id:string):Obj|undefined{return this.db(db=>db.prepare('SELECT * FROM open_delivery_inbox WHERE message_id=?').get(id)) as Obj|undefined;}
  private size(db:DatabaseSync,table:'open_delivery_outbox'|'open_delivery_inbox'):Obj{
    const expression=table==='open_delivery_outbox'?'length(body)+COALESCE(length(envelope),6291456)+COALESCE(length(session),32768)+COALESCE(length(intent),49152)+32768':'length(body)+length(envelope)+length(session)+32768';
    return db.prepare('SELECT count(*) AS count,COALESCE(sum('+expression+'),0) AS bytes FROM '+table).get() as Obj;
  }
  private prepareOutbox(requestId:string,recipient:string,inputHash:string,text:string,memoryIds:string[]):Obj{
    const prior=this.outbox(requestId);
    if(prior){if(prior.input_sha256!==inputHash||prior.recipient!==recipient)fail('network_request_id_conflict');return prior;}
    const body=memoryIds.length?canonicalBytes(validateContent({schema_version:CONTENT_SCHEMA,kind:'memory_transfer',note:text,
      share:encodeBase64url(this.vault.exportShare(memoryIds,{maximumBytes:MAX_CONTENT_SHARE_BYTES}))})):
      canonicalBytes(validateContent({schema_version:CONTENT_SCHEMA,kind:'message',text}));
    const messageId='msg_'+sha256(canonicalBytes(['memory-vault-open-delivery/v1',this.participant.keyId,requestId]));
    return this.db(db=>transaction(db,()=>{
      let row=db.prepare('SELECT * FROM open_delivery_outbox WHERE request_id=?').get(requestId) as Obj|undefined;
      if(!row){const size=this.size(db,'open_delivery_outbox');
        if(size.count>=1024||size.bytes+body.length+MAX_ENVELOPE_BYTES+MAX_SESSION_BYTES+MAX_INTENT_BYTES+2*MAX_RESULT_BYTES>MAX_LOCAL_BYTES)fail('network_outbox_capacity');
        db.prepare('INSERT INTO open_delivery_outbox(request_id,message_id,input_sha256,recipient,body,created_at) VALUES(?,?,?,?,?,?)').run(requestId,messageId,inputHash,recipient,body,now());
        row=db.prepare('SELECT * FROM open_delivery_outbox WHERE request_id=?').get(requestId) as Obj;
      }
      if(row.input_sha256!==inputHash||row.recipient!==recipient)fail('network_request_id_conflict');return row;
    }));
  }
  private static keys(session:Obj):Obj{
    if(session.intent)session=session.intent.payload.authority;
    const request=session.request.payload,policy=session.policy.payload;
    return {sender_signing_key:request.signing_key,sender_encryption_key:request.encryption_key,
      recipient_signing_key:policy.signing_key,recipient_encryption_key:policy.encryption_key};
  }
  private async encryptOutbox(row:Obj,session:Obj):Promise<Obj>{
    if(row.envelope){verifyEnvelope(row.envelope,OpenDeliveryClient.keys(document(row.session,MAX_SESSION_BYTES)) as any);return row;}
    const keys=OpenDeliveryClient.keys(session);
    const envelope=await createEnvelope(row.body,{signer:this.participant.identity,sender_encryption_key:validateEncryptionIdentity(this.encryption),
      recipient_signing_key:keys.recipient_signing_key,recipient_encryption_key:keys.recipient_encryption_key,
      message_id:row.message_id,object_key:randomBytes(32).toString('hex'),created_at:row.created_at});
    const encoded=canonicalBytes(envelope,MAX_ENVELOPE_BYTES),proof=canonicalBytes(document(session,MAX_SESSION_BYTES));
    if(encoded.length>session.decision.payload.grant.payload.resource_lease.payload.max_bytes)fail('open_delivery_approval_bytes_insufficient');
    return this.db(db=>transaction(db,()=>{
      const prior=db.prepare('SELECT * FROM open_delivery_outbox WHERE request_id=?').get(row.request_id) as Obj|undefined;
      if(!prior)fail('open_delivery_outbox_missing');
      if(!prior.envelope){const size=this.size(db,'open_delivery_outbox');
        if(size.bytes-MAX_ENVELOPE_BYTES-MAX_SESSION_BYTES+encoded.length+proof.length>MAX_LOCAL_BYTES)fail('network_outbox_capacity');
        db.prepare('UPDATE open_delivery_outbox SET envelope=?,session=? WHERE request_id=?').run(encoded,proof,row.request_id);
      }
      return db.prepare('SELECT * FROM open_delivery_outbox WHERE request_id=?').get(row.request_id) as Obj;
    }));
  }
  private contactSessions(outgoing:boolean,recipient?:string):Obj[]{
    const rows=this.db(db=>db.prepare(`SELECT a.reference,a.body,b.body AS decision FROM open_contact_local a
      JOIN open_contact_local b ON b.reference=a.reference AND b.category=? WHERE a.category=? AND a.expires_at>? AND b.expires_at>?
      ORDER BY a.expires_at DESC,a.reference LIMIT 128`).all(outgoing?'result':'decision',outgoing?'outgoing':'incoming',now(),now())) as Obj[];
    const sessions:Obj[]=[];
    for(const row of rows){const session=document(row.body,MAX_SESSION_BYTES) as Obj,decision=document(row.decision,24576).decision as Obj|undefined;
      if(!decision)continue;const original=session.request?.payload;if(!original)fail('open_delivery_invalid_session');
      if(outgoing){if(!same(original.signing_key,validateSigningIdentity(this.participant.identity))||!same(original.encryption_key,validateEncryptionIdentity(this.encryption))||recipient!==undefined&&original.recipient_key_id!==recipient)continue;}
      else if(original.recipient_key_id!==this.participant.keyId||original.recipient_encryption_key_id!==this.encryption.key_id)continue;
      if(decision.payload.decision==='approved')sessions.push({...session,decision});
    }return sessions;
  }
  private async sessionNode(session:Obj,budget:LookupBudget):Promise<SignedNode>{
    const old=session.node.payload;
    try{verifyNode(session.node);this.participant.acceptContactControl(session.node);return session.node;}
    catch(error){if(!(error instanceof NetworkCryptoError))throw error;}
    const route=await this.participant.lookupContactResource(coordinate(old.signing_key.key_id),budget);
    const candidates=this.participant.descriptor?[...route.candidates,this.participant.descriptor]:route.candidates;
    for(const node of candidates){const value=verifyNode(node);
      if(value.signing_key.key_id===old.signing_key.key_id&&value.storage_epoch===old.storage_epoch&&value.base_url===old.base_url)return node;}
    fail('contact_resource_unresolved',true);
  }
  private async checkedSession(session:Obj,budget:DeliveryBudget):Promise<Obj>{
    const child=budget.routing();let node:SignedNode;
    try{node=await this.sessionNode(session,child);}finally{budget.merge(child);}
    const checked=verifyDecision(session.decision,{request:session.request,policy:session.policy,lease:session.lease,node});
    if(checked.decision!=='approved'||!checked.grant)fail('open_contact_approval_required');return {...session,node};
  }
  private async sendingSession(recipient:string,budget:DeliveryBudget):Promise<Obj>{
    let sessions=this.contactSessions(true,recipient);
    if(!sessions.length){
      const rows=this.db(db=>db.prepare("SELECT body FROM open_contact_local WHERE category='outgoing' AND expires_at>? ORDER BY expires_at DESC,reference LIMIT 128").all(now())) as Obj[];
      for(const row of rows){const session=document(row.body,MAX_SESSION_BYTES) as Obj,request=session.request;
        if(!request||request.payload.recipient_key_id!==recipient)continue;const child=budget.routing();
        try{const node=await this.sessionNode(session,child),challenge=(await this.contact.call(node,'challenge',{request,purpose:'result'},child)).challenge;
          const answer=await solveContactChallenge(challenge,{request,node,purpose:'result',encryption_identity:this.encryption});
          const result=await this.contact.call(node,'result',{request,challenge,answer},child);
          if(result.decision){verifyDecision(result.decision,{request,policy:session.policy,lease:session.lease,node});
            const encoded=canonicalBytes({decision:result.decision});
            this.db(db=>transaction(db,()=>{const previous=db.prepare("SELECT body FROM open_contact_local WHERE category='result' AND reference=?").get(request.payload.request_id) as Obj|undefined;
              if(!previous)fail('contact_local_missing');
              if(!raw(previous.body).equals(raw(LOCAL_RESERVATION))&&!raw(previous.body).equals(raw(encoded)))fail('contact_local_conflict');
              db.prepare("UPDATE open_contact_local SET body=? WHERE category='result' AND reference=?").run(encoded,request.payload.request_id);
            }));
          }
        }finally{budget.merge(child);}break;
      }sessions=this.contactSessions(true,recipient);
    }
    for(const session of sessions){try{return await this.checkedSession(session,budget);}catch(error){if(!['contact_expired','contact_policy_mismatch'].includes((error as any)?.code))throw error;}}
    fail('open_contact_approval_required');
  }
  private uploadIntent(row:Obj,session:Obj):Obj{
    if(row.intent){const prior=document(row.intent,MAX_INTENT_BYTES) as Obj;if(prior.payload.expires_at>now())return prior;}
    const issued=now(),intent=issueUploadIntent(this.participant.identity,{operation_id:row.request_id,envelope_ref:envelopeRef(row.envelope),message_id:row.message_id,
      authority:Object.fromEntries(['request','policy','lease','decision'].map(name=>[name,session[name]])),issued_at:issued,expires_at:Math.min(issued+3600,session.decision.payload.expires_at)});
    verifyUploadIntent(intent,{node:session.node});const encoded=canonicalBytes(document(input(intent),MAX_INTENT_BYTES));
    return this.db(db=>transaction(db,()=>{const previous=db.prepare('SELECT intent FROM open_delivery_outbox WHERE request_id=?').get(row.request_id) as Obj|undefined;
      if(!previous)fail('open_delivery_outbox_missing');if(previous.intent){const value=document(previous.intent,MAX_INTENT_BYTES) as Obj;if(value.payload.expires_at>now())return value;}
      db.prepare('UPDATE open_delivery_outbox SET intent=? WHERE request_id=?').run(encoded,row.request_id);return intent;
    }));
  }
  private async call(node:SignedNode,action:string,body:Obj,budget:DeliveryBudget):Promise<Obj>{
    budget.check();this.participant.acceptContactControl(node);
    const request=signRpc(this.participant.identity,{node,action,body});verifyRpc(request,{node});budget.request(canonicalBytes(request).length);
    const reply=await this.participant.transport.request(node.payload.base_url,input(request),budget.deadline);
    budget.response(reply.wire_bytes);const checked=verifyResponse(reply.response,{request,node});this.participant.acceptContactControl(node);
    if(checked.body.error)throw new NetworkError(checked.body.error.code,checked.body.error.retryable);
    const expected:Record<string,string[]>={prepare:['challenge'],'list.prepare':['challenge'],'read.prepare':['challenge'],
      list:['state','messages','next_sequence','has_more'],'receipt.get':['state','receipt'],
      'receipt.put':['state','receipt_sha256'],commit:['state','storage_receipt','source_node']};
    if(action==='stored.get')objectFields(checked.body,checked.body.state==='absent'?['state']:['state','storage_receipt','source_node','intent']);
    else if(expected[action])objectFields(checked.body,expected[action]);
    this.participant.table.learnVerified(node,reply.observed_address);return checked.body;
  }
  private async answer(challenge:Obj,intent:Obj,node:SignedNode):Promise<string>{
    if(challenge.payload.context.subject_key_id!==this.participant.keyId)fail('open_delivery_challenge_mismatch');
    return solveChallenge(challenge,{encryption_identity:this.encryption,intent,node});
  }
  private handle(value:Obj,ref:Obj):Obj{
    const required=['state','handle_id','envelope_ref','durable_prefix','expires_at','chunk_size'];
    if(!value||typeof value!=='object'||required.some(k=>!Object.hasOwn(value,k))||Object.keys(value).some(k=>![...required,'intent','source_node','storage_receipt'].includes(k)))fail('open_delivery_invalid_response');
    opaqueId(value.handle_id);const prefix=safeInteger(value.durable_prefix),expiry=safeInteger(value.expires_at);
    if(!same(value.envelope_ref,ref)||value.chunk_size!==CHUNK_BYTES||typeof value.state!=='string'||prefix>ref.size||(prefix!==ref.size&&prefix%CHUNK_BYTES)||expiry<=now())fail('open_delivery_handle_mismatch');return value;
  }
  private async blob(node:SignedNode,action:'upload'|'download',handleId:string,ref:Obj,offset:number,length:number,chunk:Uint8Array,budget:DeliveryBudget):Promise<[Obj,Uint8Array]>{
    const header=signBlobRequest(this.participant.identity,{node,action:action+'.chunk' as 'upload.chunk'|'download.chunk',handle_id:handleId,ref,
      offset,length,...(action==='upload'?{chunk}: {})});
    budget.request(14+canonicalBytes(header).length+chunk.length);
    const reply=await this.participant.transport.requestBlob(node.payload.base_url,header,chunk,budget.deadline);budget.response(reply.wire_bytes);
    const checked=verifyBlobResponse(reply.header,{request:header,node}),body=checked.body;
    if(body.error){if(reply.chunk.length)fail('open_delivery_invalid_blob_response');throw new NetworkError(body.error.code,body.error.retryable);}
    if(action==='upload'){if(reply.chunk.length)fail('open_delivery_invalid_blob_response');}
    else if(reply.chunk.length!==length||sha256(reply.chunk)!==body.chunk_sha256)fail('open_delivery_blob_digest_mismatch');
    this.participant.acceptContactControl(node);this.participant.table.learnVerified(node,reply.observed_address);return [body,reply.chunk];
  }
  private async upload(row:Obj,node:SignedNode,handle:Obj,budget:DeliveryBudget){
    const bytes=raw(row.envelope),ref=envelopeRef(bytes),checked=this.handle(handle,ref);
    if(!['uploading','committed'].includes(checked.state))fail('open_delivery_handle_mismatch');let offset=checked.durable_prefix;
    while(offset<bytes.length){const chunk=bytes.subarray(offset,offset+CHUNK_BYTES),[result]=await this.blob(node,'upload',checked.handle_id,ref,offset,chunk.length,chunk,budget);
      const next=safeInteger(result.durable_prefix);if(next!==offset+chunk.length)fail('open_delivery_prefix_mismatch');offset=next;
      this.db(db=>db.prepare('UPDATE open_delivery_outbox SET upload_offset=? WHERE request_id=?').run(offset,row.request_id));}
  }
  private async download(node:SignedNode,handle:Obj,ref:Obj,budget:DeliveryBudget):Promise<Uint8Array>{
    const checked=this.handle(handle,ref);if(checked.state!=='reading')fail('open_delivery_handle_mismatch');const parts:Uint8Array[]=[];let offset=0;
    while(offset<ref.size){const length=Math.min(CHUNK_BYTES,ref.size-offset),[,chunk]=await this.blob(node,'download',checked.handle_id,ref,offset,length,new Uint8Array(),budget);parts.push(chunk);offset+=chunk.length;}
    const bytes=Buffer.concat(parts);if(sha256(bytes)!==ref.raw_sha256||!same(envelopeRef(bytes),ref))fail('open_delivery_envelope_mismatch');return bytes;
  }
  private saveSendResult(requestId:string,result:Obj){const encoded=canonicalBytes(document(result,MAX_RESULT_BYTES));
    this.db(db=>transaction(db,()=>{const old=db.prepare('SELECT result FROM open_delivery_outbox WHERE request_id=?').get(requestId) as Obj|undefined;
      if(!old)fail('open_delivery_outbox_missing');if(old.result&&!raw(old.result).equals(raw(encoded)))fail('open_delivery_result_conflict');
      db.prepare('UPDATE open_delivery_outbox SET result=? WHERE request_id=?').run(encoded,requestId);}));}
  async send(requestId:string,recipients:string[],text='',memoryIds:string[]=[],control?:DocumentInput):Promise<Obj>{
    opaqueId(requestId);
    if(!Array.isArray(recipients)||recipients.length!==1||typeof recipients[0]!=='string'||!/^ed25519_[0-9a-f]{64}$/.test(recipients[0])||typeof text!=='string'||Buffer.byteLength(text)>16384||control!=null)fail('open_delivery_invalid_send');
    if(!Array.isArray(memoryIds)||memoryIds.length>32||new Set(memoryIds).size!==memoryIds.length||memoryIds.some(id=>typeof id!=='string'||!/^mem_[0-9a-f]{40}$/.test(id)))fail('network_invalid_memory_selection');
    if(!text&&!memoryIds.length)fail('network_empty_message');
    const recipient=recipients[0],selected=[...memoryIds],hash=sha256(canonicalBytes({recipients:[recipient],text,memory_ids:selected}));
    return this.serial(()=>this.sendInternal(requestId,recipient,hash,text,selected));
  }
  private async sendInternal(requestId:string,recipient:string,hash:string,text:string,memoryIds:string[]):Promise<Obj>{
    let row=this.prepareOutbox(requestId,recipient,hash,text,memoryIds);const budget=new DeliveryBudget();let session:Obj;
    if(!row.session){session=await this.sendingSession(recipient,budget);row=await this.encryptOutbox(row,session);}
    session=document(row.session,MAX_SESSION_BYTES) as Obj;row=await this.encryptOutbox(row,session);
    let node:SignedNode|null=null,pendingCode:string|undefined;
    if(!row.result&&row.intent){const child=budget.routing();try{node=await this.sessionNode(session,child);}finally{budget.merge(child);}
      const stored=await this.call(node,'stored.get',{message_id:row.message_id,envelope_ref:envelopeRef(row.envelope)},budget);
      if(stored.state==='storage_accepted'){
        objectFields(stored,['state','storage_receipt','source_node','intent']);
        if(!same(stored.intent,document(row.intent,MAX_INTENT_BYTES)))fail('open_delivery_intent_mismatch');
        const recovered=verifyStorageReceipt(stored.storage_receipt,{node:stored.source_node,intent:stored.intent});
        if(recovered.stored_at>now()+30)fail('open_delivery_receipt_mismatch');
        this.saveSendResult(requestId,{state:stored.state,storage_receipt:stored.storage_receipt,source_node:stored.source_node});row=this.outbox(requestId)!;
      }else if(!same(stored,{state:'absent'}))fail('open_delivery_invalid_response');
    }
    if(!row.result){session=await this.checkedSession(session,budget);node=session.node;
      const intent=this.uploadIntent(row,session),prepared=await this.call(node!,'prepare',{intent},budget),challenge=prepared.challenge;
      const answer=await this.answer(challenge,intent,node!),handle=await this.call(node!,'start',{intent,challenge,answer},budget);
      await this.upload(row,node!,handle,budget);
      const result=await this.call(node!,'commit',{handle_id:handle.handle_id},budget);
      objectFields(result,['state','storage_receipt','source_node']);
      if(result.state!=='storage_accepted')fail('open_delivery_invalid_response');
      const receipt=verifyStorageReceipt(result.storage_receipt,{node:result.source_node,intent});if(receipt.stored_at>now()+30)fail('open_delivery_receipt_mismatch');
      this.saveSendResult(requestId,result);row=this.outbox(requestId)!;
    }else{
      const result=document(row.result,MAX_RESULT_BYTES) as Obj,intent=document(row.intent,MAX_INTENT_BYTES) as Obj;
      verifyStorageReceipt(result.storage_receipt,{node:result.source_node,intent});
      if(!row.acknowledgement){const child=budget.routing();try{node=await this.sessionNode(session,child);}catch(error){pendingCode=errorData(error).code;}finally{budget.merge(child);}}
    }
    let acknowledgement:Obj|null=row.acknowledgement?document(row.acknowledgement,4096) as Obj:null;
    if(!acknowledgement&&node){try{const result=await this.call(node,'receipt.get',{message_id:row.message_id},budget);
      objectFields(result,['state','receipt']);acknowledgement=result.receipt;if(result.state!==(acknowledgement===null?'pending':'validated_saved'))fail('open_delivery_invalid_response');
    }catch(error){pendingCode=errorData(error).code;}}
    if(acknowledgement){verifyRecipientReceipt(acknowledgement,{recipient_signing_key:OpenDeliveryClient.keys(session).recipient_signing_key,
      sender_key_id:this.participant.keyId,message_id:row.message_id,envelope_ref:envelopeRef(row.envelope)});
      const encoded=canonicalBytes(document(acknowledgement,4096));this.db(db=>transaction(db,()=>{const old=db.prepare('SELECT acknowledgement FROM open_delivery_outbox WHERE request_id=?').get(requestId) as Obj;
        if(old.acknowledgement&&!raw(old.acknowledgement).equals(raw(encoded)))fail('open_delivery_receipt_conflict');
        db.prepare('UPDATE open_delivery_outbox SET acknowledgement=? WHERE request_id=?').run(encoded,requestId);}));}
    return {state:acknowledgement?'validated_saved':'storage_accepted',request_id:requestId,message_id:row.message_id,
      content_kind:validateContent(row.body).kind,storage_accepted:true,endpoint_validated:!!acknowledgement,recipient_key_id:row.recipient,
      network_accessed:budget.requests>0,acknowledgement_pending:!acknowledgement,...(pendingCode?{pending_code:pendingCode}:{})};
  }
  private stageInbox(messageId:string,sender:string,envelope:Uint8Array,body:Uint8Array,session:Obj):Obj{
    originalDocument(envelope,{maximum:MAX_ENVELOPE_BYTES});const digest=sha256(envelope),content=validateContent(body);
    if(!['message','memory_transfer'].includes(content.kind))fail('open_delivery_invalid_content_kind');
    const proof=canonicalBytes(document(session,MAX_INBOX_SESSION_BYTES));
    return this.db(db=>transaction(db,()=>{const old=db.prepare('SELECT * FROM open_delivery_inbox WHERE message_id=?').get(messageId) as Obj|undefined;
      if(old){if(old.envelope_sha256!==digest||old.sender!==sender||!raw(old.body).equals(raw(body)))fail('network_inbox_identity_conflict');return old;}
      const size=this.size(db,'open_delivery_inbox');if(size.count>=4096||size.bytes+envelope.length+body.length+proof.length+2*MAX_RESULT_BYTES>MAX_LOCAL_BYTES)fail('network_inbox_capacity');
      db.prepare("INSERT INTO open_delivery_inbox(message_id,envelope_sha256,sender,envelope,body,session,phase,created_at) VALUES(?,?,?,?,?,?,'staged',?)").run(messageId,digest,sender,envelope,body,proof,now());
      return db.prepare('SELECT * FROM open_delivery_inbox WHERE message_id=?').get(messageId) as Obj;
    }));
  }
  private rejectInbox(messageId:string,code:string):Obj{return this.db(db=>transaction(db,()=>{
    const row=db.prepare('SELECT phase,result FROM open_delivery_inbox WHERE message_id=?').get(messageId) as Obj|undefined;
    if(!row)fail('network_message_not_found');if(['saved','rejected'].includes(row.phase))return document(row.result,MAX_RESULT_BYTES);
    const result={message_id:messageId,state:'rejected',code};db.prepare("UPDATE open_delivery_inbox SET phase='rejected',result=? WHERE message_id=?").run(canonicalBytes(result),messageId);return result;
  }));}
  private async finishInbox(messageId:string):Promise<Obj>{
    const row=this.inbox(messageId);if(!row)fail('network_message_not_found');if(['saved','rejected'].includes(row.phase))return document(row.result,MAX_RESULT_BYTES);
    const session=document(row.session,MAX_INBOX_SESSION_BYTES) as Obj;if(sha256(row.envelope)!==row.envelope_sha256)fail('network_inbox_identity_conflict');
    verifyStorageReceipt(session.storage_receipt,{node:session.source_node,intent:session.intent});const keys=OpenDeliveryClient.keys(session);
    if(!same(keys.recipient_signing_key,validateSigningIdentity(this.participant.identity)))fail('open_delivery_key_binding_mismatch');
    const reopened=await decryptEnvelope(row.envelope,{...keys,encryption_identity:this.encryption} as any);
    if(!raw(reopened).equals(raw(row.body)))fail('network_inbox_identity_conflict');const content=validateContent(row.body);let imported:Obj|null=null;
    if(content.kind==='memory_transfer'){
      const share=decodeBase64url(content.share,MAX_CONTENT_SHARE_BYTES);
      try{parseShare(share);}catch(error){if((error as any)?.retryable)throw error;return this.rejectInbox(messageId,'network_invalid_content_share');}
      // The durable inbox precedes the existing Vault transfer receipt. Crash
      // recovery repeats this original raw import with its built-in idempotency.
      try{imported=this.vault.importShare(share,{admission:'verified',maximumBytes:MAX_CONTENT_SHARE_BYTES});}
      catch(error){if(!['unknown_key','revoked_key','share_record_signature_required','share_independent_trust_required'].includes((error as any)?.code))throw error;
        imported=this.vault.importShare(share,{admission:'quarantined',maximumBytes:MAX_CONTENT_SHARE_BYTES});}
    }else if(content.kind!=='message')fail('open_delivery_invalid_content_kind');
    const text=contentText(content),part=preview(text),result={message_id:messageId,sender_key_id:row.sender,text:part,text_partial:part!==text,
      text_memory_id:null,content_kind:content.kind,share:imported?{state:imported.state,records_added:imported.records_added,admission:imported.admission??null}:null,
      state:'validated_saved',understood:false};
    const encoded=canonicalBytes(document(result,MAX_RESULT_BYTES));return this.db(db=>transaction(db,()=>{
      const prior=db.prepare('SELECT phase,result,envelope_sha256 FROM open_delivery_inbox WHERE message_id=?').get(messageId) as Obj|undefined;
      if(!prior||prior.envelope_sha256!==row.envelope_sha256)fail('network_inbox_identity_conflict');if(prior.phase==='saved')return document(prior.result,MAX_RESULT_BYTES);
      db.prepare("UPDATE open_delivery_inbox SET phase='saved',result=? WHERE message_id=?").run(encoded,messageId);return result;
    }));
  }
  private savedReceipt(messageId:string):Obj{
    const row=this.inbox(messageId);if(!row||row.phase!=='saved')fail('open_delivery_not_saved');if(row.receipt)return document(row.receipt,4096);
    const receipt=issueRecipientReceipt(this.participant.identity,{message_id:messageId,envelope_ref:envelopeRef(row.envelope),sender_key_id:row.sender});
    const encoded=canonicalBytes(document(input(receipt),4096));return this.db(db=>transaction(db,()=>{
      const old=db.prepare('SELECT phase,receipt FROM open_delivery_inbox WHERE message_id=?').get(messageId) as Obj|undefined;
      if(!old||old.phase!=='saved')fail('open_delivery_not_saved');if(old.receipt)return document(old.receipt,4096);
      db.prepare('UPDATE open_delivery_inbox SET receipt=? WHERE message_id=?').run(encoded,messageId);return receipt;
    }));
  }
  private async sendReceipt(messageId:string,budget:DeliveryBudget,node?:SignedNode){
    const row=this.inbox(messageId);if(!row||row.phase!=='saved')fail('open_delivery_not_saved');if(row.receipt_sent)return;
    const receipt=this.savedReceipt(messageId);verifyRecipientReceipt(receipt,{recipient_signing_key:validateSigningIdentity(this.participant.identity),
      sender_key_id:row.sender,message_id:messageId,envelope_ref:envelopeRef(row.envelope)});
    if(!node){const session=document(row.session,MAX_INBOX_SESSION_BYTES) as Obj,child=budget.routing();
      try{node=await this.sessionNode({node:session.source_node},child);}finally{budget.merge(child);}}
    const result=await this.call(node,'receipt.put',{message_id:messageId,receipt},budget);
    objectFields(result,['state','receipt_sha256']);
    if(result.state!=='receipt_stored'||result.receipt_sha256!==sha256(canonicalBytes(receipt)))fail('open_delivery_receipt_mismatch');
    this.db(db=>db.prepare('UPDATE open_delivery_inbox SET receipt_sent=1 WHERE message_id=? AND receipt=?').run(messageId,canonicalBytes(receipt)));
  }
  private cursor(session:Obj):[string,number]{const lease=session.decision.payload.grant.payload.resource_lease.payload,
    key='cursor_'+sha256(canonicalBytes([lease.node_key_id,lease.storage_epoch,lease.lease_id]));
    const value=this.db(db=>transaction(db,()=>{const row=db.prepare('SELECT body FROM open_delivery_client_state WHERE key=?').get(key) as Obj|undefined;
      if(row)return safeInteger(document(row.body,256).after_sequence);
      if((db.prepare('SELECT count(*) AS n FROM open_delivery_client_state').get() as Obj).n>=4097)fail('open_delivery_cursor_capacity');
      db.prepare('INSERT INTO open_delivery_client_state VALUES(?,?)').run(key,canonicalBytes({after_sequence:0}));return 0;
    }));return [key,value];
  }
  private advance(key:string,sequence:number){safeInteger(sequence,1);this.db(db=>transaction(db,()=>{
    const row=db.prepare('SELECT body FROM open_delivery_client_state WHERE key=?').get(key) as Obj|undefined;
    if(!row||safeInteger(document(row.body,256).after_sequence)<sequence)db.prepare('INSERT OR REPLACE INTO open_delivery_client_state VALUES(?,?)').run(key,canonicalBytes({after_sequence:sequence}));
  }));}
  private async receiveEntry(session:Obj,entry:Obj,budget:DeliveryBudget):Promise<[Obj,boolean]>{
    objectFields(entry,['message_id','envelope_ref','sequence']);opaqueId(entry.message_id);const ref=immutableRef(entry.envelope_ref);if(ref.namespace!=='object')fail('open_delivery_envelope_mismatch');
    const sequence=safeInteger(entry.sequence,1),prior=this.inbox(entry.message_id);
    if(prior){if(prior.envelope_sha256!==ref.raw_sha256)fail('network_inbox_identity_conflict');return [await this.finishInbox(entry.message_id),!['saved','rejected'].includes(prior.phase)];}
    const node=session.node,leaseId=session.decision.payload.grant.payload.resource_lease.payload.lease_id;
    const intent=readerIntent('read',{lease_id:leaseId,caller_key_id:this.participant.keyId,message_id:entry.message_id});
    const prepared=await this.call(node,'read.prepare',{lease_id:leaseId,message_id:entry.message_id},budget),challenge=prepared.challenge;
    const answer=await this.answer(challenge,intent,node),handle=await this.call(node,'read.start',{lease_id:leaseId,message_id:entry.message_id,challenge,answer},budget);
    this.handle(handle,ref);const original=handle.intent,authority=original.payload.authority;
    if(['request','policy','lease','decision'].some(name=>!same(authority[name],session[name])))fail('open_delivery_approval_mismatch');
    const stored=verifyStorageReceipt(handle.storage_receipt,{node:handle.source_node,intent:original});
    if(stored.message_id!==entry.message_id||!same(stored.envelope_ref,ref)||stored.sequence!==sequence||stored.stored_at>now()+30)fail('open_delivery_receipt_mismatch');
    const envelope=await this.download(node,handle,ref,budget),body=await decryptEnvelope(envelope,{...OpenDeliveryClient.keys(session),encryption_identity:this.encryption} as any);
    this.stageInbox(entry.message_id,session.request.payload.signing_key.key_id,envelope,body,
      {intent:original,storage_receipt:handle.storage_receipt,source_node:handle.source_node});return [await this.finishInbox(entry.message_id),true];
  }
  async receive(limit=4):Promise<Obj>{if(!Number.isSafeInteger(limit)||limit<1||limit>4)fail('network_invalid_receive_limit');return this.serial(()=>this.receiveInternal(limit));}
  private async receiveInternal(limit:number):Promise<Obj>{
    const budget=new DeliveryBudget(),messages:Obj[]=[],errors:Obj[]=[];
    const pending=this.db(db=>db.prepare("SELECT message_id,phase FROM open_delivery_inbox WHERE phase='staged' OR (phase='saved' AND receipt_sent=0) ORDER BY created_at,message_id LIMIT 4").all()) as Obj[];
    for(const row of pending){if(messages.length>=limit)break;try{const result=await this.finishInbox(row.message_id);if(row.phase==='staged')messages.push(result);
      if(result.state==='validated_saved')await this.sendReceipt(row.message_id,budget);}catch(error){errors.push({message_id:row.message_id,...errorData(error)});}}
    for(const candidate of this.contactSessions(false)){if(messages.length>=limit)break;
      try{const session=await this.checkedSession(candidate,budget),node=session.node,leaseId=session.decision.payload.grant.payload.resource_lease.payload.lease_id;
        let [key,after]=this.cursor(session);const intent=readerIntent('list',{lease_id:leaseId,caller_key_id:this.participant.keyId});
        const prepared=await this.call(node,'list.prepare',{lease_id:leaseId},budget),challenge=prepared.challenge,answer=await this.answer(challenge,intent,node);
        const listing=await this.call(node,'list',{lease_id:leaseId,challenge,answer,after_sequence:after,limit:limit-messages.length},budget);
        objectFields(listing,['state','messages','next_sequence','has_more']);
        if(listing.state!=='observed'||!Array.isArray(listing.messages)||listing.messages.length>limit-messages.length||typeof listing.has_more!=='boolean')fail('open_delivery_invalid_response');
        for(const entry of listing.messages){if(safeInteger(entry.sequence,1)<=after)fail('open_delivery_sequence_mismatch');
          const [result,fresh]=await this.receiveEntry(session,entry,budget);after=entry.sequence;this.advance(key,after);if(fresh)messages.push(result);
          if(result.state==='validated_saved')try{await this.sendReceipt(entry.message_id,budget,node);}catch(error){errors.push({message_id:entry.message_id,...errorData(error)});}}
        if(safeInteger(listing.next_sequence)!==after)fail('open_delivery_sequence_mismatch');
      }catch(error){errors.push(errorData(error));if(errors.length>=4)break;}}
    return {messages,errors:errors.slice(0,4),network_accessed:budget.requests>0};
  }
  readMessage(messageId:string,offset=0):Obj{
    opaqueId(messageId);if(!Number.isSafeInteger(offset)||offset<0)fail('network_invalid_message_offset');const row=this.inbox(messageId);
    if(!row||row.phase!=='saved')fail('network_message_not_found');const text=contentText(validateContent(row.body));
    return {...document(row.result,MAX_RESULT_BYTES),...contentChunk(text,offset),network_accessed:false};
  }
}
