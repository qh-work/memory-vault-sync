/** Explicitly return an actually saved inbox receipt. Shares the protected,
 * finite Python journal; a local historical retry is never a fresh network claim. */
import type {DatabaseSync} from 'node:sqlite';
import {OpenDeliveryClient} from './open-delivery-client.ts';
import {AckReceiptClient} from './open-repair-offer-client.ts';
import type {CommittedAckReceipt} from './open-repair-offer-client.ts';
import {RepairBudget,RepairError,buildNewWire,parseNewWire,objectFields,rawRef,u53,LocalRawResolver} from './open-repair-wire.ts';
import type {RawOriginal,RepairPolicy} from './open-repair-wire.ts';
import {parseOriginalControl,verifyOriginalControl} from './open-repair-original.ts';
import {verifyAckOfferBootstrapOriginal} from './open-repair-bound.ts';
import {verifyAckBindingOriginal} from './open-repair-empty.ts';
import {verifyAckOccupiedSourceEvent} from './open-repair-occupied.ts';
import type {AuthenticatedAckOccupiedSourceEvent} from './open-repair-occupied.ts';
import {signBoundedBootstrapOriginal} from './open-repair-probe.ts';
import {statusScope} from './open-repair-status.ts';
import {validateSigningIdentity,validateEncryptionIdentity} from './crypto.ts';
import {transaction} from './io.ts';
type Obj=Record<string,any>;
export const SAVED_ACK_REQUEST_FIELDS=['message_id','envelope_ref','ack_slot','owner','target','target_node_entry',
  'root_entry','write_entry','bootstrap_entry','binding_entry','current_statuses','read_until','retain_until'] as const;
const MAX_RECORDS=16,MAX_BYTES=1048576;
const key=(r:Obj)=>`${r.namespace}:${r.key}:${r.raw_sha256}:${r.size}`;
function fail(code:string):never{throw new RepairError(code);}
function equal(a:unknown,b:unknown):boolean{
  if(a===b)return true;if(!a||!b||typeof a!=='object'||typeof b!=='object'||Array.isArray(a)!==Array.isArray(b))return false;
  const names=Object.keys(a);return names.length===Object.keys(b).length&&names.every(n=>Object.hasOwn(b,n)&&equal((a as Obj)[n],(b as Obj)[n]));
}
function sameEntry(a:RawOriginal,b:RawOriginal):boolean{return equal(a.ref,b.ref)&&Buffer.from(a.raw).equals(Buffer.from(b.raw));}
export interface PublishedSavedAck{readonly source:AuthenticatedAckOccupiedSourceEvent;readonly originals:readonly RawOriginal[];readonly from_local_history:boolean;}
export class SavedAckReceiptPublisher{
  readonly #delivery:OpenDeliveryClient;readonly #client:AckReceiptClient;readonly #policy:RepairPolicy;
  constructor(delivery:OpenDeliveryClient,client:AckReceiptClient){
    if(!(delivery instanceof OpenDeliveryClient))fail('repair_saved_client_required');
    if(!equal(client.subject,{signing_key:validateSigningIdentity(delivery.participant.identity),encryption_key:validateEncryptionIdentity(delivery.encryption)}))fail('repair_saved_identity_mismatch');
    this.#delivery=delivery;this.#client=client;this.#policy=client.policy;
    this.#db(db=>transaction(db,()=>{
      db.exec(`CREATE TABLE IF NOT EXISTS open_repair_saved_ack_roots(root_digest TEXT PRIMARY KEY,revision INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS open_repair_saved_acks(slot_digest TEXT PRIMARY KEY,root_digest TEXT NOT NULL,
        request_digest TEXT NOT NULL,issued_at INTEGER NOT NULL,status_revision INTEGER NOT NULL,
        originals BLOB,result BLOB,attempted INTEGER NOT NULL DEFAULT 0);`);
      const columns=new Set((db.prepare('PRAGMA table_info(open_repair_saved_acks)').all() as Obj[]).map(r=>r.name));
      if(!columns.has('attempted')){db.exec('ALTER TABLE open_repair_saved_acks ADD COLUMN attempted INTEGER NOT NULL DEFAULT 0');
        db.exec('UPDATE open_repair_saved_acks SET attempted=1 WHERE originals IS NOT NULL AND result IS NULL');}
      for(const name of ['put_journal','put_response'])if(!columns.has(name))db.exec('ALTER TABLE open_repair_saved_acks ADD COLUMN '+name+' BLOB');
    }));
  }
  #db<T>(operation:(db:DatabaseSync)=>T):T{return this.#delivery.participant.contactStorage(operation);}
  #entry(value:unknown,budget:RepairBudget):RawOriginal{
    const e=objectFields(value,['raw','ref']),ref=rawRef(e.ref),raw=parseOriginalControl(e.raw,this.#policy,budget).raw;
    if(raw.length!==ref.size||budget.hash(raw)!==ref.raw_sha256)fail('repair_ref_mismatch');return {raw,ref};
  }
  #request(value:unknown,budget:RepairBudget):Obj{
    const v=objectFields(value,SAVED_ACK_REQUEST_FIELDS),scalars=SAVED_ACK_REQUEST_FIELDS.filter(n=>!n.endsWith('_entry')&&n!=='current_statuses');
    const r={...buildNewWire(Object.fromEntries(scalars.map(n=>[n,v[n]])),this.#policy,budget).value as Obj};
    for(const n of SAVED_ACK_REQUEST_FIELDS.filter(n=>n.endsWith('_entry')))r[n]=this.#entry(v[n],budget);
    if(!Array.isArray(v.current_statuses)||v.current_statuses.length<1||v.current_statuses.length>7)fail('repair_invalid_status');
    r.current_statuses=v.current_statuses.map((e:unknown)=>this.#entry(e,budget));return r;
  }
  #decodeEntries(raw:Uint8Array,budget:RepairBudget):Record<string,RawOriginal>{
    const v=objectFields(parseNewWire(raw,this.#policy,budget).value,['receipt','disclosure','put','status']);
    return Object.fromEntries(Object.entries(v).map(([name,item])=>{
      const e=objectFields(item,['raw','ref']);if(typeof e.raw!=='string')fail('repair_saved_corrupt');
      return [name,this.#entry({raw:Buffer.from(e.raw,'utf8'),ref:e.ref},budget)];
    }));
  }
  #archive(result:CommittedAckReceipt,budget:RepairBudget):Uint8Array{
    const originals=[...result.originals].sort((a,b)=>(a.ref.namespace<b.ref.namespace?-1:a.ref.namespace>b.ref.namespace?1:a.ref.key<b.ref.key?-1:a.ref.key>b.ref.key?1:0));
    const raw=buildNewWire({manifest_ref:result.source.commit.payload.historical_manifest_ref,commit_ref:result.source.commit.ref,
      originals:originals.map(e=>({ref:e.ref,raw_base64url:Buffer.from(e.raw).toString('base64url')}))},this.#policy,budget).raw;
    if(raw.length>MAX_BYTES)fail('repair_saved_capacity');return raw;
  }
  #restore(raw:Uint8Array,r:Obj,entries:Record<string,RawOriginal>,budget:RepairBudget):PublishedSavedAck{
    const value=objectFields(parseNewWire(raw,this.#policy,budget).value,['manifest_ref','commit_ref','originals']);
    if(!Array.isArray(value.originals)||value.originals.length<1||value.originals.length>128)fail('repair_saved_corrupt');
    const resolver=new LocalRawResolver(this.#policy,budget),originals=new Map<string,RawOriginal>();
    for(const item of value.originals){
      const encoded=objectFields(item,['ref','raw_base64url']),ref=rawRef(encoded.ref);
      if(typeof encoded.raw_base64url!=='string'||!/^[A-Za-z0-9_-]*$/.test(encoded.raw_base64url))fail('repair_saved_corrupt');
      budget.output(ref.size);const body=Buffer.from(encoded.raw_base64url,'base64url');
      if(body.toString('base64url')!==encoded.raw_base64url||body.length!==ref.size||budget.hash(body)!==ref.raw_sha256||originals.has(key(ref)))fail('repair_saved_corrupt');
      originals.set(key(ref),{raw:body,ref});if(!equal(resolver.put(ref.namespace,ref.key,body).ref,ref))fail('repair_saved_corrupt');
    }
    const manifest=originals.get(key(rawRef(value.manifest_ref))),commit=originals.get(key(rawRef(value.commit_ref)));
    if(!manifest||!commit)fail('repair_saved_corrupt');
    const node=r.target_node_entry,nodeValue=parseOriginalControl(node.raw,this.#policy,budget).value as Obj;
    const checked=verifyOriginalControl(node.raw,{expectedSigningKey:r.target.signing_key,expectedSchema:'memory-vault-open-control/v1',expectedKind:'node',
      at:nodeValue.payload.issued_at,policy:this.#policy,budget});
    const source=verifyAckOccupiedSourceEvent(manifest,resolver,commit,{expectedAckSlot:r.ack_slot,expectedOwner:r.owner,expectedReceiptWriter:this.#client.subject,
      expectedMessageId:r.message_id,expectedEnvelopeRef:r.envelope_ref,expectedTarget:r.target,targetStorageEpoch:checked.payload.storage_epoch as string,
      limitPolicy:this.#client.limits,policy:this.#policy,budget});
    if(['receipt','disclosure','put'].some(name=>!sameEntry(source.inputs[name as keyof typeof source.inputs],entries[name])))fail('repair_saved_corrupt');
    return Object.freeze({source,originals:Object.freeze([...originals.values()].map(e=>Object.freeze({ref:e.ref,get raw(){return Uint8Array.from(e.raw);}}))),from_local_history:true});
  }
  async publishSaved(baseUrl:string,value:unknown,timeout=30):Promise<PublishedSavedAck>{
    if(typeof timeout!=='number'||!Number.isFinite(timeout)||timeout<=0||timeout>60)fail('repair_invalid_deadline');
    const client=this.#client,policy=this.#policy,budget=new RepairBudget(policy),r=this.#request(value,budget);
    const receipt=this.#delivery.savedReceiptForAck(r.message_id,r.owner,r.envelope_ref),now=client.timestamp;
    const receiptPayload=(parseOriginalControl(receipt.raw,policy,budget).value as Obj).payload;
    const authorities=verifyAckOfferBootstrapOriginal(r.bootstrap_entry,{root:r.root_entry,write:r.write_entry},
      {expectedAckSlot:r.ack_slot,expectedOwner:r.owner,expectedReceiptWriter:client.subject,expectedMessageId:r.message_id,
        expectedEnvelopeRef:r.envelope_ref,at:now,limitPolicy:client.limits,policy,budget});
    const binding=verifyAckBindingOriginal(r.binding_entry,r.target,policy,budget),{root,write,bootstrap:grant}=authorities.originals;
    if(!equal(binding.payload.ack_slot,r.ack_slot)||!equal(binding.payload.root_authority_ref,root.ref)||!equal(binding.payload.grant_ref,write.ref)||
      binding.payload.bound_at>receiptPayload.saved_at||!(receiptPayload.saved_at<=now&&now<u53(r.read_until)&&r.read_until<=u53(r.retain_until))||
      r.read_until>root.payload.windows.read_until||r.retain_until>Math.min(binding.payload.retain_until as number,write.payload.windows.retain_until,root.payload.windows.retain_until))fail('repair_saved_tuple_mismatch');
    const hash=(v:unknown)=>budget.hash(buildNewWire(v,policy,budget).raw),rootDigest=hash(r.ack_slot.root_key),slotDigest=hash(r.ack_slot);
    const requestDigest=hash({slot:r.ack_slot,receipt:receipt.ref,...Object.fromEntries(['owner','target','read_until','retain_until'].map(n=>[n,r[n]])),
      ...Object.fromEntries(['root_entry','write_entry','bootstrap_entry','binding_entry'].map(n=>[n,r[n].ref]))});
    let saved=this.#db(db=>transaction(db,()=>{
      let row=db.prepare('SELECT * FROM open_repair_saved_acks WHERE slot_digest=?').get(slotDigest) as Obj|undefined;
      if(!row){
        if((db.prepare('SELECT count(*) AS n FROM open_repair_saved_acks').get() as Obj).n>=MAX_RECORDS)fail('repair_saved_capacity');
        const prior=db.prepare('SELECT revision FROM open_repair_saved_ack_roots WHERE root_digest=?').get(rootDigest) as Obj|undefined;
        const revision=u53((prior?.revision??0)+1,1);
        db.prepare('INSERT INTO open_repair_saved_ack_roots VALUES(?,?) ON CONFLICT(root_digest) DO UPDATE SET revision=excluded.revision').run(rootDigest,revision);
        db.prepare('INSERT INTO open_repair_saved_acks(slot_digest,root_digest,request_digest,issued_at,status_revision) VALUES(?,?,?,?,?)').run(slotDigest,rootDigest,requestDigest,now,revision);
        row=db.prepare('SELECT * FROM open_repair_saved_acks WHERE slot_digest=?').get(slotDigest) as Obj;
      }
      if(row.root_digest!==rootDigest||row.request_digest!==requestDigest)fail('repair_saved_retry_mismatch');return row;
    }));
    if(saved.originals===null){
      const issued=u53(saved.issued_at),retain=r.retain_until,read=r.read_until,expiry=Math.min(retain,write.payload.expires_at,grant.payload.upload_until,issued+300);
      if(expiry<=issued)fail('repair_access_expired');
      const sign=(payload:Obj)=>signBoundedBootstrapOriginal(payload,this.#delivery.participant.identity as unknown as Obj,policy,budget);
      const common={schema_version:'memory-vault-open-repair/v1',signing_key:client.subject.signing_key};
      const disclosure=sign({...common,kind:'ack.disclosure',issued_at:issued,expires_at:retain,consent_id:'consent_'+slotDigest,
        ack_slot:r.ack_slot,root_authority_ref:root.ref,grant_ref:write.ref,receipt_ref:receipt.ref,recipient:r.ack_slot.receipt_writer,
        owner:r.ack_slot.root_key.owner,allowed_roles:['ack.disclosure','ack.put','historical.status.ack_disclosure','recipient.receipt'],operation_mask:67,
        consent_until:retain,bootstrap_return:{subject:r.ack_slot.root_key.owner,consumer:'ack_owner',
          roles:['ack.disclosure','ack.put','authority.status.disclosure','recipient.receipt'],until:read},revision:1});
      const put=sign({...common,kind:'ack.put',issued_at:issued,expires_at:expiry,put_id:'put_'+slotDigest,ack_slot:r.ack_slot,
        grant_ref:write.ref,binding_ref:binding.ref,receipt_ref:receipt.ref,disclosure_ref:disclosure.ref,operation:'receipt.put'});
      const scope=statusScope(r.ack_slot.root_key,'authority',{authority_kind:'ack.disclosure',authority_sha256:disclosure.ref.raw_sha256},policy,budget);
      const status=sign({schema_version:'memory-vault-open-authority/v1',kind:'authority.status',signing_key:client.subject.signing_key,
        scope_key:{root_key:r.ack_slot.root_key,issuer_key_id:client.subject.signing_key.key_id},revision:saved.status_revision,
        issued_at:issued,valid_until:Math.min(retain,issued+3600),entries:[{scope_kind:'authority',scope_id:scope,minimum_document_revision:1,status:'active',operation_mask:67}]});
      const encoded=buildNewWire(Object.fromEntries(Object.entries({receipt,disclosure,put,status}).map(([name,e])=>[name,{raw:Buffer.from(e.raw).toString('utf8'),ref:e.ref}])),policy,budget).raw;
      if(encoded.length>65536)fail('repair_saved_capacity');
      saved=this.#db(db=>transaction(db,()=>{
        db.prepare('UPDATE open_repair_saved_acks SET originals=? WHERE slot_digest=? AND request_digest=? AND originals IS NULL').run(encoded,slotDigest,requestDigest);
        return db.prepare('SELECT * FROM open_repair_saved_acks WHERE slot_digest=?').get(slotDigest) as Obj;
      }));
    }
    const entries=this.#decodeEntries(saved.originals,budget);if(!sameEntry(entries.receipt,receipt))fail('repair_saved_corrupt');
    if(saved.result!==null)return this.#restore(saved.result,r,entries,budget);
    const pending=this.#db(db=>db.prepare('SELECT attempted,put_journal FROM open_repair_saved_acks WHERE slot_digest=? AND request_digest=?').get(slotDigest,requestDigest)) as Obj|undefined;
    if(!pending||(pending.attempted&&pending.put_journal===null))fail('repair_saved_reconciliation_required');
    const resume=pending.attempted?Buffer.from(pending.put_journal):null;
    const journal=(phase:'request'|'response',raw:Uint8Array)=>{
      if(!raw.length||raw.length>MAX_BYTES)fail('repair_saved_capacity');const column=phase==='request'?'put_journal':'put_response';
      this.#db(db=>transaction(db,()=>{
        const held=db.prepare('SELECT originals,put_journal,put_response,result FROM open_repair_saved_acks WHERE slot_digest=? AND request_digest=?').get(slotDigest,requestDigest) as Obj|undefined;
        if(!held||!Buffer.from(held.originals).equals(Buffer.from(saved.originals)))fail('repair_saved_corrupt');
        if(held[column]!==null&&!Buffer.from(held[column]).equals(Buffer.from(raw)))fail('repair_saved_retry_mismatch');
        if(phase==='response'&&held.put_journal===null)fail('repair_saved_corrupt');
        if(Object.entries(held).reduce((n,[name,v])=>n+(name!==column&&v!==null?(v as Uint8Array).length:0),0)+raw.length>MAX_BYTES)fail('repair_saved_capacity');
        db.prepare('UPDATE open_repair_saved_acks SET '+column+'=?,attempted=1 WHERE slot_digest=?').run(raw,slotDigest);
      }));
    };
    const options={currentStatuses:[...r.current_statuses,entries.status],readUntil:r.read_until,retainUntil:r.retain_until,
      targetNodeEntry:r.target_node_entry,expectedTarget:r.target,expectedAckSlot:r.ack_slot,expectedOwner:r.owner,expectedMessageId:r.message_id,
      expectedEnvelopeRef:r.envelope_ref,rootEntry:r.root_entry,writeEntry:r.write_entry,bootstrapEntry:r.bootstrap_entry,timeout,journal};
    const result=resume===null?await client.put(baseUrl,entries.receipt,entries.disclosure,entries.put,options):
      await client.resume(baseUrl,resume,entries.receipt,entries.disclosure,entries.put,options);
    const archive=this.#archive(result,budget);
    this.#db(db=>transaction(db,()=>{
      const current=db.prepare('SELECT originals,result,put_journal,put_response FROM open_repair_saved_acks WHERE slot_digest=? AND request_digest=?').get(slotDigest,requestDigest) as Obj|undefined;
      if(!current||!Buffer.from(current.originals).equals(Buffer.from(saved.originals)))fail('repair_saved_corrupt');
      if(current.result!==null&&!Buffer.from(current.result).equals(Buffer.from(archive)))fail('repair_saved_retry_mismatch');
      if(['originals','put_journal','put_response'].reduce((n,k)=>n+(current[k]?.length??0),0)+archive.length>MAX_BYTES)fail('repair_saved_capacity');
      db.prepare('UPDATE open_repair_saved_acks SET result=? WHERE slot_digest=?').run(archive,slotDigest);
    }));
    return Object.freeze({source:result.source,originals:result.originals,from_local_history:false});
  }
}
