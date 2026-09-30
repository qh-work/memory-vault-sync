/** Existing explicit mailbox registration and ordinary Agent receive polling. */
import {performance} from 'node:perf_hooks';
import {canonicalBytes,document,objectFields,sha256,opaqueId,validateSigningIdentity,validateEncryptionIdentity} from './crypto.ts';
import type {EncryptionIdentityDocument} from './crypto.ts';
import type {OpenParticipant} from './open-participant.ts';
import {OpenDeliveryClient} from './open-delivery-client.ts';
import {MailboxFeedRecoveryClient} from './open-mailbox-client.ts';
import {MailboxSetupJournal} from './open-mailbox-journal.ts';
import {RepairBudget,RepairError,parseNewWire,rawRef} from './open-repair-wire.ts';
import {DEFAULT_REPAIR_CLIENT_POLICY} from './open-repair-client.ts';
import {verifyMailboxFeedBootstrap} from './open-repair-mailbox-authority.ts';
import {verifySourceNodeOriginal} from './open-repair-original.ts';
import {endpoint} from './open-transport.ts';
import {transaction} from './io.ts';
type Obj=Record<string,any>;
export const MAILBOX_CONNECT_SCHEMA='memory-vault-open-mailbox-connect/v1';
function fail(code:string):never{throw new RepairError(code);}
function same(a:unknown,b:unknown):boolean{if(a===b)return true;if(!a||!b||typeof a!=='object'||typeof b!=='object'||Array.isArray(a)!==Array.isArray(b))return false;const keys=Object.keys(a);return keys.length===Object.keys(b).length&&keys.every(k=>Object.hasOwn(b,k)&&same((a as Obj)[k],(b as Obj)[k]));}
export class RegisteredMailboxReceivers{
  readonly #participant:OpenParticipant;readonly #encryption:EncryptionIdentityDocument;readonly #delivery:OpenDeliveryClient;
  constructor(participant:OpenParticipant,encryption:EncryptionIdentityDocument,delivery:OpenDeliveryClient){this.#participant=participant;this.#encryption=encryption;this.#delivery=delivery;
    participant.providerStorage(db=>db.exec('CREATE TABLE IF NOT EXISTS open_mailbox_receivers(receiver_id TEXT PRIMARY KEY,body BLOB NOT NULL,last_attempt INTEGER NOT NULL DEFAULT 0)'));}
  #decode(config:Obj):Obj{
    const entry=(v:unknown)=>{const e=objectFields(v,['raw','ref']);if(typeof e.raw!=='string')fail('open_invalid_mailbox_receiver');return {raw:Buffer.from(e.raw,'utf8'),ref:e.ref};};
    const slots=objectFields(config.slot_entries,['slot','read','maintenance','bootstrap']);
    return {expectedSlot:config.expected_slot,expectedSender:config.expected_sender,expectedTarget:config.expected_target,targetNodeEntry:entry(config.target_node_entry),slotEntries:Object.fromEntries(Object.entries(slots).map(([n,v])=>[n,entry(v)]))};
  }
  #validate(value:Obj):Obj{
    objectFields(value,['schema_version','action','base_url','limit_policy','expected_slot','expected_sender','expected_target','target_node_entry','slot_entries']);if(value.schema_version!==MAILBOX_CONNECT_SCHEMA||value.action!=='register')fail('open_invalid_mailbox_receiver');
    const options=this.#decode(value),policy={...DEFAULT_REPAIR_CLIENT_POLICY,max_signature_checks:512},budget=new RepairBudget(policy),at=Math.floor(Date.now()/1000),owner={signing_key:validateSigningIdentity(this.#participant.identity),encryption_key:validateEncryptionIdentity(this.#encryption)};
    const setup=verifyMailboxFeedBootstrap(options.slotEntries,{expectedSlot:value.expected_slot,expectedOwner:owner,expectedTarget:value.expected_target,targetStorageEpoch:value.expected_slot.writer_storage_epoch,limitPolicy:value.limit_policy,at,policy,budget});
    if(!same(setup.slot.payload.sender,{signing_key_id:value.expected_sender.signing_key.key_id,encryption_key_id:value.expected_sender.encryption_key.key_id}))fail('open_invalid_mailbox_receiver');
    const ref=rawRef(options.targetNodeEntry.ref),raw=parseNewWire(options.targetNodeEntry.raw,policy,budget).raw;
    if(ref.namespace!=='meta'||ref.size!==raw.length||budget.hash(raw)!==ref.raw_sha256)fail('open_invalid_mailbox_receiver');
    const node=verifySourceNodeOriginal(raw,{expectedSigningKey:value.expected_target.signing_key,expectedStorageEpoch:value.expected_slot.writer_storage_epoch,at,policy,budget});
    if(!same(endpoint(value.base_url,this.#participant.transport.allow_loopback),endpoint(node.payload.base_url,this.#participant.transport.allow_loopback)))fail('open_invalid_mailbox_receiver');return options;
  }
  connect(invitation:unknown):Obj{
    const value=document(invitation as any,65536) as Obj;if(value.schema_version!==MAILBOX_CONNECT_SCHEMA)fail('open_invalid_mailbox_receiver');
    if(value.action==='list'){objectFields(value,['schema_version','action']);const rows=this.#participant.providerStorage(db=>db.prepare('SELECT receiver_id FROM open_mailbox_receivers ORDER BY receiver_id LIMIT 17').all()) as Obj[];if(rows.length>16)fail('open_mailbox_receiver_capacity');return {state:'configured',mailboxes:rows.map(v=>v.receiver_id),network_accessed:false};}
    if(value.action==='remove'){objectFields(value,['schema_version','action','receiver_id']);opaqueId(value.receiver_id);this.#participant.providerStorage(db=>db.prepare('DELETE FROM open_mailbox_receivers WHERE receiver_id=?').run(value.receiver_id));return {state:'removed',receiver_id:value.receiver_id,network_accessed:false};}
    this.#validate(value);const receiver='mailbox_'+sha256(canonicalBytes(value.expected_slot)),raw=canonicalBytes(value);
    this.#participant.providerStorage(db=>transaction(db,()=>{const old=db.prepare('SELECT body FROM open_mailbox_receivers WHERE receiver_id=?').get(receiver) as Obj|undefined;
      if(old){if(!Buffer.from(old.body).equals(Buffer.from(raw)))fail('open_mailbox_receiver_conflict');return;}
      if((db.prepare('SELECT count(*) AS n FROM open_mailbox_receivers').get() as Obj).n>=16)fail('open_mailbox_receiver_capacity');db.prepare('INSERT INTO open_mailbox_receivers(receiver_id,body) VALUES(?,?)').run(receiver,raw);
    }));return {state:'registered',receiver_id:receiver,network_accessed:false,receipt_return:'separate_authority_required'};
  }
  async receive(limit:number):Promise<Obj>{
    const deadline=performance.now()/1000+60,result=await this.#delivery.receive(limit,{pendingOnly:true,deadline});
    const rows=this.#participant.providerStorage(db=>db.prepare('SELECT receiver_id,body FROM open_mailbox_receivers ORDER BY last_attempt,receiver_id LIMIT 17').all()) as Obj[];
    if(rows.length>16)fail('open_mailbox_receiver_capacity');
    for(const row of rows){let remaining=deadline-performance.now()/1000;if(result.messages.length>=limit||remaining<=0)break;
      this.#participant.providerStorage(db=>db.prepare('UPDATE open_mailbox_receivers SET last_attempt=? WHERE receiver_id=?').run(BigInt(Date.now())*1000000n,row.receiver_id));
      let reader:MailboxFeedRecoveryClient|undefined;
      try{
        const config=document(row.body,65536) as Obj;if(row.receiver_id!=='mailbox_'+sha256(canonicalBytes(config.expected_slot)))fail('open_invalid_mailbox_receiver');
        const options=this.#validate(config),journal=new MailboxSetupJournal(this.#participant);
        reader=new MailboxFeedRecoveryClient(this.#participant.identity,this.#encryption,{limitPolicy:config.limit_policy,allowLoopback:this.#participant.transport.allow_loopback,transport:this.#participant.transport,networkObserver:()=>{result.network_accessed=true;}});
        remaining=deadline-performance.now()/1000;if(remaining<=0)fail('repair_access_expired');const received=await this.#delivery.receiveMailbox(reader,config.base_url,{...options,journal,timeout:Math.min(60,remaining)} as any,limit-result.messages.length);
        result.messages.push(...received.messages);result.errors.push(...received.errors);
      }catch(error){result.errors.push({receiver_id:row.receiver_id,code:(error as any)?.code??'network_storage_unavailable',retryable:(error as any)?.retryable===true});}
      finally{reader?.close();}
    }
    if(result.messages.length<limit&&performance.now()/1000<deadline){const ordinary=await this.#delivery.receive(limit-result.messages.length,{skipPending:true,deadline});result.messages.push(...ordinary.messages);result.errors.push(...ordinary.errors);result.network_accessed ||=ordinary.network_accessed;}
    result.errors=result.errors.slice(0,4);return result;
  }
}
