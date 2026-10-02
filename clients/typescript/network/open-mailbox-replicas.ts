/** Explicit finite replica placements, shared with Python's protected state.
 * No global membership, authority minting, or automatic unconsented movement. */
import {performance} from 'node:perf_hooks';
import {canonicalBytes,document,sha256,opaqueId,validateSigningIdentity,validateEncryptionIdentity,validateSigningPublic,validateEncryptionPublic,encodeBase64url} from './crypto.ts';
import type {EncryptionIdentityDocument} from './crypto.ts';
import type {OpenParticipant} from './open-participant.ts';
import {transaction} from './io.ts';
import {verifyNode} from './open-control.ts';
import {endpoint} from './open-transport.ts';
import {RepairBudget,parseNewWire} from './open-repair-wire.ts';
import {DEFAULT_REPAIR_CLIENT_POLICY} from './open-repair-client.ts';
import {verifySourceNodeOriginal} from './open-repair-original.ts';
import {statusScope} from './open-repair-status.ts';
import {verifyMailboxFeedBootstrap} from './open-repair-mailbox-authority.ts';
import {MailboxMessageReplicaRecoveryClient,MAILBOX_REPLICA_LIMITS,knownReplicaStatuses} from './open-mailbox-replica-client.ts';
import {ReplicaStatusJournal} from './open-ack-status.ts';
import {replicaFields as fields,replicaFail as fail,replicaSame as same,replicaEntry,replicaFloors} from './open-repair-mailbox-replica.ts';
import type {OpenDeliveryClient} from './open-delivery-client.ts';
type Obj=Record<string,any>;
const SCHEMA='memory-vault-open-mailbox-connect/v1',TABLE='open_mailbox_replica_receivers';
const REQUEST='expected_slot expected_sender expected_target expected_source source_storage_epoch expected_maintainer expected_envelope_ref target_node_entry slot_entries known_statuses archive_statuses'.split(' ');
const decode=(v:unknown)=>{const e=fields(v,['raw','ref']);if(typeof e.raw!=='string')fail('open_invalid_mailbox_receiver');return {raw:Buffer.from(e.raw,'utf8'),ref:e.ref};};
export class RegisteredMailboxReplicas{
  readonly #participant:OpenParticipant;readonly #encryption:EncryptionIdentityDocument;readonly #delivery:OpenDeliveryClient;
  constructor(participant:OpenParticipant,encryption:EncryptionIdentityDocument,delivery:OpenDeliveryClient){this.#participant=participant;this.#encryption=encryption;this.#delivery=delivery;
    participant.providerStorage(db=>db.exec(`CREATE TABLE IF NOT EXISTS ${TABLE}(receiver_id TEXT PRIMARY KEY,selection_digest TEXT NOT NULL,envelope_sha256 TEXT NOT NULL,body BLOB NOT NULL,body_sha256 TEXT NOT NULL,last_attempt INTEGER NOT NULL DEFAULT 0)`));}
  #checked(value:Obj,current=true):Obj{
    fields(value,['schema_version','action','base_url','repair_profile','request']);if(value.schema_version!==SCHEMA||value.action!=='register_replica'||value.repair_profile!=='mailbox')fail('open_invalid_mailbox_receiver');const request=fields(value.request,REQUEST);
    const policy=Object.freeze({...DEFAULT_REPAIR_CLIENT_POLICY,max_signature_checks:512}),budget=new RepairBudget(policy),at=Math.floor(Date.now()/1000),owner={signing_key:validateSigningIdentity(this.#participant.identity),encryption_key:validateEncryptionIdentity(this.#encryption)};
    const e={slot:request.expected_slot,sender:request.expected_sender,target:request.expected_target,source:request.expected_source,maintainer:request.expected_maintainer};
    for(const keys of [owner,e.sender,e.target,e.source,e.maintainer]){fields(keys,['signing_key','encryption_key']);validateSigningPublic(keys.signing_key);validateEncryptionPublic(keys.encryption_key);}
    if(same(e.target,e.source)||same(e.target,e.maintainer)||request.source_storage_epoch!==e.slot.writer_storage_epoch)fail('open_invalid_mailbox_receiver');
    fields(request.slot_entries,['slot','read','maintenance','bootstrap']);const slots=Object.fromEntries(Object.entries(request.slot_entries).map(([n,v])=>[n,decode(v)]));
    const setup=verifyMailboxFeedBootstrap(slots,{expectedSlot:e.slot,expectedOwner:owner,expectedTarget:e.source,targetStorageEpoch:request.source_storage_epoch,limitPolicy:MAILBOX_REPLICA_LIMITS,at,policy,budget});
    if(!same(setup.slot.payload.sender,{signing_key_id:e.sender.signing_key.key_id,encryption_key_id:e.sender.encryption_key.key_id})||!setup.maintenance.payload.maintainers.some((v:Obj)=>same(v,{signing_key_id:e.maintainer.signing_key.key_id,encryption_key_id:e.maintainer.encryption_key.key_id})))fail('open_invalid_mailbox_receiver');
    const envelope=request.expected_envelope_ref;if(envelope.namespace!=='object')fail('open_invalid_mailbox_receiver');const entry=replicaEntry(decode(request.target_node_entry),policy,budget),p=(parseNewWire(entry.raw,policy,budget).value as Obj).payload;
    const node=verifySourceNodeOriginal(entry.raw,{expectedSigningKey:e.target.signing_key,expectedStorageEpoch:p.storage_epoch,at:current?at:p.issued_at,policy,budget});if(!same(endpoint(value.base_url,this.#participant.transport.allow_loopback),endpoint(node.payload.base_url,this.#participant.transport.allow_loopback)))fail('open_invalid_mailbox_receiver');
    for(const [n,max] of [['known_statuses',16],['archive_statuses',32]] as const)if(!Array.isArray(request[n])||request[n].length>max)fail('repair_status_history_capacity');
    const journal=new ReplicaStatusJournal(this.#participant,e.slot.root_key),observe=(v:any)=>journal.observe(v);
    // The independent journal survives invalid later inputs and removals.
    const retained=journal.load(new Set([owner,e.sender,e.target,e.source,e.maintainer].map(v=>v.signing_key.key_id))),known=knownReplicaStatuses([...request.known_statuses.map(decode),...request.archive_statuses.map(decode),...retained],e,owner,at,policy,budget,observe);
    return {e,owner,setup,node,slots,journal,known,policy,budget,request};
  }
  async connect(value:Obj):Promise<Obj>{
    if(value.action==='list_replicas'){fields(value,['schema_version','action']);const rows=this.#participant.providerStorage(db=>db.prepare(`SELECT receiver_id FROM ${TABLE} ORDER BY receiver_id LIMIT 17`).all()) as Obj[];if(rows.length>16)fail('open_mailbox_receiver_capacity');return {state:'configured',replicas:rows.map(v=>v.receiver_id),network_accessed:false};}
    if(['remove_replica','inspect_replica'].includes(value.action)){
      fields(value,['schema_version','action','receiver_id',...(Object.hasOwn(value,'cursor')?['cursor']:[])]);opaqueId(value.receiver_id);
      if(value.action==='remove_replica'){this.#participant.providerStorage(db=>db.prepare(`DELETE FROM ${TABLE} WHERE receiver_id=?`).run(value.receiver_id));return {state:'removed',receiver_id:value.receiver_id,network_accessed:false};}
      const row=this.#participant.providerStorage(db=>db.prepare(`SELECT body,body_sha256 FROM ${TABLE} WHERE receiver_id=?`).get(value.receiver_id)) as Obj|undefined;if(!row)fail('open_mailbox_receiver_missing');if(sha256(row.body)!==row.body_sha256)fail('open_invalid_mailbox_receiver');
      let offset=0;if(value.cursor!=null){fields(value.cursor,['sha256','offset']);offset=value.cursor.offset;if(value.cursor.sha256!==row.body_sha256||!Number.isSafeInteger(offset)||offset<=0||offset>=row.body.length||offset%3072)fail('open_invalid_mailbox_cursor');}const stop=Math.min(offset+3072,row.body.length);
      return {state:'mailbox_replica_configuration',receiver_id:value.receiver_id,replica_configuration_sha256:row.body_sha256,total_bytes:row.body.length,offset,replica_configuration_chunk:Buffer.from(row.body.subarray(offset,stop)).toString('base64'),next_cursor:stop<row.body.length?{sha256:row.body_sha256,offset:stop}:null,network_accessed:false,source_rechecked:false,receipt_return:'separate_authority_required'};
    }
    if(value.action==='receive_replica')return this.receive({...value,action:'register_replica'},performance.now()/1000+60);
    const c=this.#checked(value),selection=sha256(canonicalBytes({slot:c.e.slot,sender:c.e.sender,envelope:c.request.expected_envelope_ref})),receiver='replica_'+sha256(canonicalBytes({selection,target:c.e.target,epoch:c.node.payload.storage_epoch})),raw=canonicalBytes(value,65536);
    this.#participant.providerStorage(db=>transaction(db,()=>{const old=db.prepare(`SELECT body FROM ${TABLE} WHERE receiver_id=?`).get(receiver) as Obj|undefined;if(old){if(!Buffer.from(old.body).equals(Buffer.from(raw)))fail('open_mailbox_receiver_conflict');return;}
      if((db.prepare(`SELECT count(*) AS n FROM ${TABLE}`).get() as Obj).n>=16||(db.prepare(`SELECT count(*) AS n FROM ${TABLE} WHERE envelope_sha256=?`).get(c.request.expected_envelope_ref.raw_sha256) as Obj).n>=2)fail('open_mailbox_receiver_capacity');
      db.prepare(`INSERT INTO ${TABLE}(receiver_id,selection_digest,envelope_sha256,body,body_sha256) VALUES(?,?,?,?,?)`).run(receiver,selection,c.request.expected_envelope_ref.raw_sha256,raw,sha256(raw));}));
    return {state:'registered',receiver_id:receiver,network_accessed:false,recovery:'ordinary_receive',receipt_return:'separate_authority_required'};
  }
  async receive(value:Obj,deadline:number,accessed?:()=>void):Promise<Obj>{
    const c=this.#checked(value,false),{e,owner,setup,journal,known,policy,budget}=c;
    const needs=['slot','read','maintenance','bootstrap'].map(n=>({signer:owner.signing_key,scope_kind:n==='slot'?'mailbox_slot':'authority',scope_id:statusScope(e.slot.root_key,n==='slot'?'mailbox_slot':'authority',n==='slot'?e.slot:{authority_kind:setup[n].payload.kind,authority_sha256:setup[n].ref.raw_sha256},policy,budget),revision:setup[n].payload.revision,mask:n==='read'?2:10}));replicaFloors(known,[],needs);
    const saved=this.#participant.providerStorage(db=>db.prepare("SELECT 1 FROM open_delivery_inbox WHERE envelope_sha256=? AND phase!='staged'").get(c.request.expected_envelope_ref.raw_sha256));if(saved)return {messages:[],errors:[],state:'observed',network_accessed:false,body_transport:'mailbox_message_replica'};
    accessed?.();const introduction=(await this.#participant.transport.requestNode(value.base_url,deadline)).response,node=verifyNode(introduction);
    if(node.status!=='active'||!same(node.signing_key,e.target.signing_key)||node.storage_epoch!==c.node.payload.storage_epoch||node.revision<c.node.payload.revision||!same(endpoint(node.base_url,this.#participant.transport.allow_loopback),endpoint(value.base_url,this.#participant.transport.allow_loopback)))fail('open_invalid_mailbox_receiver');
    const raw=canonicalBytes(introduction),digest=sha256(raw),reader=new MailboxMessageReplicaRecoveryClient(this.#participant.identity,this.#encryption,{transport:this.#participant.transport,allowLoopback:this.#participant.transport.allow_loopback,networkObserver:accessed});
    const remaining=deadline-performance.now()/1000;if(remaining<=0)fail('repair_access_expired');return this.#delivery.receiveMailboxReplica(reader,value.base_url,{expectedSlot:e.slot,expectedSender:e.sender,expectedTarget:e.target,expectedSource:e.source,sourceStorageEpoch:c.request.source_storage_epoch,expectedMaintainer:e.maintainer,expectedEnvelopeRef:c.request.expected_envelope_ref,targetNodeEntry:{raw,ref:{namespace:'meta',key:digest,raw_sha256:digest,size:raw.length}},slotEntries:c.slots,journal,knownStatuses:c.request.known_statuses.map(decode),archiveStatuses:c.request.archive_statuses.map(decode),timeout:Math.min(60,remaining)});
  }
}
