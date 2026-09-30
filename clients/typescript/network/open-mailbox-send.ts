/** Sender-owned frozen mailbox drafts and actual remote admission. */
import {performance} from 'node:perf_hooks';
import {deflateSync} from 'node:zlib';
import {canonicalBytes,document,sha256,opaqueId,encodeBase64url,decodeBase64url,validateSigningIdentity,validateEncryptionIdentity} from './crypto.ts';
import type {EncryptionIdentityDocument} from './crypto.ts';
import type {OpenParticipant} from './open-participant.ts';
import {transaction} from './io.ts';
import {RepairBudget,RepairError,buildNewWire,parseNewWire,objectFields,rawRef,u53} from './open-repair-wire.ts';
import {DEFAULT_REPAIR_CLIENT_POLICY} from './open-repair-client.ts';
import {originalPublicDescriptor,verifyContactOriginals,verifyBoundedControlSignature,verifySourceNodeOriginal} from './open-repair-original.ts';
import {signBoundedBootstrapOriginal} from './open-repair-probe.ts';
import {verifyMailboxAckConfiguration} from './open-repair-mailbox-member.ts';
import {verifyEnvelope} from './open-delivery.ts';
import {statusScope} from './open-repair-status.ts';
import {issueStatus} from './open-provider.ts';
import {endpoint} from './open-transport.ts';
type Obj=Record<string,any>;
const SCHEMA='memory-vault-open-mailbox-connect/v1',REPAIR='memory-vault-open-repair/v1';
export const MAILBOX_SEND_ACTIONS=new Set(['prepare','admit','retain']);
const SLOT_FIELDS={
  slot:'issued_at expires_at revision slot_key feed_ref sender recipient data_resource_ref data_resource_offer_ref metadata_resource_ref metadata_resource_offer_ref read_grant_ref maintenance_root_ref max_appends max_live_items budget windows',
  read:'issued_at expires_at grant_id root_key slot_key reader serving_authority_id operation_mask budget windows revision',
  maintenance:'issued_at expires_at root_key authority_id slot_key sender recipient maintainers operation_mask allowed_roles budget windows max_delegate_depth max_destinations_per_job max_concurrent_jobs revision'};
const ACK_ROLES=['ack.root_authority','ack.write_grant','bootstrap.ack_offer','historical.status.ack_root','historical.status.ack_write','historical.status.ack_offer_bootstrap'];
function fail(code:string):never{throw new RepairError(code);}
function same(a:unknown,b:unknown):boolean{return Buffer.from(canonicalBytes(a)).equals(Buffer.from(canonicalBytes(b)));}
/** Shares Python's original-byte journals. Network retries never renew a grant. */
export class MailboxSender{
  readonly #participant:OpenParticipant;readonly #encryption:EncryptionIdentityDocument;
  readonly #policy={...DEFAULT_REPAIR_CLIENT_POLICY,max_signature_checks:512};
  constructor(participant:OpenParticipant,encryption:EncryptionIdentityDocument){this.#participant=participant;this.#encryption=encryption;}
  #entry(value:unknown,budget:RepairBudget):Obj{
    const e=objectFields(value,['raw','ref']);if(typeof e.raw!=='string')fail('open_invalid_mailbox_request');
    return this.#checked(Buffer.from(e.raw,'utf8'),e.ref,budget);
  }
  #checked(raw:Uint8Array,reference:unknown,budget:RepairBudget):Obj{
    const ref=rawRef(reference);if(raw.length>524288||raw.length!==ref.size||budget.hash(raw)!==ref.raw_sha256)fail('repair_ref_mismatch');return {raw,ref};
  }
  #decode(value:unknown,budget:RepairBudget):Obj{const e=objectFields(value,['ref','raw_base64url']);return this.#checked(decodeBase64url(e.raw_base64url,524288),e.ref,budget);}
  #encode(e:Obj):Obj{return {ref:e.ref,raw_base64url:encodeBase64url(e.raw)};}
  #raw(raw:Uint8Array,budget:RepairBudget):Obj{const digest=budget.hash(raw);return {raw,ref:{namespace:'meta',key:digest,raw_sha256:digest,size:raw.length}};}
  #dual(value:Obj,budget:RepairBudget):Obj{objectFields(value,['signing_key','encryption_key']);originalPublicDescriptor(value.signing_key,budget);originalPublicDescriptor(value.encryption_key,budget,true);return {signing_key_id:value.signing_key.key_id,encryption_key_id:value.encryption_key.key_id};}
  #ack(requestId:string,messageId:string,budget:RepairBudget):Obj{
    opaqueId(requestId);const row=this.#participant.providerStorage(db=>{
      if(!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='open_ack_agent_preparations'").get())return undefined;
      return db.prepare('SELECT result,result_sha256 FROM open_ack_agent_preparations WHERE request_id=?').get(requestId);
    }) as Obj|undefined;
    if(!row?.result)fail('open_ack_preparation_incomplete');if(row.result.length>1048576||sha256(row.result)!==row.result_sha256)fail('open_ack_preparation_corrupt');
    const prepared=document(row.result,1048576) as Obj;if(prepared.message_id!==messageId)fail('open_ack_preparation_conflict');
    const artifact=objectFields(prepared.recipient_request,['schema_version','base_url','repair_profile','request']) as Obj;
    if(artifact.schema_version!=='memory-vault-open-saved-ack-request/v1'||!['receipt','receipt-index'].includes(artifact.repair_profile))fail('repair_invalid_request_bundle');
    const bundle=objectFields(artifact.request,['message_id','envelope_ref','ack_slot','owner','target','target_node_entry','root_entry','write_entry','bootstrap_entry','binding_entry','current_statuses','read_until','retain_until']) as Obj,roles:Obj={};
    if(bundle.message_id!==messageId)fail('open_ack_preparation_conflict');
    for(const [name,field] of [['ack.root_authority','root_entry'],['ack.write_grant','write_entry'],['bootstrap.ack_offer','bootstrap_entry']])roles[name]=this.#decode(bundle[field],budget);
    if(!Array.isArray(bundle.current_statuses)||bundle.current_statuses.length>64)fail('open_ack_preparation_corrupt');
    const statuses=bundle.current_statuses.map((v:Obj)=>this.#decode(v,budget));
    for(const [name,role] of [['ack.root_authority','ack_root'],['ack.write_grant','ack_write'],['bootstrap.ack_offer','ack_offer_bootstrap']]){
      const entry=roles[name],p=(parseNewWire(entry.raw,this.#policy,budget).value as Obj).payload;
      const scope=statusScope(bundle.ack_slot.root_key,'authority',{authority_kind:p.kind,authority_sha256:entry.ref.raw_sha256},this.#policy,budget);
      const matches=statuses.filter((v:Obj)=>(parseNewWire(v.raw,this.#policy,budget).value as Obj).payload.entries.some((r:Obj)=>r.scope_kind==='authority'&&r.scope_id===scope));
      if(matches.length!==1)fail('open_ack_configuration_status_missing');roles['historical.status.'+role]=matches[0];
    }
    return roles;
  }
  #prepare(value:Obj):Obj{
    objectFields(value,['schema_version','action','message_id','slot_entries','destination_entry','attempt_until','consent_until',...(Object.hasOwn(value,'ack_request_id')?['ack_request_id']:[])]);
    opaqueId(value.message_id);const budget=new RepairBudget(this.#policy),at=Math.floor(Date.now()/1000);
    const row=this.#participant.providerStorage(db=>db.prepare('SELECT envelope,session FROM open_delivery_outbox WHERE message_id=?').get(value.message_id)) as Obj|undefined;
    if(!row?.envelope||!row.session)fail('open_delivery_outbox_missing');
    const session=document(row.session,65536) as Obj,request=session.request.payload,recipient={signing_key:session.policy.payload.signing_key,encryption_key:session.policy.payload.encryption_key};
    const sender={signing_key:validateSigningIdentity(this.#participant.identity),encryption_key:validateEncryptionIdentity(this.#encryption)},senderIds=this.#dual(sender,budget),recipientIds=this.#dual(recipient,budget);
    const envelope=verifyEnvelope(row.envelope,{sender_signing_key:sender.signing_key,sender_encryption_key:sender.encryption_key,recipient_signing_key:recipient.signing_key,recipient_encryption_key:recipient.encryption_key,now:at});
    if(!same(request.signing_key,sender.signing_key)||!same(request.encryption_key,sender.encryption_key)||envelope.context.message_id!==value.message_id)fail('repair_message_mismatch');
    const reference={...this.#raw(row.envelope,budget).ref,namespace:'object',key:envelope.context.object_ref.key};
    objectFields(value.slot_entries,['slot','read','maintenance']);const slots=Object.fromEntries(Object.entries(value.slot_entries).map(([n,e])=>[n,this.#entry(e,budget)]));
    const destinationEntry=this.#entry(value.destination_entry,budget);
    const check=(e:Obj,kind:string,names:string):Obj=>{
      if(e.ref.namespace!=='meta')fail('repair_ref_mismatch');const v=objectFields(parseNewWire(e.raw,this.#policy,budget).value,['payload','proof']),p=objectFields(v.payload,['schema_version','kind','signing_key',...names.split(' ')]) as Obj;
      if(p.schema_version!==REPAIR||p.kind!==kind)fail('repair_invalid_message');verifyBoundedControlSignature(p,v.proof,recipient.signing_key,budget);if(u53(p.issued_at)>=u53(p.expires_at))fail('repair_resource_expired');return p;
    };
    const slot=check(slots.slot,'mailbox.slot',SLOT_FIELDS.slot),read=check(slots.read,'mailbox.read_grant',SLOT_FIELDS.read),maintenance=check(slots.maintenance,'mailbox.maintenance_root',SLOT_FIELDS.maintenance);
    const key=slot.slot_key,root=key.root_key;objectFields(key,['root_key','slot_id','writer','writer_storage_epoch']);opaqueId(key.slot_id);opaqueId(key.writer_storage_epoch);
    objectFields(root,['root_kind','owner','owner_epoch','root_id','anchor_ref']);opaqueId(root.owner_epoch);opaqueId(root.root_id);objectFields(root.anchor_ref,['namespace','key']);
    if(root.root_kind!=='mailbox'||root.anchor_ref.namespace!=='anchor'||!/^[a-f0-9]{64}$/.test(root.anchor_ref.key))fail('repair_message_mismatch');
    const destination=check(destinationEntry,'delivery.destination','issued_at expires_at destination_id sender recipient contact_request_ref contact_policy_ref contact_knock_lease_ref contact_decision_ref store_grant_ref slot_key slot_ref data_resource_ref data_resource_offer_ref metadata_resource_ref metadata_resource_offer_ref read_grant_ref maintenance_root_ref budget windows');
    if(!same(root.owner,recipientIds)||[slot,maintenance,destination].some(p=>!same(p.sender,senderIds)||!same(p.recipient,recipientIds))||!same(read.reader,recipientIds)||
      [read,maintenance,destination].some(p=>!same(p.slot_key,key))||!same(read.root_key,root)||!same(maintenance.root_key,root)||read.serving_authority_id!==maintenance.authority_id||
      !same(destination.slot_ref,slots.slot.ref)||!same(slot.read_grant_ref,slots.read.ref)||!same(slot.maintenance_root_ref,slots.maintenance.ref))fail('repair_message_mismatch');
    for(const n of ['data_resource_ref','data_resource_offer_ref','metadata_resource_ref','metadata_resource_offer_ref','read_grant_ref','maintenance_root_ref'])if(!same(destination[n],slot[n]))fail('repair_message_mismatch');
    for(const [field,names] of [['budget','max_live_bytes max_meta_bytes max_items max_requests max_pending max_replay_records max_jobs max_job_bytes'],['windows','admit_until read_until copy_until publish_until retain_until']]){
      objectFields(destination[field],names.split(' '));for(const n of names.split(' '))if(u53(destination[field][n])>u53(slot[field][n])||(field==='windows'&&destination[field][n]>destination.windows.retain_until))fail('repair_message_mismatch');
    }
    const docs:Obj=Object.fromEntries(['node','policy','request','decision'].map(n=>[n,session[n]]));docs.knock_lease=session.lease;docs.grant=session.decision.payload.grant;docs.delivery_lease=docs.grant.payload.resource_lease;
    const contact=Object.fromEntries(Object.entries(docs).map(([n,v])=>[n,canonicalBytes(v)]));
    const held=verifyContactOriginals(contact,{senderKeyId:sender.signing_key.key_id,senderEncryptionKeyId:sender.encryption_key.key_id,recipientKeyId:recipient.signing_key.key_id,recipientEncryptionKeyId:recipient.encryption_key.key_id,nodeKeyId:key.writer.signing_key_id,storageEpoch:key.writer_storage_epoch,at:destination.issued_at,policy:this.#policy,budget});
    for(const [n,role] of [['contact_request_ref','request'],['contact_policy_ref','policy'],['contact_knock_lease_ref','knock_lease'],['contact_decision_ref','decision'],['store_grant_ref','grant']]){
      const ref=rawRef(destination[n]),raw=held.originals[role].document.raw;if(ref.raw_sha256!==budget.hash(raw)||ref.size!==raw.length)fail('repair_ref_mismatch');
    }
    u53(value.attempt_until);u53(value.consent_until);const ack=Object.hasOwn(value,'ack_request_id')?this.#ack(value.ack_request_id,value.message_id,budget):undefined;
    if(ack)verifyMailboxAckConfiguration(ack,{sender,recipient,messageId:value.message_id,envelopeRef:reference,at,policy:this.#policy,budget});
    const encodedAck=ack?Object.fromEntries(Object.entries(ack).map(([n,e])=>[n,this.#encode(e)])):undefined;
    const binding=sha256(canonicalBytes({envelope:reference,recipient,slot_refs:Object.fromEntries(Object.entries(slots).map(([n,e])=>[n,e.ref])),destination_ref:destinationEntry.ref,
      contact_hashes:Object.fromEntries(Object.entries(contact).map(([n,raw])=>[n,sha256(raw)])),attempt_until:value.attempt_until,consent_until:value.consent_until,...(ack?{ack_configuration:encodedAck}:{})}));
    const raw=this.#participant.providerStorage(db=>transaction(db,()=>{
      db.exec('CREATE TABLE IF NOT EXISTS open_mailbox_message_drafts(sender TEXT NOT NULL,message_id TEXT NOT NULL,binding TEXT NOT NULL,root_digest TEXT NOT NULL,status_revision INTEGER NOT NULL,envelope BLOB NOT NULL,originals BLOB NOT NULL,PRIMARY KEY(sender,message_id))');
      const old=db.prepare('SELECT binding,envelope,originals FROM open_mailbox_message_drafts WHERE sender=? AND message_id=?').get(sender.signing_key.key_id,value.message_id) as Obj|undefined;
      if(old){if(old.binding!==binding||!Buffer.from(old.envelope).equals(Buffer.from(row.envelope)))fail('repair_message_conflict');return old.originals;}
      if((db.prepare('SELECT count(*) AS n FROM open_mailbox_message_drafts').get() as Obj).n>=16)fail('repair_message_capacity');
      if(!(envelope.context.created_at<=at&&at<value.attempt_until&&value.attempt_until<=Math.min(destination.expires_at,held.originals.grant.payload.expires_at as number))||
        !(at<value.consent_until&&value.consent_until<=Math.min(slot.expires_at,maintenance.expires_at,slot.windows.retain_until,maintenance.windows.retain_until))||[slot,read,maintenance,destination].some(p=>!(p.issued_at<=at&&at<p.expires_at)))fail('repair_resource_expired');
      db.exec('CREATE TABLE IF NOT EXISTS open_mailbox_message_status_revisions(sender TEXT NOT NULL,root_digest TEXT NOT NULL,revision INTEGER NOT NULL,PRIMARY KEY(sender,root_digest))');
      const rootDigest=budget.hash(buildNewWire(root,this.#policy,budget).raw),prior=db.prepare('SELECT revision FROM open_mailbox_message_status_revisions WHERE sender=? AND root_digest=?').get(sender.signing_key.key_id,rootDigest) as Obj|undefined;
      const maximum=(db.prepare('SELECT max(status_revision) AS revision FROM open_mailbox_message_drafts WHERE sender=? AND root_digest=?').get(sender.signing_key.key_id,rootDigest) as Obj).revision;
      if((prior?.revision??null)!==maximum)fail('repair_message_ledger_missing');const revision=u53((maximum??0)+1,1);
      const sign=(kind:string,fields:Obj,until:number)=>signBoundedBootstrapOriginal({schema_version:REPAIR,kind,signing_key:sender.signing_key,issued_at:at,expires_at:until,...fields},this.#participant.identity,this.#policy,budget);
      const consent=sign('message.disclosure',{consent_id:'consent_'+binding,root_key:root,slot_key:key,sender:senderIds,recipient:recipientIds,envelope_ref:reference,maintenance_root_ref:slots.maintenance.ref,
        allowed_roles:['contact.request','delivery.attempt','message.disclosure','authority.status.disclosure',...(ack?ACK_ROLES:[])].sort(),operation_mask:127,consent_until:value.consent_until,
        bootstrap_return:{subject:recipientIds,consumer:'mailbox_feed',roles:['authority.status.disclosure','message.disclosure'],until:value.consent_until},revision:1},value.consent_until);
      const attempt=sign('delivery.attempt',{attempt_id:'attempt_'+binding,message_id:value.message_id,envelope_ref:reference,sender:senderIds,recipient:recipientIds,destination_ref:destinationEntry.ref,slot_key:key,
        operation:'message.store',disclosure_ref:consent.ref,ack_grant_ref:ack?.['ack.write_grant'].ref??null},value.attempt_until);
      const scope=statusScope(root,'authority',{authority_kind:'message.disclosure',authority_sha256:consent.ref.raw_sha256},this.#policy,budget);
      const observed=this.#raw(buildNewWire(issueStatus(this.#participant.identity,{root,revision,entries:[{scope_kind:'authority',scope_id:scope,minimum_document_revision:1,status:'active',operation_mask:127}],issued_at:at,valid_until:value.consent_until}),this.#policy,budget).raw,budget);
      const bundle={disclosure:this.#encode(consent),disclosure_status:this.#encode(observed),attempt:this.#encode(attempt),destination:this.#encode(destinationEntry),slot:Object.fromEntries(Object.entries(slots).map(([n,e])=>[n,this.#encode(e)])),
        contact:Object.fromEntries(Object.entries(contact).map(([n,bytes])=>[n,this.#encode(this.#raw(bytes,budget))])),...(ack?{ack_configuration:encodedAck}:{})};
      const encoded=buildNewWire(bundle,this.#policy,budget).raw;if(encoded.length>131072)fail('repair_message_capacity');
      db.prepare('INSERT OR REPLACE INTO open_mailbox_message_status_revisions VALUES(?,?,?)').run(sender.signing_key.key_id,rootDigest,revision);
      db.prepare('INSERT INTO open_mailbox_message_drafts VALUES(?,?,?,?,?,?,?)').run(sender.signing_key.key_id,value.message_id,binding,rootDigest,revision,row.envelope,encoded);return encoded;
    }));
    const saved=parseNewWire(raw,this.#policy,new RepairBudget(this.#policy)).value as Obj;
    return {state:'mailbox_draft_saved',message_id:value.message_id,attempt_ref:this.#decode(saved.attempt,budget).ref,disclosure_ref:this.#decode(saved.disclosure,budget).ref,network_accessed:false};
  }
  async #admit(value:Obj):Promise<Obj>{
    objectFields(value,['schema_version','action','base_url','message_id','target','target_node_entry','owner_status_entry','expires_at','object_until','enum_until']);opaqueId(value.message_id);
    const budget=new RepairBudget(this.#policy),at=Math.floor(Date.now()/1000),sender={signing_key:validateSigningIdentity(this.#participant.identity),encryption_key:validateEncryptionIdentity(this.#encryption)};
    const nodeEntry=this.#entry(value.target_node_entry,budget),nodePreview=(parseNewWire(nodeEntry.raw,this.#policy,budget).value as Obj).payload;
    const node=verifySourceNodeOriginal(nodeEntry.raw,{expectedSigningKey:value.target.signing_key,expectedStorageEpoch:nodePreview.storage_epoch,at,policy:this.#policy,budget});
    if(nodeEntry.ref.namespace!=='meta'||!same(endpoint(value.base_url,this.#participant.transport.allow_loopback),endpoint(node.payload.base_url as string,this.#participant.transport.allow_loopback)))fail('repair_probe_mismatch');
    const packet=this.#participant.providerStorage(db=>transaction(db,()=>{
      if(!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='open_mailbox_message_drafts'").get())fail('repair_message_delivery_missing');
      const row=db.prepare('SELECT originals FROM open_mailbox_message_drafts WHERE sender=? AND message_id=?').get(sender.signing_key.key_id,value.message_id) as Obj|undefined;if(!row)fail('repair_message_delivery_missing');
      const raw=Buffer.from(row.originals);if(raw.length>131072)fail('repair_message_capacity');const draft=parseNewWire(raw,this.#policy,budget).value as Obj;
      const slot=this.#decode(draft.slot.slot,budget),key=(parseNewWire(slot.raw,this.#policy,budget).value as Obj).payload.slot_key;
      if(!same(this.#dual(value.target,budget),key.writer)||node.payload.storage_epoch!==key.writer_storage_epoch)fail('repair_probe_mismatch');
      const plain={raw:raw.toString('utf8'),ref:this.#raw(raw,budget).ref};let encoded:Obj=plain;
      if(draft.ack_configuration){const compressed=deflateSync(raw);budget.output(compressed.length);encoded={codec:'zlib-base64url-v1',compressed_size:compressed.length,raw_base64url:encodeBase64url(compressed),ref:plain.ref};}
      const payload={schema_version:REPAIR,kind:'mailbox.source_message',signing_key:sender.signing_key,subject:sender,target:value.target,target_storage_epoch:key.writer_storage_epoch,slot_key:key,message_id:value.message_id,
        draft:encoded,owner_status:this.#encode(this.#entry(value.owner_status_entry,budget)),object_until:value.object_until,enum_until:value.enum_until};
      const binding=budget.hash(buildNewWire({...payload,draft:plain},this.#policy,budget).raw);
      db.exec('CREATE TABLE IF NOT EXISTS open_mailbox_message_requests(sender TEXT NOT NULL,message_id TEXT NOT NULL,binding TEXT NOT NULL,raw BLOB NOT NULL,PRIMARY KEY(sender,message_id))');
      const prior=db.prepare('SELECT binding,raw FROM open_mailbox_message_requests WHERE sender=? AND message_id=?').get(sender.signing_key.key_id,value.message_id) as Obj|undefined;
      let requestRaw:Uint8Array;
      if(prior){if(prior.binding!==binding)fail('repair_message_conflict');requestRaw=prior.raw;}
      else{
        if(!(at<u53(value.expires_at)&&at<u53(value.object_until)&&value.object_until<=u53(value.enum_until)))fail('repair_resource_expired');
        requestRaw=signBoundedBootstrapOriginal({...payload,issued_at:at,expires_at:value.expires_at},this.#participant.identity,this.#policy,budget).raw;
        if(requestRaw.length>65536)fail('repair_remote_setup_too_large');db.prepare('INSERT INTO open_mailbox_message_requests VALUES(?,?,?,?)').run(sender.signing_key.key_id,value.message_id,binding,requestRaw);
      }
      return {raw:requestRaw,payload,draft};
    }));
    const response=await this.#participant.transport.requestRepair(value.base_url,packet.raw,performance.now()/1000+30);
    if(response.length>65536)fail('repair_remote_setup_too_large');const signed=objectFields(parseNewWire(response,this.#policy,budget).value,['payload','proof']);
    const p=objectFields(signed.payload,['schema_version','kind','signing_key','request_sha256','slot_key','message_id','stored_at','originals']) as Obj;
    if(p.schema_version!==REPAIR||p.kind!=='mailbox.source_message_stored'||p.request_sha256!==budget.hash(packet.raw)||!same(p.slot_key,packet.payload.slot_key)||p.message_id!==value.message_id||!same(p.signing_key,value.target.signing_key))fail('repair_message_mismatch');
    u53(p.stored_at);verifyBoundedControlSignature(p,signed.proof,value.target.signing_key,budget);
    const kinds={core:'admission.core',link:'admission.link',custody:'message.custody',head:'mailbox.feed_head',feed_custody:'feed.custody'},entries:Obj={},payloads:Obj={};objectFields(p.originals,Object.keys(kinds));
    for(const [n,kind] of Object.entries(kinds)){
      const e=this.#decode(p.originals[n],budget),v=objectFields(parseNewWire(e.raw,this.#policy,budget).value,['payload','proof']),item=v.payload as Obj;
      if(item.schema_version!==REPAIR||item.kind!==kind||!same(item.slot_key,packet.payload.slot_key))fail('repair_message_mismatch');verifyBoundedControlSignature(item,v.proof,value.target.signing_key,budget);entries[n]=e;payloads[n]=item;
    }
    const core=payloads.core,custody=payloads.custody,attempt=this.#decode(packet.draft.attempt,budget),ap=(parseNewWire(attempt.raw,this.#policy,budget).value as Obj).payload;
    if(core.message_id!==value.message_id||custody.message_id!==value.message_id||core.object_until!==value.object_until||core.enum_until!==value.enum_until||!same(core.attempt_ref,attempt.ref)||!same(core.envelope_ref,ap.envelope_ref)||
      !same(custody.envelope_ref,core.envelope_ref)||!same(payloads.link.envelope_ref,core.envelope_ref)||payloads.link.message_id!==value.message_id||!same(payloads.feed_custody.feed_head_ref,entries.head.ref)||!same(custody.admission_link_ref,entries.link.ref)||!same(custody.feed_head_ref,entries.head.ref))fail('repair_message_mismatch');
    this.#participant.providerStorage(db=>transaction(db,()=>{
      db.exec('CREATE TABLE IF NOT EXISTS open_mailbox_message_results(sender TEXT NOT NULL,message_id TEXT NOT NULL,raw BLOB NOT NULL,PRIMARY KEY(sender,message_id))');
      const old=db.prepare('SELECT raw FROM open_mailbox_message_results WHERE sender=? AND message_id=?').get(sender.signing_key.key_id,value.message_id) as Obj|undefined;
      if(old&&!Buffer.from(old.raw).equals(Buffer.from(response)))fail('repair_message_conflict');db.prepare('INSERT OR IGNORE INTO open_mailbox_message_results VALUES(?,?,?)').run(sender.signing_key.key_id,value.message_id,response);
    }));
    return {state:'retained_at_mailbox',message_id:value.message_id,stored_at:p.stored_at,network_accessed:true,custody_ref:entries.custody.ref,feed_custody_ref:entries.feed_custody.ref,recipient_acknowledged:false};
  }
  async connect(invitation:unknown):Promise<Obj>{
    const v=document(invitation as any,65536) as Obj;if(v.schema_version!==SCHEMA)fail('open_invalid_mailbox_request');
    if(v.action==='prepare')return this.#prepare(v);if(v.action==='admit')return this.#admit(v);
    objectFields(v,['schema_version','action','message_id','authorization','attempt_until','consent_until','expires_at','object_until','enum_until',...(Object.hasOwn(v,'ack_request_id')?['ack_request_id']:[])]);
    if(v.action!=='retain')fail('open_invalid_mailbox_request');const a=objectFields(v.authorization,['destination_entry','owner_status_entry','slot_entries','target','target_node_entry','base_url']);
    this.#prepare({schema_version:SCHEMA,action:'prepare',message_id:v.message_id,slot_entries:a.slot_entries,destination_entry:a.destination_entry,attempt_until:v.attempt_until,consent_until:v.consent_until,...(Object.hasOwn(v,'ack_request_id')?{ack_request_id:v.ack_request_id}:{})});
    return this.#admit({schema_version:SCHEMA,action:'admit',message_id:v.message_id,...Object.fromEntries(['base_url','target','target_node_entry','owner_status_entry'].map(n=>[n,a[n]])),...Object.fromEntries(['expires_at','object_until','enum_until'].map(n=>[n,v[n]]))});
  }
}
