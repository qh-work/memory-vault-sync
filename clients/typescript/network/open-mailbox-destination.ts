/** Receiver-issued original mailbox admission, retained across client changes. */
import {canonicalBytes,sha256,encodeBase64url,decodeBase64url,validateSigningIdentity,validateEncryptionIdentity} from './crypto.ts';
import type {EncryptionIdentityDocument} from './crypto.ts';
import type {OpenParticipant} from './open-participant.ts';
import {transaction} from './io.ts';
import {RepairBudget,RepairError,buildNewWire,parseNewWire,objectFields,rawRef,u53} from './open-repair-wire.ts';
import {DEFAULT_REPAIR_CLIENT_POLICY} from './open-repair-client.ts';
import {verifyMailboxFeedBootstrap} from './open-repair-mailbox-authority.ts';
import {originalPublicDescriptor,verifyContactOriginals,verifyBoundedControlSignature} from './open-repair-original.ts';
import {signBoundedBootstrapOriginal} from './open-repair-probe.ts';
import {MailboxSetupJournal} from './open-mailbox-journal.ts';
import {authenticateStatusOriginal,statusScope} from './open-repair-status.ts';
import {issueStatus} from './open-provider.ts';
type Obj=Record<string,any>;
function fail(code:string):never{throw new RepairError(code);}
/** Inputs are the locally reauthenticated receiver and approved contact originals. */
export function prepareMailboxDestination(participant:OpenParticipant,encryption:EncryptionIdentityDocument,config:Obj,slots:Obj,contact:Obj,
  value:{expires_at:number;status_revision:number;status_until:number}):Obj{
  objectFields(value,['expires_at','status_revision','status_until']);
  const policy={...DEFAULT_REPAIR_CLIENT_POLICY,max_signature_checks:512},budget=new RepairBudget(policy),at=Math.floor(Date.now()/1000);
  const owner={signing_key:validateSigningIdentity(participant.identity),encryption_key:validateEncryptionIdentity(encryption)};
  const encode=(entry:Obj)=>{const ref=rawRef(entry.ref),raw=parseNewWire(entry.raw,policy,budget).raw;if(raw.length!==ref.size||budget.hash(raw)!==ref.raw_sha256)fail('repair_ref_mismatch');return {ref,raw_base64url:encodeBase64url(raw)};};
  const decode=(entry:unknown)=>{const e=objectFields(entry,['ref','raw_base64url']),ref=rawRef(e.ref),raw=decodeBase64url(e.raw_base64url,65536);if(raw.length!==ref.size||budget.hash(raw)!==ref.raw_sha256)fail('repair_ref_mismatch');return {ref,raw};};
  const setup=verifyMailboxFeedBootstrap(slots,{expectedSlot:config.expected_slot,expectedOwner:owner,expectedTarget:config.expected_target,
    targetStorageEpoch:config.expected_slot.writer_storage_epoch,limitPolicy:config.limit_policy,at,policy,budget}),slot=setup.slot.payload as Obj,root=slot.slot_key.root_key;
  const sender=objectFields(config.expected_sender,['signing_key','encryption_key']);
  originalPublicDescriptor(sender.signing_key,budget);originalPublicDescriptor(sender.encryption_key,budget,true);
  if(sender.signing_key.key_id!==slot.sender.signing_key_id||sender.encryption_key.key_id!==slot.sender.encryption_key_id)fail('open_invalid_mailbox_receiver');
  const plan={root_key:root,slot_key:slot.slot_key,sender:slot.sender,target:config.expected_target,limits:config.limit_policy,
    ...Object.fromEntries(['budget','windows','max_appends','max_live_items'].map(n=>[n,slot[n]]))};
  u53(value.status_revision,1);u53(value.expires_at);u53(value.status_until);
  const binding=budget.hash(buildNewWire({plan,slots:Object.fromEntries(Object.entries(slots).map(([n,e])=>[n,encode(e)])),
    contact:Object.fromEntries(Object.entries(contact).map(([n,raw])=>[n,budget.hash(raw as Uint8Array)])),...value},policy,budget).raw);
  const rootDigest=budget.hash(buildNewWire(root,policy,budget).raw);
  const journal=new MailboxSetupJournal(participant),journalKey=journal.start({kind:'mailbox.feed_recovery',slot_key:slot.slot_key,owner,
    sender:config.expected_sender,target:config.expected_target,entries:Object.fromEntries(Object.entries(setup).map(([n,e])=>[n,e.ref]))});
  const required=new Map<string,{revision:number;mask:number}>();
  for(const [name,mask] of [['slot',65],['read',2],['maintenance',65],['bootstrap',10]] as const){
    const e=setup[name],kind=name==='slot'?'mailbox_slot':'authority',scope=statusScope(root,kind,name==='slot'?slot.slot_key:{authority_kind:e.payload.kind,authority_sha256:e.ref.raw_sha256},policy,budget);
    required.set(owner.signing_key.key_id+':'+kind+':'+scope,{revision:e.payload.revision as number,mask});
  }
  for(const name of ['data','metadata'])required.set(config.expected_target.signing_key.key_id+':resource:'+statusScope(root,'resource',slot[name+'_resource_ref'],policy,budget),{revision:Infinity,mask:65});
  return participant.providerStorage(db=>transaction(db,()=>{
  const revisions=new Map<string,string>();let observedOwnerRevision=-1;
  for(const entry of journal.statuses(journalKey)){
    const signed=objectFields(parseNewWire(entry.raw,policy,budget).value,['payload','proof']),preview=signed.payload as Obj;
    const signer=[owner.signing_key,config.expected_target.signing_key,config.expected_sender.signing_key].find(v=>v.key_id===preview.signing_key?.key_id);
    if(!signer||u53(preview.issued_at)>at||!Array.isArray(preview.entries)||preview.entries.length>16)fail('repair_status_disclosure');
    const item=authenticateStatusOriginal(entry,{expectedRoot:root,expectedSigningKey:signer,at:preview.issued_at,
      allowedScopes:preview.entries.map((e:Obj)=>({scope_kind:e.scope_kind,scope_id:e.scope_id})),policy,budget});
    const status=item.payload as Obj,key=signer.key_id+':'+status.revision;
    if(revisions.has(key)&&revisions.get(key)!==item.canonical_sha256)fail('repair_status_conflict');revisions.set(key,item.canonical_sha256);
    if(signer.key_id===owner.signing_key.key_id)observedOwnerRevision=Math.max(observedOwnerRevision,status.revision);
    for(const row of status.entries){const need=required.get(signer.key_id+':'+row.scope_kind+':'+row.scope_id);if(!need)continue;
      if(row.status==='revoked'&&(row.operation_mask&need.mask))fail('repair_authority_revoked');
      if(row.minimum_document_revision>need.revision)fail('repair_status_revision');
    }
  }
    db.exec('CREATE TABLE IF NOT EXISTS open_mailbox_destinations(root_digest TEXT NOT NULL,revision INTEGER NOT NULL,binding TEXT NOT NULL,bundle BLOB NOT NULL,bundle_sha256 TEXT NOT NULL,PRIMARY KEY(root_digest,revision))');
    const old=db.prepare('SELECT binding,bundle,bundle_sha256 FROM open_mailbox_destinations WHERE root_digest=? AND revision=?').get(rootDigest,value.status_revision) as Obj|undefined;
    if(old){
      if(old.binding!==binding)fail('repair_destination_conflict');if(old.bundle.length>65536||budget.hash(old.bundle)!==old.bundle_sha256)fail('repair_destination_journal_corrupt');
      const saved=objectFields(parseNewWire(old.bundle,policy,budget).value,['destination','owner_status']),result=Object.fromEntries(Object.entries(saved).map(([n,e])=>[n,decode(e)]));
      for(const entry of Object.values(result)){const signed=objectFields(parseNewWire(entry.raw,policy,budget).value,['payload','proof']);verifyBoundedControlSignature(signed.payload,signed.proof,owner.signing_key,budget);}
      return result;
    }
    const latest=(db.prepare('SELECT max(revision) AS revision FROM open_mailbox_destinations WHERE root_digest=?').get(rootDigest) as Obj).revision;
    if(value.status_revision<=observedOwnerRevision||(latest!==null&&value.status_revision<=latest))fail('repair_destination_revision_rollback');
    if((db.prepare('SELECT count(*) AS n FROM open_mailbox_destinations').get() as Obj).n>=128)fail('repair_destination_capacity');
    const held=verifyContactOriginals(contact,{senderKeyId:slot.sender.signing_key_id,senderEncryptionKeyId:slot.sender.encryption_key_id,
      recipientKeyId:owner.signing_key.key_id,recipientEncryptionKeyId:owner.encryption_key.key_id,nodeKeyId:config.expected_target.signing_key.key_id,
      storageEpoch:slot.slot_key.writer_storage_epoch,at,policy,budget});
    if(!(at<value.expires_at&&value.expires_at<=Math.min(...['slot','read','maintenance'].map(n=>setup[n].payload.expires_at as number),held.originals.grant.payload.expires_at as number))
      ||!(at<value.status_until&&value.status_until<=Math.min(...Object.values(setup).map(e=>e.payload.expires_at as number))))fail('repair_resource_expired');
    const refs=Object.fromEntries([['contact_request_ref','request'],['contact_policy_ref','policy'],['contact_knock_lease_ref','knock_lease'],['contact_decision_ref','decision'],['store_grant_ref','grant']].map(([field,role])=>{
      const raw=held.originals[role].document.raw,digest=budget.hash(raw);return [field,{namespace:'meta',key:digest,raw_sha256:digest,size:raw.length}];}));
    const destinationId='destination_'+sha256(Buffer.concat([Buffer.from('memory-vault-mailbox-setup/v1\0'),buildNewWire(root,policy,budget).raw,Buffer.from('\0destination')]));
    const signed=signBoundedBootstrapOriginal({schema_version:'memory-vault-open-repair/v1',kind:'delivery.destination',signing_key:owner.signing_key,
      issued_at:at,expires_at:value.expires_at,destination_id:destinationId,sender:slot.sender,recipient:slot.recipient,slot_key:slot.slot_key,slot_ref:setup.slot.ref,...refs,
      ...Object.fromEntries(['data_resource_ref','data_resource_offer_ref','metadata_resource_ref','metadata_resource_offer_ref','read_grant_ref','maintenance_root_ref','budget','windows'].map(n=>[n,slot[n]]))},participant.identity,policy,budget);
    const destination={raw:signed.raw,ref:signed.ref},scopes=[['destination',destination],...Object.entries(slots)].map(([name,entry])=>{
      const e=entry as Obj,p=(parseNewWire(e.raw,policy,budget).value as Obj).payload,kind=name==='slot'?'mailbox_slot':'authority';
      return {scope_kind:kind,scope_id:statusScope(root,kind,name==='slot'?slot.slot_key:{authority_kind:p.kind,authority_sha256:e.ref.raw_sha256},policy,budget),
        minimum_document_revision:p.revision??1,status:'active',operation_mask:127};
    }).sort((a,b)=>a.scope_kind<b.scope_kind?-1:a.scope_kind>b.scope_kind?1:a.scope_id<b.scope_id?-1:a.scope_id>b.scope_id?1:0);
    const raw=buildNewWire(issueStatus(participant.identity,{root,revision:value.status_revision,entries:scopes,issued_at:at,valid_until:value.status_until}),policy,budget).raw,digest=budget.hash(raw);
    const result={destination,owner_status:{raw,ref:{namespace:'meta',key:digest,raw_sha256:digest,size:raw.length}}};
    const bundle=buildNewWire(Object.fromEntries(Object.entries(result).map(([n,e])=>[n,encode(e)])),policy,budget).raw;if(bundle.length>65536)fail('repair_destination_capacity');
    db.prepare('INSERT INTO open_mailbox_destinations VALUES(?,?,?,?,?)').run(rootDigest,value.status_revision,binding,bundle,budget.hash(bundle));return result;
  }));
}
/** Finite output shares the existing Python cursor and exact authorization bytes. */
export function mailboxPage(value:unknown,receiver:string,cursor:unknown,kind:'authorization'|'configuration'):Obj{
  const raw=canonicalBytes(value,65536),digest=sha256(raw);let offset=0;
  if(cursor!==undefined&&cursor!==null){const v=objectFields(cursor,['sha256','offset']);offset=v.offset;if(v.sha256!==digest||!Number.isSafeInteger(offset)||offset<=0||offset>=raw.length||offset%3072)fail('open_invalid_mailbox_cursor');}
  const end=Math.min(offset+3072,raw.length);return {state:'mailbox_'+kind,receiver_id:receiver,[kind+'_sha256']:digest,total_bytes:raw.length,offset,
    [kind+'_chunk']:Buffer.from(raw.subarray(offset,end)).toString('base64'),next_cursor:end===raw.length?null:{sha256:digest,offset:end},
    network_accessed:false,source_rechecked:false,receipt_return:'separate_authority_required'};
}
