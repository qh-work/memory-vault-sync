/** Independent network-v1 peer. It opens the existing Vault and transport schema. */
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import type { DatabaseSync } from 'node:sqlite';
import {
  canonicalBytes, document, documentSha256, objectFields, opaqueId, safeInteger,
  digestHex, sha256, encodeBase64url, decodeBase64url, seal, open, verify,
  validateSigningIdentity, validateEncryptionIdentity, validateSigningPublic,
  NetworkCryptoError,
} from './crypto.ts';
import type { DocumentInput, SigningIdentityDocument, EncryptionIdentityDocument, SigningPublicDescriptor } from './crypto.ts';
import { verifyCurrentRoster, verifyRoster, signRequest, verifyRequest, verifyInvitationPackage, openJoinChallenge, authorizedMember } from './control.ts';
import type { CurrentRoster, RequestAction, RecoveryAnchor } from './control.ts';
import { verifyCurrentNodes, authorizedNode, verifyNodeChallenge, verifyStorageReceipt } from './nodes.ts';
import { CanonicalVault } from './vault.ts';
import { parseShare, NetworkRecordsError } from './records.ts';
import { absolutePath, readPrivate, openPrivateDatabase, transaction, NetworkError } from './io.ts';
import { HTTPTransport, origin } from './transport.ts';
import { readTrustedKeys } from './setup.ts';
import type { Transport } from './transport.ts';

type Obj = Record<string, any>;
const CONTENT_SCHEMA = 'memory-vault-network-content/v1';
const MAX_SHARE = 2 * 1024 * 1024, MAX_QUEUE = 256 * 1024 * 1024, MAX_WIRE = 8 * 1024 * 1024;
const json = (value: unknown): string => Buffer.from(canonicalBytes(value, MAX_WIRE)).toString('utf8');
function parse(value: string | Uint8Array): any {
  const raw = typeof value === 'string' ? Buffer.from(value) : Buffer.from(value);
  return document(Buffer.concat([Buffer.from('{"value":'), raw, Buffer.from('}')]), MAX_WIRE).value;
}
const equal = (a: unknown, b: unknown): boolean => json(a) === json(b);
const now = (): number => Math.floor(Date.now() / 1000);
function errorData(error: unknown): {code: string; retryable: boolean} {
  return { code: error instanceof NetworkCryptoError || error instanceof NetworkRecordsError ? error.code : 'network_storage_unavailable', retryable: (error as any)?.retryable === true };
}
function fail(code: string): never { throw new NetworkError(code); }
function preview(value: string): string {
  let result = Array.from(value).slice(0, 512);
  while (Buffer.byteLength(JSON.stringify(result.join(''))) > 512) result = result.slice(0, Math.max(1, Math.floor(result.length / 2)));
  return result.join('');
}
export function trustedKeys(trustPath: string): SigningPublicDescriptor[] {
  return readTrustedKeys(trustPath);
}

export class NetworkPeer {
  readonly networkId: string;
  readonly clientConfigPath: string;
  readonly configPath: string;
  readonly relays: string[];
  readonly authorityUrl: string;
  readonly identity: SigningIdentityDocument;
  readonly encryption: EncryptionIdentityDocument;
  readonly issuers: SigningPublicDescriptor[];
  readonly localIdentity: Obj;
  readonly directory: string;
  readonly vault: CanonicalVault;
  private database: DatabaseSync | null = null;
  private readonly binding: Obj;
  private readonly transport: Transport;
  private readonly ownsTransport: boolean;
  private closed = false;
  private tail: Promise<unknown> = Promise.resolve();

  constructor(configPath: string, options: {transport?: Transport; clientConfigPath?: string} = {}) {
    this.configPath = absolutePath(configPath);
    const config = objectFields(document(readPrivate(this.configPath, 65536)!), ['schema_version','network_id','client_config_path','state_directory','encryption_key_path','issuer_public_key','relays','authority_url']);
    if (config.schema_version !== 'memory-vault-network-client/v1') fail('network_invalid_config');
    this.networkId = opaqueId(config.network_id);
    this.clientConfigPath = absolutePath(config.client_config_path);
    if (options.clientConfigPath !== undefined && absolutePath(options.clientConfigPath) !== this.clientConfigPath) fail('network_client_config_mismatch');
    const client = document(readPrivate(this.clientConfigPath, 65536)!);
    const allowed = ['schema_version','vault_path','identity_path','trust_path','capture_visible_turns','sync_config_path'];
    if (Object.keys(client).some(key => !allowed.includes(key)) || client.schema_version !== 'memory-vault-client-config/v1') fail('invalid_client_config');
    if (typeof client.identity_path !== 'string' || typeof client.trust_path !== 'string') fail('network_signing_identity_required');
    this.identity = document(readPrivate(absolutePath(client.identity_path), 4096)!) as unknown as SigningIdentityDocument;
    this.encryption = document(readPrivate(absolutePath(config.encryption_key_path), 16384)!) as unknown as EncryptionIdentityDocument;
    this.localIdentity = { signing_key: validateSigningIdentity(this.identity), encryption_key: validateEncryptionIdentity(this.encryption) };
    this.issuers = [validateSigningPublic(config.issuer_public_key as DocumentInput)];
    this.authorityUrl = origin(config.authority_url);
    if (!Array.isArray(config.relays) || config.relays.length < 1 || config.relays.length > 2) fail('network_one_or_two_relays_required');
    this.relays = config.relays.map(origin);
    if (new Set(this.relays).size !== this.relays.length) fail('network_duplicate_relay');
    this.directory = absolutePath(config.state_directory);
    const vaultPath = absolutePath(client.vault_path), trustPath = absolutePath(client.trust_path);
    if (this.directory === path.dirname(vaultPath)) fail('network_separate_state_required');
    this.vault = new CanonicalVault({vaultPath, identity: this.identity, trust: () => trustedKeys(trustPath)});
    this.binding = { network_id: this.networkId, ...this.localIdentity, issuer_public_key: this.issuers[0], client_config_path: this.clientConfigPath };
    this.ownsTransport = options.transport === undefined;
    this.transport = options.transport ?? new HTTPTransport();
  }
  close(): void {
    this.closed = true; this.database?.close(); this.database = null; this.vault.close();
    if (this.ownsTransport) this.transport.close?.();
  }
  private serial<T>(operation: () => Promise<T>): Promise<T> {
    const current = this.tail.then(() => { if (this.closed) fail('network_transport_closed'); return operation(); });
    this.tail = current.catch(() => undefined); return current;
  }
  private db(): DatabaseSync {
    if (this.closed) fail('network_transport_closed');
    if (this.database) return this.database;
    const db = openPrivateDatabase(path.join(this.directory, 'network.sqlite3'));
    try {
      db.exec(`CREATE TABLE IF NOT EXISTS state(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS outbox(request_id TEXT PRIMARY KEY,message_id TEXT NOT NULL UNIQUE,input_sha TEXT NOT NULL,body BLOB NOT NULL,envelope BLOB,roster BLOB,receipts TEXT NOT NULL DEFAULT '{}',recipients BLOB);
        CREATE TABLE IF NOT EXISTS inbox(message_id TEXT PRIMARY KEY,digest TEXT NOT NULL,sender TEXT NOT NULL,body BLOB NOT NULL,result TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS acknowledgements(message_id TEXT NOT NULL,recipient TEXT NOT NULL,receipt BLOB NOT NULL,PRIMARY KEY(message_id,recipient));
        CREATE TABLE IF NOT EXISTS quarantine(message_id TEXT PRIMARY KEY,digest TEXT NOT NULL UNIQUE,sender TEXT NOT NULL,envelope BLOB NOT NULL,code TEXT NOT NULL);`);
      transaction(db, () => {
        if (!(db.prepare('PRAGMA table_info(outbox)').all() as Obj[]).some(row => row.name === 'recipients')) db.exec('ALTER TABLE outbox ADD COLUMN recipients BLOB');
        const prior = db.prepare("SELECT value FROM state WHERE key='configuration_binding'").get() as Obj | undefined;
        if (!prior) {
          if (['state','outbox','inbox','acknowledgements','quarantine'].some(table => db.prepare('SELECT 1 FROM '+table+' LIMIT 1').get())) fail('network_state_binding_missing');
          db.prepare('INSERT INTO state VALUES(?,?)').run('configuration_binding', json(this.binding));
        } else if (!equal(parse(prior.value), this.binding)) fail('network_state_configuration_mismatch');
      });
      this.database = db; return db;
    } catch (error) { db.close(); throw error; }
  }
  private state(key: string): any {
    const row = this.db().prepare('SELECT value FROM state WHERE key=?').get(key) as Obj | undefined;
    return row ? parse(row.value) : undefined;
  }
  private put(key: string, value: unknown): void { this.db().prepare('INSERT OR REPLACE INTO state VALUES(?,?)').run(key, json(value)); }
  private assertNode(relay: string, binding: Obj|null): void {
    if (!equal(this.state('node:'+relay)??null,binding)) throw new NetworkError('network_node_changed',true);
  }
  private request(action: RequestAction, body: Obj, requestId = 'req_'+randomBytes(16).toString('hex')): any {
    const at = now(); return signRequest({signer:this.identity,network_id:this.networkId,action,request_id:requestId,body,issued_at:at,expires_at:at+60});
  }
  private async http(base: string, method: 'GET'|'POST', route: string, value?: Obj, deadline?: number): Promise<Obj> {
    if (deadline !== undefined && performance.now() >= deadline) throw new NetworkError('network_budget_exhausted',true);
    return this.transport.request(base,method,route,value,deadline);
  }
  private recovery(): {anchor?: RecoveryAnchor; nodes?: Obj} {
    const raw = readPrivate(path.join(path.dirname(this.configPath),'recovery-state.json'),2*1024*1024,true);
    if (!raw) return {};
    const marker = document(raw), required=['schema_version','network_id','activation_disabled','requires_fresh_issuer_status','minimum_roster_version','last_verified_roster','last_roster_sha256','old_delivery_cursors_restored','offline_outbox_restored','vault_restored_by_this_command'];
    if (!required.every(key=>key in marker) || Object.keys(marker).some(key=>!required.includes(key)&&key!=='last_verified_node_directory')) fail('network_recovery_marker_invalid');
    const complete = marker.schema_version==='memory-vault-network-restored-endpoint/v1';
    if ((!complete&&marker.schema_version!=='memory-vault-network-restored-state/v1') || marker.network_id!==this.networkId || marker.activation_disabled!==true || marker.requires_fresh_issuer_status!==true || ['old_delivery_cursors_restored','offline_outbox_restored','vault_restored_by_this_command'].some(key=>marker[key]!==complete)) fail('network_recovery_marker_invalid');
    return {anchor:{minimum_roster_version:safeInteger(marker.minimum_roster_version),last_verified_roster:marker.last_verified_roster as any,last_roster_sha256:marker.last_roster_sha256 as string|null},nodes:(marker.last_verified_node_directory as Obj|null|undefined)??undefined};
  }
  private async status(nonce: string, deadline?: number): Promise<{response: Obj; current: CurrentRoster; nodes: any}> {
    opaqueId(nonce);
    const recovery = this.recovery();
    const response = await this.http(this.authorityUrl,'POST','/v1/status',{network_id:this.networkId,nonce,request:this.request('status',{nonce})},deadline);
    return transaction(this.db(),()=>{
      const checked=verifyCurrentNodes(response as any,{network_id:this.networkId,issuers:this.issuers,nonce,now:now(),local_identity:this.localIdentity as any,
        previous_roster:this.state('roster'),recovery_anchor:recovery.anchor,previous_directory:this.state('node_directory'),recovery_directory:recovery.nodes,
        minimum_node_status_issued_at:this.state('node_status_issued_at')});
      this.put('roster',response.roster);
      if (checked.nodes) {this.put('node_directory',response.nodes);this.put('node_status_issued_at',response.node_status.payload.issued_at);}
      return {response,current:checked.current_roster,nodes:checked.nodes};
    });
  }
  private async refresh(relay: string, deadline?: number): Promise<{current:CurrentRoster;node:Obj|null}> {
    const challenge = await this.http(relay,'GET','/v1/status',undefined,deadline);
    const verified = await this.status(challenge.nonce,deadline), signed=challenge.node_challenge;
    let node:Obj|null=null;
    if (!verified.nodes) {if(signed!==undefined) fail('network_node_directory_required');}
    else {
      const entries=(verified.response.nodes.payload.nodes as Obj[]).filter(entry=>entry.base_url===relay&&['active','draining'].includes(entry.status));
      if (!signed) {if(entries.length || this.state('node:'+relay)) fail('network_node_identity_required');}
      else {
        node=transaction(this.db(),()=>{
          // Another endpoint process may have observed a later directory
          // while this refresh was awaiting I/O. Recheck under the same lock
          // used to alter incarnation bookkeeping, never roll it backward.
          const recovery=this.recovery();
          const latest=verifyCurrentNodes(verified.response as any,{network_id:this.networkId,issuers:this.issuers,nonce:challenge.nonce,now:now(),local_identity:this.localIdentity as any,
            previous_roster:this.state('roster'),recovery_anchor:recovery.anchor,previous_directory:this.state('node_directory'),recovery_directory:recovery.nodes,
            minimum_node_status_issued_at:this.state('node_status_issued_at')});
          if(!latest.nodes)fail('network_node_directory_required');
          const entry=authorizedNode(latest.nodes,signed.payload?.node?.signing_key?.key_id,'refresh',{now:now(),base_url:relay,storage_epoch:signed.payload?.node?.storage_epoch});
          const binding=verifyNodeChallenge(challenge as any,{node:entry,network_id:this.networkId,nonce:challenge.nonce,now:now()});
          if (!equal(this.state('node:'+relay)??null,binding)) {
            this.db().prepare('DELETE FROM state WHERE key=?').run('cursor:'+relay);
            for(const prefix of ['ack:'+relay+':','join:'+relay+':']) this.db().prepare('DELETE FROM state WHERE substr(key,1,?)=?').run(prefix.length,prefix);
            for(const row of this.db().prepare('SELECT request_id,receipts FROM outbox').all() as Obj[]) {
              const receipts=parse(row.receipts);if(relay in receipts){delete receipts[relay];this.db().prepare('UPDATE outbox SET receipts=? WHERE request_id=?').run(json(receipts),row.request_id);}
            }
            this.put('node:'+relay,binding);
          }
          return binding;
        });
      }
    }
    await this.http(relay,'POST','/v1/status',verified.response,deadline);
    transaction(this.db(),()=>this.assertNode(relay,node));
    return {current:verified.current,node};
  }
  connect(invitation?: Obj, requestId?: string): Promise<Obj> { return this.serial(()=>this.connectInternal(invitation,requestId)); }
  private async connectInternal(invitation?: Obj, requestId?: string): Promise<Obj> {
    let checked: any, expired=false;
    const options={network_id:this.networkId,issuers:this.issuers,now:now(),local_identity:this.localIdentity as any,encryption_identity:this.encryption};
    if (invitation) {
      try {checked=await verifyInvitationPackage(invitation as any,options);}
      catch(error) {
        if((error as any)?.code!=='network_control_expired') throw error;
        checked=await verifyInvitationPackage(invitation as any,{...options,now:invitation.invite?.payload?.issued_at});expired=true;
      }
    }
    const joined:string[]=[],errors:Obj[]=[];let last:CurrentRoster|undefined;
    for(const relay of this.relays) {
      try {
        const {current,node}=await this.refresh(relay);
        if(invitation) {
          const key='join:'+relay+':'+checked.invite.invite_id;
          let proof=this.state(key);
          const fresh=async()=>{
            if(expired) fail('network_control_expired');
            const challenge=(await this.http(relay,'POST','/v1/join',{invite:invitation.invite,roster:invitation.roster})).challenge;
            const answer=await openJoinChallenge(challenge,{identity:this.encryption,network_id:this.networkId,invite_id:checked.invite.invite_id,now:now()});
            return this.request('join',{invite_sha256:checked.invite_sha256,challenge_id:challenge.challenge_id,challenge_answer:answer},requestId);
          };
          if(proof) {if(proof.payload.body.invite_sha256!==checked.invite_sha256) fail('network_invitation_retry_conflict');}
          else {const candidate=await fresh();transaction(this.db(),()=>{this.assertNode(relay,node);this.db().prepare('INSERT OR IGNORE INTO state VALUES(?,?)').run(key,json(candidate));});proof=this.state(key);}
          const consume=()=>this.http(relay,'POST','/v1/join',{invite:invitation.invite,roster:invitation.roster,request:proof});
          let result;
          try {result=await consume();}
          catch(error) {
            if(expired||!['network_control_expired','relay_join_challenge_required'].includes((error as any)?.code)) throw error;
            const candidate=await fresh();transaction(this.db(),()=>{this.assertNode(relay,node);this.db().prepare('UPDATE state SET value=? WHERE key=? AND value=?').run(json(candidate),key,json(proof));proof=this.state(key);});result=await consume();
          }
          if(result.state!=='joined'||result.network_id!==this.networkId||result.member_key_id!==this.identity.key_id||result.invite_id!==checked.invite.invite_id) fail('network_invalid_join_receipt');
        } else await this.http(relay,'POST','/v1/poll',this.request('poll',{cursor:0,receipt_cursor:0,limit:1,maximum_bytes:MAX_WIRE}));
        transaction(this.db(),()=>this.assertNode(relay,node));
        joined.push(relay);last=current;
      } catch(error) {errors.push({node:this.relays.indexOf(relay),code:errorData(error).code});}
    }
    if(joined.length&&invitation?.handoff) await this.accept(invitation.handoff,last!);
    return {state:joined.length?'connected':'not_connected',joined_nodes:joined.length,configured_nodes:this.relays.length,degraded:joined.length!==this.relays.length,errors,member_key_id:this.identity.key_id,network_accessed:true};
  }
  discover():Promise<Obj>{return this.serial(async()=>{
    const {current}=await this.status(randomBytes(24).toString('hex'));
    const members=current.roster.payload.members.filter(member=>member.status==='active');
    return {network_id:this.networkId,members:members.slice(0,32).map(member=>({key_id:member.signing_key.key_id,scope:member.scope})),member_count:members.length,partial:members.length>32,configured_nodes:this.relays.length,network_accessed:true};
  });}
  private prepareBody(requestId:string,text:string,memoryIds:string[]):Uint8Array {
    const ids=[...memoryIds];
    if(text){const written=this.vault.remember({requestId:'req_'+sha256(Buffer.from('network-message:'+requestId)),kind:'observation',text});ids.push(written.memory_id);}
    const selected=[...new Set(ids)];let share:string|null=null;
    if(selected.length){const raw=this.vault.exportShare(selected,{maximumBytes:MAX_SHARE});if(raw.length>MAX_SHARE)fail('network_share_too_large_use_existing_pack');share=encodeBase64url(raw);}
    return canonicalBytes({schema_version:CONTENT_SCHEMA,text,share});
  }
  send(requestId:string,recipients:string[],text='',memoryIds:string[]=[]):Promise<Obj>{return this.serial(async()=>{
    opaqueId(requestId);
    if(!Array.isArray(recipients)||recipients.length<1||recipients.length>16||new Set(recipients).size!==recipients.length||recipients.some(key=>typeof key!=='string')||typeof text!=='string'||Buffer.byteLength(text)>16384)fail('network_invalid_send');
    if(!Array.isArray(memoryIds)||memoryIds.length>32)fail('network_invalid_memory_selection');
    if(!text&&!memoryIds.length)fail('network_empty_message');
    const inputSha=sha256(canonicalBytes({recipients,text,memory_ids:memoryIds}));
    const messageId='msg_'+sha256(canonicalBytes([this.networkId,this.identity.key_id,requestId]));
    let row=this.db().prepare('SELECT * FROM outbox WHERE request_id=?').get(requestId) as Obj|undefined;
    if(row&&row.input_sha!==inputSha)fail('network_request_id_conflict');
    if(row&&row.recipients===null){this.db().prepare('UPDATE outbox SET recipients=? WHERE request_id=? AND recipients IS NULL').run(canonicalBytes(recipients),requestId);row=this.db().prepare('SELECT * FROM outbox WHERE request_id=?').get(requestId) as Obj;}
    if(!row){
      const body=this.prepareBody(requestId,text,memoryIds);
      transaction(this.db(),()=>{
        const totals=this.db().prepare('SELECT COUNT(*) count,COALESCE(SUM(length(body)+COALESCE(length(envelope),0)),0) bytes FROM outbox').get() as Obj;
        if(totals.count>=1024||totals.bytes+body.length*3>MAX_QUEUE)fail('network_outbox_capacity');
        this.db().prepare('INSERT OR IGNORE INTO outbox(request_id,message_id,input_sha,body,recipients) VALUES(?,?,?,?,?)').run(requestId,messageId,inputSha,body,canonicalBytes(recipients));
        row=this.db().prepare('SELECT * FROM outbox WHERE request_id=?').get(requestId) as Obj;
        if(row.input_sha!==inputSha)fail('network_request_id_conflict');
      });
    }
    return this.deliver(row!,recipients);
  });}
  private receipts(row:Obj):Obj{return Object.fromEntries(Object.entries(parse(row.receipts)).filter(([key])=>this.relays.includes(key)));}
  private async deliver(prior:Obj,recipients:string[],deadline?:number,pendingOnly=false,firstNode=0):Promise<Obj>{
    let receipts=this.receipts(prior),envelope=prior.envelope?parse(prior.envelope):null,roster=prior.roster?parse(prior.roster):null;
    const errors:Obj[]=[];
    if(envelope&&!equal([...envelope.recipient_key_ids].sort(),[...recipients].sort()))fail('network_outbox_routing_mismatch');
    for(let offset=0;offset<this.relays.length;offset++){
      const relay=this.relays[(firstNode+offset)%this.relays.length];
      if(pendingOnly&&relay in receipts)continue;
      let nodeDeadline=deadline;
      if(pendingOnly&&deadline!==undefined){
        const remaining=this.relays.map((_,index)=>this.relays[(firstNode+index)%this.relays.length]).slice(offset).filter(node=>!(node in receipts)).length;
        const at=performance.now();nodeDeadline=at+Math.max(0,deadline-at)/remaining;
      }
      try{
        const {current,node}=await this.refresh(relay,nodeDeadline);
        if(nodeDeadline!==undefined&&performance.now()>=nodeDeadline)throw new NetworkError('network_budget_exhausted',true);
        authorizedMember(current,this.identity.key_id,'send',{now:now(),expected_identity:this.localIdentity as any});
        const destinations=recipients.map(id=>authorizedMember(current,id,'receive',{now:now()}));
        if(!envelope){
          const candidate=await seal(prior.body,{signer:this.identity,network_id:this.networkId,message_id:prior.message_id,
            recipients:destinations.map(member=>({signing_key_id:member.signing_key.key_id,encryption_key:member.encryption_key})),
            roster_version:current.roster.payload.version,roster_sha256:current.roster_sha256,created_at:now()});
          this.db().prepare('UPDATE outbox SET envelope=?,roster=? WHERE request_id=? AND envelope IS NULL').run(canonicalBytes(candidate),canonicalBytes(current.roster),prior.request_id);
          const stored=this.db().prepare('SELECT envelope,roster FROM outbox WHERE request_id=?').get(prior.request_id) as Obj;
          envelope=parse(stored.envelope);roster=parse(stored.roster);
        }
        const historical=verifyRoster(roster,{network_id:this.networkId,issuers:this.issuers,now:now(),allow_expired:true});
        for(const id of [this.identity.key_id,...recipients]){
          if(!equal(historical.members.find(member=>member.signing_key.key_id===id)??null,current.roster.payload.members.find(member=>member.signing_key.key_id===id)??null))fail('network_frozen_recipient_changed');
        }
        const result=await this.http(relay,'POST','/v1/messages',{envelope,roster},nodeDeadline);
        if(result.state!=='stored'||result.message_id!==prior.message_id||result.envelope_sha256!==documentSha256(envelope))fail('network_invalid_storage_receipt');
        transaction(this.db(),()=>{
          this.assertNode(relay,node);
          if(node)verifyStorageReceipt(result as any,{node:node as any,network_id:this.networkId,message_id:prior.message_id,envelope_sha256:documentSha256(envelope)});
          else if('node_receipt'in result)fail('network_node_identity_required');
          receipts=this.receipts(this.db().prepare('SELECT receipts FROM outbox WHERE request_id=?').get(prior.request_id) as Obj);
          receipts[relay]=result;this.db().prepare('UPDATE outbox SET receipts=? WHERE request_id=?').run(json(receipts),prior.request_id);
        });
      }catch(error){
        const detail=errorData(error);
        if(pendingOnly&&detail.code==='network_budget_exhausted'&&deadline!==undefined&&nodeDeadline!==undefined&&nodeDeadline<deadline&&performance.now()<deadline)detail.code='network_replica_send_budget';
        errors.push({node:this.relays.indexOf(relay),...detail});if(detail.code==='network_budget_exhausted')break;
      }
    }
    receipts=this.receipts(this.db().prepare('SELECT receipts FROM outbox WHERE request_id=?').get(prior.request_id) as Obj);
    const validated=(this.db().prepare('SELECT recipient FROM acknowledgements WHERE message_id=?').all(prior.message_id) as Obj[]).map(row=>row.recipient);
    return {state:Object.keys(receipts).length===this.relays.length?'stored':'queued_local',message_id:prior.message_id,stored_nodes:Object.keys(receipts).length,configured_nodes:this.relays.length,degraded:Object.keys(receipts).length<this.relays.length,validated_recipients:validated,endpoint_validated:recipients.every(key=>validated.includes(key)),understood:false,errors,retry_same_request_id:true};
  }
  private existing(messageId:string,digest:string):Obj|undefined{
    const row=this.db().prepare('SELECT * FROM inbox WHERE message_id=?').get(messageId) as Obj|undefined;
    if(row){if(row.digest!==digest)fail('network_inbox_identity_conflict');const result=parse(row.result),part=preview(result.text);result.text_partial=result.text_partial||part!==result.text;result.text=part;
      if(!('text_memory_id'in result)){const content=parse(row.body);result.text_memory_id=this.textReference(content);}return result;}
    const rejected=this.db().prepare('SELECT * FROM quarantine WHERE message_id=?').get(messageId) as Obj|undefined;
    if(rejected){if(rejected.digest!==digest)fail('network_inbox_identity_conflict');return {message_id:messageId,sender_key_id:rejected.sender,state:'rejected',code:rejected.code,understood:false};}
    return undefined;
  }
  private textReference(content:Obj):string|null{
    if(content.share===null)return null;
    const checked=parseShare(decodeBase64url(content.share,MAX_SHARE));
    return checked.records.find(item=>checked.roots.includes(item.record.memory_id)&&item.record.text===content.text)?.record.memory_id??null;
  }
  private reject(envelope:Obj,code:string):Obj{return transaction(this.db(),()=>{
    const digest=documentSha256(envelope),old=this.existing(envelope.message_id,digest);if(old)return old;
    const raw=canonicalBytes(envelope),totals=this.db().prepare('SELECT COUNT(*) count,COALESCE(SUM(length(envelope)),0) bytes FROM quarantine').get() as Obj;
    if(totals.count>=128||totals.bytes+raw.length>16*1024*1024)fail('network_quarantine_capacity');
    this.db().prepare('INSERT INTO quarantine VALUES(?,?,?,?,?)').run(envelope.message_id,digest,envelope.sender_key_id,raw,code);
    return {message_id:envelope.message_id,sender_key_id:envelope.sender_key_id,state:'rejected',code,understood:false};
  });}
  private async accept(envelope:Obj,current:CurrentRoster):Promise<Obj>{
    const peers=current.roster.payload.members.filter(member=>member.status==='active'),trusted=peers.map(member=>member.signing_key);
    const payload=verify(envelope,{network_id:this.networkId,trusted_signers:trusted});
    if(!payload.recipient_key_ids.includes(this.identity.key_id))fail('network_wrong_recipient');
    authorizedMember(current,this.identity.key_id,'receive',{now:now(),expected_identity:this.localIdentity as any});
    authorizedMember(current,payload.sender_key_id,'send',{now:now()});
    if(payload.roster_version>current.roster.payload.version||(payload.roster_version===current.roster.payload.version&&payload.roster_sha256!==current.roster_sha256))fail('network_envelope_roster_mismatch');
    const bindings=payload.recipient_key_ids.map(id=>{const member=authorizedMember(current,id,'receive',{now:now()});return {signing_key_id:id,encryption_key:member.encryption_key};});
    const body=await open(envelope,{network_id:this.networkId,trusted_signers:trusted,identity:this.encryption,recipient_bindings:bindings});
    const digest=documentSha256(envelope),old=this.existing(payload.message_id,digest);if(old)return old;
    let content:Obj;
    try{content=document(body);}catch{return this.reject(envelope,'network_invalid_content_json');}
    if(!equal(Object.keys(content).sort(),['schema_version','share','text'])||content.schema_version!==CONTENT_SCHEMA||typeof content.text!=='string'||Buffer.byteLength(content.text)>16384)return this.reject(envelope,'network_invalid_content');
    let imported:Obj|null=null;
    if(content.share!==null){
      let share:Uint8Array;
      try{share=decodeBase64url(content.share,MAX_SHARE);}catch{return this.reject(envelope,'network_invalid_content_share_encoding');}
      try{imported=this.vault.importShare(share,{admission:'verified'});}
      catch(error){if(!['unknown_key','revoked_key','share_record_signature_required','share_independent_trust_required'].includes((error as any)?.code))throw error;imported=this.vault.importShare(share,{admission:'quarantined'});}
    }
    const part=preview(content.text),result={message_id:payload.message_id,sender_key_id:payload.sender_key_id,text:part,text_partial:part!==content.text,text_memory_id:this.textReference(content),
      share:imported===null?null:{state:imported.state,records_added:imported.records_added,admission:imported.admission},state:'validated_saved',understood:false};
    return transaction(this.db(),()=>{
      const old=this.existing(payload.message_id,digest);if(old)return old;
      const totals=this.db().prepare('SELECT COUNT(*) count,COALESCE(SUM(length(body)),0) bytes FROM inbox').get() as Obj;
      if(totals.count>=4096||totals.bytes+body.length>MAX_QUEUE)fail('network_inbox_capacity');
      this.db().prepare('INSERT INTO inbox VALUES(?,?,?,?,?)').run(payload.message_id,digest,payload.sender_key_id,body,json(result));return result;
    });
  }
  receive(limit=4):Promise<Obj>{return this.serial(()=>this.receiveInternal(limit));}
  private async receiveInternal(limit=4,deadline?:number):Promise<Obj>{
    if(!Number.isSafeInteger(limit)||limit<1||limit>16)fail('network_invalid_limit');limit=Math.min(limit,4);
    const messages:Obj[]=[],errors:Obj[]=[],seen=new Set<string>();let unmatched=0;
    for(const relay of this.relays){
      if(messages.length>=limit)break;
      try{
        const {current,node}=await this.refresh(relay,deadline);
        const cursors=transaction(this.db(),()=>{this.assertNode(relay,node);return this.state('cursor:'+relay)??{cursor:0,receipt_cursor:0};});
        const page=await this.http(relay,'POST','/v1/poll',this.request('poll',{...cursors,limit:limit-messages.length,maximum_bytes:MAX_WIRE}),deadline);
        transaction(this.db(),()=>this.assertNode(relay,node));
        objectFields(page,['messages','cursor','receipts','receipt_cursor','has_more']);
        if(!Array.isArray(page.messages)||!Array.isArray(page.receipts)||page.messages.length>limit-messages.length||page.receipts.length>limit-messages.length||typeof page.has_more!=='boolean')fail('network_invalid_poll_page');
        const next={cursor:safeInteger(page.cursor),receipt_cursor:safeInteger(page.receipt_cursor)};
        if(next.cursor<cursors.cursor||next.receipt_cursor<cursors.receipt_cursor||next.cursor>4096||next.receipt_cursor>4096*32||(!page.receipts.length&&next.receipt_cursor!==cursors.receipt_cursor)||(page.messages.length&&next.cursor<=cursors.cursor)||(page.receipts.length&&next.receipt_cursor<=cursors.receipt_cursor))fail('network_invalid_cursor');
        for(const envelope of page.messages){
          const result=await this.accept(envelope,current);
          if(!seen.has(result.message_id)){messages.push(result);seen.add(result.message_id);}
          if(result.state==='rejected')continue;
          const key='ack:'+relay+':'+envelope.message_id,expected={message_id:envelope.message_id,envelope_sha256:documentSha256(envelope),state:'validated_saved'};
          let ack=transaction(this.db(),()=>{this.assertNode(relay,node);const prior=this.state(key);if(prior)return prior;const created=this.request('ack',expected);this.put(key,created);return created;});
          if(!equal(ack.payload.body,expected))fail('network_receipt_binding_mismatch');
          let response;
          try{response=await this.http(relay,'POST','/v1/ack',ack,deadline);}
          catch(error){if((error as any)?.code!=='network_control_expired')throw error;const fresh=this.request('ack',expected);transaction(this.db(),()=>{this.assertNode(relay,node);this.db().prepare('UPDATE state SET value=? WHERE key=? AND value=?').run(json(fresh),key,json(ack));ack=this.state(key);});response=await this.http(relay,'POST','/v1/ack',ack,deadline);}
          if(Object.entries(expected).some(([key,value])=>response[key]!==value)||response.recipient_key_id!==this.identity.key_id||safeInteger(response.receipt_sequence,1)>4096*32)fail('network_invalid_ack_receipt');
        }
        transaction(this.db(),()=>{
          this.assertNode(relay,node);
          const peers=current.roster.payload.members.filter(member=>member.status==='active');
          for(const receipt of page.receipts){
            const body=objectFields(receipt?.payload?.body,['message_id','envelope_sha256','state']);opaqueId(body.message_id);digestHex(body.envelope_sha256);
            const id=receipt?.proof?.key_id,known=this.db().prepare('SELECT receipt FROM acknowledgements WHERE message_id=? AND recipient=?').get(body.message_id as string,id) as Obj|undefined;
            if(known&&Buffer.from(known.receipt).equals(canonicalBytes(receipt)))continue;
            if(!peers.some(member=>member.signing_key.key_id===id&&member.scope.includes('receive'))){errors.push({node:this.relays.indexOf(relay),code:'network_receipt_peer_inactive',retryable:false});continue;}
            verifyRequest(receipt,{network_id:this.networkId,action:'ack',peers:peers.map(member=>member.signing_key),now:receipt.payload.issued_at});
            if(body.state!=='validated_saved')fail('network_receipt_binding_mismatch');
            const sent=this.db().prepare('SELECT envelope FROM outbox WHERE message_id=?').get(body.message_id as string) as Obj|undefined;
            if(!sent){unmatched++;continue;}if(!sent.envelope)fail('network_unexpected_receipt');
            const envelope=parse(sent.envelope);
            if(!envelope.recipient_key_ids.includes(id)||documentSha256(envelope)!==body.envelope_sha256)fail('network_receipt_binding_mismatch');
            this.db().prepare('INSERT OR IGNORE INTO acknowledgements VALUES(?,?,?)').run(body.message_id as string,id,canonicalBytes(receipt));
          }
          const latest=this.state('cursor:'+relay)??{cursor:0,receipt_cursor:0};
          this.put('cursor:'+relay,{cursor:Math.max(latest.cursor,next.cursor),receipt_cursor:Math.max(latest.receipt_cursor,next.receipt_cursor)});
        });
      }catch(error){const detail=errorData(error);errors.push({node:this.relays.indexOf(relay),...detail});if(detail.code==='network_budget_exhausted')break;}
    }
    return {messages,partial:messages.length>=limit,errors,unmatched_receipts:unmatched,network_accessed:true,receipts_mean:'endpoint_validated_saved_not_understood'};
  }
  private pending():Obj[]{
    const rows=this.db().prepare('SELECT rowid AS position,* FROM outbox ORDER BY rowid LIMIT 1025').all() as Obj[];
    if(rows.length>1024)fail('network_outbox_capacity');
    return rows.filter(row=>!this.relays.every(relay=>relay in this.receipts(row)));
  }
  private pumpStartNode():number{
    return transaction(this.db(),()=>{
      const cursor=safeInteger(this.state('pump_node_cursor')??0)%this.relays.length;
      this.put('pump_node_cursor',(cursor+1)%this.relays.length);return cursor;
    });
  }
  private async checkReplicaNodes(deadline:number,firstNode:number):Promise<Obj[]>{
    // Historical receipts survive outages. Only a verified new incarnation
    // invalidates them, before pending work is selected (even without poll).
    const rows=this.db().prepare('SELECT receipts FROM outbox LIMIT 1025').all() as Obj[];
    if(rows.length>1024)fail('network_outbox_capacity');
    const nodes=new Set<string>();
    for(const row of rows){
      const receipts=parse(row.receipts);
      if(receipts===null||typeof receipts!=='object'||Array.isArray(receipts))fail('network_invalid_storage_receipt');
      for(const relay of Object.keys(receipts))if(this.relays.includes(relay))nodes.add(relay);
    }
    const order=this.relays.map((_,offset)=>(firstNode+offset)%this.relays.length),checks:Obj[]=[];
    for(const index of order){
      const relay=this.relays[index];if(!nodes.has(relay))continue;
      if(performance.now()>=deadline){checks.push({node:index,state:'deferred',code:'network_replica_check_budget',retryable:true});continue;}
      try{
        const {node}=await this.refresh(relay,deadline);
        checks.push({node:index,state:'current',node_identity_verified:node!==null});
      }catch(error){const detail=errorData(error);if(detail.code==='network_budget_exhausted')detail.code='network_replica_check_budget';checks.push({node:index,state:'failed',...detail});}
    }
    return checks;
  }
  pump(maximumMessages=4,maximumSeconds=10,receiveLimit=4):Promise<Obj>{return this.serial(async()=>{
    if(!Number.isSafeInteger(maximumMessages)||maximumMessages<0||maximumMessages>16||!Number.isSafeInteger(maximumSeconds)||maximumSeconds<1||maximumSeconds>60||!Number.isSafeInteger(receiveLimit)||receiveLimit<0||receiveLimit>4)fail('network_invalid_pump_budget');
    const start=performance.now(),deadline=start+maximumSeconds*1000;
    const firstNode=maximumMessages?this.pumpStartNode():0;
    const replicaChecks=maximumMessages?await this.checkReplicaNodes(start+maximumSeconds*500,firstNode):[],rows=this.pending(),cursor=this.state('pump_cursor')??0;
    const errors:Obj[]=replicaChecks.filter(check=>check.state!=='current').map(({node,code,retryable})=>({node,code,retryable}));
    const ordered=[...rows.filter(row=>row.position>cursor),...rows.filter(row=>row.position<=cursor)],outbound:Obj[]=[],attempted=new Set<string>();
    for(const row of ordered.slice(0,maximumMessages)){
      if(performance.now()>=deadline)break;attempted.add(row.request_id);
      try{
        const recipients=row.recipients?parse(row.recipients):row.envelope?parse(row.envelope).recipient_key_ids:null;
        if(recipients===null)fail('network_outbox_recipients_unavailable');
        if(!Array.isArray(recipients)||recipients.length<1||recipients.length>16||new Set(recipients).size!==recipients.length)fail('network_outbox_routing_mismatch');recipients.forEach(opaqueId);
        const result=await this.deliver(row,recipients,deadline,true,firstNode);outbound.push({request_id:row.request_id,message_id:result.message_id,state:result.state,stored_nodes:result.stored_nodes,errors:result.errors});
      }catch(error){const detail=errorData(error);outbound.push({request_id:row.request_id,state:'queued_local',errors:[{...detail,requires_original_request:detail.code==='network_outbox_recipients_unavailable'}]});}
      this.put('pump_cursor',row.position);
    }
    const incoming=receiveLimit&&performance.now()<deadline?await this.receiveInternal(receiveLimit,deadline):null;
    const exhausted=performance.now()>=deadline;if(exhausted)errors.push({code:'network_budget_exhausted',retryable:true});
    const remaining=this.pending(),all=[...errors,...outbound.flatMap(item=>item.errors),...(incoming?.errors??[])];
    const pendingIds=new Set(remaining.map(row=>row.request_id));
    const retryPending=outbound.some(item=>pendingIds.has(item.request_id)&&item.errors.length===0);
    const retryable=exhausted||remaining.some(row=>!attempted.has(row.request_id))||retryPending||all.some(error=>error.retryable);
    return {state:exhausted?'budget_exhausted':retryable?'needs_retry':all.length?'needs_attention':'completed',outbound_attempted:attempted.size,outbound,remaining_outbox:remaining.length,receive:incoming,replica_checks:replicaChecks,errors,retryable,retry_after_ms:retryable?1000:0,elapsed_ms:Math.max(0,Math.floor(performance.now()-start)),budget_exhausted:exhausted,
      limits:{maximum_messages:maximumMessages,maximum_seconds:maximumSeconds,receive_limit:receiveLimit},deadline_semantics:'cooperative_no_new_requests_after_deadline',worker_started:false};
  });}
}
