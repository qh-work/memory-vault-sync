/** Bounded encrypted Hint vocabulary and explicitly configured local grants. */
import * as fs from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { canonicalBytes, document, objectFields, opaqueId } from './crypto.ts';
import type { DocumentInput } from './crypto.ts';
import { readPrivate, privateDirectory, NetworkError } from './io.ts';

export const HINT_SCHEMA = 'memory-vault-hint/v4';
export const POLICY_SCHEMA = 'memory-vault-hint-policy/v1';
export const SESSION_SCHEMA = 'memory-vault-hint-session/v2';
export const SESSION_PREFIX = 'hint-session:';
export const MAX_SESSION_BYTES = 32768;
export interface Hint { memory_id: string; excerpt: string; epistemic_type: string }
export interface HintSelection { offer_message_id: string; memory_id: string }
export type HintControl =
  {schema_version: typeof HINT_SCHEMA; kind: 'query'; query: string; expires_at: number} |
  {schema_version: typeof HINT_SCHEMA; kind: 'page'; query_message_id: string; cursor: string} |
  {schema_version: typeof HINT_SCHEMA; kind: 'hints'; request_message_id: string; query_message_id: string; page_index: number; policy_revision: number; expires_at: number; hints: Hint[]; next_cursor: string | null} |
  {schema_version: typeof HINT_SCHEMA; kind: 'select'; query_message_id: string; selections: HintSelection[]} |
  {schema_version: typeof HINT_SCHEMA; kind: 'cancel'; query_message_id: string; offer_message_id: string; expires_at: number} |
  {schema_version: typeof HINT_SCHEMA; kind: 'cancel_ack'; request_message_id: string; query_message_id: string; expires_at: number} |
  {schema_version: typeof HINT_SCHEMA; kind: 'refusal'; request_message_id: string; reason: 'not_available'};
export interface HintGrant { key_id: string; hint_memory_ids: string[]; record_memory_ids: string[] }
export interface HintPolicy {
  schema_version: typeof POLICY_SCHEMA; network_id: string; owner_key_id: string;
  revision: number; expires_at: number; peers: HintGrant[];
}
interface SessionCommon {
  schema_version: typeof SESSION_SCHEMA; network_id: string; owner_key_id: string;
  peer_key_id: string; query_message_id: string; query: string; expires_at: number;
  state: 'active' | 'cancelled'; cancellation: null | {message_id: string; offer_message_id: string; expires_at: number};
}
export type RequesterSession = SessionCommon & {role: 'requester'};
export type OwnerSession = SessionCommon & {role: 'owner'; policy_revision: number; policy_sha256: string; hints: Hint[]; cursors: string[]};
export type HintSession = RequesterSession | OwnerSession;
const memory = /^mem_[0-9a-f]{40}$/;
const message = /^msg_[0-9a-f]{64}$/;
const signer = /^ed25519_[0-9a-f]{64}$/;
const EPISTEMIC_TYPES = new Set(['observation','experiment','inference','hearsay','speculation','summary','external_source','unspecified']);
function fail(code = 'network_invalid_content'): never { throw new NetworkError(code); }
export function hintMemoryId(value: unknown): string {
  if (typeof value !== 'string' || value.length !== 44 || !memory.test(value)) fail(); return value;
}
export function hintMessageId(value: unknown): string {
  if (typeof value !== 'string' || value.length !== 68 || !message.test(value)) fail(); return value;
}
function integer(value: unknown, minimum = 0): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < minimum) fail(); return value;
}
function cursor(value:unknown):string {
  if(typeof value!=='string'||value.length!==72||!/^hintcur_[0-9a-f]{64}$/.test(value))fail();return value;
}
function query(value:unknown):string {
  if(typeof value!=='string'||!value.length||Buffer.byteLength(value)>256)fail();return value;
}
function hints(value:unknown,maximum:number):Hint[] {
  if(!Array.isArray(value)||value.length>maximum)fail();
  const ids=new Set<string>();
  for(const item of value){
    const hint=objectFields(item,['memory_id','excerpt','epistemic_type'],'network_invalid_content');
    const id=hintMemoryId(hint.memory_id);if(ids.has(id))fail();ids.add(id);
    if(typeof hint.excerpt!=='string'||Buffer.byteLength(hint.excerpt)>128||!EPISTEMIC_TYPES.has(hint.epistemic_type as string))fail();
  }
  return value;
}
export function validateHintControl(value: DocumentInput): HintControl {
  try {
    const control = document(value, 4096);
    if (control.schema_version !== HINT_SCHEMA) fail();
    if (control.kind === 'query') {
      objectFields(control, ['schema_version','kind','query','expires_at'], 'network_invalid_content');
      query(control.query);integer(control.expires_at,1);
    } else if(control.kind==='page'){
      objectFields(control,['schema_version','kind','query_message_id','cursor'],'network_invalid_content');
      hintMessageId(control.query_message_id);cursor(control.cursor);
    } else if (control.kind === 'hints') {
      objectFields(control, ['schema_version','kind','request_message_id','query_message_id','page_index','policy_revision','expires_at','hints','next_cursor'], 'network_invalid_content');
      hintMessageId(control.request_message_id);hintMessageId(control.query_message_id);integer(control.expires_at,1);integer(control.policy_revision,1);
      const page=integer(control.page_index);if(page>3)fail();
      const items=hints(control.hints,4);
      if(control.next_cursor!==null)cursor(control.next_cursor);
      if(page===3&&control.next_cursor!==null||control.next_cursor!==null&&items.length!==4||page>0&&!items.length)fail();
    } else if (control.kind === 'select') {
      objectFields(control, ['schema_version','kind','query_message_id','selections'], 'network_invalid_content');
      hintMessageId(control.query_message_id);
      if(!Array.isArray(control.selections)||control.selections.length<1||control.selections.length>4)fail();
      const selected=new Set<string>();
      for(const value of control.selections){
        const item=objectFields(value,['offer_message_id','memory_id'],'network_invalid_content');
        hintMessageId(item.offer_message_id);const id=hintMemoryId(item.memory_id);
        if(selected.has(id))fail();selected.add(id);
      }
    } else if(control.kind==='cancel'||control.kind==='cancel_ack'){
      objectFields(control,['schema_version','kind','query_message_id','expires_at',control.kind==='cancel'?'offer_message_id':'request_message_id'],'network_invalid_content');
      hintMessageId(control.query_message_id);hintMessageId(control.kind==='cancel'?control.offer_message_id:control.request_message_id);integer(control.expires_at,1);
    } else if (control.kind === 'refusal') {
      objectFields(control, ['schema_version','kind','request_message_id','reason'], 'network_invalid_content');
      hintMessageId(control.request_message_id); if (control.reason !== 'not_available') fail();
    } else fail();
    canonicalBytes(control, 4096);
    return control as HintControl;
  } catch { fail(); }
}
/** Shared local shape, used by both runtimes without conferring live authority. */
export function validateHintSession(key:string,value:DocumentInput,networkId:string,ownerKeyId:string):HintSession {
  try{
    const session=document(value,MAX_SESSION_BYTES),fields=['schema_version','role','network_id','owner_key_id','peer_key_id','query_message_id','query','expires_at','state','cancellation'];
    if(session.role==='owner')fields.push('policy_revision','policy_sha256','hints','cursors');
    else if(session.role!=='requester')fail();
    objectFields(session,fields);
    if(session.schema_version!==SESSION_SCHEMA||session.network_id!==networkId||session.owner_key_id!==ownerKeyId||key!==SESSION_PREFIX+hintMessageId(session.query_message_id))fail();
    for(const value of [session.owner_key_id,session.peer_key_id])if(typeof value!=='string'||value.length!==72||!signer.test(value))fail();
    query(session.query);integer(session.expires_at,1);
    if(session.state==='active'){if(session.cancellation!==null)fail();}
    else if(session.state==='cancelled'){
      const cancellation=objectFields(session.cancellation,['message_id','offer_message_id','expires_at']);
      hintMessageId(cancellation.message_id);hintMessageId(cancellation.offer_message_id);
      if(integer(cancellation.expires_at,1)>(session.expires_at as number))fail();
    }else fail();
    if(session.role==='owner'){
      integer(session.policy_revision,1);
      if(typeof session.policy_sha256!=='string'||session.policy_sha256.length!==64||!/^[0-9a-f]{64}$/.test(session.policy_sha256))fail();
      const items=hints(session.hints,16),ids=items.map(item=>item.memory_id);
      if(ids.some((id,index)=>index>0&&id<=ids[index-1]))fail();
      if(!Array.isArray(session.cursors)||session.cursors.length!==Math.max(0,Math.ceil(items.length/4)-1)||new Set(session.cursors.map(cursor)).size!==session.cursors.length)fail();
    }
    canonicalBytes(session,MAX_SESSION_BYTES);return session as unknown as HintSession;
  }catch{fail('network_hint_not_available');}
}
export function validateHintPolicy(value: DocumentInput, networkId: string, ownerKeyId: string): HintPolicy {
  try {
    const policy = objectFields(document(value,65536), ['schema_version','network_id','owner_key_id','revision','expires_at','peers']);
    if (policy.schema_version !== POLICY_SCHEMA || opaqueId(policy.network_id) !== networkId || policy.owner_key_id !== ownerKeyId || ownerKeyId.length !== 72 || !signer.test(ownerKeyId)) fail();
    integer(policy.revision,1); integer(policy.expires_at,1);
    if (!Array.isArray(policy.peers) || policy.peers.length > 16) fail();
    const peers = new Set<string>();
    for (const value of policy.peers) {
      const peer = objectFields(value,['key_id','hint_memory_ids','record_memory_ids']);
      if (typeof peer.key_id !== 'string' || peer.key_id.length !== 72 || !signer.test(peer.key_id) || peers.has(peer.key_id)) fail(); peers.add(peer.key_id);
      for (const name of ['hint_memory_ids','record_memory_ids']) {
        const ids = peer[name];
        if (!Array.isArray(ids) || ids.length > 128 || new Set(ids.map(hintMemoryId)).size !== ids.length) fail();
      }
    }
    canonicalBytes(policy,65536); return policy as unknown as HintPolicy;
  } catch { fail('network_invalid_hint_policy'); }
}
export function readHintPolicy(file: string, networkId: string, ownerKeyId: string, at: number): HintPolicy {
  try {
    const raw = readPrivate(file,65536,true); if (!raw) fail();
    const policy = validateHintPolicy(raw,networkId,ownerKeyId);
    if (policy.expires_at <= at) fail(); return policy;
  } catch { fail('network_hint_not_available'); }
}
/** Caller holds the existing transport database transaction for cross-runtime
 * revision serialization. No database key, memory object or remote grant exists. */
export function writeHintPolicy(file: string, value: DocumentInput, networkId: string, ownerKeyId: string, at: number): HintPolicy {
  const policy = validateHintPolicy(value,networkId,ownerKeyId);
  if (policy.expires_at <= at || policy.expires_at > at + 86400) fail('network_invalid_hint_policy');
  privateDirectory(path.dirname(file));
  const bytes = canonicalBytes(policy,65536), prior = readPrivate(file,65536,true);
  if (prior) {
    const previous = validateHintPolicy(prior,networkId,ownerKeyId);
    if (policy.revision < previous.revision || policy.revision === previous.revision && !Buffer.from(bytes).equals(canonicalBytes(previous))) fail('network_hint_policy_revision_conflict');
    if (policy.revision === previous.revision) return policy;
  }
  const temporary = path.join(path.dirname(file),'.hint-policy-'+randomBytes(16).toString('hex'));
  let fd: number | undefined;
  try {
    fd = fs.openSync(temporary,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
    fs.writeFileSync(fd,bytes); fs.fsyncSync(fd); fs.closeSync(fd); fd = undefined;
    fs.renameSync(temporary,file);
    const directory = fs.openSync(path.dirname(file),fs.constants.O_RDONLY|fs.constants.O_DIRECTORY|fs.constants.O_NOFOLLOW);
    try { fs.fsyncSync(directory); } finally { fs.closeSync(directory); }
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
    try { fs.unlinkSync(temporary); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
  }
  return policy;
}
export function grantFor(policy: HintPolicy, recipient: string): HintGrant {
  const grant = policy.peers.find(peer => peer.key_id === recipient);
  if (!grant) fail('network_hint_not_available'); return grant;
}
