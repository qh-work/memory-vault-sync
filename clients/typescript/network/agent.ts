/** Independent native six-operation endpoint. Uses the same client config,
 * canonical SQLite Vault, identities, network queue and permission contracts.
 * Construction and offline discovery have no filesystem or network effects.
 * This is trusted endpoint code, never an untrusted relay decryption bridge.
 */
import * as fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { canonicalBytes, document, validateSigningIdentity } from './crypto.ts';
import type { SigningIdentityDocument } from './crypto.ts';
import { NetworkError, readPrivate } from './io.ts';
import { CanonicalVault } from './vault.ts';
import { NetworkPeer } from './peer.ts';
import { readTrustedKeys, requireTrustedKey } from './setup.ts';
import type { Transport } from './transport.ts';

type Obj = Record<string, any>;
export const OPERATIONS = Object.freeze(['connect', 'remember', 'recall', 'discover', 'send', 'receive']);
export const MAX_INPUT = 65536, MAX_RESULT = 8192;
const AUTHORITY = Object.freeze({ memory: 'untrusted_historical_evidence', instruction_eligible: false,
  authorization_eligible: false, execution_eligible: false, policy_change_eligible: false, current_user_input_precedence: true });
const PROVENANCE_REFS = ['agent_ref','conversation_ref','source_ref','model_ref','device_ref','request_ref','project_ref','task_ref'];
const EVIDENCE_USAGE = Object.freeze({basis: 'retrieved_historical_evidence',
  attribution: 'recorded_source_not_assumed_reader_experience', provenance_claims_authenticated: false,
  environment: 'current_environment_not_checked', prior_failure_policy: 'revalidate_changed_or_uncertain_environment', automatic_retry: false});
const REQUEST = /^req_[A-Za-z0-9_-]{8,96}$/;
const SPACE = /^[\u0009-\u000d\u001c-\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]*$/u;
function fail(code: string): never { throw new NetworkError(code); }
function object(value: unknown): value is Obj {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    [Object.prototype, null].includes(Object.getPrototypeOf(value));
}
/** Clone ordinary JSON values without invoking accessors, toJSON or a prototype.
 * Native input is JSON, not an arbitrary executable JavaScript object graph. */
function plain(value: unknown, depth = 0): any {
  if (depth > 64) fail('invalid_json_value');
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'number') { if (!Number.isFinite(value)) fail('invalid_json_value'); return value; }
  if (typeof value === 'string') { if (Buffer.from(value).toString('utf8') !== value) fail('invalid_json_value'); return value; }
  if (!Array.isArray(value) && !object(value)) fail('invalid_json_value');
  if (Array.isArray(value)) {
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if (Object.keys(descriptors).length !== value.length + 1) fail('invalid_json_value');
    return Array.from({length: value.length}, (_, i) => {
      const field = descriptors[String(i)]; if (!field || !('value' in field)) fail('invalid_json_value');
      return plain(field.value, depth + 1);
    });
  }
  const result: Obj = Object.create(null);
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string') fail('invalid_json_value');
    const field = Object.getOwnPropertyDescriptor(value, key)!;
    if (!field.enumerable || !('value' in field)) fail('invalid_json_value');
    result[key] = plain(field.value, depth + 1);
  }
  return result;
}
function encoded(value: unknown): Buffer { return Buffer.from(JSON.stringify(value), 'utf8'); }
function success(result: Obj, requestId?: unknown): Obj {
  return {schema_version: 'universal-agent-memory-result/v1', ok: true, result, authority: AUTHORITY,
    ...(requestId == null ? {} : {request_id: requestId})};
}
function failure(error: unknown, requestId?: unknown, commit = 'unknown'): Obj {
  const detail = error && typeof error === 'object' ? error as Obj : {};
  const candidate = typeof detail.code === 'string' ? detail.code : 'agent_unavailable';
  const code = /^[a-z][a-z0-9_]{1,63}$/.test(candidate) ? candidate : 'rejected', retryable = detail.retryable === true;
  return {schema_version: 'universal-agent-memory-result/v1', ok: false,
    error: {code, retryable, retry_after_ms: retryable ? 1000 : null, commit_state: detail.commit_state ?? commit},
    authority: AUTHORITY, ...(typeof requestId === 'string' && REQUEST.test(requestId) ? {request_id: requestId} : {})};
}
const text = {type: 'string', maxLength: 16384}, identifier = {type: 'string', pattern: REQUEST};
const shape = (properties: Obj, required: string[] = []): Obj => ({type: 'object', properties, required, additionalProperties: false});
const SHAPES: Obj = {
  connect: shape({invitation: {type: 'object'}, request_id: identifier}),
  remember: shape({request_id: identifier, kind: {type: 'string', enum: ['event','fact','observation','decision','artifact','entity','relation','provenance','summary','goal','continuity']},
    text, entities: {type: 'array', maxItems: 32, items: {type: 'string', maxLength: 512}},
    relations: {type: 'array', maxItems: 32, items: {type: 'object'}}}, ['request_id','kind','text']),
  recall: shape({query: text, memory_id: {type: 'string', maxLength: 64}, cursor: {type: 'string', maxLength: 4096}, handoff: {type: 'boolean'}}),
  discover: shape({online: {type: 'boolean'}}),
  send: shape({request_id: identifier, recipients: {type: 'array', maxItems: 16, items: {type: 'string', maxLength: 128}},
    text, memory_ids: {type: 'array', maxItems: 32, items: {type: 'string', maxLength: 64}}}, ['request_id','recipients']),
  receive: shape({limit: {type: 'integer', minimum: 1, maximum: 16}}),
};
function validate(value: unknown, schema: Obj): void {
  switch (schema.type) {
    case 'object': if (!object(value)) fail('invalid_client_arguments'); break;
    case 'string':
      if (typeof value !== 'string' || SPACE.test(value) || value.includes('\0') || Buffer.from(value).toString('utf8') !== value) fail('invalid_client_text');
      if (Buffer.byteLength(value) > (schema.maxLength ?? 1024 * 1024)) fail('client_text_too_large');
      if (schema.enum && !schema.enum.includes(value) || schema.pattern && !schema.pattern.test(value)) fail('invalid_client_arguments');
      break;
    case 'integer': if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < schema.minimum || value > schema.maximum) fail('invalid_client_arguments'); break;
    case 'boolean': if (typeof value !== 'boolean') fail('invalid_client_arguments'); break;
    case 'array':
      if (!Array.isArray(value) || value.length > schema.maxItems) fail('invalid_client_arguments');
      for (const child of value) validate(child, schema.items); break;
  }
  if (object(value)) {
    const properties = schema.properties ?? {};
    if ((schema.required ?? []).some((key: string) => !Object.hasOwn(value, key)) ||
        schema.additionalProperties === false && Object.keys(value).some(key => !Object.hasOwn(properties, key))) fail('invalid_client_arguments');
    for (const [key, child] of Object.entries(properties)) if (Object.hasOwn(value, key)) validate(value[key], child as Obj);
  }
}
function clientPath(value: unknown): string {
  if (typeof value !== 'string') fail('client_path_must_be_absolute');
  const expanded = value === '~' ? os.homedir() : value.startsWith('~/') ? path.join(os.homedir(), value.slice(2)) : value;
  if (!path.isAbsolute(expanded) || expanded.split(path.sep).includes('..')) fail('client_path_must_be_absolute');
  const selected = path.normalize(expanded);
  for (let current = selected; ; current = path.dirname(current)) {
    try { if (fs.lstatSync(current).isSymbolicLink()) fail('unsafe_client_path'); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
    if (path.dirname(current) === current) break;
  }
  return selected;
}
interface Client { path: string; vault: string; identity?: string; trust?: string; sync?: string }
function loadClient(selected: string): Client {
  const file = clientPath(selected); let raw: Buffer;
  try { raw = readPrivate(file, 16384)!; }
  catch (error) {
    const code = (error as Obj).code;
    if (code === 'ENOENT') fail('client_not_configured');
    if (code === 'unprotected_private_file') fail('client_file_not_private');
    if (code === 'network_document_too_large') fail('client_file_too_large');
    throw error;
  }
  const value = document(raw, 16384), required = ['schema_version','vault_path','capture_visible_turns'];
  const optional = ['identity_path','trust_path','sync_config_path'];
  if (required.some(key => !Object.hasOwn(value, key)) || Object.keys(value).some(key => ![...required,...optional].includes(key))) fail('invalid_client_arguments');
  if (value.schema_version !== 'memory-vault-client-config/v1' || typeof value.capture_visible_turns !== 'boolean') fail('invalid_client_config');
  if (value.identity_path != null && value.trust_path == null) fail('identity_requires_trust_store');
  const result: Client = {path: file, vault: clientPath(value.vault_path)};
  for (const [key, field] of [['identity','identity_path'],['trust','trust_path'],['sync','sync_config_path']] as const)
    if (value[field] != null) result[key] = clientPath(value[field]);
  const paths = Object.values(result);
  if (new Set(paths).size !== paths.length) fail('client_paths_must_be_separate');
  const base = path.basename(file), dot = base.lastIndexOf('.');
  const stem = dot > 0 && dot < base.length - 1 ? base.slice(0, dot) : base;
  const state = path.join(path.dirname(file), stem + '.state');
  if (paths.some(item => item === state || item.startsWith(state + path.sep))) fail('keys_and_vault_must_not_be_client_state');
  return result;
}
function identityFor(config: Client): SigningIdentityDocument | undefined {
  if (!config.identity) return undefined;
  let raw: Buffer;
  try { raw = readPrivate(config.identity, 4096)!; }
  catch (error) { if ((error as Obj)?.code === 'ENOENT') fail('identity_not_found'); throw error; }
  const identity = document(raw, 4096) as unknown as SigningIdentityDocument;
  const descriptor = validateSigningIdentity(identity);
  requireTrustedKey(config.trust!, descriptor.key_id);
  return identity;
}
function openVault(config: Client, write: boolean, identity?: SigningIdentityDocument): CanonicalVault {
  return new CanonicalVault({vaultPath: config.vault, ...(identity ? {identity} : {}),
    ...(config.trust ? {trust: () => {
      if (identity) requireTrustedKey(config.trust!, identity.key_id);
      return readTrustedKeys(config.trust!);
    }} : {historicalAdmissionOnly: true}),
    allowUnsignedLocal: write && !config.identity, readOnly: !write});
}
function localRead(config: Client, operation: (vault: CanonicalVault) => Obj): Obj {
  let vault: CanonicalVault | undefined;
  try { vault = openVault(config, false); return success(operation(vault)); }
  catch (error) { return failure(error, undefined, 'not_applicable'); }
  finally { vault?.close(); }
}
/** Valid UTF-8 input with Python errors=ignore at both pagination boundaries. */
function fragment(raw: Buffer, offset: number, maximum = 768): string {
  let start = offset, end = Math.min(raw.length, offset + maximum);
  while (start < end && (raw[start] & 0xc0) === 0x80) start++;
  while (end > start && end < raw.length && (raw[end] & 0xc0) === 0x80) end--;
  return raw.subarray(start, end).toString('utf8');
}
/** Bounded claims from the immutable source, not an authenticated biography. */
function evidenceMetadata(record: Obj): Obj {
  const provenance = record.provenance ?? {}, refs: Obj = {};
  let truncated = false, claimed = false;
  for (const key of PROVENANCE_REFS) {
    const original = provenance[key]; if (typeof original !== 'string') continue;
    claimed = true;
    let value = fragment(Buffer.from(original, 'utf8'), 0, 96);
    while (value && canonicalBytes({...refs, [key]: value}).length > 256) value = Array.from(value).slice(0,-1).join('');
    if (value) refs[key] = value;
    truncated ||= value !== original;
  }
  return {recorded_at: record.created_at, provenance_refs: refs,
    provenance_refs_truncated: truncated, provenance_status: claimed ? 'claimed' : 'unknown'};
}
function recallResult(hits: Obj[], remaining: unknown[], offset: number): Obj {
  return success({hits, next_cursor: remaining.length ? Buffer.from(canonicalBytes({ids: remaining, offset})).toString('base64url') : null,
    partial: remaining.length > 0, query_candidate_limit: 32, network_accessed: false, evidence_usage: {...EVIDENCE_USAGE}});
}

export class Agent {
  readonly clientConfigPath: string;
  readonly networkConfigPath?: string;
  private readonly transport?: Transport;
  constructor(clientConfigPath: string, networkConfigPath?: string, options: {transport?: Transport} = {}) {
    this.clientConfigPath = clientConfigPath; this.networkConfigPath = networkConfigPath; this.transport = options.transport;
  }
  discovery(): Obj {
    return {profile: 'network-v1', role: 'trusted_endpoint', operations: [...OPERATIONS], network_configured: this.networkConfigPath !== undefined,
      limits: {request_bytes: MAX_INPUT, result_bytes: MAX_RESULT}, memory_owned_by_task: false, memory_grants_authority: false,
      automatic_execution: false, network_accessed: false, http_requires_trusted_endpoint_crypto: true,
      legacy_interfaces_preserved: ['handoff','share-v1','backup','restore','protocol','mcp']};
  }
  private recall(args: Obj): Obj {
    const config = loadClient(this.clientConfigPath); let ids: unknown[], offset = 0;
    if (args.cursor) {
      if (Object.keys(args).length !== 1) fail('ambiguous_recall_cursor');
      try {
        const state = document(Buffer.from(args.cursor, 'base64url'), 4096);
        if (Object.keys(state).sort().join(',') !== 'ids,offset' || !Array.isArray(state.ids) || state.ids.length > 32 ||
            typeof state.offset !== 'number' || !Number.isSafeInteger(state.offset) || state.offset < 0) fail('invalid_recall_cursor');
        ids = state.ids; offset = state.offset;
      } catch { fail('invalid_recall_cursor'); }
    } else if (Object.hasOwn(args, 'memory_id')) {
      if (Object.keys(args).length !== 1) fail('ambiguous_recall_selector');
      ids = [args.memory_id];
    } else {
      if (!args.query) fail('recall_query_required');
      const result = localRead(config, vault => vault.retrieve({query: args.query, handoff: args.handoff === true, limit: 32, maximum_context_bytes: 512}));
      if (!result.ok) return result;
      ids = result.result.hits.map((hit: Obj) => hit.memory_id);
    }
    const remaining = [...ids], hits: Obj[] = [];
    while (remaining.length && hits.length < 4) {
      const result = localRead(config, vault => vault.inspect(remaining[0] as string));
      if (!result.ok) return result;
      const record = result.result.record, raw = Buffer.from(record.text, 'utf8');
      if (offset > raw.length || offset < raw.length && (raw[offset] & 0xc0) === 0x80) fail('invalid_recall_cursor');
      let maximum = 768, hit: Obj, next: number;
      while (true) {
        const text = fragment(raw, offset, maximum); next = offset + Buffer.byteLength(text);
        if (offset < raw.length && next === offset) fail('agent_result_exceeds_budget');
        hit = {memory_id: record.memory_id, record_sha256: record.record_sha256, kind: record.kind,
          text, text_offset_bytes: offset, partial: next < raw.length, verification: result.result.verification,
          source_ids: record.relations.filter((edge: Obj) => ['derived_from','supports'].includes(edge.type)).slice(0,8).map((edge: Obj) => edge.target),
          ...evidenceMetadata(record)};
        const afterIds = next < raw.length ? remaining : remaining.slice(1), afterOffset = next < raw.length ? next : 0;
        if (encoded(recallResult([...hits,hit],afterIds,afterOffset)).length <= MAX_RESULT) break;
        if (hits.length) return recallResult(hits,remaining,offset);
        maximum = Math.floor(maximum / 2);
        if (maximum < 1) fail('agent_result_exceeds_budget');
      }
      hits.push(hit);
      if (next < raw.length) { offset = next; break; }
      remaining.shift(); offset = 0;
    }
    return recallResult(hits,remaining,offset);
  }
  async handle(request: unknown): Promise<Obj> {
    let requestId: unknown;
    try {
      if (!object(request)) fail('invalid_agent_request');
      const value = plain(request) as Obj; requestId = value.request_id;
      if (encoded(value).length > MAX_INPUT) fail('invalid_agent_request');
      const operation = value.op;
      if (!OPERATIONS.includes(operation)) fail('unsupported_agent_operation');
      const args = Object.fromEntries(Object.entries(value).filter(([key]) => key !== 'op'));
      validate(args, SHAPES[operation]); let response: Obj;
      if (operation === 'discover' && !args.online) response = success(this.discovery());
      else if (operation === 'remember') {
        const config = loadClient(this.clientConfigPath), identity = identityFor(config);
        let vault: CanonicalVault | undefined;
        try {
          vault = openVault(config, true, identity);
          const input: Obj = {requestId: args.request_id, kind: args.kind, text: args.text};
          for (const key of ['entities','relations']) if (Object.hasOwn(args, key)) input[key] = args[key];
          const result = vault.remember(input as any);
          response = success({state: 'accepted_local', memory_id: result.memory_id, verification: result.verification, network_accessed: false}, requestId);
        } catch (error) { response = failure(error, requestId); }
        finally { vault?.close(); }
      } else if (operation === 'recall') response = this.recall(args);
      else {
        if (this.networkConfigPath === undefined) fail('network_not_configured');
        const peer = new NetworkPeer(this.networkConfigPath, {transport: this.transport, clientConfigPath: this.clientConfigPath});
        try {
          const result = operation === 'connect' ? await peer.connect(args.invitation, args.request_id) :
            operation === 'discover' ? await peer.discover() : operation === 'send' ? await peer.send(args.request_id, args.recipients, args.text ?? '', args.memory_ids ?? []) :
              await peer.receive(args.limit ?? 4);
          response = success(operation === 'receive' ? {...result,evidence_usage:{...EVIDENCE_USAGE}} : result, requestId);
        } finally { peer.close(); }
      }
      if (encoded(response).length > MAX_RESULT) fail('agent_result_exceeds_budget');
      return response;
    } catch (error) { return failure(error, requestId); }
  }
}
