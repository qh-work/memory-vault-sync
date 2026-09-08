/** Shared validation for the existing single-Vault client configuration. */
import * as fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {document} from './crypto.ts';
import {NetworkError,readPrivate} from './io.ts';
type Obj=Record<string,any>;
function fail(code:string):never{throw new NetworkError(code);}
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
export interface Client { path: string; vault: string; identity?: string; trust?: string; sync?: string }
export function loadClient(selected: string): Client {
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
