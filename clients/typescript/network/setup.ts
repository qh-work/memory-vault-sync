/** Explicit, new-only local candidate setup. No Python, sockets, services,
 * Vault creation, issuer enrollment or authority issuance. Private inputs are
 * always selected paths, never discovered from a home directory/environment.
 */
import * as fs from 'node:fs';
import path from 'node:path';
import { generateKeyPairSync } from 'node:crypto';
import {
  canonicalBytes, document, objectFields, sha256, opaqueId, decodeBase64url,
  validateSigningIdentity, validateEncryptionIdentity, validateSigningPublic,
  NetworkCryptoError,
} from './crypto.ts';
import type { DocumentInput, SigningIdentityDocument, SigningPublicDescriptor, EncryptionIdentityDocument } from './crypto.ts';
import { absolutePath, readPrivate, NetworkError } from './io.ts';
import { origin } from './transport.ts';

const CLIENT_SCHEMA = 'memory-vault-client-config/v1';
const TRUST_SCHEMA = 'universal-memory-trust-store/v1';
const NETWORK_SCHEMA = 'memory-vault-network-client/v1';
const MAX_TRUST = 2 * 1024 * 1024;
type Obj = Record<string, unknown>;
export interface IdentityCreated {
  readonly state: 'identity_created'; readonly member_key_id: string;
  readonly public_member_file: string; readonly client_config: string; readonly encryption_key: string;
  readonly capture_visible_turns: false; readonly vault_created: false; readonly network_accessed: false;
  readonly services_started: false; readonly keys_enrolled: false;
}
export interface ConfigureNetworkOptions {
  readonly clientConfig: string; readonly encryptionKey: string; readonly issuerPublic: string;
  readonly networkId: string; readonly authorityUrl: string; readonly relays: readonly string[];
  readonly output: string;
}
export interface NetworkConfigured {
  readonly state: 'network_configured'; readonly config: string; readonly member_key_id: string;
  readonly issuer_key_shared_with_endpoint: boolean; readonly warning: string | null;
  readonly network_accessed: false; readonly keys_enrolled: false; readonly services_started: false;
  readonly vault_created: false;
}
function fail(code: string): never { throw new NetworkError(code); }
function checked<T>(operation: () => T): T {
  try { return operation(); }
  catch (error) {
    if (error instanceof NetworkCryptoError) throw error;
    fail('network_setup_storage_unavailable');
  }
}
function uid(): number {
  if (process.platform === 'win32' || !process.getuid) fail('protected_storage_platform_unavailable');
  return process.getuid();
}
function stat(value: string): fs.Stats | null {
  try { return fs.lstatSync(value); }
  catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null; throw error; }
}
/** Validate existing ancestry without creating any missing directories. The
 * operator may choose a normal owner-readable parent, but not another user's
 * directory, a symlink, or an untrusted writable ancestor. */
function safePath(value: unknown, missingAncestors = false): string {
  const selected = absolutePath(value), owner = uid();
  for (let current = path.dirname(selected); ; current = path.dirname(current)) {
    const info = stat(current);
    if (info === null) { if (!missingAncestors) fail('network_setup_parent_missing'); }
    else if (!info.isDirectory() || info.isSymbolicLink() || (info.uid !== owner && info.uid !== 0) ||
             ((info.mode & 0o022) !== 0 && !(info.uid === 0 && (info.mode & 0o1000)))) fail('unsafe_storage_path');
    if (path.dirname(current) === current) break;
  }
  const existing = stat(selected);
  if (existing?.isSymbolicLink()) fail('unsafe_storage_path');
  return selected;
}
function same(left: fs.Stats, right: fs.Stats | null): boolean {
  return right !== null && left.dev === right.dev && left.ino === right.ino;
}
function syncDirectory(directory: string): void {
  const fd = fs.openSync(directory, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_DIRECTORY);
  try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}
/** New O_EXCL files only. Never rename over, chmod, or truncate an existing
 * pathname. Strict fsync failure is an error, including directory flush. */
function newFile(value: string, encoded: Uint8Array): fs.Stats {
  const selected = safePath(value);
  let fd: number;
  try { fd = fs.openSync(selected, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL |
                        fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK, 0o600); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'EEXIST') fail('network_setup_file_exists');
    throw error;
  }
  const created = fs.fstatSync(fd);
  try {
    fs.fchmodSync(fd, 0o600);
    let offset = 0;
    while (offset < encoded.length) {
      const written = fs.writeSync(fd, encoded, offset, encoded.length - offset);
      if (!written) fail('network_setup_storage_unavailable');
      offset += written;
    }
    fs.fsyncSync(fd);
    if (!same(created, stat(selected))) fail('network_setup_path_changed');
    syncDirectory(path.dirname(selected));
    return created;
  } catch (error) {
    // Remove only this operation's inode. A concurrent replacement is not ours.
    try { if (same(created, stat(selected))) fs.unlinkSync(selected); } catch { /* original failure wins */ }
    throw error;
  } finally { fs.closeSync(fd); }
}
function encoded(value: unknown, maximum = 65536): Uint8Array {
  return Buffer.concat([canonicalBytes(value, maximum), Buffer.from('\n')]);
}
function readDocument(value: string, maximum: number): Obj {
  const raw = readPrivate(safePath(value), maximum);
  if (raw === null) fail('network_admin_file_missing');
  return document(raw, maximum);
}
/** Public trust anchors need not be 0600. Still reject symlinks, hardlinks,
 * special files, unsafe ancestry, overlarge inputs and changes during reading. */
function publicDocument(value: string): Obj {
  const selected = safePath(value), fd = fs.openSync(selected, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try {
    const before = fs.fstatSync(fd);
    if (!before.isFile() || before.nlink !== 1 || before.size > 16384 ||
        (before.uid !== uid() && before.uid !== 0) || (before.mode & 0o022)) fail('network_invalid_issuer_public_file');
    const buffer = Buffer.alloc(before.size); let offset = 0;
    while (offset < buffer.length) {
      const count = fs.readSync(fd, buffer, offset, buffer.length - offset, null);
      if (!count) break;
      offset += count;
    }
    const after = fs.fstatSync(fd);
    if (offset !== before.size || after.size !== before.size || after.mtimeMs !== before.mtimeMs ||
        after.ctimeMs !== before.ctimeMs || !same(before, stat(selected))) fail('network_source_changed');
    return document(buffer, 16384);
  } finally { fs.closeSync(fd); }
}
function timestamp(value: unknown): void {
  if (typeof value !== 'string') fail('invalid_trust_store');
  const match = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,6}))?Z$/.exec(value);
  if (!match || match[0] !== value) fail('invalid_trust_store');
  const [year, month, day, hour, minute, second] = match.slice(1, 7).map(Number);
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const lengths = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (year < 1 || month < 1 || month > 12 || day < 1 || day > lengths[month-1] || hour > 23 || minute > 59 || second > 59) fail('invalid_trust_store');
}
/** A trust file has exactly ONE numeric value: its signed-64 revision. Replace
 * that integer token by zero before the shared strict parser, retaining its
 * exact BigInt value for range checking. All other fields are strings/objects
 * or null; their shape is checked below. No float, duplicate name, numeric
 * string or extra numeric field can become a valid trust document. This is
 * local trust-file decoding only: network JSON remains the safe-integer profile.
 */
function trustDocument(raw: Uint8Array): Obj {
  let source: string;
  try { source = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(raw); }
  catch { fail('invalid_trust_store'); }
  let inside = false, escaped = false, token: string | undefined, start = -1, end = -1;
  for (let i = 0; i < source.length; i++) {
    const character = source[i];
    if (inside) {
      if (escaped) escaped = false;
      else if (character === '\\') escaped = true;
      else if (character === '"') inside = false;
      continue;
    }
    if (character === '"') { inside = true; continue; }
    if (character === '-' || /[0-9]/.test(character)) {
      if (token !== undefined) fail('invalid_trust_store');
      const matched = /^-?(?:0|[1-9][0-9]*)/.exec(source.slice(i));
      if (!matched || matched[0].length > 20) fail('invalid_trust_store');
      token = matched[0]; start = i; end = i + token.length; i = end - 1;
    }
  }
  if (token === undefined || BigInt(token) < 0n || BigInt(token) >= 9223372036854775808n) fail('invalid_trust_store');
  const value = objectFields(document(Buffer.from(source.slice(0, start) + '0' + source.slice(end)), MAX_TRUST),
                             ['schema_version', 'revision', 'keys'], 'invalid_trust_store');
  if (value.schema_version !== TRUST_SCHEMA) fail('unsupported_trust_store_schema');
  if (value.revision !== 0 || value.keys === null || typeof value.keys !== 'object' || Array.isArray(value.keys) ||
      Object.keys(value.keys).length > 1024) fail('invalid_trust_store');
  return value;
}
/** Current local trust only. Does not create/update the store, enroll any key,
 * treat a configured issuer as a memory author, or inspect remembered content. */
export function readTrustedKeys(trustPath: string): SigningPublicDescriptor[] {
  return checked(() => {
    const selected = safePath(trustPath, true);
    if (stat(selected) === null) return [];
    const raw = readPrivate(selected, MAX_TRUST, true);
    if (raw === null) return [];
    const trust = trustDocument(raw), keys: SigningPublicDescriptor[] = [];
    for (const [id, value] of Object.entries(trust.keys as Obj)) {
      const entry = objectFields(value, ['descriptor', 'label', 'state', 'added_at', 'revoked_at'], 'invalid_trust_store');
      const descriptor = validateSigningPublic(entry.descriptor as DocumentInput);
      if (id !== descriptor.key_id || typeof entry.label !== 'string' || Buffer.byteLength(entry.label) > 256 || /[\x00-\x1f]/u.test(entry.label)) fail('invalid_trust_store');
      timestamp(entry.added_at);
      if (entry.state === 'trusted' && entry.revoked_at === null) keys.push(descriptor);
      else if (entry.state === 'revoked') timestamp(entry.revoked_at);
      else fail('invalid_trust_store');
    }
    return keys;
  });
}
/** Preserve the existing local trust error distinction for configured writers.
 * A second read is only used to explain rejection; it can never grant trust. */
export function requireTrustedKey(trustPath: string, keyId: string): void {
  if (readTrustedKeys(trustPath).some(key => key.key_id === keyId)) return;
  const raw = readPrivate(trustPath, MAX_TRUST, true);
  if (raw !== null) {
    const value = trustDocument(raw), entry = (value.keys as Obj)[keyId] as Obj | undefined;
    if (entry?.state === 'revoked') fail('key_revoked');
  }
  fail('unknown_key');
}
function overlaps(directory: string, file: string): boolean {
  return directory === file || file.startsWith(directory + path.sep) || directory.startsWith(file + path.sep);
}
function stem(value: string): string {
  const name = path.basename(value), dot = name.lastIndexOf('.');
  // Python pathlib.Path.stem retains a trailing dot (Node path.parse does not).
  return dot > 0 && dot < name.length - 1 ? name.slice(0, dot) : name;
}
interface ClientPaths { client: string; vault: string; identity: string; trust: string; sync: string | null }
function clientPaths(value: string): ClientPaths {
  const client = safePath(value), raw = readDocument(client, 16384);
  const required = ['schema_version', 'vault_path', 'capture_visible_turns'];
  const allowed = [...required, 'identity_path', 'trust_path', 'sync_config_path'];
  if (required.some(key => !Object.hasOwn(raw, key)) || Object.keys(raw).some(key => !allowed.includes(key)) ||
      raw.schema_version !== CLIENT_SCHEMA || typeof raw.capture_visible_turns !== 'boolean') fail('invalid_client_config');
  if (typeof raw.identity_path !== 'string' || typeof raw.trust_path !== 'string') fail('network_signing_identity_required');
  const vault = safePath(raw.vault_path, true), identity = safePath(raw.identity_path), trust = safePath(raw.trust_path);
  const sync = raw.sync_config_path == null ? null : safePath(raw.sync_config_path, true);
  const all = [client, vault, identity, trust, ...(sync === null ? [] : [sync])];
  if (new Set(all).size !== all.length) fail('client_paths_must_be_separate');
  const state = path.join(path.dirname(client), stem(client) + '.state');
  if (all.some(file => state === file || file.startsWith(state + path.sep))) fail('keys_and_vault_must_not_be_client_state');
  return { client, vault, identity, trust, sync };
}

export function createIdentity(directory: string): IdentityCreated {
  return checked(() => {
    const selected = safePath(directory);
    if (stat(selected) !== null) fail('network_setup_directory_exists');
    // Two separate provider key generations; no conversion/derivation between
    // the signing identity and encryption identity.
    const signer = generateKeyPairSync('ed25519'), encryptor = generateKeyPairSync('x25519');
    const signingPrivate = signer.privateKey.export({ format: 'jwk' }), signingPublic = signer.publicKey.export({ format: 'jwk' });
    const encryptionPrivate = encryptor.privateKey.export({ format: 'jwk' }), encryptionPublic = encryptor.publicKey.export({ format: 'jwk' });
    const signingRaw = decodeBase64url(signingPublic.x, 32, 32), encryptionRaw = decodeBase64url(encryptionPublic.x, 32, 32);
    const identity: SigningIdentityDocument = { schema_version: 'universal-memory-identity/v1', algorithm: 'Ed25519',
      key_id: 'ed25519_' + sha256(signingRaw), public_key: Buffer.from(signingRaw).toString('base64'),
      private_key: Buffer.from(decodeBase64url(signingPrivate.d, 32, 32)).toString('base64') };
    const encryption: EncryptionIdentityDocument = { schema_version: 'memory-vault-network-encryption-identity/v1', algorithm: 'X25519',
      key_id: 'x25519_' + sha256(encryptionRaw), public_key: Buffer.from(encryptionRaw).toString('base64url'),
      private_key: Buffer.from(decodeBase64url(encryptionPrivate.d, 32, 32)).toString('base64url') };
    const signingKey = validateSigningIdentity(identity), encryptionKey = validateEncryptionIdentity(encryption);
    const files: Record<string, Uint8Array> = {
      'identity.json': encoded(identity), 'encryption.json': encoded(encryption),
      'trust.json': encoded({ schema_version: TRUST_SCHEMA, revision: 1, keys: { [signingKey.key_id]: {
        descriptor: signingKey, label: '', state: 'trusted', added_at: new Date().toISOString(), revoked_at: null } } }),
      // This is a public candidate preference in the existing member format.
      // Only the independently configured issuer can grant actual membership.
      'member-public.json': encoded({ signing_key: signingKey, encryption_key: encryptionKey, status: 'active', scope: ['receive', 'send'] }),
      'client.json': encoded({ schema_version: CLIENT_SCHEMA, vault_path: path.join(selected, 'vault', 'memory.sqlite3'),
        capture_visible_turns: false, identity_path: path.join(selected, 'identity.json'), trust_path: path.join(selected, 'trust.json') }),
    };
    const createdFiles: [string, fs.Stats][] = [];
    let createdDirectory: fs.Stats | undefined;
    try {
      fs.mkdirSync(selected, { mode: 0o700 });
      createdDirectory = fs.lstatSync(selected);
      if (!createdDirectory.isDirectory() || createdDirectory.uid !== uid() || (createdDirectory.mode & 0o077)) fail('unprotected_private_directory');
      syncDirectory(path.dirname(selected));
      for (const [name, raw] of Object.entries(files)) {
        const target = path.join(selected, name);
        createdFiles.push([target, newFile(target, raw)]);
      }
    } catch (error) {
      // Only roll back inodes created by this invocation. Never recursively
      // delete a directory that acquired somebody else's concurrent files.
      if (createdDirectory && same(createdDirectory, stat(selected))) {
        for (const [target, info] of createdFiles.reverse()) {
          try { if (same(info, stat(target))) fs.unlinkSync(target); } catch { /* preserve original error */ }
        }
        try { fs.rmdirSync(selected); syncDirectory(path.dirname(selected)); } catch { /* may remain partial, never claim success */ }
      }
      throw error;
    }
    return { state: 'identity_created', member_key_id: identity.key_id, public_member_file: path.join(selected, 'member-public.json'),
      client_config: path.join(selected, 'client.json'), encryption_key: path.join(selected, 'encryption.json'),
      capture_visible_turns: false, vault_created: false, network_accessed: false, services_started: false, keys_enrolled: false };
  });
}
export function configureNetwork(options: ConfigureNetworkOptions): NetworkConfigured {
  return checked(() => {
    const raw = objectFields(document(options as unknown as DocumentInput, 65536),
      ['clientConfig', 'encryptionKey', 'issuerPublic', 'networkId', 'authorityUrl', 'relays', 'output']);
    const networkId = opaqueId(raw.networkId), authorityUrl = origin(raw.authorityUrl);
    if (!Array.isArray(raw.relays) || raw.relays.length < 1 || raw.relays.length > 2) fail('network_one_or_two_relays_required');
    const relays = raw.relays.map(origin);
    if (new Set(relays).size !== relays.length) fail('network_duplicate_relay');
    const output = safePath(raw.output), encryptionPath = safePath(raw.encryptionKey), issuerPath = safePath(raw.issuerPublic);
    if (stat(output) !== null) fail('network_config_exists');
    const client = clientPaths(raw.clientConfig as string);
    const state = path.join(path.dirname(output), stem(output) + '-state');
    const paths = [output, client.client, client.identity, client.trust, client.vault, encryptionPath,
      issuerPath, ...(client.sync === null ? [] : [client.sync])];
    if (new Set(paths).size !== paths.length || paths.some(file => overlaps(state, file))) fail('network_configuration_path_conflict');
    // A new config must not silently attach an unrelated previous transport
    // history. Recovery/migration, which validates bindings, is a separate task.
    if (stat(state) !== null) fail('network_setup_state_exists');
    const identity = readDocument(client.identity, 4096) as unknown as SigningIdentityDocument;
    const signer = validateSigningIdentity(identity);
    const trusted = readTrustedKeys(client.trust);
    if (!trusted.some(key => key.key_id === signer.key_id)) fail('unknown_key');
    validateEncryptionIdentity(readDocument(encryptionPath, 4096) as unknown as EncryptionIdentityDocument);
    // Exact public schema rejects a private identity file, even if it belongs
    // to the selected issuer. No issuer is added to memory-author trust here.
    const issuer = validateSigningPublic(publicDocument(issuerPath));
    const configuration = { schema_version: NETWORK_SCHEMA, network_id: networkId, client_config_path: client.client,
      state_directory: state, encryption_key_path: encryptionPath, issuer_public_key: issuer, relays, authority_url: authorityUrl };
    const bytes = encoded(configuration);
    // Recheck current trust before the only output mutation.
    if (!readTrustedKeys(client.trust).some(key => key.key_id === signer.key_id)) fail('unknown_key');
    newFile(output, bytes);
    const shared = signer.key_id === issuer.key_id;
    return { state: 'network_configured', config: output, member_key_id: signer.key_id,
      issuer_key_shared_with_endpoint: shared,
      warning: shared ? 'Endpoint holds issuer signing authority; separate roles are not isolated in this explicit legacy configuration.' : null,
      network_accessed: false, keys_enrolled: false, services_started: false, vault_created: false };
  });
}
