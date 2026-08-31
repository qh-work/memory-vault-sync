/** Native storage-node authentication. No transport, persistence or enrollment. */
import { isIP } from 'node:net';
import {
  NetworkCryptoError, canonicalBytes, document, documentSha256, verifyMessage,
  validateSigningPublic, objectFields, safeInteger, opaqueId, digestHex,
} from './crypto.ts';
import type { DocumentInput, JsonValue, MessageProof, SigningPublicDescriptor } from './crypto.ts';
import { verifyRoster, verifyCurrentRoster } from './control.ts';
import type { SignedControl, Roster, IssuerOptions, CurrentRosterOptions, CurrentRoster } from './control.ts';

export const DIRECTORY_SCHEMA = 'memory-vault-node-directory/v1';
export const NODE_STATUS_SCHEMA = 'memory-vault-node-status/v1';
export const NODE_CHALLENGE_SCHEMA = 'memory-vault-node-challenge/v1';
export const STORAGE_RECEIPT_SCHEMA = 'memory-vault-node-storage-receipt/v1';
export const MAX_NODES = 256;
export const MAX_STORAGE_RECEIPT_BYTES = 16 * 1024;
export const MAX_OUTBOX_RECEIPT_ROW_BYTES = 64 * 1024;
export const MAX_OUTBOX_RECEIPTS_BYTES = 16 * 1024 * 1024;
const MAX_CONTROL_BYTES = 1024 * 1024;
type Obj = Record<string, unknown>;
type Window = { readonly issued_at: number; readonly expires_at: number };
export type NodeScope = 'node.status' | 'export' | 'import';
export type NodeAction = 'refresh' | 'export' | 'import';
export interface NodeDescriptor {
  readonly signing_key: SigningPublicDescriptor;
  readonly base_url: string;
  readonly storage_epoch: string;
}
export interface NodeEntry extends NodeDescriptor {
  readonly scope: readonly NodeScope[];
  readonly status: 'active' | 'draining' | 'revoked';
}
export interface NodeDirectory extends Window {
  readonly schema_version: typeof DIRECTORY_SCHEMA;
  readonly network_id: string;
  readonly version: number;
  readonly previous_sha256: string;
  readonly nodes: readonly NodeEntry[];
}
export interface NodeStatus extends Window {
  readonly schema_version: typeof NODE_STATUS_SCHEMA;
  readonly network_id: string;
  readonly nonce: string;
  readonly roster_sha256: string;
  readonly roster_version: number;
  readonly directory_sha256: string;
  readonly directory_version: number;
}
export interface DirectoryOptions extends IssuerOptions {
  readonly minimum_version?: number;
  readonly expected_previous_sha256?: string;
  readonly previous_directory?: SignedControl<NodeDirectory> | DocumentInput;
  /** Historical inspection only; active use requires a fresh node status. */
  readonly allow_expired?: boolean;
}
export interface NodeStatusOptions extends IssuerOptions {
  readonly nonce: string;
  readonly previous_directory?: SignedControl<NodeDirectory> | DocumentInput;
  readonly recovery_directory?: SignedControl<NodeDirectory> | DocumentInput;
  readonly minimum_issued_at?: number;
}
export interface CurrentNodesOptions extends CurrentRosterOptions {
  readonly previous_directory?: SignedControl<NodeDirectory> | DocumentInput;
  readonly recovery_directory?: SignedControl<NodeDirectory> | DocumentInput;
  readonly minimum_node_status_issued_at?: number;
  /** Reject an unsigned legacy node even before the first stored checkpoint. */
  readonly require_nodes?: boolean;
}
/** Verified in-memory capability; serialized copies must be verified again. */
export interface CurrentNodes {
  readonly directory: SignedControl<NodeDirectory>;
  readonly node_status: SignedControl<NodeStatus>;
  readonly directory_sha256: string;
}
export interface CurrentNodeControl {
  readonly current_roster: CurrentRoster;
  readonly nodes: CurrentNodes | null;
}
export interface StoredReceipt {
  readonly state: 'stored';
  readonly message_id: string;
  readonly envelope_sha256: string;
  readonly sequence: number;
}
const currentStates = new WeakMap<CurrentNodes, { directory: NodeDirectory; status: NodeStatus }>();

function fail(code: string): never { throw new NetworkCryptoError(code); }
function doc(value: unknown, maximum = MAX_CONTROL_BYTES): Record<string, JsonValue> {
  return document(value as DocumentInput, maximum);
}
function same(left: unknown, right: unknown): boolean {
  return Buffer.from(canonicalBytes(left)).equals(Buffer.from(canonicalBytes(right)));
}
function freeze<T>(value: T): T {
  if (value !== null && typeof value === 'object') {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}
function validity(value: Obj | Window, now: number, allowExpired = false): void {
  const issued = safeInteger(value.issued_at), expires = safeInteger(value.expires_at);
  const current = safeInteger(now);
  if (expires - issued < 1 || expires - issued > 300) fail('network_invalid_validity');
  if (issued > current + 30) fail('network_control_from_future');
  if (!allowExpired && expires <= current) fail('network_control_expired');
}
function signed<T>(value: SignedControl<T> | DocumentInput, issuers: readonly SigningPublicDescriptor[]): SignedControl<T> {
  const raw = objectFields(doc(value), ['payload', 'proof']);
  const payload = doc(raw.payload);
  verifyMessage(payload, raw.proof as DocumentInput, issuers);
  return { payload: payload as unknown as T, proof: raw.proof as unknown as MessageProof };
}

/** Preserve signed URL bytes. Never normalize a different URL into an identity. */
export function validateNodeUrl(value: unknown): string {
  if (typeof value !== 'string' || !value || value.length > 2048 || /\s|\\/.test(value)) fail('network_node_invalid_url');
  const match = /^(https?):\/\/([^/?#]+)$/i.exec(value);
  if (!match || match[2].includes('@')) fail('network_node_invalid_url');
  const authority = match[2];
  const parts = authority.startsWith('[') ? /^\[([^\]]+)\](?::([0-9]+))?$/.exec(authority)
    : /^([^:]+)(?::([0-9]+))?$/.exec(authority);
  if (!parts) fail('network_node_invalid_url');
  const host = parts[1];
  if (parts[2] !== undefined && (!Number.isSafeInteger(Number(parts[2])) || Number(parts[2]) < 1 || Number(parts[2]) > 65535)) fail('network_node_invalid_url');
  if (authority.startsWith('[') && isIP(host) !== 6) fail('network_node_invalid_url');
  let parsed: URL;
  try { parsed = new URL(value); } catch { fail('network_node_invalid_url'); }
  // WHATWG accepts 127.1, octal and numeric aliases. Python's ipaddress does
  // not call those loopback, so never use URL normalization for this decision.
  const loopback = host.toLowerCase() === 'localhost' || (isIP(host) === 4 && host.split('.')[0] === '127')
    || (isIP(host) === 6 && parsed.hostname === '[::1]');
  if (match[1].toLowerCase() !== 'https' && !loopback) fail('network_node_https_required');
  return value;
}
export function validateNodeDescriptor(value: NodeDescriptor | DocumentInput): NodeDescriptor {
  const raw = objectFields(doc(value, 8192), ['signing_key', 'base_url', 'storage_epoch']);
  validateSigningPublic(raw.signing_key as DocumentInput);
  validateNodeUrl(raw.base_url); opaqueId(raw.storage_epoch);
  return raw as unknown as NodeDescriptor;
}
export function validateNode(value: NodeEntry | DocumentInput): NodeEntry {
  const raw = objectFields(doc(value, 8192), ['signing_key', 'base_url', 'storage_epoch', 'scope', 'status']);
  validateNodeDescriptor({ signing_key: raw.signing_key, base_url: raw.base_url, storage_epoch: raw.storage_epoch });
  const scopes = raw.scope;
  if (!Array.isArray(scopes) || !scopes.length || scopes.some((item, index) =>
    !['node.status', 'export', 'import'].includes(item) || (index > 0 && item <= scopes[index - 1]))) fail('network_node_invalid_scope');
  if (!['active', 'draining', 'revoked'].includes(raw.status as string)) fail('network_node_invalid_status');
  return raw as unknown as NodeEntry;
}
function directoryPayload(value: NodeDirectory, options: IssuerOptions & { allow_expired?: boolean }): NodeDirectory {
  const raw = objectFields(value, ['schema_version', 'network_id', 'version', 'previous_sha256', 'nodes', 'issued_at', 'expires_at']);
  if (raw.schema_version !== DIRECTORY_SCHEMA || opaqueId(raw.network_id) !== opaqueId(options.network_id)) fail('network_node_directory_binding_mismatch');
  const version = safeInteger(raw.version, 1), previous = digestHex(raw.previous_sha256);
  if ((version === 1) !== (previous === '0'.repeat(64))) fail('network_node_directory_genesis_mismatch');
  if (!Array.isArray(raw.nodes) || raw.nodes.length > MAX_NODES) fail('network_node_directory_limit');
  const entries = raw.nodes.map(value => validateNode(value));
  const epochs = new Set<string>(), urls = new Set<string>();
  for (let index = 0; index < entries.length; index++) {
    const entry = entries[index];
    if ((index > 0 && entry.signing_key.key_id <= entries[index - 1].signing_key.key_id)
      || epochs.has(entry.storage_epoch) || (entry.status !== 'revoked' && urls.has(entry.base_url))) fail('network_node_directory_duplicate');
    epochs.add(entry.storage_epoch);
    if (entry.status !== 'revoked') urls.add(entry.base_url);
  }
  validity(raw, options.now, options.allow_expired === true);
  return raw as unknown as NodeDirectory;
}

export function verifyDirectory(value: SignedControl<NodeDirectory> | DocumentInput, options: DirectoryOptions): NodeDirectory {
  const incoming = signed(value, options.issuers);
  const raw = directoryPayload(incoming.payload as NodeDirectory, options);
  if (raw.version < safeInteger(options.minimum_version ?? 0)) fail('network_node_directory_rollback');
  if (options.expected_previous_sha256 !== undefined && raw.previous_sha256 !== digestHex(options.expected_previous_sha256)) fail('network_node_directory_chain_mismatch');
  if (options.previous_directory === undefined) return raw;
  const previous = signed(options.previous_directory, options.issuers);
  const old = directoryPayload(previous.payload as NodeDirectory, { ...options, allow_expired: true });
  if (raw.version < old.version || raw.issued_at < old.issued_at) fail('network_node_directory_rollback');
  const previousHash = documentSha256(previous as unknown as DocumentInput);
  if (raw.version === old.version) {
    if (documentSha256(incoming as unknown as DocumentInput) !== previousHash) fail('network_node_directory_version_conflict');
    return raw;
  }
  if (raw.version === old.version + 1 && raw.previous_sha256 !== previousHash) fail('network_node_directory_chain_mismatch');
  const current = new Map(raw.nodes.map(entry => [entry.signing_key.key_id, entry]));
  const transitions = { active: ['active', 'draining', 'revoked'], draining: ['draining', 'revoked'], revoked: ['revoked'] };
  for (const entry of old.nodes) {
    const replacement = current.get(entry.signing_key.key_id);
    if (!replacement) fail('network_node_tombstone_required');
    if (!same(entry.signing_key, replacement.signing_key) || entry.base_url !== replacement.base_url || entry.storage_epoch !== replacement.storage_epoch) fail('network_node_identity_changed');
    if (!transitions[entry.status].includes(replacement.status)) fail('network_node_reactivation_forbidden');
  }
  return raw;
}

/** Both documents are signed; this does not replace the separate member status. */
export function verifyNodeStatus(value: SignedControl<NodeStatus> | DocumentInput,
  directoryValue: SignedControl<NodeDirectory> | DocumentInput, rosterValue: SignedControl<Roster> | DocumentInput,
  options: NodeStatusOptions): NodeStatus {
  const directoryDoc = doc(directoryValue), rosterDoc = doc(rosterValue);
  if (options.recovery_directory !== undefined) verifyDirectory(directoryDoc, { ...options,
    previous_directory: options.recovery_directory, allow_expired: true });
  const directory = verifyDirectory(directoryDoc, { ...options, allow_expired: true });
  const roster = verifyRoster(rosterDoc, { ...options, allow_expired: true });
  const raw = objectFields(signed(value, options.issuers).payload,
    ['schema_version', 'network_id', 'nonce', 'roster_sha256', 'roster_version', 'directory_sha256', 'directory_version', 'issued_at', 'expires_at']);
  if (raw.schema_version !== NODE_STATUS_SCHEMA || opaqueId(raw.network_id) !== opaqueId(options.network_id)
    || opaqueId(raw.nonce) !== opaqueId(options.nonce)) fail('network_node_status_binding_mismatch');
  if (digestHex(raw.roster_sha256) !== documentSha256(rosterDoc) || safeInteger(raw.roster_version, 1) !== roster.version
    || digestHex(raw.directory_sha256) !== documentSha256(directoryDoc) || safeInteger(raw.directory_version, 1) !== directory.version) fail('network_node_status_checkpoint_mismatch');
  validity(raw, options.now);
  if (safeInteger(raw.issued_at) < safeInteger(options.minimum_issued_at ?? 0)) fail('network_node_status_rollback');
  return raw as unknown as NodeStatus;
}

/** Verify the full issuer HTTP response before an atomic host checkpoint write. */
export function verifyCurrentNodes(value: DocumentInput, options: CurrentNodesOptions): CurrentNodeControl {
  const raw = doc(value, 4 * MAX_CONTROL_BYTES);
  const names = Object.keys(raw);
  if (!names.includes('status') || !names.includes('roster') || names.some(name => !['status', 'roster', 'nodes', 'node_status'].includes(name))) fail('network_invalid_document');
  const hasDirectory = names.includes('nodes'), hasStatus = names.includes('node_status');
  if (hasDirectory !== hasStatus) fail('network_node_status_incomplete');
  if (!hasDirectory && (options.previous_directory !== undefined || options.recovery_directory !== undefined
    || options.require_nodes === true || options.minimum_node_status_issued_at !== undefined)) fail('network_node_directory_downgrade');
  const currentRoster = verifyCurrentRoster(raw.roster as DocumentInput, raw.status as DocumentInput, options);
  if (!hasDirectory) return { current_roster: currentRoster, nodes: null };
  const status = verifyNodeStatus(raw.node_status as DocumentInput, raw.nodes as DocumentInput, raw.roster as DocumentInput,
    { ...options, minimum_issued_at: options.minimum_node_status_issued_at });
  const directoryDoc = doc(raw.nodes) as unknown as SignedControl<NodeDirectory>;
  const directory = verifyDirectory(directoryDoc, { ...options, allow_expired: true });
  const current: CurrentNodes = freeze({ directory: directoryDoc, node_status: doc(raw.node_status) as unknown as SignedControl<NodeStatus>,
    directory_sha256: documentSha256(directoryDoc as unknown as DocumentInput) });
  currentStates.set(current, { directory: freeze(directory), status: freeze(status) });
  return { current_roster: currentRoster, nodes: current };
}
export function authorizedNode(current: CurrentNodes, keyId: string, action: NodeAction,
  options: { now: number; base_url?: string; storage_epoch?: string }): NodeEntry {
  const state = currentStates.get(current);
  if (!state) fail('network_verified_control_required');
  validity(state.status, options.now);
  opaqueId(keyId);
  if (!['refresh', 'export', 'import'].includes(action)) fail('network_node_action_rejected');
  const entry = state.directory.nodes.find(item => item.signing_key.key_id === keyId);
  if (!entry) fail('network_node_authorization_required');
  if (entry.status === 'revoked' || (action === 'import' && entry.status !== 'active')) fail('network_node_inactive');
  if (!entry.scope.includes(action === 'refresh' ? 'node.status' : action)) fail('network_node_scope_denied');
  if ((options.base_url !== undefined && validateNodeUrl(options.base_url) !== entry.base_url)
    || (options.storage_epoch !== undefined && opaqueId(options.storage_epoch) !== entry.storage_epoch)) fail('network_node_identity_changed');
  return doc(entry, 8192) as unknown as NodeEntry;
}

/** node must come from authorizedNode, never from the challenge's own key. */
export function verifyNodeChallenge(value: DocumentInput, options: {
  node: NodeEntry; network_id: string; nonce: string; now: number;
}): NodeDescriptor {
  const node = validateNode(options.node);
  if (node.status === 'revoked') fail('network_node_inactive');
  if (!node.scope.includes('node.status')) fail('network_node_scope_denied');
  const raw = doc(value, 16384);
  if (!Object.hasOwn(raw, 'node_challenge')) fail('network_node_identity_required');
  objectFields(raw, ['nonce', 'expires_at', 'current_roster_version', 'current_roster_sha256', 'node_challenge']);
  const payload = objectFields(signed(raw.node_challenge as DocumentInput, [node.signing_key]).payload,
    ['schema_version', 'network_id', 'node', 'nonce', 'issued_at', 'expires_at']);
  const binding = validateNodeDescriptor(payload.node as DocumentInput);
  const expected = { signing_key: node.signing_key, base_url: node.base_url, storage_epoch: node.storage_epoch };
  if (payload.schema_version !== NODE_CHALLENGE_SCHEMA || opaqueId(payload.network_id) !== opaqueId(options.network_id)
    || opaqueId(payload.nonce) !== opaqueId(options.nonce) || raw.nonce !== payload.nonce
    || safeInteger(raw.expires_at) !== safeInteger(payload.expires_at) || !same(binding, expected)) fail('network_node_challenge_mismatch');
  safeInteger(raw.current_roster_version, 1); digestHex(raw.current_roster_sha256);
  validity(payload, options.now);
  return binding;
}

/** Verify full /messages response against the current, independently bound node.
 * Receipts have no freshness window: they prove a historical storage assertion,
 * not current retention, fault-domain independence, understanding or execution.
 */
export function verifyStorageReceipt(value: DocumentInput, options: {
  node: NodeDescriptor | null; network_id: string; message_id: string; envelope_sha256: string;
  allow_legacy_unsigned?: boolean;
}): StoredReceipt {
  const raw = doc(value, MAX_STORAGE_RECEIPT_BYTES);
  opaqueId(options.network_id);
  const binding = options.node === null ? null : validateNodeDescriptor(options.node);
  if (binding === null) {
    if (options.allow_legacy_unsigned !== true || Object.hasOwn(raw, 'node_receipt')) fail('network_node_identity_required');
  } else if (!Object.hasOwn(raw, 'node_receipt')) fail('network_node_identity_required');
  objectFields(raw, ['state', 'message_id', 'envelope_sha256', 'sequence', ...(binding === null ? [] : ['node_receipt'])]);
  const receipt = { state: raw.state, message_id: raw.message_id, envelope_sha256: raw.envelope_sha256, sequence: raw.sequence };
  if (receipt.state !== 'stored' || opaqueId(receipt.message_id) !== opaqueId(options.message_id)
    || digestHex(receipt.envelope_sha256) !== digestHex(options.envelope_sha256)) fail('network_invalid_storage_receipt');
  safeInteger(receipt.sequence, 1);
  if (binding === null) return receipt as StoredReceipt;
  const payload = objectFields(signed(raw.node_receipt as DocumentInput, [binding.signing_key]).payload,
    ['schema_version', 'network_id', 'node', 'receipt']);
  if (payload.schema_version !== STORAGE_RECEIPT_SCHEMA || opaqueId(payload.network_id) !== opaqueId(options.network_id)
    || !same(validateNodeDescriptor(payload.node as DocumentInput), binding) || !same(payload.receipt, receipt)) fail('network_node_receipt_mismatch');
  return receipt as StoredReceipt;
}
