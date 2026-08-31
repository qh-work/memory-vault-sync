/** Native network-v1 control checks. No transport, persistence or enrollment. */
import { timingSafeEqual } from 'node:crypto';
import {
  NetworkCryptoError, canonicalBytes, document, documentSha256, signMessage, verifyMessage,
  validateSigningPublic, validateEncryptionPublic, objectFields, safeInteger, opaqueId,
  digestHex, signingKeyId, decodeBase64url, encodeBase64url, sha256, decryptBytes, open,
} from './crypto.ts';
import type {
  DocumentInput, JsonValue, MessageProof, SigningPublicDescriptor, SigningIdentityDocument,
  EncryptionPublicDescriptor, EncryptionIdentityDocument, Envelope,
} from './crypto.ts';

export const INVITE_SCHEMA = 'memory-vault-network-invite/v1';
export const ROSTER_SCHEMA = 'memory-vault-network-roster/v1';
export const STATUS_SCHEMA = 'memory-vault-network-status/v1';
export const REQUEST_SCHEMA = 'memory-vault-network-request/v1';
export const CHALLENGE_SCHEMA = 'memory-vault-network-join-challenge/v1';
export const MAX_CONTROL_BYTES = 1024 * 1024;
export const MAX_MEMBERS = 256;
export const MAX_VALIDITY_SECONDS = 300;
export type Scope = 'send' | 'receive';
export type RequestAction = 'join' | 'messages' | 'poll' | 'ack' | 'status';
type Obj = Record<string, unknown>;
type Window = { readonly issued_at: number; readonly expires_at: number };
export interface SignedControl<T> { readonly payload: T; readonly proof: MessageProof }
export interface Member {
  readonly signing_key: SigningPublicDescriptor;
  readonly encryption_key: EncryptionPublicDescriptor;
  readonly status: 'active' | 'revoked';
  readonly scope: readonly Scope[];
}
export interface Roster extends Window {
  readonly schema_version: typeof ROSTER_SCHEMA;
  readonly network_id: string;
  readonly version: number;
  readonly previous_sha256: string;
  readonly members: readonly Member[];
}
export interface Status extends Window {
  readonly schema_version: typeof STATUS_SCHEMA;
  readonly network_id: string;
  readonly nonce: string;
  readonly roster_sha256: string;
  readonly roster_version: number;
}
export interface Invite extends Window {
  readonly schema_version: typeof INVITE_SCHEMA;
  readonly network_id: string;
  readonly invite_id: string;
  readonly candidate_signing_key: SigningPublicDescriptor;
  readonly candidate_encryption_key: EncryptionPublicDescriptor;
  readonly scope: readonly Scope[];
  readonly handoff_sha256: string;
  readonly roster_sha256: string;
}
export interface SignedRequestPayload extends Window {
  readonly schema_version: typeof REQUEST_SCHEMA;
  readonly network_id: string;
  readonly action: RequestAction;
  readonly request_id: string;
  readonly body: Readonly<Record<string, JsonValue>>;
}
export interface IssuerOptions {
  readonly network_id: string;
  /** Operator-pinned issuer keys; incoming members never extend this set. */
  readonly issuers: readonly SigningPublicDescriptor[];
  /** Explicit trusted host clock in integer Unix seconds. */
  readonly now: number;
}
export interface RosterOptions extends IssuerOptions {
  readonly minimum_version?: number;
  readonly expected_previous_sha256?: string;
  /** Inert inspection only; use verifyCurrentRoster for active authorization. */
  readonly allow_expired?: boolean;
}
export interface StatusOptions extends IssuerOptions {
  /** A fresh unpredictable challenge supplied and tracked by the host. */
  readonly nonce: string;
  readonly roster_sha256?: string;
  readonly roster_version?: number;
}
export interface LocalPublicIdentity {
  readonly signing_key: SigningPublicDescriptor;
  readonly encryption_key: EncryptionPublicDescriptor;
}
export interface RecoveryAnchor {
  readonly minimum_roster_version: number;
  readonly last_verified_roster: SignedControl<Roster> | DocumentInput | null;
  readonly last_roster_sha256: string | null;
}
export interface CurrentRosterOptions extends IssuerOptions {
  readonly nonce: string;
  readonly previous_roster?: SignedControl<Roster> | DocumentInput;
  readonly recovery_anchor?: RecoveryAnchor;
  readonly local_identity?: LocalPublicIdentity;
}
/** In-memory verified capability; a JSON copy must be verified again. */
export interface CurrentRoster {
  readonly roster: SignedControl<Roster>;
  readonly status: SignedControl<Status>;
  readonly roster_sha256: string;
}
const currentStates = new WeakMap<CurrentRoster, { roster: Roster; status: Status }>();

function fail(code: string): never { throw new NetworkCryptoError(code); }
function asDocument(value: unknown, maximum = MAX_CONTROL_BYTES): Record<string, JsonValue> {
  return document(value as DocumentInput, maximum);
}
function equalJson(left: unknown, right: unknown): boolean {
  return Buffer.from(canonicalBytes(left)).equals(Buffer.from(canonicalBytes(right)));
}
function validity(value: Obj | Window, now: number, maximum = MAX_VALIDITY_SECONDS, allowExpired = false): void {
  const issued = safeInteger(value.issued_at), expires = safeInteger(value.expires_at);
  const current = safeInteger(now);
  if (expires - issued < 1 || expires - issued > maximum) fail('network_invalid_validity');
  if (issued > current + 30) fail('network_control_from_future');
  if (!allowExpired && expires <= current) fail('network_control_expired');
}
function scope(value: unknown): readonly Scope[] {
  if (!Array.isArray(value) || !value.length || value.some((item, index) =>
    (item !== 'send' && item !== 'receive') || (index > 0 && item <= value[index - 1]))) fail('network_invalid_scope');
  return value as Scope[];
}
function verified<T>(value: SignedControl<T> | DocumentInput, trust: readonly SigningPublicDescriptor[]): SignedControl<T> {
  const raw = objectFields(asDocument(value), ['payload', 'proof']);
  const payload = asDocument(raw.payload);
  verifyMessage(payload, raw.proof as DocumentInput, trust);
  return { payload: payload as unknown as T, proof: raw.proof as unknown as MessageProof };
}
function freeze<T>(value: T): T {
  if (value !== null && typeof value === 'object') {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}

export function validateMember(value: Member | DocumentInput): Member {
  const raw = objectFields(asDocument(value, 8192), ['signing_key', 'encryption_key', 'status', 'scope']);
  validateSigningPublic(raw.signing_key as DocumentInput);
  validateEncryptionPublic(raw.encryption_key as DocumentInput);
  scope(raw.scope);
  if (raw.status !== 'active' && raw.status !== 'revoked') fail('network_invalid_member_status');
  return raw as unknown as Member;
}
function rosterPayload(value: Roster, options: RosterOptions): Roster {
  const raw = objectFields(value, ['schema_version', 'network_id', 'version', 'previous_sha256', 'members', 'issued_at', 'expires_at']);
  if (raw.schema_version !== ROSTER_SCHEMA || opaqueId(raw.network_id) !== opaqueId(options.network_id)) fail('network_roster_binding_mismatch');
  const version = safeInteger(raw.version, 1), previous = digestHex(raw.previous_sha256);
  if ((version === 1) !== (previous === '0'.repeat(64))) fail('network_roster_genesis_mismatch');
  if (!Array.isArray(raw.members) || raw.members.length < 1 || raw.members.length > MAX_MEMBERS) fail('network_roster_member_limit');
  const checked = raw.members.map(member => validateMember(member));
  const encryption = new Set<string>();
  for (let index = 0; index < checked.length; index++) {
    const member = checked[index];
    if ((index > 0 && member.signing_key.key_id <= checked[index - 1].signing_key.key_id) || encryption.has(member.encryption_key.key_id)) fail('network_duplicate_member_key');
    encryption.add(member.encryption_key.key_id);
  }
  validity(raw, options.now, MAX_VALIDITY_SECONDS, options.allow_expired === true);
  if (version < safeInteger(options.minimum_version ?? 0)) fail('network_roster_rollback');
  if (options.expected_previous_sha256 !== undefined && previous !== digestHex(options.expected_previous_sha256)) fail('network_roster_chain_mismatch');
  return raw as unknown as Roster;
}
export function verifyRoster(value: SignedControl<Roster> | DocumentInput, options: RosterOptions): Roster {
  return rosterPayload(verified(value, options.issuers).payload, options);
}
export function verifyStatus(value: SignedControl<Status> | DocumentInput, options: StatusOptions): Status {
  const raw = objectFields(verified(value, options.issuers).payload,
    ['schema_version', 'network_id', 'nonce', 'roster_sha256', 'roster_version', 'issued_at', 'expires_at']);
  if (raw.schema_version !== STATUS_SCHEMA || opaqueId(raw.network_id) !== opaqueId(options.network_id) ||
      opaqueId(raw.nonce) !== opaqueId(options.nonce)) fail('network_status_binding_mismatch');
  digestHex(raw.roster_sha256); safeInteger(raw.roster_version, 1);
  if ((options.roster_sha256 !== undefined && raw.roster_sha256 !== digestHex(options.roster_sha256)) ||
      (options.roster_version !== undefined && raw.roster_version !== safeInteger(options.roster_version, 1))) fail('network_status_roster_mismatch');
  validity(raw, options.now);
  return raw as unknown as Status;
}
function continuity(candidate: Roster, candidateHash: string, previousVersion: number,
  previousHash: string | null, recovery = false): void {
  if (candidate.version < previousVersion || (candidate.version === previousVersion && candidateHash !== previousHash)) {
    fail(recovery ? 'network_recovery_roster_rollback' : 'network_roster_rollback');
  }
  // Match Python: a fresh issuer status may jump multiple versions; only an
  // immediately consecutive version has a checkable previous-document edge.
  if (previousHash !== null && candidate.version === previousVersion + 1 && candidate.previous_sha256 !== previousHash) {
    fail(recovery ? 'network_recovery_roster_chain_mismatch' : 'network_roster_chain_mismatch');
  }
}

/** Verify an issuer challenge response before making it current in host storage.
 * The host must atomically compare/store previous state and consume its nonce.
 */
export function verifyCurrentRoster(rosterValue: SignedControl<Roster> | DocumentInput,
  statusValue: SignedControl<Status> | DocumentInput, options: CurrentRosterOptions): CurrentRoster {
  const rosterDoc = asDocument(rosterValue) as unknown as SignedControl<Roster>;
  const statusDoc = asDocument(statusValue) as unknown as SignedControl<Status>;
  const roster = verifyRoster(rosterDoc, { ...options, allow_expired: true });
  const rosterHash = documentSha256(rosterDoc as unknown as DocumentInput);
  const status = verifyStatus(statusDoc, { ...options, roster_sha256: rosterHash, roster_version: roster.version });
  if (options.recovery_anchor !== undefined) {
    const suppliedAnchor = objectFields(options.recovery_anchor,
      ['minimum_roster_version', 'last_verified_roster', 'last_roster_sha256']);
    const anchor = asDocument({ ...suppliedAnchor, last_verified_roster: suppliedAnchor.last_verified_roster === null
      ? null : asDocument(suppliedAnchor.last_verified_roster) }, 2 * MAX_CONTROL_BYTES);
    const minimum = safeInteger(anchor.minimum_roster_version);
    let previousHash: string | null = null;
    if (anchor.last_verified_roster === null) {
      if (minimum !== 0 || anchor.last_roster_sha256 !== null) fail('network_recovery_marker_invalid');
    } else {
      const previous = verifyRoster(anchor.last_verified_roster as DocumentInput, { ...options, allow_expired: true });
      previousHash = documentSha256(anchor.last_verified_roster as DocumentInput);
      if (previous.version !== minimum || previousHash !== digestHex(anchor.last_roster_sha256)) fail('network_recovery_marker_invalid');
    }
    continuity(roster, rosterHash, minimum, previousHash, true);
  }
  if (options.previous_roster !== undefined) {
    const previousDoc = asDocument(options.previous_roster);
    const previous = verifyRoster(previousDoc, { ...options, allow_expired: true });
    continuity(roster, rosterHash, previous.version, documentSha256(previousDoc));
  }
  if (options.local_identity !== undefined) {
    const local = objectFields(asDocument(options.local_identity, 8192), ['signing_key', 'encryption_key']);
    const signing = validateSigningPublic(local.signing_key as DocumentInput);
    const encryption = validateEncryptionPublic(local.encryption_key as DocumentInput);
    const own = roster.members.find(item => item.signing_key.key_id === signing.key_id && item.status === 'active');
    if (!own || !equalJson(own.signing_key, signing) || !equalJson(own.encryption_key, encryption)) fail('network_identity_not_active');
  }
  const current: CurrentRoster = freeze({ roster: rosterDoc, status: statusDoc, roster_sha256: rosterHash });
  currentStates.set(current, { roster: freeze(roster), status: freeze(status) });
  return current;
}

/** Scope check from the verified current snapshot; revoked members never pass.
 * A JSON copy or expired status cannot become an authorization capability.
 */
export function authorizedMember(current: CurrentRoster, keyId: string, action: Scope,
  options: { now: number; expected_identity?: LocalPublicIdentity }): Member {
  const state = currentStates.get(current);
  if (!state) fail('network_verified_control_required');
  validity(state.status, options.now);
  signingKeyId(keyId);
  if (action !== 'send' && action !== 'receive') fail('network_invalid_scope');
  const member = state.roster.members.find(item => item.signing_key.key_id === keyId && item.status === 'active');
  if (!member || !member.scope.includes(action)) fail(action === 'send' ? 'network_send_scope_denied' : 'network_receive_scope_denied');
  if (options.expected_identity !== undefined) {
    const expected = objectFields(asDocument(options.expected_identity, 8192), ['signing_key', 'encryption_key']);
    const signing = validateSigningPublic(expected.signing_key as DocumentInput);
    const encryption = validateEncryptionPublic(expected.encryption_key as DocumentInput);
    if (!equalJson(signing, member.signing_key) || !equalJson(encryption, member.encryption_key)) fail('network_identity_not_active');
  }
  return asDocument(member, 8192) as unknown as Member;
}

function invitePayload(value: Invite, options: IssuerOptions): Invite {
  const raw = objectFields(value, ['schema_version', 'network_id', 'invite_id', 'candidate_signing_key',
    'candidate_encryption_key', 'scope', 'handoff_sha256', 'roster_sha256', 'issued_at', 'expires_at']);
  if (raw.schema_version !== INVITE_SCHEMA || opaqueId(raw.network_id) !== opaqueId(options.network_id)) fail('network_invite_binding_mismatch');
  opaqueId(raw.invite_id);
  validateSigningPublic(raw.candidate_signing_key as DocumentInput);
  validateEncryptionPublic(raw.candidate_encryption_key as DocumentInput);
  scope(raw.scope); digestHex(raw.handoff_sha256); digestHex(raw.roster_sha256);
  validity(raw, options.now, 7 * 86400);
  return raw as unknown as Invite;
}
export function verifyInvite(value: SignedControl<Invite> | DocumentInput, options: IssuerOptions): Invite {
  return invitePayload(verified(value, options.issuers).payload, options);
}
export interface InvitationPackage {
  readonly invite: SignedControl<Invite> | DocumentInput;
  readonly roster: SignedControl<Roster> | DocumentInput;
  readonly handoff?: Envelope | DocumentInput;
}
export interface InvitationOptions extends IssuerOptions {
  readonly local_identity: LocalPublicIdentity;
  /** Required only if a handoff is present; never returned in the result. */
  readonly encryption_identity?: EncryptionIdentityDocument;
  /** Check the relay's exact candidate membership condition when available. */
  readonly current?: CurrentRoster;
}
export interface VerifiedInvitation {
  readonly invite: Invite;
  readonly invite_sha256: string;
  readonly roster: Roster;
  readonly handoff_plaintext: Uint8Array | null;
}
/** Verify commitments/decrypt handoff before admission. Never consumes an invite
 * or imports the returned bytes as memory; the host performs those transactions.
 */
export async function verifyInvitationPackage(value: InvitationPackage, options: InvitationOptions): Promise<VerifiedInvitation> {
  // Validate each component at its own wire limit, without imposing an invented
  // smaller limit on a package containing both a roster and a full envelope.
  const keys = value && typeof value === 'object' ? Object.keys(value) : [];
  const names = keys.includes('handoff') ? ['invite', 'roster', 'handoff'] : ['invite', 'roster'];
  objectFields(value, names);
  const properties = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(value).length !== keys.length || keys.some(key => !('value' in properties[key]) || !properties[key].enumerable)) fail('network_invalid_document');
  const inviteDoc = asDocument(value.invite), rosterDoc = asDocument(value.roster);
  const handoff = value.handoff === undefined ? undefined : document(value.handoff as DocumentInput);
  const invite = verifyInvite(inviteDoc, options);
  const roster = verifyRoster(rosterDoc, { ...options, allow_expired: true });
  const local = objectFields(asDocument(options.local_identity, 8192), ['signing_key', 'encryption_key']);
  const signing = validateSigningPublic(local.signing_key as DocumentInput), encryption = validateEncryptionPublic(local.encryption_key as DocumentInput);
  if (!equalJson(invite.candidate_signing_key, signing) || !equalJson(invite.candidate_encryption_key, encryption) ||
      invite.roster_sha256 !== documentSha256(rosterDoc)) fail('network_invitation_identity_mismatch');
  const commitment = handoff === undefined ? sha256(new Uint8Array()) : documentSha256(handoff);
  if (commitment !== invite.handoff_sha256) fail('network_handoff_commitment_mismatch');
  const expected: Member = { signing_key: signing, encryption_key: encryption, scope: invite.scope, status: 'active' };
  if (!equalJson(roster.members.find(item => item.signing_key.key_id === signing.key_id) ?? null, expected)) fail('relay_invite_candidate_mismatch');
  if (options.current !== undefined) {
    const state = currentStates.get(options.current);
    if (!state) fail('network_verified_control_required');
    validity(state.status, options.now);
    if (state.roster.network_id !== options.network_id || roster.version > state.roster.version) fail('relay_invite_roster_mismatch');
    if (!equalJson(state.roster.members.find(item => item.signing_key.key_id === signing.key_id) ?? null, expected)) fail('relay_invite_candidate_mismatch');
  }
  let plaintext: Uint8Array | null = null;
  if (handoff !== undefined) {
    if (!options.encryption_identity) fail('network_encryption_identity_missing');
    const secret = asDocument(options.encryption_identity, 4096);
    const secretPublic = validateEncryptionPublic({ schema_version: 'memory-vault-network-encryption-key/v1',
      algorithm: secret.algorithm, key_id: secret.key_id, public_key: secret.public_key });
    if (!equalJson(secretPublic, encryption)) fail('network_invitation_identity_mismatch');
    // Match the client's handoff verification. It proves a current-to-that-
    // invited-roster sender, not admission, freshness of memory, or execution.
    plaintext = await open(handoff, { network_id: options.network_id,
      trusted_signers: roster.members.filter(item => item.status === 'active').map(item => item.signing_key),
      identity: secret as unknown as EncryptionIdentityDocument });
  }
  return { invite, invite_sha256: documentSha256(inviteDoc), roster, handoff_plaintext: plaintext };
}

export interface SignRequestOptions extends Window {
  readonly signer: SigningIdentityDocument;
  readonly network_id: string;
  readonly action: RequestAction;
  readonly request_id: string;
  readonly body: DocumentInput;
}
export interface VerifyRequestOptions {
  readonly peers: readonly SigningPublicDescriptor[];
  readonly network_id: string;
  readonly action?: RequestAction;
  readonly now: number;
}
function requestPayload(value: Obj, options: { network_id: string; action?: RequestAction; now: number }): SignedRequestPayload {
  const raw = objectFields(value, ['schema_version', 'network_id', 'action', 'request_id', 'body', 'issued_at', 'expires_at']);
  if (raw.schema_version !== REQUEST_SCHEMA || opaqueId(raw.network_id) !== opaqueId(options.network_id)) fail('network_request_binding_mismatch');
  if (!['join', 'messages', 'poll', 'ack', 'status'].includes(raw.action as string) ||
      (options.action !== undefined && raw.action !== options.action)) fail('network_request_action_rejected');
  opaqueId(raw.request_id); asDocument(raw.body, MAX_CONTROL_BYTES / 2); validity(raw, options.now);
  return raw as unknown as SignedRequestPayload;
}
export function signRequest(options: SignRequestOptions): SignedControl<SignedRequestPayload> {
  const raw = { schema_version: REQUEST_SCHEMA, network_id: opaqueId(options.network_id), action: options.action,
    request_id: opaqueId(options.request_id), body: asDocument(options.body, MAX_CONTROL_BYTES / 2),
    issued_at: options.issued_at, expires_at: options.expires_at };
  const payload = requestPayload(raw, { network_id: options.network_id, now: safeInteger(options.issued_at) });
  const proof = signMessage(payload as unknown as DocumentInput, options.signer);
  return asDocument({ payload, proof }) as unknown as SignedControl<SignedRequestPayload>;
}
export function verifyRequest(value: SignedControl<SignedRequestPayload> | DocumentInput, options: VerifyRequestOptions): SignedRequestPayload {
  const raw = verified(value, options.peers).payload;
  return requestPayload(raw as unknown as Obj, options);
}
export async function openJoinChallenge(value: DocumentInput, options: {
  identity: EncryptionIdentityDocument; network_id: string; invite_id: string; now: number;
}): Promise<string> {
  const raw = objectFields(document(value), ['schema_version', 'network_id', 'invite_id', 'challenge_id', 'issued_at', 'expires_at', 'jwe']);
  if (raw.schema_version !== CHALLENGE_SCHEMA || opaqueId(raw.network_id) !== opaqueId(options.network_id) ||
      opaqueId(raw.invite_id) !== opaqueId(options.invite_id)) fail('network_challenge_binding_mismatch');
  opaqueId(raw.challenge_id); validity(raw, options.now);
  const context = Object.fromEntries(Object.entries(raw).filter(([key]) => key !== 'jwe'));
  const answer = await decryptBytes(raw.jwe as DocumentInput, options.identity, { context });
  if (answer.length !== 32) fail('network_challenge_answer_invalid');
  return encodeBase64url(answer);
}
/** Verify both candidate-key possession proofs; caller atomically consumes the
 * invitation and challenge afterward. An exact successful retry is a lookup,
 * not permission to reauthorize expired input in this function.
 */
export function verifyJoinProof(request: SignedControl<SignedRequestPayload> | DocumentInput,
  invitation: SignedControl<Invite> | DocumentInput, options: IssuerOptions & {
    readonly challenge_id: string; readonly answer_sha256: string; readonly invite_sha256: string;
  }): SignedRequestPayload {
  const inviteDoc = asDocument(invitation), invite = verifyInvite(inviteDoc, options);
  const expectedInvite = digestHex(options.invite_sha256);
  if (documentSha256(inviteDoc) !== expectedInvite) fail('network_join_binding_mismatch');
  const requestPayload = verifyRequest(request, { network_id: options.network_id, now: options.now,
    action: 'join', peers: [invite.candidate_signing_key] });
  const body = objectFields(requestPayload.body, ['invite_sha256', 'challenge_id', 'challenge_answer']);
  if (body.invite_sha256 !== expectedInvite || body.challenge_id !== opaqueId(options.challenge_id)) fail('network_join_binding_mismatch');
  decodeBase64url(body.challenge_answer, 32, 32);
  const actual = sha256(Buffer.from(body.challenge_answer as string, 'ascii'));
  const expectedAnswer = digestHex(options.answer_sha256);
  if (!timingSafeEqual(Buffer.from(actual, 'ascii'), Buffer.from(expectedAnswer, 'ascii'))) fail('network_join_key_proof_failed');
  return requestPayload;
}
