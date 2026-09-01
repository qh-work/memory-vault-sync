/** Independent topic control. No transport, storage, enrollment or memory ownership.
 * Historical signature checks are not current authorization. Online selection
 * requires an unforgeable in-memory result of a fresh joint status verification.
 */
import {
  NetworkCryptoError, canonicalBytes, document, documentSha256, signMessage, verifyMessage,
  validateSigningPublic, validateSigningIdentity, objectFields, safeInteger, opaqueId,
  digestHex, signingKeyId,
} from './crypto.ts';
import type { DocumentInput, JsonValue, SigningIdentityDocument, SigningPublicDescriptor,
  EncryptionPublicDescriptor } from './crypto.ts';
import { verifyRoster, verifyCurrentRoster, authorizedMember } from './control.ts';
import type { SignedControl, IssuerOptions, CurrentRosterOptions, CurrentRoster, Roster } from './control.ts';

export const POLICY_SCHEMA = 'memory-vault-topic-policy/v1';
export const SUBSCRIPTION_SCHEMA = 'memory-vault-topic-subscription-change/v1';
export const SNAPSHOT_SCHEMA = 'memory-vault-topic-snapshot/v1';
export const STATUS_SCHEMA = 'memory-vault-topic-status/v1';
export const RECEIPT_SCHEMA = 'memory-vault-topic-subscription-receipt/v1';
export const MAX_POLICY_BYTES = 128 * 1024, MAX_SNAPSHOT_BYTES = 128 * 1024;
export const MAX_SUBSCRIPTION_BYTES = 16 * 1024, MAX_STATUS_BYTES = 16 * 1024;
export const MAX_TOPIC_STATUS_BYTES = MAX_STATUS_BYTES, MAX_RECEIPT_BYTES = 16 * 1024;
export const MAX_JOINT_BYTES = 2 * 1024 * 1024 + MAX_POLICY_BYTES + MAX_SNAPSHOT_BYTES + MAX_STATUS_BYTES;
export const MAX_GRANTS = 256, MAX_TOPIC_RECIPIENTS = 16;
type Obj = Record<string, unknown>;
type Window = { readonly issued_at: number; readonly expires_at: number };
interface Common extends Window {
  readonly network_id: string; readonly topic_id: string; readonly issuer_key_id: string;
  readonly version: number; readonly previous_sha256: string;
}
export interface Grant {
  readonly member_key_id: string; readonly grant_id: string; readonly status: 'active' | 'revoked';
}
export interface TopicPolicy extends Common {
  readonly schema_version: typeof POLICY_SCHEMA; readonly status: 'active' | 'revoked';
  readonly publishers: readonly Grant[]; readonly subscriber_grants: readonly Grant[];
}
export interface SubscriptionChange extends Window {
  readonly schema_version: typeof SUBSCRIPTION_SCHEMA;
  readonly network_id: string; readonly topic_id: string; readonly member_key_id: string;
  readonly member_signing_key: SigningPublicDescriptor; readonly grant_id: string;
  readonly revision: number; readonly previous_change_sha256: string;
  readonly state: 'subscribed' | 'unsubscribed'; readonly request_id: string;
}
export interface SubscriptionEntry {
  readonly member_key_id: string; readonly grant_id: string;
  readonly change: SignedControl<SubscriptionChange> | null;
}
export interface TopicSnapshot extends Common {
  readonly schema_version: typeof SNAPSHOT_SCHEMA; readonly policy_version: number;
  readonly policy_sha256: string; readonly subscriptions: readonly SubscriptionEntry[];
}
export interface TopicStatus extends Window {
  readonly schema_version: typeof STATUS_SCHEMA; readonly network_id: string;
  readonly topic_id: string; readonly issuer_key_id: string; readonly nonce: string;
  readonly policy_version: number; readonly policy_sha256: string;
  readonly snapshot_version: number; readonly snapshot_sha256: string;
  readonly roster_version: number; readonly roster_sha256: string;
}
export interface SubscriptionReceipt {
  readonly schema_version: typeof RECEIPT_SCHEMA; readonly network_id: string;
  readonly topic_id: string; readonly issuer_key_id: string; readonly member_key_id: string;
  readonly grant_id: string; readonly request_id: string; readonly revision: number;
  readonly change_sha256: string; readonly snapshot_version: number;
  readonly snapshot_sha256: string; readonly committed_at: number; readonly state: 'committed';
}
export interface TopicOptions extends IssuerOptions {
  readonly topic_id: string; readonly issuer_key_id: string;
}

function fail(code: string): never { throw new NetworkCryptoError(code); }
function doc(value: unknown, maximum: number): Record<string, JsonValue> {
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

const COMMON_FIELDS = ['schema_version', 'network_id', 'topic_id', 'issuer_key_id',
  'version', 'previous_sha256', 'issued_at', 'expires_at'];
const CHANGE_FIELDS = ['schema_version', 'network_id', 'topic_id', 'member_key_id', 'member_signing_key',
  'grant_id', 'revision', 'previous_change_sha256', 'state', 'request_id', 'issued_at', 'expires_at'];
const STATUS_FIELDS = ['schema_version', 'network_id', 'topic_id', 'issuer_key_id', 'nonce',
  'policy_version', 'policy_sha256', 'snapshot_version', 'snapshot_sha256',
  'roster_version', 'roster_sha256', 'issued_at', 'expires_at'];
const RECEIPT_FIELDS = ['schema_version', 'network_id', 'topic_id', 'issuer_key_id', 'member_key_id',
  'grant_id', 'request_id', 'revision', 'change_sha256', 'snapshot_version', 'snapshot_sha256',
  'committed_at', 'state'];
const ZERO = '0'.repeat(64);

function validity(value: Window | Obj, now: number, allowExpired = false): void {
  const issued = safeInteger(value.issued_at), expires = safeInteger(value.expires_at), current = safeInteger(now);
  if (expires - issued < 1 || expires - issued > 300) fail('network_invalid_validity');
  if (issued > current + 30) fail('network_control_from_future');
  if (!allowExpired && expires <= current) fail('network_control_expired');
}
function genesis(version: unknown, previous: unknown): void {
  if ((safeInteger(version, 1) === 1) !== (digestHex(previous) === ZERO)) fail('network_topic_chain_mismatch');
}
function topicBinding(raw: Obj, options: Pick<TopicOptions, 'network_id' | 'topic_id' | 'issuer_key_id'>, kind: string): void {
  if (opaqueId(raw.network_id) !== opaqueId(options.network_id) || opaqueId(raw.topic_id) !== opaqueId(options.topic_id)) fail(`network_topic_${kind}_binding_mismatch`);
  signingKeyId(raw.issuer_key_id);
}
function issuerSigned<T>(value: unknown, maximum: number, options: TopicOptions): SignedControl<T> {
  const raw = objectFields(doc(value, maximum), ['payload', 'proof']), payload = doc(raw.payload, maximum);
  const expected = signingKeyId(options.issuer_key_id), proof = raw.proof as Obj | null;
  if (payload.issuer_key_id !== expected || proof === null || typeof proof !== 'object' || Array.isArray(proof) || proof.key_id !== expected) fail('network_topic_issuer_mismatch');
  const signer = verifyMessage(payload, raw.proof as DocumentInput, options.issuers);
  if (signer !== expected) fail('network_topic_issuer_mismatch');
  return { payload: payload as unknown as T, proof: raw.proof as SignedControl<T>['proof'] };
}
function grant(value: unknown): Grant {
  const raw = objectFields(value, ['member_key_id', 'grant_id', 'status']);
  signingKeyId(raw.member_key_id); opaqueId(raw.grant_id);
  if (raw.status !== 'active' && raw.status !== 'revoked') fail('network_topic_invalid_status');
  return raw as unknown as Grant;
}
function grantOrder(a: Grant | SubscriptionEntry, b: Grant | SubscriptionEntry): number {
  return a.member_key_id < b.member_key_id ? -1 : a.member_key_id > b.member_key_id ? 1 :
    a.grant_id < b.grant_id ? -1 : a.grant_id > b.grant_id ? 1 : 0;
}
function checkpoint<T extends { version: number; previous_sha256: string; issued_at: number }>(
  incoming: SignedControl<T>, previous: SignedControl<T>, allowGap: boolean): void {
  const raw = incoming.payload, old = previous.payload;
  if (raw.version < old.version || raw.issued_at < old.issued_at) fail('network_topic_rollback');
  const oldHash = documentSha256(previous as unknown as DocumentInput);
  if (raw.version === old.version) {
    if (documentSha256(incoming as unknown as DocumentInput) !== oldHash) fail('network_topic_version_conflict');
  } else if (raw.version === old.version + 1) {
    if (raw.previous_sha256 !== oldHash) fail('network_topic_chain_mismatch');
  } else if (!allowGap) fail('network_topic_gap_requires_current');
}
function policyDocument(value: unknown, options: TopicOptions & { allow_expired?: boolean }): SignedControl<TopicPolicy> {
  const signed = issuerSigned<TopicPolicy>(value, MAX_POLICY_BYTES, options);
  const raw = objectFields(signed.payload, [...COMMON_FIELDS, 'status', 'publishers', 'subscriber_grants']);
  if (raw.schema_version !== POLICY_SCHEMA) fail('network_topic_policy_binding_mismatch');
  topicBinding(raw, options, 'policy'); genesis(raw.version, raw.previous_sha256);
  if (raw.status !== 'active' && raw.status !== 'revoked') fail('network_topic_invalid_status');
  if (!Array.isArray(raw.publishers) || !Array.isArray(raw.subscriber_grants) ||
      raw.publishers.length + raw.subscriber_grants.length > MAX_GRANTS) fail('network_topic_grant_limit');
  const ids = new Set<string>();
  for (const list of [raw.publishers, raw.subscriber_grants]) {
    const activeMembers = new Set<string>();
    for (const item of list) {
      const checked = grant(item);
      if (ids.has(checked.grant_id)) fail('network_topic_duplicate_grant');
      if (checked.status === 'active' && activeMembers.has(checked.member_key_id)) fail('network_topic_active_grant_conflict');
      ids.add(checked.grant_id); if (checked.status === 'active') activeMembers.add(checked.member_key_id);
    }
    if (list.some((item, index) => index > 0 && grantOrder(list[index - 1] as Grant, item as Grant) > 0)) fail('network_topic_grant_order');
  }
  validity(raw, options.now, options.allow_expired === true);
  return signed;
}
export interface PolicyOptions extends TopicOptions {
  readonly previous_policy?: SignedControl<TopicPolicy> | DocumentInput;
  readonly allow_expired?: boolean;
}
function policyInternal(value: unknown, options: PolicyOptions, allowGap: boolean): SignedControl<TopicPolicy> {
  const incoming = policyDocument(value, options);
  if (options.previous_policy === undefined) return incoming;
  const previous = policyDocument(options.previous_policy, { ...options, allow_expired: true });
  checkpoint(incoming, previous, allowGap);
  if (previous.payload.status === 'revoked' && incoming.payload.status !== 'revoked') fail('network_topic_reactivation_forbidden');
  const current = new Map<string, { role: string; grant: Grant }>();
  for (const role of ['publishers', 'subscriber_grants'] as const) for (const item of incoming.payload[role]) current.set(item.grant_id, { role, grant: item });
  for (const role of ['publishers', 'subscriber_grants'] as const) {
    for (const old of previous.payload[role]) {
      const next = current.get(old.grant_id);
      if (!next) fail('network_topic_tombstone_required');
      if (next.role !== role || next.grant.member_key_id !== old.member_key_id) fail('network_topic_grant_identity_changed');
      if (old.status === 'revoked' && next.grant.status !== 'revoked') fail('network_topic_reactivation_forbidden');
    }
  }
  return incoming;
}
export function verifyPolicy(value: SignedControl<TopicPolicy> | DocumentInput, options: PolicyOptions): TopicPolicy {
  return policyInternal(value, options, false).payload;
}
export interface SubscriptionOptions {
  readonly network_id: string; readonly topic_id: string; readonly member_key_id?: string; readonly grant_id?: string;
  readonly previous_change?: SignedControl<SubscriptionChange> | DocumentInput;
  readonly now: number; readonly allow_expired?: boolean;
}
function subscriptionDocument(value: unknown, options: SubscriptionOptions): SignedControl<SubscriptionChange> {
  const signed = objectFields(doc(value, MAX_SUBSCRIPTION_BYTES), ['payload', 'proof']);
  const raw = objectFields(doc(signed.payload, MAX_SUBSCRIPTION_BYTES), CHANGE_FIELDS);
  if (raw.schema_version !== SUBSCRIPTION_SCHEMA || opaqueId(raw.network_id) !== opaqueId(options.network_id) ||
      opaqueId(raw.topic_id) !== opaqueId(options.topic_id)) fail('network_topic_subscription_binding_mismatch');
  const descriptor = validateSigningPublic(raw.member_signing_key as DocumentInput);
  const member = signingKeyId(raw.member_key_id), grantId = opaqueId(raw.grant_id);
  const proof = signed.proof as Obj | null;
  if (descriptor.key_id !== member || proof === null || typeof proof !== 'object' || Array.isArray(proof) || proof.key_id !== member ||
      (options.member_key_id !== undefined && member !== signingKeyId(options.member_key_id)) ||
      (options.grant_id !== undefined && grantId !== opaqueId(options.grant_id))) fail('network_topic_subscription_binding_mismatch');
  genesis(raw.revision, raw.previous_change_sha256); opaqueId(raw.request_id);
  if (raw.state !== 'subscribed' && raw.state !== 'unsubscribed') fail('network_topic_invalid_state');
  validity(raw, options.now, options.allow_expired === true);
  verifyMessage(raw, signed.proof as DocumentInput, [descriptor]);
  return { payload: raw as unknown as SubscriptionChange, proof: signed.proof as SignedControl<SubscriptionChange>['proof'] };
}
function subscriptionInternal(value: unknown, options: SubscriptionOptions, allowGap: boolean): SignedControl<SubscriptionChange> {
  const incoming = subscriptionDocument(value, options);
  if (options.previous_change === undefined) return incoming;
  const previous = subscriptionDocument(options.previous_change, { ...options, allow_expired: true,
    member_key_id: incoming.payload.member_key_id, grant_id: incoming.payload.grant_id });
  const raw = incoming.payload, old = previous.payload;
  // Revisions and signed predecessor hashes establish causality. A member
  // correcting its clock must still be able to unsubscribe within its window.
  if (raw.revision < old.revision) fail('network_topic_change_rollback');
  const oldHash = documentSha256(previous as unknown as DocumentInput);
  if (raw.revision === old.revision) {
    if (documentSha256(incoming as unknown as DocumentInput) !== oldHash) fail('network_topic_change_conflict');
  } else if (raw.revision === old.revision + 1) {
    if (raw.previous_change_sha256 !== oldHash) fail('network_topic_change_chain_mismatch');
  } else if (!allowGap) fail('network_topic_change_gap_requires_current');
  return incoming;
}
/** Signature/history only. A self-supplied descriptor never grants membership. */
export function verifySubscription(value: SignedControl<SubscriptionChange> | DocumentInput, options: SubscriptionOptions): SubscriptionChange {
  return subscriptionInternal(value, options, false).payload;
}
function snapshotDocument(value: unknown, options: TopicOptions & { allow_expired?: boolean }): SignedControl<TopicSnapshot> {
  const signed = issuerSigned<TopicSnapshot>(value, MAX_SNAPSHOT_BYTES, options);
  const raw = objectFields(signed.payload, [...COMMON_FIELDS, 'policy_version', 'policy_sha256', 'subscriptions']);
  if (raw.schema_version !== SNAPSHOT_SCHEMA) fail('network_topic_snapshot_binding_mismatch');
  topicBinding(raw, options, 'snapshot'); genesis(raw.version, raw.previous_sha256);
  safeInteger(raw.policy_version, 1); digestHex(raw.policy_sha256); validity(raw, options.now, options.allow_expired === true);
  if (!Array.isArray(raw.subscriptions) || raw.subscriptions.length > MAX_GRANTS) fail('network_topic_grant_limit');
  const subscriptions = raw.subscriptions, ids = new Set<string>();
  for (const value of subscriptions) {
    const item = objectFields(value, ['member_key_id', 'grant_id', 'change']);
    signingKeyId(item.member_key_id); opaqueId(item.grant_id);
    const typed = item as unknown as SubscriptionEntry;
    if (ids.has(typed.grant_id)) fail('network_topic_duplicate_grant');
    if (item.change !== null) subscriptionDocument(item.change, { network_id: options.network_id, topic_id: options.topic_id,
      now: raw.issued_at as number, member_key_id: typed.member_key_id, grant_id: typed.grant_id, allow_expired: true });
    ids.add(typed.grant_id);
  }
  if (subscriptions.some((item, index) => index > 0 && grantOrder(subscriptions[index - 1] as SubscriptionEntry, item as SubscriptionEntry) > 0)) fail('network_topic_grant_order');
  return signed;
}
export interface SnapshotOptions extends TopicOptions {
  readonly policy: SignedControl<TopicPolicy> | DocumentInput;
  readonly previous_snapshot?: SignedControl<TopicSnapshot> | DocumentInput;
  readonly allow_expired?: boolean;
}
function snapshotInternal(value: unknown, options: SnapshotOptions, allowGap: boolean): SignedControl<TopicSnapshot> {
  const incoming = snapshotDocument(value, options), policy = policyDocument(options.policy, { ...options, allow_expired: true });
  const raw = incoming.payload;
  if (raw.policy_version !== policy.payload.version || raw.policy_sha256 !== documentSha256(policy as unknown as DocumentInput)) fail('network_topic_snapshot_policy_mismatch');
  if (raw.subscriptions.length !== policy.payload.subscriber_grants.length || raw.subscriptions.some((item, index) => {
    const grant = policy.payload.subscriber_grants[index]; return item.member_key_id !== grant.member_key_id || item.grant_id !== grant.grant_id;
  })) fail('network_topic_snapshot_incomplete');
  if (options.previous_snapshot === undefined) return incoming;
  const previous = snapshotDocument(options.previous_snapshot, { ...options, allow_expired: true }), old = previous.payload;
  checkpoint(incoming, previous, allowGap);
  if (raw.policy_version < old.policy_version || (raw.policy_version === old.policy_version && raw.policy_sha256 !== old.policy_sha256)) fail('network_topic_snapshot_policy_mismatch');
  const current = new Map(raw.subscriptions.map(item => [item.grant_id, item]));
  for (const entry of old.subscriptions) {
    const next = current.get(entry.grant_id);
    if (!next) fail('network_topic_tombstone_required');
    if (next.member_key_id !== entry.member_key_id) fail('network_topic_tombstone_required');
    if (entry.change !== null) {
      if (next.change === null) fail('network_topic_change_missing');
      subscriptionInternal(next.change, { network_id: options.network_id, topic_id: options.topic_id, now: options.now,
        member_key_id: entry.member_key_id, grant_id: entry.grant_id, previous_change: entry.change, allow_expired: true }, allowGap);
    }
  }
  return incoming;
}
export function verifySnapshot(value: SignedControl<TopicSnapshot> | DocumentInput, options: SnapshotOptions): TopicSnapshot {
  return snapshotInternal(value, options, false).payload;
}

export interface TopicStatusOptions extends TopicOptions {
  readonly nonce: string;
  readonly policy_version?: number; readonly policy_sha256?: string;
  readonly snapshot_version?: number; readonly snapshot_sha256?: string;
  readonly roster_version?: number; readonly roster_sha256?: string;
}
export function verifyTopicStatus(value: SignedControl<TopicStatus> | DocumentInput, options: TopicStatusOptions): TopicStatus {
  const raw = objectFields(issuerSigned<TopicStatus>(value, MAX_STATUS_BYTES, options).payload, STATUS_FIELDS);
  if (raw.schema_version !== STATUS_SCHEMA) fail('network_topic_status_binding_mismatch');
  topicBinding(raw, options, 'status');
  if (opaqueId(raw.nonce) !== opaqueId(options.nonce)) fail('network_topic_status_binding_mismatch');
  for (const prefix of ['policy', 'snapshot', 'roster'] as const) {
    const version = `${prefix}_version` as const, hash = `${prefix}_sha256` as const;
    safeInteger(raw[version], 1); digestHex(raw[hash]);
    if ((options[version] !== undefined && raw[version] !== safeInteger(options[version], 1)) ||
        (options[hash] !== undefined && raw[hash] !== digestHex(options[hash]))) fail('network_topic_status_binding_mismatch');
  }
  validity(raw, options.now);
  return raw as unknown as TopicStatus;
}
export interface CurrentTopicOptions extends TopicOptions {
  readonly nonce: string;
  readonly previous_policy?: SignedControl<TopicPolicy> | DocumentInput;
  readonly previous_snapshot?: SignedControl<TopicSnapshot> | DocumentInput;
  readonly previous_roster?: SignedControl<Roster> | DocumentInput;
  readonly minimum_topic_status_issued_at?: number;
  readonly minimum_status_issued_at?: number;
}
export interface CurrentTopic {
  readonly policy: SignedControl<TopicPolicy>; readonly snapshot: SignedControl<TopicSnapshot>;
  readonly roster: CurrentRoster['roster']; readonly status: CurrentRoster['status'];
  readonly topic_status: SignedControl<TopicStatus>;
  readonly verified_at: number; readonly expires_at: number;
}
interface TopicCapability { readonly roster: CurrentRoster; readonly deadline: number }
const currentStates = new WeakMap<CurrentTopic, TopicCapability>();

function pinnedIssuer(options: TopicOptions): SigningPublicDescriptor {
  signingKeyId(options.issuer_key_id);
  if (!Array.isArray(options.issuers)) fail('network_invalid_document');
  const selected = options.issuers.map(key => validateSigningPublic(key)).filter(key => key.key_id === options.issuer_key_id);
  if (!selected.length) fail('unknown_key');
  if (selected.length !== 1) fail('network_duplicate_signer');
  return selected[0];
}
/** Only this fresh, same-nonce joint verification may cross checkpoint gaps.
 * Host persistence must still compare/store checkpoints atomically after I/O.
 */
export function verifyCurrentTopic(value: DocumentInput, options: CurrentTopicOptions): CurrentTopic {
  const started = performance.now(), now = safeInteger(options.now);
  const raw = objectFields(doc(value, MAX_JOINT_BYTES), ['roster', 'status', 'policy', 'snapshot', 'topic_status']);
  if ((options.previous_policy === undefined) !== (options.previous_snapshot === undefined)) fail('network_topic_checkpoint_incomplete');
  const issuer = pinnedIssuer(options), pinned = { ...options, issuers: [issuer] };
  const roster = verifyCurrentRoster(raw.roster as DocumentInput, raw.status as DocumentInput, pinned);
  if (roster.status.payload.issued_at < safeInteger(options.minimum_status_issued_at ?? 0)) fail('network_topic_status_rollback');
  const policy = policyDocument(raw.policy, { ...pinned, allow_expired: true });
  const snapshot = snapshotDocument(raw.snapshot, { ...pinned, allow_expired: true });
  const topicStatus = verifyTopicStatus(raw.topic_status as DocumentInput, { ...pinned,
    policy_version: policy.payload.version, policy_sha256: documentSha256(policy as unknown as DocumentInput),
    snapshot_version: snapshot.payload.version, snapshot_sha256: documentSha256(snapshot as unknown as DocumentInput),
    roster_version: roster.roster.payload.version, roster_sha256: roster.roster_sha256 });
  if (topicStatus.issued_at < safeInteger(options.minimum_topic_status_issued_at ?? 0)) fail('network_topic_status_rollback');
  if (options.previous_policy !== undefined) {
    verifySnapshot(options.previous_snapshot!, { ...pinned, policy: options.previous_policy, allow_expired: true });
  }
  policyInternal(policy, { ...pinned, allow_expired: true }, true);
  snapshotInternal(snapshot, { ...pinned, policy, allow_expired: true }, true);
  const expires = Math.min(roster.status.payload.expires_at, topicStatus.expires_at, now + 300);
  const current: CurrentTopic = freeze({ policy, snapshot, roster: roster.roster, status: roster.status,
    topic_status: doc(raw.topic_status, MAX_STATUS_BYTES) as unknown as SignedControl<TopicStatus>, verified_at: now, expires_at: expires });
  currentStates.set(current, { roster, deadline: started + (expires - now) * 1000 });
  return current;
}
function capability(current: CurrentTopic, now: number): TopicCapability {
  const state = currentStates.get(current);
  if (!state) fail('network_topic_capability_required');
  if (safeInteger(now) < current.verified_at) fail('network_topic_clock_rollback');
  if (now >= current.expires_at || performance.now() >= state.deadline) fail('network_control_expired');
  if (current.policy.payload.status !== 'active') fail('network_topic_inactive');
  return state;
}
export interface TopicRecipient {
  readonly member_key_id: string; readonly grant_id: string; readonly change_sha256: string;
  readonly signing_key: SigningPublicDescriptor; readonly encryption_key: EncryptionPublicDescriptor;
}
export function topicRecipients(current: CurrentTopic, options: { now: number }): TopicRecipient[] {
  const state = capability(current, options.now), selected: TopicRecipient[] = [];
  const members = new Map(current.roster.payload.members.map(member => [member.signing_key.key_id, member]));
  for (let index = 0; index < current.policy.payload.subscriber_grants.length; index++) {
    const grant = current.policy.payload.subscriber_grants[index], change = current.snapshot.payload.subscriptions[index].change;
    if (grant.status !== 'active' || change === null || change.payload.state !== 'subscribed') continue;
    const member = members.get(grant.member_key_id);
    if (!member || member.status !== 'active' || !member.scope.includes('receive')) continue;
    const checked = authorizedMember(state.roster, member.signing_key.key_id, 'receive', { now: options.now });
    if (!same(checked.signing_key, change.payload.member_signing_key)) fail('network_topic_member_key_changed');
    selected.push({ member_key_id: grant.member_key_id, grant_id: grant.grant_id,
      change_sha256: documentSha256(change as unknown as DocumentInput), signing_key: checked.signing_key, encryption_key: checked.encryption_key });
  }
  if (selected.length > MAX_TOPIC_RECIPIENTS) fail('network_topic_recipient_limit');
  return selected.sort((a, b) => a.member_key_id < b.member_key_id ? -1 : a.member_key_id > b.member_key_id ? 1 : 0);
}
export function authorizedTopicPublisher(current: CurrentTopic, memberKeyId: string,
  options: { now: number; grant_id?: string }): Omit<TopicRecipient, 'change_sha256'> {
  const state = capability(current, options.now); signingKeyId(memberKeyId);
  if (options.grant_id !== undefined) opaqueId(options.grant_id);
  const grant = current.policy.payload.publishers.find(item => item.member_key_id === memberKeyId && item.status === 'active' &&
    (options.grant_id === undefined || item.grant_id === options.grant_id));
  if (!grant) fail('network_topic_publisher_denied');
  const available = current.roster.payload.members.find(item => item.signing_key.key_id === memberKeyId && item.status === 'active' && item.scope.includes('send'));
  if (!available) fail('network_topic_publisher_denied');
  const member = authorizedMember(state.roster, memberKeyId, 'send', { now: options.now });
  return { member_key_id: memberKeyId, grant_id: grant.grant_id, signing_key: member.signing_key, encryption_key: member.encryption_key };
}

export interface ReceiptOptions extends TopicOptions {
  readonly change?: SignedControl<SubscriptionChange> | DocumentInput;
  readonly snapshot?: SignedControl<TopicSnapshot> | DocumentInput;
}
export function verifySubscriptionReceipt(value: SignedControl<SubscriptionReceipt> | DocumentInput, options: ReceiptOptions): SubscriptionReceipt {
  const raw = objectFields(issuerSigned<SubscriptionReceipt>(value, MAX_RECEIPT_BYTES, options).payload, RECEIPT_FIELDS);
  if (raw.schema_version !== RECEIPT_SCHEMA) fail('network_topic_receipt_binding_mismatch');
  topicBinding(raw, options, 'receipt'); signingKeyId(raw.member_key_id); opaqueId(raw.grant_id); opaqueId(raw.request_id);
  safeInteger(raw.revision, 1); safeInteger(raw.snapshot_version, 1); safeInteger(raw.committed_at);
  digestHex(raw.change_sha256); digestHex(raw.snapshot_sha256);
  if (raw.state !== 'committed') fail('network_topic_invalid_state');
  if (safeInteger(raw.committed_at) > safeInteger(options.now) + 30) fail('network_control_from_future');
  if (options.change !== undefined) {
    const change = subscriptionDocument(options.change, { network_id: options.network_id, topic_id: options.topic_id,
      now: raw.committed_at as number, member_key_id: raw.member_key_id as string, grant_id: raw.grant_id as string });
    if (raw.change_sha256 !== documentSha256(change as unknown as DocumentInput) ||
        ['member_key_id', 'grant_id', 'request_id', 'revision'].some(key => raw[key] !== (change.payload as unknown as Obj)[key])) {
      fail('network_topic_receipt_binding_mismatch');
    }
  }
  if (options.snapshot !== undefined) {
    const snapshot = snapshotDocument(options.snapshot, { ...options, allow_expired: true });
    if (raw.snapshot_sha256 !== documentSha256(snapshot as unknown as DocumentInput) || raw.snapshot_version !== snapshot.payload.version) fail('network_topic_receipt_binding_mismatch');
  }
  return raw as unknown as SubscriptionReceipt;
}

type SignerOptions = { readonly signer: SigningIdentityDocument; readonly issuer_key_id?: string };
function signingOptions(options: SignerOptions & { network_id: string; topic_id: string; issued_at?: number; committed_at?: number }): TopicOptions {
  const key = validateSigningIdentity(options.signer);
  if (options.issuer_key_id !== undefined && options.issuer_key_id !== key.key_id) fail('network_topic_issuer_mismatch');
  return { network_id: options.network_id, topic_id: options.topic_id, issuer_key_id: key.key_id, issuers: [key],
    now: safeInteger(options.issued_at ?? options.committed_at) };
}
function signedPayload<T>(payload: Obj, signer: SigningIdentityDocument, maximum: number): SignedControl<T> {
  const checked = doc(payload, maximum), proof = signMessage(checked, signer);
  return doc({ payload: checked, proof }, maximum) as unknown as SignedControl<T>;
}
export type IssuePolicyOptions = Omit<TopicPolicy, 'schema_version' | 'issuer_key_id'> & SignerOptions;
export function issuePolicy(options: IssuePolicyOptions): SignedControl<TopicPolicy> {
  const checked = signingOptions(options), { signer, ...fields } = options;
  const signed = signedPayload<TopicPolicy>({ ...fields, schema_version: POLICY_SCHEMA, issuer_key_id: checked.issuer_key_id,
    publishers: [...options.publishers].sort(grantOrder), subscriber_grants: [...options.subscriber_grants].sort(grantOrder) }, signer, MAX_POLICY_BYTES);
  verifyPolicy(signed, checked); return signed;
}
export type SignSubscriptionOptions = Omit<SubscriptionChange, 'schema_version' | 'member_key_id' | 'member_signing_key'> & { readonly signer: SigningIdentityDocument };
export function signSubscription(options: SignSubscriptionOptions): SignedControl<SubscriptionChange> {
  const member = validateSigningIdentity(options.signer), { signer, ...fields } = options;
  const signed = signedPayload<SubscriptionChange>({ ...fields, schema_version: SUBSCRIPTION_SCHEMA,
    member_key_id: member.key_id, member_signing_key: member }, signer, MAX_SUBSCRIPTION_BYTES);
  verifySubscription(signed, { network_id: options.network_id, topic_id: options.topic_id, now: options.issued_at }); return signed;
}
export type IssueSnapshotOptions = Omit<TopicSnapshot, 'schema_version' | 'issuer_key_id'> & SignerOptions;
export function issueSnapshot(options: IssueSnapshotOptions): SignedControl<TopicSnapshot> {
  const checked = signingOptions(options), { signer, ...fields } = options;
  const signed = signedPayload<TopicSnapshot>({ ...fields, schema_version: SNAPSHOT_SCHEMA, issuer_key_id: checked.issuer_key_id }, signer, MAX_SNAPSHOT_BYTES);
  snapshotDocument(signed, checked); return signed;
}
export type IssueTopicStatusOptions = Omit<TopicStatus, 'schema_version' | 'issuer_key_id'> & SignerOptions;
export function issueTopicStatus(options: IssueTopicStatusOptions): SignedControl<TopicStatus> {
  const checked = signingOptions(options), { signer, ...fields } = options;
  const signed = signedPayload<TopicStatus>({ ...fields, schema_version: STATUS_SCHEMA, issuer_key_id: checked.issuer_key_id }, signer, MAX_STATUS_BYTES);
  verifyTopicStatus(signed, { ...checked, nonce: options.nonce }); return signed;
}
export type IssueSubscriptionReceiptOptions = Omit<SubscriptionReceipt, 'schema_version' | 'issuer_key_id' | 'state'> & SignerOptions;
export function issueSubscriptionReceipt(options: IssueSubscriptionReceiptOptions): SignedControl<SubscriptionReceipt> {
  const checked = signingOptions(options), { signer, ...fields } = options;
  const signed = signedPayload<SubscriptionReceipt>({ ...fields, schema_version: RECEIPT_SCHEMA,
    issuer_key_id: checked.issuer_key_id, state: 'committed' }, signer, MAX_STATUS_BYTES);
  verifySubscriptionReceipt(signed, checked); return signed;
}
