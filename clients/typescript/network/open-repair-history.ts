/** Local historical-manifest drafts and original-byte input resolution.
 * Constructors check shapes; the local resolver also binds explicit references
 * and fixed predecessor phases. Neither accepts signatures, permissions or
 * complete typed-parent obligations.
 * Work counters remain the wire clone/parse/canonical work, not total CPU.
 */
import {isProxy} from 'node:util/types';
import {buildNewWire, parseNewWire, parseRawPack, objectFields, rawRef, u53,
  RepairError, RepairBudget, LocalRawResolver} from './open-repair-wire.ts';
import type {DraftJson, DraftPack, RawOriginal, RawRef, RepairPolicy} from './open-repair-wire.ts';

type Obj = Record<string, unknown>;
const COMMON = ['schema_version', 'kind', 'variant', 'root_key', 'roles'];
const EXTRAS = {
  mailbox_root: ['root_authority_ref', 'catalog_ref', 'genesis_head_refs'],
  mailbox_feed: ['slot_key', 'slot_ref', 'feed_head_ref', 'covered_interval', 'subtree', 'members'],
  mailbox_member: ['slot_key', 'message_id', 'envelope_ref', 'attempt_ref'],
  ack_unbound: ['ack_slot', 'root_authority_ref'],
  ack_empty: ['ack_slot', 'root_authority_ref', 'grant_ref', 'binding_ref'],
  ack_occupied_inputs: ['ack_slot', 'root_authority_ref', 'grant_ref', 'binding_ref',
    'receipt_ref', 'put_ref', 'disclosure_ref', 'admission_resource'],
} as const;
type Variant = keyof typeof EXTRAS;
const SLOT_INPUT = ['mailbox.slot', 'mailbox.read_grant', 'mailbox.maintenance_root',
  'bootstrap.mailbox_feed', 'resource.data_allocate', 'resource.metadata_allocate',
  'resource.data_offer', 'resource.metadata_offer', 'resource.slot_activation',
  'resource.data_active', 'resource.metadata_active', 'source.descriptor'];
const SLOT_OBS = ['historical.status.slot', 'historical.status.read',
  'historical.status.maintenance', 'historical.status.bootstrap'];
const ACK_OWNER_OBS = ['historical.status.ack_root', 'historical.status.ack_read',
  'historical.status.ack_owner_bootstrap', 'historical.status.ack_slot'];
const ACK_BOUND_OBS = [...ACK_OWNER_OBS, 'historical.status.ack_write',
  'historical.status.ack_offer_bootstrap'];

// Closed candidate registries from R3 section 7.1, not caller allowlists.
// Optional roles are only allowed here: their exact obligations need originals.
const ROLES: Record<Variant, ReadonlySet<string>> = {
  mailbox_root: new Set([...SLOT_INPUT, ...SLOT_OBS, 'mailbox.root_authority',
    'mailbox.root_read_grant', 'mailbox.catalog', 'bootstrap.mailbox_root',
    'resource.anchor_allocate', 'resource.anchor_offer', 'resource.anchor_activation',
    'resource.anchor_active', 'historical.status.root', 'historical.status.root_read',
    'historical.status.root_bootstrap', 'historical.status.catalog',
    'historical.status.anchor_resource', 'historical.status.data_resource',
    'historical.status.metadata_resource', 'genesis.head', 'genesis.checkpoint']),
  mailbox_member: new Set([...SLOT_INPUT, ...SLOT_OBS, 'contact.request',
    'delivery.attempt', 'message.disclosure', 'contact.policy', 'contact.decision',
    'contact.store_grant', 'contact.knock_lease', 'contact.delivery_lease',
    'delivery.destination', 'historical.status.disclosure', 'historical.status.destination',
    'historical.status.data_resource', 'historical.status.metadata_resource',
    'ack.root_authority', 'ack.write_grant', 'bootstrap.ack_offer',
    'historical.status.ack_root', 'historical.status.ack_write',
    'historical.status.ack_offer_bootstrap']),
  mailbox_feed: new Set([...SLOT_INPUT, ...SLOT_OBS, 'historical.status.metadata_resource',
    'feed.head', 'feed.checkpoint', 'history.member', 'member.core', 'member.link',
    'member.custody', 'member.checkpoint', 'member.head', 'member.sealed_core',
    'historical.status.disclosure', 'range.index', 'range.repair_page', 'range.sealed_page']),
  ack_unbound: new Set([...ACK_OWNER_OBS, 'ack.root_authority', 'ack.read_grant',
    'bootstrap.ack_owner', 'resource.ack_allocate', 'resource.ack_offer',
    'resource.ack_activation', 'resource.ack_active', 'source.descriptor',
    'historical.status.ack_resource']),
  ack_empty: new Set([...ACK_BOUND_OBS, 'history.ack_unbound', 'ack.unbound_custody',
    'ack.write_grant', 'bootstrap.ack_offer', 'ack.binding', 'historical.status.ack_resource']),
  ack_occupied_inputs: new Set([...ACK_BOUND_OBS, 'history.ack_empty', 'ack.empty_custody',
    'recipient.receipt', 'ack.disclosure', 'ack.put', 'historical.status.ack_disclosure',
    'historical.status.admission_resource', 'admission.assignment', 'admission.allocate',
    'admission.offer', 'admission.empty_replica_manifest', 'admission.empty_replica_custody',
    'admission.descriptor', 'historical.status.admission_assignment']),
};

function fail(): never {throw new RepairError('repair_invalid_history');}
function fields(value: unknown, names: readonly string[]): Obj {
  try {return objectFields(value, names);} catch {fail();}
}
function pattern(value: unknown, expression: RegExp): string {
  // Avoid RegExp $ accepting an otherwise valid identifier before final LF.
  if (typeof value !== 'string' || expression.exec(value)?.[0] !== value) fail();
  return value;
}
function opaque(value: unknown): string {return pattern(value, /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/);}
function digest(value: unknown): string {return pattern(value, /^[0-9a-f]{64}$/);}
function keyId(value: unknown, algorithm: 'ed25519'|'x25519'): string {
  return pattern(value, new RegExp('^' + algorithm + '_[0-9a-f]{64}$'));
}
function messageId(value: unknown): string {return pattern(value, /^msg_[0-9a-f]{64}$/);}
function list(value: unknown, nonempty = false): readonly unknown[] {
  if (!Array.isArray(value) || (nonempty && value.length === 0)) fail();
  return value;
}
function dual(value: unknown): Obj {
  const raw = fields(value, ['signing_key_id', 'encryption_key_id']);
  keyId(raw.signing_key_id, 'ed25519'); keyId(raw.encryption_key_id, 'x25519'); return raw;
}
function rootKey(value: unknown, kind: 'mailbox'|'ack_return'): Obj {
  const root = fields(value, ['owner', 'root_kind', 'anchor_ref', 'owner_epoch', 'root_id']);
  dual(root.owner); if (root.root_kind !== kind) fail();
  const anchor = fields(root.anchor_ref, ['namespace', 'key']);
  if (anchor.namespace !== 'anchor') fail(); digest(anchor.key);
  opaque(root.owner_epoch); opaque(root.root_id); return root;
}
function sameRoot(left: Obj, right: Obj): boolean {
  const a = left.owner as Obj, b = right.owner as Obj;
  return left.root_kind === right.root_kind && left.owner_epoch === right.owner_epoch &&
    left.root_id === right.root_id && (left.anchor_ref as Obj).key === (right.anchor_ref as Obj).key &&
    a.signing_key_id === b.signing_key_id && a.encryption_key_id === b.encryption_key_id;
}
function slotKey(value: unknown, outer: Obj): void {
  const slot = fields(value, ['root_key', 'slot_id', 'writer', 'writer_storage_epoch']);
  if (!sameRoot(rootKey(slot.root_key, 'mailbox'), outer)) fail();
  opaque(slot.slot_id); dual(slot.writer); opaque(slot.writer_storage_epoch);
}
function ackSlot(value: unknown, outer: Obj): void {
  const slot = fields(value, ['root_key', 'slot_id', 'receipt_writer', 'grant_id']);
  if (!sameRoot(rootKey(slot.root_key, 'ack_return'), outer)) fail();
  opaque(slot.slot_id); dual(slot.receipt_writer); opaque(slot.grant_id);
}
function resource(value: unknown): void {
  const raw = fields(value, ['node_key_id', 'storage_epoch', 'lease_id', 'resource_id']);
  keyId(raw.node_key_id, 'ed25519');
  opaque(raw.storage_epoch); opaque(raw.lease_id); opaque(raw.resource_id);
}
function textOrder(a: string, b: string): number {return a < b ? -1 : a > b ? 1 : 0;}
function refOrder(a: RawRef, b: RawRef): number {
  // All accepted ref components and registered role names are ASCII.
  return textOrder(a.namespace, b.namespace) || textOrder(a.key, b.key) ||
    textOrder(a.raw_sha256, b.raw_sha256) || (a.size < b.size ? -1 : a.size > b.size ? 1 : 0);
}
function refIdentity(ref: RawRef): string {return `${ref.namespace}:${ref.key}:${ref.raw_sha256}:${ref.size}`;}
function roles(value: unknown, variant: Variant): void {
  let previous: {role: string; ref: RawRef}|undefined;
  for (const item of list(value, true)) {
    const row = fields(item, ['role', 'document_ref', 'pack_ref', 'entry_index']);
    if (typeof row.role !== 'string' || !ROLES[variant].has(row.role)) fail();
    const reference = rawRef(row.document_ref), pack = rawRef(row.pack_ref);
    if (pack.namespace !== 'meta' || pack.key !== pack.raw_sha256) fail();
    u53(row.entry_index);
    if (previous && (textOrder(previous.role, row.role) || refOrder(previous.ref, reference)) >= 0) fail();
    previous = {role: row.role, ref: reference};
  }
}
function genesis(value: unknown): void {
  let previous: RawRef|undefined;
  for (const item of list(value)) {
    const current = rawRef(item);
    if (previous && refOrder(previous, current) >= 0) fail();
    previous = current;
  }
}
const MEMBER_REFS = ['envelope_ref', 'historical_manifest_ref', 'admission_core_ref',
  'admission_link_ref', 'source_custody_ref'];
function feed(raw: Obj): void {
  rawRef(raw.slot_ref); rawRef(raw.feed_head_ref);
  const interval = fields(raw.covered_interval, ['start', 'end']);
  const start = u53(interval.start), end = u53(interval.end);
  if (start >= end) fail();
  const subtree = fields(raw.subtree, ['root_ref', 'parent_path_refs']);
  const seen = new Set([refIdentity(rawRef(subtree.root_ref))]);
  for (const item of list(subtree.parent_path_refs)) {
    const identity = refIdentity(rawRef(item));
    if (seen.has(identity)) fail(); seen.add(identity);
  }
  const members = list(raw.members, true), ids = new Set<string>();
  if (members.length !== end - start) fail();
  for (let index = 0; index < members.length; index++) {
    const member = fields(members[index], ['sequence', 'message_id', ...MEMBER_REFS]);
    if (u53(member.sequence) !== start + index) fail();
    const id = messageId(member.message_id); if (ids.has(id)) fail(); ids.add(id);
    for (const name of MEMBER_REFS) rawRef(member[name]);
  }
}
function validate(draft: DraftJson): DraftJson {
  const value = draft.value;
  // Select a variant without reading arbitrary host objects: wire already froze it.
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      !Object.hasOwn(value, 'variant')) fail();
  const variant = (value as Obj).variant;
  if (typeof variant !== 'string' || !Object.hasOwn(EXTRAS, variant)) fail();
  const selected = variant as Variant, raw = fields(value, [...COMMON, ...EXTRAS[selected]]);
  if (raw.schema_version !== 'memory-vault-open-repair/v1' || raw.kind !== 'historical.manifest') fail();
  const root = rootKey(raw.root_key, selected.startsWith('mailbox_') ? 'mailbox' : 'ack_return');
  roles(raw.roles, selected);
  if (selected === 'mailbox_root') {
    rawRef(raw.root_authority_ref); rawRef(raw.catalog_ref); genesis(raw.genesis_head_refs);
  } else if (selected === 'mailbox_feed' || selected === 'mailbox_member') {
    slotKey(raw.slot_key, root);
    if (selected === 'mailbox_feed') feed(raw);
    else {messageId(raw.message_id); rawRef(raw.envelope_ref); rawRef(raw.attempt_ref);}
  } else {
    ackSlot(raw.ack_slot, root); rawRef(raw.root_authority_ref);
    if (selected !== 'ack_unbound') {rawRef(raw.grant_ref); rawRef(raw.binding_ref);}
    if (selected === 'ack_occupied_inputs') {
      rawRef(raw.receipt_ref); rawRef(raw.put_ref); rawRef(raw.disclosure_ref); resource(raw.admission_resource);
    }
  }
  return draft;
}

/** Canonical wire plus local shape only; no claim about referenced originals. */
export function parseHistoricalManifest(raw: Uint8Array, policy: RepairPolicy, budget: RepairBudget): DraftJson {
  return validate(parseNewWire(raw, policy, budget));
}
/** Bounded snapshot before shape checks; returns the same immutable draft. */
export function buildHistoricalManifest(value: unknown, policy: RepairPolicy, budget: RepairBudget): DraftJson {
  return validate(buildNewWire(value, policy, budget));
}

export interface DraftHistoryRole {readonly role: string; readonly original: RawOriginal;}
/** Resolved bytes/explicit phase bindings, not typed Signed/authority acceptance. */
export interface DraftHistoryInputs {
  readonly manifest: DraftJson;
  readonly roles: readonly DraftHistoryRole[];
  readonly predecessors: readonly DraftHistoryInputs[];
}
function policyFailure(): never {throw new RepairError('repair_invalid_policy');}
function resolverContext(resolver: LocalRawResolver, policy: RepairPolicy, budget: RepairBudget): RepairPolicy {
  if (resolver === null || typeof resolver !== 'object' || isProxy(resolver) ||
      Object.getPrototypeOf(resolver) !== LocalRawResolver.prototype ||
      budget === null || typeof budget !== 'object' || isProxy(budget) ||
      Object.getPrototypeOf(budget) !== RepairBudget.prototype) policyFailure();
  try {
    // Read actual private backing fields, not caller's own getter overrides.
    const heldBudget = Object.getOwnPropertyDescriptor(LocalRawResolver.prototype, 'budget')!.get!.call(resolver);
    const heldPolicy = Object.getOwnPropertyDescriptor(LocalRawResolver.prototype, 'policy')!.get!.call(resolver);
    if (heldBudget !== budget) policyFailure();
    RepairBudget.prototype.assertPolicy.call(budget, policy);
    RepairBudget.prototype.assertPolicy.call(budget, heldPolicy);
    return Object.getOwnPropertyDescriptor(RepairBudget.prototype, 'policy')!.get!.call(budget) as RepairPolicy;
  } catch {policyFailure();}
}
function sameDual(a: Obj, b: Obj): boolean {
  return a.signing_key_id === b.signing_key_id && a.encryption_key_id === b.encryption_key_id;
}
function sameSlot(a: Obj, b: Obj, ack = false): boolean {
  return sameRoot(a.root_key as Obj, b.root_key as Obj) && a.slot_id === b.slot_id &&
    (ack ? a.grant_id === b.grant_id && sameDual(a.receipt_writer as Obj, b.receipt_writer as Obj) :
      a.writer_storage_epoch === b.writer_storage_epoch && sameDual(a.writer as Obj, b.writer as Obj));
}
function sameRef(a: unknown, b: unknown): boolean {return refOrder(rawRef(a), rawRef(b)) === 0;}

/** Resolve existing local packs only, with fixed predecessor transitions.
 * All roles are byte identities, not claims of their expected Signed kind,
 * signer, current/historical validity or complete typed-parent obligations.
 * Real immutable-byte copies in this native runtime charge output_bytes.
 */
export function resolveHistoricalInputs(raw: Uint8Array, resolver: LocalRawResolver,
                                        policy: RepairPolicy, budget: RepairBudget): DraftHistoryInputs {
  const effective = resolverContext(resolver, policy, budget);
  const packs = new Map<string, DraftPack>(), used = new Map<string, Set<number>>(), active = new Set<string>();
  const walk = (manifestRaw: Uint8Array, expected?: Variant, depth = 1): DraftHistoryInputs => {
    if (depth > effective.max_depth) throw new RepairError('repair_over_budget');
    const draft = parseHistoricalManifest(manifestRaw, effective, budget), value = draft.value as Obj;
    const variant = value.variant as Variant;
    if (expected !== undefined && expected !== variant) fail();
    const draftRaw = draft.raw; // One real copy; do not read again merely for size.
    const identity = RepairBudget.prototype.hash.call(budget, draftRaw) + ':' + draftRaw.length;
    if (active.has(identity)) fail(); active.add(identity);
    const rows: DraftHistoryRole[] = [], predecessors: DraftHistoryInputs[] = [], byRole = new Map<string, DraftHistoryRole>();
    for (const item of value.roles as readonly Obj[]) {
      const packRef = rawRef(item.pack_ref), key = refIdentity(packRef);
      let pack = packs.get(key);
      if (!pack) {
        const stored = LocalRawResolver.prototype.resolve.call(resolver, packRef);
        const packRaw = stored.raw;
        pack = parseRawPack(packRaw, packRef, effective, budget);
        packs.set(key, pack); used.set(key, new Set());
      }
      const index = item.entry_index as number;
      const original = pack.entry(index, rawRef(item.document_ref));
      used.get(key)!.add(index);
      const row = Object.freeze({role: item.role as string, original});
      rows.push(row); byRole.set(row.role + '|' + refIdentity(original.ref), row);
    }
    const require = (name: string, reference: unknown): DraftHistoryRole => {
      const row = byRole.get(name + '|' + refIdentity(rawRef(reference)));
      if (!row) fail(); return row;
    };
    const predecessor = (row: DraftHistoryRole, expected: Variant): Obj => {
      const child = walk(row.original.raw, expected, depth + 1), childValue = child.manifest.value as Obj;
      if (!sameRoot(childValue.root_key as Obj, value.root_key as Obj)) fail();
      predecessors.push(child); return childValue;
    };
    const exactRoleRefs = (name: string, wanted: readonly unknown[]): void => {
      const expected = new Set(wanted.map(item => refIdentity(rawRef(item))));
      const actual = rows.filter(row => row.role === name).map(row => refIdentity(row.original.ref));
      if (actual.length !== expected.size || actual.some(key => !expected.has(key))) fail();
    };
    if (variant === 'mailbox_root') {
      require('mailbox.root_authority', value.root_authority_ref); require('mailbox.catalog', value.catalog_ref);
      for (const reference of value.genesis_head_refs as readonly unknown[]) require('genesis.head', reference);
      exactRoleRefs('genesis.head', value.genesis_head_refs as readonly unknown[]);
    } else if (variant === 'mailbox_member') {
      require('delivery.attempt', value.attempt_ref);
    } else if (variant === 'mailbox_feed') {
      require('mailbox.slot', value.slot_ref); require('feed.head', value.feed_head_ref);
      const subtree = value.subtree as Obj;
      require('range.index', subtree.root_ref);
      for (const reference of subtree.parent_path_refs as readonly unknown[]) require('range.index', reference);
      // Descendant index nodes may also be required by the covered subtree.
      // Its complete exact set needs typed index children, not just these refs.
      for (const member of value.members as readonly Obj[]) {
        const child = predecessor(require('history.member', member.historical_manifest_ref), 'mailbox_member');
        if (!sameSlot(child.slot_key as Obj, value.slot_key as Obj) || child.message_id !== member.message_id ||
            !sameRef(child.envelope_ref, member.envelope_ref)) fail();
        for (const [name, field] of [['member.core', 'admission_core_ref'], ['member.link', 'admission_link_ref'],
          ['member.custody', 'source_custody_ref']]) require(name, member[field]);
      }
      exactRoleRefs('history.member', (value.members as readonly Obj[]).map(member => member.historical_manifest_ref));
    } else if (variant === 'ack_unbound') {
      require('ack.root_authority', value.root_authority_ref);
    } else {
      const priorRole = variant === 'ack_empty' ? 'history.ack_unbound' : 'history.ack_empty';
      const priorVariant = variant === 'ack_empty' ? 'ack_unbound' : 'ack_empty';
      const prior = rows.filter(row => row.role === priorRole);
      if (prior.length !== 1) fail();
      const child = predecessor(prior[0], priorVariant);
      if (!sameSlot(child.ack_slot as Obj, value.ack_slot as Obj, true) ||
          !sameRef(child.root_authority_ref, value.root_authority_ref)) fail();
      if (variant === 'ack_empty') {
        require('ack.write_grant', value.grant_ref); require('ack.binding', value.binding_ref);
      } else {
        if (!sameRef(child.grant_ref, value.grant_ref) || !sameRef(child.binding_ref, value.binding_ref)) fail();
        for (const [name, field] of [['recipient.receipt', 'receipt_ref'], ['ack.put', 'put_ref'],
          ['ack.disclosure', 'disclosure_ref']]) require(name, value[field]);
      }
    }
    active.delete(identity);
    return Object.freeze({manifest: draft, roles: Object.freeze(rows), predecessors: Object.freeze(predecessors)});
  };
  const result = walk(raw);
  for (const [key, pack] of packs) {
    if (used.get(key)!.size !== pack.entries.length) fail();
  }
  return result;
}
