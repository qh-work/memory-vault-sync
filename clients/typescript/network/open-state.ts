/** Native local open-control floors and finite contact leases, in the caller's
 * existing transport database. No subprocess, network, identity store or Vault. */
import type {DatabaseSync} from 'node:sqlite';
import {
  canonicalBytes, document, documentSha256, safeInteger, sha256, validateSigningIdentity,
} from './crypto.ts';
import type {DocumentInput, SigningIdentityDocument} from './crypto.ts';
import {NetworkError, transaction} from './io.ts';
import {
  MAX_CONTROL_BYTES, MAX_DESCRIPTOR_BYTES, MAX_DESCRIPTOR_SECONDS, MAX_REQUEST_SECONDS,
  MAX_LEASE_SECONDS, contactKey, issueLease, verifyNode, verifyContact, verifyRequest,
} from './open-control.ts';
import type {SignedNode, SignedContact, SignedOpen, OpenNode, OpenContact} from './open-control.ts';

type Row = Record<string, any>;
type Result = Record<string, any>;
export const FLOOR_RETENTION_SECONDS = MAX_DESCRIPTOR_SECONDS + MAX_REQUEST_SECONDS + 30;
export const MAX_FLOORS = 4096;
export const MAX_STATE_BYTES = 64 * 1024 * 1024;
export const RESERVED_BYTES_PER_FLOOR = 2 * MAX_DESCRIPTOR_BYTES + 512;
function fail(code: string, retryable = false): never {throw new NetworkError(code, retryable);}
function clock(now?: number): number {return now === undefined ? Math.floor(Date.now() / 1000) : safeInteger(now);}
function freshTransaction<T>(db: DatabaseSync, operation: () => T): T {
  if (db.isTransaction) fail('open_storage_transaction');
  return transaction(db, operation);
}
function parsed(value: Uint8Array): Result {return document(value) as Result;}
function same(first: unknown, second: unknown): boolean {
  return Buffer.from(canonicalBytes(first as DocumentInput)).equals(Buffer.from(canonicalBytes(second as DocumentInput)));
}

export interface CheckpointOptions {maximum_records?: number; maximum_bytes?: number;}
export class OpenCheckpoints {
  readonly connection: DatabaseSync;
  maximum_records: number;
  maximum_bytes: number;
  constructor(connection: DatabaseSync, options: CheckpointOptions = {}) {
    this.maximum_records = safeInteger(options.maximum_records === undefined ? MAX_FLOORS : options.maximum_records, 1);
    this.maximum_bytes = safeInteger(options.maximum_bytes === undefined ? MAX_STATE_BYTES : options.maximum_bytes, 1);
    if (this.maximum_records > MAX_FLOORS || this.maximum_bytes > MAX_STATE_BYTES) fail('open_invalid_checkpoint_policy');
    this.connection = connection;
  }
  initialize(): void {
    freshTransaction(this.connection, () => {
      this.connection.exec(`CREATE TABLE IF NOT EXISTS open_control_floors (
        kind TEXT NOT NULL,key_id TEXT NOT NULL,revision INTEGER NOT NULL,
        digest TEXT NOT NULL,record BLOB NOT NULL,second_digest TEXT,second_record BLOB,
        status TEXT NOT NULL,retain_until INTEGER NOT NULL,PRIMARY KEY(kind,key_id));
        CREATE INDEX IF NOT EXISTS open_control_floor_expiry ON open_control_floors(retain_until);`);
    });
  }
  #verify(signed: Result, now: number): OpenNode | OpenContact {
    if (signed.payload?.kind === 'node') return verifyNode(signed, {now});
    if (signed.payload?.kind === 'contact') return verifyContact(signed, {now});
    return fail('open_unsupported_control');
  }
  accept(value: DocumentInput, options: {now?: number} = {}): OpenNode | OpenContact {
    const signed = document(value, MAX_DESCRIPTOR_BYTES) as Result;
    this.#verify(signed, clock(options.now));
    const {payload, failure} = freshTransaction(this.connection, () => {
      const db = this.connection, now = clock(options.now), payload = this.#verify(signed, now);
      db.prepare('DELETE FROM open_control_floors WHERE retain_until<=?').run(now);
      const key = [payload.kind, payload.signing_key.key_id];
      const previous = db.prepare('SELECT revision,digest,status,retain_until FROM open_control_floors WHERE kind=? AND key_id=?').get(...key) as Row | undefined;
      const fingerprint = documentSha256(signed);
      const retained = Math.max(now + FLOOR_RETENTION_SECONDS, payload.expires_at + MAX_REQUEST_SECONDS + 30,
        previous?.retain_until ?? 0);
      if (previous?.status === 'conflict') fail('open_control_conflict');
      if (previous && payload.revision < previous.revision) fail('open_control_rollback');
      let failure: string | null = null;
      if (previous && payload.revision === previous.revision && fingerprint !== previous.digest) {
        db.prepare("UPDATE open_control_floors SET status='conflict',second_digest=?,second_record=?,retain_until=? WHERE kind=? AND key_id=?")
          .run(fingerprint, canonicalBytes(signed), retained, ...key);
        failure = 'open_control_conflict';
      } else {
        db.prepare(`INSERT INTO open_control_floors(kind,key_id,revision,digest,record,status,retain_until)
          VALUES(?,?,?,?,?,?,?) ON CONFLICT(kind,key_id) DO UPDATE SET
          revision=excluded.revision,digest=excluded.digest,record=excluded.record,
          status=excluded.status,retain_until=excluded.retain_until`)
          .run(...key, payload.revision, fingerprint, canonicalBytes(signed), payload.status, retained);
        if (payload.status === 'revoked') failure = 'open_control_revoked';
      }
      const count = (db.prepare('SELECT count(*) AS n FROM open_control_floors').get() as Row).n;
      if (count > this.maximum_records || count * RESERVED_BYTES_PER_FLOOR > this.maximum_bytes) fail('open_checkpoint_capacity', true);
      return {payload, failure};
    });
    if (failure) fail(failure);
    return payload;
  }
}

export interface IndexOptions {
  enabled?: boolean; maximum_records?: number; maximum_bytes?: number;
  maximum_replays?: number; maximum_lease_seconds?: number;
}
export class OpenIndex {
  readonly connection: DatabaseSync;
  readonly signer: SigningIdentityDocument;
  node: SignedNode;
  enabled: boolean;
  maximum_records: number;
  maximum_bytes: number;
  maximum_replays: number;
  maximum_lease_seconds: number;
  constructor(connection: DatabaseSync, signer: SigningIdentityDocument, node: SignedNode, options: IndexOptions = {}) {
    this.enabled = options.enabled === undefined ? false : options.enabled;
    if (typeof this.enabled !== 'boolean') fail('open_invalid_index_policy');
    this.maximum_records = safeInteger(options.maximum_records === undefined ? 128 : options.maximum_records, 1);
    this.maximum_bytes = safeInteger(options.maximum_bytes === undefined ? 2 * 1024 * 1024 : options.maximum_bytes, 1);
    this.maximum_replays = safeInteger(options.maximum_replays === undefined ? 512 : options.maximum_replays, 1);
    this.maximum_lease_seconds = safeInteger(options.maximum_lease_seconds === undefined ? MAX_LEASE_SECONDS : options.maximum_lease_seconds, 1);
    if (this.maximum_records > 65_536 || this.maximum_bytes > MAX_STATE_BYTES ||
        this.maximum_replays > 65_536 || this.maximum_lease_seconds > MAX_LEASE_SECONDS) fail('open_invalid_index_policy');
    const checked = verifyNode(node, {now: node.payload.issued_at});
    if (!same(checked.signing_key, validateSigningIdentity(signer))) fail('open_wrong_node');
    this.connection = connection;
    this.signer = document(signer) as unknown as SigningIdentityDocument;
    this.node = document(node as unknown as DocumentInput) as unknown as SignedNode;
  }
  initialize(): void {
    freshTransaction(this.connection, () => {
      const db = this.connection;
      db.exec(`CREATE TABLE IF NOT EXISTS open_index_state (name TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS open_contact_floors (
          owner TEXT PRIMARY KEY,lookup_key TEXT NOT NULL UNIQUE,revision INTEGER NOT NULL,
          digest TEXT NOT NULL,record BLOB NOT NULL,second_digest TEXT,second_record BLOB,
          status TEXT NOT NULL,retain_until INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS open_contacts (
          owner TEXT PRIMARY KEY,record BLOB NOT NULL,lease BLOB NOT NULL,
          lease_id TEXT NOT NULL,expires_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS open_index_replay (
          owner TEXT NOT NULL,request_id TEXT NOT NULL,digest TEXT NOT NULL,
          response BLOB NOT NULL,retain_until INTEGER NOT NULL,PRIMARY KEY(owner,request_id));
        CREATE INDEX IF NOT EXISTS open_contact_expiry ON open_contacts(expires_at);
        CREATE INDEX IF NOT EXISTS open_floor_expiry ON open_contact_floors(retain_until);
        CREATE INDEX IF NOT EXISTS open_replay_expiry ON open_index_replay(retain_until);`);
      const expected = this.signer.key_id + ':' + this.node.payload.storage_epoch;
      const previous = db.prepare("SELECT value FROM open_index_state WHERE name='binding'").get() as Row | undefined;
      if (previous && previous.value !== expected) fail('open_storage_epoch_mismatch');
      db.prepare("INSERT OR IGNORE INTO open_index_state(name,value) VALUES('binding',?)").run(expected);
    });
  }
  #prune(now: number): void {
    this.connection.prepare('DELETE FROM open_contacts WHERE expires_at<=?').run(now);
    this.connection.prepare('DELETE FROM open_contact_floors WHERE retain_until<=? AND owner NOT IN (SELECT owner FROM open_contacts)').run(now);
    this.connection.prepare('DELETE FROM open_index_replay WHERE retain_until<=?').run(now);
  }
  #capacity(): void {
    const db = this.connection;
    const records = (db.prepare('SELECT count(*) AS n FROM open_contact_floors').get() as Row).n;
    const replays = (db.prepare('SELECT count(*) AS n FROM open_index_replay').get() as Row).n;
    const floors = records * RESERVED_BYTES_PER_FLOOR;
    const contacts = (db.prepare('SELECT coalesce(sum(length(record)+length(lease)+256),0) AS n FROM open_contacts').get() as Row).n;
    const replayBytes = (db.prepare('SELECT coalesce(sum(length(response)+256),0) AS n FROM open_index_replay').get() as Row).n;
    if (records > this.maximum_records || replays > this.maximum_replays || floors + contacts + replayBytes > this.maximum_bytes)
      fail('open_index_capacity', true);
  }
  #get(key: string, now: number): Result {
    const db = this.connection, floor = db.prepare('SELECT owner,status FROM open_contact_floors WHERE lookup_key=?').get(key) as Row | undefined;
    if (!floor) return {state: 'not_found'};
    if (floor.status === 'revoked' || floor.status === 'conflict') return {state: floor.status};
    const row = db.prepare('SELECT record,lease FROM open_contacts WHERE owner=? AND expires_at>?').get(floor.owner, now) as Row | undefined;
    return row ? {state: 'found', contact: parsed(row.record), lease: parsed(row.lease)} : {state: 'not_found'};
  }
  handle(value: DocumentInput, options: {now?: number} = {}): Result {
    const signed = document(value, MAX_CONTROL_BYTES) as unknown as SignedOpen;
    let checked = verifyRequest(signed, {node: this.node, now: clock(options.now)});
    if (!['get', 'put', 'renew'].includes(checked.action)) fail('open_unsupported_action');
    if (!this.enabled || !this.node.payload.roles.includes('directory')) fail('open_index_closed');
    const result = freshTransaction(this.connection, () => {
      const now = clock(options.now);
      checked = verifyRequest(signed, {node: this.node, now});
      this.#prune(now);
      const result = checked.action === 'get' ? {body: this.#get(checked.body.key, now), failure: null}
        : this.#write(signed, checked, now);
      this.#capacity();
      return result;
    });
    if (result.failure) fail(result.failure);
    return result.body;
  }
  #write(signed: SignedOpen, request: Result, now: number): {body: Result; failure: string | null} {
    const db = this.connection, body = request.body;
    const contact = document(body.contact) as unknown as SignedContact, payload = verifyContact(contact, {now});
    const owner = payload.signing_key.key_id;
    if (!same(request.signer, payload.signing_key)) fail('open_index_not_owner');
    const requestDigest = documentSha256(signed as unknown as DocumentInput), contactDigest = documentSha256(contact as unknown as DocumentInput);
    const oldRequest = db.prepare('SELECT digest,response FROM open_index_replay WHERE owner=? AND request_id=?').get(owner, request.request_id) as Row | undefined;
    if (oldRequest) {
      if (oldRequest.digest !== requestDigest) fail('open_request_conflict');
      return {body: parsed(oldRequest.response), failure: null};
    }
    if (body.lease_seconds > this.maximum_lease_seconds) fail('open_index_lease_limit');
    const floor = db.prepare('SELECT revision,digest,record,status,retain_until,second_digest FROM open_contact_floors WHERE owner=?').get(owner) as Row | undefined;
    if (floor?.status === 'conflict') fail('open_contact_conflict');
    if (floor && payload.revision < floor.revision) fail('open_contact_rollback');
    if (floor && payload.revision === floor.revision && contactDigest !== floor.digest) {
      db.prepare("UPDATE open_contact_floors SET second_digest=?,second_record=?,status='conflict',retain_until=? WHERE owner=?")
        .run(contactDigest, canonicalBytes(contact as unknown as DocumentInput), Math.max(floor.retain_until, now + FLOOR_RETENTION_SECONDS), owner);
      db.prepare('DELETE FROM open_contacts WHERE owner=?').run(owner);
      return {body: {}, failure: 'open_contact_conflict'};
    }
    let leaseId: string;
    if (request.action === 'renew') {
      const previous = db.prepare('SELECT record,lease_id FROM open_contacts WHERE owner=?').get(owner) as Row | undefined;
      if (!previous || previous.lease_id !== body.lease_id || documentSha256(parsed(previous.record)) !== contactDigest) fail('open_lease_not_found');
      leaseId = previous.lease_id;
    } else leaseId = 'lease_' + sha256(Buffer.from(this.signer.key_id + ':' + requestDigest, 'ascii'));
    const lease = issueLease(this.signer, {node: this.node, contact, request: signed, lease_id: leaseId,
      issued_at: now, expires_at: Math.min(now + body.lease_seconds, payload.expires_at)});
    const state = payload.status === 'active' && payload.allow_discovery ? 'active' : 'revoked';
    const retained = Math.max(payload.expires_at + MAX_REQUEST_SECONDS + 30, now + FLOOR_RETENTION_SECONDS, floor?.retain_until ?? 0);
    db.prepare(`INSERT INTO open_contact_floors(owner,lookup_key,revision,digest,record,second_digest,second_record,status,retain_until)
      VALUES(?,?,?,?,?,NULL,NULL,?,?) ON CONFLICT(owner) DO UPDATE SET
      revision=excluded.revision,digest=excluded.digest,record=excluded.record,
      second_digest=NULL,second_record=NULL,status=excluded.status,retain_until=excluded.retain_until`)
      .run(owner, contactKey(owner), payload.revision, contactDigest, canonicalBytes(contact as unknown as DocumentInput), state, retained);
    if (state === 'active') {
      db.prepare(`INSERT INTO open_contacts(owner,record,lease,lease_id,expires_at) VALUES(?,?,?,?,?)
        ON CONFLICT(owner) DO UPDATE SET record=excluded.record,lease=excluded.lease,
        lease_id=excluded.lease_id,expires_at=excluded.expires_at`)
        .run(owner, canonicalBytes(contact as unknown as DocumentInput), canonicalBytes(lease as unknown as DocumentInput), leaseId, lease.payload.expires_at);
    } else db.prepare('DELETE FROM open_contacts WHERE owner=?').run(owner);
    const result = {lease};
    db.prepare('INSERT INTO open_index_replay(owner,request_id,digest,response,retain_until) VALUES(?,?,?,?,?)')
      .run(owner, request.request_id, requestDigest, canonicalBytes(result as unknown as DocumentInput), request.expires_at + 30);
    return {body: result, failure: null};
  }
}
