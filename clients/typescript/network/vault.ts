/** The existing canonical SQLite v2 Vault, independently implemented in Node.
 * No ambient path/key discovery, Python subprocess, network or second memory
 * store. Text recall is deliberately bounded and is not Python's full ranking.
 */
import { randomBytes } from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';
import { canonicalBytes, document, sha256, validateSigningIdentity, validateSigningPublic } from './crypto.ts';
import type { DocumentInput, SigningIdentityDocument, SigningPublicDescriptor } from './crypto.ts';
import { NetworkError, openPrivateDatabase, transaction } from './io.ts';
import { buildRecord, validateRecord, canonicalRecordBytes, signRecord, verifyRecord, parseShare, encodeShare, normalizeText } from './records.ts';
import type { MemoryRecord, RecordAttestation, SignedMemory } from './records.ts';

type Admission = 'local_unsigned' | 'accepted_unsigned' | 'verified' | 'quarantined';
type Row = Record<string, any>;
export type VaultTrust = readonly SigningPublicDescriptor[] | (() => readonly SigningPublicDescriptor[]);
export interface VaultOptions { vaultPath: string; identity?: SigningIdentityDocument; trust?: VaultTrust }
export interface RememberInput {
  requestId: string; kind: string; text: string; entities?: string[];
  relations?: { type: string; target: string }[]; provenance?: Record<string, string>;
}
export interface RecallOptions { limit?: number; after?: number; maximumScanned?: number; maximumBytes?: number; maximumSeconds?: number }
export interface ShareOptions { maximumRecords?: number; maximumBytes?: number; maximumSeconds?: number }

const MAX_RECORD = 2 * 1024 * 1024, MAX_SHARE = 8 * 1024 * 1024, MAX_RECORDS = 256;
const AUTHORITY = Object.freeze({ memory: 'untrusted_historical_evidence', instruction_eligible: false,
  authorization_eligible: false, execution_eligible: false, policy_change_eligible: false, current_user_input_precedence: true });
const TABLES: Record<string, string> = {
  metadata: 'CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL)',
  memories: 'CREATE TABLE memories(ingest_seq INTEGER PRIMARY KEY AUTOINCREMENT,memory_id TEXT NOT NULL UNIQUE,record_sha256 TEXT NOT NULL UNIQUE,kind TEXT NOT NULL,text TEXT NOT NULL,normalized_text TEXT NOT NULL,created_at TEXT NOT NULL,record_json TEXT NOT NULL)',
  terms: 'CREATE TABLE terms(token TEXT NOT NULL,memory_id TEXT NOT NULL REFERENCES memories(memory_id),frequency INTEGER NOT NULL,PRIMARY KEY(token,memory_id))',
  relations: 'CREATE TABLE relations(source_id TEXT NOT NULL REFERENCES memories(memory_id),relation TEXT NOT NULL,target_id TEXT NOT NULL REFERENCES memories(memory_id) DEFERRABLE INITIALLY DEFERRED,PRIMARY KEY(source_id,relation,target_id))',
  receipts: 'CREATE TABLE receipts(request_id TEXT PRIMARY KEY,request_sha256 TEXT NOT NULL,response_json TEXT NOT NULL,created_at TEXT NOT NULL)',
  record_admissions: "CREATE TABLE record_admissions(memory_id TEXT PRIMARY KEY REFERENCES memories(memory_id),state TEXT NOT NULL CHECK(state IN ('local_unsigned','accepted_unsigned','verified','quarantined')),signer_key_id TEXT,attestation_json TEXT)",
  delivery_log: 'CREATE TABLE delivery_log(sequence INTEGER PRIMARY KEY AUTOINCREMENT,memory_id TEXT NOT NULL REFERENCES memories(memory_id))',
  transfer_receipts: 'CREATE TABLE transfer_receipts(transfer_id TEXT PRIMARY KEY,payload_sha256 TEXT NOT NULL,result_json TEXT NOT NULL,created_at TEXT NOT NULL)',
  sqlite_sequence: 'CREATE TABLE sqlite_sequence(name,seq)',
};
const INDEXES: Record<string, string> = {
  terms_memory: 'CREATE INDEX terms_memory ON terms(memory_id)',
  relations_target: 'CREATE INDEX relations_target ON relations(target_id,relation)',
  delivery_memory: 'CREATE INDEX delivery_memory ON delivery_log(memory_id)',
};
const DERIVED: Record<string, string> = {
  memory_entities: 'CREATE TABLE memory_entities(entity TEXT NOT NULL,memory_id TEXT NOT NULL REFERENCES memories(memory_id),PRIMARY KEY(entity,memory_id))',
  retrieval_index: 'CREATE TABLE retrieval_index(memory_id TEXT PRIMARY KEY REFERENCES memories(memory_id),profile TEXT NOT NULL,token_count INTEGER NOT NULL CHECK(token_count>=0),timeline_key TEXT NOT NULL)',
  memory_entities_memory: 'CREATE INDEX memory_entities_memory ON memory_entities(memory_id)',
  retrieval_index_timeline: 'CREATE INDEX retrieval_index_timeline ON retrieval_index(timeline_key,memory_id)',
};
const TRIGGERS: Record<string, string> = {
  memories_no_update: "CREATE TRIGGER memories_no_update BEFORE UPDATE ON memories BEGIN SELECT RAISE(ABORT,'append-only memories'); END",
  memories_no_delete: "CREATE TRIGGER memories_no_delete BEFORE DELETE ON memories BEGIN SELECT RAISE(ABORT,'append-only memories'); END",
};
// Exact Python text matters: its dependency certificate compares trigger SQL.
const EPOCH_STEP = "SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM metadata WHERE key='dependency_epoch' " +
  "AND CAST(value AS INTEGER)>=0 AND CAST(value AS INTEGER)<9223372036854775807) " +
  "THEN RAISE(ABORT,'dependency epoch unavailable') END; " +
  "UPDATE metadata SET value=CAST(value AS INTEGER)+1 WHERE key='dependency_epoch'; ";
const EPOCH: Record<string, string> = Object.fromEntries([
  ['dependency_admission_update', 'AFTER UPDATE ON record_admissions'],
  ['dependency_admission_delete', 'AFTER DELETE ON record_admissions'],
  ['dependency_admission_replace', 'BEFORE INSERT ON record_admissions WHEN EXISTS(SELECT 1 FROM record_admissions WHERE memory_id=NEW.memory_id)'],
  ['dependency_memory_update', 'AFTER UPDATE ON memories'],
  ['dependency_memory_delete', 'AFTER DELETE ON memories'],
  ['dependency_memory_replace', 'BEFORE INSERT ON memories WHEN EXISTS(SELECT 1 FROM memories WHERE memory_id=NEW.memory_id OR record_sha256=NEW.record_sha256)'],
].map(([name, event]) => [name, 'CREATE TRIGGER ' + name + ' ' + event + ' BEGIN ' + EPOCH_STEP + 'END']));
const KNOWN = { ...TABLES, ...INDEXES, ...DERIVED, ...TRIGGERS, ...EPOCH };
const REQUIRED = new Set([...Object.keys(TABLES), ...Object.keys(INDEXES), ...Object.keys(TRIGGERS)]);
function fail(code: string, retryable = false): never { throw new NetworkError(code, retryable); }
function storageFailure(error: unknown): never {
  if (error && typeof error === 'object' && (error as Row).code === 'ERR_SQLITE_ERROR') {
    const code = Number((error as Row).errcode) & 255;
    if (code === 5 || code === 6) fail('busy', true);
    fail('storage_unavailable');
  }
  throw error;
}
function bounded(value: unknown, fallback: number, minimum: number, maximum: number): number {
  if (value === undefined) return fallback;
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < minimum || value > maximum) fail('invalid_vault_budget');
  return value;
}
function memoryId(value: unknown): string {
  if (typeof value !== 'string' || !/^mem_[0-9a-f]{40}$/.test(value)) fail('invalid_memory_id');
  return value;
}
function now(): string { return new Date().toISOString().replace('.000Z', 'Z'); }
function json(value: unknown, maximum = MAX_RECORD): string { return Buffer.from(canonicalBytes(value, maximum)).toString('utf8'); }
function sqlTokens(value: string): string {
  // Preserve quoted string contents; never normalize a trigger's literal away.
  return (value.match(/'(?:''|[^'])*'|[A-Za-z_][A-Za-z_0-9]*|[0-9]+|[^\s]/g) || [])
    .map(token => token.startsWith("'") ? token : token.toUpperCase()).join('\0').replace(/\0;$/, '');
}
const STOP = new Set('about after also and are but can for from have into not that the their then this was were will with you your'.split(' '));
function tokens(text: string): Map<string, number> {
  const normalized = normalizeText(text), counts = new Map<string, number>();
  const add = (token: string) => { counts.set(token, (counts.get(token) || 0) + 1); };
  for (const match of normalized.matchAll(/[a-z0-9][a-z0-9_+.-]{0,63}/g)) if (!STOP.has(match[0])) add('w:' + match[0]);
  for (const match of normalized.matchAll(/[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff\u3040-\u30ff\uac00-\ud7af]+/gu)) {
    const run = Array.from(match[0]);
    if (run.length === 1) add('c:' + run[0]);
    else { for (let i = 0; i + 1 < run.length; i++) add('c:' + run[i] + run[i + 1]); if (run.length <= 8) add('p:' + match[0]); }
  }
  // A million unique terms would otherwise make one synchronous write unbounded.
  if (counts.size > 32768) fail('vault_index_work_limit');
  return counts;
}

export class CanonicalVault {
  readonly vaultPath: string;
  #db: DatabaseSync;
  #identity?: SigningIdentityDocument;
  #trust: VaultTrust;
  #closed = false;

  constructor(options: VaultOptions) {
    this.vaultPath = options.vaultPath;
    this.#identity = options.identity === undefined ? undefined : document(options.identity as unknown as DocumentInput, 4096) as unknown as SigningIdentityDocument;
    const self = this.#identity ? validateSigningIdentity(this.#identity) : undefined;
    // Never add self to an explicitly supplied trust policy (including []).
    this.#trust = options.trust ?? (self ? [self] : []);
    try { this.#db = openPrivateDatabase(this.vaultPath); } catch (error) { storageFailure(error); }
    try {
      transaction(this.#db, () => {
        const empty = this.#db.prepare('SELECT 1 FROM sqlite_master LIMIT 1').get() === undefined;
        if (empty) {
          for (const [name, sql] of Object.entries(TABLES)) if (name !== 'sqlite_sequence') this.#db.exec(sql);
          for (const sql of [...Object.values(INDEXES), ...Object.values(TRIGGERS)]) this.#db.exec(sql);
          const insert = this.#db.prepare('INSERT INTO metadata(key,value) VALUES(?,?)');
          for (const [key, value] of Object.entries({ schema: 'universal-memory-sqlite/v2', min_reader: '2', min_writer: '2', store_id: 'store_' + randomBytes(16).toString('hex') })) insert.run(key, value);
          this.#db.exec('PRAGMA user_version=2');
        }
        const found = this.#schema();
        for (const [name, sql] of Object.entries(DERIVED)) if (!found.has(name)) this.#db.exec(sql);
        const metadata = this.#metadata();
        if (!Object.keys(EPOCH).every(name => found.has(name)) || !/^(0|[1-9][0-9]{0,18})$/.test(metadata.dependency_epoch || '') ||
            BigInt(metadata.dependency_epoch || '-1') >= 9223372036854775808n || !/^[0-9a-f]{32}$/.test(metadata.dependency_epoch_nonce || '')) {
          const set = this.#db.prepare('INSERT INTO metadata(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value');
          set.run('dependency_epoch', '0'); set.run('dependency_epoch_nonce', randomBytes(16).toString('hex'));
          for (const [name, sql] of Object.entries(EPOCH)) if (!found.has(name)) this.#db.exec(sql);
        }
      });
    } catch (error) { this.#db.close(); this.#closed = true; storageFailure(error); }
  }
  close(): void { if (!this.#closed) { this.#db.close(); this.#closed = true; } }
  #metadata(): Record<string, string> {
    const rows = this.#db.prepare("SELECT key,value FROM metadata WHERE key IN ('schema','min_reader','min_writer','store_id','dependency_epoch','dependency_epoch_nonce')").all();
    return Object.fromEntries(rows.map(row => [String(row.key), String(row.value)]));
  }
  #schema(): Set<string> {
    const rows = this.#db.prepare('SELECT type,name,tbl_name,sql FROM sqlite_master LIMIT 65').all();
    if (rows.length > 64) fail('unsupported_database_schema');
    const found = new Set<string>();
    for (const row of rows) {
      const name = String(row.name), table = String(row.tbl_name);
      if (row.type === 'index' && row.sql === null && new RegExp('^sqlite_autoindex_' + table + '_[12]$').test(name) && Object.hasOwn(TABLES, table) ||
          row.type === 'index' && row.sql === null && ['sqlite_autoindex_memory_entities_1', 'sqlite_autoindex_retrieval_index_1'].includes(name)) continue;
      const expected = Object.hasOwn(KNOWN, name) ? KNOWN[name] : undefined;
      if (typeof row.sql !== 'string' || expected === undefined ||
          (Object.hasOwn(EPOCH, name) ? row.sql !== expected : sqlTokens(row.sql) !== sqlTokens(expected))) fail('unsupported_database_schema');
      found.add(name);
    }
    if ([...REQUIRED].some(name => !found.has(name))) fail('unsupported_database_schema');
    const metadata = this.#metadata();
    if (metadata.schema !== 'universal-memory-sqlite/v2' || metadata.min_reader !== '2' || metadata.min_writer !== '2' ||
        !/^store_[0-9a-f]{32}$/.test(metadata.store_id || '') || this.#db.prepare('PRAGMA user_version').get()?.user_version !== 2) fail('unsupported_database_schema');
    return found;
  }
  #run<T>(write: boolean, operation: () => T): T {
    if (this.#closed) fail('vault_closed');
    try { this.#db.exec(write ? 'BEGIN IMMEDIATE' : 'BEGIN'); } catch (error) { storageFailure(error); }
    try { this.#schema(); const result = operation(); this.#db.exec('COMMIT'); return result; }
    catch (error) {
      try { if (this.#db.isTransaction) this.#db.exec('ROLLBACK'); } catch (rollback) { storageFailure(rollback); }
      storageFailure(error);
    }
  }
  #trusted(): SigningPublicDescriptor[] {
    const selected = typeof this.#trust === 'function' ? this.#trust() : this.#trust;
    if (!Array.isArray(selected) || selected.length > 4096) fail('invalid_vault_trust');
    const result = selected.map(key => validateSigningPublic(key));
    if (new Set(result.map(key => key.key_id)).size !== result.length) fail('invalid_vault_trust');
    return result;
  }
  #rank(state: unknown, signer: unknown, trusted: readonly SigningPublicDescriptor[]): number {
    if (state === 'local_unsigned' || state === 'accepted_unsigned') return 1;
    if (state === 'quarantined') return 0;
    if (state !== 'verified' || typeof signer !== 'string') fail('stored_admission_invalid');
    return trusted.some(key => key.key_id === signer) ? 2 : 0;
  }
  #row(id: string): Row | undefined {
    const size = this.#db.prepare('SELECT length(CAST(m.record_json AS BLOB)) AS record_size,length(CAST(a.attestation_json AS BLOB)) AS proof_size FROM memories m LEFT JOIN record_admissions a USING(memory_id) WHERE memory_id=?').get(id);
    if (size === undefined) return undefined;
    if (typeof size.record_size !== 'number' || size.record_size > MAX_RECORD || (size.proof_size !== null && Number(size.proof_size) > 2048)) fail('stored_record_too_large');
    return this.#db.prepare('SELECT m.*,a.state,a.signer_key_id,a.attestation_json FROM memories m LEFT JOIN record_admissions a USING(memory_id) WHERE memory_id=?').get(id);
  }
  #decode(row: Row): SignedMemory {
    const record = validateRecord(document(Buffer.from(String(row.record_json), 'utf8'), MAX_RECORD)) as MemoryRecord;
    if (Buffer.from(canonicalRecordBytes(record)).toString('utf8') !== row.record_json || record.memory_id !== row.memory_id ||
        record.record_sha256 !== row.record_sha256 || record.kind !== row.kind || record.text !== row.text || record.created_at !== row.created_at ||
        normalizeText(record.text) !== row.normalized_text) fail('stored_record_invalid');
    const attestation = row.attestation_json === null ? null : document(Buffer.from(String(row.attestation_json), 'utf8'), 2048) as unknown as RecordAttestation;
    if (!['local_unsigned', 'accepted_unsigned', 'verified', 'quarantined'].includes(row.state) ||
        (row.state === 'verified' ? attestation === null || row.signer_key_id !== attestation.key_id : attestation !== null || row.signer_key_id !== null)) fail('stored_admission_invalid');
    return { record, attestation };
  }
  #get(id: string, trusted: readonly SigningPublicDescriptor[], hidden = false): SignedMemory | null {
    const row = this.#row(id); if (row === undefined) return null;
    if (!hidden && this.#rank(row.state, row.signer_key_id, trusted) === 0) return null;
    const value = this.#decode(row);
    if (row.state === 'verified' && this.#rank(row.state, row.signer_key_id, trusted) > 0) verifyRecord(value.record, value.attestation!, trusted);
    return value;
  }
  get(id: string, options: { includeQuarantined?: boolean } = {}): SignedMemory | null {
    memoryId(id);
    if (options.includeQuarantined !== undefined && typeof options.includeQuarantined !== 'boolean') fail('invalid_vault_option');
    return this.#run(false, () => this.#get(id, this.#trusted(), options.includeQuarantined === true));
  }
  /** Local inspection metadata, never an authorization grant or a network read. */
  verification(id: string): Row {
    memoryId(id);
    return this.#run(false, () => {
      const row = this.#row(id); if (!row) fail('memory_not_found');
      this.#decode(row);
      return this.#verification(id, this.#trusted());
    });
  }
  #verification(id: string, trusted: readonly SigningPublicDescriptor[]): Row {
    const row = this.#db.prepare('SELECT state,signer_key_id FROM record_admissions WHERE memory_id=?').get(id);
    if (row === undefined) fail('stored_admission_missing');
    return { admission: row.state, signer_key_id: row.signer_key_id, signature_verified_at_admission: row.state === 'verified',
      current_trust_checked: row.state === 'verified', eligible_for_context: this.#rank(row.state, row.signer_key_id, trusted) > 0,
      claimed_provenance_is_authenticated: false, grants_authority: false };
  }
  #insert(record: MemoryRecord, pending: boolean): boolean {
    const encoded = Buffer.from(canonicalRecordBytes(record)).toString('utf8');
    const old = this.#row(record.memory_id);
    if (old !== undefined) { if (old.record_json !== encoded) fail('memory_id_collision'); return false; }
    if (!pending) for (const relation of record.relations) if (this.#row(relation.target) === undefined) fail('relation_target_not_found');
    const indexed = tokens([record.text, ...record.entities].join(' '));
    this.#db.prepare('INSERT INTO memories(memory_id,record_sha256,kind,text,normalized_text,created_at,record_json) VALUES(?,?,?,?,?,?,?)')
      .run(record.memory_id, record.record_sha256, record.kind, record.text, normalizeText(record.text), record.created_at, encoded);
    const insert = this.#db.prepare('INSERT INTO terms(token,memory_id,frequency) VALUES(?,?,?)');
    for (const [token, count] of indexed) insert.run(token, record.memory_id, count);
    const entity = this.#db.prepare('INSERT INTO memory_entities(entity,memory_id) VALUES(?,?)');
    for (const name of record.entities) entity.run(name, record.memory_id);
    const relation = this.#db.prepare('INSERT INTO relations(source_id,relation,target_id) VALUES(?,?,?)');
    for (const edge of record.relations) relation.run(record.memory_id, edge.type, edge.target);
    // Deliberately no retrieval_index certificate: Python sees an incomplete
    // disposable index and can rebuild it without changing canonical bytes.
    return true;
  }
  #admit(value: SignedMemory, state: Admission, trusted: readonly SigningPublicDescriptor[]): boolean {
    const old = this.#db.prepare('SELECT state,signer_key_id FROM record_admissions WHERE memory_id=?').get(value.record.memory_id);
    const rank = state === 'verified' ? 2 : state === 'quarantined' ? 0 : 1;
    if (old !== undefined && this.#rank(old.state, old.signer_key_id, trusted) >= rank) return false;
    const proof = state === 'verified' ? value.attestation : null;
    if (state === 'verified' && proof === null) fail('share_record_signature_required');
    this.#db.prepare('INSERT INTO record_admissions(memory_id,state,signer_key_id,attestation_json) VALUES(?,?,?,?) ON CONFLICT(memory_id) DO UPDATE SET state=excluded.state,signer_key_id=excluded.signer_key_id,attestation_json=excluded.attestation_json')
      .run(value.record.memory_id, state, proof?.key_id ?? null, proof === null ? null : json(proof, 2048));
    this.#db.prepare('INSERT INTO delivery_log(memory_id) VALUES(?)').run(value.record.memory_id);
    return old !== undefined;
  }
  #requeue(seeds: string[], trusted: readonly SigningPublicDescriptor[], deadline: number): void {
    const seen = new Set(seeds), pending = [...seeds], dependents = new Set<string>();
    while (pending.length) {
      if (performance.now() >= deadline) fail('vault_work_limit', true);
      const rows = this.#db.prepare('SELECT source_id FROM relations WHERE target_id=? LIMIT 1025').all(pending.shift()!);
      if (rows.length > 1024) fail('vault_dependency_work_limit', true);
      for (const row of rows) {
        const id = String(row.source_id); dependents.add(id);
        if (!seen.has(id)) { if (seen.size >= 1024) fail('vault_dependency_work_limit', true); seen.add(id); pending.push(id); }
      }
    }
    const admission = this.#db.prepare('SELECT state,signer_key_id FROM record_admissions WHERE memory_id=?');
    const insert = this.#db.prepare('INSERT INTO delivery_log(memory_id) VALUES(?)');
    for (const id of [...dependents].sort()) { const row = admission.get(id); if (row && this.#rank(row.state, row.signer_key_id, trusted) > 0) insert.run(id); }
  }
  remember(input: RememberInput): Row & SignedMemory {
    if (!this.#identity) fail('vault_signing_identity_required');
    const value = document(input as unknown as DocumentInput, MAX_RECORD) as Row;
    if (Object.keys(value).some(key => !['requestId', 'kind', 'text', 'entities', 'relations', 'provenance'].includes(key)) ||
        typeof value.requestId !== 'string' || !/^req_[A-Za-z0-9_-]{8,96}$/.test(value.requestId)) fail('invalid_request_id');
    if (value.kind === 'episode') fail('invalid_kind');
    const request: Row = { op: 'remember', kind: value.kind, text: value.text, request_id: value.requestId };
    for (const key of ['entities', 'relations', 'provenance']) if (Object.hasOwn(value, key)) request[key] = value[key];
    const digest = sha256(canonicalBytes(request, MAX_RECORD)), deadline = performance.now() + 5000;
    return this.#run(true, () => {
      const trusted = this.#trusted();
      if (!trusted.some(key => key.key_id === this.#identity!.key_id)) fail('unknown_key');
      const prior = this.#db.prepare('SELECT request_sha256,length(CAST(response_json AS BLOB)) AS size FROM receipts WHERE request_id=?').get(value.requestId);
      if (prior) {
        if (prior.request_sha256 !== digest) fail('request_id_conflict');
        if (Number(prior.size) > 65536) fail('stored_receipt_invalid');
        const response = document(Buffer.from(String(this.#db.prepare('SELECT response_json FROM receipts WHERE request_id=?').get(value.requestId)!.response_json), 'utf8'), 65536) as Row;
        const result = response.result;
        if (response.schema_version !== 'universal-agent-memory-result/v1' || response.ok !== true || response.request_id !== value.requestId ||
            json(response.authority) !== json(AUTHORITY) || !result || !['stored', 'duplicate'].includes(result.state)) fail('stored_receipt_invalid');
        const row = this.#row(memoryId(result.memory_id)); if (!row) fail('stored_receipt_invalid');
        const fresh = this.#trusted();
        if (!fresh.some(key => key.key_id === this.#identity!.key_id)) fail('unknown_key');
        const memory = this.#get(result.memory_id, fresh); if (!memory) fail('memory_not_found');
        return { ...result, verification: this.#verification(result.memory_id, fresh), ...memory };
      }
      const provenance = value.provenance ?? {};
      if (typeof provenance !== 'object' || Array.isArray(provenance) || provenance === null ||
          Object.keys(provenance).some(key => !['source_ref', 'task_ref', 'project_ref', 'conversation_ref', 'model_ref', 'agent_ref', 'device_ref', 'request_ref'].includes(key))) fail('forbidden_provenance_field');
      const record = buildRecord({ kind: value.kind, text: value.text, entities: value.entities ?? [], relations: value.relations ?? [],
        provenance: { ...provenance, source_type: 'agent_supplied', confidence: 'assistant_inferred' } });
      const attestation = signRecord(record, this.#identity!), signed = { record, attestation };
      const inserted = this.#insert(record, false);
      if (this.#admit(signed, 'verified', trusted)) this.#requeue([record.memory_id], trusted, deadline);
      const result = { state: inserted ? 'stored' : 'duplicate', memory_id: record.memory_id, kind: record.kind,
        network_accessed: false, verification: this.#verification(record.memory_id, this.#trusted()) };
      const response = { schema_version: 'universal-agent-memory-result/v1', ok: true, authority: AUTHORITY, result, request_id: value.requestId };
      this.#db.prepare('INSERT INTO receipts(request_id,request_sha256,response_json,created_at) VALUES(?,?,?,?)').run(value.requestId, digest, json(response, 65536), now());
      if (!this.#trusted().some(key => key.key_id === this.#identity!.key_id)) fail('unknown_key');
      if (performance.now() >= deadline) fail('vault_work_limit', true);
      return { ...result, ...signed };
    });
  }
  recall(query: string, options: RecallOptions = {}): Row {
    if (typeof query !== 'string' || !query.trim() || query.includes('\0') || Buffer.byteLength(query) > 65536) fail('invalid_query');
    const limit = bounded(options.limit, 8, 1, 64), after = bounded(options.after, 0, 0, Number.MAX_SAFE_INTEGER);
    const maximumScanned = bounded(options.maximumScanned, 256, 1, 1024), maximumBytes = bounded(options.maximumBytes, 65536, 1, MAX_SHARE);
    const deadline = performance.now() + bounded(options.maximumSeconds, 5, 1, 30) * 1000, normalized = normalizeText(query);
    return this.#run(false, () => {
      const trusted = this.#trusted(), records: SignedMemory[] = []; let scanned = 0, cursor = after, bytes = 0, partial = false, requiredBytes: number | null = null;
      const rows = this.#db.prepare('SELECT ingest_seq,memory_id FROM memories WHERE ingest_seq>? ORDER BY ingest_seq LIMIT ?').all(after, maximumScanned + 1);
      for (const row of rows.slice(0, maximumScanned)) {
        if (performance.now() >= deadline) { partial = true; break; }
        const item = this.#get(String(row.memory_id), trusted); scanned++;
        if (item && normalizeText([item.record.text, ...item.record.entities].join(' ')).includes(normalized)) {
          const size = canonicalBytes(item, MAX_RECORD + 2048).length;
          if (bytes + size > maximumBytes) { partial = true; requiredBytes = size; break; }
          bytes += size; records.push(item);
        }
        cursor = Number(row.ingest_seq);
        if (records.length >= limit) { partial = true; break; }
      }
      partial ||= rows.length > maximumScanned;
      return { records, nextAfter: partial ? cursor : null, scanned, partial, requiredBytes, ranking: 'bounded_text_match',
        canonical_records_changed: false, python_ranking_equivalent: false, network_accessed: false };
    });
  }
  exportShare(rootIds: string[], options: ShareOptions = {}): Uint8Array {
    if (!Array.isArray(rootIds) || rootIds.length < 1 || rootIds.length > 64 || new Set(rootIds).size !== rootIds.length) fail('invalid_share_roots');
    rootIds.forEach(memoryId);
    const maximum = bounded(options.maximumRecords, MAX_RECORDS, 1, MAX_RECORDS), maximumBytes = bounded(options.maximumBytes, MAX_SHARE, 1, MAX_SHARE);
    const deadline = performance.now() + bounded(options.maximumSeconds, 5, 1, 30) * 1000;
    return this.#run(false, () => {
      const trusted = this.#trusted(), selected = new Map<string, SignedMemory>(), pending = [...rootIds]; let size = 0;
      while (pending.length) {
        if (performance.now() >= deadline) fail('vault_work_limit', true);
        const id = pending.pop()!; if (selected.has(id)) continue;
        if (selected.size >= maximum) fail('share_record_limit');
        const value = this.#get(id, trusted); if (!value) fail('memory_not_found');
        size += canonicalBytes(value, MAX_RECORD + 2048).length; if (size > maximumBytes) fail('share_too_large');
        selected.set(id, value);
        for (const relation of value.record.relations) pending.push(relation.target);
      }
      // Recheck independent current policy immediately before data release.
      const fresh = this.#trusted();
      for (const value of selected.values()) if (value.attestation) verifyRecord(value.record, value.attestation, fresh);
      const raw = encodeShare([...selected.values()].sort((a, b) => a.record.memory_id.localeCompare(b.record.memory_id)), rootIds);
      if (raw.length > maximumBytes) fail('share_too_large');
      if (performance.now() >= deadline) fail('vault_work_limit', true);
      return raw;
    });
  }
  importShare(raw: Uint8Array | string, options: ShareOptions & { admission?: 'verified' | 'quarantined' | 'accepted_unsigned' } = {}): Row {
    const maximum = bounded(options.maximumRecords, MAX_RECORDS, 1, MAX_RECORDS), maximumBytes = bounded(options.maximumBytes, MAX_SHARE, 1, MAX_SHARE);
    const deadline = performance.now() + bounded(options.maximumSeconds, 5, 1, 30) * 1000;
    const admission = options.admission ?? 'quarantined';
    if (!['verified', 'quarantined', 'accepted_unsigned'].includes(admission)) fail('invalid_admission');
    if (!(typeof raw === 'string' || raw instanceof Uint8Array)) fail('invalid_share');
    if (raw instanceof Uint8Array && raw.buffer instanceof SharedArrayBuffer) fail('unsafe_share_source');
    if ((typeof raw === 'string' ? Buffer.byteLength(raw) : raw.byteLength) > maximumBytes) fail('share_too_large');
    const frozen = typeof raw === 'string' ? Buffer.from(raw, 'utf8') : Buffer.from(raw);
    let lines = 0;
    for (const byte of frozen) if (byte === 10 && ++lines > maximum + 2) fail('share_record_limit');
    const parsed = parseShare(frozen);
    if (parsed.records.length > maximum) fail('share_record_limit');
    const verified = admission === 'verified', digest = sha256(frozen);
    const transferId = 'xfer_' + sha256(canonicalBytes({ operation: 'share-import/v1', share_sha256: digest, admission }));
    const check = (): SigningPublicDescriptor[] => {
      const trusted = this.#trusted();
      if (verified) for (const value of parsed.records) {
        if (performance.now() >= deadline) fail('vault_work_limit', true);
        if (!value.attestation) fail('share_record_signature_required');
        verifyRecord(value.record, value.attestation, trusted);
      }
      return trusted;
    };
    check();
    return this.#run(true, () => {
      const trusted = check(), priorSize = this.#db.prepare('SELECT payload_sha256,length(CAST(result_json AS BLOB)) AS size FROM transfer_receipts WHERE transfer_id=?').get(transferId);
      if (priorSize && (priorSize.payload_sha256 !== digest || Number(priorSize.size) > 65536)) fail('share_import_receipt_conflict');
      let added = 0; const upgraded: string[] = [];
      for (const value of parsed.records) {
        if (performance.now() >= deadline) fail('vault_work_limit', true);
        if (priorSize) {
          if (verified) {
            const existing = this.#row(value.record.memory_id);
            if (!existing || existing.record_json !== Buffer.from(canonicalRecordBytes(value.record)).toString('utf8')) fail('share_import_receipt_records_changed');
            if (this.#admit(value, 'verified', trusted)) upgraded.push(value.record.memory_id);
          }
        } else {
          if (this.#insert(value.record, true)) added++;
          if (this.#admit(value, admission, trusted)) upgraded.push(value.record.memory_id);
        }
      }
      this.#requeue(upgraded, trusted, deadline); check();
      if (performance.now() >= deadline) fail('vault_work_limit', true);
      if (priorSize) {
        const result = document(Buffer.from(String(this.#db.prepare('SELECT result_json FROM transfer_receipts WHERE transfer_id=?').get(transferId)!.result_json), 'utf8'), 65536) as Row;
        return { ...result, records_added: 0, receipt_replayed: true, historical_receipt_is_current_admission: false,
          current_admission_rechecked: verified, admissions_restored: upgraded.length, current_trust_checked: verified, network_accessed: false };
      }
      const result = { state: 'share_imported', records_seen: parsed.records.length, records_added: added, admission,
        share_sha256: digest, current_trust_checked: verified, signatures_preserved_in_source: true, record_proofs_stored: verified,
        network_accessed: false, worker_started: false, trust_policy_changed: false };
      this.#db.prepare('INSERT INTO transfer_receipts(transfer_id,payload_sha256,result_json,created_at) VALUES(?,?,?,?)').run(transferId, digest, json(result, 65536), now());
      return result;
    });
  }
}
export { CanonicalVault as Vault };
