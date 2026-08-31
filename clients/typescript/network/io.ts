/** Private POSIX storage for the independent endpoint. No ambient config lookup. */
import * as fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { NetworkCryptoError } from './crypto.ts';

export class NetworkError extends NetworkCryptoError {
  readonly retryable: boolean;
  constructor(code: string, retryable = false) { super(code); this.retryable = retryable; }
}
function fail(code: string): never { throw new NetworkError(code); }
export function absolutePath(value: unknown): string {
  if (typeof value !== 'string' || !path.isAbsolute(value) || value.includes('\0') || value.split(path.sep).includes('..')) fail('unsafe_storage_path');
  return path.normalize(value);
}
function owner(): number {
  if (process.platform === 'win32' || !process.getuid) fail('protected_storage_platform_unavailable');
  return process.getuid();
}
function parents(value: string): void {
  const uid = owner();
  for (let current = path.dirname(absolutePath(value)); ; current = path.dirname(current)) {
    const info = fs.lstatSync(current);
    if (!info.isDirectory() || info.isSymbolicLink() || (info.uid !== uid && info.uid !== 0) ||
        ((info.mode & 0o022) !== 0 && !(info.uid === 0 && (info.mode & 0o1000)))) fail('unsafe_storage_path');
    if (path.dirname(current) === current) break;
  }
}
export function privateDirectory(value: string, create = false): string {
  const selected = absolutePath(value), uid = owner();
  if (!fs.existsSync(selected) && create) {
    const parent = path.dirname(selected);
    if (!fs.existsSync(parent)) privateDirectory(parent, true);
    parents(selected); fs.mkdirSync(selected, { mode: 0o700 });
  }
  parents(selected);
  const info = fs.lstatSync(selected);
  if (!info.isDirectory() || info.isSymbolicLink() || info.uid !== uid || (info.mode & 0o077)) fail('unprotected_private_directory');
  return selected;
}
function regular(fd: number, privateFile: boolean): fs.Stats {
  const info = fs.fstatSync(fd);
  if (!info.isFile() || info.nlink !== 1 || (privateFile && (info.uid !== owner() || (info.mode & 0o077)))) fail('unprotected_private_file');
  return info;
}
export function readPrivate(value: string, maximum: number, optional = false): Buffer | null {
  const selected = absolutePath(value); parents(selected);
  let fd: number;
  try { fd = fs.openSync(selected, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK); }
  catch (error) { if (optional && (error as NodeJS.ErrnoException).code === 'ENOENT') return null; throw error; }
  try {
    const before = regular(fd, true);
    if (before.size > maximum) fail('network_document_too_large');
    const result = Buffer.alloc(before.size); let offset = 0;
    while (offset < result.length) { const n = fs.readSync(fd, result, offset, result.length - offset, null); if (!n) break; offset += n; }
    const after = regular(fd, true), named = fs.lstatSync(selected);
    if (offset !== before.size || after.size !== before.size || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs ||
        named.ino !== before.ino || named.dev !== before.dev || !named.isFile() || named.isSymbolicLink()) fail('network_source_changed');
    return result;
  } finally { fs.closeSync(fd); }
}
export function openPrivateDatabase(value: string, readOnly = false): DatabaseSync {
  const selected = absolutePath(value);
  if (readOnly && !fs.existsSync(selected)) fail('not_initialized');
  privateDirectory(path.dirname(selected), !readOnly);
  let fd = fs.openSync(selected, (readOnly ? fs.constants.O_RDONLY : fs.constants.O_CREAT | fs.constants.O_RDWR) | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK, 0o600);
  let before: fs.Stats;
  try { before = regular(fd, true); } finally { fs.closeSync(fd); }
  for (const suffix of ['-wal', '-shm', '-journal']) {
    try { fd = fs.openSync(selected + suffix, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK); }
    catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') continue; throw error; }
    try { regular(fd, true); } finally { fs.closeSync(fd); }
  }
  const db = new DatabaseSync(selected, { readOnly, enableForeignKeyConstraints: true, enableDoubleQuotedStringLiterals: false });
  try {
    const named = fs.lstatSync(selected);
    if (named.ino !== before.ino || named.dev !== before.dev || !named.isFile() || named.isSymbolicLink()) fail('network_source_changed');
    db.exec('PRAGMA busy_timeout=2000; PRAGMA synchronous=FULL; PRAGMA trusted_schema=OFF;');
    if (!readOnly) db.exec('PRAGMA journal_mode=WAL; PRAGMA max_page_count=262144;');
    return db;
  } catch (error) { db.close(); throw error; }
}
export function transaction<T>(db: DatabaseSync, operation: () => T): T {
  db.exec('BEGIN IMMEDIATE');
  try { const result = operation(); db.exec('COMMIT'); return result; }
  catch (error) { db.exec('ROLLBACK'); throw error; }
}
