/** The existing protected transport schema and binding, shared by both profiles. */
import path from 'node:path';
import type {DatabaseSync} from 'node:sqlite';
import {canonicalBytes,document} from './crypto.ts';
import {openPrivateDatabase,transaction,NetworkError} from './io.ts';
type Obj=Record<string,any>;
const json=(value:unknown):string=>Buffer.from(canonicalBytes(value)).toString('utf8');
const parse=(value:string):any=>document(Buffer.from(value));
const equal=(a:unknown,b:unknown):boolean=>json(a)===json(b);
function fail(code:string):never{throw new NetworkError(code);}
export function openTransportState(directory:string,binding:Obj):DatabaseSync {
    const db = openPrivateDatabase(path.join(directory, 'network.sqlite3'));
    try {
      db.exec(`CREATE TABLE IF NOT EXISTS state(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS outbox(request_id TEXT PRIMARY KEY,message_id TEXT NOT NULL UNIQUE,input_sha TEXT NOT NULL,body BLOB NOT NULL,envelope BLOB,roster BLOB,receipts TEXT NOT NULL DEFAULT '{}',recipients BLOB);
        CREATE TABLE IF NOT EXISTS inbox(message_id TEXT PRIMARY KEY,digest TEXT NOT NULL,sender TEXT NOT NULL,body BLOB NOT NULL,result TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS acknowledgements(message_id TEXT NOT NULL,recipient TEXT NOT NULL,receipt BLOB NOT NULL,PRIMARY KEY(message_id,recipient));
        CREATE TABLE IF NOT EXISTS quarantine(message_id TEXT PRIMARY KEY,digest TEXT NOT NULL UNIQUE,sender TEXT NOT NULL,envelope BLOB NOT NULL,code TEXT NOT NULL);`);
      transaction(db, () => {
        if (!(db.prepare('PRAGMA table_info(outbox)').all() as Obj[]).some(row => row.name === 'recipients')) db.exec('ALTER TABLE outbox ADD COLUMN recipients BLOB');
        const prior = db.prepare("SELECT value FROM state WHERE key='configuration_binding'").get() as Obj | undefined;
        if (!prior) {
          if (['state','outbox','inbox','acknowledgements','quarantine'].some(table => db.prepare('SELECT 1 FROM '+table+' LIMIT 1').get())) fail('network_state_binding_missing');
          db.prepare('INSERT INTO state VALUES(?,?)').run('configuration_binding', json(binding));
        } else if (!equal(parse(prior.value), binding)) fail('network_state_configuration_mismatch');
      });
      return db;
    } catch (error) { db.close(); throw error; }
  }
