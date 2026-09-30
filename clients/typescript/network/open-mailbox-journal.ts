/** Bounded durable mailbox setup/status journal shared with the Python client. */
import type {OpenParticipant} from './open-participant.ts';
import type {AuthenticatedStatusOriginal} from './open-repair-status.ts';
import {canonicalBytes,sha256} from './crypto.ts';
import {RepairError} from './open-repair-wire.ts';
import type {RawOriginal} from './open-repair-wire.ts';
import {transaction} from './io.ts';
type Obj=Record<string,any>;
function fail(code:string):never{throw new RepairError(code);}
export class MailboxSetupJournal{
  readonly #participant:OpenParticipant;
  constructor(participant:OpenParticipant){this.#participant=participant;participant.providerStorage(db=>db.exec(`
    CREATE TABLE IF NOT EXISTS open_mailbox_setup_jobs(job_key TEXT PRIMARY KEY,plan BLOB NOT NULL,blocked INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS open_mailbox_setup_steps(job_key TEXT NOT NULL,stage TEXT NOT NULL,request BLOB NOT NULL,response BLOB,PRIMARY KEY(job_key,stage));
    CREATE TABLE IF NOT EXISTS open_mailbox_setup_statuses(job_key TEXT NOT NULL,digest TEXT NOT NULL,raw BLOB NOT NULL,PRIMARY KEY(job_key,digest));`));}
  start(plan:unknown):string{
    const raw=canonicalBytes(plan,65536),key=sha256(raw);
    this.#participant.providerStorage(db=>transaction(db,()=>{
      const old=db.prepare('SELECT plan,blocked FROM open_mailbox_setup_jobs WHERE job_key=?').get(key) as Obj|undefined;
      if(old){if(!Buffer.from(old.plan).equals(Buffer.from(raw)))fail('repair_setup_journal_conflict');if(old.blocked)fail('repair_setup_journal_capacity');return;}
      const size=db.prepare('SELECT count(*) AS n FROM open_mailbox_setup_jobs').get() as Obj;if(size.n>=16)fail('repair_setup_journal_capacity');
      db.prepare('INSERT INTO open_mailbox_setup_jobs(job_key,plan) VALUES(?,?)').run(key,raw);
    }));return key;
  }
  #check(db:any,key:string):void{if(!/^[0-9a-f]{64}$/.test(key))fail('repair_invalid_context');const row=db.prepare('SELECT blocked FROM open_mailbox_setup_jobs WHERE job_key=?').get(key);if(!row||row.blocked)fail('repair_setup_journal_unavailable');}
  statuses(key:string):readonly RawOriginal[]{return this.#participant.providerStorage(db=>{
    this.#check(db,key);const rows=db.prepare('SELECT digest,raw FROM open_mailbox_setup_statuses WHERE job_key=? ORDER BY digest LIMIT 33').all(key) as Obj[];
    if(rows.length>32||rows.reduce((n,v)=>n+v.raw.length,0)>262144)fail('repair_setup_journal_capacity');
    return rows.map(v=>{const raw=Uint8Array.from(v.raw);if(sha256(raw)!==v.digest)fail('repair_storage_corrupt');return {raw,ref:{namespace:'meta' as const,key:v.digest,raw_sha256:v.digest,size:raw.length}};});
  });}
  observe(key:string,item:AuthenticatedStatusOriginal):void{
    const raw=item.raw,digest=item.raw_sha256;if(raw.length>16384||sha256(raw)!==digest)fail('repair_invalid_context');
    const saved=this.#participant.providerStorage(db=>transaction(db,()=>{
      this.#check(db,key);const old=db.prepare('SELECT raw FROM open_mailbox_setup_statuses WHERE job_key=? AND digest=?').get(key,digest) as Obj|undefined;
      if(old){if(!Buffer.from(old.raw).equals(Buffer.from(raw)))fail('repair_storage_corrupt');return true;}
      const size=db.prepare('SELECT count(*) AS n,coalesce(sum(length(raw)),0) AS size FROM open_mailbox_setup_statuses WHERE job_key=?').get(key) as Obj;
      if(size.n>=32||size.size+raw.length>262144){db.prepare('UPDATE open_mailbox_setup_jobs SET blocked=1 WHERE job_key=?').run(key);return false;}
      db.prepare('INSERT INTO open_mailbox_setup_statuses VALUES(?,?,?)').run(key,digest,raw);return true;
    }));if(!saved)fail('repair_setup_journal_capacity');
  }
}
