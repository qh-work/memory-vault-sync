/** Original ACK status memory shared by native Agent and command-line recovery. */
import type {OpenParticipant} from './open-participant.ts';
import type {AuthenticatedStatusOriginal} from './open-repair-status.ts';
import type {RawOriginal} from './open-repair-wire.ts';
import {canonicalBytes,document,sha256} from './crypto.ts';
import {NetworkError,transaction} from './io.ts';
type Obj=Record<string,any>;
const bytes=(value:unknown)=>Buffer.from(canonicalBytes(value,1048576));
const hash=sha256;
const equal=(a:Uint8Array,b:Uint8Array)=>Buffer.from(a).equals(Buffer.from(b));
function fail(code:string):never{throw new NetworkError(code);}

/** Same root/domain and protected tables as the Python original-source CLI.
 * Transactions are synchronous and finish before any network await. */
export class OriginalAckStatusJournal{
  readonly root:Buffer;readonly key:string;private readonly participant:OpenParticipant;
  constructor(participant:OpenParticipant,root:unknown){
    this.participant=participant;
    this.root=bytes(root);this.key=hash(Buffer.concat([Buffer.from('original-source\0'),this.root]));
    participant.providerStorage(db=>db.exec(`
      CREATE TABLE IF NOT EXISTS open_ack_replica_roots(root_id TEXT PRIMARY KEY,root BLOB NOT NULL,blocked INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS open_ack_replica_statuses(root_id TEXT NOT NULL,ref_id TEXT NOT NULL,issuer TEXT NOT NULL,raw BLOB NOT NULL,ref BLOB NOT NULL,PRIMARY KEY(root_id,ref_id));`));
  }
  private check(db:any):Obj|undefined{
    const held=db.prepare('SELECT root,blocked FROM open_ack_replica_roots WHERE root_id=?').get(this.key);
    if(held){if(!equal(held.root,this.root))fail('repair_storage_corrupt');if(held.blocked)fail('repair_status_history_capacity');}
    return held;
  }
  load(issuers:Set<string>):RawOriginal[]{
    return this.participant.providerStorage(db=>{
      this.check(db);
      const rows=db.prepare('SELECT issuer,raw,ref FROM open_ack_replica_statuses WHERE root_id=? ORDER BY ref_id LIMIT 33').all(this.key) as Obj[];
      if(rows.length>32||rows.reduce((n,r)=>n+r.raw.length+r.ref.length,0)>262144)fail('repair_status_history_capacity');
      const retained=new Map<string,RawOriginal>();
      const keep=(item:RawOriginal)=>retained.set(bytes(item.ref).toString('utf8'),item);
      for(const row of rows)if(issuers.has(row.issuer))keep({raw:Uint8Array.from(row.raw),ref:document(row.ref,16384) as any});
      // Older Agents retained statuses by request/grant tuple. Reauthenticate
      // their original-root observations even when this invitation is new.
      if(db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='open_mailbox_setup_jobs'").get()){
        const jobs=db.prepare('SELECT job_key,plan,blocked FROM open_mailbox_setup_jobs LIMIT 17').all() as Obj[];
        if(jobs.length>16)fail('repair_status_history_capacity');
        for(const job of jobs){
          const plan=document(job.plan,65536) as Obj;
          if(plan.kind!=='ack.owner_recovery')continue;
          if(hash(job.plan)!==job.job_key)fail('repair_storage_corrupt');
          if(!equal(bytes(plan.expected_ack_slot?.root_key),this.root))continue;
          if(job.blocked)fail('repair_setup_journal_capacity');
          const old=db.prepare('SELECT digest,raw FROM open_mailbox_setup_statuses WHERE job_key=? ORDER BY digest LIMIT 33').all(job.job_key) as Obj[];
          if(old.length>32||old.reduce((n,r)=>n+r.raw.length,0)>262144)fail('repair_status_history_capacity');
          for(const row of old){
            const preview=document(row.raw,16384) as Obj;
            if(issuers.has(preview.payload?.signing_key?.key_id))keep({raw:Uint8Array.from(row.raw),
              ref:{namespace:'meta',key:row.digest,raw_sha256:row.digest,size:row.raw.length}});
          }
        }
      }
      const result=[...retained.values()];
      if(result.length>32||result.reduce((n,r)=>n+r.raw.length+bytes(r.ref).length,0)>262144)fail('repair_status_history_capacity');
      return result;
    });
  }
  observe(item:AuthenticatedStatusOriginal):void{
    if(!equal(bytes((item.payload.scope_key as Obj).root_key),this.root))fail('repair_invalid_context');
    const raw=item.raw,reference=bytes(item.ref),key=hash(reference),issuer=(item.payload.signing_key as Obj).key_id;
    const full=this.participant.providerStorage(db=>transaction(db,()=>{
      if(!this.check(db)){
        const count=db.prepare('SELECT count(*) AS n FROM open_ack_replica_roots').get()!;
        if(Number(count.n)>=16)fail('repair_status_history_capacity');
        db.prepare('INSERT INTO open_ack_replica_roots VALUES(?,?,0)').run(this.key,this.root);
      }
      const old=db.prepare('SELECT raw,ref FROM open_ack_replica_statuses WHERE root_id=? AND ref_id=?').get(this.key,key) as Obj|undefined;
      if(old){if(!equal(old.raw,raw)||!equal(old.ref,reference))fail('repair_storage_corrupt');return false;}
      const size=db.prepare('SELECT count(*) AS n,coalesce(sum(length(raw)+length(ref)),0) AS bytes FROM open_ack_replica_statuses WHERE root_id=?').get(this.key)!;
      if(Number(size.n)>=32||Number(size.bytes)+raw.length+reference.length>262144){
        db.prepare('UPDATE open_ack_replica_roots SET blocked=1 WHERE root_id=?').run(this.key);return true;
      }
      db.prepare('INSERT INTO open_ack_replica_statuses VALUES(?,?,?,?,?)').run(this.key,key,issuer,raw,reference);return false;
    }));
    if(full)fail('repair_status_history_capacity');
  }
}
