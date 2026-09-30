"""Local, finite maintenance of explicitly selected and authorized mailbox copies."""
import argparse
import hashlib
import json
import math
import sys
import time

from memory_vault import MemoryError, canonical_bytes
from memory_vault_network_crypto import document
from memory_vault_open_client import OpenNetworkClient
from memory_vault_open_repair_mailbox_copy_admin import (
    _upload_fields, _request_value, _output, upload_value, MAX_COPY_BUNDLE_BYTES,
)
from memory_vault_open_repair_wire import RepairWireError
from memory_vault_storage import file_lock
from memory_vault_trust import TrustError, _absolute_path, _read_private

MAX_JOBS = 4
MAX_BYTES = 16 * 1024 * 1024
MAX_ATTEMPTS = 8


class CopyJobs:
    def __init__(self, network):
        self.network = network
        self.state = network.participant.state
        self.lock = self.state.directory / 'mailbox-copy-jobs.lock'
        with self.state.db() as db:
            db.execute('''CREATE TABLE IF NOT EXISTS open_mailbox_copy_jobs(
                job_id TEXT PRIMARY KEY, body BLOB NOT NULL, digest TEXT NOT NULL,
                expires_at INTEGER NOT NULL, phase TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0, next_attempt INTEGER NOT NULL,
                error TEXT, result BLOB, result_digest TEXT)''')

    @staticmethod
    def _id(value):
        import re
        if type(value) is not str or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',value):
            raise MemoryError('open_copy_job_invalid')
        return value

    @staticmethod
    def _summary(row):
        return {name:row[name] for name in ('job_id','phase','attempts','expires_at','next_attempt','error')}

    @staticmethod
    def _decode(row, field, digest):
        raw = bytes(row[field])
        if hashlib.sha256(raw).hexdigest() != row[digest]:
            raise MemoryError('open_copy_job_corrupt')
        return document(raw,maximum=MAX_COPY_BUNDLE_BYTES)

    def queue(self, job_id, request, *, source_state, profile='mailbox', lifetime=600):
        self._id(job_id)
        if type(lifetime) is not int or not 1 <= lifetime <= 3600:
            raise MemoryError('open_copy_job_invalid')
        _, fields, schema = _upload_fields(source_state)
        _request_value(request,schema,fields,profile)
        body = canonical_bytes(dict(request=request,source_state=source_state,profile=profile,lifetime=lifetime))
        if len(body) > MAX_COPY_BUNDLE_BYTES: raise MemoryError('open_copy_job_capacity')
        digest = hashlib.sha256(body).hexdigest(); now = int(time.time())
        with file_lock(self.lock,busy_code='open_copy_worker_busy'), self.state.db() as db:
            db.execute('BEGIN IMMEDIATE')
            old = db.execute('SELECT * FROM open_mailbox_copy_jobs WHERE job_id=?',(job_id,)).fetchone()
            if old is not None:
                self._decode(old,'body','digest')
                if old['digest'] != digest: raise MemoryError('open_copy_job_conflict')
                return self._summary(old)
            count, used = db.execute('SELECT count(*),coalesce(sum(length(body)+coalesce(length(result),0)),0) FROM open_mailbox_copy_jobs').fetchone()
            if count >= MAX_JOBS or used + len(body) > MAX_BYTES: raise MemoryError('open_copy_job_capacity')
            db.execute('INSERT INTO open_mailbox_copy_jobs(job_id,body,digest,expires_at,phase,next_attempt) VALUES(?,?,?,?,?,?)',
                (job_id,body,digest,now+lifetime,'pending',now))
            row = db.execute('SELECT * FROM open_mailbox_copy_jobs WHERE job_id=?',(job_id,)).fetchone()
        return self._summary(row)

    def inspect(self, job_id=None):
        if job_id is not None: self._id(job_id)
        with self.state.db() as db:
            rows = db.execute('SELECT * FROM open_mailbox_copy_jobs ORDER BY job_id').fetchall()
        if job_id is None: return [self._summary(r) for r in rows]
        row = next((r for r in rows if r['job_id']==job_id),None)
        if row is None: raise MemoryError('open_copy_job_missing')
        self._decode(row,'body','digest')
        return self._summary(row)

    def remove(self, job_id):
        self._id(job_id)
        with file_lock(self.lock,busy_code='open_copy_worker_busy'), self.state.db() as db:
            db.execute('DELETE FROM open_mailbox_copy_jobs WHERE job_id=?',(job_id,))
        return dict(job_id=job_id,phase='removed',copy_journal_preserved=True)

    def export(self, job_id, output):
        self._id(job_id)
        with self.state.db() as db:
            row = db.execute('SELECT * FROM open_mailbox_copy_jobs WHERE job_id=?',(job_id,)).fetchone()
        if row is None or row['phase']!='complete': raise MemoryError('open_copy_job_incomplete')
        return _output(_absolute_path(output),self._decode(row,'result','result_digest'))

    def run_once(self, *, timeout=30):
        if type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0 < timeout <= 30:
            raise MemoryError('open_copy_job_invalid')
        with file_lock(self.lock,busy_code='open_copy_worker_busy'):
            now = int(time.time())
            with self.state.db() as db:
                db.execute('BEGIN IMMEDIATE')
                db.execute("UPDATE open_mailbox_copy_jobs SET phase='needs_attention',error='open_copy_job_expired' WHERE phase='pending' AND expires_at<=?",(now,))
                db.execute("UPDATE open_mailbox_copy_jobs SET phase='needs_attention',error='open_copy_job_attempts_exhausted' WHERE phase='pending' AND attempts>=?",(MAX_ATTEMPTS,))
                row = db.execute("SELECT * FROM open_mailbox_copy_jobs WHERE phase='pending' AND next_attempt<=? ORDER BY next_attempt,job_id LIMIT 1",(now,)).fetchone()
                if row is None: return dict(phase='idle',upload_attempted=False)
                # Persist the attempt before HTTP. A killed worker cannot erase it;
                # a restarted worker reuses the existing immutable upload journal.
                db.execute('UPDATE open_mailbox_copy_jobs SET attempts=attempts+1,next_attempt=? WHERE job_id=?',
                    (now+30,row['job_id']))
            attempted = False
            try:
                body = self._decode(row,'body','digest')
                attempted = True
                result = upload_value(self.network,body['request'],timeout=min(timeout,row['expires_at']-now),
                    repair_profile=body['profile'],source_state=body['source_state'])
                raw = canonical_bytes(result)
                if len(raw)>MAX_COPY_BUNDLE_BYTES: raise MemoryError('open_copy_job_capacity')
                with self.state.db() as db:
                    db.execute('BEGIN IMMEDIATE')
                    used = db.execute('SELECT coalesce(sum(length(body)+coalesce(length(result),0)),0) FROM open_mailbox_copy_jobs').fetchone()[0]
                    if used+len(raw)>MAX_BYTES: raise MemoryError('open_copy_job_capacity')
                    db.execute("UPDATE open_mailbox_copy_jobs SET phase='complete',error=NULL,result=?,result_digest=? WHERE job_id=?",
                        (raw,hashlib.sha256(raw).hexdigest(),row['job_id']))
            except (MemoryError,RepairWireError) as error:
                retry = error.code not in {'repair_reconciliation_required','repair_saved_reconciliation_required'} and getattr(error,'retryable',False) and row['attempts']+1<MAX_ATTEMPTS and int(time.time())<row['expires_at']
                with self.state.db() as db:
                    db.execute('UPDATE open_mailbox_copy_jobs SET phase=?,error=?,next_attempt=? WHERE job_id=?',
                        ('pending' if retry else 'needs_attention',error.code,int(time.time())+min(60,2**(row['attempts']+1)),row['job_id']))
            return dict(self.inspect(row['job_id']),upload_attempted=attempted)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--network-config',required=True)
    commands = parser.add_subparsers(dest='command',required=True)
    queue = commands.add_parser('queue')
    queue.add_argument('--job-id',required=True); queue.add_argument('--request',required=True)
    queue.add_argument('--kind',choices=('root','feed','message'),required=True)
    queue.add_argument('--lifetime',type=int,default=600)
    queue.add_argument('--repair-profile',choices=('unbound','receipt','receipt-index','mailbox'),default='mailbox')
    commands.add_parser('list')
    for name in ('inspect','remove','export'):
        command = commands.add_parser(name); command.add_argument('--job-id',required=True)
        if name=='export': command.add_argument('--output',required=True)
    run = commands.add_parser('run')
    run.add_argument('--timeout',type=float,default=30)
    run.add_argument('--watch-seconds',type=int,default=0,help='finite worker lifetime, at most 3600 seconds')
    args = parser.parse_args(argv)
    try:
        with OpenNetworkClient(_absolute_path(args.network_config)) as network:
            jobs = CopyJobs(network)
            if args.command=='queue':
                raw = _read_private(_absolute_path(args.request),MAX_COPY_BUNDLE_BYTES)
                if raw is None: raise MemoryError('open_copy_job_request_missing')
                result = jobs.queue(args.job_id,document(raw,maximum=MAX_COPY_BUNDLE_BYTES),source_state=args.kind,
                    profile=args.repair_profile,lifetime=args.lifetime)
            elif args.command=='list': result = jobs.inspect()
            elif args.command=='inspect': result = jobs.inspect(args.job_id)
            elif args.command=='remove': result = jobs.remove(args.job_id)
            elif args.command=='export': result = jobs.export(args.job_id,args.output)
            else:
                if not 0<=args.watch_seconds<=3600: raise MemoryError('open_copy_job_invalid')
                if not math.isfinite(args.timeout) or not 0<args.timeout<=30: raise MemoryError('open_copy_job_invalid')
                end = time.monotonic()+args.watch_seconds
                result = dict(phase='idle',upload_attempted=False)
                while True:
                    remaining = end-time.monotonic() if args.watch_seconds else args.timeout
                    if remaining<=0: break
                    result = jobs.run_once(timeout=min(args.timeout,remaining))
                    if not args.watch_seconds or not any(r['phase']=='pending' for r in jobs.inspect()): break
                    remaining = end-time.monotonic()
                    if remaining<=0: break
                    time.sleep(min(2,remaining))
        print(json.dumps(result,ensure_ascii=False,indent=2)); return 0
    except (MemoryError,RepairWireError,TrustError,OSError) as error:
        print(json.dumps(dict(error=getattr(error,'code','open_copy_job_storage_unavailable'))),file=sys.stderr); return 1


if __name__=='__main__': raise SystemExit(main())
