"""Finite real encrypted delivery -> saved receipt -> local read/Memory recall.

Two loopback node processes, one sender and one recipient. Each node receives an
independent explicit finite resource approval; no grant is copied to another node.
Offers continue at a fixed rate while the second node starts and is authorized.
At most 48 offers, 48 seconds and one pipeline worker; all failures/lag are retained.
"""
from __future__ import annotations

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import signal
import sys
import tempfile
import threading
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))


def usage():
    r=resource.getrusage(resource.RUSAGE_SELF)
    return dict(user_cpu_seconds=r.ru_utime,system_cpu_seconds=r.ru_stime,
        max_rss_bytes=r.ru_maxrss if sys.platform=='darwin' else r.ru_maxrss*1024)


def serve(config_path,metrics_path):
    import memory_vault_open_node as node
    from memory_vault import canonical_bytes
    from memory_vault_storage import atomic_write
    lock=threading.RLock();counts=Counter();serial=0
    OriginalParticipant=node.OpenParticipant;OriginalServer=node.OpenHTTPServer
    class Participant(OriginalParticipant):
        def handle(self,request):
            response=super().handle(request)
            with lock:
                action=request['payload']['action'];counts['rpc_'+action]+=1
                counts['request_bytes']+=len(canonical_bytes(request))
                counts['response_bytes']+=len(canonical_bytes(response))
                error=response.get('payload',{}).get('body',{}).get('error')
                if error:counts['error_'+error['code']]+=1
            return response
        def handle_blob(self,request,chunk):
            result=super().handle_blob(request,chunk)
            with lock:
                counts['blob_'+request['payload']['action']]+=1
                counts['blob_input_bytes']+=len(chunk)
                counts['blob_output_bytes']+=len(result[1])
            return result
    class Server(OriginalServer):
        def admitted(self,address):
            accepted=super().admitted(address)
            with lock:
                counts['http_requests']+=1;counts['second_'+str(int(time.time()))]+=1
                counts['admitted' if accepted else 'rate_refused']+=1
            return accepted
        def _busy(self,request):
            with lock:counts['queue_refused']+=1
            return super()._busy(request)
    node.OpenParticipant=Participant;node.OpenHTTPServer=Server
    def snapshot(*_):
        nonlocal serial
        with lock:
            serial+=1;value=dict(serial=serial,counts=dict(counts),usage=usage(),time=time.monotonic())
        atomic_write(metrics_path,json.dumps(value).encode(),replace=True)
    signal.signal(signal.SIGUSR1,snapshot)
    with node._publication_lock(config_path):
        node._run_node(config_path)


def percentile(values,p):
    ordered=sorted(values)
    return ordered[min(len(ordered)-1,int((len(ordered)-1)*p))] if ordered else None


def main_run(args):
    from memory_vault_client import ClientConfig
    from memory_vault_open_delivery_client import OpenDeliveryClient
    from tests.test_open_delivery_distribution import DeliveryDistributionFixture
    from tests.test_open_node import HTTPNodes
    class InstrumentedNodes(HTTPNodes):
        def command(self,index):
            return [sys.executable,str(Path(__file__).resolve()),'--serve-config',str(self.configs[index]),
                    '--metrics',str(self.root/f'node_{index}.metrics.json')]
        def snapshot(self,index):
            if index not in self.processes:
                return dict(counts={},usage=dict(user_cpu_seconds=0,system_cpu_seconds=0,max_rss_bytes=0))
            path=self.root/f'node_{index}.metrics.json'
            previous=json.loads(path.read_bytes())['serial'] if path.exists() else 0
            os.kill(self.processes[index].pid,signal.SIGUSR1)
            deadline=time.monotonic()+2
            while time.monotonic()<deadline:
                if path.exists():
                    value=json.loads(path.read_bytes())
                    if value['serial']>previous:return value
                time.sleep(.01)
            raise RuntimeError('bounded synthetic snapshot deadline')
    with tempfile.TemporaryDirectory(prefix='synthetic-delivery-capacity-') as temporary:
        fixture=DeliveryDistributionFixture(temporary,host_class=InstrumentedNodes,late_node=True)
        finished=threading.Event()
        native=None
        try:
            items=args.messages//2
            fixture.approve(0,items=items,bytes_limit=2*1024*1024)
            if args.runtime=='native':
                from benchmark_native_runtime import NativeRuntime
                native=NativeRuntime(fixture,ROOT)
            memory=[]
            for i in range(args.messages):
                text=f'Synthetic observation {i}: independent evidence must be checked before reuse.'
                value=fixture.call(fixture.a,op='remember',request_id=f'req_capacity_memory_{i}',
                    kind='observation',text=text)
                memory.append(dict(memory_id=value['memory_id'],text=text))
            snapshots=[fixture.host.snapshot(i) for i in range(2)]
            native_before=native.usage() if native else None
            before=usage();start=time.perf_counter();offers=[];join={};join_error=[]
            def hard_deadline():
                if not finished.wait(args.messages/args.rate+30):
                    # Terminate only this disposable harness and its two children,
                    # including queued work. Never let socket failure multiply
                    # the ordinary per-operation deadline into an unbounded run.
                    if native:native.close()
                    fixture.close()
                    os.write(2,b'synthetic benchmark exceeded its finite drain allowance\n')
                    os._exit(124)
            threading.Thread(target=hard_deadline,daemon=True).start()
            def join_node():
                join['started_seconds']=time.perf_counter()-start
                try:
                    fixture.host.start(1)
                    fixture.approve(1,items=items,bytes_limit=2*1024*1024)
                    join['authorized_seconds']=time.perf_counter()-start
                except Exception as exc:
                    join_error.append(str(exc));join['failed_seconds']=time.perf_counter()-start
            def pipeline(i,offered):
                row=dict(index=i,offered_seconds=offered-start,status='unknown',stages=[],
                    offer_lag_ms=(time.perf_counter()-offered)*1000,node=None,storage_accepted=False,
                    saved_receipt=False,local_read=False,memory_recalled=False)
                try:
                    sent=fixture.send(i,memory_ids=[memory[i]['memory_id']])
                    row['stages'].append(dict(stage='send',ok=sent['ok'],code=sent.get('error',{}).get('code')))
                    if not sent['ok']:
                        row['status']=sent['error']['code'];return row
                    result=sent['result'];row['message_id']=result['message_id'];row['storage_accepted']=result['storage_accepted']
                    with fixture.a._network() as network:
                        with network.participant.state.db() as db:
                            session=db.execute('SELECT session FROM open_delivery_outbox WHERE request_id=?',
                                (f'req_synthetic_distribution_send_{i}',)).fetchone()[0]
                    key=json.loads(session)['node']['payload']['signing_key']['key_id']
                    row['node']=next(j for j,n in enumerate(fixture.host.nodes) if n['payload']['signing_key']['key_id']==key)
                    received=fixture.b.handle({'op':'receive','limit':4})
                    row['stages'].append(dict(stage='receive',ok=received['ok'],errors=received.get('result',{}).get('errors',[])))
                    if not received['ok'] or received['result']['errors']:
                        row['status']=received.get('error',{}).get('code','receive_errors');return row
                    ack=fixture.send(i,memory_ids=[memory[i]['memory_id']])
                    row['stages'].append(dict(stage='receipt',ok=ack['ok'],code=ack.get('error',{}).get('code')))
                    row['saved_receipt']=bool(ack['ok'] and ack['result']['endpoint_validated'])
                    read=fixture.b.handle({'op':'receive','message_id':result['message_id'],'offset':0})
                    row['local_read']=bool(read['ok'] and f'payload {i}' in read['result']['text'])
                    recall=fixture.b.handle({'op':'recall','memory_id':memory[i]['memory_id']})
                    row['memory_recalled']=bool(recall['ok'] and any(x['text']==memory[i]['text'] for x in recall['result']['hits']))
                    row['status']='ok' if all(row[n] for n in ('storage_accepted','saved_receipt','local_read','memory_recalled')) else 'incomplete_chain'
                    return row
                except Exception as exc:
                    row['status']=type(exc).__name__;row['detail']=str(exc)[:256];return row
                finally:
                    row['latency_ms']=(time.perf_counter()-offered)*1000
                    row['completed_seconds']=time.perf_counter()-start
            worker=None
            with ThreadPoolExecutor(max_workers=1) as pool:
                for i in range(args.messages):
                    offered=start+i/args.rate
                    time.sleep(max(0,offered-time.perf_counter()))
                    if worker is None and i>=args.join_after:
                        worker=threading.Thread(target=join_node,daemon=True);worker.start()
                    offers.append(pool.submit(pipeline,i,offered))
                offer_window=args.messages/args.rate
                time.sleep(max(0,start+offer_window-time.perf_counter()))
                rows=[future.result() for future in offers]
            if worker:worker.join(8)
            elapsed=time.perf_counter()-start;after=usage();per_node=[]
            for i in range(2):
                snapshot=fixture.host.snapshot(i)
                counts={k:v-snapshots[i]['counts'].get(k,0) for k,v in snapshot['counts'].items()}
                with __import__('sqlite3').connect(fixture.root/f'node_{i}'/'transport/network.sqlite3') as db:
                    stored=db.execute('SELECT count(*),coalesce(sum(length(envelope)),0) FROM open_delivery_messages').fetchone()
                    receipts=db.execute('SELECT count(*) FROM open_delivery_receipts').fetchone()[0]
                    leases=[dict(lease_id=r[0],max_items=r[1],max_bytes=r[2]) for r in db.execute(
                        "SELECT lease_id,max_items,max_bytes FROM open_contact_resource_leases WHERE purpose='delivery'")]
                per_node.append(dict(node=i,counts=counts,peak_http_requests_per_second=max(
                    [v for k,v in counts.items() if k.startswith('second_')] or [0]),
                    stored_items=stored[0],stored_ciphertext_bytes=stored[1],saved_receipts=receipts,delivery_leases=leases,
                    user_cpu_seconds=snapshot['usage']['user_cpu_seconds']-snapshots[i]['usage']['user_cpu_seconds'],
                    system_cpu_seconds=snapshot['usage']['system_cpu_seconds']-snapshots[i]['usage']['system_cpu_seconds'],
                    max_rss_bytes=snapshot['usage']['max_rss_bytes']))
            ok=[r for r in rows if r['status']=='ok']
            with fixture.b._network() as network:
                with network.participant.state.db() as db:
                    inbox=db.execute("SELECT count(*) FROM open_delivery_inbox WHERE phase='saved' AND receipt_sent=1").fetchone()[0]
            with __import__('sqlite3').connect(ClientConfig.load(fixture.b.client_config).vault_path) as db:
                vault_memories=db.execute('SELECT count(*) FROM memories').fetchone()[0]
            native_after=native.usage() if native else None
            return dict(mode='approved_resource_distribution' if (native_after[0]['distribution'] if native else hasattr(OpenDeliveryClient,'_freeze_dispatch')) else 'prior_first_approved_session',
                agent_runtime=args.runtime,native_before=native_before,native_after=native_after,
                offered_messages=args.messages,offered_messages_per_second=args.rate,offer_window_seconds=offer_window,
                elapsed_including_drain=elapsed,successful_chains=len(ok),success_rate=len(ok)/len(rows),
                successful_chains_per_second=len(ok)/elapsed,statuses=dict(Counter(r['status'] for r in rows)),
                successful_p95_ms=percentile([r['latency_ms'] for r in ok],.95),successful_p99_ms=percentile([r['latency_ms'] for r in ok],.99),
                all_p95_ms=percentile([r['latency_ms'] for r in rows],.95),all_p99_ms=percentile([r['latency_ms'] for r in rows],.99),
                offer_lag_p99_ms=percentile([r['offer_lag_ms'] for r in rows],.99),successful_by_node=dict(Counter(str(r['node']) for r in ok)),
                recipient_saved_inbox=inbox,recipient_vault_memories=vault_memories,per_node=per_node,join=join,join_errors=join_error,
                setup_attempts=fixture.setup_attempts,requests=rows,driver=dict(
                    user_cpu_seconds=after['user_cpu_seconds']-before['user_cpu_seconds'],
                    system_cpu_seconds=after['system_cpu_seconds']-before['system_cpu_seconds'],max_rss_bytes=after['max_rss_bytes']))
        finally:
            finished.set()
            if native:native.close()
            fixture.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--messages',type=int,default=48)
    parser.add_argument('--rate',type=int,default=2)
    parser.add_argument('--join-after',type=int,default=12,help='offer index at which second node starts')
    parser.add_argument('--output',type=Path)
    parser.add_argument('--runtime',choices=('python','native'),default='python')
    parser.add_argument('--serve-config',type=Path)
    parser.add_argument('--metrics',type=Path)
    args=parser.parse_args()
    if args.serve_config:
        if not args.metrics:parser.error('metrics path required for synthetic child')
        serve(args.serve_config,args.metrics);return
    if args.messages not in (8,48) or args.rate not in (1,2) or not 1<=args.join_after<args.messages//2 or not args.output:
        parser.error('bounded workload: 8 or 48 messages, 1 or 2/s, join before half, output required')
    report=dict(synthetic=True,real_models=0,physical_hosts=1,cpu_count=os.cpu_count(),python=sys.version,platform=platform.platform(),
        scope='independently approved direct message storage, encrypted read, recipient saved receipt, Vault import/recall',
        source_hashes={n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in (
            'memory_vault_network.py','memory_vault_open_node.py','memory_vault_open_delivery_client.py','memory_vault_open_delivery_state.py',
            'memory_vault_open_index.py',
            *sorted(p.relative_to(ROOT).as_posix() for p in (ROOT/'clients/typescript/network').glob('*.ts')))},result=main_run(args))
    args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report['result'].items() if k!='requests'}),flush=True)


if __name__=='__main__':main()
