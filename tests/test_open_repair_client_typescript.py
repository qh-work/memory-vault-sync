"""Native owner recovers every exact original from a real Python HTTP source."""
import base64
import copy
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
from unittest.mock import patch
import json
import subprocess
import unittest

from tests import test_network_typescript_agent_network as ts_runtime
from tests import test_open_repair_http as http_fixture
from tests.test_open_repair_probe_typescript import private_signing, encoded
from tests.open_repair_ack_fixtures import signed_entry

DRIVER = r"""
import child from 'node:child_process';
import {syncBuiltinESMExports} from 'node:module';
let subprocessCalls=0;const deny=()=>{subprocessCalls++;throw Error('native recovery must not delegate');};
for(const name of ['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork'])child[name]=deny;
syncBuiltinESMExports();
const {AckOwnerRecoveryClient}=await import('./open-repair-client.ts');
const {OpenHTTPTransport,REPAIR_PATH}=await import('./open-transport.ts');
const {performance}=await import('node:perf_hooks');
const chunks=[];let inputSize=0;for await(const chunk of process.stdin){inputSize+=chunk.length;if(inputSize>1048576)throw Error('synthetic fixture limit');chunks.push(chunk);}
const input=JSON.parse(Buffer.concat(chunks).toString('utf8'));
const decode=item=>({raw:Buffer.from(item.raw,'base64'),ref:item.ref});
const calls=[],transport=new OpenHTTPTransport({allow_loopback:input.allowLoopback??true}),request=transport.requestRepair.bind(transport);
transport.requestRepair=async(base,raw,deadline,options)=>{
  calls.push({base,path:REPAIR_PATH,kind:JSON.parse(Buffer.from(raw).toString('utf8')).payload?.kind,child:options?.child??false});
  const value=await request(base,raw,deadline,options);
  if(options?.child&&input.damage==='short')return value.subarray(0,value.length-1);
  if(options?.child&&input.damage==='corrupt'){value[0]^=1;return value;}
  return value;
};
let client;
try{
  if(input.op==='transport'){
    const raw=Buffer.from(input.raw??'{}');let callbacks=0;
    if(input.rawGetter)Object.defineProperty(raw,'byteLength',{get(){callbacks++;throw Error('length getter');}});
    const value=await request(input.base,raw,performance.now()/1000+(input.expired?-1:5),{child:input.child??false});
    process.stdout.write(JSON.stringify({ok:true,raw:Buffer.from(value).toString('base64'),callbacks,subprocessCalls}));
  }else{
    client=new AckOwnerRecoveryClient(input.signing,input.encryption,{limitPolicy:input.limits,allowLoopback:true,transport,clock:()=>2000000006});
    const options={targetNodeEntry:decode(input.entries.descriptor),expectedTarget:input.expected.expected_target,expectedAckSlot:input.expected.expected_ack_slot,
      rootEntry:decode(input.entries.root),readEntry:decode(input.entries.read),bootstrapEntry:decode(input.entries.bootstrap),knownStatuses:(input.known??[]).map(decode),archiveStatuses:(input.archive??[]).map(decode),timeout:30};
    let callbacks=0;
    if(input.getter)Object.defineProperty(options,'expectedTarget',{get(){callbacks++;throw Error('getter');}});
    const pending=client.recover(input.base,options);
    if(input.mutate){input.expected.expected_target.signing_key.public_key='changed';options.rootEntry.raw.fill(0);input.signing.private_key='changed';}
    const result=await pending,first=result.originals[0],held=Buffer.from(first.raw);first.raw.fill(0);
    process.stdout.write(JSON.stringify({ok:true,stored_at:result.source.stored_at,metrics:result.metrics,roles:result.proof.manifest.value.children,
      originals:result.originals.map(item=>({ref:item.ref,raw:Buffer.from(item.raw).toString('base64')})),
      statuses:result.current_statuses.map(item=>item.payload),immutable:Buffer.from(first.raw).equals(held)&&Object.isFrozen(result.originals)&&Object.isFrozen(result),
      calls,subprocessCalls,callbacks}));
  }
}catch(error){process.stdout.write(JSON.stringify({ok:false,code:error.code??'untyped_error',detail:error.code?undefined:String(error.stack),calls,subprocessCalls}));}
finally{client?.close();transport.close();}
"""


class OpenRepairClientTypeScriptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ts_runtime.TypeScriptAgentNetworkTests.setUpClass.__func__(cls)
        (cls.fixture / 'driver.mjs').write_text(DRIVER)

    def setUp(self):
        self.http = http_fixture.RepairHTTPTests()
        self.addCleanup(self.http.doCleanups)
        self.http.setUp()
        self.f = self.http.source.fixture

    def call(self, **extra):
        return dict(base=self.http.base,signing=private_signing(self.f['signers']['owner']),
            encryption=self.f['encryption']['owner'].private_document(),limits=self.f['expected']['limit_policy'],
            expected=copy.deepcopy(self.f['expected']),entries={name:encoded(self.f['entries'][name])
              for name in ('descriptor','root','read','bootstrap')},**extra)

    def ts(self, call):
        process=subprocess.run([self.node,'--experimental-strip-types',str(self.fixture/'driver.mjs')],cwd=self.fixture,
            input=json.dumps(call).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=40)
        self.assertEqual(process.returncode,0,process.stderr.decode(errors='replace')[-5000:])
        result=json.loads(process.stdout)
        self.assertEqual(result['subprocessCalls'],0)
        return result

    def test_actual_native_owner_recovers_complete_python_http_source_after_restart(self):
        self.http.restart()
        result=self.ts(self.call())
        self.assertTrue(result['ok'],result)
        self.assertEqual(result['stored_at'],2_000_000_006)
        self.assertEqual((len(result['originals']),len(result['roles']),len(result['statuses'])),(13,21,2))
        self.assertEqual(result['metrics']['requests'],15)
        self.assertEqual(result['metrics']['signature_checks'],22)
        self.assertTrue(result['immutable'])
        self.assertEqual([item['kind'] for item in result['calls'][:2]],['bootstrap.probe','bootstrap.answer'])
        self.assertTrue(all(item['path']=='/open/v1/repair/bootstrap' for item in result['calls']))
        for item in result['originals']:
            raw=base64.b64decode(item['raw']);ref=item['ref']
            self.assertEqual((len(raw),hashlib.sha256(raw).hexdigest()),(ref['size'],ref['raw_sha256']))
            stored=self.http.source.state.read_local_original(self.http.source.resource_id,ref)
            self.assertEqual(raw,stored)

    def test_async_inputs_are_snapshotted_before_mutation(self):
        result=self.ts(self.call(mutate=True))
        self.assertTrue(result['ok'],result)
        self.assertTrue(result['immutable'])

    def test_accessor_input_is_rejected_without_invoking_callback_or_network(self):
        result=self.ts(self.call(getter=True))
        self.assertFalse(result['ok']);self.assertEqual(result['code'],'repair_unknown_fields')
        self.assertEqual(result['calls'],[])

    def test_short_child_refused_after_real_network_without_result(self):
        result=self.ts(self.call(damage='short'))
        self.assertFalse(result['ok']);self.assertEqual(result['code'],'repair_ref_mismatch')
        self.assertEqual(len(result['calls']),3)

    def test_corrupted_child_refused_after_real_network_without_result(self):
        result=self.ts(self.call(damage='corrupt'))
        self.assertFalse(result['ok']);self.assertEqual(result['code'],'repair_ref_mismatch')
        self.assertEqual(len(result['calls']),3)

    def test_independent_target_key_mismatch_prevents_network(self):
        call=self.call();call['expected']['expected_target']['signing_key']=self.f['signers']['writer'].public_descriptor()
        result=self.ts(call)
        self.assertFalse(result['ok']);self.assertEqual(result['code'],'repair_wrong_issuer');self.assertEqual(result['calls'],[])

    def test_real_source_revocation_between_children_stops_native_recovery(self):
        original=self.http.participant.handle_repair
        observations=[]
        def revoke_after_first_child(raw):
            response,child=original(raw)
            if child and not observations:
                with self.http.participant.state.db() as db:
                    service=self.http.participant._repair_service(db)
                    prepared=service.access.prepare(self.http.source.resource_id,action='proof',
                        current_statuses=self.http.fixture.statuses(revoked=True))
                    with service.state._transaction():
                        observations.append(service.access.check_locked(prepared).code)
            return response,child
        self.http.participant.handle_repair=revoke_after_first_child
        result=self.ts(self.call())
        self.assertFalse(result['ok']);self.assertEqual(result['code'],'open_request_rejected')
        self.assertEqual(observations,['repair_authority_revoked'])
        self.assertEqual(len(result['calls']),4)

    def test_known_expired_revocation_prevents_network(self):
        payload=copy.deepcopy(self.f['docs']['owner_status']['payload'])
        payload.update(revision=2,issued_at=1_999_999_900,valid_until=2_000_000_005)
        payload['entries'][0]['status']='revoked'
        known=signed_entry(payload,self.f['signers']['owner'],'expired_native_revocation')
        result=self.ts(self.call(known=[encoded(known)]))
        self.assertFalse(result['ok']);self.assertEqual(result['code'],'repair_authority_revoked');self.assertEqual(result['calls'],[])

    def test_known_newer_status_prevents_accepting_source_rollback(self):
        known=self.http.fixture.statuses(revision=2)
        result=self.ts(self.call(known=[encoded(item) for item in known]))
        self.assertFalse(result['ok']);self.assertEqual(result['code'],'repair_status_rollback');self.assertEqual(len(result['calls']),15)

    def test_archive_eighteen_with_known_overlap_recovers_using_one_finite_budget(self):
        archive=[]
        for revision in range(1,10):
            archive.extend(self.http.fixture.statuses(revision=revision))
        self.assertTrue(self.http.fixture.observe(archive[-2:]).allowed)
        result=self.ts(self.call(archive=[encoded(item) for item in archive],
            known=[encoded(item) for item in archive[-2:]]))
        self.assertTrue(result['ok'],result)
        self.assertEqual(result['metrics']['signature_checks'],40)
        self.assertLessEqual(result['metrics']['signature_checks'],64)
        self.assertEqual({item['revision'] for item in result['statuses']},{9})
        self.assertEqual(len(result['roles']),21)

    def test_archived_old_revision_witness_detects_new_fork_before_network(self):
        older=self.http.fixture.statuses(revision=2)[0]
        payload=json.loads(older['raw'])['payload']
        payload['valid_until']-=1
        fork=signed_entry(payload,self.f['signers']['owner'],'native_archived_revision_fork')
        latest=self.http.fixture.statuses(revision=3)[0]
        result=self.ts(self.call(archive=[encoded(older)],known=[encoded(latest),encoded(fork)]))
        self.assertFalse(result['ok']);self.assertEqual(result['code'],'repair_status_conflict')
        self.assertEqual(result['calls'],[])

    def test_archive_sticky_revocation_still_denies_despite_newer_known_active(self):
        revoked=self.http.fixture.statuses(revision=2,revoked=True)[0]
        latest=self.http.fixture.statuses(revision=3)[0]
        result=self.ts(self.call(archive=[encoded(revoked)],known=[encoded(latest)]))
        self.assertFalse(result['ok']);self.assertEqual(result['code'],'repair_authority_revoked')
        self.assertEqual(result['calls'],[])

    def test_unique_archive_union_limit_refuses_before_network(self):
        archive=[]
        for revision in range(1,17):
            archive.extend(self.http.fixture.statuses(revision=revision))
        extra=self.http.fixture.statuses(revision=17)[0]
        result=self.ts(self.call(archive=[encoded(item) for item in archive],known=[encoded(extra)]))
        self.assertFalse(result['ok']);self.assertEqual(result['code'],'repair_status_history_capacity')
        self.assertEqual(result['calls'],[])
        result=self.ts(self.call(archive=[encoded(item) for item in [*archive,extra]]))
        self.assertFalse(result['ok']);self.assertEqual(result['code'],'repair_status_history_capacity')
        self.assertEqual(result['calls'],[])

    def test_valid_known_legacy_status_whitespace_and_opaque_ref_remains_same_evidence(self):
        known=[]
        for role in ('owner_status','target_status'):
            packet=self.f['docs'][role]
            raw=json.dumps(packet,indent=2).encode()
            reference=dict(namespace='meta',key='ad'*32,raw_sha256=hashlib.sha256(raw).hexdigest(),size=len(raw))
            known.append(encoded(dict(raw=raw,ref=reference)))
        result=self.ts(self.call(known=known))
        self.assertTrue(result['ok'],result)
        self.assertEqual(result['metrics']['signature_checks'],24)
        self.assertEqual(result['metrics']['requests'],15)

    def test_transport_checks_exact_framing_and_fixed_route_over_real_http(self):
        class Reply(BaseHTTPRequestHandler):
            selected=()
            paths=[]
            def log_message(self,*args):
                pass
            def do_POST(self):
                self.paths.append(self.path)
                self.rfile.read(int(self.headers['Content-Length']))
                self.send_response(200)
                for name,value in self.selected:
                    self.send_header(name,value)
                self.end_headers()
                self.wfile.write(b'{}')
        with patch('socket.getfqdn',return_value='localhost'):
            server=ThreadingHTTPServer(('127.0.0.1',0),Reply)
        thread=threading.Thread(target=server.serve_forever,kwargs=dict(poll_interval=0.02),daemon=True)
        thread.start()
        base='http://127.0.0.1:'+str(server.server_port)
        try:
            for fields in (
                (('Content-Type','application/json'),('Content-Length','2'),('Content-Type','application/json')),
                (('Content-Type','application/json'),('Content-Length','2'),('Content-Length','2')),
                (('Content-Type','application/octet-stream'),('Content-Length','2')),
                (('Content-Type','application/json'),('Content-Length','02')),
                (('Content-Type','application/json'),('Content-Length','3')),
                (('Content-Type','application/json'),('Content-Length','65537')),
                (('Content-Type','application/json'),('Content-Length','2'),('Content-Encoding','identity')),
                (('Content-Type','application/json'),('Content-Length','2'),('X-Synthetic','x'*16500))):
                Reply.selected=fields
                with self.subTest(fields=tuple(name for name,_ in fields)):
                    result=self.ts(dict(op='transport',base=base))
                    self.assertFalse(result['ok'],result)
                    self.assertIn(result['code'],('open_repair_response_headers_rejected','open_repair_response_length_rejected','open_network_unavailable'))
            for child,content in ((False,'application/json'),(True,'application/octet-stream')):
                Reply.selected=(('Content-Type',content),('Content-Length','2'))
                result=self.ts(dict(op='transport',base=base,child=child,rawGetter=True))
                self.assertTrue(result['ok'],result)
                self.assertEqual(result['callbacks'],0)
                self.assertEqual(base64.b64decode(result['raw']),b'{}')
            self.assertEqual(set(Reply.paths),{'/open/v1/repair/bootstrap'})
        finally:
            server.shutdown();server.server_close();thread.join(timeout=3)

    def test_transport_keeps_private_destination_and_deadline_rejections(self):
        for base in ('http://127.0.0.1:80','https://192.168.1.2','https://example.com/arbitrary'):
            with self.subTest(base=base):
                result=self.ts(dict(op='transport',base=base,allowLoopback=False))
                self.assertEqual(result['code'],'open_destination_rejected')
        result=self.ts(dict(op='transport',base='https://example.com',expired=True))
        self.assertEqual(result['code'],'open_budget_exhausted')


if __name__ == '__main__':
    unittest.main()
