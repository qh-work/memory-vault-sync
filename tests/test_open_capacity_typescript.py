"""Same SQLite reservation policy across actual Python/native writers."""
import concurrent.futures
import json
import sqlite3
import subprocess
import unittest
import uuid

from memory_vault import canonical_bytes, MemoryError
from memory_vault_open_contact import sign_rpc, verify_lease, SLOT_BYTES
import memory_vault_open_capacity as capacity
from tests import test_network_typescript_agent_network as ts_runtime
from tests import test_open_contact as contact_fixture

DRIVER=r"""
import {DatabaseSync} from 'node:sqlite';
import * as c from './open-capacity.ts';
import {ContactState} from './open-contact-state.ts';
const chunks=[];for await(const chunk of process.stdin)chunks.push(chunk);
const input=JSON.parse(Buffer.concat(chunks).toString('utf8')),db=new DatabaseSync(input.path);
db.exec('PRAGMA busy_timeout=10000; PRAGMA trusted_schema=OFF');
const authority=new c.CapacityAuthority(db,input.policy),results=[];
function tx(fn){db.exec('BEGIN IMMEDIATE');try{const value=fn();db.exec('COMMIT');return value;}catch(e){db.exec('ROLLBACK');throw c.translateCapacityError(e);}}
let now=input.contact?.now,state;
try{
 if(input.initialize!==false)tx(()=>authority.initialize());
 if(input.contact){state=new ContactState(db,input.contact.identity,input.contact.node,{enabled:true,clock:()=>now,...input.contact.options});state.initialize();}
 for(const event of input.events??[]){try{
   if(event.now!==undefined)now=event.now;
   let value;
   if(event.op==='contact')value=await state.handle(event.rpc);
   else if(event.op==='gc')value=state.gc();
   else if(event.op==='usage')value=authority.usage();
   else if(event.op==='schema')value=db.prepare("SELECT type,name,sql FROM sqlite_master WHERE name LIKE 'open_capacity_%' ORDER BY type,name").all();
   else if(event.op==='query')value=db.prepare(event.sql).all(...(event.args??[]));
   else value=tx(()=>{
     if(event.op==='sql')return db.prepare(event.sql).run(...(event.args??[]));
     if(event.op==='reserve')return authority.reserve(event.service??'ack',event.id,event.digest,event.bytes,event.retain,{owner:'synthetic_owner',operation_id:event.id});
     if(event.op==='catch_reserve'){try{return authority.reserve(event.service??'ack',event.id,event.digest,event.bytes,event.retain,{owner:'synthetic_owner',operation_id:event.id});}catch(error){return {caught:error.code};}}
     if(event.op==='collect')return authority.collectReleased(event.service,{now:event.at,limit:event.limit});
     if(event.op==='check')return new c.CapacityAuthority(db,event.policy).checkPolicy();
     throw Error('unknown synthetic operation');
   });
   results.push({ok:true,value});
 }catch(error){results.push({ok:false,code:c.translateCapacityError(error).code??'untyped_error'});}}
 process.stdout.write(JSON.stringify({ok:true,results}));
}catch(error){process.stdout.write(JSON.stringify({ok:false,code:c.translateCapacityError(error).code??'untyped_error'}));}
finally{db.close();}
"""


class OpenCapacityTypeScriptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ts_runtime.TypeScriptAgentNetworkTests.setUpClass.__func__(cls)
        (cls.fixture/'driver.mjs').write_text(DRIVER)

    def setUp(self):
        self.path=self.fixture/('capacity_'+uuid.uuid4().hex+'.sqlite')

    def ts(self,events=(),**options):
        run=subprocess.run([self.node,'--experimental-strip-types',str(self.fixture/'driver.mjs')],cwd=self.fixture,
            input=json.dumps(dict(path=str(self.path),events=events,**options)).encode(),stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,timeout=30)
        self.assertEqual(run.returncode,0,run.stderr.decode(errors='replace')[-5000:]);return json.loads(run.stdout)

    @staticmethod
    def reserve(name='synthetic_ack',charge=4096):
        return dict(op='reserve',id=name,digest='a'*64,bytes=charge,retain=200)

    @staticmethod
    def contact_insert(name='synthetic_lease',purpose='knock',items=1,size=12800,retain=200):
        return dict(op='sql',sql='INSERT INTO open_contact_resource_leases VALUES(?,?,?,?,?,?,?,?,?,?,?,NULL)',
            args=[name,'synthetic_owner',name,'a'*64,purpose,'{}',items,size,100,retain,'active'])

    @staticmethod
    def provider_insert(name='synthetic_provider'):
        record=json.dumps(dict(payload=dict(budget=dict(max_live_bytes=100,max_meta_bytes=200,
            max_job_bytes=300,max_replay_records=2))))
        return dict(op='sql',sql='INSERT INTO open_provider_resources VALUES(?,?,?,?,CAST(? AS BLOB),CAST(? AS BLOB),?,?,?,CAST(? AS BLOB),?,?,?,0)',
            args=[name,'synthetic_owner',name,'b'*64,'{}',record,'c'*64,'provider_index','active','{}',1,100,200])

    def initialize_python(self,policy=None):
        db=sqlite3.connect(self.path)
        db.execute('BEGIN IMMEDIATE');authority=capacity.CapacityAuthority(db,policy=policy);authority.initialize();db.commit()
        return db,authority

    def test_shared_schema_identical_and_native_adopts_python_policy(self):
        selected=dict(maximum_reserved_bytes=capacity.SERVICE_RESERVE_BYTES+1000000,maximum_reservations=7)
        db,authority=self.initialize_python(selected);self.addCleanup(db.close)
        expected=[dict(zip(('type','name','sql'),row)) for row in db.execute(
            "SELECT type,name,sql FROM sqlite_master WHERE name LIKE 'open_capacity_%' ORDER BY type,name")]
        actual=self.ts([dict(op='schema'),dict(op='usage')]);self.assertTrue(actual['ok'],actual)
        self.assertEqual(actual['results'][0]['value'],expected)
        self.assertEqual(actual['results'][1]['value'],authority.usage())
        bad=self.ts(policy={**selected,'maximum_reservations':8})
        self.assertEqual(bad['code'],'open_capacity_policy_mismatch')

    def test_native_created_reservations_are_visible_to_python_and_exact_replay(self):
        actual=self.ts([self.reserve(),self.reserve(),dict(op='usage')]);self.assertTrue(actual['ok'],actual)
        self.assertTrue(actual['results'][0]['value']);self.assertFalse(actual['results'][1]['value'])
        db,authority=self.initialize_python();self.addCleanup(db.close)
        self.assertEqual(authority.usage(),actual['results'][2]['value'])
        db.execute('BEGIN IMMEDIATE')
        self.assertFalse(authority.reserve('ack','synthetic_ack','a'*64,4096,200,owner='synthetic_owner',operation_id='synthetic_ack'))
        db.commit()
        changed=self.reserve();changed['bytes']=4097
        result=self.ts([changed,dict(op='usage')])['results']
        self.assertEqual(result[0]['code'],'open_capacity_reservation_conflict')
        self.assertEqual(result[1]['value'],authority.usage())

    def test_repair_directory_and_ack_share_capacity_across_native_restart(self):
        selected = dict(maximum_reserved_bytes=capacity.SERVICE_RESERVE_BYTES+4096,maximum_reservations=2)
        index = dict(self.reserve('synthetic_index'),service='repair_index')
        first = self.ts([index,dict(op='usage')],policy=selected)['results']
        self.assertTrue(first[0]['value'])
        db, authority = self.initialize_python(); self.addCleanup(db.close)
        self.assertEqual(authority.usage(),first[1]['value'])
        db.execute('BEGIN IMMEDIATE')
        self.assertFalse(authority.reserve('repair_index','synthetic_index','a'*64,4096,200,
            owner='synthetic_owner',operation_id='synthetic_index'))
        with self.assertRaisesRegex(MemoryError,'open_capacity_exhausted'):
            authority.reserve('ack','synthetic_second','b'*64,1,200,
                owner='synthetic_owner',operation_id='synthetic_second')
        db.commit()
        again = self.ts([index,dict(self.reserve('synthetic_third',1),service='repair_index'),
            dict(op='usage')],policy=selected)['results']
        self.assertFalse(again[0]['value'])
        self.assertEqual(again[1]['code'],'open_capacity_exhausted')
        self.assertEqual(again[2]['value'],first[1]['value'])

    def test_mailbox_reservation_cannot_bypass_shared_native_capacity(self):
        selected = dict(maximum_reserved_bytes=capacity.SERVICE_RESERVE_BYTES+4096,maximum_reservations=2)
        mailbox = dict(self.reserve('synthetic_mailbox'),service='mailbox')
        first = self.ts([mailbox,dict(op='usage')],policy=selected)['results']
        self.assertTrue(first[0]['value'])
        db, authority = self.initialize_python(); self.addCleanup(db.close)
        self.assertEqual(authority.usage(),first[1]['value'])
        db.execute('BEGIN IMMEDIATE')
        self.assertFalse(authority.reserve('mailbox','synthetic_mailbox','a'*64,4096,200,
            owner='synthetic_owner',operation_id='synthetic_mailbox'))
        with self.assertRaisesRegex(MemoryError,'open_capacity_exhausted'):
            authority.reserve('ack','synthetic_ack', 'b'*64,1,200,
                owner='synthetic_owner',operation_id='synthetic_ack')
        db.commit()
        again = self.ts([mailbox,dict(self.reserve('synthetic_other',1),service='repair_index'),
            dict(op='usage')],policy=selected)['results']
        self.assertFalse(again[0]['value'])
        self.assertEqual(again[1]['code'],'open_capacity_exhausted')
        self.assertEqual(again[2]['value'],first[1]['value'])

    def test_old_oversubscribed_obligations_migrate_without_eviction(self):
        db=sqlite3.connect(self.path);self.addCleanup(db.close)
        for sql in capacity.RESERVATION_TABLES.values():db.execute(sql)
        for event in (self.contact_insert(),self.provider_insert()):db.execute(event['sql'],event['args'])
        db.commit()
        actual=self.ts([dict(op='usage'),self.reserve(),dict(op='usage')],
            policy=dict(maximum_reserved_bytes=1,maximum_reservations=1))
        self.assertTrue(actual['ok'],actual);result=actual['results']
        self.assertTrue(result[0]['value']['oversubscribed']);self.assertEqual(result[0]['value']['reservations'],2)
        self.assertEqual(result[1]['code'],'open_capacity_exhausted');self.assertEqual(result[2]['value'],result[0]['value'])
        self.assertEqual(db.execute('SELECT count(*) FROM open_contact_resource_leases').fetchone()[0],1)
        self.assertEqual(db.execute('SELECT count(*) FROM open_provider_resources').fetchone()[0],1)

    def test_contact_directory_reservation_survives_restart_and_live_job_until_retention(self):
        selected=dict(maximum_reserved_bytes=capacity.SERVICE_RESERVE_BYTES+65536,maximum_reservations=2)
        job=dict(self.reserve('synthetic_directory',65536),service='contact_directory')
        first=self.ts([job,job,dict(op='usage')],policy=selected)['results']
        self.assertTrue(first[0]['value']);self.assertFalse(first[1]['value'])
        db,authority=self.initialize_python();self.addCleanup(db.close)
        self.assertEqual(authority.usage(),first[2]['value'])
        db.execute('BEGIN IMMEDIATE')
        self.assertFalse(authority.reserve('contact_directory','synthetic_directory','a'*64,65536,200,
            owner='synthetic_owner',operation_id='synthetic_directory'))
        self.assertEqual(authority.collect_released('contact_directory',now=199),0)
        db.execute('CREATE TABLE open_contact_directory_jobs(job_id TEXT PRIMARY KEY)')
        db.execute("INSERT INTO open_contact_directory_jobs VALUES('synthetic_directory')")
        self.assertEqual(authority.collect_released('contact_directory',now=200),0)
        db.commit()
        held=self.ts([dict(op='collect',service='contact_directory',at=200),
            dict(self.reserve('synthetic_other',1),service='ack'),
            dict(job,bytes=65535),dict(op='usage')])['results']
        self.assertEqual(held[0]['value'],0)
        self.assertEqual(held[1]['code'],'open_capacity_exhausted')
        self.assertEqual(held[2]['code'],'open_capacity_reservation_conflict')
        self.assertEqual(held[3]['value'],first[2]['value'])
        db.execute("DELETE FROM open_contact_directory_jobs WHERE job_id='synthetic_directory'");db.commit()
        released=self.ts([dict(op='collect',service='contact_directory',at=199),
            dict(op='collect',service='contact_directory',at=200),dict(op='usage')])['results']
        self.assertEqual([item['value'] for item in released[:2]],[0,1])
        self.assertEqual(released[2]['value']['reserved_bytes'],capacity.SERVICE_RESERVE_BYTES)
        self.assertEqual(authority.usage(),released[2]['value'])

    def test_oversubscribed_migration_preserves_totals_above_safe_integer_exactly(self):
        db=sqlite3.connect(self.path);self.addCleanup(db.close)
        for sql in capacity.RESERVATION_TABLES.values():db.execute(sql)
        for name in ('synthetic_large_a','synthetic_large_b'):
            event=self.contact_insert(name,size=capacity.U53_MAX-capacity.CONTACT_LEASE_BYTES)
            db.execute(event['sql'],event['args'])
        db.commit()
        actual=self.ts([dict(op='usage')]);self.assertTrue(actual['ok'],actual)
        result=actual['results'][0]['value']
        self.assertTrue(result['oversubscribed'])
        self.assertEqual(result['reserved_bytes'],str(capacity.SERVICE_RESERVE_BYTES+2*capacity.U53_MAX))
        authority=capacity.CapacityAuthority(db)
        self.assertEqual(result,authority.usage())

    def test_cross_service_insert_trigger_and_update_guards_are_atomic(self):
        selected=dict(maximum_reserved_bytes=capacity.SERVICE_RESERVE_BYTES+capacity.contact_charge('knock',1,12800),maximum_reservations=2)
        results=self.ts([self.contact_insert(),self.provider_insert(),dict(op='usage'),
            dict(op='sql',sql="UPDATE open_contact_resource_leases SET max_bytes=1"),
            dict(op='query',sql='SELECT max_bytes FROM open_contact_resource_leases')],policy=selected)['results']
        self.assertTrue(results[0]['ok']);self.assertEqual(results[1]['code'],'open_capacity_exhausted')
        self.assertEqual(results[2]['value']['reservations'],1)
        self.assertEqual(results[3]['code'],'open_capacity_immutable_reservation')
        self.assertEqual(results[4]['value'],[dict(max_bytes=12800)])
        db=sqlite3.connect(self.path);self.addCleanup(db.close)
        event=self.provider_insert()
        with self.assertRaisesRegex(sqlite3.IntegrityError,'open_capacity_exhausted'):
            db.execute(event['sql'],event['args'])
        db.rollback();self.assertEqual(db.execute('SELECT count(*) FROM open_provider_resources').fetchone()[0],0)

    def test_retention_and_live_dependencies_hold_charge_until_actual_collection(self):
        events=[self.contact_insert(),dict(op='sql',sql='CREATE TABLE open_contact_policies(lease_id TEXT)'),
            dict(op='sql',sql="INSERT INTO open_contact_policies VALUES('synthetic_lease')"),
            dict(op='sql',sql='DELETE FROM open_contact_resource_leases'),
            dict(op='collect',service='contact',at=199),dict(op='collect',service='contact',at=200),
            dict(op='sql',sql='DELETE FROM open_contact_policies'),dict(op='collect',service='contact',at=200),dict(op='usage')]
        results=self.ts(events)['results']
        self.assertEqual([results[index]['value'] for index in (4,5,7)],[0,0,1])
        self.assertEqual(results[-1]['value']['reservations'],0)

    def test_explicit_policy_is_rechecked_without_reinitialization(self):
        actual=self.ts([dict(op='check',policy={**capacity.DEFAULT_POLICY,'maximum_reservations':1})])
        self.assertEqual(actual['results'][0]['code'],'open_capacity_policy_mismatch')

    def test_refused_reservation_cannot_commit_when_caller_catches_error(self):
        selected=dict(maximum_reserved_bytes=capacity.SERVICE_RESERVE_BYTES,maximum_reservations=1)
        event={**self.reserve(),'op':'catch_reserve'}
        results=self.ts([event,dict(op='usage')],policy=selected)['results']
        self.assertEqual(results[0]['value'],dict(caught='open_capacity_exhausted'))
        self.assertEqual(results[1]['value']['reservations'],0)

    def test_provider_status_root_holds_only_its_own_retained_reservation(self):
        events=[self.provider_insert(),dict(op='sql',sql='CREATE TABLE open_provider_status(root_digest TEXT)'),
            dict(op='sql',sql='INSERT INTO open_provider_status VALUES(?)',args=['c'*64]),
            dict(op='sql',sql='DELETE FROM open_provider_resources'),dict(op='collect',service='provider',at=200),
            dict(op='sql',sql='UPDATE open_provider_status SET root_digest=?',args=['d'*64]),
            dict(op='collect',service='provider',at=200),dict(op='usage')]
        results=self.ts(events)['results']
        self.assertEqual(results[4]['value'],0);self.assertEqual(results[6]['value'],1)
        self.assertEqual(results[7]['value']['reservations'],0)

    def test_two_native_connections_compete_for_one_shared_reservation(self):
        selected=dict(maximum_reserved_bytes=capacity.SERVICE_RESERVE_BYTES+4096,maximum_reservations=1)
        self.assertTrue(self.ts(policy=selected)['ok'])
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            futures=[pool.submit(self.ts,[self.reserve('synthetic_'+str(index))]) for index in range(2)]
            values=[future.result()['results'][0] for future in futures]
        self.assertEqual(sum(value['ok'] for value in values),1)
        self.assertEqual([value['code'] for value in values if not value['ok']],['open_capacity_exhausted'])
        self.assertEqual(self.ts([dict(op='usage')])['results'][0]['value']['reservations'],1)

    def test_native_contact_real_allocation_uses_shared_admission_and_typed_refusal(self):
        fixture=contact_fixture.OpenContactProtocolTests('test_valid_opt_in_request_and_explicit_finite_delivery_decision')
        self.addCleanup(fixture.doCleanups);fixture.setUp()
        body=dict(encryption_key=fixture.recipient_encryption.public_descriptor(),purpose='knock',max_items=1,
            max_bytes=SLOT_BYTES,lease_seconds=600,allocation_id='native_knock')
        rpc=sign_rpc(fixture.recipient,node=fixture.node,action='lease',body=body,now=fixture.now)
        delivery=sign_rpc(fixture.recipient,node=fixture.node,action='lease',body={**body,'purpose':'delivery',
            'max_bytes':8192,'allocation_id':'native_delivery'},now=fixture.now)
        selected=dict(maximum_reserved_bytes=capacity.DEFAULT_POLICY['maximum_reserved_bytes'],maximum_reservations=1)
        contact=dict(identity=json.loads((fixture.root/'synthetic_node.json').read_text()),node=fixture.node,now=fixture.now)
        actual=self.ts([dict(op='contact',rpc=rpc),dict(op='contact',rpc=rpc),dict(op='contact',rpc=delivery),dict(op='usage')],
            policy=selected,contact=contact)
        self.assertTrue(actual['ok'],actual);results=actual['results']
        self.assertTrue(results[0]['ok'],results);self.assertEqual(results[0],results[1])
        verify_lease(results[0]['value']['lease'],node=fixture.node,now=fixture.now)
        self.assertEqual(results[2]['code'],'open_capacity_exhausted')
        self.assertEqual(results[3]['value']['reservations'],1)
