"""Native Agent and Python share finite grants, placement and receive cursors."""
import asyncio
import json
import sqlite3
import tempfile
import unittest

from memory_vault_open_contact_client import OpenContactClient
from memory_vault_open_routing import LookupBudget
from tests.test_open_delivery_distribution import DeliveryDistributionFixture
from tests import test_open_ack_typescript_agent as native_ack
from tests import test_network_typescript_agent_network as native_runtime


class NativeDistributionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        native_runtime.TypeScriptAgentNetworkTests.setUpClass.__func__(cls)
        (cls.fixture/'driver.mjs').write_text(native_ack.DRIVER)

    def setUp(self):
        temporary=tempfile.TemporaryDirectory(prefix='synthetic-native-distribution-')
        self.addCleanup(temporary.cleanup)
        self.f=DeliveryDistributionFixture(temporary.name)
        self.addCleanup(self.f.close)

    def native(self, agent, requests, **options):
        return native_ack.NativeAckAgentTests.native(self,agent,requests,**options)

    def send(self, i, memory_ids=()):
        return dict(op='send',request_id=f'req_synthetic_distribution_send_{i}',
            recipients=[self.f.bi.key_id],text=f'Synthetic distributed payload {i}',memory_ids=list(memory_ids))

    def test_python_native_alternate_sender_receiver_and_reopen_saved_receipts(self):
        f=self.f;f.approve(0,items=2)
        memory=f.call(f.a,op='remember',request_id='req_native_distributed_memory',kind='observation',
            text='Synthetic cross-language resource reuse observation.')['memory_id']
        first=self.native(f.a,[self.send(0,[memory])])['results'][0];self.assertTrue(first['ok'],first)
        f.approve(1,items=2)
        sent=[first,f.send(1,memory_ids=[memory]),self.native(f.a,[self.send(2,[memory])])['results'][0],f.send(3,memory_ids=[memory])]
        self.assertTrue(all(row['ok'] for row in sent),sent);self.assertEqual(f.stored(),[2,2])
        received=[]
        for index in range(4):
            value=(self.native(f.b,[dict(op='receive',limit=1)])['results'][0]['result']
                   if index%2==0 else f.call(f.b,op='receive',limit=1))
            self.assertEqual(value['errors'],[]);self.assertEqual(len(value['messages']),1,value)
            received+=value['messages']
        locations={}
        for index in range(2):
            with sqlite3.connect(f.root/f'node_{index}'/'transport/network.sqlite3') as db:
                locations.update((row[0],index) for row in db.execute('SELECT message_id FROM open_delivery_messages'))
        self.assertNotEqual(locations[received[0]['message_id']],locations[received[1]['message_id']])
        for index,row in enumerate(sent):
            result=self.native(f.a,[self.send(index,[memory])])['results'][0]
            self.assertTrue(result['ok'],result);self.assertTrue(result['result']['endpoint_validated'])
            read=self.native(f.b,[dict(op='receive',message_id=row['result']['message_id']),
                dict(op='recall',memory_id=memory)],no_network=True)['results']
            self.assertTrue(all(value['ok'] for value in read),read)
            self.assertIn('Synthetic cross-language',read[1]['result']['hits'][0]['text'])
        full=self.native(f.a,[self.send(4)])['results'][0]
        self.assertFalse(full['ok']);self.assertEqual(full['error']['code'],'open_delivery_approval_capacity')
        self.assertEqual(f.stored(),[2,2])

    def test_native_obeys_live_policy_revocation_without_unapproved_retarget(self):
        f=self.f;enabled=f.approve(0,items=2)
        with f.b._network() as network:
            contact=OpenContactClient(network.participant,network.encryption)
            session=contact._load('policy',enabled['lease_id'])
            payload={**session['policy']['payload'],'revision':2,'status':'revoked'}
            revoked={'payload':payload,'proof':f.bi.sign_message(payload)}
            asyncio.run(contact.call(f.host.nodes[0],'policy.put',{'lease':session['lease'],'policy':revoked},LookupBudget()))
        refused=self.native(f.a,[self.send(0)])['results'][0]
        self.assertFalse(refused['ok']);self.assertEqual(refused['error']['code'],'open_delivery_revoked')
        self.assertEqual(f.stored(),[0,0])

    def test_native_freeze_survives_source_failure_and_restarts_without_duplicate_store(self):
        f=self.f;f.approve(0,items=2)
        first=self.native(f.a,[self.send(0)])['results'][0];self.assertTrue(first['ok'],first)
        with f.a._network() as network:
            with network.participant.state.db() as db:
                frozen=tuple(bytes(x) for x in db.execute('SELECT envelope,session,intent FROM open_delivery_outbox WHERE request_id=?',(self.send(0)['request_id'],)).fetchone())
        f.approve(1,items=2);f.host.stop(0)
        retried=self.native(f.a,[self.send(0)])['results'][0]
        self.assertTrue(retried['ok'],retried);self.assertFalse(retried['result']['endpoint_validated'])
        self.assertEqual(retried['result']['message_id'],first['result']['message_id'])
        f.host.start(0)
        received=f.call(f.b,op='receive',limit=1);self.assertEqual(len(received['messages']),1,received)
        confirmed=self.native(f.a,[self.send(0)])['results'][0]
        self.assertTrue(confirmed['ok'],confirmed);self.assertTrue(confirmed['result']['endpoint_validated'])
        with f.a._network() as network:
            with network.participant.state.db() as db:
                again=tuple(bytes(x) for x in db.execute('SELECT envelope,session,intent FROM open_delivery_outbox WHERE request_id=?',(self.send(0)['request_id'],)).fetchone())
        self.assertEqual(again,frozen);self.assertEqual(f.stored(),[1,0])

    def test_native_new_send_uses_independent_grant_after_known_old_node_revocation(self):
        import time
        from memory_vault import MemoryError
        from memory_vault_open_control import issue_node
        f=self.f;f.approve(0,items=2)
        first=self.native(f.a,[self.send(0)])['results'][0];self.assertTrue(first['ok'],first)
        f.approve(1,items=2)
        p=f.host.nodes[0]['payload'];now=int(time.time())
        revoked=issue_node(f.host.identities[0],base_url=p['base_url'],storage_epoch=p['storage_epoch'],
            roles=p['roles'],revision=2,status='revoked',issued_at=now,expires_at=now+600)
        with f.a._network() as network:
            with self.assertRaises(MemoryError):network.participant._accept(revoked)
        next_send=self.native(f.a,[self.send(1)])['results'][0]
        self.assertTrue(next_send['ok'],next_send);self.assertEqual(f.stored(),[1,1])
        old=self.native(f.a,[self.send(0)])['results'][0]
        self.assertTrue(old['ok'],old);self.assertFalse(old['result']['endpoint_validated'])
        self.assertEqual(old['result']['message_id'],first['result']['message_id'])
        self.assertEqual(f.stored(),[1,1])


if __name__=='__main__':unittest.main()
