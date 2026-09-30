"""Ordinary sender confirmation after both original delivery and ACK sources stop."""
import json
import time
from types import SimpleNamespace
from unittest.mock import patch

from memory_vault_open_client import ACK_CONNECT_SCHEMA
from memory_vault_open_control import issue_node
from memory_vault_open_delivery_client import OpenDeliveryClient
from memory_vault_open_transport import OpenHTTPTransport
from tests import test_open_repair_copy_occupied as fixtures


class RegisteredAckReplicaTests(fixtures.OccupiedReplicaAgentTests):
    def test_removed_selection_keeps_authenticated_read_revocation(self):
        import copy
        from memory_vault_agent import Agent
        from tests.open_repair_ack_fixtures import signed_entry
        f=self.fixture
        encode=lambda entry:dict(raw=entry['raw'].decode(),ref=entry['ref'])
        request=dict(target_node_entry=encode(self.node),expected_target=f.destination.state.target,
            **{name:value for name,value in f.context.items() if name!='expected_owner'},**f.bound,
            expected_maintainer=f.keys,**{name+'_entry':encode(f.f['entries'][name]) for name in ('root','read','bootstrap')})
        selected=dict(schema_version=ACK_CONNECT_SCHEMA,action='register_replica_receipt',
            base_url=self.base,repair_profile='receipt-index',request=request)
        with patch.object(OpenHTTPTransport,'request_node',side_effect=AssertionError('revocation test read node')), \
             patch.object(OpenHTTPTransport,'request_repair',side_effect=AssertionError('revoked grant reached replica')):
            registered=self.delivery.call(self.sender,op='connect',invitation=selected)
            revoked=copy.deepcopy(f.owner_status);revoked['revision']+=1
            for entry in revoked['entries']:entry['status']='revoked'
            observation=encode(signed_entry(revoked,f.f['signers']['owner'],'synthetic_retained_ack_read_revocation'))
            refused=self.sender.handle(dict(op='connect',invitation=dict(selected,
                request=dict(request,known_statuses=[observation]))))
            self.assertFalse(refused['ok']);self.assertEqual(refused['error']['code'],'repair_authority_revoked')
            self.delivery.call(self.sender,op='connect',invitation=dict(schema_version=ACK_CONNECT_SCHEMA,
                action='remove_replica_receipt',replica_id=registered['replica_id']))
            self.sender=Agent(self.sender.client_config,self.sender.network_config)
            replay=self.sender.handle(dict(op='connect',invitation=selected))
            self.assertFalse(replay['ok']);self.assertEqual(replay['error']['code'],'repair_authority_revoked')

    def recover_from_replica(self, invitation):
        from memory_vault_open_ack_replica_send import recover
        selected=dict(invitation,action='register_replica_receipt')
        with patch.object(OpenHTTPTransport,'request_node',side_effect=AssertionError('registration read a node')), \
             patch.object(OpenHTTPTransport,'request_repair',side_effect=AssertionError('registration contacted replica')):
            registered=self.delivery.call(self.sender,op='connect',invitation=selected)
            self.assertFalse(registered['network_accessed'])
            self.assertEqual(self.delivery.call(self.sender,op='connect',invitation=selected),registered)
        replica_id=registered['replica_id']
        inspect=dict(schema_version=ACK_CONNECT_SCHEMA,action='inspect_replica_receipt',replica_id=replica_id)
        self.assertFalse(self.delivery.call(self.sender,op='connect',invitation=inspect)['network_accessed'])
        with patch.object(OpenHTTPTransport,'request_node',side_effect=AssertionError('changed send read source')):
            refused=self.sender.handle(dict(self.send_request,text='Synthetic changed original send'))
        self.assertFalse(refused['ok']);self.assertEqual(refused['error']['code'],'network_request_id_conflict')
        node=json.loads(self.node['raw'])['payload']
        wrong=issue_node(self.fixture.destination.state.identity,base_url=self.base,
            storage_epoch='synthetic_other_epoch',roles=node['roles'],revision=node['revision']+1,
            issued_at=self.delivery_now[0]-1,expires_at=self.delivery_now[0]+300)
        with self.sender._network() as network:
            with patch.object(network.participant.transport,'request_node',return_value=SimpleNamespace(response=wrong)), \
                 patch.object(network.participant.transport,'request_repair',side_effect=AssertionError('wrong epoch received read grant')):
                rejected=recover(network,network._delivery(),{k:v for k,v in self.send_request.items() if k!='op'},deadline=time.monotonic()+60)
            self.assertEqual(rejected['error']['code'],'open_ack_replica_send_mismatch')
        self.assertEqual(self.delivery.call(self.sender,op='connect',invitation=inspect)['last_error'],'open_ack_replica_send_mismatch')
        with patch.object(OpenDeliveryClient,'call',side_effect=AssertionError('original delivery source contacted')):
            sent=self.delivery.call(self.sender,**self.send_request)
        self.assertEqual(sent['ack_recovery'],'validated_saved')
        self.assertEqual(sent['ack_replica_id'],replica_id)
        self.assertTrue(sent['network_accessed'])
        with patch.object(OpenHTTPTransport,'request_node',side_effect=AssertionError('confirmed send read node again')):
            again=self.delivery.call(self.sender,**self.send_request)
        self.assertEqual(again['state'],'validated_saved');self.assertFalse(again['network_accessed'])
        with self.sender._network() as network:
            with network.participant.state.db() as db:
                count=db.execute('SELECT count(*) FROM open_ack_replica_statuses').fetchone()[0]
            self.assertGreater(count,0)
            network.connect(invitation=dict(schema_version=ACK_CONNECT_SCHEMA,action='remove_replica_receipt',replica_id=replica_id))
            with network.participant.state.db() as db:
                self.assertEqual(db.execute('SELECT count(*) FROM open_ack_replica_statuses').fetchone()[0],count)
        return dict(sent,commit_ref=sent['ack_commit_ref'],replica_custody_ref=sent['ack_replica_custody_ref'])
