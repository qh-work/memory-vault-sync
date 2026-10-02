"""Native frozen send, full replica verification and independent saved receipt.

Python serves the independently approved replica. Native sender and recipient
execute their Agent operations without subprocess delegation. Finite replica
work limits are measured, retained and never increased for the load test.
"""
import hashlib
import json
import os
from pathlib import Path
import time
import unittest
from unittest.mock import patch

from tests import test_open_delivery_http as delivery_fixtures
from tests import test_open_repair_mailbox_feed_copy as feed_fixtures
from tests import test_open_mailbox_replica_receive as registered_fixtures
from tests import test_open_ack_typescript_agent as native_ack
from tests import test_network_typescript_agent_network as native_runtime


class CrossLanguageReplicaClosureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        native_runtime.TypeScriptAgentNetworkTests.setUpClass.__func__(cls)
        (cls.fixture/'driver.mjs').write_text(native_ack.DRIVER.replace('for(const name of',
            "if(process.env.MEMORY_VAULT_FIXTURE_NOW)Date.now=()=>Number(process.env.MEMORY_VAULT_FIXTURE_NOW)*1000;\nfor(const name of",1))

    def native(self, agent, requests, **options):
        return native_ack.NativeAckAgentTests.native(self,agent,requests,**options)

    def run_fixture(self, inspect):
        fixture=delivery_fixtures.MailboxStagingHTTPTests('test_ack_configuration_survives_mailbox_custody')
        fixture.setUp();self.addCleanup(fixture.doCleanups);fixture.ack_cold_return=True
        original=fixture.call
        def call(agent,**request):
            if (agent is fixture.a and request['op']=='send') or (getattr(self,'native_recipient',False) and agent is fixture.b):
                response=self.native(agent,[request])['results'][0]
                self.assertTrue(response['ok'],response)
                return response['result']
            return original(agent,**request)
        fixture.call=call;self.delivery_fixture=fixture
        def committed(staging,slot,head):
            h=feed_fixtures.FeedCopyFixture(self,fixture,staging,slot,head,message=True)
            # Both runtimes use the same fixture clock. Real monotonic deadlines
            # remain active; the protocol rejects future-dated probes strictly.
            with patch('time.time',return_value=h.now),patch.dict(os.environ,{'MEMORY_VAULT_FIXTURE_NOW':str(h.now)}):inspect(h)
        fixture.inspect_committed_mailbox=committed
        fixture.test_ack_configuration_survives_mailbox_custody()

    def inspect_registration(self,h,registration,configured):
        # Includes wrong-epoch refusal and bounded independent destination count.
        registered_fixtures.RegisteredReplicaTests.inspect_registration(self,h,registration,configured)
        self.original_envelope=h.snapshot.read(h.envelope_ref)
        self.assertEqual(hashlib.sha256(self.original_envelope).hexdigest(),h.envelope_ref['raw_sha256'])
        if getattr(self,'native_recipient',False):
            from memory_vault_open_control import issue_node
            changed=issue_node(h.identity,base_url=registration['base_url'],storage_epoch='synthetic_replaced_native_target',
                roles=['directory','router'],revision=100,issued_at=h.now,expires_at=h.now+300)
            wrong=self.native(h.recipient_agent,[dict(op='receive')],node_override=changed)
            self.assertTrue(wrong['results'][0]['ok'],wrong)
            self.assertTrue(any(e['code']=='open_invalid_mailbox_receiver' for e in wrong['results'][0]['result']['errors']),wrong)
            self.assertFalse(any(c['kind']=='requestRepair' and c['base']==registration['base_url'] for c in wrong['calls']))

    def cold_load(self,h,registration):
        """Three additional empty Vaults reuse explicit existing permission.

        This measures a bounded known-message demand on the added replica. It
        does not inject unknown future IDs into a pre-message frozen recipient,
        or represent three independent owners/failure domains.
        """
        from memory_vault_agent import Agent
        from memory_vault import canonical_bytes
        from memory_vault_trust import _write_new_private
        client=json.loads(Path(h.recipient_agent.client_config).read_bytes())
        network=json.loads(Path(h.recipient_agent.network_config).read_bytes())
        self.cold_results=[]
        for i in range(3):
            folder=h.directory/('synthetic-native-cold-'+str(i));folder.mkdir(mode=0o700)
            # A new private state binds to its own empty Vault. Copying another
            # state's frozen Vault binding would correctly be refused.
            state=folder/'transport';state.mkdir(mode=0o700)
            vault=folder/'vault';vault.mkdir(mode=0o700)
            copied_client=dict(client,vault_path=str(vault/'memory.sqlite3'))
            client_path=folder/'client.json';config_path=folder/'open.json'
            _write_new_private(client_path,canonical_bytes(copied_client))
            _write_new_private(config_path,canonical_bytes(dict(network,client_config_path=str(client_path),state_directory=str(state))))
            agent=Agent(client_path,config_path)
            work_before=h.db.execute('SELECT requests FROM open_repair_copy_work WHERE resource_id=?',(h.rid,)).fetchone()[0]
            started=time.perf_counter()
            out=self.native(agent,[dict(op='connect',invitation=registration),dict(op='receive')]);elapsed=(time.perf_counter()-started)*1000
            self.assertTrue(out['results'][0]['ok'],out)
            received=out['results'][1];self.assertTrue(received['ok'],received)
            repair=[c for c in out['calls'] if c['kind']=='requestRepair'];self.assertTrue(repair)
            self.assertTrue(all(c['base']==registration['base_url'] for c in repair))
            work_after=h.db.execute('SELECT requests FROM open_repair_copy_work WHERE resource_id=?',(h.rid,)).fetchone()[0]
            self.assertLessEqual(work_after,64)
            evidence=dict(offered=1,completed=len(received['result']['messages']),elapsed_ms=elapsed,
                repair_http_calls=len(repair),copy_work_before=work_before,copy_work_after=work_after,
                copied_ciphertext_bytes=h.envelope_ref['size'] if received['result']['messages'] else 0,subprocess_calls=0)
            self.cold_results.append(evidence)
            if not received['result']['messages']:
                # Upload and complete reads use this resource's original finite
                # work grant. Additional demand must fail closed, rather
                # than reset the durable count or silently expand permission.
                self.assertEqual(received['result']['messages'],[],received)
                self.assertEqual(work_after,64)
                self.assertTrue(received['result']['errors'],received)
                evidence['errors']=[v['code'] for v in received['result']['errors']]
                continue
            self.assertEqual(len(received['result']['messages']),1,received)
            message=received['result']['messages'][0];self.assertEqual(message['share']['records_added'],1)
            offline=self.native(agent,[dict(op='receive',message_id=message['message_id']),dict(op='recall',query='Synthetic mailbox memory')],no_network=True)
            self.assertTrue(all(row['ok'] for row in offline['results']),offline)
        self.assertGreaterEqual(sum(v['completed'] for v in self.cold_results),1,self.cold_results)
        self.assertTrue(any(not v['completed'] for v in self.cold_results),self.cold_results)

    def inspect_received_registration(self,h,registration,configured):
        f=self.delivery_fixture
        message=json.loads(self.original_envelope)['payload']['context']['message_id']
        with f.b._network() as network:
            delivery=network._delivery();row=delivery._inbox(message)
            self.assertEqual(bytes(row['envelope']),self.original_envelope)
            self.assertEqual(row['phase'],'saved');self.assertIsNotNone(row['receipt'])
        # Native reopens the imported Memory and saved message with zero network.
        read=self.native(f.b,[dict(op='receive',message_id=message),
            dict(op='recall',query='Synthetic mailbox memory')],no_network=True)['results']
        self.assertTrue(all(value['ok'] for value in read),read)
        self.assertTrue(any(hit['text']=='Synthetic mailbox memory: consult current evidence before reuse.'
                            for hit in read[1]['result']['hits']))
        if getattr(self,'native_recipient',False):self.cold_load(h,registration)
        # Fixture's existing explicit ACK authority carries the endpoint receipt
        # independently; original send identity/envelope/session stay unchanged.
        registered_fixtures.RegisteredReplicaTests.inspect_received_registration(self,h,registration,configured)
        # Removing a selection cannot erase the authenticated denial. A direct
        # retry after client restart must stop before any repair proof HTTP.
        from memory_vault_open_transport import OpenHTTPTransport
        with patch.object(OpenHTTPTransport,'request_repair',side_effect=AssertionError('retained revoked authority attempted repair HTTP')):
            refused=f.b.handle(dict(op='connect',invitation=dict(registration,action='receive_replica')))
        self.assertFalse(refused['ok'],refused)
        self.assertEqual(refused['error']['code'],'repair_authority_revoked')
        if getattr(self,'native_recipient',False):
            denied=self.native(f.b,[dict(op='connect',invitation=dict(registration,action='receive_replica'))],no_network=True)['results'][0]
            self.assertFalse(denied['ok'],denied)
            self.assertEqual(denied['error']['code'],'repair_authority_revoked')
        self.closure_evidence=dict(message_id=message,envelope_sha256=h.envelope_ref['raw_sha256'],
            copied_ciphertext_bytes=h.envelope_ref['size'],recipient_saved=True,native_offline_recall=True,
            retained_revocation_code=refused['error']['code'],revoked_repair_http_calls=0)
        self.closure_evidence['recipient_runtime']='native' if getattr(self,'native_recipient',False) else 'python'
        if hasattr(self,'cold_results'):self.closure_evidence['cold_known_message_load']=self.cold_results

    def test_native_send_python_replica_receive_native_offline_reuse_and_independent_receipt(self):
        self.with_independent_return=True
        feed_fixtures.MailboxFeedCopyTests.http_roundtrip(self,message=True,commands=True,agent=True,registered=True)
        f=self.delivery_fixture
        confirmed=self.native(f.a,[f.ack_original_send_request],no_network=True)['results'][0]
        self.assertTrue(confirmed['ok'],confirmed)
        self.assertTrue(confirmed['result']['endpoint_validated'])
        self.assertEqual(confirmed['result']['state'],'validated_saved')
        self.assertEqual(confirmed['result']['message_id'],self.closure_evidence['message_id'])
        print(json.dumps(dict(synthetic_replica_closure=self.closure_evidence,
            original_send_native_confirmed=True,frozen_send_replay_network_calls=0)))

    def test_native_recipient_verifies_full_replica_proof_after_original_source_loss(self):
        self.native_recipient=True
        self.test_native_send_python_replica_receive_native_offline_reuse_and_independent_receipt()


if __name__=='__main__':unittest.main()
