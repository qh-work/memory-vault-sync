"""Directory publication followed by native confirmation of a real Agent send."""
import copy
import hashlib
import json
from pathlib import Path
import unittest
import threading
from memory_vault_open_node import OpenHTTPServer,OpenParticipant
from memory_vault import canonical_bytes
from memory_vault_network_crypto import EncryptionIdentity,b64url
from memory_vault_storage import atomic_write
from memory_vault_open_client import ACK_CONNECT_SCHEMA
from memory_vault_open_repair_index_prepare_admin import export_plan,sign_consent,assemble_plan,EXPORT_SCHEMA
from memory_vault_open_repair_index_admin import publish_index
from tests import test_open_delivery_http as fixtures
from tests import test_open_ack_typescript_agent as native_fixture
from tests.test_open_node import HTTPNodes
import memory_vault_open_repair_state as repair_state

class NativeDiscoveredSendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):native_fixture.NativeAckAgentTests.setUpClass.__func__(cls)
    native=native_fixture.NativeAckAgentTests.native

    def observe_source(self,host):
        host.stop(0);config=json.loads(host.configs[0].read_bytes())
        from memory_vault_trust import Identity
        participant=OpenParticipant(Identity.load(Path(config['identity_path'])),Path(config['state_directory']),
            seeds=config['seeds'],descriptor=config['node'],encryption_identity=EncryptionIdentity.load(Path(config['encryption_key_path'])),
            allow_loopback=True,index_policy=config['index_policy'],provider_policy=config['provider_policy'],repair_policy=config['repair_policy'])
        self.addCleanup(participant.close);self.source_participant=participant;self.source_failures=[];original=participant.handle_repair
        def checked(raw):
            try:return original(raw)
            except Exception as error:
                import traceback
                detail=dict(code=getattr(error,'code',type(error).__name__),kind=json.loads(raw).get('payload',{}).get('kind'),
                    frames=[dict(name=f.name,line=f.lineno) for f in traceback.extract_tb(error.__traceback__)[-4:]])
                with participant.state.db() as db:
                    detail['usage']=[dict(r) for r in db.execute('SELECT requests,signatures,proof_bytes,replays FROM open_repair_bootstrap_usage')]
                    detail['pending']=db.execute('SELECT coalesce(sum(signature_allowance),0) FROM open_repair_bootstrap_work WHERE signature_checks IS NULL').fetchone()[0]
                self.source_failures.append(detail);raise
        participant.handle_repair=checked
        server=OpenHTTPServer(('127.0.0.1',config['listen_port']),participant);self.addCleanup(server.server_close)
        thread=threading.Thread(target=server.serve_forever,kwargs=dict(poll_interval=.02),daemon=True);thread.start()
        self.addCleanup(lambda:(server.shutdown(),thread.join(timeout=3)))

    def publish_directory(self,h,invitation):
        self.observe_source(h.ack_host)
        directory=HTTPNodes(h.root/'ack_directory',1);self.addCleanup(directory.close);directory.stop(0)
        encryption=EncryptionIdentity.generate();key=h.root/'ack_directory/encryption.json';encryption.save(key)
        config=json.loads(directory.configs[0].read_bytes());config.update(encryption_key_path=str(key),provider_policy=dict(enabled=True),
            repair_policy=dict(enabled=True,limit_policy=repair_state.INDEX_WORKFLOW_LIMITS))
        atomic_write(directory.configs[0],canonical_bytes(config),replace=True)
        participant=OpenParticipant(directory.identities[0],Path(config['state_directory']),seeds=[],descriptor=directory.nodes[0],
            encryption_identity=encryption,allow_loopback=True,index_policy=config['index_policy'],
            provider_policy=config['provider_policy'],repair_policy=config['repair_policy'])
        self.addCleanup(participant.close)
        failures=[];handle=participant.handle_repair
        def checked(raw):
            try:return handle(raw)
            except Exception as error:
                failures.append(getattr(error,'code',type(error).__name__));raise
        participant.handle_repair=checked
        server=OpenHTTPServer(('127.0.0.1',config['listen_port']),participant);self.addCleanup(server.server_close)
        thread=threading.Thread(target=server.serve_forever,kwargs=dict(poll_interval=.02),daemon=True);thread.start()
        self.addCleanup(lambda:(server.shutdown(),thread.join(timeout=3)))
        keys=dict(signing_key=directory.identities[0].public_descriptor(),encryption_key=encryption.public_descriptor())
        request=invitation['request'];root=json.loads(request['root_entry']['raw'])['payload']
        raw=canonical_bytes(directory.nodes[0]);digest=hashlib.sha256(raw).hexdigest()
        node=dict(raw_base64url=b64url(raw),ref=dict(namespace='meta',key=digest,raw_sha256=digest,size=len(raw)))
        folder=h.root/'index_preparation';folder.mkdir(mode=0o700)
        def write(name,value):
            path=folder/name;atomic_write(path,canonical_bytes(value),replace=False);return path
        limits=dict(root['budget'],max_live_bytes=0,max_items=64,max_meta_bytes=524288)
        export=write('export.json',dict(schema_version=EXPORT_SCHEMA,resource_id=self.prepared['resource_id'],directory=keys,
            directory_node=node,allocation_id='synthetic_real_send_directory',job_id='synthetic_real_send_publication',
            budget_limits=limits,windows=root['windows']))
        plan=folder/'plan.json';export_plan(h.ack_host.configs[0],export,plan)
        with h.a._network() as network:
            owner_keys=dict(signing_key=network.identity.public_descriptor(),encryption_key=network.encryption.public_descriptor())
        expected=write('expected.json',dict(expected_ack_slot=request['expected_ack_slot'],
            expected_owner=owner_keys,
            expected_receipt_writer=request['expected_receipt_writer'],expected_message_id=request['expected_message_id'],
            expected_envelope_ref=request['expected_envelope_ref'],expected_source=request['expected_target'],
            source_storage_epoch=h.ack_host.nodes[0]['payload']['storage_epoch'],expected_directory=keys,
            directory_storage_epoch=directory.nodes[0]['payload']['storage_epoch']))
        owner=folder/'owner.json';recipient=folder/'recipient.json';publication=folder/'publication.json'
        sign_consent(Path(h.a.network_config),plan,expected,owner,variant='owner',renew_source_status=True)
        sign_consent(Path(h.b.network_config),plan,expected,recipient,variant='receipt_writer',renew_source_status=True)
        assemble_plan(plan,owner,recipient,expected,publication)
        try:published=publish_index(h.ack_host.configs[0],publication,folder/'published.json')
        except Exception:
            if failures:raise AssertionError('actual directory refusal: '+','.join(failures))
            raise
        self.assertEqual(published['state'],'advertised')
        request=copy.deepcopy(request);request.pop('target_node_entry')
        request.update(expected_directory_node=directory.nodes[0],expected_directory=keys,
            expected_source_epoch=h.ack_host.nodes[0]['payload']['storage_epoch'])
        return dict(schema_version=ACK_CONNECT_SCHEMA,action='recover_discovered_receipt',repair_profile='receipt-index',request=request)

    def test_directory_read_confirms_original_send_and_shared_memory_after_delivery_node_stops(self):
        h=fixtures.MailboxStagingHTTPTests('test_cold_mailbox_returns_independent_receipt');h.setUp();self.addCleanup(h.doCleanups);h.ack_repair_profile='receipt-index'
        original=h.call;confirmed=[]
        def dispatch(agent,**request):
            invitation=request.get('invitation',{})
            if invitation.get('schema_version')==ACK_CONNECT_SCHEMA and invitation.get('action')=='prepare':
                request=copy.deepcopy(request);request['invitation']['repair_profile']='receipt-index'
                result=original(agent,**request)
                if invitation['action']=='prepare':self.prepared=result
                return result
            if agent is h.a and invitation.get('action')=='recover_receipt':
                discovered=self.publish_directory(h,invitation);h.host.stop(0)
                result=self.native(h.a,[dict(op='connect',invitation=discovered)])
                response=result['results'][0];self.assertTrue(response['ok'],dict(response=response,calls=result['calls'],source_failures=self.source_failures))
                self.assertEqual(response['result']['state'],'validated_saved')
                # This complete workflow consumed the old signed 128-request
                # allowance before its final proof; new original grants fund it.
                self.assertEqual(json.loads(discovered['request']['bootstrap_entry']['raw'])['payload']['limits']['max_requests'],256)
                with self.source_participant.state.db() as db:
                    used=db.execute('SELECT requests FROM open_repair_bootstrap_usage').fetchone()[0]
                self.assertGreater(used,128);self.assertLessEqual(used,256)
                self.assertTrue(any(c['kind']=='requestRepair' for c in result['calls']))
                repeated=self.native(h.a,[h.ack_original_send_request],no_network=True)['results'][0]
                self.assertTrue(repeated['ok'],repeated);self.assertEqual(repeated['result']['state'],'validated_saved')
                confirmed.append(response['result']);return response['result']
            return original(agent,**request)
        h.call=dispatch
        h.test_cold_mailbox_returns_independent_receipt()
        self.assertEqual(len(confirmed),1)

if __name__=='__main__':unittest.main()
