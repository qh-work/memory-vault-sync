"""Real protected replica HTTP reads, with fresh synthetic identities only."""
import hashlib
import copy
import json
from pathlib import Path
import threading
import time
import unittest
from unittest.mock import patch

from memory_vault import MemoryError, canonical_bytes
from memory_vault_open_control import issue_node
from memory_vault_open_node import OpenHTTPServer, OpenParticipant
from memory_vault_open_repair_copy_service import ReplicaReadService
import memory_vault_open_repair_copy_authority as authority
import memory_vault_open_repair_probe as probe
import memory_vault_open_repair_proof as proof
import memory_vault_open_repair_wire as wire
from memory_vault_open_transport import OpenHTTPTransport
from tests import test_open_repair_copy_state as copy_fixture


class ReplicaReadHTTPTests(unittest.TestCase):
    def setUp(self):
        self.clock=patch('time.time',return_value=2_000_000_010);self.clock.start();self.addCleanup(self.clock.stop)
        self.h=copy_fixture.CopyReadTests();self.h.source_capacity=dict(max_meta_bytes=1048576,max_job_bytes=1048576,max_requests=4096)
        self.h.source_limits=dict(max_probe_bytes=8192,max_proof_bytes=1048576,max_signature_checks=4096)
        self.h.setUp();self.addCleanup(self.h.doCleanups)
        self.rid,self.consents,self.statuses=self.h.read_configuration()
        self.context=dict(expected_ack_slot=self.h.f['expected']['expected_ack_slot'],expected_owner=self.h.f['expected']['expected_owner'],
            expected_source=self.h.f['expected']['expected_target'],source_storage_epoch=self.h.f['expected']['target_storage_epoch'],
            expected_maintainer=self.h.base.keys)
        with patch('socket.getfqdn',return_value='localhost'):self.server=OpenHTTPServer(('127.0.0.1',0),None)
        self.addCleanup(self.server.server_close)
        self.base='http://127.0.0.1:'+str(self.server.server_port)
        state=self.h.destination.state
        self.descriptor=issue_node(state.identity,base_url=self.base,storage_epoch=state.node['payload']['storage_epoch'],
            roles=['directory','router'],revision=2,issued_at=2_000_000_005,expires_at=2_000_003_600)
        self.directory=Path(self.h.destination.temp.name);self.errors=[]
        for name in ('network.sqlite3','network.sqlite3-wal','network.sqlite3-shm'):
            path=self.directory/name
            if path.exists():path.chmod(0o600)
        self.participant=self.make_participant()
        with self.participant.state.db() as db:
            service=ReplicaReadService(self.participant._repair_service(db).state);service.initialize()
            self.assertEqual(service.configure(self.rid,context=self.context,consents=self.consents,current_statuses=self.statuses)['state'],'configured')
        self.start();self.addCleanup(self.stop)
        self.transport=OpenHTTPTransport(allow_loopback=True);self.addCleanup(self.transport.close)
        self.policy=self.h.destination.state.policy
        self.bootstrap=self.h.f['entries']['bootstrap']
        import json
        self.grant=json.loads(self.bootstrap['raw'])['payload']
        self.expected=dict(expected_subject=self.context['expected_owner'],expected_target=state.target,
            target_storage_epoch=state.node['payload']['storage_epoch'],bootstrap_grant_sha256=self.bootstrap['ref']['raw_sha256'],
            selector=self.grant['selector'],at=2_000_000_010,policy=self.policy)

    def make_participant(self):
        state=self.h.destination.state
        participant=OpenParticipant(state.identity,self.directory,seeds=[],descriptor=self.descriptor,
            encryption_identity=state.encryption_identity,allow_loopback=True,
            repair_policy=dict(enabled=True,limit_policy=self.h.f['expected']['limit_policy']))
        handle=participant.handle_repair
        def observed(raw):
            try:return handle(raw)
            except Exception as error:
                self.errors.append(getattr(error,'code',type(error).__name__));raise
        participant.handle_repair=observed
        return participant

    def start(self):
        self.server.participant=self.participant
        self.thread=threading.Thread(target=self.server.serve_forever,kwargs=dict(poll_interval=.02),daemon=True);self.thread.start()

    def stop(self):
        self.server.shutdown();self.server.server_close();self.thread.join(3);self.participant.close()

    def restart(self):
        address=self.server.server_address;self.stop();self.participant=self.make_participant()
        with patch('socket.getfqdn',return_value='localhost'):self.server=OpenHTTPServer(address,self.participant)
        self.start()

    def send(self,raw,child=False):
        try:return self.transport.request_repair(self.base,raw,child=child,deadline=time.monotonic()+15)
        except MemoryError as error:raise AssertionError(self.errors) from error

    def entry(self,raw):
        digest=hashlib.sha256(raw).hexdigest()
        return dict(raw=raw,ref=dict(namespace='meta',key=digest,raw_sha256=digest,size=len(raw)))

    def handshake(self,restart=False):
        owner=self.h.f['signers']['owner']
        pending=probe.make_bootstrap_probe(owner,**self.expected,expires_at=2_000_000_060,budget=wire.RepairBudget(self.policy))
        challenge=self.entry(self.send(pending.original.raw))
        if restart:self.restart()
        answer=probe.solve_bootstrap_challenge(dict(raw=pending.original.raw,ref=pending.original.ref.as_dict()),challenge,
            signer=owner,encryption_identity=self.h.f['encryption']['owner'],target_nonce=pending.nonce,
            expires_at=2_000_000_060,**self.expected,budget=wire.RepairBudget(self.policy))
        raw=self.send(answer.raw)
        checked=proof.verify_bootstrap_proof_response(raw,expected_subject=self.expected['expected_subject'],expected_target=self.expected['expected_target'],
            target_storage_epoch=self.expected['target_storage_epoch'],selector=self.grant['selector'],bootstrap_grant_ref=self.bootstrap['ref'],
            probe_ref=pending.original.ref.as_dict(),challenge_ref=challenge['ref'],answer_ref=answer.ref.as_dict(),at=self.expected['at'],
            max_proof_items=self.grant['limits']['max_proof_items'],max_proof_bytes=self.grant['limits']['max_proof_bytes'],
            expected_source_state='replica_unbound',policy=self.policy,budget=wire.RepairBudget(self.policy))
        self.exchange=(pending,challenge,answer,raw)
        return checked

    def test_real_http_restart_and_complete_replica_reconstruction(self):
        checked=self.handshake(restart=True);self.restart();fetched={};roles={}
        for item in checked.manifest.value['children']:
            ref=wire.raw_ref(item['ref']);roles.setdefault(item['role'],[]).append(ref)
            if ref in fetched:continue
            chunks=[]
            for offset in range(0,ref.size,proof.MAX_CHILD_BYTES):
                count=min(proof.MAX_CHILD_BYTES,ref.size-offset)
                request=proof.make_bootstrap_child_request(self.h.f['signers']['owner'],checked,
                    subject=self.expected['expected_subject'],target=self.expected['expected_target'],at=self.expected['at'],
                    expires_at=2_000_000_060,child_index=item['index'],offset=offset,requested_bytes=count,
                    policy=self.policy,budget=wire.RepairBudget(self.policy))
                chunks.append(self.send(request.raw,child=True))
            raw=b''.join(chunks);self.assertEqual((len(raw),hashlib.sha256(raw).hexdigest()),(ref.size,ref.raw_sha256))
            fetched[ref]=dict(raw=raw,ref=ref.as_dict())
        budget=wire.RepairBudget(self.policy);resolver=wire.LocalRawResolver(self.policy,budget)
        for ref,entry in fetched.items():resolver.put(ref.namespace,ref.key,entry['raw'])
        replica=authority.verify_unbound_replica_event(fetched[roles['replica.manifest'][0]],resolver,fetched[roles['replica.custody'][0]],
            **self.context,expected_target=self.expected['expected_target'],target_storage_epoch=self.expected['target_storage_epoch'],
            limit_policy=self.h.f['expected']['limit_policy'],policy=self.policy,budget=budget)
        self.assertEqual(replica['source'].custody.raw,self.h.f['custody']['raw'])
        current=[fetched[ref] for ref in roles['current.status.replica_read']]
        consent={name:fetched[roles['return.'+name][0]] for name in ('owner','source','maintainer')}
        permission=authority._check_unbound_owner_return(replica,consent,expected_owner=self.context['expected_owner'],
            expected_source=self.context['expected_source'],expected_maintainer=self.context['expected_maintainer'],
            expected_target=self.expected['expected_target'],target_storage_epoch=self.expected['target_storage_epoch'],
            current_statuses=current,at=self.expected['at'],action='proof',policy=self.policy,budget=budget)
        self.assertIsNone(permission['denial_code']);self.assertEqual(self.errors,[])

    def child_request(self,checked):
        item=next(e for e in checked.manifest.value['children'] if e['role']=='replica.custody')
        return proof.make_bootstrap_child_request(self.h.f['signers']['owner'],checked,
            subject=self.expected['expected_subject'],target=self.expected['expected_target'],at=self.expected['at'],
            expires_at=2_000_000_060,child_index=item['index'],offset=0,requested_bytes=item['ref']['size'],
            policy=self.policy,budget=wire.RepairBudget(self.policy))

    def test_retained_revocation_prevents_old_handle_read_after_restart(self):
        from tests.open_repair_ack_fixtures import signed_entry
        checked=self.handshake();request=self.child_request(checked)
        statuses=copy.deepcopy(self.statuses);payload=json.loads(statuses[0]['raw'])['payload'];payload['revision']+=1
        for entry in payload['entries']:entry['status']='revoked'
        statuses[0]=signed_entry(payload,self.h.f['signers']['owner'],'synthetic_revoked_http_owner')
        with self.participant.state.db() as db:
            service=ReplicaReadService(self.participant._repair_service(db).state);service.initialize()
            with self.assertRaisesRegex(wire.RepairWireError,'repair_authority_revoked'):
                service.configure(self.rid,context=self.context,consents=self.consents,current_statuses=statuses)
        self.restart()
        with self.assertRaisesRegex(AssertionError,'repair_status_rollback|repair_authority_revoked'):
            self.send(request.raw,child=True)
        with self.participant.state.db() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM open_repair_bootstrap_requests').fetchone()[0],0)

    def test_signature_without_correct_encryption_answer_cannot_obtain_proof(self):
        owner=self.h.f['signers']['owner']
        pending=probe.make_bootstrap_probe(owner,**self.expected,expires_at=2_000_000_060,budget=wire.RepairBudget(self.policy))
        challenge=self.entry(self.send(pending.original.raw))
        answer=probe.solve_bootstrap_challenge(dict(raw=pending.original.raw,ref=pending.original.ref.as_dict()),challenge,
            signer=owner,encryption_identity=self.h.f['encryption']['owner'],target_nonce=pending.nonce,
            expires_at=2_000_000_060,**self.expected,budget=wire.RepairBudget(self.policy))
        payload=dict(answer.payload);payload['answer']='A'*43
        wrong=canonical_bytes(dict(payload=payload,proof=owner.sign_message(payload)))
        with self.assertRaisesRegex(AssertionError,'repair_invalid_nonce'):self.send(wrong)
        with self.participant.state.db() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM open_repair_bootstrap_handles').fetchone()[0],0)
        self.errors.clear()
        self.assertTrue(self.send(answer.raw))

    def test_exact_exchange_retry_and_child_replay_are_distinct(self):
        checked=self.handshake();pending,challenge,answer,response=self.exchange
        self.restart()
        self.assertEqual(self.send(pending.original.raw),challenge['raw'])
        self.assertEqual(self.send(answer.raw),response)
        request=self.child_request(checked)
        self.assertTrue(self.send(request.raw,child=True))
        with self.assertRaisesRegex(AssertionError,'repair_child_replay'):self.send(request.raw,child=True)
