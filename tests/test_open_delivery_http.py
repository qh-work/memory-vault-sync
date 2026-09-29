"""Approved delivery and denied authority over disposable, real loopback HTTP."""
import asyncio
from contextlib import contextmanager
import json
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest

from memory_vault import canonical_bytes
from memory_vault_agent import Agent
from memory_vault_client import ClientConfig
from memory_vault_open_contact_client import CONNECT_SCHEMA, OpenContactClient
from memory_vault_open_routing import LookupBudget
from memory_vault_storage import atomic_write
from memory_vault_trust import TrustStore
from tests.test_open_agent import configured_agent
from tests.test_open_node import HTTPNodes


@contextmanager
def repair_failure_diagnostics():
    """Keep the actual socket failure visible in synthetic Agent assertions."""
    import sys
    import time
    import traceback
    from unittest.mock import patch
    from memory_vault import MemoryError
    from memory_vault_open_transport import OpenHTTPTransport
    exchange=OpenHTTPTransport._exchange
    def observed(self,*args,**kwargs):
        started=time.monotonic()
        try:return exchange(self,*args,**kwargs)
        except MemoryError as error:
            if error.code=='open_network_unavailable':
                cause=error.__context__
                print('synthetic_repair_transport_failure',dict(seconds=time.monotonic()-started,
                    cause=type(cause).__name__,detail=str(cause)[:160],
                    frames=[(f.name,f.lineno) for f in traceback.extract_tb(cause.__traceback__)] if cause else []),file=sys.stderr)
            raise
    with patch.object(OpenHTTPTransport,'_exchange',new=observed):yield


class DeliveryHTTPTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="memory-delivery-http-synthetic-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.host = HTTPNodes(self.root, 1)
        self.addCleanup(self.host.close)
        self.host.stop(0)
        config = json.loads(self.host.configs[0].read_bytes())
        config.update(contact_policy={"enabled": True}, delivery_policy={"enabled": True})
        atomic_write(self.host.configs[0], canonical_bytes(config), replace=True)
        self.host.start(0)
        self.a, self.ai, *_ = configured_agent(SimpleNamespace(root=self.root / "a", nodes=self.host.nodes))
        self.b, self.bi, *_ = configured_agent(SimpleNamespace(root=self.root / "b", nodes=self.host.nodes))

    def call(self, agent, **request):
        result = agent.handle(request)
        self.assertTrue(result["ok"], result)
        return result["result"]

    def contact(self, agent, action, **values):
        return self.call(agent, op="connect", invitation={"schema_version": CONNECT_SCHEMA,
                         "action": action, **values})

    def request_contact(self):
        enabled = self.contact(self.b, "enable", node=self.host.nodes[0],
            allocation_id="synthetic_delivery_knock", max_pending=2, lease_seconds=3600, revision=1)
        self.call(self.a, op="connect", request_id="req_delivery_contact", invitation={
            "schema_version": CONNECT_SCHEMA, "action": "request", "recipient_key_id": self.bi.key_id})
        pending = self.contact(self.b, "poll", lease_id=enabled["lease_id"])
        return enabled, pending["requests"][0]["request_ref"]

    def decide(self, reference, decision):
        self.contact(self.b, "decide", request_ref=reference, decision=decision,
                     max_items=1, max_bytes=6291456)
        return self.contact(self.a, "result", request_id="req_delivery_contact")

    def stored_count(self):
        with sqlite3.connect(self.root / "node_0/transport/network.sqlite3") as db:
            return db.execute("SELECT count(*) FROM open_delivery_messages").fetchone()[0]

    def test_approved_memory_saved_receipt_and_restart_recall(self):
        # Author trust is a separate fixture choice, never inferred from consent.
        TrustStore(ClientConfig.load(self.b.client_config).trust_path).add(self.ai.public_descriptor())
        text = "Synthetic observation: service S was unavailable; check current evidence before reuse."
        memory = self.call(self.a, op="remember", request_id="req_delivery_memory",
                           kind="observation", text=text)
        _, reference = self.request_contact()
        self.assertTrue(self.decide(reference, "approved")["recipient_approved"])
        with sqlite3.connect(self.root / "node_0/transport/network.sqlite3") as db:
            lifecycle, signed = db.execute("SELECT state,decision FROM open_contact_requests").fetchone()
        self.assertEqual(lifecycle, "decided")
        self.assertEqual(json.loads(signed)["payload"]["decision"], "approved")
        request = {"op": "send", "request_id": "req_delivery_send", "recipients": [self.bi.key_id],
                   "text": "Synthetic selected memory", "memory_ids": [memory["memory_id"]]}
        sent = self.call(self.a, **request)
        self.assertTrue(sent["storage_accepted"])
        self.assertFalse(sent["endpoint_validated"])
        received = self.call(self.b, op="receive", limit=4)
        self.assertEqual(received["errors"], [])
        self.assertEqual(len(received["messages"]), 1)
        self.assertEqual(received["messages"][0]["state"], "validated_saved")
        self.assertIsNone(received["messages"][0]["text_memory_id"])
        self.host.stop(0)
        self.host.start(0)
        self.a = Agent(self.a.client_config, self.a.network_config)
        self.b = Agent(self.b.client_config, self.b.network_config)
        ack = self.call(self.a, **request)
        self.assertTrue(ack["endpoint_validated"])
        self.assertEqual(ack["message_id"], sent["message_id"])
        recalled = self.call(self.b, op="recall", memory_id=memory["memory_id"])
        self.assertEqual(recalled["hits"][0]["text"], text)
        changed = self.a.handle({**request, "text": "Changed under the same request ID"})
        self.assertFalse(changed["ok"])
        self.assertEqual(changed["error"]["code"], "network_request_id_conflict")
        self.assertEqual(self.stored_count(), 1)

    def test_older_pending_receipts_do_not_starve_later_receipt_after_restart(self):
        self._exercise_pending_receipt_rotation()

    def _exercise_pending_receipt_rotation(self, retry_receive=None):
        from unittest.mock import patch
        from memory_vault import MemoryError
        from memory_vault_open_delivery_client import OpenDeliveryClient
        _, reference = self.request_contact()
        self.contact(self.b, "decide", request_ref=reference, decision="approved",
                     max_items=5, max_bytes=6291456)
        self.assertTrue(self.contact(self.a, "result", request_id="req_delivery_contact")["recipient_approved"])
        requests = [{"op": "send", "request_id": "req_receipt_fairness_"+str(i),
                     "recipients": [self.bi.key_id], "text": "Synthetic receipt retry "+str(i)} for i in range(5)]
        sent = {self.call(self.a, **request)["message_id"]: request for request in requests}
        async def unavailable(*args, **kwargs):
            raise MemoryError("open_delivery_unavailable", retryable=True)
        with patch.object(OpenDeliveryClient, "_send_receipt", unavailable):
            self.call(self.b, op="receive", limit=4)
            self.call(self.b, op="receive", limit=4)
        with self.b._network() as network:
            directory = network.participant.state.directory
        with sqlite3.connect(directory / "network.sqlite3") as db:
            rows = db.execute("SELECT message_id,receipt_sent,phase FROM open_delivery_inbox ORDER BY created_at,message_id").fetchall()
        self.assertEqual(len(rows), 5)
        self.assertTrue(all(row[1:] == (0, "saved") for row in rows))
        blocked = {row[0] for row in rows[:4]}
        later = rows[4][0]
        original = OpenDeliveryClient._send_receipt
        async def selective(client, message_id, *args, **kwargs):
            if message_id in blocked:
                # An independent-return message may remain saved without a
                # direct receipt; an unavailable peer can remain pending too.
                if message_id == rows[0][0]:
                    return
                return await unavailable()
            return await original(client, message_id, *args, **kwargs)
        with patch.object(OpenDeliveryClient, "_send_receipt", selective):
            for _ in range(2):
                self.b = Agent(self.b.client_config, self.b.network_config)
                if retry_receive is None:
                    self.call(self.b, op="receive", limit=4)
                else:
                    retry_receive(self.b, sorted(blocked))
        with sqlite3.connect(directory / "network.sqlite3") as db:
            states = dict(db.execute("SELECT message_id,receipt_sent FROM open_delivery_inbox"))
        self.assertEqual(states[later], 1)
        self.assertTrue(all(states[key] == 0 for key in blocked))
        self.assertTrue(self.call(self.a, **sent[later])["endpoint_validated"])

    def test_pending_and_rejected_contact_cannot_store(self):
        _, reference = self.request_contact()
        request = {"op": "send", "request_id": "req_delivery_denied", "recipients": [self.bi.key_id],
                   "text": "Synthetic unapproved message"}
        for decision in (None, "rejected"):
            if decision is not None:
                self.assertFalse(self.decide(reference, decision)["recipient_approved"])
            denied = self.a.handle(request)
            self.assertFalse(denied["ok"])
            self.assertEqual(denied["error"]["code"], "open_contact_approval_required")
            self.assertEqual(self.stored_count(), 0)

    def test_policy_revoked_after_approval_cannot_store(self):
        enabled, reference = self.request_contact()
        self.assertTrue(self.decide(reference, "approved")["recipient_approved"])
        with self.b._network() as network:
            contact = OpenContactClient(network.participant, network.encryption)
            session = contact._load("policy", enabled["lease_id"])
            payload = {**session["policy"]["payload"], "revision": 2, "status": "revoked"}
            revoked = {"payload": payload, "proof": self.bi.sign_message(payload)}
            asyncio.run(contact.call(self.host.nodes[0], "policy.put",
                {"lease": session["lease"], "policy": revoked}, LookupBudget()))
        denied = self.a.handle({"op": "send", "request_id": "req_delivery_revoked",
                               "recipients": [self.bi.key_id], "text": "Synthetic revoked message"})
        self.assertFalse(denied["ok"])
        self.assertEqual(denied["error"]["code"], "open_delivery_revoked")
        self.assertEqual(self.stored_count(), 0)


if __name__ == "__main__":
    unittest.main()

class MailboxStagingHTTPTests(unittest.TestCase):
    def setUp(self):
        fixture=DeliveryHTTPTests("test_approved_memory_saved_receipt_and_restart_recall")
        fixture.setUp();self.addCleanup(fixture.doCleanups)
        for name in ("root","host","a","b","ai","bi","call","request_contact","decide"):
            setattr(self,name,getattr(fixture,name))

    def test_actual_delivery_stages_exact_ciphertext_under_mailbox_resources(self):
        import time
        import hashlib
        from memory_vault_network_crypto import EncryptionIdentity
        from memory_vault_open_repair_state import RepairAckState,DEFAULT_LIMITS,DEFAULT_POLICY
        from memory_vault_open_repair_mailbox_resources import RepairMailboxResources
        from memory_vault_open_repair_mailbox_activation import MailboxSlotActivation
        from memory_vault_open_repair_mailbox_root import MailboxRootActivation
        from memory_vault_open_repair_mailbox_source import MailboxRootSource,MailboxMessageStaging
        from memory_vault_open_repair_client import MailboxSetupBuilder,MailboxMessageDraftStore
        from memory_vault_open_delivery_state import DeliveryState
        from memory_vault_open_repair_wire import RepairBudget,RepairWireError
        import memory_vault_open_repair_status as status
        import memory_vault_open_repair_wire as wire
        from memory_vault_open_provider import issue_status
        from tests.test_open_repair_status import status_entry
        if self._testMethodName in ('test_ack_configuration_survives_mailbox_custody','test_ack_configuration_admitted_over_http','test_cold_mailbox_returns_independent_receipt'):
            from dataclasses import replace
            DEFAULT_POLICY=replace(DEFAULT_POLICY,max_signature_checks=128)
        limits=dict(DEFAULT_LIMITS,max_proof_bytes=524288)
        # Fund both exhaustive downloads and their bounded possession
        # renewals before signing any original resource or authority.
        exhaustive_feed=self._testMethodName in ('test_actual_delivery_stages_exact_ciphertext_under_mailbox_resources',
            'test_ack_configuration_survives_mailbox_custody')
        funded_feed=(exhaustive_feed or self._testMethodName=='test_sender_admits_message_over_http'
            or getattr(self,'ack_remote_admission',False))
        if funded_feed:
            limits.update(max_proof_bytes=1048576,max_proof_items=128,max_signature_checks=2048)
        if exhaustive_feed:limits.update(max_requests=128,max_replay_records=256)
        _,reference=self.request_contact()
        if self._testMethodName=='test_sender_admits_message_over_http' or getattr(self,'ack_remote_admission',False):
            self.call(self.b,op='connect',invitation=dict(schema_version=CONNECT_SCHEMA,action='decide',request_ref=reference,decision='approved',max_items=2,max_bytes=6291456))
            self.call(self.a,op='connect',invitation=dict(schema_version=CONNECT_SCHEMA,action='result',request_id='req_delivery_contact'))
        else:self.decide(reference,'approved')
        selected={}
        if self._testMethodName=='test_remote_feed_client_recovers_complete_index' or getattr(self,'ack_cold_return',False):
            TrustStore(ClientConfig.load(self.b.client_config).trust_path).add(self.ai.public_descriptor())
            shared_memory=self.call(self.a,op='remember',request_id='req_mailbox_memory',kind='observation',
                text='Synthetic mailbox memory: consult current evidence before reuse.')
            selected['memory_ids']=[shared_memory['memory_id']]
        sent=self.call(self.a,op='send',request_id='req_mailbox_stage',recipients=[self.bi.key_id],text='Synthetic mailbox staging message',**selected)
        self.assertTrue(sent['storage_accepted'])
        if self._testMethodName=='test_sender_admits_message_over_http' or getattr(self,'ack_remote_admission',False):
            self.second_mailbox_message=self.call(self.a,op='send',request_id='req_mailbox_stage_second',recipients=[self.bi.key_id],text='Synthetic second mailbox message')
        with self.a._network() as network:
            sender_encryption=network.encryption
            with network.participant.state.db() as sender_db:
                row=sender_db.execute('SELECT envelope,session FROM open_delivery_outbox WHERE request_id=?',('req_mailbox_stage',)).fetchone()
                envelope=bytes(row[0]);session=json.loads(bytes(row[1]))
        with self.b._network() as network:owner_encryption=network.encryption
        self.host.stop(0)
        db=sqlite3.connect(self.root/'node_0/transport/network.sqlite3');db.row_factory=sqlite3.Row;self.addCleanup(db.close)
        source=RepairAckState(db,self.host.identities[0],self.host.nodes[0],encryption_identity=EncryptionIdentity.generate(),limit_policy=limits,policy=DEFAULT_POLICY)
        resources=RepairMailboxResources(source);activation=MailboxRootActivation(resources);activation.initialize()
        now=int(time.time());owner=dict(signing_key=self.bi.public_descriptor(),encryption_key=owner_encryption.public_descriptor())
        dual=lambda value:dict(signing_key_id=value['signing_key']['key_id'],encryption_key_id=value['encryption_key']['key_id'])
        root=dict(owner=dual(owner),root_kind='mailbox',anchor_ref=dict(namespace='anchor',key='b'*64),owner_epoch='synthetic_owner',root_id='synthetic_mailbox')
        slot=dict(root_key=root,slot_id='synthetic_slot',writer=dual(source.target),writer_storage_epoch=source.node['payload']['storage_epoch'])
        caps=dict(max_live_bytes=131072,max_meta_bytes=2097152,max_items=64,max_requests=512,max_pending=8,max_replay_records=128,max_jobs=16,max_job_bytes=524288)
        if funded_feed:
            caps.update(max_items=128,max_job_bytes=1048576,max_requests=2048,max_meta_bytes=4194304)
        if exhaustive_feed:caps.update(max_replay_records=256)
        # This workflow deliberately performs many successful and rejected
        # operations before its final revocation assertions. Give synthetic
        # authorities enough lifetime for slow runners; keep the protocol's
        # short allocation reservation and possession-handle deadlines intact.
        windows={name:now+600 for name in ('admit_until','read_until','copy_until','publish_until','retain_until')}
        plan=dict(root_key=root,slot_key=slot,sender=dict(signing_key_id=self.ai.key_id,encryption_key_id=sender_encryption.key_id),target=source.target,
            budget=caps,windows=windows,limits=limits,max_appends=16,max_live_items=16)
        builder=MailboxSetupBuilder(self.bi,owner_encryption,plan)
        requests=builder.allocation_requests(at=now,expires_at=now+240)
        offers=resources.allocate_initial(list(requests.values()),expected_owner=owner)
        now=int(time.time())
        slot_entries=builder.slot_documents(requests,offers,at=now,expires_at=windows['retain_until'])
        slot_result=activation.slots.activate(slot_entries,expected_slot=slot)
        now=int(time.time())
        root_entries=builder.root_documents(requests,offers,slot_entries,slot_result,at=now,expires_at=windows['retain_until'])
        active=activation.activate(root_entries,expected_root=root,slot_keys=[slot]);rid=json.loads(active['raw'])['payload']['resource']['resource_id']
        root_source=MailboxRootSource(activation);root_source.initialize()
        activation.observe_owner_status(rid,builder.initial_owner_status(slot_entries,root_entries,at=now,valid_until=now+400))
        root_source.observe_resources(rid,'synthetic_setup',valid_until=now+400);root_source.prepare_history(rid,'synthetic_setup')
        root_source.finalize_root(rid,read_until=now+400,retain_until=now+400)
        docs={name:session[name] for name in ('node','policy','request','decision')}
        docs.update(knock_lease=session['lease'],grant=session['decision']['payload']['grant'],delivery_lease=session['decision']['payload']['grant']['payload']['resource_lease'])
        contact={name:canonical_bytes(value) for name,value in docs.items()}
        from memory_vault_open_repair_client import MailboxDestinationStore
        with self.b._network() as owner_network:
            with owner_network.participant.state.db() as owner_db:
                destination_bundle=MailboxDestinationStore(owner_db,self.bi,owner_encryption).prepare(plan,slot_entries,contact,
                    at=now,expires_at=now+240,status_revision=2,status_until=now+400)
        # A restarted client must return the original signed issuance, even
        # when the retry clock differs. Reusing its revision cannot resign.
        with self.b._network() as owner_network:
            with owner_network.participant.state.db() as owner_db:
                store=MailboxDestinationStore(owner_db,self.bi,owner_encryption)
                self.assertEqual(store.prepare(plan,slot_entries,contact,at=now+1,expires_at=now+240,status_revision=2,status_until=now+400),destination_bundle)
                with self.assertRaisesRegex(RepairWireError,'repair_destination_conflict'):
                    store.prepare(plan,slot_entries,contact,at=now+1,expires_at=now+59,status_revision=2,status_until=now+400)
                with self.assertRaisesRegex(RepairWireError,'repair_destination_revision_rollback'):
                    store.prepare(plan,slot_entries,contact,at=now+1,expires_at=now+240,status_revision=1,status_until=now+400)
        destination=destination_bundle['destination']
        if self._testMethodName=='test_sender_admits_message_over_http' or getattr(self,'ack_remote_admission',False):
            from memory_vault_open_client import MAILBOX_CONNECT_SCHEMA
            import base64
            from unittest.mock import patch
            node_raw=canonical_bytes(source.node);node_digest=hashlib.sha256(node_raw).hexdigest()
            registered=self.call(self.b,op='connect',invitation=dict(schema_version=MAILBOX_CONNECT_SCHEMA,action='register',
                base_url=source.node['payload']['base_url'],limit_policy=limits,expected_slot=slot,
                expected_sender=dict(signing_key=self.ai.public_descriptor(),encryption_key=sender_encryption.public_descriptor()),
                expected_target=source.target,target_node_entry=dict(raw=node_raw.decode(),ref=dict(namespace='meta',key=node_digest,raw_sha256=node_digest,size=len(node_raw))),
                slot_entries={name:dict(raw=slot_entries[name]['raw'].decode(),ref=slot_entries[name]['ref']) for name in ('slot','read','maintenance','bootstrap')}))
            authorize=dict(schema_version=MAILBOX_CONNECT_SCHEMA,action='authorize',receiver_id=registered['receiver_id'],
                contact_request_ref=reference,expires_at=now+240,status_revision=3,status_until=now+400)
            chunks=[]
            with patch('memory_vault_open_transport.OpenHTTPTransport.request_repair',side_effect=AssertionError('authorization used network')):
                while True:
                    page=self.call(self.b,op='connect',invitation=authorize)
                    self.assertFalse(page['network_accessed']);self.assertFalse(page['source_rechecked'])
                    chunks.append(base64.b64decode(page['authorization_chunk'],validate=True))
                    if page['next_cursor'] is None:break
                    authorize['cursor']=page['next_cursor']
            exported=b''.join(chunks)
            self.assertEqual(hashlib.sha256(exported).hexdigest(),page['authorization_sha256'])
            authorized=json.loads(exported)
            self.sender_authorization=authorized
            destination=dict(raw=authorized['destination_entry']['raw'].encode(),ref=authorized['destination_entry']['ref'])
            owner_original=dict(raw=authorized['owner_status_entry']['raw'].encode(),ref=authorized['owner_status_entry']['ref'])
            self.assertEqual(json.loads(owner_original['raw'])['payload']['revision'],3)
            destination_bundle=dict(destination=destination,owner_status=owner_original)
            prepared=self.call(self.a,op='connect',invitation=dict(schema_version=MAILBOX_CONNECT_SCHEMA,action='prepare',
                message_id=sent['message_id'],slot_entries={name:dict(raw=slot_entries[name]['raw'].decode(),ref=slot_entries[name]['ref']) for name in ('slot','read','maintenance')},
                destination_entry=dict(raw=destination['raw'].decode(),ref=destination['ref']),attempt_until=now+240,consent_until=now+400,
                **({'ack_request_id':'req_mailbox_stage'} if hasattr(self,'ack_configuration') else {})))
            self.assertEqual(prepared['state'],'mailbox_draft_saved')
            self.assertFalse(prepared['network_accessed'])
        if hasattr(self,'ack_configuration'):
            from memory_vault_open_client import MAILBOX_CONNECT_SCHEMA
            result=self.call(self.a,op='connect',invitation=dict(schema_version=MAILBOX_CONNECT_SCHEMA,action='prepare',
                message_id=sent['message_id'],ack_request_id='req_mailbox_stage',
                slot_entries={name:dict(raw=slot_entries[name]['raw'].decode(),ref=slot_entries[name]['ref']) for name in ('slot','read','maintenance')},
                destination_entry=dict(raw=destination['raw'].decode(),ref=destination['ref']),attempt_until=now+240,consent_until=now+400))
            self.assertEqual(result['state'],'mailbox_draft_saved')
        with self.a._network() as network:
            with network.participant.state.db() as sender_db:
                draft=MailboxMessageDraftStore(sender_db,self.ai,sender_encryption).prepare(envelope,recipient=owner,
                    slot_entries={name:slot_entries[name] for name in ('slot','read','maintenance')},destination_entry=destination,
                    contact_originals=contact,at=now,attempt_until=now+240,consent_until=now+400,ack_configuration=getattr(self,'ack_configuration',None))
        owner_status=destination_bundle['owner_status']
        scoped=json.loads(owner_status['raw'])['payload']['entries']
        delivery=DeliveryState(db,self.host.identities[0],self.host.nodes[0],enabled=True)
        staging=MailboxMessageStaging(resources,delivery);staging.initialize()
        raw=wire.build_new_wire(draft['originals'],DEFAULT_POLICY,RepairBudget(DEFAULT_POLICY)).raw
        if self._testMethodName=='test_sender_admits_message_over_http' or getattr(self,'ack_remote_admission',False):
            self._remote_message_admission(source,owner_status,slot,slot_entries,owner,sender_encryption,sent,now,limits,envelope)
            return
        first=staging.stage_delivered(raw,owner_status)
        self.assertEqual(first['state'],'staged');self.assertEqual(staging.stage_delivered(raw,owner_status),first)
        encryption=source.encryption_identity
        db.close();db=sqlite3.connect(self.root/'node_0/transport/network.sqlite3');db.row_factory=sqlite3.Row;self.addCleanup(db.close)
        source=RepairAckState(db,self.host.identities[0],self.host.nodes[0],encryption_identity=encryption,limit_policy=limits,policy=DEFAULT_POLICY)
        resources=RepairMailboxResources(source)
        staging=MailboxMessageStaging(resources,DeliveryState(db,self.host.identities[0],self.host.nodes[0],enabled=True));staging.initialize()
        self.assertEqual(staging.stage_delivered(raw,owner_status),first)
        stored=db.execute('SELECT envelope,phase FROM open_mailbox_message_staging').fetchone()
        self.assertEqual(bytes(stored[0]),envelope);self.assertEqual(stored[1],'pending')
        self.assertEqual(db.execute('SELECT count(*) FROM open_mailbox_message_staging').fetchone()[0],1)
        saved=staging.prepare_member_history(self.ai.key_id,sent['message_id'])
        self.assertEqual(staging.prepare_member_history(self.ai.key_id,sent['message_id']),saved)
        import memory_vault_open_repair_history as history
        budget=RepairBudget(DEFAULT_POLICY);resolver=wire.LocalRawResolver(DEFAULT_POLICY,budget)
        resolver.put('meta',saved['pack']['ref']['key'],saved['pack']['raw'])
        resolved=history.resolve_historical_inputs(saved['manifest']['raw'],resolver,DEFAULT_POLICY,budget)
        self.assertEqual(len(resolved.roles),35 if hasattr(self,'ack_configuration') else 29)
        self.assertEqual(next(value.original.raw for value in resolved.roles if value.role=='delivery.attempt'),draft['attempt']['raw'])
        self.assertNotIn('mailbox.root_authority',{value.role for value in resolved.roles})
        self.assertEqual(resolved.manifest.value['envelope_ref']['raw_sha256'],hashlib.sha256(envelope).hexdigest())
        from unittest.mock import patch
        sign=source._sign
        def interrupted(payload,*args,**kwargs):
            if payload['kind']=='message.custody':raise RuntimeError('synthetic interruption before custody')
            return sign(payload,*args,**kwargs)
        with patch.object(source,'_sign',side_effect=interrupted):
            with self.assertRaisesRegex(RuntimeError,'synthetic interruption'):
                staging.commit_member(self.ai.key_id,sent['message_id'],object_until=now+360,enum_until=now+360)
        self.assertEqual(db.execute('SELECT phase FROM open_mailbox_message_staging').fetchone()[0],'pending')
        admitted=staging.commit_member(self.ai.key_id,sent['message_id'],object_until=now+360,enum_until=now+360)
        self.assertEqual(staging.commit_member(self.ai.key_id,sent['message_id'],object_until=now+360,enum_until=now+360),admitted)
        from memory_vault_network_crypto import decrypt_bytes
        core=json.loads(admitted['core']['raw'])['payload']
        self.assertEqual(core['envelope_ref'],resolved.manifest.value['envelope_ref'])
        context=dict(schema_version=core['schema_version'],kind='admission.sealed_core',slot_key=slot,sequence=0,
            plaintext_sha256=admitted['core']['ref']['raw_sha256'],plaintext_size=len(admitted['core']['raw']))
        self.assertEqual(decrypt_bytes(admitted['sealed_core']['raw'],owner_encryption,context=context),admitted['core']['raw'])
        page=json.loads(admitted['repair_page']['raw'])
        private=wire.build_new_wire(dict(schema_version=core['schema_version'],kind='range.private_page',slot_key=slot,
            start=0,end=1,entries=page['entries']),DEFAULT_POLICY,RepairBudget(DEFAULT_POLICY)).raw
        context=dict(schema_version=core['schema_version'],kind='range.sealed_page',slot_key=slot,start=0,end=1,
            plaintext_sha256=hashlib.sha256(private).hexdigest(),plaintext_size=len(private))
        self.assertEqual(decrypt_bytes(admitted['sealed_page']['raw'],owner_encryption,context=context),private)
        self.assertEqual(json.loads(admitted['head']['raw'])['payload']['count'],1)
        self.assertEqual(db.execute('SELECT phase FROM open_mailbox_message_staging').fetchone()[0],'committed')
        self.assertEqual(db.execute('SELECT count(*) FROM open_mailbox_admissions').fetchone()[0],1)
        from memory_vault_open_repair_client import read_mailbox_index
        reads=[]
        def read_original(reference):
            reads.append(reference['key'])
            row=db.execute('SELECT raw FROM open_mailbox_admission_objects WHERE key=?',(reference['key'],)).fetchone()
            if row is None:raise RepairWireError('repair_original_missing')
            return bytes(row[0])
        args=dict(expected_slot=slot,expected_signing_key=self.host.identities[0].public_descriptor(),
            encryption_identity=owner_encryption,read_original=read_original,at=int(time.time()),max_messages=16)
        members=read_mailbox_index(admitted['head'],admitted['checkpoint'],**args)
        self.assertEqual(len(members),1)
        self.assertEqual(members[0]['admission_link_ref'],admitted['link']['ref'])
        self.assertEqual(len(reads),3)
        from memory_vault_open_repair_client import read_mailbox_admission
        from memory_vault_open_delivery import decrypt_envelope
        def read_member_original(reference):
            if reference==saved['manifest']['ref']:return saved['manifest']['raw']
            if reference==saved['pack']['ref']:return saved['pack']['raw']
            if reference==resolved.manifest.value['envelope_ref']:
                return bytes(db.execute('SELECT envelope FROM open_mailbox_message_staging').fetchone()[0])
            return read_original(reference)
        member_args=dict(expected_slot=slot,expected_signing_key=self.host.identities[0].public_descriptor(),
            expected_owner=owner,expected_sender=dict(signing_key=self.ai.public_descriptor(),encryption_key=sender_encryption.public_descriptor()),
            expected_target=source.target,limit_policy=limits,
            current_statuses=list({value.original.ref.raw_sha256:dict(raw=value.original.raw,ref=value.original.ref.as_dict())
                for value in resolved.roles if value.role.startswith('historical.status.') and not value.role.startswith('historical.status.ack_')}.values()),
            encryption_identity=owner_encryption,read_original=read_member_original,at=int(time.time()))
        recovered=read_mailbox_admission(members[0],**member_args)
        self.assertEqual(recovered['envelope'],envelope)
        plain=decrypt_envelope(recovered['envelope'],encryption_identity=owner_encryption,
            sender_signing_key=self.ai.public_descriptor(),sender_encryption_key=sender_encryption.public_descriptor(),
            recipient_signing_key=self.bi.public_descriptor(),recipient_encryption_key=owner_encryption.public_descriptor())
        self.assertIn(b'Synthetic mailbox staging message',plain)
        self.assertEqual(len(recovered['history'].roles),35 if hasattr(self,'ack_configuration') else 29)
        if hasattr(self,'ack_configuration'):
            retained={value.role:value.original for value in recovered['history'].roles}
            for role,entry in self.ack_configuration.items():self.assertEqual(retained[role].raw,entry['raw'])
            self.assertNotIn('ack.read_grant',retained)
            self.assertIsNotNone(recovered['setup']['ack_configuration'])
        self.assertEqual(len(recovered['setup']['statuses']),8)
        held_page=admitted['sealed_page'];ref=held_page['ref']
        metadata_before=db.execute('SELECT sum(metadata_bytes) FROM open_repair_mailbox_resources').fetchone()[0]
        db.execute('DELETE FROM open_mailbox_admission_objects WHERE key=?',(ref['key'],));db.commit()
        with self.assertRaisesRegex(RepairWireError,'repair_original_missing'):
            staging.prepare_feed_history(slot)
        self.assertEqual(db.execute('SELECT sum(metadata_bytes) FROM open_repair_mailbox_resources').fetchone()[0],metadata_before)
        db.execute('INSERT INTO open_mailbox_admission_objects VALUES(?,?,?,?)',(ref['key'],ref['raw_sha256'],ref['size'],held_page['raw']));db.commit()
        feed_history=staging.prepare_feed_history(slot)
        self.assertEqual(staging.prepare_feed_history(slot),feed_history)
        budget=RepairBudget(DEFAULT_POLICY);resolver=wire.LocalRawResolver(DEFAULT_POLICY,budget)
        for value in (saved['pack'],feed_history['pack']):resolver.put('meta',value['ref']['key'],value['raw'])
        feed_inputs=history.resolve_historical_inputs(feed_history['manifest']['raw'],resolver,DEFAULT_POLICY,budget)
        self.assertEqual(feed_inputs.manifest.value['covered_interval'],dict(start=0,end=1))
        self.assertEqual(len(feed_inputs.predecessors),1)
        self.assertEqual(feed_inputs.manifest.value['members'][0]['source_custody_ref'],admitted['custody']['ref'])
        from memory_vault_open_repair_mailbox_activation import verify_mailbox_feed_history_inputs
        feed_verified=verify_mailbox_feed_history_inputs(feed_inputs,expected_slot=slot,expected_owner=owner,
            expected_sender=member_args['expected_sender'],expected_target=source.target,at=int(time.time()),
            limit_policy=limits,policy=DEFAULT_POLICY,budget=RepairBudget(DEFAULT_POLICY))
        self.assertEqual(feed_verified['head']['count'],1)
        def interrupted_feed(payload,*args,**kwargs):
            if payload['kind']=='feed.custody':raise RuntimeError('synthetic feed interruption')
            return sign(payload,*args,**kwargs)
        metadata_before=db.execute('SELECT sum(metadata_bytes) FROM open_repair_mailbox_resources').fetchone()[0]
        with patch.object(source,'_sign',side_effect=interrupted_feed):
            with self.assertRaisesRegex(RuntimeError,'synthetic feed interruption'):
                staging.finalize_feed(slot,admitted['head']['ref'],read_until=now+320,retain_until=now+360)
        self.assertEqual(db.execute('SELECT sum(metadata_bytes) FROM open_repair_mailbox_resources').fetchone()[0],metadata_before)
        feed_custody=staging.finalize_feed(slot,admitted['head']['ref'],read_until=now+320,retain_until=now+360)
        self.assertEqual(staging.finalize_feed(slot,admitted['head']['ref'],read_until=now+320,retain_until=now+360),feed_custody)
        payload=json.loads(feed_custody['raw'])['payload']
        self.assertEqual(payload['historical_manifest_ref'],feed_history['manifest']['ref'])
        self.assertEqual(payload['covered_interval'],dict(start=0,end=1))
        self.assertEqual(db.execute('SELECT count(*) FROM open_mailbox_feed_custody').fetchone()[0],1)
        inspect_snapshot = getattr(self, 'inspect_committed_mailbox', None)
        if inspect_snapshot is not None:
            inspect_snapshot(staging, slot, admitted['head']['ref'])
            return
        from memory_vault_open_repair_mailbox_activation import verify_mailbox_feed_source_event
        budget=RepairBudget(DEFAULT_POLICY);resolver=wire.LocalRawResolver(DEFAULT_POLICY,budget)
        for value in (saved['pack'],feed_history['pack']):resolver.put('meta',value['ref']['key'],value['raw'])
        verified_feed=verify_mailbox_feed_source_event(feed_history['manifest'],resolver,feed_custody,expected_slot=slot,
            expected_owner=owner,expected_sender=member_args['expected_sender'],expected_target=source.target,
            limit_policy=limits,policy=DEFAULT_POLICY,budget=budget)
        self.assertEqual(verified_feed['read_until'],now+320)
        import memory_vault_open_repair_probe as probe
        import memory_vault_open_repair_proof as proof
        from memory_vault_open_repair_mailbox_source import MailboxRecoveryService
        service=MailboxRecoveryService(MailboxRootSource(MailboxRootActivation(resources)),consumer='mailbox_feed');service.initialize()
        import threading
        from memory_vault_open_node import OpenParticipant,OpenHTTPServer
        from memory_vault_open_transport import OpenHTTPTransport
        participant=OpenParticipant(source.identity,self.root/'node_0/transport',seeds=[],descriptor=source.node,
            encryption_identity=source.encryption_identity,allow_loopback=True,repair_policy=dict(enabled=True,limit_policy=limits),
            contact_policy=dict(enabled=True),delivery_policy=dict(enabled=True))
        server_errors=[];handle_repair=participant.handle_repair
        def traced_repair(raw):
            try:return handle_repair(raw)
            except Exception as error:
                server_errors.append(getattr(error,'code',type(error).__name__));raise
        participant.handle_repair=traced_repair
        server=OpenHTTPServer(('127.0.0.1',0),participant)
        thread=threading.Thread(target=server.serve_forever,kwargs=dict(poll_interval=.02),daemon=True);thread.start()
        def close_feed_server():
            server.shutdown();server.server_close();thread.join(timeout=3);participant.close()
        self.addCleanup(close_feed_server)
        transport=OpenHTTPTransport(allow_loopback=True);self.addCleanup(transport.close)
        base='http://127.0.0.1:'+str(server.server_port)
        def feed_failure(error,before):
            current=server_errors[before:]
            failure=AssertionError('synthetic feed server errors: '+repr(current))
            # The CI reporter keeps only its fixed public protocol-code allowlist.
            if len(current)==1:failure.code=current[0]
            return failure
        class RemoteFeed:
            def challenge(self,packet):
                raw=transport.request_repair(base,packet['raw'],deadline=time.monotonic()+15)
                digest=hashlib.sha256(raw).hexdigest()
                return dict(raw=raw,ref=dict(namespace='meta',key=digest,raw_sha256=digest,size=len(raw)))
            def answer(self,packet):
                before=len(server_errors)
                try:return transport.request_repair(base,packet['raw'],deadline=time.monotonic()+15)
                except Exception as error:raise feed_failure(error,before) from error
            def child(self,packet):
                before=len(server_errors)
                try:return transport.request_repair(base,packet['raw'],child=True,deadline=time.monotonic()+15)
                except Exception as error:raise feed_failure(error,before) from error
        service=RemoteFeed()
        grant=json.loads(slot_entries['bootstrap']['raw'])['payload']
        def fresh_feed_proof():
            expected=dict(expected_subject=owner,expected_target=source.target,target_storage_epoch=slot['writer_storage_epoch'],
                bootstrap_grant_sha256=slot_entries['bootstrap']['ref']['raw_sha256'],selector=grant['selector'],at=int(time.time()),consumer='mailbox_feed')
            pending=probe.make_bootstrap_probe(self.bi,expires_at=expected['at']+55,**expected,policy=DEFAULT_POLICY,budget=RepairBudget(DEFAULT_POLICY))
            packet=dict(raw=pending.original.raw,ref=pending.original.ref.as_dict())
            challenge=service.challenge(packet)
            expected['at']=int(time.time())
            answer=probe.solve_bootstrap_challenge(packet,challenge,signer=self.bi,encryption_identity=owner_encryption,
                target_nonce=pending.nonce,expires_at=min(expected['at']+50,json.loads(challenge['raw'])['payload']['expires_at']),**expected,policy=DEFAULT_POLICY,budget=RepairBudget(DEFAULT_POLICY))
            response=service.answer(dict(raw=answer.raw,ref=answer.ref.as_dict()))
            checked=proof.verify_bootstrap_proof_response(response,expected_subject=owner,expected_target=source.target,
                target_storage_epoch=slot['writer_storage_epoch'],selector=grant['selector'],bootstrap_grant_ref=slot_entries['bootstrap']['ref'],
                probe_ref=packet['ref'],challenge_ref=challenge['ref'],answer_ref=answer.ref.as_dict(),at=int(time.time()),
                max_proof_items=64,max_proof_bytes=524288,consumer='mailbox_feed',expected_source_state='feed',policy=DEFAULT_POLICY,budget=RepairBudget(DEFAULT_POLICY))
            return checked,response
        # Requests use the live authenticated handle deadline. Fixture setup
        # and cold import can already consume 45 seconds on a cloud runner.
        if self._testMethodName=='test_remote_feed_client_recovers_complete_index' or getattr(self,'ack_cold_return',False):
            from dataclasses import replace
            from memory_vault_open_repair_client import MailboxFeedRecoveryClient,MailboxSetupJournal
            from tests.open_repair_ack_fixtures import signed_entry
            node_entry=signed_entry(dict(source.node['payload'],base_url=base,revision=source.node['payload']['revision']+1),source.identity,'synthetic_feed_http_node')
            observed=[]
            client=MailboxFeedRecoveryClient(self.bi,owner_encryption,policy=replace(DEFAULT_POLICY,max_signature_checks=512),
                limit_policy=limits,allow_loopback=True,status_observer=observed.append)
            self.addCleanup(client.close)
            recipient_network=self.enterContext(self.b._network())
            recipient_db=self.enterContext(recipient_network.participant.state.db())
            client_options=dict(target_node_entry=node_entry,expected_target=source.target,expected_sender=member_args['expected_sender'],
                expected_slot=slot,slot_entries={name:slot_entries[name] for name in ('slot','read','maintenance','bootstrap')},
                journal=MailboxSetupJournal(recipient_db))
            delivery=recipient_network._delivery()
            captured=[];recover_feed=MailboxFeedRecoveryClient.recover
            def capture_feed(reader,*args,**kwargs):
                value=recover_feed(reader,*args,**kwargs);captured.append(value);return value
            # Remove the old transport before first reception, not after import.
            db.execute('DELETE FROM open_delivery_messages WHERE message_id=?',(sent['message_id'],))
            db.execute('DELETE FROM open_contact_resource_leases');db.commit()
            from memory_vault_open_delivery_client import OpenDeliveryClient
            from memory_vault_open_client import MAILBOX_CONNECT_SCHEMA
            invitation=dict(schema_version=MAILBOX_CONNECT_SCHEMA,action='register',base_url=base,limit_policy=limits,
                expected_slot=slot,expected_sender=member_args['expected_sender'],expected_target=source.target,
                target_node_entry=dict(raw=node_entry['raw'].decode(),ref=node_entry['ref']),
                slot_entries={name:dict(raw=value['raw'].decode(),ref=value['ref']) for name,value in client_options['slot_entries'].items()})
            wrong_owner=self.a.handle(dict(op='connect',invitation=invitation))
            self.assertFalse(wrong_owner['ok'])
            self.assertEqual(self.call(self.a,op='connect',invitation=dict(schema_version=MAILBOX_CONNECT_SCHEMA,action='list'))['mailboxes'],[])
            wrong_endpoint=self.b.handle(dict(op='connect',invitation=dict(invitation,base_url='http://127.0.0.1:1')))
            self.assertFalse(wrong_endpoint['ok'])
            configured=self.call(self.b,op='connect',invitation=invitation,request_id='req_synthetic_mailbox_receiver')
            self.assertEqual(configured['state'],'registered');self.assertFalse(configured['network_accessed'])
            self.assertEqual(self.call(self.b,op='connect',invitation=invitation)['receiver_id'],configured['receiver_id'])
            listed=self.call(self.b,op='connect',invitation=dict(schema_version=MAILBOX_CONNECT_SCHEMA,action='list'))
            self.assertEqual(listed['mailboxes'],[configured['receiver_id']])
            with patch.object(MailboxFeedRecoveryClient,'recover',new=capture_feed), \
                    patch.object(OpenDeliveryClient,'call',side_effect=AssertionError('legacy delivery endpoint used')), \
                    patch.object(OpenDeliveryClient,'_finish_inbox',side_effect=RuntimeError('synthetic stop after durable receipt')):
                with self.assertRaisesRegex(RuntimeError,'synthetic stop after durable receipt'):
                    # New ordinary client instance loads its selected mailbox from SQLite.
                    with self.b._network() as reopened_network:
                        reopened_network.receive(limit=1)
            observed.extend(captured[0].current_statuses)
            result=captured[0]
            self.assertEqual(delivery._inbox(sent['message_id'])['phase'],'staged')
            original_session=bytes(delivery._inbox(sent['message_id'])['session'])
            corrupted=json.loads(original_session)
            corrupted['mailbox']['originals'][0]['ref']['size']+=1
            with recipient_network.participant.state.db() as inbox_db:
                inbox_db.execute('UPDATE open_delivery_inbox SET session=? WHERE message_id=?',
                    (canonical_bytes(corrupted),sent['message_id']))
            with patch('memory_vault_open_delivery_client.NetworkClient._import_received_share',side_effect=AssertionError('unverified memory import')):
                with self.assertRaisesRegex(Exception,'repair_ref_mismatch'):
                    delivery._finish_inbox(sent['message_id'])
            self.assertEqual(delivery._inbox(sent['message_id'])['phase'],'staged')
            with recipient_network.participant.state.db() as inbox_db:
                inbox_db.execute('UPDATE open_delivery_inbox SET session=? WHERE message_id=?',(original_session,sent['message_id']))
            # A new client resumes solely from the protected inbox proof.
            delivery=recipient_network._delivery()
            with patch.object(recipient_network.participant.transport,'request_repair',side_effect=AssertionError('duplicate cold body fetch')), \
                    patch.object(OpenDeliveryClient,'call',side_effect=AssertionError('legacy delivery endpoint used')):
                received=recipient_network.receive(limit=1)
            self.assertFalse(received['network_accessed'])
            self.assertEqual(received['errors'],[])
            self.assertEqual(delivery._inbox(sent['message_id'])['receipt_sent'],0)
            self.assertIsNotNone(delivery._inbox(sent['message_id'])['receipt'])
            self.assertEqual(received['messages'][0]['state'],'validated_saved')
            self.assertIn('Synthetic mailbox staging message',received['messages'][0]['text'])
            self.assertEqual(received['messages'][0]['content_kind'],'memory_transfer')
            self.assertEqual(received['messages'][0]['share']['records_added'],1)
            recalled=self.call(self.b,op='recall',memory_id=shared_memory['memory_id'])
            self.assertEqual(recalled['hits'][0]['text'],'Synthetic mailbox memory: consult current evidence before reuse.')
            with patch.object(delivery,'call',side_effect=AssertionError('duplicate body fetch')):
                again=asyncio.run(delivery._receive_mailbox_feed(client,result,client_options,4))
            self.assertEqual(again['messages'],[])
            self.assertEqual(again['body_transport'],'mailbox_retained_copy')
            # The retained copy is also independently readable through its handle.
            try:
                cold=client.read_member(base,result,result.entries[0],expected_slot=slot,
                    expected_sender=member_args['expected_sender'],expected_target=source.target)
            except Exception as error:
                raise AssertionError('synthetic cold body server errors: '+repr(server_errors)) from error
            self.assertEqual(cold['envelope'],envelope)
            core_child=next(v for v in result.proof.manifest.value['children'] if v['role']=='member.core')
            body_request=proof.make_mailbox_body_request(self.bi,result.proof,envelope_ref=core['envelope_ref'],
                subject=owner,target=source.target,at=int(time.time()),expires_at=result.proof.handle.payload['expires_at'],
                child_index=core_child['index'],offset=0,requested_bytes=16,policy=DEFAULT_POLICY,budget=RepairBudget(DEFAULT_POLICY))
            body_packet=dict(raw=body_request.raw,ref=body_request.ref.as_dict())
            self.assertEqual(service.child(body_packet),envelope[:16])
            with self.assertRaisesRegex(AssertionError,'repair_child_replay'):
                service.child(body_packet)
            data_id=db.execute('SELECT data_id FROM open_mailbox_message_staging').fetchone()[0]
            db.execute("UPDATE open_repair_mailbox_resources SET status='pending' WHERE resource_id=?",(data_id,));db.commit()
            with self.assertRaisesRegex(AssertionError,'repair_resource_inactive'):
                service.child(body_packet)
            db.execute("UPDATE open_repair_mailbox_resources SET status='active' WHERE resource_id=?",(data_id,))
            db.commit()

            self.assertEqual(result.entries[0]['admission_link_ref'],admitted['link']['ref'])
            self.assertEqual(result.source['custody'].raw,feed_custody['raw'])
            self.assertTrue(observed);self.assertGreater(result.metrics['requests'],2)
            checked=result.proof
            child=next(v for v in checked.manifest.value['children'] if v['role']=='feed.custody')
            child_request=proof.make_bootstrap_child_request(self.bi,checked,subject=owner,target=source.target,at=int(time.time()),expires_at=checked.handle.payload['expires_at'],
                child_index=child['index'],offset=0,requested_bytes=child['ref']['size'],policy=DEFAULT_POLICY,budget=RepairBudget(DEFAULT_POLICY))
        else:
            checked,response=fresh_feed_proof()
            child=next(v for v in checked.manifest.value['children'] if v['role']=='feed.custody')
            child_request=proof.make_bootstrap_child_request(self.bi,checked,subject=owner,target=source.target,at=int(time.time()),expires_at=checked.handle.payload['expires_at'],
                child_index=child['index'],offset=0,requested_bytes=child['ref']['size'],policy=DEFAULT_POLICY,budget=RepairBudget(DEFAULT_POLICY))
            self.assertEqual(service.child(dict(raw=child_request.raw,ref=child_request.ref.as_dict())),feed_custody['raw'])
            transfer_bytes=len(response)+len(checked.handle.raw)+len(checked.manifest.raw)+len(feed_custody['raw'])+sum(v['ref']['size'] for v in checked.manifest.value['children'])
            self.assertLessEqual(transfer_bytes,grant['limits']['max_proof_bytes'])
            received={};renewals=0
            # This exhaustive endpoint check fetches even originals already
            # present in packs. Read the changing current-status entries first;
            # stable historical originals may require another possession proof
            # on a slower runner. Each renewal is charged by the real service.
            children=sorted(checked.manifest.value['children'],key=lambda item:not item['role'].startswith('current.status.'))
            for child in children:
                chunks=[]
                for offset in range(0,child['ref']['size'],65536):
                    if checked.handle.payload['expires_at']-int(time.time())<=20:
                        self.assertLess(renewals,4,'bounded exhaustive proof download')
                        checked,response=fresh_feed_proof();renewals+=1
                        transfer_bytes+=len(response)+len(checked.handle.raw)+len(checked.manifest.raw)
                        self.assertLessEqual(transfer_bytes,grant['limits']['max_proof_bytes'])
                    matches=[entry for entry in checked.manifest.value['children']
                        if entry['role']==child['role'] and entry['ref']==child['ref']]
                    self.assertEqual(len(matches),1,'renewal must retain the exact full original reference')
                    request=proof.make_bootstrap_child_request(self.bi,checked,subject=owner,target=source.target,at=int(time.time()),expires_at=checked.handle.payload['expires_at'],
                        child_index=matches[0]['index'],offset=offset,requested_bytes=min(65536,child['ref']['size']-offset),policy=DEFAULT_POLICY,budget=RepairBudget(DEFAULT_POLICY))
                    chunks.append(service.child(dict(raw=request.raw,ref=request.ref.as_dict())))
                child_raw=b''.join(chunks);self.assertEqual(hashlib.sha256(child_raw).hexdigest(),child['ref']['raw_sha256'])
                received[(child['role'],child['ref']['key'])]=dict(raw=child_raw,ref=child['ref'])
            budget=RepairBudget(DEFAULT_POLICY);resolver=wire.LocalRawResolver(DEFAULT_POLICY,budget)
            for (role,_),value in received.items():
                if role=='history.raw_pack':resolver.put('meta',value['ref']['key'],value['raw'])
            remote_verified=verify_mailbox_feed_source_event(received[('history.mailbox_feed',feed_history['manifest']['ref']['key'])],resolver,
                received[('feed.custody',feed_custody['ref']['key'])],expected_slot=slot,expected_owner=owner,
                expected_sender=member_args['expected_sender'],expected_target=source.target,limit_policy=limits,policy=DEFAULT_POLICY,budget=budget)
            self.assertEqual(remote_verified['graph']['head']['count'],1)
        extended=source._sign(dict(payload,retain_until=now+361),'synthetic_overpromise',RepairBudget(DEFAULT_POLICY))
        budget=RepairBudget(DEFAULT_POLICY);resolver=wire.LocalRawResolver(DEFAULT_POLICY,budget)
        for value in (saved['pack'],feed_history['pack']):resolver.put('meta',value['ref']['key'],value['raw'])
        with self.assertRaises(RepairWireError):
            verify_mailbox_feed_source_event(feed_history['manifest'],resolver,extended,expected_slot=slot,
                expected_owner=owner,expected_sender=member_args['expected_sender'],expected_target=source.target,
                limit_policy=limits,policy=DEFAULT_POLICY,budget=budget)
        authority_reads=[]
        def traced_original(reference):
            authority_reads.append(reference['namespace'])
            return read_member_original(reference)
        with self.assertRaises(RepairWireError):
            read_mailbox_admission(members[0],**dict(member_args,expected_sender=owner,read_original=traced_original))
        self.assertNotIn('object',authority_reads)
        attempted=[]
        def corrupt_envelope(reference):
            attempted.append(reference['namespace'])
            if reference['namespace']=='object':return b'{}'
            return read_member_original(reference)
        with self.assertRaisesRegex(RepairWireError,'repair_mailbox_member_mismatch'):
            read_mailbox_admission(members[0],**dict(member_args,encryption_identity=sender_encryption,read_original=corrupt_envelope))
        self.assertNotIn('object',attempted)
        with self.assertRaisesRegex(RepairWireError,'repair_ref_mismatch'):
            read_mailbox_admission(members[0],**dict(member_args,read_original=corrupt_envelope))
        with self.assertRaisesRegex(RepairWireError,'repair_mailbox_member_mismatch'):
            read_mailbox_admission(dict(members[0],sequence=1),**member_args)
        with self.assertRaisesRegex(RepairWireError,'repair_mailbox_range_mismatch'):
            read_mailbox_index(admitted['head'],admitted['checkpoint'],**dict(args,encryption_identity=sender_encryption))
        with self.assertRaisesRegex(RepairWireError,'repair_ref_mismatch'):
            read_mailbox_index(admitted['head'],admitted['checkpoint'],**dict(args,read_original=lambda ref:b'{}'))
        missing=admitted['sealed_page']['ref']['key']
        db.execute('SAVEPOINT missing_original')
        db.execute('DELETE FROM open_mailbox_admission_objects WHERE key=?',(missing,))
        db.execute('RELEASE missing_original')
        with self.assertRaisesRegex(RepairWireError,'repair_storage_corrupt'):
            staging.commit_member(self.ai.key_id,sent['message_id'],object_until=now+360,enum_until=now+360)
        value=admitted['sealed_page'];ref=value['ref']
        db.execute('INSERT INTO open_mailbox_admission_objects VALUES(?,?,?,?)',(missing,ref['raw_sha256'],ref['size'],value['raw']))
        db.commit()
        revoked=status_entry(issue_status(self.bi,root=root,revision=3,entries=[dict(value,status='revoked') for value in scoped],issued_at=now,valid_until=now+400))
        if self._testMethodName=='test_remote_feed_client_recovers_complete_index' or getattr(self,'ack_cold_return',False):
            observed.clear()
            with patch.object(client.transport,'request_repair',side_effect=AssertionError('unexpected network after retained revocation')):
                with self.assertRaisesRegex(RepairWireError,'repair_authority_revoked'):
                    client.recover(base,**client_options,known_statuses=[revoked])
            self.assertTrue(any(value.payload['revision']==3 for value in observed))
            restarted=MailboxFeedRecoveryClient(self.bi,owner_encryption,policy=replace(DEFAULT_POLICY,max_signature_checks=512),
                limit_policy=limits,allow_loopback=True)
            self.addCleanup(restarted.close)
            with recipient_network.participant.state.db() as reopened:
                with patch.object(restarted.transport,'request_repair',side_effect=AssertionError('unexpected network after journal reopen')):
                    with self.assertRaisesRegex(RepairWireError,'repair_authority_revoked'):
                        restarted.recover(base,**dict(client_options,journal=MailboxSetupJournal(reopened)))
        denied=[];authority_reads.clear()
        with self.assertRaisesRegex(RepairWireError,'repair_authority_revoked'):
            read_mailbox_admission(members[0],**dict(member_args,known_statuses=[revoked],
                on_status_authenticated=denied.append,read_original=traced_original))
        self.assertNotIn('object',authority_reads)
        self.assertTrue(any(value.payload['revision']==3 for value in denied))
        from memory_vault_open_repair_client import verify_mailbox_member_current
        expired=status_entry(issue_status(self.bi,root=root,revision=3,entries=[dict(value,status='revoked') for value in scoped],
            issued_at=now-10,valid_until=now-1))
        retained=[]
        with self.assertRaisesRegex(RepairWireError,'repair_status_mismatch'):
            verify_mailbox_member_current(recovered['setup'],[expired],at=int(time.time()),on_authenticated=retained.append)
        self.assertEqual(len(retained),1)
        with self.assertRaisesRegex(RepairWireError,'repair_authority_revoked'):
            verify_mailbox_member_current(recovered['setup'],member_args['current_statuses'],known_entries=[expired],at=int(time.time()))
        without_sender=[entry for entry in member_args['current_statuses']
            if json.loads(entry['raw'])['payload']['signing_key']['key_id']!=self.ai.key_id]
        with self.assertRaisesRegex(RepairWireError,'repair_status_missing'):
            verify_mailbox_member_current(recovered['setup'],without_sender,at=int(time.time()))
        from memory_vault_open_repair_mailbox_activation import verify_mailbox_member_inputs
        altered={value.role:dict(raw=value.original.raw,ref=value.original.ref.as_dict()) for value in recovered['history'].roles}
        for name in ('slot','read','maintenance','bootstrap','destination'):
            altered['historical.status.'+name]=revoked
        budget=RepairBudget(DEFAULT_POLICY)
        changed_pack=wire.build_raw_pack([value['raw'] for value in altered.values()],DEFAULT_POLICY,budget)
        indices={(value.raw_sha256,value.size):i for i,value in enumerate(changed_pack.entries)}
        changed_manifest=dict(json.loads(saved['manifest']['raw']),roles=[dict(role=role,document_ref=value['ref'],
            pack_ref=changed_pack.ref.as_dict(),entry_index=indices[(value['ref']['raw_sha256'],value['ref']['size'])])
            for role,value in sorted(altered.items())])
        changed=history.build_historical_manifest(changed_manifest,DEFAULT_POLICY,budget)
        resolver=wire.LocalRawResolver(DEFAULT_POLICY,budget);resolver.put('meta',changed_pack.ref.key,changed_pack.raw)
        changed=history.resolve_historical_inputs(changed.raw,resolver,DEFAULT_POLICY,budget)
        with self.assertRaisesRegex(RepairWireError,'repair_authority_revoked'):
            verify_mailbox_member_inputs(changed,expected_slot=slot,expected_owner=owner,expected_sender=member_args['expected_sender'],
                expected_target=source.target,target_storage_epoch=slot['writer_storage_epoch'],accepted_at=recovered['core']['accepted_at'],
                limit_policy=limits,policy=DEFAULT_POLICY,budget=RepairBudget(DEFAULT_POLICY))
        # The preceding independent integrity checks can outlive a short handle.
        # Obtain a new, charged possession proof before revocation, rather than
        # attempting to sign a child request against an expired old handle.
        denial_proof,_=fresh_feed_proof()
        denial_child=next(v for v in denial_proof.manifest.value['children'] if v['role']=='feed.custody')
        denied_request=proof.make_bootstrap_child_request(self.bi,denial_proof,subject=owner,target=source.target,
            at=int(time.time()),expires_at=denial_proof.handle.payload['expires_at'],
            child_index=denial_child['index'],offset=0,requested_bytes=feed_custody['ref']['size'],policy=DEFAULT_POLICY,budget=RepairBudget(DEFAULT_POLICY))
        if self._testMethodName=='test_remote_feed_client_recovers_complete_index' or getattr(self,'ack_cold_return',False):
            from memory_vault_open_repair_mailbox_status import MailboxStatusLedger
            metadata_id=db.execute('SELECT metadata_id FROM open_mailbox_message_staging').fetchone()[0]
            MailboxStatusLedger(resources).observe(metadata_id,revoked,expected_signing_key=owner['signing_key'],
                allowed_scopes=[dict(scope_kind=v['scope_kind'],scope_id=v['scope_id']) for v in scoped])
            with self.assertRaisesRegex(RepairWireError,'repair_message_delivery_missing'):
                staging.stage_delivered(raw,owner_status)
        else:
            with self.assertRaisesRegex(RepairWireError,'repair_authority_revoked'):
                staging.stage_delivered(raw,revoked)
            with self.assertRaisesRegex(RepairWireError,'repair_authority_revoked'):
                staging.stage_delivered(raw,owner_status)
        with self.assertRaisesRegex(AssertionError,'repair_authority_revoked'):
            service.child(dict(raw=denied_request.raw,ref=denied_request.ref.as_dict()))
        if self._testMethodName=='test_remote_feed_client_recovers_complete_index' or getattr(self,'ack_cold_return',False):
            with self.assertRaisesRegex(AssertionError,'repair_authority_revoked'):
                service.child(body_packet)
            status_count=recipient_db.execute('SELECT count(*) FROM open_mailbox_setup_statuses').fetchone()[0]
            removed=self.call(self.b,op='connect',invitation=dict(schema_version=MAILBOX_CONNECT_SCHEMA,action='remove',receiver_id=configured['receiver_id']))
            self.assertEqual(removed['state'],'removed')
            self.assertEqual(self.call(self.b,op='connect',invitation=dict(schema_version=MAILBOX_CONNECT_SCHEMA,action='list'))['mailboxes'],[])
            self.assertGreater(status_count,0)
            self.assertEqual(recipient_db.execute('SELECT count(*) FROM open_mailbox_setup_statuses').fetchone()[0],status_count)
            self.assertEqual(delivery._inbox(sent['message_id'])['phase'],'saved')

    def _remote_message_admission(self, source, owner_status, slot, slot_entries, owner, sender_encryption, sent, now, limits, envelope):
        import hashlib
        import threading
        import time
        from dataclasses import replace
        from memory_vault_open_node import OpenParticipant,OpenHTTPServer
        from memory_vault_open_transport import OpenHTTPTransport
        from memory_vault_open_repair_client import MailboxMessageDraftStore,MailboxFeedRecoveryClient
        from memory_vault_open_repair_state import DEFAULT_POLICY
        from memory_vault_open_repair_bind import decode_entry
        import memory_vault_open_repair_wire as wire
        import memory_vault_open_repair_original as original
        from tests.open_repair_ack_fixtures import signed_entry
        participant=OpenParticipant(source.identity,self.root/'node_0/transport',seeds=[],descriptor=source.node,
            encryption_identity=source.encryption_identity,allow_loopback=True,contact_policy=dict(enabled=True),delivery_policy=dict(enabled=True),
            repair_policy=dict(enabled=True,limit_policy=limits,remote_setup=dict(enabled=True)))
        errors=[];handle=participant.handle_repair
        def traced(raw):
            try:return handle(raw)
            except Exception as error:
                import traceback
                errors.append((getattr(error,'code',type(error).__name__),[(frame.name,frame.lineno) for frame in traceback.extract_tb(error.__traceback__)]));raise
        participant.handle_repair=traced
        server=OpenHTTPServer(('127.0.0.1',0),participant)
        thread=threading.Thread(target=server.serve_forever,kwargs=dict(poll_interval=.02),daemon=True);thread.start()
        def close():server.shutdown();server.server_close();thread.join(timeout=3);participant.close()
        self.addCleanup(close)
        base='http://127.0.0.1:'+str(server.server_port)
        transport=OpenHTTPTransport(allow_loopback=True);self.addCleanup(transport.close)
        with self.a._network() as network:
            with network.participant.state.db() as db:
                store=MailboxMessageDraftStore(db,self.ai,sender_encryption)
                options=dict(target=source.target,owner_status_entry=owner_status,at=now,expires_at=now+240,object_until=now+320,enum_until=now+320)
                packet=store.admission_request(sent['message_id'],**options)
        with self.a._network() as network:
            with network.participant.state.db() as db:
                again=MailboxMessageDraftStore(db,self.ai,sender_encryption).admission_request(sent['message_id'],**dict(options,at=now+1))
                self.assertEqual(again,packet)
        def request(value):
            try:return transport.request_repair(base,value,deadline=time.monotonic()+30)
            except Exception as error:raise AssertionError('synthetic admission server errors: '+repr(errors)) from error
        from unittest.mock import patch
        from memory_vault_open_repair_mailbox_source import MailboxMessageStaging
        with patch.object(MailboxMessageStaging,'prepare_feed_history',side_effect=RuntimeError('synthetic interrupted admission')):
            with self.assertRaisesRegex(AssertionError,'RuntimeError'):
                request(packet['raw'])
        self.assertEqual(source.db.execute('SELECT phase FROM open_mailbox_message_staging').fetchone()[0],'committed')
        errors.clear()
        # A later message can advance the index while the first request is
        # interrupted after commit. Resuming must finalize the first prefix.
        second=self.second_mailbox_message
        from memory_vault_open_client import MAILBOX_CONNECT_SCHEMA
        node=signed_entry(dict(source.node['payload'],base_url=base,revision=source.node['payload']['revision']+1),source.identity,'synthetic_admission_node')
        # Use B's Agent-exported bundle. The source's signed current descriptor
        # supplies the actual restarted HTTP endpoint without changing grants.
        authorization=dict(self.sender_authorization,base_url=base,target_node_entry=dict(raw=node['raw'].decode(),ref=node['ref']))
        retain=dict(schema_version=MAILBOX_CONNECT_SCHEMA,action='retain',message_id=second['message_id'],authorization=authorization,
            attempt_until=now+240,consent_until=now+400,expires_at=now+240,object_until=now+320,enum_until=now+320)
        from memory_vault import MemoryError as VaultError
        real_request=OpenHTTPTransport.request_repair
        def lose_reply(client,*args,**kwargs):
            real_request(client,*args,**kwargs)
            raise VaultError('open_network_unavailable')
        with patch.object(OpenHTTPTransport,'request_repair',new=lose_reply):
            lost=self.a.handle(dict(op='connect',invitation=retain))
        self.assertFalse(lost['ok'])
        self.assertEqual(lost['error']['code'],'open_network_unavailable')
        retained=self.call(self.a,op='connect',invitation=retain)
        self.assertEqual(retained['state'],'retained_at_mailbox')
        self.assertFalse(retained['recipient_acknowledged'])
        self.assertEqual(self.call(self.a,op='connect',invitation=retain),retained)
        response=request(packet['raw'])
        usage_before=source.db.execute('SELECT requests,signatures,bytes FROM open_mailbox_remote_message_usage').fetchone()
        self.assertEqual(request(packet['raw']),response)
        usage_after=source.db.execute('SELECT requests,signatures,bytes FROM open_mailbox_remote_message_usage').fetchone()
        self.assertEqual(usage_after['requests']-usage_before['requests'],1)
        self.assertEqual(usage_after['signatures']-usage_before['signatures'],1)
        self.assertGreater(usage_after['bytes'],usage_before['bytes'])
        payload=json.loads(packet['raw'])['payload']
        conflicting=dict(payload,enum_until=now+321)
        conflict=canonical_bytes(dict(payload=conflicting,proof=self.ai.sign_message(conflicting)))
        with self.assertRaisesRegex(AssertionError,'repair_message_conflict'):request(conflict)
        errors.clear()
        with self.a._network() as network:
            with network.participant.state.db() as db:
                checked=MailboxMessageDraftStore(db,self.ai,sender_encryption).verify_admission_response(packet['raw'],response)
        self.assertEqual(checked['message_id'],sent['message_id'])
        forged=json.loads(response);forged['payload']['message_id']='synthetic_wrong_message'
        with self.a._network() as network:
            with network.participant.state.db() as db:
                with self.assertRaises(wire.RepairWireError):
                    MailboxMessageDraftStore(db,self.ai,sender_encryption).verify_admission_response(packet['raw'],canonical_bytes(forged))
        self.assertEqual(source.db.execute('SELECT phase FROM open_mailbox_message_staging').fetchone()[0],'committed')
        self.assertEqual(source.db.execute('SELECT count(*) FROM open_mailbox_admissions').fetchone()[0],2)
        self.assertEqual(source.db.execute('SELECT count(*) FROM open_mailbox_feed_custody').fetchone()[0],2)
        # A complete remote admission is immediately usable by B's independent
        # possession exchange and full feed/member consumer, not just a flag.
        from memory_vault_open_client import MAILBOX_CONNECT_SCHEMA
        invitation=dict(schema_version=MAILBOX_CONNECT_SCHEMA,action='admit',base_url=base,message_id=sent['message_id'],target=source.target,
            target_node_entry=dict(raw=node['raw'].decode(),ref=node['ref']),
            owner_status_entry=dict(raw=owner_status['raw'].decode(),ref=owner_status['ref']),
            expires_at=now+240,object_until=now+320,enum_until=now+320)
        accepted=self.call(self.a,op='connect',invitation=invitation)
        self.assertEqual(accepted['state'],'retained_at_mailbox')
        self.assertFalse(accepted['recipient_acknowledged'])
        self.assertEqual(self.call(self.a,op='connect',invitation=invitation),accepted)
        with self.b._network() as network:
            reader=MailboxFeedRecoveryClient(self.bi,network.encryption,policy=replace(DEFAULT_POLICY,max_signature_checks=512),limit_policy=limits,allow_loopback=True)
            self.addCleanup(reader.close)
            sender=dict(signing_key=self.ai.public_descriptor(),encryption_key=sender_encryption.public_descriptor())
            try:
                recovered=reader.recover(base,target_node_entry=node,expected_target=source.target,expected_sender=sender,expected_slot=slot,
                    slot_entries={name:slot_entries[name] for name in ('slot','read','maintenance','bootstrap')})
            except Exception as error:raise AssertionError(repr(errors)) from error
            message=reader.read_member(base,recovered,recovered.entries[0],expected_slot=slot,expected_sender=sender,expected_target=source.target)
            self.assertEqual(message['envelope'],envelope)
            from memory_vault_open_repair_client import mailbox_inbox_evidence,verify_mailbox_inbox_evidence
            at=int(time.time())
            evidence=mailbox_inbox_evidence(recovered,recovered.entries[0],slot=slot,sender=sender,target=source.target,limits=limits,received_at=at)
            offline=verify_mailbox_inbox_evidence(evidence,envelope,owner=owner,encryption_identity=network.encryption,staged_at=at)
            self.assertEqual(offline['envelope'],envelope)
        self.assertEqual(errors,[])

    def test_ack_configuration_survives_mailbox_custody(self):
        from memory_vault_network_crypto import EncryptionIdentity
        from memory_vault_open_repair_state import RECEIPT_WORKFLOW_LIMITS
        from memory_vault_open_repair_mailbox_activation import ACK_CONFIGURATION_ROLES
        ack_host=HTTPNodes(self.root/'independent_ack',1);self.addCleanup(ack_host.close)
        ack_host.stop(0)
        config=json.loads(ack_host.configs[0].read_bytes())
        encryption=EncryptionIdentity.generate();key=self.root/'independent_ack'/'encryption.json';encryption.save(key)
        config.update(encryption_key_path=str(key),provider_policy=dict(enabled=True),
            repair_policy=dict(enabled=True,limit_policy=RECEIPT_WORKFLOW_LIMITS,remote_setup=dict(enabled=True)))
        atomic_write(ack_host.configs[0],canonical_bytes(config),replace=True);ack_host.start(0)
        old_call=self.call
        def call(agent,**request):
            if request['op']=='send' and agent is self.a and not hasattr(self,'ack_configuration'):
                from memory_vault_open_client import ACK_CONNECT_SCHEMA
                prepared=old_call(self.a,op='connect',invitation=dict(schema_version=ACK_CONNECT_SCHEMA,action='prepare',
                    request_id=request['request_id'],recipient=self.bi.key_id,text=request['text'],memory_ids=request.get('memory_ids',[]),
                    source_url=ack_host.nodes[0]['payload']['base_url'],source_key_id=ack_host.identities[0].key_id,
                    repair_profile='receipt',lifetime=3600))
                with self.a._network() as network:
                    self.ack_configuration=network._mailbox_ack_configuration(request['request_id'],prepared['message_id'])
                self.assertEqual(set(self.ack_configuration),ACK_CONFIGURATION_ROLES)
                self.ack_preparation_request_id=request['request_id']
            return old_call(agent,**request)
        self.call=call
        self.test_actual_delivery_stages_exact_ciphertext_under_mailbox_resources()
        if getattr(self,'ack_cold_return',False):
            self._return_cold_ack(ack_host)
        from memory_vault_open_repair_mailbox_activation import verify_mailbox_ack_configuration
        from memory_vault_open_repair_state import DEFAULT_POLICY
        from memory_vault_open_repair_wire import RepairBudget,RepairWireError
        import time
        with self.a._network() as network:
            sender=dict(signing_key=self.ai.public_descriptor(),encryption_key=network.encryption.public_descriptor())
        with self.b._network() as network:
            recipient=dict(signing_key=self.bi.public_descriptor(),encryption_key=network.encryption.public_descriptor())
        write=json.loads(self.ack_configuration['ack.write_grant']['raw'])['payload']
        arguments=dict(sender=sender,recipient=recipient,message_id=write['message_id'],envelope_ref=write['envelope_ref'],
            at=int(time.time()),policy=DEFAULT_POLICY)
        with self.assertRaisesRegex(RepairWireError,'repair_ack_bound_mismatch'):
            verify_mailbox_ack_configuration(self.ack_configuration,**dict(arguments,message_id=write['message_id'][:-1]+('0' if write['message_id'][-1]!='0' else '1')),budget=RepairBudget(DEFAULT_POLICY))
        wrong_status=dict(self.ack_configuration)
        wrong_status['historical.status.ack_root']=wrong_status['historical.status.ack_write']
        with self.assertRaisesRegex(RepairWireError,'repair_status_missing'):
            verify_mailbox_ack_configuration(wrong_status,**arguments,budget=RepairBudget(DEFAULT_POLICY))

    def test_cold_mailbox_returns_independent_receipt(self):
        self.ack_cold_return=True
        self.test_ack_configuration_survives_mailbox_custody()

    def _return_cold_ack(self, ack_host):
        import base64
        from unittest.mock import patch
        from memory_vault_open_client import ACK_CONNECT_SCHEMA
        from memory_vault_open_delivery_client import OpenDeliveryClient
        write=json.loads(self.ack_configuration['ack.write_grant']['raw'])['payload']
        invitation=dict(schema_version=ACK_CONNECT_SCHEMA,action='return_mailbox_receipt',message_id=write['message_id'],
            source_url=ack_host.nodes[0]['payload']['base_url'],source_key_id=ack_host.identities[0].key_id,repair_profile='receipt')
        from memory_vault import MemoryError
        from memory_vault_open_transport import OpenHTTPTransport
        original_request=OpenHTTPTransport.request_repair
        dropped=[]
        def lose_reply(transport,*args,**kwargs):
            reply=original_request(transport,*args,**kwargs)
            try:kind=json.loads(reply).get('kind')
            except (ValueError,UnicodeDecodeError):kind=None
            if kind=='ack.put_response' and not dropped:
                dropped.append(True)
                raise MemoryError('synthetic_lost_ack_reply')
            return reply
        with patch.object(OpenHTTPTransport,'request_repair',new=lose_reply):
            failed=self.b.handle(dict(op='connect',invitation=invitation))
        self.assertEqual(dropped,[True]);self.assertFalse(failed['ok'])
        self.assertEqual(failed['error']['code'],'synthetic_lost_ack_reply')
        # A new client resumes the frozen put journal after R already committed.
        with patch.object(OpenDeliveryClient,'call',side_effect=AssertionError('original delivery endpoint used')):
            returned=self.call(self.b,op='connect',invitation=invitation)
        self.assertEqual(returned['state'],'retained_at_ack_source')
        self.assertTrue(returned['network_accessed'])
        with self.b._network() as network:
            with patch.object(network.participant.transport,'request_repair',side_effect=AssertionError('repeated ACK network call')):
                again=network._ack_connect(invitation)
        self.assertTrue(again['from_local_history']);self.assertFalse(again['network_accessed'])
        self.assertEqual(again['receipt_ref'],returned['receipt_ref'])
        # A changed destination never reuses the saved authorization request.
        with self.b._network() as network:
            with self.assertRaisesRegex(Exception,'open_ack_mailbox_return_conflict'):
                network._ack_connect(dict(invitation,source_url='http://127.0.0.1:1'))
            with network.participant.state.db() as db:
                saved=db.execute('SELECT request FROM open_mailbox_ack_returns WHERE message_id=?',(write['message_id'],)).fetchone()[0]
                db.execute('UPDATE open_mailbox_ack_returns SET request=? WHERE message_id=?',(b'{}',write['message_id']))
            with self.assertRaisesRegex(Exception,'open_ack_mailbox_return_corrupt'):
                network._ack_connect(invitation)
            with network.participant.state.db() as db:
                db.execute('UPDATE open_mailbox_ack_returns SET request=? WHERE message_id=?',(saved,write['message_id']))
        chunks=[];cursor=None
        while True:
            query=dict(schema_version=ACK_CONNECT_SCHEMA,action='export_preparation',request_id=self.ack_preparation_request_id,part='owner_invitation')
            if cursor is not None:query['cursor']=cursor
            page=self.call(self.a,op='connect',invitation=query)
            chunks.append(base64.b64decode(page['bundle_chunk']));cursor=page['next_cursor']
            if cursor is None:break
        owner_invitation=json.loads(b''.join(chunks))
        with patch.object(OpenDeliveryClient,'call',side_effect=AssertionError('original delivery endpoint used')):
            recovered=self.call(self.a,op='connect',invitation=owner_invitation)
        self.assertEqual(recovered['message_id'],write['message_id'])
        with self.a._network() as network:
            with network.participant.state.db() as db:
                row=db.execute('SELECT acknowledgement FROM open_delivery_outbox WHERE message_id=?',(write['message_id'],)).fetchone()
                self.assertIsNotNone(row['acknowledgement'])

    def test_ack_configuration_admitted_over_http(self):
        self.ack_remote_admission=True
        self.test_ack_configuration_survives_mailbox_custody()

    def test_sender_admits_message_over_http(self):
        self.test_actual_delivery_stages_exact_ciphertext_under_mailbox_resources()

    def test_remote_feed_client_recovers_complete_index(self):
        self.test_actual_delivery_stages_exact_ciphertext_under_mailbox_resources()
