"""Approved delivery and denied authority over disposable, real loopback HTTP."""
import asyncio
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
        _,reference=self.request_contact();self.decide(reference,'approved')
        sent=self.call(self.a,op='send',request_id='req_mailbox_stage',recipients=[self.bi.key_id],text='Synthetic mailbox staging message')
        self.assertTrue(sent['storage_accepted'])
        with self.a._network() as network:
            sender_encryption=network.encryption
            with network.participant.state.db() as sender_db:
                row=sender_db.execute('SELECT envelope,session FROM open_delivery_outbox WHERE request_id=?',('req_mailbox_stage',)).fetchone()
                envelope=bytes(row[0]);session=json.loads(bytes(row[1]))
        with self.b._network() as network:owner_encryption=network.encryption
        self.host.stop(0)
        db=sqlite3.connect(self.root/'node_0/transport/network.sqlite3');db.row_factory=sqlite3.Row;self.addCleanup(db.close)
        source=RepairAckState(db,self.host.identities[0],self.host.nodes[0],encryption_identity=EncryptionIdentity.generate())
        resources=RepairMailboxResources(source);activation=MailboxRootActivation(resources);activation.initialize()
        now=int(time.time());owner=dict(signing_key=self.bi.public_descriptor(),encryption_key=owner_encryption.public_descriptor())
        dual=lambda value:dict(signing_key_id=value['signing_key']['key_id'],encryption_key_id=value['encryption_key']['key_id'])
        root=dict(owner=dual(owner),root_kind='mailbox',anchor_ref=dict(namespace='anchor',key='b'*64),owner_epoch='synthetic_owner',root_id='synthetic_mailbox')
        slot=dict(root_key=root,slot_id='synthetic_slot',writer=dual(source.target),writer_storage_epoch=source.node['payload']['storage_epoch'])
        caps=dict(max_live_bytes=131072,max_meta_bytes=1048576,max_items=64,max_requests=512,max_pending=8,max_replay_records=128,max_jobs=16,max_job_bytes=262144)
        windows={name:now+600 for name in ('admit_until','read_until','copy_until','publish_until','retain_until')}
        plan=dict(root_key=root,slot_key=slot,sender=dict(signing_key_id=self.ai.key_id,encryption_key_id=sender_encryption.key_id),target=source.target,
            budget=caps,windows=windows,limits=DEFAULT_LIMITS,max_appends=16,max_live_items=16)
        builder=MailboxSetupBuilder(self.bi,owner_encryption,plan)
        requests=builder.allocation_requests(at=now,expires_at=now+60)
        offers=resources.allocate_initial(list(requests.values()),expected_owner=owner)
        now=int(time.time())
        slot_entries=builder.slot_documents(requests,offers,at=now,expires_at=windows['retain_until'])
        slot_result=activation.slots.activate(slot_entries,expected_slot=slot)
        now=int(time.time())
        root_entries=builder.root_documents(requests,offers,slot_entries,slot_result,at=now,expires_at=windows['retain_until'])
        active=activation.activate(root_entries,expected_root=root,slot_keys=[slot]);rid=json.loads(active['raw'])['payload']['resource']['resource_id']
        root_source=MailboxRootSource(activation);root_source.initialize()
        activation.observe_owner_status(rid,builder.initial_owner_status(slot_entries,root_entries,at=now,valid_until=now+100))
        root_source.observe_resources(rid,'synthetic_setup',valid_until=now+100);root_source.prepare_history(rid,'synthetic_setup')
        root_source.finalize_root(rid,read_until=now+100,retain_until=now+100)
        docs={name:session[name] for name in ('node','policy','request','decision')}
        docs.update(knock_lease=session['lease'],grant=session['decision']['payload']['grant'],delivery_lease=session['decision']['payload']['grant']['payload']['resource_lease'])
        contact={name:canonical_bytes(value) for name,value in docs.items()}
        destination=builder.destination_document(slot_entries,contact,at=now,expires_at=now+60)
        with self.a._network() as network:
            with network.participant.state.db() as sender_db:
                draft=MailboxMessageDraftStore(sender_db,self.ai,sender_encryption).prepare(envelope,recipient=owner,
                    slot_entries={name:slot_entries[name] for name in ('slot','read','maintenance')},destination_entry=destination,
                    contact_originals=contact,at=now,attempt_until=now+60,consent_until=now+100)
        scoped=[]
        for name,value in [('destination',destination),*[(name,slot_entries[name]) for name in ('slot','read','maintenance','bootstrap')]]:
            payload=json.loads(value['raw'])['payload'];kind='mailbox_slot' if name=='slot' else 'authority'
            subject=slot if name=='slot' else dict(authority_kind=payload['kind'],authority_sha256=value['ref']['raw_sha256'])
            scope=status.status_scope(root,kind,subject,DEFAULT_POLICY,RepairBudget(DEFAULT_POLICY))
            scoped.append(dict(scope_kind=kind,scope_id=scope,minimum_document_revision=1,status='active',operation_mask=127))
        scoped.sort(key=lambda value:(value['scope_kind'],value['scope_id']))
        owner_status=status_entry(issue_status(self.bi,root=root,revision=2,entries=scoped,issued_at=now,valid_until=now+100))
        delivery=DeliveryState(db,self.host.identities[0],self.host.nodes[0],enabled=True)
        staging=MailboxMessageStaging(resources,delivery);staging.initialize()
        raw=wire.build_new_wire(draft['originals'],DEFAULT_POLICY,RepairBudget(DEFAULT_POLICY)).raw
        first=staging.stage_delivered(raw,owner_status)
        self.assertEqual(first['state'],'staged');self.assertEqual(staging.stage_delivered(raw,owner_status),first)
        encryption=source.encryption_identity
        db.close();db=sqlite3.connect(self.root/'node_0/transport/network.sqlite3');db.row_factory=sqlite3.Row;self.addCleanup(db.close)
        source=RepairAckState(db,self.host.identities[0],self.host.nodes[0],encryption_identity=encryption)
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
        self.assertEqual(len(resolved.roles),29)
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
                staging.commit_member(self.ai.key_id,sent['message_id'],object_until=now+90,enum_until=now+90)
        self.assertEqual(db.execute('SELECT phase FROM open_mailbox_message_staging').fetchone()[0],'pending')
        admitted=staging.commit_member(self.ai.key_id,sent['message_id'],object_until=now+90,enum_until=now+90)
        self.assertEqual(staging.commit_member(self.ai.key_id,sent['message_id'],object_until=now+90,enum_until=now+90),admitted)
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
        with self.assertRaisesRegex(RepairWireError,'repair_mailbox_range_mismatch'):
            read_mailbox_index(admitted['head'],admitted['checkpoint'],**dict(args,encryption_identity=sender_encryption))
        with self.assertRaisesRegex(RepairWireError,'repair_ref_mismatch'):
            read_mailbox_index(admitted['head'],admitted['checkpoint'],**dict(args,read_original=lambda ref:b'{}'))
        missing=admitted['sealed_page']['ref']['key']
        db.execute('SAVEPOINT missing_original')
        db.execute('DELETE FROM open_mailbox_admission_objects WHERE key=?',(missing,))
        db.execute('RELEASE missing_original')
        with self.assertRaisesRegex(RepairWireError,'repair_storage_corrupt'):
            staging.commit_member(self.ai.key_id,sent['message_id'],object_until=now+90,enum_until=now+90)
        value=admitted['sealed_page'];ref=value['ref']
        db.execute('INSERT INTO open_mailbox_admission_objects VALUES(?,?,?,?)',(missing,ref['raw_sha256'],ref['size'],value['raw']))
        db.commit()
        revoked=status_entry(issue_status(self.bi,root=root,revision=3,entries=[dict(value,status='revoked') for value in scoped],issued_at=now,valid_until=now+100))
        with self.assertRaisesRegex(RepairWireError,'repair_authority_revoked'):
            staging.stage_delivered(raw,revoked)
        with self.assertRaisesRegex(RepairWireError,'repair_authority_revoked'):
            staging.stage_delivered(raw,owner_status)
