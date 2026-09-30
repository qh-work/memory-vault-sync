"""Actual mailbox admission copied into independently reserved feed storage."""
import copy
import base64
import contextlib
import hashlib
import io
import json
import sqlite3
import time
import unittest
from unittest.mock import patch

from memory_vault import canonical_bytes
from memory_vault_network_crypto import EncryptionIdentity
from memory_vault_open_control import issue_node
from memory_vault_open_provider import issue_status
from memory_vault_open_repair_state import RepairAckState
from memory_vault_open_repair_mailbox_snapshot import MailboxSnapshotSource
from memory_vault_open_repair_mailbox_feed_copy import (RESERVATION_KIND, DISCLOSURE_KIND,
    feed_copy_inventory, feed_disclosure_permissions, verify_mailbox_feed_copy)
from memory_vault_open_repair_mailbox_feed_copy_state import MailboxFeedCopyState
from memory_vault_open_repair_mailbox_activation import verify_mailbox_feed_source_event
from memory_vault_trust import Identity
from memory_vault_trust import TrustStore, _write_new_private
from memory_vault_network_crypto import b64url, unb64url
import memory_vault_open_repair_index as index
import memory_vault_open_repair_status as status
import memory_vault_open_repair_wire as wire
from tests import test_open_delivery_http as fixtures


class FeedCopyFixture:
    def __init__(self, test, fixture, staging, slot, head, *, message=False, lifetime=50):
        self.message = message
        self.recipient_agent=fixture.b
        self.call_agent=fixture.call
        if message:
            from memory_vault_open_repair_mailbox_message_copy import RESERVATION_KIND, DISCLOSURE_KIND
        else:
            from memory_vault_open_repair_mailbox_feed_copy import RESERVATION_KIND, DISCLOSURE_KIND
        self.test = test; self.staging = staging; self.source = staging.source; self.slot = slot; self.root = slot['root_key']
        s = self.source; self.now = int(time.time()); self.until = self.now + lifetime; self.policy = s.policy; self.limits = s.limits
        rid = staging.db.execute('SELECT resource_id FROM open_repair_mailbox_roots').fetchone()[0]
        self.snapshot = MailboxSnapshotSource(staging).load(rid, slot, head, max_bytes=2_000_000, max_items=256)
        self.part = self.snapshot.parts[1]
        self.manifest = self.entry(self.part.manifest); self.custody = self.entry(self.part.custody)
        self.owner = json.loads(staging.db.execute('SELECT owner_keys FROM open_repair_mailbox_resources LIMIT 1').fetchone()[0])
        envelope = json.loads(self.snapshot.read(self.snapshot.envelopes[0].as_dict()))['payload']['context']
        self.sender = dict(signing_key=fixture.ai.public_descriptor(), encryption_key=envelope['sender_encryption_key'])
        self.signers = dict(owner=fixture.bi, sender=fixture.ai, source=s.identity, maintainer=s.identity)
        with fixture.b._network() as network: self.owner_encryption = network.encryption
        self.parties = dict(owner=self.owner, sender=self.sender, source=s.target, maintainer=s.target)
        self.directory = fixture.root / 'synthetic-feed-replica'; self.directory.mkdir(mode=0o700)
        self.identity = Identity.generate(self.directory / 'identity.json'); self.encryption = EncryptionIdentity.generate()
        self.node = issue_node(self.identity, base_url='https://synthetic-feed-replica.example', storage_epoch='synthetic_feed_epoch',
            roles=['directory', 'router'], revision=1, issued_at=self.now, expires_at=self.now + 600)
        self.connect(); test.addCleanup(lambda: self.db.close())
        self.target = self.state.target
        resolver = self.resolver(); budget = resolver.budget
        self.event = verify_mailbox_feed_source_event(self.manifest, resolver, self.custody, expected_slot=slot,
            expected_owner=self.owner, expected_sender=self.sender, expected_target=s.target,
            limit_policy=self.limits, policy=self.policy, budget=budget)
        if message:
            from memory_vault_open_repair_mailbox_message_copy import select_message_source
            self.envelope_ref = self.snapshot.envelopes[0].as_dict()
            self.event = select_message_source(self.event, self.envelope_ref, self.policy, budget)
        self.source_custody_ref = self.event['custody'].ref.as_dict()
        self.historical_ref = self.event['message_history_ref'] if message else self.manifest['ref']
        controls = self.event['graph']['members'][0]['originals']; self.parent = controls['maintenance']; self.bootstrap = controls['bootstrap']
        self.intent = dict(kind='resource.copy_intent', allocation_id='synthetic_feed_copy', job_id='synthetic_feed_job',
            root_key=self.root, caller=s.target, target=self.target, target_storage_epoch=self.node['payload']['storage_epoch'],
            purpose='message_replica' if message else 'feed_replica', scope=self.event['message_scope'] if message else self.part.scope, historical_manifest_ref=self.historical_ref,
            budget=dict(self.parent.payload['budget'], max_live_bytes=self.envelope_ref['size'] if message else 0), windows={k:self.until for k in self.parent.payload['windows']})
        digest = hashlib.sha256(canonical_bytes(self.intent)).hexdigest()
        self.reservations = {name:self.sign(RESERVATION_KIND, name, dict(consent_id='synthetic_'+name+'_reservation',
            revision=1, variant=name, root_authority_ref=self.parent.ref.as_dict(), source_custody_ref=self.source_custody_ref,
            historical_manifest_ref=self.historical_ref, maintainer=self.dual(s.target), target=self.target,
            target_storage_epoch=self.intent['target_storage_epoch'], reservation_disclosure=dict(intent_sha256=digest, until=self.until)))
            for name in ('owner', 'sender')}
        self.allocation = self.sign('resource.allocate', 'maintainer', dict(request_id='synthetic_feed_allocate',
            target_node_key_id=self.identity.key_id, target_storage_epoch=self.intent['target_storage_epoch'], intent=self.intent, intent_sha256=digest))
        self.offer = self.store.allocate(self.allocation, expected_caller=s.target)
        offer = json.loads(self.offer['raw'])['payload']; self.rid = offer['resource']['resource_id']
        self.assignment = self.sign('maintenance.assignment', 'maintainer', dict(assignment_id='synthetic_feed_assignment',
            job_id=self.intent['job_id'], root_key=self.root, parent_root_ref=self.parent.ref.as_dict(), parent_assignment_ref=None,
            depth=2, subject=self.dual(self.target), target_node_key_id=self.identity.key_id,
            target_storage_epoch=self.intent['target_storage_epoch'], operation_mask=70, scope=self.intent['scope'],
            resource_intent_sha256=digest, resource_offer_ref=self.offer['ref'], resource=offer['resource'],
            bootstrap_grant_refs=[self.bootstrap.ref.as_dict()], budget=self.intent['budget'], windows=self.intent['windows']))
        from memory_vault_open_repair_copy_prepare import CONSENT_FIELDS
        reservations = {name:index._signed(e, self.parties[name]['signing_key'], RESERVATION_KIND,
            CONSENT_FIELDS|{'variant'}, self.policy, budget) for name,e in self.reservations.items()}
        self.rows = feed_copy_inventory(self.event, reservations, self.policy, budget)
        self.disclosures = {}
        for name in ('owner', 'source', 'sender'):
            originals, scopes = feed_disclosure_permissions(self.rows, self.signers[name].key_id, self.root, self.policy, budget)
            self.disclosures[name] = self.sign(DISCLOSURE_KIND, name, dict(consent_id='synthetic_'+name+'_disclosure', revision=1,
                variant=name, root_key=self.root, assignment_ref=self.assignment['ref'], source_custody_ref=self.source_custody_ref,
                historical_manifest_ref=self.historical_ref, target=self.target, target_storage_epoch=self.intent['target_storage_epoch'],
                disclosure=dict(originals=originals, status_scopes=scopes, until=self.until)))
        entries = {}; revisions = {}
        for row in self.rows:
            value = json.loads(row.original.raw).get('payload', {})
            if value.get('kind') != 'authority.status': continue
            issuer = value['signing_key']['key_id']; revisions[issuer] = max(revisions.get(issuer,0), value['revision'])
            for e in value['entries']:
                key = issuer, e['scope_kind'], e['scope_id']; old = entries.get(key)
                entries[key] = dict(e, operation_mask=127, minimum_document_revision=max(e['minimum_document_revision'], old['minimum_document_revision'] if old else 0))
        for name, entry in [*self.reservations.items(), *self.disclosures.items()]:
            p = json.loads(entry['raw'])['payload']; scope_id = status.status_scope(self.root, 'authority',
                dict(authority_kind=p['kind'], authority_sha256=entry['ref']['raw_sha256']), self.policy, budget)
            entries[(self.signers[name].key_id,'authority',scope_id)] = dict(scope_kind='authority', scope_id=scope_id,
                minimum_document_revision=1, status='active', operation_mask=4)
        scope_id = status.status_scope(self.root,'assignment',dict(assignment_kind='maintenance.assignment',assignment_sha256=self.assignment['ref']['raw_sha256']),self.policy,budget)
        entries[(s.identity.key_id,'assignment',scope_id)] = dict(scope_kind='assignment',scope_id=scope_id,minimum_document_revision=0,status='active',operation_mask=70)
        self.statuses = []
        for signer in (fixture.bi,fixture.ai,s.identity):
            values = [value for key,value in sorted(entries.items()) if key[0]==signer.key_id]
            self.statuses.append(self.wrap(canonical_bytes(issue_status(signer,root=self.root,revision=revisions[signer.key_id]+1,
                entries=values,issued_at=self.now,valid_until=self.until))))

    def connect(self):
        path = self.directory/'network.sqlite3'; path.touch(mode=0o600, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.state = RepairAckState(self.db,self.identity,self.node,encryption_identity=self.encryption,
            policy=self.policy,limit_policy=self.limits,clock=lambda:self.now)
        from memory_vault_open_repair_mailbox_message_copy_state import MailboxMessageCopyState
        self.store = (MailboxMessageCopyState if self.message else MailboxFeedCopyState)(self.state); self.store.initialize()

    @staticmethod
    def dual(keys): return dict(signing_key_id=keys['signing_key']['key_id'],encryption_key_id=keys['encryption_key']['key_id'])

    @staticmethod
    def wrap(raw):
        digest=hashlib.sha256(raw).hexdigest()
        return dict(raw=raw,ref=dict(namespace='meta',key=digest,raw_sha256=digest,size=len(raw)))

    def entry(self, ref): return dict(raw=self.snapshot.read(ref.as_dict()),ref=ref.as_dict())

    def sign(self,kind,name,fields):
        signer=self.signers[name]
        p=dict(schema_version='memory-vault-open-repair/v1',kind=kind,signing_key=signer.public_descriptor(),
            issued_at=self.now,expires_at=self.until,**fields)
        return self.wrap(canonical_bytes(dict(payload=p,proof=signer.sign_message(p))))

    def resolver(self):
        result=wire.LocalRawResolver(self.policy,wire.RepairBudget(self.policy))
        for role,ref in self.part.transfer:
            if role=='history.raw_pack':result.put(ref.namespace,ref.key,self.snapshot.read(ref.as_dict()))
        return result

    def context(self):
        return dict(expected_slot=self.slot,expected_owner=self.owner,expected_sender=self.sender,
            expected_source=self.source.target,source_storage_epoch=self.source.node['payload']['storage_epoch'],
            expected_maintainer=self.source.target,limit_policy=self.limits, **(dict(expected_envelope_ref=self.envelope_ref) if self.message else {}))

    def args(self):
        return (self.manifest,self.resolver(),self.custody,self.allocation,self.offer,self.assignment,
            self.reservations['owner'],self.reservations['sender'],self.disclosures['owner'],self.disclosures['source'],self.disclosures['sender'])

    def commit(self):
        if self.message:
            return self.store.commit_message(*self.args(), **self.context(), current_statuses=self.statuses, envelope_entry=self.entry(wire.raw_ref(self.envelope_ref)))
        return self.store.commit_feed(*self.args(),**self.context(),current_statuses=self.statuses)

    @staticmethod
    def encode(entry): return dict(raw_base64url=b64url(entry['raw']),ref=entry['ref'])

    def client_config(self, role, descriptor):
        from cryptography.hazmat.primitives import serialization
        folder=self.directory/('synthetic-'+role+'-client');folder.mkdir(mode=0o700)
        signer=self.signers[role];encryption=self.owner_encryption if role=='owner' else self.source.encryption_identity
        key=folder/'identity.json';enc=folder/'encryption.json';trust=folder/'trust.json';client=folder/'client.json';network=folder/'open.json'
        raw=signer._private_key.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())
        _write_new_private(key,canonical_bytes(dict(signer.public_descriptor(),schema_version='universal-memory-identity/v1',private_key=base64.b64encode(raw).decode())))
        encryption.save(enc);TrustStore(trust).add(signer.public_descriptor())
        _write_new_private(client,canonical_bytes(dict(schema_version='memory-vault-client-config/v1',identity_path=str(key),trust_path=str(trust),
            vault_path=str(folder/'vault'/'memory.sqlite3'),capture_visible_turns=False)))
        _write_new_private(network,canonical_bytes(dict(schema_version='memory-vault-open-client-config/v1',client_config_path=str(client),
            state_directory=str(folder/'transport'),encryption_key_path=str(enc),seeds=[descriptor],allow_loopback=True)))
        return network

    def command(self, name, request, config, *, node=False):
        from memory_vault_open_repair_admin import main
        counter=getattr(self,'command_counter',0);self.command_counter=counter+1
        path=self.directory/('synthetic-request-'+str(counter)+'.json');output=self.directory/('synthetic-result-'+str(counter)+'.json')
        _write_new_private(path,canonical_bytes(request));stdout,stderr=io.StringIO(),io.StringIO()
        args=[name,'--node-config' if node else '--network-config',str(config),'--request',str(path),'--output',str(output)]
        if not node:args+=['--repair-profile','mailbox','--timeout','30']
        with contextlib.redirect_stdout(stdout),contextlib.redirect_stderr(stderr):code=main(args)
        if code:
            from memory_vault import MemoryError
            self.test.assertFalse(output.exists())
            error=json.loads(stderr.getvalue())['error']
            if error=='open_network_unavailable':raise MemoryError(error,retryable=True)
            raise AssertionError(stderr.getvalue())
        import stat
        self.test.assertEqual(stat.S_IMODE(output.stat().st_mode),0o600)
        self.test.assertEqual(json.loads(stdout.getvalue())['recipient_saved'],name=='receive-replica-message')
        return json.loads(output.read_bytes())

    def read_permissions(self):
        from memory_vault_open_repair_mailbox_feed_copy import RETURN_KIND, feed_return_permissions
        if self.message:
            from memory_vault_open_repair_mailbox_message_copy import RETURN_KIND
        replica=self.store.restore_feed(self.rid,**self.context());plan=replica['authority']
        budget=wire.RepairBudget(self.policy);consents={}
        for name in ('owner','source','maintainer','sender'):
            originals,scopes=feed_return_permissions(plan,self.signers[name].key_id,self.policy,budget)
            consents[name]=self.sign(RETURN_KIND,name,dict(consent_id='synthetic_'+name+'_return',revision=1,variant=name,
                root_key=self.root,source_custody_ref=self.source_custody_ref,historical_manifest_ref=self.historical_ref,
                assignment_ref=self.assignment['ref'],subject=self.dual(self.owner),target=self.target,
                target_storage_epoch=self.intent['target_storage_epoch'],bootstrap_grant_ref=self.bootstrap.ref.as_dict(),
                return_permission=dict(originals=originals,status_scopes=scopes,until=self.until)))
        values={item.payload['signing_key']['key_id']:dict(revision=item.payload['revision']+1,
            entries={ (e['scope_kind'],e['scope_id']):dict(e) for e in item.payload['entries']}) for item in plan.statuses}
        for name,consent in consents.items():
            scope=status.status_scope(self.root,'authority',dict(authority_kind=RETURN_KIND,authority_sha256=consent['ref']['raw_sha256']),self.policy,budget)
            values[self.signers[name].key_id]['entries'][('authority',scope)]=dict(scope_kind='authority',scope_id=scope,minimum_document_revision=1,status='active',operation_mask=2)
        scope=status.status_scope(self.root,'resource',replica['custody'].payload['resource'],self.policy,budget)
        values[self.identity.key_id]=dict(revision=1,entries={('resource',scope):dict(scope_kind='resource',scope_id=scope,minimum_document_revision=1,status='active',operation_mask=2)})
        signers={s.key_id:s for s in (*self.signers.values(),self.identity)}
        current=[self.wrap(canonical_bytes(issue_status(signers[issuer],root=self.root,revision=value['revision'],
            entries=[e for _,e in sorted(value['entries'].items())],issued_at=self.now,valid_until=self.until))) for issuer,value in sorted(values.items())]
        return consents,current


class MailboxFeedCopyTests(unittest.TestCase):
    def run_fixture(self, inspect):
        fixture=fixtures.MailboxStagingHTTPTests('test_actual_delivery_stages_exact_ciphertext_under_mailbox_resources')
        fixture.setUp(); self.addCleanup(fixture.doCleanups)
        def receive(staging,slot,head):
            h=FeedCopyFixture(self,fixture,staging,slot,head)
            with patch('time.time',return_value=h.now):inspect(h)
        fixture.inspect_committed_mailbox=receive
        fixture.test_actual_delivery_stages_exact_ciphertext_under_mailbox_resources()

    def test_complete_feed_commit_survives_source_loss_and_replica_restart_without_envelopes(self):
        def inspect(h):
            custody=h.commit(); self.assertEqual(h.commit(),custody)
            self.assertEqual(json.loads(custody['raw'])['payload']['scope'],h.part.scope)
            self.assertEqual(h.db.execute('SELECT count(*) FROM open_repair_copy_commits').fetchone()[0],1)
            self.assertFalse(any(json.loads(row[0])['namespace']=='object' for row in h.db.execute('SELECT ref FROM open_repair_copy_objects')))
            h.source.db.close();h.db.close();h.connect()
            result=h.store.restore_feed(h.rid,**h.context())
            self.assertEqual(result['source']['custody'].raw,h.custody['raw'])
            self.assertEqual(result['source']['graph']['head']['count'],1)
            self.assertEqual(result['custody'].raw,custody['raw'])
            for role,ref in h.part.transfer:
                self.assertEqual(h.store.read_local_original(h.rid,ref.as_dict()),h.snapshot.read(ref.as_dict()))
            for ref in h.snapshot.envelopes:
                with self.assertRaises(wire.RepairWireError):h.store.read_local_original(h.rid,ref.as_dict())
        self.run_fixture(inspect)

    def test_missing_sender_disclosure_and_revocation_cannot_commit_or_reset_after_restart(self):
        def inspect(h):
            real=h.disclosures['sender'];h.disclosures['sender']=h.disclosures['owner']
            with self.assertRaises(wire.RepairWireError):h.commit()
            self.assertEqual(h.db.execute('SELECT count(*) FROM open_repair_copy_commits').fetchone()[0],0)
            h.disclosures['sender']=real
            old=copy.deepcopy(h.statuses);p=json.loads(h.statuses[1]['raw'])['payload'];p['revision']+=1
            for e in p['entries']:e['status']='revoked'
            h.statuses[1]=h.wrap(canonical_bytes(dict(payload=p,proof=h.signers['sender'].sign_message(p))))
            with self.assertRaisesRegex(wire.RepairWireError,'repair_authority_revoked'):h.commit()
            h.db.close();h.connect();h.statuses=old
            with self.assertRaises(wire.RepairWireError):h.commit()
            self.assertEqual(h.db.execute('SELECT count(*) FROM open_repair_copy_commits').fetchone()[0],0)
        self.run_fixture(inspect)

    def test_http_upload_replays_lost_commit_reply_after_both_restarts(self):
        self.http_roundtrip()

    def test_read_sender_revocation_survives_restart_and_old_status_replay(self):
        from dataclasses import replace
        def inspect(h):
            h.commit();consents,current=h.read_permissions()
            h.policy=replace(h.policy,max_signature_checks=512)
            h.db.close();h.connect()
            self.assertEqual(h.store.prepare_feed_read(h.rid,consents,**h.context(),current_statuses=current)['state'],'permission_checked')
            revoked=copy.deepcopy(current)
            for i,e in enumerate(revoked):
                p=json.loads(e['raw'])['payload']
                if p['signing_key']['key_id']!=h.signers['sender'].key_id:continue
                p['revision']+=1
                for row in p['entries']:row['status']='revoked'
                revoked[i]=h.wrap(canonical_bytes(dict(payload=p,proof=h.signers['sender'].sign_message(p))))
            with self.assertRaisesRegex(wire.RepairWireError,'repair_authority_revoked'):
                h.store.prepare_feed_read(h.rid,consents,**h.context(),current_statuses=revoked)
            h.db.close();h.connect()
            with self.assertRaises(wire.RepairWireError):h.store.prepare_feed_read(h.rid,consents,**h.context(),current_statuses=current)
        self.run_fixture(inspect)

    def test_commands_upload_configure_and_recover_with_existing_keys_after_restart(self):
        self.http_roundtrip(commands=True)

    def http_roundtrip(self, commands=False, message=False, upload_only=False, agent=False, registered=False):
        from memory_vault import MemoryError
        from memory_vault_open_node import OpenParticipant, OpenHTTPServer
        from memory_vault_open_transport import OpenHTTPTransport
        from memory_vault_open_repair_mailbox_copy_prepare import MailboxFeedCopyPreparation
        from memory_vault_open_repair_mailbox_copy_client import MailboxFeedCopyUploadClient
        if message:
            from memory_vault_open_repair_mailbox_copy_prepare import MailboxMessageCopyPreparation as MailboxFeedCopyPreparation
            from memory_vault_open_repair_mailbox_copy_client import MailboxMessageCopyUploadClient as MailboxFeedCopyUploadClient
        import threading
        def inspect(h):
            with patch('socket.getfqdn',return_value='localhost'):server=OpenHTTPServer(('127.0.0.1',0),None)
            base='http://127.0.0.1:'+str(server.server_port)
            descriptor=issue_node(h.identity,base_url=base,storage_epoch=h.node['payload']['storage_epoch'],roles=['directory','router'],
                revision=2,issued_at=h.now,expires_at=h.now+300)
            if commands:
                network=h.client_config('source',descriptor);owner_network=h.client_config('owner',descriptor)
                if message:owner_network=h.recipient_agent.network_config
            participants=[];threads=[];errors=[]
            def start():
                participant=OpenParticipant(h.identity,h.directory,seeds=[],descriptor=descriptor,encryption_identity=h.encryption,
                    allow_loopback=True,provider_policy=dict(enabled=True),repair_policy=dict(enabled=True,limit_policy=h.limits))
                handle=participant.handle_repair
                def observed(raw):
                    try:return handle(raw)
                    except Exception as error:
                        import traceback
                        errors.append((getattr(error,'code',type(error).__name__),[(f.name,f.lineno) for f in traceback.extract_tb(error.__traceback__)]));raise
                participant.handle_repair=observed;server.participant=participant
                thread=threading.Thread(target=server.serve_forever,kwargs=dict(poll_interval=.02),daemon=True)
                participants.append(participant);threads.append(thread);thread.start()
            def stop():
                server.shutdown();threads[-1].join(timeout=3);participants[-1].close()
            def close():
                stop();server.server_close()
            start();self.addCleanup(close)
            transport=OpenHTTPTransport(allow_loopback=True);self.addCleanup(transport.close)
            def client():
                db=sqlite3.connect(h.directory/'synthetic-maintainer.sqlite3');self.addCleanup(db.close)
                journal=MailboxFeedCopyPreparation(db,h.source.identity,h.source.encryption_identity,policy=h.policy)
                return MailboxFeedCopyUploadClient(journal,encryption_identity=h.source.encryption_identity,transport=transport,allow_loopback=True),db
            def upload(active):
                context=h.context();context.pop('expected_maintainer')
                try:
                    if commands:
                        from memory_vault_open_repair_mailbox_copy_admin import FEED_UPLOAD_SCHEMA
                        if message:
                            from memory_vault_open_repair_mailbox_copy_admin import MESSAGE_UPLOAD_SCHEMA as FEED_UPLOAD_SCHEMA
                        request=dict(schema_version=FEED_UPLOAD_SCHEMA,node=h.encode(h.wrap(canonical_bytes(descriptor))),
                            root_key=h.root,slot_key=h.slot,sender=h.sender,owner=h.owner,source=h.source.target,
                            source_storage_epoch=h.source.node['payload']['storage_epoch'],target=h.target,target_storage_epoch=h.intent['target_storage_epoch'],
                            originals=[h.encode(h.entry(ref)) for role,ref in h.part.transfer if role=='history.raw_pack'],
                            current_statuses=[h.encode(e) for e in h.statuses],
                            **{name:h.encode(value) for name,value in dict(manifest=h.manifest,custody=h.custody,allocation=h.allocation,offer=h.offer,
                                assignment=h.assignment,reservation=h.reservations['owner'],sender_reservation=h.reservations['sender'],
                                owner_disclosure=h.disclosures['owner'],source_disclosure=h.disclosures['source'],sender_disclosure=h.disclosures['sender']).items()})
                        if message:request['envelope']=h.encode(h.entry(wire.raw_ref(h.envelope_ref)))
                        saved=h.command('copy-upload-message' if message else 'copy-upload-feed',request,network)
                        return dict(state=saved['state'],**{name:dict(raw=unb64url(saved[name]['raw_base64url'],maximum=524288),ref=saved[name]['ref']) for name in ('manifest','custody')})
                    return active.upload(base,*h.args(),**context,expected_target=h.target,target_storage_epoch=h.intent['target_storage_epoch'],
                        target_node_entry=h.wrap(canonical_bytes(descriptor)),current_statuses=h.statuses,timeout=60,
                        **(dict(envelope_entry=h.entry(wire.raw_ref(h.envelope_ref))) if message else {}))
                except MemoryError:
                    if errors:raise AssertionError(errors) from None
                    raise
            active,db=client();send=transport.request_repair;lost=[]
            def lose_reply(base,raw,**options):
                result=send(base,raw,**options)
                if json.loads(raw).get('payload',{}).get('kind')==('mailbox.message_copy_commit' if message else 'mailbox.feed_copy_commit') and not lost:
                    lost.append(raw);raise MemoryError('open_network_unavailable',retryable=True)
                return result
            def lose_cli(client,base,raw,**options):return lose_reply(base,raw,**options)
            # Save the unbound method so command-created transports still send
            # real requests while the one successful commit response is lost.
            native_send=OpenHTTPTransport.request_repair
            if commands:send=lambda base,raw,**options:native_send(transport,base,raw,**options)
            losing=patch.object(OpenHTTPTransport,'request_repair',new=lose_cli) if commands else patch.object(transport,'request_repair',side_effect=lose_reply)
            with losing:
                with self.assertRaises(MemoryError):upload(active)
            self.assertEqual(len(lost),1,errors)
            self.assertEqual(h.db.execute('SELECT count(*) FROM open_repair_copy_commits').fetchone()[0],1)
            db.close();stop();start();active,db=client()
            result=upload(active);self.assertEqual(result['state'],'replica_committed')
            self.assertEqual(upload(active),result)
            self.assertEqual(errors,[])
            if upload_only:
                h.source.db.close();h.db.close();h.connect()
                recovered=h.store.restore_message(h.rid,**h.context())
                self.assertEqual(recovered['custody'].raw,result['custody']['raw'])
                self.assertEqual(h.store.read_local_original(h.rid,h.envelope_ref),h.snapshot.read(h.envelope_ref))
                return
            from dataclasses import replace
            from memory_vault_open_repair_mailbox_copy_service import MailboxFeedReplicaReadService
            from memory_vault_open_repair_mailbox_copy_client import MailboxFeedReplicaRecoveryClient
            if message:
                from memory_vault_open_repair_mailbox_copy_service import MailboxMessageReplicaReadService as MailboxFeedReplicaReadService
                from memory_vault_open_repair_mailbox_copy_client import MailboxMessageReplicaRecoveryClient as MailboxFeedReplicaRecoveryClient
            consents,current=h.read_permissions();context=h.context();context.pop('limit_policy')
            if commands:
                from memory_vault_open_node import NODE_CONFIG
                h.encryption.save(h.directory/'encryption.json');config=h.directory/'synthetic-node.json'
                _write_new_private(config,canonical_bytes(dict(schema_version=NODE_CONFIG,identity_path=str(h.directory/'identity.json'),
                    encryption_key_path=str(h.directory/'encryption.json'),state_directory=str(h.directory),node=descriptor,seeds=[],allow_loopback=True,
                    index_policy=dict(enabled=False),repair_policy=dict(enabled=True,limit_policy=h.limits),listen_host='127.0.0.1',listen_port=server.server_port)))
                configured=h.command('configure-replica-message' if message else 'configure-replica-feed',dict(schema_version='memory-vault-open-mailbox-'+('message' if message else 'feed')+'-replica-read-config/v1',
                    resource_id=h.rid,context=context,consents={name:h.encode(e) for name,e in consents.items()},current_statuses=[h.encode(e) for e in current]),config,node=True)
                self.assertEqual(configured['state'],'configured')
            else:
                with participants[-1].state.db() as configured:
                    service=MailboxFeedReplicaReadService(participants[-1]._repair_service(configured,mailbox_workflow=True).state)
                    service.initialize();service.configure(h.rid,context=context,consents=consents,current_statuses=current)
            h.source.db.close()
            stop();start()
            restored=h.store.restore_feed(h.rid,**h.context())
            self.assertEqual(restored['source']['custody'].ref.as_dict(),h.source_custody_ref)
            reader=MailboxFeedReplicaRecoveryClient(h.signers['owner'],h.owner_encryption,
                policy=replace(h.policy,max_signature_checks=512),limit_policy=h.limits,transport=transport,allow_loopback=True,clock=lambda:h.now)
            setup=restored['source']['graph']['members'][0]['originals']
            if commands:
                from memory_vault_open_repair_mailbox_copy_admin import FEED_RECOVER_SCHEMA
                if message:
                    from memory_vault_open_repair_mailbox_copy_admin import MESSAGE_RECOVER_SCHEMA as FEED_RECOVER_SCHEMA
                if agent:
                    from memory_vault_open_client import MAILBOX_CONNECT_SCHEMA
                    encode=lambda entry:dict(raw=entry['raw'].decode('utf-8'),ref=entry['ref'])
                    invitation=dict(schema_version=MAILBOX_CONNECT_SCHEMA,action='receive_replica',base_url=base,repair_profile='mailbox',
                        request=dict(expected_slot=h.slot,expected_sender=h.sender,expected_target=h.target,expected_source=h.source.target,
                            source_storage_epoch=h.source.node['payload']['storage_epoch'],expected_maintainer=h.source.target,
                            expected_envelope_ref=h.envelope_ref,target_node_entry=encode(h.wrap(canonical_bytes(descriptor))),
                            slot_entries={name:encode(index._entry(setup[name])) for name in ('slot','read','maintenance','bootstrap')},
                            known_statuses=[],archive_statuses=[]))
                    from tests.test_open_delivery_http import repair_failure_diagnostics
                    try:
                        with repair_failure_diagnostics():
                            if registered:
                                registration=dict(invitation,action='register_replica')
                                configured=h.call_agent(h.recipient_agent,op='connect',invitation=registration)
                                self.assertEqual(configured['state'],'registered');self.assertFalse(configured['network_accessed'])
                                self.assertEqual(h.call_agent(h.recipient_agent,op='connect',invitation=registration),configured)
                                if hasattr(self,'inspect_registration'):self.inspect_registration(h,registration,configured)
                                received=h.call_agent(h.recipient_agent,op='receive')
                            else:received=h.call_agent(h.recipient_agent,op='connect',invitation=invitation)
                    except AssertionError as error:raise AssertionError((str(error),errors)) from None
                    if not registered:self.assertEqual(received['body_transport'],'mailbox_message_replica')
                    self.assertTrue(received.get('messages'),received)
                    self.assertEqual(received['messages'][0]['share']['records_added'],1)
                    self.assertTrue(received['network_accessed'])
                    # Agent operations reopen the protected state, including
                    # exact inbox evidence and retained status observations.
                    if registered:
                        original_request_node=OpenHTTPTransport.request_node
                        def no_saved_replica(transport, origin, **options):
                            if origin.rstrip('/')==base.rstrip('/'):raise AssertionError('saved replica was polled again')
                            return original_request_node(transport,origin,**options)
                        with patch.object(OpenHTTPTransport,'request_node',new=no_saved_replica):
                            repeated=h.call_agent(h.recipient_agent,op='receive')
                    else:repeated=h.call_agent(h.recipient_agent,op='connect',invitation=invitation)
                    self.assertEqual(repeated['messages'],[])
                    with h.recipient_agent._network() as network:
                        with network.participant.state.db() as db:
                            self.assertGreater(db.execute('SELECT count(*) FROM open_ack_replica_statuses').fetchone()[0],0)
                    recalled=h.call_agent(h.recipient_agent,op='recall',query='Synthetic mailbox memory')
                    self.assertTrue(any(hit['text']=='Synthetic mailbox memory: consult current evidence before reuse.' for hit in recalled['hits']))
                    if registered and hasattr(self,'inspect_received_registration'):self.inspect_received_registration(h,registration,configured)
                    return
                recovered=h.command('receive-replica-message' if message else 'recover-replica-feed',dict(schema_version=FEED_RECOVER_SCHEMA,node=h.encode(h.wrap(canonical_bytes(descriptor))),
                    root_key=h.root,slot_key=h.slot,sender=h.sender,target=h.target,source=h.source.target,
                    source_storage_epoch=h.source.node['payload']['storage_epoch'],maintainer=h.source.target,known_statuses=[],archive_statuses=[],
                    slot_entries={name:h.encode(index._entry(setup[name])) for name in ('slot','read','maintenance','bootstrap')},
                    **(dict(envelope_ref=h.envelope_ref) if message else {})),owner_network)
                if message:
                    self.assertEqual(recovered['state'],'mailbox_message_replica_received')
                    self.assertTrue(recovered['recipient_saved']);self.assertTrue(recovered['vault_modified'])
                    self.assertEqual(recovered['result']['share']['records_added'],1)
                    self.assertEqual(recovered['replica_custody'],h.encode(result['custody']))
                    recalled=h.call_agent(h.recipient_agent,op='recall',query='Synthetic mailbox memory')
                    self.assertTrue(any(hit['text']=='Synthetic mailbox memory: consult current evidence before reuse.' for hit in recalled['hits']))
                    if registered and hasattr(self,'inspect_received_registration'):self.inspect_received_registration(h,registration,configured)
                    return
                self.assertEqual(len(recovered['members']),1)
                self.assertEqual(recovered['state'],'mailbox_feed_replica_recovered')
                self.assertEqual(recovered['replica_custody'],h.encode(result['custody']))
                self.assertFalse((network.parent/'vault'/'memory.sqlite3').exists())
                self.assertFalse((owner_network.parent/'vault'/'memory.sqlite3').exists())
                return
            try:
                recovered=reader.recover(base,target_node_entry=h.wrap(canonical_bytes(descriptor)),expected_target=h.target,
                    expected_slot=h.slot,expected_sender=h.sender,expected_source=h.source.target,
                    source_storage_epoch=h.source.node['payload']['storage_epoch'],expected_maintainer=h.source.target,
                    slot_entries={name:index._entry(setup[name]) for name in ('slot','read','maintenance','bootstrap')},timeout=30,
                    **(dict(expected_envelope_ref=h.envelope_ref) if message else {}))
            except MemoryError:raise AssertionError(errors) from None
            self.assertEqual(len(recovered.members),1)
            self.assertEqual(recovered.replica['source']['custody'].ref.as_dict(),h.source_custody_ref)
            self.assertEqual(recovered.replica['custody'].raw,result['custody']['raw'])
            if message:
                try:delivery=reader.read_message(base,recovered,timeout=30)
                except MemoryError:raise AssertionError(errors) from None
                self.assertEqual(delivery['envelope'],h.snapshot.read(h.envelope_ref))
                self.assertEqual(delivery['core']['envelope_ref'],h.envelope_ref)
                if hasattr(self,'verify_replica_delivery'):
                    self.verify_replica_delivery(h,reader,recovered,delivery,descriptor)
            self.assertEqual(errors,[])
        self.run_fixture(inspect)
