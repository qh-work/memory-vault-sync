"""Node resource facts from actual synthetic mailbox reservations."""
import json
import unittest

from memory_vault_open_repair_mailbox_source import MailboxRootSource
from memory_vault_open_repair_mailbox_root import MailboxRootActivation
from memory_vault_open_repair_state import DEFAULT_POLICY
import memory_vault_open_repair_status as status
from memory_vault_open_repair_wire import RepairBudget, RepairWireError
from tests import test_open_repair_mailbox_root as root_fixture


class MailboxSourceTests(unittest.TestCase):
    def setUp(self):
        self.host = root_fixture.MailboxRootTests("test_anchor_catalog_and_slot_originals_persist_and_replay_after_restart")
        if "history" in self._testMethodName or "custody" in self._testMethodName:
            self.host.anchor_budget_overrides = dict(max_meta_bytes=1048576)
        if "recovery" in self._testMethodName:
            from tests.open_repair_ack_fixtures import LIMITS
            self.host.bootstrap_limits = dict(LIMITS,max_probe_bytes=8192,max_signature_checks=512,max_proof_bytes=524288)
            self.host.owner_budget_overrides = dict(max_requests=512,max_job_bytes=524288,max_meta_bytes=524288)
            from memory_vault_open_repair_state import DEFAULT_LIMITS
            self.host.source_limit_policy = dict(DEFAULT_LIMITS,max_proof_bytes=524288)
        self.host.setUp();self.addCleanup(self.host.doCleanups)
        active = self.host.activate()
        self.resource_id = json.loads(active["raw"])["payload"]["resource"]["resource_id"]
        self.source = MailboxRootSource(self.host.state);self.source.initialize()
        self.until = self.host.h.now+100

    def observe(self,request="synthetic_observation",**options):
        return self.source.observe_resources(self.resource_id,request,valid_until=self.until,**options)

    def owner_observation(self):
        import memory_vault_open_provider as provider
        from tests.test_open_repair_status import status_entry
        context = self.host.state.owner_status_context(self.resource_id)
        value = status_entry(provider.issue_status(self.host.h.f["signers"]["owner"],root=self.host.h.root,revision=1,
            entries=[dict(scope_kind=v["scope_kind"],scope_id=v["scope_id"],minimum_document_revision=1,
                status="active",operation_mask=127) for v in context["required"]],
            issued_at=self.host.h.now,valid_until=self.until))
        self.host.state.observe_owner_status(self.resource_id,value)
        return value

    def test_history_pins_complete_originals_and_replays_after_restart(self):
        import memory_vault_open_repair_wire as wire
        import memory_vault_open_repair_history as history
        owner = self.owner_observation(); node = self.observe()[0]
        saved = self.source.prepare_history(self.resource_id,"synthetic_observation")
        budget = RepairBudget(DEFAULT_POLICY)
        resolver = wire.LocalRawResolver(DEFAULT_POLICY,budget)
        resolver.put("meta",saved["pack"]["ref"]["key"],saved["pack"]["raw"])
        resolved = history.resolve_historical_inputs(saved["manifest"]["raw"],resolver,DEFAULT_POLICY,budget)
        self.assertEqual({v.role for v in resolved.roles},history._ROLES["mailbox_root"])
        for v in resolved.roles:
            if v.role.startswith("historical.status."):
                self.assertEqual(v.original.raw,node["raw"] if v.role.endswith("_resource") else owner["raw"])
        before = self.host.h.db.execute("SELECT metadata_bytes FROM open_repair_mailbox_resources WHERE resource_id=?",(self.resource_id,)).fetchone()
        self.host.h.db.close();self.host.h.now += 1000;self.host.h.connect()
        self.source = MailboxRootSource(MailboxRootActivation(self.host.h.resources));self.source.initialize()
        self.assertEqual(self.source.prepare_history(self.resource_id,"synthetic_observation"),saved)
        self.assertEqual(self.host.h.db.execute("SELECT metadata_bytes FROM open_repair_mailbox_resources WHERE resource_id=?",(self.resource_id,)).fetchone(),before)

    def test_history_requires_current_owner_and_complete_resource_observation(self):
        self.observe()
        with self.assertRaisesRegex(RepairWireError,"repair_status_missing"):
            self.source.prepare_history(self.resource_id,"synthetic_observation")
        self.owner_observation()
        self.observe("synthetic_selected",slot_keys=[self.host.h.slot_key])
        with self.assertRaisesRegex(RepairWireError,"repair_status_missing"):
            self.source.prepare_history(self.resource_id,"synthetic_selected")
        self.assertEqual(self.host.h.db.execute("SELECT count(*) FROM open_repair_mailbox_root_history").fetchone()[0],0)

    def test_history_failed_commit_preserves_capacity_and_allows_retry(self):
        self.owner_observation();self.observe()
        before = self.host.h.db.execute("SELECT metadata_bytes FROM open_repair_mailbox_resources WHERE resource_id=?",(self.resource_id,)).fetchone()
        calls = []
        def guard():
            calls.append(True)
            return "synthetic_closed" if len(calls)==2 else None
        with self.assertRaisesRegex(RepairWireError,"synthetic_closed"):
            self.source.prepare_history(self.resource_id,"synthetic_observation",_transaction_guard=guard)
        self.assertEqual(self.host.h.db.execute("SELECT count(*) FROM open_repair_mailbox_root_history").fetchone()[0],0)
        self.assertEqual(self.host.h.db.execute("SELECT metadata_bytes FROM open_repair_mailbox_resources WHERE resource_id=?",(self.resource_id,)).fetchone(),before)
        self.source.prepare_history(self.resource_id,"synthetic_observation")

    def test_history_status_expiring_during_commit_leaves_no_promise(self):
        self.owner_observation();self.observe()
        calls = []
        def guard():
            calls.append(True)
            if len(calls)==2:
                self.host.h.now = self.until
        with self.assertRaises(RepairWireError):
            self.source.prepare_history(self.resource_id,"synthetic_observation",_transaction_guard=guard)
        self.assertEqual(self.host.h.db.execute("SELECT count(*) FROM open_repair_mailbox_root_history").fetchone()[0],0)

    def test_history_never_expands_the_signed_resource_capacity(self):
        self.owner_observation();self.observe()
        self.host.h.db.execute("UPDATE open_repair_mailbox_resources SET metadata_bytes=1048576 WHERE resource_id=?",(self.resource_id,))
        self.host.h.db.commit()
        with self.assertRaisesRegex(RepairWireError,"repair_insufficient_capacity"):
            self.source.prepare_history(self.resource_id,"synthetic_observation")
        self.assertEqual(self.host.h.db.execute("SELECT count(*) FROM open_repair_mailbox_root_history").fetchone()[0],0)
        self.assertEqual(self.host.h.db.execute("SELECT metadata_bytes FROM open_repair_mailbox_resources WHERE resource_id=?",(self.resource_id,)).fetchone()[0],1048576)

    def custody(self,**options):
        return self.source.finalize_root(self.resource_id,read_until=self.until,retain_until=self.until,**options)

    def test_custody_survives_restart_and_reads_every_exact_original(self):
        self.owner_observation();self.observe()
        saved = self.source.prepare_history(self.resource_id,"synthetic_observation")
        custody = self.custody()
        payload = json.loads(custody["raw"])["payload"]
        self.assertEqual(payload["kind"],"root.custody")
        self.assertEqual(payload["historical_manifest_ref"],saved["manifest"]["ref"])
        self.assertEqual(len(payload["resource_refs"]["feeds"]),1)
        self.host.h.db.close();self.host.h.connect()
        self.source = MailboxRootSource(MailboxRootActivation(self.host.h.resources));self.source.initialize()
        self.assertEqual(self.custody(),custody)
        for value in (*saved.values(),custody):
            self.assertEqual(self.source.read_local_original(self.resource_id,value["ref"]),value["raw"])
        for role in json.loads(saved["manifest"]["raw"])["roles"]:
            raw = self.source.read_local_original(self.resource_id,role["document_ref"])
            import hashlib
            self.assertEqual(hashlib.sha256(raw).hexdigest(),role["document_ref"]["raw_sha256"])
        self.host.h.now = self.until
        self.assertEqual(self.custody(),custody)
        with self.assertRaisesRegex(RepairWireError,"repair_resource_expired"):
            self.source.read_local_original(self.resource_id,custody["ref"])

    def test_custody_requires_history_and_refuses_different_retry(self):
        self.owner_observation();self.observe()
        with self.assertRaisesRegex(RepairWireError,"repair_mailbox_history_missing"):
            self.custody()
        self.source.prepare_history(self.resource_id,"synthetic_observation")
        self.custody()
        with self.assertRaisesRegex(RepairWireError,"repair_custody_conflict"):
            self.source.finalize_root(self.resource_id,read_until=self.until-1,retain_until=self.until)
        altered = dict(self.host.offer["ref"],key="a"*64)
        with self.assertRaisesRegex(RepairWireError,"repair_ref_missing"):
            self.source.read_local_original(self.resource_id,altered)

    def test_custody_final_expiry_rolls_back_event_and_charge(self):
        self.owner_observation();self.observe()
        self.source.prepare_history(self.resource_id,"synthetic_observation")
        before = self.host.h.db.execute("SELECT metadata_bytes FROM open_repair_mailbox_resources WHERE resource_id=?",(self.resource_id,)).fetchone()
        calls = []
        def guard():
            calls.append(True)
            if len(calls)==2:
                self.host.h.now = self.until
        with self.assertRaises(RepairWireError):
            self.custody(_transaction_guard=guard)
        self.assertEqual(self.host.h.db.execute("SELECT count(*) FROM open_repair_mailbox_root_custody").fetchone()[0],0)
        self.assertEqual(self.host.h.db.execute("SELECT metadata_bytes FROM open_repair_mailbox_resources WHERE resource_id=?",(self.resource_id,)).fetchone(),before)

    def test_custody_partial_loss_cannot_create_a_new_original_promise(self):
        self.owner_observation();self.observe()
        self.source.prepare_history(self.resource_id,"synthetic_observation")
        self.custody()
        self.host.h.db.execute("DELETE FROM open_repair_mailbox_root_custody")
        self.host.h.db.commit()
        self.host.h.now += 1
        with self.assertRaisesRegex(RepairWireError,"repair_mailbox_custody_missing"):
            self.custody()

    def test_history_detached_resource_verifier_rejects_signed_capacity_change(self):
        import copy
        import memory_vault_open_repair_resource as resource
        from tests.open_repair_ack_fixtures import signed_entry
        h = self.host.h
        anchor = h.source._one("SELECT * FROM open_repair_mailbox_roots WHERE resource_id=?",(self.resource_id,))
        row = h.source._one("SELECT * FROM open_repair_mailbox_resources WHERE resource_id=?",(self.resource_id,))
        held = json.loads(bytes(anchor["inputs"]))
        activation = dict(raw=held["activation"]["raw"].encode(),ref=held["activation"]["ref"])
        p = json.loads(activation["raw"])["payload"]
        entries = dict(allocate=h.source._saved(row,"allocation"),offer=h.source._saved(row,"offer"),
            activation=activation,active=h.source._saved(anchor,"active"))
        expected = dict(expected_root=h.root,expected_owner=h.owner,expected_target=h.source.target,
            target_storage_epoch=h.source.node["payload"]["storage_epoch"],expected_purpose="anchor_catalog",
            expected_scope=p["scope"],expected_authority_refs=p["authority_refs"],expected_offer_refs=p["resource_offer_refs"],at=h.now)
        # The verifier receives only bytes and independently supplied expectations.
        # Close the database to ensure it cannot consult or trust local state.
        h.db.close()
        def verify(values=entries,**changes):
            return resource.verify_mailbox_resource_inputs(values,**(expected|changes),
                policy=DEFAULT_POLICY,budget=RepairBudget(DEFAULT_POLICY))
        self.assertEqual(set(verify()),set(entries))
        changed = copy.deepcopy(json.loads(entries["active"]["raw"])["payload"])
        changed["budget"]["max_meta_bytes"] += 1
        modified = dict(entries,active=signed_entry(changed,h.f["signers"]["target"],"synthetic_changed_active"))
        with self.assertRaises(RepairWireError):
            verify(modified)
        with self.assertRaises(RepairWireError):
            verify(target_storage_epoch="synthetic_wrong_epoch")
        with self.assertRaises(RepairWireError):
            verify(expected_target=h.owner)
        with self.assertRaises(RepairWireError):
            verify(expected_authority_refs=[])
        h.connect()

    def test_custody_detached_complete_verifier_rejects_overpromise_and_missing_status(self):
        import copy
        import hashlib
        import memory_vault_open_repair_wire as wire
        import memory_vault_open_repair_history as history
        from memory_vault_open_repair_mailbox_root import verify_mailbox_root_source_event
        from tests.open_repair_ack_fixtures import signed_entry
        self.owner_observation();self.observe()
        saved = self.source.prepare_history(self.resource_id,"synthetic_observation")
        custody = self.custody()
        h = self.host.h
        expected = dict(expected_root=h.root,expected_owner=h.owner,expected_target=h.source.target,
            target_storage_epoch=h.slot_key["writer_storage_epoch"],limit_policy=h.source.limits)
        h.db.close()
        def verify(event=custody,manifest=saved["manifest"],**changes):
            budget=RepairBudget(DEFAULT_POLICY);resolver=wire.LocalRawResolver(DEFAULT_POLICY,budget)
            resolver.put("meta",saved["pack"]["ref"]["key"],saved["pack"]["raw"])
            return verify_mailbox_root_source_event(manifest,resolver,event,**(expected|changes),policy=DEFAULT_POLICY,budget=budget)
        self.assertEqual(verify()["custody"].raw,custody["raw"])
        p=json.loads(custody["raw"])["payload"]
        changed=copy.deepcopy(p);changed["retain_until"] += 10000
        with self.assertRaises(RepairWireError):
            verify(signed_entry(changed,h.f["signers"]["target"],"synthetic_overpromise"))
        with self.assertRaises(RepairWireError):
            verify(expected_target=h.owner)
        m=json.loads(saved["manifest"]["raw"])
        m["roles"]=[v for v in m["roles"] if v["role"]!="historical.status.root_read"]
        raw=history.build_historical_manifest(m,DEFAULT_POLICY,RepairBudget(DEFAULT_POLICY)).raw
        digest=hashlib.sha256(raw).hexdigest()
        incomplete=dict(raw=raw,ref=dict(namespace="meta",key=digest,raw_sha256=digest,size=len(raw)))
        changed=copy.deepcopy(p);changed["historical_manifest_ref"]=incomplete["ref"]
        with self.assertRaisesRegex(RepairWireError,"repair_status_missing"):
            verify(signed_entry(changed,h.f["signers"]["target"],"synthetic_incomplete_custody"),incomplete)
        h.connect()

    def http_service(self, h, *, remote_setup=False):
        import threading
        import time
        from unittest.mock import patch
        from memory_vault_open_node import OpenParticipant, OpenHTTPServer
        from memory_vault_open_transport import OpenHTTPTransport
        self.enterContext(patch("time.time",side_effect=lambda:h.now))
        participant=OpenParticipant(h.source.identity,h.path.parent,seeds=[],descriptor=h.f["docs"]["descriptor"],
            encryption_identity=h.source.encryption_identity,allow_loopback=True,
            repair_policy=dict(enabled=True,limit_policy=dict(h.source.limits),remote_setup=dict(enabled=remote_setup)))
        server=OpenHTTPServer(("127.0.0.1",0),participant)
        thread=threading.Thread(target=server.serve_forever,kwargs=dict(poll_interval=.02),daemon=True);thread.start()
        def close():
            server.shutdown();server.server_close();thread.join(timeout=3);participant.close()
        self.addCleanup(close)
        transport=OpenHTTPTransport(allow_loopback=True);self.addCleanup(transport.close)
        base="http://127.0.0.1:"+str(server.server_port)
        class Remote:
            def initialize(self):
                pass
            def challenge(self,packet):
                raw=transport.request_repair(base,packet["raw"],deadline=time.monotonic()+15)
                import hashlib
                digest=hashlib.sha256(raw).hexdigest()
                return dict(raw=raw,ref=dict(namespace="meta",key=digest,raw_sha256=digest,size=len(raw)))
            def answer(self,packet):
                return transport.request_repair(base,packet["raw"],deadline=time.monotonic()+15)
            def child(self,packet):
                return transport.request_repair(base,packet["raw"],child=True,deadline=time.monotonic()+15)
        remote=Remote();remote.participant=participant;remote.base_url=base
        return remote

    def test_custody_recovery_rejects_tampered_pack_over_http(self):
        self.corrupt_history_pack=True
        self.test_custody_recovery_client_fetches_http_and_rejects_retained_revocation()

    def test_custody_recovery_client_fetches_http_and_rejects_retained_revocation(self):
        from memory_vault_open_repair_client import MailboxRootRecoveryClient
        from memory_vault_open_repair_mailbox_source import MailboxRecoveryService
        from tests.open_repair_ack_fixtures import signed_entry
        from tests.test_open_repair_status import status_entry
        import memory_vault_open_provider as provider
        from unittest.mock import patch
        self.owner_observation();self.observe();self.source.prepare_history(self.resource_id,"synthetic_observation");custody=self.custody()
        h=self.host.h;MailboxRecoveryService(self.source).initialize();remote=self.http_service(h)
        node=dict(h.f["docs"]["descriptor"]["payload"],base_url=remote.base_url)
        node_entry=signed_entry(node,h.f["signers"]["target"],"synthetic_http_node")
        held=json.loads(bytes(h.source._one("SELECT inputs FROM open_repair_mailbox_roots")["inputs"]))
        options=dict(target_node_entry=node_entry,expected_target=h.source.target,expected_root=h.root,
            **{name+"_entry":dict(raw=held[name]["raw"].encode(),ref=held[name]["ref"]) for name in ("root","read","bootstrap")})
        observed=[]
        client=MailboxRootRecoveryClient(h.f["signers"]["owner"],h.f["encryption"]["owner"],limit_policy=dict(h.source.limits),
            allow_loopback=True,clock=lambda:h.now,status_observer=observed.append)
        self.addCleanup(client.close)
        import base64
        manifest_children={};downloaded=[]
        real_request=client.transport.request_repair
        corrupt_pack=[getattr(self,"corrupt_history_pack",False)]
        def traced(base,raw,**kwargs):
            value=real_request(base,raw,**kwargs)
            if kwargs.get('child'):
                index=json.loads(raw)['payload']['child_index'];child=manifest_children[index]
                downloaded.append(json.dumps(child['ref'],sort_keys=True))
                if corrupt_pack[0] and child['role']=='history.raw_pack':
                    return bytes([value[0]^1])+value[1:]
            else:
                wrapper=json.loads(value)
                if 'manifest_raw_base64url' in wrapper:
                    encoded=wrapper['manifest_raw_base64url']
                    manifest=json.loads(base64.urlsafe_b64decode(encoded+'='*((-len(encoded))%4)))
                    manifest_children.update({item['index']:item for item in manifest['children']})
            return value
        with patch.object(client.transport,'request_repair',traced):
            if corrupt_pack[0]:
                with self.assertRaisesRegex(RepairWireError,'repair_ref_mismatch'):
                    client.recover(remote.base_url,**options)
                return
            result=client.recover(remote.base_url,**options)
        packed_refs={json.dumps(row.original.ref.as_dict(),sort_keys=True) for row in result.source['manifest'].roles}
        self.assertFalse(set(downloaded)&packed_refs,'already packed originals were fetched twice')

        self.assertEqual(result.source["custody"].raw,custody["raw"])
        self.assertGreater(result.metrics["requests"],2)
        self.assertTrue(observed)
        context=self.source.root.owner_status_context(self.resource_id)
        revoked=status_entry(provider.issue_status(h.f["signers"]["owner"],root=h.root,revision=2,
            entries=[dict(scope_kind=v["scope_kind"],scope_id=v["scope_id"],minimum_document_revision=1,status="revoked",operation_mask=127)
                for v in context["required"]],issued_at=h.now,valid_until=h.now+100))
        with patch.object(client.transport,"request_repair",side_effect=AssertionError("unexpected network after known revocation")):
            with self.assertRaisesRegex(RepairWireError,"repair_authority_revoked"):
                client.recover(remote.base_url,**options,known_statuses=[revoked])
            altered=json.loads(options["read_entry"]["raw"])["payload"]
            altered["reader"]=dict(signing_key_id=h.source.identity.key_id,encryption_key_id=h.source.encryption_identity.key_id)
            bad=dict(options,read_entry=signed_entry(altered,h.f["signers"]["owner"],"synthetic_wrong_reader"))
            with self.assertRaises(RepairWireError):
                client.recover(remote.base_url,**bad)

    def test_custody_recovery_full_http_originals(self):
        self.test_custody_recovery_challenge_persists_and_proves_node_keys()

    def test_custody_recovery_challenge_persists_and_proves_node_keys(self):
        import memory_vault_open_repair_probe as probe
        from memory_vault_open_repair_mailbox_source import MailboxRecoveryService
        self.owner_observation();self.observe();self.source.prepare_history(self.resource_id,"synthetic_observation");self.custody()
        h=self.host.h
        service=MailboxRecoveryService(self.source);service.initialize()
        if "http" in self._testMethodName:
            service=self.http_service(h)
        saved=json.loads(bytes(h.source._one("SELECT inputs FROM open_repair_mailbox_roots")["inputs"]))["bootstrap"]
        grant=json.loads(saved["raw"])["payload"]
        expected=dict(expected_subject=h.owner,expected_target=h.source.target,target_storage_epoch=h.slot_key["writer_storage_epoch"],
            bootstrap_grant_sha256=saved["ref"]["raw_sha256"],selector=grant["selector"],at=h.now,consumer="mailbox_root")
        def opts():
            return dict(**expected,policy=DEFAULT_POLICY,budget=RepairBudget(DEFAULT_POLICY))
        pending=probe.make_bootstrap_probe(h.f["signers"]["owner"],expires_at=h.now+40,**opts())
        packet=dict(raw=pending.original.raw,ref=pending.original.ref.as_dict())
        challenge=service.challenge(packet)
        answer=probe.solve_bootstrap_challenge(packet,challenge,signer=h.f["signers"]["owner"],
            encryption_identity=h.f["encryption"]["owner"],target_nonce=pending.nonce,expires_at=h.now+30,**opts())
        response=service.answer(dict(raw=answer.raw,ref=answer.ref.as_dict()))
        import memory_vault_open_repair_proof as proof
        checked=proof.verify_bootstrap_proof_response(response,expected_subject=h.owner,expected_target=h.source.target,
            target_storage_epoch=h.slot_key["writer_storage_epoch"],selector=grant["selector"],bootstrap_grant_ref=saved["ref"],
            probe_ref=packet["ref"],challenge_ref=challenge["ref"],answer_ref=answer.ref.as_dict(),at=h.now,
            max_proof_items=64,max_proof_bytes=524288,consumer="mailbox_root",expected_source_state="root",
            policy=DEFAULT_POLICY,budget=RepairBudget(DEFAULT_POLICY))
        self.assertIn("root.custody",{v["role"] for v in checked.manifest.value["children"]})
        held=h.source._one("SELECT * FROM open_repair_mailbox_recovery_challenges")
        probe.verify_bootstrap_answer(packet,challenge,dict(raw=answer.raw,ref=answer.ref.as_dict()),caller_nonce=bytes(held["nonce"]),**opts())
        self.assertGreater(h.source._one("SELECT signatures FROM open_repair_mailbox_recovery_usage")["signatures"],0)
        h.db.close();h.connect()
        self.source=MailboxRootSource(MailboxRootActivation(h.resources))
        if "http" not in self._testMethodName:
            service=MailboxRecoveryService(self.source);service.initialize()
        self.assertEqual(service.challenge(packet),challenge)
        prior=h.source._one("SELECT proof_bytes FROM open_repair_mailbox_recovery_responses")["proof_bytes"]
        self.assertEqual(service.answer(dict(raw=answer.raw,ref=answer.ref.as_dict())),response)
        self.assertGreater(h.source._one("SELECT proof_bytes FROM open_repair_mailbox_recovery_responses")["proof_bytes"],prior)
        self.assertEqual(h.source._one("SELECT requests FROM open_repair_mailbox_recovery_usage")["requests"],4)
        import hashlib
        received={}
        for child in checked.manifest.value["children"]:
            chunks=[]
            for offset in range(0,child["ref"]["size"],65536):
                request=proof.make_bootstrap_child_request(h.f["signers"]["owner"],checked,subject=h.owner,target=h.source.target,
                    at=h.now,expires_at=h.now+20,child_index=child["index"],offset=offset,
                    requested_bytes=min(65536,child["ref"]["size"]-offset),policy=DEFAULT_POLICY,budget=RepairBudget(DEFAULT_POLICY))
                try:
                    chunks.append(service.child(dict(raw=request.raw,ref=request.ref.as_dict())))
                except RepairWireError as exc:
                    usage=h.source._one("SELECT metadata_bytes FROM open_repair_mailbox_resources WHERE resource_id=?",(self.resource_id,))
                    transferred=h.source._one("SELECT sum(proof_bytes) AS total FROM open_repair_mailbox_recovery_responses")
                    self.fail(f"{exc.code}: role={child['role']} metadata={usage['metadata_bytes']} transferred={transferred['total']}")
            raw=b"".join(chunks)
            self.assertEqual(hashlib.sha256(raw).hexdigest(),child["ref"]["raw_sha256"])
            received[child["role"]]=dict(raw=raw,ref=child["ref"])
        from memory_vault_open_repair_mailbox_root import verify_mailbox_root_source_event
        import memory_vault_open_repair_wire as wire
        budget=RepairBudget(DEFAULT_POLICY);resolver=wire.LocalRawResolver(DEFAULT_POLICY,budget)
        pack=received["history.raw_pack"];resolver.put("meta",pack["ref"]["key"],pack["raw"])
        recovered=verify_mailbox_root_source_event(received["history.mailbox_root"],resolver,received["root.custody"],
            expected_root=h.root,expected_owner=h.owner,expected_target=h.source.target,target_storage_epoch=h.slot_key["writer_storage_epoch"],
            limit_policy=h.source.limits,policy=DEFAULT_POLICY,budget=budget)
        self.assertEqual(recovered["custody"].raw,received["root.custody"]["raw"])
        from memory_vault import MemoryError as VaultError
        rejection=VaultError if "http" in self._testMethodName else RepairWireError
        with self.assertRaises(rejection):
            service.child(dict(raw=request.raw,ref=request.ref.as_dict()))
        fresh=proof.make_bootstrap_child_request(h.f["signers"]["owner"],checked,subject=h.owner,target=h.source.target,
            at=h.now,expires_at=h.now+20,child_index=0,offset=0,requested_bytes=1,
            policy=DEFAULT_POLICY,budget=RepairBudget(DEFAULT_POLICY))
        if "http" in self._testMethodName:
            service.participant.repair_policy["enabled"]=False
            with self.assertRaises(rejection):
                service.child(dict(raw=fresh.raw,ref=fresh.ref.as_dict()))
            service.participant.repair_policy["enabled"]=True
        import memory_vault_open_provider as provider
        from tests.test_open_repair_status import status_entry
        context=self.source.root.owner_status_context(self.resource_id)
        revoked=status_entry(provider.issue_status(h.f["signers"]["owner"],root=h.root,revision=2,
            entries=[dict(scope_kind=v["scope_kind"],scope_id=v["scope_id"],minimum_document_revision=1,status="revoked",operation_mask=127)
                for v in context["required"]],issued_at=h.now,valid_until=h.now+100))
        self.source.root.observe_owner_status(self.resource_id,revoked)
        with self.assertRaises(rejection):
            service.child(dict(raw=fresh.raw,ref=fresh.ref.as_dict()))
        h.now += 41
        with self.assertRaises(rejection):
            service.challenge(packet)

    def test_custody_recovery_refuses_exhausted_budget_before_creating_challenge(self):
        import memory_vault_open_repair_probe as probe
        from memory_vault_open_repair_mailbox_source import MailboxRecoveryService
        self.owner_observation();self.observe();self.source.prepare_history(self.resource_id,"synthetic_observation");self.custody()
        h=self.host.h;service=MailboxRecoveryService(self.source);service.initialize()
        saved=json.loads(bytes(h.source._one("SELECT inputs FROM open_repair_mailbox_roots")["inputs"]))["bootstrap"]
        grant=json.loads(saved["raw"])["payload"]
        pending=probe.make_bootstrap_probe(h.f["signers"]["owner"],expected_subject=h.owner,expected_target=h.source.target,
            target_storage_epoch=h.slot_key["writer_storage_epoch"],bootstrap_grant_sha256=saved["ref"]["raw_sha256"],
            selector=grant["selector"],at=h.now,expires_at=h.now+40,consumer="mailbox_root",policy=DEFAULT_POLICY,budget=RepairBudget(DEFAULT_POLICY))
        h.db.execute("INSERT INTO open_repair_mailbox_recovery_usage VALUES(?,?,?)",(self.resource_id,0,grant["limits"]["max_signature_checks"]))
        h.db.commit()
        with self.assertRaisesRegex(RepairWireError,"repair_service_capacity"):
            service.challenge(dict(raw=pending.original.raw,ref=pending.original.ref.as_dict()))
        self.assertEqual(h.db.execute("SELECT count(*) FROM open_repair_mailbox_recovery_challenges").fetchone()[0],0)

    def test_custody_setup_builder_creates_actual_root_without_handwritten_authorities(self):
        import copy
        from memory_vault_open_repair_client import MailboxSetupBuilder
        import memory_vault_open_provider as provider
        from tests.test_open_repair_status import status_entry
        from tests.open_repair_ack_fixtures import LIMITS
        h=self.host.h
        root=copy.deepcopy(h.root);root["root_id"]="synthetic_builder_root";root["anchor_ref"]["key"]="f"*64
        slot=dict(h.slot_key,root_key=root,slot_id="synthetic_builder_slot")
        caps=copy.deepcopy(h.f["docs"]["allocate"]["payload"]["intent"]["budget"]);caps["max_meta_bytes"]=1048576
        if "recovery" in self._testMethodName:
            caps["max_requests"]=512;caps["max_job_bytes"]=524288
        if "remote" in self._testMethodName:
            caps["max_pending"]=h.source.limits["max_pending"]
            caps["max_replay_records"]=h.source.limits["max_replay_records"]
        plan=dict(root_key=root,slot_key=slot,sender=dict(signing_key_id=h.f["signers"]["writer"].key_id,
            encryption_key_id=h.f["encryption"]["writer"].key_id),target=h.source.target,budget=caps,
            windows={name:h.now+600 for name in h.f["docs"]["allocate"]["payload"]["intent"]["windows"]},
            limits=getattr(self.host,"bootstrap_limits",LIMITS),max_appends=16,max_live_items=16)
        builder=MailboxSetupBuilder(h.f["signers"]["owner"],h.f["encryption"]["owner"],plan)
        if "provision" in self._testMethodName:
            from memory_vault_open_repair_client import MailboxSetupClient,MailboxSetupJournal
            from tests.open_repair_ack_fixtures import signed_entry
            from memory_vault_open_transport import OpenHTTPTransport
            from memory_vault import MemoryError
            import sqlite3
            remote=self.http_service(h,remote_setup=True)
            node_entry=signed_entry(dict(h.f["docs"]["descriptor"]["payload"],base_url=remote.base_url),
                h.f["signers"]["target"],"synthetic_provision_node")
            if 'agent' in self._testMethodName:
                from tests.test_open_agent import configured_agent
                from types import SimpleNamespace
                from unittest.mock import patch
                from memory_vault_open_client import MAILBOX_CONNECT_SCHEMA
                from memory_vault_open_repair_resource import _dual_key
                with patch('time.time',return_value=h.now):
                    agent,identity,encryption,_=configured_agent(SimpleNamespace(root=h.path.parent/'agent-provision',nodes=[json.loads(node_entry['raw'])]))
                    owner=dict(signing_key=identity.public_descriptor(),encryption_key=encryption.public_descriptor())
                    selected_root=dict(root,owner=_dual_key(owner,RepairBudget(DEFAULT_POLICY)),root_id='synthetic_agent_root')
                    selected_slot=dict(slot,root_key=selected_root)
                    selected_plan=dict(plan,root_key=selected_root,slot_key=selected_slot)
                    invitation=dict(schema_version=MAILBOX_CONNECT_SCHEMA,action='provision',base_url=remote.base_url,
                        target_node_entry=dict(raw=node_entry['raw'].decode(),ref=node_entry['ref']),plan=selected_plan,
                        sender=dict(signing_key=h.f['signers']['writer'].public_descriptor(),encryption_key=h.f['encryption']['writer'].public_descriptor()),
                        setup_until=h.now+60,read_until=h.now+100,retain_until=h.now+100)
                    result=agent.handle(dict(op='connect',invitation=invitation))
                    self.assertTrue(result['ok'],result)
                    self.assertEqual(result['result']['state'],'mailbox_ready')
                    with patch('memory_vault_open_transport.OpenHTTPTransport.request_repair',side_effect=AssertionError('cached setup accessed network')):
                        again=agent.handle(dict(op='connect',invitation=invitation))
                    self.assertTrue(again['ok'],again)
                    self.assertEqual(again['result']['state'],'mailbox_configured')
                    self.assertFalse(again['result']['network_accessed'])
                    self.assertFalse(again['result']['source_rechecked'])
                    with patch('memory_vault_open_transport.OpenHTTPTransport.request_repair',side_effect=AssertionError('changed setup accessed network')):
                        changed=agent.handle(dict(op='connect',invitation=dict(invitation,retain_until=h.now+99)))
                    self.assertFalse(changed['ok'])
                    self.assertEqual(changed['error']['code'],'repair_setup_journal_conflict')
                    self.assertEqual(again['result']['setup_id'],result['result']['setup_id'])
                    listed=agent.handle(dict(op='connect',invitation=dict(schema_version=MAILBOX_CONNECT_SCHEMA,action='list')))
                    self.assertEqual(listed['result']['mailboxes'],[result['result']['receiver_id']])
                    with patch('memory_vault_open_transport.OpenHTTPTransport.request_repair',side_effect=AssertionError('inspection accessed network')):
                        inspected=agent.handle(dict(op='connect',invitation=dict(schema_version=MAILBOX_CONNECT_SCHEMA,
                            action='inspect',receiver_id=result['result']['receiver_id'])))
                        self.assertTrue(inspected['ok'],inspected)
                        self.assertFalse(inspected['result']['source_rechecked'])
                        import base64,hashlib
                        parts=[];page=inspected['result']
                        while True:
                            parts.append(base64.b64decode(page['configuration_chunk'],validate=True))
                            if page['next_cursor'] is None:break
                            next_page=agent.handle(dict(op='connect',invitation=dict(schema_version=MAILBOX_CONNECT_SCHEMA,
                                action='inspect',receiver_id=result['result']['receiver_id'],cursor=page['next_cursor'])))
                            self.assertTrue(next_page['ok'],next_page)
                            page=next_page['result']
                            self.assertEqual(page['offset'],sum(map(len,parts)))
                        configuration=b''.join(parts)
                        self.assertEqual(hashlib.sha256(configuration).hexdigest(),page['configuration_sha256'])
                        self.assertEqual(len(configuration),page['total_bytes'])
                        config=json.loads(configuration)
                        mismatch=agent.handle(dict(op='connect',invitation=dict(schema_version=MAILBOX_CONNECT_SCHEMA,
                            action='inspect',receiver_id=result['result']['receiver_id'],cursor=dict(sha256='0'*64,offset=3072))))
                        self.assertEqual(mismatch['error']['code'],'open_invalid_mailbox_cursor')
                        self.assertEqual(config['expected_slot'],selected_slot)
                        self.assertEqual(config['expected_sender'],invitation['sender'])
                        self.assertEqual(config['target_node_entry'],invitation['target_node_entry'])
                        agent.handle(dict(op='connect',invitation=dict(schema_version=MAILBOX_CONNECT_SCHEMA,
                            action='remove',receiver_id=result['result']['receiver_id'])))
                        missing=agent.handle(dict(op='connect',invitation=dict(schema_version=MAILBOX_CONNECT_SCHEMA,
                            action='inspect',receiver_id=result['result']['receiver_id'])))
                        self.assertEqual(missing['error']['code'],'open_mailbox_receiver_missing')
                        restored=agent.handle(dict(op='connect',invitation=config))
                        self.assertTrue(restored['ok'],restored)
                        self.assertEqual(restored['result']['receiver_id'],result['result']['receiver_id'])
                    with agent._network() as network:
                        with network.participant.state.db() as local:
                            self.assertEqual(local.execute('SELECT count(*) FROM open_mailbox_setup_steps').fetchone()[0],4)
                return
            path=h.path.parent/"recipient-setup.sqlite3";path.touch(mode=0o600)
            db=sqlite3.connect(path);self.addCleanup(db.close)
            journal=MailboxSetupJournal(db)
            transport=OpenHTTPTransport(allow_loopback=True);self.addCleanup(transport.close)
            original_request=transport.request_repair;lost=[]
            def request(base,raw,**options):
                result=original_request(base,raw,**options)
                if json.loads(raw).get("payload",{}).get("kind")=="mailbox.source_root" and not lost:
                    lost.append(raw);raise MemoryError("open_network_unavailable")
                return result
            transport.request_repair=request
            client=MailboxSetupClient(h.f["signers"]["owner"],h.f["encryption"]["owner"],limit_policy=dict(h.source.limits),
                allow_loopback=True,transport=transport,clock=lambda:h.now)
            options=dict(target_node_entry=node_entry,plan=plan,setup_until=h.now+60,read_until=h.now+100,retain_until=h.now+100)
            with self.assertRaisesRegex(MemoryError,"open_network_unavailable"):
                client.provision(remote.base_url,journal=journal,**options)
            db.close();db=sqlite3.connect(path);self.addCleanup(db.close)
            client=MailboxSetupClient(h.f["signers"]["owner"],h.f["encryption"]["owner"],limit_policy=dict(h.source.limits),
                allow_loopback=True,transport=transport,clock=lambda:h.now)
            result=client.provision(remote.base_url,journal=MailboxSetupJournal(db),**options)
            self.assertEqual(result.source["custody"].payload["root_key"],root)
            rows=db.execute("SELECT stage,request,response FROM open_mailbox_setup_steps ORDER BY stage").fetchall()
            self.assertEqual(len(rows),4);self.assertTrue(all(row[2] for row in rows))
            self.assertEqual(next(bytes(row[1]) for row in rows if row[0]=="root"),lost[0])
            self.assertGreater(db.execute("SELECT count(*) FROM open_mailbox_setup_statuses").fetchone()[0],0)
            from unittest.mock import patch
            from memory_vault_open_repair_bind import decode_entry
            import memory_vault_open_repair_wire as wire
            ready=json.loads(next(bytes(row[1]) for row in rows if row[0]=="ready"))["payload"]
            state=decode_entry(wire.build_new_wire(ready["entries"]["owner_status"],DEFAULT_POLICY,wire.RepairBudget(DEFAULT_POLICY)).value,
                DEFAULT_POLICY,wire.RepairBudget(DEFAULT_POLICY))
            status_payload=json.loads(state["raw"])["payload"]
            revoked=status_entry(provider.issue_status(h.f["signers"]["owner"],root=root,revision=2,
                entries=[dict(value,status="revoked") for value in status_payload["entries"]],issued_at=h.now,valid_until=h.now+100))
            with patch.object(transport,"request_repair",side_effect=AssertionError("network after retained revocation")):
                with self.assertRaisesRegex(RepairWireError,"repair_authority_revoked"):
                    client.provision(remote.base_url,journal=MailboxSetupJournal(db),known_statuses=[revoked],**options)
                with self.assertRaisesRegex(RepairWireError,"repair_authority_revoked"):
                    client.provision(remote.base_url,journal=MailboxSetupJournal(db),**options)
            return
        allocations=builder.allocation_requests(at=h.now,expires_at=h.now+60)
        if "remote" in self._testMethodName:
            from memory_vault_open_repair_bind import decode_entry
            from memory_vault_open_transport import OpenHTTPTransport
            import time
            remote=self.http_service(h,remote_setup=True)
            transport=OpenHTTPTransport(allow_loopback=True);self.addCleanup(transport.close)
            packet=builder.allocation_packet(allocations)
            raw=transport.request_repair(remote.base_url,packet,deadline=time.monotonic()+15)
            self.assertEqual(raw,transport.request_repair(remote.base_url,packet,deadline=time.monotonic()+15))
            changed=builder.allocation_packet(builder.allocation_requests(at=h.now,expires_at=h.now+59))
            with self.assertRaisesRegex(RepairWireError,"repair_remote_setup_conflict"):
                remote.participant.handle_repair(changed)
            import memory_vault_open_repair_wire as wire
            parsed=wire.parse_new_wire(raw,DEFAULT_POLICY,wire.RepairBudget(DEFAULT_POLICY)).value
            self.assertEqual(parsed["kind"],"mailbox.source_offers")
            offers={name:decode_entry(value,DEFAULT_POLICY,wire.RepairBudget(DEFAULT_POLICY)) for name,value in parsed["offers"].items()}
            remote.participant.repair_policy["remote_setup"]["enabled"]=False
            from memory_vault import MemoryError
            with self.assertRaisesRegex(MemoryError,"open_request_rejected"):
                transport.request_repair(remote.base_url,packet,deadline=time.monotonic()+15)
        else:
            offers=h.resources.allocate_initial(list(allocations.values()),expected_owner=h.owner)
        entries=builder.slot_documents(allocations,offers,at=h.now,expires_at=h.now+600)
        def activate_remote(stage,documents):
            packet=builder.activation_packet(stage,documents,at=h.now,expires_at=h.now+600)
            raw=transport.request_repair(remote.base_url,packet,deadline=time.monotonic()+15)
            self.assertEqual(raw,transport.request_repair(remote.base_url,packet,deadline=time.monotonic()+15))
            result=wire.parse_new_wire(raw,DEFAULT_POLICY,wire.RepairBudget(DEFAULT_POLICY)).value
            self.assertEqual(result["kind"],"mailbox.source_"+stage+"_active")
            changed=builder.activation_packet(stage,documents,at=h.now,expires_at=h.now+599)
            with self.assertRaisesRegex(RepairWireError,"repair_remote_setup_conflict"):
                remote.participant.handle_repair(changed)
            return {name:decode_entry(value,DEFAULT_POLICY,wire.RepairBudget(DEFAULT_POLICY)) for name,value in result["originals"].items()}
        if "remote" in self._testMethodName:
            remote.participant.repair_policy["remote_setup"]["enabled"]=True
            slot_result=activate_remote("slot",entries)
        else:
            slot_result=self.source.root.slots.activate(entries,expected_slot=slot)
        root_entries=builder.root_documents(allocations,offers,entries,slot_result,at=h.now,expires_at=h.now+600)
        active=(activate_remote("root",root_entries)["active"] if "remote" in self._testMethodName else
            self.source.root.activate(root_entries,expected_root=root,slot_keys=[slot]))
        rid=json.loads(active["raw"])["payload"]["resource"]["resource_id"]
        state=builder.initial_owner_status(entries,root_entries,at=h.now,valid_until=h.now+100)
        if "remote" in self._testMethodName:
            packet=builder.readiness_packet(state,at=h.now,expires_at=h.now+60,read_until=h.now+100,retain_until=h.now+100)
            from unittest.mock import patch
            committed=[];finalize=MailboxRootSource.finalize_root
            def lost_response(source,*args,**kwargs):
                committed.append(finalize(source,*args,**kwargs))
                raise RuntimeError("synthetic lost response after durable custody")
            with patch.object(MailboxRootSource,"finalize_root",lost_response):
                with self.assertRaisesRegex(MemoryError,"open_network_unavailable"):
                    transport.request_repair(remote.base_url,packet,deadline=time.monotonic()+15)
            raw=transport.request_repair(remote.base_url,packet,deadline=time.monotonic()+15)
            self.assertEqual(raw,transport.request_repair(remote.base_url,packet,deadline=time.monotonic()+15))
            result=wire.parse_new_wire(raw,DEFAULT_POLICY,wire.RepairBudget(DEFAULT_POLICY)).value
            custody=decode_entry(result["originals"]["custody"],DEFAULT_POLICY,wire.RepairBudget(DEFAULT_POLICY))
            self.assertEqual(custody,committed[0])
            from memory_vault_open_repair_client import MailboxRootRecoveryClient
            from tests.open_repair_ack_fixtures import signed_entry
            node_entry=signed_entry(dict(h.f["docs"]["descriptor"]["payload"],base_url=remote.base_url),
                h.f["signers"]["target"],"synthetic_remote_setup_node")
            client=MailboxRootRecoveryClient(h.f["signers"]["owner"],h.f["encryption"]["owner"],
                limit_policy=dict(h.source.limits),allow_loopback=True,clock=lambda:h.now)
            self.addCleanup(client.close)
            recovered=client.recover(remote.base_url,target_node_entry=node_entry,expected_target=h.source.target,
                expected_root=root,known_statuses=[state],**{name+"_entry":root_entries[name] for name in ("root","read","bootstrap")})
            self.assertEqual(recovered.source["custody"].raw,custody["raw"])
        else:
            self.source.root.observe_owner_status(rid,state)
            self.source.observe_resources(rid,"synthetic_builder_status",valid_until=h.now+100)
            self.source.prepare_history(rid,"synthetic_builder_status")
            custody=self.source.finalize_root(rid,read_until=h.now+100,retain_until=h.now+100)
        self.assertEqual(json.loads(custody["raw"])["payload"]["root_key"],root)
        self.assertEqual(builder.allocation_requests(at=h.now,expires_at=h.now+60),allocations)
        if "message_draft" in self._testMethodName:
            from unittest.mock import patch
            self.enterContext(patch("time.time",side_effect=lambda:h.now))
            from tests.test_open_repair_original import contact_fixture
            from memory_vault_open_repair_client import MailboxMessageDraftStore
            from memory_vault_open_delivery import create_envelope,decrypt_envelope
            from memory_vault import canonical_bytes
            import sqlite3
            docs,_,_=contact_fixture(identities=(h.f["signers"]["writer"],h.f["signers"]["owner"],h.f["signers"]["target"]),
                encryption=(h.f["encryption"]["writer"],h.f["encryption"]["owner"]),now=h.now,storage_epoch=slot["writer_storage_epoch"])
            contact={name:canonical_bytes(doc) for name,doc in docs.items()}
            destination=builder.destination_document(entries,contact,at=h.now,expires_at=h.now+60)
            content=canonical_bytes(dict(schema_version="memory-vault-network-content/v2",kind="message",text="synthetic offline message"))
            envelope_options=dict(signer=h.f["signers"]["writer"],sender_encryption_key=h.f["encryption"]["writer"].public_descriptor(),
                recipient_signing_key=h.owner["signing_key"],recipient_encryption_key=h.owner["encryption_key"],
                message_id="msg_"+"a"*64,object_key="b"*64,created_at=h.now)
            envelope=canonical_bytes(create_envelope(content,**envelope_options))
            path=h.path.parent/"sender-drafts.sqlite3";path.touch(mode=0o600)
            db=sqlite3.connect(path);self.addCleanup(db.close)
            options=dict(recipient=h.owner,slot_entries={name:entries[name] for name in ("slot","read","maintenance")},
                destination_entry=destination,contact_originals=contact,attempt_until=h.now+60,consent_until=h.now+100)
            store=MailboxMessageDraftStore(db,h.f["signers"]["writer"],h.f["encryption"]["writer"])
            saved=store.prepare(envelope,at=h.now,**options)
            db.close();db=sqlite3.connect(path);self.addCleanup(db.close)
            store=MailboxMessageDraftStore(db,h.f["signers"]["writer"],h.f["encryption"]["writer"])
            self.assertEqual(store.prepare(envelope,at=h.now+1,**options),saved)
            self.assertEqual(decrypt_envelope(saved["envelope"],encryption_identity=h.f["encryption"]["owner"],
                sender_signing_key=h.f["signers"]["writer"].public_descriptor(),
                sender_encryption_key=envelope_options["sender_encryption_key"],recipient_signing_key=h.owner["signing_key"],
                recipient_encryption_key=h.owner["encryption_key"]),content)
            with self.assertRaisesRegex(RepairWireError,"repair_message_conflict"):
                store.prepare(canonical_bytes(create_envelope(content,**envelope_options)),at=h.now,**options)
            self.assertEqual(db.execute("SELECT count(*) FROM open_mailbox_message_drafts").fetchone()[0],1)
            second=store.prepare(canonical_bytes(create_envelope(content,**dict(envelope_options,message_id="msg_"+"c"*64))),at=h.now,**options)
            self.assertNotEqual(second["attempt"],saved["attempt"])
            self.assertEqual([row[0] for row in db.execute("SELECT status_revision FROM open_mailbox_message_drafts ORDER BY status_revision")],[1,2])
            from memory_vault_open_repair_mailbox_status import MailboxStatusLedger
            from memory_vault_open_repair_bind import decode_entry
            import memory_vault_open_repair_wire as wire
            ledger=MailboxStatusLedger(h.resources);ledger.initialize()
            observation=decode_entry(saved["originals"]["disclosure_status"],DEFAULT_POLICY,wire.RepairBudget(DEFAULT_POLICY))
            data_id=json.loads(slot_result["data"]["raw"])["payload"]["resource"]["resource_id"]
            metadata_id=json.loads(slot_result["metadata"]["raw"])["payload"]["resource"]["resource_id"]
            with self.assertRaisesRegex(RepairWireError,"repair_wrong_issuer"):
                ledger.observe(data_id,observation,expected_signing_key=h.f["signers"]["writer"].public_descriptor(),allowed_scopes=[])
            from tests.open_repair_ack_fixtures import signed_entry
            foreign=dict(json.loads(saved["disclosure"]["raw"])["payload"],signing_key=h.owner["signing_key"])
            with self.assertRaisesRegex(RepairWireError,"repair_wrong_issuer"):
                ledger.observe_message_consent(data_id,signed_entry(foreign,h.f["signers"]["owner"],"synthetic_foreign_consent"),observation)
            authenticated=ledger.observe_message_consent(data_id,saved["disclosure"],observation)
            item=authenticated.payload["entries"][0]
            required=[dict(issuer=h.f["signers"]["writer"].key_id,scope_kind="authority",scope_id=item["scope_id"],document_revision=1,operation_mask=2)]
            with h.source._transaction():
                self.assertIsNone(ledger.check_locked(metadata_id,required))
            revoked=status_entry(provider.issue_status(h.f["signers"]["writer"],root=root,revision=3,
                entries=[dict(item,status="revoked")],issued_at=h.now,valid_until=h.now+100))
            h.now+=101
            with self.assertRaisesRegex(RepairWireError,"repair_status_mismatch"):
                ledger.observe_message_consent(data_id,saved["disclosure"],revoked)
            with h.source._transaction():
                self.assertEqual(ledger.check_locked(metadata_id,required),"repair_authority_revoked")
        wrong=dict(offers);wrong["mailbox_data"]=offers["feed_metadata"]
        with self.assertRaises(RepairWireError):
            builder.slot_documents(allocations,wrong,at=h.now,expires_at=h.now+600)

    def test_custody_message_draft_preserves_ciphertext_and_sender_originals_after_restart(self):
        self.test_custody_setup_builder_creates_actual_root_without_handwritten_authorities()

    def test_custody_recovery_remote_agent_provision_registers_mailbox(self):
        self.test_custody_setup_builder_creates_actual_root_without_handwritten_authorities()

    def test_custody_recovery_remote_provision_resumes_after_process_restart(self):
        self.test_custody_setup_builder_creates_actual_root_without_handwritten_authorities()

    def test_custody_recovery_remote_setup_builder_allocates_over_real_http(self):
        self.test_custody_setup_builder_creates_actual_root_without_handwritten_authorities()

    def test_real_anchor_and_slot_resources_share_one_node_signed_original(self):
        result = self.observe();self.assertEqual(len(result),1)
        payload = json.loads(result[0]["raw"])["payload"]
        self.assertEqual(payload["revision"],1)
        self.assertEqual(len(payload["entries"]),3)
        scopes = []
        for (raw,) in self.host.h.db.execute("SELECT offer FROM open_repair_mailbox_resources"):
            ref = json.loads(raw)["payload"]["resource"]
            scopes.append(dict(scope_kind="resource",scope_id=status.status_scope(self.host.h.root,"resource",ref,DEFAULT_POLICY,RepairBudget(DEFAULT_POLICY))))
        status.verify_status_original(result[0],expected_root=self.host.h.root,
            expected_signing_key=self.host.h.source.identity.public_descriptor(),at=self.host.h.now,
            allowed_scopes=scopes,required=[dict(**s,document_revision=1,operation_mask=66) for s in scopes],
            policy=DEFAULT_POLICY,budget=RepairBudget(DEFAULT_POLICY))

    def test_selected_slot_excludes_anchor_and_uses_next_revision(self):
        all_resources = self.observe()
        selected = self.observe("synthetic_slot_only",slot_keys=[self.host.h.slot_key])
        self.assertEqual(len(json.loads(all_resources[0]["raw"])["payload"]["entries"]),3)
        p = json.loads(selected[0]["raw"])["payload"]
        self.assertEqual(p["revision"],2);self.assertEqual(len(p["entries"]),2)
        anchor = json.loads(self.host.offer["raw"])["payload"]["resource"]
        anchor_scope = status.status_scope(self.host.h.root,"resource",anchor,DEFAULT_POLICY,RepairBudget(DEFAULT_POLICY))
        self.assertNotIn(anchor_scope,[value["scope_id"] for value in p["entries"]])

    def test_restart_and_expired_retry_return_original_without_new_revision(self):
        first = self.observe()
        before = self.host.h.db.execute("SELECT metadata_bytes FROM open_repair_mailbox_resources WHERE resource_id=?",(self.resource_id,)).fetchone()
        self.host.h.db.close();self.host.h.now += 101;self.host.h.connect()
        self.source = MailboxRootSource(MailboxRootActivation(self.host.h.resources));self.source.initialize()
        self.assertEqual(self.observe(),first)
        self.assertEqual(self.host.h.db.execute("SELECT metadata_bytes FROM open_repair_mailbox_resources WHERE resource_id=?",(self.resource_id,)).fetchone(),before)
        self.assertEqual(self.host.h.db.execute("SELECT revision FROM open_repair_mailbox_node_revisions").fetchone()[0],1)

    def test_conflicting_request_and_failed_commit_cannot_advance_counter(self):
        first = self.observe()
        with self.assertRaisesRegex(RepairWireError,"repair_status_request_conflict"):
            self.observe(slot_keys=[self.host.h.slot_key])
        calls = []
        def guard():
            calls.append(True)
            return "synthetic_closed" if len(calls)==2 else None
        with self.assertRaisesRegex(RepairWireError,"synthetic_closed"):
            self.observe("synthetic_failed",_transaction_guard=guard)
        self.assertEqual(self.observe(),first)
        self.assertEqual(self.host.h.db.execute("SELECT revision FROM open_repair_mailbox_node_revisions").fetchone()[0],1)
        self.assertEqual(self.host.h.db.execute("SELECT count(*) FROM open_repair_mailbox_node_observations").fetchone()[0],1)

    def test_missing_counter_is_not_recreated_over_historical_observations(self):
        self.observe()
        self.host.h.db.execute("DELETE FROM open_repair_mailbox_node_revisions");self.host.h.db.commit()
        with self.assertRaisesRegex(RepairWireError,"repair_mailbox_status_ledger_missing"):
            self.observe("synthetic_next")

    def test_lost_earlier_request_cannot_be_resigned_as_a_new_result(self):
        self.observe()
        self.observe("synthetic_second",slot_keys=[self.host.h.slot_key])
        self.host.h.db.execute("DELETE FROM open_repair_mailbox_node_observations WHERE request_id='synthetic_observation'")
        self.host.h.db.commit()
        with self.assertRaisesRegex(RepairWireError,"repair_mailbox_status_ledger_missing"):
            self.observe()


if __name__ == "__main__":
    unittest.main()
