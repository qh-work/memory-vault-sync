"""Independent A uses actual D discovery and R owner READ over two HTTP nodes."""
import asyncio
import hashlib
from pathlib import Path
import threading
import unittest
from unittest.mock import patch

from memory_vault import canonical_bytes
import memory_vault_open_provider as provider_wire
from memory_vault_open_node import OpenHTTPServer, OpenParticipant
from memory_vault_open_provider_client import OpenProviderClient
from memory_vault_open_repair_client import AckOwnerRecoveryClient
from memory_vault_open_repair_index_recovery import DiscoveredAckRecoveryClient
import memory_vault_open_repair_wire as wire
from tests import open_repair_ack_fixtures as ack_fixtures
from tests import test_open_repair_state as source_tests
from tests import test_open_repair_index_http as directory_http


class IndexedReceiptRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.source_server=OpenHTTPServer(('127.0.0.1',0),None)
        self.addCleanup(self.source_server.server_close)
        base='http://127.0.0.1:'+str(self.source_server.server_port)
        original_node=ack_fixtures.issue_node
        def node(signer,**kwargs):
            return original_node(signer,**(kwargs|dict(base_url=base)))
        original_connect=source_tests.RepairStateTests.connect
        def connect(instance,**options):
            f=instance.fixture
            directory=Path(instance.temp.name).resolve()/'source-protected'
            self.source_participant=OpenParticipant(f['signers']['target'],directory,seeds=[],
                descriptor=f['docs']['descriptor'],encryption_identity=f['encryption']['target'],allow_loopback=True,
                provider_policy=dict(enabled=True),repair_policy=dict(enabled=True,limit_policy=f['expected']['limit_policy']))
            self.addCleanup(self.source_participant.close)
            instance.path=directory/'network.sqlite3'
            original_connect(instance,**options)
        limits=dict(ack_fixtures.LIMITS,max_probe_bytes=8192,max_signature_checks=4096,max_proof_bytes=4194304,max_requests=128)
        self.host=directory_http.RepairIndexHTTPTests()
        self.addCleanup(self.host.doCleanups)
        with patch.object(ack_fixtures,'issue_node',node),patch.object(ack_fixtures,'LIMITS',limits),patch.object(source_tests.RepairStateTests,'connect',connect):
            self.host.setUp()
        self.source_server.participant=self.source_participant
        self.source_thread=threading.Thread(target=self.source_server.serve_forever,kwargs=dict(poll_interval=0.02),daemon=True)
        self.source_thread.start();self.addCleanup(self.stop_source)
        c=self.host.c;f=c.f.f
        self.owner=OpenParticipant(f['signers']['owner'],Path(c.temp.name)/'owner-discovery',seeds=[c.node],
            encryption_identity=f['encryption']['owner'],allow_loopback=True)
        self.addCleanup(self.owner.close)
        # RoutingTable captures its default clock at import; use the same
        # explicit synthetic event clock as the real HTTP peers.
        self.owner.table.now=lambda:c.f.at
        self.provider=OpenProviderClient(self.owner,f['encryption']['owner'])
        recovery=AckOwnerRecoveryClient(f['signers']['owner'],f['encryption']['owner'],transport=self.host.transport,
            limit_policy=f['expected']['limit_policy'],allow_loopback=True)
        self.client=DiscoveredAckRecoveryClient(self.provider,recovery)
        self.options=dict(expected_directory_node=c.node,expected_directory=c.f.directory_keys,
            expected_target=c.f.publisher,expected_source_epoch=f['expected']['target_storage_epoch'],
            expected_ack_slot=f['expected']['expected_ack_slot'],root_entry=f['entries']['root'],read_entry=f['entries']['read'],
            bootstrap_entry=f['entries']['bootstrap'],**{name:c.f.case.case.expected[name] for name in
                ('expected_receipt_writer','expected_message_id','expected_envelope_ref')})

    def stop_source(self):
        self.source_server.shutdown();self.source_thread.join(timeout=3)

    def test_directory_discovery_then_real_owner_read_matches_exact_receipt_commit(self):
        self.host.publish()
        # No routing choice is patched: find_at must contact the independent
        # exact D even with an empty A routing table.
        result=asyncio.run(self.client.recover(**self.options))
        self.assertEqual(result.state,'usable')
        self.assertEqual(result.recovery.source.commit.raw,self.host.c.f.result['commit']['raw'])
        self.assertEqual(result.recovery.source.inputs['receipt'].raw,self.host.c.f.case.receipt['raw'])
        self.assertEqual(result.recovery.source.inputs['receipt'].ref.as_dict(),self.host.c.f.case.receipt['ref'])
        self.assertEqual(result.fact['payload']['custody_id'],'ack_'+result.recovery.source.commit.ref.raw_sha256)
        self.assertGreater(result.metrics['discovery']['requests'],2)
        self.assertGreater(result.metrics['recovery']['requests'],2)

    def test_no_publication_does_not_claim_usable_or_start_private_owner_read(self):
        with patch.object(self.client.recovery,'recover_occupied',side_effect=AssertionError('no index is not usable')):
            with self.assertRaises(wire.RepairWireError) as caught:
                asyncio.run(self.client.recover(**self.options))
        self.assertEqual(caught.exception.code,'repair_index_not_observed')

    def test_signed_directory_claim_cannot_replace_actual_source_commit_readback(self):
        lease=self.host.publish()
        c=self.host.c;f=c.f
        # Model a dishonest R and D advertising a different custody ID with
        # otherwise genuine signatures. This is deliberately adversarial
        # directory storage, never a successful legitimate admission fixture.
        fact=provider_wire.issue_fact(f.f['signers']['target'],ref=f.root['anchor_ref'],
            storage_epoch=f.f['expected']['target_storage_epoch'],custody_id='ack_'+'00'*32,revision=2,
            issued_at=f.at,expires_at=f.until)
        payload=dict(lease['payload'],fact_sha256=hashlib.sha256(canonical_bytes(fact)).hexdigest(),
            custody_id=fact['payload']['custody_id'])
        other_lease=dict(payload=payload,proof=f.directory.sign_message(payload))
        key=hashlib.sha256(canonical_bytes(dict(ref=fact['payload']['ref'],provider_key_id=fact['payload']['signing_key']['key_id'],
            storage_epoch=fact['payload']['storage_epoch'],custody_id=fact['payload']['custody_id']))).hexdigest()
        c.db.execute('UPDATE open_repair_index_facts SET fact_key=?,record=?,digest=?,revision=2,index_lease=?',
            (key,canonical_bytes(fact),payload['fact_sha256'],canonical_bytes(other_lease)))
        c.db.commit()
        with patch.object(self.client.recovery,'recover_occupied',wraps=self.client.recovery.recover_occupied) as read:
            with self.assertRaises(wire.RepairWireError) as caught:
                asyncio.run(self.client.recover(**self.options))
        self.assertEqual(caught.exception.code,'repair_index_custody_mismatch')
        self.assertEqual(read.call_count,1)
