"""Actual command recovery, private new-only output, and unchanged source keys."""
import base64
import contextlib
import hashlib
import io
import json
from pathlib import Path
import stat
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from memory_vault import canonical_bytes
from memory_vault_network_crypto import b64url, unb64url
from memory_vault_open_repair_admin import main, REQUEST_SCHEMA, EMPTY_REQUEST_SCHEMA, OCCUPIED_REQUEST_SCHEMA, EVIDENCE_SCHEMA
from memory_vault_open_setup import initialize_node
from memory_vault_trust import TrustStore, _write_new_private
from tests import test_open_repair_http as http_fixture


class _AdminFixture:
    def enterContext(self, context):
        # The supported Python 3.10 TestCase lacks enterContext (3.11+).
        value = context.__enter__()
        self.addCleanup(context.__exit__, None, None, None)
        return value

    def configure_owner(self, role="owner"):
        self.directory = Path(self.host.source.temp.name).resolve() / "synthetic-owner"
        self.directory.mkdir(mode=0o700)
        f = self.host.source.fixture
        owner = f["signers"][role]
        secret = owner._private_key.private_bytes(serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw, serialization.NoEncryption())
        self.identity = self.directory / "identity.json"
        _write_new_private(self.identity, canonical_bytes({**owner.public_descriptor(),
            "schema_version": "universal-memory-identity/v1", "private_key": base64.b64encode(secret).decode()}))
        self.encryption = self.directory / "encryption.json"
        f["encryption"][role].save(self.encryption)
        self.vault = self.directory / "vault" / "memory.sqlite3"
        self.trust = self.directory / "trust.json"
        TrustStore(self.trust).add(owner.public_descriptor())
        self.config = self.directory / "client.json"
        _write_new_private(self.config, canonical_bytes(dict(schema_version="memory-vault-client-config/v1",
            identity_path=str(self.identity), trust_path=str(self.trust),
            vault_path=str(self.vault), capture_visible_turns=False)))
        self.network = self.directory / "open.json"
        _write_new_private(self.network, canonical_bytes(dict(schema_version="memory-vault-open-client-config/v1",
            client_config_path=str(self.config), state_directory=str(self.directory / "transport"),
            encryption_key_path=str(self.encryption), seeds=[f["docs"]["descriptor"]], allow_loopback=True)))
        entries = f["entries"]
        self.request = dict(schema_version=REQUEST_SCHEMA, target=f["expected"]["expected_target"],
            ack_slot=f["expected"]["expected_ack_slot"], known_statuses=[],
            **{name: dict(raw_base64url=b64url(entries[role]["raw"]), ref=entries[role]["ref"])
               for name, role in (("node", "descriptor"), ("root", "root"), ("read", "read"), ("bootstrap", "bootstrap"))})
        self.request_path, self.output = self.directory / "request.json", self.directory / "evidence.json"
        self.originals = {path: path.read_bytes() for path in (self.identity, self.encryption, self.trust, self.config, self.network)}

    def call(self, command="recover-ack"):
        _write_new_private(self.request_path, canonical_bytes(self.request))
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            args=[command, "--network-config", str(self.network), "--request", str(self.request_path),
                  "--output", str(self.output), "--timeout", str(getattr(self,"command_timeout",30))]
            if getattr(self,'repair_profile',None):args.extend(['--repair-profile',self.repair_profile])
            code = main(args)
        return code, stdout.getvalue(), stderr.getvalue()


class RepairAdminTests(_AdminFixture, unittest.TestCase):
    def setUp(self):
        self.host = http_fixture.RepairHTTPTests()
        self.host.setUp()
        self.addCleanup(self.host.doCleanups)
        self.configure_owner()

    def test_command_recovers_exact_originals_without_opening_vault_or_changing_identity(self):
        code, output, error = self.call()
        self.assertEqual((code, error), (0, ""))
        result = json.loads(output)
        saved = self.output.read_bytes()
        evidence = json.loads(saved)
        self.assertEqual(evidence["schema_version"], EVIDENCE_SCHEMA)
        self.assertEqual(result["state"], "ack_unbound_source_recovered")
        self.assertEqual(result["evidence_sha256"], hashlib.sha256(saved).hexdigest())
        self.assertFalse(result["recipient_saved"])
        self.assertFalse(result["vault_modified"])
        self.assertFalse(self.vault.exists())
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)
        self.assertEqual(len(evidence["originals"]), result["original_count"])
        self.assertGreater(result["requests"], 2)
        for entry in evidence["originals"]:
            raw = unb64url(entry["raw_base64url"], maximum=524288)
            self.assertEqual(raw, self.host.source.state.read_local_original(self.host.source.resource_id, entry["ref"]))
            self.assertEqual(hashlib.sha256(raw).hexdigest(), entry["ref"]["raw_sha256"])
        self.assertEqual({path: path.read_bytes() for path in self.originals}, self.originals)
        self.assertNotIn(b'"private_key"', saved)

    def test_existing_output_is_preserved_before_network_access(self):
        _write_new_private(self.output, b"synthetic existing evidence\n")
        code, output, error = self.call()
        self.assertEqual((code, output), (1, ""))
        self.assertEqual(json.loads(error)["error"], "repair_output_exists")
        self.assertEqual(self.output.read_bytes(), b"synthetic existing evidence\n")
        self.assertFalse((self.directory / "transport").exists())

    def test_corrupted_root_ref_produces_no_output_or_probe(self):
        self.request["root"]["ref"] = dict(self.request["root"]["ref"], raw_sha256="0" * 64)
        code, output, error = self.call()
        self.assertEqual((code, output), (1, ""))
        self.assertEqual(json.loads(error)["error"], "repair_ref_mismatch")
        self.assertFalse(self.output.exists())
        self.assertEqual(self.host.source.db.execute("SELECT count(*) FROM open_repair_bootstrap_challenges").fetchone()[0], 0)


class RepairOccupiedAdminTests(_AdminFixture, unittest.TestCase):
    def test_command_recovers_recipient_original_and_all_status_generations(self):
        from tests.test_open_repair_occupied_client import OccupiedHTTPFixture
        occupied = OccupiedHTTPFixture(self)
        self.host = occupied.http
        self.configure_owner()
        expected = occupied.empty.expected
        self.request.update(schema_version=OCCUPIED_REQUEST_SCHEMA,
            receipt_writer=expected["expected_receipt_writer"], message_id=expected["expected_message_id"],
            envelope_ref=expected["expected_envelope_ref"])
        code, output, error = self.call("recover-occupied")
        self.assertEqual((code,error),(0,""))
        result, evidence = json.loads(output),json.loads(self.output.read_bytes())
        self.assertEqual(result["state"],"ack_occupied_source_recovered")
        self.assertTrue(result["recipient_saved"])
        self.assertFalse(self.vault.exists())
        self.assertEqual(unb64url(evidence["recipient_receipt"]["raw_base64url"],maximum=4096),occupied.receipt["raw"])
        self.assertEqual(evidence["recipient_receipt"]["ref"],occupied.receipt["ref"])
        retained={canonical_bytes(item["ref"]) for item in evidence["archive_statuses"]}
        originals=[occupied.f["entries"][name] for name in ("owner_status","target_status")]
        originals.extend(occupied.empty.expected["current_statuses"])
        originals.extend(occupied.options["current_statuses"])
        self.assertTrue({canonical_bytes(item["ref"]) for item in originals} <= retained)
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode),0o600)
        self.assertEqual({path:path.read_bytes() for path in self.originals},self.originals)


class RepairEmptyAdminTests(_AdminFixture, unittest.TestCase):
    def setUp(self):
        from tests.test_open_repair_empty_http import EmptyHTTPFixture
        self.empty_host = EmptyHTTPFixture(self)
        self.host = self.empty_host.http
        self.configure_owner()
        expected = self.empty_host.expected
        self.request.update(schema_version=EMPTY_REQUEST_SCHEMA,
            receipt_writer=expected["expected_receipt_writer"], message_id=expected["expected_message_id"],
            envelope_ref=expected["expected_envelope_ref"])

    def test_message_bound_command_exports_both_generations_and_preserves_private_state(self):
        code, output, error = self.call("recover-empty")
        self.assertEqual((code, error), (0, ""))
        result, evidence = json.loads(output), json.loads(self.output.read_bytes())
        self.assertEqual(result["state"], "ack_empty_source_recovered")
        self.assertFalse(result["recipient_saved"])
        self.assertFalse(self.vault.exists())
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)
        self.assertEqual(evidence["message_id"], self.request["message_id"])
        self.assertEqual(evidence["receipt_writer"], self.request["receipt_writer"])
        self.assertEqual(evidence["envelope_ref"], self.request["envelope_ref"])
        retained = {canonical_bytes(item["ref"]) for item in evidence["archive_statuses"]}
        expected_statuses = [self.empty_host.f["entries"][name] for name in ("owner_status", "target_status")]
        expected_statuses.extend(self.empty_host.expected["current_statuses"])
        self.assertTrue({canonical_bytes(item["ref"]) for item in expected_statuses} <= retained)
        for item in evidence["originals"]:
            raw = unb64url(item["raw_base64url"], maximum=524288)
            ref = item["ref"]
            rows = self.host.source.db.execute("""SELECT o.raw FROM open_repair_ack_objects o
                JOIN open_repair_ack_pins p ON p.namespace=o.namespace AND p.opaque_key=o.opaque_key
                WHERE p.resource_id=? AND o.namespace=? AND o.opaque_key=? AND o.raw_sha256=? AND o.size=?""",
                (self.host.source.resource_id, ref["namespace"], ref["key"], ref["raw_sha256"], ref["size"])).fetchall()
            self.assertTrue(rows)
            self.assertTrue(all(raw == bytes(row[0]) for row in rows))
        self.assertEqual({path: path.read_bytes() for path in self.originals}, self.originals)
        self.assertNotIn(b'"private_key"', self.output.read_bytes())

    def test_wrong_independent_tuple_writes_no_evidence(self):
        self.request["message_id"] = "synthetic-wrong-message"
        code, output, error = self.call("recover-empty")
        self.assertEqual((code, output), (1, ""))
        self.assertTrue(json.loads(error)["error"].startswith("repair_"))
        self.assertFalse(self.output.exists())
        self.assertFalse(self.vault.exists())


class RepairReplicaAdminTests(_AdminFixture,unittest.TestCase):
    repair_profile='receipt-index'
    command_timeout=60

    def setUp(self):
        from types import SimpleNamespace
        from tests.test_open_repair_copy_service import ReplicaReadHTTPTests
        from memory_vault_open_repair_admin import REPLICA_REQUEST_SCHEMA
        self.replica=ReplicaReadHTTPTests();self.addCleanup(self.replica.doCleanups);self.replica.setUp()
        self.host=SimpleNamespace(source=SimpleNamespace(temp=self.replica.h.destination.temp,fixture=self.replica.h.f))
        self.configure_owner()
        raw=canonical_bytes(self.replica.descriptor);digest=hashlib.sha256(raw).hexdigest()
        self.request.update(schema_version=REPLICA_REQUEST_SCHEMA,target=self.replica.expected['expected_target'],
            source=self.replica.context['expected_source'],source_storage_epoch=self.replica.context['source_storage_epoch'],
            maintainer=self.replica.context['expected_maintainer'],
            node=dict(raw_base64url=b64url(raw),ref=dict(namespace='meta',key=digest,raw_sha256=digest,size=len(raw))))

    def test_command_exports_full_replica_and_reuses_retained_statuses_after_restart(self):
        code,output,error=self.call('recover-replica');self.assertEqual((code,error),(0,''))
        result=json.loads(output);evidence=json.loads(self.output.read_bytes())
        self.assertEqual(result['state'],'ack_replica_unbound_source_recovered')
        self.assertFalse(result['recipient_saved']);self.assertFalse(result['vault_modified']);self.assertFalse(self.vault.exists())
        custody=evidence['replica_custody'];self.assertNotEqual(custody['ref']['key'],custody['ref']['raw_sha256'])
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode),0o600)
        self.replica.restart()
        self.output=self.directory/'second-evidence.json';self.request_path=self.directory/'second-request.json'
        code,output,error=self.call('recover-replica');self.assertEqual((code,error),(0,''))
        second=json.loads(self.output.read_bytes());self.assertEqual(second['replica_custody'],custody)
        self.assertGreater(json.loads(output)['requests'],2)
        self.assertEqual({path:path.read_bytes() for path in self.originals},self.originals)
        import sqlite3
        with sqlite3.connect(self.directory/'transport'/'network.sqlite3') as db:
            refs={bytes(row[0]) for row in db.execute('SELECT ref FROM open_ack_replica_statuses')}
        self.assertEqual(refs,{canonical_bytes(e['ref']) for e in second['archive_statuses']})
        self.assertNotIn(b'"private_key"',self.output.read_bytes())

    def test_failed_command_remembers_supplied_revocation_before_next_command(self):
        from tests.open_repair_ack_fixtures import signed_entry
        from unittest.mock import patch
        p=json.loads(self.replica.statuses[0]['raw'])['payload'];p['revision']+=1
        for item in p['entries']:item['status']='revoked'
        revoked=signed_entry(p,self.replica.h.f['signers']['owner'],'synthetic_admin_revocation')
        self.request['known_statuses']=[dict(raw_base64url=b64url(revoked['raw']),ref=revoked['ref'])]
        with patch('memory_vault_open_transport.OpenHTTPTransport.request_repair',side_effect=AssertionError('must not send')):
            code,output,error=self.call('recover-replica')
        self.assertEqual((code,output),(1,''));self.assertEqual(json.loads(error)['error'],'repair_authority_revoked')
        self.assertFalse(self.output.exists())
        self.request['known_statuses']=[];self.request_path=self.directory/'retry-request.json'
        with patch('memory_vault_open_transport.OpenHTTPTransport.request_repair',side_effect=AssertionError('forgot revocation')):
            code,output,error=self.call('recover-replica')
        self.assertEqual((code,output),(1,''));self.assertEqual(json.loads(error)['error'],'repair_authority_revoked')
        self.assertFalse(self.output.exists());self.assertFalse(self.vault.exists())

    def test_existing_replica_output_is_preserved_before_client_initialization(self):
        _write_new_private(self.output,b'synthetic original output\n')
        code,output,error=self.call('recover-replica')
        self.assertEqual((code,output),(1,''));self.assertEqual(json.loads(error)['error'],'repair_output_exists')
        self.assertEqual(self.output.read_bytes(),b'synthetic original output\n')
        self.assertFalse((self.directory/'transport').exists())


class _CopyAdminFixture(_AdminFixture):
    repair_profile = 'receipt-index'

    def configure_copy(self, h, descriptor, operation):
        from types import SimpleNamespace
        from memory_vault_open_repair_admin import COPY_REQUEST_SCHEMA
        self.host = SimpleNamespace(source=SimpleNamespace(temp=h.destination.temp, fixture=h.f))
        self.configure_owner('maintainer')
        self.f = h.f
        self.encode = lambda entry: dict(raw_base64url=b64url(entry['raw']), ref=entry['ref'])
        raw = canonical_bytes(descriptor); digest = hashlib.sha256(raw).hexdigest()
        self.request = dict(schema_version=COPY_REQUEST_SCHEMA, operation=operation,
            node=self.encode(dict(raw=raw, ref=dict(namespace='meta', key=digest, raw_sha256=digest, size=len(raw)))),
            ack_slot=h.f['expected']['expected_ack_slot'], owner=h.f['expected']['expected_owner'],
            source=h.f['expected']['expected_target'], source_storage_epoch=h.f['expected']['target_storage_epoch'],
            manifest=self.encode(h.f['manifest']), custody=self.encode(h.f['custody']), reservation=self.encode(h.consent),
            intent=h.intent, originals=[self.encode(e) for e in h.f['packs']])


class RepairCopyReserveAdminTests(_CopyAdminFixture, unittest.TestCase):
    def setUp(self):
        from tests.test_open_repair_copy_resources import RemoteCopyClientHTTPTests
        from tests.open_repair_ack_fixtures import signed_entry
        self.remote=RemoteCopyClientHTTPTests();self.addCleanup(self.remote.doCleanups);self.remote.setUp()
        h=self.remote.h;self.configure_copy(h,self.remote.descriptor,'reserve')
        self.request['current_statuses']=[self.encode(signed_entry(h.owner_status,h.f['signers']['owner'],'copy_current')),
            self.encode(h.f['entries']['target_status'])]

    def test_reservation_command_assigns_real_offer_and_replays_after_restart(self):
        code,output,error=self.call('copy-reserve');self.assertEqual((code,error),(0,''))
        evidence=json.loads(self.output.read_bytes())
        self.assertEqual(evidence['state'],'capacity_reserved_and_assigned')
        assignment=json.loads(unb64url(evidence['assignment']['raw_base64url'], maximum=524288))['payload']
        self.assertEqual(assignment['resource_offer_ref'],evidence['offer']['ref'])
        self.remote.restart();self.request_path=self.directory/'retry.json';self.output=self.directory/'retry-result.json'
        code,output,error=self.call('copy-reserve');self.assertEqual((code,error),(0,''))
        self.assertEqual(json.loads(self.output.read_bytes()),evidence)
        self.assertEqual(self.remote.h.destination.db.execute('SELECT count(*) FROM open_repair_copy_resources').fetchone()[0],1)
        self.assertFalse(self.vault.exists());self.assertFalse(json.loads(output)['recipient_saved'])
        self.assertEqual({path:path.read_bytes() for path in self.originals},self.originals)

    def test_existing_output_prevents_network_and_transport_initialization(self):
        _write_new_private(self.output,b'original synthetic output\n')
        code,output,error=self.call('copy-reserve');self.assertEqual((code,output),(1,''))
        self.assertEqual(json.loads(error)['error'],'repair_output_exists')
        self.assertFalse((self.directory/'transport').exists())
        self.assertEqual(self.output.read_bytes(),b'original synthetic output\n')


class RepairCopyUploadAdminTests(_CopyAdminFixture, unittest.TestCase):
    def setUp(self):
        from tests.test_open_repair_copy_upload import CopyUploadHTTPTests
        from tests.open_repair_ack_fixtures import signed_entry
        self.remote=CopyUploadHTTPTests();self.addCleanup(self.remote.doCleanups);self.remote.setUp()
        h=self.remote.h;self.configure_copy(h.base,self.remote.descriptor,'upload')
        for name,entry in dict(allocation=h.request,offer=h.offer,assignment=h.assignment,
                owner_disclosure=h.disclosures['owner'],source_disclosure=h.disclosures['source']).items():
            self.request[name]=self.encode(entry)
        self.request['current_statuses']=[self.encode(signed_entry(p,s,'current_'+str(i)))
            for i,(p,s) in enumerate(zip(h.status_values,h.status_signers))]
        # Seed only the synthetic maintainer's previously prepared local journal.
        from memory_vault_open_client import OpenNetworkClient
        with OpenNetworkClient(self.network) as network, network.participant.state.db() as db:
            for table,sql in h.base.local.db.execute("SELECT name,sql FROM sqlite_master WHERE type='table' AND name LIKE 'ack_copy_prepare_%'").fetchall():
                db.execute(sql)
                for row in h.base.local.db.execute('SELECT * FROM '+table).fetchall():
                    db.execute('INSERT INTO '+table+' VALUES('+','.join('?' for _ in row)+')',row)
            db.commit()

    def test_upload_command_commits_originals_and_reuses_same_custody_after_restart(self):
        code,output,error=self.call('copy-upload');self.assertEqual((code,error),(0,''))
        first=json.loads(self.output.read_bytes());self.assertEqual(first['state'],'replica_committed')
        self.assertFalse(first['recipient_saved']);self.assertFalse(self.vault.exists())
        self.assertNotEqual(first['custody']['ref']['key'],first['custody']['ref']['raw_sha256'])
        self.remote.restart();self.output=self.directory/'retry-result.json';self.request_path=self.directory/'retry.json'
        code,output,error=self.call('copy-upload');self.assertEqual((code,error),(0,''))
        self.assertEqual(json.loads(self.output.read_bytes()),first)
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode),0o600)
        self.assertEqual({path:path.read_bytes() for path in self.originals},self.originals)


class RepairReplicaConfigureAdminTests(unittest.TestCase):
    def setUp(self):
        from tests.test_open_repair_copy_service import ReplicaReadHTTPTests
        from memory_vault_open_repair_admin import REPLICA_CONFIG_SCHEMA
        from memory_vault_open_node import NODE_CONFIG
        self.remote=ReplicaReadHTTPTests();self.addCleanup(self.remote.doCleanups);self.remote.setUp()
        host=self.remote;state=host.h.destination.state
        self.directory=host.directory/'synthetic-operator';self.directory.mkdir(mode=0o700)
        identity=self.directory/'identity.json';encryption=self.directory/'encryption.json'
        secret=state.identity._private_key.private_bytes(serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,serialization.NoEncryption())
        _write_new_private(identity,canonical_bytes(dict(state.identity.public_descriptor(),
            schema_version='universal-memory-identity/v1',private_key=base64.b64encode(secret).decode())))
        state.encryption_identity.save(encryption)
        self.config=self.directory/'node.json'
        _write_new_private(self.config,canonical_bytes(dict(schema_version=NODE_CONFIG,
            identity_path=str(identity),encryption_key_path=str(encryption),state_directory=str(host.directory),
            node=host.descriptor,seeds=[],allow_loopback=True,index_policy=dict(enabled=False),
            repair_policy=dict(enabled=True,limit_policy=host.h.f['expected']['limit_policy']),
            listen_host='127.0.0.1',listen_port=host.server.server_port)))
        encode=lambda e:dict(raw_base64url=b64url(e['raw']),ref=e['ref'])
        self.request=dict(schema_version=REPLICA_CONFIG_SCHEMA,resource_id=host.rid,context=host.context,
            consents={name:encode(e) for name,e in host.consents.items()},current_statuses=[encode(e) for e in host.statuses])
        self.request_path=self.directory/'request.json';self.output=self.directory/'result.json'
        self.originals={path:path.read_bytes() for path in (identity,encryption,self.config)}
        with host.participant.state.db() as db:db.execute('DELETE FROM open_repair_copy_read_config')

    def call(self):
        _write_new_private(self.request_path,canonical_bytes(self.request))
        stdout,stderr=io.StringIO(),io.StringIO()
        with contextlib.redirect_stdout(stdout),contextlib.redirect_stderr(stderr):
            code=main(['configure-replica','--node-config',str(self.config),'--request',str(self.request_path),
                '--output',str(self.output)])
        return code,stdout.getvalue(),stderr.getvalue()

    def test_configured_permissions_enable_real_recovery_after_restart(self):
        code,output,error=self.call();self.assertEqual((code,error),(0,''))
        result=json.loads(output);self.assertEqual(result['state'],'configured');self.assertFalse(result['network_started'])
        self.assertFalse(result['recipient_saved']);self.assertFalse(result['vault_modified'])
        self.assertEqual({path:path.read_bytes() for path in self.originals},self.originals)
        self.remote.restart();client,args=self.remote.recovery_client()
        recovered=client.recover_replica(self.remote.base,**args)
        self.assertEqual(recovered.replica['source'].custody.raw,self.remote.h.f['custody']['raw'])
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode),0o600)

    def test_missing_independent_consent_does_not_enable_read(self):
        del self.request['consents']['source']
        code,output,error=self.call();self.assertEqual((code,output),(1,''));self.assertFalse(self.output.exists())
        with self.remote.participant.state.db() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM open_repair_copy_read_config').fetchone()[0],0)


class RepairSetupTests(unittest.TestCase):
    def test_remote_copy_is_explicit_requires_repair_and_keeps_new_node_offline(self):
        from memory_vault import MemoryError
        from memory_vault_open_repair_copy_resources import REMOTE_COPY_POLICY
        with tempfile.TemporaryDirectory(prefix='synthetic-remote-copy-node-') as temporary:
            root=Path(temporary).resolve();directory=root/'copy-node'
            with self.assertRaisesRegex(MemoryError,'open_invalid_repair_policy'):
                initialize_node(directory,base_url='https://synthetic-copy.example',enable_remote_copy=True)
            self.assertFalse(directory.exists())
            result=initialize_node(directory,base_url='https://synthetic-copy.example',enable_repair=True,
                enable_remote_copy=True,repair_profile='receipt-index')
            config=json.loads(Path(result['config_path']).read_bytes())
            self.assertEqual(config['repair_policy']['remote_copy'],dict(REMOTE_COPY_POLICY,enabled=True))
            self.assertTrue(config['provider_policy']['enabled']);self.assertFalse(result['network_started'])
            self.assertFalse((directory/'state'/'network.sqlite3').exists())

    def test_new_node_can_explicitly_enable_finite_repair_and_lists_proxy_path(self):
        with tempfile.TemporaryDirectory(prefix="synthetic-repair-setup-") as temporary:
            directory = Path(temporary).resolve() / "node"
            result = initialize_node(directory, base_url="https://synthetic-node.example", enable_repair=True)
            config = json.loads(Path(result["config_path"]).read_bytes())
            self.assertIs(config["repair_policy"]["enabled"], True)
            self.assertEqual(config["repair_policy"]["limit_policy"]["max_signature_checks"], 512)
            self.assertIn("/open/v1/repair/bootstrap", result["https_paths"])
            self.assertFalse(result["network_started"])
            self.assertFalse((directory / "state" / "network.sqlite3").exists())


if __name__ == "__main__":
    unittest.main()
