"""Native private command exports and restart authority across actual HTTP."""
import contextlib
import io
import json
import stat
import subprocess
import time
import unittest

from memory_vault import canonical_bytes
from memory_vault_network_crypto import b64url
from memory_vault_trust import _write_new_private
from tests.test_open_repair_admin import _AdminFixture,EMPTY_REQUEST_SCHEMA,OCCUPIED_REQUEST_SCHEMA
from tests import test_network_typescript_agent_network as ts_runtime

DRIVER=r"""
import child from 'node:child_process';
import {syncBuiltinESMExports} from 'node:module';
let calls=0;const deny=()=>{calls++;throw Error('native command delegated');};
for(const name of ['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork'])child[name]=deny;
syncBuiltinESMExports();
const chunks=[];for await(const chunk of process.stdin)chunks.push(chunk);
const request=JSON.parse(Buffer.concat(chunks).toString('utf8'));
Date.now=()=>request.now*1000;
const {main}=await import('./open-repair-admin.ts');
const code=await main(request.argv);
if(calls)throw Error('native command delegated');
process.exitCode=code;
"""

class NativeRepairAdminTests(_AdminFixture,unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ts_runtime.TypeScriptAgentNetworkTests.setUpClass.__func__(cls)
        (cls.fixture/'driver.mjs').write_text(DRIVER)

    def setup_phase(self,phase):
        if phase=='unbound':
            from tests.test_open_repair_http import RepairHTTPTests
            self.host=RepairHTTPTests();self.addCleanup(self.host.doCleanups);self.host.setUp()
        elif phase=='empty':
            from tests.test_open_repair_empty_http import EmptyHTTPFixture
            held=EmptyHTTPFixture(self,signature_limit=1024,proof_limit=1048576);self.host=held.http
        else:
            from tests.test_open_repair_occupied_client import OccupiedHTTPFixture
            occupied=OccupiedHTTPFixture(self);held=occupied.empty;self.host=occupied.http;self.occupied=occupied
        self.configure_owner()
        if phase!='unbound':
            expected=held.expected
            self.request.update(schema_version=EMPTY_REQUEST_SCHEMA if phase=='empty' else OCCUPIED_REQUEST_SCHEMA,
                receipt_writer=expected['expected_receipt_writer'],message_id=expected['expected_message_id'],envelope_ref=expected['expected_envelope_ref'])
        self.command={'unbound':'recover-ack','empty':'recover-empty','occupied':'recover-occupied'}[phase]

    def call(self,command=None):
        _write_new_private(self.request_path,canonical_bytes(self.request))
        result=subprocess.run([self.node,'--experimental-strip-types',str(self.fixture/'driver.mjs')],cwd=self.fixture,
            input=json.dumps(dict(now=int(time.time()),argv=[command or self.command,'--network-config',str(self.network),
                '--request',str(self.request_path),'--output',str(self.output),'--repair-profile','receipt','--timeout','60'])).encode(),
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=90)
        # Node's experimental SQLite warning is not the command's JSON error.
        errors=[line for line in result.stderr.decode().splitlines() if line.startswith('{')]
        if result.returncode and not errors:self.fail(result.stderr.decode()[-4000:])
        return result.returncode,result.stdout.decode(),errors[-1] if errors else ''

    def test_native_unbound_exports_exact_private_evidence_without_vault(self):
        self.setup_phase('unbound');code,output,error=self.call();self.assertEqual((code,error),(0,''))
        value=json.loads(output);evidence=json.loads(self.output.read_bytes())
        self.assertEqual(value['state'],'ack_unbound_source_recovered');self.assertFalse(value['recipient_saved'])
        self.assertGreater(value['requests'],2);self.assertFalse(self.vault.exists())
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode),0o600)
        for item in evidence['originals']:
            from memory_vault_network_crypto import unb64url
            self.assertEqual(unb64url(item['raw_base64url'],maximum=524288),self.host.source.state.read_local_original(self.host.source.resource_id,item['ref']))
        self.assertEqual({p:p.read_bytes() for p in self.originals},self.originals)

    def test_native_commands_keep_revocation_across_restart_in_all_phases(self):
        from tests.open_repair_ack_fixtures import signed_entry
        from memory_vault_open_repair_admin import main
        for phase in ('unbound','empty','occupied'):
            with self.subTest(phase=phase):
                self.setup_phase(phase);f=self.host.source.fixture
                payload=json.loads(f['entries']['owner_status']['raw'])['payload'];payload['revision']+=1
                for item in payload['entries']:item['status']='revoked'
                revoked=signed_entry(payload,f['signers']['owner'],'synthetic_native_revocation')
                self.request['known_statuses']=[dict(raw_base64url=b64url(revoked['raw']),ref=revoked['ref'])]
                for attempt in range(2):
                    code,output,error=self.call();self.assertEqual((code,output),(1,''))
                    self.assertEqual(json.loads(error)['error'],'repair_authority_revoked')
                    self.assertFalse(self.output.exists());self.assertFalse(self.vault.exists())
                    self.request['known_statuses']=[];self.request_path=self.directory/f'retry-{attempt}.json'
                # Python must read the same authenticated native journal, too.
                _write_new_private(self.request_path,canonical_bytes(self.request))
                stdout,stderr=io.StringIO(),io.StringIO()
                with contextlib.redirect_stdout(stdout),contextlib.redirect_stderr(stderr):
                    code=main([self.command,'--network-config',str(self.network),'--request',str(self.request_path),'--output',str(self.output),'--repair-profile','receipt'])
                self.assertEqual(code,1);self.assertEqual(json.loads(stderr.getvalue())['error'],'repair_authority_revoked')
                self.assertEqual(self.host.source.db.execute('SELECT count(*) FROM open_repair_bootstrap_challenges').fetchone()[0],0)

    def test_native_empty_recovers_again_with_retained_statuses(self):
        self.setup_phase('empty');code,output,error=self.call();self.assertEqual((code,error),(0,''))
        first=json.loads(self.output.read_bytes());self.output=self.directory/'second.json';self.request_path=self.directory/'second-request.json'
        code,output,error=self.call();self.assertEqual((code,error),(0,''))
        second=json.loads(self.output.read_bytes());refs=lambda items:{canonical_bytes(i['ref']) for i in items}
        self.assertTrue(refs(first['archive_statuses'])<=refs(second['archive_statuses']))
        self.assertFalse(self.vault.exists())

    def test_existing_output_is_refused_before_transport_state(self):
        self.setup_phase('unbound');_write_new_private(self.output,b'synthetic existing output\n')
        code,output,error=self.call();self.assertEqual((code,output),(1,''));self.assertEqual(json.loads(error)['error'],'repair_output_exists')
        self.assertEqual(self.output.read_bytes(),b'synthetic existing output\n');self.assertFalse((self.directory/'transport').exists())

    def test_native_occupied_exports_actual_recipient_receipt(self):
        from memory_vault_network_crypto import unb64url
        self.setup_phase('occupied');code,output,error=self.call();self.assertEqual((code,error),(0,''))
        summary=json.loads(output);evidence=json.loads(self.output.read_bytes())
        self.assertTrue(summary['recipient_saved'])
        self.assertEqual(unb64url(evidence['recipient_receipt']['raw_base64url'],maximum=4096),self.occupied.receipt['raw'])
        self.assertEqual(evidence['recipient_receipt']['ref'],self.occupied.receipt['ref'])
        self.assertFalse(self.vault.exists())

    def test_forged_status_cannot_poison_native_journal(self):
        from tests.open_repair_ack_fixtures import signed_entry
        from memory_vault_open_client import OpenNetworkClient
        self.setup_phase('unbound');f=self.host.source.fixture
        payload=json.loads(f['entries']['owner_status']['raw'])['payload'];payload['revision']+=1
        for item in payload['entries']:item['status']='revoked'
        forged=signed_entry(payload,f['signers']['target'],'synthetic_native_wrong_signer')
        self.request['known_statuses']=[dict(raw_base64url=b64url(forged['raw']),ref=forged['ref'])]
        code,output,error=self.call();self.assertEqual((code,output),(1,''));self.assertFalse(self.output.exists())
        with OpenNetworkClient(self.network) as network,network.participant.state.db() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM open_ack_replica_statuses').fetchone()[0],0)
        self.request['known_statuses']=[];self.request_path=self.directory/'authentic.json'
        code,output,error=self.call();self.assertEqual((code,error),(0,''))

    def test_native_reads_python_retained_revocation(self):
        from tests.open_repair_ack_fixtures import signed_entry
        self.setup_phase('unbound');f=self.host.source.fixture
        payload=json.loads(f['entries']['owner_status']['raw'])['payload'];payload['revision']+=1
        for item in payload['entries']:item['status']='revoked'
        revoked=signed_entry(payload,f['signers']['owner'],'synthetic_python_revocation')
        self.request['known_statuses']=[dict(raw_base64url=b64url(revoked['raw']),ref=revoked['ref'])]
        code,output,error=_AdminFixture.call(self)
        self.assertEqual((code,output),(1,''));self.assertEqual(json.loads(error)['error'],'repair_authority_revoked')
        self.request['known_statuses']=[];self.request_path=self.directory/'native-retry.json'
        code,output,error=self.call()
        self.assertEqual((code,output),(1,''));self.assertEqual(json.loads(error)['error'],'repair_authority_revoked')
        self.assertFalse(self.output.exists());self.assertFalse(self.vault.exists())
        self.assertEqual(self.host.source.db.execute('SELECT count(*) FROM open_repair_bootstrap_challenges').fetchone()[0],0)
