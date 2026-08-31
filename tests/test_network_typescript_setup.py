"""Synthetic Node-only key/config setup, independently verified by Python.

The Node child has an empty PATH, blocked subprocess/network entrypoints, and
only explicitly selected disposable files. No installs or real credentials.
"""
from __future__ import annotations

import base64
import contextlib
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from memory_vault import build_record, canonical_bytes
from memory_vault_client import ClientConfig
from memory_vault_network import HTTPTransport, NetworkClient
from memory_vault_network_admin import configure_network, create_identity
from memory_vault_network_control import issue_invite, issue_roster, member, verify_invite
from memory_vault_network_crypto import EncryptionIdentity, PublicKeyTrust, decrypt_bytes, document_sha256, encrypt_bytes
from memory_vault_trust import Identity, TrustStore


DRIVER = r"""
import fs from 'node:fs';
import child from 'node:child_process';
import net from 'node:net';
import http from 'node:http';
import https from 'node:https';
import { syncBuiltinESMExports } from 'node:module';
const chunks = []; let size = 0;
for await (const chunk of process.stdin) {
  size += chunk.length; if (size > 4*1024*1024) throw Error('synthetic fixture limit'); chunks.push(chunk);
}
const input = JSON.parse(Buffer.concat(chunks).toString('utf8'));
let networkCalls = 0, subprocessCalls = 0, fsyncCalls = 0;
const denyNetwork = () => { networkCalls++; throw Error('setup must not access network'); };
const denySubprocess = () => { subprocessCalls++; throw Error('setup must not start subprocesses'); };
for (const name of ['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork']) child[name] = denySubprocess;
net.Socket.prototype.connect = denyNetwork;
net.Server.prototype.listen = denyNetwork;
http.request = https.request = http.get = https.get = denyNetwork;
globalThis.fetch = denyNetwork;
const realSync = fs.fsyncSync;
fs.fsyncSync = function(fd) {
  fsyncCalls++;
  if (input.failFsyncAt === fsyncCalls) { const error = Error('synthetic fsync failure'); error.code='EIO'; throw error; }
  return realSync.call(fs,fd);
};
syncBuiltinESMExports();
const setup = await import('./setup.ts');
const crypto = await import('./crypto.ts');
const records = await import('./records.ts');
async function run(operation) {
  if (operation.op === 'create') return setup.createIdentity(operation.directory);
  if (operation.op === 'configure') return setup.configureNetwork(operation.options);
  if (operation.op === 'trust') return setup.readTrustedKeys(operation.path);
  if (operation.op === 'sign') {
    const identity = JSON.parse(fs.readFileSync(operation.path,'utf8'));
    return records.signRecord(operation.record,identity);
  }
  if (operation.op === 'decrypt') {
    const identity = JSON.parse(fs.readFileSync(operation.path,'utf8'));
    return Buffer.from(await crypto.decryptBytes(operation.jwe, identity, {context:operation.context})).toString('base64');
  }
  if (operation.op === 'encrypt') return crypto.encryptBytes(Buffer.from(operation.raw,'base64'),
    operation.recipients, {context:operation.context});
  throw Error('unknown fixture operation');
}
const results=[];
for (const operation of input.operations) {
  try { results.push({ok:true,result:await run(operation)}); }
  catch (error) { results.push({ok:false,error:error.code ?? 'unexpected_error'}); }
}
process.stdout.write(JSON.stringify({results,networkCalls,subprocessCalls,fsyncCalls}));
"""


@unittest.skipUnless(os.name == 'posix', 'Current independent protected setup supports POSIX only')
class TypeScriptSetupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.node = shutil.which('node')
        if cls.node is None:
            raise unittest.SkipTest('Existing Node TypeScript stripping required')
        package = ROOT / 'clients/typescript/network/node_modules/jose'
        selected = os.environ.get('MEMORY_VAULT_JOSE_MODULE')
        if selected:
            entry = Path(selected).resolve()
            if entry.parts[-3:] != ('dist','webapi','index.js'):
                raise RuntimeError('Expected explicit jose/dist/webapi/index.js')
            package = entry.parents[2]
        if not (package/'package.json').is_file():
            raise unittest.SkipTest('Preinstalled locked jose required; tests never install')
        metadata = json.loads((package/'package.json').read_text())
        if (metadata.get('name'),metadata.get('version')) != ('jose','6.2.10'):
            raise RuntimeError('Exact locked jose 6.2.10 required')
        cls.temporary = tempfile.TemporaryDirectory(prefix='memory-vault-ts-setup-synthetic-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.fixture = Path(cls.temporary.name).resolve()
        for name in ('crypto.ts','records.ts','setup.ts','io.ts','transport.ts','package.json'):
            shutil.copyfile(ROOT/'clients/typescript/network'/name,cls.fixture/name)
        (cls.fixture/'node_modules').mkdir()
        (cls.fixture/'node_modules/jose').symlink_to(package,target_is_directory=True)
        (cls.fixture/'driver.mjs').write_text(DRIVER)

    def setUp(self) -> None:
        self.directory = Path(tempfile.mkdtemp(prefix='case-',dir=self.fixture))
        self.candidate = self.directory/'candidate'
        self.issuer = Identity.generate(self.directory/'issuer-private.json')
        self.issuer_public = self.directory/'issuer-public.json'
        self.write(self.issuer_public,self.issuer.public_descriptor(),mode=0o644)

    @staticmethod
    def write(path: Path, value: object, *, mode: int = 0o600) -> None:
        path.write_bytes(canonical_bytes(value)+b'\n')
        path.chmod(mode)

    def run_ts(self,*operations: dict, fail_fsync_at: int | None = None) -> dict:
        value = {'operations':operations}
        if fail_fsync_at is not None:
            value['failFsyncAt']=fail_fsync_at
        process = subprocess.run([self.node,'--experimental-strip-types',str(self.fixture/'driver.mjs')],
                                 input=json.dumps(value).encode(),capture_output=True,timeout=30,
                                 cwd=self.fixture,env={**os.environ,'PATH':''})
        self.assertEqual(process.returncode,0,process.stderr.decode(errors='replace')[-2000:])
        result=json.loads(process.stdout)
        self.assertEqual(result['networkCalls'],0)
        self.assertEqual(result['subprocessCalls'],0)
        self.assertEqual(len(result['results']),len(operations))
        return result

    def success(self,operation: dict):
        value=self.run_ts(operation)['results'][0]
        self.assertTrue(value['ok'],value)
        return value['result']

    def created(self):
        return self.success({'op':'create','directory':str(self.candidate)})

    def options(self, **overrides) -> dict:
        return {'clientConfig':str(self.candidate/'client.json'),'encryptionKey':str(self.candidate/'encryption.json'),
                'issuerPublic':str(self.issuer_public),'networkId':'synthetic-ts-setup',
                'authorityUrl':'https://issuer.example.invalid/','relays':['http://127.0.0.1:8765/'],
                'output':str(self.candidate/'network.json'),**overrides}

    @staticmethod
    def snapshot(directory: Path) -> dict:
        return {str(path.relative_to(directory)):hashlib.sha256(path.read_bytes()).hexdigest()
                for path in directory.rglob('*') if path.is_file() and not path.is_symlink()}

    def test_native_key_generation_python_loading_and_both_crypto_directions(self) -> None:
        result=self.created()
        self.assertEqual(result['state'],'identity_created')
        self.assertEqual(set(path.name for path in self.candidate.iterdir()),
                         {'identity.json','encryption.json','trust.json','member-public.json','client.json'})
        self.assertEqual(self.candidate.stat().st_mode&0o777,0o700)
        for path in self.candidate.iterdir():
            self.assertEqual(path.stat().st_mode&0o777,0o600)
        signing=Identity.load(self.candidate/'identity.json')
        encryption=EncryptionIdentity.load(self.candidate/'encryption.json')
        trust=TrustStore(self.candidate/'trust.json')
        trust.require_trusted(signing.key_id)
        candidate=member(json.loads((self.candidate/'member-public.json').read_text()))
        self.assertEqual(candidate['signing_key'],signing.public_descriptor())
        self.assertEqual(candidate['encryption_key'],encryption.public_descriptor())
        self.assertEqual(result['member_key_id'],signing.key_id)
        self.assertNotIn('private_key',(self.candidate/'member-public.json').read_text())
        private_signing=json.loads((self.candidate/'identity.json').read_text())
        private_encryption=json.loads((self.candidate/'encryption.json').read_text())
        self.assertNotEqual(base64.b64decode(private_signing['private_key']),
                            base64.urlsafe_b64decode(private_encryption['private_key']+'='))
        client=ClientConfig.load(self.candidate/'client.json')
        self.assertFalse(client.capture_visible_turns)
        self.assertFalse(client.vault_path.exists())
        record=build_record(kind='fact',text='Synthetic independent key test 中文😀',created_at='2026-08-31T00:00:00Z')
        proof=self.success({'op':'sign','path':str(self.candidate/'identity.json'),'record':record})
        self.assertEqual(trust.verify_record(record,proof),signing.key_id)
        self.assertEqual(proof,signing.sign_record(record))
        context={'network_id':'synthetic-ts-setup','purpose':'independent-setup-fixture'}
        plaintext=b'SYNTHETIC-EXACT-BYTES\x00\xff'
        python_jwe=encrypt_bytes(plaintext,[encryption.public_descriptor()],context=context)
        opened=self.success({'op':'decrypt','path':str(self.candidate/'encryption.json'),'jwe':python_jwe,'context':context})
        self.assertEqual(base64.b64decode(opened),plaintext)
        ts_jwe=self.success({'op':'encrypt','raw':base64.b64encode(plaintext).decode(),
                            'recipients':[encryption.public_descriptor()],'context':context})
        self.assertEqual(decrypt_bytes(ts_jwe,encryption,context=context),plaintext)

    def test_candidate_public_request_needs_independent_issuer_grant(self) -> None:
        self.created()
        candidate=member(json.loads((self.candidate/'member-public.json').read_text()))
        now=int(time.time())
        roster=issue_roster(self.issuer,network_id='synthetic-ts-setup',version=1,previous_sha256='0'*64,
                            members=[candidate],issued_at=now,expires_at=now+300)
        invitation=issue_invite(self.issuer,network_id='synthetic-ts-setup',invite_id='synthetic-candidate-invitation',
                               candidate_signing_key=candidate['signing_key'],candidate_encryption_key=candidate['encryption_key'],
                               scope=['receive','send'],handoff_sha256=hashlib.sha256(b'').hexdigest(),
                               roster_sha256=document_sha256(roster),issued_at=now,expires_at=now+600)
        verified=verify_invite(invitation,PublicKeyTrust([self.issuer.public_descriptor()]),network_id='synthetic-ts-setup')
        self.assertEqual(verified['candidate_signing_key'],candidate['signing_key'])
        self.assertFalse((self.candidate/'issuer-public.json').exists())
        before=(self.candidate/'trust.json').read_bytes()
        configured=self.success({'op':'configure','options':self.options()})
        self.assertFalse(configured['issuer_key_shared_with_endpoint'])
        self.assertIsNone(configured['warning'])
        self.assertEqual((self.candidate/'trust.json').read_bytes(),before)
        self.assertNotIn(self.issuer.key_id,json.loads(before)['keys'])
        with mock.patch.object(HTTPTransport,'request',side_effect=AssertionError('setup verifier no network')):
            client=NetworkClient(self.candidate/'network.json')
            self.assertEqual(client.issuers.require_trusted(self.issuer.key_id)['key_id'],self.issuer.key_id)
            self.assertEqual(client.identity.key_id,candidate['signing_key']['key_id'])
            self.assertEqual(client.relays,['http://127.0.0.1:8765'])
        self.assertFalse((self.candidate/'network-state').exists())
        self.assertFalse((self.candidate/'vault').exists())

    def test_existing_python_identity_and_vault_config_are_not_modified(self) -> None:
        create_identity(self.candidate)
        vault=self.candidate/'already-existing.sqlite3'
        with contextlib.closing(sqlite3.connect(vault)) as connection:
            connection.execute('CREATE TABLE synthetic(value TEXT)')
            connection.execute("INSERT INTO synthetic VALUES('preserve-history')")
            connection.commit()
        vault.chmod(0o600)
        config=json.loads((self.candidate/'client.json').read_text())
        config['vault_path']=str(vault)
        config['sync_config_path']=str(self.candidate/'existing-sync-config.json')
        self.write(self.candidate/'client.json',config)
        before=self.snapshot(self.candidate)
        result=self.success({'op':'configure','options':self.options()})
        after=self.snapshot(self.candidate)
        self.assertEqual({key:value for key,value in after.items() if key!='network.json'},before)
        self.assertFalse(result['vault_created'])
        ts_config=json.loads((self.candidate/'network.json').read_text())
        other=self.candidate/'python-network.json'
        configure_network(client_config=self.candidate/'client.json',encryption_key=self.candidate/'encryption.json',
                          issuer_public=self.issuer_public,network_id='synthetic-ts-setup',authority_url='https://issuer.example.invalid/',
                          relays=['http://127.0.0.1:8765/'],output=other)
        python_config=json.loads(other.read_text())
        python_config['state_directory']=ts_config['state_directory']
        self.assertEqual(ts_config,python_config)

    def test_bad_inputs_private_issuer_and_path_overlap_fail_before_output(self) -> None:
        self.created()
        before=self.snapshot(self.candidate)
        variations=[{'issuerPublic':str(self.directory/'issuer-private.json')},
                    {'authorityUrl':'http://remote.example.invalid'}, {'authorityUrl':'https://issuer.example.invalid/path'},
                    {'authorityUrl':'https://user:password@example.invalid'}, {'authorityUrl':'https://issuer.example.invalid/#secret'},
                    {'relays':[]}, {'relays':['http://127.0.0.1:8765']*2},
                    {'relays':['http://127.1:8765']}, {'networkId':'bad network'},
                    {'encryptionKey':str(self.candidate/'identity.json')},
                    {'output':str(self.candidate/'identity.json')},
                    {'output':str(self.candidate/'missing-parent'/'network.json')},
                    {'output':str(self.candidate/'network-state.json'),'encryptionKey':str(self.candidate/'network-state-state'/'key.json')}]
        results=self.run_ts(*[{'op':'configure','options':self.options(**change)} for change in variations])['results']
        for result in results:
            self.assertFalse(result['ok'],result)
            self.assertNotEqual(result['error'],'unexpected_error')
        self.assertFalse((self.candidate/'network.json').exists())
        self.assertEqual(self.snapshot(self.candidate),before)
        client_path=self.candidate/'client.json'
        original=client_path.read_bytes()
        config=json.loads(original)
        config['vault_path']=str(self.candidate/'network-state'/'memory.sqlite3')
        self.write(client_path,config)
        rejected=self.run_ts({'op':'configure','options':self.options()})['results'][0]
        self.assertEqual(rejected['error'],'network_configuration_path_conflict')
        self.assertFalse((self.candidate/'network-state').exists())
        self.assertFalse((self.candidate/'network.json').exists())
        client_path.write_bytes(original)
        # Existing transport history is not attached/overwritten by new config.
        state=self.candidate/'network-state'
        state.mkdir(mode=0o700)
        history=state/'history'
        history.write_bytes(b'SYNTHETIC-HISTORY')
        result=self.run_ts({'op':'configure','options':self.options()})['results'][0]
        self.assertFalse(result['ok'])
        self.assertEqual(result['error'],'network_setup_state_exists')
        self.assertEqual(history.read_bytes(),b'SYNTHETIC-HISTORY')
        self.assertFalse((self.candidate/'network.json').exists())

    def test_new_only_creation_symlinks_and_existing_output_are_preserved(self) -> None:
        self.created()
        before=self.snapshot(self.candidate)
        alias=self.directory/'alias'
        alias.symlink_to(self.candidate,target_is_directory=True)
        missing=self.directory/'missing'/'candidate'
        results=self.run_ts({'op':'create','directory':str(self.candidate)},
                            {'op':'create','directory':str(alias)},
                            {'op':'create','directory':str(missing)},
                            {'op':'create','directory':'relative-path'})['results']
        self.assertTrue(all(not item['ok'] for item in results))
        self.assertEqual(self.snapshot(self.candidate),before)
        self.assertFalse(missing.parent.exists())
        self.success({'op':'configure','options':self.options()})
        output=(self.candidate/'network.json').read_bytes()
        failed=self.run_ts({'op':'configure','options':self.options(networkId='different-network')})['results'][0]
        self.assertEqual(failed['error'],'network_config_exists')
        self.assertEqual((self.candidate/'network.json').read_bytes(),output)
        link=self.candidate/'linked-network.json'
        link.symlink_to(self.candidate/'identity.json')
        failed=self.run_ts({'op':'configure','options':self.options(output=str(link))})['results'][0]
        self.assertFalse(failed['ok'])
        self.assertEqual(hashlib.sha256((self.candidate/'identity.json').read_bytes()).hexdigest(),before['identity.json'])

    def test_explicit_legacy_shared_issuer_is_flagged_not_implicitly_enrolled(self) -> None:
        result=self.created()
        public=json.loads((self.candidate/'member-public.json').read_text())['signing_key']
        chosen=self.candidate/'explicit-owner-public.json'
        self.write(chosen,public)
        before=(self.candidate/'trust.json').read_bytes()
        configured=self.success({'op':'configure','options':self.options(issuerPublic=str(chosen))})
        self.assertTrue(configured['issuer_key_shared_with_endpoint'])
        self.assertIn('not isolated',configured['warning'])
        self.assertEqual(configured['member_key_id'],result['member_key_id'])
        self.assertEqual((self.candidate/'trust.json').read_bytes(),before)
        client=NetworkClient(self.candidate/'network.json')
        self.assertEqual(client.identity.key_id,public['key_id'])

    def test_current_trust_signed64_revision_and_strict_documents(self) -> None:
        self.created()
        trust_path=self.candidate/'trust.json'
        original=json.loads(trust_path.read_text())
        signer=json.loads((self.candidate/'member-public.json').read_text())['signing_key']
        for revision in [0,2**53-1,2**53,2**63-1]:
            value={**original,'revision':revision}
            self.write(trust_path,value)
            TrustStore(trust_path).require_trusted(signer['key_id'])
            self.assertEqual(self.success({'op':'trust','path':str(trust_path)}),[signer])
        baseline=canonical_bytes(original)
        broken=[baseline.replace(b'"revision":1',b'"revision":9223372036854775808'),
                baseline.replace(b'"revision":1',b'"revision":-1'),
                baseline.replace(b'"revision":1',b'"revision":1.0'),
                baseline.replace(b'"revision":1',b'"revision":1e0'),
                baseline.replace(b'"revision":1',b'"revision":"1"'),
                baseline.replace(b'"revision":1',b'"revision":1,"revi\\u0073ion":1'),
                baseline.replace(b'"revision":1',b'"revision":1,"extra":0'),
                b'\xef\xbb\xbf'+baseline]
        for raw in broken:
            trust_path.write_bytes(raw)
            rejected=self.run_ts({'op':'trust','path':str(trust_path)})['results'][0]
            self.assertFalse(rejected['ok'])
        revoked=copy.deepcopy(original)
        entry=revoked['keys'][signer['key_id']]
        entry.update(state='revoked',revoked_at='2026-08-31T00:00:00Z')
        self.write(trust_path,revoked)
        self.assertEqual(self.success({'op':'trust','path':str(trust_path)}),[])
        rejected=self.run_ts({'op':'configure','options':self.options()})['results'][0]
        self.assertFalse(rejected['ok'])
        self.assertEqual(rejected['error'],'unknown_key')
        self.assertFalse((self.candidate/'network.json').exists())
        self.assertEqual(self.success({'op':'trust','path':str(self.directory/'absent'/'trust.json')}),[])

    def test_fsync_failure_never_reports_success_or_overwrites_existing_data(self) -> None:
        # Directory publication, first private-file data, and its directory
        # barrier each have an independently injected, real syscall boundary.
        for call in [1,2,3,7,11]:
            target=self.directory/f'failed-{call}'
            output=self.run_ts({'op':'create','directory':str(target)},fail_fsync_at=call)
            self.assertFalse(output['results'][0]['ok'])
            self.assertEqual(output['fsyncCalls']>=call,True)
            self.assertFalse(target.exists())
        self.created()
        original=self.snapshot(self.candidate)
        for call in [1,2]:
            output=self.run_ts({'op':'configure','options':self.options()},fail_fsync_at=call)
            self.assertFalse(output['results'][0]['ok'])
            self.assertFalse((self.candidate/'network.json').exists())
            self.assertEqual(self.snapshot(self.candidate),original)
        self.success({'op':'configure','options':self.options()})


if __name__=='__main__':
    unittest.main()
