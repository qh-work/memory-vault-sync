"""Native provider clients against owned Python HTTP nodes and real JOSE.

Synthetic keys, opaque references and isolated transport databases only. These
checks establish cross-runtime publication/discovery, not ciphertext custody,
independent fault domains or permission to read a Vault.
"""
import asyncio
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import time
import unittest

from memory_vault import canonical_bytes
from memory_vault_network_crypto import EncryptionIdentity, document_sha256
from memory_vault_open_control import verify_response as verify_routing_response
from memory_vault_open_node import OpenParticipant
from memory_vault_open_provider import (
    PROFILE, as_dual, verify_document, verify_index_lease,
    verify_response as verify_provider_response,
)
from memory_vault_open_provider_client import OpenProviderClient
from memory_vault_storage import atomic_write
from memory_vault_trust import Identity
from tests.test_open_node import HTTPNodes
from tests.test_open_typescript_http import GUARD
from tests import test_network_typescript_agent_network as ts_runtime


DRIVER = GUARD + r"""
const {OpenParticipant}=await import('./open-participant.ts');
const {OpenProviderClient}=await import('./open-provider-client.ts');
const {OpenHTTPTransport}=await import('./open-transport.ts');
const {issueFact}=await import('./open-provider.ts');
const chunks=[];let size=0;
for await(const chunk of process.stdin){size+=chunk.length;if(size>1048576)throw Error('synthetic input limit');chunks.push(chunk);}
const input=JSON.parse(Buffer.concat(chunks).toString('utf8')),results=[],calls=[];
const original=OpenHTTPTransport.prototype.request;
OpenHTTPTransport.prototype.request=async function(base,value,deadline){
  const call={base,request:value,response:null,observed_address:null};calls.push(call);
  const reply=await original.call(this,base,value,deadline);
  call.response=reply.response;call.observed_address=reply.observed_address;return reply;
};
const participant=new OpenParticipant(input.identity,input.state,{
  seeds:input.seeds,allow_loopback:true,...(input.descriptor?{descriptor:input.descriptor}:{})});
try{
  const client=new OpenProviderClient(participant,input.encryption);
  for(const operation of input.operations){try{
    const value=operation.op==='fact'?issueFact(input.identity,operation.options):
      operation.op==='authorize'?await client.authorizePublication(operation.ref,operation.root_key,operation.publisher,operation.allocation_id,operation.options):
      operation.op==='publish'?await client.publish(operation.ref,operation.root_key,operation.fact,operation.allocation_id,operation.options):
      operation.op==='find'?await client.find(operation.ref,operation.options):
      operation.op==='prove'?await client.proveTarget(operation.node):
      await client.call(operation.node,operation.action,operation.body);
    results.push({ok:true,value});
  }catch(error){results.push({ok:false,code:error.code??'untyped_error',retryable:error.retryable??false});}}
}finally{participant.close();}
process.stdout.write(JSON.stringify({results,calls,subprocessCalls}));
"""


class ProviderTypeScriptHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ts_runtime.TypeScriptAgentNetworkTests.setUpClass.__func__(cls)
        (cls.fixture / 'driver.mjs').write_text(DRIVER)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='memory-provider-mixed-synthetic-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    def host(self, count=1):
        host = HTTPNodes(self.root, count)
        self.addCleanup(host.close)
        host.encryptions = []
        for index in range(count):
            host.stop(index)
            encryption = EncryptionIdentity.generate()
            path = self.root / ('node_' + str(index)) / 'encryption.json'
            encryption.save(path)
            host.encryptions.append(encryption)
            config = json.loads(host.configs[index].read_bytes())
            config.update(provider_policy={'enabled': True}, encryption_key_path=str(path))
            atomic_write(host.configs[index], canonical_bytes(config), replace=True)
            host.start(index)
        return host

    def identity(self, name):
        identity = Identity.generate(self.root / name / 'identity.json')
        encryption = EncryptionIdentity.generate()
        encryption.save(self.root / name / 'encryption.json')
        return identity, encryption

    def python(self, name, identity, encryption, nodes):
        participant = OpenParticipant(identity, self.root / name / 'transport', seeds=nodes, allow_loopback=True)
        self.addCleanup(participant.close)
        return OpenProviderClient(participant, encryption)

    def native(self, name, nodes, operations, *, descriptor=None, state_name=None, encryption_name=None):
        result = subprocess.run([self.node, '--experimental-strip-types', str(self.fixture / 'driver.mjs')],
            input=json.dumps({'identity': json.loads((self.root / name / 'identity.json').read_bytes()),
                'encryption': json.loads((self.root / (encryption_name or name) / 'encryption.json').read_bytes()),
                'state': str(self.root / (state_name or (name + '_native')) / 'transport'),
                'seeds': nodes, 'descriptor': descriptor, 'operations': operations}).encode(),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=self.fixture, timeout=40)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace')[-6000:])
        payload = json.loads(result.stdout)
        self.assertEqual(payload['subprocessCalls'], 0)
        return payload

    def value(self, result, index=0):
        row = result['results'][index]
        self.assertTrue(row['ok'], row)
        return row['value']

    def root_key(self, identity, encryption, label):
        return {'owner': {'signing_key_id': identity.key_id, 'encryption_key_id': encryption.key_id},
            'root_kind': 'mailbox', 'anchor_ref': self.ref('anchor', label),
            'owner_epoch': 'synthetic_owner_epoch', 'root_id': 'synthetic_' + label}

    @staticmethod
    def ref(namespace, label):
        return {'namespace': namespace, 'key': hashlib.sha256(('synthetic opaque ' + label).encode()).hexdigest()}

    def fact(self, host, index, ref, custody='synthetic_custody'):
        now = int(time.time())
        result = self.native('node_' + str(index), host.nodes, [{'op': 'fact', 'options': {
            'ref': ref, 'storage_epoch': host.nodes[index]['payload']['storage_epoch'],
            'custody_id': custody, 'revision': 1, 'issued_at': now, 'expires_at': now + 300}}],
            descriptor=host.nodes[index])
        fact = self.value(result)
        self.assertFalse(result['calls'], 'Signing a provider observation must not use the network')
        self.assertEqual(verify_document(fact, 'provider.fact')['signing_key'], host.identities[index].public_descriptor())
        return fact

    @staticmethod
    def actions(result):
        return [call['request']['payload']['action'] for call in result['calls']
                if call['request']['payload']['schema_version'] == PROFILE]

    def assert_trace(self, result, nodes):
        known = {node['payload']['signing_key']['key_id']: node for node in nodes}
        proven = set()
        for call in result['calls']:
            request = call['request']
            raw = request['payload']
            node = known[raw['node_key_id']]
            self.assertIsNotNone(call['response'])
            self.assertEqual(call['observed_address'], '127.0.0.1')
            provider = raw['schema_version'] == PROFILE
            checked = (verify_provider_response if provider else verify_routing_response)(call['response'], request=request, node=node)
            if provider:
                binding = (raw['node_key_id'], raw['storage_epoch'])
                if raw['action'] == 'target.answer':
                    self.assertIn('answer', checked['body'])
                    proven.add(binding)
                if raw['action'] in {'resource.allocate', 'resource.revoke', 'provider.put', 'provider.status', 'provider.result'}:
                    self.assertIn(binding, proven, 'Private authority disclosed before real target-key challenge')
            for candidate in checked['body'].get('nodes', []):
                known[candidate['payload']['signing_key']['key_id']] = candidate

    def row_counts(self, host):
        counts = []
        for index in range(len(host.nodes)):
            path = self.root / ('node_' + str(index)) / 'transport' / 'network.sqlite3'
            with sqlite3.connect(path.as_uri() + '?mode=ro', uri=True) as db:
                counts.append((db.execute('SELECT count(*) FROM open_provider_resources').fetchone()[0],
                    db.execute('SELECT count(*) FROM open_provider_facts').fetchone()[0]))
        return counts

    def test_native_owner_publication_python_read_and_native_restart_result(self):
        host = self.host()
        owner, encryption = host.identities[0], host.encryptions[0]
        root = self.root_key(owner, encryption, 'native_owner')
        ref = self.ref('feed', 'owner_feed')
        fact = self.fact(host, 0, ref)
        publish = {'op': 'publish', 'ref': ref, 'root_key': root, 'fact': fact,
            'allocation_id': 'synthetic_native_owner_publication', 'options': {'directory_count': 1}}
        first = self.native('node_0', host.nodes, [publish], descriptor=host.nodes[0])
        published = self.value(first)
        self.assertEqual(published['state'], 'published', published)
        self.assertFalse(published['partial'])
        self.assertEqual(len(published['publications']), 1)
        original = published['publications'][0]['index_lease']
        verify_index_lease(original, fact=fact, node=host.nodes[0])
        self.assert_trace(first, host.nodes)
        self.assertIn('resource.allocate', self.actions(first))
        self.assertIn('provider.put', self.actions(first))
        self.assertEqual(self.row_counts(host), [(1, 1)])

        reader, reader_encryption = self.identity('python_reader')
        client = self.python('python_reader', reader, reader_encryption, host.nodes)
        found = asyncio.run(client.find(ref, maximum_directories=1))
        self.assertEqual(found['state'], 'observed', found)
        self.assertEqual(len(found['candidates']), 1)
        self.assertEqual(canonical_bytes(found['candidates'][0]['facts'][0]['fact']), canonical_bytes(fact))
        self.assertEqual(found['candidates'][0]['target']['payload']['targetEncryptionKey'], encryption.public_descriptor())

        host.stop(0)
        host.start(0)
        again = self.native('node_0', host.nodes, [publish, {'op': 'find', 'ref': ref,
            'options': {'maximum_directories': 1}}], descriptor=host.nodes[0])
        recovered, native_found = self.value(again), self.value(again, 1)
        self.assertEqual(recovered['state'], 'published', recovered)
        self.assertEqual(canonical_bytes(recovered['publications'][0]['index_lease']), canonical_bytes(original))
        self.assertIn('provider.result', self.actions(again))
        self.assertNotIn('provider.put', self.actions(again))
        self.assertNotIn('resource.allocate', self.actions(again))
        self.assertEqual(native_found['state'], 'observed', native_found)
        self.assertEqual(native_found['candidates'][0]['facts'][0]['fact'], fact)
        self.assertEqual(self.row_counts(host), [(1, 1)])
        self.assert_trace(again, host.nodes)

    def test_python_owner_exact_third_party_authorization_and_native_refusals(self):
        host = self.host(2)
        owner, owner_encryption = self.identity('independent_owner')
        owner_client = self.python('independent_owner', owner, owner_encryption, host.nodes)
        root = self.root_key(owner, owner_encryption, 'third_party')
        ref = self.ref('feed', 'authorized_feed')
        prepared = asyncio.run(owner_client.authorize_publication(ref, root,
            as_dual({'signing_key': host.identities[0].public_descriptor(),
                     'encryption_key': host.encryptions[0].public_descriptor()}),
            'synthetic_owner_authorization', directory_count=1))
        self.assertEqual(prepared['state'], 'authorized', prepared)
        self.assertEqual(len(prepared['authorizations']), 1)
        options = {'directory_count': 1, 'authorizations': prepared['authorizations']}
        fact = self.fact(host, 0, ref)
        publish = {'op': 'publish', 'ref': ref, 'root_key': root, 'fact': fact,
            'allocation_id': 'synthetic_third_party_publication', 'options': options}

        # A third-party provider cannot create the absent owner's signature.
        absent = self.native('node_0', host.nodes,
            [{**publish, 'options': {'directory_count': 1}}], descriptor=host.nodes[0])
        self.assertEqual(absent['results'][0]['code'], 'provider_wrong_owner')
        self.assertFalse(absent['calls'])

        accepted = self.native('node_0', host.nodes, [publish], descriptor=host.nodes[0])
        self.assertEqual(self.value(accepted)['state'], 'published', accepted)
        self.assert_trace(accepted, host.nodes)
        self.assertIn('provider.put', self.actions(accepted))
        self.assertNotIn('resource.allocate', self.actions(accepted))
        before = self.row_counts(host)

        # Valid signatures alone do not authorize a different opaque reference.
        other_ref = self.ref('feed', 'not_authorized_feed')
        changed_ref = self.native('node_0', host.nodes, [{**publish, 'ref': other_ref,
            'fact': self.fact(host, 0, other_ref), 'allocation_id': 'synthetic_wrong_ref'}], descriptor=host.nodes[0])
        # Nor can another genuine node reuse the approved publisher's grant.
        changed_publisher = self.native('node_1', host.nodes, [{**publish,
            'fact': self.fact(host, 1, ref), 'allocation_id': 'synthetic_wrong_publisher'}], descriptor=host.nodes[1])
        # Matching the signing key is insufficient when the encryption key differs.
        self.identity('different_encryption')
        changed_encryption = self.native('node_0', host.nodes, [{**publish,
            'allocation_id': 'synthetic_wrong_encryption'}], descriptor=host.nodes[0],
            state_name='same_signer_different_encryption', encryption_name='different_encryption')
        for refused in (changed_ref, changed_publisher, changed_encryption):
            value = self.value(refused)
            self.assertEqual(value['state'], 'pending', value)
            self.assertEqual(value['publications'], [])
            self.assertEqual([error['code'] for error in value['errors']], ['provider_publication_not_authorized'])
            self.assertNotIn('provider.put', self.actions(refused))
            self.assertNotIn('resource.allocate', self.actions(refused))
            self.assert_trace(refused, host.nodes)
        self.assertEqual(self.row_counts(host), before)

        found = asyncio.run(owner_client.find(ref, maximum_directories=2))
        self.assertEqual(found['state'], 'observed', found)
        observations = [record['fact'] for candidate in found['candidates'] for record in candidate['facts']]
        self.assertTrue(observations)
        self.assertEqual({document_sha256(record) for record in observations}, {document_sha256(fact)})
        missing = asyncio.run(owner_client.find(other_ref, maximum_directories=2))
        self.assertEqual(missing['state'], 'not_observed', missing)

    def test_native_private_rpc_requires_live_target_proof_each_process(self):
        host = self.host()
        self.identity('private_caller')
        request = {'op': 'call', 'node': host.nodes[0], 'action': 'resource.allocate', 'body': {}}
        denied = self.native('private_caller', host.nodes, [request])
        self.assertEqual(denied['results'][0]['code'], 'provider_target_proof_required')
        self.assertFalse(denied['calls'])
        proof = self.native('private_caller', host.nodes, [{'op': 'prove', 'node': host.nodes[0]}])
        target = self.value(proof)
        self.assertEqual(verify_document(target, 'provider.target')['targetEncryptionKey'], host.encryptions[0].public_descriptor())
        self.assertEqual(self.actions(proof), ['target.get', 'target.answer'])
        self.assert_trace(proof, host.nodes)
        restarted = self.native('private_caller', host.nodes, [request])
        self.assertEqual(restarted['results'][0]['code'], 'provider_target_proof_required')
        self.assertFalse(restarted['calls'])
        self.assertEqual(self.row_counts(host), [(0, 0)])


if __name__ == '__main__':
    unittest.main()
