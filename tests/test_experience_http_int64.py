"""Dependency-free HTTP SDK parsing of synthetic Agent experience responses.

The fetch boundary returns genuine bounded Web Response streams; no remote
service, credentials, crypto shim or jose dependency is involved. Existing
HTTP integration tests separately exercise actual loopback sockets.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from memory_vault import AUTHORITY, canonical_bytes
from memory_vault_agent import Agent
from memory_vault_client import CONFIG_SCHEMA
from memory_vault_storage import atomic_write

ROOT = Path(__file__).resolve().parents[1]
INT64_MIN, INT64_MAX = -(2**63), 2**63 - 1
SAFE_MAX = 2**53 - 1
DRIVER = r'''
import fs from 'node:fs';
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const {MemoryVaultClient, MemoryVaultTransportError} = await import(input.sdk);
const requests = [];
globalThis.fetch = async (_url, options) => {
  requests.push(options.body);
  return new Response(input.response, {status: input.status ?? 200,
    headers: {'content-type': 'application/json'}});
};
if (input.disableRaw) JSON.rawJSON = undefined;
if (input.disableSource) {
  const original = JSON.parse;
  JSON.parse = (text, reviver) => original(text, typeof reviver !== 'function' ? undefined :
    function(key, value) { return reviver.call(this, key, value); });
}
const client = new MemoryVaultClient({endpoint: 'https://synthetic.invalid',
  bearerToken: 'synthetic-only-token-0000000000000000', trustedEndpoint: true});
const args = input.args ?? {};
if (input.rawRequest) args.experience = {sample: JSON.rawJSON(input.rawRequest)};
if (input.bigintRequest) args.experience = {sample: BigInt(input.bigintRequest)};
try {
  const response = await client[input.operation ?? 'recall'](args);
  const rawPaths = [];
  const walk = (value, path = []) => {
    if (typeof JSON.isRawJSON === 'function' && JSON.isRawJSON(value)) {rawPaths.push(path.join('.')); return;}
    if (value && typeof value === 'object') for (const [key, child] of Object.entries(value)) walk(child, [...path, key]);
  };
  walk(response);
  process.stdout.write(JSON.stringify({ok: true, response, rawPaths, requests}));
} catch (error) {
  process.stdout.write(JSON.stringify({ok: false, typed: error instanceof MemoryVaultTransportError,
    code: error.code, retryable: error.retryable, commit_state: error.commit_state, requests}));
}
'''


class ExperienceHTTPInt64Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.node = os.environ.get('MEMORY_VAULT_NODE') or shutil.which('node')
        if cls.node is None:
            raise unittest.SkipTest('Existing Node >=22.19 required; no dependency installation')
        version = subprocess.check_output([cls.node, '--version'], text=True).strip()
        major, minor, *_ = map(int, version.lstrip('v').split('.'))
        if major < 22 or (major == 22 and minor < 19):
            raise unittest.SkipTest('Existing Node >=22.19 required; no dependency installation')
        cls.temporary = tempfile.TemporaryDirectory(prefix='experience-http-int64-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name).resolve()
        cls.driver = cls.directory / 'driver.mjs'
        cls.driver.write_text(DRIVER)

    @staticmethod
    def response(experience):
        return {'schema_version': 'universal-agent-memory-result/v1', 'ok': True,
                'authority': AUTHORITY, 'result': {'hits': [{'memory_id': 'mem_' + '1' * 40,
                'text': 'Synthetic HTTP evidence', 'experience': experience}],
                'next_cursor': None, 'partial': False, 'query_candidate_limit': 32,
                'network_accessed': False}}

    def sdk(self, response, **options):
        process = subprocess.run([self.node, '--experimental-strip-types', str(self.driver)],
            input=json.dumps({'sdk': (ROOT / 'clients/typescript/index.ts').as_uri(),
                              'response': response if isinstance(response, str) else json.dumps(response),
                              'args': {'query': 'synthetic', 'include_experience': True}, **options}).encode(),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=self.directory,
            timeout=20, env={**os.environ, 'PATH': ''})
        self.assertEqual(process.returncode, 0, process.stderr.decode(errors='replace'))
        return json.loads(process.stdout)

    def test_int64_bounds_remain_exact_in_known_and_unknown_experience_fields(self):
        metadata = {'epistemic_type': 'experiment', 'observed_under': {'min': INT64_MIN, 'max': INT64_MAX},
                    'future': {'nested': [SAFE_MAX + 1, -(SAFE_MAX + 1), INT64_MAX]},
                    'relations': [{'type': 'contradicts', 'target': 'mem_' + '2' * 40}]}
        result = self.sdk(self.response(metadata))
        self.assertTrue(result['ok'], result)
        self.assertEqual(result['response'], self.response(metadata))
        self.assertEqual(len(result['rawPaths']), 5)

    def test_safe_integers_remain_plain_numbers(self):
        metadata = {'epistemic_type': 'experiment', 'observed_under': {'integers': [-SAFE_MAX, -1, 0, 1, SAFE_MAX]}}
        response = self.response(metadata)
        response['result']['query_candidate_limit'] = 32
        result = self.sdk(response)
        self.assertTrue(result['ok'], result)
        self.assertEqual(result['response'], response)
        self.assertEqual(result['rawPaths'], [])

    def test_unsafe_numbers_outside_successful_recall_experience_are_rejected(self):
        cases = []
        for target in ('authority', 'hit', 'verification', 'retrieval', 'result'):
            response = self.response({'epistemic_type': 'experiment'})
            destinations = {'authority': response['authority'].copy(), 'hit': response['result']['hits'][0],
                            'verification': {}, 'retrieval': {}, 'result': response['result']}
            destinations[target]['unsafe'] = INT64_MAX
            if target == 'authority': response['authority'] = destinations[target]
            if target == 'verification': response['result']['hits'][0]['verification'] = destinations[target]
            if target == 'retrieval': response['result']['retrieval'] = destinations[target]
            cases.append((target, response, {}))
        cases.append(('experience_not_object', self.response(INT64_MAX), {}))
        cases.append(('other_operation', self.response({'value': INT64_MAX}), {'operation': 'discover', 'args': {}}))
        cases.append(('error_response', {'schema_version': 'universal-agent-memory-result/v1', 'ok': False,
            'authority': AUTHORITY, 'error': {'code': 'synthetic', 'retryable': False,
            'experience': {'unsafe': INT64_MAX}}}, {'status': 400}))
        for name, response, options in cases:
            with self.subTest(name=name):
                result = self.sdk(response, **options)
                self.assertFalse(result['ok'], result)
                self.assertTrue(result['typed'])
                self.assertEqual(result['code'], 'invalid_endpoint_response_integer')
                self.assertFalse(result['retryable'])

    def test_out_of_range_or_noninteger_experience_numbers_are_rejected(self):
        for token in (str(INT64_MIN - 1), str(INT64_MAX + 1), '1.25', '1e30', '9' * 700):
            with self.subTest(token=token):
                response = json.dumps(self.response({'value': 'TOKEN'})).replace('"TOKEN"', token)
                result = self.sdk(response)
                self.assertFalse(result['ok'], result)
                self.assertEqual(result['code'], 'invalid_endpoint_response_integer')

    def test_unsupported_lossless_runtime_is_typed_failure(self):
        for setting in ('disableRaw', 'disableSource'):
            with self.subTest(setting=setting):
                result = self.sdk(self.response({'value': INT64_MAX}), **{setting: True})
                self.assertFalse(result['ok'], result)
                self.assertTrue(result['typed'])
                self.assertEqual(result['code'], 'experience_lossless_json_unavailable')
                self.assertFalse(result['retryable'])

    def test_actual_python_agent_recall_handoff_and_exact_id_remain_lossless(self):
        with tempfile.TemporaryDirectory(prefix='experience-http-agent-') as temporary:
            root = Path(temporary).resolve()
            config = root / 'client.json'
            atomic_write(config, canonical_bytes({'schema_version': CONFIG_SCHEMA,
                'vault_path': str(root / 'vault.sqlite3'), 'capture_visible_turns': False}), replace=False)
            agent = Agent(config)
            saved = agent.handle({'op': 'remember', 'request_id': 'req_http_int64_synthetic',
                'kind': 'observation', 'text': 'Synthetic HTTP int64 experiment ' + '证据😀' * 300,
                'experience': {'epistemic_type': 'experiment', 'observed_under': {'min': INT64_MIN, 'max': INT64_MAX},
                               'future': {'sample': SAFE_MAX + 1}}})
            self.assertTrue(saved['ok'], saved)
            mid = saved['result']['memory_id']
            for selector in ({'query': 'Synthetic HTTP int64'}, {'query': 'Synthetic HTTP int64', 'handoff': True}, {'memory_id': mid}):
                with self.subTest(selector=selector):
                    request = {'op': 'recall', **selector, 'include_experience': True}
                    pages = 0
                    while True:
                        response = agent.handle(request)
                        self.assertTrue(response['ok'], response)
                        result = self.sdk(canonical_bytes(response).decode(), args={k: v for k, v in request.items() if k != 'op'})
                        self.assertTrue(result['ok'], result)
                        self.assertEqual(result['response'], response)
                        pages += 1
                        cursor = response['result']['next_cursor']
                        if cursor is None:
                            break
                        self.assertLess(pages, 12)
                        request = {'op': 'recall', 'cursor': cursor}
                    self.assertGreater(pages, 1)

    def test_deep_response_is_bounded_before_path_traversal_can_expand(self):
        nested = {'value': INT64_MAX}
        for _ in range(40):
            nested = {'nested': nested}
        result = self.sdk(self.response(nested))
        self.assertFalse(result['ok'], result)
        self.assertTrue(result['typed'])
        self.assertEqual(result['code'], 'invalid_endpoint_response')

    def test_native_rawjson_request_preserves_literal_without_accepting_bigint(self):
        response = {'schema_version': 'universal-agent-memory-result/v1', 'ok': True,
                    'authority': AUTHORITY, 'result': {'state': 'accepted_local'}}
        args = {'request_id': 'req_http_int64_request', 'kind': 'observation', 'text': 'Synthetic requested metadata'}
        result = self.sdk(response, operation='remember', args=args, rawRequest=str(INT64_MAX))
        self.assertTrue(result['ok'], result)
        self.assertEqual(json.loads(result['requests'][0])['experience']['sample'], INT64_MAX)
        failed = self.sdk(response, operation='remember', args=args, bigintRequest=str(INT64_MAX))
        self.assertFalse(failed['ok'], failed)
        self.assertEqual(failed['code'], 'invalid_request_json')
        self.assertEqual(failed['requests'], [])


if __name__ == '__main__':
    unittest.main()
