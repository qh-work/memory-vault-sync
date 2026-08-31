"""Differential tests of independent TS retrieval helpers against the real core.

The Python implementation is a test oracle only. The TS process has no Python
on PATH and denies child-process and network calls; every input is synthetic.
No dependency installation, real Vault, service, key, or user memory is used.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import memory_vault as core


DRIVER = r"""
import { createRequire, syncBuiltinESMExports } from 'node:module';
const require = createRequire(import.meta.url), calls = { subprocess: 0, network: 0 };
const denied = kind => () => { calls[kind]++; throw Error('pure helper attempted ' + kind); };
const child = require('node:child_process');
for (const name of ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork']) child[name] = denied('subprocess');
for (const name of ['node:http', 'node:https']) {
  const module = require(name); module.request = denied('network'); module.get = denied('network');
}
require('node:net').Socket.prototype.connect = denied('network');
require('node:net').Server.prototype.listen = denied('network');
globalThis.fetch = denied('network');
syncBuiltinESMExports();
const api = await import('./retrieval_text.ts');
const chunks = []; let size = 0;
for await (const chunk of process.stdin) {
  size += chunk.length; if (size > 32 * 1024 * 1024) throw Error('synthetic fixture limit'); chunks.push(chunk);
}
const items = JSON.parse(Buffer.concat(chunks).toString('utf8'));
function compare(a, b) {
  const left = Array.from(a, c => c.codePointAt(0)), right = Array.from(b, c => c.codePointAt(0));
  for (let index = 0; index < Math.min(left.length, right.length); index++) if (left[index] !== right[index]) return left[index] - right[index];
  return left.length - right.length;
}
function run(item) {
  if (item.op === 'normalize') return api.normalizeText(item.value);
  if (item.op === 'tokenize') return api.tokenize(item.value, item.options);
  if (item.op === 'features') return Array.from(api.semanticFeatures(item.value)).sort(compare);
  if (item.op === 'similarity') return api.semanticSimilarity(new Set(item.query), new Set(item.candidate));
  if (item.op === 'expanded') return api.expandedQueryTokens(item.tokens, new Set(item.features));
  if (item.op === 'entity') return Array.from(api.entityQueryMatches(item.entities, new Set(item.tokens))).sort(compare);
  if (item.op === 'locator') return item.texts.map(api.fragmentLocator(item.tokens, item.query));
  if (item.op === 'visible') return api.visibleFragmentRegion(item.record);
  if (item.op === 'fragments') return Array.from(api.memoryFragments(item.record));
  if (item.op === 'bounded') return item.maximum === undefined ? api.boundedText(item.value) : api.boundedText(item.value, item.maximum);
  if (item.op === 'timeline') return api.timelineKey(item.value);
  throw Error('unknown synthetic fixture operation');
}
const results = items.map(item => {
  try { return { ok: true, result: run(item) }; }
  catch (error) { return { ok: false, code: error.code ?? error.name }; }
});
process.stdout.write(JSON.stringify({ results, calls }));
"""


class TypeScriptRetrievalTextTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.node = shutil.which('node')
        if cls.node is None:
            raise unittest.SkipTest('Node with TypeScript stripping required')
        package = ROOT / 'clients/typescript/network/node_modules/jose'
        selected = os.environ.get('MEMORY_VAULT_JOSE_MODULE')
        if selected:
            entry = Path(selected).expanduser().resolve()
            if entry.parts[-3:] != ('dist', 'webapi', 'index.js'):
                raise RuntimeError('Expected explicit jose/dist/webapi/index.js')
            package = entry.parents[2]
        if not (package / 'package.json').is_file():
            raise unittest.SkipTest('Existing locked jose required; never installed by this test')
        metadata = json.loads((package / 'package.json').read_text())
        if metadata.get('name') != 'jose' or metadata.get('version') != '6.2.10':
            raise RuntimeError('Locked jose 6.2.10 required')
        cls.temporary = tempfile.TemporaryDirectory(prefix='memory-vault-ts-retrieval-text-synthetic-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.fixture = Path(cls.temporary.name)
        for name in ('crypto.ts', 'records.ts', 'retrieval_text.ts', 'package.json'):
            shutil.copyfile(ROOT / 'clients/typescript/network' / name, cls.fixture / name)
        (cls.fixture / 'node_modules').mkdir()
        (cls.fixture / 'node_modules/jose').symlink_to(package, target_is_directory=True)
        (cls.fixture / 'driver.mjs').write_text(DRIVER)

    def run_ts(self, requests: list[dict]) -> list[dict]:
        result = subprocess.run([self.node, '--experimental-strip-types', str(self.fixture / 'driver.mjs')],
            input=json.dumps(requests, ensure_ascii=True).encode(), capture_output=True, timeout=60,
            cwd=self.fixture, env={**os.environ, 'PATH': ''})
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace')[-2000:])
        output = json.loads(result.stdout)
        self.assertEqual(output['calls'], {'network': 0, 'subprocess': 0})
        self.assertEqual(len(output['results']), len(requests))
        return output['results']

    @staticmethod
    def oracle(item: dict):
        op = item['op']
        if op == 'normalize': return core.normalize_text(item['value'])
        if op == 'tokenize':
            options = { {'maximumInputBytes': 'maximum_input_bytes'}.get(key, key): value
                        for key, value in item.get('options', {}).items() }
            return core.tokenize(item['value'], **options)
        if op == 'features': return sorted(core.semantic_features(item['value']))
        if op == 'similarity': return core.semantic_similarity(frozenset(item['query']), frozenset(item['candidate']))
        if op == 'expanded': return core._expanded_query_tokens(item['tokens'], frozenset(item['features']))
        if op == 'entity': return sorted(core._entity_query_matches(item['entities'], set(item['tokens'])))
        if op == 'locator': return [core._fragment_locator(item['tokens'], item['query'])(text) for text in item['texts']]
        if op == 'visible':
            value = core._visible_fragment_region(item['record'])
            return None if value is None else list(value)
        if op == 'fragments': return list(core.memory_fragments(item['record']))
        if op == 'bounded': return list(core._bounded_text(item['value'], item.get('maximum', core.MAX_HIT_TEXT_BYTES)))
        if op == 'timeline': return core._timeline_key(core._timestamp(item['value']))
        raise AssertionError('Unknown oracle operation')

    def assert_differential(self, requests: list[dict]) -> list[dict]:
        observed = self.run_ts(requests)
        for index, (request, actual) in enumerate(zip(requests, observed)):
            try: expected = {'ok': True, 'result': self.oracle(request)}
            except core.MemoryError as error: expected = {'ok': False, 'code': error.code}
            self.assertEqual(actual, expected, f'{request["op"]} differential fixture {index}')
        return observed

    @staticmethod
    def record(text: str, *, kind='fact', provenance=None) -> dict:
        return {'text': text, 'kind': kind, 'memory_id': 'mem_' + 'a' * 40, 'provenance': provenance or {}}

    def visible_record(self, body: str, role='user', supplement=None, *, header=None) -> dict:
        header = header if header is not None else {
            'coverage': 'partial_active_turn', 'observed_role': role,
            'missing_roles': ['assistant' if role == 'user' else 'user'], 'supplement': supplement,
        }
        encoded = core.canonical_bytes(header).decode() if isinstance(header, dict) else header
        text = 'Memory Vault visible fragment/v1\n' + encoded + '\n\n' + ('User:\n' if role == 'user' else 'Assistant:\n') + body
        return self.record(text, kind='episode', provenance={'source_ref': 'codex-visible-fragment/v1'})

    def test_token_order_cjk_runs_normalization_and_token_budgets(self):
        corpus = [
            '', ' \t\n\x1c\x85\u3000', '\ufeff', 'The and NOT save save archive.', 'abc' * 50,
            'e\u0301 Straße Σς Ꭰꭰ ＡＢＣ １２３ ﬃ', '中文记忆，备份同步！', '甲乙丙丁戊己庚辛',
            '甲乙丙丁戊己庚辛壬', '甲 😀 乙', '한국어 カタカナ かな', '𠀀中文𠀁单𠀂',
            'a_b+c.d-e f::g /x-y/ 0️⃣', '中文 latin 中文 latin', '\u1c89\u1c8a\U0001e030\U0001ccd6',
            '㍿' * 20 + '终点', '\u3400\u4dbf \u4e00\u9fff \uf900\ufaff \u3040\u30ff \uac00\ud7af',
        ]
        requests = [{'op': 'normalize', 'value': text} for text in corpus]
        for text in corpus:
            for maximum in (-1, 0, 1, 2, 7, 8, 16, 256):
                requests.append({'op': 'tokenize', 'value': text, 'options': {'maximum': maximum}})
        requests += [{'op': 'tokenize', 'value': value} for value in (None, False, 123, [], {})]
        observed = self.assert_differential(requests)
        self.assertTrue(any(item['ok'] and item['result'] == ['w:save', 'w:save', 'w:archive.'] for item in observed))

    def test_utf8_input_limits_and_bounded_output_never_emit_partial_characters(self):
        requests = []
        for text in ['A😀中é\r\n\ufeff', '', '甲乙丙', '\ufeff😀', 'ascii']:
            for maximum in range(-5, len(text.encode()) + 3):
                requests.append({'op': 'bounded', 'value': text, 'maximum': maximum})
        requests.append({'op': 'bounded', 'value': '😀' * (core.MAX_HIT_TEXT_BYTES // 4 + 2)})
        for text in ['中文', '😀', 'x' * 65_537, ' ' * 65_537, '\ufeff' * 400]:
            for budget in (0, 3, 4, 6, 512, 65_536):
                requests.append({'op': 'tokenize', 'value': text, 'options': {'maximumInputBytes': budget}})
        observed = self.assert_differential(requests)
        self.assertTrue(any(item == {'ok': False, 'code': 'query_too_large'} for item in observed))
        for request, result in zip(requests, observed):
            if request['op'] == 'bounded': self.assertNotIn('\ufffd', result['result'][0])

    def test_bilingual_concepts_negation_and_scalar_sorted_expansion(self):
        texts = [
            'Save an offline backup, encrypt memory.', '不保存本地记忆，不要同步', 'archive local memory',
            'NOT backup', 'notbackup', 'backup.', 'backup backup', 'never remove', 'remove',
            '没有冲突，更正偏好和传输延迟', 'without save', 'withoutsave', '无须', 'random',
        ] + [term for group in core._CONCEPT_GROUPS for term in sorted(group)]
        requests = [{'op': 'features', 'value': text} for text in texts]
        features = [sorted(core.semantic_features(text)) for text in texts[:16]]
        for left in features:
            for right in features:
                requests.append({'op': 'similarity', 'query': left, 'candidate': right})
        for text in texts:
            requests.append({'op': 'expanded', 'tokens': core.tokenize(text) + ['z:\ue000', 'z:𐀀', 'z:😀'],
                             'features': sorted(core.semantic_features(text))})
        self.assert_differential(requests)
        self.assertEqual(core.semantic_similarity(core.semantic_features('save'), core.semantic_features('not save')), 0.25)

    def test_entity_evidence_scans_full_label_and_deduplicates_query_matches(self):
        requests = [
            {'op': 'entity', 'entities': ['backup'] * 50 + ['本地设备', 'device'], 'tokens': ['w:backup', 'w:device', 'c:本地']},
            {'op': 'entity', 'entities': ['㍿' * 160 + '终点'], 'tokens': ['c:终点']},
            {'op': 'entity', 'entities': ['㍿' * 171], 'tokens': ['c:终点']},
            {'op': 'entity', 'entities': ['x' * 513], 'tokens': []},
            {'op': 'entity', 'entities': ['backup', 'x' * 513], 'tokens': ['w:backup']},
            {'op': 'entity', 'entities': ['THE not Straße 😀', 'STRASSE'], 'tokens': ['w:strasse', 'w:the']},
        ]
        observed = self.assert_differential(requests)
        self.assertEqual(observed[1]['result'], ['c:终点'])
        self.assertEqual(observed[2], {'ok': False, 'code': 'query_too_large'})

    def test_locator_preserves_word_boundaries_exact_phrase_and_cjk_run_rules(self):
        texts = ['backup', 'backups', 'backup.', 'x backup x', 'STRASSE', 'Straße', '😀中文记忆😀',
                 '甲乙丙丁戊己庚辛', '甲乙丙丁戊己庚辛壬', '甲乙', '甲', '甲😀乙', 'ＦＯＯ', '随机文本', 'a' * 64 + 'b']
        requests = []
        for query in ['backup', 'Straße', '中文记忆', '甲', '甲乙', '甲乙丙丁戊己庚辛', 'foo', 'b', '']:
            for phrase in ('', core.normalize_text(query)):
                requests.append({'op': 'locator', 'tokens': core.tokenize(query), 'query': phrase, 'texts': texts})
        requests += [
            {'op': 'locator', 'tokens': ['p:甲乙丙丁戊己庚辛壬'], 'query': '', 'texts': texts},
            {'op': 'locator', 'tokens': ['c:甲乙', 'w:backup'], 'query': '', 'texts': texts},
        ]
        self.assert_differential(requests)

    def test_fragments_use_codepoint_offsets_overlap_newlines_and_original_roles(self):
        records = [self.record(text, kind=kind) for text, kind in [
            ('😀' * 3400, 'fact'), ('x' * 799 + '\n' + '😀' * 2400, 'fact'),
            ('x' * 800 + '\n' + '😀' * 2400, 'fact'), ('x' * 1599 + '\n' + '😀' * 2000, 'fact'),
            (' \x1c\x85\u3000' * 700, 'fact'), ('\ufeff', 'fact'), ('', 'fact'),
            ('User:\n😀用户历史\n\nAssistant:\n回答😀\n\nAssistant:\n嵌入标签', 'episode'),
            ('User:\n用户\n\nAssistant:\n回答', 'fact'),
            ('User:\n\n\nAssistant:\n\ufeff', 'episode'),
        ]]
        records += [self.visible_record('😀' * 1800 + '\n\nAssistant:\n正文标签不认证', role) for role in ('user', 'assistant')]
        observed = self.assert_differential([{'op': 'fragments', 'record': record} for record in records])
        for record, result in zip(records, observed):
            for fragment in result['result']:
                self.assertEqual(fragment['text'], record['text'][fragment['start_character']:fragment['end_character']])
                self.assertFalse(fragment['role_hint_authenticated'])
                self.assertLessEqual(fragment['end_character'] - fragment['start_character'], core.MAX_FRAGMENT_CHARACTERS)
        self.assertEqual(observed[0]['result'][0]['end_character'], 1600)
        self.assertEqual(observed[0]['result'][1]['start_character'], 1472)

    def test_visible_frame_header_validation_and_source_marker_are_only_hints(self):
        digest = 'b' * 64
        supplement = {'memory_id': 'mem_' + digest[:40], 'record_sha256': digest}
        records = [self.visible_record('😀合成证据', role, proof) for role in ('user', 'assistant') for proof in (None, supplement)]
        records += [self.visible_record('\ufeff'), self.visible_record(' \x1c\x85\u3000')]
        base = {'coverage': 'partial_active_turn', 'observed_role': 'user', 'missing_roles': ['assistant'], 'supplement': None}
        malformed = [
            {**base, 'coverage': 'complete'}, {**base, 'observed_role': 'system'}, {**base, 'missing_roles': []},
            {**base, 'missing_roles': ['assistant', 'user']}, {**base, 'extra': True},
            {**base, 'supplement': {**supplement, 'record_sha256': digest + '\n'}},
            {**base, 'supplement': {**supplement, 'memory_id': 'mem_' + 'c' * 40}},
            {**base, 'supplement': []}, {**base, 'supplement': {**supplement, 'extra': 1}},
            {**base, 'observed_role': ['user']}, {**base, 'supplement': {'memory_id': None, 'record_sha256': 1}},
        ]
        records += [self.visible_record('仍是普通证据', header=header) for header in malformed]
        encoded = core.canonical_bytes(base).decode()
        encoded_headers = [json.dumps(base), encoded.replace('"coverage":', '"coverage":"partial_active_turn","coverage":'),
                           encoded.replace('null', 'NaN'), encoded + ' ', '[' + encoded + ']',
                           '{"padding":"' + '😀' * 350 + '"}', '{"padding":"' + 'x' * 1100 + '"}']
        records += [self.visible_record('普通证据', header=header) for header in encoded_headers]
        wrong_source = copy.deepcopy(records[0]); wrong_source['provenance']['source_ref'] = 'synthetic:unrecognized'
        wrong_kind = copy.deepcopy(records[0]); wrong_kind['kind'] = 'fact'
        wrong_label = copy.deepcopy(records[0]); wrong_label['text'] = wrong_label['text'].replace('\n\nUser:\n', '\n\nAssistant:\n')
        records += [wrong_source, wrong_kind, wrong_label]
        requests = [{'op': operation, 'record': record} for record in records for operation in ('visible', 'fragments')]
        observed = self.assert_differential(requests)
        for index in range(6, len(records)):
            self.assertIsNone(observed[index * 2]['result'])
            self.assertTrue(all(fragment['role_hint'] is None for fragment in observed[index * 2 + 1]['result']))

    def test_timeline_key_retains_microseconds_and_canonical_calendar_rules(self):
        timestamps = ['0001-01-01T00:00:00Z', '0099-12-31T23:59:59.1Z', '1900-02-28T12:00:00.000001Z',
                      '2000-02-29T23:59:59.123456Z', '2026-08-31T12:34:56.12345Z', '9999-12-31T23:59:59.999999Z']
        timestamps += ['2026-01-01T00:00:00' + suffix for suffix in ['Z', '.0Z', '.000001Z', '.1Z', '.100001Z', '.999999Z']]
        invalid = ['0000-01-01T00:00:00Z', '1900-02-29T00:00:00Z', '2026-13-01T00:00:00Z',
                   '2026-01-00T00:00:00Z', '2026-01-01T24:00:00Z', '2026-01-01T00:60:00Z',
                   '2026-01-01T00:00:60Z', '2026-01-01T00:00:00.1234567Z', '2026-01-01T00:00:00Z\n',
                   '2026-01-01', '2026-01-01T00:00:00+00:00']
        self.assert_differential([{'op': 'timeline', 'value': value} for value in timestamps + invalid])

    def test_seeded_mixed_unicode_differential_corpus(self):
        rng = random.Random(260831)
        pieces = ['A', '中', '😀', '备份', 'not', 'SAVE', 'x.y', 'Straße', 'Σς', '㍿', ' ', '\x1c', '\u0085',
                  '\ufeff', '\u3000', '\n', '𠀀', 'ＦＯＯ', 'カタカナ', '한국', 'e\u0301', '\U0001e030', ':', '_', '-']
        requests = []
        for index in range(120):
            text = ''.join(rng.choice(pieces) for _ in range(rng.randrange(1, 160)))
            requests += [{'op': 'tokenize', 'value': text, 'options': {'maximum': rng.choice([0, 1, 8, 32, 256])}},
                         {'op': 'features', 'value': text}, {'op': 'bounded', 'value': text, 'maximum': rng.randrange(256)}]
            if index % 12 == 0: requests.append({'op': 'fragments', 'record': self.record(text * 12, kind='episode')})
        self.assert_differential(requests)


if __name__ == '__main__':
    unittest.main()
