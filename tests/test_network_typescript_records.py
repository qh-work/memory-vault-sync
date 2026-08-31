"""Independent TypeScript <-> Python canonical record and share interop.

Only synthetic keys/records and disposable private files are used. No package
installation, real user memory, running Python bridge, or external service.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unicodedata
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import memory_vault as core
import memory_vault_sharing as sharing
import memory_vault_storage as storage
from memory_vault_client import CONFIG_SCHEMA, ClientConfig
from memory_vault_network_crypto import PublicKeyTrust
from memory_vault_trust import Identity


DRIVER = r"""
import * as records from './records.ts';
import { canonicalBytes, NetworkCryptoError } from './crypto.ts';
const chunks = []; let size = 0;
for await (const chunk of process.stdin) {
  size += chunk.length; if (size > 32 * 1024 * 1024) throw Error('synthetic fixture limit'); chunks.push(chunk);
}
const requests = JSON.parse(Buffer.concat(chunks).toString('utf8'));
function value(item) { return item.raw === undefined ? item.value : Buffer.from(item.raw, 'base64'); }
function run(item) {
  if (item.op === 'build') {
    const record = records.buildRecord(item.input);
    return { record, bytes: Buffer.from(records.canonicalRecordBytes(record)).toString('base64') };
  }
  if (item.op === 'validate') return records.validateRecord(value(item));
  if (item.op === 'canonical') return Buffer.from(records.canonicalRecordBytes(value(item))).toString('base64');
  if (item.op === 'sign') return records.signRecord(item.record, item.identity);
  if (item.op === 'verify') return records.verifyRecord(item.record, item.proof, item.trusted);
  if (item.op === 'parse') return records.parseShare(Buffer.from(item.raw, 'base64'));
  if (item.op === 'encode') {
    const encoded = records.encodeShare(item.records, item.roots);
    return { raw: Buffer.from(encoded).toString('base64'), parsed: records.parseShare(encoded) };
  }
  if (item.op === 'normalize') return item.values.map(value => records.normalizeText(value));
  if (item.op === 'unsafe-number') {
    const record = { ...item.record, provenance: { agent_ref: 9223372036854775807n } };
    return records.canonicalRecordBytes(record);
  }
  if (item.op === 'unsafe-object') {
    let called = false;
    const input = { kind: 'fact', created_at: '2026-01-01T00:00:00Z' };
    Object.defineProperty(input, 'text', { enumerable: true, get() { called = true; return 'not read'; } });
    try { records.buildRecord(input); } catch (error) { return { called, code: error.code }; }
    throw Error('getter was accepted');
  }
  if (item.op === 'shared-buffer') {
    const buffer = new SharedArrayBuffer(1); return records.parseShare(new Uint8Array(buffer));
  }
  throw Error('unknown fixture operation');
}
const results = [];
for (const item of requests) {
  try { results.push({ ok: true, result: run(item) }); }
  catch (error) { results.push({ ok: false, error: error instanceof records.NetworkRecordsError || error instanceof NetworkCryptoError ? error.code : 'unexpected_error' }); }
}
process.stdout.write(JSON.stringify(results));
"""


class TypeScriptRecordTests(unittest.TestCase):
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
            raise unittest.SkipTest('Existing locked jose required; this test never installs dependencies')
        metadata = json.loads((package / 'package.json').read_text())
        if metadata.get('name') != 'jose' or metadata.get('version') != '6.2.10':
            raise RuntimeError('Test requires locked jose 6.2.10')
        cls.temporary = tempfile.TemporaryDirectory(prefix='memory-vault-ts-records-synthetic-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.fixture = Path(cls.temporary.name)
        for name in ('crypto.ts', 'records.ts', 'package.json'):
            shutil.copyfile(ROOT / 'clients/typescript/network' / name, cls.fixture / name)
        (cls.fixture / 'node_modules').mkdir()
        (cls.fixture / 'node_modules/jose').symlink_to(package, target_is_directory=True)
        (cls.fixture / 'driver.mjs').write_text(DRIVER)

    def setUp(self) -> None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        self.identity = Identity(Ed25519PrivateKey.generate())
        self.other = Identity(Ed25519PrivateKey.generate())
        self.trust = PublicKeyTrust([self.identity.public_descriptor()])
        self.dependency = core.build_record(kind='fact', text='Synthetic shared historical evidence.',
                                            entities=['evidence'], created_at='2025-01-01T00:00:00.000001Z')
        self.root = core.build_record(kind='decision', text='Synthetic memory: Straße Σς Ꭰꭰ 中文 e\u0301 😀.',
                                     entities=['claim:v021:storage-choice', 'shared entity'],
                                     relations=[{'type': 'derived_from', 'target': self.dependency['memory_id']}],
                                     provenance={'agent_ref': 'synthetic:author', 'task_ref': 'synthetic:provenance-only',
                                                 'source_type': 'agent_supplied', 'confidence': 'observed'},
                                     created_at='2026-01-01T00:00:00.123456Z')
        self.records = [self.root, self.dependency]
        self.proofs = {item['memory_id']: self.identity.sign_record(item) for item in self.records}

    @staticmethod
    def secret(identity: Identity) -> dict:
        from cryptography.hazmat.primitives import serialization
        raw = identity._private_key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                                 serialization.NoEncryption())
        return {**identity.public_descriptor(), 'schema_version': 'universal-memory-identity/v1',
                'private_key': base64.b64encode(raw).decode('ascii')}

    def run_ts(self, *requests: dict) -> list[dict]:
        result = subprocess.run([self.node, '--experimental-strip-types', str(self.fixture / 'driver.mjs')],
                                input=json.dumps(requests, ensure_ascii=True).encode(), capture_output=True,
                                timeout=60, cwd=self.fixture)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace')[-2000:])
        output = json.loads(result.stdout)
        self.assertEqual(len(output), len(requests))
        return output

    def success(self, request: dict):
        result, = self.run_ts(request)
        self.assertTrue(result['ok'], result.get('error'))
        return result['result']

    def rejected(self, requests: list[dict]) -> list[dict]:
        results = self.run_ts(*requests)
        for index, result in enumerate(results):
            self.assertFalse(result['ok'], f'fixture {index} unexpectedly accepted')
            self.assertNotEqual(result['error'], 'unexpected_error', f'fixture {index} escaped controlled failure')
        return results

    @staticmethod
    def wire(raw: bytes) -> str:
        return base64.b64encode(raw).decode('ascii')

    def packet(self, records: list[dict] | None = None, *, roots: list[str] | None = None,
               selector: dict | None = None, proofs: dict | None = None) -> bytes:
        values = self.records if records is None else records
        roots = [self.root['memory_id']] if roots is None else roots
        selected = sharing.parse_selector(selector or {'schema_version': sharing.SELECTOR_SCHEMA, 'memory_ids': roots})
        header = {'type': 'header', 'schema_version': sharing.SHARE_SCHEMA, 'hash_profile': core.HASH_PROFILE,
                  'created_at': '2026-01-01T00:00:00Z', 'selector': selected,
                  'selector_sha256': core.sha256(core.canonical_bytes(selected))}
        proof_map = self.proofs if proofs is None else proofs
        frames = [core.canonical_bytes({'type': 'record', 'record': record,
                                       'attestation': proof_map.get(record['memory_id']),
                                       'selected': record['memory_id'] in roots}) + b'\n' for record in values]
        footer = {'type': 'footer', 'records': len(values),
                  'selected_records': sum(item['memory_id'] in roots for item in values),
                  'records_sha256': hashlib.sha256(b''.join(item['record_sha256'].encode() + b'\n' for item in values)).hexdigest(),
                  'lines_sha256': hashlib.sha256(b''.join(frames)).hexdigest()}
        return core.canonical_bytes(header) + b'\n' + b''.join(frames) + core.canonical_bytes(footer) + b'\n'

    def scan_python(self, raw: bytes) -> dict:
        with tempfile.TemporaryDirectory(prefix='memory-vault-record-share-synthetic-') as temporary:
            path = Path(temporary).resolve() / 'share.ndjson'
            storage.atomic_write(path, raw, replace=False)
            result = sharing._scan(path, time.monotonic() + 30).as_dict()
            result.pop('path')
            return result

    def test_original_bytes_ids_and_domain_separated_signatures_both_directions(self) -> None:
        inputs = [{'kind': record['kind'], 'text': record['text'], 'entities': record['entities'] * 2,
                   'relations': record['relations'] * 2, 'provenance': record['provenance'],
                   'created_at': record['created_at']} for record in self.records]
        built = self.run_ts(*[{'op': 'build', 'input': item} for item in inputs])
        for original, item in zip(self.records, built):
            self.assertTrue(item['ok'], item)
            generated = item['result']['record']
            self.assertEqual(core.validate_record(generated), original)
            self.assertEqual(base64.b64decode(item['result']['bytes']), core.canonical_bytes(original))
        outputs = self.run_ts(*[{'op': 'sign', 'record': item, 'identity': self.secret(self.identity)} for item in self.records],
                              *[{'op': 'verify', 'record': item, 'proof': self.proofs[item['memory_id']],
                                 'trusted': [self.identity.public_descriptor()]} for item in self.records])
        for original, item in zip(self.records, outputs[:2]):
            self.assertTrue(item['ok'], item)
            self.assertEqual(item['result'], self.proofs[original['memory_id']])  # Deterministic Ed25519, identical domain/bytes.
            self.assertEqual(self.trust.verify_record(original, item['result']), self.identity.key_id)
        for item in outputs[2:]:
            self.assertEqual(item, {'ok': True, 'result': self.identity.key_id})

    def test_signature_cannot_change_content_key_identity_or_domain(self) -> None:
        proof = self.proofs[self.root['memory_id']]
        tampered = {**self.root, 'text': self.root['text'] + '!'}
        alternate = core.build_record(kind='decision', text='Synthetic substituted content.', created_at=self.root['created_at'])
        bad_signature = {**proof, 'signature': base64.b64encode(b'\0' * 64).decode()}
        fake_pair = {**self.secret(self.identity), 'private_key': self.secret(self.other)['private_key']}
        message = self.identity.sign_message({'schema_version': proof['schema_version'], 'key_id': proof['key_id'],
                                              'record_sha256': proof['record_sha256']})
        wrong_domain = {**proof, 'signature': message['signature']}
        variations = [(tampered, proof, [self.identity.public_descriptor()]),
                      (alternate, proof, [self.identity.public_descriptor()]),
                      (self.root, proof, []), (self.root, proof, [self.other.public_descriptor()]),
                      (self.root, bad_signature, [self.identity.public_descriptor()]),
                      (self.root, wrong_domain, [self.identity.public_descriptor()]),
                      (self.root, None, [self.identity.public_descriptor()]),
                      (self.root, {**proof, 'authority': 'trusted'}, [self.identity.public_descriptor()]),
                      (self.root, {**proof, 'signature': proof['signature'].rstrip('=')}, [self.identity.public_descriptor()])]
        self.rejected([{'op': 'verify', 'record': record, 'proof': attestation, 'trusted': trusted}
                       for record, attestation, trusted in variations] +
                      [{'op': 'sign', 'record': self.root, 'identity': fake_pair}])

    def test_record_validation_does_not_bind_ignored_noncanonical_data(self) -> None:
        duplicate = {**self.root, 'entities': self.root['entities'] * 2, 'relations': self.root['relations'] * 2}
        self.assertEqual(core.validate_record(duplicate), self.root)
        self.assertEqual(self.success({'op': 'validate', 'value': duplicate}), self.root)
        with self.assertRaises(Exception):
            self.trust.verify_record(duplicate, self.proofs[self.root['memory_id']])
        raw = core.canonical_bytes(self.root)
        duplicate_key = raw.replace(b'"kind":"decision"', b'"kind":"decision","ki\\u006ed":"decision"')
        invalid = [duplicate_key, b'\xef\xbb\xbf' + raw, raw.replace(b'Synthetic memory', b'\xffmemory')]
        self.rejected([{'op': 'canonical', 'value': duplicate},
                       {'op': 'verify', 'record': duplicate, 'proof': self.proofs[self.root['memory_id']],
                        'trusted': [self.identity.public_descriptor()]},
                       {'op': 'unsafe-number', 'record': self.root}] +
                      [{'op': 'validate', 'raw': self.wire(value)} for value in invalid])
        getter = self.success({'op': 'unsafe-object'})
        self.assertFalse(getter['called'])

    def test_field_and_timestamp_boundaries_match_core_valid_records(self) -> None:
        valid_times = ['0001-01-01T00:00:00Z', '2000-02-29T23:59:59.000001Z', '9999-12-31T23:59:59.999999Z']
        for timestamp in valid_times:
            expected = core.build_record(kind='fact', text='\ufeff', created_at=timestamp)
            actual = self.success({'op': 'build', 'input': {'kind': 'fact', 'text': '\ufeff', 'created_at': timestamp}})
            self.assertEqual(actual['record'], expected)
        invalid = [{'kind': 'fact', 'text': '\x1c'}, {'kind': 'fact', 'text': 'a\0b'},
                   {'kind': 'fact', 'text': '\ud800'}, {'kind': 'fact', 'text': 'x' * (core.MAX_TEXT_BYTES + 1)},
                   {'kind': 'fact', 'text': 'synthetic', 'entities': ['a'] * 257},
                   {'kind': 'fact', 'text': 'synthetic', 'provenance': {'owner': 'task'}},
                   {'kind': 'fact', 'text': 'synthetic', 'provenance': {'agent_ref': 2**63-1}},
                   {'kind': 'fact', 'text': 'synthetic', 'provenance': {'agent_ref': {'nested': 'x'}}}]
        invalid += [{'kind': 'fact', 'text': 'synthetic', 'created_at': value} for value in
                    ['0000-01-01T00:00:00Z', '1900-02-29T00:00:00Z', '2026-04-31T00:00:00Z',
                     '2026-01-01T00:00:60Z', '2026-01-01T24:00:00Z', '2026-01-01T00:00:00.0000001Z',
                     '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00Z\n']]
        self.rejected([{'op': 'build', 'input': value} for value in invalid])
        maximum = {'kind': 'fact', 'text': '😀' * (core.MAX_TEXT_BYTES // 4), 'created_at': valid_times[1]}
        actual = self.success({'op': 'build', 'input': maximum})['record']
        self.assertEqual(actual, core.build_record(**maximum))

    def test_python_export_is_parsed_and_typescript_share_is_python_verified(self) -> None:
        # First exercise the actual Python export, not just a constructed packet.
        with tempfile.TemporaryDirectory(prefix='memory-vault-ts-export-synthetic-') as temporary:
            base = Path(temporary).resolve()
            config_path = base / 'client.json'
            storage.atomic_write(config_path, core.canonical_bytes({'schema_version': CONFIG_SCHEMA,
                                 'vault_path': str(base / 'vault.sqlite3'), 'capture_visible_turns': False}), replace=False)
            config = ClientConfig.load(config_path)
            for record in self.records:
                self.trust.verify_record(record, self.proofs[record['memory_id']])
            core.Vault(config.vault_path).ingest_records(self.records, admission='verified', attestations=self.proofs)
            path = base / 'python.ndjson'
            sharing.export_share(config.path, path, {'schema_version': sharing.SELECTOR_SCHEMA,
                                 'memory_ids': [self.root['memory_id']]})
            raw = path.read_bytes()
        parsed = self.success({'op': 'parse', 'raw': self.wire(raw)})
        self.assertEqual(parsed['summary'], self.scan_python(raw))
        by_id = {item['record']['memory_id']: item for item in parsed['records']}
        self.assertEqual(set(by_id), {item['memory_id'] for item in self.records})
        for original in self.records:
            actual = by_id[original['memory_id']]
            self.assertEqual(core.canonical_bytes(actual['record']), core.canonical_bytes(original))
            self.assertEqual(actual['attestation'], self.proofs[original['memory_id']])
        encoded = self.success({'op': 'encode', 'records': parsed['records'], 'roots': parsed['roots']})
        ts_raw = base64.b64decode(encoded['raw'])
        self.assertEqual(encoded['parsed']['summary'], self.scan_python(ts_raw))
        for item in encoded['parsed']['records']:
            self.assertEqual(self.trust.verify_record(item['record'], item['attestation']), self.identity.key_id)

    def test_share_checksum_does_not_grant_trust_and_closure_cannot_smuggle(self) -> None:
        outsider = core.build_record(kind='fact', text='Synthetic unselected unrelated item.', created_at='2026-01-01T00:00:00Z')
        fake_proofs = {key: {**value, 'signature': base64.b64encode(b'\0' * 64).decode()}
                       for key, value in self.proofs.items()}
        # Parser mirrors the legacy non-cryptographic scan; admission must verify.
        parsed = self.success({'op': 'parse', 'raw': self.wire(self.packet(proofs=fake_proofs))})
        self.assertFalse(parsed['summary']['signatures_cryptographically_verified'])
        self.assertFalse(parsed['summary']['grants_authority'])
        self.rejected([{'op': 'verify', 'record': item['record'], 'proof': item['attestation'],
                        'trusted': [self.identity.public_descriptor()]} for item in parsed['records']])
        unsigned = self.success({'op': 'parse', 'raw': self.wire(self.packet(proofs={}))})
        self.assertEqual(unsigned['summary']['attestations'], 0)
        self.assertTrue(all(item['attestation'] is None for item in unsigned['records']))
        invalid = [self.packet([self.root]), self.packet(self.records + [outsider]),
                   self.packet(self.records + [self.root]),
                   self.packet(roots=[], selector={'schema_version': sharing.SELECTOR_SCHEMA, 'all_records': True}),
                   self.packet(selector={'schema_version': sharing.SELECTOR_SCHEMA, 'entities': ['not selected']})]
        for raw in invalid:
            with self.assertRaises(core.MemoryError):
                self.scan_python(raw)
        self.rejected([{'op': 'parse', 'raw': self.wire(raw)} for raw in invalid])
        self.rejected([{'op': 'encode', 'records': [{'record': item, 'attestation': self.proofs.get(item['memory_id'])}
                        for item in self.records + [outsider]], 'roots': [self.root['memory_id']]},
                       {'op': 'encode', 'records': [{'record': self.root, 'attestation': self.proofs[self.root['memory_id']]}],
                        'roots': [self.root['memory_id']]}])

    def test_strict_share_frames_proofs_selector_and_footer(self) -> None:
        raw = self.packet()
        frames = [json.loads(line) for line in raw.splitlines()]
        bad_frames = []
        for mutate in [lambda x: x[0].update(authority='trust-me'),
                       lambda x: x[0]['selector'].update(task_id='new-owner'),
                       lambda x: x[0].update(selector_sha256='0'*64),
                       lambda x: x[-1].update(records=True),
                       lambda x: x[-1].update(records_sha256='0'*64),
                       lambda x: x[-1].update(lines_sha256='0'*64),
                       lambda x: x[1].update(selected='true'),
                       lambda x: x[1]['attestation'].update(signature='AA==')]:
            copied = copy.deepcopy(frames)
            mutate(copied)
            bad_frames.append(b''.join(core.canonical_bytes(frame) + b'\n' for frame in copied))
        invalid = bad_frames + [raw[:-1], raw + b'\n', raw.replace(b'\n', b'\r\n'), b'\xef\xbb\xbf' + raw,
                                raw.replace(b'"type":"header"', b'"type":"header","t\\u0079pe":"header"'),
                                b' ' + raw, b'x' * (sharing.MAX_LINE_BYTES + 1)]
        self.rejected([{'op': 'parse', 'raw': self.wire(value)} for value in invalid] + [{'op': 'shared-buffer'}])

    @unittest.skipUnless(unicodedata.unidata_version == '14.0.0', 'Unicode comparison baseline is Python 3.11 Unicode14')
    def test_unicode14_normalization_matches_python_without_changing_records(self) -> None:
        values = [' Straße Σς Ꭰꭰ  İ\ufeff\x1cＡKÅ e\u0301 😀 ', 'x\u0315\u0300y', '각',
                  'x\U0001e030\u0301y', 'x\U0001e4ec\u0315\u0300y', '\u0378\u0300A']
        # Exhaust every character changed by Python NFKC/casefold, with each
        # separated by an unambiguous ASCII boundary, plus newer assignments.
        changed = [chr(point) for point in range(0x110000)
                   if not 0xd800 <= point <= 0xdfff and
                   (chr(point).casefold() != chr(point) or unicodedata.normalize('NFKC', chr(point)) != chr(point))]
        values += ['|'.join(changed[start:start+256]) for start in range(0, len(changed), 256)]
        values += ['|' .join(chr(point) for point in range(start, min(start+256, 0x1e080)))
                   for start in range(0x1e000, 0x1e080, 256)]
        actual = self.success({'op': 'normalize', 'values': values})
        self.assertEqual(actual, [core.normalize_text(value) for value in values])
        # Meaning-based selectors must use the same NFKC+casefold as Python.
        for concept in ['STRASSE', 'σσ', 'Ꭰ', 'e\u0301']:
            raw = self.packet(selector={'schema_version': sharing.SELECTOR_SCHEMA, 'concepts': [concept]})
            parsed = self.success({'op': 'parse', 'raw': self.wire(raw)})
            self.assertEqual(parsed['summary'], self.scan_python(raw))
            self.assertEqual(parsed['records'][0]['record'], self.root)

    def test_selector_axes_microseconds_offsets_and_root_limit(self) -> None:
        selectors = [
            {'claim_keys': ['storage-choice'], 'kinds': ['decision'],
             'captured_after': '2026-01-01T08:00:00.123456+08:00',
             'captured_before': '2026-01-01T00:00:00.123457Z'},
            {'entities': ['wrong', 'shared entity', '\U0001f600', '\ue000']},
            {'memory_ids': [self.root['memory_id']], 'concepts': ['does-not-match']},
            {'kinds': ['decision']},
            {'captured_after': '2026-01-01T00:00:00Z'},
            {'all_records': True},
        ]
        for selection in selectors:
            raw = self.packet(selector={'schema_version': sharing.SELECTOR_SCHEMA, **selection})
            parsed = self.success({'op': 'parse', 'raw': self.wire(raw)})
            self.assertEqual(parsed['summary'], self.scan_python(raw))
        for selection in [{'captured_before': self.root['created_at']},
                          {'captured_after': '2026-01-01T00:00:00.123457Z'},
                          {'kinds': ['fact']}]:
            raw = self.packet(selector={'schema_version': sharing.SELECTOR_SCHEMA, **selection})
            self.rejected([{'op': 'parse', 'raw': self.wire(raw)}])
        records = [core.build_record(kind='fact', text=f'Synthetic root {number}', created_at='2026-01-01T00:00:00Z')
                   for number in range(65)]
        signed = [{'record': item, 'attestation': None} for item in records]
        result = self.success({'op': 'encode', 'records': signed[:64], 'roots': [item['memory_id'] for item in records[:64]]})
        self.assertEqual(self.scan_python(base64.b64decode(result['raw']))['records'], 64)
        self.rejected([{'op': 'encode', 'records': signed, 'roots': [item['memory_id'] for item in records]},
                       {'op': 'encode', 'records': signed[:1], 'roots': [records[0]['memory_id']] * 2}])


if __name__ == '__main__':
    unittest.main()
