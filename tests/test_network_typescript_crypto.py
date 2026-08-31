"""Independent TS crypto API against the real Python carrier; synthetic only.

No install, Python bridge inside TypeScript, Vault/identity discovery, or network
request. Point MEMORY_VAULT_JOSE_MODULE at an already installed jose 6.2.10 entry
or install the isolated TS package beforehand. Missing prerequisites are skips,
which must not be reported as successful cross-runtime verification.
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
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from memory_vault import MemoryError, canonical_bytes
from memory_vault_trust import Identity
import memory_vault_network_crypto as crypto


DRIVER = r"""
import * as api from './crypto.ts';
import { GeneralEncrypt, importJWK } from 'jose';
import { createHash } from 'node:crypto';
const decode = value => Buffer.from(value, 'base64url');
const encode = value => Buffer.from(value).toString('base64url');
const inputValue = item => item.raw === undefined ? item.value : decode(item.raw);
async function run(item) {
  if (item.op === 'document') {
    const value = api.document(inputValue(item), item.maximum);
    return { canonical: encode(api.canonicalBytes(value)), sha256: api.documentSha256(value), value };
  }
  if (item.op === 'canonical') return { canonical: encode(api.canonicalBytes(item.value)) };
  if (item.op === 'seal' || item.op === 'mutate-seal') {
    const bytes = decode(item.plaintext);
    const options = structuredClone(item.options);
    const pending = api.seal(bytes, options);
    if (item.op === 'mutate-seal') {
      bytes.fill(0x78);
      options.network_id = 'mutated'; options.message_id = 'mutated';
      options.signer.private_key = 'mutated';
      options.recipients[0].encryption_key.public_key = 'mutated';
      options.recipients.reverse();
    }
    return { envelope: await pending };
  }
  if (item.op === 'verify') return { payload: api.verify(inputValue(item), item.options) };
  if (item.op === 'open' || item.op === 'mutate-open') {
    const value = inputValue(item), options = structuredClone(item.options);
    const pending = api.open(value, options);
    if (item.op === 'mutate-open') {
      value.jwe.ciphertext = ''; value.recipient_key_ids.reverse();
      options.identity.private_key = 'mutated'; options.trusted_signers.length = 0;
    }
    return { plaintext: encode(await pending) };
  }
  if (item.op === 'encrypt') return { jwe: await api.encryptBytes(decode(item.plaintext), item.recipients, { context: item.context }) };
  if (item.op === 'decrypt') return { plaintext: encode(await api.decryptBytes(inputValue(item), item.identity, { context: item.context })) };
  if (item.op === 'validate-jwe') return { jwe: api.validateJwe(inputValue(item), { context: item.context }) };
  if (item.op === 'signing-public') return { key: api.validateSigningPublic(inputValue(item)) };
  if (item.op === 'encryption-public') return { key: api.validateEncryptionPublic(inputValue(item)) };
  if (item.op === 'object-invalid') {
    let value, getterCalled = false;
    if (item.kind === 'getter') value = Object.defineProperty({}, 'sensitive', { enumerable: true, get() { getterCalled = true; throw Error('getter ran'); } });
    if (item.kind === 'symbol') value = { [Symbol('ignored')]: 1 };
    if (item.kind === 'hidden') value = Object.defineProperty({}, 'hidden', { value: 1 });
    if (item.kind === 'sparse') value = { array: new Array(2) };
    if (item.kind === 'array-extra') { value = { array: [1] }; value.array.extra = 1; }
    if (item.kind === 'date') value = { value: new Date() };
    if (item.kind === 'toJSON') value = { toJSON() { throw Error('toJSON ran'); } };
    if (item.kind === 'bigint') value = { value: 9223372036854775807n };
    if (item.kind === 'infinity') value = { value: Infinity };
    if (item.kind === 'nan') value = { value: NaN };
    if (item.kind === 'cycle') { value = {}; value.loop = value; }
    try { api.document(value); return { rejected: false }; }
    catch (error) { return { rejected: error instanceof api.NetworkCryptoError, code: error.code, getterCalled }; }
  }
  if (item.op === 'invalid-frame') {
    const plain = decode(item.plaintext), magic = Buffer.from(api.BYTES_SCHEMA + '\n');
    const length = Buffer.alloc(8); length.writeBigUInt64BE(BigInt(item.size));
    const digest = createHash('sha256').update(plain).digest();
    if (item.kind === 'digest') digest[0] ^= 1;
    if (item.kind === 'magic') magic[0] ^= 1;
    const frame = Buffer.concat([magic, length, digest, plain]);
    const recipient = item.recipient;
    const builder = new GeneralEncrypt(frame).setProtectedHeader({ enc: api.ENC, typ: api.BYTES_SCHEMA })
      .setAdditionalAuthenticatedData(api.canonicalBytes(item.context));
    // Match the protocol's recipient-local epk using jose's public multi path.
    for (let i = 0; i < 2; i++) {
      builder.addRecipient(await importJWK({ kty: 'OKP', crv: 'X25519', x: recipient.public_key }, api.ALG))
        .setUnprotectedHeader({ alg: api.ALG, kid: recipient.key_id });
    }
    const jwe = await builder.encrypt(); jwe.recipients = jwe.recipients.slice(0, 1);
    return { jwe };
  }
  throw Error('unknown synthetic operation');
}
const chunks = []; let size = 0;
for await (const chunk of process.stdin) {
  size += chunk.length; if (size > 32 * 1024 * 1024) throw Error('fixture input limit'); chunks.push(chunk);
}
const requests = JSON.parse(Buffer.concat(chunks).toString('utf8'));
const results = [];
for (const request of requests) {
  try { results.push({ ok: true, result: await run(request) }); }
  catch (error) { results.push({ ok: false, error: error instanceof api.NetworkCryptoError ? error.code : 'unexpected_error' }); }
}
process.stdout.write(JSON.stringify(results));
"""


class TypeScriptCryptoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.node = shutil.which("node")
        if cls.node is None:
            raise unittest.SkipTest("Node is required for independent TS crypto verification")
        selected = os.environ.get("MEMORY_VAULT_JOSE_MODULE")
        package = ROOT / "clients/typescript/network/node_modules/jose"
        if selected:
            entry = Path(selected).expanduser().resolve()
            if entry.parts[-3:] != ("dist", "webapi", "index.js"):
                raise RuntimeError("MEMORY_VAULT_JOSE_MODULE must identify jose/dist/webapi/index.js")
            package = entry.parents[2]
        if not (package / "package.json").is_file():
            raise unittest.SkipTest("Explicit installed jose 6.2.10 is required; test does not install dependencies")
        metadata = json.loads((package / "package.json").read_text())
        if metadata.get("name") != "jose" or metadata.get("version") != "6.2.10":
            raise RuntimeError("Independent crypto test requires the exact locked jose 6.2.10")
        cls.temporary = tempfile.TemporaryDirectory(prefix="memory-vault-ts-crypto-synthetic-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.fixture = Path(cls.temporary.name)
        shutil.copyfile(ROOT / "clients/typescript/network/crypto.ts", cls.fixture / "crypto.ts")
        shutil.copyfile(ROOT / "clients/typescript/network/package.json", cls.fixture / "package.json")
        (cls.fixture / "node_modules").mkdir()
        (cls.fixture / "node_modules/jose").symlink_to(package, target_is_directory=True)
        (cls.fixture / "driver.mjs").write_text(DRIVER)

    def setUp(self) -> None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        self.sender = Identity(Ed25519PrivateKey.generate())
        self.other = Identity(Ed25519PrivateKey.generate())
        self.first = crypto.EncryptionIdentity.generate()
        self.second = crypto.EncryptionIdentity.generate()
        self.stranger = crypto.EncryptionIdentity.generate()
        secret = self.sender._private_key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        self.signer = {**self.sender.public_descriptor(), "schema_version": "universal-memory-identity/v1",
                       "private_key": base64.b64encode(secret).decode("ascii")}
        self.recipients = [
            {"signing_key_id": self.sender.key_id, "encryption_key": self.first.public_descriptor()},
            {"signing_key_id": self.other.key_id, "encryption_key": self.second.public_descriptor()},
        ]
        self.options = {"signer": self.signer, "network_id": "synthetic-network", "message_id": "synthetic-message",
                        "recipients": self.recipients, "roster_version": 9007199254740991,
                        "roster_sha256": "a" * 64, "created_at": 0}
        self.trust = crypto.PublicKeyTrust([self.sender.public_descriptor()])
        self.verify_options = {"network_id": "synthetic-network", "trusted_signers": [self.sender.public_descriptor()],
                               "recipient_bindings": self.recipients}
        self.context = {"schema_version": "synthetic-bytes/v1", "unicode": "中文😀e\u0301\u2028\u2029\x00",
                        "smallest": -9007199254740991, "largest": 9007199254740991}
        self.data = (b'unchanged memory\x00\xff\xfe\x01' + '中文😀e\u0301\u2028\u2029'.encode()
                     + b'{"signed_min":-9223372036854775808,"unsigned_max":18446744073709551615}\n')

    def run_ts(self, *requests: dict) -> list[dict]:
        result = subprocess.run([self.node, "--experimental-strip-types", str(self.fixture / "driver.mjs")],
                                input=json.dumps(requests, ensure_ascii=True).encode(), capture_output=True,
                                timeout=60, cwd=self.fixture)
        # Do not copy stdin/private key fixture values into failure messages.
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", errors="replace")[-2000:])
        output = json.loads(result.stdout)
        self.assertEqual(len(output), len(requests))
        return output

    def success(self, request: dict) -> dict:
        result, = self.run_ts(request)
        self.assertTrue(result["ok"], result.get("error"))
        return result["result"]

    def python_envelope(self, plaintext: bytes | None = None) -> dict:
        return crypto.seal(self.data if plaintext is None else plaintext, signer=self.sender,
                           **{key: value for key, value in self.options.items() if key != "signer"})

    def assert_rejected(self, requests: list[dict]) -> list[dict]:
        results = self.run_ts(*requests)
        for index, result in enumerate(results):
            self.assertFalse(result["ok"], f"malformed fixture {index} was accepted")
            self.assertNotEqual(result["error"], "unexpected_error", f"fixture {index} leaked a provider/runtime failure")
        return results

    def test_bidirectional_signed_multirecipient_and_input_snapshot(self) -> None:
        python = self.python_envelope()
        requests = [
            {"op": "open", "raw": crypto.b64url(canonical_bytes(python)),
             "options": {**self.verify_options, "identity": identity.private_document()}}
            for identity in (self.first, self.second)
        ]
        requests.extend([
            {"op": "mutate-open", "value": python, "options": {**self.verify_options, "identity": self.first.private_document()}},
            {"op": "verify", "value": python, "options": self.verify_options},
            {"op": "seal", "plaintext": crypto.b64url(self.data), "options": self.options},
            {"op": "mutate-seal", "plaintext": crypto.b64url(self.data), "options": self.options},
        ])
        results = self.run_ts(*requests)
        for result in results:
            self.assertTrue(result["ok"], result.get("error"))
        for result in results[:3]:
            self.assertEqual(crypto.unb64url(result["result"]["plaintext"], maximum=crypto.MAX_PLAINTEXT_BYTES), self.data)
        self.assertEqual(canonical_bytes(results[3]["result"]["payload"]), canonical_bytes({k: v for k, v in python.items() if k != "proof"}))
        for result in results[4:]:
            envelope = result["result"]["envelope"]
            for identity in (self.first, self.second):
                self.assertEqual(crypto.open_envelope(envelope, identity, self.trust, network_id="synthetic-network"), self.data)

    def test_raw_bytes_and_full_four_mib_budget(self) -> None:
        for data in (b"", self.data, b"m" * crypto.MAX_PLAINTEXT_BYTES):
            with self.subTest(length=len(data)):
                python = crypto.encrypt_bytes(data, [self.first.public_descriptor()], context=self.context)
                results = self.run_ts(
                    {"op": "decrypt", "value": python, "identity": self.first.private_document(), "context": self.context},
                    {"op": "encrypt", "plaintext": crypto.b64url(data), "recipients": [self.first.public_descriptor()], "context": self.context},
                )
                for result in results:
                    self.assertTrue(result["ok"], result.get("error"))
                self.assertEqual(crypto.unb64url(results[0]["result"]["plaintext"], maximum=crypto.MAX_PLAINTEXT_BYTES), data)
                self.assertEqual(crypto.decrypt_bytes(results[1]["result"]["jwe"], self.first, context=self.context), data)
        self.assert_rejected([{"op": "encrypt", "plaintext": crypto.b64url(b"m" * (crypto.MAX_PLAINTEXT_BYTES + 1)),
                               "recipients": [self.first.public_descriptor()], "context": self.context}])

    def test_signed_single_recipient_and_maximum_32_destinations(self) -> None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        local_options = {**self.options, "recipients": [self.recipients[0]]}
        local_verify = {**self.verify_options, "recipient_bindings": [self.recipients[0]], "identity": self.first.private_document()}
        sealed = self.success({"op": "seal", "plaintext": crypto.b64url(self.data), "options": local_options})["envelope"]
        self.assertEqual(len(sealed["jwe"]["recipients"]), 1)
        self.assertEqual(sealed["jwe"]["recipients"][0]["header"]["kid"], self.first.key_id)
        self.assertEqual(json.loads(crypto.unb64url(sealed["jwe"]["protected"], maximum=1024)),
                         {"enc": crypto.ENC, "typ": crypto.BYTES_SCHEMA})
        self.assertEqual(crypto.open_envelope(sealed, self.first, self.trust, network_id="synthetic-network"), self.data)
        python = crypto.seal(self.data, signer=self.sender, **{k: v for k, v in local_options.items() if k != "signer"})
        results = self.run_ts(*[{"op": "open", "value": value, "options": local_verify} for value in (sealed, python)])
        for result in results:
            self.assertTrue(result["ok"], result.get("error"))
            self.assertEqual(crypto.unb64url(result["result"]["plaintext"], maximum=4096), self.data)
        altered = copy.deepcopy(sealed)
        altered["message_id"] = "changed-route"
        ciphertext = bytearray(crypto.unb64url(sealed["jwe"]["ciphertext"], maximum=4096))
        ciphertext[-1] ^= 1
        damaged = copy.deepcopy(sealed)
        damaged["jwe"]["ciphertext"] = crypto.b64url(ciphertext)
        self.assert_rejected([
            {"op": "open", "value": altered, "options": local_verify},
            {"op": "open", "value": damaged, "options": local_verify},
            {"op": "decrypt", "value": sealed["jwe"], "identity": self.first.private_document(),
             "context": {k: v for k, v in altered.items() if k not in {"jwe", "proof"}}},
        ])
        recipients = [self.recipients[0]]
        identities = [self.first]
        for _ in range(crypto.MAX_RECIPIENTS - 1):
            signer = Identity(Ed25519PrivateKey.generate())
            identity = crypto.EncryptionIdentity.generate()
            identities.append(identity)
            recipients.append({"signing_key_id": signer.key_id, "encryption_key": identity.public_descriptor()})
        full = self.success({"op": "seal", "plaintext": crypto.b64url(self.data), "options": {**self.options, "recipients": recipients}})["envelope"]
        self.assertEqual(len(full["jwe"]["recipients"]), crypto.MAX_RECIPIENTS)
        self.assertEqual(crypto.open_envelope(full, identities[-1], self.trust, network_id="synthetic-network"), self.data)
        for identity in (identities[0], identities[-1]):
            opened = self.success({"op": "open", "value": full,
                                   "options": {**self.verify_options, "recipient_bindings": recipients, "identity": identity.private_document()}})
            self.assertEqual(crypto.unb64url(opened["plaintext"], maximum=4096), self.data)
        self.assert_rejected([{"op": "seal", "plaintext": crypto.b64url(self.data), "options": {**self.options, "recipients": recipients + [self.recipients[1]]}}])

    def test_canonical_unicode_safe_integers_and_strict_raw_json(self) -> None:
        value = {**self.context, "special": '\b\f\n\r\t"\\/', "nested": {"__proto__": {"safe": True}, "Z": None, "a": [0, -1]}}
        canonical = canonical_bytes(value)
        actual = self.success({"op": "document", "raw": crypto.b64url(json.dumps(value, ensure_ascii=True, indent=2).encode())})
        self.assertEqual(crypto.unb64url(actual["canonical"], maximum=crypto.MAX_ENVELOPE_BYTES), canonical)
        self.assertEqual(actual["sha256"], hashlib.sha256(canonical).hexdigest())
        zero = self.success({"op": "document", "raw": crypto.b64url(b'{"zero":-0}')})
        self.assertEqual(crypto.unb64url(zero["canonical"], maximum=100), b'{"zero":0}')
        malformed = [
            b'{"same":1,"same":2}', b'{"same":1,"s\\u0061me":2}', b'{"x":{"same":1,"same":2}}',
            b'{"n":9007199254740992}', b'{"n":-9007199254740992}', b'{"n":18446744073709551615}',
            b'{"n":1.0}', b'{"n":1e0}', b'{"n":-0.0}', b'{"n":NaN}', b'{"n":Infinity}',
            b'{"x":"\\ud800"}', b'{"x":"\\udc00"}', b'{"x":"\xff"}', b'{"x":"\xc0\xaf"}',
            b'\xef\xbb\xbf{}', b'{"x":1} trailing', b'[]', b'{"x":01}', b'{"x":1,}',
            '{"非ASCII键":1}'.encode(), b'{"a":' * 25 + b'1' + b'}' * 25,
        ]
        self.assert_rejected([{"op": "document", "raw": crypto.b64url(raw)} for raw in malformed])
        self.assert_rejected([{"op": "document", "raw": crypto.b64url(b'{"x":"' + b'x' * 64 + b'"}'), "maximum": 64}])
        results = self.run_ts(*[{"op": "object-invalid", "kind": kind} for kind in
                               ("getter", "symbol", "hidden", "sparse", "array-extra", "date", "toJSON", "bigint", "infinity", "nan", "cycle")])
        for result in results:
            self.assertTrue(result["ok"])
            self.assertTrue(result["result"]["rejected"])
            self.assertFalse(result["result"]["getterCalled"])

    def test_signature_route_and_trust_fail_closed(self) -> None:
        envelope = self.python_envelope()
        requests = []
        for path, replacement in [
            (("network_id",), "different"), (("message_id",), "different"), (("network_id",), "synthetic-network\n"),
            (("roster_version",), 0), (("roster_version",), True), (("created_at",), -1),
            (("roster_sha256",), "A" * 64), (("sender_key_id",), self.other.key_id),
            (("proof", "key_id"), self.other.key_id), (("proof", "signature"), "A" * 86 + "=="),
            (("proof", "schema_version"), "wrong/v1"), (("proof", "payload_sha256"), "0" * 64),
            (("recipient_key_ids",), sorted(envelope["recipient_key_ids"], reverse=True)),
            (("recipient_key_ids",), [self.sender.key_id, self.sender.key_id]),
            (("recipient_key_ids",), [self.sender.key_id]), (("extra",), "unrecognized"),
        ]:
            altered = copy.deepcopy(envelope)
            target = altered
            for name in path[:-1]:
                target = target[name]
            target[path[-1]] = replacement
            requests.append({"op": "verify", "value": altered, "options": self.verify_options})
        for options in [
            {**self.verify_options, "trusted_signers": []},
            {**self.verify_options, "trusted_signers": [self.other.public_descriptor()]},
            {**self.verify_options, "trusted_signers": [self.sender.public_descriptor()] * 2},
            {**self.verify_options, "recipient_bindings": [{**self.recipients[0], "encryption_key": self.stranger.public_descriptor()}, self.recipients[1]]},
        ]:
            requests.append({"op": "verify", "value": envelope, "options": options})
        requests.append({"op": "open", "value": envelope, "options": {**self.verify_options, "identity": self.stranger.private_document()}})
        raw = canonical_bytes(envelope)
        requests.append({"op": "verify", "raw": crypto.b64url(raw[:-1] + b',"network_id":"synthetic-network"}'), "options": self.verify_options})
        self.assert_rejected(requests)
        # Signature-only crypto verification matches Python; a stale/untrusted
        # roster is NOT endorsed by this API even when its hash is signed.
        minimal = {k: v for k, v in self.verify_options.items() if k != "recipient_bindings"}
        self.success({"op": "verify", "value": envelope, "options": minimal})

    def test_keys_are_distinct_strict_and_private_public_pairs_match(self) -> None:
        envelope = self.python_envelope()
        mismatched = {**self.first.private_document(), "private_key": self.stranger.private_document()["private_key"]}
        signer = {**self.signer, "private_key": base64.b64encode(bytes(range(32))).decode("ascii")}
        requests = [
            {"op": "open", "value": envelope, "options": {**self.verify_options, "identity": mismatched}},
            {"op": "seal", "plaintext": crypto.b64url(self.data), "options": {**self.options, "signer": signer}},
            {"op": "seal", "plaintext": crypto.b64url(self.data), "options": {**self.options, "recipients": [self.recipients[0]] * 2}},
        ]
        for key, operation in [(self.sender.public_descriptor(), "signing-public"), (self.first.public_descriptor(), "encryption-public")]:
            for changed in ({**key, "extra": True}, {**key, "key_id": key["key_id"] + "\n"},
                            {**key, "public_key": key["public_key"] + "="}, {**key, "algorithm": "wrong"},
                            {**key, "schema_version": "wrong/v1"}, {**key, "public_key": key["public_key"][:-1]}):
                requests.append({"op": operation, "value": changed})
        requests.extend([
            {"op": "signing-public", "value": self.first.public_descriptor()},
            {"op": "encryption-public", "value": self.sender.public_descriptor()},
        ])
        self.assert_rejected(requests)

    def test_jwe_profile_limits_and_authenticated_invalid_frames(self) -> None:
        jwe = crypto.encrypt_bytes(self.data, [self.first.public_descriptor()], context=self.context)
        requests = []
        protected = {"enc": crypto.ENC, "typ": crypto.BYTES_SCHEMA}
        headers = [{**protected, "zip": "DEF"}, {**protected, "alg": crypto.ALG}, {**protected, "enc": "A128GCM"},
                   {**protected, "crit": ["x"]}, {**protected, "typ": "wrong/v1"}]
        for header in headers:
            altered = {**jwe, "protected": crypto.b64url(canonical_bytes(header))}
            requests.append({"op": "validate-jwe", "value": altered, "context": self.context})
        duplicate_header = b'{"enc":"A256GCM","enc":"A256GCM","typ":"memory-vault-network-bytes/v1"}'
        requests.append({"op": "validate-jwe", "value": {**jwe, "protected": crypto.b64url(duplicate_header)}, "context": self.context})
        for path, replacement in [
            (("recipients", 0, "header", "alg"), "dir"), (("recipients", 0, "header", "kid"), self.first.key_id + "\n"),
            (("recipients", 0, "header", "epk", "crv"), "Ed25519"), (("recipients", 0, "header", "epk", "d"), "secret"),
            (("recipients", 0, "encrypted_key"), ""), (("ciphertext",), ""), (("iv",), ""), (("tag",), ""),
            (("iv",), jwe["iv"] + "="), (("aad",), crypto.b64url(b'{}')), (("extra",), True),
            (("recipients",), []), (("recipients",), jwe["recipients"] * 2), (("recipients",), jwe["recipients"] * 33),
        ]:
            altered = copy.deepcopy(jwe)
            target = altered
            for name in path[:-1]:
                target = target[name]
            target[path[-1]] = replacement
            requests.append({"op": "validate-jwe", "value": altered, "context": self.context})
        damaged = bytearray(crypto.unb64url(jwe["ciphertext"], maximum=4096))
        damaged[-1] ^= 1
        requests.append({"op": "decrypt", "value": {**jwe, "ciphertext": crypto.b64url(damaged)},
                         "identity": self.first.private_document(), "context": self.context})
        requests.append({"op": "encrypt", "plaintext": "", "recipients": [self.first.public_descriptor()], "context": {"text": "x" * 16384}})
        self.assert_rejected(requests)
        invalid_frames = self.run_ts(*[
            {"op": "invalid-frame", "kind": kind, "size": size, "plaintext": crypto.b64url(self.data),
             "recipient": self.first.public_descriptor(), "context": self.context}
            for kind, size in [("length", "18446744073709551615"), ("length", "4294967296"), ("length", "0"),
                               ("digest", str(len(self.data))), ("magic", str(len(self.data)))]
        ])
        decrypt_requests = []
        for result in invalid_frames:
            self.assertTrue(result["ok"])
            value = result["result"]["jwe"]
            with self.assertRaises(MemoryError):
                crypto.decrypt_bytes(value, self.first, context=self.context)
            decrypt_requests.append({"op": "decrypt", "value": value, "identity": self.first.private_document(), "context": self.context})
        errors = self.assert_rejected(decrypt_requests)
        self.assertEqual(errors[0]["error"], "network_plaintext_integrity_failed")
        self.assertEqual(errors[-1]["error"], "network_plaintext_frame_invalid")

    def test_isolated_package_lock_and_no_io_or_adapter_dependency(self) -> None:
        directory = ROOT / "clients/typescript/network"
        package = json.loads((directory / "package.json").read_text())
        lock = json.loads((directory / "package-lock.json").read_text())
        self.assertEqual(package["dependencies"], {"jose": "6.2.10"})
        self.assertEqual(lock["packages"][""]["dependencies"], package["dependencies"])
        self.assertEqual(set(lock["packages"]), {"", "node_modules/jose"})
        self.assertEqual(lock["packages"]["node_modules/jose"]["resolved"], "https://registry.npmjs.org/jose/-/jose-6.2.10.tgz")
        self.assertTrue(lock["packages"]["node_modules/jose"]["integrity"].startswith("sha512-"))
        source = (directory / "crypto.ts").read_text()
        for prohibited in ("node:fs", "node:child_process", "node:http", "fetch(", "process.env", "process.stdin", "MCP", "A2A"):
            self.assertNotIn(prohibited, source)
        parent = json.loads((directory.parent / "package.json").read_text())
        self.assertNotIn("dependencies", parent)


if __name__ == "__main__":
    unittest.main()
