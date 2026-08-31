/** Independent synthetic interop companion. Node >=22 with type stripping.
 * No network, key discovery, disk writes, or model-specific storage.
 * Input private keys are synthetic fixture keys supplied explicitly on stdin.
 */
import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { pathToFileURL } from 'node:url';

const jose = process.env.MEMORY_VAULT_JOSE_MODULE
  ? await import(pathToFileURL(process.env.MEMORY_VAULT_JOSE_MODULE).href)
  : await import('jose');
const ALG = 'ECDH-ES+A256KW';
const ENC = 'A256GCM';
const TYPE = 'memory-vault-network-bytes/v1';
const MAGIC = Buffer.from(TYPE + '\n');
const MAX = 4 * 1024 * 1024;
const MAX_WIRE = 6 * 1024 * 1024;
type Obj = Record<string, any>;
function fail(): never { throw new Error('network_interop_invalid'); }
function hash(b: Uint8Array): string { return createHash('sha256').update(b).digest('hex'); }
function b64(b: Uint8Array): string { return Buffer.from(b).toString('base64url'); }
function unb64(s: any, max: number, length?: number): Buffer {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]*$/.test(s) || s.length > Math.ceil(max * 4 / 3)) fail();
  const b = Buffer.from(s, 'base64url');
  if (b64(b) !== s || b.length > max || (length !== undefined && b.length !== length)) fail();
  return b;
}
function canonical(v: any): Buffer {
  function encode(x: any, depth = 0): string {
    if (depth > 24) fail();
    if (x === null || typeof x === 'boolean') return JSON.stringify(x);
    if (typeof x === 'string') {
      if (Buffer.from(x).toString('utf8') !== x) fail();
      return JSON.stringify(x);
    }
    if (typeof x === 'number' && Number.isSafeInteger(x)) return JSON.stringify(x);
    if (Array.isArray(x)) return '[' + x.map(y => encode(y, depth + 1)).join(',') + ']';
    if (typeof x === 'object' && x) {
      const out: string[] = [];
      for (const key of Object.keys(x).sort()) {
        if (!/^[\x00-\x7f]*$/.test(key)) fail();
        out.push(JSON.stringify(key) + ':' + encode(x[key], depth + 1));
      }
      return '{' + out.join(',') + '}';
    }
    fail();
  }
  return Buffer.from(encode(v));
}
function fields(v: any, names: string[]): Obj {
  if (!v || Array.isArray(v) || typeof v !== 'object' || Object.keys(v).sort().join('|') !== names.sort().join('|')) fail();
  return v;
}
// A small duplicate-rejecting JSON reader. Native JSON.parse alone discards
// duplicate property names before protocol validation can see them.
function parseStrict(source: string): any {
  let i = 0;
  function ws() { while (/[ \t\r\n]/.test(source[i] || '') && i < source.length) i++; }
  function value(depth = 0): any {
    if (depth > 24) fail(); ws();
    if (source[i] === '"') {
      const start = i++;
      while (i < source.length) { if (source[i] === '\\') { i += 2; continue; } if (source[i++] === '"') return JSON.parse(source.slice(start, i)); }
      fail();
    }
    if (source[i] === '{') {
      i++; ws(); const out: Obj = Object.create(null); const keys = new Set<string>();
      if (source[i] === '}') { i++; return out; }
      while (true) {
        if (source[i] !== '"') fail(); const key = value(depth + 1); ws();
        if (keys.has(key) || source[i++] !== ':') fail(); keys.add(key); out[key] = value(depth + 1); ws();
        if (source[i] === '}') { i++; return out; } if (source[i++] !== ',') fail(); ws();
      }
    }
    if (source[i] === '[') {
      i++; ws(); const out = []; if (source[i] === ']') { i++; return out; }
      while (true) { out.push(value(depth + 1)); ws(); if (source[i] === ']') { i++; return out; } if (source[i++] !== ',') fail(); }
    }
    const token = /^(?:true|false|null|-?(?:0|[1-9][0-9]*))/.exec(source.slice(i));
    if (!token) fail(); i += token[0].length; return JSON.parse(token[0]);
  }
  const result = value(); ws(); if (i !== source.length) fail(); canonical(result); return result;
}
function publicKey(v: Obj): Obj {
  fields(v, ['schema_version', 'algorithm', 'key_id', 'public_key']);
  const x = unb64(v.public_key, 32, 32);
  if (v.schema_version !== 'memory-vault-network-encryption-key/v1' || v.algorithm !== 'X25519' || v.key_id !== 'x25519_' + hash(x)) fail();
  return { kty: 'OKP', crv: 'X25519', x: v.public_key, kid: v.key_id };
}
function validate(jwe: Obj, context: Obj) {
  fields(jwe, ['protected', 'recipients', 'aad', 'iv', 'ciphertext', 'tag']);
  const protectedHeader = parseStrict(unb64(jwe.protected, 1024).toString('utf8'));
  if (!canonical(protectedHeader).equals(canonical({ enc: ENC, typ: TYPE }))) fail();
  if (!unb64(jwe.aad, 16384).equals(canonical(context))) fail();
  unb64(jwe.iv, 12, 12); unb64(jwe.tag, 16, 16); unb64(jwe.ciphertext, MAX + MAGIC.length + 40);
  if (!Array.isArray(jwe.recipients) || jwe.recipients.length < 1 || jwe.recipients.length > 32) fail();
  const kids = new Set();
  for (const recipient of jwe.recipients) {
    fields(recipient, ['header', 'encrypted_key']); fields(recipient.header, ['alg', 'kid', 'epk']);
    const h = recipient.header; fields(h.epk, ['kty', 'crv', 'x']);
    if (h.alg !== ALG || !/^x25519_[a-f0-9]{64}$/.test(h.kid) || kids.has(h.kid) || h.epk.kty !== 'OKP' || h.epk.crv !== 'X25519') fail();
    kids.add(h.kid); unb64(h.epk.x, 32, 32); unb64(recipient.encrypted_key, 40, 40);
  }
  if (canonical(jwe).length > MAX_WIRE) fail();
}
async function encryptBytes(plaintext: Buffer, recipients: Obj[], context: Obj): Promise<Obj> {
  if (plaintext.length > MAX || canonical(context).length > 16384 || recipients.length < 1 || recipients.length > 32) fail();
  const length = Buffer.alloc(8); length.writeBigUInt64BE(BigInt(plaintext.length));
  const frame = Buffer.concat([MAGIC, length, Buffer.from(hash(plaintext), 'hex'), plaintext]);
  const builder = new jose.GeneralEncrypt(frame).setProtectedHeader({ enc: ENC, typ: TYPE }).setAdditionalAuthenticatedData(canonical(context));
  for (const item of [...recipients].sort((a, b) => a.key_id.localeCompare(b.key_id))) {
    const jwk = publicKey(item);
    builder.addRecipient(await jose.importJWK(jwk, ALG)).setUnprotectedHeader({ alg: ALG, kid: item.key_id });
  }
  const result = await builder.encrypt(); validate(result, context); return result;
}
async function decryptBytes(jwe: Obj, privateDocument: Obj, context: Obj): Promise<Buffer> {
  validate(jwe, context);
  fields(privateDocument, ['schema_version', 'algorithm', 'key_id', 'public_key', 'private_key']);
  if (privateDocument.schema_version !== 'memory-vault-network-encryption-identity/v1') fail();
  const pub = publicKey({ schema_version: 'memory-vault-network-encryption-key/v1', algorithm: privateDocument.algorithm,
    key_id: privateDocument.key_id, public_key: privateDocument.public_key });
  return decryptWithKey(jwe, privateDocument, pub);
}
async function decryptWithKey(jwe: Obj, privateDocument: Obj, pub?: Obj): Promise<Buffer> {
  const publicDocument = { schema_version: 'memory-vault-network-encryption-key/v1', algorithm: privateDocument.algorithm, key_id: privateDocument.key_id, public_key: privateDocument.public_key };
  const jwk = { ...(pub || publicKey(publicDocument)), d: privateDocument.private_key };
  unb64(jwk.d, 32, 32);
  const matching = jwe.recipients.filter((r: Obj) => r.header.kid === privateDocument.key_id);
  if (matching.length !== 1) fail();
  // Preserve the complete externally signed object. jose decrypts only with
  // this explicitly supplied recipient key, not other members' private keys.
  const result = await jose.generalDecrypt(jwe, await jose.importJWK(jwk, ALG), { keyManagementAlgorithms: [ALG], contentEncryptionAlgorithms: [ENC] });
  const frame = Buffer.from(result.plaintext);
  if (!frame.subarray(0, MAGIC.length).equals(MAGIC) || frame.length < MAGIC.length + 40) fail();
  const plain = frame.subarray(MAGIC.length + 40);
  if (frame.readBigUInt64BE(MAGIC.length) !== BigInt(plain.length) || !frame.subarray(MAGIC.length + 8, MAGIC.length + 40).equals(Buffer.from(hash(plain), 'hex'))) fail();
  return plain;
}
function route(envelope: Obj): Obj {
  const result: Obj = { ...envelope }; delete result.jwe; delete result.proof; return result;
}
function verifyEnvelope(envelope: Obj, publicDescriptor: Obj, networkId: string) {
  fields(envelope, ['schema_version', 'network_id', 'message_id', 'sender_key_id', 'recipient_key_ids', 'roster_version', 'roster_sha256', 'created_at', 'jwe', 'proof']);
  if (envelope.schema_version !== 'memory-vault-network-envelope/v1' || envelope.network_id !== networkId) fail();
  const x = Buffer.from(publicDescriptor.public_key, 'base64');
  const keyId = 'ed25519_' + hash(x);
  if (x.length !== 32 || publicDescriptor.key_id !== keyId || envelope.sender_key_id !== keyId) fail();
  const body = { ...envelope }; delete body.proof;
  const proof = envelope.proof;
  fields(proof, ['schema_version', 'key_id', 'payload_sha256', 'signature']);
  if (proof.schema_version !== 'universal-memory-message-signature/v1' || proof.key_id !== keyId || proof.payload_sha256 !== hash(canonical(body))) fail();
  const signed = { schema_version: proof.schema_version, key_id: proof.key_id, payload_sha256: proof.payload_sha256 };
  const bytes = Buffer.concat([Buffer.from('UniversalAgentMemory\0message-signature\0v1\0'), canonical(signed)]);
  if (!verify(null, bytes, createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: b64(x) }, format: 'jwk' }), Buffer.from(proof.signature, 'base64'))) fail();
  validate(envelope.jwe, route(envelope));
}
async function main(input: Obj): Promise<Obj> {
  if (input.op === 'encrypt') return { jwe: await encryptBytes(unb64(input.plaintext, MAX), input.recipients, input.context) };
  if (input.op === 'decrypt') {
    return { plaintext: b64(await decryptBytes(input.jwe, input.identity, input.context)) };
  }
  if (input.op === 'open') {
    verifyEnvelope(input.envelope, input.signing_public, input.network_id);
    return { plaintext: b64(await decryptBytes(input.envelope.jwe, input.identity, route(input.envelope))) };
  }
  if (input.op === 'seal') {
    const body = { ...input.route, jwe: await encryptBytes(unb64(input.plaintext, MAX), input.recipients, input.route) };
    const key = createPrivateKey({ key: input.signing_private_jwk, format: 'jwk' });
    const proof = { schema_version: 'universal-memory-message-signature/v1', key_id: input.route.sender_key_id, payload_sha256: hash(canonical(body)) };
    const bytes = Buffer.concat([Buffer.from('UniversalAgentMemory\0message-signature\0v1\0'), canonical(proof)]);
    return { envelope: { ...body, proof: { ...proof, signature: sign(null, bytes, key).toString('base64') } } };
  }
  fail();
}
try {
  const chunks: Buffer[] = []; let size = 0;
  for await (const chunk of process.stdin) { size += chunk.length; if (size > 2 * MAX_WIRE) fail(); chunks.push(chunk); }
  const result = await main(parseStrict(Buffer.concat(chunks).toString('utf8')));
  process.stdout.write(JSON.stringify(result) + '\n');
} catch {
  process.stdout.write('{"error":"network_interop_failed"}\n'); process.exitCode = 1;
}
