"""Bounded ACK owner/offer mutual-possession wire, without service authority.

Fresh nonces remain local return values. Callers must authenticate local grant
and current service permission before exposure, and persist replay/one-use state
separately. This module performs no network, DB or file operations. The shared
meter counts actual outer SHA256, Ed25519 verification and explicit byte work;
JOSE's internal curve/KDF/AES allocations and hashes are not reported as such.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hmac
import secrets
from types import MappingProxyType

import memory_vault_network_crypto as crypto
import memory_vault_open_repair_original as original
import memory_vault_open_repair_resource as resource
import memory_vault_open_repair_wire as wire
from memory_vault_trust import Identity

SCHEMA = "memory-vault-open-repair/v1"
MAX_CONTROL_BYTES = 65536
MAX_AAD_BYTES = 16384
_FRAME_SIZE = len(crypto.MAGIC) + 40 + 32
_COMMON = frozenset("schema_version kind signing_key issued_at expires_at subject target target_storage_epoch purpose consumer bootstrap_grant_sha256".split())
_FIELDS = {
    "probe": _COMMON | {"probe_id", "selector", "target_nonce_jwe"},
    "challenge": _COMMON | {"challenge_id", "probe_ref", "target_nonce_answer", "caller_nonce_jwe"},
    "answer": _COMMON | {"challenge_ref", "probe_ref", "answer"},
}
_SELECTOR = frozenset("root_key_sha256 ack_slot_sha256 root_authority_sha256 read_grant_sha256".split())
_SELECTORS = {"ack_owner": _SELECTOR,
              "ack_offer": (_SELECTOR - {"read_grant_sha256"}) | {"write_grant_sha256"}}


def _fail(code="repair_invalid_probe"):
    wire._fail(code)


def _fields(value, names):
    if (type(value) not in (dict, wire._DraftDict) or len(value) != len(names)
            or any(type(key) is not str for key in value) or value.keys() != set(names)):
        _fail()
    return value


def _shape(function, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except wire.RepairWireError:
        _fail()


def _ref(value):
    result = wire.RawRef(**_fields(value, {"namespace", "key", "raw_sha256", "size"}))
    if result.namespace != "meta":
        _fail()
    return result


def _expected(subject, target, epoch, grant, selector, at, policy, budget, *, consumer="ack_owner"):
    if type(consumer) is not str or consumer not in _SELECTORS:
        _fail()
    value = wire.build_new_wire(dict(subject=subject, target=target, epoch=epoch,
        grant=grant, selector=selector, at=at), policy, budget).value
    _shape(wire.u53, value["at"])
    _shape(original._opaque, value["epoch"])
    _shape(original._digest, value["grant"])
    for digest in _fields(value["selector"], _SELECTORS[consumer]).values():
        _shape(original._digest, digest)
    for name in ("subject", "target"):
        key = _shape(resource._dual_key_shape, value[name])
        original._descriptor(key["signing_key"], budget)
        original._descriptor(key["encryption_key"], budget, encryption=True)
    return dict(value, consumer=consumer)


def _dual(keys):
    return {"signing_key_id": keys["signing_key"]["key_id"],
            "encryption_key_id": keys["encryption_key"]["key_id"]}


def _window(payload, at):
    issued, expires = _shape(wire.u53, payload["issued_at"]), _shape(wire.u53, payload["expires_at"])
    if not (1 <= expires - issued <= 60 and issued <= at < expires):
        _fail()


def _nonce(value, budget):
    if type(value) not in (bytes, bytearray, memoryview):
        _fail("repair_invalid_nonce")
    try:
        size = value.nbytes if type(value) is memoryview else len(value)
    except ValueError:
        _fail("repair_invalid_nonce")
    if size != 32:
        _fail("repair_invalid_nonce")
    budget._bytes("input_bytes", 32)
    budget._bytes("output_bytes", 32)
    return memoryview(value).tobytes()


def _fresh_nonce(budget):
    budget._bytes("output_bytes", 32)
    return secrets.token_bytes(32)


def _fresh_id(prefix, budget):
    budget._bytes("output_bytes", 16)
    return prefix + "_" + secrets.token_bytes(16).hex()


def _encode(raw, budget, *, url=True):
    size = 4 * ((len(raw) + 2) // 3)
    budget._bytes("output_bytes", size)
    encoded = base64.urlsafe_b64encode(raw) if url else base64.b64encode(raw)
    if url and encoded.endswith(b"="):
        stripped_size = (len(raw) * 4 + 2) // 3
        budget._bytes("output_bytes", stripped_size)
        encoded = encoded[:stripped_size]
    return encoded.decode("ascii")


def _aad(payload, field, budget):
    context = {name: value for name, value in payload.items() if name != field}
    raw = wire._canonical(context, budget)
    if len(raw) > MAX_AAD_BYTES:
        _fail()
    return raw


def _jwe(value, aad, recipient, policy, budget):
    value = _fields(value, {"protected", "recipients", "aad", "iv", "ciphertext", "tag"})
    header = value["protected"]
    if type(header) is not str or not 1 <= len(header) <= 1366:
        _fail()
    decoded = original._decode64(header, len(header) * 3 // 4, budget, url=True)
    if len(decoded) > 1024:
        _fail()
    protected = original.parse_original_control(decoded, policy, budget).value
    if _fields(protected, {"enc", "typ"}) != {"enc": crypto.ENC, "typ": crypto.BYTES_SCHEMA}:
        _fail()
    if not hmac.compare_digest(original._decode64(value["aad"], len(aad), budget, url=True), aad):
        _fail("repair_probe_mismatch")
    for name, size in (("iv", 12), ("tag", 16), ("ciphertext", _FRAME_SIZE)):
        original._decode64(value[name], size, budget, url=True)
    recipients = value["recipients"]
    if type(recipients) is not wire._DraftList or len(recipients) != 1:
        _fail()
    item = _fields(recipients[0], {"header", "encrypted_key"})
    fields = _fields(item["header"], {"alg", "kid", "epk"})
    if fields["alg"] != crypto.ALG or fields["kid"] != recipient["key_id"]:
        _fail("repair_probe_mismatch")
    ephemeral = _fields(fields["epk"], {"kty", "crv", "x"})
    if ephemeral["kty"] != "OKP" or ephemeral["crv"] != "X25519":
        _fail()
    original._decode64(ephemeral["x"], 32, budget, url=True)
    original._decode64(item["encrypted_key"], 40, budget, url=True)
    return value


def _registry(jwe):
    result = crypto._registry(jwe)
    result.max_recipients = 1
    # joserfc applies this limit to the encoded segment, before base64 decode.
    result.max_ciphertext_length = 4 * ((_FRAME_SIZE + 2) // 3)
    return result


def _encrypt(nonce, recipient, context, field, policy, budget):
    aad = _aad(context, field, budget)
    digest = budget._hash(nonce)
    budget._bytes("output_bytes", 8 + 32 + _FRAME_SIZE)
    frame = b"".join((crypto.MAGIC, (32).to_bytes(8, "big"), bytes.fromhex(digest), nonce))
    _, _, jwe, okp = crypto._providers()
    try:
        obj = jwe.GeneralJSONEncryption({"enc": crypto.ENC, "typ": crypto.BYTES_SCHEMA}, frame, aad=aad)
        key = okp.import_key({"kty": "OKP", "crv": "X25519", "x": recipient["public_key"], "kid": recipient["key_id"]})
        obj.add_recipient({"alg": crypto.ALG, "kid": recipient["key_id"]}, key)
        encrypted = jwe.encrypt_json(obj, None, registry=_registry(jwe))
    except Exception:
        _fail("repair_encryption_failed")
    value = wire.build_new_wire(encrypted, policy, budget).value
    _jwe(value, aad, recipient, policy, budget)
    return value


def _encryption_identity(identity, expected, budget):
    if type(identity) is not crypto.EncryptionIdentity or identity.public_descriptor() != expected:
        _fail("repair_probe_mismatch")
    _, serialization, _, _ = crypto._providers()
    budget._bytes("output_bytes", 32)
    public = identity._private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if not hmac.compare_digest(public, original._decode64(expected["public_key"], 32, budget, url=True)):
        _fail("repair_probe_mismatch")


def _decrypt(value, identity, expected, aad, budget):
    _encryption_identity(identity, expected, budget)
    if not hmac.compare_digest(original._decode64(value["aad"], len(aad), budget, url=True), aad):
        _fail("repair_probe_mismatch")
    budget._fits("output_bytes", _FRAME_SIZE, budget.policy.max_total_bytes - budget._usage["input_bytes"])
    _, _, jwe, okp = crypto._providers()
    try:
        frame = jwe.decrypt_json(value, okp.import_key(identity._jwk()), registry=_registry(jwe)).plaintext
    except Exception:
        _fail("repair_decryption_failed")
    if type(frame) is not bytes or len(frame) != _FRAME_SIZE:
        _fail("repair_invalid_nonce")
    budget._bytes("output_bytes", len(frame))
    prefix = len(crypto.MAGIC)
    if not frame.startswith(crypto.MAGIC) or int.from_bytes(memoryview(frame)[prefix:prefix + 8], "big") != 32:
        _fail("repair_invalid_nonce")
    budget._bytes("output_bytes", 32)
    nonce = frame[prefix + 40:]
    budget._bytes("output_bytes", 32)
    if not hmac.compare_digest(memoryview(frame)[prefix + 8:prefix + 40], bytes.fromhex(budget._hash(nonce))):
        _fail("repair_invalid_nonce")
    return nonce


def _sign(payload, signer, policy, budget):
    if type(signer) is not Identity or signer.public_descriptor() != payload["signing_key"]:
        _fail("repair_probe_mismatch")
    from cryptography.hazmat.primitives import serialization
    budget._bytes("output_bytes", 32)
    actual = signer._private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if not hmac.compare_digest(actual, original._decode64(payload["signing_key"]["public_key"], 32, budget)):
        _fail("repair_probe_mismatch")
    body = dict(schema_version="universal-memory-message-signature/v1", key_id=signer.key_id,
                payload_sha256=budget._hash(wire._canonical(payload, budget)))
    canonical = wire._canonical(body, budget)
    budget._bytes("output_bytes", len(original._DOMAIN) + len(canonical))
    message = original._DOMAIN + canonical
    budget._fits("output_bytes", 64, budget.policy.max_total_bytes - budget._usage["input_bytes"])
    try:
        signature = signer._private_key.sign(message)
    except Exception:
        _fail("repair_signing_failed")
    budget._bytes("output_bytes", len(signature))
    signed = wire.build_new_wire(dict(payload=payload, proof=body | {"signature": _encode(signature, budget, url=False)}), policy, budget)
    if len(signed.raw) > MAX_CONTROL_BYTES:
        _fail()
    digest = budget._hash(signed.raw)
    return resource.AuthenticatedRepairOriginal(signed.raw, wire.RawRef("meta", digest, digest, len(signed.raw)), signed.value["payload"])


def _base(kind, expected, expires_at, budget):
    expires_at = _shape(wire.u53, expires_at)
    signer = expected["target" if kind == "challenge" else "subject"]["signing_key"]
    payload = dict(schema_version=SCHEMA, kind="bootstrap." + kind, signing_key=signer,
        issued_at=expected["at"], expires_at=expires_at,
        subject=expected["subject"] if kind == "probe" else _dual(expected["subject"]),
        target=expected["target"] if kind == "probe" else _dual(expected["target"]),
        target_storage_epoch=expected["epoch"], purpose="bootstrap.service_proof", consumer=expected["consumer"],
        bootstrap_grant_sha256=expected["grant"])
    _window(payload, expected["at"])
    return payload


def _verify(entry, kind, expected, policy, budget):
    entry = _fields(entry, {"raw", "ref"})
    reference = _ref(entry["ref"])
    if wire._raw_size(entry["raw"], policy) > MAX_CONTROL_BYTES:
        _fail()
    draft = wire.parse_new_wire(entry["raw"], policy, budget)
    if len(draft.raw) != reference.size or budget._hash(draft.raw) != reference.raw_sha256:
        _fail("repair_ref_mismatch")
    signed = _fields(draft.value, {"payload", "proof"})
    payload = _fields(signed["payload"], _FIELDS[kind])
    _window(payload, expected["at"])
    if (payload["schema_version"] != SCHEMA or payload["kind"] != "bootstrap." + kind
            or payload["purpose"] != "bootstrap.service_proof" or payload["consumer"] != expected["consumer"]):
        _fail()
    if (payload["target_storage_epoch"] != expected["epoch"] or payload["bootstrap_grant_sha256"] != expected["grant"]
            or payload["subject"] != (expected["subject"] if kind == "probe" else _dual(expected["subject"]))
            or payload["target"] != (expected["target"] if kind == "probe" else _dual(expected["target"]))):
        _fail("repair_probe_mismatch")
    if kind == "probe":
        _shape(original._opaque, payload["probe_id"])
        if payload["selector"] != expected["selector"]:
            _fail("repair_probe_mismatch")
        _jwe(payload["target_nonce_jwe"], _aad(payload, "target_nonce_jwe", budget), expected["target"]["encryption_key"], policy, budget)
    else:
        _ref(payload["probe_ref"])
        if kind == "challenge":
            _shape(original._opaque, payload["challenge_id"])
            original._decode64(payload["target_nonce_answer"], 32, budget, url=True)
            _jwe(payload["caller_nonce_jwe"], _aad(payload, "caller_nonce_jwe", budget), expected["subject"]["encryption_key"], policy, budget)
        else:
            _ref(payload["challenge_ref"])
            original._decode64(payload["answer"], 32, budget, url=True)
    original._verify_control_signature(payload, signed["proof"], expected["target" if kind == "challenge" else "subject"]["signing_key"], budget)
    return resource.AuthenticatedRepairOriginal(draft.raw, reference, payload)


def _child(child, parent, field):
    if (_ref(child.payload[field]) != parent.ref or child.payload["issued_at"] < parent.payload["issued_at"]
            or child.payload["expires_at"] > parent.payload["expires_at"]):
        _fail("repair_probe_mismatch")


@dataclass(frozen=True, slots=True)
class PreparedBootstrapProbe:
    original: resource.AuthenticatedRepairOriginal
    nonce: bytes


@dataclass(frozen=True, slots=True)
class PreparedBootstrapChallenge:
    original: resource.AuthenticatedRepairOriginal
    nonce: bytes


@dataclass(frozen=True, slots=True)
class AuthenticatedBootstrapExchange:
    originals: object
    at: int


def make_bootstrap_probe(signer, *, expected_subject, expected_target, target_storage_epoch,
                         bootstrap_grant_sha256, selector, at, expires_at, policy, budget, consumer="ack_owner"):
    wire._context(policy, budget)
    with budget._lock:
        expected = _expected(expected_subject, expected_target, target_storage_epoch, bootstrap_grant_sha256, selector, at, policy, budget, consumer=consumer)
        payload = _base("probe", expected, expires_at, budget)
        payload.update(probe_id=_fresh_id("probe", budget), selector=expected["selector"])
        nonce = _fresh_nonce(budget)
        payload["target_nonce_jwe"] = _encrypt(nonce, expected["target"]["encryption_key"], payload, "target_nonce_jwe", policy, budget)
        return PreparedBootstrapProbe(_sign(payload, signer, policy, budget), nonce)


def verify_bootstrap_probe(entry, *, expected_subject, expected_target, target_storage_epoch,
                           bootstrap_grant_sha256, selector, at, policy, budget, consumer="ack_owner"):
    wire._context(policy, budget)
    with budget._lock:
        expected = _expected(expected_subject, expected_target, target_storage_epoch, bootstrap_grant_sha256, selector, at, policy, budget, consumer=consumer)
        return _verify(entry, "probe", expected, policy, budget)


def issue_bootstrap_challenge(probe_entry, *, signer, encryption_identity, expected_subject, expected_target,
                              target_storage_epoch, bootstrap_grant_sha256, selector, at, expires_at, policy, budget, consumer="ack_owner"):
    wire._context(policy, budget)
    with budget._lock:
        expected = _expected(expected_subject, expected_target, target_storage_epoch, bootstrap_grant_sha256, selector, at, policy, budget, consumer=consumer)
        probe = _verify(probe_entry, "probe", expected, policy, budget)
        payload = _base("challenge", expected, expires_at, budget)
        if expires_at > probe.payload["expires_at"]:
            _fail("repair_probe_mismatch")
        nonce_answer = _decrypt(probe.payload["target_nonce_jwe"], encryption_identity, expected["target"]["encryption_key"],
                                _aad(probe.payload, "target_nonce_jwe", budget), budget)
        payload.update(challenge_id=_fresh_id("challenge", budget), probe_ref=probe.ref.as_dict(),
                       target_nonce_answer=_encode(nonce_answer, budget))
        nonce = _fresh_nonce(budget)
        payload["caller_nonce_jwe"] = _encrypt(nonce, expected["subject"]["encryption_key"], payload, "caller_nonce_jwe", policy, budget)
        return PreparedBootstrapChallenge(_sign(payload, signer, policy, budget), nonce)


def solve_bootstrap_challenge(probe_entry, challenge_entry, *, signer, encryption_identity, target_nonce,
                              expected_subject, expected_target, target_storage_epoch, bootstrap_grant_sha256,
                              selector, at, expires_at, policy, budget, consumer="ack_owner"):
    wire._context(policy, budget)
    with budget._lock:
        expected = _expected(expected_subject, expected_target, target_storage_epoch, bootstrap_grant_sha256, selector, at, policy, budget, consumer=consumer)
        probe = _verify(probe_entry, "probe", expected, policy, budget)
        challenge = _verify(challenge_entry, "challenge", expected, policy, budget)
        _child(challenge, probe, "probe_ref")
        if not hmac.compare_digest(_nonce(target_nonce, budget), original._decode64(challenge.payload["target_nonce_answer"], 32, budget, url=True)):
            _fail("repair_invalid_nonce")
        payload = _base("answer", expected, expires_at, budget)
        if expires_at > challenge.payload["expires_at"]:
            _fail("repair_probe_mismatch")
        nonce = _decrypt(challenge.payload["caller_nonce_jwe"], encryption_identity, expected["subject"]["encryption_key"],
                         _aad(challenge.payload, "caller_nonce_jwe", budget), budget)
        payload.update(probe_ref=probe.ref.as_dict(), challenge_ref=challenge.ref.as_dict(), answer=_encode(nonce, budget))
        return _sign(payload, signer, policy, budget)


def verify_bootstrap_answer(probe_entry, challenge_entry, answer_entry, *, caller_nonce, expected_subject,
                            expected_target, target_storage_epoch, bootstrap_grant_sha256, selector, at, policy, budget, consumer="ack_owner"):
    wire._context(policy, budget)
    with budget._lock:
        expected = _expected(expected_subject, expected_target, target_storage_epoch, bootstrap_grant_sha256, selector, at, policy, budget, consumer=consumer)
        checked = {kind: _verify(entry, kind, expected, policy, budget) for kind, entry in
                   (("probe", probe_entry), ("challenge", challenge_entry), ("answer", answer_entry))}
        probe, challenge, answer = (checked[kind] for kind in ("probe", "challenge", "answer"))
        _child(challenge, probe, "probe_ref")
        _child(answer, challenge, "challenge_ref")
        _child(answer, probe, "probe_ref")
        if not hmac.compare_digest(_nonce(caller_nonce, budget), original._decode64(answer.payload["answer"], 32, budget, url=True)):
            _fail("repair_invalid_nonce")
        return AuthenticatedBootstrapExchange(MappingProxyType(checked), expected["at"])
