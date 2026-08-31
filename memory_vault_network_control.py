"""Explicit signed network administration, separate from memory and the relay.

Invitations do not grant host execution rights. The relay never issues keys or
membership policy. Recovery decrypts data only: it cannot reactivate an identity.
Optional HTTP authority signs the current operator-selected roster, not remote
membership changes. All crypto/web dependencies are lazy.
"""
from __future__ import annotations

import hashlib
import hmac
from pathlib import Path
import secrets
import time
from typing import Any, Mapping, Sequence

from memory_vault import MemoryError, canonical_bytes
from memory_vault_trust import Identity, TrustStore, TrustError, _read_private
from memory_vault_network_crypto import (
    EncryptionIdentity, NetworkCryptoError, PublicKeyTrust, b64url, unb64url,
    digest, document, document_sha256, encrypt_bytes, decrypt_bytes,
    encryption_public_descriptor, integer, object_fields, opaque, public_signing_key,
)

INVITE_SCHEMA = "memory-vault-network-invite/v1"
ROSTER_SCHEMA = "memory-vault-network-roster/v1"
STATUS_SCHEMA = "memory-vault-network-status/v1"
REQUEST_SCHEMA = "memory-vault-network-request/v1"
CHALLENGE_SCHEMA = "memory-vault-network-join-challenge/v1"
RECOVERY_SCHEMA = "memory-vault-network-recovery/v1"
MAX_CONTROL_BYTES = 1024 * 1024
MAX_MEMBERS = 256
MAX_VALIDITY_SECONDS = 300


def _now(value: int | None) -> int:
    return int(time.time()) if value is None else integer(value)


def _window(raw: Mapping[str, Any], *, maximum: int = MAX_VALIDITY_SECONDS,
            now: int | None = None, allow_expired: bool = False) -> None:
    issued, expires = integer(raw["issued_at"]), integer(raw["expires_at"])
    if not 1 <= expires - issued <= maximum:
        raise NetworkCryptoError("network_invalid_validity")
    current = _now(now)
    if issued > current + 30:
        raise NetworkCryptoError("network_control_from_future")
    if not allow_expired and expires <= current:
        raise NetworkCryptoError("network_control_expired")


def _scope(value: Any) -> list[str]:
    if (not isinstance(value, list) or not value or any(item not in ("send", "receive") for item in value)
            or value != sorted(set(value))):
        raise NetworkCryptoError("network_invalid_scope")
    return value


def _sign(payload: Mapping[str, Any], issuer: Identity) -> dict[str, Any]:
    checked = document(payload, maximum=MAX_CONTROL_BYTES)
    return {"payload": checked, "proof": issuer.sign_message(checked)}


def _verify(value: Mapping[str, Any] | bytes, trust: TrustStore) -> dict[str, Any]:
    raw = object_fields(document(value, maximum=MAX_CONTROL_BYTES), {"payload", "proof"})
    payload = document(raw["payload"], maximum=MAX_CONTROL_BYTES)
    try:
        trust.verify_message(payload, raw["proof"])
    except TrustError as exc:
        raise NetworkCryptoError(exc.code) from None
    return payload


def _invite(value: Mapping[str, Any], *, network_id: str, now: int | None = None,
            allow_expired: bool = False) -> dict[str, Any]:
    raw = object_fields(value, {"schema_version", "network_id", "invite_id", "candidate_signing_key",
                               "candidate_encryption_key", "scope", "handoff_sha256", "roster_sha256", "issued_at", "expires_at"})
    if raw["schema_version"] != INVITE_SCHEMA or opaque(raw["network_id"]) != network_id:
        raise NetworkCryptoError("network_invite_binding_mismatch")
    opaque(raw["invite_id"])
    public_signing_key(raw["candidate_signing_key"])
    encryption_public_descriptor(raw["candidate_encryption_key"])
    _scope(raw["scope"])
    digest(raw["handoff_sha256"])
    digest(raw["roster_sha256"])
    _window(raw, maximum=7 * 86400, now=now, allow_expired=allow_expired)
    return raw


def issue_invite(issuer: Identity, *, network_id: str, invite_id: str,
                 candidate_signing_key: Mapping[str, Any], candidate_encryption_key: Mapping[str, Any],
                 scope: Sequence[str], handoff_sha256: str, roster_sha256: str,
                 issued_at: int, expires_at: int) -> dict[str, Any]:
    raw = {"schema_version": INVITE_SCHEMA, "network_id": network_id, "invite_id": invite_id,
           "candidate_signing_key": dict(candidate_signing_key), "candidate_encryption_key": dict(candidate_encryption_key),
           "scope": sorted(scope), "handoff_sha256": handoff_sha256, "roster_sha256": roster_sha256,
           "issued_at": issued_at, "expires_at": expires_at}
    return _sign(_invite(raw, network_id=network_id, now=issued_at), issuer)


def verify_invite(value: Mapping[str, Any] | bytes, issuers: TrustStore, *, network_id: str,
                  now: int | None = None) -> dict[str, Any]:
    return _invite(_verify(value, issuers), network_id=network_id, now=now)


def member(value: Mapping[str, Any]) -> dict[str, Any]:
    raw = object_fields(value, {"signing_key", "encryption_key", "status", "scope"})
    public_signing_key(raw["signing_key"])
    encryption_public_descriptor(raw["encryption_key"])
    _scope(raw["scope"])
    if raw["status"] not in ("active", "revoked"):
        raise NetworkCryptoError("network_invalid_member_status")
    return raw


def _roster(value: Mapping[str, Any], *, network_id: str, now: int | None = None,
            allow_expired: bool = False) -> dict[str, Any]:
    raw = object_fields(value, {"schema_version", "network_id", "version", "previous_sha256", "members", "issued_at", "expires_at"})
    if raw["schema_version"] != ROSTER_SCHEMA or opaque(raw["network_id"]) != network_id:
        raise NetworkCryptoError("network_roster_binding_mismatch")
    version = integer(raw["version"], minimum=1)
    previous = digest(raw["previous_sha256"])
    if (version == 1) != (previous == "0" * 64):
        raise NetworkCryptoError("network_roster_genesis_mismatch")
    if not isinstance(raw["members"], list) or not 1 <= len(raw["members"]) <= MAX_MEMBERS:
        raise NetworkCryptoError("network_roster_member_limit")
    checked = [member(item) for item in raw["members"]]
    signers = [item["signing_key"]["key_id"] for item in checked]
    encryption = [item["encryption_key"]["key_id"] for item in checked]
    if signers != sorted(set(signers)) or len(set(encryption)) != len(encryption):
        raise NetworkCryptoError("network_duplicate_member_key")
    _window(raw, now=now, allow_expired=allow_expired)
    return raw


def issue_roster(issuer: Identity, *, network_id: str, version: int, previous_sha256: str,
                 members: Sequence[Mapping[str, Any]], issued_at: int, expires_at: int) -> dict[str, Any]:
    raw = {"schema_version": ROSTER_SCHEMA, "network_id": network_id, "version": version,
           "previous_sha256": previous_sha256, "members": sorted([dict(item) for item in members], key=lambda item: item["signing_key"]["key_id"]),
           "issued_at": issued_at, "expires_at": expires_at}
    return _sign(_roster(raw, network_id=network_id, now=issued_at), issuer)


def verify_roster(value: Mapping[str, Any] | bytes, issuers: TrustStore, *, network_id: str,
                  minimum_version: int = 0, expected_previous_sha256: str | None = None,
                  now: int | None = None, allow_expired: bool = False) -> dict[str, Any]:
    """allow_expired requires a separately verified fresh issuer status.

    It is also useful for inert recovery inspection, never for authorizing an
    operation without that status. Merely fetching this document from a relay
    does not prove it is the issuer's current roster.
    """
    raw = _roster(_verify(value, issuers), network_id=network_id, now=now, allow_expired=allow_expired)
    if raw["version"] < integer(minimum_version):
        raise NetworkCryptoError("network_roster_rollback")
    if expected_previous_sha256 is not None and raw["previous_sha256"] != digest(expected_previous_sha256):
        raise NetworkCryptoError("network_roster_chain_mismatch")
    return raw


def issue_status(issuer: Identity, *, network_id: str, nonce: str, roster_sha256: str,
                 roster_version: int, issued_at: int, expires_at: int) -> dict[str, Any]:
    raw = {"schema_version": STATUS_SCHEMA, "network_id": opaque(network_id), "nonce": opaque(nonce),
           "roster_sha256": digest(roster_sha256), "roster_version": integer(roster_version, minimum=1),
           "issued_at": issued_at, "expires_at": expires_at}
    _window(raw, now=issued_at)
    return _sign(raw, issuer)


def verify_status(value: Mapping[str, Any] | bytes, issuers: TrustStore, *, network_id: str, nonce: str,
                  roster_sha256: str | None = None, roster_version: int | None = None,
                  now: int | None = None) -> dict[str, Any]:
    raw = object_fields(_verify(value, issuers), {"schema_version", "network_id", "nonce", "roster_sha256", "roster_version", "issued_at", "expires_at"})
    if raw["schema_version"] != STATUS_SCHEMA or opaque(raw["network_id"]) != network_id or opaque(raw["nonce"]) != opaque(nonce):
        raise NetworkCryptoError("network_status_binding_mismatch")
    digest(raw["roster_sha256"])
    integer(raw["roster_version"], minimum=1)
    if roster_sha256 is not None and raw["roster_sha256"] != digest(roster_sha256):
        raise NetworkCryptoError("network_status_roster_mismatch")
    if roster_version is not None and raw["roster_version"] != integer(roster_version, minimum=1):
        raise NetworkCryptoError("network_status_roster_mismatch")
    _window(raw, now=now)
    return raw


def sign_request(signer: Identity, *, network_id: str, action: str, request_id: str,
                 body: Mapping[str, Any], issued_at: int, expires_at: int) -> dict[str, Any]:
    raw = {"schema_version": REQUEST_SCHEMA, "network_id": opaque(network_id), "action": action,
           "request_id": opaque(request_id), "body": document(body, maximum=MAX_CONTROL_BYTES // 2),
           "issued_at": issued_at, "expires_at": expires_at}
    if action not in ("join", "messages", "poll", "ack", "status"):
        raise NetworkCryptoError("network_request_action_rejected")
    _window(raw, now=issued_at)
    return _sign(raw, signer)


def verify_request(value: Mapping[str, Any] | bytes, peers: TrustStore, *, network_id: str,
                   action: str | None = None, now: int | None = None) -> dict[str, Any]:
    raw = object_fields(_verify(value, peers), {"schema_version", "network_id", "action", "request_id", "body", "issued_at", "expires_at"})
    if raw["schema_version"] != REQUEST_SCHEMA or opaque(raw["network_id"]) != network_id:
        raise NetworkCryptoError("network_request_binding_mismatch")
    if raw["action"] not in ("join", "messages", "poll", "ack", "status") or (action is not None and raw["action"] != action):
        raise NetworkCryptoError("network_request_action_rejected")
    opaque(raw["request_id"])
    document(raw["body"], maximum=MAX_CONTROL_BYTES // 2)
    _window(raw, now=now)
    return raw


def _challenge(value: Mapping[str, Any], *, network_id: str, invite_id: str,
               now: int | None = None) -> dict[str, Any]:
    raw = object_fields(value, {"schema_version", "network_id", "invite_id", "challenge_id", "issued_at", "expires_at", "jwe"})
    if raw["schema_version"] != CHALLENGE_SCHEMA or opaque(raw["network_id"]) != network_id or opaque(raw["invite_id"]) != invite_id:
        raise NetworkCryptoError("network_challenge_binding_mismatch")
    opaque(raw["challenge_id"])
    _window(raw, now=now)
    return raw


def create_join_challenge(invite_payload: Mapping[str, Any], *, challenge_id: str,
                          issued_at: int, expires_at: int) -> tuple[dict[str, Any], str]:
    """Input is the result of verify_invite; caller stores only hash(answer)."""
    invite = _invite(invite_payload, network_id=invite_payload.get("network_id"), now=issued_at)
    if expires_at > invite["expires_at"]:
        raise NetworkCryptoError("network_challenge_outlives_invite")
    context = {"schema_version": CHALLENGE_SCHEMA, "network_id": invite["network_id"], "invite_id": invite["invite_id"],
               "challenge_id": opaque(challenge_id), "issued_at": issued_at, "expires_at": expires_at}
    _window(context, now=issued_at)
    answer = secrets.token_bytes(32)
    return {**context, "jwe": encrypt_bytes(answer, [invite["candidate_encryption_key"]], context=context)}, b64url(answer)


def open_join_challenge(value: Mapping[str, Any] | bytes, identity: EncryptionIdentity, *, network_id: str,
                        invite_id: str, now: int | None = None) -> str:
    raw = _challenge(document(value), network_id=network_id, invite_id=invite_id, now=now)
    context = {key: val for key, val in raw.items() if key != "jwe"}
    answer = decrypt_bytes(raw["jwe"], identity, context=context)
    if len(answer) != 32:
        raise NetworkCryptoError("network_challenge_answer_invalid")
    return b64url(answer)


def verify_join_proof(request: Mapping[str, Any] | bytes, invite_payload: Mapping[str, Any], *,
                      challenge_id: str, answer_sha256: str, invite_sha256: str,
                      now: int | None = None) -> dict[str, Any]:
    """The invite payload must already pass independent issuer verification.

    answer_sha256 is SHA256 of the ASCII base64url answer returned above.
    Relay must consume invitation and challenge atomically after this succeeds.
    """
    invite = _invite(invite_payload, network_id=invite_payload.get("network_id"), now=now)
    trust = PublicKeyTrust([invite["candidate_signing_key"]])
    raw = verify_request(request, trust, network_id=invite["network_id"], action="join", now=now)
    body = object_fields(raw["body"], {"invite_sha256", "challenge_id", "challenge_answer"})
    if body["invite_sha256"] != digest(invite_sha256) or body["challenge_id"] != opaque(challenge_id):
        raise NetworkCryptoError("network_join_binding_mismatch")
    unb64url(body["challenge_answer"], maximum=32, size=32)
    actual = hashlib.sha256(body["challenge_answer"].encode("ascii")).hexdigest()
    if not hmac.compare_digest(actual, digest(answer_sha256)):
        raise NetworkCryptoError("network_join_key_proof_failed")
    return raw


def generate_recovery_secret() -> str:
    """Explicit operator action; keep this separate from the encrypted package."""
    return b64url(secrets.token_bytes(32))


def _aesgcm() -> Any:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        raise NetworkCryptoError("network_crypto_dependency_unavailable") from None
    return AESGCM


def export_recovery(payload: Mapping[str, Any], *, recovery_secret: str, network_id: str,
                    created_at: int | None = None) -> dict[str, Any]:
    secret = unb64url(recovery_secret, maximum=32, size=32)
    context = {"schema_version": RECOVERY_SCHEMA, "network_id": opaque(network_id),
               "created_at": _now(created_at), "enc": "A256GCM"}
    plaintext = canonical_bytes({"payload": document(payload, maximum=MAX_CONTROL_BYTES), "activation_disabled": True})
    nonce = secrets.token_bytes(12)
    ciphertext = _aesgcm()(secret).encrypt(nonce, plaintext, canonical_bytes(context))
    return {**context, "iv": b64url(nonce), "ciphertext": b64url(ciphertext)}


def import_recovery(value: Mapping[str, Any] | bytes, *, recovery_secret: str, network_id: str) -> dict[str, Any]:
    """Return inert data only; no key files, registry writes, activation or I/O."""
    raw = object_fields(document(value, maximum=2 * MAX_CONTROL_BYTES), {"schema_version", "network_id", "created_at", "enc", "iv", "ciphertext"})
    if raw["schema_version"] != RECOVERY_SCHEMA or opaque(raw["network_id"]) != network_id or raw["enc"] != "A256GCM":
        raise NetworkCryptoError("network_recovery_binding_mismatch")
    integer(raw["created_at"])
    context = {key: raw[key] for key in ("schema_version", "network_id", "created_at", "enc")}
    try:
        plaintext = _aesgcm()(unb64url(recovery_secret, maximum=32, size=32)).decrypt(
            unb64url(raw["iv"], maximum=12, size=12), unb64url(raw["ciphertext"], maximum=MAX_CONTROL_BYTES + 4096), canonical_bytes(context))
    except MemoryError:
        raise
    except Exception:
        raise NetworkCryptoError("network_recovery_decryption_failed") from None
    restored = object_fields(document(plaintext, maximum=MAX_CONTROL_BYTES + 4096), {"payload", "activation_disabled"})
    if restored["activation_disabled"] is not True:
        raise NetworkCryptoError("network_recovery_activation_forbidden")
    return {"schema_version": "memory-vault-network-recovery-result/v1", "network_id": network_id,
            "payload": restored["payload"], "activation_disabled": True, "requires_fresh_issuer_status": True}


def create_authority_app(config_path: Path) -> Any:
    """Optional read-only status signer; serve behind operator-owned HTTPS.

    Config: schema_version memory-vault-network-authority-config/v1, network_id,
    identity_path, trust_store_path, roster_path (explicit protected files).
    Optional node_directory_path enables POST /v1/node-status for independently
    authorized node keys and adds node control to member status responses; it
    does not enroll storage nodes as agent members.
    POST /v1/status accepts {network_id, nonce, request}; the signed request must
    prove an active member key in the local issuer roster. It cannot modify it.
    """
    try:
        from starlette.applications import Starlette
        from starlette.requests import Request
        from starlette.responses import JSONResponse
        from starlette.routing import Route
    except ImportError:
        raise NetworkCryptoError("network_http_dependency_unavailable") from None

    async def status(request: Request) -> JSONResponse:
        try:
            data = bytearray()
            async for chunk in request.stream():
                data.extend(chunk)
                if len(data) > 4096:
                    raise NetworkCryptoError("network_request_too_large")
            query = object_fields(document(bytes(data), maximum=4096), {"network_id", "nonce", "request"})
            nonce = opaque(query["nonce"])
            raw_config = _read_private(config_path, 16 * 1024)
            if raw_config is None:
                raise NetworkCryptoError("network_authority_not_configured")
            config = document(raw_config, maximum=16 * 1024)
            required = {"schema_version", "network_id", "identity_path", "trust_store_path", "roster_path"}
            if not required <= set(config) or set(config) - required - {"node_directory_path"}:
                raise NetworkCryptoError("network_authority_configuration_invalid")
            if config["schema_version"] != "memory-vault-network-authority-config/v1" or opaque(config["network_id"]) != query["network_id"]:
                raise NetworkCryptoError("network_authority_configuration_invalid")
            paths = [Path(config[name]) for name in ("identity_path", "trust_store_path", "roster_path")]
            if not all(path.is_absolute() for path in paths):
                raise NetworkCryptoError("network_authority_configuration_invalid")
            issuer = Identity.load(paths[0])
            trust = TrustStore(paths[1])
            trust.require_trusted(issuer.key_id)
            roster_raw = _read_private(paths[2], MAX_CONTROL_BYTES)
            if roster_raw is None:
                raise NetworkCryptoError("network_roster_missing")
            roster_doc = document(roster_raw, maximum=MAX_CONTROL_BYTES)
            # This operator-selected file is the authority's current state.
            # Fresh status attests the old signed roster is still current; it
            # does not infer currentness from an untrusted relay response.
            roster = verify_roster(roster_doc, trust, network_id=config["network_id"], allow_expired=True)
            node_route = request.url.path == "/v1/node-status"
            directory_doc = directory = None
            if node_route or "node_directory_path" in config:
                from memory_vault_nodes import authorized_node, issue_node_status, verify_directory, verify_node_request
                directory_path = config.get("node_directory_path")
                if not isinstance(directory_path, str) or not Path(directory_path).is_absolute():
                    raise NetworkCryptoError("network_node_authority_not_configured")
                directory_raw = _read_private(Path(directory_path), MAX_CONTROL_BYTES)
                if directory_raw is None:
                    raise NetworkCryptoError("network_node_directory_missing")
                directory_doc = document(directory_raw, maximum=MAX_CONTROL_BYTES)
                directory = verify_directory(directory_doc, trust, network_id=config["network_id"], allow_expired=True)
            if node_route:
                # This separate domain proves possession of a node signing key.
                # No agent membership or X25519 decryption key is required.
                key_id = query["request"].get("proof", {}).get("key_id")
                entry = authorized_node(directory, key_id, "refresh")
                caller = verify_node_request(query["request"], PublicKeyTrust([entry["signing_key"]]),
                                             network_id=config["network_id"], action="refresh")
            else:
                callers = PublicKeyTrust([entry["signing_key"] for entry in roster["members"] if entry["status"] == "active"])
                caller = verify_request(query["request"], callers, network_id=config["network_id"], action="status")
            if object_fields(caller["body"], {"nonce"})["nonce"] != nonce:
                raise NetworkCryptoError("network_status_binding_mismatch")
            now = int(time.time())
            signed = issue_status(issuer, network_id=config["network_id"], nonce=nonce,
                                  roster_sha256=document_sha256(roster_doc), roster_version=roster["version"],
                                  issued_at=now, expires_at=now + MAX_VALIDITY_SECONDS)
            response = {"status": signed, "roster": roster_doc}
            if directory_doc is not None:
                response.update({"nodes": directory_doc, "node_status": issue_node_status(issuer,
                    network_id=config["network_id"], nonce=nonce, roster_sha256=document_sha256(roster_doc),
                    roster_version=roster["version"], directory_sha256=document_sha256(directory_doc),
                    directory_version=directory["version"], issued_at=now, expires_at=now + MAX_VALIDITY_SECONDS)})
            return JSONResponse(response, headers={"Cache-Control": "no-store"})
        except (MemoryError, TrustError) as exc:
            return JSONResponse({"error": exc.code}, status_code=400, headers={"Cache-Control": "no-store"})
        except Exception:
            return JSONResponse({"error": "network_authority_unavailable"}, status_code=503, headers={"Cache-Control": "no-store"})

    return Starlette(routes=[Route(path, status, methods=["POST"]) for path in ("/v1/status", "/v1/node-status")])


def main(argv: Sequence[str] | None = None) -> int:
    """Explicit foreground loopback service, with no installation/autostart."""
    import argparse
    parser = argparse.ArgumentParser(description="Private issuer status signer. Put an operator-owned HTTPS proxy in front; no remote administration.")
    commands = parser.add_subparsers(dest="action", required=True)
    serve = commands.add_parser("serve")
    serve.add_argument("--config", type=Path, required=True)
    serve.add_argument("--port", type=int, default=8767)
    args = parser.parse_args(argv)
    if not args.config.is_absolute() or not 1024 <= args.port <= 65535:
        parser.error("an absolute private configuration and unprivileged port are required")
    try:
        import uvicorn
        app = create_authority_app(args.config)
        uvicorn.run(app, host="127.0.0.1", port=args.port, access_log=False)
        return 0
    except ImportError:
        raise NetworkCryptoError("network_http_dependency_unavailable") from None


if __name__ == "__main__":
    raise SystemExit(main())
