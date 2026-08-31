"""Small real-crypto acceptance fixture; synthetic keys only, no cloud calls.

Optional independent Node/jose interop is enabled with MEMORY_VAULT_JOSE_MODULE
pointing at an explicitly installed jose/dist/webapi/index.js. No dependency is
installed and no real identity is discovered by this fixture.
"""
from __future__ import annotations

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
import unittest

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from memory_vault import MemoryError, canonical_bytes
from memory_vault_trust import Identity, TrustStore, _write_new_private
import memory_vault_network_crypto as crypto
import memory_vault_network_control as control


class NetworkCryptoTests(unittest.TestCase):
    def test_real_crypto_control_and_optional_independent_interop(self) -> None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        issuer = Identity(Ed25519PrivateKey.generate())
        sender = Identity(Ed25519PrivateKey.generate())
        candidate = Identity(Ed25519PrivateKey.generate())
        first = crypto.EncryptionIdentity.generate()
        second = crypto.EncryptionIdentity.generate()
        strangers = crypto.EncryptionIdentity.generate()
        trust = crypto.PublicKeyTrust([sender.public_descriptor()])
        issuers = crypto.PublicKeyTrust([issuer.public_descriptor()])
        now = int(time.time())
        data = (b'unchanged canonical memory bytes\x00\xff'
                + '跨模型记忆'.encode()
                + b'{"signed_min":-9223372036854775808,"unsigned_max":18446744073709551615}')
        context = {"schema_version": "synthetic-backup/v1", "object_id": "synthetic-object"}
        jwe = crypto.encrypt_bytes(data, [first.public_descriptor(), second.public_descriptor()], context=context)
        self.assertEqual(crypto.decrypt_bytes(jwe, first, context=context), data)
        self.assertEqual(crypto.decrypt_bytes(jwe, second, context=context), data)
        self.assertNotIn(hashlib.sha256(data).hexdigest().encode(), canonical_bytes(jwe))
        with self.assertRaises(MemoryError):
            crypto.decrypt_bytes(jwe, strangers, context=context)
        with self.assertRaises(MemoryError):
            crypto.decrypt_bytes(jwe, first, context={**context, "object_id": "different"})
        damaged = copy.deepcopy(jwe)
        ciphertext = bytearray(crypto.unb64url(damaged["ciphertext"], maximum=crypto.MAX_PLAINTEXT_BYTES + 4096))
        ciphertext[-1] ^= 1
        damaged["ciphertext"] = crypto.b64url(bytes(ciphertext))
        with self.assertRaises(MemoryError):
            crypto.decrypt_bytes(damaged, first, context=context)
        wrong_alg = copy.deepcopy(jwe)
        wrong_alg["recipients"][0]["header"]["alg"] = "dir"
        with self.assertRaises(MemoryError):
            crypto.decrypt_bytes(wrong_alg, first, context=context)
        zipped = copy.deepcopy(jwe)
        zipped["protected"] = crypto.b64url(canonical_bytes({"enc": crypto.ENC, "typ": crypto.BYTES_SCHEMA, "zip": "DEF"}))
        with self.assertRaises(MemoryError):
            crypto.decrypt_bytes(zipped, first, context=context)
        with self.assertRaises(MemoryError):
            crypto.document(b'{"same":1,"same":2}')
        # Provider's default 64-KiB ceiling must not accidentally break normal
        # four-MiB sync fragments; the explicit carrier budget is exercised.
        maximum = b"s" * crypto.MAX_PLAINTEXT_BYTES
        large = crypto.encrypt_bytes(maximum, [first.public_descriptor()], context=context)
        self.assertLessEqual(len(canonical_bytes(large)), crypto.MAX_ENVELOPE_BYTES)
        self.assertEqual(crypto.decrypt_bytes(large, first, context=context), maximum)

        members = [
            {"signing_key": sender.public_descriptor(), "encryption_key": first.public_descriptor(), "status": "active", "scope": ["receive", "send"]},
            {"signing_key": candidate.public_descriptor(), "encryption_key": second.public_descriptor(), "status": "active", "scope": ["receive", "send"]},
        ]
        roster = control.issue_roster(issuer, network_id="synthetic-network", version=1, previous_sha256="0" * 64,
                                      members=members, issued_at=now, expires_at=now + 300)
        roster_hash = crypto.document_sha256(roster)
        verified = control.verify_roster(roster, issuers, network_id="synthetic-network", now=now)
        self.assertEqual(verified["version"], 1)
        with self.assertRaises(MemoryError):
            control.verify_roster(roster, issuers, network_id="synthetic-network", minimum_version=2, now=now)
        invite = control.issue_invite(issuer, network_id="synthetic-network", invite_id="synthetic-invitation",
                                      candidate_signing_key=candidate.public_descriptor(), candidate_encryption_key=second.public_descriptor(),
                                      scope=["receive", "send"], handoff_sha256="a" * 64, roster_sha256=roster_hash,
                                      issued_at=now, expires_at=now + 600)
        admitted = control.verify_invite(invite, issuers, network_id="synthetic-network", now=now)
        with self.assertRaises(MemoryError):
            control.verify_invite(invite, trust, network_id="synthetic-network", now=now)
        challenge, answer = control.create_join_challenge(admitted, challenge_id="synthetic-challenge", issued_at=now, expires_at=now + 60)
        self.assertEqual(control.open_join_challenge(challenge, second, network_id="synthetic-network", invite_id="synthetic-invitation", now=now), answer)
        request = control.sign_request(candidate, network_id="synthetic-network", action="join", request_id="synthetic-join",
                                       body={"invite_sha256": crypto.document_sha256(invite), "challenge_id": "synthetic-challenge", "challenge_answer": answer},
                                       issued_at=now, expires_at=now + 60)
        control.verify_join_proof(request, admitted, challenge_id="synthetic-challenge", invite_sha256=crypto.document_sha256(invite),
                                  answer_sha256=hashlib.sha256(answer.encode("ascii")).hexdigest(), now=now)
        with self.assertRaises(MemoryError):
            control.verify_join_proof(request, admitted, challenge_id="synthetic-challenge", invite_sha256=crypto.document_sha256(invite),
                                      answer_sha256="0" * 64, now=now)
        status = control.issue_status(issuer, network_id="synthetic-network", nonce="synthetic-nonce", roster_sha256=roster_hash,
                                      roster_version=1, issued_at=now, expires_at=now + 300)
        control.verify_status(status, issuers, network_id="synthetic-network", nonce="synthetic-nonce", roster_sha256=roster_hash, roster_version=1, now=now)
        with self.assertRaises(MemoryError):
            control.verify_status(status, issuers, network_id="synthetic-network", nonce="different-nonce", now=now)
        with self.assertRaises(MemoryError):
            control.verify_status(status, issuers, network_id="synthetic-network", nonce="synthetic-nonce", now=now + 301)
        envelope = crypto.seal(data, signer=sender, network_id="synthetic-network", message_id="synthetic-message",
                               recipients=[{"signing_key_id": sender.key_id, "encryption_key": first.public_descriptor()},
                                           {"signing_key_id": candidate.key_id, "encryption_key": second.public_descriptor()}],
                               roster_version=1, roster_sha256=roster_hash, created_at=now)
        self.assertEqual(crypto.open_envelope(envelope, second, trust, network_id="synthetic-network"), data)
        altered = copy.deepcopy(envelope)
        altered["recipient_key_ids"].reverse()
        with self.assertRaises(MemoryError):
            crypto.verify_envelope(altered, trust, network_id="synthetic-network")
        key = control.generate_recovery_secret()
        recovery = control.export_recovery({"encryption_identity": second.private_document(), "last_roster_sha256": roster_hash},
                                            recovery_secret=key, network_id="synthetic-network", created_at=now)
        recovered = control.import_recovery(recovery, recovery_secret=key, network_id="synthetic-network")
        self.assertTrue(recovered["activation_disabled"])
        self.assertTrue(recovered["requires_fresh_issuer_status"])
        with self.assertRaises(MemoryError):
            control.import_recovery(recovery, recovery_secret=control.generate_recovery_secret(), network_id="synthetic-network")

        # The optional authority rejects anonymous/unknown callers. This is an
        # in-process ASGI request, not a listening server or network operation.
        from starlette.testclient import TestClient
        with tempfile.TemporaryDirectory(prefix="network-crypto-synthetic-") as temporary:
            root = Path(temporary).resolve()
            identity_path = root / "issuer.json"
            signing_key = issuer._private_key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
            import base64
            _write_new_private(identity_path, canonical_bytes({**issuer.public_descriptor(), "schema_version": "universal-memory-identity/v1", "private_key": base64.b64encode(signing_key).decode("ascii")}))
            registry = TrustStore(root / "trust.json")
            registry.add(issuer.public_descriptor())
            _write_new_private(root / "roster.json", canonical_bytes(roster))
            _write_new_private(root / "authority.json", canonical_bytes({"schema_version": "memory-vault-network-authority-config/v1", "network_id": "synthetic-network",
                               "identity_path": str(identity_path), "trust_store_path": str(root / "trust.json"), "roster_path": str(root / "roster.json")}))
            with TestClient(control.create_authority_app(root / "authority.json")) as client:
                self.assertEqual(client.post("/v1/status", json={"network_id": "synthetic-network", "nonce": "synthetic-authority-nonce"}).status_code, 400)
                signed_request = control.sign_request(sender, network_id="synthetic-network", action="status", request_id="synthetic-status-request",
                                                       body={"nonce": "synthetic-authority-nonce"}, issued_at=now, expires_at=now + 60)
                response = client.post("/v1/status", json={"network_id": "synthetic-network", "nonce": "synthetic-authority-nonce", "request": signed_request})
                self.assertEqual(response.status_code, 200)
                control.verify_status(response.json()["status"], issuers, network_id="synthetic-network", nonce="synthetic-authority-nonce", roster_sha256=roster_hash)

        module = os.environ.get("MEMORY_VAULT_JOSE_MODULE")
        node = shutil.which("node")
        if module:
            self.assertIsNotNone(node, "explicit independent interop requires Node")
            self.assertTrue(Path(module).is_file(), "explicit independent interop module is missing")
        if module and node:
            script = Path(__file__).resolve().parents[1] / "examples/network-interop/interop.ts"
            def interop(value: dict) -> dict:
                result = subprocess.run([node, "--experimental-strip-types", str(script)], input=canonical_bytes(value),
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15,
                                        env={"PATH": os.environ.get("PATH", ""), "MEMORY_VAULT_JOSE_MODULE": module})
                self.assertEqual(result.returncode, 0, "independent synthetic interop failed")
                return json.loads(result.stdout)
            opened = interop({"op": "open", "envelope": envelope, "signing_public": sender.public_descriptor(),
                              "identity": second.private_document(), "network_id": "synthetic-network"})
            self.assertEqual(crypto.unb64url(opened["plaintext"], maximum=crypto.MAX_PLAINTEXT_BYTES), data)
            route = {key: val for key, val in envelope.items() if key not in ("proof", "jwe")}
            secret = sender._private_key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
            public = sender._private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            sealed = interop({"op": "seal", "plaintext": crypto.b64url(data), "route": route,
                              "recipients": [first.public_descriptor(), second.public_descriptor()],
                              "signing_private_jwk": {"kty": "OKP", "crv": "Ed25519", "x": crypto.b64url(public), "d": crypto.b64url(secret)}})
            self.assertEqual(crypto.open_envelope(sealed["envelope"], first, trust, network_id="synthetic-network"), data)


if __name__ == "__main__":
    unittest.main()
