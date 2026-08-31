"""Real Python/TypeScript control interop, using synthetic in-memory keys only."""
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

from memory_vault import canonical_bytes
from memory_vault_trust import Identity
import memory_vault_network_crypto as crypto
import memory_vault_network_control as control


DRIVER = r"""
import * as api from './control.ts';
import * as crypto from './crypto.ts';
const inputValue = item => item.raw === undefined ? item.value : Buffer.from(item.raw, 'base64url');
const capture = operation => {
  try { return { ok: true, result: operation() }; }
  catch (error) { return { ok: false, error: error instanceof crypto.NetworkCryptoError ? error.code : 'unexpected_error' }; }
};
async function run(item) {
  if (item.op === 'roster') return api.verifyRoster(inputValue(item), item.options);
  if (item.op === 'status') return api.verifyStatus(inputValue(item), item.options);
  if (item.op === 'member') return api.validateMember(inputValue(item));
  if (item.op === 'current') {
    const current = api.verifyCurrentRoster(item.roster, item.status, item.options);
    const results = (item.authorize || []).map(action => capture(() => api.authorizedMember(
      action.copy ? JSON.parse(JSON.stringify(current)) : current, action.key_id, action.action,
      { now: action.now, expected_identity: action.expected_identity })));
    const immutable = Object.isFrozen(current) && Object.isFrozen(current.roster.payload.members[0].scope);
    return { current, authorized: results, immutable };
  }
  if (item.op === 'invite') return api.verifyInvite(inputValue(item), item.options);
  if (item.op === 'invitation') {
    const options = { ...item.options };
    if (item.current) options.current = api.verifyCurrentRoster(item.current.roster, item.current.status, item.current.options);
    const result = await api.verifyInvitationPackage(item.value, options);
    return { ...result, handoff_plaintext: result.handoff_plaintext === null ? null : Buffer.from(result.handoff_plaintext).toString('base64url') };
  }
  if (item.op === 'sign-request') return api.signRequest(item.options);
  if (item.op === 'request') return api.verifyRequest(inputValue(item), item.options);
  if (item.op === 'challenge') return { answer: await api.openJoinChallenge(inputValue(item), item.options) };
  if (item.op === 'join-proof') return api.verifyJoinProof(item.request, item.invite, item.options);
  throw Error('unknown fixture operation');
}
const chunks = []; let size = 0;
for await (const chunk of process.stdin) {
  size += chunk.length; if (size > 24 * 1024 * 1024) throw Error('fixture input limit'); chunks.push(chunk);
}
const requests = JSON.parse(Buffer.concat(chunks).toString('utf8')), results = [];
for (const item of requests) {
  try { results.push({ ok: true, result: await run(item) }); }
  catch (error) { results.push({ ok: false, error: error instanceof crypto.NetworkCryptoError ? error.code : 'unexpected_error' }); }
}
process.stdout.write(JSON.stringify(results));
"""


class TypeScriptControlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.node = shutil.which("node")
        if cls.node is None:
            raise unittest.SkipTest("Node required for independent TS control verification")
        package = ROOT / "clients/typescript/network/node_modules/jose"
        selected = os.environ.get("MEMORY_VAULT_JOSE_MODULE")
        if selected:
            entry = Path(selected).expanduser().resolve()
            if entry.parts[-3:] != ("dist", "webapi", "index.js"):
                raise RuntimeError("Expected explicit jose/dist/webapi/index.js")
            package = entry.parents[2]
        if not (package / "package.json").is_file():
            raise unittest.SkipTest("Existing jose 6.2.10 required; no dependency installed by this test")
        metadata = json.loads((package / "package.json").read_text())
        if metadata.get("name") != "jose" or metadata.get("version") != "6.2.10":
            raise RuntimeError("Test requires locked jose 6.2.10")
        cls.temporary = tempfile.TemporaryDirectory(prefix="memory-vault-ts-control-synthetic-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.fixture = Path(cls.temporary.name)
        for name in ("crypto.ts", "control.ts", "package.json"):
            shutil.copyfile(ROOT / "clients/typescript/network" / name, cls.fixture / name)
        (cls.fixture / "node_modules").mkdir()
        (cls.fixture / "node_modules/jose").symlink_to(package, target_is_directory=True)
        (cls.fixture / "driver.mjs").write_text(DRIVER)

    @staticmethod
    def signing() -> Identity:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        return Identity(Ed25519PrivateKey.generate())

    @staticmethod
    def secret(identity: Identity) -> dict:
        from cryptography.hazmat.primitives import serialization
        secret = identity._private_key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        return {**identity.public_descriptor(), "schema_version": "universal-memory-identity/v1",
                "private_key": base64.b64encode(secret).decode("ascii")}

    def setUp(self) -> None:
        self.issuer, self.owner, self.candidate = self.signing(), self.signing(), self.signing()
        self.owner_encryption, self.candidate_encryption = crypto.EncryptionIdentity.generate(), crypto.EncryptionIdentity.generate()
        self.now = 2_000_000_000
        self.network = "synthetic-control-network"
        self.nonce = "synthetic-fresh-challenge-001"
        self.members = [
            {"signing_key": self.owner.public_descriptor(), "encryption_key": self.owner_encryption.public_descriptor(),
             "status": "active", "scope": ["receive", "send"]},
            {"signing_key": self.candidate.public_descriptor(), "encryption_key": self.candidate_encryption.public_descriptor(),
             "status": "active", "scope": ["receive", "send"]},
        ]
        self.issuers = crypto.PublicKeyTrust([self.issuer.public_descriptor()])
        self.options = {"issuers": [self.issuer.public_descriptor()], "network_id": self.network, "now": self.now}
        self.roster = self.make_roster()
        self.status = self.make_status(self.roster)
        self.local = {"signing_key": self.candidate.public_descriptor(), "encryption_key": self.candidate_encryption.public_descriptor()}
        self.current_options = {**self.options, "nonce": self.nonce, "local_identity": self.local}

    def make_roster(self, *, version: int = 1, previous: str = "0" * 64, members: list | None = None,
                    issued: int | None = None, expires: int | None = None) -> dict:
        start = self.now - 10 if issued is None else issued
        return control.issue_roster(self.issuer, network_id=self.network, version=version, previous_sha256=previous,
                                    members=self.members if members is None else members,
                                    issued_at=start, expires_at=start + 300 if expires is None else expires)

    def make_status(self, roster: dict, *, nonce: str | None = None, issued: int | None = None,
                    expires: int | None = None) -> dict:
        start = self.now if issued is None else issued
        return control.issue_status(self.issuer, network_id=self.network, nonce=self.nonce if nonce is None else nonce,
                                    roster_sha256=crypto.document_sha256(roster), roster_version=roster["payload"]["version"],
                                    issued_at=start, expires_at=start + 300 if expires is None else expires)

    def signed(self, payload: dict, signer: Identity | None = None) -> dict:
        return {"payload": payload, "proof": (signer or self.issuer).sign_message(payload)}

    def run_ts(self, *requests: dict) -> list[dict]:
        result = subprocess.run([self.node, "--experimental-strip-types", str(self.fixture / "driver.mjs")],
                                input=json.dumps(requests, ensure_ascii=True).encode(), capture_output=True,
                                timeout=60, cwd=self.fixture)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace")[-2000:])
        output = json.loads(result.stdout)
        self.assertEqual(len(output), len(requests))
        return output

    def success(self, request: dict):
        result, = self.run_ts(request)
        self.assertTrue(result["ok"], result.get("error"))
        return result["result"]

    def rejected(self, requests: list[dict]) -> list[dict]:
        results = self.run_ts(*requests)
        for index, result in enumerate(results):
            self.assertFalse(result["ok"], f"fixture {index} was accepted")
            self.assertNotEqual(result["error"], "unexpected_error", f"fixture {index} did not produce a controlled failure")
        return results

    def current(self, roster: dict | None = None, **options) -> dict:
        selected = self.roster if roster is None else roster
        return {"op": "current", "roster": selected, "status": self.make_status(selected),
                "options": {**self.current_options, **options}}

    def invitation(self, handoff: dict | None = None, *, expires: int | None = None) -> dict:
        return control.issue_invite(self.issuer, network_id=self.network, invite_id="synthetic-invitation",
                                    candidate_signing_key=self.candidate.public_descriptor(),
                                    candidate_encryption_key=self.candidate_encryption.public_descriptor(),
                                    scope=["receive", "send"],
                                    handoff_sha256=hashlib.sha256(b"").hexdigest() if handoff is None else crypto.document_sha256(handoff),
                                    roster_sha256=crypto.document_sha256(self.roster), issued_at=self.now - 10,
                                    expires_at=self.now + 600 if expires is None else expires)

    def test_current_nonce_status_window_and_immutable_authorization(self) -> None:
        expired = self.make_roster(issued=self.now - 600, expires=self.now - 300)
        self.rejected([{"op": "roster", "value": expired, "options": self.options}])
        command = self.current(expired)
        command["authorize"] = [
            {"key_id": self.candidate.key_id, "action": "receive", "now": self.now, "expected_identity": self.local},
            {"key_id": self.candidate.key_id, "action": "receive", "now": self.now + 300},
            {"key_id": self.candidate.key_id, "action": "receive", "now": self.now, "copy": True},
        ]
        accepted = self.success(command)
        self.assertTrue(accepted["immutable"])
        self.assertEqual(accepted["current"]["roster_sha256"], crypto.document_sha256(expired))
        self.assertTrue(accepted["authorized"][0]["ok"])
        self.assertEqual(accepted["authorized"][1]["error"], "network_control_expired")
        self.assertEqual(accepted["authorized"][2]["error"], "network_verified_control_required")
        # The actual Python contract also accepts an expired, still-current
        # roster only when a separate fresh nonce status matches its signed hash.
        verified = control.verify_roster(expired, self.issuers, network_id=self.network, now=self.now, allow_expired=True)
        control.verify_status(command["status"], self.issuers, network_id=self.network, nonce=self.nonce,
                              roster_sha256=crypto.document_sha256(expired), roster_version=verified["version"], now=self.now)
        negative = []
        for payload in [
            {**self.status["payload"], "nonce": "old-nonce"},
            {**self.status["payload"], "roster_sha256": "f" * 64},
            {**self.status["payload"], "roster_version": 2},
            {**self.status["payload"], "issued_at": self.now - 300, "expires_at": self.now},
            {**self.status["payload"], "expires_at": self.now + 301},
            {**self.status["payload"], "issued_at": self.now + 31, "expires_at": self.now + 300},
        ]:
            negative.append({**self.current(), "status": self.signed(payload)})
        self.rejected(negative)
        self.success({**self.current(), "status": self.make_status(self.roster, issued=self.now + 30, expires=self.now + 300)})

    def test_issuer_trust_and_signed_malicious_roster_validation(self) -> None:
        roster_payload = self.roster["payload"]
        negative = [{"op": "roster", "value": self.signed(roster_payload, self.owner), "options": self.options}]
        for changed in [
            {**roster_payload, "network_id": "wrong"}, {**roster_payload, "schema_version": "wrong/v1"},
            {**roster_payload, "version": 0}, {**roster_payload, "version": 2},
            {**roster_payload, "version": 9007199254740992}, {**roster_payload, "version": True},
            {**roster_payload, "previous_sha256": "a" * 64}, {**roster_payload, "members": []},
            {**roster_payload, "members": list(reversed(roster_payload["members"]))},
            {**roster_payload, "members": [roster_payload["members"][0]] * 2},
            {**roster_payload, "members": [roster_payload["members"][0]] * 257},
            {**roster_payload, "expires_at": roster_payload["issued_at"]},
            {**roster_payload, "expires_at": roster_payload["issued_at"] + 301}, {**roster_payload, "extra": 1},
        ]:
            negative.append({"op": "roster", "value": self.signed(changed), "options": self.options})
        for patch in [
            {"scope": ["send", "receive"]}, {"scope": ["send", "send"]}, {"scope": []},
            {"scope": ["execute"]}, {"status": "pending"}, {"extra": 1},
            {"encryption_key": roster_payload["members"][1]["encryption_key"]},
            {"signing_key": self.candidate_encryption.public_descriptor()},
        ]:
            altered = copy.deepcopy(roster_payload)
            altered["members"][0].update(patch)
            negative.append({"op": "roster", "value": self.signed(altered), "options": self.options})
        raw = canonical_bytes(self.roster)
        negative.append({"op": "roster", "raw": crypto.b64url(raw[:-1] + b',"payload":{}}'), "options": self.options})
        self.assertEqual(self.rejected(negative)[-1]["error"], "duplicate_json_key")
        largest = self.make_roster(version=9007199254740991, previous="1" * 64)
        self.assertEqual(self.success({"op": "roster", "value": largest, "options": self.options})["version"], 9007199254740991)
        members = copy.deepcopy(self.members)
        while len(members) < control.MAX_MEMBERS:
            members.append({"signing_key": self.signing().public_descriptor(),
                            "encryption_key": crypto.EncryptionIdentity.generate().public_descriptor(),
                            "status": "active", "scope": ["receive"]})
        maximum = self.make_roster(members=members)
        self.assertEqual(len(self.success({"op": "roster", "value": maximum, "options": self.options})["members"]), control.MAX_MEMBERS)

    def test_fork_rollback_contiguous_chain_recovery_and_fresh_gap(self) -> None:
        previous_hash = crypto.document_sha256(self.roster)
        second = self.make_roster(version=2, previous=previous_hash)
        self.success(self.current(second, previous_roster=self.roster))
        self.success(self.current(self.roster, previous_roster=self.roster))
        fork = self.make_roster(issued=self.now - 9)
        bad_chain = self.make_roster(version=2, previous="b" * 64)
        recovered = {"minimum_roster_version": 1, "last_verified_roster": self.roster, "last_roster_sha256": previous_hash}
        self.success(self.current(second, recovery_anchor=recovered))
        self.success(self.current(recovery_anchor={"minimum_roster_version": 0, "last_verified_roster": None, "last_roster_sha256": None}))
        errors = self.rejected([
            self.current(self.roster, previous_roster=second), self.current(fork, previous_roster=self.roster),
            self.current(bad_chain, previous_roster=self.roster), self.current(fork, recovery_anchor=recovered),
            self.current(bad_chain, recovery_anchor=recovered),
            self.current(recovery_anchor={**recovered, "last_roster_sha256": "0" * 64}),
            self.current(recovery_anchor={**recovered, "minimum_roster_version": 2}),
        ])
        self.assertEqual(errors[0]["error"], "network_roster_rollback")
        self.assertEqual(errors[2]["error"], "network_roster_chain_mismatch")
        self.assertEqual(errors[3]["error"], "network_recovery_roster_rollback")
        # Matches the Python client's explicit branch: a >1 version gap is
        # authenticated by fresh issuer status, not a fabricated full hash chain.
        third = self.make_roster(version=3, previous="c" * 64)
        self.success(self.current(third, previous_roster=self.roster, recovery_anchor=recovered))

    def test_revocation_scopes_and_exact_local_dual_keys(self) -> None:
        members = copy.deepcopy(self.members)
        members[1]["status"] = "revoked"
        revoked = self.make_roster(version=2, previous=crypto.document_sha256(self.roster), members=members)
        self.rejected([self.current(revoked)])
        result = self.success(self.current(revoked, local_identity={"signing_key": self.owner.public_descriptor(),
                                                                  "encryption_key": self.owner_encryption.public_descriptor()}) |
                              {"authorize": [{"key_id": self.candidate.key_id, "action": "receive", "now": self.now}]})
        self.assertEqual(result["authorized"][0]["error"], "network_receive_scope_denied")
        members[1]["status"] = "active"
        members[1]["scope"] = ["receive"]
        scoped = self.make_roster(version=2, previous=crypto.document_sha256(self.roster), members=members)
        result = self.success(self.current(scoped) | {"authorize": [
            {"key_id": self.candidate.key_id, "action": "receive", "now": self.now},
            {"key_id": self.candidate.key_id, "action": "send", "now": self.now},
            {"key_id": self.candidate.key_id, "action": "receive", "now": self.now,
             "expected_identity": {**self.local, "encryption_key": self.owner_encryption.public_descriptor()}},
        ]})
        self.assertTrue(result["authorized"][0]["ok"])
        self.assertEqual(result["authorized"][1]["error"], "network_send_scope_denied")
        self.assertEqual(result["authorized"][2]["error"], "network_identity_not_active")
        self.rejected([self.current(local_identity={**self.local, "encryption_key": self.owner_encryption.public_descriptor()})])

    def test_typescript_signed_requests_verified_by_python_and_reverse(self) -> None:
        body = {"nonce": self.nonce, "unicode": "中文😀e\u0301\u2028\u2029", "small": -9007199254740991, "large": 9007199254740991}
        base = {"signer": self.secret(self.candidate), "network_id": self.network, "request_id": "req-synthetic-control",
                "body": body, "issued_at": self.now, "expires_at": self.now + 60}
        results = self.run_ts(*[{"op": "sign-request", "options": {**base, "action": action}} for action in ("join", "messages", "poll", "ack", "status")])
        peers = crypto.PublicKeyTrust([self.candidate.public_descriptor()])
        for result in results:
            self.assertTrue(result["ok"], result.get("error"))
            request = result["result"]
            checked = control.verify_request(request, peers, network_id=self.network, now=self.now)
            self.assertEqual(canonical_bytes(checked["body"]), canonical_bytes(body))
        python = control.sign_request(self.candidate, network_id=self.network, action="status", request_id="req-python",
                                      body=body, issued_at=self.now, expires_at=self.now + 60)
        options = {"network_id": self.network, "peers": [self.candidate.public_descriptor()], "action": "status", "now": self.now}
        self.assertEqual(self.success({"op": "request", "value": python, "options": options}), python["payload"])
        invalid = []
        for patch in ({"action": "execute"}, {"request_id": "bad id"}, {"network_id": "wrong"},
                      {"expires_at": self.now + 301}, {"expires_at": self.now}, {"body": []}, {"extra": True}):
            invalid.append({"op": "request", "value": self.signed({**python["payload"], **patch}, self.candidate), "options": options})
        invalid.append({"op": "request", "value": self.signed(python["payload"], self.owner), "options": options})
        invalid.extend([{ "op": "sign-request", "options": {**base, "action": "status", **patch}} for patch in
                        ({"action": "execute"}, {"expires_at": self.now + 301}, {"body": {"x": "x" * (control.MAX_CONTROL_BYTES // 2)}})])
        self.rejected(invalid)

    def test_invitation_dual_key_roster_handoff_and_current_binding(self) -> None:
        invite = self.invitation()
        options = {**self.options, "local_identity": self.local, "encryption_identity": self.candidate_encryption.private_document()}
        command = {"op": "invitation", "value": {"invite": invite, "roster": self.roster}, "options": options,
                   "current": {"roster": self.roster, "status": self.status, "options": self.current_options}}
        self.assertIsNone(self.success(command)["handoff_plaintext"])
        data = b'opaque handoff bytes\x00\xff' + b'{"n":18446744073709551615}'
        handoff = crypto.seal(data, signer=self.owner, network_id=self.network, message_id="synthetic-handoff",
                              recipients=[{"signing_key_id": self.candidate.key_id, "encryption_key": self.candidate_encryption.public_descriptor()}],
                              roster_version=1, roster_sha256=crypto.document_sha256(self.roster), created_at=self.now)
        with_handoff = {**command, "value": {"invite": self.invitation(handoff), "roster": self.roster, "handoff": handoff}}
        accepted = self.success(with_handoff)
        self.assertEqual(crypto.unb64url(accepted["handoff_plaintext"], maximum=4096), data)
        negative = [
            {**command, "options": {**options, "local_identity": {**self.local, "encryption_key": self.owner_encryption.public_descriptor()}}},
            {**command, "value": {"invite": invite, "roster": self.make_roster(issued=self.now - 9)}},
            {**with_handoff, "value": {**with_handoff["value"], "invite": invite}},
            {**with_handoff, "options": {**options, "encryption_identity": self.owner_encryption.private_document()}},
            {**command, "value": {"invite": self.signed(invite["payload"], self.owner), "roster": self.roster}},
            {**command, "value": {"invite": self.invitation(expires=self.now), "roster": self.roster}},
        ]
        members = copy.deepcopy(self.members)
        members[1]["scope"] = ["receive"]
        changed = self.make_roster(version=2, previous=crypto.document_sha256(self.roster), members=members)
        negative.append({**command, "current": {"roster": changed, "status": self.make_status(changed), "options": self.current_options}})
        for patch in ({"scope": ["execute"]}, {"expires_at": invite["payload"]["issued_at"] + 7 * 86400 + 1}, {"extra": True}):
            negative.append({"op": "invite", "value": self.signed({**invite["payload"], **patch}), "options": self.options})
        self.rejected(negative)

    def test_python_challenge_typescript_answer_and_join_signature(self) -> None:
        invite = self.invitation()
        challenge, answer = control.create_join_challenge(invite["payload"], challenge_id="synthetic-join-challenge",
                                                          issued_at=self.now, expires_at=self.now + 60)
        options = {"network_id": self.network, "invite_id": invite["payload"]["invite_id"], "now": self.now,
                   "identity": self.candidate_encryption.private_document()}
        opened = self.success({"op": "challenge", "value": challenge, "options": options})
        self.assertEqual(opened["answer"], answer)
        body = {"invite_sha256": crypto.document_sha256(invite), "challenge_id": challenge["challenge_id"], "challenge_answer": answer}
        request = self.success({"op": "sign-request", "options": {"signer": self.secret(self.candidate),
                               "network_id": self.network, "action": "join", "request_id": "req-join-synthetic", "body": body,
                               "issued_at": self.now, "expires_at": self.now + 60}})
        join_options = {**self.options, "challenge_id": challenge["challenge_id"], "invite_sha256": crypto.document_sha256(invite),
                        "answer_sha256": hashlib.sha256(answer.encode("ascii")).hexdigest()}
        control.verify_join_proof(request, invite["payload"], **{key: value for key, value in join_options.items() if key not in {"issuers", "network_id"}})
        self.success({"op": "join-proof", "request": request, "invite": invite, "options": join_options})
        negative = [
            {"op": "challenge", "value": challenge, "options": {**options, "invite_id": "wrong"}},
            {"op": "challenge", "value": challenge, "options": {**options, "identity": self.owner_encryption.private_document()}},
            {"op": "challenge", "value": challenge, "options": {**options, "now": self.now + 60}},
        ]
        for patch in ({"challenge_id": "wrong"}, {"answer_sha256": "0" * 64}, {"invite_sha256": "f" * 64},
                      {"answer_sha256": hashlib.sha256(crypto.unb64url(answer, maximum=32)).hexdigest()}):
            negative.append({"op": "join-proof", "request": request, "invite": invite, "options": {**join_options, **patch}})
        wrong_body = {**body, "challenge_answer": crypto.b64url(bytes(32))}
        wrong_request = control.sign_request(self.candidate, network_id=self.network, action="join", request_id="req-wrong-answer",
                                            body=wrong_body, issued_at=self.now, expires_at=self.now + 60)
        negative.append({"op": "join-proof", "request": wrong_request, "invite": invite, "options": join_options})
        self.rejected(negative)


if __name__ == "__main__":
    unittest.main()
