"""Independent TypeScript node verification of Python-signed synthetic wire data."""
from __future__ import annotations

import base64
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

from memory_vault_trust import Identity
from memory_vault_relay import Relay
import memory_vault_network_crypto as crypto
import memory_vault_network_control as control
import memory_vault_nodes as nodes

ROOT = Path(__file__).resolve().parents[1]
DRIVER = r"""
import * as api from './nodes.ts';
import * as crypto from './crypto.ts';
const input = item => item.raw === undefined ? item.value : Buffer.from(item.raw, 'base64url');
const capture = operation => {
  try { return { ok: true, result: operation() }; }
  catch (error) { return { ok: false, error: error instanceof crypto.NetworkCryptoError ? error.code : 'unexpected_error' }; }
};
function run(item) {
  if (item.op === 'directory') return api.verifyDirectory(input(item), item.options);
  if (item.op === 'node_status') return api.verifyNodeStatus(input(item), item.directory, item.roster, item.options);
  if (item.op === 'challenge') return api.verifyNodeChallenge(input(item), item.options);
  if (item.op === 'receipt') return api.verifyStorageReceipt(input(item), item.options);
  if (item.op === 'url') return api.validateNodeUrl(item.value);
  if (item.op === 'current') {
    const state = api.verifyCurrentNodes(input(item), item.options);
    const authorized = (item.authorize || []).map(action => capture(() => api.authorizedNode(
      action.copy ? JSON.parse(JSON.stringify(state.nodes)) : state.nodes,
      action.key_id, action.action, action.options)));
    return { state, authorized, immutable: state.nodes === null || (Object.isFrozen(state.nodes)
      && Object.isFrozen(state.nodes.directory.payload.nodes[0].scope)) };
  }
  throw Error('unknown synthetic operation');
}
const chunks = []; let size = 0;
for await (const chunk of process.stdin) {
  size += chunk.length; if (size > 24 * 1024 * 1024) throw Error('fixture input limit'); chunks.push(chunk);
}
const requests = JSON.parse(Buffer.concat(chunks).toString('utf8'));
process.stdout.write(JSON.stringify(requests.map(item => capture(() => run(item)))));
"""


class TypeScriptNodeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.node = shutil.which("node")
        if cls.node is None:
            raise unittest.SkipTest("Existing Node required for independent TypeScript verification")
        package = ROOT / "clients/typescript/network/node_modules/jose"
        selected = os.environ.get("MEMORY_VAULT_JOSE_MODULE")
        if selected:
            entry = Path(selected).expanduser().resolve()
            if entry.parts[-3:] != ("dist", "webapi", "index.js"):
                raise RuntimeError("Expected explicit jose/dist/webapi/index.js")
            package = entry.parents[2]
        if not (package / "package.json").is_file():
            raise unittest.SkipTest("Existing jose 6.2.10 required; this test never installs dependencies")
        metadata = json.loads((package / "package.json").read_bytes())
        if metadata.get("name") != "jose" or metadata.get("version") != "6.2.10":
            raise RuntimeError("Locked jose 6.2.10 required")
        cls.temporary = tempfile.TemporaryDirectory(prefix="memory-vault-ts-nodes-synthetic-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.fixture = Path(cls.temporary.name)
        for name in ("crypto.ts", "control.ts", "nodes.ts", "package.json"):
            shutil.copyfile(ROOT / "clients/typescript/network" / name, cls.fixture / name)
        (cls.fixture / "node_modules").mkdir()
        (cls.fixture / "node_modules/jose").symlink_to(package, target_is_directory=True)
        (cls.fixture / "driver.mjs").write_text(DRIVER)

    @staticmethod
    def signing():
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        return Identity(Ed25519PrivateKey.generate())

    def setUp(self):
        self.issuer, self.member, self.node_key, self.other_node_key = [self.signing() for _ in range(4)]
        self.now = 2_000_000_000
        self.network, self.nonce = "synthetic-ts-node-network", "synthetic-ts-node-nonce"
        self.node_entry = {"signing_key": self.node_key.public_descriptor(), "base_url": "http://127.0.0.1:18881",
                           "storage_epoch": "synthetic-node-epoch-001", "scope": ["export", "import", "node.status"], "status": "active"}
        self.other_entry = {**self.node_entry, "signing_key": self.other_node_key.public_descriptor(),
                            "base_url": "http://127.0.0.1:18882", "storage_epoch": "synthetic-node-epoch-002"}
        self.options = {"network_id": self.network, "issuers": [self.issuer.public_descriptor()], "now": self.now}
        self.roster = control.issue_roster(self.issuer, network_id=self.network, version=1, previous_sha256="0" * 64,
            members=[{"signing_key": self.member.public_descriptor(), "encryption_key": crypto.EncryptionIdentity.generate().public_descriptor(),
                      "status": "active", "scope": ["receive", "send"]}], issued_at=self.now - 10, expires_at=self.now + 290)
        self.directory = self.make_directory()
        self.response = self.make_response(self.directory)

    def signed(self, payload, signer=None):
        return {"payload": payload, "proof": (signer or self.issuer).sign_message(payload)}

    def make_directory(self, *, version=1, previous=None, entries=None, issued=None, expires=None):
        start = self.now - 10 if issued is None else issued
        return nodes.issue_directory(self.issuer, network_id=self.network, version=version,
            previous_sha256="0" * 64 if previous is None else crypto.document_sha256(previous),
            nodes=[self.node_entry] if entries is None else entries, issued_at=start,
            expires_at=start + 300 if expires is None else expires)

    def make_response(self, directory, *, roster=None, issued=None, nonce=None):
        roster = self.roster if roster is None else roster
        now = self.now if issued is None else issued
        nonce = self.nonce if nonce is None else nonce
        status = control.issue_status(self.issuer, network_id=self.network, nonce=nonce,
            roster_sha256=crypto.document_sha256(roster), roster_version=roster["payload"]["version"], issued_at=now, expires_at=now + 300)
        node_status = nodes.issue_node_status(self.issuer, network_id=self.network, nonce=nonce,
            roster_sha256=crypto.document_sha256(roster), roster_version=roster["payload"]["version"],
            directory_sha256=crypto.document_sha256(directory), directory_version=directory["payload"]["version"],
            issued_at=now, expires_at=now + 300)
        return {"status": status, "roster": roster, "nodes": directory, "node_status": node_status}

    def request(self, op, value, **options):
        return {"op": op, "value": value, "options": {**self.options, **options}}

    def run_ts(self, *requests):
        result = subprocess.run([self.node, "--experimental-strip-types", str(self.fixture / "driver.mjs")],
            input=json.dumps(requests, ensure_ascii=True).encode(), capture_output=True, timeout=30, cwd=self.fixture)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace")[-2000:])
        output = json.loads(result.stdout)
        self.assertEqual(len(output), len(requests))
        return output

    def success(self, request):
        result, = self.run_ts(request)
        self.assertTrue(result["ok"], result.get("error"))
        return result["result"]

    def rejected(self, requests):
        for result in self.run_ts(*requests):
            self.assertFalse(result["ok"], result)
            self.assertNotEqual(result["error"], "unexpected_error", result)

    def test_python_directory_and_replacement_tombstones_verify_without_member_rights(self):
        payload = self.success(self.request("directory", self.directory))
        self.assertEqual(payload, nodes.verify_directory(self.directory, crypto.PublicKeyTrust([self.issuer.public_descriptor()]),
                                                        network_id=self.network, now=self.now))
        self.assertNotIn(self.node_key.key_id, [m["signing_key"]["key_id"] for m in self.roster["payload"]["members"]])
        self.assertNotIn("encryption_key", payload["nodes"][0])
        revoked = {**self.node_entry, "status": "revoked"}
        replacement = {**self.other_entry, "base_url": self.node_entry["base_url"]}
        directory = self.make_directory(version=2, previous=self.directory, entries=[revoked, replacement])
        self.assertEqual(self.success(self.request("directory", directory, previous_directory=self.directory)), directory["payload"])
        jumped = self.make_directory(version=4, previous=directory, entries=[revoked, replacement])
        self.success(self.request("current", self.make_response(jumped), nonce=self.nonce, previous_directory=directory))
        empty = self.make_directory(entries=[])
        self.success(self.request("directory", empty))

    def test_directory_signatures_shape_limits_and_strict_json_reject_attacks(self):
        bad = []
        tampered = copy.deepcopy(self.directory)
        tampered["payload"]["nodes"][0]["storage_epoch"] = "attacker-epoch"
        bad.append(self.request("directory", tampered))
        bad.append(self.request("directory", self.signed(copy.deepcopy(self.directory["payload"]), self.node_key)))
        for field, value in (("network_id", "other-network"), ("version", 0), ("version", 2**53),
                             ("previous_sha256", "1" * 64), ("expires_at", self.now + 301),
                             ("nodes", [self.node_entry] * 257), ("nodes", [self.node_entry] * 2)):
            payload = copy.deepcopy(self.directory["payload"])
            payload[field] = value
            bad.append(self.request("directory", self.signed(payload)))
        for field, value in (("scope", ["send"]), ("scope", ["node.status", "export"]),
                             ("scope", ["export", "export"]), ("status", "pending"),
                             ("encryption_key", {"algorithm": "X25519"}), ("base_url", "http://example.invalid")):
            payload = copy.deepcopy(self.directory["payload"])
            payload["nodes"][0][field] = value
            bad.append(self.request("directory", self.signed(payload)))
        for entry in ({**self.other_entry, "storage_epoch": self.node_entry["storage_epoch"]},
                      {**self.other_entry, "base_url": self.node_entry["base_url"]}):
            payload = copy.deepcopy(self.directory["payload"])
            payload["nodes"] = sorted([self.node_entry, entry], key=lambda n: n["signing_key"]["key_id"])
            bad.append(self.request("directory", self.signed(payload)))
        raw = json.dumps(self.directory, separators=(",", ":"))
        raw = raw.replace('"network_id":', '"network_id":"duplicate", "network_id":', 1)
        bad.append({"op": "directory", "raw": base64.urlsafe_b64encode(raw.encode()).decode().rstrip("="), "options": self.options})
        self.rejected(bad)

    def test_directory_monotonicity_immutable_identity_and_revocation(self):
        later = self.make_directory(version=2, previous=self.directory, entries=[self.node_entry, self.other_entry])
        bad = [self.request("directory", self.directory, minimum_version=2),
               self.request("directory", self.directory, previous_directory=later),
               self.request("directory", later, expected_previous_sha256="f" * 64)]
        fork = copy.deepcopy(self.directory["payload"])
        fork["expires_at"] -= 1
        bad.append(self.request("directory", self.signed(fork), previous_directory=self.directory))
        for field, value in (("previous_sha256", "f" * 64), ("issued_at", self.now - 11), ("nodes", [])):
            payload = copy.deepcopy(later["payload"])
            payload[field] = value
            if field == "issued_at": payload["expires_at"] -= 1
            bad.append(self.request("directory", self.signed(payload), previous_directory=self.directory))
        for field, value in (("base_url", "https://other.synthetic.invalid"), ("storage_epoch", "other-epoch"),
                             ("signing_key", self.other_node_key.public_descriptor())):
            entry = {**self.node_entry, field: value}
            changed = self.make_directory(version=2, previous=self.directory, entries=[entry])
            bad.append(self.request("directory", changed, previous_directory=self.directory))
        for status in ("draining", "revoked"):
            previous = self.make_directory(version=2, previous=self.directory, entries=[{**self.node_entry, "status": status}])
            revived = self.make_directory(version=3, previous=previous)
            bad.append(self.request("directory", revived, previous_directory=previous))
        self.rejected(bad)

    def test_joint_status_freshness_downgrade_and_authorization_capability(self):
        expired_directory = self.make_directory(issued=self.now - 600, expires=self.now - 300)
        expired_roster = copy.deepcopy(self.roster["payload"])
        expired_roster.update(issued_at=self.now - 600, expires_at=self.now - 300)
        expired_roster = self.signed(expired_roster)
        response = self.make_response(expired_directory, roster=expired_roster)
        request = self.request("current", response, nonce=self.nonce)
        request["authorize"] = [
            {"key_id": self.node_key.key_id, "action": "refresh", "options": {"now": self.now}},
            {"key_id": self.node_key.key_id, "action": "import", "options": {"now": self.now}},
            {"key_id": self.node_key.key_id, "action": "export", "options": {"now": self.now + 300}},
            {"key_id": self.node_key.key_id, "action": "refresh", "options": {"now": self.now}, "copy": True},
            {"key_id": self.member.key_id, "action": "refresh", "options": {"now": self.now}},
            {"key_id": self.node_key.key_id, "action": "receive", "options": {"now": self.now}},
        ]
        result = self.success(request)
        self.assertTrue(result["immutable"])
        self.assertEqual([r["ok"] for r in result["authorized"]], [True, True, False, False, False, False])
        legacy = {k: v for k, v in self.response.items() if k in {"status", "roster"}}
        self.assertIsNone(self.success(self.request("current", legacy, nonce=self.nonce))["state"]["nodes"])
        bad = [self.request("directory", expired_directory),
               self.request("current", legacy, nonce=self.nonce, previous_directory=self.directory),
               self.request("current", legacy, nonce=self.nonce, recovery_directory=self.directory),
               self.request("current", legacy, nonce=self.nonce, require_nodes=True),
               self.request("current", legacy, nonce=self.nonce, minimum_node_status_issued_at=self.now),
               self.request("current", self.response, nonce="wrong-nonce"),
               self.request("current", self.response, nonce=self.nonce, now=self.now + 300),
               self.request("current", self.response, nonce=self.nonce, minimum_node_status_issued_at=self.now + 1)]
        for field in ("node_status", "nodes"):
            partial = copy.deepcopy(self.response); partial.pop(field)
            bad.append(self.request("current", partial, nonce=self.nonce))
        for field in ("roster_sha256", "directory_sha256", "roster_version", "directory_version", "nonce"):
            modified = copy.deepcopy(self.response)
            value = modified["node_status"]["payload"]
            value[field] = value[field] + 1 if isinstance(value[field], int) else "f" * 64
            modified["node_status"] = self.signed(value)
            bad.append(self.request("current", modified, nonce=self.nonce))
        for field in ("status", "node_status"):
            modified = copy.deepcopy(self.response)
            modified[field] = self.signed(modified[field]["payload"], self.node_key)
            bad.append(self.request("current", modified, nonce=self.nonce))
        self.rejected(bad)

    def test_scopes_draining_and_revoked_nodes_are_not_members(self):
        requests = []
        for status, scopes in (("draining", ["export", "import", "node.status"]),
                               ("revoked", ["export", "import", "node.status"]), ("active", ["node.status"])):
            directory = self.make_directory(entries=[{**self.node_entry, "status": status, "scope": scopes}])
            request = self.request("current", self.make_response(directory), nonce=self.nonce)
            request["authorize"] = [{"key_id": self.node_key.key_id, "action": action, "options": {"now": self.now}}
                                    for action in ("refresh", "export", "import")]
            requests.append(request)
        result = self.run_ts(*requests)
        for row in result: self.assertTrue(row["ok"], row)
        self.assertEqual([[r["ok"] for r in row["result"]["authorized"]] for row in result],
                         [[True, True, False], [False, False, False], [True, False, False]])

    def test_real_python_storage_result_and_node_challenge_bind_every_field(self):
        descriptor = {k: self.node_entry[k] for k in ("signing_key", "base_url", "storage_epoch")}
        challenge_payload = {"schema_version": "memory-vault-node-challenge/v1", "network_id": self.network,
                             "node": descriptor, "nonce": self.nonce, "issued_at": self.now, "expires_at": self.now + 300}
        challenge = {"nonce": self.nonce, "expires_at": self.now + 300, "current_roster_version": 1,
                     "current_roster_sha256": crypto.document_sha256(self.roster),
                     "node_challenge": self.signed(challenge_payload, self.node_key)}
        challenge_options = {"node": self.node_entry, "nonce": self.nonce}
        self.assertEqual(self.success(self.request("challenge", challenge, **challenge_options)), descriptor)
        receipt = {"state": "stored", "message_id": "synthetic-message-001", "envelope_sha256": "a" * 64, "sequence": 3}
        # Invoke the actual Python response signer, without constructing Relay,
        # opening a database, creating a member, or starting any service.
        relay = SimpleNamespace(node_identity=self.node_key, network_id=self.network, node_descriptor=lambda: descriptor)
        response = Relay._stored_result(relay, receipt)
        receipt_options = {"node": descriptor, "message_id": receipt["message_id"], "envelope_sha256": receipt["envelope_sha256"]}
        self.assertEqual(self.success(self.request("receipt", response, **receipt_options)), receipt)
        bad = []
        for field, value in (("nonce", "another-nonce"), ("expires_at", self.now + 301)):
            changed = copy.deepcopy(challenge); changed[field] = value
            bad.append(self.request("challenge", changed, **challenge_options))
        for field, value in (("storage_epoch", "wrong-epoch"), ("base_url", "https://wrong.synthetic.invalid"),
                             ("signing_key", self.other_node_key.public_descriptor())):
            changed = copy.deepcopy(descriptor); changed[field] = value
            forged_challenge = copy.deepcopy(challenge_payload); forged_challenge["node"] = changed
            altered = {**challenge, "node_challenge": self.signed(forged_challenge, self.node_key)}
            bad.append(self.request("challenge", altered, **challenge_options))
            bad.append(self.request("receipt", response, **{**receipt_options, "node": changed}))
        missing = copy.deepcopy(challenge); missing.pop("node_challenge")
        bad.append(self.request("challenge", missing, **challenge_options))
        bad.append(self.request("challenge", challenge, **{**challenge_options, "now": self.now + 300}))
        bad.append(self.request("challenge", challenge, **{**challenge_options, "node": {**self.node_entry, "status": "revoked"}}))
        bad.append(self.request("challenge", {**challenge, "node_challenge": self.signed(challenge_payload, self.other_node_key)}, **challenge_options))
        for field, value in (("state", "validated_saved"), ("message_id", "other-message"),
                             ("envelope_sha256", "f" * 64), ("sequence", 4), ("sequence", 0), ("sequence", 2**53)):
            altered = copy.deepcopy(response); altered[field] = value
            bad.append(self.request("receipt", altered, **receipt_options))
        unsigned = copy.deepcopy(response); unsigned.pop("node_receipt")
        bad.append(self.request("receipt", unsigned, **receipt_options))
        forged = copy.deepcopy(response)
        forged["node_receipt"] = self.signed(forged["node_receipt"]["payload"], self.other_node_key)
        bad.append(self.request("receipt", forged, **receipt_options))
        self.rejected(bad)

    def test_urls_reject_insecure_aliases_and_preserve_signed_text(self):
        allowed = ["http://127.0.0.1:18881", "http://127.2.3.4", "http://localhost:1", "http://[::1]:65535",
                   "https://synthetic.example.invalid:443"]
        for result, value in zip(self.run_ts(*[{"op": "url", "value": value} for value in allowed]), allowed):
            self.assertTrue(result["ok"], result)
            self.assertEqual(result["result"], value)
        denied = ["http://127.1", "http://2130706433", "http://0177.0.0.1", "http://0.0.0.0",
                  "https://synthetic.invalid:", "https://synthetic.invalid:0", "https://synthetic.invalid:65536",
                  "https://synthetic.invalid:bad", "https://user@synthetic.invalid", "https://synthetic.invalid/",
                  "https://synthetic.invalid?", "https://synthetic.invalid#", "https://synthetic.invalid\\foo",
                  "https://synthetic.invalid \n", "https://" + "a" * 2050, "https://[127.0.0.1]"]
        self.rejected([{"op": "url", "value": value} for value in denied])


if __name__ == "__main__":
    unittest.main()
