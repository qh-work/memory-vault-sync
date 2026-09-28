"""Actual command recovery, private new-only output, and unchanged source keys."""
import base64
import contextlib
import hashlib
import io
import json
from pathlib import Path
import stat
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from memory_vault import canonical_bytes
from memory_vault_network_crypto import b64url, unb64url
from memory_vault_open_repair_admin import main, REQUEST_SCHEMA, EVIDENCE_SCHEMA
from memory_vault_open_setup import initialize_node
from memory_vault_trust import TrustStore, _write_new_private
from tests import test_open_repair_http as http_fixture


class RepairAdminTests(unittest.TestCase):
    def setUp(self):
        self.host = http_fixture.RepairHTTPTests()
        self.host.setUp()
        self.addCleanup(self.host.doCleanups)
        self.directory = Path(self.host.source.temp.name).resolve() / "synthetic-owner"
        self.directory.mkdir(mode=0o700)
        f = self.host.source.fixture
        owner = f["signers"]["owner"]
        secret = owner._private_key.private_bytes(serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw, serialization.NoEncryption())
        self.identity = self.directory / "identity.json"
        _write_new_private(self.identity, canonical_bytes({**owner.public_descriptor(),
            "schema_version": "universal-memory-identity/v1", "private_key": base64.b64encode(secret).decode()}))
        self.encryption = self.directory / "encryption.json"
        f["encryption"]["owner"].save(self.encryption)
        self.vault = self.directory / "vault" / "memory.sqlite3"
        self.trust = self.directory / "trust.json"
        TrustStore(self.trust).add(owner.public_descriptor())
        self.config = self.directory / "client.json"
        _write_new_private(self.config, canonical_bytes(dict(schema_version="memory-vault-client-config/v1",
            identity_path=str(self.identity), trust_path=str(self.trust),
            vault_path=str(self.vault), capture_visible_turns=False)))
        self.network = self.directory / "open.json"
        _write_new_private(self.network, canonical_bytes(dict(schema_version="memory-vault-open-client-config/v1",
            client_config_path=str(self.config), state_directory=str(self.directory / "transport"),
            encryption_key_path=str(self.encryption), seeds=[f["docs"]["descriptor"]], allow_loopback=True)))
        entries = f["entries"]
        self.request = dict(schema_version=REQUEST_SCHEMA, target=f["expected"]["expected_target"],
            ack_slot=f["expected"]["expected_ack_slot"], known_statuses=[],
            **{name: dict(raw_base64url=b64url(entries[role]["raw"]), ref=entries[role]["ref"])
               for name, role in (("node", "descriptor"), ("root", "root"), ("read", "read"), ("bootstrap", "bootstrap"))})
        self.request_path, self.output = self.directory / "request.json", self.directory / "evidence.json"
        self.originals = {path: path.read_bytes() for path in (self.identity, self.encryption, self.trust, self.config, self.network)}

    def call(self):
        _write_new_private(self.request_path, canonical_bytes(self.request))
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(["recover-ack", "--network-config", str(self.network), "--request", str(self.request_path),
                         "--output", str(self.output), "--timeout", "30"])
        return code, stdout.getvalue(), stderr.getvalue()

    def test_command_recovers_exact_originals_without_opening_vault_or_changing_identity(self):
        code, output, error = self.call()
        self.assertEqual((code, error), (0, ""))
        result = json.loads(output)
        saved = self.output.read_bytes()
        evidence = json.loads(saved)
        self.assertEqual(evidence["schema_version"], EVIDENCE_SCHEMA)
        self.assertEqual(result["state"], "ack_unbound_source_recovered")
        self.assertEqual(result["evidence_sha256"], hashlib.sha256(saved).hexdigest())
        self.assertFalse(result["recipient_saved"])
        self.assertFalse(result["vault_modified"])
        self.assertFalse(self.vault.exists())
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)
        self.assertEqual(len(evidence["originals"]), result["original_count"])
        self.assertGreater(result["requests"], 2)
        for entry in evidence["originals"]:
            raw = unb64url(entry["raw_base64url"], maximum=524288)
            self.assertEqual(raw, self.host.source.state.read_local_original(self.host.source.resource_id, entry["ref"]))
            self.assertEqual(hashlib.sha256(raw).hexdigest(), entry["ref"]["raw_sha256"])
        self.assertEqual({path: path.read_bytes() for path in self.originals}, self.originals)
        self.assertNotIn(b'"private_key"', saved)

    def test_existing_output_is_preserved_before_network_access(self):
        _write_new_private(self.output, b"synthetic existing evidence\n")
        code, output, error = self.call()
        self.assertEqual((code, output), (1, ""))
        self.assertEqual(json.loads(error)["error"], "repair_output_exists")
        self.assertEqual(self.output.read_bytes(), b"synthetic existing evidence\n")
        self.assertFalse((self.directory / "transport").exists())

    def test_corrupted_root_ref_produces_no_output_or_probe(self):
        self.request["root"]["ref"] = dict(self.request["root"]["ref"], raw_sha256="0" * 64)
        code, output, error = self.call()
        self.assertEqual((code, output), (1, ""))
        self.assertEqual(json.loads(error)["error"], "repair_ref_mismatch")
        self.assertFalse(self.output.exists())
        self.assertEqual(self.host.source.db.execute("SELECT count(*) FROM open_repair_bootstrap_challenges").fetchone()[0], 0)


class RepairSetupTests(unittest.TestCase):
    def test_new_node_can_explicitly_enable_finite_repair_and_lists_proxy_path(self):
        with tempfile.TemporaryDirectory(prefix="synthetic-repair-setup-") as temporary:
            directory = Path(temporary).resolve() / "node"
            result = initialize_node(directory, base_url="https://synthetic-node.example", enable_repair=True)
            config = json.loads(Path(result["config_path"]).read_bytes())
            self.assertIs(config["repair_policy"]["enabled"], True)
            self.assertEqual(config["repair_policy"]["limit_policy"]["max_signature_checks"], 512)
            self.assertIn("/open/v1/repair/bootstrap", result["https_paths"])
            self.assertFalse(result["network_started"])
            self.assertFalse((directory / "state" / "network.sqlite3").exists())


if __name__ == "__main__":
    unittest.main()
