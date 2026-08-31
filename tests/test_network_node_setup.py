"""Synthetic storage-node registration does not create agent permissions."""
from __future__ import annotations

from pathlib import Path
import copy
import os
import subprocess
import sys
import tempfile
import time
import unittest

from memory_vault import MemoryError, canonical_bytes, strict_json_loads
from memory_vault_network_admin import initialize, initialize_node, authorize_node
from memory_vault_network_control import create_authority_app
from memory_vault_network_crypto import document_sha256
from memory_vault_nodes import issue_directory
from memory_vault_node import refresh
from memory_vault_relay import Relay
from memory_vault_storage import atomic_write
from memory_vault_trust import Identity, TrustError


class NodeSetupTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="memory-node-setup-synthetic-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.owner = self.root / "owner"
        self.network_id = "synthetic-node-setup-network"
        initialize(self.owner, network_id=self.network_id, relay_url="http://127.0.0.1:18765",
                   authority_url="http://127.0.0.1:18767")
        self.kwargs = {"network_id": self.network_id, "issuer_public": self.owner / "issuer-public.json",
                       "roster_path": self.owner / "roster.json", "authority_url": "http://127.0.0.1:18767",
                       "node_url": "http://127.0.0.1:18766"}

    def registration(self, name="node", **kwargs):
        directory = self.root / name
        result = initialize_node(directory, **{**self.kwargs, **kwargs})
        return directory, result

    def test_actual_cli_and_issuer_authorization_need_no_member_or_decryption_key(self):
        directory = self.root / "cli-node"
        command = [sys.executable, "-B", "-m", "memory_vault_network_admin", "node-init",
            "--directory", str(directory), "--network-id", self.network_id,
            "--issuer-public", str(self.kwargs["issuer_public"]), "--roster", str(self.kwargs["roster_path"]),
            "--authority-url", self.kwargs["authority_url"], "--node-url", self.kwargs["node_url"],
            "--maximum-messages", "12", "--maximum-object-bytes", "1048576"]
        process = subprocess.run(command, cwd=Path(__file__).resolve().parents[1], capture_output=True, timeout=10, check=True)
        result = strict_json_loads(process.stdout)["result"]
        self.assertFalse(result["agent_identity_created"])
        self.assertFalse(result["plaintext_keys_created"])
        self.assertFalse(result["network_accessed"])
        self.assertFalse(result["services_started"])
        self.assertEqual({path.name for path in directory.iterdir()},
                         {"node-identity.json", "node-public.json", "roster.json", "relay.json"})
        local = Relay(directory / "relay.json")
        self.assertEqual(local.limits["maximum_messages"], 12)
        self.assertEqual(local.initial, set())
        with local._transaction() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM members").fetchone()[0], 0)
        before_roster = (self.owner / "roster.json").read_bytes()
        before_nodes = (self.owner / "nodes.json").read_bytes()
        from starlette.testclient import TestClient
        with TestClient(create_authority_app(self.owner / "authority.json")) as authority:
            class Transport:
                def request(self, base, method, path, value):
                    response = authority.request(method, path, content=canonical_bytes(value),
                                                 headers={"content-type": "application/json"})
                    if response.status_code != 200:
                        raise MemoryError(response.json()["error"])
                    return response.json()
            with self.assertRaises(MemoryError) as unregistered:
                refresh(local, transport=Transport())
            self.assertEqual(unregistered.exception.code, "network_node_authorization_required")
            registered = authorize_node(authority_config=self.owner / "authority.json", candidate=directory / "node-public.json")
            self.assertFalse(registered["agent_membership_granted"])
            self.assertEqual(registered["directory_version"], 2)
            self.assertNotEqual((self.owner / "nodes.json").read_bytes(), before_nodes)
            self.assertEqual((self.owner / "roster.json").read_bytes(), before_roster)
            ready = refresh(local, transport=Transport())
            self.assertEqual(ready["state"], "fresh")
            self.assertFalse(ready["agent_identity_used"])
            self.assertFalse(ready["plaintext_keys_used"])
        before = (self.owner / "nodes.json").read_bytes()
        retried = authorize_node(authority_config=self.owner / "authority.json", candidate=directory / "node-public.json")
        self.assertEqual(retried["state"], "node_already_authorized")
        self.assertEqual((self.owner / "nodes.json").read_bytes(), before)

    def test_registration_tampering_and_duplicate_address_do_not_change_authority(self):
        directory, _ = self.registration()
        source = strict_json_loads((directory / "node-public.json").read_bytes())
        before = (self.owner / "nodes.json").read_bytes()
        for field, value in (("network_id", "other-network"), ("issuer_key_id", "untrusted-issuer")):
            altered = copy.deepcopy(source)
            altered["payload"][field] = value
            candidate = self.root / ("bad-" + field + ".json")
            atomic_write(candidate, canonical_bytes(altered), replace=False)
            with self.assertRaises(MemoryError):
                authorize_node(authority_config=self.owner / "authority.json", candidate=candidate)
        altered = copy.deepcopy(source)
        altered["payload"]["node"]["base_url"] = "https://synthetic-other.invalid"
        candidate = self.root / "bad-signature.json"
        atomic_write(candidate, canonical_bytes(altered), replace=False)
        with self.assertRaises((MemoryError, TrustError)):
            authorize_node(authority_config=self.owner / "authority.json", candidate=candidate)
        collision, _ = self.registration("collision", node_url="http://127.0.0.1:18765")
        with self.assertRaises(MemoryError):
            authorize_node(authority_config=self.owner / "authority.json", candidate=collision / "node-public.json")
        self.assertEqual((self.owner / "nodes.json").read_bytes(), before)

    def test_new_paths_quotas_and_revocation_cannot_be_bypassed_by_registration_retry(self):
        for index, invalid in enumerate((0, -1, True, 4097)):
            path = self.root / ("invalid-" + str(index))
            with self.assertRaises(MemoryError):
                initialize_node(path, **self.kwargs, maximum_messages=invalid)
            self.assertFalse(path.exists())
        for field in ("node_url", "authority_url"):
            for index, invalid in enumerate(("https://synthetic.invalid:bad", "https://synthetic.invalid:70000",
                                            "https://synthetic.invalid:", "https://" + "a" * 2049 + ".invalid")):
                path = self.root / ("invalid-url-" + field + str(index))
                with self.assertRaises(MemoryError):
                    initialize_node(path, **{**self.kwargs, field: invalid})
                self.assertFalse(path.exists())
        directory, _ = self.registration()
        before_key = (directory / "node-identity.json").read_bytes()
        with self.assertRaises(MemoryError):
            initialize_node(directory, **self.kwargs)
        self.assertEqual((directory / "node-identity.json").read_bytes(), before_key)
        result = authorize_node(authority_config=self.owner / "authority.json", candidate=directory / "node-public.json")
        previous = strict_json_loads((self.owner / "nodes.json").read_bytes())
        entries = copy.deepcopy(previous["payload"]["nodes"])
        for entry in entries:
            if entry["signing_key"]["key_id"] == result["node_key_id"]:
                entry["status"] = "revoked"
        now = int(time.time())
        revoked = issue_directory(Identity.load(self.owner / "authority-identity.json"), network_id=self.network_id,
            version=3, previous_sha256=document_sha256(previous), nodes=entries, issued_at=now, expires_at=now + 300)
        atomic_write(self.owner / "nodes.json", canonical_bytes(revoked), replace=True)
        with self.assertRaises(MemoryError) as denied:
            authorize_node(authority_config=self.owner / "authority.json", candidate=directory / "node-public.json")
        self.assertEqual(denied.exception.code, "network_node_already_listed_with_different_authority")
        self.assertEqual(strict_json_loads((self.owner / "nodes.json").read_bytes()), revoked)


@unittest.skipUnless(os.name == "posix", "the isolated HTTP fixture uses POSIX sockets")
class NodeCommandTests(unittest.TestCase):
    def test_prepare_authorize_and_bounded_transfer_through_actual_cli(self):
        from tests.test_network_node_transfer import fixture, seed
        with fixture() as host:
            seed(host, 1)
            snapshot, grant = host.root / "cli-snapshot.json", host.root / "cli-grant.json"

            def call(module, args, expected=0):
                result = subprocess.run([sys.executable, "-B", "-m", module, *args],
                    cwd=Path(__file__).resolve().parents[1], capture_output=True, timeout=20)
                self.assertEqual(result.returncode, expected, result.stderr.decode() + result.stdout.decode())
                response = strict_json_loads(result.stdout)
                self.assertTrue(response["ok"], response)
                return response["result"]

            prepared = call("memory_vault_node", ["--config", str(host.relays[0].config), "prepare-export",
                "--transfer-id", "synthetic-cli-node-transfer", "--output", str(snapshot)])
            self.assertEqual(prepared["state"], "node_export_prepared")
            self.assertFalse(prepared["safe_to_remove"])
            authorized = call("memory_vault_network_admin", ["node-transfer-authorize",
                "--authority-config", str(host.authority.config), "--snapshot", str(snapshot),
                "--target-node-key-id", host.node_identities[1].key_id, "--output", str(grant)])
            self.assertEqual(authorized["state"], "node_transfer_authorized")
            args = ["--config", str(host.relays[0].config), "transfer", "--grant", str(grant)]
            partial = call("memory_vault_node", [*args, "--maximum-objects", "0"], expected=2)
            self.assertEqual(partial["state"], "pending")
            completed = call("memory_vault_node", args)
            self.assertEqual(completed["state"], "exit_ready")
            self.assertEqual(completed["confirmed_objects"], 1)
            self.assertFalse(completed["source_data_deleted"])
            self.assertFalse(completed["safe_to_remove"])


if __name__ == "__main__":
    unittest.main()
