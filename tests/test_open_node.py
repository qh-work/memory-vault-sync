"""Real isolated HTTP processes: introductions, contact shards and bootstrap exit.

All nodes use actual loopback sockets and remain one observed source group and
one physical fault domain. No routing source cap, signature check, HTTP request
or neighbour table is patched. These are bounded local integration checks.
"""
import asyncio
from contextlib import contextmanager
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest

from memory_vault import MemoryError, canonical_bytes
from memory_vault_network_crypto import EncryptionIdentity
from memory_vault_open_control import (
    contact_key, issue_contact, issue_node, sign_request, verify_response,
)
from memory_vault_open_node import NODE_CONFIG, OpenParticipant
from memory_vault_open_routing import LookupBudget, SOURCE_CAP, source_group
from memory_vault_open_transport import OpenHTTPTransport
from memory_vault_storage import atomic_write
from memory_vault_trust import Identity


class HTTPNodes:
    def __init__(self, root, count):
        self.root, self.processes, self.logs = root, {}, {}
        self.identities, self.nodes, self.configs = [], [], []
        reservations = []
        now = int(time.time())
        try:
            for index in range(count):
                address = socket.socket()
                address.bind(("127.0.0.1", 0))
                reservations.append(address)
                port = address.getsockname()[1]
                directory = root / ("node_" + str(index))
                signer = Identity.generate(directory / "identity.json")
                self.identities.append(signer)
                self.nodes.append(issue_node(signer, base_url="http://127.0.0.1:" + str(port),
                    storage_epoch="synthetic_epoch_" + str(index), roles=["directory", "router"],
                    revision=1, issued_at=now, expires_at=now + 3600))
                seeds = self.nodes[max(0, index - 2):index]
                config = {"schema_version": NODE_CONFIG, "identity_path": str(directory / "identity.json"),
                    "state_directory": str(directory / "transport"), "node": self.nodes[-1],
                    "seeds": seeds, "allow_loopback": True, "index_policy": {"enabled": True},
                    "listen_host": "127.0.0.1", "listen_port": port}
                config_path = directory / "node.json"
                atomic_write(config_path, canonical_bytes(config), replace=False)
                self.configs.append(config_path)
            for index, reservation in enumerate(reservations):
                reservation.close()
                self.start(index)
        except BaseException:
            self.close()
            raise
        finally:
            for reservation in reservations:
                reservation.close()

    def start(self, index):
        log = open(self.root / ("synthetic_node_" + str(index) + ".log"), "ab")
        self.logs[index] = log
        process = subprocess.Popen([sys.executable, str(Path(__file__).resolve().parents[1] / "memory_vault_open_node.py"),
                                    "--config", str(self.configs[index])], stdout=log, stderr=log,
                                   cwd=Path(__file__).resolve().parents[1])
        self.processes[index] = process
        port = int(self.nodes[index]["payload"]["base_url"].rsplit(":", 1)[1])
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if process.poll() is not None:
                log.flush()
                diagnostic = (self.root / ("synthetic_node_" + str(index) + ".log")).read_text()[-5000:]
                raise AssertionError("Synthetic node exited before listening: " + diagnostic)
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=.15):
                    return
            except OSError:
                time.sleep(.05)
        raise AssertionError("Synthetic node did not start within its deadline")

    def stop(self, index):
        process = self.processes.pop(index, None)
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
        log = self.logs.pop(index, None)
        if log is not None:
            log.close()

    def close(self):
        for index in list(self.processes):
            self.stop(index)

    def contact(self, signer, encryption):
        endpoint = self.nodes[-1]["payload"]
        now = int(time.time())
        return issue_contact(signer, encryption_key=encryption.public_descriptor(), revision=1,
            allow_discovery=True, endpoints=[{"kind": "node", "node_key_id": endpoint["signing_key"]["key_id"],
                "base_url": endpoint["base_url"], "storage_epoch": endpoint["storage_epoch"]}],
            issued_at=now, expires_at=now + 600)

    def put_only_last(self, signer, contact):
        now = int(time.time())
        request = sign_request(signer, action="put", request_id="synthetic_last_shard_put", node=self.nodes[-1],
            body={"contact": contact, "lease_seconds": 300}, issued_at=now, expires_at=now + 60)
        transport = OpenHTTPTransport(allow_loopback=True)
        try:
            result = transport.request(self.nodes[-1]["payload"]["base_url"], request, deadline=time.monotonic() + 5)
            return verify_response(result.response, request=request, node=self.nodes[-1])["body"]
        finally:
            transport.close()

    def public_contacts(self, index):
        path = self.root / ("node_" + str(index)) / "transport" / "network.sqlite3"
        with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=1) as db:
            return db.execute("SELECT count(*) FROM open_contacts").fetchone()[0]


@contextmanager
def nodes(count):
    with tempfile.TemporaryDirectory(prefix="memory-open-http-synthetic-") as temporary:
        host = HTTPNodes(Path(temporary).resolve(), count)
        try:
            yield host
        finally:
            host.close()


class OpenNodeTests(unittest.TestCase):
    def test_verified_seed_revision_survives_configured_old_seed_and_client_restart(self):
        from memory_vault_open_control import coordinate
        from memory_vault_network_crypto import document
        with nodes(1) as net:
            root = net.root
            identity = Identity.generate(root / "client-identity.json")
            directory = root / "client-transport"
            old = net.nodes[0]
            now = int(time.time())
            new = issue_node(net.identities[0], base_url=old["payload"]["base_url"],
                storage_epoch=old["payload"]["storage_epoch"], roles=["directory", "router"],
                revision=2, issued_at=now, expires_at=now + 3600)
            with OpenParticipant(identity, directory, seeds=[old], allow_loopback=True) as client:
                asyncio.run(client._call(old, "hello", {"node": None}, LookupBudget()))
                net.stop(0)
                config = document(net.configs[0].read_bytes())
                config["node"] = new
                atomic_write(net.configs[0], canonical_bytes(config), replace=True)
                net.nodes[0] = new
                net.start(0)
                # A fresh signed response has already proved the newer
                # descriptor; old configuration must not mask this proof.
                asyncio.run(client._call(new, "hello", {"node": None}, LookupBudget()))
                target = coordinate(net.identities[0].key_id)
                warm = asyncio.run(client._lookup(target, "general", LookupBudget()))
                self.assertEqual(warm["candidates"], [new])
                self.assertEqual(warm["metrics"]["errors"], [])
            with OpenParticipant(identity, directory, seeds=[old], allow_loopback=True) as cold:
                self.assertEqual(cold.table.stats()["general_active"], 0)
                result = asyncio.run(cold._lookup(target, "general", LookupBudget()))
                self.assertEqual(result["candidates"], [new])
                self.assertEqual(result["metrics"]["requests"], 1)
                self.assertEqual(result["metrics"]["errors"], [])

    def test_owner_revocation_reaches_directory_and_cannot_restore_stale_contact(self):
        with nodes(1) as host:
            owner = Identity.generate(host.root / "synthetic_owner" / "identity.json")
            encryption = EncryptionIdentity.generate()
            contact = host.contact(owner, encryption)
            state = host.root / "synthetic_publisher"
            with OpenParticipant(owner, state, seeds=host.nodes, allow_loopback=True) as publisher:
                first = asyncio.run(publisher.publish_contact(contact))
                self.assertEqual(first["confirmed_leases"], 1)
                now = int(time.time())
                revoked = issue_contact(owner, encryption_key=encryption.public_descriptor(), revision=2,
                    allow_discovery=False, endpoints=[], issued_at=now, expires_at=now+600, status="revoked")
                withdrawn = asyncio.run(publisher.publish_contact(revoked))
                self.assertEqual(withdrawn["confirmed_leases"], 1)
                self.assertEqual(withdrawn["leases"][0]["payload"]["contact_revision"], 2)
                repeated = asyncio.run(publisher.publish_contact(revoked))
                self.assertEqual(repeated["confirmed_leases"], 1)
                self.assertEqual(host.public_contacts(0), 0)
                with self.assertRaisesRegex(MemoryError, "open_control_rollback"):
                    asyncio.run(publisher.publish_contact(contact))
                # A valid conflicting owner signature cannot use the narrow
                # revocation path to bypass a persisted local conflict floor.
                fork = issue_contact(owner, encryption_key=encryption.public_descriptor(), revision=2,
                    allow_discovery=False, endpoints=contact["payload"]["endpoints"],
                    issued_at=now, expires_at=now+600, status="revoked")
                with self.assertRaisesRegex(MemoryError, "open_control_conflict"):
                    asyncio.run(publisher.publish_contact(fork))
                foreign = Identity.generate(host.root / "synthetic_foreign" / "identity.json")
                foreign_revocation = issue_contact(foreign, encryption_key=encryption.public_descriptor(), revision=1,
                    allow_discovery=False, endpoints=[], issued_at=now, expires_at=now+600, status="revoked")
                with self.assertRaisesRegex(MemoryError, "open_contact_owner_required"):
                    asyncio.run(publisher.publish_contact(foreign_revocation))
            # A cold observer uses the signed directory API, with no local copy
            # of the owner's revocation or publisher checkpoint injected.
            observer = Identity.generate(host.root / "synthetic_observer" / "identity.json")
            with OpenParticipant(observer, host.root / "synthetic_observer_state", seeds=host.nodes,
                                 allow_loopback=True) as reader:
                result = asyncio.run(reader.find_contact(owner.key_id))
                self.assertEqual(result["state"], "inconclusive")
                self.assertIsNone(result["contact"])
            host.stop(0)
            host.start(0)
            transport = OpenHTTPTransport(allow_loopback=True)
            self.addCleanup(transport.close)
            now = int(time.time())
            request = sign_request(observer, action="get", node=host.nodes[0], request_id="synthetic_revoked_after_restart",
                body={"key":contact_key(owner.key_id)}, issued_at=now, expires_at=now+60)
            reply = transport.request(host.nodes[0]["payload"]["base_url"], request, deadline=time.monotonic()+5)
            self.assertEqual(verify_response(reply.response, request=request, node=host.nodes[0])["body"],
                             {"state":"revoked"})

    def test_two_real_processes_discovery_and_explicit_degraded_index_publication(self):
        with nodes(2) as host:
            owner = Identity.generate(host.root / "contact_owner" / "identity.json")
            contact = host.contact(owner, EncryptionIdentity.generate())
            with OpenParticipant(owner, host.root / "owner_transport", seeds=[host.nodes[0]], allow_loopback=True) as participant:
                join = asyncio.run(participant.join())
                self.assertFalse(join["authority_required"])
                self.assertFalse(join["discovery_grants_access"])
                # Node 1's normal two-second worker proves its advertisement
                # back to node 0. Do not seed the owner with node 1 or fill tables.
                deadline = time.monotonic() + 12
                published = None
                while time.monotonic() < deadline:
                    published = asyncio.run(participant.publish_contact(contact))
                    if published["confirmed_leases"] == 2:
                        break
                    time.sleep(.25)
                self.assertEqual(published["confirmed_leases"], 2, published)
                self.assertEqual(published["state"], "degraded")
                self.assertEqual(published["desired_leases"], 3)
                self.assertFalse(published["physical_failure_domains_verified"])
                received = asyncio.run(participant.find_contact(owner.key_id))
                self.assertEqual(received["state"], "found", received)
                self.assertEqual(canonical_bytes(received["contact"]), canonical_bytes(contact))
                self.assertFalse(received["encryption_key_possession_proven"])
                self.assertLessEqual(received["metrics"]["requests"], 64)
                self.assertEqual([host.public_contacts(i) for i in range(2)], [1, 1])

    def test_eight_process_multihop_unknown_contact_and_bootstrap_exit_restart(self):
        with nodes(8) as host:
            self.assertEqual(SOURCE_CAP, 2)
            self.assertEqual(source_group("127.0.0.1"), "4:127.0.0.0/24")
            for path in host.configs:
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            owner = Identity.generate(host.root / "unseen_owner" / "identity.json")
            contact = host.contact(owner, EncryptionIdentity.generate())
            saved = host.put_only_last(owner, contact)
            self.assertIn("lease", saved)
            self.assertEqual([host.public_contacts(i) for i in range(8)], [0] * 7 + [1])

            # This independent observer waits for normal production maintenance.
            # Its read-only FIND/GET calls do not advertise itself or populate any
            # node's routing table. A's fresh state remains absent until below.
            observer_id = Identity.generate(host.root / "observer" / "identity.json")
            with OpenParticipant(observer_id, host.root / "observer_transport", seeds=host.nodes[:2], allow_loopback=True) as observer:
                deadline = time.monotonic() + 25
                observed = None
                while time.monotonic() < deadline:
                    observed = asyncio.run(observer.find_contact(owner.key_id))
                    if observed["state"] == "found":
                        break
                    time.sleep(.25)
                self.assertEqual(observed["state"], "found", observed)

            client_id = Identity.generate(host.root / "cold_client" / "identity.json")
            client_state = host.root / "cold_client_transport"
            self.assertFalse(client_state.exists())
            with OpenParticipant(client_id, client_state, seeds=host.nodes[:2], allow_loopback=True) as client:
                result = asyncio.run(client.find_contact(owner.key_id))
                self.assertEqual(result["state"], "found", result)
                self.assertEqual(canonical_bytes(result["contact"]), canonical_bytes(contact))
                paths = result["route"]["metrics"]["paths"]
                self.assertTrue(any(path["parent_key_id"] is not None and path["state"] == "verified" for path in paths), paths)
                known = {node["payload"]["signing_key"]["key_id"] for node in host.nodes[:2]}
                self.assertTrue(any(path["key_id"] not in known and path["state"] == "verified" for path in paths), paths)
                self.assertLessEqual(result["metrics"]["requests"], 64)
                self.assertLessEqual(result["route"]["metrics"]["candidate_peak"], 32)
                self.assertLessEqual(result["route"]["metrics"]["concurrency_peak"], 3)
            host.stop(0)
            host.stop(1)
            with OpenParticipant(client_id, client_state, seeds=host.nodes[:2], allow_loopback=True) as restarted:
                result = asyncio.run(restarted.find_contact(owner.key_id))
                self.assertEqual(result["state"], "found", result)
                self.assertEqual(canonical_bytes(result["contact"]), canonical_bytes(contact))
                self.assertFalse(result["discovery_grants_access"])
                self.assertLessEqual(result["metrics"]["requests"], 64)
            self.assertEqual([host.public_contacts(i) for i in range(2, 8)], [0] * 5 + [1])


if __name__ == "__main__":
    unittest.main()
