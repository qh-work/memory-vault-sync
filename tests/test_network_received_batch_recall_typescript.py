"""Local historical batch inspection with actual Node/jose and Python peers.

All identities, records, services, recovery packages and mutations are disposable
synthetic fixtures. No real model, cross-host or scale claim is made.
"""
import base64
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import unittest

from memory_vault import canonical_bytes, strict_json_loads
from memory_vault_agent import Agent
from memory_vault_network import NetworkClient
import memory_vault_network_recovery as recovery
from memory_vault_trust import TrustStore
from tests import test_network_hints_typescript as harness
from tests.test_network_hints import control, outbox_row
from tests.test_network_message_semantics import inject_ciphertext, records, proofs, vault_snapshot
from tests.test_network_recovery import archive
from tests.test_network_received_batch_recall import prepare_batch, readonly_probe, transport_snapshot


LOCAL_DRIVER = r"""
import fs from 'node:fs';
import child from 'node:child_process';
import sqlite from 'node:sqlite';
import {syncBuiltinESMExports} from 'node:module';
const input=JSON.parse(fs.readFileSync(0,'utf8'));
let networkCalls=0,writeCalls=0,subprocessCalls=0;
const databaseOpens=[];
const denyWrite=()=>{writeCalls++;throw Error('local recall attempted persistent mutation');};
for(const name of ['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork'])child[name]=()=>{subprocessCalls++;throw Error('native recall attempted subprocess');};
const NativeDatabase=sqlite.DatabaseSync;
sqlite.DatabaseSync=class extends NativeDatabase {
 constructor(file,options){
   databaseOpens.push({readOnly:options?.readOnly===true});
   if(options?.readOnly!==true)denyWrite();
   super(file,options);
 }
};
for(const name of ['writeFileSync','appendFileSync','mkdirSync','renameSync','unlinkSync','rmSync','chmodSync'])fs[name]=denyWrite;
syncBuiltinESMExports();
const {Agent}=await import('./agent.ts');
const {NetworkPeer}=await import('./peer.ts');
const {CanonicalVault}=await import('./vault.ts');
NetworkPeer.prototype.db=NetworkPeer.prototype.readMessage=denyWrite;
for(const name of ['importShare','exportShare','remember'])CanonicalVault.prototype[name]=denyWrite;
const transport={request(){networkCalls++;throw Error('local recall attempted network');},close(){}};
const agent=new Agent(input.client_config,input.network_config,{transport}),results=[];
for(const request of input.requests)results.push(await agent.handle(request));
process.stdout.write(JSON.stringify({results,networkCalls,writeCalls,subprocessCalls,databaseOpens}));
"""


class TypeScriptReceivedBatchRecallTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        harness.TypeScriptHintExchangeTests.setUpClass.__func__(cls)
        (cls.fixture / "received-batch-local.mjs").write_text(LOCAL_DRIVER)

    setUp = harness.TypeScriptHintExchangeTests.setUp
    ts = harness.TypeScriptHintExchangeTests.ts
    ts_value = harness.TypeScriptHintExchangeTests.ts_value
    py_value = harness.TypeScriptHintExchangeTests.py_value

    def local(self, index, *requests, client_config=None, network_config=None):
        output = subprocess.run([self.node, "--experimental-strip-types", str(self.fixture / "received-batch-local.mjs")],
            input=json.dumps({"client_config": str(client_config or self.host.configs[index]),
                             "network_config": str(network_config or self.host.net_configs[index]),
                             "requests": requests}).encode(), cwd=self.fixture, capture_output=True, timeout=45)
        self.assertEqual(output.returncode, 0, output.stderr.decode(errors="replace")[-4000:])
        value = json.loads(output.stdout)
        self.assertEqual((value["networkCalls"], value["writeCalls"], value["subprocessCalls"]), (0, 0, 0))
        self.assertTrue(all(item["readOnly"] for item in value["databaseOpens"]))
        for response in value["results"]:
            self.assertLessEqual(len(canonical_bytes(response)), 8192)
            self.assertFalse(response["authority"]["execution_eligible"])
            self.assertFalse(response["authority"]["authorization_eligible"])
        return value["results"]

    def parity(self, index, request, *, expected_error=None):
        response, = self.local(index, request)
        python = Agent(self.host.configs[index], self.host.net_configs[index],
                       transport=self.host.transports[index]).handle(request)
        self.assertEqual(response, python)
        if expected_error is None:
            self.assertTrue(response["ok"], response)
            self.assertFalse(response["result"]["network_accessed"])
        else:
            self.assertFalse(response["ok"], response)
            self.assertEqual(response["error"]["code"], expected_error)
        return response

    @staticmethod
    def cursor(value):
        return base64.urlsafe_b64encode(canonical_bytes(value)).decode().rstrip("=")

    def prepared(self, owner=0, requester=1, **options):
        endpoints = [self.host.sender, self.host.receiver]
        return prepare_batch(self, endpoints[owner], endpoints[requester], self.host.transports[owner],
            transfer_call=(lambda identifier: self.ts_value(owner, {"op": "receive", "respond_to": identifier})) if owner else None,
            receive_call=(lambda: self.ts_value(requester, {"op": "receive"})) if requester else None,
            **options)

    def pages(self, requester, batch, *, include_experience=None):
        request = {"op": "recall", "received_batch_message_id": batch["transfer"]["message_id"]}
        if include_experience is not None:
            request["include_experience"] = include_experience
        pages = []
        for _ in range(64):
            value = self.parity(requester, request)["result"]
            self.assertEqual(value["received_batch_message_id"], batch["transfer"]["message_id"])
            self.assertEqual(value["selected_memory_ids"], batch["roots"])
            self.assertEqual(value["query_candidate_limit"], 4)
            self.assertLessEqual(len(value["hits"]), 4)
            self.assertNotIn("context", value)
            pages.append(value)
            if value["next_cursor"] is None:
                return pages
            decoded = strict_json_loads(base64.urlsafe_b64decode(value["next_cursor"] + "=" * (-len(value["next_cursor"]) % 4)))
            self.assertEqual(set(decoded), {"received_batch_message_id", "root_index", "offset", "include_experience"})
            self.assertLess(decoded["root_index"], len(batch["roots"]))
            self.assertEqual(decoded["include_experience"], include_experience is not False)
            request = {"op": "recall", "cursor": value["next_cursor"]}
        self.fail("bounded local batch pagination failed to terminate")

    def test_both_directions_preserve_selection_order_sources_context_int64_and_readonly_pages(self):
        self.host.join_receiver()
        endpoints = [self.host.sender, self.host.receiver]
        for owner, requester in ((0, 1), (1, 0)):
            with self.subTest(owner=owner):
                batch = self.prepared(owner, requester, cross_pages=True, long_text=True, suffix="native_" + str(owner))
                self.assertEqual([len(page["hints"]) for page in batch["pages"]], [4, 4, 4, 1])
                endpoint = endpoints[requester]
                with readonly_probe(self, endpoint, self.host.transports[requester]):
                    pages = self.pages(requester, batch)
                    repeated = self.pages(requester, batch, include_experience=False)
                hits = [hit for page in pages for hit in page["hits"]]
                encountered = list(dict.fromkeys(hit["memory_id"] for hit in hits))
                self.assertEqual(encountered, batch["roots"])
                self.assertNotIn(batch["dependency"], encountered)
                self.assertTrue(all("experience" not in hit for page in repeated for hit in page["hits"]))
                for memory_id in batch["roots"]:
                    matching = [hit for hit in hits if hit["memory_id"] == memory_id]
                    original = strict_json_loads(batch["originals"][memory_id])
                    self.assertEqual("".join(hit["text"] for hit in matching), original["text"])
                    self.assertTrue(all(len(hit["text"].encode()) <= 768 for hit in matching))
                    self.assertEqual(records(endpoint)[memory_id], batch["originals"][memory_id])
                    self.assertEqual(proofs(endpoint)[memory_id], batch["original_proofs"][memory_id])
                by_id = {hit["memory_id"]: hit for hit in hits}
                summary, v2, observation, confirmation = batch["roots"]
                self.assertEqual(by_id[summary]["experience"]["epistemic_type"], "summary")
                self.assertEqual(by_id[observation]["experience"]["observed_under"]["environment"], "V1")
                self.assertEqual(by_id[confirmation]["experience"]["epistemic_type"], "experiment")
                self.assertEqual(by_id[v2]["experience"]["observed_under"], {"environment": "V2", "build_id": 2**63 - 1})
                self.assertEqual(by_id[v2]["experience"]["source"]["signer_key_id"], batch["witnesses"][1].key_id)
                self.assertEqual(by_id[observation]["experience"]["provenance_summary"]["independent_confirmation_count"], 1)
                self.assertEqual(by_id[observation]["experience"]["provenance_summary"]["contradiction_count"], 1)

    def test_cancelled_and_encrypted_restored_history_stays_readable_but_late_batch_is_unavailable(self):
        host = self.host
        host.join_receiver()
        batch = self.prepared(suffix="history")
        accepted = batch["transfer"]["message_id"]
        notice = self.ts_value(1, {"op": "send", "request_id": "req_received_history_cancel",
            "recipients": [host.identities[0].key_id], "control": control("cancel",
                query_message_id=batch["query"]["message_id"], offer_message_id=batch["offers"][0]["message_id"],
                expires_at=batch["pages"][0]["expires_at"])})
        self.assertTrue(notice["cancellation"]["local_cancelled"])
        before = vault_snapshot(host.receiver)
        late = "msg_" + hashlib.sha256(b"synthetic-received-batch-late-duplicate").hexdigest()
        inject_ciphertext(host.sender, host.receiver, outbox_row(host.sender, accepted)["body"], late)
        received = self.ts_value(1, {"op": "receive"})
        self.assertFalse(received["errors"])
        rejected, = [item for item in received["messages"] if item["message_id"] == late]
        self.assertEqual((rejected["state"], rejected["code"]), ("rejected", "network_invalid_content"))
        self.assertEqual(vault_snapshot(host.receiver), before)
        with readonly_probe(self, host.receiver, host.transports[1]):
            expected = self.pages(1, batch)
            self.parity(1, {"op": "recall", "received_batch_message_id": late}, expected_error="received_batch_not_available")
        _, arguments = archive(host.receiver)
        restored = recovery.restore_endpoint(directory=host.root / "synthetic-received-restored", **arguments)
        original_configs = host.configs[1], host.net_configs[1]
        try:
            host.configs[1], host.net_configs[1] = Path(restored["client_config"]), Path(restored["network_config"])
            with NetworkClient(host.net_configs[1], transport=host.transports[1]) as endpoint:
                state = transport_snapshot(endpoint)["state"]
                self.assertFalse(any(row[0].startswith("hint-session:") for row in state))
                with readonly_probe(self, endpoint, host.transports[1]):
                    self.assertEqual(self.pages(1, batch), expected)
                    self.parity(1, {"op": "recall", "received_batch_message_id": late}, expected_error="received_batch_not_available")
        finally:
            host.configs[1], host.net_configs[1] = original_configs

    def test_strict_selector_cursor_binding_and_current_trust_are_rechecked(self):
        host = self.host
        host.join_receiver()
        batch = self.prepared(long_text=True, suffix="strict")
        identifier = batch["transfer"]["message_id"]
        request = {"op": "recall", "received_batch_message_id": identifier}
        first = self.parity(1, request)["result"]
        cursor = strict_json_loads(base64.urlsafe_b64decode(first["next_cursor"] + "=" * (-len(first["next_cursor"]) % 4)))
        invalid = [({**request, **extra}, "ambiguous_recall_selector") for extra in (
            {"query": "Synthetic"}, {"memory_id": batch["roots"][0]}, {"handoff": False}, {"ranking_profile": "recall-v1"})]
        invalid.append(({**request, "cursor": first["next_cursor"]}, "ambiguous_recall_cursor"))
        states = [{**cursor, "ids": batch["roots"]}, {**cursor, "root_index": 4}, {**cursor, "root_index": True},
                  {**cursor, "offset": -1}, {**cursor, "offset": 999999}, {**cursor, "include_experience": 1},
                  {key: value for key, value in cursor.items() if key != "include_experience"}]
        invalid += [({"op": "recall", "cursor": self.cursor(state)}, "invalid_recall_cursor") for state in states]
        invalid.append(({"op": "recall", "cursor": self.cursor({**cursor, "received_batch_message_id": "msg_" + "0" * 64})}, "received_batch_not_available"))
        with readonly_probe(self, host.receiver, host.transports[1]):
            for value, error in invalid:
                self.parity(1, value, expected_error=error)
        # A previously accepted source remains inspectable as history, but each
        # continuation uses current trust rather than its import-time verdict.
        TrustStore(host.receiver.client_config.trust_path).revoke(host.sender.identity.key_id)
        with readonly_probe(self, host.receiver, host.transports[1]):
            continuation = self.parity(1, {"op": "recall", "cursor": first["next_cursor"]})["result"]
            self.assertEqual(continuation["hits"][0]["memory_id"], batch["roots"][0])
            self.assertFalse(continuation["hits"][0]["verification"]["eligible_for_context"])
        # A retained outbox index mismatch cannot authorize a replacement root.
        with host.receiver.db() as db:
            db.execute("UPDATE outbox SET input_sha=? WHERE message_id=?", ("0" * 64, batch["select"]["message_id"]))
        with readonly_probe(self, host.receiver, host.transports[1]):
            self.parity(1, request, expected_error="received_batch_not_available")

    def test_initial_quarantine_and_absent_transport_never_become_imported_history(self):
        host = self.host
        absent = host.root / "synthetic-absent-transport"
        configured = strict_json_loads(host.net_configs[1].read_bytes())
        configured["state_directory"] = str(absent)
        config_path = host.net_configs[1].parent / "synthetic-absent-config.json"
        from memory_vault_storage import atomic_write
        atomic_write(config_path, canonical_bytes(configured), replace=False)
        result, = self.local(1, {"op": "recall", "received_batch_message_id": "msg_" + "0" * 64}, network_config=config_path)
        self.assertEqual(result["error"]["code"], "received_batch_not_available")
        self.assertFalse(absent.exists())
        self.assertFalse(host.receiver.client_config.vault_path.exists())
        # A real, private SQLite file with no transport schema is a storage
        # failure, not evidence that a historical batch was never received.
        absent.mkdir(mode=0o700)
        database = absent / "network.sqlite3"
        with sqlite3.connect(database) as fixture_db:
            fixture_db.execute("CREATE TABLE synthetic_fixture(value TEXT)")
        database.chmod(0o600)
        for locked in (False, True):
            with sqlite3.connect(database) as fixture_db:
                if locked:
                    fixture_db.execute("BEGIN EXCLUSIVE")
                result, = self.local(1, {"op": "recall", "received_batch_message_id": "msg_" + "0" * 64}, network_config=config_path)
                python = Agent(host.configs[1], config_path, transport=host.transports[1]).handle(
                    {"op": "recall", "received_batch_message_id": "msg_" + "0" * 64})
                self.assertEqual(result, python)
                self.assertEqual(result["error"]["code"], "busy" if locked else "storage_unavailable")
                self.assertEqual(result["error"]["retryable"], locked)
                if locked:
                    fixture_db.rollback()
        host.join_receiver()
        batch = self.prepared(trusted_witnesses=False, suffix="quarantine")
        self.assertEqual(batch["received"]["messages"][0]["share"]["admission"], "quarantined")
        with readonly_probe(self, host.receiver, host.transports[1]):
            self.parity(1, {"op": "recall", "received_batch_message_id": batch["transfer"]["message_id"]},
                        expected_error="received_batch_not_available")


if __name__ == "__main__":
    unittest.main()
