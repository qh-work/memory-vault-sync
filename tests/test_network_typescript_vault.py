"""Real Node SQLite <-> Python canonical Vault interoperability; synthetic only.

The TypeScript runtime never calls Python. The Python process is an independent
verifier and alternating writer. Missing preinstalled Node/jose is a skip, not
evidence of interoperability. No installation, real memories or network calls.
"""
from __future__ import annotations

import base64
import contextlib
import copy
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from memory_vault import Vault, build_record, canonical_bytes, normalize_text
from memory_vault_backup import backup_database, database_summary, _validate_write_receipts
from memory_vault_client import CONFIG_SCHEMA
from memory_vault_sharing import export_share, import_share, verify_share_bundle
from memory_vault_trust import Identity, TrustStore


DRIVER = r"""
import { CanonicalVault } from './vault.ts';
import { encodeShare } from './records.ts';
import { DatabaseSync } from 'node:sqlite';
const chunks = []; let size = 0;
for await (const chunk of process.stdin) { size += chunk.length; if (size > 20*1024*1024) throw Error('fixture input limit'); chunks.push(chunk); }
const request = JSON.parse(Buffer.concat(chunks).toString('utf8'));
let vault;
try {
  if (request.packet) {
    process.stdout.write(JSON.stringify({ok:true, packet:Buffer.from(encodeShare(request.packet.records,request.packet.roots)).toString('base64')}));
  } else {
    let activeTrust = request.trust, calls = 0;
    const options = { vaultPath:request.vaultPath };
    if (request.identity) options.identity = request.identity;
    if (request.trust !== undefined || request.trustSequence !== undefined) options.trust = () => {
      if (request.trustSequence) return request.trustSequence[Math.min(calls++,request.trustSequence.length-1)];
      return activeTrust;
    };
    vault = new CanonicalVault(options);
    const results = [];
    for (const item of request.operations) {
      try {
        let value;
        if (item.op === 'remember') value = vault.remember(item.value);
        else if (item.op === 'get') value = vault.get(item.id,item.options);
        else if (item.op === 'verification') value = vault.verification(item.id);
        else if (item.op === 'recall') value = vault.recall(item.query,item.options);
        else if (item.op === 'export') value = {raw:Buffer.from(vault.exportShare(item.roots,item.options)).toString('base64')};
        else if (item.op === 'import') value = vault.importShare(Buffer.from(item.raw,'base64'),item.options);
        else if (item.op === 'trust') { activeTrust = item.value; value = {changed:true}; }
        else if (item.op === 'clock-step') {
          const origin = performance.now(); let tick = 0;
          Object.defineProperty(performance,'now',{value:() => origin + tick++ * item.value}); value = {controlledClock:true};
        }
        else if (item.op === 'foreign-trigger') {
          const other = new DatabaseSync(request.vaultPath);
          try { other.exec("CREATE TRIGGER foreign_code AFTER INSERT ON memories BEGIN DELETE FROM receipts; END"); } finally {other.close();}
          value = {created:true};
        } else throw Error('unknown fixture operation');
        results.push({ok:true,result:value});
      } catch (error) { results.push({ok:false,error:error.code ?? 'unexpected_error',retryable:error.retryable===true,detail:error.code ? undefined : String(error.message)}); }
    }
    process.stdout.write(JSON.stringify({ok:true,results}));
  }
} catch (error) { process.stdout.write(JSON.stringify({ok:false,error:error.code ?? 'unexpected_error',retryable:error.retryable===true,detail:error.code ? undefined : String(error.message)})); }
finally { vault?.close(); }
"""


class TypeScriptVaultTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.node = os.environ.get("MEMORY_VAULT_NODE") or shutil.which("node")
        if not cls.node:
            raise unittest.SkipTest("Node >=22.19 with node:sqlite is required")
        version = subprocess.check_output([cls.node, "--version"], text=True).strip()
        major, minor, *_ = map(int, version.lstrip("v").split("."))
        if major < 22 or (major == 22 and minor < 19):
            raise unittest.SkipTest("Node >=22.19 with node:sqlite is required")
        entry = os.environ.get("MEMORY_VAULT_JOSE_MODULE")
        package = ROOT / "clients/typescript/network/node_modules/jose"
        if entry:
            selected = Path(entry).resolve()
            if selected.parts[-3:] != ("dist", "webapi", "index.js"):
                raise RuntimeError("Expected explicit jose/dist/webapi/index.js")
            package = selected.parents[2]
        if not (package / "package.json").is_file():
            raise unittest.SkipTest("Preinstalled locked jose 6.2.10 required; tests never install")
        metadata = json.loads((package / "package.json").read_text())
        if (metadata.get("name"), metadata.get("version")) != ("jose", "6.2.10"):
            raise RuntimeError("Exact locked jose 6.2.10 required")
        cls.temporary = tempfile.TemporaryDirectory(prefix="memory-vault-ts-vault-synthetic-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.fixture = Path(cls.temporary.name).resolve()
        for name in ("crypto.ts", "records.ts", "io.ts", "vault.ts", "retrieval.ts", "retrieval_text.ts", "ranking_math.ts", "package.json"):
            shutil.copyfile(ROOT / "clients/typescript/network" / name, cls.fixture / name)
        (cls.fixture / "node_modules").mkdir()
        (cls.fixture / "node_modules/jose").symlink_to(package, target_is_directory=True)
        (cls.fixture / "driver.mjs").write_text(DRIVER)

    def setUp(self) -> None:
        self.directory = Path(tempfile.mkdtemp(prefix="case-", dir=self.fixture))
        self.identity_path = self.directory / "identity.json"
        self.identity = Identity.generate(self.identity_path)
        self.signer = json.loads(self.identity_path.read_text())
        self.public = self.identity.public_descriptor()
        self.trust = TrustStore(self.directory / "trust.json")
        self.trust.add(self.public, "synthetic signer")
        self.path = self.directory / "canonical.sqlite3"

    def run_ts(self, operations: list[dict], *, path: Path | None = None,
               identity: dict | None = None, trust: list[dict] | None = None,
               trust_sequence: list[list[dict]] | None = None) -> dict:
        value = {"vaultPath": str(path or self.path), "identity": self.signer if identity is None else identity,
                 "operations": operations}
        if trust is not None:
            value["trust"] = trust
        if trust_sequence is not None:
            value["trustSequence"] = trust_sequence
        return self._run(value)

    def _run(self, value: dict) -> dict:
        process = subprocess.run([self.node, "--experimental-strip-types", str(self.fixture / "driver.mjs")],
                                 input=json.dumps(value), text=True, capture_output=True, timeout=30,
                                 cwd=self.fixture, env={**os.environ, "NO_PROXY": "*"})
        self.assertEqual(process.returncode, 0, process.stderr)
        return json.loads(process.stdout)

    def successful(self, result: dict) -> list:
        self.assertTrue(result["ok"], result)
        for row in result["results"]:
            self.assertTrue(row["ok"], row)
        return [row["result"] for row in result["results"]]

    def python_vault(self, path: Path | None = None) -> Vault:
        return Vault(path or self.path, signer=self.identity.sign_record, trust_check=self.trust.require_trusted)

    def request(self, suffix: str, text: str = "Synthetic remembered fact", **values: object) -> dict:
        return {"requestId": "req_synthetic_" + suffix, "kind": "fact", "text": text, **values}

    def config(self, path: Path) -> Path:
        result = self.directory / (path.stem + "-client.json")
        result.write_bytes(canonical_bytes({"schema_version": CONFIG_SCHEMA, "vault_path": str(path),
            "capture_visible_turns": False, "identity_path": str(self.identity_path), "trust_path": str(self.trust.path)}))
        result.chmod(0o600)
        return result

    def signed(self, text: str, **kwargs: object) -> dict:
        record = build_record(kind="fact", text=text, created_at="2026-08-31T00:00:00Z", **kwargs)
        return {"record": record, "attestation": self.identity.sign_record(record)}

    def packet(self, records: list[dict], roots: list[str] | None = None) -> bytes:
        result = self._run({"packet": {"records": records, "roots": roots or [records[-1]["record"]["memory_id"]]}})
        self.assertTrue(result["ok"], result)
        return base64.b64decode(result["packet"])

    def test_typescript_initialization_signed_record_python_retry_and_backup(self) -> None:
        request = self.request("first", "Straße Σς 中文😀\u0085 ＡＢＣ \U0001e030", entities=["test:unicode"])
        result = self.successful(self.run_ts([{"op": "remember", "value": request}]))[0]
        self.trust.verify_record(result["record"], result["attestation"])
        python_request = {"op": "remember", "request_id": request["requestId"], **{k: v for k, v in request.items() if k != "requestId"}}
        response = self.python_vault().handle(python_request)
        self.assertTrue(response["ok"], response)
        self.assertEqual(response["result"]["memory_id"], result["memory_id"])
        with contextlib.closing(self.python_vault()._connect()) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM memories").fetchone()[0], 1)
            row = connection.execute("SELECT * FROM memories").fetchone()
            self.assertEqual(row["record_json"].encode(), canonical_bytes(result["record"]))
            self.assertEqual(row["normalized_text"], normalize_text(request["text"]))
            self.assertIsNotNone(Vault.dependency_epoch(connection))
            self.assertTrue(Vault._retrieval_index_state(connection)["complete"])
            _validate_write_receipts(connection, time.monotonic() + 5)
            self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            database_summary(connection)
        backup = backup_database(self.path, self.directory / "snapshot")
        self.assertIsInstance(backup, dict)
        self.assertEqual(self.path.stat().st_mode & 0o077, 0)

    def test_signed_receipt_retry_does_not_bypass_current_record_trust(self) -> None:
        request = self.request("scope_replay", "Synthetic evidence from the original signer")
        first = self.successful(self.run_ts([{"op": "remember", "value": request}]))[0]
        other_path = self.directory / "other-identity.json"
        other = Identity.generate(other_path)
        observed = self.run_ts([
            {"op": "get", "id": first["memory_id"]},
            {"op": "remember", "value": request},
        ], identity=json.loads(other_path.read_text()), trust=[other.public_descriptor()])
        self.assertTrue(observed["ok"], observed)
        self.assertEqual(observed["results"][0], {"ok": True, "result": None})
        self.assertFalse(observed["results"][1]["ok"], observed)
        self.assertEqual(observed["results"][1]["error"], "memory_not_found")
        with sqlite3.connect(self.path) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM receipts").fetchone()[0], 1)
            admission = connection.execute("SELECT state,signer_key_id,attestation_json FROM record_admissions").fetchone()
            self.assertEqual(admission[:2], ("verified", self.public["key_id"]))
            self.assertEqual(json.loads(admission[2]), first["attestation"])

    def test_python_and_typescript_alternate_same_receipts_and_preserve_proofs(self) -> None:
        original = {"op": "remember", "request_id": "req_python_alternating", "kind": "fact", "text": "Python origin"}
        python_result = self.python_vault().handle(original)
        self.assertTrue(python_result["ok"], python_result)
        old_id = python_result["result"]["memory_id"]
        with sqlite3.connect(self.path) as connection:
            old = connection.execute("SELECT m.record_json,a.attestation_json FROM memories m JOIN record_admissions a USING(memory_id)").fetchone()
        request = self.request("alternating", "TypeScript continuation", relations=[{"type": "derived_from", "target": old_id}])
        results = self.successful(self.run_ts([
            {"op": "get", "id": old_id},
            {"op": "remember", "value": {"requestId": original["request_id"], "kind": "fact", "text": original["text"]}},
            {"op": "remember", "value": request},
        ]))
        self.assertEqual(results[1]["memory_id"], old_id)
        self.assertEqual(results[0]["record"], json.loads(old[0]))
        new_id = results[2]["memory_id"]
        response = self.python_vault().handle({"op": "remember", "request_id": request["requestId"], "kind": request["kind"], "text": request["text"], "relations": request["relations"]})
        self.assertTrue(response["ok"], response)
        self.assertEqual(response["result"]["memory_id"], new_id)
        with contextlib.closing(self.python_vault()._connect()) as connection:
            self.assertEqual(tuple(connection.execute("SELECT m.record_json,a.attestation_json FROM memories m JOIN record_admissions a USING(memory_id) WHERE memory_id=?", (old_id,)).fetchone()), old)
            self.assertEqual(connection.execute("SELECT count(*) FROM memories").fetchone()[0], 2)
        conflict = self.run_ts([{"op": "remember", "value": {**request, "text": "changed"}}])
        self.assertEqual(conflict["results"][0]["error"], "request_id_conflict")

    def test_shares_cross_both_directions_with_complete_dependencies_and_exact_bytes(self) -> None:
        parent = self.signed("Dependency root")
        child = self.signed("Selected leaf", relations=[{"type": "derived_from", "target": parent["record"]["memory_id"]}])
        packet = self.packet([child, parent], [child["record"]["memory_id"]])
        self.successful(self.run_ts([{"op": "import", "raw": base64.b64encode(packet).decode(), "options": {"admission": "verified"}}], trust=[self.public]))
        exported = self.successful(self.run_ts([{"op": "export", "roots": [child["record"]["memory_id"]]}]))[0]
        share = self.directory / "ts.share"
        share.write_bytes(base64.b64decode(exported["raw"])); share.chmod(0o600)
        summary = verify_share_bundle(share)
        self.assertEqual((summary.records, summary.selected_records, summary.dependency_records), (2, 1, 1))
        receiver = self.directory / "python-receiver.sqlite3"
        imported = import_share(self.config(receiver), share, verify_signatures=True)
        self.assertEqual(imported["records_added"], 2)
        python_share = self.directory / "python.share"
        export_share(self.config(receiver), python_share, {"schema_version": "universal-memory-selection/v1", "memory_ids": [child["record"]["memory_id"]]})
        target = self.directory / "ts-receiver.sqlite3"
        result = self.successful(self.run_ts([
            {"op": "import", "raw": base64.b64encode(python_share.read_bytes()).decode(), "options": {"admission": "verified"}},
            {"op": "get", "id": parent["record"]["memory_id"]},
            {"op": "get", "id": child["record"]["memory_id"]},
        ], path=target, trust=[self.public]))
        self.assertEqual(result[1], parent); self.assertEqual(result[2], child)
        with sqlite3.connect(target) as connection:
            actual = dict(connection.execute("SELECT memory_id,record_json FROM memories"))
        for item in (parent, child):
            self.assertEqual(actual[item["record"]["memory_id"]].encode(), canonical_bytes(item["record"]))

    def test_quarantine_promotion_replay_and_live_revocation(self) -> None:
        item = self.signed("Never use a receipt as current trust")
        packet = base64.b64encode(self.packet([item])).decode()
        result = self.run_ts([
            {"op": "import", "raw": packet},
            {"op": "get", "id": item["record"]["memory_id"]},
            {"op": "import", "raw": packet, "options": {"admission": "verified"}},
            {"op": "get", "id": item["record"]["memory_id"]},
            {"op": "import", "raw": packet, "options": {"admission": "verified"}},
            {"op": "trust", "value": []},
            {"op": "get", "id": item["record"]["memory_id"]},
            {"op": "import", "raw": packet, "options": {"admission": "verified"}},
        ], trust=[self.public])
        self.assertTrue(result["ok"], result)
        rows = result["results"]
        self.assertIsNone(rows[1]["result"]); self.assertEqual(rows[3]["result"], item)
        self.assertTrue(rows[4]["result"]["receipt_replayed"])
        self.assertIsNone(rows[6]["result"]); self.assertFalse(rows[7]["ok"])
        with sqlite3.connect(self.path) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM memories").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT count(*) FROM delivery_log").fetchone()[0], 2)

    def test_invalid_proof_or_mid_import_revocation_rolls_back_all_records(self) -> None:
        first, second = self.signed("First imported fact"), self.signed("Second imported fact")
        damaged = copy.deepcopy(second)
        raw_signature = bytearray(base64.b64decode(damaged["attestation"]["signature"]))
        raw_signature[0] ^= 1
        damaged["attestation"]["signature"] = base64.b64encode(raw_signature).decode()
        packet = self.packet([first, damaged], [first["record"]["memory_id"], damaged["record"]["memory_id"]])
        failure = self.run_ts([{"op": "import", "raw": base64.b64encode(packet).decode(), "options": {"admission": "verified"}}], trust=[self.public])
        self.assertFalse(failure["results"][0]["ok"], failure)
        with sqlite3.connect(self.path) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM memories").fetchone()[0], 0)
        good = self.packet([first, second], [first["record"]["memory_id"], second["record"]["memory_id"]])
        failure = self.run_ts([{"op": "import", "raw": base64.b64encode(good).decode(), "options": {"admission": "verified"}}], trust_sequence=[[self.public], [self.public], []])
        self.assertFalse(failure["results"][0]["ok"], failure)
        with sqlite3.connect(self.path) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM memories").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT count(*) FROM transfer_receipts").fetchone()[0], 0)

    def test_recall_scan_result_budgets_and_python_index_equivalence(self) -> None:
        requests = [self.request(str(index), "target " + str(index)) for index in range(4)]
        remembered = self.successful(self.run_ts([{"op": "remember", "value": value} for value in requests]))
        page = self.successful(self.run_ts([{"op": "recall", "query": "target", "options": {"limit": 1, "maximumScanned": 2}}]))[0]
        self.assertEqual(len(page["records"]), 1); self.assertEqual(page["scanned"], 1)
        self.assertTrue(page["partial"]); self.assertEqual(page["ranking"], "bounded_text_match")
        next_page = self.successful(self.run_ts([{"op": "recall", "query": "target", "options": {"after": page["nextAfter"], "limit": 4}}]))[0]
        self.assertEqual(len(next_page["records"]), 3)
        tiny = self.successful(self.run_ts([{"op": "recall", "query": "target", "options": {"maximumBytes": 1}}]))[0]
        self.assertEqual(tiny["records"], []); self.assertEqual(tiny["nextAfter"], 0)
        self.assertGreater(tiny["requiredBytes"], 1)
        scan = self.successful(self.run_ts([{"op": "recall", "query": "absent", "options": {"maximumScanned": 2}}]))[0]
        self.assertEqual(scan["scanned"], 2); self.assertTrue(scan["partial"])
        with contextlib.closing(self.python_vault()._connect()) as connection, connection:
            self.assertTrue(Vault._retrieval_index_state(connection)["complete"])
            statements = {
                "terms": "SELECT token,memory_id,frequency FROM terms ORDER BY token,memory_id",
                "entities": "SELECT entity,memory_id FROM memory_entities ORDER BY entity,memory_id",
                "certificate": "SELECT memory_id,profile,token_count,timeline_key FROM retrieval_index ORDER BY memory_id",
            }
            before = {name: [tuple(row) for row in connection.execute(sql)] for name, sql in statements.items()}
            for result in remembered:
                Vault.rebuild_record_index(connection, result["record"])
            self.assertTrue(Vault._retrieval_index_state(connection)["complete"])
            self.assertEqual(before, {name: [tuple(row) for row in connection.execute(sql)] for name, sql in statements.items()})
        repaired = self.successful(self.run_ts([{"op": "recall", "query": "target"}]))[0]
        self.assertEqual(len(repaired["records"]), 4)

    def test_share_limits_fail_closed_and_exact_dependency_closure(self) -> None:
        parent = self.signed("Required ancestor")
        child = self.signed("Child", relations=[{"type": "derived_from", "target": parent["record"]["memory_id"]}])
        packet = base64.b64encode(self.packet([child, parent], [child["record"]["memory_id"]])).decode()
        result = self.run_ts([
            {"op": "import", "raw": packet, "options": {"admission": "verified", "maximumRecords": 1}},
            {"op": "import", "raw": packet, "options": {"admission": "verified", "maximumBytes": 1}},
        ])
        self.assertEqual([row["error"] for row in result["results"]], ["share_record_limit", "share_too_large"])
        with sqlite3.connect(self.path) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM memories").fetchone()[0], 0)
        self.successful(self.run_ts([{"op": "import", "raw": packet, "options": {"admission": "verified"}}]))
        failed = self.run_ts([{"op": "export", "roots": [child["record"]["memory_id"]], "options": {"maximumRecords": 1}}])
        self.assertEqual(failed["results"][0]["error"], "share_record_limit")

    def test_revoked_author_cannot_write_or_read_through_remember_receipt(self) -> None:
        request = self.request("revoked")
        rejected = self.run_ts([{"op": "remember", "value": request}], trust=[])
        self.assertEqual(rejected["results"][0]["error"], "unknown_key")
        with sqlite3.connect(self.path) as connection:
            for table in ("memories", "receipts", "delivery_log"):
                self.assertEqual(connection.execute("SELECT count(*) FROM " + table).fetchone()[0], 0)
        rejected = self.run_ts([{"op": "remember", "value": request}], trust_sequence=[[self.public], [self.public], []])
        self.assertEqual(rejected["results"][0]["error"], "unknown_key")
        with sqlite3.connect(self.path) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM memories").fetchone()[0], 0)
        original = self.successful(self.run_ts([{"op": "remember", "value": request}]))[0]
        replay = self.run_ts([{"op": "remember", "value": request}], trust=[])
        self.assertEqual(replay["results"][0]["error"], "unknown_key")
        metadata = self.successful(self.run_ts([{"op": "verification", "id": original["memory_id"]}], trust=[]))[0]
        self.assertTrue(metadata["signature_verified_at_admission"])
        self.assertTrue(metadata["current_trust_checked"])
        self.assertFalse(metadata["eligible_for_context"])
        self.assertFalse(metadata["grants_authority"])

    def test_cooperative_time_budget_rolls_back_write_and_bounds_scan(self) -> None:
        written = self.run_ts([
            {"op": "clock-step", "value": 6000},
            {"op": "remember", "value": self.request("budget")},
        ])
        self.assertEqual(written["results"][1]["error"], "vault_work_limit")
        with sqlite3.connect(self.path) as connection:
            for table in ("memories", "receipts", "delivery_log"):
                self.assertEqual(connection.execute("SELECT count(*) FROM " + table).fetchone()[0], 0)
        self.successful(self.run_ts([{"op": "remember", "value": self.request("afterbudget")}]))
        limited = self.successful(self.run_ts([
            {"op": "clock-step", "value": 6000},
            {"op": "recall", "query": "Synthetic"},
        ]))[1]
        self.assertEqual(limited["scanned"], 0)
        self.assertTrue(limited["partial"])
        self.assertEqual(limited["nextAfter"], 0)

    def test_python_writer_lock_is_bounded_retryable_and_does_not_duplicate(self) -> None:
        self.successful(self.run_ts([{"op": "remember", "value": self.request("beforelock")}]))
        request = self.request("afterlock")
        with contextlib.closing(sqlite3.connect(self.path)) as connection:
            connection.execute("BEGIN IMMEDIATE")
            start = time.monotonic()
            rejected = self.run_ts([{"op": "remember", "value": request}])
            self.assertLess(time.monotonic() - start, 8)
            self.assertEqual(rejected["error"], "busy", rejected)
            self.assertTrue(rejected["retryable"])
            self.assertEqual(connection.execute("SELECT count(*) FROM memories").fetchone()[0], 1)
            connection.rollback()
        results = self.successful(self.run_ts([{"op": "remember", "value": request}, {"op": "remember", "value": request}]))
        self.assertEqual(results[0]["memory_id"], results[1]["memory_id"])
        with sqlite3.connect(self.path) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM memories").fetchone()[0], 2)

    def test_private_paths_symlinks_and_changed_executable_schema_rejected(self) -> None:
        original = self.successful(self.run_ts([{"op": "remember", "value": self.request("safe")}]))[0]
        link = self.directory / "link.sqlite3"; link.symlink_to(self.path)
        rejected = self.run_ts([], path=link)
        self.assertFalse(rejected["ok"], rejected)
        self.path.chmod(0o644)
        rejected = self.run_ts([])
        self.assertFalse(rejected["ok"], rejected)
        self.path.chmod(0o600)
        live = self.run_ts([
            {"op": "foreign-trigger"},
            {"op": "remember", "value": self.request("unsafe")},
            {"op": "get", "id": original["memory_id"]},
        ])
        self.assertEqual(live["results"][1]["error"], "unsupported_database_schema")
        self.assertEqual(live["results"][2]["error"], "unsupported_database_schema")
        with sqlite3.connect(self.path) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM memories").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT count(*) FROM receipts").fetchone()[0], 1)
        self.assertEqual(self.run_ts([])["error"], "unsupported_database_schema")


if __name__ == "__main__":
    unittest.main()
