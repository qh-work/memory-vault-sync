"""Native TS/Python alternate on the same protected synthetic transport DB."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from memory_vault import MemoryError, canonical_bytes
from memory_vault_network_crypto import EncryptionIdentity
from memory_vault_open_control import contact_key, issue_contact, issue_node, issue_lease, sign_request
from memory_vault_open_index import OpenIndex
from memory_vault_open_node import _TransportState
from memory_vault_open_state import OpenCheckpoints, RESERVED_BYTES_PER_FLOOR
from tests import test_network_typescript_agent_network as ts_runtime
from tests.test_open_typescript import synthetic_identity


DRIVER = r"""
import child from 'node:child_process';
import {syncBuiltinESMExports} from 'node:module';
let subprocessCalls=0;
const deny=()=>{subprocessCalls++;throw Error('native state cannot delegate');};
for(const name of ['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork'])child[name]=deny;
syncBuiltinESMExports();
const {OpenCheckpoints,OpenIndex}=await import('./open-state.ts');
const {openPrivateDatabase}=await import('./io.ts');
const parts=[];let bytes=0;
for await(const part of process.stdin){bytes+=part.length;if(bytes>2097152)throw Error('synthetic input limit');parts.push(part);}
const input=JSON.parse(Buffer.concat(parts).toString('utf8'));
let db=openPrivateDatabase(input.database),options=input.options??{};
const construct=()=>input.mode==='state'?new OpenCheckpoints(db,options):new OpenIndex(db,input.signer,input.node,options);
let service=construct();service.initialize();const results=[];
try {
  for(const event of input.events){
    try{
      let value=null;
      if(event.op==='reopen'){db.close();db=openPrivateDatabase(input.database);service=construct();service.initialize();}
      else if(event.op==='configure'){options=event.options;service=construct();}
      else if(event.op==='trigger')db.exec(`CREATE TRIGGER synthetic_failure BEFORE INSERT ON ${input.mode==='state'?'open_control_floors':'open_contacts'} BEGIN SELECT RAISE(ABORT,'synthetic interruption'); END`);
      else if(event.op==='clear_trigger')db.exec('DROP TRIGGER synthetic_failure');
      else if(event.op==='accept')value=service.accept(event.document,{now:event.now});
      else if(event.op==='handle')value=service.handle(event.request,{now:event.now});
      else throw Error('unknown synthetic operation');
      results.push({ok:true,value});
    }catch(error){results.push({ok:false,code:error.code??'untyped_error',retryable:error.retryable??false});}
  }
}finally{db.close();}
process.stdout.write(JSON.stringify({results,subprocessCalls}));
"""


class OpenTypeScriptStateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ts_runtime.TypeScriptAgentNetworkTests.setUpClass.__func__(cls)
        cls.node_runtime = cls.node
        (cls.fixture / "driver.mjs").write_text(DRIVER)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="memory-open-native-state-synthetic-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.now = 2_000_000_000
        self.server, self.server_doc = synthetic_identity("state server")
        self.owner, self.owner_doc = synthetic_identity("state owner")
        self.other, self.other_doc = synthetic_identity("state other")
        self.node_document = self.make_node()
        self.encryption = EncryptionIdentity.generate()
        self.contact = self.contact_document()
        self.store = _TransportState(self.root / "transport", self.server, "synthetic_epoch")
        with self.store.db() as db:
            db.execute("CREATE TABLE original_transport_marker(value TEXT)")
            db.execute("INSERT INTO original_transport_marker VALUES('synthetic preserved transport')")

    def make_node(self, *, signer=None, **changes):
        values = dict(base_url="http://127.0.0.1:18501", storage_epoch="synthetic_epoch",
                      roles=["directory", "router"], revision=1, issued_at=self.now, expires_at=self.now + 3600)
        values.update(changes)
        return issue_node(signer or self.server, **values)

    def contact_document(self, **changes):
        values = dict(encryption_key=self.encryption.public_descriptor(), revision=1,
                      allow_discovery=True, endpoints=[], issued_at=self.now, expires_at=self.now + 3600)
        values.update(changes)
        return issue_contact(self.owner, **values)

    def request(self, action, body, *, request_id="synthetic_native_request", now=None, signer=None):
        current = self.now if now is None else now
        return sign_request(signer or self.owner, action=action, body=body, node=self.node_document,
                            request_id=request_id, issued_at=current, expires_at=current + 60)

    def ts(self, mode, events, **values):
        process = subprocess.run([type(self).node_runtime, "--experimental-strip-types", str(self.fixture / "driver.mjs")],
            input=json.dumps(dict(database=str(self.store.directory / "network.sqlite3"), mode=mode,
                                  signer=self.server_doc, node=self.node_document, events=events, **values)).encode(),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=self.fixture, timeout=15)
        self.assertEqual(process.returncode, 0, process.stderr.decode(errors="replace")[-6000:])
        result = json.loads(process.stdout)
        self.assertEqual(result["subprocessCalls"], 0)
        return result["results"]

    def test_python_floor_ts_restart_then_python_sees_exact_higher_signed_record(self):
        higher = self.make_node(revision=2)
        with self.store.db() as db:
            state = OpenCheckpoints(db); state.initialize(); state.accept(higher, now=self.now)
        highest = self.make_node(revision=3)
        result = self.ts("state", [dict(op="accept", document=self.node_document, now=self.now),
            dict(op="accept", document=highest, now=self.now), dict(op="reopen"),
            dict(op="accept", document=higher, now=self.now), dict(op="accept", document=self.contact, now=self.now)])
        self.assertEqual(result[0]["code"], "open_control_rollback")
        self.assertTrue(result[1]["ok"], result)
        self.assertEqual(result[3]["code"], "open_control_rollback")
        self.assertTrue(result[4]["ok"], result)
        with self.store.db() as db:
            self.assertEqual(bytes(db.execute("SELECT record FROM open_control_floors WHERE kind='node'").fetchone()[0]), canonical_bytes(highest))
            self.assertEqual(db.execute("SELECT value FROM original_transport_marker").fetchone()[0], "synthetic preserved transport")
            self.assertEqual(OpenCheckpoints(db).accept(self.contact, now=self.now), self.contact["payload"])

    def test_native_full_reserved_fork_blocks_python_and_higher_revision(self):
        fork = self.make_node(base_url="http://127.0.0.1:18502")
        result = self.ts("state", [dict(op="accept", document=self.node_document, now=self.now),
            dict(op="accept", document=fork, now=self.now), dict(op="reopen"),
            dict(op="accept", document=self.make_node(revision=2), now=self.now),
            dict(op="accept", document=self.make_node(signer=self.other), now=self.now)],
            options=dict(maximum_records=1, maximum_bytes=RESERVED_BYTES_PER_FLOOR))
        self.assertTrue(result[0]["ok"], result)
        self.assertEqual(result[1]["code"], "open_control_conflict")
        self.assertEqual(result[3]["code"], "open_control_conflict")
        self.assertEqual(result[4]["code"], "open_checkpoint_capacity")
        with self.store.db() as db:
            row = db.execute("SELECT record,second_record FROM open_control_floors").fetchone()
            self.assertEqual((bytes(row[0]), bytes(row[1])), (canonical_bytes(self.node_document), canonical_bytes(fork)))
            with self.assertRaisesRegex(MemoryError, "open_control_conflict"):
                OpenCheckpoints(db).accept(self.make_node(revision=3), now=self.now)

    def test_python_index_lease_native_replay_renew_exact_bytes_and_python_read(self):
        request = self.request("put", {"contact": self.contact, "lease_seconds": 120})
        with self.store.db() as db:
            index = OpenIndex(db, self.server, self.node_document, enabled=True); index.initialize()
            first = index.handle(request, now=self.now)
        lease_id = first["lease"]["payload"]["lease_id"]
        renewal = self.request("renew", {"contact": self.contact, "lease_seconds": 200, "lease_id": lease_id},
                               request_id="synthetic_native_renew", now=self.now + 10)
        expected = issue_lease(self.server, node=self.node_document, contact=self.contact, request=renewal,
                               lease_id=lease_id, issued_at=self.now + 10, expires_at=self.now + 210)
        get = self.request("get", {"key": contact_key(self.owner.key_id)}, now=self.now + 10)
        result = self.ts("index", [dict(op="handle", request=request, now=self.now),
            dict(op="handle", request=renewal, now=self.now + 10), dict(op="reopen"),
            dict(op="handle", request=get, now=self.now + 10)], options=dict(enabled=True))
        self.assertEqual(canonical_bytes(result[0]["value"]), canonical_bytes(first))
        self.assertEqual(canonical_bytes(result[1]["value"]["lease"]), canonical_bytes(expected))
        self.assertEqual(canonical_bytes(result[3]["value"]["contact"]), canonical_bytes(self.contact))
        with self.store.db() as db:
            value = OpenIndex(db, self.server, self.node_document, enabled=True).handle(get, now=self.now + 10)
            self.assertEqual(canonical_bytes(value["lease"]), canonical_bytes(expected))

    def test_native_index_lease_python_replay_and_expiry_do_not_erase_floor(self):
        request = self.request("put", {"contact": self.contact, "lease_seconds": 30})
        result = self.ts("index", [dict(op="handle", request=request, now=self.now)], options=dict(enabled=True))
        self.assertTrue(result[0]["ok"], result)
        with self.store.db() as db:
            index = OpenIndex(db, self.server, self.node_document, enabled=True)
            replay = index.handle(request, now=self.now + 1)
            self.assertEqual(canonical_bytes(replay), canonical_bytes(result[0]["value"]))
            get = self.request("get", {"key": contact_key(self.owner.key_id)}, now=self.now + 30)
            self.assertEqual(index.handle(get, now=self.now + 30), {"state": "not_found"})
            self.assertEqual(db.execute("SELECT count(*) FROM open_contact_floors").fetchone()[0], 1)

    def test_native_capacity_sql_failure_revocation_and_owner_checks(self):
        request = self.request("put", {"contact": self.contact, "lease_seconds": 120})
        foreign = self.request("put", {"contact": self.contact, "lease_seconds": 120}, signer=self.other,
                               request_id="synthetic_native_foreign")
        closed = self.ts("index", [dict(op="handle", request=request, now=self.now)])
        self.assertEqual(closed[0]["code"], "open_index_closed")
        limited = self.ts("index", [dict(op="handle", request=request, now=self.now)],
                          options=dict(enabled=True, maximum_bytes=1))
        self.assertEqual(limited[0]["code"], "open_index_capacity")
        with self.store.db() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM open_contact_floors").fetchone()[0], 0)
        result = self.ts("index", [dict(op="handle", request=foreign, now=self.now), dict(op="trigger"),
            dict(op="handle", request=request, now=self.now), dict(op="clear_trigger")], options=dict(enabled=True))
        self.assertEqual(result[0]["code"], "open_index_not_owner")
        self.assertFalse(result[2]["ok"])
        with self.store.db() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM open_contact_floors").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT count(*) FROM open_index_replay").fetchone()[0], 0)
        revoked = self.contact_document(revision=2, status="revoked", allow_discovery=False)
        revocation = self.request("put", {"contact": revoked, "lease_seconds": 120}, request_id="synthetic_native_revoke")
        rollback = self.request("put", {"contact": self.contact, "lease_seconds": 120}, request_id="synthetic_native_rollback")
        get = self.request("get", {"key": contact_key(self.owner.key_id)})
        result = self.ts("index", [dict(op="handle", request=request, now=self.now),
            dict(op="handle", request=revocation, now=self.now), dict(op="reopen"),
            dict(op="handle", request=rollback, now=self.now), dict(op="handle", request=get, now=self.now)], options=dict(enabled=True))
        self.assertTrue(result[0]["ok"], result)
        self.assertEqual(result[3]["code"], "open_contact_rollback")
        self.assertEqual(result[4]["value"], {"state": "revoked"})
        with self.store.db() as db:
            self.assertEqual(OpenIndex(db, self.server, self.node_document, enabled=True).handle(get, now=self.now), {"state": "revoked"})

    def test_native_index_fork_remains_blocked_after_reopen_and_higher_revision(self):
        request = self.request("put", {"contact": self.contact, "lease_seconds": 120})
        fork = self.contact_document(allow_discovery=False)
        fork_request = self.request("put", {"contact": fork, "lease_seconds": 120}, request_id="synthetic_native_fork")
        higher = self.request("put", {"contact": self.contact_document(revision=2), "lease_seconds": 120}, request_id="synthetic_native_higher")
        get = self.request("get", {"key": contact_key(self.owner.key_id)})
        result = self.ts("index", [dict(op="handle", request=request, now=self.now),
            dict(op="handle", request=fork_request, now=self.now), dict(op="reopen"),
            dict(op="handle", request=higher, now=self.now), dict(op="handle", request=get, now=self.now)], options=dict(enabled=True))
        self.assertEqual(result[1]["code"], "open_contact_conflict")
        self.assertEqual(result[3]["code"], "open_contact_conflict")
        self.assertEqual(result[4]["value"], {"state": "conflict"})
        with self.store.db() as db:
            row = db.execute("SELECT record,second_record FROM open_contact_floors").fetchone()
            self.assertEqual((bytes(row[0]), bytes(row[1])), (canonical_bytes(self.contact), canonical_bytes(fork)))


if __name__ == "__main__":
    unittest.main()
