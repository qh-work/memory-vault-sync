"""Mailbox prefix boundaries against an independent complete synthetic tree."""
import copy
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from memory_vault import canonical_bytes
import memory_vault_open_repair_mailbox_range as tree
from memory_vault_open_repair_state import DEFAULT_POLICY as POLICY
from memory_vault_open_repair_wire import RepairBudget, RepairWireError
from tests.open_repair_resource_fixtures import ack_resource_fixture


class MailboxRangeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        docs, _, expected, _, _ = ack_resource_fixture(include_encryption=True)
        root = copy.deepcopy(docs["allocate"]["payload"]["intent"]["root_key"])
        root["root_kind"] = "mailbox"
        target = docs["allocate"]["payload"]["intent"]["target"]
        cls.slot = dict(root_key=root,slot_id="synthetic_range",writer={
            "signing_key_id":target["signing_key"]["key_id"],"encryption_key_id":target["encryption_key"]["key_id"]},
            writer_storage_epoch="synthetic_epoch")
        cls.binding = hashlib.sha256(b"memory-vault-mailbox-slot/v1\x00"+canonical_bytes(cls.slot)).hexdigest()
        binding = bytes.fromhex(cls.binding)
        cls.sealed = [hashlib.sha256(("synthetic sealed core "+str(i)).encode()).hexdigest() for i in range(65536)]
        cls.levels = [[hashlib.sha256(b"memory-vault-mailbox-leaf/v1\x00"+binding+
            i.to_bytes(4,"big")+bytes.fromhex(digest)).hexdigest() for i,digest in enumerate(cls.sealed)]]
        cls.empty = [hashlib.sha256(b"memory-vault-mailbox-empty/v1\x00"+binding).hexdigest()]
        for height in range(1,17):
            prev = cls.levels[-1]
            cls.levels.append([cls.parent(height,prev[i],prev[i+1]) for i in range(0,len(prev),2)])
            cls.empty.append(cls.parent(height,cls.empty[-1],cls.empty[-1]))

    @classmethod
    def parent(cls,height,left,right):
        return hashlib.sha256(b"memory-vault-mailbox-node/v1\x00"+bytes.fromhex(cls.binding)+bytes([height])+
            bytes.fromhex(left)+bytes.fromhex(right)).hexdigest()

    @classmethod
    def prefix(cls,count,height=16,start=0):
        if start>=count:
            return cls.empty[height]
        if start+(1<<height)<=count:
            return cls.levels[height][start>>height]
        return cls.parent(height,cls.prefix(count,height-1,start),cls.prefix(count,height-1,start+(1<<(height-1))))

    @classmethod
    def reference(cls,count):
        return dict(slot_binding=cls.binding,count=count,leaf_root=cls.prefix(count),
            frontier=[cls.levels[h][(count>>(h+1))<<1] if count&(1<<h) else None for h in range(17)])

    def append(self,state,digest,slot=None):
        return tree.append(state,digest,expected_slot=slot or self.slot,policy=POLICY,budget=RepairBudget(POLICY))

    def path(self,count,sequence):
        return [self.prefix(count,h,((sequence>>h)^1)<<h) for h in range(16)]

    def test_empty_small_boundaries_and_complete_frontier(self):
        current = tree.empty_state(self.slot,policy=POLICY,budget=RepairBudget(POLICY))
        self.assertEqual(current,self.reference(0))
        for count in range(1,18):
            current = self.append(current,self.sealed[count-1])
            if count in (1,15,16,17):
                self.assertEqual(current,self.reference(count))
        self.assertEqual(self.append(self.reference(65535),self.sealed[65535]),self.reference(65536))
        with self.assertRaisesRegex(RepairWireError,"repair_mailbox_full"):
            self.append(self.reference(65536),self.sealed[0])

    def test_inclusion_rejects_substitution_and_absent_sequence(self):
        for count,sequence in ((1,0),(17,0),(17,15),(17,16),(65536,65535)):
            with self.subTest(count=count,sequence=sequence):
                options=dict(expected_slot=self.slot,policy=POLICY)
                self.assertTrue(tree.verify_inclusion(self.reference(count),sequence,self.sealed[sequence],
                    self.path(count,sequence),budget=RepairBudget(POLICY),**options))
                with self.assertRaises(RepairWireError):
                    tree.verify_inclusion(self.reference(count),sequence,"0"*64,self.path(count,sequence),
                        budget=RepairBudget(POLICY),**options)
        with self.assertRaises(RepairWireError):
            tree.verify_inclusion(self.reference(17),17,self.sealed[17],self.path(17,17),
                expected_slot=self.slot,policy=POLICY,budget=RepairBudget(POLICY))

    def test_cross_slot_and_malformed_frontier_cannot_extend(self):
        other = copy.deepcopy(self.slot); other["slot_id"]="synthetic_other"
        with self.assertRaises(RepairWireError):
            self.append(self.reference(1),self.sealed[1],other)
        for changes in ({"count":True},{"count":65537},{"frontier":[None]*16},
                        {"frontier":["0"*64]*17},{"leaf_root":"0"*64}):
            with self.subTest(changes=changes),self.assertRaises(RepairWireError):
                self.append({**self.reference(1),**changes},self.sealed[1])

    def test_native_matches_every_boundary_and_full_count(self):
        node=os.environ.get("MEMORY_VAULT_NODE") or shutil.which("node")
        if not node:
            self.skipTest("Existing Node >=22.19 required")
        version=subprocess.check_output([node,"--version"],text=True).strip().lstrip("v")
        if tuple(map(int,version.split(".")[:2]))<(22,19):
            self.skipTest("Existing Node >=22.19 required")
        source=Path(__file__).resolve().parents[1]/"clients/typescript/network"
        with tempfile.TemporaryDirectory(prefix="synthetic-mailbox-native-range-") as folder:
            folder=Path(folder)
            for name in ("open-repair-wire.ts","open-repair-mailbox-range.ts"):
                shutil.copyfile(source/name,folder/name)
            (folder/"package.json").write_text('{"type":"module"}')
            (folder/"driver.mjs").write_text('''
import * as r from './open-repair-mailbox-range.ts';
import {RepairBudget} from './open-repair-wire.ts';
const chunks=[];for await(const c of process.stdin)chunks.push(c);
const input=JSON.parse(Buffer.concat(chunks).toString()),results=[];
for(const c of input.cases){const b=new RepairBudget(input.policy);try{
const value=c.op==='empty'?r.emptyMailboxState(input.slot,input.policy,b):
c.op==='append'?r.appendMailboxState(c.state,c.sealed,input.slot,input.policy,b):
r.verifyMailboxInclusion(c.state,c.sequence,c.sealed,c.path,input.slot,input.policy,b);
results.push({ok:true,value});}catch(e){results.push({ok:false,code:e.code??'untyped_error'});}}
process.stdout.write(JSON.stringify(results));
''')
            counts=(0,1,14,15,16,65535)
            cases=[dict(op="empty")]+[dict(op="append",state=self.reference(n),sealed=self.sealed[n]) for n in counts]
            cases += [dict(op="append",state=self.reference(65536),sealed=self.sealed[0]),
                dict(op="verify",state=self.reference(17),sequence=16,sealed=self.sealed[16],path=self.path(17,16)),
                dict(op="verify",state=self.reference(17),sequence=16,sealed=self.sealed[0],path=self.path(17,16))]
            run=subprocess.run([node,"--experimental-strip-types",str(folder/"driver.mjs")],
                input=json.dumps(dict(policy=asdict(POLICY),slot=self.slot,cases=cases)).encode(),
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,cwd=folder)
            self.assertEqual(run.returncode,0,run.stderr.decode())
            results=json.loads(run.stdout)
            self.assertEqual(results[0],dict(ok=True,value=self.reference(0)))
            for index,count in enumerate(counts,1):
                self.assertEqual(results[index],dict(ok=True,value=self.reference(count+1)))
            self.assertEqual(results[-3],dict(ok=False,code="repair_mailbox_full"))
            self.assertEqual(results[-2],dict(ok=True,value=True))
            self.assertEqual(results[-1],dict(ok=False,code="repair_mailbox_range_mismatch"))


if __name__ == "__main__":
    unittest.main()
