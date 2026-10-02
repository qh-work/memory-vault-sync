"""Native reconstruction of exact historical COPY, without Python delegation."""
import json
import subprocess
import unittest
from tests import test_network_typescript_agent_network as runtime
from tests import test_open_repair_mailbox_message_copy as fixtures

DRIVER=runtime.DRIVER.split('const {Agent}',1)[0]+r'''
import {RepairBudget,LocalRawResolver} from './open-repair-wire.ts';
import {DEFAULT_REPAIR_CLIENT_POLICY} from './open-repair-client.ts';
import {verifyMailboxMessageReplica} from './open-repair-mailbox-replica.ts';
const parts=[];let size=0;for await(const p of process.stdin){size+=p.length;if(size>1048576)throw Error('finite fixture input');parts.push(p);}
const v=JSON.parse(Buffer.concat(parts)),decode=e=>({ref:e.ref,raw:Buffer.from(e.raw_base64url,'base64url')}),results=[];
for(const change of v.contexts){try{const policy={...DEFAULT_REPAIR_CLIENT_POLICY,max_signature_checks:512},budget=new RepairBudget(policy),resolver=new LocalRawResolver(policy,budget);
  for(const item of v.originals){const e=decode(item);resolver.put(e.ref.namespace,e.ref.key,e.raw);}
  const result=verifyMailboxMessageReplica(decode(v.manifest),resolver,decode(v.custody),{...change,policy,budget});
  results.push({ok:true,envelope:result.source.message_scope.envelope_ref,originals:result.entries.size,read_until:result.authority.read_until});
}catch(error){results.push({ok:false,code:error.code??error.name});}}
process.stdout.write(JSON.stringify({results,subprocessCalls}));
'''

class NativeMessageReplicaProofTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        runtime.TypeScriptAgentNetworkTests.setUpClass.__func__(cls)
        (cls.fixture/'driver.mjs').write_text(DRIVER)

    def run_fixture(self,inspect):
        return fixtures.MailboxMessageCopyTests.run_fixture(self,inspect)

    def test_full_original_closure_and_independent_expected_bindings(self):
        def inspect(h):
            custody=h.commit();replica=h.store.restore_message(h.rid,**h.context())
            manifest_ref=json.loads(custody['raw'])['payload']['replica_manifest_ref']
            manifest=h.wrap(h.store.read_local_original(h.rid,manifest_ref))
            originals={json.dumps(e['ref'],sort_keys=True):e for values in replica['entries'].values() for e in values}
            context=dict(expectedSlot=h.slot,expectedOwner=h.owner,expectedSender=h.sender,expectedSource=h.source.target,
                sourceStorageEpoch=h.slot['writer_storage_epoch'],expectedMaintainer=h.source.target,expectedTarget=h.target,
                targetStorageEpoch=h.node['payload']['storage_epoch'],expectedEnvelopeRef=h.envelope_ref,limitPolicy=h.limits)
            changes=[context]
            for name,value in (('sourceStorageEpoch','synthetic_replaced_source'),('targetStorageEpoch','synthetic_replaced_target'),
                               ('expectedSource',h.target),('expectedSender',h.owner),('expectedMaintainer',h.owner)):
                changes.append(dict(context,**{name:value}))
            bad=json.loads(json.dumps(context));bad['expectedEnvelopeRef']['raw_sha256']='f'*64;changes.append(bad)
            result=subprocess.run([self.node,'--experimental-strip-types',str(self.fixture/'driver.mjs')],cwd=self.fixture,
                input=json.dumps(dict(manifest=h.encode(manifest),custody=h.encode(custody),originals=[h.encode(e) for e in originals.values()],contexts=changes)).encode(),
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
            self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace')[-2000:]);out=json.loads(result.stdout)
            self.assertEqual(out['subprocessCalls'],0);self.assertTrue(out['results'][0]['ok'],out)
            self.assertEqual(out['results'][0]['envelope'],h.envelope_ref)
            self.assertTrue(all(not row['ok'] for row in out['results'][1:]),out)
        self.run_fixture(inspect)

if __name__=='__main__':unittest.main()
