"""Native recipient uploads its actual receipt and checks the returned storage event."""
import base64
import json
import unittest
from unittest.mock import patch

from tests import test_open_repair_offer_client_typescript as offer_ts
from tests import test_open_repair_put_client as put_py
from tests import test_open_repair_probe_typescript as probe_ts
from tests.test_open_repair_occupied import receipt_inputs

DRIVER=offer_ts.DRIVER.replace("const {AckOfferClient}=", "const {AckReceiptClient}=").replace('new AckOfferClient(', 'new AckReceiptClient(')
DRIVER=DRIVER.replace("calls.push(JSON.parse(Buffer.from(raw).toString()).payload.kind);","const packet=JSON.parse(Buffer.from(raw).toString());calls.push(packet.payload?.kind??packet.kind);")
DRIVER=DRIVER.replace("const input=JSON.parse", "const journal=[];\nconst input=JSON.parse")
DRIVER=DRIVER.replace("return request(base,raw,...rest);", """const response=await request(base,raw,...rest);
  if(input.corruptReply&&calls.at(-1)==='ack.put_request'){
    const body=JSON.parse(Buffer.from(response).toString());body.commit.ref.raw_sha256='0'.repeat(64);
    const {canonicalBytes}=await import('./crypto.ts');return canonicalBytes(body);
  }return response;""")
DRIVER=DRIVER.replace("['knownStatuses','archiveStatuses']", "['knownStatuses','archiveStatuses','knownDisclosureStatuses','currentStatuses']")
DRIVER=DRIVER.replace('const result=await client.preflight(input.base,options);', """options.journal=async(kind,raw)=>{
    journal.push({kind,raw:Buffer.from(raw).toString('base64'),calls:[...calls]});
    if(input.failJournal&&kind==='request')throw Error('synthetic journal unavailable');
    if(input.blockJournal&&kind==='request')await new Promise(()=>{});
  };
  const result=await client.put(input.base,decode(input.receipt),decode(input.disclosure),decode(input.put),options);""")
start=DRIVER.index('  process.stdout.write(JSON.stringify({ok:true')
end=DRIVER.index('\n}catch(error)',start)
DRIVER=DRIVER[:start]+'''  process.stdout.write(JSON.stringify({ok:true,metrics:result.metrics,
    receipt:Buffer.from(result.source.inputs.receipt.raw).toString('base64'),commit:result.source.commit.ref,
    immutable:Buffer.from(original.raw).toString('hex')===before,calls,nativeChecks,subprocessCalls,journal}));'''+DRIVER[end:]
DRIVER=DRIVER.replace('calls,nativeChecks,subprocessCalls}));}', 'calls,nativeChecks,subprocessCalls,journal}));}')


class NativePutClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        offer_ts.NativeOfferClientTests.setUpClass.__func__(cls)
        (cls.fixture/'driver.mjs').write_text(DRIVER)

    def setUp(self):
        self.case=put_py.RepairPutClientTests();self.addCleanup(self.case.doCleanups)
        if self._testMethodName=='test_bad_returned_commit_cannot_claim_verified_storage':
            # One original finite grant funds both the upload and exact replay.
            with patch.object(put_py.offer_fixture.RepairOfferClientTests,'fixture_limits',dict(proof_limit=524288),create=True):self.case.setUp()
        else:self.case.setUp()
        self.host=self.case.host;self.f=self.host.f

    def call(self,inputs=None,**extra):
        value=offer_ts.NativeOfferClientTests.call(self)
        receipt,disclosure,put,options=inputs or self.case.inputs
        value.update(receipt=probe_ts.encoded(receipt),disclosure=probe_ts.encoded(disclosure),put=probe_ts.encoded(put),now=2_000_000_008,**extra)
        value['policy']=dict(value['policy'],max_signature_checks=96)
        value['options'].update(currentStatuses=[probe_ts.encoded(item) for item in options['current_statuses']],readUntil=options['read_until'],retainUntil=options['retain_until'])
        return value

    native=offer_ts.NativeOfferClientTests.native

    def test_native_upload_saves_exact_receipt_and_records_request_before_network(self):
        self.host.http.restart();result=self.native(self.call())
        self.assertTrue(result['ok'],{k:v for k,v in result.items() if k!='journal'});self.assertTrue(result['immutable'])
        self.assertEqual(result['receipt'],probe_ts.encoded(self.case.inputs[0])['raw'])
        self.assertEqual(result['metrics']['requests'],13)
        self.assertEqual(result['nativeChecks'],result['metrics']['signature_checks'])
        self.assertEqual([item['kind'] for item in result['journal']],['request','response'])
        self.assertNotIn('ack.put_request',result['journal'][0]['calls']);self.assertEqual(result['calls'][-1],'ack.put_request')
        self.assertEqual(self.host.source.db.execute('SELECT status FROM open_repair_ack_resources').fetchone()[0],'occupied')

    def test_legacy_disclosure_does_not_send_receipt(self):
        from memory_vault_open_repair_occupied import RETURN_ROLES_LEGACY
        inputs=receipt_inputs(self.case.fixture,bootstrap_roles=RETURN_ROLES_LEGACY)
        result=self.native(self.call(inputs));self.assertFalse(result['ok']);self.assertEqual(result['code'],'repair_disclosure_permission')
        self.assertNotIn('ack.put_request',result['calls'])

    def test_original_signature_budget_covers_preflight_and_upload_together(self):
        value=self.call();value['policy']['max_signature_checks']=64
        result=self.native(value);self.assertFalse(result['ok']);self.assertEqual(result['code'],'repair_over_budget')
        self.assertNotIn('ack.put_request',result['calls'])

    def test_journal_failure_stops_before_private_upload(self):
        result=self.native(self.call(failJournal=True));self.assertFalse(result['ok'])
        self.assertNotIn('ack.put_request',result['calls'])
        self.assertEqual(self.host.source.db.execute('SELECT status FROM open_repair_ack_resources').fetchone()[0],'empty')

    def test_unfinished_journal_obeys_original_deadline_without_upload(self):
        value=self.call(blockJournal=True);value['options']['timeout']=8
        result=self.native(value);self.assertFalse(result['ok']);self.assertEqual(result['code'],'repair_access_expired')
        self.assertEqual([item['kind'] for item in result['journal']],['request'])
        self.assertNotIn('ack.put_request',result['calls'])

    def test_bad_returned_commit_cannot_claim_verified_storage(self):
        result=self.native(self.call(corruptReply=True));self.assertFalse(result['ok'])
        self.assertEqual(result['code'],'repair_ref_mismatch')
        self.assertEqual([item['kind'] for item in result['journal']],['request'])
        self.assertEqual(self.host.source.db.execute('SELECT status FROM open_repair_ack_resources').fetchone()[0],'occupied')
        # The exact native journal is interoperable with the existing durable
        # Python recovery path; no second probe or replacement put is created.
        receipt,disclosure,put,options=self.case.inputs
        recovered=self.case.client().resume(self.host.http.base,base64.b64decode(result['journal'][0]['raw']),
            receipt,disclosure,put,**options,**self.case.case.args)
        self.assertEqual(recovered.source.inputs['receipt'].raw,receipt['raw'])
        self.assertEqual(recovered.metrics['requests'],1)
        self.assertEqual(self.host.source.db.execute('SELECT count(*) FROM open_repair_put_requests').fetchone()[0],1)



if __name__=='__main__':unittest.main()
