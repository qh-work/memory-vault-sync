"""Native sender retains exact drafts, submits actual HTTP and reopens in Python."""
import json
import sqlite3
import subprocess
import unittest
from pathlib import Path
from tests import test_open_delivery_http as fixtures
from tests import test_open_ack_typescript_agent as runtime

class NativeMailboxSenderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        runtime.NativeAckAgentTests.setUpClass.__func__(cls)
        driver=runtime.DRIVER.replace("const {Agent}", "const {NetworkError}=await import('./io.ts');\nconst {Agent}",1)
        driver=driver.replace("const result=await original.apply(this,args);", "const result=await original.apply(this,args);\n    if(name==='requestRepair'&&input.lose_reply)throw new NetworkError('open_network_unavailable',true);")
        (cls.fixture/'driver.mjs').write_text(driver)

    def native(self,agent,request,lose=False,no_network=False):
        run=subprocess.run([self.node,'--experimental-strip-types',str(self.fixture/'driver.mjs')],cwd=self.fixture,
            input=json.dumps(dict(client_config=str(agent.client_config),network_config=str(agent.network_config),requests=[request],lose_reply=lose,no_network=no_network)).encode(),
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=45)
        self.assertEqual(run.returncode,0,run.stderr.decode(errors='replace')[-2500:])
        result=json.loads(run.stdout);self.assertEqual(result['subprocessCalls'],0)
        if no_network:self.assertEqual(result['calls'],[])
        return result['results'][0]

    def test_native_prepare_admit_restart_and_python_reuse(self):
        self.journey(False)

    def test_native_sender_preserves_independent_receipt_permission(self):
        self.journey(True)

    def test_native_compressed_receipt_draft_admitted_over_http(self):
        self.journey(True,True)

    def journey(self,ack,remote=False):
        name='test_cold_mailbox_returns_independent_receipt' if ack else 'test_sender_admits_message_over_http'
        if remote:name='test_ack_configuration_admitted_over_http'
        h=fixtures.MailboxStagingHTTPTests(name);h.setUp();self.addCleanup(h.doCleanups)
        original=h.a.handle;actions=[];lost=[];snapshots={}
        def state():return Path(json.loads(Path(h.a.network_config).read_bytes())['state_directory'])/'network.sqlite3'
        def saved(message):
            db=sqlite3.connect(state())
            try:
                self.assertEqual(db.execute('PRAGMA integrity_check').fetchall(),[('ok',)])
                draft=db.execute('SELECT originals,envelope FROM open_mailbox_message_drafts WHERE message_id=?',(message,)).fetchone()
                if db.execute("SELECT 1 FROM sqlite_master WHERE name='open_mailbox_message_requests'").fetchone():
                    packet=db.execute('SELECT raw FROM open_mailbox_message_requests WHERE message_id=?',(message,)).fetchone()
                else:packet=None
                return draft,packet
            finally:db.close()
        def dispatch(request):
            value=request.get('invitation',{})
            if value.get('schema_version')!='memory-vault-open-mailbox-connect/v1' or value.get('action') not in ('prepare','admit','retain'):
                return original(request)
            action=value['action'];lose=action=='retain' and not lost
            result=self.native(h.a,request,lose,action=='prepare');actions.append(action)
            if lose:
                lost.append(True);self.assertFalse(result['ok'],result);snapshots[value['message_id']]=saved(value['message_id']);return result
            self.assertTrue(result['ok'],result)
            before=saved(value['message_id'])
            if value['message_id'] in snapshots:self.assertEqual(before,snapshots[value['message_id']])
            # Reopen the same originals through Python and compare response and persisted bytes.
            reopened=original(request);self.assertTrue(reopened['ok'],reopened);self.assertEqual(reopened['result'],result['result']);self.assertEqual(saved(value['message_id']),before)
            if action=='prepare':
                changed=dict(value,consent_until=value['consent_until']-1)
                denied=self.native(h.a,dict(request,invitation=changed),no_network=True);self.assertFalse(denied['ok']);self.assertEqual(denied['error']['code'],'repair_message_conflict')
                self.assertEqual(saved(value['message_id']),before)
            if action=='admit':
                changed=dict(value,enum_until=value['enum_until']+1)
                denied=self.native(h.a,dict(request,invitation=changed),no_network=True);self.assertFalse(denied['ok']);self.assertEqual(denied['error']['code'],'repair_message_conflict')
            return result
        h.a.handle=dispatch
        getattr(h,name)()
        self.assertIn('prepare',actions)
        if not ack or remote:self.assertIn('admit',actions);self.assertEqual(lost,[True])

if __name__=='__main__':unittest.main()
